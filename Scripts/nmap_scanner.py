#!/usr/bin/env python3
"""
nmap wrapper with per-host logging, pause/resume, scheduled start, time limit.

Usage:
    ./nmap_wrapper.py 10.0.0.1 10.0.0.2 example.com    # targets on CLI
    ./nmap_wrapper.py 192.168.1.0/24                    # CIDR
    ./nmap_wrapper.py 10.0.0.1-10.0.0.50                # full IP-IP range
    ./nmap_wrapper.py 10.0.0.1-10.0.0.50,10.0.1.1-10.0.1.9   # comma-separated ranges
    ./nmap_wrapper.py -iL targets.txt                   # targets from file (like nmap)
    ./nmap_wrapper.py -iL targets.txt 10.0.0.5          # both work together
    ./nmap_wrapper.py 10.0.0.0/24 --time 8h             # 8h then auto-pause
    ./nmap_wrapper.py 10.0.0.0/24 --start 14:46         # wait until 14:46
    ./nmap_wrapper.py 10.0.0.0/24 --window 17:00-07:00  # scan 5pm-7am daily, idle otherwise
    ./nmap_wrapper.py 10.0.0.0/24 --custom '-sU -p 53,161 -T4'  # skip discovery/service, run this instead
    ./nmap_wrapper.py 10.0.0.0/24 -o /data/scans        # write output to a custom directory
    ./nmap_wrapper.py 10.0.0.0/24 --batch-size 32       # discover 32 hosts per nmap invocation
    ./nmap_wrapper.py --resume 12345                    # resume by old PID

Only run this against hosts you are authorized to scan.
"""

import argparse
import fcntl
import ipaddress
import json
import os
import pty
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import termios
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from engagement_db import EngagementDB

# ==================== CONFIGURATION ====================
OUTPUT_BASE = Path("./NMAP_scans")

# Discovery scan: find open ports. -p- = all 65535 TCP ports.
# -v makes nmap report open ports as they're found; --stats-every prints a
# periodic progress + ETA line. Both keep a long batched scan visibly alive.
# nmap only emits the periodic status when stdout is a TTY, so run_nmap attaches
# it to a pseudo-terminal (see _run_nmap_streamed).
STATS_INTERVAL = "10s"

DISCOVERY_ARGS = [
    "-p-",
    "-T4",
    "--min-rate", "5000",
    "-Pn",
    "--open",
    "--randomize-hosts",
    "-n",
    "-v",
    "--stats-every", STATS_INTERVAL,
]

# Service/script scan: runs only on the open ports found above.
SERVICE_ARGS = [
    "-sV",
    "-sC",
    "-Pn",
    "--min-rate", "5000",
    "-T4",
    "-n",
    "-v",
    "--stats-every", STATS_INTERVAL,
]

NMAP_BIN = "nmap"
# Default engagement DB filename when neither --db nor --resume is given.
DEFAULT_DB = Path("./engagement.db")
# ========================================================

_pause_requested = False
_current_proc = None
_prompting = False
# Scheduled scan-window state. _window_paused is True while we're outside the
# allowed wall-clock window; _resume_event is set when the window is open so the
# main loop can block on it while paused. Distinct from _pause_requested, which
# means "stop and exit" — a window pause means "stop and wait".
_window_paused = False
_resume_event = threading.Event()


# --------------------- argument parsing helpers ---------------------

def parse_duration(s):
    m = re.fullmatch(r"(\d+)([smhd])", s.strip().lower())
    if not m:
        raise argparse.ArgumentTypeError(
            f"invalid duration {s!r} (use e.g. 30s, 8m, 8h, 2d)"
        )
    n, u = int(m.group(1)), m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[u]


def parse_start_time(s):
    now = datetime.now()
    try:
        h, m = s.split(":")
        target = now.replace(hour=int(h), minute=int(m), second=0, microsecond=0)
    except Exception:
        raise argparse.ArgumentTypeError(f"invalid start time {s!r} (use HH:MM)")
    if target <= now:
        target += timedelta(days=1)
    return target


def parse_window(s):
    """Parse a daily scan window 'HH:MM-HH:MM' into ((sh, sm), (eh, em)).
    The window may wrap past midnight (e.g. 17:00-07:00 = 5pm to 7am)."""
    try:
        start_s, end_s = s.split("-")
        sh, sm = (int(x) for x in start_s.split(":"))
        eh, em = (int(x) for x in end_s.split(":"))
    except Exception:
        raise argparse.ArgumentTypeError(
            f"invalid window {s!r} (use HH:MM-HH:MM, e.g. 17:00-07:00)"
        )
    for h, m in ((sh, sm), (eh, em)):
        if not (0 <= h < 24 and 0 <= m < 60):
            raise argparse.ArgumentTypeError(f"invalid time of day in window {s!r}")
    if (sh, sm) == (eh, em):
        raise argparse.ArgumentTypeError(f"window start and end are equal in {s!r}")
    return (sh, sm), (eh, em)


def in_window(now, start, end):
    """True if `now` (a datetime) falls inside the [start, end) window, where
    start/end are (hour, minute) tuples. Handles windows that wrap midnight."""
    cur = now.hour * 60 + now.minute
    s = start[0] * 60 + start[1]
    e = end[0] * 60 + end[1]
    if s <= e:
        return s <= cur < e
    # Wraps midnight, e.g. 17:00-07:00 -> in window from 17:00 to 23:59 or 00:00 to 06:59.
    return cur >= s or cur < e


# --------------------- target normalization ---------------------

# Full dotted range on both sides, e.g. 10.0.0.1-10.0.0.50. This is NOT valid
# nmap syntax (nmap only does per-octet ranges like 10.0.0.1-50), so we expand
# it ourselves below.
_IP_RANGE_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)")


def split_target_tokens(text):
    """Split a string into target tokens on whitespace and commas, so
    'a-b, c-d' (commas, with or without spaces) yields ['a-b', 'c-d']."""
    return [t for t in re.split(r"[\s,]+", text) if t]


def normalize_targets(raw_targets):
    """Expand full IP-IP ranges (e.g. 10.0.0.1-10.0.0.50) into CIDR blocks that
    nmap understands. Everything else — single IPs, CIDRs, hostnames, and
    nmap's own octet-ranges like 10.0.0.1-50 — passes through unchanged."""
    out = []
    for tok in raw_targets:
        m = _IP_RANGE_RE.fullmatch(tok)
        if not m:
            out.append(tok)
            continue
        try:
            start = ipaddress.IPv4Address(m.group(1))
            end = ipaddress.IPv4Address(m.group(2))
        except ipaddress.AddressValueError:
            # Octet > 255 etc. — let nmap's expansion report the error.
            out.append(tok)
            continue
        if end < start:
            sys.stderr.write(f"[!] range start is after end: {tok}\n")
            sys.exit(2)
        # summarize_address_range gives the minimal set of CIDR blocks covering
        # the inclusive range, which nmap -sL then expands to individual hosts.
        out.extend(str(net) for net in ipaddress.summarize_address_range(start, end))
    return out


# --------------------- nmap process management ---------------------

# When streaming nmap live we only echo "heartbeat" lines — periodic progress,
# discovered ports, completion — plus real warnings/errors. The rest (port
# tables, -sC script output, etc.) is still written to the result files; it's
# just not mirrored to the console, which would otherwise be a wall of text.
_HEARTBEAT_RE = re.compile(
    r"Stats:|Timing: About|Discovered open port|Nmap done|QUITTING|WARNING",
    re.IGNORECASE,
)


def _halt_work():
    """True when in-progress nmap work should stop now — either a user kill/pause
    (which exits) or a scheduled window pause (which waits). Used to bail out of
    scan stages and to suppress the nmap-exited-nonzero message when we are the
    ones who killed it."""
    return _pause_requested or _window_paused


def check_nmap():
    try:
        subprocess.run([NMAP_BIN, "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        sys.stderr.write(f"[!] nmap not found or not working: {NMAP_BIN}\n")
        sys.exit(1)


def run_nmap(cmd, stream=False, prefix="    "):
    """Run nmap in its own session so Ctrl-C at terminal does not kill it
    directly — we control killing it ourselves from the interrupt handler.

    stream=False: capture output quietly and return it.
    stream=True: run nmap attached to a pseudo-terminal and echo its output
    live (each line indented with `prefix`). nmap only prints its periodic
    --stats-every progress when stdout is a TTY, so the pty is what makes a long
    scan show continuous progress instead of looking hung.

    Returns (returncode, collected_output, "")."""
    if stream:
        return _run_nmap_streamed(cmd, prefix)

    global _current_proc
    _current_proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    stdout, _ = _current_proc.communicate()
    rc = _current_proc.returncode if _current_proc.returncode is not None else -1
    _current_proc = None
    if rc != 0 and not _halt_work():
        sys.stderr.write(f"[!] nmap exited {rc} for: {' '.join(cmd)}\n")
        if stdout.strip():
            sys.stderr.write(f"    {stdout.strip().splitlines()[-1]}\n")
    return rc, stdout, ""


def _run_nmap_streamed(cmd, prefix):
    """Run nmap with all three std streams on a pseudo-terminal so it enters
    interactive mode (which is what makes it line-buffer and emit the periodic
    --stats-every status), echoing each line live while collecting the output.

    nmap's stdin is the pty slave — its own private TTY, NOT our real stdin — so
    its interactive-key reader can't fight with input() in the signal handler
    (which reads fd 0). We never write to the master, so nmap just gets no keys.

    The child makes the slave its controlling terminal (setsid + TIOCSCTTY);
    nmap only emits its periodic status when it has a controlling TTY."""
    global _current_proc
    master, slave = pty.openpty()

    def _setup_controlling_tty():
        os.setsid()  # new session (also isolates nmap from terminal Ctrl-C)
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)  # slave becomes controlling tty

    try:
        _current_proc = subprocess.Popen(
            cmd,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            preexec_fn=_setup_controlling_tty,
            pass_fds=(slave,),  # keep slave open through close_fds for the ioctl
        )
    except Exception:
        os.close(master)
        os.close(slave)
        _current_proc = None
        raise
    os.close(slave)  # parent keeps only the master end

    def _emit(text):
        # Mirror only heartbeat/warning lines to the console (see _HEARTBEAT_RE).
        if _HEARTBEAT_RE.search(text):
            sys.stdout.write(prefix + text + "\n")

    chunks = []
    pending = b""
    while True:
        try:
            data = os.read(master, 65536)
        except OSError:
            break  # EIO is raised on Linux when the child (slave) closes/exits
        if not data:
            break
        chunks.append(data)
        pending += data
        # Process complete lines as they arrive; the pty maps \n->\r\n, strip \r.
        *lines, pending = pending.split(b"\n")
        for ln in lines:
            _emit(ln.rstrip(b"\r").decode("utf-8", "replace"))
    if pending:
        _emit(pending.rstrip(b"\r").decode("utf-8", "replace"))
    os.close(master)

    _current_proc.wait()
    rc = _current_proc.returncode if _current_proc.returncode is not None else -1
    _current_proc = None
    stdout = b"".join(chunks).decode("utf-8", "replace")
    if rc != 0 and not _halt_work():
        sys.stderr.write(f"[!] nmap exited {rc} for: {' '.join(cmd)}\n")
    return rc, stdout, ""


def kill_current_proc():
    # Snapshot the global so a concurrent main-thread assignment to
    # _current_proc = None cannot race us between check and use.
    proc = _current_proc
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        for _ in range(15):
            if proc.poll() is not None:
                return
            time.sleep(0.2)
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# --------------------- scan stages ---------------------

def expand_targets(targets):
    """Use `nmap -sL` to turn CIDRs/ranges into a flat list of IPs."""
    cmd = [NMAP_BIN, "-sL", "-n"] + list(targets)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write("[!] target expansion failed (bad IP / CIDR / hostname?)\n")
        if e.stderr:
            for line in e.stderr.strip().splitlines():
                sys.stderr.write(f"    {line}\n")
        sys.exit(1)
    ips = []
    for line in result.stdout.splitlines():
        m = re.match(r"Nmap scan report for (\S+)", line)
        if m:
            ips.append(m.group(1))
    return ips


def parse_open_ports(grep_output):
    """Extract sorted, unique open port numbers from nmap greppable output
    (`-oG -` or a .gnmap file)."""
    ports = []
    for line in grep_output.splitlines():
        if "Ports:" not in line:
            continue
        section = line.split("Ports:", 1)[1]
        for entry in section.split(","):
            parts = entry.strip().split("/")
            if len(parts) >= 2 and parts[1] == "open":
                try:
                    ports.append(int(parts[0]))
                except ValueError:
                    pass
    return sorted(set(ports))


def discovery_scan_host(host):
    """Full-port discovery on one host. Returns sorted list of open ports."""
    with tempfile.TemporaryDirectory(prefix="nmap_wrapper_") as tmp:
        grep_file = str(Path(tmp) / "discovery.gnmap")
        cmd = [NMAP_BIN] + DISCOVERY_ARGS + ["-oG", grep_file, host]
        run_nmap(cmd, stream=True)
        if _halt_work():
            return []
        try:
            return parse_open_ports(Path(grep_file).read_text())
        except FileNotFoundError:
            return []


def parse_discovery_batch(grep_output):
    """Map every host nmap reported in greppable output to its open ports
    ([] if none). A host appears as a key iff nmap emitted a 'Host:' line for
    it, so the caller can tell 'scanned, nothing open' (present with []) from
    'never reported' (absent — e.g. a target token nmap echoed differently)."""
    result = {}
    for line in grep_output.splitlines():
        m = re.search(r"Host:\s+(\S+)", line)
        if not m:
            continue
        host = m.group(1)
        ports = parse_open_ports(line) if "Ports:" in line else []
        if host in result:
            result[host].extend(p for p in ports if p not in result[host])
            result[host].sort()
        else:
            result[host] = ports
    return result


def discovery_scan_batch(hosts):
    """Full-port discovery on a batch of hosts in a single nmap invocation, so
    nmap parallelizes across the whole group instead of one host at a time.
    Returns {host: [open ports]} for every host nmap reported; {} if halted.

    Greppable output goes to a temp file (not stdout) so nmap's live progress
    can stream to the terminal while the batch runs."""
    with tempfile.TemporaryDirectory(prefix="nmap_wrapper_") as tmp:
        grep_file = str(Path(tmp) / "discovery.gnmap")
        cmd = [NMAP_BIN] + DISCOVERY_ARGS + ["-oG", grep_file] + list(hosts)
        run_nmap(cmd, stream=True)
        if _halt_work():
            return {}
        try:
            return parse_discovery_batch(Path(grep_file).read_text())
        except FileNotFoundError:
            return {}


def update_open_ports(host, ports, output_dir, seen_cache=None):
    """Append host to OpenPorts/[PORT]/hosts.md — one file per open port.

    seen_cache, if given, maps each hosts.md path to the set of hosts already
    recorded in it, so a long run dedupes against an in-memory set rather than
    re-reading the (growing) file on every host. The file is read at most once
    per port per process and seeded lazily, so resume still dedupes against
    hosts written in earlier runs."""
    for p in ports:
        port_dir = output_dir / "OpenPorts" / str(p)
        port_dir.mkdir(parents=True, exist_ok=True)
        hosts_file = port_dir / "hosts.md"

        if seen_cache is not None and hosts_file in seen_cache:
            existing = seen_cache[hosts_file]
        else:
            existing = set()
            if hosts_file.exists():
                existing = {l.strip() for l in hosts_file.read_text().splitlines() if l.strip()}
            if seen_cache is not None:
                seen_cache[hosts_file] = existing

        if host not in existing:
            with open(hosts_file, "a") as f:
                f.write(f"{host}\n")
            existing.add(host)  # keep the cached set in sync with the file


def service_scan_host(host, ports, output_dir):
    """Service+script scan on the open ports. Writes nmap's -oA output into a
    scratch tempdir (per-host files are not retained), then appends the
    completed scan to:
      - ServiceScans/all_hosts.{nmap,gnmap}
      - OpenPorts/[PORT]/service_scans.{nmap,gnmap} for every port this host
        had open
    Aggregation happens only after nmap completes successfully; a paused or
    failed scan leaves the combined files untouched so resume redoes the host
    cleanly."""
    if not ports:
        return
    port_list = ",".join(str(p) for p in ports)

    with tempfile.TemporaryDirectory(prefix="nmap_wrapper_") as tmp:
        # Use a plain string prefix and append the extension ourselves.
        # Do NOT use Path.with_suffix — it treats IPs/hostnames as having
        # an extension (e.g. Path("192.168.1.1").with_suffix(".nmap")
        # becomes "192.168.1.nmap", which is not what nmap -oA produces).
        prefix = str(Path(tmp) / "scan")
        cmd = [NMAP_BIN] + SERVICE_ARGS + [
            "-p", port_list,
            "-oA", prefix,
            host,
        ]
        run_nmap(cmd, stream=True)
        if _halt_work():
            return

        svc_dir = output_dir / "ServiceScans"
        svc_dir.mkdir(parents=True, exist_ok=True)

        for ext in (".nmap", ".gnmap"):
            src = Path(prefix + ext)
            if not src.exists():
                continue
            content = src.read_text()
            if not content.endswith("\n"):
                content += "\n"

            # Combined all-hosts file
            with open(svc_dir / f"all_hosts{ext}", "a") as f:
                f.write(content)

            # Per-port file: every port the host had open gets a copy
            for p in ports:
                port_file = output_dir / "OpenPorts" / str(p) / f"service_scans{ext}"
                with open(port_file, "a") as f:
                    f.write(content)


def custom_scan_batch(hosts, custom_args, output_dir, seen_cache=None):
    """Run the user's custom nmap scan on a batch of hosts in ONE invocation so
    nmap parallelizes across them. The combined output is appended to
    CustomScans/all_hosts.{nmap,gnmap}, and open ports parsed per host populate
    CustomScans/OpenPorts/[PORT]/hosts.md (the discovery role).

    This does NOT write per-port service_scans.* copies: a single batched
    invocation yields one combined output file that can't be cleanly attributed
    to an individual host/port, so the per-port scan output lives only in
    all_hosts.* here. Aggregation happens only after nmap completes (an empty
    dict signals a halted run, so resume redoes the batch cleanly).

    Returns {host: [open ports]} for every host nmap reported. The invocation
    scans every host in `hosts`; a host absent from the result was scanned but
    reported nothing open (e.g. down without -Pn), so the caller marks it done
    rather than re-scanning it.
    """
    with tempfile.TemporaryDirectory(prefix="nmap_wrapper_") as tmp:
        # Plain string prefix + explicit extension, same reasoning as the
        # service scan. -oA always writes a .gnmap so we can extract open ports.
        prefix = str(Path(tmp) / "scan")
        # Inject --stats-every for live progress unless the user set their own.
        stats = [] if any(a.startswith("--stats-every") for a in custom_args) \
            else ["--stats-every", STATS_INTERVAL]
        cmd = [NMAP_BIN] + custom_args + stats + ["-oA", prefix] + list(hosts)
        run_nmap(cmd, stream=True)
        if _halt_work():
            return {}

        custom_dir = output_dir / "CustomScans"
        custom_dir.mkdir(parents=True, exist_ok=True)

        # Discovery role: per-host open ports from the combined greppable output.
        gnmap = Path(prefix + ".gnmap")
        host_ports = parse_discovery_batch(gnmap.read_text()) if gnmap.exists() else {}
        for host, ports in host_ports.items():
            if ports:
                update_open_ports(host, ports, custom_dir, seen_cache)

        # Aggregate the combined scan across all hosts (no per-port copies).
        for ext in (".nmap", ".gnmap"):
            src = Path(prefix + ext)
            if not src.exists():
                continue
            content = src.read_text()
            if not content.endswith("\n"):
                content += "\n"
            with open(custom_dir / f"all_hosts{ext}", "a") as f:
                f.write(content)

        return host_ports


# --------------------- interrupt + time-limit handling ---------------------

def install_interrupt_handler():
    def handler(signum, frame):
        global _pause_requested, _prompting
        if _prompting:
            return
        _prompting = True
        try:
            sys.stderr.write("\n\n[!] Interrupt.\n")
            sys.stderr.write("    (k) kill scan and exit\n")
            sys.stderr.write("    (p) pause and save state for --resume\n")
            sys.stderr.write("    (c) continue\n")
            while True:
                try:
                    choice = input("Choice [k/p/c]: ").strip().lower()
                except EOFError:
                    choice = "k"
                    break
                if choice in ("k", "p", "c"):
                    break
            if choice == "k":
                kill_current_proc()
                sys.stderr.write("[*] Killed.\n")
                os._exit(130)
            elif choice == "p":
                _pause_requested = True
                # Wake the main loop if it is blocked waiting for a scan window.
                _resume_event.set()
                kill_current_proc()
                sys.stderr.write("[*] Pausing — will stop after current host settles.\n")
        finally:
            _prompting = False
    signal.signal(signal.SIGINT, handler)


def start_time_limit(seconds):
    def worker():
        time.sleep(seconds)
        global _pause_requested
        if _pause_requested:
            return
        sys.stderr.write(f"\n[!] Time limit ({seconds}s) reached — pausing.\n")
        _pause_requested = True
        kill_current_proc()
    threading.Thread(target=worker, daemon=True).start()


# --------------------- scheduled scan window (APScheduler) ---------------------

def window_pause():
    """Window closed: stop the running nmap and make the main loop wait. Called
    from the APScheduler thread at the window's end time."""
    global _window_paused
    if _window_paused:
        return
    _window_paused = True
    _resume_event.clear()
    sys.stderr.write("\n[*] Scan window closed — pausing after current host settles.\n")
    kill_current_proc()


def window_resume():
    """Window opened: let the main loop proceed. Called from the APScheduler
    thread at the window's start time."""
    global _window_paused
    if not _window_paused:
        return
    _window_paused = False
    sys.stderr.write("\n[*] Scan window open — resuming.\n")
    _resume_event.set()


def wait_for_window(state):
    """If we are outside the scan window, checkpoint progress and block until the
    window reopens (or a user kill/pause unblocks us). No-op when no window is
    configured or we are inside it."""
    if not _window_paused:
        return
    state.commit()
    sys.stderr.write("[*] Outside scan window — waiting for it to reopen "
                     "(Ctrl-C to kill/pause)...\n")
    # Loop with a timeout so signals are delivered promptly and we re-check both
    # the window flag (cleared by window_resume) and a user pause request.
    while _window_paused and not _pause_requested:
        _resume_event.wait(timeout=30)


def start_window_scheduler(window):
    """Run only inside the given daily wall-clock window, every day (Mon-Sun),
    using APScheduler cron triggers: pause at the end time, resume at the start
    time. Returns the live scheduler (keep a reference so it is not GC'd)."""
    global _window_paused
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
        from apscheduler.triggers.interval import IntervalTrigger
    except ImportError:
        sys.stderr.write("[!] --window requires APScheduler: pip install apscheduler\n")
        sys.exit(1)

    (sh, sm), (eh, em) = window

    def reconcile():
        """Level-triggered safety net: drive the paused/running state to match
        where the wall clock actually is right now. window_pause/window_resume
        are idempotent, so this is silent except right at a boundary or after a
        cron fire was missed (e.g. the host was asleep at 17:00 and woke later)."""
        if in_window(datetime.now(), (sh, sm), (eh, em)):
            window_resume()
        else:
            window_pause()

    sched = BackgroundScheduler()
    # Edge-triggered: react at the exact boundary instants, every day (Mon-Sun).
    sched.add_job(window_resume, CronTrigger(hour=sh, minute=sm), id="window_resume")
    sched.add_job(window_pause, CronTrigger(hour=eh, minute=em), id="window_pause")
    # Level-triggered: re-check every minute so a missed edge self-corrects within
    # ~1 minute of the process next being awake.
    sched.add_job(reconcile, IntervalTrigger(minutes=1), id="window_reconcile")
    sched.start()

    win = f"{sh:02d}:{sm:02d}-{eh:02d}:{em:02d}"
    # Set the initial state directly — the interval job's first run is a minute
    # out, and we want the right state from the moment the loop starts.
    if in_window(datetime.now(), (sh, sm), (eh, em)):
        _window_paused = False
        _resume_event.set()
        print(f"[*] Scan window {win} (daily) — inside it now; "
              f"will pause at {eh:02d}:{em:02d}.")
    else:
        _window_paused = True
        _resume_event.clear()
        print(f"[*] Scan window {win} (daily) — outside it now; "
              f"will start at {sh:02d}:{sm:02d}.")
    return sched


# --------------------- main ---------------------

def main():
    # Force line-buffered stdout so progress lines appear immediately even when
    # output is piped or redirected (otherwise Python block-buffers a non-TTY
    # stdout and the long, silent discovery scans look like a hang).
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass  # not a regular text stream (e.g. already wrapped) — nothing to do

    ap = argparse.ArgumentParser(
        description="nmap wrapper: per-host logs, pause/resume, scheduled start, time limit.",
    )
    ap.add_argument("targets", nargs="*",
                    help="IP(s), hostname(s), CIDR(s), or range(s) to scan; "
                         "ranges may be nmap octet form (10.0.0.1-50), full "
                         "IP-IP (10.0.0.1-10.0.0.50), and comma-separated")
    ap.add_argument("-iL", dest="input_file", metavar="FILE",
                    help="read targets from a file (one per line, # comments ok)")
    ap.add_argument("-o", "--output-dir", metavar="DIR",
                    help=f"directory to write scan output into "
                         f"(default: {OUTPUT_BASE})")
    ap.add_argument("--db", metavar="PATH",
                    help="start a NEW engagement, storing state in this SQLite "
                         "DB. A directory (or '.') creates engagement.db inside "
                         "it; a file path is used as-is. Default when omitted: "
                         f"{DEFAULT_DB}. Errors if the DB already exists "
                         "(use --resume to continue it).")
    ap.add_argument("--resume", metavar="DB",
                    help="continue an existing engagement DB, scanning only the "
                         "hosts it hasn't completed yet (output dir and scan "
                         "mode are restored from the DB).")
    ap.add_argument("--time", metavar="DUR", type=parse_duration,
                    help="run for this long then auto-pause (e.g. 30s, 8m, 8h, 2d)")
    ap.add_argument("--start", metavar="HH:MM", type=parse_start_time,
                    help="wait until this wall-clock time before starting")
    ap.add_argument("--window", metavar="HH:MM-HH:MM", type=parse_window,
                    help="only scan inside this daily window, every day (Mon-Sun); "
                         "pauses outside it and resumes when it reopens. e.g. "
                         "17:00-07:00 scans 5pm-7am. Requires APScheduler.")
    ap.add_argument("--batch-size", metavar="N", type=int, default=16,
                    help="hosts per nmap invocation, so nmap parallelizes across "
                         "them (default: 16). Applies to discovery and to "
                         "--custom scans. Normal-mode service scans still run "
                         "per host (each needs its own open-port set).")
    ap.add_argument("--custom", metavar="ARGS",
                    help="skip the discovery and service scans; instead run nmap "
                         "with these args (quote them, e.g. --custom '-sU -p "
                         "53,161 -T4'), batched per --batch-size. Output is "
                         "self-contained under CustomScans/: combined scans in "
                         "all_hosts.*, open ports in CustomScans/OpenPorts/. "
                         "Add -Pn to scan hosts that don't answer ping discovery "
                         "(otherwise they're recorded as down with nothing open).")
    args = ap.parse_args()

    if args.batch_size < 1:
        ap.error("--batch-size must be at least 1")

    # Parse the custom nmap args up front so a bad quote fails before any scan.
    # The effective mode is resolved from state below (so resume reuses it).
    cli_custom_args = None
    if args.custom is not None:
        try:
            cli_custom_args = shlex.split(args.custom)
        except ValueError as e:
            ap.error(f"could not parse --custom args: {e}")
        if not cli_custom_args:
            ap.error("--custom was given no nmap arguments")

    if args.db is not None and args.resume is not None:
        ap.error("--db (start new) and --resume (continue existing) are mutually exclusive")

    check_nmap()

    # --- load/build engagement ---
    if args.resume is not None:
        if args.targets or args.input_file:
            sys.stderr.write("[!] --resume cannot be combined with targets or -iL\n")
            sys.exit(2)
        if args.custom is not None:
            sys.stderr.write("[!] --custom cannot be combined with --resume "
                             "(the scan mode is restored from the DB)\n")
            sys.exit(2)
        db_path = EngagementDB.resolve_path(args.resume, for_new=False)
        try:
            state = EngagementDB.connect(db_path, create=False)
        except FileNotFoundError:
            sys.stderr.write(f"[!] cannot resume: no engagement DB at {db_path}\n")
            sys.exit(1)
        state.clear_paused()  # this run is no longer paused
        done, total = state.counts()
        print(f"[*] Resumed engagement {state.path}. "
              f"{done}/{total} hosts already done.")
    else:
        raw_targets = []
        for arg in args.targets:
            raw_targets.extend(split_target_tokens(arg))
        if args.input_file:
            try:
                with open(args.input_file) as f:
                    for line in f:
                        # Strip comments, then split on whitespace and commas so
                        # both nmap-style whitespace separation and comma-separated
                        # ranges work.
                        line = line.split("#", 1)[0]
                        raw_targets.extend(split_target_tokens(line))
            except OSError as e:
                sys.stderr.write(f"[!] cannot read {args.input_file}: {e}\n")
                sys.exit(1)
        if not raw_targets:
            ap.error("no targets given (pass IPs/hostnames as args, use -iL FILE, "
                     "or --resume DB)")

        # A new engagement: refuse to clobber an existing DB.
        db_path = EngagementDB.resolve_path(args.db, for_new=True) if args.db else DEFAULT_DB
        if Path(db_path).exists():
            sys.stderr.write(f"[!] engagement DB already exists at {db_path}\n"
                             f"    use --resume {db_path} to continue it, "
                             f"or pass --db <new_path> to start elsewhere\n")
            sys.exit(2)

        # Turn full IP-IP ranges into CIDRs before handing to nmap -sL.
        raw_targets = normalize_targets(raw_targets)

        state = EngagementDB.connect(db_path, create=True)
        state.started_at = time.time()
        state.custom_args = cli_custom_args
        state.output_dir = str(OUTPUT_BASE)
        print(f"[*] New engagement: {state.path}")
        print(f"[*] Expanding {len(raw_targets)} target spec(s)...")
        state.add_hosts(expand_targets(raw_targets))
        done, total = state.counts()
        print(f"[*] {total} hosts to scan.")

    # Override the output directory if requested. Applies to new engagements and
    # resumes; on resume this redirects only the not-yet-scanned hosts, leaving
    # already-collected output in the original location.
    if args.output_dir is not None:
        state.output_dir = args.output_dir

    # Effective scan mode comes from the DB: set from --custom on a new
    # engagement, restored from the DB on resume.
    custom_args = state.custom_args
    if custom_args is not None:
        print(f"[*] Custom scan: nmap {' '.join(custom_args)}")

    # --- scheduled start ---
    if args.start is not None:
        wait = (args.start - datetime.now()).total_seconds()
        if wait > 0:
            print(f"[*] Waiting {wait:.0f}s until {args.start.strftime('%Y-%m-%d %H:%M')}...")
            time.sleep(wait)

    # --- time limit ---
    if args.time is not None:
        print(f"[*] Time limit: {args.time}s — will auto-pause.")
        start_time_limit(args.time)

    # --- daily scan window (APScheduler cron triggers) ---
    sched = None  # keep a reference so the BackgroundScheduler is not GC'd
    if args.window is not None:
        sched = start_window_scheduler(args.window)

    print(f"[*] PID {os.getpid()} — Ctrl-C to pause/kill; "
          f"resume with: {sys.argv[0]} --resume {state.path}")
    print(f"[*] Output: {state.output_dir}")

    install_interrupt_handler()

    output_dir = Path(state.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if custom_args is None:
        (output_dir / "ServiceScans").mkdir(parents=True, exist_ok=True)

    targets = state.all_hosts()
    total = len(targets)
    completed_set = set(state.completed_hosts())
    # In-memory dedup cache for OpenPorts/[PORT]/hosts.md, so update_open_ports
    # reads each port file at most once per process instead of on every host.
    open_ports_seen = {}
    # Hosts are processed in batches, one nmap invocation per batch so nmap
    # parallelizes across the group. Normal mode: batched full-port discovery,
    # then service scans per host. Custom mode: the whole custom scan runs
    # batched. idx is the scan cursor over the target list; already-completed
    # hosts are skipped when building each batch. idx only advances past a batch
    # once it finishes — a window pause mid-batch redoes the unfinished hosts
    # (completed ones are skipped); a user pause exits.
    idx = 0
    while idx < total:
        # Build the next batch of up to batch_size not-yet-completed hosts.
        batch = []
        batch_end = idx
        while batch_end < total and len(batch) < args.batch_size:
            h = targets[batch_end]
            batch_end += 1
            if h not in completed_set:
                batch.append(h)
        if not batch:
            idx = batch_end
            continue

        # Block here while outside the scheduled scan window; returns at once when
        # no window is configured or we are inside it.
        wait_for_window(state)
        if _pause_requested:
            break

        # One batched nmap invocation for the whole group. Both modes return a
        # {host: [open ports]} map of the hosts nmap actually reported.
        label = "custom scan" if custom_args is not None else "discovery scan"
        print(f"\n[{len(state.completed)}/{total} done] {label} on {len(batch)} host(s)...")
        try:
            if custom_args is not None:
                host_ports = custom_scan_batch(batch, custom_args, output_dir, open_ports_seen)
            else:
                host_ports = discovery_scan_batch(batch)
        except Exception as e:
            print(f"    [!] {label} error: {e}")
            idx = batch_end  # skip this batch this run; resume retries it
            continue
        if _window_paused:
            continue  # window closed mid-scan — redo batch once it reopens
        if _pause_requested:
            break

        # Custom mode: the one batched invocation already scanned and recorded
        # every host in the batch, so there is nothing left to run per host.
        # Mark the whole batch atomically (a host absent from host_ports was
        # scanned but reported nothing open / down — not something to re-scan).
        if custom_args is not None:
            for host in batch:
                ports = host_ports.get(host, [])
                summary = (f"open {', '.join(str(p) for p in ports)}"
                           if ports else "no open ports / down")
                print(f"[{len(state.completed) + 1}/{total}] {host}: {summary}")
                completed_set.add(host)
                state.mark_completed(host)  # O(1) append checkpoint
            idx = batch_end
            continue

        # Normal mode: service-scan each host on its own open ports. This stage
        # is per host (each needs its own port set) and interruptible, so hosts
        # are marked one at a time; idx advances only if the whole batch
        # finishes without a window/user interrupt.
        interrupted = False
        for host in batch:
            if _halt_work():  # pause/window arrived between hosts
                interrupted = True
                break

            # Batched discovery (with -Pn) reports every host, so absence means
            # nothing was open — treat it as such rather than re-scanning.
            ports = host_ports.get(host, [])
            if ports:
                print(f"[{len(state.completed) + 1}/{total}] {host}: "
                      f"open {', '.join(str(p) for p in ports)} — service scan...")
                update_open_ports(host, ports, output_dir, open_ports_seen)
                try:
                    service_scan_host(host, ports, output_dir)
                except Exception as e:
                    print(f"    [!] service scan error: {e}")
                    continue  # skip this host this run; resume retries it
                # Don't mark a host whose service scan was cut short.
                if _halt_work():
                    interrupted = True
                    break
            else:
                print(f"[{len(state.completed) + 1}/{total}] {host}: no open ports")

            completed_set.add(host)
            state.mark_completed(host)  # O(1) append checkpoint

        if interrupted:
            if _pause_requested:
                break
            continue  # window pause — rebuild batch, redo the unfinished hosts
        idx = batch_end

    # --- finish ---
    if _pause_requested:
        state.save_paused()
        elapsed = state.paused_at - state.started_at
        print(f"\n[*] Paused. {len(state.completed)}/{len(state.targets)} hosts done.")
        print(f"[*] PID {state.pid}, ran {elapsed:.0f}s "
              f"(started {datetime.fromtimestamp(state.started_at).strftime('%Y-%m-%d %H:%M:%S')}, "
              f"paused {datetime.fromtimestamp(state.paused_at).strftime('%Y-%m-%d %H:%M:%S')}).")
        print(f"[*] Resume with: {sys.argv[0]} --resume {state.pid}")
        print(f"[*] State file: {state.state_file}")
    else:
        print(f"\n[*] Scan complete. {len(state.completed)}/{len(state.targets)} hosts scanned.")
        for f in (state.state_file, state.done_file):
            try:
                f.unlink()
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    main()