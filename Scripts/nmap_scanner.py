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
    ./nmap_wrapper.py --resume 12345                    # resume by old PID

Only run this against hosts you are authorized to scan.
"""

import argparse
import ipaddress
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

# ==================== CONFIGURATION ====================
OUTPUT_BASE = Path("./NMAP_scans")

# Discovery scan: find open ports. -p- = all 65535 TCP ports.
DISCOVERY_ARGS = [
    "-p-",
    "-T4",
    "--min-rate", "2000",
    "-Pn",
    "--open",
    "--randomize-hosts"
]

# Service/script scan: runs only on the open ports found above.
SERVICE_ARGS = [
    "-sV",
    "-sC",
    "-Pn",
    "--min-rate", "1500",
    "-T4"
]

NMAP_BIN = "nmap"
# State file lives in the directory the scan is launched from (./) so it sits
# alongside the run and is not exposed in a shared, predictable /tmp path.
# Note: --resume must therefore be run from the same working directory.
STATE_DIR = Path(".")
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


def run_nmap(cmd):
    """Run nmap in its own session so Ctrl-C at terminal does not kill it
    directly — we control killing it ourselves from the interrupt handler.
    stdin is detached so nmap's interactive-key reader does not fight with
    input() in the signal handler."""
    global _current_proc
    _current_proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    stdout, stderr = _current_proc.communicate()
    rc = _current_proc.returncode if _current_proc.returncode is not None else -1
    _current_proc = None
    # Surface real nmap failures; suppress if we killed it ourselves (pause/kill
    # or a scheduled window close).
    if rc != 0 and not _halt_work():
        sys.stderr.write(f"[!] nmap exited {rc} for: {' '.join(cmd)}\n")
        if stderr.strip():
            sys.stderr.write(f"    {stderr.strip()}\n")
    return rc, stdout, stderr


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
    cmd = [NMAP_BIN] + DISCOVERY_ARGS + ["-oG", "-", host]
    _, stdout, _ = run_nmap(cmd)
    if _halt_work():
        return []
    return parse_open_ports(stdout)


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
        run_nmap(cmd)
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


def custom_scan_host(host, custom_args, output_dir, seen_cache=None):
    """Run a user-supplied nmap scan on one host, replacing both the discovery
    and service stages with a single scan that does double duty: open ports
    parsed from its greppable output populate OpenPorts/[PORT]/hosts.md (the
    discovery role), and the scan output is recorded per open port and in an
    aggregate file (the service role).

    custom_args is the already-split list of nmap arguments (from --custom).
    Output is written to a scratch tempdir via -oA and, on success, aggregated
    into CustomScans/all_hosts.{nmap,gnmap} plus OpenPorts/[PORT]/* — mirroring
    how service_scan_host aggregates, so a paused/failed scan leaves the
    combined files untouched and resume redoes the host cleanly."""
    with tempfile.TemporaryDirectory(prefix="nmap_wrapper_") as tmp:
        # Plain string prefix + explicit extension, same reasoning as the
        # service scan: Path.with_suffix would mangle IP/hostname "extensions".
        # -oA always writes a .gnmap regardless of the user's args, so we can
        # extract open ports from it.
        prefix = str(Path(tmp) / "scan")
        cmd = [NMAP_BIN] + custom_args + ["-oA", prefix, host]
        run_nmap(cmd)
        if _halt_work():
            return

        # Everything from a custom scan is self-contained under CustomScans/,
        # including its OpenPorts/ tree, to keep it separate from a normal
        # discovery+service run's top-level OpenPorts/.
        custom_dir = output_dir / "CustomScans"
        custom_dir.mkdir(parents=True, exist_ok=True)

        # Discovery role: pull open ports from the greppable output.
        gnmap = Path(prefix + ".gnmap")
        ports = parse_open_ports(gnmap.read_text()) if gnmap.exists() else []
        if ports:
            print(f"    open: {', '.join(str(p) for p in ports)}")
            update_open_ports(host, ports, custom_dir, seen_cache)
        else:
            print(f"    no open ports")

        for ext in (".nmap", ".gnmap"):
            src = Path(prefix + ext)
            if not src.exists():
                continue
            content = src.read_text()
            if not content.endswith("\n"):
                content += "\n"

            # Aggregate across all hosts.
            with open(custom_dir / f"all_hosts{ext}", "a") as f:
                f.write(content)

            # Service role: a copy under every port this host had open.
            for p in ports:
                port_file = custom_dir / "OpenPorts" / str(p) / f"service_scans{ext}"
                with open(port_file, "a") as f:
                    f.write(content)


# --------------------- state (for pause/resume) ---------------------

class ScanState:
    def __init__(self, pid=None):
        self.pid = pid if pid is not None else os.getpid()
        self.state_file = STATE_DIR / f"nmap_wrapper_state_{self.pid}.json"
        self.targets = []
        self.completed = []
        self.output_dir = str(OUTPUT_BASE)
        # Wall-clock the run began (epoch + ISO). Set once at creation and
        # carried across resumes so elapsed time reflects the original start.
        self.started_at = time.time()
        # Set only when the scan is paused; None while running / on a fresh run.
        self.paused_at = None

    def save(self):
        self.state_file.write_text(json.dumps({
            "pid": self.pid,
            "targets": self.targets,
            "completed": self.completed,
            "output_dir": self.output_dir,
            "started_at": self.started_at,
            "started_at_iso": datetime.fromtimestamp(self.started_at).isoformat(timespec="seconds"),
            "paused_at": self.paused_at,
            "paused_at_iso": (datetime.fromtimestamp(self.paused_at).isoformat(timespec="seconds")
                              if self.paused_at is not None else None),
            "elapsed_seconds": round((self.paused_at or time.time()) - self.started_at, 1),
        }, indent=2))

    def save_paused(self):
        """Stamp the pause time, then persist. Called when the scan is paused so
        the state file records the PID and when work stopped for --resume."""
        self.paused_at = time.time()
        self.save()

    @staticmethod
    def _resolve_ref(ref):
        """Map a --resume argument to a state-file path. Accepts either a path
        to a state json file or a bare PID (looked up in STATE_DIR)."""
        p = Path(str(ref))
        if p.exists():
            return p
        try:
            pid = int(ref)
        except (ValueError, TypeError):
            raise FileNotFoundError(
                f"{ref!r} is neither an existing state file nor a PID")
        return STATE_DIR / f"nmap_wrapper_state_{pid}.json"

    @classmethod
    def load(cls, ref):
        state_file = cls._resolve_ref(ref)
        if not state_file.exists():
            raise FileNotFoundError(state_file)
        data = json.loads(state_file.read_text())
        s = cls()
        # Point at the file we loaded; main re-keys it under the new PID.
        s.state_file = state_file
        s.pid = data.get("pid", s.pid)
        s.targets = data["targets"]
        s.completed = data["completed"]
        s.output_dir = data["output_dir"]
        # Preserve the original start time across resumes; fall back to now for
        # state files written before this field existed.
        s.started_at = data.get("started_at", time.time())
        # A fresh resume is no longer paused.
        s.paused_at = None
        return s


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
    state.save()
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
    ap.add_argument("--resume", metavar="PID|FILE",
                    help="resume a paused scan by its original PID or by the "
                         "path to its state json file")
    ap.add_argument("--time", metavar="DUR", type=parse_duration,
                    help="run for this long then auto-pause (e.g. 30s, 8m, 8h, 2d)")
    ap.add_argument("--start", metavar="HH:MM", type=parse_start_time,
                    help="wait until this wall-clock time before starting")
    ap.add_argument("--window", metavar="HH:MM-HH:MM", type=parse_window,
                    help="only scan inside this daily window, every day (Mon-Sun); "
                         "pauses outside it and resumes when it reopens. e.g. "
                         "17:00-07:00 scans 5pm-7am. Requires APScheduler.")
    ap.add_argument("--custom", metavar="ARGS",
                    help="skip the discovery and service scans; instead run a "
                         "single nmap scan with these args on each host (quote "
                         "them, e.g. --custom '-sU -p 53,161 -T4'). It doubles "
                         "as discovery+service: all output is self-contained "
                         "under CustomScans/, including CustomScans/OpenPorts/.")
    args = ap.parse_args()

    # Parse the custom nmap args up front so a bad quote fails before any scan.
    custom_args = None
    if args.custom is not None:
        try:
            custom_args = shlex.split(args.custom)
        except ValueError as e:
            ap.error(f"could not parse --custom args: {e}")
        if not custom_args:
            ap.error("--custom was given no nmap arguments")

    check_nmap()

    # --- load/build state ---
    if args.resume is not None:
        if args.targets or args.input_file:
            sys.stderr.write("[!] --resume cannot be combined with targets or -iL\n")
            sys.exit(2)
        try:
            state = ScanState.load(args.resume)
        except FileNotFoundError as e:
            sys.stderr.write(f"[!] cannot resume {args.resume!r}: {e}\n")
            sys.exit(1)
        # Re-key state file under the new PID so subsequent pauses use the new PID.
        old_file = state.state_file
        state.pid = os.getpid()
        state.state_file = STATE_DIR / f"nmap_wrapper_state_{state.pid}.json"
        state.save()
        try:
            old_file.unlink()
        except FileNotFoundError:
            pass
        print(f"[*] Resumed from {args.resume}. "
              f"{len(state.completed)}/{len(state.targets)} hosts already done.")
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
            ap.error("no targets given (pass IPs/hostnames as args, use -iL FILE, or --resume PID)")

        # Turn full IP-IP ranges into CIDRs before handing to nmap -sL.
        raw_targets = normalize_targets(raw_targets)

        state = ScanState()
        print(f"[*] Expanding {len(raw_targets)} target spec(s)...")
        state.targets = expand_targets(raw_targets)
        print(f"[*] {len(state.targets)} hosts to scan.")
        state.save()

    # Override the output directory if requested. Applies to fresh runs and
    # resumes; on resume this redirects only the not-yet-scanned hosts, leaving
    # already-collected output in the original location.
    if args.output_dir is not None:
        state.output_dir = args.output_dir
        state.save()

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
          f"resume with: {sys.argv[0]} --resume {os.getpid()}")
    print(f"[*] Output: {state.output_dir}")

    install_interrupt_handler()

    output_dir = Path(state.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if custom_args is None:
        (output_dir / "ServiceScans").mkdir(parents=True, exist_ok=True)

    total = len(state.targets)
    completed_set = set(state.completed)
    # Index-based loop (not enumerate) so that if the scan window closes partway
    # through a host we can wait and then redo that same host, rather than
    # skipping it. A user pause/kill takes the exit path (break) instead.
    idx = 0
    while idx < total:
        host = state.targets[idx]
        if host in completed_set:
            idx += 1
            continue

        # Block here while outside the scheduled scan window; returns at once when
        # no window is configured or we are inside it.
        wait_for_window(state)
        if _pause_requested:
            break

        if custom_args is not None:
            # --custom: skip discovery + service entirely, run the user's scan.
            print(f"\n[{idx + 1}/{total}] {host}: custom scan...")
            try:
                custom_scan_host(host, custom_args, output_dir)
            except Exception as e:
                print(f"    [!] custom scan error: {e}")
                idx += 1  # genuine error — skip this run; resume retries it
                continue
            if _window_paused:
                continue  # window closed mid-scan — redo this host once it reopens
            if _pause_requested:
                break
        else:
            print(f"\n[{idx + 1}/{total}] {host}: discovery scan...")
            try:
                ports = discovery_scan_host(host)
            except Exception as e:
                print(f"    [!] discovery error: {e}")
                idx += 1  # genuine error — skip this run; resume retries it
                continue
            if _window_paused:
                continue  # window closed mid-scan — redo this host once it reopens
            if _pause_requested:
                break

            if ports:
                print(f"    open: {', '.join(str(p) for p in ports)}")
                update_open_ports(host, ports, output_dir)
                print(f"[{idx + 1}/{total}] {host}: service scan on {len(ports)} port(s)...")
                try:
                    service_scan_host(host, ports, output_dir)
                except Exception as e:
                    print(f"    [!] service scan error: {e}")
                    idx += 1  # genuine error — skip this run; resume retries it
                    continue
                if _window_paused:
                    continue  # window closed mid-scan — redo this host once it reopens
            else:
                print(f"    no open ports")

            if _pause_requested:
                break

        completed_set.add(host)
        state.completed.append(host)
        state.save()  # checkpoint: written to disk after EVERY host
        idx += 1

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
        try:
            state.state_file.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()