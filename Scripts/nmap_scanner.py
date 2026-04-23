#!/usr/bin/env python3
"""
nmap wrapper with per-host logging, pause/resume, scheduled start, time limit.

Usage:
    ./nmap_wrapper.py 10.0.0.1 10.0.0.2 example.com    # targets on CLI
    ./nmap_wrapper.py 192.168.1.0/24                    # CIDR
    ./nmap_wrapper.py -iL targets.txt                   # targets from file (like nmap)
    ./nmap_wrapper.py -iL targets.txt 10.0.0.5          # both work together
    ./nmap_wrapper.py 10.0.0.0/24 --time 8h             # 8h then auto-pause
    ./nmap_wrapper.py 10.0.0.0/24 --start 14:46         # wait until 14:46
    ./nmap_wrapper.py --resume 12345                    # resume by old PID
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

# ==================== CONFIGURATION ====================

OUTPUT_BASE = Path("./NMAP_scans")

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
    "-T4",
    "--min-rate=1500"
]

NMAP_BIN = "nmap"
STATE_DIR = Path("/tmp")
# ========================================================

_pause_requested = False
_current_proc = None
_prompting = False


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


# --------------------- nmap process management ---------------------

def check_nmap():
    try:
        subprocess.run([NMAP_BIN, "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        sys.stderr.write(f"[!] nmap not found or not working: {NMAP_BIN}\n")
        sys.exit(1)


def run_nmap(cmd):
    """Run nmap in its own session so Ctrl-C at terminal does not kill it
    directly — we control killing it ourselves from the interrupt handler."""
    global _current_proc
    _current_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    stdout, stderr = _current_proc.communicate()
    rc = _current_proc.returncode if _current_proc.returncode is not None else -1
    _current_proc = None
    return rc, stdout, stderr


def kill_current_proc():
    global _current_proc
    if _current_proc is None or _current_proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(_current_proc.pid), signal.SIGTERM)
        for _ in range(15):
            if _current_proc.poll() is not None:
                return
            time.sleep(0.2)
        os.killpg(os.getpgid(_current_proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# --------------------- scan stages ---------------------

def expand_targets(targets):
    """Use `nmap -sL` to turn CIDRs/ranges into a flat list of IPs."""
    cmd = [NMAP_BIN, "-sL", "-n"] + list(targets)
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    ips = []
    for line in result.stdout.splitlines():
        m = re.match(r"Nmap scan report for (\S+)", line)
        if m:
            ips.append(m.group(1))
    return ips


def discovery_scan_host(host):
    """Full-port discovery on one host. Returns sorted list of open ports."""
    cmd = [NMAP_BIN] + DISCOVERY_ARGS + ["-oG", "-", host]
    _, stdout, _ = run_nmap(cmd)
    if _pause_requested:
        return []
    ports = []
    for line in stdout.splitlines():
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


def update_open_ports(host, ports, output_dir):
    """Append host to OpenPorts/[PORT]/hosts.md — one file per open port."""
    for p in ports:
        port_dir = output_dir / "OpenPorts" / str(p)
        port_dir.mkdir(parents=True, exist_ok=True)
        hosts_file = port_dir / "hosts.md"
        existing = set()
        if hosts_file.exists():
            existing = {l.strip() for l in hosts_file.read_text().splitlines() if l.strip()}
        if host not in existing:
            with open(hosts_file, "a") as f:
                f.write(f"{host}\n")


def service_scan_host(host, ports, output_dir):
    """Service+script scan on the open ports. Writes per-host .nmap/.gnmap/.xml
    and a [host].md copy, then appends to all_hosts.nmap / all_hosts.gnmap."""
    if not ports:
        return
    port_list = ",".join(str(p) for p in ports)
    host_dir = output_dir / "ServiceScans" / "Hosts"
    host_dir.mkdir(parents=True, exist_ok=True)
    host_prefix = host_dir / host  # nmap -oA produces host.nmap/.gnmap/.xml
    cmd = [NMAP_BIN] + SERVICE_ARGS + [
        "-p", port_list,
        "-oA", str(host_prefix),
        host,
    ]
    run_nmap(cmd)
    if _pause_requested:
        # don't commit partial results to the combined logs; we'll retry this host
        return

    nmap_file = host_prefix.with_suffix(".nmap")
    if nmap_file.exists():
        (host_dir / f"{host}.md").write_text(nmap_file.read_text())

    svc_dir = output_dir / "ServiceScans"
    for ext, name in [(".nmap", "all_hosts.nmap"), (".gnmap", "all_hosts.gnmap")]:
        src = host_prefix.with_suffix(ext)
        if not src.exists():
            continue
        with open(svc_dir / name, "a") as out, open(src) as inp:
            out.write(inp.read())
            out.write("\n")


# --------------------- state (for pause/resume) ---------------------

class ScanState:
    def __init__(self, pid=None):
        self.pid = pid if pid is not None else os.getpid()
        self.state_file = STATE_DIR / f"nmap_wrapper_state_{self.pid}.json"
        self.targets = []
        self.completed = []
        self.output_dir = str(OUTPUT_BASE)

    def save(self):
        self.state_file.write_text(json.dumps({
            "targets": self.targets,
            "completed": self.completed,
            "output_dir": self.output_dir,
        }, indent=2))

    @classmethod
    def load(cls, pid):
        s = cls(pid=pid)
        if not s.state_file.exists():
            raise FileNotFoundError(s.state_file)
        data = json.loads(s.state_file.read_text())
        s.targets = data["targets"]
        s.completed = data["completed"]
        s.output_dir = data["output_dir"]
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


# --------------------- main ---------------------

def main():
    ap = argparse.ArgumentParser(
        description="nmap wrapper: per-host logs, pause/resume, scheduled start, time limit.",
    )
    ap.add_argument("targets", nargs="*",
                    help="IP(s), hostname(s), CIDR(s), or range(s) to scan")
    ap.add_argument("-iL", dest="input_file", metavar="FILE",
                    help="read targets from a file (one per line, # comments ok)")
    ap.add_argument("--resume", metavar="PID", type=int,
                    help="resume a paused scan by its original PID")
    ap.add_argument("--time", metavar="DUR", type=parse_duration,
                    help="run for this long then auto-pause (e.g. 30s, 8m, 8h, 2d)")
    ap.add_argument("--start", metavar="HH:MM", type=parse_start_time,
                    help="wait until this wall-clock time before starting")
    args = ap.parse_args()

    check_nmap()

    # --- load/build state ---
    if args.resume is not None:
        if args.targets or args.input_file:
            sys.stderr.write("[!] --resume cannot be combined with targets or -iL\n")
            sys.exit(2)
        try:
            state = ScanState.load(args.resume)
        except FileNotFoundError as e:
            sys.stderr.write(f"[!] no state file for PID {args.resume}: {e}\n")
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
        print(f"[*] Resumed from PID {args.resume}. "
              f"{len(state.completed)}/{len(state.targets)} hosts already done.")
    else:
        raw_targets = list(args.targets)
        if args.input_file:
            try:
                with open(args.input_file) as f:
                    for line in f:
                        line = line.split("#", 1)[0].strip()
                        if line:
                            raw_targets.append(line)
            except OSError as e:
                sys.stderr.write(f"[!] cannot read {args.input_file}: {e}\n")
                sys.exit(1)
        if not raw_targets:
            ap.error("no targets given (pass IPs/hostnames as args, use -iL FILE, or --resume PID)")

        state = ScanState()
        print(f"[*] Expanding {len(raw_targets)} target spec(s)...")
        state.targets = expand_targets(raw_targets)
        print(f"[*] {len(state.targets)} hosts to scan.")
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

    print(f"[*] PID {os.getpid()} — Ctrl-C to pause/kill; "
          f"resume with: {sys.argv[0]} --resume {os.getpid()}")
    print(f"[*] Output: {state.output_dir}")

    install_interrupt_handler()

    output_dir = Path(state.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ServiceScans").mkdir(parents=True, exist_ok=True)

    total = len(state.targets)
    for i, host in enumerate(state.targets, 1):
        if host in state.completed:
            continue
        if _pause_requested:
            break

        print(f"\n[{i}/{total}] {host}: discovery scan...")
        try:
            ports = discovery_scan_host(host)
        except Exception as e:
            print(f"    [!] discovery error: {e}")
            continue
        if _pause_requested:
            break

        if ports:
            print(f"    open: {', '.join(str(p) for p in ports)}")
            update_open_ports(host, ports, output_dir)
            print(f"[{i}/{total}] {host}: service scan on {len(ports)} port(s)...")
            try:
                service_scan_host(host, ports, output_dir)
            except Exception as e:
                print(f"    [!] service scan error: {e}")
        else:
            print(f"    no open ports")

        if _pause_requested:
            break

        state.completed.append(host)
        state.save()  # checkpoint: written to disk after EVERY host

    # --- finish ---
    if _pause_requested:
        state.save()
        print(f"\n[*] Paused. {len(state.completed)}/{len(state.targets)} hosts done.")
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