#!/usr/bin/env python3
"""Import nmap .gnmap / .nmap output into an engagement DB.

Fills the engagement's hosts + open_ports tables from existing nmap output, so
scans run outside nmap_scanner.py (or from other engagements) can be folded into
one engagement database.

Usage:
    ./nmap_import.py --db engagement.db scan.gnmap [more.nmap ...]
    ./nmap_import.py --db ./ results/*.gnmap            # new/!default DB in ./
    ./nmap_import.py --db eng.db --status pending scan.nmap   # don't mark scanned

By default imported hosts are marked 'completed' (so a resumed scan skips them).
Pass --status pending to record their ports without claiming they're scanned.

Only run this against data you are authorized to handle.
"""

import argparse
import re
import sys
from pathlib import Path

from engagement_db import EngagementDB


# --------------------- parsers ---------------------

def parse_gnmap(text):
    """Parse greppable (.gnmap) output into {ip: [(port, proto, service)]}."""
    results = {}
    for line in text.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        parts = line.split()
        ip = parts[1]
        # The Ports section is a tab-delimited field; take just that field.
        section = line.split("Ports:", 1)[1].split("\t")[0]
        ports = []
        for entry in section.split(","):
            # fields: port / state / proto / owner / service / rpc / version
            f = entry.strip().split("/")
            if len(f) >= 3 and f[1] == "open":
                try:
                    port = int(f[0])
                except ValueError:
                    continue
                proto = f[2] or "tcp"
                svc = f[4] if len(f) > 4 and f[4] else None
                ports.append((port, proto, svc))
        results.setdefault(ip, [])
        results[ip].extend(ports)
    return results


def parse_nmap(text):
    """Parse normal (.nmap) output into {ip: [(port, proto, service)]}."""
    results = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r"Nmap scan report for (.+)", line)
        if m:
            target = m.group(1).strip()
            # "hostname (1.2.3.4)" -> prefer the IP in parentheses.
            ip_m = re.search(r"\(([0-9A-Fa-f:.]+)\)\s*$", target)
            cur = ip_m.group(1) if ip_m else target
            results.setdefault(cur, [])
            continue
        if cur is None:
            continue
        # "22/tcp   open  ssh   OpenSSH 8.4" — version (rest) is optional.
        pm = re.match(r"(\d+)/(\w+)\s+open\s+(\S+)", line)
        if pm:
            results[cur].append((int(pm.group(1)), pm.group(2), pm.group(3)))
    return results


def parse_file(path):
    """Pick a parser by extension, falling back to sniffing the content."""
    text = Path(path).read_text(errors="replace")
    suffix = Path(path).suffix.lower()
    if suffix == ".gnmap":
        return parse_gnmap(text)
    if suffix == ".nmap":
        return parse_nmap(text)
    # Unknown extension: sniff. Greppable has "Host: ... Ports:" lines.
    if re.search(r"^Host:.*Ports:", text, re.MULTILINE):
        return parse_gnmap(text)
    return parse_nmap(text)


# --------------------- main ---------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", metavar="FILE",
                    help="nmap .gnmap or .nmap output files to import")
    ap.add_argument("--db", required=True, metavar="PATH",
                    help="engagement DB to import into (created if it doesn't "
                         "exist; a directory/'.' uses engagement.db inside it)")
    ap.add_argument("--status", choices=("completed", "pending"), default="completed",
                    help="status to record imported hosts with (default: "
                         "completed, so a resumed scan skips them)")
    args = ap.parse_args()

    db_path = EngagementDB.resolve_path(args.db, for_new=True)
    db = EngagementDB.connect(db_path, create=True)
    print(f"[*] Engagement DB: {db.path}")

    grand_hosts = 0
    grand_ports = 0
    for f in args.files:
        if not Path(f).exists():
            sys.stderr.write(f"[!] no such file: {f}\n")
            continue
        try:
            host_ports = parse_file(f)
        except OSError as e:
            sys.stderr.write(f"[!] cannot read {f}: {e}\n")
            continue

        source = f"import:{Path(f).name}"
        n_ports = 0
        # One transaction per file: set host status + record its ports, commit once.
        for ip, ports in host_ports.items():
            db.set_host_status(ip, args.status, commit=False)
            if ports:
                db.record_open_ports(ip, ports, source, commit=False)
                n_ports += len(ports)
        db.commit()

        grand_hosts += len(host_ports)
        grand_ports += n_ports
        print(f"[*] {f}: {len(host_ports)} hosts, {n_ports} open ports "
              f"(status={args.status})")

    done, total = db.counts()
    print(f"[*] Imported {grand_hosts} host record(s), {grand_ports} port record(s).")
    print(f"[*] Engagement now: {done}/{total} hosts completed.")
    db.close()


if __name__ == "__main__":
    main()
