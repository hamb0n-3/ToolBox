#!/usr/bin/env python3
"""
Parse nmap .gnmap output and create OpenPorts/[PORT]/hosts.md structure.
Usage: python gnmap_parser.py <file.gnmap> [file2.gnmap ...]
       python gnmap_parser.py *.gnmap
"""

import re
import sys
from pathlib import Path
from collections import defaultdict

def parse_gnmap(filepath):
    port_hosts = defaultdict(set)

    with open(filepath) as f:
        for line in f:
            if not line.startswith("Host:"):
                continue

            ip_match = re.search(r"Host:\s+(\S+)", line)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            ports = re.findall(r"(\d+)/open/", line)
            for port in ports:
                port_hosts[port].add(ip)

    return port_hosts

def write_structure(port_hosts, base_dir="OpenPorts"):
    base = Path(base_dir)

    for port, hosts in sorted(port_hosts.items(), key=lambda x: int(x[0])):
        port_dir = base / port
        port_dir.mkdir(parents=True, exist_ok=True)

        hosts_file = port_dir / "hosts.md"

        existing = set()
        if hosts_file.exists():
            existing = {line.strip() for line in hosts_file.read_text().splitlines() if line.strip()}

        new_hosts = hosts - existing
        all_hosts = existing | hosts

        with open(hosts_file, "w") as f:
            for host in sorted(all_hosts):
                f.write(f"{host}\n")

        if new_hosts:
            print(f"[+] Port {port:>5} — added {len(new_hosts)} new host(s), {len(all_hosts)} total → {hosts_file}")
        else:
            print(f"[=] Port {port:>5} — no new hosts ({len(all_hosts)} existing) → {hosts_file}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.gnmap> [file2.gnmap ...]")
        sys.exit(1)

    combined = defaultdict(set)

    for filepath in sys.argv[1:]:
        result = parse_gnmap(filepath)
        print(f"[*] Parsed {filepath}: {len(result)} port(s) with open hosts")
        for port, hosts in result.items():
            combined[port] |= hosts

    if not combined:
        print("No open ports found.")
        sys.exit(0)

    write_structure(combined)
    print(f"\nDone. {len(combined)} unique port(s) written to OpenPorts/")

if __name__ == "__main__":
    main()