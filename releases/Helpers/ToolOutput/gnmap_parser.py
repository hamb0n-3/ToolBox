#!/usr/bin/env python3
"""
Parse nmap .gnmap output and create OpenPorts/[PORT]/hosts.md structure.
Usage: python parse_gnmap.py <file.gnmap>
"""

import re
import sys
from pathlib import Path
from collections import defaultdict

def parse_gnmap(filepath):
    port_hosts = defaultdict(list)

    with open(filepath) as f:
        for line in f:
            if not line.startswith("Host:"):
                continue

            # Extract IP
            ip_match = re.search(r"Host:\s+(\S+)", line)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            # Extract open ports
            ports = re.findall(r"(\d+)/open/", line)
            for port in ports:
                port_hosts[port].append(ip)

    return port_hosts

def write_structure(port_hosts, base_dir="OpenPorts"):
    base = Path(base_dir)

    for port, hosts in sorted(port_hosts.items(), key=lambda x: int(x[0])):
        port_dir = base / port
        port_dir.mkdir(parents=True, exist_ok=True)

        hosts_file = port_dir / "hosts.md"
        with open(hosts_file, "w") as f:
            for host in sorted(hosts):
                f.write(f"{host}\n")

        print(f"[+] Port {port:>5} — {len(hosts)} host(s) → {hosts_file}")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file.gnmap>")
        sys.exit(1)

    port_hosts = parse_gnmap(sys.argv[1])

    if not port_hosts:
        print("No open ports found.")
        sys.exit(0)

    write_structure(port_hosts)
    print(f"\nDone. {len(port_hosts)} unique port(s) written to OpenPorts/")

if __name__ == "__main__":
    main()