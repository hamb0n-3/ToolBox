#!/usr/bin/env python3
"""
Parse nmap .gnmap output and report hosts running OpenSSH < 10.3.
Requires a version scan (-sV) to have been run.
Usage: python parse_ssh_versions.py <file.gnmap>
"""

import re
import sys
from packaging.version import Version

# Matches: 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu.../
SSH_PORT_RE = re.compile(
    r"(\d+)/open/tcp//ssh//([^/]*OpenSSH[^/]*)/",
    re.IGNORECASE
)

# Extracts the numeric version from e.g. "OpenSSH 8.9p1 Ubuntu 3ubuntu0.6"
VERSION_RE = re.compile(r"OpenSSH\s+(\d+\.\d+)", re.IGNORECASE)

TARGET = Version("10.3")


def parse_gnmap(filepath):
    vulnerable = []

    with open(filepath) as f:
        for line in f:
            if not line.startswith("Host:"):
                continue

            ip_match = re.search(r"Host:\s+(\S+)", line)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            for port, banner in SSH_PORT_RE.findall(line):
                ver_match = VERSION_RE.search(banner)
                if not ver_match:
                    continue

                ver_str = ver_match.group(1)
                try:
                    ver = Version(ver_str)
                except Exception:
                    continue

                if ver < TARGET:
                    vulnerable.append((ip, port, banner.strip()))

    return vulnerable


def write_output(results, out_dir="OpenSSH_10.3_RCE"):
    from pathlib import Path

    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)

    # nmap.output — tabular view
    nmap_file = base / "nmap.output"
    lines = [f"Hosts running OpenSSH < 10.3 ({len(results)} found)\n"]
    lines.append(f"{'IP':<18} {'PORT':<8} BANNER")
    lines.append("-" * 60)
    for ip, port, banner in sorted(results):
        lines.append(f"{ip:<18} {port:<8} {banner}")
    content = "\n".join(lines) + "\n"

    with open(nmap_file, "w") as f:
        f.write(content)

    # hosts.md — plain IP list
    hosts_file = base / "hosts.md"
    with open(hosts_file, "w") as f:
        for ip, _, _ in sorted(results):
            f.write(f"{ip}\n")

    print(content)
    print(f"[+] {nmap_file}")
    print(f"[+] {hosts_file}")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file.gnmap>")
        sys.exit(1)

    results = parse_gnmap(sys.argv[1])

    if not results:
        print("No hosts found running OpenSSH < 10.3.")
        sys.exit(0)

    write_output(results)


if __name__ == "__main__":
    main()