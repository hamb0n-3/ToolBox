#!/usr/bin/env python3
"""
Minimal nmap wrapper to verify rmi-dumpregistry findings.

Runs nmap's rmi-dumpregistry NSE script against one or more targets and
classifies the result as one of:
  - NO_RMI       : Port closed/filtered, no RMI registry detected
  - EMPTY        : Registry reachable but no bound objects returned
  - CLASSPATH_ONLY : Only classpath/.jar entries returned (low severity)
  - BOUND_OBJECTS  : Real remote objects registered (high severity)
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Hardcoded settings
# ---------------------------------------------------------------------------
RMI_PORT = 1099
NMAP_BINARY = "nmap"
NMAP_ARGS = [
    "-Pn",                       # Skip host discovery
    "-n",                        # No DNS resolution
    "-p", str(RMI_PORT),         # Default RMI registry port
    "--script", "rmi-dumpregistry",
    "--script-timeout", "60s",
    "--host-timeout", "120s",
    "-oN", "-",                  # Normal output to stdout
]

# Regex to detect classpath/.jar-only entries in script output
JAR_LINE_RE = re.compile(r"\.jar\b", re.IGNORECASE)
# Lines that indicate a real bound RMI object (e.g., "Registered objects:")
BOUND_OBJECT_HINTS = ("extends:", "@", "implements")

# ---------------------------------------------------------------------------


def run_nmap(target: str) -> str:
    """Run nmap against a single target and return stdout."""
    cmd = [NMAP_BINARY, *NMAP_ARGS, target]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
    except FileNotFoundError:
        sys.exit(f"[!] '{NMAP_BINARY}' not found. Install nmap and retry.")
    except subprocess.TimeoutExpired:
        return ""
    return result.stdout


def classify(output: str) -> tuple[str, list[str]]:
    """
    Classify rmi-dumpregistry output.
    Returns (verdict, evidence_lines).
    """
    if "rmi-dumpregistry" not in output:
        # Script didn't run — probably port closed/filtered
        if f"{RMI_PORT}/tcp" in output and "open" in output:
            return "EMPTY", []
        return "NO_RMI", []

    # Extract the script output block
    lines = output.splitlines()
    script_lines: list[str] = []
    in_script = False
    for line in lines:
        if "rmi-dumpregistry" in line:
            in_script = True
            continue
        if in_script:
            # Script blocks are indented; blank or new section ends them
            if line.startswith("|") or line.startswith("| "):
                script_lines.append(line.lstrip("| ").rstrip())
            elif line.strip() == "":
                continue
            else:
                in_script = False

    content_lines = [ln for ln in script_lines if ln.strip()]

    if not content_lines:
        return "EMPTY", []

    # Look for indicators of real bound objects
    has_bound_object = any(
        any(hint in ln for hint in BOUND_OBJECT_HINTS) for ln in content_lines
    )
    has_jars = any(JAR_LINE_RE.search(ln) for ln in content_lines)
    only_jars = has_jars and not has_bound_object

    if has_bound_object and not only_jars:
        return "BOUND_OBJECTS", content_lines
    if only_jars:
        return "CLASSPATH_ONLY", content_lines
    return "BOUND_OBJECTS", content_lines  # default to higher severity if unsure


def severity_for(verdict: str) -> str:
    return {
        "NO_RMI": "None",
        "EMPTY": "Low (exposed registry, no objects)",
        "CLASSPATH_ONLY": "Low/Medium (path disclosure only)",
        "BOUND_OBJECTS": "High/Critical (deserialization risk)",
    }.get(verdict, "Unknown")


def load_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.iL:
        path = Path(args.iL)
        if not path.is_file():
            sys.exit(f"[!] Target list not found: {path}")
        targets.extend(
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        )
    targets.extend(args.targets)
    if not targets:
        sys.exit("[!] No targets provided. Pass IPs/domains or use -iL FILE.")
    return targets


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify rmi-dumpregistry findings via nmap."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="One or more IPs/hostnames",
    )
    parser.add_argument(
        "-iL",
        metavar="FILE",
        help="Input file with targets (one per line), like nmap -iL",
    )
    args = parser.parse_args()

    if not shutil.which(NMAP_BINARY):
        sys.exit(f"[!] '{NMAP_BINARY}' not in PATH.")

    targets = load_targets(args)

    print(f"[*] Scanning {len(targets)} target(s) on tcp/{RMI_PORT}\n")
    for target in targets:
        print(f"=== {target} ===")
        output = run_nmap(target)
        verdict, evidence = classify(output)
        print(f"Verdict : {verdict}")
        print(f"Severity: {severity_for(verdict)}")
        if evidence:
            print("Evidence:")
            for line in evidence:
                print(f"  {line}")
        print()


if __name__ == "__main__":
    main()