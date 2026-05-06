#!/usr/bin/env python3
"""
RMI Registry Exposure Verification Tool

Wraps nmap's rmi-dumpregistry NSE script, classifies the result for each
target, and emits a professional pentest-style markdown report.
"""

import argparse
import datetime as dt
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Hardcoded settings
# ---------------------------------------------------------------------------
RMI_PORT = 1099
NMAP_BINARY = "nmap"
NMAP_ARGS = [
    "-Pn",                           # Skip host discovery
    "-n",                            # No DNS resolution
    "-p", str(RMI_PORT),
    "--script", "rmi-dumpregistry",
    "--script-timeout", "60s",
    "--host-timeout", "180s",
    "-oX", "-",                      # XML to stdout (reliable parsing)
]
SUBPROCESS_TIMEOUT = 240
DEFAULT_REPORT_DIR = Path("./reports")

# Verdict -> (severity, short_label, cvss_estimate)
VERDICT_META = {
    "NO_RMI":          ("Informational", "RMI registry not exposed",                  "N/A"),
    "ERROR":           ("Informational", "Registry reachable but enumeration failed", "3.1"),
    "EMPTY":           ("Low",           "Registry exposed without bound objects",    "3.7"),
    "CLASSPATH_ONLY":  ("Medium",        "Registry exposes classpath/path data only", "5.3"),
    "BOUND_OBJECTS":   ("High",          "Registry exposes bound remote objects",     "7.5"),
}

# Detection patterns
JAR_OR_FILE_RE = re.compile(r"\.jar\b|file:/", re.IGNORECASE)
CLASS_REF_RE = re.compile(r"\b(?:[a-z][a-z0-9_]*\.){2,}[A-Z][A-Za-z0-9_$]+")  # e.g. java.rmi.server.RemoteStub
ENDPOINT_RE = re.compile(r"@[\w.\-]+:\d{2,5}")                                # e.g. @host:42997
BOUND_KEYWORDS = ("extends", "implements", "Stub", "Remote")
ERROR_KEYWORDS = (
    "Registry listing failed",
    "Handshake failed",
    "ERROR:",
    "TIMEOUT",
    "Connection refused",
)

# ---------------------------------------------------------------------------


@dataclass
class HostResult:
    target: str
    address: str = ""
    port_state: str = "unknown"
    script_output: str = ""
    verdict: str = "NO_RMI"
    bound_objects: list[str] = field(default_factory=list)
    classpath_entries: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def severity(self) -> str:
        return VERDICT_META[self.verdict][0]

    @property
    def label(self) -> str:
        return VERDICT_META[self.verdict][1]

    @property
    def cvss(self) -> str:
        return VERDICT_META[self.verdict][2]


# ---------------------------------------------------------------------------
# nmap execution + XML parsing
# ---------------------------------------------------------------------------


def run_nmap(target: str) -> str:
    cmd = [NMAP_BINARY, *NMAP_ARGS, target]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=SUBPROCESS_TIMEOUT,
        )
    except FileNotFoundError:
        sys.exit(f"[!] '{NMAP_BINARY}' not found in PATH.")
    except subprocess.TimeoutExpired:
        return ""
    return proc.stdout


def parse_nmap_xml(xml_text: str, target: str) -> HostResult:
    result = HostResult(target=target)
    if not xml_text.strip():
        result.error = "nmap produced no output (timeout or failure)"
        return result

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        result.error = f"XML parse error: {exc}"
        return result

    host = root.find("host")
    if host is None:
        return result

    addr_el = host.find("address")
    if addr_el is not None:
        result.address = addr_el.get("addr", "")

    port = host.find(f".//port[@portid='{RMI_PORT}']")
    if port is None:
        return result

    state_el = port.find("state")
    if state_el is not None:
        result.port_state = state_el.get("state", "unknown")

    script = port.find("script[@id='rmi-dumpregistry']")
    if script is not None:
        result.script_output = (script.get("output") or "").strip()

    return result


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def classify(result: HostResult) -> None:
    output = result.script_output

    if not output:
        result.verdict = "EMPTY" if result.port_state == "open" else "NO_RMI"
        return

    if any(k in output for k in ERROR_KEYWORDS):
        result.verdict = "ERROR"
        result.error = output.splitlines()[0][:200]
        return

    has_bound = False
    has_jar = False
    bound_lines: list[str] = []
    jar_lines: list[str] = []

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue

        is_class_ref = bool(CLASS_REF_RE.search(line))
        is_endpoint = bool(ENDPOINT_RE.search(line))
        is_keyword = any(kw in line for kw in BOUND_KEYWORDS)
        is_jar = bool(JAR_OR_FILE_RE.search(line))

        if (is_class_ref or is_endpoint or is_keyword) and not (is_jar and not is_class_ref):
            has_bound = True
            bound_lines.append(line)
        elif is_jar:
            has_jar = True
            jar_lines.append(line)

    result.bound_objects = bound_lines
    result.classpath_entries = jar_lines

    if has_bound:
        result.verdict = "BOUND_OBJECTS"
    elif has_jar:
        result.verdict = "CLASSPATH_ONLY"
    else:
        result.verdict = "EMPTY"


# ---------------------------------------------------------------------------
# Markdown report generation
# ---------------------------------------------------------------------------


SEVERITY_ORDER = ["High", "Medium", "Low", "Informational"]


def build_report(results: list[HostResult], started: dt.datetime, ended: dt.datetime) -> str:
    md: list[str] = []
    md.append("# RMI Registry Exposure Assessment Report")
    md.append("")
    md.append(f"**Report Generated:** {ended.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    md.append(f"**Scan Started:** {started.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    md.append(f"**Scan Duration:** {(ended - started).total_seconds():.1f} seconds  ")
    md.append(f"**Targets Assessed:** {len(results)}  ")
    md.append(f"**Service Tested:** Java RMI Registry (TCP/{RMI_PORT})  ")
    md.append(f"**Tool:** nmap NSE `rmi-dumpregistry`")
    md.append("")
    md.append("---")
    md.append("")

    md.append("## 1. Executive Summary")
    md.append("")
    md.append(
        "This assessment evaluated the exposure of the Java Remote Method Invocation "
        "(RMI) registry on a defined set of targets. The RMI registry is a well-known "
        "vector for Java deserialization attacks and information disclosure when "
        "exposed without authentication. Each target was probed with nmap's "
        "`rmi-dumpregistry` script and classified by the nature of the data returned."
    )
    md.append("")

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        severity_counts[r.severity] += 1

    md.append("### 1.1 Severity Distribution")
    md.append("")
    md.append("| Severity | Count |")
    md.append("|----------|-------|")
    for sev in SEVERITY_ORDER:
        md.append(f"| {sev} | {severity_counts[sev]} |")
    md.append("")

    md.append("### 1.2 Findings Summary")
    md.append("")
    md.append("| # | Target | Resolved Address | Port State | Verdict | Severity |")
    md.append("|---|--------|------------------|------------|---------|----------|")
    for i, r in enumerate(results, 1):
        md.append(
            f"| {i} | `{r.target}` | `{r.address or '-'}` | {r.port_state} | "
            f"{r.verdict} | {r.severity} |"
        )
    md.append("")
    md.append("---")
    md.append("")

    md.append("## 2. Methodology")
    md.append("")
    md.append("Each target was scanned with the following nmap invocation:")
    md.append("")
    md.append("```bash")
    md.append(f"nmap {' '.join(NMAP_ARGS)} <target>")
    md.append("```")
    md.append("")
    md.append("Results were classified using the following rubric:")
    md.append("")
    md.append("| Verdict | Definition | Severity | CVSS (est.) |")
    md.append("|---------|------------|----------|-------------|")
    for v, (sev, label, cvss) in VERDICT_META.items():
        md.append(f"| `{v}` | {label} | {sev} | {cvss} |")
    md.append("")
    md.append(
        "- **BOUND_OBJECTS** is identified by the presence of fully-qualified Java "
        "class references (e.g. `javax.management.remote.rmi.RMIServerImpl_Stub`), "
        "remote endpoint annotations (`@host:port`), or RMI keywords "
        "(`extends`, `implements`, `Stub`, `Remote`)."
    )
    md.append(
        "- **CLASSPATH_ONLY** is identified when only `.jar` filenames or `file:/` "
        "URLs appear in the registry output, with no class or endpoint references."
    )
    md.append(
        "- **EMPTY** indicates the registry port is reachable but no usable data "
        "was returned by the script."
    )
    md.append("- **ERROR** indicates a handshake or protocol error during enumeration.")
    md.append("- **NO_RMI** indicates the port is closed or filtered.")
    md.append("")
    md.append("---")
    md.append("")

    md.append("## 3. Detailed Findings")
    md.append("")

    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    ordered = sorted(results, key=lambda r: (severity_rank[r.severity], r.target))

    for idx, r in enumerate(ordered, 1):
        md.append(f"### 3.{idx} {r.target}")
        md.append("")
        md.append(f"- **Resolved Address:** `{r.address or 'unresolved'}`")
        md.append(f"- **Port:** `{RMI_PORT}/tcp` ({r.port_state})")
        md.append(f"- **Verdict:** `{r.verdict}` — {r.label}")
        md.append(f"- **Severity:** {r.severity}")
        md.append(f"- **CVSS (estimate):** {r.cvss}")
        md.append("")

        md.append("#### Description")
        md.append("")
        md.append(_description_for(r.verdict))
        md.append("")

        if r.script_output:
            md.append("#### Evidence")
            md.append("")
            md.append("Raw output from `rmi-dumpregistry`:")
            md.append("")
            md.append("```")
            md.append(r.script_output)
            md.append("```")
            md.append("")

        if r.bound_objects:
            md.append("**Detected bound object indicators:**")
            md.append("")
            for line in r.bound_objects[:25]:
                md.append(f"- `{line}`")
            if len(r.bound_objects) > 25:
                md.append(f"- _… {len(r.bound_objects) - 25} additional line(s) suppressed_")
            md.append("")

        if r.classpath_entries:
            md.append("**Detected classpath / file references:**")
            md.append("")
            for line in r.classpath_entries[:25]:
                md.append(f"- `{line}`")
            if len(r.classpath_entries) > 25:
                md.append(f"- _… {len(r.classpath_entries) - 25} additional line(s) suppressed_")
            md.append("")

        if r.error:
            md.append("#### Errors")
            md.append("")
            md.append(f"```\n{r.error}\n```")
            md.append("")

        md.append("#### Impact")
        md.append("")
        md.append(_impact_for(r.verdict))
        md.append("")

        md.append("#### Recommendation")
        md.append("")
        md.append(_recommendation_for(r.verdict))
        md.append("")
        md.append("---")
        md.append("")

    md.append("## 4. References")
    md.append("")
    md.append("- Oracle, *Java RMI Specification*: "
              "<https://docs.oracle.com/javase/8/docs/platform/rmi/spec/rmiTOC.html>")
    md.append("- Oracle, *Secure Coding Guidelines for Java SE — RMI*: "
              "<https://www.oracle.com/java/technologies/javase/seccodeguide.html>")
    md.append("- Nmap NSE, *rmi-dumpregistry*: "
              "<https://nmap.org/nsedoc/scripts/rmi-dumpregistry.html>")
    md.append("- CWE-502, *Deserialization of Untrusted Data*: "
              "<https://cwe.mitre.org/data/definitions/502.html>")
    md.append("- ysoserial, *Java deserialization payload generator*: "
              "<https://github.com/frohoff/ysoserial>")
    md.append("")

    return "\n".join(md)


def _description_for(verdict: str) -> str:
    return {
        "BOUND_OBJECTS": (
            "The Java RMI registry on this host returned one or more bound remote "
            "objects with their fully-qualified class names and/or remote endpoints. "
            "This is the most exploitable RMI registry state: an attacker can "
            "interact with these objects directly and is positioned to attempt Java "
            "deserialization attacks against the underlying server."
        ),
        "CLASSPATH_ONLY": (
            "The Java RMI registry on this host returned only classpath or file-path "
            "references (`.jar` files or `file:/` URLs). No bound remote objects "
            "were enumerated. While the immediate deserialization attack surface is "
            "reduced, the host is still leaking internal file system paths and "
            "library names that aid an attacker during reconnaissance."
        ),
        "EMPTY": (
            "The Java RMI registry port is reachable, but the registry either has "
            "no objects bound or refused to enumerate them. The port should not be "
            "exposed to untrusted networks regardless of current contents, since "
            "applications may bind objects at runtime."
        ),
        "ERROR": (
            "The registry was reachable but enumeration failed during the RMI "
            "handshake. This may indicate a non-standard service on the port, a "
            "TLS-wrapped registry, or partial filtering. Manual verification is "
            "recommended."
        ),
        "NO_RMI": (
            "No RMI registry was detected on this host. The port is closed, "
            "filtered, or not running an RMI service."
        ),
    }[verdict]


def _impact_for(verdict: str) -> str:
    return {
        "BOUND_OBJECTS": (
            "An unauthenticated attacker on the network can invoke methods on the "
            "exposed remote objects and submit crafted serialized payloads. If a "
            "vulnerable gadget chain exists in the server's classpath (commonly "
            "true for legacy stacks such as JBoss, WebLogic, WebSphere, and "
            "applications using vulnerable versions of Apache Commons-Collections), "
            "this can lead directly to **Remote Code Execution** with the privileges "
            "of the Java process."
        ),
        "CLASSPATH_ONLY": (
            "An attacker gains reconnaissance value: deployed library names and "
            "version hints, internal file system layout, and indirect confirmation "
            "that an RMI-capable service is present. This information accelerates "
            "targeted follow-on attacks but does not, on its own, grant code "
            "execution."
        ),
        "EMPTY": (
            "Information disclosure is minimal at the moment of testing, but the "
            "exposed registry port violates least-privilege network principles and "
            "creates a window for exploitation if objects are bound at runtime."
        ),
        "ERROR": (
            "Impact cannot be confirmed without manual verification. Treat the "
            "exposure as unverified until the service has been identified."
        ),
        "NO_RMI": "No impact identified.",
    }[verdict]


def _recommendation_for(verdict: str) -> str:
    if verdict == "NO_RMI":
        return "No action required."
    base = [
        f"Restrict TCP/{RMI_PORT} (and dynamically-allocated RMI object ports) to "
        "trusted management networks only via host- or network-level firewall rules.",
        "Set the JVM property `java.rmi.server.useCodebaseOnly=true` to prevent "
        "remote codebase loading.",
        "Where RMI is required across trust boundaries, enforce TLS and "
        "authentication using `javax.rmi.ssl.SslRMIClientSocketFactory` / "
        "`SslRMIServerSocketFactory` and an `RMIServerSocketFactory` that requires "
        "client certificates.",
        "Audit the application's classpath for known deserialization gadget "
        "libraries (e.g. vulnerable versions of Apache Commons-Collections) and "
        "upgrade or remove them.",
        "Consider migrating away from RMI to a modern, authenticated RPC protocol "
        "(gRPC, REST/HTTPS) where feasible.",
    ]
    if verdict in ("CLASSPATH_ONLY", "EMPTY", "ERROR"):
        base.insert(0, "Confirm whether the RMI registry is required externally; "
                       "if not, disable the listener entirely.")
    return "\n".join(f"- {item}" for item in base)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def load_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.iL:
        path = Path(args.iL)
        if not path.is_file():
            sys.exit(f"[!] Target list not found: {path}")
        targets.extend(
            ln.strip()
            for ln in path.read_text().splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        )
    targets.extend(args.targets)
    seen: set[str] = set()
    deduped: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    if not deduped:
        sys.exit("[!] No targets provided. Pass IPs/hostnames or use -iL FILE.")
    return deduped


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify and report on RMI registry exposures using nmap.",
    )
    parser.add_argument("targets", nargs="*", help="One or more IPs/hostnames")
    parser.add_argument("-iL", metavar="FILE",
                        help="Input file with targets (one per line), like nmap -iL")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Path to write the markdown report (default: ./reports/<timestamp>.md)")
    parser.add_argument("--stdout", action="store_true",
                        help="Also print the full markdown report to stdout")
    args = parser.parse_args()

    if not shutil.which(NMAP_BINARY):
        sys.exit(f"[!] '{NMAP_BINARY}' not in PATH.")

    targets = load_targets(args)
    print(f"[*] Scanning {len(targets)} target(s) on tcp/{RMI_PORT}", file=sys.stderr)

    started = dt.datetime.utcnow()
    results: list[HostResult] = []
    for t in targets:
        print(f"[*] {t} ...", file=sys.stderr, flush=True)
        xml_out = run_nmap(t)
        result = parse_nmap_xml(xml_out, t)
        classify(result)
        results.append(result)
        print(f"    -> {result.verdict} ({result.severity})", file=sys.stderr)
    ended = dt.datetime.utcnow()

    report = build_report(results, started, ended)

    if args.output:
        out_path = Path(args.output)
    else:
        DEFAULT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = ended.strftime("%Y%m%d-%H%M%S")
        out_path = DEFAULT_REPORT_DIR / f"rmi-report-{stamp}.md"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report)
    print(f"\n[+] Report written to: {out_path}", file=sys.stderr)

    if args.stdout:
        print(report)


if __name__ == "__main__":
    main()