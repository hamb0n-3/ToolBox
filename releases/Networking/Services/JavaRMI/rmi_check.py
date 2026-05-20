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
NMAP_BINARY = "nmap"
RMG_DOCKER_IMAGE = "ghcr.io/qtc-de/remote-method-guesser/rmg:v5.1.0"
RMG_TIMEOUT = 120  # seconds per rmg action

# Default ports scanned. Includes the NSE script's native portrule set
# (1090, 1098, 1099, 8901, 8902, 8903) plus 5111 which is commonly used
# by Spring's RmiServiceExporter and other custom RMI deployments.
# Override at runtime with -p / --ports.
DEFAULT_RMI_PORTS = "1090,1098,1099,5111,8901,8902,8903"

NMAP_BASE_ARGS = [
    "-Pn",                              # Skip host discovery
    "-sV",                              # Service/version detection — required:
                                        # rmi-dumpregistry produces a fuller
                                        # dump when -sV has already
                                        # fingerprinted the service as Java
                                        # RMI; without it the script can fire
                                        # on the port alone and return
                                        # partial output (or nothing useful).
    "--script", "rmi-dumpregistry",
    "--min-rate=1500",
    "-T4",
    "--open"
]
SUBPROCESS_TIMEOUT = 600  # 10 minutes per host. Generous — only fires if
                          # nmap genuinely hangs.
DEFAULT_REPORT_DIR = Path("./reports")


def build_nmap_args(ports: str) -> list[str]:
    """Return the full nmap argv list for the given port spec."""
    return ["-p", ports, *NMAP_BASE_ARGS]

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
    port: str = ""
    port_state: str = "unknown"
    script_output: str = ""
    verdict: str = "NO_RMI"
    bound_objects: list[str] = field(default_factory=list)
    classpath_entries: list[str] = field(default_factory=list)
    error: str = ""
    rmg_enum_output: str = ""
    rmg_guess_output: str = ""
    rmg_security_checks: dict[str, str] = field(default_factory=dict)

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


def run_nmap(target: str, ports: str) -> tuple[str, str]:
    """
    Run nmap and capture BOTH outputs by writing to temp files.

    Returns (xml_text, normal_text). Either may be empty on failure.

    Both outputs are written to temp files (not piped through stdout).
    Using '-oN -' (normal output to stdout) alongside '-oX <file>' caused
    empty output on some nmap versions due to pipe-buffering interactions
    when stdout is a subprocess pipe.
    """
    import tempfile, os

    xml_fd, xml_path = tempfile.mkstemp(suffix=".xml")
    nrm_fd, nrm_path = tempfile.mkstemp(suffix=".nmap")
    os.close(xml_fd)
    os.close(nrm_fd)

    cmd = [
        NMAP_BINARY,
        "-p", ports,
        *NMAP_BASE_ARGS,
        "-oX", xml_path,
        "-oN", nrm_path,
        target,
    ]
    try:
        try:
            subprocess.run(
                cmd,
                check=False,
                timeout=SUBPROCESS_TIMEOUT,
            )
        except FileNotFoundError:
            sys.exit(f"[!] '{NMAP_BINARY}' not found in PATH.")
        except subprocess.TimeoutExpired:
            return "", ""

        try:
            xml_text = Path(xml_path).read_text(errors="replace")
        except OSError:
            xml_text = ""
        try:
            normal_text = Path(nrm_path).read_text(errors="replace")
        except OSError:
            normal_text = ""

        return xml_text, normal_text
    finally:
        for p in (xml_path, nrm_path):
            try:
                Path(p).unlink()
            except OSError:
                pass


def extract_script_block_from_normal(normal_text: str, script_id: str = "rmi-dumpregistry") -> str:
    """
    Pull the lines belonging to a specific NSE script out of nmap's normal
    (-oN) output. The format looks like:

        | <script_id>: 
        |   line one
        |   line two
        |_  last line

    Returns the de-prefixed text content, or '' if the block isn't present.
    """
    lines = normal_text.splitlines()
    collected: list[str] = []
    in_block = False
    header_re = re.compile(rf"^\|[_ ]?\s*{re.escape(script_id)}\s*:\s*(.*)$")

    for raw in lines:
        if not in_block:
            m = header_re.match(raw)
            if m:
                in_block = True
                trailing = m.group(1).strip()
                if trailing:
                    collected.append(trailing)
            continue

        # In-block: lines start with '|' or '|_' until the next non-pipe line
        if raw.startswith("|"):
            # strip leading '|', '_', and a single space if present
            content = raw[1:]
            if content.startswith("_"):
                content = content[1:]
            if content.startswith(" "):
                content = content[1:]
            collected.append(content.rstrip())
            # '|_' marks the last line of the block
            if raw.startswith("|_"):
                break
        else:
            break

    return "\n".join(collected).strip()


def _extract_script_text(script_el: ET.Element) -> str:
    """
    Pull human-readable text out of a <script> element.

    Strategy: combine THREE sources so we never lose data:
      1. The `output` attribute (stdnse.format_output text).
      2. A keyed walk of <elem>/<table> descendants.
      3. A flat `itertext()` dump as a last-resort fallback for cases where
         non-keyed structured data slips past the keyed walk.
    Duplication across sources is harmless — the regex classifier doesn't
    care if a `file:/` URL appears more than once.
    """
    parts: list[str] = []

    output_attr = (script_el.get("output") or "").strip()
    if output_attr:
        parts.append(output_attr)

    structured: list[str] = []

    def walk(el: ET.Element, depth: int) -> None:
        for child in el:
            indent = "  " * depth
            if child.tag == "elem":
                key = child.get("key", "")
                text = (child.text or "").strip()
                if text:
                    structured.append(f"{indent}{key}: {text}" if key else f"{indent}{text}")
            elif child.tag == "table":
                key = child.get("key", "")
                if key:
                    structured.append(f"{indent}{key}")
                walk(child, depth + 1)

    walk(script_el, 0)
    if structured:
        parts.append("\n".join(structured))

    # Fallback: flat dump of every text node beneath the script element.
    flat = " ".join(t.strip() for t in script_el.itertext() if t and t.strip())
    if flat:
        parts.append(flat)

    return "\n\n".join(parts).strip()


def parse_nmap_xml(xml_text: str, target: str, normal_text: str = "") -> HostResult:
    result = HostResult(target=target)
    if not xml_text.strip() and not normal_text.strip():
        result.error = "nmap produced no output (timeout or failure)"
        return result

    if xml_text.strip():
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            result.error = f"XML parse error: {exc}"
            root = None
    else:
        root = None

    found_port_el: ET.Element | None = None
    found_script: ET.Element | None = None

    if root is not None:
        host = root.find("host")
        if host is not None:
            addr_el = host.find("address")
            if addr_el is not None:
                result.address = addr_el.get("addr", "")

            for port_el in host.iter("port"):
                script = port_el.find("script[@id='rmi-dumpregistry']")
                if script is not None:
                    found_port_el = port_el
                    found_script = script
                    break

            if found_port_el is not None:
                result.port = found_port_el.get("portid", "")
                state_el = found_port_el.find("state")
                if state_el is not None:
                    result.port_state = state_el.get("state", "unknown")
            else:
                # Surface the first open port we scanned, if any
                for port_el in host.iter("port"):
                    state_el = port_el.find("state")
                    if state_el is not None and state_el.get("state") == "open":
                        result.port = port_el.get("portid", "")
                        result.port_state = "open"
                        break

    if found_script is not None:
        result.script_output = _extract_script_text(found_script)

    # Fallback: if XML extraction found nothing useful, parse the normal-text
    # block. Some nmap versions / script paths leave the structured XML empty
    # but populate the normal-mode output fully.
    if not result.script_output.strip() and normal_text.strip():
        block = extract_script_block_from_normal(normal_text)
        if block:
            result.script_output = block
            # Best-effort port + state recovery from the normal text
            if not result.port:
                m = re.search(r"^(\d+)/tcp\s+(open|closed|filtered)\s+",
                              normal_text, re.MULTILINE)
                if m:
                    result.port = m.group(1)
                    result.port_state = m.group(2)

    return result


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def classify(result: HostResult) -> None:
    """
    Classify rmi-dumpregistry output.

    Verdict rule (in priority order):
      1. No output, port not open  -> NO_RMI
      2. No output, port open      -> EMPTY
      3. Output contains an error  -> ERROR
      4. Output contains .jar/file:/ markers (with or without stub classes)
                                   -> CLASSPATH_ONLY
         Rationale: when classpath data is present, the "real" finding is
         path/library disclosure. Standard RMI scaffolding classes
         (RemoteStub, RemoteObject, etc.) are expected and not separately
         actionable, so we do not let their presence override the
         classpath signal.
      5. Output contains class refs / endpoints / RMI keywords (no jars)
                                   -> BOUND_OBJECTS
      6. Output exists but matches none of the above
                                   -> BOUND_OBJECTS (conservative — registry
                                      is exposed and returned data we can't
                                      classify; surface it as a real finding)
    """
    output = result.script_output

    if not output.strip():
        result.verdict = "EMPTY" if result.port_state == "open" else "NO_RMI"
        return

    if any(k in output for k in ERROR_KEYWORDS):
        result.verdict = "ERROR"
        result.error = output.splitlines()[0][:200]
        return

    bound_lines: list[str] = []
    jar_lines: list[str] = []

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue

        is_jar = bool(JAR_OR_FILE_RE.search(line)) or line.lower() == "classpath"
        is_class_ref = bool(CLASS_REF_RE.search(line))
        is_endpoint = bool(ENDPOINT_RE.search(line))
        is_keyword = any(kw in line for kw in BOUND_KEYWORDS)

        if is_jar:
            jar_lines.append(line)
        elif is_class_ref or is_endpoint or is_keyword:
            bound_lines.append(line)

    result.bound_objects = bound_lines
    result.classpath_entries = jar_lines

    if jar_lines:
        result.verdict = "CLASSPATH_ONLY"
    elif bound_lines:
        result.verdict = "BOUND_OBJECTS"
    else:
        # Output exists but no recognised signal — treat conservatively:
        # the registry IS exposing data, just not in a form we know.
        result.verdict = "BOUND_OBJECTS"

    # rmg-based verdict upgrades (never downgrade)
    if result.rmg_enum_output:
        enum_lower = result.rmg_enum_output.lower()
        # If nmap saw nothing but rmg found bound names, upgrade
        if result.verdict == "EMPTY" and "bound names:" in enum_lower:
            for line in result.rmg_enum_output.splitlines():
                stripped = line.strip()
                if stripped.startswith("- ") and "-->" not in stripped:
                    # rmg lists bound names as "- <name>"
                    result.verdict = "BOUND_OBJECTS"
                    break
        # If classpath-only but rmg guess found callable methods, upgrade
        if result.verdict == "CLASSPATH_ONLY" and result.rmg_guess_output:
            if "identified methods" in result.rmg_guess_output.lower():
                result.verdict = "BOUND_OBJECTS"


# ---------------------------------------------------------------------------
# rmg (remote-method-guesser) Docker integration
# ---------------------------------------------------------------------------


def check_docker_available() -> bool:
    """Return True if Docker is usable."""
    try:
        subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=10, check=False,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def pull_rmg_image(image: str) -> bool:
    """Pull the rmg Docker image. Returns True on success."""
    print(f"[*] Pulling rmg image: {image}", file=sys.stderr)
    try:
        proc = subprocess.run(
            ["docker", "pull", image],
            capture_output=True, text=True, timeout=300, check=False,
        )
        if proc.returncode != 0:
            print(f"[!] docker pull failed: {proc.stderr.strip()[:200]}", file=sys.stderr)
            return False
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_rmg(target: str, port: str, image: str, timeout: int) -> tuple[str, str]:
    """
    Run rmg enum and guess against a single target:port.

    Returns (enum_output, guess_output). Either may be empty on failure.
    """
    def _docker_run(action: str, extra_args: list[str] | None = None) -> str:
        cmd = [
            "docker", "run", "--rm",
            image, action, target, port, "--no-color",
        ]
        if extra_args:
            cmd.extend(extra_args)
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, check=False,
            )
            return proc.stdout
        except subprocess.TimeoutExpired:
            print(f"    [!] rmg {action} timed out for {target}:{port}",
                  file=sys.stderr)
            return ""

    enum_out = _docker_run("enum")
    guess_out = _docker_run("guess")
    return enum_out, guess_out


def parse_rmg_enum(output: str) -> dict[str, str]:
    """
    Parse rmg enum output for security-check results.

    Looks for lines like:
        [+]   - String Marshalling       Current Default
        [+]   - DGC                       Enabled
        [+]   - JEP290                    Vulnerable
    Returns e.g. {"String Marshalling": "Current Default", "JEP290": "Vulnerable"}
    """
    checks: dict[str, str] = {}
    # rmg enum security lines follow the pattern:
    #   [+] RMI server ... configuration:
    #   [+]
    #   [+]   - <Check Name>       <Status>
    check_re = re.compile(
        r"^\[[\+\-]\]\s{2,}-\s+(.+?)\s{2,}(\S.*)$"
    )
    for line in output.splitlines():
        m = check_re.match(line)
        if m:
            name = m.group(1).strip()
            status = m.group(2).strip()
            checks[name] = status
    return checks


# ---------------------------------------------------------------------------
# Markdown report generation
# ---------------------------------------------------------------------------


SEVERITY_ORDER = ["High", "Medium", "Low", "Informational"]


def build_report(
    results: list[HostResult],
    started: dt.datetime,
    ended: dt.datetime,
    ports_scanned: str,
    rmg_used: bool = False,
) -> str:
    md: list[str] = []
    md.append("# RMI Registry Exposure Assessment Report")
    md.append("")
    md.append(f"**Report Generated:** {ended.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    md.append(f"**Scan Started:** {started.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    md.append(f"**Scan Duration:** {(ended - started).total_seconds():.1f} seconds  ")
    md.append(f"**Targets Assessed:** {len(results)}  ")
    md.append(f"**Service Tested:** Java RMI Registry (TCP ports scanned: `{ports_scanned}`)  ")
    tools = "nmap NSE `rmi-dumpregistry`"
    if rmg_used:
        tools += ", remote-method-guesser (`rmg`) via Docker"
    md.append(f"**Tools:** {tools}")
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
    md.append(f"nmap {' '.join(build_nmap_args(ports_scanned))} <target>")
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
        "- **BOUND_OBJECTS** is identified when fully-qualified Java class "
        "references (e.g. `javax.management.remote.rmi.RMIServerImpl_Stub`), "
        "remote endpoint annotations (`@host:port`), or RMI keywords "
        "(`extends`, `implements`, `Stub`, `Remote`) appear in the output "
        "**and no classpath/jar data is present**. Output that is exposed but "
        "does not match a known pattern is also treated as `BOUND_OBJECTS` to "
        "avoid silently dropping a real exposure."
    )
    md.append(
        "- **CLASSPATH_ONLY** is identified when `.jar` filenames or `file:/` "
        "URLs appear anywhere in the registry output, including under a stub "
        "object's `Custom data → Classpath` section. Jar presence drives this "
        "verdict regardless of any standard RMI scaffolding classes also shown "
        "(e.g. `RemoteStub`, `RemoteObject`), because in that scenario the "
        "actionable disclosure is the classpath itself, not the generic stub."
    )
    md.append(
        "- **EMPTY** indicates the registry port is reachable but no usable data "
        "was returned by the script."
    )
    md.append("- **ERROR** indicates a handshake or protocol error during enumeration.")
    md.append("- **NO_RMI** indicates the port is closed or filtered.")
    md.append("")
    if rmg_used:
        md.append("### 2.1 rmg Validation")
        md.append("")
        md.append(
            "Targets with open RMI ports were additionally probed with "
            "[remote-method-guesser (rmg)](https://github.com/qtc-de/remote-method-guesser) "
            "via Docker for deeper security validation:"
        )
        md.append("")
        md.append("```bash")
        md.append("docker run --rm <image> enum <target> <port> --no-color")
        md.append("docker run --rm <image> guess <target> <port> --no-color")
        md.append("```")
        md.append("")
        md.append(
            "`rmg enum` enumerates bound names and performs security configuration "
            "checks (JEP 290, codebase settings, localhost bypass, security manager, "
            "string marshalling, DGC, activation system). `rmg guess` performs "
            "non-destructive remote method signature discovery."
        )
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
        md.append(f"- **Port:** `{r.port or '?'}/tcp` ({r.port_state})")
        md.append(f"- **Verdict:** `{r.verdict}` — {r.label}")
        md.append(f"- **Severity:** {r.severity}")
        md.append(f"- **CVSS (estimate):** {r.cvss}")
        md.append("")

        md.append("#### Description")
        md.append("")
        md.append(_description_for(r.verdict))
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

        if r.rmg_enum_output or r.rmg_guess_output:
            md.append("#### rmg Validation")
            md.append("")
            if r.rmg_security_checks:
                md.append("**Security Configuration Checks:**")
                md.append("")
                md.append("| Check | Status |")
                md.append("|-------|--------|")
                for check_name, status in r.rmg_security_checks.items():
                    md.append(f"| {check_name} | {status} |")
                md.append("")
            if r.rmg_guess_output.strip():
                md.append("**Method Guessing Results:**")
                md.append("")
                md.append(f"```\n{r.rmg_guess_output.strip()}\n```")
                md.append("")
            if r.rmg_enum_output.strip():
                md.append("<details>")
                md.append("<summary>Raw rmg enum output</summary>")
                md.append("")
                md.append(f"```\n{r.rmg_enum_output.strip()}\n```")
                md.append("")
                md.append("</details>")
                md.append("")

        md.append("#### Impact")
        md.append("")
        md.append(_impact_for(r.verdict))
        md.append("")

        md.append("#### Recommendation")
        md.append("")
        md.append(_recommendation_for(r.verdict, r.port))
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
    if rmg_used:
        md.append("- qtc-de, *remote-method-guesser (rmg)*: "
                  "<https://github.com/qtc-de/remote-method-guesser>")
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
            "The Java RMI registry on this host returned classpath or file-path "
            "references (`.jar` files or `file:/` URLs), typically nested under a "
            "bound stub object's `Custom data → Classpath` section. The dominant "
            "disclosure is path and library information; generic RMI scaffolding "
            "classes (`RemoteStub`, `RemoteObject`, etc.) may also be present "
            "alongside the classpath but do not by themselves constitute a "
            "directly attackable remote object. The immediate deserialization "
            "attack surface is reduced compared to a fully enumerated "
            "application-specific remote object, but the host is still leaking "
            "internal file system paths and library names that aid an attacker "
            "during reconnaissance and gadget-chain selection."
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


def _recommendation_for(verdict: str, port: str = "") -> str:
    if verdict == "NO_RMI":
        return "No action required."
    port_label = f"TCP/{port}" if port else "the RMI registry port"
    base = [
        f"Restrict {port_label} (and dynamically-allocated RMI object ports) to "
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
    parser.add_argument("-p", "--ports", default=DEFAULT_RMI_PORTS,
                        help=f"Comma/range port spec passed to nmap -p "
                             f"(default: {DEFAULT_RMI_PORTS})")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Path to write the markdown report (default: ./reports/<timestamp>.md)")
    parser.add_argument("--stdout", action="store_true",
                        help="Also print the full markdown report to stdout")
    parser.add_argument("--debug", action="store_true",
                        help="Save raw nmap XML for each host alongside the report")
    parser.add_argument("--rmg", action="store_true",
                        help="Run rmg via Docker for additional RMI validation")
    parser.add_argument("--rmg-image", default=RMG_DOCKER_IMAGE,
                        help=f"Docker image for rmg (default: {RMG_DOCKER_IMAGE})")
    parser.add_argument("--rmg-timeout", type=int, default=RMG_TIMEOUT, metavar="SEC",
                        help=f"Timeout per rmg action in seconds (default: {RMG_TIMEOUT})")
    args = parser.parse_args()

    if not shutil.which(NMAP_BINARY):
        sys.exit(f"[!] '{NMAP_BINARY}' not in PATH.")

    targets = load_targets(args)
    print(f"[*] Scanning {len(targets)} target(s) on tcp/{args.ports}", file=sys.stderr)

    started = dt.datetime.now(dt.timezone.utc)
    results: list[HostResult] = []

    # Always save raw nmap outputs alongside the report — they're tiny and
    # invaluable when a verdict looks wrong. --debug is now redundant but
    # kept for backwards compatibility.
    stamp = started.strftime("%Y%m%d-%H%M%S")
    raw_dir = DEFAULT_REPORT_DIR / f"evidence_data-{stamp}"
    raw_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Evidence data saved under: {raw_dir}", file=sys.stderr)

    for t in targets:
        print(f"[*] {t} ...", file=sys.stderr, flush=True)
        xml_out, normal_out = run_nmap(t, args.ports)
        safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", t)
        (raw_dir / f"{safe}.xml").write_text(xml_out)
        (raw_dir / f"{safe}.nmap").write_text(normal_out)

        result = parse_nmap_xml(xml_out, t, normal_out)
        classify(result)
        results.append(result)

        port_str = f"tcp/{result.port}" if result.port else "n/a"
        out_len = len(result.script_output)
        print(f"    -> {result.verdict} ({result.severity}) on {port_str} "
              f"[extracted {out_len} chars]", file=sys.stderr)

    # --- rmg validation pass ---
    rmg_used = False
    if args.rmg:
        if not check_docker_available():
            print("[!] Docker not available — skipping rmg validation",
                  file=sys.stderr)
        elif not pull_rmg_image(args.rmg_image):
            print("[!] Failed to pull rmg image — skipping rmg validation",
                  file=sys.stderr)
        else:
            rmg_used = True
            open_results = [r for r in results
                            if r.port and r.port_state == "open"]
            print(f"[*] Running rmg against {len(open_results)} open target(s)",
                  file=sys.stderr)
            for r in open_results:
                print(f"[*] rmg {r.target}:{r.port} ...",
                      file=sys.stderr, flush=True)
                enum_out, guess_out = run_rmg(
                    r.target, r.port, args.rmg_image, args.rmg_timeout,
                )
                r.rmg_enum_output = enum_out
                r.rmg_guess_output = guess_out
                r.rmg_security_checks = parse_rmg_enum(enum_out)

                # Save evidence
                safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", r.target)
                if enum_out:
                    (raw_dir / f"{safe}.rmg-enum.txt").write_text(enum_out)
                if guess_out:
                    (raw_dir / f"{safe}.rmg-guess.txt").write_text(guess_out)

                # Re-classify with rmg data
                old_verdict = r.verdict
                classify(r)
                if r.verdict != old_verdict:
                    print(f"    [+] Verdict upgraded: {old_verdict} -> {r.verdict}",
                          file=sys.stderr)
                checks_summary = ", ".join(
                    f"{k}={v}" for k, v in r.rmg_security_checks.items()
                ) or "no checks parsed"
                print(f"    -> rmg checks: {checks_summary}", file=sys.stderr)

    ended = dt.datetime.now(dt.timezone.utc)

    report = build_report(results, started, ended, args.ports, rmg_used=rmg_used)

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