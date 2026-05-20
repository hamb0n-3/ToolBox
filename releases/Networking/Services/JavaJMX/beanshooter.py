#!/usr/bin/env python3
"""
beanshooter-batch: Batch JMX security testing wrapper.

Wraps the beanshooter Docker image to test multiple JMX endpoints for:
  - Anonymous access (and optional credential brute-force via `--brute`)
  - Enumeration (MBeans, bound names)
  - Remote Code Execution vectors (pre-auth deserialization, JEP290 bypass,
    JMXMP-no-SASL, sensitive MBeans like MLet / DiagnosticCommand /
    HotSpotDiagnostic, and any TonkaBean already deployed)

Produces a Markdown findings report and a JSON results file.

USAGE
    python beanshooter_batch.py -i hosts.txt -o findings.md

INPUT FORMAT (hosts.txt)
    one `host[:port]` per line (default port 9010)
    `#` comments and blank lines are ignored

ONLY USE THIS AGAINST SYSTEMS YOU OWN OR HAVE WRITTEN PERMISSION TO TEST.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DOCKER_IMAGE = "ghcr.io/qtc-de/beanshooter/beanshooter:4.1.0"
DEFAULT_JMX_PORT = 9010

# ANSI escape sequences emitted by beanshooter (colour codes).
ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# `[+]`, `[-]`, `[!]`, `[*]` line markers at the start of beanshooter output.
PREFIX_RE = re.compile(r"^\s*\[[+\-!*]\]\s?")

# Section headers in `beanshooter enum` output, e.g.
#   "[+] Checking for unauthorized access:"
#   "[+] Checking pre-auth deserialization behavior:"
SECTION_RE = re.compile(r"^Checking\s+(?P<name>[^:]+):\s*$", re.IGNORECASE)

# Status lines, e.g.
#   "Vulnerability Status: Vulnerable"
#   "Configuration Status: Non Default"
STATUS_RE = re.compile(
    r"^(?P<kind>Vulnerability Status|Configuration Status)\s*:\s*"
    r"(?P<value>.+?)\s*$",
    re.IGNORECASE,
)

# Hit line from `beanshooter brute`, e.g.
#   "[HIT] admin:admin"   (best-effort; brute output format may vary by release)
HIT_RE = re.compile(r"\[hit\][\s:]*(\S+?):(\S+)", re.IGNORECASE)

# Permissive MBean ObjectName matcher. ObjectNames are
#   domain:key1=val1,key2=val2,...
# where values may be quoted and contain a wide range of characters.
OBJECTNAME_RE = re.compile(
    r"^[A-Za-z0-9_.\-$]+:[A-Za-z0-9_.\-$,=/\s\"'()\[\]\*\?!@+]+$"
)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    severity: str  # critical | high | medium | low | info
    title: str
    description: str
    category: str  # anonymous | enumeration | rce


@dataclass
class HostResult:
    host: str
    port: int
    reachable: bool = False
    ssl: bool = False
    auth_required: bool = True
    anonymous_access: bool = False
    weak_creds: Optional[str] = None
    mbean_count: int = 0
    nondefault_mbean_count: int = 0
    mbeans: List[str] = field(default_factory=list)
    bound_names: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_outputs: Dict[str, str] = field(default_factory=dict)
    duration_seconds: float = 0.0


# --------------------------------------------------------------------------- #
# Parsing primitives
# --------------------------------------------------------------------------- #
def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def clean_line(raw: str) -> str:
    """Drop ANSI codes, strip a leading `[+]`/`[-]`/`[!]`/`[*]` marker and
    surrounding whitespace. Unlike `lstrip("[+-!] ")`, this only strips the
    literal three-character marker, not a character class."""
    return PREFIX_RE.sub("", strip_ansi(raw)).strip()


def parse_enum_sections(text: str) -> Dict[str, List[str]]:
    """Parse `beanshooter enum` output into named sections keyed by
    lower-cased section name (e.g. 'for unauthorized access', 'pre-auth
    deserialization behavior'). Each value is the list of cleaned content
    lines under that section header."""
    sections: Dict[str, List[str]] = {}
    current: Optional[str] = None
    buf: List[str] = []
    for raw in text.splitlines():
        line = clean_line(raw)
        m = SECTION_RE.match(line)
        if m:
            if current is not None:
                sections[current] = buf
            current = m.group("name").strip().lower()
            buf = []
            continue
        if line and current is not None:
            buf.append(line)
    if current is not None:
        sections[current] = buf
    return sections


def _section_status(
    lines: List[str],
) -> Tuple[Optional[Tuple[str, str]], List[str]]:
    """From a section's content lines, return:
      ((status_kind_lower, status_value_lower), other_detail_lines)
    `status` is None if no Vulnerability/Configuration Status line was found.
    """
    status: Optional[Tuple[str, str]] = None
    details: List[str] = []
    for line in lines:
        m = STATUS_RE.match(line)
        if m:
            status = (
                m.group("kind").strip().lower(),
                m.group("value").strip().lower(),
            )
            continue
        details.append(line)
    return status, details


# --------------------------------------------------------------------------- #
# Higher-level parsers: enum / brute / list
# --------------------------------------------------------------------------- #
def parse_enum_findings(text: str, result: HostResult) -> None:
    """Populate `result` in-place from `beanshooter enum` output.

    Sets: reachable, auth_required, anonymous_access, ssl, mbean_count,
    nondefault_mbean_count, bound_names, plus any Findings.
    """
    sections = parse_enum_sections(text)

    # Reachability: if we successfully parsed any section the endpoint
    # responded to RMI.
    if sections:
        result.reachable = True

    # Bound names -> confirms RMI registry, exposes JMX endpoint URL
    for line in sections.get("available bound names", []):
        m = re.match(r"\*\s*(\S+)\s*\(JMX endpoint", line)
        if m:
            result.bound_names.append(m.group(1))

    # ------------------------------------------------------------------ #
    # Anonymous access (RMI-based)
    # ------------------------------------------------------------------ #
    if "for unauthorized access" in sections:
        status, details = _section_status(
            sections["for unauthorized access"]
        )
        says_no_auth = any(
            "does not require authentication" in d.lower() for d in details
        )
        # "requires authentication" *without* "does not" preceding
        says_auth = any(
            re.search(
                r"(?<!not\s)(?<!does\s)requires authentication",
                d, re.IGNORECASE,
            ) and "does not" not in d.lower()
            for d in details
        )
        vulnerable = status is not None and status[1].startswith("vulnerable")

        if says_no_auth or (vulnerable and not says_auth):
            result.auth_required = False
            result.anonymous_access = True
            result.findings.append(Finding(
                severity="critical",
                title="JMX endpoint allows anonymous access",
                description=(
                    "beanshooter confirmed the JMX RMI endpoint does not "
                    "require authentication. Any unauthenticated network "
                    "attacker can enumerate MBeans, read sensitive "
                    "attributes, and in most configurations achieve RCE via "
                    "MLet, DiagnosticCommand, or deserialization vectors."
                ),
                category="anonymous",
            ))
        elif says_auth:
            result.auth_required = True

    # ------------------------------------------------------------------ #
    # JMXMP SASL (alternative anonymous-access channel)
    # ------------------------------------------------------------------ #
    if "servers sasl configuration" in sections:
        status, details = _section_status(
            sections["servers sasl configuration"]
        )
        no_sasl = any(
            "does not use sasl" in d.lower() or
            "login is possible without specifying credentials" in d.lower()
            for d in details
        )
        if no_sasl or (status is not None and status[1].startswith("vulnerable")):
            result.auth_required = False
            result.anonymous_access = True
            result.findings.append(Finding(
                severity="critical",
                title="JMXMP endpoint accepts unauthenticated login",
                description=(
                    "beanshooter detected a JMXMP endpoint with no SASL "
                    "configuration. Anyone can authenticate without "
                    "credentials, then deploy MBeans for RCE."
                ),
                category="anonymous",
            ))

    # ------------------------------------------------------------------ #
    # Pre-authentication deserialization (RMI based)
    # The trigger is "accepted the payload class" + "Configuration Status:
    # Non Default" -- the literal word "Vulnerable" does NOT appear here.
    # ------------------------------------------------------------------ #
    if "pre-auth deserialization behavior" in sections:
        status, details = _section_status(
            sections["pre-auth deserialization behavior"]
        )
        accepted = any(
            "accepted the payload class" in d.lower() for d in details
        )
        rejected = any(
            "rejected the payload class" in d.lower() for d in details
        )
        cfg_nondefault = (
            status is not None
            and status[0] == "configuration status"
            and "non default" in status[1]
        )
        if (accepted or cfg_nondefault) and not rejected:
            result.findings.append(Finding(
                severity="critical",
                title="Pre-authentication deserialization accepted",
                description=(
                    "The JMX endpoint deserialized a beanshooter payload "
                    "class without authentication. Combined with a known "
                    "ysoserial gadget chain on the classpath "
                    "(CommonsCollections, Groovy, Spring, etc.), this "
                    "typically yields unauthenticated RCE on the JVM. "
                    "Confirm with: `beanshooter serial <host> <port> "
                    "<gadget> '<cmd>' --preauth`."
                ),
                category="rce",
            ))

    # ------------------------------------------------------------------ #
    # RMI registry JEP290 bypass -> registry-process deserialization RCE
    # ------------------------------------------------------------------ #
    if "rmi registry jep290 bypass enumeration" in sections:
        status, _ = _section_status(
            sections["rmi registry jep290 bypass enumeration"]
        )
        if status is not None and status[1].startswith("vulnerable"):
            result.findings.append(Finding(
                severity="critical",
                title="RMI registry vulnerable to JEP290 bypass",
                description=(
                    "The RMI registry allows JEP290 deserialization filter "
                    "bypass. This typically enables RCE in the registry JVM."
                ),
                category="rce",
            ))

    # ------------------------------------------------------------------ #
    # MBean inventory (count only -- detailed list comes from Phase 3)
    # ------------------------------------------------------------------ #
    for line in sections.get("available mbeans", []):
        m = re.search(
            r"(\d+)\s+MBeans?\s+are\s+currently\s+regist",
            line, re.IGNORECASE,
        )
        if m:
            result.mbean_count = int(m.group(1))
        m = re.search(
            r"Found\s+(\d+)\s+non\s+default\s+MBeans",
            line, re.IGNORECASE,
        )
        if m:
            result.nondefault_mbean_count = int(m.group(1))
    if result.mbean_count:
        result.findings.append(Finding(
            severity="medium",
            title=f"{result.mbean_count} MBeans enumerable",
            description=(
                "Full MBean inventory was enumerable from this endpoint "
                f"({result.nondefault_mbean_count} non-default). Sensitive "
                "MBeans may leak credentials, JDBC URLs, or expose dangerous "
                "operations such as heap dumps or arbitrary class loading."
            ),
            category="enumeration",
        ))

    # ------------------------------------------------------------------ #
    # SSL detection (only credit "enabled" when not preceded by a negation)
    # ------------------------------------------------------------------ #
    for raw in text.splitlines():
        line = clean_line(raw).lower()
        if "ssl" in line and "enabled" in line:
            if not re.search(r"(?:not|no|disable)\b[^.]*?enabled", line):
                result.ssl = True
                break


def parse_brute_hits(text: str) -> List[Tuple[str, str]]:
    """Return list of (username, password) hits from `beanshooter brute`
    output. Best-effort: matches `[HIT] user:pass`."""
    hits: List[Tuple[str, str]] = []
    for raw in text.splitlines():
        line = clean_line(raw)
        m = HIT_RE.search(line)
        if m:
            hits.append((m.group(1), m.group(2)))
    return hits


def parse_list_mbeans(text: str) -> List[str]:
    """Extract MBean ObjectNames from `beanshooter list` output."""
    mbeans: List[str] = []
    seen: set = set()
    for raw in text.splitlines():
        line = clean_line(raw)
        if OBJECTNAME_RE.match(line) and line not in seen:
            mbeans.append(line)
            seen.add(line)
    return mbeans


# --------------------------------------------------------------------------- #
# Logging / docker / I/O
# --------------------------------------------------------------------------- #
def setup_logging(log_path: Path, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("beanshooter_batch")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger


_SECRET_FLAGS = {"--password", "--password-file", "--credentials-file"}


def _redact_args(args: List[str]) -> List[str]:
    """Replace values following a secret flag with `***` for safe logging."""
    out: List[str] = []
    skip_next = False
    for a in args:
        if skip_next:
            out.append("***")
            skip_next = False
            continue
        out.append(a)
        if a in _SECRET_FLAGS:
            skip_next = True
    return out


def _redact_text(text: str, secrets: List[str]) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text


def ensure_docker(image: str, logger: logging.Logger, skip_pull: bool) -> bool:
    if shutil.which("docker") is None:
        logger.error("`docker` binary not found in PATH")
        return False
    if skip_pull:
        logger.info("Skipping docker pull (per --skip-pull)")
        return True
    logger.info(f"Pulling Docker image: {image}")
    try:
        proc = subprocess.run(
            ["docker", "pull", image],
            capture_output=True, text=True, errors="replace", timeout=600,
        )
    except subprocess.TimeoutExpired:
        logger.error("docker pull timed out")
        return False
    if proc.returncode != 0:
        logger.error(f"docker pull failed: {proc.stderr.strip()}")
        return False
    logger.info("Docker image ready")
    return True


def run_beanshooter(
    args: List[str],
    timeout: int,
    logger: logging.Logger,
    use_host_net: bool,
) -> Tuple[int, str, str]:
    """Run a beanshooter sub-command inside the docker image.
    Sensitive arg values are redacted in the DEBUG log line."""
    cmd: List[str] = ["docker", "run", "--rm"]
    if use_host_net:
        cmd.append("--network=host")
    cmd += [DOCKER_IMAGE, *args]

    logger.debug("Exec: %s", " ".join(_redact_args(cmd)))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            errors="replace", timeout=timeout,
        )
        return proc.returncode, strip_ansi(proc.stdout), strip_ansi(proc.stderr)
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except Exception as exc:  # noqa: BLE001
        return -2, "", f"exec error: {exc}"


def parse_host_line(line: str) -> Optional[Tuple[str, int]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if ":" in line:
        host, port_s = line.rsplit(":", 1)
        try:
            return host.strip(), int(port_s)
        except ValueError:
            return None
    return line, DEFAULT_JMX_PORT


# --------------------------------------------------------------------------- #
# Per-host pipeline
# --------------------------------------------------------------------------- #
def test_host(
    host: str,
    port: int,
    timeout: int,
    extra_args: List[str],
    use_host_net: bool,
    do_brute: bool,
    auth_username: Optional[str],
    auth_password: Optional[str],
    logger: logging.Logger,
) -> HostResult:
    start = datetime.utcnow()
    result = HostResult(host=host, port=port)
    label = f"{host}:{port}"
    logger.info(f"[{label}] starting tests")

    # Build optional auth prefix for beanshooter invocations.
    user_auth: List[str] = []
    if auth_username:
        user_auth = ["--username", auth_username]
        if auth_password:
            user_auth += ["--password", auth_password]

    secrets = [s for s in (auth_password,) if s]

    # --------------------------------------------------------------- #
    # Phase 1: enum (covers anonymous + pre-auth deser + bound names +
    # MBean count + JEP290 / JMXMP SASL checks)
    # --------------------------------------------------------------- #
    logger.info(f"[{label}] phase 1: enum")
    rc, out, err = run_beanshooter(
        [*user_auth, "enum", host, str(port), *extra_args],
        timeout=timeout, logger=logger, use_host_net=use_host_net,
    )
    blob = out + "\n" + err
    result.raw_outputs["enum"] = _redact_text(blob.strip(), secrets)

    if rc == -1:
        result.errors.append("enum command timed out")
    elif rc == -2:
        result.errors.append(f"enum exec error: {err}")

    # Hard unreachable: connection refused / no route AND nothing parsed.
    sections = parse_enum_sections(blob)
    if not sections and any(s in blob.lower() for s in (
        "connection refused", "no route to host", "connection timed out",
        "unknown host", "connect timed out", "host is unreachable",
    )):
        result.reachable = False
        result.errors.append("host unreachable")
        result.duration_seconds = (datetime.utcnow() - start).total_seconds()
        logger.warning(f"[{label}] unreachable")
        return result

    parse_enum_findings(blob, result)

    # --------------------------------------------------------------- #
    # Phase 2: brute (optional, behind --brute flag)
    # Only meaningful when authentication is actually required.
    # --------------------------------------------------------------- #
    if do_brute and result.auth_required and not result.anonymous_access:
        logger.info(f"[{label}] phase 2: brute (credential bruteforce)")
        rc, out, err = run_beanshooter(
            ["brute", host, str(port), *extra_args],
            timeout=timeout * 2, logger=logger, use_host_net=use_host_net,
        )
        blob = out + "\n" + err
        result.raw_outputs["brute"] = _redact_text(blob.strip(), secrets)
        hits = parse_brute_hits(blob)
        if hits:
            user, pw = hits[0]
            result.weak_creds = f"{user}:{pw}"
            for u, p in hits:
                result.findings.append(Finding(
                    severity="critical",
                    title=f"Weak / default credentials: {u}:{p}",
                    description=(
                        "beanshooter brute-force succeeded with a well-known "
                        "credential pair. Rotate immediately. Note that "
                        "brute-forcing JMX on JDK 11+ can lock accounts; "
                        "verify no production users were impacted."
                    ),
                    category="anonymous",
                ))

    # --------------------------------------------------------------- #
    # Phase 3: list MBeans (any access path)
    # --------------------------------------------------------------- #
    list_auth = user_auth[:]
    if not list_auth and result.weak_creds:
        u, p = result.weak_creds.split(":", 1)
        list_auth = ["--username", u, "--password", p]
        secrets.append(p)

    have_access = (
        result.anonymous_access
        or result.weak_creds is not None
        or bool(user_auth)
    )

    if have_access:
        logger.info(f"[{label}] phase 3: list MBeans")
        rc, out, err = run_beanshooter(
            [*list_auth, "list", host, str(port), *extra_args],
            timeout=timeout, logger=logger, use_host_net=use_host_net,
        )
        blob = out + "\n" + err
        result.raw_outputs["list"] = _redact_text(blob.strip(), secrets)
        result.mbeans = parse_list_mbeans(blob)
        if not result.mbean_count:
            result.mbean_count = len(result.mbeans)

        # Risky MBeans in the inventory.
        risky_specs = (
            # (substring, severity, category, title, description)
            ("javax.management.loading:type=MLet", "high", "rce",
             "MLet MBean deployed",
             "javax.management.loading.MLet is registered on the target. An "
             "attacker with JMX access can call getMBeansFromURL() to load "
             "arbitrary MBeans from a remote HTTP URL, leading to RCE."),
            ("DiagnosticCommand", "medium", "enumeration",
             "DiagnosticCommand MBean exposed",
             "DiagnosticCommand exposes the JVM control surface: heap dumps, "
             "JFR start/stop, system-property changes."),
            ("HotSpotDiagnostic", "medium", "enumeration",
             "HotSpotDiagnostic MBean exposed",
             "HotSpotDiagnostic allows heap dumps which frequently leak "
             "in-memory credentials, sessions, and tokens."),
            ("tonka", "critical", "rce",
             "TonkaBean payload MBean already deployed",
             "A beanshooter TonkaBean payload appears in the MBean inventory. "
             "RCE is live until it is undeployed (`beanshooter undeploy`)."),
        )
        for substr, sev, cat, title, desc in risky_specs:
            if any(substr.lower() in m.lower() for m in result.mbeans):
                result.findings.append(Finding(
                    severity=sev, title=title, description=desc,
                    category=cat,
                ))

    result.duration_seconds = (datetime.utcnow() - start).total_seconds()
    logger.info(
        f"[{label}] done: findings={len(result.findings)} "
        f"anon={result.anonymous_access} weak_creds={bool(result.weak_creds)} "
        f"mbeans={result.mbean_count} ({result.duration_seconds:.1f}s)"
    )
    return result


# --------------------------------------------------------------------------- #
# Markdown report rendering
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_BADGE = {
    "critical": "🟥 CRITICAL",
    "high":     "🟧 HIGH",
    "medium":   "🟨 MEDIUM",
    "low":      "🟦 LOW",
    "info":     "⬜ INFO",
}


def render_report(
    results: List[HostResult], started: datetime, finished: datetime
) -> str:
    L: List[str] = []
    L.append("# JMX Security Assessment — beanshooter Findings\n")
    L.append(f"_Generated:_ `{finished.strftime('%Y-%m-%d %H:%M:%S UTC')}`  ")
    L.append(f"_Scan duration:_ `{(finished - started).total_seconds():.1f}s`  ")
    L.append(f"_Tool:_ `{DOCKER_IMAGE}`\n")

    total = len(results)
    unreach = sum(1 for r in results if not r.reachable)
    anon = sum(1 for r in results if r.anonymous_access)
    weak = sum(1 for r in results if r.weak_creds)
    rce_hosts = sum(
        1 for r in results if any(f.category == "rce" for f in r.findings)
    )

    sev_counts = {k: 0 for k in SEVERITY_ORDER}
    for r in results:
        for f in r.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    L.append("## Executive Summary\n")
    L.append(f"- **Hosts tested:** {total}")
    L.append(f"- **Unreachable:** {unreach}")
    L.append(f"- **Anonymous access:** {anon}")
    L.append(f"- **Weak credentials:** {weak}")
    L.append(f"- **Hosts with RCE vector:** {rce_hosts}\n")
    L.append("| Severity | Count |")
    L.append("|----------|------:|")
    for sev in ("critical", "high", "medium", "low", "info"):
        L.append(f"| {SEVERITY_BADGE[sev]} | {sev_counts[sev]} |")
    L.append("")

    # Host summary table.
    L.append("## Host Summary\n")
    L.append(
        "| Host | Port | Reachable | Anon | Weak Creds | RCE | "
        "MBeans | Findings |"
    )
    L.append(
        "|------|-----:|:---------:|:----:|:----------:|:---:|"
        "------:|---------:|"
    )
    for r in sorted(
        results,
        key=lambda x: (
            not any(f.severity == "critical" for f in x.findings),
            not x.anonymous_access,
            x.host,
        ),
    ):
        rce_flag = "✅" if any(f.category == "rce" for f in r.findings) else ""
        anon_flag = "✅" if r.anonymous_access else ""
        reach_flag = "✅" if r.reachable else "❌"
        creds = f"`{r.weak_creds}`" if r.weak_creds else "—"
        L.append(
            f"| `{r.host}` | {r.port} | {reach_flag} | {anon_flag} | "
            f"{creds} | {rce_flag} | {r.mbean_count} | "
            f"{len(r.findings)} |"
        )
    L.append("")

    # Per-host detail.
    L.append("## Detailed Findings\n")
    for r in sorted(results, key=lambda x: x.host):
        L.append(f"### `{r.host}:{r.port}`\n")
        L.append(f"- Reachable: **{r.reachable}**")
        L.append(f"- SSL: **{r.ssl}**")
        L.append(f"- Authentication required: **{r.auth_required}**")
        L.append(f"- Anonymous access: **{r.anonymous_access}**")
        if r.weak_creds:
            L.append(f"- Weak credentials: `{r.weak_creds}`")
        if r.bound_names:
            L.append(f"- RMI bound names: {', '.join(f'`{n}`' for n in r.bound_names)}")
        if r.mbean_count:
            L.append(
                f"- MBeans discovered: **{r.mbean_count}** "
                f"({r.nondefault_mbean_count} non-default)"
            )
        if r.errors:
            L.append("- Errors:")
            for e in r.errors:
                L.append(f"  - {e}")
        L.append(f"- Test duration: `{r.duration_seconds:.1f}s`\n")

        if r.findings:
            for f in sorted(
                r.findings,
                key=lambda x: SEVERITY_ORDER.get(x.severity, 99),
            ):
                L.append(
                    f"#### {SEVERITY_BADGE.get(f.severity, '')} — {f.title}"
                )
                L.append(f"*Category:* `{f.category}`\n")
                L.append(f"{f.description}\n")
        else:
            L.append("_No findings._\n")

        if r.mbeans:
            L.append("<details><summary>MBean inventory</summary>\n")
            L.append("```")
            for m in r.mbeans[:200]:
                L.append(m)
            if len(r.mbeans) > 200:
                L.append(f"... ({len(r.mbeans) - 200} more)")
            L.append("```")
            L.append("</details>\n")

        if r.raw_outputs:
            L.append("<details><summary>Raw beanshooter output</summary>\n")
            for phase, blob in r.raw_outputs.items():
                L.append(f"\n**{phase}**\n")
                L.append("```")
                L.append((blob or "").strip()[:8000])
                L.append("```")
            L.append("</details>\n")

    L.append("## Recommendations\n")
    L.append(
        "- Enforce JMX authentication "
        "(`com.sun.management.jmxremote.authenticate=true`) and TLS "
        "(`com.sun.management.jmxremote.ssl=true`) on every JVM."
    )
    L.append(
        "- Restrict JMX RMI ports (registry + dynamic) to management VLANs; "
        "never expose to the public internet."
    )
    L.append(
        "- Rotate any default JMX credentials and enforce a strong password "
        "policy with per-environment rotation."
    )
    L.append(
        "- Remove or restrict access to dangerous MBeans such as "
        "`javax.management.loading.MLet`, `DiagnosticCommand`, and any "
        "third-party payload MBeans (e.g. TonkaBean)."
    )
    L.append(
        "- Patch the JVM and bundled frameworks (CommonsCollections, Groovy, "
        "Spring, etc.) to remove known deserialization gadget chains."
    )
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(
        description="Batch JMX security tester wrapping beanshooter.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-i", "--input", required=True, type=Path,
                   help="File with one `host[:port]` per line.")
    p.add_argument("-o", "--output", type=Path,
                   default=Path("jmx_findings.md"),
                   help="Markdown findings report path.")
    p.add_argument("-j", "--json", type=Path,
                   default=Path("jmx_findings.json"),
                   help="JSON results path.")
    p.add_argument("-l", "--log", type=Path,
                   default=Path("jmx_batch.log"),
                   help="Log file path.")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="Concurrent host workers (default 4).")
    p.add_argument("--timeout", type=int, default=180,
                   help="Per-beanshooter-command timeout in s (default 180).")
    p.add_argument("--ssl", action="store_true",
                   help="Pass --ssl to beanshooter for all targets.")
    p.add_argument("--host-net", action="store_true",
                   help="Run docker with --network=host (Linux only).")
    p.add_argument("--skip-pull", action="store_true",
                   help="Skip `docker pull` (use locally cached image).")
    p.add_argument("--username",
                   help="JMX username for authenticated enumeration.")
    p.add_argument("--password",
                   help="JMX password (paired with --username). Value is "
                        "redacted in logs and raw-output blobs.")
    p.add_argument("--brute", action="store_true",
                   help="Run `beanshooter brute` against auth-required "
                        "endpoints. WARNING: may lock accounts on JDK 11+.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose console logging.")
    p.add_argument("--extra", nargs=argparse.REMAINDER, default=[],
                   help="Extra args appended to every beanshooter call.")
    args = p.parse_args()

    logger = setup_logging(args.log, args.verbose)
    logger.info("beanshooter-batch starting")
    logger.info(f"image={DOCKER_IMAGE}")
    logger.info(
        f"input={args.input} output={args.output} json={args.json} "
        f"threads={args.threads} timeout={args.timeout}s "
        f"brute={args.brute} ssl={args.ssl}"
    )
    if args.password and not args.username:
        logger.error("--password requires --username")
        return 2

    if not args.input.exists():
        logger.error(f"Input file not found: {args.input}")
        return 2

    targets: List[Tuple[str, int]] = []
    for line in args.input.read_text().splitlines():
        parsed = parse_host_line(line)
        if parsed:
            targets.append(parsed)
    if not targets:
        logger.error("No valid targets parsed from input file")
        return 2
    logger.info(f"Loaded {len(targets)} target(s)")

    if not ensure_docker(DOCKER_IMAGE, logger, args.skip_pull):
        return 3

    extra_args = list(args.extra)
    if args.ssl and "--ssl" not in extra_args:
        extra_args.append("--ssl")

    started = datetime.utcnow()
    results: List[HostResult] = []
    executor = ThreadPoolExecutor(max_workers=args.threads)
    interrupted = False
    try:
        futures = {
            executor.submit(
                test_host, host, port, args.timeout,
                extra_args, args.host_net, args.brute,
                args.username, args.password, logger,
            ): (host, port)
            for host, port in targets
        }
        for fut in as_completed(futures):
            host, port = futures[fut]
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                logger.exception(f"[{host}:{port}] worker crashed")
                r = HostResult(host=host, port=port)
                r.errors.append(f"worker crashed: {exc}")
                results.append(r)
    except KeyboardInterrupt:
        interrupted = True
        logger.warning("Interrupted by user; cancelling pending work")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    finished = datetime.utcnow()

    try:
        args.json.write_text(
            json.dumps([asdict(r) for r in results], indent=2, default=str),
            encoding="utf-8",
        )
        logger.info(f"Wrote JSON results to {args.json}")
    except OSError as exc:
        logger.error(f"Failed to write JSON: {exc}")

    try:
        report = render_report(results, started, finished)
        args.output.write_text(report, encoding="utf-8")
        logger.info(f"Wrote Markdown report to {args.output}")
    except OSError as exc:
        logger.error(f"Failed to write Markdown report: {exc}")
        return 4

    crit = sum(
        1 for r in results for f in r.findings if f.severity == "critical"
    )
    logger.info(
        f"DONE{' (interrupted)' if interrupted else ''}: "
        f"{len(results)} host(s), {crit} critical finding(s)."
    )
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())