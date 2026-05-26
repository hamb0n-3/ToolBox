#!/usr/bin/env python3
"""
VA Lighthouse Facilities API - Security Test Suite (v2)
=======================================================

Non-destructive, OWASP API Security Top 10 (2023) verification suite for the
VA Lighthouse Facilities API.

  *** AUTHORIZED USE ONLY ***
  - Run ONLY against the SANDBOX environment with YOUR OWN issued API key.
  - Unauthorized testing of VA systems may violate the CFAA.
  - This script is non-destructive: write/delete probes only confirm that the
    server REJECTS them; they never expect or rely on success.

Design notes
------------
  * Every network call goes through safe_send(), which never raises - a network
    error becomes a WARN result instead of silently dropping a test or aborting.
  * Every test group runs inside an isolation wrapper, so an unexpected crash in
    one group degrades to a single FAIL and the run still finishes + reports.
  * Probes that depend on exactly what bytes hit the wire (path traversal, null
    bytes) record the ACTUAL request URL as evidence, because HTTP client
    libraries normalize/re-encode paths and can neuter a naive payload. Use
    pre-encoded sequences (e.g. ..%2f) that survive requests' requoting.

Requirements:
    python3 -m pip install requests

Usage:
    python3 va_facilities_security_test.py
"""

import argparse
import json
import sys
import time
import ssl
import socket
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("Missing dependency. Run: python3 -m pip install requests")


# =============================================================================
# CONFIGURATION  --  edit everything in this block, nothing below.
# =============================================================================

# --- Target ---------------------------------------------------------------
BASE_URL = "https://sandbox-api.va.gov/services/va_facilities/v1"
API_KEY = None                               # optional; pass via --api-key or set here
API_KEY_HEADER = "apikey"                    # header name used to send the key

# A known-valid facility ID for the sandbox. Leave as None to auto-discover
# one from the /facilities listing at runtime.
KNOWN_FACILITY_ID = None

# --- Request behaviour ----------------------------------------------------
TIMEOUT = 15                 # seconds per request
USER_AGENT = "VA-Facilities-SecTest/2.0 (authorized-sandbox-testing)"
VERIFY_TLS = True            # keep True; only disable for proxy debugging
PROXIES = None               # e.g. {"https": "http://127.0.0.1:8080"} for Burp

# --- Rate-limit test ------------------------------------------------------
RATE_LIMIT_REQUESTS = 60     # number of rapid requests to fire
RATE_LIMIT_THREADS = 10      # concurrency for the burst
RATE_LIMIT_DELAY = 0.0       # seconds between dispatches (0 = as fast as possible)

# --- Reporting ------------------------------------------------------------
OUTPUT_JSON = "va_facilities_security_report.json"
OUTPUT_MARKDOWN = "va_facilities_security_report.md"
VERBOSE = True               # print per-test detail to stdout

# --- Endpoint paths (relative to BASE_URL) --------------------------------
EP_FACILITIES = "/facilities"
EP_FACILITY_BY_ID = "/facilities/{id}"
EP_NEARBY = "/nearby"
EP_IDS = "/facilities/ids"
EP_OPENAPI = "/openapi.json"

# --- Security headers we expect to be PRESENT (with quality checks) -------
# value: callable(header_value) -> (bool ok, str note)  or None for presence-only
def _hsts_ok(v):
    # Expect a meaningful max-age (>= ~6 months)
    try:
        parts = dict(p.strip().split("=", 1) if "=" in p else (p.strip(), "")
                     for p in v.split(";"))
        max_age = int(parts.get("max-age", "0"))
        return (max_age >= 15552000, f"max-age={max_age}")
    except Exception:
        return (False, "unparseable")

def _nosniff_ok(v):
    return (v.strip().lower() == "nosniff", v)

def _frame_ok(v):
    return (v.strip().lower() in ("deny", "sameorigin"), v)

EXPECTED_SECURITY_HEADERS = {
    "Strict-Transport-Security": _hsts_ok,
    "X-Content-Type-Options": _nosniff_ok,
    "X-Frame-Options": _frame_ok,
    "Content-Security-Policy": None,
    "Referrer-Policy": None,
    "Permissions-Policy": None,
}

# --- Headers that LEAK info and should be ABSENT --------------------------
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                     "X-AspNetMvc-Version", "X-Runtime", "X-Generator"]

# --- Injection payloads (read-only filters; non-destructive) --------------
SQLI_PAYLOADS = [
    "'", "''", "' OR '1'='1", "1' OR '1'='1' -- ",
    "1; SELECT pg_sleep(0)--", "' UNION SELECT NULL--", "%27", "\")",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'\"><svg/onload=alert(1)>",
]
NOSQL_PAYLOADS = ['{"$gt":""}', '{"$ne":null}', "[$ne]=1"]
CMD_PAYLOADS = [";id", "|id", "$(id)", "`id`", "&& whoami"]
TEMPLATE_PAYLOADS = ["${7*7}", "{{7*7}}", "#{7*7}", "<%= 7*7 %>"]
# Pre-encoded traversal payloads that survive client requoting (..%2f stays).
TRAVERSAL_PAYLOADS = [
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "..%5c..%5cwindows%5cwin.ini",
    "%00",
]

# --- HTTP methods to test against a read-only API -------------------------
WRITE_METHODS = ["POST", "PUT", "DELETE", "PATCH"]
META_METHODS = ["OPTIONS", "HEAD", "TRACE"]

# --- Deprecated / inventory versions + common debug paths to probe --------
HOST_RELATIVE_PROBES = [
    "/services/va_facilities/v0/facilities",
    "/services/va_facilities/v2/facilities",
    "/services/va_facilities/v3/facilities",
]
DEBUG_PATH_PROBES = [
    "/actuator", "/actuator/health", "/actuator/env",
    "/health", "/metrics", "/debug", "/.git/config",
    "/swagger-ui.html", "/v2/api-docs",
]

# =============================================================================
# END CONFIGURATION
# =============================================================================


# ---- ANSI colors (degrade gracefully if not a TTY) ----
class C:
    if sys.stdout.isatty():
        GREEN, RED, YELLOW, BLUE, BOLD, DIM, END = (
            "\033[92m", "\033[91m", "\033[93m",
            "\033[94m", "\033[1m", "\033[2m", "\033[0m",
        )
    else:
        GREEN = RED = YELLOW = BLUE = BOLD = DIM = END = ""


PASS, FAIL, WARN, INFO = "PASS", "FAIL", "WARN", "INFO"

RESULTS = []
_RESULTS_LOCK = threading.Lock()


def record(test_id, name, status, detail, owasp=None, evidence=None):
    """Store and optionally print a single test result. Thread-safe."""
    entry = {
        "id": test_id,
        "name": name,
        "status": status,
        "detail": detail,
        "owasp": owasp,
        "evidence": evidence,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    with _RESULTS_LOCK:
        RESULTS.append(entry)
    if VERBOSE:
        color = {PASS: C.GREEN, FAIL: C.RED, WARN: C.YELLOW, INFO: C.BLUE}[status]
        tag = f"{color}[{status:<4}]{C.END}"
        owasp_tag = f"{C.DIM}({owasp}){C.END} " if owasp else ""
        print(f"  {tag} {owasp_tag}{name}")
        print(f"        {C.DIM}{detail}{C.END}")


def make_session():
    """Build a requests session with sane retry/transport settings.

    Note: 429 is intentionally NOT in status_forcelist so the rate-limit test
    sees raw throttling responses instead of silently retried ones.
    """
    s = requests.Session()
    retries = Retry(total=2, backoff_factor=0.3,
                    status_forcelist=[500, 502, 503, 504],
                    allowed_methods=["GET", "HEAD", "OPTIONS"])
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    if PROXIES:
        s.proxies.update(PROXIES)
    return s


def safe_send(session, method, url, headers=None, params=None, json_body=None,
              allow_auth=True):
    """Send a request and ALWAYS return (response_or_None, error_or_None).

    Never raises. Lets every test handle the error path uniformly so a network
    blip becomes a WARN instead of a vanished test or a crashed run.
    """
    h = dict(headers or {})
    if allow_auth and API_KEY:
        h.setdefault(API_KEY_HEADER, API_KEY)
    try:
        r = session.request(method, url, headers=h, params=params,
                            json=json_body, timeout=TIMEOUT, verify=VERIFY_TLS)
        return r, None
    except requests.exceptions.RequestException as e:
        return None, str(e)


def url_for(path):
    return BASE_URL.rstrip("/") + path


def host_root():
    p = urlparse(BASE_URL)
    return f"{p.scheme}://{p.netloc}"


def expect_status(test_id, name, r, err, allowed, owasp,
                  fail_status=FAIL, extra_evidence=None):
    """Uniform helper: WARN on network error, PASS if status in `allowed`,
    else `fail_status`. Returns the recorded status string."""
    if err is not None or r is None:
        record(test_id, name, WARN, f"Network error: {err}", owasp=owasp)
        return WARN
    ev = {"status": r.status_code}
    if extra_evidence:
        ev.update(extra_evidence)
    ok = r.status_code in allowed
    status = PASS if ok else fail_status
    record(test_id, name, status,
           f"HTTP {r.status_code} (expect {'/'.join(map(str, allowed))})",
           owasp=owasp, evidence=ev)
    return status


def body_lower(r):
    try:
        return (r.text or "").lower()
    except Exception:
        return ""


# =============================================================================
# PRE-FLIGHT
# =============================================================================

def preflight(session, assume_yes=False):
    print(f"\n{C.BOLD}== Pre-flight =={C.END}")
    if not API_KEY or API_KEY.startswith("PUT-YOUR"):
        print(f"{C.YELLOW}NOTE: No API key set. Running unauthenticated; "
              f"endpoints requiring auth will return 401/403.{C.END}")

    parsed = urlparse(BASE_URL)
    if "sandbox" not in parsed.netloc:
        print(f"{C.YELLOW}WARNING: BASE_URL does not contain 'sandbox'. "
              f"Confirm you are authorized to test this host.{C.END}")
        if assume_yes:
            print(f"{C.DIM}--yes supplied; continuing without prompt.{C.END}")
        else:
            ans = input("Type 'yes' to continue: ").strip().lower()
            if ans != "yes":
                sys.exit("Aborted.")

    r, err = safe_send(session, "GET", url_for(EP_FACILITIES),
                       params={"per_page": 1, "page": 1})
    if err:
        sys.exit(f"{C.RED}Cannot reach API: {err}{C.END}")
    if r.status_code in (401, 403):
        if API_KEY:
            sys.exit(f"{C.RED}Auth failed ({r.status_code}). "
                     f"Check your API key.{C.END}")
        print(f"{C.YELLOW}Baseline returned HTTP {r.status_code} "
              f"(expected without an API key; auth-gated tests will be "
              f"limited).{C.END}")
    if r.status_code >= 500:
        print(f"{C.YELLOW}WARNING: baseline request returned HTTP "
              f"{r.status_code}. The API may be unhealthy; results below may be "
              f"unreliable.{C.END}")
    elif r.status_code == 200:
        print(f"{C.GREEN}Connectivity + auth OK (HTTP 200).{C.END}")
    else:
        print(f"{C.YELLOW}Baseline returned HTTP {r.status_code} "
              f"(continuing).{C.END}")
    return r


def discover_facility_id(session):
    """Find a valid facility ID to use in object-level tests."""
    global KNOWN_FACILITY_ID
    if KNOWN_FACILITY_ID:
        return KNOWN_FACILITY_ID
    r, err = safe_send(session, "GET", url_for(EP_FACILITIES),
                       params={"per_page": 1, "page": 1})
    if err or r is None or r.status_code != 200:
        return None
    try:
        data = r.json().get("data", [])
        if data:
            KNOWN_FACILITY_ID = data[0].get("id")
            print(f"{C.DIM}Discovered facility ID: {KNOWN_FACILITY_ID}{C.END}")
            return KNOWN_FACILITY_ID
    except (ValueError, KeyError, IndexError):
        pass
    return None


# =============================================================================
# POSITIVE CONTROL (sanity: a valid request behaves correctly)
# =============================================================================

def test_positive_control(session):
    print(f"\n{C.BOLD}== Positive Control =={C.END}")
    r, err = safe_send(session, "GET", url_for(EP_FACILITIES),
                       params={"per_page": 1, "page": 1})
    if err or r is None:
        record("CTRL-01", "Valid authenticated request", WARN,
               f"Network error: {err}")
        return
    ctype = r.headers.get("Content-Type", "")
    well_formed = False
    try:
        well_formed = isinstance(r.json(), dict)
    except ValueError:
        pass
    ok = r.status_code == 200 and "json" in ctype.lower() and well_formed
    record("CTRL-01", "Valid authenticated request",
           PASS if ok else WARN,
           f"HTTP {r.status_code}, Content-Type={ctype!r}, "
           f"valid JSON={well_formed}",
           evidence={"status": r.status_code, "content_type": ctype})


# =============================================================================
# TRANSPORT SECURITY (TLS) - beefed up
# =============================================================================

def _negotiate(host, port, min_v, max_v):
    """Try to negotiate a TLS version range. Returns (version_or_None, err)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = min_v
        ctx.maximum_version = max_v
    except (ValueError, AttributeError):
        return None, "version-not-supported-by-client"
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.version(), None
    except Exception as e:
        return None, str(e)


def test_tls(session):
    print(f"\n{C.BOLD}== Transport Security (TLS) =={C.END}")
    host = urlparse(BASE_URL).netloc.split(":")[0]
    port = 443

    # 1) Default negotiation: capture version, cipher, cert
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
        good = version in ("TLSv1.2", "TLSv1.3")
        record("TLS-01", "Negotiated TLS version", PASS if good else FAIL,
               f"{version}, cipher={cipher[0] if cipher else '?'}",
               owasp="API8",
               evidence={"tls_version": version,
                         "cipher": cipher[0] if cipher else None})

        # Certificate expiry (days remaining)
        not_after = cert.get("notAfter") if cert else None
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                exp = exp.replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                st = PASS if days > 14 else (WARN if days > 0 else FAIL)
                record("TLS-02", "Certificate validity", st,
                       f"Expires {not_after} ({days} days remaining)",
                       owasp="API8", evidence={"days_remaining": days})
            except ValueError:
                record("TLS-02", "Certificate validity", INFO,
                       f"Expires {not_after} (unparsed)", owasp="API8")
        else:
            record("TLS-02", "Certificate validity", WARN,
                   "No certificate returned.", owasp="API8")
    except Exception as e:
        record("TLS-01", "Negotiated TLS version", FAIL,
               f"Handshake error: {e}", owasp="API8")

    # 2) Weak-protocol rejection: TLS 1.0 and 1.1 should NOT negotiate
    for label, ver in (("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                       ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))):
        if ver is None:
            record("TLS-03", f"{label} rejected", INFO,
                   "Client cannot test this version (OpenSSL too new).",
                   owasp="API8")
            continue
        v, err = _negotiate(host, port, ver, ver)
        if v is None:
            record("TLS-03", f"{label} rejected", PASS,
                   f"Server refused {label} (good).", owasp="API8",
                   evidence={"error": err})
        else:
            record("TLS-03", f"{label} rejected", FAIL,
                   f"Server negotiated weak {v}!", owasp="API8",
                   evidence={"negotiated": v})


# =============================================================================
# API2: BROKEN AUTHENTICATION - beefed up + uniform error handling
# =============================================================================

def test_authentication(session):
    print(f"\n{C.BOLD}== API2: Authentication =={C.END}")
    url = url_for(EP_FACILITIES)
    base_params = {"per_page": 1}

    # Each case: (id, name, headers, params, allow_auth)
    cases = [
        ("AUTH-01", "No API key",
         {}, base_params, False),
        ("AUTH-02", "Empty API key",
         {API_KEY_HEADER: ""}, base_params, False),
        ("AUTH-03", "Invalid API key",
         {API_KEY_HEADER: "invalid-key-000000000000"}, base_params, False),
        ("AUTH-05", "Whitespace API key",
         {API_KEY_HEADER: "   "}, base_params, False),
        ("AUTH-07", "SQL metachar in API key",
         {API_KEY_HEADER: "' OR '1'='1"}, base_params, False),
    ]
    if API_KEY:
        cases.append(
            ("AUTH-06", "Key in wrong header (Authorization Bearer)",
             {"Authorization": f"Bearer {API_KEY}"}, base_params, False))
    for tid, name, hdrs, params, allow in cases:
        r, err = safe_send(session, "GET", url, headers=hdrs, params=params,
                           allow_auth=allow)
        expect_status(tid, name, r, err, allowed=(401, 403), owasp="API2")

    if not API_KEY:
        record("AUTH-04", "API key accepted in URL query", INFO,
               "Skipped: no API key configured.", owasp="API2")
        return

    # AUTH-04: key in URL query string. PASS = rejected (key shouldn't leak to
    # logs); WARN = honored.
    r, err = safe_send(session, "GET", url, allow_auth=False,
                       params={API_KEY_HEADER: API_KEY, "per_page": 1})
    if err or r is None:
        record("AUTH-04", "API key accepted in URL query", WARN,
               f"Network error: {err}", owasp="API2")
    elif r.status_code == 200:
        record("AUTH-04", "API key accepted in URL query", WARN,
               "Key in URL is honored; risks exposure in logs/history/referrer.",
               owasp="API2", evidence={"status": r.status_code})
    else:
        record("AUTH-04", "API key accepted in URL query", PASS,
               f"Key-in-URL rejected (HTTP {r.status_code}).",
               owasp="API2", evidence={"status": r.status_code})


# =============================================================================
# API1/API3: OBJECT-LEVEL ACCESS + property exposure - beefed up
# =============================================================================

def test_object_authorization(session, facility_id):
    print(f"\n{C.BOLD}== API1/API3: Object-Level Access =={C.END}")

    bad_ids = ["does_not_exist_999", "0", "-1", "null", "undefined",
               "%20", "vha_%00", "*"]
    for bad_id in bad_ids:
        url = url_for(EP_FACILITY_BY_ID.format(id=bad_id))
        r, err = safe_send(session, "GET", url)
        if err or r is None:
            record("BOLA-01", f"Invalid ID {bad_id!r}", WARN,
                   f"Network error: {err}", owasp="API1")
            continue
        sent = getattr(r.request, "url", url)
        leaked = r.status_code == 200
        record("BOLA-01", f"Invalid ID {bad_id!r}",
               FAIL if leaked else PASS,
               f"HTTP {r.status_code} (expect 400/404, not 200)",
               owasp="API1",
               evidence={"status": r.status_code, "sent_url": sent})

    # Property-level exposure on a valid object
    if facility_id:
        url = url_for(EP_FACILITY_BY_ID.format(id=facility_id))
        r, err = safe_send(session, "GET", url)
        if r is not None and r.status_code == 200:
            try:
                body = r.json()
                blob = json.dumps(body).lower()
                # Heuristic: flag suspicious internal-looking field names
                suspicious = [k for k in ("password", "secret", "ssn",
                              "internal", "token", "apikey", "private_key")
                              if k in blob]
                if suspicious:
                    record("PROP-01", "Property-level exposure", FAIL,
                           f"Suspicious fields present: {suspicious}",
                           owasp="API3", evidence={"matched": suspicious})
                else:
                    record("PROP-01", "Property-level exposure", PASS,
                           "No obviously sensitive field names in response.",
                           owasp="API3",
                           evidence={"top_level_keys": list(body.keys())})
            except ValueError:
                record("PROP-01", "Property-level exposure", WARN,
                       "Response not JSON-parseable.", owasp="API3")


# =============================================================================
# API5: FUNCTION-LEVEL AUTH / HTTP METHOD HANDLING - beefed up
# =============================================================================

def test_method_handling(session, facility_id):
    print(f"\n{C.BOLD}== API5: HTTP Method Handling =={C.END}")
    target_id = facility_id or "vha_000"
    by_id = url_for(EP_FACILITY_BY_ID.format(id=target_id))

    # Write methods MUST be rejected on a read-only API
    write_cases = [
        ("POST", url_for(EP_FACILITIES), {}),
        ("PUT", by_id, {}),
        ("DELETE", by_id, None),
        ("PATCH", by_id, {}),
    ]
    for method, url, body in write_cases:
        r, err = safe_send(session, method, url, json_body=body)
        expect_status("FUNC-01", f"{method} on read-only endpoint",
                      r, err, allowed=(401, 403, 404, 405, 501), owasp="API5")

    # OPTIONS / HEAD are generally fine; record the Allow header for review
    r, err = safe_send(session, "OPTIONS", url_for(EP_FACILITIES))
    if r is not None:
        allow = r.headers.get("Allow", "(none)")
        record("FUNC-02", "OPTIONS Allow header", INFO,
               f"HTTP {r.status_code}, Allow: {allow}", owasp="API5",
               evidence={"allow": allow, "status": r.status_code})

    # TRACE should be disabled (Cross-Site Tracing / XST)
    r, err = safe_send(session, "TRACE", url_for(EP_FACILITIES))
    if err or r is None:
        record("FUNC-03", "TRACE disabled", PASS,
               "TRACE refused at transport layer.", owasp="API5")
    else:
        ok = r.status_code in (403, 405, 501)
        record("FUNC-03", "TRACE disabled", PASS if ok else FAIL,
               f"HTTP {r.status_code} (expect 405/501/403)", owasp="API5",
               evidence={"status": r.status_code})

    # Unknown/arbitrary method
    r, err = safe_send(session, "FOOBAR", url_for(EP_FACILITIES))
    if r is not None:
        ok = r.status_code in (400, 401, 403, 405, 501)
        record("FUNC-04", "Arbitrary method rejected", PASS if ok else WARN,
               f"HTTP {r.status_code}", owasp="API5",
               evidence={"status": r.status_code})


# =============================================================================
# API4: RATE LIMITING - thread-safe header collection
# =============================================================================

def test_rate_limiting(session):
    print(f"\n{C.BOLD}== API4: Rate Limiting =={C.END}")
    url = url_for(EP_FACILITIES)
    params = {"per_page": 1, "page": 1}
    statuses = []
    rl_headers_seen = {}
    rl_lock = threading.Lock()

    def worker():
        if RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY)
        r, err = safe_send(session, "GET", url, params=params)
        if r is not None:
            with rl_lock:
                for h in r.headers:
                    hl = h.lower()
                    if hl.startswith("x-ratelimit") or hl in (
                            "retry-after", "ratelimit-limit",
                            "ratelimit-remaining", "ratelimit-reset"):
                        rl_headers_seen[h] = r.headers[h]
            return r.status_code
        return None

    with ThreadPoolExecutor(max_workers=RATE_LIMIT_THREADS) as ex:
        futures = [ex.submit(worker) for _ in range(RATE_LIMIT_REQUESTS)]
        for f in as_completed(futures):
            statuses.append(f.result())

    throttled = sum(1 for s in statuses if s == 429)
    if throttled > 0:
        record("RATE-01", "Rate limiting enforced", PASS,
               f"{throttled}/{RATE_LIMIT_REQUESTS} requests got HTTP 429.",
               owasp="API4",
               evidence={"throttled": throttled, "total": RATE_LIMIT_REQUESTS})
    else:
        record("RATE-01", "Rate limiting enforced", WARN,
               f"No 429s in {RATE_LIMIT_REQUESTS} rapid requests. "
               f"Inconclusive - retest at higher volume/duration.",
               owasp="API4", evidence={"statuses_seen": sorted(
                   {s for s in statuses if s is not None})})

    if rl_headers_seen:
        record("RATE-02", "Rate-limit headers exposed", INFO,
               f"Headers: {', '.join(rl_headers_seen)}",
               owasp="API4", evidence=rl_headers_seen)
    else:
        record("RATE-02", "Rate-limit headers exposed", WARN,
               "No X-RateLimit-* / RateLimit-* / Retry-After headers observed.",
               owasp="API4")


# =============================================================================
# API6: PAGINATION / INPUT-RANGE ABUSE - beefed up
# =============================================================================

def test_pagination_abuse(session):
    print(f"\n{C.BOLD}== API6: Pagination / Input Ranges =={C.END}")
    url = url_for(EP_FACILITIES)

    # Oversized page sizes should be capped or rejected
    for huge in [1000, 10000, 99999]:
        r, err = safe_send(session, "GET", url,
                           params={"per_page": huge, "page": 1})
        if err or r is None:
            record("PAGE-01", f"per_page={huge}", WARN,
                   f"Network error: {err}", owasp="API6")
            continue
        if r.status_code in (400, 422):
            record("PAGE-01", f"per_page={huge}", PASS,
                   f"Server rejected oversized page size (HTTP {r.status_code}).",
                   owasp="API6", evidence={"status": r.status_code})
        elif r.status_code == 200:
            try:
                count = len(r.json().get("data", []))
                capped = count < huge
                record("PAGE-01", f"per_page={huge}",
                       PASS if capped else WARN,
                       f"Returned {count} records "
                       f"({'capped' if capped else 'NOT capped'}).",
                       owasp="API6",
                       evidence={"returned": count, "requested": huge})
            except ValueError:
                record("PAGE-01", f"per_page={huge}", WARN,
                       "200 but non-JSON body.", owasp="API6")
        else:
            record("PAGE-01", f"per_page={huge}", INFO,
                   f"HTTP {r.status_code}.", owasp="API6",
                   evidence={"status": r.status_code})

    # Malformed pagination params should be cleanly rejected (400/422), not 500
    malformed = [{"page": "0"}, {"page": "-1"}, {"page": "abc"},
                 {"per_page": "-5"}, {"per_page": "abc"},
                 {"page": "99999999999999999999"}]
    for params in malformed:
        r, err = safe_send(session, "GET", url, params=params)
        if err or r is None:
            record("PAGE-02", f"Malformed {params}", WARN,
                   f"Network error: {err}", owasp="API6")
            continue
        # 500 = unhandled = bad; 400/422/200(clamped) = handled
        if r.status_code >= 500:
            record("PAGE-02", f"Malformed {params}", FAIL,
                   f"HTTP {r.status_code} (unhandled - server error).",
                   owasp="API6", evidence={"status": r.status_code})
        else:
            record("PAGE-02", f"Malformed {params}", PASS,
                   f"Handled gracefully (HTTP {r.status_code}).",
                   owasp="API6", evidence={"status": r.status_code})


# =============================================================================
# API10: INJECTION / INPUT HANDLING - beefed up + XSS gated on content-type
# =============================================================================

def _probe_filter(session, payload, param="state"):
    return safe_send(session, "GET", url_for(EP_FACILITIES),
                     params={param: payload})


def test_injection(session):
    print(f"\n{C.BOLD}== API10: Injection / Input Handling =={C.END}")

    # SQLi - error-signature based (smoke test; cannot detect blind/time-based)
    db_errors = ["sql syntax", "sqlstate", "psql:", "ora-0", "odbc",
                 "unclosed quotation", "pg::", "mysql", "syntax error at",
                 "sqlite", "near \"", "column does not exist"]
    for payload in SQLI_PAYLOADS:
        r, err = _probe_filter(session, payload)
        if err or r is None:
            record("INJ-01", f"SQLi {payload[:24]!r}", WARN,
                   f"Network error: {err}", owasp="API10")
            continue
        b = body_lower(r)
        leaked = any(sig in b for sig in db_errors)
        unhandled = r.status_code >= 500
        if leaked or unhandled:
            record("INJ-01", f"SQLi {payload[:24]!r}", FAIL,
                   f"HTTP {r.status_code}"
                   + (" + DB error signature leaked!" if leaked else
                      " (unhandled 5xx)"),
                   owasp="API10", evidence={"status": r.status_code})
        else:
            record("INJ-01", f"SQLi {payload[:24]!r}", PASS,
                   f"No DB error, HTTP {r.status_code}.",
                   owasp="API10", evidence={"status": r.status_code})

    # XSS - reflection ONLY matters if served as HTML. JSON reflection w/
    # nosniff is not exploitable, so downgrade that case to INFO.
    for payload in XSS_PAYLOADS:
        r, err = _probe_filter(session, payload)
        if err or r is None:
            record("INJ-02", f"XSS {payload[:24]!r}", WARN,
                   f"Network error: {err}", owasp="API10")
            continue
        ctype = r.headers.get("Content-Type", "").lower()
        nosniff = r.headers.get("X-Content-Type-Options", "").lower() == "nosniff"
        reflected = payload in (r.text or "")
        html_served = "text/html" in ctype
        if reflected and html_served:
            record("INJ-02", f"XSS {payload[:24]!r}", FAIL,
                   "Payload reflected unescaped in an HTML response!",
                   owasp="API10",
                   evidence={"status": r.status_code, "content_type": ctype})
        elif reflected and not nosniff:
            record("INJ-02", f"XSS {payload[:24]!r}", WARN,
                   f"Reflected in {ctype!r} WITHOUT nosniff (sniffing risk).",
                   owasp="API10",
                   evidence={"status": r.status_code, "content_type": ctype})
        elif reflected:
            record("INJ-02", f"XSS {payload[:24]!r}", INFO,
                   f"Reflected in {ctype!r} but nosniff set - not exploitable.",
                   owasp="API10",
                   evidence={"status": r.status_code, "content_type": ctype})
        else:
            record("INJ-02", f"XSS {payload[:24]!r}", PASS,
                   f"Not reflected (HTTP {r.status_code}).",
                   owasp="API10", evidence={"status": r.status_code})

    # Command / template / NoSQL injection - look for evaluation or 5xx
    for label, payloads, marker in (
            ("CMD", CMD_PAYLOADS, ["uid=", "gid=", "root:"]),
            ("TMPL", TEMPLATE_PAYLOADS, ["49"]),         # 7*7 evaluated
            ("NOSQL", NOSQL_PAYLOADS, None)):
        for payload in payloads:
            r, err = _probe_filter(session, payload)
            if err or r is None:
                record(f"INJ-{label}", f"{label} {payload[:20]!r}", WARN,
                       f"Network error: {err}", owasp="API10")
                continue
            b = body_lower(r)
            evaluated = marker and any(m in b for m in marker)
            unhandled = r.status_code >= 500
            if evaluated:
                record(f"INJ-{label}", f"{label} {payload[:20]!r}", FAIL,
                       f"Payload appears evaluated (marker found)!",
                       owasp="API10", evidence={"status": r.status_code})
            elif unhandled:
                record(f"INJ-{label}", f"{label} {payload[:20]!r}", FAIL,
                       f"Unhandled HTTP {r.status_code}.",
                       owasp="API10", evidence={"status": r.status_code})
            else:
                record(f"INJ-{label}", f"{label} {payload[:20]!r}", PASS,
                       f"No evidence of evaluation (HTTP {r.status_code}).",
                       owasp="API10", evidence={"status": r.status_code})


# =============================================================================
# PATH TRAVERSAL - records actual bytes sent (client may normalize)
# =============================================================================

def test_path_traversal(session):
    print(f"\n{C.BOLD}== Path Traversal =={C.END}")
    for payload in TRAVERSAL_PAYLOADS:
        url = url_for(EP_FACILITY_BY_ID.format(id=payload))
        r, err = safe_send(session, "GET", url)
        if err or r is None:
            # urllib3 can refuse to send certain payloads (e.g. null bytes) -
            # that's effectively the client blocking it; note it.
            record("TRAV-01", f"Traversal {payload[:28]!r}", INFO,
                   f"Client refused to send: {err}", owasp="API1")
            continue
        sent = getattr(r.request, "url", url)
        b = body_lower(r)
        sysfile = any(m in b for m in ["root:x:", "[extensions]",
                                       "/bin/bash", "16-bit app support"])
        if sysfile or r.status_code == 200:
            record("TRAV-01", f"Traversal {payload[:28]!r}",
                   FAIL if sysfile else WARN,
                   f"HTTP {r.status_code}"
                   + (" - SYSTEM FILE CONTENT RETURNED!" if sysfile
                      else " - 200 to a traversal path, review."),
                   owasp="API1",
                   evidence={"status": r.status_code, "sent_url": sent})
        else:
            record("TRAV-01", f"Traversal {payload[:28]!r}", PASS,
                   f"Rejected (HTTP {r.status_code}).", owasp="API1",
                   evidence={"status": r.status_code, "sent_url": sent})


# =============================================================================
# API7: SSRF - beefed up
# =============================================================================

def test_ssrf(session):
    print(f"\n{C.BOLD}== API7: SSRF =={C.END}")
    url = url_for(EP_NEARBY)
    # Cloud metadata IP + loopback as geo / address-ish params. We can only
    # confirm the input is validated, not prove no internal fetch occurs.
    cases = [
        {"lat": "169.254.169.254", "lng": "0.0", "drive_time": "10"},
        {"lat": "127.0.0.1", "lng": "127.0.0.1"},
        {"street_address": "http://169.254.169.254/latest/meta-data/",
         "city": "x", "state": "VA", "zip": "00000"},
    ]
    for params in cases:
        r, err = safe_send(session, "GET", url, params=params)
        if err or r is None:
            record("SSRF-01", f"Nearby {list(params)[0]}", WARN,
                   f"Network error: {err}", owasp="API7")
            continue
        b = body_lower(r)
        meta_leak = any(m in b for m in ["ami-id", "instance-id",
                                         "iam/security-credentials",
                                         "computemetadata"])
        if meta_leak:
            record("SSRF-01", f"Nearby {list(params)[0]}", FAIL,
                   "Cloud metadata content in response - possible SSRF!",
                   owasp="API7", evidence={"status": r.status_code})
        else:
            ok = r.status_code in (400, 404, 422, 200)
            record("SSRF-01", f"Nearby {list(params)[0]}",
                   PASS if ok else WARN,
                   f"HTTP {r.status_code}; no metadata leaked "
                   f"(manual review still advised).",
                   owasp="API7", evidence={"status": r.status_code})


# =============================================================================
# API8: SECURITY HEADERS - beefed up with quality checks + cookie flags
# =============================================================================

def test_security_headers(session):
    print(f"\n{C.BOLD}== API8: Security Headers =={C.END}")
    r, err = safe_send(session, "GET", url_for(EP_FACILITIES),
                       params={"per_page": 1})
    if err or r is None:
        record("HDR-00", "Header retrieval", WARN, f"Network error: {err}",
               owasp="API8")
        return
    headers = {k.lower(): v for k, v in r.headers.items()}

    for name, quality in EXPECTED_SECURITY_HEADERS.items():
        val = headers.get(name.lower())
        if val is None:
            record("HDR-01", f"{name}", WARN, "MISSING", owasp="API8")
        elif quality is None:
            record("HDR-01", f"{name}", PASS, val, owasp="API8")
        else:
            ok, note = quality(val)
            record("HDR-01", f"{name}", PASS if ok else WARN,
                   f"{val}  ({note})", owasp="API8")

    for leak in INFO_LEAK_HEADERS:
        val = headers.get(leak.lower())
        record("HDR-02", f"Info-leak absent: {leak}",
               WARN if val is not None else PASS,
               val if val is not None else "absent (good)", owasp="API8")

    ctype = headers.get("content-type", "")
    record("HDR-03", "JSON content-type", PASS if "json" in ctype else WARN,
           ctype or "missing", owasp="API8")

    # Cookie flags, if any cookies are set
    set_cookie = r.headers.get("Set-Cookie")
    if set_cookie:
        sc = set_cookie.lower()
        flags_ok = "secure" in sc and "httponly" in sc and "samesite" in sc
        record("HDR-04", "Cookie security flags", PASS if flags_ok else WARN,
               f"Secure={'secure' in sc}, HttpOnly={'httponly' in sc}, "
               f"SameSite={'samesite' in sc}", owasp="API8")
    else:
        record("HDR-04", "Cookie security flags", INFO,
               "No Set-Cookie header (stateless API).", owasp="API8")


def test_error_verbosity(session):
    print(f"\n{C.BOLD}== API8: Error Verbosity =={C.END}")
    triggers = [
        ("malformed params", {"page": "not-a-number", "per_page": "abc"},
         url_for(EP_FACILITIES)),
        ("nonexistent path", None, host_root() + "/services/va_facilities/v1/zzz"),
    ]
    stack_sigs = ["traceback", "exception in", "at java.", "at org.",
                  "stacktrace", ".java:", ".rb:", ".py\", line", "nullpointer",
                  "caused by:", "at com.", "system.web", "werkzeug"]
    for label, params, url in triggers:
        r, err = safe_send(session, "GET", url, params=params)
        if err or r is None:
            record("ERR-01", f"Error verbosity ({label})", WARN,
                   f"Network error: {err}", owasp="API8")
            continue
        b = body_lower(r)
        leaked = any(sig in b for sig in stack_sigs)
        record("ERR-01", f"Error verbosity ({label})",
               FAIL if leaked else PASS,
               "Stack trace / internal detail leaked!" if leaked
               else f"Clean error (HTTP {r.status_code}).",
               owasp="API8", evidence={"status": r.status_code})


# =============================================================================
# API9: INVENTORY MANAGEMENT - versions + debug/metadata path probing
# =============================================================================

def test_inventory(session):
    print(f"\n{C.BOLD}== API9: Inventory / Surface =={C.END}")
    root = host_root()

    for path in HOST_RELATIVE_PROBES:
        r, err = safe_send(session, "GET", root + path, params={"per_page": 1})
        if err or r is None:
            record("INV-01", f"Version path {path}", WARN,
                   f"Network error: {err}", owasp="API9")
            continue
        if r.status_code == 200:
            record("INV-01", f"Version path {path}", WARN,
                   "Undocumented/old version returns 200 - review.",
                   owasp="API9", evidence={"status": r.status_code})
        else:
            record("INV-01", f"Version path {path}", PASS,
                   f"Not exposed (HTTP {r.status_code}).",
                   owasp="API9", evidence={"status": r.status_code})

    # Common debug / framework / metadata endpoints (GET only, non-destructive)
    for path in DEBUG_PATH_PROBES:
        r, err = safe_send(session, "GET", root + path)
        if err or r is None:
            continue
        if r.status_code == 200:
            record("INV-02", f"Debug path {path}", WARN,
                   "Reachable (HTTP 200) - confirm it should be public.",
                   owasp="API9", evidence={"status": r.status_code})
        else:
            record("INV-02", f"Debug path {path}", PASS,
                   f"Not exposed (HTTP {r.status_code}).",
                   owasp="API9", evidence={"status": r.status_code})

    # OpenAPI spec exposure (informational - expected for a public dev portal)
    r, err = safe_send(session, "GET", url_for(EP_OPENAPI))
    if r is not None and r.status_code == 200:
        record("INV-03", "OpenAPI spec exposed", INFO,
               "Spec reachable (expected for a public dev-portal API).",
               owasp="API9")


# =============================================================================
# CORS - simple request + preflight
# =============================================================================

def test_cors(session):
    print(f"\n{C.BOLD}== CORS Configuration =={C.END}")
    evil = "https://evil.example.com"

    # Simple request with a foreign Origin
    r, err = safe_send(session, "GET", url_for(EP_FACILITIES),
                       headers={"Origin": evil}, params={"per_page": 1})
    if not (err or r is None):
        _eval_cors("CORS-01", "Simple request", r, evil)

    # Preflight: OPTIONS with Access-Control-Request-Method
    r, err = safe_send(session, "OPTIONS", url_for(EP_FACILITIES),
                       headers={"Origin": evil,
                                "Access-Control-Request-Method": "GET",
                                "Access-Control-Request-Headers": "apikey"},
                       allow_auth=False)
    if not (err or r is None):
        _eval_cors("CORS-02", "Preflight (OPTIONS)", r, evil)


def _eval_cors(tid, name, r, evil_origin):
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
    ev = {"acao": acao, "acac": acac, "status": r.status_code}
    if acao == "*" and acac == "true":
        record(tid, name, FAIL,
               "ACAO='*' WITH credentials=true (invalid + dangerous).",
               owasp="API8", evidence=ev)
    elif acao == evil_origin and acac == "true":
        record(tid, name, FAIL,
               "Arbitrary origin reflected WITH credentials.",
               owasp="API8", evidence=ev)
    elif acao == evil_origin:
        record(tid, name, WARN,
               "Arbitrary origin reflected (no creds) - review allow-list.",
               owasp="API8", evidence=ev)
    else:
        record(tid, name, PASS,
               f"ACAO={acao or 'not set'!r} - no obvious misconfig.",
               owasp="API8", evidence=ev)


# =============================================================================
# RUNNER (isolated) + REPORTING
# =============================================================================

def run_group(label, fn, *args):
    """Run a test group in isolation; a crash becomes one FAIL, run continues."""
    try:
        fn(*args)
    except Exception as e:  # noqa: BLE001 - we want to catch everything here
        record(f"GROUP-{label}", f"Test group '{label}' crashed", FAIL,
               f"{type(e).__name__}: {e}")
        print(f"  {C.RED}[FAIL] Group '{label}' raised {type(e).__name__}: "
              f"{e}{C.END}")


def write_markdown(report):
    lines = [
        f"# VA Facilities API - Security Report",
        "",
        f"- **Target:** `{report['target']}`",
        f"- **Generated:** {report['generated']}",
        f"- **Totals:** {report['summary']}",
        "",
        "| Status | OWASP | Test | Detail |",
        "|---|---|---|---|",
    ]
    order = {FAIL: 0, WARN: 1, INFO: 2, PASS: 3}
    for r in sorted(report["results"], key=lambda x: order.get(x["status"], 9)):
        detail = r["detail"].replace("|", "\\|")
        lines.append(f"| {r['status']} | {r['owasp'] or '-'} | "
                     f"{r['name']} | {detail} |")
    with open(OUTPUT_MARKDOWN, "w") as f:
        f.write("\n".join(lines) + "\n")


def summarize_and_save():
    print(f"\n{C.BOLD}{'='*64}{C.END}")
    print(f"{C.BOLD}  SUMMARY{C.END}")
    print(f"{C.BOLD}{'='*64}{C.END}")

    counts = {PASS: 0, FAIL: 0, WARN: 0, INFO: 0}
    by_owasp = {}
    for r in RESULTS:
        counts[r["status"]] += 1
        key = r["owasp"] or "general"
        by_owasp.setdefault(key, {PASS: 0, FAIL: 0, WARN: 0, INFO: 0})
        by_owasp[key][r["status"]] += 1

    print(f"  {C.GREEN}PASS: {counts[PASS]:>3}{C.END}   "
          f"{C.RED}FAIL: {counts[FAIL]:>3}{C.END}   "
          f"{C.YELLOW}WARN: {counts[WARN]:>3}{C.END}   "
          f"{C.BLUE}INFO: {counts[INFO]:>3}{C.END}   "
          f"(total {len(RESULTS)})")

    print(f"\n  {C.BOLD}By OWASP category:{C.END}")
    for cat in sorted(by_owasp):
        c = by_owasp[cat]
        print(f"    {cat:<8} "
              f"{C.GREEN}P{c[PASS]}{C.END} "
              f"{C.RED}F{c[FAIL]}{C.END} "
              f"{C.YELLOW}W{c[WARN]}{C.END} "
              f"{C.BLUE}I{c[INFO]}{C.END}")

    if counts[FAIL]:
        print(f"\n  {C.RED}{C.BOLD}Failures requiring attention:{C.END}")
        for r in RESULTS:
            if r["status"] == FAIL:
                print(f"    {C.RED}- [{r['owasp']}] {r['name']}: "
                      f"{r['detail']}{C.END}")
    if counts[WARN]:
        print(f"\n  {C.YELLOW}{C.BOLD}Warnings to review:{C.END}")
        for r in RESULTS:
            if r["status"] == WARN:
                print(f"    {C.YELLOW}- [{r['owasp']}] {r['name']}: "
                      f"{r['detail']}{C.END}")

    report = {
        "target": BASE_URL,
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": counts,
        "by_owasp": by_owasp,
        "results": RESULTS,
    }
    with open(OUTPUT_JSON, "w") as f:
        json.dump(report, f, indent=2)
    write_markdown(report)
    print(f"\n  {C.DIM}JSON report : {OUTPUT_JSON}{C.END}")
    print(f"  {C.DIM}Markdown    : {OUTPUT_MARKDOWN}{C.END}")

    return 1 if counts[FAIL] else 0


# =============================================================================
# MAIN
# =============================================================================

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="VA Lighthouse Facilities API - Security Test Suite v2",
        epilog="All flags override the matching constants in the "
               "CONFIGURATION block at the top of this file.")
    p.add_argument("--base-url", default=None,
                   help=f"target base URL (default: {BASE_URL})")
    p.add_argument("--api-key", default=None,
                   help="API key (optional; auth-gated tests are skipped "
                        "if omitted)")
    p.add_argument("--api-key-header", default=None,
                   help=f"header name for the API key (default: "
                        f"{API_KEY_HEADER})")
    p.add_argument("--facility-id", default=None,
                   help="known-valid facility ID (default: auto-discover)")
    p.add_argument("--timeout", type=int, default=None,
                   help=f"per-request timeout in seconds (default: {TIMEOUT})")
    p.add_argument("--no-verify-tls", action="store_true",
                   help="disable TLS certificate verification "
                        "(proxy debugging only)")
    p.add_argument("--proxy", default=None,
                   help="HTTPS proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--rate-limit-requests", type=int, default=None,
                   help=f"rapid requests to fire in the rate-limit burst "
                        f"(default: {RATE_LIMIT_REQUESTS})")
    p.add_argument("--rate-limit-threads", type=int, default=None,
                   help=f"concurrency for the rate-limit burst "
                        f"(default: {RATE_LIMIT_THREADS})")
    p.add_argument("--rate-limit-delay", type=float, default=None,
                   help=f"seconds between dispatches "
                        f"(default: {RATE_LIMIT_DELAY})")
    p.add_argument("--output-json", default=None,
                   help=f"JSON report path (default: {OUTPUT_JSON})")
    p.add_argument("--output-markdown", default=None,
                   help=f"Markdown report path (default: {OUTPUT_MARKDOWN})")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress per-test output")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip the non-sandbox confirmation prompt")
    return p.parse_args(argv)


def apply_args(args):
    """Override module-level configuration constants from parsed CLI args."""
    global BASE_URL, API_KEY, API_KEY_HEADER, KNOWN_FACILITY_ID
    global TIMEOUT, VERIFY_TLS, PROXIES
    global RATE_LIMIT_REQUESTS, RATE_LIMIT_THREADS, RATE_LIMIT_DELAY
    global OUTPUT_JSON, OUTPUT_MARKDOWN, VERBOSE

    if args.base_url is not None:
        BASE_URL = args.base_url
    if args.api_key is not None:
        API_KEY = args.api_key
    if args.api_key_header is not None:
        API_KEY_HEADER = args.api_key_header
    if args.facility_id is not None:
        KNOWN_FACILITY_ID = args.facility_id
    if args.timeout is not None:
        TIMEOUT = args.timeout
    if args.no_verify_tls:
        VERIFY_TLS = False
    if args.proxy is not None:
        PROXIES = {"https": args.proxy, "http": args.proxy}
    if args.rate_limit_requests is not None:
        RATE_LIMIT_REQUESTS = args.rate_limit_requests
    if args.rate_limit_threads is not None:
        RATE_LIMIT_THREADS = args.rate_limit_threads
    if args.rate_limit_delay is not None:
        RATE_LIMIT_DELAY = args.rate_limit_delay
    if args.output_json is not None:
        OUTPUT_JSON = args.output_json
    if args.output_markdown is not None:
        OUTPUT_MARKDOWN = args.output_markdown
    if args.quiet:
        VERBOSE = False


def main(argv=None):
    args = parse_args(argv)
    apply_args(args)

    print(f"""
{C.BOLD}VA Lighthouse Facilities API - Security Test Suite v2{C.END}
{C.DIM}Target : {BASE_URL}
Time   : {datetime.now(timezone.utc).isoformat()}
Mode   : Non-destructive (OWASP API Top 10 2023){C.END}
""")

    session = make_session()
    preflight(session, assume_yes=args.yes)
    facility_id = discover_facility_id(session)

    # Each group is isolated: a crash in one still lets the rest run + report.
    run_group("control", test_positive_control, session)
    run_group("tls", test_tls, session)
    run_group("auth", test_authentication, session)
    run_group("bola", test_object_authorization, session, facility_id)
    run_group("methods", test_method_handling, session, facility_id)
    run_group("rate", test_rate_limiting, session)
    run_group("pagination", test_pagination_abuse, session)
    run_group("injection", test_injection, session)
    run_group("traversal", test_path_traversal, session)
    run_group("ssrf", test_ssrf, session)
    run_group("headers", test_security_headers, session)
    run_group("errors", test_error_verbosity, session)
    run_group("inventory", test_inventory, session)
    run_group("cors", test_cors, session)

    return summarize_and_save()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Interrupted by user.{C.END}")
        sys.exit(130)