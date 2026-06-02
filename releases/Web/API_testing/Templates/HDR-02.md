## HDR-02 — Server Information Disclosed via Response Headers

## OWASP
[API8 - Security Misconfiguration]

## Finding Title
Web Server or Framework Version Disclosed in Response Headers

## Finding Description
The API response includes one or more headers that disclose the underlying server software and version: `[OBSERVED HEADER: VALUE]`. This information provides attackers with a starting point for identifying known CVEs and tailoring exploits to the specific software stack in use.

## Risk Level
Low

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Version disclosure reduces the effort required to identify and exploit known vulnerabilities in the underlying web server, application framework, or runtime. While not exploitable by itself, it lowers the bar for subsequent attacks.

## Steps to Reproduce Finding
```bash
curl -s -D - -o /dev/null -H "apikey: $API_KEY" "$BASE_URL/facilities?per_page=1" \
  | grep -iE "^server:|^x-powered-by:|^x-aspnet-version:|^x-runtime:|^x-generator:"
```
Observed: `[HEADER]: [VALUE]` — this header should be suppressed.
