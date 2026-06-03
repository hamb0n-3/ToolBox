## HDR-01 — Required Security Headers Missing

## OWASP
[API8 - Security Misconfiguration]

## Finding Title
One or More Required Security Response Headers Absent

## Finding Description
The API response is missing one or more of the following security headers: `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`, or `Permissions-Policy`. The missing headers are: `[LIST MISSING HEADERS]`.

## Risk Level
Medium

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Each missing header removes a specific browser-level defence. Absent `Strict-Transport-Security` allows protocol downgrade attacks. Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff responses and execute content as a different type. A missing CSP expands the XSS attack surface. Without `X-Frame-Options`, the site can be embedded in an iframe for clickjacking.

## Steps to Reproduce Finding
```bash
curl -s -D - -o /dev/null -H "apikey: $API_KEY" "$BASE_URL/facilities?per_page=1" \
  | grep -iE "strict-transport-security|x-content-type-options|x-frame-options|content-security-policy|referrer-policy|permissions-policy"
```
Observed: `[MISSING HEADER]` absent from the response. HSTS `max-age` below `15552000` also constitutes a finding.

## Remediation Steps
- Add the missing headers at the reverse proxy or API gateway layer so they apply globally to all responses without per-route configuration:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'none'`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: geolocation=(), microphone=()`
- Validate header presence with an automated check in the CI pipeline (e.g. `securityheaders.com` API or a custom integration test).
