## HDR-04 — Insecure Cookie Configuration

## OWASP
[API8 - Security Misconfiguration]

## Finding Title
Session Cookie Missing Security Flags

## Finding Description
The API sets a cookie via `Set-Cookie` that is missing one or more of the following security flags: `Secure`, `HttpOnly`, `SameSite`. The observed `Set-Cookie` header was: `[OBSERVED VALUE]`. Missing flags allow the cookie to be transmitted over plaintext connections, accessed by JavaScript, or sent in cross-site requests.

## Risk Level
Medium

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
A missing `Secure` flag allows the cookie to be transmitted over HTTP and captured by a network attacker. A missing `HttpOnly` flag allows JavaScript to read the cookie, enabling theft via XSS. A missing `SameSite` flag exposes the cookie to cross-site request forgery (CSRF) attacks.

## Steps to Reproduce Finding
```bash
curl -s -D - -o /dev/null -H "apikey: $API_KEY" "$BASE_URL/facilities?per_page=1" \
  | grep -i "^set-cookie:"
```
Observed: `Set-Cookie: [VALUE]` — missing `[Secure / HttpOnly / SameSite]` flag(s).
