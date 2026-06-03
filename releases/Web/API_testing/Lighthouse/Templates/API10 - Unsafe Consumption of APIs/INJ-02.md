## INJ-02 — Reflected Cross-Site Scripting (XSS)

## OWASP
[API10 - Unsafe Consumption of APIs]

## Finding Title
XSS Payload Reflected in HTML Response

## Finding Description
An XSS payload submitted in the `state` filter parameter was reflected back unescaped in an HTTP response served with `Content-Type: text/html`. A victim's browser would execute the reflected script in the context of the origin, allowing session hijacking, credential theft, or malicious actions on behalf of the user.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Reflected XSS can be weaponised by tricking a user into clicking a crafted URL. In the context of a developer portal or documentation page that renders API responses, the attacker could steal API keys, session tokens, or perform actions on behalf of the authenticated user.

## Steps to Reproduce Finding
```bash
curl -s -G -i -H "apikey: $API_KEY" "$BASE_URL/facilities" \
  --data-urlencode 'state=<script>alert(1)</script>' \
  | grep -iE "content-type|<script"
```
Observed: payload `<script>alert(1)</script>` reflected unescaped in the body; `Content-Type: text/html` with no `X-Content-Type-Options: nosniff`.

> **Note:** Reflection inside a `application/json` response **with** `nosniff` set is not exploitable as XSS and should be recorded as Informational only.

## Remediation Steps
- HTML-encode all user-supplied values before rendering them in any HTML context. Use your framework's built-in output encoding functions rather than manual string replacement.
- Return API responses with `Content-Type: application/json` and `X-Content-Type-Options: nosniff` so that even if a payload is reflected in the JSON body, the browser will not render it as HTML.
- If any endpoint intentionally renders HTML, apply a strict `Content-Security-Policy` that disables inline scripts.
