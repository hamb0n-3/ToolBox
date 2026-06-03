## CORS-01 — CORS Misconfiguration (Simple Request)

## OWASP
[API8 - Security Misconfiguration]

## Finding Title
CORS Policy Reflects Arbitrary Origin or Uses Wildcard with Credentials

## Finding Description
A simple cross-origin `GET` request with `Origin: https://evil.example.com` received a response with `Access-Control-Allow-Origin: https://evil.example.com` (or `*`) combined with `Access-Control-Allow-Credentials: true`. This allows a malicious site to make authenticated cross-origin API requests on behalf of a visiting user.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
A user visiting a malicious site can have their authenticated session used to make API requests to the VA API. Any data returned is accessible to the attacker's script. This enables cross-site request forgery at the API level, bypassing same-origin browser protections.

## Steps to Reproduce Finding
```bash
curl -s -D - -o /dev/null -H "apikey: $API_KEY" \
  -H "Origin: https://evil.example.com" "$BASE_URL/facilities?per_page=1" \
  | grep -i "access-control"
```
Observed: `Access-Control-Allow-Origin: [VALUE]` and `Access-Control-Allow-Credentials: [VALUE]`. A reflected arbitrary origin combined with `credentials: true` confirms the finding.

## Remediation Steps
- Maintain an explicit server-side allow-list of trusted origins. On each request, compare the `Origin` header against the list and echo it back only if it matches; never reflect an arbitrary origin.
- Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` — the browser will reject it, and attempting it is a configuration error.
- If a broad origin policy is required, reconsider whether the API should rely on session cookies/credentials at all, or enforce API-key-based auth that is not affected by CORS.
