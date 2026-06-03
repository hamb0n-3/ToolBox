## CORS-02 — CORS Misconfiguration (Preflight)

## OWASP
[API8 - Security Misconfiguration]

## Finding Title
CORS Preflight Response Grants Access to Arbitrary Origin

## Finding Description
An `OPTIONS` preflight request with `Origin: https://evil.example.com` and `Access-Control-Request-Method: GET` received a response granting the requested cross-origin access. The CORS policy does not enforce an origin allow-list, permitting any website to initiate credentialed cross-origin API calls after a successful preflight negotiation.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Browsers rely on a successful preflight response before issuing credentialed cross-origin requests with custom headers (such as the `apikey` header). A permissive preflight response means any attacker-controlled site can send authenticated API requests using the victim's credentials, and read the responses — bypassing the browser's same-origin policy.

## Steps to Reproduce Finding
```bash
curl -s -D - -o /dev/null -X OPTIONS \
  -H "Origin: https://evil.example.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: apikey" \
  "$BASE_URL/facilities" | grep -i "access-control"
```
Observed: `Access-Control-Allow-Origin: [VALUE]` and `Access-Control-Allow-Headers: apikey` in the preflight response for an arbitrary origin.
