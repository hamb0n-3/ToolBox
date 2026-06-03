## AUTH-03 — Invalid API Key Accepted

## OWASP
[API2 - Broken Authentication]

## Finding Title
Invalid API Key Grants Access

## Finding Description
A request using a fabricated, non-issued API key value (`invalid-key-000000000000`) returned an HTTP `200` response. The server is not validating credentials against its issued key store before granting access.

## Risk Level
Critical

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Authentication can be bypassed entirely by supplying any value in the `apikey` header. No valid credentials are required to access the API, rendering the authentication scheme non-functional.

## Steps to Reproduce Finding
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "apikey: invalid-key-000000000000" "$BASE_URL/facilities?per_page=1"
```
Observed: `200` — expected `401` or `403`.
