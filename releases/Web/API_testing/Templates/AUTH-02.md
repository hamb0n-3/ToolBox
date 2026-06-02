## AUTH-02 — Empty API Key Accepted

## OWASP
[API2 - Broken Authentication]

## Finding Title
Empty API Key Value Grants Access

## Finding Description
Sending an `apikey` header with an empty string value returned an HTTP `200` response. The authentication middleware does not validate that the key value is non-empty before processing the request, effectively treating an empty credential as valid.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Any client aware of the expected header name can bypass authentication by submitting an empty value. This eliminates the access control value of the API key scheme entirely.

## Steps to Reproduce Finding
```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "apikey: " "$BASE_URL/facilities?per_page=1"
```
Observed: `200` — expected `401` or `403`.
