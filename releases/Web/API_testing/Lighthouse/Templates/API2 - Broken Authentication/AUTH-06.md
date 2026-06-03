## AUTH-06 — Incorrect Authentication Scheme Accepted

## OWASP
[API2 - Broken Authentication]

## Finding Title
API Key Accepted via Wrong Authentication Header

## Finding Description
A request using `Authorization: Bearer [KEY]` instead of the documented `apikey: [KEY]` header returned an HTTP `200` response. The server appears to accept credentials supplied through an undocumented authentication mechanism, indicating inconsistent authentication logic.

## Risk Level
Medium

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Undocumented authentication pathways are difficult to audit and maintain. An alternate scheme that grants the same access may have weaker validation, different rate limiting, or be excluded from security monitoring, creating a shadow authentication path.

## Steps to Reproduce Finding
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $API_KEY" "$BASE_URL/facilities?per_page=1"
```
Observed: `200` — expected `401` or `403`.
