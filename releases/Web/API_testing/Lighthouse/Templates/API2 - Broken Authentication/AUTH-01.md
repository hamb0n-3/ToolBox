## AUTH-01 — Unauthenticated Access Permitted

## OWASP
[API2 - Broken Authentication]

## Finding Title
API Endpoint Accessible Without Authentication

## Finding Description
A request to `/facilities` without any API key returned an HTTP `200` response with data. The endpoint does not enforce authentication, allowing any party with network access to retrieve VA facility information without credentials.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Any unauthenticated party can enumerate VA facility data without obtaining credentials. While this API serves publicly available information, the lack of authentication removes all access controls, prevents audit logging of who is accessing the data, and eliminates the ability to revoke access from abusive clients.

## Steps to Reproduce Finding
```bash
curl -s -o /dev/null -w "%{http_code}\n" "$BASE_URL/facilities?per_page=1"
```
Observed: `200` — expected `401` or `403`.
