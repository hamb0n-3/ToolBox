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

## Remediation Steps
- Apply authentication middleware globally at the framework or gateway level so that no endpoint can be reached without a valid credential, rather than relying on per-route decoration.
- Return `401 Unauthorized` with a `WWW-Authenticate` header for missing credentials and `403 Forbidden` for a valid but unauthorised key.
- Ensure authentication is enforced before any business logic or data access is triggered, so unauthenticated requests cannot reach the data layer even partially.
- Audit all routes with an automated integration test that asserts every endpoint returns `4xx` when called without credentials.
