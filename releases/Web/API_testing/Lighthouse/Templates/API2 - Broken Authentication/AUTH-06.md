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

## Remediation Steps
- Restrict credential acceptance to a single, explicitly documented authentication scheme. Parse only the expected header (`apikey`) and ignore all others.
- Return `401` for requests that present a credential via an alternative header or scheme.
- Remove any code paths that extract credentials from `Authorization`, `X-Api-Key`, or other non-canonical headers unless those schemes are intentionally supported and documented.
- Audit the authentication middleware to confirm there is exactly one credential-extraction path.
