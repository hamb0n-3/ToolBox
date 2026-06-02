## AUTH-05 — Whitespace API Key Accepted

## OWASP
[API2 - Broken Authentication]

## Finding Title
Whitespace-Only API Key Value Grants Access

## Finding Description
An `apikey` header containing only whitespace characters (spaces) was accepted and returned an HTTP `200` response. The authentication layer is not trimming or validating that the key contains meaningful content before performing a credential lookup.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Authentication can be bypassed by submitting a header with whitespace content. This may indicate the key validation logic is absent or trivially circumventable with simple character manipulation.

## Steps to Reproduce Finding
```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "apikey:    " "$BASE_URL/facilities?per_page=1"
```
Observed: `200` — expected `401` or `403`.
