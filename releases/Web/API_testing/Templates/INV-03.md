## INV-03 — API Specification Publicly Exposed

## OWASP
[API9 - Improper Inventory Management]

## Finding Title
OpenAPI Specification Accessible Without Restriction

## Finding Description
The OpenAPI specification (`/openapi.json`) is publicly accessible and returns a complete description of all endpoints, parameters, data models, and authentication schemes. While expected for a public developer portal API, this should be confirmed as intentional.

## Risk Level
Informational

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
The OpenAPI specification provides an attacker with a complete, machine-readable map of the API surface. This significantly accelerates automated fuzzing and vulnerability scanning. For internal or partner APIs, unintended specification exposure can reveal endpoints that are not intended to be public.

## Steps to Reproduce Finding
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "apikey: $API_KEY" "$BASE_URL/openapi.json"
```
Observed: `200` — confirm that specification exposure is intentional for this environment.
