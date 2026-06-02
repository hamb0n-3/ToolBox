## CTRL-01 — Baseline Request Failure

## OWASP
[N/A — Positive Control]

## Finding Title
API Baseline Request Returns Unexpected Response

## Finding Description
A valid, authenticated request to the `/facilities` endpoint did not return an HTTP `200` with a well-formed JSON body. This indicates the API is unavailable, misconfigured, or that the authentication credentials provided are not accepted, undermining the reliability of all subsequent test results.

## Risk Level
Informational

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
No functional impact by itself. However, a failing baseline invalidates the result of any test that requires a successful authenticated response. Results from data-dependent tests (injection, pagination, property exposure) must be treated as inconclusive.

## Steps to Reproduce Finding
```bash
curl -s -i -H "apikey: $API_KEY" "$BASE_URL/facilities?per_page=1&page=1"
```
Observed response: `[HTTP STATUS]` — expected `200` with `Content-Type: application/json`.
