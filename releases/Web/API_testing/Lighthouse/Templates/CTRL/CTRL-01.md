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

## Remediation Steps
- This is a positive control check, not a vulnerability finding. No remediation is required for the API itself.
- If this check fails during a test run, investigate the cause before relying on any other test results: confirm the `$API_KEY` is valid and not expired, verify the `$BASE_URL` is reachable from the test host, and check for any known API outages or maintenance windows.
- All other test results should be treated as inconclusive until this baseline check passes.
