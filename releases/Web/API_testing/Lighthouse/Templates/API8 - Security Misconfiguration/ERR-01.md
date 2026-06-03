## ERR-01 — Verbose Error Messages Reveal Internal Detail

## OWASP
[API8 - Security Misconfiguration]

## Finding Title
Stack Trace or Internal Detail Returned in Error Response

## Finding Description
Submitting malformed input caused the server to return a `5xx` response body containing a stack trace, internal file path, framework version, or exception type. This information reveals the internal architecture of the application and provides an attacker with a detailed map of the codebase, dependencies, and execution flow.

## Risk Level
Medium

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Stack traces reveal the exact line and file of the failure, the framework and library versions in use, and often the full call stack. This significantly reduces the effort required to identify exploitable code paths and tailor payloads to the specific runtime environment.

## Steps to Reproduce Finding
```bash
curl -s -H "apikey: $API_KEY" \
  "$BASE_URL/facilities?page=not-a-number&per_page=abc"

curl -s -H "apikey: $API_KEY" \
  "$HOST_ROOT/services/va_facilities/v1/zzz-nonexistent"
```
Observed: `[STACK TRACE EXCERPT OR INTERNAL PATH]` in the response body.

## Remediation Steps
- Configure a global exception handler that catches all unhandled errors and returns a generic `500` response body (e.g. `{"error": "Internal server error"}`) with no stack trace or internal detail.
- Set the framework or runtime to production mode to suppress debug output (e.g. `RAILS_ENV=production`, `DEBUG=False`, `NODE_ENV=production`).
- Log full error details (stack trace, request context) to a secure, internal log aggregator — not to the HTTP response.
- Validate this is working by confirming that triggering a known error path returns a generic message with no framework or path information.
