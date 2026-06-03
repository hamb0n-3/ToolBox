## INV-02 — Debug or Administrative Endpoint Exposed

## OWASP
[API9 - Improper Inventory Management]

## Finding Title
Internal Debug or Framework Management Endpoint Publicly Reachable

## Finding Description
A request to a common framework or operational endpoint (e.g. `/actuator/env`, `/actuator/health`, `/.git/config`) returned an HTTP `200` response. These endpoints are intended for internal use and expose configuration, environment variables, dependency versions, Git repository metadata, or operational metrics.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Depending on the specific endpoint, an attacker can retrieve environment variables containing credentials and secrets, enumerate all routes and beans in the application, read Git history to identify previous credentials or internal paths, or trigger operations such as thread dumps and heap dumps that can expose data from memory.

## Steps to Reproduce Finding
```bash
for p in /actuator /actuator/health /actuator/env /health /metrics \
         /debug /.git/config /swagger-ui.html /v2/api-docs; do
  printf "%-22s " "$p"
  curl -s -o /dev/null -w "%{http_code}\n" -H "apikey: $API_KEY" "$HOST_ROOT$p"
done
```
Observed: `200` for `[PATH]`. Response contents: `[SUMMARY OF EXPOSED DATA]`.
