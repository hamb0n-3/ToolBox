## INV-01 — Deprecated API Version Still Active

## OWASP
[API9 - Improper Inventory Management]

## Finding Title
Deprecated API Version Returns Live Data

## Finding Description
An earlier API version path (e.g. `/services/va_facilities/v0/facilities`) returned an HTTP `200` response with live data. Deprecated API versions are typically less well-maintained, may lack security patches applied to the current version, and are less likely to be included in security monitoring.

## Risk Level
Medium

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Older API versions may contain vulnerabilities that have been patched in the current version, may expose deprecated endpoints with weaker access controls, and may bypass security tooling configured to monitor only the documented current version path. Attackers deliberately target older versions for exactly this reason.

## Steps to Reproduce Finding
```bash
for v in v0 v2 v3; do
  printf "%-3s " "$v"
  curl -s -o /dev/null -w "%{http_code}\n" -H "apikey: $API_KEY" \
    "$HOST_ROOT/services/va_facilities/$v/facilities?per_page=1"
done
```
Observed: `200` for version `[VERSION]` — this path should return `404`.
