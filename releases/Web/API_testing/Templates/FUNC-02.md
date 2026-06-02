## FUNC-02 — Permissive Allow Header via OPTIONS

## OWASP
[API5 - Broken Function Level Authorization]

## Finding Title
OPTIONS Response Advertises Overly Permissive Allowed Methods

## Finding Description
The `OPTIONS` response includes an `Allow` header advertising HTTP methods beyond those required for normal API operation. Advertising write methods that are not intended for public use can guide attackers toward unexplored attack surface.

## Risk Level
Informational

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Low direct impact. The `Allow` header itself does not grant access, but advertising methods like `PUT`, `DELETE`, or `PATCH` on read-only endpoints provides attackers with a roadmap of potentially unguarded functionality to probe further.

## Steps to Reproduce Finding
```bash
curl -s -i -X OPTIONS -H "apikey: $API_KEY" "$BASE_URL/facilities" \
  | grep -i "^allow:"
```
Observed: `Allow: [VALUES]` — review whether all advertised methods are intentional and appropriately access-controlled.
