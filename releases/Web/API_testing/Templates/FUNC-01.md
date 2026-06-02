## FUNC-01 — Write Methods Accepted on Read-Only Endpoint

## OWASP
[API5 - Broken Function Level Authorization]

## Finding Title
Mutating HTTP Methods Not Rejected on Read-Only Endpoint

## Finding Description
One or more mutating HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`) sent to a read-only endpoint returned an unexpected success response rather than `405 Method Not Allowed` or a comparable rejection code. This indicates function-level access controls are not correctly enforced.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
An attacker may be able to create, modify, or delete facility records that should be read-only through the public API. Even partial write access can corrupt reference data relied upon by VA systems and consumers.

## Steps to Reproduce Finding
```bash
FID=[VALID_FACILITY_ID]
for m in POST PUT DELETE PATCH; do
  printf "%-7s " "$m"
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X "$m" -H "apikey: $API_KEY" "$BASE_URL/facilities/$FID"
done
```
Observed: `[METHOD]` returned `[STATUS]` — expected `401`, `403`, `404`, or `405`.
