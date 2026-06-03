## BOLA-01 — Broken Object Level Authorization

## OWASP
[API1 - Broken Object Level Authorization]

## Finding Title
Invalid or Malformed Object Identifiers Return Data

## Finding Description
One or more requests to `/facilities/{id}` using invalid, malformed, or potentially malicious identifier values (e.g. `null`, `0`, `-1`, `*`, URL-encoded null byte) returned an HTTP `200` response with data. The API is not validating that the requested identifier is a legitimate, well-formed value before processing the request.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Depending on what data is returned, an attacker may be able to access facility records they should not have visibility into, enumerate internal identifiers, or exploit special-character handling to trigger unexpected server behavior. Returning `200` for identifiers like `null` or `*` suggests the ID is not being properly scoped or validated server-side.

## Steps to Reproduce Finding
```bash
for id in does_not_exist_999 0 -1 null undefined "%20" "vha_%00" "*"; do
  printf "%-22s " "$id"
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "apikey: $API_KEY" "$BASE_URL/facilities/$id"
done
```
Observed: `200` for `[ID VALUE]` — expected `400` or `404`.

## Remediation Steps
- Validate that all path-segment identifiers conform to the expected format (e.g. alphanumeric facility ID pattern) before passing them to the data layer. Reject non-conforming values with `400 Bad Request`.
- Perform an explicit existence check: if no record matches the validated identifier, return `404 Not Found` rather than silently returning empty data or a `200`.
- Apply object-level authorization checks to confirm the requesting caller is permitted to access the resolved record, not just that the record exists.
- Reject or sanitise null bytes, wildcard characters, and other special values at the input-validation layer before any database or filesystem interaction occurs.
