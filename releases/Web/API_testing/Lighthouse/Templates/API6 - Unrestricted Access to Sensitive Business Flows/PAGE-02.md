## PAGE-02 — Malformed Pagination Input Causes Unhandled Server Error

## OWASP
[API6 - Unrestricted Access to Sensitive Business Flows]

## Finding Title
Invalid Pagination Parameters Return 5xx Server Error

## Finding Description
Submitting malformed `page` or `per_page` values (e.g. `page=abc`, `per_page=-5`, or an integer overflow value) caused the server to return a `5xx` error response. The API is not validating and sanitising pagination inputs before use, resulting in unhandled exceptions propagating to the client.

## Risk Level
Medium

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Unhandled errors can reveal stack traces, framework version information, and internal path details useful for further exploitation. Repeated triggering of unhandled errors can also destabilise the application process, contributing to availability degradation.

## Steps to Reproduce Finding
```bash
for p in "page=0" "page=-1" "page=abc" "per_page=-5" \
         "per_page=abc" "page=99999999999999999999"; do
  printf "%-30s " "$p"
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "apikey: $API_KEY" "$BASE_URL/facilities?$p"
done
```
Observed: `5xx` for `[PARAM]=[VALUE]` — expected `400` or `422`.
