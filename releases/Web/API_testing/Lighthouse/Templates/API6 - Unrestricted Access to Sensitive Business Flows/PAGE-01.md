## PAGE-01 — Unrestricted Page Size Allows Mass Data Retrieval

## OWASP
[API6 - Unrestricted Access to Sensitive Business Flows]

## Finding Title
Oversized Pagination Parameter Not Rejected or Capped

## Finding Description
Requests with `per_page` values of `10000` or `99999` were not rejected and returned a `200` response with an uncapped dataset. The API does not enforce a maximum page size, allowing a single request to retrieve the entire dataset or an arbitrarily large number of records.

## Risk Level
Medium

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
An attacker or abusive client can scrape the entire dataset with a minimal number of requests, bypassing the protective effect of pagination. Large responses also increase server-side compute and I/O cost, contributing to resource exhaustion under load.

## Steps to Reproduce Finding
```bash
for n in 1000 10000 99999; do
  printf "per_page=%-6s " "$n"
  curl -s -H "apikey: $API_KEY" "$BASE_URL/facilities?per_page=$n&page=1" \
    -o /dev/null -w "%{http_code}\n"
done
```
Observed: `200` with `[COUNT]` records returned for `per_page=[VALUE]` — server should cap or reject this value.

## Remediation Steps
- Enforce a server-side maximum page size (e.g. 100 records). Silently cap values above the maximum rather than returning an error, or return `400` with a clear message if you prefer strict enforcement.
- Never pass the raw `per_page` value directly to a database `LIMIT` clause; always apply `min(requested, MAX_PAGE_SIZE)` before query execution.
- Document the maximum page size in the API specification so consumers can rely on it.
