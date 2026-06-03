## RATE-02 — Rate-Limit Headers Absent from Responses

## OWASP
[API4 - Unrestricted Resource Consumption]

## Finding Title
Rate-Limit Quota Headers Not Returned

## Finding Description
API responses do not include standard rate-limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`). Without these headers, API consumers cannot implement client-side throttling, making accidental rate-limit violations and resultant `429` errors difficult to handle gracefully.

## Risk Level
Low

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Clients cannot proactively throttle their requests or back off intelligently. This increases the likelihood of clients hammering the API until a hard block occurs, degrading the experience for that consumer and potentially affecting shared infrastructure capacity.

## Steps to Reproduce Finding
```bash
curl -s -D - -o /dev/null -H "apikey: $API_KEY" "$BASE_URL/facilities?per_page=1" \
  | grep -iE "x-ratelimit|ratelimit-|retry-after"
```
Observed: no rate-limit headers present in the response.
