## RATE-01 — Missing or Ineffective Rate Limiting

## OWASP
[API4 - Unrestricted Resource Consumption]

## Finding Title
No Rate Limiting Enforced on API Endpoint

## Finding Description
A burst of `60` concurrent requests to the `/facilities` endpoint produced no `429 Too Many Requests` responses. The API does not appear to enforce request rate limits, allowing any single client to issue an unrestricted volume of requests.

## Risk Level
High

## Tools Used
- `curl`, `xargs`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Without rate limiting, the API is vulnerable to denial-of-service through resource exhaustion, brute-force enumeration of facility identifiers, and automated scraping of the full dataset. High-volume abuse can degrade availability for all legitimate consumers and increase infrastructure costs.

## Steps to Reproduce Finding
```bash
seq 60 | xargs -P10 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  -H "apikey: $API_KEY" "$BASE_URL/facilities?per_page=1" | sort | uniq -c
```
Observed: no `429` responses in `60` rapid concurrent requests.

## Remediation Steps
- Implement rate limiting at the API gateway or reverse proxy layer (e.g. nginx `limit_req`, Kong rate-limiting plugin, AWS API Gateway usage plans). Apply limits per API key and per IP.
- Return `429 Too Many Requests` with a `Retry-After` header when the limit is exceeded.
- Set limits appropriate to legitimate use cases (e.g. 60 requests/minute per key) and test that the limit is enforced before deployment.
- Consider tiered limits: a burst allowance for short spikes and a sustained rate limit to prevent prolonged abuse.
