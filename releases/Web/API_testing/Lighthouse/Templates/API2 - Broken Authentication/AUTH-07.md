## AUTH-07 — SQL Metacharacters in API Key Not Rejected

## OWASP
[API2 - Broken Authentication]

## Finding Title
SQL Injection Characters in API Key Header Not Sanitized

## Finding Description
Submitting SQL metacharacters (`' OR '1'='1`) as the API key value did not result in a validation error or `400` response. If the key value is used in a database query without parameterization, this input could manipulate the authentication query and bypass credential validation.

## Risk Level
Medium

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
If authentication relies on a SQL query that interpolates the key value, injection could allow an attacker to bypass authentication entirely or extract the contents of the credential store. Even if the current implementation is not vulnerable, the lack of input rejection indicates insufficient input validation.

## Steps to Reproduce Finding
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "apikey: ' OR '1'='1" "$BASE_URL/facilities?per_page=1"
```
Observed: `[HTTP STATUS]` — a `400` or `401` with an input validation error is expected. Any `200` response warrants deeper investigation.

## Remediation Steps
- Validate that the API key value matches the expected format (e.g. alphanumeric, fixed length) before using it in any lookup. Return `400` for keys that fail structural validation.
- Use parameterised queries or ORM methods for all credential lookups; never interpolate the key value into a SQL string.
- Reject keys containing SQL metacharacters (`'`, `"`, `;`, `--`) with a `400` or `401` response at the input-validation layer.
