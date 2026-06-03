## FUNC-04 — Arbitrary HTTP Method Not Rejected

## OWASP
[API5 - Broken Function Level Authorization]

## Finding Title
Unrecognised HTTP Method Returns Unexpected Response

## Finding Description
A request using a fabricated, non-standard HTTP method (`FOOBAR`) did not return an appropriate rejection code (`400`, `405`, or `501`). This may indicate the HTTP parsing layer is not enforcing a strict allow-list of expected methods, which can expose unexpected behaviour in downstream middleware or proxies.

## Risk Level
Low

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Permissive method handling can confuse web application firewalls, reverse proxies, and load balancers that expect only standard verbs, potentially routing non-standard requests to unintended backend handlers. Some frameworks expose debugging or introspection functionality via non-standard methods.

## Steps to Reproduce Finding
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -X FOOBAR -H "apikey: $API_KEY" "$BASE_URL/facilities"
```
Observed: `[STATUS]` — expected `400`, `405`, or `501`.

## Remediation Steps
- Configure the HTTP server or API gateway with an explicit method allow-list (e.g. `GET`, `POST`, `OPTIONS`, `HEAD`). Reject any request using a method not on the list with `405 Method Not Allowed`.
- Avoid permissive fallback routing that passes unrecognised methods to the application layer.
- Add a test that submits a fabricated method (e.g. `FOOBAR`) and asserts a `405` response.
