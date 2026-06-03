## FUNC-03 — HTTP TRACE Method Enabled

## OWASP
[API5 - Broken Function Level Authorization]

## Finding Title
HTTP TRACE Method Enabled (Cross-Site Tracing Risk)

## Finding Description
The server responded to an HTTP `TRACE` request without returning `405 Method Not Allowed` or `501 Not Implemented`. The `TRACE` method causes the server to echo back the full request, including headers. In certain browser and proxy configurations this can expose authentication headers to malicious scripts via the Cross-Site Tracing (XST) technique.

## Risk Level
Low

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
In conjunction with a cross-site scripting vulnerability or a permissive browser, `TRACE` can be used to steal session tokens or API keys by reflecting them back through a victim's browser. The method has no legitimate operational use on a production REST API.

## Steps to Reproduce Finding
```bash
curl -s -D - -o /dev/null -X TRACE \
  -H "apikey: $API_KEY" "$BASE_URL/facilities"
```
Observed: `[STATUS]` — expected `405`, `501`, or `403`. A `200` with the request echoed in the body confirms the finding.
