## AUTH-04 — API Key Accepted via URL Query Parameter

## OWASP
[API2 - Broken Authentication]

## Finding Title
API Key Transmitted and Accepted in URL Query String

## Finding Description
When the API key is supplied as a URL query parameter (`?apikey=...`) rather than as an `apikey` request header, the server still authenticates the request and returns a `200` response. Credentials placed in URLs are routinely captured in web server access logs, browser history, proxy logs, and `Referer` headers, significantly broadening the credential exposure surface.

## Risk Level
Medium

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
API keys transmitted in URLs can be harvested from access logs, referrer logs, browser history, or network intermediaries without requiring any active attack. Any system that stores or forwards URLs (CDNs, WAFs, SIEM tools) becomes an inadvertent credential store.

## Steps to Reproduce Finding
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "$BASE_URL/facilities?apikey=$API_KEY&per_page=1"
```
Observed: `200` — a key supplied in the URL query string should not be honored.

## Remediation Steps
- Accept the API key only via the documented request header. Explicitly reject requests where the key is found in query parameters, request body, or any other location.
- Return `401` if the credential is absent from the expected header, even if the same value appears elsewhere in the request.
- If backward compatibility temporarily requires query-parameter support, log a deprecation warning and set a firm sunset date.
