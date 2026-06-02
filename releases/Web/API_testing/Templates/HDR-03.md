## HDR-03 — Incorrect or Missing Content-Type Header

## OWASP
[API8 - Security Misconfiguration]

## Finding Title
API Response Served Without Correct JSON Content-Type

## Finding Description
The API response does not include a `Content-Type` header specifying `application/json` (or `application/vnd.api+json`). Without a declared content type, browsers and parsers may attempt to infer the type, which can lead to incorrect handling or enable MIME-sniffing based attacks when combined with absent `X-Content-Type-Options` headers.

## Risk Level
Low

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Incorrect content type declarations can cause client libraries to misparse responses, and in combination with absent `nosniff` headers can allow browsers to render JSON content as HTML, potentially enabling script injection in certain edge cases.

## Steps to Reproduce Finding
```bash
curl -s -D - -o /dev/null -H "apikey: $API_KEY" "$BASE_URL/facilities?per_page=1" \
  | grep -i "^content-type:"
```
Observed: `Content-Type: [OBSERVED VALUE]` — expected `application/json` or `application/vnd.api+json`.
