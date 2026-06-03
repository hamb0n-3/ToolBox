## TRAV-01 — Path Traversal

## OWASP
[API1 - Broken Object Level Authorization]

## Finding Title
Path Traversal via Encoded Sequences in Facility ID

## Finding Description
Submitting URL-encoded path traversal sequences (e.g. `..%2f..%2f..%2fetc%2fpasswd`) in the facility ID path segment caused the server to respond with `200` and return the contents of a file outside the intended directory. The server is not normalising or validating the path component before use in file system operations.

## Risk Level
Critical

## Tools Used
- `curl` (with `--path-as-is` to prevent client-side normalization)
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
An attacker can read arbitrary files accessible to the application process, including configuration files, private keys, environment variables, and operating system files such as `/etc/passwd`. On write-capable paths this can escalate to remote code execution via log poisoning or configuration overwrite.

## Steps to Reproduce Finding
```bash
for p in "..%2f..%2f..%2fetc%2fpasswd" \
         "%2e%2e%2f%2e%2e%2fetc%2fpasswd" \
         "..%5c..%5cwindows%5cwin.ini"; do
  curl -s --path-as-is -H "apikey: $API_KEY" "$BASE_URL/facilities/$p" \
    | grep -iE "root:x:|/bin/bash|\[extensions\]" && echo "!! Traversal: $p"
done
```
Observed: `[FILE CONTENTS]` returned for traversal payload `[PAYLOAD]`. Confirm the `Sent URL` in the test report to verify the payload was not normalised by the client.

## Remediation Steps
- Decode and canonicalise the path component server-side before any validation or use. Use your framework's built-in path resolution functions rather than string manipulation.
- Validate the resolved path against an explicit allow-list of permitted base directories. Reject any request where the resolved path escapes the intended directory.
- Accept only known-good identifier patterns (e.g. `^[a-zA-Z0-9_-]+$`) at the routing layer and return `400` for any value that does not match.
- Configure the web server or reverse proxy to decode and normalise percent-encoded sequences before they reach the application, and to block traversal sequences at the WAF/ingress layer as a defence-in-depth measure.
