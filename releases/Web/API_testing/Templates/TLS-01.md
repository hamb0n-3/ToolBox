## TLS-01 — Weak or Invalid TLS Version Negotiated

## OWASP
[API8 - Security Misconfiguration]

## Finding Title
Weak TLS Version Negotiated

## Finding Description
The server negotiated a TLS version below the acceptable minimum of TLS 1.2. Older protocol versions (TLS 1.0, SSL 3.0) contain known cryptographic weaknesses that can allow an attacker to decrypt traffic or perform protocol downgrade attacks.

## Risk Level
High

## Tools Used
- `openssl s_client`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
An attacker with a network-level position (e.g. on the same network segment or a compromised intermediate router) could decrypt API traffic, including API keys and response data. This may expose authentication credentials and the contents of all API calls.

## Steps to Reproduce Finding
```bash
echo | openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null \
  | grep -i "protocol"
```
Observed: `[NEGOTIATED VERSION]` — expected `TLSv1.2` or `TLSv1.3`.
