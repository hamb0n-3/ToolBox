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

## Remediation Steps
- Configure the server to support only TLS 1.2 and TLS 1.3. Explicitly disable TLS 1.0, TLS 1.1, and all SSL versions.
  - **nginx**: `ssl_protocols TLSv1.2 TLSv1.3;`
  - **Apache**: `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`
- Also restrict the cipher suite to approved algorithms (e.g. ECDHE-based suites) and disable RC4, DES, and 3DES.
- Validate with `openssl s_client -tls1` and `openssl s_client -tls1_1` — both should fail to handshake after the fix.
