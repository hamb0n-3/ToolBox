## TLS-02 — TLS Certificate Expired or Nearing Expiry

## OWASP
[API8 - Security Misconfiguration]

## Finding Title
TLS Certificate Expired or Expiring Within 14 Days

## Finding Description
The TLS certificate presented by the server has expired or will expire within 14 days. Expired certificates cause client trust errors and, if left unaddressed, result in complete API unavailability for compliant clients. Certificates expiring imminently represent an operational risk.

## Risk Level
High

## Tools Used
- `openssl s_client`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Clients enforcing certificate validation will refuse the connection entirely. This could result in denial of service for all API consumers. An expired certificate also suggests the certificate lifecycle management process is not functioning, which may indicate broader PKI hygiene issues.

## Steps to Reproduce Finding
```bash
echo | openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null \
  | openssl x509 -noout -dates
```
Observed: `notAfter=[DATE]` — `[N]` days remaining (threshold: 14).
