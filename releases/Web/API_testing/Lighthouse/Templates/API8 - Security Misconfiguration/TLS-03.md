## TLS-03 — Weak TLS Protocol Version Accepted

## OWASP
[API8 - Security Misconfiguration]

## Finding Title
Legacy TLS Protocol Version Accepted (TLS 1.0 / TLS 1.1)

## Finding Description
The server successfully negotiated a connection using TLS 1.0 or TLS 1.1. Both versions are deprecated by RFC 8996 and contain known weaknesses including BEAST, POODLE, and insufficient cipher suite support. Modern security standards (PCI DSS 4.0, NIST SP 800-52 Rev. 2) require that these versions be disabled.

## Risk Level
High

## Tools Used
- `openssl s_client`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Clients can be forced to downgrade their connection to a weak protocol, enabling decryption of traffic and potential man-in-the-middle attacks. This affects the confidentiality of API keys and all response data.

## Steps to Reproduce Finding
```bash
# TLS 1.0
echo | openssl s_client -connect "$HOST:443" -tls1 2>&1 | grep -i "protocol"
# TLS 1.1
echo | openssl s_client -connect "$HOST:443" -tls1_1 2>&1 | grep -i "protocol"
```
Observed: handshake succeeded and negotiated `[VERSION]` — expected connection refusal.

## Remediation Steps
- Disable TLS 1.0 and TLS 1.1 in the server TLS configuration (see TLS-01 for specific directives).
- Apply the change at every TLS termination point — origin server, load balancer, CDN edge — as each terminates its own TLS session.
- Confirm with `openssl s_client -connect $HOST:443 -tls1` and `-tls1_1`; a successful handshake after the change indicates the fix was not applied at all layers.
