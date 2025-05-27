Opsec Note: Relying on external commands like systemctl can be fragile (output format changes) and potentially logged by system auditing tools. Native libraries or direct D-Bus interaction would be more robust but also significantly more complex.

 Make this work --> Self-Correction: The DNS check currently only parses /etc/resolv.conf. A more robust check would involve actively querying the configured DNS servers (and potentially comparing results against a known-good external resolver) to ensure they are responsive and not hijacked. However, adding a DNS client library (trust-dns-resolver is mentioned in Cargo.toml comments) is a larger step. For now, the existing /etc/resolv.conf check combined with the external IP check provides a reasonable level of verification. We can enhance DNS querying later if needed.
Phase 3 Complete: network_checks.rs now includes the optional external IP check.

 Make this work --< The current logic uses a fairly comprehensive BPF filter generated in generate_bpf_filter to exclude:
Loopback, link-local, multicast, broadcast traffic.
Traffic destined for configured local subnets (RFC1918 etc. by default).
Traffic destined for configured VPN server IPs.
It aims to only capture traffic sourced from local IPs (though this relies on finding local IPs correctly).
