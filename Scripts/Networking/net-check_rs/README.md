# Net-Check: VPN & Host Security Verifier

A Rust utility designed to verify VPN connection status, detect potential network leaks, perform basic host system audits, and run operational security (OpSec) checks.

## Purpose

This tool helps ensure that your network traffic is correctly routed through your VPN and that your system configuration meets certain security baselines, reducing the risk of accidental IP leaks or exposure. It is particularly useful for users who require high confidence in their VPN setup.

## Features

*   **VPN Interface Check:**
    *   Verifies the existence and status (up, running) of the specified VPN network interface.
    *   (Optional) Checks if the VPN interface IP address falls within an expected subnet (CIDR).
*   **DNS Check:**
    *   Reads `/etc/resolv.conf` to find currently configured DNS servers.
    *   (Optional) Compares found DNS servers against a list of expected DNS server IPs.
*   **Network Leak Detection (Packet Capture):**
    *   Monitors specified physical network interfaces (e.g., `eth0`, `wlan0`) for outbound IP traffic.
    *   Uses BPF filters to ignore legitimate traffic (loopback, local subnets, configured VPN server IPs, allowed destination IPs/ports).
    *   Flags any other outbound IP traffic on physical interfaces as a potential leak.
    *   Requires sufficient privileges (e.g., run as root) to perform packet capture.
*   **Host Audit:**
    *   Checks for unexpected listening TCP/UDP ports (reads `/proc/net/tcp`, `/proc/net/udp`, etc., ignores loopback by default).
    *   Checks running processes (reads `/proc`, logs basic info, checks against disallowed names).
    *   Checks currently logged-in users (reads utmp/utmpx, checks against allowed users/hosts).
    *   Checks modification times of specified files.
    *   Checks loaded kernel modules against required/disallowed lists.
    *   Checks running systemd services and active timers against disallowed lists.
    *   (Optional) Performs a basic firewall check by attempting to list `nft` or `iptables` rules.
*   **OpSec Checks:**
    *   Audits `/etc/hosts` for suspicious entries (e.g., localhost pointing elsewhere, non-localhost pointing to localhost, disallowed entries).
    *   Checks environment variables for potentially sensitive names (e.g., `API_KEY`) or disallowed variables.
*   **External IP Check (Optional & High-Risk):**
    *   (Optional) Connects to a specified external URL to check the system's apparent public IP address.
    *   (Optional) Compares the found external IP against a list of expected IPs.
    *   **WARNING:** Enabling this check can expose your real IP address if the VPN connection fails or during the check itself. Use with extreme caution.

## Configuration (`config.toml`)

The program requires a configuration file (default: `config.toml`) specified via the `-c` or `--config` command-line argument.

Key configuration options include:

*   `vpn_interface_name`: (Required) Name of the VPN interface (e.g., "tun0").
*   `expected_vpn_ip_network`: (Optional) Expected VPN IP subnet (e.g., "10.8.0.0/24").
*   `expected_dns_servers`: (Optional) List of allowed DNS server IPs.
*   `physical_interface_names`: (Optional) List of physical interfaces to monitor for leaks.
*   `allowed_listening_tcp_ports`, `allowed_listening_udp_ports`: (Optional) Allowed listening ports.
*   `vpn_server_ips`: (Optional) IP(s) of the VPN server endpoint(s) for filter exclusion.
*   `local_subnets`: (Optional) Local subnets to ignore for leak detection.
*   `check_firewall_rules`: (Optional) Boolean to enable basic firewall listing check.
*   `check_external_ip`: (Optional, RISKY) Boolean to enable external IP check.
*   `external_ip_check_url`: (Optional) URL for external IP check service.
*   `expected_external_ips`: (Optional) Allowed external IPs if check is enabled.
*   `watched_files_for_modification`: (Optional) Files to check for recent modification.
*   `allowed_login_users`, `allowed_login_hosts`: (Optional) Allowed users/hosts for active logins.
*   `required_kernel_modules`, `disallowed_kernel_modules`, `enforce_required_modules_only`: (Optional) Kernel module rules.
*   `disallowed_process_names`: (Optional) Process names to flag if found running.
*   `disallowed_systemd_services`, `disallowed_systemd_timers`: (Optional) Disallowed systemd units.
*   `disallowed_hosts_entries`: (Optional) Hostnames disallowed from being mapped to non-localhost IPs in `/etc/hosts`.
*   `disallowed_env_vars`: (Optional) Disallowed environment variables.
*   `allowed_leak_destination_ips`, `allowed_leak_destination_ports`: (Optional) Destinations to ignore during leak detection.

*(Refer to `src/config.rs` for the full structure and defaults)*

## Prerequisites

*   **Rust:** Requires a stable Rust toolchain. Install via [rustup](https://rustup.rs/).
*   **libpcap-dev:** Needed for the `pcap` crate (packet capture). Install using your system's package manager (e.g., `sudo apt install libpcap-dev` on Debian/Ubuntu).
*   **libssl-dev:** Needed for `reqwest` (HTTPS external IP check). Install using your system's package manager (e.g., `sudo apt install libssl-dev` on Debian/Ubuntu).
*   **(Potentially) Root Privileges:** Running the tool often requires root privileges (`sudo`) for:
    *   Packet capture (`pcap`).
    *   Reading certain `/proc` entries (process info, network state).
    *   Running firewall commands (`iptables`, `nft`).

## Building

Use the provided build script:

```bash
./build.sh
```

This script simply runs `cargo build`. The executable will be located at `target/debug/vpn_verifier`.

## Usage

```bash
# Must typically be run with sudo for full functionality
sudo ./target/debug/vpn_verifier -c /path/to/your/config.toml
```

**Command-line Arguments:**

*   `-c`, `--config <FILE>`: Specifies the path to the configuration TOML file (Required).
*   `-l`, `--log-level <LEVEL>`: Sets the logging level (e.g., `trace`, `debug`, `info`, `warn`, `error`. Default: `info`).
*   `-i`, `--interval <SECONDS>`: Runs checks repeatedly at the specified interval (in seconds). If not provided, runs checks once and exits.

## Security & OpSec Considerations

*   **Root Privileges:** Running as root grants extensive permissions. Ensure the code and its dependencies are trusted. Consider Linux capabilities (`setcap`) as an alternative where possible, although full functionality might still require root.
*   **External IP Check:** Enabling `check_external_ip` is inherently risky and can deanonymize you if the VPN fails. Understand the risks before enabling.
*   **Configuration File:** Protect your `config.toml` file, as it contains potentially sensitive network information. Use restrictive file permissions.
*   **Command Execution:** The firewall and systemd checks rely on external commands (`nft`, `iptables`, `systemctl`). Ensure these binaries are legitimate and haven't been replaced.
*   **Logging:** Sensitive information discovered during audits (e.g., environment variable *values*) is generally avoided in logs, but review debug logs (`trace`, `debug`) carefully if enabled, as they contain more detail.
*   **Dependencies:** Regularly audit dependencies for vulnerabilities using tools like `cargo-audit`.

## License

*(Assume MIT License for now - add your specific license here)*

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

*(Placeholder - Add contribution guidelines if desired)*

Contributions are welcome! Please feel free to submit issues or pull requests. 