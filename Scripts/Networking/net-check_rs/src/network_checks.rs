use crate::Config; // Use Config from the main module (since config.rs is deleted)
use log::{info, warn, debug, error}; // Logging
use pnet::datalink; // Network interface listing
use std::fs; // Filesystem access for resolv.conf
use std::collections::HashSet; // For comparing DNS servers
use regex::Regex; // For parsing resolv.conf
use std::net::IpAddr;
use std::net::IpAddr::V4; // Import specific variants if needed for clarity
use std::net::IpAddr::V6;
use ipnetwork::IpNetwork; // For IpNetwork type used in results
use reqwest::blocking::Client; // Added for external IP check
use serde::Deserialize; // Added for parsing JSON response from IP check service

/// Represents the outcome of matching an IP against an expected network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpNetworkMatchStatus {
    NotChecked,         // No expected network was specified.
    Match(IpNetwork),   // Found an IP matching the expected network.
    Mismatch(IpNetwork),// Found IPs, but none matched the expected network.
    NoIPs(IpNetwork),   // Expected a network, but the interface had no IPs.
    InterfaceHasNoIPs,  // No expected network, and interface has no IPs (warning).
}

/// Represents the outcome of the optional external IP check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalIpStatus {
    Disabled,                      // Check was not enabled.
    CheckFailed(String),           // The check itself failed (e.g., network error).
    CheckedOk(IpAddr),             // Check successful, no expected IPs configured.
    ExpectedMatch(IpAddr),         // Reported IP matches one of the expected IPs.
    ExpectedMismatch(IpAddr, Vec<IpAddr>), // Reported IP does not match expected IPs.
}

/// Holds the detailed results of the network interface verification.
#[derive(Debug, Clone)]
pub struct InterfaceCheckResult {
    pub interface_name: String,
    pub interface_found: bool,
    pub is_up: Option<bool>, // None if not found
    pub is_running: Option<bool>, // None if not found
    pub is_loopback: Option<bool>, // None if not found
    pub is_point_to_point: Option<bool>, // None if not found
    pub ip_addresses: Vec<IpNetwork>, // IPs found on the interface
    pub mac_address: Option<String>, // MAC address if available
    pub ip_network_match_status: IpNetworkMatchStatus,
    pub external_ip_status: ExternalIpStatus,
    /// Collected warnings or errors found during the check.
    pub findings: Vec<String>,
}

/// Represents the outcome of matching DNS servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsMatchStatus {
    NotChecked,     // No expected DNS servers were specified.
    ReadError(String), // Failed to read or parse resolv.conf
    Match,          // Found servers exactly match expected servers.
    Mismatch,       // Found servers do not match expected servers.
    NoServersFound, // resolv.conf parsed, but no nameserver lines found.
}

/// Holds the detailed results of the DNS verification.
#[derive(Debug, Clone)]
pub struct DnsCheckResult {
    pub servers_expected: Vec<IpAddr>,
    pub servers_found: Vec<IpAddr>,
    pub match_status: DnsMatchStatus,
    /// Collected warnings or errors found during the check.
    pub findings: Vec<String>,
}

/// Helper struct to parse simple JSON IP response (e.g., {"ip": "1.2.3.4"})
#[derive(Deserialize, Debug)]
struct IpCheckResponse {
    ip: String,
}

/// Verifies network interfaces, checking the VPN interface status and IP configuration.
/// Optionally performs an external IP check.
/// Collects findings instead of returning early errors.
///
/// # Arguments
/// * `config` - The application configuration (hardcoded defaults).
/// # Returns
/// An `InterfaceCheckResult` struct containing detailed results and findings.
pub fn verify_network_interfaces(config: &Config) -> InterfaceCheckResult {
    info!("Verifying network interfaces...");
    debug!("Looking for VPN interface: {}", config.vpn_interface_name);

    let mut result = InterfaceCheckResult {
        interface_name: config.vpn_interface_name.clone(),
        interface_found: false,
        is_up: None,
        is_running: None,
        is_loopback: None,
        is_point_to_point: None,
        ip_addresses: Vec::new(),
        mac_address: None,
        ip_network_match_status: IpNetworkMatchStatus::NotChecked, // Default
        external_ip_status: ExternalIpStatus::Disabled, // Default
        findings: Vec::new(),
    };

    let interfaces = datalink::interfaces();
    let vpn_iface = interfaces.iter().find(|iface| iface.name == config.vpn_interface_name);

    match vpn_iface {
        Some(iface) => {
            result.interface_found = true;
            result.is_up = Some(iface.is_up());
            result.is_running = Some(iface.is_running());
            result.is_loopback = Some(iface.is_loopback());
            result.is_point_to_point = Some(iface.is_point_to_point());
            result.ip_addresses = iface.ips.clone();
            result.mac_address = iface.mac.map(|mac| mac.to_string());

            info!("Found VPN interface: {}", iface.name);
            debug!("Interface details: {:?}", iface);

            if !iface.is_up() {
                result.findings.push(format!(
                    "VPN interface {} is down.", config.vpn_interface_name
                ));
            }
            if !iface.is_running() {
                 // This might be acceptable briefly, but flag it.
                result.findings.push(format!(
                    "Warning: VPN interface {} is up but not running (may lack carrier or be misconfigured).",
                    config.vpn_interface_name
                ));
            }
            if iface.is_loopback() {
                result.findings.push(format!(
                    "Warning: VPN interface {} is a loopback interface.", config.vpn_interface_name
                ));
            }
            if iface.is_point_to_point() {
                info!("VPN interface {} is a point-to-point interface.", config.vpn_interface_name);
            }

            if iface.is_up() { // Only proceed with IP checks if interface is up
                info!("VPN interface {} is up.", config.vpn_interface_name);

                // Check IP addresses associated with the interface against the expected network.
                match &config.expected_vpn_ip_network {
                    Some(expected_network) => {
                        let mut found_matching_ip = false;
                        if iface.ips.is_empty() {
                            result.findings.push(format!(
                                "VPN interface {} has no IP addresses, but expected network {} was configured.",
                                config.vpn_interface_name,
                                expected_network
                            ));
                            result.ip_network_match_status = IpNetworkMatchStatus::NoIPs(*expected_network);
                        } else {
                            for ip_net in &iface.ips {
                                if expected_network.contains(ip_net.ip()) {
                                    info!("Found expected IP {} on VPN interface {}.", ip_net, config.vpn_interface_name);
                                    found_matching_ip = true;
                                    break;
                                }
                            }
                            if found_matching_ip {
                                result.ip_network_match_status = IpNetworkMatchStatus::Match(*expected_network);
                            } else {
                                result.findings.push(format!(
                                    "No IP address on VPN interface {} belongs to the expected network {}. Found IPs: {:?}",
                                    config.vpn_interface_name,
                                    expected_network,
                                    iface.ips
                                ));
                                result.ip_network_match_status = IpNetworkMatchStatus::Mismatch(*expected_network);
                            }
                        }
                    }
                    None => {
                        // No expected network configured, just check if *any* IP exists.
                         if iface.ips.is_empty() {
                            result.findings.push(format!(
                                "Warning: VPN interface {} has no assigned IP addresses. (No expected network was configured).",
                                config.vpn_interface_name
                            ));
                             result.ip_network_match_status = IpNetworkMatchStatus::InterfaceHasNoIPs;
                        } else {
                            info!("IP addresses found for {}: {:?}. (No specific network expected).", config.vpn_interface_name, iface.ips);
                            // Status remains NotChecked as no expectation was set.
                        }
                    }
                }

                // Perform external IP check if enabled
                if config.check_external_ip.unwrap_or(false) {
                    info!("--- Performing External IP Check ---");
                    warn!("OPSEC WARNING: External IP check enabled. This sends traffic outside the VPN potentially, revealing real IP if VPN fails.");
                    match perform_external_ip_check(config) {
                        Ok(reported_ip) => {
                            info!("External IP check service reported IP: {}", reported_ip);
                            if let Some(expected_ips) = &config.expected_external_ips {
                                if expected_ips.is_empty() {
                                    result.findings.push("Warning: External IP check enabled, but 'expected_external_ips' list is empty. Cannot verify.".to_string());
                                    result.external_ip_status = ExternalIpStatus::CheckedOk(reported_ip); // OK, but can't verify
                                } else if expected_ips.contains(&reported_ip) {
                                    info!("Reported external IP matches one of the expected IPs.");
                                    result.external_ip_status = ExternalIpStatus::ExpectedMatch(reported_ip);
                                } else {
                                    let finding = format!(
                                        "Reported external IP {} does NOT match any expected IPs: {:?}",
                                        reported_ip, expected_ips
                                    );
                                    result.findings.push(finding);
                                    result.external_ip_status = ExternalIpStatus::ExpectedMismatch(reported_ip, expected_ips.clone());
                                }
                            } else {
                                // Check ran successfully, but no IPs were expected
                                result.external_ip_status = ExternalIpStatus::CheckedOk(reported_ip);
                            }
                        }
                        Err(e) => {
                             let finding = format!("External IP check failed: {}", e);
                             result.findings.push(finding.clone());
                             result.external_ip_status = ExternalIpStatus::CheckFailed(e);
                        }
                    }
                } else {
                    info!("--- Skipping External IP Check (disabled) ---");
                    result.external_ip_status = ExternalIpStatus::Disabled;
                }
            } // End if iface.is_up()
        }
        None => {
            result.findings.push(format!(
                "Configured VPN interface {} not found.", config.vpn_interface_name
            ));
            result.interface_found = false;
        }
    }

    // Log collected findings at the end
    for finding in &result.findings {
        // Use error! for definite problems, warn! for potential issues
        if finding.starts_with("Warning:") {
             warn!("{}", finding);
        } else {
             error!("{}", finding); // Treat other findings as errors for now
        }
    }

    result
}

/// Performs the external IP check using the configured URL.
/// (Function remains largely the same, just used by the refactored verify_network_interfaces)
///
/// # Arguments
/// * `config` - The application configuration.
/// # Returns
/// A `Result` containing the reported `IpAddr` or an error string.
fn perform_external_ip_check(config: &Config) -> Result<IpAddr, String> {
    let url = config.external_ip_check_url.as_deref().unwrap_or("https://ifconfig.me/ip");
    debug!("Querying external IP check service: {}", url);

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10)) // Add a timeout
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let response = client.get(url)
        .send()
        .map_err(|e| format!("HTTP request to {} failed: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!("External IP check service {} returned status: {}", url, response.status()));
    }

    let content_type = response.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|val| val.to_str().ok())
        .unwrap_or("");

    let ip_str = if content_type.contains("application/json") {
        // Try parsing as JSON: {"ip": "..."}
        let json_response: IpCheckResponse = response.json()
            .map_err(|e| format!("Failed to parse JSON response from {}: {}", url, e))?;
        json_response.ip
    } else {
        // Assume plain text IP
        response.text()
            .map_err(|e| format!("Failed to read text response from {}: {}", url, e))?
            .trim().to_string()
    };

    // Parse the extracted string as an IP address
    ip_str.parse::<IpAddr>()
        .map_err(|e| format!("Invalid IP address format received from {}: '{}' ({})", url, ip_str, e))
}

/// Verifies DNS configuration by reading /etc/resolv.conf and comparing against expected servers.
/// Collects findings instead of returning early errors.
///
/// # Arguments
/// * `config` - The application configuration (hardcoded defaults).
/// # Returns
/// A `DnsCheckResult` struct containing detailed results and findings.
pub fn verify_dns(config: &Config) -> DnsCheckResult {
    info!("Verifying DNS configuration...");

    let expected_servers = config.expected_dns_servers.clone().unwrap_or_default();

    let mut result = DnsCheckResult {
        servers_expected: expected_servers.clone(),
        servers_found: Vec::new(),
        match_status: DnsMatchStatus::NotChecked, // Default
        findings: Vec::new(),
    };

    if expected_servers.is_empty() {
        warn!("No expected DNS servers configured. Skipping DNS check.");
        // Status remains NotChecked
        return result;
    }

    let resolv_conf_path = "/etc/resolv.conf";
    debug!("Reading DNS configuration from {}", resolv_conf_path);

    let content = match fs::read_to_string(resolv_conf_path) {
        Ok(c) => c,
        Err(e) => {
            let finding = format!("Failed to read {}: {}", resolv_conf_path, e);
            result.findings.push(finding.clone());
            result.match_status = DnsMatchStatus::ReadError(e.to_string());
            error!("{}", finding);
            return result; // Cannot proceed without the file content
        }
    };

    // Regex to find lines starting with "nameserver" followed by an IP address.
    let re = match Regex::new(r"^\s*nameserver\s+([^\s]+)") {
        Ok(r) => r,
        Err(e) => {
            // This is a programming error (invalid regex), should likely panic or log severe error.
            let finding = format!("FATAL: Failed to compile regex for DNS parsing: {}", e);
            result.findings.push(finding.clone());
            result.match_status = DnsMatchStatus::ReadError("Regex compilation failed".to_string());
            error!("{}", finding);
            // Consider returning here as parsing won't work
            return result;
        }
    };

    for line in content.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }

        if let Some(caps) = re.captures(trimmed_line) {
            if let Some(server_str_match) = caps.get(1) {
                let server_str = server_str_match.as_str();
                match server_str.parse::<IpAddr>() {
                    Ok(ip_addr) => result.servers_found.push(ip_addr),
                    Err(e) => {
                        // Log a warning but continue parsing other lines
                        warn!(
                            "Failed to parse potential nameserver IP '{}' from {}: {}. Skipping.",
                            server_str, resolv_conf_path, e
                        );
                        // Optionally add to findings if strict parsing is desired
                        // result.findings.push(format!("Warning: Unparseable nameserver entry '{}'", server_str));
                    }
                }
            }
        }
    }

    if result.servers_found.is_empty() {
         let finding = format!("No valid nameserver entries found in {}", resolv_conf_path);
         result.findings.push(finding.clone());
         result.match_status = DnsMatchStatus::NoServersFound;
         error!("{}", finding);
         return result; // No servers found to compare
    }

    info!("DNS servers found in {}: {:?}", resolv_conf_path, result.servers_found);
    debug!("Expected DNS servers: {:?}", result.servers_expected);

    // Compare the found servers with the expected servers using HashSets for order-insensitivity.
    let actual_set: HashSet<_> = result.servers_found.iter().collect();
    let expected_set: HashSet<_> = result.servers_expected.iter().collect();

    if actual_set == expected_set {
        info!("Actual DNS servers match expected configuration.");
        result.match_status = DnsMatchStatus::Match;
    } else {
        let missing: Vec<_> = expected_set.difference(&actual_set).map(|&&ip| ip.to_string()).collect();
        let unexpected: Vec<_> = actual_set.difference(&expected_set).map(|&&ip| ip.to_string()).collect();

        let mut error_msg = String::from("DNS server configuration mismatch.");
        if !missing.is_empty() {
            error_msg.push_str(&format!(" Missing expected servers: {:?}", missing));
        }
        if !unexpected.is_empty() {
            error_msg.push_str(&format!(" Found unexpected servers: {:?}", unexpected));
        }
        result.findings.push(error_msg.clone());
        result.match_status = DnsMatchStatus::Mismatch;
        error!("{}", error_msg); // Log the mismatch as an error
    }

    result
} 