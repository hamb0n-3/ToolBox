// Declare the modules we created
mod network_checks;
mod host_audit;
mod packet_capture;
mod opsec_tests;

use log::{info, error, warn, debug, LevelFilter}; // Import logging tools
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
// Add necessary imports for types used in default config
use std::net::IpAddr;
use std::str::FromStr; // To parse IP addresses
use ipnetwork::IpNetwork; // For CIDR notation
use std::net::IpAddr::V6;
use reqwest::blocking::Client; // Added for external IP check
use serde::Deserialize; // Added for parsing JSON response from IP check service

// Use functions and types from our modules
// Import the new result types and enums from network_checks
use network_checks::{
    verify_network_interfaces, verify_dns,
    InterfaceCheckResult, DnsCheckResult,
    IpNetworkMatchStatus, ExternalIpStatus, DnsMatchStatus // Import enums too
};
// Import Host Audit results
use host_audit::{
    audit_host, HostAuditResult,
    PortCheckResult, ProcessCheckResult, LoginCheckResult, FileCheckResult,
    ModuleCheckResult, SystemdCheckResult, FirewallCheckResult // Import sub-results if needed
};
// Import Packet Capture results
use packet_capture::{monitor_traffic, TrafficMonitorResult, LeakEvent};
// Import Opsec Test results
use opsec_tests::{perform_opsec_tests, OpsecTestResult};

// Define a struct to hold the configuration settings (even if hardcoded)
// This keeps the function signatures compatible for now.
// We might refactor later to remove this entirely.
#[derive(Debug, Clone)]
pub struct Config {
    // Network Checks related
    pub vpn_interface_name: String,
    pub expected_vpn_ip_network: Option<IpNetwork>,
    pub expected_dns_servers: Option<Vec<IpAddr>>,
    pub physical_interface_names: Option<Vec<String>>, // If None, attempt auto-detect later
    pub vpn_server_ips: Option<Vec<IpAddr>>,
    pub local_subnets: Option<Vec<IpNetwork>>,
    pub check_firewall_rules: Option<bool>,
    pub check_external_ip: Option<bool>,
    pub external_ip_check_url: Option<String>,
    pub expected_external_ips: Option<Vec<IpAddr>>,
    pub allowed_leak_destination_ips: Option<Vec<IpAddr>>,
    pub allowed_leak_destination_ports: Option<Vec<u16>>,

    // Host Audit related
    pub allowed_listening_tcp_ports: Option<Vec<u16>>,
    pub allowed_listening_udp_ports: Option<Vec<u16>>,
    pub watched_files_for_modification: Option<Vec<PathBuf>>,
    pub allowed_login_users: Option<Vec<String>>,
    pub allowed_login_hosts: Option<Vec<String>>,
    pub required_kernel_modules: Option<Vec<String>>,
    pub disallowed_kernel_modules: Option<Vec<String>>,
    pub enforce_required_modules_only: Option<bool>,
    pub disallowed_process_names: Option<Vec<String>>,
    pub disallowed_systemd_services: Option<Vec<String>>,
    pub disallowed_systemd_timers: Option<Vec<String>>,
    pub disallowed_hosts_entries: Option<Vec<String>>,
    pub disallowed_env_vars: Option<Vec<String>>,
}

// Add a structure to hold all check results together
#[derive(Debug, Clone)]
struct AllCheckResults {
    interface_check: Option<InterfaceCheckResult>,
    dns_check: Option<DnsCheckResult>,
    host_audit: Option<HostAuditResult>,
    opsec_tests: Option<OpsecTestResult>,
    traffic_monitor: Option<TrafficMonitorResult>,
}

impl AllCheckResults {
    fn new() -> Self {
        AllCheckResults {
            interface_check: None,
            dns_check: None,
            host_audit: None,
            opsec_tests: None,
            traffic_monitor: None,
        }
    }

    // Function to calculate confidence score based on collected results
    fn calculate_confidence(&self) -> (f64, Vec<String>) {
        let mut score = 100.0;
        let mut critical_findings = Vec::new();

        // --- Penalties from Network Checks --- //
        if let Some(ref iface_res) = self.interface_check {
            if !iface_res.interface_found {
                score -= 50.0; // Major penalty: VPN interface missing
                critical_findings.push(format!("Major: VPN interface {} not found.", iface_res.interface_name));
            } else {
                if iface_res.is_up == Some(false) {
                    score -= 30.0; // Significant penalty: Interface down
                    critical_findings.push(format!("Critical: VPN interface {} is down.", iface_res.interface_name));
                }
                if iface_res.is_running == Some(false) {
                    score -= 5.0; // Minor penalty: Not running (might be temporary)
                     critical_findings.push(format!("Warning: VPN interface {} is up but not running.", iface_res.interface_name));
                }
                 // Penalize IP mismatches/issues (if checked)
                match iface_res.ip_network_match_status {
                    IpNetworkMatchStatus::Mismatch(_) | IpNetworkMatchStatus::NoIPs(_) => {
                        score -= 25.0;
                        critical_findings.push("Critical: VPN IP address configuration mismatch or missing.".to_string());
                    },
                    IpNetworkMatchStatus::InterfaceHasNoIPs => {
                         score -= 10.0; // Warning level
                         critical_findings.push("Warning: VPN interface has no IP addresses assigned.".to_string());
                    },
                    _ => {} // Match or NotChecked are ok here
                }
                // Penalize External IP mismatches (if checked)
                match iface_res.external_ip_status {
                    ExternalIpStatus::ExpectedMismatch(_, _) => {
                        score -= 40.0; // High penalty for confirmed wrong external IP
                        critical_findings.push("Critical: External IP address does not match expected IPs.".to_string());
                    },
                    ExternalIpStatus::CheckFailed(_) => {
                         score -= 10.0; // Penalty for being unable to check
                         critical_findings.push("Warning: External IP check failed.".to_string());
                    }
                    _ => {} // Disabled, Ok, Match are fine
                }
            }
        } else {
            score -= 10.0; // Penalty if check didn't run for some reason
            critical_findings.push("Warning: Interface check did not complete.".to_string());
        }

        if let Some(ref dns_res) = self.dns_check {
            match dns_res.match_status {
                DnsMatchStatus::Mismatch | DnsMatchStatus::NoServersFound => {
                    score -= 30.0; // Significant penalty for wrong/missing DNS
                    critical_findings.push("Critical: DNS server configuration mismatch or no servers found.".to_string());
                }
                DnsMatchStatus::ReadError(_) => {
                    score -= 15.0; // Penalty for being unable to read/parse resolv.conf
                    critical_findings.push("Warning: Failed to read or parse DNS configuration file.".to_string());
                }
                _ => {} // Match or NotChecked are ok
            }
        } else {
             score -= 10.0; // Penalty if check didn't run
             critical_findings.push("Warning: DNS check did not complete.".to_string());
        }

        // --- Penalties from Host Audit --- //
        if let Some(ref audit_res) = self.host_audit {
            // 1. Port Check Penalties
            if !audit_res.port_check.unexpected_sockets.is_empty() {
                score -= 15.0 * audit_res.port_check.unexpected_sockets.len() as f64; // Penalty per unexpected port
                critical_findings.push(format!(
                    "Critical: Found {} unexpected listening sockets.",
                    audit_res.port_check.unexpected_sockets.len()
                ));
            }
             // Add small penalty for parsing errors
            if audit_res.port_check.findings.iter().any(|f| f.contains("Failed to parse")) {
                score -= 5.0;
                 critical_findings.push("Warning: Errors encountered parsing listening port data.".to_string());
            }

            // 2. Process Check Penalties
            if !audit_res.process_check.disallowed_processes_found.is_empty() {
                 score -= 25.0 * audit_res.process_check.disallowed_processes_found.len() as f64; // High penalty per disallowed process
                 critical_findings.push(format!(
                    "Critical: Found {} disallowed processes running.",
                    audit_res.process_check.disallowed_processes_found.len()
                 ));
            }
            if audit_res.process_check.findings.iter().any(|f| f.contains("Error reading info")) {
                 score -= 5.0; // Minor penalty for failing to read some process info
                 critical_findings.push("Warning: Errors encountered reading some process info.".to_string());
            }

            // 3. Login Check Penalties
            if !audit_res.login_check.disallowed_logins_found.is_empty() {
                 score -= 20.0 * audit_res.login_check.disallowed_logins_found.len() as f64;
                 critical_findings.push(format!(
                    "Critical: Found {} disallowed user logins.",
                    audit_res.login_check.disallowed_logins_found.len()
                 ));
            }
            if audit_res.login_check.findings.iter().any(|f| f.contains("Failed to parse utmp")) {
                 score -= 10.0;
                 critical_findings.push("Warning: Failed to parse user login records (utmp).".to_string());
            }

             // 4. File Check Penalties
            if !audit_res.file_check.recently_modified_files.is_empty() {
                score -= 5.0 * audit_res.file_check.recently_modified_files.len() as f64; // Moderate penalty per modified file
                critical_findings.push(format!(
                    "Warning: Found {} critical files modified recently.",
                    audit_res.file_check.recently_modified_files.len()
                ));
            }
            if audit_res.file_check.findings.iter().any(|f| f.contains("Could not get")) {
                score -= 5.0; // Minor penalty for access errors
                critical_findings.push("Warning: Errors accessing metadata/mtime for some watched files.".to_string());
            }

             // 5. Module Check Penalties
            if !audit_res.module_check.disallowed_modules_loaded.is_empty() {
                 score -= 30.0 * audit_res.module_check.disallowed_modules_loaded.len() as f64; // High penalty per disallowed module
                 critical_findings.push(format!(
                    "Critical: Found {} disallowed kernel modules loaded.",
                    audit_res.module_check.disallowed_modules_loaded.len()
                 ));
            }
            if !audit_res.module_check.required_modules_missing.is_empty() {
                 score -= 25.0 * audit_res.module_check.required_modules_missing.len() as f64;
                 critical_findings.push(format!(
                    "Critical: Found {} required kernel modules missing.",
                    audit_res.module_check.required_modules_missing.len()
                 ));
            }
            if !audit_res.module_check.unexpected_modules_loaded.is_empty() {
                 score -= 10.0 * audit_res.module_check.unexpected_modules_loaded.len() as f64;
                 critical_findings.push(format!(
                    "Warning: Found {} unexpected kernel modules loaded (strict mode).",
                    audit_res.module_check.unexpected_modules_loaded.len()
                 ));
            }
            if audit_res.module_check.findings.iter().any(|f| f.contains("Error reading")) {
                 score -= 5.0;
                 critical_findings.push("Warning: Errors encountered reading kernel module data.".to_string());
            }

             // 6. Systemd Check Penalties
            if !audit_res.systemd_check.disallowed_services_found.is_empty() {
                 score -= 20.0 * audit_res.systemd_check.disallowed_services_found.len() as f64;
                 critical_findings.push(format!(
                    "Critical: Found {} disallowed systemd services running.",
                    audit_res.systemd_check.disallowed_services_found.len()
                 ));
            }
             if !audit_res.systemd_check.disallowed_timers_found.is_empty() {
                 score -= 15.0 * audit_res.systemd_check.disallowed_timers_found.len() as f64;
                 critical_findings.push(format!(
                    "Critical: Found {} disallowed systemd timers active.",
                    audit_res.systemd_check.disallowed_timers_found.len()
                 ));
            }
             if audit_res.systemd_check.findings.iter().any(|f| f.contains("Failed to run") || f.contains("Failed to parse")) {
                 score -= 10.0;
                 critical_findings.push("Warning: Errors running or parsing systemctl commands.".to_string());
            }

             // 7. Firewall Check Penalties (Optional Check)
            if let Some(ref fw_res) = audit_res.firewall_check {
                if fw_res.findings.iter().any(|f| f.contains("failed with status") || f.contains("Failed to execute")) {
                    score -= 10.0;
                    critical_findings.push("Warning: Errors executing firewall list commands.".to_string());
                }
                 if fw_res.findings.iter().any(|f| f.contains("Cannot check firewall rules")) {
                    score -= 5.0;
                    critical_findings.push("Warning: Firewall check skipped (nft/iptables not found).".to_string());
                }
                 // TODO: Add more sophisticated firewall rule analysis later?
            }

        } else {
            score -= 10.0; // Penalty if host audit didn't run
            critical_findings.push("Warning: Host audit check did not complete.".to_string());
        }

        // --- Penalties from Opsec Tests --- //
        if let Some(ref opsec_res) = self.opsec_tests {
            // Opsec findings are generally warnings/heuristics.
            // Apply smaller penalties, but ensure they are reported.
            let num_opsec_findings = opsec_res.all_findings.len();
            if num_opsec_findings > 0 {
                 // Example: Deduct 2 points per opsec finding, max penalty of 20
                let penalty = (num_opsec_findings as f64 * 2.0).min(20.0);
                score -= penalty;
                // Add a general note to critical findings if opsec issues exist
                critical_findings.push(format!(
                    "Opsec Warning: {} potential opsec issues identified (check findings list).",
                    num_opsec_findings
                ));
            }
        } else {
            // Minor penalty if opsec tests didn't run (should always run)
            score -= 5.0;
             critical_findings.push("Warning: Opsec tests did not complete.".to_string());
        }

        // --- Penalties from Traffic Monitoring --- //
        if let Some(ref monitor_res) = self.traffic_monitor {
            // Very high penalty for any detected leak
            if !monitor_res.detected_leaks.is_empty() {
                // Example: Base penalty + penalty per leak, capped reduction
                let leak_penalty = (50.0 + 10.0 * monitor_res.detected_leaks.len() as f64).min(80.0);
                score -= leak_penalty;
                critical_findings.push(format!(
                    "CRITICAL: {} potential traffic leak(s) detected!",
                    monitor_res.detected_leaks.len()
                ));
                // Add details of first few leaks to critical findings for visibility
                for (i, leak) in monitor_res.detected_leaks.iter().take(3).enumerate() {
                     critical_findings.push(format!(
                        "  Leak {}: Iface={}, Proto={}, Src={}:{}, Dst={}:{}",
                        i + 1,
                        leak.interface_name,
                        leak.protocol,
                        leak.source_ip,
                        leak.source_port.map_or_else(|| "N/A".to_string(), |p| p.to_string()),
                        leak.dest_ip,
                        leak.dest_port.map_or_else(|| "N/A".to_string(), |p| p.to_string())
                    ));
                }
                if monitor_res.detected_leaks.len() > 3 {
                     critical_findings.push("  ... (more leaks logged)".to_string());
                }
            }
            // Penalty for errors during monitoring setup/run
            if !monitor_res.findings.is_empty() {
                score -= 15.0; // Significant penalty for monitoring errors
                 critical_findings.push(format!(
                    "Warning: {} errors encountered during traffic monitoring setup or capture.",
                    monitor_res.findings.len()
                ));
            }

        } else {
             // Penalty if monitoring didn't run/complete (should always run in this version)
             score -= 20.0;
             critical_findings.push("Warning: Traffic monitoring did not complete.".to_string());
        }

        // Ensure score doesn't go below 0
        score = score.max(0.0);

        (score, critical_findings)
    }
}

/// VPN Verifier: A tool to verify VPN connection security and monitor traffic.
/// Checks interface status, IP, DNS, listening ports, and optionally monitors for leaks.
/*
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the configuration file (TOML format)
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: PathBuf,

    /// Enable verbose logging (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Run traffic monitoring continuously (requires root privileges).
    /// Without this flag, only static checks are performed.
    #[arg(long)]
    monitor: bool,
}
*/

fn main() -> ExitCode {
    // REMOVE: Parse command-line arguments
    // let args = Args::parse();

    // Initialize logging based on verbosity - FIX Level
    // REMOVE: let log_level = match args.verbose { ... };
    let log_level = LevelFilter::Info; // Hardcode log level to Info

    // Simple logger setup
    env_logger::Builder::new()
        .filter_level(log_level) // Apply the fixed log level
        .format_timestamp_secs() // Use seconds for timestamps (or customize/remove for opsec)
        .init();

    info!("Starting Network Defense Monitor..."); // Updated name
    // REMOVE: debug!("Arguments received: {:?}"", args);

    // --- Default Configuration Values ---
    // Define the hardcoded configuration settings here.
    let config = Config {
        // Network Checks related
        vpn_interface_name: "tun0".to_string(), // Default VPN interface name
        expected_vpn_ip_network: None, // Don't enforce a specific VPN IP range by default
        // Default to known privacy DNS servers (Quad9)
        expected_dns_servers: Some(vec![
            IpAddr::from_str("9.9.9.9").unwrap(),
            IpAddr::from_str("149.112.112.112").unwrap(),
            IpAddr::from_str("2620:fe::fe").unwrap(), // IPv6 Quad9
            IpAddr::from_str("2620:fe::9").unwrap(),  // IPv6 Quad9
        ]),
        physical_interface_names: None, // Let `monitor_traffic` try to auto-detect physical interfaces
        vpn_server_ips: None, // Don't assume specific VPN server IPs by default
        // Default local subnets to ignore for leak detection
        local_subnets: Some(vec![
            IpNetwork::from_str("10.0.0.0/8").unwrap(),
            IpNetwork::from_str("172.16.0.0/12").unwrap(),
            IpNetwork::from_str("192.168.0.0/16").unwrap(),
            IpNetwork::from_str("fe80::/10").unwrap(), // IPv6 link-local
            IpNetwork::from_str("fc00::/7").unwrap(), // IPv6 unique local
        ]),
        check_firewall_rules: Some(true), // Check basic firewall rules
        check_external_ip: Some(false), // Disable external IP check by default for opsec
        external_ip_check_url: None, // Not needed if check_external_ip is false
        expected_external_ips: None, // Not needed if check_external_ip is false
        allowed_leak_destination_ips: None, // No exceptions for leak destinations by default
        allowed_leak_destination_ports: None, // No exceptions for leak ports by default

        // Host Audit related
        // Allow only SSH by default on TCP. Add others if strictly needed.
        allowed_listening_tcp_ports: Some(vec![22]),
        // Allow only DHCP client (bootpc) and potentially DNS (domain) by default on UDP.
        // Domain (53) might be problematic if local resolver listens. DHCP (67/68) often needed.
        allowed_listening_udp_ports: Some(vec![68]), // bootpc (DHCP client)
        // Watch critical system files for modifications
        watched_files_for_modification: Some(vec![
            PathBuf::from("/etc/passwd"),
            PathBuf::from("/etc/shadow"),
            PathBuf::from("/etc/group"),
            PathBuf::from("/etc/gshadow"),
            PathBuf::from("/etc/sudoers"),
            PathBuf::from("/etc/hosts"),
            PathBuf::from("/etc/resolv.conf"),
            // Add other critical config/binary paths as needed
            // e.g., PathBuf::from("/etc/ssh/sshd_config"),
        ]),
        allowed_login_users: None, // Don't restrict login users by default (monitor only)
        allowed_login_hosts: None, // Don't restrict login hosts by default (monitor only)
        required_kernel_modules: None, // Don't require specific modules by default
        // Disallow modules often used unexpectedly or potentially maliciously
        disallowed_kernel_modules: Some(vec![
            "dummy".to_string(),
            "floppy".to_string(),
            // Add known suspicious module names
        ]),
        enforce_required_modules_only: Some(false), // Don't enforce strict module list
        // Disallow common reconnaissance, backdoor, or suspicious tools
        disallowed_process_names: Some(vec![
            "nc".to_string(),
            "netcat".to_string(),
            "ncat".to_string(),
            "socat".to_string(),
            "mimikatz".to_string(), // Windows tool, but check anyway
            "meterpreter".to_string(), // Metasploit payload
            // Add other suspicious process names
        ]),
        disallowed_systemd_services: None, // Don't disallow specific services by default
        disallowed_systemd_timers: None, // Don't disallow specific timers by default
        // Disallow mapping common public domains to local IPs in /etc/hosts
        disallowed_hosts_entries: Some(vec![
             // Could add specific domains like "google.com", "microsoft.com" etc.
             // Or focus on preventing common malware C2 techniques if known.
        ]),
        // Disallow potentially dangerous environment variables
        disallowed_env_vars: Some(vec![
            "LD_PRELOAD".to_string(),
            "LD_LIBRARY_PATH".to_string(), // Unless essential and carefully managed
            // Add other vars like HISTFILE=/dev/null etc. if desired
        ]),
    };
    info!("Using built-in default configuration."); // Indicate defaults are used

    // --- Setup Graceful Shutdown Signal --- //
    // This atomic boolean will be shared with the monitoring thread.
    // When Ctrl+C is pressed, we set it to true.
    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let signal_clone = Arc::clone(&shutdown_signal);
    // Setup the Ctrl+C handler.
    if let Err(e) = ctrlc::set_handler(move || {
        warn!("Ctrl+C received, signalling shutdown...");
        signal_clone.store(true, Ordering::Relaxed);
        // Note: The handler might run multiple times if Ctrl+C is spammed.
        // The AtomicBool handles this correctly (multiple stores are fine).
        // We could add logic here to only print the message once if desired.
    }) {
        error!("Failed to set Ctrl+C handler: {}. Monitoring cannot be shut down gracefully.", e);
        // Decide whether to proceed without graceful shutdown or exit.
        // For now, we'll proceed, but monitoring won't stop cleanly via Ctrl+C.
    }

    // --- Run Verification Checks --- //
    let mut all_results = AllCheckResults::new();
    let mut all_findings: Vec<String> = Vec::new(); // Central list for all findings

    // 1. Verify Network Interfaces and VPN Status
    info!("--- Running Network Interface Check ---");
    let interface_result = verify_network_interfaces(&config);
    // Add findings from this check to the central list
    all_findings.extend(interface_result.findings.iter().cloned());
    // Store the result
    all_results.interface_check = Some(interface_result);

    // 2. Verify DNS Configuration
    info!("--- Running DNS Check ---");
    let dns_result = verify_dns(&config);
    all_findings.extend(dns_result.findings.iter().cloned());
    all_results.dns_check = Some(dns_result);

    // 3. Audit Host (Listening Ports)
    // Note: This check might require specific permissions depending on the OS or security modules (like AppArmor/SELinux).
    info!("--- Running Host Audit (Listening Ports) ---");
    let host_audit_result = audit_host(&config);
    // Add all findings collected during the host audit
    all_findings.extend(host_audit_result.all_findings.iter().cloned());
    all_results.host_audit = Some(host_audit_result);

    // 4. Perform Opsec Tests
    info!("--- Running Opsec Tests ---");
    let opsec_result = perform_opsec_tests(&config);
    all_findings.extend(opsec_result.all_findings.iter().cloned());
    all_results.opsec_tests = Some(opsec_result);

    // 5. Monitor Traffic (Packet Capture)
    info!("--- Starting Continuous Traffic Monitoring (Requires Root/Capabilities) ---");
    warn!("Monitoring will run until Ctrl+C is pressed...");
    let monitor_result = monitor_traffic(&config, Arc::clone(&shutdown_signal));
    // Add findings (errors) from monitoring to the main list
    all_findings.extend(monitor_result.findings.iter().cloned());
    // Store the full result including leaks
    all_results.traffic_monitor = Some(monitor_result);

    // --- Final Report --- //
    info!("--- Verification Summary ---");

    let (confidence, mut critical_findings) = all_results.calculate_confidence(); // Make critical_findings mutable
    let overall_status_ok = confidence >= 80.0;

    info!("System Confidence Score: {:.1}%", confidence);

    // Add leak details to the final report output if any were found
    if let Some(ref monitor_res) = all_results.traffic_monitor {
         if !monitor_res.detected_leaks.is_empty() {
             // Ensure the critical findings list includes leak info if not already added by confidence calc
             if !critical_findings.iter().any(|s| s.contains("traffic leak(s) detected")) {
                 critical_findings.push(format!(
                    "CRITICAL: {} potential traffic leak(s) detected!",
                    monitor_res.detected_leaks.len()
                 ));
             }
             // Add details for *all* leaks to the main findings list for full reporting
             all_findings.push("--- Detected Leak Details ---".to_string());
             for leak in &monitor_res.detected_leaks {
                 all_findings.push(format!(
                    "Leak: Iface={}, Proto={}, Src={}:{}, Dst={}:{}, Len={}, Time={:?}",
                    leak.interface_name,
                    leak.protocol,
                    leak.source_ip,
                    leak.source_port.map_or_else(|| "N/A".to_string(), |p| p.to_string()),
                    leak.dest_ip,
                    leak.dest_port.map_or_else(|| "N/A".to_string(), |p| p.to_string()),
                    leak.packet_len,
                    leak.timestamp // Consider formatting timestamp
                 ));
             }
             all_findings.push("--- End Leak Details ---".to_string());
         }
    }

    if overall_status_ok && all_findings.is_empty() {
         info!("All checks indicate nominal status.");
         ExitCode::SUCCESS
    } else {
        if !overall_status_ok {
             error!("Confidence score below threshold! System status potentially compromised or misconfigured.");
        } else {
             warn!("Confidence score is acceptable, but review the following findings:");
        }

        // List critical findings affecting the score
        if !critical_findings.is_empty() {
            error!("Critical Findings Impacting Score:");
            for finding in critical_findings {
                 error!("- {}", finding);
            }
        }

        // List all other findings (including warnings logged during checks)
        // Filter out findings already listed as critical to avoid duplication
        let other_findings: Vec<_> = all_findings.iter()
            // .filter(|f| !critical_findings.contains(f)) // Simple string comparison might miss variants
            .collect(); // Keep all for now, refine later if needed

        if !other_findings.is_empty() {
             warn!("All Reported Findings & Warnings (includes Opsec checks & Leak details):");
            for finding in other_findings {
                 warn!("- {}", finding);
            }
        }
         // Always return failure code if confidence is low or findings exist
        ExitCode::FAILURE
    }
}

// Optional: Add a simple root check if monitor is enabled
// fn uid_check() {
//     use nix::unistd::Uid;
//     if !Uid::current().is_root() {
//          error!("Traffic monitoring requires root privileges. Please run with sudo.");
//          // Consider exiting immediately
//          // std::process::exit(1);
//     }
// } 