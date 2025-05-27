// src/opsec_tests.rs
use crate::config::Config;
use log::{info, warn, debug, error};
use std::fs;
use std::io::{BufRead, BufReader};
use std::collections::HashSet;
use std::env;
use std::net::IpAddr;

// --- Result Structs for Opsec Tests ---

/// Holds findings from the /etc/hosts file check.
#[derive(Debug, Clone, Default)]
pub struct HostsFileCheckResult {
    pub findings: Vec<String>, // List of suspicious or disallowed entries found.
}

/// Holds findings from the environment variable check.
#[derive(Debug, Clone, Default)]
pub struct EnvVarCheckResult {
    pub findings: Vec<String>, // List of potentially sensitive or disallowed vars found.
}

/// Overall result structure for all opsec tests.
#[derive(Debug, Clone, Default)]
pub struct OpsecTestResult {
    pub hosts_file_check: HostsFileCheckResult,
    pub env_var_check: EnvVarCheckResult,
    // TODO: Add fields for future opsec test results
    // Collect all findings for easy access
    pub all_findings: Vec<String>,
}

impl OpsecTestResult {
    // Helper to add findings from a sub-result
    fn add_findings(&mut self, sub_check_name: &str, findings: &[String]) {
        if !findings.is_empty() {
            debug!("Findings from {}:
{}", sub_check_name, findings.join("\n"));
            self.all_findings.extend(findings.iter().cloned());
        }
    }
}

/// Performs various operational security (Opsec) checks.
///
/// # Arguments
/// * `config` - The application configuration.
/// # Returns
/// An `OpsecTestResult` struct containing detailed findings.
pub fn perform_opsec_tests(config: &Config) -> OpsecTestResult {
    info!("--- Performing Opsec Tests ---");
    let mut result = OpsecTestResult::default();

    // --- 1. Check /etc/hosts file ---
    info!("Checking /etc/hosts file...");
    let hosts_res = check_hosts_file(config);
    result.add_findings("Hosts File Check", &hosts_res.findings);
    result.hosts_file_check = hosts_res;

    // --- 2. Check Environment Variables ---
    info!("Checking environment variables...");
    let env_res = check_environment_variables(config);
    result.add_findings("Environment Variable Check", &env_res.findings);
    result.env_var_check = env_res;

    // TODO: Add more opsec tests:
    // - Persistence locations (cron, systemd user units)
    // - Network connections to known bad IPs
    // - Indicators of virtualization/sandboxing
    // - Check loaded browser extensions?
    // - Check for known tracking domains/IPs in DNS cache or connections?

    // --- Report Overall Opsec Test Result ---
    if result.all_findings.is_empty() {
        info!("Opsec tests completed with no findings.");
    } else {
        warn!("Opsec tests completed with {} findings.", result.all_findings.len());
    }
    result
}

/// Checks the /etc/hosts file for potentially suspicious entries.
/// TODO: Add configuration options for allowed/disallowed entries.
/// Returns a `HostsFileCheckResult`.
fn check_hosts_file(config: &Config) -> HostsFileCheckResult {
    let mut result = HostsFileCheckResult::default();
    let hosts_path = "/etc/hosts";
    debug!("Reading hosts file from {}", hosts_path);

    // Prepare rules from config
    let disallowed_entries: Option<HashSet<String>> = config.disallowed_hosts_entries.as_ref().map(|v| v.iter().cloned().collect());
    debug!("Disallowed hosts entries (mapping to non-localhost): {:?}", disallowed_entries);

    let file = match fs::File::open(hosts_path) {
        Ok(f) => f,
        Err(e) => {
            let finding = format!("Failed to open {}: {}", hosts_path, e);
            error!("{}", finding);
            result.findings.push(finding);
            return result;
        }
    };
    let reader = BufReader::new(file);

    // Example checks (can be expanded based on config):
    let localhost_ips: HashSet<IpAddr> = ["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()].iter().cloned().collect();

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                let finding = format!("Error reading line {} from {}: {}", line_num + 1, hosts_path, e);
                error!("{}", finding);
                result.findings.push(finding);
                continue; // Try next line
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue; // Malformed line
        }

        let ip_str = parts[0];
        let hosts: Vec<&str> = parts[1..].to_vec();

        match ip_str.parse::<IpAddr>() {
            Ok(ip) => {
                let is_localhost_ip = localhost_ips.contains(&ip);

                // Check 1: Is localhost IP pointing to something other than 'localhost' or common variations?
                if is_localhost_ip {
                    for host in &hosts {
                        if *host != "localhost" && !host.ends_with(".localhost") && *host != "localhost.localdomain" {
                            let msg = format!("Suspicious localhost entry: IP {} points to '{}' (line {})", ip, host, line_num + 1);
                            warn!("{}", msg);
                            result.findings.push(msg);
                        }
                    }
                }
                // Check 2: Are non-localhost IPs pointing to 'localhost'?
                else {
                    for host in &hosts {
                        if *host == "localhost" {
                            let msg = format!("Suspicious entry: Non-localhost IP {} points to 'localhost' (line {})", ip, line_num + 1);
                            warn!("{}", msg);
                            result.findings.push(msg);
                        }
                    }
                }

                // Check 3: Check against disallowed entries (mapping disallowed host to non-localhost IP)
                if !is_localhost_ip {
                    if let Some(ref disallowed) = disallowed_entries {
                        for host in &hosts {
                            if disallowed.contains(*host) {
                                let msg = format!("Disallowed hosts entry: IP {} mapped to disallowed host '{}' (line {})", ip, host, line_num + 1);
                                warn!("{}", msg);
                                result.findings.push(msg);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                 let finding = format!("Warning: Could not parse IP address '{}' in {} (line {}). Skipping entry.", ip_str, hosts_path, line_num + 1);
                 warn!("{}", finding);
                 result.findings.push(finding);
            }
        }
    }

    result
}

/// Checks environment variables for potentially sensitive or suspicious values.
/// TODO: Add configuration options for specific variables/patterns to check.
/// Returns an `EnvVarCheckResult`.
fn check_environment_variables(config: &Config) -> EnvVarCheckResult {
    debug!("Checking environment variables...");
    let mut result = EnvVarCheckResult::default();

    // Prepare rules from config
    let disallowed_vars: Option<HashSet<String>> = config.disallowed_env_vars.as_ref().map(|v| v.iter().cloned().collect());
    debug!("Disallowed environment variables: {:?}", disallowed_vars);

    // Example checks (expand with config):
    let sensitive_vars = ["PASS", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY"];
    let suspicious_patterns = ["LD_PRELOAD", "LD_LIBRARY_PATH"]; // Often used for hijacking

    for (key, value) in env::vars() {
        let upper_key = key.to_uppercase();

        // Check 0: Is the variable explicitly disallowed?
        if let Some(ref disallowed) = disallowed_vars {
            if disallowed.contains(&key) {
                let msg = format!("Disallowed environment variable set: {}", key);
                warn!("{}", msg);
                result.findings.push(msg);
                continue; // Skip other checks if disallowed
            }
        }

        // Check 1: Key looks like a common pattern for secrets
        for sensitive in sensitive_vars {
            if upper_key.contains(sensitive) {
                 warn!("Potentially sensitive env var found: {}", key); // Log only key
                 debug!("Sensitive env var detail: {} = <REDACTED, len={}>", key, value.len());
                 result.findings.push(format!("Potentially sensitive var: {}", key));
                 break; // Check next env var
            }
        }

        // Check 2: Key matches potentially risky variables
         for pattern in suspicious_patterns {
             if upper_key == pattern {
                 let msg = format!("Potentially risky environment variable set: {} = {}", key, value);
                 warn!("{}", msg);
                 result.findings.push(msg);
             }
         }
         // TODO: Check value for suspicious content (e.g., paths to unusual locations in LD_*, API key formats)?
    }

    result
}
