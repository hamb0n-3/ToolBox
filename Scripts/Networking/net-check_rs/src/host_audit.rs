use crate::config::Config;
use log::{info, warn, error, debug};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr /*, Ipv4Addr, Ipv6Addr*/}; // Removed unused Ipv4Addr, Ipv6Addr
use std::collections::{HashSet, HashMap};
// use nix::utmpx::{self, Utmpx, UserProcess}; // Commented out unused utmpx import
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::process::{Command, Output};
// use utmp_rs::{UtmpParser, entry::UtmpEntryType}; // Incorrect import
use utmp_rs::UtmpEntry; // Only need UtmpEntry enum
use which;
use std::path::PathBuf;

/// Represents a listening socket identified during the host audit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListeningSocket {
    pub protocol: String,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub uid: Option<u32>,
    pub inode: Option<u64>,
}

/// Represents basic information about a running process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub uid: u32,
    pub name: String,
    pub cmdline: String,
}

/// Represents basic information about a logged-in user session.
#[derive(Debug, Clone)]
pub struct UserLoginInfo {
    pub user: String,
    pub terminal: String,
    pub host: String,
    pub timestamp: Option<SystemTime>,
}

/// Represents a kernel module found during the check.
#[derive(Debug, Clone)]
pub struct KernelModuleInfo {
    pub name: String,
}

/// Represents a systemd unit found during the check.
#[derive(Debug, Clone)]
pub struct SystemdUnitInfo {
    pub name: String,
    pub unit_type: String,
    pub state: String,
}

/// Result from checking listening ports.
#[derive(Debug, Clone, Default)]
pub struct PortCheckResult {
    pub listening_sockets: Vec<ListeningSocket>,
    pub unexpected_sockets: Vec<ListeningSocket>,
    pub findings: Vec<String>,
}

/// Result from checking running processes.
#[derive(Debug, Clone, Default)]
pub struct ProcessCheckResult {
    pub processes: Vec<ProcessInfo>,
    pub disallowed_processes_found: Vec<ProcessInfo>,
    pub findings: Vec<String>,
}

/// Result from checking user logins.
#[derive(Debug, Clone, Default)]
pub struct LoginCheckResult {
    pub active_logins: Vec<UserLoginInfo>,
    pub disallowed_logins_found: Vec<UserLoginInfo>,
    pub findings: Vec<String>,
}

/// Result from checking file modifications.
#[derive(Debug, Clone, Default)]
pub struct FileCheckResult {
    pub recently_modified_files: Vec<(PathBuf, Duration)>,
    pub findings: Vec<String>,
}

/// Result from checking kernel modules.
#[derive(Debug, Clone, Default)]
pub struct ModuleCheckResult {
    pub loaded_modules: Vec<KernelModuleInfo>,
    pub required_modules_missing: Vec<String>,
    pub disallowed_modules_loaded: Vec<String>,
    pub unexpected_modules_loaded: Vec<String>,
    pub findings: Vec<String>,
}

/// Result from checking systemd units.
#[derive(Debug, Clone, Default)]
pub struct SystemdCheckResult {
    pub running_services: Vec<SystemdUnitInfo>,
    pub active_timers: Vec<SystemdUnitInfo>,
    pub disallowed_services_found: Vec<SystemdUnitInfo>,
    pub disallowed_timers_found: Vec<SystemdUnitInfo>,
    pub findings: Vec<String>,
}

/// Result from checking firewall status (basic).
#[derive(Debug, Clone, Default)]
pub struct FirewallCheckResult {
    pub tool_used: Option<String>,
    pub ruleset_output: Option<String>,
    pub findings: Vec<String>,
}

/// Overall result structure for the entire host audit.
#[derive(Debug, Clone)]
pub struct HostAuditResult {
    pub port_check: PortCheckResult,
    pub process_check: ProcessCheckResult,
    pub login_check: LoginCheckResult,
    pub file_check: FileCheckResult,
    pub module_check: ModuleCheckResult,
    pub systemd_check: SystemdCheckResult,
    pub firewall_check: Option<FirewallCheckResult>,
    pub all_findings: Vec<String>,
}

impl HostAuditResult {
    fn new() -> Self {
        HostAuditResult {
            port_check: PortCheckResult::default(),
            process_check: ProcessCheckResult::default(),
            login_check: LoginCheckResult::default(),
            file_check: FileCheckResult::default(),
            module_check: ModuleCheckResult::default(),
            systemd_check: SystemdCheckResult::default(),
            firewall_check: None,
            all_findings: Vec::new(),
        }
    }

    fn add_findings(&mut self, sub_check_name: &str, findings: &[String]) {
        if !findings.is_empty() {
            debug!("Findings from {}:
{}", sub_check_name, findings.join("\n"));
            self.all_findings.extend(findings.iter().cloned());
        }
    }
}

/// Performs a host audit by checking various system aspects.
/// Returns a `HostAuditResult` containing detailed findings and statistics.
///
/// # Arguments
/// * `config` - The application configuration (hardcoded defaults).
/// # Returns
/// A `HostAuditResult` struct.
pub fn audit_host(config: &Config) -> HostAuditResult {
    info!("Performing host audit...");
    let mut result = HostAuditResult::new();

    // --- 1. Check Listening Ports ---
    info!("Checking listening ports...");
    let port_res = check_listening_ports(config);
    result.add_findings("Listening Ports", &port_res.findings);
    result.port_check = port_res;

    // --- 2. Check Running Processes ---
    info!("Checking running processes...");
    let proc_res = check_running_processes(config);
    result.add_findings("Running Processes", &proc_res.findings);
    result.process_check = proc_res;

    // --- 3. Check User Logins ---
    info!("Checking user logins...");
    let login_res = check_user_logins(config);
    result.add_findings("User Logins", &login_res.findings);
    result.login_check = login_res;

    // --- 4. Check File Modifications ---
    info!("Checking file modifications...");
    let file_res = check_file_modifications(config);
    result.add_findings("File Modifications", &file_res.findings);
    result.file_check = file_res;

    // --- 5. Check Loaded Kernel Modules ---
    info!("Checking loaded kernel modules...");
    let mod_res = check_kernel_modules(config);
    result.add_findings("Kernel Modules", &mod_res.findings);
    result.module_check = mod_res;

    // --- 6. Check Systemd Units ---
    info!("Checking systemd services and timers...");
    let systemd_res = check_systemd_units(config);
    result.add_findings("Systemd Units", &systemd_res.findings);
    result.systemd_check = systemd_res;

    // --- 7. Check Firewall Rules ---
    if config.check_firewall_rules.unwrap_or(false) {
        info!("Checking firewall rules (basic check)...");
        let fw_res = check_firewall(config);
        result.add_findings("Firewall Check", &fw_res.findings);
        result.firewall_check = Some(fw_res);
    } else {
        info!("Skipping firewall check (disabled).");
    }

    // Log summary of findings count
    if result.all_findings.is_empty() {
        info!("Host audit completed with no findings.");
    } else {
        warn!("Host audit completed with {} findings.", result.all_findings.len());
        // Detailed findings are already logged by sub-functions or the add_findings helper
    }

    result
}

/// Checks for unexpected listening TCP and UDP ports.
/// Returns a `PortCheckResult`.
fn check_listening_ports(config: &Config) -> PortCheckResult {
    let mut result = PortCheckResult::default();

    let allowed_tcp_ports: HashSet<u16> = config.allowed_listening_tcp_ports.as_ref().map_or_else(HashSet::new, |v| v.iter().cloned().collect());
    let allowed_udp_ports: HashSet<u16> = config.allowed_listening_udp_ports.as_ref().map_or_else(HashSet::new, |v| v.iter().cloned().collect());

    debug!("Allowed TCP Listening Ports: {:?}", allowed_tcp_ports);
    debug!("Allowed UDP Listening Ports: {:?}", allowed_udp_ports);

    let mut all_sockets = HashSet::new();

    let mut process_proc_net_file = |path: &str, protocol: &str, is_ipv6: bool| {
        match parse_proc_net_listen(path, protocol, is_ipv6) {
            Ok(sockets) => all_sockets.extend(sockets),
            Err(e) => {
                let finding = format!("Failed to parse {}: {}", path, e);
                error!("{}", finding);
                result.findings.push(finding);
            }
        }
    };

    process_proc_net_file("/proc/net/tcp", "TCP", false);
    process_proc_net_file("/proc/net/udp", "UDP", false);
    process_proc_net_file("/proc/net/tcp6", "TCP", true);
    process_proc_net_file("/proc/net/udp6", "UDP", true);

    debug!("Detected {} potential listening sockets (incl. loopback)", all_sockets.len());

    for socket in all_sockets {
        if socket.local_ip.is_loopback() {
            debug!("Skipping loopback listening socket: {:?}", socket);
            continue;
        }
        result.listening_sockets.push(socket.clone());

        match socket.protocol.as_str() {
            "TCP" => {
                if !allowed_tcp_ports.contains(&socket.local_port) {
                    let msg = format!("Unexpected TCP listening socket: {}:{} (UID: {:?}, Inode: {:?})",
                                    socket.local_ip, socket.local_port, socket.uid, socket.inode);
                    warn!("{}", msg);
                    result.unexpected_sockets.push(socket.clone());
                    result.findings.push(msg);
                }
            }
            "UDP" => {
                if !allowed_udp_ports.contains(&socket.local_port) {
                    let msg = format!("Unexpected UDP bound socket: {}:{} (UID: {:?}, Inode: {:?})",
                                    socket.local_ip, socket.local_port, socket.uid, socket.inode);
                    warn!("{}", msg);
                    result.unexpected_sockets.push(socket.clone());
                    result.findings.push(msg);
                }
            }
            _ => {}
        }
    }

    info!("Found {} non-loopback listening sockets. {} were unexpected.",
          result.listening_sockets.len(), result.unexpected_sockets.len());

    result
}

/// Checks running processes.
/// Returns a `ProcessCheckResult`.
fn check_running_processes(config: &Config) -> ProcessCheckResult {
    debug!("Reading /proc directory for running processes...");
    let mut result = ProcessCheckResult::default();

    let disallowed_names: Option<HashSet<String>> = config.disallowed_process_names.as_ref().map(|v| v.iter().cloned().collect());
    debug!("Disallowed process names: {:?}", disallowed_names);

    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(e) => {
            let finding = format!("Failed to read /proc directory: {}", e);
            error!("{}", finding);
            result.findings.push(finding);
            return result;
        }
    };

    for entry_result in proc_dir {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                warn!("Error reading entry in /proc: {}", e);
                continue;
            }
        };

        let path = entry.path();
        if path.is_dir() {
            if let Some(dir_name) = path.file_name() {
                if let Some(pid_str) = dir_name.to_str() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        match read_process_info(pid) {
                            Ok(info) => {
                                let info_clone = info.clone();
                                result.processes.push(info);

                                if let Some(ref disallowed) = disallowed_names {
                                    if disallowed.contains(&info_clone.name) {
                                        let msg = format!("Disallowed process found: PID={}, Name='{}', Cmd='{}'",
                                                        info_clone.pid, info_clone.name, info_clone.cmdline);
                                        warn!("{}", msg);
                                        result.disallowed_processes_found.push(info_clone);
                                        result.findings.push(msg);
                                    }
                                }
                            },
                            Err(e) => {
                                // Log failures to read process info as debug, not findings unless necessary
                                debug!("Failed to read info for PID {}: {}", pid, e);
                                // Optionally add as finding: result.findings.push(format!("Error reading info for PID {}: {}", pid, e));
                            }
                        }
                    }
                }
            }
        }
    }

    info!("Found {} running processes.", result.processes.len());
    if !result.disallowed_processes_found.is_empty() {
         warn!("Found {} disallowed processes.", result.disallowed_processes_found.len());
    }

    result
}

/// Reads basic information for a specific process ID from /proc/<pid>.
///
/// # Arguments
/// * `pid` - The process ID.
/// # Returns
/// A `Result` containing `ProcessInfo` or an error string.
fn read_process_info(pid: u32) -> Result<ProcessInfo, String> {
    let status_path = format!("/proc/{}/status", pid);
    let cmdline_path = format!("/proc/{}/cmdline", pid);

    let mut name = String::new();
    let mut uid = u32::MAX;

    let status_content = fs::read_to_string(&status_path)
        .map_err(|e| format!("Failed to read {}: {}", status_path, e))?;

    for line in status_content.lines() {
        if line.starts_with("Name:") {
            name = line.split_whitespace().nth(1).unwrap_or("").to_string();
        } else if line.starts_with("Uid:") {
            if let Some(uid_str) = line.split_whitespace().nth(1) {
                uid = uid_str.parse::<u32>().map_err(|e| format!("Failed to parse UID '{}': {}", uid_str, e))?;
            }
        }
        if !name.is_empty() && uid != u32::MAX {
            break;
        }
    }

    let mut cmdline_bytes = Vec::new();
    File::open(&cmdline_path)
        .and_then(|mut f| f.read_to_end(&mut cmdline_bytes))
        .map_err(|e| format!("Failed to read {}: {}", cmdline_path, e))?;

    let cmdline = String::from_utf8(cmdline_bytes)
        .map(|s| s.replace('\0', " ").trim().to_string())
        .unwrap_or_else(|_| "<invalid UTF-8>".to_string());

    if name.is_empty() || uid == u32::MAX {
        return Err(format!("Could not extract Name or UID from {}", status_path));
    }

    Ok(ProcessInfo { pid, uid, name, cmdline })
}

/// Checks modification times of configured files.
/// Returns a `FileCheckResult`.
fn check_file_modifications(config: &Config) -> FileCheckResult {
    let mut result = FileCheckResult::default();

    let watched_files = match &config.watched_files_for_modification {
        Some(files) if !files.is_empty() => files,
        _ => {
            debug!("No files configured for modification checks.");
            return result;
        }
    };

    debug!("Checking modification times for: {:?}", watched_files);
    let recent_threshold = Duration::from_secs(3600); // TODO: Make configurable
    let now = SystemTime::now();

    for file_path in watched_files {
        match fs::metadata(file_path) {
            Ok(metadata) => {
                match metadata.modified() {
                    Ok(mtime) => {
                        if let Ok(elapsed) = now.duration_since(mtime) {
                            if elapsed < recent_threshold {
                                let msg = format!("File '{}' modified recently ({:?} ago).", file_path.display(), elapsed);
                                warn!("{}", msg);
                                result.recently_modified_files.push((file_path.clone(), elapsed));
                                result.findings.push(msg);
                            }
                        } else {
                            let msg = format!("Modification time for '{}' is in the future!", file_path.display());
                            warn!("{}", msg);
                            result.findings.push(msg);
                        }
                    }
                    Err(e) => {
                        let msg = format!("Could not get modification time for '{}': {}.", file_path.display(), e);
                        warn!("{}", msg);
                        result.findings.push(msg);
                    }
                }
            }
            Err(e) => {
                let msg = format!("Could not get metadata for watched file '{}': {}.", file_path.display(), e);
                warn!("{}", msg);
                result.findings.push(msg);
            }
        }
    }
    result
}

/// Checks loaded kernel modules by parsing /proc/modules.
/// Compares against configured required/disallowed lists.
///
/// # Arguments
/// * `config` - The application configuration, containing kernel module rules.
/// # Returns
/// A `Result` indicating success or an error string if issues are found or parsing fails.
fn check_kernel_modules(config: &Config) -> ModuleCheckResult {
    let mut result = ModuleCheckResult::default();

    let proc_modules_path = "/proc/modules";
    debug!("Reading kernel modules from {}", proc_modules_path);

    let required_modules: Option<HashSet<String>> = config.required_kernel_modules.as_ref().map(|v| v.iter().cloned().collect());
    let disallowed_modules: HashSet<String> = config.disallowed_kernel_modules.as_ref().map_or_else(HashSet::new, |v| v.iter().cloned().collect());
    let enforce_required_only = config.enforce_required_modules_only.unwrap_or(false);

    if enforce_required_only && required_modules.is_none() {
        let finding = "Config error: 'enforce_required_modules_only' is true, but 'required_kernel_modules' is not set.".to_string();
        error!("{}", finding);
        result.findings.push(finding);
        return result; // Cannot proceed reliably
    }

    debug!("Required kernel modules: {:?}", required_modules);
    debug!("Disallowed kernel modules: {:?}", disallowed_modules);
    debug!("Enforce required only: {}", enforce_required_only);

    let file = match File::open(proc_modules_path) {
        Ok(f) => f,
        Err(e) => {
            let finding = format!("Failed to open {}: {}", proc_modules_path, e);
            error!("{}", finding);
            result.findings.push(finding);
            return result;
        }
    };
    let reader = BufReader::new(file);
    let mut current_loaded_names = HashSet::new();

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                let finding = format!("Error reading line {} from {}: {}", line_num + 1, proc_modules_path, e);
                error!("{}", finding);
                result.findings.push(finding);
                continue;
            }
        };

        if let Some(module_name) = line.split_whitespace().next() {
            let name_str = module_name.to_string();
            debug!("Found loaded module: {}", name_str);
            result.loaded_modules.push(KernelModuleInfo { name: name_str.clone() });
            current_loaded_names.insert(name_str.clone());

            if disallowed_modules.contains(&name_str) {
                 let msg = format!("Disallowed kernel module loaded: {}", name_str);
                 warn!("{}", msg);
                 result.disallowed_modules_loaded.push(name_str.clone());
                 result.findings.push(msg);
                 continue;
            }

            if enforce_required_only {
               if let Some(ref required) = required_modules {
                   if !required.contains(&name_str) {
                       let msg = format!("Unexpected kernel module loaded (required list enforced): {}", name_str);
                       warn!("{}", msg);
                       result.unexpected_modules_loaded.push(name_str.clone());
                       result.findings.push(msg);
                   }
               }
            }
        } else {
            let finding = format!("Warning: Skipping malformed line {} in {}: {}", line_num + 1, proc_modules_path, line);
            warn!("{}", finding);
            result.findings.push(finding);
        }
    }

    info!("Found {} loaded kernel modules.", result.loaded_modules.len());

    if let Some(ref required) = required_modules {
       for req_mod in required {
           if !current_loaded_names.contains(req_mod) {
               let msg = format!("Required kernel module not loaded: {}", req_mod);
               error!("{}", msg);
               result.required_modules_missing.push(req_mod.clone());
               result.findings.push(msg);
           }
       }
   }

    result
}

/// Runs an external command and returns its output or an error string.
fn run_command(cmd: &str, args: &[&str]) -> Result<Output, String> {
    debug!("Running command: {} {:?}", cmd, args);
    Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute command '{}': {}", cmd, e))
}

/// Parses the output of `systemctl list-units` or `list-timers`.
/// Returns a map of unit name to its state.
fn parse_systemctl_output(output: &Output, unit_type: &str) -> Result<HashMap<String, String>, String> {
    if !output.status.success() {
        // Log stdout/stderr from failed command for debugging
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let stderr_str = String::from_utf8_lossy(&output.stderr);
        debug!("systemctl stdout on error: {}", stdout_str);
        debug!("systemctl stderr on error: {}", stderr_str);
        return Err(format!("systemctl command failed with status {}: stderr: {}",
                           output.status, stderr_str));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut units = HashMap::new();
    let mut lines = stdout.lines();

    // Skip header line (usually just one line)
    lines.next();

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains(" loaded units listed.") || trimmed.contains(" timers listed.") || trimmed.starts_with("NEXT") || trimmed.starts_with('@') {
             continue; // Skip empty lines, summary lines, template instances for now
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() { continue; }

        // systemd units often start with '●', remove it
        let name_part = parts[0].trim_start_matches(|c: char| !c.is_alnum());

        // Determine state based on unit type and output format
        let state = match unit_type {
            "service" => parts.get(2).unwrap_or(&"unknown").to_string(), // Usually LOAD, ACTIVE, SUB
            "timer" => parts.get(3).unwrap_or(&"unknown").to_string(), // Usually NEXT, LEFT, LAST, PASSED
            _ => "unknown".to_string(),
        };

        if !name_part.is_empty() {
            debug!("Found {} {}: {} ({})", state, unit_type, name_part, trimmed);
            units.insert(name_part.to_string(), state);
        } else {
            warn!("Could not parse unit name from systemctl {} output line: {}", unit_type, trimmed);
        }
    }
    Ok(units)
}

/// Checks running systemd services and active timers.
/// Returns a `SystemdCheckResult`.
fn check_systemd_units(config: &Config) -> SystemdCheckResult {
    let mut result = SystemdCheckResult::default();

    let disallowed_services: HashSet<String> = config.disallowed_systemd_services.as_ref().map_or_else(HashSet::new, |v| v.iter().cloned().collect());
    let disallowed_timers: HashSet<String> = config.disallowed_systemd_timers.as_ref().map_or_else(HashSet::new, |v| v.iter().cloned().collect());

    debug!("Disallowed systemd services: {:?}", disallowed_services);
    debug!("Disallowed systemd timers: {:?}", disallowed_timers);

    // Check running services
    match run_command("systemctl", &["list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"]) {
        Ok(output) => {
            match parse_systemctl_output(&output, "service") {
                Ok(services) => {
                    info!("Found {} running systemd services.", services.len());
                    for (name, state) in services {
                         let unit_info = SystemdUnitInfo { name: name.clone(), unit_type: "service".to_string(), state };
                         result.running_services.push(unit_info.clone());
                        if disallowed_services.contains(&name) {
                            let msg = format!("Disallowed systemd service running: {}", name);
                            warn!("{}", msg);
                            result.disallowed_services_found.push(unit_info);
                            result.findings.push(msg);
                        }
                    }
                }
                Err(e) => {
                    let finding = format!("Failed to parse systemctl service output: {}", e);
                    error!("{}", finding);
                    result.findings.push(finding);
                }
            }
        }
        Err(e) => {
             let finding = format!("Failed to run systemctl list-units: {}", e);
             error!("{}", finding);
             result.findings.push(finding);
         }
    }

    // Check active timers
    match run_command("systemctl", &["list-timers", "--state=active", "--no-pager", "--no-legend"]) {
        Ok(output) => {
            match parse_systemctl_output(&output, "timer") {
                Ok(timers) => {
                    info!("Found {} active systemd timers.", timers.len());
                    for (name, state) in timers {
                         let unit_info = SystemdUnitInfo { name: name.clone(), unit_type: "timer".to_string(), state };
                         result.active_timers.push(unit_info.clone());
                        if disallowed_timers.contains(&name) {
                            let msg = format!("Disallowed systemd timer active: {}", name);
                            warn!("{}", msg);
                            result.disallowed_timers_found.push(unit_info);
                             result.findings.push(msg);
                        }
                    }
                }
                 Err(e) => {
                    let finding = format!("Failed to parse systemctl timer output: {}", e);
                    error!("{}", finding);
                    result.findings.push(finding);
                 }
            }
        }
         Err(e) => {
             let finding = format!("Failed to run systemctl list-timers: {}", e);
             error!("{}", finding);
             result.findings.push(finding);
         }
    }

    result
}

/// Parses a /proc/net/{tcp,udp,tcp6,udp6} file to find listening sockets.
/// Updated to include UID and inode parsing.
fn parse_proc_net_listen(path: &str, protocol: &str, is_ipv6: bool) -> Result<HashSet<ListeningSocket>, String> {
    let file = File::open(path).map_err(|e| format!("Cannot open {}: {}", path, e))?;
    let reader = BufReader::new(file);
    let mut sockets = HashSet::new();

    for line_result in reader.lines().skip(1) {
        let line = line_result.map_err(|e| format!("Error reading line from {}: {}", path, e))?;
        let fields: Vec<&str> = line.split_whitespace().collect();

        // Need at least local_addr(1), state(3), uid(7), inode(9)
        if fields.len() < 10 {
            // Log lower severity, as this can happen with truncated reads etc.
            debug!("Skipping short/malformed line in {}: {}", path, line);
            continue;
        }

        let local_address_field = fields[1];
        let state_field = fields[3];
        let uid_field = fields[7];
        let inode_field = fields[9];

        // Only check TCP listening state (0A). For UDP, any entry implies bound.
        if protocol == "TCP" && state_field != "0A" { continue; }

        match parse_hex_address_port(local_address_field, is_ipv6) {
            Ok((local_ip, local_port)) => {
                let uid = uid_field.parse::<u32>().ok();
                let inode = inode_field.parse::<u64>().ok();
                sockets.insert(ListeningSocket {
                    protocol: protocol.to_string(),
                    local_ip,
                    local_port,
                    uid,
                    inode,
                });
            }
            Err(e) => {
                warn!("Failed to parse address '{}' in {}: {}. Skipping line.", local_address_field, path, e);
            }
        }
    }
    Ok(sockets)
}

/// Parses the hex-encoded "IP:Port" string from /proc/net/* files.
/// Returns `Ok((IpAddr, u16))` or `Err(String)`.
fn parse_hex_address_port(hex_addr_port: &str, is_ipv6: bool) -> Result<(IpAddr, u16), String> {
    let parts: Vec<&str> = hex_addr_port.split(':').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid address format: {}", hex_addr_port));
    }
    let hex_ip = parts[0];
    let hex_port = parts[1];

    let port = u16::from_str_radix(hex_port, 16)
        .map_err(|e| format!("Invalid port hex '{}': {}", hex_port, e))?;

    let ip = if is_ipv6 {
        if hex_ip.len() != 32 {
            return Err(format!("Invalid IPv6 hex length: {} ({})", hex_ip.len(), hex_ip));
        }
        let bytes_res: Result<Vec<u8>, _> = (0..16)
            .map(|i| u8::from_str_radix(&hex_ip[i * 2..i * 2 + 2], 16))
            .collect();
        let bytes = bytes_res.map_err(|e| format!("Invalid IPv6 hex '{}': {}", hex_ip, e))?;
        let addr_bytes: [u8; 16] = bytes.try_into()
            .map_err(|_| "Internal error: Incorrect byte count for IPv6 hex decode".to_string())?;
        IpAddr::V6(std::net::Ipv6Addr::from(addr_bytes))
    } else {
        if hex_ip.len() != 8 {
            return Err(format!("Invalid IPv4 hex length: {} ({})", hex_ip.len(), hex_ip));
        }
        let ip_u32 = u32::from_str_radix(hex_ip, 16)
            .map_err(|e| format!("Invalid IPv4 hex '{}': {}", hex_ip, e))?;
        IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(ip_u32))) // Ensure correct endianness
    };

    Ok((ip, port))
}

/// Checks currently logged-in users using utmp records.
/// Returns a `LoginCheckResult`.
fn check_user_logins(config: &Config) -> LoginCheckResult {
    debug!("Reading utmp/utmpx records for logged-in users...");
    let mut result = LoginCheckResult::default();

    let allowed_users: Option<HashSet<String>> = config.allowed_login_users.as_ref().map(|v| v.iter().cloned().collect());
    let allowed_hosts: Option<HashSet<String>> = config.allowed_login_hosts.as_ref().map(|v| v.iter().cloned().collect());

    debug!("Allowed login users: {:?}", allowed_users);
    debug!("Allowed login hosts: {:?}", allowed_hosts);

    // Try standard paths for utmp
    let utmp_paths = ["/var/run/utmp", "/run/utmp"];
    let mut entries = None;
    for path in utmp_paths.iter() {
        match utmp_rs::parse_from_path(path) {
            Ok(parsed_entries) => {
                debug!("Successfully parsed utmp file: {}", path);
                entries = Some(parsed_entries);
                break;
            }
            Err(e) => {
                debug!("Failed to parse utmp file {}: {}", path, e);
                // Store potential error, but try next path
                if result.findings.is_empty() { // Only store the first error message encountered
                    result.findings.push(format!("Failed to parse utmp file {}: {}", path, e));
                }
            }
        }
    }

    // If no path worked, log the stored error (if any) and return
    let entries = match entries {
        Some(e) => e,
        None => {
            if !result.findings.is_empty() {
                error!("{}", result.findings[0]); // Log the first error encountered
            }
            error!("Could not parse utmp from standard locations.");
            result.findings.push("Could not parse utmp from standard locations.".to_string());
            return result;
        }
    };

    // Clear findings if we successfully parsed a file
    result.findings.clear();

    for entry in entries {
        match entry {
            UtmpEntry::UserProcess { user, line, host, timeval, .. } => {
                if user.is_empty() { continue; }

                let timestamp = timeval.map(|tv| UNIX_EPOCH.checked_add(Duration::from_secs(tv as u64))).flatten();

                let login_info = UserLoginInfo {
                    user: user.to_string(),
                    terminal: line.to_string(),
                    host: host.to_string(),
                    timestamp,
                 };
                debug!("Found active login: {:?}", login_info);
                let info_clone = login_info.clone();
                result.active_logins.push(login_info);

                let current_user = &info_clone.user;
                let current_host = &info_clone.host;
                let current_terminal = &info_clone.terminal;

                let mut disallowed = false;
                if let Some(ref allowed) = allowed_users {
                    if !allowed.contains(current_user) {
                        let msg = format!("Disallowed user login detected: User '{}' (Terminal: {}, Host: {})", current_user, current_terminal, current_host);
                        warn!("{}", msg);
                        result.disallowed_logins_found.push(info_clone.clone());
                        result.findings.push(msg);
                        disallowed = true;
                    }
                }

                // Only check host if user wasn't already disallowed
                if !disallowed && !current_host.is_empty() {
                    if let Some(ref allowed) = allowed_hosts {
                        if !allowed.contains(current_host) {
                            let msg = format!("Login from disallowed host detected: User '{}' from '{}' (Terminal: {})", current_user, current_host, current_terminal);
                            warn!("{}", msg);
                             result.disallowed_logins_found.push(info_clone);
                             result.findings.push(msg);
                        }
                    }
                }
            }
            _ => { debug!("Skipping non-user utmp entry: {:?}", entry); }
        }
    }

    info!("Found {} active user login sessions.", result.active_logins.len());
    if !result.disallowed_logins_found.is_empty() {
        warn!("Found {} disallowed logins.", result.disallowed_logins_found.len());
    }

    result
}

/// Performs a basic check of firewall rules.
/// Returns a `FirewallCheckResult`.
fn check_firewall(_config: &Config) -> FirewallCheckResult {
    let mut result = FirewallCheckResult::default();
    result.ruleset_output = Some(String::new()); // Initialize buffer
    let mut command_found = false;
    let ruleset_buffer = result.ruleset_output.as_mut().unwrap();

    // Try nft
    if let Ok(path) = which::which("nft") {
        command_found = true;
        result.tool_used = Some("nft".to_string());
        info!("Found nft command at: {}", path.display());
        match run_command("nft", &["list", "ruleset"]) {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                ruleset_buffer.push_str("--- nft ruleset ---\n");
                ruleset_buffer.push_str(&stdout);
                ruleset_buffer.push_str("\n");
                if output.status.success() {
                    info!("Successfully listed nft ruleset.");
                    debug!("nft ruleset:\n{}", stdout);
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let err_msg = format!("nft list ruleset failed with status {}: stderr: {}",
                                         output.status, stderr);
                    error!("{}", err_msg);
                    result.findings.push(err_msg);
                }
            }
            Err(e) => {
                let finding = format!("Failed to execute nft: {}", e);
                error!("{}", finding);
                result.findings.push(finding);
             }
        }
    }

    // Try iptables/ip6tables
    if let Ok(path) = which::which("iptables") {
        if !command_found {
             result.tool_used = Some("iptables".to_string());
             command_found = true;
        }
        info!("Found iptables command at: {}", path.display());
        let mut iptables_failed = false;

        for cmd_args in [&["-L", "-n", "-v"][..], &["-t", "nat", "-L", "-n", "-v"][..]] {
             match run_command("iptables", cmd_args) {
                 Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    ruleset_buffer.push_str(&format!("--- iptables {}
", cmd_args.join(" ")));
                    ruleset_buffer.push_str(&stdout);
                    ruleset_buffer.push_str("\n");
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let err_msg = format!("iptables {} failed with status {}: stderr: {}",
                                             cmd_args.join(" "), output.status, stderr);
                        error!("{}", err_msg);
                        result.findings.push(err_msg.clone());
                        iptables_failed = true;
                    }
                 }
                 Err(e) => {
                     let err_msg = format!("Failed to execute iptables {}: {}", cmd_args.join(" "), e);
                     error!("{}", err_msg);
                     result.findings.push(err_msg.clone());
                     iptables_failed = true;
                 }
             }
        }
        if let Ok(_path6) = which::which("ip6tables") {
             for cmd_args in [&["-L", "-n", "-v"][..], &["-t", "nat", "-L", "-n", "-v"][..]] {
                 match run_command("ip6tables", cmd_args) {
                     Ok(output) => {
                         let stdout = String::from_utf8_lossy(&output.stdout);
                         ruleset_buffer.push_str(&format!("--- ip6tables {}
", cmd_args.join(" ")));
                         ruleset_buffer.push_str(&stdout);
                         ruleset_buffer.push_str("\n");
                        if !output.status.success() {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            let err_msg = format!("ip6tables {} failed with status {}: stderr: {}",
                                                 cmd_args.join(" "), output.status, stderr);
                            error!("{}", err_msg);
                             result.findings.push(err_msg.clone());
                            iptables_failed = true;
                        }
                     }
                     Err(e) => {
                         let err_msg = format!("Failed to execute ip6tables {}: {}", cmd_args.join(" "), e);
                         error!("{}", err_msg);
                         result.findings.push(err_msg.clone());
                         iptables_failed = true;
                     }
                 }
            }
        } else {
             debug!("ip6tables command not found, skipping IPv6 rules check.");
             ruleset_buffer.push_str("--- ip6tables (command not found) ---\n");
        }

        if !iptables_failed {
             info!("Successfully listed iptables/ip6tables rules.");
             debug!("iptables/ip6tables rules:\n{}", result.ruleset_output.as_ref().unwrap());
        } else {
             warn!("Errors encountered while listing iptables/ip6tables rules.");
             debug!("iptables/ip6tables rules (including errors):\n{}", result.ruleset_output.as_ref().unwrap());
        }
    }

    if !command_found {
        let msg = "Neither 'nft' nor 'iptables' command found in PATH. Cannot check firewall rules.".to_string();
        warn!("{}", msg);
        result.findings.push(msg);
        result.ruleset_output = None;
    }

    // Limit stored ruleset size for memory reasons
    if let Some(ref mut output) = result.ruleset_output {
        if output.len() > 16384 { // Limit to 16KB
            warn!("Firewall ruleset output truncated ({} bytes).", output.len());
            output.truncate(16384);
            output.push_str("\n... (truncated)");
        }
    }

    result
}