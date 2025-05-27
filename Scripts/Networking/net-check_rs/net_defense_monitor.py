#!/usr/bin/env python3

"""
Network Defense Monitor (Python Port)

This script monitors network configuration, host status, and network traffic
to verify system security posture, particularly when using a VPN.
It performs various checks and calculates a confidence score.

Requires elevated privileges (root) for packet capture and some host checks.
"""

import logging
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from pathlib import Path
from typing import List, Optional, Dict, Tuple, Any

# --- Configuration ---
# Mimics the hardcoded Rust configuration

@dataclass
class Config:
    # Network Checks related
    vpn_interface_name: str = "tun0"
    expected_vpn_ip_network: Optional[ip_network] = None
    expected_dns_servers: Optional[List[IPv4Address | IPv6Address]] = field(default_factory=lambda: [
        ip_address("9.9.9.9"),
        ip_address("149.112.112.112"),
        ip_address("2620:fe::fe"),
        ip_address("2620:fe::9"),
    ])
    physical_interface_names: Optional[List[str]] = None # Auto-detect if None in packet capture
    vpn_server_ips: Optional[List[IPv4Address | IPv6Address]] = None
    local_subnets: Optional[List[ip_network]] = field(default_factory=lambda: [
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("fe80::/10"),
        ip_network("fc00::/7"),
        ip_network("169.254.0.0/16"), # Added link-local v4 explicitly
    ])
    check_firewall_rules: bool = True
    check_external_ip: bool = False # Disabled by default for opsec
    external_ip_check_url: Optional[str] = None # Default "https://ifconfig.me/ip" will be used if check_external_ip=True
    expected_external_ips: Optional[List[IPv4Address | IPv6Address]] = None
    allowed_leak_destination_ips: Optional[List[IPv4Address | IPv6Address]] = None
    allowed_leak_destination_ports: Optional[List[int]] = None

    # Host Audit related
    allowed_listening_tcp_ports: Optional[List[int]] = field(default_factory=lambda: [22]) # SSH
    allowed_listening_udp_ports: Optional[List[int]] = field(default_factory=lambda: [68]) # DHCP client
    watched_files_for_modification: Optional[List[Path]] = field(default_factory=lambda: [
        Path("/etc/passwd"),
        Path("/etc/shadow"),
        Path("/etc/group"),
        Path("/etc/gshadow"),
        Path("/etc/sudoers"),
        Path("/etc/hosts"),
        Path("/etc/resolv.conf"),
    ])
    allowed_login_users: Optional[List[str]] = None
    allowed_login_hosts: Optional[List[str]] = None
    required_kernel_modules: Optional[List[str]] = None
    disallowed_kernel_modules: Optional[List[str]] = field(default_factory=lambda: [
        "dummy",
        "floppy",
    ])
    enforce_required_modules_only: bool = False
    disallowed_process_names: Optional[List[str]] = field(default_factory=lambda: [
        "nc",
        "netcat",
        "ncat",
        "socat",
        "mimikatz",
        "meterpreter",
    ])
    disallowed_systemd_services: Optional[List[str]] = None
    disallowed_systemd_timers: Optional[List[str]] = None
    disallowed_hosts_entries: Optional[List[str]] = None # Hostnames disallowed from being mapped to non-localhost IPs
    disallowed_env_vars: Optional[List[str]] = field(default_factory=lambda: [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
    ])

# --- Placeholder Result Structures ---
# These will be defined properly in their respective modules later

@dataclass
class InterfaceCheckResult:
    findings: List[str] = field(default_factory=list)
    # Add other fields from Rust version as needed
    interface_found: bool = False
    is_up: Optional[bool] = None
    is_running: Optional[bool] = None
    ip_network_match_status: Any = None # Replace Any with Enum later
    external_ip_status: Any = None # Replace Any with Enum later

@dataclass
class DnsCheckResult:
    findings: List[str] = field(default_factory=list)
    match_status: Any = None # Replace Any with Enum later

@dataclass
class HostAuditResult:
    all_findings: List[str] = field(default_factory=list)
    # Add sub-results (PortCheckResult, ProcessCheckResult etc.) as fields
    port_check: Any = None
    process_check: Any = None
    login_check: Any = None
    file_check: Any = None
    module_check: Any = None
    systemd_check: Any = None
    firewall_check: Any = None

@dataclass
class OpsecTestResult:
    all_findings: List[str] = field(default_factory=list)
    # Add sub-results (HostsFileCheckResult, EnvVarCheckResult)

@dataclass
class TrafficMonitorResult:
    findings: List[str] = field(default_factory=list)
    detected_leaks: List[Any] = field(default_factory=list) # Replace Any with LeakEvent class later

@dataclass
class AllCheckResults:
    interface_check: Optional[InterfaceCheckResult] = None
    dns_check: Optional[DnsCheckResult] = None
    host_audit: Optional[HostAuditResult] = None
    opsec_tests: Optional[OpsecTestResult] = None
    traffic_monitor: Optional[TrafficMonitorResult] = None

    def calculate_confidence(self) -> Tuple[float, List[str]]:
        """Calculates the confidence score based on collected results.
        Ported from the Rust implementation's logic.
        """
        score = 100.0
        critical_findings = []

        # Placeholder - Implement the scoring logic from Rust here
        # based on the fields in the result objects.
        # Example (needs full implementation):
        if self.interface_check:
             if not self.interface_check.interface_found:
                 score -= 50.0
                 critical_findings.append(f"Major: VPN interface not found.") # Needs interface name later
             # ... add other penalties from Rust code ...
        else:
             score -= 10.0
             critical_findings.append("Warning: Interface check did not complete.")

        # ... add penalties for DNS, Host Audit, Opsec, Traffic Monitor ...

        # Ensure score doesn't go below 0
        score = max(0.0, score)
        # Ensure score doesn't exceed 100
        score = min(100.0, score)

        return score, critical_findings


# --- Placeholder Check Functions ---
# These will import actual implementations from other files later

def run_network_checks(config: Config) -> Tuple[Optional[InterfaceCheckResult], Optional[DnsCheckResult]]:
    logging.info("--- Running Network Checks ---")
    # TODO: Call actual implementations from network_checks.py
    # Example:
    # from network_checks import verify_network_interfaces, verify_dns
    # interface_result = verify_network_interfaces(config)
    # dns_result = verify_dns(config)
    # return interface_result, dns_result
    return InterfaceCheckResult(findings=["Network checks not implemented yet"]), DnsCheckResult(findings=["DNS checks not implemented yet"])

def run_host_audit(config: Config) -> Optional[HostAuditResult]:
    logging.info("--- Running Host Audit ---")
    # TODO: Call actual implementation from host_audit.py
    # from host_audit import audit_host
    # return audit_host(config)
    return HostAuditResult(all_findings=["Host audit not implemented yet"])

def run_opsec_tests(config: Config) -> Optional[OpsecTestResult]:
    logging.info("--- Running Opsec Tests ---")
    # TODO: Call actual implementation from opsec_tests.py
    # from opsec_tests import perform_opsec_tests
    # return perform_opsec_tests(config)
    return OpsecTestResult(all_findings=["Opsec tests not implemented yet"])

def run_traffic_monitoring(config: Config, shutdown_event: threading.Event) -> Optional[TrafficMonitorResult]:
    logging.info("--- Running Traffic Monitoring (if enabled) ---")
    # TODO: Call actual implementation from packet_capture.py
    # from packet_capture import monitor_traffic
    # return monitor_traffic(config, shutdown_event)

    # Check if physical interfaces are specified
    if not config.physical_interface_names:
         logging.info("No physical interfaces configured. Skipping traffic monitoring.")
         return None # Return None if monitoring is skipped

    # Placeholder simulation: Run for a short time or until shutdown
    start_time = time.time()
    monitor_duration = 10 # seconds, just for placeholder
    while not shutdown_event.is_set() and time.time() - start_time < monitor_duration:
        time.sleep(0.5)

    if shutdown_event.is_set():
        logging.info("Traffic monitoring placeholder interrupted by shutdown signal.")
    else:
        logging.info("Traffic monitoring placeholder finished.")

    # In the real implementation, this would block until capture threads finish
    # or the shutdown_event is set and threads are joined.
    return TrafficMonitorResult(findings=["Traffic monitoring not fully implemented yet"])


# --- Main Execution Logic ---

# Global shutdown event for signaling threads
shutdown_event = threading.Event()

def signal_handler(sig, frame):
    """Handles SIGINT (Ctrl+C) and SIGTERM signals."""
    logging.warning(f"Signal {sig} received, initiating graceful shutdown...")
    shutdown_event.set() # Signal all threads to stop

def setup_logging():
    """Configures basic logging."""
    logging.basicConfig(
        level=logging.INFO, # Default level
        format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    # TODO: Add option for more verbose logging (e.g., based on args)

def main():
    setup_logging()
    logging.info("Starting Network Defense Monitor (Python Port)...")

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Use default configuration
    config = Config()
    logging.info("Using built-in default configuration.")
    logging.debug(f"Config: {config}") # Log full config only in debug

    all_results = AllCheckResults()
    all_findings = []
    monitoring_thread = None

    try:
        # Run static checks first
        interface_result, dns_result = run_network_checks(config)
        all_results.interface_check = interface_result
        if interface_result: all_findings.extend(interface_result.findings)
        all_results.dns_check = dns_result
        if dns_result: all_findings.extend(dns_result.findings)

        host_audit_result = run_host_audit(config)
        all_results.host_audit = host_audit_result
        if host_audit_result: all_findings.extend(host_audit_result.all_findings)

        opsec_test_result = run_opsec_tests(config)
        all_results.opsec_tests = opsec_test_result
        if opsec_test_result: all_findings.extend(opsec_test_result.all_findings)

        # --- Optional: Continuous Traffic Monitoring ---
        # Check if monitoring should run (based on config)
        # In this version, it runs if physical_interface_names is set.
        if config.physical_interface_names:
            # Run monitoring in a separate thread so main thread can handle shutdown
            logging.info("Starting traffic monitoring thread...")
            monitor_args = (config, shutdown_event)
            monitoring_thread = threading.Thread(
                target=lambda cfg, evt, res: setattr(res, 'traffic_monitor', run_traffic_monitoring(cfg, evt)),
                args=monitor_args + (all_results,), # Pass results object to store output
                name="TrafficMonitorThread",
                daemon=True # Allows main thread to exit even if this is stuck (though we join)
            )
            monitoring_thread.start()

            # Keep main thread alive while monitoring runs, waiting for shutdown
            logging.info("Monitoring active. Press Ctrl+C to stop.")
            while monitoring_thread.is_alive():
                # Check frequently if shutdown signal was received externally
                if shutdown_event.is_set():
                     logging.info("Main thread detected shutdown signal.")
                     break
                # time.sleep(0.5) # Or use monitoring_thread.join(timeout=0.5)
                monitoring_thread.join(timeout=0.5) # Wait with timeout allows checking signal

            logging.info("Monitoring thread has finished or shutdown signal received.")
            # Ensure thread finishes if it wasn't already joined
            if monitoring_thread.is_alive():
                 monitoring_thread.join()
                 logging.info("Monitoring thread joined.")

            # Retrieve findings from the monitoring result (if the thread set it)
            if all_results.traffic_monitor:
                all_findings.extend(all_results.traffic_monitor.findings)
                # Log detected leaks summary
                if all_results.traffic_monitor.detected_leaks:
                     logging.error(f"!!! DETECTED {len(all_results.traffic_monitor.detected_leaks)} POTENTIAL LEAKS !!!")
                     # TODO: Print leak details
                else:
                     logging.info("Traffic monitoring completed with no leaks detected by the filter.")

        else:
            logging.info("Traffic monitoring skipped as per configuration.")

        # --- Calculate Confidence Score ---
        confidence, critical_findings = all_results.calculate_confidence()

        # --- Report Results ---
        logging.info("--- Final Results ---")
        # TODO: Print more detailed results from each check category
        logging.info(f"Total Findings Recorded: {len(all_findings)}")
        if critical_findings:
             logging.error("Critical Findings Summary:")
             for finding in critical_findings:
                 logging.error(f"  - {finding}")

        logging.info(f"Overall Confidence Score: {confidence:.2f}% ")

        if confidence < 70:
            logging.critical("Confidence score is low. System state is potentially insecure.")
            sys.exit(1) # Exit with error code if confidence is low
        elif confidence < 90:
            logging.warning("Confidence score is moderate. Review findings carefully.")
        else:
            logging.info("Confidence score is high. System state appears secure based on checks.")

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(2)
    except KeyboardInterrupt:
        logging.warning("KeyboardInterrupt received in main thread. Shutting down.")
        shutdown_event.set() # Ensure signal is set if Ctrl+C happened outside handler scope
        if monitoring_thread and monitoring_thread.is_alive():
             logging.info("Waiting for monitoring thread to stop...")
             monitoring_thread.join(timeout=5.0) # Give some time to stop gracefully
             if monitoring_thread.is_alive():
                  logging.error("Monitoring thread did not stop gracefully.")
        sys.exit(130) # Standard exit code for Ctrl+C

    finally:
        logging.info("Network Defense Monitor finished.")

if __name__ == "__main__":
    # Basic check for root privileges if monitoring is likely needed
    # Note: Some checks might work without root, but capture won't.
    # A more robust check would use `os.geteuid()` == 0
    # if config.physical_interface_names: # Check only if monitoring might run
    #     if os.geteuid() != 0:
    #         logging.warning("Traffic monitoring requires root privileges. Some checks might fail.")
            # Consider exiting or disabling monitoring if not root?

    main() 