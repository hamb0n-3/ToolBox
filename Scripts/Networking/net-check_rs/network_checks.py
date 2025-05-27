#!/usr/bin/env python3

"""
Network Check Functions for Network Defense Monitor

Contains functions to verify network interface status, IP configuration,
external IP, and DNS settings.
"""

import logging
import re
import socket
from enum import Enum, auto
from ipaddress import ip_address, ip_network, AddressValueError, NetworkValueError, IPv4Address, IPv6Address
from typing import List, Optional, Tuple, Set

import psutil
import requests

# Import Config from main script (adjust path if necessary)
# This assumes network_checks.py is in the same directory as net_defense_monitor.py
from net_defense_monitor import Config

# --- Result Enums (Matching Rust Enums) ---

class IpNetworkMatchStatus(Enum):
    NOT_CHECKED = auto()        # No expected network was specified.
    MATCH = auto()              # Found an IP matching the expected network.
    MISMATCH = auto()           # Found IPs, but none matched the expected network.
    NO_IPS = auto()             # Expected a network, but the interface had no IPs.
    INTERFACE_HAS_NO_IPS = auto() # No expected network, and interface has no IPs (warning).

class ExternalIpStatus(Enum):
    DISABLED = auto()             # Check was not enabled.
    CHECK_FAILED = auto()         # The check itself failed (e.g., network error).
    CHECKED_OK = auto()           # Check successful, no expected IPs configured.
    EXPECTED_MATCH = auto()       # Reported IP matches one of the expected IPs.
    EXPECTED_MISMATCH = auto()    # Reported IP does not match expected IPs.

class DnsMatchStatus(Enum):
    NOT_CHECKED = auto()        # No expected DNS servers were specified.
    READ_ERROR = auto()         # Failed to read or parse resolv.conf
    MATCH = auto()              # Found servers exactly match expected servers.
    MISMATCH = auto()           # Found servers do not match expected servers.
    NO_SERVERS_FOUND = auto()   # resolv.conf parsed, but no nameserver lines found.

# --- Result Dataclasses ---
# Re-define here for clarity, matching main script structure but adding details

@dataclass
class InterfaceCheckResult:
    interface_name: str
    interface_found: bool = False
    is_up: Optional[bool] = None
    is_running: Optional[bool] = None # psutil doesn't directly map to "is_running", use is_up for now
    is_loopback: Optional[bool] = None
    ip_addresses: List[ip_network] = field(default_factory=list)
    mac_address: Optional[str] = None
    ip_network_match_status: IpNetworkMatchStatus = IpNetworkMatchStatus.NOT_CHECKED
    expected_ip_network: Optional[ip_network] = None # Store what was expected
    external_ip_status: ExternalIpStatus = ExternalIpStatus.DISABLED
    reported_external_ip: Optional[IPv4Address | IPv6Address] = None
    expected_external_ips: Optional[List[IPv4Address | IPv6Address]] = None
    findings: List[str] = field(default_factory=list)

@dataclass
class DnsCheckResult:
    servers_expected: List[IPv4Address | IPv6Address] = field(default_factory=list)
    servers_found: List[IPv4Address | IPv6Address] = field(default_factory=list)
    match_status: DnsMatchStatus = DnsMatchStatus.NOT_CHECKED
    resolv_conf_path: str = "/etc/resolv.conf"
    findings: List[str] = field(default_factory=list)

# --- Helper Functions ---

def _get_interface_stats(if_name: str) -> Optional[psutil._common.snicstats]:
    """Gets status flags for a given interface name using psutil."""
    try:
        stats = psutil.net_if_stats()
        return stats.get(if_name)
    except Exception as e:
        logging.error(f"Error getting interface stats for {if_name}: {e}")
        return None

def _get_interface_addrs(if_name: str) -> Tuple[List[ip_network], Optional[str]]:
    """Gets IP addresses and MAC address for a given interface name using psutil."""
    ips = []
    mac = None
    try:
        addrs = psutil.net_if_addrs()
        if if_name in addrs:
            for snicaddr in addrs[if_name]:
                if snicaddr.family == psutil.AF_LINK:
                    mac = snicaddr.address
                elif snicaddr.family in (socket.AF_INET, socket.AF_INET6):
                    try:
                        # Construct ip_network, requires netmask
                        if snicaddr.netmask:
                            ip_str = f"{snicaddr.address}/{snicaddr.netmask}"
                            ips.append(ip_network(ip_str, strict=False))
                        else:
                            # Handle cases without netmask (e.g., point-to-point)
                            ips.append(ip_network(snicaddr.address, strict=False))
                            logging.debug(f"Interface {if_name} address {snicaddr.address} has no netmask.")
                    except (AddressValueError, NetworkValueError, TypeError) as e:
                        logging.warning(f"Could not parse IP/Network {snicaddr.address}/{snicaddr.netmask} for {if_name}: {e}")
    except Exception as e:
        logging.error(f"Error getting interface addresses for {if_name}: {e}")

    return ips, mac

def _perform_external_ip_check(config: Config) -> Tuple[ExternalIpStatus, Optional[IPv4Address | IPv6Address], Optional[str]]:
    """Performs the external IP check using the configured URL."""
    url = config.external_ip_check_url or "https://ifconfig.me/ip"
    logging.debug(f"Querying external IP check service: {url}")
    finding = None
    reported_ip = None

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        # Try parsing as plain text first
        ip_str = response.text.strip()
        try:
            reported_ip = ip_address(ip_str)
        except ValueError:
            # If plain text fails, try common JSON format {"ip": "..."}
            try:
                json_response = response.json()
                if isinstance(json_response, dict) and 'ip' in json_response:
                     ip_str = json_response['ip'].strip()
                     reported_ip = ip_address(ip_str)
                else:
                     raise ValueError("JSON response lacks 'ip' key")
            except (requests.exceptions.JSONDecodeError, ValueError) as json_e:
                finding = f"Failed to parse response from {url} as IP or JSON: {json_e}. Content: '{response.text[:100]}...'"
                logging.error(finding)
                return ExternalIpStatus.CHECK_FAILED, None, finding

        # Successfully parsed IP
        logging.info(f"External IP check service reported IP: {reported_ip}")
        expected_ips = config.expected_external_ips or []

        if not expected_ips:
            return ExternalIpStatus.CHECKED_OK, reported_ip, None
        elif reported_ip in expected_ips:
            logging.info("Reported external IP matches one of the expected IPs.")
            return ExternalIpStatus.EXPECTED_MATCH, reported_ip, None
        else:
            finding = f"Reported external IP {reported_ip} does NOT match any expected IPs: {expected_ips}"
            logging.error(finding)
            return ExternalIpStatus.EXPECTED_MISMATCH, reported_ip, finding

    except requests.exceptions.RequestException as e:
        finding = f"External IP check to {url} failed: {e}"
        logging.error(finding)
        return ExternalIpStatus.CHECK_FAILED, None, finding
    except Exception as e:
        finding = f"Unexpected error during external IP check: {e}"
        logging.error(finding, exc_info=True)
        return ExternalIpStatus.CHECK_FAILED, None, finding

# --- Main Check Functions ---

def verify_network_interfaces(config: Config) -> InterfaceCheckResult:
    """Verifies network interfaces using psutil.

    Checks the VPN interface status and IP configuration.
    Optionally performs an external IP check.
    Collects findings instead of raising exceptions.
    """
    if_name = config.vpn_interface_name
    logging.info(f"Verifying network interface: {if_name}...")

    result = InterfaceCheckResult(interface_name=if_name,
                                expected_ip_network=config.expected_vpn_ip_network,
                                expected_external_ips=config.expected_external_ips)

    stats = _get_interface_stats(if_name)
    ips, mac = _get_interface_addrs(if_name)

    if stats is not None:
        result.interface_found = True
        result.is_up = stats.isup
        # psutil doesn't have a direct 'is_running' like Rust's pnet.
        # isup is the closest, indicating if admin enabled and link detected (usually).
        # We can use is_up for the 'running' check logic from Rust.
        result.is_running = stats.isup
        # Check flags attribute for loopback (requires psutil >= 5.8.0 maybe? check docs)
        # result.is_loopback = 'LOOPBACK' in stats.flags # Example, check actual flags
        # psutil doesn't easily expose point-to-point or loopback flags directly in stats.
        # We might need more specific checks if those flags are critical.
        result.mac_address = mac
        result.ip_addresses = ips

        logging.info(f"Found interface: {if_name}")
        logging.debug(f"Interface stats: {stats}")
        logging.debug(f"Interface IPs: {ips}")
        logging.debug(f"Interface MAC: {mac}")

        if not result.is_up:
            finding = f"Interface {if_name} is down."
            result.findings.append(finding)
            logging.error(finding)
            # If down, skip IP and external checks
            result.ip_network_match_status = IpNetworkMatchStatus.NOT_CHECKED # Or a new status? InterfaceDown?
            result.external_ip_status = ExternalIpStatus.DISABLED # Or InterfaceDown?
            return result
        else:
            logging.info(f"Interface {if_name} is up.")
            # Check IP network matching
            expected_network = config.expected_vpn_ip_network
            if expected_network:
                found_match = False
                if not ips:
                    finding = f"Interface {if_name} has no IP addresses, but expected network {expected_network} was configured."
                    result.findings.append(finding)
                    logging.error(finding)
                    result.ip_network_match_status = IpNetworkMatchStatus.NO_IPS
                else:
                    for ip_net in ips:
                        # Check if the interface IP (ip_net.ip) is within the expected network
                        if ip_net.ip in expected_network:
                            logging.info(f"Found expected IP {ip_net.ip} (in {ip_net}) within network {expected_network} on interface {if_name}.")
                            found_match = True
                            break
                    if found_match:
                        result.ip_network_match_status = IpNetworkMatchStatus.MATCH
                    else:
                        finding = f"No IP address on interface {if_name} belongs to the expected network {expected_network}. Found IPs: {ips}"
                        result.findings.append(finding)
                        logging.error(finding)
                        result.ip_network_match_status = IpNetworkMatchStatus.MISMATCH
            else:
                # No expected network, just check if any IP exists
                if not ips:
                    finding = f"Warning: Interface {if_name} has no assigned IP addresses. (No expected network was configured)."
                    result.findings.append(finding)
                    logging.warning(finding)
                    result.ip_network_match_status = IpNetworkMatchStatus.INTERFACE_HAS_NO_IPS
                else:
                    logging.info(f"IP addresses found for {if_name}: {ips}. (No specific network expected).")
                    result.ip_network_match_status = IpNetworkMatchStatus.NOT_CHECKED

            # Perform external IP check if enabled
            if config.check_external_ip:
                logging.info("--- Performing External IP Check ---")
                logging.warning("OPSEC WARNING: External IP check enabled. This sends traffic outside the VPN potentially, revealing real IP if VPN fails.")
                status, reported_ip, finding = _perform_external_ip_check(config)
                result.external_ip_status = status
                result.reported_external_ip = reported_ip
                if finding:
                    result.findings.append(finding)
            else:
                logging.info("--- Skipping External IP Check (disabled) ---")
                result.external_ip_status = ExternalIpStatus.DISABLED

    else:
        finding = f"Configured interface {if_name} not found or failed to get stats."
        result.findings.append(finding)
        logging.error(finding)
        result.interface_found = False

    return result

def verify_dns(config: Config) -> DnsCheckResult:
    """Verifies DNS configuration by reading /etc/resolv.conf.

    Compares found nameservers against the expected list in the config.
    """
    logging.info("Verifying DNS configuration...")
    resolv_conf_path = "/etc/resolv.conf"
    expected_servers = config.expected_dns_servers or []

    result = DnsCheckResult(servers_expected=expected_servers,
                              resolv_conf_path=resolv_conf_path)

    if not expected_servers:
        logging.warning("No expected DNS servers configured. Skipping DNS check.")
        result.match_status = DnsMatchStatus.NOT_CHECKED
        return result

    logging.debug(f"Reading DNS configuration from {resolv_conf_path}")
    logging.debug(f"Expected DNS servers: {expected_servers}")

    found_servers_set: Set[IPv4Address | IPv6Address] = set()
    try:
        with open(resolv_conf_path, 'r') as f:
            # Regex to find lines starting with "nameserver" followed by an IP address.
            # Allows for potential comments after the IP
            nameserver_re = re.compile(r"^\s*nameserver\s+([^\s#]+)")
            for line_num, line in enumerate(f):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                match = nameserver_re.match(line)
                if match:
                    server_str = match.group(1)
                    try:
                        ip = ip_address(server_str)
                        found_servers_set.add(ip)
                    except ValueError as e:
                        finding = f"Warning: Failed to parse potential nameserver IP '{server_str}' from {resolv_conf_path} (line {line_num+1}): {e}. Skipping."
                        result.findings.append(finding)
                        logging.warning(finding)

    except FileNotFoundError:
        finding = f"DNS configuration file not found: {resolv_conf_path}"
        result.findings.append(finding)
        logging.error(finding)
        result.match_status = DnsMatchStatus.READ_ERROR
        return result
    except IOError as e:
        finding = f"Failed to read {resolv_conf_path}: {e}"
        result.findings.append(finding)
        logging.error(finding)
        result.match_status = DnsMatchStatus.READ_ERROR
        return result
    except Exception as e:
        finding = f"Unexpected error reading or parsing {resolv_conf_path}: {e}"
        result.findings.append(finding)
        logging.error(finding, exc_info=True)
        result.match_status = DnsMatchStatus.READ_ERROR
        return result

    result.servers_found = sorted(list(found_servers_set)) # Store sorted list

    if not found_servers_set:
        finding = f"No valid 'nameserver' entries found in {resolv_conf_path}"
        result.findings.append(finding)
        logging.error(finding)
        result.match_status = DnsMatchStatus.NO_SERVERS_FOUND
        return result

    logging.info(f"DNS servers found in {resolv_conf_path}: {result.servers_found}")

    # Compare found set with expected set (order-insensitive)
    expected_servers_set = set(expected_servers)

    if found_servers_set == expected_servers_set:
        logging.info("Actual DNS servers match expected configuration.")
        result.match_status = DnsMatchStatus.MATCH
    else:
        missing = sorted(list(expected_servers_set - found_servers_set))
        unexpected = sorted(list(found_servers_set - expected_servers_set))
        error_msg = "DNS server configuration mismatch."
        if missing:
            error_msg += f" Missing expected servers: {missing}."
        if unexpected:
            error_msg += f" Found unexpected servers: {unexpected}."

        result.findings.append(error_msg)
        logging.error(error_msg)
        result.match_status = DnsMatchStatus.MISMATCH

    return result 