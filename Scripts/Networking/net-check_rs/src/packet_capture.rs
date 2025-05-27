// Note: This module requires the program to be run with sufficient privileges (e.g., root)
// to perform packet capture.

use crate::config::Config;
use ipnetwork::IpNetwork;
use log::{info, warn, error, debug};
use pcap::{Device, Packet/*, Capture, PacketHeader, Active*/}; // Removed unused Capture, PacketHeader, Active
use pnet::packet::Packet as PnetPacketTrait;
use pnet::packet::{
    ethernet::{EthernetPacket, EtherTypes},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    arp::ArpPacket,
};
use std::net::IpAddr;
use std::sync::{
    mpsc, // For sending results back from threads
    Arc, // For sharing the shutdown signal
    atomic::{AtomicBool, Ordering},
};
use std::thread;
//use std::time::Duration; // Removed unused Duration
use std::str::FromStr;
use std::time::SystemTime; // For leak timestamps

/// Represents details of a detected potential leak event.
#[derive(Debug, Clone)]
pub struct LeakEvent {
    pub timestamp: SystemTime,
    pub interface_name: String,
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub protocol: String,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub packet_len: u32,
}

/// Holds the results from the traffic monitoring phase.
#[derive(Debug, Clone, Default)]
pub struct TrafficMonitorResult {
    pub detected_leaks: Vec<LeakEvent>,
    pub total_packets_processed_filtered: u64, // Count of packets that *passed* the BPF filter
    // TODO: Add more stats like per-protocol counts, byte counts etc.
    pub findings: Vec<String>, // Errors during setup or capture
}

/// Sets up and runs packet capture on specified physical interfaces to detect potential leaks.
/// Returns a `TrafficMonitorResult` containing detected leaks and basic stats.
///
/// # Arguments
/// * `config` - The application configuration.
/// * `shutdown_signal` - An `Arc<AtomicBool>` shared with the main thread.
/// # Returns
/// A `TrafficMonitorResult` struct.
pub fn monitor_traffic(config: &Config, shutdown_signal: Arc<AtomicBool>) -> TrafficMonitorResult {
    info!("Initializing traffic monitoring for potential leaks...");
    let mut result = TrafficMonitorResult::default();

    let interfaces_to_monitor = match &config.physical_interface_names {
        Some(names) if !names.is_empty() => names.clone(),
        _ => {
            info!("No physical interfaces specified. Skipping traffic monitoring.");
            return result; // Return default empty result
        }
    };

    // --- Prepare for Capture --- //
    let all_devices = match Device::list() {
        Ok(devs) => devs,
        Err(e) => {
            let finding = format!("Failed to list network devices: {}", e);
            error!("{}", finding);
            result.findings.push(finding);
            return result;
        }
    };

    let mut devices_to_capture = Vec::new();
    let mut local_ips_set = std::collections::HashSet::new();

    for iface in pnet::datalink::interfaces() {
        if !iface.is_loopback() && iface.name != config.vpn_interface_name {
            for ipnet in &iface.ips {
                local_ips_set.insert(ipnet.ip());
            }
        }
    }
    let local_ips: Vec<IpAddr> = local_ips_set.into_iter().collect();
    if local_ips.is_empty() {
        let finding = "Warning: Could not determine any local IP addresses (excluding loopback/VPN). Leak detection accuracy reduced.".to_string();
        warn!("{}", finding);
        result.findings.push(finding);
    }
    debug!("Using local IPs for outbound check: {:?}", local_ips);

    for name in &interfaces_to_monitor {
        match all_devices.iter().find(|d| &d.name == name) {
            Some(device) => devices_to_capture.push(device.clone()),
            None => {
                let finding = format!("Configured physical interface '{}' not found.", name);
                error!("{}", finding);
                result.findings.push(finding);
                // Don't return immediately, try to monitor other configured interfaces
            }
        }
    }

    if devices_to_capture.is_empty() {
        info!("No valid physical interfaces found to monitor. Skipping traffic monitoring.");
        result.findings.push("No valid physical interfaces found to monitor.".to_string());
        return result;
    }

    // --- Generate BPF Filter --- //
    let bpf_filter = match generate_bpf_filter(config, &local_ips) {
        Ok(filter) => filter,
        Err(e) => {
             let finding = format!("Failed to generate BPF filter: {}", e);
             error!("{}", finding);
             result.findings.push(finding);
             return result; // Cannot proceed without a filter
        }
    };
    info!("Using generated BPF filter: {}", bpf_filter);

    // --- Spawn Capture Threads --- //
    // Channel to send back results (Leaks or Errors)
    enum CaptureThreadResult {
        Leak(LeakEvent),
        Error(String),
        PacketProcessed, // Signal a processed packet for counting
    }
    let (tx, rx) = mpsc::channel::<CaptureThreadResult>();
    let mut capture_handles = Vec::new();

    for device in devices_to_capture {
        info!("Starting packet capture task on interface: {}", device.name);
        let tx_clone = tx.clone();
        let shutdown_clone = Arc::clone(&shutdown_signal);
        let device_name = device.name.clone();
        let filter_clone = bpf_filter.clone();

        let handle = thread::spawn(move || {
            capture_packets_on_device(device, tx_clone, shutdown_clone, &filter_clone);
            // Log when thread exits
            info!("Packet capture task on {} is finishing.", device_name);
        });
        capture_handles.push(handle);
    }

    drop(tx); // Drop original sender

    // --- Main thread: Process results and wait for shutdown --- //
    info!("Waiting for potential leak reports or shutdown signal...");

    // Loop while receiver is not disconnected (i.e., threads are running)
    while let Ok(thread_result) = rx.recv() {
        match thread_result {
            CaptureThreadResult::Leak(leak_info) => {
                error!(
                    "LEAK DETECTED! Iface: {}, Proto: {}, Src: {}:{}, Dst: {}:{}, Len: {}",
                    leak_info.interface_name,
                    leak_info.protocol,
                    leak_info.source_ip,
                    leak_info.source_port.map_or_else(|| "N/A".to_string(), |p| p.to_string()),
                    leak_info.dest_ip,
                    leak_info.dest_port.map_or_else(|| "N/A".to_string(), |p| p.to_string()),
                    leak_info.packet_len
                );
                result.detected_leaks.push(leak_info);
                result.total_packets_processed_filtered += 1; // Count leak as processed packet
            }
            CaptureThreadResult::Error(e) => {
                error!("Capture thread error reported: {}", e);
                result.findings.push(e);
            }
             CaptureThreadResult::PacketProcessed => {
                result.total_packets_processed_filtered += 1;
                 // Optional: Log progress periodically
                 // if result.total_packets_processed_filtered % 100 == 0 {
                 //     debug!("Processed {} packets matching filter...", result.total_packets_processed_filtered);
                 // }
            }
        }
        // Check if shutdown was signaled externally even if channel is open
        if shutdown_signal.load(Ordering::Relaxed) {
             info!("Shutdown signal received while processing results, stopping.");
             break;
        }
    }
    // Loop finished because channel closed (all threads stopped sending) or break called.

    // --- Cleanup --- //
    info!("All capture threads have stopped sending. Waiting for threads to join...");
    // Ensure shutdown signal is set for any lingering threads
    shutdown_signal.store(true, Ordering::Relaxed);

    for handle in capture_handles {
        if let Err(e) = handle.join() {
            let finding = format!("Error joining capture thread: {:?}", e);
            error!("{}", finding);
             result.findings.push(finding);
        }
    }

    info!("All capture threads joined.");

    if !result.detected_leaks.is_empty() {
        warn!("Detected {} potential leak(s) during monitoring.", result.detected_leaks.len());
    } else {
        info!("Traffic monitoring finished with no leaks detected by the filter.");
    }
     info!("Total packets processed (matching filter): {}", result.total_packets_processed_filtered);

    result
}

/// Helper function to add BPF filter conditions for a list of items.
fn add_formatted_conditions<T, F>(
    conditions_vec: &mut Vec<String>,
    items: &Option<Vec<T>>,
    prefix: &str,
    formatter: F,
) where
    T: Clone,
    F: Fn(T) -> String,
{
    if let Some(list) = items {
        for item in list {
            conditions_vec.push(format!("{} {}", prefix, formatter(item.clone())));
        }
    }
}

/// Generates a BPF filter string to capture potential leaks.
/// Aims to capture outbound IP traffic NOT destined for allowed local/VPN destinations.
fn generate_bpf_filter(config: &Config, local_ips: &[IpAddr]) -> Result<String, String> {
    let mut conditions = vec!["(ip or ip6)".to_string()]; // Start with IP traffic

    // --- Source IP conditions (Outbound Check) --- //
    if !local_ips.is_empty() {
        let src_hosts: Vec<String> = local_ips.iter().map(|ip| format!("src host {}", ip)).collect();
        conditions.push(format!("({})", src_hosts.join(" or ")));
    } else {
        // If we don't know local IPs, we can't reliably filter for outbound here.
        // The filter will catch more, and we'd have to re-check source in Rust.
        // Or, we could filter based on `outbound` direction if supported, but that's less portable.
        warn!("Cannot add source IP filter condition; local IPs unknown.");
    }

    // --- Destination IP Exclusions (Allowed Traffic) --- //
    let mut not_dst_conditions = Vec::new();

    // Exclude standard non-leak destinations
    not_dst_conditions.push("dst net 127.0.0.0/8".to_string()); // Loopback v4
    not_dst_conditions.push("dst host ::1".to_string());       // Loopback v6
    not_dst_conditions.push("dst net fe80::/10".to_string());   // Link-local v6
    not_dst_conditions.push("dst net ff00::/8".to_string());   // Multicast v6
    not_dst_conditions.push("dst net 224.0.0.0/4".to_string()); // Multicast v4
    not_dst_conditions.push("dst host 255.255.255.255".to_string()); // Broadcast v4

    // Exclude configured local subnets (or defaults)
    let local_subnets_to_exclude = config.local_subnets.clone().unwrap_or_else(|| {
        info!("No local_subnets configured, using default RFC1918/LinkLocal exclusions.");
        vec![
            IpNetwork::from_str("10.0.0.0/8").unwrap(),
            IpNetwork::from_str("172.16.0.0/12").unwrap(),
            IpNetwork::from_str("192.168.0.0/16").unwrap(),
            IpNetwork::from_str("169.254.0.0/16").unwrap(), // Link-local v4
            // Add ULA fc00::/7 for IPv6? Standard library doesn't parse it easily.
            // IpNetwork::from_str("fc00::/7").unwrap(),
        ]
    });

    for subnet in local_subnets_to_exclude {
        not_dst_conditions.push(format!("dst net {}", subnet));
    }

    // Exclude configured VPN server IPs
    add_formatted_conditions(
        &mut not_dst_conditions,
        &config.vpn_server_ips,
        "dst host",
        |ip| ip.to_string()
    );

    // Exclude specifically allowed leak destination IPs
    add_formatted_conditions(
        &mut not_dst_conditions,
        &config.allowed_leak_destination_ips,
        "dst host",
        |ip| ip.to_string()
    );

    // Exclude specifically allowed leak destination ports (TCP or UDP)
    if let Some(allowed_ports) = &config.allowed_leak_destination_ports {
        for port in allowed_ports {
            // Add condition for both TCP and UDP for the port
            not_dst_conditions.push(format!("(tcp dst port {})", port));
            not_dst_conditions.push(format!("(udp dst port {})", port));
        }
    }

    // Combine the exclusion conditions
    if !not_dst_conditions.is_empty() {
        conditions.push(format!("not ({})", not_dst_conditions.join(" or ")));
    }

    Ok(conditions.join(" and "))
}

/// Captures packets on a single device, applies filter, and sends results back.
fn capture_packets_on_device(
    device: Device,
    tx: mpsc::Sender<CaptureThreadResult>,
    shutdown_signal: Arc<AtomicBool>,
    bpf_filter: &str,
) {
    // Use a helper function to send errors and simplify logic
    let send_error = |tx: &mpsc::Sender<CaptureThreadResult>, msg: String| {
        error!("{}", msg); // Log error here too
        let _ = tx.send(CaptureThreadResult::Error(msg)); // Ignore error if channel closed
    };

    // --- Activate Capture Handle --- //
    let mut cap = match pcap::Capture::from_device(device.clone()) {
        Ok(c) => c,
        Err(e) => {
            send_error(&tx, format!("Failed to get capture device {}: {}", device.name, e));
            return;
        }
    };
    cap = cap.promisc(true)
        .snaplen(65535)
        .timeout(500) // ms timeout
        .immediate_mode(true);

    let mut active_cap = match cap.open() {
        Ok(ac) => ac,
        Err(e) => {
             send_error(&tx, format!("Failed to open capture handle on {}: {}", device.name, e));
            return;
        }
    };

    info!("Opened capture handle on {}. Applying filter...", device.name);

    // --- Apply BPF Filter --- //
    if let Err(e) = active_cap.filter(bpf_filter, true) {
        send_error(&tx, format!("Failed to apply BPF filter to {}: {}", device.name, e));
        return;
    }
    info!("Successfully applied BPF filter to {}", device.name);

    // --- Packet Processing Loop --- //
    info!("Starting packet processing loop on {}...", device.name);
    while !shutdown_signal.load(Ordering::Relaxed) {
        match active_cap.next_packet() {
            Ok(packet) => {
                // Let main thread know a packet passed the filter
                if tx.send(CaptureThreadResult::PacketProcessed).is_err() {
                     info!("Result channel closed on {}. Stopping capture.", device.name);
                     break;
                }

                // Process and potentially send LeakEvent
                match process_filtered_packet(&packet, &device.name) {
                    Some(leak_info) => {
                        debug!("Sending potential leak info: {:?}", leak_info);
                        if tx.send(CaptureThreadResult::Leak(leak_info)).is_err() {
                            info!("Leak channel closed on {}. Stopping capture.", device.name);
                            break;
                        }
                    }
                    None => { /* Packet filtered but failed parsing (e.g., not IP) */ }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                continue;
            }
            Err(pcap::Error::NoMorePackets) => {
                 info!("Capture source reported no more packets on {}. Stopping.", device.name);
                 break;
            }
            Err(e) => {
                // Send error back to main thread, then stop this thread's loop
                send_error(&tx, format!("Error capturing packet on {}: {}. Stopping loop.", device.name, e));
                break;
            }
        }
    }

    // No explicit Ok(()) needed as function has no return value
    // Log handled by caller thread::spawn
}

/// Analyzes a single captured packet *that has already passed the BPF filter*.
/// Parses IP/TCP/UDP headers to extract details for the leak report.
fn process_filtered_packet(packet: &Packet, if_name: &str) -> Option<LeakEvent> {
    let timestamp = SystemTime::now();
    let ethernet_packet = EthernetPacket::new(packet.data)?;

    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(ethernet_packet.payload())?;
            let src_ip = IpAddr::V4(ipv4.get_source());
            let dst_ip = IpAddr::V4(ipv4.get_destination());
            let (proto_name, src_port, dst_port) = match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                     let tcp = TcpPacket::new(ipv4.payload());
                     ("TCP".to_string(), tcp.map(|p| p.get_source()), tcp.map(|p| p.get_destination()))
                 },
                 IpNextHeaderProtocols::Udp => {
                     let udp = UdpPacket::new(ipv4.payload());
                     ("UDP".to_string(), udp.map(|p| p.get_source()), udp.map(|p| p.get_destination()))
                 },
                p => (format!("{:?}", p), None, None),
            };
            Some(LeakEvent {
                timestamp,
                interface_name: if_name.to_string(),
                source_ip: src_ip,
                dest_ip: dst_ip,
                protocol: proto_name,
                source_port,
                dest_port,
                packet_len: packet.header.len,
            })
        }
        EtherTypes::Ipv6 => {
            let ipv6 = Ipv6Packet::new(ethernet_packet.payload())?;
            let src_ip = IpAddr::V6(ipv6.get_source());
            let dst_ip = IpAddr::V6(ipv6.get_destination());
            let (proto_name, src_port, dst_port) = match ipv6.get_next_header() {
                 IpNextHeaderProtocols::Tcp => {
                     let tcp = TcpPacket::new(ipv6.payload());
                     ("TCP".to_string(), tcp.map(|p| p.get_source()), tcp.map(|p| p.get_destination()))
                 },
                 IpNextHeaderProtocols::Udp => {
                     let udp = UdpPacket::new(ipv6.payload());
                     ("UDP".to_string(), udp.map(|p| p.get_source()), udp.map(|p| p.get_destination()))
                 },
                 p => (format!("{:?}", p), None, None),
            };
            Some(LeakEvent {
                timestamp,
                interface_name: if_name.to_string(),
                source_ip: src_ip,
                dest_ip: dst_ip,
                protocol: proto_name,
                source_port,
                dest_port,
                packet_len: packet.header.len,
            })
        }
        EtherTypes::Arp => {
            // ARP packets might be relevant for local network reconnaissance, log as info/debug
            if let Some(arp) = ArpPacket::new(ethernet_packet.payload()) {
                debug!("ARP packet seen on {}: {:?}", if_name, arp);
            } else {
                 debug!("Malformed ARP/Unknown L3 packet on {} (EtherType: {:?})", if_name, ethernet_packet.get_ethertype());
            }
            None // Not considered an IP leak
        }
        _ => {
             debug!("Unknown L3 packet on {} (EtherType: {:?})", if_name, ethernet_packet.get_ethertype());
             None
         }
    }
} 