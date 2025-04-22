#!/bin/bash

# ===========================================
# Quantum Scanner Comprehensive Test Script
# ===========================================
# This script performs a series of scans against scanme.nmap.org
# using different scan techniques and options to test scanner functionality.
# 
# NOTES:
# - This script requires root/sudo privileges to run raw socket operations
# - scanme.nmap.org is explicitly set up for testing scan tools
# - Running extensive scans against other hosts without permission may be illegal

echo "======================================================="
echo "  Quantum Scanner - Comprehensive Test Script           "
echo "======================================================="

# Set target to scan
TARGET="scanme.nmap.org"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
OUTPUT_DIR="scanme_results_${TIMESTAMP}"

# Create output directory
mkdir -p "$OUTPUT_DIR"
echo "Creating output directory: $OUTPUT_DIR"

# Function to run a scan and log details
run_scan() {
    local name="$1"
    local options="$2"
    local output_file="${OUTPUT_DIR}/${name}.json"
    local log_file="${OUTPUT_DIR}/${name}.log"
    local packet_log="${OUTPUT_DIR}/${name}_packets.json"
    
    echo "======================================================="
    echo "Running scan: $name"
    echo "Command: ./target/release/quantum_scanner $TARGET $options --json --output $output_file --packet-log-file $packet_log"
    echo "======================================================="
    
    # Run the scan
    sudo ./target/release/quantum_scanner $TARGET $options --json --output $output_file --packet-log-file $packet_log 2>&1 | tee "$log_file"
    
    echo "Completed scan: $name"
    echo "Results saved to: $output_file"
    echo "Log saved to: $log_file"
    echo "Packet log saved to: $packet_log"
    echo ""
}

# Run basic scan (SYN on top ports)
run_scan "basic_scan" "--top-100 --scan-types syn"

# Run enhanced scan (multiple techniques)
run_scan "enhanced_scan" "--top-100 --scan-types syn,null,fin,ack --enhanced-evasion"

# Run service scan (with banner grabbing and version detection)
run_scan "service_scan" "-p 20-30,80,443 --scan-types syn,ssl --verbose --grab-banners"

# Run SSL/TLS scan (focusing on HTTPS and SSL services)
run_scan "ssl_scan" "-p 22,80,443,8080 --scan-types ssl --ssl-details --analyze-http"

# Run evasive scan (using fragmentation and evasion features)
run_scan "evasive_scan" "-p 20-30,80,443 --scan-types frag,mimic --evasion --ttl-jitter 3"

# Run UDP scan (to test non-TCP protocols)
run_scan "udp_scan" "-p 53,123,161,500 --scan-types udp --verbose"

# Generate a scan summary
echo "======================================================="
echo "Scan Summary"
echo "======================================================="
echo "All scan results saved to: $OUTPUT_DIR"
echo ""
echo "Port findings across all scans:"
grep -h "Port " ${OUTPUT_DIR}/*.log | sort -u

echo ""
echo "Service detections:"
grep -h "Service: " ${OUTPUT_DIR}/*.log | sort -u

echo ""
echo "Version detections:"
grep -h "Version: " ${OUTPUT_DIR}/*.log | sort -u

echo ""
echo "Testing completed!"
echo "=======================================================" 