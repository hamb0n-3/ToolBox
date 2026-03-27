#!/bin/bash
# =============================================================================
# system_usage.sh — Display memory, CPU, disk, and network stats
# Run as: bash system_usage.sh
# =============================================================================
 
# ── Memory (from /proc/meminfo, values in kB) ─────────────────────────────────
mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
mem_available_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
mem_used_kb=$(( mem_total_kb - mem_available_kb ))
 
mem_total=$(( mem_total_kb / 1024 ))
mem_used=$(( mem_used_kb / 1024 ))
mem_percent=$(( mem_used * 100 / mem_total ))
 
# ── CPU (average across all cores over a 1-second sample) ────────────────────
cpu_usage=$(top -bn2 -d0.5 | awk '
  /^%Cpu/{
    idle=$8; usage=100-idle
  }
  END { printf "%.1f", usage }
')
 
# ── Disk (root filesystem) ────────────────────────────────────────────────────
read -r disk_used disk_total disk_percent <<< \
  $(df -h / | awk 'NR==2{print $3, $2, $5}')
 
# ── Network (total RX/TX across all non-loopback interfaces) ──────────────────
net_rx=0
net_tx=0
while read -r iface rx tx; do
    net_rx=$(( net_rx + rx ))
    net_tx=$(( net_tx + tx ))
done < <(awk '
  NR>2 && !/lo:/ {
    gsub(/:/, "", $1)
    print $1, $2, $10
  }
' /proc/net/dev)
 
# ── Output ────────────────────────────────────────────────────────────────────
echo "--- System Usage ---"
echo "Memory    : ${mem_used}MB / ${mem_total}MB (${mem_percent}%)"
echo "CPU Usage : ${cpu_usage}%"
echo "Disk Space: ${disk_used} / ${disk_total} (${disk_percent})"
echo "Network RX/TX: ${net_rx} bytes / ${net_tx} bytes"s