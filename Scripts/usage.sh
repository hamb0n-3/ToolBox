# CPU Usage
cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')

# Disk Space Usage
disk_total=$(df -h / | awk 'NR==2{print $2}')
disk_used=$(df -h / | awk 'NR==2{print $3}')
disk_percent=$(df -h / | awk 'NR==2{print $5}')

# Network Usage
net_rx=$(ip -s link | awk '/RX:/{sum+=$2} END{print sum}')
net_tx=$(ip -s link | awk '/TX:/{sum+=$2} END{print sum}')

# Display
echo "--- System Usage ---"
echo "Memory : ${mem_used}MB / ${mem_total}MB (${mem_percent}%)"
echo "CPU Usage: ${cpu_usage}%"
echo "Disk Space: ${disk_used} / ${disk_total} (${disk_percent})"
echo "Network RX/TX: ${net_rx} bytes / ${net_tx} bytes"