#!/bin/bash
# network-snapshot.sh
# macOS Network State Snapshot for Incident Response
#
# Purpose: Capture comprehensive network state for forensic analysis
# Requirements: sudo access for complete information
#
# Usage: sudo ./network-snapshot.sh [output_directory]

set -euo pipefail

# Configuration
OUTPUT_DIR="${1:-/tmp/network_snapshot_$(date +%Y%m%d_%H%M%S)}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}macOS Network Snapshot Tool${NC}"
echo "=============================="
echo ""

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}Warning: Running without sudo. Some information may be incomplete.${NC}"
fi

# Create output directory
mkdir -p "${OUTPUT_DIR}"
echo "Output directory: ${OUTPUT_DIR}"
echo ""

# Function to run command and save output
capture() {
    local name=$1
    local cmd=$2
    local output_file="${OUTPUT_DIR}/${name}.txt"
    
    echo -n "Capturing ${name}... "
    if eval "${cmd}" > "${output_file}" 2>&1; then
        echo -e "${GREEN}done${NC}"
    else
        echo -e "${YELLOW}partial${NC}"
    fi
}

# Function to run command requiring sudo
capture_sudo() {
    local name=$1
    local cmd=$2
    local output_file="${OUTPUT_DIR}/${name}.txt"
    
    echo -n "Capturing ${name} (sudo)... "
    if sudo ${cmd} > "${output_file}" 2>&1; then
        echo -e "${GREEN}done${NC}"
    else
        echo -e "${YELLOW}partial${NC}"
    fi
}

echo "=== Network Connections ==="
capture "lsof_network" "lsof -i -n -P"
capture "lsof_established" "lsof -i -n -P | grep ESTABLISHED"
capture "lsof_listen" "lsof -i -n -P | grep LISTEN"
capture "netstat_all" "netstat -an"
capture "netstat_routing" "netstat -rn"

echo ""
echo "=== Network Interfaces ==="
capture "ifconfig" "ifconfig -a"
capture "networksetup_services" "networksetup -listallnetworkservices"
capture "networksetup_hardware" "networksetup -listallhardwareports"

echo ""
echo "=== DNS Configuration ==="
capture "dns_config" "scutil --dns"
capture "resolv_conf" "cat /etc/resolv.conf 2>/dev/null || echo 'No resolv.conf'"
capture "hosts_file" "cat /etc/hosts"

echo ""
echo "=== ARP and Neighbors ==="
capture "arp_cache" "arp -a"
capture "ndp_cache" "ndp -a 2>/dev/null || echo 'No IPv6 neighbors'"

echo ""
echo "=== Firewall Status ==="
capture "pf_status" "pfctl -s info 2>/dev/null || echo 'pf not running'"
capture "pf_rules" "pfctl -s rules 2>/dev/null || echo 'No pf rules'"
capture "alf_status" "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
capture "alf_apps" "/usr/libexec/ApplicationFirewall/socketfilterfw --listapps"

echo ""
echo "=== Process Information ==="
capture "ps_network" "ps aux | head -1; ps aux | grep -E '(curl|wget|nc|ncat|python|ruby|perl|ssh|telnet)' | grep -v grep"
capture "ps_all" "ps aux"

echo ""
echo "=== System Information ==="
capture "hostname" "hostname"
capture "uname" "uname -a"
capture "sw_vers" "sw_vers"
capture "system_profiler_network" "system_profiler SPNetworkDataType"

echo ""
echo "=== Recent DNS Logs ==="
capture "dns_logs" "log show --last 10m --predicate 'process == \"mDNSResponder\"' --style syslog 2>/dev/null || echo 'Unable to access logs'"

echo ""
echo "=== Network Extensions ==="
capture "network_extensions" "systemextensionsctl list 2>/dev/null || echo 'No system extensions'"

echo ""
echo "=== VPN Status ==="
capture "vpn_status" "scutil --nc list"

# osquery queries if available
if command -v osqueryi &> /dev/null; then
    echo ""
    echo "=== osquery Data ==="
    capture "osquery_sockets" "osqueryi --json 'SELECT p.name, p.path, p.pid, pos.local_address, pos.local_port, pos.remote_address, pos.remote_port, pos.state FROM processes p JOIN process_open_sockets pos USING (pid) WHERE pos.remote_port != 0'"
    capture "osquery_listening" "osqueryi --json 'SELECT p.name, p.path, lp.port, lp.address, lp.protocol FROM processes p JOIN listening_ports lp USING (pid)'"
    capture "osquery_dns" "osqueryi --json 'SELECT * FROM dns_resolvers'"
fi

echo ""
echo "=== Creating Archive ==="

# Create summary file
cat > "${OUTPUT_DIR}/README.txt" << EOF
Network Snapshot
================
Timestamp: ${TIMESTAMP}
Hostname: $(hostname)
macOS Version: $(sw_vers -productVersion)

This snapshot contains:
- Network connections (lsof, netstat)
- Interface configuration
- DNS configuration
- ARP/NDP cache
- Firewall status
- Process information
- System information
- DNS logs (last 10 minutes)

For incident response, review:
1. lsof_established.txt - Active connections
2. lsof_listen.txt - Listening services
3. dns_logs.txt - Recent DNS activity
4. arp_cache.txt - Local network devices
EOF

# Create tar archive
ARCHIVE="${OUTPUT_DIR}.tar.gz"
tar -czf "${ARCHIVE}" -C "$(dirname ${OUTPUT_DIR})" "$(basename ${OUTPUT_DIR})"

echo -e "${GREEN}Snapshot complete!${NC}"
echo ""
echo "Files saved to: ${OUTPUT_DIR}/"
echo "Archive created: ${ARCHIVE}"
echo ""
echo "File listing:"
ls -la "${OUTPUT_DIR}/"
