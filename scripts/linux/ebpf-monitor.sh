#!/bin/bash
# ebpf-monitor.sh
# eBPF-based Network Connection Monitoring Script
#
# Purpose: Monitor network connections with process attribution using BCC tools
# Requirements: 
#   - Linux kernel 4.9+
#   - bcc-tools package installed
#   - Root privileges
#
# Usage: sudo ./ebpf-monitor.sh [options]
#   Options:
#     -o, --output DIR     Output directory (default: /var/log/ebpf)
#     -d, --duration SECS  Duration in seconds (0 = indefinite)
#     -r, --rotate SIZE    Rotate logs at SIZE MB (default: 100)
#     -h, --help           Show this help

set -euo pipefail

# Default configuration
OUTPUT_DIR="/var/log/ebpf"
DURATION=0
ROTATE_SIZE_MB=100
BCC_TOOLS_PATH="/usr/share/bcc/tools"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -r|--rotate)
            ROTATE_SIZE_MB="$2"
            shift 2
            ;;
        -h|--help)
            head -20 "$0" | tail -15
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Check BCC tools availability
check_tool() {
    local tool=$1
    if [[ ! -x "${BCC_TOOLS_PATH}/${tool}" ]]; then
        echo -e "${YELLOW}Warning: ${tool} not found at ${BCC_TOOLS_PATH}${NC}"
        return 1
    fi
    return 0
}

# Create output directory
mkdir -p "${OUTPUT_DIR}"
chmod 750 "${OUTPUT_DIR}"

echo -e "${GREEN}Starting eBPF network monitoring...${NC}"
echo "Output directory: ${OUTPUT_DIR}"
echo "Duration: $(if [[ $DURATION -eq 0 ]]; then echo 'indefinite'; else echo "${DURATION}s"; fi)"

# Timestamp for log files
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Array to store background PIDs
declare -a PIDS=()

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Stopping monitoring...${NC}"
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    echo -e "${GREEN}Monitoring stopped.${NC}"
    echo "Logs saved to: ${OUTPUT_DIR}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start tcpconnect (outbound TCP connections)
if check_tool "tcpconnect"; then
    echo "Starting tcpconnect..."
    ${BCC_TOOLS_PATH}/tcpconnect -t >> "${OUTPUT_DIR}/tcpconnect_${TIMESTAMP}.log" 2>&1 &
    PIDS+=($!)
fi

# Start tcplife (TCP session lifecycle)
if check_tool "tcplife"; then
    echo "Starting tcplife..."
    ${BCC_TOOLS_PATH}/tcplife -t >> "${OUTPUT_DIR}/tcplife_${TIMESTAMP}.log" 2>&1 &
    PIDS+=($!)
fi

# Start gethostlatency (DNS lookups)
if check_tool "gethostlatency"; then
    echo "Starting gethostlatency..."
    ${BCC_TOOLS_PATH}/gethostlatency >> "${OUTPUT_DIR}/gethostlatency_${TIMESTAMP}.log" 2>&1 &
    PIDS+=($!)
fi

# Start tcpaccept (inbound TCP connections)
if check_tool "tcpaccept"; then
    echo "Starting tcpaccept..."
    ${BCC_TOOLS_PATH}/tcpaccept -t >> "${OUTPUT_DIR}/tcpaccept_${TIMESTAMP}.log" 2>&1 &
    PIDS+=($!)
fi

echo -e "${GREEN}Monitoring active with ${#PIDS[@]} tools${NC}"
echo "Press Ctrl+C to stop"

# Log rotation function
rotate_logs() {
    for logfile in "${OUTPUT_DIR}"/*.log; do
        if [[ -f "$logfile" ]]; then
            size_mb=$(du -m "$logfile" | cut -f1)
            if [[ $size_mb -ge $ROTATE_SIZE_MB ]]; then
                mv "$logfile" "${logfile}.$(date +%Y%m%d_%H%M%S)"
                gzip "${logfile}."* 2>/dev/null || true
            fi
        fi
    done
}

# Main loop
if [[ $DURATION -gt 0 ]]; then
    sleep "$DURATION"
    cleanup
else
    while true; do
        sleep 60
        rotate_logs
        
        # Check if processes are still running
        for i in "${!PIDS[@]}"; do
            if ! kill -0 "${PIDS[$i]}" 2>/dev/null; then
                echo -e "${YELLOW}Warning: Process ${PIDS[$i]} died${NC}"
                unset 'PIDS[$i]'
            fi
        done
        
        if [[ ${#PIDS[@]} -eq 0 ]]; then
            echo -e "${RED}All monitoring processes stopped${NC}"
            exit 1
        fi
    done
fi
