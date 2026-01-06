#!/bin/bash
# ==============================================================================
# Fortress Packet Loss Diagnostic Script
# ==============================================================================
# Run this on your Fortress device to diagnose network packet loss
#
# Usage: sudo ./diagnose-packet-loss.sh
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Fortress Packet Loss Diagnostics${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# ==============================================================================
# 1. SYSTEM RESOURCES
# ==============================================================================
echo -e "${YELLOW}[1/8] System Resources${NC}"
echo "----------------------------------------"

echo -e "${CYAN}CPU Usage:${NC}"
top -bn1 | head -5

echo ""
echo -e "${CYAN}Memory:${NC}"
free -h

echo ""
echo -e "${CYAN}Load Average:${NC}"
uptime

echo ""
echo -e "${CYAN}Top Processes by CPU:${NC}"
ps aux --sort=-%cpu | head -10

# ==============================================================================
# 2. CONTAINER STATUS
# ==============================================================================
echo ""
echo -e "${YELLOW}[2/8] Container Status${NC}"
echo "----------------------------------------"

if command -v podman &> /dev/null; then
    echo -e "${CYAN}Container Resource Usage:${NC}"
    podman stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}" 2>/dev/null || echo "Cannot get container stats"

    echo ""
    echo -e "${CYAN}Container Health:${NC}"
    podman ps --format "table {{.Names}}\t{{.Status}}\t{{.RunningFor}}" 2>/dev/null | head -20
else
    echo "Podman not found"
fi

# ==============================================================================
# 3. OVS BRIDGE STATUS
# ==============================================================================
echo ""
echo -e "${YELLOW}[3/8] OVS Bridge Status${NC}"
echo "----------------------------------------"

if command -v ovs-vsctl &> /dev/null; then
    echo -e "${CYAN}OVS Configuration:${NC}"
    ovs-vsctl show

    echo ""
    echo -e "${CYAN}OVS Flow Table Size:${NC}"
    FLOW_COUNT=$(ovs-ofctl dump-flows FTS 2>/dev/null | wc -l)
    echo "Total flows: $FLOW_COUNT"

    if [[ $FLOW_COUNT -gt 5000 ]]; then
        echo -e "${RED}WARNING: High flow count ($FLOW_COUNT) - may cause drops${NC}"
    elif [[ $FLOW_COUNT -gt 2000 ]]; then
        echo -e "${YELLOW}NOTICE: Elevated flow count ($FLOW_COUNT)${NC}"
    else
        echo -e "${GREEN}Flow count OK${NC}"
    fi

    echo ""
    echo -e "${CYAN}OVS Port Statistics:${NC}"
    ovs-ofctl dump-ports FTS 2>/dev/null | grep -E "port|rx|tx|drop|err"

    echo ""
    echo -e "${CYAN}OVS Datapath Statistics:${NC}"
    ovs-dpctl show 2>/dev/null | head -20
else
    echo "OVS not installed or not running"
fi

# ==============================================================================
# 4. NETWORK INTERFACE STATISTICS
# ==============================================================================
echo ""
echo -e "${YELLOW}[4/8] Network Interface Statistics${NC}"
echo "----------------------------------------"

echo -e "${CYAN}Interface Error Counters:${NC}"
ip -s link show | grep -A6 -E "^[0-9]+:" | grep -E "^[0-9]+:|errors|dropped|overrun|carrier"

echo ""
echo -e "${CYAN}VLAN Interface Status:${NC}"
ip addr show FTS 2>/dev/null || echo "FTS not found"
ip addr show FTS 2>/dev/null || echo "FTS not found"

echo ""
echo -e "${CYAN}Bridge/OVS Interface:${NC}"
ip addr show FTS 2>/dev/null || echo "FTS bridge not found"

# ==============================================================================
# 5. IPTABLES / NETFILTER
# ==============================================================================
echo ""
echo -e "${YELLOW}[5/8] Firewall / Conntrack${NC}"
echo "----------------------------------------"

echo -e "${CYAN}Conntrack Table Usage:${NC}"
if [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    CONNTRACK_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
    CONNTRACK_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
    USAGE_PCT=$((CONNTRACK_COUNT * 100 / CONNTRACK_MAX))
    echo "Connections: $CONNTRACK_COUNT / $CONNTRACK_MAX ($USAGE_PCT%)"

    if [[ $USAGE_PCT -gt 80 ]]; then
        echo -e "${RED}WARNING: Conntrack table nearly full!${NC}"
    elif [[ $USAGE_PCT -gt 50 ]]; then
        echo -e "${YELLOW}NOTICE: Conntrack table over 50%${NC}"
    else
        echo -e "${GREEN}Conntrack usage OK${NC}"
    fi
else
    echo "Conntrack stats not available"
fi

echo ""
echo -e "${CYAN}iptables DROP/REJECT Rules:${NC}"
iptables -L -n -v 2>/dev/null | grep -i -E "drop|reject" | head -10 || echo "No DROP rules found"

echo ""
echo -e "${CYAN}nftables counters (if used):${NC}"
nft list ruleset 2>/dev/null | grep -i -E "drop|counter" | head -10 || echo "nftables not in use"

# ==============================================================================
# 6. KERNEL / DMESG ERRORS
# ==============================================================================
echo ""
echo -e "${YELLOW}[6/8] Kernel Messages (Network Related)${NC}"
echo "----------------------------------------"

echo -e "${CYAN}Recent network-related kernel messages:${NC}"
dmesg | grep -i -E "dropped|error|fail|timeout|reset|link" | tail -20

echo ""
echo -e "${CYAN}OVS kernel messages:${NC}"
dmesg | grep -i openvswitch | tail -10

# ==============================================================================
# 7. WIFI / WIRELESS
# ==============================================================================
echo ""
echo -e "${YELLOW}[7/8] WiFi Status${NC}"
echo "----------------------------------------"

echo -e "${CYAN}WiFi Interfaces:${NC}"
iw dev 2>/dev/null || echo "iw command not available"

echo ""
echo -e "${CYAN}hostapd Status:${NC}"
systemctl status fts-hostapd-24ghz --no-pager 2>/dev/null | head -10 || echo "2.4GHz AP not running"
systemctl status fts-hostapd-5ghz --no-pager 2>/dev/null | head -10 || echo "5GHz AP not running"

echo ""
echo -e "${CYAN}WiFi Station Statistics:${NC}"
for iface in wlan_24ghz wlan_5ghz wlan0 wlan1; do
    if iw dev $iface station dump 2>/dev/null | head -5; then
        echo "--- $iface stations above ---"
    fi
done

echo ""
echo -e "${CYAN}DFS/Radar Events (5GHz):${NC}"
dmesg | grep -i -E "dfs|radar|cac" | tail -5 || echo "No DFS events found"

# ==============================================================================
# 8. SPECIFIC CONTAINER CHECKS
# ==============================================================================
echo ""
echo -e "${YELLOW}[8/8] Service-Specific Checks${NC}"
echo "----------------------------------------"

echo -e "${CYAN}QSecBit Container Logs (last errors):${NC}"
podman logs fts-qsecbit 2>&1 | grep -i -E "error|warn|drop" | tail -10 || echo "No QSecBit errors"

echo ""
echo -e "${CYAN}Suricata Container (if running):${NC}"
podman logs fts-suricata 2>&1 | grep -i -E "error|drop|overflow" | tail -5 || echo "Suricata not running or no errors"

echo ""
echo -e "${CYAN}dnsXai Container:${NC}"
podman logs fts-dnsxai 2>&1 | grep -i -E "error|timeout" | tail -5 || echo "No dnsXai errors"

# ==============================================================================
# SUMMARY
# ==============================================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  DIAGNOSTIC SUMMARY${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Collect issues
ISSUES=()

# Check CPU
LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')
if (( $(echo "$LOAD > 2.0" | bc -l 2>/dev/null || echo 0) )); then
    ISSUES+=("HIGH CPU LOAD: $LOAD")
fi

# Check memory
MEM_AVAIL=$(free | awk '/^Mem:/ {print $7}')
if [[ $MEM_AVAIL -lt 500000 ]]; then
    ISSUES+=("LOW MEMORY: ${MEM_AVAIL}KB available")
fi

# Check OVS flows
if command -v ovs-ofctl &> /dev/null; then
    FLOWS=$(ovs-ofctl dump-flows FTS 2>/dev/null | wc -l)
    if [[ $FLOWS -gt 5000 ]]; then
        ISSUES+=("HIGH OVS FLOW COUNT: $FLOWS flows")
    fi
fi

# Check conntrack
if [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    CT_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
    CT_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
    CT_PCT=$((CT_COUNT * 100 / CT_MAX))
    if [[ $CT_PCT -gt 80 ]]; then
        ISSUES+=("CONNTRACK TABLE NEARLY FULL: $CT_PCT%")
    fi
fi

# Check interface drops
for iface in FTS FTS eth0 enp1s0; do
    DROPS=$(ip -s link show $iface 2>/dev/null | grep -A1 "RX:" | tail -1 | awk '{print $4}')
    if [[ -n "$DROPS" && "$DROPS" -gt 1000 ]]; then
        ISSUES+=("INTERFACE DROPS on $iface: $DROPS")
    fi
done

if [[ ${#ISSUES[@]} -eq 0 ]]; then
    echo -e "${GREEN}No obvious issues detected.${NC}"
    echo ""
    echo "Possible causes not detected by this script:"
    echo "  - WiFi interference (check with WiFi analyzer app)"
    echo "  - Client-side issues (check client network settings)"
    echo "  - ISP/WAN issues (if pinging external IPs)"
    echo "  - Hardware NIC issues (check ethtool -S)"
else
    echo -e "${RED}ISSUES DETECTED:${NC}"
    for issue in "${ISSUES[@]}"; do
        echo -e "  ${RED}* $issue${NC}"
    done
fi

echo ""
echo -e "${CYAN}Recommendations:${NC}"
echo "  1. If OVS flows > 5000: Restart fortress service to clear stale flows"
echo "  2. If conntrack > 80%: Increase limit with:"
echo "     sysctl -w net.netfilter.nf_conntrack_max=262144"
echo "  3. If container CPU > 100%: Consider disabling optional services"
echo "  4. If WiFi, try switching to non-DFS channel (36, 40, 44, 48)"
echo ""
echo -e "${CYAN}To continuously monitor:${NC}"
echo "  watch -n1 'ovs-ofctl dump-ports FTS | grep -E \"rx|tx|drop\"'"
echo ""
