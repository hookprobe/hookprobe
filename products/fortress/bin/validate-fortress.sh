#!/bin/bash
#
# Fortress Configuration Validation Script
#
# Usage: ./validate-fortress.sh [--full] [--fix]
#
# Validates:
#   - OVS bridge configuration
#   - OpenFlow rules
#   - WiFi hostapd-ovs integration
#   - Device identity tracking
#   - NAC policy rules
#   - Network connectivity
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Options
FULL_CHECK=false
FIX_MODE=false

for arg in "$@"; do
    case $arg in
        --full) FULL_CHECK=true ;;
        --fix) FIX_MODE=true ;;
        -h|--help)
            echo "Usage: $0 [--full] [--fix]"
            echo "  --full   Run all validation checks including performance tests"
            echo "  --fix    Attempt to fix issues automatically"
            exit 0
            ;;
    esac
done

# Counters
PASSED=0
FAILED=0
WARNINGS=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASSED++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAILED++)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)); }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }

section() {
    echo ""
    echo -e "${CYAN}=== $1 ===${NC}"
}

# ============================================================
# OVS BRIDGE VALIDATION
# ============================================================
section "OVS Bridge Configuration"

# Check OVS bridge exists
if ovs-vsctl br-exists FTS 2>/dev/null; then
    pass "OVS bridge FTS exists"
else
    fail "OVS bridge FTS not found"
fi

# Check fail mode
fail_mode=$(ovs-vsctl get-fail-mode FTS 2>/dev/null || echo "")
if [ "$fail_mode" = "standalone" ]; then
    pass "OVS fail mode is standalone"
else
    warn "OVS fail mode is '$fail_mode' (expected: standalone)"
fi

# Check multicast snooping disabled
mcast_snoop=$(ovs-vsctl get Bridge FTS mcast_snooping_enable 2>/dev/null | tr -d '"')
if [ "$mcast_snoop" = "false" ]; then
    pass "Multicast snooping disabled"
else
    warn "Multicast snooping is $mcast_snoop (should be false for mDNS)"
fi

# Check gateway IP on FTS
fts_ip=$(ip -4 addr show FTS 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
if [ -n "$fts_ip" ]; then
    pass "Gateway IP assigned: $fts_ip"
else
    fail "No IP address on FTS bridge"
fi

# ============================================================
# OPENFLOW RULES VALIDATION
# ============================================================
section "OpenFlow Rules"

# Count total flows
flow_count=$(ovs-ofctl dump-flows FTS 2>/dev/null | wc -l)
if [ "$flow_count" -gt 10 ]; then
    pass "OpenFlow rules present: $flow_count rules"
else
    warn "Only $flow_count OpenFlow rules (expected more)"
fi

# Check base rules by priority
for priority in 1000 900 800 700 500 400; do
    count=$(ovs-ofctl dump-flows FTS 2>/dev/null | grep -c "priority=$priority" || echo 0)
    if [ "$count" -gt 0 ]; then
        pass "Priority $priority rules present: $count"
    else
        warn "No priority $priority rules found"
    fi
done

# Check mDNS reflection rules
mdns_refl=$(ovs-ofctl dump-flows FTS 2>/dev/null | grep -c "224.0.0.251" || echo 0)
if [ "$mdns_refl" -gt 0 ]; then
    pass "mDNS reflection rules present: $mdns_refl"
else
    warn "No mDNS reflection rules (cross-band discovery may fail)"
fi

# ============================================================
# WIFI HOSTAPD-OVS VALIDATION
# ============================================================
section "WiFi hostapd-ovs Integration"

# Check hostapd-ovs binary
if [ -x "/usr/local/bin/hostapd-ovs" ]; then
    pass "hostapd-ovs binary installed"
else
    fail "hostapd-ovs not found at /usr/local/bin/hostapd-ovs"
fi

# Check hostapd running with correct binary
hostapd_pid=$(pgrep -f "hostapd-ovs" 2>/dev/null || true)
if [ -n "$hostapd_pid" ]; then
    pass "hostapd-ovs running (PID: $hostapd_pid)"
else
    warn "hostapd-ovs not running"
fi

# Check WiFi interfaces in OVS
for iface in wlan_24ghz wlan_5ghz; do
    if ovs-vsctl port-to-br "$iface" 2>/dev/null | grep -q FTS; then
        port_num=$(ovs-vsctl get interface "$iface" ofport 2>/dev/null | tr -d '"')
        pass "$iface in OVS bridge (port $port_num)"
    else
        warn "$iface not in OVS bridge"
    fi
done

# Check no legacy br-wifi
if ip link show br-wifi &>/dev/null; then
    warn "Legacy br-wifi bridge exists (should be removed)"
else
    pass "No legacy br-wifi bridge"
fi

# Check hostapd config uses bridge=FTS
for conf in /etc/hostapd/hostapd-24ghz.conf /etc/hostapd/hostapd-5ghz.conf; do
    if [ -f "$conf" ]; then
        bridge=$(grep "^bridge=" "$conf" 2>/dev/null | cut -d= -f2)
        if [ "$bridge" = "FTS" ]; then
            pass "$(basename $conf): bridge=FTS (direct OVS)"
        else
            fail "$(basename $conf): bridge=$bridge (should be FTS)"
        fi
    fi
done

# ============================================================
# DEVICE IDENTITY TRACKING
# ============================================================
section "Device Identity Tracking"

# Check device identity database
id_db="/var/lib/hookprobe/device_identity.db"
if [ -f "$id_db" ]; then
    id_count=$(sqlite3 "$id_db" "SELECT COUNT(*) FROM device_identities" 2>/dev/null || echo 0)
    mac_count=$(sqlite3 "$id_db" "SELECT COUNT(*) FROM mac_to_identity" 2>/dev/null || echo 0)
    pass "Device identity database exists ($id_count identities, $mac_count MAC mappings)"
else
    warn "Device identity database not found at $id_db"
fi

# Check DHCP events file
dhcp_file="/opt/hookprobe/fortress/data/devices.json"
if [ -f "$dhcp_file" ]; then
    device_count=$(python3 -c "import json; print(len(json.load(open('$dhcp_file'))))" 2>/dev/null || echo 0)
    pass "DHCP events file exists ($device_count devices)"
else
    warn "DHCP events file not found at $dhcp_file"
fi

# Check autopilot database
ap_db="/var/lib/hookprobe/autopilot.db"
if [ -f "$ap_db" ]; then
    policy_count=$(sqlite3 "$ap_db" "SELECT COUNT(*) FROM device_identity WHERE policy IS NOT NULL" 2>/dev/null || echo 0)
    pass "Autopilot database exists ($policy_count devices with policies)"
else
    warn "Autopilot database not found at $ap_db"
fi

# ============================================================
# NAC POLICY VALIDATION
# ============================================================
section "NAC Policy Rules"

# Check for per-device policy rules (priority 475-850)
policy_rules=$(ovs-ofctl dump-flows FTS 2>/dev/null | grep -cE "priority=(475|600|650|700|720|750|800|850)" || echo 0)
info "Per-device policy rules: $policy_rules"

# Check QUARANTINE rules (priority 999-1001)
quarantine_rules=$(ovs-ofctl dump-flows FTS 2>/dev/null | grep -cE "priority=(999|1000|1001)" || echo 0)
if [ "$quarantine_rules" -gt 0 ]; then
    info "Quarantine rules active: $quarantine_rules"
fi

# Check container network blocking
container_block=$(ovs-ofctl dump-flows FTS 2>/dev/null | grep -c "172.20.0.0" || echo 0)
if [ "$container_block" -gt 0 ]; then
    pass "Container network blocking rules: $container_block"
else
    info "No explicit container blocking rules (may rely on NAT)"
fi

# ============================================================
# NETWORK CONNECTIVITY
# ============================================================
section "Network Connectivity"

# Check default route
default_gw=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
if [ -n "$default_gw" ]; then
    pass "Default gateway: $default_gw"
else
    fail "No default gateway"
fi

# Check DNS resolution
if host google.com &>/dev/null; then
    pass "DNS resolution working"
else
    warn "DNS resolution failed"
fi

# Check dnsmasq running
if systemctl is-active dnsmasq &>/dev/null; then
    pass "dnsmasq DHCP server running"
else
    warn "dnsmasq not running"
fi

# ============================================================
# SERVICES STATUS
# ============================================================
section "Services Status"

services=(
    "fortress:Main container orchestration"
    "fortress-vlan:OVS VLAN setup"
    "fts-hostapd-24ghz:2.4GHz WiFi AP"
    "fts-hostapd-5ghz:5GHz WiFi AP"
    "dnsmasq:DHCP server"
)

for svc in "${services[@]}"; do
    name="${svc%%:*}"
    desc="${svc#*:}"
    if systemctl is-active "$name" &>/dev/null; then
        pass "$name ($desc)"
    else
        status=$(systemctl is-enabled "$name" 2>/dev/null || echo "unknown")
        if [ "$status" = "enabled" ]; then
            warn "$name not running but enabled"
        else
            info "$name not active (status: $status)"
        fi
    fi
done

# ============================================================
# FULL CHECKS (optional)
# ============================================================
if [ "$FULL_CHECK" = true ]; then
    section "Performance Tests (--full)"

    # mDNS test
    info "Testing mDNS discovery..."
    if command -v avahi-browse &>/dev/null; then
        mdns_services=$(timeout 5 avahi-browse -art 2>/dev/null | grep -c "=" || echo 0)
        if [ "$mdns_services" -gt 0 ]; then
            pass "mDNS discovery found $mdns_services services"
        else
            warn "No mDNS services discovered"
        fi
    else
        info "avahi-browse not installed, skipping mDNS test"
    fi

    # OpenFlow rule performance
    info "Checking OpenFlow rule count per priority..."
    ovs-ofctl dump-flows FTS 2>/dev/null | grep -oP 'priority=\K[0-9]+' | sort -rn | uniq -c | sort -rn | head -10 | while read count prio; do
        echo "    Priority $prio: $count rules"
    done
fi

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo -e "${CYAN}=== VALIDATION SUMMARY ===${NC}"
echo -e "  ${GREEN}Passed:${NC}   $PASSED"
echo -e "  ${RED}Failed:${NC}   $FAILED"
echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All critical checks passed!${NC}"
    exit 0
else
    echo -e "${RED}$FAILED critical checks failed - review issues above${NC}"
    exit 1
fi
