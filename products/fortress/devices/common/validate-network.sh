#!/bin/bash
#
# validate-network.sh - Network Configuration Validation for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Validates network interface detection and configuration before deployment.
# Run this script to verify the system is correctly configured.
#
# Version: 1.0.0
# License: AGPL-3.0
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# State files
STATE_DIR="/var/lib/fortress"
INTERFACE_STATE_FILE="$STATE_DIR/network-interfaces.conf"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASS=0
WARN=0
FAIL=0

# Test helpers
check_pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    PASS=$((PASS + 1))
}

check_warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
    WARN=$((WARN + 1))
}

check_fail() {
    echo -e "  ${RED}✗${NC} $1"
    FAIL=$((FAIL + 1))
}

section() {
    echo ""
    echo -e "${BLUE}━━━ $1 ━━━${NC}"
}

# ============================================================
# PREREQUISITE CHECKS
# ============================================================

check_prerequisites() {
    section "Prerequisites"

    # Check running as root
    if [ "$(id -u)" -eq 0 ]; then
        check_pass "Running as root"
    else
        check_warn "Not running as root (some tests may fail)"
    fi

    # Check required commands
    local required_cmds="ip iw nmcli ethtool hostapd"
    for cmd in $required_cmds; do
        if command -v "$cmd" &>/dev/null; then
            check_pass "Command available: $cmd"
        else
            check_warn "Command not found: $cmd (optional)"
        fi
    done

    # Check kernel modules
    local required_mods="bridge 8021q"
    for mod in $required_mods; do
        if lsmod | grep -q "^$mod" || [ -d "/sys/module/$mod" ]; then
            check_pass "Kernel module loaded: $mod"
        else
            check_warn "Kernel module not loaded: $mod"
        fi
    done

    # Check sysfs
    if [ -d "/sys/class/net" ]; then
        check_pass "Network sysfs available"
    else
        check_fail "Network sysfs not available"
    fi
}

# ============================================================
# INTERFACE DETECTION TESTS
# ============================================================

check_interface_detection() {
    section "Interface Detection"

    # Run detection
    if [ -x "$SCRIPT_DIR/network-interface-detector.sh" ]; then
        source <("$SCRIPT_DIR/network-interface-detector.sh" detect 2>&1 | grep -E "^export" || true) 2>/dev/null
        check_pass "Network interface detector loaded"
    else
        check_fail "Network interface detector not found: $SCRIPT_DIR/network-interface-detector.sh"
        return 1
    fi

    # Check Ethernet detection
    if [ -n "$NET_ETH_INTERFACES" ]; then
        check_pass "Ethernet interfaces detected: $NET_ETH_INTERFACES"
    else
        check_fail "No Ethernet interfaces detected"
    fi

    # Check WAN assignment
    if [ -n "$NET_WAN_IFACE" ]; then
        check_pass "WAN interface assigned: $NET_WAN_IFACE"

        # Verify WAN interface exists
        if [ -d "/sys/class/net/$NET_WAN_IFACE" ]; then
            check_pass "WAN interface exists in sysfs"
        else
            check_fail "WAN interface not found: $NET_WAN_IFACE"
        fi
    else
        check_warn "No WAN interface assigned"
    fi

    # Check LAN assignment
    if [ -n "$NET_LAN_IFACES" ]; then
        check_pass "LAN interfaces assigned: $NET_LAN_IFACES"

        for iface in $NET_LAN_IFACES; do
            if [ -d "/sys/class/net/$iface" ]; then
                check_pass "LAN interface exists: $iface"
            else
                check_fail "LAN interface not found: $iface"
            fi
        done
    else
        check_warn "No LAN interfaces assigned (single-port mode)"
    fi
}

# ============================================================
# WIFI DETECTION TESTS
# ============================================================

check_wifi_detection() {
    section "WiFi Detection"

    # Check WiFi interfaces
    if [ -n "$NET_WIFI_INTERFACES" ]; then
        check_pass "WiFi interfaces detected: $NET_WIFI_INTERFACES"

        for iface in $NET_WIFI_INTERFACES; do
            if [ -d "/sys/class/net/$iface" ]; then
                check_pass "WiFi interface exists: $iface"
            else
                check_fail "WiFi interface not found: $iface"
            fi
        done
    else
        check_warn "No WiFi interfaces detected"
        return 0
    fi

    # Check band detection
    if [ -n "$NET_WIFI_24GHZ_IFACE" ]; then
        check_pass "2.4GHz interface: $NET_WIFI_24GHZ_IFACE"
    else
        check_warn "No 2.4GHz capable interface"
    fi

    if [ -n "$NET_WIFI_5GHZ_IFACE" ]; then
        check_pass "5GHz interface: $NET_WIFI_5GHZ_IFACE"
    else
        check_warn "No 5GHz capable interface"
    fi

    if [ -n "$NET_WIFI_6GHZ_IFACE" ]; then
        check_pass "6GHz interface: $NET_WIFI_6GHZ_IFACE (WiFi 6E)"
    fi

    # Check configuration mode
    case "${NET_WIFI_CONFIG_MODE:-none}" in
        separate-radios)
            check_pass "Config mode: separate radios (optimal for dual-band)"
            ;;
        single-dual-band)
            check_pass "Config mode: single dual-band radio"
            check_warn "May not support simultaneous 2.4GHz + 5GHz"
            ;;
        24ghz-only)
            check_pass "Config mode: 2.4GHz only"
            ;;
        5ghz-only)
            check_pass "Config mode: 5GHz only"
            ;;
        none)
            check_warn "No WiFi configuration mode detected"
            ;;
    esac

    # Check AP mode support
    if command -v iw &>/dev/null; then
        for iface in $NET_WIFI_INTERFACES; do
            local iface_upper="${iface^^}"
            local has_ap
            eval "has_ap=\$NET_WIFI_${iface_upper}_AP"

            if [ "$has_ap" = "true" ]; then
                check_pass "AP mode supported: $iface"
            else
                check_warn "AP mode not supported: $iface"
            fi
        done
    fi
}

# ============================================================
# WWAN/LTE DETECTION TESTS
# ============================================================

check_wwan_detection() {
    section "WWAN/LTE Detection"

    # Check WWAN interfaces
    if [ -n "$NET_WWAN_INTERFACES" ]; then
        check_pass "WWAN interfaces detected: $NET_WWAN_INTERFACES"

        for iface in $NET_WWAN_INTERFACES; do
            if [ -d "/sys/class/net/$iface" ]; then
                check_pass "WWAN interface exists: $iface"
            else
                check_fail "WWAN interface not found: $iface"
            fi
        done
    else
        check_warn "No WWAN interfaces detected (LTE modem not connected?)"
    fi

    # Check control device
    if [ -n "$NET_WWAN_CONTROL" ]; then
        if [ -c "$NET_WWAN_CONTROL" ]; then
            check_pass "Control device available: $NET_WWAN_CONTROL"
        else
            check_fail "Control device not accessible: $NET_WWAN_CONTROL"
        fi
    else
        check_warn "No WWAN control device found"
    fi

    # Check ModemManager
    if command -v mmcli &>/dev/null; then
        if systemctl is-active --quiet ModemManager 2>/dev/null; then
            check_pass "ModemManager is running"

            local modem_count
            modem_count=$(mmcli -L 2>/dev/null | grep -c "Modem" || echo "0")
            if [ "$modem_count" -gt 0 ]; then
                check_pass "ModemManager sees $modem_count modem(s)"
            else
                check_warn "ModemManager running but no modems detected"
            fi
        else
            check_warn "ModemManager not running"
        fi
    fi

    # Check USB modems
    if command -v lsusb &>/dev/null; then
        local known_modems
        known_modems=$(lsusb 2>/dev/null | grep -ciE "2c7c|1199|12d1|19d2|2cb7|1bc7|quectel|sierra|huawei|fibocom" || echo "0")
        if [ "$known_modems" -gt 0 ]; then
            check_pass "USB modem(s) detected: $known_modems"
        fi
    fi
}

# ============================================================
# NETWORK STACK TESTS
# ============================================================

check_network_stack() {
    section "Network Stack"

    # Check IP forwarding
    local ip_forward
    ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [ "$ip_forward" = "1" ]; then
        check_pass "IPv4 forwarding enabled"
    else
        check_warn "IPv4 forwarding disabled (required for routing)"
    fi

    # Check bridge module
    if [ -d "/sys/module/bridge" ]; then
        check_pass "Bridge module loaded"
    else
        check_warn "Bridge module not loaded"
    fi

    # Check existing bridges
    local bridges
    bridges=$(ls /sys/class/net/*/bridge 2>/dev/null | wc -l)
    if [ "$bridges" -gt 0 ]; then
        check_pass "Existing bridges: $bridges"
        for br_path in /sys/class/net/*/bridge; do
            local br_name
            br_name=$(dirname "$br_path" | xargs basename)
            check_pass "  Bridge: $br_name"
        done
    fi

    # Check NetworkManager status
    if command -v nmcli &>/dev/null; then
        if systemctl is-active --quiet NetworkManager 2>/dev/null; then
            check_pass "NetworkManager is running"
        else
            check_warn "NetworkManager not running"
        fi
    fi
}

# ============================================================
# HOSTAPD CONFIGURATION TESTS
# ============================================================

check_hostapd_config() {
    section "WiFi AP Configuration"

    # Check hostapd installation
    if command -v hostapd &>/dev/null; then
        local version
        version=$(hostapd -v 2>&1 | head -1 | awk '{print $2}')
        check_pass "hostapd installed: $version"
    else
        check_fail "hostapd not installed"
        return 1
    fi

    # Check configuration files
    local hostapd_dir="/etc/hostapd"

    if [ -f "$hostapd_dir/hostapd-24ghz.conf" ]; then
        check_pass "2.4GHz config exists: $hostapd_dir/hostapd-24ghz.conf"

        # Validate config
        if hostapd -t "$hostapd_dir/hostapd-24ghz.conf" 2>&1 | grep -q "OK"; then
            check_pass "2.4GHz config syntax valid"
        else
            check_warn "2.4GHz config may have issues"
        fi
    else
        check_warn "2.4GHz config not found (run hostapd-generator.sh)"
    fi

    if [ -f "$hostapd_dir/hostapd-5ghz.conf" ]; then
        check_pass "5GHz config exists: $hostapd_dir/hostapd-5ghz.conf"

        # Validate config
        if hostapd -t "$hostapd_dir/hostapd-5ghz.conf" 2>&1 | grep -q "OK"; then
            check_pass "5GHz config syntax valid"
        else
            check_warn "5GHz config may have issues"
        fi
    else
        check_warn "5GHz config not found (run hostapd-generator.sh)"
    fi

    # Check VLAN file
    if [ -f "$hostapd_dir/hostapd.vlan" ]; then
        check_pass "VLAN config exists: $hostapd_dir/hostapd.vlan"
    else
        check_warn "VLAN config not found"
    fi
}

# ============================================================
# DNSMASQ/DHCP TESTS
# ============================================================

check_dhcp_config() {
    section "DHCP Server"

    if command -v dnsmasq &>/dev/null; then
        check_pass "dnsmasq installed"

        if systemctl is-active --quiet dnsmasq 2>/dev/null; then
            check_pass "dnsmasq is running"
        else
            check_warn "dnsmasq not running"
        fi
    else
        check_warn "dnsmasq not installed"
    fi

    # Check for fortress dnsmasq config
    if [ -f "/etc/dnsmasq.d/fortress.conf" ]; then
        check_pass "Fortress dnsmasq config exists"
    else
        check_warn "Fortress dnsmasq config not found"
    fi
}

# ============================================================
# CONNECTIVITY TESTS
# ============================================================

check_connectivity() {
    section "Connectivity Tests"

    # Check WAN interface has carrier
    if [ -n "$NET_WAN_IFACE" ]; then
        local carrier
        carrier=$(cat "/sys/class/net/$NET_WAN_IFACE/carrier" 2>/dev/null || echo "0")
        if [ "$carrier" = "1" ]; then
            check_pass "WAN interface has carrier: $NET_WAN_IFACE"
        else
            check_warn "WAN interface no carrier: $NET_WAN_IFACE (cable connected?)"
        fi

        # Check for IP address
        local wan_ip
        wan_ip=$(ip addr show "$NET_WAN_IFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        if [ -n "$wan_ip" ]; then
            check_pass "WAN has IP address: $wan_ip"
        else
            check_warn "WAN has no IP address"
        fi

        # Check default gateway
        local gateway
        gateway=$(ip route show dev "$NET_WAN_IFACE" 2>/dev/null | grep "default" | awk '{print $3}')
        if [ -n "$gateway" ]; then
            check_pass "Default gateway: $gateway"

            # Ping test
            if ping -c 1 -W 2 "$gateway" &>/dev/null; then
                check_pass "Gateway reachable"
            else
                check_warn "Gateway not reachable"
            fi
        else
            check_warn "No default gateway"
        fi
    fi

    # Check DNS
    if ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
        check_pass "Internet connectivity (1.1.1.1)"
    else
        check_warn "Cannot reach internet (1.1.1.1)"
    fi
}

# ============================================================
# SUMMARY
# ============================================================

print_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Validation Summary${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}Passed:${NC}   $PASS"
    echo -e "  ${YELLOW}Warnings:${NC} $WARN"
    echo -e "  ${RED}Failed:${NC}   $FAIL"
    echo ""

    if [ "$FAIL" -gt 0 ]; then
        echo -e "${RED}❌ Validation FAILED - $FAIL critical issue(s) found${NC}"
        echo ""
        echo "Please fix the failed checks before deploying."
        return 1
    elif [ "$WARN" -gt 0 ]; then
        echo -e "${YELLOW}⚠ Validation completed with $WARN warning(s)${NC}"
        echo ""
        echo "System may work but consider addressing warnings."
        return 0
    else
        echo -e "${GREEN}✓ Validation PASSED - All checks successful${NC}"
        echo ""
        echo "System is ready for deployment."
        return 0
    fi
}

# ============================================================
# QUICK FIX SUGGESTIONS
# ============================================================

suggest_fixes() {
    section "Quick Fixes"

    echo "If you see failures or warnings, try these commands:"
    echo ""
    echo "# Enable IP forwarding"
    echo "echo 1 > /proc/sys/net/ipv4/ip_forward"
    echo ""
    echo "# Load bridge module"
    echo "modprobe bridge"
    echo ""
    echo "# Detect interfaces"
    echo "$SCRIPT_DIR/network-interface-detector.sh detect"
    echo ""
    echo "# Generate WiFi config"
    echo "$SCRIPT_DIR/hostapd-generator.sh configure MySSID MyPassword"
    echo ""
    echo "# Start ModemManager (for LTE)"
    echo "systemctl start ModemManager"
    echo ""
}

# ============================================================
# MAIN
# ============================================================

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --all           Run all validation tests (default)"
    echo "  --interfaces    Test interface detection only"
    echo "  --wifi          Test WiFi detection only"
    echo "  --wwan          Test WWAN/LTE detection only"
    echo "  --connectivity  Test connectivity only"
    echo "  --hostapd       Test hostapd configuration only"
    echo "  --quick         Quick validation (skip slow tests)"
    echo "  --fix           Show suggested fixes"
    echo "  --help          Show this help"
    echo ""
}

main() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  HookProbe Fortress - Network Validation${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    case "${1:-all}" in
        --all|all)
            check_prerequisites
            check_interface_detection
            check_wifi_detection
            check_wwan_detection
            check_network_stack
            check_hostapd_config
            check_dhcp_config
            check_connectivity
            ;;
        --interfaces)
            check_prerequisites
            check_interface_detection
            ;;
        --wifi)
            check_prerequisites
            check_interface_detection
            check_wifi_detection
            check_hostapd_config
            ;;
        --wwan)
            check_prerequisites
            check_interface_detection
            check_wwan_detection
            ;;
        --connectivity)
            check_prerequisites
            check_interface_detection
            check_connectivity
            ;;
        --hostapd)
            check_hostapd_config
            ;;
        --quick)
            check_prerequisites
            check_interface_detection
            check_network_stack
            ;;
        --fix)
            suggest_fixes
            return 0
            ;;
        --help|-h)
            usage
            return 0
            ;;
        *)
            usage
            return 1
            ;;
    esac

    print_summary
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
