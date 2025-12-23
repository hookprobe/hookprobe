#!/bin/bash
#
# test-pbr.sh - Policy-Based Routing Test Suite for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Comprehensive testing for WAN failover PBR configuration.
# Run this script to validate your dual-WAN setup.
#
# Usage:
#   ./test-pbr.sh              # Run all tests
#   ./test-pbr.sh --quick      # Quick connectivity tests only
#   ./test-pbr.sh --verbose    # Verbose output
#   ./test-pbr.sh --fix        # Attempt to fix issues found
#
# Exit codes:
#   0 - All tests passed
#   1 - Critical failures (routing broken)
#   2 - Warnings (suboptimal configuration)
#
# Version: 1.0.0
# License: AGPL-3.0

set -u

# ============================================================
# Configuration
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="/etc/hookprobe/wan-failover.conf"
STATE_FILE="/run/fortress/wan-failover.state"
LOG_TAG="fts-pbr-test"

# Test targets
PING_TARGETS="1.1.1.1 8.8.8.8 9.9.9.9"
DNS_TEST_DOMAIN="google.com"
HTTP_TEST_URL="http://httpbin.org/ip"

# Expected values
TABLE_PRIMARY=100
TABLE_BACKUP=200
FWMARK_PRIMARY=0x100
FWMARK_BACKUP=0x200
FWMARK_MASK=0xf00

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0

# Options
VERBOSE=false
QUICK=false
FIX=false

# ============================================================
# Output Helpers
# ============================================================

print_header() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

print_section() {
    echo ""
    echo -e "${BOLD}▸ $1${NC}"
    echo -e "  ─────────────────────────────────────────────────────────────"
}

pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

warn() {
    echo -e "  ${YELLOW}!${NC} $1"
    TESTS_WARNED=$((TESTS_WARNED + 1))
}

info() {
    [ "$VERBOSE" = "true" ] && echo -e "  ${CYAN}ℹ${NC} $1"
}

# ============================================================
# Load Configuration
# ============================================================

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # shellcheck source=/dev/null
        . "$CONFIG_FILE"
        return 0
    fi
    return 1
}

load_state() {
    if [ -f "$STATE_FILE" ]; then
        # shellcheck source=/dev/null
        . "$STATE_FILE"
        return 0
    fi
    return 1
}

# ============================================================
# Test: Prerequisites
# ============================================================

test_prerequisites() {
    print_section "Prerequisites"

    # Root check
    if [ "$EUID" -ne 0 ] && [ "$(id -u)" -ne 0 ]; then
        fail "Must run as root"
        return 1
    fi
    pass "Running as root"

    # Required commands
    local missing=""
    for cmd in ip nft ping curl dig; do
        if ! command -v "$cmd" &>/dev/null; then
            missing="$missing $cmd"
        fi
    done

    if [ -n "$missing" ]; then
        fail "Missing commands:$missing"
        return 1
    fi
    pass "Required commands available"

    # Configuration file
    if [ -f "$CONFIG_FILE" ]; then
        pass "Configuration file exists: $CONFIG_FILE"
        load_config
    else
        fail "Configuration file missing: $CONFIG_FILE"
        return 1
    fi

    # Interface validation
    if [ -z "${PRIMARY_IFACE:-}" ]; then
        fail "PRIMARY_IFACE not configured"
        return 1
    fi
    if [ -z "${BACKUP_IFACE:-}" ]; then
        fail "BACKUP_IFACE not configured"
        return 1
    fi
    pass "Interfaces configured: PRIMARY=$PRIMARY_IFACE, BACKUP=$BACKUP_IFACE"

    return 0
}

# ============================================================
# Test: Interface Status
# ============================================================

test_interfaces() {
    print_section "Interface Status"

    # Primary interface
    if ip link show "$PRIMARY_IFACE" &>/dev/null; then
        local state
        state=$(ip link show "$PRIMARY_IFACE" | grep -oP 'state \K\w+')
        if [ "$state" = "UP" ]; then
            pass "Primary interface $PRIMARY_IFACE is UP"

            # Check for IP address
            local ip_addr
            ip_addr=$(ip -4 addr show "$PRIMARY_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
            if [ -n "$ip_addr" ]; then
                pass "Primary has IP: $ip_addr"
            else
                warn "Primary interface has no IP address"
            fi
        else
            warn "Primary interface $PRIMARY_IFACE state: $state"
        fi
    else
        fail "Primary interface $PRIMARY_IFACE does not exist"
    fi

    # Backup interface
    if ip link show "$BACKUP_IFACE" &>/dev/null; then
        local state
        state=$(ip link show "$BACKUP_IFACE" | grep -oP 'state \K\w+')
        if [ "$state" = "UP" ]; then
            pass "Backup interface $BACKUP_IFACE is UP"

            local ip_addr
            ip_addr=$(ip -4 addr show "$BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
            if [ -n "$ip_addr" ]; then
                pass "Backup has IP: $ip_addr"
            else
                warn "Backup interface has no IP address (may need connection)"
            fi
        else
            warn "Backup interface $BACKUP_IFACE state: $state"
        fi
    else
        warn "Backup interface $BACKUP_IFACE does not exist (LTE modem not connected?)"
    fi
}

# ============================================================
# Test: Routing Tables
# ============================================================

test_routing_tables() {
    print_section "Routing Tables"

    # Check /etc/iproute2/rt_tables
    if grep -q "^$TABLE_PRIMARY" /etc/iproute2/rt_tables 2>/dev/null; then
        pass "Table $TABLE_PRIMARY (wan_primary) registered"
    else
        fail "Table $TABLE_PRIMARY not in /etc/iproute2/rt_tables"
    fi

    if grep -q "^$TABLE_BACKUP" /etc/iproute2/rt_tables 2>/dev/null; then
        pass "Table $TABLE_BACKUP (wan_backup) registered"
    else
        fail "Table $TABLE_BACKUP not in /etc/iproute2/rt_tables"
    fi

    # Check routing table contents
    local primary_routes
    primary_routes=$(ip route show table $TABLE_PRIMARY 2>/dev/null)
    if [ -n "$primary_routes" ]; then
        if echo "$primary_routes" | grep -q "^default"; then
            pass "Table $TABLE_PRIMARY has default route"
            info "$(echo "$primary_routes" | head -1)"
        else
            warn "Table $TABLE_PRIMARY has no default route"
        fi
    else
        fail "Table $TABLE_PRIMARY is empty"
    fi

    local backup_routes
    backup_routes=$(ip route show table $TABLE_BACKUP 2>/dev/null)
    if [ -n "$backup_routes" ]; then
        if echo "$backup_routes" | grep -q "^default"; then
            pass "Table $TABLE_BACKUP has default route"
            info "$(echo "$backup_routes" | head -1)"
        else
            warn "Table $TABLE_BACKUP has no default route (backup WAN down?)"
        fi
    else
        warn "Table $TABLE_BACKUP is empty (backup WAN not configured?)"
    fi

    # Check main table
    local main_default
    main_default=$(ip route show default 2>/dev/null)
    if [ -z "$main_default" ]; then
        pass "Main table has no default route (PBR handles routing)"
    else
        warn "Main table still has default route (may conflict with PBR)"
        info "Main default: $main_default"
    fi
}

# ============================================================
# Test: IP Rules
# ============================================================

test_ip_rules() {
    print_section "IP Rules (Policy Routing)"

    local rules
    rules=$(ip rule show)

    # Primary fwmark rule
    if echo "$rules" | grep -qE "fwmark.*0x100.*table.*(100|wan_primary)"; then
        pass "Rule: fwmark 0x100 → table wan_primary"
    else
        fail "Missing rule: fwmark 0x100 → table wan_primary"
    fi

    # Backup fwmark rule
    if echo "$rules" | grep -qE "fwmark.*0x200.*table.*(200|wan_backup)"; then
        pass "Rule: fwmark 0x200 → table wan_backup"
    else
        fail "Missing rule: fwmark 0x200 → table wan_backup"
    fi

    # Fallback rule
    if echo "$rules" | grep -qE "from all.*table.*(100|wan_primary).*priority 1000"; then
        pass "Fallback rule: priority 1000 → table wan_primary"
    else
        warn "Missing fallback rule (unmarked traffic may fail)"
    fi

    # Source-based routing (for proper return path)
    local primary_ip backup_ip
    primary_ip=$(ip -4 addr show "$PRIMARY_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    backup_ip=$(ip -4 addr show "$BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

    if [ -n "$primary_ip" ]; then
        if echo "$rules" | grep -qE "from $primary_ip.*table.*(100|wan_primary)"; then
            pass "Source rule: from $primary_ip → table wan_primary"
        else
            warn "Missing source rule for $primary_ip (may cause asymmetric routing)"
        fi
    fi

    if [ -n "$backup_ip" ]; then
        if echo "$rules" | grep -qE "from $backup_ip.*table.*(200|wan_backup)"; then
            pass "Source rule: from $backup_ip → table wan_backup"
        else
            warn "Missing source rule for $backup_ip (may cause asymmetric routing)"
        fi
    fi
}

# ============================================================
# Test: nftables Configuration
# ============================================================

test_nftables() {
    print_section "nftables Packet Marking"

    # Check fts_wan_failover table exists
    if nft list table inet fts_wan_failover &>/dev/null; then
        pass "Table inet fts_wan_failover exists"

        # Check chains
        local chains
        chains=$(nft list table inet fts_wan_failover 2>/dev/null)

        # Prerouting chain (conntrack restore)
        if echo "$chains" | grep -q "chain prerouting"; then
            if echo "$chains" | grep -q "ct mark.*meta mark"; then
                pass "Prerouting chain restores conntrack marks"
            else
                warn "Prerouting chain missing conntrack restore rule"
            fi
        else
            fail "Missing prerouting chain"
        fi

        # Output chain (host traffic marking)
        if echo "$chains" | grep -q "chain output"; then
            if echo "$chains" | grep -q "meta mark set 0x[12]00"; then
                local mark
                mark=$(echo "$chains" | grep -oP 'meta mark set 0x[12]00' | tail -1)
                pass "Output chain marks traffic: $mark"
            else
                warn "Output chain has no active marking rule"
            fi
        else
            fail "Missing output chain"
        fi

        # Postrouting chain (conntrack save)
        if echo "$chains" | grep -q "chain postrouting"; then
            if echo "$chains" | grep -q "ct mark set meta mark"; then
                pass "Postrouting chain saves marks to conntrack"
            else
                warn "Postrouting chain missing conntrack save rule"
            fi
        else
            fail "Missing postrouting chain"
        fi
    else
        fail "Table inet fts_wan_failover does not exist"
    fi

    # Check fts_forward_mark table (for container/LAN traffic)
    if nft list table inet fts_forward_mark &>/dev/null; then
        pass "Table inet fts_forward_mark exists"

        local forward_rules
        forward_rules=$(nft list chain inet fts_forward_mark forward 2>/dev/null)
        if echo "$forward_rules" | grep -q "meta mark set"; then
            pass "Forward chain marks container/LAN traffic"
        else
            warn "Forward chain has no marking rules"
        fi
    else
        warn "Table inet fts_forward_mark missing (container traffic may not use PBR)"
    fi

    # Check NAT table
    if nft list table inet fts_nat &>/dev/null; then
        pass "Table inet fts_nat exists"

        if nft list table inet fts_nat 2>/dev/null | grep -q "masquerade"; then
            pass "NAT masquerade rules present"
        else
            warn "No masquerade rules (container/LAN NAT may fail)"
        fi
    else
        warn "Table inet fts_nat missing (run traffic-flow-setup.sh setup)"
    fi
}

# ============================================================
# Test: Health Monitoring
# ============================================================

test_health_monitoring() {
    print_section "Health Monitoring Service"

    # Service status
    if systemctl is-active fts-wan-failover &>/dev/null; then
        pass "fts-wan-failover service is running"
    else
        if systemctl is-enabled fts-wan-failover &>/dev/null; then
            warn "fts-wan-failover service enabled but not running"
        else
            fail "fts-wan-failover service not enabled"
        fi
    fi

    # PID file
    if [ -f "/run/fortress/wan-failover.pid" ]; then
        local pid
        pid=$(cat /run/fortress/wan-failover.pid)
        if kill -0 "$pid" 2>/dev/null; then
            pass "Monitor process running (PID $pid)"
        else
            warn "Stale PID file (process not running)"
        fi
    else
        warn "No PID file (daemon mode not started)"
    fi

    # State file
    if [ -f "$STATE_FILE" ]; then
        pass "State file exists"
        load_state

        echo -e "  ${CYAN}Current state:${NC}"
        echo "    Active WAN:     ${ACTIVE_WAN:-unknown}"
        echo "    Primary:        ${PRIMARY_STATUS:-unknown} (score: ${PRIMARY_COUNT:-0})"
        echo "    Backup:         ${BACKUP_STATUS:-unknown} (score: ${BACKUP_COUNT:-0})"
        echo "    Failover count: ${FAILOVER_COUNT:-0}"
    else
        warn "No state file (run: wan-failover-pbr.sh setup)"
    fi
}

# ============================================================
# Test: Connectivity
# ============================================================

test_connectivity() {
    print_section "Connectivity Tests"

    # Test via primary using enhanced checks
    if [ -n "${PRIMARY_IFACE:-}" ] && ip link show "$PRIMARY_IFACE" &>/dev/null; then
        echo -e "  ${CYAN}Testing via $PRIMARY_IFACE (enhanced checks):${NC}"

        # Check 1: Link state
        local link_state
        link_state=$(ip link show "$PRIMARY_IFACE" | grep -oP 'state \K\w+')
        if [ "$link_state" = "UP" ]; then
            pass "Link state: UP"
        else
            fail "Link state: $link_state"
        fi

        # Check 2: IP address
        local primary_ip
        primary_ip=$(ip -4 addr show "$PRIMARY_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        if [ -n "$primary_ip" ]; then
            pass "IP address: $primary_ip"
        else
            fail "No IP address (DHCP expired?)"
        fi

        # Check 3: Gateway reachable
        if [ -n "$primary_ip" ]; then
            local gateway
            gateway=$(ip route show dev "$PRIMARY_IFACE" 2>/dev/null | grep default | awk '{print $3}' | head -1)
            if [ -n "$gateway" ]; then
                if ping -c 1 -W 1 -I "$PRIMARY_IFACE" "$gateway" &>/dev/null; then
                    pass "Gateway $gateway: reachable"
                else
                    fail "Gateway $gateway: unreachable (link up but no traffic?)"
                fi
            else
                warn "No gateway found"
            fi
        fi

        # Check 4: Internet via source IP (PBR path)
        if [ -n "$primary_ip" ]; then
            local success=0
            for target in $PING_TARGETS; do
                if ping -I "$primary_ip" -c 1 -W 2 -q "$target" &>/dev/null; then
                    success=1
                    pass "Internet via source $primary_ip: OK"
                    break
                fi
            done
            if [ $success -eq 0 ]; then
                fail "Internet via source $primary_ip: FAILED"
            fi
        fi
    fi

    # Test via backup
    if [ -n "${BACKUP_IFACE:-}" ] && ip link show "$BACKUP_IFACE" &>/dev/null; then
        local backup_ip
        backup_ip=$(ip -4 addr show "$BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

        if [ -n "$backup_ip" ]; then
            echo -e "  ${CYAN}Testing via $BACKUP_IFACE:${NC}"

            # Gateway check
            local gateway
            gateway=$(ip route show dev "$BACKUP_IFACE" 2>/dev/null | grep default | awk '{print $3}' | head -1)
            if [ -n "$gateway" ]; then
                if ping -c 1 -W 1 -I "$BACKUP_IFACE" "$gateway" &>/dev/null; then
                    pass "Gateway $gateway: reachable"
                else
                    warn "Gateway $gateway: unreachable"
                fi
            fi

            # Internet check
            local success=0
            for target in $PING_TARGETS; do
                if ping -I "$backup_ip" -c 1 -W 2 -q "$target" &>/dev/null; then
                    success=1
                    pass "Internet via source $backup_ip: OK"
                    break
                fi
            done
            if [ $success -eq 0 ]; then
                warn "Backup WAN has no internet connectivity"
            fi
        else
            warn "Backup interface has no IP (not connected)"
        fi
    fi

    # Test DNS
    echo -e "  ${CYAN}Testing DNS resolution:${NC}"
    if dig +short +timeout=2 "$DNS_TEST_DOMAIN" | grep -q "[0-9]"; then
        pass "DNS resolution working"
    else
        warn "DNS resolution failed (check dnsmasq/dnsXai)"
    fi

    # Test HTTP (verifies NAT + routing + TCP)
    if [ "$QUICK" = "false" ]; then
        echo -e "  ${CYAN}Testing HTTP (full TCP path):${NC}"

        # Test via primary
        if [ -n "${PRIMARY_IFACE:-}" ]; then
            local http_result
            http_result=$(curl -s -m 5 --interface "$PRIMARY_IFACE" "$HTTP_TEST_URL" 2>/dev/null)
            if [ -n "$http_result" ]; then
                local exit_ip
                exit_ip=$(echo "$http_result" | grep -oP '"origin":\s*"\K[^"]+' | head -1)
                pass "HTTP via $PRIMARY_IFACE: OK (exit IP: ${exit_ip:-unknown})"
            else
                warn "HTTP via $PRIMARY_IFACE: FAILED (ICMP may work, TCP blocked?)"
            fi
        fi

        # Test via backup
        if [ -n "${BACKUP_IFACE:-}" ]; then
            local backup_ip
            backup_ip=$(ip -4 addr show "$BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
            if [ -n "$backup_ip" ]; then
                local http_result
                http_result=$(curl -s -m 5 --interface "$BACKUP_IFACE" "$HTTP_TEST_URL" 2>/dev/null)
                if [ -n "$http_result" ]; then
                    local exit_ip
                    exit_ip=$(echo "$http_result" | grep -oP '"origin":\s*"\K[^"]+' | head -1)
                    pass "HTTP via $BACKUP_IFACE: OK (exit IP: ${exit_ip:-unknown})"
                else
                    warn "HTTP via $BACKUP_IFACE: FAILED"
                fi
            fi
        fi
    fi
}

# ============================================================
# Test: Failover Simulation
# ============================================================

test_failover_simulation() {
    print_section "Failover Simulation (Non-Destructive)"

    if [ "$QUICK" = "true" ]; then
        info "Skipping failover simulation (--quick mode)"
        return
    fi

    # Get current state
    load_state 2>/dev/null || true
    local original_wan="${ACTIVE_WAN:-primary}"

    echo -e "  ${CYAN}Current active WAN: $original_wan${NC}"

    # Check if we can test failover
    local backup_ip
    backup_ip=$(ip -4 addr show "$BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

    if [ -z "$backup_ip" ]; then
        warn "Cannot test failover: backup WAN not connected"
        return
    fi

    # Test that we can manually switch marks
    echo -e "  ${CYAN}Verifying mark switching:${NC}"

    # Check current mark
    local current_mark
    current_mark=$(nft list chain inet fts_wan_failover output 2>/dev/null | grep -oP 'meta mark set 0x[12]00' | grep -oP '0x[12]00')
    if [ -n "$current_mark" ]; then
        pass "Current output mark: $current_mark"
    else
        warn "Could not determine current mark"
    fi

    # Verify conntrack integration
    echo -e "  ${CYAN}Checking conntrack marks:${NC}"
    local ct_marked
    ct_marked=$(conntrack -L 2>/dev/null | grep -c "mark=0x[12]00" || echo "0")
    if [ "$ct_marked" -gt 0 ]; then
        pass "Conntrack has $ct_marked marked connections"
    else
        info "No marked connections in conntrack (may be normal)"
    fi
}

# ============================================================
# Test: Configuration Consistency
# ============================================================

test_config_consistency() {
    print_section "Configuration Consistency"

    # Check variable naming consistency
    if [ -f "$CONFIG_FILE" ]; then
        # Check for mismatched variable names
        if grep -q "FAIL_THRESHOLD" "$CONFIG_FILE" && ! grep -q "DOWN_THRESHOLD" "$CONFIG_FILE"; then
            warn "Config uses FAIL_THRESHOLD but script uses DOWN_THRESHOLD"
            info "Consider renaming for consistency"
        fi

        if grep -q "RECOVER_THRESHOLD" "$CONFIG_FILE" && ! grep -q "UP_THRESHOLD" "$CONFIG_FILE"; then
            warn "Config uses RECOVER_THRESHOLD but script uses UP_THRESHOLD"
            info "Consider renaming for consistency"
        fi

        # Check for sane values
        local check_interval="${CHECK_INTERVAL:-5}"
        if [ "$check_interval" -lt 2 ]; then
            warn "CHECK_INTERVAL=$check_interval is very aggressive"
        elif [ "$check_interval" -gt 30 ]; then
            warn "CHECK_INTERVAL=$check_interval may be too slow for SLA"
        else
            pass "CHECK_INTERVAL=$check_interval is reasonable"
        fi
    fi

    # Check gateway configuration
    if [ -n "${PRIMARY_GATEWAY:-}" ]; then
        if ping -c 1 -W 1 "$PRIMARY_GATEWAY" &>/dev/null; then
            pass "Primary gateway $PRIMARY_GATEWAY is reachable"
        else
            warn "Primary gateway $PRIMARY_GATEWAY not responding"
        fi
    else
        info "Primary gateway not configured (auto-discovery)"
    fi

    if [ -n "${BACKUP_GATEWAY:-}" ]; then
        if ping -c 1 -W 1 "$BACKUP_GATEWAY" &>/dev/null; then
            pass "Backup gateway $BACKUP_GATEWAY is reachable"
        else
            warn "Backup gateway $BACKUP_GATEWAY not responding"
        fi
    else
        info "Backup gateway not configured (auto-discovery)"
    fi
}

# ============================================================
# Summary
# ============================================================

# ============================================================
# Installation Flow Resilience Tests
# ============================================================

test_early_network_resilience() {
    print_section "Early Network Resilience"

    local enr_script="${SCRIPT_DIR}/early-network-resilience.sh"

    # Check script exists
    if [ -f "$enr_script" ]; then
        pass "Early network resilience script exists"
    else
        fail "Early network resilience script missing: $enr_script"
        return 1
    fi

    # Check script is executable
    if [ -x "$enr_script" ]; then
        pass "Early network resilience script is executable"
    else
        warn "Early network resilience script not executable"
        if [ "$FIX" = "true" ]; then
            chmod +x "$enr_script"
            pass "Fixed: Made script executable"
        fi
    fi

    # Source the script and test functions
    # shellcheck source=/dev/null
    source "$enr_script" 2>/dev/null || {
        fail "Failed to source early-network-resilience.sh"
        return 1
    }

    # Test that key functions are available
    if type ensure_network_connectivity &>/dev/null; then
        pass "ensure_network_connectivity function available"
    else
        fail "ensure_network_connectivity function not found"
    fi

    if type with_network_resilience &>/dev/null; then
        pass "with_network_resilience function available"
    else
        fail "with_network_resilience function not found"
    fi

    if type enr_status &>/dev/null; then
        pass "enr_status function available"
    else
        warn "enr_status function not found"
    fi

    # Test interface detection
    _enr_detect_primary_wan
    if [ -n "$ENR_PRIMARY_IFACE" ]; then
        pass "Primary WAN detected: $ENR_PRIMARY_IFACE"
    else
        warn "No primary WAN detected (may be expected in some environments)"
    fi

    _enr_detect_lte_interface
    if [ -n "$ENR_BACKUP_IFACE" ]; then
        pass "Backup WAN (LTE) detected: $ENR_BACKUP_IFACE"
    else
        info "No backup WAN detected (LTE modem may not be present)"
    fi

    # Test connectivity function
    if [ -n "$ENR_PRIMARY_IFACE" ]; then
        if _enr_check_connectivity "$ENR_PRIMARY_IFACE"; then
            pass "Connectivity check works on $ENR_PRIMARY_IFACE"
        else
            warn "Connectivity check failed on $ENR_PRIMARY_IFACE"
        fi
    fi
}

test_installation_integration() {
    print_section "Installation Integration"

    local install_script="$(dirname "$SCRIPT_DIR")/../../install-container.sh"

    # Check if install script exists
    if [ -f "$install_script" ]; then
        pass "Install script exists"
    else
        warn "Install script not found at expected location"
        install_script="$(find /home -name 'install-container.sh' -path '*fortress*' 2>/dev/null | head -1)"
        if [ -n "$install_script" ]; then
            pass "Found install script at: $install_script"
        else
            fail "Cannot locate install-container.sh"
            return 1
        fi
    fi

    # Check that install script sources early-network-resilience.sh
    if grep -q "early-network-resilience.sh" "$install_script"; then
        pass "Install script references early-network-resilience.sh"
    else
        fail "Install script does not integrate early-network-resilience.sh"
    fi

    # Check for network-resilient apt wrapper
    if grep -q "_apt_install_resilient" "$install_script"; then
        pass "Install script has network-resilient apt wrapper"
    else
        warn "Install script may not have network-resilient apt wrapper"
    fi

    # Check for network-resilient podman wrapper
    if grep -q "_podman_build_resilient" "$install_script"; then
        pass "Install script has network-resilient podman wrapper"
    else
        warn "Install script may not have network-resilient podman wrapper"
    fi

    # Check for ensure_network_connectivity usage
    if grep -q "ensure_network_connectivity" "$install_script"; then
        pass "Install script uses ensure_network_connectivity"
    else
        fail "Install script does not call ensure_network_connectivity"
    fi
}

test_pbr_transition() {
    print_section "PBR Transition (Minimal → Full)"

    # Check if both scripts exist
    local enr_script="${SCRIPT_DIR}/early-network-resilience.sh"
    local pbr_script="${SCRIPT_DIR}/wan-failover-pbr.sh"

    if [ ! -f "$enr_script" ] || [ ! -f "$pbr_script" ]; then
        warn "Cannot test PBR transition - missing scripts"
        return 0
    fi

    # Source early network resilience
    # shellcheck source=/dev/null
    source "$enr_script" 2>/dev/null || return 1

    # Check that enr_cleanup function exists
    if type enr_cleanup &>/dev/null; then
        pass "enr_cleanup function available for transition"
    else
        fail "enr_cleanup function missing - PBR transition may fail"
    fi

    # Check for enr_cleanup call in install script
    local install_script="$(find /home -name 'install-container.sh' -path '*fortress*' 2>/dev/null | head -1)"
    if [ -n "$install_script" ] && grep -q "enr_cleanup" "$install_script"; then
        pass "Install script calls enr_cleanup before full PBR"
    else
        warn "Install script may not transition from minimal to full PBR properly"
    fi

    # Check that routing tables don't conflict
    if ip rule show 2>/dev/null | grep -q "from.*table 100"; then
        info "Source-based routing rules present (table 100)"
    fi
    if ip rule show 2>/dev/null | grep -q "from.*table 200"; then
        info "Source-based routing rules present (table 200)"
    fi
}

print_summary() {
    print_header "Test Summary"

    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}Warnings:${NC} $TESTS_WARNED"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        if [ $TESTS_WARNED -eq 0 ]; then
            echo -e "  ${GREEN}${BOLD}All tests passed! PBR configuration is healthy.${NC}"
        else
            echo -e "  ${YELLOW}${BOLD}Tests passed with warnings. Review recommendations above.${NC}"
        fi
        return 0
    else
        echo -e "  ${RED}${BOLD}$TESTS_FAILED critical test(s) failed.${NC}"
        echo ""
        echo "  Recommended actions:"
        echo "    1. Run: wan-failover-pbr.sh setup"
        echo "    2. Run: traffic-flow-setup.sh setup"
        echo "    3. Check: systemctl status fts-wan-failover"
        echo "    4. Logs: journalctl -u fts-wan-failover -f"
        return 1
    fi
}

# ============================================================
# Main
# ============================================================

main() {
    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --verbose|-v)
                VERBOSE=true
                ;;
            --quick|-q)
                QUICK=true
                ;;
            --fix|-f)
                FIX=true
                ;;
            --help|-h)
                echo "Usage: $0 [--quick] [--verbose] [--fix]"
                echo ""
                echo "Options:"
                echo "  --quick, -q     Quick tests only (skip HTTP, failover sim)"
                echo "  --verbose, -v   Show detailed output"
                echo "  --fix, -f       Attempt to fix issues found"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
    done

    print_header "HookProbe Fortress - PBR Test Suite"
    echo "  Testing Policy-Based Routing configuration..."
    echo ""

    # Run tests
    test_prerequisites || exit 1
    test_interfaces
    test_routing_tables
    test_ip_rules
    test_nftables
    test_health_monitoring
    test_connectivity
    test_failover_simulation
    test_config_consistency

    # Installation flow resilience tests (new)
    if [ "$QUICK" != "true" ]; then
        test_early_network_resilience
        test_installation_integration
        test_pbr_transition
    fi

    # Summary
    print_summary
}

main "$@"
