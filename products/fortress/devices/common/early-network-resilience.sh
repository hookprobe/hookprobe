#!/bin/bash
#
# early-network-resilience.sh - Early Dual-WAN Failover for Installation
#
# This script provides network resilience DURING installation, ensuring that
# if the primary WAN fails during apt-get, container builds, or any network
# operation, the installation can continue on the backup WAN.
#
# Key Features:
#   - Quick LTE modem detection (no slow scanning)
#   - Emergency LTE activation if primary WAN is down
#   - Minimal PBR setup for immediate failover capability
#   - Can be called multiple times safely (idempotent)
#
# Usage:
#   source early-network-resilience.sh
#   ensure_network_connectivity  # Call when you need network
#
# Version: 1.0.0
# License: AGPL-3.0

# ============================================================
# CONFIGURATION
# ============================================================

# Don't re-source if already loaded
if [ "${EARLY_NET_RESILIENCE_LOADED:-}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi
EARLY_NET_RESILIENCE_LOADED=1

# Colors (only if not already defined)
: "${RED:=\033[0;31m}"
: "${GREEN:=\033[0;32m}"
: "${YELLOW:=\033[1;33m}"
: "${NC:=\033[0m}"

_enr_log_info()  { echo -e "${GREEN}[NET-RESIL]${NC} $1"; }
_enr_log_warn()  { echo -e "${YELLOW}[NET-RESIL]${NC} $1"; }
_enr_log_error() { echo -e "${RED}[NET-RESIL]${NC} $1"; }

# State tracking
ENR_PRIMARY_IFACE=""
ENR_BACKUP_IFACE=""
ENR_PRIMARY_GATEWAY=""
ENR_BACKUP_GATEWAY=""
ENR_ACTIVE_WAN=""
ENR_PBR_ACTIVE=false

# ============================================================
# QUICK INTERFACE DETECTION
# ============================================================

# Detect primary WAN interface (from default route)
_enr_detect_primary_wan() {
    local iface
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)

    if [ -n "$iface" ] && [ -d "/sys/class/net/$iface" ]; then
        ENR_PRIMARY_IFACE="$iface"
        ENR_PRIMARY_GATEWAY=$(ip route show default dev "$iface" 2>/dev/null | awk '{print $3}' | head -1)
        return 0
    fi
    return 1
}

# Quick detection of LTE/WWAN modem (no slow ModemManager queries)
_enr_detect_lte_interface() {
    local iface

    # Method 1: Check existing WWAN interfaces
    for pattern in wwan0 wwan1 wwp0s* wwx*; do
        # shellcheck disable=SC2044
        for iface in /sys/class/net/$pattern; do
            [ -e "$iface" ] || continue  # Skip if glob didn't match
            iface=$(basename "$iface" 2>/dev/null)
            if [ -d "/sys/class/net/$iface" ] && [ "$iface" != "$ENR_PRIMARY_IFACE" ]; then
                ENR_BACKUP_IFACE="$iface"
                return 0
            fi
        done
    done

    # Method 2: Check for USB modems via cdc_ether
    for iface in /sys/class/net/usb* /sys/class/net/eth*; do
        [ -e "$iface" ] || continue  # Skip if glob didn't match
        iface=$(basename "$iface" 2>/dev/null)
        if [ -d "/sys/class/net/$iface" ] && [ "$iface" != "$ENR_PRIMARY_IFACE" ]; then
            # Check if this is a USB modem
            local driver
            driver=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null)
            if [[ "$driver" =~ ^(cdc_ether|cdc_ncm|qmi_wwan|option|sierra)$ ]]; then
                ENR_BACKUP_IFACE="$iface"
                return 0
            fi
        fi
    done

    return 1
}

# ============================================================
# QUICK CONNECTIVITY CHECK
# ============================================================

# Check if an interface has working internet (fast, 2-second timeout)
_enr_check_connectivity() {
    local iface="$1"

    # Check 1: Interface exists and is up
    if [ ! -d "/sys/class/net/$iface" ]; then
        return 1
    fi

    local state
    state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null)
    if [ "$state" != "up" ]; then
        return 1
    fi

    # Check 2: Has IP address
    if ! ip addr show "$iface" 2>/dev/null | grep -q "inet "; then
        return 1
    fi

    # Check 3: Can reach internet (fast check using /dev/tcp)
    # Try multiple targets for reliability
    local iface_ip
    iface_ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)

    if [ -n "$iface_ip" ]; then
        # Use ping with source IP binding for proper routing
        if timeout 2 ping -c1 -W1 -I "$iface_ip" 8.8.8.8 &>/dev/null; then
            return 0
        fi
        if timeout 2 ping -c1 -W1 -I "$iface_ip" 1.1.1.1 &>/dev/null; then
            return 0
        fi
    fi

    # Fallback: TCP check (works even if ICMP is blocked)
    if timeout 2 bash -c "exec 3<>/dev/tcp/8.8.8.8/53" 2>/dev/null; then
        exec 3>&- 2>/dev/null || true
        return 0
    fi

    return 1
}

# ============================================================
# EMERGENCY LTE ACTIVATION
# ============================================================

# Quickly bring up LTE modem for network access
_enr_activate_lte() {
    local iface="$ENR_BACKUP_IFACE"

    if [ -z "$iface" ]; then
        _enr_log_error "No LTE interface to activate"
        return 1
    fi

    _enr_log_info "Emergency LTE activation: $iface"

    # Bring interface up
    ip link set "$iface" up 2>/dev/null || true

    # Method 1: Try ModemManager if available (fastest for preconfigured modems)
    if command -v mmcli &>/dev/null; then
        local modem_idx
        modem_idx=$(mmcli -L 2>/dev/null | grep -oP '/Modem/\K\d+' | head -1)

        if [ -n "$modem_idx" ]; then
            _enr_log_info "Found modem at index $modem_idx"

            # Enable modem
            mmcli -m "$modem_idx" -e 2>/dev/null || true

            # Try simple connect (uses SIM's default APN)
            if mmcli -m "$modem_idx" --simple-connect="" 2>/dev/null; then
                _enr_log_info "LTE connected via ModemManager"
                sleep 2  # Give time for IP assignment

                # Get the bearer interface
                local bearer_iface
                bearer_iface=$(mmcli -m "$modem_idx" --output-keyvalue 2>/dev/null | \
                    grep "modem.generic.ports" | grep -oP '\b(wwan\d+|wwp\S+)' | head -1)

                if [ -n "$bearer_iface" ] && [ -d "/sys/class/net/$bearer_iface" ]; then
                    ENR_BACKUP_IFACE="$bearer_iface"
                fi

                return 0
            fi
        fi
    fi

    # Method 2: Try nmcli for existing connection
    if command -v nmcli &>/dev/null; then
        # Look for GSM/LTE connection
        local gsm_conn
        gsm_conn=$(nmcli -t -f NAME,TYPE con show 2>/dev/null | grep ":gsm" | cut -d: -f1 | head -1)

        if [ -n "$gsm_conn" ]; then
            _enr_log_info "Activating existing connection: $gsm_conn"
            if nmcli con up "$gsm_conn" 2>/dev/null; then
                sleep 2
                return 0
            fi
        fi

        # Try auto-connect on the interface
        if nmcli dev connect "$iface" 2>/dev/null; then
            _enr_log_info "LTE connected via nmcli"
            sleep 2
            return 0
        fi
    fi

    # Method 3: Request DHCP on the interface (for CDC-Ethernet modems)
    if command -v dhclient &>/dev/null; then
        _enr_log_info "Requesting DHCP on $iface..."
        dhclient -1 -v "$iface" 2>/dev/null &
        local dhcp_pid=$!
        sleep 5
        kill "$dhcp_pid" 2>/dev/null || true

        if _enr_check_connectivity "$iface"; then
            return 0
        fi
    fi

    _enr_log_warn "LTE activation may have partially succeeded"
    return 1
}

# ============================================================
# MINIMAL PBR SETUP
# ============================================================

# Setup minimal PBR for immediate failover during installation
_enr_setup_minimal_pbr() {
    if [ "$ENR_PBR_ACTIVE" = "true" ]; then
        return 0  # Already set up
    fi

    if [ -z "$ENR_PRIMARY_IFACE" ] || [ -z "$ENR_BACKUP_IFACE" ]; then
        return 1  # Need both interfaces
    fi

    _enr_log_info "Setting up minimal PBR for installation failover..."

    local TABLE_PRIMARY=100
    local TABLE_BACKUP=200

    # Create routing tables if not exist
    if ! grep -q "wan_primary" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "100 wan_primary" >> /etc/iproute2/rt_tables
    fi
    if ! grep -q "wan_backup" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "200 wan_backup" >> /etc/iproute2/rt_tables
    fi

    # Get gateways
    local primary_gw backup_gw primary_ip backup_ip
    primary_gw=$(ip route show dev "$ENR_PRIMARY_IFACE" 2>/dev/null | grep "default\|via" | awk '/via/ {print $3}' | head -1)
    backup_gw=$(ip route show dev "$ENR_BACKUP_IFACE" 2>/dev/null | grep "default\|via" | awk '/via/ {print $3}' | head -1)

    primary_ip=$(ip -4 addr show "$ENR_PRIMARY_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)
    backup_ip=$(ip -4 addr show "$ENR_BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)

    # Setup primary table
    if [ -n "$primary_gw" ]; then
        ip route flush table $TABLE_PRIMARY 2>/dev/null || true
        ip route add default via "$primary_gw" dev "$ENR_PRIMARY_IFACE" table $TABLE_PRIMARY 2>/dev/null || true

        # Source-based rule for primary
        if [ -n "$primary_ip" ]; then
            ip rule del from "$primary_ip" table $TABLE_PRIMARY 2>/dev/null || true
            ip rule add from "$primary_ip" table $TABLE_PRIMARY priority 50 2>/dev/null || true
        fi
    fi

    # Setup backup table
    if [ -n "$backup_gw" ]; then
        ip route flush table $TABLE_BACKUP 2>/dev/null || true
        ip route add default via "$backup_gw" dev "$ENR_BACKUP_IFACE" table $TABLE_BACKUP 2>/dev/null || true

        # Source-based rule for backup
        if [ -n "$backup_ip" ]; then
            ip rule del from "$backup_ip" table $TABLE_BACKUP 2>/dev/null || true
            ip rule add from "$backup_ip" table $TABLE_BACKUP priority 60 2>/dev/null || true
        fi
    fi

    # Ensure both routes are in main table with proper metrics
    # Primary with lower metric (preferred)
    if [ -n "$primary_gw" ]; then
        ip route del default via "$primary_gw" 2>/dev/null || true
        ip route add default via "$primary_gw" dev "$ENR_PRIMARY_IFACE" metric 100 2>/dev/null || true
    fi

    # Backup with higher metric (failover)
    if [ -n "$backup_gw" ]; then
        ip route del default via "$backup_gw" 2>/dev/null || true
        ip route add default via "$backup_gw" dev "$ENR_BACKUP_IFACE" metric 200 2>/dev/null || true
    fi

    ENR_PBR_ACTIVE=true
    _enr_log_info "Minimal PBR active: $ENR_PRIMARY_IFACE (metric 100) + $ENR_BACKUP_IFACE (metric 200)"

    return 0
}

# ============================================================
# MAIN FUNCTION: ENSURE NETWORK CONNECTIVITY
# ============================================================

# Main entry point - ensures network is available for installation
# Call this before any network-dependent operation
ensure_network_connectivity() {
    local retry_lte="${1:-true}"  # Whether to try LTE if primary fails

    # Step 1: Detect interfaces
    _enr_detect_primary_wan
    _enr_detect_lte_interface

    # Step 2: Check primary WAN connectivity
    if [ -n "$ENR_PRIMARY_IFACE" ] && _enr_check_connectivity "$ENR_PRIMARY_IFACE"; then
        ENR_ACTIVE_WAN="$ENR_PRIMARY_IFACE"
        _enr_log_info "Primary WAN ($ENR_PRIMARY_IFACE) has connectivity"

        # If we have LTE too, set up PBR for redundancy
        if [ -n "$ENR_BACKUP_IFACE" ]; then
            _enr_setup_minimal_pbr
        fi

        return 0
    fi

    _enr_log_warn "Primary WAN connectivity check failed"

    # Step 3: Try backup (LTE) if available
    if [ "$retry_lte" = "true" ] && [ -n "$ENR_BACKUP_IFACE" ]; then
        _enr_log_info "Attempting LTE failover..."

        # Check if LTE already has connectivity
        if _enr_check_connectivity "$ENR_BACKUP_IFACE"; then
            ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
            _enr_log_info "LTE ($ENR_BACKUP_IFACE) already has connectivity"
            _enr_setup_minimal_pbr
            return 0
        fi

        # Try to activate LTE
        if _enr_activate_lte && _enr_check_connectivity "$ENR_BACKUP_IFACE"; then
            ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
            _enr_log_info "Failover to LTE ($ENR_BACKUP_IFACE) successful"
            _enr_setup_minimal_pbr
            return 0
        fi
    fi

    # Step 4: Try to detect LTE if we don't have it yet
    if [ -z "$ENR_BACKUP_IFACE" ] && [ "$retry_lte" = "true" ]; then
        _enr_log_info "Looking for LTE modem..."

        # Wait briefly for USB devices
        sleep 2

        if _enr_detect_lte_interface; then
            _enr_log_info "Found LTE interface: $ENR_BACKUP_IFACE"

            if _enr_activate_lte && _enr_check_connectivity "$ENR_BACKUP_IFACE"; then
                ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
                _enr_log_info "Failover to LTE ($ENR_BACKUP_IFACE) successful"
                _enr_setup_minimal_pbr
                return 0
            fi
        fi
    fi

    # Step 5: Last resort - check if primary came back
    if [ -n "$ENR_PRIMARY_IFACE" ] && _enr_check_connectivity "$ENR_PRIMARY_IFACE"; then
        ENR_ACTIVE_WAN="$ENR_PRIMARY_IFACE"
        _enr_log_info "Primary WAN ($ENR_PRIMARY_IFACE) recovered"
        return 0
    fi

    _enr_log_error "No network connectivity available"
    return 1
}

# Wrapper for network operations with automatic retry on failover
with_network_resilience() {
    local cmd="$*"
    local max_retries=2
    local retry=0

    while [ $retry -lt $max_retries ]; do
        # Ensure network is available
        if ensure_network_connectivity; then
            # Execute the command
            if eval "$cmd"; then
                return 0
            fi

            _enr_log_warn "Command failed, checking network..."
        fi

        retry=$((retry + 1))
        if [ $retry -lt $max_retries ]; then
            _enr_log_info "Retrying with network failover (attempt $((retry + 1))/$max_retries)..."
            sleep 2
        fi
    done

    _enr_log_error "Command failed after $max_retries attempts: $cmd"
    return 1
}

# ============================================================
# STATUS AND CLEANUP
# ============================================================

# Show current network resilience status
enr_status() {
    echo "Early Network Resilience Status"
    echo "================================"
    echo "Primary WAN:    ${ENR_PRIMARY_IFACE:-not detected}"
    echo "Backup WAN:     ${ENR_BACKUP_IFACE:-not detected}"
    echo "Active WAN:     ${ENR_ACTIVE_WAN:-unknown}"
    echo "PBR Active:     $ENR_PBR_ACTIVE"
    echo ""

    if [ -n "$ENR_PRIMARY_IFACE" ]; then
        echo "Primary ($ENR_PRIMARY_IFACE):"
        echo "  State: $(cat /sys/class/net/$ENR_PRIMARY_IFACE/operstate 2>/dev/null || echo 'unknown')"
        echo "  IP: $(ip -4 addr show $ENR_PRIMARY_IFACE 2>/dev/null | grep -oP 'inet \K[0-9./]+' | head -1)"
        echo "  Connectivity: $(_enr_check_connectivity $ENR_PRIMARY_IFACE && echo 'OK' || echo 'FAILED')"
    fi

    if [ -n "$ENR_BACKUP_IFACE" ]; then
        echo "Backup ($ENR_BACKUP_IFACE):"
        echo "  State: $(cat /sys/class/net/$ENR_BACKUP_IFACE/operstate 2>/dev/null || echo 'unknown')"
        echo "  IP: $(ip -4 addr show $ENR_BACKUP_IFACE 2>/dev/null | grep -oP 'inet \K[0-9./]+' | head -1)"
        echo "  Connectivity: $(_enr_check_connectivity $ENR_BACKUP_IFACE && echo 'OK' || echo 'FAILED')"
    fi
}

# Clean up minimal PBR (called when full PBR takes over)
enr_cleanup() {
    if [ "$ENR_PBR_ACTIVE" != "true" ]; then
        return 0
    fi

    _enr_log_info "Cleaning up minimal PBR (full PBR will take over)"

    # Remove source-based rules (we keep the tables for full PBR)
    local primary_ip backup_ip
    primary_ip=$(ip -4 addr show "$ENR_PRIMARY_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)
    backup_ip=$(ip -4 addr show "$ENR_BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)

    ip rule del from "$primary_ip" table 100 2>/dev/null || true
    ip rule del from "$backup_ip" table 200 2>/dev/null || true

    ENR_PBR_ACTIVE=false
}

# Export functions for use by other scripts
export -f ensure_network_connectivity
export -f with_network_resilience
export -f enr_status
export -f enr_cleanup
