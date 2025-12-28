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
                # Wait for IP assignment and route installation (NM needs time)
                _enr_log_info "Waiting for LTE IP and route assignment..."
                local wait_count=0
                while [ $wait_count -lt 10 ]; do
                    sleep 1
                    # Check if we have an IP and default route
                    if _enr_update_backup_gateway_from_nm; then
                        _enr_log_info "LTE gateway detected: $ENR_BACKUP_GATEWAY via $ENR_BACKUP_IFACE"
                        return 0
                    fi
                    wait_count=$((wait_count + 1))
                done
                _enr_log_warn "LTE connected but no gateway detected after 10s"
                return 0  # Still return success - connection is up
            fi
        fi

        # Try auto-connect on the interface
        if nmcli dev connect "$iface" 2>/dev/null; then
            _enr_log_info "LTE connected via nmcli"
            sleep 3
            _enr_update_backup_gateway_from_nm
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
# GATEWAY DETECTION HELPERS
# ============================================================

# Detect backup gateway from NetworkManager routes (called after LTE activation)
_enr_update_backup_gateway_from_nm() {
    # Method 1: Check NetworkManager's active connection for the gateway
    if command -v nmcli &>/dev/null; then
        # Get the active GSM/LTE connection device and gateway
        local nm_info
        nm_info=$(nmcli -t -f DEVICE,TYPE,IP4.GATEWAY dev show 2>/dev/null | grep -A2 "gsm\|cdma" || true)

        if [ -n "$nm_info" ]; then
            local nm_device nm_gateway
            nm_device=$(echo "$nm_info" | grep "^DEVICE:" | cut -d: -f2 | head -1)
            nm_gateway=$(echo "$nm_info" | grep "IP4.GATEWAY" | cut -d: -f2 | head -1)

            if [ -n "$nm_device" ] && [ -n "$nm_gateway" ] && [ "$nm_gateway" != "--" ]; then
                ENR_BACKUP_IFACE="$nm_device"
                ENR_BACKUP_GATEWAY="$nm_gateway"
                return 0
            fi
        fi
    fi

    # Method 2: Look for any default route NOT via primary interface
    local route_line
    route_line=$(ip route show default 2>/dev/null | grep -v "dev $ENR_PRIMARY_IFACE" | head -1)

    if [ -n "$route_line" ]; then
        local gw dev
        gw=$(echo "$route_line" | awk '/via/ {print $3}')
        dev=$(echo "$route_line" | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

        if [ -n "$gw" ] && [ -n "$dev" ]; then
            ENR_BACKUP_IFACE="$dev"
            ENR_BACKUP_GATEWAY="$gw"
            return 0
        fi
    fi

    # Method 3: Check WWAN/LTE interfaces directly for gateway
    for pattern in wwan0 wwan1 wwp* usb0; do
        local iface
        for iface_path in /sys/class/net/$pattern; do
            [ -e "$iface_path" ] || continue
            iface=$(basename "$iface_path")
            [ "$iface" = "$ENR_PRIMARY_IFACE" ] && continue

            # Check if it has an IP
            local iface_ip
            iface_ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)
            [ -z "$iface_ip" ] && continue

            # Try to find gateway from route table
            local gw
            gw=$(ip route show dev "$iface" 2>/dev/null | awk '/default|via/ {print $3}' | head -1)

            # If no explicit gateway, try the first hop (common for PPP/LTE)
            if [ -z "$gw" ]; then
                gw=$(ip route show dev "$iface" 2>/dev/null | grep -E "^[0-9]" | awk '{print $1}' | head -1)
            fi

            if [ -n "$gw" ]; then
                ENR_BACKUP_IFACE="$iface"
                ENR_BACKUP_GATEWAY="$gw"
                return 0
            fi
        done
    done

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

    # Get gateways - use stored values if available, otherwise detect
    local primary_gw backup_gw primary_ip backup_ip

    # Primary gateway: try stored value first, then detect
    if [ -n "$ENR_PRIMARY_GATEWAY" ]; then
        primary_gw="$ENR_PRIMARY_GATEWAY"
    else
        # Method 1: From default route
        primary_gw=$(ip route show default dev "$ENR_PRIMARY_IFACE" 2>/dev/null | awk '{print $3}' | head -1)
        # Method 2: From any route with "via" on the interface
        [ -z "$primary_gw" ] && primary_gw=$(ip route show dev "$ENR_PRIMARY_IFACE" 2>/dev/null | awk '/via/ {print $3}' | head -1)
    fi

    # Backup gateway: use stored value if available (set by _enr_update_backup_gateway_from_nm)
    if [ -n "$ENR_BACKUP_GATEWAY" ]; then
        backup_gw="$ENR_BACKUP_GATEWAY"
    else
        # Try to detect backup gateway
        _enr_update_backup_gateway_from_nm
        backup_gw="$ENR_BACKUP_GATEWAY"
    fi

    primary_ip=$(ip -4 addr show "$ENR_PRIMARY_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)
    backup_ip=$(ip -4 addr show "$ENR_BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)

    _enr_log_info "  Primary: $ENR_PRIMARY_IFACE (gw: ${primary_gw:-none}, ip: ${primary_ip:-none})"
    _enr_log_info "  Backup:  $ENR_BACKUP_IFACE (gw: ${backup_gw:-none}, ip: ${backup_ip:-none})"

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

    # Store gateway info for later use
    ENR_PRIMARY_GATEWAY="$primary_gw"
    ENR_BACKUP_GATEWAY="$backup_gw"

    # Setup BOTH routes with different metrics - kernel uses lowest metric automatically
    # This is the stable approach: routes are constant, we only remove dead ones
    _enr_setup_dual_routes

    ENR_PBR_ACTIVE=true
    _enr_log_info "Dual-route failover active (primary=100, backup=200)"

    return 0
}

# Setup both default routes with different metrics
# Kernel will automatically use lowest metric route that exists
_enr_setup_dual_routes() {
    _enr_log_info "Setting up dual default routes..."

    # First, check what routes already exist
    local existing_routes
    existing_routes=$(ip route show default 2>/dev/null)

    # Add primary route (metric 100) if we have gateway
    if [ -n "$ENR_PRIMARY_GATEWAY" ] && [ -n "$ENR_PRIMARY_IFACE" ]; then
        # Remove any existing route for this interface first (to reset metric)
        ip route del default via "$ENR_PRIMARY_GATEWAY" dev "$ENR_PRIMARY_IFACE" 2>/dev/null || true
        ip route del default dev "$ENR_PRIMARY_IFACE" 2>/dev/null || true

        # Add with metric 100 (preferred)
        if ip route add default via "$ENR_PRIMARY_GATEWAY" dev "$ENR_PRIMARY_IFACE" metric 100 2>/dev/null; then
            _enr_log_info "  Primary route: via $ENR_PRIMARY_GATEWAY dev $ENR_PRIMARY_IFACE metric 100"
        fi
    fi

    # Add backup route (metric 200) if we have gateway
    if [ -n "$ENR_BACKUP_GATEWAY" ] && [ -n "$ENR_BACKUP_IFACE" ]; then
        # Remove any existing route for this interface first (to reset metric)
        ip route del default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" 2>/dev/null || true
        ip route del default dev "$ENR_BACKUP_IFACE" 2>/dev/null || true

        # Add with metric 200 (fallback)
        if ip route add default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" metric 200 2>/dev/null; then
            _enr_log_info "  Backup route:  via $ENR_BACKUP_GATEWAY dev $ENR_BACKUP_IFACE metric 200"
        fi
    fi

    # Show current routing state
    _enr_log_info "Current default routes:"
    ip route show default 2>/dev/null | while read -r line; do
        _enr_log_info "    $line"
    done
}

# Health check - ping Google from each interface, remove route for dead interfaces only
# CRITICAL: Never remove a working route, only dead ones
_enr_remove_dead_routes() {
    local primary_alive=false
    local backup_alive=false

    # Test primary interface by pinging Google with source IP binding
    if [ -n "$ENR_PRIMARY_IFACE" ] && [ -n "$ENR_PRIMARY_GATEWAY" ]; then
        local primary_ip
        primary_ip=$(ip -4 addr show "$ENR_PRIMARY_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)

        if [ -n "$primary_ip" ]; then
            if ping -c1 -W3 -I "$primary_ip" 8.8.8.8 &>/dev/null || \
               ping -c1 -W3 -I "$primary_ip" 1.1.1.1 &>/dev/null; then
                primary_alive=true
                _enr_log_info "Primary ($ENR_PRIMARY_IFACE) can reach internet"
            else
                _enr_log_warn "Primary ($ENR_PRIMARY_IFACE) CANNOT reach internet"
            fi
        else
            _enr_log_warn "Primary ($ENR_PRIMARY_IFACE) has no IP"
        fi
    fi

    # Test backup interface
    if [ -n "$ENR_BACKUP_IFACE" ] && [ -n "$ENR_BACKUP_GATEWAY" ]; then
        local backup_ip
        backup_ip=$(ip -4 addr show "$ENR_BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)

        if [ -n "$backup_ip" ]; then
            if ping -c1 -W3 -I "$backup_ip" 8.8.8.8 &>/dev/null || \
               ping -c1 -W3 -I "$backup_ip" 1.1.1.1 &>/dev/null; then
                backup_alive=true
                _enr_log_info "Backup ($ENR_BACKUP_IFACE) can reach internet"
            else
                _enr_log_warn "Backup ($ENR_BACKUP_IFACE) CANNOT reach internet"
            fi
        else
            _enr_log_warn "Backup ($ENR_BACKUP_IFACE) has no IP"
        fi
    fi

    # Only remove routes for DEAD interfaces - never touch working ones
    if [ "$primary_alive" = "false" ] && [ -n "$ENR_PRIMARY_GATEWAY" ]; then
        _enr_log_warn "Removing dead primary route..."
        ip route del default via "$ENR_PRIMARY_GATEWAY" dev "$ENR_PRIMARY_IFACE" 2>/dev/null || true
    fi

    if [ "$backup_alive" = "false" ] && [ -n "$ENR_BACKUP_GATEWAY" ]; then
        _enr_log_warn "Removing dead backup route..."
        ip route del default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" 2>/dev/null || true
    fi

    # Update active WAN tracking
    if [ "$primary_alive" = "true" ]; then
        ENR_ACTIVE_WAN="$ENR_PRIMARY_IFACE"
    elif [ "$backup_alive" = "true" ]; then
        ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
    fi

    # Return success if at least one interface works
    if [ "$primary_alive" = "true" ] || [ "$backup_alive" = "true" ]; then
        return 0
    fi

    return 1
}

# Re-add route for recovered interface (called by monitor when interface recovers)
_enr_restore_route() {
    local iface="$1"
    local gateway="$2"
    local metric="$3"

    # Check if route already exists
    if ip route show default via "$gateway" dev "$iface" 2>/dev/null | grep -q "default"; then
        return 0  # Already exists
    fi

    _enr_log_info "Restoring route: via $gateway dev $iface metric $metric"
    ip route add default via "$gateway" dev "$iface" metric "$metric" 2>/dev/null || true
}

# Check interface health without requiring default route
# Uses gateway ping (direct route exists) and link state
_enr_check_interface_health() {
    local iface="$1"
    local gateway="$2"

    # Check 1: Interface exists
    if [ ! -d "/sys/class/net/$iface" ]; then
        return 1
    fi

    # Check 2: Link state (carrier)
    local carrier
    carrier=$(cat "/sys/class/net/$iface/carrier" 2>/dev/null || echo "0")
    if [ "$carrier" != "1" ]; then
        _enr_log_debug "[$iface] No carrier (link down)"
        return 1
    fi

    # Check 3: Has IP address
    local iface_ip
    iface_ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)
    if [ -z "$iface_ip" ]; then
        _enr_log_debug "[$iface] No IP address"
        return 1
    fi

    # Check 4: Can reach gateway (direct route, doesn't need default)
    if [ -n "$gateway" ]; then
        if ! ping -c1 -W2 -I "$iface" "$gateway" &>/dev/null; then
            _enr_log_debug "[$iface] Gateway $gateway unreachable"
            return 1
        fi
    fi

    # Check 5: Can reach internet via this interface
    # Add temporary route, check, remove
    local temp_route_added=false
    if ! ip route show default dev "$iface" 2>/dev/null | grep -q "default"; then
        ip route add default via "$gateway" dev "$iface" metric 999 2>/dev/null && temp_route_added=true
    fi

    local internet_ok=false
    if ping -c1 -W2 -I "$iface_ip" 8.8.8.8 &>/dev/null || \
       ping -c1 -W2 -I "$iface_ip" 1.1.1.1 &>/dev/null; then
        internet_ok=true
    fi

    # Remove temporary route if we added it
    if [ "$temp_route_added" = "true" ]; then
        ip route del default via "$gateway" dev "$iface" metric 999 2>/dev/null || true
    fi

    if [ "$internet_ok" = "true" ]; then
        return 0
    fi

    _enr_log_debug "[$iface] Internet unreachable"
    return 1
}

_enr_log_debug() {
    [ "${DEBUG:-0}" = "1" ] && echo -e "${CYAN}[NET-RESIL-DBG]${NC} $1"
}

# ============================================================
# MAIN FUNCTION: ENSURE NETWORK CONNECTIVITY
# ============================================================

# Main entry point - ensures network is available for installation
# STABLE APPROACH: Setup both routes with metrics, only remove dead ones
ensure_network_connectivity() {
    local retry_lte="${1:-true}"  # Whether to try LTE if primary fails

    _enr_log_info "Checking network connectivity..."

    # Step 1: Detect interfaces
    _enr_detect_primary_wan
    _enr_detect_lte_interface

    # Step 2: Get primary gateway if we have primary interface
    if [ -n "$ENR_PRIMARY_IFACE" ] && [ -z "$ENR_PRIMARY_GATEWAY" ]; then
        ENR_PRIMARY_GATEWAY=$(ip route show default dev "$ENR_PRIMARY_IFACE" 2>/dev/null | awk '{print $3}' | head -1)
        [ -z "$ENR_PRIMARY_GATEWAY" ] && ENR_PRIMARY_GATEWAY=$(ip route show dev "$ENR_PRIMARY_IFACE" 2>/dev/null | awk '/via/ {print $3}' | head -1)
    fi

    # Step 3: If LTE interface exists but no gateway, try to activate it
    if [ "$retry_lte" = "true" ] && [ -n "$ENR_BACKUP_IFACE" ] && [ -z "$ENR_BACKUP_GATEWAY" ]; then
        _enr_log_info "LTE interface found ($ENR_BACKUP_IFACE), activating..."
        _enr_activate_lte
    fi

    # Step 4: Try to detect LTE if we don't have it yet
    if [ -z "$ENR_BACKUP_IFACE" ] && [ "$retry_lte" = "true" ]; then
        _enr_log_info "Looking for LTE modem..."
        sleep 2
        if _enr_detect_lte_interface; then
            _enr_log_info "Found LTE interface: $ENR_BACKUP_IFACE"
            _enr_activate_lte
        fi
    fi

    # Step 5: Setup BOTH routes with different metrics
    # This is the stable foundation - we NEVER remove all routes at once
    _enr_log_info "Setting up dual-WAN routes..."

    # Show what we have
    _enr_log_info "  Primary: ${ENR_PRIMARY_IFACE:-none} (gw: ${ENR_PRIMARY_GATEWAY:-none})"
    _enr_log_info "  Backup:  ${ENR_BACKUP_IFACE:-none} (gw: ${ENR_BACKUP_GATEWAY:-none})"

    # Add primary route (metric 100) - will be preferred if working
    if [ -n "$ENR_PRIMARY_GATEWAY" ] && [ -n "$ENR_PRIMARY_IFACE" ]; then
        ip route del default via "$ENR_PRIMARY_GATEWAY" dev "$ENR_PRIMARY_IFACE" 2>/dev/null || true
        ip route add default via "$ENR_PRIMARY_GATEWAY" dev "$ENR_PRIMARY_IFACE" metric 100 2>/dev/null || true
        _enr_log_info "Added primary route: metric 100"
    fi

    # Add backup route (metric 200) - automatic fallback
    if [ -n "$ENR_BACKUP_GATEWAY" ] && [ -n "$ENR_BACKUP_IFACE" ]; then
        ip route del default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" 2>/dev/null || true
        ip route add default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" metric 200 2>/dev/null || true
        _enr_log_info "Added backup route: metric 200"
    fi

    # Step 6: Test both interfaces and ONLY remove dead routes
    _enr_log_info "Testing connectivity on each interface..."
    if _enr_remove_dead_routes; then
        _enr_log_info "Network ready - active WAN: $ENR_ACTIVE_WAN"

        # Start background monitor for continuous health checking
        if [ -n "$ENR_PRIMARY_IFACE" ] && [ -n "$ENR_BACKUP_IFACE" ]; then
            enr_start_monitor
        fi

        return 0
    fi

    # Step 7: Both failed - at least ensure one route exists for retry
    _enr_log_error "Both WANs failed connectivity test"

    # Keep at least backup route if we have it (don't remove anything more)
    if [ -n "$ENR_BACKUP_GATEWAY" ] && [ -n "$ENR_BACKUP_IFACE" ]; then
        ip route replace default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" metric 200 2>/dev/null || true
        _enr_log_warn "Keeping backup route for retry attempts"
        ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
        return 0  # Return success - let the command retry
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
# BACKGROUND HEALTH MONITOR FOR INSTALLATION
# ============================================================

# PID file for background monitor
ENR_MONITOR_PID=""
ENR_MONITOR_PIDFILE="/run/enr-health-monitor.pid"

# Start background health monitor during installation
# STABLE APPROACH: Only remove dead routes, restore recovered ones
# Never touch working routes - kernel handles metric-based failover automatically
enr_start_monitor() {
    if [ -n "$ENR_MONITOR_PID" ] && kill -0 "$ENR_MONITOR_PID" 2>/dev/null; then
        _enr_log_info "Health monitor already running (PID $ENR_MONITOR_PID)"
        return 0
    fi

    # Need both interfaces for monitoring to make sense
    if [ -z "$ENR_PRIMARY_IFACE" ] || [ -z "$ENR_BACKUP_IFACE" ]; then
        _enr_log_info "Single WAN mode - no monitor needed"
        return 0
    fi

    _enr_log_info "Starting background health monitor..."

    # Run monitor in background
    (
        local check_interval=15
        local primary_was_dead=false
        local backup_was_dead=false

        while true; do
            sleep "$check_interval"

            # Get current IPs for testing
            local primary_ip backup_ip
            primary_ip=$(ip -4 addr show "$ENR_PRIMARY_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)
            backup_ip=$(ip -4 addr show "$ENR_BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)

            # Test PRIMARY interface
            local primary_alive=false
            if [ -n "$primary_ip" ]; then
                if ping -c1 -W3 -I "$primary_ip" 8.8.8.8 &>/dev/null; then
                    primary_alive=true
                fi
            fi

            # Test BACKUP interface
            local backup_alive=false
            if [ -n "$backup_ip" ]; then
                if ping -c1 -W3 -I "$backup_ip" 8.8.8.8 &>/dev/null; then
                    backup_alive=true
                fi
            fi

            # Handle PRIMARY state changes
            if [ "$primary_alive" = "true" ]; then
                if [ "$primary_was_dead" = "true" ]; then
                    _enr_log_info "Primary WAN recovered - restoring route (metric 100)"
                    ip route add default via "$ENR_PRIMARY_GATEWAY" dev "$ENR_PRIMARY_IFACE" metric 100 2>/dev/null || true
                    primary_was_dead=false
                fi
            else
                if [ "$primary_was_dead" = "false" ] && [ -n "$ENR_PRIMARY_GATEWAY" ]; then
                    _enr_log_warn "Primary WAN dead - removing route"
                    ip route del default via "$ENR_PRIMARY_GATEWAY" dev "$ENR_PRIMARY_IFACE" 2>/dev/null || true
                    primary_was_dead=true
                fi
            fi

            # Handle BACKUP state changes
            if [ "$backup_alive" = "true" ]; then
                if [ "$backup_was_dead" = "true" ]; then
                    _enr_log_info "Backup WAN recovered - restoring route (metric 200)"
                    ip route add default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" metric 200 2>/dev/null || true
                    backup_was_dead=false
                fi
            else
                if [ "$backup_was_dead" = "false" ] && [ -n "$ENR_BACKUP_GATEWAY" ]; then
                    _enr_log_warn "Backup WAN dead - removing route"
                    ip route del default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" 2>/dev/null || true
                    backup_was_dead=true
                fi
            fi

            # Update active WAN tracking
            if [ "$primary_alive" = "true" ]; then
                ENR_ACTIVE_WAN="$ENR_PRIMARY_IFACE"
            elif [ "$backup_alive" = "true" ]; then
                ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
            fi
        done
    ) &
    ENR_MONITOR_PID=$!
    echo "$ENR_MONITOR_PID" > "$ENR_MONITOR_PIDFILE"
    _enr_log_info "Health monitor started (PID $ENR_MONITOR_PID)"
}

# Stop background health monitor
enr_stop_monitor() {
    # Kill by PID variable
    if [ -n "$ENR_MONITOR_PID" ] && kill -0 "$ENR_MONITOR_PID" 2>/dev/null; then
        kill "$ENR_MONITOR_PID" 2>/dev/null || true
        _enr_log_info "Health monitor stopped (PID $ENR_MONITOR_PID)"
        ENR_MONITOR_PID=""
    fi

    # Also try PID file
    if [ -f "$ENR_MONITOR_PIDFILE" ]; then
        local pid
        pid=$(cat "$ENR_MONITOR_PIDFILE" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
        rm -f "$ENR_MONITOR_PIDFILE"
    fi
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
    # Stop background health monitor
    enr_stop_monitor

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
export -f enr_start_monitor
export -f enr_stop_monitor
