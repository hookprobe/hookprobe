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

    # Set ACTIVE route based on current connectivity (SINGLE default route strategy)
    # This ensures traffic uses the WORKING interface, not just lowest metric
    _enr_set_active_route

    ENR_PBR_ACTIVE=true
    _enr_log_info "Minimal PBR active with health-based routing"

    return 0
}

# Set active route - only ONE default route for the healthy interface
# This is critical: metrics don't work when link is UP but traffic isn't flowing
_enr_set_active_route() {
    # IMPORTANT: Check connectivity BEFORE removing routes!
    # Otherwise the connectivity check itself will fail (no route to 8.8.8.8)
    local use_primary=false
    local use_backup=false

    # Check primary connectivity (using gateway ping - doesn't need default route)
    if [ -n "$ENR_PRIMARY_IFACE" ] && [ -n "$ENR_PRIMARY_GATEWAY" ]; then
        if _enr_check_interface_health "$ENR_PRIMARY_IFACE" "$ENR_PRIMARY_GATEWAY"; then
            use_primary=true
        fi
    fi

    # Check backup connectivity
    if [ -n "$ENR_BACKUP_IFACE" ] && [ -n "$ENR_BACKUP_GATEWAY" ]; then
        if _enr_check_interface_health "$ENR_BACKUP_IFACE" "$ENR_BACKUP_GATEWAY"; then
            use_backup=true
        fi
    fi

    # Now remove ALL existing default routes
    local max_tries=5
    while ip route show default 2>/dev/null | grep -q "^default" && [ $max_tries -gt 0 ]; do
        ip route del default 2>/dev/null || break
        max_tries=$((max_tries - 1))
    done

    # Add routes based on connectivity (active interface gets lower metric)
    if [ "$use_primary" = "true" ]; then
        ip route add default via "$ENR_PRIMARY_GATEWAY" dev "$ENR_PRIMARY_IFACE" metric 100 2>/dev/null || true
        ENR_ACTIVE_WAN="$ENR_PRIMARY_IFACE"
        _enr_log_info "Active route: PRIMARY ($ENR_PRIMARY_IFACE via $ENR_PRIMARY_GATEWAY)"

        # Add backup as fallback (higher metric)
        if [ "$use_backup" = "true" ]; then
            ip route add default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" metric 200 2>/dev/null || true
        fi
    elif [ "$use_backup" = "true" ]; then
        # Primary unhealthy, use backup only
        ip route add default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" metric 100 2>/dev/null || true
        ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
        _enr_log_warn "Active route: BACKUP ($ENR_BACKUP_IFACE via $ENR_BACKUP_GATEWAY) - Primary unhealthy!"
    else
        # CRITICAL: Both failed - restore at least one route so traffic can flow
        _enr_log_error "No healthy WAN detected - restoring backup route anyway"
        if [ -n "$ENR_BACKUP_GATEWAY" ] && [ -n "$ENR_BACKUP_IFACE" ]; then
            ip route add default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" metric 100 2>/dev/null || true
            ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
        elif [ -n "$ENR_PRIMARY_GATEWAY" ] && [ -n "$ENR_PRIMARY_IFACE" ]; then
            ip route add default via "$ENR_PRIMARY_GATEWAY" dev "$ENR_PRIMARY_IFACE" metric 100 2>/dev/null || true
            ENR_ACTIVE_WAN="$ENR_PRIMARY_IFACE"
        fi
        return 1
    fi

    return 0
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

        # If we have LTE too, set up PBR for redundancy and start monitoring
        if [ -n "$ENR_BACKUP_IFACE" ]; then
            _enr_setup_minimal_pbr
            # Start background monitor for continuous failover during installation
            enr_start_monitor
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
            enr_start_monitor  # Monitor for primary recovery
            return 0
        fi

        # Try to activate LTE
        if _enr_activate_lte; then
            # CRITICAL: LTE is now active but default route may still point to dead primary!
            # Force traffic through LTE by setting it as the default route
            _enr_log_info "LTE activated - configuring route to use backup..."

            # If we have backup gateway now, force it as default route
            if [ -n "$ENR_BACKUP_GATEWAY" ] && [ -n "$ENR_BACKUP_IFACE" ]; then
                # Remove all default routes (including dead primary)
                local tries=5
                while ip route show default 2>/dev/null | grep -q "^default" && [ $tries -gt 0 ]; do
                    ip route del default 2>/dev/null || break
                    tries=$((tries - 1))
                done

                # Add LTE as default route
                ip route add default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" metric 100 2>/dev/null || true
                _enr_log_info "Default route set via LTE: $ENR_BACKUP_GATEWAY dev $ENR_BACKUP_IFACE"
            fi

            # Now check connectivity (should work since traffic goes through LTE)
            if _enr_check_connectivity "$ENR_BACKUP_IFACE"; then
                ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
                _enr_log_info "Failover to LTE ($ENR_BACKUP_IFACE) successful"
                _enr_setup_minimal_pbr
                enr_start_monitor  # Monitor for primary recovery
                return 0
            else
                _enr_log_warn "LTE connectivity check failed even with direct route"
            fi
        fi
    fi

    # Step 4: Try to detect LTE if we don't have it yet
    if [ -z "$ENR_BACKUP_IFACE" ] && [ "$retry_lte" = "true" ]; then
        _enr_log_info "Looking for LTE modem..."

        # Wait briefly for USB devices
        sleep 2

        if _enr_detect_lte_interface; then
            _enr_log_info "Found LTE interface: $ENR_BACKUP_IFACE"

            if _enr_activate_lte; then
                # Same fix as Step 3: force route through LTE before checking
                if [ -n "$ENR_BACKUP_GATEWAY" ] && [ -n "$ENR_BACKUP_IFACE" ]; then
                    local tries=5
                    while ip route show default 2>/dev/null | grep -q "^default" && [ $tries -gt 0 ]; do
                        ip route del default 2>/dev/null || break
                        tries=$((tries - 1))
                    done
                    ip route add default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" metric 100 2>/dev/null || true
                fi

                if _enr_check_connectivity "$ENR_BACKUP_IFACE"; then
                    ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
                    _enr_log_info "Failover to LTE ($ENR_BACKUP_IFACE) successful"
                    _enr_setup_minimal_pbr
                    enr_start_monitor  # Monitor for primary recovery
                    return 0
                fi
            fi
        fi
    fi

    # Step 5: Last resort - check if primary came back
    if [ -n "$ENR_PRIMARY_IFACE" ] && _enr_check_connectivity "$ENR_PRIMARY_IFACE"; then
        ENR_ACTIVE_WAN="$ENR_PRIMARY_IFACE"
        _enr_log_info "Primary WAN ($ENR_PRIMARY_IFACE) recovered"
        return 0
    fi

    # Step 6: If we have LTE gateway but connectivity check failed, try one more time
    # This handles the case where NM route conflicted with our check
    if [ -n "$ENR_BACKUP_GATEWAY" ] && [ -n "$ENR_BACKUP_IFACE" ]; then
        _enr_log_warn "Last attempt: forcing all traffic through LTE..."

        # Aggressively remove ALL default routes
        local tries=10
        while ip route show default 2>/dev/null | grep -q "^default" && [ $tries -gt 0 ]; do
            ip route del default 2>/dev/null || break
            tries=$((tries - 1))
        done

        # Add LTE as ONLY default route
        ip route add default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" 2>/dev/null || true

        # Give kernel a moment to update routing cache
        sleep 1

        if _enr_check_connectivity "$ENR_BACKUP_IFACE"; then
            ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
            _enr_log_info "LTE failover successful (forced route)"
            return 0
        fi
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
# This ensures failover happens even during long-running operations
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
        local check_interval=10
        local fail_count=0
        local fail_threshold=2
        local last_active="$ENR_ACTIVE_WAN"

        while true; do
            sleep "$check_interval"

            # Check if primary is healthy using the new function that doesn't need default route
            if _enr_check_interface_health "$ENR_PRIMARY_IFACE" "$ENR_PRIMARY_GATEWAY"; then
                fail_count=0

                # If we were on backup and primary recovered, switch back
                if [ "$last_active" = "$ENR_BACKUP_IFACE" ]; then
                    _enr_log_info "Primary WAN recovered - switching back"
                    _enr_set_active_route
                    last_active="$ENR_ACTIVE_WAN"
                fi
            else
                fail_count=$((fail_count + 1))
                _enr_log_warn "Primary connectivity check failed ($fail_count/$fail_threshold)"

                # If failed enough times, switch to backup
                if [ "$fail_count" -ge "$fail_threshold" ]; then
                    # Check if backup is healthy
                    if _enr_check_interface_health "$ENR_BACKUP_IFACE" "$ENR_BACKUP_GATEWAY"; then
                        _enr_log_warn "Primary WAN unhealthy - switching to backup"
                        _enr_set_active_route
                        last_active="$ENR_ACTIVE_WAN"
                        fail_count=0
                    else
                        # Both checks failed, but backup might still work for existing connections
                        # Force switch to backup anyway - better than no connectivity
                        _enr_log_error "Both WANs appear unhealthy - forcing backup route"

                        # Remove all routes and add backup
                        local tries=5
                        while ip route show default 2>/dev/null | grep -q "^default" && [ $tries -gt 0 ]; do
                            ip route del default 2>/dev/null || break
                            tries=$((tries - 1))
                        done

                        ip route add default via "$ENR_BACKUP_GATEWAY" dev "$ENR_BACKUP_IFACE" metric 100 2>/dev/null || true
                        ENR_ACTIVE_WAN="$ENR_BACKUP_IFACE"
                        last_active="$ENR_BACKUP_IFACE"
                        fail_count=0
                    fi
                fi
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
