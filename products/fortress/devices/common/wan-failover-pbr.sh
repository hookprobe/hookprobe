#!/bin/bash
#
# wan-failover-pbr.sh - Policy-Based Routing WAN Failover for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Implements mwan3-style intelligent failover using:
#   - Multiple routing tables (one per WAN)
#   - Firewall marks (fwmark) for traffic classification
#   - ip rules to direct traffic to specific tables
#   - Hysteresis to prevent route flapping
#   - Sticky sessions (connections survive failover)
#
# Architecture:
#   Table 100 (wan_primary):   Default route via primary WAN (wired)
#   Table 200 (wan_backup):    Default route via backup WAN (LTE/modem)
#   Main table:                No default route (all traffic uses rules)
#
# Traffic Flow:
#   1. New connection → Mark based on active WAN → Route via marked table
#   2. Existing connection → Conntrack preserves mark → Same WAN
#   3. Health check fails → Update rules → New connections use backup
#   4. Old connections on failed WAN timeout naturally
#
# Usage:
#   wan-failover-pbr.sh setup        # Initial setup (run once at boot)
#   wan-failover-pbr.sh start        # Start monitoring daemon
#   wan-failover-pbr.sh stop         # Stop monitoring
#   wan-failover-pbr.sh status       # Show current status
#   wan-failover-pbr.sh failover     # Force failover to backup
#   wan-failover-pbr.sh failback     # Force failback to primary
#   wan-failover-pbr.sh check        # Single health check (for cron)
#
# Configuration: /etc/hookprobe/wan-failover.conf
#
# Version: 2.0.0
# License: AGPL-3.0

set -u

# ============================================================
# Configuration
# ============================================================

CONFIG_FILE="/etc/hookprobe/wan-failover.conf"
STATE_FILE="/run/fortress/wan-failover.state"
PID_FILE="/run/fortress/wan-failover.pid"
LOG_TAG="fts-wan-pbr"

# Routing table IDs (must match /etc/iproute2/rt_tables)
TABLE_PRIMARY=100
TABLE_BACKUP=200
TABLE_NAME_PRIMARY="wan_primary"
TABLE_NAME_BACKUP="wan_backup"

# Firewall marks
FWMARK_PRIMARY=0x100
FWMARK_BACKUP=0x200
FWMARK_MASK=0xf00

# Default health check settings
PING_TARGETS="1.1.1.1 8.8.8.8 9.9.9.9"
PING_COUNT=2
PING_TIMEOUT=3
CHECK_INTERVAL=5

# Hysteresis settings (prevent flapping)
# Note: Config file may use FAIL_THRESHOLD/RECOVER_THRESHOLD - we map them below
UP_THRESHOLD=3      # Require X consecutive successes to mark UP
DOWN_THRESHOLD=3    # Require X consecutive failures to mark DOWN

# DNS failover settings
DNS_FAILOVER_ENABLED="${DNS_FAILOVER_ENABLED:-true}"
PRIMARY_DNS="${PRIMARY_DNS:-}"
BACKUP_DNS="${BACKUP_DNS:-}"

# ============================================================
# Logging
# ============================================================

log_info()  { logger -t "$LOG_TAG" "$1"; echo "[INFO] $1"; }
log_warn()  { logger -t "$LOG_TAG" -p warning "$1"; echo "[WARN] $1"; }
log_error() { logger -t "$LOG_TAG" -p err "$1"; echo "[ERROR] $1" >&2; }
log_debug() { [ "${DEBUG:-0}" = "1" ] && logger -t "$LOG_TAG" -p debug "$1"; }

# ============================================================
# Load Configuration
# ============================================================

load_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        return 1
    fi

    # shellcheck source=/dev/null
    . "$CONFIG_FILE"

    # Validate required settings
    if [ -z "${PRIMARY_IFACE:-}" ] || [ -z "${BACKUP_IFACE:-}" ]; then
        log_error "PRIMARY_IFACE and BACKUP_IFACE must be set in $CONFIG_FILE"
        return 1
    fi

    # Set defaults
    PRIMARY_GATEWAY="${PRIMARY_GATEWAY:-}"
    BACKUP_GATEWAY="${BACKUP_GATEWAY:-}"
    PING_TARGETS="${PING_TARGETS:-${HEALTH_TARGETS:-1.1.1.1 8.8.8.8 9.9.9.9}}"
    CHECK_INTERVAL="${CHECK_INTERVAL:-5}"

    # Map config file variable names (FAIL_THRESHOLD/RECOVER_THRESHOLD) to script names
    # This maintains backward compatibility with existing config files
    UP_THRESHOLD="${UP_THRESHOLD:-${RECOVER_THRESHOLD:-3}}"
    DOWN_THRESHOLD="${DOWN_THRESHOLD:-${FAIL_THRESHOLD:-3}}"

    # DNS failover settings
    DNS_FAILOVER_ENABLED="${DNS_FAILOVER_ENABLED:-true}"
    PRIMARY_DNS="${PRIMARY_DNS:-}"
    BACKUP_DNS="${BACKUP_DNS:-}"

    return 0
}

# ============================================================
# Gateway Discovery
# ============================================================

get_gateway() {
    # Discover gateway for an interface using multiple methods
    # Priority: nmcli > ip route > DHCP lease > ARP scan
    local iface="$1"
    local gw

    # Method 1: NetworkManager (most reliable when available)
    if command -v nmcli &>/dev/null; then
        gw=$(nmcli -t -f IP4.GATEWAY device show "$iface" 2>/dev/null | cut -d: -f2 | grep -v '^$' | head -1)
        if [ -n "$gw" ] && [ "$gw" != "--" ]; then
            echo "$gw"
            return 0
        fi
    fi

    # Method 2: ip route (works for static routes and some DHCP setups)
    gw=$(ip route show dev "$iface" 2>/dev/null | grep -E '^default|^0\.0\.0\.0' | awk '{print $3}' | head -1)
    if [ -n "$gw" ]; then
        echo "$gw"
        return 0
    fi

    # Method 3: Check routing table for the interface's network
    local iface_ip
    iface_ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    if [ -n "$iface_ip" ]; then
        # Get the network and find a gateway
        local network
        network=$(ip route show dev "$iface" 2>/dev/null | grep "$iface_ip" | head -1 | awk '{print $1}')
        if [ -n "$network" ]; then
            # Look for a gateway in this network (usually .1 or .254)
            local base
            base=$(echo "$iface_ip" | cut -d. -f1-3)
            for gw_candidate in "${base}.1" "${base}.254"; do
                if ping -c 1 -W 1 -I "$iface" "$gw_candidate" &>/dev/null; then
                    echo "$gw_candidate"
                    return 0
                fi
            done
        fi
    fi

    # Method 4: DHCP lease file (NetworkManager)
    if [ -f "/var/lib/NetworkManager/dhclient-$iface.lease" ]; then
        gw=$(grep 'option routers' "/var/lib/NetworkManager/dhclient-$iface.lease" 2>/dev/null | tail -1 | awk '{print $3}' | tr -d ';')
        [ -n "$gw" ] && echo "$gw" && return 0
    fi

    # Method 5: DHCP lease file (dhclient)
    if [ -f "/var/lib/dhcp/dhclient.$iface.leases" ]; then
        gw=$(grep 'option routers' "/var/lib/dhcp/dhclient.$iface.leases" 2>/dev/null | tail -1 | awk '{print $3}' | tr -d ';')
        [ -n "$gw" ] && echo "$gw" && return 0
    fi

    # Method 6: For WWAN/LTE interfaces, check ModemManager
    if [[ "$iface" =~ ^wwan|^wwp ]]; then
        if command -v mmcli &>/dev/null; then
            local modem_idx
            modem_idx=$(mmcli -L 2>/dev/null | grep -oP 'Modem/\K\d+' | head -1)
            if [ -n "$modem_idx" ]; then
                local bearer_idx
                bearer_idx=$(mmcli -m "$modem_idx" 2>/dev/null | grep -oP 'Bearer/\K\d+' | head -1)
                if [ -n "$bearer_idx" ]; then
                    gw=$(mmcli -b "$bearer_idx" 2>/dev/null | grep -oP 'gateway:\s*\K[\d.]+')
                    [ -n "$gw" ] && echo "$gw" && return 0
                fi
            fi
        fi
    fi

    return 1
}

discover_gateways() {
    # Discover gateways for both interfaces
    # Forces rediscovery even if values are set (they may have changed)

    local old_primary="${PRIMARY_GATEWAY:-}"
    local old_backup="${BACKUP_GATEWAY:-}"

    # Always try to discover current gateway (DHCP may have renewed)
    local new_primary
    new_primary=$(get_gateway "$PRIMARY_IFACE")
    if [ -n "$new_primary" ]; then
        PRIMARY_GATEWAY="$new_primary"
        if [ "$new_primary" != "$old_primary" ] && [ -n "$old_primary" ]; then
            log_info "Primary gateway changed: $old_primary -> $new_primary"
        fi
    elif [ -z "$PRIMARY_GATEWAY" ]; then
        log_warn "Could not discover gateway for $PRIMARY_IFACE"
    fi

    local new_backup
    new_backup=$(get_gateway "$BACKUP_IFACE")
    if [ -n "$new_backup" ]; then
        BACKUP_GATEWAY="$new_backup"
        if [ "$new_backup" != "$old_backup" ] && [ -n "$old_backup" ]; then
            log_info "Backup gateway changed: $old_backup -> $new_backup"
        fi
    elif [ -z "$BACKUP_GATEWAY" ]; then
        log_debug "Could not discover gateway for $BACKUP_IFACE (may not be connected)"
    fi
}

# ============================================================
# Routing Table Setup
# ============================================================

setup_rt_tables() {
    log_info "Setting up routing tables..."

    # Add table names to /etc/iproute2/rt_tables if not present
    if ! grep -q "^$TABLE_PRIMARY" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "$TABLE_PRIMARY $TABLE_NAME_PRIMARY" >> /etc/iproute2/rt_tables
        log_info "Added table $TABLE_PRIMARY ($TABLE_NAME_PRIMARY)"
    fi

    if ! grep -q "^$TABLE_BACKUP" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "$TABLE_BACKUP $TABLE_NAME_BACKUP" >> /etc/iproute2/rt_tables
        log_info "Added table $TABLE_BACKUP ($TABLE_NAME_BACKUP)"
    fi
}

# Prevent NetworkManager from adding routes on WAN interfaces
# This is critical - NM adds routes that override our PBR routes
# We configure connections to never add default routes or auto-routes
configure_networkmanager_no_default_route() {
    log_info "Configuring NetworkManager to not add routes on WAN interfaces..."

    # Skip if NetworkManager is not installed
    if ! command -v nmcli &>/dev/null; then
        log_debug "NetworkManager not installed, skipping"
        return 0
    fi

    # For each WAN interface, find its connection and configure it
    for iface in "$PRIMARY_IFACE" "$BACKUP_IFACE"; do
        # Find the connection name for this interface
        local conn_name
        conn_name=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | grep ":${iface}$" | cut -d: -f1 | head -1)

        if [ -z "$conn_name" ]; then
            # Try inactive connections too
            conn_name=$(nmcli -t -f NAME,DEVICE connection show 2>/dev/null | grep ":${iface}$" | cut -d: -f1 | head -1)
        fi

        if [ -n "$conn_name" ]; then
            log_info "Configuring connection '$conn_name' ($iface) to not add routes..."

            # Prevent this connection from becoming the default gateway
            nmcli connection modify "$conn_name" ipv4.never-default yes 2>/dev/null || true

            # Prevent DHCP-provided routes (classless static routes) from being added
            nmcli connection modify "$conn_name" ipv4.ignore-auto-routes yes 2>/dev/null || true

            # Same for IPv6
            nmcli connection modify "$conn_name" ipv6.never-default yes 2>/dev/null || true
            nmcli connection modify "$conn_name" ipv6.ignore-auto-routes yes 2>/dev/null || true

            # Reapply the connection to take effect immediately
            nmcli connection up "$conn_name" 2>/dev/null || true

            log_info "$iface ($conn_name): never-default=yes, ignore-auto-routes=yes"
        else
            log_warn "No NetworkManager connection found for $iface"
        fi
    done

    log_info "NetworkManager configured to not add routes on WAN interfaces"
}

# Configure netplan to not add routes on WAN interfaces (Ubuntu/Debian with netplan)
# NOTE: This only works for DHCP-based configs. For static routes defined in netplan,
# we must either modify the existing config or rely on cleanup_stray_routes()
configure_netplan_no_routes() {
    log_info "Checking for netplan configuration..."

    # Skip if netplan is not installed
    if ! command -v netplan &>/dev/null; then
        log_debug "Netplan not installed, skipping"
        return 0
    fi

    # Check existing netplan files for static routes on our WAN interfaces
    # If static routes exist, warn and skip - we can't override those with dhcp4-overrides
    local has_static_routes=false
    for iface in "$PRIMARY_IFACE" "$BACKUP_IFACE"; do
        if grep -r "routes:" /etc/netplan/*.yaml 2>/dev/null | grep -q "$iface" || \
           grep -rA5 "$iface:" /etc/netplan/*.yaml 2>/dev/null | grep -q "to:.*default"; then
            log_warn "Found static route for $iface in netplan - cannot override with dhcp4-overrides"
            log_warn "To prevent automatic routes, remove the 'routes:' section from your netplan config"
            log_warn "PBR failover will manage routes via cleanup_stray_routes() instead"
            has_static_routes=true
        fi
    done

    if [ "$has_static_routes" = "true" ]; then
        log_info "Skipping netplan dhcp4-overrides (static routes detected)"
        return 0
    fi

    # Check if interfaces use DHCP in netplan
    local uses_dhcp=false
    for iface in "$PRIMARY_IFACE" "$BACKUP_IFACE"; do
        if grep -rA5 "$iface:" /etc/netplan/*.yaml 2>/dev/null | grep -q "dhcp4: true"; then
            uses_dhcp=true
            break
        fi
    done

    if [ "$uses_dhcp" = "false" ]; then
        log_debug "No DHCP-based WAN interfaces in netplan, skipping dhcp4-overrides"
        return 0
    fi

    local netplan_dir="/etc/netplan"
    local netplan_file="${netplan_dir}/99-fortress-wan-no-routes.yaml"

    # Create netplan override to prevent DHCP WAN interfaces from adding routes
    mkdir -p "$netplan_dir"

    cat > "$netplan_file" << EOF
# HookProbe Fortress - WAN interfaces managed by PBR failover
# Generated: $(date -Iseconds)
# This prevents DHCP WAN interfaces from adding default routes
# NOTE: Only applies to DHCP configs, not static routes
network:
  version: 2
  ethernets:
    ${PRIMARY_IFACE}:
      dhcp4-overrides:
        use-routes: false
        use-dns: false
    ${BACKUP_IFACE}:
      dhcp4-overrides:
        use-routes: false
        use-dns: false
EOF

    chmod 600 "$netplan_file"

    # Apply netplan changes
    if netplan apply 2>/dev/null; then
        log_info "Netplan configured to not add routes on DHCP WAN interfaces"
    else
        log_warn "Failed to apply netplan configuration"
    fi
}

# Configure ModemManager to not add default routes from carrier DHCP
# This prevents the LTE carrier from pushing routes that interfere with PBR
configure_modemmanager_no_routes() {
    log_info "Configuring ModemManager to not add carrier routes..."

    # Skip if ModemManager is not installed
    if ! command -v mmcli &>/dev/null; then
        log_debug "ModemManager not installed, skipping"
        return 0
    fi

    # Find the modem
    local modem_idx
    modem_idx=$(mmcli -L 2>/dev/null | grep -oP 'Modem/\K\d+' | head -1)

    if [ -z "$modem_idx" ]; then
        log_debug "No modem found"
        return 0
    fi

    # Check if there's an active bearer
    local bearer_idx
    bearer_idx=$(mmcli -m "$modem_idx" 2>/dev/null | grep -oP 'Bearer/\K\d+' | head -1)

    if [ -n "$bearer_idx" ]; then
        log_debug "Found bearer $bearer_idx on modem $modem_idx"
        # Note: ModemManager doesn't directly support disabling routes,
        # but we handle this by cleaning up routes in cleanup_stray_routes()
    fi

    # For NetworkManager-managed modems, configure the connection to not add routes
    # This catches cases where NM is managing the cellular connection
    local wwan_conn
    for iface in "${BACKUP_IFACE:-wwan0}"; do
        # Find NM connection for this interface (if any)
        wwan_conn=$(nmcli -t -f NAME,DEVICE connection show 2>/dev/null | grep ":${iface}$" | cut -d: -f1 | head -1)
        if [ -n "$wwan_conn" ]; then
            log_info "Configuring NM connection '$wwan_conn' to not add default route"
            nmcli connection modify "$wwan_conn" ipv4.never-default yes 2>/dev/null || true
            nmcli connection modify "$wwan_conn" ipv6.never-default yes 2>/dev/null || true
            nmcli connection modify "$wwan_conn" ipv4.route-metric 9999 2>/dev/null || true
        fi
    done

    log_info "ModemManager/NM route suppression configured"
}

# Remove any stray default routes not managed by us
# Called before updating routes to ensure clean state
# This handles routes added by:
#   - NetworkManager (no metric, or unexpected metrics)
#   - ModemManager/carrier DHCP (proto static, often metric 200)
#   - dhclient or other DHCP clients
cleanup_stray_routes() {
    # Clean up routes not managed by us - but ONLY if they would cause routing issues
    #
    # We use metrics 10 (active) and 100 (standby) exclusively.
    # Stray routes are those that:
    #   1. Have no metric (highest priority, overrides ours)
    #   2. Have proto static (carrier-pushed via DHCP)
    #   3. Have metric < 10 (would take precedence over active)
    #
    # IMPORTANT: Routes with metric > 100 are IGNORED - they don't affect us
    # This prevents constant fighting with NetworkManager/ModemManager.

    local dominated_by_stray=false
    local route_info
    local needs_cleanup=false

    route_info=$(ip route show default 2>/dev/null)

    # Only care about routes that would DOMINATE our routing:
    # 1. Routes without metric (implicit metric 0, highest priority)
    if echo "$route_info" | grep "^default" | grep -v "metric" | grep -qv "proto static"; then
        # Has default route without metric AND without proto static
        # This is typically a manually added route or broken NM config
        needs_cleanup=true
        log_debug "Found default route without metric"
    fi

    # 2. Routes with proto static AND no metric (carrier DHCP - highest priority)
    if echo "$route_info" | grep "proto static" | grep -qv "metric"; then
        needs_cleanup=true
        log_debug "Found carrier route without metric"
    fi

    # 3. Routes with metric LESS than 10 (would override our active route)
    if echo "$route_info" | grep -E "metric [0-9]( |$)" | grep -q .; then
        needs_cleanup=true
        log_debug "Found route with metric < 10"
    fi

    # Do NOT cleanup routes with metric >= 100 - they don't affect active routing
    # This is the key fix: stop fighting with NM/MM over standby routes

    if [ "$needs_cleanup" = "true" ]; then
        # Rate limit: only cleanup once per 30 seconds
        local now cleanup_file="/run/fortress/last_route_cleanup"
        now=$(date +%s)
        if [ -f "$cleanup_file" ]; then
            local last_cleanup
            last_cleanup=$(cat "$cleanup_file" 2>/dev/null || echo 0)
            if [ $((now - last_cleanup)) -lt 30 ]; then
                log_debug "Route cleanup rate-limited (last: ${last_cleanup})"
                return 0
            fi
        fi
        echo "$now" > "$cleanup_file"

        log_info "Cleaning up dominating stray routes..."

        # Remove proto static routes (carrier DHCP) - these are problematic
        while ip route show default 2>/dev/null | grep "proto static" | grep -qv "metric"; do
            local proto_route
            proto_route=$(ip route show default 2>/dev/null | grep "proto static" | grep -v "metric" | head -1)
            [ -z "$proto_route" ] && break
            log_info "Removing carrier route: $proto_route"
            ip route del $proto_route 2>/dev/null || break
        done

        # Remove routes without metric (excluding proto static which we handled)
        local tries=5
        while [ $tries -gt 0 ]; do
            local bad_route
            bad_route=$(ip route show default 2>/dev/null | grep "^default" | grep -v "metric" | grep -v "proto static" | head -1)
            [ -z "$bad_route" ] && break
            log_info "Removing stray route without metric: $bad_route"
            ip route del $bad_route 2>/dev/null || break
            tries=$((tries - 1))
        done

        # Ensure our routes exist with correct metrics
        ensure_main_table_routes
    fi
}

setup_routing_tables() {
    log_info "Configuring routing tables..."

    discover_gateways

    # Flush existing table routes
    ip route flush table $TABLE_PRIMARY 2>/dev/null || true
    ip route flush table $TABLE_BACKUP 2>/dev/null || true

    # Primary table (wired)
    if [ -n "$PRIMARY_GATEWAY" ]; then
        # Add default route via primary
        ip route add default via "$PRIMARY_GATEWAY" dev "$PRIMARY_IFACE" table $TABLE_PRIMARY
        # Copy local routes (for source address selection)
        ip route show dev "$PRIMARY_IFACE" scope link 2>/dev/null | while read -r route; do
            ip route add $route dev "$PRIMARY_IFACE" table $TABLE_PRIMARY 2>/dev/null || true
        done
        log_info "Primary table configured: default via $PRIMARY_GATEWAY dev $PRIMARY_IFACE"
    fi

    # Backup table (modem)
    if [ -n "$BACKUP_GATEWAY" ]; then
        ip route add default via "$BACKUP_GATEWAY" dev "$BACKUP_IFACE" table $TABLE_BACKUP
        ip route show dev "$BACKUP_IFACE" scope link 2>/dev/null | while read -r route; do
            ip route add $route dev "$BACKUP_IFACE" table $TABLE_BACKUP 2>/dev/null || true
        done
        log_info "Backup table configured: default via $BACKUP_GATEWAY dev $BACKUP_IFACE"
    fi

    # IMPORTANT: Keep a default route in main table as fallback
    # This ensures connectivity even if PBR marking fails
    update_main_table_route
}

ensure_main_table_routes() {
    # INCREMENTAL route management - only add/modify what's needed
    # This prevents route flapping by NOT removing routes unnecessarily
    #
    # Expected state:
    #   - Active WAN:  metric 10 (preferred)
    #   - Standby WAN: metric 100 (fallback)
    #
    # We check if routes exist with correct metrics before modifying

    local active="${ACTIVE_WAN:-primary}"
    local metric_active=10
    local metric_standby=100
    local route_info
    local changes_made=false

    route_info=$(ip route show default 2>/dev/null)

    # Determine which gateway should be active/standby
    local active_gw active_iface standby_gw standby_iface
    if [ "$active" = "primary" ]; then
        active_gw="${PRIMARY_GATEWAY:-}"
        active_iface="${PRIMARY_IFACE:-}"
        standby_gw="${BACKUP_GATEWAY:-}"
        standby_iface="${BACKUP_IFACE:-}"
    else
        active_gw="${BACKUP_GATEWAY:-}"
        active_iface="${BACKUP_IFACE:-}"
        standby_gw="${PRIMARY_GATEWAY:-}"
        standby_iface="${PRIMARY_IFACE:-}"
    fi

    # Check if active route exists with correct metric
    if [ -n "$active_gw" ] && [ -n "$active_iface" ]; then
        if ! echo "$route_info" | grep -q "via $active_gw dev $active_iface.*metric $metric_active"; then
            # Active route missing or wrong metric - fix it
            # First remove any existing route for this gateway (any metric)
            ip route del default via "$active_gw" dev "$active_iface" 2>/dev/null || true
            # Add with correct metric
            if ip route add default via "$active_gw" dev "$active_iface" metric $metric_active 2>/dev/null; then
                log_info "Added active route: via $active_gw metric $metric_active"
                changes_made=true
            fi
        fi
    fi

    # Check if standby route exists with correct metric
    if [ -n "$standby_gw" ] && [ -n "$standby_iface" ]; then
        if ! echo "$route_info" | grep -q "via $standby_gw dev $standby_iface.*metric $metric_standby"; then
            # Standby route missing or wrong metric - fix it
            ip route del default via "$standby_gw" dev "$standby_iface" 2>/dev/null || true
            if ip route add default via "$standby_gw" dev "$standby_iface" metric $metric_standby 2>/dev/null; then
                log_info "Added standby route: via $standby_gw metric $metric_standby"
                changes_made=true
            fi
        fi
    fi

    if [ "$changes_made" = "true" ]; then
        log_debug "Routes after ensure: $(ip route show default 2>/dev/null | tr '\n' ' ')"
    fi
}

update_main_table_route() {
    # Full route update - used during failover when active WAN changes
    # This is more aggressive than ensure_main_table_routes() and swaps metrics
    #
    # Called when:
    #   - ACTIVE_WAN changes (failover/failback)
    #   - Manual failover command
    #   - Initial setup

    local active="${ACTIVE_WAN:-primary}"
    local metric_active=10
    local metric_standby=100

    log_info "Updating main table routes for active=$active..."

    # Determine which gateway should be active/standby
    local active_gw active_iface standby_gw standby_iface
    if [ "$active" = "primary" ]; then
        active_gw="${PRIMARY_GATEWAY:-}"
        active_iface="${PRIMARY_IFACE:-}"
        standby_gw="${BACKUP_GATEWAY:-}"
        standby_iface="${BACKUP_IFACE:-}"
    else
        active_gw="${BACKUP_GATEWAY:-}"
        active_iface="${BACKUP_IFACE:-}"
        standby_gw="${PRIMARY_GATEWAY:-}"
        standby_iface="${PRIMARY_IFACE:-}"
    fi

    # Remove ONLY the routes we're about to change (not all routes!)
    # This preserves any other default routes (unlikely but possible)
    if [ -n "$active_gw" ]; then
        ip route del default via "$active_gw" 2>/dev/null || true
    fi
    if [ -n "$standby_gw" ]; then
        ip route del default via "$standby_gw" 2>/dev/null || true
    fi

    # Add routes with correct metrics
    if [ -n "$active_gw" ] && [ -n "$active_iface" ]; then
        ip route add default via "$active_gw" dev "$active_iface" metric $metric_active 2>/dev/null || true
        log_debug "Active route: via $active_gw dev $active_iface metric $metric_active"
    fi

    if [ -n "$standby_gw" ] && [ -n "$standby_iface" ]; then
        ip route add default via "$standby_gw" dev "$standby_iface" metric $metric_standby 2>/dev/null || true
        log_debug "Standby route: via $standby_gw dev $standby_iface metric $metric_standby"
    fi

    log_info "Main table routes updated: active=$active"
}

setup_ip_rules() {
    log_info "Setting up IP rules..."

    # Get interface IP addresses for source-based routing
    local primary_ip backup_ip
    primary_ip=$(ip -4 addr show "$PRIMARY_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    backup_ip=$(ip -4 addr show "$BACKUP_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

    # Remove old rules (clean slate)
    ip rule del fwmark $FWMARK_PRIMARY/$FWMARK_MASK table $TABLE_PRIMARY 2>/dev/null || true
    ip rule del fwmark $FWMARK_BACKUP/$FWMARK_MASK table $TABLE_BACKUP 2>/dev/null || true
    ip rule del table $TABLE_PRIMARY priority 1000 2>/dev/null || true
    [ -n "$primary_ip" ] && ip rule del from "$primary_ip" table $TABLE_PRIMARY 2>/dev/null || true
    [ -n "$backup_ip" ] && ip rule del from "$backup_ip" table $TABLE_BACKUP 2>/dev/null || true

    # Source-based routing rules (priority 50-60) - IMPORTANT for asymmetric routing prevention
    # Traffic originating FROM an interface's IP must route back via that interface
    if [ -n "$primary_ip" ]; then
        ip rule add from "$primary_ip" table $TABLE_PRIMARY priority 50
        log_info "Source rule: from $primary_ip → table wan_primary (priority 50)"
    fi

    if [ -n "$backup_ip" ]; then
        ip rule add from "$backup_ip" table $TABLE_BACKUP priority 60
        log_info "Source rule: from $backup_ip → table wan_backup (priority 60)"
    fi

    # Fwmark-based routing rules (priority 100-200) - for PBR packet marking
    ip rule add fwmark $FWMARK_PRIMARY/$FWMARK_MASK table $TABLE_PRIMARY priority 100
    ip rule add fwmark $FWMARK_BACKUP/$FWMARK_MASK table $TABLE_BACKUP priority 200

    # Fallback rule: unmarked packets use primary (if available)
    ip rule add table $TABLE_PRIMARY priority 1000 2>/dev/null || true

    log_info "IP rules configured"
}

# ============================================================
# nftables Packet Marking
# ============================================================

setup_nftables() {
    log_info "Setting up nftables packet marking..."

    # Create nftables rules for WAN failover
    # Architecture:
    #   1. prerouting: Restore marks from conntrack (for incoming return traffic)
    #   2. forward: Mark and restore for forwarded traffic (LAN/containers)
    #   3. output: Mark host-originated traffic
    #   4. postrouting: Save marks to conntrack
    nft -f - << 'NFTEOF'
# Fortress WAN Failover - Packet Marking
# Ensures sticky sessions: connections stay on their original WAN during failover

table inet fts_wan_failover {
    # Prerouting: Restore marks for incoming traffic (return packets)
    chain prerouting {
        type filter hook prerouting priority mangle - 1; policy accept;

        # Restore mark from conntrack (sticky sessions for return traffic)
        ct mark != 0 meta mark set ct mark
    }

    # Forward: Handle forwarded traffic (LAN clients, containers)
    # This runs AFTER prerouting, so conntrack marks are already restored
    chain forward {
        type filter hook forward priority mangle; policy accept;

        # Skip if already marked (from conntrack or previous rules)
        meta mark & 0xf00 != 0 return

        # Skip local/private destination traffic
        ip daddr 10.0.0.0/8 return
        ip daddr 172.16.0.0/12 return
        ip daddr 192.168.0.0/16 return

        # New forwarded connections will be marked in the dynamic section
        # This chain is updated by set_active_wan()
    }

    # Output: Mark host-originated traffic
    chain output {
        type route hook output priority mangle; policy accept;

        # Skip if already marked (from conntrack)
        meta mark & 0xf00 != 0 return

        # Mark new connections based on active WAN
        # This chain is updated dynamically by the monitor
    }

    # Postrouting: Save marks to conntrack (for return traffic matching)
    chain postrouting {
        type filter hook postrouting priority mangle; policy accept;

        # Save mark to conntrack (for return traffic)
        meta mark != 0 ct mark set meta mark
    }
}
NFTEOF

    # Set initial mark to primary
    set_active_wan primary

    log_info "nftables packet marking configured"
}

set_active_wan() {
    local wan="$1"
    local mark

    case "$wan" in
        primary)
            mark=$FWMARK_PRIMARY
            ;;
        backup)
            mark=$FWMARK_BACKUP
            ;;
        *)
            log_error "Invalid WAN: $wan"
            return 1
            ;;
    esac

    # Update nftables to mark new connections
    # We update BOTH the output chain (host traffic) and forward chain (LAN/container traffic)
    nft -f - << NFTEOF
# Update OUTPUT chain for host-originated traffic
flush chain inet fts_wan_failover output
table inet fts_wan_failover {
    chain output {
        type route hook output priority mangle; policy accept;

        # Skip if already marked (conntrack restored)
        meta mark & 0xf00 != 0 return

        # Skip local/multicast traffic
        ip daddr 127.0.0.0/8 return
        ip daddr 10.0.0.0/8 return
        ip daddr 172.16.0.0/12 return
        ip daddr 192.168.0.0/16 return
        ip daddr 224.0.0.0/4 return

        # Mark all outbound traffic for active WAN
        meta mark set $mark
    }
}

# Update FORWARD chain for forwarded traffic (LAN clients, containers)
flush chain inet fts_wan_failover forward
table inet fts_wan_failover {
    chain forward {
        type filter hook forward priority mangle; policy accept;

        # Skip if already marked (from conntrack or previous rules)
        meta mark & 0xf00 != 0 return

        # Skip local/private destination traffic
        ip daddr 10.0.0.0/8 return
        ip daddr 172.16.0.0/12 return
        ip daddr 192.168.0.0/16 return

        # Mark all forwarded internet-bound traffic
        # LAN clients (10.200.0.0/23)
        ip saddr 10.200.0.0/23 meta mark set $mark

        # Container services tier (172.20.201.0/24) - internet-allowed containers
        ip saddr 172.20.201.0/24 meta mark set $mark
    }
}
NFTEOF

    # Also update legacy fts_forward_mark table if it exists (backward compatibility)
    if nft list table inet fts_forward_mark &>/dev/null; then
        nft -f - << NFTEOF
flush chain inet fts_forward_mark forward
table inet fts_forward_mark {
    chain forward {
        type filter hook forward priority mangle; policy accept;

        # Skip if already marked
        meta mark & 0xf00 != 0 return

        # Skip local traffic
        ip daddr 10.0.0.0/8 return
        ip daddr 172.16.0.0/12 return
        ip daddr 192.168.0.0/16 return

        # Mark container traffic from services tier (internet-allowed)
        ip saddr 172.20.201.0/24 meta mark set $mark

        # Mark LAN client traffic
        ip saddr 10.200.0.0/23 meta mark set $mark
    }
}
NFTEOF
        log_debug "Legacy forward chain (fts_forward_mark) updated with mark $mark"
    fi

    # Update the main table default route to reflect the active WAN
    # This ensures traffic flows correctly even if PBR marking fails
    ACTIVE_WAN="$wan"
    update_main_table_route

    # Update NAT rules to masquerade via active WAN
    update_nat_for_wan "$wan"

    log_info "Active WAN set to: $wan (mark $mark)"
}

cleanup_nftables() {
    nft delete table inet fts_wan_failover 2>/dev/null || true
}

# ============================================================
# DNS Failover
# ============================================================

get_dns_for_interface() {
    # Get DNS servers for an interface from various sources
    local iface="$1"
    local dns=""

    # Try NetworkManager
    if command -v nmcli &>/dev/null; then
        dns=$(nmcli -t -f IP4.DNS device show "$iface" 2>/dev/null | cut -d: -f2 | head -1)
        [ -n "$dns" ] && echo "$dns" && return 0
    fi

    # Try systemd-resolved
    if [ -f "/run/systemd/resolve/resolv.conf" ]; then
        dns=$(grep "^nameserver" /run/systemd/resolve/resolv.conf 2>/dev/null | head -1 | awk '{print $2}')
        [ -n "$dns" ] && echo "$dns" && return 0
    fi

    # Try DHCP lease
    if [ -f "/var/lib/NetworkManager/dhclient-$iface.lease" ]; then
        dns=$(grep 'option domain-name-servers' "/var/lib/NetworkManager/dhclient-$iface.lease" 2>/dev/null | tail -1 | awk '{print $3}' | tr -d ';,' | head -1)
        [ -n "$dns" ] && echo "$dns" && return 0
    fi

    # Fallback to public DNS
    echo "1.1.1.1"
}

update_dns_for_wan() {
    # Update DNS configuration when WAN changes
    # This ensures DNS queries use the active WAN's DNS servers
    local active_wan="$1"
    local dns_server

    [ "$DNS_FAILOVER_ENABLED" != "true" ] && return 0

    if [ "$active_wan" = "primary" ]; then
        dns_server="${PRIMARY_DNS:-$(get_dns_for_interface "$PRIMARY_IFACE")}"
    else
        dns_server="${BACKUP_DNS:-$(get_dns_for_interface "$BACKUP_IFACE")}"
    fi

    [ -z "$dns_server" ] && return 0

    log_info "Updating DNS to $dns_server for $active_wan WAN"

    # Update dnsmasq if it's the DNS server
    if [ -d "/etc/dnsmasq.d" ]; then
        # Check if dnsXai is running (it handles its own upstream DNS)
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fts-dnsxai"; then
            # dnsXai handles upstream DNS, just update its config
            log_debug "dnsXai running, skipping dnsmasq DNS update"
        else
            # Update dnsmasq upstream server
            cat > /etc/dnsmasq.d/fts-wan-failover-dns.conf << EOF
# HookProbe Fortress - DNS Failover
# Auto-generated by wan-failover-pbr.sh
# Active WAN: $active_wan

server=$dns_server
server=1.1.1.1
server=8.8.8.8
EOF
            # Reload dnsmasq
            if systemctl is-active dnsmasq &>/dev/null; then
                systemctl reload dnsmasq 2>/dev/null || true
            fi
        fi
    fi

    # Update resolv.conf if it's not managed by systemd-resolved
    if [ ! -L /etc/resolv.conf ] || [ "$(readlink /etc/resolv.conf)" != "/run/systemd/resolve/stub-resolv.conf" ]; then
        # Only update if it looks like a static file
        if grep -q "# HookProbe Fortress" /etc/resolv.conf 2>/dev/null; then
            cat > /etc/resolv.conf << EOF
# HookProbe Fortress - DNS Failover
# Auto-generated by wan-failover-pbr.sh
# Active WAN: $active_wan

nameserver $dns_server
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
        fi
    fi
}

# ============================================================
# NAT/MASQUERADE Management
# ============================================================

# LAN subnets that need NAT (space-separated)
LAN_SUBNETS="${LAN_SUBNETS:-10.200.0.0/24 172.20.200.0/24 172.20.201.0/24}"

setup_nat_rules() {
    log_info "Setting up NAT rules..."

    # Delete existing table if any (clean slate)
    nft delete table inet fts_wan_nat 2>/dev/null || true

    # Use nftables for NAT (consistent with our other rules)
    nft -f - << 'NFTEOF'
# Fortress WAN Failover - NAT/Masquerade Rules
table inet fts_wan_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # Rules are added dynamically by update_nat_for_wan()
    }
}
NFTEOF

    if ! nft list table inet fts_wan_nat &>/dev/null; then
        log_error "Failed to create nftables NAT table!"
        return 1
    fi

    log_info "nftables NAT table created successfully"

    # Set initial NAT based on active WAN
    update_nat_for_wan "${ACTIVE_WAN:-primary}"
}

update_nat_for_wan() {
    local active_wan="$1"
    local wan_iface

    if [ "$active_wan" = "primary" ]; then
        wan_iface="${PRIMARY_IFACE:-}"
    else
        wan_iface="${BACKUP_IFACE:-}"
    fi

    [ -z "$wan_iface" ] && return 0

    log_info "Updating NAT rules for $active_wan WAN ($wan_iface)..."

    # Ensure nftables NAT table exists (create if missing)
    if ! nft list table inet fts_wan_nat &>/dev/null; then
        log_warn "NAT table missing, recreating..."
        nft -f - << 'NFTEOF'
table inet fts_wan_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
    }
}
NFTEOF
    fi

    # Rebuild NAT chain with correct output interface
    nft flush chain inet fts_wan_nat postrouting 2>/dev/null || true

    # Add masquerade rules for all LAN subnets
    for subnet in $LAN_SUBNETS; do
        if nft add rule inet fts_wan_nat postrouting ip saddr "$subnet" oifname "$wan_iface" masquerade 2>/dev/null; then
            log_debug "NAT: $subnet -> $wan_iface (masquerade)"
        else
            log_warn "Failed to add nftables NAT rule for $subnet"
        fi
    done

    # Always add iptables rules as primary fallback (more reliable on some systems)
    for subnet in $LAN_SUBNETS; do
        # Remove old rules for this subnet (both interfaces)
        iptables -t nat -D POSTROUTING -s "$subnet" -o "${PRIMARY_IFACE:-eth0}" -j MASQUERADE 2>/dev/null || true
        iptables -t nat -D POSTROUTING -s "$subnet" -o "${BACKUP_IFACE:-wwan0}" -j MASQUERADE 2>/dev/null || true

        # Add rule for active interface
        if iptables -t nat -A POSTROUTING -s "$subnet" -o "$wan_iface" -j MASQUERADE 2>/dev/null; then
            log_debug "iptables NAT: $subnet -> $wan_iface (masquerade)"
        else
            log_warn "Failed to add iptables NAT rule for $subnet"
        fi
    done

    log_info "NAT rules updated for $wan_iface"
}

cleanup_nat_rules() {
    log_info "Cleaning up NAT rules..."

    # Remove nftables NAT table
    nft delete table inet fts_wan_nat 2>/dev/null || true

    # Remove iptables NAT rules
    for subnet in $LAN_SUBNETS; do
        iptables -t nat -D POSTROUTING -s "$subnet" -o "${PRIMARY_IFACE:-eth0}" -j MASQUERADE 2>/dev/null || true
        iptables -t nat -D POSTROUTING -s "$subnet" -o "${BACKUP_IFACE:-wwan0}" -j MASQUERADE 2>/dev/null || true
    done
}

# Restore NetworkManager default route settings (called during cleanup)
restore_networkmanager_management() {
    log_info "Restoring NetworkManager route settings for WAN interfaces..."

    if ! command -v nmcli &>/dev/null; then
        return 0
    fi

    # For each WAN interface, restore default route settings
    for iface in "${PRIMARY_IFACE:-}" "${BACKUP_IFACE:-}"; do
        [ -z "$iface" ] && continue

        # Find the connection name for this interface
        local conn_name
        conn_name=$(nmcli -t -f NAME,DEVICE connection show 2>/dev/null | grep ":${iface}$" | cut -d: -f1 | head -1)

        if [ -n "$conn_name" ]; then
            log_info "Restoring route settings for '$conn_name' ($iface)..."

            # Re-enable default gateway and auto-routes
            nmcli connection modify "$conn_name" ipv4.never-default no 2>/dev/null || true
            nmcli connection modify "$conn_name" ipv4.ignore-auto-routes no 2>/dev/null || true
            nmcli connection modify "$conn_name" ipv6.never-default no 2>/dev/null || true
            nmcli connection modify "$conn_name" ipv6.ignore-auto-routes no 2>/dev/null || true

            log_info "$iface ($conn_name): default route settings restored"
        fi
    done

    # Remove netplan override file if it exists
    rm -f /etc/netplan/99-fortress-wan-no-routes.yaml
    if command -v netplan &>/dev/null; then
        netplan apply 2>/dev/null || true
    fi

    # Reload NM config
    nmcli general reload conf 2>/dev/null || true
}

# ============================================================
# Health Checking
# ============================================================

# Enhanced health check settings
HTTP_CHECK_ENABLED="${HTTP_CHECK_ENABLED:-true}"
HTTP_CHECK_URL="${HTTP_CHECK_URL:-http://httpbin.org/ip}"
HTTP_CHECK_TIMEOUT="${HTTP_CHECK_TIMEOUT:-5}"

check_interface_health() {
    # Check WAN interface health using multiple methods
    # This handles the "link UP but no traffic" scenario
    #
    # Checks performed:
    #   1. Link state (carrier detect)
    #   2. IP address assigned
    #   3. Gateway reachable (ARP/ping)
    #   4. Internet connectivity (ICMP to multiple targets)
    #   5. HTTP connectivity (optional, for full SLA validation)
    #
    # Returns: 0 if healthy, 1 if unhealthy

    local iface="$1"
    local iface_ip
    local gateway

    # === Check 1: Link state ===
    if ! ip link show "$iface" 2>/dev/null | grep -q "state UP"; then
        log_debug "[$iface] Link state: DOWN"
        return 1
    fi
    log_debug "[$iface] Link state: UP"

    # === Check 2: IP address assigned ===
    iface_ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    if [ -z "$iface_ip" ]; then
        log_debug "[$iface] No IP address (DHCP expired?)"
        return 1
    fi
    log_debug "[$iface] IP: $iface_ip"

    # === Check 3: Gateway reachable ===
    # Get gateway for this interface
    gateway=$(get_gateway "$iface")
    if [ -n "$gateway" ]; then
        # Try ARP check first (if arping is available), then fall back to ping
        if command -v arping &>/dev/null; then
            if ! arping -c 1 -w 1 -I "$iface" "$gateway" >/dev/null 2>&1; then
                # arping failed, try regular ping to gateway
                if ! ping -c 1 -W 1 -I "$iface" "$gateway" >/dev/null 2>&1; then
                    log_debug "[$iface] Gateway $gateway unreachable"
                    return 1
                fi
            fi
        else
            # arping not installed, use ping only
            if ! ping -c 1 -W 1 -I "$iface" "$gateway" >/dev/null 2>&1; then
                log_debug "[$iface] Gateway $gateway unreachable"
                return 1
            fi
        fi
        log_debug "[$iface] Gateway $gateway: reachable"
    fi

    # === Check 4: Internet connectivity (ICMP) ===
    # Use routing table directly to ensure correct path
    # This is critical for "link up but no traffic" scenarios
    local table
    if [ "$iface" = "$PRIMARY_IFACE" ]; then
        table=$TABLE_PRIMARY
    else
        table=$TABLE_BACKUP
    fi

    local ping_success=0
    for target in $PING_TARGETS; do
        # Method 1: Use source IP binding (triggers source-based routing rule)
        if ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -I "$iface_ip" -q "$target" >/dev/null 2>&1; then
            ping_success=1
            log_debug "[$iface] Ping $target: OK (via source $iface_ip)"
            break
        fi

        # Method 2: Direct interface binding (SO_BINDTODEVICE)
        if ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -I "$iface" -q "$target" >/dev/null 2>&1; then
            ping_success=1
            log_debug "[$iface] Ping $target: OK (via interface bind)"
            break
        fi

        log_debug "[$iface] Ping $target: FAILED"
    done

    if [ $ping_success -eq 0 ]; then
        log_debug "[$iface] All ping targets failed"
        return 1
    fi

    # === Check 5: HTTP connectivity (optional) ===
    # This validates full TCP/HTTP path, not just ICMP
    # Some ISPs/networks block ICMP but allow TCP
    if [ "$HTTP_CHECK_ENABLED" = "true" ] && command -v curl &>/dev/null; then
        # Use curl with interface binding
        if ! curl -s -m "$HTTP_CHECK_TIMEOUT" --interface "$iface" -o /dev/null "$HTTP_CHECK_URL" 2>/dev/null; then
            # HTTP failed, but ICMP worked - might be a temporary issue
            # Log warning but don't fail immediately (ICMP success is enough)
            log_debug "[$iface] HTTP check failed (ICMP OK, may be transient)"
            # We still return success because ICMP worked
        else
            log_debug "[$iface] HTTP check: OK"
        fi
    fi

    return 0
}

check_interface_quick() {
    # Quick health check - just ICMP, used for rapid polling
    local iface="$1"
    local iface_ip

    # Must have IP
    iface_ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    [ -z "$iface_ip" ] && return 1

    # Quick ping with first target only
    local first_target
    first_target=$(echo "$PING_TARGETS" | awk '{print $1}')
    ping -c 1 -W 2 -I "$iface_ip" -q "$first_target" >/dev/null 2>&1
}

# ============================================================
# State Management
# ============================================================

init_state() {
    mkdir -p "$(dirname "$STATE_FILE")"

    cat > "$STATE_FILE" << EOF
PRIMARY_STATUS=unknown
BACKUP_STATUS=unknown
PRIMARY_COUNT=0
BACKUP_COUNT=0
ACTIVE_WAN=primary
LAST_CHECK=$(date +%s)
FAILOVER_COUNT=0
BOTH_DOWN_SINCE=0
LAST_ALTERNATE_TIME=0
LAST_RECOVERY_TIME=0
EOF
}

load_state() {
    if [ -f "$STATE_FILE" ]; then
        # shellcheck source=/dev/null
        . "$STATE_FILE"
    else
        init_state
        # shellcheck source=/dev/null
        . "$STATE_FILE"
    fi
}

save_state() {
    cat > "$STATE_FILE" << EOF
PRIMARY_STATUS=$PRIMARY_STATUS
BACKUP_STATUS=$BACKUP_STATUS
PRIMARY_COUNT=$PRIMARY_COUNT
BACKUP_COUNT=$BACKUP_COUNT
ACTIVE_WAN=$ACTIVE_WAN
LAST_CHECK=$(date +%s)
FAILOVER_COUNT=$FAILOVER_COUNT
BOTH_DOWN_SINCE=${BOTH_DOWN_SINCE:-0}
LAST_ALTERNATE_TIME=${LAST_ALTERNATE_TIME:-0}
LAST_RECOVERY_TIME=${LAST_RECOVERY_TIME:-0}
LAST_ROUTE_CHECK=${LAST_ROUTE_CHECK:-0}
LAST_ROUTE_CLEANUP=${LAST_ROUTE_CLEANUP:-0}
EOF
}

# ============================================================
# Failover Logic
# ============================================================

# Both-down recovery settings
BOTH_DOWN_ALTERNATE_INTERVAL="${BOTH_DOWN_ALTERNATE_INTERVAL:-30}"  # Try other WAN every 30s
BOTH_DOWN_RECOVERY_INTERVAL="${BOTH_DOWN_RECOVERY_INTERVAL:-60}"    # Attempt recovery every 60s

attempt_interface_recovery() {
    # Attempt to recover a failed interface
    # This is called when both WANs are down to try to restore connectivity
    local iface="$1"
    local iface_type="$2"  # primary or backup

    log_info "Attempting recovery for $iface ($iface_type)..."

    # Check if interface has link but no IP (DHCP expired)
    if ip link show "$iface" 2>/dev/null | grep -q "state UP"; then
        local iface_ip
        iface_ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

        if [ -z "$iface_ip" ]; then
            log_info "[$iface] Link UP but no IP - attempting DHCP renewal"

            # Try dhclient
            if command -v dhclient &>/dev/null; then
                dhclient -1 -timeout 10 "$iface" 2>/dev/null &
                sleep 2
            fi

            # Try NetworkManager
            if command -v nmcli &>/dev/null; then
                nmcli device reapply "$iface" 2>/dev/null || true
            fi
        fi
    fi

    # For LTE/WWAN interfaces, try to reconnect the modem
    if [[ "$iface" =~ ^wwan|^wwp ]] && command -v mmcli &>/dev/null; then
        log_info "[$iface] Attempting LTE modem reconnection..."

        local modem_idx
        modem_idx=$(mmcli -L 2>/dev/null | grep -oP 'Modem/\K\d+' | head -1)

        if [ -n "$modem_idx" ]; then
            # Check if modem is connected
            local modem_state
            modem_state=$(mmcli -m "$modem_idx" 2>/dev/null | grep -oP 'state:\s+\K\w+' | head -1)

            if [ "$modem_state" != "connected" ]; then
                log_info "[$iface] Modem state: $modem_state - attempting simple connect"
                mmcli -m "$modem_idx" --simple-connect="apn=internet" 2>/dev/null &
                sleep 3
            fi
        fi
    fi

    # Rediscover gateway after recovery attempt
    discover_gateways
}

verify_nat_rules() {
    # Verify NAT rules exist and are correct
    # Called during health check to ensure NAT persists
    local active="${ACTIVE_WAN:-primary}"
    local wan_iface

    if [ "$active" = "primary" ]; then
        wan_iface="${PRIMARY_IFACE:-}"
    else
        wan_iface="${BACKUP_IFACE:-}"
    fi

    [ -z "$wan_iface" ] && return 0

    # Check if iptables NAT rules exist for the active interface
    local nat_ok=false
    for subnet in $LAN_SUBNETS; do
        if iptables -t nat -C POSTROUTING -s "$subnet" -o "$wan_iface" -j MASQUERADE 2>/dev/null; then
            nat_ok=true
            break
        fi
    done

    if [ "$nat_ok" = "false" ]; then
        log_warn "NAT rules missing for $wan_iface - recreating..."
        update_nat_for_wan "$active"
    fi
}

do_health_check() {
    load_state

    local now
    now=$(date +%s)

    # Route maintenance - run periodically, not every check
    # Only cleanup stray routes every 60 seconds (rate-limited inside function too)
    local last_route_check="${LAST_ROUTE_CHECK:-0}"
    if [ $((now - last_route_check)) -ge 60 ]; then
        cleanup_stray_routes
        LAST_ROUTE_CHECK=$now
    fi

    # Verify NAT rules are in place (lightweight check)
    verify_nat_rules

    local primary_now backup_now
    local old_active="$ACTIVE_WAN"

    # Check primary (wired)
    if check_interface_health "$PRIMARY_IFACE"; then
        primary_now="up"
        PRIMARY_COUNT=$((PRIMARY_COUNT + 1))
        [ $PRIMARY_COUNT -gt $UP_THRESHOLD ] && PRIMARY_COUNT=$UP_THRESHOLD
    else
        primary_now="down"
        PRIMARY_COUNT=$((PRIMARY_COUNT - 1))
        [ $PRIMARY_COUNT -lt 0 ] && PRIMARY_COUNT=0
    fi

    # Check backup (modem)
    if check_interface_health "$BACKUP_IFACE"; then
        backup_now="up"
        BACKUP_COUNT=$((BACKUP_COUNT + 1))
        [ $BACKUP_COUNT -gt $UP_THRESHOLD ] && BACKUP_COUNT=$UP_THRESHOLD
    else
        backup_now="down"
        BACKUP_COUNT=$((BACKUP_COUNT - 1))
        [ $BACKUP_COUNT -lt 0 ] && BACKUP_COUNT=0
    fi

    # Apply hysteresis: only change status when threshold reached
    if [ $PRIMARY_COUNT -ge $UP_THRESHOLD ]; then
        PRIMARY_STATUS="up"
    elif [ $PRIMARY_COUNT -eq 0 ]; then
        PRIMARY_STATUS="down"
    fi

    if [ $BACKUP_COUNT -ge $UP_THRESHOLD ]; then
        BACKUP_STATUS="up"
    elif [ $BACKUP_COUNT -eq 0 ]; then
        BACKUP_STATUS="down"
    fi

    # Determine active WAN
    if [ "$PRIMARY_STATUS" = "up" ]; then
        ACTIVE_WAN="primary"
        BOTH_DOWN_SINCE=0  # Reset both-down timer
    elif [ "$BACKUP_STATUS" = "up" ]; then
        ACTIVE_WAN="backup"
        BOTH_DOWN_SINCE=0  # Reset both-down timer
    else
        # ============================================================
        # BOTH WANS DOWN - Enhanced Recovery Logic
        # ============================================================

        # Track how long both have been down
        if [ "${BOTH_DOWN_SINCE:-0}" -eq 0 ]; then
            BOTH_DOWN_SINCE=$now
            log_warn "ALERT: Both WANs are DOWN - starting recovery mode"
            logger -t "$LOG_TAG" -p crit "Both WAN connections lost - entering recovery mode"
        fi

        local down_duration=$((now - BOTH_DOWN_SINCE))

        # Strategy 1: If one interface shows ANY sign of life, prefer it
        # (even if below threshold - faster recovery)
        if [ "$primary_now" = "up" ] && [ "$backup_now" = "down" ]; then
            log_info "Primary showing signs of recovery - switching immediately"
            ACTIVE_WAN="primary"
            PRIMARY_COUNT=$UP_THRESHOLD  # Boost to prevent immediate re-failover
        elif [ "$backup_now" = "up" ] && [ "$primary_now" = "down" ]; then
            log_info "Backup showing signs of recovery - switching immediately"
            ACTIVE_WAN="backup"
            BACKUP_COUNT=$UP_THRESHOLD  # Boost to prevent immediate re-failover
        else
            # Both still down - try alternating and recovery

            # Strategy 2: Alternate between WANs periodically
            # This gives each WAN a chance to be tested as active
            local last_alternate="${LAST_ALTERNATE_TIME:-0}"
            if [ $((now - last_alternate)) -ge "$BOTH_DOWN_ALTERNATE_INTERVAL" ]; then
                if [ "$ACTIVE_WAN" = "primary" ]; then
                    log_info "Both down for ${down_duration}s - trying backup WAN"
                    ACTIVE_WAN="backup"
                else
                    log_info "Both down for ${down_duration}s - trying primary WAN"
                    ACTIVE_WAN="primary"
                fi
                LAST_ALTERNATE_TIME=$now

                # Update routing to use the new active WAN
                set_active_wan "$ACTIVE_WAN"
            fi

            # Strategy 3: Attempt interface recovery periodically
            local last_recovery="${LAST_RECOVERY_TIME:-0}"
            if [ $((now - last_recovery)) -ge "$BOTH_DOWN_RECOVERY_INTERVAL" ]; then
                log_info "Attempting interface recovery (both down for ${down_duration}s)..."

                # Try to recover the non-active interface first
                if [ "$ACTIVE_WAN" = "primary" ]; then
                    attempt_interface_recovery "$BACKUP_IFACE" "backup"
                else
                    attempt_interface_recovery "$PRIMARY_IFACE" "primary"
                fi

                LAST_RECOVERY_TIME=$now
            fi

            log_warn "Both WANs DOWN for ${down_duration}s - active=$ACTIVE_WAN (alternating)"
        fi
    fi

    # Apply change if needed
    if [ "$ACTIVE_WAN" != "$old_active" ]; then
        FAILOVER_COUNT=$((FAILOVER_COUNT + 1))
        log_info "WAN failover: $old_active -> $ACTIVE_WAN (event #$FAILOVER_COUNT)"

        # Update packet marking
        set_active_wan "$ACTIVE_WAN"

        # Refresh routing tables (gateway may have changed)
        discover_gateways
        setup_routing_tables

        # Update IP rules if interface IPs changed (DHCP renewal)
        setup_ip_rules

        # Update DNS configuration for new WAN
        update_dns_for_wan "$ACTIVE_WAN"

        # Log the failover event for monitoring
        logger -t "$LOG_TAG" -p notice "WAN failover completed: $old_active -> $ACTIVE_WAN"
    fi

    save_state

    log_debug "Health: primary=$PRIMARY_STATUS($PRIMARY_COUNT) backup=$BACKUP_STATUS($BACKUP_COUNT) active=$ACTIVE_WAN"
}

# ============================================================
# Commands
# ============================================================

cmd_setup() {
    log_info "Setting up PBR WAN failover..."

    load_config || exit 1

    # Prevent NetworkManager from adding routes
    configure_networkmanager_no_default_route

    # Prevent netplan/systemd-networkd from adding routes
    configure_netplan_no_routes

    # Prevent ModemManager/carrier from pushing routes
    configure_modemmanager_no_routes

    setup_rt_tables
    setup_routing_tables
    setup_ip_rules
    setup_nftables
    setup_nat_rules
    init_state

    log_info "PBR WAN failover setup complete"
}

cmd_start() {
    log_info "Starting WAN failover monitor..."

    load_config || exit 1

    # Check if already running
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        log_error "Monitor already running (PID $(cat "$PID_FILE"))"
        exit 1
    fi

    # Ensure setup is done
    if ! ip rule show | grep -q "fwmark.*table $TABLE_PRIMARY"; then
        cmd_setup
    fi

    # Write PID
    echo $$ > "$PID_FILE"

    # Trap signals
    trap 'log_info "Received signal, shutting down..."; rm -f "$PID_FILE"; exit 0' INT TERM

    log_info "Monitor started (PID $$), checking every ${CHECK_INTERVAL}s"

    # Main loop
    while true; do
        do_health_check
        sleep "$CHECK_INTERVAL"
    done
}

cmd_stop() {
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping monitor (PID $pid)..."
            kill "$pid"
            rm -f "$PID_FILE"
        else
            log_warn "Monitor not running (stale PID file)"
            rm -f "$PID_FILE"
        fi
    else
        log_warn "Monitor not running (no PID file)"
    fi
}

cmd_status() {
    load_config 2>/dev/null || true
    load_state 2>/dev/null || true

    echo "════════════════════════════════════════════════════════════════"
    echo "  HookProbe Fortress - WAN Failover Status (PBR)"
    echo "════════════════════════════════════════════════════════════════"
    echo ""

    # Monitor status
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Monitor:        RUNNING (PID $(cat "$PID_FILE"))"
    else
        echo "Monitor:        STOPPED"
    fi
    echo ""

    # Interface status
    echo "Primary WAN:    ${PRIMARY_IFACE:-unknown}"
    echo "  Gateway:      ${PRIMARY_GATEWAY:-unknown}"
    echo "  Status:       ${PRIMARY_STATUS:-unknown} (score: ${PRIMARY_COUNT:-0}/$UP_THRESHOLD)"
    echo ""

    echo "Backup WAN:     ${BACKUP_IFACE:-unknown}"
    echo "  Gateway:      ${BACKUP_GATEWAY:-unknown}"
    echo "  Status:       ${BACKUP_STATUS:-unknown} (score: ${BACKUP_COUNT:-0}/$UP_THRESHOLD)"
    echo ""

    echo "Active WAN:     ${ACTIVE_WAN:-unknown}"
    echo "Failover Count: ${FAILOVER_COUNT:-0}"

    # Show both-down recovery status if applicable
    if [ "${BOTH_DOWN_SINCE:-0}" -gt 0 ]; then
        local now down_duration
        now=$(date +%s)
        down_duration=$((now - BOTH_DOWN_SINCE))
        echo ""
        echo "⚠️  RECOVERY MODE:"
        echo "  Both WANs down for: ${down_duration}s"
        echo "  Last alternate:     ${LAST_ALTERNATE_TIME:-0}"
        echo "  Last recovery try:  ${LAST_RECOVERY_TIME:-0}"
    fi
    echo ""

    # Main table default routes (critical for failover)
    echo "Main Table (fallback routes):"
    ip route show default 2>/dev/null | sed 's/^/    /' || echo "    (none - PROBLEM!)"
    echo ""

    # Routing tables
    echo "PBR Routing Tables:"
    echo "  Table $TABLE_PRIMARY ($TABLE_NAME_PRIMARY):"
    ip route show table $TABLE_PRIMARY 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
    echo ""
    echo "  Table $TABLE_BACKUP ($TABLE_NAME_BACKUP):"
    ip route show table $TABLE_BACKUP 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
    echo ""

    # IP rules
    echo "IP Rules (fwmark):"
    ip rule show | grep -E "fwmark|table (wan_|$TABLE_PRIMARY|$TABLE_BACKUP)" | sed 's/^/    /'
    echo ""

    # nftables
    echo "nftables marks:"
    nft list chain inet fts_wan_failover output 2>/dev/null | grep -E "mark set" | sed 's/^/    /' || echo "    (not configured)"
    echo ""
}

cmd_failover() {
    log_info "Forcing failover to backup..."
    load_state
    ACTIVE_WAN="backup"
    PRIMARY_STATUS="down"
    PRIMARY_COUNT=0
    save_state
    set_active_wan backup
    log_info "Forced failover complete"
}

cmd_failback() {
    log_info "Forcing failback to primary..."
    load_state
    ACTIVE_WAN="primary"
    PRIMARY_STATUS="up"
    PRIMARY_COUNT=$UP_THRESHOLD
    save_state
    set_active_wan primary
    log_info "Forced failback complete"
}

cmd_check() {
    load_config || exit 1
    do_health_check
}

cmd_cleanup() {
    log_info "Cleaning up PBR configuration..."

    # Load config for interface names (needed for route restoration)
    load_config 2>/dev/null || true

    # Stop monitor
    cmd_stop 2>/dev/null || true

    # Restore NetworkManager management of WAN interfaces
    restore_networkmanager_management

    # Remove nftables rules
    cleanup_nftables

    # Remove NAT rules
    cleanup_nat_rules

    # Remove IP rules
    ip rule del fwmark $FWMARK_PRIMARY/$FWMARK_MASK table $TABLE_PRIMARY 2>/dev/null || true
    ip rule del fwmark $FWMARK_BACKUP/$FWMARK_MASK table $TABLE_BACKUP 2>/dev/null || true
    ip rule del table $TABLE_PRIMARY priority 1000 2>/dev/null || true

    # Flush tables
    ip route flush table $TABLE_PRIMARY 2>/dev/null || true
    ip route flush table $TABLE_BACKUP 2>/dev/null || true

    # Restore default route (use primary gateway if available)
    if [ -n "${PRIMARY_IFACE:-}" ]; then
        discover_gateways
        if [ -n "${PRIMARY_GATEWAY:-}" ]; then
            ip route add default via "$PRIMARY_GATEWAY" dev "$PRIMARY_IFACE" 2>/dev/null || true
        elif [ -n "${BACKUP_GATEWAY:-}" ]; then
            ip route add default via "$BACKUP_GATEWAY" dev "$BACKUP_IFACE" 2>/dev/null || true
        fi
    fi

    # Remove state
    rm -f "$STATE_FILE" "$PID_FILE"

    log_info "Cleanup complete"
}

# ============================================================
# Main
# ============================================================

case "${1:-}" in
    setup)
        cmd_setup
        ;;
    start)
        cmd_start
        ;;
    stop)
        cmd_stop
        ;;
    status)
        cmd_status
        ;;
    failover)
        cmd_failover
        ;;
    failback)
        cmd_failback
        ;;
    check)
        cmd_check
        ;;
    cleanup)
        cmd_cleanup
        ;;
    *)
        echo "Usage: $0 {setup|start|stop|status|failover|failback|check|cleanup}"
        echo ""
        echo "Commands:"
        echo "  setup     - Initial PBR setup (routing tables, rules, nftables)"
        echo "  start     - Start the health monitoring daemon"
        echo "  stop      - Stop the monitoring daemon"
        echo "  status    - Show current failover status"
        echo "  failover  - Force immediate failover to backup"
        echo "  failback  - Force immediate failback to primary"
        echo "  check     - Run single health check (for cron)"
        echo "  cleanup   - Remove all PBR configuration"
        exit 1
        ;;
esac
