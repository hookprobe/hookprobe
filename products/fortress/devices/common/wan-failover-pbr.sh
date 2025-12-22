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
UP_THRESHOLD=3      # Require X consecutive successes to mark UP
DOWN_THRESHOLD=3    # Require X consecutive failures to mark DOWN

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
    PING_TARGETS="${PING_TARGETS:-1.1.1.1 8.8.8.8 9.9.9.9}"
    CHECK_INTERVAL="${CHECK_INTERVAL:-5}"
    UP_THRESHOLD="${UP_THRESHOLD:-3}"
    DOWN_THRESHOLD="${DOWN_THRESHOLD:-3}"

    return 0
}

# ============================================================
# Gateway Discovery
# ============================================================

get_gateway() {
    local iface="$1"
    local gw

    # Try to get gateway from DHCP lease
    if [ -f "/var/lib/NetworkManager/dhclient-$iface.lease" ]; then
        gw=$(grep 'option routers' "/var/lib/NetworkManager/dhclient-$iface.lease" 2>/dev/null | tail -1 | awk '{print $3}' | tr -d ';')
        [ -n "$gw" ] && echo "$gw" && return 0
    fi

    # Try nmcli
    gw=$(nmcli -t -f IP4.GATEWAY device show "$iface" 2>/dev/null | cut -d: -f2)
    [ -n "$gw" ] && echo "$gw" && return 0

    # Try ip route
    gw=$(ip route show dev "$iface" 2>/dev/null | grep default | awk '{print $3}' | head -1)
    [ -n "$gw" ] && echo "$gw" && return 0

    return 1
}

discover_gateways() {
    if [ -z "$PRIMARY_GATEWAY" ]; then
        PRIMARY_GATEWAY=$(get_gateway "$PRIMARY_IFACE")
        if [ -z "$PRIMARY_GATEWAY" ]; then
            log_warn "Could not discover gateway for $PRIMARY_IFACE"
        fi
    fi

    if [ -z "$BACKUP_GATEWAY" ]; then
        BACKUP_GATEWAY=$(get_gateway "$BACKUP_IFACE")
        if [ -z "$BACKUP_GATEWAY" ]; then
            log_warn "Could not discover gateway for $BACKUP_IFACE"
        fi
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

    # Remove default route from main table (policy routing handles it)
    ip route del default 2>/dev/null || true
}

setup_ip_rules() {
    log_info "Setting up IP rules..."

    # Remove old rules
    ip rule del fwmark $FWMARK_PRIMARY/$FWMARK_MASK table $TABLE_PRIMARY 2>/dev/null || true
    ip rule del fwmark $FWMARK_BACKUP/$FWMARK_MASK table $TABLE_BACKUP 2>/dev/null || true

    # Add rules: packets marked with fwmark go to corresponding table
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
    nft -f - << 'NFTEOF'
# Fortress WAN Failover - Packet Marking
table inet fts_wan_failover {
    # Track connection state for sticky sessions
    chain prerouting {
        type filter hook prerouting priority mangle - 1; policy accept;

        # Restore mark from conntrack (sticky sessions)
        ct mark != 0 meta mark set ct mark
    }

    chain output {
        type route hook output priority mangle; policy accept;

        # Skip if already marked
        meta mark & 0xf00 != 0 return

        # Mark new connections based on active WAN
        # This chain is updated dynamically by the monitor
    }

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
    nft -f - << NFTEOF
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
NFTEOF

    log_info "Active WAN set to: $wan (mark $mark)"
}

cleanup_nftables() {
    nft delete table inet fts_wan_failover 2>/dev/null || true
}

# ============================================================
# Health Checking
# ============================================================

check_interface_health() {
    local iface="$1"
    local success=0

    # Check if interface exists and is up
    if ! ip link show "$iface" 2>/dev/null | grep -q "state UP"; then
        log_debug "Interface $iface is not UP"
        return 1
    fi

    # Ping multiple targets through specific interface
    for target in $PING_TARGETS; do
        if ping -I "$iface" -c "$PING_COUNT" -W "$PING_TIMEOUT" -q "$target" >/dev/null 2>&1; then
            success=$((success + 1))
            # One successful ping is enough
            log_debug "Ping to $target via $iface: SUCCESS"
            return 0
        fi
        log_debug "Ping to $target via $iface: FAILED"
    done

    return 1
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
EOF
}

# ============================================================
# Failover Logic
# ============================================================

do_health_check() {
    load_state

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
    elif [ "$BACKUP_STATUS" = "up" ]; then
        ACTIVE_WAN="backup"
    else
        # Both down - keep current (avoid thrashing)
        log_warn "Both WANs appear down, keeping $ACTIVE_WAN"
    fi

    # Apply change if needed
    if [ "$ACTIVE_WAN" != "$old_active" ]; then
        FAILOVER_COUNT=$((FAILOVER_COUNT + 1))
        log_info "WAN failover: $old_active -> $ACTIVE_WAN (event #$FAILOVER_COUNT)"
        set_active_wan "$ACTIVE_WAN"

        # Refresh routing tables (gateway may have changed)
        discover_gateways
        setup_routing_tables
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

    setup_rt_tables
    setup_routing_tables
    setup_ip_rules
    setup_nftables
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
    echo ""

    # Routing tables
    echo "Routing Tables:"
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

    # Stop monitor
    cmd_stop 2>/dev/null || true

    # Remove nftables rules
    cleanup_nftables

    # Remove IP rules
    ip rule del fwmark $FWMARK_PRIMARY/$FWMARK_MASK table $TABLE_PRIMARY 2>/dev/null || true
    ip rule del fwmark $FWMARK_BACKUP/$FWMARK_MASK table $TABLE_BACKUP 2>/dev/null || true
    ip rule del table $TABLE_PRIMARY priority 1000 2>/dev/null || true

    # Flush tables
    ip route flush table $TABLE_PRIMARY 2>/dev/null || true
    ip route flush table $TABLE_BACKUP 2>/dev/null || true

    # Restore default route (use primary gateway)
    discover_gateways
    if [ -n "$PRIMARY_GATEWAY" ]; then
        ip route add default via "$PRIMARY_GATEWAY" dev "$PRIMARY_IFACE" 2>/dev/null || true
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
