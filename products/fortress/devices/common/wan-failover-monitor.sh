#!/bin/bash
#
# wan-failover-monitor.sh - IP SLA-style WAN Health Monitoring for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# This script implements Cisco IP SLA-like functionality for Linux:
#   - Monitors primary WAN connectivity by pinging targets
#   - Detects when primary is down even if link is up (cable connected)
#   - Switches to backup interface (LTE) when primary fails
#   - Switches back when primary recovers
#   - Includes hysteresis to prevent route flapping
#
# Usage:
#   wan-failover-monitor.sh start       # Run as daemon
#   wan-failover-monitor.sh check       # Single check (for cron)
#   wan-failover-monitor.sh status      # Show current status
#   wan-failover-monitor.sh failover    # Force failover to backup
#   wan-failover-monitor.sh failback    # Force failback to primary
#
# Configuration: /etc/hookprobe/wan-failover.conf
#
# Version: 1.0.0
# License: AGPL-3.0
#

set -u

# ============================================================
# CONFIGURATION
# ============================================================

CONFIG_FILE="/etc/hookprobe/wan-failover.conf"
STATE_FILE="/var/lib/fortress/wan-failover-state.json"
LOG_FILE="/var/log/hookprobe/wan-failover.log"
LOCK_FILE="/var/run/fortress-wan-failover.lock"

# Default configuration (can be overridden by config file)
PRIMARY_IFACE=""          # Auto-detected from default route
BACKUP_IFACE=""           # Auto-detected from WWAN interfaces
PRIMARY_METRIC=100        # Route metric for primary
BACKUP_METRIC=200         # Route metric for backup

# Health check targets (multiple for reliability)
# Using public DNS servers and well-known IPs
HEALTH_TARGETS="8.8.8.8 1.1.1.1 9.9.9.9"

# Timing configuration
CHECK_INTERVAL=5          # Seconds between checks
PING_TIMEOUT=2            # Timeout for each ping (seconds)
PING_COUNT=1              # Number of pings per target

# Failover thresholds (hysteresis)
FAIL_THRESHOLD=3          # Consecutive failures before failover
RECOVER_THRESHOLD=5       # Consecutive successes before failback

# Current state tracking
PRIMARY_FAIL_COUNT=0
PRIMARY_RECOVER_COUNT=0
CURRENT_ACTIVE="primary"  # "primary" or "backup"

# Colors for status output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================
# LOGGING
# ============================================================

ensure_log_dir() {
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    mkdir -p "$log_dir" 2>/dev/null || true
    mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || true
}

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE"

    # Also output to stderr if running interactively
    if [ -t 2 ]; then
        case "$level" in
            ERROR)   echo -e "${RED}[$level]${NC} $msg" >&2 ;;
            WARN)    echo -e "${YELLOW}[$level]${NC} $msg" >&2 ;;
            INFO)    echo -e "${GREEN}[$level]${NC} $msg" >&2 ;;
            DEBUG)   [ "${DEBUG:-false}" = "true" ] && echo -e "${CYAN}[$level]${NC} $msg" >&2 ;;
        esac
    fi
}

log_info()  { log "INFO" "$@"; }
log_warn()  { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

# ============================================================
# CONFIGURATION LOADING
# ============================================================

load_config() {
    # Load config file if exists
    if [ -f "$CONFIG_FILE" ]; then
        log_info "Loading configuration from $CONFIG_FILE"
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi

    # Auto-detect primary interface from default route
    if [ -z "$PRIMARY_IFACE" ]; then
        PRIMARY_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
        log_info "Auto-detected primary WAN: ${PRIMARY_IFACE:-none}"
    fi

    # Auto-detect backup interface from WWAN or second ethernet
    if [ -z "$BACKUP_IFACE" ]; then
        # Try WWAN first
        BACKUP_IFACE=$(ip -o link show 2>/dev/null | awk -F': ' '/wwan|wwp/ {print $2}' | head -1)

        # If no WWAN, try to find second ethernet
        if [ -z "$BACKUP_IFACE" ]; then
            for iface in $(ip -o link show 2>/dev/null | awk -F': ' '/eth|enp|eno/ {print $2}'); do
                if [ "$iface" != "$PRIMARY_IFACE" ]; then
                    BACKUP_IFACE="$iface"
                    break
                fi
            done
        fi
        log_info "Auto-detected backup WAN: ${BACKUP_IFACE:-none}"
    fi

    # Load saved state
    load_state
}

load_state() {
    if [ -f "$STATE_FILE" ]; then
        local state
        state=$(cat "$STATE_FILE" 2>/dev/null)

        CURRENT_ACTIVE=$(echo "$state" | jq -r '.active // "primary"' 2>/dev/null || echo "primary")
        PRIMARY_FAIL_COUNT=$(echo "$state" | jq -r '.primary_fail_count // 0' 2>/dev/null || echo 0)
        PRIMARY_RECOVER_COUNT=$(echo "$state" | jq -r '.primary_recover_count // 0' 2>/dev/null || echo 0)

        log_debug "Loaded state: active=$CURRENT_ACTIVE, fail_count=$PRIMARY_FAIL_COUNT, recover_count=$PRIMARY_RECOVER_COUNT"
    fi
}

save_state() {
    cat > "$STATE_FILE" << EOF
{
    "active": "$CURRENT_ACTIVE",
    "primary_iface": "$PRIMARY_IFACE",
    "backup_iface": "$BACKUP_IFACE",
    "primary_fail_count": $PRIMARY_FAIL_COUNT,
    "primary_recover_count": $PRIMARY_RECOVER_COUNT,
    "last_check": "$(date -Iseconds)",
    "last_failover": "${LAST_FAILOVER:-}",
    "last_failback": "${LAST_FAILBACK:-}"
}
EOF
}

# ============================================================
# HEALTH CHECKING
# ============================================================

check_interface_link() {
    # Check if interface has link (carrier)
    local iface="$1"

    if [ ! -d "/sys/class/net/$iface" ]; then
        log_debug "Interface $iface does not exist"
        return 1
    fi

    local carrier
    carrier=$(cat "/sys/class/net/$iface/carrier" 2>/dev/null || echo "0")

    if [ "$carrier" = "1" ]; then
        return 0
    else
        log_debug "Interface $iface has no carrier (link down)"
        return 1
    fi
}

check_interface_ip() {
    # Check if interface has an IP address
    local iface="$1"

    if ip addr show "$iface" 2>/dev/null | grep -q "inet "; then
        return 0
    else
        log_debug "Interface $iface has no IP address"
        return 1
    fi
}

ping_through_interface() {
    # Ping a target through a specific interface
    local iface="$1"
    local target="$2"

    # Use -I to bind to interface
    if ping -I "$iface" -c "$PING_COUNT" -W "$PING_TIMEOUT" "$target" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

check_connectivity() {
    # Check connectivity through an interface by pinging multiple targets
    # Returns 0 if at least one target responds, 1 if all fail
    local iface="$1"

    # First check link state
    if ! check_interface_link "$iface"; then
        return 1
    fi

    # Check if interface has IP
    if ! check_interface_ip "$iface"; then
        return 1
    fi

    # Ping health check targets
    local success=0
    for target in $HEALTH_TARGETS; do
        if ping_through_interface "$iface" "$target"; then
            log_debug "Health check passed: $iface -> $target"
            success=1
            break  # One success is enough
        else
            log_debug "Health check failed: $iface -> $target"
        fi
    done

    return $((1 - success))
}

# ============================================================
# ROUTE MANAGEMENT
# ============================================================

get_gateway_for_interface() {
    # Get the gateway IP for an interface
    local iface="$1"

    # Try to get from current routes
    local gw
    gw=$(ip route show dev "$iface" 2>/dev/null | grep "^default" | awk '{print $3}' | head -1)

    if [ -z "$gw" ]; then
        # Try DHCP lease file
        for lease_file in /var/lib/dhcp/dhclient."$iface".leases /var/lib/dhclient/dhclient-"$iface".leases /var/lib/NetworkManager/*.lease; do
            if [ -f "$lease_file" ]; then
                gw=$(grep "option routers" "$lease_file" 2>/dev/null | tail -1 | awk '{print $NF}' | tr -d ';')
                [ -n "$gw" ] && break
            fi
        done 2>/dev/null
    fi

    if [ -z "$gw" ]; then
        # Try nmcli
        if command -v nmcli &>/dev/null; then
            gw=$(nmcli -t -f IP4.GATEWAY device show "$iface" 2>/dev/null | cut -d: -f2)
        fi
    fi

    echo "$gw"
}

activate_primary() {
    # Activate primary WAN as the default route
    local primary_gw
    primary_gw=$(get_gateway_for_interface "$PRIMARY_IFACE")

    if [ -z "$primary_gw" ]; then
        log_error "Cannot get gateway for primary interface $PRIMARY_IFACE"
        return 1
    fi

    log_info "Activating PRIMARY WAN: $PRIMARY_IFACE via $primary_gw (metric $PRIMARY_METRIC)"

    # Remove ALL existing default routes (ip route del only removes one at a time)
    # Loop until no more defaults exist
    local max_tries=10
    while ip route show default 2>/dev/null | grep -q "^default" && [ $max_tries -gt 0 ]; do
        ip route del default 2>/dev/null || break
        max_tries=$((max_tries - 1))
    done

    # Add primary route with low metric (preferred)
    ip route add default via "$primary_gw" dev "$PRIMARY_IFACE" metric "$PRIMARY_METRIC" 2>/dev/null || {
        ip route replace default via "$primary_gw" dev "$PRIMARY_IFACE" metric "$PRIMARY_METRIC"
    }

    # Add backup route with high metric (fallback)
    if [ -n "$BACKUP_IFACE" ]; then
        local backup_gw
        backup_gw=$(get_gateway_for_interface "$BACKUP_IFACE")
        if [ -n "$backup_gw" ]; then
            ip route add default via "$backup_gw" dev "$BACKUP_IFACE" metric "$BACKUP_METRIC" 2>/dev/null || true
        fi
    fi

    CURRENT_ACTIVE="primary"
    LAST_FAILBACK=$(date -Iseconds)
    save_state

    log_info "PRIMARY WAN ACTIVATED - Traffic now routed through $PRIMARY_IFACE"
    return 0
}

activate_backup() {
    # Activate backup WAN as the default route
    if [ -z "$BACKUP_IFACE" ]; then
        log_error "No backup interface configured"
        return 1
    fi

    local backup_gw
    backup_gw=$(get_gateway_for_interface "$BACKUP_IFACE")

    if [ -z "$backup_gw" ]; then
        log_error "Cannot get gateway for backup interface $BACKUP_IFACE"
        return 1
    fi

    log_warn "Activating BACKUP WAN: $BACKUP_IFACE via $backup_gw (metric $PRIMARY_METRIC)"

    # Remove ALL existing default routes (ip route del only removes one at a time)
    # Loop until no more defaults exist
    local max_tries=10
    while ip route show default 2>/dev/null | grep -q "^default" && [ $max_tries -gt 0 ]; do
        ip route del default 2>/dev/null || break
        max_tries=$((max_tries - 1))
    done

    # Add backup route with low metric (now preferred)
    ip route add default via "$backup_gw" dev "$BACKUP_IFACE" metric "$PRIMARY_METRIC" 2>/dev/null || {
        ip route replace default via "$backup_gw" dev "$BACKUP_IFACE" metric "$PRIMARY_METRIC"
    }

    # Keep primary as high metric for when it recovers
    local primary_gw
    primary_gw=$(get_gateway_for_interface "$PRIMARY_IFACE")
    if [ -n "$primary_gw" ]; then
        ip route add default via "$primary_gw" dev "$PRIMARY_IFACE" metric "$BACKUP_METRIC" 2>/dev/null || true
    fi

    CURRENT_ACTIVE="backup"
    LAST_FAILOVER=$(date -Iseconds)
    save_state

    log_warn "BACKUP WAN ACTIVATED - Traffic now routed through $BACKUP_IFACE (LTE)"
    return 0
}

# ============================================================
# FAILOVER LOGIC
# ============================================================

run_health_check() {
    # Main health check logic with hysteresis

    log_debug "Running health check (current: $CURRENT_ACTIVE, fail_count: $PRIMARY_FAIL_COUNT, recover_count: $PRIMARY_RECOVER_COUNT)"

    # Check primary connectivity
    if check_connectivity "$PRIMARY_IFACE"; then
        # Primary is healthy
        log_debug "Primary WAN is healthy"

        PRIMARY_FAIL_COUNT=0

        if [ "$CURRENT_ACTIVE" = "backup" ]; then
            # We're on backup, check if we should failback
            PRIMARY_RECOVER_COUNT=$((PRIMARY_RECOVER_COUNT + 1))
            log_info "Primary WAN recovering... ($PRIMARY_RECOVER_COUNT/$RECOVER_THRESHOLD)"

            if [ "$PRIMARY_RECOVER_COUNT" -ge "$RECOVER_THRESHOLD" ]; then
                log_info "Primary WAN recovered - initiating failback"
                activate_primary
                PRIMARY_RECOVER_COUNT=0
            fi
        fi
    else
        # Primary is unhealthy
        log_debug "Primary WAN is unhealthy"

        PRIMARY_RECOVER_COUNT=0
        PRIMARY_FAIL_COUNT=$((PRIMARY_FAIL_COUNT + 1))

        if [ "$CURRENT_ACTIVE" = "primary" ]; then
            log_warn "Primary WAN failure detected ($PRIMARY_FAIL_COUNT/$FAIL_THRESHOLD)"

            if [ "$PRIMARY_FAIL_COUNT" -ge "$FAIL_THRESHOLD" ]; then
                log_warn "Primary WAN down - initiating failover to backup"

                # Check if backup is healthy before failing over
                if [ -n "$BACKUP_IFACE" ] && check_connectivity "$BACKUP_IFACE"; then
                    activate_backup
                    PRIMARY_FAIL_COUNT=0
                else
                    log_error "Backup WAN also unhealthy - no failover possible!"
                fi
            fi
        fi
    fi

    save_state
}

# ============================================================
# DAEMON MODE
# ============================================================

cleanup() {
    log_info "WAN failover monitor stopping"
    rm -f "$LOCK_FILE"
    exit 0
}

run_daemon() {
    # Check for existing instance
    if [ -f "$LOCK_FILE" ]; then
        local pid
        pid=$(cat "$LOCK_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_error "Another instance is already running (PID: $pid)"
            exit 1
        fi
        rm -f "$LOCK_FILE"
    fi

    # Create lock file
    echo $$ > "$LOCK_FILE"
    trap cleanup EXIT INT TERM

    log_info "WAN failover monitor starting"
    log_info "Primary WAN: $PRIMARY_IFACE"
    log_info "Backup WAN: ${BACKUP_IFACE:-none}"
    log_info "Health targets: $HEALTH_TARGETS"
    log_info "Check interval: ${CHECK_INTERVAL}s"
    log_info "Fail threshold: $FAIL_THRESHOLD, Recover threshold: $RECOVER_THRESHOLD"

    # Validate configuration
    if [ -z "$PRIMARY_IFACE" ]; then
        log_error "No primary WAN interface detected"
        exit 1
    fi

    if [ -z "$BACKUP_IFACE" ]; then
        log_warn "No backup WAN interface detected - running in monitor-only mode"
    fi

    # Initial state setup
    if [ "$CURRENT_ACTIVE" = "primary" ]; then
        # Ensure routes are set correctly on startup
        if check_connectivity "$PRIMARY_IFACE"; then
            activate_primary
        elif [ -n "$BACKUP_IFACE" ] && check_connectivity "$BACKUP_IFACE"; then
            log_warn "Primary WAN down on startup - activating backup"
            activate_backup
        fi
    fi

    # Main monitoring loop
    while true; do
        run_health_check
        sleep "$CHECK_INTERVAL"
    done
}

# ============================================================
# STATUS AND CONTROL
# ============================================================

show_status() {
    load_config

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  HookProbe Fortress - WAN Failover Status${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Current active interface
    echo -e "  ${GREEN}Active WAN:${NC}"
    if [ "$CURRENT_ACTIVE" = "primary" ]; then
        echo -e "    ► ${GREEN}PRIMARY${NC}: $PRIMARY_IFACE"
    else
        echo -e "    ► ${YELLOW}BACKUP${NC}: $BACKUP_IFACE"
    fi
    echo ""

    # Primary WAN status
    echo -e "  ${GREEN}Primary WAN ($PRIMARY_IFACE):${NC}"
    if check_interface_link "$PRIMARY_IFACE"; then
        echo -e "    Link:     ${GREEN}UP${NC}"
    else
        echo -e "    Link:     ${RED}DOWN${NC}"
    fi
    if check_interface_ip "$PRIMARY_IFACE"; then
        local ip
        ip=$(ip addr show "$PRIMARY_IFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        echo -e "    IP:       ${GREEN}$ip${NC}"
    else
        echo -e "    IP:       ${RED}None${NC}"
    fi
    if check_connectivity "$PRIMARY_IFACE"; then
        echo -e "    Health:   ${GREEN}HEALTHY${NC}"
    else
        echo -e "    Health:   ${RED}UNREACHABLE${NC}"
    fi
    local primary_gw
    primary_gw=$(get_gateway_for_interface "$PRIMARY_IFACE")
    echo -e "    Gateway:  ${primary_gw:-unknown}"
    echo ""

    # Backup WAN status
    if [ -n "$BACKUP_IFACE" ]; then
        echo -e "  ${GREEN}Backup WAN ($BACKUP_IFACE):${NC}"
        if check_interface_link "$BACKUP_IFACE"; then
            echo -e "    Link:     ${GREEN}UP${NC}"
        else
            echo -e "    Link:     ${RED}DOWN${NC}"
        fi
        if check_interface_ip "$BACKUP_IFACE"; then
            local ip
            ip=$(ip addr show "$BACKUP_IFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
            echo -e "    IP:       ${GREEN}$ip${NC}"
        else
            echo -e "    IP:       ${RED}None${NC}"
        fi
        if check_connectivity "$BACKUP_IFACE"; then
            echo -e "    Health:   ${GREEN}HEALTHY${NC}"
        else
            echo -e "    Health:   ${YELLOW}UNREACHABLE${NC}"
        fi
        local backup_gw
        backup_gw=$(get_gateway_for_interface "$BACKUP_IFACE")
        echo -e "    Gateway:  ${backup_gw:-unknown}"
    else
        echo -e "  ${YELLOW}Backup WAN:${NC} Not configured"
    fi
    echo ""

    # Failover counters
    echo -e "  ${GREEN}Counters:${NC}"
    echo -e "    Fail count:    $PRIMARY_FAIL_COUNT / $FAIL_THRESHOLD"
    echo -e "    Recover count: $PRIMARY_RECOVER_COUNT / $RECOVER_THRESHOLD"
    echo ""

    # Current routes
    echo -e "  ${GREEN}Default Routes:${NC}"
    ip route show default 2>/dev/null | while read -r line; do
        echo "    $line"
    done
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

force_failover() {
    load_config
    log_warn "Manual failover requested"

    if [ -z "$BACKUP_IFACE" ]; then
        log_error "No backup interface configured"
        exit 1
    fi

    if ! check_connectivity "$BACKUP_IFACE"; then
        log_error "Backup interface is not healthy - failover may fail!"
    fi

    activate_backup
    echo -e "${GREEN}Failover complete - traffic now routed through $BACKUP_IFACE${NC}"
}

force_failback() {
    load_config
    log_info "Manual failback requested"

    if ! check_connectivity "$PRIMARY_IFACE"; then
        log_warn "Primary interface is not healthy - failback may fail!"
    fi

    activate_primary
    echo -e "${GREEN}Failback complete - traffic now routed through $PRIMARY_IFACE${NC}"
}

# ============================================================
# MAIN
# ============================================================

ensure_log_dir
load_config

case "${1:-}" in
    start|daemon)
        run_daemon
        ;;
    check)
        run_health_check
        ;;
    status)
        show_status
        ;;
    failover)
        force_failover
        ;;
    failback)
        force_failback
        ;;
    *)
        echo "Usage: $0 {start|check|status|failover|failback}"
        echo ""
        echo "Commands:"
        echo "  start     - Run as daemon (continuous monitoring)"
        echo "  check     - Single health check (for cron)"
        echo "  status    - Show current WAN status"
        echo "  failover  - Force failover to backup"
        echo "  failback  - Force failback to primary"
        echo ""
        exit 1
        ;;
esac
