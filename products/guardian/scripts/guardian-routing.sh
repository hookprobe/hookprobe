#!/bin/bash
#
# Guardian Routing and WAN Failover Script
# Manages automatic failover between eth0 and wlan0 for WAN connectivity
#
# Features:
# - Automatic WAN failover from eth0 to wlan0
# - NAT masquerading for clients on br0/wlan1
# - Periodic health checks
# - Configurable route metrics
#
# Version: 5.1.0
# License: AGPL-3.0

set -e

# Configuration
WAN_PRIMARY="eth0"           # Primary WAN interface
WAN_SECONDARY="wlan0"        # Secondary WAN interface (WiFi uplink)
LAN_INTERFACE="br0"          # LAN bridge interface (clients connect here)
CHECK_INTERVAL=30            # Health check interval in seconds
CHECK_HOST="1.1.1.1"         # Host to ping for connectivity check
CHECK_COUNT=2                # Number of ping attempts
CHECK_TIMEOUT=5              # Ping timeout in seconds
METRIC_PRIMARY=100           # Route metric for primary (lower = preferred)
METRIC_SECONDARY=200         # Route metric for secondary

# State tracking
STATE_FILE="/run/guardian-wan-state"
LOG_FILE="/var/log/hookprobe/guardian-routing.log"
CURRENT_WAN=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ============================================================
# LOGGING
# ============================================================
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    case "$level" in
        INFO)  echo -e "${GREEN}[INFO]${NC} $message" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} $message" ;;
        *)     echo "[$level] $message" ;;
    esac
}

# ============================================================
# INTERFACE MANAGEMENT
# ============================================================
interface_exists() {
    local iface="$1"
    [ -d "/sys/class/net/$iface" ]
}

interface_is_up() {
    local iface="$1"
    local state
    if [ -f "/sys/class/net/$iface/operstate" ]; then
        state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null)
        [ "$state" = "up" ]
    else
        return 1
    fi
}

interface_has_ip() {
    local iface="$1"
    ip addr show "$iface" 2>/dev/null | grep -q "inet "
}

interface_has_gateway() {
    local iface="$1"
    ip route show dev "$iface" 2>/dev/null | grep -q "default"
}

# ============================================================
# CONNECTIVITY CHECKS
# ============================================================
check_wan_connectivity() {
    local iface="$1"

    if ! interface_exists "$iface"; then
        return 1
    fi

    if ! interface_is_up "$iface"; then
        return 1
    fi

    if ! interface_has_ip "$iface"; then
        return 1
    fi

    # Try to ping through specific interface
    # Use timeout to avoid hanging
    if timeout "$CHECK_TIMEOUT" ping -c "$CHECK_COUNT" -W "$CHECK_TIMEOUT" -I "$iface" "$CHECK_HOST" >/dev/null 2>&1; then
        return 0
    fi

    # Fallback: try DNS resolution as backup check
    if timeout "$CHECK_TIMEOUT" nslookup google.com >/dev/null 2>&1; then
        return 0
    fi

    return 1
}

get_interface_gateway() {
    local iface="$1"
    ip route show dev "$iface" 2>/dev/null | grep "default" | awk '{print $3}' | head -1
}

# ============================================================
# ROUTING MANAGEMENT
# ============================================================
setup_nat_for_interface() {
    local wan_iface="$1"

    log INFO "Setting up NAT for WAN interface: $wan_iface"

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Try nftables first
    if command -v nft &>/dev/null; then
        # Create nftables NAT rules
        nft -f - <<EOF 2>/dev/null || true
table ip guardian_nat
delete table ip guardian_nat

table ip guardian_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$wan_iface" masquerade
    }
}
EOF
        log INFO "nftables NAT configured for $wan_iface"
    else
        # Fallback to iptables
        iptables -t nat -F POSTROUTING 2>/dev/null || true
        iptables -t nat -A POSTROUTING -o "$wan_iface" -j MASQUERADE
        log INFO "iptables NAT configured for $wan_iface"
    fi
}

set_default_route() {
    local iface="$1"
    local metric="$2"
    local gateway

    gateway=$(get_interface_gateway "$iface")

    if [ -z "$gateway" ]; then
        # Try to get gateway from DHCP lease
        if [ -f "/var/lib/dhcpcd/dhcpcd-$iface.lease" ]; then
            gateway=$(grep -oP 'routers=\K[0-9.]+' "/var/lib/dhcpcd/dhcpcd-$iface.lease" 2>/dev/null | head -1)
        fi
    fi

    if [ -z "$gateway" ]; then
        log WARN "No gateway found for $iface, trying to add route without gateway"
        # Some interfaces (like PPP) don't need explicit gateway
        ip route add default dev "$iface" metric "$metric" 2>/dev/null || true
    else
        log INFO "Setting default route via $gateway dev $iface metric $metric"
        ip route add default via "$gateway" dev "$iface" metric "$metric" 2>/dev/null || true
    fi
}

remove_default_routes() {
    # Remove all default routes to start fresh
    while ip route del default 2>/dev/null; do
        :
    done
}

configure_wan() {
    local primary_up=false
    local secondary_up=false

    # Check primary WAN
    if interface_exists "$WAN_PRIMARY" && check_wan_connectivity "$WAN_PRIMARY"; then
        primary_up=true
    fi

    # Check secondary WAN
    if interface_exists "$WAN_SECONDARY" && check_wan_connectivity "$WAN_SECONDARY"; then
        secondary_up=true
    fi

    # Determine which WAN to use
    local new_wan=""

    if $primary_up; then
        new_wan="$WAN_PRIMARY"
        log INFO "Primary WAN ($WAN_PRIMARY) is available"
    elif $secondary_up; then
        new_wan="$WAN_SECONDARY"
        log INFO "Failover to secondary WAN ($WAN_SECONDARY)"
    else
        log ERROR "No WAN connectivity available"
        # Keep existing configuration, might recover
        return 1
    fi

    # Check if WAN changed
    if [ "$new_wan" != "$CURRENT_WAN" ]; then
        log INFO "Switching WAN from '$CURRENT_WAN' to '$new_wan'"

        # Update routing
        remove_default_routes

        # Set routes with appropriate metrics
        if $primary_up; then
            set_default_route "$WAN_PRIMARY" "$METRIC_PRIMARY"
        fi
        if $secondary_up; then
            set_default_route "$WAN_SECONDARY" "$METRIC_SECONDARY"
        fi

        # Configure NAT for active WAN
        setup_nat_for_interface "$new_wan"

        # Update state
        CURRENT_WAN="$new_wan"
        echo "$CURRENT_WAN" > "$STATE_FILE"

        log INFO "WAN switched to: $CURRENT_WAN"
    fi

    return 0
}

# ============================================================
# STARTUP CONFIGURATION
# ============================================================
initial_setup() {
    log INFO "Guardian Routing - Initial Setup"

    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

    # Load previous state if exists
    if [ -f "$STATE_FILE" ]; then
        CURRENT_WAN=$(cat "$STATE_FILE" 2>/dev/null || echo "")
    fi

    # Ensure IP forwarding is enabled persistently
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        mkdir -p /etc/sysctl.d
        echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-guardian-routing.conf
    fi
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

    # Configure initial WAN
    configure_wan

    log INFO "Initial setup complete. Active WAN: $CURRENT_WAN"
}

# ============================================================
# DAEMON MODE
# ============================================================
run_daemon() {
    log INFO "Guardian Routing Daemon started (check interval: ${CHECK_INTERVAL}s)"

    initial_setup

    while true; do
        sleep "$CHECK_INTERVAL"

        if ! configure_wan; then
            log WARN "WAN configuration failed, will retry"
        fi
    done
}

# ============================================================
# STATUS COMMAND
# ============================================================
show_status() {
    echo "Guardian Routing Status"
    echo "========================"
    echo ""

    # Current WAN
    if [ -f "$STATE_FILE" ]; then
        echo "Active WAN: $(cat "$STATE_FILE")"
    else
        echo "Active WAN: Unknown"
    fi
    echo ""

    # Primary WAN status
    echo "Primary WAN ($WAN_PRIMARY):"
    if interface_exists "$WAN_PRIMARY"; then
        echo "  Exists: Yes"
        echo "  Up: $(interface_is_up "$WAN_PRIMARY" && echo "Yes" || echo "No")"
        echo "  Has IP: $(interface_has_ip "$WAN_PRIMARY" && echo "Yes" || echo "No")"
        if interface_has_ip "$WAN_PRIMARY"; then
            ip addr show "$WAN_PRIMARY" 2>/dev/null | grep "inet " | awk '{print "  IP:", $2}'
        fi
        echo "  Connectivity: $(check_wan_connectivity "$WAN_PRIMARY" && echo "OK" || echo "FAILED")"
    else
        echo "  Exists: No"
    fi
    echo ""

    # Secondary WAN status
    echo "Secondary WAN ($WAN_SECONDARY):"
    if interface_exists "$WAN_SECONDARY"; then
        echo "  Exists: Yes"
        echo "  Up: $(interface_is_up "$WAN_SECONDARY" && echo "Yes" || echo "No")"
        echo "  Has IP: $(interface_has_ip "$WAN_SECONDARY" && echo "Yes" || echo "No")"
        if interface_has_ip "$WAN_SECONDARY"; then
            ip addr show "$WAN_SECONDARY" 2>/dev/null | grep "inet " | awk '{print "  IP:", $2}'
        fi
        echo "  Connectivity: $(check_wan_connectivity "$WAN_SECONDARY" && echo "OK" || echo "FAILED")"
    else
        echo "  Exists: No"
    fi
    echo ""

    # LAN status
    echo "LAN Interface ($LAN_INTERFACE):"
    if interface_exists "$LAN_INTERFACE"; then
        echo "  Exists: Yes"
        ip addr show "$LAN_INTERFACE" 2>/dev/null | grep "inet " | awk '{print "  IP:", $2}'
    else
        echo "  Exists: No"
    fi
    echo ""

    # Current routes
    echo "Default Routes:"
    ip route show | grep "^default" | while read -r line; do
        echo "  $line"
    done
    echo ""

    # NAT rules
    echo "NAT Rules:"
    if command -v nft &>/dev/null; then
        nft list table ip guardian_nat 2>/dev/null | grep masquerade || echo "  (no nftables rules)"
    fi
    iptables -t nat -L POSTROUTING -n 2>/dev/null | grep MASQUERADE || true
}

# ============================================================
# FORCE FAILOVER
# ============================================================
force_failover() {
    local target="$1"

    if [ -z "$target" ]; then
        echo "Usage: $0 failover <primary|secondary>"
        exit 1
    fi

    case "$target" in
        primary)
            log INFO "Forcing failover to primary WAN ($WAN_PRIMARY)"
            remove_default_routes
            set_default_route "$WAN_PRIMARY" "$METRIC_PRIMARY"
            setup_nat_for_interface "$WAN_PRIMARY"
            echo "$WAN_PRIMARY" > "$STATE_FILE"
            ;;
        secondary)
            log INFO "Forcing failover to secondary WAN ($WAN_SECONDARY)"
            remove_default_routes
            set_default_route "$WAN_SECONDARY" "$METRIC_SECONDARY"
            setup_nat_for_interface "$WAN_SECONDARY"
            echo "$WAN_SECONDARY" > "$STATE_FILE"
            ;;
        *)
            echo "Unknown target: $target"
            echo "Usage: $0 failover <primary|secondary>"
            exit 1
            ;;
    esac

    log INFO "Failover complete"
}

# ============================================================
# MAIN
# ============================================================
usage() {
    echo "Guardian Routing - WAN Failover Manager"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  start       Start the routing daemon (monitors and auto-fails over)"
    echo "  check       Run a single connectivity check and reconfigure if needed"
    echo "  status      Show current routing status"
    echo "  failover    Force failover to specific WAN"
    echo "    primary     Force to eth0"
    echo "    secondary   Force to wlan0"
    echo "  setup       Run initial setup without daemon"
    echo ""
    echo "Configuration:"
    echo "  Primary WAN:   $WAN_PRIMARY"
    echo "  Secondary WAN: $WAN_SECONDARY"
    echo "  LAN Bridge:    $LAN_INTERFACE"
    echo "  Check Host:    $CHECK_HOST"
    echo "  Check Interval: ${CHECK_INTERVAL}s"
    echo ""
}

main() {
    case "${1:-}" in
        start|daemon)
            run_daemon
            ;;
        check)
            initial_setup
            ;;
        status)
            show_status
            ;;
        failover)
            force_failover "${2:-}"
            ;;
        setup|init)
            initial_setup
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

# Run if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
