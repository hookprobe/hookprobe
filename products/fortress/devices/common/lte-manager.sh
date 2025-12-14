#!/bin/bash
#
# lte-manager.sh - LTE Modem Management and WAN Failover for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Supports:
#   - LTE modem detection (Quectel, Sierra, Huawei, Fibocom)
#   - ModemManager integration
#   - WAN failover (Ethernet -> LTE)
#   - Connection health monitoring
#
# Usage:
#   source lte-manager.sh
#   detect_lte_modems
#   setup_wan_failover
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
LTE_STATE_DIR="/var/lib/fortress/lte"
LTE_CONFIG_FILE="$LTE_STATE_DIR/config.conf"
FAILOVER_STATE_FILE="$LTE_STATE_DIR/failover-state"
HEALTH_CHECK_INTERVAL=30  # seconds
FAILOVER_THRESHOLD=3      # consecutive failures before failover

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[LTE]${NC} $*"; }
log_success() { echo -e "${GREEN}[LTE]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[LTE]${NC} $*"; }
log_error() { echo -e "${RED}[LTE]${NC} $*"; }

# ============================================================
# LTE MODEM DETECTION
# ============================================================

# Known LTE modem USB IDs
declare -A LTE_MODEM_VENDORS=(
    ["2c7c"]="Quectel"
    ["1199"]="Sierra Wireless"
    ["12d1"]="Huawei"
    ["19d2"]="ZTE"
    ["2cb7"]="Fibocom"
    ["1bc7"]="Telit"
    ["05c6"]="Qualcomm"
    ["0489"]="Foxconn"
    ["413c"]="Dell"
    ["03f0"]="HP"
)

# Known modem models
declare -A LTE_MODEM_MODELS=(
    # Quectel
    ["2c7c:0125"]="EC25"
    ["2c7c:0121"]="EC21"
    ["2c7c:0306"]="EG25-G"
    ["2c7c:0512"]="EM05"
    ["2c7c:0620"]="EM120R"
    ["2c7c:0800"]="RM500Q"
    ["2c7c:0801"]="RM502Q"
    # Sierra Wireless
    ["1199:9071"]="EM7455"
    ["1199:9079"]="EM7565"
    ["1199:68c0"]="MC7455"
    ["1199:9091"]="EM7690"
    # Fibocom
    ["2cb7:0210"]="L850-GL"
    ["2cb7:0104"]="L830-EB"
    ["2cb7:01a0"]="FM150-AE"
)

detect_usb_lte_modems() {
    # Detect USB LTE modems using lsusb and sysfs
    #
    # Exports:
    #   LTE_MODEMS_FOUND - Array of detected modems
    #   LTE_MODEM_COUNT - Number of modems found

    log_info "Scanning for USB LTE modems..."

    declare -gA LTE_MODEMS_FOUND
    export LTE_MODEM_COUNT=0

    # Method 1: Parse lsusb
    if command -v lsusb &>/dev/null; then
        while IFS= read -r line; do
            # Extract vendor:product ID
            local usb_id=$(echo "$line" | grep -oP '\b[0-9a-f]{4}:[0-9a-f]{4}\b')
            local vendor_id=$(echo "$usb_id" | cut -d: -f1)
            local product_id=$(echo "$usb_id" | cut -d: -f2)

            # Check if it's a known LTE modem vendor
            if [ -n "${LTE_MODEM_VENDORS[$vendor_id]}" ]; then
                local vendor="${LTE_MODEM_VENDORS[$vendor_id]}"
                local model="${LTE_MODEM_MODELS[$usb_id]:-Unknown}"

                LTE_MODEMS_FOUND["$usb_id"]="$vendor $model"
                LTE_MODEM_COUNT=$((LTE_MODEM_COUNT + 1))

                log_info "  Found: $vendor $model ($usb_id)"
            fi
        done < <(lsusb 2>/dev/null)
    fi

    # Method 2: Check ModemManager
    if command -v mmcli &>/dev/null && systemctl is-active ModemManager &>/dev/null; then
        local modem_list
        modem_list=$(mmcli -L 2>/dev/null | grep "/Modem/" || true)

        while IFS= read -r line; do
            if [ -n "$line" ]; then
                local modem_path=$(echo "$line" | grep -oP '/org/freedesktop/ModemManager1/Modem/\d+')
                if [ -n "$modem_path" ]; then
                    local modem_idx=$(basename "$modem_path")
                    local modem_info
                    modem_info=$(mmcli -m "$modem_idx" 2>/dev/null | grep -E "manufacturer|model" | head -2)

                    log_info "  ModemManager modem $modem_idx:"
                    echo "$modem_info" | while read -r info_line; do
                        log_info "    $info_line"
                    done
                fi
            fi
        done <<< "$modem_list"
    fi

    # Method 3: Check for WWAN interfaces
    for iface in /sys/class/net/wwan* /sys/class/net/wwp*; do
        if [ -d "$iface" ]; then
            local name=$(basename "$iface")
            log_info "  Found WWAN interface: $name"
        fi
    done 2>/dev/null || true

    if [ "$LTE_MODEM_COUNT" -eq 0 ]; then
        log_warn "No LTE modems detected"
    else
        log_success "Found $LTE_MODEM_COUNT LTE modem(s)"
    fi

    export LTE_MODEMS_FOUND LTE_MODEM_COUNT
}

get_modem_interface() {
    # Get network interface name for LTE modem
    #
    # Args:
    #   $1 - Modem index (optional, defaults to first modem)
    #
    # Returns: Interface name (e.g., wwan0, usb0)

    local modem_idx="${1:-0}"

    # Try ModemManager first
    if command -v mmcli &>/dev/null; then
        local bearer_path
        bearer_path=$(mmcli -m "$modem_idx" 2>/dev/null | grep "primary port" | awk '{print $NF}')

        if [ -n "$bearer_path" ]; then
            echo "$bearer_path"
            return 0
        fi
    fi

    # Fallback: Find first wwan interface
    for iface in /sys/class/net/wwan* /sys/class/net/wwp*; do
        if [ -d "$iface" ]; then
            basename "$iface"
            return 0
        fi
    done 2>/dev/null

    return 1
}

# ============================================================
# MODEM CONFIGURATION
# ============================================================

configure_modem_apn() {
    # Configure APN settings for LTE modem
    #
    # Args:
    #   $1 - APN name (e.g., "internet", "fast.t-mobile.com")
    #   $2 - Modem index (optional)

    local apn="$1"
    local modem_idx="${2:-0}"

    [ -z "$apn" ] && { log_error "APN name required"; return 1; }

    log_info "Configuring APN: $apn for modem $modem_idx"

    if command -v mmcli &>/dev/null; then
        # Using ModemManager
        mmcli -m "$modem_idx" --simple-connect="apn=$apn" 2>/dev/null && {
            log_success "APN configured via ModemManager"
            return 0
        }
    fi

    # Alternative: Use QMI/MBIM directly (for Quectel modems)
    if command -v qmicli &>/dev/null; then
        local qmi_dev="/dev/cdc-wdm0"
        if [ -c "$qmi_dev" ]; then
            qmicli -d "$qmi_dev" --wds-start-network="apn=$apn" 2>/dev/null && {
                log_success "APN configured via QMI"
                return 0
            }
        fi
    fi

    log_error "Failed to configure APN"
    return 1
}

connect_lte_modem() {
    # Connect LTE modem and bring up interface
    #
    # Args:
    #   $1 - Modem index (optional)

    local modem_idx="${1:-0}"

    log_info "Connecting LTE modem $modem_idx..."

    # Ensure ModemManager is running
    if ! systemctl is-active ModemManager &>/dev/null; then
        systemctl start ModemManager
        sleep 2
    fi

    if command -v mmcli &>/dev/null; then
        # Enable modem
        mmcli -m "$modem_idx" -e 2>/dev/null || true

        # Check if already connected
        local state
        state=$(mmcli -m "$modem_idx" 2>/dev/null | grep "state:" | awk '{print $NF}')

        if [ "$state" = "connected" ]; then
            log_success "Modem already connected"
            return 0
        fi

        # Connect with configured APN
        local apn
        apn=$(grep "^LTE_APN=" "$LTE_CONFIG_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"')

        if [ -n "$apn" ]; then
            mmcli -m "$modem_idx" --simple-connect="apn=$apn" 2>/dev/null && {
                log_success "LTE connected with APN: $apn"
                return 0
            }
        else
            # Try to connect without explicit APN (auto-detect)
            mmcli -m "$modem_idx" --simple-connect="" 2>/dev/null && {
                log_success "LTE connected (auto APN)"
                return 0
            }
        fi
    fi

    log_error "Failed to connect LTE modem"
    return 1
}

disconnect_lte_modem() {
    # Disconnect LTE modem
    local modem_idx="${1:-0}"

    log_info "Disconnecting LTE modem $modem_idx..."

    if command -v mmcli &>/dev/null; then
        mmcli -m "$modem_idx" --simple-disconnect 2>/dev/null
        log_success "LTE disconnected"
    fi
}

get_lte_signal_strength() {
    # Get LTE signal strength
    #
    # Returns: Signal quality percentage (0-100)

    local modem_idx="${1:-0}"

    if command -v mmcli &>/dev/null; then
        local signal
        signal=$(mmcli -m "$modem_idx" --signal-get 2>/dev/null | grep "quality" | awk '{print $NF}' | tr -d '%')

        if [ -n "$signal" ]; then
            echo "$signal"
            return 0
        fi
    fi

    echo "0"
}

# ============================================================
# WAN FAILOVER
# ============================================================

setup_wan_failover() {
    # Set up WAN failover between primary WAN and LTE
    #
    # Args:
    #   $1 - Primary WAN interface
    #   $2 - LTE interface (optional, auto-detected)

    local primary_wan="${1:-$FORTRESS_WAN_IFACE}"
    local lte_iface="${2:-$(get_modem_interface)}"

    [ -z "$primary_wan" ] && { log_error "Primary WAN interface required"; return 1; }
    [ -z "$lte_iface" ] && { log_error "LTE interface not found"; return 1; }

    log_info "Setting up WAN failover:"
    log_info "  Primary: $primary_wan"
    log_info "  Backup:  $lte_iface (LTE)"

    # Create state directory
    mkdir -p "$LTE_STATE_DIR"

    # Save failover configuration
    cat > "$LTE_STATE_DIR/failover.conf" << EOF
# Fortress WAN Failover Configuration
PRIMARY_WAN="$primary_wan"
BACKUP_WAN="$lte_iface"
HEALTH_CHECK_INTERVAL=$HEALTH_CHECK_INTERVAL
FAILOVER_THRESHOLD=$FAILOVER_THRESHOLD
HEALTH_CHECK_HOSTS="1.1.1.1 8.8.8.8 9.9.9.9"
EOF

    # Initialize state
    echo "primary" > "$FAILOVER_STATE_FILE"

    # Set up routing tables for failover
    setup_failover_routing "$primary_wan" "$lte_iface"

    log_success "WAN failover configured"
}

setup_failover_routing() {
    # Configure policy routing for failover
    local primary="$1"
    local backup="$2"

    # Add routing tables if not exist
    grep -q "200 primary_wan" /etc/iproute2/rt_tables || echo "200 primary_wan" >> /etc/iproute2/rt_tables
    grep -q "201 backup_wan" /etc/iproute2/rt_tables || echo "201 backup_wan" >> /etc/iproute2/rt_tables

    # Rules will be added dynamically during failover
    log_info "Routing tables configured"
}

check_wan_health() {
    # Check if WAN interface has connectivity
    #
    # Args:
    #   $1 - Interface name
    #
    # Returns: 0 if healthy, 1 if not

    local iface="$1"
    local hosts="${HEALTH_CHECK_HOSTS:-1.1.1.1 8.8.8.8}"

    # Check if interface is up
    if ! ip link show "$iface" 2>/dev/null | grep -q "state UP"; then
        return 1
    fi

    # Check if interface has IP
    if ! ip addr show "$iface" 2>/dev/null | grep -q "inet "; then
        return 1
    fi

    # Ping test through specific interface
    for host in $hosts; do
        if ping -c 1 -W 3 -I "$iface" "$host" &>/dev/null; then
            return 0
        fi
    done

    return 1
}

perform_failover() {
    # Execute failover from primary to backup WAN
    #
    # Args:
    #   $1 - Direction: "to_backup" or "to_primary"

    local direction="${1:-to_backup}"

    source "$LTE_STATE_DIR/failover.conf" 2>/dev/null || return 1

    local current_state
    current_state=$(cat "$FAILOVER_STATE_FILE" 2>/dev/null || echo "primary")

    if [ "$direction" = "to_backup" ] && [ "$current_state" = "primary" ]; then
        log_warn "FAILOVER: Switching from $PRIMARY_WAN to $BACKUP_WAN (LTE)"

        # Connect LTE if not connected
        connect_lte_modem

        # Update default route
        local backup_gw
        backup_gw=$(ip route show dev "$BACKUP_WAN" 2>/dev/null | grep default | awk '{print $3}')

        if [ -n "$backup_gw" ]; then
            # Remove primary default route
            ip route del default via "$(ip route show dev "$PRIMARY_WAN" | grep default | awk '{print $3}')" 2>/dev/null || true

            # Add backup default route
            ip route add default via "$backup_gw" dev "$BACKUP_WAN" metric 100 2>/dev/null || true
        fi

        # Update state
        echo "backup" > "$FAILOVER_STATE_FILE"
        log_success "Failover complete - now using LTE"

    elif [ "$direction" = "to_primary" ] && [ "$current_state" = "backup" ]; then
        log_info "FAILBACK: Switching from $BACKUP_WAN (LTE) to $PRIMARY_WAN"

        # Update default route
        local primary_gw
        primary_gw=$(ip route show dev "$PRIMARY_WAN" 2>/dev/null | grep default | awk '{print $3}')

        if [ -n "$primary_gw" ]; then
            # Remove backup default route
            ip route del default via "$(ip route show dev "$BACKUP_WAN" | grep default | awk '{print $3}')" 2>/dev/null || true

            # Add primary default route
            ip route add default via "$primary_gw" dev "$PRIMARY_WAN" metric 50 2>/dev/null || true
        fi

        # Update state
        echo "primary" > "$FAILOVER_STATE_FILE"
        log_success "Failback complete - now using primary WAN"
    fi
}

monitor_wan_failover() {
    # Continuous WAN health monitoring loop
    # Runs in background, checks health and performs failover as needed

    source "$LTE_STATE_DIR/failover.conf" 2>/dev/null || { log_error "Failover not configured"; return 1; }

    local primary_failures=0
    local backup_available=false

    log_info "Starting WAN failover monitor..."
    log_info "  Checking every ${HEALTH_CHECK_INTERVAL}s"
    log_info "  Failover after $FAILOVER_THRESHOLD consecutive failures"

    while true; do
        local current_state
        current_state=$(cat "$FAILOVER_STATE_FILE" 2>/dev/null || echo "primary")

        # Check primary WAN
        if check_wan_health "$PRIMARY_WAN"; then
            primary_failures=0

            # If on backup, try to failback
            if [ "$current_state" = "backup" ]; then
                perform_failover "to_primary"
            fi
        else
            primary_failures=$((primary_failures + 1))
            log_warn "Primary WAN ($PRIMARY_WAN) unhealthy (failures: $primary_failures/$FAILOVER_THRESHOLD)"

            # Check if failover threshold reached
            if [ "$primary_failures" -ge "$FAILOVER_THRESHOLD" ] && [ "$current_state" = "primary" ]; then
                # Check if backup is available
                if check_wan_health "$BACKUP_WAN" 2>/dev/null || connect_lte_modem; then
                    perform_failover "to_backup"
                else
                    log_error "Primary WAN down, LTE backup unavailable!"
                fi
            fi
        fi

        sleep "$HEALTH_CHECK_INTERVAL"
    done
}

# ============================================================
# SYSTEMD SERVICE
# ============================================================

install_failover_service() {
    # Install systemd service for WAN failover monitoring

    log_info "Installing WAN failover systemd service..."

    cat > /etc/systemd/system/fortress-wan-failover.service << 'EOF'
[Unit]
Description=HookProbe Fortress WAN Failover Monitor
After=network-online.target ModemManager.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/hookprobe/fortress/devices/common/lte-manager.sh monitor
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fortress-wan-failover.service
    log_success "WAN failover service installed"
}

# ============================================================
# MAIN
# ============================================================

show_lte_status() {
    # Display current LTE modem and failover status

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  HookProbe Fortress - LTE Status${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Detect modems
    detect_usb_lte_modems

    echo ""

    # Show signal strength
    local signal=$(get_lte_signal_strength)
    echo -e "  ${GREEN}Signal:${NC}     $signal%"

    # Show failover state
    if [ -f "$FAILOVER_STATE_FILE" ]; then
        local state=$(cat "$FAILOVER_STATE_FILE")
        echo -e "  ${GREEN}Failover:${NC}   $state"
    else
        echo -e "  ${GREEN}Failover:${NC}   Not configured"
    fi

    # Show interface
    local lte_iface=$(get_modem_interface)
    if [ -n "$lte_iface" ]; then
        echo -e "  ${GREEN}Interface:${NC}  $lte_iface"
        local lte_ip=$(ip addr show "$lte_iface" 2>/dev/null | grep "inet " | awk '{print $2}')
        echo -e "  ${GREEN}IP:${NC}         ${lte_ip:-Not assigned}"
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  detect       - Detect LTE modems"
    echo "  status       - Show LTE and failover status"
    echo "  connect      - Connect LTE modem"
    echo "  disconnect   - Disconnect LTE modem"
    echo "  setup-failover <primary_wan> - Configure WAN failover"
    echo "  monitor      - Start failover monitoring (foreground)"
    echo "  install      - Install failover systemd service"
    echo ""
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        detect)
            detect_usb_lte_modems
            ;;
        status)
            show_lte_status
            ;;
        connect)
            connect_lte_modem "${2:-0}"
            ;;
        disconnect)
            disconnect_lte_modem "${2:-0}"
            ;;
        setup-failover)
            setup_wan_failover "$2" "$3"
            ;;
        monitor)
            monitor_wan_failover
            ;;
        install)
            install_failover_service
            ;;
        *)
            usage
            ;;
    esac
fi
