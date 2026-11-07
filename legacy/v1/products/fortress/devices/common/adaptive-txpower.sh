#!/bin/bash
#
# adaptive-txpower.sh - Adaptive WiFi TX Power Management
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Dynamically adjusts WiFi transmission power based on:
#   - Client signal strength (RSSI)
#   - Number of connected clients
#   - Time of day (optional power save at night)
#
# This reduces interference, saves power, and optimizes coverage.
#
# Version: 1.0.0
# License: AGPL-3.0
#

set -e

# Configuration
CONFIG_FILE="${FORTRESS_TXPOWER_CONFIG:-/etc/fortress/txpower.conf}"
STATE_FILE="/var/lib/fortress/txpower-state.json"
LOG_FILE="/var/log/fortress/txpower.log"

# Default settings (can be overridden in config)
MIN_TXPOWER_DBM=5          # Minimum TX power (dBm)
MAX_TXPOWER_DBM=20         # Maximum TX power (dBm) - hardware dependent
DEFAULT_TXPOWER_DBM=15     # Default TX power
RSSI_THRESHOLD_NEAR=-50    # Client is "near" if RSSI > this (dBm)
RSSI_THRESHOLD_FAR=-75     # Client is "far" if RSSI < this (dBm)
ADJUST_INTERVAL=30         # Seconds between adjustments
NIGHT_MODE_START=22        # Hour to start night mode (reduce power)
NIGHT_MODE_END=7           # Hour to end night mode
NIGHT_MODE_REDUCTION=5     # dBm to reduce during night mode

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[TXPOWER]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[TXPOWER]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[TXPOWER]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[TXPOWER]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }

# Load configuration if exists
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        log_info "Loaded config from $CONFIG_FILE"
    fi
}

# Get current TX power for interface (in dBm)
get_current_txpower() {
    local iface="$1"
    local power

    # iw returns power in mBm (millidBm), divide by 100 for dBm
    power=$(iw dev "$iface" info 2>/dev/null | grep "txpower" | awk '{print $2}' | cut -d. -f1)

    if [ -n "$power" ]; then
        echo "$power"
    else
        echo "$DEFAULT_TXPOWER_DBM"
    fi
}

# Get maximum TX power supported by hardware
get_max_txpower() {
    local iface="$1"
    local phy
    local max_power

    phy=$(iw dev "$iface" info 2>/dev/null | grep wiphy | awk '{print $2}')

    if [ -n "$phy" ]; then
        # Get max power from any frequency (usually same across bands)
        max_power=$(iw phy "phy$phy" info 2>/dev/null | grep -oP '\[\d+\.\d+ dBm\]' | head -1 | grep -oP '[\d.]+' | cut -d. -f1)

        # Fallback: check iw phy output differently
        if [ -z "$max_power" ]; then
            max_power=$(iw phy 2>/dev/null | sed -n "/Wiphy phy$phy/,/^Wiphy /p" | grep "max TX power" | grep -oP '[\d.]+' | head -1 | cut -d. -f1)
        fi
    fi

    if [ -n "$max_power" ] && [ "$max_power" -gt 0 ] 2>/dev/null; then
        echo "$max_power"
    else
        echo "$MAX_TXPOWER_DBM"
    fi
}

# Set TX power for interface
set_txpower() {
    local iface="$1"
    local power_dbm="$2"
    local max_power

    max_power=$(get_max_txpower "$iface")

    # Clamp to valid range
    if [ "$power_dbm" -lt "$MIN_TXPOWER_DBM" ]; then
        power_dbm="$MIN_TXPOWER_DBM"
    elif [ "$power_dbm" -gt "$max_power" ]; then
        power_dbm="$max_power"
    fi

    # iw expects mBm (millidBm), so multiply by 100
    local power_mbm=$((power_dbm * 100))

    if iw dev "$iface" set txpower fixed "$power_mbm" 2>/dev/null; then
        log_success "Set $iface TX power to ${power_dbm} dBm"
        return 0
    else
        log_error "Failed to set TX power for $iface"
        return 1
    fi
}

# Get list of connected clients and their RSSI
get_client_rssi() {
    local iface="$1"

    # Use iw to get station info
    iw dev "$iface" station dump 2>/dev/null | grep -E "^Station|signal:" | \
        paste - - | awk '{print $2, $4}' | sed 's/ dBm//'
}

# Calculate optimal TX power based on client distances
calculate_optimal_power() {
    local iface="$1"
    local current_power
    local optimal_power
    local client_count=0
    local total_rssi=0
    local min_rssi=-100
    local max_rssi=-100

    current_power=$(get_current_txpower "$iface")

    # Read client RSSI values
    while read -r mac rssi; do
        [ -z "$mac" ] && continue

        client_count=$((client_count + 1))
        total_rssi=$((total_rssi + rssi))

        # Track min/max RSSI
        if [ "$rssi" -gt "$max_rssi" ]; then
            max_rssi="$rssi"
        fi
        if [ "$rssi" -lt "$min_rssi" ] || [ "$min_rssi" -eq -100 ]; then
            min_rssi="$rssi"
        fi
    done < <(get_client_rssi "$iface")

    # No clients - use default power
    if [ "$client_count" -eq 0 ]; then
        optimal_power="$DEFAULT_TXPOWER_DBM"
        log_info "$iface: No clients, using default power ${optimal_power} dBm"
        echo "$optimal_power"
        return
    fi

    # Calculate average RSSI
    local avg_rssi=$((total_rssi / client_count))

    # Determine power adjustment based on weakest client (min RSSI)
    # We want to ensure the farthest client has acceptable signal

    if [ "$min_rssi" -lt "$RSSI_THRESHOLD_FAR" ]; then
        # Weakest client is far - increase power
        optimal_power=$((current_power + 2))
        log_info "$iface: Weak client (RSSI=${min_rssi}dBm) - increasing power"
    elif [ "$min_rssi" -gt "$RSSI_THRESHOLD_NEAR" ]; then
        # All clients are near - can reduce power
        optimal_power=$((current_power - 2))
        log_info "$iface: All clients near (min RSSI=${min_rssi}dBm) - reducing power"
    else
        # Clients at reasonable distance - maintain current
        optimal_power="$current_power"
    fi

    # Apply night mode reduction if applicable
    local hour
    hour=$(date +%H | sed 's/^0//')

    if [ "$hour" -ge "$NIGHT_MODE_START" ] || [ "$hour" -lt "$NIGHT_MODE_END" ]; then
        optimal_power=$((optimal_power - NIGHT_MODE_REDUCTION))
        log_info "$iface: Night mode active - reducing by ${NIGHT_MODE_REDUCTION} dBm"
    fi

    # Clamp to valid range
    local max_hw
    max_hw=$(get_max_txpower "$iface")

    if [ "$optimal_power" -lt "$MIN_TXPOWER_DBM" ]; then
        optimal_power="$MIN_TXPOWER_DBM"
    elif [ "$optimal_power" -gt "$max_hw" ]; then
        optimal_power="$max_hw"
    fi

    log_info "$iface: Clients=$client_count AvgRSSI=${avg_rssi}dBm MinRSSI=${min_rssi}dBm -> ${optimal_power}dBm"
    echo "$optimal_power"
}

# Adjust power for a single interface
adjust_interface_power() {
    local iface="$1"
    local current_power
    local optimal_power

    current_power=$(get_current_txpower "$iface")
    optimal_power=$(calculate_optimal_power "$iface")

    if [ "$optimal_power" -ne "$current_power" ]; then
        set_txpower "$iface" "$optimal_power"
    fi
}

# Get all WiFi AP interfaces
get_ap_interfaces() {
    iw dev 2>/dev/null | grep -B1 "type AP" | grep "Interface" | awk '{print $2}'
}

# Main adjustment loop
run_adaptive_loop() {
    log_info "Starting adaptive TX power management"
    log_info "  Min power: ${MIN_TXPOWER_DBM} dBm"
    log_info "  Max power: ${MAX_TXPOWER_DBM} dBm"
    log_info "  Interval: ${ADJUST_INTERVAL}s"
    log_info "  Night mode: ${NIGHT_MODE_START}:00 - ${NIGHT_MODE_END}:00 (-${NIGHT_MODE_REDUCTION} dBm)"

    mkdir -p "$(dirname "$STATE_FILE")" "$(dirname "$LOG_FILE")"

    while true; do
        for iface in $(get_ap_interfaces); do
            adjust_interface_power "$iface"
        done

        sleep "$ADJUST_INTERVAL"
    done
}

# One-shot adjustment
adjust_once() {
    for iface in $(get_ap_interfaces); do
        adjust_interface_power "$iface"
    done
}

# Show current status
show_status() {
    echo "Adaptive TX Power Status"
    echo "========================"
    echo ""

    for iface in $(get_ap_interfaces); do
        local power
        local max_power
        local clients

        power=$(get_current_txpower "$iface")
        max_power=$(get_max_txpower "$iface")
        clients=$(iw dev "$iface" station dump 2>/dev/null | grep -c "^Station" || echo "0")

        echo "Interface: $iface"
        echo "  Current TX Power: ${power} dBm"
        echo "  Maximum TX Power: ${max_power} dBm"
        echo "  Connected Clients: $clients"

        if [ "$clients" -gt 0 ]; then
            echo "  Client RSSI:"
            get_client_rssi "$iface" | while read -r mac rssi; do
                echo "    $mac: ${rssi} dBm"
            done
        fi
        echo ""
    done
}

# Create systemd service
install_service() {
    cat > /etc/systemd/system/fts-adaptive-txpower.service << 'EOF'
[Unit]
Description=HookProbe Fortress - Adaptive WiFi TX Power
After=network.target fts-hostapd-24ghz.service fts-hostapd-5ghz.service
Wants=fts-hostapd-24ghz.service fts-hostapd-5ghz.service

[Service]
Type=simple
ExecStart=/opt/hookprobe/fortress/devices/common/adaptive-txpower.sh daemon
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Installed fts-adaptive-txpower.service"
    echo "To enable: systemctl enable --now fts-adaptive-txpower"
}

# Create default config
create_config() {
    mkdir -p "$(dirname "$CONFIG_FILE")"

    cat > "$CONFIG_FILE" << EOF
# Fortress Adaptive TX Power Configuration
#
# Automatically adjusts WiFi transmission power based on client distance

# Power limits (dBm)
MIN_TXPOWER_DBM=5
MAX_TXPOWER_DBM=20
DEFAULT_TXPOWER_DBM=15

# RSSI thresholds for power adjustment (dBm)
# Clients with RSSI > NEAR are considered close
# Clients with RSSI < FAR are considered distant
RSSI_THRESHOLD_NEAR=-50
RSSI_THRESHOLD_FAR=-75

# How often to adjust power (seconds)
ADJUST_INTERVAL=30

# Night mode - reduce power during quiet hours
NIGHT_MODE_START=22    # 10 PM
NIGHT_MODE_END=7       # 7 AM
NIGHT_MODE_REDUCTION=5 # dBm to reduce
EOF

    log_success "Created config at $CONFIG_FILE"
}

# Usage
usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  daemon          - Run continuous adaptive power loop"
    echo "  adjust          - One-shot power adjustment"
    echo "  status          - Show current power and client status"
    echo "  set <iface> <dBm> - Manually set TX power"
    echo "  install         - Install systemd service"
    echo "  config          - Create default configuration file"
    echo ""
    echo "Examples:"
    echo "  $0 daemon                    # Run as daemon"
    echo "  $0 adjust                    # Adjust once and exit"
    echo "  $0 status                    # Show current status"
    echo "  $0 set wlan0 15              # Set wlan0 to 15 dBm"
    echo ""
}

# Main
load_config

case "${1:-}" in
    daemon)
        run_adaptive_loop
        ;;
    adjust)
        adjust_once
        ;;
    status)
        show_status
        ;;
    set)
        [ -z "$2" ] && { echo "Usage: $0 set <iface> <dBm>"; exit 1; }
        [ -z "$3" ] && { echo "Usage: $0 set <iface> <dBm>"; exit 1; }
        set_txpower "$2" "$3"
        ;;
    install)
        install_service
        ;;
    config)
        create_config
        ;;
    *)
        usage
        ;;
esac
