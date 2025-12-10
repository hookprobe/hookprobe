#!/bin/bash
#
# Guardian WiFi WAN Health Check
# Monitors and repairs wlan0 connection to upstream WiFi network
#
# Run manually: /usr/local/bin/guardian-wifi-health.sh
# Or via systemd timer for periodic checks
#
# Version: 5.1.0
# License: AGPL-3.0

set -e

LOG_TAG="guardian-wifi-health"
MAX_RETRIES=3
RETRY_DELAY=5
WPA_CONF="/etc/wpa_supplicant/wpa_supplicant-wlan0.conf"
INTERFACE="wlan0"

log_info() {
    logger -t "$LOG_TAG" -p user.info "$1"
    echo "[INFO] $1"
}

log_warn() {
    logger -t "$LOG_TAG" -p user.warning "$1"
    echo "[WARN] $1"
}

log_error() {
    logger -t "$LOG_TAG" -p user.err "$1"
    echo "[ERROR] $1"
}

# Check if wlan0 exists
check_interface_exists() {
    if [ -d "/sys/class/net/$INTERFACE" ]; then
        return 0
    fi
    return 1
}

# Check if wpa_supplicant config exists and has a network
check_config_exists() {
    if [ -f "$WPA_CONF" ] && grep -q "network=" "$WPA_CONF" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Get configured SSID from wpa_supplicant config
get_configured_ssid() {
    grep -oP 'ssid="\K[^"]+' "$WPA_CONF" 2>/dev/null | head -1
}

# Check if wpa_supplicant is running for wlan0
check_wpa_running() {
    if pgrep -f "wpa_supplicant.*$INTERFACE" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Get wpa_supplicant state
get_wpa_state() {
    wpa_cli -i "$INTERFACE" status 2>/dev/null | grep "^wpa_state=" | cut -d= -f2
}

# Get connected SSID
get_connected_ssid() {
    wpa_cli -i "$INTERFACE" status 2>/dev/null | grep "^ssid=" | cut -d= -f2
}

# Check if connected with IP
check_connected() {
    local state
    local ip

    state=$(get_wpa_state)
    if [ "$state" != "COMPLETED" ]; then
        return 1
    fi

    ip=$(ip -4 addr show "$INTERFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    if [ -z "$ip" ] || [[ "$ip" == 169.254.* ]]; then
        return 1
    fi

    return 0
}

# Fix WiFi connection
fix_wifi() {
    local ssid
    ssid=$(get_configured_ssid)

    log_info "Attempting to fix WiFi connection to '$ssid'..."

    # Stop existing wpa_supplicant
    log_info "Stopping wpa_supplicant..."
    pkill -9 -f "wpa_supplicant.*$INTERFACE" 2>/dev/null || true
    sleep 1

    # Unblock WiFi
    rfkill unblock wifi 2>/dev/null || true

    # Bring interface down
    ip link set "$INTERFACE" down 2>/dev/null || true
    sleep 1

    # Start wpa_supplicant
    log_info "Starting wpa_supplicant..."
    if ! wpa_supplicant -B -i "$INTERFACE" -c "$WPA_CONF" -D nl80211 2>/dev/null; then
        log_warn "nl80211 driver failed, trying wext..."
        if ! wpa_supplicant -B -i "$INTERFACE" -c "$WPA_CONF" -D wext 2>/dev/null; then
            log_error "Failed to start wpa_supplicant"
            return 1
        fi
    fi

    # Bring interface up
    sleep 1
    ip link set "$INTERFACE" up 2>/dev/null || true
    sleep 2

    # Wait for association (up to 10 seconds)
    local count=0
    while [ $count -lt 10 ]; do
        local state
        state=$(get_wpa_state)
        if [ "$state" = "COMPLETED" ]; then
            log_info "Associated with network"
            break
        fi
        sleep 1
        count=$((count + 1))
    done

    # Request DHCP lease
    log_info "Requesting DHCP lease..."
    if command -v dhclient >/dev/null 2>&1; then
        dhclient -4 "$INTERFACE" 2>/dev/null || true
    elif command -v dhcpcd >/dev/null 2>&1; then
        dhcpcd -4 "$INTERFACE" 2>/dev/null || true
    elif command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i "$INTERFACE" -n -q 2>/dev/null || true
    fi

    sleep 2
    return 0
}

# Main health check
main() {
    log_info "WiFi WAN health check starting..."

    # Check if interface exists
    if ! check_interface_exists; then
        log_info "Interface $INTERFACE not found - no USB WiFi adapter connected"
        exit 0
    fi

    # Check if config exists
    if ! check_config_exists; then
        log_info "No WiFi network configured in $WPA_CONF"
        exit 0
    fi

    local ssid
    ssid=$(get_configured_ssid)
    log_info "Configured network: $ssid"

    # Check if already connected
    if check_connected; then
        local connected_ssid
        local ip
        connected_ssid=$(get_connected_ssid)
        ip=$(ip -4 addr show "$INTERFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        log_info "WiFi health check PASSED - Connected to '$connected_ssid' with IP $ip"
        exit 0
    fi

    # Not connected, try to fix
    local retry=0
    while [ $retry -lt $MAX_RETRIES ]; do
        retry=$((retry + 1))
        log_warn "Not connected (attempt $retry/$MAX_RETRIES)"

        fix_wifi

        sleep 3

        if check_connected; then
            local ip
            ip=$(ip -4 addr show "$INTERFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
            log_info "WiFi health check PASSED after fix - Connected with IP $ip"
            exit 0
        fi

        if [ $retry -lt $MAX_RETRIES ]; then
            log_info "Waiting ${RETRY_DELAY}s before next attempt..."
            sleep $RETRY_DELAY
        fi
    done

    # Final check
    if check_connected; then
        log_info "WiFi health check PASSED after fixes"
        exit 0
    else
        local state
        state=$(get_wpa_state)
        log_error "WiFi health check FAILED after $MAX_RETRIES attempts (state: $state)"
        log_error "Check WiFi credentials or signal strength"
        exit 1
    fi
}

# Run if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
