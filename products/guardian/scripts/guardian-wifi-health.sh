#!/bin/bash
#
# Guardian WiFi WAN Health Check
# Monitors and repairs wlan0 connection to upstream WiFi network
#
# Uses NetworkManager (nmcli) as primary method with wpa_supplicant fallback.
#
# Run manually: /usr/local/bin/guardian-wifi-health.sh
# Or via systemd timer for periodic checks
#
# Version: 5.1.1
# License: AGPL-3.0

set -e

LOG_TAG="guardian-wifi-health"
MAX_RETRIES=3
RETRY_DELAY=5
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

# ============================================================
# DETECTION FUNCTIONS
# ============================================================

# Check if interface exists
check_interface_exists() {
    [ -d "/sys/class/net/$INTERFACE" ]
}

# Check if NetworkManager is available and running
nmcli_available() {
    systemctl is-active NetworkManager &>/dev/null && command -v nmcli &>/dev/null
}

# Get configured SSID (from NM connection or wpa_supplicant)
get_configured_ssid() {
    if nmcli_available; then
        # Get active or most recent guardian connection for wlan0
        nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | \
            grep ":$INTERFACE$" | cut -d: -f1 | sed 's/^guardian-//' | head -1

        # If no active connection, check saved guardian connections
        if [ -z "$ssid" ]; then
            nmcli -t -f NAME connection show 2>/dev/null | \
                grep "^guardian-" | sed 's/^guardian-//' | head -1
        fi
    else
        # Fallback: check wpa_supplicant config
        local wpa_conf="/etc/wpa_supplicant/wpa_supplicant-wlan0.conf"
        if [ -f "$wpa_conf" ]; then
            grep -oP 'ssid="\K[^"]+' "$wpa_conf" 2>/dev/null | head -1
        fi
    fi
}

# Check if connected with valid IP
check_connected() {
    local ip
    ip=$(ip -4 addr show "$INTERFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

    # Must have IP and not be link-local
    if [ -n "$ip" ] && [[ ! "$ip" == 169.254.* ]]; then
        return 0
    fi
    return 1
}

# Get connection state
get_connection_state() {
    if nmcli_available; then
        nmcli -t -f GENERAL.STATE device show "$INTERFACE" 2>/dev/null | \
            cut -d: -f2 | head -1
    else
        wpa_cli -i "$INTERFACE" status 2>/dev/null | grep "^wpa_state=" | cut -d= -f2
    fi
}

# Get connected SSID
get_connected_ssid() {
    if nmcli_available; then
        nmcli -t -f GENERAL.CONNECTION device show "$INTERFACE" 2>/dev/null | \
            cut -d: -f2 | sed 's/^guardian-//'
    else
        wpa_cli -i "$INTERFACE" status 2>/dev/null | grep "^ssid=" | cut -d= -f2
    fi
}

# ============================================================
# FIX FUNCTIONS
# ============================================================

# Fix WiFi using NetworkManager
fix_wifi_nmcli() {
    local ssid="$1"

    log_info "Fixing WiFi via NetworkManager..."

    # Ensure wlan1 stays unmanaged (AP interface)
    nmcli device set wlan1 managed no 2>/dev/null || true

    # Ensure wlan0 is managed
    nmcli device set "$INTERFACE" managed yes 2>/dev/null || true
    sleep 1

    # Try to reconnect existing connection
    local conn_name="guardian-${ssid}"
    if nmcli connection show "$conn_name" &>/dev/null; then
        log_info "Reconnecting to saved connection: $conn_name"
        if nmcli connection up "$conn_name" 2>/dev/null; then
            sleep 3
            return 0
        fi
    fi

    # Try to bring up the device (will auto-connect if configured)
    log_info "Bringing up $INTERFACE..."
    nmcli device connect "$INTERFACE" 2>/dev/null || true
    sleep 3

    return 0
}

# Fix WiFi using wpa_supplicant (fallback)
fix_wifi_wpa() {
    local wpa_conf="/etc/wpa_supplicant/wpa_supplicant-wlan0.conf"

    if [ ! -f "$wpa_conf" ]; then
        log_error "No wpa_supplicant config found"
        return 1
    fi

    log_info "Fixing WiFi via wpa_supplicant (fallback)..."

    # Stop existing wpa_supplicant
    pkill -9 -f "wpa_supplicant.*$INTERFACE" 2>/dev/null || true
    sleep 1

    # Unblock WiFi
    rfkill unblock wifi 2>/dev/null || true

    # Bring interface down
    ip link set "$INTERFACE" down 2>/dev/null || true
    sleep 1

    # Start wpa_supplicant
    if ! wpa_supplicant -B -i "$INTERFACE" -c "$wpa_conf" -D nl80211 2>/dev/null; then
        if ! wpa_supplicant -B -i "$INTERFACE" -c "$wpa_conf" -D wext 2>/dev/null; then
            log_error "Failed to start wpa_supplicant"
            return 1
        fi
    fi

    # Bring interface up
    sleep 1
    ip link set "$INTERFACE" up 2>/dev/null || true
    sleep 2

    # Wait for association
    local count=0
    while [ $count -lt 10 ]; do
        local state
        state=$(wpa_cli -i "$INTERFACE" status 2>/dev/null | grep "^wpa_state=" | cut -d= -f2)
        if [ "$state" = "COMPLETED" ]; then
            break
        fi
        sleep 1
        count=$((count + 1))
    done

    # Request DHCP
    log_info "Requesting DHCP lease..."
    if command -v dhclient >/dev/null 2>&1; then
        dhclient -4 "$INTERFACE" 2>/dev/null || true
    elif command -v dhcpcd >/dev/null 2>&1; then
        dhcpcd -4 "$INTERFACE" 2>/dev/null || true
    fi

    sleep 2
    return 0
}

# Main fix function - tries nmcli first, then wpa_supplicant
fix_wifi() {
    local ssid
    ssid=$(get_configured_ssid)

    if [ -z "$ssid" ]; then
        log_error "No WiFi network configured"
        return 1
    fi

    log_info "Attempting to fix WiFi connection to '$ssid'..."

    # Unblock WiFi first
    rfkill unblock wifi 2>/dev/null || true

    if nmcli_available; then
        fix_wifi_nmcli "$ssid"
    else
        fix_wifi_wpa
    fi
}

# ============================================================
# MAIN
# ============================================================

main() {
    log_info "WiFi WAN health check starting..."

    # Check if interface exists
    if ! check_interface_exists; then
        log_info "Interface $INTERFACE not found - no USB WiFi adapter for WAN"
        exit 0
    fi

    # Check for configured network
    local ssid
    ssid=$(get_configured_ssid)
    if [ -z "$ssid" ]; then
        log_info "No WiFi network configured for $INTERFACE"
        exit 0
    fi

    log_info "Configured network: $ssid (method: $(nmcli_available && echo 'nmcli' || echo 'wpa_supplicant'))"

    # Check if already connected
    if check_connected; then
        local connected_ssid ip
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
        state=$(get_connection_state)
        log_error "WiFi health check FAILED after $MAX_RETRIES attempts (state: $state)"
        log_error "Check WiFi credentials or signal strength"
        exit 1
    fi
}

# Run if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
