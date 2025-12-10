#!/bin/bash
#
# Guardian SSID Health Check
# Monitors and repairs wlan1 AP mode to ensure SSID is always broadcasting
#
# Run manually: /usr/local/bin/guardian-ssid-health.sh
# Or via systemd timer for periodic checks
#
# Version: 5.1.0
# License: AGPL-3.0

set -e

LOG_TAG="guardian-ssid-health"
MAX_RETRIES=3
RETRY_DELAY=5
INTERFACE="wlan1"

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

# Check if interface exists
check_interface_exists() {
    if [ -d "/sys/class/net/$INTERFACE" ]; then
        return 0
    fi
    return 1
}

# Check if SSID is broadcasting using iw dev
check_ssid_broadcasting() {
    local ssid
    ssid=$(iw dev "$INTERFACE" info 2>/dev/null | grep -oP 'ssid\s+\K.*' | head -1)
    if [ -n "$ssid" ]; then
        echo "$ssid"
        return 0
    fi
    return 1
}

# Get configured SSID from hostapd.conf
get_configured_ssid() {
    grep -oP '^ssid=\K.*' /etc/hostapd/hostapd.conf 2>/dev/null | head -1
}

# Check if hostapd is running
check_hostapd_running() {
    if systemctl is-active --quiet hostapd; then
        return 0
    fi
    return 1
}

# Fix SSID by restarting services
fix_ssid() {
    local expected_ssid="$1"

    log_info "Attempting to fix SSID broadcast..."

    # Stop services
    log_info "Stopping services..."
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl stop hostapd 2>/dev/null || true

    # Restart guardian-wlan to prepare interface
    if systemctl is-active --quiet guardian-wlan; then
        systemctl restart guardian-wlan 2>/dev/null || true
    else
        systemctl start guardian-wlan 2>/dev/null || true
    fi
    sleep 2

    # Start hostapd
    log_info "Starting hostapd..."
    systemctl start hostapd 2>/dev/null || {
        log_warn "hostapd failed to start via systemctl, trying direct..."
        hostapd -B /etc/hostapd/hostapd.conf 2>/dev/null || true
    }
    sleep 3

    # Start dnsmasq
    log_info "Starting dnsmasq..."
    systemctl start dnsmasq 2>/dev/null || true
    sleep 2

    return 0
}

# Main health check
main() {
    log_info "SSID health check starting..."

    # Check if interface exists
    if ! check_interface_exists; then
        log_info "Interface $INTERFACE not found - no second WiFi adapter connected"
        exit 0
    fi

    # Get expected SSID
    local expected_ssid
    expected_ssid=$(get_configured_ssid)
    if [ -z "$expected_ssid" ]; then
        log_info "No SSID configured in hostapd.conf"
        exit 0
    fi
    log_info "Expected SSID: $expected_ssid"

    # Check if SSID is broadcasting
    local current_ssid
    if current_ssid=$(check_ssid_broadcasting); then
        if [ "$current_ssid" = "$expected_ssid" ]; then
            log_info "SSID health check PASSED - '$current_ssid' is broadcasting"
            exit 0
        else
            log_warn "Wrong SSID broadcasting: '$current_ssid' (expected '$expected_ssid')"
        fi
    else
        log_warn "SSID is not broadcasting"
    fi

    # Not broadcasting correctly, try to fix
    local retry=0
    while [ $retry -lt $MAX_RETRIES ]; do
        retry=$((retry + 1))
        log_warn "Attempting fix (attempt $retry/$MAX_RETRIES)..."

        fix_ssid "$expected_ssid"

        if current_ssid=$(check_ssid_broadcasting); then
            if [ "$current_ssid" = "$expected_ssid" ]; then
                log_info "SSID health check PASSED after fix - '$current_ssid' is broadcasting"
                exit 0
            fi
        fi

        if [ $retry -lt $MAX_RETRIES ]; then
            log_info "Waiting ${RETRY_DELAY}s before next attempt..."
            sleep $RETRY_DELAY
        fi
    done

    # Final check
    if current_ssid=$(check_ssid_broadcasting) && [ "$current_ssid" = "$expected_ssid" ]; then
        log_info "SSID health check PASSED after fixes"
        exit 0
    else
        log_error "SSID health check FAILED after $MAX_RETRIES attempts"
        log_error "Check hostapd configuration or wireless adapter"
        exit 1
    fi
}

# Run if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
