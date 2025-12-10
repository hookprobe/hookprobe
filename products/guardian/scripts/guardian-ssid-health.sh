#!/bin/bash
#
# Guardian SSID Health Check
# Monitors and fixes SSID broadcasting issues
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

# Get the configured SSID from hostapd.conf
get_configured_ssid() {
    grep "^ssid=" /etc/hostapd/hostapd.conf 2>/dev/null | cut -d= -f2
}

# Get the AP interface from hostapd.conf or detect it
get_ap_interface() {
    local iface
    iface=$(grep "^interface=" /etc/hostapd/hostapd.conf 2>/dev/null | cut -d= -f2)
    if [ -z "$iface" ]; then
        iface="wlan1"
    fi
    echo "$iface"
}

# Check if SSID is being broadcast
check_ssid_broadcasting() {
    local iface="$1"
    local expected_ssid="$2"

    # Check if interface exists
    if [ ! -d "/sys/class/net/$iface" ]; then
        log_warn "Interface $iface does not exist"
        return 1
    fi

    # Check if interface is UP
    if ! ip link show "$iface" | grep -q "state UP"; then
        log_warn "Interface $iface is not UP"
        return 1
    fi

    # Check if hostapd is running
    if ! systemctl is-active --quiet hostapd; then
        log_warn "hostapd is not running"
        return 1
    fi

    # Check if iw dev shows the SSID
    local current_ssid
    current_ssid=$(iw dev "$iface" info 2>/dev/null | grep -oP 'ssid \K.*' || true)

    if [ -z "$current_ssid" ]; then
        log_warn "No SSID found on $iface (iw dev shows no ssid)"
        return 1
    fi

    if [ "$current_ssid" != "$expected_ssid" ]; then
        log_warn "SSID mismatch: expected '$expected_ssid', got '$current_ssid'"
        return 1
    fi

    log_info "SSID '$current_ssid' is broadcasting on $iface"
    return 0
}

# Fix SSID by restarting services
fix_ssid() {
    local iface="$1"

    log_info "Attempting to fix SSID on $iface..."

    # Stop services
    log_info "Stopping services..."
    systemctl stop hostapd 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true
    sleep 2

    # Kill any interfering processes
    pkill -f "wpa_supplicant.*$iface" 2>/dev/null || true

    # Bring interface down
    ip link set "$iface" down 2>/dev/null || true
    sleep 1

    # Set AP mode
    iw dev "$iface" set type __ap 2>/dev/null || \
        iw dev "$iface" set type ap 2>/dev/null || true

    # Run guardian-wlan-setup if available
    if [ -x /usr/local/bin/guardian-wlan-setup.sh ]; then
        log_info "Running guardian-wlan-setup.sh..."
        /usr/local/bin/guardian-wlan-setup.sh || true
    fi

    # Start hostapd
    log_info "Starting hostapd..."
    systemctl start hostapd
    sleep 3

    # Start dnsmasq
    log_info "Starting dnsmasq..."
    systemctl start dnsmasq
    sleep 2

    return 0
}

# Main health check loop
main() {
    local iface
    local ssid
    local retry=0

    iface=$(get_ap_interface)
    ssid=$(get_configured_ssid)

    if [ -z "$ssid" ]; then
        log_error "No SSID configured in /etc/hostapd/hostapd.conf"
        exit 1
    fi

    log_info "Health check starting - Interface: $iface, Expected SSID: $ssid"

    # Check if SSID is broadcasting
    while [ $retry -lt $MAX_RETRIES ]; do
        if check_ssid_broadcasting "$iface" "$ssid"; then
            log_info "SSID health check PASSED"
            exit 0
        fi

        retry=$((retry + 1))
        log_warn "SSID not broadcasting (attempt $retry/$MAX_RETRIES)"

        if [ $retry -lt $MAX_RETRIES ]; then
            fix_ssid "$iface"
            log_info "Waiting ${RETRY_DELAY}s before next check..."
            sleep $RETRY_DELAY
        fi
    done

    # Final check after all retries
    if check_ssid_broadcasting "$iface" "$ssid"; then
        log_info "SSID health check PASSED after fixes"
        exit 0
    else
        log_error "SSID health check FAILED after $MAX_RETRIES attempts"
        log_error "Manual intervention may be required"
        log_error "Debug: iw dev $iface info"
        iw dev "$iface" info 2>&1 || true
        exit 1
    fi
}

# Run if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
