#!/bin/bash
#
# Guardian WLAN Setup Script
# Prepares the AP interface (wlan1) for hostapd without requiring WAN connectivity
#
# This script runs early in boot to ensure clients can connect to the Guardian
# hotspot even when there's no upstream internet connection (eth0/wlan0)
#
# Version: 5.1.0
# License: AGPL-3.0

set -e

LOG_TAG="guardian-wlan"

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

# Determine AP interface
# Priority: HOOKPROBE_AP_IFACE env var > wlan1 > first available wlan
detect_ap_interface() {
    local iface="${HOOKPROBE_AP_IFACE:-}"

    if [ -n "$iface" ] && [ -d "/sys/class/net/$iface" ]; then
        echo "$iface"
        return 0
    fi

    # Prefer wlan1 for AP (wlan0 is typically for WAN)
    if [ -d "/sys/class/net/wlan1" ]; then
        echo "wlan1"
        return 0
    fi

    # Fallback to first available wlan interface
    local first_wlan
    first_wlan=$(ls /sys/class/net/ 2>/dev/null | grep -E '^wlan' | head -1)
    if [ -n "$first_wlan" ]; then
        echo "$first_wlan"
        return 0
    fi

    return 1
}

# Wait for USB WiFi adapter to be detected
wait_for_interface() {
    local iface="$1"
    local max_wait=30
    local count=0

    while [ ! -d "/sys/class/net/$iface" ] && [ $count -lt $max_wait ]; do
        sleep 1
        count=$((count + 1))
        if [ $((count % 5)) -eq 0 ]; then
            log_info "Waiting for $iface... ($count/$max_wait)"
        fi
    done

    if [ -d "/sys/class/net/$iface" ]; then
        return 0
    fi
    return 1
}

# Check if interface supports AP mode
check_ap_support() {
    local iface="$1"

    if iw list 2>/dev/null | grep -A 15 "Supported interface modes" | grep -q "\* AP"; then
        return 0
    fi

    log_warn "$iface may not support AP mode"
    return 1
}

# Kill any processes that might interfere with hostapd
kill_interfering_processes() {
    local iface="$1"

    # Kill wpa_supplicant on AP interface
    pkill -f "wpa_supplicant.*$iface" 2>/dev/null || true

    # Kill NetworkManager control of this interface (if installed)
    if command -v nmcli &>/dev/null; then
        nmcli device set "$iface" managed no 2>/dev/null || true
    fi

    sleep 1
}

# Set interface to AP mode
prepare_interface() {
    local iface="$1"

    log_info "Preparing $iface for AP mode..."

    # Remove interface from any existing bridge
    for br in $(ls /sys/class/net/*/brif 2>/dev/null | xargs -I{} dirname {} | xargs -I{} basename {} 2>/dev/null); do
        ip link set "$iface" nomaster 2>/dev/null || true
    done

    # Bring interface down
    ip link set "$iface" down 2>/dev/null || true
    sleep 1

    # Try to set AP mode (hostapd will also do this, but pre-setting helps)
    iw dev "$iface" set type __ap 2>/dev/null || \
        iw dev "$iface" set type ap 2>/dev/null || \
        log_warn "Could not pre-set AP mode, hostapd will handle it"

    # Bring interface up
    ip link set "$iface" up 2>/dev/null || true
    sleep 1

    log_info "$iface prepared for AP mode"
}

# Create bridge interface if needed
setup_bridge() {
    local bridge_ip="${HOOKPROBE_BRIDGE_IP:-192.168.4.1}"

    # Check if br0 exists
    if ! ip link show br0 &>/dev/null; then
        log_info "Creating bridge interface br0..."
        ip link add br0 type bridge 2>/dev/null || true
    fi

    # Ensure bridge is up
    ip link set br0 up 2>/dev/null || true

    # Set IP if not already set
    if ! ip addr show br0 | grep -q "$bridge_ip"; then
        ip addr add "$bridge_ip/27" dev br0 2>/dev/null || true
        log_info "Set bridge IP: $bridge_ip/27"
    fi
}

# Set regulatory domain
set_regulatory_domain() {
    local country="${HOOKPROBE_COUNTRY:-}"

    if [ -z "$country" ]; then
        # Try to get from hostapd config
        country=$(grep "^country_code=" /etc/hostapd/hostapd.conf 2>/dev/null | cut -d= -f2)
    fi

    if [ -z "$country" ]; then
        # Try system regulatory domain
        country=$(iw reg get 2>/dev/null | grep -oP 'country \K[A-Z]{2}' | head -1)
    fi

    if [ -n "$country" ] && [ "$country" != "00" ]; then
        log_info "Setting regulatory domain: $country"
        iw reg set "$country" 2>/dev/null || true
        sleep 1
    fi
}

# Main execution
main() {
    log_info "Guardian WLAN Setup starting..."

    # Detect AP interface
    local ap_iface
    if ! ap_iface=$(detect_ap_interface); then
        log_error "No WiFi interface found for AP mode"
        log_error "Please connect a USB WiFi adapter that supports AP mode"
        exit 1
    fi

    log_info "Using AP interface: $ap_iface"

    # Wait for interface (USB adapters may take time)
    if ! wait_for_interface "$ap_iface"; then
        log_error "Interface $ap_iface not available after 30 seconds"
        exit 1
    fi

    # Check AP mode support
    check_ap_support "$ap_iface" || true

    # Kill interfering processes
    kill_interfering_processes "$ap_iface"

    # Set regulatory domain before configuring
    set_regulatory_domain

    # Prepare interface for AP mode
    prepare_interface "$ap_iface"

    # Setup bridge interface
    setup_bridge

    # Update hostapd config with correct interface name if needed
    if [ -f /etc/hostapd/hostapd.conf ]; then
        local current_iface
        current_iface=$(grep "^interface=" /etc/hostapd/hostapd.conf | cut -d= -f2)
        if [ "$current_iface" != "$ap_iface" ]; then
            log_info "Updating hostapd interface: $current_iface -> $ap_iface"
            sed -i "s/^interface=.*/interface=$ap_iface/" /etc/hostapd/hostapd.conf
        fi
    fi

    log_info "Guardian WLAN Setup complete - interface $ap_iface ready for hostapd"

    # Write state file for other services
    mkdir -p /run/guardian
    echo "$ap_iface" > /run/guardian/ap_interface

    exit 0
}

main "$@"
