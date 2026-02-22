#!/bin/bash
#
# Guardian WLAN Setup Script
# Prepares the AP interface (wlan1) for hostapd without requiring WAN connectivity
# Also ensures WAN interface (wlan0) is up for upstream connectivity
#
# This script runs early in boot to ensure clients can connect to the Guardian
# hotspot even when there's no upstream internet connection (eth0/wlan0)
#
# Version: 5.2.0
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

# Ensure interface is up and running
ensure_interface_up() {
    local iface="$1"
    local max_wait="${2:-10}"
    local count=0

    if [ ! -d "/sys/class/net/$iface" ]; then
        log_warn "Interface $iface not found"
        return 1
    fi

    # Check if interface is up
    if ip link show "$iface" | grep -q "state UP"; then
        log_info "$iface is already up"
        return 0
    fi

    log_info "Bringing up $iface..."

    # Unblock rfkill if needed
    rfkill unblock wifi 2>/dev/null || true

    # Bring interface up
    ip link set "$iface" up 2>/dev/null || true

    # Wait for interface to come up
    while [ $count -lt $max_wait ]; do
        if ip link show "$iface" 2>/dev/null | grep -q "state UP\|state UNKNOWN"; then
            log_info "$iface is up"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done

    # Check final state
    local state
    state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
    if [ "$state" = "up" ] || [ "$state" = "unknown" ]; then
        log_info "$iface state: $state (acceptable)"
        return 0
    fi

    log_warn "$iface failed to come up (state: $state)"
    return 1
}

# Setup WAN interface (wlan0) for upstream connectivity
# In single-radio mode (only wlan0, no wlan1), the AP uses wlan0 and
# WAN is via eth0 - skip WiFi WAN setup to avoid conflict with hostapd.
setup_wan_interface() {
    local wan_iface="${HOOKPROBE_WAN_IFACE:-wlan0}"
    local ap_iface="${1:-}"

    if [ ! -d "/sys/class/net/$wan_iface" ]; then
        log_info "WAN interface $wan_iface not present, skipping"
        return 0
    fi

    # Single-radio mode: if WAN and AP are the same interface, the radio
    # is reserved for AP (hostapd). WAN uplink goes through eth0 instead.
    if [ -n "$ap_iface" ] && [ "$wan_iface" = "$ap_iface" ]; then
        log_info "Single-radio mode: $wan_iface reserved for AP, WAN via eth0"
        echo "eth0" > /run/guardian/wan_interface 2>/dev/null || true
        return 0
    fi

    log_info "Setting up WAN interface: $wan_iface"

    # Ensure NetworkManager manages wlan0 for WAN connectivity
    if command -v nmcli &>/dev/null; then
        nmcli device set "$wan_iface" managed yes 2>/dev/null || true
    fi

    # Bring interface up
    ensure_interface_up "$wan_iface" 15

    # Write state
    echo "$wan_iface" > /run/guardian/wan_interface 2>/dev/null || true
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

    # Bring interface down for hostapd to configure
    ip link set "$iface" down 2>/dev/null || true
    sleep 1

    # Try to set AP mode (hostapd will also do this, but pre-setting helps)
    iw dev "$iface" set type __ap 2>/dev/null || \
        iw dev "$iface" set type ap 2>/dev/null || \
        log_warn "Could not pre-set AP mode, hostapd will handle it"

    # DO NOT bring interface up - let hostapd do it
    # hostapd needs to configure the interface from a down state
    log_info "$iface prepared for AP mode (interface down, ready for hostapd)"
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

    # Create state directory
    mkdir -p /run/guardian

    # Detect AP interface first (needed to avoid WAN/AP conflict on single-radio)
    local ap_iface
    if ! ap_iface=$(detect_ap_interface); then
        log_error "No WiFi interface found for AP mode"
        log_error "Please connect a USB WiFi adapter that supports AP mode"
        exit 1
    fi

    # Setup WAN interface (skips WiFi WAN if same as AP - single-radio mode)
    setup_wan_interface "$ap_iface"

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

    # Write state file for other services
    echo "$ap_iface" > /run/guardian/ap_interface

    # Log interface status
    log_info "Guardian WLAN Setup complete"
    log_info "  WAN interface: $(cat /run/guardian/wan_interface 2>/dev/null || echo 'N/A')"
    log_info "  AP interface: $ap_iface (ready for hostapd)"

    exit 0
}

main "$@"
