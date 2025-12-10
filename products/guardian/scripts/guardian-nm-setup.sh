#!/bin/bash
#
# HookProbe Guardian - NetworkManager Setup Script
# Version: 5.1.0
#
# Generates NetworkManager configuration with actual MAC addresses
# to ensure stable connections and prevent MAC randomization interference.
#
# Usage: sudo ./guardian-nm-setup.sh [--force]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

FORCE=false
if [[ "$1" == "--force" ]]; then
    FORCE=true
fi

NM_CONF_DIR="/etc/NetworkManager/conf.d"
GUARDIAN_CONF="$NM_CONF_DIR/guardian-unmanaged.conf"

# ============================================================
# MAC ADDRESS DETECTION
# ============================================================
get_mac_address() {
    local iface="$1"
    if [ -f "/sys/class/net/$iface/address" ]; then
        cat "/sys/class/net/$iface/address" 2>/dev/null | tr '[:lower:]' '[:upper:]'
    fi
}

get_interface_driver() {
    local iface="$1"
    if [ -L "/sys/class/net/$iface/device/driver" ]; then
        basename "$(readlink -f /sys/class/net/$iface/device/driver)" 2>/dev/null
    fi
}

# Detect interfaces and their MACs
WLAN0_MAC=$(get_mac_address "wlan0")
WLAN1_MAC=$(get_mac_address "wlan1")
ETH0_MAC=$(get_mac_address "eth0")

log_info "Detected interfaces:"
[ -n "$WLAN0_MAC" ] && log_info "  wlan0: $WLAN0_MAC (WAN WiFi - will be managed)"
[ -n "$WLAN1_MAC" ] && log_info "  wlan1: $WLAN1_MAC (AP - will be unmanaged)"
[ -n "$ETH0_MAC" ] && log_info "  eth0:  $ETH0_MAC (Ethernet)"

# ============================================================
# GENERATE CONFIGURATION
# ============================================================
mkdir -p "$NM_CONF_DIR"

log_info "Generating NetworkManager configuration..."

cat > "$GUARDIAN_CONF" << EOF
# HookProbe Guardian - NetworkManager Configuration
# Generated: $(date -Iseconds)
# Version: 5.1.0
#
# This configuration prevents NetworkManager from interfering with
# interfaces managed by Open vSwitch and hostapd, while ensuring
# stable MAC addresses for managed interfaces.
#
# Detected MAC Addresses:
#   wlan0 (WAN WiFi): ${WLAN0_MAC:-not detected}
#   wlan1 (AP):       ${WLAN1_MAC:-not detected}
#   eth0 (Ethernet):  ${ETH0_MAC:-not detected}

[keyfile]
# ============================================================
# UNMANAGED DEVICES
# ============================================================
# Interfaces that NetworkManager should NOT manage
# wlan1 = AP (hostapd), br* = OVS bridges, ovs-* = OVS ports
unmanaged-devices=interface-name:wlan1;interface-name:br*;interface-name:ovs-*;interface-name:vlan*;interface-name:guardian;driver:openvswitch
EOF

# Add MAC-based unmanaged rule for wlan1 if detected
if [ -n "$WLAN1_MAC" ]; then
    # Append MAC to unmanaged devices for extra safety
    sed -i "s/driver:openvswitch/driver:openvswitch;mac:${WLAN1_MAC}/" "$GUARDIAN_CONF"
fi

cat >> "$GUARDIAN_CONF" << 'EOF'

[device]
# ============================================================
# MAC ADDRESS RANDOMIZATION - GLOBALLY DISABLED
# ============================================================
# Disable all MAC randomization to ensure stable connections
# and prevent interference with network policies

# Disable MAC randomization during WiFi scanning
wifi.scan-rand-mac-address=no

# Preserve original MAC addresses (no cloning/spoofing)
wifi.cloned-mac-address=preserve
ethernet.cloned-mac-address=preserve

EOF

# Add wlan0-specific section with its MAC
if [ -n "$WLAN0_MAC" ]; then
    cat >> "$GUARDIAN_CONF" << EOF
[device-wlan0-mac]
# wlan0 (WAN WiFi) - Preserve MAC: $WLAN0_MAC
match-device=mac:$WLAN0_MAC
wifi.scan-rand-mac-address=no
wifi.cloned-mac-address=preserve
managed=1

[device-wlan0-name]
# wlan0 by interface name (backup match)
match-device=interface-name:wlan0
wifi.scan-rand-mac-address=no
wifi.cloned-mac-address=preserve
managed=1

EOF
fi

# Add eth0-specific section with its MAC
if [ -n "$ETH0_MAC" ]; then
    cat >> "$GUARDIAN_CONF" << EOF
[device-eth0-mac]
# eth0 (Ethernet) - Preserve MAC: $ETH0_MAC
match-device=mac:$ETH0_MAC
ethernet.cloned-mac-address=preserve

[device-eth0-name]
# eth0 by interface name (backup match)
match-device=interface-name:eth0
ethernet.cloned-mac-address=preserve

EOF
fi

# Add wlan1 explicit unmanage by MAC
if [ -n "$WLAN1_MAC" ]; then
    cat >> "$GUARDIAN_CONF" << EOF
[device-wlan1-unmanaged]
# wlan1 (AP/hostapd) - MUST remain unmanaged
# MAC: $WLAN1_MAC
match-device=mac:$WLAN1_MAC
managed=0

EOF
fi

cat >> "$GUARDIAN_CONF" << 'EOF'
[connection]
# ============================================================
# CONNECTION DEFAULTS
# ============================================================
# Disable MAC randomization for all new connections
wifi.cloned-mac-address=preserve
ethernet.cloned-mac-address=preserve

# Don't auto-connect to random/unknown networks
wifi.wake-on-wlan=ignore

# Retry authentication up to 3 times
connection.auth-retries=3

[main]
# Use internal DHCP client (more reliable than dhclient)
dhcp=internal

# Don't modify resolv.conf - dnsmasq handles DNS for Guardian
dns=none

# Plugins (use keyfile for our config)
plugins=keyfile
EOF

chmod 644 "$GUARDIAN_CONF"

# ============================================================
# APPLY CONFIGURATION
# ============================================================
log_info "Reloading NetworkManager configuration..."

# Reload NetworkManager
if systemctl is-active --quiet NetworkManager; then
    nmcli general reload
    sleep 1

    # Explicitly set interface management
    if [ -n "$WLAN0_MAC" ] && [ -d "/sys/class/net/wlan0" ]; then
        nmcli device set wlan0 managed yes 2>/dev/null || true
        log_info "wlan0 set to managed"
    fi

    if [ -d "/sys/class/net/wlan1" ]; then
        nmcli device set wlan1 managed no 2>/dev/null || true
        log_info "wlan1 set to unmanaged"
    fi

    # Show final status
    echo ""
    log_info "Interface status:"
    nmcli device status 2>/dev/null | grep -E "wlan|eth" || true
else
    log_warn "NetworkManager not running. Configuration saved for next start."
fi

echo ""
log_info "Configuration saved to: $GUARDIAN_CONF"
log_info "MAC addresses are now preserved (no randomization)"

# ============================================================
# VERIFY
# ============================================================
echo ""
log_info "Verification:"
if [ -n "$WLAN0_MAC" ]; then
    current_mac=$(get_mac_address "wlan0")
    if [ "$current_mac" == "$WLAN0_MAC" ]; then
        log_info "  ✓ wlan0 MAC unchanged: $current_mac"
    else
        log_warn "  ! wlan0 MAC changed: $WLAN0_MAC -> $current_mac"
    fi
fi

if [ -n "$ETH0_MAC" ]; then
    current_mac=$(get_mac_address "eth0")
    if [ "$current_mac" == "$ETH0_MAC" ]; then
        log_info "  ✓ eth0 MAC unchanged: $current_mac"
    else
        log_warn "  ! eth0 MAC changed: $ETH0_MAC -> $current_mac"
    fi
fi

exit 0
