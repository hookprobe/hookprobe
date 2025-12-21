#!/bin/bash
#
# HookProbe Fortress - WiFi Setup Fix Script
# Run this if WiFi packages weren't installed during main installation
#
# Usage: sudo ./fix-wifi-setup.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Ensure root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVICES_DIR="${SCRIPT_DIR}/devices"
INSTALL_DIR="/opt/hookprobe/fortress"
CONFIG_DIR="/etc/hookprobe"

log_info "=== HookProbe Fortress WiFi Setup Fix ==="
echo ""

# Step 1: Check and fix DNS
log_info "Step 1: Checking network connectivity..."
if ! timeout 5 bash -c 'exec 3<>/dev/tcp/archive.ubuntu.com/80' 2>/dev/null; then
    if ! timeout 5 bash -c 'exec 3<>/dev/tcp/8.8.8.8/53' 2>/dev/null; then
        log_error "No network connectivity!"
        log_error "Ensure your WAN interface has internet access"
        exit 1
    else
        log_warn "DNS not working, adding fallback nameservers..."
        echo "nameserver 1.1.1.1" >> /etc/resolv.conf
        echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    fi
fi
log_info "Network: OK"

# Step 2: Install WiFi packages
log_info "Step 2: Installing WiFi packages..."
apt-get update
apt-get install -y hostapd iw wireless-tools || {
    log_error "Failed to install WiFi packages"
    exit 1
}
log_info "Packages installed: hostapd, iw, wireless-tools"

# Step 3: Source network integration and detect interfaces
log_info "Step 3: Detecting WiFi interfaces..."
INTEGRATION_SCRIPT="${DEVICES_DIR}/common/network-integration.sh"

if [ -f "$INTEGRATION_SCRIPT" ]; then
    source "$INTEGRATION_SCRIPT"
    network_integration_init || true

    log_info "Detected interfaces:"
    log_info "  2.4GHz: ${NET_WIFI_24GHZ_IFACE:-not detected}"
    log_info "  5GHz:   ${NET_WIFI_5GHZ_IFACE:-not detected}"
else
    log_error "Network integration script not found: $INTEGRATION_SCRIPT"
    exit 1
fi

# Step 4: Create WiFi udev rules
log_info "Step 4: Creating WiFi udev rules..."

# Detect interfaces using iw dev
iface_24ghz=""
iface_5ghz=""
mac_24ghz=""
mac_5ghz=""

for iface in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
    # Get MAC address
    mac=$(cat /sys/class/net/$iface/address 2>/dev/null || true)
    [ -z "$mac" ] && continue

    # Get supported bands
    phy=$(iw dev "$iface" info 2>/dev/null | awk '/wiphy/{print $2}')
    [ -z "$phy" ] && continue

    bands=$(iw phy "phy${phy}" info 2>/dev/null | grep -E "^\s+Band [0-9]:" | wc -l)
    has_5ghz=$(iw phy "phy${phy}" info 2>/dev/null | grep -A100 "Band 2:" | grep -c "MHz" || echo 0)

    if [ "$has_5ghz" -gt 0 ]; then
        # This interface supports 5GHz
        if [ -z "$iface_5ghz" ]; then
            iface_5ghz="$iface"
            mac_5ghz="$mac"
            log_info "  Found 5GHz: $iface ($mac)"
        elif [ -z "$iface_24ghz" ]; then
            # Dual-band - second radio for 2.4GHz
            iface_24ghz="$iface"
            mac_24ghz="$mac"
            log_info "  Found 2.4GHz: $iface ($mac)"
        fi
    else
        # 2.4GHz only
        if [ -z "$iface_24ghz" ]; then
            iface_24ghz="$iface"
            mac_24ghz="$mac"
            log_info "  Found 2.4GHz only: $iface ($mac)"
        fi
    fi
done

if [ -z "$iface_24ghz" ] && [ -z "$iface_5ghz" ]; then
    log_error "No WiFi interfaces detected!"
    exit 1
fi

# Create udev rules
udev_rule_file="/etc/udev/rules.d/70-fortress-wifi.rules"
log_info "Creating $udev_rule_file..."

cat > "$udev_rule_file" << EOF
# HookProbe Fortress WiFi Interface Naming
# Generated: $(date -Iseconds)
# Provides stable interface names for WiFi APs

EOF

if [ -n "$mac_24ghz" ]; then
    echo "SUBSYSTEM==\"net\", ACTION==\"add\", ATTR{address}==\"$mac_24ghz\", NAME=\"wlan_24ghz\"" >> "$udev_rule_file"
fi
if [ -n "$mac_5ghz" ]; then
    echo "SUBSYSTEM==\"net\", ACTION==\"add\", ATTR{address}==\"$mac_5ghz\", NAME=\"wlan_5ghz\"" >> "$udev_rule_file"
fi

log_info "Created udev rules"

# Step 5: Rename interfaces now
log_info "Step 5: Renaming interfaces..."
udevadm control --reload-rules
udevadm settle --timeout=5 2>/dev/null || sleep 1

if [ -n "$iface_24ghz" ] && [ "$iface_24ghz" != "wlan_24ghz" ]; then
    log_info "  Renaming $iface_24ghz -> wlan_24ghz"
    ip link set "$iface_24ghz" down 2>/dev/null || true
    if ip link set "$iface_24ghz" name wlan_24ghz 2>/dev/null; then
        ip link set wlan_24ghz up 2>/dev/null || true
        log_info "  Success"
    else
        log_warn "  Could not rename (will work after reboot)"
    fi
fi

if [ -n "$iface_5ghz" ] && [ "$iface_5ghz" != "wlan_5ghz" ]; then
    log_info "  Renaming $iface_5ghz -> wlan_5ghz"
    ip link set "$iface_5ghz" down 2>/dev/null || true
    if ip link set "$iface_5ghz" name wlan_5ghz 2>/dev/null; then
        ip link set wlan_5ghz up 2>/dev/null || true
        log_info "  Success"
    else
        log_warn "  Could not rename (will work after reboot)"
    fi
fi

# Step 6: Generate hostapd configuration
log_info "Step 6: Generating hostapd configuration..."
HOSTAPD_SCRIPT="${DEVICES_DIR}/common/hostapd-generator.sh"
OVS_BRIDGE="43ess"

# Get WiFi credentials
WIFI_SSID=$(grep "^WIFI_SSID=" "$CONFIG_DIR/fortress.conf" 2>/dev/null | cut -d= -f2 || echo "HookProbe-Fortress")
WIFI_PASSWORD=$(cat "$CONFIG_DIR/secrets/wifi_password" 2>/dev/null || echo "changeme123")

if [ -f "$HOSTAPD_SCRIPT" ]; then
    chmod +x "$HOSTAPD_SCRIPT"
    "$HOSTAPD_SCRIPT" configure "$WIFI_SSID" "$WIFI_PASSWORD" "$OVS_BRIDGE" || {
        log_warn "Hostapd configuration had issues, will try manual setup"
    }
else
    log_warn "hostapd-generator.sh not found - skipping config generation"
fi

# Step 7: Create WiFi services
log_info "Step 7: Creating systemd services..."
if [ -f "$INTEGRATION_SCRIPT" ]; then
    # Re-source with detected interfaces
    export NET_WIFI_24GHZ_IFACE="${iface_24ghz:-wlan_24ghz}"
    export NET_WIFI_5GHZ_IFACE="${iface_5ghz:-wlan_5ghz}"
    export OVS_BRIDGE_NAME="43ess"
    create_wifi_services 2>/dev/null || log_warn "Service creation had issues"
fi

# Step 8: Update hostapd configs with stable names
log_info "Step 8: Updating configs with stable interface names..."

if [ -f /etc/hostapd/hostapd-24ghz.conf ]; then
    sed -i "s/^interface=.*/interface=wlan_24ghz/" /etc/hostapd/hostapd-24ghz.conf
    log_info "  Updated 2.4GHz config"
fi

if [ -f /etc/hostapd/hostapd-5ghz.conf ]; then
    sed -i "s/^interface=.*/interface=wlan_5ghz/" /etc/hostapd/hostapd-5ghz.conf
    log_info "  Updated 5GHz config"
fi

systemctl daemon-reload 2>/dev/null || true

# Save interface mapping
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/wifi-interfaces.conf" << EOF
# WiFi Interface Mapping
# Generated: $(date -Iseconds)
WIFI_24GHZ_MAC=$mac_24ghz
WIFI_24GHZ_ORIGINAL=$iface_24ghz
WIFI_24GHZ_STABLE=wlan_24ghz
WIFI_5GHZ_MAC=$mac_5ghz
WIFI_5GHZ_ORIGINAL=$iface_5ghz
WIFI_5GHZ_STABLE=wlan_5ghz
EOF

echo ""
log_info "=== WiFi Setup Complete ==="
echo ""
echo "Interface mapping:"
echo "  2.4GHz: ${iface_24ghz:-none} ($mac_24ghz) -> wlan_24ghz"
echo "  5GHz:   ${iface_5ghz:-none} ($mac_5ghz) -> wlan_5ghz"
echo ""
echo "Files created:"
echo "  /etc/udev/rules.d/70-fortress-wifi.rules"
echo "  /etc/hookprobe/wifi-interfaces.conf"
echo "  /etc/hostapd/hostapd-24ghz.conf (if 2.4GHz available)"
echo "  /etc/hostapd/hostapd-5ghz.conf (if 5GHz available)"
echo ""
echo "Next steps:"
echo "  1. Verify interface names: ip link show"
echo "  2. If interfaces not renamed, reboot: sudo reboot"
echo "  3. Start WiFi AP: sudo systemctl start fortress-hostapd"
echo "  4. Check status: sudo systemctl status fortress-hostapd-*"
echo ""
