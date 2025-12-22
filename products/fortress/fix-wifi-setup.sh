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
OVS_BRIDGE="FTS"

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

# Step 7: Unmask hostapd (Debian/Ubuntu ship it masked)
log_info "Step 7: Unmasking hostapd..."
systemctl unmask hostapd 2>/dev/null || true

# Step 8: Create bridge helper script
log_info "Step 8: Creating WiFi bridge helper script..."
BRIDGE_HELPER="/usr/local/bin/fortress-wifi-bridge-helper.sh"

cat > "$BRIDGE_HELPER" << 'HELPER_EOF'
#!/bin/bash
# Fortress WiFi Bridge Helper
# Adds WiFi interface to OVS bridge after hostapd starts

IFACE="$1"
BRIDGE="${2:-FTS}"
ACTION="${3:-add}"

[ -z "$IFACE" ] && exit 1

# Wait for interface to be ready
for i in {1..10}; do
    if ip link show "$IFACE" &>/dev/null; then
        break
    fi
    sleep 0.5
done

if ! ip link show "$IFACE" &>/dev/null; then
    echo "Interface $IFACE not found after waiting"
    exit 1
fi

# Check if OVS is available and bridge exists
if ! command -v ovs-vsctl &>/dev/null; then
    echo "OVS not available, skipping bridge configuration"
    exit 0
fi

if ! ovs-vsctl br-exists "$BRIDGE" 2>/dev/null; then
    echo "OVS bridge $BRIDGE does not exist, skipping"
    exit 0
fi

if [ "$ACTION" = "add" ]; then
    # Add interface to OVS bridge
    if ! ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -q "^${IFACE}$"; then
        echo "Adding $IFACE to OVS bridge $BRIDGE"
        ovs-vsctl --may-exist add-port "$BRIDGE" "$IFACE" 2>/dev/null || {
            echo "Failed to add $IFACE to $BRIDGE"
            exit 1
        }
    fi
    ip link set "$IFACE" up 2>/dev/null || true
    echo "WiFi interface $IFACE added to OVS bridge $BRIDGE"
elif [ "$ACTION" = "remove" ]; then
    # Remove interface from OVS bridge
    if ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -q "^${IFACE}$"; then
        echo "Removing $IFACE from OVS bridge $BRIDGE"
        ovs-vsctl del-port "$BRIDGE" "$IFACE" 2>/dev/null || true
    fi
fi

exit 0
HELPER_EOF

chmod +x "$BRIDGE_HELPER"
log_info "  Created $BRIDGE_HELPER"

# Step 9: Create systemd services
log_info "Step 9: Creating systemd services..."

# Use stable interface names
IFACE_24GHZ="wlan_24ghz"
IFACE_5GHZ="wlan_5ghz"

# Find hostapd binary - check common locations
HOSTAPD_BIN=""
for path in /usr/local/bin/hostapd /usr/sbin/hostapd /usr/bin/hostapd; do
    if [ -x "$path" ]; then
        HOSTAPD_BIN="$path"
        break
    fi
done
if [ -z "$HOSTAPD_BIN" ]; then
    HOSTAPD_BIN=$(which hostapd 2>/dev/null || echo "/usr/sbin/hostapd")
fi
log_info "  Using hostapd: $HOSTAPD_BIN"

if [ -n "$mac_24ghz" ]; then
    cat > /etc/systemd/system/fortress-hostapd-24ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 2.4GHz WiFi Access Point
After=network.target openvswitch-switch.service sys-subsystem-net-devices-${IFACE_24GHZ}.device
Wants=network.target sys-subsystem-net-devices-${IFACE_24GHZ}.device
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=forking
PIDFile=/run/hostapd-24ghz.pid
ExecStartPre=/bin/bash -c 'for i in {1..30}; do [ -e /sys/class/net/${IFACE_24GHZ} ] && break; sleep 0.5; done; [ -e /sys/class/net/${IFACE_24GHZ} ] || exit 1'
ExecStartPre=-/bin/bash -c 'pkill -f "hostapd.*${IFACE_24GHZ}" 2>/dev/null; rm -f /run/hostapd-24ghz.pid'
ExecStartPre=-/sbin/ip link set ${IFACE_24GHZ} down
ExecStartPre=/bin/sleep 0.5
ExecStartPre=/sbin/ip link set ${IFACE_24GHZ} up
ExecStart=${HOSTAPD_BIN} -B -P /run/hostapd-24ghz.pid /etc/hostapd/hostapd-24ghz.conf
ExecStartPost=${BRIDGE_HELPER} ${IFACE_24GHZ} ${OVS_BRIDGE} add
ExecStop=-/bin/kill -TERM \$MAINPID
ExecStopPost=-/sbin/ip link set ${IFACE_24GHZ} down
ExecStopPost=-${BRIDGE_HELPER} ${IFACE_24GHZ} ${OVS_BRIDGE} remove
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    log_info "  Created fortress-hostapd-24ghz.service"
fi

if [ -n "$mac_5ghz" ]; then
    cat > /etc/systemd/system/fortress-hostapd-5ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 5GHz WiFi Access Point
After=network.target openvswitch-switch.service sys-subsystem-net-devices-${IFACE_5GHZ}.device
Wants=network.target sys-subsystem-net-devices-${IFACE_5GHZ}.device
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=forking
PIDFile=/run/hostapd-5ghz.pid
ExecStartPre=/bin/bash -c 'for i in {1..30}; do [ -e /sys/class/net/${IFACE_5GHZ} ] && break; sleep 0.5; done; [ -e /sys/class/net/${IFACE_5GHZ} ] || exit 1'
ExecStartPre=-/bin/bash -c 'pkill -f "hostapd.*${IFACE_5GHZ}" 2>/dev/null; rm -f /run/hostapd-5ghz.pid'
ExecStartPre=-/sbin/ip link set ${IFACE_5GHZ} down
ExecStartPre=/bin/sleep 0.5
ExecStartPre=/sbin/ip link set ${IFACE_5GHZ} up
ExecStart=${HOSTAPD_BIN} -B -P /run/hostapd-5ghz.pid /etc/hostapd/hostapd-5ghz.conf
ExecStartPost=${BRIDGE_HELPER} ${IFACE_5GHZ} ${OVS_BRIDGE} add
ExecStop=-/bin/kill -TERM \$MAINPID
ExecStopPost=-/sbin/ip link set ${IFACE_5GHZ} down
ExecStopPost=-${BRIDGE_HELPER} ${IFACE_5GHZ} ${OVS_BRIDGE} remove
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    log_info "  Created fortress-hostapd-5ghz.service"
fi

# Step 10: Update hostapd configs with stable names
log_info "Step 10: Updating configs with stable interface names..."

if [ -f /etc/hostapd/hostapd-24ghz.conf ]; then
    sed -i "s/^interface=.*/interface=wlan_24ghz/" /etc/hostapd/hostapd-24ghz.conf
    log_info "  Updated 2.4GHz config"
fi

if [ -f /etc/hostapd/hostapd-5ghz.conf ]; then
    sed -i "s/^interface=.*/interface=wlan_5ghz/" /etc/hostapd/hostapd-5ghz.conf
    log_info "  Updated 5GHz config"
fi

# Step 11: Reload and enable services
log_info "Step 11: Enabling services..."
systemctl daemon-reload

if [ -n "$mac_24ghz" ]; then
    systemctl enable fortress-hostapd-24ghz 2>/dev/null || true
    log_info "  Enabled fortress-hostapd-24ghz"
fi

if [ -n "$mac_5ghz" ]; then
    systemctl enable fortress-hostapd-5ghz 2>/dev/null || true
    log_info "  Enabled fortress-hostapd-5ghz"
fi

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
echo "  /usr/local/bin/fortress-wifi-bridge-helper.sh"
echo "  /etc/systemd/system/fortress-hostapd-24ghz.service (if 2.4GHz)"
echo "  /etc/systemd/system/fortress-hostapd-5ghz.service (if 5GHz)"
echo "  /etc/hostapd/hostapd-24ghz.conf (if 2.4GHz available)"
echo "  /etc/hostapd/hostapd-5ghz.conf (if 5GHz available)"
echo ""
echo "Next steps:"
echo "  1. Verify interface names: ip link show"
echo "  2. If interfaces not renamed, reboot: sudo reboot"
echo "  3. Start WiFi AP:"
[ -n "$mac_24ghz" ] && echo "     sudo systemctl start fortress-hostapd-24ghz"
[ -n "$mac_5ghz" ] && echo "     sudo systemctl start fortress-hostapd-5ghz"
echo "  4. Check status: sudo systemctl status fortress-hostapd-*"
echo ""
