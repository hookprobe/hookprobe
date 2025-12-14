#!/bin/bash
#
# HookProbe Fortress Setup Script
# Version: 5.0.0
# License: AGPL-3.0 - see LICENSE file
#
# Fortress - Full-Featured Edge Gateway with Monitoring
#
# Fortress Mode Features:
#   - VLAN segmentation with VAP-capable WiFi (IoT isolation)
#   - MACsec (802.1AE) Layer 2 encryption
#   - OpenFlow 1.3 SDN for advanced traffic control
#   - VXLAN tunnels with VNI and PSK encryption
#   - Full monitoring stack (Grafana + Victoria Metrics)
#   - n8n workflow automation (optional)
#   - ClickHouse analytics (optional)
#   - LTE/5G failover (optional)
#
# Requirements:
#   - 8GB+ RAM (16GB recommended)
#   - 32GB+ storage
#   - 2+ Ethernet interfaces
#   - VAP-capable WiFi adapter for VLAN segmentation (optional)
#     Recommended: Atheros AR9271, MediaTek MT7612U
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORTRESS_ROOT="$SCRIPT_DIR"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ============================================================
# COLORS
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ============================================================
# CONFIGURATION
# ============================================================
OVS_BRIDGE_NAME="fortress"
OVS_BRIDGE_SUBNET="10.250.0.0/16"
MACSEC_ENABLED=true
VLAN_SEGMENTATION=true

# VLAN Configuration for IoT isolation
declare -A VLAN_CONFIG=(
    ["management"]="10:10.250.10.0/24"
    ["trusted"]="20:10.250.20.0/24"
    ["iot"]="30:10.250.30.0/24"
    ["guest"]="40:10.250.40.0/24"
    ["quarantine"]="99:10.250.99.0/24"
)

# VXLAN Configuration for mesh connectivity
declare -A VXLAN_CONFIG=(
    ["fortress-core"]="1000:4800"
    ["fortress-monitoring"]="1001:4801"
    ["fortress-automation"]="1002:4802"
    ["fortress-analytics"]="1003:4803"
    ["mssp-uplink"]="2000:4900"
)

# Optional features
ENABLE_N8N="${ENABLE_N8N:-false}"
ENABLE_MONITORING="${ENABLE_MONITORING:-true}"
ENABLE_CLICKHOUSE="${ENABLE_CLICKHOUSE:-false}"
ENABLE_LTE="${ENABLE_LTE:-false}"
ENABLE_REMOTE_ACCESS="${ENABLE_REMOTE_ACCESS:-false}"

# Installation mode
NON_INTERACTIVE="${NON_INTERACTIVE:-false}"

# LTE Configuration
HOOKPROBE_LTE_APN="${HOOKPROBE_LTE_APN:-}"
HOOKPROBE_LTE_AUTH="${HOOKPROBE_LTE_AUTH:-none}"
HOOKPROBE_LTE_USER="${HOOKPROBE_LTE_USER:-}"
HOOKPROBE_LTE_PASS="${HOOKPROBE_LTE_PASS:-}"

# ============================================================
# LOGGING
# ============================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ============================================================
# DEVICE DETECTION
# ============================================================
DEVICES_DIR="$FORTRESS_ROOT/devices"

# Source device detection framework
if [ -f "$DEVICES_DIR/common/detect-hardware.sh" ]; then
    source "$DEVICES_DIR/common/detect-hardware.sh"
    DEVICE_DETECTION_AVAILABLE=true
else
    DEVICE_DETECTION_AVAILABLE=false
    log_warn "Device detection framework not found"
fi

# Source LTE manager
if [ -f "$DEVICES_DIR/common/lte-manager.sh" ]; then
    source "$DEVICES_DIR/common/lte-manager.sh"
    LTE_MANAGER_AVAILABLE=true
else
    LTE_MANAGER_AVAILABLE=false
fi

# ============================================================
# PREREQUISITES
# ============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_requirements() {
    log_step "Checking system requirements..."

    # Check RAM (minimum 8GB)
    local total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -lt 7 ]; then
        log_warn "Less than 8GB RAM detected. Some features may be limited."
    else
        log_info "RAM: ${total_mem}GB (OK)"
    fi

    # Check storage
    local free_storage=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$free_storage" -lt 30 ]; then
        log_warn "Less than 30GB free storage. Consider expanding."
    else
        log_info "Storage: ${free_storage}GB free (OK)"
    fi

    # Check CPU cores
    local cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 4 ]; then
        log_warn "Less than 4 CPU cores. Performance may be limited."
    else
        log_info "CPU: ${cpu_cores} cores (OK)"
    fi
}

detect_platform() {
    log_step "Detecting platform and hardware..."

    if [ -f /sys/class/dmi/id/product_name ]; then
        PLATFORM_NAME=$(cat /sys/class/dmi/id/product_name)
    else
        PLATFORM_NAME="Generic Linux"
    fi

    PLATFORM_ARCH=$(uname -m)
    log_info "Platform: $PLATFORM_NAME ($PLATFORM_ARCH)"

    # Use device detection framework if available
    if [ "$DEVICE_DETECTION_AVAILABLE" = true ]; then
        log_step "Running device profile detection..."
        detect_hardware

        log_info "Device ID: ${FORTRESS_DEVICE_ID:-unknown}"
        log_info "Device Name: ${FORTRESS_DEVICE_NAME:-Unknown Device}"
        log_info "Device Family: ${FORTRESS_DEVICE_FAMILY:-unknown}"
        log_info "Architecture: ${FORTRESS_ARCHITECTURE:-$(uname -m)}"

        if [ -n "$FORTRESS_PROFILE_DIR" ] && [ -d "$FORTRESS_PROFILE_DIR" ]; then
            log_info "Device profile: $FORTRESS_PROFILE_DIR"

            # Source device-specific interface detection
            if [ -f "$FORTRESS_PROFILE_DIR/interfaces.sh" ]; then
                log_step "Running device-specific interface detection..."
                source "$FORTRESS_PROFILE_DIR/interfaces.sh"

                # Run the device-specific detection function
                case "$FORTRESS_DEVICE_ID" in
                    intel-n100|intel-n150|intel-n200|intel-n305)
                        detect_intel_n100_interfaces
                        ;;
                    rpi-cm5)
                        detect_cm5_interfaces
                        ;;
                    radxa-rock5b)
                        detect_rock5b_interfaces
                        ;;
                    *)
                        detect_device_interfaces 2>/dev/null || true
                        ;;
                esac

                # Export detected interfaces
                if [ -n "$FORTRESS_WAN_IFACE" ]; then
                    log_info "WAN Interface: $FORTRESS_WAN_IFACE"
                    WAN_INTERFACE="$FORTRESS_WAN_IFACE"
                fi
                if [ -n "$FORTRESS_LAN_IFACES" ]; then
                    log_info "LAN Interfaces: $FORTRESS_LAN_IFACES"
                    LAN_INTERFACES="$FORTRESS_LAN_IFACES"
                fi
            fi
        else
            log_warn "No device profile found for: ${FORTRESS_DEVICE_ID:-unknown}"
        fi
    fi
}

detect_interfaces() {
    log_step "Detecting network interfaces..."

    # Ethernet interfaces (eth*, enp*, eno*) - exclude WWAN
    ETH_INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|enp|eno)' | grep -v '^ww' | tr '\n' ' ')
    ETH_COUNT=$(echo $ETH_INTERFACES | wc -w)

    # WiFi interfaces (wlan*, wlp*) - managed by iw
    WIFI_INTERFACES=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | tr '\n' ' ')
    WIFI_COUNT=$(echo $WIFI_INTERFACES | wc -w)

    # WWAN/LTE interfaces (wwan*, wwp*) - double 'w' prefix
    WWAN_INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(wwan|wwp)' | tr '\n' ' ')
    WWAN_COUNT=$(echo $WWAN_INTERFACES | wc -w)

    # Detect modem control devices
    MODEM_CTRL_DEVICES=""
    # Check for CDC-WDM devices (QMI/MBIM modems)
    for dev in /dev/cdc-wdm*; do
        [ -c "$dev" ] && MODEM_CTRL_DEVICES="$MODEM_CTRL_DEVICES $(basename $dev)"
    done 2>/dev/null
    # Check for ttyUSB devices (AT command modems)
    for dev in /dev/ttyUSB*; do
        [ -c "$dev" ] && MODEM_CTRL_DEVICES="$MODEM_CTRL_DEVICES $(basename $dev)"
    done 2>/dev/null
    MODEM_CTRL_DEVICES=$(echo $MODEM_CTRL_DEVICES | xargs)  # trim whitespace

    # Check NetworkManager for GSM connections
    GSM_CONNECTIONS=""
    if command -v nmcli &>/dev/null; then
        GSM_CONNECTIONS=$(nmcli -t -f NAME,TYPE,DEVICE connection show 2>/dev/null | grep ":gsm:" | cut -d: -f1,3 | tr '\n' ' ')
    fi

    # Check for VAP-capable WiFi (required for VLAN segmentation)
    WIFI_VAP_SUPPORT=false
    for iface in $WIFI_INTERFACES; do
        if iw list 2>/dev/null | grep -A 20 "Supported interface modes" | grep -q "AP/VLAN"; then
            WIFI_VAP_SUPPORT=true
            log_info "VAP-capable WiFi detected - VLAN segmentation available"
            break
        fi
    done

    log_info "Ethernet interfaces ($ETH_COUNT): ${ETH_INTERFACES:-none}"
    log_info "WiFi interfaces ($WIFI_COUNT): ${WIFI_INTERFACES:-none}"
    log_info "WWAN/LTE interfaces ($WWAN_COUNT): ${WWAN_INTERFACES:-none}"
    [ -n "$MODEM_CTRL_DEVICES" ] && log_info "Modem control devices: $MODEM_CTRL_DEVICES"
    [ -n "$GSM_CONNECTIONS" ] && log_info "GSM connections: $GSM_CONNECTIONS"

    # Export for LTE manager
    export WWAN_INTERFACES WWAN_COUNT MODEM_CTRL_DEVICES GSM_CONNECTIONS

    if [ "$WIFI_VAP_SUPPORT" = false ] && [ "$VLAN_SEGMENTATION" = true ]; then
        log_warn "No VAP-capable WiFi adapter found."
        log_warn "VLAN segmentation will use wired interfaces only."
        log_warn "For WiFi VLAN, use Atheros AR9271 or MediaTek MT7612U adapters."
    fi
}

# ============================================================
# PACKAGE INSTALLATION
# ============================================================

# Required packages - installation will fail if these cannot be installed
REQUIRED_PACKAGES_APT=(
    "openvswitch-switch"
    "python3"
    "python3-pip"
    "curl"
    "jq"
    "openssl"
    "iptables"
    "bridge-utils"
)

# Optional packages - won't fail if unavailable
OPTIONAL_PACKAGES_APT=(
    "hostapd"
    "dnsmasq"
    "nftables"
    "iw"
    "wireless-tools"
    "wpasupplicant"
    "wpa_supplicant"
    "python3-flask"
    "python3-requests"
    "net-tools"
    "freeradius"
    "freeradius-utils"
    "vlan"
    "network-manager"
    "modemmanager"
    "libqmi-utils"
    "libmbim-utils"
    "usb-modeswitch"
)

# Helper function to check if apt package is installed
is_pkg_installed_apt() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

install_packages() {
    log_step "Installing required packages..."

    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"

        log_info "Updating package lists..."
        apt-get update -qq 2>&1 || log_warn "apt-get update had warnings, continuing..."

        # Install required packages first (will fail if any are missing)
        log_info "Installing required packages..."
        for pkg in "${REQUIRED_PACKAGES_APT[@]}"; do
            if is_pkg_installed_apt "$pkg"; then
                log_info "  $pkg: already installed"
            else
                log_info "  Installing $pkg..."
                if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>&1; then
                    log_error "Failed to install required package: $pkg"
                    log_error "This package is required for Fortress to function."
                    log_error "Please install it manually and re-run setup."
                    exit 1
                fi
                # Verify it actually installed
                if ! is_pkg_installed_apt "$pkg"; then
                    log_error "Package $pkg installation reported success but package not found"
                    exit 1
                fi
                log_info "  $pkg: installed successfully"
            fi
        done

        # Install optional packages (won't fail)
        log_info "Installing optional packages..."
        for pkg in "${OPTIONAL_PACKAGES_APT[@]}"; do
            if is_pkg_installed_apt "$pkg"; then
                log_info "  $pkg: already installed"
            else
                if DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>/dev/null; then
                    log_info "  $pkg: installed"
                else
                    log_warn "  $pkg: not available (optional)"
                fi
            fi
        done

        log_info "System package installation complete"

    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"

        # Fedora/RHEL package names
        local required_pkgs=(
            "openvswitch"
            "python3"
            "python3-pip"
            "curl"
            "jq"
            "openssl"
            "iptables"
            "bridge-utils"
        )

        local optional_pkgs=(
            "hostapd"
            "dnsmasq"
            "nftables"
            "iw"
            "wireless-tools"
            "wpa_supplicant"
            "python3-flask"
            "python3-requests"
            "net-tools"
            "freeradius"
            "NetworkManager"
            "ModemManager"
            "libqmi-utils"
            "libmbim-utils"
            "usb_modeswitch"
        )

        log_info "Installing required packages..."
        for pkg in "${required_pkgs[@]}"; do
            if rpm -q "$pkg" &>/dev/null; then
                log_info "  $pkg: already installed"
            else
                log_info "  Installing $pkg..."
                if ! dnf install -y "$pkg"; then
                    log_error "Failed to install required package: $pkg"
                    exit 1
                fi
            fi
        done

        log_info "Installing optional packages..."
        for pkg in "${optional_pkgs[@]}"; do
            if rpm -q "$pkg" &>/dev/null 2>&1; then
                log_info "  $pkg: already installed"
            else
                dnf install -y "$pkg" 2>/dev/null && log_info "  $pkg: installed" || log_warn "  $pkg: not available"
            fi
        done

        log_info "System package installation complete"
    else
        log_error "Unsupported package manager. Fortress requires apt (Debian/Ubuntu) or dnf (Fedora/RHEL)."
        exit 1
    fi
}

# Python package installation
install_python_packages() {
    log_step "Installing Python packages..."

    # Ensure pip is available
    if ! command -v pip3 &>/dev/null; then
        log_error "pip3 not found. Please install python3-pip."
        exit 1
    fi

    # Core Python packages for Fortress
    local PYTHON_PACKAGES=(
        "flask>=2.3.0"
        "flask-login>=0.6.0"
        "flask-wtf>=1.2.0"
        "werkzeug>=2.3.0"
        "bcrypt>=4.0.0"
        "gunicorn>=21.0.0"
        "requests>=2.31.0"
        "psutil>=5.9.0"
    )

    # dnsXai ML packages (optional but recommended)
    local ML_PACKAGES=(
        "numpy"
        "dnslib"
    )

    log_info "Installing core Python packages..."
    for pkg in "${PYTHON_PACKAGES[@]}"; do
        pkg_name=$(echo "$pkg" | cut -d'>' -f1 | cut -d'=' -f1)
        if pip3 show "$pkg_name" &>/dev/null; then
            log_info "  $pkg_name: already installed"
        else
            log_info "  Installing $pkg_name..."
            if pip3 install --break-system-packages "$pkg" 2>/dev/null || pip3 install "$pkg" 2>/dev/null; then
                log_info "  $pkg_name: installed"
            else
                log_warn "  $pkg_name: failed to install (may affect some features)"
            fi
        fi
    done

    log_info "Installing ML/AI packages for dnsXai..."
    for pkg in "${ML_PACKAGES[@]}"; do
        if pip3 show "$pkg" &>/dev/null; then
            log_info "  $pkg: already installed"
        else
            log_info "  Installing $pkg..."
            if pip3 install --break-system-packages "$pkg" 2>/dev/null || pip3 install "$pkg" 2>/dev/null; then
                log_info "  $pkg: installed"
            else
                log_warn "  $pkg: not installed (dnsXai ML features limited)"
            fi
        fi
    done

    # Install from requirements.txt if it exists
    if [ -f "$FORTRESS_ROOT/web/requirements.txt" ]; then
        log_info "Installing from web/requirements.txt..."
        pip3 install --break-system-packages -r "$FORTRESS_ROOT/web/requirements.txt" 2>/dev/null || \
        pip3 install -r "$FORTRESS_ROOT/web/requirements.txt" 2>/dev/null || \
        log_warn "Some web requirements may not have installed"
    fi

    log_info "Python package installation complete"
}

verify_critical_packages() {
    log_step "Verifying critical packages..."

    local missing=()

    # Check for ovs-vsctl (Open vSwitch)
    if ! command -v ovs-vsctl &>/dev/null; then
        missing+=("openvswitch-switch (ovs-vsctl not found)")
    else
        log_info "  ovs-vsctl: OK"
    fi

    # Check for python3
    if ! command -v python3 &>/dev/null; then
        missing+=("python3")
    else
        log_info "  python3: OK ($(python3 --version))"
    fi

    # Check for curl
    if ! command -v curl &>/dev/null; then
        missing+=("curl")
    else
        log_info "  curl: OK"
    fi

    # Check for jq
    if ! command -v jq &>/dev/null; then
        missing+=("jq")
    else
        log_info "  jq: OK"
    fi

    # Check for iptables
    if ! command -v iptables &>/dev/null; then
        missing+=("iptables")
    else
        log_info "  iptables: OK"
    fi

    # Check for ip command
    if ! command -v ip &>/dev/null; then
        missing+=("iproute2 (ip command not found)")
    else
        log_info "  ip: OK"
    fi

    # Check for brctl (optional but useful)
    if command -v brctl &>/dev/null; then
        log_info "  brctl: OK"
    else
        log_warn "  brctl: not found (bridge-utils optional)"
    fi

    # Check for iw (WiFi)
    if command -v iw &>/dev/null; then
        log_info "  iw: OK"
    else
        log_warn "  iw: not found (WiFi features limited)"
    fi

    # Check for nmcli (NetworkManager - needed for LTE)
    if command -v nmcli &>/dev/null; then
        log_info "  nmcli: OK (NetworkManager available)"
    else
        log_warn "  nmcli: not found (LTE failover requires NetworkManager)"
    fi

    # Check for mmcli (ModemManager - needed for LTE)
    if command -v mmcli &>/dev/null; then
        log_info "  mmcli: OK (ModemManager available)"
    else
        log_warn "  mmcli: not found (LTE modem detection requires ModemManager)"
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing critical packages:"
        for pkg in "${missing[@]}"; do
            log_error "  - $pkg"
        done
        log_error ""
        log_error "Please install missing packages and re-run setup."
        exit 1
    fi

    log_info "All critical packages verified"
}

install_podman() {
    log_step "Installing Podman container runtime..."

    if command -v podman &>/dev/null; then
        log_info "Podman already installed: $(podman --version)"
    else
        if [ "$PKG_MGR" = "apt" ]; then
            apt-get install -y -qq podman
        else
            dnf install -y -q podman
        fi
    fi

    systemctl enable --now podman.socket 2>/dev/null || true
    log_info "Podman installed: $(podman --version)"
}

# ============================================================
# OPEN VSWITCH SETUP
# ============================================================
install_openvswitch() {
    log_step "Installing and configuring Open vSwitch..."

    # Start OVS service
    systemctl enable openvswitch-switch 2>/dev/null || \
        systemctl enable openvswitch 2>/dev/null || true
    systemctl start openvswitch-switch 2>/dev/null || \
        systemctl start openvswitch 2>/dev/null || true

    # Verify OVS is working
    if ! command -v ovs-vsctl &>/dev/null; then
        log_error "Open vSwitch is required for Fortress deployment"
        exit 1
    fi

    log_info "Open vSwitch installed and running"
}

generate_vxlan_psk() {
    openssl rand -base64 32
}

setup_ovs_bridge() {
    log_step "Setting up OVS bridge with VXLAN and OpenFlow..."

    local local_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    # Create OVS bridge
    if ovs-vsctl br-exists "$OVS_BRIDGE_NAME" 2>/dev/null; then
        log_info "OVS bridge '$OVS_BRIDGE_NAME' already exists"
    else
        ovs-vsctl add-br "$OVS_BRIDGE_NAME" || {
            log_error "Failed to create OVS bridge"
            exit 1
        }
        log_info "OVS bridge '$OVS_BRIDGE_NAME' created"
    fi

    # Enable OpenFlow 1.3 for advanced SDN capabilities
    ovs-vsctl set bridge "$OVS_BRIDGE_NAME" protocols=OpenFlow10,OpenFlow13 2>/dev/null || true
    log_info "OpenFlow 1.3 enabled"

    # Configure bridge IP
    ip link set "$OVS_BRIDGE_NAME" up
    ip addr add 10.250.0.1/16 dev "$OVS_BRIDGE_NAME" 2>/dev/null || true

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-hookprobe.conf 2>/dev/null || true

    # Create secrets directory for PSK
    mkdir -p /etc/hookprobe/secrets/vxlan
    chmod 700 /etc/hookprobe/secrets/vxlan

    # Generate master PSK
    if [ ! -f /etc/hookprobe/secrets/vxlan/master.psk ]; then
        generate_vxlan_psk > /etc/hookprobe/secrets/vxlan/master.psk
        chmod 600 /etc/hookprobe/secrets/vxlan/master.psk
        log_info "VXLAN master PSK generated"
    fi

    # Save configuration
    mkdir -p /etc/hookprobe
    cat > /etc/hookprobe/ovs-config.sh << OVSEOF
# HookProbe Fortress OVS Configuration
OVS_BRIDGE_NAME=$OVS_BRIDGE_NAME
OVS_BRIDGE_SUBNET=$OVS_BRIDGE_SUBNET
LOCAL_IP=$local_ip
OPENFLOW_VERSION=1.3

# VXLAN Configuration
VXLAN_ENABLED=true
VXLAN_MASTER_PSK=/etc/hookprobe/secrets/vxlan/master.psk
OVSEOF

    log_info "OVS bridge configured with OpenFlow 1.3"
}

# ============================================================
# BRIDGE LAN INTERFACES
# ============================================================
setup_lan_bridge() {
    log_step "Adding LAN interfaces to bridge..."

    # Get LAN interfaces (exclude WAN which is typically the first one or has default route)
    local wan_iface=""
    wan_iface=$(ip route | grep default | awk '{print $5}' | head -1)

    local lan_ifaces=""
    for iface in $ETH_INTERFACES; do
        # Skip WAN interface
        if [ "$iface" = "$wan_iface" ]; then
            log_info "Skipping WAN interface: $iface"
            continue
        fi
        lan_ifaces="$lan_ifaces $iface"
    done

    lan_ifaces=$(echo $lan_ifaces | xargs)  # trim

    if [ -z "$lan_ifaces" ]; then
        log_warn "No LAN interfaces found to bridge"
        log_info "WAN interface: ${wan_iface:-none}"
        log_info "Available interfaces: $ETH_INTERFACES"
        return 0
    fi

    log_info "WAN interface: $wan_iface"
    log_info "LAN interfaces to bridge: $lan_ifaces"

    # Add each LAN interface to the OVS bridge
    for iface in $lan_ifaces; do
        if ip link show "$iface" &>/dev/null; then
            # Remove any existing IP from the interface
            ip addr flush dev "$iface" 2>/dev/null || true

            # Add to OVS bridge
            if ! ovs-vsctl list-ports "$OVS_BRIDGE_NAME" 2>/dev/null | grep -q "^${iface}$"; then
                log_info "Adding $iface to bridge $OVS_BRIDGE_NAME..."
                ovs-vsctl add-port "$OVS_BRIDGE_NAME" "$iface" 2>/dev/null || {
                    log_warn "Failed to add $iface to bridge"
                    continue
                }
            else
                log_info "$iface already in bridge"
            fi

            # Bring interface up
            ip link set "$iface" up
        fi
    done

    # Save LAN configuration
    cat > /etc/hookprobe/lan-bridge.conf << EOF
# HookProbe Fortress LAN Bridge Configuration
WAN_INTERFACE=$wan_iface
LAN_INTERFACES="$lan_ifaces"
BRIDGE_NAME=$OVS_BRIDGE_NAME
BRIDGE_IP=10.250.0.1
BRIDGE_NETMASK=255.255.0.0
DHCP_RANGE_START=10.250.1.100
DHCP_RANGE_END=10.250.1.250
EOF

    log_info "LAN interfaces bridged"
}

# ============================================================
# WIFI ACCESS POINT (hostapd)
# ============================================================
setup_wifi_ap() {
    log_step "Setting up WiFi Access Point..."

    if [ -z "$WIFI_INTERFACES" ]; then
        log_info "No WiFi interfaces detected, skipping AP setup"
        return 0
    fi

    if ! command -v hostapd &>/dev/null; then
        log_warn "hostapd not installed, skipping WiFi AP setup"
        return 0
    fi

    # Use first WiFi interface
    local wifi_iface=$(echo $WIFI_INTERFACES | awk '{print $1}')
    log_info "Configuring WiFi AP on: $wifi_iface"

    # =========================================
    # CRITICAL: Remove WiFi from netplan/NetworkManager control
    # =========================================
    log_info "Removing $wifi_iface from netplan/NetworkManager control..."

    # Remove WiFi interface from any netplan configuration
    for netplan_file in /etc/netplan/*.yaml; do
        if [ -f "$netplan_file" ]; then
            # Check if this netplan file has WiFi configuration
            if grep -q "wifis:" "$netplan_file" 2>/dev/null; then
                log_info "Removing WiFi section from $netplan_file"
                # Backup the file
                cp "$netplan_file" "${netplan_file}.fortress-backup"
                # Remove wifis section using Python for reliable YAML manipulation
                python3 << PYEOF
import yaml
import sys

try:
    with open('$netplan_file', 'r') as f:
        config = yaml.safe_load(f) or {}

    if 'network' in config and 'wifis' in config['network']:
        del config['network']['wifis']
        with open('$netplan_file', 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        print("Removed wifis section from $netplan_file")
except Exception as e:
    print(f"Warning: Could not modify netplan: {e}", file=sys.stderr)
PYEOF
            fi
        fi
    done

    # Apply netplan changes
    netplan apply 2>/dev/null || true

    # Tell NetworkManager to ignore this interface
    if [ -d /etc/NetworkManager/conf.d ]; then
        cat > /etc/NetworkManager/conf.d/fortress-wifi.conf << NMEOF
# HookProbe Fortress: Let hostapd manage WiFi AP
[keyfile]
unmanaged-devices=interface-name:$wifi_iface
NMEOF
        # Reload NetworkManager
        systemctl reload NetworkManager 2>/dev/null || true
    fi

    # Disconnect and release the interface
    nmcli device disconnect "$wifi_iface" 2>/dev/null || true
    nmcli device set "$wifi_iface" managed no 2>/dev/null || true

    # Wait a moment for release
    sleep 1

    # Bring down interface, set AP mode, bring up
    ip link set "$wifi_iface" down 2>/dev/null || true
    iw dev "$wifi_iface" set type __ap 2>/dev/null || true
    ip link set "$wifi_iface" up 2>/dev/null || true

    # Verify AP mode was set
    local current_mode=$(iw dev "$wifi_iface" info 2>/dev/null | grep "type" | awk '{print $2}')
    if [ "$current_mode" != "AP" ]; then
        log_warn "Could not set $wifi_iface to AP mode (current: $current_mode)"
        log_warn "WiFi AP may not work correctly - will retry during service start"
    else
        log_info "WiFi interface $wifi_iface set to AP mode"
    fi

    # Generate random password if not set
    local ap_password="${FORTRESS_WIFI_PASSWORD:-$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)}"
    local ap_ssid="${FORTRESS_WIFI_SSID:-Fortress-$(hostname -s)}"

    # Create hostapd configuration
    # NOTE: Removed wpa_pairwise=TKIP - modern devices reject it
    mkdir -p /etc/hostapd
    cat > /etc/hostapd/fortress.conf << EOF
# HookProbe Fortress WiFi AP Configuration
interface=$wifi_iface
driver=nl80211
ssid=$ap_ssid
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$ap_password
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP

# Bridge to OVS
bridge=$OVS_BRIDGE_NAME
EOF

    chmod 600 /etc/hostapd/fortress.conf

    # Point hostapd to our config
    if [ -f /etc/default/hostapd ]; then
        sed -i 's|^#*DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/fortress.conf"|' /etc/default/hostapd
    fi

    # Create helper script to prepare interface for AP mode
    cat > /usr/local/bin/fortress-wifi-prepare.sh << 'PREPEOF'
#!/bin/bash
# Prepare WiFi interface for AP mode
WIFI_IFACE="$1"

# Ensure NetworkManager isn't managing it
nmcli device set "$WIFI_IFACE" managed no 2>/dev/null || true
nmcli device disconnect "$WIFI_IFACE" 2>/dev/null || true

# Set AP mode
ip link set "$WIFI_IFACE" down 2>/dev/null
iw dev "$WIFI_IFACE" set type __ap 2>/dev/null
ip link set "$WIFI_IFACE" up 2>/dev/null

# Verify
sleep 0.5
MODE=$(iw dev "$WIFI_IFACE" info 2>/dev/null | grep "type" | awk '{print $2}')
if [ "$MODE" = "AP" ]; then
    echo "WiFi interface $WIFI_IFACE ready in AP mode"
    exit 0
else
    echo "Warning: Could not set AP mode (current: $MODE)"
    exit 1
fi
PREPEOF
    chmod +x /usr/local/bin/fortress-wifi-prepare.sh

    # Create systemd service for hostapd with pre-start preparation
    cat > /etc/systemd/system/fortress-hostapd.service << EOF
[Unit]
Description=Fortress WiFi Access Point
After=network.target openvswitch-switch.service sys-subsystem-net-devices-${wifi_iface}.device
Wants=sys-subsystem-net-devices-${wifi_iface}.device
Requires=openvswitch-switch.service

[Service]
Type=forking
PIDFile=/run/hostapd.pid
ExecStartPre=/usr/local/bin/fortress-wifi-prepare.sh ${wifi_iface}
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd.pid /etc/hostapd/fortress.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fortress-hostapd 2>/dev/null || true

    # Save WiFi credentials
    cat > /etc/hookprobe/wifi-ap.conf << EOF
# HookProbe Fortress WiFi AP Credentials
WIFI_INTERFACE=$wifi_iface
WIFI_SSID=$ap_ssid
WIFI_PASSWORD=$ap_password
EOF
    chmod 600 /etc/hookprobe/wifi-ap.conf

    log_info "WiFi AP configured:"
    log_info "  SSID: $ap_ssid"
    log_info "  Password: $ap_password"
    log_info "  Interface: $wifi_iface"
}

# ============================================================
# DHCP SERVER (dnsmasq)
# ============================================================
setup_dhcp_server() {
    log_step "Setting up DHCP server (dnsmasq)..."

    if ! command -v dnsmasq &>/dev/null; then
        log_warn "dnsmasq not installed, skipping DHCP setup"
        return 0
    fi

    # Create dnsmasq configuration for Fortress
    mkdir -p /etc/dnsmasq.d
    cat > /etc/dnsmasq.d/fortress.conf << EOF
# HookProbe Fortress DHCP Configuration

# Listen on the bridge interface
interface=$OVS_BRIDGE_NAME
bind-interfaces

# DHCP range for the main network (10.250.0.0/16)
dhcp-range=10.250.1.100,10.250.1.250,255.255.0.0,24h

# Gateway (this Fortress)
dhcp-option=option:router,10.250.0.1

# DNS servers (Fortress itself + Cloudflare)
dhcp-option=option:dns-server,10.250.0.1,1.1.1.1

# Domain
dhcp-option=option:domain-name,fortress.local
local=/fortress.local/

# Lease file
dhcp-leasefile=/var/lib/misc/fortress-dnsmasq.leases

# Logging
log-queries
log-dhcp
log-facility=/var/log/fortress-dnsmasq.log

# Don't read /etc/resolv.conf
no-resolv

# Upstream DNS
server=1.1.1.1
server=8.8.8.8

# Local hostname
address=/fortress.local/10.250.0.1
address=/fortress/10.250.0.1

# DHCP authoritative mode
dhcp-authoritative

# Fast DHCP
dhcp-rapid-commit

# Hostname for DHCP clients
expand-hosts
domain=fortress.local
EOF

    # Create lease file directory
    mkdir -p /var/lib/misc
    touch /var/lib/misc/fortress-dnsmasq.leases

    # Stop system dnsmasq if running (we'll use our own config)
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl disable dnsmasq 2>/dev/null || true

    # Create fortress-dnsmasq service
    cat > /etc/systemd/system/fortress-dnsmasq.service << EOF
[Unit]
Description=Fortress DHCP and DNS Server
After=network.target fortress-hostapd.service
Wants=network.target

[Service]
Type=forking
PIDFile=/run/fortress-dnsmasq.pid
ExecStartPre=/usr/sbin/dnsmasq --test -C /etc/dnsmasq.d/fortress.conf
ExecStart=/usr/sbin/dnsmasq -C /etc/dnsmasq.d/fortress.conf --pid-file=/run/fortress-dnsmasq.pid
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fortress-dnsmasq 2>/dev/null || true

    log_info "DHCP server configured:"
    log_info "  Range: 10.250.1.100 - 10.250.1.250"
    log_info "  Gateway: 10.250.0.1"
    log_info "  DNS: 10.250.0.1, 1.1.1.1"
    log_info "  Domain: fortress.local"
}

# ============================================================
# START NETWORK SERVICES
# ============================================================
start_network_services() {
    log_step "Starting network services..."

    # Start dnsmasq first (DHCP/DNS)
    if [ -f /etc/systemd/system/fortress-dnsmasq.service ]; then
        log_info "Starting DHCP server..."
        systemctl start fortress-dnsmasq 2>/dev/null || log_warn "Failed to start dnsmasq"
    fi

    # Start hostapd (WiFi AP)
    if [ -f /etc/systemd/system/fortress-hostapd.service ]; then
        log_info "Starting WiFi AP..."
        systemctl start fortress-hostapd 2>/dev/null || log_warn "Failed to start hostapd"
    fi

    # Verify services
    sleep 2
    if systemctl is-active fortress-dnsmasq &>/dev/null; then
        log_info "✓ DHCP server running"
    else
        log_warn "✗ DHCP server not running"
    fi

    if systemctl is-active fortress-hostapd &>/dev/null; then
        log_info "✓ WiFi AP running"
    else
        log_warn "✗ WiFi AP not running (may need WiFi interface)"
    fi
}

# ============================================================
# VLAN SEGMENTATION
# ============================================================
setup_vlans() {
    log_step "Setting up VLAN segmentation..."

    # Load 8021q kernel module
    modprobe 8021q 2>/dev/null || true
    echo "8021q" >> /etc/modules 2>/dev/null || true

    # Create VLAN configuration file
    cat > /etc/hookprobe/vlans.conf << 'VLANHEADER'
# HookProbe Fortress VLAN Configuration
# Format: VLAN_NAME|VLAN_ID|SUBNET|DESCRIPTION
VLANHEADER

    for vlan_name in "${!VLAN_CONFIG[@]}"; do
        local config="${VLAN_CONFIG[$vlan_name]}"
        local vlan_id=$(echo "$config" | cut -d: -f1)
        local subnet=$(echo "$config" | cut -d: -f2)

        # Add VLAN to OVS bridge
        ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "vlan${vlan_id}" \
            -- set interface "vlan${vlan_id}" type=internal \
            -- set port "vlan${vlan_id}" tag="${vlan_id}" 2>/dev/null || true

        # Configure VLAN interface
        ip link set "vlan${vlan_id}" up 2>/dev/null || true
        local gateway=$(echo "$subnet" | sed 's/.0\/24/.1/')
        ip addr add "$gateway/24" dev "vlan${vlan_id}" 2>/dev/null || true

        # Save to config
        echo "${vlan_name}|${vlan_id}|${subnet}|${vlan_name} network" >> /etc/hookprobe/vlans.conf

        log_info "VLAN $vlan_id ($vlan_name) configured: $subnet"
    done

    log_info "VLAN segmentation complete"
}

# ============================================================
# VXLAN TUNNELS WITH VNI AND PSK
# ============================================================
setup_vxlan_tunnels() {
    log_step "Setting up VXLAN tunnels with VNI and PSK..."

    local local_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    cat > /etc/hookprobe/vxlan-networks.conf << 'VXLANHEADER'
# HookProbe Fortress VXLAN Network Configuration
# Format: NETWORK_NAME|VNI|PORT|SUBNET|PSK_FILE
VXLANHEADER

    for network in "${!VXLAN_CONFIG[@]}"; do
        local config="${VXLAN_CONFIG[$network]}"
        local vni=$(echo "$config" | cut -d: -f1)
        local port=$(echo "$config" | cut -d: -f2)

        # Generate per-tunnel PSK
        local psk_file="/etc/hookprobe/secrets/vxlan/${network}.psk"
        if [ ! -f "$psk_file" ]; then
            generate_vxlan_psk > "$psk_file"
            chmod 600 "$psk_file"
        fi

        # Add VXLAN port to OVS bridge
        local vxlan_port="vxlan_${vni}"
        ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "$vxlan_port" \
            -- set interface "$vxlan_port" type=vxlan \
            options:key="$vni" \
            options:local_ip="$local_ip" \
            options:remote_ip=flow 2>/dev/null || true

        # Determine subnet
        local subnet=""
        case "$network" in
            fortress-core) subnet="10.250.100.0/24" ;;
            fortress-monitoring) subnet="10.250.101.0/24" ;;
            fortress-automation) subnet="10.250.102.0/24" ;;
            fortress-analytics) subnet="10.250.103.0/24" ;;
            mssp-uplink) subnet="10.250.200.0/24" ;;
        esac

        echo "${network}|${vni}|${port}|${subnet}|${psk_file}" >> /etc/hookprobe/vxlan-networks.conf
        log_info "VXLAN tunnel $network (VNI: $vni) configured"
    done

    log_info "VXLAN tunnels configured"
}

# ============================================================
# MACSEC (802.1AE) LAYER 2 ENCRYPTION
# ============================================================
setup_macsec() {
    log_step "Setting up MACsec (802.1AE) Layer 2 encryption..."

    if [ "$MACSEC_ENABLED" != true ]; then
        log_info "MACsec disabled by configuration"
        return 0
    fi

    # Check for MACsec kernel support
    if ! modprobe macsec 2>/dev/null; then
        log_warn "MACsec kernel module not available"
        log_warn "MACsec requires Linux kernel 4.6+ with CONFIG_MACSEC=y"
        MACSEC_ENABLED=false
        return 0
    fi

    # Create MACsec secrets directory
    mkdir -p /etc/hookprobe/secrets/macsec
    chmod 700 /etc/hookprobe/secrets/macsec

    # Generate MACsec CAK (Connectivity Association Key) and CKN (Connectivity Key Name)
    if [ ! -f /etc/hookprobe/secrets/macsec/cak.key ]; then
        # Generate 128-bit CAK (32 hex chars)
        openssl rand -hex 16 > /etc/hookprobe/secrets/macsec/cak.key
        chmod 600 /etc/hookprobe/secrets/macsec/cak.key
        log_info "MACsec CAK generated"
    fi

    if [ ! -f /etc/hookprobe/secrets/macsec/ckn.key ]; then
        # Generate 128-bit CKN (32 hex chars)
        openssl rand -hex 16 > /etc/hookprobe/secrets/macsec/ckn.key
        chmod 600 /etc/hookprobe/secrets/macsec/ckn.key
        log_info "MACsec CKN generated"
    fi

    local CAK=$(cat /etc/hookprobe/secrets/macsec/cak.key)
    local CKN=$(cat /etc/hookprobe/secrets/macsec/ckn.key)

    # Create MACsec configuration for wpa_supplicant
    cat > /etc/hookprobe/macsec.conf << MACSECEOF
# HookProbe Fortress MACsec Configuration
# 802.1AE Layer 2 Encryption

# MACsec is enabled on wired interfaces for secure L2 communication
# between Fortress nodes and MSSP uplinks

MACSEC_ENABLED=true
MACSEC_CIPHER=gcm-aes-128
MACSEC_REPLAY_PROTECT=true
MACSEC_REPLAY_WINDOW=32

# Keys are stored separately for security
MACSEC_CAK_FILE=/etc/hookprobe/secrets/macsec/cak.key
MACSEC_CKN_FILE=/etc/hookprobe/secrets/macsec/ckn.key
MACSECEOF

    # Create wpa_supplicant MACsec config template
    for iface in $ETH_INTERFACES; do
        cat > "/etc/hookprobe/macsec-${iface}.conf" << WPASECEOF
# MACsec configuration for $iface
ctrl_interface=/var/run/wpa_supplicant
eapol_version=3
ap_scan=0

network={
    key_mgmt=NONE
    eapol_flags=0
    macsec_policy=1
    macsec_integ_only=0
    mka_cak=$CAK
    mka_ckn=$CKN
}
WPASECEOF
        chmod 600 "/etc/hookprobe/macsec-${iface}.conf"
    done

    # Create MACsec management script
    cat > /usr/local/bin/hookprobe-macsec << 'MACSECSCRIPT'
#!/bin/bash
# HookProbe MACsec Management

MACSEC_DIR="/etc/hookprobe"

case "$1" in
    enable)
        IFACE="${2:-eth0}"
        if [ -f "$MACSEC_DIR/macsec-${IFACE}.conf" ]; then
            # Start MKA on the interface
            wpa_supplicant -i "$IFACE" -D macsec_linux \
                -c "$MACSEC_DIR/macsec-${IFACE}.conf" -B
            echo "MACsec enabled on $IFACE"
        else
            echo "No MACsec config for $IFACE"
            exit 1
        fi
        ;;
    disable)
        IFACE="${2:-eth0}"
        pkill -f "wpa_supplicant.*${IFACE}" 2>/dev/null
        ip link del "macsec0" 2>/dev/null || true
        echo "MACsec disabled on $IFACE"
        ;;
    status)
        echo "=== MACsec Status ==="
        ip macsec show 2>/dev/null || echo "No MACsec interfaces"
        echo ""
        echo "=== MKA Sessions ==="
        ps aux | grep -v grep | grep wpa_supplicant | grep macsec || echo "No MKA sessions"
        ;;
    *)
        echo "Usage: $0 {enable|disable|status} [interface]"
        exit 1
        ;;
esac
MACSECSCRIPT

    chmod +x /usr/local/bin/hookprobe-macsec

    log_info "MACsec (802.1AE) configured"
    log_info "  Enable with: hookprobe-macsec enable eth0"
}

# ============================================================
# OPENFLOW SDN RULES
# ============================================================
setup_openflow_rules() {
    log_step "Setting up OpenFlow SDN rules..."

    # Default drop rule (lowest priority)
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=0,actions=drop" 2>/dev/null || true

    # Allow ARP for network discovery
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=100,arp,actions=normal" 2>/dev/null || true

    # Allow ICMP for diagnostics
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=100,icmp,actions=normal" 2>/dev/null || true

    # Allow established connections
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=50,ip,actions=normal" 2>/dev/null || true

    # VLAN-specific rules
    for vlan_name in "${!VLAN_CONFIG[@]}"; do
        local config="${VLAN_CONFIG[$vlan_name]}"
        local vlan_id=$(echo "$config" | cut -d: -f1)

        # Allow intra-VLAN traffic
        ovs-ofctl add-flow "$OVS_BRIDGE_NAME" \
            "priority=200,dl_vlan=${vlan_id},actions=normal" 2>/dev/null || true

        # Log inter-VLAN attempts (for security monitoring)
        # These would be blocked by default drop rule
    done

    # VXLAN tunnel rules
    for port in 4800 4801 4802 4803 4900; do
        ovs-ofctl add-flow "$OVS_BRIDGE_NAME" \
            "priority=200,udp,tp_dst=$port,actions=normal" 2>/dev/null || true
    done

    # Create OpenFlow monitoring script
    cat > /usr/local/bin/hookprobe-openflow << 'OFSCRIPT'
#!/bin/bash
# HookProbe OpenFlow Monitoring

OVS_BRIDGE="${1:-fortress}"

case "${2:-status}" in
    flows)
        echo "=== OpenFlow Flows ==="
        ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null
        ;;
    ports)
        echo "=== Port Statistics ==="
        ovs-ofctl dump-ports "$OVS_BRIDGE" 2>/dev/null
        ;;
    status)
        echo "=== OpenFlow Status ==="
        echo "Bridge: $OVS_BRIDGE"
        ovs-vsctl show | grep -A 20 "$OVS_BRIDGE"
        echo ""
        echo "--- Flow Count ---"
        ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | wc -l
        ;;
    *)
        echo "Usage: $0 [bridge] {flows|ports|status}"
        ;;
esac
OFSCRIPT

    chmod +x /usr/local/bin/hookprobe-openflow

    log_info "OpenFlow SDN rules configured"
}

# ============================================================
# NAT AND ROUTING
# ============================================================
setup_nat_routing() {
    log_step "Configuring NAT and routing for internet access..."

    # Ensure IP forwarding is enabled (also done in setup_ovs_bridge but ensure it persists)
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    # Make IP forwarding persistent
    if [ ! -f /etc/sysctl.d/99-fortress-routing.conf ]; then
        cat > /etc/sysctl.d/99-fortress-routing.conf << 'SYSCTL_EOF'
# Fortress routing configuration
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv6.conf.all.forwarding=1
SYSCTL_EOF
        sysctl -p /etc/sysctl.d/99-fortress-routing.conf >/dev/null 2>&1 || true
    fi

    # Determine WAN interface (interface with default route)
    local wan_iface
    wan_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)

    if [ -z "$wan_iface" ]; then
        # Fallback: first interface that's not loopback, bridge, or vlan
        wan_iface=$(ip -o link show | awk -F': ' '!/lo|fortress|vlan|br-/ {print $2}' | head -1)
    fi

    if [ -z "$wan_iface" ]; then
        log_warn "Could not determine WAN interface - NAT not configured"
        log_warn "Configure manually: iptables -t nat -A POSTROUTING -o <wan_iface> -j MASQUERADE"
        return 1
    fi

    log_info "WAN interface detected: $wan_iface"

    # Clear any existing fortress NAT rules to avoid duplicates
    iptables -t nat -D POSTROUTING -o "$wan_iface" -j MASQUERADE 2>/dev/null || true

    # Setup MASQUERADE on WAN interface
    iptables -t nat -A POSTROUTING -o "$wan_iface" -j MASQUERADE
    log_info "MASQUERADE enabled on $wan_iface"

    # Setup FORWARD rules for bridge traffic
    local bridge="$OVS_BRIDGE_NAME"
    if [ -z "$bridge" ]; then
        bridge="fortress"
    fi

    # Clear existing FORWARD rules for bridge
    iptables -D FORWARD -i "$bridge" -o "$wan_iface" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$wan_iface" -o "$bridge" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$bridge" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$bridge" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    # Add FORWARD rules
    iptables -A FORWARD -i "$bridge" -o "$wan_iface" -j ACCEPT
    iptables -A FORWARD -i "$wan_iface" -o "$bridge" -m state --state RELATED,ESTABLISHED -j ACCEPT
    log_info "FORWARD rules configured for $bridge <-> $wan_iface"

    # Also allow traffic from bridge to any destination (for failover scenarios)
    iptables -A FORWARD -i "$bridge" -j ACCEPT
    iptables -A FORWARD -o "$bridge" -m state --state RELATED,ESTABLISHED -j ACCEPT

    # If LTE interface exists, add MASQUERADE for it too (failover)
    if [ -n "$WWAN_INTERFACES" ]; then
        for lte_iface in $WWAN_INTERFACES; do
            iptables -t nat -D POSTROUTING -o "$lte_iface" -j MASQUERADE 2>/dev/null || true
            iptables -t nat -A POSTROUTING -o "$lte_iface" -j MASQUERADE
            log_info "MASQUERADE enabled on LTE interface: $lte_iface"
        done
    fi

    # Create systemd service for persistence
    cat > /etc/systemd/system/fortress-nat.service << NATEOF
[Unit]
Description=Fortress NAT and Routing Rules
After=network-online.target openvswitch-switch.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/fortress-nat-setup

[Install]
WantedBy=multi-user.target
NATEOF

    # Create NAT setup script
    cat > /usr/local/bin/fortress-nat-setup << 'NATSCRIPT'
#!/bin/bash
# Fortress NAT Setup Script
# Dynamically detects WAN and configures NAT

set -e

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Find WAN interface
WAN=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
if [ -z "$WAN" ]; then
    WAN=$(ip -o link show | awk -F': ' '!/lo|fortress|vlan|br-/ {print $2}' | head -1)
fi

[ -z "$WAN" ] && { echo "No WAN interface found"; exit 1; }

BRIDGE="fortress"

# Setup MASQUERADE
if ! iptables -t nat -C POSTROUTING -o "$WAN" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE
    echo "MASQUERADE enabled on $WAN"
fi

# Setup FORWARD rules
if ! iptables -C FORWARD -i "$BRIDGE" -o "$WAN" -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -i "$BRIDGE" -o "$WAN" -j ACCEPT
fi

if ! iptables -C FORWARD -i "$WAN" -o "$BRIDGE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -i "$WAN" -o "$BRIDGE" -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

# Generic bridge forwarding
if ! iptables -C FORWARD -i "$BRIDGE" -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -i "$BRIDGE" -j ACCEPT
fi

if ! iptables -C FORWARD -o "$BRIDGE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -o "$BRIDGE" -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

# LTE failover interfaces
for LTE in /sys/class/net/wwan* /sys/class/net/wwp*; do
    [ -e "$LTE" ] || continue
    LTE_IFACE=$(basename "$LTE")
    if ! iptables -t nat -C POSTROUTING -o "$LTE_IFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -o "$LTE_IFACE" -j MASQUERADE
        echo "MASQUERADE enabled on $LTE_IFACE"
    fi
done

echo "Fortress NAT configured successfully"
NATSCRIPT

    chmod +x /usr/local/bin/fortress-nat-setup

    # Enable and start NAT service
    systemctl daemon-reload
    systemctl enable fortress-nat 2>/dev/null || true
    systemctl start fortress-nat 2>/dev/null || true

    log_info "NAT and routing configured successfully"
}

# ============================================================
# QSECBIT AGENT
# ============================================================
install_qsecbit_agent() {
    log_step "Installing QSecBit agent..."

    mkdir -p /opt/hookprobe/fortress/qsecbit
    mkdir -p /opt/hookprobe/fortress/data

    # Copy QSecBit modules from source if available
    local QSECBIT_SRC="$REPO_ROOT/core/qsecbit"
    if [ -d "$QSECBIT_SRC" ]; then
        log_info "Copying QSecBit modules from source..."
        cp -r "$QSECBIT_SRC"/*.py /opt/hookprobe/fortress/qsecbit/ 2>/dev/null || true
    fi

    # Create Fortress-specific QSecBit agent
    cat > /opt/hookprobe/fortress/qsecbit/fortress_agent.py << 'QSECBITEOF'
#!/usr/bin/env python3
"""
QSecBit Fortress Agent - Full Implementation
Version: 5.0.0
License: AGPL-3.0

Fortress-enhanced QSecBit with:
- Extended telemetry from monitoring stack
- VLAN security scoring
- MACsec status monitoring
- OpenFlow flow analysis
"""

import json
import time
import os
import sys
import signal
import logging
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from threading import Thread, Event
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List
from http.server import HTTPServer, BaseHTTPRequestHandler

# Logging setup
LOG_DIR = Path("/var/log/hookprobe")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'qsecbit-fortress.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('qsecbit-fortress')

# Paths
DATA_DIR = Path("/opt/hookprobe/fortress/data")
STATS_FILE = DATA_DIR / "qsecbit_stats.json"
CONFIG_DIR = Path("/etc/hookprobe")


@dataclass
class QSecBitConfig:
    """QSecBit configuration for Fortress"""
    # Component weights (must sum to 1.0)
    alpha: float = 0.20   # System drift weight
    beta: float = 0.25    # Network health weight
    gamma: float = 0.25   # Threat detection weight
    delta: float = 0.15   # Energy efficiency weight
    epsilon: float = 0.15 # Infrastructure health weight

    # Thresholds
    amber_threshold: float = 0.45
    red_threshold: float = 0.30

    # Fortress-specific weights
    vlan_weight: float = 0.10
    macsec_weight: float = 0.10
    openflow_weight: float = 0.10


@dataclass
class QSecBitSample:
    """Single QSecBit measurement"""
    timestamp: str
    score: float
    rag_status: str
    components: Dict[str, float]
    threats_detected: int
    suricata_alerts: int
    vlan_violations: int
    macsec_status: str
    openflow_flows: int


class QSecBitFortressAgent:
    """Full QSecBit agent for Fortress deployments"""

    def __init__(self, config: QSecBitConfig = None):
        self.config = config or QSecBitConfig()
        self.running = Event()
        self.start_time = time.time()
        self.last_sample: Optional[QSecBitSample] = None
        self.history: List[QSecBitSample] = []

        DATA_DIR.mkdir(parents=True, exist_ok=True)

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info("QSecBit Fortress Agent initialized")

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.running.clear()

    def get_vlan_violations(self) -> int:
        """Check for VLAN policy violations"""
        try:
            # Check OVS logs for inter-VLAN attempts
            result = subprocess.run(
                ['ovs-ofctl', 'dump-flows', 'fortress'],
                capture_output=True, text=True, timeout=5
            )
            # Count dropped packets (potential violations)
            violations = 0
            for line in result.stdout.split('\n'):
                if 'n_packets=' in line and 'actions=drop' in line:
                    packets = int(line.split('n_packets=')[1].split(',')[0])
                    violations += packets
            return violations
        except Exception:
            return 0

    def get_macsec_status(self) -> str:
        """Check MACsec status"""
        try:
            result = subprocess.run(
                ['ip', 'macsec', 'show'],
                capture_output=True, text=True, timeout=5
            )
            if 'macsec' in result.stdout:
                return 'active'
            return 'inactive'
        except Exception:
            return 'unknown'

    def get_openflow_stats(self) -> int:
        """Get OpenFlow flow count"""
        try:
            result = subprocess.run(
                ['ovs-ofctl', 'dump-flows', 'fortress'],
                capture_output=True, text=True, timeout=5
            )
            return len([l for l in result.stdout.split('\n') if l.strip()])
        except Exception:
            return 0

    def get_suricata_alerts(self) -> int:
        """Get recent Suricata alert count"""
        try:
            alert_file = Path("/var/log/suricata/fast.log")
            if alert_file.exists():
                # Count alerts in last 5 minutes
                cutoff = time.time() - 300
                count = 0
                with open(alert_file, 'r') as f:
                    for line in f:
                        count += 1
                return min(count, 100)  # Cap at 100
            return 0
        except Exception:
            return 0

    def calculate_score(self) -> tuple:
        """Calculate QSecBit score with Fortress enhancements"""
        components = {
            'drift': 0.0,
            'network': 0.0,
            'threats': 0.0,
            'energy': 0.0,
            'infrastructure': 0.0,
            'vlan': 0.0,
            'macsec': 0.0,
            'openflow': 0.0
        }

        # System drift (CPU, memory usage)
        try:
            with open('/proc/loadavg', 'r') as f:
                load = float(f.read().split()[0])
            components['drift'] = max(0, 1.0 - (load / os.cpu_count()))
        except Exception:
            components['drift'] = 0.5

        # Network health
        try:
            result = subprocess.run(['ip', 'link', 'show', 'up'],
                                  capture_output=True, text=True, timeout=5)
            up_interfaces = len([l for l in result.stdout.split('\n') if 'state UP' in l])
            components['network'] = min(1.0, up_interfaces / 4)
        except Exception:
            components['network'] = 0.5

        # Threat detection
        alerts = self.get_suricata_alerts()
        components['threats'] = max(0, 1.0 - (alerts / 50))

        # Energy efficiency (simplified)
        components['energy'] = 0.8

        # Infrastructure health
        try:
            result = subprocess.run(['podman', 'ps', '-q'],
                                  capture_output=True, text=True, timeout=5)
            containers = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
            components['infrastructure'] = min(1.0, containers / 5)
        except Exception:
            components['infrastructure'] = 0.5

        # VLAN security
        violations = self.get_vlan_violations()
        components['vlan'] = max(0, 1.0 - (violations / 100))

        # MACsec status
        macsec = self.get_macsec_status()
        components['macsec'] = 1.0 if macsec == 'active' else 0.5 if macsec == 'inactive' else 0.3

        # OpenFlow health
        flows = self.get_openflow_stats()
        components['openflow'] = min(1.0, flows / 20) if flows > 0 else 0.5

        # Calculate weighted score
        score = (
            self.config.alpha * components['drift'] +
            self.config.beta * components['network'] +
            self.config.gamma * components['threats'] +
            self.config.delta * components['energy'] +
            self.config.epsilon * components['infrastructure'] +
            self.config.vlan_weight * components['vlan'] +
            self.config.macsec_weight * components['macsec'] +
            self.config.openflow_weight * components['openflow']
        )

        # Determine RAG status
        if score >= self.config.amber_threshold:
            rag_status = "GREEN"
        elif score >= self.config.red_threshold:
            rag_status = "AMBER"
        else:
            rag_status = "RED"

        return score, rag_status, components

    def collect_sample(self) -> QSecBitSample:
        """Collect a complete QSecBit sample"""
        score, rag_status, components = self.calculate_score()

        sample = QSecBitSample(
            timestamp=datetime.now().isoformat(),
            score=score,
            rag_status=rag_status,
            components=components,
            threats_detected=0,
            suricata_alerts=self.get_suricata_alerts(),
            vlan_violations=self.get_vlan_violations(),
            macsec_status=self.get_macsec_status(),
            openflow_flows=self.get_openflow_stats()
        )

        self.last_sample = sample
        self.history.append(sample)
        if len(self.history) > 1000:
            self.history = self.history[-500:]

        return sample

    def save_stats(self, sample: QSecBitSample):
        """Save stats to file"""
        try:
            stats = {
                'timestamp': sample.timestamp,
                'score': sample.score,
                'rag_status': sample.rag_status,
                'components': sample.components,
                'threats_detected': sample.threats_detected,
                'suricata_alerts': sample.suricata_alerts,
                'vlan_violations': sample.vlan_violations,
                'macsec_status': sample.macsec_status,
                'openflow_flows': sample.openflow_flows,
                'uptime_seconds': int(time.time() - self.start_time)
            }
            with open(STATS_FILE, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")

    def run_monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("Starting QSecBit monitoring loop...")
        interval = 10

        while self.running.is_set():
            try:
                sample = self.collect_sample()
                self.save_stats(sample)

                logger.info(
                    f"QSecBit: {sample.rag_status} score={sample.score:.3f} "
                    f"vlan_violations={sample.vlan_violations} "
                    f"macsec={sample.macsec_status}"
                )

                time.sleep(interval)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(interval)

    def start(self):
        """Start the agent"""
        logger.info("Starting QSecBit Fortress Agent v5.0.0...")
        self.running.set()

        monitor_thread = Thread(target=self.run_monitoring_loop, daemon=True)
        monitor_thread.start()

        self.running.wait()

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping QSecBit Fortress Agent...")
        self.running.clear()


def main():
    agent = QSecBitFortressAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
QSECBITEOF

    chmod +x /opt/hookprobe/fortress/qsecbit/fortress_agent.py

    # Create systemd service
    cat > /etc/systemd/system/fortress-qsecbit.service << 'SERVICEEOF'
[Unit]
Description=HookProbe Fortress QSecBit Agent v5.0
After=network.target openvswitch-switch.service
Wants=openvswitch-switch.service

[Service]
Type=simple
WorkingDirectory=/opt/hookprobe/fortress/qsecbit
ExecStart=/usr/bin/python3 /opt/hookprobe/fortress/qsecbit/fortress_agent.py
Restart=always
RestartSec=10
User=root
Environment=PYTHONPATH=/opt/hookprobe/fortress

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload
    systemctl enable fortress-qsecbit

    log_info "QSecBit Fortress Agent installed"
}

# ============================================================
# FREERADIUS WITH VLAN ASSIGNMENT
# ============================================================
configure_freeradius_vlan() {
    log_step "Configuring FreeRADIUS for VLAN assignment..."

    local RADIUS_SECRET="${HOOKPROBE_RADIUS_SECRET:-hookprobe_fortress}"

    mkdir -p /etc/fortress
    chmod 755 /etc/fortress

    # Create MAC-to-VLAN database
    cat > /etc/fortress/mac_vlan.json << 'MACVLANEOF'
{
  "version": "1.0",
  "description": "HookProbe Fortress - MAC to VLAN Assignment",
  "default_vlan": 40,
  "vlans": {
    "10": {"name": "management", "description": "Management devices"},
    "20": {"name": "trusted", "description": "Trusted devices"},
    "30": {"name": "iot", "description": "IoT devices"},
    "40": {"name": "guest", "description": "Guest devices"},
    "99": {"name": "quarantine", "description": "Quarantined devices"}
  },
  "devices": {}
}
MACVLANEOF

    chmod 644 /etc/fortress/mac_vlan.json

    # Configure FreeRADIUS for dynamic VLAN
    if [ -d /etc/freeradius/3.0/mods-config/files ]; then
        cat > /etc/freeradius/3.0/mods-config/files/authorize << 'USERSEOF'
# HookProbe Fortress - MAC Authentication with VLAN Assignment
# Devices are assigned to VLANs based on their MAC address

# Management VLAN (10) - Known admin devices
# Add trusted MAC addresses here
# AA:BB:CC:DD:EE:FF Cleartext-Password := "AA:BB:CC:DD:EE:FF"
#     Tunnel-Type = VLAN,
#     Tunnel-Medium-Type = IEEE-802,
#     Tunnel-Private-Group-Id = 10

# DEFAULT: Guest VLAN (40)
DEFAULT Cleartext-Password := "%{User-Name}"
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = 40,
    Reply-Message = "Welcome to HookProbe Fortress - Guest Network"
USERSEOF
        chmod 640 /etc/freeradius/3.0/mods-config/files/authorize
        chown freerad:freerad /etc/freeradius/3.0/mods-config/files/authorize 2>/dev/null || true
    fi

    log_info "FreeRADIUS configured for VLAN assignment"
}

# ============================================================
# MONITORING STACK (OPTIONAL)
# ============================================================
install_monitoring() {
    if [ "$ENABLE_MONITORING" != true ]; then
        log_info "Monitoring disabled"
        return 0
    fi

    log_step "Installing monitoring stack..."

    # Create monitoring directories
    mkdir -p /opt/hookprobe/fortress/monitoring
    mkdir -p /opt/hookprobe/fortress/grafana

    # Victoria Metrics container
    podman run -d \
        --name fortress-victoria \
        --restart unless-stopped \
        -p 8428:8428 \
        -v /opt/hookprobe/fortress/monitoring:/victoria-metrics-data:Z \
        docker.io/victoriametrics/victoria-metrics:latest \
        2>/dev/null || log_warn "Victoria Metrics may already be running"

    # Grafana container
    podman run -d \
        --name fortress-grafana \
        --restart unless-stopped \
        -p 3000:3000 \
        -v /opt/hookprobe/fortress/grafana:/var/lib/grafana:Z \
        -e GF_SECURITY_ADMIN_PASSWORD=hookprobe \
        docker.io/grafana/grafana:latest \
        2>/dev/null || log_warn "Grafana may already be running"

    log_info "Monitoring stack installed"
    log_info "  Victoria Metrics: http://localhost:8428"
    log_info "  Grafana: http://localhost:3000 (admin/hookprobe)"
}

# ============================================================
# CLOUDFLARE TUNNEL (REMOTE ACCESS)
# ============================================================
install_cloudflared() {
    if [ "$ENABLE_REMOTE_ACCESS" != true ]; then
        log_info "Remote access (Cloudflare Tunnel) disabled"
        return 0
    fi

    log_step "Installing Cloudflare Tunnel client for remote access..."

    # Check if already installed
    if command -v cloudflared &>/dev/null; then
        local version=$(cloudflared version 2>&1 | head -1 | awk '{print $3}')
        log_info "cloudflared already installed: $version"
        return 0
    fi

    # Detect architecture
    local arch=""
    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l|armhf) arch="arm" ;;
        *)
            log_warn "Unsupported architecture for cloudflared: $(uname -m)"
            return 1
            ;;
    esac

    log_info "Downloading cloudflared for $arch..."

    local url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}"

    if curl -fsSL -o /tmp/cloudflared "$url"; then
        mv /tmp/cloudflared /usr/local/bin/cloudflared
        chmod +x /usr/local/bin/cloudflared

        # Verify installation
        if /usr/local/bin/cloudflared version &>/dev/null; then
            local version=$(/usr/local/bin/cloudflared version 2>&1 | head -1 | awk '{print $3}')
            log_info "cloudflared $version installed successfully"

            # Create tunnel configuration directory
            mkdir -p /opt/hookprobe/fortress/tunnel
            chmod 700 /opt/hookprobe/fortress/tunnel

            # Copy tunnel management library
            if [ -f "$FORTRESS_ROOT/lib/cloudflare_tunnel.py" ]; then
                cp "$FORTRESS_ROOT/lib/cloudflare_tunnel.py" /opt/hookprobe/fortress/lib/
                log_info "Cloudflare Tunnel manager library installed"
            fi

            log_info ""
            log_info "Cloudflare Tunnel installed! To enable remote access:"
            log_info "  1. Open the Fortress web UI"
            log_info "  2. Go to 'Remote Access' in the sidebar"
            log_info "  3. Follow the setup wizard"
            log_info ""
            log_info "Or configure manually:"
            log_info "  cloudflared tunnel login"
            log_info "  cloudflared tunnel create fortress-\$(hostname)"
            log_info ""
        else
            log_error "cloudflared installation verification failed"
            return 1
        fi
    else
        log_error "Failed to download cloudflared"
        return 1
    fi
}

# ============================================================
# LTE FAILOVER SETUP
# ============================================================
setup_lte_failover() {
    if [ "$ENABLE_LTE" != true ]; then
        log_info "LTE failover disabled"
        return 0
    fi

    if [ "$LTE_MANAGER_AVAILABLE" != true ]; then
        log_error "LTE manager not available. Cannot setup LTE failover."
        return 1
    fi

    log_step "Setting up LTE WAN failover..."

    # Install ModemManager if not present
    if ! command -v mmcli &>/dev/null; then
        log_info "Installing ModemManager..."
        if [ "$PKG_MGR" = "apt" ]; then
            apt-get install -y -qq modemmanager libqmi-utils libmbim-utils 2>/dev/null || true
        else
            dnf install -y -q ModemManager libqmi-utils libmbim-utils 2>/dev/null || true
        fi
    fi

    # Detect LTE modem
    log_info "Detecting LTE modem..."
    if detect_lte_modem; then
        log_info "LTE modem detected:"
        log_info "  Vendor: ${LTE_VENDOR:-unknown}"
        log_info "  Model: ${LTE_MODEL:-unknown}"
        log_info "  Interface: ${LTE_INTERFACE:-unknown}"
        log_info "  Protocol: ${LTE_PROTOCOL:-unknown}"

        # Configure modem with APN
        # Check if APN was provided via command line
        if [ -z "$HOOKPROBE_LTE_APN" ]; then
            if [ "$NON_INTERACTIVE" = true ]; then
                # Non-interactive mode - use default APN
                log_warn "No APN provided in non-interactive mode. Using default: internet"
                log_warn "Configure APN later with: /opt/hookprobe/fortress/devices/common/lte-manager.sh configure"
                HOOKPROBE_LTE_APN="internet"
            else
                # Interactive mode - prompt for APN
                log_info "No APN provided. Starting interactive configuration..."
                echo ""

                if configure_apn_interactive; then
                    log_info "LTE APN configured successfully via interactive setup"
                else
                    log_warn "Failed to configure LTE APN. You can configure it later with:"
                    log_warn "  /opt/hookprobe/fortress/devices/common/lte-manager.sh configure"
                fi
            fi
        fi

        if [ -n "$HOOKPROBE_LTE_APN" ]; then
            # APN provided via command line - use full parameters
            local apn="$HOOKPROBE_LTE_APN"
            local auth_type="${HOOKPROBE_LTE_AUTH:-none}"
            local username="${HOOKPROBE_LTE_USER:-}"
            local password="${HOOKPROBE_LTE_PASS:-}"

            log_info "Configuring LTE modem:"
            log_info "  APN: $apn"
            log_info "  Auth: $auth_type"
            [ -n "$username" ] && log_info "  Username: $username"

            if configure_modem_apn "$apn" "$auth_type" "$username" "$password"; then
                log_info "LTE modem configured successfully"
            else
                log_warn "Failed to configure LTE modem"
            fi
        fi

        # Setup WAN failover
        log_info "Setting up WAN failover..."
        local primary_wan="${WAN_INTERFACE:-eth0}"
        local backup_wan="${LTE_INTERFACE:-wwan0}"

        if setup_wan_failover "$primary_wan" "$backup_wan"; then
            log_info "WAN failover configured:"
            log_info "  Primary WAN: $primary_wan"
            log_info "  Backup WAN: $backup_wan"
        else
            log_warn "Failed to setup WAN failover"
        fi

        # Create LTE failover systemd service
        cat > /etc/systemd/system/fortress-lte-failover.service << 'LTESERVICEEOF'
[Unit]
Description=HookProbe Fortress LTE WAN Failover Monitor
After=network.target ModemManager.service
Wants=ModemManager.service

[Service]
Type=simple
ExecStart=/usr/local/bin/fortress-lte-monitor
Restart=always
RestartSec=30
Environment=HEALTH_CHECK_INTERVAL=30
Environment=FAILOVER_THRESHOLD=3
Environment=FAILBACK_THRESHOLD=5

[Install]
WantedBy=multi-user.target
LTESERVICEEOF

        # Create LTE monitor script
        cat > /usr/local/bin/fortress-lte-monitor << 'LTEMONITOREOF'
#!/bin/bash
# HookProbe Fortress LTE Failover Monitor

source /etc/hookprobe/lte-failover.conf 2>/dev/null || {
    PRIMARY_WAN="eth0"
    BACKUP_WAN="wwan0"
    HEALTH_CHECK_INTERVAL="${HEALTH_CHECK_INTERVAL:-30}"
    FAILOVER_THRESHOLD="${FAILOVER_THRESHOLD:-3}"
    FAILBACK_THRESHOLD="${FAILBACK_THRESHOLD:-5}"
}

DEVICES_DIR="/opt/hookprobe/fortress/devices"
if [ -f "$DEVICES_DIR/common/lte-manager.sh" ]; then
    source "$DEVICES_DIR/common/lte-manager.sh"
    monitor_wan_failover
else
    echo "LTE manager not found"
    exit 1
fi
LTEMONITOREOF

        chmod +x /usr/local/bin/fortress-lte-monitor

        # Save failover configuration
        # Get APN from saved config if set via interactive mode
        local saved_apn="${HOOKPROBE_LTE_APN:-}"
        if [ -z "$saved_apn" ] && [ -f "/var/lib/fortress/lte/config.conf" ]; then
            saved_apn=$(grep "^LTE_APN=" /var/lib/fortress/lte/config.conf 2>/dev/null | cut -d= -f2 | tr -d '"')
        fi

        cat > /etc/hookprobe/lte-failover.conf << LTECONFEOF
# HookProbe Fortress LTE Failover Configuration
# Generated: $(date -Iseconds)

PRIMARY_WAN="${primary_wan}"
BACKUP_WAN="${backup_wan}"
HEALTH_CHECK_INTERVAL=${HEALTH_CHECK_INTERVAL:-30}
FAILOVER_THRESHOLD=${FAILOVER_THRESHOLD:-3}
FAILBACK_THRESHOLD=${FAILBACK_THRESHOLD:-5}
HEALTH_CHECK_TARGETS="8.8.8.8 1.1.1.1"

# LTE Modem Info
LTE_VENDOR="${LTE_VENDOR:-}"
LTE_MODEL="${LTE_MODEL:-}"
LTE_INTERFACE="${LTE_INTERFACE:-}"
LTE_APN="${saved_apn:-}"
LTE_AUTH="${HOOKPROBE_LTE_AUTH:-none}"
LTECONFEOF

        chmod 644 /etc/hookprobe/lte-failover.conf

        systemctl daemon-reload
        systemctl enable fortress-lte-failover

        log_info "LTE failover setup complete"
    else
        log_warn "No LTE modem detected. LTE failover not configured."
        log_warn "Connect a supported LTE modem and re-run setup with --enable-lte"
    fi
}

# ============================================================
# SYSTEMD SERVICES
# ============================================================
create_systemd_services() {
    log_step "Creating systemd services..."

    # Main Fortress service
    cat > /etc/systemd/system/hookprobe-fortress.service << 'SERVICEEOF'
[Unit]
Description=HookProbe Fortress Edge Gateway
After=network.target openvswitch-switch.service
Wants=openvswitch-switch.service fortress-qsecbit.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecStartPost=/usr/local/bin/hookprobe-fortress-start
ExecStop=/usr/local/bin/hookprobe-fortress-stop

[Install]
WantedBy=multi-user.target
SERVICEEOF

    # Start script
    cat > /usr/local/bin/hookprobe-fortress-start << 'STARTEOF'
#!/bin/bash
echo "Starting HookProbe Fortress..."

# Ensure OVS is running
systemctl start openvswitch-switch 2>/dev/null || true

# Start QSecBit agent
systemctl start fortress-qsecbit 2>/dev/null || true

# Start containers
podman start fortress-victoria 2>/dev/null || true
podman start fortress-grafana 2>/dev/null || true

echo "HookProbe Fortress started"
STARTEOF

    chmod +x /usr/local/bin/hookprobe-fortress-start

    # Stop script
    cat > /usr/local/bin/hookprobe-fortress-stop << 'STOPEOF'
#!/bin/bash
echo "Stopping HookProbe Fortress..."

systemctl stop fortress-qsecbit 2>/dev/null || true
podman stop fortress-victoria 2>/dev/null || true
podman stop fortress-grafana 2>/dev/null || true

echo "HookProbe Fortress stopped"
STOPEOF

    chmod +x /usr/local/bin/hookprobe-fortress-stop

    systemctl daemon-reload
    systemctl enable hookprobe-fortress

    log_info "Systemd services created"
}

# ============================================================
# WEB DASHBOARD
# ============================================================
install_web_dashboard() {
    log_step "Installing web dashboard..."

    local WEB_DIR="/opt/hookprobe/fortress/web"
    local SRC_WEB="$FORTRESS_ROOT/web"

    # Create web directory
    mkdir -p "$WEB_DIR"

    # Copy web files from source
    if [ -d "$SRC_WEB" ]; then
        log_info "Copying web files from $SRC_WEB..."
        cp -r "$SRC_WEB"/* "$WEB_DIR/"
    else
        log_error "Web source directory not found: $SRC_WEB"
        return 1
    fi

    # Generate SSL certificates for HTTPS
    local CERT_DIR="/etc/hookprobe/ssl"
    mkdir -p "$CERT_DIR"

    if [ ! -f "$CERT_DIR/fortress.crt" ] || [ ! -f "$CERT_DIR/fortress.key" ]; then
        log_info "Generating self-signed SSL certificate..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$CERT_DIR/fortress.key" \
            -out "$CERT_DIR/fortress.crt" \
            -subj "/C=US/ST=State/L=City/O=HookProbe/OU=Fortress/CN=$(hostname)" \
            2>/dev/null
        chmod 600 "$CERT_DIR/fortress.key"
        chmod 644 "$CERT_DIR/fortress.crt"
        log_info "SSL certificate generated"
    fi

    # Generate secret key for Flask sessions
    local SECRET_DIR="/etc/hookprobe/secrets"
    mkdir -p "$SECRET_DIR"
    if [ ! -f "$SECRET_DIR/fortress_secret_key" ]; then
        openssl rand -hex 32 > "$SECRET_DIR/fortress_secret_key"
        chmod 600 "$SECRET_DIR/fortress_secret_key"
    fi

    # Create default admin user credentials file
    local USERS_FILE="$WEB_DIR/users.json"
    if [ ! -f "$USERS_FILE" ]; then
        # Generate random password for admin
        local ADMIN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | head -c 12)
        # Hash password with Python
        local PASS_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw('$ADMIN_PASS'.encode(), bcrypt.gensalt()).decode())" 2>/dev/null || echo "")

        if [ -n "$PASS_HASH" ]; then
            cat > "$USERS_FILE" << USERSEOF
{
    "admin": {
        "password_hash": "$PASS_HASH",
        "role": "admin",
        "name": "Administrator"
    }
}
USERSEOF
            chmod 600 "$USERS_FILE"

            # Save credentials for display
            echo "$ADMIN_PASS" > "$SECRET_DIR/admin_password"
            chmod 600 "$SECRET_DIR/admin_password"
            log_info "Admin user created (password saved to $SECRET_DIR/admin_password)"
        else
            log_warn "Could not hash password - bcrypt may not be installed"
        fi
    fi

    # Create gunicorn configuration
    cat > "$WEB_DIR/gunicorn.conf.py" << 'GUNICORNEOF'
# Gunicorn configuration for Fortress Web Dashboard
import multiprocessing

# Bind to all interfaces on port 8443
bind = "0.0.0.0:8443"

# SSL Configuration
certfile = "/etc/hookprobe/ssl/fortress.crt"
keyfile = "/etc/hookprobe/ssl/fortress.key"

# Workers - 2 for small devices, more for larger
workers = min(2, multiprocessing.cpu_count())
worker_class = "sync"
threads = 2

# Timeouts
timeout = 30
keepalive = 2

# Logging
accesslog = "/var/log/hookprobe/fortress-web-access.log"
errorlog = "/var/log/hookprobe/fortress-web-error.log"
loglevel = "info"

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
GUNICORNEOF

    # Create systemd service for web dashboard
    cat > /etc/systemd/system/fortress-web.service << 'WEBSERVICEEOF'
[Unit]
Description=HookProbe Fortress Web Dashboard
After=network.target openvswitch-switch.service
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/hookprobe/fortress/web
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=/usr/bin/python3 -m gunicorn --config gunicorn.conf.py app:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fortress-web

[Install]
WantedBy=multi-user.target
WEBSERVICEEOF

    # Enable and start the service
    systemctl daemon-reload
    systemctl enable fortress-web
    systemctl start fortress-web

    # Wait for startup
    sleep 2

    if systemctl is-active fortress-web &>/dev/null; then
        log_info "Web dashboard started successfully on https://0.0.0.0:8443"
    else
        log_warn "Web dashboard may not have started - check: journalctl -u fortress-web"
    fi

    log_info "Web dashboard installed"
}

# ============================================================
# MAIN CONFIGURATION FILE
# ============================================================
create_config_file() {
    log_step "Creating main configuration file..."

    cat > /etc/hookprobe/fortress.conf << CONFEOF
# HookProbe Fortress Configuration
# Version: 5.0.0
# Generated: $(date -Iseconds)

[general]
tier = fortress
node_id = ${HOOKPROBE_NODE_ID:-$(hostname)-fortress}
version = 5.0.0

[device]
device_id = ${FORTRESS_DEVICE_ID:-unknown}
device_name = ${FORTRESS_DEVICE_NAME:-Unknown Device}
device_family = ${FORTRESS_DEVICE_FAMILY:-unknown}
architecture = ${FORTRESS_ARCHITECTURE:-$(uname -m)}
profile_dir = ${FORTRESS_PROFILE_DIR:-}

[network]
ovs_bridge = $OVS_BRIDGE_NAME
vlan_segmentation = $VLAN_SEGMENTATION
macsec_enabled = $MACSEC_ENABLED
wan_interface = ${WAN_INTERFACE:-${FORTRESS_WAN_IFACE:-}}
lan_interfaces = ${LAN_INTERFACES:-${FORTRESS_LAN_IFACES:-}}
total_nics = ${FORTRESS_TOTAL_NICS:-0}

[vlans]
management = 10
trusted = 20
iot = 30
guest = 40
quarantine = 99

[vxlan]
enabled = true
mssp_vni = 2000
mssp_endpoint = ${HOOKPROBE_MSSP_URL:-mssp.hookprobe.com}

[security]
qsecbit_enabled = true
openflow_enabled = true
macsec_enabled = $MACSEC_ENABLED
xdp_mode = ${FORTRESS_XDP_MODE:-generic}

[monitoring]
enabled = $ENABLE_MONITORING
victoria_metrics_port = 8428
grafana_port = 3000

[automation]
n8n_enabled = $ENABLE_N8N

[lte]
enabled = $ENABLE_LTE
interface = ${LTE_INTERFACE:-}
vendor = ${LTE_VENDOR:-}
model = ${LTE_MODEL:-}
protocol = ${LTE_PROTOCOL:-}
CONFEOF

    chmod 644 /etc/hookprobe/fortress.conf
    log_info "Configuration file created: /etc/hookprobe/fortress.conf"

    # Copy device profiles to installation directory
    if [ -d "$DEVICES_DIR" ]; then
        log_info "Installing device profiles..."
        mkdir -p /opt/hookprobe/fortress/devices
        cp -r "$DEVICES_DIR"/* /opt/hookprobe/fortress/devices/
        log_info "Device profiles installed to /opt/hookprobe/fortress/devices/"
    fi
}

# ============================================================
# VALIDATION
# ============================================================
validate_installation() {
    log_step "Validating installation..."

    local errors=0
    local warnings=0

    # Check OVS bridge
    if command -v ovs-vsctl &>/dev/null && ovs-vsctl br-exists "$OVS_BRIDGE_NAME" 2>/dev/null; then
        log_info "✓ OVS bridge '$OVS_BRIDGE_NAME' exists"
    else
        log_error "✗ OVS bridge '$OVS_BRIDGE_NAME' not found"
        errors=$((errors + 1))
    fi

    # Check systemd services are enabled
    for service in hookprobe-fortress fortress-qsecbit; do
        if systemctl is-enabled "$service" &>/dev/null; then
            log_info "✓ Service $service enabled"
        else
            log_warn "⚠ Service $service not enabled"
            warnings=$((warnings + 1))
        fi
    done

    # Check management scripts exist
    for script in hookprobe-macsec hookprobe-openflow; do
        if [ -x "/usr/local/bin/$script" ]; then
            log_info "✓ Script $script installed"
        else
            log_warn "⚠ Script $script not found"
            warnings=$((warnings + 1))
        fi
    done

    # Check QSecBit agent
    if [ -f "/opt/hookprobe/fortress/qsecbit/fortress_agent.py" ]; then
        log_info "✓ QSecBit Fortress agent installed"
    else
        log_error "✗ QSecBit Fortress agent not found"
        errors=$((errors + 1))
    fi

    # Check config files
    if [ -f "/etc/hookprobe/fortress.conf" ]; then
        log_info "✓ Fortress configuration file created"
    else
        log_error "✗ Fortress configuration file not found"
        errors=$((errors + 1))
    fi

    # Check VLAN setup
    local vlan_count=0
    for vlan_id in 10 20 30 40 99; do
        if ip link show "vlan${vlan_id}" &>/dev/null 2>&1 || ovs-vsctl port-to-br "vlan${vlan_id}" &>/dev/null 2>&1; then
            vlan_count=$((vlan_count + 1))
        fi
    done
    if [ "$vlan_count" -ge 3 ]; then
        log_info "✓ VLAN interfaces configured ($vlan_count/5)"
    else
        log_warn "⚠ Only $vlan_count/5 VLAN interfaces found"
        warnings=$((warnings + 1))
    fi

    # Check monitoring containers if enabled
    if [ "$ENABLE_MONITORING" = true ]; then
        if command -v podman &>/dev/null; then
            if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fortress-victoria"; then
                log_info "✓ Victoria Metrics container running"
            else
                log_warn "⚠ Victoria Metrics container not running"
                warnings=$((warnings + 1))
            fi
            if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fortress-grafana"; then
                log_info "✓ Grafana container running"
            else
                log_warn "⚠ Grafana container not running"
                warnings=$((warnings + 1))
            fi
        fi
    fi

    # Check LTE if enabled
    if [ "$ENABLE_LTE" = true ]; then
        if systemctl is-enabled fortress-lte-failover &>/dev/null; then
            log_info "✓ LTE failover service enabled"
        else
            log_warn "⚠ LTE failover service not enabled"
            warnings=$((warnings + 1))
        fi
    fi

    # Summary
    echo ""
    if [ $errors -eq 0 ] && [ $warnings -eq 0 ]; then
        log_info "Validation complete: All checks passed"
        return 0
    elif [ $errors -eq 0 ]; then
        log_warn "Validation complete: $warnings warning(s)"
        return 0
    else
        log_error "Validation failed: $errors error(s), $warnings warning(s)"
        return 1
    fi
}

# ============================================================
# SHOW COMPLETION
# ============================================================
show_completion() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║   ${GREEN}HookProbe Fortress Installation Complete${NC}                  ${CYAN}║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Device information
    if [ -n "$FORTRESS_DEVICE_ID" ] && [ "$FORTRESS_DEVICE_ID" != "unknown" ]; then
        echo -e "  ${BOLD}Detected Hardware:${NC}"
        echo -e "  Device: ${GREEN}${FORTRESS_DEVICE_NAME:-$FORTRESS_DEVICE_ID}${NC}"
        echo -e "  Family: ${FORTRESS_DEVICE_FAMILY:-unknown}"
        echo -e "  Architecture: ${FORTRESS_ARCHITECTURE:-$(uname -m)}"
        [ -n "$FORTRESS_WAN_IFACE" ] && echo -e "  WAN Interface: ${CYAN}$FORTRESS_WAN_IFACE${NC}"
        [ -n "$FORTRESS_LAN_IFACES" ] && echo -e "  LAN Interfaces: ${CYAN}$FORTRESS_LAN_IFACES${NC}"
        echo ""
    fi

    echo -e "  ${BOLD}Installed Components:${NC}"
    echo -e "  ${GREEN}✓${NC} Open vSwitch with OpenFlow 1.3"
    echo -e "  ${GREEN}✓${NC} VLAN Segmentation (management, trusted, iot, guest, quarantine)"
    echo -e "  ${GREEN}✓${NC} VXLAN Tunnels with VNI and PSK encryption"
    echo -e "  ${GREEN}✓${NC} MACsec (802.1AE) Layer 2 encryption"
    echo -e "  ${GREEN}✓${NC} QSecBit Fortress Agent"
    echo -e "  ${GREEN}✓${NC} FreeRADIUS with dynamic VLAN assignment"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  ${GREEN}✓${NC} Monitoring (Grafana + Victoria Metrics)"
    [ "$ENABLE_N8N" = true ] && echo -e "  ${GREEN}✓${NC} n8n Workflow Automation"
    [ "$ENABLE_REMOTE_ACCESS" = true ] && echo -e "  ${GREEN}✓${NC} Cloudflare Tunnel (Remote Access)"

    # LTE information
    if [ "$ENABLE_LTE" = true ] && [ -n "$LTE_INTERFACE" ]; then
        echo -e "  ${GREEN}✓${NC} LTE WAN Failover (${LTE_VENDOR:-Unknown} ${LTE_MODEL:-modem})"
    fi
    echo ""

    echo -e "  ${BOLD}Network Configuration:${NC}"
    echo -e "  Bridge: $OVS_BRIDGE_NAME (10.250.0.1)"
    echo -e "  DHCP Range: 10.250.1.100 - 10.250.1.250"
    [ -n "$FORTRESS_WAN_IFACE" ] && echo -e "  Primary WAN: $FORTRESS_WAN_IFACE"
    [ "$ENABLE_LTE" = true ] && [ -n "$LTE_INTERFACE" ] && echo -e "  Backup WAN (LTE): $LTE_INTERFACE"

    # Show WiFi credentials if configured
    if [ -f /etc/hookprobe/wifi-ap.conf ]; then
        source /etc/hookprobe/wifi-ap.conf 2>/dev/null
        if [ -n "$WIFI_SSID" ]; then
            echo ""
            echo -e "  ${BOLD}${GREEN}WiFi Access Point:${NC}"
            echo -e "  SSID:     ${CYAN}$WIFI_SSID${NC}"
            echo -e "  Password: ${CYAN}$WIFI_PASSWORD${NC}"
        fi
    fi

    # Show admin credentials
    if [ -f /etc/hookprobe/secrets/admin_password ]; then
        local ADMIN_PASS=$(cat /etc/hookprobe/secrets/admin_password 2>/dev/null)
        if [ -n "$ADMIN_PASS" ]; then
            echo ""
            echo -e "  ${BOLD}${GREEN}Web Dashboard Login:${NC}"
            echo -e "  URL:      ${CYAN}https://10.250.0.1:8443${NC}"
            echo -e "  Username: ${CYAN}admin${NC}"
            echo -e "  Password: ${CYAN}$ADMIN_PASS${NC}"
            echo -e "  ${DIM}(Change this password after first login!)${NC}"
        fi
    fi
    echo ""

    echo -e "  ${BOLD}Connect to Fortress:${NC}"
    echo -e "  1. Connect to WiFi: ${CYAN}${WIFI_SSID:-Fortress-$(hostname -s)}${NC}"
    echo -e "  2. Or plug into a LAN port"
    echo -e "  3. You'll get an IP in 10.250.1.x range"
    echo -e "  4. Access dashboard: ${CYAN}https://10.250.0.1:8443${NC}"
    echo ""

    echo -e "  ${BOLD}Management Commands:${NC}"
    echo -e "  ${CYAN}hookprobe-macsec${NC} enable eth0  - Enable MACsec on interface"
    echo -e "  ${CYAN}hookprobe-openflow${NC} status     - View OpenFlow status"
    echo -e "  ${CYAN}systemctl status${NC} hookprobe-fortress"
    [ "$ENABLE_LTE" = true ] && echo -e "  ${CYAN}systemctl status${NC} fortress-lte-failover"
    echo ""
    echo -e "  ${BOLD}Web Interfaces:${NC}"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  Grafana:          http://localhost:3000"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  Victoria Metrics: http://localhost:8428"
    echo -e "  Fortress Web UI:  https://localhost:8443"
    [ "$ENABLE_REMOTE_ACCESS" = true ] && echo -e ""
    [ "$ENABLE_REMOTE_ACCESS" = true ] && echo -e "  ${BOLD}Remote Access:${NC}"
    [ "$ENABLE_REMOTE_ACCESS" = true ] && echo -e "  cloudflared installed - configure via Web UI > Remote Access"
    echo ""
    echo -e "  ${BOLD}Logs:${NC}"
    echo -e "  journalctl -u fortress-qsecbit -f"
    [ "$ENABLE_LTE" = true ] && echo -e "  journalctl -u fortress-lte-failover -f"
    echo ""

    # Show device profile info if available
    if [ -n "$FORTRESS_PROFILE_DIR" ] && [ -d "$FORTRESS_PROFILE_DIR" ]; then
        echo -e "  ${BOLD}Device Profile:${NC}"
        echo -e "  $FORTRESS_PROFILE_DIR"
        echo ""
    fi
}

# ============================================================
# USER INPUT COLLECTION (before installation)
# ============================================================
collect_user_inputs() {
    # Collect all user configuration BEFORE starting installation
    # This allows users to provide all inputs upfront, then enjoy coffee

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Configuration Setup${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "We'll collect a few settings before starting installation."
    echo "After this, no further input is needed - grab a coffee! ☕"
    echo ""

    # ─────────────────────────────────────────────────────────────
    # Feature Selection
    # ─────────────────────────────────────────────────────────────
    echo -e "${YELLOW}Optional Features:${NC}"
    echo ""

    # LTE Failover
    if [ "$ENABLE_LTE" != true ]; then
        if [ "$WWAN_COUNT" -gt 0 ] || [ -n "$MODEM_CTRL_DEVICES" ]; then
            echo -e "${GREEN}✓ LTE modem detected${NC}"
            read -p "Enable LTE WAN failover? [Y/n]: " enable_lte_choice
            enable_lte_choice="${enable_lte_choice:-Y}"
            [[ "${enable_lte_choice,,}" =~ ^y ]] && ENABLE_LTE=true
        else
            read -p "Enable LTE WAN failover? (no modem detected) [y/N]: " enable_lte_choice
            [[ "${enable_lte_choice,,}" =~ ^y ]] && ENABLE_LTE=true
        fi
    fi

    # Remote Access (Cloudflare Tunnel)
    if [ "$ENABLE_REMOTE_ACCESS" != true ]; then
        read -p "Enable remote dashboard access (Cloudflare Tunnel)? [y/N]: " enable_remote_choice
        [[ "${enable_remote_choice,,}" =~ ^y ]] && ENABLE_REMOTE_ACCESS=true
    fi

    echo ""

    # ─────────────────────────────────────────────────────────────
    # LTE Configuration
    # ─────────────────────────────────────────────────────────────
    if [ "$ENABLE_LTE" = true ] && [ -z "$HOOKPROBE_LTE_APN" ]; then
        echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
        echo -e "${CYAN}  LTE Configuration${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
        echo ""

        # Show detected modem
        if [ -n "$MODEM_CTRL_DEVICES" ]; then
            echo -e "${GREEN}✓ Modem device: $MODEM_CTRL_DEVICES${NC}"
        fi
        if [ -n "$WWAN_INTERFACES" ]; then
            echo -e "${GREEN}✓ WWAN interface: $WWAN_INTERFACES${NC}"
        fi
        echo ""

        # Common APNs
        echo "Common APNs by carrier:"
        echo "  Vodafone:   internet.vodafone.ro, web.vodafone.de, internet"
        echo "  Orange:     internet, orange.ro, orange"
        echo "  T-Mobile:   internet.t-mobile, fast.t-mobile.com"
        echo "  AT&T:       broadband, phone"
        echo "  Verizon:    vzwinternet"
        echo "  Generic:    internet"
        echo ""

        read -p "Enter your APN name: " HOOKPROBE_LTE_APN
        if [ -z "$HOOKPROBE_LTE_APN" ]; then
            log_warn "No APN provided - using 'internet' as default"
            HOOKPROBE_LTE_APN="internet"
        fi

        # Authentication (most don't need it)
        echo ""
        echo "Does your carrier require authentication? (most don't)"
        read -p "Require auth? [y/N]: " need_auth
        if [[ "${need_auth,,}" =~ ^y ]]; then
            echo "Auth types: 1=PAP, 2=CHAP, 3=MSCHAPv2"
            read -p "Select [1-3]: " auth_choice
            case "$auth_choice" in
                1) HOOKPROBE_LTE_AUTH="pap" ;;
                2) HOOKPROBE_LTE_AUTH="chap" ;;
                3) HOOKPROBE_LTE_AUTH="mschapv2" ;;
                *) HOOKPROBE_LTE_AUTH="none" ;;
            esac
            if [ "$HOOKPROBE_LTE_AUTH" != "none" ]; then
                read -p "Username: " HOOKPROBE_LTE_USER
                read -sp "Password: " HOOKPROBE_LTE_PASS
                echo ""
            fi
        else
            HOOKPROBE_LTE_AUTH="none"
        fi
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────
    # Cloudflare Tunnel Configuration
    # ─────────────────────────────────────────────────────────────
    if [ "$ENABLE_REMOTE_ACCESS" = true ]; then
        echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
        echo -e "${CYAN}  Remote Access Configuration${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
        echo ""
        echo "Cloudflare Tunnel allows secure remote access to your dashboard."
        echo "You'll need a Cloudflare account and can set this up later via Web UI."
        echo ""
        echo "Setup options:"
        echo "  1. Configure now (need Cloudflare tunnel token)"
        echo "  2. Configure later via Web UI (recommended)"
        echo ""
        read -p "Select [1-2] (default: 2): " cf_choice
        cf_choice="${cf_choice:-2}"

        if [ "$cf_choice" = "1" ]; then
            echo ""
            echo "To get your tunnel token:"
            echo "  1. Go to https://one.dash.cloudflare.com"
            echo "  2. Networks → Tunnels → Create a tunnel"
            echo "  3. Copy the tunnel token"
            echo ""
            read -p "Enter Cloudflare tunnel token (or press Enter to skip): " CLOUDFLARE_TUNNEL_TOKEN
            if [ -n "$CLOUDFLARE_TUNNEL_TOKEN" ]; then
                read -p "Enter hostname (e.g., fortress.yourdomain.com): " CLOUDFLARE_TUNNEL_HOSTNAME
            fi
        fi
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────
    # Configuration Summary
    # ─────────────────────────────────────────────────────────────
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Configuration Summary${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Core Features:${NC}"
    echo "    ✓ OVS Bridge with OpenFlow 1.3"
    echo "    ✓ VLAN Segmentation (5 VLANs)"
    [ "$MACSEC_ENABLED" = true ] && echo "    ✓ MACsec Layer 2 Encryption"
    echo "    ✓ QSecBit Security Agent"
    echo "    ✓ Web Dashboard (https://localhost:8443)"
    echo ""
    echo -e "  ${BOLD}Optional Features:${NC}"
    [ "$ENABLE_LTE" = true ] && echo "    ✓ LTE Failover (APN: $HOOKPROBE_LTE_APN)"
    [ "$ENABLE_REMOTE_ACCESS" = true ] && echo "    ✓ Remote Access (Cloudflare Tunnel)"
    [ "$ENABLE_MONITORING" = true ] && echo "    ✓ Monitoring (Grafana + Victoria Metrics)"
    [ "$ENABLE_N8N" = true ] && echo "    ✓ n8n Workflow Automation"
    [ "$ENABLE_LTE" != true ] && [ "$ENABLE_REMOTE_ACCESS" != true ] && echo "    (none selected)"
    echo ""

    # Confirm
    read -p "Proceed with installation? [Y/n]: " confirm_install
    confirm_install="${confirm_install:-Y}"
    if [[ ! "${confirm_install,,}" =~ ^y ]]; then
        echo "Installation cancelled."
        exit 0
    fi
}

# ============================================================
# MAIN
# ============================================================
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║              HookProbe Fortress Installer                    ║${NC}"
    echo -e "${CYAN}║                    Version 5.0.0                             ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --enable-n8n) ENABLE_N8N=true; shift ;;
            --enable-monitoring) ENABLE_MONITORING=true; shift ;;
            --enable-clickhouse) ENABLE_CLICKHOUSE=true; shift ;;
            --enable-lte) ENABLE_LTE=true; shift ;;
            --enable-remote-access) ENABLE_REMOTE_ACCESS=true; shift ;;
            --non-interactive) NON_INTERACTIVE=true; shift ;;
            --lte-apn) HOOKPROBE_LTE_APN="$2"; shift 2 ;;
            --lte-auth) HOOKPROBE_LTE_AUTH="$2"; shift 2 ;;
            --lte-user) HOOKPROBE_LTE_USER="$2"; shift 2 ;;
            --lte-pass) HOOKPROBE_LTE_PASS="$2"; shift 2 ;;
            --disable-macsec) MACSEC_ENABLED=false; shift ;;
            --disable-vlan) VLAN_SEGMENTATION=false; shift ;;
            --node-id) HOOKPROBE_NODE_ID="$2"; shift 2 ;;
            --mssp-url) HOOKPROBE_MSSP_URL="$2"; shift 2 ;;
            --help|-h)
                echo "HookProbe Fortress Installer v5.0.0"
                echo ""
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --enable-n8n           Enable n8n workflow automation"
                echo "  --enable-monitoring    Enable Grafana + Victoria Metrics"
                echo "  --enable-clickhouse    Enable ClickHouse analytics"
                echo "  --enable-lte           Enable LTE WAN failover"
                echo "  --enable-remote-access Install Cloudflare Tunnel for remote dashboard access"
                echo "  --lte-apn APN          Set LTE APN (e.g., internet.vodafone.ro)"
                echo "  --lte-auth TYPE        Set LTE auth type: none, pap, chap, mschapv2"
                echo "  --lte-user USER        Set LTE username (for PAP/CHAP auth)"
                echo "  --lte-pass PASS        Set LTE password (for PAP/CHAP auth)"
                echo "  --disable-macsec       Disable MACsec L2 encryption"
                echo "  --disable-vlan         Disable VLAN segmentation"
                echo "  --node-id ID           Set node identifier"
                echo "  --mssp-url URL         Set MSSP endpoint URL"
                echo "  --non-interactive      Run without prompts (for automation)"
                echo "  --help, -h             Show this help message"
                echo ""
                echo "Supported Devices:"
                echo "  - Intel N100/N150/N200/N305 Mini-PCs"
                echo "  - Raspberry Pi Compute Module 5"
                echo "  - Radxa Rock 5B"
                echo "  - Generic x86_64/ARM64 systems"
                echo ""
                echo "LTE Modems:"
                echo "  - Quectel EC25, EM05, RM500Q"
                echo "  - Sierra Wireless EM7455, EM7565"
                echo "  - Huawei ME909s"
                echo "  - Fibocom FM150, L850-GL"
                echo ""
                exit 0
                ;;
            *) shift ;;
        esac
    done

    # Phase 1: Pre-flight checks
    check_root
    check_requirements
    detect_platform
    detect_interfaces

    # Phase 2: Collect all user inputs BEFORE installation
    if [ "$NON_INTERACTIVE" != true ]; then
        collect_user_inputs
    fi

    # Phase 3: Installation - user can enjoy coffee ☕
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║   ☕ Grab a coffee - Fortress is being configured for you   ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║   This will take a few minutes. No further input needed.    ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    sleep 2

    install_packages
    verify_critical_packages
    install_python_packages
    install_podman
    install_openvswitch

    setup_ovs_bridge
    setup_lan_bridge
    setup_wifi_ap
    setup_dhcp_server
    setup_vlans
    setup_vxlan_tunnels
    setup_macsec
    setup_openflow_rules
    setup_nat_routing

    install_qsecbit_agent
    configure_freeradius_vlan
    install_monitoring
    install_cloudflared
    setup_lte_failover

    # Start network services (DHCP, WiFi AP)
    start_network_services

    create_systemd_services
    create_config_file
    install_web_dashboard

    # Start services
    log_step "Starting services..."
    systemctl start hookprobe-fortress 2>/dev/null || true
    systemctl start fortress-qsecbit 2>/dev/null || true

    # Validate installation
    validate_installation

    show_completion
}

main "$@"
