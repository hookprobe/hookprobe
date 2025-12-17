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

# Source network integration module (new unified detection)
if [ -f "$DEVICES_DIR/common/network-integration.sh" ]; then
    source "$DEVICES_DIR/common/network-integration.sh"
    NETWORK_INTEGRATION_AVAILABLE=true
else
    NETWORK_INTEGRATION_AVAILABLE=false
fi

# Source hostapd generator for dual-band WiFi
if [ -f "$DEVICES_DIR/common/hostapd-generator.sh" ]; then
    HOSTAPD_GENERATOR_AVAILABLE=true
else
    HOSTAPD_GENERATOR_AVAILABLE=false
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
    # NET_QUIET_MODE=true suppresses verbose detector output
    # NET_SKIP_SUMMARY=true also suppresses the summary display

    [ "$NET_SKIP_SUMMARY" = "true" ] || log_step "Detecting network interfaces..."

    # Use new unified network detection if available
    if [ "$NETWORK_INTEGRATION_AVAILABLE" = true ]; then
        [ "$NET_SKIP_SUMMARY" = "true" ] || log_info "Using unified network interface detection..."
        network_integration_init

        # Show summary of detected interfaces (unless NET_SKIP_SUMMARY is set)
        if [ "$NET_SKIP_SUMMARY" != "true" ]; then
            log_info "Ethernet interfaces ($NET_ETH_COUNT): ${NET_ETH_INTERFACES:-none}"
            log_info "  WAN: ${NET_WAN_IFACE:-not assigned}"
            log_info "  LAN: ${NET_LAN_IFACES:-not assigned}"
            log_info "WiFi interfaces ($NET_WIFI_COUNT): ${NET_WIFI_INTERFACES:-none}"
            log_info "  2.4GHz: ${NET_WIFI_24GHZ_IFACE:-not available}"
            log_info "  5GHz: ${NET_WIFI_5GHZ_IFACE:-not available}"
            log_info "  Config Mode: ${NET_WIFI_CONFIG_MODE:-unknown}"
            log_info "WWAN/LTE interfaces ($NET_WWAN_COUNT): ${NET_WWAN_INTERFACES:-none}"
            [ -n "$NET_WWAN_CONTROL" ] && log_info "  Control device: $NET_WWAN_CONTROL"
        fi

        # Variables are exported by network_integration_init via export_for_setup
        return 0
    fi

    # Fallback to legacy detection
    [ "$NET_SKIP_SUMMARY" = "true" ] || log_info "Using legacy interface detection..."

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
            [ "$NET_SKIP_SUMMARY" = "true" ] || log_info "VAP-capable WiFi detected - VLAN segmentation available"
            break
        fi
    done

    # Show summary (unless NET_SKIP_SUMMARY is set)
    if [ "$NET_SKIP_SUMMARY" != "true" ]; then
        log_info "Ethernet interfaces ($ETH_COUNT): ${ETH_INTERFACES:-none}"
        log_info "WiFi interfaces ($WIFI_COUNT): ${WIFI_INTERFACES:-none}"
        log_info "WWAN/LTE interfaces ($WWAN_COUNT): ${WWAN_INTERFACES:-none}"
        [ -n "$MODEM_CTRL_DEVICES" ] && log_info "Modem control devices: $MODEM_CTRL_DEVICES"
        [ -n "$GSM_CONNECTIONS" ] && log_info "GSM connections: $GSM_CONNECTIONS"
    fi

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
    "iproute2"
    "bridge-utils"
    "iw"
    "hostapd"
    "dnsmasq"
)

# Optional packages - won't fail if unavailable
OPTIONAL_PACKAGES_APT=(
    "nftables"
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

# ============================================================
# BOOT OPTIMIZATION - Reduce network-wait timeout
# ============================================================
optimize_boot_time() {
    log_step "Optimizing boot time..."

    # systemd-networkd-wait-online.service can cause 2+ minute boot delays
    # when waiting for all interfaces (WiFi, LTE may not always connect)

    # Option 1: Reduce timeout to 10 seconds and wait for any interface
    mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d
    cat > /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf << 'EOF'
[Service]
# Fortress: Reduce boot delay from 2min to 10sec
# Only wait for any one interface to be online, not all
ExecStart=
ExecStart=/usr/lib/systemd/systemd-networkd-wait-online --any --timeout=10
EOF

    # Also configure NetworkManager's wait-online if present
    if [ -f /etc/systemd/system/NetworkManager-wait-online.service ] || \
       systemctl list-unit-files | grep -q NetworkManager-wait-online; then
        mkdir -p /etc/systemd/system/NetworkManager-wait-online.service.d
        cat > /etc/systemd/system/NetworkManager-wait-online.service.d/override.conf << 'EOF'
[Service]
# Fortress: Reduce boot delay
ExecStart=
ExecStart=/usr/bin/nm-online -s -q --timeout=10
EOF
    fi

    # Reload systemd to apply changes
    systemctl daemon-reload

    log_info "Boot optimization applied (network wait timeout: 10s)"
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
    # Using simple access mode (no VLAN tagging) for basic client connectivity
    # Clients get IPs from main bridge range (10.250.0.x)
    for iface in $lan_ifaces; do
        if ip link show "$iface" &>/dev/null; then
            # Remove any existing IP from the interface
            ip addr flush dev "$iface" 2>/dev/null || true

            # Add to OVS bridge as simple port (no VLAN tagging)
            if ! ovs-vsctl list-ports "$OVS_BRIDGE_NAME" 2>/dev/null | grep -q "^${iface}$"; then
                log_info "Adding $iface to bridge $OVS_BRIDGE_NAME..."
                ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "$iface" 2>/dev/null || {
                    log_warn "Failed to add $iface to bridge"
                    continue
                }
            else
                log_info "$iface already in bridge, updating config"
            fi

            # Clear any VLAN settings - make it a simple access port
            # This ensures untagged traffic flows to/from the bridge
            ovs-vsctl clear port "$iface" tag 2>/dev/null || true
            ovs-vsctl clear port "$iface" trunks 2>/dev/null || true
            ovs-vsctl clear port "$iface" vlan_mode 2>/dev/null || true

            # Bring interface up
            ip link set "$iface" up
            log_info "$iface added to bridge (no VLAN - direct access)"
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
# LAN ports are simple access ports on the main bridge
# Clients get DHCP from 10.250.0.100-200 range
EOF

    log_info "LAN interfaces bridged to $OVS_BRIDGE_NAME"
}

# ============================================================
# WIFI CHANNEL SCANNING AND SELECTION
# ============================================================
scan_wifi_channels() {
    local iface="$1"
    local best_channel=6  # Default fallback

    # Ensure interface is up for scanning
    ip link set "$iface" up 2>/dev/null || true
    sleep 1

    # Try to scan for networks
    local scan_result
    scan_result=$(iw dev "$iface" scan 2>/dev/null || true)

    if [ -z "$scan_result" ]; then
        # Scan failed, return default
        echo "$best_channel"
        return
    fi

    # Count networks on each non-overlapping 2.4GHz channel (1, 6, 11)
    local ch1_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 1$" 2>/dev/null || echo 0)
    local ch6_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 6$" 2>/dev/null || echo 0)
    local ch11_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 11$" 2>/dev/null || echo 0)

    # Also count adjacent channels (adds interference)
    local ch2_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 2$" 2>/dev/null || echo 0)
    local ch3_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 3$" 2>/dev/null || echo 0)
    local ch4_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 4$" 2>/dev/null || echo 0)
    local ch5_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 5$" 2>/dev/null || echo 0)
    local ch7_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 7$" 2>/dev/null || echo 0)
    local ch8_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 8$" 2>/dev/null || echo 0)
    local ch9_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 9$" 2>/dev/null || echo 0)
    local ch10_count=$(echo "$scan_result" | grep -c "DS Parameter set: channel 10$" 2>/dev/null || echo 0)

    # Calculate interference scores (includes adjacent channel interference)
    local score_1=$((ch1_count * 3 + ch2_count * 2 + ch3_count))
    local score_6=$((ch6_count * 3 + ch4_count + ch5_count * 2 + ch7_count * 2 + ch8_count))
    local score_11=$((ch11_count * 3 + ch9_count + ch10_count * 2))

    log_info "Channel scan: CH1=$ch1_count(score:$score_1) CH6=$ch6_count(score:$score_6) CH11=$ch11_count(score:$score_11)"

    # Select channel with lowest interference score
    if [ "$score_1" -le "$score_6" ] && [ "$score_1" -le "$score_11" ]; then
        best_channel=1
    elif [ "$score_11" -le "$score_6" ]; then
        best_channel=11
    else
        best_channel=6
    fi

    echo "$best_channel"
}

scan_wifi_channels_5ghz() {
    local iface="$1"
    local best_channel=36  # Default 5GHz channel

    # Ensure interface is up for scanning
    ip link set "$iface" up 2>/dev/null || true
    sleep 1

    # Try to scan for networks
    local scan_result
    scan_result=$(iw dev "$iface" scan 2>/dev/null || true)

    if [ -z "$scan_result" ]; then
        echo "$best_channel"
        return
    fi

    # Check common 5GHz channels (UNII-1 and UNII-3)
    # UNII-1: 36, 40, 44, 48 (indoor use, no DFS)
    # UNII-3: 149, 153, 157, 161, 165 (high power, no DFS)
    local channels_5g=(36 40 44 48 149 153 157 161 165)
    local min_count=999
    local min_channel=36

    for ch in "${channels_5g[@]}"; do
        local count=$(echo "$scan_result" | grep -c "DS Parameter set: channel $ch$" 2>/dev/null || echo 0)
        if [ "$count" -lt "$min_count" ]; then
            min_count=$count
            min_channel=$ch
        fi
    done

    echo "$min_channel"
}

# ============================================================
# WIFI ACCESS POINT HELPERS
# ============================================================
_create_hostapd_service() {
    # Helper function to create hostapd systemd service and scripts
    # Args: $1 - wifi_iface
    local wifi_iface="$1"

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

    # Create helper script to add WiFi to OVS bridge after hostapd starts
    cat > /usr/local/bin/fortress-wifi-bridge.sh << BRIDGEOF
#!/bin/bash
# Add WiFi interface to OVS bridge after hostapd starts
WIFI_IFACE="\$1"
OVS_BRIDGE="$OVS_BRIDGE_NAME"

sleep 1  # Wait for hostapd to fully initialize

# Remove from OVS if already exists (cleanup)
ovs-vsctl --if-exists del-port "\$OVS_BRIDGE" "\$WIFI_IFACE" 2>/dev/null || true

# Add WiFi interface to OVS bridge
if ovs-vsctl add-port "\$OVS_BRIDGE" "\$WIFI_IFACE" 2>/dev/null; then
    echo "WiFi interface \$WIFI_IFACE added to OVS bridge \$OVS_BRIDGE"
else
    echo "Warning: Could not add \$WIFI_IFACE to OVS bridge"
    exit 1
fi
BRIDGEOF
    chmod +x /usr/local/bin/fortress-wifi-bridge.sh

    # Create systemd service for hostapd with pre/post scripts
    cat > /etc/systemd/system/fortress-hostapd.service << EOF
[Unit]
Description=Fortress WiFi Access Point
After=network.target openvswitch-switch.service fortress-nat.service sys-subsystem-net-devices-${wifi_iface}.device
Wants=sys-subsystem-net-devices-${wifi_iface}.device fortress-nat.service
Requires=openvswitch-switch.service

[Service]
Type=forking
PIDFile=/run/hostapd.pid
# Small delay to ensure regulatory domain is set
ExecStartPre=/bin/sleep 2
ExecStartPre=/usr/local/bin/fortress-wifi-prepare.sh ${wifi_iface}
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd.pid /etc/hostapd/fortress.conf
# NOTE: Do NOT add WiFi interface to OVS bridge - it interferes with hostapd
# WiFi clients are bridged internally by hostapd and routed via NAT
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fortress-hostapd 2>/dev/null || true
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
    # IMPORTANT: Avoid special characters that might cause issues
    local ap_password="${FORTRESS_WIFI_PASSWORD:-$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 12)}"
    local ap_ssid="${FORTRESS_WIFI_SSID:-hookprobe}"

    # Detect country code from system settings or default to US
    local country_code="${FORTRESS_COUNTRY_CODE:-US}"
    if [ -f /etc/default/crda ]; then
        country_code=$(grep "^REGDOMAIN=" /etc/default/crda 2>/dev/null | cut -d= -f2 || echo "US")
    fi

    # Scan for best channel (least congested)
    log_info "Scanning for optimal WiFi channel..."
    local best_channel=$(scan_wifi_channels "$wifi_iface")

    # Ensure we have a valid channel (must be 1, 6, or 11 for 2.4GHz)
    # If scan failed or returned invalid, default to channel 6
    case "$best_channel" in
        1|6|11) ;;  # Valid channels
        *) best_channel=6 ;;  # Default fallback
    esac
    log_info "Selected channel: $best_channel"

    # Detect if this is a dual-band adapter
    local supports_5ghz=false
    local phy_name=$(iw dev "$wifi_iface" info 2>/dev/null | grep wiphy | awk '{print "phy"$2}')
    if iw phy "$phy_name" info 2>/dev/null | grep -q "5[0-9][0-9][0-9] MHz"; then
        supports_5ghz=true
        log_info "Dual-band WiFi adapter detected (2.4GHz + 5GHz)"
    fi

    # Kill any running wpa_supplicant on this interface
    # wpa_supplicant can interfere with hostapd
    log_info "Stopping wpa_supplicant on $wifi_iface..."
    wpa_cli -i "$wifi_iface" terminate 2>/dev/null || true
    pkill -f "wpa_supplicant.*$wifi_iface" 2>/dev/null || true

    # Disable wpa_supplicant service if it exists
    systemctl disable wpa_supplicant@"$wifi_iface" 2>/dev/null || true
    systemctl stop wpa_supplicant@"$wifi_iface" 2>/dev/null || true

    # Unblock WiFi if blocked by rfkill
    rfkill unblock wifi 2>/dev/null || true

    # Use new hostapd-generator.sh if available for dual-band WiFi 7 support
    if [ "$HOSTAPD_GENERATOR_AVAILABLE" = true ] && [ "$NETWORK_INTEGRATION_AVAILABLE" = true ]; then
        log_info "Using advanced dual-band WiFi configuration (WiFi 6/7 supported)"

        # Source the hostapd generator
        source "$DEVICES_DIR/common/hostapd-generator.sh"

        # Configure dual-band WiFi using our generator
        # This creates configs at /etc/hostapd/hostapd-24ghz.conf and hostapd-5ghz.conf
        # with auto-detected regulatory domain, WPA2 on 2.4GHz, WPA3 on 5GHz
        configure_dual_band_wifi "$ap_ssid" "$ap_password" "br-lan"
        local generator_result=$?

        if [ $generator_result -eq 0 ]; then
            # Point main fortress.conf to appropriate config based on capabilities
            mkdir -p /etc/hostapd
            if [ -f /etc/hostapd/hostapd-5ghz.conf ] && [ "$supports_5ghz" = true ]; then
                ln -sf /etc/hostapd/hostapd-5ghz.conf /etc/hostapd/fortress.conf
                log_info "Primary AP: 5GHz with WPA3/WPA2 transition mode"
            elif [ -f /etc/hostapd/hostapd-24ghz.conf ]; then
                ln -sf /etc/hostapd/hostapd-24ghz.conf /etc/hostapd/fortress.conf
                log_info "Primary AP: 2.4GHz with WPA2 (IoT compatible)"
            fi

            # Save WiFi credentials
            cat > /etc/hookprobe/wifi-ap.conf << WIFICOF
# HookProbe Fortress WiFi AP Credentials
# Generated by advanced dual-band generator
WIFI_INTERFACE=$wifi_iface
WIFI_SSID=$ap_ssid
WIFI_PASSWORD=$ap_password
WIFI_24GHZ_IFACE=${NET_WIFI_24GHZ_IFACE:-}
WIFI_5GHZ_IFACE=${NET_WIFI_5GHZ_IFACE:-}
WIFI_CONFIG_MODE=${NET_WIFI_CONFIG_MODE:-single-band}
WIFICOF
            chmod 600 /etc/hookprobe/wifi-ap.conf

            # Skip legacy config generation
            log_info "WiFi AP configured with dual-band support"
            log_info "  SSID: $ap_ssid"
            log_info "  2.4GHz: WPA2-PSK (IoT compatible)"
            log_info "  5GHz:   WPA3-SAE + WPA2 (modern devices)"

            # Create systemd service and helper scripts
            _create_hostapd_service "$wifi_iface"
            return 0
        else
            log_warn "Dual-band configuration failed, falling back to legacy config"
        fi
    fi

    # Legacy single-band hostapd configuration (fallback)
    log_info "Using legacy single-band WiFi configuration"
    mkdir -p /etc/hostapd
    cat > /etc/hostapd/fortress.conf << EOF
# HookProbe Fortress WiFi AP Configuration
# Auto-generated - modifications may be overwritten

# ============================================
# Interface Configuration
# ============================================
interface=$wifi_iface
driver=nl80211

# Control interface for hostapd_cli and debugging
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0

# ============================================
# SSID Configuration
# ============================================
ssid=$ap_ssid
utf8_ssid=1

# ============================================
# Wireless Mode
# ============================================
hw_mode=g
channel=$best_channel

# Regulatory domain - IMPORTANT for proper operation
country_code=$country_code
ieee80211d=1

# ============================================
# 802.11n Support (2.4GHz)
# ============================================
ieee80211n=1
wmm_enabled=1

# HT capabilities for 2.4GHz
# Compatible with most adapters
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]

# ============================================
# Security - WPA2-PSK with AES/CCMP
# ============================================
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=$ap_password

# Key management
wpa_group_rekey=600
wpa_ptk_rekey=600
wpa_gmk_rekey=86400

# Workaround for older devices
eapol_key_index_workaround=0

# ============================================
# Client Management
# ============================================
macaddr_acl=0
ap_isolate=0
max_num_sta=64

# ============================================
# Performance
# ============================================
beacon_int=100
dtim_period=2
ignore_broadcast_ssid=0

# ============================================
# Logging (enable for debugging)
# ============================================
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2

# NOTE: OVS bridge integration handled via ExecStartPost
# Do NOT use bridge= option with OVS bridges
EOF

    chmod 600 /etc/hostapd/fortress.conf

    # Point hostapd to our config
    if [ -f /etc/default/hostapd ]; then
        sed -i 's|^#*DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/fortress.conf"|' /etc/default/hostapd
    fi

    # Create systemd service and helper scripts using shared function
    _create_hostapd_service "$wifi_iface"

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

    # Get the WiFi interface from detection
    local wifi_iface=""
    for iface in $WIFI_INTERFACES; do
        wifi_iface="$iface"
        break
    done

    # Remove any old conflicting configs
    rm -f /etc/dnsmasq.d/fortress.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fortress-bridge.conf 2>/dev/null || true

    # Create dnsmasq configuration for Fortress with VLAN support
    mkdir -p /etc/dnsmasq.d
    cat > /etc/dnsmasq.d/fortress-vlans.conf << EOF
# HookProbe Fortress VLAN DHCP Configuration
# Generated: $(date -Iseconds)
#
# Provides DHCP on all VLAN interfaces for proper network segmentation

# Global settings
domain-needed
bogus-priv
no-resolv
no-poll

# Upstream DNS servers
server=1.1.1.1
server=8.8.8.8

# Local domain
domain=fortress.local
local=/fortress.local/
expand-hosts

# Local hostname resolution
address=/fortress.local/10.250.0.1
address=/fortress/10.250.0.1

# Logging
log-queries
log-dhcp
log-facility=/var/log/fortress-dnsmasq.log

# Lease file
dhcp-leasefile=/var/lib/misc/fortress-dnsmasq.leases

# DHCP authoritative mode
dhcp-authoritative
dhcp-rapid-commit

# ─────────────────────────────────────────────────────────────
# VLAN Interfaces - Each VLAN has its own DHCP range
# ─────────────────────────────────────────────────────────────

# VLAN 10 - Management (10.250.10.x)
interface=vlan10
dhcp-range=vlan10,10.250.10.100,10.250.10.200,255.255.255.0,12h
dhcp-option=vlan10,3,10.250.10.1
dhcp-option=vlan10,6,10.250.10.1,1.1.1.1

# VLAN 20 - Trusted/Staff (10.250.20.x)
interface=vlan20
dhcp-range=vlan20,10.250.20.100,10.250.20.200,255.255.255.0,12h
dhcp-option=vlan20,3,10.250.20.1
dhcp-option=vlan20,6,10.250.20.1,1.1.1.1

# VLAN 30 - IoT Devices (10.250.30.x)
interface=vlan30
dhcp-range=vlan30,10.250.30.100,10.250.30.200,255.255.255.0,12h
dhcp-option=vlan30,3,10.250.30.1
dhcp-option=vlan30,6,10.250.30.1,1.1.1.1

# VLAN 40 - Guest Network (10.250.40.x)
interface=vlan40
dhcp-range=vlan40,10.250.40.100,10.250.40.200,255.255.255.0,12h
dhcp-option=vlan40,3,10.250.40.1
dhcp-option=vlan40,6,10.250.40.1,1.1.1.1

# VLAN 99 - Quarantine (10.250.99.x)
interface=vlan99
dhcp-range=vlan99,10.250.99.100,10.250.99.200,255.255.255.0,12h
dhcp-option=vlan99,3,10.250.99.1
dhcp-option=vlan99,6,10.250.99.1,1.1.1.1

# ─────────────────────────────────────────────────────────────
# Main Bridge - For untagged/default traffic (10.250.0.x)
# ─────────────────────────────────────────────────────────────
interface=$OVS_BRIDGE_NAME
dhcp-range=$OVS_BRIDGE_NAME,10.250.0.100,10.250.0.200,255.255.0.0,24h
dhcp-option=$OVS_BRIDGE_NAME,3,10.250.0.1
dhcp-option=$OVS_BRIDGE_NAME,6,10.250.0.1,1.1.1.1

# ─────────────────────────────────────────────────────────────
# WiFi Interface - Handled via OVS Bridge
# ─────────────────────────────────────────────────────────────
# Note: WiFi interface is added to OVS bridge by hostapd service
# (via ExecStartPost in fortress-hostapd-*.service)
# WiFi clients receive DHCP from the bridge interface above
# No separate WiFi DHCP configuration needed

# Bind only to specified interfaces
bind-interfaces
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
After=network.target fortress-nat.service fortress-hostapd.service
Wants=network.target fortress-nat.service

[Service]
Type=forking
PIDFile=/run/fortress-dnsmasq.pid
ExecStartPre=/usr/sbin/dnsmasq --test -C /etc/dnsmasq.d/fortress-vlans.conf
ExecStart=/usr/sbin/dnsmasq -C /etc/dnsmasq.d/fortress-vlans.conf --pid-file=/run/fortress-dnsmasq.pid
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fortress-dnsmasq 2>/dev/null || true

    log_info "DHCP server configured for VLAN segmentation:"
    log_info "  VLAN 10 (Management): 10.250.10.100-200"
    log_info "  VLAN 20 (Trusted):    10.250.20.100-200"
    log_info "  VLAN 30 (IoT):        10.250.30.100-200"
    log_info "  VLAN 40 (Guest):      10.250.40.100-200"
    log_info "  VLAN 99 (Quarantine): 10.250.99.100-200"
    log_info "  Bridge (default):     10.250.0.100-200"
}

# ============================================================
# START NETWORK SERVICES
# ============================================================
start_network_services() {
    log_step "Starting network services..."

    # Start hostapd (WiFi AP) FIRST - creates the WiFi interface
    # Check for band-specific services first (created by hostapd-generator)
    local wifi_started=false

    if [ -f /etc/systemd/system/fortress-hostapd-24ghz.service ]; then
        log_info "Starting 2.4GHz WiFi AP..."
        systemctl start fortress-hostapd-24ghz 2>/dev/null || log_warn "Failed to start 2.4GHz hostapd"
        wifi_started=true
    fi

    if [ -f /etc/systemd/system/fortress-hostapd-5ghz.service ]; then
        log_info "Starting 5GHz WiFi AP..."
        # 5GHz with DFS channels may take 60+ seconds for radar detection
        # Start in background and continue
        systemctl start fortress-hostapd-5ghz 2>/dev/null || log_warn "Failed to start 5GHz hostapd"
        wifi_started=true
    fi

    # Fallback to generic service if band-specific don't exist
    if [ "$wifi_started" = false ] && [ -f /etc/systemd/system/fortress-hostapd.service ]; then
        log_info "Starting WiFi AP (legacy)..."
        systemctl start fortress-hostapd 2>/dev/null || log_warn "Failed to start hostapd"
    fi

    # Give hostapd time to initialize the interface
    sleep 3

    # Start NAT routing AFTER hostapd - needs WiFi interface to exist
    # This assigns IPs to bridge AND WiFi interface
    if [ -f /etc/systemd/system/fortress-nat.service ]; then
        log_info "Starting NAT routing..."
        systemctl restart fortress-nat 2>/dev/null || log_warn "Failed to start NAT"
        sleep 1
    fi

    # Start dnsmasq (DHCP/DNS) LAST - needs interfaces with IPs
    if [ -f /etc/systemd/system/fortress-dnsmasq.service ]; then
        log_info "Starting DHCP server..."
        systemctl restart fortress-dnsmasq 2>/dev/null || log_warn "Failed to start dnsmasq"
    fi

    # Verify services
    sleep 2
    if systemctl is-active fortress-nat &>/dev/null; then
        log_info "✓ NAT routing active"
    else
        log_warn "✗ NAT routing not active"
    fi

    # Check WiFi AP status
    local wifi_active=false
    if systemctl is-active fortress-hostapd-24ghz &>/dev/null; then
        log_info "✓ 2.4GHz WiFi AP running"
        wifi_active=true
    fi
    if systemctl is-active fortress-hostapd-5ghz &>/dev/null; then
        log_info "✓ 5GHz WiFi AP running"
        wifi_active=true
    elif [ -f /etc/systemd/system/fortress-hostapd-5ghz.service ]; then
        # 5GHz may still be in DFS radar detection period (60s)
        log_info "⏳ 5GHz WiFi AP starting (DFS radar detection may take 60s)"
    fi
    if [ "$wifi_active" = false ]; then
        if systemctl is-active fortress-hostapd &>/dev/null; then
            log_info "✓ WiFi AP running"
        else
            log_warn "✗ WiFi AP not running (may need WiFi interface)"
        fi
    fi

    if systemctl is-active fortress-dnsmasq &>/dev/null; then
        log_info "✓ DHCP server running"
    else
        log_warn "✗ DHCP server not running"
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
# Configures bridge IP, NAT, and regulatory domain

set -e

BRIDGE="fortress"
BRIDGE_IP="10.250.0.1"
BRIDGE_SUBNET="16"
# WiFi clients get Guest VLAN IPs (10.250.40.x) via DHCP
# WiFi interface must be the gateway for that subnet
WIFI_IP="10.250.40.1"
WIFI_SUBNET="24"

# ============================================================
# BRIDGE IP CONFIGURATION
# ============================================================
# Ensure bridge exists and has IP address
if ip link show "$BRIDGE" &>/dev/null; then
    # Check if bridge already has IP
    if ! ip addr show "$BRIDGE" | grep -q "$BRIDGE_IP"; then
        ip addr add ${BRIDGE_IP}/${BRIDGE_SUBNET} dev "$BRIDGE" 2>/dev/null || true
        echo "Bridge IP configured: ${BRIDGE_IP}/${BRIDGE_SUBNET}"
    fi
    # Ensure bridge is up
    ip link set "$BRIDGE" up 2>/dev/null || true
else
    echo "WARNING: Bridge $BRIDGE does not exist"
fi

# ============================================================
# WIFI INTERFACE IP CONFIGURATION
# ============================================================
# Note: When WiFi interface is added to OVS bridge (via hostapd ExecStartPost),
# it becomes a bridge port and should NOT have its own IP address.
# Clients get DHCP from the bridge interface instead.
#
# Only assign WiFi IP if NOT using OVS bridge mode (legacy standalone mode)

WIFI_IFACE=""
if [ -f /etc/hostapd/fortress.conf ]; then
    WIFI_IFACE=$(grep "^interface=" /etc/hostapd/fortress.conf | cut -d= -f2)
fi
if [ -z "$WIFI_IFACE" ]; then
    # Check 2.4GHz and 5GHz configs
    for conf in /etc/hostapd/hostapd-24ghz.conf /etc/hostapd/hostapd-5ghz.conf; do
        if [ -f "$conf" ]; then
            WIFI_IFACE=$(grep "^interface=" "$conf" | cut -d= -f2)
            [ -n "$WIFI_IFACE" ] && break
        fi
    done
fi
if [ -z "$WIFI_IFACE" ]; then
    for iface in /sys/class/net/wl*; do
        [ -e "$iface" ] && WIFI_IFACE=$(basename "$iface") && break
    done
fi

if [ -n "$WIFI_IFACE" ] && ip link show "$WIFI_IFACE" &>/dev/null; then
    echo "Found WiFi interface: $WIFI_IFACE"

    # Check if WiFi is part of OVS bridge (no IP needed - bridge handles routing)
    if command -v ovs-vsctl &>/dev/null && \
       ovs-vsctl br-exists "$BRIDGE" 2>/dev/null && \
       ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -q "^${WIFI_IFACE}$"; then
        echo "WiFi interface $WIFI_IFACE is part of OVS bridge $BRIDGE"
        echo "  Clients will get DHCP from bridge (gateway: $BRIDGE_IP)"
        echo "  No separate WiFi IP needed"
    else
        # Legacy mode: WiFi not in bridge, needs own IP for DHCP
        echo "Configuring WiFi interface IP (standalone mode): $WIFI_IFACE"
        if ! ip addr show "$WIFI_IFACE" | grep -q "$WIFI_IP"; then
            ip addr add ${WIFI_IP}/${WIFI_SUBNET} dev "$WIFI_IFACE" 2>/dev/null || true
            echo "WiFi interface IP configured: ${WIFI_IP}/${WIFI_SUBNET}"
        fi
    fi
else
    echo "No WiFi interface found"
fi

# ============================================================
# WAIT FOR INTERNET CONNECTIVITY
# ============================================================
wait_for_internet() {
    local max_attempts=30
    local attempt=0
    echo "Waiting for internet connectivity..."

    while [ $attempt -lt $max_attempts ]; do
        # Try to reach a reliable endpoint
        if curl -sf --max-time 3 "http://connectivitycheck.gstatic.com/generate_204" &>/dev/null || \
           ping -c 1 -W 2 8.8.8.8 &>/dev/null || \
           ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
            echo "Internet connectivity confirmed"
            return 0
        fi
        attempt=$((attempt + 1))
        echo "Waiting for internet... (attempt $attempt/$max_attempts)"
        sleep 2
    done

    echo "WARNING: Internet connectivity check failed after $max_attempts attempts"
    return 1
}

# ============================================================
# COUNTRY CODE DETECTION (for WiFi regulatory domain)
# ============================================================
detect_country_code() {
    local country=""
    local max_retries=3
    local retry=0

    while [ $retry -lt $max_retries ] && [ -z "$country" ]; do
        # Method 1: ipinfo.io (most reliable)
        country=$(curl -sf --max-time 5 "https://ipinfo.io/country" 2>/dev/null | tr -d '\n\r ' | grep -E '^[A-Z]{2}$' || true)

        # Method 2: ip-api.com (fallback)
        if [ -z "$country" ]; then
            country=$(curl -sf --max-time 5 "http://ip-api.com/line/?fields=countryCode" 2>/dev/null | tr -d '\n\r ' | grep -E '^[A-Z]{2}$' || true)
        fi

        # Method 3: ifconfig.co (another fallback)
        if [ -z "$country" ]; then
            country=$(curl -sf --max-time 5 "https://ifconfig.co/country-iso" 2>/dev/null | tr -d '\n\r ' | grep -E '^[A-Z]{2}$' || true)
        fi

        if [ -z "$country" ]; then
            retry=$((retry + 1))
            [ $retry -lt $max_retries ] && sleep 2
        fi
    done

    # Default to US if detection fails
    echo "${country:-US}"
}

# Wait for internet before detecting country
wait_for_internet

# Set WiFi regulatory domain based on geolocation
COUNTRY=$(detect_country_code)
echo "Detected country code: $COUNTRY"

# Set regulatory domain
if command -v iw &>/dev/null; then
    iw reg set "$COUNTRY" 2>/dev/null || true
    echo "WiFi regulatory domain set to: $COUNTRY"

    # Save to CRDA config for persistence
    echo "REGDOMAIN=$COUNTRY" > /etc/default/crda 2>/dev/null || true

    # Also update hostapd config if it exists
    if [ -f /etc/hostapd/fortress.conf ]; then
        sed -i "s/^country_code=.*/country_code=$COUNTRY/" /etc/hostapd/fortress.conf 2>/dev/null || true
        echo "Updated hostapd config with country_code=$COUNTRY"
    fi
fi

# ============================================================
# IP FORWARDING
# ============================================================
echo 1 > /proc/sys/net/ipv4/ip_forward

# Make persistent
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

# ============================================================
# WAN DETECTION
# ============================================================
WAN=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
if [ -z "$WAN" ]; then
    WAN=$(ip -o link show | awk -F': ' '!/lo|fortress|vlan|br-/ {print $2}' | head -1)
fi

[ -z "$WAN" ] && { echo "No WAN interface found"; exit 1; }
echo "WAN interface: $WAN"

# ============================================================
# NAT RULES
# ============================================================
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

# ============================================================
# WIFI FORWARDING RULES
# ============================================================
if [ -n "$WIFI_IFACE" ]; then
    echo "Setting up WiFi forwarding for $WIFI_IFACE"

    # WiFi to WAN forwarding
    if ! iptables -C FORWARD -i "$WIFI_IFACE" -o "$WAN" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$WIFI_IFACE" -o "$WAN" -j ACCEPT
    fi

    # WAN to WiFi established connections
    if ! iptables -C FORWARD -i "$WAN" -o "$WIFI_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$WAN" -o "$WIFI_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi

    # WiFi to bridge (for local network access)
    if ! iptables -C FORWARD -i "$WIFI_IFACE" -o "$BRIDGE" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$WIFI_IFACE" -o "$BRIDGE" -j ACCEPT
    fi

    # Bridge to WiFi
    if ! iptables -C FORWARD -i "$BRIDGE" -o "$WIFI_IFACE" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$BRIDGE" -o "$WIFI_IFACE" -j ACCEPT
    fi

    # Allow DHCP on WiFi interface
    if ! iptables -C INPUT -i "$WIFI_IFACE" -p udp --dport 67 -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -i "$WIFI_IFACE" -p udp --dport 67 -j ACCEPT
    fi

    echo "WiFi forwarding configured for $WIFI_IFACE"
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
# FREERADIUS WITH VLAN ASSIGNMENT (OUI-BASED)
# ============================================================
configure_freeradius_vlan() {
    log_step "Configuring FreeRADIUS for VLAN assignment..."

    local RADIUS_SECRET="${HOOKPROBE_RADIUS_SECRET:-hookprobe_fortress}"
    local VLAN_SCRIPT="$SCRIPT_DIR/devices/common/vlan-assignment.sh"

    mkdir -p /etc/fortress
    mkdir -p /var/lib/fortress
    chmod 755 /etc/fortress

    # Install the vlan-assignment script to system path
    if [ -f "$VLAN_SCRIPT" ]; then
        cp "$VLAN_SCRIPT" /usr/local/bin/fortress-vlan
        chmod +x /usr/local/bin/fortress-vlan
        log_info "Installed vlan-assignment script to /usr/local/bin/fortress-vlan"
    fi

    # Initialize VLAN assignment system with OUI rules
    if [ -f /usr/local/bin/fortress-vlan ]; then
        log_info "Initializing OUI-based VLAN assignment..."
        /usr/local/bin/fortress-vlan init
    else
        # Fallback: Create basic MAC-to-VLAN database
        cat > /etc/fortress/mac_vlan.json << 'MACVLANEOF'
{
  "version": "1.0",
  "description": "HookProbe Fortress - MAC to VLAN Assignment",
  "default_vlan": 40,
  "vlans": {
    "10": {"name": "management", "description": "Admin/Network devices"},
    "20": {"name": "pos", "description": "Payment terminals"},
    "30": {"name": "staff", "description": "Employee devices"},
    "40": {"name": "guest", "description": "Guest/Unknown devices"},
    "99": {"name": "iot", "description": "IoT/Cameras/Sensors"}
  },
  "devices": {}
}
MACVLANEOF
        chmod 644 /etc/fortress/mac_vlan.json

        # Fallback: Basic FreeRADIUS config
        if [ -d /etc/freeradius/3.0/mods-config/files ]; then
            cat > /etc/freeradius/3.0/mods-config/files/authorize << 'USERSEOF'
# HookProbe Fortress - MAC Authentication with VLAN Assignment
# For OUI-based auto-assignment, run: fortress-vlan init

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
    fi

    # Configure FreeRADIUS clients.conf for hostapd
    if [ -d /etc/freeradius/3.0 ]; then
        # Add hostapd as a RADIUS client if not already configured
        if ! grep -q "hookprobe-hostapd" /etc/freeradius/3.0/clients.conf 2>/dev/null; then
            cat >> /etc/freeradius/3.0/clients.conf << CLIENTSEOF

# HookProbe Fortress - hostapd RADIUS client
client hookprobe-hostapd {
    ipaddr = 127.0.0.1
    secret = $RADIUS_SECRET
    require_message_authenticator = no
    nas_type = other
}
CLIENTSEOF
            log_info "Added hostapd RADIUS client configuration"
        fi
    fi

    # Enable and start FreeRADIUS
    systemctl enable freeradius 2>/dev/null || true
    systemctl restart freeradius 2>/dev/null || true

    log_info "FreeRADIUS configured for OUI-based VLAN assignment"
    log_info "  OUI rules: /etc/fortress/oui_vlan_rules.conf"
    log_info "  MAC database: /etc/fortress/mac_vlan.json"
    log_info "  Management: fortress-vlan add-device MAC VLAN NAME"
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

    # Create directories with proper permissions
    mkdir -p /opt/hookprobe/fortress/monitoring
    mkdir -p /opt/hookprobe/fortress/grafana
    mkdir -p /opt/hookprobe/fortress/postgres

    # CRITICAL: Fix Grafana permissions (runs as UID 472)
    chown -R 472:472 /opt/hookprobe/fortress/grafana

    # Generate Grafana admin password
    local GRAFANA_PASS="${GRAFANA_ADMIN_PASSWORD:-$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)}"

    # Save Grafana credentials
    cat > /etc/hookprobe/secrets/grafana.conf << GRAFANAEOF
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=$GRAFANA_PASS
GRAFANA_URL=http://localhost:3000
GRAFANAEOF
    chmod 600 /etc/hookprobe/secrets/grafana.conf

    # Stop existing containers if running (for clean restart)
    podman stop fortress-victoria fortress-grafana 2>/dev/null || true
    podman rm fortress-victoria fortress-grafana 2>/dev/null || true

    # Victoria Metrics container (time-series database)
    log_info "Starting Victoria Metrics..."
    podman run -d \
        --name fortress-victoria \
        --restart unless-stopped \
        -p 8428:8428 \
        -v /opt/hookprobe/fortress/monitoring:/victoria-metrics-data:Z \
        docker.io/victoriametrics/victoria-metrics:latest \
        2>/dev/null && log_info "✓ Victoria Metrics started" || log_warn "Victoria Metrics may already be running"

    # Grafana container (dashboards)
    log_info "Starting Grafana..."
    podman run -d \
        --name fortress-grafana \
        --restart unless-stopped \
        -p 3000:3000 \
        -v /opt/hookprobe/fortress/grafana:/var/lib/grafana:Z \
        -e GF_SECURITY_ADMIN_USER=admin \
        -e GF_SECURITY_ADMIN_PASSWORD="$GRAFANA_PASS" \
        -e GF_USERS_ALLOW_SIGN_UP=false \
        -e GF_SERVER_ROOT_URL=http://localhost:3000 \
        docker.io/grafana/grafana:latest \
        2>/dev/null && log_info "✓ Grafana started" || log_warn "Grafana may already be running"

    # Wait for containers to start
    sleep 3

    # Verify containers are running
    if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fortress-grafana"; then
        log_info "✓ Grafana container verified running"
    else
        log_warn "Grafana container not running - checking logs..."
        podman logs fortress-grafana 2>&1 | tail -5 || true
    fi

    log_info "Monitoring stack installed"
    log_info "  Victoria Metrics: http://localhost:8428"
    log_info "  Grafana: http://localhost:3000 (admin/$GRAFANA_PASS)"

    # Install security monitoring (Suricata, Zeek, ML)
    install_security_monitoring
}

# ============================================================
# SECURITY MONITORING (Suricata, Zeek, ML/LSTM)
# ============================================================
install_security_monitoring() {
    log_step "Installing security monitoring stack..."

    # Create directories for security monitoring
    mkdir -p /opt/hookprobe/fortress/data/{suricata-logs,suricata-rules}
    mkdir -p /opt/hookprobe/fortress/data/{zeek-logs,zeek-spool}
    mkdir -p /opt/hookprobe/fortress/data/{ml-models,threat-intel}
    mkdir -p /opt/hookprobe/fortress/zeek
    mkdir -p /var/log/hookprobe

    # Determine interface to monitor
    local MONITOR_IFACE=""
    if [ -e /sys/class/net/eth0 ]; then
        MONITOR_IFACE="eth0"
    elif [ -e /sys/class/net/br0 ]; then
        MONITOR_IFACE="br0"
    elif [ -e /sys/class/net/fortress ]; then
        MONITOR_IFACE="fortress"
    else
        MONITOR_IFACE="any"
    fi
    log_info "Security monitoring interface: $MONITOR_IFACE"

    # Pull container images
    log_info "Pulling security monitoring images..."
    podman pull docker.io/jasonish/suricata:latest 2>/dev/null || log_warn "Failed to pull Suricata image"
    podman pull docker.io/zeek/zeek:latest 2>/dev/null || log_warn "Failed to pull Zeek image"

    # Stop existing containers
    podman stop fortress-suricata fortress-zeek 2>/dev/null || true
    podman rm fortress-suricata fortress-zeek 2>/dev/null || true

    # Start Suricata IDS container
    log_info "Starting Suricata IDS..."
    podman run -d \
        --name fortress-suricata \
        --network host \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --cap-add SYS_NICE \
        --restart unless-stopped \
        -v /opt/hookprobe/fortress/data/suricata-logs:/var/log/suricata:Z \
        -v /opt/hookprobe/fortress/data/suricata-rules:/var/lib/suricata:Z \
        docker.io/jasonish/suricata:latest \
        -i "$MONITOR_IFACE" \
        2>/dev/null && log_info "✓ Suricata started" || log_warn "Suricata may already be running"

    # Create Zeek configuration
    cat > /opt/hookprobe/fortress/zeek/local.zeek << 'ZEEKEOF'
# Fortress Zeek Configuration - Threat Pattern Analysis
# Focus: HOW users are targeted, NOT what they browse

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load policy/misc/detect-traceroute
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services

# Custom threat pattern detection
redef Notice::policy += {
    [$action = Notice::ACTION_LOG,
     $pred(n: Notice::Info) = {
        return n$note in set(
            Scan::Port_Scan,
            Scan::Address_Scan,
            SSL::Invalid_Server_Cert,
            DNS::External_Name
        );
     }]
};
ZEEKEOF

    # Start Zeek Network Analyzer
    log_info "Starting Zeek Network Analyzer..."
    podman run -d \
        --name fortress-zeek \
        --network host \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --restart unless-stopped \
        --memory 512m \
        -v /opt/hookprobe/fortress/data/zeek-logs:/usr/local/zeek/logs:Z \
        -v /opt/hookprobe/fortress/data/zeek-spool:/usr/local/zeek/spool:Z \
        -v /opt/hookprobe/fortress/zeek/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek:ro \
        docker.io/zeek/zeek:latest \
        zeek -i "$MONITOR_IFACE" local \
        2>/dev/null && log_info "✓ Zeek started" || log_warn "Zeek may already be running"

    # Install ML/LSTM components
    install_ml_components

    # Setup dnsXai privacy controls
    setup_dnsxai_privacy_controls

    log_info "Security monitoring stack installed"
    log_info "  Suricata: monitoring $MONITOR_IFACE for threats"
    log_info "  Zeek: analyzing network patterns"
    log_info "  ML/LSTM: daily training at 3:00 AM"
}

# ============================================================
# ML/LSTM THREAT DETECTION COMPONENTS
# ============================================================
install_ml_components() {
    log_step "Installing ML/LSTM threat detection..."

    # Copy LSTM module to installation directory
    mkdir -p /opt/hookprobe/fortress/lib
    if [ -f "$FORTRESS_ROOT/lib/lstm_threat_detector.py" ]; then
        cp "$FORTRESS_ROOT/lib/lstm_threat_detector.py" /opt/hookprobe/fortress/lib/
        chmod +x /opt/hookprobe/fortress/lib/lstm_threat_detector.py
    fi

    # Create ML aggregator service
    cat > /etc/systemd/system/fortress-ml-aggregator.service << 'EOF'
[Unit]
Description=Fortress ML Threat Aggregator
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=30
ExecStart=/usr/bin/python3 /opt/hookprobe/fortress/containers/../../ml/threat_aggregator.py 2>/dev/null || /bin/true
StandardOutput=append:/var/log/hookprobe/ml-aggregator.log
StandardError=append:/var/log/hookprobe/ml-aggregator.log

[Install]
WantedBy=multi-user.target
EOF

    # Create LSTM daily training service
    cat > /etc/systemd/system/fortress-lstm-train.service << 'EOF'
[Unit]
Description=Fortress LSTM Threat Model Training
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/hookprobe/fortress/lib/lstm_threat_detector.py --train --epochs 100
StandardOutput=append:/var/log/hookprobe/lstm-training.log
StandardError=append:/var/log/hookprobe/lstm-training.log
EOF

    # Create daily training timer (runs at 3am)
    cat > /etc/systemd/system/fortress-lstm-train.timer << 'EOF'
[Unit]
Description=Daily LSTM Threat Model Training (3:00 AM)

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=600

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable fortress-lstm-train.timer 2>/dev/null || true

    log_info "ML/LSTM components installed (daily training at 3:00 AM)"
}

# ============================================================
# DNSXAI PRIVACY CONTROLS
# ============================================================
setup_dnsxai_privacy_controls() {
    log_step "Setting up dnsXai privacy controls..."

    mkdir -p /etc/hookprobe/dnsxai

    # Create default privacy configuration (privacy-first defaults)
    cat > /etc/hookprobe/dnsxai/privacy.json << 'PRIVEOF'
{
    "version": "1.0",
    "description": "dnsXai Privacy Settings - Controls what data is collected",
    "settings": {
        "enable_query_logging": false,
        "enable_domain_tracking": false,
        "enable_ad_blocking_stats": true,
        "enable_threat_detection": true,
        "enable_ml_training_data": false,
        "anonymize_client_ips": true,
        "retention_days": 7,
        "export_allowed": false
    },
    "explanation": {
        "enable_query_logging": "Log individual DNS queries (PRIVACY IMPACT: HIGH). Disabled by default.",
        "enable_domain_tracking": "Track domain visit frequency per client (PRIVACY IMPACT: HIGH). Disabled by default.",
        "enable_ad_blocking_stats": "Count blocked ads/trackers (PRIVACY IMPACT: LOW). Enabled for statistics.",
        "enable_threat_detection": "Detect malicious domains (PRIVACY IMPACT: LOW). Essential for security.",
        "enable_ml_training_data": "Use anonymized query patterns for ML (PRIVACY IMPACT: MEDIUM). Disabled by default.",
        "anonymize_client_ips": "Replace client IPs with hashes (PRIVACY IMPACT: NONE). Always recommended.",
        "retention_days": "Days to keep logs before deletion. Shorter = more privacy.",
        "export_allowed": "Allow exporting DNS data. Disabled by default."
    }
}
PRIVEOF

    chmod 644 /etc/hookprobe/dnsxai/privacy.json

    # Create privacy management CLI tool
    cat > /usr/local/bin/fortress-dnsxai-privacy << 'PRIVSCRIPT'
#!/bin/bash
# Fortress dnsXai Privacy Control Tool
# Manages privacy settings for DNS query tracking

PRIVACY_FILE="/etc/hookprobe/dnsxai/privacy.json"

show_status() {
    echo "=== dnsXai Privacy Settings ==="
    echo ""
    if [ -f "$PRIVACY_FILE" ]; then
        python3 -c "
import json
with open('$PRIVACY_FILE') as f:
    data = json.load(f)
    settings = data.get('settings', {})
    for key, value in settings.items():
        status = '✓ Enabled' if value is True else ('✗ Disabled' if value is False else str(value))
        print(f'  {key}: {status}')
"
    else
        echo "Privacy file not found!"
    fi
}

set_setting() {
    local setting="$1"
    local value="$2"
    python3 -c "
import json, sys
with open('$PRIVACY_FILE', 'r') as f: data = json.load(f)
val = True if '$value'.lower() in ('true','yes','1') else (False if '$value'.lower() in ('false','no','0') else int('$value') if '$value'.isdigit() else None)
if val is None: print('Invalid value'); sys.exit(1)
data['settings']['$setting'] = val
with open('$PRIVACY_FILE', 'w') as f: json.dump(data, f, indent=2)
print('Set $setting = ' + str(val))
"
}

case "\${1:-status}" in
    status) show_status ;;
    set) set_setting "\$2" "\$3" ;;
    max*) python3 -c "import json; f=open('$PRIVACY_FILE'); d=json.load(f); f.close(); d['settings']={'enable_query_logging':False,'enable_domain_tracking':False,'enable_ad_blocking_stats':False,'enable_threat_detection':True,'enable_ml_training_data':False,'anonymize_client_ips':True,'retention_days':1,'export_allowed':False}; f=open('$PRIVACY_FILE','w'); json.dump(d,f,indent=2); f.close(); print('Maximum privacy enabled')" ;;
    *) echo "Usage: \$0 {status|set <key> <value>|maximum}" ;;
esac
PRIVSCRIPT

    chmod +x /usr/local/bin/fortress-dnsxai-privacy

    log_info "dnsXai privacy controls installed"
    log_info "  Use 'fortress-dnsxai-privacy status' to view settings"
    log_info "  Use 'fortress-dnsxai-privacy maximum' for maximum privacy"
}

# ============================================================
# DATABASE STACK (PostgreSQL)
# ============================================================
install_database() {
    log_step "Installing database stack..."

    # Create directories
    mkdir -p /opt/hookprobe/fortress/postgres/data
    mkdir -p /opt/hookprobe/fortress/postgres/init

    # Generate PostgreSQL credentials
    local PG_PASS="${POSTGRES_PASSWORD:-$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)}"

    # Save PostgreSQL credentials
    cat > /etc/hookprobe/secrets/postgres.conf << PGEOF
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=fortress
POSTGRES_USER=fortress
POSTGRES_PASSWORD=$PG_PASS
DATABASE_URL=postgresql://fortress:$PG_PASS@localhost:5432/fortress
PGEOF
    chmod 600 /etc/hookprobe/secrets/postgres.conf

    # Create init script for database schema
    cat > /opt/hookprobe/fortress/postgres/init/01-init.sql << 'SQLEOF'
-- HookProbe Fortress Database Schema

-- Device tracking
CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    mac_address VARCHAR(17) UNIQUE NOT NULL,
    hostname VARCHAR(255),
    ip_address VARCHAR(45),
    vlan_id INTEGER DEFAULT 40,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    device_type VARCHAR(100),
    manufacturer VARCHAR(255),
    is_blocked BOOLEAN DEFAULT FALSE,
    notes TEXT
);

-- Threat events
CREATE TABLE IF NOT EXISTS threats (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45),
    source_mac VARCHAR(17),
    threat_type VARCHAR(100),
    severity VARCHAR(20),
    layer INTEGER,
    description TEXT,
    mitre_id VARCHAR(20),
    blocked BOOLEAN DEFAULT FALSE
);

-- QSecBit history
CREATE TABLE IF NOT EXISTS qsecbit_history (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    score FLOAT,
    status VARCHAR(10),
    l2_score FLOAT,
    l3_score FLOAT,
    l4_score FLOAT,
    l5_score FLOAT,
    l7_score FLOAT
);

-- DNS query logs
CREATE TABLE IF NOT EXISTS dns_queries (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    client_ip VARCHAR(45),
    domain VARCHAR(255),
    query_type VARCHAR(10),
    action VARCHAR(20),
    category VARCHAR(100),
    response_time_ms INTEGER
);

-- User audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(100),
    action VARCHAR(100),
    resource VARCHAR(255),
    details JSONB,
    ip_address VARCHAR(45)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_vlan ON devices(vlan_id);
CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
CREATE INDEX IF NOT EXISTS idx_qsecbit_timestamp ON qsecbit_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_queries(timestamp);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries(domain);
SQLEOF

    # Stop existing container if running
    podman stop fortress-postgres 2>/dev/null || true
    podman rm fortress-postgres 2>/dev/null || true

    # Start PostgreSQL container
    log_info "Starting PostgreSQL..."
    podman run -d \
        --name fortress-postgres \
        --restart unless-stopped \
        -p 5432:5432 \
        -v /opt/hookprobe/fortress/postgres/data:/var/lib/postgresql/data:Z \
        -v /opt/hookprobe/fortress/postgres/init:/docker-entrypoint-initdb.d:Z \
        -e POSTGRES_DB=fortress \
        -e POSTGRES_USER=fortress \
        -e POSTGRES_PASSWORD="$PG_PASS" \
        docker.io/postgres:15-alpine \
        2>/dev/null && log_info "✓ PostgreSQL started" || log_warn "PostgreSQL may already be running"

    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to be ready..."
    local retries=0
    while [ $retries -lt 30 ]; do
        if podman exec fortress-postgres pg_isready -U fortress &>/dev/null; then
            log_info "✓ PostgreSQL is ready"
            break
        fi
        sleep 1
        retries=$((retries + 1))
    done

    if [ $retries -ge 30 ]; then
        log_warn "PostgreSQL may not be fully ready yet"
    fi

    log_info "Database stack installed"
    log_info "  PostgreSQL: localhost:5432 (fortress/***)"
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
# WIFI CHANNEL OPTIMIZATION SERVICE (4am daily)
# ============================================================
install_channel_optimization_service() {
    log_step "Installing WiFi Channel Optimization service..."

    # Create the channel optimization script
    cat > /usr/local/bin/fortress-channel-optimize.sh << 'CHANNEL_SCRIPT'
#!/bin/bash
# Fortress WiFi Channel Optimization
# Automatically selects the best WiFi channel based on RF environment
# Runs at boot and daily at 4:00 AM

set -e

LOG_FILE="/var/log/hookprobe/channel-optimization.log"
STATE_FILE="/var/lib/fortress/channel_state.json"
HOSTAPD_CONF="/etc/hostapd/fortress.conf"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "$1"
}

# Ensure log directory exists
mkdir -p /var/log/hookprobe
mkdir -p /var/lib/fortress

# Find WiFi interface from hostapd config
AP_INTERFACE=$(grep "^interface=" "$HOSTAPD_CONF" 2>/dev/null | cut -d= -f2 || echo "")

if [ -z "$AP_INTERFACE" ] || [ ! -e "/sys/class/net/$AP_INTERFACE" ]; then
    log "ERROR: No WiFi interface found in hostapd config"
    exit 1
fi

log "Starting WiFi channel optimization on $AP_INTERFACE..."

# Get current channel from hostapd config
CURRENT_CHANNEL=$(grep "^channel=" "$HOSTAPD_CONF" 2>/dev/null | cut -d= -f2 || echo "6")
log "Current channel: $CURRENT_CHANNEL"

# Check if AP is running - if so, use survey dump instead of scan
SCAN_DATA=""
if systemctl is-active --quiet fortress-hostapd; then
    # AP is running - temporarily stop for scan
    log "Stopping hostapd for channel scan..."
    systemctl stop fortress-hostapd
    sleep 2

    # Put interface in managed mode for scanning
    ip link set "$AP_INTERFACE" down 2>/dev/null || true
    iw dev "$AP_INTERFACE" set type managed 2>/dev/null || true
    ip link set "$AP_INTERFACE" up 2>/dev/null || true
    sleep 1

    SCAN_DATA=$(iw dev "$AP_INTERFACE" scan 2>/dev/null || true)

    # Restore AP mode and restart hostapd
    ip link set "$AP_INTERFACE" down 2>/dev/null || true
    iw dev "$AP_INTERFACE" set type __ap 2>/dev/null || true
    ip link set "$AP_INTERFACE" up 2>/dev/null || true
else
    # AP not running - can do full scan
    log "AP not running, performing full scan..."
    ip link set "$AP_INTERFACE" up 2>/dev/null || true
    sleep 1
    SCAN_DATA=$(iw dev "$AP_INTERFACE" scan 2>/dev/null || true)
fi

if [ -z "$SCAN_DATA" ]; then
    log "Scan failed, keeping current channel"
    systemctl start fortress-hostapd 2>/dev/null || true
    exit 0
fi

# Count networks on each non-overlapping 2.4GHz channel (1, 6, 11)
ch1_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 1$" || echo 0)
ch6_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 6$" || echo 0)
ch11_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 11$" || echo 0)

# Also count adjacent channels
ch2_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 2$" || echo 0)
ch3_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 3$" || echo 0)
ch4_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 4$" || echo 0)
ch5_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 5$" || echo 0)
ch7_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 7$" || echo 0)
ch8_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 8$" || echo 0)
ch9_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 9$" || echo 0)
ch10_count=$(echo "$SCAN_DATA" | grep -c "DS Parameter set: channel 10$" || echo 0)

# Calculate interference scores
score_1=$((ch1_count * 3 + ch2_count * 2 + ch3_count))
score_6=$((ch6_count * 3 + ch4_count + ch5_count * 2 + ch7_count * 2 + ch8_count))
score_11=$((ch11_count * 3 + ch9_count + ch10_count * 2))

log "Channel scan results:"
log "  Channel 1:  $ch1_count networks (interference score: $score_1)"
log "  Channel 6:  $ch6_count networks (interference score: $score_6)"
log "  Channel 11: $ch11_count networks (interference score: $score_11)"

# Select best channel
BEST_CHANNEL=6
if [ "$score_1" -le "$score_6" ] && [ "$score_1" -le "$score_11" ]; then
    BEST_CHANNEL=1
elif [ "$score_11" -le "$score_6" ]; then
    BEST_CHANNEL=11
fi

log "Best channel: $BEST_CHANNEL (current: $CURRENT_CHANNEL)"

# Only change if different and significant improvement
if [ "$BEST_CHANNEL" != "$CURRENT_CHANNEL" ]; then
    log "Updating hostapd config to channel $BEST_CHANNEL"
    sed -i "s/^channel=.*/channel=$BEST_CHANNEL/" "$HOSTAPD_CONF"

    # Save state
    cat > "$STATE_FILE" << EOF
{
    "last_scan": "$(date -Iseconds)",
    "selected_channel": $BEST_CHANNEL,
    "previous_channel": $CURRENT_CHANNEL,
    "scores": {"ch1": $score_1, "ch6": $score_6, "ch11": $score_11}
}
EOF
else
    log "Channel $CURRENT_CHANNEL is already optimal, no change needed"
fi

# Restart hostapd
log "Restarting hostapd..."
systemctl start fortress-hostapd

log "Channel optimization complete"
CHANNEL_SCRIPT

    chmod +x /usr/local/bin/fortress-channel-optimize.sh

    # Create systemd service
    cat > /etc/systemd/system/fortress-channel-optimize.service << 'SERVICEEOF'
[Unit]
Description=Fortress WiFi Channel Optimization
After=network.target fortress-hostapd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/fortress-channel-optimize.sh
StandardOutput=journal
StandardError=journal

# Note: No [Install] section - this service is only triggered by timer
# Do NOT add WantedBy=multi-user.target as it would stop hostapd at every boot
SERVICEEOF

    # Create systemd timer for daily 4am execution
    cat > /etc/systemd/system/fortress-channel-optimize.timer << 'TIMEREOF'
[Unit]
Description=Daily WiFi Channel Optimization (4:00 AM)

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=300
# DO NOT set Persistent=true - it would run at boot and stop hostapd!

[Install]
WantedBy=timers.target
TIMEREOF

    # Enable and start the timer
    systemctl daemon-reload
    systemctl enable fortress-channel-optimize.timer
    systemctl start fortress-channel-optimize.timer

    log_info "WiFi Channel Optimization installed"
    log_info "  - Runs daily at 4:00 AM (timer-triggered)"
    log_info "  - Selects best channel from 1, 6, 11"
    log_info "  - Run manually: systemctl start fortress-channel-optimize"
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
    # IMPORTANT: Must match path in models.py: /etc/hookprobe/users.json
    local USERS_FILE="/etc/hookprobe/users.json"
    if [ ! -f "$USERS_FILE" ]; then
        # Generate random password for admin
        local ADMIN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | head -c 12)
        # Hash password with Python/bcrypt
        local PASS_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw('$ADMIN_PASS'.encode(), bcrypt.gensalt()).decode())" 2>/dev/null || echo "")

        if [ -n "$PASS_HASH" ]; then
            # JSON format must match User model expectations (see models.py)
            cat > "$USERS_FILE" << USERSEOF
{
    "users": {
        "admin": {
            "password_hash": "$PASS_HASH",
            "role": "admin",
            "display_name": "Administrator",
            "email": null,
            "created_at": "$(date -Iseconds)",
            "last_login": null,
            "is_active": true
        }
    },
    "version": "1.0"
}
USERSEOF
            chmod 600 "$USERS_FILE"

            # Save credentials for display at end of installation
            echo "$ADMIN_PASS" > "$SECRET_DIR/admin_password"
            chmod 600 "$SECRET_DIR/admin_password"
            log_info "Admin user created:"
            log_info "  Username: admin"
            log_info "  Password: $ADMIN_PASS"
            log_info "  (saved to $SECRET_DIR/admin_password)"
        else
            log_warn "Could not hash password - bcrypt may not be installed"
            log_warn "Default credentials will be: admin / hookprobe"
        fi
    else
        log_info "Users file already exists, keeping existing credentials"
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
    for service in hookprobe-fortress fortress-qsecbit fortress-nat fortress-hostapd fortress-dnsmasq; do
        if systemctl is-enabled "$service" &>/dev/null; then
            log_info "✓ Service $service enabled"
        else
            log_warn "⚠ Service $service not enabled"
            warnings=$((warnings + 1))
        fi
    done

    # Check network services are running
    log_info "Checking network services..."
    if systemctl is-active fortress-nat &>/dev/null; then
        log_info "✓ NAT routing active"
    else
        log_warn "⚠ NAT routing not running"
        warnings=$((warnings + 1))
    fi

    if systemctl is-active fortress-dnsmasq &>/dev/null; then
        log_info "✓ DHCP server running"
    else
        log_warn "⚠ DHCP server not running"
        warnings=$((warnings + 1))
    fi

    # hostapd may not start if no WiFi interface
    if systemctl is-active fortress-hostapd &>/dev/null; then
        log_info "✓ WiFi AP running"
    else
        log_warn "⚠ WiFi AP not running (check if WiFi interface is available)"
    fi

    # Check management scripts exist
    for script in hookprobe-macsec hookprobe-openflow fortress-dnsxai-privacy; do
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
            # Check security monitoring containers
            if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fortress-suricata"; then
                log_info "✓ Suricata IDS container running"
            else
                log_warn "⚠ Suricata IDS container not running"
                warnings=$((warnings + 1))
            fi
            if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fortress-zeek"; then
                log_info "✓ Zeek network analyzer running"
            else
                log_warn "⚠ Zeek network analyzer not running"
                warnings=$((warnings + 1))
            fi
        fi
    fi

    # Check LSTM training timer
    if systemctl is-enabled fortress-lstm-train.timer &>/dev/null 2>&1; then
        log_info "✓ LSTM daily training timer enabled"
    else
        log_warn "⚠ LSTM daily training timer not enabled"
        warnings=$((warnings + 1))
    fi

    # Check dnsXai privacy controls
    if [ -f "/etc/hookprobe/dnsxai/privacy.json" ]; then
        log_info "✓ dnsXai privacy controls configured"
    else
        log_warn "⚠ dnsXai privacy controls not configured"
        warnings=$((warnings + 1))
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
    [ "$ENABLE_MONITORING" = true ] && echo -e "  ${GREEN}✓${NC} Security Monitoring (Suricata IDS + Zeek Network Analyzer)"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  ${GREEN}✓${NC} ML/LSTM Threat Detection (daily training at 3:00 AM)"
    echo -e "  ${GREEN}✓${NC} dnsXai Privacy Controls (default: privacy-first)"
    [ "$ENABLE_N8N" = true ] && echo -e "  ${GREEN}✓${NC} n8n Workflow Automation"
    [ "$ENABLE_REMOTE_ACCESS" = true ] && echo -e "  ${GREEN}✓${NC} Cloudflare Tunnel (Remote Access)"

    # LTE information
    if [ "$ENABLE_LTE" = true ] && [ -n "$LTE_INTERFACE" ]; then
        echo -e "  ${GREEN}✓${NC} LTE WAN Failover (${LTE_VENDOR:-Unknown} ${LTE_MODEL:-modem})"
    fi
    echo ""

    echo -e "  ${BOLD}Network Configuration:${NC}"
    echo -e "  Bridge: $OVS_BRIDGE_NAME (10.250.0.1)"
    echo -e "  DHCP per VLAN:"
    echo -e "    VLAN 10 (Management): 10.250.10.100-200"
    echo -e "    VLAN 20 (Trusted):    10.250.20.100-200"
    echo -e "    VLAN 30 (IoT):        10.250.30.100-200"
    echo -e "    VLAN 40 (Guest):      10.250.40.100-200"
    echo -e "    VLAN 99 (Quarantine): 10.250.99.100-200"
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

    # Show admin credentials - CRITICAL INFO BOX
    echo ""
    echo -e "  ${YELLOW}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${YELLOW}│${NC}  ${BOLD}${GREEN}🔐 FORTRESS ADMIN DASHBOARD${NC}                            ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}├──────────────────────────────────────────────────────────┤${NC}"
    if [ -f /etc/hookprobe/secrets/admin_password ]; then
        local ADMIN_PASS=$(cat /etc/hookprobe/secrets/admin_password 2>/dev/null)
        if [ -n "$ADMIN_PASS" ]; then
            echo -e "  ${YELLOW}│${NC}  URL:      ${CYAN}https://10.250.0.1:8443${NC}                   ${YELLOW}│${NC}"
            echo -e "  ${YELLOW}│${NC}  Username: ${CYAN}admin${NC}                                     ${YELLOW}│${NC}"
            echo -e "  ${YELLOW}│${NC}  Password: ${CYAN}$ADMIN_PASS${NC}                            ${YELLOW}│${NC}"
        else
            echo -e "  ${YELLOW}│${NC}  URL:      ${CYAN}https://10.250.0.1:8443${NC}                   ${YELLOW}│${NC}"
            echo -e "  ${YELLOW}│${NC}  Username: ${CYAN}admin${NC}                                     ${YELLOW}│${NC}"
            echo -e "  ${YELLOW}│${NC}  Password: ${CYAN}hookprobe${NC}  (default)                      ${YELLOW}│${NC}"
        fi
    else
        echo -e "  ${YELLOW}│${NC}  URL:      ${CYAN}https://10.250.0.1:8443${NC}                   ${YELLOW}│${NC}"
        echo -e "  ${YELLOW}│${NC}  Username: ${CYAN}admin${NC}                                     ${YELLOW}│${NC}"
        echo -e "  ${YELLOW}│${NC}  Password: ${CYAN}hookprobe${NC}  (default)                      ${YELLOW}│${NC}"
    fi
    echo -e "  ${YELLOW}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "  ${YELLOW}│${NC}  ${RED}⚠  CHANGE PASSWORD AFTER FIRST LOGIN!${NC}                  ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"

    # Show Grafana credentials if monitoring enabled
    if [ "$ENABLE_MONITORING" = true ] && [ -f /etc/hookprobe/secrets/grafana.conf ]; then
        source /etc/hookprobe/secrets/grafana.conf 2>/dev/null
        if [ -n "$GRAFANA_ADMIN_PASSWORD" ]; then
            echo ""
            echo -e "  ${BOLD}${GREEN}Grafana Dashboard:${NC}"
            echo -e "  URL:      ${CYAN}http://10.250.0.1:3000${NC}"
            echo -e "  Username: ${CYAN}admin${NC}"
            echo -e "  Password: ${CYAN}$GRAFANA_ADMIN_PASSWORD${NC}"
        fi
    fi

    # Show PostgreSQL credentials
    if [ -f /etc/hookprobe/secrets/postgres.conf ]; then
        source /etc/hookprobe/secrets/postgres.conf 2>/dev/null
        if [ -n "$POSTGRES_PASSWORD" ]; then
            echo ""
            echo -e "  ${BOLD}${GREEN}PostgreSQL Database:${NC}"
            echo -e "  Host:     ${CYAN}localhost:5432${NC}"
            echo -e "  Database: ${CYAN}fortress${NC}"
            echo -e "  Username: ${CYAN}fortress${NC}"
            echo -e "  Password: ${CYAN}$POSTGRES_PASSWORD${NC}"
        fi
    fi
    echo ""

    # Summary box with all credentials
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}SAVE THESE CREDENTIALS - YOU'LL NEED THEM TO ACCESS FORTRESS${NC}"
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    echo -e "  ${BOLD}Connect to Fortress:${NC}"
    echo -e "  1. Connect to WiFi: ${CYAN}${WIFI_SSID:-hookprobe}${NC}"
    echo -e "  2. Or plug into a LAN port"
    echo -e "  3. You'll get an IP in 10.250.1.x range"
    echo -e "  4. Access dashboard: ${CYAN}https://10.250.0.1:8443${NC}"
    echo ""

    echo -e "  ${BOLD}Management Commands:${NC}"
    echo -e "  ${CYAN}hookprobe-macsec${NC} enable eth0  - Enable MACsec on interface"
    echo -e "  ${CYAN}hookprobe-openflow${NC} status     - View OpenFlow status"
    echo -e "  ${CYAN}fortress-dnsxai-privacy${NC} status - View/change privacy settings"
    echo -e "  ${CYAN}systemctl status${NC} hookprobe-fortress"
    [ "$ENABLE_LTE" = true ] && echo -e "  ${CYAN}systemctl status${NC} fortress-lte-failover"
    echo ""
    echo -e "  ${BOLD}Web Interfaces:${NC}"
    echo -e "  Fortress Admin:   ${CYAN}https://10.250.0.1:8443${NC}"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  Grafana:          ${CYAN}http://10.250.0.1:3000${NC}"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  Victoria Metrics: ${CYAN}http://10.250.0.1:8428${NC}"
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

    # Wait for user to acknowledge before returning to shell
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${GREEN}Installation complete!${NC}"
    echo ""
    echo -e "  ${BOLD}Next steps:${NC}"
    echo -e "  1. Connect to WiFi '${CYAN}${WIFI_SSID:-hookprobe}${NC}' or plug into LAN port"
    echo -e "  2. Open ${CYAN}https://10.250.0.1:8443${NC} in your browser"
    echo -e "  3. Login with credentials shown above"
    echo -e "  4. Change the default password immediately!"
    echo ""
    if [ "$NON_INTERACTIVE" != true ]; then
        echo -e "  ${YELLOW}Press ENTER to return to shell, or Ctrl+C to stay here...${NC}"
        read -r
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
    # WiFi Access Point Configuration
    # ─────────────────────────────────────────────────────────────
    echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}  WiFi Access Point Configuration${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
    echo ""

    if [ -n "$WIFI_INTERFACES" ]; then
        echo -e "${GREEN}✓ WiFi adapter detected: $(echo $WIFI_INTERFACES | awk '{print $1}')${NC}"
        echo ""

        # SSID
        read -p "WiFi Network Name (SSID) [hookprobe]: " user_ssid
        FORTRESS_WIFI_SSID="${user_ssid:-hookprobe}"

        # Password
        echo ""
        echo "WiFi Password options:"
        echo "  1. Enter custom password"
        echo "  2. Generate random password (recommended)"
        echo ""
        read -p "Select [1-2] (default: 2): " pw_choice
        pw_choice="${pw_choice:-2}"

        if [ "$pw_choice" = "1" ]; then
            while true; do
                read -sp "Enter WiFi password (min 8 chars): " user_password
                echo ""
                if [ ${#user_password} -lt 8 ]; then
                    echo -e "${RED}Password must be at least 8 characters.${NC}"
                else
                    FORTRESS_WIFI_PASSWORD="$user_password"
                    break
                fi
            done
        else
            # Generate random password (12 chars, alphanumeric only for compatibility)
            FORTRESS_WIFI_PASSWORD=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 12)
            echo -e "Generated password: ${CYAN}$FORTRESS_WIFI_PASSWORD${NC}"
            echo -e "${YELLOW}(Save this password - you'll need it to connect!)${NC}"
        fi
        echo ""
    else
        echo -e "${YELLOW}⚠ No WiFi adapter detected - WiFi AP will be skipped${NC}"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────
    # Network Configuration
    # ─────────────────────────────────────────────────────────────
    echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}  Network Configuration${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
    echo ""

    echo "Network size determines how many devices can connect:"
    echo "  /29 = 6 devices     (very small office)"
    echo "  /28 = 14 devices    (small office)"
    echo "  /27 = 30 devices    (small business)"
    echo "  /26 = 62 devices    (medium business)"
    echo "  /25 = 126 devices   (larger office)"
    echo "  /24 = 254 devices   (large network)"
    echo "  /23 = 510 devices   (default - recommended for growth)"
    echo ""
    read -p "Network size [/23]: " user_netmask
    user_netmask="${user_netmask:-/23}"
    # Remove leading slash if present
    FORTRESS_NETWORK_PREFIX="${user_netmask#/}"

    # Validate network size
    if ! [[ "$FORTRESS_NETWORK_PREFIX" =~ ^(23|24|25|26|27|28|29)$ ]]; then
        echo -e "${YELLOW}Invalid network size. Using default /23${NC}"
        FORTRESS_NETWORK_PREFIX="23"
    fi
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

        read -p "Enter your APN name [internet]: " HOOKPROBE_LTE_APN
        HOOKPROBE_LTE_APN="${HOOKPROBE_LTE_APN:-internet}"

        # Authentication type
        echo ""
        echo "Authentication type (most carriers use 'none'):"
        echo "  1. none     - No authentication (default, most common)"
        echo "  2. pap      - PAP authentication"
        echo "  3. chap     - CHAP authentication"
        echo "  4. mschapv2 - MS-CHAPv2 authentication"
        echo ""
        read -p "Select [1-4] (default: 1): " auth_choice
        auth_choice="${auth_choice:-1}"

        case "$auth_choice" in
            2) HOOKPROBE_LTE_AUTH="pap" ;;
            3) HOOKPROBE_LTE_AUTH="chap" ;;
            4) HOOKPROBE_LTE_AUTH="mschapv2" ;;
            *) HOOKPROBE_LTE_AUTH="none" ;;
        esac

        # If auth selected, get credentials
        if [ "$HOOKPROBE_LTE_AUTH" != "none" ]; then
            echo ""
            echo -e "${YELLOW}Authentication: $HOOKPROBE_LTE_AUTH${NC}"
            read -p "Username: " HOOKPROBE_LTE_USER
            read -sp "Password: " HOOKPROBE_LTE_PASS
            echo ""
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

    echo -e "  ${BOLD}Network Settings:${NC}"
    echo "    Network size: /${FORTRESS_NETWORK_PREFIX:-23}"
    [ -n "$FORTRESS_WIFI_SSID" ] && echo "    WiFi SSID: $FORTRESS_WIFI_SSID"
    echo ""

    echo -e "  ${BOLD}Core Features:${NC}"
    echo "    ✓ OVS Bridge with OpenFlow 1.3"
    echo "    ✓ VLAN Segmentation (5 VLANs)"
    [ "$MACSEC_ENABLED" = true ] && echo "    ✓ MACsec Layer 2 Encryption"
    echo "    ✓ QSecBit Security Agent"
    echo "    ✓ Web Dashboard (https://localhost:8443)"
    echo "    ✓ Local Auth (max 5 users)"
    echo ""

    echo -e "  ${BOLD}Optional Features:${NC}"
    [ "$ENABLE_LTE" = true ] && echo "    ✓ LTE Failover (APN: $HOOKPROBE_LTE_APN, Auth: ${HOOKPROBE_LTE_AUTH:-none})"
    [ "$ENABLE_REMOTE_ACCESS" = true ] && echo "    ✓ Remote Access (Cloudflare Tunnel)"
    [ "$ENABLE_MONITORING" = true ] && echo "    ✓ Monitoring (Grafana + Victoria Metrics)"
    [ "$ENABLE_N8N" = true ] && echo "    ✓ n8n Workflow Automation"
    [ "$ENABLE_LTE" != true ] && [ "$ENABLE_REMOTE_ACCESS" != true ] && [ "$ENABLE_MONITORING" != true ] && [ "$ENABLE_N8N" != true ] && echo "    (none selected)"
    echo ""

    # Confirm - default YES
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
    # Use quiet mode for detector to suppress verbose output
    # The summary will still be shown (controlled by detect_interfaces)
    NET_QUIET_MODE=true detect_interfaces

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

    # Re-detect interfaces now that iw is installed
    # This ensures WiFi interfaces are properly detected for AP setup
    # Use quiet mode and skip summary to avoid duplicate output
    NET_QUIET_MODE=true NET_SKIP_SUMMARY=true detect_interfaces

    install_python_packages
    install_podman
    optimize_boot_time
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
    install_database
    install_monitoring
    install_cloudflared
    setup_lte_failover

    # Start network services (DHCP, WiFi AP)
    start_network_services

    create_systemd_services
    create_config_file
    install_web_dashboard

    # Install channel optimization service (daily 4am calibration)
    install_channel_optimization_service

    # Start services
    log_step "Starting services..."
    systemctl start hookprobe-fortress 2>/dev/null || true
    systemctl start fortress-qsecbit 2>/dev/null || true

    # Start channel optimization timer
    systemctl enable --now fortress-channel-optimize.timer 2>/dev/null || true

    # Validate installation
    validate_installation

    show_completion
}

main "$@"
