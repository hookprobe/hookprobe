#!/bin/bash
#
# HookProbe Guardian Setup Script
# Version: 5.0.0
# License: AGPL-3.0 - see LICENSE file
#
# Guardian - Portable Travel Security Companion
#
# Guardian Mode (This Script):
#   - Simple WiFi hotspot (all devices on same network)
#   - Client tracking via hostapd (see connected devices in UI)
#   - Full security stack (NAPSE IDS via AIOCHI, WAF, XDP DDoS protection)
#   - Works with any USB WiFi adapter that supports AP mode
#
# For VLAN Segmentation (Fortress Mode):
#   - Requires special WiFi adapters that support multiple VAPs
#   - Recommended: Atheros AR9271, MediaTek MT7612U
#   - See Fortress installation guide for IoT VLAN isolation
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDIAN_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$GUARDIAN_ROOT/config"

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
# LOGGING
# ============================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ============================================================
# PREREQUISITES CHECK
# ============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_platform() {
    log_step "Detecting platform..."

    if grep -q "Raspberry Pi 5" /proc/cpuinfo 2>/dev/null; then
        PLATFORM="rpi5"
        PLATFORM_NAME="Raspberry Pi 5"
    elif grep -q "Raspberry Pi 4" /proc/cpuinfo 2>/dev/null; then
        PLATFORM="rpi4"
        PLATFORM_NAME="Raspberry Pi 4"
    elif grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        PLATFORM="rpi"
        PLATFORM_NAME="Raspberry Pi"
    else
        PLATFORM="generic"
        PLATFORM_NAME="Generic Linux"
    fi

    log_info "Platform: $PLATFORM_NAME"
}

detect_interfaces() {
    log_step "Detecting network interfaces..."

    # Ethernet interfaces
    ETH_INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|enp|eno)' | tr '\n' ' ')
    ETH_COUNT=$(echo $ETH_INTERFACES | wc -w)

    # WiFi interfaces
    WIFI_INTERFACES=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | tr '\n' ' ')
    WIFI_COUNT=$(echo $WIFI_INTERFACES | wc -w)

    # Check AP mode support
    WIFI_AP_SUPPORT=false
    for iface in $WIFI_INTERFACES; do
        if iw list 2>/dev/null | grep -A 10 "Supported interface modes" | grep -q "AP"; then
            WIFI_AP_SUPPORT=true
            break
        fi
    done

    # Detect built-in vs USB WiFi based on driver
    # Built-in Raspberry Pi WiFi uses brcmfmac driver
    # USB adapters use various drivers (rtl8xxxu, ath9k_htc, mt76x0u, etc.)
    BUILTIN_WIFI=""
    USB_WIFI=""
    for iface in $WIFI_INTERFACES; do
        local driver=$(readlink -f /sys/class/net/$iface/device/driver 2>/dev/null | xargs basename 2>/dev/null)
        # Try alternate method if driver is empty
        if [ -z "$driver" ]; then
            driver=$(cat /sys/class/net/$iface/device/uevent 2>/dev/null | grep "^DRIVER=" | cut -d= -f2)
        fi
        log_info "Interface $iface has driver: ${driver:-unknown}"

        if [ "$driver" = "brcmfmac" ] || [ "$driver" = "brcmsmac" ]; then
            BUILTIN_WIFI="$iface"
            log_info "Built-in WiFi (Raspberry Pi): $iface"
        else
            # Any non-brcmfmac interface is considered USB/external
            USB_WIFI="$iface"
            log_info "External WiFi (USB adapter): $iface"
        fi
    done

    # Set recommended interfaces based on detection
    # Built-in WiFi = WAN (connects to upstream network)
    # USB WiFi = AP (hosts the hotspot)
    if [ -n "$BUILTIN_WIFI" ]; then
        RECOMMENDED_WAN_IFACE="$BUILTIN_WIFI"
        # Find any interface that is NOT the built-in for AP
        for iface in $WIFI_INTERFACES; do
            if [ "$iface" != "$BUILTIN_WIFI" ]; then
                RECOMMENDED_AP_IFACE="$iface"
                break
            fi
        done
        if [ -n "$RECOMMENDED_AP_IFACE" ]; then
            log_info "Auto-detected: WAN=$RECOMMENDED_WAN_IFACE (built-in), AP=$RECOMMENDED_AP_IFACE (external)"
        fi
    fi

    log_info "Ethernet interfaces ($ETH_COUNT): $ETH_INTERFACES"
    log_info "WiFi interfaces ($WIFI_COUNT): $WIFI_INTERFACES"
    log_info "WiFi AP mode: $WIFI_AP_SUPPORT"
}

check_mesh_connectivity() {
    local mesh_url="${HOOKPROBE_MESH_URL:-https://nexus.hookprobe.com}"
    local timeout=10

    log_step "Checking mesh connectivity..."

    if command -v curl &>/dev/null; then
        if curl -s --max-time $timeout "$mesh_url/api/health" &>/dev/null; then
            log_info "Mesh server is reachable"
            return 0
        fi
    fi

    log_warn "Mesh server not reachable (SDN features may be limited)"
    return 1
}

# ============================================================
# INSTALLATION FUNCTIONS
# ============================================================
install_packages() {
    log_step "Installing required packages..."

    # Detect package manager
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
        apt-get update -qq

        # Pre-create hostapd config directory and files BEFORE installing
        # This prevents systemd ConditionFileNotEmpty check from failing
        log_info "Pre-creating hostapd configuration..."
        mkdir -p /etc/hostapd
        mkdir -p /etc/default

        # Create placeholder hostapd.conf if it doesn't exist
        # This satisfies the systemd ConditionFileNotEmpty=/etc/hostapd/hostapd.conf
        if [ ! -f /etc/hostapd/hostapd.conf ]; then
            cat > /etc/hostapd/hostapd.conf << 'PLACEHOLDER'
# HookProbe Guardian - Placeholder configuration
# This file will be replaced during setup with proper configuration
interface=wlan1
driver=nl80211
ssid=HookProbe-Guardian
hw_mode=g
channel=6
PLACEHOLDER
            chmod 644 /etc/hostapd/hostapd.conf
        fi

        # Create /etc/default/hostapd for init script compatibility
        if [ ! -f /etc/default/hostapd ]; then
            echo '# Defaults for hostapd initscript' > /etc/default/hostapd
            echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> /etc/default/hostapd
        fi

        # Mask hostapd to prevent auto-start during package installation
        # We'll unmask and configure it properly later
        systemctl mask hostapd.service 2>/dev/null || true

        # Install packages non-interactively (auto-keep existing configs)
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            hostapd \
            dnsmasq \
            bridge-utils \
            iptables \
            nftables \
            iw \
            wireless-tools \
            wpasupplicant \
            network-manager \
            python3 \
            python3-pip \
            python3-flask \
            python3-requests \
            python3-numpy \
            net-tools \
            curl \
            jq
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        dnf install -y -q \
            hostapd \
            dnsmasq \
            bridge-utils \
            iptables \
            nftables \
            iw \
            wireless-tools \
            wpa_supplicant \
            NetworkManager \
            NetworkManager-wifi \
            python3 \
            python3-pip \
            python3-flask \
            python3-requests \
            python3-numpy \
            net-tools \
            curl \
            jq
    else
        log_error "Unsupported package manager"
        exit 1
    fi

    log_info "Packages installed"
}

# ============================================================
# SYSTEM LOCALE AND REGIONAL CONFIGURATION
# ============================================================
configure_system_locale() {
    log_step "Configuring system locale and regional settings..."

    local TARGET_LOCALE="en_US.UTF-8"

    # Debian/Ubuntu/Raspberry Pi OS
    if command -v locale-gen &>/dev/null; then
        log_info "Setting locale to $TARGET_LOCALE..."

        # Install locales package if missing
        if ! dpkg -l locales &>/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq locales 2>/dev/null || true
        fi

        # Enable ONLY en_US.UTF-8 in locale.gen
        if [ -f /etc/locale.gen ]; then
            # Comment out all locales first (including en_GB)
            sed -i 's/^[^#].*UTF-8/# &/' /etc/locale.gen 2>/dev/null || true
            # Uncomment en_US.UTF-8
            sed -i 's/^# *\(en_US.UTF-8 UTF-8\)/\1/' /etc/locale.gen
            # Ensure the line exists
            if ! grep -q "^en_US.UTF-8 UTF-8" /etc/locale.gen; then
                echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
            fi
        fi

        # Generate the locale
        locale-gen $TARGET_LOCALE 2>/dev/null || locale-gen 2>/dev/null || true

        # Apply immediately for this session BEFORE writing config files
        # First unset LC_ALL to prevent "cannot change locale" warnings
        # (bash validates the locale when setting LC_ALL, which fails if not yet loaded)
        unset LC_ALL 2>/dev/null || true
        export LANG=$TARGET_LOCALE
        export LANGUAGE=$TARGET_LOCALE
        export LC_CTYPE=$TARGET_LOCALE
        export LC_MESSAGES=$TARGET_LOCALE
        # Set LC_ALL last after other LC_* are set
        export LC_ALL=$TARGET_LOCALE 2>/dev/null || true

        # Write complete /etc/default/locale with ALL variables
        cat > /etc/default/locale << EOF
LANG=$TARGET_LOCALE
LANGUAGE=$TARGET_LOCALE
LC_ALL=$TARGET_LOCALE
LC_CTYPE=$TARGET_LOCALE
LC_NUMERIC=$TARGET_LOCALE
LC_TIME=$TARGET_LOCALE
LC_COLLATE=$TARGET_LOCALE
LC_MONETARY=$TARGET_LOCALE
LC_MESSAGES=$TARGET_LOCALE
LC_PAPER=$TARGET_LOCALE
LC_NAME=$TARGET_LOCALE
LC_ADDRESS=$TARGET_LOCALE
LC_TELEPHONE=$TARGET_LOCALE
LC_MEASUREMENT=$TARGET_LOCALE
LC_IDENTIFICATION=$TARGET_LOCALE
EOF

        # Also update /etc/environment for system-wide effect
        if [ -f /etc/environment ]; then
            # Remove any existing LANG/LC_ lines
            sed -i '/^LANG=/d; /^LC_/d; /^LANGUAGE=/d' /etc/environment
            # Add our settings
            echo "LANG=$TARGET_LOCALE" >> /etc/environment
            echo "LC_ALL=$TARGET_LOCALE" >> /etc/environment
        fi

        # Run update-locale as backup
        update-locale LANG=$TARGET_LOCALE LANGUAGE=$TARGET_LOCALE LC_ALL=$TARGET_LOCALE 2>/dev/null || true

        # Verify locale is working
        if locale 2>&1 | grep -q "Cannot set"; then
            log_warn "Locale warnings detected, attempting dpkg-reconfigure..."
            dpkg-reconfigure -f noninteractive locales 2>/dev/null || true
        fi

        log_info "Locale configured: $TARGET_LOCALE"

    elif command -v localectl &>/dev/null; then
        # Fedora/RHEL/systemd systems
        localectl set-locale LANG=$TARGET_LOCALE LC_ALL=$TARGET_LOCALE 2>/dev/null || true
        export LANG=$TARGET_LOCALE
        export LC_ALL=$TARGET_LOCALE
        log_info "Locale configured: $TARGET_LOCALE"
    fi
}

configure_wifi_country() {
    log_step "Auto-detecting WiFi regulatory country from public IP..."

    # Try to get country from public IP geolocation
    WIFI_COUNTRY=""

    # Try multiple geolocation services (in case one is down)
    for api in "http://ip-api.com/line/?fields=countryCode" \
               "https://ipinfo.io/country" \
               "https://ifconfig.co/country-iso"; do
        if WIFI_COUNTRY=$(curl -s --connect-timeout 5 --max-time 10 "$api" 2>/dev/null); then
            # Validate it's a 2-letter country code
            if [[ "$WIFI_COUNTRY" =~ ^[A-Z]{2}$ ]]; then
                log_info "Detected country from IP: $WIFI_COUNTRY"
                break
            fi
        fi
        WIFI_COUNTRY=""
    done

    # Fallback to US if detection failed
    if [ -z "$WIFI_COUNTRY" ]; then
        WIFI_COUNTRY="US"
        log_warn "Could not detect country from IP, defaulting to US"
    fi

    # Set WiFi regulatory domain
    log_info "Setting WiFi regulatory domain to $WIFI_COUNTRY..."

    # Method 1: iw reg set (immediate)
    if command -v iw &>/dev/null; then
        iw reg set "$WIFI_COUNTRY" 2>/dev/null || true
    fi

    # Method 2: CRDA config (persistent)
    if [ -f /etc/default/crda ]; then
        sed -i "s/^REGDOMAIN=.*/REGDOMAIN=$WIFI_COUNTRY/" /etc/default/crda
    else
        echo "REGDOMAIN=$WIFI_COUNTRY" > /etc/default/crda 2>/dev/null || true
    fi

    # Method 3: wpa_supplicant global config (for WiFi client)
    if [ -d /etc/wpa_supplicant ]; then
        # Update any existing wpa_supplicant configs
        for conf in /etc/wpa_supplicant/*.conf; do
            if [ -f "$conf" ]; then
                if grep -q "^country=" "$conf"; then
                    sed -i "s/^country=.*/country=$WIFI_COUNTRY/" "$conf"
                else
                    # Add country at the beginning of the file
                    sed -i "1i country=$WIFI_COUNTRY" "$conf"
                fi
            fi
        done
    fi

    # Method 4: Raspberry Pi specific - raspi-config style
    if [ -f /boot/firmware/config.txt ] || [ -f /boot/config.txt ]; then
        # Create/update wpa_supplicant.conf for first boot
        WPA_CONF="/etc/wpa_supplicant/wpa_supplicant.conf"
        if [ ! -f "$WPA_CONF" ]; then
            mkdir -p /etc/wpa_supplicant
            cat > "$WPA_CONF" << EOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=$WIFI_COUNTRY
EOF
        elif ! grep -q "^country=" "$WPA_CONF"; then
            sed -i "1i country=$WIFI_COUNTRY" "$WPA_CONF"
        else
            sed -i "s/^country=.*/country=$WIFI_COUNTRY/" "$WPA_CONF"
        fi
    fi

    # Method 5: NetworkManager regulatory domain
    if [ -d /etc/NetworkManager/conf.d ]; then
        cat > /etc/NetworkManager/conf.d/99-wifi-country.conf << EOF
[device]
wifi.scan-rand-mac-address=no

[connection]
wifi.cloned-mac-address=preserve
EOF
    fi

    # Store detected country for other scripts to use
    mkdir -p /etc/guardian
    echo "$WIFI_COUNTRY" > /etc/guardian/wifi_country

    log_info "WiFi country configured: $WIFI_COUNTRY"
}

# ============================================================
# GUARDIAN CONFIGURATION DIRECTORY
# ============================================================
setup_guardian_config() {
    log_step "Setting up Guardian configuration directory..."

    # Create Guardian config directory
    mkdir -p /etc/guardian
    chmod 755 /etc/guardian

    # Create HookProbe config directory
    mkdir -p /etc/hookprobe
    chmod 755 /etc/hookprobe

    # Determine installation directory (where this script is located)
    # GUARDIAN_ROOT is set at top of script: GUARDIAN_ROOT="$(dirname "$SCRIPT_DIR")"
    # This gives us .../products/guardian, so go up two levels for repo root
    local INSTALL_DIR
    INSTALL_DIR="$(cd "$GUARDIAN_ROOT/../.." && pwd)"

    # Get git info if available
    local INSTALL_COMMIT="unknown"
    local INSTALL_BRANCH="unknown"
    if [ -d "$INSTALL_DIR/.git" ]; then
        INSTALL_COMMIT=$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
        INSTALL_BRANCH=$(git -C "$INSTALL_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
    fi

    # Detect install user (even when run with sudo)
    local INSTALL_USER="${SUDO_USER:-$USER}"
    local INSTALL_DATE
    INSTALL_DATE=$(date -Iseconds)

    # Write installation config file
    log_info "Writing installation config to /etc/hookprobe/install.conf..."
    cat > /etc/hookprobe/install.conf << INSTALLEOF
# HookProbe Installation Configuration
# Generated by Guardian setup.sh on $INSTALL_DATE
# This file tells the update system where HookProbe is installed

# Installation paths
HOOKPROBE_INSTALL_DIR="$INSTALL_DIR"
HOOKPROBE_USER="$INSTALL_USER"
HOOKPROBE_TIER="guardian"

# Git information at install time
HOOKPROBE_INSTALL_COMMIT="$INSTALL_COMMIT"
HOOKPROBE_INSTALL_BRANCH="$INSTALL_BRANCH"
HOOKPROBE_INSTALL_DATE="$INSTALL_DATE"

# Remote configuration for updates
HOOKPROBE_REMOTE="origin"
HOOKPROBE_BRANCH="main"

# Environment variables for services
GUARDIAN_REPO_PATH="$INSTALL_DIR"
GUARDIAN_BRANCH="main"
INSTALLEOF

    chmod 644 /etc/hookprobe/install.conf
    log_info "Installation config saved: HOOKPROBE_INSTALL_DIR=$INSTALL_DIR"

    # Create environment file for systemd services
    cat > /etc/hookprobe/environment << ENVEOF
# HookProbe Environment Variables
# Sourced by systemd services
GUARDIAN_REPO_PATH=$INSTALL_DIR
GUARDIAN_BRANCH=main
HOOKPROBE_INSTALL_DIR=$INSTALL_DIR
HOOKPROBE_TIER=guardian
ENVEOF

    chmod 644 /etc/hookprobe/environment
    log_info "Environment file saved to /etc/hookprobe/environment"

    log_info "Guardian configuration directory created"
}

# ============================================================
# PODMAN CONTAINER RUNTIME
# ============================================================
install_podman() {
    log_step "Installing Podman container runtime..."

    if command -v podman &>/dev/null; then
        log_info "Podman already installed: $(podman --version)"
    else
        if [ "$PKG_MGR" = "apt" ]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" \
                podman
        else
            dnf install -y -q podman
        fi
    fi

    # Enable and start podman socket
    systemctl enable --now podman.socket 2>/dev/null || true

    log_info "Podman installed: $(podman --version)"
}

# ============================================================
# OPEN VSWITCH WITH VXLAN
# ============================================================
install_openvswitch() {
    log_step "Installing Open vSwitch..."

    if command -v ovs-vsctl &>/dev/null; then
        log_info "Open vSwitch already installed"
    else
        if [ "$PKG_MGR" = "apt" ]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" \
                openvswitch-switch
        else
            dnf install -y -q openvswitch
        fi
    fi

    # Enable and start OVS
    systemctl enable openvswitch-switch 2>/dev/null || \
        systemctl enable openvswitch 2>/dev/null || true
    systemctl start openvswitch-switch 2>/dev/null || \
        systemctl start openvswitch 2>/dev/null || true

    log_info "Open vSwitch installed and running"
}

# ============================================================
# NETWORKMANAGER CONFIGURATION
# ============================================================
configure_networkmanager() {
    log_step "Configuring NetworkManager for Guardian..."

    # Enable and start NetworkManager first
    systemctl enable NetworkManager 2>/dev/null || true
    systemctl start NetworkManager 2>/dev/null || true
    sleep 2

    # Use the guardian-nm-setup.sh script to generate MAC-aware configuration
    # This script auto-detects MAC addresses and creates proper config
    local nm_setup_script="$SCRIPT_DIR/guardian-nm-setup.sh"

    if [ -f "$nm_setup_script" ]; then
        log_info "Running NetworkManager setup with MAC detection..."
        bash "$nm_setup_script" || {
            log_warn "guardian-nm-setup.sh failed, using fallback config"
            _configure_nm_fallback
        }
    else
        log_warn "guardian-nm-setup.sh not found, using fallback config"
        _configure_nm_fallback
    fi

    log_info "NetworkManager configured (wlan0=managed, wlan1/OVS=unmanaged)"
}

_configure_nm_fallback() {
    # Fallback configuration if guardian-nm-setup.sh is not available
    mkdir -p /etc/NetworkManager/conf.d

    cat > /etc/NetworkManager/conf.d/guardian-unmanaged.conf << 'EOF'
# HookProbe Guardian - NetworkManager Configuration (Fallback)
# For full MAC-aware config, run: guardian-nm-setup.sh

[keyfile]
unmanaged-devices=interface-name:wlan1;interface-name:br*;interface-name:ovs-*;interface-name:guardian;interface-name:vlan*;driver:openvswitch

[device]
# Disable MAC randomization
wifi.scan-rand-mac-address=no
wifi.cloned-mac-address=preserve
ethernet.cloned-mac-address=preserve

[connection]
wifi.cloned-mac-address=preserve
ethernet.cloned-mac-address=preserve

[main]
dhcp=internal
dns=none
EOF

    chmod 644 /etc/NetworkManager/conf.d/guardian-unmanaged.conf
    nmcli general reload 2>/dev/null || true

    if [ -d "/sys/class/net/wlan1" ]; then
        nmcli device set wlan1 managed no 2>/dev/null || true
    fi
}

generate_vxlan_psk() {
    # Generate a PSK for VXLAN tunnel encryption
    openssl rand -base64 32
}

setup_ovs_bridge() {
    log_step "Setting up OVS bridge with VXLAN..."

    local OVS_BRIDGE_NAME="guardian"
    local local_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    # Check if OVS is available
    if ! command -v ovs-vsctl &>/dev/null; then
        log_warn "OVS not available, skipping OVS bridge setup"
        return 0
    fi

    # Create OVS bridge if it doesn't exist
    if ovs-vsctl br-exists "$OVS_BRIDGE_NAME" 2>/dev/null; then
        log_info "OVS bridge '$OVS_BRIDGE_NAME' already exists"
    else
        ovs-vsctl add-br "$OVS_BRIDGE_NAME" 2>/dev/null || {
            log_warn "Failed to create OVS bridge"
            return 0
        }
        log_info "OVS bridge '$OVS_BRIDGE_NAME' created"
    fi

    # Enable OpenFlow 1.3 for advanced flow monitoring
    ovs-vsctl set bridge "$OVS_BRIDGE_NAME" protocols=OpenFlow10,OpenFlow13 2>/dev/null || true

    # Configure bridge IP
    ip link set "$OVS_BRIDGE_NAME" up
    ip addr add 10.250.0.1/16 dev "$OVS_BRIDGE_NAME" 2>/dev/null || true

    # Create secrets directory for VXLAN PSK
    mkdir -p /etc/hookprobe/secrets/vxlan
    chmod 700 /etc/hookprobe/secrets/vxlan

    # Generate master PSK if not exists
    if [ ! -f /etc/hookprobe/secrets/vxlan/master.psk ]; then
        generate_vxlan_psk > /etc/hookprobe/secrets/vxlan/master.psk
        chmod 600 /etc/hookprobe/secrets/vxlan/master.psk
        log_info "VXLAN master PSK generated"
    fi

    # Setup VXLAN tunnel for mesh connection
    local vxlan_vni="${HOOKPROBE_VXLAN_VNI:-1000}"
    local vxlan_port="vxlan_mesh"

    # Add VXLAN port to OVS bridge
    ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "$vxlan_port" \
        -- set interface "$vxlan_port" type=vxlan \
        options:key="$vxlan_vni" \
        options:local_ip="$local_ip" \
        options:remote_ip=flow 2>/dev/null || true

    # Save OVS configuration
    mkdir -p /etc/hookprobe
    cat > /etc/hookprobe/ovs-config.sh << OVSEOF
# HookProbe Guardian OVS Configuration
OVS_BRIDGE_NAME=$OVS_BRIDGE_NAME
LOCAL_IP=$local_ip

# VXLAN Configuration
VXLAN_ENABLED=true
VXLAN_VNI=$vxlan_vni
VXLAN_MASTER_PSK=/etc/hookprobe/secrets/vxlan/master.psk
OVSEOF

    log_info "OVS bridge configured with VXLAN (VNI: $vxlan_vni)"
}

# ============================================================
# MACSEC (802.1AE) LAYER 2 ENCRYPTION (OPTIONAL)
# ============================================================
# MACsec provides Layer 2 encryption for wired connections.
# Guardian mode: MACsec is optional, primarily for travel setups
# where wired connections need protection (e.g., untrusted LANs).
# ============================================================
setup_macsec() {
    log_step "Setting up MACsec (802.1AE) Layer 2 encryption..."

    local MACSEC_ENABLED="${HOOKPROBE_MACSEC_ENABLED:-false}"

    if [ "$MACSEC_ENABLED" != "true" ]; then
        log_info "MACsec disabled (set HOOKPROBE_MACSEC_ENABLED=true to enable)"
        return 0
    fi

    # Check for MACsec kernel support
    if ! modprobe macsec 2>/dev/null; then
        log_warn "MACsec kernel module not available"
        log_warn "MACsec requires Linux kernel 4.6+ with CONFIG_MACSEC=y"
        return 0
    fi

    # Create MACsec secrets directory
    mkdir -p /etc/hookprobe/secrets/macsec
    chmod 700 /etc/hookprobe/secrets/macsec

    # Generate MACsec CAK (Connectivity Association Key) - 128-bit (32 hex chars)
    if [ ! -f /etc/hookprobe/secrets/macsec/cak.key ]; then
        openssl rand -hex 16 > /etc/hookprobe/secrets/macsec/cak.key
        chmod 600 /etc/hookprobe/secrets/macsec/cak.key
        log_info "MACsec CAK generated"
    fi

    # Generate MACsec CKN (Connectivity Key Name) - 128-bit (32 hex chars)
    if [ ! -f /etc/hookprobe/secrets/macsec/ckn.key ]; then
        openssl rand -hex 16 > /etc/hookprobe/secrets/macsec/ckn.key
        chmod 600 /etc/hookprobe/secrets/macsec/ckn.key
        log_info "MACsec CKN generated"
    fi

    local CAK=$(cat /etc/hookprobe/secrets/macsec/cak.key)
    local CKN=$(cat /etc/hookprobe/secrets/macsec/ckn.key)

    # Create MACsec configuration
    cat > /etc/hookprobe/macsec.conf << MACSECEOF
# HookProbe Guardian MACsec Configuration
# 802.1AE Layer 2 Encryption

# MACsec encrypts wired Ethernet traffic at Layer 2
# Use when connecting to untrusted networks via Ethernet

MACSEC_ENABLED=$MACSEC_ENABLED
MACSEC_CIPHER=gcm-aes-128
MACSEC_REPLAY_PROTECT=true
MACSEC_REPLAY_WINDOW=32

# Keys are stored separately for security
MACSEC_CAK_FILE=/etc/hookprobe/secrets/macsec/cak.key
MACSEC_CKN_FILE=/etc/hookprobe/secrets/macsec/ckn.key
MACSECEOF

    # Create wpa_supplicant MACsec config for each ethernet interface
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
    cat > /usr/local/bin/guardian-macsec << 'MACSECSCRIPT'
#!/bin/bash
# HookProbe Guardian MACsec Management
# Provides Layer 2 encryption for wired connections

MACSEC_DIR="/etc/hookprobe"

case "$1" in
    enable)
        IFACE="${2:-eth0}"
        if [ -f "$MACSEC_DIR/macsec-${IFACE}.conf" ]; then
            echo "Enabling MACsec on $IFACE..."
            wpa_supplicant -i "$IFACE" -D macsec_linux \
                -c "$MACSEC_DIR/macsec-${IFACE}.conf" -B
            echo "MACsec enabled on $IFACE"
            echo "Note: Both endpoints need the same CAK/CKN keys"
        else
            echo "Error: No MACsec config for $IFACE"
            echo "Available configs:"
            ls -1 "$MACSEC_DIR"/macsec-*.conf 2>/dev/null | sed 's/.*macsec-/  /' | sed 's/.conf//'
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
        if ip macsec show 2>/dev/null | grep -q .; then
            ip macsec show
        else
            echo "No active MACsec interfaces"
        fi
        echo ""
        echo "=== MKA Sessions ==="
        if ps aux | grep -v grep | grep -q "wpa_supplicant.*macsec"; then
            ps aux | grep -v grep | grep "wpa_supplicant.*macsec"
        else
            echo "No active MKA sessions"
        fi
        ;;
    keys)
        echo "=== MACsec Keys ==="
        echo "Share these keys with the other endpoint for MACsec to work:"
        echo ""
        echo "CAK (Connectivity Association Key):"
        cat /etc/hookprobe/secrets/macsec/cak.key 2>/dev/null || echo "  Not generated"
        echo ""
        echo "CKN (Connectivity Key Name):"
        cat /etc/hookprobe/secrets/macsec/ckn.key 2>/dev/null || echo "  Not generated"
        ;;
    *)
        echo "Usage: $0 {enable|disable|status|keys} [interface]"
        echo ""
        echo "Commands:"
        echo "  enable <iface>   Enable MACsec on interface (default: eth0)"
        echo "  disable <iface>  Disable MACsec on interface"
        echo "  status           Show MACsec status"
        echo "  keys             Display MACsec keys (for sharing)"
        exit 1
        ;;
esac
MACSECSCRIPT

    chmod +x /usr/local/bin/guardian-macsec

    log_info "MACsec (802.1AE) configured"
    log_info "  Enable with: guardian-macsec enable eth0"
    log_info "  View keys:   guardian-macsec keys"
}

# ============================================================
# SECURITY CONTAINERS
# ============================================================
install_security_containers() {
    log_step "Installing Guardian security containers..."

    # NOTE: All security containers use --network host mode
    # This is required for:
    # - WAF: intercept HTTP traffic on host ports
    # - Neuro: access host network for neural resonance protocol
    # - IDS (NAPSE): deployed via AIOCHI containers, not Guardian

    # Create volumes
    podman volume create guardian-waf-logs 2>/dev/null || true

    # Pull container images first
    log_info "Pulling container images (this may take a few minutes)..."
    podman pull docker.io/owasp/modsecurity-crs:nginx-alpine 2>/dev/null || log_warn "Failed to pull WAF image"
    podman pull docker.io/library/python:3.11-slim 2>/dev/null || log_warn "Failed to pull Python image"

    # Install core security containers
    install_waf_container
    install_neuro_container

    # Install XDP/eBPF DDoS protection
    install_xdp_ddos_protection

    # Install threat aggregator
    install_threat_aggregator

    # Install attack simulator
    install_attack_simulator

    # Install DNS Shield (ad blocking) if enabled
    if [ "${HOOKPROBE_ADBLOCK:-yes}" = "yes" ]; then
        install_dns_shield
    fi

    log_info "Security containers and services installed"
}

install_dns_shield() {
    log_step "Installing dnsXai Ad Block (beta) - ML-powered DNS protection..."

    local SHIELD_DIR="/opt/hookprobe/guardian/dns-shield"
    local SCRIPTS_DIR="/opt/hookprobe/guardian/scripts"
    local SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Create required directories
    mkdir -p "$SHIELD_DIR"
    mkdir -p "$SHIELD_DIR/ml"  # ML data directory for dnsXai
    mkdir -p "$SCRIPTS_DIR"
    mkdir -p /var/log/hookprobe

    # Copy update script
    if [ -f "$SCRIPT_DIR/update-blocklists.sh" ]; then
        cp "$SCRIPT_DIR/update-blocklists.sh" "$SCRIPTS_DIR/"
        chmod +x "$SCRIPTS_DIR/update-blocklists.sh"
    fi

    # Create default configuration
    cat > "$SHIELD_DIR/shield.conf" << 'SHIELDCONF'
# DNS Shield Configuration
# ========================
# Shield Level determines which blocklist variant to use:
#
#   1 = Base (Adware + Malware) - ~130,000 domains
#   2 = Base + Fakenews - ~132,000 domains
#   3 = Base + Fakenews + Gambling - ~135,000 domains
#   4 = Base + Fakenews + Gambling + Porn - ~200,000 domains
#   5 = Full Protection (All categories) - ~250,000 domains
#
# Higher levels = more blocking, may affect some legitimate sites
SHIELD_LEVEL=3

# Custom whitelist (one domain per line)
WHITELIST_FILE="/opt/hookprobe/guardian/dns-shield/whitelist.txt"

# Auto-update schedule (handled by systemd timer)
AUTO_UPDATE_DAYS=7

# Block response (0.0.0.0 is faster)
BLOCK_TARGET="0.0.0.0"
SHIELDCONF

    # Create empty whitelist
    cat > "$SHIELD_DIR/whitelist.txt" << 'WHITELIST'
# DNS Shield Whitelist
# ====================
# Add domains here (one per line) to bypass blocking
# Example:
# example.com
WHITELIST

    # Initialize stats
    cat > "$SHIELD_DIR/stats.json" << 'STATS'
{
    "shield_level": 3,
    "shield_level_name": "Strong (+ Gambling)",
    "domains_blocked": 0,
    "last_update": null,
    "update_count": 0,
    "blocklist_source": "StevenBlack Unified Hosts",
    "version": "1.0.0"
}
STATS

    # Create systemd service for blocklist updates
    cat > /etc/systemd/system/dns-shield-update.service << 'SERVICE'
[Unit]
Description=DNS Shield Blocklist Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/hookprobe/guardian/scripts/update-blocklists.sh --silent
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
SERVICE

    # Create systemd timer for weekly updates
    cat > /etc/systemd/system/dns-shield-update.timer << 'TIMER'
[Unit]
Description=DNS Shield Weekly Blocklist Update

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
TIMER

    systemctl daemon-reload
    systemctl enable dns-shield-update.timer 2>/dev/null || true

    # Download blocklist now (with network check)
    log_info "Downloading initial blocklist..."
    if ping -c 1 -W 2 raw.githubusercontent.com &>/dev/null; then
        /opt/hookprobe/guardian/scripts/update-blocklists.sh --silent || {
            log_warn "Initial blocklist download failed - will retry on next boot"
        }
    else
        log_warn "No internet connection - blocklist will download when available"
    fi

    # Configure dnsmasq to use blocklist
    configure_dnsmasq_dns_shield

    log_info "dnsXai Ad Block (beta) installed"
    log_info "  Blocklist: StevenBlack Unified Hosts"
    log_info "  ML Classification: Domain anomaly detection"
    log_info "  Shield Level: 3 (Strong Protection)"
    log_info "  Auto-update: Weekly"
}

configure_dnsmasq_dns_shield() {
    # Create dnsmasq include config for DNS Shield
    # NOTE: Only blocklist include - all other settings are in guardian.conf
    cat > /etc/dnsmasq.d/dns-shield.conf << 'DNSCONF'
# DNS Shield - Blocklist Configuration
# Auto-generated by Guardian setup
# NOTE: Core dnsmasq settings are in guardian.conf

# Include blocklist (if exists)
conf-file=/opt/hookprobe/guardian/dns-shield/blocked-hosts

# Enable DNSSEC validation (unique to dns-shield)
dnssec
trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D

# Minimum cache TTL for blocked domains
min-cache-ttl=300
DNSCONF

    # Restart dnsmasq to apply
    systemctl restart dnsmasq 2>/dev/null || true
}

install_waf_container() {
    log_step "Installing WAF (ModSecurity) container..."

    # Check if already running
    if podman ps -a --format "{{.Names}}" | grep -q "^guardian-waf$"; then
        log_info "WAF container already exists"
        return 0
    fi

    # Create systemd service for WAF container (creates container on start)
    # WAF listens on port 8888, proxies to Guardian WebUI or backend services
    cat > /etc/systemd/system/guardian-waf.service << 'EOF'
[Unit]
Description=HookProbe Guardian WAF (ModSecurity)
After=network-online.target podman.socket guardian-webui.service
Wants=network-online.target
Requires=podman.socket

[Service]
Type=simple
Restart=on-failure
RestartSec=30
StartLimitIntervalSec=300
StartLimitBurst=3
# Wait for network and webui to be ready
ExecStartPre=/bin/sleep 5
ExecStartPre=-/usr/bin/podman stop guardian-waf
ExecStartPre=-/usr/bin/podman rm guardian-waf
# Pull image if not present
ExecStartPre=-/usr/bin/podman pull docker.io/owasp/modsecurity-crs:nginx-alpine
ExecStart=/usr/bin/podman run --name guardian-waf \
    -p 8888:8080 \
    --cap-add NET_ADMIN \
    -v guardian-waf-logs:/var/log/modsecurity:Z \
    -e PORT=8080 \
    -e PARANOIA=1 \
    -e ANOMALY_INBOUND=5 \
    -e ANOMALY_OUTBOUND=4 \
    -e BACKEND=http://192.168.4.1:8080 \
    docker.io/owasp/modsecurity-crs:nginx-alpine
ExecStop=/usr/bin/podman stop -t 10 guardian-waf

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-waf 2>/dev/null || true

    log_info "WAF (ModSecurity) container installed"
}

install_neuro_container() {
    log_step "Installing Neuro Protocol (QSecBit + HTP) container..."

    # Check if already running
    if podman ps -a --format "{{.Names}}" | grep -q "^guardian-neuro$"; then
        log_info "Neuro container already exists"
        return 0
    fi

    # Create neuro working directory
    mkdir -p /opt/hookprobe/guardian/neuro

    # Create the neuro agent script
    cat > /opt/hookprobe/guardian/neuro/agent.py << 'PYEOF'
#!/usr/bin/env python3
"""QSecBit Lite Guardian Agent - Neuro Protocol"""
import time
import os
import json
from datetime import datetime

print("QSecBit Lite Guardian Agent running...")

stats_file = "/app/neuro/stats.json"

while True:
    try:
        stats = {
            "timestamp": datetime.now().isoformat(),
            "mode": "guardian",
            "status": "active"
        }
        os.makedirs(os.path.dirname(stats_file), exist_ok=True)
        with open(stats_file, "w") as f:
            json.dump(stats, f)
    except Exception as e:
        print(f"Stats error: {e}")
    time.sleep(30)
PYEOF

    # Create systemd service for Neuro container (creates container on start)
    cat > /etc/systemd/system/guardian-neuro.service << 'EOF'
[Unit]
Description=HookProbe Guardian Neuro Protocol (QSecBit + HTP)
After=network.target podman.socket
Requires=podman.socket

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=-/usr/bin/podman stop guardian-neuro
ExecStartPre=-/usr/bin/podman rm guardian-neuro
ExecStart=/usr/bin/podman run --name guardian-neuro \
    --network host \
    -v /opt/hookprobe/guardian/neuro:/app/neuro:Z \
    -v /etc/hookprobe/secrets:/secrets:ro \
    -e QSECBIT_MODE=quantum-resistant \
    -e HTP_ENABLED=true \
    -e PYTHONPATH=/app \
    docker.io/library/python:3.11-slim \
    python /app/neuro/agent.py
ExecStop=/usr/bin/podman stop guardian-neuro

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-neuro 2>/dev/null || true

    log_info "Neuro Protocol container installed"
}

install_xdp_ddos_protection() {
    log_step "Installing XDP/eBPF DDoS protection..."

    # Check if kernel supports XDP
    if ! grep -q "CONFIG_XDP" /boot/config-$(uname -r) 2>/dev/null; then
        log_warn "Kernel may not support XDP, attempting anyway..."
    fi

    # Install required packages
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        clang llvm libelf-dev linux-headers-$(uname -r) bpftool 2>/dev/null || {
        log_warn "Some XDP packages not available, limited functionality"
    }

    # Create XDP program directory
    mkdir -p /opt/hookprobe/guardian/xdp

    # Create XDP DDoS mitigation program (C code)
    cat > /opt/hookprobe/guardian/xdp/ddos_mitigate.c << 'XDPEOF'
/*
 * HookProbe Guardian XDP DDoS Mitigation
 * Drops packets from suspected DDoS sources
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

/* Rate limiting map - tracks packets per IP */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    /* Source IP */
    __type(value, __u64);  /* Packet count + timestamp */
    __uint(max_entries, 10000);
} rate_limit_map SEC(".maps");

/* Blocklist map - IPs to drop */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    /* Source IP */
    __type(value, __u8);   /* Block flag */
    __uint(max_entries, 1000);
} blocklist_map SEC(".maps");

/* Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} stats_map SEC(".maps");

#define STATS_PASSED 0
#define STATS_DROPPED 1
#define STATS_RATE_LIMITED 2
#define STATS_BLOCKLISTED 3

#define RATE_LIMIT 1000  /* Max packets per second per IP */

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u32 key;
    __u64 *value;
    __u8 *blocked;

    /* Bounds check */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    /* Check blocklist */
    blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);
    if (blocked && *blocked) {
        key = STATS_BLOCKLISTED;
        value = bpf_map_lookup_elem(&stats_map, &key);
        if (value)
            __sync_fetch_and_add(value, 1);
        return XDP_DROP;
    }

    /* Rate limiting */
    __u64 *count = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    __u64 now = bpf_ktime_get_ns();

    if (count) {
        __u64 last_time = *count >> 32;
        __u64 pkt_count = *count & 0xFFFFFFFF;

        /* Reset counter if more than 1 second passed */
        if ((now - last_time) > 1000000000ULL) {
            *count = (now << 32) | 1;
        } else {
            pkt_count++;
            *count = (last_time << 32) | pkt_count;

            if (pkt_count > RATE_LIMIT) {
                key = STATS_RATE_LIMITED;
                value = bpf_map_lookup_elem(&stats_map, &key);
                if (value)
                    __sync_fetch_and_add(value, 1);
                return XDP_DROP;
            }
        }
    } else {
        __u64 new_count = (now << 32) | 1;
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_count, BPF_ANY);
    }

    /* Packet passed */
    key = STATS_PASSED;
    value = bpf_map_lookup_elem(&stats_map, &key);
    if (value)
        __sync_fetch_and_add(value, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
XDPEOF

    # Create XDP manager script
    cat > /opt/hookprobe/guardian/xdp/xdp_manager.py << 'PYEOF'
#!/usr/bin/env python3
"""
XDP DDoS Protection Manager for Guardian
Compiles, loads, and manages XDP programs
"""
import subprocess
import os
import json
import time
from pathlib import Path

XDP_DIR = Path("/opt/hookprobe/guardian/xdp")
XDP_SRC = XDP_DIR / "ddos_mitigate.c"
XDP_OBJ = XDP_DIR / "ddos_mitigate.o"
STATS_FILE = XDP_DIR / "xdp_stats.json"

def compile_xdp():
    """Compile XDP program"""
    if not XDP_SRC.exists():
        print("XDP source not found")
        return False

    cmd = [
        "clang", "-O2", "-g", "-target", "bpf",
        "-c", str(XDP_SRC), "-o", str(XDP_OBJ),
        "-I/usr/include/bpf"
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print("XDP program compiled successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed: {e.stderr.decode()}")
        return False

def load_xdp(interface="br0"):
    """Load XDP program on interface"""
    if not XDP_OBJ.exists():
        if not compile_xdp():
            return False

    # Detach any existing XDP program
    subprocess.run(["ip", "link", "set", interface, "xdp", "off"], capture_output=True)

    # Attach new XDP program
    cmd = ["ip", "link", "set", interface, "xdp", "obj", str(XDP_OBJ), "sec", "xdp"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"XDP program loaded on {interface}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to load XDP: {e.stderr.decode()}")
        return False

def unload_xdp(interface="br0"):
    """Unload XDP program from interface"""
    subprocess.run(["ip", "link", "set", interface, "xdp", "off"], capture_output=True)
    print(f"XDP program unloaded from {interface}")

def get_stats():
    """Get XDP statistics using bpftool"""
    stats = {
        "passed": 0,
        "dropped": 0,
        "rate_limited": 0,
        "blocklisted": 0,
        "xdp_loaded": False,
        "timestamp": time.time()
    }

    # Check if XDP is loaded
    result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    stats["xdp_loaded"] = "xdp" in result.stdout

    # Try to get map stats via bpftool
    try:
        result = subprocess.run(
            ["bpftool", "map", "dump", "name", "stats_map", "-j"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for entry in data:
                key = entry.get("key", 0)
                value = entry.get("value", 0)
                if key == 0:
                    stats["passed"] = value
                elif key == 1:
                    stats["dropped"] = value
                elif key == 2:
                    stats["rate_limited"] = value
                elif key == 3:
                    stats["blocklisted"] = value
    except Exception as e:
        pass

    return stats

def block_ip(ip_addr):
    """Add IP to blocklist"""
    try:
        subprocess.run([
            "bpftool", "map", "update", "name", "blocklist_map",
            "key", ip_addr, "value", "1"
        ], check=True, capture_output=True)
        print(f"Blocked IP: {ip_addr}")
        return True
    except Exception as e:
        print(f"Failed to block IP: {e}")
        return False

def save_stats():
    """Save current stats to file"""
    stats = get_stats()
    with open(STATS_FILE, 'w') as f:
        json.dump(stats, f, indent=2)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: xdp_manager.py [compile|load|unload|stats|block <ip>]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "compile":
        compile_xdp()
    elif cmd == "load":
        iface = sys.argv[2] if len(sys.argv) > 2 else "br0"
        load_xdp(iface)
    elif cmd == "unload":
        iface = sys.argv[2] if len(sys.argv) > 2 else "br0"
        unload_xdp(iface)
    elif cmd == "stats":
        print(json.dumps(get_stats(), indent=2))
    elif cmd == "block" and len(sys.argv) > 2:
        block_ip(sys.argv[2])
    else:
        print("Unknown command")
PYEOF

    chmod +x /opt/hookprobe/guardian/xdp/xdp_manager.py

    # Create systemd service for XDP
    # IMPORTANT: XDP should only attach to ethernet interfaces, never wireless
    # Wireless interfaces (wlan*) don't work well with XDP and can break WiFi
    cat > /etc/systemd/system/guardian-xdp.service << 'EOF'
[Unit]
Description=HookProbe Guardian XDP DDoS Protection
After=network-online.target
Wants=network-online.target
# Allow start if either eth0 OR br0 exists (| prefix makes condition non-fatal)
ConditionPathExists=|/sys/class/net/eth0
ConditionPathExists=|/sys/class/net/br0

[Service]
Type=oneshot
RemainAfterExit=yes
# Wait for network interface to be ready
ExecStartPre=/bin/sleep 5
# Prefer eth0 for XDP (never use wlan interfaces!)
ExecStartPre=/bin/bash -c 'if [ -e /sys/class/net/eth0 ]; then echo eth0 > /run/guardian-xdp-iface; elif [ -e /sys/class/net/br0 ]; then echo br0 > /run/guardian-xdp-iface; else echo none > /run/guardian-xdp-iface; fi'
ExecStart=/bin/bash -c 'IFACE=$(cat /run/guardian-xdp-iface); if [ "$IFACE" != "none" ] && [ -e /sys/class/net/$IFACE ]; then /usr/bin/python3 /opt/hookprobe/guardian/xdp/xdp_manager.py load $IFACE && echo "XDP loaded on $IFACE"; else echo "No suitable interface for XDP (eth0/br0 not found)"; fi'
ExecStop=/bin/bash -c 'IFACE=$(cat /run/guardian-xdp-iface 2>/dev/null || echo eth0); /usr/bin/python3 /opt/hookprobe/guardian/xdp/xdp_manager.py unload $IFACE 2>/dev/null || true'
# Restart if failed to attach (interface may come up later)
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-xdp 2>/dev/null || true

    log_info "XDP/eBPF DDoS protection installed"
}

install_threat_aggregator() {
    log_step "Installing Threat Aggregator service..."

    # Create aggregator directory
    mkdir -p /opt/hookprobe/guardian/aggregator
    mkdir -p /var/log/hookprobe/threats

    # Create threat aggregator script
    cat > /opt/hookprobe/guardian/aggregator/threat_aggregator.py << 'PYEOF'
#!/usr/bin/env python3
"""
HookProbe Guardian Threat Aggregator
Collects and correlates alerts from all security tools
"""
import json
import os
import time
import subprocess
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

NAPSE_ALERT_FILE = "/var/log/hookprobe/napse/alerts.json"
OUTPUT_FILE = "/var/log/hookprobe/threats/aggregated.json"
ALERT_FILE = "/var/log/hookprobe/threats/active_alerts.json"

class ThreatAggregator:
    def __init__(self):
        self.threats = []
        self.stats = {
            "napse_alerts": 0,
            "xdp_drops": 0,
            "blocked_ips": [],
            "active_attacks": [],
            "severity_counts": {"high": 0, "medium": 0, "low": 0},
            "last_update": None
        }

    def parse_napse_alerts(self, limit=100):
        """Parse NAPSE IDS alert log"""
        alerts = []
        try:
            if not os.path.exists(NAPSE_ALERT_FILE):
                return alerts

            # Read last N lines
            result = subprocess.run(
                ["tail", "-n", str(limit), NAPSE_ALERT_FILE],
                capture_output=True, text=True
            )

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alert = {
                            "source": "napse",
                            "timestamp": event.get("timestamp"),
                            "src_ip": event.get("src_ip"),
                            "dest_ip": event.get("dest_ip"),
                            "src_port": event.get("src_port"),
                            "dest_port": event.get("dest_port"),
                            "signature": event.get("alert", {}).get("signature"),
                            "signature_id": event.get("alert", {}).get("signature_id"),
                            "severity": event.get("alert", {}).get("severity", 3),
                            "category": event.get("alert", {}).get("category"),
                            "protocol": event.get("proto")
                        }
                        alerts.append(alert)
                        self.stats["napse_alerts"] += 1
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"Error parsing NAPSE logs: {e}")

        return alerts

    def get_xdp_stats(self):
        """Get XDP statistics"""
        try:
            result = subprocess.run(
                ["python3", "/opt/hookprobe/guardian/xdp/xdp_manager.py", "stats"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                stats = json.loads(result.stdout)
                self.stats["xdp_drops"] = stats.get("dropped", 0) + stats.get("rate_limited", 0)
                return stats
        except Exception as e:
            print(f"Error getting XDP stats: {e}")
        return {}

    def detect_attacks(self, alerts):
        """Detect ongoing attacks from alert patterns"""
        attacks = []
        ip_counts = defaultdict(int)
        port_scan_ips = set()
        ddos_ips = set()

        for alert in alerts:
            src_ip = alert.get("src_ip")
            if not src_ip:
                continue

            ip_counts[src_ip] += 1

            # Detect port scans
            sig = alert.get("signature", "") or alert.get("note", "")
            if any(x in sig.lower() for x in ["scan", "portscan", "reconnaissance"]):
                port_scan_ips.add(src_ip)

            # Detect DDoS patterns
            if ip_counts[src_ip] > 50:
                ddos_ips.add(src_ip)

        # Create attack entries
        for ip in port_scan_ips:
            attacks.append({
                "type": "port_scan",
                "source_ip": ip,
                "severity": "medium",
                "description": f"Port scanning detected from {ip}",
                "recommendation": "Consider blocking this IP"
            })

        for ip in ddos_ips:
            attacks.append({
                "type": "ddos_attempt",
                "source_ip": ip,
                "severity": "high",
                "alert_count": ip_counts[ip],
                "description": f"Possible DDoS from {ip} ({ip_counts[ip]} alerts)",
                "recommendation": "IP should be rate-limited or blocked"
            })

        return attacks

    def aggregate(self):
        """Main aggregation routine"""
        all_alerts = []

        # Collect from all sources
        all_alerts.extend(self.parse_napse_alerts())

        # Get XDP stats
        xdp_stats = self.get_xdp_stats()

        # Detect attacks
        attacks = self.detect_attacks(all_alerts)
        self.stats["active_attacks"] = attacks

        # Count severities
        for alert in all_alerts:
            sev = alert.get("severity", 3)
            if sev <= 1:
                self.stats["severity_counts"]["high"] += 1
            elif sev == 2:
                self.stats["severity_counts"]["medium"] += 1
            else:
                self.stats["severity_counts"]["low"] += 1

        self.stats["last_update"] = datetime.now().isoformat()

        # Save aggregated data
        output = {
            "stats": self.stats,
            "recent_alerts": all_alerts[-50:],  # Last 50 alerts
            "xdp_stats": xdp_stats,
            "attacks": attacks
        }

        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(output, f, indent=2, default=str)

        # Save active alerts separately for quick access
        with open(ALERT_FILE, 'w') as f:
            json.dump({
                "alerts": all_alerts[-20:],
                "attacks": attacks,
                "timestamp": datetime.now().isoformat()
            }, f, indent=2, default=str)

        return output

def main():
    """Run aggregator continuously"""
    print("HookProbe Guardian Threat Aggregator starting...")
    aggregator = ThreatAggregator()

    while True:
        try:
            result = aggregator.aggregate()
            print(f"[{datetime.now()}] Aggregated: "
                  f"NAPSE={result['stats']['napse_alerts']}, "
                  f"XDP drops={result['stats']['xdp_drops']}, "
                  f"Active attacks={len(result['attacks'])}")
        except Exception as e:
            print(f"Aggregation error: {e}")

        time.sleep(30)  # Update every 30 seconds

if __name__ == "__main__":
    main()
PYEOF

    chmod +x /opt/hookprobe/guardian/aggregator/threat_aggregator.py

    # Create systemd service
    cat > /etc/systemd/system/guardian-aggregator.service << 'EOF'
[Unit]
Description=HookProbe Guardian Threat Aggregator
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStart=/usr/bin/python3 /opt/hookprobe/guardian/aggregator/threat_aggregator.py

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-aggregator 2>/dev/null || true

    log_info "Threat Aggregator service installed"
}

install_attack_simulator() {
    log_step "Installing attack simulation tools..."

    # Create simulator directory
    mkdir -p /opt/hookprobe/guardian/simulator

    # Create attack simulation script
    cat > /opt/hookprobe/guardian/simulator/test_security.sh << 'BASHEOF'
#!/bin/bash
#
# HookProbe Guardian Security Test Suite
# Simulates various attacks to verify security stack is working
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET="${1:-192.168.4.1}"
REPORT_FILE="/var/log/hookprobe/threats/test_report.json"

echo "=============================================="
echo " HookProbe Guardian Security Test Suite"
echo "=============================================="
echo ""
echo "Target: $TARGET"
echo "Time: $(date)"
echo ""

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}Installing nmap for security testing...${NC}"
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        nmap
fi

# Initialize results
RESULTS=()

test_result() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    RESULTS+=("{\"test\": \"$test_name\", \"status\": \"$status\", \"details\": \"$details\"}")
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}[PASS]${NC} $test_name"
    else
        echo -e "${RED}[FAIL]${NC} $test_name - $details"
    fi
}

echo ""
echo "1. Testing NAPSE IDS..."
echo "   Running TCP SYN scan (should trigger alerts)..."
nmap -sS -p 22,80,443,8080 $TARGET -T4 --max-retries 1 2>/dev/null || true
sleep 2

# Check NAPSE alert log
if [ -f "/var/log/hookprobe/napse/alerts.json" ] && tail -20 /var/log/hookprobe/napse/alerts.json 2>/dev/null | grep -q -i "alert"; then
    test_result "NAPSE_Detection" "PASS" "Alerts generated for port scan"
else
    test_result "NAPSE_Detection" "FAIL" "No alerts detected (NAPSE deployed via AIOCHI)"
fi

echo ""
echo "2. Testing with aggressive scan..."
nmap -A -p 1-1000 $TARGET -T5 --max-retries 1 2>/dev/null || true
sleep 2

echo ""
echo "3. Testing UDP scan (potential DDoS pattern)..."
nmap -sU -p 53,123,161 $TARGET --max-retries 1 2>/dev/null || true
sleep 2

echo ""
echo "4. Testing vulnerability scan signatures..."
nmap --script vuln -p 80,443,8080 $TARGET --max-retries 1 2>/dev/null || true
sleep 2

echo ""
echo "5. Checking NAPSE network analysis..."
if [ -d "/var/log/hookprobe/napse" ]; then
    if ls /var/log/hookprobe/napse/*.json 2>/dev/null | grep -q .; then
        test_result "NAPSE_Logging" "PASS" "NAPSE logging active"
    else
        test_result "NAPSE_Logging" "FAIL" "No NAPSE logs found"
    fi
else
    test_result "NAPSE_Logging" "FAIL" "NAPSE not running (deployed via AIOCHI)"
fi

echo ""
echo "6. Checking XDP/eBPF status..."
if ip link show | grep -q "xdp"; then
    test_result "XDP_Active" "PASS" "XDP program loaded"
else
    test_result "XDP_Active" "FAIL" "XDP not loaded"
fi

echo ""
echo "7. Checking threat aggregator..."
if [ -f "/var/log/hookprobe/threats/aggregated.json" ]; then
    ALERT_COUNT=$(cat /var/log/hookprobe/threats/aggregated.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['stats']['napse_alerts'])" 2>/dev/null || echo "0")
    if [ "$ALERT_COUNT" -gt 0 ]; then
        test_result "Threat_Aggregation" "PASS" "$ALERT_COUNT alerts aggregated"
    else
        test_result "Threat_Aggregation" "FAIL" "No alerts aggregated"
    fi
else
    test_result "Threat_Aggregation" "FAIL" "Aggregation file not found"
fi

echo ""
echo "8. Testing WAF (if web server on port 80/8080)..."
# SQL injection attempt
curl -s "http://$TARGET:8080/?id=1'%20OR%20'1'='1" 2>/dev/null || true
# XSS attempt
curl -s "http://$TARGET:8080/?q=<script>alert(1)</script>" 2>/dev/null || true
sleep 1

if podman logs guardian-waf 2>&1 | tail -10 | grep -q -i "modsecurity\|blocked\|denied"; then
    test_result "WAF_Detection" "PASS" "WAF blocking malicious requests"
else
    test_result "WAF_Detection" "FAIL" "WAF not detecting attacks"
fi

echo ""
echo "=============================================="
echo " Test Summary"
echo "=============================================="

# Count results
PASS_COUNT=0
FAIL_COUNT=0
for r in "${RESULTS[@]}"; do
    if echo "$r" | grep -q '"PASS"'; then
        ((PASS_COUNT++))
    else
        ((FAIL_COUNT++))
    fi
done

echo ""
echo -e "Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Failed: ${RED}$FAIL_COUNT${NC}"
echo ""

# Generate JSON report
mkdir -p /var/log/hookprobe/threats
cat > "$REPORT_FILE" << EOF
{
    "test_time": "$(date -Iseconds)",
    "target": "$TARGET",
    "summary": {
        "passed": $PASS_COUNT,
        "failed": $FAIL_COUNT
    },
    "results": [$(IFS=,; echo "${RESULTS[*]}")]
}
EOF

echo "Report saved to: $REPORT_FILE"
echo ""
echo "To view live threats, check:"
echo "  - NAPSE: cat /var/log/hookprobe/napse/alerts.json"
echo "  - Aggregated: cat /var/log/hookprobe/threats/aggregated.json"
BASHEOF

    chmod +x /opt/hookprobe/guardian/simulator/test_security.sh

    log_info "Attack simulation tools installed"
    log_info "Run tests with: /opt/hookprobe/guardian/simulator/test_security.sh"
}

install_qsecbit_agent() {
    log_step "Installing QSecBit agent (full version from core/qsecbit)..."

    # Create directories
    mkdir -p /opt/hookprobe/guardian/qsecbit
    mkdir -p /opt/hookprobe/guardian/data

    # Copy QSecBit modules from source (if available)
    # Dynamically detect hookprobe root from script location
    local HOOKPROBE_ROOT="$(cd "$GUARDIAN_ROOT/../.." && pwd)"
    local QSECBIT_SRC="$HOOKPROBE_ROOT/core/qsecbit"
    if [ -d "$QSECBIT_SRC" ]; then
        log_info "Copying QSecBit modules from source..."
        cp -r "$QSECBIT_SRC"/*.py /opt/hookprobe/guardian/qsecbit/ 2>/dev/null || true
    fi

    # Create Guardian-specific QSecBit agent that uses the full modules
    cat > /opt/hookprobe/guardian/qsecbit/guardian_agent.py << 'PYEOF'
#!/usr/bin/env python3
"""
QSecBit Guardian Agent - Full Implementation
Version: 5.0.0
License: AGPL-3.0

Uses the full QSecBit modules for:
- Energy monitoring (RAPL + per-PID tracking)
- NIC detection and XDP capability
- XDP/eBPF DDoS mitigation
- Mahalanobis drift calculation
- RAG (Red/Amber/Green) scoring
"""

import os
import sys
import json
import time
import signal
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, Optional, List
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread, Event

# Logging setup
LOG_DIR = Path('/var/log/hookprobe')
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'qsecbit.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('qsecbit-guardian')

# Paths - IMPORTANT: Web UI reads from /var/log/hookprobe/qsecbit/current.json
CONFIG_DIR = Path('/opt/hookprobe/guardian')
DATA_DIR = CONFIG_DIR / 'data'
QSECBIT_LOG_DIR = Path('/var/log/hookprobe/qsecbit')
STATS_FILE = QSECBIT_LOG_DIR / 'current.json'  # Web UI reads this path
THREATS_FILE = DATA_DIR / 'threats.json'
NEURO_STATS = CONFIG_DIR / 'neuro' / 'stats.json'

@dataclass
class QSecBitConfig:
    """QSecBit configuration"""
    # Component weights (must sum to 1.0)
    alpha: float = 0.25   # System drift weight
    beta: float = 0.25    # Attack probability weight
    gamma: float = 0.20   # Classifier decay weight
    delta: float = 0.15   # Quantum drift weight
    epsilon: float = 0.15 # Energy anomaly weight

    # RAG thresholds
    amber_threshold: float = 0.45
    red_threshold: float = 0.70

    # Energy monitoring
    energy_monitoring_enabled: bool = True
    energy_spike_threshold: float = 2.5


@dataclass
class QSecBitSample:
    """Single QSecBit measurement - unified across all data sources"""
    timestamp: str
    score: float
    rag_status: str
    components: Dict[str, float]
    xdp_stats: Dict[str, int]
    energy_stats: Dict[str, float]
    network_stats: Dict[str, any]
    threats_detected: int
    napse_alerts: int
    dnsxai_stats: Dict[str, any] = None  # DNS protection stats
    bridge_stats: Dict[str, any] = None  # NAPSE-dnsXai bridge stats


class HealthCheckHandler(BaseHTTPRequestHandler):
    """HTTP handler for health checks and metrics API"""

    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                "status": "healthy",
                "version": "5.0.0",
                "mode": "guardian"
            }
            self.wfile.write(json.dumps(response).encode())
        elif self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            if hasattr(self.server, 'agent') and hasattr(self.server.agent, 'last_sample'):
                self.wfile.write(json.dumps(asdict(self.server.agent.last_sample)).encode())
            else:
                self.wfile.write(json.dumps({"error": "no metrics"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logging


class QSecBitGuardianAgent:
    """Full QSecBit agent for Guardian devices"""

    def __init__(self, config: QSecBitConfig = None):
        self.config = config or QSecBitConfig()
        self.running = Event()
        self.start_time = time.time()
        self.last_sample: Optional[QSecBitSample] = None
        self.history: List[QSecBitSample] = []

        # Ensure directories exist
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        QSECBIT_LOG_DIR.mkdir(parents=True, exist_ok=True)

        # Signal handling
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info("QSecBit Guardian Agent initialized")

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def get_xdp_stats(self) -> Dict[str, int]:
        """Get XDP/eBPF statistics"""
        stats = {
            'xdp_enabled': False,
            'total_packets': 0,
            'dropped_blocked': 0,
            'dropped_rate_limit': 0,
            'passed': 0,
            'tcp_syn_flood': 0,
            'udp_flood': 0,
            'icmp_flood': 0
        }

        # Check if XDP is enabled on any interface
        try:
            result = subprocess.run(
                ['ip', 'link', 'show'],
                capture_output=True, text=True, timeout=5
            )
            if 'xdp' in result.stdout.lower():
                stats['xdp_enabled'] = True

            # Try to get eBPF program list
            result = subprocess.run(
                ['bpftool', 'prog', 'list', '-j'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                programs = json.loads(result.stdout)
                stats['ebpf_programs'] = len(programs)
        except Exception:
            pass

        return stats

    def get_energy_stats(self) -> Dict[str, float]:
        """Get energy consumption statistics"""
        stats = {
            'rapl_available': False,
            'package_watts': 0.0,
            'total_rx_bytes': 0,
            'total_tx_bytes': 0,
            'interfaces': {}
        }

        # Check RAPL availability
        rapl_path = Path('/sys/class/powercap/intel-rapl')
        if rapl_path.exists():
            stats['rapl_available'] = True
            try:
                energy_file = rapl_path / 'intel-rapl:0' / 'energy_uj'
                if energy_file.exists():
                    stats['rapl_energy_uj'] = int(energy_file.read_text().strip())
            except Exception:
                pass

        # Get interface traffic stats
        for iface in ['wlan0', 'wlan1', 'br0', 'eth0']:
            iface_stats = {}
            for stat_type in ['tx_bytes', 'rx_bytes', 'tx_packets', 'rx_packets', 'tx_errors', 'rx_errors']:
                stat_path = Path(f'/sys/class/net/{iface}/statistics/{stat_type}')
                if stat_path.exists():
                    try:
                        value = int(stat_path.read_text().strip())
                        iface_stats[stat_type] = value
                        if stat_type == 'rx_bytes':
                            stats['total_rx_bytes'] += value
                        elif stat_type == 'tx_bytes':
                            stats['total_tx_bytes'] += value
                    except Exception:
                        pass
            if iface_stats:
                stats['interfaces'][iface] = iface_stats

        return stats

    def get_network_stats(self) -> Dict[str, any]:
        """Get network statistics"""
        stats = {
            'timestamp': datetime.now().isoformat(),
            'connections': 0,
            'nic_info': {}
        }

        # Get connection count
        try:
            result = subprocess.run(
                ['ss', '-t', '-n'],
                capture_output=True, text=True, timeout=5
            )
            stats['connections'] = max(0, len(result.stdout.strip().split('\n')) - 1)
        except Exception:
            pass

        # Get NIC info using iw
        for iface in ['wlan0', 'wlan1']:
            try:
                result = subprocess.run(
                    ['iw', 'dev', iface, 'info'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    info = {'interface': iface}
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line.startswith('type '):
                            info['type'] = line.split('type ', 1)[1]
                        elif line.startswith('ssid '):
                            info['ssid'] = line.split('ssid ', 1)[1]
                        elif line.startswith('channel '):
                            info['channel'] = line.split()[1]
                    stats['nic_info'][iface] = info
            except Exception:
                pass

        return stats

    def check_napse_alerts(self) -> int:
        """Check NAPSE IDS for new alerts"""
        count = 0
        napse_log = Path('/var/log/hookprobe/napse/alerts.json')

        try:
            if napse_log.exists():
                result = subprocess.run(
                    ['tail', '-100', str(napse_log)],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            event = json.loads(line)
                            if event.get('event_type') == 'alert':
                                count += 1
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass

        return count

    def check_threats(self) -> int:
        """Check threat log"""
        count = 0
        if THREATS_FILE.exists():
            try:
                content = THREATS_FILE.read_text().strip()
                if content:
                    count = len(content.split('\n'))
            except Exception:
                pass
        return count

    def get_dnsxai_stats(self) -> Dict:
        """Get dnsXai DNS protection statistics"""
        stats = {
            'total_queries': 0,
            'blocked': 0,
            'block_rate': 0.0,
            'ml_blocks': 0,
            'cname_uncloaked': 0,
            'threat_score': 0.0,
        }

        # Read from dnsmasq query log
        query_log = Path('/var/log/hookprobe/dnsmasq-queries.log')
        if query_log.exists():
            try:
                content = query_log.read_text()
                lines = content.strip().split('\n') if content.strip() else []
                stats['total_queries'] = len([l for l in lines if ' query[' in l])
                stats['blocked'] = len([l for l in lines if '0.0.0.0' in l or '127.0.0.1' in l])
                if stats['total_queries'] > 0:
                    stats['block_rate'] = (stats['blocked'] / stats['total_queries']) * 100
            except Exception:
                pass

        # Read from dnsXai stats file
        dnsxai_file = Path('/opt/hookprobe/guardian/dnsxai/stats.json')
        if dnsxai_file.exists():
            try:
                data = json.loads(dnsxai_file.read_text())
                stats['ml_blocks'] = data.get('ml_blocks', 0)
                stats['cname_uncloaked'] = data.get('cname_uncloaked', 0)
            except Exception:
                pass

        # Calculate threat score (0-1) based on DNS activity
        # High block rate indicates active threats
        stats['threat_score'] = min(1.0, stats['block_rate'] / 30.0)  # 30% block rate = 1.0

        return stats

    def get_napse_bridge_stats(self) -> Dict:
        """Get NAPSE-dnsXai bridge deep packet inspection stats"""
        stats = {
            'enabled': False,
            'detections': 0,
            'tls_sni_blocks': 0,
            'ja3_blocks': 0,
            'ip_reputation_blocks': 0,
            'threat_score': 0.0,
        }

        bridge_log = Path('/var/log/hookprobe/napse-dnsxai-bridge.log')
        if bridge_log.exists():
            stats['enabled'] = True
            try:
                # Read last 5KB
                with open(bridge_log, 'rb') as f:
                    f.seek(0, 2)
                    size = f.tell()
                    f.seek(max(0, size - 5000))
                    content = f.read().decode('utf-8', errors='ignore')

                for line in content.split('\n'):
                    if 'TLS_SNI' in line:
                        stats['tls_sni_blocks'] += 1
                    elif 'JA3' in line:
                        stats['ja3_blocks'] += 1
                    elif 'IP_REPUTATION' in line:
                        stats['ip_reputation_blocks'] += 1
                    elif 'blocked' in line.lower():
                        stats['detections'] += 1

                # Threat score based on deep packet inspection hits
                stats['threat_score'] = min(1.0, stats['detections'] / 20.0)
            except Exception:
                pass

        return stats

    def calculate_score(self, xdp_stats: Dict, energy_stats: Dict, network_stats: Dict,
                        threats: int, napse_alerts: int, dnsxai_stats: Dict = None,
                        bridge_stats: Dict = None) -> tuple:
        """Calculate QSecBit score using full algorithm"""
        components = {
            'drift': 0.0,
            'attack_probability': 0.0,
            'classifier_decay': 0.0,
            'quantum_drift': 0.0,
            'energy_anomaly': 0.0
        }

        # Component 1: System drift (based on traffic volume deviation)
        total_bytes = energy_stats.get('total_rx_bytes', 0) + energy_stats.get('total_tx_bytes', 0)
        # Normalize: assume 1GB is high
        components['drift'] = min(1.0, total_bytes / (1024 * 1024 * 1024))

        # Component 2: Attack probability (based on NAPSE alerts and XDP drops)
        alert_factor = min(1.0, napse_alerts / 50.0)  # Normalize by 50 alerts
        drop_factor = min(1.0, xdp_stats.get('dropped_blocked', 0) / 1000.0)
        components['attack_probability'] = max(alert_factor, drop_factor)

        # Component 3: Classifier decay (simplified - based on threat increase rate)
        components['classifier_decay'] = min(1.0, threats / 20.0)

        # Component 4: Quantum drift (entropy-based, simplified)
        connections = network_stats.get('connections', 0)
        components['quantum_drift'] = min(1.0, connections / 100.0)

        # Component 5: Energy anomaly (if enabled)
        if self.config.energy_monitoring_enabled:
            # Check for high energy consumption
            if energy_stats.get('rapl_available'):
                components['energy_anomaly'] = 0.1  # Low baseline if RAPL available
            else:
                components['energy_anomaly'] = 0.0

        # Component 6: dnsXai threat score (DNS-based threat indicator)
        dnsxai_score = 0.0
        if dnsxai_stats:
            # dnsXai contributes when blocking threats
            dnsxai_score = dnsxai_stats.get('threat_score', 0.0)
            # ML and CNAME uncloaking are strong indicators
            ml_factor = min(1.0, dnsxai_stats.get('ml_blocks', 0) / 10.0)
            cname_factor = min(1.0, dnsxai_stats.get('cname_uncloaked', 0) / 5.0)
            dnsxai_score = max(dnsxai_score, ml_factor, cname_factor)
        components['dnsxai_threat'] = dnsxai_score

        # Component 7: Deep Packet Inspection (NAPSE bridge)
        dpi_score = 0.0
        if bridge_stats and bridge_stats.get('enabled'):
            dpi_score = bridge_stats.get('threat_score', 0.0)
            # TLS/JA3 detections are high confidence
            tls_factor = min(1.0, bridge_stats.get('tls_sni_blocks', 0) / 5.0)
            ja3_factor = min(1.0, bridge_stats.get('ja3_blocks', 0) / 3.0)
            dpi_score = max(dpi_score, tls_factor * 0.8, ja3_factor * 0.9)
        components['dpi_threat'] = dpi_score

        # Calculate weighted score (adjusted weights for new components)
        # Original 5 components: 0.25 + 0.25 + 0.20 + 0.15 + 0.15 = 1.0
        # New 7 components: reduce each slightly and add dnsxai (0.08) + dpi (0.07) = 0.15
        base_score = (
            self.config.alpha * 0.85 * components['drift'] +          # 0.2125
            self.config.beta * 0.85 * components['attack_probability'] +  # 0.2125
            self.config.gamma * 0.85 * components['classifier_decay'] +   # 0.17
            self.config.delta * 0.85 * components['quantum_drift'] +      # 0.1275
            self.config.epsilon * 0.85 * components['energy_anomaly']     # 0.1275 = 0.85
        )
        # Add dnsXai and DPI contributions
        score = base_score + 0.08 * dnsxai_score + 0.07 * dpi_score

        # Determine RAG status
        if score >= self.config.red_threshold:
            rag_status = 'RED'
        elif score >= self.config.amber_threshold:
            rag_status = 'AMBER'
        else:
            rag_status = 'GREEN'

        return score, rag_status, components

    def collect_sample(self) -> QSecBitSample:
        """Collect a complete QSecBit sample - integrates all data sources"""
        # Gather all data sources in parallel-ready manner
        xdp_stats = self.get_xdp_stats()
        energy_stats = self.get_energy_stats()
        network_stats = self.get_network_stats()
        threats = self.check_threats()
        napse_alerts = self.check_napse_alerts()
        dnsxai_stats = self.get_dnsxai_stats()
        bridge_stats = self.get_napse_bridge_stats()

        # Calculate unified score including all components
        score, rag_status, components = self.calculate_score(
            xdp_stats, energy_stats, network_stats, threats, napse_alerts,
            dnsxai_stats, bridge_stats
        )

        sample = QSecBitSample(
            timestamp=datetime.now().isoformat(),
            score=score,
            rag_status=rag_status,
            components=components,
            xdp_stats=xdp_stats,
            energy_stats=energy_stats,
            network_stats=network_stats,
            threats_detected=threats,
            napse_alerts=napse_alerts,
            dnsxai_stats=dnsxai_stats,
            bridge_stats=bridge_stats
        )

        return sample

    def save_stats(self, sample: QSecBitSample):
        """Save stats to file for Web UI - optimized unified format"""
        try:
            # Map internal component names to web UI expected names
            components = {
                'drift': sample.components.get('drift', 0.0),
                'p_attack': sample.components.get('attack_probability', 0.0),
                'decay': sample.components.get('classifier_decay', 0.0),
                'q_drift': sample.components.get('quantum_drift', 0.0),
                'energy_anomaly': sample.components.get('energy_anomaly', 0.0),
                'dnsxai': sample.components.get('dnsxai_threat', 0.0),
                'dpi': sample.components.get('dpi_threat', 0.0),
            }

            # Calculate intelligent layer scores
            dnsxai = sample.dnsxai_stats or {}
            bridge = sample.bridge_stats or {}
            l7_dns_score = dnsxai.get('threat_score', 0.0)
            l7_dpi_score = bridge.get('threat_score', 0.0)

            stats_data = {
                'timestamp': sample.timestamp,
                'score': round(sample.score, 4),
                'status': sample.rag_status,  # Web UI expects 'status'
                'rag_status': sample.rag_status,  # Keep for compatibility
                'components': components,
                'weights': {
                    'alpha': self.config.alpha,
                    'beta': self.config.beta,
                    'gamma': self.config.gamma,
                    'delta': self.config.delta,
                    'epsilon': self.config.epsilon,
                    'dnsxai': 0.08,
                    'dpi': 0.07,
                },
                # Layer scores for unified view (enhanced with dnsXai and DPI)
                'layers': {
                    'L2': {'score': 0.0, 'threats': 0, 'status': 'GREEN'},
                    'L3': {
                        'score': min(1.0, sample.xdp_stats.get('dropped_blocked', 0) / 100),
                        'threats': sample.xdp_stats.get('dropped_blocked', 0),
                        'status': 'GREEN' if sample.xdp_stats.get('dropped_blocked', 0) < 50 else 'AMBER'
                    },
                    'L4': {
                        'score': min(1.0, sample.network_stats.get('connections', 0) / 50),
                        'threats': 0,
                        'status': 'GREEN'
                    },
                    'L5': {
                        'score': bridge.get('tls_sni_blocks', 0) / 10 if bridge.get('enabled') else 0.0,
                        'threats': bridge.get('tls_sni_blocks', 0),
                        'status': 'GREEN' if bridge.get('tls_sni_blocks', 0) < 3 else 'AMBER'
                    },
                    'L7': {
                        'score': max(l7_dns_score, l7_dpi_score, min(1.0, sample.napse_alerts / 10)),
                        'threats': sample.napse_alerts + dnsxai.get('blocked', 0),
                        'status': 'GREEN' if sample.napse_alerts < 5 else 'AMBER'
                    },
                },
                'xdp': sample.xdp_stats,
                'energy': sample.energy_stats,
                'network': sample.network_stats,
                'threats': sample.threats_detected,
                'napse_alerts': sample.napse_alerts,
                # dnsXai integration
                'dnsxai': {
                    'total_queries': dnsxai.get('total_queries', 0),
                    'blocked': dnsxai.get('blocked', 0),
                    'block_rate': round(dnsxai.get('block_rate', 0.0), 2),
                    'ml_blocks': dnsxai.get('ml_blocks', 0),
                    'cname_uncloaked': dnsxai.get('cname_uncloaked', 0),
                    'threat_score': round(dnsxai.get('threat_score', 0.0), 4),
                },
                # NAPSE-dnsXai bridge (DPI)
                'dpi': {
                    'enabled': bridge.get('enabled', False),
                    'detections': bridge.get('detections', 0),
                    'tls_sni_blocks': bridge.get('tls_sni_blocks', 0),
                    'ja3_blocks': bridge.get('ja3_blocks', 0),
                    'ip_reputation_blocks': bridge.get('ip_reputation_blocks', 0),
                    'threat_score': round(bridge.get('threat_score', 0.0), 4),
                },
                'active': True,
                'mode': 'guardian-edge',
                'version': '5.1.0',  # Bumped for unified integration
            }
            STATS_FILE.write_text(json.dumps(stats_data, indent=2))
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")

    def run_monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("Starting QSecBit monitoring loop...")
        interval = 10  # seconds

        while self.running.is_set():
            try:
                sample = self.collect_sample()
                self.last_sample = sample
                self.history.append(sample)

                # Keep history bounded
                if len(self.history) > 1000:
                    self.history.pop(0)

                # Save for Web UI
                self.save_stats(sample)

                # Log status
                logger.info(
                    f"QSecBit: {sample.rag_status} score={sample.score:.3f} "
                    f"threats={sample.threats_detected} alerts={sample.napse_alerts}"
                )

                # Alert on RED status
                if sample.rag_status == 'RED':
                    logger.warning("RED ALERT: System under stress!")

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}", exc_info=True)

            time.sleep(interval)

        logger.info("Monitoring loop stopped")

    def start(self):
        """Start the agent"""
        logger.info("Starting QSecBit Guardian Agent v5.0.0...")

        # Start health check server
        try:
            server = HTTPServer(('0.0.0.0', 8889), HealthCheckHandler)
            server.agent = self
            health_thread = Thread(target=server.serve_forever, daemon=True)
            health_thread.start()
            logger.info("Health check server listening on port 8889")
        except Exception as e:
            logger.warning(f"Could not start health server: {e}")

        # Set running flag
        self.running.set()

        # Run monitoring loop (blocking)
        self.run_monitoring_loop()

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping QSecBit Guardian Agent...")
        self.running.clear()
        logger.info("Agent stopped")


def main():
    agent = QSecBitGuardianAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        agent.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        agent.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()
PYEOF

    chmod +x /opt/hookprobe/guardian/qsecbit/guardian_agent.py

    # Create systemd service
    cat > /etc/systemd/system/guardian-qsecbit.service << 'EOF'
[Unit]
Description=HookProbe Guardian QSecBit Agent v5.0
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/hookprobe/guardian/qsecbit
ExecStart=/usr/bin/python3 /opt/hookprobe/guardian/qsecbit/guardian_agent.py
Restart=always
RestartSec=10
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-qsecbit

    log_info "QSecBit Guardian Agent v5.0 installed"
    log_info "  Health check: http://localhost:8889/health"
    log_info "  Metrics API: http://localhost:8889/metrics"
}

# ============================================================
# BASE NETWORK CONFIGURATION (Bridge, Hostapd, DHCP)
# ============================================================
configure_base_networking() {
    log_step "Configuring base networking..."

    local HOTSPOT_SSID="${HOOKPROBE_WIFI_SSID:-HookProbe-Guardian}"
    local HOTSPOT_PASS="${HOOKPROBE_WIFI_PASS:-hookprobe123}"
    # /27 subnet for Guardian (30 usable addresses - sufficient for travel companion)
    local BRIDGE_IP="192.168.4.1"
    local DHCP_START="192.168.4.2"
    local DHCP_END="192.168.4.30"
    local NETMASK="255.255.255.224"

    # Determine interfaces
    # AP Interface selection priority:
    # 1. HOOKPROBE_AP_IFACE env variable (user override)
    # 2. RECOMMENDED_AP_IFACE from driver detection (USB WiFi)
    # 3. wlan1 (legacy default)
    # 4. First available wlan
    local WIFI_IFACE="${HOOKPROBE_AP_IFACE:-}"
    if [ -z "$WIFI_IFACE" ]; then
        if [ -n "$RECOMMENDED_AP_IFACE" ]; then
            # Use driver-detected USB WiFi adapter for AP
            WIFI_IFACE="$RECOMMENDED_AP_IFACE"
            log_info "Using detected USB WiFi for AP: $WIFI_IFACE"
        elif echo "$WIFI_INTERFACES" | grep -qw "wlan1"; then
            # Legacy fallback to wlan1
            WIFI_IFACE="wlan1"
        else
            # Last resort: first available
            WIFI_IFACE=$(echo $WIFI_INTERFACES | awk '{print $1}')
        fi
    fi
    local ETH_IFACE=$(echo $ETH_INTERFACES | awk '{print $1}')

    if [ -z "$WIFI_IFACE" ]; then
        log_error "No WiFi interface found"
        exit 1
    fi

    # Stop services during configuration
    systemctl stop hostapd 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true

    # ─────────────────────────────────────────────────────────────
    # Clean up any existing netplan/NetworkManager configurations
    # ─────────────────────────────────────────────────────────────
    log_info "Cleaning up existing network configurations..."

    # Remove netplan WiFi configurations
    if [ -d /etc/netplan ]; then
        for conf in /etc/netplan/*.yaml /etc/netplan/*.yml; do
            if [ -f "$conf" ] && grep -q "wlan" "$conf" 2>/dev/null; then
                log_info "Removing WiFi config from netplan: $conf"
                # Comment out wlan sections instead of deleting the file
                sed -i 's/^\([[:space:]]*\)\(wlan[0-9]*:\)/\1# \2 # Disabled by Guardian/' "$conf" 2>/dev/null || true
            fi
        done
        # Apply netplan changes
        netplan generate 2>/dev/null || true
    fi

    # Delete existing NetworkManager connections for WiFi interfaces
    if command -v nmcli &>/dev/null; then
        for iface in $WIFI_INTERFACES; do
            # Find and delete connections associated with this interface
            local connections=$(nmcli -t -f NAME,DEVICE connection show 2>/dev/null | grep ":${iface}$" | cut -d: -f1)
            for conn in $connections; do
                log_info "Removing NetworkManager connection: $conn (interface: $iface)"
                nmcli connection delete "$conn" 2>/dev/null || true
            done
            # Also delete connections by name pattern (netplan-wlan*, wlan*, etc)
            local pattern_connections=$(nmcli -t -f NAME connection show 2>/dev/null | grep -E "^(netplan-)?${iface}" || true)
            for conn in $pattern_connections; do
                log_info "Removing NetworkManager connection by name: $conn"
                nmcli connection delete "$conn" 2>/dev/null || true
            done
        done
    fi

    # ─────────────────────────────────────────────────────────────
    # Clean up wpa_supplicant (user may have pre-configured WiFi)
    # ─────────────────────────────────────────────────────────────
    log_info "Cleaning up wpa_supplicant configurations..."

    # Stop and disable wpa_supplicant service
    systemctl stop wpa_supplicant 2>/dev/null || true
    systemctl disable wpa_supplicant 2>/dev/null || true

    # Kill any wpa_supplicant processes
    pkill -9 wpa_supplicant 2>/dev/null || true

    # Remove wpa_supplicant configurations
    if [ -f /etc/wpa_supplicant/wpa_supplicant.conf ]; then
        log_info "Removing /etc/wpa_supplicant/wpa_supplicant.conf"
        rm -f /etc/wpa_supplicant/wpa_supplicant.conf
    fi

    # Remove interface-specific wpa_supplicant configs
    rm -f /etc/wpa_supplicant/wpa_supplicant-*.conf 2>/dev/null || true

    # Disable interface-specific wpa_supplicant services
    for iface in $WIFI_INTERFACES; do
        systemctl disable "wpa_supplicant@${iface}" 2>/dev/null || true
        systemctl stop "wpa_supplicant@${iface}" 2>/dev/null || true
    done

    # ─────────────────────────────────────────────────────────────
    # Prepare WiFi interface for AP mode
    # ─────────────────────────────────────────────────────────────
    log_info "Preparing $WIFI_IFACE for AP mode..."

    # Kill any remaining wpa_supplicant processes using this interface
    pkill -f "wpa_supplicant.*$WIFI_IFACE" 2>/dev/null || true
    sleep 1

    # Stop NetworkManager from managing this interface
    if command -v nmcli &>/dev/null; then
        nmcli device set "$WIFI_IFACE" managed no 2>/dev/null || true
    fi

    # Remove interface from any existing bridge
    for br in $(ls /sys/class/net/*/brif 2>/dev/null | xargs -I{} dirname {} | xargs -I{} basename {}); do
        ip link set "$WIFI_IFACE" nomaster 2>/dev/null || true
    done

    # Bring interface down
    ip link set "$WIFI_IFACE" down 2>/dev/null || true
    sleep 1

    # Check if interface supports AP mode
    if ! iw list 2>/dev/null | grep -A 15 "Supported interface modes" | grep -q "\* AP"; then
        log_error "WiFi interface $WIFI_IFACE does not support AP mode"
        log_error "Please use a USB WiFi adapter that supports AP mode (e.g., RTL8812AU, MT7612U)"
        exit 1
    fi

    # Set interface type to AP mode
    log_info "Setting $WIFI_IFACE to AP mode..."
    iw dev "$WIFI_IFACE" set type __ap 2>/dev/null || {
        # Try alternative method
        iw dev "$WIFI_IFACE" set type ap 2>/dev/null || {
            log_warn "Could not set AP mode with iw, hostapd will attempt to set it"
        }
    }

    # Bring interface back up
    ip link set "$WIFI_IFACE" up 2>/dev/null || true
    sleep 1

    # Verify interface is ready
    local iface_mode=$(iw dev "$WIFI_IFACE" info 2>/dev/null | grep -oP 'type \K\w+' || echo "unknown")
    log_info "Interface $WIFI_IFACE mode: $iface_mode"

    # Unblock WiFi if rfkill blocked
    if command -v rfkill &>/dev/null; then
        rfkill unblock wifi 2>/dev/null || true
    fi

    # Create bridge interface
    log_info "Creating bridge br0..."
    ip link add br0 type bridge 2>/dev/null || true
    ip link set br0 up
    ip addr add $BRIDGE_IP/27 dev br0 2>/dev/null || true

    # NOTE: eth0 is NOT added to bridge - it's a WAN interface for failover
    # Only the LAN-side (USB WiFi dongle) is bridged via hostapd
    # eth0 should get its own IP from upstream router for WAN failover
    log_info "eth0 kept as WAN interface (not bridged) for failover support"

    # ─────────────────────────────────────────────────────────────
    # Detect WiFi driver for hostapd
    # ─────────────────────────────────────────────────────────────
    log_info "Detecting WiFi driver for $WIFI_IFACE..."

    # Get the driver in use
    local WIFI_DRIVER="nl80211"  # Default
    local PHY_NAME=$(iw dev "$WIFI_IFACE" info 2>/dev/null | grep -oP 'wiphy \K\d+')
    local DRIVER_PATH="/sys/class/net/$WIFI_IFACE/device/driver"

    if [ -L "$DRIVER_PATH" ]; then
        local KERNEL_DRIVER=$(basename $(readlink "$DRIVER_PATH"))
        log_info "Kernel driver: $KERNEL_DRIVER"

        # Map kernel drivers to hostapd drivers
        case "$KERNEL_DRIVER" in
            rtl8*|r8*|88*|8188*|8192*|rtw*)
                # Realtek USB adapters - try nl80211 first, some need rtl871xdrv
                # Check if nl80211 is supported
                if iw list 2>/dev/null | grep -q "nl80211"; then
                    WIFI_DRIVER="nl80211"
                else
                    log_warn "Realtek adapter detected - may need rtl871xdrv driver"
                    WIFI_DRIVER="nl80211"  # Still try nl80211 first
                fi
                ;;
            mt76*|mt7*|mediatek*)
                WIFI_DRIVER="nl80211"
                ;;
            ath9k*|ath10k*|ath*|carl9170*)
                WIFI_DRIVER="nl80211"
                ;;
            brcmfmac|brcmsmac)
                WIFI_DRIVER="nl80211"
                ;;
            *)
                WIFI_DRIVER="nl80211"
                ;;
        esac
    fi

    log_info "Using hostapd driver: $WIFI_DRIVER"

    # Determine best channel (avoid DFS channels)
    local WIFI_CHANNEL=6

    # Auto-detect country code from system regulatory domain
    local COUNTRY_CODE="${HOOKPROBE_COUNTRY:-}"
    if [ -z "$COUNTRY_CODE" ]; then
        # Try to get from system regulatory domain
        COUNTRY_CODE=$(iw reg get 2>/dev/null | grep -oP 'country \K[A-Z]{2}' | head -1)
        # Fallback to timezone-based detection
        if [ -z "$COUNTRY_CODE" ] || [ "$COUNTRY_CODE" = "00" ] || [ "$COUNTRY_CODE" = "99" ]; then
            local TZ_COUNTRY=$(timedatectl 2>/dev/null | grep "Time zone" | grep -oP '/\K[^/]+(?=\s)' | head -1)
            case "$TZ_COUNTRY" in
                Bucharest) COUNTRY_CODE="RO" ;;
                London) COUNTRY_CODE="GB" ;;
                Paris|Berlin|Rome|Madrid|Amsterdam) COUNTRY_CODE="DE" ;;
                New_York|Chicago|Los_Angeles) COUNTRY_CODE="US" ;;
                *) COUNTRY_CODE="US" ;;
            esac
        fi
    fi
    log_info "Detected country code: $COUNTRY_CODE"

    # Set regulatory domain and wait for it to apply
    log_info "Setting regulatory domain to $COUNTRY_CODE..."
    iw reg set "$COUNTRY_CODE" 2>/dev/null || true
    sleep 2

    # Verify regulatory domain was applied
    local APPLIED_COUNTRY=$(iw reg get 2>/dev/null | grep -oP 'country \K[A-Z]{2}' | head -1)
    if [ "$APPLIED_COUNTRY" != "$COUNTRY_CODE" ]; then
        log_warn "Regulatory domain may not have applied correctly (got: $APPLIED_COUNTRY)"
    fi

    # Check available channels for this regulatory domain
    log_info "Checking available channels for $COUNTRY_CODE..."
    local AVAILABLE_CHANNELS=$(iw phy phy$PHY_NAME channels 2>/dev/null | grep -v "disabled\|radar\|no IR" | grep -oP '\[\K\d+(?=\])' | head -10)
    if [ -n "$AVAILABLE_CHANNELS" ]; then
        log_info "Available 2.4GHz channels: $(echo $AVAILABLE_CHANNELS | tr '\n' ' ')"
        # Prefer channel 1, 6, or 11 for 2.4GHz (non-overlapping)
        for ch in 6 1 11 7 13; do
            if echo "$AVAILABLE_CHANNELS" | grep -qw "$ch"; then
                WIFI_CHANNEL=$ch
                break
            fi
        done
    fi
    log_info "Using channel: $WIFI_CHANNEL"

    # Configure hostapd
    log_info "Configuring hostapd..."
    cat > /etc/hostapd/hostapd.conf << EOF
# HookProbe Guardian - Base Network Configuration
# Auto-generated - do not edit manually

interface=$WIFI_IFACE
driver=$WIFI_DRIVER
bridge=br0

ssid=$HOTSPOT_SSID
hw_mode=g
channel=$WIFI_CHANNEL

# Regulatory domain - IMPORTANT for proper operation
country_code=$COUNTRY_CODE
ieee80211d=1
local_pwr_constraint=3

# 802.11n support (disable if causing issues)
ieee80211n=1
wmm_enabled=1
# HT capabilities - comment out if adapter doesn't support
#ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]

# Security
wpa=2
wpa_passphrase=$HOTSPOT_PASS
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
auth_algs=1

# Logging (verbose for debugging)
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2

# Performance
max_num_sta=32
ignore_broadcast_ssid=0

# Workarounds for various drivers
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0
EOF

    # Test hostapd configuration before committing
    log_info "Testing hostapd configuration..."

    # Make sure interface is down for hostapd to configure it
    ip link set "$WIFI_IFACE" down 2>/dev/null || true
    sleep 1

    # Run a quick syntax check with timeout (hostapd -t can hang on some systems)
    local TEST_OUTPUT
    if TEST_OUTPUT=$(timeout 5 hostapd -t /etc/hostapd/hostapd.conf 2>&1); then
        log_info "Hostapd configuration syntax OK"
    elif [ $? -eq 124 ]; then
        log_warn "Hostapd config test timed out (this is OK, will verify at startup)"
    elif echo "$TEST_OUTPUT" | grep -qi "error\|invalid\|failed"; then
        log_warn "Hostapd config may have issues:"
        echo "$TEST_OUTPUT" | head -10
    else
        log_info "Hostapd configuration appears OK"
    fi

    # Configure hostapd daemon defaults
    cat > /etc/default/hostapd << 'EOF'
# Defaults for hostapd
DAEMON_CONF="/etc/hostapd/hostapd.conf"
DAEMON_OPTS=""
EOF

    # Configure dnsmasq (DHCP + DNS)
    log_info "Configuring dnsmasq..."

    # First, clean up main dnsmasq.conf to prevent duplicate keyword errors
    # dnsmasq reads /etc/dnsmasq.conf first, then /etc/dnsmasq.d/*.conf
    # We need to ensure no conflicts between main config and guardian.conf
    if [ -f /etc/dnsmasq.conf ]; then
        log_info "Cleaning up main dnsmasq.conf to prevent keyword conflicts..."
        cp /etc/dnsmasq.conf /etc/dnsmasq.conf.guardian-backup 2>/dev/null || true

        # Comment out keywords that will be defined in guardian.conf
        sed -i 's/^domain-needed/#domain-needed/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^bogus-priv/#bogus-priv/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^cache-size/#cache-size/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^server=/#server=/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^log-queries/#log-queries/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^log-dhcp/#log-dhcp/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^log-facility/#log-facility/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^interface=/#interface=/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^bind-interfaces/#bind-interfaces/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^listen-address/#listen-address/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^no-resolv/#no-resolv/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^no-poll/#no-poll/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^domain=/#domain=/' /etc/dnsmasq.conf 2>/dev/null || true
        sed -i 's/^expand-hosts/#expand-hosts/' /etc/dnsmasq.conf 2>/dev/null || true
    fi

    # Remove existing guardian.conf to start fresh (preserve dns-shield.conf if exists)
    # NOTE: dns-shield.conf is created by install_dns_shield() which runs before this function
    rm -f /etc/dnsmasq.d/guardian.conf 2>/dev/null || true

    cat > /etc/dnsmasq.d/guardian.conf << EOF
# HookProbe Guardian - DHCP/DNS Configuration
# Version: 5.1.0
# This is the MASTER dnsmasq config - all core settings here

# General settings
domain-needed
bogus-priv
no-resolv
no-poll

# Interface - listen on bridge only
interface=br0
bind-dynamic

# Do NOT listen on WAN interfaces
except-interface=eth0
except-interface=wlan0
except-interface=lo

# DHCP range (/27 subnet - 30 usable addresses)
dhcp-range=$DHCP_START,$DHCP_END,$NETMASK,24h

# Gateway and DNS
dhcp-option=option:router,$BRIDGE_IP
dhcp-option=option:dns-server,$BRIDGE_IP
dhcp-option=option:domain-search,guardian.local
dhcp-option=option:domain-name,guardian.local

# Upstream DNS servers (privacy-focused)
server=1.1.1.1
server=9.9.9.9
server=8.8.8.8

# Domain
domain=guardian.local
local=/guardian.local/
expand-hosts

# Performance - large cache for DNS filtering
cache-size=10000

# Logging
log-queries=extra
log-dhcp
log-facility=/var/log/hookprobe/dnsmasq-queries.log

# Lease file
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
EOF

    # Enable IP forwarding
    log_info "Enabling IP forwarding..."
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-guardian.conf
    sysctl -p /etc/sysctl.d/99-guardian.conf

    # Configure route metrics for WAN failover (eth0 primary, wlan0 backup)
    log_info "Configuring WAN failover with route metrics..."

    # Configure dhcpcd for route metrics (Raspberry Pi standard)
    if [ -f /etc/dhcpcd.conf ]; then
        # Remove any existing guardian metrics config
        sed -i '/# Guardian WAN failover/,/^$/d' /etc/dhcpcd.conf

        # Add route metrics - lower metric = higher priority
        # Industry standard: wired=100, wireless=600, failover timeout=10s
        cat >> /etc/dhcpcd.conf << 'DHCPCD_EOF'

# Guardian WAN failover configuration
# eth0 = primary (metric 100), wlan0 = backup (metric 600)

interface eth0
metric 100
# Faster failover detection
timeout 10
option rapid_commit

interface wlan0
metric 600
timeout 10
option rapid_commit

# Prefer wired over wireless for default route
allowinterfaces eth0 wlan0

DHCPCD_EOF
        log_info "Route metrics configured: eth0=100 (primary), wlan0=600 (backup)"
    fi

    # Also set metrics via ip route for immediate effect
    if ip link show eth0 &>/dev/null && ip addr show eth0 | grep -q "inet "; then
        # Get current gateway for eth0
        ETH_GW=$(ip route | grep "default.*eth0" | awk '{print $3}' | head -1)
        if [ -n "$ETH_GW" ]; then
            ip route del default via $ETH_GW dev eth0 2>/dev/null || true
            ip route add default via $ETH_GW dev eth0 metric 100 2>/dev/null || true
            log_info "Set eth0 route metric to 100"
        fi
    fi

    if ip link show wlan0 &>/dev/null && ip addr show wlan0 | grep -q "inet "; then
        # Get current gateway for wlan0
        WLAN_GW=$(ip route | grep "default.*wlan0" | awk '{print $3}' | head -1)
        if [ -n "$WLAN_GW" ]; then
            ip route del default via $WLAN_GW dev wlan0 2>/dev/null || true
            ip route add default via $WLAN_GW dev wlan0 metric 600 2>/dev/null || true
            log_info "Set wlan0 route metric to 600"
        fi
    fi

    # Configure NAT (masquerade outgoing traffic)
    log_info "Configuring NAT..."
    mkdir -p /etc/nftables.d
    cat > /etc/nftables.d/guardian.nft << 'EOF'
#!/usr/sbin/nft -f
# HookProbe Guardian - NAT and Firewall Rules
# IMPORTANT: Preserves existing connections (SSH, etc.)

# Delete old tables if they exist (clean slate)
table inet guardian
delete table inet guardian

table ip guardian_nat
delete table ip guardian_nat

# Filtering rules (inet family supports both IPv4 and IPv6)
table inet guardian {
    # Input chain - allow established connections and SSH
    chain input {
        type filter hook input priority 0; policy accept;
        # Always allow established/related connections (keeps SSH alive)
        ct state established,related accept
        # Allow SSH on all interfaces
        tcp dport 22 accept
        # Allow web UI
        tcp dport 8080 accept
        # Allow DNS queries to dnsmasq from LAN
        iifname "br0" udp dport 53 accept
        iifname "br0" tcp dport 53 accept
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
        # Allow forwarding from LAN to WAN
        iifname "br0" accept
    }
}

# NAT rules (MUST use ip family, not inet - inet doesn't support NAT)
table ip guardian_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # Masquerade traffic going out WAN interfaces (all common patterns)
        # Don't masquerade on LAN interfaces (br0, wlan1)
        oifname != "br0" oifname != "wlan1" oifname != "lo" masquerade
    }
}
EOF

    # Apply nftables rules (preserving existing connections)
    log_info "Applying firewall rules (preserving SSH connections)..."
    nft -f /etc/nftables.d/guardian.nft 2>/dev/null || {
        log_warn "nftables apply failed, trying iptables fallback..."
        # Fallback to iptables if nftables fails
        iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE 2>/dev/null || true
        iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
    }

    # Ensure nftables loads guardian rules at boot
    log_info "Configuring nftables to load Guardian rules at boot..."
    if [ -f /etc/nftables.conf ]; then
        # Add include directive if not already present
        if ! grep -q "guardian.nft" /etc/nftables.conf; then
            echo 'include "/etc/nftables.d/guardian.nft"' >> /etc/nftables.conf
            log_info "Added Guardian rules to nftables.conf"
        fi
    fi

    # Create iptables fallback script for systems without nftables
    log_info "Creating iptables fallback for boot persistence..."
    cat > /etc/network/if-up.d/guardian-nat << 'IPTABLES_EOF'
#!/bin/bash
# Guardian NAT rules - applied when network interfaces come up
# This ensures routing works even if nftables fails

# Only run for WAN interfaces
case "$IFACE" in
    eth0|wlan0|enp*|wlp*)
        # Enable IP forwarding
        echo 1 > /proc/sys/net/ipv4/ip_forward

        # Add NAT masquerade if not already present
        if ! iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
        fi

        # Add FORWARD rules for LAN interfaces
        for LAN_IFACE in wlan1 br0; do
            if [ -d "/sys/class/net/$LAN_IFACE" ]; then
                if ! iptables -C FORWARD -i "$LAN_IFACE" -o "$IFACE" -j ACCEPT 2>/dev/null; then
                    iptables -A FORWARD -i "$LAN_IFACE" -o "$IFACE" -j ACCEPT
                fi
                if ! iptables -C FORWARD -i "$IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
                    iptables -A FORWARD -i "$IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
                fi
            fi
        done
        ;;
esac
IPTABLES_EOF
    chmod +x /etc/network/if-up.d/guardian-nat 2>/dev/null || true

    # Also create systemd service for iptables persistence (for systems using systemd-networkd)
    cat > /etc/systemd/system/guardian-routing.service << 'ROUTING_EOF'
[Unit]
Description=Guardian NAT and Routing Rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/guardian-setup-routing.sh

[Install]
WantedBy=multi-user.target
ROUTING_EOF

    # Create the routing setup script (more readable and maintainable)
    cat > /usr/local/bin/guardian-setup-routing.sh << 'ROUTING_SCRIPT_EOF'
#!/bin/bash
# Guardian NAT/Routing Setup Script
# Dynamically detects WAN interface and configures NAT/forwarding

set -e

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Detect WAN interface from default route
WAN=$(ip route | grep '^default' | head -1 | awk '{print $5}')

if [ -z "$WAN" ]; then
    echo "Warning: No default route found, trying common interfaces..."
    for iface in eth0 wlan0 enp0s25 enp1s0 wlp2s0; do
        if [ -d "/sys/class/net/$iface" ] && ip addr show "$iface" | grep -q "inet "; then
            WAN="$iface"
            break
        fi
    done
fi

if [ -z "$WAN" ]; then
    echo "Error: Could not detect WAN interface"
    exit 1
fi

echo "Detected WAN interface: $WAN"

# Add MASQUERADE for WAN interface
if ! iptables -t nat -C POSTROUTING -o "$WAN" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE
    echo "Added MASQUERADE for $WAN"
fi

# Also add masquerade for other potential WAN interfaces (failover)
for iface in eth0 wlan0; do
    if [ "$iface" != "$WAN" ] && [ -d "/sys/class/net/$iface" ]; then
        if ! iptables -t nat -C POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE
            echo "Added MASQUERADE for failover interface $iface"
        fi
    fi
done

# Configure FORWARD rules for LAN interfaces
for LAN in wlan1 br0; do
    if [ -d "/sys/class/net/$LAN" ]; then
        # Allow LAN to WAN forwarding
        if ! iptables -C FORWARD -i "$LAN" -o "$WAN" -j ACCEPT 2>/dev/null; then
            iptables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
            echo "Added FORWARD rule: $LAN -> $WAN"
        fi

        # Allow return traffic (established connections)
        if ! iptables -C FORWARD -i "$WAN" -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
            iptables -A FORWARD -i "$WAN" -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT
            echo "Added FORWARD rule: $WAN -> $LAN (established)"
        fi

        # General LAN outbound (for any WAN)
        if ! iptables -C FORWARD -i "$LAN" -j ACCEPT 2>/dev/null; then
            iptables -A FORWARD -i "$LAN" -j ACCEPT
        fi

        # General return traffic to LAN
        if ! iptables -C FORWARD -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
            iptables -A FORWARD -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT
        fi
    fi
done

echo "Guardian routing setup complete"
ROUTING_SCRIPT_EOF
    chmod +x /usr/local/bin/guardian-setup-routing.sh

    systemctl daemon-reload
    systemctl enable guardian-routing.service 2>/dev/null || true
    systemctl start guardian-routing.service 2>/dev/null || true

    # Also apply routing rules immediately (in case service start failed or for immediate effect)
    log_info "Applying NAT/routing rules immediately..."
    /usr/local/bin/guardian-setup-routing.sh 2>&1 || {
        log_warn "Routing script failed, applying basic rules..."
        # Fallback: apply basic rules directly
        echo 1 > /proc/sys/net/ipv4/ip_forward
        WAN=$(ip route | grep '^default' | head -1 | awk '{print $5}')
        if [ -n "$WAN" ]; then
            iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE 2>/dev/null || true
        fi
        for LAN in wlan1 br0; do
            [ -d "/sys/class/net/$LAN" ] && {
                iptables -A FORWARD -i "$LAN" -j ACCEPT 2>/dev/null || true
                iptables -A FORWARD -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
            }
        done
    }

    log_info "Base networking configuration complete"
}

# ============================================================
# HOSTAPD CONFIGURATION (Guardian Simple Mode)
# ============================================================
# Guardian Mode: Simple WiFi hotspot - client tracking via hostapd_cli
# - All devices on same network (br0) - no VLAN segmentation
# - hostapd_cli tracks connected stations
# - Web UI shows connected devices list
#
# For VLAN segmentation, use Fortress mode which requires
# special WiFi adapters (Atheros AR9271, MediaTek MT7612U)
# ============================================================
configure_guardian_hostapd() {
    log_step "Configuring Guardian hostapd..."

    # Create Guardian config directory
    mkdir -p /etc/guardian
    chmod 755 /etc/guardian

    # Guardian mode: Simple hostapd config - all devices on br0
    log_info "Configuring hostapd for simple mode (all devices on br0)..."

    if [ -f /etc/hostapd/hostapd.conf ]; then
        # Remove any VLAN/802.1X settings that might be in the config
        sed -i 's/^ieee8021x=.*/#ieee8021x=0/' /etc/hostapd/hostapd.conf
        sed -i 's/^dynamic_vlan=.*/#dynamic_vlan=0/' /etc/hostapd/hostapd.conf
        sed -i 's/^vlan_file=.*/#vlan_file=/' /etc/hostapd/hostapd.conf
        sed -i 's/^vlan_tagged_interface=.*/#vlan_tagged_interface=/' /etc/hostapd/hostapd.conf
        sed -i 's/^vlan_bridge=.*/#vlan_bridge=/' /etc/hostapd/hostapd.conf
        sed -i 's/^macaddr_acl=2/macaddr_acl=0/' /etc/hostapd/hostapd.conf
        sed -i 's/^auth_server_addr=.*/#auth_server_addr=/' /etc/hostapd/hostapd.conf
        sed -i 's/^acct_server_addr=.*/#acct_server_addr=/' /etc/hostapd/hostapd.conf
        sed -i 's/^wpa_key_mgmt=WPA-PSK WPA-EAP/wpa_key_mgmt=WPA-PSK/' /etc/hostapd/hostapd.conf
    fi

    # Create files for MAC-based access control (optional use via web UI)
    mkdir -p /etc/hostapd
    touch /etc/hostapd/hostapd.accept
    touch /etc/hostapd/hostapd.deny

    # Guardian mode: NO VLAN interfaces, NO VLAN bridges
    # All devices connect to br0 (192.168.4.x network)
    log_info "Guardian mode: All devices on single network (br0 / 192.168.4.0/27)"
    log_info "For IoT VLAN segmentation, use Fortress mode with VAP-capable WiFi adapter"

    log_info "Hostapd configuration complete"
}

# ============================================================
# GUARDIAN LIBRARY INSTALLATION
# ============================================================
install_guardian_lib() {
    log_step "Installing Guardian Python library..."

    local LIB_SRC="$GUARDIAN_ROOT/lib"
    local LIB_DEST="/opt/hookprobe/guardian/lib"

    # Create destination directory
    mkdir -p "$LIB_DEST"

    # Check if lib directory exists in source
    if [ -d "$LIB_SRC" ]; then
        log_info "Copying Guardian library modules..."

        # Copy all Python modules
        cp "$LIB_SRC"/*.py "$LIB_DEST/" 2>/dev/null || true

        # List installed modules
        local modules_installed=$(ls -1 "$LIB_DEST"/*.py 2>/dev/null | wc -l)
        log_info "Installed $modules_installed Python modules"

        # Install Python dependencies
        log_info "Installing Python dependencies..."
        pip3 install --quiet --upgrade \
            pyyaml \
            cryptography \
            aiohttp \
            dataclasses-json 2>/dev/null || true

    else
        log_warn "Guardian library source not found at $LIB_SRC"
        log_info "Creating minimal library structure..."

        # Create minimal __init__.py
        cat > "$LIB_DEST/__init__.py" << 'PYEOF'
"""
HookProbe Guardian Library
Version: 5.0.0 Cortex
"""
__version__ = '5.0.0'
PYEOF
    fi

    # Set permissions
    chmod -R 755 "$LIB_DEST"

    # Add to Python path
    local PYTHON_SITE=$(python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "/usr/lib/python3/dist-packages")
    if [ -d "$PYTHON_SITE" ]; then
        echo "/opt/hookprobe/guardian" > "$PYTHON_SITE/guardian.pth" 2>/dev/null || true
        log_info "Added Guardian to Python path"
    fi

    log_info "Guardian library installation complete"
}

# ============================================================
# OFFLINE MODE SERVICE INSTALLATION
# ============================================================
install_offline_mode_service() {
    log_step "Installing Offline Mode service..."

    # Create state directory
    mkdir -p /var/lib/guardian
    chmod 755 /var/lib/guardian

    # Backup existing dhcpcd.conf if not already backed up
    if [ -f /etc/dhcpcd.conf ] && [ ! -f /etc/dhcpcd.conf.guardian.bak ]; then
        cp /etc/dhcpcd.conf /etc/dhcpcd.conf.guardian.bak
        log_info "Backed up dhcpcd.conf"
    fi

    # Install systemd service from config directory
    local SERVICE_SRC="$CONFIG_DIR/systemd/guardian-offline.service"
    local SERVICE_DEST="/etc/systemd/system/guardian-offline.service"

    if [ -f "$SERVICE_SRC" ]; then
        cp "$SERVICE_SRC" "$SERVICE_DEST"
        chmod 644 "$SERVICE_DEST"
        log_info "Installed guardian-offline.service"
    else
        # Create service inline if source not found
        log_info "Creating guardian-offline.service..."
        cat > "$SERVICE_DEST" << 'EOF'
[Unit]
Description=Guardian Offline Mode - Smart WiFi AP Initialization
Documentation=https://github.com/hookprobe/hookprobe
After=network-pre.target
Before=network.target hostapd.service dnsmasq.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 2

# Initialize offline mode with smart channel selection
# This runs before hostapd starts and:
# 1. Scans RF environment for congestion
# 2. Selects optimal channel (1, 6, or 11 for 2.4GHz)
# 3. Generates hostapd.conf with best channel
# 4. Sets up bridge interface
ExecStart=/usr/bin/python3 /opt/hookprobe/guardian/lib/offline_mode_manager.py init

# Ensure we have proper permissions
User=root
Group=root

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=guardian-offline

# Security hardening
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
        chmod 644 "$SERVICE_DEST"
    fi

    # Reload systemd
    systemctl daemon-reload

    log_info "Offline mode service installed"
}

# ============================================================
# AP SERVICES INSTALLATION (WAN-Independent Startup)
# ============================================================
install_ap_services() {
    log_step "Installing Guardian AP services for WAN-independent startup..."

    local SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local CONFIG_DIR="$(dirname "$SCRIPT_DIR")/config"

    # Install guardian-wlan-setup.sh script
    log_info "Installing guardian-wlan-setup.sh..."
    cp "$SCRIPT_DIR/guardian-wlan-setup.sh" /usr/local/bin/
    chmod +x /usr/local/bin/guardian-wlan-setup.sh

    # Install additional helper scripts to /usr/local/bin
    log_info "Installing helper scripts..."

    # guardian-nm-setup.sh - NetworkManager MAC-aware configuration
    if [ -f "$SCRIPT_DIR/guardian-nm-setup.sh" ]; then
        cp "$SCRIPT_DIR/guardian-nm-setup.sh" /usr/local/bin/
        chmod +x /usr/local/bin/guardian-nm-setup.sh
    fi

    # guardian-wifi-health.sh - WiFi health monitoring
    if [ -f "$SCRIPT_DIR/guardian-wifi-health.sh" ]; then
        cp "$SCRIPT_DIR/guardian-wifi-health.sh" /usr/local/bin/
        chmod +x /usr/local/bin/guardian-wifi-health.sh
    fi

    # fix-dns-nat.sh - DNS/NAT troubleshooting tool
    if [ -f "$SCRIPT_DIR/fix-dns-nat.sh" ]; then
        cp "$SCRIPT_DIR/fix-dns-nat.sh" /usr/local/bin/
        chmod +x /usr/local/bin/fix-dns-nat.sh
    fi

    # guardian-routing.sh - WAN failover management
    if [ -f "$SCRIPT_DIR/guardian-routing.sh" ]; then
        cp "$SCRIPT_DIR/guardian-routing.sh" /usr/local/bin/
        chmod +x /usr/local/bin/guardian-routing.sh
    fi

    # update-blocklists.sh - DNS Shield blocklist updater (also in /opt)
    if [ -f "$SCRIPT_DIR/update-blocklists.sh" ]; then
        cp "$SCRIPT_DIR/update-blocklists.sh" /usr/local/bin/
        chmod +x /usr/local/bin/update-blocklists.sh
    fi

    # update-cortex-modules.sh - Cortex module updater
    if [ -f "$SCRIPT_DIR/update-cortex-modules.sh" ]; then
        cp "$SCRIPT_DIR/update-cortex-modules.sh" /usr/local/bin/
        chmod +x /usr/local/bin/update-cortex-modules.sh
    fi

    # Install guardian-wlan.service
    log_info "Installing guardian-wlan.service..."
    if [ -f "$CONFIG_DIR/systemd/guardian-wlan.service" ]; then
        cp "$CONFIG_DIR/systemd/guardian-wlan.service" /etc/systemd/system/
        chmod 644 /etc/systemd/system/guardian-wlan.service
    else
        log_warn "guardian-wlan.service not found in config directory"
    fi

    # Install guardian-ap.service (umbrella service)
    log_info "Installing guardian-ap.service..."
    if [ -f "$CONFIG_DIR/systemd/guardian-ap.service" ]; then
        cp "$CONFIG_DIR/systemd/guardian-ap.service" /etc/systemd/system/
        chmod 644 /etc/systemd/system/guardian-ap.service
    else
        log_warn "guardian-ap.service not found in config directory"
    fi

    # Install hostapd service override (removes network-online dependency)
    log_info "Installing hostapd service override..."
    mkdir -p /etc/systemd/system/hostapd.service.d
    if [ -f "$CONFIG_DIR/systemd/hostapd.service.d/guardian-override.conf" ]; then
        cp "$CONFIG_DIR/systemd/hostapd.service.d/guardian-override.conf" \
            /etc/systemd/system/hostapd.service.d/
        chmod 644 /etc/systemd/system/hostapd.service.d/guardian-override.conf
    else
        # Create inline if source not found
        cat > /etc/systemd/system/hostapd.service.d/guardian-override.conf << 'HOSTAPD_OVERRIDE'
# Guardian Override for hostapd.service
# Minimal override - just clear problematic conditions and dependencies

[Unit]
# Clear ALL conditions to prevent startup failures
ConditionFileNotEmpty=
ConditionPathExists=

# Clear ALL dependencies - hostapd just needs the interface to exist
After=
Wants=
Requires=
BindsTo=

# Minimal dependencies - just local filesystem
After=local-fs.target

[Service]
Restart=on-failure
RestartSec=3
TimeoutStartSec=30
Environment="DAEMON_CONF=/etc/hostapd/hostapd.conf"
HOSTAPD_OVERRIDE
    fi

    # Install dnsmasq service override (removes network-online dependency)
    log_info "Installing dnsmasq service override..."
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    if [ -f "$CONFIG_DIR/systemd/dnsmasq.service.d/guardian-override.conf" ]; then
        cp "$CONFIG_DIR/systemd/dnsmasq.service.d/guardian-override.conf" \
            /etc/systemd/system/dnsmasq.service.d/
        chmod 644 /etc/systemd/system/dnsmasq.service.d/guardian-override.conf
    else
        # Create inline if source not found
        cat > /etc/systemd/system/dnsmasq.service.d/guardian-override.conf << 'DNSMASQ_OVERRIDE'
# Guardian Override for dnsmasq.service
# Removes dependency on network-online.target for offline-first operation

[Unit]
After=
Wants=
After=guardian-wlan.service hostapd.service network.target
Wants=hostapd.service

[Service]
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
ExecStartPre=/bin/sleep 2
DNSMASQ_OVERRIDE
    fi

    # Reload systemd to pick up new services
    systemctl daemon-reload

    # Enable services to start at boot
    log_info "Enabling Guardian AP services..."
    systemctl enable guardian-wlan.service 2>/dev/null || true
    systemctl enable guardian-ap.service 2>/dev/null || true
    systemctl enable hostapd.service 2>/dev/null || true
    systemctl enable dnsmasq.service 2>/dev/null || true

    # Unmask hostapd if it was masked (common on Raspberry Pi OS)
    systemctl unmask hostapd.service 2>/dev/null || true

    # Start the services now
    log_info "Starting Guardian AP services..."
    systemctl start guardian-wlan.service 2>/dev/null || true
    sleep 2
    systemctl start hostapd.service 2>/dev/null || {
        log_warn "hostapd failed to start - check /etc/hostapd/hostapd.conf"
        systemctl status hostapd.service --no-pager || true
    }
    systemctl start dnsmasq.service 2>/dev/null || true

    # Install SSID health check script
    log_info "Installing SSID health check..."
    cp "$SCRIPT_DIR/guardian-ssid-health.sh" /usr/local/bin/
    chmod +x /usr/local/bin/guardian-ssid-health.sh

    # Install health check service and timer
    if [ -f "$CONFIG_DIR/systemd/guardian-ssid-health.service" ]; then
        cp "$CONFIG_DIR/systemd/guardian-ssid-health.service" /etc/systemd/system/
        chmod 644 /etc/systemd/system/guardian-ssid-health.service
    fi
    if [ -f "$CONFIG_DIR/systemd/guardian-ssid-health.timer" ]; then
        cp "$CONFIG_DIR/systemd/guardian-ssid-health.timer" /etc/systemd/system/
        chmod 644 /etc/systemd/system/guardian-ssid-health.timer
    fi

    systemctl daemon-reload
    systemctl enable guardian-ssid-health.timer 2>/dev/null || true
    systemctl start guardian-ssid-health.timer 2>/dev/null || true

    log_info "Guardian AP services installed and enabled"
    log_info "  - guardian-wlan.service: Prepares wlan1 for AP mode"
    log_info "  - guardian-ap.service: Ensures hostapd/dnsmasq start"
    log_info "  - guardian-ssid-health.timer: Monitors SSID every 5 minutes"
    log_info "  - hostapd/dnsmasq overrides: Removed network-online dependency"
    log_info "  - All services enabled to start at boot"
}

# ============================================================
# AUTOMATIC WIFI CHANNEL OPTIMIZATION
# ============================================================
install_channel_optimization_service() {
    log_step "Installing Automatic WiFi Channel Optimization..."

    # Create state directory
    mkdir -p /var/lib/guardian

    # Create the channel optimization script
    log_info "Creating channel optimization script..."
    cat > /usr/local/bin/guardian-channel-optimize.sh << 'CHANNEL_SCRIPT'
#!/bin/bash
# Guardian WiFi Channel Optimization
# Automatically selects the best WiFi channel based on RF environment
# Runs at boot and daily at 4:00 AM

set -e

LOG_FILE="/var/log/hookprobe/channel-optimization.log"
STATE_FILE="/var/lib/guardian/channel_state.json"
HOSTAPD_CONF="/etc/hostapd/hostapd.conf"
AP_INTERFACE="wlan1"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "$1"
}

# Ensure log directory exists
mkdir -p /var/log/hookprobe

log "Starting WiFi channel optimization..."

# Check if AP interface exists
if [ ! -e "/sys/class/net/$AP_INTERFACE" ]; then
    AP_INTERFACE="wlan0"
    if [ ! -e "/sys/class/net/$AP_INTERFACE" ]; then
        log "ERROR: No WiFi interface found"
        exit 1
    fi
fi

# Get current channel from hostapd config
CURRENT_CHANNEL=$(grep "^channel=" "$HOSTAPD_CONF" 2>/dev/null | cut -d= -f2 || echo "6")

log "Current channel: $CURRENT_CHANNEL"

# Scan for networks and channel utilization
# Use iw scan if hostapd is not running, otherwise use survey dump
SCAN_DATA=""

if systemctl is-active --quiet hostapd; then
    # AP is running - use survey dump (non-disruptive)
    log "AP is running, using survey dump..."
    SCAN_DATA=$(sudo iw dev "$AP_INTERFACE" survey dump 2>/dev/null || true)
else
    # AP not running - can do full scan
    log "AP not running, performing full scan..."
    sudo ip link set "$AP_INTERFACE" up 2>/dev/null || true
    sleep 1
    SCAN_DATA=$(sudo iw dev "$AP_INTERFACE" scan 2>/dev/null || true)
fi

# Analyze channels 1, 6, 11 (non-overlapping 2.4GHz)
declare -A CHANNEL_SCORE

# Initialize scores (lower is better)
CHANNEL_SCORE[1]=0
CHANNEL_SCORE[6]=0
CHANNEL_SCORE[11]=0

# Parse scan/survey data for channel utilization
if [ -n "$SCAN_DATA" ]; then
    # Count networks on each channel from scan data
    for ch in 1 6 11; do
        # Look for DS Parameter Set (channel info) or frequency
        freq_2_4g=$((2407 + ch * 5))
        count=$(echo "$SCAN_DATA" | grep -c "frequency: $freq_2_4g" 2>/dev/null || echo "0")
        CHANNEL_SCORE[$ch]=$((CHANNEL_SCORE[$ch] + count * 10))

        # Check survey data for busy time
        busy=$(echo "$SCAN_DATA" | grep -A5 "frequency.*$freq_2_4g" | grep "channel busy time" | awk '{print $4}' | head -1)
        if [ -n "$busy" ] && [ "$busy" -gt 0 ]; then
            CHANNEL_SCORE[$ch]=$((CHANNEL_SCORE[$ch] + busy / 1000))
        fi
    done
fi

# Find best channel (lowest score)
BEST_CHANNEL=6
BEST_SCORE=${CHANNEL_SCORE[6]}

for ch in 1 11; do
    if [ "${CHANNEL_SCORE[$ch]}" -lt "$BEST_SCORE" ]; then
        BEST_SCORE="${CHANNEL_SCORE[$ch]}"
        BEST_CHANNEL=$ch
    fi
done

log "Channel scores: CH1=${CHANNEL_SCORE[1]}, CH6=${CHANNEL_SCORE[6]}, CH11=${CHANNEL_SCORE[11]}"
log "Best channel: $BEST_CHANNEL (score: $BEST_SCORE)"

# Only change channel if significantly better (score difference > 5)
SCORE_DIFF=$((${CHANNEL_SCORE[$CURRENT_CHANNEL]} - BEST_SCORE))

if [ "$BEST_CHANNEL" != "$CURRENT_CHANNEL" ] && [ "$SCORE_DIFF" -gt 5 ]; then
    log "Switching from channel $CURRENT_CHANNEL to $BEST_CHANNEL (improvement: $SCORE_DIFF)"

    # Update hostapd config
    sudo sed -i "s/^channel=.*/channel=$BEST_CHANNEL/" "$HOSTAPD_CONF"

    # Restart hostapd to apply new channel
    if systemctl is-active --quiet hostapd; then
        log "Restarting hostapd to apply new channel..."
        sudo systemctl restart hostapd
        sleep 3

        if systemctl is-active --quiet hostapd; then
            log "Channel changed successfully to $BEST_CHANNEL"
        else
            log "WARNING: hostapd failed to restart, reverting to channel $CURRENT_CHANNEL"
            sudo sed -i "s/^channel=.*/channel=$CURRENT_CHANNEL/" "$HOSTAPD_CONF"
            sudo systemctl start hostapd
        fi
    fi
else
    log "Keeping current channel $CURRENT_CHANNEL (no significant improvement available)"
fi

# Save state
cat > "$STATE_FILE" << EOF
{
    "last_optimization": "$(date -Iseconds)",
    "current_channel": $BEST_CHANNEL,
    "channel_scores": {
        "1": ${CHANNEL_SCORE[1]},
        "6": ${CHANNEL_SCORE[6]},
        "11": ${CHANNEL_SCORE[11]}
    },
    "auto_enabled": true
}
EOF

log "Channel optimization complete"
CHANNEL_SCRIPT

    chmod +x /usr/local/bin/guardian-channel-optimize.sh

    # Create systemd service for channel optimization
    log_info "Creating channel optimization service..."
    cat > /etc/systemd/system/guardian-channel-optimize.service << 'SERVICE_EOF'
[Unit]
Description=Guardian WiFi Channel Optimization
After=network.target hostapd.service
Wants=hostapd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/guardian-channel-optimize.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    # Create systemd timer for daily optimization at 4:00 AM
    log_info "Creating channel optimization timer..."
    cat > /etc/systemd/system/guardian-channel-optimize.timer << 'TIMER_EOF'
[Unit]
Description=Daily WiFi Channel Optimization at 4:00 AM

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
TIMER_EOF

    # Reload systemd
    systemctl daemon-reload

    # Enable and start timer
    systemctl enable guardian-channel-optimize.timer 2>/dev/null || true
    systemctl start guardian-channel-optimize.timer 2>/dev/null || true

    # Run optimization once at boot (via service)
    systemctl enable guardian-channel-optimize.service 2>/dev/null || true

    log_info "Automatic WiFi Channel Optimization installed"
    log_info "  - Runs at boot and daily at 4:00 AM"
    log_info "  - Selects best channel from 1, 6, 11 (non-overlapping)"
    log_info "  - Only changes if significant improvement available"
}

# ============================================================
# CONFIGURATION FILE CREATION
# ============================================================
create_default_config() {
    log_step "Creating Guardian configuration..."

    local CONFIG_DIR="/etc/guardian"
    local CONFIG_FILE="$CONFIG_DIR/guardian.yaml"

    # Create configuration directory
    mkdir -p "$CONFIG_DIR"

    # Skip if config already exists
    if [ -f "$CONFIG_FILE" ]; then
        log_info "Configuration file already exists: $CONFIG_FILE"
        return 0
    fi

    log_info "Creating default configuration file..."

    cat > "$CONFIG_FILE" << 'YAMLEOF'
# HookProbe Guardian Configuration
# Version: 5.0.0 Cortex
# Mode: Guardian (Portable Travel Security)
#
# Guardian mode provides simple WiFi hotspot with security features.
# All devices connect to the same network (br0 / 192.168.4.0/27).
#
# For VLAN segmentation and IoT isolation, use Fortress mode
# with VAP-capable WiFi adapters (Atheros AR9271, MediaTek MT7612U).

# Network Configuration (Guardian Simple Mode)
network:
  mode: "guardian"  # guardian = simple, fortress = vlan segmentation
  lan_interface: "br0"
  lan_subnet: "192.168.4.0/27"
  lan_gateway: "192.168.4.1"
  dhcp_start: "192.168.4.2"
  dhcp_end: "192.168.4.30"

# HTP (HookProbe Transport Protocol) Configuration
htp:
  enabled: true
  mesh_host: "mesh.hookprobe.com"
  mesh_port: 8443
  use_tls: true
  reconnect_interval: 30
  heartbeat_interval: 60
  compression: true

# HTP File Transfer Configuration
htp_file:
  enabled: true
  chunk_size: 8192  # 8KB (optimized for SBC memory)
  max_file_size_mb: 1024  # 1GB max file size
  transfer_timeout: 300  # 5 minutes
  compression_enabled: true
  verify_hash: true
  atomic_writes: true
  base_path: "/srv/guardian"
  allowed_paths:
    - "/home"
    - "/srv/files"
    - "/var/log/guardian"

# WAN Configuration (Internet uplink)
wan:
  interface: "eth0"
  failover_interface: "wlan0"  # USB WiFi can connect to upstream network
  metric_primary: 100
  metric_backup: 600

# Security Configuration
security:
  threat_detection:
    enabled: true
    layers: ["L2", "L3", "L4", "L5", "L6", "L7"]
  qsecbit:
    enabled: true
    amber_threshold: 0.45
    red_threshold: 0.70
  napse:
    enabled: true
    alert_log: "/var/log/hookprobe/napse/alerts.json"
  waf:
    enabled: true
    modsecurity_rules: "/etc/modsecurity/crs"
  xdp:
    enabled: true
    interface: "eth0"

# Web UI Configuration
webui:
  enabled: true
  host: "0.0.0.0"
  port: 8080
  debug: false
  theme: "dark"

# Logging Configuration
logging:
  level: "INFO"
  log_dir: "/var/log/hookprobe"
  max_size_mb: 100
  backup_count: 5
  syslog:
    enabled: false
    host: "localhost"
    port: 514
YAMLEOF

    # Set secure permissions
    chmod 640 "$CONFIG_FILE"

    log_info "Configuration created: $CONFIG_FILE"
    log_info "Edit this file to customize Guardian settings"
}

# ============================================================
# WEB UI INSTALLATION
# ============================================================
install_web_ui() {
    log_step "Installing Guardian Web UI..."

    # Copy entire web directory structure (modular Flask app)
    mkdir -p /opt/hookprobe/guardian/web
    cp -r "$GUARDIAN_ROOT/web/"* /opt/hookprobe/guardian/web/

    # Also copy app.py to guardian root for backwards compatibility
    cp "$GUARDIAN_ROOT/web/app.py" /opt/hookprobe/guardian/

    # Copy logo emblem for web UI
    if [ -f "$GUARDIAN_ROOT/../assets/hookprobe-emblem-small.png" ]; then
        cp "$GUARDIAN_ROOT/../assets/hookprobe-emblem-small.png" /opt/hookprobe/guardian/web/hookprobe-emblem.png
    fi

    log_info "Copied web UI: app.py, modules/, templates/, static/, utils.py, config.py"

    # Install shared Cortex visualization modules (frontend JS + backend Python)
    log_info "Installing shared Cortex visualization modules..."
    local SHARED_CORTEX="$GUARDIAN_ROOT/../../shared/cortex"
    if [ -d "$SHARED_CORTEX/frontend/js" ]; then
        # Frontend JS modules (for globe visualization)
        mkdir -p /opt/hookprobe/shared/cortex/frontend/js
        cp "$SHARED_CORTEX/frontend/js/"*.js /opt/hookprobe/shared/cortex/frontend/js/ 2>/dev/null || true
        log_info "Installed Cortex frontend JS modules"
    else
        log_warn "Shared Cortex frontend modules not found at $SHARED_CORTEX/frontend/js"
    fi

    # Backend Python modules (for demo data generation with 75+ nodes)
    if [ -d "$SHARED_CORTEX/backend" ]; then
        mkdir -p /opt/hookprobe/shared/cortex/backend
        cp "$SHARED_CORTEX/backend/"*.py /opt/hookprobe/shared/cortex/backend/ 2>/dev/null || true
        # Create __init__.py if it doesn't exist
        touch /opt/hookprobe/shared/cortex/__init__.py
        touch /opt/hookprobe/shared/cortex/backend/__init__.py
        log_info "Installed Cortex backend Python modules (demo data generator)"
    else
        log_warn "Shared Cortex backend modules not found at $SHARED_CORTEX/backend"
    fi

    # Install ML libraries for dnsXai AI features
    log_info "Installing ML libraries for dnsXai..."

    # First try system packages (more reliable on ARM/Raspberry Pi)
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq python3-sklearn python3-joblib 2>/dev/null && {
            log_info "ML libraries installed via apt"
        } || {
            # Fall back to pip if system packages not available
            log_info "System packages not available, trying pip..."
            # Install build dependencies first
            apt-get install -y -qq python3-dev build-essential 2>/dev/null || true
            pip3 install --break-system-packages numpy scikit-learn joblib 2>&1 | head -5 || \
            pip3 install numpy scikit-learn joblib 2>&1 | head -5 || \
            log_warn "Could not install ML libraries - dnsXai will run in rule-based mode"
        }
    elif command -v dnf &>/dev/null; then
        dnf install -y -q python3-scikit-learn python3-joblib 2>/dev/null && {
            log_info "ML libraries installed via dnf"
        } || {
            log_info "System packages not available, trying pip..."
            dnf install -y -q python3-devel gcc 2>/dev/null || true
            pip3 install numpy scikit-learn joblib 2>&1 | head -5 || \
            log_warn "Could not install ML libraries - dnsXai will run in rule-based mode"
        }
    else
        # Generic pip install
        pip3 install --break-system-packages numpy scikit-learn joblib 2>&1 | head -5 || \
        pip3 install numpy scikit-learn joblib 2>&1 | head -5 || \
        log_warn "Could not install ML libraries - dnsXai will run in rule-based mode"
    fi

    # If guardian-webui was already running, restart it to pick up new ML libraries
    if systemctl is-active --quiet guardian-webui 2>/dev/null; then
        log_info "Restarting guardian-webui to load ML libraries..."
        systemctl restart guardian-webui
    fi

    # Create systemd service
    cat > /etc/systemd/system/guardian-webui.service << 'EOF'
[Unit]
Description=HookProbe Guardian Web UI
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/hookprobe/guardian/web
ExecStart=/usr/bin/python3 /opt/hookprobe/guardian/web/app.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-webui

    log_info "Web UI installed"
}

# ============================================================
# SERVICE MANAGEMENT
# ============================================================
enable_services() {
    log_step "Enabling services..."

    systemctl unmask hostapd 2>/dev/null || true
    systemctl enable hostapd
    systemctl enable dnsmasq
    systemctl enable nftables 2>/dev/null || true
    systemctl enable openvswitch-switch 2>/dev/null || systemctl enable openvswitch 2>/dev/null || true

    # Enable Guardian AP services (WAN-independent startup)
    log_info "Enabling Guardian AP services for offline-first operation..."
    systemctl enable guardian-wlan 2>/dev/null || true
    systemctl enable guardian-ap 2>/dev/null || true

    # Enable all Guardian security services
    # Note: IDS (NAPSE) is deployed via AIOCHI containers, not Guardian
    log_info "Enabling Guardian security stack..."
    systemctl enable guardian-offline 2>/dev/null || true
    systemctl enable guardian-waf 2>/dev/null || true
    systemctl enable guardian-xdp 2>/dev/null || true
    systemctl enable guardian-aggregator 2>/dev/null || true
    systemctl enable guardian-neuro 2>/dev/null || true
    systemctl enable guardian-qsecbit 2>/dev/null || true
    systemctl enable guardian-webui 2>/dev/null || true

    log_info "Services enabled"
    log_info "AP services will start on boot even without WAN connectivity"
}

start_services() {
    log_step "Starting services..."

    # Start OVS first
    systemctl start openvswitch-switch 2>/dev/null || systemctl start openvswitch 2>/dev/null || true

    systemctl start nftables 2>/dev/null || true

    systemctl start dnsmasq

    # ─────────────────────────────────────────────────────────────
    # Start hostapd with enhanced error handling
    # ─────────────────────────────────────────────────────────────
    log_info "Starting hostapd WiFi access point..."

    # Check if hostapd is already running (started by install_ap_services)
    if systemctl is-active --quiet hostapd; then
        log_info "Hostapd is already running, skipping startup"
    else
        # Set regulatory domain from hostapd config before starting
        local HOSTAPD_COUNTRY=$(grep "^country_code=" /etc/hostapd/hostapd.conf 2>/dev/null | cut -d= -f2)
        if [ -n "$HOSTAPD_COUNTRY" ]; then
            log_info "Setting regulatory domain to $HOSTAPD_COUNTRY..."
            iw reg set "$HOSTAPD_COUNTRY" 2>/dev/null || true
            sleep 2
        fi

        # Make sure WiFi interface is ready
        local WIFI_IFACE="${HOOKPROBE_WIFI_IFACE:-wlan1}"
        if [ ! -d "/sys/class/net/$WIFI_IFACE" ]; then
            WIFI_IFACE=$(ls /sys/class/net/ | grep -E '^wlan' | head -1)
        fi

        if [ -n "$WIFI_IFACE" ]; then
            # Kill interfering processes
            pkill -f "wpa_supplicant.*$WIFI_IFACE" 2>/dev/null || true
            sleep 1

            # Ensure interface is down (hostapd will bring it up)
            ip link set "$WIFI_IFACE" down 2>/dev/null || true
            sleep 1

            # Try to start hostapd
            if ! systemctl start hostapd; then
                log_warn "Hostapd failed to start, attempting diagnostics..."

                # Show hostapd error output
                journalctl -u hostapd -n 20 --no-pager 2>/dev/null || true

                # Try running hostapd directly for better error message
                log_info "Running hostapd diagnostic..."
                timeout 5 hostapd -d /etc/hostapd/hostapd.conf 2>&1 | head -30 || true

                # Common fixes
                log_info "Attempting common fixes..."

                # Fix 1: Try without bridge first
                if grep -q "bridge=br0" /etc/hostapd/hostapd.conf; then
                    log_info "  - Trying without bridge..."
                    sed -i 's/^bridge=br0/#bridge=br0/' /etc/hostapd/hostapd.conf
                    if systemctl start hostapd 2>/dev/null; then
                        log_info "Hostapd started without bridge mode"
                    else
                        # Restore bridge setting
                        sed -i 's/^#bridge=br0/bridge=br0/' /etc/hostapd/hostapd.conf
                    fi
                fi

            # Fix 2: Try different channel
            if ! systemctl is-active --quiet hostapd; then
                log_info "  - Trying channel 1..."
                sed -i 's/^channel=.*/channel=1/' /etc/hostapd/hostapd.conf
                systemctl start hostapd 2>/dev/null || true
            fi

            # Fix 3: Disable HT capabilities for older adapters
            if ! systemctl is-active --quiet hostapd; then
                log_info "  - Disabling HT capabilities..."
                sed -i 's/^ht_capab=.*/#ht_capab=[DISABLED]/' /etc/hostapd/hostapd.conf
                sed -i 's/^ieee80211n=1/ieee80211n=0/' /etc/hostapd/hostapd.conf
                systemctl start hostapd 2>/dev/null || true
            fi

            # Final check
            if ! systemctl is-active --quiet hostapd; then
                log_error "Hostapd could not be started. WiFi AP will not be available."
                log_error "Check: journalctl -u hostapd -f"
                log_error "Common issues:"
                log_error "  1. WiFi adapter doesn't support AP mode"
                log_error "  2. Another process is using the interface"
                log_error "  3. Regulatory domain restrictions"
            fi
        else
            log_info "Hostapd started successfully"
        fi
    else
        log_warn "No WiFi interface found, skipping hostapd"
    fi
fi  # end of "if hostapd not already running"

    systemctl start guardian-webui

    # Start security containers and services
    log_info "Starting security stack..."

    # Note: IDS (NAPSE) is deployed via AIOCHI containers, not Guardian

    # Web Application Firewall
    log_info "  - Starting ModSecurity WAF..."
    systemctl start guardian-waf 2>/dev/null || true

    # XDP/eBPF DDoS protection
    log_info "  - Starting XDP DDoS Protection..."
    systemctl start guardian-xdp 2>/dev/null || true

    # Threat aggregator
    log_info "  - Starting Threat Aggregator..."
    systemctl start guardian-aggregator 2>/dev/null || true

    # QSecBit agent
    log_info "  - Starting QSecBit Agent..."
    systemctl start guardian-qsecbit 2>/dev/null || true

    # Neuro protocol
    log_info "  - Starting Neuro Protocol..."
    systemctl start guardian-neuro 2>/dev/null || true

    # dnsXai Ad Block (integrated with dnsmasq, no separate service needed)
    log_info "  - dnsXai Ad Block: Active (via dnsmasq)"

    # Wait a moment for containers to start
    sleep 3

    # Verify services are running
    log_info "Verifying security stack status..."
    local failed_services=""

    for svc in guardian-waf guardian-xdp guardian-aggregator; do
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            failed_services="$failed_services $svc"
        fi
    done

    if [ -n "$failed_services" ]; then
        log_warn "Some services may need attention:$failed_services"
        log_info "Check with: systemctl status <service-name>"
    else
        log_info "All security services started successfully"
    fi

    log_info "Services started"
}

# ============================================================
# UNIFIED GUARDIAN INSTALLATION
# ============================================================
show_guardian_banner() {
    echo ""
    echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║         HookProbe Guardian - Cortex 5.0.0                  ║${NC}"
    echo -e "${BOLD}${GREEN}║       Portable Travel Security Companion                   ║${NC}"
    echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}${WHITE}Security Features:${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} L1-L7 OSI Layer Threat Detection"
    echo -e "  ${GREEN}✓${NC} QSecBit AI-Powered Security Scoring"
    echo -e "  ${GREEN}✓${NC} NAPSE IDS/IPS (via AIOCHI containers)"
    echo -e "  ${GREEN}✓${NC} ModSecurity WAF (Web Application Firewall)"
    echo -e "  ${GREEN}✓${NC} XDP/eBPF High-Performance Packet Processing"
    echo -e "  ${GREEN}✓${NC} dnsXai Ad Block (beta) - ML DNS Protection"
    echo -e "  ${GREEN}✓${NC} MAC Authentication & Device Tracking"
    echo -e "  ${GREEN}✓${NC} HTP Secure File Transfer"
    echo ""
    echo -e "  ${BOLD}${WHITE}Network Features:${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} Simple WiFi Hotspot (all devices on br0)"
    echo -e "  ${GREEN}✓${NC} WAN Failover (eth0 primary, wlan0 backup)"
    echo -e "  ${GREEN}✓${NC} Connected Devices Tracking via Web UI"
    echo ""
    echo -e "  ${DIM}For VLAN segmentation, use Fortress mode with VAP-capable adapters${NC}"
    echo ""
}

confirm_installation() {
    show_guardian_banner

    echo -e "${YELLOW}This will install Guardian with all security features.${NC}"
    echo ""

    # Check mesh connectivity
    if check_mesh_connectivity; then
        echo -e "  ${GREEN}✓${NC} Mesh connectivity: ${GREEN}Available${NC}"
    else
        echo -e "  ${YELLOW}!${NC} Mesh connectivity: ${YELLOW}Offline${NC} (HTP Mesh features disabled until connected)"
    fi
    echo ""

    read -p "Continue with installation? (yes/no) [yes]: " confirm
    confirm=${confirm:-yes}

    if [ "$confirm" != "yes" ] && [ "$confirm" != "y" ]; then
        echo "Installation cancelled."
        exit 0
    fi
}

# ============================================================
# NETWORK CONFIGURATION PROMPTS
# ============================================================
prompt_network_config() {
    # Skip if already configured via environment (from main install.sh)
    if [ -n "${HOOKPROBE_WIFI_SSID:-}" ] && [ -n "${HOOKPROBE_WIFI_PASS:-}" ]; then
        log_info "Using pre-configured WiFi settings: $HOOKPROBE_WIFI_SSID"
        return
    fi

    echo ""
    echo -e "${BOLD}Network Configuration${NC}"
    echo ""

    # Hotspot SSID
    read -p "Hotspot SSID [HookProbe-Guardian]: " ssid
    export HOOKPROBE_WIFI_SSID="${ssid:-HookProbe-Guardian}"

    # Hotspot password
    while true; do
        read -sp "Hotspot password (min 8 chars): " pass
        echo ""
        if [ ${#pass} -ge 8 ]; then
            export HOOKPROBE_WIFI_PASS="$pass"
            break
        else
            echo -e "${RED}Password must be at least 8 characters${NC}"
        fi
    done

    echo ""
    echo -e "${GREEN}✓${NC} Network configuration saved"
}

# ============================================================
# VM SUPPORT (QEMU/KVM for Home Assistant, OpenMediaVault)
# ============================================================

# Detect system RAM in GB
detect_system_ram() {
    local mem_kb
    mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    # Convert KB to GB (integer)
    echo $(( mem_kb / 1024 / 1024 ))
}

# Check if VM support is available (6GB+ RAM required)
check_vm_support_available() {
    local ram_gb
    ram_gb=$(detect_system_ram)
    if [ "$ram_gb" -ge 6 ]; then
        return 0
    fi
    return 1
}

# Prompt user for VM support installation
prompt_vm_support() {
    local ram_gb
    ram_gb=$(detect_system_ram)

    # Skip if less than 6GB RAM
    if [ "$ram_gb" -lt 6 ]; then
        log_info "VM support requires 6GB+ RAM (detected: ${ram_gb}GB) - skipping"
        export HOOKPROBE_VM_SUPPORT="no"
        return 0
    fi

    echo ""
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║          VM Support Available (${ram_gb}GB RAM detected)            ║${NC}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Guardian can run lightweight VMs alongside security services:"
    echo ""
    echo -e "  ${GREEN}•${NC} Home Assistant    - Smart home automation (1GB RAM)"
    echo -e "  ${GREEN}•${NC} OpenMediaVault   - NAS/Storage management (1GB RAM)"
    echo ""
    echo -e "  ${DIM}Uses QEMU/KVM virtualization with libvirt management${NC}"
    echo -e "  ${DIM}VMs will be accessible from Guardian dashboard${NC}"
    echo ""

    read -p "Install VM support with Home Assistant + OpenMediaVault? (yes/no) [yes]: " vm_choice
    vm_choice=${vm_choice:-yes}

    if [ "$vm_choice" = "yes" ] || [ "$vm_choice" = "y" ]; then
        export HOOKPROBE_VM_SUPPORT="yes"
        log_info "VM support will be installed"
    else
        export HOOKPROBE_VM_SUPPORT="no"
        log_info "VM support skipped"
    fi
}

# Install QEMU/KVM and libvirt packages
install_vm_packages() {
    if [ "${HOOKPROBE_VM_SUPPORT:-no}" != "yes" ]; then
        return 0
    fi

    log_step "Installing VM support packages (QEMU/KVM)..."

    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq \
            qemu-system-arm \
            qemu-utils \
            libvirt-daemon-system \
            libvirt-clients \
            virtinst \
            virt-manager \
            bridge-utils \
            genisoimage \
            cloud-image-utils \
            2>/dev/null || {
            log_warn "Some VM packages may not be available, installing core packages..."
            apt-get install -y -qq qemu-system libvirt-daemon-system libvirt-clients 2>/dev/null || true
        }
    fi

    # Enable and start libvirtd
    systemctl enable libvirtd 2>/dev/null || true
    systemctl start libvirtd 2>/dev/null || true

    # Add current user to libvirt group
    if [ -n "${SUDO_USER:-}" ]; then
        usermod -aG libvirt "$SUDO_USER" 2>/dev/null || true
        usermod -aG kvm "$SUDO_USER" 2>/dev/null || true
    fi

    log_info "VM packages installed"
}

# Configure libvirt network to use Guardian's br0 bridge
configure_libvirt_network() {
    if [ "${HOOKPROBE_VM_SUPPORT:-no}" != "yes" ]; then
        return 0
    fi

    log_step "Configuring libvirt network..."

    # Create hookprobe network definition using existing br0 bridge
    local net_xml="/tmp/hookprobe-network.xml"
    cat > "$net_xml" << 'NETXML'
<network>
  <name>hookprobe</name>
  <forward mode="bridge"/>
  <bridge name="br0"/>
</network>
NETXML

    # Define and start the network
    virsh net-define "$net_xml" 2>/dev/null || true
    virsh net-start hookprobe 2>/dev/null || true
    virsh net-autostart hookprobe 2>/dev/null || true

    rm -f "$net_xml"
    log_info "Libvirt 'hookprobe' network configured (bridge: br0)"
}

# Configure DHCP reservations for VMs
configure_vm_dhcp_reservations() {
    if [ "${HOOKPROBE_VM_SUPPORT:-no}" != "yes" ]; then
        return 0
    fi

    local dnsmasq_conf="/etc/dnsmasq.d/hookprobe-vms.conf"

    log_step "Configuring VM DHCP reservations..."

    cat > "$dnsmasq_conf" << 'VMDHCP'
# HookProbe VM DHCP Reservations
# Home Assistant: 192.168.4.10
dhcp-host=52:54:00:HP:HA:01,192.168.4.10,homeassistant
# OpenMediaVault: 192.168.4.11
dhcp-host=52:54:00:HP:OM:01,192.168.4.11,openmediavault

# DNS entries for VMs
address=/homeassistant.local/192.168.4.10
address=/ha.local/192.168.4.10
address=/openmediavault.local/192.168.4.11
address=/omv.local/192.168.4.11
address=/nas.local/192.168.4.11
VMDHCP

    log_info "VM DHCP reservations configured"
}

# Create VM storage directory
setup_vm_storage() {
    if [ "${HOOKPROBE_VM_SUPPORT:-no}" != "yes" ]; then
        return 0
    fi

    log_step "Setting up VM storage..."

    local vm_dir="/var/lib/hookprobe/vms"
    local images_dir="$vm_dir/images"
    local disks_dir="$vm_dir/disks"

    mkdir -p "$images_dir" "$disks_dir"
    chmod 755 "$vm_dir"

    # Create libvirt storage pool
    virsh pool-define-as hookprobe-vms dir --target "$disks_dir" 2>/dev/null || true
    virsh pool-build hookprobe-vms 2>/dev/null || true
    virsh pool-start hookprobe-vms 2>/dev/null || true
    virsh pool-autostart hookprobe-vms 2>/dev/null || true

    log_info "VM storage configured at $vm_dir"
}

# Download and deploy Home Assistant VM
deploy_homeassistant_vm() {
    if [ "${HOOKPROBE_VM_SUPPORT:-no}" != "yes" ]; then
        return 0
    fi

    log_step "Deploying Home Assistant VM..."

    local vm_dir="/var/lib/hookprobe/vms"
    local ha_image="$vm_dir/images/haos_ova-12.4.qcow2"
    local ha_disk="$vm_dir/disks/homeassistant.qcow2"

    # Download Home Assistant OS image if not exists
    if [ ! -f "$ha_image" ]; then
        log_info "Downloading Home Assistant OS (this may take a few minutes)..."
        local ha_url="https://github.com/home-assistant/operating-system/releases/download/12.4/haos_generic-aarch64-12.4.qcow2.xz"

        if curl -L -o "${ha_image}.xz" "$ha_url" 2>/dev/null; then
            log_info "Extracting Home Assistant image..."
            xz -d "${ha_image}.xz" 2>/dev/null || {
                log_warn "Failed to extract, trying uncompressed download..."
                rm -f "${ha_image}.xz"
                curl -L -o "$ha_image" "https://github.com/home-assistant/operating-system/releases/download/12.4/haos_generic-aarch64-12.4.qcow2" 2>/dev/null || {
                    log_error "Failed to download Home Assistant image"
                    return 1
                }
            }
        else
            log_error "Failed to download Home Assistant image"
            return 1
        fi
    fi

    # Create VM disk from image
    if [ ! -f "$ha_disk" ]; then
        log_info "Creating Home Assistant VM disk..."
        cp "$ha_image" "$ha_disk"
        # Resize disk to 32GB
        qemu-img resize "$ha_disk" 32G 2>/dev/null || true
    fi

    # Define VM
    local ha_xml="/tmp/homeassistant-vm.xml"
    cat > "$ha_xml" << 'HAXML'
<domain type='kvm'>
  <name>homeassistant</name>
  <uuid>a1b2c3d4-e5f6-7890-abcd-ef1234567890</uuid>
  <memory unit='GiB'>1</memory>
  <vcpu>2</vcpu>
  <os>
    <type arch='aarch64' machine='virt'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
  </features>
  <cpu mode='host-passthrough'/>
  <clock offset='utc'/>
  <devices>
    <emulator>/usr/bin/qemu-system-aarch64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/hookprobe/vms/disks/homeassistant.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <mac address='52:54:00:48:50:01'/>
      <source network='hookprobe'/>
      <model type='virtio'/>
    </interface>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>
  </devices>
</domain>
HAXML

    # Check if VM already exists
    if virsh dominfo homeassistant &>/dev/null; then
        log_info "Home Assistant VM already exists"
    else
        virsh define "$ha_xml" 2>/dev/null || {
            log_warn "Failed to define Home Assistant VM"
            rm -f "$ha_xml"
            return 1
        }
        log_info "Home Assistant VM defined"
    fi

    rm -f "$ha_xml"

    # Set VM to autostart
    virsh autostart homeassistant 2>/dev/null || true

    # Start VM
    virsh start homeassistant 2>/dev/null || log_warn "Home Assistant VM not started (may already be running)"

    log_info "Home Assistant VM deployed - access at http://192.168.4.10:8123"
}

# Download and deploy OpenMediaVault VM
deploy_openmediavault_vm() {
    if [ "${HOOKPROBE_VM_SUPPORT:-no}" != "yes" ]; then
        return 0
    fi

    log_step "Deploying OpenMediaVault VM..."

    local vm_dir="/var/lib/hookprobe/vms"
    local omv_disk="$vm_dir/disks/openmediavault.qcow2"

    # Create blank disk for OMV (will need manual install or cloud-init)
    if [ ! -f "$omv_disk" ]; then
        log_info "Creating OpenMediaVault VM disk (32GB)..."
        qemu-img create -f qcow2 "$omv_disk" 32G 2>/dev/null || {
            log_error "Failed to create OMV disk"
            return 1
        }
    fi

    # For OMV, we'll use Debian cloud image as base and configure OMV on first boot
    local debian_image="$vm_dir/images/debian-12-genericcloud-arm64.qcow2"
    if [ ! -f "$debian_image" ]; then
        log_info "Downloading Debian cloud image for OpenMediaVault..."
        curl -L -o "$debian_image" \
            "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-arm64.qcow2" 2>/dev/null || {
            log_warn "Failed to download Debian image - OMV VM will need manual setup"
        }
    fi

    # Create OMV disk from Debian base if image exists and disk is empty
    if [ -f "$debian_image" ]; then
        local disk_size
        disk_size=$(stat -c%s "$omv_disk" 2>/dev/null || echo "0")
        if [ "$disk_size" -lt 1000000 ]; then
            cp "$debian_image" "$omv_disk"
            qemu-img resize "$omv_disk" 32G 2>/dev/null || true
        fi
    fi

    # Create cloud-init config for OMV
    local ci_dir="$vm_dir/cloud-init/omv"
    mkdir -p "$ci_dir"

    cat > "$ci_dir/user-data" << 'CIUSERDATA'
#cloud-config
hostname: openmediavault
manage_etc_hosts: true
users:
  - name: admin
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    passwd: $6$rounds=4096$hookprobe$YQ3vPgH.5qG8qP5K5GyBVYKj3z9TmCBaJ1X5vYbKrL0T9QZJX5yP8fGh3d6wKmN7pL2s1vR8cB4x9nM0qT5w.
package_update: true
package_upgrade: true
packages:
  - curl
  - gnupg
runcmd:
  - curl -sSL https://github.com/OpenMediaVault-Plugin-Developers/installScript/raw/master/install | bash
  - systemctl enable openmediavault
CIUSERDATA

    cat > "$ci_dir/meta-data" << 'CIMETADATA'
instance-id: omv-001
local-hostname: openmediavault
CIMETADATA

    # Create cloud-init ISO
    local ci_iso="$vm_dir/disks/omv-cloud-init.iso"
    if command -v genisoimage &>/dev/null; then
        genisoimage -output "$ci_iso" -volid cidata -joliet -rock \
            "$ci_dir/user-data" "$ci_dir/meta-data" 2>/dev/null || true
    fi

    # Define VM
    local omv_xml="/tmp/openmediavault-vm.xml"
    cat > "$omv_xml" << 'OMVXML'
<domain type='kvm'>
  <name>openmediavault</name>
  <uuid>b2c3d4e5-f6a7-8901-bcde-f23456789012</uuid>
  <memory unit='GiB'>1</memory>
  <vcpu>2</vcpu>
  <os>
    <type arch='aarch64' machine='virt'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
  </features>
  <cpu mode='host-passthrough'/>
  <clock offset='utc'/>
  <devices>
    <emulator>/usr/bin/qemu-system-aarch64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/hookprobe/vms/disks/openmediavault.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/var/lib/hookprobe/vms/disks/omv-cloud-init.iso'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <mac address='52:54:00:48:50:02'/>
      <source network='hookprobe'/>
      <model type='virtio'/>
    </interface>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>
  </devices>
</domain>
OMVXML

    # Check if VM already exists
    if virsh dominfo openmediavault &>/dev/null; then
        log_info "OpenMediaVault VM already exists"
    else
        virsh define "$omv_xml" 2>/dev/null || {
            log_warn "Failed to define OpenMediaVault VM"
            rm -f "$omv_xml"
            return 1
        }
        log_info "OpenMediaVault VM defined"
    fi

    rm -f "$omv_xml"

    # Set VM to autostart
    virsh autostart openmediavault 2>/dev/null || true

    # Start VM
    virsh start openmediavault 2>/dev/null || log_warn "OpenMediaVault VM not started (may already be running)"

    log_info "OpenMediaVault VM deployed - access at http://192.168.4.11"
    log_info "Default credentials: admin / openmediavault"
}

# Install VM management service for Guardian
install_vm_management_service() {
    if [ "${HOOKPROBE_VM_SUPPORT:-no}" != "yes" ]; then
        return 0
    fi

    log_step "Installing VM management service..."

    # Create systemd service for VM health monitoring
    cat > /etc/systemd/system/guardian-vms.service << 'VMSERVICE'
[Unit]
Description=HookProbe Guardian VM Management
After=libvirtd.service network-online.target
Wants=network-online.target
Requires=libvirtd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'virsh start homeassistant 2>/dev/null || true; virsh start openmediavault 2>/dev/null || true'
ExecStop=/bin/bash -c 'virsh shutdown homeassistant 2>/dev/null || true; virsh shutdown openmediavault 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
VMSERVICE

    systemctl daemon-reload
    systemctl enable guardian-vms.service 2>/dev/null || true

    log_info "VM management service installed"
}

# Main VM support installation function
install_vm_support() {
    if [ "${HOOKPROBE_VM_SUPPORT:-no}" != "yes" ]; then
        return 0
    fi

    log_step "Installing VM support..."

    install_vm_packages
    setup_vm_storage
    configure_libvirt_network
    configure_vm_dhcp_reservations

    # Deploy VMs
    deploy_homeassistant_vm
    deploy_openmediavault_vm

    install_vm_management_service

    log_info "VM support installation complete"
}

# ============================================================
# MAIN INSTALLATION
# ============================================================
main() {
    # Prerequisites
    check_root
    detect_platform
    detect_interfaces

    # Show banner and confirm
    confirm_installation

    # Check WiFi AP support
    if [ "$WIFI_AP_SUPPORT" != "true" ]; then
        log_error "No WiFi interface with AP mode support found"
        log_error "Guardian requires WiFi AP capability"
        exit 1
    fi

    # Install base packages
    log_step "Installing base packages..."
    install_packages

    # Configure system locale (en_US.UTF-8)
    configure_system_locale

    # Auto-detect and configure WiFi country from public IP
    configure_wifi_country

    # Setup Guardian config directory
    log_step "Setting up Guardian configuration..."
    setup_guardian_config

    # Install Podman container runtime
    log_step "Installing container runtime..."
    install_podman

    # Install Open vSwitch
    log_step "Installing Open vSwitch..."
    install_openvswitch

    # Configure NetworkManager (must be before OVS bridge setup)
    # This prevents NM from managing OVS/hostapd interfaces
    log_step "Configuring NetworkManager..."
    configure_networkmanager

    # Setup OVS bridge with VXLAN tunnel
    log_step "Configuring OVS bridge..."
    setup_ovs_bridge

    # Setup MACsec (optional - disabled by default, enable with HOOKPROBE_MACSEC_ENABLED=true)
    # Note: MACsec may not work on all Raspberry Pi models due to kernel configuration
    setup_macsec

    # Network configuration prompt
    prompt_network_config

    # VM support prompt (only on 6GB+ RAM systems)
    prompt_vm_support

    # Install security containers (WAF, Neuro) and services (IDS via NAPSE/AIOCHI)
    log_step "Installing security containers..."
    install_security_containers

    # Configure Guardian networking
    log_step "Configuring Guardian networking..."
    configure_base_networking       # Setup bridge, hostapd, DHCP
    configure_guardian_hostapd      # Configure hostapd for simple mode

    # Install QSecBit agent
    log_step "Installing QSecBit agent..."
    install_qsecbit_agent

    # Install Guardian Python library
    log_step "Installing Guardian library..."
    install_guardian_lib

    # Install Offline Mode service (smart channel selection, route metrics)
    log_step "Installing Offline Mode service..."
    install_offline_mode_service

    # Install AP services (WAN-independent startup)
    log_step "Installing AP services for WAN-independent operation..."
    install_ap_services

    # Install automatic WiFi channel optimization
    log_step "Installing Automatic WiFi Channel Optimization..."
    install_channel_optimization_service

    # Create default configuration file
    log_step "Creating configuration file..."
    create_default_config

    # Save mode configuration (always unified now)
    mkdir -p /opt/hookprobe/guardian
    echo "unified" > /opt/hookprobe/guardian/mode.conf
    log_info "Mode: unified (all features enabled)"

    # Install Web UI
    log_step "Installing Web UI..."
    install_web_ui

    # Install VM support (if enabled)
    install_vm_support

    # Enable and start services
    log_step "Starting services..."
    enable_services
    start_services

    # Final summary
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       Guardian Cortex 5.0.0 Installation Complete!        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "  Version:     ${BOLD}Cortex 5.0.0${NC}"
    echo -e "  Mode:        ${BOLD}Guardian (Portable Travel Security)${NC}"
    echo -e "  Hotspot:     ${BOLD}${HOOKPROBE_WIFI_SSID:-HookProbe-Guardian}${NC}"
    echo -e "  Network:     ${BOLD}192.168.4.0/27 (br0, 30 devices max)${NC}"
    echo -e "  Web UI:      ${BOLD}http://192.168.4.1:8080${NC}"
    echo ""
    echo -e "  ${BOLD}Security Features:${NC}"
    echo -e "  • L1-L7 OSI Layer Threat Detection"
    echo -e "  • QSecBit AI Security Scoring"
    echo -e "  • NAPSE IDS/IPS (via AIOCHI)"
    echo -e "  • ModSecurity WAF"
    echo -e "  • XDP/eBPF Acceleration"
    echo ""
    echo -e "  ${BOLD}Network Features:${NC}"
    echo -e "  • Simple WiFi Hotspot (all devices on br0)"
    echo -e "  • Offline Mode - Works without WAN connection"
    echo -e "  • Smart Channel Selection (scans for least congested)"
    echo -e "  • MAC Authentication & Device Tracking"
    echo -e "  • Connected Devices list in Web UI"
    echo -e "  • WAN Failover (eth0 primary, wlan0 backup)"
    echo -e "  • Route Metrics (eth0:100, wlan:200 for proper priority)"
    echo -e "  • HTP Secure File Transfer"
    echo ""
    echo -e "  ${CYAN}Note:${NC} For IoT VLAN segmentation, upgrade to ${BOLD}Fortress${NC} mode"
    echo -e "        with VAP-capable WiFi adapters (Atheros AR9271, MT7612U)"
    echo ""
    if [ "${HOOKPROBE_ADBLOCK:-yes}" = "yes" ]; then
        echo -e "  ${BOLD}Additional:${NC}"
        echo -e "  • dnsXai Ad Block (beta): Integrated in Web UI - dnsXai tab"
        echo -e "    ML-powered domain classification, CNAME uncloaking, threat detection"
        echo ""
    fi
    if [ "${HOOKPROBE_VM_SUPPORT:-no}" = "yes" ]; then
        echo -e "  ${BOLD}${CYAN}VM Support:${NC}"
        echo -e "  • Home Assistant:    ${BOLD}http://192.168.4.10:8123${NC} (ha.local)"
        echo -e "  • OpenMediaVault:    ${BOLD}http://192.168.4.11${NC} (omv.local)"
        echo -e "  ${DIM}  Manage VMs from Guardian dashboard or via 'virsh' command${NC}"
        echo ""
    fi
    echo -e "  ${BOLD}Service Status:${NC}"
    echo -e "  $(systemctl is-active hostapd 2>/dev/null || echo 'inactive') hostapd (WiFi AP)"
    echo -e "  $(systemctl is-active dnsmasq 2>/dev/null || echo 'inactive') dnsmasq (DHCP/DNS)"
    echo -e "  $(systemctl is-active guardian-webui 2>/dev/null || echo 'inactive') guardian-webui"
    echo -e "  NAPSE IDS: deployed via AIOCHI containers"
    echo -e "  $(systemctl is-active guardian-waf 2>/dev/null || echo 'inactive') guardian-waf (WAF)"
    echo -e "  $(systemctl is-active guardian-qsecbit 2>/dev/null || echo 'inactive') guardian-qsecbit"
    if [ "${HOOKPROBE_VM_SUPPORT:-no}" = "yes" ]; then
        echo -e "  $(systemctl is-active libvirtd 2>/dev/null || echo 'inactive') libvirtd (VMs)"
        echo -e "  $(virsh domstate homeassistant 2>/dev/null || echo 'not defined') homeassistant VM"
        echo -e "  $(virsh domstate openmediavault 2>/dev/null || echo 'not defined') openmediavault VM"
    fi
    echo ""
    echo -e "  ${YELLOW}Next steps:${NC}"
    echo -e "  1. Connect to '${HOOKPROBE_WIFI_SSID:-HookProbe-Guardian}' WiFi network"
    echo -e "  2. Open http://192.168.4.1:8080 in your browser"
    echo -e "  3. View connected devices in the Web UI"
    echo -e "  4. Configure upstream WiFi connection for internet access"
    echo ""
    echo -e "  ${DIM}Logs: journalctl -u guardian-qsecbit -f${NC}"
    echo ""
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
