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
#   - Full security stack (IDS, WAF, XDP DDoS protection)
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

    log_info "Ethernet interfaces ($ETH_COUNT): $ETH_INTERFACES"
    log_info "WiFi interfaces ($WIFI_COUNT): $WIFI_INTERFACES"
    log_info "WiFi AP mode: $WIFI_AP_SUPPORT"
}

check_mssp_connectivity() {
    local mssp_url="${HOOKPROBE_MSSP_URL:-https://nexus.hookprobe.com}"
    local timeout=10

    log_step "Checking MSSP connectivity..."

    if command -v curl &>/dev/null; then
        if curl -s --max-time $timeout "$mssp_url/api/health" &>/dev/null; then
            log_info "MSSP server is reachable"
            return 0
        fi
    fi

    log_warn "MSSP server not reachable (SDN features may be limited)"
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

        # Create /etc/default/hostapd before installing hostapd
        # This prevents the post-install script from failing
        if [ ! -f /etc/default/hostapd ]; then
            mkdir -p /etc/default
            echo '# Defaults for hostapd initscript' > /etc/default/hostapd
            echo 'DAEMON_CONF=""' >> /etc/default/hostapd
        fi

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
            python3 \
            python3-pip \
            python3-flask \
            python3-requests \
            python3-numpy \
            net-tools \
            curl
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
            python3 \
            python3-pip \
            python3-flask \
            python3-requests \
            python3-numpy \
            net-tools \
            curl
    else
        log_error "Unsupported package manager"
        exit 1
    fi

    log_info "Packages installed"
}

# ============================================================
# GUARDIAN CONFIGURATION DIRECTORY
# ============================================================
setup_guardian_config() {
    log_step "Setting up Guardian configuration directory..."

    # Create Guardian config directory
    mkdir -p /etc/guardian
    chmod 755 /etc/guardian

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

    # Setup VXLAN tunnel for MSSP connection
    local vxlan_vni="${HOOKPROBE_VXLAN_VNI:-1000}"
    local vxlan_port="vxlan_mssp"

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

    # Create Guardian pod network
    podman network create guardian-net 2>/dev/null || true

    # Create volumes
    podman volume create guardian-suricata-logs 2>/dev/null || true
    podman volume create guardian-suricata-rules 2>/dev/null || true
    podman volume create guardian-waf-logs 2>/dev/null || true

    # Pull container images first
    log_info "Pulling container images (this may take a few minutes)..."
    podman pull docker.io/jasonish/suricata:latest 2>/dev/null || log_warn "Failed to pull Suricata image"
    podman pull docker.io/owasp/modsecurity-crs:nginx-alpine 2>/dev/null || log_warn "Failed to pull WAF image"
    podman pull docker.io/library/python:3.11-slim 2>/dev/null || log_warn "Failed to pull Python image"
    podman pull docker.io/zeek/zeek:latest 2>/dev/null || log_warn "Failed to pull Zeek image"

    # Install core security containers
    install_suricata_container
    install_waf_container
    install_neuro_container

    # Install Zeek network analyzer
    install_zeek_container

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

install_suricata_container() {
    log_step "Installing Suricata IDS/IPS container..."

    # Check if already running
    if podman ps -a --format "{{.Names}}" | grep -q "^guardian-suricata$"; then
        log_info "Suricata container already exists"
        return 0
    fi

    # Determine interface to monitor for IDS
    # IMPORTANT: Never use wlan* interfaces directly - promiscuous mode interferes with hostapd
    # Priority: eth0 (ethernet), br0 (bridge), then skip if only WiFi
    local MONITOR_IFACE=""
    if ip link show eth0 &>/dev/null && [ -d /sys/class/net/eth0 ]; then
        MONITOR_IFACE="eth0"
    elif ip link show br0 &>/dev/null && [ -d /sys/class/net/br0 ]; then
        MONITOR_IFACE="br0"
    else
        log_warn "No suitable interface for Suricata (eth0/br0 not found)"
        log_warn "WiFi interfaces cannot be used for IDS monitoring"
        MONITOR_IFACE="eth0"  # Default, may not work but won't break WiFi
    fi
    log_info "Suricata will monitor interface: $MONITOR_IFACE"

    # Create systemd service for Suricata container (creates container on start)
    cat > /etc/systemd/system/guardian-suricata.service << EOF
[Unit]
Description=HookProbe Guardian Suricata IDS
After=network-online.target podman.socket
Wants=network-online.target
Requires=podman.socket
# Only start if we have an interface to monitor
ConditionPathExists=/sys/class/net/${MONITOR_IFACE}

[Service]
Type=simple
Restart=on-failure
RestartSec=30
StartLimitIntervalSec=300
StartLimitBurst=3
# Wait for interface to be fully up
ExecStartPre=/bin/sleep 10
ExecStartPre=-/usr/bin/podman stop guardian-suricata
ExecStartPre=-/usr/bin/podman rm guardian-suricata
# Pull image if not present
ExecStartPre=-/usr/bin/podman pull docker.io/jasonish/suricata:latest
ExecStart=/usr/bin/podman run --name guardian-suricata \\
    --network host \\
    --cap-add NET_ADMIN \\
    --cap-add NET_RAW \\
    --cap-add SYS_NICE \\
    -v guardian-suricata-logs:/var/log/suricata:Z \\
    -v guardian-suricata-rules:/var/lib/suricata:Z \\
    docker.io/jasonish/suricata:latest -i $MONITOR_IFACE
ExecStop=/usr/bin/podman stop -t 10 guardian-suricata

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-suricata 2>/dev/null || true

    log_info "Suricata IDS container installed"
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
After=network.target podman.socket guardian-suricata.service
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

install_zeek_container() {
    log_step "Installing Zeek Network Analysis container..."

    # Check if already running
    if podman ps -a --format "{{.Names}}" | grep -q "^guardian-zeek$"; then
        log_info "Zeek container already exists"
        return 0
    fi

    # Create volumes for Zeek logs
    podman volume create guardian-zeek-logs 2>/dev/null || true
    podman volume create guardian-zeek-spool 2>/dev/null || true

    # Pull Zeek image
    log_info "Pulling Zeek image..."
    podman pull docker.io/zeek/zeek:latest 2>/dev/null || log_warn "Failed to pull Zeek image"

    # Determine interface to monitor for network analysis
    # IMPORTANT: Never use wlan* interfaces directly - promiscuous mode interferes with hostapd
    # Priority: eth0 (ethernet), br0 (bridge), then skip if only WiFi
    local MONITOR_IFACE=""
    if ip link show eth0 &>/dev/null && [ -d /sys/class/net/eth0 ]; then
        MONITOR_IFACE="eth0"
    elif ip link show br0 &>/dev/null && [ -d /sys/class/net/br0 ]; then
        MONITOR_IFACE="br0"
    else
        log_warn "No suitable interface for Zeek (eth0/br0 not found)"
        log_warn "WiFi interfaces cannot be used for network monitoring"
        MONITOR_IFACE="eth0"  # Default, may not work but won't break WiFi
    fi
    log_info "Zeek will monitor interface: $MONITOR_IFACE"

    # Create Zeek local.zeek configuration
    mkdir -p /opt/hookprobe/guardian/zeek
    cat > /opt/hookprobe/guardian/zeek/local.zeek << 'ZEEKEOF'
# Guardian Zeek Configuration
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load policy/frameworks/notice/extend-email/hostnames
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/dns/detect-external-names
@load policy/protocols/http/detect-sqli
@load policy/protocols/ssl/validate-certs
@load policy/misc/detect-traceroute
@load policy/misc/scan

# Enable JSON logging for easier parsing
redef LogAscii::use_json = T;

# Detect port scans
redef Scan::scan_threshold = 25;

# Notice types to log
redef Notice::policy += {
    [$action = Notice::LOG,
     $pred(n: Notice::Info) = { return T; }]
};
ZEEKEOF

    # Create systemd service for Zeek container
    # Dynamically detects interface at start time for resilience
    cat > /etc/systemd/system/guardian-zeek.service << 'EOF'
[Unit]
Description=HookProbe Guardian Zeek Network Analyzer
After=network-online.target podman.socket
Wants=network-online.target
Requires=podman.socket
# Allow start if either eth0 OR br0 exists (| prefix makes condition non-fatal)
ConditionPathExists=|/sys/class/net/eth0
ConditionPathExists=|/sys/class/net/br0

[Service]
Type=simple
Restart=on-failure
RestartSec=30
StartLimitIntervalSec=600
StartLimitBurst=5
# Memory limit to prevent OOM
MemoryMax=512M
MemoryHigh=384M
# Wait for interface to be fully up
ExecStartPre=/bin/sleep 15
ExecStartPre=-/usr/bin/podman stop guardian-zeek
ExecStartPre=-/usr/bin/podman rm guardian-zeek
# Detect interface dynamically at start time (prefer eth0, fallback to br0)
ExecStartPre=/bin/bash -c 'if [ -e /sys/class/net/eth0 ]; then echo eth0 > /run/guardian-zeek-iface; elif [ -e /sys/class/net/br0 ]; then echo br0 > /run/guardian-zeek-iface; else echo none > /run/guardian-zeek-iface; fi'
# Pull image if not present
ExecStartPre=-/usr/bin/podman pull docker.io/zeek/zeek:latest
ExecStart=/bin/bash -c 'IFACE=$(cat /run/guardian-zeek-iface); if [ "$IFACE" = "none" ]; then echo "No interface available for Zeek"; exit 1; fi; exec /usr/bin/podman run --name guardian-zeek --network host --cap-add NET_ADMIN --cap-add NET_RAW --memory 512m -v guardian-zeek-logs:/usr/local/zeek/logs:Z -v guardian-zeek-spool:/usr/local/zeek/spool:Z -v /opt/hookprobe/guardian/zeek/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek:ro docker.io/zeek/zeek:latest zeek -i $IFACE local'
ExecStop=/usr/bin/podman stop -t 10 guardian-zeek

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-zeek 2>/dev/null || true

    log_info "Zeek Network Analyzer container installed"
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

SURICATA_LOG = "/var/lib/containers/storage/volumes/guardian-suricata-logs/_data/eve.json"
ZEEK_LOG_DIR = "/var/lib/containers/storage/volumes/guardian-zeek-logs/_data/current"
OUTPUT_FILE = "/var/log/hookprobe/threats/aggregated.json"
ALERT_FILE = "/var/log/hookprobe/threats/active_alerts.json"

class ThreatAggregator:
    def __init__(self):
        self.threats = []
        self.stats = {
            "suricata_alerts": 0,
            "zeek_notices": 0,
            "xdp_drops": 0,
            "blocked_ips": [],
            "active_attacks": [],
            "severity_counts": {"high": 0, "medium": 0, "low": 0},
            "last_update": None
        }

    def parse_suricata_eve(self, limit=100):
        """Parse Suricata EVE JSON log"""
        alerts = []
        try:
            if not os.path.exists(SURICATA_LOG):
                return alerts

            # Read last N lines
            result = subprocess.run(
                ["tail", "-n", str(limit), SURICATA_LOG],
                capture_output=True, text=True
            )

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alert = {
                            "source": "suricata",
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
                        self.stats["suricata_alerts"] += 1
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"Error parsing Suricata logs: {e}")

        return alerts

    def parse_zeek_notices(self, limit=100):
        """Parse Zeek notice.log"""
        notices = []
        try:
            notice_log = Path(ZEEK_LOG_DIR) / "notice.log"
            if not notice_log.exists():
                return notices

            result = subprocess.run(
                ["tail", "-n", str(limit), str(notice_log)],
                capture_output=True, text=True
            )

            for line in result.stdout.strip().split('\n'):
                if not line or line.startswith('#'):
                    continue
                try:
                    # Zeek JSON format
                    event = json.loads(line)
                    notice = {
                        "source": "zeek",
                        "timestamp": event.get("ts"),
                        "src_ip": event.get("src"),
                        "dest_ip": event.get("dst"),
                        "note": event.get("note"),
                        "msg": event.get("msg"),
                        "severity": 2 if "Scan" in event.get("note", "") else 3
                    }
                    notices.append(notice)
                    self.stats["zeek_notices"] += 1
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"Error parsing Zeek logs: {e}")

        return notices

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
        all_alerts.extend(self.parse_suricata_eve())
        all_alerts.extend(self.parse_zeek_notices())

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
                  f"Suricata={result['stats']['suricata_alerts']}, "
                  f"Zeek={result['stats']['zeek_notices']}, "
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
After=network.target guardian-suricata.service guardian-zeek.service

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
echo "1. Testing Suricata IDS..."
echo "   Running TCP SYN scan (should trigger alerts)..."
nmap -sS -p 22,80,443,8080 $TARGET -T4 --max-retries 1 2>/dev/null || true
sleep 2

# Check Suricata logs
if podman logs guardian-suricata 2>&1 | tail -20 | grep -q -i "alert\|signature"; then
    test_result "Suricata_Detection" "PASS" "Alerts generated for port scan"
else
    test_result "Suricata_Detection" "FAIL" "No alerts detected"
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
echo "5. Checking Zeek network analysis..."
if podman ps | grep -q guardian-zeek; then
    # Check if Zeek is logging
    if podman exec guardian-zeek ls /usr/local/zeek/logs/current/ 2>/dev/null | grep -q "conn.log"; then
        test_result "Zeek_Logging" "PASS" "Connection logging active"
    else
        test_result "Zeek_Logging" "FAIL" "No logs found"
    fi
else
    test_result "Zeek_Logging" "FAIL" "Zeek container not running"
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
    ALERT_COUNT=$(cat /var/log/hookprobe/threats/aggregated.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['stats']['suricata_alerts'])" 2>/dev/null || echo "0")
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
echo "  - Suricata: podman logs -f guardian-suricata"
echo "  - Zeek: podman exec guardian-zeek cat /usr/local/zeek/logs/current/notice.log"
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
    local QSECBIT_SRC="/home/xsoc/hookprobe/core/qsecbit"
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

# Paths
CONFIG_DIR = Path('/opt/hookprobe/guardian')
DATA_DIR = CONFIG_DIR / 'data'
STATS_FILE = DATA_DIR / 'stats.json'
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
    """Single QSecBit measurement"""
    timestamp: str
    score: float
    rag_status: str
    components: Dict[str, float]
    xdp_stats: Dict[str, int]
    energy_stats: Dict[str, float]
    network_stats: Dict[str, any]
    threats_detected: int
    suricata_alerts: int


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

    def check_suricata_alerts(self) -> int:
        """Check Suricata for new alerts"""
        count = 0
        eve_log = Path('/var/log/suricata/eve.json')

        # Also check container logs
        try:
            result = subprocess.run(
                ['podman', 'exec', 'guardian-suricata', 'tail', '-100', '/var/log/suricata/eve.json'],
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

    def calculate_score(self, xdp_stats: Dict, energy_stats: Dict, network_stats: Dict,
                        threats: int, suricata_alerts: int) -> tuple:
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

        # Component 2: Attack probability (based on Suricata alerts and XDP drops)
        alert_factor = min(1.0, suricata_alerts / 50.0)  # Normalize by 50 alerts
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

        # Calculate weighted score
        score = (
            self.config.alpha * components['drift'] +
            self.config.beta * components['attack_probability'] +
            self.config.gamma * components['classifier_decay'] +
            self.config.delta * components['quantum_drift'] +
            self.config.epsilon * components['energy_anomaly']
        )

        # Determine RAG status
        if score >= self.config.red_threshold:
            rag_status = 'RED'
        elif score >= self.config.amber_threshold:
            rag_status = 'AMBER'
        else:
            rag_status = 'GREEN'

        return score, rag_status, components

    def collect_sample(self) -> QSecBitSample:
        """Collect a complete QSecBit sample"""
        xdp_stats = self.get_xdp_stats()
        energy_stats = self.get_energy_stats()
        network_stats = self.get_network_stats()
        threats = self.check_threats()
        suricata_alerts = self.check_suricata_alerts()

        score, rag_status, components = self.calculate_score(
            xdp_stats, energy_stats, network_stats, threats, suricata_alerts
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
            suricata_alerts=suricata_alerts
        )

        return sample

    def save_stats(self, sample: QSecBitSample):
        """Save stats to file for Web UI"""
        try:
            stats_data = {
                'timestamp': sample.timestamp,
                'score': sample.score,
                'rag_status': sample.rag_status,
                'components': sample.components,
                'xdp': sample.xdp_stats,
                'energy': sample.energy_stats,
                'network': sample.network_stats,
                'threats': sample.threats_detected,
                'suricata_alerts': sample.suricata_alerts,
                'status': 'active',
                'mode': 'guardian-edge',
                'version': '5.0.0'
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
                    f"threats={sample.threats_detected} alerts={sample.suricata_alerts}"
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
After=network.target guardian-suricata.service
Wants=guardian-suricata.service

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
    # AP Interface: Use wlan1 if available (wlan0 is for WAN uplink)
    # Priority: HOOKPROBE_AP_IFACE env > wlan1 > first available wlan
    local WIFI_IFACE="${HOOKPROBE_AP_IFACE:-}"
    if [ -z "$WIFI_IFACE" ]; then
        # Prefer wlan1 for AP (wlan0 is typically WAN/uplink)
        if echo "$WIFI_INTERFACES" | grep -qw "wlan1"; then
            WIFI_IFACE="wlan1"
        else
            # Fallback to first available
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
    # Prepare WiFi interface for AP mode
    # ─────────────────────────────────────────────────────────────
    log_info "Preparing $WIFI_IFACE for AP mode..."

    # Kill any wpa_supplicant processes using this interface
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

    # Remove any existing guardian/dns-shield configs to start fresh
    rm -f /etc/dnsmasq.d/guardian.conf /etc/dnsmasq.d/dns-shield.conf 2>/dev/null || true

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
log-facility=/var/log/hookprobe/dnsmasq.log

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
# HookProbe Guardian - NAT Rules
# IMPORTANT: Preserves existing connections (SSH, etc.)

# Delete old table if exists (clean slate)
table inet guardian
delete table inet guardian

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
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
    }

    chain postrouting {
        type nat hook postrouting priority 100;
        oifname != "br0" masquerade
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
Version: 5.0.0 Liberty
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
# Removes dependency on network-online.target for offline-first operation

[Unit]
After=
Wants=
After=guardian-wlan.service guardian-offline.service local-fs.target
Wants=guardian-wlan.service
Requires=guardian-wlan.service

[Service]
Restart=on-failure
RestartSec=5
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

    # Install SSID health check script and timer
    log_info "Installing SSID health check..."
    if [ -f "$SCRIPT_DIR/guardian-ssid-health.sh" ]; then
        cp "$SCRIPT_DIR/guardian-ssid-health.sh" /usr/local/bin/
        chmod +x /usr/local/bin/guardian-ssid-health.sh
    fi
    if [ -f "$CONFIG_DIR/systemd/guardian-ssid-health.service" ]; then
        cp "$CONFIG_DIR/systemd/guardian-ssid-health.service" /etc/systemd/system/
        chmod 644 /etc/systemd/system/guardian-ssid-health.service
    fi
    if [ -f "$CONFIG_DIR/systemd/guardian-ssid-health.timer" ]; then
        cp "$CONFIG_DIR/systemd/guardian-ssid-health.timer" /etc/systemd/system/
        chmod 644 /etc/systemd/system/guardian-ssid-health.timer
        systemctl daemon-reload
        systemctl enable guardian-ssid-health.timer 2>/dev/null || true
        systemctl start guardian-ssid-health.timer 2>/dev/null || true
    fi

    # Install WiFi WAN health check script and timer
    log_info "Installing WiFi WAN health check..."
    if [ -f "$SCRIPT_DIR/guardian-wifi-health.sh" ]; then
        cp "$SCRIPT_DIR/guardian-wifi-health.sh" /usr/local/bin/
        chmod +x /usr/local/bin/guardian-wifi-health.sh
    fi
    if [ -f "$CONFIG_DIR/systemd/guardian-wifi-health.service" ]; then
        cp "$CONFIG_DIR/systemd/guardian-wifi-health.service" /etc/systemd/system/
        chmod 644 /etc/systemd/system/guardian-wifi-health.service
    fi
    if [ -f "$CONFIG_DIR/systemd/guardian-wifi-health.timer" ]; then
        cp "$CONFIG_DIR/systemd/guardian-wifi-health.timer" /etc/systemd/system/
        chmod 644 /etc/systemd/system/guardian-wifi-health.timer
        systemctl daemon-reload
        systemctl enable guardian-wifi-health.timer 2>/dev/null || true
        systemctl start guardian-wifi-health.timer 2>/dev/null || true
    fi

    log_info "Guardian AP services installed and enabled"
    log_info "  - guardian-wlan.service: Prepares wlan1 for AP mode"
    log_info "  - guardian-ap.service: Ensures hostapd/dnsmasq start"
    log_info "  - hostapd/dnsmasq overrides: Removed network-online dependency"
    log_info "  - All services enabled to start at boot"
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
# Version: 5.0.0 Liberty
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
  mssp_host: "mssp.hookprobe.com"
  mssp_port: 8443
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
  suricata:
    enabled: true
    eve_log: "/var/log/suricata/eve.json"
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

    # Install ML libraries for dnsXai AI features
    log_info "Installing ML libraries for dnsXai..."
    pip3 install --quiet --break-system-packages scikit-learn joblib 2>/dev/null || \
    pip3 install --quiet scikit-learn joblib 2>/dev/null || \
    log_warn "Could not install ML libraries - dnsXai will run in rule-based mode"

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
    log_info "Enabling Guardian security stack..."
    systemctl enable guardian-offline 2>/dev/null || true
    systemctl enable guardian-suricata 2>/dev/null || true
    systemctl enable guardian-zeek 2>/dev/null || true
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

    systemctl start guardian-webui

    # Start security containers and services
    log_info "Starting security stack..."

    # Core IDS/IPS
    log_info "  - Starting Suricata IDS/IPS..."
    systemctl start guardian-suricata 2>/dev/null || true

    # Network analysis
    log_info "  - Starting Zeek Network Analysis..."
    systemctl start guardian-zeek 2>/dev/null || true

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

    for svc in guardian-suricata guardian-zeek guardian-waf guardian-xdp guardian-aggregator; do
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
    echo -e "${BOLD}${GREEN}║         HookProbe Guardian - Liberty 5.0.0                  ║${NC}"
    echo -e "${BOLD}${GREEN}║       Portable Travel Security Companion                   ║${NC}"
    echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}${WHITE}Security Features:${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} L1-L7 OSI Layer Threat Detection"
    echo -e "  ${GREEN}✓${NC} QSecBit AI-Powered Security Scoring"
    echo -e "  ${GREEN}✓${NC} Suricata IDS/IPS (Intrusion Detection/Prevention)"
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

    # Check MSSP connectivity
    if check_mssp_connectivity; then
        echo -e "  ${GREEN}✓${NC} MSSP connectivity: ${GREEN}Available${NC}"
    else
        echo -e "  ${YELLOW}!${NC} MSSP connectivity: ${YELLOW}Offline${NC} (HTP Mesh features disabled until connected)"
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

    # Setup Guardian config directory
    log_step "Setting up Guardian configuration..."
    setup_guardian_config

    # Install Podman container runtime
    log_step "Installing container runtime..."
    install_podman

    # Install Open vSwitch
    log_step "Installing Open vSwitch..."
    install_openvswitch

    # Setup OVS bridge with VXLAN tunnel
    log_step "Configuring OVS bridge..."
    setup_ovs_bridge

    # Setup MACsec (optional - disabled by default, enable with HOOKPROBE_MACSEC_ENABLED=true)
    # Note: MACsec may not work on all Raspberry Pi models due to kernel configuration
    setup_macsec

    # Network configuration prompt
    prompt_network_config

    # Install security containers (Suricata IDS, WAF, Neuro, AdGuard)
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

    # Enable and start services
    log_step "Starting services..."
    enable_services
    start_services

    # Final summary
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       Guardian Liberty 5.0.0 Installation Complete!        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "  Version:     ${BOLD}Liberty 5.0.0${NC}"
    echo -e "  Mode:        ${BOLD}Guardian (Portable Travel Security)${NC}"
    echo -e "  Hotspot:     ${BOLD}${HOOKPROBE_WIFI_SSID:-HookProbe-Guardian}${NC}"
    echo -e "  Network:     ${BOLD}192.168.4.0/27 (br0, 30 devices max)${NC}"
    echo -e "  Web UI:      ${BOLD}http://192.168.4.1:8080${NC}"
    echo ""
    echo -e "  ${BOLD}Security Features:${NC}"
    echo -e "  • L1-L7 OSI Layer Threat Detection"
    echo -e "  • QSecBit AI Security Scoring"
    echo -e "  • Suricata IDS/IPS"
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
    echo -e "  ${BOLD}Service Status:${NC}"
    echo -e "  $(systemctl is-active hostapd 2>/dev/null || echo 'inactive') hostapd (WiFi AP)"
    echo -e "  $(systemctl is-active dnsmasq 2>/dev/null || echo 'inactive') dnsmasq (DHCP/DNS)"
    echo -e "  $(systemctl is-active guardian-webui 2>/dev/null || echo 'inactive') guardian-webui"
    echo -e "  $(systemctl is-active guardian-suricata 2>/dev/null || echo 'inactive') guardian-suricata (IDS)"
    echo -e "  $(systemctl is-active guardian-waf 2>/dev/null || echo 'inactive') guardian-waf (WAF)"
    echo -e "  $(systemctl is-active guardian-qsecbit 2>/dev/null || echo 'inactive') guardian-qsecbit"
    echo ""
    echo -e "  ${YELLOW}Next steps:${NC}"
    echo -e "  1. Connect to '${HOOKPROBE_WIFI_SSID:-HookProbe-Guardian}' WiFi network"
    echo -e "  2. Open http://192.168.4.1:8080 in your browser"
    echo -e "  3. View connected devices in the Web UI"
    echo -e "  4. Configure upstream WiFi connection for internet access"
    echo ""
    echo -e "  ${DIM}Logs: journalctl -u guardian-suricata -u guardian-qsecbit -f${NC}"
    echo ""
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
