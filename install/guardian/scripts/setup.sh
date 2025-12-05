#!/bin/bash
#
# HookProbe Guardian Setup Script
# Version: 5.0.0
# License: MIT
#
# Installation modes:
#   - Basic: Simple bridge (WiFi + LAN), DHCP client, no SDN
#   - SDN:   Full VLAN segmentation with FreeRADIUS (requires MSSP)
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

# ============================================================
# RADIUS CONNECTIVITY CHECK
# ============================================================
check_radius_connectivity() {
    local radius_server="${1:-127.0.0.1}"
    local radius_port="${2:-1812}"
    local timeout=5

    log_step "Checking RADIUS connectivity to $radius_server:$radius_port..."

    # Check if we can reach the RADIUS server
    if command -v nc &>/dev/null; then
        if nc -z -w $timeout "$radius_server" "$radius_port" 2>/dev/null; then
            log_info "RADIUS server is reachable"
            return 0
        fi
    elif command -v timeout &>/dev/null; then
        if timeout $timeout bash -c "echo >/dev/udp/$radius_server/$radius_port" 2>/dev/null; then
            log_info "RADIUS server is reachable"
            return 0
        fi
    fi

    log_warn "RADIUS server not reachable"
    return 1
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
        apt-get install -y -qq \
            hostapd \
            dnsmasq \
            bridge-utils \
            iptables \
            nftables \
            iw \
            wireless-tools \
            wpasupplicant \
            python3 \
            python3-flask \
            python3-requests \
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
            python3-flask \
            python3-requests \
            net-tools \
            curl
    else
        log_error "Unsupported package manager"
        exit 1
    fi

    log_info "Packages installed"
}

install_sdn_packages() {
    log_step "Installing SDN packages (VLAN, RADIUS)..."

    if [ "$PKG_MGR" = "apt" ]; then
        apt-get install -y -qq vlan freeradius
    else
        dnf install -y -q vlan freeradius
    fi

    # Enable 802.1q VLAN module
    modprobe 8021q 2>/dev/null || true
    if ! grep -q "8021q" /etc/modules 2>/dev/null; then
        echo "8021q" >> /etc/modules
    fi

    log_info "SDN packages installed"
}

# ============================================================
# BASIC MODE CONFIGURATION (Simple Bridge)
# ============================================================
configure_basic_mode() {
    log_step "Configuring Guardian in Basic Mode..."

    local HOTSPOT_SSID="${HOOKPROBE_WIFI_SSID:-HookProbe-Guardian}"
    local HOTSPOT_PASS="${HOOKPROBE_WIFI_PASS:-hookprobe123}"
    local BRIDGE_IP="192.168.4.1"
    local DHCP_START="192.168.4.100"
    local DHCP_END="192.168.4.200"

    # Determine interfaces
    local WIFI_IFACE=$(echo $WIFI_INTERFACES | awk '{print $1}')
    local ETH_IFACE=$(echo $ETH_INTERFACES | awk '{print $1}')

    if [ -z "$WIFI_IFACE" ]; then
        log_error "No WiFi interface found"
        exit 1
    fi

    # Stop services during configuration
    systemctl stop hostapd 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true

    # Create bridge interface
    log_info "Creating bridge br0..."
    ip link add br0 type bridge 2>/dev/null || true
    ip link set br0 up
    ip addr add $BRIDGE_IP/24 dev br0 2>/dev/null || true

    # Add ethernet to bridge if available
    if [ -n "$ETH_IFACE" ]; then
        ip link set "$ETH_IFACE" master br0 2>/dev/null || true
        log_info "Added $ETH_IFACE to bridge"
    fi

    # Configure hostapd (simple mode)
    log_info "Configuring hostapd..."
    cat > /etc/hostapd/hostapd.conf << EOF
# HookProbe Guardian - Basic Mode
# Simple WiFi hotspot with bridge

interface=$WIFI_IFACE
driver=nl80211
bridge=br0

ssid=$HOTSPOT_SSID
hw_mode=g
channel=6
country_code=US

# 802.11n support
ieee80211n=1
wmm_enabled=1

# Security
wpa=2
wpa_passphrase=$HOTSPOT_PASS
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP

# Logging
logger_syslog=-1
logger_syslog_level=2

# Performance
max_num_sta=32
EOF

    # Configure hostapd daemon
    echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' > /etc/default/hostapd

    # Configure dnsmasq (DHCP + DNS)
    log_info "Configuring dnsmasq..."
    cat > /etc/dnsmasq.d/guardian.conf << EOF
# HookProbe Guardian - DHCP/DNS Configuration

# Interface
interface=br0
bind-interfaces

# DHCP range
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,24h

# Gateway
dhcp-option=3,$BRIDGE_IP

# DNS servers
server=1.1.1.1
server=8.8.8.8

# Domain
domain=guardian.local
local=/guardian.local/

# Logging
log-queries
log-dhcp
EOF

    # Enable IP forwarding
    log_info "Enabling IP forwarding..."
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-guardian.conf
    sysctl -p /etc/sysctl.d/99-guardian.conf

    # Configure NAT (masquerade outgoing traffic)
    log_info "Configuring NAT..."
    cat > /etc/nftables.d/guardian.nft << 'EOF'
#!/usr/sbin/nft -f
# HookProbe Guardian - Basic NAT

table inet guardian {
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

    # Apply nftables rules
    mkdir -p /etc/nftables.d
    nft -f /etc/nftables.d/guardian.nft 2>/dev/null || true

    log_info "Basic mode configuration complete"
}

# ============================================================
# SDN MODE CONFIGURATION (VLAN Segmentation)
# ============================================================
configure_sdn_mode() {
    log_step "Configuring Guardian in SDN Mode..."

    local RADIUS_SERVER="${HOOKPROBE_RADIUS_SERVER:-127.0.0.1}"
    local RADIUS_SECRET="${HOOKPROBE_RADIUS_SECRET:-hookprobe_radius}"

    # Install SDN packages
    install_sdn_packages

    # Copy SDN configuration files
    log_info "Installing SDN configuration..."

    mkdir -p /etc/hostapd
    cp "$CONFIG_DIR/hostapd.conf" /etc/hostapd/hostapd.conf
    cp "$CONFIG_DIR/hostapd.vlan" /etc/hostapd/hostapd.vlan
    touch /etc/hostapd/hostapd.accept
    touch /etc/hostapd/hostapd.deny

    # Update RADIUS server in hostapd config
    sed -i "s/auth_server_addr=.*/auth_server_addr=$RADIUS_SERVER/" /etc/hostapd/hostapd.conf
    sed -i "s/auth_server_shared_secret=.*/auth_server_shared_secret=$RADIUS_SECRET/" /etc/hostapd/hostapd.conf

    # Configure dnsmasq for VLANs
    cp "$CONFIG_DIR/dnsmasq.conf" /etc/dnsmasq.d/guardian.conf

    # Create VLAN interfaces
    log_info "Creating VLAN interfaces..."

    local ETH_IFACE=$(echo $ETH_INTERFACES | awk '{print $1}')

    for vlan in 10 20 30 40 50 60 70 80 999; do
        # Create VLAN interface
        ip link add link "$ETH_IFACE" name "${ETH_IFACE}.${vlan}" type vlan id $vlan 2>/dev/null || true
        ip link set "${ETH_IFACE}.${vlan}" up

        # Create bridge for VLAN
        ip link add "br${vlan}" type bridge 2>/dev/null || true
        ip link set "br${vlan}" up
        ip link set "${ETH_IFACE}.${vlan}" master "br${vlan}" 2>/dev/null || true

        # Assign IP to bridge
        local octet=$((vlan == 999 ? 99 : vlan))
        ip addr add "192.168.${octet}.1/24" dev "br${vlan}" 2>/dev/null || true
    done

    # Copy nftables rules for VLAN isolation
    mkdir -p /etc/nftables.d
    cat > /etc/nftables.d/guardian-vlans.nft << 'EOF'
#!/usr/sbin/nft -f
# HookProbe Guardian - VLAN Isolation

table inet guardian {
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Allow established connections
        ct state established,related accept

        # Allow each VLAN to access internet
        iifname "br10" oifname != "br*" accept
        iifname "br20" oifname != "br*" accept
        iifname "br30" oifname != "br*" accept
        iifname "br40" oifname != "br*" accept
        iifname "br50" oifname != "br*" accept
        iifname "br60" oifname != "br*" accept
        iifname "br70" oifname != "br*" accept
        iifname "br80" oifname != "br*" accept

        # Quarantine VLAN - NO internet
        iifname "br999" drop

        # Management bridge full access
        iifname "br0" accept
        oifname "br0" accept
    }

    chain postrouting {
        type nat hook postrouting priority 100;
        oifname != "br*" masquerade
    }
}
EOF

    nft -f /etc/nftables.d/guardian-vlans.nft 2>/dev/null || true

    log_info "SDN mode configuration complete"
}

# ============================================================
# WEB UI INSTALLATION
# ============================================================
install_web_ui() {
    log_step "Installing Guardian Web UI..."

    mkdir -p /opt/hookprobe/guardian
    cp "$GUARDIAN_ROOT/web/app.py" /opt/hookprobe/guardian/

    # Create systemd service
    cat > /etc/systemd/system/guardian-webui.service << 'EOF'
[Unit]
Description=HookProbe Guardian Web UI
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/hookprobe/guardian
ExecStart=/usr/bin/python3 /opt/hookprobe/guardian/app.py
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

    log_info "Services enabled"
}

start_services() {
    log_step "Starting services..."

    systemctl start nftables 2>/dev/null || true
    systemctl start dnsmasq
    systemctl start hostapd
    systemctl start guardian-webui

    log_info "Services started"
}

# ============================================================
# MODE SELECTION MENU
# ============================================================
show_mode_menu() {
    echo ""
    echo -e "${BOLD}${WHITE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${WHITE}║          HookProbe Guardian - Installation Mode            ║${NC}"
    echo -e "${BOLD}${WHITE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}1)${NC} ${GREEN}Basic Mode${NC} - Simple WiFi hotspot with bridge"
    echo -e "     ${DIM}• Single SSID, all devices on same network${NC}"
    echo -e "     ${DIM}• WiFi + LAN bridged together${NC}"
    echo -e "     ${DIM}• WAN DHCP client for internet${NC}"
    echo -e "     ${DIM}• No MSSP required${NC}"
    echo ""
    echo -e "  ${BOLD}2)${NC} ${CYAN}SDN Mode${NC} - Full VLAN segmentation (requires MSSP)"
    echo -e "     ${DIM}• MAC-based VLAN assignment${NC}"
    echo -e "     ${DIM}• IoT device isolation${NC}"
    echo -e "     ${DIM}• Per-category internet policies${NC}"
    echo -e "     ${DIM}• Requires FreeRADIUS connection${NC}"
    echo ""
}

prompt_mode_selection() {
    local mode=""

    # Check if mode was passed as environment variable
    if [ -n "${GUARDIAN_MODE:-}" ]; then
        mode="$GUARDIAN_MODE"
    else
        show_mode_menu

        while true; do
            read -p "Select installation mode [1]: " choice
            choice=${choice:-1}

            case $choice in
                1)
                    mode="basic"
                    break
                    ;;
                2)
                    mode="sdn"
                    # Check RADIUS connectivity
                    if ! check_mssp_connectivity; then
                        echo ""
                        echo -e "${YELLOW}Warning: MSSP not reachable. SDN features require MSSP connection.${NC}"
                        read -p "Continue with SDN mode anyway? (yes/no) [no]: " continue_sdn
                        if [ "$continue_sdn" != "yes" ]; then
                            echo "Falling back to Basic mode..."
                            mode="basic"
                        fi
                    fi
                    break
                    ;;
                *)
                    echo -e "${RED}Invalid selection. Please choose 1 or 2.${NC}"
                    ;;
            esac
        done
    fi

    echo "$mode"
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
    echo ""
    echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║                  HookProbe Guardian Setup                   ║${NC}"
    echo -e "${BOLD}${GREEN}║              Portable SDN Security Gateway                  ║${NC}"
    echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Prerequisites
    check_root
    detect_platform
    detect_interfaces

    # Check WiFi AP support
    if [ "$WIFI_AP_SUPPORT" != "true" ]; then
        log_error "No WiFi interface with AP mode support found"
        log_error "Guardian requires WiFi AP capability"
        exit 1
    fi

    # Install base packages
    install_packages

    # Select installation mode
    MODE=$(prompt_mode_selection)
    log_info "Selected mode: $MODE"

    # Network configuration
    prompt_network_config

    # Configure based on mode
    case $MODE in
        basic)
            configure_basic_mode
            ;;
        sdn)
            configure_sdn_mode
            ;;
    esac

    # Save mode configuration
    mkdir -p /opt/hookprobe/guardian
    echo "$MODE" > /opt/hookprobe/guardian/mode.conf
    log_info "Mode saved: $MODE"

    # Install Web UI
    install_web_ui

    # Enable and start services
    enable_services
    start_services

    # Final summary
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Guardian Installation Complete!                   ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Mode:        ${BOLD}$MODE${NC}"
    echo -e "  Hotspot:     ${BOLD}$HOOKPROBE_WIFI_SSID${NC}"
    echo -e "  Web UI:      ${BOLD}http://192.168.4.1:8080${NC}"
    echo ""
    echo -e "  ${YELLOW}Next steps:${NC}"
    echo -e "  1. Connect to '$HOOKPROBE_WIFI_SSID' WiFi network"
    echo -e "  2. Open http://192.168.4.1:8080 in your browser"
    echo -e "  3. Configure upstream WiFi connection"
    echo ""

    if [ "$MODE" = "sdn" ]; then
        echo -e "  ${CYAN}SDN Features:${NC}"
        echo -e "  • Register devices in web UI to assign VLANs"
        echo -e "  • Unknown devices go to quarantine (VLAN 999)"
        echo -e "  • VLANs: 10=Lights, 20=Thermo, 30=Cameras, etc."
        echo ""
    fi
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
