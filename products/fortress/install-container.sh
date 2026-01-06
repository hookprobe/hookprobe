#!/bin/bash
#
# HookProbe Fortress - Container-based Installation
#
# Installs Fortress as a self-contained containerized deployment.
# All components run in containers with persistent volumes.
#
# Features:
#   - Self-contained Flask web application in container
#   - PostgreSQL database with persistent volume
#   - Redis cache for sessions
#   - Network filtering (VLAN or nftables-based)
#   - Full uninstall capability
#
# Usage:
#   ./install-container.sh              # Interactive installation
#   ./install-container.sh --quick      # Quick install with defaults
#   ./install-container.sh --uninstall  # Complete removal
#
# Version: 5.5.0
# License: AGPL-3.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# FORTRESS_ROOT is preserved even when sourced scripts overwrite SCRIPT_DIR
FORTRESS_ROOT="$SCRIPT_DIR"
CONTAINERS_DIR="${SCRIPT_DIR}/containers"
DEVICES_DIR="${SCRIPT_DIR}/devices"

# Installation directories
INSTALL_DIR="/opt/hookprobe/fortress"
CONFIG_DIR="/etc/hookprobe"
DATA_DIR="${INSTALL_DIR}/data"
LOG_DIR="/var/log/fortress"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${CYAN}${BOLD}==> $1${NC}"; }

# ============================================================
# BANNER
# ============================================================
show_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  _   _             _    ____            _
 | | | | ___   ___ | | _|  _ \ _ __ ___ | |__   ___
 | |_| |/ _ \ / _ \| |/ / |_) | '__/ _ \| '_ \ / _ \
 |  _  | (_) | (_) |   <|  __/| | | (_) | |_) |  __/
 |_| |_|\___/ \___/|_|\_\_|   |_|  \___/|_.__/ \___|

           F O R T R E S S   v5.5.0
       Container-based Security Gateway
EOF
    echo -e "${NC}"
}

# ============================================================
# PREREQUISITES
# ============================================================
check_prerequisites() {
    log_step "Checking prerequisites"

    # Root check
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi

    # ============================================================
    # EARLY NETWORK RESILIENCE - Dual-WAN failover during installation
    # ============================================================
    # This ensures installation can continue even if primary WAN fails
    # by detecting and activating LTE/backup WAN automatically
    log_info "Checking network connectivity (with dual-WAN failover)..."

    local enr_script="${DEVICES_DIR}/common/early-network-resilience.sh"
    if [ -f "$enr_script" ]; then
        chmod +x "$enr_script"
        # shellcheck source=devices/common/early-network-resilience.sh
        source "$enr_script"

        # Try to ensure network connectivity with automatic LTE failover
        if ensure_network_connectivity; then
            log_info "Network connectivity: OK (active WAN: ${ENR_ACTIVE_WAN:-auto})"

            # Show dual-WAN status if both are available
            if [ -n "$ENR_PRIMARY_IFACE" ] && [ -n "$ENR_BACKUP_IFACE" ]; then
                log_info "Dual-WAN resilience active: $ENR_PRIMARY_IFACE + $ENR_BACKUP_IFACE"
            fi

            # LOCK the network routes - prevent flapping during container builds
            # Routes are now stable and won't be modified for the rest of installation
            if type enr_lock_network &>/dev/null; then
                enr_lock_network
            fi
        else
            # Network resilience failed - try basic fallback
            log_warn "Automatic network setup failed, trying basic connectivity..."

            if ! timeout 5 bash -c 'exec 3<>/dev/tcp/8.8.8.8/53' 2>/dev/null; then
                log_error "No network connectivity detected!"
                log_error "Cannot reach internet on any WAN interface"
                log_error ""
                log_error "Troubleshooting:"
                log_error "  1. Check Ethernet WAN: ip addr show eth0"
                log_error "  2. Check LTE modem: mmcli -L"
                log_error "  3. Check routes: ip route show default"
                log_error "  4. Try manual connect: nmcli con up <connection-name>"
                exit 1
            fi
            log_info "Network connectivity: OK (basic check passed)"
        fi
    else
        # Fallback: Original simple connectivity check
        log_warn "Early network resilience script not found, using basic check"

        if ! timeout 5 bash -c 'exec 3<>/dev/tcp/archive.ubuntu.com/80' 2>/dev/null; then
            if ! timeout 5 bash -c 'exec 3<>/dev/tcp/8.8.8.8/53' 2>/dev/null; then
                log_error "No network connectivity detected!"
                log_error "Cannot reach archive.ubuntu.com or 8.8.8.8"
                log_error "Please ensure the WAN interface has internet access"
                exit 1
            fi
        fi
        log_info "Network connectivity: OK"
    fi

    # Ensure DNS resolution works
    if ! timeout 5 bash -c 'exec 3<>/dev/tcp/archive.ubuntu.com/80' 2>/dev/null; then
        log_warn "DNS resolution not working, adding fallback nameserver..."
        if ! grep -q "nameserver" /etc/resolv.conf 2>/dev/null; then
            echo "nameserver 1.1.1.1" >> /etc/resolv.conf
            echo "nameserver 8.8.8.8" >> /etc/resolv.conf
        fi
    fi

    # ============================================================
    # Helper: Network-resilient apt-get with automatic failover
    # ============================================================
    _apt_install_resilient() {
        local packages="$*"
        local max_retries=3
        local retry=0

        while [ $retry -lt $max_retries ]; do
            # Verify network before apt operation
            if type ensure_network_connectivity &>/dev/null; then
                ensure_network_connectivity || true
            fi

            # Try apt-get update + install
            if apt-get update && apt-get install -y $packages; then
                return 0
            fi

            retry=$((retry + 1))
            if [ $retry -lt $max_retries ]; then
                log_warn "Package installation failed, checking network failover (attempt $((retry + 1))/$max_retries)..."
                sleep 3
            fi
        done

        log_error "Failed to install packages after $max_retries attempts: $packages"
        return 1
    }

    # Open vSwitch (required for secure container networking)
    if ! command -v ovs-vsctl &>/dev/null; then
        log_warn "Open vSwitch not found. Installing..."
        _apt_install_resilient openvswitch-switch || {
            log_error "Failed to install openvswitch-switch"
            exit 1
        }
    fi
    # Ensure OVS is running
    if ! systemctl is-active openvswitch-switch &>/dev/null; then
        systemctl start openvswitch-switch
        systemctl enable openvswitch-switch
    fi
    log_info "Open vSwitch: $(ovs-vsctl --version | head -1)"

    # dnsmasq (required for DHCP)
    if ! command -v dnsmasq &>/dev/null; then
        log_warn "dnsmasq not found. Installing..."
        _apt_install_resilient dnsmasq || {
            log_error "Failed to install dnsmasq"
            exit 1
        }
    fi
    # Ensure dnsmasq is enabled
    systemctl enable dnsmasq 2>/dev/null || true
    log_info "dnsmasq: $(dnsmasq --version | head -1)"

    # Podman check
    if ! command -v podman &>/dev/null; then
        log_warn "Podman not found. Installing..."
        _apt_install_resilient podman podman-compose || {
            log_error "Failed to install podman"
            exit 1
        }
    fi
    log_info "Podman: $(podman --version)"

    # podman-compose check (handle PEP 668 on modern Ubuntu/Debian)
    if ! command -v podman-compose &>/dev/null; then
        log_warn "podman-compose not found. Installing..."

        # Method 1: Try apt (available on Ubuntu 23.04+)
        if apt-get install -y podman-compose 2>/dev/null; then
            log_info "podman-compose installed via apt"
        # Method 2: Try pipx (recommended for PEP 668 systems)
        elif command -v pipx &>/dev/null; then
            pipx install podman-compose || {
                log_error "Failed to install podman-compose via pipx"
                exit 1
            }
            # Add pipx bin to PATH for this session
            export PATH="$HOME/.local/bin:$PATH"
        # Method 3: Install pipx first, then podman-compose
        elif apt-get install -y pipx 2>/dev/null; then
            pipx ensurepath
            export PATH="$HOME/.local/bin:$PATH"
            pipx install podman-compose || {
                log_error "Failed to install podman-compose via pipx"
                exit 1
            }
        # Method 4: pip with --break-system-packages (last resort)
        else
            log_warn "Using pip3 with --break-system-packages..."
            pip3 install --break-system-packages podman-compose || {
                log_error "Failed to install podman-compose"
                log_error "Try: apt install pipx && pipx install podman-compose"
                exit 1
            }
        fi
    fi
    log_info "podman-compose: $(podman-compose --version 2>/dev/null || echo 'available')"

    # WiFi AP dependencies (hostapd, iw, wireless-tools)
    local wifi_packages_needed=""
    if ! command -v hostapd &>/dev/null; then
        wifi_packages_needed="hostapd"
    fi
    if ! command -v iw &>/dev/null; then
        wifi_packages_needed="$wifi_packages_needed iw"
    fi
    if ! command -v iwconfig &>/dev/null; then
        wifi_packages_needed="$wifi_packages_needed wireless-tools"
    fi
    if [ -n "$wifi_packages_needed" ]; then
        log_warn "Installing WiFi packages: $wifi_packages_needed"
        # shellcheck disable=SC2086
        _apt_install_resilient $wifi_packages_needed || {
            log_error "Failed to install WiFi packages: $wifi_packages_needed"
            exit 1
        }
        # Unmask hostapd - Debian/Ubuntu ship it masked by default
        systemctl unmask hostapd 2>/dev/null || true
    fi
    log_info "hostapd: $(hostapd -v 2>&1 | head -1 || echo 'available')"
    log_info "iw: $(iw --version 2>&1 | head -1 || echo 'available')"

    # Python3 (required for host-based fingerprinting services)
    if ! command -v python3 &>/dev/null; then
        log_warn "Python3 not found. Installing..."
        _apt_install_resilient python3 python3-pip python3-venv || {
            log_error "Failed to install Python3"
            exit 1
        }
    fi
    log_info "Python3: $(python3 --version 2>&1)"

    # ebtables (required for WiFi-to-WiFi isolation via OVS)
    if ! command -v ebtables &>/dev/null; then
        log_warn "ebtables not found. Installing..."
        _apt_install_resilient ebtables || {
            log_warn "Failed to install ebtables - WiFi isolation via OVS will be limited"
        }
    fi
    if command -v ebtables &>/dev/null; then
        log_info "ebtables: available (WiFi isolation via OVS enabled)"
    fi

    # Check for nftables (optional, for additional filtering)
    if command -v nft &>/dev/null; then
        log_info "nftables: available"
        NFTABLES_AVAILABLE=true
    else
        log_warn "nftables not found (additional filtering will not be available)"
        NFTABLES_AVAILABLE=false
    fi

    # Check RAM
    local total_ram_mb
    total_ram_mb=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$total_ram_mb" -lt 2048 ]; then
        log_warn "Low RAM detected (${total_ram_mb}MB). Fortress works best with 4GB+"
    else
        log_info "RAM: ${total_ram_mb}MB"
    fi

    # Check disk space
    local free_space_gb
    free_space_gb=$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')
    if [ "$free_space_gb" -lt 10 ]; then
        log_warn "Low disk space (${free_space_gb}GB). Recommend 20GB+"
    else
        log_info "Free disk: ${free_space_gb}GB"
    fi
}

# ============================================================
# CONFIGURATION - Environment Variables & Non-Interactive Mode
# ============================================================
#
# This installer supports configuration via environment variables
# (set by the root install.sh) or interactive prompts.
#
# Environment Variables (from root installer):
#   WIFI_SSID / FORTRESS_WIFI_SSID     - WiFi network name
#   WIFI_PASSWORD / FORTRESS_WIFI_PASSWORD - WiFi password
#   FORTRESS_NETWORK_PREFIX            - Subnet mask (e.g., "23" or "/23")
#   ADMIN_USER                         - Admin username (default: admin)
#   ADMIN_PASS                         - Admin password (auto-generated if not set)
#   WEB_PORT                           - Web UI port (default: 8443)
#   NETWORK_MODE                       - vlan (VLAN-based network segmentation)
#   NON_INTERACTIVE                    - Set to skip all prompts
#
# ============================================================

# Helper to set subnet DHCP ranges based on mask
set_subnet_ranges() {
    local mask="$1"
    case "$mask" in
        29) LAN_SUBNET_MASK="29"; LAN_DHCP_START="10.200.0.2"; LAN_DHCP_END="10.200.0.6" ;;
        28) LAN_SUBNET_MASK="28"; LAN_DHCP_START="10.200.0.2"; LAN_DHCP_END="10.200.0.14" ;;
        27) LAN_SUBNET_MASK="27"; LAN_DHCP_START="10.200.0.10"; LAN_DHCP_END="10.200.0.30" ;;
        26) LAN_SUBNET_MASK="26"; LAN_DHCP_START="10.200.0.10"; LAN_DHCP_END="10.200.0.62" ;;
        25) LAN_SUBNET_MASK="25"; LAN_DHCP_START="10.200.0.10"; LAN_DHCP_END="10.200.0.126" ;;
        24) LAN_SUBNET_MASK="24"; LAN_DHCP_START="10.200.0.100"; LAN_DHCP_END="10.200.0.200" ;;
        *)  LAN_SUBNET_MASK="23"; LAN_DHCP_START="10.200.0.100"; LAN_DHCP_END="10.200.1.200" ;;
    esac
}

collect_configuration() {
    log_step "Configuration"

    # Security services are ALWAYS installed (core backbone of HookProbe mesh)
    INSTALL_ML=true
    BUILD_ML_CONTAINERS=true

    # ============================================================
    # Check for environment variables from root installer first
    # ============================================================

    # WiFi - check both naming conventions
    if [ -n "${WIFI_SSID:-}" ]; then
        : # Already set
    elif [ -n "${FORTRESS_WIFI_SSID:-}" ]; then
        WIFI_SSID="$FORTRESS_WIFI_SSID"
    fi

    if [ -n "${WIFI_PASSWORD:-}" ]; then
        : # Already set
    elif [ -n "${FORTRESS_WIFI_PASSWORD:-}" ]; then
        WIFI_PASSWORD="$FORTRESS_WIFI_PASSWORD"
    fi

    # Network prefix - normalize (remove leading /)
    if [ -n "${FORTRESS_NETWORK_PREFIX:-}" ]; then
        local prefix="${FORTRESS_NETWORK_PREFIX#/}"
        set_subnet_ranges "$prefix"
    fi

    # Other defaults from environment
    NETWORK_MODE="flat"  # Flat bridge mode - OpenFlow NAC (no VLANs)
    ADMIN_USER="${ADMIN_USER:-admin}"
    WEB_PORT="${WEB_PORT:-8443}"

    # ============================================================
    # Non-interactive mode - use defaults/env vars, no prompts
    # ============================================================
    if [ "${NON_INTERACTIVE:-false}" = true ]; then
        log_info "Non-interactive mode - using environment variables and defaults"

        # Set remaining defaults if not already set
        WIFI_SSID="${WIFI_SSID:-HookProbe-Fortress}"
        if [ -z "${WIFI_PASSWORD:-}" ]; then
            WIFI_PASSWORD=$(openssl rand -base64 12 | tr -d '/+=' | head -c 12)
            log_info "Generated random WiFi password"
        fi
        if [ -z "${ADMIN_PASS:-}" ]; then
            ADMIN_PASS=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)
            log_info "Generated random admin password"
        fi
        if [ -z "${LAN_SUBNET_MASK:-}" ]; then
            set_subnet_ranges "23"
        fi

        # Show complete configuration summary
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo -e "  ${CYAN}${BOLD}FORTRESS CONFIGURATION${NC}"
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        echo -e "  ${BOLD}Network:${NC}"
        echo "    Mode:           $NETWORK_MODE"
        echo "    LAN Subnet:     10.200.0.0/$LAN_SUBNET_MASK"
        echo ""
        echo -e "  ${BOLD}Access:${NC}"
        echo "    Admin User:     $ADMIN_USER"
        echo "    WiFi SSID:      $WIFI_SSID"
        echo "    Web Port:       $WEB_PORT"
        echo ""
        echo -e "  ${BOLD}Security Core (always installed):${NC}"
        echo "    ✓ QSecBit AI threat detection"
        echo "    ✓ dnsXai DNS ML protection"
        echo "    ✓ DFS WiFi intelligence"
        echo "    ✓ SDN Autopilot device classification"
        echo ""
        if [ "${INSTALL_AIOCHI:-}" = true ]; then
            echo -e "  ${BOLD}AIOCHI - AI Eyes (Cognitive Layer):${NC}"
            echo "    ✓ ClickHouse analytics database"
            echo "    ✓ VictoriaMetrics time-series"
            echo "    ✓ Grafana dashboards"
            echo "    ✓ n8n AI agent workflows"
            echo "    ✓ Suricata + Zeek network capture"
            echo "    ✓ Ollama local LLM"
            echo ""
        fi
        echo -e "  ${BOLD}Connectivity:${NC}"
        [ "${INSTALL_LTE:-}" = true ] && echo "    ✓ LTE Failover (APN: ${LTE_APN:-auto})"
        [ "${INSTALL_CLOUDFLARE_TUNNEL:-}" = true ] && echo "    ✓ Cloudflare Tunnel: ${CLOUDFLARE_HOSTNAME:-configured}"
        [ "${INSTALL_LTE:-}" != true ] && [ "${INSTALL_CLOUDFLARE_TUNNEL:-}" != true ] && echo "    (no optional connectivity)"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        log_info "Starting fully automated installation..."
        echo ""
        return 0
    fi

    # ============================================================
    # Interactive mode - prompt for any missing configuration
    # ============================================================

    # Network mode selection
    echo ""
    # FLAT BRIDGE ARCHITECTURE
    # Network architecture:
    #   - FTS Bridge: Layer 2 OVS switch with gateway IP (10.200.0.1)
    #   - All devices on same L2 segment (no VLANs)
    #   - Segmentation via OpenFlow NAC rules (device policies)
    NETWORK_MODE="flat"
    log_info "Network mode: Flat Bridge (OpenFlow-based NAC)"

    # LAN subnet (only if not set via FORTRESS_NETWORK_PREFIX)
    if [ -z "${LAN_SUBNET_MASK:-}" ]; then
        echo ""
        echo -e "${BOLD}NETWORK SIZE CONFIGURATION${NC}"
        echo ""
        echo "Select the network size based on expected number of devices:"
        echo ""
        echo "  1) /29 -   6 devices  (10.200.0.0/29)  - very small office"
        echo "  2) /28 -  14 devices  (10.200.0.0/28)  - small office"
        echo "  3) /27 -  30 devices  (10.200.0.0/27)  - small business"
        echo "  4) /26 -  62 devices  (10.200.0.0/26)  - medium business"
        echo "  5) /25 - 126 devices  (10.200.0.0/25)  - larger office"
        echo "  6) /24 - 254 devices  (10.200.0.0/24)  - large network"
        echo "  7) /23 - 510 devices  (10.200.0.0/23)  - default (recommended)"
        echo ""
        read -p "Select subnet [7]: " subnet_choice
        set_subnet_ranges "${subnet_choice:-7}"
    fi
    log_info "LAN subnet: 10.200.0.0/$LAN_SUBNET_MASK (DHCP: $LAN_DHCP_START - $LAN_DHCP_END)"

    # Admin credentials (only if not set)
    if [ -z "${ADMIN_PASS:-}" ]; then
        echo ""
        echo "Admin Portal Access:"
        read -p "Admin username [${ADMIN_USER}]: " admin_input
        ADMIN_USER="${admin_input:-$ADMIN_USER}"

        while true; do
            read -sp "Admin password (min 8 chars): " ADMIN_PASS
            echo ""
            if [ ${#ADMIN_PASS} -lt 8 ]; then
                log_warn "Password must be at least 8 characters"
                continue
            fi
            read -sp "Confirm password: " ADMIN_PASS_CONFIRM
            echo ""
            if [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; then
                log_warn "Passwords do not match"
                continue
            fi
            break
        done
    else
        log_info "Admin user: $ADMIN_USER (password from environment)"
    fi

    # WiFi configuration (only if not set)
    if [ -z "${WIFI_SSID:-}" ]; then
        echo ""
        echo "WiFi Access Point:"
        read -p "WiFi SSID [HookProbe-Fortress]: " WIFI_SSID
        WIFI_SSID="${WIFI_SSID:-HookProbe-Fortress}"
    else
        log_info "WiFi SSID: $WIFI_SSID (from environment)"
    fi

    if [ -z "${WIFI_PASSWORD:-}" ]; then
        while true; do
            read -sp "WiFi password (min 8 chars, or press Enter for random): " WIFI_PASSWORD
            echo ""
            if [ -z "$WIFI_PASSWORD" ]; then
                WIFI_PASSWORD=$(openssl rand -base64 12 | tr -d '/+=' | head -c 12)
                log_info "Generated random WiFi password"
                break
            elif [ ${#WIFI_PASSWORD} -lt 8 ]; then
                log_warn "Password must be at least 8 characters"
                continue
            else
                break
            fi
        done
    else
        log_info "WiFi password: (from environment)"
    fi

    # Web port (only if not already customized)
    if [ "$WEB_PORT" = "8443" ]; then
        echo ""
        read -p "Web UI port [8443]: " port_input
        WEB_PORT="${port_input:-8443}"
    fi

    # ============================================================
    # LTE/WWAN MODEM CONFIGURATION
    # ============================================================
    # Check if modem is detected and prompt for APN configuration
    local modem_detected=false
    if ls /sys/class/net/wwan* &>/dev/null 2>&1 || ls /sys/class/net/wwp* &>/dev/null 2>&1; then
        modem_detected=true
    elif ls /dev/cdc-wdm* &>/dev/null 2>&1 || ls /dev/ttyUSB* &>/dev/null 2>&1; then
        modem_detected=true
    fi

    if [ "$modem_detected" = true ] && [ -z "${LTE_APN:-}" ]; then
        echo ""
        echo -e "${BOLD}LTE MODEM DETECTED${NC}"
        echo ""
        echo "Configure LTE/WWAN modem for WAN failover:"
        echo ""
        echo "Common APNs by carrier:"
        echo "  Vodafone:  internet.vodafone.ro, web.vodafone.de, internet"
        echo "  Orange:    internet, orange.ro, orange"
        echo "  T-Mobile:  internet.t-mobile, fast.t-mobile.com"
        echo "  AT&T:      broadband, phone"
        echo "  Verizon:   vzwinternet"
        echo ""
        read -p "Enter APN name (or press Enter to skip): " LTE_APN
        export LTE_APN

        if [ -n "$LTE_APN" ]; then
            echo ""
            echo "Authentication types:"
            echo "  1. none     - No authentication (most carriers)"
            echo "  2. pap      - PAP authentication"
            echo "  3. chap     - CHAP authentication"
            echo "  4. mschapv2 - MS-CHAPv2 (enterprise/private APNs)"
            echo ""
            read -p "Select authentication type [1-4] (default: 1): " auth_choice
            case "${auth_choice:-1}" in
                2) export LTE_AUTH="pap" ;;
                3) export LTE_AUTH="chap" ;;
                4) export LTE_AUTH="mschapv2" ;;
                *) export LTE_AUTH="none" ;;
            esac

            if [ "$LTE_AUTH" != "none" ]; then
                read -p "Enter username: " LTE_USER
                export LTE_USER
                read -sp "Enter password: " LTE_PASS
                echo ""
                export LTE_PASS
            fi
            export INSTALL_LTE=true
            log_info "LTE configured: APN=$LTE_APN, Auth=$LTE_AUTH"
        fi
    fi

    # ============================================================
    # CLOUDFLARE TUNNEL (Remote Access)
    # ============================================================
    if [ -z "${CLOUDFLARE_TOKEN:-}" ]; then
        echo ""
        echo -e "${BOLD}REMOTE ACCESS CONFIGURATION${NC}"
        echo ""
        echo "Cloudflare Tunnel allows secure remote access to Fortress admin portal"
        echo "without exposing ports to the internet."
        echo ""
        echo "To get a tunnel token:"
        echo "  1. Go to https://one.dash.cloudflare.com/"
        echo "  2. Navigate to Networks → Tunnels"
        echo "  3. Create a tunnel and copy the token"
        echo ""
        read -p "Configure Cloudflare Tunnel? [y/N]: " cf_choice
        if [[ "${cf_choice:-N}" =~ ^[Yy]$ ]]; then
            read -p "Enter tunnel token: " CLOUDFLARE_TOKEN
            export CLOUDFLARE_TOKEN
            if [ -n "$CLOUDFLARE_TOKEN" ]; then
                read -p "Enter hostname (e.g., fortress.mybusiness.com): " CLOUDFLARE_HOSTNAME
                export CLOUDFLARE_HOSTNAME
                export INSTALL_CLOUDFLARE_TUNNEL=true
                log_info "Cloudflare Tunnel configured: $CLOUDFLARE_HOSTNAME"
            fi
        fi
    fi

    # ============================================================
    # AIOCHI - AI Eyes (Cognitive Network Layer)
    # ============================================================
    # Ask about AIOCHI FIRST - it bundles all monitoring/analytics components
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}AIOCHI - AI EYES (COGNITIVE NETWORK LAYER)${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${BOLD}🔭 Do you want EYES on your network?${NC}"
    echo ""
    echo "AIOCHI (AI Eyes) transforms your network into a"
    echo "living story that anyone can understand:"
    echo ""
    echo "  • Visual presence map (who's home)"
    echo "  • Human-readable network feed (not tech jargon)"
    echo "  • One-touch actions (pause kids' internet, game mode)"
    echo "  • Performance health score with insights"
    echo "  • AI-powered security analysis via local Ollama LLM"
    echo ""
    echo -e "${DIM}Includes: ClickHouse, Grafana, VictoriaMetrics, Suricata, Zeek, n8n${NC}"
    echo -e "${DIM}Adds ~2GB RAM usage${NC}"
    echo ""

    if [ -z "${INSTALL_AIOCHI:-}" ]; then
        read -p "Install AIOCHI (AI Eyes)? [Y/n]: " aiochi_choice
        if [[ ! "${aiochi_choice:-Y}" =~ ^[Nn]$ ]]; then
            export INSTALL_AIOCHI=true
            # AIOCHI bundles all monitoring components with cognitive layer
            export INSTALL_MONITORING=true
            export INSTALL_CLICKHOUSE=true
            export INSTALL_N8N=true
            export INSTALL_IDS=true
            log_info "AIOCHI: enabled (includes Monitoring, ClickHouse, n8n, IDS/IPS)"
        fi
    fi

    # No individual optional services - AIOCHI is all-or-nothing
    # Monitoring, ClickHouse, n8n, IDS are ONLY available as part of AIOCHI bundle

    # ============================================================
    # INSTALLATION SUMMARY
    # ============================================================

    # Confirm installation
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}CONFIGURATION SUMMARY${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${BOLD}Network Settings:${NC}"
    echo "  • Network size: /$LAN_SUBNET_MASK"
    echo "  • WiFi SSID: $WIFI_SSID"
    echo ""
    echo -e "${BOLD}Core Features (always installed):${NC}"
    echo "  ✓ Linux Bridge (FTS) for LAN"
    echo "  ✓ QSecBit AI Security Agent"
    echo "  ✓ dnsXai DNS ML Protection"
    echo "  ✓ DFS WiFi Intelligence"
    echo "  ✓ SDN Autopilot + Device Classification"
    echo "  ✓ Web Dashboard (https://localhost:$WEB_PORT)"
    echo "  ✓ Local Auth (max 5 users)"
    echo ""
    if [ "${INSTALL_AIOCHI:-}" = true ]; then
        echo -e "${BOLD}AIOCHI - AI Eyes (Cognitive Layer):${NC}"
        echo "  ✓ ClickHouse analytics database"
        echo "  ✓ VictoriaMetrics time-series"
        echo "  ✓ Grafana monitoring dashboards"
        echo "  ✓ n8n AI Agent workflows + Ollama LLM"
        echo "  ✓ Suricata + Zeek network capture"
        echo "  ✓ Identity Engine + Log Shipper"
        echo ""
    fi
    echo -e "${BOLD}Connectivity:${NC}"
    [ "${INSTALL_LTE:-}" = true ] && echo "  ✓ LTE Failover (APN: $LTE_APN, Auth: ${LTE_AUTH:-none})"
    [ "${INSTALL_CLOUDFLARE_TUNNEL:-}" = true ] && echo "  ✓ Cloudflare Tunnel: $CLOUDFLARE_HOSTNAME"
    [ "${INSTALL_LTE:-}" != true ] && [ "${INSTALL_CLOUDFLARE_TUNNEL:-}" != true ] && echo "  (no optional connectivity configured)"
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    read -p "Proceed with installation? [Y/n]: " confirm
    if [[ "${confirm:-Y}" =~ ^[Nn]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi
}

# ============================================================
# INSTALLATION
# ============================================================

# Create fortress system user and group for container file access
# NOTE: Containers use UID/GID 1000 internally, but podman-compose.yml uses
# the :U volume suffix to auto-adjust ownership on bind mounts. This means
# even if host GID differs from 1000, containers can still access the files.
# For read-only mounts (/etc/hookprobe), files are made world-readable (644).
create_fortress_user() {
    log_step "Creating fortress system user"

    # Create fortress group - prefer GID 1000 to match container, but not required
    # The :U volume suffix in podman-compose.yml handles ownership mapping
    if ! getent group fortress &>/dev/null; then
        # Try to create with GID 1000 (matches container for best compatibility)
        if groupadd --gid 1000 fortress 2>/dev/null; then
            log_info "Created fortress group (gid=1000)"
        else
            # GID 1000 may be taken by another group (common with user's personal group)
            local gid_owner
            gid_owner=$(getent group 1000 2>/dev/null | cut -d: -f1 || echo "")
            if [ -n "$gid_owner" ]; then
                log_info "GID 1000 is used by group '$gid_owner' (normal for user's primary group)"
            fi
            # Create with system GID - the :U volume suffix handles ownership mapping
            groupadd --system fortress
            local new_gid
            new_gid=$(getent group fortress | cut -d: -f3)
            log_info "Created fortress group with system GID (gid=$new_gid)"
            log_info "Note: Podman :U volume suffix handles container UID/GID mapping"
        fi
    else
        local current_gid
        current_gid=$(getent group fortress | cut -d: -f3)
        if [ "$current_gid" = "1000" ]; then
            log_info "Fortress group exists with GID 1000"
        else
            # GID mismatch - no longer an issue due to :U volume suffix
            log_info "Fortress group exists (gid=$current_gid)"
            log_info "Note: Podman :U volume suffix handles container UID/GID mapping"
        fi
    fi

    # Check if fortress user already exists
    if id "fortress" &>/dev/null; then
        log_info "Fortress user exists (uid=$(id -u fortress))"
        usermod -g fortress fortress 2>/dev/null || true
        return 0
    fi

    # Create fortress user as system user (automatic UID in system range)
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --gid fortress --comment "HookProbe Fortress Service Account" fortress

    log_info "Created fortress user (uid=$(id -u fortress))"
}

create_directories() {
    log_step "Creating directories"

    mkdir -p "$INSTALL_DIR"/{web,lib,data,backups,containers/secrets}
    mkdir -p "$CONFIG_DIR/secrets"
    mkdir -p "$LOG_DIR"

    # Persistent user data directory (survives reinstalls)
    # Stores: dnsXai whitelist, user configs, blocked traffic logs
    mkdir -p /var/lib/hookprobe/userdata/dnsxai

    # CRITICAL: Truly persistent storage that is NEVER removed by any uninstall
    # This is the canonical location for user data that must survive even --purge
    mkdir -p /etc/hookprobe/persistent/dnsxai

    chmod 755 "$INSTALL_DIR" "$CONFIG_DIR"
    chmod 700 "$INSTALL_DIR/containers/secrets"
    chmod 750 "$CONFIG_DIR/secrets"  # Group-readable for fortress user
    chmod 755 "$LOG_DIR"

    # /var/lib/hookprobe - writable for SDN autopilot database
    # The autopilot.db stores device classification, policies, WiFi signals
    chmod 777 /var/lib/hookprobe
    chown 1000:1000 /var/lib/hookprobe 2>/dev/null || true

    # Pre-create databases with correct permissions (critical for fresh install!)
    # If we don't do this, the first process to create them might be root
    # and then the web container (uid 1000) can't write to them
    local core_databases=(
        "/var/lib/hookprobe/autopilot.db"
        "/var/lib/hookprobe/dfs_intelligence.db"
        "/var/lib/hookprobe/devices.db"
        # AI Fingerprinting databases (used by host services, read by web container)
        "/var/lib/hookprobe/fingerprint.db"
        "/var/lib/hookprobe/presence.db"
        "/var/lib/hookprobe/ecosystem_bubbles.db"
    )

    for db_file in "${core_databases[@]}"; do
        if [ ! -f "$db_file" ]; then
            # Create empty SQLite database with correct ownership
            touch "$db_file"
            log_info "Pre-created database: $db_file"
        fi
        chmod 666 "$db_file"
        chown 1000:1000 "$db_file" 2>/dev/null || true
    done

    chmod 755 /var/lib/hookprobe/userdata
    chmod 755 /var/lib/hookprobe/userdata/dnsxai

    # Data directory needs to be writable by qsecbit container (runs as uid 1000)
    # This is a bind mount shared between host and containers for device data
    chmod 777 "$INSTALL_DIR/data"
    chown 1000:1000 "$INSTALL_DIR/data" 2>/dev/null || true

    # Bootstrap dnsXai whitelist to PERSISTENT location
    # /etc/hookprobe/persistent/ is NEVER removed by any uninstall, even --purge
    # The userdata location is a symlink for backwards compatibility
    local default_whitelist="${FORTRESS_ROOT}/../../shared/dnsXai/data/whitelist.txt"
    local persistent_whitelist="/etc/hookprobe/persistent/dnsxai/whitelist.txt"
    local userdata_whitelist="/var/lib/hookprobe/userdata/dnsxai/whitelist.txt"

    # Migrate existing whitelist to persistent location if present
    if [ -f "$userdata_whitelist" ] && [ ! -L "$userdata_whitelist" ]; then
        if [ ! -f "$persistent_whitelist" ]; then
            log_info "Migrating existing whitelist to persistent location..."
            mv "$userdata_whitelist" "$persistent_whitelist"
        else
            log_info "Merging existing whitelist with persistent copy..."
            cat "$userdata_whitelist" >> "$persistent_whitelist"
            sort -u "$persistent_whitelist" -o "$persistent_whitelist"
            rm -f "$userdata_whitelist"
        fi
    fi

    # Bootstrap defaults if no whitelist exists
    if [ ! -f "$persistent_whitelist" ] && [ -f "$default_whitelist" ]; then
        log_info "Bootstrapping default dnsXai whitelist to persistent location..."
        cp "$default_whitelist" "$persistent_whitelist"
    fi
    chmod 644 "$persistent_whitelist" 2>/dev/null || true

    # Create symlink from userdata to persistent (backwards compatibility)
    if [ ! -L "$userdata_whitelist" ]; then
        rm -f "$userdata_whitelist" 2>/dev/null || true
        ln -sf "$persistent_whitelist" "$userdata_whitelist"
        log_info "Created symlink: $userdata_whitelist -> $persistent_whitelist"
    fi

    # Set group ownership so container (fortress user) can read config files
    chgrp -R fortress "$CONFIG_DIR" 2>/dev/null || true
    chgrp -R fortress /var/lib/hookprobe/userdata 2>/dev/null || true

    log_info "Directories created"
    log_info "  User data: /var/lib/hookprobe/userdata/ (persistent across reinstalls)"
}

copy_application_files() {
    log_step "Copying application files"

    # Copy web application
    cp -r "${SCRIPT_DIR}/web/"* "${INSTALL_DIR}/web/"

    # Copy library files
    cp -r "${SCRIPT_DIR}/lib/"* "${INSTALL_DIR}/lib/"

    # Copy container files (compose file, Containerfiles, etc.)
    # Note: Don't overwrite secrets directory if it exists
    for f in "${CONTAINERS_DIR}"/*; do
        local fname=$(basename "$f")
        if [ "$fname" != "secrets" ]; then
            cp -r "$f" "${INSTALL_DIR}/containers/" 2>/dev/null || true
        fi
    done

    # Create grafana provisioning directory (for monitoring profile)
    mkdir -p "${INSTALL_DIR}/containers/grafana/provisioning"/{dashboards,datasources,alerting}
    # Create basic datasource config for VictoriaMetrics
    cat > "${INSTALL_DIR}/containers/grafana/provisioning/datasources/victoria.yml" << 'EOF'
apiVersion: 1
datasources:
  - name: VictoriaMetrics
    type: prometheus
    access: proxy
    # VictoriaMetrics is on fts-internal network at 172.20.200.31
    url: http://172.20.200.31:8428
    isDefault: true
    editable: false
EOF

    # Copy device profiles
    mkdir -p "${INSTALL_DIR}/devices"
    cp -r "${DEVICES_DIR}/"* "${INSTALL_DIR}/devices/" 2>/dev/null || true

    # Copy bin scripts (dhcp-event.sh, etc.)
    if [ -d "${SCRIPT_DIR}/bin" ]; then
        mkdir -p "${INSTALL_DIR}/bin"
        cp -r "${SCRIPT_DIR}/bin/"* "${INSTALL_DIR}/bin/" 2>/dev/null || true
        chmod +x "${INSTALL_DIR}/bin/"*.sh 2>/dev/null || true
        log_info "  Installed: bin/ scripts (dhcp-event.sh, etc.)"
    fi

    # Ensure all shell scripts are executable (git may not preserve executable bit)
    find "${INSTALL_DIR}/devices" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

    # Install log rotation configuration (30-day retention for dnsXai logs)
    if [ -f "${CONTAINERS_DIR}/logrotate-dnsxai.conf" ]; then
        cp "${CONTAINERS_DIR}/logrotate-dnsxai.conf" /etc/logrotate.d/hookprobe-dnsxai
        chmod 644 /etc/logrotate.d/hookprobe-dnsxai
        log_info "Log rotation configured (30-day retention for dnsXai logs)"
    fi

    # Copy AIOCHI shared module (if AIOCHI installation requested)
    # AIOCHI location: shared/aiochi relative to repository root
    if [ "${INSTALL_AIOCHI:-}" = true ]; then
        local aiochi_src="${FORTRESS_ROOT}/../../shared/aiochi"
        local aiochi_dst="/opt/hookprobe/shared/aiochi"

        if [ -d "$aiochi_src" ]; then
            log_info "Copying AIOCHI module..."
            mkdir -p "$aiochi_dst"

            # Copy with error visibility (don't suppress errors)
            if ! cp -r "$aiochi_src/"* "$aiochi_dst/" 2>&1; then
                log_warn "  Some files failed to copy"
            fi

            # Verify critical files were copied
            local missing_files=0
            for critical_file in \
                "backend/__init__.py" \
                "backend/identity_engine.py" \
                "containers/Containerfile.identity" \
                "containers/Containerfile.logshipper" \
                "containers/podman-compose.aiochi.yml"; do
                if [ ! -f "$aiochi_dst/$critical_file" ]; then
                    log_warn "  Missing critical file: $critical_file"
                    missing_files=$((missing_files + 1))
                fi
            done

            if [ $missing_files -gt 0 ]; then
                log_warn "  $missing_files critical AIOCHI files missing - custom containers may fail to build"
            fi

            # Ensure scripts are executable
            find "$aiochi_dst" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
            find "$aiochi_dst" -name "*.py" -exec chmod +x {} \; 2>/dev/null || true

            # Create configs directory if it doesn't exist
            mkdir -p "$aiochi_dst/containers/configs/suricata/rules"
            mkdir -p "$aiochi_dst/containers/configs/zeek"
            mkdir -p "$aiochi_dst/containers/configs/grafana/provisioning"/{dashboards,datasources}
            mkdir -p "$aiochi_dst/containers/configs/grafana/dashboards"
            mkdir -p "$aiochi_dst/containers/n8n-workflows"

            log_info "  Installed: AIOCHI module to $aiochi_dst"
        else
            log_warn "AIOCHI source directory not found: $aiochi_src"
            log_warn "AIOCHI will not be available"
            export INSTALL_AIOCHI=false
        fi
    fi

    log_info "Application files copied to ${INSTALL_DIR}"
}

generate_secrets() {
    log_step "Generating secrets"

    # Secrets go in the INSTALLED containers directory (where compose runs from)
    local secrets_dir="${INSTALL_DIR}/containers/secrets"
    mkdir -p "$secrets_dir"
    mkdir -p "${CONFIG_DIR}/secrets"

    # PostgreSQL password
    if [ ! -f "$secrets_dir/postgres_password" ]; then
        openssl rand -base64 32 | tr -d '/+=' | head -c 32 > "$secrets_dir/postgres_password"
        chmod 600 "$secrets_dir/postgres_password"
        log_info "Generated PostgreSQL password"
    fi

    # Flask secret key
    if [ ! -f "$secrets_dir/flask_secret" ]; then
        openssl rand -base64 48 | tr -d '/+=' | head -c 48 > "$secrets_dir/flask_secret"
        chmod 600 "$secrets_dir/flask_secret"
        log_info "Generated Flask secret key"
    fi

    # Grafana admin password (required for monitoring profile)
    if [ ! -f "$secrets_dir/grafana_password" ]; then
        openssl rand -base64 24 | tr -d '/+=' | head -c 24 > "$secrets_dir/grafana_password"
        chmod 600 "$secrets_dir/grafana_password"
        log_info "Generated Grafana password"
    fi

    # Copy to config dir for web app access
    cp "$secrets_dir/flask_secret" "${CONFIG_DIR}/secrets/fortress_secret_key" 2>/dev/null || true

    # Save admin password for display (root-only, not needed by container)
    echo "${ADMIN_PASS}" > "${CONFIG_DIR}/secrets/admin_password"
    chmod 600 "${CONFIG_DIR}/secrets/admin_password"

    # Set ownership on config secrets so container (fortress user) can read
    chown root:fortress "${CONFIG_DIR}/secrets/fortress_secret_key" 2>/dev/null || true
    chmod 640 "${CONFIG_DIR}/secrets/fortress_secret_key" 2>/dev/null || true

    log_info "Secrets generated in $secrets_dir"

    # Generate Redis password if not exists
    if [ ! -f "$secrets_dir/redis_password" ]; then
        openssl rand -base64 24 | tr -d '/+=' | head -c 24 > "$secrets_dir/redis_password"
        chmod 600 "$secrets_dir/redis_password"
        log_info "Generated Redis password"
    fi

    # Create .env file for podman-compose to auto-read secrets
    # This ensures database volumes can be reused after reinstall!
    create_compose_env_file
}

# Create .env file in containers directory for podman-compose
# This is CRITICAL for data volume reuse - same credentials must be used!
create_compose_env_file() {
    local secrets_dir="${INSTALL_DIR}/containers/secrets"
    local env_file="${INSTALL_DIR}/containers/.env"

    log_info "Creating .env file for podman-compose"

    # Read secrets from files (or use defaults if files don't exist)
    local pg_pass="${POSTGRES_PASSWORD:-}"
    local redis_pass="${REDIS_PASSWORD:-}"
    local flask_key="${FLASK_SECRET_KEY:-}"
    local grafana_pass="${GRAFANA_PASSWORD:-}"

    # Load from files if not set via environment
    [ -z "$pg_pass" ] && [ -f "$secrets_dir/postgres_password" ] && pg_pass=$(cat "$secrets_dir/postgres_password")
    [ -z "$redis_pass" ] && [ -f "$secrets_dir/redis_password" ] && redis_pass=$(cat "$secrets_dir/redis_password")
    [ -z "$flask_key" ] && [ -f "$secrets_dir/flask_secret" ] && flask_key=$(cat "$secrets_dir/flask_secret")
    [ -z "$grafana_pass" ] && [ -f "$secrets_dir/grafana_password" ] && grafana_pass=$(cat "$secrets_dir/grafana_password")

    # Use safe defaults if still empty (first install)
    [ -z "$pg_pass" ] && pg_pass="fortress_db_secret"
    [ -z "$redis_pass" ] && redis_pass="fortress_redis_secret"
    [ -z "$flask_key" ] && flask_key="fortress_flask_secret_key_change_me"
    [ -z "$grafana_pass" ] && grafana_pass="fortress_grafana_admin"

    # Write .env file
    cat > "$env_file" << EOF
# HookProbe Fortress Container Environment
# Generated: $(date -Iseconds)
# WARNING: Do not modify - these credentials match your data volumes!
#
# If you change these passwords after initial install, you must either:
#   1. Remove the data volumes (podman volume rm fts-postgres-data fts-redis-data)
#   2. Or manually update the passwords inside the databases
#
# For reinstall with existing volumes: keep this file!

# Database credentials (CRITICAL for volume reuse)
POSTGRES_PASSWORD=${pg_pass}
REDIS_PASSWORD=${redis_pass}

# Application secrets
FLASK_SECRET_KEY=${flask_key}
GRAFANA_PASSWORD=${grafana_pass}

# Web port (can be changed freely)
WEB_PORT=${WEB_PORT:-8443}

# Network interfaces (set during install)
SURICATA_INTERFACE=${SURICATA_INTERFACE:-FTS}
ZEEK_INTERFACE=${ZEEK_INTERFACE:-FTS}
XDP_INTERFACE=${XDP_INTERFACE:-FTS}
EOF

    chmod 600 "$env_file"
    log_info ".env file created at $env_file"
}

create_admin_user() {
    log_step "Creating admin user"

    # Generate password hash
    local password_hash
    password_hash=$(python3 -c "
import bcrypt
password = '${ADMIN_PASS}'.encode('utf-8')
salt = bcrypt.gensalt(rounds=12)
hash = bcrypt.hashpw(password, salt)
print(hash.decode('utf-8'))
" 2>/dev/null) || {
        # Fallback - install bcrypt first
        pip3 install bcrypt &>/dev/null
        password_hash=$(python3 -c "
import bcrypt
password = '${ADMIN_PASS}'.encode('utf-8')
salt = bcrypt.gensalt(rounds=12)
hash = bcrypt.hashpw(password, salt)
print(hash.decode('utf-8'))
")
    }

    # Create users.json (dict format keyed by user ID - required by models.py)
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/users.json" << EOF
{
  "users": {
    "${ADMIN_USER}": {
      "password_hash": "${password_hash}",
      "role": "admin",
      "created_at": "$(date -Iseconds)",
      "email": "${ADMIN_USER}@localhost",
      "display_name": "Administrator",
      "is_active": true
    }
  },
  "version": "1.0"
}
EOF
    # Set ownership so container can read users.json
    # /etc/hookprobe is mounted as :ro (read-only), so we use world-readable (644)
    # This is safe because passwords are bcrypt-hashed and secrets are in env vars
    local fortress_gid
    fortress_gid=$(getent group fortress 2>/dev/null | cut -d: -f3)

    if [ "$fortress_gid" = "1000" ]; then
        # GID matches container - use group ownership for tighter permissions
        chown root:fortress "$CONFIG_DIR/users.json"
        chmod 640 "$CONFIG_DIR/users.json"
        log_info "Admin user created (group-readable by fortress)"
    else
        # GID differs from container - use world-readable for read-only config mount
        # This is acceptable security: passwords are bcrypt-hashed, secrets are in env vars
        chown root:root "$CONFIG_DIR/users.json"
        chmod 644 "$CONFIG_DIR/users.json"
        log_info "Admin user created (world-readable for container access)"
    fi
}

create_configuration() {
    log_step "Creating configuration"

    cat > "$CONFIG_DIR/fortress.conf" << EOF
# HookProbe Fortress Configuration
# Generated: $(date -Iseconds)

# Deployment mode
FORTRESS_MODE=container
FORTRESS_VERSION=5.5.0

# Network mode (flat bridge architecture)
NETWORK_MODE=${NETWORK_MODE}

# LAN Network Configuration (Flat Bridge)
LAN_SUBNET_MASK=${LAN_SUBNET_MASK:-24}
LAN_DHCP_START=${LAN_DHCP_START:-10.200.0.100}
LAN_DHCP_END=${LAN_DHCP_END:-10.200.0.200}
GATEWAY_IP=10.200.0.1

# Database (handled by container)
DATABASE_HOST=fts-postgres
DATABASE_PORT=5432
DATABASE_NAME=fortress
DATABASE_USER=fortress

# Redis (handled by container)
REDIS_HOST=fts-redis
REDIS_PORT=6379

# Web UI
WEB_PORT=${WEB_PORT}
WEB_SSL=true

# Logging
LOG_LEVEL=info
LOG_DIR=${LOG_DIR}

# Optional features
INSTALL_AIOCHI=${INSTALL_AIOCHI:-false}
INSTALL_LTE=${INSTALL_LTE:-false}
INSTALL_TUNNEL=${INSTALL_TUNNEL:-false}

# Container networking - SKIP OVS attachment to preserve podman port forwarding
# OVS veth attachment breaks podman's DNAT rules for port 8443
# Set to false only if you need OpenFlow visibility into container traffic
SKIP_OVS_CONTAINER_ATTACH=true

# WiFi Device-to-Device (D2D) communication
# ENABLE_WIFI_D2D=true (default): Allow AirPlay, HomeKit, printers, file sharing
# ENABLE_WIFI_D2D=false: Strict isolation for guest networks (blocks all D2D)
ENABLE_WIFI_D2D=true
EOF

    # Set ownership so container (fortress user) can read
    chown root:fortress "$CONFIG_DIR/fortress.conf"
    chmod 640 "$CONFIG_DIR/fortress.conf"
    log_info "Configuration created"
}

setup_network_filter() {
    log_step "Setting up network filtering"

    if [ "$NFTABLES_AVAILABLE" = true ]; then
        # Initialize nftables filter manager for per-device policies
        chmod +x "${DEVICES_DIR}/common/network-filter-manager.sh" 2>/dev/null || true
        "${DEVICES_DIR}/common/network-filter-manager.sh" init || {
            log_warn "Failed to initialize nftables filters (may need manual setup)"
        }
        log_info "nftables filter mode initialized"
    else
        log_warn "nftables not available - network filtering disabled"
    fi
}

setup_network() {
    log_step "Setting up OVS network infrastructure"

    # Source network integration module for interface detection
    local integration_script="${DEVICES_DIR}/common/network-integration.sh"
    local ovs_script="${DEVICES_DIR}/common/ovs-container-network.sh"
    local hostapd_script="${DEVICES_DIR}/common/hostapd-generator.sh"

    # Make scripts executable
    chmod +x "$integration_script" "$ovs_script" "$hostapd_script" 2>/dev/null || true

    # Detect network interfaces
    # Note: Sourced scripts may overwrite SCRIPT_DIR - we use FORTRESS_ROOT where needed
    log_info "Detecting network interfaces..."
    if [ -f "$integration_script" ]; then
        source "$integration_script"
        network_integration_init || {
            log_warn "Network detection had issues - continuing with defaults"
        }
    else
        log_error "Network integration script not found: $integration_script"
        return 1
    fi

    # Show what we detected
    log_info "Detected interfaces:"
    log_info "  WAN:  ${NET_WAN_IFACE:-auto-detect}"
    log_info "  LAN:  ${NET_LAN_IFACES:-none}"
    log_info "  Admin: ${MGMT_INTERFACE:-none}${MGMT_INTERFACE:+ (admin console port)}"
    log_info "  WiFi: ${NET_WIFI_24GHZ_IFACE:-none} (2.4G) / ${NET_WIFI_5GHZ_IFACE:-none} (5G)"
    log_info "  LTE:  ${NET_WWAN_IFACE:-none}"

    # Initialize OVS network fabric
    log_info "Initializing OVS network fabric..."
    if [ -f "$ovs_script" ]; then
        # Export configuration for OVS script
        export OVS_BRIDGE="FTS"
        export LAN_SUBNET_MASK="${LAN_SUBNET_MASK:-24}"

        # Initialize OVS bridge for podman mode (skips tier internal ports)
        # Podman-compose creates its own networks with the tier IPs
        "$ovs_script" init-podman || {
            log_error "Failed to initialize OVS network"
            return 1
        }

        # Add LAN physical interfaces to OVS bridge
        if [ -n "$NET_LAN_IFACES" ]; then
            for iface in $NET_LAN_IFACES; do
                log_info "  Adding LAN interface $iface to OVS bridge..."
                "$ovs_script" add-lan "$iface" || {
                    log_warn "Failed to add $iface to OVS bridge"
                }
            done
        else
            log_warn "No LAN interfaces detected to add to bridge"
            log_info "  WiFi AP will provide client connectivity"
        fi

        # Add admin console interface to OVS bridge if detected
        # This is designated as the last LAN ethernet port (by PCI order)
        # Recommended for connecting admin workstation for initial setup
        if [ -n "$MGMT_INTERFACE" ]; then
            log_info "  Adding admin interface $MGMT_INTERFACE to OVS bridge..."
            "$ovs_script" add-lan "$MGMT_INTERFACE" || {
                log_warn "Failed to add admin interface $MGMT_INTERFACE to OVS bridge"
            }
        fi

        # Setup NAT - detect WAN interface if not already set
        local wan_iface="${NET_WAN_IFACE:-}"
        if [ -z "$wan_iface" ]; then
            # Fallback: detect WAN from default route
            wan_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
            if [ -n "$wan_iface" ]; then
                log_info "Detected WAN interface from default route: $wan_iface"
                NET_WAN_IFACE="$wan_iface"
            fi
        fi

        if [ -n "$wan_iface" ]; then
            "$ovs_script" nat "$wan_iface" || {
                log_warn "NAT setup had issues"
            }
        else
            log_warn "No WAN interface detected - NAT not configured"
            log_warn "Clients may not have internet access"
        fi

        # Configure network mode (VLAN or filter-based)
        local netplan_gen="${DEVICES_DIR}/common/netplan-ovs-generator.sh"
        local ovs_post="${DEVICES_DIR}/common/ovs-post-setup.sh"

        if [ -f "$netplan_gen" ]; then
            # FLAT BRIDGE ARCHITECTURE - Use Netplan + OVS for fast, reliable network setup
            # FTS Bridge: 10.200.0.0/xx - All devices on same L2 segment
            # Segmentation via OpenFlow NAC rules (device policies)
            log_info "Configuring flat bridge network (netplan + OVS)..."

            chmod +x "$netplan_gen"
            [ -f "$ovs_post" ] && chmod +x "$ovs_post"

            # Export configuration for netplan generator
            export OVS_BRIDGE="${OVS_BRIDGE:-FTS}"
            export LAN_MASK="${LAN_SUBNET_MASK:-24}"
            export LAN_INTERFACES="${NET_LAN_IFACES:-}"

            # Step 1: Generate netplan config for OVS bridge + VLANs
            log_info "Generating netplan configuration..."
            if "$netplan_gen" generate --mask "$LAN_MASK" --lan-ifaces "$LAN_INTERFACES"; then
                log_success "Netplan config generated"

                # Step 2: Apply netplan (creates bridge, VLANs, assigns IPs)
                log_info "Applying netplan configuration..."
                if "$netplan_gen" apply; then
                    log_success "Netplan applied - bridge and VLANs created"

                    # Step 3: Run OVS post-setup (OpenFlow rules, port tagging)
                    if [ -f "$ovs_post" ]; then
                        log_info "Configuring OpenFlow rules and port VLAN tags..."
                        if "$ovs_post" setup; then
                            log_success "OVS post-setup complete"
                        else
                            log_warn "OVS post-setup had issues - may need manual config"
                        fi
                    fi

                    log_success "Flat bridge network configured via netplan"
                    log_info "  FTS Bridge: 10.200.0.0/$LAN_MASK - WiFi clients, LAN devices"
                    log_info "  OpenFlow:   NAC via device fingerprinting policies"

                    # Configure DHCP on FTS bridge (flat bridge mode)
                    setup_flat_bridge_dhcp

                    # Install services for boot persistence
                    install_vlan_service

                    # Install device status updater (tracks online/idle/offline via OpenFlow + ARP)
                    install_device_status_service
                else
                    log_error "Netplan apply failed"
                    "$netplan_gen" remove 2>/dev/null || true
                    return 1
                fi
            else
                log_error "Netplan generation failed"
                return 1
            fi
        fi

    else
        log_error "OVS network manager not found: $ovs_script"
        return 1
    fi

    # Setup WiFi AP (bridges to OVS)
    # =========================================
    # WIFI SETUP - DETECT FIRST, THEN CONFIGURE
    # =========================================
    # Order: 1) Detect bands, 2) Create udev rules, 3) Generate configs, 4) Create services

    log_info "Configuring WiFi access point..."

    # PHASE 1: DETECTION - Detect interfaces and bands, create udev rules
    # This sets WIFI_24GHZ_STABLE, WIFI_5GHZ_STABLE, WIFI_24GHZ_DETECTED, WIFI_5GHZ_DETECTED
    detect_wifi_and_create_udev_rules

    # Check if we found any WiFi interfaces
    if [ -z "$WIFI_24GHZ_DETECTED" ] && [ -z "$WIFI_5GHZ_DETECTED" ]; then
        log_info "No WiFi adapters found"
        WIFI_SSID=""
        WIFI_PASSWORD=""
    else
        # Use the configured WIFI_SSID and WIFI_PASSWORD
        local wifi_ssid="${WIFI_SSID:-HookProbe-Fortress}"
        local wifi_pass="${WIFI_PASSWORD:-}"

        # Generate password if not set
        if [ -z "$wifi_pass" ]; then
            wifi_pass=$(openssl rand -base64 12 | tr -d '/+=' | head -c 12)
            WIFI_PASSWORD="$wifi_pass"
        fi

        # PHASE 2: CONFIGURATION - Generate hostapd configs with stable names
        if [ -f "$hostapd_script" ]; then
            # Export interface names FIRST - before prepare_wifi_interfaces
            # hostapd-generator.sh and prepare_wifi_interfaces expect NET_WIFI_* variables
            export NET_WIFI_24GHZ_IFACE="${WIFI_24GHZ_STABLE:-}"
            export NET_WIFI_5GHZ_IFACE="${WIFI_5GHZ_STABLE:-}"

            # Set config mode based on detected interfaces
            if [ -n "$WIFI_24GHZ_DETECTED" ] && [ -n "$WIFI_5GHZ_DETECTED" ]; then
                export NET_WIFI_CONFIG_MODE="separate-radios"
            elif [ -n "$WIFI_24GHZ_DETECTED" ]; then
                export NET_WIFI_CONFIG_MODE="24ghz-only"
            elif [ -n "$WIFI_5GHZ_DETECTED" ]; then
                export NET_WIFI_CONFIG_MODE="5ghz-only"
            fi

            log_info "  WiFi config mode: ${NET_WIFI_CONFIG_MODE:-none}"
            log_info "  2.4GHz interface: ${NET_WIFI_24GHZ_IFACE:-none}"
            log_info "  5GHz interface: ${NET_WIFI_5GHZ_IFACE:-none}"

            # Update the state file with stable names so hostapd-generator sees them
            # even if environment variable propagation fails for some reason
            local state_file="/var/lib/fortress/network-interfaces.conf"
            if [ -f "$state_file" ]; then
                # Replace original interface names with stable names in state file
                if [ -n "$NET_WIFI_24GHZ_IFACE" ]; then
                    sed -i "s|^NET_WIFI_24GHZ_IFACE=.*|NET_WIFI_24GHZ_IFACE=\"${NET_WIFI_24GHZ_IFACE}\"|" "$state_file"
                fi
                if [ -n "$NET_WIFI_5GHZ_IFACE" ]; then
                    sed -i "s|^NET_WIFI_5GHZ_IFACE=.*|NET_WIFI_5GHZ_IFACE=\"${NET_WIFI_5GHZ_IFACE}\"|" "$state_file"
                fi
                if [ -n "$NET_WIFI_CONFIG_MODE" ]; then
                    sed -i "s|^NET_WIFI_CONFIG_MODE=.*|NET_WIFI_CONFIG_MODE=\"${NET_WIFI_CONFIG_MODE}\"|" "$state_file"
                fi
                log_info "  Updated state file with stable interface names"
            fi

            # Prepare interfaces for AP mode (uses exported variables)
            prepare_wifi_interfaces 2>/dev/null || true

            # Generate hostapd configs - uses NET_WIFI_* variables
            if ! "$hostapd_script" configure "$wifi_ssid" "$wifi_pass" "$OVS_BRIDGE" 2>&1; then
                log_warn "Hostapd configuration had issues"
            fi

            # Ensure configs use stable interface names (in case generator used originals)
            update_hostapd_configs_stable_names

            # PHASE 3: Create services with stable names (once, not redundantly)
            create_wifi_services_stable

            # Save WiFi credentials
            echo "WIFI_SSID=$wifi_ssid" >> "$CONFIG_DIR/fortress.conf"
            echo "$wifi_pass" > "$CONFIG_DIR/secrets/wifi_password"
            chmod 600 "$CONFIG_DIR/secrets/wifi_password"

            log_info "WiFi AP configured (bridged to OVS):"
            log_info "  SSID: $wifi_ssid"
            log_info "  2.4GHz: ${WIFI_24GHZ_STABLE:-not detected}"
            log_info "  5GHz:   ${WIFI_5GHZ_STABLE:-not detected}"
        else
            log_warn "Hostapd generator not found - WiFi not configured"
        fi
    fi

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-fts-forward.conf

    # NOTE: WiFi udev rules creation is handled above in the conditional blocks
    # (lines 707 and 736) - we don't need a redundant unconditional call here
    # as it would overwrite any successful rules created earlier

    # Initialize LTE/WWAN modem if detected
    if [ -n "$NET_WWAN_IFACE" ] || [ -n "$NET_WWAN_INTERFACES" ]; then
        log_info "LTE modem detected - initializing..."
        if type initialize_lte_modem &>/dev/null; then
            if initialize_lte_modem; then
                # Try to connect (will use auto-APN or configured APN)
                local lte_apn="${LTE_APN:-}"
                if connect_lte "$lte_apn"; then
                    log_info "LTE connected successfully"
                    # Setup WAN failover if we have both Ethernet WAN and LTE
                    if [ -n "$NET_WAN_IFACE" ]; then
                        # Clean up minimal PBR from early network resilience
                        # before installing full PBR with monitoring
                        if type enr_cleanup &>/dev/null; then
                            enr_cleanup
                        fi
                        setup_wan_failover "$NET_WAN_IFACE" "$NET_WWAN_IFACE" 2>/dev/null || true
                    fi
                else
                    log_warn "LTE connection failed - will retry on boot"
                fi
                # Create systemd service for LTE on boot
                setup_lte_on_boot "$lte_apn"
            else
                log_warn "LTE modem initialization failed"
            fi
        else
            log_warn "LTE functions not available"
        fi
    elif ls /sys/class/net/wwan* &>/dev/null 2>&1 || ls /sys/class/net/wwp* &>/dev/null 2>&1; then
        # WWAN interface exists but wasn't detected in initial scan
        log_info "WWAN interface found - attempting late initialization..."
        if type initialize_lte_modem &>/dev/null; then
            if type enr_cleanup &>/dev/null; then
                enr_cleanup
            fi
            initialize_lte_modem && connect_lte && setup_lte_on_boot
        fi
    fi

    # Validate network setup
    validate_network_setup

    log_info "OVS network infrastructure configured"
    log_info "  OpenFlow: Tier isolation rules installed"
    log_info "  Mirror:   Traffic mirroring to QSecBit enabled"
    log_info "  sFlow:    Flow export to 127.0.0.1:6343"
    log_info "  IPFIX:    Flow export to 127.0.0.1:4739"
}

# Validate network setup and report issues
validate_network_setup() {
    log_step "Validating Network Configuration"
    local errors=0
    local warnings=0

    # Check OVS bridge exists and is up
    if ! ovs-vsctl br-exists "${OVS_BRIDGE:-FTS}" 2>/dev/null; then
        log_error "OVS bridge ${OVS_BRIDGE:-FTS} does not exist"
        errors=$((errors + 1))
    elif ! ip link show "${OVS_BRIDGE:-FTS}" 2>/dev/null | grep -q "state UP"; then
        log_warn "OVS bridge ${OVS_BRIDGE:-FTS} is not UP"
        warnings=$((warnings + 1))
    else
        log_info "OVS bridge: ${OVS_BRIDGE:-FTS} (UP)"
    fi

    # Check gateway IP is configured on FTS bridge (flat bridge mode)
    if ip addr show "${OVS_BRIDGE:-FTS}" 2>/dev/null | grep -q "10.200.0.1"; then
        log_info "LAN gateway: 10.200.0.1 on ${OVS_BRIDGE:-FTS} bridge"
    else
        log_warn "LAN gateway IP not configured on bridge"
        warnings=$((warnings + 1))
    fi

    # Check IP forwarding
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
        log_info "IP forwarding: enabled"
    else
        log_warn "IP forwarding: disabled (clients won't have internet)"
        warnings=$((warnings + 1))
    fi

    # Check dnsmasq is running
    if systemctl is-active --quiet dnsmasq 2>/dev/null; then
        log_info "DHCP server: dnsmasq (running)"
    elif systemctl is-active --quiet fortress-dnsmasq 2>/dev/null; then
        log_info "DHCP server: fortress-dnsmasq (running)"
    else
        log_warn "DHCP server: not running"
        warnings=$((warnings + 1))
    fi

    # Check NAT is configured (if WAN interface detected)
    if [ -n "$NET_WAN_IFACE" ]; then
        if iptables -t nat -L POSTROUTING 2>/dev/null | grep -q "MASQUERADE"; then
            log_info "NAT: configured (WAN: $NET_WAN_IFACE)"
        elif nft list tables 2>/dev/null | grep -q "nat"; then
            log_info "NAT: configured via nftables (WAN: $NET_WAN_IFACE)"
        else
            log_warn "NAT: not configured (clients may not have internet)"
            warnings=$((warnings + 1))
        fi
    fi

    # Check WiFi AP status
    if [ -n "$WIFI_SSID" ]; then
        local wifi_running=false
        if systemctl is-active --quiet fts-hostapd-24 2>/dev/null; then
            wifi_running=true
        fi
        if systemctl is-active --quiet fts-hostapd-5g 2>/dev/null; then
            wifi_running=true
        fi
        if [ "$wifi_running" = true ]; then
            log_info "WiFi AP: running (SSID: $WIFI_SSID)"
        else
            log_warn "WiFi AP: not running yet (will start after installation)"
            # This is expected during install, services start after
        fi
    fi

    # Summary
    echo ""
    if [ $errors -gt 0 ]; then
        log_error "Network validation: $errors error(s), $warnings warning(s)"
        log_error "Critical network issues detected - installation may fail"
        return 1
    elif [ $warnings -gt 0 ]; then
        log_warn "Network validation: $warnings warning(s)"
        log_info "Some features may not work until issues are resolved"
        return 0
    else
        log_success "Network validation: passed"
        return 0
    fi
}

# ============================================================
# WIFI DETECTION AND UDEV RULES - PHASE 1
# ============================================================

# Global variables for WiFi detection results
WIFI_24GHZ_DETECTED=""
WIFI_5GHZ_DETECTED=""
WIFI_24GHZ_STABLE="wlan_24ghz"
WIFI_5GHZ_STABLE="wlan_5ghz"
WIFI_24GHZ_ORIGINAL=""
WIFI_5GHZ_ORIGINAL=""
WIFI_24GHZ_MAC=""
WIFI_5GHZ_MAC=""

detect_wifi_and_create_udev_rules() {
    # PHASE 1: Detect WiFi interfaces, determine bands, create udev rules
    #
    # This function:
    #   1. Detects all WiFi interfaces
    #   2. Determines which band each supports (2.4GHz vs 5GHz)
    #   3. Creates udev rules for stable naming
    #   4. Renames interfaces immediately
    #   5. Sets global variables for use by later phases
    #
    # After this function, use:
    #   - WIFI_24GHZ_STABLE (wlan_24ghz) and WIFI_5GHZ_STABLE (wlan_5ghz) for configs
    #   - WIFI_24GHZ_DETECTED and WIFI_5GHZ_DETECTED to check if interfaces exist

    log_info "Phase 1: Detecting WiFi interfaces and bands..."

    local udev_rule_file="/etc/udev/rules.d/70-fts-wifi.rules"

    # Check if iw command exists
    if ! command -v iw &>/dev/null; then
        log_warn "  'iw' command not found - cannot detect WiFi adapters"
        return 1
    fi

    # Try iw dev first
    log_info "  Scanning for WiFi adapters..."
    local wifi_ifaces
    wifi_ifaces=$(iw dev 2>/dev/null | awk '/Interface/{print $2}')

    # Fallback to sysfs if iw dev returns nothing
    if [ -z "$wifi_ifaces" ]; then
        log_info "  iw dev returned nothing, trying sysfs fallback..."
        wifi_ifaces=""
        for wireless_dir in /sys/class/net/*/wireless; do
            if [ -d "$wireless_dir" ]; then
                local iface_name
                iface_name=$(basename "$(dirname "$wireless_dir")")
                wifi_ifaces="$wifi_ifaces $iface_name"
            fi
        done
        wifi_ifaces=$(echo "$wifi_ifaces" | xargs)  # trim whitespace
    fi

    if [ -z "$wifi_ifaces" ]; then
        log_warn "  No WiFi interfaces found via iw dev or sysfs"
        return 1
    fi

    log_info "  Found WiFi interfaces: $wifi_ifaces"

    for iface in $wifi_ifaces; do
        local mac
        mac=$(cat /sys/class/net/$iface/address 2>/dev/null)
        [ -z "$mac" ] && continue

        # Check band support via iw phy
        local phy
        phy=$(iw dev $iface info 2>/dev/null | awk '/wiphy/{print "phy"$2}')

        # Fallback 1: try sysfs phy80211 symlink
        if [ -z "$phy" ]; then
            if [ -L "/sys/class/net/$iface/phy80211" ]; then
                phy=$(basename "$(readlink -f /sys/class/net/$iface/phy80211)")
            fi
        fi

        # Fallback 2: scan /sys/class/ieee80211/phy*/device/net/ for interface
        if [ -z "$phy" ]; then
            for phy_dir in /sys/class/ieee80211/phy*; do
                if [ -d "$phy_dir/device/net/$iface" ]; then
                    phy=$(basename "$phy_dir")
                    break
                fi
            done
        fi

        if [ -z "$phy" ]; then
            log_warn "  Could not determine phy for $iface - skipping"
            continue
        fi

        local has_5ghz=0
        local has_24ghz=0
        local phy_info
        phy_info=$(iw phy $phy info 2>/dev/null)

        # Debug: log what we found
        log_info "  Checking $iface on $phy..."

        # Check for 2.4GHz band (Band 1, frequencies 2400-2500 MHz)
        # Match patterns like "2412 MHz" or "2437 MHz"
        if echo "$phy_info" | grep -qE "24[0-9]{2} MHz"; then
            has_24ghz=1
        fi

        # Check for 5GHz band (Band 2, frequencies 5000-5900 MHz)
        # Match patterns like "5180 MHz" or "5745 MHz"
        if echo "$phy_info" | grep -qE "5[0-9]{3} MHz"; then
            has_5ghz=1
        fi

        # Alternative: check by Band number in iw output
        if [ "$has_24ghz" -eq 0 ] && [ "$has_5ghz" -eq 0 ]; then
            # Try band-based detection
            if echo "$phy_info" | grep -q "Band 1:"; then
                has_24ghz=1
            fi
            if echo "$phy_info" | grep -q "Band 2:"; then
                has_5ghz=1
            fi
        fi

        log_info "    2.4GHz: $has_24ghz, 5GHz: $has_5ghz"

        # Assign to 5GHz slot first if capable (prioritize 5GHz/dual-band)
        if [ "$has_5ghz" -gt 0 ] && [ -z "$WIFI_5GHZ_MAC" ]; then
            WIFI_5GHZ_ORIGINAL="$iface"
            WIFI_5GHZ_MAC="$mac"
            WIFI_5GHZ_DETECTED="true"
            log_info "  5GHz adapter: $iface ($mac)"
        elif [ "$has_24ghz" -gt 0 ] && [ -z "$WIFI_24GHZ_MAC" ]; then
            WIFI_24GHZ_ORIGINAL="$iface"
            WIFI_24GHZ_MAC="$mac"
            WIFI_24GHZ_DETECTED="true"
            log_info "  2.4GHz adapter: $iface ($mac)"
        elif [ -z "$WIFI_24GHZ_MAC" ]; then
            # If we can't determine band, default to 2.4GHz slot
            WIFI_24GHZ_ORIGINAL="$iface"
            WIFI_24GHZ_MAC="$mac"
            WIFI_24GHZ_DETECTED="true"
            log_info "  Unknown band adapter (defaulting to 2.4GHz): $iface ($mac)"
        elif [ -z "$WIFI_5GHZ_MAC" ]; then
            # Second unknown goes to 5GHz
            WIFI_5GHZ_ORIGINAL="$iface"
            WIFI_5GHZ_MAC="$mac"
            WIFI_5GHZ_DETECTED="true"
            log_info "  Unknown band adapter (defaulting to 5GHz): $iface ($mac)"
        fi
    done

    # Check if any WiFi was found
    if [ -z "$WIFI_24GHZ_MAC" ] && [ -z "$WIFI_5GHZ_MAC" ]; then
        log_warn "  No WiFi adapters detected"
        return 1
    fi

    # Generate udev rules file
    log_info "  Creating udev rules..."
    cat > "$udev_rule_file" << 'UDEV_HEADER'
# HookProbe Fortress - WiFi Interface Stable Naming
# Generated automatically - do not edit manually
#
# These rules ensure WiFi interfaces have stable names across reboots
# by matching on MAC address instead of kernel enumeration order.

UDEV_HEADER

    if [ -n "$WIFI_24GHZ_MAC" ]; then
        echo "# 2.4GHz WiFi adapter (original: $WIFI_24GHZ_ORIGINAL)" >> "$udev_rule_file"
        echo "SUBSYSTEM==\"net\", ACTION==\"add\", ATTR{address}==\"$WIFI_24GHZ_MAC\", NAME=\"$WIFI_24GHZ_STABLE\"" >> "$udev_rule_file"
        log_info "  Rule: $WIFI_24GHZ_MAC -> $WIFI_24GHZ_STABLE"
    fi

    if [ -n "$WIFI_5GHZ_MAC" ]; then
        echo "# 5GHz WiFi adapter (original: $WIFI_5GHZ_ORIGINAL)" >> "$udev_rule_file"
        echo "SUBSYSTEM==\"net\", ACTION==\"add\", ATTR{address}==\"$WIFI_5GHZ_MAC\", NAME=\"$WIFI_5GHZ_STABLE\"" >> "$udev_rule_file"
        log_info "  Rule: $WIFI_5GHZ_MAC -> $WIFI_5GHZ_STABLE"
    fi

    log_info "  Created $udev_rule_file"

    # Rename interfaces immediately (udev rules only apply at boot)
    log_info "  Renaming interfaces now..."
    udevadm control --reload-rules
    udevadm settle --timeout=5 2>/dev/null || sleep 1

    local rename_failed=false

    if [ -n "$WIFI_24GHZ_MAC" ] && [ -n "$WIFI_24GHZ_ORIGINAL" ]; then
        if [ "$WIFI_24GHZ_ORIGINAL" != "$WIFI_24GHZ_STABLE" ]; then
            ip link set "$WIFI_24GHZ_ORIGINAL" down 2>/dev/null || true
            if ip link set "$WIFI_24GHZ_ORIGINAL" name "$WIFI_24GHZ_STABLE" 2>/dev/null; then
                ip link set "$WIFI_24GHZ_STABLE" up 2>/dev/null || true
                log_info "  Renamed: $WIFI_24GHZ_ORIGINAL -> $WIFI_24GHZ_STABLE"
            else
                log_warn "  Could not rename $WIFI_24GHZ_ORIGINAL (reboot required)"
                rename_failed=true
            fi
        fi
    fi

    if [ -n "$WIFI_5GHZ_MAC" ] && [ -n "$WIFI_5GHZ_ORIGINAL" ]; then
        if [ "$WIFI_5GHZ_ORIGINAL" != "$WIFI_5GHZ_STABLE" ]; then
            ip link set "$WIFI_5GHZ_ORIGINAL" down 2>/dev/null || true
            if ip link set "$WIFI_5GHZ_ORIGINAL" name "$WIFI_5GHZ_STABLE" 2>/dev/null; then
                ip link set "$WIFI_5GHZ_STABLE" up 2>/dev/null || true
                log_info "  Renamed: $WIFI_5GHZ_ORIGINAL -> $WIFI_5GHZ_STABLE"
            else
                log_warn "  Could not rename $WIFI_5GHZ_ORIGINAL (reboot required)"
                rename_failed=true
            fi
        fi
    fi

    # Save interface mapping for reference
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/wifi-interfaces.conf" << EOF
# WiFi Interface Mapping - Generated $(date -Iseconds)
WIFI_24GHZ_MAC=$WIFI_24GHZ_MAC
WIFI_24GHZ_ORIGINAL=$WIFI_24GHZ_ORIGINAL
WIFI_24GHZ_STABLE=$WIFI_24GHZ_STABLE
WIFI_5GHZ_MAC=$WIFI_5GHZ_MAC
WIFI_5GHZ_ORIGINAL=$WIFI_5GHZ_ORIGINAL
WIFI_5GHZ_STABLE=$WIFI_5GHZ_STABLE
EOF

    if $rename_failed; then
        log_warn "Some interfaces need reboot to rename"
    fi

    log_info "Phase 1 complete: WiFi detected, udev rules created"
    return 0
}

# ============================================================
# WIFI HOSTAPD CONFIG UPDATE - PHASE 2 HELPER
# ============================================================
update_hostapd_configs_stable_names() {
    # Update hostapd configs to use stable interface names
    # Called if hostapd-generator used original names

    log_info "  Updating hostapd configs to stable names..."

    if [ -n "$WIFI_24GHZ_DETECTED" ] && [ -f /etc/hostapd/hostapd-24ghz.conf ]; then
        sed -i "s/^interface=.*/interface=$WIFI_24GHZ_STABLE/" /etc/hostapd/hostapd-24ghz.conf
        log_info "    Updated: hostapd-24ghz.conf -> $WIFI_24GHZ_STABLE"
    fi

    if [ -n "$WIFI_5GHZ_DETECTED" ] && [ -f /etc/hostapd/hostapd-5ghz.conf ]; then
        sed -i "s/^interface=.*/interface=$WIFI_5GHZ_STABLE/" /etc/hostapd/hostapd-5ghz.conf
        log_info "    Updated: hostapd-5ghz.conf -> $WIFI_5GHZ_STABLE"
    fi
}

# ============================================================
# WIFI BRIDGE HELPER - SDN AUTOPILOT SUPPORT
# ============================================================
generate_wifi_bridge_helper() {
    # Generate helper script for WiFi → br-wifi → veth → OVS architecture
    # This enables SDN policy enforcement and ebtables-based WiFi isolation

    local helper_script="/usr/local/bin/fts-wifi-bridge-helper.sh"
    local ovs_bridge="${OVS_BRIDGE:-FTS}"

    log_info "Generating WiFi bridge helper script..."

    cat > "$helper_script" << 'HELPER_EOF'
#!/bin/bash
# Fortress WiFi Bridge Helper - SDN Autopilot Edition
#
# Architecture: WiFi → br-wifi (Linux bridge) → veth → OVS
#
# This script:
# 1. Ensures br-wifi exists and is connected to OVS via veth
# 2. Adds WiFi interface to br-wifi (NOT directly to OVS)
# 3. Sets up ebtables to force WiFi-to-WiFi through veth for OVS policy enforcement
# 4. Enables hairpin mode for mDNS/Bonjour reflection (HomeKit/AirPlay)

IFACE="$1"
OVS_BRIDGE="${2:-FTS}"
ACTION="${3:-add}"
WIFI_BRIDGE="br-wifi"
VETH_BR="veth-wifi-a"
VETH_OVS="veth-wifi-b"
# FLAT BRIDGE: No VLAN tagging - all ports untagged

# Load Fortress config for D2D setting
# ENABLE_WIFI_D2D=true allows device-to-device (AirPlay, HomeKit, printers)
# ENABLE_WIFI_D2D=false forces strict isolation (guest network mode)
if [ -f /etc/hookprobe/fortress.conf ]; then
    # shellcheck source=/dev/null
    source /etc/hookprobe/fortress.conf 2>/dev/null || true
fi
ENABLE_WIFI_D2D="${ENABLE_WIFI_D2D:-true}"  # Default: allow D2D

[ -z "$IFACE" ] && exit 1

log() { echo "[wifi-bridge] $*"; logger -t fts-wifi-bridge "$*" 2>/dev/null || true; }

# Wait for interface to be ready
for i in {1..10}; do
    if ip link show "$IFACE" &>/dev/null; then
        break
    fi
    sleep 0.5
done

if ! ip link show "$IFACE" &>/dev/null; then
    log "Interface $IFACE not found after waiting"
    exit 1
fi

# Ensure br-wifi exists
ensure_wifi_bridge() {
    if ! ip link show "$WIFI_BRIDGE" &>/dev/null; then
        log "Creating WiFi bridge $WIFI_BRIDGE"
        ip link add "$WIFI_BRIDGE" type bridge
        ip link set "$WIFI_BRIDGE" type bridge stp_state 0
        echo 0 > "/sys/class/net/$WIFI_BRIDGE/bridge/forward_delay" 2>/dev/null || true
    fi
    ip link set "$WIFI_BRIDGE" up
}

# Ensure veth pair connecting br-wifi to OVS
ensure_veth_pair() {
    if ! ip link show "$VETH_BR" &>/dev/null; then
        log "Creating veth pair $VETH_BR <-> $VETH_OVS"
        ip link add "$VETH_BR" type veth peer name "$VETH_OVS"
    fi

    # Add veth_br to br-wifi
    if ! ip link show master "$WIFI_BRIDGE" 2>/dev/null | grep -q "$VETH_BR"; then
        ip link set "$VETH_BR" master "$WIFI_BRIDGE" 2>/dev/null || true
    fi

    # Add veth_ovs to OVS (flat bridge - no VLAN tagging)
    if command -v ovs-vsctl &>/dev/null && ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        if ! ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${VETH_OVS}$"; then
            log "Adding $VETH_OVS to OVS bridge $OVS_BRIDGE (flat mode)"
            ovs-vsctl --may-exist add-port "$OVS_BRIDGE" "$VETH_OVS" 2>/dev/null || true
        fi
    fi

    ip link set "$VETH_BR" up
    ip link set "$VETH_OVS" up
}

# Set up hairpin mode for D2D traffic
# With ap_isolate=1 in hostapd, all WiFi traffic goes through br-wifi bridge.
# Hairpin mode allows traffic to return to the same or different WiFi interface.
# OVS NAC rules handle policy enforcement (internet_only blocks LAN traffic).
#
# NO ebtables DROP rules - they block D2D before OVS can apply policy!
# NO bridge port isolation - ap_isolate=1 already forces traffic through bridge.
setup_hairpin() {
    # Clean up any old ebtables DROP rules (migration from old approach)
    if command -v ebtables &>/dev/null; then
        ebtables -D FORWARD -i "$IFACE" -o "$IFACE" -j DROP 2>/dev/null || true
        for other in wlan_24ghz wlan_5ghz wlan0 wlan1; do
            if [ "$other" != "$IFACE" ]; then
                ebtables -D FORWARD -i "$IFACE" -o "$other" -j DROP 2>/dev/null || true
            fi
        done

        # Ensure ACCEPT rule for veth (OVS return traffic)
        if ! ebtables -L FORWARD 2>/dev/null | grep -q "veth-wifi-a.*ACCEPT"; then
            ebtables -I FORWARD 1 -i "$VETH_BR" -j ACCEPT 2>/dev/null || true
        fi
    fi

    # Enable hairpin mode for D2D reflection
    if command -v bridge &>/dev/null; then
        bridge link set dev "$VETH_BR" hairpin on 2>/dev/null || true
        bridge link set dev "$IFACE" hairpin on 2>/dev/null || true
        log "Hairpin enabled on $IFACE and $VETH_BR for D2D"
    fi
}

# Clean up hairpin settings (for interface removal)
remove_hairpin() {
    # Clean up any ebtables rules
    if command -v ebtables &>/dev/null; then
        ebtables -D FORWARD -i "$IFACE" -o "$IFACE" -j DROP 2>/dev/null || true
        for other in wlan_24ghz wlan_5ghz wlan0 wlan1; do
            if [ "$other" != "$IFACE" ]; then
                ebtables -D FORWARD -i "$IFACE" -o "$other" -j DROP 2>/dev/null || true
            fi
        done
    fi
    log "Cleaned up ebtables rules for $IFACE"
}

if [ "$ACTION" = "add" ]; then
    # Ensure infrastructure is ready
    ensure_wifi_bridge
    ensure_veth_pair

    # Add WiFi interface to br-wifi (NOT directly to OVS)
    if ! ip link show master "$WIFI_BRIDGE" 2>/dev/null | grep -q "$IFACE"; then
        log "Adding $IFACE to bridge $WIFI_BRIDGE"
        ip link set "$IFACE" master "$WIFI_BRIDGE" 2>/dev/null || true
    fi

    ip link set "$IFACE" up 2>/dev/null || true

    # Enable hairpin for D2D traffic (ap_isolate=1 forces through bridge)
    # OVS NAC rules handle policy - internet_only blocks LAN, smart_home allows D2D
    setup_hairpin

    log "WiFi interface $IFACE configured: br-wifi (hairpin) → veth → OVS ($OVS_BRIDGE)"
    log "D2D: smart_home=allowed, internet_only=blocked by OVS NAC rules"

elif [ "$ACTION" = "remove" ]; then
    # Clean up hairpin settings
    remove_hairpin

    # Remove interface from br-wifi
    if ip link show master "$WIFI_BRIDGE" 2>/dev/null | grep -q "$IFACE"; then
        log "Removing $IFACE from bridge $WIFI_BRIDGE"
        ip link set "$IFACE" nomaster 2>/dev/null || true
    fi
fi

exit 0
HELPER_EOF

    chmod +x "$helper_script"
    log_info "  Created: $helper_script"
}

# ============================================================
# WIFI SERVICES WITH STABLE NAMES - PHASE 3
# ============================================================
create_wifi_services_stable() {
    # Create systemd services for WiFi APs using stable interface names
    # This is called AFTER hostapd configs are generated

    log_info "Phase 3: Creating WiFi services with stable names..."

    local ovs_bridge="${OVS_BRIDGE:-FTS}"

    # Generate the WiFi bridge helper script first
    generate_wifi_bridge_helper

    # Find hostapd binary - check common locations
    local hostapd_bin=""
    for path in /usr/local/bin/hostapd /usr/sbin/hostapd /usr/bin/hostapd; do
        if [ -x "$path" ]; then
            hostapd_bin="$path"
            break
        fi
    done
    if [ -z "$hostapd_bin" ]; then
        hostapd_bin=$(which hostapd 2>/dev/null || echo "/usr/sbin/hostapd")
    fi
    log_info "  Using hostapd: $hostapd_bin"

    # 2.4GHz service
    if [ -n "$WIFI_24GHZ_DETECTED" ] && [ -f /etc/hostapd/hostapd-24ghz.conf ]; then
        local dev_unit="sys-subsystem-net-devices-${WIFI_24GHZ_STABLE}.device"

        cat > /etc/systemd/system/fts-hostapd-24ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 2.4GHz WiFi Access Point
After=network.target openvswitch-switch.service ${dev_unit}
Wants=network.target ${dev_unit}
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=forking
PIDFile=/run/hostapd-24ghz.pid
ExecStartPre=/bin/bash -c 'for i in {1..30}; do [ -e /sys/class/net/${WIFI_24GHZ_STABLE} ] && break; sleep 0.5; done; [ -e /sys/class/net/${WIFI_24GHZ_STABLE} ] || exit 1'
ExecStartPre=-/bin/bash -c 'pkill -f "hostapd.*${WIFI_24GHZ_STABLE}" 2>/dev/null; rm -f /run/hostapd-24ghz.pid'
ExecStartPre=-/sbin/ip link set ${WIFI_24GHZ_STABLE} down
ExecStartPre=/bin/sleep 0.5
ExecStartPre=/sbin/ip link set ${WIFI_24GHZ_STABLE} up
ExecStart=${hostapd_bin} -B -P /run/hostapd-24ghz.pid /etc/hostapd/hostapd-24ghz.conf
ExecStartPost=/usr/local/bin/fts-wifi-bridge-helper.sh ${WIFI_24GHZ_STABLE} ${ovs_bridge} add
ExecStop=-/bin/kill -TERM \$MAINPID
ExecStopPost=-/sbin/ip link set ${WIFI_24GHZ_STABLE} down
ExecStopPost=-/usr/local/bin/fts-wifi-bridge-helper.sh ${WIFI_24GHZ_STABLE} ${ovs_bridge} remove
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable fts-hostapd-24ghz 2>/dev/null || true
        log_info "  Created: fts-hostapd-24ghz.service (uses $WIFI_24GHZ_STABLE with SDN bridge)"
    fi

    # 5GHz service
    if [ -n "$WIFI_5GHZ_DETECTED" ] && [ -f /etc/hostapd/hostapd-5ghz.conf ]; then
        local dev_unit="sys-subsystem-net-devices-${WIFI_5GHZ_STABLE}.device"

        cat > /etc/systemd/system/fts-hostapd-5ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 5GHz WiFi Access Point
After=network.target openvswitch-switch.service ${dev_unit}
Wants=network.target ${dev_unit}
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=forking
PIDFile=/run/hostapd-5ghz.pid
ExecStartPre=/bin/bash -c 'for i in {1..30}; do [ -e /sys/class/net/${WIFI_5GHZ_STABLE} ] && break; sleep 0.5; done; [ -e /sys/class/net/${WIFI_5GHZ_STABLE} ] || exit 1'
ExecStartPre=-/bin/bash -c 'pkill -f "hostapd.*${WIFI_5GHZ_STABLE}" 2>/dev/null; rm -f /run/hostapd-5ghz.pid'
ExecStartPre=-/sbin/ip link set ${WIFI_5GHZ_STABLE} down
ExecStartPre=/bin/sleep 0.5
ExecStartPre=/sbin/ip link set ${WIFI_5GHZ_STABLE} up
ExecStart=${hostapd_bin} -B -P /run/hostapd-5ghz.pid /etc/hostapd/hostapd-5ghz.conf
ExecStartPost=/usr/local/bin/fts-wifi-bridge-helper.sh ${WIFI_5GHZ_STABLE} ${ovs_bridge} add
ExecStop=-/bin/kill -TERM \$MAINPID
ExecStopPost=-/sbin/ip link set ${WIFI_5GHZ_STABLE} down
ExecStopPost=-/usr/local/bin/fts-wifi-bridge-helper.sh ${WIFI_5GHZ_STABLE} ${ovs_bridge} remove
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable fts-hostapd-5ghz 2>/dev/null || true
        log_info "  Created: fts-hostapd-5ghz.service (uses $WIFI_5GHZ_STABLE with SDN bridge)"
    fi

    log_info "Phase 3 complete: Services created with SDN Autopilot support"

    # Start hostapd services now (don't wait for reboot)
    log_info "Starting WiFi access points..."
    if [ -n "$WIFI_24GHZ_DETECTED" ] && [ -f /etc/hostapd/hostapd-24ghz.conf ]; then
        if systemctl start fts-hostapd-24ghz 2>/dev/null; then
            log_info "  2.4GHz AP started"
        else
            log_warn "  2.4GHz AP failed to start - check: journalctl -u fts-hostapd-24ghz"
        fi
    fi
    if [ -n "$WIFI_5GHZ_DETECTED" ] && [ -f /etc/hostapd/hostapd-5ghz.conf ]; then
        if systemctl start fts-hostapd-5ghz 2>/dev/null; then
            log_info "  5GHz AP started"
        else
            log_warn "  5GHz AP failed to start - check: journalctl -u fts-hostapd-5ghz"
        fi
    fi
}

setup_ovs_dhcp() {
    log_info "Configuring DHCP on OVS bridge..."

    # Use the OVS bridge directly - dnsmasq binds to the bridge interface
    local lan_port="${OVS_BRIDGE:-FTS}"
    local config_file="/etc/dnsmasq.d/fts-ovs.conf"

    # Calculate DHCP range based on subnet mask
    # CRITICAL: Default range (.100-.200) is only valid for /24 or larger!
    # For smaller subnets, we MUST calculate correct ranges.
    local dhcp_start="${LAN_DHCP_START:-}"
    local dhcp_end="${LAN_DHCP_END:-}"
    local subnet_mask="${LAN_SUBNET_MASK:-24}"

    # If DHCP range not explicitly set, calculate based on subnet size
    if [ -z "$dhcp_start" ] || [ -z "$dhcp_end" ]; then
        case "$subnet_mask" in
            29) dhcp_start="10.200.0.2"; dhcp_end="10.200.0.6" ;;      # 6 usable, reserve .1 for gateway
            28) dhcp_start="10.200.0.2"; dhcp_end="10.200.0.14" ;;     # 14 usable, reserve .1 for gateway
            27) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.30" ;;    # 30 usable, reserve .1-.9 for infra
            26) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.62" ;;    # 62 usable
            25) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.126" ;;   # 126 usable
            24) dhcp_start="10.200.0.100"; dhcp_end="10.200.0.200" ;;  # 254 usable
            *)  dhcp_start="10.200.0.100"; dhcp_end="10.200.1.200" ;;  # /23 or larger
        esac
        log_info "DHCP range calculated for /${subnet_mask}: ${dhcp_start} - ${dhcp_end}"
    fi

    mkdir -p "$(dirname "$config_file")"

    cat > "$config_file" << EOF
# HookProbe Fortress DHCP Configuration (OVS)
# Generated: $(date -Iseconds)
# LAN Subnet: 10.200.0.0/${subnet_mask}

# Bind to OVS bridge interface
interface=${lan_port}

# Use bind-dynamic instead of bind-interfaces
# This allows dnsmasq to wait for interface to appear (critical for boot order)
bind-dynamic

# Don't read /etc/resolv.conf - use our explicit servers
no-resolv
no-poll

# LAN DHCP range (configured subnet: /${subnet_mask})
dhcp-range=${dhcp_start},${dhcp_end},12h

# Gateway (fortress OVS LAN port)
dhcp-option=3,10.200.0.1

# DNS (clients query dnsmasq on gateway, which forwards to dnsXai or upstream)
dhcp-option=6,10.200.0.1

# Domain
domain=hookprobe.local
local=/hookprobe.local/

# Logging
log-dhcp
log-queries

# Cache
cache-size=1000

# DNS resolution order: try dnsXai first, then fallback to upstream
# strict-order ensures servers are tried in the order listed
strict-order

# Primary: dnsXai ML protection (localhost:53)
# Port 53 frees 5353 for mDNS/Bonjour discovery
server=127.0.0.1

# Fallback: Public DNS (used if dnsXai container is down)
server=1.1.1.1
server=8.8.8.8
EOF

    chmod 644 "$config_file"

    # Create systemd drop-in to make dnsmasq wait for OVS
    setup_dnsmasq_ovs_dependency

    # Restart dnsmasq
    systemctl restart dnsmasq 2>/dev/null || systemctl start dnsmasq 2>/dev/null || {
        log_warn "dnsmasq service not available"
    }

    log_info "DHCP configured on $lan_port"
}

# Setup DHCP for flat bridge mode - listens on FTS bridge directly
# Flat bridge: FTS bridge has gateway IP, OpenFlow handles NAC
setup_flat_bridge_dhcp() {
    log_info "Configuring DHCP for flat bridge mode..."

    # In flat bridge mode, dnsmasq listens on FTS bridge directly
    local lan_interface="${OVS_BRIDGE:-FTS}"
    local config_file="/etc/dnsmasq.d/fts-vlan.conf"

    # Use saved configuration values
    local dhcp_start="${LAN_DHCP_START:-10.200.0.100}"
    local dhcp_end="${LAN_DHCP_END:-10.200.0.200}"
    local subnet_mask="${LAN_SUBNET_MASK:-24}"
    local gateway_lan="${GATEWAY_LAN:-10.200.0.1}"

    # Recalculate DHCP range if using defaults and subnet is not /24
    if [ "$subnet_mask" != "24" ] && [ "$dhcp_start" = "10.200.0.100" ]; then
        case "$subnet_mask" in
            29) dhcp_start="10.200.0.2"; dhcp_end="10.200.0.6" ;;
            28) dhcp_start="10.200.0.2"; dhcp_end="10.200.0.14" ;;
            27) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.30" ;;
            26) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.62" ;;
            25) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.126" ;;
            *)  dhcp_start="10.200.0.100"; dhcp_end="10.200.1.200" ;;
        esac
        log_info "DHCP range recalculated for /${subnet_mask}: ${dhcp_start} - ${dhcp_end}"
    fi

    mkdir -p "$(dirname "$config_file")"

    # Remove ALL old FTS/Fortress dnsmasq configs to avoid duplicate options
    # This is critical: duplicate cache-size, interface, etc. cause dnsmasq to fail
    log_info "Cleaning up old dnsmasq configs..."
    rm -f /etc/dnsmasq.d/fts-ovs.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fts-bridge.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fts-vlans.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fts-vlan.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fts-dns-forward.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fts-mgmt-vlan.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fortress.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fortress-bridge.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fortress-vlans.conf 2>/dev/null || true

    cat > "$config_file" << EOF
# HookProbe Fortress DHCP Configuration (Flat Bridge Mode)
# Generated: $(date -Iseconds)
# LAN Subnet: 10.200.0.0/${subnet_mask}
#
# Flat Bridge Architecture:
#   FTS bridge has gateway IP directly on its internal port
#   OpenFlow rules handle NAC (Network Access Control)
#   No VLANs - all ports untagged for low-latency operation

# ============================================
# Interface binding
# ============================================
# DHCP/DNS listens on FTS bridge (LAN gateway)
# Using bind-dynamic to allow late binding to interfaces
interface=${lan_interface}
bind-dynamic
listen-address=${gateway_lan}
# Don't listen on localhost (avoids conflict with systemd-resolved)
except-interface=lo

# Don't read /etc/resolv.conf - use our explicit servers
no-resolv
no-poll

# LAN DHCP range (configured subnet: /${subnet_mask})
dhcp-range=${dhcp_start},${dhcp_end},12h

# Gateway (FTS bridge IP)
dhcp-option=3,${gateway_lan}

# DNS (clients query dnsmasq on gateway, which forwards to dnsXai or upstream)
dhcp-option=6,${gateway_lan}

# Domain
domain=hookprobe.local
local=/hookprobe.local/

# Logging
log-dhcp
log-queries

# Cache
cache-size=1000

# DHCP event script for device fingerprinting and SDN Auto Pilot
# Captures DHCP Option 55 (fingerprint) for device identification
dhcp-script=/opt/hookprobe/fortress/bin/dhcp-event.sh

# DNS resolution order: try dnsXai first, then fallback to upstream
# strict-order ensures servers are tried in the order listed
strict-order

# Primary: dnsXai ML protection (localhost:53)
# Port 53 frees 5353 for mDNS/Bonjour discovery
server=127.0.0.1

# Fallback: Public DNS (used if dnsXai container is down)
server=1.1.1.1
server=8.8.8.8
EOF

    chmod 644 "$config_file"

    # Create systemd drop-in to make dnsmasq wait for OVS bridge
    setup_dnsmasq_bridge_dependency

    # Restart dnsmasq
    systemctl restart dnsmasq 2>/dev/null || systemctl start dnsmasq 2>/dev/null || {
        log_warn "dnsmasq service not available"
    }

    log_info "DHCP configured on ${lan_interface} (flat bridge mode)"
}

# Create systemd drop-in for flat bridge mode dnsmasq
setup_dnsmasq_bridge_dependency() {
    local dropin_dir="/etc/systemd/system/dnsmasq.service.d"
    mkdir -p "$dropin_dir"

    cat > "${dropin_dir}/fortress-bridge.conf" << 'EOF'
# HookProbe Fortress - Make dnsmasq wait for FTS bridge
[Unit]
# Wait for OVS and bridge setup to be ready before starting dnsmasq
After=openvswitch-switch.service fortress-vlan.service
Wants=openvswitch-switch.service fortress-vlan.service

# Also wait for network to be online
After=network-online.target
Wants=network-online.target

[Service]
# Wait for FTS bridge to have IP address AND be stable (required for DHCP socket binding)
# 1. Wait up to 60s for FTS to get an IP
# 2. Sleep 3s after finding it to let OVS OpenFlow rules propagate
# 3. Verify interface is still ready (handles transient states)
# This fixes the race condition where dnsmasq starts before DHCP socket can bind properly
ExecStartPre=/bin/bash -c '\
    echo "dnsmasq: Waiting for FTS bridge..."; \
    for i in $(seq 1 60); do \
        if ip addr show FTS 2>/dev/null | grep -q "inet 10.200"; then \
            echo "dnsmasq: FTS bridge found, waiting for OpenFlow rules..."; \
            sleep 3; \
            if ip addr show FTS 2>/dev/null | grep -q "inet 10.200"; then \
                echo "dnsmasq: FTS bridge stable, starting DHCP"; \
                exit 0; \
            fi; \
        fi; \
        sleep 1; \
    done; \
    echo "ERROR: FTS bridge not ready after 60s"; \
    exit 1'

# ALWAYS restart dnsmasq if it stops (not just on failure)
# This ensures DHCP is always available for clients
Restart=always
RestartSec=5

# Clear default ExecStartPost/ExecStopPost that try to register with resolvconf/systemd-resolved
# This prevents "Failed to set DNS configuration" errors when systemd-resolved isn't running
ExecStartPost=
ExecStopPost=
EOF

    systemctl daemon-reload
}

# Create systemd drop-in to make dnsmasq wait for OVS bridge
setup_dnsmasq_ovs_dependency() {
    local dropin_dir="/etc/systemd/system/dnsmasq.service.d"
    mkdir -p "$dropin_dir"

    cat > "${dropin_dir}/fortress-ovs.conf" << 'EOF'
# HookProbe Fortress - Make dnsmasq wait for OVS bridge
[Unit]
# Wait for OVS to be ready before starting dnsmasq
After=openvswitch-switch.service
Wants=openvswitch-switch.service

# Also wait for network to be online
After=network-online.target
Wants=network-online.target

[Service]
# Give OVS time to create bridge interfaces
ExecStartPre=/bin/sleep 3
# Restart on failure (interface not ready yet)
Restart=on-failure
RestartSec=5
EOF

    systemctl daemon-reload 2>/dev/null || true
    log_info "dnsmasq configured to wait for OVS"
}

# NOTE: setup_mgmt_vlan_filter_mode() removed - VLAN mode handles management network via netplan

# Install network boot persistence service
# Netplan handles OVS bridge creation at boot
# The fortress-vlan service runs OVS post-setup (OpenFlow NAC rules, port config)
# Note: Named "vlan" for historical reasons, but flat bridge uses OpenFlow NAC
install_vlan_service() {
    log_info "Installing network boot persistence..."

    # Use INSTALL_DIR which is /opt/hookprobe/fortress
    # The systemd service ExecStart points to this path
    local install_base="${INSTALL_DIR}/devices/common"
    mkdir -p "$install_base"

    # Install netplan generator
    local netplan_src="${DEVICES_DIR}/common/netplan-ovs-generator.sh"
    local netplan_dst="$install_base/netplan-ovs-generator.sh"
    if [ -f "$netplan_src" ]; then
        cp "$netplan_src" "$netplan_dst"
        chmod +x "$netplan_dst"
        log_info "  Installed: netplan-ovs-generator.sh"
    fi

    # Install OVS post-setup script
    local ovs_post_src="${DEVICES_DIR}/common/ovs-post-setup.sh"
    local ovs_post_dst="$install_base/ovs-post-setup.sh"
    if [ -f "$ovs_post_src" ]; then
        cp "$ovs_post_src" "$ovs_post_dst"
        chmod +x "$ovs_post_dst"
        log_info "  Installed: ovs-post-setup.sh"
    else
        log_warn "  ovs-post-setup.sh not found at $ovs_post_src"
        return 1
    fi

    # Install NAC policy sync script (syncs device policies to OpenFlow after boot)
    local nac_sync_src="${DEVICES_DIR}/common/nac-policy-sync.sh"
    local nac_sync_dst="$install_base/nac-policy-sync.sh"
    if [ -f "$nac_sync_src" ]; then
        cp "$nac_sync_src" "$nac_sync_dst"
        chmod +x "$nac_sync_dst"
        log_info "  Installed: nac-policy-sync.sh"
    else
        log_warn "  nac-policy-sync.sh not found - NAC policies will sync via web app"
    fi

    # Install DHCP event handler for device fingerprinting (SDN Auto Pilot)
    local bin_dir="${INSTALL_DIR}/bin"
    mkdir -p "$bin_dir"
    local dhcp_event_src="${FORTRESS_ROOT}/bin/dhcp-event.sh"
    local dhcp_event_dst="$bin_dir/dhcp-event.sh"
    if [ -f "$dhcp_event_src" ]; then
        cp "$dhcp_event_src" "$dhcp_event_dst"
        chmod +x "$dhcp_event_dst"
        log_info "  Installed: dhcp-event.sh (DHCP fingerprinting)"
    else
        log_warn "  dhcp-event.sh not found - device fingerprinting disabled"
    fi

    # Install fortress-ctl CLI to /usr/local/bin
    local ctl_src="${FORTRESS_ROOT}/fortress-ctl.sh"
    local ctl_dst="/usr/local/bin/fortress-ctl"
    if [ -f "$ctl_src" ]; then
        cp "$ctl_src" "$ctl_dst"
        chmod +x "$ctl_dst"
        log_info "  Installed: fortress-ctl CLI"
    fi

    # Copy and enable systemd service
    local service_src="${FORTRESS_ROOT}/systemd/fortress-vlan.service"
    local service_dst="/etc/systemd/system/fortress-vlan.service"

    if [ -f "$service_src" ]; then
        cp "$service_src" "$service_dst"
    else
        # Create service inline if file not found
        cat > "$service_dst" << 'EOF'
[Unit]
Description=HookProbe Fortress OVS Post-Setup
Documentation=https://hookprobe.com/docs/fortress
After=network-online.target systemd-networkd.service openvswitch-switch.service
Wants=network-online.target
Requires=openvswitch-switch.service
After=fts-hostapd-24ghz.service fts-hostapd-5ghz.service
Wants=fts-hostapd-24ghz.service fts-hostapd-5ghz.service

[Service]
Type=oneshot
RemainAfterExit=yes
# Run OVS post-setup (brings up VLANs, OpenFlow rules, port VLANs, container veth)
ExecStart=/opt/hookprobe/fortress/devices/common/ovs-post-setup.sh setup
# CRITICAL: Stop then start dnsmasq after OVS flows are configured
# This ensures DHCP works - dnsmasq may have started before OpenFlow rules
# Use stop+start instead of restart - restart doesn't reinitialize DHCP sockets
# Use --no-block on start to avoid deadlock (dnsmasq has After=fortress-vlan.service)
ExecStartPost=-/bin/systemctl stop dnsmasq.service
ExecStartPost=-/bin/systemctl start --no-block dnsmasq.service

[Install]
WantedBy=multi-user.target
EOF
    fi

    # Install OVS cleanup service (runs BEFORE netplan to fix stale OVS state)
    local cleanup_src="${FORTRESS_ROOT}/systemd/fortress-ovs-cleanup.service"
    local cleanup_dst="/etc/systemd/system/fortress-ovs-cleanup.service"
    if [ -f "$cleanup_src" ]; then
        cp "$cleanup_src" "$cleanup_dst"
        log_info "  Installed: fortress-ovs-cleanup.service (pre-netplan OVS cleanup)"
    fi

    systemctl daemon-reload
    systemctl enable fortress-vlan.service 2>/dev/null || true
    systemctl enable fortress-ovs-cleanup.service 2>/dev/null || true
    log_success "VLAN services installed - OVS cleanup runs before netplan on boot"
}

# Install device status updater service and timer
# Runs on HOST to track device online/idle/offline status using OpenFlow + neighbor state
install_device_status_service() {
    log_info "Installing device status updater..."

    local install_base="${INSTALL_DIR}/devices/common"
    local data_dir="${INSTALL_DIR}/data"
    mkdir -p "$install_base" "$data_dir"

    # Install device status updater script
    local status_src="${DEVICES_DIR}/common/device-status-updater.sh"
    local status_dst="$install_base/device-status-updater.sh"
    if [ -f "$status_src" ]; then
        cp "$status_src" "$status_dst"
        chmod +x "$status_dst"
        log_info "  Installed: device-status-updater.sh"
    else
        log_warn "  device-status-updater.sh not found at $status_src"
        return 1
    fi

    # Install systemd service
    local service_src="${FORTRESS_ROOT}/systemd/fts-device-status.service"
    local service_dst="/etc/systemd/system/fts-device-status.service"
    if [ -f "$service_src" ]; then
        cp "$service_src" "$service_dst"
    else
        # Create service inline if file not found
        cat > "$service_dst" << 'EOF'
[Unit]
Description=HookProbe Fortress Device Status Updater
Documentation=https://github.com/hookprobe/hookprobe
After=network.target openvswitch-switch.service fortress.service

[Service]
Type=oneshot
ExecStart=/opt/hookprobe/fortress/devices/common/device-status-updater.sh
User=root
Group=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fts-device-status

[Install]
WantedBy=multi-user.target
EOF
    fi

    # Install systemd timer
    local timer_src="${FORTRESS_ROOT}/systemd/fts-device-status.timer"
    local timer_dst="/etc/systemd/system/fts-device-status.timer"
    if [ -f "$timer_src" ]; then
        cp "$timer_src" "$timer_dst"
    else
        # Create timer inline if file not found
        cat > "$timer_dst" << 'EOF'
[Unit]
Description=HookProbe Fortress Device Status Timer
Documentation=https://github.com/hookprobe/hookprobe

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
    fi

    systemctl daemon-reload
    systemctl enable fts-device-status.timer 2>/dev/null || true
    systemctl start fts-device-status.timer 2>/dev/null || true
    log_success "Device status updater installed (timer runs every 30s)"

    # -------------------------------------------------------------------------
    # LTE Usage Tracker (watermark-based metered data tracking)
    # Uses SQLite database for proper baseline/reset handling
    # -------------------------------------------------------------------------
    log_info "Installing LTE usage tracker..."

    # Ensure sqlite3 is available for watermark tracking
    if ! command -v sqlite3 &>/dev/null; then
        log_info "Installing sqlite3..."
        apt-get update -qq && apt-get install -y -qq sqlite3 >/dev/null 2>&1 || true
    fi

    # Deploy new watermark-based tracker (primary)
    local lte_tracker_src="${FORTRESS_ROOT}/devices/common/lte-usage-tracker.sh"
    local lte_tracker_dst="${INSTALL_DIR}/devices/common/lte-usage-tracker.sh"
    if [ -f "$lte_tracker_src" ]; then
        mkdir -p "${INSTALL_DIR}/devices/common"
        cp "$lte_tracker_src" "$lte_tracker_dst"
        chmod +x "$lte_tracker_dst"
    fi

    # Also deploy legacy collector (for compatibility)
    local lte_script_src="${FORTRESS_ROOT}/devices/common/lte-traffic-collector.sh"
    local lte_script_dst="${INSTALL_DIR}/devices/common/lte-traffic-collector.sh"
    if [ -f "$lte_script_src" ]; then
        cp "$lte_script_src" "$lte_script_dst"
        chmod +x "$lte_script_dst"
    fi

    # Deploy NAC policy sync script
    local nac_script_src="${FORTRESS_ROOT}/devices/common/nac-policy-sync.sh"
    local nac_script_dst="${INSTALL_DIR}/devices/common/nac-policy-sync.sh"
    if [ -f "$nac_script_src" ]; then
        cp "$nac_script_src" "$nac_script_dst"
        chmod +x "$nac_script_dst"
    fi

    # Create LTE usage tracker service (uses watermark method)
    cat > /etc/systemd/system/fts-lte-collector.service << 'EOF'
[Unit]
Description=Fortress LTE Usage Tracker (Watermark-based)
After=network.target
# Only run if the script exists
ConditionPathExists=/opt/hookprobe/fortress/devices/common/lte-usage-tracker.sh

[Service]
Type=oneshot
ExecStart=/opt/hookprobe/fortress/devices/common/lte-usage-tracker.sh collect
User=root
Group=root
Nice=19
IOSchedulingClass=idle
# Don't fail the boot if this fails
SuccessExitStatus=0 1
EOF

    # Create LTE collector timer (runs every 30s)
    cat > /etc/systemd/system/fts-lte-collector.timer << 'EOF'
[Unit]
Description=Fortress LTE Usage Tracker Timer
Requires=fts-lte-collector.service

[Timer]
OnBootSec=10s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable fts-lte-collector.timer 2>/dev/null || true
    systemctl start fts-lte-collector.timer 2>/dev/null || true
    log_success "LTE usage tracker installed (watermark-based, timer runs every 30s)"

    # -------------------------------------------------------------------------
    # WiFi Signal Collector (premium SDN feature)
    # Collects RSSI/signal quality from hostapd for connected WiFi clients
    # -------------------------------------------------------------------------
    log_info "Installing WiFi signal collector..."

    local wifi_script_src="${FORTRESS_ROOT}/devices/common/wifi-signal-collector.sh"
    local wifi_script_dst="${INSTALL_DIR}/devices/common/wifi-signal-collector.sh"
    if [ -f "$wifi_script_src" ]; then
        cp "$wifi_script_src" "$wifi_script_dst"
        chmod +x "$wifi_script_dst"
        log_info "  Installed: wifi-signal-collector.sh"
    else
        log_warn "  wifi-signal-collector.sh not found at $wifi_script_src"
    fi

    # Create WiFi signal collector service
    cat > /etc/systemd/system/fts-wifi-signal.service << 'EOF'
[Unit]
Description=Fortress WiFi Signal Collector
After=network.target fts-hostapd-24ghz.service fts-hostapd-5ghz.service
# Only run if the script exists
ConditionPathExists=/opt/hookprobe/fortress/devices/common/wifi-signal-collector.sh

[Service]
Type=oneshot
ExecStart=/opt/hookprobe/fortress/devices/common/wifi-signal-collector.sh
User=root
Group=root
Nice=19
IOSchedulingClass=idle
# Don't fail the boot if this fails
SuccessExitStatus=0 1

[Install]
WantedBy=multi-user.target
EOF

    # Create WiFi signal collector timer (runs every 30s)
    cat > /etc/systemd/system/fts-wifi-signal.timer << 'EOF'
[Unit]
Description=Fortress WiFi Signal Collector Timer

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable fts-wifi-signal.timer 2>/dev/null || true
    systemctl start fts-wifi-signal.timer 2>/dev/null || true
    log_success "WiFi signal collector installed (timer runs every 30s)"

    # NAC policy sync timer for real-time quarantine enforcement
    cp "$FORTRESS_ROOT/systemd/fts-nac-sync.service" /etc/systemd/system/
    cp "$FORTRESS_ROOT/systemd/fts-nac-sync.timer" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable fts-nac-sync.timer 2>/dev/null || true
    systemctl start fts-nac-sync.timer 2>/dev/null || true
    log_success "NAC policy sync timer installed (runs every 5s)"
}

# Check if container image needs rebuilding
# Returns 0 if rebuild needed, 1 if image is current
needs_rebuild() {
    local image_name="$1"
    local containerfile="$2"
    local context_dir="$3"

    # If --force-rebuild was specified, always rebuild
    if [ "${FORCE_REBUILD:-false}" = true ]; then
        return 0
    fi

    # Check if image exists
    if ! podman image exists "$image_name" 2>/dev/null; then
        return 0  # Image doesn't exist, need to build
    fi

    # Get image creation time
    local image_time
    image_time=$(podman image inspect "$image_name" --format '{{.Created}}' 2>/dev/null | head -1)
    if [ -z "$image_time" ]; then
        return 0  # Can't get image time, rebuild
    fi

    # Convert to epoch seconds
    local image_epoch
    image_epoch=$(date -d "$image_time" +%s 2>/dev/null || echo 0)

    # Check if Containerfile is newer than image
    local containerfile_time
    containerfile_time=$(stat -c %Y "$containerfile" 2>/dev/null || echo 0)
    if [ "$containerfile_time" -gt "$image_epoch" ]; then
        return 0  # Containerfile changed, rebuild
    fi

    # Check if any source file in context is newer than image
    # This catches Python code changes that the Containerfile check misses
    if [ -d "$context_dir" ]; then
        local newest_source
        newest_source=$(find "$context_dir" -type f \( -name "*.py" -o -name "*.html" -o -name "*.js" -o -name "*.css" \) -printf '%T@\n' 2>/dev/null | sort -n | tail -1 | cut -d. -f1)
        if [ -n "$newest_source" ] && [ "$newest_source" -gt "$image_epoch" ]; then
            log_info "Source files in $context_dir are newer than image, rebuilding..."
            return 0  # Source files changed, rebuild
        fi
    fi

    # Image exists and is current
    return 1
}

build_containers() {
    log_step "Building container images"

    cd "$CONTAINERS_DIR"
    # Use FORTRESS_ROOT (not SCRIPT_DIR) since sourced scripts may overwrite SCRIPT_DIR
    local repo_root="${FORTRESS_ROOT}/../.."
    local built_count=0
    local skipped_count=0

    # ============================================================
    # VERIFY network before container builds (routes are already locked)
    # ============================================================
    # Network was set up and locked in check_prerequisites().
    # Here we just verify connectivity is still working - NO route modification.
    log_info "Verifying network connectivity before container builds..."

    # Use fast check that doesn't modify routes
    if type enr_check_connectivity_fast &>/dev/null; then
        if enr_check_connectivity_fast; then
            log_info "Network connectivity verified - ready for container builds"
        else
            log_error "Network connectivity lost!"
            log_error "Cannot build containers without network connectivity"
            log_info "Current routes:"
            ip route show default 2>/dev/null | while read -r line; do
                log_info "  $line"
            done
            return 1
        fi
    else
        # Fallback: simple ping check
        if ! ping -c1 -W3 8.8.8.8 &>/dev/null && ! ping -c1 -W3 1.1.1.1 &>/dev/null; then
            log_error "No network connectivity - cannot build containers"
            return 1
        fi
        log_info "Network connectivity verified"
    fi

    # Helper: Network-resilient podman build with retry on failure
    # NOTE: Routes are locked - we only check connectivity, never modify routes
    _podman_build_resilient() {
        local containerfile="$1"
        local tag="$2"
        local context="$3"
        local max_retries=3
        local retry=0

        while [ $retry -lt $max_retries ]; do
            # Quick connectivity check (does NOT modify routes)
            if type enr_check_connectivity_fast &>/dev/null; then
                if ! enr_check_connectivity_fast; then
                    log_warn "Network connectivity issue detected, waiting 5s..."
                    sleep 5
                fi
            fi

            if podman build -f "$containerfile" -t "$tag" "$context"; then
                return 0
            fi

            retry=$((retry + 1))
            if [ $retry -lt $max_retries ]; then
                log_warn "Container build failed, retrying (attempt $((retry + 1))/$max_retries)..."
                sleep 3
            fi
        done

        return 1
    }

    # Web container - needs fortress root dir as context (contains web/ directory)
    if needs_rebuild "localhost/fts-web:latest" "Containerfile.web" "$FORTRESS_ROOT"; then
        log_info "Building web container..."
        _podman_build_resilient Containerfile.web localhost/fts-web:latest "$FORTRESS_ROOT" || {
            log_error "Failed to build web container"
            exit 1
        }
        built_count=$((built_count + 1))
    else
        log_info "Skipping web container (already built)"
        skipped_count=$((skipped_count + 1))
    fi

    # Security Core - QSecBit, dnsXai, DFS (backbone of HookProbe mesh)
    log_info "Checking security core containers..."

    if needs_rebuild "localhost/fts-agent:latest" "Containerfile.agent" "$repo_root"; then
        log_info "  - Building qsecbit-agent (threat detection)..."
        _podman_build_resilient Containerfile.agent localhost/fts-agent:latest "$repo_root" || {
            log_error "Failed to build qsecbit-agent container"
            exit 1
        }
        built_count=$((built_count + 1))
    else
        log_info "  - Skipping qsecbit-agent (already built)"
        skipped_count=$((skipped_count + 1))
    fi

    if needs_rebuild "localhost/fts-dnsxai:latest" "Containerfile.dnsxai" "$repo_root"; then
        log_info "  - Building dnsxai (DNS ML protection)..."
        _podman_build_resilient Containerfile.dnsxai localhost/fts-dnsxai:latest "$repo_root" || {
            log_error "Failed to build dnsxai container"
            exit 1
        }
        built_count=$((built_count + 1))
    else
        log_info "  - Skipping dnsxai (already built)"
        skipped_count=$((skipped_count + 1))
    fi

    if needs_rebuild "localhost/fts-dfs:latest" "Containerfile.dfs" "$repo_root"; then
        log_info "  - Building dfs-intelligence (WiFi intelligence)..."
        _podman_build_resilient Containerfile.dfs localhost/fts-dfs:latest "$repo_root" || {
            log_error "Failed to build dfs-intelligence container"
            exit 1
        }
        built_count=$((built_count + 1))
    else
        log_info "  - Skipping dfs-intelligence (already built)"
        skipped_count=$((skipped_count + 1))
    fi

    # NOTE: bubble-manager is now part of AIOCHI stack - skip building in Fortress
    # AIOCHI will build aiochi-bubble using shared/aiochi/bubble code
    log_info "  - Skipping bubble-manager (moved to AIOCHI stack)"
    skipped_count=$((skipped_count + 1))

    # LSTM trainer is optional (used for retraining models)
    if needs_rebuild "localhost/fts-lstm:latest" "Containerfile.lstm" "$repo_root"; then
        log_info "  - Building lstm-trainer (optional training)..."
        _podman_build_resilient Containerfile.lstm localhost/fts-lstm:latest "$repo_root" || {
            log_warn "Failed to build lstm container (training will be unavailable)"
        }
        built_count=$((built_count + 1))
    else
        log_info "  - Skipping lstm-trainer (already built)"
        skipped_count=$((skipped_count + 1))
    fi

    # XDP/eBPF protection is optional (for IDS profile)
    if needs_rebuild "localhost/fts-xdp:latest" "Containerfile.xdp" "$repo_root"; then
        log_info "  - Building xdp-protection (IDS tier)..."
        _podman_build_resilient Containerfile.xdp localhost/fts-xdp:latest "$repo_root" || {
            log_warn "Failed to build xdp container (IDS tier will be unavailable)"
        }
        built_count=$((built_count + 1))
    else
        log_info "  - Skipping xdp-protection (already built)"
        skipped_count=$((skipped_count + 1))
    fi

    if [ "$built_count" -gt 0 ]; then
        log_info "Built $built_count container(s), skipped $skipped_count"
    else
        log_info "All containers already built (use --force-rebuild to rebuild)"
    fi
}

# ============================================================
# STOP ALL SERVICES (for upgrade/uninstall)
# ============================================================
# Comprehensive stop function that halts everything safely
stop_all_services() {
    log_step "Stopping all Fortress services"

    local compose_dir="${INSTALL_DIR}/containers"

    # 1. Stop systemd services first (graceful)
    log_info "Stopping systemd services..."
    systemctl stop fortress 2>/dev/null || true
    systemctl stop fortress-hostapd-2ghz 2>/dev/null || true
    systemctl stop fortress-hostapd-5ghz 2>/dev/null || true
    systemctl stop fortress-dnsmasq 2>/dev/null || true
    systemctl stop fts-web 2>/dev/null || true
    systemctl stop fts-agent 2>/dev/null || true
    systemctl stop fts-qsecbit 2>/dev/null || true
    systemctl stop fts-suricata 2>/dev/null || true
    systemctl stop fts-zeek 2>/dev/null || true
    systemctl stop fts-xdp 2>/dev/null || true

    # 2. Stop podman-compose (graceful container shutdown)
    log_info "Stopping podman containers (graceful)..."
    if [ -f "$compose_dir/podman-compose.yml" ]; then
        cd "$compose_dir" 2>/dev/null && {
            podman-compose down --timeout 30 2>/dev/null || true
        }
    fi

    # 3. Force-stop any remaining containers (brute force)
    log_info "Force-stopping remaining containers..."
    for container in $(podman ps --format "{{.Names}}" 2>/dev/null | grep -E "^fts-" || true); do
        log_info "  Force stopping: $container"
        podman stop -t 5 "$container" 2>/dev/null || true
    done

    # 4. Kill any containers that didn't respond to stop
    for container in $(podman ps --format "{{.Names}}" 2>/dev/null | grep -E "^fts-" || true); do
        log_warn "  Killing unresponsive: $container"
        podman kill "$container" 2>/dev/null || true
    done

    # 5. Stop hostapd processes (in case systemd didn't catch them)
    log_info "Stopping hostapd processes..."
    pkill -f "hostapd.*fortress" 2>/dev/null || true
    pkill -f "hostapd.*fts" 2>/dev/null || true

    # 6. Stop dnsmasq fortress instances
    log_info "Stopping dnsmasq instances..."
    pkill -f "dnsmasq.*fortress" 2>/dev/null || true
    pkill -f "dnsmasq.*fts" 2>/dev/null || true

    # 7. Stop OVS flows if present
    log_info "Clearing OVS configuration..."
    ovs-ofctl del-flows FTS 2>/dev/null || true
    ovs-vsctl del-br FTS 2>/dev/null || true

    # 8. Bring down fortress bridge interface
    log_info "Bringing down network interfaces..."
    ip link set fortress down 2>/dev/null || true
    ip link delete fortress 2>/dev/null || true

    # 9. Clear any iptables rules we added
    log_info "Clearing firewall rules..."
    iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -j MASQUERADE 2>/dev/null || true
    nft delete table inet fortress_filter 2>/dev/null || true

    # 10. Release any locked resources
    log_info "Releasing resources..."
    fuser -k 8443/tcp 2>/dev/null || true  # Web port
    fuser -k 53/udp 2>/dev/null || true    # dnsXai DNS port (NOT 5353 - that's mDNS)
    fuser -k 8050/tcp 2>/dev/null || true  # DFS port

    log_info "All services stopped"
}

start_containers() {
    log_step "Starting containers"

    # Use the INSTALLED containers directory
    local compose_dir="${INSTALL_DIR}/containers"
    cd "$compose_dir"

    # Export WEB_PORT for podman-compose (web container uses host network with GUNICORN_BIND)
    export WEB_PORT="${WEB_PORT:-8443}"

    # ========================================
    # CLEANUP: Remove existing containers before starting fresh
    # This prevents "container name already in use" errors
    # ========================================
    log_info "Cleaning up any existing containers..."

    # First try graceful podman-compose down
    if [ -f "podman-compose.yml" ]; then
        podman-compose down --timeout 10 2>/dev/null || true
    fi

    # Force-remove any remaining fts-* containers (in case compose didn't manage them)
    for container in $(podman ps -a --format "{{.Names}}" 2>/dev/null | grep -E "^fts-" || true); do
        log_info "  Removing existing container: $container"
        podman stop -t 5 "$container" 2>/dev/null || true
        podman rm -f "$container" 2>/dev/null || true
    done

    # Remove stale networks (recreated fresh by compose)
    for network in $(podman network ls --format "{{.Name}}" 2>/dev/null | grep -E "^fts-" || true); do
        log_info "  Removing existing network: $network"
        podman network rm -f "$network" 2>/dev/null || true
    done

    # ========================================
    # PORT CONFLICT RESOLUTION
    # ========================================
    # dnsXai uses 127.0.0.1:53/udp (DNS) and 0.0.0.0:853/tcp (DoT)
    # Port 5353 is FREE for mDNS (Avahi + bubble manager ecosystem detection)
    # dnsmasq forwards DNS queries to dnsXai at localhost:53
    log_info "Configuring mDNS and DNS coexistence..."

    # Configure Avahi to allow other stacks (needed for bubble manager mDNS)
    # This allows bubble manager's zeroconf to use mDNS multicast on port 5353
    if [ -f /etc/avahi/avahi-daemon.conf ]; then
        if ! grep -q "disallow-other-stacks=no" /etc/avahi/avahi-daemon.conf 2>/dev/null; then
            log_info "  Configuring avahi to allow stack sharing..."
            cp /etc/avahi/avahi-daemon.conf /etc/avahi/avahi-daemon.conf.bak.fts 2>/dev/null || true
            if grep -q "disallow-other-stacks" /etc/avahi/avahi-daemon.conf 2>/dev/null; then
                sed -i 's/disallow-other-stacks=.*/disallow-other-stacks=no/' /etc/avahi/avahi-daemon.conf
            else
                sed -i '/^\[server\]/a disallow-other-stacks=no' /etc/avahi/avahi-daemon.conf
            fi
            systemctl restart avahi-daemon 2>/dev/null || true
        else
            log_info "  Avahi already configured for stack sharing"
        fi
    fi

    # Disable systemd-resolved mDNS if it's using 5353 (let Avahi/bubble manager use it)
    if ss -tulpn 2>/dev/null | grep -q ":5353.*systemd-resolve"; then
        log_info "  Disabling systemd-resolved mDNS (Avahi will handle it)..."
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/no-mdns.conf << 'MDNSCONF'
[Resolve]
# Disable mDNS in systemd-resolved to avoid port conflicts
# mDNS is handled by avahi-daemon and bubble manager for ecosystem detection
MulticastDNS=no
MDNSCONF
        systemctl restart systemd-resolved 2>/dev/null || true
    fi

    # Release DoT port for dnsXai
    fuser -k 853/tcp 2>/dev/null || true

    # Check if dnsXai port 53 is available (not 5353 - that's for mDNS now)
    if ss -tulpn 2>/dev/null | grep -qE ":53\s.*(systemd-resolve|dnsmasq)"; then
        log_info "  Port 53 in use by resolver - dnsXai will bind to localhost:53"
    fi

    # Verify mDNS port 5353 is available for bubble manager
    if ss -tulpn 2>/dev/null | grep -qE ":5353.*(systemd-resolve)"; then
        log_warn "Port 5353 in use by systemd-resolved - mDNS may not work"
        ss -tulpn 2>/dev/null | grep ":5353 " | head -3
    else
        log_info "  Port 5353 available for mDNS (ecosystem detection)"
    fi

    # ========================================
    # START: Launch containers
    # ========================================
    # Start all services (security core + data tier)
    # NOTE: --no-build is required because podman-compose 1.0.6 has broken
    # context path resolution. Images are already built in build_containers().
    log_info "Starting Fortress services..."
    log_info "Web UI will be available on port ${WEB_PORT}"

    # ========================================
    # SMART SERVICE STARTUP (avoid start-then-stop waste)
    # ========================================
    # podman-compose 1.x doesn't support --profile flag. Instead of starting
    # ALL containers then stopping the ones AIOCHI replaces, we specify exactly
    # which services to start.
    #
    # Core services (always started):
    #   - postgres, redis (data tier)
    #   - web, qsecbit-agent, bubble-manager (application tier)
    #   - dnsxai, dfs-intelligence (services tier)
    #   - cloudflared (if tunnel configured)
    #
    # OPTIONAL services (NOT started by default - use profiles manually):
    #   - grafana, victoria (monitoring) - use: --profile monitoring
    #   - n8n (automation) - use: --profile automation
    #   - clickhouse (analytics) - use: --profile analytics
    #   - suricata, zeek, xdp-protection (IDS) - use: --profile ids
    #   - lstm-trainer (ML training) - use: --profile training
    #
    # IMPORTANT: We ALWAYS specify explicit service names because podman-compose
    # 1.x ignores profiles and would start ALL services otherwise.

    # Service names must match podman-compose.yml (no fts- prefix in compose file)
    # NOTE: bubble-manager is NOW part of AIOCHI stack (requires Zeek for mDNS detection)
    # This removes host network dependency that was blocking port forwarding
    local core_services="postgres redis web qsecbit-agent dnsxai dfs-intelligence"

    # Add cloudflared if tunnel token is configured
    if [ -n "${CLOUDFLARE_TOKEN:-}" ]; then
        core_services="$core_services cloudflared"
    fi

    if [ "${INSTALL_AIOCHI:-}" = true ]; then
        # AIOCHI mode: bubble detection is handled by AIOCHI stack (aiochi-bubble)
        log_info "AIOCHI mode - core services + AIOCHI provides bubble detection..."
    else
        # Standard mode: no bubble detection (requires AIOCHI for ecosystem grouping)
        log_info "Standard mode - starting core services (bubble detection requires --enable-aiochi)..."
    fi

    # Always use explicit service list (podman-compose 1.x doesn't support profiles)
    # shellcheck disable=SC2086
    podman-compose up -d --no-build $core_services

    # Wait for services in dependency order
    log_info "Waiting for services to be ready..."

    # Phase 1: Wait for data tier (postgres, redis) - no dependencies
    log_info "  Waiting for data tier (postgres, redis)..."
    wait_for_container_healthy "fts-postgres" 60 || log_warn "postgres may not be healthy"
    wait_for_container_healthy "fts-redis" 30 || log_warn "redis may not be healthy"

    # Phase 2: Wait for independent services (dnsxai, dfs) - no dependencies
    log_info "  Waiting for services tier (dnsxai, dfs)..."
    wait_for_container_running "fts-dnsxai" 30 || log_warn "dnsxai may not be running"
    wait_for_container_running "fts-dfs" 30 || log_warn "dfs may not be running"

    # Phase 3: Wait for dependent services (web, qsecbit) - depend on postgres/redis
    log_info "  Waiting for application tier (web, qsecbit)..."
    wait_for_container_running "fts-web" 30 || log_warn "web may not be running"
    wait_for_container_running "fts-qsecbit" 30 || log_warn "qsecbit may not be running"

    # Final check: web health endpoint
    local retries=15
    while [ $retries -gt 0 ]; do
        if curl -sf -k "https://localhost:${WEB_PORT}/health" &>/dev/null; then
            log_info "All services are ready"
            break
        fi
        sleep 2
        ((retries--))
    done

    if [ $retries -eq 0 ]; then
        log_warn "Web health check failed - check logs: podman logs fts-web"
    fi

    # Connect containers to OVS for flow monitoring
    connect_containers_to_ovs

    # Setup traffic flow rules (NAT, PBR integration)
    setup_traffic_flow

    # ========================================
    # CLEANUP REDUNDANT DNSMASQ CONFIG
    # ========================================
    # fts-vlan.conf already has all DNS settings, remove any duplicate
    if [ -f "/etc/dnsmasq.d/fts-vlan.conf" ] && grep -q "^server=" /etc/dnsmasq.d/fts-vlan.conf 2>/dev/null; then
        if [ -f "/etc/dnsmasq.d/fts-dns-forward.conf" ]; then
            rm -f /etc/dnsmasq.d/fts-dns-forward.conf
            log_info "Removed redundant fts-dns-forward.conf"
        fi
    fi

    # Ensure dnsmasq is running
    if ! systemctl is-active dnsmasq &>/dev/null; then
        systemctl restart dnsmasq 2>/dev/null || log_warn "dnsmasq failed to start"
    fi

    # ========================================
    # START OPTIONAL SERVICES
    # ========================================
    # Since podman-compose 1.x doesn't support --profile, we start
    # optional services separately using direct podman commands

    start_optional_services
}

start_optional_services() {
    log_step "Starting optional services"

    local compose_dir="${INSTALL_DIR}/containers"
    cd "$compose_dir"

    # Load environment for container configs
    [ -f ".env" ] && source .env 2>/dev/null || true

    # If AIOCHI is enabled, skip individual fts-* services (they're bundled in AIOCHI)
    # AIOCHI provides its own aiochi-* containers for all monitoring/analytics
    if [ "${INSTALL_AIOCHI:-}" = true ]; then
        log_info "AIOCHI enabled - skipping individual fts-* services (bundled in AIOCHI)"
    fi

    # Monitoring (Grafana + VictoriaMetrics) - ONLY if NOT using AIOCHI
    if [ "${INSTALL_MONITORING:-}" = true ] && [ "${INSTALL_AIOCHI:-}" != true ]; then
        log_info "Starting monitoring services (Grafana + VictoriaMetrics)..."

        # VictoriaMetrics
        podman run -d --name fts-victoria \
            --restart unless-stopped \
            --network fts-internal \
            --ip 172.20.200.31 \
            -p 0.0.0.0:8428:8428 \
            -v fts-victoria-data:/storage \
            docker.io/victoriametrics/victoria-metrics:v1.106.1 \
            -storageDataPath=/storage -retentionPeriod=30d -httpListenAddr=:8428 \
            2>/dev/null || log_warn "VictoriaMetrics may already be running"

        # Grafana
        podman run -d --name fts-grafana \
            --restart unless-stopped \
            --network fts-internal \
            --ip 172.20.200.30 \
            -p 0.0.0.0:3000:3000 \
            -v fts-grafana-data:/var/lib/grafana \
            -e GF_SECURITY_ADMIN_PASSWORD="${GRAFANA_PASSWORD:-fortress_grafana_admin}" \
            docker.io/grafana/grafana:11.4.0 \
            2>/dev/null || log_warn "Grafana may already be running"

        log_info "Monitoring services started (Grafana: http://localhost:3000)"
    fi

    # n8n Workflow Automation - ONLY if NOT using AIOCHI
    if [ "${INSTALL_N8N:-}" = true ] && [ "${INSTALL_AIOCHI:-}" != true ]; then
        log_info "Starting n8n workflow automation..."

        podman run -d --name fts-n8n \
            --restart unless-stopped \
            --network fts-internal \
            --ip 172.20.200.50 \
            -p 0.0.0.0:5678:5678 \
            -v fts-n8n-data:/home/node/.n8n \
            -v /etc/hookprobe:/etc/hookprobe:ro \
            -e N8N_HOST=0.0.0.0 \
            -e N8N_PORT=5678 \
            -e N8N_PROTOCOL=http \
            -e DB_TYPE=postgresdb \
            -e DB_POSTGRESDB_HOST=172.20.200.10 \
            -e DB_POSTGRESDB_PORT=5432 \
            -e DB_POSTGRESDB_DATABASE=fortress \
            -e DB_POSTGRESDB_USER=fortress \
            -e DB_POSTGRESDB_PASSWORD="${POSTGRES_PASSWORD:-fortress_db_secret}" \
            -e DB_POSTGRESDB_SCHEMA=n8n \
            -e N8N_BASIC_AUTH_ACTIVE=true \
            -e N8N_BASIC_AUTH_USER="${N8N_USER:-admin}" \
            -e N8N_BASIC_AUTH_PASSWORD="${N8N_PASSWORD:-fortress_n8n_admin}" \
            docker.io/n8nio/n8n:latest \
            2>/dev/null || log_warn "n8n may already be running"

        log_info "n8n started (http://localhost:5678)"
    fi

    # ClickHouse Analytics - ONLY if NOT using AIOCHI
    if [ "${INSTALL_CLICKHOUSE:-}" = true ] && [ "${INSTALL_AIOCHI:-}" != true ]; then
        log_info "Starting ClickHouse analytics database..."

        podman run -d --name fts-clickhouse \
            --restart unless-stopped \
            --network fts-internal \
            --ip 172.20.200.51 \
            -p 0.0.0.0:8123:8123 \
            -p 0.0.0.0:9000:9000 \
            -v fts-clickhouse-data:/var/lib/clickhouse \
            -v fts-clickhouse-logs:/var/log/clickhouse-server \
            -e CLICKHOUSE_DB=fortress \
            -e CLICKHOUSE_USER=fortress \
            -e CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-fortress_clickhouse_secret}" \
            docker.io/clickhouse/clickhouse-server:latest \
            2>/dev/null || log_warn "ClickHouse may already be running"

        log_info "ClickHouse started (HTTP: localhost:8123, Native: localhost:9000)"
    fi

    # IDS/IPS (Suricata + Zeek + XDP) - ONLY if NOT using AIOCHI
    if [ "${INSTALL_IDS:-}" = true ] && [ "${INSTALL_AIOCHI:-}" != true ]; then
        log_info "Starting IDS/IPS services..."

        # Suricata
        podman run -d --name fts-suricata \
            --restart unless-stopped \
            --network host \
            --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_NICE \
            -v fts-suricata-logs:/var/log/suricata \
            -v fts-suricata-rules:/var/lib/suricata \
            -v fts-suricata-config:/etc/suricata \
            -e SURICATA_INTERFACE="${SURICATA_INTERFACE:-FTS}" \
            docker.io/jasonish/suricata:latest \
            2>/dev/null || log_warn "Suricata may already be running"

        # Zeek
        podman run -d --name fts-zeek \
            --restart unless-stopped \
            --network host \
            --cap-add NET_ADMIN --cap-add NET_RAW \
            -v fts-zeek-logs:/usr/local/zeek/logs \
            -v fts-zeek-spool:/usr/local/zeek/spool \
            docker.io/zeek/zeek:latest \
            zeek -i "${ZEEK_INTERFACE:-FTS}" local LogAscii::use_json=T \
            2>/dev/null || log_warn "Zeek may already be running"

        log_info "IDS/IPS services started (Suricata + Zeek)"
    fi

    # Cloudflare Tunnel
    if [ "${INSTALL_CLOUDFLARE_TUNNEL:-}" = true ] && [ -n "${CLOUDFLARE_TOKEN:-}" ]; then
        log_info "Starting Cloudflare Tunnel..."

        podman run -d --name fts-cloudflared \
            --restart unless-stopped \
            --network fts-internal \
            --ip 172.20.200.60 \
            docker.io/cloudflare/cloudflared:latest \
            tunnel --no-autoupdate run --token "$CLOUDFLARE_TOKEN" \
            2>/dev/null || log_warn "Cloudflared may already be running"

        if [ -n "${CLOUDFLARE_HOSTNAME:-}" ]; then
            log_info "Cloudflare Tunnel started (https://${CLOUDFLARE_HOSTNAME})"
        else
            log_info "Cloudflare Tunnel started"
        fi
    fi

    # ============================================================
    # AIOCHI - AI Eyes (Cognitive Network Layer)
    # ============================================================
    # AIOCHI provides:
    #   - ClickHouse: Event storage and analytics
    #   - VictoriaMetrics: Time-series metrics
    #   - Suricata + Zeek: Network traffic capture
    #   - Identity Engine: Device fingerprinting and labeling
    #   - Narrative Engine (n8n): Human-readable event stories
    #   - Grafana: Visual dashboards
    #   - Log Shipper: Event pipeline
    #
    if [ "${INSTALL_AIOCHI:-}" = true ]; then
        log_info "Starting AIOCHI (AI Eyes) - Cognitive Network Layer..."

        local aiochi_compose="/opt/hookprobe/shared/aiochi/containers/podman-compose.aiochi.yml"
        local aiochi_dir="/opt/hookprobe/shared/aiochi/containers"

        if [ -f "$aiochi_compose" ]; then
            # Create AIOCHI environment file
            cat > "${aiochi_dir}/.env" << AIOCHIENV
# AIOCHI Environment Configuration
# Generated: $(date -Iseconds)

# ClickHouse credentials (analytics database)
CLICKHOUSE_PASSWORD=${CLICKHOUSE_PASSWORD:-aiochi_secure_password}

# Grafana credentials
GRAFANA_USER=admin
GRAFANA_PASSWORD=${GRAFANA_PASSWORD:-fortress_grafana_admin}
GRAFANA_PORT=3000

# n8n credentials (narrative engine)
N8N_USER=admin
N8N_PASSWORD=${N8N_PASSWORD:-fortress_n8n_admin}

# Capture interface (OVS mirror port - NOT the main bridge!)
# FTS-mirror receives a copy of all traffic without impacting OVS datapath
CAPTURE_INTERFACE=FTS-mirror

# Log level
LOG_LEVEL=INFO

# Timezone
TZ=${TZ:-UTC}
AIOCHIENV
            chmod 600 "${aiochi_dir}/.env"

            # Build AIOCHI containers (identity-engine, log-shipper)
            # Build from parent directory (shared/aiochi/) to access backend/ folder
            log_info "  Building AIOCHI containers..."
            local aiochi_parent="/opt/hookprobe/shared/aiochi"
            local aiochi_containers="${aiochi_parent}/containers"

            # Track which images were built successfully (default: false)
            AIOCHI_IDENTITY_BUILT=false
            AIOCHI_LOGSHIPPER_BUILT=false

            # Verify required files exist before building
            log_info "    Verifying AIOCHI build context..."
            if [ ! -d "${aiochi_parent}/backend" ]; then
                log_warn "    backend/ directory missing - AIOCHI custom containers will not be built"
            elif [ ! -f "${aiochi_parent}/backend/__init__.py" ]; then
                log_warn "    backend/__init__.py missing - AIOCHI custom containers will not be built"
            else
                # Build custom containers with proper error handling
                # Use absolute paths and match proven syntax: podman build -f FILE -t TAG CONTEXT
                local containerfile_identity="${aiochi_containers}/Containerfile.identity"
                local containerfile_logshipper="${aiochi_containers}/Containerfile.logshipper"

                if [ -f "$containerfile_identity" ]; then
                    log_info "    Building identity-engine..."
                    # Verify Containerfile has valid FROM statement
                    if head -20 "$containerfile_identity" | grep -q "^FROM "; then
                        # Build with explicit format and absolute paths
                        if podman build --format docker \
                            -f "$containerfile_identity" \
                            -t localhost/aiochi-identity:latest \
                            "$aiochi_parent" 2>&1; then
                            log_info "    ✓ identity-engine built successfully"
                            AIOCHI_IDENTITY_BUILT=true
                        else
                            log_warn "    ✗ Failed to build identity-engine (container will be skipped)"
                        fi
                    else
                        log_warn "    ✗ Containerfile.identity appears invalid (no FROM statement)"
                    fi
                fi

                if [ -f "$containerfile_logshipper" ]; then
                    log_info "    Building log-shipper..."
                    if head -20 "$containerfile_logshipper" | grep -q "^FROM "; then
                        # Build with explicit format and absolute paths
                        if podman build --format docker \
                            -f "$containerfile_logshipper" \
                            -t localhost/aiochi-logshipper:latest \
                            "$aiochi_parent" 2>&1; then
                            log_info "    ✓ log-shipper built successfully"
                            AIOCHI_LOGSHIPPER_BUILT=true
                        else
                            log_warn "    ✗ Failed to build log-shipper (container will be skipped)"
                        fi
                    else
                        log_warn "    ✗ Containerfile.logshipper appears invalid (no FROM statement)"
                    fi
                fi
            fi

            # ============================================================
            # PULL AIOCHI CONTAINER IMAGES (with progress visibility)
            # ============================================================
            # Total download: ~3-4GB for all images
            # Ollama + LLM model is the largest (~2GB)
            log_info "  Pulling AIOCHI container images..."
            log_info "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_info "  Total download: ~3-4GB (depending on cached images)"
            log_info "  This may take 5-15 minutes on first install..."
            log_info "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""

            # Helper function to pull with progress
            pull_with_progress() {
                local image="$1"
                local name="$2"
                local size="$3"
                echo -n "    [PULL] ${name} (${size})... "
                if podman pull "$image" >/dev/null 2>&1; then
                    echo "✓"
                    return 0
                else
                    echo "✗ (will retry later)"
                    return 1
                fi
            }

            # Pull images with size estimates
            pull_with_progress "docker.io/clickhouse/clickhouse-server:24.8" "ClickHouse" "~500MB"
            pull_with_progress "docker.io/victoriametrics/victoria-metrics:v1.106.1" "VictoriaMetrics" "~30MB"
            pull_with_progress "docker.io/jasonish/suricata:7.0.8" "Suricata IDS" "~300MB"
            pull_with_progress "docker.io/zeek/zeek:7.0.3" "Zeek NSM" "~400MB"
            pull_with_progress "docker.io/n8nio/n8n:1.70.3" "n8n Workflows" "~400MB"
            pull_with_progress "docker.io/grafana/grafana:11.4.0" "Grafana" "~400MB"

            # Ollama is special - it's the LLM runtime
            log_info ""
            log_info "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_info "  OLLAMA LOCAL LLM (~2GB download)"
            log_info "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_info "  Ollama provides local AI reasoning for security narratives."
            log_info "  The llama3.2:3b model will be downloaded on first start."
            log_info "  This is a ~2GB download and may take 5-10 minutes."
            log_info ""
            echo -n "    [PULL] Ollama runtime (~500MB)... "
            if podman pull docker.io/ollama/ollama:latest >/dev/null 2>&1; then
                echo "✓"
            else
                echo "✗ (AIOCHI will start without LLM)"
                log_warn "Ollama pull failed - AI narratives will use template fallback"
            fi

            echo ""
            log_info "  Image pulls complete. Starting containers..."
            echo ""

            # ============================================================
            # START AIOCHI CONTAINERS
            # ============================================================
            # We start containers individually for better progress visibility
            # and to handle Ollama's async model download gracefully
            log_info "  Starting AIOCHI containers..."
            log_info "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""

            # Helper function for container start with status
            # NOTE: Returns 0 even on failure - AIOCHI is optional, failures shouldn't abort install
            AIOCHI_FAILED_CONTAINERS=""
            start_aiochi_container() {
                local name="$1"
                local desc="$2"
                shift 2
                echo -n "    [START] ${desc}... "
                if podman run -d "$@" >/dev/null 2>&1; then
                    echo "✓"
                    return 0
                elif podman ps -a --format "{{.Names}}" | grep -q "^${name}$"; then
                    echo "○ (already exists)"
                    return 0
                else
                    echo "✗"
                    AIOCHI_FAILED_CONTAINERS="${AIOCHI_FAILED_CONTAINERS} ${name}"
                    # Don't return 1 - AIOCHI is optional, continue installation
                    return 0
                fi
            }

            # Create AIOCHI network
            podman network create --subnet 172.20.210.0/24 --gateway 172.20.210.1 aiochi-internal 2>/dev/null || true

            # 1. Data Tier
            start_aiochi_container "aiochi-clickhouse" "ClickHouse (analytics)" \
                --name aiochi-clickhouse \
                --restart unless-stopped \
                --network aiochi-internal \
                --ip 172.20.210.10 \
                -p 127.0.0.1:8123:8123 \
                -p 127.0.0.1:9000:9000 \
                -v aiochi-clickhouse-data:/var/lib/clickhouse \
                -v aiochi-clickhouse-logs:/var/log/clickhouse-server \
                -e CLICKHOUSE_DB=aiochi \
                -e CLICKHOUSE_USER=aiochi \
                -e CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-aiochi_secure_password}" \
                docker.io/clickhouse/clickhouse-server:24.8

            start_aiochi_container "aiochi-victoria" "VictoriaMetrics (time-series)" \
                --name aiochi-victoria \
                --restart unless-stopped \
                --network aiochi-internal \
                --ip 172.20.210.11 \
                -p 127.0.0.1:8428:8428 \
                -v aiochi-victoria-data:/victoria-metrics-data \
                docker.io/victoriametrics/victoria-metrics:v1.106.1 \
                --retentionPeriod=30d --httpListenAddr=:8428 --storageDataPath=/victoria-metrics-data

            # 2. Capture Tier
            # IMPORTANT: Capture from FTS-mirror (OVS mirror port), NOT FTS directly!
            # Direct AF_PACKET capture on OVS bridge causes packet loss and CPU starvation.
            # See: devices/common/ovs-post-setup.sh (setup_traffic_mirror function)
            start_aiochi_container "aiochi-suricata" "Suricata IDS (host network)" \
                --name aiochi-suricata \
                --restart unless-stopped \
                --network host \
                --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_NICE \
                -v aiochi-suricata-logs:/var/log/suricata \
                docker.io/jasonish/suricata:7.0.8 \
                -i FTS-mirror --af-packet

            start_aiochi_container "aiochi-zeek" "Zeek NSM (host network)" \
                --name aiochi-zeek \
                --restart unless-stopped \
                --network host \
                --cap-add NET_ADMIN --cap-add NET_RAW \
                -v aiochi-zeek-logs:/opt/zeek/logs \
                docker.io/zeek/zeek:7.0.3 \
                zeek -i FTS-mirror local LogAscii::use_json=T

            # 3. Visualization Tier
            start_aiochi_container "aiochi-grafana" "Grafana (dashboards)" \
                --name aiochi-grafana \
                --restart unless-stopped \
                --network aiochi-internal \
                --ip 172.20.210.30 \
                -p 0.0.0.0:3000:3000 \
                -v aiochi-grafana-data:/var/lib/grafana \
                -e GF_SECURITY_ADMIN_USER=admin \
                -e GF_SECURITY_ADMIN_PASSWORD="${GRAFANA_PASSWORD:-fortress_grafana_admin}" \
                -e GF_USERS_DEFAULT_THEME=dark \
                docker.io/grafana/grafana:11.4.0

            # 4. Intelligence Tier - n8n Narratives
            start_aiochi_container "aiochi-narrative" "n8n Workflows (narratives)" \
                --name aiochi-narrative \
                --restart unless-stopped \
                --network aiochi-internal \
                --ip 172.20.210.21 \
                -p 127.0.0.1:5678:5678 \
                -v aiochi-n8n-data:/home/node/.n8n \
                -e N8N_BASIC_AUTH_ACTIVE=true \
                -e N8N_BASIC_AUTH_USER=admin \
                -e N8N_BASIC_AUTH_PASSWORD="${N8N_PASSWORD:-fortress_n8n_admin}" \
                -e N8N_HOST=0.0.0.0 \
                -e N8N_PORT=5678 \
                docker.io/n8nio/n8n:1.70.3

            # 5. Identity Engine (CRITICAL for fts-web integration)
            # Only start if the image was built successfully
            if [ "${AIOCHI_IDENTITY_BUILT:-false}" = "true" ]; then
                start_aiochi_container "aiochi-identity" "Identity Engine" \
                    --name aiochi-identity \
                    --restart unless-stopped \
                    --network aiochi-internal \
                    --ip 172.20.210.20 \
                    -p 127.0.0.1:8060:8060 \
                    -v aiochi-identity-data:/app/data \
                    -v /var/lib/misc:/var/lib/misc:ro \
                    -v /run/avahi-daemon:/run/avahi-daemon:ro \
                    -e CLICKHOUSE_HOST=172.20.210.10 \
                    -e CLICKHOUSE_PORT=8123 \
                    -e CLICKHOUSE_DB=aiochi \
                    -e CLICKHOUSE_USER=aiochi \
                    -e CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-aiochi_secure_password}" \
                    -e LOG_LEVEL="${LOG_LEVEL:-INFO}" \
                    localhost/aiochi-identity:latest
            else
                echo "    [SKIP] Identity Engine (image build failed)"
                AIOCHI_FAILED_CONTAINERS="${AIOCHI_FAILED_CONTAINERS} aiochi-identity(build-failed)"
            fi

            # 6. Log Shipper (ships Suricata/Zeek logs to ClickHouse)
            # Only start if the image was built successfully
            if [ "${AIOCHI_LOGSHIPPER_BUILT:-false}" = "true" ]; then
                start_aiochi_container "aiochi-logshipper" "Log Shipper" \
                    --name aiochi-logshipper \
                    --restart unless-stopped \
                    --network aiochi-internal \
                    --ip 172.20.210.40 \
                    -v aiochi-suricata-logs:/var/log/suricata:ro \
                    -v aiochi-zeek-logs:/opt/zeek/logs:ro \
                    -e CLICKHOUSE_HOST=172.20.210.10 \
                    -e CLICKHOUSE_PORT=8123 \
                    -e CLICKHOUSE_DB=aiochi \
                    -e CLICKHOUSE_USER=aiochi \
                    -e CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-aiochi_secure_password}" \
                    -e SURICATA_LOG_PATH=/var/log/suricata/eve.json \
                    -e ZEEK_LOG_PATH=/opt/zeek/logs/current \
                    -e LOG_LEVEL="${LOG_LEVEL:-INFO}" \
                    localhost/aiochi-logshipper:latest
            else
                echo "    [SKIP] Log Shipper (image build failed)"
                AIOCHI_FAILED_CONTAINERS="${AIOCHI_FAILED_CONTAINERS} aiochi-logshipper(build-failed)"
            fi

            # 7. AI Tier - Ollama (starts in background, model downloads async)
            log_info ""
            log_info "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_info "  Starting Ollama LLM (model download is ASYNC)"
            log_info "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo -n "    [START] Ollama LLM runtime... "
            # Start Ollama WITHOUT the model pull in entrypoint - we'll do that async
            if podman run -d --name aiochi-ollama \
                --restart unless-stopped \
                --network aiochi-internal \
                --ip 172.20.210.50 \
                -p 127.0.0.1:11434:11434 \
                -v aiochi-ollama-models:/root/.ollama \
                -e OLLAMA_HOST=0.0.0.0 \
                -e OLLAMA_KEEP_ALIVE=24h \
                docker.io/ollama/ollama:latest \
                serve >/dev/null 2>&1; then
                echo "✓"
                # Queue model download in background (don't block install)
                log_info "    → Model download will start in background (~2GB)..."
                log_info "    → Monitor: tail -f ${LOG_DIR}/aiochi-llm-download.log"
                (
                    sleep 15  # Wait for Ollama to fully start
                    mkdir -p "$LOG_DIR"
                    echo "[$(date -Iseconds)] Starting llama3.2:3b model download..." >> "${LOG_DIR}/aiochi-llm-download.log"
                    podman exec aiochi-ollama ollama pull llama3.2:3b 2>&1 | while read line; do
                        echo "[$(date -Iseconds)] $line" >> "${LOG_DIR}/aiochi-llm-download.log"
                    done
                    echo "[$(date -Iseconds)] Model download complete." >> "${LOG_DIR}/aiochi-llm-download.log"
                ) &
            elif podman ps -a --format "{{.Names}}" | grep -q "^aiochi-ollama$"; then
                echo "○ (already exists)"
            else
                echo "✗ (AI narratives will use templates)"
                log_warn "Ollama failed to start - AI narratives will fall back to templates"
            fi

            echo ""
            log_info "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            if [ -z "$AIOCHI_FAILED_CONTAINERS" ]; then
                log_info "  AIOCHI containers started successfully!"
            else
                log_warn "  AIOCHI started with some failures"
                log_warn "  Failed containers:${AIOCHI_FAILED_CONTAINERS}"
                log_warn "  These containers may need manual attention."
                log_warn "  Check with: podman logs <container-name>"
            fi
            log_info "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_info ""
            log_info "  Services available at:"
            log_info "    • ClickHouse:      http://localhost:8123"
            log_info "    • VictoriaMetrics: http://localhost:8428"
            log_info "    • Grafana:         http://localhost:3000"
            log_info "    • n8n Workflows:   http://localhost:5678"
            log_info "    • Identity Engine: http://localhost:8060"
            log_info "    • Ollama LLM:      http://localhost:11434"
            log_info ""
            log_info "  NOTE: Ollama is downloading the llama3.2:3b model (~2GB)"
            log_info "        in the background. AI features will activate once complete."
            log_info "        Check progress: tail -f ${LOG_DIR}/aiochi-llm-download.log"
            echo ""

            cd "${INSTALL_DIR}/containers"
        else
            log_warn "AIOCHI compose file not found: $aiochi_compose"
            log_warn "AIOCHI will not be available"
            export INSTALL_AIOCHI=false
        fi
    fi

    # Save configuration for optional services
    save_optional_services_config
}

save_optional_services_config() {
    # Save which optional services were installed for future upgrades/uninstalls
    local config_file="${CONFIG_DIR}/optional-services.conf"

    cat > "$config_file" << EOF
# Fortress Optional Services Configuration
# Generated: $(date -Iseconds)
#
# Core services (always installed):
#   - QSecBit AI threat detection
#   - dnsXai DNS ML protection
#   - DFS WiFi intelligence
#   - SDN Autopilot device classification
#   - PostgreSQL + Redis + Flask Web UI
#
# AIOCHI is an all-or-nothing bundle that adds cognitive network layer

# AIOCHI - AI Eyes (Cognitive Network Layer)
# When true, includes ALL monitoring/analytics components:
#   - ClickHouse analytics database
#   - VictoriaMetrics time-series
#   - Grafana monitoring dashboards
#   - n8n AI Agent workflows + Ollama LLM
#   - Suricata + Zeek network capture
#   - Identity Engine + Log Shipper
INSTALL_AIOCHI=${INSTALL_AIOCHI:-false}

# Component flags (set automatically when AIOCHI=true)
INSTALL_MONITORING=${INSTALL_MONITORING:-false}
INSTALL_N8N=${INSTALL_N8N:-false}
INSTALL_CLICKHOUSE=${INSTALL_CLICKHOUSE:-false}
INSTALL_IDS=${INSTALL_IDS:-false}

# Connectivity options
INSTALL_LTE=${INSTALL_LTE:-false}
LTE_APN="${LTE_APN:-}"
LTE_AUTH="${LTE_AUTH:-none}"

INSTALL_CLOUDFLARE_TUNNEL=${INSTALL_CLOUDFLARE_TUNNEL:-false}
CLOUDFLARE_TOKEN="${CLOUDFLARE_TOKEN:-}"
CLOUDFLARE_HOSTNAME="${CLOUDFLARE_HOSTNAME:-}"
EOF

    chmod 600 "$config_file"
    log_info "Optional services config saved to $config_file"
}

setup_traffic_flow() {
    log_step "Configuring traffic flow"

    local traffic_script="${INSTALL_DIR}/devices/common/traffic-flow-setup.sh"

    if [ -x "$traffic_script" ]; then
        log_info "Setting up NAT and PBR for container traffic..."
        "$traffic_script" setup || {
            log_warn "Traffic flow setup had issues - containers may have limited internet access"
        }
        log_info "Traffic flow configured"
    else
        log_warn "Traffic flow script not found at: $traffic_script"
    fi

    # Add iptables SNAT fallback for container replies to LAN clients
    # This ensures dashboard is accessible even if nftables setup failed
    # Container replies going out FTS bridge must appear from 10.200.0.1 (LAN gateway)
    log_info "Adding iptables SNAT fallback for container traffic..."
    iptables -t nat -C POSTROUTING -s 172.20.200.0/24 -o "${OVS_BRIDGE:-FTS}" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 172.20.200.0/24 -o "${OVS_BRIDGE:-FTS}" -j MASQUERADE

    # Also need DNAT rule for web UI access (fallback if nftables fails)
    # LAN clients accessing 10.200.0.1:8443 → container at 172.20.200.20:8443
    log_info "Adding iptables DNAT fallback for web UI access..."
    iptables -t nat -C PREROUTING -i "${OVS_BRIDGE:-FTS}" -p tcp --dport "${WEB_PORT:-8443}" -j DNAT --to-destination 172.20.200.20:"${WEB_PORT:-8443}" 2>/dev/null || \
        iptables -t nat -A PREROUTING -i "${OVS_BRIDGE:-FTS}" -p tcp --dport "${WEB_PORT:-8443}" -j DNAT --to-destination 172.20.200.20:"${WEB_PORT:-8443}"

    # Allow forwarding to container network
    iptables -C FORWARD -d 172.20.200.0/24 -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -d 172.20.200.0/24 -j ACCEPT
    iptables -C FORWARD -s 172.20.200.0/24 -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -s 172.20.200.0/24 -j ACCEPT
}

# Wait for container to be running
wait_for_container_running() {
    local container="$1"
    local timeout="${2:-30}"
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        local state
        state=$(podman inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "not found")
        if [ "$state" = "running" ]; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

# Wait for container to be healthy (has healthcheck)
wait_for_container_healthy() {
    local container="$1"
    local timeout="${2:-60}"
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        local health
        health=$(podman inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "none")
        if [ "$health" = "healthy" ]; then
            return 0
        fi
        # Also accept running if no healthcheck defined
        if [ "$health" = "none" ] || [ "$health" = "" ]; then
            local state
            state=$(podman inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "not found")
            if [ "$state" = "running" ]; then
                return 0
            fi
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

connect_containers_to_ovs() {
    log_step "Connecting containers to OVS"

    local ovs_script="${DEVICES_DIR}/common/ovs-container-network.sh"

    # Source fortress.conf to get current settings (may have been written during this install)
    if [ -f "$CONFIG_DIR/fortress.conf" ]; then
        # shellcheck source=/dev/null
        source "$CONFIG_DIR/fortress.conf" 2>/dev/null || true
    fi

    # Check if OVS container attachment is disabled
    # This can be set in /etc/hookprobe/fortress.conf or via environment
    # Set SKIP_OVS_CONTAINER_ATTACH=true to disable OVS veth attachment
    if [ "${SKIP_OVS_CONTAINER_ATTACH:-false}" = "true" ]; then
        log_warn "OVS container attachment DISABLED (SKIP_OVS_CONTAINER_ATTACH=true)"
        log_warn "Containers will use podman network only - OpenFlow per-device rules won't apply to container traffic"
        return 0
    fi

    if [ ! -f "$ovs_script" ]; then
        log_warn "OVS script not found - skipping container OVS integration"
        return 0
    fi

    # Connect each container to its OVS tier via veth pair
    # This provides OpenFlow-controlled traffic monitoring alongside Podman networking
    #
    # NOTE: Containers using network_mode: host (qsecbit, bubble-manager) cannot be
    # attached to OVS - they share the host network namespace and are already visible
    # to OVS via host interfaces.
    #
    # IMPORTANT: All containers are on fts-internal (172.20.200.0/24) as defined in
    # podman-compose.yml. The "tier" label is only for OpenFlow policy decisions.
    #
    # TROUBLESHOOTING: If containers have networking issues (empty routing table,
    # can't reach each other), set SKIP_OVS_CONTAINER_ATTACH=true in fortress.conf

    log_info "Attaching containers to OVS bridge for flow monitoring..."

    # Data tier containers (database layer - no internet access via OpenFlow)
    attach_container_if_running "$ovs_script" fts-postgres 172.20.200.10 data
    attach_container_if_running "$ovs_script" fts-redis 172.20.200.11 data

    # Services tier containers (internet-allowed via OpenFlow)
    # IPs must match podman-compose.yml assignments
    #
    # IMPORTANT: fts-web is NOT attached to OVS because it needs podman's native
    # port forwarding for port 8443. OVS attachment breaks DNAT rules.
    # attach_container_if_running "$ovs_script" fts-web 172.20.200.20 services  # DISABLED - breaks port 8443
    attach_container_if_running "$ovs_script" fts-dnsxai 172.20.200.21 services
    attach_container_if_running "$ovs_script" fts-dfs 172.20.200.22 services

    # Note: qsecbit and bubble-manager use host network - already visible via host interfaces
    # They capture traffic on host interfaces directly

    # ML tier (optional - only with --profile training)
    attach_container_if_running "$ovs_script" fts-lstm-trainer 172.20.200.40 ml true

    # Mgmt tier (optional - only with --profile monitoring)
    attach_container_if_running "$ovs_script" fts-grafana 172.20.200.30 mgmt true
    attach_container_if_running "$ovs_script" fts-victoria 172.20.200.31 mgmt true

    log_info "OVS container integration complete"
    log_info "  Note: qsecbit and bubble-manager use host network (no OVS attachment needed)"
    log_info "  Traffic mirroring: all bridge container traffic → fts-mirror"
    log_info "  sFlow export: 127.0.0.1:6343"
    log_info "  IPFIX export: 127.0.0.1:4739"
}

# Attach a container to OVS if it's running
attach_container_if_running() {
    local ovs_script="$1"
    local container="$2"
    local ip="$3"
    local tier="$4"
    local optional="${5:-false}"

    # Check if container exists and is running
    local state
    state=$(podman inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "not found")

    if [ "$state" = "running" ]; then
        # Check if container uses host network (can't attach to OVS)
        local network_mode
        network_mode=$(podman inspect -f '{{.HostConfig.NetworkMode}}' "$container" 2>/dev/null || echo "")
        if [ "$network_mode" = "host" ]; then
            log_info "  $container: uses host network (skipping OVS attachment)"
            return 0
        fi

        if "$ovs_script" attach "$container" "$ip" "$tier" 2>/dev/null; then
            log_info "  $container: attached to OVS ($tier tier)"
        else
            # OVS attachment is optional - containers work fine on podman network
            log_info "  $container: skipped OVS attachment (using podman network)"
        fi
    elif [ "$optional" = "true" ]; then
        # Optional containers - silently skip if not running
        :
    else
        log_warn "  $container: not running (state: $state)"
    fi
}

create_systemd_service() {
    log_step "Creating systemd service"

    # NOTE: podman-compose 1.x does NOT support --profile flag (docker-compose feature)
    # All containers are started/stopped together via podman-compose up/down
    # Monitoring containers (grafana, victoria) are optional via podman-compose.yml profiles
    # but we just start everything and let healthchecks handle it

    # Use the INSTALLED containers directory for systemd service
    local compose_dir="${INSTALL_DIR}/containers"
    local ovs_script="${INSTALL_DIR}/devices/common/ovs-container-network.sh"

    # Create bin directory for scripts
    mkdir -p "${INSTALL_DIR}/bin"

    # Create OVS post-start hook script
    cat > "${INSTALL_DIR}/bin/fts-ovs-connect.sh" << 'OVSEOF'
#!/bin/bash
# Connect fortress containers to OVS after startup
# Called by systemd ExecStartPost

OVS_SCRIPT="/opt/hookprobe/fortress/devices/common/ovs-container-network.sh"
LOG_TAG="fts-ovs"

log_info() { logger -t "$LOG_TAG" "$1"; echo "[INFO] $1"; }
log_warn() { logger -t "$LOG_TAG" -p warning "$1"; echo "[WARN] $1"; }

# Wait for a container to be running (max 30 seconds)
wait_for_container() {
    local container="$1"
    local timeout=30
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        local state
        state=$(podman inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "not found")
        if [ "$state" = "running" ]; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

# Attach container to OVS if running and not using host network
attach_if_ready() {
    local container="$1"
    local ip="$2"
    local tier="$3"
    local optional="${4:-false}"

    # Check if container is running
    local state
    state=$(podman inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "not found")
    if [ "$state" != "running" ]; then
        [ "$optional" != "true" ] && log_warn "$container: not running"
        return 1
    fi

    # Check if using host network (can't attach to OVS)
    local network_mode
    network_mode=$(podman inspect -f '{{.HostConfig.NetworkMode}}' "$container" 2>/dev/null || echo "")
    if [ "$network_mode" = "host" ]; then
        log_info "$container: uses host network (skipping)"
        return 0
    fi

    # Attach to OVS
    if "$OVS_SCRIPT" attach "$container" "$ip" "$tier" 2>/dev/null; then
        log_info "$container: attached to OVS ($tier tier)"
    else
        log_warn "$container: failed to attach to OVS"
    fi
}

if [ ! -f "$OVS_SCRIPT" ]; then
    log_warn "OVS script not found: $OVS_SCRIPT"
    exit 0
fi

# CRITICAL: Ensure OVS bridge is UP and configured before connecting containers
# After reboot, openvswitch-switch restores the bridge but may not bring it UP
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"
LAN_BASE_IP="${LAN_BASE_IP:-10.200.0.1}"
LAN_SUBNET_MASK="${LAN_SUBNET_MASK:-24}"
# Flat bridge architecture - no VLANs, OpenFlow NAC for segmentation
NETWORK_MODE="flat"

log_info "Ensuring OVS bridge $OVS_BRIDGE is ready..."

# Check if bridge exists
if ! ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
    log_warn "OVS bridge $OVS_BRIDGE does not exist - running init"
    export OVS_BRIDGE LAN_SUBNET_MASK
    "$OVS_SCRIPT" init-podman || log_warn "Failed to initialize OVS"
fi

# Ensure bridge is UP
if ! ip link show "$OVS_BRIDGE" 2>/dev/null | grep -q "state UP"; then
    log_info "Bringing OVS bridge UP..."
    ip link set "$OVS_BRIDGE" up || log_warn "Failed to bring bridge UP"
fi

# Flat bridge mode: IP is on FTS bridge directly (no VLANs)
log_info "Flat bridge mode: IP on FTS bridge, OpenFlow NAC"
# Ensure FTS bridge has gateway IP (fortress-vlan.service should have done this)
if ! ip addr show "${OVS_BRIDGE:-FTS}" 2>/dev/null | grep -q "10.200.0.1/"; then
    log_warn "FTS bridge not ready - running ovs-post-setup setup-gateway"
    /opt/hookprobe/fortress/devices/common/ovs-post-setup.sh setup-gateway 2>/dev/null || {
        log_warn "Failed to configure bridge gateway"
    }
fi

# Reinstall OpenFlow rules (they are not persisted across OVS restart)
log_info "Installing OpenFlow rules..."
export OVS_BRIDGE LAN_SUBNET_MASK
"$OVS_SCRIPT" flows 2>/dev/null || log_warn "Failed to install OpenFlow rules"

# Sync NAC device policies to OpenFlow (per-device rules with higher priority)
NAC_SYNC_SCRIPT="/opt/hookprobe/fortress/devices/common/nac-policy-sync.sh"
if [ -f "$NAC_SYNC_SCRIPT" ]; then
    log_info "Syncing NAC device policies..."
    export OVS_BRIDGE LAN_NETWORK GATEWAY_IP
    "$NAC_SYNC_SCRIPT" 2>/dev/null || log_warn "NAC policy sync failed (non-fatal)"
else
    log_info "NAC sync script not found - will sync when web app starts"
fi

# Check if OVS container attachment is disabled
# Source fortress.conf to get the setting
FORTRESS_CONF="/etc/hookprobe/fortress.conf"
if [ -f "$FORTRESS_CONF" ]; then
    # shellcheck source=/dev/null
    source "$FORTRESS_CONF"
fi

if [ "${SKIP_OVS_CONTAINER_ATTACH:-false}" = "true" ]; then
    log_warn "OVS container attachment DISABLED (SKIP_OVS_CONTAINER_ATTACH=true)"
    log_warn "Containers using podman network only - this is safe but limits OpenFlow visibility"
    log_info "OVS bridge setup complete (container attachment skipped)"
    exit 0
fi

log_info "Waiting for containers..."

# Wait for core containers first
wait_for_container fts-postgres || log_warn "postgres not ready"
wait_for_container fts-redis || log_warn "redis not ready"

# Now attach all containers
log_info "Attaching containers to OVS..."

# Data tier (required - no internet via OpenFlow)
attach_if_ready fts-postgres 172.20.200.10 data
attach_if_ready fts-redis 172.20.200.11 data

# Services tier (internet-allowed via OpenFlow)
# All containers are on fts-internal (172.20.200.0/24) per podman-compose.yml
# IPs MUST match compose file assignments
#
# IMPORTANT: fts-web is NOT attached to OVS - it needs podman port forwarding for :8443
# attach_if_ready fts-web 172.20.200.20 services  # DISABLED - breaks port 8443 forwarding
attach_if_ready fts-dnsxai 172.20.200.21 services
attach_if_ready fts-dfs 172.20.200.22 services

# Note: fts-qsecbit and fts-bubble-manager use host network (no attachment needed)

# Optional tiers (mgmt tier = no internet, ml tier = no internet)
attach_if_ready fts-lstm-trainer 172.20.200.40 ml true
attach_if_ready fts-grafana 172.20.200.30 mgmt true
attach_if_ready fts-victoria 172.20.200.31 mgmt true

# Clean up orphan veth interfaces from br-wifi
# These can accumulate from container restarts or failed network setups
cleanup_orphan_veths() {
    local br_wifi="br-wifi"
    if ip link show "$br_wifi" &>/dev/null; then
        local members
        members=$(bridge link show master "$br_wifi" 2>/dev/null | awk '{print $2}' | tr -d ':')
        for member in $members; do
            local base_name="${member%%@*}"
            # Only remove numbered veths (veth0, veth1, etc.) not our veth-wifi-a
            if [[ "$base_name" =~ ^veth[0-9]+$ ]]; then
                log_info "Removing orphan veth: $base_name"
                ip link set "$base_name" nomaster 2>/dev/null || true
                ip link delete "$base_name" 2>/dev/null || true
            fi
        done
    fi
}

# Clean up any orphan veths that might have accumulated
cleanup_orphan_veths

log_info "OVS container integration complete"
OVSEOF

    chmod +x "${INSTALL_DIR}/bin/fts-ovs-connect.sh"

    # Find podman-compose path (may be in /usr/bin or ~/.local/bin)
    local podman_compose_bin
    podman_compose_bin=$(command -v podman-compose || echo "/usr/bin/podman-compose")

    # Flat bridge mode always uses fortress-vlan.service for bridge setup
    local is_flat_mode="true"

    # Build After/Requires lines based on network mode
    local after_deps="network-online.target openvswitch-switch.service podman.socket podman.service"
    local requires_deps="podman.socket openvswitch-switch.service"
    local wants_deps="network-online.target"

    if [ "$is_flat_mode" = "true" ]; then
        # Flat bridge mode: Wait for fortress-vlan.service which sets up bridge gateway
        after_deps="$after_deps fortress-vlan.service"
        wants_deps="$wants_deps fortress-vlan.service"
    fi

    cat > /etc/systemd/system/fortress.service << EOF
[Unit]
Description=HookProbe Fortress Security Gateway
# Wait for network, OVS, VLAN setup (if enabled), and container runtime
After=${after_deps}
Wants=${wants_deps}
# Require both podman and OVS to be running
Requires=${requires_deps}
# Prevent rapid restarts on repeated failures
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${compose_dir}
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.local/bin
Environment=OVS_BRIDGE=FTS
Environment=LAN_BASE_IP=10.200.0.1
Environment=LAN_SUBNET_MASK=${LAN_SUBNET_MASK:-24}
# Load persisted config for NETWORK_MODE (sourced from fortress.conf)
EnvironmentFile=-/etc/hookprobe/fortress.conf

# Wait for OVS to be fully ready
ExecStartPre=/bin/bash -c 'for i in \$(seq 1 30); do ovs-vsctl show >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'

# Ensure bridge is UP
ExecStartPre=/bin/bash -c 'ip link set FTS up 2>/dev/null || true'

# CRITICAL: Ensure FTS bridge has gateway IP
# Flat bridge mode: IP is on FTS bridge directly (no VLANs)
ExecStartPre=/bin/bash -c '/opt/hookprobe/fortress/devices/common/ovs-post-setup.sh setup-gateway 2>/dev/null || \\
  (ip link set FTS up 2>/dev/null; ip addr add 10.200.0.1/\${LAN_SUBNET_MASK:-24} dev FTS 2>/dev/null || true)'

# Wait for podman to be fully ready (max 60 seconds)
ExecStartPre=/bin/bash -c 'for i in \$(seq 1 60); do podman info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'

# CRITICAL: Ensure podman network exists before starting containers
# podman-compose creates networks with project prefix (directory name)
# If network is missing/corrupted, containers won't have eth0 interface
ExecStartPre=/bin/bash -c 'cd /opt/hookprobe/fortress/containers && \\
  NETWORK_NAME="containers_fts-internal" && \\
  if ! podman network exists "\$NETWORK_NAME" 2>/dev/null; then \\
    echo "[FTS] Creating podman network: \$NETWORK_NAME" && \\
    podman network create --driver bridge --subnet 172.20.200.0/24 --gateway 172.20.200.1 "\$NETWORK_NAME" || \\
    echo "[FTS] Network creation failed - compose will retry"; \\
  fi'

# Start containers - SMART STARTUP
# podman-compose 1.x doesn't support profiles, so we ALWAYS specify explicit services.
#
# Core services (names must match podman-compose.yml - no fts- prefix):
#   postgres, redis, web, qsecbit-agent, dnsxai, dfs-intelligence
# Optional connectivity: cloudflared (only if INSTALL_CLOUDFLARE_TUNNEL=true)
#
# NOTE: bubble-manager moved to AIOCHI stack (aiochi-bubble) to avoid host network blocking
#
# OPTIONAL (NOT started by default):
#   - grafana, victoria (monitoring)
#   - n8n, clickhouse (automation/analytics)
#   - suricata, zeek, xdp-protection (IDS)
#   - lstm-trainer (ML training)
ExecStart=/bin/bash -c 'cd /opt/hookprobe/fortress/containers && \\
  CORE="postgres redis web qsecbit-agent dnsxai dfs-intelligence" && \\
  if [ "\${INSTALL_CLOUDFLARE_TUNNEL:-}" = "true" ]; then CORE="\$CORE cloudflared"; fi && \\
  echo "[FTS] Starting core services: \$CORE" && \\
  ${podman_compose_bin} -f podman-compose.yml up -d --no-build \$CORE'

# Connect containers to OVS and install OpenFlow rules after containers are up
ExecStartPost=${INSTALL_DIR}/bin/fts-ovs-connect.sh

# Stop containers gracefully
ExecStop=${podman_compose_bin} -f podman-compose.yml down

# Reload containers
ExecReload=${podman_compose_bin} -f podman-compose.yml restart

TimeoutStartSec=300
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF

    # Save config for reference
    echo "FORTRESS_PROFILES=\"all\"" >> /etc/hookprobe/fortress.conf

    # Ensure required services are enabled for boot
    log_info "Enabling systemd services for boot..."

    # Enable podman socket (required for container startup)
    systemctl enable podman.socket 2>/dev/null || true
    systemctl start podman.socket 2>/dev/null || true

    # Enable network-online.target (some distros don't enable this by default)
    systemctl enable systemd-networkd-wait-online.service 2>/dev/null || \
        systemctl enable NetworkManager-wait-online.service 2>/dev/null || true

    # Reload and enable fortress service
    systemctl daemon-reload
    systemctl enable fortress

    log_info "Systemd service created and enabled"
    log_info "  fortress.service will start containers on boot"
}

# ============================================================
# AI FINGERPRINTING & ECOSYSTEM BUBBLE SETUP
# ============================================================
install_fingerprinting_services() {
    log_step "Installing AI Fingerprinting & Ecosystem Bubble services"

    local SYSTEMD_SRC="${FORTRESS_ROOT}/systemd"
    local SYSTEMD_DST="/etc/systemd/system"

    # Install fingerprinting engine service
    if [ -f "${SYSTEMD_SRC}/fts-fingerprint-engine.service" ]; then
        cp "${SYSTEMD_SRC}/fts-fingerprint-engine.service" "${SYSTEMD_DST}/"
        log_info "  Installed: fts-fingerprint-engine.service"
    fi

    # Install presence sensor service
    if [ -f "${SYSTEMD_SRC}/fts-presence-sensor.service" ]; then
        cp "${SYSTEMD_SRC}/fts-presence-sensor.service" "${SYSTEMD_DST}/"
        log_info "  Installed: fts-presence-sensor.service"
    fi

    # NOTE: Ecosystem bubble manager is now part of AIOCHI stack (aiochi-bubble)
    # No separate systemd service needed - managed by AIOCHI containers
    # if [ -f "${SYSTEMD_SRC}/fts-bubble-manager.service" ]; then
    #     cp "${SYSTEMD_SRC}/fts-bubble-manager.service" "${SYSTEMD_DST}/"
    #     log_info "  Installed: fts-bubble-manager.service"
    # fi

    # Install WAN failover service (for dual-WAN PBR failover)
    if [ -f "${SYSTEMD_SRC}/fts-wan-failover.service" ]; then
        cp "${SYSTEMD_SRC}/fts-wan-failover.service" "${SYSTEMD_DST}/"
        log_info "  Installed: fts-wan-failover.service"
    fi

    # Initialize fingerprinting databases
    log_info "Initializing fingerprinting databases..."

    local FP_DB_DIR="/var/lib/hookprobe"
    mkdir -p "$FP_DB_DIR"
    chown fortress:fortress "$FP_DB_DIR" 2>/dev/null || true

    # Create ML model directory
    mkdir -p "$FP_DB_DIR/ml_fingerprint_models"
    chown fortress:fortress "$FP_DB_DIR/ml_fingerprint_models" 2>/dev/null || true

    # Create bubble state directory
    mkdir -p /var/lib/fortress/bubbles
    chown fortress:fortress /var/lib/fortress/bubbles 2>/dev/null || true

    # Initialize SQLite databases with schema (using sqlite3 CLI)
    if command -v sqlite3 &>/dev/null; then
        # Fingerprint database
        sqlite3 /var/lib/hookprobe/fingerprint.db << 'SQLEOF'
CREATE TABLE IF NOT EXISTS fingerprints (
    mac_address TEXT PRIMARY KEY,
    device_type TEXT,
    device_category TEXT,
    vendor TEXT,
    os_type TEXT,
    confidence REAL DEFAULT 0.0,
    dhcp_fingerprint TEXT,
    hostname TEXT,
    first_seen TEXT,
    last_seen TEXT,
    signals TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS fingerprint_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT,
    correct_type TEXT,
    correct_vendor TEXT,
    submitted_by TEXT,
    submitted_at TEXT DEFAULT CURRENT_TIMESTAMP
);
SQLEOF
        chmod 644 /var/lib/hookprobe/fingerprint.db

        # Ecosystem bubbles database
        sqlite3 /var/lib/hookprobe/ecosystem_bubbles.db << 'SQLEOF'
CREATE TABLE IF NOT EXISTS bubbles (
    bubble_id TEXT PRIMARY KEY,
    name TEXT,
    ecosystem TEXT,
    state TEXT DEFAULT 'FORMING',
    confidence REAL DEFAULT 0.0,
    device_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS bubble_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bubble_id TEXT,
    mac_address TEXT,
    device_type TEXT,
    joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bubble_id) REFERENCES bubbles(bubble_id)
);
CREATE TABLE IF NOT EXISTS bubble_sdn_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bubble_id TEXT,
    rule_type TEXT,
    priority INTEGER,
    match_criteria TEXT,
    actions TEXT,
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bubble_id) REFERENCES bubbles(bubble_id)
);
SQLEOF
        chmod 644 /var/lib/hookprobe/ecosystem_bubbles.db

        # Presence sensor database
        # Note: Must handle schema migrations for existing installations
        sqlite3 /var/lib/hookprobe/presence.db << 'SQLEOF'
-- Create table if not exists (new installs)
CREATE TABLE IF NOT EXISTS presence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT,
    event_type TEXT,
    ecosystem TEXT,
    signal_type TEXT,
    signal_data TEXT,
    confidence REAL,
    detected_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Schema migration: add ecosystem column if missing (upgrades from older versions)
-- SQLite doesn't have "ADD COLUMN IF NOT EXISTS", so we check first
PRAGMA table_info(presence_events);
SQLEOF

        # Check if ecosystem column exists and add if missing
        if ! sqlite3 /var/lib/hookprobe/presence.db "PRAGMA table_info(presence_events);" | grep -q "ecosystem"; then
            log_info "  Adding ecosystem column to presence_events (schema migration)..."
            sqlite3 /var/lib/hookprobe/presence.db "ALTER TABLE presence_events ADD COLUMN ecosystem TEXT;" 2>/dev/null || true
        fi

        # Continue with remaining schema
        sqlite3 /var/lib/hookprobe/presence.db << 'SQLEOF'
CREATE TABLE IF NOT EXISTS mdns_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT,
    service_type TEXT,
    service_name TEXT,
    hostname TEXT,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_presence_mac ON presence_events(mac_address);
CREATE INDEX IF NOT EXISTS idx_presence_ecosystem ON presence_events(ecosystem);
SQLEOF
        chmod 644 /var/lib/hookprobe/presence.db

        log_info "Databases initialized successfully"
    else
        log_warn "Database initialization skipped (sqlite3 not available)"
    fi

    # Enable and start services
    # NOTE: bubble-manager is now part of AIOCHI stack - no systemd service here
    systemctl daemon-reload
    systemctl enable fts-fingerprint-engine.service 2>/dev/null || true
    systemctl enable fts-presence-sensor.service 2>/dev/null || true
    # Bubble manager moved to AIOCHI (aiochi-bubble container)

    # Enable WAN failover service (only if config exists - ConditionPathExists checks this)
    # The service will be inactive until /etc/hookprobe/wan-failover.conf is created
    systemctl enable fts-wan-failover.service 2>/dev/null || true

    # Start host-based services (fingerprint-engine and presence-sensor run on host)
    log_info "Starting AI Fingerprinting services..."
    systemctl start fts-fingerprint-engine.service 2>/dev/null || {
        log_warn "fts-fingerprint-engine failed to start (may need dependencies)"
    }
    systemctl start fts-presence-sensor.service 2>/dev/null || {
        log_warn "fts-presence-sensor failed to start (may need bluetooth)"
    }

    # NOTE: Bubble manager is now part of AIOCHI stack (aiochi-bubble)
    # Ecosystem detection requires --enable-aiochi during installation
    if [ "${INSTALL_AIOCHI:-}" = true ]; then
        log_info "Bubble detection available via AIOCHI stack (aiochi-bubble)"
    else
        log_info "Bubble detection disabled (enable with --enable-aiochi)"
    fi

    log_info "AI Fingerprinting services installed and started"
}

# ============================================================
# STATE MANAGEMENT
# ============================================================
STATE_FILE="${CONFIG_DIR}/fortress-state.json"

# Fix config file permissions for container access
# Called after all config files are created to ensure proper ownership
# Note: /etc/hookprobe is mounted read-only in containers, so world-readable (644) is acceptable
# Writable volumes use :U suffix in podman-compose.yml to auto-adjust ownership
fix_config_permissions() {
    log_step "Setting config file permissions"

    # Check if fortress group has GID 1000 (matches container)
    local fortress_gid
    fortress_gid=$(getent group fortress 2>/dev/null | cut -d: -f3)

    if [ "$fortress_gid" = "1000" ]; then
        # GID matches container - use group ownership for tighter permissions
        chgrp -R fortress "$CONFIG_DIR" 2>/dev/null || true

        # Config files that container needs to read (640 = rw-r-----)
        for file in "$CONFIG_DIR/users.json" "$CONFIG_DIR/fortress.conf" \
                    "$CONFIG_DIR/wifi-interfaces.conf"; do
            if [ -f "$file" ]; then
                chown root:fortress "$file"
                chmod 640 "$file"
            fi
        done
    else
        # GID differs from container - use world-readable for read-only config mount
        # This is acceptable: passwords are bcrypt-hashed, secrets are in env vars
        log_info "Using world-readable config files (GID $fortress_gid != container GID 1000)"

        for file in "$CONFIG_DIR/users.json" "$CONFIG_DIR/fortress.conf" \
                    "$CONFIG_DIR/wifi-interfaces.conf"; do
            if [ -f "$file" ]; then
                chown root:root "$file"
                chmod 644 "$file"
            fi
        done
    fi

    # Secrets that container needs (640 or 644 based on GID match)
    for file in "$CONFIG_DIR/secrets/fortress_secret_key"; do
        if [ -f "$file" ]; then
            if [ "$fortress_gid" = "1000" ]; then
                chown root:fortress "$file"
                chmod 640 "$file"
            else
                chown root:root "$file"
                chmod 644 "$file"
            fi
        fi
    done

    # Secrets that only root needs (600) - keep restrictive
    for file in "$CONFIG_DIR/secrets/admin_password" \
                "$CONFIG_DIR/optional-services.conf" \
                "$STATE_FILE"; do
        if [ -f "$file" ]; then
            chmod 600 "$file"
        fi
    done

    # Secrets directory should be accessible by group but files are restrictive
    if [ "$fortress_gid" = "1000" ]; then
        chmod 750 "$CONFIG_DIR/secrets" 2>/dev/null || true
    else
        chmod 755 "$CONFIG_DIR/secrets" 2>/dev/null || true
    fi

    # Ensure all databases are writable by web container (uid 1000)
    # The databases store device info, WiFi signals, DFS data, and policies
    local autopilot_db="/var/lib/hookprobe/autopilot.db"
    local dfs_db="/var/lib/hookprobe/dfs_intelligence.db"
    local devices_db="/var/lib/hookprobe/devices.db"

    for db_file in "$autopilot_db" "$dfs_db" "$devices_db"; do
        if [ ! -f "$db_file" ]; then
            touch "$db_file"
        fi
        chmod 666 "$db_file"
        chown 1000:1000 "$db_file" 2>/dev/null || true
    done
    log_info "  Database permissions fixed for container access"

    log_info "Config permissions set for container access"
}

save_installation_state() {
    log_step "Saving installation state"

    mkdir -p "$(dirname "$STATE_FILE")"

    # All security core containers are always installed
    local containers='["fts-web", "fts-postgres", "fts-redis", "fts-qsecbit", "fts-dnsxai", "fts-dfs"]'
    # Volumes defined in podman-compose.yml (core tier only, optional profiles auto-create theirs)
    local volumes='["fts-postgres-data", "fts-postgres-certs", "fts-redis-data", "fts-web-data", "fts-web-logs", "fts-dnsxai-data", "fts-dnsxai-blocklists", "fts-dnsxai-certs", "fts-dfs-data", "fts-zeek-logs"]'

    # Network configuration for Python config.py to load
    local lan_subnet="10.200.0.0/${LAN_SUBNET_MASK:-24}"
    local lan_gateway="${GATEWAY_LAN:-10.200.0.1}"
    local ovs_bridge="${OVS_BRIDGE:-FTS}"

    cat > "$STATE_FILE" << EOF
{
    "deployment_mode": "container",
    "version": "5.5.0",
    "installed_at": "$(date -Iseconds)",
    "network_mode": "${NETWORK_MODE}",
    "security_core": true,
    "web_port": "${WEB_PORT}",
    "admin_user": "${ADMIN_USER}",
    "lan_subnet": "${lan_subnet}",
    "lan_gateway": "${lan_gateway}",
    "lan_dhcp_start": "${LAN_DHCP_START:-10.200.0.100}",
    "lan_dhcp_end": "${LAN_DHCP_END:-10.200.0.200}",
    "ovs_bridge": "${ovs_bridge}",
    "containers": ${containers},
    "volumes": ${volumes}
}
EOF

    chmod 600 "$STATE_FILE"

    # Create VERSION file
    echo "5.5.0" > "${INSTALL_DIR}/VERSION"

    log_info "Installation state saved"
}

# ============================================================
# UNINSTALL (Staged)
# ============================================================
uninstall() {
    log_step "Staged Uninstall"

    local keep_data=false
    local keep_config=false

    # Parse uninstall options
    for arg in "$@"; do
        case "$arg" in
            --keep-data) keep_data=true ;;
            --keep-config) keep_config=true ;;
            --purge) keep_data=false; keep_config=false ;;
        esac
    done

    echo ""
    echo -e "${YELLOW}Uninstall Options:${NC}"
    echo "  --keep-data   : Preserve database and user data"
    echo "  --keep-config : Preserve configuration files"
    echo "  --purge       : Remove everything including user data"
    echo ""
    echo -e "${GREEN}Always preserved (unless --purge):${NC}"
    echo "  /var/lib/hookprobe/userdata/dnsxai/"
    echo "    - whitelist.txt      User's DNS whitelist"
    echo "    - config.json        dnsXai configuration"
    echo ""
    echo -e "${RED}Components to be removed:${NC}"
    echo ""
    echo "  Services:"
    echo "    - fortress (main systemd service)"
    echo "    - fts-hostapd-* (WiFi AP services)"
    echo ""
    echo "  Containers:"
    echo "    - fts-web (Flask admin portal)"
    echo "    - fts-postgres (database)"
    echo "    - fts-redis (cache/sessions)"
    echo "    - fts-qsecbit (threat detection)"
    echo "    - fts-dnsxai (DNS ML protection)"
    echo "    - fts-dfs (WiFi DFS intelligence)"
    echo "    - fts-lstm-trainer (ML training)"
    echo "    - fts-grafana (monitoring dashboard)"
    echo "    - fts-victoria (metrics database)"
    echo "    - fts-n8n (workflow automation, if installed)"
    echo "    - fts-clickhouse (analytics database, if installed)"
    echo "    - fts-suricata (IDS, if installed)"
    echo "    - fts-zeek (network analyzer, if installed)"
    echo "    - fts-cloudflared (tunnel, if installed)"
    echo ""
    echo "  OVS Network:"
    echo "    - OVS bridge: $OVS_BRIDGE"
    echo "    - Internal ports: ${OVS_BRIDGE}-data, ${OVS_BRIDGE}-services, ${OVS_BRIDGE}-ml, ${OVS_BRIDGE}-mgmt, ${OVS_BRIDGE}-lan"
    echo "    - Traffic mirror port: ${OVS_BRIDGE}-mirror"
    echo "    - Container veth interfaces"
    echo "    - VXLAN tunnel configurations"
    echo "    - OpenFlow rules"
    echo "    - sFlow/IPFIX export"
    echo ""
    [ "$keep_data" = false ] && echo "  Data volumes (all user data, ML models, blocklists)"
    [ "$keep_config" = false ] && echo "  Configuration: /etc/hookprobe"
    [ "$keep_config" = false ] && echo "  Secrets: VXLAN PSK, admin credentials, WiFi passwords"
    echo "  Installation: /opt/hookprobe/fortress"
    echo "  DHCP config: /etc/dnsmasq.d/fts-ovs.conf"
    echo "  WiFi config: /etc/hostapd/fts-*.conf"
    echo ""

    if [ "$keep_data" = true ]; then
        echo -e "${GREEN}Data will be preserved for reinstallation.${NC}"
    fi
    echo ""

    read -p "Type 'yes' to confirm uninstall: " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "Uninstall cancelled"
        exit 0
    fi

    # Stage 1: Stop services
    log_info "Stage 1: Stopping services..."
    systemctl stop fortress 2>/dev/null || true
    systemctl stop fts-hostapd-2g 2>/dev/null || true
    systemctl stop fts-hostapd-5g 2>/dev/null || true
    cd "${INSTALL_DIR}/containers" 2>/dev/null && \
        podman-compose --profile monitoring --profile training down 2>/dev/null || true

    # Stage 2: Remove application containers
    log_info "Stage 2: Removing application containers..."
    podman rm -f fts-web fts-qsecbit fts-dnsxai fts-dfs fts-lstm-trainer 2>/dev/null || true
    podman rm -f fts-grafana fts-victoria 2>/dev/null || true
    # Optional services
    podman rm -f fts-n8n fts-clickhouse fts-cloudflared 2>/dev/null || true
    podman rm -f fts-suricata fts-zeek fts-xdp 2>/dev/null || true

    # Stage 2b: Remove container images
    log_info "Stage 2b: Removing container images..."
    podman rmi -f localhost/fts-web:latest 2>/dev/null || true
    podman rmi -f localhost/fts-agent:latest 2>/dev/null || true
    podman rmi -f localhost/fts-dnsxai:latest 2>/dev/null || true
    podman rmi -f localhost/fts-dfs:latest 2>/dev/null || true
    podman rmi -f localhost/fts-lstm:latest 2>/dev/null || true

    # Stage 3: Handle data containers/volumes
    if [ "$keep_data" = false ]; then
        log_info "Stage 3: Removing data containers and volumes..."
        podman rm -f fts-postgres fts-redis 2>/dev/null || true
        # Remove all Fortress volumes
        podman volume rm -f \
            fts-postgres-data \
            fts-postgres-certs \
            fts-redis-data \
            fts-web-data \
            fts-web-logs \
            fts-agent-data \
            fts-dnsxai-data \
            fts-dnsxai-blocklists \
            fts-dfs-data \
            fts-ml-models \
            fts-grafana-data \
            fts-victoria-data \
            fts-n8n-data \
            fts-clickhouse-data \
            fts-clickhouse-logs \
            fts-suricata-logs \
            fts-suricata-rules \
            fts-suricata-config \
            fts-zeek-logs \
            fts-zeek-spool \
            fts-zeek-config \
            fts-xdp-data \
            fortress-config \
            2>/dev/null || true
    else
        log_info "Stage 3: Preserving data containers and volumes..."
        # Only stop data containers, don't remove
        podman stop fts-postgres fts-redis 2>/dev/null || true
    fi

    # Stage 4: Remove systemd services
    log_info "Stage 4: Removing systemd services..."
    systemctl disable fortress 2>/dev/null || true
    systemctl disable fts-hostapd-2g 2>/dev/null || true
    systemctl disable fts-hostapd-5g 2>/dev/null || true
    # Stop and disable host timers
    systemctl stop fts-device-status.timer fts-lte-collector.timer fts-wifi-signal.timer 2>/dev/null || true
    systemctl disable fts-device-status.timer fts-lte-collector.timer fts-wifi-signal.timer 2>/dev/null || true
    rm -f /etc/systemd/system/fortress.service
    rm -f /etc/systemd/system/fts-hostapd-*.service
    rm -f /etc/systemd/system/fts-device-status.service /etc/systemd/system/fts-device-status.timer
    rm -f /etc/systemd/system/fts-lte-collector.service /etc/systemd/system/fts-lte-collector.timer
    rm -f /etc/systemd/system/fts-wifi-signal.service /etc/systemd/system/fts-wifi-signal.timer
    systemctl daemon-reload

    # Stage 5: Remove OVS network configuration
    log_info "Stage 5: Removing OVS network..."

    # Remove container veth interfaces from OVS
    for veth in veth-fts-postgres veth-fts-redis veth-fts-web \
                veth-fts-dnsxai veth-fts-dfs veth-fts-lstm-trainer \
                veth-fts-grafana veth-fts-victoria \
                veth-fts-n8n veth-fts-clickhouse veth-fts-cloudflared; do
        ovs-vsctl del-port "$OVS_BRIDGE" "$veth" 2>/dev/null || true
        ip link del "$veth" 2>/dev/null || true
    done

    # Remove VXLAN tunnels
    for tunnel in vxlan-mesh-core vxlan-mesh-threat vxlan-mssp-uplink; do
        ovs-vsctl del-port "$OVS_BRIDGE" "$tunnel" 2>/dev/null || true
    done

    # Clear OVS mirrors, sFlow, IPFIX
    ovs-vsctl clear bridge "$OVS_BRIDGE" mirrors 2>/dev/null || true
    ovs-vsctl clear bridge "$OVS_BRIDGE" sflow 2>/dev/null || true
    ovs-vsctl clear bridge "$OVS_BRIDGE" ipfix 2>/dev/null || true

    # Delete OVS bridge (removes all ports including internal ports)
    ovs-vsctl del-br "$OVS_BRIDGE" 2>/dev/null || true
    # Also clean up legacy 'fortress' bridge if it exists
    ovs-vsctl del-br fortress 2>/dev/null || true

    # Remove nftables rules if any
    nft delete table inet fortress_filter 2>/dev/null || true

    # Remove NAT rules - try all possible LAN subnet sizes
    for mask in 23 24 25 26 27 28 29; do
        iptables -t nat -D POSTROUTING -s 10.200.0.0/$mask -j MASQUERADE 2>/dev/null || true
    done
    iptables -t nat -D POSTROUTING -s 172.20.201.0/24 -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$OVS_BRIDGE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$OVS_BRIDGE" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    # Also clean up legacy 'fortress' bridge rules
    iptables -D FORWARD -i fortress -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o fortress -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    log_info "  OVS bridge and network rules removed"

    # Stage 6: Remove DHCP and WiFi configuration
    log_info "Stage 6: Removing DHCP and WiFi config..."
    rm -f /etc/dnsmasq.d/fts-ovs.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fts-bridge.conf 2>/dev/null || true
    rm -f /etc/hostapd/fts-*.conf 2>/dev/null || true
    systemctl restart dnsmasq 2>/dev/null || true

    # Stage 7: Handle configuration
    if [ "$keep_config" = false ]; then
        log_info "Stage 7: Removing configuration..."
        rm -f "$CONFIG_DIR/fortress.conf" 2>/dev/null || true
        rm -f "$CONFIG_DIR/users.json" 2>/dev/null || true
        rm -f "$STATE_FILE" 2>/dev/null || true
        rm -rf "$CONFIG_DIR/secrets" 2>/dev/null || true
        rm -f /var/lib/fortress/ovs/*.conf 2>/dev/null || true
        rm -rf /var/lib/fortress 2>/dev/null || true
    else
        log_info "Stage 7: Preserving configuration..."
    fi

    # Stage 8: Remove installation directory
    log_info "Stage 8: Removing installation files..."
    rm -rf "$INSTALL_DIR/web" "$INSTALL_DIR/lib" "$INSTALL_DIR/bin" 2>/dev/null || true
    rm -rf "$INSTALL_DIR/devices" "$INSTALL_DIR/containers" 2>/dev/null || true
    [ "$keep_data" = false ] && rm -rf "$INSTALL_DIR" "$DATA_DIR" 2>/dev/null || true

    # Stage 9: Handle persistent user data
    # /var/lib/hookprobe/userdata/dnsxai contains whitelist.txt and config.json
    # This data should ALWAYS be preserved unless --purge is specified
    local purge_mode=false
    for arg in "$@"; do
        [ "$arg" = "--purge" ] && purge_mode=true
    done

    if [ "$purge_mode" = true ]; then
        log_info "Stage 9: Removing user data (--purge mode)..."
        rm -rf /var/lib/hookprobe/userdata 2>/dev/null || true
    else
        if [ -d "/var/lib/hookprobe/userdata" ]; then
            log_info "Stage 9: Preserving user data..."
            log_info "  Location: /var/lib/hookprobe/userdata/"
            log_info "  Contains: dnsXai whitelist, blocked traffic logs, user configs"
            log_info "  Use --purge to remove this data"
        fi
    fi

    # Remove sysctl config
    rm -f /etc/sysctl.d/99-fts-forward.conf 2>/dev/null || true

    # Clean empty directories
    rmdir "$INSTALL_DIR" 2>/dev/null || true
    rmdir /opt/hookprobe 2>/dev/null || true

    echo ""
    echo "════════════════════════════════════════════════════════════════"
    log_info "Uninstall complete!"
    echo "════════════════════════════════════════════════════════════════"
    echo ""

    if [ "$keep_data" = true ]; then
        echo -e "${GREEN}Data preserved!${NC}"
        echo "  To reinstall with existing data:"
        echo "    ./install-container.sh --preserve-data"
        echo ""
        echo "  To completely remove data later:"
        echo "    podman volume rm fts-postgres-data fts-redis-data"
        echo ""
    fi

    if [ "$keep_config" = true ]; then
        echo "Configuration preserved in: $CONFIG_DIR"
        echo ""
    fi

    # Always show user data preservation message unless --purge was used
    if [ "$purge_mode" != true ] && [ -d "/var/lib/hookprobe/userdata" ]; then
        echo -e "${GREEN}User data preserved!${NC}"
        echo "  Location: /var/lib/hookprobe/userdata/"
        echo "  Contains: dnsXai whitelist, blocked traffic logs"
        echo "  This data will be automatically used on reinstall."
        echo ""
        echo "  To completely remove user data:"
        echo "    rm -rf /var/lib/hookprobe/userdata"
        echo ""
    fi

    echo "Note: WiFi interface names may revert to default after reboot"
    echo "      (e.g., wlp2s0 instead of wlan-2g)"
    echo ""
}

# ============================================================
# QUICK INSTALL
# ============================================================
quick_install() {
    NETWORK_MODE="flat"  # Always VLAN mode
    ADMIN_USER="admin"
    ADMIN_PASS="hookprobe"
    WEB_PORT="8443"
    INSTALL_ML=true
    BUILD_ML_CONTAINERS=true
    WIFI_SSID="HookProbe-Fortress"
    WIFI_PASSWORD="hookprobe123"
    # Subnet defaults - /23 for maximum flexibility (510 devices)
    LAN_SUBNET_MASK="23"
    LAN_DHCP_START="10.200.0.100"
    LAN_DHCP_END="10.200.1.200"

    log_warn "Quick install with default credentials"
    log_warn "Admin: admin / hookprobe - CHANGE THIS IMMEDIATELY!"
    log_warn "WiFi:  HookProbe-Fortress / hookprobe123"
}

# ============================================================
# MAIN
# ============================================================
main() {
    # Parse all arguments first
    local do_uninstall=false
    local do_quick=false
    local preserve_data=false
    local uninstall_args=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --uninstall|uninstall|remove)
                do_uninstall=true
                ;;
            --quick|quick)
                do_quick=true
                ;;
            --non-interactive)
                NON_INTERACTIVE=true
                export NON_INTERACTIVE
                ;;
            --preserve-data)
                preserve_data=true
                ;;
            --force-rebuild)
                FORCE_REBUILD=true
                export FORCE_REBUILD
                ;;
            --keep-data|--keep-config|--purge)
                uninstall_args="$uninstall_args $1"
                ;;
            --enable-aiochi)
                # AIOCHI bundles all monitoring/analytics components
                export INSTALL_AIOCHI=true
                export INSTALL_MONITORING=true
                export INSTALL_CLICKHOUSE=true
                export INSTALL_N8N=true
                export INSTALL_IDS=true
                ;;
            --enable-remote-access)
                export INSTALL_CLOUDFLARE_TUNNEL=true
                ;;
            --enable-lte)
                export INSTALL_LTE=true
                ;;
            --lte-apn)
                shift
                export LTE_APN="$1"
                ;;
            --lte-auth)
                shift
                export LTE_AUTH="$1"
                ;;
            --lte-user)
                shift
                export LTE_USER="$1"
                ;;
            --lte-pass)
                shift
                export LTE_PASS="$1"
                ;;
            --cloudflare-token)
                shift
                export CLOUDFLARE_TOKEN="$1"
                ;;
            --cloudflare-hostname)
                shift
                export CLOUDFLARE_HOSTNAME="$1"
                ;;
            --help|help|-h)
                echo "Usage: $0 [options]"
                echo ""
                echo "Installation Options:"
                echo "  (none)              Interactive installation"
                echo "  --quick             Quick install with defaults"
                echo "  --non-interactive   Use environment variables, no prompts"
                echo "  --preserve-data     Reinstall using existing data volumes"
                echo "  --force-rebuild     Force rebuild of all containers"
                echo ""
                echo "Optional Components:"
                echo "  --enable-aiochi           Install AIOCHI (AI Eyes) - Cognitive Network Layer"
                echo "                            Bundles: ClickHouse, Grafana, VictoriaMetrics,"
                echo "                            n8n, Suricata, Zeek, Ollama LLM"
                echo "  --enable-remote-access    Configure Cloudflare Tunnel"
                echo "  --enable-lte              Enable LTE modem failover"
                echo ""
                echo "LTE Configuration (with --enable-lte or when modem detected):"
                echo "  --lte-apn <apn>           APN name (e.g., internet.vodafone.ro)"
                echo "  --lte-auth <type>         Auth type: none, pap, chap, mschapv2"
                echo "  --lte-user <user>         Username for APN authentication"
                echo "  --lte-pass <pass>         Password for APN authentication"
                echo ""
                echo "Cloudflare Tunnel (with --enable-remote-access):"
                echo "  --cloudflare-token <token>     Tunnel token from Cloudflare dashboard"
                echo "  --cloudflare-hostname <host>   Subdomain (e.g., fortress.mybakery.com)"
                echo ""
                echo "Environment Variables (for --non-interactive):"
                echo "  WIFI_SSID           WiFi network name"
                echo "  WIFI_PASSWORD       WiFi password"
                echo "  FORTRESS_NETWORK_PREFIX  Subnet mask (e.g., 23)"
                echo "  ADMIN_USER          Admin username"
                echo "  ADMIN_PASS          Admin password"
                echo "  WEB_PORT            Web UI port"
                echo "  INSTALL_AIOCHI      true/false - Enable AIOCHI (AI Eyes)"
                echo "  LTE_APN             LTE APN name"
                echo "  LTE_AUTH            LTE auth type (none/pap/chap/mschapv2)"
                echo "  LTE_USER            LTE username"
                echo "  LTE_PASS            LTE password"
                echo "  CLOUDFLARE_TOKEN    Cloudflare tunnel token"
                echo "  CLOUDFLARE_HOSTNAME Cloudflare tunnel hostname"
                echo ""
                echo "Uninstall Options:"
                echo "  --uninstall              Remove Fortress"
                echo "  --uninstall --keep-data  Remove but preserve database"
                echo "  --uninstall --keep-config Remove but preserve config"
                echo "  --uninstall --purge      Remove everything"
                echo ""
                echo "Upgrade (use fortress-ctl for advanced operations):"
                echo "  fortress-ctl upgrade --app   Hot upgrade application only"
                echo "  fortress-ctl upgrade --full  Full system upgrade"
                echo "  fortress-ctl backup          Create backup"
                echo "  fortress-ctl status          Show status"
                echo ""
                exit 0
                ;;
            *)
                # Ignore unknown arguments
                ;;
        esac
        shift
    done

    show_banner

    # Handle uninstall
    if [ "$do_uninstall" = true ]; then
        check_prerequisites
        uninstall $uninstall_args
        exit 0
    fi

    # Handle quick install
    if [ "$do_quick" = true ]; then
        check_prerequisites
        quick_install
    elif [ "$preserve_data" = true ]; then
        check_prerequisites
        log_info "Reinstalling with preserved data..."
        PRESERVE_DATA=true
        collect_configuration
    else
        check_prerequisites
        collect_configuration
    fi

    # Run installation
    create_fortress_user  # Create system user before directories (for proper ownership)
    create_directories
    copy_application_files
    generate_secrets
    create_admin_user
    create_configuration
    setup_network_filter
    setup_network
    build_containers
    start_containers
    create_systemd_service
    install_fingerprinting_services  # AI fingerprinting & ecosystem bubble
    fix_config_permissions  # Ensure container can read config files
    save_installation_state

    # Final service restarts to ensure clean state
    log_step "Finalizing services"

    # Stop and start dnsmasq to pick up VLAN config changes cleanly
    # (stop+start avoids issues with interface binding during restart)
    systemctl stop dnsmasq 2>/dev/null || true
    sleep 1
    systemctl start dnsmasq 2>/dev/null || {
        log_warn "dnsmasq failed to start - may need manual intervention"
    }

    # Start fortress service if not already running (container orchestration)
    if ! systemctl is-active --quiet fortress 2>/dev/null; then
        systemctl start fortress 2>/dev/null || {
            log_warn "fortress.service failed to start - containers may need manual start"
        }
    fi

    log_success "Services finalized"

    # Final message
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${GREEN}  HookProbe Fortress Installation Complete!${NC}"
    echo "════════════════════════════════════════════════════════════════"
    echo ""

    # Access information for flat bridge mode
    echo "Access the admin portal:"
    echo -e "  ${CYAN}https://10.200.0.1:${WEB_PORT}${NC}"
    if [ -n "$MGMT_INTERFACE" ]; then
        echo -e "  ${CYAN}Admin Port:${NC}     $MGMT_INTERFACE (recommended for admin workstation)"
    fi
    echo -e "  ${CYAN}Via Cloudflare:${NC} Configure tunnel for remote access"
    echo ""

    echo "Login credentials:"
    echo -e "  Username: ${BOLD}${ADMIN_USER}${NC}"
    echo -e "  Password: ${BOLD}(saved to ${CONFIG_DIR}/secrets/admin_password)${NC}"
    echo ""
    echo "To retrieve your admin password:"
    echo "  sudo cat ${CONFIG_DIR}/secrets/admin_password"
    echo ""

    if [ -n "$WIFI_SSID" ] && [ -n "$WIFI_PASSWORD" ]; then
        echo "WiFi Access Point:"
        echo -e "  SSID:     ${BOLD}${WIFI_SSID}${NC}"
        echo -e "  Password: ${BOLD}${WIFI_PASSWORD}${NC}"
        echo ""
    fi

    echo "Network Configuration:"
    echo -e "  Mode:       ${BOLD}Flat Bridge${NC} (OpenFlow NAC)"
    echo -e "  Bridge:     $OVS_BRIDGE (OVS with OpenFlow 1.3+)"
    echo ""
    echo "Network Architecture:"
    echo -e "  FTS Bridge:  10.200.0.0/${LAN_SUBNET_MASK:-24} - WiFi clients, LAN devices"
    echo -e "  OpenFlow:    NAC via device fingerprinting policies"
    echo ""

    echo "Container Network: 172.20.200.0/24 (isolated)"
    echo ""

    echo "Security Features:"
    echo "  - OpenFlow NAC (Network Access Control via fingerprints)"
    echo "  - Traffic mirroring to QSecBit (all traffic analyzed)"
    echo "  - Flat bridge for low-latency packet processing"
    echo "  - sFlow/IPFIX export for ML analysis"
    echo "  - VXLAN tunnels ready for mesh connectivity"
    echo "  - AI Device Fingerprinting (99%+ accuracy)"
    echo "  - Ecosystem Bubble (same-user device detection)"
    echo ""

    echo "Useful commands:"
    echo "  systemctl status fortress             # Check container status"
    echo "  systemctl status fts-hostapd-*        # Check WiFi AP status"
    echo "  systemctl status fts-fingerprint-engine  # AI fingerprinting"
    echo "  # Bubble detection: requires --enable-aiochi (runs as aiochi-bubble)"
    echo "  fortress-ctl fingerbank status        # Fingerbank API status"
    echo "  ovs-vsctl show                        # View OVS bridge"
    echo "  cat /etc/netplan/60-fortress-ovs.yaml # View netplan config"
    echo "  ${DEVICES_DIR}/common/ovs-post-setup.sh status"
    echo ""
}

main "$@"
