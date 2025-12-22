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
# Version: 5.4.0
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

           F O R T R E S S   v5.4.0
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

    # Network connectivity check - required for package installation
    log_info "Checking network connectivity..."
    if ! timeout 5 bash -c 'exec 3<>/dev/tcp/archive.ubuntu.com/80' 2>/dev/null; then
        # Try DNS resolution
        if ! timeout 5 bash -c 'exec 3<>/dev/tcp/8.8.8.8/53' 2>/dev/null; then
            log_error "No network connectivity detected!"
            log_error "Cannot reach archive.ubuntu.com or 8.8.8.8"
            log_error "Please ensure the WAN interface has internet access before running install"
            log_error ""
            log_error "Check your network with:"
            log_error "  ip route show default"
            log_error "  cat /etc/resolv.conf"
            log_error "  ping -c1 8.8.8.8"
            exit 1
        else
            # IP works but DNS doesn't - fix resolv.conf
            log_warn "DNS resolution not working, adding fallback nameserver..."
            if ! grep -q "nameserver" /etc/resolv.conf 2>/dev/null; then
                echo "nameserver 1.1.1.1" >> /etc/resolv.conf
                echo "nameserver 8.8.8.8" >> /etc/resolv.conf
            fi
        fi
    fi
    log_info "Network connectivity: OK"

    # Open vSwitch (required for secure container networking)
    if ! command -v ovs-vsctl &>/dev/null; then
        log_warn "Open vSwitch not found. Installing..."
        apt-get update
        apt-get install -y openvswitch-switch || {
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
        apt-get update
        apt-get install -y dnsmasq || {
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
        apt-get update
        apt-get install -y podman podman-compose || {
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
        apt-get update
        # shellcheck disable=SC2086
        apt-get install -y $wifi_packages_needed || {
            log_error "Failed to install WiFi packages: $wifi_packages_needed"
            exit 1
        }
        # Unmask hostapd - Debian/Ubuntu ship it masked by default
        systemctl unmask hostapd 2>/dev/null || true
    fi
    log_info "hostapd: $(hostapd -v 2>&1 | head -1 || echo 'available')"
    log_info "iw: $(iw --version 2>&1 | head -1 || echo 'available')"

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
#   NETWORK_MODE                       - filter or vlan (default: filter)
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
    NETWORK_MODE="${NETWORK_MODE:-filter}"
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

        # Show configuration summary
        log_info "Configuration:"
        log_info "  Network Mode:  $NETWORK_MODE"
        log_info "  LAN Subnet:    10.200.0.0/$LAN_SUBNET_MASK"
        log_info "  Admin User:    $ADMIN_USER"
        log_info "  WiFi SSID:     $WIFI_SSID"
        log_info "  Web Port:      $WEB_PORT"
        return 0
    fi

    # ============================================================
    # Interactive mode - prompt for any missing configuration
    # ============================================================

    # Network mode - nftables filter is the only implemented mode
    # VLAN mode was planned but not implemented, so we default to filter
    NETWORK_MODE="filter"
    log_info "Network mode: nftables filter (per-device policies)"

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

    # Confirm installation
    echo ""
    echo "Installation Summary:"
    echo "====================="
    echo "  Network Mode:  $NETWORK_MODE"
    echo "  LAN Subnet:    10.200.0.0/$LAN_SUBNET_MASK (DHCP: $LAN_DHCP_START - $LAN_DHCP_END)"
    echo "  Security Core: QSecBit + dnsXai + DFS Intelligence"
    echo "  Admin User:    $ADMIN_USER"
    echo "  WiFi SSID:     $WIFI_SSID"
    echo "  Web Port:      $WEB_PORT"
    echo "  Install Dir:   $INSTALL_DIR"
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
create_directories() {
    log_step "Creating directories"

    mkdir -p "$INSTALL_DIR"/{web,lib,data,backups,containers/secrets}
    mkdir -p "$CONFIG_DIR/secrets"
    mkdir -p "$LOG_DIR"

    chmod 755 "$INSTALL_DIR" "$CONFIG_DIR"
    chmod 700 "$INSTALL_DIR/containers/secrets"
    chmod 700 "$CONFIG_DIR/secrets"
    chmod 755 "$LOG_DIR"

    log_info "Directories created"
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
    url: http://172.20.203.11:8428
    isDefault: true
    editable: false
EOF

    # Copy device profiles
    mkdir -p "${INSTALL_DIR}/devices"
    cp -r "${DEVICES_DIR}/"* "${INSTALL_DIR}/devices/" 2>/dev/null || true

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

    # Save admin password for display
    echo "${ADMIN_PASS}" > "${CONFIG_DIR}/secrets/admin_password"
    chmod 600 "${CONFIG_DIR}/secrets/admin_password"

    log_info "Secrets generated in $secrets_dir"
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
    chmod 600 "$CONFIG_DIR/users.json"
    log_info "Admin user created"
}

create_configuration() {
    log_step "Creating configuration"

    cat > "$CONFIG_DIR/fortress.conf" << EOF
# HookProbe Fortress Configuration
# Generated: $(date -Iseconds)

# Deployment mode
FORTRESS_MODE=container
FORTRESS_VERSION=5.4.0

# Network mode (vlan or filter)
NETWORK_MODE=${NETWORK_MODE}

# Database (handled by container)
DATABASE_HOST=fortress-postgres
DATABASE_PORT=5432
DATABASE_NAME=fortress
DATABASE_USER=fortress

# Redis (handled by container)
REDIS_HOST=fortress-redis
REDIS_PORT=6379

# Web UI
WEB_PORT=${WEB_PORT}
WEB_SSL=true

# Logging
LOG_LEVEL=info
LOG_DIR=${LOG_DIR}
EOF

    chmod 644 "$CONFIG_DIR/fortress.conf"
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
    log_info "  WiFi: ${NET_WIFI_24GHZ_IFACE:-none} (2.4G) / ${NET_WIFI_5GHZ_IFACE:-none} (5G)"
    log_info "  LTE:  ${NET_WWAN_IFACE:-none}"

    # Initialize OVS network fabric
    log_info "Initializing OVS network fabric..."
    if [ -f "$ovs_script" ]; then
        # Export configuration for OVS script
        export OVS_BRIDGE="43ess"
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

        # Configure DHCP on OVS LAN port
        setup_ovs_dhcp

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
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-fortress-forward.conf

    # NOTE: WiFi udev rules creation is handled above in the conditional blocks
    # (lines 707 and 736) - we don't need a redundant unconditional call here
    # as it would overwrite any successful rules created earlier

    log_info "OVS network infrastructure configured"
    log_info "  OpenFlow: Tier isolation rules installed"
    log_info "  Mirror:   Traffic mirroring to QSecBit enabled"
    log_info "  sFlow:    Flow export to 127.0.0.1:6343"
    log_info "  IPFIX:    Flow export to 127.0.0.1:4739"
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

    local udev_rule_file="/etc/udev/rules.d/70-fortress-wifi.rules"

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
# WIFI SERVICES WITH STABLE NAMES - PHASE 3
# ============================================================
create_wifi_services_stable() {
    # Create systemd services for WiFi APs using stable interface names
    # This is called AFTER hostapd configs are generated

    log_info "Phase 3: Creating WiFi services with stable names..."

    local ovs_bridge="${OVS_BRIDGE:-43ess}"

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

        cat > /etc/systemd/system/fortress-hostapd-24ghz.service << EOF
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
ExecStartPre=-/sbin/ip link set ${WIFI_24GHZ_STABLE} down
ExecStartPre=/bin/sleep 0.5
ExecStartPre=/sbin/ip link set ${WIFI_24GHZ_STABLE} up
ExecStart=${hostapd_bin} -B -P /run/hostapd-24ghz.pid /etc/hostapd/hostapd-24ghz.conf
ExecStartPost=-/usr/bin/ovs-vsctl --may-exist add-port ${ovs_bridge} ${WIFI_24GHZ_STABLE}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable fortress-hostapd-24ghz 2>/dev/null || true
        log_info "  Created: fortress-hostapd-24ghz.service (uses $WIFI_24GHZ_STABLE)"
    fi

    # 5GHz service
    if [ -n "$WIFI_5GHZ_DETECTED" ] && [ -f /etc/hostapd/hostapd-5ghz.conf ]; then
        local dev_unit="sys-subsystem-net-devices-${WIFI_5GHZ_STABLE}.device"

        cat > /etc/systemd/system/fortress-hostapd-5ghz.service << EOF
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
ExecStartPre=-/sbin/ip link set ${WIFI_5GHZ_STABLE} down
ExecStartPre=/bin/sleep 0.5
ExecStartPre=/sbin/ip link set ${WIFI_5GHZ_STABLE} up
ExecStart=${hostapd_bin} -B -P /run/hostapd-5ghz.pid /etc/hostapd/hostapd-5ghz.conf
ExecStartPost=-/usr/bin/ovs-vsctl --may-exist add-port ${ovs_bridge} ${WIFI_5GHZ_STABLE}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable fortress-hostapd-5ghz 2>/dev/null || true
        log_info "  Created: fortress-hostapd-5ghz.service (uses $WIFI_5GHZ_STABLE)"
    fi

    log_info "Phase 3 complete: Services created"

    # Start hostapd services now (don't wait for reboot)
    log_info "Starting WiFi access points..."
    if [ -n "$WIFI_24GHZ_DETECTED" ] && [ -f /etc/hostapd/hostapd-24ghz.conf ]; then
        if systemctl start fortress-hostapd-24ghz 2>/dev/null; then
            log_info "  2.4GHz AP started"
        else
            log_warn "  2.4GHz AP failed to start - check: journalctl -u fortress-hostapd-24ghz"
        fi
    fi
    if [ -n "$WIFI_5GHZ_DETECTED" ] && [ -f /etc/hostapd/hostapd-5ghz.conf ]; then
        if systemctl start fortress-hostapd-5ghz 2>/dev/null; then
            log_info "  5GHz AP started"
        else
            log_warn "  5GHz AP failed to start - check: journalctl -u fortress-hostapd-5ghz"
        fi
    fi
}

setup_ovs_dhcp() {
    log_info "Configuring DHCP on OVS bridge..."

    # Use the OVS bridge directly - dnsmasq binds to the bridge interface
    local lan_port="${OVS_BRIDGE:-43ess}"
    local config_file="/etc/dnsmasq.d/fortress-ovs.conf"

    mkdir -p "$(dirname "$config_file")"

    cat > "$config_file" << EOF
# HookProbe Fortress DHCP Configuration (OVS)
# Generated: $(date -Iseconds)

# Bind to OVS bridge interface
interface=${lan_port}
bind-interfaces

# Don't read /etc/resolv.conf - use our explicit servers
no-resolv
no-poll

# LAN DHCP range (configured subnet: /${LAN_SUBNET_MASK:-24})
dhcp-range=${LAN_DHCP_START:-10.200.0.100},${LAN_DHCP_END:-10.200.0.200},12h

# Gateway (fortress OVS LAN port)
dhcp-option=3,10.200.0.1

# DNS (clients query dnsmasq on gateway, which forwards to dnsXai or upstream)
dhcp-option=6,10.200.0.1

# Domain
domain=fortress.local
local=/fortress.local/

# Logging
log-dhcp
log-queries

# Cache
cache-size=1000

# Forward DNS to dnsXai container (published on host port 5353)
# Use 127.0.0.1 since dnsXai publishes port 5353 to host
server=127.0.0.1#5353

# Fallback upstream DNS servers (used if dnsXai is unreachable)
server=1.1.1.1
server=8.8.8.8
EOF

    chmod 644 "$config_file"

    # Restart dnsmasq
    systemctl restart dnsmasq 2>/dev/null || systemctl start dnsmasq 2>/dev/null || {
        log_warn "dnsmasq service not available"
    }

    log_info "DHCP configured on $lan_port"
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

    # Web container - needs fortress root dir as context (contains web/ directory)
    if needs_rebuild "localhost/fortress-web:latest" "Containerfile.web" "$FORTRESS_ROOT"; then
        log_info "Building web container..."
        podman build -f Containerfile.web -t localhost/fortress-web:latest "$FORTRESS_ROOT" || {
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

    if needs_rebuild "localhost/fortress-agent:latest" "Containerfile.agent" "$repo_root"; then
        log_info "  - Building qsecbit-agent (threat detection)..."
        podman build -f Containerfile.agent -t localhost/fortress-agent:latest "$repo_root" || {
            log_error "Failed to build qsecbit-agent container"
            exit 1
        }
        built_count=$((built_count + 1))
    else
        log_info "  - Skipping qsecbit-agent (already built)"
        skipped_count=$((skipped_count + 1))
    fi

    if needs_rebuild "localhost/fortress-dnsxai:latest" "Containerfile.dnsxai" "$repo_root"; then
        log_info "  - Building dnsxai (DNS ML protection)..."
        podman build -f Containerfile.dnsxai -t localhost/fortress-dnsxai:latest "$repo_root" || {
            log_error "Failed to build dnsxai container"
            exit 1
        }
        built_count=$((built_count + 1))
    else
        log_info "  - Skipping dnsxai (already built)"
        skipped_count=$((skipped_count + 1))
    fi

    if needs_rebuild "localhost/fortress-dfs:latest" "Containerfile.dfs" "$repo_root"; then
        log_info "  - Building dfs-intelligence (WiFi intelligence)..."
        podman build -f Containerfile.dfs -t localhost/fortress-dfs:latest "$repo_root" || {
            log_error "Failed to build dfs-intelligence container"
            exit 1
        }
        built_count=$((built_count + 1))
    else
        log_info "  - Skipping dfs-intelligence (already built)"
        skipped_count=$((skipped_count + 1))
    fi

    # LSTM trainer is optional (used for retraining models)
    if needs_rebuild "localhost/fortress-lstm:latest" "Containerfile.lstm" "$repo_root"; then
        log_info "  - Building lstm-trainer (optional training)..."
        podman build -f Containerfile.lstm -t localhost/fortress-lstm:latest "$repo_root" || {
            log_warn "Failed to build lstm container (training will be unavailable)"
        }
        built_count=$((built_count + 1))
    else
        log_info "  - Skipping lstm-trainer (already built)"
        skipped_count=$((skipped_count + 1))
    fi

    if [ "$built_count" -gt 0 ]; then
        log_info "Built $built_count container(s), skipped $skipped_count"
    else
        log_info "All containers already built (use --force-rebuild to rebuild)"
    fi
}

start_containers() {
    log_step "Starting containers"

    # Use the INSTALLED containers directory
    local compose_dir="${INSTALL_DIR}/containers"
    cd "$compose_dir"

    # Export WEB_PORT for podman-compose (web container uses host network with GUNICORN_BIND)
    export WEB_PORT="${WEB_PORT:-8443}"

    # Start all services (security core + data tier)
    log_info "Starting Fortress services..."
    log_info "Web UI will be available on port ${WEB_PORT}"
    podman-compose up -d

    # Wait for services in dependency order
    log_info "Waiting for services to be ready..."

    # Phase 1: Wait for data tier (postgres, redis) - no dependencies
    log_info "  Waiting for data tier (postgres, redis)..."
    wait_for_container_healthy "fortress-postgres" 60 || log_warn "postgres may not be healthy"
    wait_for_container_healthy "fortress-redis" 30 || log_warn "redis may not be healthy"

    # Phase 2: Wait for independent services (dnsxai, dfs) - no dependencies
    log_info "  Waiting for services tier (dnsxai, dfs)..."
    wait_for_container_running "fortress-dnsxai" 30 || log_warn "dnsxai may not be running"
    wait_for_container_running "fortress-dfs" 30 || log_warn "dfs may not be running"

    # Phase 3: Wait for dependent services (web, qsecbit) - depend on postgres/redis
    log_info "  Waiting for application tier (web, qsecbit)..."
    wait_for_container_running "fortress-web" 30 || log_warn "web may not be running"
    wait_for_container_running "fortress-qsecbit" 30 || log_warn "qsecbit may not be running"

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
        log_warn "Web health check failed - check logs: podman logs fortress-web"
    fi

    # Connect containers to OVS for flow monitoring
    connect_containers_to_ovs
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

    if [ ! -f "$ovs_script" ]; then
        log_warn "OVS script not found - skipping container OVS integration"
        return 0
    fi

    # Connect each container to its OVS tier via veth pair
    # This provides OpenFlow-controlled traffic monitoring alongside Podman networking
    #
    # NOTE: Containers using network_mode: host (web, qsecbit) cannot be attached to OVS
    # They share the host network namespace and are already visible to OVS via host interfaces

    log_info "Attaching containers to OVS bridge for flow monitoring..."

    # Data tier containers (always required)
    attach_container_if_running "$ovs_script" fortress-postgres 172.20.200.10 data
    attach_container_if_running "$ovs_script" fortress-redis 172.20.200.11 data

    # Services tier containers (dnsxai and dfs use bridge network)
    # Note: web uses host network - already visible via host interfaces
    attach_container_if_running "$ovs_script" fortress-dnsxai 172.20.201.11 services
    attach_container_if_running "$ovs_script" fortress-dfs 172.20.201.12 services

    # Note: qsecbit uses host network - already visible via host interfaces
    # It captures traffic on host interfaces directly

    # ML tier (optional - only with --profile training)
    attach_container_if_running "$ovs_script" fortress-lstm-trainer 172.20.202.10 ml true

    # Mgmt tier (optional - only with --profile monitoring)
    attach_container_if_running "$ovs_script" fortress-grafana 172.20.203.10 mgmt true
    attach_container_if_running "$ovs_script" fortress-victoria 172.20.203.11 mgmt true

    log_info "OVS container integration complete"
    log_info "  Note: web and qsecbit use host network (no OVS attachment needed)"
    log_info "  Traffic mirroring: all bridge container traffic → fortress-mirror"
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
            log_warn "  $container: failed to attach to OVS"
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
    cat > "${INSTALL_DIR}/bin/fortress-ovs-connect.sh" << 'OVSEOF'
#!/bin/bash
# Connect fortress containers to OVS after startup
# Called by systemd ExecStartPost

OVS_SCRIPT="/opt/hookprobe/fortress/devices/common/ovs-container-network.sh"
LOG_TAG="fortress-ovs"

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
OVS_BRIDGE="${OVS_BRIDGE:-43ess}"
LAN_BASE_IP="${LAN_BASE_IP:-10.200.0.1}"
LAN_SUBNET_MASK="${LAN_SUBNET_MASK:-24}"

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

# Ensure gateway IP is assigned
if ! ip addr show "$OVS_BRIDGE" 2>/dev/null | grep -q "${LAN_BASE_IP}/"; then
    log_info "Assigning gateway IP ${LAN_BASE_IP}/${LAN_SUBNET_MASK}..."
    ip addr add "${LAN_BASE_IP}/${LAN_SUBNET_MASK}" dev "$OVS_BRIDGE" 2>/dev/null || log_warn "IP already assigned or failed"
fi

# Reinstall OpenFlow rules (they are not persisted across OVS restart)
log_info "Installing OpenFlow rules..."
export OVS_BRIDGE LAN_SUBNET_MASK
"$OVS_SCRIPT" flows 2>/dev/null || log_warn "Failed to install OpenFlow rules"

log_info "Waiting for containers..."

# Wait for core containers first
wait_for_container fortress-postgres || log_warn "postgres not ready"
wait_for_container fortress-redis || log_warn "redis not ready"

# Now attach all containers
log_info "Attaching containers to OVS..."

# Data tier (required)
attach_if_ready fortress-postgres 172.20.200.10 data
attach_if_ready fortress-redis 172.20.200.11 data

# Services tier (dnsxai and dfs use bridge network)
attach_if_ready fortress-dnsxai 172.20.201.11 services
attach_if_ready fortress-dfs 172.20.201.12 services

# Optional tiers
attach_if_ready fortress-lstm-trainer 172.20.202.10 ml true
attach_if_ready fortress-grafana 172.20.203.10 mgmt true
attach_if_ready fortress-victoria 172.20.203.11 mgmt true

log_info "OVS container integration complete"
OVSEOF

    chmod +x "${INSTALL_DIR}/bin/fortress-ovs-connect.sh"

    # Find podman-compose path (may be in /usr/bin or ~/.local/bin)
    local podman_compose_bin
    podman_compose_bin=$(command -v podman-compose || echo "/usr/bin/podman-compose")

    cat > /etc/systemd/system/fortress.service << EOF
[Unit]
Description=HookProbe Fortress Security Gateway
# Wait for network and container runtime
After=network-online.target openvswitch-switch.service podman.socket podman.service
Wants=network-online.target openvswitch-switch.service
Requires=podman.socket
# Prevent rapid restarts on repeated failures
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${compose_dir}
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.local/bin

# Wait for podman to be fully ready (max 60 seconds)
ExecStartPre=/bin/bash -c 'for i in \$(seq 1 60); do podman info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'

# Start containers
ExecStart=${podman_compose_bin} -f podman-compose.yml up -d

# Connect to OVS after containers are up
ExecStartPost=${INSTALL_DIR}/bin/fortress-ovs-connect.sh

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
# STATE MANAGEMENT
# ============================================================
STATE_FILE="${CONFIG_DIR}/fortress-state.json"

save_installation_state() {
    log_step "Saving installation state"

    mkdir -p "$(dirname "$STATE_FILE")"

    # All security core containers are always installed
    local containers='["fortress-web", "fortress-postgres", "fortress-redis", "fortress-qsecbit", "fortress-dnsxai", "fortress-dfs"]'
    local volumes='["fortress-postgres-data", "fortress-redis-data", "fortress-web-data", "fortress-web-logs", "fortress-config", "fortress-agent-data", "fortress-dnsxai-data", "fortress-dnsxai-blocklists", "fortress-dfs-data", "fortress-ml-models"]'

    cat > "$STATE_FILE" << EOF
{
    "deployment_mode": "container",
    "version": "5.4.0",
    "installed_at": "$(date -Iseconds)",
    "network_mode": "${NETWORK_MODE}",
    "security_core": true,
    "web_port": "${WEB_PORT}",
    "admin_user": "${ADMIN_USER}",
    "containers": ${containers},
    "volumes": ${volumes}
}
EOF

    chmod 600 "$STATE_FILE"

    # Create VERSION file
    echo "5.2.0" > "${INSTALL_DIR}/VERSION"

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
    echo "  --purge       : Remove everything"
    echo ""
    echo -e "${RED}Components to be removed:${NC}"
    echo ""
    echo "  Services:"
    echo "    - fortress (main systemd service)"
    echo "    - fortress-hostapd-* (WiFi AP services)"
    echo ""
    echo "  Containers:"
    echo "    - fortress-web (Flask admin portal)"
    echo "    - fortress-postgres (database)"
    echo "    - fortress-redis (cache/sessions)"
    echo "    - fortress-qsecbit (threat detection)"
    echo "    - fortress-dnsxai (DNS ML protection)"
    echo "    - fortress-dfs (WiFi DFS intelligence)"
    echo "    - fortress-lstm-trainer (ML training)"
    echo "    - fortress-grafana (monitoring dashboard)"
    echo "    - fortress-victoria (metrics database)"
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
    echo "  DHCP config: /etc/dnsmasq.d/fortress-ovs.conf"
    echo "  WiFi config: /etc/hostapd/fortress-*.conf"
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
    systemctl stop fortress-hostapd-2g 2>/dev/null || true
    systemctl stop fortress-hostapd-5g 2>/dev/null || true
    cd "${INSTALL_DIR}/containers" 2>/dev/null && \
        podman-compose --profile monitoring --profile training down 2>/dev/null || true

    # Stage 2: Remove application containers
    log_info "Stage 2: Removing application containers..."
    podman rm -f fortress-web fortress-qsecbit fortress-dnsxai fortress-dfs fortress-lstm-trainer 2>/dev/null || true
    podman rm -f fortress-grafana fortress-victoria 2>/dev/null || true

    # Stage 2b: Remove container images
    log_info "Stage 2b: Removing container images..."
    podman rmi -f localhost/fortress-web:latest 2>/dev/null || true
    podman rmi -f localhost/fortress-agent:latest 2>/dev/null || true
    podman rmi -f localhost/fortress-dnsxai:latest 2>/dev/null || true
    podman rmi -f localhost/fortress-dfs:latest 2>/dev/null || true
    podman rmi -f localhost/fortress-lstm:latest 2>/dev/null || true

    # Stage 3: Handle data containers/volumes
    if [ "$keep_data" = false ]; then
        log_info "Stage 3: Removing data containers and volumes..."
        podman rm -f fortress-postgres fortress-redis 2>/dev/null || true
        # Remove all Fortress volumes
        podman volume rm -f \
            fortress-postgres-data \
            fortress-postgres-certs \
            fortress-redis-data \
            fortress-web-data \
            fortress-web-logs \
            fortress-agent-data \
            fortress-dnsxai-data \
            fortress-dnsxai-blocklists \
            fortress-dfs-data \
            fortress-ml-models \
            fortress-grafana-data \
            fortress-victoria-data \
            fortress-config \
            2>/dev/null || true
    else
        log_info "Stage 3: Preserving data containers and volumes..."
        # Only stop data containers, don't remove
        podman stop fortress-postgres fortress-redis 2>/dev/null || true
    fi

    # Stage 4: Remove systemd services
    log_info "Stage 4: Removing systemd services..."
    systemctl disable fortress 2>/dev/null || true
    systemctl disable fortress-hostapd-2g 2>/dev/null || true
    systemctl disable fortress-hostapd-5g 2>/dev/null || true
    rm -f /etc/systemd/system/fortress.service
    rm -f /etc/systemd/system/fortress-hostapd-*.service
    systemctl daemon-reload

    # Stage 5: Remove OVS network configuration
    log_info "Stage 5: Removing OVS network..."

    # Remove container veth interfaces from OVS
    for veth in veth-fortress-postgres veth-fortress-redis veth-fortress-web \
                veth-fortress-dnsxai veth-fortress-dfs veth-fortress-lstm-trainer \
                veth-fortress-grafana veth-fortress-victoria; do
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
    rm -f /etc/dnsmasq.d/fortress-ovs.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/fortress-bridge.conf 2>/dev/null || true
    rm -f /etc/hostapd/fortress-*.conf 2>/dev/null || true
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

    # Remove sysctl config
    rm -f /etc/sysctl.d/99-fortress-forward.conf 2>/dev/null || true

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
        echo "    podman volume rm fortress-postgres-data fortress-redis-data"
        echo ""
    fi

    if [ "$keep_config" = true ]; then
        echo "Configuration preserved in: $CONFIG_DIR"
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
    NETWORK_MODE="filter"
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
            --enable-monitoring)
                export INSTALL_MONITORING=true
                ;;
            --enable-n8n)
                # n8n addon - handled separately
                ;;
            --enable-clickhouse)
                # ClickHouse addon - handled separately
                ;;
            --enable-remote-access)
                # Cloudflare tunnel - config already saved by root installer
                ;;
            --enable-lte)
                # LTE failover - handled by network scripts
                ;;
            --lte-apn|--lte-auth|--lte-user|--lte-pass)
                # Skip LTE config args (followed by value)
                shift
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
                echo "Environment Variables (for --non-interactive):"
                echo "  WIFI_SSID           WiFi network name"
                echo "  WIFI_PASSWORD       WiFi password"
                echo "  FORTRESS_NETWORK_PREFIX  Subnet mask (e.g., 23)"
                echo "  ADMIN_USER          Admin username"
                echo "  ADMIN_PASS          Admin password"
                echo "  WEB_PORT            Web UI port"
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
    save_installation_state

    # Final message
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${GREEN}  HookProbe Fortress Installation Complete!${NC}"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "Access the admin portal at:"
    echo -e "  ${CYAN}https://localhost:${WEB_PORT}${NC}"
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
    echo "OVS Network Configuration:"
    echo -e "  Bridge:     $OVS_BRIDGE (OVS with OpenFlow 1.3+)"
    echo -e "  LAN Tier:   10.200.0.0/${LAN_SUBNET_MASK:-24}"
    echo -e "  DHCP:       ${LAN_DHCP_START:-10.200.0.100} - ${LAN_DHCP_END:-10.200.0.200}"
    echo ""
    echo "Container Network Tiers (isolated via OpenFlow):"
    echo "  Data Tier:     172.20.200.0/24 (postgres, redis) - NO internet"
    echo "  Services Tier: 172.20.201.0/24 (web, dnsxai, dfs) - internet OK"
    echo "  ML Tier:       172.20.202.0/24 (lstm-trainer) - NO internet"
    echo "  Mgmt Tier:     172.20.203.0/24 (grafana, victoria) - NO internet"
    echo ""
    echo "Security Features:"
    echo "  - OpenFlow tier isolation (containers can't reach unauthorized tiers)"
    echo "  - Traffic mirroring to QSecBit (all traffic analyzed)"
    echo "  - sFlow/IPFIX export for ML analysis"
    echo "  - QoS meters for rate limiting threats"
    echo "  - VXLAN tunnels ready for mesh connectivity"
    echo ""
    echo "Useful commands:"
    echo "  systemctl status fortress             # Check container status"
    echo "  systemctl status fortress-hostapd-*   # Check WiFi AP status"
    echo "  ovs-vsctl show                        # View OVS bridge"
    echo "  ovs-ofctl dump-flows $OVS_BRIDGE         # View OpenFlow rules"
    echo "  ${DEVICES_DIR}/common/ovs-container-network.sh status"
    echo ""
}

main "$@"
