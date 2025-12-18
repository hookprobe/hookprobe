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
# Version: 5.2.0
# License: AGPL-3.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

           F O R T R E S S   v5.2.0
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

    # podman-compose check
    if ! command -v podman-compose &>/dev/null; then
        log_warn "podman-compose not found. Installing..."
        pip3 install podman-compose || {
            log_error "Failed to install podman-compose"
            exit 1
        }
    fi
    log_info "podman-compose: available"

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
# CONFIGURATION PROMPTS
# ============================================================
collect_configuration() {
    log_step "Configuration"

    # Network mode selection
    echo ""
    echo "Network Segmentation Mode:"
    echo "  1) filter  - nftables-based per-device filtering (simpler, recommended)"
    echo "  2) vlan    - OVS VLAN-based segmentation (requires OVS setup)"
    echo ""
    read -p "Select mode [1]: " mode_choice
    case "${mode_choice:-1}" in
        2|vlan)
            NETWORK_MODE="vlan"
            ;;
        *)
            NETWORK_MODE="filter"
            ;;
    esac
    log_info "Network mode: $NETWORK_MODE"

    # Security services are ALWAYS installed (core backbone of HookProbe mesh)
    # QSecBit, dnsXai, DFS intelligence are not optional
    INSTALL_ML=true
    BUILD_ML_CONTAINERS=true

    # LAN subnet configuration
    echo ""
    echo "LAN Subnet Size:"
    echo "  1) /24 - 254 devices (10.200.0.0/24) - recommended for most"
    echo "  2) /26 - 62 devices  (10.200.0.0/26) - small office"
    echo "  3) /28 - 14 devices  (10.200.0.0/28) - very small"
    echo ""
    read -p "Select subnet [1]: " subnet_choice
    case "${subnet_choice:-1}" in
        2)
            LAN_SUBNET_MASK="26"
            LAN_DHCP_START="10.200.0.10"
            LAN_DHCP_END="10.200.0.62"
            ;;
        3)
            LAN_SUBNET_MASK="28"
            LAN_DHCP_START="10.200.0.2"
            LAN_DHCP_END="10.200.0.14"
            ;;
        *)
            LAN_SUBNET_MASK="24"
            LAN_DHCP_START="10.200.0.100"
            LAN_DHCP_END="10.200.0.200"
            ;;
    esac
    log_info "LAN subnet: 10.200.0.0/$LAN_SUBNET_MASK"

    # Admin password
    echo ""
    echo "Admin Portal Access:"
    read -p "Admin username [admin]: " ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-admin}"

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

    # WiFi configuration
    echo ""
    echo "WiFi Access Point:"
    read -p "WiFi SSID [HookProbe-Fortress]: " WIFI_SSID
    WIFI_SSID="${WIFI_SSID:-HookProbe-Fortress}"

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

    # Port configuration
    echo ""
    read -p "Web UI port [8443]: " WEB_PORT
    WEB_PORT="${WEB_PORT:-8443}"

    # Confirm
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
    url: http://10.250.203.11:8428
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
FORTRESS_VERSION=5.0.0

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

    if [ "$NETWORK_MODE" = "filter" ] && [ "$NFTABLES_AVAILABLE" = true ]; then
        # Initialize nftables filter manager
        chmod +x "${DEVICES_DIR}/common/network-filter-manager.sh" 2>/dev/null || true
        "${DEVICES_DIR}/common/network-filter-manager.sh" init || {
            log_warn "Failed to initialize nftables filters (may need manual setup)"
        }
        log_info "nftables filter mode initialized"
    elif [ "$NETWORK_MODE" = "vlan" ]; then
        log_info "VLAN mode - OVS bridge will be configured"
    else
        log_warn "Network filtering not configured"
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
        export OVS_BRIDGE="fortress"
        export LAN_SUBNET_MASK="${LAN_SUBNET_MASK:-24}"

        # Initialize OVS bridge with all tiers
        "$ovs_script" init || {
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

        # Setup NAT if we have a WAN interface
        if [ -n "$NET_WAN_IFACE" ]; then
            "$ovs_script" nat "$NET_WAN_IFACE" || {
                log_warn "NAT setup had issues"
            }
        fi

        # Configure DHCP on OVS LAN port
        setup_ovs_dhcp

    else
        log_error "OVS network manager not found: $ovs_script"
        return 1
    fi

    # Setup WiFi AP (bridges to OVS)
    if [ -n "$NET_WIFI_24GHZ_IFACE" ] || [ -n "$NET_WIFI_5GHZ_IFACE" ]; then
        log_info "Configuring WiFi access point..."

        # Use the configured WIFI_SSID and WIFI_PASSWORD from collect_configuration()
        local wifi_ssid="${WIFI_SSID:-HookProbe-Fortress}"
        local wifi_pass="${WIFI_PASSWORD:-}"

        # Generate password if not set
        if [ -z "$wifi_pass" ]; then
            wifi_pass=$(openssl rand -base64 12 | tr -d '/+=' | head -c 12)
            WIFI_PASSWORD="$wifi_pass"  # Update global for final message
        fi

        if [ -f "$hostapd_script" ]; then
            # Prepare interfaces
            prepare_wifi_interfaces 2>/dev/null || true

            # Generate hostapd config with OVS bridge
            "$hostapd_script" configure "$wifi_ssid" "$wifi_pass" "fortress" || {
                log_warn "Hostapd configuration had issues"
            }

            # Create systemd services for WiFi
            create_wifi_services 2>/dev/null || true

            # Save WiFi credentials
            echo "WIFI_SSID=$wifi_ssid" >> "$CONFIG_DIR/fortress.conf"
            echo "$wifi_pass" > "$CONFIG_DIR/secrets/wifi_password"
            chmod 600 "$CONFIG_DIR/secrets/wifi_password"

            log_info "WiFi AP configured (bridged to OVS):"
            log_info "  SSID: $wifi_ssid"
            log_info "  2.4GHz: ${NET_WIFI_24GHZ_IFACE:-not configured}"
            log_info "  5GHz:   ${NET_WIFI_5GHZ_IFACE:-not configured}"
        else
            log_warn "Hostapd generator not found - WiFi not configured"
        fi
    else
        log_info "No WiFi interfaces detected - skipping AP setup"
        WIFI_SSID=""
        WIFI_PASSWORD=""
    fi

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-fortress-forward.conf

    log_info "OVS network infrastructure configured"
    log_info "  OpenFlow: Tier isolation rules installed"
    log_info "  Mirror:   Traffic mirroring to QSecBit enabled"
    log_info "  sFlow:    Flow export to 127.0.0.1:6343"
    log_info "  IPFIX:    Flow export to 127.0.0.1:4739"
}

setup_ovs_dhcp() {
    log_info "Configuring DHCP on OVS LAN port..."

    local lan_port="fortress-lan"
    local config_file="/etc/dnsmasq.d/fortress-ovs.conf"

    mkdir -p "$(dirname "$config_file")"

    cat > "$config_file" << EOF
# HookProbe Fortress DHCP Configuration (OVS)
# Generated: $(date -Iseconds)

# Bind to OVS LAN internal port
interface=${lan_port}
bind-interfaces

# LAN DHCP range (configured subnet: /${LAN_SUBNET_MASK:-24})
dhcp-range=${LAN_DHCP_START:-10.200.0.100},${LAN_DHCP_END:-10.200.0.200},12h

# Gateway (fortress OVS LAN port)
dhcp-option=3,10.200.0.1

# DNS (dnsXai via OVS - clients query gateway, forwarded to dnsXai)
dhcp-option=6,10.200.0.1

# Domain
domain=fortress.local
local=/fortress.local/

# Logging
log-dhcp
log-queries

# Cache
cache-size=1000

# Forward DNS to dnsXai container
server=10.250.201.11#5353
EOF

    chmod 644 "$config_file"

    # Restart dnsmasq
    systemctl restart dnsmasq 2>/dev/null || systemctl start dnsmasq 2>/dev/null || {
        log_warn "dnsmasq service not available"
    }

    log_info "DHCP configured on $lan_port"
}

build_containers() {
    log_step "Building container images"

    cd "$CONTAINERS_DIR"
    local repo_root="${SCRIPT_DIR}/../.."

    # Web container
    log_info "Building web container..."
    podman build -f Containerfile.web -t localhost/fortress-web:latest "$SCRIPT_DIR" || {
        log_error "Failed to build web container"
        exit 1
    }

    # Security Core - QSecBit, dnsXai, DFS (backbone of HookProbe mesh)
    log_info "Building security core containers..."

    log_info "  - Building qsecbit-agent (threat detection)..."
    podman build -f Containerfile.agent -t localhost/fortress-agent:latest "$repo_root" || {
        log_error "Failed to build qsecbit-agent container"
        exit 1
    }

    log_info "  - Building dnsxai (DNS ML protection)..."
    podman build -f Containerfile.dnsxai -t localhost/fortress-dnsxai:latest "$repo_root" || {
        log_error "Failed to build dnsxai container"
        exit 1
    }

    log_info "  - Building dfs-intelligence (WiFi intelligence)..."
    podman build -f Containerfile.dfs -t localhost/fortress-dfs:latest "$repo_root" || {
        log_error "Failed to build dfs-intelligence container"
        exit 1
    }

    # LSTM trainer is optional (used for retraining models)
    log_info "  - Building lstm-trainer (optional training)..."
    podman build -f Containerfile.lstm -t localhost/fortress-lstm:latest "$repo_root" || {
        log_warn "Failed to build lstm container (training will be unavailable)"
    }

    log_info "All security containers built successfully"
}

start_containers() {
    log_step "Starting containers"

    # Use the INSTALLED containers directory
    local compose_dir="${INSTALL_DIR}/containers"
    cd "$compose_dir"

    # Update compose file with configured port
    sed -i "s/8443:8443/${WEB_PORT}:8443/" podman-compose.yml 2>/dev/null || true

    # Start all services (security core + data tier)
    log_info "Starting Fortress services..."
    podman-compose up -d

    # Wait for services
    log_info "Waiting for services to be ready..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if curl -sf -k "https://localhost:${WEB_PORT}/health" &>/dev/null; then
            log_info "Services are ready"
            break
        fi
        sleep 2
        ((retries--))
    done

    if [ $retries -eq 0 ]; then
        log_warn "Services may not be fully ready - check logs"
    fi

    # Connect containers to OVS for flow monitoring
    connect_containers_to_ovs
}

connect_containers_to_ovs() {
    log_step "Connecting containers to OVS"

    local ovs_script="${DEVICES_DIR}/common/ovs-container-network.sh"

    if [ ! -f "$ovs_script" ]; then
        log_warn "OVS script not found - skipping container OVS integration"
        return 0
    fi

    # Give containers a moment to fully initialize
    sleep 3

    # Connect each container to its OVS tier via veth pair
    # This provides OpenFlow-controlled traffic monitoring alongside Podman networking

    log_info "Attaching containers to OVS bridge for flow monitoring..."

    # Data tier containers
    "$ovs_script" attach fortress-postgres 10.250.200.10 data 2>/dev/null || \
        log_warn "Could not attach postgres to OVS (may not be running)"
    "$ovs_script" attach fortress-redis 10.250.200.11 data 2>/dev/null || \
        log_warn "Could not attach redis to OVS (may not be running)"

    # Services tier containers
    "$ovs_script" attach fortress-web 10.250.201.10 services 2>/dev/null || \
        log_warn "Could not attach web to OVS (may not be running)"
    "$ovs_script" attach fortress-dnsxai 10.250.201.11 services 2>/dev/null || \
        log_warn "Could not attach dnsxai to OVS (may not be running)"
    "$ovs_script" attach fortress-dfs 10.250.201.12 services 2>/dev/null || \
        log_warn "Could not attach dfs to OVS (may not be running)"

    # ML tier (optional containers)
    "$ovs_script" attach fortress-lstm-trainer 10.250.202.10 ml 2>/dev/null || true

    # Mgmt tier (optional containers)
    "$ovs_script" attach fortress-grafana 10.250.203.10 mgmt 2>/dev/null || true
    "$ovs_script" attach fortress-victoria 10.250.203.11 mgmt 2>/dev/null || true

    log_info "Containers connected to OVS for OpenFlow monitoring"
    log_info "  Traffic mirroring: all container traffic → fortress-mirror"
    log_info "  sFlow export: 127.0.0.1:6343"
    log_info "  IPFIX export: 127.0.0.1:4739"
}

create_systemd_service() {
    log_step "Creating systemd service"

    # Build profile flags for optional services only
    # Security core (QSecBit, dnsXai, DFS) are always started - no profile needed
    local profile_flags=""
    # Monitoring profile (--profile monitoring) is optional and disabled by default
    # Enable with INSTALL_MONITORING=true before running install
    if [ "${INSTALL_MONITORING:-false}" = true ]; then
        profile_flags="--profile monitoring"
    fi
    profile_flags=$(echo "$profile_flags" | xargs)  # trim whitespace

    # Use the INSTALLED containers directory for systemd service
    local compose_dir="${INSTALL_DIR}/containers"
    local ovs_script="${INSTALL_DIR}/devices/common/ovs-container-network.sh"

    # Create OVS post-start hook script
    cat > "${INSTALL_DIR}/bin/fortress-ovs-connect.sh" << 'OVSEOF'
#!/bin/bash
# Connect fortress containers to OVS after startup
# Called by systemd ExecStartPost

OVS_SCRIPT="/opt/hookprobe/fortress/devices/common/ovs-container-network.sh"

# Wait for containers to be fully up
sleep 5

if [ -f "$OVS_SCRIPT" ]; then
    # Data tier
    "$OVS_SCRIPT" attach fortress-postgres 10.250.200.10 data 2>/dev/null || true
    "$OVS_SCRIPT" attach fortress-redis 10.250.200.11 data 2>/dev/null || true

    # Services tier
    "$OVS_SCRIPT" attach fortress-web 10.250.201.10 services 2>/dev/null || true
    "$OVS_SCRIPT" attach fortress-dnsxai 10.250.201.11 services 2>/dev/null || true
    "$OVS_SCRIPT" attach fortress-dfs 10.250.201.12 services 2>/dev/null || true

    # Optional tiers
    "$OVS_SCRIPT" attach fortress-lstm-trainer 10.250.202.10 ml 2>/dev/null || true
    "$OVS_SCRIPT" attach fortress-grafana 10.250.203.10 mgmt 2>/dev/null || true
    "$OVS_SCRIPT" attach fortress-victoria 10.250.203.11 mgmt 2>/dev/null || true
fi
OVSEOF

    mkdir -p "${INSTALL_DIR}/bin"
    chmod +x "${INSTALL_DIR}/bin/fortress-ovs-connect.sh"

    cat > /etc/systemd/system/fortress.service << EOF
[Unit]
Description=HookProbe Fortress Security Gateway
After=network.target openvswitch-switch.service
Requires=podman.socket openvswitch-switch.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${compose_dir}
ExecStart=/usr/bin/podman-compose ${profile_flags} -f podman-compose.yml up -d
ExecStartPost=${INSTALL_DIR}/bin/fortress-ovs-connect.sh
ExecStop=/usr/bin/podman-compose ${profile_flags} -f podman-compose.yml down
ExecReload=/usr/bin/podman-compose ${profile_flags} -f podman-compose.yml restart
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

    # Also save profile config for reference
    echo "FORTRESS_PROFILES=\"${profile_flags:-core}\"" >> /etc/hookprobe/fortress.conf

    systemctl daemon-reload
    systemctl enable fortress

    log_info "Systemd service created with OVS post-start hook"
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
    "version": "5.2.0",
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
    echo -e "${RED}This will remove:${NC}"
    echo "  - Fortress containers (web, postgres, redis, ML services)"
    [ "$keep_data" = false ] && echo "  - Database volumes (all user data)"
    [ "$keep_data" = false ] && echo "  - ML model data and blocklists"
    [ "$keep_config" = false ] && echo "  - Configuration files"
    echo "  - Container images"
    echo "  - Systemd service"
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
    systemctl stop fortress-ml 2>/dev/null || true
    cd "$CONTAINERS_DIR" 2>/dev/null && podman-compose --profile full --profile training down 2>/dev/null || true

    # Stage 2: Remove application containers
    log_info "Stage 2: Removing application containers..."
    podman rm -f fortress-web fortress-qsecbit fortress-dnsxai fortress-dfs fortress-lstm-trainer 2>/dev/null || true

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
            fortress-redis-data \
            fortress-web-data \
            fortress-web-logs \
            fortress-agent-data \
            fortress-dnsxai-data \
            fortress-dnsxai-blocklists \
            fortress-dfs-data \
            fortress-ml-models \
            fortress-config \
            2>/dev/null || true
    else
        log_info "Stage 3: Preserving data containers and volumes..."
        # Only stop data containers, don't remove
        podman stop fortress-postgres fortress-redis 2>/dev/null || true
    fi

    # Stage 4: Remove systemd service
    log_info "Stage 4: Removing systemd service..."
    systemctl disable fortress 2>/dev/null || true
    rm -f /etc/systemd/system/fortress.service
    systemctl daemon-reload

    # Stage 5: Remove network configuration
    log_info "Stage 5: Removing network filters..."
    nft delete table inet fortress_filter 2>/dev/null || true

    # Stage 6: Handle configuration
    if [ "$keep_config" = false ]; then
        log_info "Stage 6: Removing configuration..."
        rm -f "$CONFIG_DIR/fortress.conf" 2>/dev/null || true
        rm -f "$CONFIG_DIR/users.json" 2>/dev/null || true
        rm -f "$STATE_FILE" 2>/dev/null || true
        rm -rf "${CONTAINERS_DIR}/secrets" 2>/dev/null || true
    else
        log_info "Stage 6: Preserving configuration..."
    fi

    # Stage 7: Remove installation directory
    log_info "Stage 7: Removing installation files..."
    rm -rf "$INSTALL_DIR/web" "$INSTALL_DIR/lib" 2>/dev/null || true
    [ "$keep_data" = false ] && rm -rf "$INSTALL_DIR" "$DATA_DIR" 2>/dev/null || true

    # Clean empty directories
    rmdir "$INSTALL_DIR" 2>/dev/null || true
    rmdir /opt/hookprobe 2>/dev/null || true

    echo ""
    log_info "Uninstall complete!"
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
    fi
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
    # Subnet defaults
    LAN_SUBNET_MASK="24"
    LAN_DHCP_START="10.200.0.100"
    LAN_DHCP_END="10.200.0.200"

    log_warn "Quick install with default credentials"
    log_warn "Admin: admin / hookprobe - CHANGE THIS IMMEDIATELY!"
    log_warn "WiFi:  HookProbe-Fortress / hookprobe123"
}

# ============================================================
# MAIN
# ============================================================
main() {
    show_banner

    case "${1:-}" in
        --uninstall|uninstall|remove)
            shift || true
            check_prerequisites
            uninstall "$@"
            exit 0
            ;;
        --quick|quick)
            check_prerequisites
            quick_install
            ;;
        --preserve-data)
            check_prerequisites
            log_info "Reinstalling with preserved data..."
            PRESERVE_DATA=true
            collect_configuration
            ;;
        --help|help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Installation Options:"
            echo "  (none)          Interactive installation"
            echo "  --quick         Quick install with defaults"
            echo "  --preserve-data Reinstall using existing data volumes"
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
            check_prerequisites
            collect_configuration
            ;;
    esac

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
    echo -e "  Bridge:     fortress (OVS with OpenFlow 1.3+)"
    echo -e "  LAN Tier:   10.200.0.0/${LAN_SUBNET_MASK:-24}"
    echo -e "  DHCP:       ${LAN_DHCP_START:-10.200.0.100} - ${LAN_DHCP_END:-10.200.0.200}"
    echo ""
    echo "Container Network Tiers (isolated via OpenFlow):"
    echo "  Data Tier:     10.250.200.0/24 (postgres, redis) - NO internet"
    echo "  Services Tier: 10.250.201.0/24 (web, dnsxai, dfs) - internet OK"
    echo "  ML Tier:       10.250.202.0/24 (lstm-trainer) - NO internet"
    echo "  Mgmt Tier:     10.250.203.0/24 (grafana, victoria) - NO internet"
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
    echo "  ovs-ofctl dump-flows fortress         # View OpenFlow rules"
    echo "  ${DEVICES_DIR}/common/ovs-container-network.sh status"
    echo ""
}

main "$@"
