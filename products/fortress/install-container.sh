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

    # Check for nftables (optional, for filter mode)
    if command -v nft &>/dev/null; then
        log_info "nftables: available"
        NFTABLES_AVAILABLE=true
    else
        log_warn "nftables not found (filter mode will not be available)"
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

    # ML/AI services selection
    echo ""
    echo "ML/AI Services:"
    echo "  1) Core only  - Web UI, database, cache (lightweight)"
    echo "  2) Full       - Include QSecBit, dnsXai, DFS intelligence (recommended)"
    echo ""
    echo "  Full mode includes:"
    echo "    - QSecBit threat detection (numpy, scipy, sklearn)"
    echo "    - dnsXai DNS ML protection"
    echo "    - DFS WiFi channel intelligence"
    echo "    - LSTM threat pattern training"
    echo ""
    read -p "Select mode [2]: " ml_choice
    case "${ml_choice:-2}" in
        1|core)
            INSTALL_ML=false
            BUILD_ML_CONTAINERS=false
            ;;
        *)
            INSTALL_ML=true
            BUILD_ML_CONTAINERS=true
            ;;
    esac
    log_info "ML services: $([ "$INSTALL_ML" = true ] && echo "enabled" || echo "disabled")"

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

    # Port configuration
    echo ""
    read -p "Web UI port [8443]: " WEB_PORT
    WEB_PORT="${WEB_PORT:-8443}"

    # Confirm
    echo ""
    echo "Installation Summary:"
    echo "====================="
    echo "  Network Mode:  $NETWORK_MODE"
    echo "  ML Services:   $([ "$INSTALL_ML" = true ] && echo "Full (QSecBit, dnsXai, DFS)" || echo "Core only")"
    echo "  Admin User:    $ADMIN_USER"
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

    mkdir -p "$INSTALL_DIR"/{web,lib,data,backups}
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "${CONTAINERS_DIR}/secrets"

    chmod 755 "$INSTALL_DIR" "$CONFIG_DIR"
    chmod 700 "${CONTAINERS_DIR}/secrets"
    chmod 755 "$LOG_DIR"

    log_info "Directories created"
}

copy_application_files() {
    log_step "Copying application files"

    # Copy web application
    cp -r "${SCRIPT_DIR}/web/"* "${INSTALL_DIR}/web/"

    # Copy library files
    cp -r "${SCRIPT_DIR}/lib/"* "${INSTALL_DIR}/lib/"

    # Copy container files
    cp -r "${CONTAINERS_DIR}/"* "${INSTALL_DIR}/containers/" 2>/dev/null || true

    # Copy device profiles
    mkdir -p "${INSTALL_DIR}/devices"
    cp -r "${DEVICES_DIR}/"* "${INSTALL_DIR}/devices/" 2>/dev/null || true

    log_info "Application files copied"
}

generate_secrets() {
    log_step "Generating secrets"

    local secrets_dir="${CONTAINERS_DIR}/secrets"

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

    # Copy to config dir
    cp "$secrets_dir/flask_secret" "${CONFIG_DIR}/secrets/fortress_secret_key" 2>/dev/null || true

    log_info "Secrets generated"
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

    # Create users.json
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/users.json" << EOF
{
  "users": [
    {
      "id": "${ADMIN_USER}",
      "username": "${ADMIN_USER}",
      "password_hash": "${password_hash}",
      "role": "admin",
      "created_at": "$(date -Iseconds)",
      "email": "${ADMIN_USER}@localhost"
    }
  ]
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
        chmod +x "${DEVICES_DIR}/common/network-filter-manager.sh"
        "${DEVICES_DIR}/common/network-filter-manager.sh" init || {
            log_warn "Failed to initialize nftables filters (may need manual setup)"
        }
        log_info "nftables filter mode initialized"
    elif [ "$NETWORK_MODE" = "vlan" ]; then
        log_info "VLAN mode selected - OVS setup required separately"
        log_warn "Run setup.sh for full VLAN configuration"
    else
        log_warn "Network filtering not configured"
    fi
}

build_containers() {
    log_step "Building container images"

    cd "$CONTAINERS_DIR"
    local repo_root="${SCRIPT_DIR}/../.."

    # Core containers (always built)
    log_info "Building web container..."
    podman build -f Containerfile.web -t localhost/fortress-web:latest "$SCRIPT_DIR" || {
        log_error "Failed to build web container"
        exit 1
    }

    # ML containers (built if --full mode or explicitly requested)
    if [ "${BUILD_ML_CONTAINERS:-false}" = true ] || [ "${INSTALL_ML:-false}" = true ]; then
        log_info "Building ML/AI containers..."

        log_info "  - Building qsecbit-agent (numpy, scipy, sklearn)..."
        podman build -f Containerfile.agent -t localhost/fortress-agent:latest "$repo_root" || {
            log_warn "Failed to build agent container (ML features may be limited)"
        }

        log_info "  - Building dnsxai (DNS ML protection)..."
        podman build -f Containerfile.dnsxai -t localhost/fortress-dnsxai:latest "$repo_root" || {
            log_warn "Failed to build dnsxai container"
        }

        log_info "  - Building dfs-intelligence (WiFi ML)..."
        podman build -f Containerfile.dfs -t localhost/fortress-dfs:latest "$repo_root" || {
            log_warn "Failed to build dfs container"
        }

        log_info "  - Building lstm-trainer (PyTorch)..."
        podman build -f Containerfile.lstm -t localhost/fortress-lstm:latest "$repo_root" || {
            log_warn "Failed to build lstm container (training will be unavailable)"
        }

        log_info "ML containers built successfully"
    else
        log_info "Skipping ML containers (use --full to include)"
    fi
}

start_containers() {
    log_step "Starting containers"

    cd "$CONTAINERS_DIR"

    # Update compose file with configured port
    sed -i "s/8443:8443/${WEB_PORT}:8443/" podman-compose.yml 2>/dev/null || true

    # Start services based on mode
    if [ "${INSTALL_ML:-false}" = true ]; then
        log_info "Starting all services (including ML)..."
        podman-compose --profile full up -d
    else
        log_info "Starting core services..."
        podman-compose up -d
    fi

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
}

create_systemd_service() {
    log_step "Creating systemd service"

    # Build profile flags based on installation options
    local profile_flags=""
    if [ "${INSTALL_ML:-false}" = true ]; then
        profile_flags="--profile full"
    fi
    if [ "${INSTALL_MONITORING:-true}" = true ]; then
        profile_flags="$profile_flags --profile monitoring"
    fi
    profile_flags=$(echo "$profile_flags" | xargs)  # trim whitespace

    cat > /etc/systemd/system/fortress.service << EOF
[Unit]
Description=HookProbe Fortress Security Gateway
After=network.target openvswitch-switch.service
Requires=podman.socket
Wants=openvswitch-switch.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${CONTAINERS_DIR}
ExecStart=/usr/bin/podman-compose ${profile_flags} -f podman-compose.yml up -d
ExecStop=/usr/bin/podman-compose ${profile_flags} -f podman-compose.yml down
ExecReload=/usr/bin/podman-compose ${profile_flags} -f podman-compose.yml restart
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

    # Also save profile config for reference
    echo "FORTRESS_PROFILES=\"${profile_flags}\"" >> /etc/hookprobe/fortress.conf

    systemctl daemon-reload
    systemctl enable fortress

    log_info "Systemd service created with profiles: ${profile_flags:-none (core only)}"
}

# ============================================================
# STATE MANAGEMENT
# ============================================================
STATE_FILE="${CONFIG_DIR}/fortress-state.json"

save_installation_state() {
    log_step "Saving installation state"

    mkdir -p "$(dirname "$STATE_FILE")"

    # Build container and volume lists based on installation mode
    local containers='["fortress-web", "fortress-postgres", "fortress-redis"'
    local volumes='["fortress-postgres-data", "fortress-redis-data", "fortress-web-data", "fortress-web-logs", "fortress-config"'

    if [ "${INSTALL_ML:-false}" = true ]; then
        containers="${containers}, \"fortress-qsecbit\", \"fortress-dnsxai\", \"fortress-dfs\""
        volumes="${volumes}, \"fortress-agent-data\", \"fortress-dnsxai-data\", \"fortress-dnsxai-blocklists\", \"fortress-dfs-data\", \"fortress-ml-models\""
    fi
    containers="${containers}]"
    volumes="${volumes}]"

    cat > "$STATE_FILE" << EOF
{
    "deployment_mode": "container",
    "version": "5.2.0",
    "installed_at": "$(date -Iseconds)",
    "network_mode": "${NETWORK_MODE}",
    "ml_enabled": ${INSTALL_ML:-false},
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

    log_warn "Quick install with default credentials"
    log_warn "Admin: admin / hookprobe - CHANGE THIS IMMEDIATELY!"
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
    build_containers
    start_containers
    create_systemd_service
    save_installation_state

    # Final message
    echo ""
    echo "========================================"
    echo -e "${GREEN}Installation Complete!${NC}"
    echo "========================================"
    echo ""
    echo "Access the admin portal at:"
    echo -e "  ${CYAN}https://localhost:${WEB_PORT}${NC}"
    echo ""
    echo "Login credentials:"
    echo -e "  Username: ${BOLD}${ADMIN_USER}${NC}"
    echo -e "  Password: ${BOLD}(your configured password)${NC}"
    echo ""
    echo "Useful commands:"
    echo "  systemctl status fortress    # Check service status"
    echo "  systemctl restart fortress   # Restart services"
    echo "  podman logs fortress-web     # View web logs"
    echo "  podman logs fortress-postgres # View database logs"
    echo ""
    echo "Network filtering:"
    if [ "$NETWORK_MODE" = "filter" ]; then
        echo "  ${DEVICES_DIR}/common/network-filter-manager.sh status"
        echo "  ${DEVICES_DIR}/common/network-filter-manager.sh set-policy <mac> <policy>"
    else
        echo "  VLAN mode - use setup.sh for full configuration"
    fi
    echo ""
}

main "$@"
