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
# Version: 5.0.0
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

           F O R T R E S S   v5.0.0
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

start_containers() {
    log_step "Starting containers"

    cd "$CONTAINERS_DIR"

    # Build images
    log_info "Building container images..."
    podman build -f Containerfile.web -t localhost/fortress-web:latest "$SCRIPT_DIR" || {
        log_error "Failed to build web container"
        exit 1
    }

    # Update compose file with configured port
    sed -i "s/8443:8443/${WEB_PORT}:8443/" podman-compose.yml 2>/dev/null || true

    # Start services
    log_info "Starting services..."
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
}

create_systemd_service() {
    log_step "Creating systemd service"

    cat > /etc/systemd/system/fortress.service << EOF
[Unit]
Description=HookProbe Fortress Security Gateway
After=network.target
Requires=podman.socket

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${CONTAINERS_DIR}
ExecStart=/usr/bin/podman-compose -f podman-compose.yml up -d
ExecStop=/usr/bin/podman-compose -f podman-compose.yml down
ExecReload=/usr/bin/podman-compose -f podman-compose.yml restart
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fortress

    log_info "Systemd service created and enabled"
}

# ============================================================
# UNINSTALL
# ============================================================
uninstall() {
    log_step "Uninstalling Fortress"

    echo ""
    echo -e "${RED}WARNING: This will remove:${NC}"
    echo "  - All Fortress containers"
    echo "  - All Fortress volumes (database, logs, data)"
    echo "  - Container images"
    echo "  - Systemd service"
    echo ""
    echo "Configuration in /etc/hookprobe will be preserved."
    echo ""
    read -p "Type 'yes' to confirm uninstall: " confirm

    if [ "$confirm" != "yes" ]; then
        log_info "Uninstall cancelled"
        exit 0
    fi

    # Stop and remove containers
    log_info "Stopping containers..."
    cd "$CONTAINERS_DIR" 2>/dev/null && podman-compose down -v 2>/dev/null || true

    # Remove volumes
    log_info "Removing volumes..."
    podman volume rm -f fortress-postgres-data fortress-redis-data fortress-web-data fortress-web-logs fortress-agent-data fortress-config 2>/dev/null || true

    # Remove images
    log_info "Removing images..."
    podman rmi -f localhost/fortress-web:latest 2>/dev/null || true

    # Remove systemd service
    log_info "Removing systemd service..."
    systemctl stop fortress 2>/dev/null || true
    systemctl disable fortress 2>/dev/null || true
    rm -f /etc/systemd/system/fortress.service
    systemctl daemon-reload

    # Remove nftables rules
    log_info "Removing network filters..."
    nft delete table inet fortress_filter 2>/dev/null || true

    # Remove installation directory
    log_info "Removing installation directory..."
    rm -rf "$INSTALL_DIR"
    rm -rf "$DATA_DIR"

    echo ""
    log_info "Uninstall complete!"
    log_info "Configuration preserved in: $CONFIG_DIR"
    log_info "To remove config: rm -rf $CONFIG_DIR"
}

# ============================================================
# QUICK INSTALL
# ============================================================
quick_install() {
    NETWORK_MODE="filter"
    ADMIN_USER="admin"
    ADMIN_PASS="hookprobe"
    WEB_PORT="8443"

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
            check_prerequisites
            uninstall
            exit 0
            ;;
        --quick|quick)
            check_prerequisites
            quick_install
            ;;
        --help|help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  (none)       Interactive installation"
            echo "  --quick      Quick install with defaults"
            echo "  --uninstall  Complete removal"
            echo "  --help       Show this help"
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
    start_containers
    create_systemd_service

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
