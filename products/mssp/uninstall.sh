#!/bin/bash
# =============================================================================
# HookProbe MSSP Uninstall Script v5.0
# Managed Security Service Provider - Cleanup and Removal
# =============================================================================

set -e

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Installation directories
MSSP_BASE_DIR="/opt/hookprobe/mssp"
MSSP_CONFIG_DIR="/etc/hookprobe/mssp"
MSSP_DATA_DIR="/var/lib/hookprobe/mssp"
MSSP_LOG_DIR="/var/log/hookprobe/mssp"
MSSP_SECRETS_DIR="/etc/hookprobe/secrets/mssp"

# OVS Bridge
OVS_BRIDGE="mssp-bridge"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN} $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# =============================================================================
# UNINSTALL FUNCTIONS
# =============================================================================

stop_services() {
    log_section "Stopping Services"

    # Stop systemd service
    if systemctl is-active --quiet hookprobe-mssp 2>/dev/null; then
        log_info "Stopping hookprobe-mssp service..."
        systemctl stop hookprobe-mssp || true
    fi

    # Disable service
    if systemctl is-enabled --quiet hookprobe-mssp 2>/dev/null; then
        log_info "Disabling hookprobe-mssp service..."
        systemctl disable hookprobe-mssp || true
    fi

    log_success "Services stopped"
}

stop_containers() {
    log_section "Stopping Containers"

    local containers=(
        "mssp-htp"
        "mssp-n8n"
        "mssp-qsecbit"
        "mssp-suricata"
        "mssp-zeek"
        "mssp-nginx"
        "mssp-celery"
        "mssp-celery-beat"
        "mssp-django"
        "mssp-logto"
        "mssp-grafana"
        "mssp-vector"
        "mssp-clickhouse"
        "mssp-victoriametrics"
        "mssp-valkey"
        "mssp-postgres"
    )

    for container in "${containers[@]}"; do
        if podman container exists "$container" 2>/dev/null; then
            log_info "Stopping container: $container"
            podman stop "$container" 2>/dev/null || true
        fi
    done

    log_success "Containers stopped"
}

remove_containers() {
    log_section "Removing Containers"

    local containers=(
        "mssp-htp"
        "mssp-n8n"
        "mssp-qsecbit"
        "mssp-suricata"
        "mssp-zeek"
        "mssp-nginx"
        "mssp-celery"
        "mssp-celery-beat"
        "mssp-django"
        "mssp-logto"
        "mssp-grafana"
        "mssp-vector"
        "mssp-clickhouse"
        "mssp-victoriametrics"
        "mssp-valkey"
        "mssp-postgres"
    )

    for container in "${containers[@]}"; do
        if podman container exists "$container" 2>/dev/null; then
            log_info "Removing container: $container"
            podman rm -f "$container" 2>/dev/null || true
        fi
    done

    log_success "Containers removed"
}

remove_images() {
    log_section "Removing Container Images"

    local images=(
        "localhost/mssp-django:latest"
        "localhost/mssp-qsecbit:latest"
        "localhost/mssp-htp:latest"
    )

    for image in "${images[@]}"; do
        if podman image exists "$image" 2>/dev/null; then
            log_info "Removing image: $image"
            podman rmi "$image" 2>/dev/null || true
        fi
    done

    log_success "Custom images removed"
}

remove_networks() {
    log_section "Removing Podman Networks"

    local networks=(
        "mssp-pod-001-dmz"
        "mssp-pod-002-iam"
        "mssp-pod-003-db"
        "mssp-pod-004-cache"
        "mssp-pod-005-monitoring"
        "mssp-pod-006-security"
        "mssp-pod-007-response"
        "mssp-pod-008-automation"
        "mssp-external"
    )

    for network in "${networks[@]}"; do
        if podman network exists "$network" 2>/dev/null; then
            log_info "Removing network: $network"
            podman network rm "$network" 2>/dev/null || true
        fi
    done

    log_success "Networks removed"
}

remove_ovs_bridge() {
    log_section "Removing OVS Bridge"

    if command -v ovs-vsctl &> /dev/null; then
        # Remove VXLAN tunnels
        for vni in 201 202 203 204 205 206 207 208 1000; do
            local vxlan_name="vxlan_${vni}"
            if ovs-vsctl port-to-br "$vxlan_name" &>/dev/null; then
                log_info "Removing VXLAN: $vxlan_name"
                ovs-vsctl del-port "$OVS_BRIDGE" "$vxlan_name" 2>/dev/null || true
            fi
        done

        # Remove edge VXLAN
        if ovs-vsctl port-to-br "vxlan_edge" &>/dev/null; then
            log_info "Removing VXLAN: vxlan_edge"
            ovs-vsctl del-port "$OVS_BRIDGE" "vxlan_edge" 2>/dev/null || true
        fi

        # Remove bridge
        if ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
            log_info "Removing OVS bridge: $OVS_BRIDGE"
            ip link set "$OVS_BRIDGE" down 2>/dev/null || true
            ovs-vsctl del-br "$OVS_BRIDGE" 2>/dev/null || true
        fi
    fi

    log_success "OVS bridge removed"
}

remove_systemd_files() {
    log_section "Removing Systemd Files"

    local files=(
        "/etc/systemd/system/hookprobe-mssp.service"
        "/usr/local/bin/hookprobe-mssp-start"
        "/usr/local/bin/hookprobe-mssp-stop"
    )

    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            log_info "Removing: $file"
            rm -f "$file"
        fi
    done

    # Reload systemd
    systemctl daemon-reload

    log_success "Systemd files removed"
}

backup_data() {
    log_section "Backing Up Data"

    local backup_dir="/var/backup/hookprobe-mssp-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"

    # Backup PostgreSQL data
    if [ -d "$MSSP_DATA_DIR/postgres" ]; then
        log_info "Backing up PostgreSQL data..."
        cp -r "$MSSP_DATA_DIR/postgres" "$backup_dir/" 2>/dev/null || true
    fi

    # Backup ClickHouse data
    if [ -d "$MSSP_DATA_DIR/clickhouse" ]; then
        log_info "Backing up ClickHouse data..."
        cp -r "$MSSP_DATA_DIR/clickhouse" "$backup_dir/" 2>/dev/null || true
    fi

    # Backup secrets
    if [ -d "$MSSP_SECRETS_DIR" ]; then
        log_info "Backing up secrets..."
        cp -r "$MSSP_SECRETS_DIR" "$backup_dir/" 2>/dev/null || true
    fi

    # Backup config
    if [ -d "$MSSP_CONFIG_DIR" ]; then
        log_info "Backing up configuration..."
        cp -r "$MSSP_CONFIG_DIR" "$backup_dir/" 2>/dev/null || true
    fi

    log_success "Data backed up to: $backup_dir"
    echo "$backup_dir"
}

remove_data() {
    log_section "Removing Data Directories"

    local dirs=(
        "$MSSP_BASE_DIR"
        "$MSSP_CONFIG_DIR"
        "$MSSP_DATA_DIR"
        "$MSSP_LOG_DIR"
    )

    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            log_info "Removing: $dir"
            rm -rf "$dir"
        fi
    done

    log_success "Data directories removed"
}

remove_secrets() {
    log_section "Removing Secrets"

    if [ -d "$MSSP_SECRETS_DIR" ]; then
        log_info "Securely removing secrets..."
        # Overwrite with random data before deletion
        find "$MSSP_SECRETS_DIR" -type f -exec shred -u {} \; 2>/dev/null || true
        rm -rf "$MSSP_SECRETS_DIR"
    fi

    log_success "Secrets removed"
}

# =============================================================================
# UNINSTALL MODES
# =============================================================================

uninstall_soft() {
    # Soft uninstall: Stop services but keep data
    log_section "Soft Uninstall (Keep Data)"

    stop_services
    stop_containers
    remove_containers
    remove_networks
    remove_ovs_bridge
    remove_systemd_files

    log_success "Soft uninstall complete. Data preserved."
    echo ""
    echo "  Data directories preserved:"
    echo "  - $MSSP_DATA_DIR"
    echo "  - $MSSP_CONFIG_DIR"
    echo "  - $MSSP_SECRETS_DIR"
    echo ""
    echo "  To completely remove all data, run:"
    echo "  $0 --complete"
}

uninstall_complete() {
    # Complete uninstall: Remove everything including data
    log_section "Complete Uninstall (Remove All Data)"

    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                         WARNING                                ║${NC}"
    echo -e "${RED}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║  This will permanently delete ALL MSSP data including:         ║${NC}"
    echo -e "${RED}║  - PostgreSQL database (all customer data)                     ║${NC}"
    echo -e "${RED}║  - ClickHouse analytics (all security events)                  ║${NC}"
    echo -e "${RED}║  - VictoriaMetrics (all time-series metrics)                   ║${NC}"
    echo -e "${RED}║  - All configuration and secrets                               ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [ "$FORCE" != "true" ]; then
        echo -n "Type 'DELETE-MSSP' to confirm complete removal: "
        read -r confirmation

        if [ "$confirmation" != "DELETE-MSSP" ]; then
            log_error "Uninstall cancelled"
            exit 1
        fi
    fi

    # Backup before deletion
    local backup_path
    backup_path=$(backup_data)

    stop_services
    stop_containers
    remove_containers
    remove_images
    remove_networks
    remove_ovs_bridge
    remove_systemd_files
    remove_data
    remove_secrets

    log_success "Complete uninstall finished"
    echo ""
    echo "  Backup saved to: $backup_path"
    echo ""
    echo -e "${YELLOW}  NOTE: PostgreSQL/ClickHouse container images still available.${NC}"
    echo -e "${YELLOW}  Run 'podman system prune -a' to remove all unused images.${NC}"
}

uninstall_preserve_db() {
    # Uninstall but preserve database volumes
    log_section "Uninstall (Preserve Databases)"

    stop_services
    stop_containers
    remove_containers
    remove_networks
    remove_ovs_bridge
    remove_systemd_files

    # Remove non-database directories
    rm -rf "$MSSP_BASE_DIR"
    rm -rf "$MSSP_LOG_DIR"

    log_success "Uninstall complete. Database volumes preserved."
    echo ""
    echo "  Preserved data:"
    echo "  - $MSSP_DATA_DIR/postgres"
    echo "  - $MSSP_DATA_DIR/clickhouse"
    echo "  - $MSSP_DATA_DIR/victoriametrics"
    echo "  - $MSSP_CONFIG_DIR"
    echo "  - $MSSP_SECRETS_DIR"
}

# =============================================================================
# USAGE
# =============================================================================

show_usage() {
    echo "HookProbe MSSP Uninstall Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --soft              Stop services and remove containers, keep data (default)"
    echo "  --complete          Remove everything including all data (requires confirmation)"
    echo "  --preserve-db       Remove app but preserve database volumes"
    echo "  --force             Skip confirmation prompts"
    echo "  --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                  # Soft uninstall (default)"
    echo "  $0 --complete       # Complete removal with confirmation"
    echo "  $0 --complete --force  # Complete removal without confirmation"
    echo "  $0 --preserve-db    # Uninstall but keep databases"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    local mode="soft"
    FORCE="false"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --soft)
                mode="soft"
                shift
                ;;
            --complete)
                mode="complete"
                shift
                ;;
            --preserve-db)
                mode="preserve-db"
                shift
                ;;
            --force)
                FORCE="true"
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    check_root

    echo -e "${CYAN}"
    cat << 'EOF'
  _   _             _    ____            _
 | | | | ___   ___ | | _|  _ \ _ __ ___ | |__   ___
 | |_| |/ _ \ / _ \| |/ / |_) | '__/ _ \| '_ \ / _ \
 |  _  | (_) | (_) |   <|  __/| | | (_) | |_) |  __/
 |_| |_|\___/ \___/|_|\_\_|   |_|  \___/|_.__/ \___|

  __  __ ____ ____  ____    _   _       _           _        _ _
 |  \/  / ___/ ___||  _ \  | | | |_ __ (_)_ __  ___| |_ __ _| | |
 | |\/| \___ \___ \| |_) | | | | | '_ \| | '_ \/ __| __/ _` | | |
 | |  | |___) |__) |  __/  | |_| | | | | | | | \__ \ || (_| | | |
 |_|  |_|____/____/|_|      \___/|_| |_|_|_| |_|___/\__\__,_|_|_|

EOF
    echo -e "${NC}"
    echo "  HookProbe MSSP Uninstaller"
    echo "  Mode: $mode"
    echo ""

    case $mode in
        soft)
            uninstall_soft
            ;;
        complete)
            uninstall_complete
            ;;
        preserve-db)
            uninstall_preserve_db
            ;;
    esac
}

main "$@"
