#!/bin/bash
#
# HookProbe Fortress Uninstall Script
# Version: 5.0.0
# License: AGPL-3.0 - see LICENSE file
#
# Removes all Fortress components:
# - Systemd services (hookprobe-fortress, fortress-qsecbit)
# - Podman containers (VictoriaMetrics, Grafana)
# - OVS bridge and VXLAN tunnels
# - Configuration files
# - Data and log directories
#

set -e

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
# PATHS
# ============================================================
INSTALL_DIR="/opt/hookprobe/fortress"
CONFIG_DIR="/etc/hookprobe"
FORTRESS_CONFIG_DIR="/etc/fortress"
SECRETS_DIR="/etc/hookprobe/secrets"
DATA_DIR="/var/lib/hookprobe/fortress"
LOG_DIR="/var/log/hookprobe"
OVS_BRIDGE="${OVS_BRIDGE_NAME:-hookprobe}"

# ============================================================
# LOGGING
# ============================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ============================================================
# PREREQUISITES
# ============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# ============================================================
# STOP SERVICES
# ============================================================
stop_services() {
    log_step "Stopping Fortress services..."

    local services=(
        "hookprobe-fortress"
        "fortress-qsecbit"
    )

    for service in "${services[@]}"; do
        if systemctl is-active "$service" &>/dev/null; then
            log_info "Stopping $service..."
            systemctl stop "$service" 2>/dev/null || true
        fi
    done

    log_info "Services stopped"
}

# ============================================================
# DISABLE AND REMOVE SYSTEMD SERVICES
# ============================================================
remove_systemd_services() {
    log_step "Removing systemd services..."

    local services=(
        "hookprobe-fortress"
        "fortress-qsecbit"
    )

    for service in "${services[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            log_info "Disabling $service..."
            systemctl disable "$service" 2>/dev/null || true
        fi

        if [ -f "/etc/systemd/system/${service}.service" ]; then
            log_info "Removing ${service}.service..."
            rm -f "/etc/systemd/system/${service}.service"
        fi
    done

    systemctl daemon-reload
    log_info "Systemd services removed"
}

# ============================================================
# REMOVE PODMAN CONTAINERS
# ============================================================
remove_containers() {
    log_step "Removing Podman containers..."

    if ! command -v podman &>/dev/null; then
        log_info "Podman not installed, skipping container removal"
        return 0
    fi

    local containers=(
        "fortress-victoriametrics"
        "fortress-grafana"
    )

    for container in "${containers[@]}"; do
        if podman ps -a --format "{{.Names}}" | grep -q "^${container}$"; then
            log_info "Removing container: $container"
            podman stop "$container" 2>/dev/null || true
            podman rm -f "$container" 2>/dev/null || true
        fi
    done

    # Remove volumes
    log_info "Removing Podman volumes..."
    local volumes=(
        "fortress-victoriametrics-data"
        "fortress-grafana-data"
    )

    for volume in "${volumes[@]}"; do
        if podman volume exists "$volume" 2>/dev/null; then
            log_info "Removing volume: $volume"
            podman volume rm "$volume" 2>/dev/null || true
        fi
    done

    log_info "Containers removed"
}

# ============================================================
# REMOVE OVS CONFIGURATION
# ============================================================
remove_ovs_config() {
    log_step "Removing OVS configuration..."

    if ! command -v ovs-vsctl &>/dev/null; then
        log_info "OVS not installed, skipping"
        return 0
    fi

    # Remove VXLAN tunnels
    if ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        local ports=$(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -E "^vxlan" || true)
        for port in $ports; do
            log_info "Removing VXLAN port: $port"
            ovs-vsctl --if-exists del-port "$OVS_BRIDGE" "$port"
        done
    fi

    # Note: We don't delete the OVS bridge itself as other components may use it

    log_info "OVS configuration cleaned"
}

# ============================================================
# REMOVE CONFIGURATION FILES
# ============================================================
remove_configuration() {
    log_step "Removing configuration files..."

    # Remove Fortress-specific config
    if [ -d "$FORTRESS_CONFIG_DIR" ]; then
        log_info "Removing $FORTRESS_CONFIG_DIR..."
        rm -rf "$FORTRESS_CONFIG_DIR"
    fi

    # Remove VXLAN secrets
    if [ -d "$SECRETS_DIR/vxlan" ]; then
        log_info "Removing VXLAN secrets..."
        rm -rf "$SECRETS_DIR/vxlan"
    fi

    # Remove MACsec secrets
    if [ -d "$SECRETS_DIR/macsec" ]; then
        log_info "Removing MACsec secrets..."
        rm -rf "$SECRETS_DIR/macsec"
    fi

    # Remove OVS config
    rm -f "$CONFIG_DIR/ovs-config.sh" 2>/dev/null || true

    # Clean up empty directories
    if [ -d "$SECRETS_DIR" ] && [ -z "$(ls -A $SECRETS_DIR 2>/dev/null)" ]; then
        rmdir "$SECRETS_DIR" 2>/dev/null || true
    fi

    if [ -d "$CONFIG_DIR" ] && [ -z "$(ls -A $CONFIG_DIR 2>/dev/null)" ]; then
        rmdir "$CONFIG_DIR" 2>/dev/null || true
    fi

    log_info "Configuration files removed"
}

# ============================================================
# REMOVE INSTALLATION DIRECTORY
# ============================================================
remove_installation() {
    log_step "Removing Fortress installation..."

    if [ -d "$INSTALL_DIR" ]; then
        log_info "Removing $INSTALL_DIR..."
        rm -rf "$INSTALL_DIR"
    fi

    if [ -d "$DATA_DIR" ]; then
        log_info "Removing $DATA_DIR..."
        rm -rf "$DATA_DIR"
    fi

    # Clean up parent directories if empty
    if [ -d "/var/lib/hookprobe" ] && [ -z "$(ls -A /var/lib/hookprobe 2>/dev/null)" ]; then
        rmdir "/var/lib/hookprobe" 2>/dev/null || true
    fi

    if [ -d "/opt/hookprobe" ] && [ -z "$(ls -A /opt/hookprobe 2>/dev/null)" ]; then
        rmdir "/opt/hookprobe" 2>/dev/null || true
    fi

    log_info "Installation removed"
}

# ============================================================
# HANDLE LOGS
# ============================================================
handle_logs() {
    log_step "Handling log files..."

    if [ -d "$LOG_DIR" ]; then
        echo ""
        echo -e "${YELLOW}Log files are preserved at:${NC} $LOG_DIR"
        echo ""
        read -p "Remove Fortress log files too? (yes/no) [no]: " remove_logs
        if [ "$remove_logs" = "yes" ]; then
            log_info "Removing Fortress log files..."
            rm -f "$LOG_DIR/fortress"*.log 2>/dev/null || true
            rm -f "$LOG_DIR/qsecbit-fortress"*.log 2>/dev/null || true
            if [ -z "$(ls -A $LOG_DIR 2>/dev/null)" ]; then
                rm -rf "$LOG_DIR"
            fi
        else
            log_info "Log files preserved"
        fi
    fi
}

# ============================================================
# MAIN
# ============================================================
main() {
    echo ""
    echo -e "${BOLD}${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${RED}║              HookProbe Fortress Uninstaller                ║${NC}"
    echo -e "${BOLD}${RED}║                    \"Edge Router\"                           ║${NC}"
    echo -e "${BOLD}${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    check_root

    echo -e "${YELLOW}This will remove all Fortress components including:${NC}"
    echo -e "  - Fortress systemd services"
    echo -e "  - Podman containers (VictoriaMetrics, Grafana)"
    echo -e "  - OVS VXLAN tunnels"
    echo -e "  - Configuration files ($FORTRESS_CONFIG_DIR)"
    echo -e "  - VXLAN and MACsec secrets"
    echo -e "  - Installation directory ($INSTALL_DIR)"
    echo -e "  - Data directory ($DATA_DIR)"
    echo ""

    read -p "Are you sure you want to continue? (yes/no) [no]: " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "Uninstall cancelled"
        exit 0
    fi

    echo ""

    stop_services
    remove_containers
    remove_ovs_config
    remove_systemd_services
    remove_configuration
    remove_installation
    handle_logs

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Fortress Uninstall Complete!                     ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Removed:${NC}"
    echo -e "  • hookprobe-fortress service"
    echo -e "  • fortress-qsecbit service"
    echo -e "  • Monitoring containers (VictoriaMetrics, Grafana)"
    echo -e "  • OVS VXLAN tunnels"
    echo -e "  • Configuration: $FORTRESS_CONFIG_DIR"
    echo -e "  • Secrets: VXLAN, MACsec"
    echo -e "  • Installation: $INSTALL_DIR"
    echo -e "  • Data: $DATA_DIR"
    echo ""
    echo -e "  ${DIM}To reinstall Fortress:${NC}"
    echo -e "  ${DIM}sudo ./install.sh --tier fortress${NC}"
    echo ""
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
