#!/bin/bash
#
# HookProbe Fortress Uninstall Script
# Version: 5.0.0
# License: AGPL-3.0 - see LICENSE file
#
# Removes all Fortress components installed by setup.sh:
# - Systemd services (hookprobe-fortress, fortress-qsecbit, fortress-lte-failover)
# - Podman containers (VictoriaMetrics, Grafana)
# - OVS bridge, VLANs, VXLAN tunnels
# - Management scripts (hookprobe-macsec, hookprobe-openflow, fortress-lte-monitor)
# - Configuration files and secrets
# - Data and log directories
#
# Usage: sudo ./uninstall.sh [--force] [--keep-logs] [--keep-data]
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
LTE_STATE_DIR="/var/lib/fortress/lte"
LOG_DIR="/var/log/hookprobe"
OVS_BRIDGE="fortress"

# ============================================================
# OPTIONS
# ============================================================
FORCE_MODE=false
KEEP_LOGS=false
KEEP_DATA=false

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

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force|-f) FORCE_MODE=true; shift ;;
            --keep-logs) KEEP_LOGS=true; shift ;;
            --keep-data) KEEP_DATA=true; shift ;;
            --help|-h)
                echo "HookProbe Fortress Uninstaller"
                echo ""
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --force, -f    Skip confirmation prompts"
                echo "  --keep-logs    Preserve log files"
                echo "  --keep-data    Preserve data directories"
                echo "  --help, -h     Show this help message"
                echo ""
                exit 0
                ;;
            *) shift ;;
        esac
    done
}

# ============================================================
# STOP SERVICES
# ============================================================
stop_services() {
    log_step "Stopping Fortress services..."

    local services=(
        "hookprobe-fortress"
        "fortress-qsecbit"
        "fortress-lte-failover"
        "fortress-wan-failover"
        "fortress-tunnel"
        "fortress-dnsmasq"
        "fortress-hostapd"
        "fortress-nat"
    )

    for service in "${services[@]}"; do
        if systemctl is-active "$service" &>/dev/null; then
            log_info "Stopping $service..."
            systemctl stop "$service" 2>/dev/null || true
        fi
    done

    # Kill any running MACsec sessions
    pkill -f "wpa_supplicant.*macsec" 2>/dev/null || true

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
        "fortress-lte-failover"
        "fortress-wan-failover"
        "fortress-tunnel"
        "fortress-dnsmasq"
        "fortress-hostapd"
        "fortress-nat"
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
# REMOVE MANAGEMENT SCRIPTS
# ============================================================
remove_management_scripts() {
    log_step "Removing management scripts..."

    local scripts=(
        "/usr/local/bin/hookprobe-macsec"
        "/usr/local/bin/hookprobe-openflow"
        "/usr/local/bin/hookprobe-fortress-start"
        "/usr/local/bin/hookprobe-fortress-stop"
        "/usr/local/bin/fortress-lte-monitor"
        "/usr/local/bin/fortress-nat-setup"
    )

    for script in "${scripts[@]}"; do
        if [ -f "$script" ]; then
            log_info "Removing $(basename $script)..."
            rm -f "$script"
        fi
    done

    log_info "Management scripts removed"
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

    # Container names as created by setup.sh
    local containers=(
        "fortress-victoria"
        "fortress-grafana"
        "fortress-victoriametrics"  # Alternative name
        "fortress-n8n"
        "fortress-clickhouse"
    )

    for container in "${containers[@]}"; do
        if podman ps -a --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            log_info "Removing container: $container"
            podman stop "$container" 2>/dev/null || true
            podman rm -f "$container" 2>/dev/null || true
        fi
    done

    # Remove volumes
    log_info "Removing Podman volumes..."
    local volumes=(
        "fortress-victoriametrics-data"
        "fortress-victoria-data"
        "fortress-grafana-data"
        "fortress-n8n-data"
        "fortress-clickhouse-data"
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

    if ! ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        log_info "OVS bridge '$OVS_BRIDGE' does not exist, skipping"
        return 0
    fi

    # Remove all ports from the bridge
    local ports
    ports=$(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null || true)

    for port in $ports; do
        log_info "Removing OVS port: $port"
        ovs-vsctl --if-exists del-port "$OVS_BRIDGE" "$port" 2>/dev/null || true
    done

    # Remove the bridge itself
    log_info "Removing OVS bridge: $OVS_BRIDGE"
    ip link set "$OVS_BRIDGE" down 2>/dev/null || true
    ovs-vsctl --if-exists del-br "$OVS_BRIDGE" 2>/dev/null || true

    log_info "OVS configuration removed"
}

# ============================================================
# REMOVE VLAN INTERFACES
# ============================================================
remove_vlan_interfaces() {
    log_step "Removing VLAN interfaces..."

    local vlans=(10 20 30 40 99)

    for vlan_id in "${vlans[@]}"; do
        local iface="vlan${vlan_id}"
        if ip link show "$iface" &>/dev/null; then
            log_info "Removing VLAN interface: $iface"
            ip link set "$iface" down 2>/dev/null || true
            ip link delete "$iface" 2>/dev/null || true
        fi
    done

    log_info "VLAN interfaces removed"
}

# ============================================================
# REMOVE MACSEC INTERFACES
# ============================================================
remove_macsec_interfaces() {
    log_step "Removing MACsec interfaces..."

    # Find and remove any MACsec interfaces
    for iface in $(ip link show 2>/dev/null | grep -oP 'macsec\d+' || true); do
        log_info "Removing MACsec interface: $iface"
        ip link set "$iface" down 2>/dev/null || true
        ip link delete "$iface" 2>/dev/null || true
    done

    log_info "MACsec interfaces removed"
}

# ============================================================
# REMOVE FREERADIUS CONFIGURATION
# ============================================================
remove_freeradius_config() {
    log_step "Removing FreeRADIUS configuration..."

    local freeradius_conf="/etc/freeradius/3.0/mods-config/files/authorize"
    if [ -f "$freeradius_conf" ]; then
        # Check if it's our config
        if grep -q "HookProbe Fortress" "$freeradius_conf" 2>/dev/null; then
            log_info "Resetting FreeRADIUS authorize file..."
            # Restore to default (empty users file)
            cat > "$freeradius_conf" << 'EOF'
# FreeRADIUS - User Authorization
# This file was reset by HookProbe Fortress uninstaller
# Add your user configurations below
EOF
            chmod 640 "$freeradius_conf"
            chown freerad:freerad "$freeradius_conf" 2>/dev/null || true
        fi
    fi

    log_info "FreeRADIUS configuration cleaned"
}

# ============================================================
# REMOVE NETWORKMANAGER CONFIGURATION
# ============================================================
remove_networkmanager_config() {
    log_step "Removing NetworkManager configuration..."

    local nm_conf="/etc/NetworkManager/conf.d/fortress-unmanaged.conf"
    if [ -f "$nm_conf" ]; then
        log_info "Removing $nm_conf..."
        rm -f "$nm_conf"

        # Reload NetworkManager if running
        if systemctl is-active --quiet NetworkManager 2>/dev/null; then
            nmcli general reload 2>/dev/null || true
        fi
    fi

    # Remove LTE connection if it exists
    nmcli con delete "fortress-lte" 2>/dev/null || true

    log_info "NetworkManager configuration removed"
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

    # Remove specific config files
    local config_files=(
        "$CONFIG_DIR/fortress.conf"
        "$CONFIG_DIR/ovs-config.sh"
        "$CONFIG_DIR/vlans.conf"
        "$CONFIG_DIR/vxlan-networks.conf"
        "$CONFIG_DIR/macsec.conf"
        "$CONFIG_DIR/lte-failover.conf"
    )

    for conf in "${config_files[@]}"; do
        if [ -f "$conf" ]; then
            log_info "Removing $(basename $conf)..."
            rm -f "$conf"
        fi
    done

    # Remove MACsec interface configs
    rm -f "$CONFIG_DIR"/macsec-*.conf 2>/dev/null || true

    # Remove hostapd configuration
    if [ -f /etc/hostapd/fortress.conf ]; then
        log_info "Removing hostapd configuration..."
        rm -f /etc/hostapd/fortress.conf
    fi

    # Remove dnsmasq configuration
    if [ -f /etc/dnsmasq.d/fortress.conf ]; then
        log_info "Removing dnsmasq configuration..."
        rm -f /etc/dnsmasq.d/fortress.conf
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

    # Remove Cloudflare Tunnel configuration
    if [ -d "$INSTALL_DIR/tunnel" ]; then
        log_info "Removing Cloudflare Tunnel configuration..."
        rm -rf "$INSTALL_DIR/tunnel"
    fi

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
# REMOVE LTE CONFIGURATION
# ============================================================
remove_lte_config() {
    log_step "Removing LTE configuration..."

    # Remove LTE state directory
    if [ -d "$LTE_STATE_DIR" ]; then
        log_info "Removing $LTE_STATE_DIR..."
        rm -rf "$LTE_STATE_DIR"
    fi

    # Clean up parent directory if empty
    if [ -d "/var/lib/fortress" ] && [ -z "$(ls -A /var/lib/fortress 2>/dev/null)" ]; then
        rmdir "/var/lib/fortress" 2>/dev/null || true
    fi

    log_info "LTE configuration removed"
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

    if [ "$KEEP_DATA" = false ] && [ -d "$DATA_DIR" ]; then
        log_info "Removing $DATA_DIR..."
        rm -rf "$DATA_DIR"
    elif [ -d "$DATA_DIR" ]; then
        log_info "Preserving data directory: $DATA_DIR"
    fi

    # Remove monitoring data directories
    if [ "$KEEP_DATA" = false ]; then
        rm -rf /opt/hookprobe/fortress/monitoring 2>/dev/null || true
        rm -rf /opt/hookprobe/fortress/grafana 2>/dev/null || true
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
# REMOVE ROUTING TABLES
# ============================================================
remove_routing_tables() {
    log_step "Removing routing table entries..."

    # Remove Fortress-specific routing tables
    if [ -f /etc/iproute2/rt_tables ]; then
        sed -i '/primary_wan/d' /etc/iproute2/rt_tables 2>/dev/null || true
        sed -i '/backup_wan/d' /etc/iproute2/rt_tables 2>/dev/null || true
    fi

    log_info "Routing tables cleaned"
}

# ============================================================
# REMOVE SYSCTL SETTINGS
# ============================================================
remove_sysctl_settings() {
    log_step "Removing sysctl settings..."

    if [ -f /etc/sysctl.d/99-hookprobe.conf ]; then
        log_info "Removing /etc/sysctl.d/99-hookprobe.conf..."
        rm -f /etc/sysctl.d/99-hookprobe.conf
    fi

    if [ -f /etc/sysctl.d/99-fortress-routing.conf ]; then
        log_info "Removing /etc/sysctl.d/99-fortress-routing.conf..."
        rm -f /etc/sysctl.d/99-fortress-routing.conf
    fi

    sysctl --system &>/dev/null || true

    # Clean up iptables NAT rules
    log_info "Cleaning up iptables NAT rules..."
    for WAN in eth0 eth1 wlan0 wlan1 enp0s* wwan0 wwp0s*; do
        iptables -t nat -D POSTROUTING -o "$WAN" -j MASQUERADE 2>/dev/null || true
    done

    # Clean up FORWARD rules for fortress bridge
    iptables -D FORWARD -i fortress -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o fortress -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    log_info "Sysctl settings removed"
}

# ============================================================
# HANDLE LOGS
# ============================================================
handle_logs() {
    log_step "Handling log files..."

    if [ "$KEEP_LOGS" = true ]; then
        log_info "Preserving log files as requested"
        return 0
    fi

    if [ -d "$LOG_DIR" ]; then
        if [ "$FORCE_MODE" = true ]; then
            log_info "Removing Fortress log files..."
            rm -f "$LOG_DIR/fortress"*.log 2>/dev/null || true
            rm -f "$LOG_DIR/qsecbit-fortress"*.log 2>/dev/null || true
            if [ -z "$(ls -A $LOG_DIR 2>/dev/null)" ]; then
                rm -rf "$LOG_DIR"
            fi
        else
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
    fi
}

# ============================================================
# VERIFY UNINSTALL
# ============================================================
verify_uninstall() {
    log_step "Verifying uninstall..."

    local issues=0

    # Check services
    for svc in hookprobe-fortress fortress-qsecbit fortress-lte-failover; do
        if systemctl is-active "$svc" &>/dev/null; then
            log_warn "Service still running: $svc"
            issues=$((issues + 1))
        fi
    done

    # Check OVS bridge
    if command -v ovs-vsctl &>/dev/null && ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        log_warn "OVS bridge still exists: $OVS_BRIDGE"
        issues=$((issues + 1))
    fi

    # Check containers
    if command -v podman &>/dev/null; then
        for container in fortress-victoria fortress-grafana; do
            if podman ps -a --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
                log_warn "Container still exists: $container"
                issues=$((issues + 1))
            fi
        done
    fi

    # Check installation directory
    if [ -d "$INSTALL_DIR" ]; then
        log_warn "Installation directory still exists: $INSTALL_DIR"
        issues=$((issues + 1))
    fi

    if [ $issues -eq 0 ]; then
        log_info "Verification complete - all components removed"
        return 0
    else
        log_warn "Verification found $issues issue(s)"
        return 1
    fi
}

# ============================================================
# MAIN
# ============================================================
main() {
    parse_args "$@"

    echo ""
    echo -e "${BOLD}${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${RED}║              HookProbe Fortress Uninstaller                ║${NC}"
    echo -e "${BOLD}${RED}║                    Version 5.0.0                           ║${NC}"
    echo -e "${BOLD}${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    check_root

    if [ "$FORCE_MODE" = false ]; then
        echo -e "${YELLOW}This will remove all Fortress components including:${NC}"
        echo -e "  • Fortress systemd services"
        echo -e "  • Podman containers (VictoriaMetrics, Grafana)"
        echo -e "  • OVS bridge and VLAN/VXLAN configuration"
        echo -e "  • MACsec interfaces and configuration"
        echo -e "  • LTE failover configuration"
        echo -e "  • Management scripts (hookprobe-macsec, hookprobe-openflow)"
        echo -e "  • Configuration files ($CONFIG_DIR, $FORTRESS_CONFIG_DIR)"
        echo -e "  • Secrets (VXLAN, MACsec)"
        echo -e "  • Installation directory ($INSTALL_DIR)"
        [ "$KEEP_DATA" = false ] && echo -e "  • Data directory ($DATA_DIR)"
        echo ""

        read -p "Are you sure you want to continue? (yes/no) [no]: " confirm
        if [ "$confirm" != "yes" ]; then
            log_info "Uninstall cancelled"
            exit 0
        fi
    fi

    echo ""

    stop_services
    remove_containers
    remove_ovs_config
    remove_vlan_interfaces
    remove_macsec_interfaces
    remove_systemd_services
    remove_management_scripts
    remove_freeradius_config
    remove_networkmanager_config
    remove_lte_config
    remove_configuration
    remove_routing_tables
    remove_sysctl_settings
    remove_installation
    handle_logs
    verify_uninstall

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Fortress Uninstall Complete!                     ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Removed Components:${NC}"
    echo -e "  • hookprobe-fortress service"
    echo -e "  • fortress-qsecbit service"
    echo -e "  • fortress-lte-failover service"
    echo -e "  • fortress-dnsmasq (DHCP server)"
    echo -e "  • fortress-hostapd (WiFi AP)"
    echo -e "  • Monitoring containers (VictoriaMetrics, Grafana)"
    echo -e "  • OVS bridge: $OVS_BRIDGE"
    echo -e "  • VLAN interfaces (10, 20, 30, 40, 99)"
    echo -e "  • VXLAN tunnels"
    echo -e "  • MACsec configuration"
    echo -e "  • Management scripts"
    echo -e "  • Configuration: $CONFIG_DIR, $FORTRESS_CONFIG_DIR"
    echo -e "  • Secrets: VXLAN, MACsec"
    echo -e "  • Installation: $INSTALL_DIR"
    [ "$KEEP_DATA" = false ] && echo -e "  • Data: $DATA_DIR"
    [ "$KEEP_LOGS" = true ] && echo -e "  ${DIM}(Logs preserved at $LOG_DIR)${NC}"
    echo ""
    echo -e "  ${DIM}To reinstall Fortress:${NC}"
    echo -e "  ${DIM}sudo ./install.sh --tier fortress${NC}"
    echo ""
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
