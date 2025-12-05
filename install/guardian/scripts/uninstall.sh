#!/bin/bash
#
# HookProbe Guardian Uninstall Script
# Version: 5.0.0
# License: MIT
#
# Removes all Guardian components:
# - Podman containers (Suricata, AdGuard)
# - Systemd services
# - Network bridges and VLAN interfaces
# - hostapd and dnsmasq configurations
# - nftables rules
# - Guardian directories
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
    log_step "Stopping Guardian services..."

    local services=(
        "guardian-webui"
        "guardian-suricata"
        "guardian-adguard"
        "guardian-qsecbit"
        "hostapd"
        "dnsmasq"
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
        "guardian-webui"
        "guardian-suricata"
        "guardian-adguard"
        "guardian-qsecbit"
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

    # Reload systemd
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
        "guardian-suricata"
        "guardian-adguard"
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
        "guardian-suricata-logs"
        "guardian-suricata-rules"
        "guardian-adguard-work"
        "guardian-adguard-conf"
    )

    for volume in "${volumes[@]}"; do
        if podman volume exists "$volume" 2>/dev/null; then
            log_info "Removing volume: $volume"
            podman volume rm "$volume" 2>/dev/null || true
        fi
    done

    # Remove network
    if podman network exists guardian-net 2>/dev/null; then
        log_info "Removing network: guardian-net"
        podman network rm guardian-net 2>/dev/null || true
    fi

    log_info "Containers removed"
}

# ============================================================
# REMOVE NETWORK INTERFACES
# ============================================================
remove_network_interfaces() {
    log_step "Removing network interfaces..."

    # Remove VLAN bridges (SDN mode)
    local vlans=(10 20 30 40 50 60 70 80 999)
    for vlan in "${vlans[@]}"; do
        if ip link show "br${vlan}" &>/dev/null; then
            log_info "Removing bridge: br${vlan}"
            ip link set "br${vlan}" down 2>/dev/null || true
            ip link delete "br${vlan}" 2>/dev/null || true
        fi
    done

    # Remove VLAN interfaces
    for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -E '\.[0-9]+$'); do
        log_info "Removing VLAN interface: $iface"
        ip link set "$iface" down 2>/dev/null || true
        ip link delete "$iface" 2>/dev/null || true
    done

    # Remove main bridge (basic mode)
    if ip link show br0 &>/dev/null; then
        log_info "Removing bridge: br0"
        ip link set br0 down 2>/dev/null || true
        ip link delete br0 2>/dev/null || true
    fi

    # Remove any VXLAN interfaces
    for vxlan in $(ip -o link show | awk -F': ' '{print $2}' | grep -E '^vxlan'); do
        log_info "Removing VXLAN interface: $vxlan"
        ip link set "$vxlan" down 2>/dev/null || true
        ip link delete "$vxlan" 2>/dev/null || true
    done

    # Remove OVS bridges if present
    if command -v ovs-vsctl &>/dev/null; then
        for bridge in $(ovs-vsctl list-br 2>/dev/null); do
            if [[ "$bridge" == *guardian* ]] || [[ "$bridge" == "br-sdn" ]]; then
                log_info "Removing OVS bridge: $bridge"
                ovs-vsctl del-br "$bridge" 2>/dev/null || true
            fi
        done
    fi

    log_info "Network interfaces removed"
}

# ============================================================
# REMOVE NFTABLES RULES
# ============================================================
remove_nftables_rules() {
    log_step "Removing nftables rules..."

    # Delete Guardian table if it exists
    if nft list tables 2>/dev/null | grep -q "guardian"; then
        log_info "Removing nftables table: guardian"
        nft delete table inet guardian 2>/dev/null || true
    fi

    # Remove nftables configuration files
    rm -f /etc/nftables.d/guardian.nft
    rm -f /etc/nftables.d/guardian-vlans.nft

    log_info "nftables rules removed"
}

# ============================================================
# REMOVE HOSTAPD CONFIGURATION
# ============================================================
remove_hostapd_config() {
    log_step "Removing hostapd configuration..."

    rm -f /etc/hostapd/hostapd.conf
    rm -f /etc/hostapd/hostapd.vlan
    rm -f /etc/hostapd/hostapd.accept
    rm -f /etc/hostapd/hostapd.deny
    rm -f /etc/default/hostapd

    # Restore default hostapd if needed
    if [ -f /etc/hostapd/hostapd.conf.bak ]; then
        mv /etc/hostapd/hostapd.conf.bak /etc/hostapd/hostapd.conf
        log_info "Restored original hostapd.conf"
    fi

    log_info "hostapd configuration removed"
}

# ============================================================
# REMOVE DNSMASQ CONFIGURATION
# ============================================================
remove_dnsmasq_config() {
    log_step "Removing dnsmasq configuration..."

    rm -f /etc/dnsmasq.d/guardian.conf

    # Restore original dnsmasq config if backed up
    if [ -f /etc/dnsmasq.conf.bak ]; then
        mv /etc/dnsmasq.conf.bak /etc/dnsmasq.conf
        log_info "Restored original dnsmasq.conf"
    fi

    log_info "dnsmasq configuration removed"
}

# ============================================================
# REMOVE SYSCTL SETTINGS
# ============================================================
remove_sysctl_settings() {
    log_step "Removing sysctl settings..."

    rm -f /etc/sysctl.d/99-guardian.conf

    # Reload sysctl
    sysctl --system &>/dev/null || true

    log_info "sysctl settings removed"
}

# ============================================================
# REMOVE GUARDIAN DIRECTORIES
# ============================================================
remove_guardian_directories() {
    log_step "Removing Guardian directories..."

    rm -rf /opt/hookprobe/guardian

    # Don't remove /opt/hookprobe if other components exist
    if [ -d /opt/hookprobe ] && [ -z "$(ls -A /opt/hookprobe 2>/dev/null)" ]; then
        rm -rf /opt/hookprobe
        log_info "Removed /opt/hookprobe (was empty)"
    fi

    log_info "Guardian directories removed"
}

# ============================================================
# OPTIONAL: REMOVE PACKAGES
# ============================================================
remove_packages() {
    log_step "Removing installed packages (optional)..."

    read -p "Remove hostapd and dnsmasq packages? (yes/no) [no]: " remove_pkgs
    if [ "$remove_pkgs" != "yes" ]; then
        log_info "Skipping package removal"
        return 0
    fi

    if command -v apt-get &>/dev/null; then
        apt-get remove -y hostapd dnsmasq 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf remove -y hostapd dnsmasq 2>/dev/null || true
    fi

    log_info "Packages removed"
}

# ============================================================
# RESTORE NETWORK
# ============================================================
restore_network() {
    log_step "Restoring network configuration..."

    # Restart networking service to restore original config
    if systemctl is-active NetworkManager &>/dev/null; then
        log_info "Restarting NetworkManager..."
        systemctl restart NetworkManager
    elif systemctl is-active networking &>/dev/null; then
        log_info "Restarting networking..."
        systemctl restart networking
    fi

    # Bring up original interfaces
    for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|enp|eno|wlan|wlp)'); do
        if ! ip link show "$iface" | grep -q "UP"; then
            log_info "Bringing up interface: $iface"
            ip link set "$iface" up 2>/dev/null || true
        fi
    done

    log_info "Network restored"
}

# ============================================================
# MAIN
# ============================================================
main() {
    echo ""
    echo -e "${BOLD}${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${RED}║              HookProbe Guardian Uninstaller                ║${NC}"
    echo -e "${BOLD}${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    check_root

    echo -e "${YELLOW}WARNING: This will remove all Guardian components including:${NC}"
    echo -e "  - Guardian systemd services"
    echo -e "  - Podman containers (Suricata IDS, AdGuard)"
    echo -e "  - Network bridges and VLAN interfaces"
    echo -e "  - WiFi hotspot (hostapd) configuration"
    echo -e "  - DHCP/DNS (dnsmasq) configuration"
    echo -e "  - nftables firewall rules"
    echo -e "  - Guardian data directories"
    echo ""

    read -p "Are you sure you want to continue? (yes/no) [no]: " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "Uninstall cancelled"
        exit 0
    fi

    echo ""

    # Stop all services first
    stop_services

    # Remove components in order
    remove_containers
    remove_network_interfaces
    remove_nftables_rules
    remove_hostapd_config
    remove_dnsmasq_config
    remove_sysctl_settings
    remove_systemd_services
    remove_guardian_directories

    # Restore network
    restore_network

    # Optional package removal
    remove_packages

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Guardian Uninstall Complete!                     ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Removed:${NC}"
    echo -e "  • Guardian systemd services"
    echo -e "  • Podman containers and volumes"
    echo -e "  • Network bridges (br0, br10-br999)"
    echo -e "  • VLAN interfaces"
    echo -e "  • hostapd configuration"
    echo -e "  • dnsmasq configuration"
    echo -e "  • nftables rules"
    echo -e "  • Guardian directories"
    echo ""
    echo -e "  ${YELLOW}Note:${NC} You may need to reboot for all changes to take effect."
    echo -e "  ${DIM}Reboot: sudo reboot${NC}"
    echo ""
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
