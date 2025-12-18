#!/bin/bash
#
# HookProbe Fortress Uninstall Script
# Version: 5.4.0
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
# Usage: sudo ./uninstall.sh [--force] [--keep-logs] [--keep-data] [--keep-config]
#
# Stages:
#   1. Stop services
#   2. Clean network interfaces
#   3. Remove containers
#   4. Remove OVS/VLAN configuration
#   5. Remove systemd services
#   6. Remove management scripts
#   7. Handle configuration (optional preserve)
#   8. Handle data (optional preserve)
#   9. Handle logs (optional preserve)
#   10. Cleanup and verify
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
BACKUP_DIR="/var/backups/fortress"
STATE_FILE="${CONFIG_DIR}/fortress-state.json"
OVS_BRIDGE="43ess"

# ============================================================
# OPTIONS
# ============================================================
FORCE_MODE=false
KEEP_LOGS=false
KEEP_DATA=false
KEEP_CONFIG=false

# ============================================================
# LOGGING
# ============================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${CYAN}[STAGE]${NC} $1"; }
log_substep() { echo -e "  ${BLUE}→${NC} $1"; }

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
            --keep-config) KEEP_CONFIG=true; shift ;;
            --help|-h)
                echo "HookProbe Fortress Uninstaller v5.2.0"
                echo ""
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --force, -f     Skip confirmation prompts"
                echo "  --keep-logs     Preserve log files"
                echo "  --keep-data     Preserve data directories and database"
                echo "  --keep-config   Preserve configuration files (for reinstall)"
                echo "  --help, -h      Show this help message"
                echo ""
                echo "Stages performed:"
                echo "  1. Stop services"
                echo "  2. Clean network interfaces"
                echo "  3. Remove containers (monitoring, etc)"
                echo "  4. Remove OVS/VLAN configuration"
                echo "  5. Remove systemd services"
                echo "  6. Remove management scripts"
                echo "  7. Handle configuration"
                echo "  8. Handle data directories"
                echo "  9. Handle log files"
                echo "  10. Verify uninstall"
                echo ""
                echo "Examples:"
                echo "  $0                    # Interactive uninstall"
                echo "  $0 --force            # Non-interactive, remove all"
                echo "  $0 --keep-data        # Keep database for reinstall"
                echo "  $0 --keep-config      # Keep config for reinstall"
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
        "fortress"
        "hookprobe-fortress"
        "fortress-qsecbit"
        "fortress-lte-failover"
        "fortress-wan-failover"
        "fortress-tunnel"
        "fortress-dnsmasq"
        "fortress-wifi-allocator"
        "fortress-hostapd"
        "fortress-hostapd-24ghz"
        "fortress-hostapd-5ghz"
        "fortress-nat"
        "fortress-web"
        "fortress-channel-optimize"
        "fortress-ml-aggregator"
        "fortress-lstm-train"
    )

    # Stop the channel optimization timer first
    log_info "Stopping fortress-channel-optimize.timer..."
    systemctl stop fortress-channel-optimize.timer 2>/dev/null || true

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
# CLEAN UP NETWORK INTERFACES
# ============================================================
cleanup_network_interfaces() {
    log_step "Cleaning up network interfaces..."

    # Stop hostapd services (dual-band)
    log_info "Stopping hostapd services..."
    systemctl stop fortress-hostapd-24ghz 2>/dev/null || true
    systemctl stop fortress-hostapd-5ghz 2>/dev/null || true
    systemctl stop hostapd 2>/dev/null || true
    pkill -f hostapd 2>/dev/null || true

    # Stop dnsmasq
    systemctl stop fortress-dnsmasq 2>/dev/null || true

    # Find and clean up WiFi interfaces
    log_info "Cleaning up WiFi interface state..."
    for iface in $(find /sys/class/net -maxdepth 1 -name "wlan*" -o -name "wlp*" 2>/dev/null | xargs -I{} basename {}); do
        if [ -d "/sys/class/net/$iface" ]; then
            log_info "  Resetting interface: $iface"

            # Flush IP addresses
            ip addr flush dev "$iface" 2>/dev/null || true

            # Remove from any bridge
            ip link set "$iface" nomaster 2>/dev/null || true

            # Bring down and back up to reset state
            ip link set "$iface" down 2>/dev/null || true

            # Reset to managed mode for NetworkManager
            if command -v nmcli &>/dev/null; then
                nmcli device set "$iface" managed yes 2>/dev/null || true
            fi
        fi
    done

    # Clean up WWAN/LTE interfaces
    log_info "Cleaning up WWAN interfaces..."
    for iface in $(find /sys/class/net -maxdepth 1 -name "wwan*" -o -name "wwp*" 2>/dev/null | xargs -I{} basename {}); do
        if [ -d "/sys/class/net/$iface" ]; then
            log_info "  Resetting interface: $iface"
            ip addr flush dev "$iface" 2>/dev/null || true
            ip link set "$iface" down 2>/dev/null || true
        fi
    done

    # Clean up bridge interfaces created by Fortress
    log_info "Cleaning up bridge interfaces..."
    for bridge in fortress br-lan br-mgmt br-pos br-staff br-guest br-iot; do
        if ip link show "$bridge" &>/dev/null; then
            log_info "  Removing bridge: $bridge"

            # Remove all ports from bridge first
            for port in $(ip link show master "$bridge" 2>/dev/null | grep -oP '^\d+:\s+\K[^:@]+'); do
                ip link set "$port" nomaster 2>/dev/null || true
            done

            ip link set "$bridge" down 2>/dev/null || true
            ip link delete "$bridge" type bridge 2>/dev/null || true
        fi
    done

    # Clean up any stale default routes with fortress metrics
    log_info "Cleaning up route metrics..."
    # Remove routes with metric 100 and 200 that may be leftover
    ip route del default metric 100 2>/dev/null || true
    ip route del default metric 200 2>/dev/null || true

    # Remove hostapd configuration files
    log_info "Removing hostapd configuration files..."
    rm -f /etc/hostapd/hostapd-24ghz.conf 2>/dev/null || true
    rm -f /etc/hostapd/hostapd-5ghz.conf 2>/dev/null || true
    rm -f /etc/hostapd/hostapd.conf 2>/dev/null || true
    rm -f /etc/hostapd/hostapd.vlan 2>/dev/null || true
    rm -f /etc/hostapd/fortress.conf 2>/dev/null || true

    # Remove dnsmasq configuration
    rm -f /etc/dnsmasq.d/fortress*.conf 2>/dev/null || true

    # Remove WiFi configuration state
    rm -f /etc/hookprobe/wifi.conf 2>/dev/null || true
    rm -f /etc/hookprobe/wifi-ap.conf 2>/dev/null || true
    rm -rf /var/lib/fortress/network-interfaces.conf 2>/dev/null || true

    # Remove WiFi interface udev rules (stable naming)
    # Note: setup.sh creates 70-fortress-wifi.rules, but check both for compatibility
    local udev_removed=false
    for rule_file in /etc/udev/rules.d/70-fortress-wifi.rules /etc/udev/rules.d/80-fortress-wifi.rules; do
        if [ -f "$rule_file" ]; then
            log_info "Removing WiFi interface udev rules: $rule_file"
            rm -f "$rule_file"
            udev_removed=true
        fi
    done

    if [ "$udev_removed" = true ]; then
        # Reload udev rules
        udevadm control --reload-rules 2>/dev/null || true

        # Try to rename interfaces back to original names
        # This requires unbinding and rebinding the driver
        log_info "  Attempting to restore original interface names..."
        for iface in wlan_24ghz wlan_5ghz; do
            if [ -d "/sys/class/net/$iface" ]; then
                # Get the device path for driver rebind
                local dev_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null)
                local driver_path=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null)

                if [ -n "$dev_path" ] && [ -n "$driver_path" ]; then
                    local dev_name=$(basename "$dev_path")
                    log_info "  Rebinding $iface to restore original name..."
                    # Unbind and rebind to trigger re-enumeration
                    echo "$dev_name" > "$driver_path/unbind" 2>/dev/null || true
                    sleep 1
                    echo "$dev_name" > "$driver_path/bind" 2>/dev/null || true
                fi
            fi
        done

        # Trigger udev for any remaining interfaces
        udevadm trigger --action=add --subsystem-match=net 2>/dev/null || true
        log_info "  WiFi interface names will revert after reboot if not already"
    fi

    # Remove LAN bridge service and script
    if [ -f /etc/systemd/system/fortress-lan-bridge.service ]; then
        log_info "Removing LAN bridge service..."
        systemctl stop fortress-lan-bridge.service 2>/dev/null || true
        systemctl disable fortress-lan-bridge.service 2>/dev/null || true
        rm -f /etc/systemd/system/fortress-lan-bridge.service
        rm -f /usr/local/bin/fortress-lan-bridge.sh
        systemctl daemon-reload 2>/dev/null || true
    fi

    # Remove LAN bridge configuration
    rm -f /etc/hookprobe/lan-bridge.conf 2>/dev/null || true

    # Remove WiFi interface mapping file (keeps original→stable name mapping)
    rm -f /etc/hookprobe/wifi-interfaces.conf 2>/dev/null || true

    # Kill any remaining wpa_supplicant processes on AP interfaces
    pkill -f "wpa_supplicant.*wlan" 2>/dev/null || true

    log_info "Network interfaces cleaned up"
}

# ============================================================
# DISABLE AND REMOVE SYSTEMD SERVICES
# ============================================================
remove_systemd_services() {
    log_step "Removing systemd services..."

    local services=(
        "fortress"
        "hookprobe-fortress"
        "fortress-qsecbit"
        "fortress-lte-failover"
        "fortress-wan-failover"
        "fortress-tunnel"
        "fortress-dnsmasq"
        "fortress-wifi-allocator"
        "fortress-hostapd"
        "fortress-hostapd-24ghz"
        "fortress-hostapd-5ghz"
        "fortress-nat"
        "fortress-web"
        "fortress-channel-optimize"
        "fortress-dfs-monitor"
        "fortress-dfs-api"
        "fortress-ml-aggregator"
        "fortress-lstm-train"
    )

    # Disable and remove channel optimization timer
    log_info "Removing fortress-channel-optimize.timer..."
    systemctl disable fortress-channel-optimize.timer 2>/dev/null || true
    rm -f /etc/systemd/system/fortress-channel-optimize.timer

    # Disable and remove LSTM training timer
    log_info "Removing fortress-lstm-train.timer..."
    systemctl disable fortress-lstm-train.timer 2>/dev/null || true
    rm -f /etc/systemd/system/fortress-lstm-train.timer

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

    # Remove boot optimization overrides
    rm -rf /etc/systemd/system/systemd-networkd-wait-online.service.d 2>/dev/null || true
    rm -rf /etc/systemd/system/NetworkManager-wait-online.service.d 2>/dev/null || true

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
        "/usr/local/bin/fortress-wan-failover"
        "/usr/local/bin/fortress-nat-setup"
        "/usr/local/bin/fortress-channel-optimize.sh"
        "/usr/local/bin/fortress-wifi-prepare.sh"
        "/usr/local/bin/fortress-wifi-bridge.sh"
        "/usr/local/bin/fortress-dnsxai-privacy"
        "/usr/local/bin/dfs-channel-selector"
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

    # Container names - includes monitoring, ML, and data containers
    local containers=(
        # Core containers (container mode)
        "fortress-web"
        "fortress-postgres"
        "fortress-redis"
        # ML/AI containers
        "fortress-qsecbit"
        "fortress-agent"
        "fortress-dnsxai"
        "fortress-dfs"
        "fortress-lstm-trainer"
        # Monitoring containers (native mode)
        "fortress-victoria"
        "fortress-grafana"
        "fortress-victoriametrics"
        "fortress-n8n"
        "fortress-clickhouse"
        "fortress-suricata"
        "fortress-zeek"
    )

    for container in "${containers[@]}"; do
        if podman ps -a --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            log_info "Removing container: $container"
            podman stop "$container" 2>/dev/null || true
            podman rm -f "$container" 2>/dev/null || true
        fi
    done

    # Remove container images
    log_info "Removing container images..."
    local images=(
        "localhost/fortress-web:latest"
        "localhost/fortress-agent:latest"
        "localhost/fortress-dnsxai:latest"
        "localhost/fortress-dfs:latest"
        "localhost/fortress-lstm:latest"
    )

    for image in "${images[@]}"; do
        if podman images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -q "^${image}$"; then
            log_info "Removing image: $image"
            podman rmi -f "$image" 2>/dev/null || true
        fi
    done

    # Remove volumes
    log_info "Removing Podman volumes..."
    local volumes=(
        # Core volumes
        "fortress-postgres-data"
        "fortress-redis-data"
        "fortress-web-data"
        "fortress-web-logs"
        "fortress-config"
        # ML volumes
        "fortress-agent-data"
        "fortress-dnsxai-data"
        "fortress-dnsxai-blocklists"
        "fortress-dfs-data"
        "fortress-ml-models"
        # Monitoring volumes
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

    # Load saved LAN configuration to identify WAN (which must NOT be touched)
    local wan_iface=""
    local lan_ifaces=""
    if [ -f /etc/hookprobe/lan-bridge.conf ]; then
        source /etc/hookprobe/lan-bridge.conf
        wan_iface="${WAN_INTERFACE:-}"
        lan_ifaces="${LAN_INTERFACES:-}"
        log_info "Loaded bridge config - WAN: ${wan_iface:-none}, LAN: ${lan_ifaces:-none}"
    fi

    # Fallback: detect WAN from default route
    if [ -z "$wan_iface" ]; then
        wan_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
        [ -n "$wan_iface" ] && log_info "WAN detected from default route: $wan_iface"
    fi

    # Remove all ports from the bridge
    local ports
    ports=$(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null || true)

    for port in $ports; do
        # CRITICAL: Skip WAN interface - it should never have been in bridge anyway
        if [ "$port" = "$wan_iface" ]; then
            log_warn "WAN interface $wan_iface found in OVS bridge - removing safely"
            log_warn "WAN configuration will be preserved"
        fi

        log_info "Removing OVS port: $port"
        ovs-vsctl --if-exists del-port "$OVS_BRIDGE" "$port" 2>/dev/null || true

        # Restore ethernet LAN interfaces to normal state (but not WAN!)
        if [ "$port" != "$wan_iface" ]; then
            # Check if this is a physical ethernet interface (not VLAN/internal)
            if [[ "$port" =~ ^(eth|enp|eno|ens)[0-9] ]]; then
                log_info "  Restoring interface $port to normal state"
                # Enable DHCP on the interface via NetworkManager if available
                if command -v nmcli &>/dev/null; then
                    nmcli device set "$port" managed yes 2>/dev/null || true
                fi
            fi
        fi
    done

    # Remove the bridge itself
    log_info "Removing OVS bridge: $OVS_BRIDGE"
    ip link set "$OVS_BRIDGE" down 2>/dev/null || true
    ovs-vsctl --if-exists del-br "$OVS_BRIDGE" 2>/dev/null || true

    # Log WAN preservation notice
    if [ -n "$wan_iface" ]; then
        log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_info "WAN INTERFACE PRESERVED: $wan_iface"
        log_info "  Your internet connection through this interface is intact"
        log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    fi

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
# REMOVE NFTABLES FILTERING
# ============================================================
remove_nftables_filtering() {
    log_step "Removing nftables filter rules..."

    # Stop device monitor service
    systemctl stop fortress-device-monitor 2>/dev/null || true
    systemctl disable fortress-device-monitor 2>/dev/null || true
    rm -f /etc/systemd/system/fortress-device-monitor.service

    # Remove nftables rules
    if command -v nft &>/dev/null; then
        log_info "Removing nftables fortress_filter table..."
        nft delete table inet fortress_filter 2>/dev/null || true
    fi

    # Remove nftables config file
    rm -f /etc/nftables.d/fortress-filters.nft

    # Remove OUI database and policy files
    rm -f /etc/hookprobe/oui_policies.conf
    rm -rf /var/lib/fortress/filters

    log_info "nftables filtering removed"
}

# ============================================================
# REMOVE DFS INTELLIGENCE
# ============================================================
remove_dfs_intelligence() {
    log_step "Removing DFS intelligence..."

    # Stop DFS services
    systemctl stop fortress-dfs-monitor 2>/dev/null || true
    systemctl stop fortress-dfs-api 2>/dev/null || true
    systemctl disable fortress-dfs-monitor 2>/dev/null || true
    systemctl disable fortress-dfs-api 2>/dev/null || true

    # Remove service files
    rm -f /etc/systemd/system/fortress-dfs-monitor.service
    rm -f /etc/systemd/system/fortress-dfs-api.service

    # Remove DFS directory and scripts
    rm -rf /opt/hookprobe/fortress/dfs
    rm -f /usr/local/bin/dfs-channel-selector

    # Remove DFS database (keep by default - user may want history)
    if [ "$REMOVE_DATA" = true ]; then
        rm -f /var/lib/hookprobe/dfs_intelligence.db
    else
        log_info "DFS database preserved: /var/lib/hookprobe/dfs_intelligence.db"
        log_info "  (Use --remove-data to delete)"
    fi

    # Remove DFS state files
    rm -rf /var/lib/fortress/dfs

    # Remove shared wireless module (if not used by other products)
    if [ ! -d /opt/hookprobe/guardian ] && [ ! -d /opt/hookprobe/nexus ]; then
        rm -rf /opt/hookprobe/shared/wireless
    fi

    log_info "DFS intelligence removed"
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

    # Remove all Fortress NetworkManager config files
    local nm_configs=(
        "/etc/NetworkManager/conf.d/fortress-unmanaged.conf"
        "/etc/NetworkManager/conf.d/fortress-wifi.conf"
    )

    for nm_conf in "${nm_configs[@]}"; do
        if [ -f "$nm_conf" ]; then
            log_info "Removing $nm_conf..."
            rm -f "$nm_conf"
        fi
    done

    # Reload NetworkManager if running
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        nmcli general reload 2>/dev/null || true
    fi

    # Remove LTE connection if it exists
    nmcli con delete "fortress-lte" 2>/dev/null || true

    # Remove WiFi helper scripts
    rm -f /usr/local/bin/fortress-wifi-prepare.sh 2>/dev/null || true
    rm -f /usr/local/bin/fortress-wifi-bridge.sh 2>/dev/null || true

    # Restore WiFi interface to managed mode
    local wifi_conf="/etc/hookprobe/wifi-ap.conf"
    if [ -f "$wifi_conf" ]; then
        local wifi_iface=$(grep "^WIFI_INTERFACE=" "$wifi_conf" | cut -d= -f2)
        if [ -n "$wifi_iface" ]; then
            log_info "Restoring WiFi interface $wifi_iface to managed mode..."
            nmcli device set "$wifi_iface" managed yes 2>/dev/null || true
        fi
    fi

    # Restore netplan backup if it exists
    for backup in /etc/netplan/*.yaml.fortress-backup; do
        if [ -f "$backup" ]; then
            original="${backup%.fortress-backup}"
            log_info "Restoring netplan backup: $original"
            mv "$backup" "$original"
        fi
    done
    netplan apply 2>/dev/null || true

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
        "$CONFIG_DIR/wan-failover.conf"
    )

    for conf in "${config_files[@]}"; do
        if [ -f "$conf" ]; then
            log_info "Removing $(basename $conf)..."
            rm -f "$conf"
        fi
    done

    # Remove MACsec interface configs
    rm -f "$CONFIG_DIR"/macsec-*.conf 2>/dev/null || true

    # Remove dnsXai privacy configuration
    if [ -d "$CONFIG_DIR/dnsxai" ]; then
        log_info "Removing dnsXai privacy configuration..."
        rm -rf "$CONFIG_DIR/dnsxai"
    fi

    # Remove users.json
    rm -f "$CONFIG_DIR/users.json" 2>/dev/null || true

    # Remove hostapd configuration
    if [ -f /etc/hostapd/fortress.conf ]; then
        log_info "Removing hostapd configuration..."
        rm -f /etc/hostapd/fortress.conf
    fi

    # Remove dnsmasq configuration (both old and new VLAN config)
    if [ -f /etc/dnsmasq.d/fortress.conf ] || [ -f /etc/dnsmasq.d/fortress-vlans.conf ]; then
        log_info "Removing dnsmasq configuration..."
        rm -f /etc/dnsmasq.d/fortress.conf
        rm -f /etc/dnsmasq.d/fortress-vlans.conf
        rm -f /etc/dnsmasq.d/fortress-bridge.conf
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

    # Remove SSL certificates
    if [ -d /etc/hookprobe/ssl ]; then
        log_info "Removing SSL certificates..."
        rm -rf /etc/hookprobe/ssl
    fi

    # Remove admin password and secret key
    rm -f "$SECRETS_DIR/admin_password" 2>/dev/null || true
    rm -f "$SECRETS_DIR/fortress_secret_key" 2>/dev/null || true

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
# REMOVE LTE AND WAN FAILOVER CONFIGURATION
# ============================================================
remove_lte_config() {
    log_step "Removing LTE and WAN failover configuration..."

    # Remove WAN failover state file
    if [ -f "/var/lib/fortress/wan-failover-state.json" ]; then
        log_info "Removing WAN failover state..."
        rm -f /var/lib/fortress/wan-failover-state.json
    fi

    # Remove WAN failover lock file
    rm -f /var/run/fortress-wan-failover.lock 2>/dev/null || true

    # Remove LTE state directory
    if [ -d "$LTE_STATE_DIR" ]; then
        log_info "Removing $LTE_STATE_DIR..."
        rm -rf "$LTE_STATE_DIR"
    fi

    # Clean up parent directory if empty
    if [ -d "/var/lib/fortress" ] && [ -z "$(ls -A /var/lib/fortress 2>/dev/null)" ]; then
        rmdir "/var/lib/fortress" 2>/dev/null || true
    fi

    log_info "LTE and WAN failover configuration removed"
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
        # Remove security monitoring data
        rm -rf /opt/hookprobe/fortress/data/suricata-logs 2>/dev/null || true
        rm -rf /opt/hookprobe/fortress/data/zeek-logs 2>/dev/null || true
        rm -rf /opt/hookprobe/fortress/data/ml-models 2>/dev/null || true
        rm -rf /opt/hookprobe/fortress/data/threat-intel 2>/dev/null || true
        rm -rf /opt/hookprobe/fortress/ml 2>/dev/null || true
        rm -rf /opt/hookprobe/fortress/zeek 2>/dev/null || true
        rm -rf /opt/hookprobe/fortress/lib 2>/dev/null || true
        # Remove ML training logs
        rm -f /var/log/hookprobe/ml-aggregator.log 2>/dev/null || true
        rm -f /var/log/hookprobe/lstm-training.log 2>/dev/null || true
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
    for svc in fortress hookprobe-fortress fortress-qsecbit fortress-lte-failover; do
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

    # Check containers (core + monitoring)
    if command -v podman &>/dev/null; then
        for container in fortress-web fortress-postgres fortress-redis fortress-qsecbit fortress-dnsxai fortress-dfs fortress-victoria fortress-grafana fortress-suricata fortress-zeek; do
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
# STATE FILE HANDLING
# ============================================================
remove_state_file() {
    if [ "$KEEP_CONFIG" = true ]; then
        log_info "Preserving state file: $STATE_FILE"
        # Update state to indicate uninstalled
        if [ -f "$STATE_FILE" ]; then
            python3 -c "
import json
with open('$STATE_FILE', 'r') as f:
    d = json.load(f)
d['last_action'] = 'uninstalled'
d['uninstalled_at'] = '$(date -Iseconds)'
with open('$STATE_FILE', 'w') as f:
    json.dump(d, f, indent=2)
" 2>/dev/null || true
        fi
    else
        if [ -f "$STATE_FILE" ]; then
            log_info "Removing state file: $STATE_FILE"
            rm -f "$STATE_FILE"
        fi
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
    echo -e "${BOLD}${RED}║                    Version 5.1.0                           ║${NC}"
    echo -e "${BOLD}${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    check_root

    # Show current state if available
    if [ -f "$STATE_FILE" ]; then
        local mode=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('deployment_mode', 'native'))" 2>/dev/null || echo "native")
        local version=$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null || echo "unknown")
        log_info "Detected installation: ${mode} mode, version ${version}"
    fi

    if [ "$FORCE_MODE" = false ]; then
        echo ""
        echo -e "${YELLOW}This will remove the following components:${NC}"
        echo ""
        echo -e "  ${BOLD}Services:${NC}"
        echo -e "    • Fortress systemd services (hookprobe-fortress, fortress-qsecbit)"
        echo -e "    • WiFi AP (hostapd), DHCP (dnsmasq)"
        echo ""
        echo -e "  ${BOLD}Containers:${NC}"
        echo -e "    • VictoriaMetrics, Grafana, Suricata, Zeek"
        echo ""
        echo -e "  ${BOLD}Network:${NC}"
        echo -e "    • OVS bridge and VLAN/VXLAN configuration"
        echo -e "    • MACsec interfaces and configuration"
        echo -e "    • LTE failover configuration"
        echo ""
        echo -e "  ${BOLD}Files:${NC}"
        echo -e "    • Management scripts"
        [ "$KEEP_CONFIG" = false ] && echo -e "    • Configuration files ($CONFIG_DIR)"
        echo -e "    • Installation directory ($INSTALL_DIR)"
        [ "$KEEP_DATA" = false ] && echo -e "    • Data directory ($DATA_DIR)"
        [ "$KEEP_LOGS" = false ] && echo -e "    • Log files ($LOG_DIR)"
        echo ""

        if [ "$KEEP_DATA" = true ]; then
            echo -e "${GREEN}  Data will be PRESERVED for reinstallation.${NC}"
        fi
        if [ "$KEEP_CONFIG" = true ]; then
            echo -e "${GREEN}  Configuration will be PRESERVED for reinstallation.${NC}"
        fi
        echo ""

        read -p "Are you sure you want to continue? (yes/no) [no]: " confirm
        if [ "$confirm" != "yes" ]; then
            log_info "Uninstall cancelled"
            exit 0
        fi
    fi

    echo ""

    # Stage 1: Stop services
    log_step "Stage 1/10: Stopping services"
    stop_services

    # Stage 2: Clean network interfaces
    log_step "Stage 2/10: Cleaning network interfaces"
    cleanup_network_interfaces

    # Stage 3: Remove containers
    log_step "Stage 3/10: Removing containers"
    remove_containers

    # Stage 4: Remove OVS configuration
    log_step "Stage 4/10: Removing OVS configuration"
    remove_ovs_config
    remove_vlan_interfaces
    remove_macsec_interfaces
    remove_nftables_filtering
    remove_dfs_intelligence

    # Stage 5: Remove systemd services
    log_step "Stage 5/10: Removing systemd services"
    remove_systemd_services

    # Stage 6: Remove management scripts
    log_step "Stage 6/10: Removing management scripts"
    remove_management_scripts
    remove_freeradius_config
    remove_networkmanager_config

    # Stage 7: Handle configuration
    log_step "Stage 7/10: Handling configuration"
    if [ "$KEEP_CONFIG" = true ]; then
        log_info "Preserving configuration files"
    else
        remove_lte_config
        remove_configuration
    fi

    # Stage 8: Handle data and installation
    log_step "Stage 8/10: Handling data and installation"
    remove_routing_tables
    remove_sysctl_settings
    remove_installation

    # Stage 9: Handle logs
    log_step "Stage 9/10: Handling logs"
    handle_logs

    # Stage 10: Cleanup and verify
    log_step "Stage 10/10: Final cleanup and verification"
    remove_state_file
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
    echo -e "  • Security monitoring (Suricata, Zeek)"
    echo -e "  • ML/LSTM threat detection"
    echo -e "  • dnsXai privacy controls"
    echo -e "  • OVS bridge: $OVS_BRIDGE"
    echo -e "  • VLAN interfaces (10, 20, 30, 40, 99)"
    echo -e "  • VXLAN tunnels"
    echo -e "  • MACsec configuration"
    echo -e "  • Management scripts"
    echo -e "  • Configuration: $CONFIG_DIR, $FORTRESS_CONFIG_DIR"
    echo -e "  • Secrets: VXLAN, MACsec"
    echo -e "  • WiFi udev rules (interface names revert after reboot)"
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
