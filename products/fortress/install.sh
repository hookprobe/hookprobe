#!/bin/bash
#
# HookProbe Fortress - Unified Installer
# Version: 5.5.0
# License: AGPL-3.0
#
# Single entry point for all Fortress operations:
#   - Install (container mode with VLAN segmentation)
#   - Uninstall (staged with data preservation options)
#   - Backup/Restore
#   - Status and diagnostics
#
# For upgrades, use: backup + uninstall --keep-data + install
#
# Usage:
#   ./install.sh                      # Interactive install
#   ./install.sh --container          # Container-based installation
#   ./install.sh uninstall --keep-data  # Uninstall but keep data
#   ./install.sh status               # Show installation status
#
# For detailed help: ./install.sh --help
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="5.5.0"

# ============================================================
# PATHS
# ============================================================
INSTALL_DIR="/opt/hookprobe/fortress"
CONFIG_DIR="/etc/hookprobe"
DATA_DIR="/var/lib/hookprobe/fortress"
BACKUP_DIR="/var/backups/fortress"
LOG_DIR="/var/log/hookprobe"
STATE_FILE="${CONFIG_DIR}/fortress-state.json"
VERSION_FILE="${INSTALL_DIR}/VERSION"

# ============================================================
# COLORS
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ============================================================
# LOGGING
# ============================================================
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

           F O R T R E S S   v5.1.0
        Unified Security Gateway Installer
EOF
    echo -e "${NC}"
}

# ============================================================
# STATE DETECTION
# ============================================================
detect_installation() {
    # Check if Fortress is already installed
    if [ -f "$STATE_FILE" ]; then
        INSTALLED=true
        DEPLOYMENT_MODE=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('deployment_mode', 'unknown'))" 2>/dev/null || echo "unknown")
        INSTALLED_VERSION=$(cat "$VERSION_FILE" 2>/dev/null || echo "unknown")
        return 0
    fi

    # Fallback detection
    if [ -d "$INSTALL_DIR" ] || systemctl is-active fortress &>/dev/null || systemctl is-active hookprobe-fortress &>/dev/null; then
        INSTALLED=true
        # Try to detect mode
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fortress"; then
            DEPLOYMENT_MODE="container"
        elif systemctl is-enabled hookprobe-fortress &>/dev/null; then
            DEPLOYMENT_MODE="native"
        else
            DEPLOYMENT_MODE="unknown"
        fi
        INSTALLED_VERSION=$(cat "$VERSION_FILE" 2>/dev/null || echo "unknown")
        return 0
    fi

    INSTALLED=false
    DEPLOYMENT_MODE=""
    INSTALLED_VERSION=""
    return 0  # Return 0 to avoid set -e exit; INSTALLED=false indicates no installation
}

save_state() {
    local mode="$1"

    mkdir -p "$(dirname "$STATE_FILE")"
    cat > "$STATE_FILE" << EOF
{
    "deployment_mode": "${mode}",
    "version": "${VERSION}",
    "installed_at": "$(date -Iseconds)",
    "installer_version": "${VERSION}",
    "last_action": "install"
}
EOF
    chmod 600 "$STATE_FILE"

    # Create VERSION file
    mkdir -p "$INSTALL_DIR"
    echo "$VERSION" > "$VERSION_FILE"
}

update_state() {
    local key="$1"
    local value="$2"

    if [ -f "$STATE_FILE" ]; then
        python3 -c "
import json
with open('$STATE_FILE', 'r') as f:
    d = json.load(f)
d['$key'] = '$value'
d['last_updated'] = '$(date -Iseconds)'
with open('$STATE_FILE', 'w') as f:
    json.dump(d, f, indent=2)
" 2>/dev/null || true
    fi
}

# ============================================================
# PRE-FLIGHT CHECKS
# ============================================================
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo "Try: sudo $0 $*"
        exit 1
    fi
}

check_system() {
    log_step "System Check"

    # RAM check
    local total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$total_ram" -lt 2048 ]; then
        log_warn "Low RAM: ${total_ram}MB. Container mode recommended for <4GB."
    else
        log_info "RAM: ${total_ram}MB"
    fi

    # Disk check
    local free_disk=$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')
    if [ "$free_disk" -lt 10 ]; then
        log_warn "Low disk space: ${free_disk}GB free. Recommend 20GB+."
    else
        log_info "Disk: ${free_disk}GB free"
    fi

    # Architecture
    local arch=$(uname -m)
    log_info "Architecture: ${arch}"

    # Check for existing installation
    detect_installation
    if [ "$INSTALLED" = true ]; then
        log_info "Existing installation detected: ${DEPLOYMENT_MODE} mode, version ${INSTALLED_VERSION}"
    fi
}

# ============================================================
# MODE SELECTION
# ============================================================
select_installation_mode() {
    # Fortress uses container mode by default
    # All components (web, network, WiFi) are handled by install-container.sh
    SELECTED_MODE="container"
    log_info "Using container mode (default for Fortress)"
}

# ============================================================
# INSTALL FUNCTIONS
# ============================================================
do_install() {
    local mode="${1:-}"
    local extra_args="${@:2}"

    if [ "$INSTALLED" = true ]; then
        echo ""
        log_warn "Fortress is already installed (${DEPLOYMENT_MODE} mode, v${INSTALLED_VERSION})"
        echo ""
        echo "Options:"
        echo "  1) Upgrade existing installation"
        echo "  2) Uninstall and reinstall"
        echo "  3) Cancel"
        echo ""
        read -p "Select [1-3]: " choice

        case "$choice" in
            1)
                show_upgrade_guidance
                return
                ;;
            2)
                do_uninstall --force
                INSTALLED=false
                ;;
            *)
                log_info "Installation cancelled"
                exit 0
                ;;
        esac
    fi

    # Default to container mode
    if [ -z "$mode" ]; then
        mode="container"
    fi

    case "$mode" in
        container)
            log_step "Starting container-based installation"
            save_state "container"
            exec "${SCRIPT_DIR}/install-container.sh" $extra_args
            ;;
        native)
            # Native mode is deprecated - redirect to container mode
            log_warn "Native mode is deprecated. Using container mode instead."
            log_info "Container mode now includes all network features (bridge, WiFi AP, DHCP, NAT)"
            save_state "container"
            exec "${SCRIPT_DIR}/install-container.sh" $extra_args
            ;;
        *)
            log_error "Unknown mode: $mode"
            exit 1
            ;;
    esac
}

# ============================================================
# UPGRADE GUIDANCE
# ============================================================
show_upgrade_guidance() {
    if [ "$INSTALLED" != true ]; then
        log_error "No existing installation found"
        echo "Run: $0 install"
        exit 1
    fi

    log_step "Upgrade Fortress (${DEPLOYMENT_MODE} mode, v${INSTALLED_VERSION})"

    echo ""
    echo "To upgrade Fortress, follow these steps:"
    echo ""
    echo "  1. Create a backup:"
    echo "     fortress-ctl backup --full"
    echo ""
    echo "  2. Uninstall while keeping data:"
    echo "     fortress-ctl uninstall --keep-data"
    echo ""
    echo "  3. Run fresh install (will use preserved data):"
    echo "     ./install.sh"
    echo ""
    echo "This ensures a clean installation without network issues."
    echo ""

    read -p "Would you like to start this process now? [y/N]: " confirm

    if [[ "${confirm}" =~ ^[Yy]$ ]]; then
        log_step "Step 1: Creating backup..."
        "${SCRIPT_DIR}/fortress-ctl.sh" backup --full || true

        log_step "Step 2: Uninstalling (keeping data)..."
        "${SCRIPT_DIR}/fortress-ctl.sh" uninstall --keep-data

        log_step "Step 3: Running fresh install..."
        exec "${SCRIPT_DIR}/install-container.sh"
    else
        log_info "Upgrade cancelled. Run the commands above when ready."
        exit 0
    fi
}

# ============================================================
# UNINSTALL FUNCTIONS
# ============================================================
do_uninstall() {
    local force=false
    local keep_data=false
    local keep_config=false
    local purge=false

    # Parse options
    for arg in "$@"; do
        case "$arg" in
            --force|-f) force=true ;;
            --keep-data) keep_data=true ;;
            --keep-config) keep_config=true ;;
            --purge) purge=true ;;
        esac
    done

    if [ "$INSTALLED" != true ]; then
        log_warn "No installation detected"
        exit 0
    fi

    if [ "$force" != true ]; then
        echo ""
        echo -e "${RED}Uninstall Fortress${NC}"
        echo ""
        echo "Current installation:"
        echo "  Mode:    ${DEPLOYMENT_MODE}"
        echo "  Version: ${INSTALLED_VERSION}"
        echo ""
        echo "Options:"
        echo "  1) Remove but keep data (can reinstall later)"
        echo "  2) Remove but keep configuration"
        echo "  3) Remove everything (purge)"
        echo "  4) Cancel"
        echo ""
        read -p "Select [1-4]: " choice

        case "$choice" in
            1) keep_data=true ;;
            2) keep_config=true ;;
            3) purge=true ;;
            *)
                log_info "Uninstall cancelled"
                exit 0
                ;;
        esac
    fi

    # Delegate to appropriate uninstaller
    case "$DEPLOYMENT_MODE" in
        container)
            local args=""
            [ "$keep_data" = true ] && args="$args --keep-data"
            [ "$keep_config" = true ] && args="$args --keep-config"
            [ "$purge" = true ] && args="$args --purge"
            exec "${SCRIPT_DIR}/install-container.sh" --uninstall $args
            ;;
        native)
            local args=""
            [ "$force" = true ] && args="$args --force"
            [ "$keep_data" = true ] && args="$args --keep-data"
            exec "${SCRIPT_DIR}/uninstall.sh" $args
            ;;
        *)
            log_warn "Unknown deployment mode. Attempting generic uninstall..."
            exec "${SCRIPT_DIR}/uninstall.sh" --force
            ;;
    esac
}

# ============================================================
# BACKUP/RESTORE FUNCTIONS
# ============================================================
do_backup() {
    local backup_type="${1:---full}"

    if [ "$INSTALLED" != true ]; then
        log_error "No installation to backup"
        exit 1
    fi

    # Use fortress-ctl for container mode
    if [ "$DEPLOYMENT_MODE" = "container" ] && [ -x "${SCRIPT_DIR}/fortress-ctl.sh" ]; then
        exec "${SCRIPT_DIR}/fortress-ctl.sh" backup "$backup_type"
    fi

    # Native mode backup
    log_step "Creating backup (${DEPLOYMENT_MODE} mode)"

    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_name="fortress_${backup_type#--}_${timestamp}"
    local backup_path="${BACKUP_DIR}/${backup_name}"

    mkdir -p "$backup_path"

    # Configuration
    log_info "Backing up configuration..."
    if [ -d "$CONFIG_DIR" ]; then
        cp -r "$CONFIG_DIR" "${backup_path}/config"
    fi

    # Database (if PostgreSQL is local)
    if systemctl is-active postgresql &>/dev/null; then
        log_info "Backing up PostgreSQL..."
        sudo -u postgres pg_dump fortress > "${backup_path}/database.sql" 2>/dev/null || true
    fi

    # Web application
    if [ -d "${INSTALL_DIR}/web" ]; then
        log_info "Backing up web application..."
        tar -czf "${backup_path}/webapp.tar.gz" -C "$INSTALL_DIR" web lib 2>/dev/null || true
    fi

    # Systemd services
    mkdir -p "${backup_path}/systemd"
    cp /etc/systemd/system/fortress*.service "${backup_path}/systemd/" 2>/dev/null || true
    cp /etc/systemd/system/hookprobe*.service "${backup_path}/systemd/" 2>/dev/null || true

    # Network configuration
    mkdir -p "${backup_path}/network"
    cp /etc/dnsmasq.d/fortress*.conf "${backup_path}/network/" 2>/dev/null || true
    cp /etc/hostapd/*.conf "${backup_path}/network/" 2>/dev/null || true
    ovs-vsctl show > "${backup_path}/network/ovs.txt" 2>/dev/null || true
    nft list ruleset > "${backup_path}/network/nftables.conf" 2>/dev/null || true

    # Create manifest
    cat > "${backup_path}/manifest.json" << EOF
{
    "type": "${backup_type#--}",
    "timestamp": "${timestamp}",
    "version": "${INSTALLED_VERSION}",
    "deployment_mode": "${DEPLOYMENT_MODE}",
    "created_by": "install.sh ${VERSION}"
}
EOF

    # Create archive
    tar -czf "${BACKUP_DIR}/${backup_name}.tar.gz" -C "$BACKUP_DIR" "$backup_name"
    rm -rf "$backup_path"

    log_info "Backup created: ${BACKUP_DIR}/${backup_name}.tar.gz"
}

do_restore() {
    local backup_file="$1"

    if [ -z "$backup_file" ]; then
        log_step "Available backups"
        ls -la "${BACKUP_DIR}/"*.tar.gz 2>/dev/null || {
            log_warn "No backups found in $BACKUP_DIR"
            exit 1
        }
        echo ""
        read -p "Enter backup filename to restore: " backup_file
    fi

    if [ ! -f "$backup_file" ]; then
        # Try with backup dir prefix
        if [ -f "${BACKUP_DIR}/${backup_file}" ]; then
            backup_file="${BACKUP_DIR}/${backup_file}"
        else
            log_error "Backup file not found: $backup_file"
            exit 1
        fi
    fi

    # Use fortress-ctl for container mode
    if [ "$DEPLOYMENT_MODE" = "container" ] && [ -x "${SCRIPT_DIR}/fortress-ctl.sh" ]; then
        exec "${SCRIPT_DIR}/fortress-ctl.sh" restore "$backup_file"
    fi

    log_step "Restoring from: $backup_file"
    # TODO: Implement native restore
    log_warn "Native restore not yet implemented"
    log_info "Backup location: $backup_file"
}

# ============================================================
# STATUS
# ============================================================
do_status() {
    show_banner

    log_step "Installation Status"

    detect_installation

    if [ "$INSTALLED" = true ]; then
        echo ""
        echo "Installation:"
        echo "  Status:  ${GREEN}Installed${NC}"
        echo "  Mode:    ${DEPLOYMENT_MODE}"
        echo "  Version: ${INSTALLED_VERSION}"
        echo "  State:   ${STATE_FILE}"
        echo ""
    else
        echo ""
        echo -e "Installation: ${YELLOW}Not installed${NC}"
        echo ""
        echo "To install: $0 install"
        exit 0
    fi

    # Services status
    echo "Services:"
    if [ "$DEPLOYMENT_MODE" = "container" ]; then
        if command -v podman &>/dev/null; then
            podman ps --filter "name=fortress" --format "  {{.Names}}: {{.Status}}" 2>/dev/null || echo "  No containers running"
        fi
    else
        for svc in hookprobe-fortress fts-qsecbit fts-web fts-dnsmasq fts-hostapd; do
            if systemctl is-active "$svc" &>/dev/null; then
                echo -e "  ${svc}: ${GREEN}active${NC}"
            elif systemctl is-enabled "$svc" &>/dev/null; then
                echo -e "  ${svc}: ${YELLOW}inactive${NC}"
            fi
        done
    fi
    echo ""

    # Health check
    echo "Health:"
    if curl -sf -k "https://localhost:8443/health" &>/dev/null; then
        echo -e "  Web UI: ${GREEN}healthy${NC} (https://localhost:8443)"
    else
        echo -e "  Web UI: ${RED}unhealthy${NC}"
    fi
    echo ""

    # Backups
    echo "Backups:"
    if [ -d "$BACKUP_DIR" ]; then
        local count=$(ls -1 "${BACKUP_DIR}/"*.tar.gz 2>/dev/null | wc -l)
        echo "  Location: $BACKUP_DIR"
        echo "  Count: $count backup(s)"
        ls -lh "${BACKUP_DIR}/"*.tar.gz 2>/dev/null | tail -3 | while read line; do
            echo "  $line"
        done
    else
        echo "  No backups found"
    fi
}

# ============================================================
# HELP
# ============================================================
show_help() {
    cat << EOF
HookProbe Fortress - Unified Installer v${VERSION}

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    install              Install Fortress (container mode)
    upgrade              Show upgrade guidance (backup + reinstall)
    uninstall            Remove Fortress installation
    backup               Create backup
    restore [FILE]       Restore from backup
    status               Show installation status

INSTALL OPTIONS:
    --container          Container-based installation (default)
    --quick              Quick install with defaults

UNINSTALL OPTIONS:
    --keep-data          Preserve database and user data
    --keep-config        Preserve configuration files
    --purge              Remove everything including backups
    --force              Skip confirmation prompts

BACKUP OPTIONS:
    --full               Full backup (default)
    --db                 Database only
    --config             Configuration only

UPGRADING:
    To upgrade an existing installation:
      1. fortress-ctl backup --full
      2. fortress-ctl uninstall --keep-data
      3. ./install.sh

    This ensures a clean installation without network issues.

EXAMPLES:
    $0                           # Interactive install
    $0 install --container       # Container mode install
    $0 upgrade                   # Show upgrade steps
    $0 uninstall --keep-data     # Uninstall but keep data
    $0 backup --full             # Create full backup
    $0 status                    # Show installation status

DEPLOYMENT MODE:

    Container Mode (Default):
      - Self-contained Podman deployment
      - PostgreSQL + Redis + Flask web UI
      - OVS bridge with VLAN segmentation
      - WiFi AP with dual-band support (hostapd)
      - DHCP server (dnsmasq)
      - NAT for internet access
      - ML/AI services (QSecBit, dnsXai, DFS)
      - Requirements: 2GB+ RAM, Podman

For more information, see:
    https://github.com/hookprobe/hookprobe

EOF
}

# ============================================================
# FULL SYSTEM PURGE (Option 9)
# ============================================================
do_full_purge() {
    echo ""
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║            ⚠️  FULL SYSTEM PURGE + REBOOT  ⚠️                  ║${NC}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}This will COMPLETELY remove HookProbe and reboot the system:${NC}"
    echo ""
    echo "  • All containers, images, pods, volumes, networks"
    echo "  • All systemd services and timers"
    echo "  • All OVS bridges, VLANs, network interfaces"
    echo "  • All udev rules (WiFi, LTE)"
    echo "  • All configuration files and secrets"
    echo "  • All data directories and logs"
    echo "  • All sysctl and iptables rules"
    echo "  • All management scripts"
    echo ""
    echo -e "${RED}${BOLD}THE SYSTEM WILL AUTOMATICALLY REBOOT AFTER PURGE${NC}"
    echo ""
    echo -e "${CYAN}This returns the system to a clean state for fresh install.${NC}"
    echo ""

    # Allow multiple attempts for confirmation
    local attempts=0
    local max_attempts=3
    while [ $attempts -lt $max_attempts ]; do
        read -p "Type 'PURGE' to confirm complete removal and reboot (or 'cancel' to abort): " confirm

        if [ "$confirm" = "PURGE" ]; then
            break
        elif [ "$confirm" = "cancel" ] || [ "$confirm" = "CANCEL" ]; then
            log_info "Purge cancelled"
            return 1
        else
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                echo -e "${YELLOW}Invalid input. Please type 'PURGE' exactly (${max_attempts}-${attempts} attempts remaining)${NC}"
            else
                log_info "Maximum attempts reached. Purge cancelled."
                return 1
            fi
        fi
    done

    echo ""
    log_step "Starting full system purge..."

    # Run uninstall with purge flag
    if [ -x "${SCRIPT_DIR}/uninstall.sh" ]; then
        "${SCRIPT_DIR}/uninstall.sh" --purge --force || true
    fi

    # Extra cleanup for any remaining bits
    log_info "Final cleanup..."

    # Remove any remaining podman artifacts
    if command -v podman &>/dev/null; then
        podman system prune -af --volumes 2>/dev/null || true
    fi

    # Remove routing tables
    if [ -f /etc/iproute2/rt_tables ]; then
        sed -i '/wan_primary/d' /etc/iproute2/rt_tables 2>/dev/null || true
        sed -i '/wan_backup/d' /etc/iproute2/rt_tables 2>/dev/null || true
        sed -i '/primary_wan/d' /etc/iproute2/rt_tables 2>/dev/null || true
        sed -i '/backup_wan/d' /etc/iproute2/rt_tables 2>/dev/null || true
    fi

    # Flush nftables
    nft flush ruleset 2>/dev/null || true

    # Remove LTE/Modem configuration
    log_info "Removing LTE/Modem configuration..."
    if command -v nmcli &>/dev/null; then
        # Remove all HookProbe/Fortress related NetworkManager connections
        for conn in $(nmcli -t -f NAME con show 2>/dev/null | grep -iE "fts|hookprobe|fortress|lte|wwan|gsm" || true); do
            log_info "  Removing nmcli connection: $conn"
            nmcli con delete "$conn" 2>/dev/null || true
        done
    fi
    # Remove ModemManager config
    rm -f /etc/ModemManager/fcc-unlock.d/* 2>/dev/null || true
    # Stop and reset WWAN interfaces
    for iface in $(ip link show 2>/dev/null | grep -oE "wwan[0-9]+" || true); do
        log_info "  Resetting WWAN interface: $iface"
        ip link set "$iface" down 2>/dev/null || true
    done

    # Remove udev rules
    rm -f /etc/udev/rules.d/*fts*.rules 2>/dev/null || true
    rm -f /etc/udev/rules.d/*fortress*.rules 2>/dev/null || true
    rm -f /etc/udev/rules.d/*modem*.rules 2>/dev/null || true
    udevadm control --reload-rules 2>/dev/null || true

    # Remove sysctl configs
    rm -f /etc/sysctl.d/*fortress*.conf 2>/dev/null || true
    rm -f /etc/sysctl.d/*fts*.conf 2>/dev/null || true
    sysctl --system &>/dev/null || true

    # Remove all systemd services and timers (extra cleanup)
    log_info "Removing systemd services and timers..."
    for svc in fortress fortress-vlan hookprobe-fortress fts-qsecbit fts-lte fts-lte-failover \
               fts-lte-collector fts-wan-failover fts-tunnel fts-dnsmasq fts-wifi-allocator \
               fts-wifi-signal fts-hostapd fts-hostapd-24ghz fts-hostapd-5ghz fts-adaptive-txpower \
               fts-nat fts-web fts-channel-optimize fts-channel-calibrate fts-channel-quickstart \
               fts-channel-standard fts-dfs-monitor fts-dfs-api fts-ml-aggregator fts-lstm-train \
               fts-device-status fts-nac-sync; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.timer" 2>/dev/null || true
    done
    # Remove any remaining fts-* service/timer files
    rm -f /etc/systemd/system/fts-*.service 2>/dev/null || true
    rm -f /etc/systemd/system/fts-*.timer 2>/dev/null || true
    rm -f /etc/systemd/system/fortress*.service 2>/dev/null || true
    rm -f /etc/systemd/system/hookprobe-*.service 2>/dev/null || true

    # Remove all hookprobe directories
    rm -rf /opt/hookprobe 2>/dev/null || true
    rm -rf /etc/hookprobe 2>/dev/null || true
    rm -rf /etc/fortress 2>/dev/null || true
    rm -rf /var/lib/hookprobe 2>/dev/null || true
    rm -rf /var/lib/fortress 2>/dev/null || true
    rm -rf /var/log/hookprobe 2>/dev/null || true
    rm -rf /var/backups/fortress 2>/dev/null || true

    # Configure network wait services to be lenient after purge (prevents boot failures)
    log_info "Configuring network-wait services for safe reboot..."
    if systemctl is-enabled systemd-networkd-wait-online.service &>/dev/null; then
        mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d
        cat > /etc/systemd/system/systemd-networkd-wait-online.service.d/99-fortress-cleanup.conf << 'EOF'
# Fortress cleanup - prevent boot failure after purge
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-networkd-wait-online --any --timeout=30
SuccessExitStatus=0 1 2
EOF
    fi
    if systemctl is-enabled NetworkManager-wait-online.service &>/dev/null; then
        mkdir -p /etc/systemd/system/NetworkManager-wait-online.service.d
        cat > /etc/systemd/system/NetworkManager-wait-online.service.d/99-fortress-cleanup.conf << 'EOF'
# Fortress cleanup - prevent boot failure after purge
[Service]
SuccessExitStatus=0 1 2
TimeoutStartSec=30
EOF
    fi

    # Reload systemd
    systemctl daemon-reload 2>/dev/null || true

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Full System Purge Complete!                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}System will reboot in 5 seconds...${NC}"
    echo ""

    sleep 5
    reboot
}

# ============================================================
# INTERACTIVE MENU
# ============================================================
show_interactive_menu() {
    detect_installation

    while true; do
        echo ""
        echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}${BOLD}║              HookProbe Unified Installer v${VERSION}              ║${NC}"
        echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        if [ "$INSTALLED" = true ]; then
            echo -e "  ${GREEN}●${NC} Currently installed: ${BOLD}${DEPLOYMENT_MODE}${NC} mode, v${INSTALLED_VERSION}"
        else
            echo -e "  ${DIM}○ No installation detected${NC}"
        fi
        echo ""

        echo -e "${BOLD}  INSTALL${NC}"
        echo "    1) Sentinel   - IoT Validator (256MB RAM)"
        echo "    2) Guardian   - Travel Companion (1.5GB RAM)"
        echo "    3) Fortress   - Small Business Gateway (4GB RAM)"
        echo "    4) Nexus      - ML/AI Compute Node (16GB+ RAM)"
        echo "    5) MSSP       - Cloud Platform (16GB+ RAM)"
        echo ""
        echo -e "${BOLD}  MANAGE${NC}"
        echo "    6) Upgrade    - Upgrade existing installation"
        echo "    7) Status     - Show installation status"
        echo "    8) Backup     - Create backup"
        echo ""
        echo -e "${BOLD}  UNINSTALL${NC}"
        echo "   10) Uninstall (keep data)     - Remove but preserve database volumes"
        echo "   11) Uninstall (remove data)   - Remove everything except config"
        echo "   12) Uninstall (purge)         - Remove absolutely everything"
        echo ""
        echo -e "${RED}${BOLD}   99) FULL SYSTEM PURGE + REBOOT${NC}"
        echo -e "${DIM}       Complete removal and reboot for clean slate${NC}"
        echo ""
        echo "    0) Exit"
        echo ""

        read -p "Select option [0-99]: " choice

        case "$choice" in
            1)
                log_info "Sentinel installation not yet available in this installer"
                log_info "Use: cd ../sentinel && ./install.sh"
                ;;
            2)
                log_info "Guardian installation not yet available in this installer"
                log_info "Use: cd ../guardian && ./scripts/setup.sh"
                ;;
            3)
                do_install "container"
                ;;
            4)
                log_info "Nexus installation not yet available in this installer"
                log_info "Use: cd ../nexus && ./install.sh"
                ;;
            5)
                log_info "MSSP installation not yet available in this installer"
                log_info "Use: cd ../mssp && ./setup.sh"
                ;;
            6)
                if [ "$INSTALLED" = true ]; then
                    show_upgrade_guidance
                else
                    log_warn "No installation to upgrade"
                fi
                ;;
            7)
                do_status
                ;;
            8)
                if [ "$INSTALLED" = true ]; then
                    do_backup --full
                else
                    log_warn "No installation to backup"
                fi
                ;;
            10)
                if [ "$INSTALLED" = true ]; then
                    echo ""
                    echo -e "${YELLOW}Uninstall (keep data):${NC}"
                    echo "  Removes: containers, images, networks, services, scripts"
                    echo "  Keeps:   Podman volumes (database, redis, grafana data)"
                    echo ""
                    read -p "Continue? [y/N]: " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        exec "${SCRIPT_DIR}/uninstall.sh" --keep-data --force
                    fi
                else
                    log_warn "No installation to remove"
                fi
                ;;
            11)
                if [ "$INSTALLED" = true ]; then
                    echo ""
                    echo -e "${YELLOW}Uninstall (remove data):${NC}"
                    echo "  Removes: containers, images, networks, volumes, services, scripts"
                    echo "  Keeps:   Configuration files (for quick reinstall)"
                    echo ""
                    read -p "Continue? [y/N]: " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        exec "${SCRIPT_DIR}/uninstall.sh" --keep-config --force
                    fi
                else
                    log_warn "No installation to remove"
                fi
                ;;
            12)
                if [ "$INSTALLED" = true ]; then
                    echo ""
                    echo -e "${RED}Uninstall (purge):${NC}"
                    echo "  Removes: EVERYTHING - containers, images, volumes, networks,"
                    echo "           configs, data, logs, services, scripts"
                    echo ""
                    read -p "Continue? [y/N]: " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        exec "${SCRIPT_DIR}/uninstall.sh" --purge
                    fi
                else
                    log_warn "No installation to remove"
                fi
                ;;
            99)
                do_full_purge
                ;;
            0|q|Q|exit)
                echo ""
                log_info "Goodbye!"
                exit 0
                ;;
            *)
                log_warn "Invalid option: $choice"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ============================================================
# MAIN
# ============================================================
main() {
    local command=""
    local install_args=""
    local mode="container"
    local interactive=false

    # If no arguments, show interactive menu
    if [ $# -eq 0 ]; then
        check_root
        show_banner
        check_system
        show_interactive_menu
        exit 0
    fi

    # Parse arguments - separate command from flags
    while [ $# -gt 0 ]; do
        case "$1" in
            # Commands
            install|upgrade|uninstall|remove|backup|restore|status|menu)
                command="$1"
                shift
                break  # Remaining args go to the command handler
                ;;
            # Help
            --help|-h|help)
                show_help
                exit 0
                ;;
            # Installation mode flags
            --native)
                mode="native"
                ;;
            --container)
                mode="container"
                ;;
            --quick)
                install_args="$install_args --quick"
                ;;
            # Pass-through flags to install-container.sh
            --non-interactive|--preserve-data|--enable-monitoring|--enable-n8n|--enable-clickhouse|--enable-remote-access|--enable-lte|--keep-data|--keep-config|--purge)
                install_args="$install_args $1"
                ;;
            # Flags with values (for LTE config)
            --lte-apn|--lte-auth|--lte-user|--lte-pass)
                install_args="$install_args $1 $2"
                shift
                ;;
            *)
                # Unknown arg - pass through
                install_args="$install_args $1"
                ;;
        esac
        shift
    done

    # Check root for most commands
    case "$command" in
        status)
            ;;
        *)
            check_root
            ;;
    esac

    # Handle status without banner
    if [ "$command" = "status" ]; then
        do_status
        exit 0
    fi

    # Handle menu command
    if [ "$command" = "menu" ]; then
        show_banner
        check_system
        show_interactive_menu
        exit 0
    fi

    show_banner
    check_system

    # Default to install if no command specified
    if [ -z "$command" ]; then
        command="install"
    fi

    case "$command" in
        install)
            do_install "$mode" $install_args "$@"
            ;;
        upgrade)
            show_upgrade_guidance
            ;;
        uninstall|remove)
            do_uninstall $install_args "$@"
            ;;
        backup)
            do_backup "$@"
            ;;
        restore)
            do_restore "$@"
            ;;
        *)
            log_error "Unknown command: $command"
            echo "Run '$0 --help' for usage"
            exit 1
            ;;
    esac
}

main "$@"
