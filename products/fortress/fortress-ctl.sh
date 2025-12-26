#!/bin/bash
#
# HookProbe Fortress Control Script (fortress-ctl)
# Version: 5.5.0
# License: AGPL-3.0
#
# Installation, backup, and uninstall management.
# For upgrades, use: uninstall --keep-data && ./install.sh
#
# Usage:
#   fortress-ctl install [--container] [--quick]
#   fortress-ctl uninstall [--keep-data|--keep-config|--purge]
#   fortress-ctl backup [--full|--db|--config]
#   fortress-ctl restore <backup-file>
#   fortress-ctl status
#   fortress-ctl stop|start|restart
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
CONTAINERS_DIR="${SCRIPT_DIR}/containers"

# State files
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
log_substep() { echo -e "  ${BLUE}→${NC} $1"; }

# ============================================================
# STATE MANAGEMENT
# ============================================================
get_state() {
    local key="$1"
    if [ -f "$STATE_FILE" ]; then
        STATE_FILE="$STATE_FILE" STATE_KEY="$key" python3 -c '
import json
import os
state_file = os.environ["STATE_FILE"]
key = os.environ["STATE_KEY"]
d = json.load(open(state_file))
print(d.get(key, ""))
' 2>/dev/null || echo ""
    fi
}

set_state() {
    local key="$1"
    local value="$2"
    mkdir -p "$(dirname "$STATE_FILE")"

    if [ -f "$STATE_FILE" ]; then
        # Use environment variables to avoid shell escaping issues
        STATE_FILE="$STATE_FILE" STATE_KEY="$key" STATE_VALUE="$value" python3 -c '
import json
import os
state_file = os.environ["STATE_FILE"]
key = os.environ["STATE_KEY"]
value = os.environ["STATE_VALUE"]
with open(state_file, "r") as f:
    d = json.load(f)
d[key] = value
with open(state_file, "w") as f:
    json.dump(d, f, indent=2)
'
    else
        # Escape special characters for JSON
        local escaped_value
        escaped_value=$(printf '%s' "$value" | sed 's/\\/\\\\/g; s/"/\\"/g')
        echo "{\"$key\": \"$escaped_value\"}" > "$STATE_FILE"
    fi
}

get_installed_version() {
    if [ -f "$VERSION_FILE" ]; then
        cat "$VERSION_FILE"
    else
        echo "unknown"
    fi
}

get_deployment_mode() {
    get_state "deployment_mode" || echo "unknown"
}


# ============================================================
# BACKUP FUNCTIONS
# ============================================================
create_backup() {
    local backup_type="${1:-full}"  # full, db, config, app
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_name="fortress_${backup_type}_${timestamp}"
    local backup_path="${BACKUP_DIR}/${backup_name}"

    log_step "Creating ${backup_type} backup"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$backup_path"

    case "$backup_type" in
        full|db)
            # Database backup
            log_substep "Backing up PostgreSQL database..."
            if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fts-postgres"; then
                podman exec fts-postgres pg_dump -U fortress fortress > "${backup_path}/database.sql" 2>/dev/null || {
                    log_warn "Database backup failed (container may not be running)"
                }
            elif [ -f /var/lib/postgresql/data/PG_VERSION ]; then
                sudo -u postgres pg_dump fortress > "${backup_path}/database.sql" 2>/dev/null || true
            fi
            ;;&

        full|config)
            # Configuration backup
            log_substep "Backing up configuration..."
            if [ -d "$CONFIG_DIR" ]; then
                cp -r "$CONFIG_DIR" "${backup_path}/config"
            fi

            # Systemd services
            mkdir -p "${backup_path}/systemd"
            cp /etc/systemd/system/fortress*.service "${backup_path}/systemd/" 2>/dev/null || true
            cp /etc/systemd/system/fortress*.timer "${backup_path}/systemd/" 2>/dev/null || true

            # Network configuration
            mkdir -p "${backup_path}/network"
            nft list ruleset > "${backup_path}/network/nftables.conf" 2>/dev/null || true
            ovs-vsctl show > "${backup_path}/network/ovs.conf" 2>/dev/null || true
            ;;&

        full|app)
            # Application backup (web app code)
            log_substep "Backing up application..."
            if [ -d "$INSTALL_DIR/web" ]; then
                tar -czf "${backup_path}/web-app.tar.gz" -C "$INSTALL_DIR" web lib 2>/dev/null || true
            fi

            # Container image tag
            if podman images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -q "fts-web"; then
                podman images --format "{{.Repository}}:{{.Tag}}:{{.ID}}" | grep fortress > "${backup_path}/images.txt" 2>/dev/null || true
            fi
            ;;
    esac

    # Create manifest
    cat > "${backup_path}/manifest.json" << EOF
{
    "type": "${backup_type}",
    "timestamp": "${timestamp}",
    "version": "$(get_installed_version)",
    "deployment_mode": "$(get_deployment_mode)",
    "created_by": "fts-ctl ${VERSION}"
}
EOF

    # Create archive
    tar -czf "${BACKUP_DIR}/${backup_name}.tar.gz" -C "$BACKUP_DIR" "$backup_name"
    rm -rf "$backup_path"

    log_info "Backup created: ${BACKUP_DIR}/${backup_name}.tar.gz"
    echo "${BACKUP_DIR}/${backup_name}.tar.gz"
}

restore_backup() {
    local backup_file="$1"

    if [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi

    log_step "Restoring from backup: $backup_file"

    local temp_dir=$(mktemp -d)
    tar -xzf "$backup_file" -C "$temp_dir"
    local backup_dir=$(ls "$temp_dir")
    local restore_path="${temp_dir}/${backup_dir}"

    # Read manifest
    local backup_type=$(python3 -c "import json; print(json.load(open('${restore_path}/manifest.json'))['type'])")
    log_info "Backup type: $backup_type"

    # Restore database
    if [ -f "${restore_path}/database.sql" ]; then
        log_substep "Restoring database..."
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fts-postgres"; then
            podman exec -i fts-postgres psql -U fortress fortress < "${restore_path}/database.sql"
        fi
    fi

    # Restore configuration
    if [ -d "${restore_path}/config" ]; then
        log_substep "Restoring configuration..."
        cp -r "${restore_path}/config/"* "$CONFIG_DIR/" 2>/dev/null || true
    fi

    # Restore application
    if [ -f "${restore_path}/web-app.tar.gz" ]; then
        log_substep "Restoring application..."
        tar -xzf "${restore_path}/web-app.tar.gz" -C "$INSTALL_DIR"
    fi

    rm -rf "$temp_dir"
    log_info "Restore complete"
}

list_backups() {
    log_step "Available backups"
    if [ -d "$BACKUP_DIR" ]; then
        ls -la "$BACKUP_DIR"/*.tar.gz 2>/dev/null || log_info "No backups found"
    else
        log_info "No backup directory found"
    fi
}

# ============================================================
# STOP ALL SERVICES (comprehensive - for UNINSTALL only)
# ============================================================
stop_all_services() {
    log_step "Stopping all Fortress services (full teardown)"

    # 1. Stop systemd services first (graceful)
    log_substep "Stopping systemd services..."
    systemctl stop fortress 2>/dev/null || true
    systemctl stop fortress-hostapd-2ghz fortress-hostapd-5ghz 2>/dev/null || true
    systemctl stop fortress-dnsmasq 2>/dev/null || true
    systemctl stop fts-web fts-agent fts-qsecbit 2>/dev/null || true
    systemctl stop fts-suricata fts-zeek fts-xdp 2>/dev/null || true

    # 2. Stop podman-compose (graceful)
    log_substep "Stopping podman containers..."
    if [ -f "$CONTAINERS_DIR/podman-compose.yml" ]; then
        cd "$CONTAINERS_DIR" 2>/dev/null && {
            podman-compose down --timeout 30 2>/dev/null || true
        }
    fi

    # 3. Force-stop any remaining fts-* containers
    log_substep "Force-stopping remaining containers..."
    for container in $(podman ps --format "{{.Names}}" 2>/dev/null | grep -E "^fts-" || true); do
        podman stop -t 5 "$container" 2>/dev/null || true
    done

    # 4. Kill unresponsive containers
    for container in $(podman ps --format "{{.Names}}" 2>/dev/null | grep -E "^fts-" || true); do
        podman kill "$container" 2>/dev/null || true
    done

    # 5. Stop hostapd & dnsmasq processes
    log_substep "Stopping WiFi/DHCP processes..."
    pkill -f "hostapd.*fortress\|hostapd.*fts" 2>/dev/null || true
    pkill -f "dnsmasq.*fortress\|dnsmasq.*fts" 2>/dev/null || true

    # 6. Clear OVS (ONLY for uninstall - NOT for upgrade)
    log_substep "Clearing OVS..."
    ovs-ofctl del-flows FTS 2>/dev/null || true
    ovs-vsctl del-br FTS 2>/dev/null || true

    # 7. Bring down bridge interface
    ip link set fortress down 2>/dev/null || true
    ip link delete fortress 2>/dev/null || true

    # 8. Clear firewall rules
    log_substep "Clearing firewall rules..."
    iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -j MASQUERADE 2>/dev/null || true
    nft delete table inet fortress_filter 2>/dev/null || true

    # 9. Release locked ports
    fuser -k 8443/tcp 5353/udp 8050/tcp 2>/dev/null || true

    log_info "All services stopped"
}



# ============================================================
# START ALL SERVICES
# ============================================================
start_all_services() {
    log_step "Starting all Fortress services"

    # Start containers via podman-compose
    log_substep "Starting containers..."
    if [ -f "$CONTAINERS_DIR/podman-compose.yml" ]; then
        cd "$CONTAINERS_DIR" 2>/dev/null && {
            # Load environment from .env file
            if [ -f ".env" ]; then
                set -a
                source .env
                set +a
            fi

            # Clean up any existing containers first to prevent name conflicts
            log_substep "Cleaning up stale containers..."
            podman-compose down --timeout 10 2>/dev/null || true

            # Force-remove any remaining fts-* containers
            for container in $(podman ps -a --format "{{.Names}}" 2>/dev/null | grep -E "^fts-" || true); do
                podman rm -f "$container" 2>/dev/null || true
            done

            # Remove stale networks
            for network in $(podman network ls --format "{{.Name}}" 2>/dev/null | grep -E "^fts-" || true); do
                podman network rm -f "$network" 2>/dev/null || true
            done

            # Now start fresh
            podman-compose up -d --no-build
        }
    fi

    # Wait for essential containers
    log_substep "Waiting for containers to be ready..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fts-postgres"; then
            break
        fi
        sleep 2
        ((retries--))
    done

    # Start systemd services
    log_substep "Starting systemd services..."
    systemctl start fortress 2>/dev/null || true
    systemctl start fortress-hostapd-2ghz fortress-hostapd-5ghz 2>/dev/null || true
    systemctl start fortress-dnsmasq 2>/dev/null || true

    # Verify web is accessible
    retries=30
    while [ $retries -gt 0 ]; do
        if curl -sf -k "https://localhost:8443/health" &>/dev/null; then
            log_info "All services started successfully"
            return 0
        fi
        sleep 2
        ((retries--))
    done

    log_warn "Services started but web health check failed"
}


# ============================================================
# UNINSTALL FUNCTIONS
# ============================================================
uninstall_staged() {
    local keep_data="${1:-false}"
    local keep_config="${2:-false}"
    local purge="${3:-false}"

    log_step "Staged Uninstall"
    echo ""
    echo "Uninstall options:"
    echo "  --keep-data   : Preserve database and user data"
    echo "  --keep-config : Preserve configuration files"
    echo "  --purge       : Remove everything including backups"
    echo ""

    if [ "$purge" = "true" ]; then
        keep_data="false"
        keep_config="false"
    fi

    # Stage 1: Stop services (always)
    log_substep "Stage 1: Stopping services..."
    local mode=$(get_deployment_mode)

    if [ "$mode" = "container" ]; then
        cd "$CONTAINERS_DIR" 2>/dev/null
        podman-compose down 2>/dev/null || true
    fi

    systemctl stop fts-web fts-agent fortress 2>/dev/null || true

    # Stage 2: Remove application (Tier 3)
    log_substep "Stage 2: Removing application..."

    if [ "$mode" = "container" ]; then
        # Remove containers but not volumes
        podman rm -f fts-web fts-agent 2>/dev/null || true
        podman rmi localhost/fts-web:latest localhost/fts-agent:latest 2>/dev/null || true
    fi

    rm -rf "$INSTALL_DIR/web" "$INSTALL_DIR/lib" 2>/dev/null || true

    # Stage 3: Remove infrastructure (Tier 2)
    log_substep "Stage 3: Removing infrastructure..."

    # Remove systemd services
    systemctl disable fortress fts-web fts-agent 2>/dev/null || true
    rm -f /etc/systemd/system/fortress*.service /etc/systemd/system/fortress*.timer 2>/dev/null || true
    systemctl daemon-reload

    # Remove nftables rules
    nft delete table inet fortress_filter 2>/dev/null || true

    # Remove redis container/data if not keeping data
    if [ "$keep_data" = "false" ]; then
        podman rm -f fts-redis 2>/dev/null || true
        podman volume rm fts-redis-data 2>/dev/null || true
    fi

    # Stage 4: Handle data (Tier 1)
    if [ "$keep_data" = "false" ]; then
        log_substep "Stage 4: Removing data (database, logs)..."

        # Backup before removal (safety)
        if [ "$purge" != "true" ]; then
            log_info "Creating safety backup before data removal..."
            create_backup "db" >/dev/null 2>&1 || true
        fi

        podman rm -f fts-postgres 2>/dev/null || true
        podman volume rm fts-postgres-data fts-web-data fts-web-logs fortress-config 2>/dev/null || true

        rm -rf "$DATA_DIR" "$LOG_DIR/fortress"* 2>/dev/null || true
    else
        log_info "Preserving data volumes and database"
    fi

    # Stage 5: Handle configuration
    if [ "$keep_config" = "false" ]; then
        log_substep "Stage 5: Removing configuration..."
        rm -rf "$CONFIG_DIR/fortress.conf" "$CONFIG_DIR/users.json" 2>/dev/null || true
        rm -rf "${CONTAINERS_DIR}/secrets" 2>/dev/null || true
    else
        log_info "Preserving configuration in $CONFIG_DIR"
    fi

    # Stage 6: Purge (if requested)
    if [ "$purge" = "true" ]; then
        log_substep "Stage 6: Purging all data including backups..."
        rm -rf "$BACKUP_DIR" 2>/dev/null || true
        rm -rf "$CONFIG_DIR" 2>/dev/null || true
        rm -rf "$INSTALL_DIR" 2>/dev/null || true
        rm -f "$STATE_FILE" 2>/dev/null || true
    fi

    # Clean empty directories
    rmdir "$INSTALL_DIR" 2>/dev/null || true
    rmdir /opt/hookprobe 2>/dev/null || true

    log_info "Uninstall complete"

    if [ "$keep_data" = "true" ]; then
        echo ""
        log_info "Data preserved. To reinstall with existing data:"
        log_info "  fortress-ctl install --container --preserve-data"
    fi

    if [ "$keep_config" = "true" ]; then
        log_info "Configuration preserved in: $CONFIG_DIR"
    fi
}

# ============================================================
# STATUS
# ============================================================
show_status() {
    log_step "Fortress Status"

    echo ""
    echo "Installation:"
    echo "  Version:     $(get_installed_version)"
    echo "  Mode:        $(get_deployment_mode)"
    echo "  State file:  $STATE_FILE"
    echo ""

    echo "Services:"
    if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fortress"; then
        podman ps --filter "name=fortress" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    else
        systemctl is-active fortress fts-web fts-agent 2>/dev/null || echo "  No services running"
    fi
    echo ""

    echo "Volumes:"
    podman volume ls --filter "name=fortress" 2>/dev/null || echo "  No volumes found"
    echo ""

    echo "Backups:"
    if [ -d "$BACKUP_DIR" ]; then
        ls -lh "$BACKUP_DIR"/*.tar.gz 2>/dev/null | tail -5 || echo "  No backups found"
    else
        echo "  No backup directory"
    fi
    echo ""

    echo "Health:"
    if curl -sf -k "https://localhost:8443/health" &>/dev/null; then
        echo -e "  Web UI: ${GREEN}healthy${NC}"
    else
        echo -e "  Web UI: ${RED}unhealthy${NC}"
    fi
}

# ============================================================
# HELP
# ============================================================
show_help() {
    cat << EOF
HookProbe Fortress Control (v${VERSION})

Usage: fortress-ctl <command> [options]

Commands:
  install       Install Fortress
    --container   Container-based deployment (default)
    --quick       Use defaults, minimal prompts
    --preserve-data  Reuse existing data volumes

  uninstall     Remove Fortress installation
    --keep-data   Preserve database and user data
    --keep-config Preserve configuration files
    --purge       Remove everything including backups

  backup        Create backup
    --full        Full backup (all data)
    --db          Database only
    --config      Configuration only

  restore       Restore from backup
    <file>        Path to backup file

  stop          Stop all Fortress services (containers, hostapd, dnsmasq)
  start         Start all Fortress services
  restart       Restart all services (stop + start)

  status        Show installation status

  list-backups  List available backups

Upgrading:
  To upgrade Fortress, use uninstall with --keep-data then reinstall:
    fortress-ctl backup --full
    fortress-ctl uninstall --keep-data
    ./install.sh

Examples:
  fortress-ctl install --container
  fortress-ctl backup --full
  fortress-ctl uninstall --keep-data
  fortress-ctl restore /var/backups/fortress/fortress_full_20250101.tar.gz

EOF
}

# ============================================================
# MAIN
# ============================================================
main() {
    local command="${1:-help}"
    shift || true

    # Check root for most commands
    case "$command" in
        status|list-backups|help|--help|-h)
            ;;
        *)
            if [ "$EUID" -ne 0 ]; then
                log_error "This command requires root privileges"
                exit 1
            fi
            ;;
    esac

    case "$command" in
        install)
            local quick=false
            local preserve_data=false
            local args=""

            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --container) shift ;;  # Default, ignored
                    --native)
                        log_warn "Native mode is deprecated. Using container mode."
                        shift
                        ;;
                    --quick) quick=true; shift ;;
                    --preserve-data) preserve_data=true; args="$args --preserve-data"; shift ;;
                    *) shift ;;
                esac
            done

            if [ "$quick" = true ]; then
                exec "${SCRIPT_DIR}/install-container.sh" --quick $args
            else
                exec "${SCRIPT_DIR}/install-container.sh" $args
            fi
            ;;

        uninstall)
            local keep_data=false
            local keep_config=false
            local purge=false

            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --keep-data) keep_data=true; shift ;;
                    --keep-config) keep_config=true; shift ;;
                    --purge) purge=true; shift ;;
                    *) shift ;;
                esac
            done

            uninstall_staged "$keep_data" "$keep_config" "$purge"
            ;;

        backup)
            local backup_type="full"

            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --full) backup_type="full"; shift ;;
                    --db) backup_type="db"; shift ;;
                    --config) backup_type="config"; shift ;;
                    --app) backup_type="app"; shift ;;
                    *) shift ;;
                esac
            done

            create_backup "$backup_type"
            ;;

        restore)
            local backup_file="${1:-}"
            if [ -z "$backup_file" ]; then
                log_error "Backup file required"
                echo "Usage: fortress-ctl restore <backup-file>"
                exit 1
            fi
            restore_backup "$backup_file"
            ;;

        stop)
            stop_all_services
            ;;

        start)
            start_all_services
            ;;

        restart)
            stop_all_services
            sleep 2
            start_all_services
            ;;

        status)
            show_status
            ;;

        list-backups)
            list_backups
            ;;

        help|--help|-h)
            show_help
            ;;

        *)
            log_error "Unknown command: $command"
            echo "Run 'fortress-ctl help' for usage"
            exit 1
            ;;
    esac
}

main "$@"
