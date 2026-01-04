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
            # Database backup (check both fts-postgres and aiochi-postgres)
            log_substep "Backing up PostgreSQL database..."
            local pg_container=""
            if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "aiochi-postgres"; then
                pg_container="aiochi-postgres"
            elif podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fts-postgres"; then
                pg_container="fts-postgres"
            fi
            if [ -n "$pg_container" ]; then
                podman exec "$pg_container" pg_dump -U fortress fortress > "${backup_path}/database.sql" 2>/dev/null || {
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

            # Container image tag (check for fts-web or aiochi-web)
            if podman images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -qE "(fts|aiochi)-web"; then
                podman images --format "{{.Repository}}:{{.Tag}}:{{.ID}}" | grep -E "(fortress|aiochi)" > "${backup_path}/images.txt" 2>/dev/null || true
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

    # Restore database (check for both fts-postgres and aiochi-postgres)
    if [ -f "${restore_path}/database.sql" ]; then
        log_substep "Restoring database..."
        local pg_container=""
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "aiochi-postgres"; then
            pg_container="aiochi-postgres"
        elif podman ps --format "{{.Names}}" 2>/dev/null | grep -q "fts-postgres"; then
            pg_container="fts-postgres"
        fi
        if [ -n "$pg_container" ]; then
            podman exec -i "$pg_container" psql -U fortress fortress < "${restore_path}/database.sql"
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

    # 3. Force-stop any remaining fts-* or aiochi-* containers
    log_substep "Force-stopping remaining containers..."
    for container in $(podman ps --format "{{.Names}}" 2>/dev/null | grep -E "^(fts|aiochi)-" || true); do
        podman stop -t 5 "$container" 2>/dev/null || true
    done

    # 4. Kill unresponsive containers
    for container in $(podman ps --format "{{.Names}}" 2>/dev/null | grep -E "^(fts|aiochi)-" || true); do
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

    # 9. Release locked ports (53/udp is dnsXai, 5353 is mDNS - don't kill mDNS)
    fuser -k 8443/tcp 53/udp 8050/tcp 2>/dev/null || true

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

            # Force-remove any remaining fts-* or aiochi-* containers
            for container in $(podman ps -a --format "{{.Names}}" 2>/dev/null | grep -E "^(fts|aiochi)-" || true); do
                podman rm -f "$container" 2>/dev/null || true
            done

            # Remove stale networks
            for network in $(podman network ls --format "{{.Name}}" 2>/dev/null | grep -E "^(fts|aiochi)-" || true); do
                podman network rm -f "$network" 2>/dev/null || true
            done

            # Now start fresh
            podman-compose up -d --no-build
        }
    fi

    # Wait for essential containers (fts-postgres or aiochi-postgres)
    log_substep "Waiting for containers to be ready..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -qE "(fts|aiochi)-postgres"; then
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
        # Remove containers but not volumes (both fts-* and aiochi-* prefixes)
        podman rm -f fts-web fts-agent aiochi-web aiochi-agent 2>/dev/null || true
        podman rmi localhost/fts-web:latest localhost/fts-agent:latest 2>/dev/null || true
        podman rmi localhost/aiochi-web:latest localhost/aiochi-agent:latest 2>/dev/null || true
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

    # Remove redis container/data if not keeping data (both fts-* and aiochi-* prefixes)
    if [ "$keep_data" = "false" ]; then
        podman rm -f fts-redis aiochi-redis 2>/dev/null || true
        podman volume rm fts-redis-data aiochi-redis-data 2>/dev/null || true
    fi

    # Stage 4: Handle data (Tier 1)
    if [ "$keep_data" = "false" ]; then
        log_substep "Stage 4: Removing data (database, logs)..."

        # Backup before removal (safety)
        if [ "$purge" != "true" ]; then
            log_info "Creating safety backup before data removal..."
            create_backup "db" >/dev/null 2>&1 || true
        fi

        # Remove postgres containers (fts or aiochi)
        podman rm -f fts-postgres aiochi-postgres 2>/dev/null || true
        # Remove volumes (both fts-* and aiochi-* prefixes)
        podman volume rm fts-postgres-data fts-web-data fts-web-logs fortress-config 2>/dev/null || true
        podman volume rm aiochi-postgres-data aiochi-web-data aiochi-web-logs 2>/dev/null || true

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
# DEVICE MANAGEMENT
# ============================================================
AUTOPILOT_DB="/var/lib/hookprobe/autopilot.db"
FINGERBANK_CONFIG="${CONFIG_DIR}/fingerbank.json"
FINGERBANK_API_URL="https://api.fingerbank.org"

# ============================================================
# FINGERBANK MANAGEMENT
# ============================================================
fingerbank_set_key() {
    local api_key="${1:-}"

    if [ -z "$api_key" ]; then
        log_error "API key required"
        echo ""
        echo "Usage: fortress-ctl fingerbank set-api-key <your-api-key>"
        echo ""
        echo "Get your free API key (up to 600 requests/month):"
        echo "  1. Visit https://api.fingerbank.org/email_registrations/current"
        echo "  2. Register with your email"
        echo "  3. Check your email for the API key"
        echo ""
        exit 1
    fi

    mkdir -p "$CONFIG_DIR"

    # Test API key first using the interrogate endpoint (the actual API endpoint used)
    log_substep "Testing API key..."
    local test_result
    # Use the interrogate endpoint with a common DHCP fingerprint (Windows 10)
    # This is the actual endpoint used for device lookups, so it validates the key properly
    test_result=$(curl -s -o /dev/null -w "%{http_code}" -m 10 --connect-timeout 5 \
        -H "Content-Type: application/json" \
        -X POST -d '{"dhcp_fingerprint":"1,3,6,15,31,33,43,44,46,47,119,121,249,252"}' \
        "${FINGERBANK_API_URL}/api/v2/combinations/interrogate?key=${api_key}" 2>/dev/null) || test_result="000"

    if [ "$test_result" = "200" ]; then
        log_info "API key validated successfully"
    elif [ "$test_result" = "401" ]; then
        log_error "Invalid API key"
        exit 1
    elif [ "$test_result" = "403" ]; then
        log_error "API key forbidden - key may be revoked"
        exit 1
    elif [ "$test_result" = "429" ]; then
        log_warn "API rate limit exceeded - key stored but may be over quota"
    else
        log_warn "Could not verify API key (HTTP $test_result) - storing anyway"
    fi

    # Save API key
    cat > "$FINGERBANK_CONFIG" << EOF
{
    "api_key": "${api_key}",
    "enabled": true,
    "created_at": "$(date -Iseconds)",
    "requests_today": 0,
    "last_reset": "$(date +%Y-%m-%d)"
}
EOF
    chmod 600 "$FINGERBANK_CONFIG"

    log_info "Fingerbank API key configured"
    log_info "Config saved to: $FINGERBANK_CONFIG"
    echo ""
    echo "SDN Autopilot will now use Fingerbank for unknown devices."
    echo "Free tier: 600 requests/month (~20/day)"
}

fingerbank_status() {
    log_step "Fingerbank API Status"
    echo ""

    if [ ! -f "$FINGERBANK_CONFIG" ]; then
        echo -e "  Status:  ${RED}Not configured${NC}"
        echo ""
        echo "To enable Fingerbank enrichment:"
        echo "  fortress-ctl fingerbank set-api-key <your-api-key>"
        echo ""
        echo "Get a free API key at:"
        echo "  https://api.fingerbank.org/email_registrations/current"
        echo ""
        return
    fi

    # Read config
    local api_key enabled requests_today last_reset
    api_key=$(python3 -c "import json; print(json.load(open('$FINGERBANK_CONFIG')).get('api_key', '')[:8] + '...')" 2>/dev/null)
    enabled=$(python3 -c "import json; print(json.load(open('$FINGERBANK_CONFIG')).get('enabled', False))" 2>/dev/null)
    requests_today=$(python3 -c "import json; print(json.load(open('$FINGERBANK_CONFIG')).get('requests_today', 0))" 2>/dev/null)
    last_reset=$(python3 -c "import json; print(json.load(open('$FINGERBANK_CONFIG')).get('last_reset', 'unknown'))" 2>/dev/null)

    if [ "$enabled" = "True" ]; then
        echo -e "  Status:     ${GREEN}Enabled${NC}"
    else
        echo -e "  Status:     ${YELLOW}Disabled${NC}"
    fi
    echo "  API Key:    ${api_key}"
    echo "  Requests:   ${requests_today}/20 today (free tier: ~20/day)"
    echo "  Last Reset: ${last_reset}"
    echo ""

    # Test API connectivity using the actual interrogate endpoint
    log_substep "Testing API connectivity..."
    local test_api_key
    test_api_key=$(python3 -c "import json; print(json.load(open('$FINGERBANK_CONFIG')).get('api_key', ''))" 2>/dev/null)

    if [ -n "$test_api_key" ]; then
        local test_result
        # Use the interrogate endpoint with a sample DHCP fingerprint (Windows 10)
        test_result=$(curl -s -o /dev/null -w "%{http_code}" -m 10 --connect-timeout 5 \
            -H "Content-Type: application/json" \
            -X POST -d '{"dhcp_fingerprint":"1,3,6,15,31,33,43,44,46,47,119,121,249,252"}' \
            "${FINGERBANK_API_URL}/api/v2/combinations/interrogate?key=${test_api_key}" 2>/dev/null) || test_result="000"

        case "$test_result" in
            200) echo -e "  API Test:   ${GREEN}OK${NC}" ;;
            401) echo -e "  API Test:   ${RED}Invalid API key${NC}" ;;
            403) echo -e "  API Test:   ${RED}API key forbidden${NC}" ;;
            404) echo -e "  API Test:   ${YELLOW}Endpoint not found (API may have changed)${NC}" ;;
            429) echo -e "  API Test:   ${YELLOW}Rate limited${NC}" ;;
            000) echo -e "  API Test:   ${RED}Connection failed${NC}" ;;
            *)   echo -e "  API Test:   ${YELLOW}HTTP $test_result${NC}" ;;
        esac
    fi
    echo ""

    # Show learned fingerprints
    local learned_count=0
    if [ -f "/var/lib/hookprobe/fingerbank.db" ]; then
        learned_count=$(sqlite3 /var/lib/hookprobe/fingerbank.db \
            "SELECT COUNT(*) FROM learned_fingerprints WHERE source='fingerbank_api';" 2>/dev/null || echo "0")
    fi
    echo "  Learned from API: ${learned_count} fingerprints"
    echo ""
}

fingerbank_test() {
    local fingerprint="${1:-1,121,3,6,15,119,252,95,44,46}"

    log_step "Testing Fingerbank API"
    echo ""

    if [ ! -f "$FINGERBANK_CONFIG" ]; then
        log_error "Fingerbank not configured. Run: fortress-ctl fingerbank set-api-key <key>"
        exit 1
    fi

    local api_key
    api_key=$(python3 -c "import json; print(json.load(open('$FINGERBANK_CONFIG')).get('api_key', ''))" 2>/dev/null)

    if [ -z "$api_key" ]; then
        log_error "No API key found in configuration"
        exit 1
    fi

    log_substep "Querying fingerprint: $fingerprint"

    local response
    response=$(curl -sf "${FINGERBANK_API_URL}/api/v2/combinations/interrogate?key=${api_key}" \
        -H "Content-Type: application/json" \
        -d "{\"dhcp_fingerprint\": \"${fingerprint}\"}" 2>/dev/null)

    if [ -z "$response" ]; then
        log_error "API query failed"
        exit 1
    fi

    echo ""
    echo "API Response:"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    echo ""

    # Parse result
    local device_name score
    device_name=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('device',{}).get('name','Unknown'))" 2>/dev/null)
    score=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('score',0))" 2>/dev/null)

    log_info "Identified: $device_name (score: $score)"
}

fingerbank_enable() {
    if [ ! -f "$FINGERBANK_CONFIG" ]; then
        log_error "Fingerbank not configured. Run: fortress-ctl fingerbank set-api-key <key>"
        exit 1
    fi

    python3 -c "
import json
with open('$FINGERBANK_CONFIG', 'r') as f:
    config = json.load(f)
config['enabled'] = True
with open('$FINGERBANK_CONFIG', 'w') as f:
    json.dump(config, f, indent=2)
"
    log_info "Fingerbank API enabled"
}

fingerbank_disable() {
    if [ ! -f "$FINGERBANK_CONFIG" ]; then
        log_error "Fingerbank not configured"
        exit 1
    fi

    python3 -c "
import json
with open('$FINGERBANK_CONFIG', 'r') as f:
    config = json.load(f)
config['enabled'] = False
with open('$FINGERBANK_CONFIG', 'w') as f:
    json.dump(config, f, indent=2)
"
    log_info "Fingerbank API disabled"
}

device_list() {
    log_step "Connected Devices"

    if [ ! -f "$AUTOPILOT_DB" ]; then
        log_error "Device database not found: $AUTOPILOT_DB"
        exit 1
    fi

    echo ""
    printf "%-19s %-15s %-15s %-30s\n" "MAC ADDRESS" "POLICY" "STATUS" "NAME"
    printf "%-19s %-15s %-15s %-30s\n" "-------------------" "---------------" "---------------" "------------------------------"

    sqlite3 -separator '|' "$AUTOPILOT_DB" \
        "SELECT mac, policy, status, COALESCE(friendly_name, hostname, 'Unknown') FROM device_identity ORDER BY last_seen DESC;" 2>/dev/null | \
    while IFS='|' read -r mac policy status name; do
        # Colorize policy
        case "$policy" in
            quarantine) policy_color="${RED}${policy}${NC}" ;;
            internet_only) policy_color="${GREEN}${policy}${NC}" ;;
            lan_only) policy_color="${YELLOW}${policy}${NC}" ;;
            normal|smart_home) policy_color="${CYAN}${policy}${NC}" ;;
            full_access) policy_color="${BLUE}${policy}${NC}" ;;
            *) policy_color="$policy" ;;
        esac
        printf "%-19s %-15b %-15s %-30s\n" "$mac" "$policy_color" "$status" "${name:0:30}"
    done
    echo ""
}

device_show() {
    local mac="${1:-}"

    if [ -z "$mac" ]; then
        log_error "MAC address required"
        echo "Usage: fortress-ctl device show <mac-address>"
        exit 1
    fi

    mac=$(echo "$mac" | tr '[:lower:]' '[:upper:]')

    if [ ! -f "$AUTOPILOT_DB" ]; then
        log_error "Device database not found"
        exit 1
    fi

    log_step "Device Details: $mac"
    echo ""

    sqlite3 -header -column "$AUTOPILOT_DB" \
        "SELECT mac, ip, hostname, friendly_name, vendor, category, policy, status, confidence, first_seen, last_seen, manual_override FROM device_identity WHERE mac='$mac';" 2>/dev/null || {
        log_error "Device not found: $mac"
        exit 1
    }
    echo ""
}

device_set_policy() {
    local mac="${1:-}"
    local policy="${2:-}"

    if [ -z "$mac" ] || [ -z "$policy" ]; then
        log_error "MAC address and policy required"
        echo ""
        echo "Usage: fortress-ctl device set-policy <mac-address> <policy>"
        echo ""
        echo "Available policies:"
        echo "  quarantine     - Block all network access"
        echo "  internet_only  - Internet access only (no LAN)"
        echo "  lan_only       - LAN access only (no internet)"
        echo "  normal         - LAN + Internet (aka smart_home)"
        echo "  full_access    - Full access including management"
        echo ""
        exit 1
    fi

    mac=$(echo "$mac" | tr '[:lower:]' '[:upper:]')
    policy=$(echo "$policy" | tr '[:upper:]' '[:lower:]')

    # Validate policy
    case "$policy" in
        quarantine|internet_only|lan_only|normal|smart_home|full_access)
            # Normalize normal (legacy) to smart_home
            [ "$policy" = "normal" ] && policy="smart_home"
            ;;
        *)
            log_error "Invalid policy: $policy"
            echo "Valid policies: quarantine, internet_only, lan_only, smart_home, full_access"
            exit 1
            ;;
    esac

    if [ ! -f "$AUTOPILOT_DB" ]; then
        log_error "Device database not found"
        exit 1
    fi

    # Update database
    sqlite3 "$AUTOPILOT_DB" \
        "UPDATE device_identity SET policy='$policy', manual_override=1 WHERE mac='$mac';" 2>/dev/null

    # Check if device exists
    local result
    result=$(sqlite3 "$AUTOPILOT_DB" "SELECT mac FROM device_identity WHERE mac='$mac';" 2>/dev/null)

    if [ -z "$result" ]; then
        log_error "Device not found: $mac"
        exit 1
    fi

    log_info "Policy updated: $mac → $policy"

    # Trigger OpenFlow rule update if NAC sync script exists
    local nac_script="/opt/hookprobe/fortress/devices/common/nac-policy-sync.sh"
    if [ -x "$nac_script" ]; then
        log_substep "Syncing OpenFlow rules..."
        "$nac_script" 2>/dev/null || log_warn "OpenFlow sync failed (non-fatal)"
    fi

    echo ""
    log_info "Device policy changed successfully"
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
    if podman ps --format "{{.Names}}" 2>/dev/null | grep -qE "(fortress|fts-|aiochi-)"; then
        podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | grep -E "(NAME|fts-|aiochi-)"
    else
        systemctl is-active fortress fts-web fts-agent 2>/dev/null || echo "  No services running"
    fi
    echo ""

    echo "Volumes:"
    podman volume ls 2>/dev/null | grep -E "(NAME|fts-|aiochi-|fortress)" || echo "  No volumes found"
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

  device        Manage network devices
    list                        List all devices with policies
    show <mac>                  Show device details
    set-policy <mac> <policy>   Change device network policy

  fingerbank    Manage Fingerbank API for device identification
    status                      Show Fingerbank API status
    set-api-key <key>           Configure API key
    test [fingerprint]          Test API with sample fingerprint
    enable                      Enable Fingerbank enrichment
    disable                     Disable Fingerbank enrichment

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

Device Policies:
  quarantine     - Block all network access (default for unknown)
  internet_only  - Internet only, no LAN access
  lan_only       - LAN only, no internet access
  normal         - LAN + Internet (smart home devices)
  full_access    - Full access including management network

Examples:
  fortress-ctl device list
  fortress-ctl device set-policy AA:BB:CC:DD:EE:FF internet_only
  fortress-ctl device show 66:E1:5E:04:CE:05
  fortress-ctl backup --full
  fortress-ctl uninstall --keep-data

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
        device)
            # device list/show don't need root, but set-policy does
            if [ "${1:-}" = "set-policy" ] || [ "${1:-}" = "policy" ]; then
                if [ "$EUID" -ne 0 ]; then
                    log_error "This command requires root privileges"
                    exit 1
                fi
            fi
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

        device)
            local subcommand="${1:-list}"
            shift || true

            case "$subcommand" in
                list|ls)
                    device_list
                    ;;
                show|info)
                    device_show "$1"
                    ;;
                set-policy|policy)
                    device_set_policy "$1" "$2"
                    ;;
                *)
                    log_error "Unknown device subcommand: $subcommand"
                    echo "Usage: fortress-ctl device [list|show|set-policy]"
                    exit 1
                    ;;
            esac
            ;;

        fingerbank)
            local subcommand="${1:-status}"
            shift || true

            case "$subcommand" in
                status)
                    fingerbank_status
                    ;;
                set-api-key|set-key|key)
                    fingerbank_set_key "$1"
                    ;;
                test)
                    fingerbank_test "$1"
                    ;;
                enable)
                    fingerbank_enable
                    ;;
                disable)
                    fingerbank_disable
                    ;;
                *)
                    log_error "Unknown fingerbank subcommand: $subcommand"
                    echo ""
                    echo "Usage: fortress-ctl fingerbank [status|set-api-key|test|enable|disable]"
                    echo ""
                    echo "Commands:"
                    echo "  status                 Show Fingerbank API status"
                    echo "  set-api-key <key>      Configure Fingerbank API key"
                    echo "  test [fingerprint]     Test API with a DHCP fingerprint"
                    echo "  enable                 Enable Fingerbank enrichment"
                    echo "  disable                Disable Fingerbank enrichment"
                    echo ""
                    echo "Get your free API key (600 requests/month):"
                    echo "  https://api.fingerbank.org/email_registrations/current"
                    echo ""
                    exit 1
                    ;;
            esac
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
