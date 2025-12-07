#!/bin/bash
# =============================================================================
# HookProbe MSSP Health Check Script
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# =============================================================================
# CONFIGURATION
# =============================================================================

MSSP_CONFIG_DIR="/etc/hookprobe/mssp"
MSSP_DATA_DIR="/var/lib/hookprobe/mssp"
MSSP_SECRETS_DIR="/etc/hookprobe/secrets/mssp"

# Expected containers
CONTAINERS=(
    "mssp-postgres"
    "mssp-valkey"
    "mssp-victoriametrics"
    "mssp-clickhouse"
    "mssp-grafana"
    "mssp-logto"
    "mssp-django"
    "mssp-celery"
    "mssp-nginx"
    "mssp-qsecbit"
)

OPTIONAL_CONTAINERS=(
    "mssp-n8n"
    "mssp-htp"
)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

check_passed() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

check_failed() {
    echo -e "${RED}[FAIL]${NC} $1"
}

check_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

check_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# =============================================================================
# HEALTH CHECKS
# =============================================================================

check_systemd_service() {
    echo ""
    echo "Checking systemd service..."

    if systemctl is-active --quiet hookprobe-mssp 2>/dev/null; then
        check_passed "hookprobe-mssp service is active"
    else
        check_failed "hookprobe-mssp service is not active"
    fi

    if systemctl is-enabled --quiet hookprobe-mssp 2>/dev/null; then
        check_passed "hookprobe-mssp service is enabled"
    else
        check_warning "hookprobe-mssp service is not enabled"
    fi
}

check_containers() {
    echo ""
    echo "Checking containers..."

    local failed=0
    local running=0

    for container in "${CONTAINERS[@]}"; do
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            check_passed "$container is running"
            ((running++))
        else
            check_failed "$container is NOT running"
            ((failed++))
        fi
    done

    for container in "${OPTIONAL_CONTAINERS[@]}"; do
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            check_passed "$container is running (optional)"
            ((running++))
        else
            check_warning "$container is not running (optional)"
        fi
    done

    echo ""
    echo "Container Summary: $running running, $failed failed"
}

check_networks() {
    echo ""
    echo "Checking Podman networks..."

    local networks=(
        "mssp-pod-001-dmz"
        "mssp-pod-002-iam"
        "mssp-pod-003-db"
        "mssp-pod-004-cache"
        "mssp-pod-005-monitoring"
        "mssp-pod-006-security"
        "mssp-external"
    )

    for network in "${networks[@]}"; do
        if podman network exists "$network" 2>/dev/null; then
            check_passed "Network $network exists"
        else
            check_failed "Network $network does NOT exist"
        fi
    done
}

check_ovs_bridge() {
    echo ""
    echo "Checking OVS bridge..."

    if command -v ovs-vsctl &>/dev/null; then
        if ovs-vsctl br-exists mssp-bridge 2>/dev/null; then
            check_passed "OVS bridge mssp-bridge exists"

            # Check VXLAN tunnels
            local vxlan_count=$(ovs-vsctl list-ports mssp-bridge 2>/dev/null | grep -c "vxlan_" || echo 0)
            if [ "$vxlan_count" -gt 0 ]; then
                check_passed "Found $vxlan_count VXLAN tunnels"
            else
                check_warning "No VXLAN tunnels found"
            fi
        else
            check_failed "OVS bridge mssp-bridge does NOT exist"
        fi
    else
        check_warning "OVS not installed"
    fi
}

check_database_connectivity() {
    echo ""
    echo "Checking database connectivity..."

    # PostgreSQL
    if podman exec mssp-postgres pg_isready -U hookprobe &>/dev/null; then
        check_passed "PostgreSQL is accepting connections"
    else
        check_failed "PostgreSQL is NOT accepting connections"
    fi

    # ClickHouse
    local ch_password=""
    if [ -f "$MSSP_SECRETS_DIR/clickhouse/password" ]; then
        ch_password=$(cat "$MSSP_SECRETS_DIR/clickhouse/password")
    fi

    if podman exec mssp-clickhouse clickhouse-client --password="$ch_password" -q "SELECT 1" &>/dev/null; then
        check_passed "ClickHouse is accepting connections"
    else
        check_failed "ClickHouse is NOT accepting connections"
    fi

    # Valkey
    if podman exec mssp-valkey valkey-cli ping 2>/dev/null | grep -q "PONG"; then
        check_passed "Valkey is accepting connections"
    else
        check_failed "Valkey is NOT accepting connections"
    fi
}

check_web_endpoints() {
    echo ""
    echo "Checking web endpoints..."

    # Nginx health
    if curl -sk https://localhost/health 2>/dev/null | grep -q "healthy"; then
        check_passed "Nginx health endpoint responding"
    elif curl -sk http://localhost/health 2>/dev/null | grep -q "healthy"; then
        check_passed "Nginx health endpoint responding (HTTP)"
    else
        check_failed "Nginx health endpoint NOT responding"
    fi

    # Django
    if curl -s http://localhost:8000/ &>/dev/null; then
        check_passed "Django application responding"
    else
        check_warning "Django application not directly accessible (may be behind proxy)"
    fi

    # Grafana
    if curl -s http://localhost:3000/api/health 2>/dev/null | grep -q "ok"; then
        check_passed "Grafana health endpoint responding"
    else
        check_warning "Grafana health endpoint not responding"
    fi

    # VictoriaMetrics
    if curl -s http://localhost:8428/health 2>/dev/null | grep -iq "ok\|alive"; then
        check_passed "VictoriaMetrics health endpoint responding"
    else
        check_warning "VictoriaMetrics health endpoint not responding"
    fi
}

check_htp_endpoint() {
    echo ""
    echo "Checking HTP endpoint..."

    # Check if HTP port is listening
    if ss -uln | grep -q ":4478 "; then
        check_passed "HTP UDP port 4478 is listening"
    else
        check_warning "HTP UDP port 4478 is NOT listening"
    fi

    if ss -tln | grep -q ":4478 "; then
        check_passed "HTP TCP port 4478 is listening"
    else
        check_warning "HTP TCP port 4478 is NOT listening"
    fi

    # Check HTP status API
    if curl -s http://localhost:8889/health 2>/dev/null | grep -q "ok"; then
        check_passed "HTP status API responding"
    else
        check_warning "HTP status API not responding"
    fi
}

check_disk_space() {
    echo ""
    echo "Checking disk space..."

    local data_usage=$(du -sh "$MSSP_DATA_DIR" 2>/dev/null | cut -f1)
    local root_avail=$(df -h / | awk 'NR==2 {print $4}')

    check_info "MSSP data directory usage: ${data_usage:-unknown}"
    check_info "Root partition available: ${root_avail:-unknown}"

    # Check if less than 10GB available
    local avail_gb=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$avail_gb" -lt 10 ]; then
        check_warning "Low disk space: ${avail_gb}GB available"
    else
        check_passed "Disk space OK: ${avail_gb}GB available"
    fi
}

check_memory_usage() {
    echo ""
    echo "Checking memory usage..."

    local total_mem=$(free -g | awk '/^Mem:/{print $2}')
    local used_mem=$(free -g | awk '/^Mem:/{print $3}')
    local avail_mem=$(free -g | awk '/^Mem:/{print $7}')

    check_info "Total memory: ${total_mem}GB"
    check_info "Used memory: ${used_mem}GB"
    check_info "Available memory: ${avail_mem}GB"

    if [ "$avail_mem" -lt 4 ]; then
        check_warning "Low memory: ${avail_mem}GB available"
    else
        check_passed "Memory OK: ${avail_mem}GB available"
    fi
}

check_logs_for_errors() {
    echo ""
    echo "Checking recent logs for errors..."

    local error_count=0

    for container in mssp-django mssp-postgres mssp-nginx; do
        local errors=$(podman logs --tail 100 "$container" 2>&1 | grep -ci "error\|exception\|critical" || echo 0)
        if [ "$errors" -gt 0 ]; then
            check_warning "$container has $errors error(s) in recent logs"
            ((error_count += errors))
        fi
    done

    if [ "$error_count" -eq 0 ]; then
        check_passed "No recent errors found in container logs"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} HookProbe MSSP Health Check${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Timestamp: $(date)"

    check_systemd_service
    check_containers
    check_networks
    check_ovs_bridge
    check_database_connectivity
    check_web_endpoints
    check_htp_endpoint
    check_disk_space
    check_memory_usage
    check_logs_for_errors

    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} Health Check Complete${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Handle arguments
case "${1:-}" in
    --json)
        # JSON output mode (for monitoring integration)
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"status\": \"running\","
        echo "  \"containers\": $(podman ps --filter 'name=mssp-' --format json 2>/dev/null || echo '[]')"
        echo "}"
        ;;
    --quiet|-q)
        # Quiet mode - only show failures
        exec 3>&1
        exec 1>/dev/null
        main 2>&1 | grep -E "^\[FAIL\]" >&3
        ;;
    *)
        main
        ;;
esac
