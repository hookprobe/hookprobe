#!/bin/bash
# =============================================================================
# HookProbe MSSP Health Check Script
# =============================================================================
# Version: 2.0
# Last Updated: 2026-01-20
#
# Enhanced with:
# - Namespace mismatch detection (root vs rootless)
# - Security configuration validation (ALLOWED_HOSTS)
# - Cross-namespace communication checks
# - Hybrid vs rootless architecture detection
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# CONFIGURATION
# =============================================================================

MSSP_CONFIG_DIR="/etc/hookprobe/mssp"
MSSP_DATA_DIR="/var/lib/hookprobe/mssp"
MSSP_SECRETS_DIR="/etc/hookprobe/secrets/mssp"
DJANGO_ENV_FILE="$MSSP_CONFIG_DIR/django.env"

# Expected containers for ROOT namespace (hybrid mode)
ROOT_CONTAINERS=(
    "mssp-postgres"
    "mssp-valkey"
    "mssp-victoriametrics"
    "mssp-clickhouse"
    "mssp-grafana"
    "mssp-logto"
    "mssp-django"
    "mssp-celery"
    "mssp-qsecbit"
)

# Expected containers for ROOTLESS namespace (hookprobe-com proxy)
ROOTLESS_CONTAINERS=(
    "hookprobe-proxy"
    "hookprobe-website"
)

# Host networking containers (required for cross-namespace communication)
HOST_NETWORK_CONTAINERS=(
    "mssp-django"
    "mssp-logto"
)

OPTIONAL_CONTAINERS=(
    "mssp-n8n"
    "mssp-htp"
)

# Security: FORBIDDEN values in ALLOWED_HOSTS
# These open doors for Host Header Injection attacks
FORBIDDEN_HOSTS=(
    "localhost"
    "127.0.0.1"
    "host.containers.internal"
    "0.0.0.0"
    "::1"
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

check_critical() {
    echo -e "${RED}[CRITICAL]${NC} $1"
}

check_section() {
    echo ""
    echo -e "${CYAN}━━━ $1 ━━━${NC}"
}

# =============================================================================
# NAMESPACE DETECTION (CRITICAL)
# =============================================================================

detect_architecture() {
    check_section "Architecture Detection"

    local root_count=0
    local rootless_count=0
    local hybrid_mode=false

    # Count containers in root namespace
    for container in "${ROOT_CONTAINERS[@]}"; do
        if sudo podman ps --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            ((root_count++))
        fi
    done

    # Count containers in rootless namespace
    for container in "${ROOTLESS_CONTAINERS[@]}"; do
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            ((rootless_count++))
        fi
    done

    # Detect architecture mode
    if [ "$root_count" -gt 0 ] && [ "$rootless_count" -gt 0 ]; then
        hybrid_mode=true
        check_info "Architecture: HYBRID MODE (root + rootless)"
        check_info "  Root containers: $root_count"
        check_info "  Rootless containers: $rootless_count"
        echo "ARCHITECTURE=hybrid" > /tmp/mssp-health-arch.tmp
    elif [ "$root_count" -gt 0 ]; then
        check_info "Architecture: ROOT ONLY (standalone mode)"
        echo "ARCHITECTURE=root" > /tmp/mssp-health-arch.tmp
    elif [ "$rootless_count" -gt 0 ]; then
        check_info "Architecture: ROOTLESS ONLY (recommended)"
        echo "ARCHITECTURE=rootless" > /tmp/mssp-health-arch.tmp
    else
        check_critical "No MSSP containers detected in either namespace!"
        return 1
    fi

    # In hybrid mode, check for namespace mismatches
    if [ "$hybrid_mode" = true ]; then
        check_namespace_isolation
    fi
}

check_namespace_isolation() {
    check_section "Namespace Isolation Check"

    local issues=0

    # Check if MSSP containers exist in BOTH namespaces (BAD)
    for container in "${ROOT_CONTAINERS[@]}"; do
        local in_root=false
        local in_rootless=false

        if sudo podman ps -a --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            in_root=true
        fi

        if podman ps -a --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            in_rootless=true
        fi

        if [ "$in_root" = true ] && [ "$in_rootless" = true ]; then
            check_critical "DUPLICATE: $container exists in BOTH namespaces!"
            check_info "  This causes routing confusion and potential data split"
            check_info "  Fix: Remove rootless duplicate with: podman rm -f $container"
            ((issues++))
        fi
    done

    if [ "$issues" -eq 0 ]; then
        check_passed "No duplicate containers across namespaces"
    else
        check_failed "$issues namespace isolation issues found"
    fi

    return $issues
}

check_host_networking() {
    check_section "Host Networking (Cross-Namespace Communication)"

    local issues=0

    for container in "${HOST_NETWORK_CONTAINERS[@]}"; do
        # Skip if container doesn't exist
        if ! sudo podman ps --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            continue
        fi

        # Check network mode
        local network_mode=$(sudo podman inspect "$container" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null || echo "unknown")

        if [ "$network_mode" = "host" ]; then
            check_passed "$container uses host networking (required for hybrid mode)"
        else
            check_failed "$container NOT on host network (mode: $network_mode)"
            check_info "  In hybrid mode, this container cannot be reached from rootless proxy"
            check_info "  Fix: Recreate with --network=host"
            ((issues++))
        fi
    done

    return $issues
}

# =============================================================================
# SECURITY CONFIGURATION CHECKS
# =============================================================================

check_allowed_hosts_security() {
    check_section "Django ALLOWED_HOSTS Security"

    local issues=0

    if [ ! -f "$DJANGO_ENV_FILE" ]; then
        check_warning "Django env file not found: $DJANGO_ENV_FILE"
        return 0
    fi

    # Extract ALLOWED_HOSTS
    local allowed_hosts=$(grep "^DJANGO_ALLOWED_HOSTS=" "$DJANGO_ENV_FILE" 2>/dev/null | cut -d'=' -f2)

    if [ -z "$allowed_hosts" ]; then
        check_warning "DJANGO_ALLOWED_HOSTS not configured"
        return 0
    fi

    check_info "Current ALLOWED_HOSTS: $allowed_hosts"

    # Check for forbidden hosts
    for forbidden in "${FORBIDDEN_HOSTS[@]}"; do
        if echo "$allowed_hosts" | grep -qi "\b${forbidden}\b"; then
            check_critical "SECURITY: '$forbidden' found in ALLOWED_HOSTS!"
            check_info "  This allows Host Header Injection attacks"
            check_info "  Risk: Cache poisoning, password reset hijacking, SSRF"
            check_info "  Fix: Remove '$forbidden' from DJANGO_ALLOWED_HOSTS"
            ((issues++))
        fi
    done

    if [ "$issues" -eq 0 ]; then
        check_passed "ALLOWED_HOSTS configuration is secure"
    else
        check_failed "$issues security issues in ALLOWED_HOSTS"
    fi

    return $issues
}

check_nginx_host_header() {
    check_section "Nginx Host Header Configuration"

    local nginx_conf="/home/ubuntu/hookprobe-com/containers/proxy/nginx.conf"

    if [ ! -f "$nginx_conf" ]; then
        check_warning "Nginx config not found: $nginx_conf"
        return 0
    fi

    # Check that nginx passes the correct Host header
    if grep -q 'proxy_set_header Host \$host' "$nginx_conf"; then
        check_passed "Nginx passes original Host header (\$host)"
    else
        check_warning "Nginx may not be passing correct Host header"
        check_info "  Ensure: proxy_set_header Host \$host;"
    fi

    # Check MSSP upstream configuration
    local mssp_upstream=$(grep -A2 "upstream mssp" "$nginx_conf" | grep "server" | head -1)

    if echo "$mssp_upstream" | grep -q "host.containers.internal"; then
        check_passed "MSSP upstream uses host.containers.internal (hybrid mode)"
    elif echo "$mssp_upstream" | grep -q "172.30.0"; then
        check_passed "MSSP upstream uses direct IP (rootless mode)"
    else
        check_warning "MSSP upstream configuration unclear: $mssp_upstream"
    fi
}

check_cross_namespace_connectivity() {
    check_section "Cross-Namespace Connectivity"

    local issues=0

    # Check if rootless proxy can reach host networking services
    if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "hookprobe-proxy"; then
        # Test connectivity to Django (should be on port 8000)
        if podman exec hookprobe-proxy curl -s --connect-timeout 2 -o /dev/null -w "%{http_code}" http://host.containers.internal:8000/health/ 2>/dev/null | grep -q "200\|301\|302"; then
            check_passed "Proxy can reach Django via host.containers.internal:8000"
        else
            check_failed "Proxy CANNOT reach Django via host.containers.internal:8000"
            check_info "  This causes 502 Bad Gateway on mssp.hookprobe.com"
            check_info "  Fix: Ensure mssp-django runs with --network=host"
            ((issues++))
        fi

        # Test connectivity to Logto
        if podman exec hookprobe-proxy curl -s --connect-timeout 2 -o /dev/null -w "%{http_code}" http://host.containers.internal:3001/api/status 2>/dev/null | grep -q "200"; then
            check_passed "Proxy can reach Logto via host.containers.internal:3001"
        else
            check_warning "Proxy cannot reach Logto via host.containers.internal:3001"
        fi
    else
        check_info "Rootless proxy not running - skipping cross-namespace tests"
    fi

    return $issues
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
    check_section "Container Status"

    local failed=0
    local running=0

    # Check ROOT containers (use sudo)
    echo "Root namespace (sudo podman):"
    for container in "${ROOT_CONTAINERS[@]}"; do
        if sudo podman ps --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            # Check health status
            local health=$(sudo podman inspect "$container" --format '{{.State.Health.Status}}' 2>/dev/null || echo "none")
            if [ "$health" = "healthy" ]; then
                check_passed "$container is running (healthy)"
            elif [ "$health" = "unhealthy" ]; then
                check_warning "$container is running but UNHEALTHY"
            else
                check_passed "$container is running"
            fi
            ((running++))
        else
            check_failed "$container is NOT running"
            ((failed++))
        fi
    done

    # Check ROOTLESS containers (no sudo)
    echo ""
    echo "Rootless namespace (podman):"
    for container in "${ROOTLESS_CONTAINERS[@]}"; do
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            local health=$(podman inspect "$container" --format '{{.State.Health.Status}}' 2>/dev/null || echo "none")
            if [ "$health" = "healthy" ]; then
                check_passed "$container is running (healthy)"
            elif [ "$health" = "unhealthy" ]; then
                check_warning "$container is running but UNHEALTHY"
            else
                check_passed "$container is running"
            fi
            ((running++))
        else
            check_warning "$container is not running"
        fi
    done

    # Check optional containers (in root namespace)
    echo ""
    echo "Optional containers:"
    for container in "${OPTIONAL_CONTAINERS[@]}"; do
        if sudo podman ps --format "{{.Names}}" 2>/dev/null | grep -q "^${container}$"; then
            check_passed "$container is running (optional)"
            ((running++))
        else
            check_info "$container is not running (optional)"
        fi
    done

    echo ""
    check_info "Container Summary: $running running, $failed failed"
}

check_networks() {
    check_section "Podman Networks"

    # Root namespace networks (for MSSP pod segregation)
    local root_networks=(
        "mssp-pod-001-dmz"
        "mssp-pod-002-iam"
        "mssp-pod-003-db"
        "mssp-pod-004-cache"
        "mssp-pod-005-monitoring"
        "mssp-pod-006-security"
    )

    # Rootless namespace networks
    local rootless_networks=(
        "hookprobe-public"
    )

    echo "Root namespace networks:"
    for network in "${root_networks[@]}"; do
        if sudo podman network exists "$network" 2>/dev/null; then
            local subnet=$(sudo podman network inspect "$network" --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null || echo "unknown")
            check_passed "$network exists (subnet: $subnet)"
        else
            check_failed "$network does NOT exist"
        fi
    done

    echo ""
    echo "Rootless namespace networks:"
    for network in "${rootless_networks[@]}"; do
        if podman network exists "$network" 2>/dev/null; then
            local subnet=$(podman network inspect "$network" --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null || echo "unknown")
            check_passed "$network exists (subnet: $subnet)"
        else
            check_warning "$network does NOT exist"
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
    echo -e "${BLUE} HookProbe MSSP Health Check v2.0${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Timestamp: $(date)"
    echo "User: $(whoami)"

    # CRITICAL: Architecture and namespace detection first
    detect_architecture
    check_host_networking

    # Security checks
    check_allowed_hosts_security
    check_nginx_host_header
    check_cross_namespace_connectivity

    # Standard health checks
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

    # Summary
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} Health Check Complete${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

    # Architecture recommendation
    if [ -f /tmp/mssp-health-arch.tmp ]; then
        source /tmp/mssp-health-arch.tmp
        rm -f /tmp/mssp-health-arch.tmp
        echo ""
        if [ "$ARCHITECTURE" = "hybrid" ]; then
            echo -e "${YELLOW}NOTE: Running in hybrid mode (root + rootless namespaces)${NC}"
            echo -e "${YELLOW}      Consider migrating to fully rootless for simpler management.${NC}"
            echo -e "${YELLOW}      See: products/mssp/MIGRATION-ROOTLESS.md${NC}"
        fi
    fi
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
