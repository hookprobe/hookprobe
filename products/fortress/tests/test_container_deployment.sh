#!/bin/bash
#
# test_container_deployment.sh - Fortress Container Deployment Tests
#
# Validates that the containerized Fortress deployment works correctly.
# Run after ./fortress-containers.sh start
#
# Tests:
#   1. Container health checks
#   2. Database connectivity
#   3. Redis connectivity
#   4. Web UI accessibility
#   5. API endpoints
#   6. Volume persistence
#
# Usage: ./test_container_deployment.sh
#
# Version: 1.0.0
# License: AGPL-3.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONTAINERS_DIR="${PROJECT_DIR}/containers"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
WARNINGS=0

log_test() {
    echo -e "\n${YELLOW}[TEST]${NC} $1"
}

log_pass() {
    echo -e "  ${GREEN}✓ PASS:${NC} $1"
    ((PASSED++))
}

log_fail() {
    echo -e "  ${RED}✗ FAIL:${NC} $1"
    ((FAILED++))
}

log_warn() {
    echo -e "  ${YELLOW}! WARN:${NC} $1"
    ((WARNINGS++))
}

log_info() {
    echo -e "  [INFO] $1"
}

# ============================================================
# TEST: Podman/Docker availability
# ============================================================
test_runtime() {
    log_test "Container Runtime"

    if command -v podman &>/dev/null; then
        log_pass "Podman is available"
        CONTAINER_CMD="podman"
    elif command -v docker &>/dev/null; then
        log_pass "Docker is available"
        CONTAINER_CMD="docker"
    else
        log_fail "No container runtime found (podman or docker)"
        exit 1
    fi
}

# ============================================================
# TEST: Container Status
# ============================================================
test_container_status() {
    log_test "Container Status"

    local containers=("fortress-postgres" "fortress-redis" "fortress-web")

    for container in "${containers[@]}"; do
        if $CONTAINER_CMD ps --format "{{.Names}}" | grep -q "^${container}$"; then
            local status
            status=$($CONTAINER_CMD inspect --format '{{.State.Status}}' "$container" 2>/dev/null)
            if [ "$status" = "running" ]; then
                log_pass "$container is running"
            else
                log_fail "$container status: $status"
            fi
        else
            log_fail "$container is not running"
        fi
    done
}

# ============================================================
# TEST: Health Checks
# ============================================================
test_health_checks() {
    log_test "Container Health Checks"

    # PostgreSQL health
    if $CONTAINER_CMD exec fortress-postgres pg_isready -U fortress &>/dev/null; then
        log_pass "PostgreSQL is healthy"
    else
        log_fail "PostgreSQL health check failed"
    fi

    # Redis health
    if $CONTAINER_CMD exec fortress-redis redis-cli ping 2>/dev/null | grep -q "PONG"; then
        log_pass "Redis is healthy"
    else
        log_fail "Redis health check failed"
    fi

    # Web health endpoint
    if curl -sf -k https://localhost:8443/health &>/dev/null; then
        log_pass "Web health endpoint is accessible"
    else
        log_fail "Web health endpoint failed"
    fi
}

# ============================================================
# TEST: Database Connectivity
# ============================================================
test_database() {
    log_test "Database Connectivity"

    # Test database exists
    if $CONTAINER_CMD exec fortress-postgres psql -U fortress -d fortress -c "SELECT 1" &>/dev/null; then
        log_pass "Database 'fortress' exists and is accessible"
    else
        log_fail "Cannot connect to database"
        return
    fi

    # Test tables exist
    local tables=("devices" "vlans" "threats" "network_policies" "oui_classifications")
    for table in "${tables[@]}"; do
        if $CONTAINER_CMD exec fortress-postgres psql -U fortress -d fortress -c "SELECT 1 FROM $table LIMIT 1" &>/dev/null; then
            log_pass "Table '$table' exists"
        else
            log_warn "Table '$table' not found"
        fi
    done
}

# ============================================================
# TEST: Redis Connectivity
# ============================================================
test_redis() {
    log_test "Redis Connectivity"

    # Test set/get
    local test_key="fortress_test_$(date +%s)"
    local test_value="test_value_$$"

    if $CONTAINER_CMD exec fortress-redis redis-cli SET "$test_key" "$test_value" &>/dev/null; then
        log_pass "Redis SET operation works"
    else
        log_fail "Redis SET operation failed"
        return
    fi

    local retrieved
    retrieved=$($CONTAINER_CMD exec fortress-redis redis-cli GET "$test_key" 2>/dev/null)
    if [ "$retrieved" = "$test_value" ]; then
        log_pass "Redis GET operation works"
    else
        log_fail "Redis GET operation failed"
    fi

    # Cleanup
    $CONTAINER_CMD exec fortress-redis redis-cli DEL "$test_key" &>/dev/null
}

# ============================================================
# TEST: Web UI Accessibility
# ============================================================
test_web_ui() {
    log_test "Web UI Accessibility"

    # Test HTTPS redirect
    local response
    response=$(curl -sk -o /dev/null -w "%{http_code}" https://localhost:8443/)
    if [ "$response" = "302" ] || [ "$response" = "200" ]; then
        log_pass "Web UI responds (HTTP $response)"
    else
        log_fail "Web UI not responding (HTTP $response)"
    fi

    # Test login page
    response=$(curl -sk https://localhost:8443/login)
    if echo "$response" | grep -qi "login\|password\|sign in"; then
        log_pass "Login page is accessible"
    else
        log_warn "Login page may not be rendering correctly"
    fi

    # Test static assets
    response=$(curl -sk -o /dev/null -w "%{http_code}" https://localhost:8443/static/css/fortress.css 2>/dev/null)
    if [ "$response" = "200" ] || [ "$response" = "404" ]; then
        log_info "Static assets check: HTTP $response"
    fi
}

# ============================================================
# TEST: API Endpoints
# ============================================================
test_api_endpoints() {
    log_test "API Endpoints"

    # Health endpoint
    local health_response
    health_response=$(curl -sk https://localhost:8443/health)
    if echo "$health_response" | grep -q "healthy"; then
        log_pass "/health endpoint returns healthy"
    else
        log_fail "/health endpoint not working"
    fi
}

# ============================================================
# TEST: Volume Persistence
# ============================================================
test_volumes() {
    log_test "Volume Persistence"

    local volumes=("fortress-postgres-data" "fortress-redis-data" "fortress-web-data")

    for volume in "${volumes[@]}"; do
        if $CONTAINER_CMD volume exists "$volume" 2>/dev/null || $CONTAINER_CMD volume ls | grep -q "$volume"; then
            log_pass "Volume '$volume' exists"
        else
            log_warn "Volume '$volume' not found"
        fi
    done
}

# ============================================================
# TEST: Network Connectivity
# ============================================================
test_network() {
    log_test "Container Network"

    # Check containers can communicate
    if $CONTAINER_CMD exec fortress-web ping -c 1 postgres &>/dev/null 2>&1; then
        log_pass "Web can reach PostgreSQL"
    else
        log_warn "Web cannot ping PostgreSQL (may be expected)"
    fi

    # Check web can connect to database
    if $CONTAINER_CMD exec fortress-web python3 -c "
import os
try:
    import psycopg2
    conn = psycopg2.connect(
        host=os.environ.get('DATABASE_HOST', 'postgres'),
        port=os.environ.get('DATABASE_PORT', 5432),
        user=os.environ.get('DATABASE_USER', 'fortress'),
        dbname=os.environ.get('DATABASE_NAME', 'fortress')
    )
    conn.close()
    print('connected')
except Exception as e:
    print(f'failed: {e}')
" 2>/dev/null | grep -q "connected"; then
        log_pass "Web container can connect to database"
    else
        log_warn "Web container database connection check failed"
    fi
}

# ============================================================
# TEST: Logs Accessibility
# ============================================================
test_logs() {
    log_test "Container Logs"

    for container in fortress-postgres fortress-redis fortress-web; do
        if $CONTAINER_CMD logs --tail 1 "$container" &>/dev/null; then
            log_pass "Logs accessible for $container"
        else
            log_fail "Cannot access logs for $container"
        fi
    done
}

# ============================================================
# MAIN
# ============================================================
main() {
    echo "========================================"
    echo "Fortress Container Deployment Tests"
    echo "========================================"
    echo ""

    # Run tests
    test_runtime
    test_container_status
    test_health_checks
    test_database
    test_redis
    test_web_ui
    test_api_endpoints
    test_volumes
    test_network
    test_logs

    # Summary
    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo -e "  ${GREEN}Passed:${NC}   $PASSED"
    echo -e "  ${RED}Failed:${NC}   $FAILED"
    echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
    echo ""

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}All critical tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed. Check output above.${NC}"
        exit 1
    fi
}

main "$@"
