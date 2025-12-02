#!/bin/bash
#
# lightweight-config.sh
# HookProbe Lightweight Configuration for Testing/Development
# Target: Raspberry Pi 4 (4GB RAM), Development machines
# Version: 5.0
# License: MIT
#
# This configuration is optimized for testing and development with
# minimal resource usage. Only essential PODs are included.
#

set -euo pipefail

# ============================================================
# DEPLOYMENT TYPE
# ============================================================
DEPLOYMENT_TYPE="lightweight-testing"  # Lightweight testing/development
MSSP_MODE="false"                       # Single-tenant only

# ============================================================
# INCLUDED PODS (LIGHTWEIGHT)
# ============================================================
# POD-001: Web Server (Django + Nginx + NAXSI WAF)
# POD-002: IAM (Logto - lightweight alternative to Keycloak)
# POD-003: Database (PostgreSQL 16-alpine)
# POD-005: Cache (Redis 7-alpine)
#
# EXCLUDED (Too heavy for 4GB RAM):
# POD-004: Monitoring (Grafana, ClickHouse, VictoriaMetrics)
# POD-007: AI/Qsecbit (ML workloads)

ENABLE_WEB=true          # POD-001: Django web application
ENABLE_IAM=true          # POD-002: Logto authentication
ENABLE_DATABASE=true     # POD-003: PostgreSQL
ENABLE_CACHE=true        # POD-005: Redis
ENABLE_MONITORING=false  # POD-004: Disabled (too heavy)
ENABLE_AI=false          # POD-007: Disabled (too heavy)

# ============================================================
# SYSTEM DETECTION
# ============================================================
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="$ID"
        OS_VERSION="$VERSION_ID"
    else
        OS_NAME="unknown"
        OS_VERSION="unknown"
    fi
    export OS_NAME OS_VERSION
}

detect_os

# ============================================================
# PHYSICAL HOST CONFIGURATION
# ============================================================
LOCAL_HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || echo "127.0.0.1")
EXTERNAL_DOMAIN="localhost"  # For testing

# ============================================================
# PODMAN POD DEFINITIONS (Lightweight)
# ============================================================
POD_WEB="hookprobe-web"
POD_DATABASE="hookprobe-database"
POD_CACHE="hookprobe-cache"
POD_IAM="hookprobe-iam"

NETWORK_WEB="web-net"
NETWORK_DATABASE="database-net"
NETWORK_CACHE="cache-net"
NETWORK_IAM="iam-net"

# Network Interface Names (visible in ip addr / ifconfig)
INTERFACE_WEB="hpweb0"        # HookProbe Web interface
INTERFACE_DATABASE="hpdb0"    # HookProbe Database interface
INTERFACE_CACHE="hpcache0"    # HookProbe Cache interface
INTERFACE_IAM="hpiam0"        # HookProbe IAM interface

# ============================================================
# WEB POD NETWORK (Django + Nginx + NAXSI)
# ============================================================
SUBNET_WEB="10.250.1.0/24"
GATEWAY_WEB="10.250.1.1"
IP_WEB_DJANGO="10.250.1.10"
IP_WEB_NGINX="10.250.1.11"

# ============================================================
# DATABASE NETWORK (PostgreSQL)
# ============================================================
SUBNET_DATABASE="10.250.2.0/24"
GATEWAY_DATABASE="10.250.2.1"
IP_DATABASE_POSTGRES="10.250.2.10"

# ============================================================
# CACHE NETWORK (Redis)
# ============================================================
SUBNET_CACHE="10.250.3.0/24"
GATEWAY_CACHE="10.250.3.1"
IP_CACHE_REDIS="10.250.3.10"

# ============================================================
# IAM NETWORK (Logto)
# ============================================================
SUBNET_IAM="10.250.4.0/24"
GATEWAY_IAM="10.250.4.1"
IP_IAM_LOGTO="10.250.4.10"
IP_IAM_POSTGRES="10.250.4.11"

# ============================================================
# CONTAINER IMAGES (Lightweight versions)
# ============================================================
IMAGE_POSTGRES="docker.io/library/postgres:16-alpine"      # PostgreSQL License
IMAGE_REDIS="docker.io/library/redis:7-alpine"             # BSD-3-Clause
IMAGE_LOGTO="docker.io/svhd/logto:latest"                  # MPL-2.0
IMAGE_NGINX="docker.io/library/nginx:1.25-alpine"          # BSD-2-Clause

# ============================================================
# DATABASE CONFIGURATION
# ============================================================
# Main PostgreSQL Database
POSTGRES_DB="hookprobe"
POSTGRES_USER="hookprobe"
POSTGRES_PASSWORD="hookprobe_test_password_CHANGE_ME"  # ⚠️ CHANGE IN PRODUCTION

# Logto IAM Database
LOGTO_DB="logto"
LOGTO_DB_USER="logto"
LOGTO_DB_PASSWORD="logto_test_password_CHANGE_ME"     # ⚠️ CHANGE IN PRODUCTION

# PostgreSQL Resource Limits (Optimized for 4GB RAM)
POSTGRES_MEMORY_LIMIT="512m"
POSTGRES_SHARED_BUFFERS="128MB"
POSTGRES_EFFECTIVE_CACHE_SIZE="256MB"
POSTGRES_MAX_CONNECTIONS="50"

# ============================================================
# REDIS CONFIGURATION
# ============================================================
REDIS_PASSWORD="redis_test_password_CHANGE_ME"         # ⚠️ CHANGE IN PRODUCTION
REDIS_MEMORY_LIMIT="256m"
REDIS_MAXMEMORY="200mb"
REDIS_MAXMEMORY_POLICY="allkeys-lru"

# ============================================================
# DJANGO WEB APPLICATION CONFIGURATION
# ============================================================
DJANGO_SECRET_KEY="django_test_secret_key_CHANGE_ME_IN_PRODUCTION"  # ⚠️ CHANGE
DJANGO_DEBUG="True"   # Set to False in production
DJANGO_ALLOWED_HOSTS="*"  # Set specific hosts in production
DJANGO_ENV="development"  # development, testing, or production

# Django Resource Limits
DJANGO_MEMORY_LIMIT="1g"
DJANGO_CPU_LIMIT="2.0"

# ============================================================
# LOGTO IAM CONFIGURATION
# ============================================================
LOGTO_ENDPOINT="http://localhost:3001"
LOGTO_ADMIN_ENDPOINT="http://localhost:3002"

# Logto Application Credentials (set these after Logto is configured)
LOGTO_APP_ID="CHANGE_ME_AFTER_LOGTO_SETUP"
LOGTO_APP_SECRET="CHANGE_ME_AFTER_LOGTO_SETUP"

# Logto Resource Limits
LOGTO_MEMORY_LIMIT="512m"
LOGTO_CPU_LIMIT="1.0"

# ============================================================
# NGINX WAF CONFIGURATION
# ============================================================
NGINX_MEMORY_LIMIT="256m"
NGINX_CPU_LIMIT="1.0"

# ============================================================
# PERSISTENT VOLUMES
# ============================================================
VOLUME_POSTGRES_DATA="hookprobe-postgres-data-test"
VOLUME_DJANGO_STATIC="hookprobe-django-static-test"
VOLUME_DJANGO_MEDIA="hookprobe-django-media-test"
VOLUME_LOGTO_DATA="hookprobe-logto-data-test"

# ============================================================
# PORT MAPPINGS
# ============================================================
PORT_HTTP="8080"           # Web application HTTP
PORT_HTTPS="8443"          # Web application HTTPS
PORT_POSTGRES="5432"       # PostgreSQL database
PORT_REDIS="6379"          # Redis cache
PORT_LOGTO="3001"          # Logto authentication API
PORT_LOGTO_ADMIN="3002"    # Logto admin interface

# ============================================================
# RESOURCE TOTALS (Estimated for 4GB RAM System)
# ============================================================
# Django:      1GB
# PostgreSQL:  512MB
# Logto:       512MB
# Redis:       256MB
# Nginx:       256MB
# ------------
# Total:       ~2.5GB (leaves ~1.5GB for OS and overhead)

# ============================================================
# VALIDATION
# ============================================================
validate_config() {
    echo "Validating lightweight configuration..."

    # Check RAM
    local ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_gb=$((ram_kb / 1024 / 1024))

    if [ "$ram_gb" -lt 4 ]; then
        echo "⚠️  WARNING: System has ${ram_gb}GB RAM. Minimum 4GB recommended."
        echo "   Continue at your own risk."
    else
        echo "✓ RAM check passed: ${ram_gb}GB"
    fi

    # Check Podman
    if ! command -v podman &> /dev/null; then
        echo "✗ Podman not installed"
        echo "  Install: sudo apt install podman (Debian/Ubuntu)"
        echo "           sudo dnf install podman (Fedora/RHEL)"
        return 1
    else
        echo "✓ Podman installed: $(podman --version | head -1)"
    fi

    # Check disk space (need at least 20GB)
    local disk_avail=$(df / | awk 'NR==2 {print $4}')
    local disk_gb=$((disk_avail / 1024 / 1024))

    if [ "$disk_gb" -lt 20 ]; then
        echo "⚠️  WARNING: Only ${disk_gb}GB disk space available. 20GB+ recommended."
    else
        echo "✓ Disk space check passed: ${disk_gb}GB available"
    fi

    # Check architecture
    local arch=$(uname -m)
    case "$arch" in
        x86_64|aarch64)
            echo "✓ Architecture supported: $arch"
            ;;
        *)
            echo "⚠️  WARNING: Untested architecture: $arch"
            ;;
    esac

    echo ""
    echo "Configuration validated for lightweight deployment"
    echo "Target: Testing/Development on Raspberry Pi 4 or similar"
    echo ""
}

# ============================================================
# SECURITY WARNINGS
# ============================================================
show_security_warnings() {
    echo "⚠️  SECURITY WARNINGS FOR LIGHTWEIGHT DEPLOYMENT:"
    echo ""
    echo "1. Default passwords are set - CHANGE THEM before production use"
    echo "2. DJANGO_DEBUG=True - DO NOT use in production"
    echo "3. ALLOWED_HOSTS='*' - Restrict in production"
    echo "4. No monitoring - Consider enabling for production"
    echo "5. No AI/Qsecbit - Limited threat detection"
    echo ""
    echo "This configuration is suitable for:"
    echo "  ✓ Development and testing"
    echo "  ✓ Learning and experimentation"
    echo "  ✓ CI/CD pipelines"
    echo "  ✗ Production deployments"
    echo ""
}

# Export all variables
export DEPLOYMENT_TYPE MSSP_MODE
export ENABLE_WEB ENABLE_IAM ENABLE_DATABASE ENABLE_CACHE ENABLE_MONITORING ENABLE_AI
export POD_WEB POD_DATABASE POD_CACHE POD_IAM
export NETWORK_WEB NETWORK_DATABASE NETWORK_CACHE NETWORK_IAM
export INTERFACE_WEB INTERFACE_DATABASE INTERFACE_CACHE INTERFACE_IAM
export SUBNET_WEB GATEWAY_WEB IP_WEB_DJANGO IP_WEB_NGINX
export SUBNET_DATABASE GATEWAY_DATABASE IP_DATABASE_POSTGRES
export SUBNET_CACHE GATEWAY_CACHE IP_CACHE_REDIS
export SUBNET_IAM GATEWAY_IAM IP_IAM_LOGTO IP_IAM_POSTGRES
export IMAGE_POSTGRES IMAGE_REDIS IMAGE_LOGTO IMAGE_NGINX
export POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD
export LOGTO_DB LOGTO_DB_USER LOGTO_DB_PASSWORD
export POSTGRES_MEMORY_LIMIT POSTGRES_SHARED_BUFFERS POSTGRES_EFFECTIVE_CACHE_SIZE POSTGRES_MAX_CONNECTIONS
export REDIS_PASSWORD REDIS_MEMORY_LIMIT REDIS_MAXMEMORY REDIS_MAXMEMORY_POLICY
export DJANGO_SECRET_KEY DJANGO_DEBUG DJANGO_ALLOWED_HOSTS DJANGO_ENV
export DJANGO_MEMORY_LIMIT DJANGO_CPU_LIMIT
export LOGTO_ENDPOINT LOGTO_ADMIN_ENDPOINT LOGTO_APP_ID LOGTO_APP_SECRET
export LOGTO_MEMORY_LIMIT LOGTO_CPU_LIMIT
export NGINX_MEMORY_LIMIT NGINX_CPU_LIMIT
export VOLUME_POSTGRES_DATA VOLUME_DJANGO_STATIC VOLUME_DJANGO_MEDIA VOLUME_LOGTO_DATA
export PORT_HTTP PORT_HTTPS PORT_POSTGRES PORT_REDIS PORT_LOGTO PORT_LOGTO_ADMIN

echo "✓ Lightweight configuration loaded for $DEPLOYMENT_TYPE"
