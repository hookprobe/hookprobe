#!/bin/bash
#
# HookProbe Web Server Configuration
# Optional addon for POD-001 Web DMZ
#
# This configuration is sourced by the web server installation script
#

# ============================================================================
# Deployment Type
# ============================================================================
# Options: edge, cloud, standalone
# - edge: Full web server on edge device (recommended for home/SMB)
# - cloud: Centralized Service Provider web server (multi-tenant)
# - standalone: Development/testing
DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-edge}"

# ============================================================================
# Web Server Configuration
# ============================================================================
WEBSERVER_ENABLED="${WEBSERVER_ENABLED:-true}"
WEBSERVER_PORT="${WEBSERVER_PORT:-8000}"
WEBSERVER_HOST="${WEBSERVER_HOST:-0.0.0.0}"
WEBSERVER_WORKERS="${WEBSERVER_WORKERS:-4}"
WEBSERVER_TIMEOUT="${WEBSERVER_TIMEOUT:-120}"

# ============================================================================
# Database Configuration (POD-003)
# ============================================================================
POSTGRES_HOST="${POSTGRES_HOST:-10.200.3.12}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-hookprobe}"
POSTGRES_USER="${POSTGRES_USER:-hookprobe}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-changeme}"

# ============================================================================
# Cache Configuration (POD-004)
# ============================================================================
REDIS_HOST="${REDIS_HOST:-10.200.4.12}"
REDIS_PORT="${REDIS_PORT:-6379}"

# ============================================================================
# ClickHouse Configuration (POD-005)
# ============================================================================
CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-10.200.5.12}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
CLICKHOUSE_DATABASE="${CLICKHOUSE_DATABASE:-security}"

# ============================================================================
# Qsecbit API Configuration (POD-006)
# ============================================================================
QSECBIT_API_URL="${QSECBIT_API_URL:-http://10.200.6.12:8888}"

# ============================================================================
# Django Configuration
# ============================================================================
DJANGO_ENV="${DJANGO_ENV:-production}"
DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:-$(openssl rand -base64 64 | tr -d '\n')}"
DJANGO_ALLOWED_HOST="${DJANGO_ALLOWED_HOST:-*}"
DJANGO_DEBUG="${DJANGO_DEBUG:-False}"

# ============================================================================
# Container Configuration
# ============================================================================
CONTAINER_NAME="${CONTAINER_NAME:-hookprobe-webserver}"
CONTAINER_IMAGE="${CONTAINER_IMAGE:-python:3.11-slim}"
CONTAINER_NETWORK="${CONTAINER_NETWORK:-hookprobe-pod-001}"

# ============================================================================
# Installation Paths
# ============================================================================
INSTALL_DIR="${INSTALL_DIR:-/opt/hookprobe}"
WEB_DIR="${WEB_DIR:-${INSTALL_DIR}/web}"
VENV_DIR="${VENV_DIR:-${WEB_DIR}/venv}"
LOG_DIR="${LOG_DIR:-/var/log/hookprobe}"
STATIC_DIR="${STATIC_DIR:-${WEB_DIR}/staticfiles}"
MEDIA_DIR="${MEDIA_DIR:-${WEB_DIR}/media}"

# ============================================================================
# Nginx Configuration (optional)
# ============================================================================
NGINX_ENABLED="${NGINX_ENABLED:-true}"
NGINX_PORT="${NGINX_PORT:-80}"
NGINX_SSL_PORT="${NGINX_SSL_PORT:-443}"
NGINX_SSL_ENABLED="${NGINX_SSL_ENABLED:-false}"

# ============================================================================
# Grafana Integration
# ============================================================================
GRAFANA_URL="${GRAFANA_URL:-http://10.200.5.12:3000}"
GRAFANA_API_KEY="${GRAFANA_API_KEY:-}"

# ============================================================================
# Email Configuration (optional)
# ============================================================================
EMAIL_ENABLED="${EMAIL_ENABLED:-false}"
EMAIL_HOST="${EMAIL_HOST:-smtp.gmail.com}"
EMAIL_PORT="${EMAIL_PORT:-587}"
EMAIL_HOST_USER="${EMAIL_HOST_USER:-}"
EMAIL_HOST_PASSWORD="${EMAIL_HOST_PASSWORD:-}"
DEFAULT_FROM_EMAIL="${DEFAULT_FROM_EMAIL:-noreply@hookprobe.local}"

# ============================================================================
# Multi-Tenant Configuration (Service Provider Cloud only)
# ============================================================================
MULTITENANT_ENABLED="${MULTITENANT_ENABLED:-false}"
TENANT_ID="${TENANT_ID:-default}"

# ============================================================================
# Frontend Themes
# ============================================================================
# Automatically download and configure themes
AUTO_DOWNLOAD_THEMES="${AUTO_DOWNLOAD_THEMES:-true}"
FORTY_THEME_URL="${FORTY_THEME_URL:-https://html5up.net/forty/download}"
ADMINLTE_THEME_URL="${ADMINLTE_THEME_URL:-https://github.com/ColorlibHQ/AdminLTE/releases/download/v3.2.0/AdminLTE-3.2.0.zip}"

# ============================================================================
# Systemd Service
# ============================================================================
SYSTEMD_ENABLED="${SYSTEMD_ENABLED:-true}"
SYSTEMD_SERVICE_NAME="${SYSTEMD_SERVICE_NAME:-hookprobe-webserver}"

# ============================================================================
# Validation
# ============================================================================
validate_config() {
    echo "Validating web server configuration..."

    # Check deployment type
    if [[ ! "$DEPLOYMENT_TYPE" =~ ^(edge|cloud|standalone)$ ]]; then
        echo "ERROR: Invalid DEPLOYMENT_TYPE: $DEPLOYMENT_TYPE"
        echo "Must be: edge, cloud, or standalone"
        return 1
    fi

    # Check if POD-003 is accessible (PostgreSQL)
    if ! nc -z -w5 "$POSTGRES_HOST" "$POSTGRES_PORT" 2>/dev/null; then
        echo "WARNING: Cannot connect to PostgreSQL at $POSTGRES_HOST:$POSTGRES_PORT"
        echo "Make sure POD-003 is running before starting web server"
    fi

    # Check if POD-004 is accessible (Redis)
    if ! nc -z -w5 "$REDIS_HOST" "$REDIS_PORT" 2>/dev/null; then
        echo "WARNING: Cannot connect to Redis at $REDIS_HOST:$REDIS_PORT"
        echo "Make sure POD-004 is running before starting web server"
    fi

    echo "Configuration validation complete"
    return 0
}

# ============================================================================
# Display Configuration
# ============================================================================
show_config() {
    cat <<EOF

========================================
HookProbe Web Server Configuration
========================================
Deployment Type: $DEPLOYMENT_TYPE
Web Server Port: $WEBSERVER_PORT
Django Environment: $DJANGO_ENV

Database:
  PostgreSQL: $POSTGRES_HOST:$POSTGRES_PORT
  Database: $POSTGRES_DB

Cache:
  Redis: $REDIS_HOST:$REDIS_PORT

Integration:
  ClickHouse: $CLICKHOUSE_HOST:$CLICKHOUSE_PORT
  Qsecbit API: $QSECBIT_API_URL
  Grafana: $GRAFANA_URL

Paths:
  Install Dir: $INSTALL_DIR
  Web Dir: $WEB_DIR
  Log Dir: $LOG_DIR

Services:
  Nginx: $([ "$NGINX_ENABLED" = "true" ] && echo "Enabled" || echo "Disabled")
  Systemd: $([ "$SYSTEMD_ENABLED" = "true" ] && echo "Enabled" || echo "Disabled")
  Multi-Tenant: $([ "$MULTITENANT_ENABLED" = "true" ] && echo "Enabled" || echo "Disabled")

========================================

EOF
}
