#!/bin/bash
#
# HookProbe Unified Configuration System
#
# This file contains all common configuration variables used across
# different deployment types (edge, cloud, hybrid, headless).
#
# Each deployment type should source this file and override specific
# variables as needed.
#
# Usage:
#   source /path/to/unified-config.sh
#   # Override variables as needed
#

# ============================================================================
# Version and Release Information
# ============================================================================

# HookProbe version
export HOOKPROBE_VERSION="${HOOKPROBE_VERSION:-5.0.1}"

# Release codename
export HOOKPROBE_CODENAME="${HOOKPROBE_CODENAME:-Horizon}"

# Build date (ISO 8601 format)
export HOOKPROBE_BUILD_DATE="${HOOKPROBE_BUILD_DATE:-2025-11-25}"

# ============================================================================
# Deployment Configuration
# ============================================================================

# Deployment type: edge, cloud, hybrid, headless, development
export DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-edge}"

# Environment: production, staging, development
export ENVIRONMENT="${ENVIRONMENT:-production}"

# Enable debug mode (should be false in production)
export DEBUG_MODE="${DEBUG_MODE:-false}"

# Enable verbose logging
export VERBOSE_LOGGING="${VERBOSE_LOGGING:-false}"

# ============================================================================
# Network Configuration
# ============================================================================

# Physical host interface (for edge deployments)
export PHYSICAL_HOST_INTERFACE="${PHYSICAL_HOST_INTERFACE:-eth0}"

# Physical host IP (for edge deployments)
export PHYSICAL_HOST_IP="${PHYSICAL_HOST_IP:-}"

# Network prefix for all PODs
export POD_NETWORK_PREFIX="${POD_NETWORK_PREFIX:-10.200}"

# POD Network Ranges
export POD_001_NETWORK="${POD_001_NETWORK:-${POD_NETWORK_PREFIX}.1.0/24}"
export POD_002_NETWORK="${POD_002_NETWORK:-${POD_NETWORK_PREFIX}.2.0/24}"
export POD_003_NETWORK="${POD_003_NETWORK:-${POD_NETWORK_PREFIX}.3.0/24}"
export POD_004_NETWORK="${POD_004_NETWORK:-${POD_NETWORK_PREFIX}.4.0/24}"
export POD_005_NETWORK="${POD_005_NETWORK:-${POD_NETWORK_PREFIX}.5.0/24}"
export POD_006_NETWORK="${POD_006_NETWORK:-${POD_NETWORK_PREFIX}.6.0/24}"
export POD_007_NETWORK="${POD_007_NETWORK:-${POD_NETWORK_PREFIX}.7.0/24}"
export POD_008_NETWORK="${POD_008_NETWORK:-${POD_NETWORK_PREFIX}.8.0/24}"

# POD Gateway IPs (typically .1 in each network)
export POD_001_GATEWAY="${POD_001_GATEWAY:-${POD_NETWORK_PREFIX}.1.1}"
export POD_002_GATEWAY="${POD_002_GATEWAY:-${POD_NETWORK_PREFIX}.2.1}"
export POD_003_GATEWAY="${POD_003_GATEWAY:-${POD_NETWORK_PREFIX}.3.1}"
export POD_004_GATEWAY="${POD_004_GATEWAY:-${POD_NETWORK_PREFIX}.4.1}"
export POD_005_GATEWAY="${POD_005_GATEWAY:-${POD_NETWORK_PREFIX}.5.1}"
export POD_006_GATEWAY="${POD_006_GATEWAY:-${POD_NETWORK_PREFIX}.6.1}"
export POD_007_GATEWAY="${POD_007_GATEWAY:-${POD_NETWORK_PREFIX}.7.1}"
export POD_008_GATEWAY="${POD_008_GATEWAY:-${POD_NETWORK_PREFIX}.8.1}"

# ============================================================================
# POD-001: Web DMZ & Management
# ============================================================================

export POD_001_ENABLED="${POD_001_ENABLED:-true}"
export POD_001_IP="${POD_001_IP:-${POD_NETWORK_PREFIX}.1.12}"

# Nginx configuration
export NGINX_PORT="${NGINX_PORT:-80}"
export NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT:-443}"
export NGINX_ENABLED="${NGINX_ENABLED:-true}"

# Django CMS (optional)
export DJANGO_CMS_ENABLED="${DJANGO_CMS_ENABLED:-false}"
export DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:-CHANGE-THIS-IN-PRODUCTION}"
export DJANGO_DEBUG="${DJANGO_DEBUG:-False}"
export DJANGO_ALLOWED_HOST="${DJANGO_ALLOWED_HOST:-*}"
export DJANGO_ENV="${DJANGO_ENV:-production}"

# Gunicorn settings
export GUNICORN_WORKERS="${GUNICORN_WORKERS:-4}"
export GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-120}"

# Cloudflare Tunnel (optional)
export CLOUDFLARE_TUNNEL_ENABLED="${CLOUDFLARE_TUNNEL_ENABLED:-false}"
export CLOUDFLARE_TUNNEL_TOKEN="${CLOUDFLARE_TUNNEL_TOKEN:-}"

# ============================================================================
# POD-002: IAM (Identity and Access Management)
# ============================================================================

export POD_002_ENABLED="${POD_002_ENABLED:-true}"
export POD_002_IP="${POD_002_IP:-${POD_NETWORK_PREFIX}.2.12}"

# Logto configuration
export LOGTO_PORT="${LOGTO_PORT:-3001}"
export LOGTO_ADMIN_PORT="${LOGTO_ADMIN_PORT:-3002}"
export LOGTO_ENDPOINT="${LOGTO_ENDPOINT:-http://${POD_002_IP}:${LOGTO_PORT}}"

# ============================================================================
# POD-003: Database (PostgreSQL)
# ============================================================================

export POD_003_ENABLED="${POD_003_ENABLED:-true}"
export POD_003_IP="${POD_003_IP:-${POD_NETWORK_PREFIX}.3.12}"

# PostgreSQL configuration
export POSTGRES_VERSION="${POSTGRES_VERSION:-16}"
export POSTGRES_PORT="${POSTGRES_PORT:-5432}"
export POSTGRES_DB="${POSTGRES_DB:-hookprobe}"
export POSTGRES_USER="${POSTGRES_USER:-hookprobe}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-changeme}"
export POSTGRES_HOST="${POSTGRES_HOST:-${POD_003_IP}}"

# Database backup settings
export DB_BACKUP_ENABLED="${DB_BACKUP_ENABLED:-true}"
export DB_BACKUP_RETENTION_DAYS="${DB_BACKUP_RETENTION_DAYS:-7}"

# ============================================================================
# POD-004: Cache (Redis)
# ============================================================================

export POD_004_ENABLED="${POD_004_ENABLED:-true}"
export POD_004_IP="${POD_004_IP:-${POD_NETWORK_PREFIX}.4.12}"

# Redis configuration
export REDIS_VERSION="${REDIS_VERSION:-7}"
export REDIS_PORT="${REDIS_PORT:-6379}"
export REDIS_HOST="${REDIS_HOST:-${POD_004_IP}}"
export REDIS_PASSWORD="${REDIS_PASSWORD:-}"
export REDIS_MAXMEMORY="${REDIS_MAXMEMORY:-256mb}"

# ============================================================================
# POD-005: Monitoring (Grafana, VictoriaMetrics, ClickHouse)
# ============================================================================

export POD_005_ENABLED="${POD_005_ENABLED:-true}"
export POD_005_IP="${POD_005_IP:-${POD_NETWORK_PREFIX}.5.12}"

# Grafana configuration
export GRAFANA_PORT="${GRAFANA_PORT:-3000}"
export GRAFANA_ADMIN_USER="${GRAFANA_ADMIN_USER:-admin}"
export GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-changeme}"
export GRAFANA_URL="${GRAFANA_URL:-http://${POD_005_IP}:${GRAFANA_PORT}}"
export GRAFANA_API_KEY="${GRAFANA_API_KEY:-}"

# VictoriaMetrics configuration
export VICTORIAMETRICS_PORT="${VICTORIAMETRICS_PORT:-8428}"
export VICTORIAMETRICS_RETENTION="${VICTORIAMETRICS_RETENTION:-12}"  # months

# ClickHouse configuration
export CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
export CLICKHOUSE_NATIVE_PORT="${CLICKHOUSE_NATIVE_PORT:-9000}"
export CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-${POD_005_IP}}"
export CLICKHOUSE_DATABASE="${CLICKHOUSE_DATABASE:-security}"
export CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"

# ============================================================================
# POD-006: Security (Zeek, Snort 3, Qsecbit)
# ============================================================================

export POD_006_ENABLED="${POD_006_ENABLED:-true}"
export POD_006_IP="${POD_006_IP:-${POD_NETWORK_PREFIX}.6.12}"

# Qsecbit API configuration
export QSECBIT_API_PORT="${QSECBIT_API_PORT:-8888}"
export QSECBIT_API_URL="${QSECBIT_API_URL:-http://${POD_006_IP}:${QSECBIT_API_PORT}}"

# Zeek configuration
export ZEEK_ENABLED="${ZEEK_ENABLED:-true}"
export ZEEK_INTERFACE="${ZEEK_INTERFACE:-${PHYSICAL_HOST_INTERFACE}}"

# Snort 3 configuration
export SNORT_ENABLED="${SNORT_ENABLED:-true}"
export SNORT_INTERFACE="${SNORT_INTERFACE:-${PHYSICAL_HOST_INTERFACE}}"

# ============================================================================
# POD-007: AI Response (Kali Linux, Mitigation Engine)
# ============================================================================

export POD_007_ENABLED="${POD_007_ENABLED:-true}"
export POD_007_IP="${POD_007_IP:-${POD_NETWORK_PREFIX}.7.12}"

# AI/ML model configuration
export AI_MODEL_ENABLED="${AI_MODEL_ENABLED:-false}"
export AI_MODEL_TYPE="${AI_MODEL_TYPE:-local}"  # local, openai, anthropic

# Mitigation engine
export AUTO_MITIGATION_ENABLED="${AUTO_MITIGATION_ENABLED:-false}"
export MITIGATION_CONFIDENCE_THRESHOLD="${MITIGATION_CONFIDENCE_THRESHOLD:-0.8}"

# ============================================================================
# POD-008: Workflow Automation (n8n) - Optional
# ============================================================================

export POD_008_ENABLED="${POD_008_ENABLED:-false}"
export POD_008_IP="${POD_008_IP:-${POD_NETWORK_PREFIX}.8.12}"

# n8n configuration
export N8N_PORT="${N8N_PORT:-5678}"
export N8N_URL="${N8N_URL:-http://${POD_008_IP}:${N8N_PORT}}"

# ============================================================================
# Container Runtime Configuration
# ============================================================================

# Container runtime: podman or docker
export CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"

# Container registry
export CONTAINER_REGISTRY="${CONTAINER_REGISTRY:-ghcr.io/hookprobe}"

# Pull policy: always, missing, never
export CONTAINER_PULL_POLICY="${CONTAINER_PULL_POLICY:-missing}"

# ============================================================================
# Installation Paths
# ============================================================================

# Installation root directory
export INSTALL_DIR="${INSTALL_DIR:-/opt/hookprobe}"

# Configuration directory
export CONFIG_DIR="${CONFIG_DIR:-${INSTALL_DIR}/config}"

# Data directory
export DATA_DIR="${DATA_DIR:-${INSTALL_DIR}/data}"

# Log directory
export LOG_DIR="${LOG_DIR:-${INSTALL_DIR}/logs}"

# ============================================================================
# Web Server Paths (if Django CMS is enabled)
# ============================================================================

export WEB_DIR="${WEB_DIR:-${INSTALL_DIR}/web}"
export VENV_DIR="${VENV_DIR:-${INSTALL_DIR}/venv}"
export STATIC_DIR="${STATIC_DIR:-${WEB_DIR}/staticfiles}"
export MEDIA_DIR="${MEDIA_DIR:-${WEB_DIR}/media}"

# ============================================================================
# Email Configuration
# ============================================================================

export EMAIL_ENABLED="${EMAIL_ENABLED:-false}"
export EMAIL_HOST="${EMAIL_HOST:-smtp.gmail.com}"
export EMAIL_PORT="${EMAIL_PORT:-587}"
export EMAIL_HOST_USER="${EMAIL_HOST_USER:-}"
export EMAIL_HOST_PASSWORD="${EMAIL_HOST_PASSWORD:-}"
export EMAIL_USE_TLS="${EMAIL_USE_TLS:-true}"
export DEFAULT_FROM_EMAIL="${DEFAULT_FROM_EMAIL:-noreply@hookprobe.local}"

# Alert email recipients
export ALERT_EMAIL_RECIPIENTS="${ALERT_EMAIL_RECIPIENTS:-admin@hookprobe.local}"

# ============================================================================
# Multi-Tenancy Configuration
# ============================================================================

export MULTITENANT_ENABLED="${MULTITENANT_ENABLED:-false}"
export TENANT_ID="${TENANT_ID:-default}"

# ============================================================================
# Feature Flags
# ============================================================================

# Enable/disable specific features
export FEATURE_WEB_CMS="${FEATURE_WEB_CMS:-${DJANGO_CMS_ENABLED}}"
export FEATURE_WORKFLOW_AUTOMATION="${FEATURE_WORKFLOW_AUTOMATION:-${POD_008_ENABLED}}"
export FEATURE_AI_DETECTION="${FEATURE_AI_DETECTION:-${AI_MODEL_ENABLED}}"
export FEATURE_AUTO_MITIGATION="${FEATURE_AUTO_MITIGATION:-${AUTO_MITIGATION_ENABLED}}"
export FEATURE_EMAIL_ALERTS="${FEATURE_EMAIL_ALERTS:-${EMAIL_ENABLED}}"

# ============================================================================
# Systemd Configuration
# ============================================================================

export SYSTEMD_ENABLED="${SYSTEMD_ENABLED:-true}"
export SYSTEMD_SERVICE_PREFIX="${SYSTEMD_SERVICE_PREFIX:-hookprobe}"

# ============================================================================
# Theme and Customization
# ============================================================================

# Auto-download frontend themes
export AUTO_DOWNLOAD_THEMES="${AUTO_DOWNLOAD_THEMES:-true}"

# Theme URLs
export FORTY_THEME_URL="${FORTY_THEME_URL:-https://html5up.net/forty/download}"
export ADMINLTE_THEME_URL="${ADMINLTE_THEME_URL:-https://github.com/ColorlibHQ/AdminLTE/archive/refs/tags/v3.2.0.zip}"

# ============================================================================
# Validation Functions
# ============================================================================

# Validate configuration
validate_unified_config() {
    local errors=0

    # Check required variables
    if [ -z "$DEPLOYMENT_TYPE" ]; then
        echo "ERROR: DEPLOYMENT_TYPE is not set"
        ((errors++))
    fi

    if [ -z "$HOOKPROBE_VERSION" ]; then
        echo "ERROR: HOOKPROBE_VERSION is not set"
        ((errors++))
    fi

    # Validate deployment type
    case "$DEPLOYMENT_TYPE" in
        edge|cloud|hybrid|headless|development)
            ;;
        *)
            echo "ERROR: Invalid DEPLOYMENT_TYPE: $DEPLOYMENT_TYPE"
            echo "Valid values: edge, cloud, hybrid, headless, development"
            ((errors++))
            ;;
    esac

    # Validate network prefix
    if ! echo "$POD_NETWORK_PREFIX" | grep -Eq '^[0-9]{1,3}\.[0-9]{1,3}$'; then
        echo "ERROR: Invalid POD_NETWORK_PREFIX: $POD_NETWORK_PREFIX"
        ((errors++))
    fi

    # Check for default passwords in production
    if [ "$ENVIRONMENT" = "production" ]; then
        if [ "$POSTGRES_PASSWORD" = "changeme" ]; then
            echo "WARNING: PostgreSQL password is still default (changeme)"
        fi

        if [ "$DJANGO_SECRET_KEY" = "CHANGE-THIS-IN-PRODUCTION" ]; then
            echo "WARNING: Django secret key is still default"
        fi

        if [ "$GRAFANA_ADMIN_PASSWORD" = "changeme" ]; then
            echo "WARNING: Grafana admin password is still default"
        fi
    fi

    return $errors
}

# Display configuration summary
show_unified_config() {
    cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HookProbe Unified Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Version:          $HOOKPROBE_VERSION ($HOOKPROBE_CODENAME)
Deployment Type:  $DEPLOYMENT_TYPE
Environment:      $ENVIRONMENT
Container Runtime: $CONTAINER_RUNTIME

Network Configuration:
  Network Prefix:  $POD_NETWORK_PREFIX.x.0/24

Enabled PODs:
  POD-001 (Web DMZ):       $([ "$POD_001_ENABLED" = "true" ] && echo "✓" || echo "✗") - $POD_001_IP
  POD-002 (IAM):           $([ "$POD_002_ENABLED" = "true" ] && echo "✓" || echo "✗") - $POD_002_IP
  POD-003 (Database):      $([ "$POD_003_ENABLED" = "true" ] && echo "✓" || echo "✗") - $POD_003_IP
  POD-004 (Cache):         $([ "$POD_004_ENABLED" = "true" ] && echo "✓" || echo "✗") - $POD_004_IP
  POD-005 (Monitoring):    $([ "$POD_005_ENABLED" = "true" ] && echo "✓" || echo "✗") - $POD_005_IP
  POD-006 (Security):      $([ "$POD_006_ENABLED" = "true" ] && echo "✓" || echo "✗") - $POD_006_IP
  POD-007 (AI Response):   $([ "$POD_007_ENABLED" = "true" ] && echo "✓" || echo "✗") - $POD_007_IP
  POD-008 (Automation):    $([ "$POD_008_ENABLED" = "true" ] && echo "✓" || echo "✗") - $POD_008_IP

Features:
  Django CMS:         $([ "$FEATURE_WEB_CMS" = "true" ] && echo "✓" || echo "✗")
  Workflow Automation: $([ "$FEATURE_WORKFLOW_AUTOMATION" = "true" ] && echo "✓" || echo "✗")
  AI Detection:       $([ "$FEATURE_AI_DETECTION" = "true" ] && echo "✓" || echo "✗")
  Auto Mitigation:    $([ "$FEATURE_AUTO_MITIGATION" = "true" ] && echo "✓" || echo "✗")
  Email Alerts:       $([ "$FEATURE_EMAIL_ALERTS" = "true" ] && echo "✓" || echo "✗")

Installation Paths:
  Install Dir:  $INSTALL_DIR
  Config Dir:   $CONFIG_DIR
  Data Dir:     $DATA_DIR
  Log Dir:      $LOG_DIR

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF
}

# ============================================================================
# Export all configuration
# ============================================================================

# This function exports all configuration to a .env file
export_config_to_env() {
    local env_file="${1:-${CONFIG_DIR}/hookprobe.env}"

    cat > "$env_file" <<EOF
# HookProbe Environment Configuration
# Generated on: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Deployment Type: $DEPLOYMENT_TYPE

# Version
HOOKPROBE_VERSION=$HOOKPROBE_VERSION
DEPLOYMENT_TYPE=$DEPLOYMENT_TYPE
ENVIRONMENT=$ENVIRONMENT

# POD Networks
POD_NETWORK_PREFIX=$POD_NETWORK_PREFIX

# POD-001 (Web DMZ)
POD_001_IP=$POD_001_IP
NGINX_PORT=$NGINX_PORT
DJANGO_SECRET_KEY=$DJANGO_SECRET_KEY

# POD-002 (IAM)
POD_002_IP=$POD_002_IP
LOGTO_ENDPOINT=$LOGTO_ENDPOINT

# POD-003 (Database)
POSTGRES_HOST=$POSTGRES_HOST
POSTGRES_PORT=$POSTGRES_PORT
POSTGRES_DB=$POSTGRES_DB
POSTGRES_USER=$POSTGRES_USER
POSTGRES_PASSWORD=$POSTGRES_PASSWORD

# POD-004 (Cache)
REDIS_HOST=$REDIS_HOST
REDIS_PORT=$REDIS_PORT

# POD-005 (Monitoring)
GRAFANA_URL=$GRAFANA_URL
CLICKHOUSE_HOST=$CLICKHOUSE_HOST
CLICKHOUSE_PORT=$CLICKHOUSE_PORT

# POD-006 (Security)
QSECBIT_API_URL=$QSECBIT_API_URL

# Feature Flags
FEATURE_WEB_CMS=$FEATURE_WEB_CMS
FEATURE_WORKFLOW_AUTOMATION=$FEATURE_WORKFLOW_AUTOMATION
EOF

    chmod 600 "$env_file"
    echo "Configuration exported to: $env_file"
}

# ============================================================================
# End of Configuration
# ============================================================================

# Auto-validate if running directly (not sourced)
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    echo "Running configuration validation..."
    validate_unified_config
    show_unified_config
fi
