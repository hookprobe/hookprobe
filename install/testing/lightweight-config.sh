#!/bin/bash
#
# lightweight-config.sh - Configuration for HookProbe Lightweight Testing Setup
# Version: 5.0
#
# This file defines all configuration variables for the lightweight testing environment
# Optimized for Raspberry Pi 4B and resource-constrained devices (2-8GB RAM)
#

# ============================================================
# VOLUME NAMES (Podman/Docker Volumes)
# ============================================================

VOLUME_POSTGRES_DATA="hookprobe-postgres-test"
VOLUME_DJANGO_STATIC="hookprobe-django-static-test"
VOLUME_DJANGO_MEDIA="hookprobe-django-media-test"
VOLUME_VICTORIAMETRICS_DATA="hookprobe-victoriametrics-test"
VOLUME_GRAFANA_DATA="hookprobe-grafana-test"
VOLUME_QSECBIT_DATA="hookprobe-qsecbit-test"

# ============================================================
# CONTAINER/POD NAMES
# ============================================================

POD_WEB="hookprobe-web-test"
POD_DATABASE="hookprobe-database-test"
POD_MONITORING="hookprobe-monitoring-test"

# ============================================================
# NETWORK NAMES
# ============================================================

NETWORK_NAME="hookprobe-test-net"

# ============================================================
# PORT MAPPINGS
# ============================================================

PORT_HTTP=8000
PORT_HTTPS=8443
PORT_POSTGRES=5432
PORT_GRAFANA=3000
PORT_VICTORIAMETRICS=8428

# ============================================================
# INSTALLATION MODE
# ============================================================

# Options: minimal, standard, full
INSTALL_MODE="minimal"

# ============================================================
# CONTAINER IMAGES
# ============================================================

IMAGE_POSTGRES="docker.io/library/postgres:16-alpine"
IMAGE_PYTHON="docker.io/library/python:3.11-slim"
IMAGE_GRAFANA="docker.io/grafana/grafana:latest"
IMAGE_VICTORIAMETRICS="docker.io/victoriametrics/victoria-metrics:latest"

# ============================================================
# DATABASE CONFIGURATION
# ============================================================

POSTGRES_DB="hookprobe"
POSTGRES_USER="hookprobe"
# Generate secure password if not set
if [ -z "${POSTGRES_PASSWORD:-}" ]; then
    POSTGRES_PASSWORD=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)
fi

# ============================================================
# DJANGO CONFIGURATION
# ============================================================

# Generate Django secret key if not set
if [ -z "${DJANGO_SECRET_KEY:-}" ]; then
    DJANGO_SECRET_KEY=$(openssl rand -base64 64 2>/dev/null || head -c 64 /dev/urandom | base64)
fi

DJANGO_DEBUG="True"
ALLOWED_HOSTS="localhost,127.0.0.1,0.0.0.0"
DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}"

# ============================================================
# GRAFANA CONFIGURATION
# ============================================================

GRAFANA_ADMIN_USER="admin"
GRAFANA_ADMIN_PASSWORD="admin"

# ============================================================
# HELPER FUNCTIONS
# ============================================================

validate_lightweight_config() {
    local errors=0

    # Check required variables are defined
    local required_vars=(
        "VOLUME_POSTGRES_DATA"
        "VOLUME_GRAFANA_DATA"
        "VOLUME_VICTORIAMETRICS_DATA"
        "POD_DATABASE"
        "NETWORK_NAME"
        "POSTGRES_PASSWORD"
        "DJANGO_SECRET_KEY"
    )

    for var in "${required_vars[@]}"; do
        if [ -z "${!var:-}" ]; then
            echo "ERROR: Required variable $var is not defined"
            errors=$((errors + 1))
        fi
    done

    if [ $errors -gt 0 ]; then
        echo "ERROR: Configuration validation failed with $errors errors"
        return 1
    fi

    return 0
}

# Export all variables for use in other scripts
export VOLUME_POSTGRES_DATA VOLUME_DJANGO_STATIC VOLUME_DJANGO_MEDIA
export VOLUME_VICTORIAMETRICS_DATA VOLUME_GRAFANA_DATA VOLUME_QSECBIT_DATA
export POD_WEB POD_DATABASE POD_MONITORING
export NETWORK_NAME
export PORT_HTTP PORT_HTTPS PORT_POSTGRES PORT_GRAFANA PORT_VICTORIAMETRICS
export INSTALL_MODE
export IMAGE_POSTGRES IMAGE_PYTHON IMAGE_GRAFANA IMAGE_VICTORIAMETRICS
export POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD
export DJANGO_SECRET_KEY DJANGO_DEBUG ALLOWED_HOSTS DATABASE_URL
export GRAFANA_ADMIN_USER GRAFANA_ADMIN_PASSWORD

echo "✓ Lightweight configuration loaded"
