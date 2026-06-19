#!/bin/bash
# HookProbe Fortress Web Container Entrypoint
#
# Initializes the web application environment and starts gunicorn
# Version: 5.5.0

set -e

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INIT]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ============================================================
# INITIALIZATION
# ============================================================

log_info "Starting HookProbe Fortress Web Container"

# Check required environment variables
: "${FORTRESS_CONFIG_DIR:=/etc/hookprobe}"
: "${FORTRESS_DATA_DIR:=/app/data}"

# Gunicorn config: the image ships products/fortress/web/gunicorn.conf.py at
# /app/gunicorn.conf.py (the CMD points at it). Do NOT regenerate it here — a
# heredoc guarded by `[ ! -f ]` never fired (the file always exists from the
# image build), which silently shadowed the security settings. Single source of
# truth is the committed file.

# Initialize users.json if not exists.
# SECURITY: never write a hardcoded/known credential to disk. Provision the admin
# from FORTRESS_ADMIN_PASSWORD (set by install.sh) via models.ensure_admin_exists(),
# and fail closed if neither users.json nor that env var is present.
if [ ! -f "${FORTRESS_CONFIG_DIR}/users.json" ]; then
    if [ -z "${FORTRESS_ADMIN_PASSWORD:-}" ]; then
        log_error "FATAL: ${FORTRESS_CONFIG_DIR}/users.json is missing and FORTRESS_ADMIN_PASSWORD is not set."
        log_error "Provision admin credentials via install.sh (or inject FORTRESS_ADMIN_PASSWORD) before starting fts-web."
        exit 1
    fi
    log_warn "No users.json found - admin will be provisioned from FORTRESS_ADMIN_PASSWORD on first start"
    # models.ensure_admin_exists() reads FORTRESS_ADMIN_PASSWORD, enforces the
    # strong-password policy, and writes users.json with 0640 perms.
fi

# Create data directory structure
mkdir -p "${FORTRESS_DATA_DIR}"/{reports,cache,uploads} 2>/dev/null || true
mkdir -p /app/logs 2>/dev/null || true

# ============================================================
# SECRET HANDLING
# ============================================================
# Support both direct environment variables and file-based secrets
# Direct env vars take precedence over file-based ones

# Database password
if [ -z "${DATABASE_PASSWORD:-}" ] && [ -f "${DATABASE_PASSWORD_FILE:-}" ] && [ -r "${DATABASE_PASSWORD_FILE:-}" ]; then
    export DATABASE_PASSWORD=$(cat "${DATABASE_PASSWORD_FILE}")
    log_info "Loaded database password from secret file"
elif [ -n "${DATABASE_PASSWORD:-}" ]; then
    log_info "Using database password from environment"
fi

# Redis password
if [ -z "${REDIS_PASSWORD:-}" ] && [ -f "${REDIS_PASSWORD_FILE:-}" ] && [ -r "${REDIS_PASSWORD_FILE:-}" ]; then
    export REDIS_PASSWORD=$(cat "${REDIS_PASSWORD_FILE}")
    log_info "Loaded Redis password from secret file"
elif [ -n "${REDIS_PASSWORD:-}" ]; then
    log_info "Using Redis password from environment"
fi

# Flask secret key
if [ -z "${FLASK_SECRET_KEY:-}" ] && [ -f "${FLASK_SECRET_KEY_FILE:-}" ] && [ -r "${FLASK_SECRET_KEY_FILE:-}" ]; then
    export FLASK_SECRET_KEY=$(cat "${FLASK_SECRET_KEY_FILE}")
    log_info "Loaded Flask secret key from secret file"
elif [ -n "${FLASK_SECRET_KEY:-}" ]; then
    log_info "Using Flask secret key from environment"
fi

# Validate required secrets are set (no default fallbacks in production)
if [ -n "${DATABASE_HOST:-}" ] && [ -z "${DATABASE_PASSWORD:-}" ]; then
    log_error "DATABASE_PASSWORD is required but not set"
    log_error "Set it in .env or via podman secret"
    exit 1
fi
if [ -n "${REDIS_HOST:-}" ] && [ -z "${REDIS_PASSWORD:-}" ]; then
    log_error "REDIS_PASSWORD is required but not set"
    log_error "Set it in .env or via podman secret"
    exit 1
fi

# Wait for database to be ready (if using PostgreSQL)
if [ -n "${DATABASE_HOST}" ]; then
    log_info "Waiting for database at ${DATABASE_HOST}:${DATABASE_PORT:-5432}..."
    max_attempts=30
    attempt=0
    last_error=""
    while [ $attempt -lt $max_attempts ]; do
        # Try connection and capture any error
        if result=$(python3 -c "
import psycopg2
try:
    conn = psycopg2.connect(
        host='${DATABASE_HOST}',
        port='${DATABASE_PORT:-5432}',
        user='${DATABASE_USER:-fortress}',
        password='${DATABASE_PASSWORD}',
        dbname='${DATABASE_NAME:-fortress}',
        connect_timeout=5
    )
    conn.close()
    print('OK')
except Exception as e:
    print(f'ERROR: {e}')
" 2>&1); then
            if [ "$result" = "OK" ]; then
                log_info "Database is ready"
                break
            else
                last_error="$result"
            fi
        else
            last_error="$result"
        fi
        attempt=$((attempt + 1))
        if [ $((attempt % 5)) -eq 0 ]; then
            log_warn "Still waiting for database... ($attempt/$max_attempts) - $last_error"
        else
            log_info "Waiting for database... ($attempt/$max_attempts)"
        fi
        sleep 2
    done

    if [ $attempt -eq $max_attempts ]; then
        log_error "Database not available after ${max_attempts} attempts"
        log_error "Last error: $last_error"
        log_error "Check: DATABASE_HOST=${DATABASE_HOST}, DATABASE_PORT=${DATABASE_PORT:-5432}, DATABASE_USER=${DATABASE_USER:-fortress}"
        exit 1
    fi
fi

# Wait for Redis (if configured)
if [ -n "${REDIS_HOST}" ]; then
    log_info "Waiting for Redis at ${REDIS_HOST}:${REDIS_PORT:-6379}..."
    max_attempts=15
    attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if python3 -c "
import redis
r = redis.Redis(
    host='${REDIS_HOST}',
    port=${REDIS_PORT:-6379},
    password='${REDIS_PASSWORD}',
    socket_connect_timeout=3
)
r.ping()
print('OK')
" 2>/dev/null; then
            log_info "Redis is ready"
            break
        fi
        attempt=$((attempt + 1))
        if [ $((attempt % 5)) -eq 0 ]; then
            log_warn "Still waiting for Redis... ($attempt/$max_attempts)"
        fi
        sleep 1
    done

    if [ $attempt -eq $max_attempts ]; then
        log_warn "Redis not available after ${max_attempts} attempts - continuing anyway"
    fi
fi

log_info "Initialization complete"

# ============================================================
# START APPLICATION
# ============================================================

exec "$@"
