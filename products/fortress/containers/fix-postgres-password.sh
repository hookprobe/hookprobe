#!/bin/bash
# HookProbe Fortress - Fix PostgreSQL Password
#
# This script fixes the PostgreSQL password mismatch that can occur when
# switching from secret files to environment variables.
#
# Usage: sudo ./fix-postgres-password.sh
#
# The script will:
# 1. Check if postgres container is running
# 2. Reset the fortress user password to match the environment variable
# 3. Restart affected containers
#
# Version: 5.5.0
# License: AGPL-3.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

# Get the expected password from environment or use default
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-fortress_db_secret}"

log_info "HookProbe Fortress - PostgreSQL Password Fix"
log_info "============================================"
echo ""

# Check if postgres container is running
if ! podman ps --format "{{.Names}}" | grep -q "fts-postgres"; then
    log_error "fts-postgres container is not running"
    log_info "Start it with: podman start fts-postgres"
    exit 1
fi

log_info "Found running postgres container"
log_info "Resetting password to match environment variable..."

# Reset the password in PostgreSQL
if podman exec -i fts-postgres psql -U postgres -c "ALTER USER fortress WITH PASSWORD '${POSTGRES_PASSWORD}';" 2>/dev/null; then
    log_info "Password updated successfully"
else
    log_error "Failed to update password"
    log_warn "You may need to manually run:"
    log_warn "  podman exec -it fts-postgres psql -U postgres"
    log_warn "  ALTER USER fortress WITH PASSWORD 'fortress_db_secret';"
    exit 1
fi

# Restart web and qsecbit containers to pick up the connection
log_info "Restarting dependent containers..."

for container in fts-web fts-qsecbit; do
    if podman ps --format "{{.Names}}" | grep -q "$container"; then
        log_info "Restarting $container..."
        podman restart "$container" || log_warn "Failed to restart $container"
    else
        log_info "$container not running, skipping restart"
    fi
done

# Wait for containers to become healthy
log_info "Waiting for containers to become healthy..."
sleep 10

# Check container status
echo ""
log_info "Container Status:"
podman ps --format "table {{.Names}}\t{{.Status}}" | grep -E "^NAMES|fortress"

echo ""
log_info "Password fix complete!"
log_info ""
log_info "If web container is still unhealthy, check logs with:"
log_info "  podman logs fts-web"
