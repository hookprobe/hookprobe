#!/bin/bash
#
# backend-uninstall.sh
# HookProbe Mesh Cloud Backend Removal
# Version: 5.0
# License: AGPL-3.0 - see LICENSE file
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.sh"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Require root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root"
    exit 1
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "============================================================"
log "HookProbe Mesh Cloud Backend Uninstallation"
log "============================================================"

# Stop and remove containers
log "Stopping and removing containers..."

CONTAINERS=(
    "doris-fe-1" "doris-fe-2" "doris-fe-3"
    "doris-be-1" "doris-be-2" "doris-be-3"
    "hookprobe-kafka"
    "hookprobe-postgres-mgmt"
    "hookprobe-grafana-backend"
    "hookprobe-keycloak"
    "hookprobe-redis-stream"
    "hookprobe-redis-cache"
    "hookprobe-vector-backend"
    "hookprobe-nginx-backend"
)

for container in "${CONTAINERS[@]}"; do
    if podman ps -a --format "{{.Names}}" | grep -q "^${container}$"; then
        log "  → Removing container: $container"
        podman rm -f "$container" 2>/dev/null || true
    fi
done

# Remove networks
log "Removing networks..."
NETWORKS=(
    "doris-frontend-net"
    "doris-backend-net"
    "ingestion-net"
    "management-net"
)

for network in "${NETWORKS[@]}"; do
    if podman network exists "$network" 2>/dev/null; then
        log "  → Removing network: $network"
        podman network rm "$network" 2>/dev/null || true
    fi
done

# Ask about volumes
read -p "Remove all data volumes? This will DELETE all stored data! (yes/no): " -r
if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    log "Removing volumes..."

    VOLUMES=(
        "hookprobe-doris-fe-1-meta"
        "hookprobe-doris-fe-2-meta"
        "hookprobe-doris-fe-3-meta"
        "hookprobe-doris-be-1-storage"
        "hookprobe-doris-be-2-storage"
        "hookprobe-doris-be-3-storage"
        "hookprobe-kafka-data"
        "hookprobe-postgres-mgmt"
        "hookprobe-grafana-backend"
        "hookprobe-keycloak-data"
    )

    for volume in "${VOLUMES[@]}"; do
        if podman volume exists "$volume" 2>/dev/null; then
            log "  → Removing volume: $volume"
            podman volume rm "$volume" 2>/dev/null || true
        fi
    done
else
    log "Skipping volume removal (data preserved)"
fi

# Clean up storage directories
read -p "Remove storage directories? (yes/no): " -r
if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    log "Removing storage directories..."
    rm -rf /mnt/doris
    rm -rf /opt/hookprobe
    rm -rf /var/lib/hookprobe
fi

log "============================================================"
log "Uninstallation complete!"
log "============================================================"
