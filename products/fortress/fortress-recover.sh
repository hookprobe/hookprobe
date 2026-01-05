#!/bin/bash
# Fortress Network Recovery Script
# Fixes podman container networking issues
# Run as root: sudo ./fortress-recover.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ok() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; }
info() { echo -e "${BLUE}ℹ${NC} $1"; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          FORTRESS NETWORK RECOVERY v1.0                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"

if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root (sudo)"
    exit 1
fi

# Step 1: Stop all services
header "STOPPING ALL SERVICES"

info "Stopping fortress service..."
systemctl stop fortress 2>/dev/null || true

info "Stopping AIOCHI service (if running)..."
systemctl stop fortress-aiochi 2>/dev/null || true

# Give containers time to stop
sleep 3

# Step 2: Force remove all fortress containers
header "REMOVING CONTAINERS"

info "Removing all fts-* containers..."
for container in $(podman ps -a --format "{{.Names}}" 2>/dev/null | grep "^fts-" || true); do
    info "  Removing $container..."
    podman stop -t 2 "$container" 2>/dev/null || true
    podman rm -f "$container" 2>/dev/null || true
done

info "Removing all aiochi-* containers..."
for container in $(podman ps -a --format "{{.Names}}" 2>/dev/null | grep "^aiochi-" || true); do
    info "  Removing $container..."
    podman stop -t 2 "$container" 2>/dev/null || true
    podman rm -f "$container" 2>/dev/null || true
done

# Step 3: Clean up podman state
header "CLEANING PODMAN STATE"

# Check for zombie containers
zombies=$(podman ps -a --format "{{.Names}}" 2>/dev/null | wc -l)
if [ "$zombies" -gt 0 ]; then
    warn "Found $zombies containers still present, forcing cleanup..."
    podman container prune -f 2>/dev/null || true
fi

# Step 4: Remove and recreate networks
header "RECREATING NETWORKS"

# Remove all fortress-related networks
info "Removing existing networks..."
for network in containers_fts-internal fts-internal aiochi-internal containers_aiochi-internal; do
    if podman network exists "$network" 2>/dev/null; then
        info "  Removing network: $network"
        podman network rm -f "$network" 2>/dev/null || true
    fi
done

# Create the fortress container network
info "Creating containers_fts-internal network..."
if podman network create --driver bridge \
    --subnet 172.20.200.0/24 \
    --gateway 172.20.200.1 \
    containers_fts-internal 2>/dev/null; then
    ok "Network containers_fts-internal created"
else
    warn "Network creation returned error (may already exist)"
fi

# Verify network exists
if podman network exists containers_fts-internal 2>/dev/null; then
    ok "Network containers_fts-internal is ready"
    podman network inspect containers_fts-internal 2>/dev/null | grep -E "subnet|gateway" | head -4
else
    fail "Failed to create network!"
    exit 1
fi

# Step 5: Verify OVS bridge
header "CHECKING OVS BRIDGE"

if ovs-vsctl br-exists FTS 2>/dev/null; then
    ok "FTS bridge exists"
    ip link set FTS up 2>/dev/null || true
else
    warn "FTS bridge not found - will be created on service start"
fi

# Step 6: Update systemd service (if needed)
header "UPDATING SYSTEMD SERVICE"

# Check if service file needs the network pre-check
SERVICE_FILE="/etc/systemd/system/fortress.service"
if [ -f "$SERVICE_FILE" ]; then
    if grep -q "containers_fts-internal" "$SERVICE_FILE"; then
        ok "Service already has network pre-check"
    else
        info "Service file may need update - consider reinstalling"
        info "  Or run: sudo ./install.sh --quick"
    fi
fi

# Reload systemd
systemctl daemon-reload

# Step 7: Reset service failure state
header "RESETTING SERVICE STATE"

systemctl reset-failed fortress 2>/dev/null || true
systemctl reset-failed fortress-aiochi 2>/dev/null || true

# Step 8: Restart services
header "RESTARTING SERVICES"

# Check if AIOCHI is enabled
AIOCHI_ENABLED="false"
if [ -f /etc/hookprobe/fortress.conf ]; then
    if grep -q "INSTALL_AIOCHI=true" /etc/hookprobe/fortress.conf 2>/dev/null; then
        AIOCHI_ENABLED="true"
    fi
fi

info "Starting fortress service..."
systemctl start fortress

# Wait for containers to start
info "Waiting for containers to start (30 seconds)..."
sleep 30

# Step 9: Verify containers
header "VERIFYING CONTAINERS"

expected_containers="fts-postgres fts-redis fts-web fts-qsecbit fts-dnsxai fts-dfs fts-bubble-manager"
all_ok=true

for container in $expected_containers; do
    status=$(podman inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "not found")
    if [ "$status" = "running" ]; then
        ok "$container: running"
    else
        fail "$container: $status"
        all_ok=false
    fi
done

# Check web container network
header "CHECKING CONTAINER NETWORK"

web_eth0=$(podman exec fts-web ip addr show eth0 2>/dev/null | grep "inet " || echo "")
if [ -n "$web_eth0" ]; then
    ok "fts-web has eth0 interface"
    echo "    $web_eth0"
else
    fail "fts-web missing eth0 interface!"
    info "Debugging network..."
    podman exec fts-web ip addr 2>/dev/null || true
fi

# Step 10: Test web UI
header "TESTING WEB UI"

WEB_PORT=$(grep "^WEB_PORT=" /etc/hookprobe/fortress.conf 2>/dev/null | cut -d= -f2 || echo "8443")

# Test via localhost first (container port mapping)
if curl -sk "https://127.0.0.1:${WEB_PORT}/health" --max-time 5 2>/dev/null | grep -q "healthy"; then
    ok "Web UI responding on localhost:${WEB_PORT}"
else
    warn "Web UI not responding on localhost - checking container health..."
    if podman exec fts-web curl -sk "https://127.0.0.1:${WEB_PORT}/health" --max-time 5 2>/dev/null | grep -q "healthy"; then
        ok "Web UI responding inside container"
        warn "Port mapping issue - checking podman port configuration..."
        podman port fts-web 2>/dev/null || true
    else
        fail "Web UI not responding"
    fi
fi

# Summary
header "RECOVERY COMPLETE"

if [ "$all_ok" = "true" ]; then
    echo ""
    ok "All core containers are running!"
    echo ""
    info "Access web UI at:"
    info "  https://<fortress-ip>:${WEB_PORT}"
    echo ""
    info "From MGMT VLAN: https://10.200.100.1:${WEB_PORT}"
    info "From LAN:       https://10.200.0.1:${WEB_PORT}"
else
    echo ""
    warn "Some containers failed to start. Check logs:"
    echo ""
    info "  sudo podman logs fts-postgres"
    info "  sudo podman logs fts-web"
    info "  sudo journalctl -u fortress -f"
fi

if [ "$AIOCHI_ENABLED" = "true" ]; then
    echo ""
    info "AIOCHI is enabled. Start with:"
    info "  sudo systemctl start fortress-aiochi"
fi

echo ""
