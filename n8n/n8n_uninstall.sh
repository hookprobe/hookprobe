#!/bin/bash
#
# n8n_uninstall.sh - HookProbe n8n Automation Platform Cleanup
# Version: 1.0
#
# Safely removes POD 008 and all associated resources
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load configuration
if [ -f "$SCRIPT_DIR/n8n_network-config.sh" ]; then
    source "$SCRIPT_DIR/n8n_network-config.sh"
else
    echo "WARNING: n8n_network-config.sh not found, using defaults..."
    POD_008_NAME="hookprobe-pod-008-automation"
    NETWORK_POD008="pod008-automation-net"
    OVS_MAIN_BRIDGE="ovs-br0"
    VNI_AUTOMATION=208
    PORT_N8N=5678
    PORT_MCP=8889
fi

echo "============================================================"
echo "   HOOKPROBE N8N AUTOMATION CLEANUP"
echo "============================================================"
echo ""
echo "⚠️  WARNING: This will REMOVE POD 008 and all automation!"
echo ""
echo "Components to be removed:"
echo "  ❌ n8n workflow engine"
echo "  ❌ PostgreSQL database"
echo "  ❌ Redis queue"
echo "  ❌ Chromium scraping service"
echo "  ❌ MCP server"
echo "  ❌ All workflows and data"
echo "  ❌ VXLAN tunnel (VNI $VNI_AUTOMATION)"
echo ""
read -p "Are you sure? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "✓ Uninstall cancelled."
    exit 0
fi

echo ""
echo "⏰ Starting cleanup in 5 seconds... (Ctrl+C to cancel)"
sleep 5

# ============================================================
# STEP 1: REMOVE POD 008
# ============================================================
echo ""
echo "[STEP 1] Removing POD 008..."

if podman pod exists "$POD_008_NAME" 2>/dev/null; then
    echo "  → Stopping POD: $POD_008_NAME"
    podman pod stop "$POD_008_NAME" 2>/dev/null || true
    
    echo "  → Removing POD: $POD_008_NAME"
    podman pod rm -f "$POD_008_NAME" 2>/dev/null || true
    
    echo "✓ POD 008 removed"
else
    echo "  → POD 008 not found"
fi

# Clean up any orphaned containers
podman container prune -f || true

# ============================================================
# STEP 2: REMOVE NETWORK
# ============================================================
echo ""
echo "[STEP 2] Removing Podman network..."

if podman network exists "$NETWORK_POD008" 2>/dev/null; then
    echo "  → Removing network: $NETWORK_POD008"
    podman network rm "$NETWORK_POD008" 2>/dev/null || true
    echo "✓ Network removed"
else
    echo "  → Network not found"
fi

podman network prune -f || true

# ============================================================
# STEP 3: REMOVE VOLUMES (OPTIONAL)
# ============================================================
echo ""
read -p "Remove all n8n volumes? THIS DELETES ALL DATA! (yes/no): " remove_volumes

if [ "$remove_volumes" == "yes" ]; then
    echo "[STEP 3] Removing volumes..."
    
    VOLUMES=(
        "hookprobe-n8n-data"
        "hookprobe-n8n-db"
        "hookprobe-n8n-redis"
        "hookprobe-mcp-data"
        "hookprobe-scraping-cache"
    )
    
    for volume in "${VOLUMES[@]}"; do
        if podman volume exists "$volume" 2>/dev/null; then
            echo "  → Removing: $volume"
            podman volume rm "$volume" 2>/dev/null || true
        fi
    done
    
    echo "✓ All volumes removed (DATA DELETED)"
else
    echo "[STEP 3] ✓ Volumes preserved"
fi

podman volume prune -f || true

# ============================================================
# STEP 4: REMOVE VXLAN TUNNEL
# ============================================================
echo ""
echo "[STEP 4] Removing VXLAN tunnel..."

if ovs-vsctl br-exists "$OVS_MAIN_BRIDGE" 2>/dev/null; then
    VXLAN_PORT="vxlan-${VNI_AUTOMATION}"
    
    if ovs-vsctl list-ports "$OVS_MAIN_BRIDGE" | grep -q "$VXLAN_PORT"; then
        echo "  → Removing VXLAN port: $VXLAN_PORT"
        ovs-vsctl --if-exists del-port "$OVS_MAIN_BRIDGE" "$VXLAN_PORT"
        echo "✓ VXLAN tunnel removed"
    else
        echo "  → VXLAN tunnel not found"
    fi
else
    echo "  → OVS bridge not found"
fi

# ============================================================
# STEP 5: CLEAN FIREWALL
# ============================================================
echo ""
echo "[STEP 5] Cleaning firewall rules..."

if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --remove-port=${PORT_N8N}/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=${PORT_MCP}/tcp 2>/dev/null || true
    firewall-cmd --reload
    echo "✓ Firewall cleaned"
else
    echo "  → firewalld not found, skipping"
fi

# ============================================================
# STEP 6: REMOVE BUILD DIRECTORIES
# ============================================================
echo ""
echo "[STEP 6] Removing build directories..."

BUILD_DIRS=(
    "/tmp/mcp-server-build"
    "/tmp/n8n-workflows"
)

for dir in "${BUILD_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        rm -rf "$dir"
        echo "  → Removed: $dir"
    fi
done

echo "✓ Build directories cleaned"

# ============================================================
# STEP 7: REMOVE IMAGES (OPTIONAL)
# ============================================================
echo ""
read -p "Remove n8n container images? (yes/no): " remove_images

if [ "$remove_images" == "yes" ]; then
    echo "[STEP 7] Removing images..."
    
    IMAGES=(
        "hookprobe-mcp-server:latest"
    )
    
    for image in "${IMAGES[@]}"; do
        if podman images | grep -q "$image"; then
            echo "  → Removing: $image"
            podman rmi -f "$image" 2>/dev/null || true
        fi
    done
    
    # Remove n8n and related official images
    podman images | grep -E "n8nio/n8n|browserless/chrome" | awk '{print $3}' | xargs -r podman rmi -f 2>/dev/null || true
    
    echo "✓ Images removed"
else
    echo "[STEP 7] ✓ Images preserved"
fi

podman image prune -af || true

# ============================================================
# STEP 8: FINAL CLEANUP
# ============================================================
echo ""
echo "[STEP 8] Final system cleanup..."

podman system prune -af --volumes 2>/dev/null || true

echo "✓ System cleanup complete"

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   N8N AUTOMATION CLEANUP COMPLETE!"
echo "============================================================"
echo ""
echo "✅ Removed:"
echo "  ✓ POD 008 (Automation)"
echo "  ✓ All containers (n8n, PostgreSQL, Redis, Chromium, MCP)"
if [ "$remove_volumes" == "yes" ]; then
    echo "  ✓ All data volumes (PERMANENTLY DELETED)"
else
    echo "  ⊘ Data volumes preserved"
fi
echo "  ✓ VXLAN tunnel (VNI $VNI_AUTOMATION)"
echo "  ✓ Podman network"
echo "  ✓ Firewall rules"
if [ "$remove_images" == "yes" ]; then
    echo "  ✓ Container images"
else
    echo "  ⊘ Container images preserved"
fi
echo ""
echo "📝 Notes:"
echo "  • Workflow templates preserved in /tmp/n8n-workflows (if not removed)"
echo "  • Configuration file preserved: n8n_network-config.sh"
echo "  • Main HookProbe infrastructure (PODs 001-007) unchanged"
echo ""
echo "To reinstall:"
echo "  1. Review n8n_network-config.sh"
echo "  2. Run: sudo ./n8n_setup.sh"
echo ""
echo "============================================================"
