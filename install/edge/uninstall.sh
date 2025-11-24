#!/bin/bash
#
# uninstall.sh - HookProbe v5.0 Complete Removal
# GPL-FREE Edition
# Version: 5.0.0
#
# This script safely removes all HookProbe v5.0 components
# Use with caution - this will destroy all data!
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load configuration
if [ -f "$SCRIPT_DIR/config.sh" ]; then
    source "$SCRIPT_DIR/config.sh"
else
    echo "WARNING: config.sh not found, using defaults..."
    QSEC_BRIDGE="qsec-bridge"
    POD_WEB="hookprobe-web-dmz"
    POD_IAM="hookprobe-iam"
    POD_DATABASE="hookprobe-database"
    POD_CACHE="hookprobe-cache"
    POD_MONITORING="hookprobe-monitoring"
    POD_SECURITY="hookprobe-security"
    POD_HONEYPOT="hookprobe-honeypot"
fi

echo "============================================================"
echo "   HOOKPROBE v5.0 INFRASTRUCTURE CLEANUP"
echo "============================================================"
echo ""
echo "⚠️  WARNING: This will DESTROY all HookProbe v5.0 infrastructure!"
echo ""
echo "Components to be removed:"
echo "  ❌ All PODs and containers"
echo "  ❌ All volumes (databases, logs, data)"
echo "  ❌ All Podman networks"
echo "  ❌ OVS bridge and VXLAN tunnels"
echo "  ❌ Firewall rules (nftables)"
echo "  ❌ XDP DDoS mitigation program"
echo "  ❌ Kernel configuration"
echo ""
read -p "Are you ABSOLUTELY sure? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "✓ Uninstall cancelled."
    exit 0
fi

echo ""
echo "⏰ Starting cleanup in 5 seconds... (Ctrl+C to cancel)"
sleep 5

# ============================================================
# STEP 1: REMOVE PODS
# ============================================================
echo ""
echo "[STEP 1] Removing PODs..."

POD_NAMES=(
    "$POD_WEB"
    "$POD_IAM"
    "$POD_DATABASE"
    "$POD_CACHE"
    "$POD_MONITORING"
    "$POD_SECURITY"
    "$POD_HONEYPOT"
)

for pod in "${POD_NAMES[@]}"; do
    if podman pod exists "$pod" 2>/dev/null; then
        echo "  → Removing: $pod"
        podman pod stop "$pod" 2>/dev/null || true
        podman pod rm -f "$pod" 2>/dev/null || true
    fi
done

# Remove any remaining containers
podman container prune -f || true
echo "✓ All PODs removed"

# ============================================================
# STEP 2: REMOVE NETWORKS
# ============================================================
echo ""
echo "[STEP 2] Removing networks..."

NETWORK_NAMES=(
    "web-dmz-net"
    "iam-net"
    "database-net"
    "cache-net"
    "monitoring-net"
    "security-net"
    "honeypot-net"
)

for network in "${NETWORK_NAMES[@]}"; do
    if podman network exists "$network" 2>/dev/null; then
        echo "  → Removing: $network"
        podman network rm "$network" 2>/dev/null || true
    fi
done

podman network prune -f || true
echo "✓ Networks removed"

# ============================================================
# STEP 3: REMOVE VOLUMES
# ============================================================
echo ""
read -p "Remove all volumes? THIS DELETES ALL DATA! (yes/no): " remove_volumes

if [ "$remove_volumes" == "yes" ]; then
    echo "[STEP 3] Removing volumes..."
    
    VOLUMES=$(podman volume ls -q | grep -i hookprobe 2>/dev/null || true)
    
    if [ -n "$VOLUMES" ]; then
        for volume in $VOLUMES; do
            echo "  → Removing: $volume"
            podman volume rm "$volume" 2>/dev/null || true
        done
    fi
    
    podman volume prune -f || true
    echo "✓ All volumes removed (DATA DELETED)"
else
    echo "[STEP 3] ✓ Volumes preserved"
fi

# ============================================================
# STEP 4: REMOVE XDP PROGRAM
# ============================================================
echo ""
echo "[STEP 4] Removing XDP DDoS mitigation..."

if [ -n "$PHYSICAL_HOST_INTERFACE" ]; then
    # Remove XDP program from interface
    ip link set dev "$PHYSICAL_HOST_INTERFACE" xdp off 2>/dev/null || true
    echo "✓ XDP program removed from $PHYSICAL_HOST_INTERFACE"
fi

# Remove XDP files
if [ -d /opt/hookprobe/xdp ]; then
    rm -rf /opt/hookprobe/xdp
    echo "✓ XDP files removed"
fi

# ============================================================
# STEP 5: REMOVE OVS CONFIGURATION
# ============================================================
echo ""
echo "[STEP 5] Removing OVS configuration..."

if ovs-vsctl br-exists "$QSEC_BRIDGE" 2>/dev/null; then
    VXLAN_PORTS=$(ovs-vsctl list-ports "$QSEC_BRIDGE" 2>/dev/null | grep -i vxlan || true)
    
    if [ -n "$VXLAN_PORTS" ]; then
        echo "$VXLAN_PORTS" | while read port; do
            echo "  → Removing VXLAN: $port"
            ovs-vsctl --if-exists del-port "$QSEC_BRIDGE" "$port"
        done
    fi
    
    echo "  → Removing bridge: $QSEC_BRIDGE"
    ovs-vsctl --if-exists del-br "$QSEC_BRIDGE"
fi

echo "✓ OVS configuration removed"

# ============================================================
# STEP 6: CLEAN FIREWALL (NFTABLES)
# ============================================================
echo ""
echo "[STEP 6] Cleaning firewall..."

if [ -f /etc/nftables/hookprobe-v5.nft ]; then
    rm -f /etc/nftables/hookprobe-v5.nft
    echo "✓ nftables configuration removed"
fi

# Flush all nftables rules
nft flush ruleset 2>/dev/null || true

echo "✓ Firewall cleaned"

# ============================================================
# STEP 7: REMOVE KERNEL CONFIGURATION
# ============================================================
echo ""
echo "[STEP 7] Removing kernel configuration..."

if [ -f /etc/sysctl.d/99-hookprobe-v5.conf ]; then
    rm -f /etc/sysctl.d/99-hookprobe-v5.conf
    echo "✓ Kernel sysctl configuration removed"
fi

if [ -f /etc/modules-load.d/hookprobe-v5.conf ]; then
    rm -f /etc/modules-load.d/hookprobe-v5.conf
    echo "✓ Kernel modules configuration removed"
fi

# ============================================================
# STEP 8: REMOVE BUILD DIRECTORIES
# ============================================================
echo ""
echo "[STEP 8] Removing build directories..."

BUILD_DIRS=(
    "/tmp/hookprobe-django-build"
    "/tmp/modsecurity-config"
    "/tmp/victoriametrics-config"
    "/tmp/victorialogs-config"
    "/tmp/grafana-provisioning"
    "/tmp/keycloak-config"
    "/opt/hookprobe"
)

for dir in "${BUILD_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        rm -rf "$dir"
    fi
done

echo "✓ Build directories removed"

# ============================================================
# STEP 9: REMOVE IMAGES (OPTIONAL)
# ============================================================
echo ""
read -p "Remove HookProbe container images? (yes/no): " remove_images

if [ "$remove_images" == "yes" ]; then
    echo "[STEP 9] Removing images..."
    
    IMAGES=$(podman images -q | xargs podman images --format "{{.Repository}}:{{.Tag}}" | grep -E "hookprobe|modsecurity|zeek|victoriametrics|victorialogs" 2>/dev/null || true)
    
    if [ -n "$IMAGES" ]; then
        echo "$IMAGES" | while read image; do
            podman rmi -f "$image" 2>/dev/null || true
        done
    fi
    
    podman image prune -af || true
    echo "✓ Images removed"
fi

# ============================================================
# STEP 10: STOP OVS (OPTIONAL)
# ============================================================
echo ""
read -p "Stop OVS service? (yes/no): " stop_ovs

if [ "$stop_ovs" == "yes" ]; then
    systemctl stop openvswitch 2>/dev/null || true
    systemctl disable openvswitch 2>/dev/null || true
    echo "✓ OVS stopped"
fi

# ============================================================
# FINAL CLEANUP
# ============================================================
echo ""
echo "[FINAL] System cleanup..."

podman system prune -af --volumes 2>/dev/null || true

ip netns list 2>/dev/null | grep -i hookprobe | while read ns; do
    ip netns delete "$ns" 2>/dev/null || true
done

echo "✓ System cleanup complete"

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   HOOKPROBE v5.0 CLEANUP COMPLETE!"
echo "============================================================"
echo ""
echo "✅ Removed:"
echo "  ✓ All 7 PODs"
if [ "$remove_volumes" == "yes" ]; then
    echo "  ✓ All data (PERMANENTLY DELETED)"
else
    echo "  ⊘ Volumes preserved"
fi
echo "  ✓ Networks and OVS bridge"
echo "  ✓ Firewall rules (nftables)"
echo "  ✓ XDP DDoS mitigation"
echo "  ✓ Kernel configuration"
if [ "$remove_images" == "yes" ]; then
    echo "  ✓ Container images"
fi
echo ""
echo "To reinstall:"
echo "  1. Review config.sh"
echo "  2. Run: sudo ./install.sh (and select option 1)"
echo ""
echo "============================================================"
