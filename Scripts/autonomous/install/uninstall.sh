#!/bin/bash
#
# uninstall.sh - Complete cleanup of HookProbe infrastructure
#
# This script removes all PODs, networks, volumes, and OVS configuration
# Use with caution - this will destroy all data!
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load network configuration if available
if [ -f "$SCRIPT_DIR/network-config.sh" ]; then
    source "$SCRIPT_DIR/network-config.sh"
else
    echo "WARNING: network-config.sh not found, using defaults..."
    # Set defaults
    POD_001_NAME="hookprobe-pod-001-web-dmz"
    POD_002_NAME="hookprobe-pod-002-app"
    POD_003_NAME="hookprobe-pod-003-db-persistent"
    POD_004_NAME="hookprobe-pod-004-db-transient"
    POD_005_NAME="hookprobe-pod-005-monitoring"
    POD_006_NAME="hookprobe-pod-006-security"
    
    NETWORK_POD001="pod001-dmz-net"
    NETWORK_POD002="pod002-app-net"
    NETWORK_POD003="pod003-db-persistent-net"
    NETWORK_POD004="pod004-db-transient-net"
    NETWORK_POD005="pod005-monitoring-net"
    NETWORK_POD006="pod006-security-net"
    
    OVS_MAIN_BRIDGE="ovs-br0"
    OVS_DMZ_BRIDGE="ovs-br-dmz"
    OVS_INTERNAL_BRIDGE="ovs-br-internal"
fi

echo "============================================================"
echo "   HOOKPROBE INFRASTRUCTURE CLEANUP"
echo "============================================================"
echo ""
echo "⚠  WARNING: This will DESTROY all HookProbe infrastructure!"
echo "   - All containers and pods"
echo "   - All volumes (INCLUDING DATABASES)"
echo "   - All networks"
echo "   - All OVS configuration"
echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Uninstall cancelled."
    exit 0
fi

echo ""
echo "Starting cleanup in 5 seconds... (Press Ctrl+C to cancel)"
sleep 5

# ============================================================
# STEP 1: STOP AND REMOVE ALL PODS
# ============================================================
echo ""
echo "[STEP 1] Removing PODs and containers..."

POD_NAMES=(
    "$POD_001_NAME"
    "$POD_002_NAME"
    "$POD_003_NAME"
    "$POD_004_NAME"
    "$POD_005_NAME"
    "$POD_006_NAME"
)

for pod in "${POD_NAMES[@]}"; do
    if podman pod exists "$pod" 2>/dev/null; then
        echo "  → Removing pod: $pod"
        podman pod rm -f "$pod" || true
    fi
done

# Remove any orphaned containers
echo "  → Cleaning up orphaned containers..."
podman container prune -f || true

echo "✓ All PODs removed"

# ============================================================
# STEP 2: REMOVE PODMAN NETWORKS
# ============================================================
echo ""
echo "[STEP 2] Removing Podman networks..."

NETWORK_NAMES=(
    "$NETWORK_POD001"
    "$NETWORK_POD002"
    "$NETWORK_POD003"
    "$NETWORK_POD004"
    "$NETWORK_POD005"
    "$NETWORK_POD006"
)

for network in "${NETWORK_NAMES[@]}"; do
    if podman network exists "$network" 2>/dev/null; then
        echo "  → Removing network: $network"
        podman network rm "$network" || true
    fi
done

# Prune unused networks
podman network prune -f || true

echo "✓ All networks removed"

# ============================================================
# STEP 3: REMOVE VOLUMES (OPTIONAL - DATA LOSS!)
# ============================================================
echo ""
read -p "Do you want to remove ALL volumes (THIS WILL DELETE ALL DATA)? (yes/no): " remove_volumes

if [ "$remove_volumes" == "yes" ]; then
    echo "[STEP 3] Removing volumes..."
    
    # List all hookprobe volumes
    VOLUMES=$(podman volume ls -q | grep -i hookprobe || true)
    
    if [ -n "$VOLUMES" ]; then
        for volume in $VOLUMES; do
            echo "  → Removing volume: $volume"
            podman volume rm "$volume" || true
        done
    fi
    
    # Prune all unused volumes
    podman volume prune -f || true
    
    echo "✓ All volumes removed"
else
    echo "[STEP 3] Skipping volume removal (data preserved)"
fi

# ============================================================
# STEP 4: REMOVE OVS CONFIGURATION
# ============================================================
echo ""
echo "[STEP 4] Removing Open vSwitch configuration..."

# List all VXLAN ports and remove them
echo "  → Removing VXLAN tunnels..."
VXLAN_PORTS=$(ovs-vsctl list-ports "$OVS_MAIN_BRIDGE" 2>/dev/null | grep -i vxlan || true)

if [ -n "$VXLAN_PORTS" ]; then
    for port in $VXLAN_PORTS; do
        echo "    • Removing VXLAN port: $port"
        ovs-vsctl --if-exists del-port "$OVS_MAIN_BRIDGE" "$port"
    done
fi

# Remove OVS bridges
echo "  → Removing OVS bridges..."
for bridge in "$OVS_MAIN_BRIDGE" "$OVS_DMZ_BRIDGE" "$OVS_INTERNAL_BRIDGE"; do
    if ovs-vsctl br-exists "$bridge" 2>/dev/null; then
        echo "    • Removing bridge: $bridge"
        ovs-vsctl --if-exists del-br "$bridge"
    fi
done

echo "✓ OVS configuration removed"

# ============================================================
# STEP 5: CLEAN FIREWALL RULES
# ============================================================
echo ""
echo "[STEP 5] Cleaning firewall rules..."

if command -v firewall-cmd &> /dev/null; then
    echo "  → Removing HookProbe firewall rules..."
    
    # Remove custom ports
    firewall-cmd --permanent --remove-port=4789/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=500/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=4500/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=9090/tcp 2>/dev/null || true
    
    # Remove rich rules
    firewall-cmd --permanent --remove-rich-rule='rule family="ipv4" source address="10.100.0.0/16" accept' 2>/dev/null || true
    
    firewall-cmd --reload
    
    echo "✓ Firewall rules cleaned"
else
    echo "  ⚠ firewalld not found, skipping"
fi

# ============================================================
# STEP 6: REMOVE BUILD DIRECTORIES
# ============================================================
echo ""
echo "[STEP 6] Removing temporary build directories..."

BUILD_DIRS=(
    "/tmp/hookprobe-django-build"
    "/tmp/nginx-hookprobe"
)

for dir in "${BUILD_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "  → Removing: $dir"
        rm -rf "$dir"
    fi
done

echo "✓ Build directories removed"

# ============================================================
# STEP 7: REMOVE CONTAINER IMAGES (OPTIONAL)
# ============================================================
echo ""
read -p "Do you want to remove HookProbe container images? (yes/no): " remove_images

if [ "$remove_images" == "yes" ]; then
    echo "[STEP 7] Removing container images..."
    
    # Remove HookProbe images
    IMAGES=$(podman images -q hookprobe-django 2>/dev/null || true)
    
    if [ -n "$IMAGES" ]; then
        for image in $IMAGES; do
            echo "  → Removing image: $image"
            podman rmi -f "$image" || true
        done
    fi
    
    # Prune unused images
    podman image prune -f || true
    
    echo "✓ Container images removed"
else
    echo "[STEP 7] Skipping image removal"
fi

# ============================================================
# STEP 8: STOP OVS SERVICE (OPTIONAL)
# ============================================================
echo ""
read -p "Do you want to stop the OVS service? (yes/no): " stop_ovs

if [ "$stop_ovs" == "yes" ]; then
    echo "[STEP 8] Stopping Open vSwitch service..."
    systemctl stop openvswitch
    systemctl disable openvswitch
    echo "✓ OVS service stopped"
else
    echo "[STEP 8] OVS service left running"
fi

# ============================================================
# STEP 9: REMOVE KERNEL MODULE CONFIGURATION
# ============================================================
echo ""
read -p "Do you want to remove kernel module configuration? (yes/no): " remove_modules

if [ "$remove_modules" == "yes" ]; then
    echo "[STEP 9] Removing kernel module configuration..."
    
    if [ -f /etc/modules-load.d/hookprobe.conf ]; then
        rm -f /etc/modules-load.d/hookprobe.conf
        echo "✓ Kernel module configuration removed"
    fi
else
    echo "[STEP 9] Kernel module configuration preserved"
fi

# ============================================================
# FINAL SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   HOOKPROBE CLEANUP COMPLETE!"
echo "============================================================"
echo ""
echo "Removed:"
echo "  ✓ All PODs and containers"
echo "  ✓ All Podman networks"

if [ "$remove_volumes" == "yes" ]; then
    echo "  ✓ All volumes and data"
else
    echo "  ⊘ Volumes preserved"
fi

echo "  ✓ OVS bridges and VXLAN tunnels"
echo "  ✓ Firewall rules"
echo "  ✓ Temporary build directories"

if [ "$remove_images" == "yes" ]; then
    echo "  ✓ Container images"
else
    echo "  ⊘ Container images preserved"
fi

echo ""
echo "The system is now clean and ready for a fresh installation."
echo ""
echo "To reinstall HookProbe:"
echo "  ./setup.sh"
echo "============================================================"
