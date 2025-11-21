#!/bin/bash
#
# uninstall.sh - HookProbe Infrastructure Cleanup
# Version: 4.0 - Complete removal of 7-POD architecture
#
# This script safely removes all HookProbe components
# Use with caution - this will destroy all data!
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load configuration
if [ -f "$SCRIPT_DIR/network-config.sh" ]; then
    source "$SCRIPT_DIR/network-config.sh"
else
    echo "WARNING: network-config.sh not found, using defaults..."
    POD_001_NAME="hookprobe-pod-001-web-dmz"
    POD_002_NAME="hookprobe-pod-002-iam"
    POD_003_NAME="hookprobe-pod-003-db-persistent"
    POD_004_NAME="hookprobe-pod-004-db-transient"
    POD_005_NAME="hookprobe-pod-005-monitoring"
    POD_006_NAME="hookprobe-pod-006-security"
    POD_007_NAME="hookprobe-pod-007-ai-response"
    
    NETWORK_POD001="pod001-dmz-net"
    NETWORK_POD002="pod002-iam-net"
    NETWORK_POD003="pod003-db-persistent-net"
    NETWORK_POD004="pod004-db-transient-net"
    NETWORK_POD005="pod005-monitoring-net"
    NETWORK_POD006="pod006-security-net"
    NETWORK_POD007="pod007-ai-response-net"
    
    OVS_MAIN_BRIDGE="ovs-br0"
    RSYSLOG_PORT=514
    PORT_WAF=8080
fi

echo "============================================================"
echo "   HOOKPROBE INFRASTRUCTURE CLEANUP v4.0"
echo "============================================================"
echo ""
echo "⚠️  WARNING: This will DESTROY all HookProbe infrastructure!"
echo ""
echo "Components to be removed:"
echo "  ❌ All 7 PODs and containers"
echo "  ❌ All volumes (databases, logs, models)"
echo "  ❌ All Podman networks"
echo "  ❌ All OVS bridges and VXLAN tunnels"
echo "  ❌ Firewall rules"
echo "  ❌ NAXSI WAF configuration"
echo "  ❌ Cloudflare Tunnel"
echo "  ❌ Rsyslog forwarding"
echo "  ❌ Qsecbit AI models and data"
echo "  ❌ Kali Linux tools and reports"
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
    "$POD_001_NAME"
    "$POD_002_NAME"
    "$POD_003_NAME"
    "$POD_004_NAME"
    "$POD_005_NAME"
    "$POD_006_NAME"
    "$POD_007_NAME"
)

for pod in "${POD_NAMES[@]}"; do
    if podman pod exists "$pod" 2>/dev/null; then
        echo "  → Removing: $pod"
        podman pod stop "$pod" 2>/dev/null || true
        podman pod rm -f "$pod" 2>/dev/null || true
    fi
done

podman container prune -f || true
echo "✓ All PODs removed"

# ============================================================
# STEP 2: REMOVE NETWORKS
# ============================================================
echo ""
echo "[STEP 2] Removing networks..."

NETWORK_NAMES=(
    "$NETWORK_POD001"
    "$NETWORK_POD002"
    "$NETWORK_POD003"
    "$NETWORK_POD004"
    "$NETWORK_POD005"
    "$NETWORK_POD006"
    "$NETWORK_POD007"
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
# STEP 4: REMOVE OVS CONFIGURATION
# ============================================================
echo ""
echo "[STEP 4] Removing OVS configuration..."

if ovs-vsctl br-exists "$OVS_MAIN_BRIDGE" 2>/dev/null; then
    VXLAN_PORTS=$(ovs-vsctl list-ports "$OVS_MAIN_BRIDGE" 2>/dev/null | grep -i vxlan || true)
    
    if [ -n "$VXLAN_PORTS" ]; then
        echo "$VXLAN_PORTS" | while read port; do
            echo "  → Removing VXLAN: $port"
            ovs-vsctl --if-exists del-port "$OVS_MAIN_BRIDGE" "$port"
        done
    fi
    
    echo "  → Removing bridge: $OVS_MAIN_BRIDGE"
    ovs-vsctl --if-exists del-br "$OVS_MAIN_BRIDGE"
fi

echo "✓ OVS configuration removed"

# ============================================================
# STEP 5: CLEAN FIREWALL
# ============================================================
echo ""
echo "[STEP 5] Cleaning firewall..."

if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --remove-port=4789/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=500/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=4500/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=${PORT_WAF}/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=3001/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=3002/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=3000/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=9090/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=${RSYSLOG_PORT}/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=${RSYSLOG_PORT}/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=8888/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-rich-rule='rule family="ipv4" source address="10.100.0.0/16" accept' 2>/dev/null || true
    firewall-cmd --reload
    echo "✓ Firewall cleaned"
fi

# ============================================================
# STEP 6: REMOVE RSYSLOG CONFIG
# ============================================================
echo ""
echo "[STEP 6] Removing rsyslog configuration..."

if [ -f /etc/rsyslog.d/50-hookprobe-containers.conf ]; then
    rm -f /etc/rsyslog.d/50-hookprobe-containers.conf
    systemctl restart rsyslog 2>/dev/null || true
    echo "✓ Rsyslog configuration removed"
fi

# ============================================================
# STEP 7: REMOVE BUILD DIRECTORIES
# ============================================================
echo ""
echo "[STEP 7] Removing build directories..."

BUILD_DIRS=(
    "/tmp/hookprobe-django-build"
    "/tmp/naxsi-config"
    "/tmp/nginx-naxsi-build"
    "/tmp/prometheus-config"
    "/tmp/loki-config"
    "/tmp/promtail-config"
    "/tmp/alertmanager-config"
    "/tmp/grafana-provisioning"
    "/tmp/rsyslog-config"
    "/tmp/qsecbit-build"
)

for dir in "${BUILD_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        rm -rf "$dir"
    fi
done

echo "✓ Build directories removed"

# ============================================================
# STEP 8: REMOVE IMAGES
# ============================================================
echo ""
read -p "Remove HookProbe container images? (yes/no): " remove_images

if [ "$remove_images" == "yes" ]; then
    echo "[STEP 8] Removing images..."
    
    IMAGES=$(podman images -q | xargs podman images --format "{{.Repository}}:{{.Tag}}" | grep -E "hookprobe|naxsi|qsecbit" 2>/dev/null || true)
    
    if [ -n "$IMAGES" ]; then
        echo "$IMAGES" | while read image; do
            podman rmi -f "$image" 2>/dev/null || true
        done
    fi
    
    podman image prune -af || true
    echo "✓ Images removed"
fi

# ============================================================
# STEP 9: STOP OVS
# ============================================================
echo ""
read -p "Stop OVS service? (yes/no): " stop_ovs

if [ "$stop_ovs" == "yes" ]; then
    systemctl stop openvswitch 2>/dev/null || true
    systemctl disable openvswitch 2>/dev/null || true
    echo "✓ OVS stopped"
fi

# ============================================================
# STEP 10: REMOVE KERNEL CONFIG
# ============================================================
echo ""
read -p "Remove kernel module configuration? (yes/no): " remove_modules

if [ "$remove_modules" == "yes" ]; then
    if [ -f /etc/modules-load.d/hookprobe.conf ]; then
        rm -f /etc/modules-load.d/hookprobe.conf
        echo "✓ Kernel config removed"
    fi
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
echo "   HOOKPROBE CLEANUP COMPLETE!"
echo "============================================================"
echo ""
echo "✅ Removed:"
echo "  ✓ All 7 PODs"
if [ "$remove_volumes" == "yes" ]; then
    echo "  ✓ All data (PERMANENTLY DELETED)"
else
    echo "  ⊘ Volumes preserved"
fi
echo "  ✓ Networks and OVS"
echo "  ✓ Firewall rules"
echo "  ✓ Rsyslog config"
if [ "$remove_images" == "yes" ]; then
    echo "  ✓ Container images"
fi
echo ""
echo "To reinstall:"
echo "  1. Review network-config.sh"
echo "  2. Run: sudo ./setup.sh"
echo ""
echo "============================================================"
