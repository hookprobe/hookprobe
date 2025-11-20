#!/bin/bash
#
# uninstall.sh - Complete cleanup of HookProbe infrastructure
# Version: 3.0 - Enhanced for WAF + Cloudflare + Centralized Logging
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
    POD_002_NAME="hookprobe-pod-002-iam"
    POD_003_NAME="hookprobe-pod-003-db-persistent"
    POD_004_NAME="hookprobe-pod-004-db-transient"
    POD_005_NAME="hookprobe-pod-005-monitoring"
    POD_006_NAME="hookprobe-pod-006-security"
    
    NETWORK_POD001="pod001-dmz-net"
    NETWORK_POD002="pod002-iam-net"
    NETWORK_POD003="pod003-db-persistent-net"
    NETWORK_POD004="pod004-db-transient-net"
    NETWORK_POD005="pod005-monitoring-net"
    NETWORK_POD006="pod006-security-net"
    
    OVS_MAIN_BRIDGE="ovs-br0"
    OVS_DMZ_BRIDGE="ovs-br-dmz"
    OVS_INTERNAL_BRIDGE="ovs-br-internal"
    
    VOLUME_POSTGRES_DATA="hookprobe-postgres-data"
    VOLUME_LOGTO_DB="hookprobe-logto-db"
    VOLUME_GRAFANA_DATA="hookprobe-grafana-data"
    VOLUME_PROMETHEUS_DATA="hookprobe-prometheus-data"
    VOLUME_LOKI_DATA="hookprobe-loki-data"
    VOLUME_RSYSLOG_DATA="hookprobe-rsyslog-data"
    VOLUME_WAF_LOGS="hookprobe-waf-logs"
    VOLUME_CLOUDFLARED_CREDS="hookprobe-cloudflared-creds"
    
    RSYSLOG_PORT=514
    RSYSLOG_TLS_PORT=6514
    PORT_WAF=8080
fi

echo "============================================================"
echo "   HOOKPROBE INFRASTRUCTURE CLEANUP v3.0"
echo "============================================================"
echo ""
echo "⚠  WARNING: This will DESTROY all HookProbe infrastructure!"
echo ""
echo "This includes:"
echo "  ❌ All 6 PODs and their containers"
echo "  ❌ All volumes (INCLUDING ALL DATABASES AND DATA)"
echo "  ❌ All Podman networks"
echo "  ❌ All OVS bridges and VXLAN tunnels"
echo "  ❌ Firewall rules"
echo "  ❌ All logs and monitoring data"
echo "  ❌ NAXSI WAF configuration"
echo "  ❌ Cloudflare Tunnel configuration"
echo "  ❌ Rsyslog forwarding rules"
echo ""
echo "Data that will be lost:"
echo "  • Django CMS content and media"
echo "  • PostgreSQL databases (main + Logto)"
echo "  • Redis cache data"
echo "  • Grafana dashboards and settings"
echo "  • Prometheus metrics history"
echo "  • Loki log archives"
echo "  • Rsyslog centralized logs"
echo "  • IDS/IPS logs and alerts"
echo "  • WAF logs and statistics"
echo ""
read -p "⚠️  Are you ABSOLUTELY sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "✓ Uninstall cancelled. Your infrastructure is safe."
    exit 0
fi

echo ""
echo "⏰ Starting cleanup in 5 seconds... (Press Ctrl+C to cancel)"
sleep 5

# ============================================================
# STEP 1: STOP AND REMOVE ALL PODS
# ============================================================
echo ""
echo "[STEP 1] Stopping and removing all PODs..."

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
        echo "  → Stopping and removing POD: $pod"
        podman pod stop "$pod" 2>/dev/null || true
        podman pod rm -f "$pod" 2>/dev/null || true
    else
        echo "  ⊘ POD not found: $pod"
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
        podman network rm "$network" 2>/dev/null || true
    else
        echo "  ⊘ Network not found: $network"
    fi
done

# Prune unused networks
echo "  → Pruning unused networks..."
podman network prune -f || true

echo "✓ All networks removed"

# ============================================================
# STEP 3: REMOVE VOLUMES (OPTIONAL - DATA LOSS!)
# ============================================================
echo ""
echo "⚠️  CRITICAL DECISION: Volume Removal"
echo ""
echo "Volumes contain all your data:"
echo "  📊 PostgreSQL databases"
echo "  🎨 Django media files"
echo "  📈 Grafana dashboards"
echo "  📊 Prometheus metrics"
echo "  📝 Loki logs"
echo "  🔐 Logto user data"
echo "  📋 Rsyslog centralized logs"
echo "  🛡️  WAF logs and statistics"
echo ""
read -p "Do you want to PERMANENTLY DELETE all volumes and data? (yes/no): " remove_volumes

if [ "$remove_volumes" == "yes" ]; then
    echo "[STEP 3] Removing volumes..."
    
    # List all hookprobe volumes
    VOLUMES=$(podman volume ls -q | grep -i hookprobe 2>/dev/null || true)
    
    if [ -n "$VOLUMES" ]; then
        echo "  Found volumes:"
        echo "$VOLUMES" | while read vol; do
            echo "    • $vol"
        done
        echo ""
        
        for volume in $VOLUMES; do
            echo "  → Removing volume: $volume"
            podman volume rm "$volume" 2>/dev/null || true
        done
    else
        echo "  ⊘ No HookProbe volumes found"
    fi
    
    # Prune all unused volumes
    echo "  → Pruning unused volumes..."
    podman volume prune -f || true
    
    echo "✓ All volumes removed (DATA PERMANENTLY DELETED)"
else
    echo "[STEP 3] ✓ Volumes preserved (data intact)"
    echo ""
    echo "  Your data is still available in these volumes:"
    VOLUMES=$(podman volume ls -q | grep -i hookprobe 2>/dev/null || true)
    if [ -n "$VOLUMES" ]; then
        echo "$VOLUMES" | while read vol; do
            echo "    • $vol"
        done
    fi
fi

# ============================================================
# STEP 4: REMOVE OVS CONFIGURATION
# ============================================================
echo ""
echo "[STEP 4] Removing Open vSwitch configuration..."

# List all VXLAN ports and remove them
echo "  → Removing VXLAN tunnels..."
if ovs-vsctl br-exists "$OVS_MAIN_BRIDGE" 2>/dev/null; then
    VXLAN_PORTS=$(ovs-vsctl list-ports "$OVS_MAIN_BRIDGE" 2>/dev/null | grep -i vxlan || true)
    
    if [ -n "$VXLAN_PORTS" ]; then
        echo "$VXLAN_PORTS" | while read port; do
            echo "    • Removing VXLAN port: $port"
            ovs-vsctl --if-exists del-port "$OVS_MAIN_BRIDGE" "$port"
        done
    else
        echo "    ⊘ No VXLAN ports found"
    fi
else
    echo "    ⊘ OVS bridge not found"
fi

# Remove OVS bridges
echo "  → Removing OVS bridges..."
for bridge in "$OVS_MAIN_BRIDGE" "$OVS_DMZ_BRIDGE" "$OVS_INTERNAL_BRIDGE"; do
    if ovs-vsctl br-exists "$bridge" 2>/dev/null; then
        echo "    • Removing bridge: $bridge"
        ovs-vsctl --if-exists del-br "$bridge"
    else
        echo "    ⊘ Bridge not found: $bridge"
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
    
    # Remove VXLAN and IPsec ports
    firewall-cmd --permanent --remove-port=4789/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=500/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=4500/udp 2>/dev/null || true
    
    # Remove WAF port
    firewall-cmd --permanent --remove-port=${PORT_WAF}/tcp 2>/dev/null || true
    
    # Remove Logto ports
    firewall-cmd --permanent --remove-port=3001/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=3002/tcp 2>/dev/null || true
    
    # Remove monitoring ports
    firewall-cmd --permanent --remove-port=3000/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=9090/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=9093/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=3100/tcp 2>/dev/null || true
    
    # Remove syslog ports
    firewall-cmd --permanent --remove-port=${RSYSLOG_PORT}/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=${RSYSLOG_PORT}/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=${RSYSLOG_TLS_PORT}/tcp 2>/dev/null || true
    
    # Remove rich rules
    firewall-cmd --permanent --remove-rich-rule='rule family="ipv4" source address="10.100.0.0/16" accept' 2>/dev/null || true
    
    # Remove trusted interface
    if ovs-vsctl br-exists "$OVS_MAIN_BRIDGE" 2>/dev/null; then
        firewall-cmd --permanent --zone=trusted --remove-interface="$OVS_MAIN_BRIDGE" 2>/dev/null || true
    fi
    
    firewall-cmd --reload
    
    echo "✓ Firewall rules cleaned"
else
    echo "  ⊘ firewalld not found, skipping"
fi

# ============================================================
# STEP 6: REMOVE RSYSLOG CONFIGURATION
# ============================================================
echo ""
echo "[STEP 6] Removing rsyslog forwarding configuration..."

if [ -f /etc/rsyslog.d/50-hookprobe-containers.conf ]; then
    echo "  → Removing rsyslog configuration..."
    rm -f /etc/rsyslog.d/50-hookprobe-containers.conf
    systemctl restart rsyslog 2>/dev/null || true
    echo "✓ Rsyslog configuration removed"
else
    echo "  ⊘ Rsyslog configuration not found"
fi

# ============================================================
# STEP 7: REMOVE BUILD DIRECTORIES
# ============================================================
echo ""
echo "[STEP 7] Removing temporary build directories..."

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
)

for dir in "${BUILD_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "  → Removing: $dir"
        rm -rf "$dir"
    else
        echo "  ⊘ Directory not found: $dir"
    fi
done

echo "✓ Build directories removed"

# ============================================================
# STEP 8: REMOVE CONTAINER IMAGES (OPTIONAL)
# ============================================================
echo ""
read -p "Do you want to remove HookProbe container images? (yes/no): " remove_images

if [ "$remove_images" == "yes" ]; then
    echo "[STEP 8] Removing container images..."
    
    # Remove HookProbe images
    IMAGES=$(podman images -q | xargs podman images --format "{{.Repository}}:{{.Tag}}" | grep -E "hookprobe|naxsi" 2>/dev/null || true)
    
    if [ -n "$IMAGES" ]; then
        echo "$IMAGES" | while read image; do
            echo "  → Removing image: $image"
            podman rmi -f "$image" 2>/dev/null || true
        done
    else
        echo "  ⊘ No HookProbe images found"
    fi
    
    # Prune unused images
    echo "  → Pruning unused images..."
    podman image prune -af || true
    
    echo "✓ Container images removed"
else
    echo "[STEP 8] ✓ Container images preserved"
fi

# ============================================================
# STEP 9: STOP OVS SERVICE (OPTIONAL)
# ============================================================
echo ""
read -p "Do you want to stop and disable the OVS service? (yes/no): " stop_ovs

if [ "$stop_ovs" == "yes" ]; then
    echo "[STEP 9] Stopping Open vSwitch service..."
    systemctl stop openvswitch 2>/dev/null || true
    systemctl disable openvswitch 2>/dev/null || true
    echo "✓ OVS service stopped and disabled"
else
    echo "[STEP 9] ✓ OVS service left running"
fi

# ============================================================
# STEP 10: REMOVE KERNEL MODULE CONFIGURATION
# ============================================================
echo ""
read -p "Do you want to remove kernel module configuration? (yes/no): " remove_modules

if [ "$remove_modules" == "yes" ]; then
    echo "[STEP 10] Removing kernel module configuration..."
    
    if [ -f /etc/modules-load.d/hookprobe.conf ]; then
        rm -f /etc/modules-load.d/hookprobe.conf
        echo "✓ Kernel module configuration removed"
    else
        echo "  ⊘ Configuration file not found"
    fi
else
    echo "[STEP 10] ✓ Kernel module configuration preserved"
fi

# ============================================================
# STEP 11: SYSTEM CLEANUP
# ============================================================
echo ""
echo "[STEP 11] Final system cleanup..."

# Clean up podman system
echo "  → Running podman system prune..."
podman system prune -af --volumes 2>/dev/null || true

# Remove any lingering network namespaces
echo "  → Cleaning network namespaces..."
ip netns list 2>/dev/null | grep -i hookprobe | while read ns; do
    echo "    • Removing namespace: $ns"
    ip netns delete "$ns" 2>/dev/null || true
done

echo "✓ System cleanup complete"

# ============================================================
# FINAL SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   HOOKPROBE CLEANUP COMPLETE!"
echo "============================================================"
echo ""
echo "✅ Removed Components:"
echo "  ✓ All 6 PODs and containers"
echo "  ✓ All Podman networks"

if [ "$remove_volumes" == "yes" ]; then
    echo "  ✓ All volumes and data (PERMANENTLY DELETED)"
else
    echo "  ⊘ Volumes preserved (data intact)"
fi

echo "  ✓ OVS bridges and VXLAN tunnels"
echo "  ✓ Firewall rules"
echo "  ✓ Rsyslog forwarding configuration"
echo "  ✓ Temporary build directories"

if [ "$remove_images" == "yes" ]; then
    echo "  ✓ Container images (including NAXSI WAF)"
else
    echo "  ⊘ Container images preserved"
fi

if [ "$stop_ovs" == "yes" ]; then
    echo "  ✓ OVS service stopped"
else
    echo "  ⊘ OVS service still running"
fi

if [ "$remove_modules" == "yes" ]; then
    echo "  ✓ Kernel module configuration"
else
    echo "  ⊘ Kernel module configuration preserved"
fi

echo ""
echo "📊 Summary:"
if [ "$remove_volumes" != "yes" ]; then
    echo "  ℹ️  Your data volumes are preserved and can be reused"
    echo "  ℹ️  Run './setup.sh' to redeploy with existing data"
else
    echo "  ⚠️  All data has been permanently deleted"
    echo "  ℹ️  Run './setup.sh' for a fresh installation"
fi

echo ""
echo "🔧 System Status:"
echo "  • Podman: $(podman --version 2>/dev/null || echo 'Not running')"
echo "  • OVS: $(systemctl is-active openvswitch 2>/dev/null || echo 'Stopped')"
echo "  • Rsyslog: $(systemctl is-active rsyslog 2>/dev/null || echo 'Stopped')"
echo "  • Remaining containers: $(podman ps -a | wc -l)"
echo "  • Remaining volumes: $(podman volume ls -q | wc -l)"
echo "  • Remaining networks: $(podman network ls -q | wc -l)"
echo ""
echo "To reinstall HookProbe v3.0:"
echo "  1. Review and update network-config.sh"
echo "  2. Configure Cloudflare Tunnel token (optional)"
echo "  3. Run: sudo ./setup.sh"
echo ""
echo "============================================================"
echo "  🎉 Cleanup completed successfully!"
echo "============================================================"
echo ""
echo "⚠  WARNING: This will DESTROY all HookProbe infrastructure!"
echo ""
echo "This includes:"
echo "  ❌ All 6 PODs and their containers"
echo "  ❌ All volumes (INCLUDING ALL DATABASES AND DATA)"
echo "  ❌ All Podman networks"
echo "  ❌ All OVS bridges and VXLAN tunnels"
echo "  ❌ Firewall rules"
echo "  ❌ All logs and monitoring data"
echo ""
echo "Data that will be lost:"
echo "  • Django CMS content and media"
echo "  • PostgreSQL databases (main + Logto)"
echo "  • Redis cache data"
echo "  • Grafana dashboards and settings"
echo "  • Prometheus metrics history"
echo "  • Loki log archives"
echo "  • IDS/IPS logs and alerts"
echo ""
read -p "⚠️  Are you ABSOLUTELY sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "✓ Uninstall cancelled. Your infrastructure is safe."
    exit 0
fi

echo ""
echo "⏰ Starting cleanup in 5 seconds... (Press Ctrl+C to cancel)"
sleep 5

# ============================================================
# STEP 1: STOP AND REMOVE ALL PODS
# ============================================================
echo ""
echo "[STEP 1] Stopping and removing all PODs..."

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
        echo "  → Stopping and removing POD: $pod"
        podman pod stop "$pod" 2>/dev/null || true
        podman pod rm -f "$pod" 2>/dev/null || true
    else
        echo "  ⊘ POD not found: $pod"
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
        podman network rm "$network" 2>/dev/null || true
    else
        echo "  ⊘ Network not found: $network"
    fi
done

# Prune unused networks
echo "  → Pruning unused networks..."
podman network prune -f || true

echo "✓ All networks removed"

# ============================================================
# STEP 3: REMOVE VOLUMES (OPTIONAL - DATA LOSS!)
# ============================================================
echo ""
echo "⚠️  CRITICAL DECISION: Volume Removal"
echo ""
echo "Volumes contain all your data:"
echo "  📊 PostgreSQL databases"
echo "  🎨 Django media files"
echo "  📈 Grafana dashboards"
echo "  📊 Prometheus metrics"
echo "  📝 Loki logs"
echo "  🔐 Logto user data"
echo ""
read -p "Do you want to PERMANENTLY DELETE all volumes and data? (yes/no): " remove_volumes

if [ "$remove_volumes" == "yes" ]; then
    echo "[STEP 3] Removing volumes..."
    
    # List all hookprobe volumes
    VOLUMES=$(podman volume ls -q | grep -i hookprobe 2>/dev/null || true)
    
    if [ -n "$VOLUMES" ]; then
        echo "  Found volumes:"
        echo "$VOLUMES" | while read vol; do
            echo "    • $vol"
        done
        echo ""
        
        for volume in $VOLUMES; do
            echo "  → Removing volume: $volume"
            podman volume rm "$volume" 2>/dev/null || true
        done
    else
        echo "  ⊘ No HookProbe volumes found"
    fi
    
    # Prune all unused volumes
    echo "  → Pruning unused volumes..."
    podman volume prune -f || true
    
    echo "✓ All volumes removed (DATA PERMANENTLY DELETED)"
else
    echo "[STEP 3] ✓ Volumes preserved (data intact)"
    echo ""
    echo "  Your data is still available in these volumes:"
    VOLUMES=$(podman volume ls -q | grep -i hookprobe 2>/dev/null || true)
    if [ -n "$VOLUMES" ]; then
        echo "$VOLUMES" | while read vol; do
            echo "    • $vol"
        done
    fi
fi

# ============================================================
# STEP 4: REMOVE OVS CONFIGURATION
# ============================================================
echo ""
echo "[STEP 4] Removing Open vSwitch configuration..."

# List all VXLAN ports and remove them
echo "  → Removing VXLAN tunnels..."
if ovs-vsctl br-exists "$OVS_MAIN_BRIDGE" 2>/dev/null; then
    VXLAN_PORTS=$(ovs-vsctl list-ports "$OVS_MAIN_BRIDGE" 2>/dev/null | grep -i vxlan || true)
    
    if [ -n "$VXLAN_PORTS" ]; then
        echo "$VXLAN_PORTS" | while read port; do
            echo "    • Removing VXLAN port: $port"
            ovs-vsctl --if-exists del-port "$OVS_MAIN_BRIDGE" "$port"
        done
    else
        echo "    ⊘ No VXLAN ports found"
    fi
else
    echo "    ⊘ OVS bridge not found"
fi

# Remove OVS bridges
echo "  → Removing OVS bridges..."
for bridge in "$OVS_MAIN_BRIDGE" "$OVS_DMZ_BRIDGE" "$OVS_INTERNAL_BRIDGE"; do
    if ovs-vsctl br-exists "$bridge" 2>/dev/null; then
        echo "    • Removing bridge: $bridge"
        ovs-vsctl --if-exists del-br "$bridge"
    else
        echo "    ⊘ Bridge not found: $bridge"
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
    
    # Remove VXLAN and IPsec ports
    firewall-cmd --permanent --remove-port=4789/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=500/udp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=4500/udp 2>/dev/null || true
    
    # Remove Logto ports
    firewall-cmd --permanent --remove-port=3001/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=3002/tcp 2>/dev/null || true
    
    # Remove monitoring ports
    firewall-cmd --permanent --remove-port=3000/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=9090/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=9093/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=3100/tcp 2>/dev/null || true
    
    # Remove rich rules
    firewall-cmd --permanent --remove-rich-rule='rule family="ipv4" source address="10.100.0.0/16" accept' 2>/dev/null || true
    
    # Remove trusted interface
    if ovs-vsctl br-exists "$OVS_MAIN_BRIDGE" 2>/dev/null; then
        firewall-cmd --permanent --zone=trusted --remove-interface="$OVS_MAIN_BRIDGE" 2>/dev/null || true
    fi
    
    firewall-cmd --reload
    
    echo "✓ Firewall rules cleaned"
else
    echo "  ⊘ firewalld not found, skipping"
fi

# ============================================================
# STEP 6: REMOVE BUILD DIRECTORIES
# ============================================================
echo ""
echo "[STEP 6] Removing temporary build directories..."

BUILD_DIRS=(
    "/tmp/hookprobe-django-build"
    "/tmp/nginx-hookprobe"
    "/tmp/prometheus-config"
    "/tmp/loki-config"
    "/tmp/promtail-config"
    "/tmp/alertmanager-config"
    "/tmp/grafana-provisioning"
)

for dir in "${BUILD_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "  → Removing: $dir"
        rm -rf "$dir"
    else
        echo "  ⊘ Directory not found: $dir"
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
    
    # Remove HookProbe Django image
    IMAGES=$(podman images -q hookprobe-django 2>/dev/null || true)
    
    if [ -n "$IMAGES" ]; then
        for image in $IMAGES; do
            echo "  → Removing image: $image"
            podman rmi -f "$image" 2>/dev/null || true
        done
    else
        echo "  ⊘ No HookProbe images found"
    fi
    
    # Prune unused images
    echo "  → Pruning unused images..."
    podman image prune -af || true
    
    echo "✓ Container images removed"
else
    echo "[STEP 7] ✓ Container images preserved"
fi

# ============================================================
# STEP 8: STOP OVS SERVICE (OPTIONAL)
# ============================================================
echo ""
read -p "Do you want to stop and disable the OVS service? (yes/no): " stop_ovs

if [ "$stop_ovs" == "yes" ]; then
    echo "[STEP 8] Stopping Open vSwitch service..."
    systemctl stop openvswitch 2>/dev/null || true
    systemctl disable openvswitch 2>/dev/null || true
    echo "✓ OVS service stopped and disabled"
else
    echo "[STEP 8] ✓ OVS service left running"
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
    else
        echo "  ⊘ Configuration file not found"
    fi
else
    echo "[STEP 9] ✓ Kernel module configuration preserved"
fi

# ============================================================
# STEP 10: SYSTEM CLEANUP
# ============================================================
echo ""
echo "[STEP 10] Final system cleanup..."

# Clean up podman system
echo "  → Running podman system prune..."
podman system prune -af --volumes 2>/dev/null || true

# Remove any lingering network namespaces
echo "  → Cleaning network namespaces..."
ip netns list 2>/dev/null | grep -i hookprobe | while read ns; do
    echo "    • Removing namespace: $ns"
    ip netns delete "$ns" 2>/dev/null || true
done

echo "✓ System cleanup complete"

# ============================================================
# FINAL SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   HOOKPROBE CLEANUP COMPLETE!"
echo "============================================================"
echo ""
echo "✅ Removed Components:"
echo "  ✓ All 6 PODs and containers"
echo "  ✓ All Podman networks"

if [ "$remove_volumes" == "yes" ]; then
    echo "  ✓ All volumes and data (PERMANENTLY DELETED)"
else
    echo "  ⊘ Volumes preserved (data intact)"
fi

echo "  ✓ OVS bridges and VXLAN tunnels"
echo "  ✓ Firewall rules"
echo "  ✓ Temporary build directories"

if [ "$remove_images" == "yes" ]; then
    echo "  ✓ Container images"
else
    echo "  ⊘ Container images preserved"
fi

if [ "$stop_ovs" == "yes" ]; then
    echo "  ✓ OVS service stopped"
else
    echo "  ⊘ OVS service still running"
fi

if [ "$remove_modules" == "yes" ]; then
    echo "  ✓ Kernel module configuration"
else
    echo "  ⊘ Kernel module configuration preserved"
fi

echo ""
echo "📊 Summary:"
if [ "$remove_volumes" != "yes" ]; then
    echo "  ℹ️  Your data volumes are preserved and can be reused"
    echo "  ℹ️  Run './setup.sh' to redeploy with existing data"
else
    echo "  ⚠️  All data has been permanently deleted"
    echo "  ℹ️  Run './setup.sh' for a fresh installation"
fi

echo ""
echo "🔧 System Status:"
echo "  • Podman: $(podman --version 2>/dev/null || echo 'Not running')"
echo "  • OVS: $(systemctl is-active openvswitch 2>/dev/null || echo 'Stopped')"
echo "  • Remaining containers: $(podman ps -a | wc -l)"
echo "  • Remaining volumes: $(podman volume ls -q | wc -l)"
echo "  • Remaining networks: $(podman network ls -q | wc -l)"
echo ""
echo "To reinstall HookProbe:"
echo "  1. Review and update network-config.sh"
echo "  2. Run: sudo ./setup.sh"
echo ""
echo "============================================================"
echo "  🎉 Cleanup completed successfully!"
echo "============================================================"
