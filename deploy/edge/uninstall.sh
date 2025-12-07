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

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Load configuration
if [ -f "$SCRIPT_DIR/config.sh" ]; then
    source "$SCRIPT_DIR/config.sh"
fi

# Load OVS bridge config if exists
if [ -f /etc/hookprobe/ovs-bridge.conf ]; then
    source /etc/hookprobe/ovs-bridge.conf
fi

# Default values (new unified naming)
OVS_BRIDGE_NAME="${OVS_BRIDGE_NAME:-hookprobe}"
QSEC_BRIDGE="${QSEC_BRIDGE:-qsec-bridge}"  # Legacy support

echo "============================================================"
echo "   HOOKPROBE v5.0 INFRASTRUCTURE CLEANUP"
echo "============================================================"
echo ""
echo -e "${RED}WARNING: This will DESTROY all HookProbe v5.0 infrastructure!${NC}"
echo ""
echo "Components to be removed:"
echo -e "  ${RED}[x]${NC} All PODs and containers"
echo -e "  ${RED}[x]${NC} All volumes (databases, logs, data)"
echo -e "  ${RED}[x]${NC} All Podman networks"
echo -e "  ${RED}[x]${NC} OVS bridge ($OVS_BRIDGE_NAME) and VXLAN tunnels"
echo -e "  ${RED}[x]${NC} OpenFlow flows"
echo -e "  ${RED}[x]${NC} Firewall and NAT routing rules"
echo -e "  ${RED}[x]${NC} XDP DDoS mitigation program"
echo -e "  ${RED}[x]${NC} Kernel configuration"
echo -e "  ${RED}[x]${NC} Configuration files (/etc/hookprobe)"
echo ""
read -p "Are you ABSOLUTELY sure? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo -e "${GREEN}[x]${NC} Uninstall cancelled."
    exit 0
fi

echo ""
echo -e "${YELLOW}Starting cleanup in 5 seconds... (Ctrl+C to cancel)${NC}"
sleep 5

# ============================================================
# STEP 1: REMOVE PODS
# ============================================================
echo ""
echo "[STEP 1] Removing PODs..."

# New unified POD names
NEW_POD_NAMES=(
    "hookprobe-web"
    "hookprobe-iam"
    "hookprobe-database"
    "hookprobe-cache"
    "hookprobe-monitoring"
    "hookprobe-detection"
    "hookprobe-ai"
    "hookprobe-neuro"
    "hookprobe-sentinel"
)

# Legacy POD names
LEGACY_POD_NAMES=(
    "hookprobe-web-dmz"
    "hookprobe-security"
    "hookprobe-honeypot"
)

# Remove all new PODs
for pod in "${NEW_POD_NAMES[@]}"; do
    if podman pod exists "$pod" 2>/dev/null; then
        echo -e "  ${YELLOW}→${NC} Removing: $pod"
        podman pod stop "$pod" 2>/dev/null || true
        podman pod rm -f "$pod" 2>/dev/null || true
    fi
done

# Remove legacy PODs
for pod in "${LEGACY_POD_NAMES[@]}"; do
    if podman pod exists "$pod" 2>/dev/null; then
        echo -e "  ${YELLOW}→${NC} Removing (legacy): $pod"
        podman pod stop "$pod" 2>/dev/null || true
        podman pod rm -f "$pod" 2>/dev/null || true
    fi
done

# Remove any hookprobe-* pods we might have missed
podman pod ls --format "{{.Name}}" 2>/dev/null | grep -E "^hookprobe" | while read -r pod; do
    echo -e "  ${YELLOW}→${NC} Removing: $pod"
    podman pod stop "$pod" 2>/dev/null || true
    podman pod rm -f "$pod" 2>/dev/null || true
done

# Remove any remaining containers
podman container prune -f 2>/dev/null || true
echo -e "${GREEN}[x]${NC} All PODs removed"

# ============================================================
# STEP 2: REMOVE NETWORKS
# ============================================================
echo ""
echo "[STEP 2] Removing networks..."

# New unified network names (hookprobe-*)
NEW_NETWORK_NAMES=(
    "hookprobe-web"
    "hookprobe-iam"
    "hookprobe-database"
    "hookprobe-cache"
    "hookprobe-monitoring"
    "hookprobe-detection"
    "hookprobe-ai"
    "hookprobe-neuro"
)

# Legacy network names
LEGACY_NETWORK_NAMES=(
    "web-dmz-net"
    "iam-net"
    "database-net"
    "cache-net"
    "monitoring-net"
    "security-net"
    "honeypot-net"
)

# Remove new networks
for network in "${NEW_NETWORK_NAMES[@]}"; do
    if podman network exists "$network" 2>/dev/null; then
        echo -e "  ${YELLOW}→${NC} Removing: $network"
        podman network rm "$network" 2>/dev/null || true
    fi
done

# Remove legacy networks
for network in "${LEGACY_NETWORK_NAMES[@]}"; do
    if podman network exists "$network" 2>/dev/null; then
        echo -e "  ${YELLOW}→${NC} Removing (legacy): $network"
        podman network rm "$network" 2>/dev/null || true
    fi
done

# Remove any hookprobe-* networks we might have missed
podman network ls --format "{{.Name}}" 2>/dev/null | grep -E "^hookprobe" | while read -r network; do
    echo -e "  ${YELLOW}→${NC} Removing: $network"
    podman network rm "$network" 2>/dev/null || true
done

podman network prune -f || true
echo -e "${GREEN}[x]${NC} Networks removed"

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
            echo -e "  ${YELLOW}→${NC} Removing: $volume"
            podman volume rm "$volume" 2>/dev/null || true
        done
    fi

    podman volume prune -f || true
    echo -e "${GREEN}[x]${NC} All volumes removed (DATA DELETED)"
else
    echo -e "[STEP 3] ${GREEN}[x]${NC} Volumes preserved"
fi

# ============================================================
# STEP 4: REMOVE XDP PROGRAM
# ============================================================
echo ""
echo "[STEP 4] Removing XDP DDoS mitigation..."

if [ -n "$PHYSICAL_HOST_INTERFACE" ]; then
    # Remove XDP program from interface
    ip link set dev "$PHYSICAL_HOST_INTERFACE" xdp off 2>/dev/null || true
    echo -e "${GREEN}[x]${NC} XDP program removed from $PHYSICAL_HOST_INTERFACE"
fi

# Remove XDP files
if [ -d /opt/hookprobe/xdp ]; then
    rm -rf /opt/hookprobe/xdp
    echo -e "${GREEN}[x]${NC} XDP files removed"
fi

# ============================================================
# STEP 5: REMOVE OVS CONFIGURATION
# ============================================================
echo ""
echo "[STEP 5] Removing OVS configuration..."

# Function to remove OVS bridge and all its components
remove_ovs_bridge() {
    local bridge_name="$1"

    if ! command -v ovs-vsctl &> /dev/null; then
        echo -e "  ${YELLOW}!${NC} OVS not installed, skipping bridge removal"
        return 0
    fi

    if ovs-vsctl br-exists "$bridge_name" 2>/dev/null; then
        echo -e "  ${CYAN}Found bridge: $bridge_name${NC}"

        # Remove all OpenFlow flows first
        echo -e "  ${YELLOW}→${NC} Clearing OpenFlow flows..."
        ovs-ofctl del-flows "$bridge_name" 2>/dev/null || true

        # List and remove all ports (including VXLAN tunnels)
        local ports=$(ovs-vsctl list-ports "$bridge_name" 2>/dev/null || true)

        if [ -n "$ports" ]; then
            echo "$ports" | while read -r port; do
                if [ -n "$port" ]; then
                    # Get port type for display
                    local port_type=$(ovs-vsctl get interface "$port" type 2>/dev/null || echo "unknown")
                    echo -e "  ${YELLOW}→${NC} Removing port: $port (type: $port_type)"
                    ovs-vsctl --if-exists del-port "$bridge_name" "$port"
                fi
            done
        fi

        # Remove the bridge itself
        echo -e "  ${YELLOW}→${NC} Removing bridge: $bridge_name"
        ovs-vsctl --if-exists del-br "$bridge_name"
        echo -e "  ${GREEN}[x]${NC} Bridge $bridge_name removed"
    else
        echo -e "  ${YELLOW}!${NC} Bridge $bridge_name not found"
    fi
}

# Remove new unified bridge (hookprobe)
remove_ovs_bridge "$OVS_BRIDGE_NAME"

# Remove legacy bridge (qsec-bridge) if different
if [ "$QSEC_BRIDGE" != "$OVS_BRIDGE_NAME" ]; then
    remove_ovs_bridge "$QSEC_BRIDGE"
fi

# Clean up any orphaned OVS ports
echo -e "  ${YELLOW}→${NC} Cleaning orphaned OVS ports..."
ovs-vsctl show 2>/dev/null | grep -E "hookprobe|qsec" | while read -r line; do
    echo -e "  ${YELLOW}!${NC} Found orphaned: $line"
done

# Remove VXLAN monitoring script
if [ -f /usr/local/bin/hookprobe-vxlan-monitor ]; then
    echo -e "  ${YELLOW}→${NC} Removing VXLAN monitor script"
    rm -f /usr/local/bin/hookprobe-vxlan-monitor
fi

echo -e "${GREEN}[x]${NC} OVS configuration removed"

# ============================================================
# STEP 6: CLEAN FIREWALL AND ROUTING
# ============================================================
echo ""
echo "[STEP 6] Cleaning firewall and routing..."

if [ -f /etc/nftables/hookprobe-v5.nft ]; then
    rm -f /etc/nftables/hookprobe-v5.nft
    echo -e "${GREEN}[x]${NC} nftables configuration removed"
fi

# Remove HookProbe NAT table (nftables)
if command -v nft &>/dev/null; then
    if nft list table ip hookprobe_nat &>/dev/null 2>&1; then
        echo -e "  ${YELLOW}→${NC} Removing hookprobe_nat table"
        nft delete table ip hookprobe_nat 2>/dev/null || true
        echo -e "  ${GREEN}[x]${NC} NAT table removed"
    fi
fi

# Remove HookProbe NAT rules (iptables fallback)
if command -v iptables &>/dev/null; then
    # Load routing config if exists
    if [ -f /etc/hookprobe/routing.conf ]; then
        source /etc/hookprobe/routing.conf
    fi
    hookprobe_subnet="${HOOKPROBE_SUBNET:-10.250.0.0/16}"
    wan_iface="${WAN_INTERFACE:-}"

    if [ -n "$wan_iface" ]; then
        if iptables -t nat -C POSTROUTING -s "$hookprobe_subnet" -o "$wan_iface" -j MASQUERADE 2>/dev/null; then
            echo -e "  ${YELLOW}→${NC} Removing iptables NAT rule"
            iptables -t nat -D POSTROUTING -s "$hookprobe_subnet" -o "$wan_iface" -j MASQUERADE 2>/dev/null || true
            echo -e "  ${GREEN}[x]${NC} iptables NAT rule removed"
        fi
    fi
fi

# Remove routing config file
if [ -f /etc/hookprobe/routing.conf ]; then
    echo -e "  ${YELLOW}→${NC} Removing routing configuration"
    rm -f /etc/hookprobe/routing.conf
fi

echo -e "${GREEN}[x]${NC} Firewall and routing cleaned"

# ============================================================
# STEP 7: REMOVE KERNEL CONFIGURATION
# ============================================================
echo ""
echo "[STEP 7] Removing kernel configuration..."

if [ -f /etc/sysctl.d/99-hookprobe-v5.conf ]; then
    rm -f /etc/sysctl.d/99-hookprobe-v5.conf
    echo -e "${GREEN}[x]${NC} Kernel sysctl configuration removed"
fi

if [ -f /etc/modules-load.d/hookprobe-v5.conf ]; then
    rm -f /etc/modules-load.d/hookprobe-v5.conf
    echo -e "${GREEN}[x]${NC} Kernel modules configuration removed"
fi

# ============================================================
# STEP 8: REMOVE BUILD AND CONFIG DIRECTORIES
# ============================================================
echo ""
echo "[STEP 8] Removing build and config directories..."

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
        echo -e "  ${YELLOW}→${NC} Removing: $dir"
        rm -rf "$dir"
    fi
done

# Remove HookProbe configuration directory
if [ -d /etc/hookprobe ]; then
    echo ""
    read -p "Remove /etc/hookprobe configuration (contains secrets)? (yes/no): " remove_config

    if [ "$remove_config" == "yes" ]; then
        echo -e "  ${YELLOW}→${NC} Removing /etc/hookprobe (secrets, OVS config, VXLAN PSKs)"
        rm -rf /etc/hookprobe
        echo -e "  ${GREEN}[x]${NC} Configuration removed"
    else
        echo -e "  ${YELLOW}!${NC} Configuration preserved at /etc/hookprobe"
    fi
fi

echo -e "${GREEN}[x]${NC} Build directories removed"

# ============================================================
# STEP 9: REMOVE IMAGES (OPTIONAL)
# ============================================================
echo ""
read -p "Remove HookProbe container images? (yes/no): " remove_images

if [ "$remove_images" == "yes" ]; then
    echo "[STEP 9] Removing images..."

    # Get list of HookProbe-related images
    IMAGES=$(podman images --format "{{.Repository}}:{{.Tag}}" | grep -E "hookprobe|modsecurity|zeek|victoriametrics|victorialogs" 2>/dev/null || true)

    if [ -n "$IMAGES" ]; then
        echo "$IMAGES" | while read -r image; do
            if [ -n "$image" ]; then
                echo -e "  ${YELLOW}→${NC} Removing: $image"
                podman rmi -f "$image" 2>/dev/null || true
            fi
        done
    fi

    # Also remove any dangling images
    podman image prune -af 2>/dev/null || true
    echo -e "${GREEN}[x]${NC} Images removed"
fi

# ============================================================
# STEP 10: STOP OVS (OPTIONAL)
# ============================================================
echo ""
read -p "Stop OVS service? (yes/no): " stop_ovs

if [ "$stop_ovs" == "yes" ]; then
    systemctl stop openvswitch 2>/dev/null || true
    systemctl disable openvswitch 2>/dev/null || true
    echo -e "${GREEN}[x]${NC} OVS stopped"
fi

# ============================================================
# FINAL CLEANUP
# ============================================================
echo ""
echo "[FINAL] System cleanup..."

podman system prune -af --volumes 2>/dev/null || true

ip netns list 2>/dev/null | grep -i hookprobe | while read -r ns; do
    ip netns delete "$ns" 2>/dev/null || true
done

echo -e "${GREEN}[x]${NC} System cleanup complete"

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   HOOKPROBE v5.0 CLEANUP COMPLETE!"
echo "============================================================"
echo ""
echo -e "${GREEN}Removed:${NC}"
echo -e "  ${GREEN}[x]${NC} All PODs (hookprobe-web, iam, database, cache, monitoring, detection, ai, neuro)"
if [ "$remove_volumes" == "yes" ]; then
    echo -e "  ${GREEN}[x]${NC} All data (PERMANENTLY DELETED)"
else
    echo -e "  ${YELLOW}[-]${NC} Volumes preserved"
fi
echo -e "  ${GREEN}[x]${NC} Networks (hookprobe-* podman networks)"
echo -e "  ${GREEN}[x]${NC} OVS bridge ($OVS_BRIDGE_NAME) and VXLAN tunnels"
echo -e "  ${GREEN}[x]${NC} OpenFlow flows"
echo -e "  ${GREEN}[x]${NC} Firewall and NAT routing rules"
echo -e "  ${GREEN}[x]${NC} XDP DDoS mitigation"
echo -e "  ${GREEN}[x]${NC} Kernel configuration"
if [ "$remove_images" == "yes" ]; then
    echo -e "  ${GREEN}[x]${NC} Container images"
fi
if [ "$remove_config" == "yes" ]; then
    echo -e "  ${GREEN}[x]${NC} Configuration and secrets (/etc/hookprobe)"
else
    echo -e "  ${YELLOW}[-]${NC} Configuration preserved (/etc/hookprobe)"
fi
echo ""
echo "To reinstall:"
echo "  1. Review config.sh"
echo "  2. Run: sudo ./install-edge.sh"
echo ""
echo "============================================================"
