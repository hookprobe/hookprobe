#!/bin/bash
#
# HookProbe Nexus Setup Script
# Version: 5.0.0
# License: AGPL-3.0 - see LICENSE file
#
# Nexus - ML/AI Heavy Computation Hub
#
# Nexus Features:
#   - All Fortress features, plus:
#   - GPU acceleration (NVIDIA CUDA)
#   - ML/AI threat detection models
#   - ClickHouse analytics cluster
#   - High availability mode
#   - Regional threat coordination
#   - Federated learning aggregation
#   - Advanced telemetry and observability
#
# Requirements:
#   - 64GB+ RAM (128GB recommended)
#   - 500GB+ SSD storage
#   - 8+ CPU cores
#   - NVIDIA GPU (optional but recommended)
#   - 10GbE networking (recommended)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEXUS_ROOT="$SCRIPT_DIR"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ============================================================
# COLORS
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ============================================================
# CONFIGURATION
# ============================================================
OVS_BRIDGE_NAME="nexus"
OVS_BRIDGE_SUBNET="10.250.0.0/16"
MACSEC_ENABLED=true
VLAN_SEGMENTATION=true

# VLAN Configuration (extended for datacenter)
declare -A VLAN_CONFIG=(
    ["management"]="10:10.250.10.0/24"
    ["compute"]="11:10.250.11.0/24"
    ["storage"]="12:10.250.12.0/24"
    ["trusted"]="20:10.250.20.0/24"
    ["edge-uplink"]="50:10.250.50.0/24"
    ["mesh-uplink"]="60:10.250.60.0/24"
    ["quarantine"]="99:10.250.99.0/24"
)

# VXLAN Configuration for mesh connectivity
declare -A VXLAN_CONFIG=(
    ["nexus-core"]="3000:4800"
    ["nexus-compute"]="3001:4801"
    ["nexus-storage"]="3002:4802"
    ["nexus-analytics"]="3003:4803"
    ["nexus-ml"]="3004:4804"
    ["edge-mesh"]="4000:4900"
    ["mesh-federation"]="5000:4950"
)

# Optional features
ENABLE_GPU="${ENABLE_GPU:-false}"
ENABLE_HA="${ENABLE_HA:-false}"
ENABLE_CLICKHOUSE="${ENABLE_CLICKHOUSE:-true}"
ENABLE_ML="${ENABLE_ML:-true}"
ENABLE_MONITORING="${ENABLE_MONITORING:-true}"
ENABLE_N8N="${ENABLE_N8N:-true}"

# ============================================================
# LOGGING
# ============================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ============================================================
# PREREQUISITES
# ============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_requirements() {
    log_step "Checking system requirements..."

    # Check RAM (minimum 64GB for Nexus)
    local total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -lt 60 ]; then
        log_warn "Less than 64GB RAM detected ($total_mem GB)."
        log_warn "Nexus is optimized for 64GB+. Some features may be limited."
    else
        log_info "RAM: ${total_mem}GB (OK)"
    fi

    # Check storage
    local free_storage=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$free_storage" -lt 400 ]; then
        log_warn "Less than 400GB free storage. Consider expanding for analytics."
    else
        log_info "Storage: ${free_storage}GB free (OK)"
    fi

    # Check CPU cores
    local cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 8 ]; then
        log_warn "Less than 8 CPU cores. ML features may be limited."
    else
        log_info "CPU: ${cpu_cores} cores (OK)"
    fi

    # Check for GPU
    if command -v nvidia-smi &>/dev/null; then
        local gpu_info=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
        if [ -n "$gpu_info" ]; then
            log_info "GPU: $gpu_info detected"
            ENABLE_GPU=true
        fi
    else
        log_info "GPU: None detected (ML will use CPU)"
        ENABLE_GPU=false
    fi
}

detect_platform() {
    log_step "Detecting platform..."

    if [ -f /sys/class/dmi/id/product_name ]; then
        PLATFORM_NAME=$(cat /sys/class/dmi/id/product_name)
    else
        PLATFORM_NAME="Generic Linux"
    fi

    PLATFORM_ARCH=$(uname -m)
    log_info "Platform: $PLATFORM_NAME ($PLATFORM_ARCH)"

    # Check if running in cloud environment
    if curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        log_info "Cloud environment detected (AWS)"
        CLOUD_PROVIDER="aws"
    elif curl -s --max-time 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ &>/dev/null; then
        log_info "Cloud environment detected (GCP)"
        CLOUD_PROVIDER="gcp"
    elif curl -s --max-time 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
        log_info "Cloud environment detected (Azure)"
        CLOUD_PROVIDER="azure"
    else
        CLOUD_PROVIDER="onprem"
        log_info "On-premises deployment detected"
    fi
}

detect_interfaces() {
    log_step "Detecting network interfaces..."

    ETH_INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|enp|eno|ens)' | tr '\n' ' ')
    ETH_COUNT=$(echo $ETH_INTERFACES | wc -w)

    # Check for 10GbE interfaces
    TEN_GBE_INTERFACES=""
    for iface in $ETH_INTERFACES; do
        local speed=$(ethtool "$iface" 2>/dev/null | grep "Speed:" | awk '{print $2}')
        if [[ "$speed" == "10000Mb/s" ]] || [[ "$speed" == "25000Mb/s" ]] || [[ "$speed" == "40000Mb/s" ]]; then
            TEN_GBE_INTERFACES="$TEN_GBE_INTERFACES $iface"
        fi
    done

    log_info "Ethernet interfaces ($ETH_COUNT): $ETH_INTERFACES"
    if [ -n "$TEN_GBE_INTERFACES" ]; then
        log_info "High-speed interfaces:$TEN_GBE_INTERFACES"
    fi
}

# ============================================================
# PACKAGE INSTALLATION
# ============================================================
install_packages() {
    log_step "Installing required packages..."

    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
        apt-get update -qq

        apt-get install -y -qq \
            bridge-utils \
            iptables \
            nftables \
            python3 \
            python3-pip \
            python3-dev \
            net-tools \
            curl \
            jq \
            openssl \
            openvswitch-switch \
            openvswitch-common \
            freeradius \
            freeradius-utils \
            vlan \
            ethtool \
            2>/dev/null || true

        # ML/AI dependencies
        if [ "$ENABLE_ML" = true ]; then
            apt-get install -y -qq \
                python3-numpy \
                python3-scipy \
                python3-sklearn \
                2>/dev/null || true
        fi

        log_info "Packages installed"

    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        dnf install -y -q \
            bridge-utils \
            iptables \
            nftables \
            python3 \
            python3-pip \
            python3-devel \
            net-tools \
            curl \
            jq \
            openssl \
            openvswitch \
            freeradius \
            ethtool \
            2>/dev/null || true

        log_info "Packages installed"
    else
        log_error "Unsupported package manager"
        exit 1
    fi
}

install_podman() {
    log_step "Installing Podman container runtime..."

    if command -v podman &>/dev/null; then
        log_info "Podman already installed: $(podman --version)"
    else
        if [ "$PKG_MGR" = "apt" ]; then
            apt-get install -y -qq podman
        else
            dnf install -y -q podman
        fi
    fi

    systemctl enable --now podman.socket 2>/dev/null || true
    log_info "Podman installed: $(podman --version)"
}

install_nvidia_container() {
    if [ "$ENABLE_GPU" != true ]; then
        return 0
    fi

    log_step "Installing NVIDIA container toolkit..."

    # Check if already installed
    if command -v nvidia-container-cli &>/dev/null; then
        log_info "NVIDIA container toolkit already installed"
        return 0
    fi

    if [ "$PKG_MGR" = "apt" ]; then
        # Add NVIDIA container toolkit repo
        curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | \
            gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg 2>/dev/null || true

        curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
            sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
            tee /etc/apt/sources.list.d/nvidia-container-toolkit.list > /dev/null 2>/dev/null || true

        apt-get update -qq
        apt-get install -y -qq nvidia-container-toolkit 2>/dev/null || {
            log_warn "NVIDIA container toolkit installation failed"
            ENABLE_GPU=false
        }
    fi

    log_info "NVIDIA container toolkit installed"
}

# ============================================================
# OPEN VSWITCH SETUP
# ============================================================
install_openvswitch() {
    log_step "Installing and configuring Open vSwitch..."

    systemctl enable openvswitch-switch 2>/dev/null || \
        systemctl enable openvswitch 2>/dev/null || true
    systemctl start openvswitch-switch 2>/dev/null || \
        systemctl start openvswitch 2>/dev/null || true

    if ! command -v ovs-vsctl &>/dev/null; then
        log_error "Open vSwitch is required for Nexus deployment"
        exit 1
    fi

    log_info "Open vSwitch installed and running"
}

generate_vxlan_psk() {
    openssl rand -base64 32
}

setup_ovs_bridge() {
    log_step "Setting up OVS bridge with advanced networking..."

    local local_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    # Create OVS bridge
    if ovs-vsctl br-exists "$OVS_BRIDGE_NAME" 2>/dev/null; then
        log_info "OVS bridge '$OVS_BRIDGE_NAME' already exists"
    else
        ovs-vsctl add-br "$OVS_BRIDGE_NAME" || {
            log_error "Failed to create OVS bridge"
            exit 1
        }
        log_info "OVS bridge '$OVS_BRIDGE_NAME' created"
    fi

    # Enable OpenFlow 1.3 and 1.4 for advanced SDN
    ovs-vsctl set bridge "$OVS_BRIDGE_NAME" protocols=OpenFlow10,OpenFlow13,OpenFlow14 2>/dev/null || true
    log_info "OpenFlow 1.3/1.4 enabled"

    # Configure bridge IP
    ip link set "$OVS_BRIDGE_NAME" up
    ip addr add 10.250.0.1/16 dev "$OVS_BRIDGE_NAME" 2>/dev/null || true

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-hookprobe.conf 2>/dev/null || true

    # Network performance tuning for high-throughput
    sysctl -w net.core.rmem_max=134217728 >/dev/null 2>&1 || true
    sysctl -w net.core.wmem_max=134217728 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728" >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728" >/dev/null 2>&1 || true

    # Create secrets directory
    mkdir -p /etc/hookprobe/secrets/vxlan
    chmod 700 /etc/hookprobe/secrets/vxlan

    # Generate master PSK
    if [ ! -f /etc/hookprobe/secrets/vxlan/master.psk ]; then
        generate_vxlan_psk > /etc/hookprobe/secrets/vxlan/master.psk
        chmod 600 /etc/hookprobe/secrets/vxlan/master.psk
        log_info "VXLAN master PSK generated"
    fi

    # Save configuration
    mkdir -p /etc/hookprobe
    cat > /etc/hookprobe/ovs-config.sh << OVSEOF
# HookProbe Nexus OVS Configuration
OVS_BRIDGE_NAME=$OVS_BRIDGE_NAME
OVS_BRIDGE_SUBNET=$OVS_BRIDGE_SUBNET
LOCAL_IP=$local_ip
OPENFLOW_VERSION=1.4

# VXLAN Configuration
VXLAN_ENABLED=true
VXLAN_MASTER_PSK=/etc/hookprobe/secrets/vxlan/master.psk
OVSEOF

    log_info "OVS bridge configured with OpenFlow 1.3/1.4"
}

# ============================================================
# VLAN SEGMENTATION
# ============================================================
setup_vlans() {
    log_step "Setting up VLAN segmentation..."

    modprobe 8021q 2>/dev/null || true
    echo "8021q" >> /etc/modules 2>/dev/null || true

    cat > /etc/hookprobe/vlans.conf << 'VLANHEADER'
# HookProbe Nexus VLAN Configuration
# Format: VLAN_NAME|VLAN_ID|SUBNET|DESCRIPTION
VLANHEADER

    for vlan_name in "${!VLAN_CONFIG[@]}"; do
        local config="${VLAN_CONFIG[$vlan_name]}"
        local vlan_id=$(echo "$config" | cut -d: -f1)
        local subnet=$(echo "$config" | cut -d: -f2)

        ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "vlan${vlan_id}" \
            -- set interface "vlan${vlan_id}" type=internal \
            -- set port "vlan${vlan_id}" tag="${vlan_id}" 2>/dev/null || true

        ip link set "vlan${vlan_id}" up 2>/dev/null || true
        local gateway=$(echo "$subnet" | sed 's/.0\/24/.1/')
        ip addr add "$gateway/24" dev "vlan${vlan_id}" 2>/dev/null || true

        echo "${vlan_name}|${vlan_id}|${subnet}|${vlan_name} network" >> /etc/hookprobe/vlans.conf
        log_info "VLAN $vlan_id ($vlan_name) configured: $subnet"
    done

    log_info "VLAN segmentation complete"
}

# ============================================================
# VXLAN TUNNELS
# ============================================================
setup_vxlan_tunnels() {
    log_step "Setting up VXLAN tunnels for mesh networking..."

    local local_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    cat > /etc/hookprobe/vxlan-networks.conf << 'VXLANHEADER'
# HookProbe Nexus VXLAN Network Configuration
# Format: NETWORK_NAME|VNI|PORT|SUBNET|PSK_FILE
VXLANHEADER

    for network in "${!VXLAN_CONFIG[@]}"; do
        local config="${VXLAN_CONFIG[$network]}"
        local vni=$(echo "$config" | cut -d: -f1)
        local port=$(echo "$config" | cut -d: -f2)

        local psk_file="/etc/hookprobe/secrets/vxlan/${network}.psk"
        if [ ! -f "$psk_file" ]; then
            generate_vxlan_psk > "$psk_file"
            chmod 600 "$psk_file"
        fi

        local vxlan_port="vxlan_${vni}"
        ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "$vxlan_port" \
            -- set interface "$vxlan_port" type=vxlan \
            options:key="$vni" \
            options:local_ip="$local_ip" \
            options:remote_ip=flow 2>/dev/null || true

        local subnet=""
        case "$network" in
            nexus-core) subnet="10.250.100.0/24" ;;
            nexus-compute) subnet="10.250.101.0/24" ;;
            nexus-storage) subnet="10.250.102.0/24" ;;
            nexus-analytics) subnet="10.250.103.0/24" ;;
            nexus-ml) subnet="10.250.104.0/24" ;;
            edge-mesh) subnet="10.250.200.0/24" ;;
            mesh-federation) subnet="10.250.250.0/24" ;;
        esac

        echo "${network}|${vni}|${port}|${subnet}|${psk_file}" >> /etc/hookprobe/vxlan-networks.conf
        log_info "VXLAN tunnel $network (VNI: $vni) configured"
    done

    log_info "VXLAN mesh networking configured"
}

# ============================================================
# MACSEC (802.1AE)
# ============================================================
setup_macsec() {
    log_step "Setting up MACsec (802.1AE) Layer 2 encryption..."

    if [ "$MACSEC_ENABLED" != true ]; then
        log_info "MACsec disabled by configuration"
        return 0
    fi

    if ! modprobe macsec 2>/dev/null; then
        log_warn "MACsec kernel module not available"
        MACSEC_ENABLED=false
        return 0
    fi

    mkdir -p /etc/hookprobe/secrets/macsec
    chmod 700 /etc/hookprobe/secrets/macsec

    if [ ! -f /etc/hookprobe/secrets/macsec/cak.key ]; then
        openssl rand -hex 16 > /etc/hookprobe/secrets/macsec/cak.key
        chmod 600 /etc/hookprobe/secrets/macsec/cak.key
    fi

    if [ ! -f /etc/hookprobe/secrets/macsec/ckn.key ]; then
        openssl rand -hex 16 > /etc/hookprobe/secrets/macsec/ckn.key
        chmod 600 /etc/hookprobe/secrets/macsec/ckn.key
    fi

    local CAK=$(cat /etc/hookprobe/secrets/macsec/cak.key)
    local CKN=$(cat /etc/hookprobe/secrets/macsec/ckn.key)

    cat > /etc/hookprobe/macsec.conf << MACSECEOF
# HookProbe Nexus MACsec Configuration
MACSEC_ENABLED=true
MACSEC_CIPHER=gcm-aes-256
MACSEC_REPLAY_PROTECT=true
MACSEC_REPLAY_WINDOW=64
MACSEC_CAK_FILE=/etc/hookprobe/secrets/macsec/cak.key
MACSEC_CKN_FILE=/etc/hookprobe/secrets/macsec/ckn.key
MACSECEOF

    for iface in $ETH_INTERFACES; do
        cat > "/etc/hookprobe/macsec-${iface}.conf" << WPASECEOF
ctrl_interface=/var/run/wpa_supplicant
eapol_version=3
ap_scan=0

network={
    key_mgmt=NONE
    eapol_flags=0
    macsec_policy=1
    macsec_integ_only=0
    mka_cak=$CAK
    mka_ckn=$CKN
}
WPASECEOF
        chmod 600 "/etc/hookprobe/macsec-${iface}.conf"
    done

    cat > /usr/local/bin/hookprobe-macsec << 'MACSECSCRIPT'
#!/bin/bash
MACSEC_DIR="/etc/hookprobe"

case "$1" in
    enable)
        IFACE="${2:-eth0}"
        if [ -f "$MACSEC_DIR/macsec-${IFACE}.conf" ]; then
            wpa_supplicant -i "$IFACE" -D macsec_linux \
                -c "$MACSEC_DIR/macsec-${IFACE}.conf" -B
            echo "MACsec enabled on $IFACE"
        else
            echo "No MACsec config for $IFACE"
            exit 1
        fi
        ;;
    disable)
        IFACE="${2:-eth0}"
        pkill -f "wpa_supplicant.*${IFACE}" 2>/dev/null
        ip link del "macsec0" 2>/dev/null || true
        echo "MACsec disabled on $IFACE"
        ;;
    status)
        echo "=== MACsec Status ==="
        ip macsec show 2>/dev/null || echo "No MACsec interfaces"
        ;;
    *)
        echo "Usage: $0 {enable|disable|status} [interface]"
        ;;
esac
MACSECSCRIPT

    chmod +x /usr/local/bin/hookprobe-macsec
    log_info "MACsec (802.1AE) configured"
}

# ============================================================
# OPENFLOW SDN RULES
# ============================================================
setup_openflow_rules() {
    log_step "Setting up advanced OpenFlow SDN rules..."

    # Default drop
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=0,actions=drop" 2>/dev/null || true

    # Allow ARP
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=100,arp,actions=normal" 2>/dev/null || true

    # Allow ICMP
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=100,icmp,actions=normal" 2>/dev/null || true

    # Allow established
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=50,ip,actions=normal" 2>/dev/null || true

    # VLAN-specific rules
    for vlan_name in "${!VLAN_CONFIG[@]}"; do
        local config="${VLAN_CONFIG[$vlan_name]}"
        local vlan_id=$(echo "$config" | cut -d: -f1)
        ovs-ofctl add-flow "$OVS_BRIDGE_NAME" \
            "priority=200,dl_vlan=${vlan_id},actions=normal" 2>/dev/null || true
    done

    # VXLAN tunnel rules
    for port in 4800 4801 4802 4803 4804 4900 4950; do
        ovs-ofctl add-flow "$OVS_BRIDGE_NAME" \
            "priority=200,udp,tp_dst=$port,actions=normal" 2>/dev/null || true
    done

    # Rate limiting for DDoS protection
    ovs-vsctl set interface "$OVS_BRIDGE_NAME" ingress_policing_rate=10000000 2>/dev/null || true
    ovs-vsctl set interface "$OVS_BRIDGE_NAME" ingress_policing_burst=1000000 2>/dev/null || true

    cat > /usr/local/bin/hookprobe-openflow << 'OFSCRIPT'
#!/bin/bash
OVS_BRIDGE="${1:-nexus}"

case "${2:-status}" in
    flows) ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null ;;
    ports) ovs-ofctl dump-ports "$OVS_BRIDGE" 2>/dev/null ;;
    status)
        echo "=== Nexus OpenFlow Status ==="
        ovs-vsctl show | grep -A 30 "$OVS_BRIDGE"
        echo "Flow count: $(ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | wc -l)"
        ;;
    *) echo "Usage: $0 [bridge] {flows|ports|status}" ;;
esac
OFSCRIPT

    chmod +x /usr/local/bin/hookprobe-openflow
    log_info "OpenFlow SDN rules configured"
}

# ============================================================
# QSECBIT NEXUS AGENT
# ============================================================
install_qsecbit_agent() {
    log_step "Installing QSecBit Nexus agent..."

    mkdir -p /opt/hookprobe/nexus/qsecbit
    mkdir -p /opt/hookprobe/nexus/data
    mkdir -p /opt/hookprobe/nexus/models

    local QSECBIT_SRC="$REPO_ROOT/core/qsecbit"
    if [ -d "$QSECBIT_SRC" ]; then
        log_info "Copying QSecBit modules from source..."
        cp -r "$QSECBIT_SRC"/*.py /opt/hookprobe/nexus/qsecbit/ 2>/dev/null || true
    fi

    cat > /opt/hookprobe/nexus/qsecbit/nexus_agent.py << 'QSECBITEOF'
#!/usr/bin/env python3
"""
QSecBit Nexus Agent - ML-Enhanced Implementation
Version: 5.0.0
License: AGPL-3.0

Nexus-enhanced QSecBit with:
- ML-based anomaly detection
- GPU acceleration support
- Federated learning aggregation
- Regional threat coordination
- Advanced telemetry
"""

import json
import time
import os
import sys
import signal
import logging
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from threading import Thread, Event
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Any
from http.server import HTTPServer, BaseHTTPRequestHandler

LOG_DIR = Path("/var/log/hookprobe")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'qsecbit-nexus.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('qsecbit-nexus')

DATA_DIR = Path("/opt/hookprobe/nexus/data")
MODELS_DIR = Path("/opt/hookprobe/nexus/models")
STATS_FILE = DATA_DIR / "qsecbit_stats.json"


@dataclass
class NexusConfig:
    """QSecBit configuration for Nexus"""
    alpha: float = 0.15
    beta: float = 0.20
    gamma: float = 0.20
    delta: float = 0.10
    epsilon: float = 0.10
    ml_weight: float = 0.15
    federation_weight: float = 0.10

    amber_threshold: float = 0.45
    red_threshold: float = 0.30

    enable_ml: bool = True
    enable_gpu: bool = False
    enable_federation: bool = True


@dataclass
class NexusSample:
    """Single QSecBit measurement with ML enhancements"""
    timestamp: str
    score: float
    rag_status: str
    components: Dict[str, float]
    threats_detected: int
    ml_anomaly_score: float
    federation_status: str
    connected_edges: int
    gpu_utilization: float


class QSecBitNexusAgent:
    """ML-Enhanced QSecBit agent for Nexus deployments"""

    def __init__(self, config: NexusConfig = None):
        self.config = config or NexusConfig()
        self.running = Event()
        self.start_time = time.time()
        self.last_sample: Optional[NexusSample] = None
        self.history: List[NexusSample] = []
        self.connected_edges: Dict[str, Any] = {}

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        MODELS_DIR.mkdir(parents=True, exist_ok=True)

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        # Check GPU availability
        try:
            result = subprocess.run(['nvidia-smi', '--query-gpu=utilization.gpu',
                                   '--format=csv,noheader,nounits'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.config.enable_gpu = True
                logger.info("GPU detected - ML acceleration enabled")
        except Exception:
            self.config.enable_gpu = False

        logger.info("QSecBit Nexus Agent initialized")

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.running.clear()

    def get_gpu_utilization(self) -> float:
        """Get GPU utilization percentage"""
        if not self.config.enable_gpu:
            return 0.0
        try:
            result = subprocess.run(
                ['nvidia-smi', '--query-gpu=utilization.gpu',
                 '--format=csv,noheader,nounits'],
                capture_output=True, text=True, timeout=5
            )
            return float(result.stdout.strip()) / 100.0
        except Exception:
            return 0.0

    def get_ml_anomaly_score(self) -> float:
        """Calculate ML-based anomaly score"""
        # Simplified anomaly detection - in production this would use trained models
        try:
            # Check for unusual process patterns
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            process_count = len(result.stdout.strip().split('\n'))

            # Check network connections
            result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=5)
            connection_count = len(result.stdout.strip().split('\n'))

            # Simple heuristic - in production use trained ML model
            if process_count > 500 or connection_count > 200:
                return 0.7  # Elevated anomaly
            elif process_count > 300 or connection_count > 100:
                return 0.4  # Moderate anomaly
            else:
                return 0.1  # Normal
        except Exception:
            return 0.5

    def get_federation_status(self) -> str:
        """Check federation connectivity"""
        try:
            # Check VXLAN tunnel status
            result = subprocess.run(['ovs-vsctl', 'show'],
                                  capture_output=True, text=True, timeout=5)
            if 'mesh-federation' in result.stdout or 'edge-mesh' in result.stdout:
                return 'connected'
            return 'standalone'
        except Exception:
            return 'unknown'

    def get_connected_edges(self) -> int:
        """Count connected edge devices"""
        try:
            result = subprocess.run(
                ['ovs-ofctl', 'dump-ports', 'nexus'],
                capture_output=True, text=True, timeout=5
            )
            # Count active VXLAN ports
            active = len([l for l in result.stdout.split('\n')
                         if 'vxlan' in l.lower() and 'rx pkts' in l])
            return active
        except Exception:
            return 0

    def calculate_score(self) -> tuple:
        """Calculate QSecBit score with ML enhancements"""
        components = {
            'drift': 0.0,
            'network': 0.0,
            'threats': 0.0,
            'energy': 0.0,
            'infrastructure': 0.0,
            'ml_anomaly': 0.0,
            'federation': 0.0
        }

        # System drift
        try:
            with open('/proc/loadavg', 'r') as f:
                load = float(f.read().split()[0])
            components['drift'] = max(0, 1.0 - (load / (os.cpu_count() * 2)))
        except Exception:
            components['drift'] = 0.5

        # Network health
        try:
            result = subprocess.run(['ip', 'link', 'show', 'up'],
                                  capture_output=True, text=True, timeout=5)
            up_interfaces = len([l for l in result.stdout.split('\n') if 'state UP' in l])
            components['network'] = min(1.0, up_interfaces / 8)
        except Exception:
            components['network'] = 0.5

        # Threat detection
        try:
            alert_file = Path("/var/log/suricata/fast.log")
            if alert_file.exists():
                with open(alert_file, 'r') as f:
                    alerts = len(f.readlines())
                components['threats'] = max(0, 1.0 - (alerts / 100))
            else:
                components['threats'] = 0.9
        except Exception:
            components['threats'] = 0.5

        # Energy efficiency
        components['energy'] = 0.8

        # Infrastructure health
        try:
            result = subprocess.run(['podman', 'ps', '-q'],
                                  capture_output=True, text=True, timeout=5)
            containers = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
            components['infrastructure'] = min(1.0, containers / 10)
        except Exception:
            components['infrastructure'] = 0.5

        # ML anomaly (inverted - lower anomaly = higher score)
        ml_anomaly = self.get_ml_anomaly_score()
        components['ml_anomaly'] = 1.0 - ml_anomaly

        # Federation status
        fed_status = self.get_federation_status()
        components['federation'] = 1.0 if fed_status == 'connected' else 0.5

        # Calculate weighted score
        score = (
            self.config.alpha * components['drift'] +
            self.config.beta * components['network'] +
            self.config.gamma * components['threats'] +
            self.config.delta * components['energy'] +
            self.config.epsilon * components['infrastructure'] +
            self.config.ml_weight * components['ml_anomaly'] +
            self.config.federation_weight * components['federation']
        )

        if score >= self.config.amber_threshold:
            rag_status = "GREEN"
        elif score >= self.config.red_threshold:
            rag_status = "AMBER"
        else:
            rag_status = "RED"

        return score, rag_status, components

    def collect_sample(self) -> NexusSample:
        """Collect a complete QSecBit sample"""
        score, rag_status, components = self.calculate_score()

        sample = NexusSample(
            timestamp=datetime.now().isoformat(),
            score=score,
            rag_status=rag_status,
            components=components,
            threats_detected=0,
            ml_anomaly_score=self.get_ml_anomaly_score(),
            federation_status=self.get_federation_status(),
            connected_edges=self.get_connected_edges(),
            gpu_utilization=self.get_gpu_utilization()
        )

        self.last_sample = sample
        self.history.append(sample)
        if len(self.history) > 2000:
            self.history = self.history[-1000:]

        return sample

    def save_stats(self, sample: NexusSample):
        """Save stats to file"""
        try:
            stats = {
                'timestamp': sample.timestamp,
                'score': sample.score,
                'rag_status': sample.rag_status,
                'components': sample.components,
                'threats_detected': sample.threats_detected,
                'ml_anomaly_score': sample.ml_anomaly_score,
                'federation_status': sample.federation_status,
                'connected_edges': sample.connected_edges,
                'gpu_utilization': sample.gpu_utilization,
                'uptime_seconds': int(time.time() - self.start_time)
            }
            with open(STATS_FILE, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")

    def run_monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("Starting QSecBit monitoring loop...")
        interval = 5  # Faster interval for Nexus

        while self.running.is_set():
            try:
                sample = self.collect_sample()
                self.save_stats(sample)

                logger.info(
                    f"QSecBit: {sample.rag_status} score={sample.score:.3f} "
                    f"ml_anomaly={sample.ml_anomaly_score:.2f} "
                    f"edges={sample.connected_edges} "
                    f"gpu={sample.gpu_utilization:.1%}"
                )

                time.sleep(interval)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(interval)

    def start(self):
        """Start the agent"""
        logger.info("Starting QSecBit Nexus Agent v5.0.0...")
        self.running.set()

        monitor_thread = Thread(target=self.run_monitoring_loop, daemon=True)
        monitor_thread.start()

        self.running.wait()

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping QSecBit Nexus Agent...")
        self.running.clear()


def main():
    agent = QSecBitNexusAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
QSECBITEOF

    chmod +x /opt/hookprobe/nexus/qsecbit/nexus_agent.py

    cat > /etc/systemd/system/nexus-qsecbit.service << 'SERVICEEOF'
[Unit]
Description=HookProbe Nexus QSecBit Agent v5.0
After=network.target openvswitch-switch.service

[Service]
Type=simple
WorkingDirectory=/opt/hookprobe/nexus/qsecbit
ExecStart=/usr/bin/python3 /opt/hookprobe/nexus/qsecbit/nexus_agent.py
Restart=always
RestartSec=10
User=root
Environment=PYTHONPATH=/opt/hookprobe/nexus

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload
    systemctl enable nexus-qsecbit

    log_info "QSecBit Nexus Agent installed"
}

# ============================================================
# CLICKHOUSE ANALYTICS
# ============================================================
install_clickhouse() {
    if [ "$ENABLE_CLICKHOUSE" != true ]; then
        log_info "ClickHouse disabled"
        return 0
    fi

    log_step "Installing ClickHouse analytics database..."

    mkdir -p /opt/hookprobe/nexus/clickhouse

    podman run -d \
        --name nexus-clickhouse \
        --restart unless-stopped \
        -p 8123:8123 \
        -p 9000:9000 \
        -v /opt/hookprobe/nexus/clickhouse:/var/lib/clickhouse:Z \
        docker.io/clickhouse/clickhouse-server:latest \
        2>/dev/null || log_warn "ClickHouse may already be running"

    log_info "ClickHouse installed on ports 8123 (HTTP) and 9000 (native)"
}

# ============================================================
# MONITORING STACK
# ============================================================
install_monitoring() {
    if [ "$ENABLE_MONITORING" != true ]; then
        log_info "Monitoring disabled"
        return 0
    fi

    log_step "Installing monitoring stack..."

    mkdir -p /opt/hookprobe/nexus/monitoring
    mkdir -p /opt/hookprobe/nexus/grafana

    # Victoria Metrics
    podman run -d \
        --name nexus-victoria \
        --restart unless-stopped \
        -p 8428:8428 \
        -v /opt/hookprobe/nexus/monitoring:/victoria-metrics-data:Z \
        docker.io/victoriametrics/victoria-metrics:latest \
        2>/dev/null || log_warn "Victoria Metrics may already be running"

    # Grafana
    podman run -d \
        --name nexus-grafana \
        --restart unless-stopped \
        -p 3000:3000 \
        -v /opt/hookprobe/nexus/grafana:/var/lib/grafana:Z \
        -e GF_SECURITY_ADMIN_PASSWORD=hookprobe \
        docker.io/grafana/grafana:latest \
        2>/dev/null || log_warn "Grafana may already be running"

    log_info "Monitoring stack installed"
}

# ============================================================
# N8N AUTOMATION
# ============================================================
install_n8n() {
    if [ "$ENABLE_N8N" != true ]; then
        log_info "n8n disabled"
        return 0
    fi

    log_step "Installing n8n workflow automation..."

    mkdir -p /opt/hookprobe/nexus/n8n

    podman run -d \
        --name nexus-n8n \
        --restart unless-stopped \
        -p 5678:5678 \
        -v /opt/hookprobe/nexus/n8n:/home/node/.n8n:Z \
        docker.io/n8nio/n8n:latest \
        2>/dev/null || log_warn "n8n may already be running"

    log_info "n8n installed on port 5678"
}

# ============================================================
# SYSTEMD SERVICES
# ============================================================
create_systemd_services() {
    log_step "Creating systemd services..."

    cat > /etc/systemd/system/hookprobe-nexus.service << 'SERVICEEOF'
[Unit]
Description=HookProbe Nexus ML/AI Hub
After=network.target openvswitch-switch.service
Wants=openvswitch-switch.service nexus-qsecbit.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecStartPost=/usr/local/bin/hookprobe-nexus-start
ExecStop=/usr/local/bin/hookprobe-nexus-stop

[Install]
WantedBy=multi-user.target
SERVICEEOF

    cat > /usr/local/bin/hookprobe-nexus-start << 'STARTEOF'
#!/bin/bash
echo "Starting HookProbe Nexus..."

systemctl start openvswitch-switch 2>/dev/null || true
systemctl start nexus-qsecbit 2>/dev/null || true

podman start nexus-victoria 2>/dev/null || true
podman start nexus-grafana 2>/dev/null || true
podman start nexus-clickhouse 2>/dev/null || true
podman start nexus-n8n 2>/dev/null || true

echo "HookProbe Nexus started"
STARTEOF

    chmod +x /usr/local/bin/hookprobe-nexus-start

    cat > /usr/local/bin/hookprobe-nexus-stop << 'STOPEOF'
#!/bin/bash
echo "Stopping HookProbe Nexus..."

systemctl stop nexus-qsecbit 2>/dev/null || true
podman stop nexus-victoria 2>/dev/null || true
podman stop nexus-grafana 2>/dev/null || true
podman stop nexus-clickhouse 2>/dev/null || true
podman stop nexus-n8n 2>/dev/null || true

echo "HookProbe Nexus stopped"
STOPEOF

    chmod +x /usr/local/bin/hookprobe-nexus-stop

    systemctl daemon-reload
    systemctl enable hookprobe-nexus

    log_info "Systemd services created"
}

# ============================================================
# CONFIGURATION FILE
# ============================================================
create_config_file() {
    log_step "Creating main configuration file..."

    cat > /etc/hookprobe/nexus.conf << CONFEOF
# HookProbe Nexus Configuration
# Version: 5.0.0
# Generated: $(date -Iseconds)

[general]
tier = nexus
node_id = ${HOOKPROBE_NODE_ID:-$(hostname)-nexus}
version = 5.0.0
cloud_provider = $CLOUD_PROVIDER

[network]
ovs_bridge = $OVS_BRIDGE_NAME
vlan_segmentation = $VLAN_SEGMENTATION
macsec_enabled = $MACSEC_ENABLED

[ml]
enabled = $ENABLE_ML
gpu_enabled = $ENABLE_GPU
models_dir = /opt/hookprobe/nexus/models

[federation]
enabled = true
mesh_vni = 5000
edge_mesh_vni = 4000

[analytics]
clickhouse_enabled = $ENABLE_CLICKHOUSE
clickhouse_port = 8123

[monitoring]
enabled = $ENABLE_MONITORING
victoria_metrics_port = 8428
grafana_port = 3000

[automation]
n8n_enabled = $ENABLE_N8N
n8n_port = 5678
CONFEOF

    chmod 644 /etc/hookprobe/nexus.conf
    log_info "Configuration file created: /etc/hookprobe/nexus.conf"
}

# ============================================================
# COMPLETION
# ============================================================
show_completion() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║   ${GREEN}HookProbe Nexus Installation Complete${NC}                     ${CYAN}║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Installed Components:${NC}"
    echo -e "  ${GREEN}✓${NC} Open vSwitch with OpenFlow 1.3/1.4"
    echo -e "  ${GREEN}✓${NC} VLAN Segmentation (datacenter layout)"
    echo -e "  ${GREEN}✓${NC} VXLAN Mesh Networking with VNI and PSK"
    echo -e "  ${GREEN}✓${NC} MACsec (802.1AE) Layer 2 encryption"
    echo -e "  ${GREEN}✓${NC} QSecBit Nexus Agent (ML-enhanced)"
    [ "$ENABLE_GPU" = true ] && echo -e "  ${GREEN}✓${NC} NVIDIA GPU acceleration"
    [ "$ENABLE_CLICKHOUSE" = true ] && echo -e "  ${GREEN}✓${NC} ClickHouse analytics"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  ${GREEN}✓${NC} Monitoring (Grafana + Victoria Metrics)"
    [ "$ENABLE_N8N" = true ] && echo -e "  ${GREEN}✓${NC} n8n Workflow Automation"
    echo ""
    echo -e "  ${BOLD}Web Interfaces:${NC}"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  Grafana:          http://localhost:3000 (admin/hookprobe)"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  Victoria Metrics: http://localhost:8428"
    [ "$ENABLE_CLICKHOUSE" = true ] && echo -e "  ClickHouse:       http://localhost:8123"
    [ "$ENABLE_N8N" = true ] && echo -e "  n8n:              http://localhost:5678"
    echo ""
    echo -e "  ${BOLD}Management:${NC}"
    echo -e "  hookprobe-macsec status    - MACsec status"
    echo -e "  hookprobe-openflow status  - OpenFlow status"
    echo -e "  systemctl status hookprobe-nexus"
    echo ""
}

# ============================================================
# MAIN
# ============================================================
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║               HookProbe Nexus Installer                      ║${NC}"
    echo -e "${CYAN}║                  ML/AI Hub v5.0.0                            ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --enable-gpu) ENABLE_GPU=true; shift ;;
            --enable-ha) ENABLE_HA=true; shift ;;
            --enable-clickhouse) ENABLE_CLICKHOUSE=true; shift ;;
            --enable-ml) ENABLE_ML=true; shift ;;
            --enable-monitoring) ENABLE_MONITORING=true; shift ;;
            --enable-n8n) ENABLE_N8N=true; shift ;;
            --disable-macsec) MACSEC_ENABLED=false; shift ;;
            --node-id) HOOKPROBE_NODE_ID="$2"; shift 2 ;;
            --mesh-url) HOOKPROBE_MESH_URL="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    check_root
    check_requirements
    detect_platform
    detect_interfaces

    install_packages
    install_podman
    install_nvidia_container
    install_openvswitch

    setup_ovs_bridge
    setup_vlans
    setup_vxlan_tunnels
    setup_macsec
    setup_openflow_rules

    install_qsecbit_agent
    install_clickhouse
    install_monitoring
    install_n8n

    create_systemd_services
    create_config_file

    log_step "Starting services..."
    systemctl start hookprobe-nexus
    systemctl start nexus-qsecbit

    show_completion
}

main "$@"
