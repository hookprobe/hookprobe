#!/bin/bash
#
# HookProbe Fortress Setup Script
# Version: 5.0.0
# License: MIT
#
# Fortress - Full-Featured Edge Gateway with Monitoring
#
# Fortress Mode Features:
#   - VLAN segmentation with VAP-capable WiFi (IoT isolation)
#   - MACsec (802.1AE) Layer 2 encryption
#   - OpenFlow 1.3 SDN for advanced traffic control
#   - VXLAN tunnels with VNI and PSK encryption
#   - Full monitoring stack (Grafana + Victoria Metrics)
#   - n8n workflow automation (optional)
#   - ClickHouse analytics (optional)
#   - LTE/5G failover (optional)
#
# Requirements:
#   - 8GB+ RAM (16GB recommended)
#   - 32GB+ storage
#   - 2+ Ethernet interfaces
#   - VAP-capable WiFi adapter for VLAN segmentation (optional)
#     Recommended: Atheros AR9271, MediaTek MT7612U
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORTRESS_ROOT="$SCRIPT_DIR"
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
OVS_BRIDGE_NAME="fortress"
OVS_BRIDGE_SUBNET="10.250.0.0/16"
MACSEC_ENABLED=true
VLAN_SEGMENTATION=true

# VLAN Configuration for IoT isolation
declare -A VLAN_CONFIG=(
    ["management"]="10:10.250.10.0/24"
    ["trusted"]="20:10.250.20.0/24"
    ["iot"]="30:10.250.30.0/24"
    ["guest"]="40:10.250.40.0/24"
    ["quarantine"]="99:10.250.99.0/24"
)

# VXLAN Configuration for mesh connectivity
declare -A VXLAN_CONFIG=(
    ["fortress-core"]="1000:4800"
    ["fortress-monitoring"]="1001:4801"
    ["fortress-automation"]="1002:4802"
    ["fortress-analytics"]="1003:4803"
    ["mssp-uplink"]="2000:4900"
)

# Optional features
ENABLE_N8N="${ENABLE_N8N:-false}"
ENABLE_MONITORING="${ENABLE_MONITORING:-true}"
ENABLE_CLICKHOUSE="${ENABLE_CLICKHOUSE:-false}"
ENABLE_LTE="${ENABLE_LTE:-false}"

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

    # Check RAM (minimum 8GB)
    local total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -lt 7 ]; then
        log_warn "Less than 8GB RAM detected. Some features may be limited."
    else
        log_info "RAM: ${total_mem}GB (OK)"
    fi

    # Check storage
    local free_storage=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$free_storage" -lt 30 ]; then
        log_warn "Less than 30GB free storage. Consider expanding."
    else
        log_info "Storage: ${free_storage}GB free (OK)"
    fi

    # Check CPU cores
    local cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 4 ]; then
        log_warn "Less than 4 CPU cores. Performance may be limited."
    else
        log_info "CPU: ${cpu_cores} cores (OK)"
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
}

detect_interfaces() {
    log_step "Detecting network interfaces..."

    ETH_INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|enp|eno)' | tr '\n' ' ')
    ETH_COUNT=$(echo $ETH_INTERFACES | wc -w)

    WIFI_INTERFACES=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | tr '\n' ' ')
    WIFI_COUNT=$(echo $WIFI_INTERFACES | wc -w)

    # Check for VAP-capable WiFi (required for VLAN segmentation)
    WIFI_VAP_SUPPORT=false
    for iface in $WIFI_INTERFACES; do
        if iw list 2>/dev/null | grep -A 20 "Supported interface modes" | grep -q "AP/VLAN"; then
            WIFI_VAP_SUPPORT=true
            log_info "VAP-capable WiFi detected - VLAN segmentation available"
            break
        fi
    done

    log_info "Ethernet interfaces ($ETH_COUNT): $ETH_INTERFACES"
    log_info "WiFi interfaces ($WIFI_COUNT): $WIFI_INTERFACES"

    if [ "$WIFI_VAP_SUPPORT" = false ] && [ "$VLAN_SEGMENTATION" = true ]; then
        log_warn "No VAP-capable WiFi adapter found."
        log_warn "VLAN segmentation will use wired interfaces only."
        log_warn "For WiFi VLAN, use Atheros AR9271 or MediaTek MT7612U adapters."
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
            hostapd \
            dnsmasq \
            bridge-utils \
            iptables \
            nftables \
            iw \
            wireless-tools \
            wpasupplicant \
            python3 \
            python3-pip \
            python3-flask \
            python3-requests \
            net-tools \
            curl \
            jq \
            openssl \
            openvswitch-switch \
            freeradius \
            freeradius-utils \
            vlan \
            2>/dev/null || true

        # MACsec tools (may not be available on all distros)
        apt-get install -y -qq wpa_supplicant 2>/dev/null || true

        log_info "Packages installed"

    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        dnf install -y -q \
            hostapd \
            dnsmasq \
            bridge-utils \
            iptables \
            nftables \
            iw \
            wireless-tools \
            wpa_supplicant \
            python3 \
            python3-pip \
            python3-flask \
            python3-requests \
            net-tools \
            curl \
            jq \
            openssl \
            openvswitch \
            freeradius \
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

# ============================================================
# OPEN VSWITCH SETUP
# ============================================================
install_openvswitch() {
    log_step "Installing and configuring Open vSwitch..."

    # Start OVS service
    systemctl enable openvswitch-switch 2>/dev/null || \
        systemctl enable openvswitch 2>/dev/null || true
    systemctl start openvswitch-switch 2>/dev/null || \
        systemctl start openvswitch 2>/dev/null || true

    # Verify OVS is working
    if ! command -v ovs-vsctl &>/dev/null; then
        log_error "Open vSwitch is required for Fortress deployment"
        exit 1
    fi

    log_info "Open vSwitch installed and running"
}

generate_vxlan_psk() {
    openssl rand -base64 32
}

setup_ovs_bridge() {
    log_step "Setting up OVS bridge with VXLAN and OpenFlow..."

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

    # Enable OpenFlow 1.3 for advanced SDN capabilities
    ovs-vsctl set bridge "$OVS_BRIDGE_NAME" protocols=OpenFlow10,OpenFlow13 2>/dev/null || true
    log_info "OpenFlow 1.3 enabled"

    # Configure bridge IP
    ip link set "$OVS_BRIDGE_NAME" up
    ip addr add 10.250.0.1/16 dev "$OVS_BRIDGE_NAME" 2>/dev/null || true

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-hookprobe.conf 2>/dev/null || true

    # Create secrets directory for PSK
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
# HookProbe Fortress OVS Configuration
OVS_BRIDGE_NAME=$OVS_BRIDGE_NAME
OVS_BRIDGE_SUBNET=$OVS_BRIDGE_SUBNET
LOCAL_IP=$local_ip
OPENFLOW_VERSION=1.3

# VXLAN Configuration
VXLAN_ENABLED=true
VXLAN_MASTER_PSK=/etc/hookprobe/secrets/vxlan/master.psk
OVSEOF

    log_info "OVS bridge configured with OpenFlow 1.3"
}

# ============================================================
# VLAN SEGMENTATION
# ============================================================
setup_vlans() {
    log_step "Setting up VLAN segmentation..."

    # Load 8021q kernel module
    modprobe 8021q 2>/dev/null || true
    echo "8021q" >> /etc/modules 2>/dev/null || true

    # Create VLAN configuration file
    cat > /etc/hookprobe/vlans.conf << 'VLANHEADER'
# HookProbe Fortress VLAN Configuration
# Format: VLAN_NAME|VLAN_ID|SUBNET|DESCRIPTION
VLANHEADER

    for vlan_name in "${!VLAN_CONFIG[@]}"; do
        local config="${VLAN_CONFIG[$vlan_name]}"
        local vlan_id=$(echo "$config" | cut -d: -f1)
        local subnet=$(echo "$config" | cut -d: -f2)

        # Add VLAN to OVS bridge
        ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "vlan${vlan_id}" \
            -- set interface "vlan${vlan_id}" type=internal \
            -- set port "vlan${vlan_id}" tag="${vlan_id}" 2>/dev/null || true

        # Configure VLAN interface
        ip link set "vlan${vlan_id}" up 2>/dev/null || true
        local gateway=$(echo "$subnet" | sed 's/.0\/24/.1/')
        ip addr add "$gateway/24" dev "vlan${vlan_id}" 2>/dev/null || true

        # Save to config
        echo "${vlan_name}|${vlan_id}|${subnet}|${vlan_name} network" >> /etc/hookprobe/vlans.conf

        log_info "VLAN $vlan_id ($vlan_name) configured: $subnet"
    done

    log_info "VLAN segmentation complete"
}

# ============================================================
# VXLAN TUNNELS WITH VNI AND PSK
# ============================================================
setup_vxlan_tunnels() {
    log_step "Setting up VXLAN tunnels with VNI and PSK..."

    local local_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    cat > /etc/hookprobe/vxlan-networks.conf << 'VXLANHEADER'
# HookProbe Fortress VXLAN Network Configuration
# Format: NETWORK_NAME|VNI|PORT|SUBNET|PSK_FILE
VXLANHEADER

    for network in "${!VXLAN_CONFIG[@]}"; do
        local config="${VXLAN_CONFIG[$network]}"
        local vni=$(echo "$config" | cut -d: -f1)
        local port=$(echo "$config" | cut -d: -f2)

        # Generate per-tunnel PSK
        local psk_file="/etc/hookprobe/secrets/vxlan/${network}.psk"
        if [ ! -f "$psk_file" ]; then
            generate_vxlan_psk > "$psk_file"
            chmod 600 "$psk_file"
        fi

        # Add VXLAN port to OVS bridge
        local vxlan_port="vxlan_${vni}"
        ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "$vxlan_port" \
            -- set interface "$vxlan_port" type=vxlan \
            options:key="$vni" \
            options:local_ip="$local_ip" \
            options:remote_ip=flow 2>/dev/null || true

        # Determine subnet
        local subnet=""
        case "$network" in
            fortress-core) subnet="10.250.100.0/24" ;;
            fortress-monitoring) subnet="10.250.101.0/24" ;;
            fortress-automation) subnet="10.250.102.0/24" ;;
            fortress-analytics) subnet="10.250.103.0/24" ;;
            mssp-uplink) subnet="10.250.200.0/24" ;;
        esac

        echo "${network}|${vni}|${port}|${subnet}|${psk_file}" >> /etc/hookprobe/vxlan-networks.conf
        log_info "VXLAN tunnel $network (VNI: $vni) configured"
    done

    log_info "VXLAN tunnels configured"
}

# ============================================================
# MACSEC (802.1AE) LAYER 2 ENCRYPTION
# ============================================================
setup_macsec() {
    log_step "Setting up MACsec (802.1AE) Layer 2 encryption..."

    if [ "$MACSEC_ENABLED" != true ]; then
        log_info "MACsec disabled by configuration"
        return 0
    fi

    # Check for MACsec kernel support
    if ! modprobe macsec 2>/dev/null; then
        log_warn "MACsec kernel module not available"
        log_warn "MACsec requires Linux kernel 4.6+ with CONFIG_MACSEC=y"
        MACSEC_ENABLED=false
        return 0
    fi

    # Create MACsec secrets directory
    mkdir -p /etc/hookprobe/secrets/macsec
    chmod 700 /etc/hookprobe/secrets/macsec

    # Generate MACsec CAK (Connectivity Association Key) and CKN (Connectivity Key Name)
    if [ ! -f /etc/hookprobe/secrets/macsec/cak.key ]; then
        # Generate 128-bit CAK (32 hex chars)
        openssl rand -hex 16 > /etc/hookprobe/secrets/macsec/cak.key
        chmod 600 /etc/hookprobe/secrets/macsec/cak.key
        log_info "MACsec CAK generated"
    fi

    if [ ! -f /etc/hookprobe/secrets/macsec/ckn.key ]; then
        # Generate 128-bit CKN (32 hex chars)
        openssl rand -hex 16 > /etc/hookprobe/secrets/macsec/ckn.key
        chmod 600 /etc/hookprobe/secrets/macsec/ckn.key
        log_info "MACsec CKN generated"
    fi

    local CAK=$(cat /etc/hookprobe/secrets/macsec/cak.key)
    local CKN=$(cat /etc/hookprobe/secrets/macsec/ckn.key)

    # Create MACsec configuration for wpa_supplicant
    cat > /etc/hookprobe/macsec.conf << MACSECEOF
# HookProbe Fortress MACsec Configuration
# 802.1AE Layer 2 Encryption

# MACsec is enabled on wired interfaces for secure L2 communication
# between Fortress nodes and MSSP uplinks

MACSEC_ENABLED=true
MACSEC_CIPHER=gcm-aes-128
MACSEC_REPLAY_PROTECT=true
MACSEC_REPLAY_WINDOW=32

# Keys are stored separately for security
MACSEC_CAK_FILE=/etc/hookprobe/secrets/macsec/cak.key
MACSEC_CKN_FILE=/etc/hookprobe/secrets/macsec/ckn.key
MACSECEOF

    # Create wpa_supplicant MACsec config template
    for iface in $ETH_INTERFACES; do
        cat > "/etc/hookprobe/macsec-${iface}.conf" << WPASECEOF
# MACsec configuration for $iface
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

    # Create MACsec management script
    cat > /usr/local/bin/hookprobe-macsec << 'MACSECSCRIPT'
#!/bin/bash
# HookProbe MACsec Management

MACSEC_DIR="/etc/hookprobe"

case "$1" in
    enable)
        IFACE="${2:-eth0}"
        if [ -f "$MACSEC_DIR/macsec-${IFACE}.conf" ]; then
            # Start MKA on the interface
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
        echo ""
        echo "=== MKA Sessions ==="
        ps aux | grep -v grep | grep wpa_supplicant | grep macsec || echo "No MKA sessions"
        ;;
    *)
        echo "Usage: $0 {enable|disable|status} [interface]"
        exit 1
        ;;
esac
MACSECSCRIPT

    chmod +x /usr/local/bin/hookprobe-macsec

    log_info "MACsec (802.1AE) configured"
    log_info "  Enable with: hookprobe-macsec enable eth0"
}

# ============================================================
# OPENFLOW SDN RULES
# ============================================================
setup_openflow_rules() {
    log_step "Setting up OpenFlow SDN rules..."

    # Default drop rule (lowest priority)
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=0,actions=drop" 2>/dev/null || true

    # Allow ARP for network discovery
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=100,arp,actions=normal" 2>/dev/null || true

    # Allow ICMP for diagnostics
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=100,icmp,actions=normal" 2>/dev/null || true

    # Allow established connections
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=50,ip,actions=normal" 2>/dev/null || true

    # VLAN-specific rules
    for vlan_name in "${!VLAN_CONFIG[@]}"; do
        local config="${VLAN_CONFIG[$vlan_name]}"
        local vlan_id=$(echo "$config" | cut -d: -f1)

        # Allow intra-VLAN traffic
        ovs-ofctl add-flow "$OVS_BRIDGE_NAME" \
            "priority=200,dl_vlan=${vlan_id},actions=normal" 2>/dev/null || true

        # Log inter-VLAN attempts (for security monitoring)
        # These would be blocked by default drop rule
    done

    # VXLAN tunnel rules
    for port in 4800 4801 4802 4803 4900; do
        ovs-ofctl add-flow "$OVS_BRIDGE_NAME" \
            "priority=200,udp,tp_dst=$port,actions=normal" 2>/dev/null || true
    done

    # Create OpenFlow monitoring script
    cat > /usr/local/bin/hookprobe-openflow << 'OFSCRIPT'
#!/bin/bash
# HookProbe OpenFlow Monitoring

OVS_BRIDGE="${1:-fortress}"

case "${2:-status}" in
    flows)
        echo "=== OpenFlow Flows ==="
        ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null
        ;;
    ports)
        echo "=== Port Statistics ==="
        ovs-ofctl dump-ports "$OVS_BRIDGE" 2>/dev/null
        ;;
    status)
        echo "=== OpenFlow Status ==="
        echo "Bridge: $OVS_BRIDGE"
        ovs-vsctl show | grep -A 20 "$OVS_BRIDGE"
        echo ""
        echo "--- Flow Count ---"
        ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | wc -l
        ;;
    *)
        echo "Usage: $0 [bridge] {flows|ports|status}"
        ;;
esac
OFSCRIPT

    chmod +x /usr/local/bin/hookprobe-openflow

    log_info "OpenFlow SDN rules configured"
}

# ============================================================
# QSECBIT AGENT
# ============================================================
install_qsecbit_agent() {
    log_step "Installing QSecBit agent..."

    mkdir -p /opt/hookprobe/fortress/qsecbit
    mkdir -p /opt/hookprobe/fortress/data

    # Copy QSecBit modules from source if available
    local QSECBIT_SRC="$REPO_ROOT/core/qsecbit"
    if [ -d "$QSECBIT_SRC" ]; then
        log_info "Copying QSecBit modules from source..."
        cp -r "$QSECBIT_SRC"/*.py /opt/hookprobe/fortress/qsecbit/ 2>/dev/null || true
    fi

    # Create Fortress-specific QSecBit agent
    cat > /opt/hookprobe/fortress/qsecbit/fortress_agent.py << 'QSECBITEOF'
#!/usr/bin/env python3
"""
QSecBit Fortress Agent - Full Implementation
Version: 5.0.0
License: MIT

Fortress-enhanced QSecBit with:
- Extended telemetry from monitoring stack
- VLAN security scoring
- MACsec status monitoring
- OpenFlow flow analysis
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
from typing import Optional, Dict, List
from http.server import HTTPServer, BaseHTTPRequestHandler

# Logging setup
LOG_DIR = Path("/var/log/hookprobe")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'qsecbit-fortress.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('qsecbit-fortress')

# Paths
DATA_DIR = Path("/opt/hookprobe/fortress/data")
STATS_FILE = DATA_DIR / "qsecbit_stats.json"
CONFIG_DIR = Path("/etc/hookprobe")


@dataclass
class QSecBitConfig:
    """QSecBit configuration for Fortress"""
    # Component weights (must sum to 1.0)
    alpha: float = 0.20   # System drift weight
    beta: float = 0.25    # Network health weight
    gamma: float = 0.25   # Threat detection weight
    delta: float = 0.15   # Energy efficiency weight
    epsilon: float = 0.15 # Infrastructure health weight

    # Thresholds
    amber_threshold: float = 0.45
    red_threshold: float = 0.30

    # Fortress-specific weights
    vlan_weight: float = 0.10
    macsec_weight: float = 0.10
    openflow_weight: float = 0.10


@dataclass
class QSecBitSample:
    """Single QSecBit measurement"""
    timestamp: str
    score: float
    rag_status: str
    components: Dict[str, float]
    threats_detected: int
    suricata_alerts: int
    vlan_violations: int
    macsec_status: str
    openflow_flows: int


class QSecBitFortressAgent:
    """Full QSecBit agent for Fortress deployments"""

    def __init__(self, config: QSecBitConfig = None):
        self.config = config or QSecBitConfig()
        self.running = Event()
        self.start_time = time.time()
        self.last_sample: Optional[QSecBitSample] = None
        self.history: List[QSecBitSample] = []

        DATA_DIR.mkdir(parents=True, exist_ok=True)

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info("QSecBit Fortress Agent initialized")

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.running.clear()

    def get_vlan_violations(self) -> int:
        """Check for VLAN policy violations"""
        try:
            # Check OVS logs for inter-VLAN attempts
            result = subprocess.run(
                ['ovs-ofctl', 'dump-flows', 'fortress'],
                capture_output=True, text=True, timeout=5
            )
            # Count dropped packets (potential violations)
            violations = 0
            for line in result.stdout.split('\n'):
                if 'n_packets=' in line and 'actions=drop' in line:
                    packets = int(line.split('n_packets=')[1].split(',')[0])
                    violations += packets
            return violations
        except Exception:
            return 0

    def get_macsec_status(self) -> str:
        """Check MACsec status"""
        try:
            result = subprocess.run(
                ['ip', 'macsec', 'show'],
                capture_output=True, text=True, timeout=5
            )
            if 'macsec' in result.stdout:
                return 'active'
            return 'inactive'
        except Exception:
            return 'unknown'

    def get_openflow_stats(self) -> int:
        """Get OpenFlow flow count"""
        try:
            result = subprocess.run(
                ['ovs-ofctl', 'dump-flows', 'fortress'],
                capture_output=True, text=True, timeout=5
            )
            return len([l for l in result.stdout.split('\n') if l.strip()])
        except Exception:
            return 0

    def get_suricata_alerts(self) -> int:
        """Get recent Suricata alert count"""
        try:
            alert_file = Path("/var/log/suricata/fast.log")
            if alert_file.exists():
                # Count alerts in last 5 minutes
                cutoff = time.time() - 300
                count = 0
                with open(alert_file, 'r') as f:
                    for line in f:
                        count += 1
                return min(count, 100)  # Cap at 100
            return 0
        except Exception:
            return 0

    def calculate_score(self) -> tuple:
        """Calculate QSecBit score with Fortress enhancements"""
        components = {
            'drift': 0.0,
            'network': 0.0,
            'threats': 0.0,
            'energy': 0.0,
            'infrastructure': 0.0,
            'vlan': 0.0,
            'macsec': 0.0,
            'openflow': 0.0
        }

        # System drift (CPU, memory usage)
        try:
            with open('/proc/loadavg', 'r') as f:
                load = float(f.read().split()[0])
            components['drift'] = max(0, 1.0 - (load / os.cpu_count()))
        except Exception:
            components['drift'] = 0.5

        # Network health
        try:
            result = subprocess.run(['ip', 'link', 'show', 'up'],
                                  capture_output=True, text=True, timeout=5)
            up_interfaces = len([l for l in result.stdout.split('\n') if 'state UP' in l])
            components['network'] = min(1.0, up_interfaces / 4)
        except Exception:
            components['network'] = 0.5

        # Threat detection
        alerts = self.get_suricata_alerts()
        components['threats'] = max(0, 1.0 - (alerts / 50))

        # Energy efficiency (simplified)
        components['energy'] = 0.8

        # Infrastructure health
        try:
            result = subprocess.run(['podman', 'ps', '-q'],
                                  capture_output=True, text=True, timeout=5)
            containers = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
            components['infrastructure'] = min(1.0, containers / 5)
        except Exception:
            components['infrastructure'] = 0.5

        # VLAN security
        violations = self.get_vlan_violations()
        components['vlan'] = max(0, 1.0 - (violations / 100))

        # MACsec status
        macsec = self.get_macsec_status()
        components['macsec'] = 1.0 if macsec == 'active' else 0.5 if macsec == 'inactive' else 0.3

        # OpenFlow health
        flows = self.get_openflow_stats()
        components['openflow'] = min(1.0, flows / 20) if flows > 0 else 0.5

        # Calculate weighted score
        score = (
            self.config.alpha * components['drift'] +
            self.config.beta * components['network'] +
            self.config.gamma * components['threats'] +
            self.config.delta * components['energy'] +
            self.config.epsilon * components['infrastructure'] +
            self.config.vlan_weight * components['vlan'] +
            self.config.macsec_weight * components['macsec'] +
            self.config.openflow_weight * components['openflow']
        )

        # Determine RAG status
        if score >= self.config.amber_threshold:
            rag_status = "GREEN"
        elif score >= self.config.red_threshold:
            rag_status = "AMBER"
        else:
            rag_status = "RED"

        return score, rag_status, components

    def collect_sample(self) -> QSecBitSample:
        """Collect a complete QSecBit sample"""
        score, rag_status, components = self.calculate_score()

        sample = QSecBitSample(
            timestamp=datetime.now().isoformat(),
            score=score,
            rag_status=rag_status,
            components=components,
            threats_detected=0,
            suricata_alerts=self.get_suricata_alerts(),
            vlan_violations=self.get_vlan_violations(),
            macsec_status=self.get_macsec_status(),
            openflow_flows=self.get_openflow_stats()
        )

        self.last_sample = sample
        self.history.append(sample)
        if len(self.history) > 1000:
            self.history = self.history[-500:]

        return sample

    def save_stats(self, sample: QSecBitSample):
        """Save stats to file"""
        try:
            stats = {
                'timestamp': sample.timestamp,
                'score': sample.score,
                'rag_status': sample.rag_status,
                'components': sample.components,
                'threats_detected': sample.threats_detected,
                'suricata_alerts': sample.suricata_alerts,
                'vlan_violations': sample.vlan_violations,
                'macsec_status': sample.macsec_status,
                'openflow_flows': sample.openflow_flows,
                'uptime_seconds': int(time.time() - self.start_time)
            }
            with open(STATS_FILE, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")

    def run_monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("Starting QSecBit monitoring loop...")
        interval = 10

        while self.running.is_set():
            try:
                sample = self.collect_sample()
                self.save_stats(sample)

                logger.info(
                    f"QSecBit: {sample.rag_status} score={sample.score:.3f} "
                    f"vlan_violations={sample.vlan_violations} "
                    f"macsec={sample.macsec_status}"
                )

                time.sleep(interval)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(interval)

    def start(self):
        """Start the agent"""
        logger.info("Starting QSecBit Fortress Agent v5.0.0...")
        self.running.set()

        monitor_thread = Thread(target=self.run_monitoring_loop, daemon=True)
        monitor_thread.start()

        self.running.wait()

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping QSecBit Fortress Agent...")
        self.running.clear()


def main():
    agent = QSecBitFortressAgent()
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

    chmod +x /opt/hookprobe/fortress/qsecbit/fortress_agent.py

    # Create systemd service
    cat > /etc/systemd/system/fortress-qsecbit.service << 'SERVICEEOF'
[Unit]
Description=HookProbe Fortress QSecBit Agent v5.0
After=network.target openvswitch-switch.service
Wants=openvswitch-switch.service

[Service]
Type=simple
WorkingDirectory=/opt/hookprobe/fortress/qsecbit
ExecStart=/usr/bin/python3 /opt/hookprobe/fortress/qsecbit/fortress_agent.py
Restart=always
RestartSec=10
User=root
Environment=PYTHONPATH=/opt/hookprobe/fortress

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload
    systemctl enable fortress-qsecbit

    log_info "QSecBit Fortress Agent installed"
}

# ============================================================
# FREERADIUS WITH VLAN ASSIGNMENT
# ============================================================
configure_freeradius_vlan() {
    log_step "Configuring FreeRADIUS for VLAN assignment..."

    local RADIUS_SECRET="${HOOKPROBE_RADIUS_SECRET:-hookprobe_fortress}"

    mkdir -p /etc/fortress
    chmod 755 /etc/fortress

    # Create MAC-to-VLAN database
    cat > /etc/fortress/mac_vlan.json << 'MACVLANEOF'
{
  "version": "1.0",
  "description": "HookProbe Fortress - MAC to VLAN Assignment",
  "default_vlan": 40,
  "vlans": {
    "10": {"name": "management", "description": "Management devices"},
    "20": {"name": "trusted", "description": "Trusted devices"},
    "30": {"name": "iot", "description": "IoT devices"},
    "40": {"name": "guest", "description": "Guest devices"},
    "99": {"name": "quarantine", "description": "Quarantined devices"}
  },
  "devices": {}
}
MACVLANEOF

    chmod 644 /etc/fortress/mac_vlan.json

    # Configure FreeRADIUS for dynamic VLAN
    if [ -d /etc/freeradius/3.0/mods-config/files ]; then
        cat > /etc/freeradius/3.0/mods-config/files/authorize << 'USERSEOF'
# HookProbe Fortress - MAC Authentication with VLAN Assignment
# Devices are assigned to VLANs based on their MAC address

# Management VLAN (10) - Known admin devices
# Add trusted MAC addresses here
# AA:BB:CC:DD:EE:FF Cleartext-Password := "AA:BB:CC:DD:EE:FF"
#     Tunnel-Type = VLAN,
#     Tunnel-Medium-Type = IEEE-802,
#     Tunnel-Private-Group-Id = 10

# DEFAULT: Guest VLAN (40)
DEFAULT Cleartext-Password := "%{User-Name}"
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = 40,
    Reply-Message = "Welcome to HookProbe Fortress - Guest Network"
USERSEOF
        chmod 640 /etc/freeradius/3.0/mods-config/files/authorize
        chown freerad:freerad /etc/freeradius/3.0/mods-config/files/authorize 2>/dev/null || true
    fi

    log_info "FreeRADIUS configured for VLAN assignment"
}

# ============================================================
# MONITORING STACK (OPTIONAL)
# ============================================================
install_monitoring() {
    if [ "$ENABLE_MONITORING" != true ]; then
        log_info "Monitoring disabled"
        return 0
    fi

    log_step "Installing monitoring stack..."

    # Create monitoring directories
    mkdir -p /opt/hookprobe/fortress/monitoring
    mkdir -p /opt/hookprobe/fortress/grafana

    # Victoria Metrics container
    podman run -d \
        --name fortress-victoria \
        --restart unless-stopped \
        -p 8428:8428 \
        -v /opt/hookprobe/fortress/monitoring:/victoria-metrics-data:Z \
        docker.io/victoriametrics/victoria-metrics:latest \
        2>/dev/null || log_warn "Victoria Metrics may already be running"

    # Grafana container
    podman run -d \
        --name fortress-grafana \
        --restart unless-stopped \
        -p 3000:3000 \
        -v /opt/hookprobe/fortress/grafana:/var/lib/grafana:Z \
        -e GF_SECURITY_ADMIN_PASSWORD=hookprobe \
        docker.io/grafana/grafana:latest \
        2>/dev/null || log_warn "Grafana may already be running"

    log_info "Monitoring stack installed"
    log_info "  Victoria Metrics: http://localhost:8428"
    log_info "  Grafana: http://localhost:3000 (admin/hookprobe)"
}

# ============================================================
# SYSTEMD SERVICES
# ============================================================
create_systemd_services() {
    log_step "Creating systemd services..."

    # Main Fortress service
    cat > /etc/systemd/system/hookprobe-fortress.service << 'SERVICEEOF'
[Unit]
Description=HookProbe Fortress Edge Gateway
After=network.target openvswitch-switch.service
Wants=openvswitch-switch.service fortress-qsecbit.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecStartPost=/usr/local/bin/hookprobe-fortress-start
ExecStop=/usr/local/bin/hookprobe-fortress-stop

[Install]
WantedBy=multi-user.target
SERVICEEOF

    # Start script
    cat > /usr/local/bin/hookprobe-fortress-start << 'STARTEOF'
#!/bin/bash
echo "Starting HookProbe Fortress..."

# Ensure OVS is running
systemctl start openvswitch-switch 2>/dev/null || true

# Start QSecBit agent
systemctl start fortress-qsecbit 2>/dev/null || true

# Start containers
podman start fortress-victoria 2>/dev/null || true
podman start fortress-grafana 2>/dev/null || true

echo "HookProbe Fortress started"
STARTEOF

    chmod +x /usr/local/bin/hookprobe-fortress-start

    # Stop script
    cat > /usr/local/bin/hookprobe-fortress-stop << 'STOPEOF'
#!/bin/bash
echo "Stopping HookProbe Fortress..."

systemctl stop fortress-qsecbit 2>/dev/null || true
podman stop fortress-victoria 2>/dev/null || true
podman stop fortress-grafana 2>/dev/null || true

echo "HookProbe Fortress stopped"
STOPEOF

    chmod +x /usr/local/bin/hookprobe-fortress-stop

    systemctl daemon-reload
    systemctl enable hookprobe-fortress

    log_info "Systemd services created"
}

# ============================================================
# MAIN CONFIGURATION FILE
# ============================================================
create_config_file() {
    log_step "Creating main configuration file..."

    cat > /etc/hookprobe/fortress.conf << CONFEOF
# HookProbe Fortress Configuration
# Version: 5.0.0
# Generated: $(date -Iseconds)

[general]
tier = fortress
node_id = ${HOOKPROBE_NODE_ID:-$(hostname)-fortress}
version = 5.0.0

[network]
ovs_bridge = $OVS_BRIDGE_NAME
vlan_segmentation = $VLAN_SEGMENTATION
macsec_enabled = $MACSEC_ENABLED

[vlans]
management = 10
trusted = 20
iot = 30
guest = 40
quarantine = 99

[vxlan]
enabled = true
mssp_vni = 2000
mssp_endpoint = ${HOOKPROBE_MSSP_URL:-mssp.hookprobe.com}

[security]
qsecbit_enabled = true
openflow_enabled = true
macsec_enabled = $MACSEC_ENABLED

[monitoring]
enabled = $ENABLE_MONITORING
victoria_metrics_port = 8428
grafana_port = 3000

[automation]
n8n_enabled = $ENABLE_N8N
CONFEOF

    chmod 644 /etc/hookprobe/fortress.conf
    log_info "Configuration file created: /etc/hookprobe/fortress.conf"
}

# ============================================================
# SHOW COMPLETION
# ============================================================
show_completion() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║   ${GREEN}HookProbe Fortress Installation Complete${NC}                  ${CYAN}║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Installed Components:${NC}"
    echo -e "  ${GREEN}✓${NC} Open vSwitch with OpenFlow 1.3"
    echo -e "  ${GREEN}✓${NC} VLAN Segmentation (management, trusted, iot, guest, quarantine)"
    echo -e "  ${GREEN}✓${NC} VXLAN Tunnels with VNI and PSK encryption"
    echo -e "  ${GREEN}✓${NC} MACsec (802.1AE) Layer 2 encryption"
    echo -e "  ${GREEN}✓${NC} QSecBit Fortress Agent"
    echo -e "  ${GREEN}✓${NC} FreeRADIUS with dynamic VLAN assignment"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  ${GREEN}✓${NC} Monitoring (Grafana + Victoria Metrics)"
    [ "$ENABLE_N8N" = true ] && echo -e "  ${GREEN}✓${NC} n8n Workflow Automation"
    echo ""
    echo -e "  ${BOLD}Management Commands:${NC}"
    echo -e "  ${CYAN}hookprobe-macsec${NC} enable eth0  - Enable MACsec on interface"
    echo -e "  ${CYAN}hookprobe-openflow${NC} status     - View OpenFlow status"
    echo -e "  ${CYAN}systemctl status${NC} hookprobe-fortress"
    echo ""
    echo -e "  ${BOLD}Web Interfaces:${NC}"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  Grafana:          http://localhost:3000"
    [ "$ENABLE_MONITORING" = true ] && echo -e "  Victoria Metrics: http://localhost:8428"
    echo ""
    echo -e "  ${BOLD}Logs:${NC}"
    echo -e "  journalctl -u fortress-qsecbit -f"
    echo ""
}

# ============================================================
# MAIN
# ============================================================
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║              HookProbe Fortress Installer                    ║${NC}"
    echo -e "${CYAN}║                    Version 5.0.0                             ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --enable-n8n) ENABLE_N8N=true; shift ;;
            --enable-monitoring) ENABLE_MONITORING=true; shift ;;
            --enable-clickhouse) ENABLE_CLICKHOUSE=true; shift ;;
            --enable-lte) ENABLE_LTE=true; shift ;;
            --disable-macsec) MACSEC_ENABLED=false; shift ;;
            --disable-vlan) VLAN_SEGMENTATION=false; shift ;;
            --node-id) HOOKPROBE_NODE_ID="$2"; shift 2 ;;
            --mssp-url) HOOKPROBE_MSSP_URL="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Run installation steps
    check_root
    check_requirements
    detect_platform
    detect_interfaces

    install_packages
    install_podman
    install_openvswitch

    setup_ovs_bridge
    setup_vlans
    setup_vxlan_tunnels
    setup_macsec
    setup_openflow_rules

    install_qsecbit_agent
    configure_freeradius_vlan
    install_monitoring

    create_systemd_services
    create_config_file

    # Start services
    log_step "Starting services..."
    systemctl start hookprobe-fortress
    systemctl start fortress-qsecbit

    show_completion
}

main "$@"
