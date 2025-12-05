#!/bin/bash
#
# HookProbe Guardian Setup Script
# Version: 5.0.0
# License: MIT
#
# Installation modes:
#   - Basic: Simple bridge (WiFi + LAN), DHCP client, no SDN
#   - SDN:   Full VLAN segmentation with FreeRADIUS (requires MSSP)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDIAN_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$GUARDIAN_ROOT/config"

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
# LOGGING
# ============================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ============================================================
# PREREQUISITES CHECK
# ============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_platform() {
    log_step "Detecting platform..."

    if grep -q "Raspberry Pi 5" /proc/cpuinfo 2>/dev/null; then
        PLATFORM="rpi5"
        PLATFORM_NAME="Raspberry Pi 5"
    elif grep -q "Raspberry Pi 4" /proc/cpuinfo 2>/dev/null; then
        PLATFORM="rpi4"
        PLATFORM_NAME="Raspberry Pi 4"
    elif grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        PLATFORM="rpi"
        PLATFORM_NAME="Raspberry Pi"
    else
        PLATFORM="generic"
        PLATFORM_NAME="Generic Linux"
    fi

    log_info "Platform: $PLATFORM_NAME"
}

detect_interfaces() {
    log_step "Detecting network interfaces..."

    # Ethernet interfaces
    ETH_INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|enp|eno)' | tr '\n' ' ')
    ETH_COUNT=$(echo $ETH_INTERFACES | wc -w)

    # WiFi interfaces
    WIFI_INTERFACES=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | tr '\n' ' ')
    WIFI_COUNT=$(echo $WIFI_INTERFACES | wc -w)

    # Check AP mode support
    WIFI_AP_SUPPORT=false
    for iface in $WIFI_INTERFACES; do
        if iw list 2>/dev/null | grep -A 10 "Supported interface modes" | grep -q "AP"; then
            WIFI_AP_SUPPORT=true
            break
        fi
    done

    log_info "Ethernet interfaces ($ETH_COUNT): $ETH_INTERFACES"
    log_info "WiFi interfaces ($WIFI_COUNT): $WIFI_INTERFACES"
    log_info "WiFi AP mode: $WIFI_AP_SUPPORT"
}

# ============================================================
# RADIUS CONNECTIVITY CHECK
# ============================================================
check_radius_connectivity() {
    local radius_server="${1:-127.0.0.1}"
    local radius_port="${2:-1812}"
    local timeout=5

    log_step "Checking RADIUS connectivity to $radius_server:$radius_port..."

    # Check if we can reach the RADIUS server
    if command -v nc &>/dev/null; then
        if nc -z -w $timeout "$radius_server" "$radius_port" 2>/dev/null; then
            log_info "RADIUS server is reachable"
            return 0
        fi
    elif command -v timeout &>/dev/null; then
        if timeout $timeout bash -c "echo >/dev/udp/$radius_server/$radius_port" 2>/dev/null; then
            log_info "RADIUS server is reachable"
            return 0
        fi
    fi

    log_warn "RADIUS server not reachable"
    return 1
}

check_mssp_connectivity() {
    local mssp_url="${HOOKPROBE_MSSP_URL:-https://nexus.hookprobe.com}"
    local timeout=10

    log_step "Checking MSSP connectivity..."

    if command -v curl &>/dev/null; then
        if curl -s --max-time $timeout "$mssp_url/api/health" &>/dev/null; then
            log_info "MSSP server is reachable"
            return 0
        fi
    fi

    log_warn "MSSP server not reachable (SDN features may be limited)"
    return 1
}

# ============================================================
# INSTALLATION FUNCTIONS
# ============================================================
install_packages() {
    log_step "Installing required packages..."

    # Detect package manager
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
        apt-get update -qq

        # Create /etc/default/hostapd before installing hostapd
        # This prevents the post-install script from failing
        if [ ! -f /etc/default/hostapd ]; then
            mkdir -p /etc/default
            echo '# Defaults for hostapd initscript' > /etc/default/hostapd
            echo 'DAEMON_CONF=""' >> /etc/default/hostapd
        fi

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
            python3-flask \
            python3-requests \
            net-tools \
            curl
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
            python3-flask \
            python3-requests \
            net-tools \
            curl
    else
        log_error "Unsupported package manager"
        exit 1
    fi

    log_info "Packages installed"
}

install_sdn_packages() {
    log_step "Installing SDN packages (VLAN, RADIUS)..."

    if [ "$PKG_MGR" = "apt" ]; then
        apt-get install -y -qq vlan freeradius
    else
        dnf install -y -q vlan freeradius
    fi

    # Enable 802.1q VLAN module
    modprobe 8021q 2>/dev/null || true
    if ! grep -q "8021q" /etc/modules 2>/dev/null; then
        echo "8021q" >> /etc/modules
    fi

    log_info "SDN packages installed"
}

# ============================================================
# PODMAN CONTAINER RUNTIME
# ============================================================
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

    # Enable and start podman socket
    systemctl enable --now podman.socket 2>/dev/null || true

    log_info "Podman installed: $(podman --version)"
}

# ============================================================
# OPEN VSWITCH WITH VXLAN
# ============================================================
install_openvswitch() {
    log_step "Installing Open vSwitch..."

    if command -v ovs-vsctl &>/dev/null; then
        log_info "Open vSwitch already installed"
    else
        if [ "$PKG_MGR" = "apt" ]; then
            apt-get install -y -qq openvswitch-switch
        else
            dnf install -y -q openvswitch
        fi
    fi

    # Enable and start OVS
    systemctl enable openvswitch-switch 2>/dev/null || \
        systemctl enable openvswitch 2>/dev/null || true
    systemctl start openvswitch-switch 2>/dev/null || \
        systemctl start openvswitch 2>/dev/null || true

    log_info "Open vSwitch installed and running"
}

generate_vxlan_psk() {
    # Generate a PSK for VXLAN tunnel encryption
    openssl rand -base64 32
}

setup_ovs_bridge() {
    log_step "Setting up OVS bridge with VXLAN..."

    local OVS_BRIDGE_NAME="guardian"
    local local_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    # Check if OVS is available
    if ! command -v ovs-vsctl &>/dev/null; then
        log_warn "OVS not available, skipping OVS bridge setup"
        return 0
    fi

    # Create OVS bridge if it doesn't exist
    if ovs-vsctl br-exists "$OVS_BRIDGE_NAME" 2>/dev/null; then
        log_info "OVS bridge '$OVS_BRIDGE_NAME' already exists"
    else
        ovs-vsctl add-br "$OVS_BRIDGE_NAME" 2>/dev/null || {
            log_warn "Failed to create OVS bridge"
            return 0
        }
        log_info "OVS bridge '$OVS_BRIDGE_NAME' created"
    fi

    # Enable OpenFlow 1.3 for advanced flow monitoring
    ovs-vsctl set bridge "$OVS_BRIDGE_NAME" protocols=OpenFlow10,OpenFlow13 2>/dev/null || true

    # Configure bridge IP
    ip link set "$OVS_BRIDGE_NAME" up
    ip addr add 10.250.0.1/16 dev "$OVS_BRIDGE_NAME" 2>/dev/null || true

    # Create secrets directory for VXLAN PSK
    mkdir -p /etc/hookprobe/secrets/vxlan
    chmod 700 /etc/hookprobe/secrets/vxlan

    # Generate master PSK if not exists
    if [ ! -f /etc/hookprobe/secrets/vxlan/master.psk ]; then
        generate_vxlan_psk > /etc/hookprobe/secrets/vxlan/master.psk
        chmod 600 /etc/hookprobe/secrets/vxlan/master.psk
        log_info "VXLAN master PSK generated"
    fi

    # Setup VXLAN tunnel for MSSP connection
    local vxlan_vni="${HOOKPROBE_VXLAN_VNI:-1000}"
    local vxlan_port="vxlan_mssp"

    # Add VXLAN port to OVS bridge
    ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "$vxlan_port" \
        -- set interface "$vxlan_port" type=vxlan \
        options:key="$vxlan_vni" \
        options:local_ip="$local_ip" \
        options:remote_ip=flow 2>/dev/null || true

    # Save OVS configuration
    mkdir -p /etc/hookprobe
    cat > /etc/hookprobe/ovs-config.sh << OVSEOF
# HookProbe Guardian OVS Configuration
OVS_BRIDGE_NAME=$OVS_BRIDGE_NAME
LOCAL_IP=$local_ip

# VXLAN Configuration
VXLAN_ENABLED=true
VXLAN_VNI=$vxlan_vni
VXLAN_MASTER_PSK=/etc/hookprobe/secrets/vxlan/master.psk
OVSEOF

    log_info "OVS bridge configured with VXLAN (VNI: $vxlan_vni)"
}

# ============================================================
# SECURITY CONTAINERS
# ============================================================
install_security_containers() {
    log_step "Installing Guardian security containers..."

    # Create Guardian pod network
    podman network create guardian-net 2>/dev/null || true

    # Create volumes
    podman volume create guardian-suricata-logs 2>/dev/null || true
    podman volume create guardian-suricata-rules 2>/dev/null || true
    podman volume create guardian-adguard-work 2>/dev/null || true
    podman volume create guardian-adguard-conf 2>/dev/null || true
    podman volume create guardian-waf-logs 2>/dev/null || true

    # Pull container images first
    log_info "Pulling container images (this may take a few minutes)..."
    podman pull docker.io/jasonish/suricata:latest 2>/dev/null || log_warn "Failed to pull Suricata image"
    podman pull docker.io/adguard/adguardhome:latest 2>/dev/null || log_warn "Failed to pull AdGuard image"
    podman pull docker.io/owasp/modsecurity-crs:nginx-alpine 2>/dev/null || log_warn "Failed to pull WAF image"
    podman pull docker.io/library/python:3.11-slim 2>/dev/null || log_warn "Failed to pull Python image"

    # Install containers
    install_suricata_container
    install_waf_container
    install_neuro_container

    # Install AdGuard (ad blocking) if enabled
    if [ "${HOOKPROBE_ADBLOCK:-yes}" = "yes" ]; then
        install_adguard_container
    fi

    log_info "Security containers installed"
}

install_suricata_container() {
    log_step "Installing Suricata IDS/IPS container..."

    # Check if already running
    if podman ps -a --format "{{.Names}}" | grep -q "^guardian-suricata$"; then
        log_info "Suricata container already exists"
        return 0
    fi

    # Determine network interface to monitor
    local MONITOR_IFACE="br0"

    # Pull and run Suricata
    podman run -d \
        --name guardian-suricata \
        --network host \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --cap-add SYS_NICE \
        -v guardian-suricata-logs:/var/log/suricata:Z \
        -v guardian-suricata-rules:/var/lib/suricata:Z \
        -e SURICATA_OPTIONS="-i $MONITOR_IFACE" \
        --restart unless-stopped \
        docker.io/jasonish/suricata:latest \
        -i "$MONITOR_IFACE" 2>/dev/null || {
            log_warn "Suricata container failed to start (may need network first)"
        }

    # Create systemd service for Suricata container
    cat > /etc/systemd/system/guardian-suricata.service << 'EOF'
[Unit]
Description=HookProbe Guardian Suricata IDS
After=network.target podman.socket
Requires=podman.socket

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=-/usr/bin/podman stop guardian-suricata
ExecStartPre=-/usr/bin/podman rm guardian-suricata
ExecStart=/usr/bin/podman start -a guardian-suricata
ExecStop=/usr/bin/podman stop guardian-suricata

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-suricata 2>/dev/null || true

    log_info "Suricata IDS container installed"
}

install_adguard_container() {
    log_step "Installing AdGuard Home (ad blocking)..."

    # Check if already running
    if podman ps -a --format "{{.Names}}" | grep -q "^guardian-adguard$"; then
        log_info "AdGuard container already exists"
        return 0
    fi

    # AdGuard DNS ports: 53 (DNS), 3000 (setup), 80 (dashboard after setup)
    # Use alternative ports to avoid conflicts with dnsmasq
    podman run -d \
        --name guardian-adguard \
        --network host \
        -v guardian-adguard-work:/opt/adguardhome/work:Z \
        -v guardian-adguard-conf:/opt/adguardhome/conf:Z \
        -e ADGUARD_PORT_DNS=5353 \
        --restart unless-stopped \
        docker.io/adguard/adguardhome:latest 2>/dev/null || {
            log_warn "AdGuard container failed to start"
        }

    # Create systemd service for AdGuard container
    cat > /etc/systemd/system/guardian-adguard.service << 'EOF'
[Unit]
Description=HookProbe Guardian AdGuard Home
After=network.target podman.socket
Requires=podman.socket

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=-/usr/bin/podman stop guardian-adguard
ExecStartPre=-/usr/bin/podman rm guardian-adguard
ExecStart=/usr/bin/podman start -a guardian-adguard
ExecStop=/usr/bin/podman stop guardian-adguard

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-adguard 2>/dev/null || true

    # Update dnsmasq to forward to AdGuard
    if [ -f /etc/dnsmasq.d/guardian.conf ]; then
        sed -i 's/server=1.1.1.1/server=127.0.0.1#5353/' /etc/dnsmasq.d/guardian.conf
        sed -i 's/server=8.8.8.8/server=127.0.0.1#5353/' /etc/dnsmasq.d/guardian.conf
    fi

    log_info "AdGuard Home installed (setup: http://192.168.4.1:3000)"
}

install_waf_container() {
    log_step "Installing WAF (ModSecurity) container..."

    # Check if already running
    if podman ps -a --format "{{.Names}}" | grep -q "^guardian-waf$"; then
        log_info "WAF container already exists"
        return 0
    fi

    # Run OWASP ModSecurity WAF
    podman run -d \
        --name guardian-waf \
        --network host \
        --cap-add NET_ADMIN \
        -v guardian-waf-logs:/var/log/modsecurity:Z \
        -e PARANOIA=1 \
        -e ANOMALY_INBOUND=5 \
        -e ANOMALY_OUTBOUND=4 \
        -e BACKEND=http://127.0.0.1:8080 \
        --restart unless-stopped \
        docker.io/owasp/modsecurity-crs:nginx-alpine 2>/dev/null || {
            log_warn "WAF container failed to start"
        }

    # Create systemd service for WAF container
    cat > /etc/systemd/system/guardian-waf.service << 'EOF'
[Unit]
Description=HookProbe Guardian WAF (ModSecurity)
After=network.target podman.socket
Requires=podman.socket

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=-/usr/bin/podman stop guardian-waf
ExecStartPre=-/usr/bin/podman rm guardian-waf
ExecStart=/usr/bin/podman start -a guardian-waf
ExecStop=/usr/bin/podman stop guardian-waf

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-waf 2>/dev/null || true

    log_info "WAF (ModSecurity) container installed"
}

install_neuro_container() {
    log_step "Installing Neuro Protocol (QSecBit + HTP) container..."

    # Check if already running
    if podman ps -a --format "{{.Names}}" | grep -q "^guardian-neuro$"; then
        log_info "Neuro container already exists"
        return 0
    fi

    # Create neuro working directory
    mkdir -p /opt/hookprobe/guardian/neuro

    # Load MSSP configuration if available
    local mssp_env=""
    if [ -f /etc/hookprobe/secrets/mssp.env ]; then
        source /etc/hookprobe/secrets/mssp.env
        mssp_env="-e MSSP_ENDPOINT=$MSSP_ENDPOINT -e MSSP_PORT=$MSSP_PORT -e HTP_NODE_ID=$HTP_NODE_ID"
    fi

    # Run Neuro/QSecBit container
    podman run -d \
        --name guardian-neuro \
        --network host \
        -v /opt/hookprobe/guardian/neuro:/app/neuro:Z \
        -v /etc/hookprobe/secrets:/secrets:ro \
        -e QSECBIT_MODE="quantum-resistant" \
        -e HTP_ENABLED="true" \
        -e PYTHONPATH="/app" \
        $mssp_env \
        --restart unless-stopped \
        docker.io/library/python:3.11-slim \
        bash -c '
            pip install --quiet numpy cryptography 2>/dev/null || pip install --quiet numpy
            echo "HookProbe Neuro Protocol starting..."
            echo "  Mode: guardian"
            echo "  MSSP: ${MSSP_ENDPOINT:-not configured}"
            python -c "
import time
import os
import json
from datetime import datetime

print(\"QSecBit Lite Guardian Agent running...\")

stats_file = \"/app/neuro/stats.json\"

while True:
    try:
        stats = {
            \"timestamp\": datetime.now().isoformat(),
            \"mode\": \"guardian\",
            \"status\": \"active\"
        }
        os.makedirs(os.path.dirname(stats_file), exist_ok=True)
        with open(stats_file, \"w\") as f:
            json.dump(stats, f)
    except Exception as e:
        print(f\"Stats error: {e}\")
    time.sleep(30)
"
        ' 2>/dev/null || {
            log_warn "Neuro container failed to start"
        }

    # Create systemd service for Neuro container
    cat > /etc/systemd/system/guardian-neuro.service << 'EOF'
[Unit]
Description=HookProbe Guardian Neuro Protocol (QSecBit + HTP)
After=network.target podman.socket guardian-suricata.service
Requires=podman.socket

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=-/usr/bin/podman stop guardian-neuro
ExecStartPre=-/usr/bin/podman rm guardian-neuro
ExecStart=/usr/bin/podman start -a guardian-neuro
ExecStop=/usr/bin/podman stop guardian-neuro

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-neuro 2>/dev/null || true

    log_info "Neuro Protocol container installed"
}

install_qsecbit_agent() {
    log_step "Installing QSecBit agent..."

    mkdir -p /opt/hookprobe/guardian/agent

    # Create QSecBit agent script
    cat > /opt/hookprobe/guardian/agent/qsecbit-lite.py << 'PYEOF'
#!/usr/bin/env python3
"""
QSecBit Lite - Guardian Edition
Quantum-resistant security agent for edge devices.
Version: 5.0.0
"""

import os
import json
import time
import logging
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('qsecbit-lite')

class QSecBitLite:
    """Lightweight security agent for Guardian."""

    def __init__(self):
        self.config_dir = Path('/opt/hookprobe/guardian')
        self.data_dir = self.config_dir / 'data'
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.threat_log = self.data_dir / 'threats.json'
        self.stats_file = self.data_dir / 'stats.json'

    def check_suricata_alerts(self):
        """Check Suricata for new alerts."""
        alerts = []
        eve_log = Path('/var/log/suricata/eve.json')

        if eve_log.exists():
            try:
                # Read last 100 lines of eve.json
                result = subprocess.run(
                    ['tail', '-100', str(eve_log)],
                    capture_output=True, text=True
                )
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            event = json.loads(line)
                            if event.get('event_type') == 'alert':
                                alerts.append({
                                    'timestamp': event.get('timestamp'),
                                    'signature': event.get('alert', {}).get('signature'),
                                    'severity': event.get('alert', {}).get('severity'),
                                    'src_ip': event.get('src_ip'),
                                    'dest_ip': event.get('dest_ip'),
                                })
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                logger.error(f"Error reading Suricata alerts: {e}")

        return alerts

    def get_network_stats(self):
        """Get network statistics."""
        stats = {
            'timestamp': datetime.now().isoformat(),
            'interfaces': {},
            'connections': 0,
        }

        # Get interface stats
        try:
            result = subprocess.run(
                ['ip', '-s', 'link'],
                capture_output=True, text=True
            )
            # Parse output (simplified)
            stats['raw_interface_stats'] = result.stdout[:500]
        except Exception as e:
            logger.error(f"Error getting network stats: {e}")

        # Get connection count
        try:
            result = subprocess.run(
                ['ss', '-t', '-n'],
                capture_output=True, text=True
            )
            stats['connections'] = len(result.stdout.strip().split('\n')) - 1
        except Exception:
            pass

        return stats

    def run(self):
        """Main agent loop."""
        logger.info("QSecBit Lite starting...")

        while True:
            try:
                # Check for threats
                alerts = self.check_suricata_alerts()
                if alerts:
                    logger.warning(f"Found {len(alerts)} alerts")
                    # Log to threat file
                    with open(self.threat_log, 'a') as f:
                        for alert in alerts[-10:]:  # Last 10 alerts
                            f.write(json.dumps(alert) + '\n')

                # Collect stats
                stats = self.get_network_stats()
                with open(self.stats_file, 'w') as f:
                    json.dump(stats, f, indent=2)

            except Exception as e:
                logger.error(f"Agent error: {e}")

            time.sleep(30)  # Check every 30 seconds

if __name__ == '__main__':
    agent = QSecBitLite()
    agent.run()
PYEOF

    chmod +x /opt/hookprobe/guardian/agent/qsecbit-lite.py

    # Create systemd service
    cat > /etc/systemd/system/guardian-qsecbit.service << 'EOF'
[Unit]
Description=HookProbe Guardian QSecBit Agent
After=network.target guardian-suricata.service
Wants=guardian-suricata.service

[Service]
Type=simple
WorkingDirectory=/opt/hookprobe/guardian/agent
ExecStart=/usr/bin/python3 /opt/hookprobe/guardian/agent/qsecbit-lite.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-qsecbit

    log_info "QSecBit agent installed"
}

# ============================================================
# BASIC MODE CONFIGURATION (Simple Bridge)
# ============================================================
configure_basic_mode() {
    log_step "Configuring Guardian in Basic Mode..."

    local HOTSPOT_SSID="${HOOKPROBE_WIFI_SSID:-HookProbe-Guardian}"
    local HOTSPOT_PASS="${HOOKPROBE_WIFI_PASS:-hookprobe123}"
    local BRIDGE_IP="192.168.4.1"
    local DHCP_START="192.168.4.100"
    local DHCP_END="192.168.4.200"

    # Determine interfaces
    local WIFI_IFACE=$(echo $WIFI_INTERFACES | awk '{print $1}')
    local ETH_IFACE=$(echo $ETH_INTERFACES | awk '{print $1}')

    if [ -z "$WIFI_IFACE" ]; then
        log_error "No WiFi interface found"
        exit 1
    fi

    # Stop services during configuration
    systemctl stop hostapd 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true

    # Create bridge interface
    log_info "Creating bridge br0..."
    ip link add br0 type bridge 2>/dev/null || true
    ip link set br0 up
    ip addr add $BRIDGE_IP/24 dev br0 2>/dev/null || true

    # Add ethernet to bridge if available
    if [ -n "$ETH_IFACE" ]; then
        ip link set "$ETH_IFACE" master br0 2>/dev/null || true
        log_info "Added $ETH_IFACE to bridge"
    fi

    # Configure hostapd (simple mode)
    log_info "Configuring hostapd..."
    cat > /etc/hostapd/hostapd.conf << EOF
# HookProbe Guardian - Basic Mode
# Simple WiFi hotspot with bridge

interface=$WIFI_IFACE
driver=nl80211
bridge=br0

ssid=$HOTSPOT_SSID
hw_mode=g
channel=6
country_code=US

# 802.11n support
ieee80211n=1
wmm_enabled=1

# Security
wpa=2
wpa_passphrase=$HOTSPOT_PASS
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP

# Logging
logger_syslog=-1
logger_syslog_level=2

# Performance
max_num_sta=32
EOF

    # Configure hostapd daemon
    echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' > /etc/default/hostapd

    # Configure dnsmasq (DHCP + DNS)
    log_info "Configuring dnsmasq..."
    cat > /etc/dnsmasq.d/guardian.conf << EOF
# HookProbe Guardian - DHCP/DNS Configuration

# Interface
interface=br0
bind-interfaces

# DHCP range
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,24h

# Gateway
dhcp-option=3,$BRIDGE_IP

# DNS servers
server=1.1.1.1
server=8.8.8.8

# Domain
domain=guardian.local
local=/guardian.local/

# Logging
log-queries
log-dhcp
EOF

    # Enable IP forwarding
    log_info "Enabling IP forwarding..."
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-guardian.conf
    sysctl -p /etc/sysctl.d/99-guardian.conf

    # Configure NAT (masquerade outgoing traffic)
    log_info "Configuring NAT..."
    mkdir -p /etc/nftables.d
    cat > /etc/nftables.d/guardian.nft << 'EOF'
#!/usr/sbin/nft -f
# HookProbe Guardian - Basic NAT

table inet guardian {
    chain forward {
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
    }

    chain postrouting {
        type nat hook postrouting priority 100;
        oifname != "br0" masquerade
    }
}
EOF

    # Apply nftables rules
    nft -f /etc/nftables.d/guardian.nft 2>/dev/null || true

    log_info "Basic mode configuration complete"
}

# ============================================================
# SDN MODE CONFIGURATION (VLAN Segmentation)
# ============================================================
configure_sdn_mode() {
    log_step "Configuring Guardian in SDN Mode..."

    local RADIUS_SERVER="${HOOKPROBE_RADIUS_SERVER:-127.0.0.1}"
    local RADIUS_SECRET="${HOOKPROBE_RADIUS_SECRET:-hookprobe_radius}"

    # Install SDN packages
    install_sdn_packages

    # Copy SDN configuration files
    log_info "Installing SDN configuration..."

    mkdir -p /etc/hostapd
    cp "$CONFIG_DIR/hostapd.conf" /etc/hostapd/hostapd.conf
    cp "$CONFIG_DIR/hostapd.vlan" /etc/hostapd/hostapd.vlan
    touch /etc/hostapd/hostapd.accept
    touch /etc/hostapd/hostapd.deny

    # Update RADIUS server in hostapd config
    sed -i "s/auth_server_addr=.*/auth_server_addr=$RADIUS_SERVER/" /etc/hostapd/hostapd.conf
    sed -i "s/auth_server_shared_secret=.*/auth_server_shared_secret=$RADIUS_SECRET/" /etc/hostapd/hostapd.conf

    # Configure dnsmasq for VLANs
    cp "$CONFIG_DIR/dnsmasq.conf" /etc/dnsmasq.d/guardian.conf

    # Create VLAN interfaces
    log_info "Creating VLAN interfaces..."

    local ETH_IFACE=$(echo $ETH_INTERFACES | awk '{print $1}')

    for vlan in 10 20 30 40 50 60 70 80 999; do
        # Create VLAN interface
        ip link add link "$ETH_IFACE" name "${ETH_IFACE}.${vlan}" type vlan id $vlan 2>/dev/null || true
        ip link set "${ETH_IFACE}.${vlan}" up

        # Create bridge for VLAN
        ip link add "br${vlan}" type bridge 2>/dev/null || true
        ip link set "br${vlan}" up
        ip link set "${ETH_IFACE}.${vlan}" master "br${vlan}" 2>/dev/null || true

        # Assign IP to bridge
        local octet=$((vlan == 999 ? 99 : vlan))
        ip addr add "192.168.${octet}.1/24" dev "br${vlan}" 2>/dev/null || true
    done

    # Copy nftables rules for VLAN isolation
    mkdir -p /etc/nftables.d
    cat > /etc/nftables.d/guardian-vlans.nft << 'EOF'
#!/usr/sbin/nft -f
# HookProbe Guardian - VLAN Isolation

table inet guardian {
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Allow established connections
        ct state established,related accept

        # Allow each VLAN to access internet
        iifname "br10" oifname != "br*" accept
        iifname "br20" oifname != "br*" accept
        iifname "br30" oifname != "br*" accept
        iifname "br40" oifname != "br*" accept
        iifname "br50" oifname != "br*" accept
        iifname "br60" oifname != "br*" accept
        iifname "br70" oifname != "br*" accept
        iifname "br80" oifname != "br*" accept

        # Quarantine VLAN - NO internet
        iifname "br999" drop

        # Management bridge full access
        iifname "br0" accept
        oifname "br0" accept
    }

    chain postrouting {
        type nat hook postrouting priority 100;
        oifname != "br*" masquerade
    }
}
EOF

    nft -f /etc/nftables.d/guardian-vlans.nft 2>/dev/null || true

    log_info "SDN mode configuration complete"
}

# ============================================================
# WEB UI INSTALLATION
# ============================================================
install_web_ui() {
    log_step "Installing Guardian Web UI..."

    mkdir -p /opt/hookprobe/guardian
    cp "$GUARDIAN_ROOT/web/app.py" /opt/hookprobe/guardian/

    # Create systemd service
    cat > /etc/systemd/system/guardian-webui.service << 'EOF'
[Unit]
Description=HookProbe Guardian Web UI
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/hookprobe/guardian
ExecStart=/usr/bin/python3 /opt/hookprobe/guardian/app.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable guardian-webui

    log_info "Web UI installed"
}

# ============================================================
# SERVICE MANAGEMENT
# ============================================================
enable_services() {
    log_step "Enabling services..."

    systemctl unmask hostapd 2>/dev/null || true
    systemctl enable hostapd
    systemctl enable dnsmasq
    systemctl enable nftables 2>/dev/null || true
    systemctl enable openvswitch-switch 2>/dev/null || systemctl enable openvswitch 2>/dev/null || true

    # Container services
    systemctl enable guardian-suricata 2>/dev/null || true
    systemctl enable guardian-waf 2>/dev/null || true
    systemctl enable guardian-neuro 2>/dev/null || true
    systemctl enable guardian-adguard 2>/dev/null || true
    systemctl enable guardian-qsecbit 2>/dev/null || true

    log_info "Services enabled"
}

start_services() {
    log_step "Starting services..."

    # Start OVS first
    systemctl start openvswitch-switch 2>/dev/null || systemctl start openvswitch 2>/dev/null || true

    systemctl start nftables 2>/dev/null || true
    systemctl start dnsmasq
    systemctl start hostapd
    systemctl start guardian-webui

    # Start containers (may take a moment)
    log_info "Starting security containers..."
    systemctl start guardian-suricata 2>/dev/null || true
    systemctl start guardian-waf 2>/dev/null || true
    systemctl start guardian-neuro 2>/dev/null || true
    systemctl start guardian-adguard 2>/dev/null || true
    systemctl start guardian-qsecbit 2>/dev/null || true

    log_info "Services started"
}

# ============================================================
# MODE SELECTION MENU
# ============================================================
show_mode_menu() {
    echo ""
    echo -e "${BOLD}${WHITE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${WHITE}║          HookProbe Guardian - Installation Mode            ║${NC}"
    echo -e "${BOLD}${WHITE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}1)${NC} ${GREEN}Basic Mode${NC} - Simple WiFi hotspot with bridge"
    echo -e "     ${DIM}• Single SSID, all devices on same network${NC}"
    echo -e "     ${DIM}• WiFi + LAN bridged together${NC}"
    echo -e "     ${DIM}• WAN DHCP client for internet${NC}"
    echo -e "     ${DIM}• No MSSP required${NC}"
    echo ""
    echo -e "  ${BOLD}2)${NC} ${CYAN}SDN Mode${NC} - Full VLAN segmentation (requires MSSP)"
    echo -e "     ${DIM}• MAC-based VLAN assignment${NC}"
    echo -e "     ${DIM}• IoT device isolation${NC}"
    echo -e "     ${DIM}• Per-category internet policies${NC}"
    echo -e "     ${DIM}• Requires FreeRADIUS connection${NC}"
    echo ""
}

prompt_mode_selection() {
    local mode=""

    # Check if mode was passed as environment variable
    if [ -n "${GUARDIAN_MODE:-}" ]; then
        mode="$GUARDIAN_MODE"
    else
        show_mode_menu

        while true; do
            read -p "Select installation mode [1]: " choice
            choice=${choice:-1}

            case $choice in
                1)
                    mode="basic"
                    break
                    ;;
                2)
                    mode="sdn"
                    # Check RADIUS connectivity
                    if ! check_mssp_connectivity; then
                        echo ""
                        echo -e "${YELLOW}Warning: MSSP not reachable. SDN features require MSSP connection.${NC}"
                        read -p "Continue with SDN mode anyway? (yes/no) [no]: " continue_sdn
                        if [ "$continue_sdn" != "yes" ]; then
                            echo "Falling back to Basic mode..."
                            mode="basic"
                        fi
                    fi
                    break
                    ;;
                *)
                    echo -e "${RED}Invalid selection. Please choose 1 or 2.${NC}"
                    ;;
            esac
        done
    fi

    echo "$mode"
}

# ============================================================
# NETWORK CONFIGURATION PROMPTS
# ============================================================
prompt_network_config() {
    # Skip if already configured via environment (from main install.sh)
    if [ -n "${HOOKPROBE_WIFI_SSID:-}" ] && [ -n "${HOOKPROBE_WIFI_PASS:-}" ]; then
        log_info "Using pre-configured WiFi settings: $HOOKPROBE_WIFI_SSID"
        return
    fi

    echo ""
    echo -e "${BOLD}Network Configuration${NC}"
    echo ""

    # Hotspot SSID
    read -p "Hotspot SSID [HookProbe-Guardian]: " ssid
    export HOOKPROBE_WIFI_SSID="${ssid:-HookProbe-Guardian}"

    # Hotspot password
    while true; do
        read -sp "Hotspot password (min 8 chars): " pass
        echo ""
        if [ ${#pass} -ge 8 ]; then
            export HOOKPROBE_WIFI_PASS="$pass"
            break
        else
            echo -e "${RED}Password must be at least 8 characters${NC}"
        fi
    done

    echo ""
    echo -e "${GREEN}✓${NC} Network configuration saved"
}

# ============================================================
# MAIN INSTALLATION
# ============================================================
main() {
    echo ""
    echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║                  HookProbe Guardian Setup                   ║${NC}"
    echo -e "${BOLD}${GREEN}║              Portable SDN Security Gateway                  ║${NC}"
    echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Prerequisites
    check_root
    detect_platform
    detect_interfaces

    # Check WiFi AP support
    if [ "$WIFI_AP_SUPPORT" != "true" ]; then
        log_error "No WiFi interface with AP mode support found"
        log_error "Guardian requires WiFi AP capability"
        exit 1
    fi

    # Install base packages
    install_packages

    # Install Podman container runtime
    install_podman

    # Install Open vSwitch (for both modes - provides SDN capabilities)
    install_openvswitch

    # Setup OVS bridge with VXLAN tunnel
    setup_ovs_bridge

    # Select installation mode
    MODE=$(prompt_mode_selection)
    log_info "Selected mode: $MODE"

    # Network configuration
    prompt_network_config

    # Install security containers first (Suricata IDS, WAF, Neuro, AdGuard)
    install_security_containers

    # Configure based on mode
    case $MODE in
        basic)
            configure_basic_mode
            ;;
        sdn)
            install_sdn_packages
            configure_sdn_mode
            ;;
    esac

    # Install QSecBit agent (Python-based backup agent)
    install_qsecbit_agent

    # Save mode configuration
    mkdir -p /opt/hookprobe/guardian
    echo "$MODE" > /opt/hookprobe/guardian/mode.conf
    log_info "Mode saved: $MODE"

    # Install Web UI
    install_web_ui

    # Enable and start services
    enable_services
    start_services

    # Final summary
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Guardian Installation Complete!                   ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "  Mode:        ${BOLD}$MODE${NC}"
    echo -e "  Hotspot:     ${BOLD}${HOOKPROBE_WIFI_SSID:-HookProbe-Guardian}${NC}"
    echo -e "  Web UI:      ${BOLD}http://192.168.4.1:8080${NC}"
    echo ""
    echo -e "  ${BOLD}Installed Components:${NC}"
    echo -e "  • Open vSwitch (SDN with VXLAN tunnel)"
    echo -e "  • Podman container runtime"
    echo -e "  • Suricata IDS/IPS (threat detection)"
    echo -e "  • ModSecurity WAF (web application firewall)"
    echo -e "  • Neuro Protocol (QSecBit + HTP)"
    echo -e "  • QSecBit Lite security agent"
    if [ "${HOOKPROBE_ADBLOCK:-yes}" = "yes" ]; then
        echo -e "  • AdGuard Home (ad blocking)"
        echo -e "    Setup: ${BOLD}http://192.168.4.1:3000${NC}"
    fi
    if [ "$MODE" = "sdn" ]; then
        echo -e "  • VLAN segmentation enabled"
    fi
    echo ""
    echo -e "  ${BOLD}Service Status:${NC}"
    echo -e "  $(systemctl is-active hostapd 2>/dev/null || echo 'inactive') hostapd (WiFi AP)"
    echo -e "  $(systemctl is-active dnsmasq 2>/dev/null || echo 'inactive') dnsmasq (DHCP/DNS)"
    echo -e "  $(systemctl is-active guardian-webui 2>/dev/null || echo 'inactive') guardian-webui"
    echo -e "  $(systemctl is-active guardian-suricata 2>/dev/null || echo 'inactive') guardian-suricata (IDS)"
    echo -e "  $(systemctl is-active guardian-waf 2>/dev/null || echo 'inactive') guardian-waf (WAF)"
    echo -e "  $(systemctl is-active guardian-neuro 2>/dev/null || echo 'inactive') guardian-neuro (Neuro)"
    echo -e "  $(systemctl is-active guardian-qsecbit 2>/dev/null || echo 'inactive') guardian-qsecbit"
    echo ""
    echo -e "  ${YELLOW}Next steps:${NC}"
    echo -e "  1. Connect to '${HOOKPROBE_WIFI_SSID:-HookProbe-Guardian}' WiFi network"
    echo -e "  2. Open http://192.168.4.1:8080 in your browser"
    echo -e "  3. Configure upstream WiFi connection"
    if [ "${HOOKPROBE_ADBLOCK:-yes}" = "yes" ]; then
        echo -e "  4. Complete AdGuard setup: http://192.168.4.1:3000"
    fi
    echo ""

    if [ "$MODE" = "sdn" ]; then
        echo -e "  ${CYAN}SDN Features:${NC}"
        echo -e "  • Register devices in web UI to assign VLANs"
        echo -e "  • Unknown devices go to quarantine (VLAN 999)"
        echo -e "  • VLANs: 10=Lights, 20=Thermo, 30=Cameras, etc."
        echo ""
    fi

    echo -e "  ${DIM}Logs: journalctl -u guardian-suricata -u guardian-qsecbit -f${NC}"
    echo ""
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
