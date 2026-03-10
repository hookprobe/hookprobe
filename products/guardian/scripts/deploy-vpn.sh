#!/bin/bash
# =============================================================================
# Guardian HTP VPN Deployment Script
# =============================================================================
# Deploys VPN client + PSK auth to Guardian and configures MSSP gateway.
# Run from Fortress (10.200.0.1) which has SSH access to both.
#
# Usage: sudo ./deploy-vpn.sh
# =============================================================================

set -euo pipefail

GUARDIAN_HOST="10.200.0.3"
GUARDIAN_USER="andrei"
MSSP_HOST="mssp.hookprobe.com"
MSSP_USER="andrei"
PSK="Gf4BWtyWstFM1ImwafyG-KcSebIsjc-5A8wh4z7QCfY"
REPO_DIR="/home/andrei/hookprobe"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

# ---------------------------------------------------------------------------
# Phase 1: MSSP Gateway — Enable PSK authentication
# ---------------------------------------------------------------------------
phase1_mssp() {
    info "Phase 1: Configuring MSSP gateway with PSK..."

    # Verify connectivity
    if ! ssh -o ConnectTimeout=5 "${MSSP_USER}@${MSSP_HOST}" "echo ok" &>/dev/null; then
        error "Cannot reach MSSP at ${MSSP_HOST}"
        return 1
    fi

    # Deploy updated htp_gateway.py
    info "Deploying htp_gateway.py to MSSP..."
    scp "${REPO_DIR}/shared/mesh/htp_gateway.py" \
        "${MSSP_USER}@${MSSP_HOST}:/tmp/htp_gateway.py"

    ssh "${MSSP_USER}@${MSSP_HOST}" "
        sudo podman cp /tmp/htp_gateway.py hookprobe-mesh:/opt/hookprobe/shared/mesh/htp_gateway.py
        rm /tmp/htp_gateway.py
    "

    # Deploy PSK file inside container
    info "Deploying PSK to MSSP container..."
    ssh "${MSSP_USER}@${MSSP_HOST}" "
        echo '${PSK}' | sudo podman exec -i hookprobe-mesh tee /opt/hookprobe/mesh/data/vpn_psk > /dev/null
        sudo podman exec hookprobe-mesh chmod 600 /opt/hookprobe/mesh/data/vpn_psk
    "

    # Fix entrypoint to pass PSK_ARG to exec line
    info "Updating MSSP entrypoint with PSK support..."
    ssh "${MSSP_USER}@${MSSP_HOST}" "
        sudo podman exec hookprobe-mesh bash -c '
            cat > /tmp/fix-entrypoint.py << \"PYEOF\"
import re

with open(\"/opt/hookprobe/entrypoint-mesh.sh\", \"r\") as f:
    content = f.read()

# Ensure PSK block exists before the exec line
if \"VPN PSK\" not in content:
    content = content.replace(
        \"exec python3 /opt/hookprobe/shared/mesh/htp_gateway.py\",
        \"\"\"PSK_ARG=\"\"
if [ -f \"/opt/hookprobe/mesh/data/vpn_psk\" ]; then
    PSK_ARG=\"--psk-file /opt/hookprobe/mesh/data/vpn_psk\"
    echo \"[mesh] VPN PSK authentication enabled\"
fi
exec python3 /opt/hookprobe/shared/mesh/htp_gateway.py\"\"\"
    )

# Ensure PSK_ARG is passed on the exec line
if \"\\$PSK_ARG\" not in content:
    content = content.replace(
        \"--verbose\",
        \"\\$PSK_ARG \\\\\\n        --verbose\"
    )

with open(\"/opt/hookprobe/entrypoint-mesh.sh\", \"w\") as f:
    f.write(content)
PYEOF
            python3 /tmp/fix-entrypoint.py
        '
    "

    # Restart container
    info "Restarting MSSP mesh container..."
    ssh "${MSSP_USER}@${MSSP_HOST}" "
        sudo podman restart hookprobe-mesh
        sleep 3
        sudo podman logs --tail 20 hookprobe-mesh
    "

    info "MSSP gateway configured with PSK."
}

# ---------------------------------------------------------------------------
# Phase 2: Guardian — Deploy code + PSK + systemd service
# ---------------------------------------------------------------------------
phase2_guardian() {
    info "Phase 2: Configuring Guardian VPN client..."

    # Verify connectivity
    if ! ssh -o ConnectTimeout=5 "${GUARDIAN_USER}@${GUARDIAN_HOST}" "echo ok" &>/dev/null; then
        error "Cannot reach Guardian at ${GUARDIAN_HOST}"
        return 1
    fi

    # Deploy updated VPN client
    info "Deploying htp_vpn_client.py to Guardian..."
    scp "${REPO_DIR}/products/guardian/lib/htp_vpn_client.py" \
        "${GUARDIAN_USER}@${GUARDIAN_HOST}:/tmp/htp_vpn_client.py"

    ssh "${GUARDIAN_USER}@${GUARDIAN_HOST}" "
        sudo cp /tmp/htp_vpn_client.py /opt/hookprobe/guardian/lib/htp_vpn_client.py
        sudo chmod 644 /opt/hookprobe/guardian/lib/htp_vpn_client.py
        rm /tmp/htp_vpn_client.py
    "

    # Update VPN config with PSK (device_token) and mesh.hookprobe.com
    info "Configuring Guardian VPN with PSK..."
    ssh "${GUARDIAN_USER}@${GUARDIAN_HOST}" "
        sudo python3 -c \"
import json, os
conf_path = '/etc/hookprobe/guardian_vpn.json'
try:
    with open(conf_path) as f:
        conf = json.load(f)
except:
    conf = {}

conf['gateway_host'] = 'mesh.hookprobe.com'
conf['gateway_port'] = 8144
conf['device_token'] = '${PSK}'
conf['node_id'] = 'guardian-pi'
conf['kill_switch'] = True
conf['auto_connect'] = True
conf['wan_interface'] = 'eth0'
conf['lan_interface'] = 'br0'
conf['tun_device'] = 'htp0'
conf['tun_local_ip'] = '10.250.0.2'
conf['tun_remote_ip'] = '10.250.0.1'
conf['mtu'] = 1400

os.makedirs(os.path.dirname(conf_path), exist_ok=True)
with open(conf_path, 'w') as f:
    json.dump(conf, f, indent=2)
os.chmod(conf_path, 0o600)
print('Config written:', conf_path)
\"
    "

    # Deploy systemd service
    info "Installing guardian-htp-vpn systemd service..."
    scp "${REPO_DIR}/products/guardian/config/systemd/guardian-htp-vpn.service" \
        "${GUARDIAN_USER}@${GUARDIAN_HOST}:/tmp/guardian-htp-vpn.service"

    ssh "${GUARDIAN_USER}@${GUARDIAN_HOST}" "
        sudo cp /tmp/guardian-htp-vpn.service /etc/systemd/system/guardian-htp-vpn.service
        sudo systemctl daemon-reload
        sudo systemctl enable guardian-htp-vpn.service
        rm /tmp/guardian-htp-vpn.service
    "

    info "Guardian VPN configured."
}

# ---------------------------------------------------------------------------
# Phase 3: Test VPN connection
# ---------------------------------------------------------------------------
phase3_test() {
    info "Phase 3: Testing VPN connection..."

    ssh "${GUARDIAN_USER}@${GUARDIAN_HOST}" "
        sudo systemctl start guardian-htp-vpn
        sleep 5
        echo '--- VPN service status ---'
        sudo systemctl status guardian-htp-vpn --no-pager -l | head -20
        echo ''
        echo '--- TUN interface ---'
        ip addr show htp0 2>/dev/null || echo 'htp0 not found (handshake may still be in progress)'
        echo ''
        echo '--- Default route ---'
        ip route show default
        echo ''
        echo '--- Exit IP test ---'
        curl -s --max-time 10 https://ifconfig.me 2>/dev/null || echo 'Could not reach ifconfig.me'
        echo ''
    "
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo "=========================================="
    echo "  Guardian HTP VPN Deployment"
    echo "=========================================="
    echo ""

    phase1_mssp
    echo ""
    phase2_guardian
    echo ""
    phase3_test

    echo ""
    info "Deployment complete!"
    info "Expected exit IP: 130.61.174.233 (MSSP Oracle Cloud)"
    info "To check status: ssh ${GUARDIAN_USER}@${GUARDIAN_HOST} 'sudo systemctl status guardian-htp-vpn'"
    info "To view logs: ssh ${GUARDIAN_USER}@${GUARDIAN_HOST} 'sudo journalctl -u guardian-htp-vpn -f'"
}

main "$@"
