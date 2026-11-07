#!/bin/bash
# HookProbe HTP Mesh Gateway — Deployment Script
#
# Installs the HTP VPN Gateway on any Linux server.
# Run on MSSP, Fortress, or any machine with internet access.
#
# Usage: sudo ./install.sh [--wan eth0] [--port 8144] [--uninstall]
set -euo pipefail

WAN_INTERFACE="${WAN_INTERFACE:-eth0}"
LISTEN_PORT="${LISTEN_PORT:-8144}"
MAX_CLIENTS="${MAX_CLIENTS:-10}"
INSTALL_DIR="/opt/hookprobe"
CONF_DIR="/etc/hookprobe"
CONF_FILE="${CONF_DIR}/mesh-gateway.conf"
SERVICE_NAME="mesh-gateway"

# Parse arguments
UNINSTALL=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --wan)      WAN_INTERFACE="$2"; shift 2 ;;
        --port)     LISTEN_PORT="$2"; shift 2 ;;
        --max)      MAX_CLIENTS="$2"; shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
        *)          echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root"
    exit 1
fi

# --- Uninstall ---
if $UNINSTALL; then
    echo "Stopping and removing mesh-gateway..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    echo "Mesh gateway uninstalled. Config preserved at ${CONF_FILE}"
    exit 0
fi

# --- Install ---
echo "=== HookProbe HTP Mesh Gateway Installer ==="
echo "WAN interface: ${WAN_INTERFACE}"
echo "Listen port:   UDP ${LISTEN_PORT}"
echo "Max clients:   ${MAX_CLIENTS}"
echo ""

# 1. Detect WAN interface if default doesn't exist
if ! ip link show "${WAN_INTERFACE}" &>/dev/null; then
    WAN_INTERFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    echo "Auto-detected WAN interface: ${WAN_INTERFACE}"
fi

# 2. Copy gateway script
echo "[1/5] Installing gateway..."
mkdir -p "${INSTALL_DIR}/shared/mesh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ -f "${REPO_ROOT}/shared/mesh/htp_gateway.py" ]]; then
    cp "${REPO_ROOT}/shared/mesh/htp_gateway.py" "${INSTALL_DIR}/shared/mesh/htp_gateway.py"
else
    echo "Error: htp_gateway.py not found at ${REPO_ROOT}/shared/mesh/"
    exit 1
fi
chmod 755 "${INSTALL_DIR}/shared/mesh/htp_gateway.py"

# 3. Create config
echo "[2/5] Writing config..."
mkdir -p "${CONF_DIR}"
cat > "${CONF_FILE}" <<CONF
{
    "port": ${LISTEN_PORT},
    "wan_interface": "${WAN_INTERFACE}",
    "max_clients": ${MAX_CLIENTS}
}
CONF
chmod 600 "${CONF_FILE}"

# 4. Install systemd service
echo "[3/5] Installing systemd service..."
cp "${SCRIPT_DIR}/mesh-gateway.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload

# 5. Enable IP forwarding
echo "[4/5] Enabling IP forwarding..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# 6. Open firewall port
echo "[5/5] Configuring firewall..."
if command -v ufw &>/dev/null; then
    ufw allow "${LISTEN_PORT}/udp" comment "HTP Mesh Gateway" 2>/dev/null || true
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port="${LISTEN_PORT}/udp" 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
fi

# 7. Install Python dependency
if ! python3 -c "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305" 2>/dev/null; then
    echo "Installing cryptography package..."
    pip3 install cryptography 2>/dev/null || apt-get install -y python3-cryptography 2>/dev/null || true
fi

# 8. Start
echo ""
echo "Starting mesh-gateway..."
systemctl enable "${SERVICE_NAME}"
systemctl start "${SERVICE_NAME}"

if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo ""
    echo "=== HTP Mesh Gateway is running ==="
    echo "Listening: UDP ${LISTEN_PORT}"
    echo "WAN:       ${WAN_INTERFACE}"
    echo "Config:    ${CONF_FILE}"
    echo "Logs:      journalctl -u ${SERVICE_NAME} -f"
    echo ""
    echo "Nodes can now connect with: gateway_host=$(hostname -f)"
else
    echo "Warning: service failed to start. Check: journalctl -u ${SERVICE_NAME}"
    exit 1
fi
