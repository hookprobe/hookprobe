#!/bin/bash
# ==============================================================================
# Mesh Orchestrator Container Entrypoint
# ==============================================================================
# Runs HTP/Neuro/DSM communication hub for inter-product mesh networking
#
# Services:
#   - HTP Transport: 8144/UDP+TCP (primary), 443 (fallback), 853 (stealth)
#   - STUN/TURN: 3478/UDP (NAT traversal relay)
#   - Cortex WebSocket: 8766/TCP (visualization bridge)
# NOTE: Fortress deploys override fallback→8543, stealth→8853 via env vars
# ==============================================================================

set -e

DATA_DIR="${MESH_DATA_DIR:-/opt/hookprobe/mesh/data}"
NEURO_DIR="${NEURO_WEIGHT_DIR:-/opt/hookprobe/mesh/neuro}"
LOG_DIR="${LOG_DIR:-/var/log/hookprobe}"

# Ensure directories exist
mkdir -p "$DATA_DIR" "$NEURO_DIR" "$LOG_DIR"

echo "[mesh] HookProbe Mesh Orchestrator starting..."
echo "[mesh] Node ID: ${MESH_NODE_ID:-fortress-$(hostname)}"
echo "[mesh] Node Type: ${MESH_NODE_TYPE:-fortress}"
echo "[mesh] "
echo "[mesh] Port Configuration:"
echo "[mesh]   - HTP Primary:  ${HTP_PRIMARY_PORT:-8144}/UDP+TCP"
echo "[mesh]   - HTP Fallback: ${HTP_FALLBACK_PORT:-443}/UDP+TCP"
echo "[mesh]   - HTP Stealth:  ${HTP_STEALTH_PORT:-853}/UDP+TCP (DoQ/DoT cover)"
echo "[mesh]   - STUN/TURN:    ${HTP_RELAY_PORT:-3478}/UDP"
echo "[mesh]   - Cortex WS:    ${CORTEX_WS_PORT:-8766}/TCP"

# Initialize Neuro weights if first run
if [ ! -f "$NEURO_DIR/weights.bin" ]; then
    echo "[mesh] Initializing neural weight matrix..."
    python -c "
import os
import struct
import hashlib

# Initialize random weights seeded by hardware identity
identity_seed = hashlib.sha256(
    (os.environ.get('MESH_NODE_ID', 'fortress') + os.uname().nodename).encode()
).digest()

# Create Q16.16 fixed-point weight matrix (128x128 = 16KB)
weights = []
for i in range(128 * 128):
    # Deterministic but unique per-node weight initialization
    seed_byte = identity_seed[(i * 7) % 32]
    weight = ((seed_byte - 128) << 8)  # Q16.16 range [-0.5, 0.5]
    weights.append(weight)

weight_path = os.environ.get('NEURO_WEIGHT_DIR', '/opt/hookprobe/mesh/neuro')
os.makedirs(weight_path, exist_ok=True)
with open(f'{weight_path}/weights.bin', 'wb') as f:
    for w in weights:
        f.write(struct.pack('<i', w))
print(f'[mesh] Neural weights initialized ({len(weights)} parameters)')
"
fi

# Initialize mesh identity if first run
if [ ! -f "$DATA_DIR/identity.json" ]; then
    echo "[mesh] Generating mesh identity..."
    python -c "
import json
import os
import hashlib
import time
import socket

node_id = os.environ.get('MESH_NODE_ID', f'fortress-{socket.gethostname()}')
node_type = os.environ.get('MESH_NODE_TYPE', 'fortress')

# Generate deterministic key fingerprint
fingerprint = hashlib.sha256(
    f'{node_id}:{node_type}:{time.time()}'.encode()
).hexdigest()[:32]

identity = {
    'node_id': node_id,
    'node_type': node_type,
    'fingerprint': fingerprint,
    'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'capabilities': [
        'htp_transport',
        'neuro_auth',
        'dsm_consensus',
        'cortex_bridge',
        'threat_propagation'
    ],
    'ports': {
        'htp_primary': int(os.environ.get('HTP_PRIMARY_PORT', 8144)),
        'htp_fallback': int(os.environ.get('HTP_FALLBACK_PORT', 443)),
        'htp_stealth': int(os.environ.get('HTP_STEALTH_PORT', 853)),
        'relay': int(os.environ.get('HTP_RELAY_PORT', 3478)),
        'cortex': int(os.environ.get('CORTEX_WS_PORT', 8766))
    }
}

data_dir = os.environ.get('MESH_DATA_DIR', '/opt/hookprobe/mesh/data')
os.makedirs(data_dir, exist_ok=True)
with open(f'{data_dir}/identity.json', 'w') as f:
    json.dump(identity, f, indent=2)
print(f'[mesh] Identity generated: {node_id} ({fingerprint[:8]}...)')
"
fi

echo "[mesh] Starting services..."

# Trap to cleanup on exit
PEER_SERVER_PID=""
VPN_GW_PID=""
cleanup() {
    echo "[mesh] Shutting down..."
    [ -n "$PEER_SERVER_PID" ] && kill "$PEER_SERVER_PID" 2>/dev/null || true
    [ -n "$VPN_GW_PID" ] && kill "$VPN_GW_PID" 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# ---------------------------------------------------------------------------
# 1. Mesh Peer Server (TCP 8144) + HTTP API (TCP 8766)
# ---------------------------------------------------------------------------
# mesh_server.py now serves health/status/gossip on --api-port internally,
# so no separate health server process is needed.
BOOTSTRAP_ARGS=""
if [ -n "${MESH_BOOTSTRAP_PEERS:-}" ]; then
    echo "[mesh] Bootstrap peers: ${MESH_BOOTSTRAP_PEERS}"
    BOOTSTRAP_ARGS="--bootstrap ${MESH_BOOTSTRAP_PEERS}"
fi

echo "[mesh] Starting Mesh Peer Server on TCP ${HTP_PRIMARY_PORT:-8144}..."
echo "[mesh] HTTP API (health/status/gossip) on TCP ${CORTEX_WS_PORT:-8766}..."
python3 /opt/hookprobe/shared/mesh/mesh_server.py \
    --port "${HTP_PRIMARY_PORT:-8144}" \
    --api-port "${CORTEX_WS_PORT:-8766}" \
    --node-id "${MESH_NODE_ID:-fortress001}" \
    ${BOOTSTRAP_ARGS} \
    --verbose \
    > >(sed -u 's/^/[peer-server] /') 2>&1 &
PEER_SERVER_PID=$!

# Give peer server time to bind
sleep 2

# ---------------------------------------------------------------------------
# 2. HTP VPN Gateway (UDP 8144) — optional, graceful failure without TUN
# ---------------------------------------------------------------------------
# Creates TUN device, handles HELLO→CHALLENGE→ATTEST→ACCEPT handshake,
# assigns client IPs from 10.250.0.0/24, encrypts with ChaCha20-Poly1305,
# and responds to STUN Binding Requests on the same port.
# NOTE: If /dev/net/tun is unavailable the gateway exits — this is non-fatal,
# the peer server continues running for mesh gossip.
if [ -c /dev/net/tun ]; then
    echo "[mesh] Starting HTP VPN Gateway on UDP ${HTP_PRIMARY_PORT:-8144}..."
    PSK_ARG=""
    if [ -f "${VPN_PSK_FILE:-/opt/hookprobe/mesh/data/vpn_psk}" ]; then
        PSK_ARG="--psk-file ${VPN_PSK_FILE:-/opt/hookprobe/mesh/data/vpn_psk}"
        echo "[mesh] VPN PSK authentication enabled"
    fi
    python3 /opt/hookprobe/shared/mesh/htp_gateway.py \
        --port "${HTP_PRIMARY_PORT:-8144}" \
        --wan "${WAN_INTERFACE:-eth0}" \
        --max-clients "${MAX_VPN_CLIENTS:-20}" \
        $PSK_ARG \
        --verbose \
        > >(sed -u 's/^/[vpn-gw] /') 2>&1 &
    VPN_GW_PID=$!
else
    echo "[mesh] /dev/net/tun not available — VPN gateway disabled (gossip-only mode)"
fi

# Wait for peer server — it's the critical process
wait "$PEER_SERVER_PID"
echo "[mesh] Peer server exited, shutting down..."
cleanup
