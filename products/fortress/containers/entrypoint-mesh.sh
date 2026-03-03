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
HEALTH_PID=""
cleanup() {
    echo "[mesh] Shutting down..."
    [ -n "$HEALTH_PID" ] && kill "$HEALTH_PID" 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# Start health check endpoint in background
# This serves the container healthcheck on CORTEX_WS_PORT (8766)
echo "[mesh] Starting health endpoint on port ${CORTEX_WS_PORT:-8766}..."
python3 -c "
import asyncio, os, json, time

async def handle(reader, writer):
    request = await reader.read(1024)
    if b'GET /health' in request:
        body = json.dumps({
            'status': 'healthy',
            'service': 'mesh-orchestrator',
            'node_id': os.environ.get('MESH_NODE_ID', 'unknown'),
            'uptime': int(time.time() - START),
        })
        resp = f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}'
    else:
        resp = 'HTTP/1.1 404 Not Found\r\n\r\n'
    writer.write(resp.encode())
    await writer.drain()
    writer.close()
    await writer.wait_closed()

START = time.time()

async def main():
    port = int(os.environ.get('CORTEX_WS_PORT', 8766))
    server = await asyncio.start_server(handle, '0.0.0.0', port)
    print(f'[health] Listening on port {port}')
    await server.serve_forever()

asyncio.run(main())
" 2>&1 | sed 's/^/[health] /' &
HEALTH_PID=$!

# Give health endpoint time to bind
sleep 1

# Start HTP VPN Gateway (uses shared/mesh/htp_gateway.py)
# This is the real gateway: creates TUN device, handles HELLO→CHALLENGE→ATTEST→ACCEPT
# handshake, assigns client IPs from 10.250.0.0/24, encrypts with ChaCha20-Poly1305,
# and responds to STUN Binding Requests on the same port.
echo "[mesh] Starting HTP VPN Gateway on port ${HTP_PRIMARY_PORT:-8144}..."
exec python3 /opt/hookprobe/shared/mesh/htp_gateway.py \
    --port "${HTP_PRIMARY_PORT:-8144}" \
    --wan "${WAN_INTERFACE:-eth0}" \
    --max-clients "${MAX_VPN_CLIENTS:-20}" \
    --verbose
