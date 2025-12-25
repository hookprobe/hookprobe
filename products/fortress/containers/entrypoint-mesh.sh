#!/bin/bash
# ==============================================================================
# Mesh Orchestrator Container Entrypoint
# ==============================================================================
# Runs HTP/Neuro/DSM communication hub for inter-product mesh networking
#
# Services:
#   - HTP Transport: 8144/UDP+TCP (primary), 8443 (fallback), 853 (stealth)
#   - STUN/TURN: 3478/UDP (NAT traversal relay)
#   - Cortex WebSocket: 8766/TCP (visualization bridge)
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
echo "[mesh]   - HTP Fallback: ${HTP_FALLBACK_PORT:-8443}/UDP+TCP"
echo "[mesh]   - HTP Stealth:  ${HTP_STEALTH_PORT:-853}/UDP+TCP (DoT/DoQ cover)"
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
        'htp_fallback': int(os.environ.get('HTP_FALLBACK_PORT', 8443)),
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

# Start Cortex WebSocket bridge in background if enabled
if [ "${CORTEX_ENABLED:-true}" = "true" ]; then
    echo "[mesh] Starting Cortex visualization bridge..."
    python -m shared.cortex.backend.server \
        --host 0.0.0.0 \
        --port "${CORTEX_WS_PORT:-8766}" \
        --mode live \
        2>&1 | sed 's/^/[cortex] /' &
    CORTEX_PID=$!
    echo "[mesh] Cortex WebSocket bridge started (PID: $CORTEX_PID)"
fi

# Give Cortex time to start
sleep 1

# Trap to cleanup on exit
cleanup() {
    echo "[mesh] Shutting down..."
    [ -n "$CORTEX_PID" ] && kill $CORTEX_PID 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# Start mesh transport in foreground
echo "[mesh] Starting HTP/Neuro/DSM transport..."
exec python -c "
import asyncio
import json
import os
import signal
import sys
import socket
from datetime import datetime

# Add hookprobe to path
sys.path.insert(0, '/opt/hookprobe')

# Graceful shutdown
shutdown_event = asyncio.Event()

def handle_signal(sig, frame):
    print(f'[mesh] Received signal {sig}, initiating shutdown...')
    shutdown_event.set()

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

async def health_server():
    '''Simple HTTP health endpoint'''
    async def handle_request(reader, writer):
        request = await reader.read(1024)
        if b'GET /health' in request:
            response = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"healthy\",\"service\":\"mesh-orchestrator\"}'
        else:
            response = 'HTTP/1.1 404 Not Found\r\n\r\n'
        writer.write(response.encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    port = int(os.environ.get('CORTEX_WS_PORT', 8766))
    server = await asyncio.start_server(handle_request, '0.0.0.0', port)
    print(f'[mesh] Health endpoint listening on port {port}')
    return server

async def htp_listener(port, protocol='udp'):
    '''HTP transport listener'''
    print(f'[mesh] HTP {protocol.upper()} listener starting on port {port}')

    if protocol == 'udp':
        class HTPProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                # Log incoming HTP packets (first 8 bytes header)
                if len(data) >= 8:
                    print(f'[mesh] HTP UDP packet from {addr[0]}:{addr[1]} ({len(data)} bytes)')

        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            HTPProtocol, local_addr=('0.0.0.0', port)
        )
        return transport
    else:  # TCP
        async def handle_tcp(reader, writer):
            addr = writer.get_extra_info('peername')
            print(f'[mesh] HTP TCP connection from {addr[0]}:{addr[1]}')
            try:
                while not reader.at_eof():
                    data = await reader.read(4096)
                    if not data:
                        break
                    print(f'[mesh] HTP TCP data from {addr[0]}:{addr[1]} ({len(data)} bytes)')
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle_tcp, '0.0.0.0', port)
        return server

async def stun_relay(port):
    '''STUN/TURN relay for NAT traversal'''
    print(f'[mesh] STUN/TURN relay starting on port {port}/UDP')

    class STUNProtocol(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            # Basic STUN binding response
            if len(data) >= 20 and data[0:2] == b'\\x00\\x01':
                print(f'[mesh] STUN Binding Request from {addr[0]}:{addr[1]}')
                # Would send STUN response here in full implementation

    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        STUNProtocol, local_addr=('0.0.0.0', port)
    )
    return transport

async def main():
    print('[mesh] Mesh Orchestrator initializing...')

    # Load identity
    data_dir = os.environ.get('MESH_DATA_DIR', '/opt/hookprobe/mesh/data')
    try:
        with open(f'{data_dir}/identity.json') as f:
            identity = json.load(f)
        print(f'[mesh] Node: {identity[\"node_id\"]} ({identity[\"node_type\"]})')
    except Exception as e:
        print(f'[mesh] Warning: Could not load identity: {e}')
        identity = {'node_id': 'unknown', 'node_type': 'fortress'}

    # Get ports from environment
    primary_port = int(os.environ.get('HTP_PRIMARY_PORT', 8144))
    fallback_port = int(os.environ.get('HTP_FALLBACK_PORT', 8443))
    stealth_port = int(os.environ.get('HTP_STEALTH_PORT', 853))
    relay_port = int(os.environ.get('HTP_RELAY_PORT', 3478))

    # Start all listeners
    tasks = []

    # Health server
    health = await health_server()

    # HTP Primary (UDP + TCP)
    tasks.append(await htp_listener(primary_port, 'udp'))
    tasks.append(await htp_listener(primary_port, 'tcp'))

    # HTP Fallback (UDP + TCP)
    tasks.append(await htp_listener(fallback_port, 'udp'))
    tasks.append(await htp_listener(fallback_port, 'tcp'))

    # HTP Stealth (UDP + TCP)
    tasks.append(await htp_listener(stealth_port, 'udp'))
    tasks.append(await htp_listener(stealth_port, 'tcp'))

    # STUN/TURN relay
    tasks.append(await stun_relay(relay_port))

    print('[mesh] All listeners started, mesh orchestrator ready')
    print(f'[mesh] Timestamp: {datetime.utcnow().isoformat()}Z')

    # Wait for shutdown signal
    await shutdown_event.wait()

    print('[mesh] Closing listeners...')
    health.close()
    await health.wait_closed()

    for task in tasks:
        if hasattr(task, 'close'):
            task.close()
            if hasattr(task, 'wait_closed'):
                await task.wait_closed()

    print('[mesh] Mesh orchestrator stopped')

if __name__ == '__main__':
    asyncio.run(main())
"
