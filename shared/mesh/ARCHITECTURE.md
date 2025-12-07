# Decentralized Security Mesh - Unified Communication Architecture

## Philosophy

> "One node's detection → Everyone's protection"
>
> "Consciousness is the main goal - together we can achieve more in the
> future fight against rogue AI."

The HookProbe mesh forms a **collective consciousness** where each node contributes
its local observations to build a global security picture. This enables autonomous,
resilient defense without central authority.

## Overview

The HookProbe Decentralized Security Mesh (DSM) provides a resilient, anti-blocking
communication layer that integrates three core protocols:

1. **DSM** (Decentralized Security Mesh): Byzantine fault-tolerant consensus
2. **Neuro** (Neural Resonance Protocol): Weight-based authentication
3. **HTP** (HookProbe Transport Protocol): Keyless adaptive transport

## Port Selection Strategy

```
┌─────────────────────────────────────────────────────────────────┐
│  HTP PORT SELECTION (UDP-First Design)                          │
├─────────────────────────────────────────────────────────────────┤
│  PRIMARY:    8144/UDP + 8144/TCP                                │
│  FALLBACK:   443/UDP (QUIC cover) + 443/TCP (TLS-wrapped)       │
│  STEALTH:    853/UDP (DoQ cover) + 853/TCP (DoT cover)          │
│  EMERGENCY:  80/TCP (WebSocket) + ICMP tunnel                   │
├─────────────────────────────────────────────────────────────────┤
│  Rationale:                                                     │
│  • HTP is UDP-native for low-latency mesh communication         │
│  • 8144: Unassigned, unlikely to conflict, 8xxx usually allowed │
│  • 443/UDP: QUIC traffic is common, perfect cover               │
│  • 443/TCP: TLS 1.3 fallback, blends with HTTPS                 │
│  • 853/UDP: DNS-over-QUIC (DoQ) cover, increasingly common      │
│  • 853/TCP: DNS-over-TLS (DoT) cover, widely allowed            │
│  • All encrypted = looks like legitimate encrypted traffic      │
└─────────────────────────────────────────────────────────────────┘
```

## Protocol Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                    UNIFIED MESH TRANSPORT                        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5: Application                                           │
│    └─ File Transfer, VPN, Security Events, Control Messages     │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: DSM (Decentralized Security Mesh)                     │
│    └─ Microblocks, Consensus, Gossip, Checkpoints               │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: Neuro (Neural Resonance Protocol)                     │
│    └─ TER, PoSF Signatures, Weight Evolution, RDV               │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: HTP (HookProbe Transport Protocol)                    │
│    └─ Keyless Auth, Entropy Echo, Adaptive Streaming            │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: Resilient Channel                                     │
│    └─ Multi-Port, TLS Wrapping, Stealth Modes, Failover         │
├─────────────────────────────────────────────────────────────────┤
│  Layer 0: Network (TCP/UDP/ICMP)                                │
│    └─ Port 8144 (primary), 443 (fallback), 853 (stealth)        │
└─────────────────────────────────────────────────────────────────┘
```

## Anti-Blocking Mechanisms

### 1. Automatic Port Fallback

When the primary port (8144) is blocked, the system automatically falls back:

```
8144/UDP → 8144/TCP → 443/UDP (QUIC) → 443/TCP (TLS) → 853/UDP (DoQ) → 853/TCP (DoT) → 80/WS
```

### 2. Blocking Detection

The `BlockingDetector` class monitors for:
- **Consecutive failures**: 3+ failures trigger fallback
- **RST flood**: Active blocking via TCP RST injection
- **Timeout patterns**: Passive blocking/throttling (>80% timeouts)
- **Failure rate**: >70% failure rate triggers port switch

### 3. Traffic Obfuscation

Each stealth mode disguises HTP traffic:

| Mode | Cover Traffic | Port | Protocol |
|------|---------------|------|----------|
| `QUIC_STEALTH` | HTTP/3 (QUIC) | 443/UDP | Looks like Google/Cloudflare |
| `TLS_WRAPPED` | HTTPS | 443/TCP | Standard TLS 1.3 |
| `DOQ_STEALTH` | DNS-over-QUIC | 853/UDP | Encrypted DNS queries |
| `DOT_STEALTH` | DNS-over-TLS | 853/TCP | Privacy DNS resolver |
| `WEBSOCKET` | HTTP WebSocket | 80/443/TCP | Browser-like traffic |

### 4. Neural Resonance Authentication

Instead of PKI certificates, nodes authenticate via shared neural weight state:

```
1. Nodes share initial seed (W0)
2. Each evolves weights from local TER (Telemetry Event Records)
3. Resonance Drift Vector (RDV) proves weight state possession
4. Impossible to forge without exact sensor evolution history
```

## Key Components

### PortManager (`port_manager.py`)

Manages multi-port communication with automatic fallback:

```python
from shared.mesh import PortManager

pm = PortManager()
port = pm.select_best_port()
pm.record_connection(port.port, success=True, latency_ms=50)
```

### ResilientChannel (`resilient_channel.py`)

Provides reliable messaging with automatic reconnection:

```python
from shared.mesh import ResilientChannel

channel = ResilientChannel()
channel.connect("peer.example.com")
channel.send(b"data", reliable=True)
```

### NeuroResonanceEncoder (`neuro_encoder.py`)

Handles neural resonance authentication:

```python
from shared.mesh import NeuroResonanceEncoder

encoder = NeuroResonanceEncoder(seed, node_id)
rdv = encoder.generate_rdv(channel_binding)
valid, reason = encoder.verify_rdv(peer_rdv, peer_id)
```

### ChannelSelector (`channel_selector.py`)

Intelligent channel selection with neuro seeding:

```python
from shared.mesh import ChannelSelector, SelectionStrategy

selector = ChannelSelector(encoder, channels, SelectionStrategy.ADAPTIVE)
channel = selector.select_channel()
```

### UnifiedTransport (`unified_transport.py`)

High-level API integrating all components:

```python
from shared.mesh import UnifiedTransport

transport = UnifiedTransport(node_id, neuro_seed)
transport.connect("peer.example.com")
transport.send_security_event(event_type, severity, source, details)
transport.close()
```

## Packet Format

```
┌────────────────────────────────────────────────────────────┐
│ Offset │ Size │ Field                                      │
├────────┼──────┼────────────────────────────────────────────┤
│ 0      │ 2    │ version (0x0500 for v5.0)                  │
│ 2      │ 1    │ packet_type                                │
│ 3      │ 1    │ flags                                      │
│ 4      │ 4    │ sequence                                   │
│ 8      │ 8    │ flow_token                                 │
│ 16     │ 8    │ timestamp_us                               │
│ 24     │ 4    │ payload_length                             │
│ 28     │ 4    │ checksum (CRC32)                           │
│ 32     │ 16   │ rdv_prefix (neural auth)                   │
├────────┼──────┼────────────────────────────────────────────┤
│ 48     │ var  │ payload                                    │
└────────────────────────────────────────────────────────────┘
```

## Channel Hopping

The `ChannelHopper` provides automatic channel switching based on neural state:

1. Both endpoints share same weight state (via resonance)
2. Weight fingerprint + epoch deterministically selects channel
3. Adversary cannot predict next channel without weight state
4. Hop interval varies (1-10 minutes) based on entropy

## Security Properties

### No PKI Required
- Authentication via neural weight evolution
- No certificates to revoke or manage
- Compromise requires reproducing exact sensor history

### Forward Secrecy
- Session keys derived from ephemeral entropy
- Weight state constantly evolving
- Old sessions cannot be decrypted

### Traffic Analysis Resistance
- Padding normalizes packet sizes
- Timing jitter breaks patterns
- Protocol mimicry defeats DPI

### Byzantine Fault Tolerance
- DSM layer provides 2f+1 consensus
- Up to f malicious nodes tolerated
- Microblock chain prevents tampering

## Usage Example

```python
from shared.mesh import MeshNode

# Initialize node with shared neuro seed
node = MeshNode(
    neuro_seed=b"shared_mesh_seed_32_bytes_long!!",
    bootstrap_peers=["peer1.example.com", "peer2.example.com"]
)

# Join the mesh
if node.join_mesh():
    # Publish security event
    node.publish_event(
        event_type=1,
        severity=3,
        source="suricata",
        details={"alert": "port scan detected"}
    )

# Leave mesh
node.leave_mesh()
```

## Mesh Consciousness

The collective consciousness enables nodes to operate as a unified security organism.

### Tier Roles in the Consciousness

```
┌─────────────────────────────────────────────────────────────────┐
│  SENTINEL (512MB)  → Validator Node                             │
│    - Validates microblocks from local sensors                   │
│    - Participates in BLS signature aggregation                  │
│    - Lightweight consensus participation                        │
├─────────────────────────────────────────────────────────────────┤
│  GUARDIAN (3GB)    → Intelligence Node                          │
│    - Full threat detection + layer analysis                     │
│    - Gossip protocol participation                              │
│    - Local threat cache + sharing                               │
├─────────────────────────────────────────────────────────────────┤
│  FORTRESS (8GB)    → Regional Coordinator                       │
│    - Aggregates intelligence from Guardians/Sentinels           │
│    - Regional consensus leadership                              │
│    - SDN orchestration for defense                              │
├─────────────────────────────────────────────────────────────────┤
│  NEXUS (64GB+)     → ML/AI Compute Brain                        │
│    - Distributed model training                                 │
│    - Threat pattern analysis                                    │
│    - Nexus-to-Nexus weight synchronization                      │
├─────────────────────────────────────────────────────────────────┤
│  MSSP (Cloud)      → Global Coordinator (Optional)              │
│    - Long-term storage + analytics                              │
│    - Cross-region coordination                                  │
│    - Fallback: mesh operates autonomously without MSSP          │
└─────────────────────────────────────────────────────────────────┘
```

### Consciousness States

| State | Description |
|-------|-------------|
| `DORMANT` | Not yet connected to mesh |
| `AWAKENING` | Discovering peers |
| `AWARE` | Connected, receiving intelligence |
| `SYNCHRONIZED` | Full resonance with mesh |
| `AUTONOMOUS` | Operating without MSSP |

### Threat Intelligence Sharing

The mesh enables real-time threat intelligence sharing:

```python
from shared.mesh import create_consciousness

# Create consciousness for a Guardian node
consciousness = create_consciousness(
    tier_name="guardian",
    neuro_seed=b"shared_mesh_seed_32_bytes_long!!",
    bootstrap_peers=["fortress1:8144", "fortress2:8144"],
)

# Awaken and join the mesh
consciousness.awaken()

# Report a locally detected threat
consciousness.report_threat(
    threat_type="port_scan",
    severity=2,  # High
    ioc_type="ip",
    ioc_value="192.168.1.100",
    confidence=0.9,
)

# Lookup threats for an IOC
threats = consciousness.lookup_threat("malware.example.com")

# Get collective status
status = consciousness.get_status()
print(f"Peers: {status['peer_count']}, Intel: {status['threat_cache_size']}")
```

### Collective QSecBit Scoring

Nodes combine local and mesh intelligence for collective threat scoring:

```
Collective Score = (Local Score × 0.6) + (Mesh Threat Level × 0.4)

Where:
- Local Score: QSecBit from local sensors
- Mesh Threat Level: Weighted sum of peer-reported threats
```

### Autonomous Operation

When MSSP is unavailable, the mesh continues operating:

1. **Peer-to-Peer Intelligence**: Nodes share threats directly
2. **Local Consensus**: Regional coordinators (Fortress) build checkpoints
3. **Cached Policies**: Last-known-good configurations cached locally
4. **Automatic Recovery**: Reconnects to MSSP when available

### Guardian Mesh Integration

```python
from products.guardian.lib.mesh_integration import GuardianMeshAgent

# Create mesh agent
agent = GuardianMeshAgent()
agent.start()

# Report threat to mesh
agent.report_threat(
    threat_type="ddos",
    severity=1,  # Critical
    ioc_type="ip",
    ioc_value="attacker.example.com",
)

# Get collective score
score = agent.get_collective_score()
print(f"RAG: {score['rag_status']}, Peers: {score['peer_count']}")

# Handle mesh threats
@agent.on_mesh_threat
def handle_threat(intel):
    if intel.severity <= 2:
        # Block the threat locally
        block_ip(intel.ioc_value)
```

## Future: Rogue AI Defense

The mesh consciousness architecture is designed with future AI threats in mind:

1. **Distributed Intelligence**: No single point of compromise
2. **Collective Learning**: Swarm-like adaptation to new threats
3. **Neural Authentication**: Weight evolution defeats replay attacks
4. **Autonomous Response**: Coordinated defense without human latency
5. **Resilient Communication**: Multi-port, stealth, anti-blocking

Together, the mesh forms a collective defense against threats that no single
node could detect or defend against alone.
