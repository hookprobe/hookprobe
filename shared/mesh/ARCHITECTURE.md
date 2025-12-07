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

## NAT/CGNAT Traversal

A critical challenge for decentralized mesh: most nodes are behind NAT/CGNAT
and don't have public IPs. When MSSP is unavailable, nodes can't find each other.

### The NAT Problem

```
┌────────────────────────────────────────────────────────────────────────┐
│                        THE NAT/CGNAT CHALLENGE                          │
│                                                                         │
│   ┌─────────────┐                              ┌─────────────┐          │
│   │   Sentinel  │                              │   Guardian  │          │
│   │  10.0.1.50  │                              │ 192.168.1.x │          │
│   └──────┬──────┘                              └──────┬──────┘          │
│          │                                            │                 │
│   ┌──────▼──────┐                              ┌──────▼──────┐          │
│   │  NAT/CGNAT  │                              │  NAT/CGNAT  │          │
│   │ (No Public) │                              │ (No Public) │          │
│   └──────┬──────┘                              └──────┬──────┘          │
│          │                                            │                 │
│          └────────────────┬───────────────────────────┘                 │
│                           │                                             │
│                   ┌───────▼───────┐                                     │
│                   │     MSSP      │ ◄── Single point of failure!        │
│                   │  (Public IP)  │                                     │
│                   └───────────────┘                                     │
│                                                                         │
│   Problem: If MSSP goes down, NAT nodes can't communicate P2P          │
└────────────────────────────────────────────────────────────────────────┘
```

### Solution: Multi-Layer NAT Traversal

```
┌────────────────────────────────────────────────────────────────────────┐
│                    NAT TRAVERSAL SOLUTION STACK                         │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Layer 1: STUN Discovery                                              │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  • Discover public IP/port via STUN servers                      │  │
│   │  • Detect NAT type (Open, Cone, Symmetric, Blocked)              │  │
│   │  • HookProbe STUN servers + public fallbacks (Google, Cloudflare)│  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                              ↓                                          │
│   Layer 2: ICE Connectivity                                            │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  • Gather candidates: host, server-reflexive, relay              │  │
│   │  • Exchange candidates via signaling (MSSP or promoted node)     │  │
│   │  • Connectivity checks to find working path                      │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                              ↓                                          │
│   Layer 3: UDP Hole Punching                                           │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  • Simultaneous packet exchange to punch NAT holes               │  │
│   │  • Works for Full Cone, Restricted Cone, Port Restricted         │  │
│   │  • Coordinated via rendezvous timestamp                          │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                              ↓                                          │
│   Layer 4: Relay Network                                               │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  • Fortress/Nexus nodes with public IPs become relays            │  │
│   │  • TURN-style allocation for symmetric NAT traversal             │  │
│   │  • Load-balanced relay selection                                 │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

### NAT Type Detection

```python
from shared.mesh import STUNClient, NATType

stun = STUNClient()
nat_type = stun.detect_nat_type()

# NAT Types:
# - OPEN:            No NAT, public IP (can be relay/coordinator)
# - FULL_CONE:       Any external host can send (best for P2P)
# - RESTRICTED_CONE: Only hosts we've sent to can reply
# - PORT_RESTRICTED: Only host:port we've sent to can reply
# - SYMMETRIC:       Different mapping per destination (needs relay)
# - BLOCKED:         UDP blocked entirely
```

### ICE Connectivity Establishment

```python
from shared.mesh import ICEAgent, ICECandidate

# Initialize ICE agent
ice = ICEAgent(node_id="guardian-01")

# Gather local candidates
local_candidates = ice.gather_candidates(local_port=8144)

# Exchange candidates with peer (via signaling)
# ... send local_candidates, receive remote_candidates ...

ice.set_remote_candidates(remote_candidates)

# Find working connection
result = ice.check_connectivity(timeout=5.0)
if result:
    local_cand, remote_cand = result
    print(f"Connected via {remote_cand.type}: {remote_cand.ip}:{remote_cand.port}")
```

## Mesh Promotion Protocol (Innovation)

When MSSP is unavailable, the mesh doesn't die - it **promotes** nodes with
public IPs to become temporary coordinators.

```
┌────────────────────────────────────────────────────────────────────────┐
│                    MESH PROMOTION PROTOCOL                              │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Normal Operation:                                                     │
│  ┌────────┐     ┌────────┐     ┌────────┐                              │
│  │Sentinel├────►│  MSSP  │◄────┤Guardian│     (Star topology)          │
│  └────────┘     └────┬───┘     └────────┘                              │
│                      │                                                  │
│                      ▼                                                  │
│                  [Central]                                              │
│                                                                         │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  MSSP Unavailable - Mesh Promotion:                                    │
│                                                                         │
│  ┌────────┐     ┌─────────┐     ┌────────┐                              │
│  │Sentinel├────►│ Fortress│◄────┤Guardian│     (Promoted coordinator)  │
│  └────────┘     │(PROMOTED)│     └────────┘                             │
│                 └────┬────┘                                             │
│       ┌──────────────┼──────────────┐                                  │
│       ▼              ▼              ▼                                  │
│  ┌────────┐     ┌────────┐     ┌────────┐                              │
│  │Guardian│     │ Nexus  │     │Sentinel│    (Mesh continues!)         │
│  └────────┘     │(PROMOTED)│     └────────┘                             │
│                 └────────┘                                              │
│                                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

### Promotion Levels

| Level | Role | Requirements | Capabilities |
|-------|------|--------------|--------------|
| `LEAF` | Regular node | Any | Consumes relay/coordination |
| `BRIDGE` | Local relay | Public IP + Cone NAT | Relay for local network |
| `COORDINATOR` | Peer discovery | Public IP + Full Cone | Rendezvous point |
| `SUPER_NODE` | Mini-MSSP | Public IP + Fortress/Nexus | Full coordination |

### Promotion Logic

```python
from shared.mesh import MeshPromotionManager, MeshPromotion

# Create promotion manager
promotion = MeshPromotionManager(
    node_id="fortress-01",
    tier="fortress",
    region="us-west"
)

# Check if we can be promoted
can_promote, level = promotion.check_promotability()
if can_promote:
    promotion.promote(level)
    print(f"Promoted to {level.name}")

# Get promotion info for advertising
my_info = promotion.get_my_promotion_info()
# ... broadcast to mesh ...
```

## Emergent Relay Network

When nodes can't connect directly, Fortress/Nexus nodes with public IPs
automatically form a relay network.

```python
from shared.mesh import RelayServer, RelayClient, RelayNetwork

# Fortress node runs relay server
if tier == "fortress" and has_public_ip:
    relay_server = RelayServer(
        listen_port=3478,
        max_allocations=100,
        node_id="fortress-relay-01"
    )
    relay_server.start()

# Nodes behind NAT use relay
relay_client = RelayClient(
    client_id="guardian-01",
    relay_addr=("relay.example.com", 3478)
)
relay_client.allocate(lifetime=600)
relay_client.create_permission(peer_addr)
relay_client.send_to_peer(peer_addr, data)
```

### Relay Network Discovery

```python
from shared.mesh import RelayNetwork, RelayNodeInfo

# Relay network manager
network = RelayNetwork(node_id="guardian-01")

# Register known relays
network.register_node(RelayNodeInfo(
    node_id="fortress-01",
    public_ip="203.0.113.1",
    public_port=3478,
    region="us-west",
    tier="fortress",
    capacity=100,
    current_load=25,
    latency_ms=50
))

# Get best relay (load-balanced, region-aware)
best_relay = network.get_best_relay(prefer_region="us-west")
```

## MSSP High Availability

To ensure mesh continuity, MSSP should be designed for high availability:

```
┌────────────────────────────────────────────────────────────────────────┐
│                    MSSP HIGH AVAILABILITY ARCHITECTURE                  │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │                        Global Load Balancer                      │  │
│   │                     (Anycast or Geo-DNS)                         │  │
│   └──────────────────────────┬──────────────────────────────────────┘  │
│                              │                                          │
│     ┌────────────────────────┼────────────────────────┐                 │
│     │                        │                        │                 │
│   ┌─▼─────────┐        ┌─────▼─────┐        ┌────────▼──┐               │
│   │ MSSP-US   │◄──────►│ MSSP-EU   │◄──────►│ MSSP-AP   │               │
│   │ (Primary) │        │ (Replica) │        │ (Replica) │               │
│   └─────┬─────┘        └─────┬─────┘        └─────┬─────┘               │
│         │                    │                    │                     │
│   ┌─────▼─────┐        ┌─────▼─────┐        ┌─────▼─────┐               │
│   │ Database  │◄──────►│ Database  │◄──────►│ Database  │               │
│   │ (Replica) │        │ (Replica) │        │ (Replica) │               │
│   └───────────┘        └───────────┘        └───────────┘               │
│                                                                         │
│   Features:                                                            │
│   • Multi-region deployment (US, EU, AP)                               │
│   • Active-active with leader election                                 │
│   • Automatic failover < 30 seconds                                    │
│   • Geographic load balancing                                          │
│   • Mesh continues via promotion if ALL regions fail                   │
│                                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

### Recommended MSSP Deployment

1. **Multi-Region**: Deploy in at least 3 geographic regions
2. **Anycast**: Use anycast IP for automatic failover
3. **Health Checks**: Active probes every 10 seconds
4. **Failover Time**: < 30 seconds to backup region
5. **Data Replication**: Synchronous within region, async across regions

## Complete Resilience Stack

```
┌────────────────────────────────────────────────────────────────────────┐
│                    MESH RESILIENCE HIERARCHY                            │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Level 1: MSSP Available (Normal Operation)                           │
│   └── Central coordination, full capabilities                          │
│                                                                         │
│   Level 2: MSSP Unavailable, Promoted Coordinators Active              │
│   └── Fortress/Nexus nodes with public IPs coordinate                  │
│   └── Full mesh connectivity via ICE + hole punching                   │
│                                                                         │
│   Level 3: Most Nodes Behind Symmetric NAT                             │
│   └── Relay network for nodes that can't punch holes                   │
│   └── Load-balanced relay selection                                    │
│                                                                         │
│   Level 4: Extreme Censorship/Network Isolation                        │
│   └── Domain fronting via CDN (Cloudflare, AWS)                        │
│   └── Tor/I2P integration for overlay routing                          │
│   └── Sneakernet checkpoint exchange as last resort                    │
│                                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

## Usage: Complete NAT Traversal

```python
from shared.mesh import NATTraversalManager, MeshConsciousness

# Initialize NAT traversal
nat = NATTraversalManager(
    node_id="guardian-01",
    tier="guardian",
    region="us-west"
)
nat.initialize()

print(f"Public endpoint: {nat.public_endpoint}")
print(f"NAT type: {nat.nat_type.name}")

# Get ICE candidates for peer exchange
my_candidates = nat.get_my_candidates()

# Connect to peer
endpoint = nat.connect_to_peer(
    peer_id="sentinel-02",
    peer_candidates=their_candidates,
    coordinator=promoted_node  # Fallback coordinator
)

if endpoint.connectivity == ConnectivityType.DIRECT:
    print("Direct P2P connection!")
elif endpoint.connectivity == ConnectivityType.HOLE_PUNCHED:
    print("NAT hole punched!")
elif endpoint.connectivity == ConnectivityType.RELAYED:
    print(f"Relayed via {endpoint.relay_node}")
```

## Future: Rogue AI Defense

The mesh consciousness architecture is designed with future AI threats in mind:

1. **Distributed Intelligence**: No single point of compromise
2. **Collective Learning**: Swarm-like adaptation to new threats
3. **Neural Authentication**: Weight evolution defeats replay attacks
4. **Autonomous Response**: Coordinated defense without human latency
5. **Resilient Communication**: Multi-port, stealth, anti-blocking
6. **NAT Resilience**: Mesh survives without central coordination
7. **Emergent Hierarchy**: Automatic promotion when leaders fail

Together, the mesh forms a collective defense against threats that no single
node could detect or defend against alone. The mesh is designed to be
**unkillable** - it adapts, promotes, relays, and continues operating even
under extreme network conditions.
