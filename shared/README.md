# HookProbe Shared Infrastructure

> **Common Components Across All Products**

The shared/ directory contains infrastructure components used by multiple products.

```
shared/
├── dnsXai/    # AI-Powered DNS Protection
│   ├── engine.py           # ML classifier (20 features, 8 categories)
│   ├── integration.py      # Product integration
│   └── mesh_intelligence.py # Federated learning
│
├── mesh/      # Unified Mesh Communication
│   ├── ARCHITECTURE.md     # Complete mesh documentation
│   ├── nat_traversal.py    # STUN/ICE/hole punching
│   ├── consciousness.py    # Mesh consciousness states
│   ├── unified_transport.py # High-level API
│   └── relay.py            # TURN-style relay
│
├── dsm/       # Decentralized Security Mesh
│   ├── consensus.py        # BLS signature aggregation
│   ├── gossip.py           # P2P threat announcement
│   └── ledger.py           # Microblock chain
│
└── response/  # Automated Threat Response
    └── attack-mitigation-orchestrator.sh
```

---

## dnsXai — AI-Powered DNS Protection

**Location:** `shared/dnsXai/`

Next-generation DNS protection with machine learning. Traditional blockers miss, dnsXai catches.

### Why dnsXai?

| Traditional Blockers | dnsXai |
|---------------------|--------|
| Static blocklists only | ML-based classification for unknown domains |
| Miss CNAME cloaking | Detects first-party tracker masquerading |
| Isolated protection | Federated learning across mesh network |
| Manual updates | Self-learning and auto-updating |
| Binary block/allow | Confidence-based decisions with 8 categories |

### Features

- **ML Classification** — 20-feature neural classifier for unknown domains
- **CNAME Uncloaking** — Detects `track.yoursite.com → adobe.demdex.net`
- **5 Protection Levels** — Base (ads/malware) to Full (social trackers)
- **Federated Learning** — Privacy-preserving collective intelligence
- **<1ms Inference** — Lightweight enough for Raspberry Pi
- **~130K-250K domains** — Comprehensive blocklist coverage

### Protection Levels

| Level | Name | Blocks | Domains |
|-------|------|--------|---------|
| 1 | **Base** | Ads + Malware | ~130K |
| 2 | **Enhanced** | + Fakenews | ~132K |
| 3 | **Strong** | + Gambling | ~135K |
| 4 | **Maximum** | + Adult Content | ~200K |
| 5 | **Full** | + Social Trackers | ~250K |

### Qsecbit Integration

dnsXai contributes **8%** to the Qsecbit security score:

```
Qsecbit = 0.30·threats + 0.20·mobile + 0.25·ids + 0.15·xdp + 0.02·network + 0.08·dnsxai
```

High ad/tracker ratio indicates potential malware or compromised network.

### Components

| File | Purpose |
|------|---------|
| `engine.py` | ML classifier with feature extraction |
| `integration.py` | Product integration utilities |
| `mesh_intelligence.py` | Federated learning across mesh |
| `update-blocklist.sh` | Blocklist update script |

### Usage

```python
from shared.dnsXai import DNSXai, ProtectionLevel

# Create instance
dnsxai = DNSXai()

# Set protection level
dnsxai.set_protection_level(ProtectionLevel.STRONG)

# Classify a domain
result = dnsxai.classify_domain("suspicious-tracker.com")
print(f"Category: {result.category}, Blocked: {result.blocked}")
```

See `shared/dnsXai/README.md` for full documentation.

---

## Mesh — Unified Communication Layer

**Location:** `shared/mesh/`

Resilient, anti-blocking mesh communication for all HookProbe nodes.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    MESH COMMUNICATION FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Guardian A ◄──── Direct P2P (preferred) ────► Guardian B      │
│        │                                              │          │
│        │         [If NAT blocks direct]               │          │
│        └──────────► Fortress Relay ◄─────────────────┘          │
│                          │                                       │
│                          │    [If all else fails]               │
│                          ▼                                       │
│                    MSSP Cloud Relay                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Port Selection

```
PRIMARY:    8144/UDP + 8144/TCP
FALLBACK:   443/UDP (QUIC cover) + 443/TCP (TLS-wrapped)
STEALTH:    853/UDP (DoQ cover) + 853/TCP (DoT cover)
EMERGENCY:  80/TCP (WebSocket) + ICMP tunnel
```

### Consciousness States

Mesh nodes progress through awareness levels:

| State | Description |
|-------|-------------|
| **DORMANT** | Offline, no mesh activity |
| **AWAKENING** | Discovering peers, establishing connections |
| **AWARE** | Connected to mesh, receiving updates |
| **SYNCHRONIZED** | Full participation, sharing threat intel |
| **AUTONOMOUS** | Self-coordinating, can operate without MSSP |

### Components

| File | Purpose |
|------|---------|
| `ARCHITECTURE.md` | **MUST READ** — Complete mesh documentation |
| `nat_traversal.py` | STUN/ICE/hole punching for P2P |
| `consciousness.py` | Mesh consciousness state machine |
| `port_manager.py` | Multi-port failover management |
| `resilient_channel.py` | Reliable messaging with retries |
| `channel_selector.py` | Intelligent channel selection |
| `relay.py` | TURN-style relay for blocked nodes |
| `tunnel.py` | Cloudflare/ngrok/Tailscale tunnels |
| `unified_transport.py` | High-level transport API |
| `neuro_encoder.py` | Neural resonance authentication |

### Usage

```python
from shared.mesh import UnifiedTransport

# Create transport
transport = UnifiedTransport(node_id="guardian-001")

# Connect to mesh
await transport.connect()

# Send threat indicator to mesh
await transport.broadcast({
    "type": "threat_indicator",
    "ioc": "malicious-domain.com",
    "confidence": 0.95
})
```

See `shared/mesh/ARCHITECTURE.md` for full documentation.

---

## DSM — Decentralized Security Mesh

**Location:** `shared/dsm/`

One brain powered by many edge nodes. Traditional SOC: One analyst watches 1000 networks (impossible). DSM: 1000 nodes share intelligence instantly (unstoppable).

### How It Works

```
T+00s: Home 1 detects C2 communication
T+05s: Creates microblock with PoSF signature
T+10s: Announces to mesh via gossip protocol
T+15s: Validators aggregate into checkpoint
T+20s: ALL mesh nodes block the threat

One node's detection → Everyone's protection
```

### Components

| File | Purpose |
|------|---------|
| `node.py` | Edge node microblock creation |
| `validator.py` | Checkpoint creation and verification |
| `consensus.py` | BLS signature aggregation (2/3 quorum) |
| `gossip.py` | P2P threat announcement |
| `ledger.py` | Microblock chain storage |
| `merkle.py` | Merkle tree verification |
| `identity.py` | Node identity management |

### BLS Consensus

Validators use BLS (Boneh-Lynn-Shacham) signatures for efficient aggregation:

```python
# 2/3 quorum required for checkpoint
signatures = [validator.sign(checkpoint) for validator in validators]
aggregated = bls_aggregate(signatures)
assert verify_quorum(aggregated, validators, threshold=0.67)
```

---

## Response — Automated Threat Mitigation

**Location:** `shared/response/`

Kali Linux on-demand for automated threat response.

### Response Pipeline

```
Qsecbit detects threat (AMBER/RED)
    ↓
Spin up Kali container (on-demand)
    ↓
Analyze threat with appropriate tools
    ↓
Implement countermeasures
    ↓
Shut down when threat cleared
```

### Response Actions

| Threat | Response |
|--------|----------|
| **XSS** | Update WAF rules, block IP |
| **SQLi** | DB snapshot, update WAF |
| **DDoS** | XDP filtering, rate limiting |
| **Memory overflow** | Capture diagnostics, safe restart |
| **C2 Communication** | Block outbound, isolate host |
| **Lateral movement** | VLAN isolation, credential rotation |

---

## Integration Matrix

All components are used across HookProbe products:

| Product | dnsXai | Mesh | DSM | Response |
|---------|--------|------|-----|----------|
| **Sentinel** | - | Participate | Validate | - |
| **Guardian** | ✓ Full | Participate | Participate | Auto-mitigate |
| **Fortress** | ✓ Advanced | Coordinate | Participate | Auto + Custom |
| **Nexus** | ✓ Train | Super-node | Coordinate | Regional |
| **MSSP** | ✓ Global | Coordinate | Aggregate | Global |

### dnsXai Features by Tier

| Feature | Guardian | Fortress | Nexus | MSSP |
|---------|----------|----------|-------|------|
| ML Classification | ✓ | ✓ | ✓ | ✓ |
| CNAME Uncloaking | ✓ | ✓ | ✓ | ✓ |
| Federated Learning | Participate | Hub | Train | Coordinate |
| Per-VLAN Policies | - | ✓ | - | - |
| Analytics (ClickHouse) | - | Optional | ✓ | ✓ |

---

**HookProbe Shared Infrastructure v5.0** — *Common Components*

MIT License
