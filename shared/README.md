# HookProbe Shared Infrastructure

> **Common Components Across All Products**

The shared/ directory contains infrastructure components used by multiple products.

```
shared/
├── dsm/       # Decentralized Security Mesh
│   ├── consensus/   # BLS signature aggregation
│   ├── gossip/      # P2P threat announcement
│   └── ledger/      # Microblock chain
│
└── response/  # Automated Threat Response
```

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

## Integration

Both components are used across all products:

| Product | DSM Usage | Response Usage |
|---------|-----------|----------------|
| Sentinel | Validation only | - |
| Guardian | Participate | Auto-mitigate |
| Fortress | Participate | Auto-mitigate + custom |
| Nexus | Coordinate | Regional response |
| MSSP | Aggregate | Global coordination |

---

**HookProbe Shared** — *Common Infrastructure*

MIT License
