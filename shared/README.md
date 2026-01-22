# HookProbe Shared Infrastructure

> **The Transparent Foundation That Powers Everything**

Every HookProbe product tier - from Sentinel to Nexus - shares the same transparent infrastructure. Same algorithms. Same visibility. Same data ownership.

```
shared/
├── dnsXai/    # AI DNS Protection - Every block explained
├── mesh/      # Collective Defense - Privacy-preserving intelligence
├── dsm/       # Decentralized Consensus - Auditable validation
├── response/  # Automated Mitigation - Visible response actions
└── cortex/    # Neural Command Center - See your mesh
```

---

## Our Transparency Commitment

Every shared module follows the same principles:

| Principle | What It Means | How We Deliver |
|-----------|---------------|----------------|
| **Explainable Decisions** | You understand why | Every classification includes reasoning |
| **Auditable Code** | You can verify | Open source foundation |
| **Data Ownership** | It's yours | Export everything, anytime |
| **Privacy First** | Your data stays yours | Federated learning, no raw data sharing |

---

## dnsXai — Explainable DNS Protection

**Location:** `shared/dnsXai/`

Not just blocking - explaining. Every DNS decision is transparent.

### Why Traditional Blockers Fail You

| Traditional Blockers | dnsXai |
|---------------------|--------|
| "Domain blocked" | "Domain blocked: ML confidence 94%, high entropy, CNAME uncloaked to tracker" |
| Static lists only | ML classification for unknown threats |
| Miss CNAME cloaking | Detects first-party tracker masquerading |
| No explanation | Full feature breakdown for every decision |
| Isolated protection | Privacy-preserving collective intelligence |

### What You See for Every Decision

```json
{
  "domain": "suspicious-tracker.com",
  "decision": "BLOCKED",
  "confidence": 0.94,
  "category": "TRACKING",
  "explanation": {
    "shannon_entropy": 4.2,
    "ad_pattern_score": 0.15,
    "cname_uncloaked": "adobe.demdex.net",
    "blocklist_match": false,
    "ml_features_used": 20,
    "human_readable": "High entropy domain resolving to known tracker network"
  }
}
```

### Protection Levels - Your Choice

| Level | Protection | Your Control |
|-------|------------|--------------|
| 1 | Ads + Malware | See what's blocked, whitelist as needed |
| 2 | + Fakenews | Full visibility into classifications |
| 3 | + Gambling | Export decisions for your records |
| 4 | + Adult Content | Adjust anytime via dashboard |
| 5 | + Social Trackers | Complete data ownership |

**Every level gives you full visibility into what's happening.**

See `shared/dnsXai/README.md` for complete documentation.

---

## Mesh — Privacy-Preserving Collective Defense

**Location:** `shared/mesh/`

Join a global defense network without sacrificing privacy.

### The Transparency Challenge We Solved

Traditional collective defense: Your data goes to a central server
HookProbe mesh: Your data stays local, only signatures are shared

```
┌─────────────────────────────────────────────────────────────────┐
│                    MESH COMMUNICATION                            │
│                  What You Share vs What You Keep                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   What Leaves Your Node:              What Stays Local:          │
│   ├── Anonymized threat hashes        ├── Your raw traffic       │
│   ├── ML model weight updates         ├── Your IP addresses      │
│   └── Attack patterns (source removed) ├── Your DNS queries      │
│                                        ├── Your browsing history │
│                                        └── Any identifiable info │
│                                                                  │
│   You See:                                                       │
│   ├── Your mesh contribution stats                               │
│   ├── Threats shared and received                                │
│   ├── Model updates applied                                      │
│   └── Connection status with other nodes                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Consciousness States - Know Your Mesh Status

| State | What It Means | What You See |
|-------|---------------|--------------|
| **DORMANT** | Offline | "Not connected to mesh" |
| **AWAKENING** | Connecting | "Finding peers: 3 discovered" |
| **AWARE** | Connected | "Connected to mesh, receiving updates" |
| **SYNCHRONIZED** | Full participation | "Sharing and receiving, 15 peers" |
| **AUTONOMOUS** | Self-coordinating | "Can operate independently" |

### Port Selection - Resilient But Visible

```
PRIMARY:    8144/UDP + 8144/TCP
FALLBACK:   443/UDP (QUIC cover) + 443/TCP (TLS-wrapped)
STEALTH:    853/UDP (DoQ cover) + 853/TCP (DoT cover)
EMERGENCY:  80/TCP (WebSocket) + ICMP tunnel

You see which channel is active and why.
```

See `shared/mesh/ARCHITECTURE.md` for complete documentation.

---

## DSM — Transparent Decentralized Consensus

**Location:** `shared/dsm/`

How the mesh agrees on threats - fully auditable.

### The Problem with Centralized Validation

Traditional: One company decides what's a threat
DSM: Multiple nodes must agree, you can verify

```
T+00s: Node A detects suspicious pattern
T+05s: Creates microblock with cryptographic proof
T+10s: Broadcasts to mesh for validation
T+15s: 2/3 of validators must agree
T+20s: If consensus reached, all nodes block

You see: Every step, every vote, every decision
```

### What You Can Audit

| Component | Transparency |
|-----------|--------------|
| **Microblocks** | View any block in the chain |
| **Validator votes** | See who agreed and why |
| **Consensus results** | Full vote breakdown |
| **Your contributions** | Your node's validation history |

### BLS Consensus - Verified Math

```python
# 2/3 quorum required - you can verify the math
signatures = [validator.sign(checkpoint) for validator in validators]
aggregated = bls_aggregate(signatures)
verified = verify_quorum(aggregated, validators, threshold=0.67)

# You see: Which validators signed, final aggregated proof
```

---

## Response — Visible Automated Mitigation

**Location:** `shared/response/`

When HookProbe acts, you see exactly what it did and why.

### Response Transparency

| When This Happens | You See |
|-------------------|---------|
| **IP blocked** | "Blocked 192.168.1.100: SYN flood detected, 50,000 packets/sec" |
| **Rate limited** | "Limited 10.0.0.50 to 1000 pps: Port scan behavior" |
| **Kali activated** | "Mitigation container started: Analyzing attack pattern" |
| **Firewall rule added** | "Rule added: DROP from 203.0.113.0/24, reason: Botnet C2" |

### Response Actions - All Visible

```
┌─────────────────────────────────────────────────────────────────┐
│                    AUTOMATED RESPONSE                            │
│               Every Action Is Logged and Explainable             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Threat: SYN Flood from 192.168.1.100                          │
│   Qsecbit Score: 0.78 (RED)                                     │
│                                                                  │
│   Actions Taken:                                                 │
│   1. [00:00:01] ALERT sent to dashboard                         │
│   2. [00:00:02] Rate limit applied: 1000 pps                    │
│   3. [00:00:05] XDP block: Packets dropped at kernel level      │
│   4. [00:00:10] Firewall rule: Permanent block added            │
│                                                                  │
│   Result: Attack mitigated in 10 seconds                        │
│   Packets blocked: 847,293                                       │
│   Your network: Protected                                        │
│                                                                  │
│   [View Full Log] [Export Report] [Modify Rules]                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Cortex — See Your Entire Mesh

**Location:** `shared/cortex/`

Transparency isn't complete without visualization.

### What Cortex Shows You

| View | What You See |
|------|--------------|
| **3D Globe** | Every node in your mesh, real-time |
| **Attack Arcs** | Threats arriving and being repelled |
| **Node Health** | Color-coded Qsecbit status |
| **City View** | Zoom to street-level detail |
| **Event Stream** | Every security event as it happens |

### From Macro to Micro

```
Global View → Continent → City → Street → Individual Node
              ↓           ↓       ↓         ↓
          Cluster    Building  Node      Detailed
          status     context   location  stats
```

See `shared/cortex/README.md` for complete documentation.

---

## Integration Matrix - Same Transparency Everywhere

| Product | dnsXai | Mesh | DSM | Response | Cortex |
|---------|--------|------|-----|----------|--------|
| **Sentinel** | - | Participate | Validate | - | View |
| **Guardian** | Full | Participate | Participate | Auto | Full |
| **Fortress** | Advanced | Coordinate | Participate | Auto+Custom | Full |
| **Nexus** | Train | Super-node | Coordinate | Regional | Full |

**Every tier, same transparency, same data ownership.**

---

## The Shared Difference

**Other security infrastructure:** Complex, opaque, vendor-controlled
**HookProbe shared modules:** Transparent, explainable, user-owned

1. **Every decision is explained** - Not just what, but why
2. **Every action is logged** - Complete audit trail
3. **Every piece of data is yours** - Export anytime
4. **Every component is documented** - No black boxes

**This is the foundation that makes transparent security possible.**

---

**HookProbe Shared Infrastructure v5.0** — *Transparent Components for Transparent Security*

AGPL v3.0 (Open Source Components) + Proprietary (Documented Innovations)
