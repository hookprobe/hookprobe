# HookProbe Architecture

**Federated Cybersecurity Mesh: Privacy-Preserving Collective Defense**

**Version**: 1.0-Liberty
**Status**: Production Ready
**Last Updated**: 2025-12-07

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [The Three Pillars](#the-three-pillars)
3. [NEURO Protocol - Living Cryptography](#neuro-protocol---living-cryptography)
4. [DSM - Decentralized Security Mesh](#dsm---decentralized-security-mesh)
5. [HTP - HookProbe Transport Protocol](#htp---hookprobe-transport-protocol)
6. [Federation Architecture](#federation-architecture)
7. [Product Tiers](#product-tiers)
8. [Security Model](#security-model)
9. [Backend Deployment Foundation](#backend-deployment-foundation)
10. [Implementation Status](#implementation-status)

---

## Executive Summary

**Traditional SOC**: One analyst watches 1000 networks (impossible)
**HookProbe Mesh**: 1000 nodes share intelligence instantly (unstoppable)

HookProbe is a **federated cybersecurity mesh** that delivers enterprise-grade security on $75 hardware through three revolutionary innovations:

| Pillar | Function | Innovation |
|--------|----------|------------|
| **NEURO** | Living Cryptography | Neural weights replace static keys |
| **DSM** | Collective Intelligence | Byzantine fault-tolerant distributed SOC |
| **HTP** | Trust Fabric | Simple, auditable transport protocol |

**Core Philosophy**:
- **No raw data leaves** your network (privacy-preserving)
- **Collective defense** without exposing individual data
- **Self-evolving** threat detection via adversarial AI
- **Zero-trust mesh** where nodes prove integrity continuously

**Cost Reduction**: 99.98% compared to traditional enterprise SOC ($75 vs $400,000+)

---

## The Three Pillars

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          HOOKPROBE THREE PILLARS                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐              │
│   │     NEURO       │   │      DSM        │   │      HTP        │              │
│   │     Protocol    │   │  Decentralized  │   │    Transport    │              │
│   │                 │   │  Security Mesh  │   │    Protocol     │              │
│   ├─────────────────┤   ├─────────────────┤   ├─────────────────┤              │
│   │ Living          │   │ Collective      │   │ Trust Fabric    │              │
│   │ Cryptography    │   │ Intelligence    │   │ + File Transfer │              │
│   │                 │   │                 │   │                 │              │
│   │ • TER Sensors   │   │ • Microblocks   │   │ • UDP 4719      │              │
│   │ • Weight Evolve │   │ • BLS Consensus │   │ • ChaCha20      │              │
│   │ • PoSF Signing  │   │ • Merkle DAG    │   │ • NAT Traversal │              │
│   │ • Deterministic │   │ • Byzantine FT  │   │ • CRUD Files    │              │
│   └─────────────────┘   └─────────────────┘   └─────────────────┘              │
│           │                     │                     │                        │
│           └─────────────────────┼─────────────────────┘                        │
│                                 │                                              │
│                    ┌────────────┴────────────┐                                 │
│                    │       QSECBIT           │                                 │
│                    │  Universal Resilience   │                                 │
│                    │    Metric (0.0-1.0)     │                                 │
│                    └─────────────────────────┘                                 │
│                                                                                 │
│   Together: Edge nodes prove continuous integrity via neural resonance,        │
│   share collective threat intelligence without exposing raw data,              │
│   and coordinate autonomous responses across a federated mesh.                 │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## NEURO Protocol - Living Cryptography

**Pillar 1: Where Neural Networks Become Cryptographic Keys**

### Core Innovation

Traditional authentication: *"Do you know the password?"*
**Neural Resonance**: *"Can you prove your entire sensor history through deterministic weight evolution?"*

Instead of static keys (RSA, ECDSA), NEURO uses **neural network weights that evolve deterministically** based on sensor data. This creates continuously-authenticating, tamper-evident communication.

### Four-Layer Security Model

```
┌──────────────────────────────────────────────────────────────────┐
│          LAYER 4: TRANSPORT (HookProbe Transport Protocol)        │
│  UDP-based, NAT-friendly, ChaCha20-Poly1305 encrypted            │
│  Session key = SHA256(session_secret + weight_fingerprint)       │
└──────────────────────────────────────────────────────────────────┘
                              ▲
┌──────────────────────────────────────────────────────────────────┐
│         LAYER 3: AUTHENTICATION (Proof-of-Sensor-Fusion)         │
│  Neural network output becomes signature                         │
│  Signature = NN(W_current, message_hash, nonce)                  │
└──────────────────────────────────────────────────────────────────┘
                              ▲
┌──────────────────────────────────────────────────────────────────┐
│         LAYER 2: WEIGHT EVOLUTION ENGINE (Deterministic)         │
│  W(t+1) = W(t) - η × ∇L(W, TER)                                  │
│  η = η_base × exp(-Δt / τ)  (time-decayed learning rate)        │
│  L = L_base + (C × Σ_threat)  (integrity penalty)               │
│  Fixed-point Q16.16 ensures bit-for-bit equivalence              │
└──────────────────────────────────────────────────────────────────┘
                              ▲
┌──────────────────────────────────────────────────────────────────┐
│           LAYER 1: SENSOR CAPTURE (Temporal Event Record)        │
│  H_Entropy (32 bytes): SHA256(CPU, Memory, Network, Disk)       │
│  H_Integrity (20 bytes): RIPEMD160(Kernel, Binary, Config)      │
│  Timestamp (8 bytes): Microseconds since epoch                   │
│  Sequence (2 bytes): Monotonic counter (0-65535)                 │
│  Chain_Hash (2 bytes): CRC16 of previous TER                     │
└──────────────────────────────────────────────────────────────────┘
```

### Temporal Event Record (TER) - 64 Bytes

```python
@dataclass
class TER:
    """64-byte sensor snapshot that drives weight evolution"""
    h_entropy: bytes      # 32 bytes - SHA256 of system metrics
    h_integrity: bytes    # 20 bytes - RIPEMD160 of critical files
    timestamp: int        # 8 bytes  - Microseconds since epoch
    sequence: int         # 2 bytes  - Monotonic counter
    chain_hash: int       # 2 bytes  - CRC16 of previous TER
```

**Security Property**: Compromised system → H_Integrity changes → unpredictable Σ_threat → weight divergence → resonance breaks → **immediate detection**.

### Weight Evolution Formula

```
W(t+1) = W(t) - η_mod × ∇L(W(t), TER)

where:
  η_mod = η_base × exp(-Δt / τ)           # Time-decayed learning rate
  L = L_base + (C_integral × Σ_threat)    # Modified loss with integrity penalty
  Σ_threat = uint32(H_Integrity[:4]) / 2^32  # Threat score from TER

Parameters:
  η_base = 0.0001    # Base learning rate
  τ = 7200 seconds   # Decay time constant (2 hours)
  C_integral = 5.0   # Integrity loss coefficient
```

### Proof-of-Sensor-Fusion (PoSF)

Neural network output becomes the cryptographic signature:

```python
def sign(message_hash: bytes, nonce: bytes) -> bytes:
    """Generate PoSF signature using neural network weights"""
    input_bytes = message_hash + nonce + padding
    signature = neural_network.forward(input_bytes, output_layer='L_X_SIG_07')
    return signature  # 32 bytes
```

**Verification**: Cloud simulates edge weight evolution from TER history, regenerates signature, and compares bit-for-bit.

### Hardware Fingerprinting (Liberty Architecture)

**No TPM required** - works on $75 Raspberry Pi:

```python
# Device identity from hardware characteristics
fingerprint = SHA256(
    cpu_id +
    mac_addresses +
    disk_serials +
    dmi_uuid +
    hostname +
    timestamp
)
```

**Optional hardware security** (for validators):
- TPM 2.0 (preferred)
- ARM TrustZone
- Intel TXT/SGX

---

## DSM - Decentralized Security Mesh

**Pillar 2: One Brain Powered by Many Edge Nodes**

### Core Innovation

Traditional SOC: One analyst watches 1000 networks (impossible)
**DSM**: 1000 nodes share intelligence instantly (unstoppable)

**Not a blockchain. Not a cryptocurrency. Not mining.**

Instead, DSM uses a **lightweight Merkle-DAG with RAFT-like consensus** to sign, validate, and propagate security events.

### Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Layer 3: Consensus                            │
│  Validators aggregate microblocks into checkpoints              │
│  BLS signature aggregation for Byzantine fault tolerance        │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                  Layer 2: Validation                             │
│  Merkle DAG of microblocks from all edge nodes                  │
│  Gossip protocol for block announcement                         │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                   Layer 1: Detection                             │
│  Edge nodes create microblocks for security events              │
│  TPM-signed, cryptographically verifiable                       │
└─────────────────────────────────────────────────────────────────┘
```

### Key Data Structures

#### Microblock (M) - Security Event Record

```json
{
  "type": "M",
  "node_id": "edge-uuid-12345",
  "seq": 1847,
  "prev": "hash-of-previous-microblock",
  "timestamp": "2025-12-07T18:35:00Z",
  "payload_hash": "sha256-of-security-event",
  "event_type": "ids_alert|mitigation|threat_intel|policy_update",
  "signature": "tpm-signed-data",
  "neuro": {
    "ter_hash": "sha256-of-current-ter",
    "w_fingerprint": "sha512-of-current-weights",
    "posf_signature": "32-byte-neural-signature"
  }
}
```

#### Checkpoint (C) - Epoch Aggregation

```json
{
  "type": "C",
  "epoch": 147,
  "timestamp": "2025-12-07T18:40:00Z",
  "merkle_root": "root-of-all-microblocks-in-epoch",
  "included_ranges": {
    "edge-uuid-12345": [1840, 1850],
    "edge-uuid-67890": [923, 935]
  },
  "validator_id": "validator-uuid-001",
  "signature": "tpm-signed-checkpoint",
  "agg_signature": "bls-aggregated-sig-from-quorum"
}
```

### Byzantine Fault Tolerance

```python
def bft_quorum_required(total_validators: int) -> int:
    """
    Tolerates f=(n-1)/3 Byzantine (malicious) validators.

    For n=10 validators: f=3 Byzantine tolerated, require 7 signatures
    For n=7 validators: f=2 Byzantine tolerated, require 5 signatures
    """
    f = (total_validators - 1) // 3
    quorum = total_validators - f
    return quorum
```

### POD-010 Integration

```
┌─────────────────────────────────────────────────────────────┐
│ POD-010: DSM Ledger & Consensus Engine                      │
├─────────────────────────────────────────────────────────────┤
│ Services:                                                    │
│  - dsm-node          (Microblock creation & gossip)         │
│  - dsm-validator     (Checkpoint creation if validator)     │
│  - dsm-consensus     (BLS aggregation & verification)       │
│  - dsm-api           (Query interface for blocks)           │
│                                                              │
│ Storage:                                                     │
│  - Local: LevelDB/RocksDB for microblocks                   │
│  - Persistent: PostgreSQL (POD-003) for checkpoints         │
│  - Cache: Redis (POD-004) for pending validations           │
│                                                              │
│ Integration Points:                                          │
│  - POD-006: Receives security events                        │
│  - POD-007: Logs mitigation actions                         │
│  - POD-005: Exports metrics to Grafana                      │
│  - POD-002: Validates node identities via IAM              │
└─────────────────────────────────────────────────────────────┘
```

---

## HTP - HookProbe Transport Protocol

**Pillar 3: Trust Fabric for the Mesh**

### Design Philosophy

**Why HTP instead of QUIC?**
- **Simplicity**: 9 message types vs QUIC's 100+ (easier to audit)
- **HookProbe-specific**: Designed for weight fingerprint binding
- **NAT-friendly**: UDP with heartbeat keep-alive
- **Auditability**: Open source, fully transparent

**Port**: UDP 4719

### Core Message Types

```python
class MessageType(Enum):
    HELLO = 0x01       # Edge → Validator: Initiate connection
    CHALLENGE = 0x02   # Validator → Edge: Send attestation challenge
    ATTEST = 0x03      # Edge → Validator: Attestation response
    ACCEPT = 0x04      # Validator → Edge: Session accepted
    REJECT = 0x05      # Validator → Edge: Session rejected
    DATA = 0x10        # Bidirectional: Encrypted payload
    HEARTBEAT = 0x20   # Bidirectional: Keep NAT alive (every 30s)
    ACK = 0x21         # Response to DATA/HEARTBEAT
    CLOSE = 0xFF       # Bidirectional: Close session
```

### Connection Flow

```
Edge (behind NAT/CGNAT)               Validator (Cloud)
  │                                        │
  │─── (1) HELLO ─────────────────────────►│
  │   [node_id, W_fingerprint]             │ Check MSSP registry
  │                                        │ Validate device exists
  │                                        │
  │◄── (2) CHALLENGE ──────────────────────│
  │   [nonce (16 bytes)]                   │
  │                                        │
  │ Sign: Ed25519(nonce + W_fingerprint)   │
  │                                        │
  │─── (3) ATTEST ─────────────────────────►│
  │   [signature (64 bytes)]               │ Verify device signature
  │                                        │ Generate session_secret
  │                                        │
  │◄── (4) ACCEPT ──────────────────────────│
  │   [session_secret (32 bytes)]          │
  │                                        │
  │ Derive ChaCha20 key:                   │ Derive same key:
  │ k = SHA256(secret + W_fingerprint)     │ k = SHA256(secret + W_fingerprint)
  │                                        │
  │◄══ (5) DATA (ChaCha20-Poly1305) ══════►│
  │   [encrypted TER logs, PoSF sigs]      │
  │                                        │
  │─── (6) HEARTBEAT (every 30s) ──────────►│ Maintain NAT mapping
  │                                        │
  │◄── (7) ACK ─────────────────────────────│
```

### HTP Packet Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    HTP PACKET (100+ bytes)                   │
├─────────────────────────────────────────────────────────────┤
│ Header (32 bytes):                                           │
│   version (2) + type (2) + sequence (4) + timestamp (4)     │
│   flow_token (8) + nonce (8) + flags (4)                    │
├─────────────────────────────────────────────────────────────┤
│ Resonance Layer (64 bytes):                                  │
│   RDV (32 bytes) + PoSF (32 bytes)                          │
├─────────────────────────────────────────────────────────────┤
│ Payload Header (4 bytes):                                    │
│   payload_length (4)                                         │
├─────────────────────────────────────────────────────────────┤
│ Payload (variable):                                          │
│   ChaCha20-Poly1305 encrypted data                          │
└─────────────────────────────────────────────────────────────┘
```

### HTP File Transfer Extension

CRUD file operations while maintaining all security properties:

```python
class FileOperation(IntEnum):
    """HTP File Operation codes (0x30-0x38)"""
    CREATE = 0x30      # Create new file on remote
    READ = 0x31        # Retrieve file from remote
    UPDATE = 0x32      # Update existing file
    DELETE = 0x33      # Delete file on remote
    STAT = 0x34        # Get file metadata
    LIST = 0x35        # List directory contents
    CHUNK = 0x36       # File data chunk
    COMPLETE = 0x37    # Transfer complete signal
    ERROR = 0x38       # File operation error
```

#### File Transfer Header (16 bytes)

```
file_op     (1 byte):  FileOperation enum
flags       (1 byte):  FileFlags bitmask
chunk_index (2 bytes): Current chunk index (0-65535)
file_id     (4 bytes): Unique transfer ID
total_chunks(4 bytes): Total chunks in transfer
file_hash   (4 bytes): First 4 bytes of SHA256 (quick verify)
```

#### File Security Features

- **8KB default chunk size** (tunable for SBC memory)
- **SHA256 integrity verification**
- **Optional zlib compression** (auto-selected if beneficial)
- **Path traversal prevention**
- **File extension whitelisting**
- **Atomic write** (write to temp, then rename)
- **Maximum file size**: 1GB default
- **Maximum concurrent transfers**: 16

#### File Transfer Client Usage

```python
from htp_file import HTPFileTransfer

async with HTPFileTransfer(htp_session) as ft:
    # Create file
    await ft.create('/remote/path/file.txt', b'file contents')

    # Read file
    data = await ft.read('/remote/path/file.txt')

    # Update file
    await ft.update('/remote/path/file.txt', b'new contents')

    # Delete file
    await ft.delete('/remote/path/file.txt')

    # Get metadata
    metadata = await ft.stat('/remote/path/file.txt')

    # List directory
    entries = await ft.list('/remote/path/')
```

### HTP 2026 Roadmap Enhancements

| Enhancement | Purpose | Status |
|-------------|---------|--------|
| **Neural Trust Scoring** | Continuous trust (0.0-1.0) vs binary accept/reject | Planned Q1 2026 |
| **Adaptive Polymorphism** | BURST/SWARM/GHOST transmission modes | Planned Q1 2026 |
| **Jitter Injection** | Anti-surveillance timing randomization | Planned Q1 2026 |
| **Energy-Aware Routing** | Battery management for edge nodes | Planned Q1 2026 |
| **Witness Verification** | Anti-hallucination BLS signatures | Planned Q2 2026 |

---

## Federation Architecture

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────┐     Raw        ┌─────────┐    Qsecbit    ┌─────────┐             │
│   │Guardian │ ──telemetry──► │ Nexus   │ ───scores───► │  MSSP   │             │
│   │Fortress │    (local)     │         │   (derived)   │         │             │
│   │Sentinel │                │         │               │         │             │
│   └─────────┘                └─────────┘               └─────────┘             │
│                                                              │                  │
│                                                              │                  │
│   ┌─────────┐    Hardened    ┌─────────┐    Global     ┌────┴────┐             │
│   │Guardian │ ◄───model────  │ Nexus   │ ◄──updates──  │  MSSP   │             │
│   │Fortress │    (updates)   │         │   (insights)  │         │             │
│   │Sentinel │                │         │               │         │             │
│   └─────────┘                └─────────┘               └─────────┘             │
│                                                                                 │
│   RAW DATA NEVER LEAVES THE EDGE                                               │
│   Only derived intelligence flows up                                            │
│   Only hardened models flow down                                                │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### What Gets Shared (Not Raw Data)

- **Qsecbit scores** (not raw telemetry)
- **Attack signatures** (hashed patterns, not payloads)
- **Neural fingerprints** (behavioral embeddings, ~256 bytes)

### Qsecbit - Universal Resilience Metric

```python
# The Formula
Qsecbit = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly

# RAG Status
GREEN  (< 0.45):  Normal — learning baseline
AMBER  (0.45-0.70): Warning — auto-response triggered
RED    (> 0.70):  Critical — full mitigation deployed
```

Every decision traces back to Qsecbit: **Auditable, explainable AI**.

### Coordinated Attack Response (Herd Immunity)

```
T+00s: MSSP detects pattern hitting Nexus A, B, C
       │
       ▼
T+05s: MSSP broadcasts: "Attack signature X detected"
       │
       ├─────────────────────────────────────────────────┐
       ▼                   ▼                   ▼         ▼
     Nexus A            Nexus B            Nexus C    Nexus D
    (already hit)      (already hit)      (already hit) (safe)
       │                   │                   │         │
       ▼                   ▼                   ▼         ▼
T+10s: All Nexuses preemptively block signature X
       │
       ▼
T+15s: Nexus D protected BEFORE attack reaches it

Attacker's campaign fails before reaching 80% of targets
```

---

## Product Tiers

### Component Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ TIER 1: CORE INTELLIGENCE                                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│   HTP (Transport Protocol)    │    QSECBIT (Security Metric)                    │
│   Location: /core/htp/        │    Location: /core/qsecbit/                     │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│ TIER 2: EDGE NODES                                                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│   SENTINEL (256MB)     │   GUARDIAN (1.5GB)    │   FORTRESS (4GB)               │
│   DSM Validator        │   Travel Companion    │   Edge Router                  │
│   IoT gateways         │   RPi 4/5             │   Mini PC/Server               │
│   /products/sentinel/  │   /products/guardian/ │   /products/fortress/          │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│ TIER 3: COMPUTE NODES                                                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│   NEXUS (16GB+) - ML/AI Heavy Computation                                        │
│   Location: /products/nexus/                                                     │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│ TIER 4: CENTRAL BRAIN                                                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│   MSSP - Cloud Federation Platform (mssp.hookprobe.com)                          │
│   Location: /products/mssp/                                                      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Product Comparison

| Feature | Sentinel | Guardian | Fortress | Nexus | MSSP |
|---------|----------|----------|----------|-------|------|
| **RAM** | 256MB | 1.5GB | 4GB | 16GB+ | Scales |
| **Role** | Validator | Edge | Edge+ | Compute | Brain |
| **L2-L7 Detection** | - | Yes | Yes | Yes | - |
| **WiFi Hotspot** | - | Yes | Yes | - | - |
| **VLAN Segmentation** | - | - | Yes | - | - |
| **Local AI** | - | - | Yes | Yes | - |
| **ML Training** | - | - | - | Yes | Yes |
| **Fleet Management** | - | - | - | Regional | Global |
| **Multi-Tenant** | - | - | - | - | Yes |

---

## Security Model

### Threat Mitigation

| Attack | Traditional Defense | HookProbe Defense |
|--------|-------------------|-------------------|
| **Static Key Theft** | Key rotation, HSM | No static keys - weights evolve continuously |
| **Offline Tampering** | TPM attestation | Integrity hash change → weight divergence |
| **MITM** | TLS/WireGuard | HTP with weight-bound session keys |
| **Replay Attack** | Nonces, timestamps | TER chain hash + monotonic sequence |
| **Impersonation** | Digital signatures | PoSF signature from unique weight trajectory |
| **Compromised Device** | Manual re-provisioning | Automatic resonance failure on reconnect |
| **NAT/CGNAT Traversal** | Complex hole-punching | HTP heartbeat protocol |

### Security Guarantees

1. **Tamper-Evidence**
   - Microblock chain: Each block references previous block hash
   - Merkle tree: Any modification invalidates checkpoint root
   - BLS aggregation: Requires 2/3 validator consensus

2. **Non-Repudiation**
   - TPM signatures: Hardware-backed, cannot be forged
   - Attestation: Proves node integrity at signing time
   - Sequence numbers: Prevents replay attacks

3. **Byzantine Fault Tolerance**
   - Quorum consensus: Tolerates f=(n-1)/3 malicious validators
   - Validator rotation: Periodic re-attestation required
   - Optional stake/slash: Economic incentives for honest behavior

4. **Privacy**
   - IP anonymization: Hashed before inclusion in blocks
   - Payload separation: Only hash stored in microblock
   - Selective disclosure: Full payloads only shared with authorized nodes

---

## Backend Deployment Foundation

### POD Architecture

| POD | Function |
|-----|----------|
| **001** | Web Management UI / API gateway / DMZ services |
| **002** | IAM: Identity, Auth, RBAC, SSO |
| **003** | Persistent DB (PostgreSQL + encrypted volumes) |
| **004** | Transient data, cache, queues (Redis/Valkey) |
| **005** | Metrics, Logs, Dashboards (ClickHouse, Grafana) |
| **006** | Security Detection: Suricata, Snort3, Zeek, XDP/eBPF |
| **007** | Autonomous AI Response & Mitigation Engine |
| **008** | Workflow Automation (n8n, hooks, defensive playbooks) |
| **009** | Email System, Cloudflare Tunnel, Notification Mesh |
| **010** | DSM Ledger & Consensus Engine |

### MSSP Device Registry

```sql
-- Main devices table
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    device_type TEXT NOT NULL,              -- 'edge', 'validator', 'cloud'
    hardware_fingerprint TEXT NOT NULL,
    public_key_ed25519 TEXT NOT NULL,
    status TEXT NOT NULL,                   -- 'PENDING', 'ACTIVE', 'SUSPENDED', 'REVOKED'
    kyc_verified INTEGER DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);

-- Location tracking table
CREATE TABLE device_locations (
    device_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    country TEXT,
    region TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    asn INTEGER,
    isp TEXT
);
```

### Configuration Example

```yaml
dsm:
  node:
    id: "${HOOKPROBE_NODE_ID}"
    role: "edge"  # edge, validator, or both

  tpm:
    enabled: true
    key_path: "/var/lib/hookprobe/tpm/dsm-key"
    pcr_indices: [0, 1, 2, 3, 7]

  validator:
    enabled: false
    certificate_path: "/var/lib/hookprobe/certs/validator.pem"

  consensus:
    epoch_duration: 300  # 5 minutes per epoch
    quorum_threshold: 0.67  # 2/3 validators required
    signature_timeout: 30  # seconds to collect signatures

  storage:
    microblocks:
      backend: "rocksdb"
      path: "/var/lib/hookprobe/dsm/microblocks"
      retention_days: 30
    checkpoints:
      backend: "postgresql"
      table: "dsm_checkpoints"
      retention_days: 365

  gossip:
    port: 7946
    bootstrap_nodes:
      - "validator1.hookprobe.mesh:7946"
      - "validator2.hookprobe.mesh:7946"
```

### Installation

```bash
# Choose your tier based on hardware:

# IoT/LTE devices (256MB RAM)
sudo ./install.sh --tier sentinel

# Raspberry Pi travel setup (1.5GB RAM)
sudo ./install.sh --tier guardian

# Mini PC/Server (4GB RAM)
sudo ./install.sh --tier fortress

# Datacenter/Cloud (16GB+ RAM)
sudo ./install.sh --tier nexus

# MSSP Cloud deployment
# See docs/deployment/MSSP-PRODUCTION-DEPLOYMENT.md
```

---

## Implementation Status

### Core Components

| Component | Status | Location |
|-----------|--------|----------|
| **TER Generation** | Complete | `core/neuro/core/ter.py` |
| **Neural Engine** | Complete | `core/neuro/neural/engine.py` |
| **Fixed-Point Math** | Complete | `core/neuro/neural/fixedpoint.py` |
| **PoSF Signatures** | Complete | `core/neuro/core/posf.py` |
| **Deterministic Replay** | Complete | `core/neuro/core/replay.py` |
| **HTP Protocol** | Complete | `core/neuro/transport/htp.py` |
| **HTP Client** | Complete | `products/guardian/lib/htp_client.py` |
| **HTP File Transfer** | Complete | `products/guardian/lib/htp_file.py` |
| **Hardware Fingerprinting** | Complete | `core/neuro/identity/hardware_fingerprint.py` |
| **MSSP Device Registry** | Complete | `core/mssp/device_registry.py` |
| **DSM Node** | Complete | `shared/dsm/node.py` |
| **DSM Validator** | Complete | `shared/dsm/validator.py` |
| **Consensus Engine** | Complete | `shared/dsm/consensus.py` |

### Roadmap

| Phase | Timeline | Status |
|-------|----------|--------|
| **Phase 1**: Core Protocol | Q1 2025 | Complete |
| **Phase 2**: POD Integration | Q2 2025 | Complete |
| **Phase 3**: Liberty Integration | Q3 2025 | Complete |
| **Phase 4**: Production MSSP | Q4 2025 | In Progress |
| **Phase 5**: HTP Enhancements | Q1 2026 | Planned |
| **Phase 6**: Beta Testing | Q2-Q3 2026 | Planned |
| **Phase 7**: Production Launch | Q4 2026 | Planned |

---

## Repository Structure

```
hookprobe/
├── core/                           # Core Intelligence
│   ├── htp/                       # HookProbe Transport Protocol
│   ├── qsecbit/                   # Quantified Security Metric
│   └── neuro/                     # Neural Resonance Protocol
│
├── products/                       # Product Tiers
│   ├── sentinel/                  # DSM Validator (IoT, 256MB)
│   ├── guardian/                  # Travel Companion (RPi, 1.5GB)
│   ├── fortress/                  # Edge Router (Mini PC, 4GB)
│   ├── nexus/                     # ML/AI Compute (Server, 16GB+)
│   └── mssp/                      # Cloud Federation
│
├── shared/                         # Shared Infrastructure
│   ├── dsm/                       # Decentralized Security Mesh
│   └── response/                  # Automated threat response
│
├── infrastructure/                 # POD Deployments
│   └── pod-010-dsm/               # DSM Ledger POD
│
├── deploy/                         # Deployment Scripts
│   ├── install/                   # Installation scripts
│   └── containers/                # Podman/Docker configs
│
└── docs/                           # Documentation
    └── architecture/              # This document
```

---

## License

**MIT License** — Enterprise-grade security, democratized for everyone.

---

**HookProbe** — *Federated Cybersecurity Mesh*

*One node's detection → Everyone's protection*

**The Future of Cybersecurity**:
Neural Resonance · Decentralized Mesh · Surgical Precision
