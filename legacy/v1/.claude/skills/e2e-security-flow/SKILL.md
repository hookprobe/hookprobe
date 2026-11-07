---
name: e2e-security-flow
description: End-to-end HookProbe security flow reference — attack detection (Qsecbit) → RAG scoring → automated response → mesh propagation → DSM consensus → Neuro authentication — including the full E2E validation checklist, per-tier integration roles, and key integration file map. Use when validating, testing, debugging, or reasoning about the complete detection-to-consensus pipeline.
---

# End-to-End (E2E) Security Flow

Attack detection → response → propagation pipeline: how an attack is detected, how it propagates through the mesh, and how consensus is achieved.

## E2E Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           HOOKPROBE E2E SECURITY FLOW                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │  DETECTION  │───▶│   SCORING   │───▶│  RESPONSE   │───▶│ PROPAGATION │      │
│  │  (Qsecbit)  │    │   (RAG)     │    │  (XDP/FW)   │    │   (Mesh)    │      │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘      │
│         │                  │                  │                  │              │
│         ▼                  ▼                  ▼                  ▼              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │    DSM      │◀──▶│    HTP      │◀──▶│   NEURO     │◀──▶│   CORTEX    │      │
│  │ (Consensus) │    │ (Transport) │    │   (Auth)    │    │   (Visual)  │      │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘      │
│                                                                                  │
│  Product Tiers:  SENTINEL ──▶ GUARDIAN ──▶ FORTRESS ──▶ NEXUS                 │
│                  (Validate)   (Detect)     (Route)      (ML/Aggregate)          │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Component Roles in E2E Flow

| Component | Role | Key Files |
|-----------|------|-----------|
| **Qsecbit** | Detection & scoring | `core/qsecbit/qsecbit.py`, `unified_engine.py` |
| **HTP** | Secure transport | `core/htp/transport/htp.py` |
| **DSM** | Consensus & ledger | `shared/dsm/consensus.py`, `node.py` |
| **Neuro** | Neural authentication | `core/neuro/core/ter.py`, `posf.py` |
| **Mesh** | Communication layer | `shared/mesh/unified_transport.py` |
| **Response** | Automated mitigation | `shared/response/`, `core/qsecbit/response/` |
| **Cortex** | Visualization | `shared/cortex/backend/server.py` |

## Phase 1: Attack Detection (Qsecbit)

**Detection Layers (L2-L7):**

```python
# core/qsecbit/detectors/ - 7 OSI layer detectors
L2DataLinkDetector   → ARP spoofing, MAC flooding, Evil Twin, Rogue DHCP
L3NetworkDetector    → IP spoofing, ICMP flood, Smurf attack, Fragmentation
L4TransportDetector  → SYN flood, Port scan, TCP reset, Session hijacking
L5SessionDetector    → SSL strip, TLS downgrade, Cert pinning bypass
L7ApplicationDetector → SQL injection, XSS, DNS tunneling, Malware C2
```

**Qsecbit Scoring Formula:**

```python
Qsecbit = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly

# Default weights (Guardian):
α = 0.30  # System drift (Mahalanobis distance)
β = 0.30  # Attack probability (ML classifier)
γ = 0.20  # Classifier decay
δ = 0.20  # Quantum drift (entropy deviation)
ε = 0.15  # Energy anomaly (RAPL monitoring)

# Layer-weighted formula:
Qsecbit = 0.25·L2 + 0.10·L3 + 0.10·L4 + 0.25·L5 + 0.10·L7 + 0.10·energy + 0.05·behavioral + 0.05·correlation
```

**RAG Status Thresholds:**

| Status | Protection | Action Triggered |
|--------|------------|------------------|
| **GREEN** | > 55% | All clear, learning baseline |
| **AMBER** | 30-55% | Monitoring, investigating |
| **RED** | < 30% | Defending, active mitigation |

## Phase 2: Automated Response

**Response Orchestrator Actions:**

| Action | Implementation | Trigger Severity |
|--------|----------------|------------------|
| `BLOCK_IP` | XDP kernel-level / iptables | HIGH, CRITICAL |
| `BLOCK_MAC` | ebtables | MEDIUM+ |
| `RATE_LIMIT` | XDP tc qdisc | SYN_FLOOD, UDP_FLOOD |
| `ALERT` | Write to alerts.json | ALL |
| `TERMINATE_SESSION` | conntrack -D | SESSION_HIJACK |
| `QUARANTINE` | SDN isolation (via OVS) | MALWARE_C2 |
| `HONEYPOT_REDIRECT` | iptables REDIRECT | PORT_SCAN |

**Response Flow:**

```
ThreatEvent detected
    ↓
ResponseOrchestrator.respond(threat)
    ↓
├─ Get actions from DEFAULT_RESPONSE_MAP[attack_type]
├─ Execute each action:
│   ├─ BLOCK_IP → XDPManager.block_ip() or iptables
│   ├─ RATE_LIMIT → XDPManager.rate_limit()
│   └─ ALERT → _write_alert_file()
├─ Mark threat.blocked = True
└─ Return List[ResponseResult]
```

## Phase 3: Mesh Propagation

**Threat Intelligence Flow:**

```
Guardian detects threat
    ↓
QsecbitMeshBridge.report_threat(threat)
    ↓
├─ Convert to ThreatIntelligence
│   (intel_id, source_node, timestamp, threat_type, severity, ioc_type, ioc_value)
├─ Add to threat_cache (10K entries, LRU)
├─ Queue in _pending_gossip
└─ Create Cortex event (if callbacks registered)
    ↓
_gossip_loop() (every 5s)
    ↓
├─ For each connected peer:
│   ├─ Skip if peer in seen_by
│   ├─ Skip if hop_count ≥ 5
│   └─ transport.gossip(intel.to_bytes())
└─ PacketType.GOSSIP via UnifiedTransport
    ↓
Remote Node Receives
    ↓
├─ Dedup check (by intel_id)
├─ Add to local threat_cache
├─ intel.hop_count += 1
├─ Re-gossip if hop_count < 5
└─ Trigger local defense callbacks
```

**Mesh Packet Types:**

| Type | Code | Purpose |
|------|------|---------|
| `GOSSIP` | 0x32 | Threat intelligence propagation |
| `MICROBLOCK` | 0x30 | DSM microblock announcement |
| `CHECKPOINT` | 0x31 | Validator checkpoint broadcast |
| `SECURITY_EVENT` | 0x42 | Direct threat report |
| `CONSENSUS_VOTE` | 0x33 | BLS signature contribution |

## Phase 4: DSM Consensus

**Microblock Creation:**

```
ThreatEvent (from Qsecbit)
    ↓
DSMNode.create_microblock(event_type='threat_intel', payload=threat.to_bytes())
    ↓
├─ Increment sequence counter
├─ Hash payload (SHA-256)
├─ Sign with TPM (or RSA fallback)
├─ Calculate block ID
├─ Store in LevelDB ledger
└─ Announce via gossip protocol
```

**Checkpoint Consensus (Validators):**

```
Validators collect announced microblocks (5-minute epochs)
    ↓
Build Merkle tree from microblock IDs
    ↓
Create checkpoint:
  - merkle_root
  - included_ranges (node_id → seq range)
  - validator signature
    ↓
Broadcast to validator quorum
    ↓
ConsensusEngine.collect_signatures()
    ↓
├─ Gather signatures from validators
├─ Verify each signature
├─ Check 2/3 quorum (BFT threshold)
├─ Aggregate via BLS (RSA fallback)
├─ Commit finalized checkpoint
└─ Broadcast to all nodes
```

**Quorum Calculation:**

```python
def bft_quorum_required(total_validators: int) -> int:
    f = (total_validators - 1) // 3  # Byzantine tolerance
    return total_validators - f

# Examples:
# 10 validators → requires 7 (tolerates 3 Byzantine)
# 7 validators → requires 5 (tolerates 2 Byzantine)
```

## Phase 5: Neuro Authentication

**TER (Telemetry Event Record) Structure:**

```
H_Entropy    (32 bytes) - SHA256(CPU, memory, network, disk metrics)
H_Integrity  (20 bytes) - RIPEMD160(kernel, binary, config hashes)
Timestamp    (8 bytes)  - Unix microseconds
Sequence     (2 bytes)  - Monotonic counter
Chain_Hash   (2 bytes)  - CRC16(previous TER)
Total: 64 bytes fixed
```

**PoSF (Proof of Sensor Fusion) Verification:**

```
Message Hash + Nonce → NeuralEngine.forward() → Signature
    ↓
Cloud replays TER sequence
    ↓
Simulates weight evolution: W(t+1) = W(t) - η × ∇L(W(t), TER)
    ↓
Compares fingerprint: W_edge == W_simulated
    ↓
If mismatch: QUARANTINE (weight tampering detected)
```

**Resonance States:**

```
UNALIGNED → SEEKING → ALIGNED → DRIFTING → LOST
     │          │         │          │         │
  Initial   Handshake   Active   Drift>5%   Reconnect
```

## E2E Validation Checklist

Use this checklist to verify complete E2E flow:

```
[ ] DETECTION
    [ ] Detector identifies threat (NAPSE/ML)
    [ ] ThreatEvent created with all required fields
    [ ] Confidence score is realistic (0.0-1.0)
    [ ] Evidence dictionary populated
    [ ] MITRE ATT&CK ID assigned

[ ] SCORING
    [ ] Threat incorporated into layer score
    [ ] Unified Qsecbit score updated
    [ ] RAG status reflects severity
    [ ] Convergence rate calculated
    [ ] Trend analysis (IMPROVING/STABLE/DEGRADING)

[ ] RESPONSE
    [ ] ResponseOrchestrator.respond() called
    [ ] Appropriate ResponseAction(s) executed
    [ ] threat.blocked = True if successful
    [ ] ResponseResult logged
    [ ] Blocked IPs persisted (response_state.json)

[ ] PROPAGATION
    [ ] Threat converted to ThreatIntelligence
    [ ] Reported to mesh consciousness
    [ ] Cortex visualization event emitted
    [ ] DSM microblock created
    [ ] HTP encrypted transport used

[ ] CONSENSUS
    [ ] Microblock announced via gossip
    [ ] Validators collect blocks
    [ ] Merkle tree built
    [ ] Checkpoint created with signatures
    [ ] 2/3 quorum achieved
    [ ] Finalized checkpoint broadcast

[ ] NEURO AUTH
    [ ] TER generated with valid entropy
    [ ] Weight evolution applied
    [ ] PoSF signature created
    [ ] RDV (Resonance Drift Vector) validated
    [ ] Channel binding active

[ ] STORAGE
    [ ] ThreatEvent serialized to JSON
    [ ] QsecbitUnifiedScore saved to database
    [ ] Microblock stored in LevelDB
    [ ] Checkpoint persisted
    [ ] Audit trail in merkle_log
```

## Product Tier Integration

**Sentinel (256MB - IoT Validator):**
- Validates microblocks (timestamp, sequence, source)
- Contributes partial BLS signatures
- Maintains compact threat cache (100 entries)
- Gossip receive-only mode (bandwidth optimization)

**Guardian (1.5GB - Travel Companion):**
- Full L2-L7 detection pipeline
- Local Qsecbit scoring
- Dual-path: P2P mesh + cloud uplink
- Collective score aggregation
- Autonomous defense (AUTONOMOUS state)

**Fortress (4GB - Edge Router):**
- Regional consensus coordinator
- Full DSM participation
- Microblock → Checkpoint aggregation
- SDN rule distribution

**Nexus (16GB+ - ML/AI Compute):**
- Federated ML model training
- Pattern correlation across mesh
- Predictive threat escalation
- Advanced behavioral analysis
- Multi-tenant aggregation
- Historical threat database

## Key Integration Files

| Integration | File | Key Method |
|-------------|------|------------|
| Detection → Scoring | `core/qsecbit/unified_engine.py` | `detect()` |
| Scoring → Response | `core/qsecbit/response/orchestrator.py` | `respond()` |
| Response → Mesh | `core/qsecbit/mesh_bridge.py` | `report_threat()` |
| Mesh → DSM | `shared/dsm/node.py` | `create_microblock()` |
| DSM → Consensus | `shared/dsm/consensus.py` | `collect_validator_signatures()` |
| Mesh → Cortex | `shared/cortex/backend/connectors/` | `report_threat()` |
| HTP → Neuro | `shared/mesh/neuro_encoder.py` | `generate_rdv()` |
| Neuro → TER | `core/neuro/core/ter.py` | `generate()` |

## Running E2E Tests

```bash
# Run E2E integration test
pytest tests/test_e2e_integration.py -v

# Test specific flow
pytest tests/test_e2e_integration.py::test_attack_detection_to_mesh_propagation -v

# Test with coverage
pytest tests/test_e2e_integration.py --cov=core --cov=shared --cov-report=html
```
