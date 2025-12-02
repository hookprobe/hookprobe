# HookProbe DSM: Decentralized Security Mesh

**Python implementation of the DSM distributed security architecture**

## Overview

This module implements the Decentralized Security Mesh (DSM) described in the [DSM Whitepaper](../../docs/architecture/dsm-whitepaper.md) and [DSM Implementation Architecture](../../docs/architecture/dsm-implementation.md).

DSM transforms HookProbe from a standalone security platform into a distributed, cryptographically verifiable security mesh operating as **"one brain powered by many"** edge nodes.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│              Layer 3: Consensus (BFT)                     │
│  ConsensusEngine: BLS signature aggregation              │
└──────────────────────────────────────────────────────────┘
                         ▲
┌──────────────────────────────────────────────────────────┐
│           Layer 2: Validation (Merkle DAG)                │
│  DSMValidator: Checkpoint creation                       │
│  GossipProtocol: Block announcement                      │
└──────────────────────────────────────────────────────────┘
                         ▲
┌──────────────────────────────────────────────────────────┐
│          Layer 1: Detection (Edge Nodes)                  │
│  DSMNode: Microblock creation                            │
│  Integration with POD-006, POD-007                       │
└──────────────────────────────────────────────────────────┘
```

## Components

### Core Classes

- **`DSMNode`** (`node.py`): Edge node that creates cryptographically signed microblocks for security events
- **`DSMValidator`** (`validator.py`): Enhanced node with validator capabilities for checkpoint creation
- **`ConsensusEngine`** (`consensus.py`): BLS signature aggregation for Byzantine fault-tolerant consensus
- **`NodeIdentity`** (`identity.py`): TPM-backed hardware identity and attestation

### Supporting Modules

- **`LevelDBLedger`** (`ledger.py`): Local microblock storage
- **`GossipProtocol`** (`gossip.py`): Peer-to-peer block announcement
- **`MerkleTree`** (`merkle.py`): Cryptographic aggregation of microblocks
- **`crypto/tpm.py`**: TPM 2.0 cryptographic operations
- **`crypto/bls.py`**: BLS signature aggregation
- **`crypto/attestation.py`**: Platform integrity verification

## Usage

### Edge Node (POD-010)

```python
from hookprobe.dsm import DSMNode

# Initialize edge node
node = DSMNode(
    node_id="edge-12345",
    tpm_key_path="/var/lib/hookprobe/tpm/dsm-key",
    bootstrap_nodes=["validator1.mesh:7946", "validator2.mesh:7946"]
)

# Create microblock for security event (called by POD-006/POD-007)
microblock = node.create_microblock(
    payload={
        'event_id': 'evt-123',
        'severity': 'critical',
        'category': 'malware',
        'threat_score': 95
    },
    event_type='ids_alert'
)

print(f"Microblock created: {microblock['id']}")
```

### Validator Node

```python
from hookprobe.dsm import DSMValidator, ConsensusEngine

# Initialize validator
validator = DSMValidator(
    node_id="validator-001",
    tpm_key_path="/var/lib/hookprobe/tpm/validator-key",
    validator_cert="/etc/hookprobe/certs/validator.pem"
)

# Build checkpoint (every 5 minutes)
checkpoint = validator.build_checkpoint(epoch=147)

# Aggregate signatures via BLS consensus
consensus = ConsensusEngine(validators, quorum_threshold=0.67)
finalized = consensus.collect_validator_signatures(checkpoint)

print(f"Checkpoint finalized: epoch={finalized['epoch']}")
```

### Integration with POD-006 (Security Detection)

```python
from hookprobe.dsm.node import SecurityEventHandler

# Create handler
handler = SecurityEventHandler(dsm_node)

# On Suricata/Zeek alert
microblock_id = handler.on_suricata_alert(alert)
```

### Integration with POD-007 (AI Response)

```python
from hookprobe.dsm.node import MitigationLogger

# Create logger
logger = MitigationLogger(dsm_node)

# On mitigation executed
microblock_id = logger.on_mitigation_executed(threat, action)
```

## Security Guarantees

### 1. Tamper-Evidence
Every security event is immutably recorded in a cryptographic chain:
```
Event → Hash → TPM Sign → Merkle Tree → BLS Aggregate
```

### 2. Non-Repudiation
- TPM signatures are hardware-backed and cannot be forged
- Validators cannot deny signing checkpoints
- Complete audit trail of all security actions

### 3. Byzantine Fault Tolerance
- Tolerates f=(n-1)/3 malicious validators
- Requires 2/3 quorum for consensus
- Attacker must compromise majority of validators

### 4. Platform Integrity
- Continuous TPM attestation required
- Compromised nodes automatically quarantined
- PCR measurements prove software authenticity

## Dependencies

```
# Required
tpm2-pytss>=2.0.0          # TPM 2.0 operations
py-ecc>=6.0.0              # BLS signature aggregation
plyvel>=1.5.0              # LevelDB for local storage

# Optional
blspy>=2.0.0               # Alternative BLS implementation
cryptography>=41.0.0       # Certificate operations
```

## Configuration

See `config/dsm.yaml` for full configuration options:

```yaml
dsm:
  node:
    id: "${HOOKPROBE_NODE_ID}"
    role: "edge"  # or "validator"

  tpm:
    enabled: true
    key_path: "/var/lib/hookprobe/tpm/dsm-key"

  consensus:
    epoch_duration: 300  # 5 minutes
    quorum_threshold: 0.67
```

## Development Status

| Component | Status | Notes |
|-----------|--------|-------|
| DSMNode | ✅ Implemented | Core microblock creation |
| DSMValidator | ✅ Implemented | Checkpoint creation |
| ConsensusEngine | ✅ Implemented | BLS aggregation logic |
| TPM Integration | 🟡 Stub | Requires tpm2-pytss integration |
| BLS Signatures | 🟡 Stub | Requires py-ecc implementation |
| Gossip Protocol | 🟡 Stub | Requires P2P network implementation |
| LevelDB Storage | 🟡 Stub | Requires plyvel integration |

**Legend**: ✅ Complete | 🟡 Stub/In Progress | ❌ Not Started

## Testing

```bash
# Run DSM tests
pytest src/dsm/tests/

# Run with coverage
pytest src/dsm/tests/ --cov=src/dsm --cov-report=html
```

## Documentation

- [DSM Whitepaper](../../docs/architecture/dsm-whitepaper.md) - Conceptual architecture
- [DSM Implementation](../../docs/architecture/dsm-implementation.md) - Technical specifications
- [Security Model](../../docs/architecture/security-model.md#8-decentralized-security-mesh-dsm) - Trust architecture

## Related PODs

- **POD-006**: Security Detection (IDS/IPS) - Event source
- **POD-007**: AI Response (Qsecbit) - Mitigation logging
- **POD-003**: PostgreSQL - Checkpoint storage
- **POD-005**: Grafana - DSM metrics visualization
- **POD-010**: DSM Ledger - This module

## License

MIT License - See [LICENSE](../../LICENSE) file

## Contributors

HookProbe DSM Team

For questions or contributions, see [CONTRIBUTING.md](../../docs/CONTRIBUTING.md)
