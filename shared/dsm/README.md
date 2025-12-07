# HookProbe DSM: Decentralized Security Mesh

**Pillar 2 of HookProbe: Collective Intelligence**

> *One brain powered by many edge nodes*

**Full Documentation**: [../../docs/architecture/HOOKPROBE-ARCHITECTURE.md](../../docs/architecture/HOOKPROBE-ARCHITECTURE.md#dsm---decentralized-security-mesh)

## Quick Start

```python
from hookprobe.dsm import DSMNode

# Initialize edge node
node = DSMNode(
    node_id="edge-12345",
    tpm_key_path="/var/lib/hookprobe/tpm/dsm-key",
    bootstrap_nodes=["validator1.mesh:7946", "validator2.mesh:7946"]
)

# Create microblock for security event
microblock = node.create_microblock(
    payload={'event_id': 'evt-123', 'severity': 'critical'},
    event_type='ids_alert'
)
```

## Module Structure

- **`node.py`**: DSMNode - Edge node microblock creation
- **`validator.py`**: DSMValidator - Checkpoint creation
- **`consensus.py`**: ConsensusEngine - BLS signature aggregation
- **`identity.py`**: NodeIdentity - TPM-backed hardware identity
- **`ledger.py`**: LevelDBLedger - Local microblock storage
- **`gossip.py`**: GossipProtocol - P2P block announcement
- **`merkle.py`**: MerkleTree - Cryptographic aggregation
- **`crypto/`**: TPM, BLS, and attestation operations
