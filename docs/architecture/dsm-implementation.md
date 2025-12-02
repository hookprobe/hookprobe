# HookProbe DSM: Implementation Architecture

**Integrating Decentralized Security Mesh into HookProbe Infrastructure**

*Technical Implementation Guide — 2025*

---

## Table of Contents

1. [Overview](#overview)
2. [DSM Core Concepts](#dsm-core-concepts)
3. [Integration with Existing POD Architecture](#integration-with-existing-pod-architecture)
4. [Microblock & Checkpoint Architecture](#microblock--checkpoint-architecture)
5. [Validator Network & Trust Model](#validator-network--trust-model)
6. [Implementation Specifications](#implementation-specifications)
7. [Data Flow & Protocol](#data-flow--protocol)
8. [Security Guarantees](#security-guarantees)
9. [Deployment Strategy](#deployment-strategy)
10. [API Reference](#api-reference)

---

## Overview

HookProbe DSM transforms the existing POD-based security platform into a **distributed, tamper-evident security mesh** where:

- Every security event becomes a cryptographically signed **microblock**
- Validators create **checkpoints** that aggregate microblocks into a Merkle tree
- BLS signature aggregation ensures **Byzantine fault tolerance**
- TPM-backed identities prevent **unauthorized node participation**
- The mesh operates as **"one brain powered by many"** edge nodes

This document specifies how DSM integrates with HookProbe's existing infrastructure without disrupting current functionality.

---

## DSM Core Concepts

### The Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Layer 3: Consensus                        │
│  Validators aggregate microblocks into checkpoints          │
│  BLS signature aggregation for Byzantine fault tolerance    │
└─────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────┐
│                  Layer 2: Validation                         │
│  Merkle DAG of microblocks from all edge nodes              │
│  Gossip protocol for block announcement                     │
└─────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────┐
│                   Layer 1: Detection                         │
│  Edge nodes create microblocks for security events          │
│  TPM-signed, cryptographically verifiable                   │
└─────────────────────────────────────────────────────────────┘
```

### Key Data Structures

#### 1. Microblock (M)
```json
{
  "type": "M",
  "node_id": "edge-uuid-12345",
  "seq": 1847,
  "prev": "hash-of-previous-microblock",
  "timestamp": "2025-11-26T18:35:00Z",
  "payload_hash": "sha256-of-security-event",
  "event_type": "ids_alert|mitigation|threat_intel|policy_update",
  "signature": "tpm-signed-data"
}
```

#### 2. Checkpoint (C)
```json
{
  "type": "C",
  "epoch": 147,
  "timestamp": "2025-11-26T18:40:00Z",
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

#### 3. Security Event Payload
```json
{
  "event_id": "evt-uuid",
  "source": "suricata|zeek|xdp|qsecbit",
  "severity": "critical|high|medium|low",
  "category": "malware|c2|scan|exploit|anomaly",
  "indicators": {
    "src_ip": "anonymized-hash",
    "dst_ip": "anonymized-hash",
    "signature_id": 2024001,
    "threat_score": 95
  },
  "mitigation": {
    "action": "block|rate_limit|alert|quarantine",
    "applied": true,
    "timestamp": "2025-11-26T18:35:05Z"
  }
}
```

---

## Integration with Existing POD Architecture

### New Component: POD-010 (DSM Ledger)

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

### Modified POD Interactions

#### POD-006 (Security Detection) → POD-010 (DSM)
```python
# When Suricata/Zeek generates alert
def on_security_event(event):
    # Existing: Log to ClickHouse
    log_to_clickhouse(event)

    # NEW: Create DSM microblock
    microblock = dsm_node.create_microblock(
        payload=event,
        event_type='ids_alert'
    )

    # Gossip to network
    dsm_node.announce(microblock)
```

#### POD-007 (AI Response) → POD-010 (DSM)
```python
# When mitigation is executed
def execute_mitigation(threat):
    action = qsecbit_decide(threat)
    apply_mitigation(action)

    # NEW: Log as DSM microblock
    microblock = dsm_node.create_microblock(
        payload={
            'threat_id': threat.id,
            'action': action,
            'success': True
        },
        event_type='mitigation'
    )
    dsm_node.announce(microblock)
```

---

## Microblock & Checkpoint Architecture

### Microblock Creation Flow

```python
class DSMNode:
    """
    DSM node running on each HookProbe edge device.
    Integrates with POD-006, POD-007 for event capture.
    """

    def __init__(self, node_id, tpm_key_path):
        self.node_id = node_id
        self.tpm_key = load_tpm_key(tpm_key_path)
        self.sequence = 0
        self.prev_block_id = None
        self.ledger = LevelDBLedger()
        self.gossip = GossipProtocol(node_id)

    def create_microblock(self, payload, event_type):
        """
        Create a cryptographically signed microblock for a security event.

        Args:
            payload: Security event data (dict)
            event_type: Type of event (ids_alert, mitigation, etc.)

        Returns:
            Microblock object with TPM signature
        """
        self.sequence += 1
        payload_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()

        microblock = {
            'type': 'M',
            'node_id': self.node_id,
            'seq': self.sequence,
            'prev': self.prev_block_id,
            'timestamp': datetime.utcnow().isoformat(),
            'payload_hash': payload_hash,
            'event_type': event_type
        }

        # TPM signing for hardware-backed authenticity
        signature = self._sign_with_tpm(microblock)
        microblock['signature'] = signature

        # Calculate block ID
        block_id = self._calculate_block_id(microblock)
        microblock['id'] = block_id

        # Store locally
        self.ledger.store(block_id, microblock, payload)
        self.prev_block_id = block_id

        # Announce to network via gossip
        self.gossip.announce(block_id, microblock)

        # Metrics
        metrics.increment('dsm.microblocks.created',
                         tags=[f'type:{event_type}'])

        return microblock

    def _sign_with_tpm(self, data):
        """
        Sign data using TPM 2.0 hardware key.
        Falls back to TrustZone/SGX if available.
        """
        serialized = json.dumps(data, sort_keys=True).encode()
        return tpm2_sign(self.tpm_key, serialized)

    def _calculate_block_id(self, microblock):
        """Calculate unique block ID from microblock content."""
        content = {k: v for k, v in microblock.items() if k != 'signature'}
        serialized = json.dumps(content, sort_keys=True).encode()
        return hashlib.sha256(serialized).hexdigest()
```

### Checkpoint Creation (Validators Only)

```python
class DSMValidator(DSMNode):
    """
    Enhanced node with validator capabilities.
    Only authorized, attested validators can create checkpoints.
    """

    def __init__(self, node_id, tpm_key_path, validator_cert):
        super().__init__(node_id, tpm_key_path)
        self.validator_cert = validator_cert
        self.is_validator = self._verify_validator_cert()

    def build_checkpoint(self, epoch):
        """
        Aggregate all announced microblocks into a checkpoint.

        Args:
            epoch: Current epoch number (e.g., every 5 minutes)

        Returns:
            Checkpoint object with Merkle root and signature
        """
        if not self.is_validator:
            raise PermissionError("Only validators can create checkpoints")

        # Collect all microblock IDs announced in this epoch window
        epoch_window = self._get_epoch_window(epoch)
        microblock_ids = self.gossip.collect_announced_blocks(epoch_window)

        # Build Merkle tree
        merkle_tree = MerkleTree(microblock_ids)
        merkle_root = merkle_tree.root()

        # Map which ranges from each node are included
        included_ranges = self._map_node_ranges(microblock_ids)

        checkpoint = {
            'type': 'C',
            'epoch': epoch,
            'timestamp': datetime.utcnow().isoformat(),
            'merkle_root': merkle_root,
            'included_ranges': included_ranges,
            'validator_id': self.node_id,
            'microblock_count': len(microblock_ids)
        }

        # Sign with validator TPM key
        checkpoint['signature'] = self._sign_with_tpm(checkpoint)

        # Broadcast to other validators for BLS aggregation
        self.gossip.broadcast_checkpoint(checkpoint)

        return checkpoint

    def _verify_validator_cert(self):
        """
        Verify this node has a valid validator certificate
        issued by the DSM attestation authority.
        """
        return verify_certificate_chain(
            self.validator_cert,
            trusted_root=DSM_CA_ROOT
        )
```

### BLS Signature Aggregation

```python
class ConsensusEngine:
    """
    Handles BLS signature aggregation for Byzantine fault tolerance.
    Requires 2/3 validator quorum for checkpoint finality.
    """

    def __init__(self, validators, quorum_threshold=0.67):
        self.validators = validators
        self.quorum_threshold = quorum_threshold
        self.pending_checkpoints = {}

    def collect_validator_signatures(self, checkpoint):
        """
        Gather signatures from validators and aggregate via BLS.

        Args:
            checkpoint: Checkpoint object to be finalized

        Returns:
            Finalized checkpoint with aggregated signature
        """
        epoch = checkpoint['epoch']
        timeout = 30  # seconds

        # Gather signatures from other validators
        signatures = self._gather_signatures(
            epoch,
            checkpoint['merkle_root'],
            timeout
        )

        # Verify quorum
        if len(signatures) < len(self.validators) * self.quorum_threshold:
            raise QuorumNotReached(
                f"Only {len(signatures)}/{len(self.validators)} validators signed"
            )

        # Aggregate using BLS signature scheme
        aggregated_sig = bls_aggregate(signatures)

        # Verify aggregated signature
        if not self._verify_aggregated_signature(aggregated_sig, checkpoint):
            raise InvalidAggregateSignature("BLS verification failed")

        # Add to checkpoint
        checkpoint['agg_signature'] = aggregated_sig
        checkpoint['validator_count'] = len(signatures)

        # Commit to persistent storage
        self._commit_checkpoint(checkpoint)

        # Broadcast finalized checkpoint to all nodes
        self.gossip.broadcast_finalized_checkpoint(checkpoint)

        metrics.increment('dsm.checkpoints.finalized')

        return checkpoint

    def _verify_aggregated_signature(self, agg_sig, checkpoint):
        """
        Verify BLS aggregated signature against validator public keys.
        """
        validator_pubkeys = [v.public_key for v in self.validators]
        message = self._checkpoint_message(checkpoint)
        return bls_verify(agg_sig, validator_pubkeys, message)
```

---

## Validator Network & Trust Model

### "One Brain Powered by Many" Architecture

The DSM creates a **distributed trust model** where:

1. **Edge Nodes (Many)**: Generate microblocks from local security events
2. **Validators (Trusted Few)**: Aggregate and attest to the validity of events
3. **Consensus (The Brain)**: BLS aggregation creates single source of truth

### Preventing Bad Actors

#### 1. TPM-Backed Identity
```python
class NodeIdentity:
    """
    Every node must have a TPM-backed cryptographic identity.
    Prevents spoofing and unauthorized participation.
    """

    @staticmethod
    def provision_node(hardware_id):
        """
        Provision new node with TPM-backed identity.
        Requires attestation by DSM CA.
        """
        # Generate TPM key pair
        tpm_keypair = tpm2_create_primary()

        # Measure platform integrity
        pcr_values = tpm2_pcr_read([0, 1, 2, 3, 7])

        # Request certificate from DSM CA
        csr = create_certificate_request(
            public_key=tpm_keypair.public,
            hardware_id=hardware_id,
            pcr_snapshot=pcr_values
        )

        # CA validates hardware + integrity before issuing
        certificate = dsm_ca.issue_certificate(csr)

        return NodeIdentity(certificate, tpm_keypair.private)

    def attest(self):
        """
        Prove current integrity state matches provisioned state.
        Required before joining validator network.
        """
        current_pcr = tpm2_pcr_read([0, 1, 2, 3, 7])
        quote = tpm2_quote(current_pcr, nonce=random_nonce())

        return {
            'pcr_values': current_pcr,
            'quote': quote,
            'certificate': self.certificate
        }
```

#### 2. Validator Authorization
```python
class ValidatorRegistry:
    """
    Maintains registry of authorized validators.
    Only nodes with valid attestation can become validators.
    """

    def __init__(self):
        self.validators = {}
        self.pending_applications = {}

    def apply_for_validator(self, node_identity):
        """
        Node applies to become a validator.
        Requires:
        - Valid TPM certificate
        - Successful attestation
        - Stake/bond (optional, for economic incentive)
        """
        # Verify identity
        if not self._verify_identity(node_identity):
            raise InvalidIdentity("Node identity verification failed")

        # Verify attestation
        attestation = node_identity.attest()
        if not self._verify_attestation(attestation):
            raise AttestationFailed("Platform integrity check failed")

        # Add to pending (requires quorum approval)
        application = {
            'node_id': node_identity.node_id,
            'certificate': node_identity.certificate,
            'attestation': attestation,
            'timestamp': datetime.utcnow(),
            'status': 'pending'
        }

        self.pending_applications[node_identity.node_id] = application

        # Vote by existing validators
        self._initiate_validator_vote(application)

    def _verify_attestation(self, attestation):
        """
        Verify TPM quote and PCR values.
        Ensures node is running authentic HookProbe software.
        """
        # Verify PCR values match expected measurements
        expected_pcr = get_expected_pcr_values()
        if attestation['pcr_values'] != expected_pcr:
            return False

        # Verify TPM quote signature
        if not tpm2_verify_quote(attestation['quote'], attestation['certificate']):
            return False

        return True
```

#### 3. Byzantine Fault Tolerance
```python
def bft_quorum_required(total_validators):
    """
    Calculate minimum validators required for BFT consensus.
    Tolerates up to f=(n-1)/3 Byzantine (malicious) validators.

    For n=10 validators: f=3 Byzantine tolerated, require 7 signatures
    For n=7 validators: f=2 Byzantine tolerated, require 5 signatures
    """
    f = (total_validators - 1) // 3
    quorum = total_validators - f
    return quorum

# Example: With 10 validators, we can tolerate 3 compromised nodes
# and still achieve consensus with 7 honest validators
```

---

## Implementation Specifications

### Component Structure

```
src/dsm/
├── __init__.py
├── node.py                 # DSMNode class
├── validator.py            # DSMValidator class
├── consensus.py            # ConsensusEngine class
├── identity.py             # NodeIdentity, TPM operations
├── ledger.py              # Local storage (LevelDB/RocksDB)
├── gossip.py              # Gossip protocol implementation
├── merkle.py              # Merkle tree construction
├── crypto/
│   ├── tpm.py            # TPM 2.0 operations
│   ├── bls.py            # BLS signature aggregation
│   └── attestation.py    # Platform attestation
├── api/
│   ├── query.py          # Query interface for blocks
│   └── webhooks.py       # Event notifications
└── tests/
    ├── test_node.py
    ├── test_validator.py
    └── test_consensus.py
```

### Configuration (`config/dsm.yaml`)

```yaml
dsm:
  # Node configuration
  node:
    id: "${HOOKPROBE_NODE_ID}"
    role: "edge"  # edge, validator, or both

  # TPM configuration
  tpm:
    enabled: true
    key_path: "/var/lib/hookprobe/tpm/dsm-key"
    pcr_indices: [0, 1, 2, 3, 7]  # Platform integrity measurements

  # Validator configuration (only for validators)
  validator:
    enabled: false  # Set true for validator nodes
    certificate_path: "/var/lib/hookprobe/certs/validator.pem"

  # Consensus parameters
  consensus:
    epoch_duration: 300  # 5 minutes per epoch
    quorum_threshold: 0.67  # 2/3 validators required
    signature_timeout: 30  # seconds to collect signatures

  # Storage configuration
  storage:
    microblocks:
      backend: "rocksdb"
      path: "/var/lib/hookprobe/dsm/microblocks"
      retention_days: 30
    checkpoints:
      backend: "postgresql"  # POD-003
      table: "dsm_checkpoints"
      retention_days: 365

  # Network configuration
  gossip:
    port: 7946
    bootstrap_nodes:
      - "validator1.hookprobe.mesh:7946"
      - "validator2.hookprobe.mesh:7946"
    max_peers: 50

  # Integration with existing PODs
  integrations:
    pod_006:
      enabled: true
      events: ["ids_alert", "threat_detected"]
    pod_007:
      enabled: true
      events: ["mitigation_applied"]
    pod_005:
      metrics_export: true
      dashboard: "DSM Mesh Overview"
```

---

## Data Flow & Protocol

### End-to-End Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Security Event Occurs (POD-006)                              │
│    Suricata detects C2 beacon                                   │
└────────────────┬────────────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. Edge Node Creates Microblock (POD-010)                       │
│    - Hash event payload                                         │
│    - Sign with TPM key                                          │
│    - Increment sequence counter                                 │
│    - Link to previous block                                     │
└────────────────┬────────────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. Gossip Announcement                                          │
│    - Announce block ID to mesh peers                            │
│    - Peers request full block if interested                     │
└────────────────┬────────────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. Validators Collect Microblocks                               │
│    - Gather all announced blocks in epoch window                │
│    - Validate signatures and TPM attestations                   │
└────────────────┬────────────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. Checkpoint Creation (Every 5 minutes)                        │
│    - Build Merkle tree of all microblock IDs                    │
│    - Sign checkpoint with validator TPM key                     │
│    - Broadcast to validator quorum                              │
└────────────────┬────────────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. BLS Signature Aggregation                                    │
│    - Collect signatures from 2/3 validators                     │
│    - Aggregate into single BLS signature                        │
│    - Verify aggregated signature                                │
└────────────────┬────────────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. Checkpoint Finalization                                      │
│    - Commit to PostgreSQL (POD-003)                             │
│    - Broadcast to all mesh nodes                                │
│    - Update Grafana dashboards (POD-005)                        │
└─────────────────────────────────────────────────────────────────┘
```

### Protocol Messages

#### ANNOUNCE (Gossip)
```json
{
  "type": "ANNOUNCE",
  "block_id": "abc123...",
  "node_id": "edge-uuid-12345",
  "seq": 1847,
  "timestamp": "2025-11-26T18:35:00Z"
}
```

#### REQUEST (Fetch full block)
```json
{
  "type": "REQUEST",
  "block_id": "abc123...",
  "requester": "validator-uuid-001"
}
```

#### CHECKPOINT_PROPOSAL (From validator)
```json
{
  "type": "CHECKPOINT_PROPOSAL",
  "checkpoint": { /* checkpoint object */ },
  "validator_id": "validator-uuid-001"
}
```

#### CHECKPOINT_VOTE (BLS signature)
```json
{
  "type": "CHECKPOINT_VOTE",
  "epoch": 147,
  "merkle_root": "root-hash",
  "signature": "bls-signature",
  "validator_id": "validator-uuid-002"
}
```

---

## Security Guarantees

### 1. Tamper-Evidence
- **Microblock chain**: Each block references previous block hash
- **Merkle tree**: Any modification invalidates checkpoint root
- **BLS aggregation**: Requires 2/3 validator consensus

### 2. Non-Repudiation
- **TPM signatures**: Hardware-backed, cannot be forged
- **Attestation**: Proves node integrity at signing time
- **Sequence numbers**: Prevents replay attacks

### 3. Byzantine Fault Tolerance
- **Quorum consensus**: Tolerates f=(n-1)/3 malicious validators
- **Validator rotation**: Periodic re-attestation required
- **Stake/slash**: Economic incentives for honest behavior (optional)

### 4. Privacy
- **IP anonymization**: Hashed before inclusion in blocks
- **Payload separation**: Only hash stored in microblock
- **Selective disclosure**: Full payloads only shared with authorized nodes

---

## Deployment Strategy

### Phase 1: Edge Node Integration (Q1 2025) - ✅ Complete
- ✅ Deploy POD-010 alongside existing PODs
- ✅ Integrate with POD-006 (detection) and POD-007 (response)
- ✅ Create microblocks for all security events
- ✅ Local-only validation (no consensus yet)

### Phase 2: Validator Network (Q2 2025) - ✅ Complete
- ✅ Deploy first validator quorum (3-5 nodes)
- ✅ Implement checkpoint creation
- ✅ BLS signature aggregation
- ✅ Merkle tree verification

### Phase 3: Liberty Integration (Q3 2025) - ✅ Complete
- ✅ HTP protocol for NAT/CGNAT traversal
- ✅ MSSP device registry with geolocation
- ✅ Hardware fingerprinting (no TPM required)
- ✅ Validator KYC workflow
- ✅ Complete documentation

### Phase 4: Production Deployment (Q4 2025) - 🔄 In Progress
- 🔄 Production MSSP deployment (hookprobe.com)
- 🔄 Beta validator network (3-10 nodes)
- 🔄 Edge node beta program
- 🔄 Performance benchmarking
- 🔄 Security audit (internal)

### Phase 5: Production Launch (Q1 2026) - Planned
- Public MSSP cloud launch
- Cross-tenant threat intelligence
- Automated validator onboarding
- Grafana dashboard integration

### Phase 6: Advanced Features (Q2-Q4 2026) - Planned
- Federated ML model sharing
- Zero-knowledge proofs for privacy
- Smart contract-based policies
- Quantum-resistant signatures
- Cross-mesh federation

---

## API Reference

### Query Interface

```python
from hookprobe.dsm import DSMClient

client = DSMClient()

# Query microblocks by node
blocks = client.get_microblocks(
    node_id='edge-uuid-12345',
    start_seq=1000,
    end_seq=2000
)

# Get checkpoint by epoch
checkpoint = client.get_checkpoint(epoch=147)

# Verify block in checkpoint
is_valid = client.verify_block_in_checkpoint(
    block_id='abc123...',
    checkpoint_epoch=147
)

# Get threat intelligence from mesh
threats = client.query_threat_intel(
    threat_type='c2',
    time_range='24h'
)
```

### Event Webhooks

```yaml
# config/dsm-webhooks.yaml
webhooks:
  - url: "https://siem.company.com/hookprobe/events"
    events: ["checkpoint_finalized"]
    auth:
      type: "bearer"
      token: "${SIEM_TOKEN}"

  - url: "https://slack.com/webhooks/..."
    events: ["validator_quorum_lost"]
    format: "slack"
```

---

## Related Documentation

- [DSM Whitepaper](dsm-whitepaper.md) - Conceptual architecture
- [Security Model](security-model.md) - Trust and threat model
- [POD Components](../components/README.md) - Integration points
- [IAM Integration](../IAM-INTEGRATION-GUIDE.md) - Identity management

---

**Version**: 1.0 (Draft)
**Last Updated**: 2025-12-02
**Status**: Implementation Planning
**Maintained by**: HookProbe DSM Team
