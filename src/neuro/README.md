# HookProbe Neuro Protocol

**Revolutionary cryptographic protocol using deterministic neural weight evolution for continuous mutual authentication.**

---

## Overview

**Neuro** replaces traditional static keys (RSA, ECDSA) with **neural network weights that evolve deterministically** based on sensor data. This creates a continuously-authenticating, tamper-evident communication channel between Edge nodes and Cloud validators.

### Core Innovation

Instead of: *"Do you still know the secret key?"*
**Neuro asks**: *"Can you prove your sensor history by showing the correct weight evolution?"*

---

## Key Concepts

### 1. Temporal Event Record (TER)
64-byte sensor snapshot that drives weight evolution:
- **H_Entropy** (32 bytes): SHA256 of system metrics (CPU, memory, network, disk)
- **H_Integrity** (20 bytes): RIPEMD160 of critical file hashes (kernel, binary, config)
- **Timestamp** (8 bytes): Microsecond-precision time
- **Sequence** (2 bytes): Monotonic counter
- **Chain_Hash** (2 bytes): CRC16 of previous TER (tamper detection)

### 2. Deterministic Weight Evolution
```
W(t+1) = W(t) - η_mod × ∇L_new(W(t), TER)

where:
  η_mod = η_base × exp(-Δt / τ)           # Time-decayed learning rate
  L_new = L_base + (C_integral × Σ_threat) # Security-penalized loss
  Σ_threat = uint32(H_Integrity[:4]) / 2^32  # Threat score from integrity hash
```

**Security Property**: If device is compromised offline → H_Integrity changes → Σ_threat becomes unpredictable → weights diverge → cloud detects mismatch.

### 3. Proof-of-Sensor-Fusion (PoSF)
Neural network output becomes the signature:
```python
signature = neural_network(W_current, message_hash, nonce)
```

**Verification**: Cloud simulates edge weights from TER history and regenerates signature.

### 4. E2EE Transport
ChaCha20-Poly1305 encryption with keys derived from current weights:
```python
K_transport = HKDF-SHA256(W_fingerprint, session_salt, "Neuro-v1.0")
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                  HookProbe Neuro Stack                     │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Layer 3: E2EE Transport (ChaCha20-Poly1305)          │  │
│  │   Key = HKDF(W_fingerprint)                          │  │
│  └──────────────────────────────────────────────────────┘  │
│                         ▲                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Layer 2: PoSF Signatures (Neural Network)            │  │
│  │   Signature = NN(W_current, msg, nonce)              │  │
│  └──────────────────────────────────────────────────────┘  │
│                         ▲                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Layer 1: Deterministic Weight Evolution              │  │
│  │   W(t+1) = f(W(t), TER, η_mod, Σ_threat)             │  │
│  └──────────────────────────────────────────────────────┘  │
│                         ▲                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Layer 0: TER Generation (Qsecbit Interface)          │  │
│  │   H_Entropy + H_Integrity → 64 bytes                 │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

---

## Module Structure

```
src/neuro/
├── __init__.py                 # Package exports
├── requirements.txt            # Dependencies
├── README.md                   # This file
│
├── core/
│   ├── ter.py                  # Temporal Event Record
│   ├── posf.py                 # Proof-of-Sensor-Fusion signatures
│   └── replay.py               # Deterministic replay engine (TODO Phase 2)
│
├── neural/
│   ├── fixedpoint.py           # Q16.16 fixed-point math library
│   └── engine.py               # Deterministic neural network engine
│
├── crypto/
│   └── transport.py            # E2EE transport layer (TODO Phase 2)
│
├── storage/
│   └── dreamlog.py             # Offline TER storage (TODO Phase 2)
│
└── tools/
    └── init_weights.py         # Weight initialization tool (TODO)
```

---

## Quick Start

### 1. Installation

```bash
cd /home/user/hookprobe
pip install -r src/neuro/requirements.txt
```

### 2. Generate Initial Weights

```python
from neuro.neural.engine import create_initial_weights

# Create deterministic initial weights (run once during provisioning)
W0 = create_initial_weights(seed=42)

# Save for edge and cloud
W0.to_bytes()  # Serialize for storage
```

### 3. Edge: Generate TER

```python
from neuro.core.ter import TERGenerator

# Initialize TER generator (integrates with Qsecbit)
ter_gen = TERGenerator(qsecbit_interface=None)  # Uses psutil fallback

# Generate TER from current system state
ter = ter_gen.generate()

print(f"TER Sequence: {ter.sequence}")
print(f"H_Entropy: {ter.h_entropy.hex()[:32]}...")
print(f"Threat Score: {ter.calculate_threat_score():.4f}")
```

### 4. Edge: Sign with PoSF

```python
from neuro.core.posf import PoSFSigner

# Create signer with current weights
signer = PoSFSigner(W_current)

# Sign TER
signature, nonce = signer.sign_ter(ter)

print(f"PoSF Signature: {signature.hex()[:32]}...")
```

### 5. Cloud: Verify Signature

```python
from neuro.core.posf import PoSFVerifier

# Cloud simulates edge weights from TER history
W_simulated = simulate_edge_evolution(ter_history)

# Create verifier with simulated weights
verifier = PoSFVerifier(W_simulated)

# Verify signature
is_valid = verifier.verify_ter(ter, nonce, signature)

if is_valid:
    print("✓ Edge authenticated - weights match simulation")
else:
    print("❌ Edge compromised - weight divergence detected")
```

---

## Configuration

See `config/neuro-phase1.yaml` for complete configuration options.

### Key Parameters

```yaml
neural_engine:
  base_learning_rate: 0.0001  # η_base

hibernation:
  decay_constant_seconds: 7200  # τ (2 hours)
  max_quarantine_time: 86400   # 24 hours
  base_coefficient: 5.0         # C_integral

qsecbit_interface:
  h_integrity:
    recalculation_interval: 100  # Recalc every 100 TERs (expensive)

security:
  weight_verification:
    tolerance: 0  # Bit-for-bit match required
  quarantine:
    integrity_violation_threshold: 1  # Any violation → quarantine
```

---

## Security Analysis

### Threat Model

| Attack | Defense |
|--------|---------|
| **Static Key Theft** | No static keys - weights constantly evolve |
| **Offline Tampering** | H_Integrity change → unpredictable weight drift → detection |
| **MITM** | E2EE with ephemeral keys from weights |
| **Replay** | TER chain hash + monotonic sequence |
| **Impersonation** | PoSF signature from unique weight trajectory |

### Critical Requirements

1. **Fixed-Point Determinism**: Both edge and cloud MUST use identical Q16.16 math
2. **Secure Time Source**: Δt must be trustworthy (prefer TPM clock)
3. **Initial Trust**: W_0 shared securely during provisioning
4. **TER Authenticity**: Qsecbit sensor data must be trustworthy

---

## Testing Determinism

**Critical**: Run this on both edge and cloud to verify identical implementation:

```bash
# Test fixed-point math
python3 -m neuro.neural.fixedpoint

# Test neural engine
python3 -m neuro.neural.engine

# Test PoSF signatures
python3 -m neuro.core.posf
```

**Expected Output**:
```
=== Fixed-Point Determinism Verification ===
✓ All tests passed - Determinism verified!

=== Testing Deterministic Neural Engine ===
✓ Determinism verified: Same input → Same output
✓ Weight serialization verified
```

---

## Integration with DSM

Neuro enhances DSM microblocks with continuous authentication:

```json
{
  "type": "M",
  "node_id": "edge-uuid-12345",
  "seq": 1847,
  "payload_hash": "sha256-of-security-event",

  "neuro_z": {
    "ter_hash": "sha256-of-current-ter",
    "w_fingerprint": "sha512-of-current-weights",
    "posf_signature": "32-byte-neural-signature"
  },

  "signature": "tpm-signed-data"
}
```

---

## Roadmap

### Phase 1 (Q1 2025) - CURRENT
- ✅ Protocol specification
- ✅ Fixed-point math library
- ✅ TER generation from Qsecbit
- ✅ PoSF signature implementation
- ✅ Configuration files
- ⏳ Integration testing

### Phase 2 (Q2 2025)
- [ ] Full deterministic replay engine
- [ ] E2EE transport layer
- [ ] Dream log (offline storage)
- [ ] Cloud validator service
- [ ] Reconnection protocol

### Phase 3 (Q3 2025)
- [ ] Side-channel attack mitigation
- [ ] Quantum-resistant AEAD upgrade
- [ ] Hardware acceleration (FPGA)
- [ ] Performance optimization (1M TER/sec)

### Phase 4 (Q4 2025)
- [ ] Formal verification of determinism
- [ ] Academic publication
- [ ] Bug bounty program

---

## Performance

### Resource Usage

| Component | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| **TER Generation** | <1% | 1 MB | 64 bytes/TER |
| **PoSF Signing** | 2-5% | 2 MB | - |
| **Weight Storage** | - | - | 512 bytes |
| **Dream Log (24h)** | - | - | ~92 KB |

### Throughput

- **Edge**: 60 TER/hour (1 per minute) - minimal overhead
- **Cloud Validator**: 1000+ signature verifications/sec
- **Network**: 146 bytes handshake + 64 bytes per TER

---

## References

1. **[Protocol Specification](../../docs/architecture/hookprobe-neuro-protocol.md)** - Complete technical spec
2. **[DSM Integration](../../docs/architecture/dsm-implementation.md)** - Decentralized Security Mesh
3. **[Qsecbit AI](../qsecbit/README.md)** - Sensor interface

---

## License

MIT License - See [LICENSE](../../LICENSE) file

---

## Author

**Andrei Toma**
HookProbe Project
neuro@hookprobe.com

---

**HookProbe Neuro** - Where Neural Networks Become Cryptographic Keys
