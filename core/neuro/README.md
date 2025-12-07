# HookProbe Neuro Protocol

**Pillar 1 of HookProbe: Living Cryptography**

> *Where Neural Networks Become Cryptographic Keys*

**Full Documentation**: [../../docs/architecture/HOOKPROBE-ARCHITECTURE.md](../../docs/architecture/HOOKPROBE-ARCHITECTURE.md#neuro-protocol---living-cryptography)

## Quick Start

```python
from neuro.core.ter import TERGenerator
from neuro.core.posf import PoSFSigner
from neuro.neural.engine import create_initial_weights

# 1. Create initial weights (provisioning)
W0 = create_initial_weights(seed=42)

# 2. Generate TER from system state
ter_gen = TERGenerator()
ter = ter_gen.generate()

# 3. Sign with PoSF
signer = PoSFSigner(W0)
signature, nonce = signer.sign_ter(ter)
```

## Module Structure

- **`core/ter.py`**: Temporal Event Record - 64-byte sensor snapshots
- **`core/posf.py`**: Proof-of-Sensor-Fusion signatures
- **`core/replay.py`**: Deterministic replay engine
- **`neural/engine.py`**: Deterministic neural network engine
- **`neural/fixedpoint.py`**: Q16.16 fixed-point math library
- **`transport/htp.py`**: HookProbe Transport Protocol
- **`identity/hardware_fingerprint.py`**: Device identity without TPM
- **`storage/dreamlog.py`**: Offline TER storage

## Core Innovation

Traditional: *"Do you know the password?"*
**Neuro**: *"Can you prove your sensor history through deterministic weight evolution?"*

```
W(t+1) = W(t) - η_mod × ∇L(W(t), TER)

Security Property:
Compromise → H_Integrity changes → weight divergence → detection
```
