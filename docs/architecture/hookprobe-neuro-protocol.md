# HookProbe-Neuro Protocol Specification

**Version**: 1.0-alpha
**Status**: Phase 1 Implementation
**Last Updated**: 2025-11-26

---

## Executive Summary

**HookProbe-Neuro** introduces a revolutionary cryptographic protocol where **deterministic neural network weight evolution replaces traditional static keys** for continuous mutual authentication between Edge nodes and Cloud validators.

### Core Innovation

Instead of pre-shared keys or PKI, Neuro uses:
- **Temporal Event Records (TER)**: 64-byte sensor snapshots (entropy + integrity)
- **Deterministic Weight Evolution**: W(t+1) = f(W(t), TER, Δt) via fixed-point math
- **Proof-of-Sensor-Fusion (PoSF)**: Neural network output becomes the signature
- **Continuous Verification**: Cloud simulates edge weights and detects drift

**Security Property**: Any offline tampering → integrity hash change → unpredictable weight divergence → immediate detection.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Threat Model](#threat-model)
3. [Protocol Primitives](#protocol-primitives)
4. [Temporal Event Record (TER)](#temporal-event-record-ter)
5. [Deterministic Weight Evolution](#deterministic-weight-evolution)
6. [Proof-of-Sensor-Fusion (PoSF)](#proof-of-sensor-fusion-posf)
7. [E2EE Transport Layer](#e2ee-transport-layer)
8. [Hibernation & Offline Operation](#hibernation--offline-operation)
9. [Security Analysis](#security-analysis)
10. [Implementation Requirements](#implementation-requirements)
11. [Integration with DSM](#integration-with-dsm)

---

## Architecture Overview

### Three-Layer Security Model

```
┌──────────────────────────────────────────────────────────────────┐
│                  LAYER 3: E2EE TRANSPORT                          │
│  ChaCha20-Poly1305 with keys derived from neural weights         │
│  Key Material: K = HKDF-SHA256(W_fingerprint, salt, info)        │
└──────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Encrypts payload
                              │
┌──────────────────────────────────────────────────────────────────┐
│              LAYER 2: PROOF-OF-SENSOR-FUSION (PoSF)              │
│  Neural network L_X_SIG_07 output becomes signature              │
│  Signature = NN(W_current, TER_hash, nonce)                      │
│  Verification: Cloud simulates W_current and checks match        │
└──────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Uses current weights
                              │
┌──────────────────────────────────────────────────────────────────┐
│         LAYER 1: DETERMINISTIC WEIGHT EVOLUTION ENGINE           │
│  W(t+1) = W(t) + η_mod × ∇L(W, TER)                              │
│  η_mod = η_base × exp(-Δt / τ)                                   │
│  L_new = L_base + (C_integral × Σ_threat)                        │
│  Fixed-point math ensures bit-for-bit equivalence                │
└──────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Driven by TER
                              │
┌──────────────────────────────────────────────────────────────────┐
│           LAYER 0: TEMPORAL EVENT RECORD (TER) CAPTURE           │
│  H_Entropy (32 bytes): CPU, Memory, Network, Disk metrics        │
│  H_Integrity (20 bytes): Kernel, Binary, Config hashes           │
│  Timestamp: TPM-backed trusted time                              │
│  Chain_Hash: Previous TER hash (tamper detection)                │
└──────────────────────────────────────────────────────────────────┘
```

### Key Participants

| Role | Responsibility | Weight State |
|------|---------------|--------------|
| **Edge Node** | Collect TER, evolve weights locally, generate PoSF signatures | W_edge(t) |
| **Cloud Validator** | Simulate edge weight evolution from TER logs, verify PoSF | W_simulated(t) |
| **Qsecbit Interface** | Generate deterministic H_Entropy and H_Integrity from sensors | - |

---

## Threat Model

### Threats Mitigated

| Attack | Traditional Defense | Neuro Defense |
|--------|-------------------|---------------|
| **Static Key Theft** | Key rotation, HSM | No static keys - weights constantly evolve |
| **Offline Tampering** | TPM attestation | Integrity hash change → weight divergence → detection |
| **MITM** | TLS/WireGuard | E2EE with ephemeral keys from weights |
| **Replay Attack** | Nonces, timestamps | TER chain hash + monotonic sequence |
| **Impersonation** | Digital signatures | PoSF signature from unique weight trajectory |
| **Compromised Offline Device** | Manual re-provisioning | Automatic drift detection on reconnect |

### Assumptions

1. **Initial Trust**: Edge and Cloud share W_0 (initial weights) via secure provisioning
2. **Trusted Time**: Edge has access to monotonic time (ideally TPM clock)
3. **Qsecbit Integrity**: Sensor data collection (TER) is trustworthy
4. **Fixed-Point Determinism**: Both edge and cloud use identical math libraries
5. **TPM Availability**: Preferred but not required (software fallback available)

### Out-of-Scope

- Physical attacks on TPM chip (assumed hardware-secure)
- Side-channel attacks on neural weight computation (future work)
- Quantum computing attacks on ChaCha20 (future: quantum-resistant AEAD)

---

## Protocol Primitives

### 1. E2EE Configuration

```yaml
protocol:
  name: "HookProbe-Neuro"
  version: "1.0-alpha"
  max_handshake_mtu: 146  # bytes
  min_ter_rate_per_min: 10  # Minimum TER generation rate

e2ee_primitives:
  transport_aead:
    name: "ChaCha20-Poly1305"
    key_size_bits: 256
    nonce_size_bytes: 12
    tag_size_bytes: 16

  key_agreement:
    name: "Curve25519"
    key_size_bytes: 32

  hkdf:
    name: "HKDF-SHA256"
    hash_primitive: "SHA256"
    output_key_material_bytes: 32
```

### 2. Neural Network Architecture

```yaml
neural_engine:
  architecture: "FeedForward-FixedPoint-Micro"
  precision: "Q16.16"  # 16-bit integer, 16-bit fractional
  layers:
    - name: "L_INPUT"
      size: 64  # TER block size
      activation: "none"

    - name: "L_HIDDEN_1"
      size: 128
      activation: "ReLU-FP"  # Fixed-point ReLU

    - name: "L_HIDDEN_2"
      size: 64
      activation: "ReLU-FP"

    - name: "L_X_SIG_07"  # PoSF signing layer
      size: 32
      activation: "Sigmoid-FP"

  optimizer:
    type: "SGD-FixedPoint"
    base_learning_rate: 0.0001  # η_base
    momentum: 0.9
```

### 3. Qsecbit Interface Mapping

```yaml
qsecbit_interface:
  ter_block_size_bytes: 64

  components:
    h_entropy:
      size_bytes: 32
      source_metrics:
        - cpu_usage
        - memory_footprint
        - network_queue_depth
        - disk_io_wait
      derivation: "SHA256(cpu || mem || net || disk || timestamp)"

    h_integrity:
      size_bytes: 20
      source_metrics:
        - kernel_hash
        - core_binary_hash
        - config_file_hash
      derivation: "RIPEMD160(kernel_sha256 || binary_sha256 || config_sha256)"

    posf_signing_layer:
      layer_id: "L_X_SIG_07"
      output_size_bytes: 32
```

---

## Temporal Event Record (TER)

### Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                   Temporal Event Record (64 bytes)               │
├──────────────┬──────────────────────────────────────────────────┤
│ Field        │ Size   │ Description                             │
├──────────────┼────────┼─────────────────────────────────────────┤
│ H_Entropy    │ 32 B   │ SHA256 hash of system metrics           │
│ H_Integrity  │ 20 B   │ RIPEMD160 hash of critical files        │
│ Timestamp    │ 8 B    │ Unix timestamp (microseconds)           │
│ Sequence     │ 2 B    │ Monotonic sequence number               │
│ Chain_Hash   │ 2 B    │ CRC16 of previous TER (tamper detect)   │
├──────────────┴────────┴─────────────────────────────────────────┤
│ Total: 64 bytes (fits in single cache line)                     │
└─────────────────────────────────────────────────────────────────┘
```

### Generation Algorithm

```python
def generate_ter(qsecbit_state, prev_ter_hash):
    # 1. Collect system metrics
    cpu = qsecbit.get_cpu_usage()
    mem = qsecbit.get_memory_footprint()
    net = qsecbit.get_network_queue_depth()
    disk = qsecbit.get_disk_io_wait()
    timestamp = time.monotonic_ns() // 1000  # microseconds

    # 2. Derive H_Entropy (deterministic hash)
    entropy_data = struct.pack('<4f Q', cpu, mem, net, disk, timestamp)
    h_entropy = hashlib.sha256(entropy_data).digest()  # 32 bytes

    # 3. Derive H_Integrity
    kernel_hash = hashlib.sha256(open('/boot/vmlinuz', 'rb').read()).digest()
    binary_hash = hashlib.sha256(open('/usr/bin/hookprobe', 'rb').read()).digest()
    config_hash = hashlib.sha256(open('/etc/hookprobe/config.yaml', 'rb').read()).digest()

    integrity_data = kernel_hash + binary_hash + config_hash
    h_integrity = hashlib.new('ripemd160', integrity_data).digest()  # 20 bytes

    # 4. Build TER
    ter = TER(
        h_entropy=h_entropy,
        h_integrity=h_integrity,
        timestamp=timestamp,
        sequence=get_next_sequence(),
        chain_hash=crc16(prev_ter_hash)
    )

    return ter
```

### Security Properties

1. **Tamper Detection**: Chain_Hash links TER sequence
2. **Replay Prevention**: Monotonic sequence + timestamp
3. **Integrity Binding**: H_Integrity captures system state
4. **Deterministic**: Same system state → same TER (for simulation)

---

## Deterministic Weight Evolution

### Mathematical Framework

#### 1. Learning Rate Modulator (Time-Based Decay)

**Purpose**: Prevent unbounded weight drift during offline periods.

**Formula**:
```
η_mod = η_base × exp(-Δt / τ)

where:
  η_mod = modified learning rate
  η_base = base learning rate (0.0001)
  Δt = time since last TER (seconds)
  τ = decay constant (7200 seconds = 2 hours)
```

**Example**:
```
Δt = 0 seconds     → η_mod = 0.0001 × exp(0) = 0.0001 (100%)
Δt = 7200 seconds  → η_mod = 0.0001 × exp(-1) ≈ 0.000037 (37%)
Δt = 14400 seconds → η_mod = 0.0001 × exp(-2) ≈ 0.000014 (14%)
Δt = 86400 seconds → η_mod ≈ 0 (24 hours → negligible learning)
```

**Rationale**: If edge device is offline for 24 hours and gets compromised, learning rate decays to near-zero, preventing attacker from "training" the weights into a different state that cloud might accidentally simulate.

#### 2. Integrity Loss Coefficient (Security Penalty)

**Purpose**: Amplify weight changes when system integrity is violated.

**Formula**:
```
L_new = L_base + (C_integral × Σ_threat)

where:
  L_new = modified loss function
  L_base = base loss from H_Entropy input
  C_integral = integrity coefficient (5.0)
  Σ_threat = threat score from H_Integrity
```

**Threat Score Derivation**:
```python
def calculate_threat_score(h_integrity):
    """
    Convert H_Integrity hash to numerical threat score.
    Deterministic: same hash → same score.
    """
    # Take first 4 bytes of H_Integrity and interpret as uint32
    Σ_threat = struct.unpack('<I', h_integrity[:4])[0]

    # Normalize to [0, 1] range
    Σ_threat_normalized = Σ_threat / (2**32 - 1)

    return Σ_threat_normalized
```

**Security Property**: If attacker modifies kernel/binary/config while offline, H_Integrity changes drastically → Σ_threat becomes unpredictable → weights diverge unpredictably → cloud detects mismatch.

#### 3. Weight Update Rule

**Standard Gradient Descent** (fixed-point):
```
W(t+1) = W(t) - η_mod × ∇L_new(W(t), TER)

where:
  W(t) = current weights (Q16.16 fixed-point)
  ∇L_new = gradient of modified loss function
  η_mod = time-decayed learning rate
```

**Fixed-Point Implementation** (critical for determinism):
```c
// Q16.16 fixed-point format (32-bit total)
// 16 bits integer part, 16 bits fractional part
typedef int32_t fixed_point_t;

#define FP_SHIFT 16
#define FP_ONE (1 << FP_SHIFT)  // 1.0 in fixed-point

fixed_point_t fp_mul(fixed_point_t a, fixed_point_t b) {
    int64_t result = ((int64_t)a * (int64_t)b) >> FP_SHIFT;
    return (fixed_point_t)result;
}

fixed_point_t fp_div(fixed_point_t a, fixed_point_t b) {
    int64_t result = ((int64_t)a << FP_SHIFT) / b;
    return (fixed_point_t)result;
}

// Exponential approximation for learning rate decay
fixed_point_t fp_exp_approx(fixed_point_t x) {
    // Taylor series: exp(x) ≈ 1 + x + x²/2 + x³/6 + ...
    // Sufficient for -5 < x < 5 range
    fixed_point_t sum = FP_ONE;
    fixed_point_t term = FP_ONE;

    for (int i = 1; i <= 10; i++) {
        term = fp_mul(term, fp_div(x, i << FP_SHIFT));
        sum += term;
    }

    return sum;
}
```

### Deterministic Replay Algorithm

**Cloud Validator Simulation**:
```python
class DeterministicReplay:
    def __init__(self, W_initial, config):
        self.W = W_initial.copy()  # Fixed-point weights
        self.config = config
        self.ter_log = []

    def simulate_edge_evolution(self, ter_sequence):
        """
        Given TER sequence from edge, simulate weight evolution.
        Must produce bit-for-bit identical result to edge.
        """
        W_simulated = self.W.copy()

        for i, ter in enumerate(ter_sequence):
            # Calculate time delta
            if i == 0:
                Δt = 0
            else:
                Δt = (ter.timestamp - ter_sequence[i-1].timestamp) / 1e6  # seconds

            # Learning rate modulation (fixed-point)
            η_mod = self._calculate_learning_rate(Δt)

            # Threat score from integrity hash
            Σ_threat = self._calculate_threat_score(ter.h_integrity)

            # Modified loss
            L_base = self._forward_pass(W_simulated, ter.h_entropy)
            L_new = L_base + (self.config.C_integral * Σ_threat)

            # Gradient (fixed-point backprop)
            ∇L = self._backward_pass(W_simulated, ter.h_entropy, L_new)

            # Weight update (fixed-point)
            W_simulated = self._update_weights(W_simulated, ∇L, η_mod)

        return W_simulated

    def verify_edge_weights(self, W_edge, ter_sequence):
        """
        Verify edge weights match simulated evolution.
        """
        W_simulated = self.simulate_edge_evolution(ter_sequence)

        # Bit-for-bit comparison (no tolerance)
        return np.array_equal(W_edge, W_simulated)
```

---

## Proof-of-Sensor-Fusion (PoSF)

### Concept

Instead of traditional digital signatures (RSA, ECDSA), use the **neural network output itself as the signature**. Security derives from the infeasibility of forging exact fixed-point weight states.

### Signature Generation

```python
def generate_posf_signature(W_current, message_hash, nonce):
    """
    Generate PoSF signature using neural network.

    Args:
        W_current: Current weight state (fixed-point)
        message_hash: SHA256 hash of message to sign
        nonce: Random 8-byte nonce

    Returns:
        32-byte PoSF signature from L_X_SIG_07 layer output
    """
    # Combine message and nonce
    input_vector = np.concatenate([
        np.frombuffer(message_hash, dtype=np.uint8),  # 32 bytes
        np.frombuffer(nonce, dtype=np.uint8),         # 8 bytes
        np.zeros(24, dtype=np.uint8)                  # Padding to 64 bytes
    ])

    # Convert to fixed-point
    input_fp = (input_vector.astype(np.int32) << FP_SHIFT) // 255

    # Forward pass through neural network
    signature = neural_network_forward(W_current, input_fp, output_layer="L_X_SIG_07")

    # Convert 32 fixed-point outputs to bytes
    signature_bytes = np.array([fp_to_byte(s) for s in signature], dtype=np.uint8)

    return signature_bytes
```

### Signature Verification

```python
def verify_posf_signature(W_expected, message_hash, nonce, signature):
    """
    Verify PoSF signature.

    Cloud validator uses W_expected (simulated from TER logs).
    """
    # Regenerate signature using expected weights
    signature_expected = generate_posf_signature(W_expected, message_hash, nonce)

    # Bit-for-bit comparison
    return np.array_equal(signature, signature_expected)
```

### Security Analysis

**Attack Scenario**: Attacker tries to forge signature without knowing W_current

**Defense**:
1. Attacker must know exact fixed-point weight state (512 bytes = 4096 bits)
2. Weight state is result of entire TER history (path-dependent)
3. Even 1-bit difference in weights → completely different signature
4. Brute-forcing 2^4096 weight states is computationally infeasible

**Advantages over RSA/ECDSA**:
- No separate key management (weights are the key)
- Continuous authentication (weights evolve, not static)
- Tamper-evident (weight divergence is immediately visible)
- Quantum-resistant (no discrete log or factoring)

**Limitation**:
- Requires deterministic replay capability (cloud must simulate edge evolution)
- Larger "signature" size (32 bytes vs 64 bytes for ECDSA)

---

## E2EE Transport Layer

### Key Derivation from Neural Weights

```python
def derive_transport_key(W_current, session_id, direction):
    """
    Derive ChaCha20-Poly1305 key from current weight state.

    Args:
        W_current: Current neural weights (fixed-point)
        session_id: Unique session identifier
        direction: 'edge_to_cloud' or 'cloud_to_edge'

    Returns:
        32-byte encryption key
    """
    # Create weight fingerprint (512 bytes → 64 bytes via SHA512)
    W_bytes = W_current.tobytes()
    W_fingerprint = hashlib.sha512(W_bytes).digest()

    # HKDF key derivation
    salt = hashlib.sha256(session_id).digest()
    info = f"HookProbe-Neuro-v1.0-{direction}".encode()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    )

    transport_key = hkdf.derive(W_fingerprint)

    return transport_key
```

### Handshake Protocol

```
Edge                                                 Cloud
  │                                                    │
  │ ─────── (1) CLIENT_HELLO ───────────────────────► │
  │   [node_id, nonce_edge, W_fingerprint_edge]       │
  │                                                    │
  │ ◄────── (2) SERVER_HELLO ────────────────────────  │
  │   [validator_id, nonce_cloud, W_fingerprint_cloud] │
  │                                                    │
  │ ──────── (3) KEY_EXCHANGE ──────────────────────► │
  │   [Curve25519_pubkey_edge, PoSF_sig_edge]         │
  │                                                    │
  │ ◄─────── (4) KEY_CONFIRM ────────────────────────  │
  │   [Curve25519_pubkey_cloud, PoSF_sig_cloud]       │
  │                                                    │
  │ ── (5) Both derive shared secret via ECDH ──────  │
  │   K_shared = ECDH(privkey_self, pubkey_peer)      │
  │   K_transport = HKDF(K_shared || W_edge || W_cloud)│
  │                                                    │
  │ ◄══════ (6) Encrypted channel established ═══════► │
  │   ChaCha20-Poly1305(K_transport, nonce, message)  │
```

### Message Encryption

```python
def encrypt_message(plaintext, W_current, session_id):
    """
    Encrypt message using ChaCha20-Poly1305 with key from weights.
    """
    # Derive key from current weight state
    key = derive_transport_key(W_current, session_id, 'edge_to_cloud')

    # Generate nonce (12 bytes)
    nonce = os.urandom(12)

    # Encrypt with AEAD
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)

    # Return nonce + ciphertext + tag
    return nonce + ciphertext
```

---

## Hibernation & Offline Operation

### Hibernation Logic

When edge node goes offline, it continues collecting TER logs locally.

**Configuration**:
```yaml
hibernation:
  max_quarantine_time: 86400  # 24 hours

  learning_rate_modulator_formula:
    base_rate: 0.0001
    decay_constant_seconds: 7200  # 2 hours

  integrity_loss_coefficient_formula:
    base_coefficient: 5.0
```

### Dream Log (Offline TER Storage)

```python
class DreamLog:
    """
    Stores TER sequence while offline for later replay verification.
    """
    def __init__(self, storage_path):
        self.storage_path = storage_path
        self.ter_sequence = []

    def append_ter(self, ter):
        """Append TER to offline log."""
        self.ter_sequence.append(ter)
        self._persist_to_disk(ter)

    def get_replay_sequence(self):
        """Return TER sequence for cloud verification."""
        return self.ter_sequence

    def clear_after_sync(self):
        """Clear dream log after successful cloud sync."""
        self.ter_sequence = []
        os.remove(self.storage_path)
```

### Reconnection Protocol

```
Edge (after 8 hours offline)                         Cloud
  │                                                    │
  │ ───── (1) RECONNECT_REQUEST ────────────────────► │
  │   [node_id, last_sync_timestamp, ter_count]       │
  │                                                    │
  │ ◄──── (2) CHALLENGE_REPLAY ─────────────────────  │
  │   [nonce_cloud, "send_dream_log"]                 │
  │                                                    │
  │ ───── (3) DREAM_LOG_UPLOAD ─────────────────────► │
  │   [ter_sequence (compressed), W_current_edge]     │
  │                                                    │
  │ ── (4) Cloud simulates W from ter_sequence ─────  │
  │   W_simulated = simulate_evolution(ter_sequence)  │
  │   match = (W_simulated == W_current_edge)         │
  │                                                    │
  │ ◄──── (5) VERIFICATION_RESULT ──────────────────  │
  │   IF match:   "AUTHENTICATED"                     │
  │   IF mismatch: "QUARANTINE - INTEGRITY_FAILURE"   │
  │                                                    │
  │ ══════ (6) Resume encrypted channel ═════════════►│
```

### Quarantine Logic

```python
def verify_hibernation_integrity(ter_sequence, W_edge, W_cloud_last_known):
    """
    Verify edge node wasn't compromised during offline period.
    """
    # Simulate edge weight evolution from cloud's last known state
    W_simulated = simulate_edge_evolution(W_cloud_last_known, ter_sequence)

    # Compare simulated vs reported weights
    if np.array_equal(W_simulated, W_edge):
        return "AUTHENTICATED"

    # Calculate divergence magnitude
    divergence = np.linalg.norm(W_simulated - W_edge)

    # Check if divergence is consistent with integrity violation
    integrity_violations = count_integrity_hash_changes(ter_sequence)

    if integrity_violations > 0:
        return f"QUARANTINE - INTEGRITY_FAILURE ({integrity_violations} violations)"
    else:
        return f"QUARANTINE - UNEXPLAINED_DRIFT (divergence: {divergence})"
```

---

## Security Analysis

### Threat Scenarios

#### 1. Offline Device Compromise

**Attack**: Attacker gains physical access to edge device while offline, modifies kernel.

**Detection**:
1. Modified kernel → H_Integrity changes
2. H_Integrity change → Σ_threat spikes to unpredictable value
3. Σ_threat spike → L_new = L_base + (5.0 × Σ_threat) becomes large
4. Large loss → large weight updates
5. Weight trajectory diverges from cloud simulation
6. On reconnect, cloud detects W_edge ≠ W_simulated → QUARANTINE

**Example**:
```
Before compromise: H_Integrity = 0xA1B2C3... → Σ_threat = 0.12
After compromise:  H_Integrity = 0x7F8E9D... → Σ_threat = 0.89
Weight divergence: ||W_edge - W_simulated|| > 1000 (detected)
```

#### 2. TER Forgery Attack

**Attack**: Attacker tries to forge "clean" TER logs to hide compromise.

**Defense**:
1. **Chain Hash**: Each TER includes CRC16 of previous TER
2. **Sequence Numbers**: Monotonic, gap detection
3. **Timestamp Validation**: Cloud checks for anomalies (time jumps, too-fast generation)
4. **Statistical Analysis**: Cloud analyzes TER distribution for anomalies

**Detection Example**:
```python
def detect_ter_forgery(ter_sequence):
    # Check chain integrity
    for i in range(1, len(ter_sequence)):
        expected_chain_hash = crc16(ter_sequence[i-1].to_bytes())
        if ter_sequence[i].chain_hash != expected_chain_hash:
            return "CHAIN_BREAK_DETECTED"

    # Check timestamp monotonicity
    for i in range(1, len(ter_sequence)):
        Δt = ter_sequence[i].timestamp - ter_sequence[i-1].timestamp
        if Δt < 0 or Δt > 3600e6:  # Negative or > 1 hour gap
            return "TIMESTAMP_ANOMALY"

    # Statistical entropy check (H_Entropy should have high entropy)
    entropy_values = [calculate_entropy(ter.h_entropy) for ter in ter_sequence]
    avg_entropy = np.mean(entropy_values)
    if avg_entropy < 7.0:  # Too low for SHA256 output
        return "LOW_ENTROPY_DETECTED"

    return "VALID"
```

#### 3. Rollback Attack

**Attack**: Attacker replays old TER sequence with old weights.

**Defense**:
1. Cloud maintains `last_known_sequence` per edge node
2. Reject any TER with sequence ≤ last_known_sequence
3. Reject any timestamp earlier than last sync

#### 4. Side-Channel Attacks

**Potential Attack**: Power analysis during neural network weight computation.

**Mitigation** (Future Work):
- Constant-time fixed-point operations
- Noise injection during weight updates
- TPM-backed secure computation (if available)

---

## Implementation Requirements

### Fixed-Point Math Library

**Critical**: Must use **identical** fixed-point implementation on edge and cloud.

**Recommended**: Q16.16 format (16-bit integer, 16-bit fractional)

**Test Vectors**:
```python
# These must produce identical results on all platforms
assert fp_mul(1.5, 2.0) == 3.0
assert fp_div(5.0, 2.0) == 2.5
assert fp_exp(-1.0) ≈ 0.367879 (within 1e-6)
```

### Neural Network Implementation

**Requirements**:
- Fixed-point forward pass (no floating-point)
- Fixed-point backpropagation
- Deterministic ReLU, Sigmoid (fixed-point approximations)
- Identical weight initialization on edge and cloud

**Reference Implementation**: `/src/neuro/neural_engine_fp.c`

### Time Synchronization

**Edge Requirements**:
1. Monotonic clock access: `clock_gettime(CLOCK_MONOTONIC, ...)`
2. TPM clock (if available): `TPM2_ReadClock()`
3. Fallback: NTP sync with 1-second tolerance

**Cloud Requirements**:
1. Accept TER with ±5 second timestamp tolerance
2. Detect and flag excessive clock drift

### Storage Requirements

**Edge Node**:
- Dream Log: 64 bytes/TER × 60 TER/hour × 24 hours = 92 KB/day
- Weight State: 512 bytes (fixed-point)
- Total: ~100 KB for 24-hour offline operation

**Cloud Validator**:
- TER Archive: 64 bytes/TER × N edges × 60 TER/hour × 24 hours
- For 1000 edges: 1000 × 92 KB = 92 MB/day
- Recommended retention: 30 days = 2.76 GB

---

## Integration with DSM

### DSM Microblock Enhancement

Add Neuro authentication to DSM microblocks:

```json
{
  "type": "M",
  "node_id": "edge-uuid-12345",
  "seq": 1847,
  "prev": "hash-of-previous-microblock",
  "timestamp": "2025-11-26T18:35:00Z",
  "payload_hash": "sha256-of-security-event",
  "event_type": "ids_alert",

  "neuro_z": {
    "ter_hash": "sha256-of-current-ter",
    "w_fingerprint": "sha512-of-current-weights",
    "posf_signature": "32-byte-neural-signature"
  },

  "signature": "tpm-signed-data"
}
```

### Validator Checkpoint Enhancement

```json
{
  "type": "C",
  "epoch": 147,
  "timestamp": "2025-11-26T18:40:00Z",
  "merkle_root": "root-of-all-microblocks-in-epoch",

  "neuro_z_verification": {
    "verified_edges": ["edge-uuid-12345", "edge-uuid-67890"],
    "quarantined_edges": [],
    "total_ter_replayed": 1847,
    "avg_weight_divergence": 0.0023
  },

  "validator_id": "validator-uuid-001",
  "signature": "tpm-signed-checkpoint",
  "agg_signature": "bls-aggregated-sig-from-quorum"
}
```

### Integration Flow

```
POD-006 (Detection)          Neuro Engine          POD-010 (DSM)
        │                          │                       │
        │── Security Event ───────►│                       │
        │                          │                       │
        │                      Generate TER                │
        │                      Update Weights              │
        │                      Create PoSF                 │
        │                          │                       │
        │                          │──── Microblock ──────►│
        │                          │    (with Neuro auth) │
        │                          │                       │
        │                          │                   Gossip to
        │                          │                   validators
        │                          │                       │
```

---

## Deployment Guide

### Phase 1: Core Components

```bash
# Install Neuro protocol
cd /opt/hookprobe
pip install -r src/neuro/requirements.txt

# Initialize neural weights (first-time setup)
python3 -m neuro.tools.init_weights --node-id edge-001 --output /var/lib/hookprobe/neuro/W_initial.bin

# Start Neuro daemon
systemctl start hookprobe-neuro

# Verify TER generation
journalctl -u hookprobe-neuro -f | grep "TER_GENERATED"
```

### Phase 2: Cloud Validator Setup

```bash
# Configure cloud validator
export NEURO_Z_ROLE=validator
export NEURO_Z_STORAGE=/data/hookprobe/neuro/ter_archive

# Start replay simulation engine
systemctl start hookprobe-neuro-validator

# Monitor edge verifications
curl http://localhost:8080/neuro/status
```

---

## Roadmap

### Phase 1 (Q1 2025) - CURRENT
- ✅ Protocol specification
- ✅ Fixed-point math library
- ✅ TER generation from Qsecbit
- ✅ Basic PoSF implementation
- ✅ Dream log storage

### Phase 2 (Q2 2025)
- [ ] Full deterministic replay engine
- [ ] Cloud validator integration
- [ ] Reconnection protocol implementation
- [ ] Integration with DSM microblocks

### Phase 3 (Q3 2025)
- [ ] Side-channel attack mitigation
- [ ] Quantum-resistant AEAD upgrade
- [ ] Hardware acceleration (FPGA/ASIC)
- [ ] Performance optimization (1M TER/sec)

### Phase 4 (Q4 2025)
- [ ] Formal verification of determinism
- [ ] Academic publication
- [ ] Open-source release
- [ ] Bug bounty program

---

## References

1. **Neural Network Cryptography**: "CryptoNets" (Microsoft Research, 2016)
2. **Deterministic ML**: "Reproducibility in Machine Learning" (NeurIPS, 2019)
3. **Fixed-Point Neural Networks**: "FixyNN" (IEEE, 2020)
4. **Proof-of-Useful-Work**: Ethereum Casper FFG
5. **Hardware Root of Trust**: TCG TPM 2.0 Specification

---

## Contributors

- **Andrei Toma** - Protocol Design, Architecture
- **HookProbe Team** - Implementation, Testing

---

**HookProbe-Neuro Protocol v1.0-alpha**
*Where Neural Networks Become Cryptographic Keys*

---
