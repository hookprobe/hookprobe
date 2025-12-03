# HookProbe Source Code

<p align="center">
  <strong>The Future of Cybersecurity</strong><br>
  <em>Neural Resonance · Decentralized Mesh · Surgical Precision</em>
</p>

**Enterprise-Grade AI Security for $150 · Democratizing Cybersecurity for Millions**

---

## The Three Pillars

This directory contains the core implementations of HookProbe's revolutionary security architecture.

```
src/
├── neuro/      # Pillar 1: Neural Resonance Protocol
├── dsm/        # Pillar 2: Decentralized Security Mesh
├── qsecbit/    # Pillar 3: AI Resilience Metrics
├── response/   # Automated Threat Mitigation
└── web/        # Django Dashboard & APIs
```

---

## Pillar 1: Neural Resonance Protocol (`neuro/`)

**Living cryptography where neural network weights become your identity.**

Traditional authentication: *"Do you know the password?"*
Neural Resonance: *"Can you prove your sensor history through deterministic weight evolution?"*

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| **TER Generator** | `core/ter.py` | 64-byte sensor snapshots every 60 seconds |
| **Weight Engine** | `neural/engine.py` | Deterministic Q16.16 fixed-point evolution |
| **PoSF Signatures** | `core/posf.py` | Neural network output as cryptographic proof |
| **HTP Transport** | `transport/htp.py` | 9-message UDP protocol, quantum-resistant |

### The Algorithm

```python
# Weight Evolution (every 60 seconds)
W(t+1) = W(t) - η × ∇L(W, TER)

where:
    η = η_base × exp(-Δt / τ)     # Time-decayed learning rate
    L = L_base + C × Σ_threat     # Integrity penalty
```

**Why attackers can't win**: Tampering changes integrity hash → unpredictable weight divergence → instant detection on reconnect.

📖 **[Full Documentation →](neuro/README.md)**

---

## Pillar 2: Decentralized Security Mesh (`dsm/`)

**One brain powered by many edge nodes.**

Traditional SOC: One analyst watches 1000 networks (impossible).
DSM: 1000 nodes share intelligence instantly (unstoppable).

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| **DSM Node** | `node.py` | Edge node microblock creation |
| **Validator** | `validator.py` | Checkpoint creation and verification |
| **Consensus** | `consensus.py` | BLS signature aggregation (2/3 quorum) |
| **Gossip** | `gossip.py` | P2P threat announcement |

### Real Attack Scenario

```
T+00s: Home 1 detects C2 communication
T+05s: Creates microblock with PoSF signature
T+10s: Announces to mesh via gossip protocol
T+15s: Validators aggregate into checkpoint
T+20s: ALL mesh nodes block the threat

One node's detection → Everyone's protection
```

📖 **[Full Documentation →](dsm/README.md)**

---

## Pillar 3: Qsecbit AI (`qsecbit/`)

**Quantified cyber resilience, not binary detection.**

Traditional security: *"Are we under attack?"* (yes/no)
Qsecbit: *"How fast can we return to equilibrium?"* (0.0-1.0)

### The Formula

```python
Qsecbit = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly

# RAG Status
GREEN  (< 0.45):  Normal — learning baseline
AMBER  (0.45-0.70): Warning — auto-response triggered
RED    (> 0.70):  Critical — full mitigation deployed
```

### Energy-Based Attack Detection (v5.0)

```
DDoS Attack Pattern:
  ksoftirqd/0 power: 2.5W → 8.3W (Z-score: 4.2)
  → Qsecbit: 0.78 (RED)
  → XDP auto-deploys rate limiting
```

📖 **[Full Documentation →](qsecbit/README.md)**

---

## Automated Response (`response/`)

**Kali Linux on-demand for automated threat mitigation.**

When Qsecbit detects a threat (AMBER/RED):

1. Spin up Kali container (on-demand)
2. Analyze threat with appropriate tools
3. Implement countermeasures (WAF, firewall, forensics)
4. Shut down when threat cleared

| Threat | Response |
|--------|----------|
| **XSS** | Update WAF rules, block IP |
| **SQLi** | DB snapshot, update WAF |
| **DDoS** | XDP filtering, rate limiting |
| **Memory overflow** | Capture diagnostics, safe restart |

📖 **[Full Documentation →](response/README.md)**

---

## Web Application (`web/`)

**Django-powered dashboard and APIs** (optional addon).

- **Public CMS**: Forty HTML5 theme
- **Admin Dashboard**: AdminLTE system management
- **MSSP Portal**: Multi-tenant device management
- **REST APIs**: Device registration, security events

📖 **[Full Documentation →](web/README.md)**

---

## Quick Start

### Development Environment

```bash
# Create virtual environment
python3 -m venv venv && source venv/bin/activate

# Install all dependencies
pip install -r src/neuro/requirements.txt
pip install -r src/qsecbit/requirements.txt
pip install -r src/web/requirements.txt

# Test Neuro Protocol
python3 -m neuro.core.ter       # TER generation
python3 -m neuro.neural.engine  # Weight evolution
python3 -m neuro.core.posf      # PoSF signatures
```

### Production Deployment

```bash
# Full installation
sudo ./install.sh --role edge

# Initialize Neuro weights
python3 -m neuro.tools.init_weights --node-id edge-001

# Start services
sudo systemctl start hookprobe-edge hookprobe-neuro
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HOOKPROBE STACK                           │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4: DSM Consensus (BLS signatures, 2/3 quorum)        │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: Neural Resonance (TER → Weight → PoSF)            │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: Qsecbit AI (Resilience metrics, auto-response)    │
├─────────────────────────────────────────────────────────────┤
│  LAYER 1: Detection (XDP/eBPF, Suricata, Zeek, Snort3)      │
└─────────────────────────────────────────────────────────────┘
```

---

## Performance

| Component | CPU | RAM | Throughput |
|-----------|-----|-----|------------|
| **Neuro** | <1% | 2MB | 60 TER/hour |
| **Qsecbit** | 5-15% | 500MB | 10K events/sec |
| **XDP** | 5-10% | 1MB | 2.5 Gbps line-rate |
| **Response** | 0% idle | 0MB idle | On-demand |

---

## Documentation

| Module | Technical Spec | Architecture |
|--------|----------------|--------------|
| **Neuro** | [neuro/README.md](neuro/README.md) | [Protocol Spec](../docs/architecture/hookprobe-neuro-protocol.md) |
| **DSM** | [dsm/README.md](dsm/README.md) | [Whitepaper](../docs/architecture/dsm-whitepaper.md) |
| **Qsecbit** | [qsecbit/README.md](qsecbit/README.md) | [Security Model](../docs/architecture/security-model.md) |
| **HTP** | [neuro/transport/](neuro/transport/) | [Quantum Analysis](../docs/HTP_QUANTUM_CRYPTOGRAPHY.md) |

---

## License

**MIT License** — All source code components.

---

**HookProbe** · Neural Resonance · Decentralized Mesh · Surgical Precision

*Democratizing enterprise-grade cybersecurity for millions*
