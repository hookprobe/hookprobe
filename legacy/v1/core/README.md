# HookProbe Core Intelligence

The `core/` directory contains HookProbe's proprietary security intelligence modules.

## Modules

### HTP - HookProbe Transport Protocol
**Location**: `htp/`

Secure, keyless transport with post-quantum cryptography.

- `transport/htp.py` - Main HTP implementation
- `transport/htp_vpn.py` - VPN integration
- `transport/htp_file.py` - File transfer protocol
- `crypto/hybrid_kem.py` - Kyber post-quantum crypto
- `crypto/transport.py` - ChaCha20-Poly1305 encryption

**Key Features**:
- Keyless authentication via entropy echo
- Post-quantum Kyber KEM
- Adaptive streaming
- VPN integration

### Qsecbit - Quantified Security Metric
**Location**: `qsecbit/`

The brain of HookProbe's threat detection.

- `qsecbit.py` - Main orchestrator (RAG scoring)
- `qsecbit-agent.py` - Agent daemon
- `energy_monitor.py` - RAPL power monitoring
- `xdp_manager.py` - XDP/eBPF DDoS mitigation
- `nic_detector.py` - NIC capability detection
- `gdpr_privacy.py` - Privacy-preserving module

**RAG Status**:
| Status | Range | Meaning |
|--------|-------|---------|
| GREEN | < 0.45 | Normal |
| AMBER | 0.45-0.70 | Warning |
| RED | > 0.70 | Critical |

### Neuro - Neural Resonance Protocol
**Location**: `neuro/`

Living cryptography where neural networks become keys.

- `core/ter.py` - Telemetry Event Record
- `core/posf.py` - Proof of Secure Function
- `neural/engine.py` - Weight evolution
- `attestation/device_identity.py` - Device attestation
- `identity/hardware_fingerprint.py` - Hardware fingerprinting

**Core Innovation**:
```
Traditional: "Do you know the password?"
Neuro: "Can you prove your sensor history through weight evolution?"
```

## Licensing

The modules in this directory are **proprietary** and require a commercial license for SaaS/OEM use. See `LICENSING.md` in the project root for details.

For personal/home use and internal business protection, these modules are free to use under the dual license terms.
