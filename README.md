<p align="center">
  <img src="assets/hookprobe-logo.svg" alt="HookProbe Logo" width="400"/>
</p>

<p align="center">
  <strong>The Future of Cybersecurity</strong><br>
  <em>Neural Resonance · Decentralized Mesh · Surgical Precision</em>
</p>

<p align="center">
  <img src="assets/hookprobe-future-ram-cine.png" alt="Future of Cybersecurity" width="600"/>
</p>

<p align="center">
  <strong>Enterprise-Grade AI Security for $150 · Democratizing Cybersecurity for Millions</strong>
</p>

---

## 🧠 The Paradigm Shift

**Traditional cybersecurity is broken.** Static keys get stolen. Centralized SOCs fail. Enterprise solutions cost millions. The modern distributed world needs a fundamentally different approach.

**HookProbe introduces the world's first Neurosurgical Cybersecurity Platform** — where cryptography meets neuroscience, creating a living, learning, self-healing security mesh powered by:

- 🧬 **Neuro Protocol**: Neural networks **become** the cryptographic keys
- 🌐 **Decentralized Security Mesh (DSM)**: Byzantine fault-tolerant distributed SOC
- 🎯 **Qsecbit AI**: Resilience metrics that quantify attack-defense equilibrium
- 💰 **$150 Hardware**: Raspberry Pi delivers enterprise capabilities

**This is not incremental improvement. This is the evolution of cybersecurity from static defense to living organism.**

---

## 🔬 The Neurosurgical Approach

### What is Neurosurgical Cybersecurity?

Traditional security operates like **medieval fortifications** — static walls that eventually crumble.

**HookProbe operates like a neural system** — dynamic, adaptive, self-healing:

```
Traditional Security          HookProbe Neuro Security
┌──────────────┐              ┌──────────────────────────┐
│ Static Keys  │              │ Living Neural Weights    │
│ Gets Stolen  │              │ Evolve Continuously      │
├──────────────┤              ├──────────────────────────┤
│ Manual SOC   │              │ AI Autonomous Response   │
│ Hours/Days   │    VS.       │ Sub-30 Second            │
├──────────────┤              ├──────────────────────────┤
│ Centralized  │              │ Decentralized Mesh       │
│ Single Fail  │              │ Byzantine Tolerant       │
├──────────────┤              ├──────────────────────────┤
│ $100K+ Cost  │              │ $150 Edge Nodes          │
│ Enterprise   │              │ Everyone                 │
└──────────────┘              └──────────────────────────┘
```

**Key Insight**: Your security system should **think, learn, and heal like a nervous system**, not sit like a vault.

---

## 🌟 The Three Pillars of HookProbe

### 1. **Neuro Protocol** - Living Cryptography

**The world's first protocol where neural networks ARE the cryptographic keys.**

Instead of asking *"Do you still know the secret password?"*
**Neuro asks**: *"Can you prove your entire sensor history through weight evolution?"*

<details>
<summary><strong>🧬 How Neural Cryptography Works</strong></summary>

#### Temporal Event Records (TER)
Every minute, your edge node captures a 64-byte snapshot:
```
┌─────────────────────────────────────┐
│ H_Entropy (32B)                     │
│  CPU · Memory · Network · Disk      │
├─────────────────────────────────────┤
│ H_Integrity (20B)                   │
│  Kernel · Binary · Config Hashes    │
├─────────────────────────────────────┤
│ Timestamp · Sequence · Chain Hash   │
└─────────────────────────────────────┘
```

#### Weight Evolution Formula
```
W(t+1) = W(t) - η_mod × ∇L_new(W(t), TER)

where:
  η_mod = η_base × exp(-Δt / τ)           # Time decay during hibernation
  L_new = L_base + (C_integral × Σ_threat) # Security penalty for tampering
  Σ_threat = uint32(H_Integrity[:4]) / 2^32  # Unpredictable if compromised
```

#### The Security Magic
If an attacker compromises your device offline:
1. **Integrity hash changes** (kernel modified)
2. **Σ_threat becomes unpredictable** (was 0.12, now 0.89)
3. **Weights diverge unpredictably** (large random updates)
4. **Cloud detects mismatch** on reconnect
5. **Device QUARANTINED** immediately

**No static keys to steal. Tampering creates mathematical impossibility.**

📖 **[Neuro Protocol Specification →](docs/architecture/hookprobe-neuro-protocol.md)**

</details>

<details>
<summary><strong>🔐 Resonance Handshakes - The Neurosurgical Connection</strong></summary>

Traditional cryptography: **"Prove you know the key"**
**Neuro Protocol**: **"Prove our neural weights resonate"**

#### The Handshake
```
Edge                                Cloud Validator
 │                                   │
 │ "My weights evolved this way      │
 │  based on my sensor history"      │
 │                                   │
 │─── W_fingerprint + TER_log ──────►│
 │                                   │
 │                         Cloud simulates:
 │                         "If I replay your TER,
 │                          do I get same weights?"
 │                                   │
 │                         W_sim = replay(TER_log)
 │                         Match? → RESONATE ✓
 │                         Differ? → QUARANTINE ✗
 │                                   │
 │◄─── AUTHENTICATED / QUARANTINE ───│
```

#### Why "Resonance"?
Like neurons firing in sync, edge and cloud weights **must resonate perfectly**.

One bit of difference = **complete desynchronization** = **immediate detection**.

This is **quantum-level authentication** — you can't fake it, you can't replay it, you can't steal it.

📖 **[Resonance Mathematics →](src/neuro/README.md#proof-of-sensor-fusion-posf)**

</details>

---

### 1.5 **Liberty Transport Layer** - Simple, Secure Communication

**HookProbe Transport Protocol (HTP)** is our custom protocol designed specifically for edge-validator communication under NAT/CGNAT environments.

**Why NOT generic QUIC?** Because HookProbe needs **simple, auditable, unhackable** security. Generic protocols are complex and hard to audit.

<details>
<summary><strong>🔒 HTP Protocol Design</strong></summary>

#### The 9 Message Types
```
HELLO      → Edge initiates connection with weight fingerprint
CHALLENGE  → Validator sends nonce
ATTEST     → Edge signs nonce with device key
ACCEPT     → Validator approves, sends session secret
REJECT     → Validator denies connection
DATA       → Encrypted bidirectional communication
HEARTBEAT  → NAT keep-alive every 30 seconds
ACK        → Message acknowledgment
CLOSE      → Session termination
```

#### Connection Flow
```
Edge (behind NAT)               Validator (public IP)
 │                                   │
 │──HELLO (weight_fp + node_id)─────►│
 │                                   │ Checks MSSP registry
 │                                   │ Validates device exists
 │                                   │
 │◄─────CHALLENGE (nonce)────────────│
 │                                   │
 │ Sign: sig = Ed25519(nonce + fp)   │
 │                                   │
 │──ATTEST (signature)───────────────►│
 │                                   │ Verify signature
 │                                   │ Generate session_secret
 │                                   │
 │◄─────ACCEPT (session_secret)──────│
 │                                   │
 │ Derive ChaCha20 key:              │ Derive same key:
 │ k = SHA256(secret + weight_fp)    │ k = SHA256(secret + weight_fp)
 │                                   │
 │◄────DATA (encrypted)─────────────►│
 │                                   │
 │──HEARTBEAT (every 30s)───────────►│ Keeps NAT mapping alive
```

#### Security Properties
- **UDP-based**: Works through NAT/CGNAT
- **ChaCha20-Poly1305**: AEAD encryption (fast, secure)
- **Weight fingerprint binding**: Session key derived from neural weights
- **Ed25519 signatures**: Device authentication
- **Heartbeat protocol**: Maintains NAT mappings for long-lived sessions
- **Simple state machine**: Easy to audit = unhackable

📖 **[HTP Implementation →](src/neuro/transport/htp.py)**

</details>

---

### 1.6 **Liberty Device Identity** - Hardware Fingerprinting

**No TPM? No problem.** Liberty creates unique device fingerprints from stable hardware characteristics.

<details>
<summary><strong>🔧 Hardware Fingerprinting Without TPM</strong></summary>

#### What We Collect
```python
fingerprint_id = SHA256(
    cpu_id +           # CPU model/serial
    mac_addresses +    # Network interface MACs
    disk_serials +     # Storage device serials
    dmi_uuid +         # SMBIOS UUID
    hostname +         # System hostname
    timestamp          # Binding timestamp
)
```

#### Why This Works
- **Stable**: Hardware IDs don't change across reboots
- **Unique**: Combination creates device-specific fingerprint
- **Verifiable**: MSSP tracks all devices by fingerprint
- **Tolerance**: Verification allows 2 component changes (e.g., add NIC)

#### MSSP Device Registry
Every device in HookProbe network is tracked:
```
devices table:
  - device_id (unique identifier)
  - hardware_fingerprint (SHA256 hash)
  - public_key_ed25519 (device signing key)
  - status (PENDING → ACTIVE → SUSPENDED → REVOKED)
  - kyc_verified (for validators)
  - geolocation (IP-based tracking)

device_locations table:
  - device_id
  - timestamp
  - ip_address, country, region, city
  - latitude, longitude
  - asn, isp
```

#### Prerequisite Enforcement
```
Cannot deploy validator without MSSP cloud:

  ┌─────────────┐
  │ MSSP Cloud  │ ← Must exist first (device_type=CLOUD, status=ACTIVE)
  └──────┬──────┘
         │
    ┌────▼────┐
    │Validator│ ← Requires cloud + KYC verification
    └────┬────┘
         │
    ┌────▼────┐
    │  Edge   │ ← Can deploy anytime (auto-approve)
    └─────────┘
```

**Benefits**:
- ✅ Works on any device ($75 Raspberry Pi to $200 SBC)
- ✅ No special hardware required
- ✅ Tracks device location changes
- ✅ Enforces deployment order (cloud → validator → edge)
- ✅ KYC verification for validators (trust model)

📖 **[Hardware Fingerprinting →](src/neuro/identity/hardware_fingerprint.py)**
📖 **[MSSP Device Registry →](src/mssp/device_registry.py)**
📖 **[GeoIP Integration →](src/mssp/geolocation.py)**

</details>

---

### 2. **Decentralized Security Mesh (DSM)** - Collective Intelligence

**One brain powered by many edge nodes.**

Traditional SOC: One analyst tries to watch 1000 networks (impossible)
**HookProbe DSM**: 1000 nodes share intelligence instantly (unstoppable)

<details>
<summary><strong>🌐 The Mesh Architecture</strong></summary>

```
┌─────────────────────────────────────────────────────────┐
│              CONSENSUS LAYER (Cloud Validators)          │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐          │
│  │Validator │◄──►│Validator │◄──►│Validator │          │
│  │    1     │    │    2     │    │    3     │          │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘          │
│       │ BLS Signatures (Byzantine Fault Tolerant)       │
│       │ Requires 2/3 Quorum                             │
└───────┼──────────────┼──────────────┼──────────────────┘
        │              │              │
┌───────▼──────────────▼──────────────▼──────────────────┐
│              MESH LAYER (Edge Nodes)                    │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐    │
│  │Home 1│◄─┤Home 2│◄─┤SMB 1 │◄─┤SMB 2 │◄─┤Branch│    │
│  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘    │
│         Gossip Protocol - Instant Threat Sharing       │
└────────────────────────────────────────────────────────┘
        │              │              │
┌───────▼──────────────▼──────────────▼──────────────────┐
│           DETECTION LAYER (Local AI)                    │
│  Qsecbit + Suricata + Zeek + XDP/eBPF                  │
│  Autonomous Response in <30 seconds                     │
└────────────────────────────────────────────────────────┘
```

#### Real-World Example: C2 Detection
```
T+00s: Home 1 detects C2 communication (192.168.1.100)
       Qsecbit threat score: 0.92 (RED)

T+05s: Creates microblock with PoSF signature
       Announces to mesh via gossip protocol

T+10s: Validators aggregate into checkpoint
       BLS signature quorum (2/3 validators sign)

T+15s: Checkpoint finalized and broadcast
       ALL MESH NODES receive update

T+20s: Home 2, SMB 1, SMB 2, Branch ALL block 192.168.1.100
       Attack neutralized globally

One node's detection → Everyone's protection
```

📖 **[DSM Whitepaper →](docs/architecture/dsm-whitepaper.md)**
📖 **[DSM Implementation →](docs/architecture/dsm-implementation.md)**

</details>

---

### 3. **Qsecbit Algorithm** - The Resilience Metric

**Traditional security asks**: *"Are we under attack?"* (yes/no)
**Qsecbit asks**: *"How fast can we return to equilibrium?"* (quantified resilience)

<details>
<summary><strong>🎯 Beyond Detection: Measuring Cyber Resilience</strong></summary>

Qsecbit is **not just a threat detector** — it's a **resilience metric** that measures the smallest unit where AI-driven attack and defense reach equilibrium.

#### The Formula
```
Qsecbit = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly

where:
  drift        = Mahalanobis distance from baseline (system deviation)
  p_attack     = ML-predicted attack probability (0.0 - 1.0)
  decay        = Rate of classifier confidence change (degradation)
  q_drift      = System entropy deviation (chaos measure)
  energy_anomaly = Power consumption anomalies (NEW v5.0)
```

#### RAG Status (Red/Amber/Green)
```
┌─────────────────────────────────────────────────────┐
│ Qsecbit Score │ Status │ Action                     │
├───────────────┼────────┼────────────────────────────┤
│ < 0.45        │ GREEN  │ Normal - learning baseline │
│ 0.45 - 0.70   │ AMBER  │ Warning - auto-response    │
│ > 0.70        │ RED    │ Critical - full mitigation │
└─────────────────────────────────────────────────────┘
```

#### What Makes Qsecbit Revolutionary

**1. Convergence Rate Analysis**
How quickly does your system return to GREEN after an attack?
- **Fast convergence** = robust resilience
- **Slow convergence** = degrading defenses (early warning!)

**2. Energy-Based Anomaly Detection (v5.0)**
Detects attacks by **power consumption patterns**:
```
DDoS Attack Pattern:
  ksoftirqd/0 power: 2.5W → 8.3W (Z-score: 4.2)
  NIC interrupt:     1.2W → 5.1W (Z-score: 3.8)
  → Total spike: +262% → AMBER alert
  → XDP auto-deploys rate limiting
```

**3. Network Direction-Aware Efficiency**
```
Public Server (normal):  IN > OUT (0.6 ratio)
Public Server (DDoS):    IN >>> OUT (0.2 ratio) → DETECTED
Public Server (exfil):   OUT > IN (2.4 ratio) → DETECTED

User Endpoint (normal):  OUT > IN (1.8 ratio)
User Endpoint (botnet):  OUT >>> IN (8.5 ratio) → DETECTED
```

**4. XDP/eBPF Kernel-Level Mitigation**
Sub-microsecond packet filtering **before** network stack:
```
Intel I226 NIC (XDP-DRV mode):
  - 2.5 Gbps line rate filtering
  - <1 µs latency
  - 5-10% CPU usage
  - Blocks attacks at Layer 0 (NIC hardware)
```

#### Integration with Neuro Protocol
```
Qsecbit Score → H_Entropy (TER) → Neural Weight Evolution
                                    │
                                    ▼
                         Neuro weights capture
                         attack-defense dynamics
                                    │
                                    ▼
                         Cloud validates resilience
                         via deterministic replay
```

**Qsecbit + Neuro = Quantified, verifiable cyber resilience**

📖 **[Qsecbit Algorithm Details →](src/qsecbit/README.md)**

</details>

---

## 💡 Why This Changes Everything

### The Cost Revolution

```
Traditional Enterprise Security Stack
├── SIEM License:        $50,000/year
├── SOC Infrastructure:  $100,000
├── Managed Services:    $200,000/year
├── Incident Response:   $50,000/year
└── Total Year 1:        $400,000+

HookProbe Complete Stack
├── Edge Node (RPi 5):   $75 one-time
├── Cloud Validator:     $0 (optional self-host)
├── Software:            $0 (open source, MIT license)
├── Maintenance:         $0 (autonomous)
└── Total Year 1:        $75

Cost Reduction: 99.98%
```

### The Democratization Effect

**Before HookProbe**:
- Small businesses: Can't afford security ($200K+ minimum)
- Home users: Rely on basic antivirus (inadequate)
- Developing nations: No access to enterprise tools
- **Result**: 90% of the world is unprotected

**With HookProbe**:
- Small business: $150 edge node = full SOC capability
- Home user: Same $150 = same protection as Fortune 500
- Developing nations: Open source = free access to code
- **Result**: Enterprise security for everyone

**This is how we achieve cybersecurity for millions, not thousands.**

---

## 🚀 The Three Innovations That Make It Possible

### Innovation 1: Neural Cryptography (Neuro Protocol)

**No more static keys to steal.**

Your cryptographic "key" is the **deterministic evolution of neural network weights** driven by your unique sensor history.

- **Tamper-evident**: Any offline compromise causes mathematical divergence
- **Continuous authentication**: Not one-time login, ongoing resonance verification
- **Quantum-resistant**: No reliance on discrete log or factoring problems
- **Zero trust**: Even with physical access, attacker can't forge weight trajectory

**Technical breakthrough**: Proof-of-Sensor-Fusion (PoSF) signatures using neural network layer outputs instead of RSA/ECDSA.

### Innovation 2: Decentralized Consensus for Security Events

**No more single-point-of-failure SOC.**

Every security event becomes a cryptographically signed microblock. Validators aggregate into tamper-evident checkpoints with BLS signature quorum.

- **Byzantine fault tolerant**: Tolerates f=(n-1)/3 malicious nodes
- **Instant threat sharing**: One node's detection → all nodes' protection
- **Cryptographic audit trail**: Every decision is provable
- **Scales horizontally**: Add more validators = more resilience

**Technical breakthrough**: Applying blockchain-style consensus to security operations without the blockchain overhead.

### Innovation 3: AI-Driven Resilience Metrics

**No more "are we safe?" guessing.**

Qsecbit quantifies your **ability to absorb and recover from attacks**, not just detect them.

- **Convergence rate**: How fast you return to GREEN = resilience score
- **Energy anomalies**: Detect attacks by power consumption patterns
- **Self-learning**: Improves across entire mesh (your attacks train my defense)
- **Explainable**: Every Qsecbit score has mathematical justification

**Technical breakthrough**: Combining Mahalanobis distance, ML predictions, entropy analysis, and RAPL energy monitoring into unified resilience metric.

---

## 🎯 Real-World Impact

### Use Case: Home Network Protection

**The Problem**:
- IoT devices are security nightmares (cameras, smart TVs, etc.)
- Traditional solution: $50/month monitoring service
- **Cost over 5 years**: $3,000

**HookProbe Solution**:
- $75 Raspberry Pi 5 runs full edge stack
- Qsecbit monitors all devices with <30s response
- Neuro protocol ensures device hasn't been compromised
- DSM shares threats with global mesh
- **Cost over 5 years**: $75 (99.75% savings)

**Results**:
- 24/7 autonomous monitoring
- Enterprise-grade IDS/IPS (Suricata, Zeek, Snort3)
- AI threat analysis with explainable scores
- Participation in global threat intelligence mesh

### Use Case: Small Business (20 employees)

**The Problem**:
- Can't afford $100K+ enterprise SOC
- Rely on basic antivirus (inadequate for modern threats)
- No incident response capability
- **Risk**: One breach = business closure

**HookProbe Solution**:
- 2x edge nodes ($150 total) for redundancy
- 1x cloud validator (optional, self-hosted on existing server)
- Full SOC capabilities: detection, analysis, response
- DSM integration with global mesh
- **Total cost**: $150 + $0/month

**Results**:
- Sub-30 second threat response
- Cryptographic audit trail for compliance
- Global threat intelligence participation
- Same protection as Fortune 500 company

### Use Case: MSSP (Managed Security Service Provider)

**The Problem**:
- Scaling SOC operations is expensive
- Each customer needs dedicated infrastructure
- **Cost**: $500+/month per customer minimum

**HookProbe Solution**:
- Deploy $150 edge node at each customer site
- Centralized cloud validators (multi-tenant)
- DSM aggregates all customer intelligence
- Neuro protocol ensures device authenticity
- **Cost**: $150/customer one-time + cloud hosting

**Results**:
- 10x more customers on same infrastructure
- Automated threat response (reduce analyst workload)
- Cross-tenant threat intelligence (one customer's attack protects all)
- **Business model**: Offer enterprise security at $50/month (vs $500/month traditional)

---

## 🏗️ Architecture - The Complete Picture

**Liberty Architecture Philosophy**: Simple, yet effective. Robust, secure, unhackable.

Every component in HookProbe follows the **KISS principle** (Keep It Simple & Secure):
- HTP has 9 message types (vs QUIC's 100+)
- Hardware fingerprinting uses standard /proc /sys files (no proprietary TPM)
- MSSP registry is SQLite (proven, auditable, fast)
- All code is open source (anyone can audit = trust through transparency)

**Why simplicity matters**: Complex systems have more bugs. Simple systems are auditable. Auditable systems are unhackable.

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                   │
│                    HOOKPROBE ARCHITECTURE                         │
│         "Neurosurgical Precision · Decentralized Resilience"     │
│                                                                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │         LAYER 4: CONSENSUS & VALIDATION (Cloud)            │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │  │
│  │  │ Validator 1  │◄►│ Validator 2  │◄►│ Validator 3  │     │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘     │  │
│  │  · BLS Signature Aggregation (2/3 quorum)                 │  │
│  │  · Deterministic Replay (Neuro weight verification)       │  │
│  │  · Checkpoint Finalization                                │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              ▲                                    │
│                              │ Microblocks + TER Logs             │
│                              ▼                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │         LAYER 3: MESH INTELLIGENCE (P2P Network)           │  │
│  │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐        │  │
│  │  │Edge 1│◄─┤Edge 2│◄─┤Edge 3│◄─┤Edge N│◄─┤Cloud │        │  │
│  │  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘        │  │
│  │  · Gossip Protocol (threat announcement)                   │  │
│  │  · Neuro Resonance Handshakes                              │  │
│  │  · Global Threat Intelligence Sharing                      │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              ▲                                    │
│                              │ Security Events + Qsecbit Scores   │
│                              ▼                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │         LAYER 2: AI ANALYSIS & RESPONSE (Edge Node)        │  │
│  │  ┌────────────────────────────────────────────────────┐    │  │
│  │  │ Qsecbit AI Engine                                   │    │  │
│  │  │  · Resilience metric calculation (0.0 - 1.0)        │    │  │
│  │  │  · RAG status (Green/Amber/Red)                     │    │  │
│  │  │  · Convergence rate analysis                        │    │  │
│  │  │  · Energy anomaly detection (v5.0)                  │    │  │
│  │  └────────────────────────────────────────────────────┘    │  │
│  │  ┌────────────────────────────────────────────────────┐    │  │
│  │  │ Automated Response                                  │    │  │
│  │  │  · WAF rule injection (NAXSI)                       │    │  │
│  │  │  · Firewall updates (iptables/nftables)             │    │  │
│  │  │  · Rate limiting                                    │    │  │
│  │  │  · Kali Linux arsenal (on-demand)                   │    │  │
│  │  └────────────────────────────────────────────────────┘    │  │
│  │  ┌────────────────────────────────────────────────────┐    │  │
│  │  │ Neuro Protocol Engine                               │    │  │
│  │  │  · TER generation (every 60s)                       │    │  │
│  │  │  · Neural weight evolution                          │    │  │
│  │  │  · PoSF signature creation                          │    │  │
│  │  │  · Dream log (offline storage)                      │    │  │
│  │  └────────────────────────────────────────────────────┘    │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              ▲                                    │
│                              │ Raw Network Traffic                │
│                              ▼                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │         LAYER 1: DETECTION (Kernel/Hardware Level)         │  │
│  │  ┌────────────────────────────────────────────────────┐    │  │
│  │  │ XDP/eBPF (Kernel-Level Filtering)                  │    │  │
│  │  │  · Sub-microsecond packet decisions                │    │  │
│  │  │  · 2.5 Gbps line rate (Intel I226)                 │    │  │
│  │  │  · DDoS mitigation before network stack            │    │  │
│  │  └────────────────────────────────────────────────────┘    │  │
│  │  ┌────────────────────────────────────────────────────┐    │  │
│  │  │ IDS/IPS Engines                                     │    │  │
│  │  │  · Suricata (emerging threats)                      │    │  │
│  │  │  · Zeek (protocol analysis)                         │    │  │
│  │  │  · Snort3 (signature detection)                     │    │  │
│  │  └────────────────────────────────────────────────────┘    │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘

         When Attack Detected - The 30-Second Neurosurgical Response:

         T+00s: XDP/eBPF intercepts suspicious packet at NIC
         T+02s: Suricata/Zeek confirm threat signature
         T+05s: Qsecbit calculates resilience score: 0.85 (RED)
         T+08s: Auto-deploy mitigation (WAF + firewall + rate limit)
         T+10s: Generate TER with H_Integrity check
         T+12s: Create microblock with PoSF signature
         T+15s: Announce to mesh via gossip protocol
         T+18s: Neural weights evolve based on attack pattern
         T+20s: Validators aggregate into checkpoint
         T+25s: BLS quorum signs checkpoint (2/3 validators)
         T+28s: ALL mesh nodes receive threat update
         T+30s: Attack neutralized globally + intelligence shared
```

---

## 📦 Complete POD Architecture

| POD | Component | Purpose | Neuro Integration |
|-----|-----------|---------|-------------------|
| **001** | Web DMZ | Nginx, NAXSI WAF, Django | PoSF-authenticated API endpoints |
| **002** | IAM | Logto OAuth, SSO, RBAC | Neuro session keys for MFA |
| **003** | Database | PostgreSQL, RADIUS | Encrypted with Neuro-derived keys |
| **004** | Cache | Redis/Valkey | Session storage with PoSF auth |
| **005** | Monitoring | Grafana, ClickHouse, VictoriaMetrics | Qsecbit + Neuro metrics dashboards |
| **006** | Detection | Suricata, Zeek, Snort3, XDP | Feeds Qsecbit + TER generation |
| **007** | AI Response | Qsecbit, Kali, Auto-mitigation | Core resilience metrics engine |
| **008** | Automation | n8n, MCP Server, Workflows | AI agent orchestration |
| **009** | Email | Postfix, DKIM, Cloudflare Tunnel | Alert notifications |
| **010** | **DSM Ledger** | **Neuro Protocol + Microblocks** | **🔥 Neural cryptography core** |

📖 **[Complete POD Documentation →](docs/components/README.md)**

---

## 🚦 Quick Start

### Option 1: Edge Node (Home/SMB)

```bash
# Clone from GitHub
git clone https://github.com/hookprobe/hookprobe
cd hookprobe

# Install for edge deployment
sudo ./install.sh --role edge

# Initialize Neuro protocol
python3 -m neuro.tools.init_weights --node-id edge-001

# Start services
sudo systemctl start hookprobe-edge
sudo systemctl start hookprobe-neuro
```

### Option 2: Cloud Validator (MSSP)

**⚠️ PREREQUISITE**: MSSP Cloud must be deployed first. Validators cannot be installed without cloud infrastructure.

```bash
# Clone repository
git clone https://github.com/hookprobe/hookprobe
cd hookprobe

# Install validator (requires MSSP cloud deployed)
sudo ./install-validator.sh

# The script will:
# 1. Check MSSP cloud is deployed (strict prerequisite)
# 2. Validate hardware requirements (4+ cores, 8GB+ RAM)
# 3. Collect KYC information (organization, email, country)
# 4. Generate hardware fingerprint (no TPM required)
# 5. Register with MSSP (status: PENDING)
# 6. Generate Ed25519 device key
# 7. Wait for KYC approval before activation

# After KYC approval by MSSP admin:
sudo systemctl start hookprobe-validator
sudo systemctl start hookprobe-neuro-validator
```

### Verify Installation

```bash
# Check POD status
make status

# View Qsecbit scores
make metrics

# Check Neuro protocol health
python3 -m neuro.core.ter  # Test TER generation

# View DSM mesh connectivity
make dsm-status
```

📖 **[Complete Installation Guide →](docs/installation/INSTALLATION.md)**

---

## 🌐 Hardware Compatibility

### Recommended Edge Nodes

| Platform | CPU | RAM | Network | Storage | Price | Qsecbit Performance |
|----------|-----|-----|---------|---------|-------|---------------------|
| **Raspberry Pi 5** ⭐ | ARM Cortex-A76 (4 cores, 2.4 GHz) | 8GB | 1 Gbps | 256GB NVMe | $75 | ~500 Mbps, <100ms detection |
| **Intel N100** 🏆 | x86_64 (4 cores, 3.4 GHz) | 8-16GB | 2.5 Gbps (I226) | 512GB NVMe | $150 | ~2.5 Gbps, <50ms, XDP-DRV support |
| **Banana Pi M7** | Rockchip RK3588 | 16GB | 2.5 Gbps | 512GB NVMe | $200 | ~2.5 Gbps, <30ms |
| **NVIDIA Jetson Nano** | ARM + GPU | 4GB | 1 Gbps | 256GB NVMe | $99 | ~1 Gbps, <20ms (AI accelerated) |

**Winner for Most Users**: **Intel N100** — Best balance of performance, XDP support, and cost.

**Budget Option**: **Raspberry Pi 5** — Still delivers enterprise capabilities for $75.

### XDP/eBPF Support

**Critical for best performance**: Choose NIC with XDP-DRV support.

| NIC | Driver | XDP Mode | Throughput | HookProbe Performance |
|-----|--------|----------|------------|----------------------|
| Intel I226-V ⭐ | igc | **XDP-DRV** ✅ | 2.5 Gbps | Line-rate filtering, 5-10% CPU |
| Intel I211 | igb | **XDP-DRV** ✅ | 1 Gbps | Line-rate filtering, 8-12% CPU |
| Realtek r8169 | r8169 | XDP-SKB ❌ | 1 Gbps | Software mode, 25-30% CPU |
| Broadcom (RPi) | bcmgenet | XDP-SKB ❌ | 1 Gbps | Software mode, 25-30% CPU |

📖 **[Complete Hardware Guide →](docs/installation/INSTALLATION.md#hardware-requirements)**

---

## 📊 The Future: What We're Building

### Phase 1 (Q1 2025) - ✅ COMPLETE
- [x] Neuro protocol specification
- [x] Fixed-point deterministic neural engine
- [x] TER generation and validation
- [x] PoSF signatures
- [x] Qsecbit v5.0 with energy monitoring
- [x] DSM Phase 1 (microblocks, fallbacks)

### Phase 2 (Q2 2025) - ✅ COMPLETE
- [x] Deterministic replay engine
- [x] E2EE transport (ChaCha20-Poly1305)
- [x] Dream log (offline TER storage)
- [x] Neuro resonance handshakes
- [x] Cloud validator service

### Phase 3 (Q3 2025) - ✅ LIBERTY COMPLETE
- [x] **HookProbe Transport Protocol (HTP)** - Custom UDP protocol for NAT/CGNAT
- [x] **Hardware Fingerprinting** - Device identity without TPM
- [x] **MSSP Device Registry** - Centralized device tracking with geolocation
- [x] **Validator Install Script** - MSSP prerequisite enforcement + KYC
- [x] **GeoIP2 Integration** - MaxMind + IP-API geolocation service
- [x] **End-to-End HTP Tests** - Complete edge ↔ validator communication flow
- [x] **Complete Documentation** - Protocol spec, deployment guides, architecture docs

### Phase 4 (Q4 2025) - 🔄 IN PROGRESS
- [ ] Production MSSP deployment (hookprobe.com)
- [ ] First validator network (beta testing)
- [ ] Edge node beta program (10-50 nodes)
- [ ] Neuro + Qsecbit convergence analysis
- [ ] Performance benchmarking and optimization
- [ ] Security audit (internal)
- [ ] Community building and outreach

### Phase 5 (Q1 2026) - PRODUCTION LAUNCH
- [ ] Public MSSP cloud launch
- [ ] Validator onboarding program (KYC workflow)
- [ ] Edge node general availability
- [ ] **ATP v2.0 Development** - Adaptive Transmission Protocol
  - [ ] Smart-contract handshakes with trust scoring
  - [ ] Adaptive polymorphism (Burst/Swarm/Ghost modes)
  - [ ] Jitter-injection engine (anti-surveillance)
  - [ ] Energy-aware routing (battery management)
- [ ] Performance optimization (1M TER/sec target)
- [ ] Side-channel attack mitigation
- [ ] Academic publication (preprint)

### Phase 6 (Q2-Q3 2026) - ADVANCED FEATURES
- [ ] **ATP v2.0 Beta Testing** - Deploy adaptive transmission modes
- [ ] Federated machine learning across mesh
- [ ] Zero-knowledge proofs for privacy-preserving intelligence
- [ ] Mobile edge nodes (iOS/Android) with ATP
- [ ] Formal verification of critical components
- [ ] Third-party security audit (ATP + Neuro Protocol)

### Phase 7 (Q4 2026) - ECOSYSTEM EXPANSION
- [ ] **ATP v2.0 Production** - Migrate all nodes from HTP v1.0
- [ ] Quantum-resistant signature upgrade
- [ ] Cross-mesh federation protocol with ATP
- [ ] Decentralized governance framework (DAO design)
- [ ] Open consortium formation
- [ ] **Goal**: 1,000 edge nodes deployed globally with ATP

### Vision (2027+)
- [ ] Smart contract-based threat bounties
- [ ] Decentralized autonomous operations
- [ ] Multi-mesh global federation
- [ ] **Goal**: 10,000+ edge nodes protecting 10M+ endpoints

---

## 🤝 Join the Revolution

### For Users
- **Deploy**: Start with one $75 edge node
- **Participate**: Your threats train the global AI
- **Benefit**: Protection improves every day

### For Developers
- **Contribute**: Open source, MIT license
- **Innovate**: Build new PODs, integrate services
- **Research**: Novel crypto + AI + distributed systems

### For MSSPs
- **Adopt**: Offer enterprise security at 1/10th the cost
- **Scale**: One cloud validator serves 1000+ customers
- **Differentiate**: Neural cryptography no competitor has

### For Researchers
- **Explore**: New cryptographic primitives
- **Publish**: Novel approaches to continuous authentication
- **Collaborate**: Academia + industry partnership

---

## 📚 Documentation

### Quick Links
- 🚀 **[Quick Start](QUICK-START.md)** - 3-step installation
- 🏗️ **[Architecture Overview](docs/architecture/security-model.md)** - Complete security model
- 🧬 **[Neuro Protocol](docs/architecture/hookprobe-neuro-protocol.md)** - Neural cryptography spec
- 🌐 **[DSM Whitepaper](docs/architecture/dsm-whitepaper.md)** - Decentralized mesh architecture
- 🎯 **[Qsecbit Algorithm](src/qsecbit/README.md)** - Resilience metrics deep dive
- 📦 **[POD Components](docs/components/README.md)** - All modules explained
- 📖 **[Complete Documentation Index](docs/DOCUMENTATION-INDEX.md)** - Find anything

### Key Concepts
- **[Neuro Resonance Handshakes](src/neuro/README.md#resonance)** - How edge and cloud synchronize
- **[Proof-of-Sensor-Fusion](src/neuro/README.md#posf)** - Neural network signatures
- **[Deterministic Replay](src/neuro/core/replay.py)** - Cloud weight simulation
- **[Qsecbit Convergence](src/qsecbit/README.md#convergence-rate)** - Resilience quantification
- **[Byzantine Fault Tolerance](docs/architecture/dsm-implementation.md#consensus)** - Validator quorum

---

## 🌟 Why This Is The Future

### The Three Impossibilities We Solved

**1. Impossible to scale SOC operations affordably**
   - Solution: Decentralized mesh with autonomous AI → One analyst monitors 1000+ nodes

**2. Impossible to authenticate continuously without static keys**
   - Solution: Neural weight evolution → Cryptographic key IS the sensor history

**3. Impossible to quantify resilience (only detect attacks)**
   - Solution: Qsecbit convergence rate → Measure recovery speed, not just threats

### The Neurosurgical Metaphor

Traditional cybersecurity is like **medieval surgery** — crude, reactive, high mortality rate.

**HookProbe is neurosurgery** — precise, proactive, monitors every signal:

```
Medieval Surgery              Neurosurgery              Traditional Security        HookProbe
├─ Cut and hope              ├─ Millimeter precision   ├─ Block and pray          ├─ Surgical threat isolation
├─ Infection common          ├─ Monitor vitals 24/7    ├─ Attacks spread          ├─ Mesh quarantine in <30s
├─ High mortality            ├─ Predictive analytics   ├─ Breach = catastrophic   ├─ Resilience metrics + recovery
└─ Expensive, for elites     └─ Accessible medicine    └─ $100K+ (enterprise)     └─ $150 (everyone)
```

**The shift from reactive defense to predictive resilience is the evolution from surgery to neurosurgery.**

---

## 💬 Community & Support

- **GitHub**: [github.com/hookprobe/hookprobe](https://github.com/hookprobe/hookprobe)
- **Issues**: Bug reports, feature requests
- **Discussions**: Architecture, deployment, research
- **Website**: [hookprobe.com](https://hookprobe.com)
- **Email**: neuro@hookprobe.com (Neuro protocol), security@hookprobe.com (Security)

### Security Disclosure
Found a vulnerability? **Responsible disclosure please**:
📧 security@hookprobe.com | 🔒 [PGP Key](https://hookprobe.com/pgp)

---

## 📜 License

**MIT License** — Use commercially, modify, distribute freely.

See [LICENSE](LICENSE) file for details.

**Philosophy**: Security should be open, auditable, and accessible to everyone.

---

## 🙏 Credits

**Core Team**:
- **Andrei Toma** - Architecture, Neuro Protocol, DSM Design, Qsecbit AI

**Technology Stack**:
- **Security**: Suricata, Zeek, Snort3, NAXSI, ModSecurity
- **AI/ML**: Custom Qsecbit algorithm, TensorFlow
- **Analytics**: ClickHouse, Grafana, VictoriaMetrics
- **Orchestration**: Podman, systemd
- **Crypto**: ChaCha20-Poly1305, Ed25519, Curve25519, BLS signatures
- **Transport**: HookProbe Transport Protocol (HTP) - custom UDP-based
- **Identity**: Hardware fingerprinting (CPU/MAC/disk/DMI), MSSP device registry
- **Geolocation**: MaxMind GeoIP2, IP-API
- **Networking**: OVS, VXLAN, XDP/eBPF

**Inspiration**:
- **Neuroscience**: Neural networks as living cryptographic systems
- **Distributed Systems**: Bitcoin consensus, Ethereum BFT, IPFS
- **Security Research**: MITRE ATT&CK, OWASP, NIST

---

## 🌍 The Vision

**By 2030, we envision**:

- 🌐 **1 million edge nodes** deployed globally
- 🏠 **Enterprise security in every home** ($75 cost)
- 🏢 **Every SMB protected** (10x security at 1/10th cost)
- 🌍 **Cybersecurity democratized** (billions protected, not millions)
- 🧬 **Neural cryptography standard** (adopted by industry)
- 🎯 **Quantified resilience** (Qsecbit becomes the metric)

**This is not a product. This is a movement.**

**From fortifications to nervous systems. From static defense to living resilience.**

**Welcome to the future of cybersecurity.**

---

<p align="center">
  <strong>🚀 Start Your Neurosurgical Security Journey Today</strong><br>
  <code>git clone https://github.com/hookprobe/hookprobe && cd hookprobe && sudo ./install.sh</code>
</p>

<p align="center">
  <em>"Neural Resonance · Decentralized Intelligence · Surgical Precision"</em>
</p>

<p align="center">
  <strong>HookProbe</strong> · Democratizing Cybersecurity Through Neuroscience
</p>

---

**Made with ❤️ and 🧠 for a safer, more equitable internet**
