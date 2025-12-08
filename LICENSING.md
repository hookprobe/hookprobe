# HookProbe Licensing

**Version**: 5.0 "Liberty"
**Last Updated**: 2025-12-08

---

## Dual Licensing Model

HookProbe uses a **dual licensing model** to balance open-source community benefits with intellectual property protection for core innovations.

### Why Dual Licensing?

1. **Community Trust** - AGPL is OSI-approved, ensuring true open-source credibility
2. **Protection Against Cloud Exploitation** - Network copyleft prevents competitors from offering SaaS without contributing back
3. **Sustainable Business Model** - Commercial licenses fund continued development
4. **Innovation Protection** - Core AI/ML algorithms remain proprietary to maintain competitive advantage

This approach is used successfully by Grafana, MinIO, ParadeDB, and other leading open-source companies.

---

## License Categories

### Open Source (AGPL v3.0)

The following components are licensed under the **GNU Affero General Public License v3.0**:

| Component | Location | Description |
|-----------|----------|-------------|
| Core Firewall Engine | `core/htp/transport/` | HTP protocol base implementation |
| Detection Rules | `shared/response/` | Threat detection signatures |
| Basic Management Interface | `products/guardian/web/` | Guardian Flask web UI |
| Agent/Endpoint Software | `products/*/` | Product tier agents |
| Community Documentation | `docs/` | Public documentation |
| Self-hosted Deployment | `deploy/` | Edge and cloud deployment scripts |
| Mesh Communication Base | `shared/mesh/` | Basic mesh networking |
| Blocklist Management | `shared/dnsXai/update-blocklist.sh` | Blocklist updater scripts |

**AGPL v3.0 Key Requirements:**
- Source code must be provided when software is distributed
- **Network use = distribution**: If you run modified AGPL software as a network service, you must provide source code to users
- Modifications must be licensed under AGPL v3.0
- Original copyright and license notices must be preserved

### Proprietary / Commercial License

The following **core innovations** are **NOT** open source and require a commercial license for use:

| Innovation | Location | Description |
|------------|----------|-------------|
| **Qsecbit AI Algorithm** | `core/qsecbit/qsecbit.py` | AI threat scoring models, resilience calculation |
| **Qsecbit ML Models** | `core/qsecbit/` | Trained model weights, training data, architecture |
| **Neural Resonance Protocol** | `core/neuro/` | TER generation, weight evolution, PoSF signatures |
| **dnsXai ML Classifier** | `shared/dnsXai/engine.py` | 20-feature neural classifier, domain categorization |
| **dnsXai Federated Learning** | `shared/dnsXai/mesh_intelligence.py` | Privacy-preserving collective intelligence |
| **DSM Consensus Algorithm** | `shared/dsm/consensus.py` | BLS signature aggregation, quorum logic |
| **DSM Ledger System** | `shared/dsm/ledger.py` | Microblock chain implementation |
| **Energy-Based Detection** | `core/qsecbit/energy_monitor.py` | RAPL power anomaly detection |
| **XDP/eBPF DDoS Mitigation** | `core/qsecbit/xdp_manager.py` | Kernel-level attack mitigation |
| **Premium Threat Intelligence** | N/A | Cloud-sourced threat feeds |
| **MSSP Cloud Platform** | `products/mssp/` | Complete MSSP cloud federation |
| **Multi-tenant Dashboard** | `products/mssp/web/` | Commercial MSSP Django portal |
| **Device Registry** | `products/mssp/device_registry.py` | Fleet device management |
| **MSSP API Layer** | `products/mssp/web/apps/` | All Django apps and APIs |
| **Compliance Automation** | Various | NIS2, GDPR automation tools |
| **Cloud Management Plane** | Cloud Services | Fleet management, analytics |
| **White-label Capabilities** | N/A | Rebranding features |

---

## Detailed Innovation Protection

### 1. Qsecbit AI Algorithm (Proprietary)

**What it is**: The core resilience metric algorithm that calculates security scores using:
- Mahalanobis distance-based drift detection
- ML-predicted attack probability
- Quantum drift measurement
- Energy anomaly detection (RAPL)
- dnsXai integration scoring

**Protection**: The formula, weights, normalization constants, and trained models are proprietary. The concept of a "resilience metric" is public, but the specific implementation is protected.

**Files**: `core/qsecbit/qsecbit.py`, `core/qsecbit/energy_monitor.py`, `core/qsecbit/xdp_manager.py`

### 2. Neural Resonance Protocol (Proprietary)

**What it is**: Living cryptography where neural networks become keys:
- Temporal Event Record (TER) generation
- Deterministic weight evolution
- Proof-of-Sensor-Fusion (PoSF) signatures
- Hardware fingerprinting without TPM

**Protection**: The weight evolution algorithm, TER structure, and PoSF signature scheme are proprietary innovations.

**Files**: `core/neuro/`

### 3. dnsXai ML Classifier (Proprietary)

**What it is**: AI-powered DNS protection beyond blocklists:
- 20-feature domain classifier
- 8-category classification system
- CNAME uncloaking detection
- Federated learning across mesh

**Protection**: The feature extraction pipeline, model architecture, and federated learning protocol are proprietary.

**Files**: `shared/dnsXai/engine.py`, `shared/dnsXai/mesh_intelligence.py`

### 4. DSM Consensus (Proprietary)

**What it is**: Decentralized Security Mesh consensus layer:
- BLS signature aggregation
- 2/3 Byzantine fault-tolerant quorum
- Microblock chain for threat sharing
- Deterministic replay verification

**Protection**: The consensus algorithm and ledger structure are proprietary implementations.

**Files**: `shared/dsm/consensus.py`, `shared/dsm/ledger.py`, `shared/dsm/validator.py`

### 5. HTP Keyless Protocol (Proprietary)

**What it is**: The keyless authentication mechanism:
- Entropy echo verification
- Resonance drift detection
- Sensor-derived identity
- Adaptive transmission modes

**Protection**: The keyless authentication scheme and adaptive security mechanisms are proprietary.

**Files**: `core/htp/transport/htp.py` (keyless portions)

### 6. MSSP Cloud Platform (Proprietary)

**What it is**: Complete cloud federation platform for Managed Security Service Providers:
- Multi-tenant Django portal
- Device registry and fleet management
- Customer onboarding and management
- VPN service provisioning
- SDN management APIs
- Security dashboard and monitoring
- AI-generated content services
- Merchandise/product catalog
- Geolocation services

**Protection**: The entire MSSP platform is proprietary, including all Django apps, APIs, database schemas, and business logic. This is the commercial heart of HookProbe's SaaS offering.

**Files**: `products/mssp/` (entire directory)

---

## Usage Scenarios

### Scenario 1: Personal/Home Use (FREE)

Use HookProbe on your own hardware for personal protection.

**License**: AGPL v3.0 (open source portions) + Proprietary (free for personal use)
**Cost**: $0
**Requirements**: No commercial use, no redistribution of proprietary components

### Scenario 2: Self-Hosted Business (FREE)

Deploy HookProbe on your own infrastructure to protect your business.

**License**: AGPL v3.0 + Proprietary (free for internal business use)
**Cost**: $0
**Requirements**: Internal use only, no offering as a service to third parties

### Scenario 3: MSSP / SaaS Provider (Commercial License Required)

Offer HookProbe-based security services to customers.

**License**: Commercial License Required
**Contact**: qsecbit@hookprobe.com
**Why**: The AGPL network copyleft clause applies - offering modified software as a service requires source disclosure OR commercial license

### Scenario 4: Integration / OEM (Commercial License Required)

Embed HookProbe technology in your products.

**License**: Commercial License Required
**Contact**: qsecbit@hookprobe.com
**Includes**: White-label rights, priority support, SLA guarantees

### Scenario 5: Contributing to HookProbe (CLA)

Submit improvements back to the project.

**Process**: Sign Contributor License Agreement (CLA)
**Benefit**: Contributions may be dual-licensed (AGPL + commercial)
**Contact**: qsecbit@hookprobe.com

---

## Commercial License Options

### Startup License
- **For**: Early-stage companies (<$1M ARR)
- **Includes**: Full proprietary access, basic support
- **Pricing**: Contact for startup-friendly pricing

### Professional License
- **For**: SMBs and growth companies
- **Includes**: Full access, priority support, training
- **Pricing**: Annual subscription based on deployment size

### Enterprise License
- **For**: Large organizations and MSSPs
- **Includes**: Unlimited deployment, white-label, SLA, dedicated support
- **Pricing**: Custom enterprise agreement

### Research License
- **For**: Academic institutions and security researchers
- **Includes**: Full access for non-commercial research
- **Pricing**: Free for qualifying institutions

**Contact**: qsecbit@hookprobe.com

---

## Frequently Asked Questions

### Q: Can I use HookProbe for my home network?
**A**: Yes, completely free under both AGPL and proprietary personal use terms.

### Q: Can I use HookProbe to protect my business?
**A**: Yes, free for internal business use. No commercial license needed if you're protecting your own infrastructure.

### Q: Can I offer HookProbe as a managed service to clients?
**A**: This requires a commercial license due to AGPL network copyleft provisions.

### Q: Can I modify HookProbe and keep my changes private?
**A**: For AGPL components: No, modifications must be shared if distributed or offered as a service.
For proprietary components: Modifications require commercial license.

### Q: Can I fork HookProbe and create a competitor?
**A**: You can fork the AGPL portions, but proprietary innovations cannot be used without a license.

### Q: What if I just want the blocklists without the AI?
**A**: Blocklist management scripts are AGPL-licensed and free to use. The AI classifier requires proper licensing.

### Q: How do I verify I'm compliant?
**A**: Contact qsecbit@hookprobe.com for a license audit.

---

## Third-Party Licenses

See [3rd-party-licenses.md](3rd-party-licenses.md) for comprehensive third-party license documentation.

All third-party components are GPL-free and commercially compatible.

---

## Contact

For all licensing inquiries, compliance questions, contributor agreements, security issues, and general questions:

**Email**: qsecbit@hookprobe.com

---

**HookProbe v5.0 "Liberty"**
*Protecting innovation while democratizing security*
