# dnsXai - AI-Powered DNS Protection

<p align="center">
  <img src="../../docs/images/dnsxai-logo.png" alt="dnsXai Logo" width="200">
</p>

<p align="center">
  <strong>Next-Generation DNS Protection with Machine Learning</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#api">API</a> •
  <a href="#architecture">Architecture</a>
</p>

---

## Overview

**dnsXai** is HookProbe's innovative, forward-thinking DNS protection system that goes beyond traditional blocklists. Using machine learning, federated intelligence, and advanced detection techniques, dnsXai provides enterprise-grade ad blocking and tracker protection for homes and offices.

### Why dnsXai?

| Traditional Blockers | dnsXai |
|---------------------|--------|
| Static blocklists only | ML-based classification for unknown domains |
| Miss CNAME cloaking | Detects first-party tracker masquerading |
| Isolated protection | Federated learning across mesh network |
| Manual updates | Self-learning and auto-updating |
| Binary block/allow | Confidence-based decisions with 8 categories |

---

## Features

### 🧠 AI-Powered Classification

Our lightweight neural classifier analyzes 20 domain features in real-time:

- **Lexical Analysis**: Length, structure, character distribution
- **Entropy Measurement**: Shannon entropy, n-gram entropy
- **Pattern Detection**: Ad keywords, suspicious TLDs
- **Structural Analysis**: Subdomain depth, numeric patterns

```python
# Example: Domain feature extraction
features = {
    'shannon_entropy': 3.42,
    'ad_pattern_count': 2,
    'suspicious_tld': 0,
    'subdomain_depth': 3,
    # ... 16 more features
}
```

**Performance**: ~50KB model, <1ms inference on Raspberry Pi

### 🔍 CNAME Uncloaking

Detects sophisticated tracking that bypasses traditional blockers:

```
track.yoursite.com → CNAME → adobe.demdex.net (BLOCKED!)
```

Traditional blockers see `track.yoursite.com` (first-party, allowed).
dnsXai follows the chain and detects the hidden tracker.

**Detected Services**: Adobe/Omniture, Criteo, Oracle/BlueKai, Pardot, Branch, Segment, and 25+ more

### 🌐 Federated Learning

Privacy-preserving collective intelligence:

- **No raw queries shared** - Only model weights and domain hashes
- **Differential privacy** - Mathematical privacy guarantees
- **Consensus validation** - Multiple nodes must agree before applying
- **GDPR compliant** - By design, not afterthought

```
One node detects new tracker → Model weights shared →
All nodes learn → Collective protection improves
```

### 📊 5-Tier Protection Levels

| Level | Name | Protection | Domains |
|-------|------|------------|---------|
| 1 | **Base** | Ads + Malware | ~130K |
| 2 | **Enhanced** | + Fakenews | ~132K |
| 3 | **Strong** | + Gambling | ~135K |
| 4 | **Maximum** | + Adult Content | ~200K |
| 5 | **Full** | + Social Trackers | ~250K |

### 🔗 Mesh Intelligence

When connected to the HookProbe mesh:

- Real-time IOC (Indicators of Compromise) sharing
- Collective Qsecbit scoring
- Distributed blocklist updates
- Coordinated defense response

---

## Installation

### Prerequisites

- Python 3.8+
- dnslib (for DNS server)
- numpy (optional, for optimized operations)

### Install Dependencies

```bash
pip install dnslib numpy
```

### Quick Start

```python
from shared.dnsXai import DNSXai, ProtectionLevel

# Create instance
dnsxai = DNSXai()

# Update blocklists
dnsxai.update_blocklist()

# Start protecting
dnsxai.start_server(port=5353)
```

### Systemd Service

```bash
# Copy service file
sudo cp /opt/hookprobe/shared/dnsXai/dnsxai.service /etc/systemd/system/

# Enable and start
sudo systemctl enable dnsxai
sudo systemctl start dnsxai
```

---

## Usage

### Command Line Interface

```bash
# Classify a domain
python -m shared.dnsXai.engine --classify doubleclick.net

# Update blocklists
python -m shared.dnsXai.engine --update

# Start DNS server
python -m shared.dnsXai.engine --serve --port 5353

# Show statistics
python -m shared.dnsXai.engine --stats
```

### Python API

```python
from shared.dnsXai import DNSXai, DNSXaiConfig, ProtectionLevel

# Custom configuration
config = DNSXaiConfig(
    dns_listen_port=5353,
    upstream_dns="1.1.1.1",
    ml_enabled=True,
    cname_check_enabled=True,
    federated_enabled=True,
    ml_confidence_threshold=0.75
)

# Create instance
dnsxai = DNSXai(config)

# Classify domains
result = dnsxai.classify_domain("ads.example.com")
print(f"Domain: {result.domain}")
print(f"Category: {result.category.name}")
print(f"Confidence: {result.confidence:.2%}")
print(f"Blocked: {result.blocked}")
print(f"Method: {result.method}")

# Get statistics
stats = dnsxai.get_stats()
print(f"Total queries: {stats['total_queries']}")
print(f"Block rate: {stats['block_rate']:.2%}")
```

### Protection Level Control

```python
from shared.dnsXai import DNSXai, ProtectionLevel

dnsxai = DNSXai()

# Set protection level (1-5)
dnsxai.set_protection_level(ProtectionLevel.STRONG)  # Level 3

# Or by number
dnsxai.set_protection_level(4)  # Maximum
```

### Whitelist Management

```python
# Add to whitelist
dnsxai.add_to_whitelist("example.com")
dnsxai.add_to_whitelist("*.trusted-domain.com")

# Remove from whitelist
dnsxai.remove_from_whitelist("example.com")

# Get current whitelist
whitelist = dnsxai.get_whitelist()
```

### Blocklist Sources

```python
# Add custom blocklist source
dnsxai.add_blocklist_source("https://example.com/blocklist.txt")

# Remove source
dnsxai.remove_blocklist_source("https://example.com/blocklist.txt")

# Get current sources
sources = dnsxai.get_blocklist_sources()
```

---

## API Reference

### REST API Endpoints

When running the web UI, these endpoints are available:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dnsxai/stats` | GET | Get current statistics |
| `/api/dnsxai/config` | GET | Get current configuration |
| `/api/dnsxai/config` | POST | Update configuration |
| `/api/dnsxai/level` | POST | Set protection level |
| `/api/dnsxai/whitelist` | GET | Get whitelist |
| `/api/dnsxai/whitelist` | POST | Add to whitelist |
| `/api/dnsxai/whitelist` | DELETE | Remove from whitelist |
| `/api/dnsxai/sources` | GET | Get blocklist sources |
| `/api/dnsxai/sources` | POST | Add blocklist source |
| `/api/dnsxai/sources` | DELETE | Remove blocklist source |
| `/api/dnsxai/update` | POST | Trigger blocklist update |
| `/api/dnsxai/classify` | POST | Classify a domain |

### Example Requests

```bash
# Get stats
curl http://localhost:5000/api/dnsxai/stats

# Set protection level
curl -X POST http://localhost:5000/api/dnsxai/level \
  -H "Content-Type: application/json" \
  -d '{"level": 3}'

# Add to whitelist
curl -X POST http://localhost:5000/api/dnsxai/whitelist \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Classify domain
curl -X POST http://localhost:5000/api/dnsxai/classify \
  -H "Content-Type: application/json" \
  -d '{"domain": "doubleclick.net"}'
```

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         DNS Query                                │
│                      (e.g., ads.example.com)                     │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        dnsXai Engine                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  Whitelist  │  │  Blocklist  │  │    CNAME    │              │
│  │   Check     │  │   Lookup    │  │  Uncloaker  │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         ▼                ▼                ▼                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  ML Classifier                           │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐               │    │
│  │  │ Feature  │  │  Neural  │  │ Softmax  │               │    │
│  │  │Extraction│→ │ Network  │→ │  Output  │               │    │
│  │  └──────────┘  └──────────┘  └──────────┘               │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                │                                 │
│                                ▼                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Classification Result                       │    │
│  │  Category: ADVERTISING | Confidence: 0.92 | Blocked: ✓  │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Federated Learning                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Record    │  │   Share     │  │   Apply     │              │
│  │   Sample    │→ │   Weights   │→ │   Updates   │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      HookProbe Mesh                              │
│         Guardian ←→ Guardian ←→ Fortress ←→ MSSP                │
└─────────────────────────────────────────────────────────────────┘
```

### Component Details

#### 1. Feature Extractor (`DomainFeatureExtractor`)

Extracts 20 features from domain names:

| Category | Features |
|----------|----------|
| Lexical | length, num_parts, avg_part_length, max_part_length |
| Characters | digit_ratio, hyphen_ratio, underscore_ratio, vowel_ratio |
| Entropy | shannon_entropy, bigram_entropy, trigram_entropy |
| Patterns | ad_pattern_count, has_ad_keyword, suspicious_tld |
| Structure | tld_length, is_cdn, subdomain_depth, numeric_subdomain |
| Special | has_uuid, subdomain_entropy |

#### 2. Neural Classifier (`DomainClassifier`)

- **Architecture**: Input(20) → Hidden(32, ReLU) → Output(8, Softmax)
- **Categories**: Legitimate, Advertising, Tracking, Analytics, Social Tracker, Malware, Cryptominer, Unknown
- **Size**: ~50KB serialized
- **Speed**: <1ms inference

#### 3. CNAME Uncloaker (`CNAMEUncloaker`)

- Resolves full CNAME chain (up to 5 levels)
- Checks each destination against blocklist and ML
- Caches results for 1 hour
- Known tracker database: 30+ services

#### 4. Federated Learning (`FederatedAdLearning`)

- Records classifications locally
- Computes weight updates from local data
- Shares weights (not data) with mesh
- Applies consensus-validated updates

---

## Configuration

### Config File Location

```
/opt/hookprobe/guardian/dnsxai/config.json
/opt/hookprobe/fortress/dnsxai/config.json
```

### Configuration Options

```json
{
  "enabled": true,
  "protection_level": 3,
  "dns_listen_addr": "0.0.0.0",
  "dns_listen_port": 5353,
  "upstream_dns": "1.1.1.1",
  "upstream_port": 53,

  "ml_enabled": true,
  "ml_confidence_threshold": 0.75,

  "cname_check_enabled": true,
  "cname_max_depth": 5,

  "federated_enabled": true,
  "federated_share_interval": 3600,

  "blocklist_sources": [
    "https://big.oisd.nl/",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
  ],

  "whitelist": [
    "example.com",
    "trusted-domain.org"
  ]
}
```

---

## Integration

### Guardian Integration

```python
from shared.dnsXai import patch_guardian_agent_with_adblock, DNSXai

# Patch existing Guardian agent
guardian = GuardianAgent()
dnsxai = DNSXai()
guardian = patch_guardian_agent_with_adblock(guardian, dnsxai)

# Now guardian.calculate_qsecbit_score includes ad blocking
```

### Fortress Integration

```python
from shared.dnsXai import DNSXai, DNSXaiConfig

# Configure for Fortress (higher resources)
config = DNSXaiConfig(
    dns_listen_port=53,  # Can bind to privileged port
    ml_enabled=True,
    federated_enabled=True
)

fortress_dnsxai = DNSXai(config)
fortress_dnsxai.start_server()
```

### Qsecbit Integration

dnsXai contributes to the Qsecbit security score:

- **Weight**: 8% of total score
- **Component**: Privacy protection
- **Scoring**: High ad ratio = higher score (worse)

```
Qsecbit = 0.30·threats + 0.20·mobile + 0.25·ids + 0.15·xdp + 0.02·network + 0.08·dnsxai
```

---

## Blocklist Sources

### Default Sources

| Source | Description | Domains |
|--------|-------------|---------|
| OISD Big | Comprehensive blocklist | ~800K |
| StevenBlack | Unified hosts with extensions | ~130K |
| AdGuard CNAME | CNAME tracker list | ~3K |
| Hagezi Pro | DNS blocklist | ~300K |

### Adding Custom Sources

The blocklist updater supports multiple formats:

- **Hosts format**: `0.0.0.0 domain.com` or `127.0.0.1 domain.com`
- **Domain list**: One domain per line
- **AdBlock format**: `||domain.com^`

---

## Performance

### Benchmarks (Raspberry Pi 4)

| Operation | Time |
|-----------|------|
| Feature extraction | 0.2ms |
| ML classification | 0.5ms |
| Blocklist lookup | 0.01ms |
| CNAME resolution | 5-50ms (network) |
| **Total (cache hit)** | **<1ms** |
| **Total (cache miss)** | **~10ms** |

### Memory Usage

| Component | Memory |
|-----------|--------|
| Blocklist (250K domains) | ~25MB |
| ML model | ~50KB |
| CNAME cache (10K entries) | ~5MB |
| **Total** | **~35MB** |

---

## Troubleshooting

### Common Issues

**DNS not resolving:**
```bash
# Check if dnsxai is running
systemctl status dnsxai

# Check if port is listening
netstat -tulpn | grep 5353

# Test DNS resolution
dig @127.0.0.1 -p 5353 google.com
```

**Blocklist not updating:**
```bash
# Manual update
/opt/hookprobe/shared/dnsXai/update-blocklist.sh --verbose

# Check logs
journalctl -u dnsxai -f
```

**False positives:**
```bash
# Add to whitelist via API
curl -X POST http://localhost:5000/api/dnsxai/whitelist \
  -d '{"domain": "legitimate-site.com"}'

# Or edit whitelist file directly
echo "legitimate-site.com" >> /opt/hookprobe/guardian/dnsxai/whitelist.txt
```

---

## Contributing

See [CONTRIBUTING.md](../../docs/CONTRIBUTING.md) for guidelines.

### Running Tests

```bash
pytest tests/test_dnsxai.py -v
```

### Code Style

```bash
black shared/dnsXai/
flake8 shared/dnsXai/
```

---

## License

MIT License - see [LICENSE](../../LICENSE) for details.

---

## Credits

- **HookProbe Team** - Architecture and implementation
- **StevenBlack** - Unified hosts blocklist
- **OISD** - Comprehensive blocklist
- **AdGuard** - CNAME tracker research

---

<p align="center">
  <strong>dnsXai</strong> - Smarter DNS Protection for a Safer Internet
</p>
