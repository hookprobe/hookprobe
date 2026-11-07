# AI Device Fingerprinting & Ecosystem Bubble Integration

**Version**: 5.5.0
**Status**: Production Ready
**License**: Proprietary (Commercial license required for SaaS/OEM)

---

## Overview

HookProbe Fortress includes two proprietary AI-powered features for intelligent device management:

1. **AI Device Fingerprinting** - 99%+ accuracy device identification using ML/XGBoost
2. **Ecosystem Bubble** - "Atmospheric Presence" networking for same-user device detection

These features work together to provide:
- Automatic device classification and NAC policy assignment
- Same-user device grouping without credentials
- SDN-enforced bubble traffic optimization
- Active learning with human feedback

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Device Connection                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Unified Fingerprint Engine                            │
│  ┌──────────────┬──────────────┬──────────────┬───────────────────────┐ │
│  │ DHCP Option  │   MAC OUI    │   Hostname   │    mDNS Discovery     │ │
│  │ 55 Parser    │   Lookup     │   Analysis   │    (Apple, Google)    │ │
│  ├──────────────┼──────────────┼──────────────┼───────────────────────┤ │
│  │ JA3/TLS      │  TCP Stack   │  Fingerbank  │    BLE Proximity      │ │
│  │ Fingerprint  │  Analysis    │  API Client  │    (Continuity)       │ │
│  └──────────────┴──────────────┴──────────────┴───────────────────────┘ │
│                           ▼                                              │
│              XGBoost ML Classifier (Active Learning)                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     ▼                              ▼
┌─────────────────────────────┐    ┌─────────────────────────────────────┐
│    NAC Policy Assignment    │    │      Ecosystem Bubble Manager       │
│  ┌───────────────────────┐  │    │  ┌─────────────────────────────────┐│
│  │ VLAN placement        │  │    │  │ DBSCAN Behavioral Clustering   ││
│  │ QoS priority          │  │    │  │ Time correlation               ││
│  │ Access rules          │  │    │  │ Protocol overlap               ││
│  │ Bandwidth limits      │  │    │  │ Hostname patterns              ││
│  └───────────────────────┘  │    │  └─────────────────────────────────┘│
└─────────────────────────────┘    │                  ▼                   │
                                   │  ┌─────────────────────────────────┐ │
                                   │  │ SDN Bubble Enforcement          │ │
                                   │  │ - Intra-bubble fast path        │ │
                                   │  │ - Cross-bubble inspection       │ │
                                   │  │ - OpenFlow rule generation      │ │
                                   │  └─────────────────────────────────┘ │
                                   └─────────────────────────────────────┘
```

---

## Components

### 1. ML Fingerprint Classifier

**File**: `products/fortress/lib/ml_fingerprint_classifier.py`

XGBoost-based device classifier with active learning.

**Features**:
- 20+ input features from multiple signal sources
- Hierarchical classification (category → type → vendor)
- Active learning with human feedback loop
- Automatic retraining when feedback threshold reached
- Model versioning and persistence

**Signal Weights**:
```python
SIGNAL_WEIGHTS = {
    'dhcp_fingerprint': 0.40,  # DHCP Option 55 (device DNA)
    'mac_oui': 0.15,           # Manufacturer ID
    'hostname': 0.15,          # Device naming patterns
    'mdns': 0.10,              # Service advertisements
    'ja3': 0.10,               # TLS fingerprint
    'tcp_stack': 0.05,         # TCP behavior
    'fingerbank_api': 0.05,    # Cloud enrichment
}
```

### 2. JA3 TLS Fingerprinter

**File**: `products/fortress/lib/ja3_fingerprint.py`

Passive TLS fingerprinting for OS and application detection.

**Known Signatures**:
- Safari on iOS/macOS
- Chrome on various platforms
- Firefox, Edge, Brave
- Android system apps
- Windows Update, Office 365
- IoT device patterns

### 3. Unified Fingerprint Engine

**File**: `products/fortress/lib/unified_fingerprint_engine.py`

Orchestrates all fingerprinting signals.

**Features**:
- Weighted ensemble voting
- Fingerbank API integration (600 free requests/month)
- Result caching and deduplication
- Policy recommendation based on device identity

### 4. Presence Sensor

**File**: `products/fortress/lib/presence_sensor.py`

Multi-modal presence detection.

**Detection Methods**:
- **mDNS/Bonjour**: Apple AirPlay, HomeKit, Continuity services
- **BLE Proximity**: Apple Continuity packets, Nearby Share
- **Spatial Correlation**: Join/leave timing analysis

**Ecosystem Detection**:
```python
APPLE_MDNS_SERVICES = [
    "_airplay._tcp",          # AirPlay
    "_raop._tcp",             # AirPlay audio
    "_companion-link._tcp",   # Continuity
    "_homekit._tcp",          # HomeKit
    "_hap._tcp",              # HomeKit Accessory
    "_sleep-proxy._udp",      # Wake on Demand
    "_apple-mobdev2._tcp",    # Apple Mobile Device
]
```

### 5. Behavioral Clustering Engine

**File**: `products/fortress/lib/behavior_clustering.py`

DBSCAN unsupervised clustering for user bubble detection.

**Clustering Features**:
- Time correlation (devices joining/leaving together)
- Protocol overlap (shared mDNS, BLE patterns)
- Hostname patterns (owner name extraction)
- Ecosystem membership (Apple, Google, Amazon)

### 6. Ecosystem Bubble Manager

**File**: `products/fortress/lib/ecosystem_bubble.py`

Main orchestrator for bubble lifecycle and SDN enforcement.

**Bubble States**:
```
FORMING → ACTIVE → DORMANT → DISSOLVED
   │         │        │          │
 New     Confirmed  Inactive   Removed
cluster  (>85%     (5min+    from SDN
         conf)     no activity)
```

**SDN Integration**:
```python
# Example OpenFlow rules for bubble
rules = [
    {
        "priority": 100,
        "match": {
            "in_port": device_a_port,
            "eth_dst": device_b_mac
        },
        "actions": ["output:device_b_port"]
    },
    # Reverse path
    {
        "priority": 100,
        "match": {
            "in_port": device_b_port,
            "eth_dst": device_a_mac
        },
        "actions": ["output:device_a_port"]
    }
]
```

---

## Systemd Services

### fts-fingerprint-engine.service

Unified fingerprint engine daemon.

```bash
systemctl status fts-fingerprint-engine
systemctl restart fts-fingerprint-engine
journalctl -u fts-fingerprint-engine -f
```

### fts-presence-sensor.service

Multi-modal presence sensor (runs as root for BLE/mDNS access).

```bash
systemctl status fts-presence-sensor
systemctl restart fts-presence-sensor
journalctl -u fts-presence-sensor -f
```

### fts-bubble-manager.service

Ecosystem bubble manager with SDN enforcement.

```bash
systemctl status fts-bubble-manager
systemctl restart fts-bubble-manager
journalctl -u fts-bubble-manager -f
```

---

## Databases

All databases are SQLite, stored in `/var/lib/hookprobe/`:

| Database | Purpose |
|----------|---------|
| `fingerprint.db` | Device fingerprints and ML feedback |
| `ecosystem_bubbles.db` | Bubble state and SDN rules |
| `presence.db` | Presence events and mDNS services |
| `ja3_signatures.db` | Learned JA3 signatures (optional) |

### Schema: fingerprint.db

```sql
CREATE TABLE fingerprints (
    mac_address TEXT PRIMARY KEY,
    device_type TEXT,
    device_category TEXT,
    vendor TEXT,
    os_type TEXT,
    confidence REAL,
    dhcp_fingerprint TEXT,
    hostname TEXT,
    first_seen TEXT,
    last_seen TEXT,
    signals TEXT,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE fingerprint_feedback (
    id INTEGER PRIMARY KEY,
    mac_address TEXT,
    correct_type TEXT,
    correct_vendor TEXT,
    submitted_by TEXT,
    submitted_at TEXT
);
```

### Schema: ecosystem_bubbles.db

```sql
CREATE TABLE bubbles (
    bubble_id TEXT PRIMARY KEY,
    name TEXT,
    ecosystem TEXT,
    state TEXT,
    confidence REAL,
    device_count INTEGER,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE bubble_devices (
    id INTEGER PRIMARY KEY,
    bubble_id TEXT,
    mac_address TEXT,
    device_type TEXT,
    joined_at TEXT
);

CREATE TABLE bubble_sdn_rules (
    id INTEGER PRIMARY KEY,
    bubble_id TEXT,
    rule_type TEXT,
    priority INTEGER,
    match_criteria TEXT,
    actions TEXT,
    active INTEGER,
    created_at TEXT
);
```

---

## REST API Endpoints

### Fingerprinting

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/fingerprint/status` | GET | Engine status, accuracy stats |
| `/api/fingerprint/device/<mac>` | GET | Device fingerprint details |
| `/api/fingerprint/device/<mac>/reclassify` | POST | Force reclassification |
| `/api/fingerprint/feedback` | POST | Submit correction for active learning |
| `/api/fingerprint/stats` | GET | Classification statistics |

### Ecosystem Bubbles

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/bubbles` | GET | List all bubbles |
| `/api/bubbles/<id>` | GET | Bubble details |
| `/api/bubbles/<id>/devices` | GET | Devices in bubble |
| `/api/bubbles/<id>/rules` | GET | SDN rules for bubble |
| `/api/bubbles/stats` | GET | Bubble statistics |
| `/api/presence/status` | GET | Presence sensor status |

---

## CLI Commands

### fortress-ctl fingerbank

```bash
# Set Fingerbank API key
sudo fortress-ctl fingerbank set-api-key YOUR_API_KEY

# Check API status
fortress-ctl fingerbank status

# Test with a fingerprint
fortress-ctl fingerbank test "1,121,3,6,15,119,252"

# Enable/disable API
sudo fortress-ctl fingerbank enable
sudo fortress-ctl fingerbank disable
```

---

## Configuration

### Fingerbank API

Create `/etc/hookprobe/fingerbank.json`:

```json
{
    "api_key": "YOUR_API_KEY",
    "enabled": true,
    "requests_today": 0,
    "last_reset": "2024-01-15"
}
```

### Bubble Manager

Configuration in `/etc/hookprobe/fortress.conf`:

```ini
[ecosystem_bubble]
enabled = true
min_cluster_confidence = 0.65
confirmation_threshold = 0.85
dormant_timeout_seconds = 300
dissolve_timeout_seconds = 3600
sdn_enforcement = true
```

---

## Uninstall

All fingerprinting data is cleaned by `uninstall.sh`:

```bash
# Standard uninstall (preserves data with --keep-data)
sudo ./uninstall.sh

# Full purge (removes all databases)
sudo ./uninstall.sh --purge
```

Databases removed:
- `/var/lib/hookprobe/fingerprint.db`
- `/var/lib/hookprobe/ecosystem_bubbles.db`
- `/var/lib/hookprobe/presence.db`
- `/var/lib/hookprobe/ml_fingerprint_models/`
- `/var/lib/fortress/bubbles/`

---

## Privacy Considerations

### Data Collected

- MAC addresses (for device identification)
- DHCP fingerprints (Option 55 values)
- Hostnames (for pattern matching)
- mDNS service advertisements (public by design)
- BLE manufacturer data (for ecosystem detection)

### Data NOT Collected

- Traffic content
- User credentials
- Personal files
- Browsing history

### Fingerbank API

Only anonymized data sent:
- DHCP Option 55 fingerprint
- MAC OUI prefix (first 3 bytes only)
- Hostname (optional)

**No IP addresses or full MAC addresses are sent.**

---

## Troubleshooting

### Service Not Starting

```bash
# Check service logs
journalctl -u fts-fingerprint-engine -n 50

# Check Python path
python3 -c "from products.fortress.lib import get_unified_fingerprint_engine; print('OK')"

# Check database permissions
ls -la /var/lib/hookprobe/*.db
```

### Low Accuracy

1. Submit feedback for misclassified devices
2. Wait for active learning retrain (50 feedback samples)
3. Enable Fingerbank API for unknown devices
4. Check if DHCP fingerprints are being captured

### Bubbles Not Forming

1. Verify presence sensor is running
2. Check mDNS services are visible (`avahi-browse -a`)
3. Ensure devices are from same ecosystem
4. Check clustering confidence threshold

---

## References

- [Fingerbank API Documentation](https://api.fingerbank.org/api_doc)
- [JA3 Fingerprinting](https://github.com/salesforce/ja3)
- [DBSCAN Algorithm](https://en.wikipedia.org/wiki/DBSCAN)
- [OpenFlow Specification](https://opennetworking.org/software-defined-standards/specifications/)

---

*HookProbe Fortress - SDN Autopilot with AI-Powered Device Intelligence*
