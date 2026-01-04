# AIOCHI - AI Eyes (AI OCHII in Romanian)

**Version**: 1.0.0
**Status**: Core Product - Proprietary
**Philosophy**: *Less is more for everyone, but powerful monitoring underneath*

---

## Vision

AIOCHI is not just a dashboard - it's a **Cognitive Network Layer** that transforms the complexity of SDN, IDS/IPS, and cybersecurity into a **narrative that a homeowner can understand**.

Think of AIOCHI as the "nervous system" that feels the network and translates its sensations into human language.

**The Core Promise**:
> "Your network speaks human now."

---

## The Three Pillars

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AIOCHI DASHBOARD                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐           │
│   │   PRESENCE   │   │   PRIVACY    │   │ PERFORMANCE  │           │
│   │  "Who's Home"│   │  "What's Up" │   │  "How Fast"  │           │
│   │              │   │              │   │              │           │
│   │  ┌───────┐   │   │  ┌───────┐   │   │    ┌──┐     │           │
│   │  │ 👨‍👩‍👧‍👦  │   │   │  │ Feed  │   │   │    │85│     │           │
│   │  │Bubbles│   │   │  │Events │   │   │    └──┘     │           │
│   │  └───────┘   │   │  └───────┘   │   │   Score     │           │
│   └──────────────┘   └──────────────┘   └──────────────┘           │
│                                                                      │
│   ┌──────────────────────────────────────────────────────────────┐  │
│   │                    AMBIENT STATUS BAR                         │  │
│   │        "Everything is quiet. 12 devices online."              │  │
│   └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Pillar 1: PRESENCE - "Who's Home"

**What the user sees**: Floating bubbles representing family members/device groups.

**Behind the scenes**:
- Ecosystem Bubble detection (Apple, Google, Samsung clusters)
- Same-user device correlation via DBSCAN
- AP association mapping
- mDNS/Bonjour service discovery

**Key Insight**: A user doesn't care about "MAC AA:BB:CC:DD:EE:FF" - they care about "Dad's devices are connected."

### Pillar 2: PRIVACY - "What's Up" (The News Feed)

**What the user sees**: A Facebook-style scrolling feed of network events in plain English.

**Behind the scenes**:
- Suricata/Zeek → ClickHouse → LLM Translation → Human Sentence
- Severity-based filtering (only important stuff surfaces)
- Device identity lookup for personalization

**Examples**:
- "10:00 AM: The HomePod updated its software successfully."
- "10:15 AM: A new device 'Guest_Laptop' joined the Guest WiFi."
- "10:30 AM: The Living Room Camera blocked a suspicious connection from Russia. Your camera is safe."

### Pillar 3: PERFORMANCE - "How Fast"

**What the user sees**: A single health score (0-100) with one-sentence AI insight.

**Behind the scenes**:
- Signal strength, latency, packet loss, interference
- Per-device performance tracking
- Correlation with environmental factors

**Example Insight**: "Score: 85. The microwave in the kitchen is currently slowing down the HomePod."

---

## Key Improvements Over Standard Monitoring

### 1. Ambient Mode (Zero-Attention Dashboard)

**Problem**: Traditional dashboards require constant attention.

**Solution**: AIOCHI runs in "Ambient Mode" by default:
- Single green shield = "Everything is OK"
- Only alerts when action is needed
- No graphs, no numbers, just peace of mind

```python
class AmbientState(Enum):
    CALM = "green_shield"      # No attention needed
    CURIOUS = "yellow_pulse"   # Something interesting (optional view)
    ALERT = "red_glow"         # Action required
```

### 2. Persona-Aware Narratives

**Problem**: Technical alerts don't resonate with non-technical users.

**Solution**: Configurable personas that change how AIOCHI "talks":

| Persona | Tone | Example Alert |
|---------|------|---------------|
| `parent` | Reassuring | "The kids' tablets are safely connected. All parental controls are active." |
| `gamer` | Performance-focused | "Your PS5 has priority. Ping: 12ms. No one else is streaming." |
| `remote_worker` | Productivity-focused | "Your work laptop has dedicated bandwidth. Video calls will be crystal clear." |
| `privacy_conscious` | Security-focused | "3 trackers blocked today. Your browsing is private." |

### 3. Whisper Mode (AI Thinking Out Loud)

**Problem**: Users don't know what the AI is doing.

**Solution**: Optional "Whisper Mode" that shows AI reasoning:

```
🤔 "I noticed unusual traffic from the printer at 3 AM..."
🔍 "Checking if it's a software update..."
✅ "Confirmed: HP firmware update. All good!"
```

### 4. One-Touch Actions (Big Buttons)

**Problem**: Complex network actions require CLI/expert knowledge.

**Solution**: Pre-built action buttons:

| Action | What It Does |
|--------|--------------|
| "Pause Kids' Internet" | Rate-limits all devices in "Kids" bubble |
| "Game Mode" | Prioritizes gaming devices, deprioritizes IoT |
| "Guest Lockdown" | Isolates guest VLAN, blocks internal access |
| "Boost This Device" | QoS priority for selected device |
| "Privacy Mode" | Blocks all analytics/tracking domains |

### 5. Time-Pattern Learning

**Problem**: Static rules don't adapt to household rhythms.

**Solution**: AIOCHI learns patterns:

```python
class TimePattern:
    """Learns household rhythms"""

    def __init__(self):
        self.patterns = {}  # device_id -> typical_schedule

    def learn(self, device_id: str, events: List[Event]):
        # "Dad's phone usually appears at 6:30 AM (home from gym)"
        # "Kids' tablets go offline at 9 PM (bedtime)"
        # "Smart TV peaks usage 8-10 PM (evening viewing)"
        pass

    def detect_anomaly(self, device_id: str, current_time: datetime) -> Optional[str]:
        # "Unusual: The garage door opened at 3 AM"
        pass
```

### 6. Family Dashboard (Multi-User Awareness)

**Problem**: One dashboard for multiple household members.

**Solution**: Personalized views per family member:

```
┌─────────────────────────────────────────────────────────────────────┐
│  👨 Dad's View                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ Your devices: iPhone, MacBook, Apple Watch                     │ │
│  │ Status: All connected, good signal                             │ │
│  │ Insight: "Your MacBook used 2.3 GB today (normal)"             │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  👧 Kids' View (Parental Controls Active)                           │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ Screen time today: 2h 15m (limit: 3h)                          │ │
│  │ Blocked: 12 ads, 3 inappropriate sites                         │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### 7. Voice Integration (Optional)

**Problem**: Mobile dashboards require app switching.

**Solution**: Browser-based voice queries:

```
User: "Hey Fortress, is everything okay?"
AIOCHI: "Yes! 14 devices online, no threats detected. Your internet speed is 285 Mbps."

User: "Pause the kids' internet"
AIOCHI: "Done. I'll remind you to turn it back on in an hour."
```

### 8. Trust Heatmap (Visual Security)

**Problem**: Users don't understand "trust levels."

**Solution**: Visual heatmap showing device trust over time:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Device Trust Timeline                                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  iPhone (Dad)      ████████████████████████  TRUSTED (6 months)     │
│  MacBook           ██████████████████████░░  HIGH (4 months)        │
│  Smart TV          ████████████████░░░░░░░░  MEDIUM (2 months)      │
│  Guest_Laptop      ██░░░░░░░░░░░░░░░░░░░░░░  NEW (1 hour)           │
│                                                                      │
│  Legend: ████ Trusted  ░░░░ Learning  ▓▓▓▓ Suspicious               │
└─────────────────────────────────────────────────────────────────────┘
```

### 9. Mobile-First PWA (Progressive Web App)

**Problem**: Native apps are heavy and require store approval.

**Solution**: PWA that:
- Installs to home screen
- Works offline (cached state)
- Push notifications for alerts
- Biometric unlock (FaceID/fingerprint)

### 10. Narrative Templates (LLM-Free Fallback)

**Problem**: LLM API calls are slow and expensive.

**Solution**: Pre-built narrative templates for common events:

```python
NARRATIVE_TEMPLATES = {
    "new_device": [
        "A new device '{device_name}' just joined {network_name}.",
        "Welcome! '{device_name}' is now connected to your network.",
        "New arrival: '{device_name}' on {network_name}.",
    ],
    "blocked_threat": [
        "I blocked a suspicious connection from {threat_source}. {device_name} is safe.",
        "Threat neutralized! {device_name} tried to connect to a known bad server.",
        "Your {device_name} was protected from a potential attack.",
    ],
    "device_offline": [
        "{device_name} went offline. This might be normal if it's sleeping.",
        "Heads up: {device_name} disconnected at {time}.",
    ],
    # ... hundreds more templates
}
```

---

## Data Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AIOCHI DATA PIPELINE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  STAGE 1: CAPTURE                                                            │
│  ┌─────────────┐     ┌─────────────┐                                        │
│  │  Suricata   │────▶│   Zeek      │                                        │
│  │  (Alerts)   │     │  (Logs)     │                                        │
│  └─────────────┘     └─────────────┘                                        │
│         │                   │                                                │
│         ▼                   ▼                                                │
│  STAGE 2: STORE                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                       ClickHouse                                     │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │    │
│  │  │ alerts      │  │ connections │  │ dns_queries │                  │    │
│  │  │ (suricata)  │  │ (zeek)      │  │ (zeek)      │                  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │    │
│  │  │ device_ids  │  │ narratives  │  │ metrics     │                  │    │
│  │  │ (identity)  │  │ (stories)   │  │ (timeseries)│                  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│         │                                                                    │
│         ▼                                                                    │
│  STAGE 3: ENRICH (Identity Engine)                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Python Worker (watches for new devices/events)                      │    │
│  │                                                                       │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │ 1. Pull last 50 packets for MAC from ClickHouse             │    │    │
│  │  │ 2. Run through Unified Fingerprint Engine (7 signals)       │    │    │
│  │  │ 3. Classify device type (ML + rules)                        │    │    │
│  │  │ 4. Detect ecosystem (Apple/Google/Samsung bubble)           │    │    │
│  │  │ 5. Assign human label ("Dad's iPhone")                      │    │    │
│  │  │ 6. Update device_ids table in ClickHouse                    │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│         │                                                                    │
│         ▼                                                                    │
│  STAGE 4: TRANSLATE (Narrative Engine)                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  n8n Workflow (triggered by event severity)                          │    │
│  │                                                                       │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │ 1. Receive alert from ClickHouse (webhook/poll)             │    │    │
│  │  │ 2. Lookup device identity (device_ids table)                │    │    │
│  │  │ 3. Check user persona (parent/gamer/worker)                 │    │    │
│  │  │ 4. Generate narrative:                                       │    │    │
│  │  │    - Fast path: Template matching (95% of events)           │    │    │
│  │  │    - Slow path: LLM API call (5% complex events)            │    │    │
│  │  │ 5. Write to narratives table in ClickHouse                  │    │    │
│  │  │ 6. Push WebSocket update to dashboard                       │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│         │                                                                    │
│         ▼                                                                    │
│  STAGE 5: VISUALIZE                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Grafana Dashboard                                                   │    │
│  │                                                                       │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │    │
│  │  │  PRESENCE   │  │   PRIVACY   │  │ PERFORMANCE │                  │    │
│  │  │  (Bubbles)  │  │   (Feed)    │  │  (Score)    │                  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │    │
│  │                                                                       │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │               AMBIENT STATUS (single sentence)               │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Container Stack

AIOCHI containers are separate from core security (dnsXai, QSecBit remain standalone).

### AIOCHI Containers (Profile: `aiochi`)

| Container | Image | Purpose | Ports | Network |
|-----------|-------|---------|-------|---------|
| `aiochi-clickhouse` | clickhouse/clickhouse-server | Event storage | 8123, 9000 | fts-internal |
| `aiochi-suricata` | jasonish/suricata | IDS alerts | - | host (capture) |
| `aiochi-zeek` | zeek/zeek | Connection logging | - | host (capture) |
| `aiochi-identity` | custom (Python) | Device fingerprinting | 8060 | fts-internal |
| `aiochi-narrative` | n8nio/n8n | Event translation | 5678 | fts-internal |
| `aiochi-grafana` | grafana/grafana | Dashboard | 3000 | fts-internal |
| `aiochi-victoria` | victoriametrics | Metrics storage | 8428 | fts-internal |

### Why Separate from Core Security?

| Component | Core Security? | AIOCHI Stack? | Reason |
|-----------|----------------|---------------|--------|
| QSecBit | Yes | No | Real-time threat detection, always running |
| dnsXai | Yes | No | DNS protection, always running |
| Suricata | Optional | Yes | Alerting for narratives |
| Zeek | Optional | Yes | Connection logging for identity |
| ClickHouse | Optional | Yes | Analytics, not required for security |
| Grafana | Optional | Yes | Visualization, not required for security |
| n8n | Optional | Yes | Automation, not required for security |

**Installation Decision Tree**:
```
Install Fortress?
    │
    ├── Core services (postgres, redis, web, qsecbit, dnsxai) → ALWAYS
    │
    └── "Do you want Eyes on the Network?" (Y/N)
            │
            ├── Yes → Install AIOCHI stack (clickhouse, suricata, zeek, grafana, n8n)
            │
            └── No → Skip AIOCHI (core security still active)
```

---

## ClickHouse Schema

```sql
-- Device identities (enriched by Identity Engine)
CREATE TABLE device_identities (
    mac String,
    first_seen DateTime,
    last_seen DateTime,
    human_label String,           -- "Dad's iPhone"
    device_type String,           -- "iPhone 15 Pro"
    vendor String,                -- "Apple"
    ecosystem String,             -- "apple_bubble"
    bubble_id String,             -- "family_dad"
    trust_level UInt8,            -- 0-4 (L0-L4)
    confidence Float32,           -- 0.0-1.0
    fingerprint_hash String,      -- Unique identifier

    INDEX idx_mac mac TYPE bloom_filter GRANULARITY 1,
    INDEX idx_bubble bubble_id TYPE bloom_filter GRANULARITY 1
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (mac);

-- Narratives (human-readable stories)
CREATE TABLE narratives (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    severity Enum8('info' = 1, 'low' = 2, 'medium' = 3, 'high' = 4, 'critical' = 5),
    category String,              -- "security", "device", "performance"
    device_mac String,
    device_label String,          -- "Dad's iPhone" (denormalized for speed)
    headline String,              -- Short summary
    narrative String,             -- Full human-readable story
    technical_details String,     -- JSON blob for curious users
    action_required Bool DEFAULT false,
    action_taken String,
    persona String DEFAULT 'parent',

    INDEX idx_severity severity TYPE minmax GRANULARITY 1,
    INDEX idx_category category TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, severity)
TTL timestamp + INTERVAL 30 DAY;

-- Presence snapshots (for bubble visualization)
CREATE TABLE presence_snapshots (
    timestamp DateTime DEFAULT now(),
    bubble_id String,
    bubble_label String,          -- "Dad", "Mom", "Kids"
    devices Array(String),        -- List of device labels
    ap_name String,               -- "Living Room AP"
    signal_strength Int16,
    is_home Bool DEFAULT true,

    INDEX idx_bubble bubble_id TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, bubble_id)
TTL timestamp + INTERVAL 7 DAY;

-- Performance metrics (for health score)
CREATE TABLE performance_metrics (
    timestamp DateTime DEFAULT now(),
    device_mac String,
    latency_ms Float32,
    jitter_ms Float32,
    packet_loss_pct Float32,
    signal_dbm Int16,
    bandwidth_mbps Float32,
    health_score UInt8,           -- 0-100

    INDEX idx_device device_mac TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, device_mac)
TTL timestamp + INTERVAL 7 DAY;

-- Time patterns (learned behaviors)
CREATE TABLE time_patterns (
    device_mac String,
    day_of_week UInt8,            -- 0-6 (Monday-Sunday)
    hour_of_day UInt8,            -- 0-23
    typical_state Enum8('online' = 1, 'offline' = 2, 'active' = 3, 'idle' = 4),
    confidence Float32,
    last_updated DateTime DEFAULT now(),

    INDEX idx_device device_mac TYPE bloom_filter GRANULARITY 1
) ENGINE = ReplacingMergeTree(last_updated)
ORDER BY (device_mac, day_of_week, hour_of_day);
```

---

## API Endpoints

### Identity Engine API (port 8060)

```
GET  /api/v1/devices                 # List all known devices
GET  /api/v1/devices/{mac}           # Get device by MAC
POST /api/v1/devices/{mac}/label     # Set human label
GET  /api/v1/bubbles                 # List all bubbles (user groups)
GET  /api/v1/bubbles/{id}/devices    # Devices in a bubble
POST /api/v1/bubbles/{id}/name       # Rename bubble
GET  /api/v1/presence                # Current presence snapshot
```

### Narrative Engine API (n8n webhooks)

```
POST /webhook/new-device             # Triggered when new device joins
POST /webhook/threat-detected        # Triggered by Suricata alert
POST /webhook/device-offline         # Triggered when device disconnects
POST /webhook/performance-alert      # Triggered by QoS degradation
```

### Dashboard API (Grafana data sources)

```
GET  /api/v1/narratives?limit=20     # Recent narratives for feed
GET  /api/v1/health-score            # Current overall health
GET  /api/v1/ambient-state           # CALM/CURIOUS/ALERT
GET  /api/v1/quick-actions           # Available one-touch actions
POST /api/v1/quick-actions/{id}      # Execute action
```

---

## Installation Flow

```bash
# During Fortress install
sudo ./install.sh

# ... standard prompts ...

# AIOCHI prompt
┌─────────────────────────────────────────────────────────────────────┐
│                                                                      │
│   🔭 Do you want EYES on your network?                              │
│                                                                      │
│   AIOCHI (AI Eyes) provides:                                        │
│   • Visual presence map (who's home)                                │
│   • Human-readable network feed                                     │
│   • One-touch actions (pause internet, game mode)                   │
│   • Performance health score                                        │
│                                                                      │
│   This adds ~2GB RAM usage.                                         │
│                                                                      │
│   Install AIOCHI? [Y/n]:                                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

# If yes, deploy AIOCHI stack
podman-compose --profile aiochi up -d
```

---

## File Structure

```
shared/aiochi/
├── ARCHITECTURE.md              # This document
├── __init__.py
├── backend/
│   ├── __init__.py
│   ├── identity_engine.py       # Device fingerprint → identity
│   ├── narrative_engine.py      # Event → human sentence
│   ├── presence_tracker.py      # Bubble presence detection
│   ├── performance_scorer.py    # Health score calculation
│   ├── time_patterns.py         # Behavioral pattern learning
│   ├── ambient_state.py         # CALM/CURIOUS/ALERT state machine
│   └── quick_actions.py         # One-touch action executor
├── containers/
│   ├── podman-compose.aiochi.yml
│   ├── Containerfile.identity
│   ├── Containerfile.narrative
│   └── configs/
│       ├── clickhouse/
│       ├── grafana/
│       ├── suricata/
│       └── zeek/
├── schemas/
│   ├── clickhouse-init.sql      # ClickHouse table definitions
│   └── grafana-dashboards/      # Pre-built dashboard JSON
├── personas/
│   ├── parent.yaml              # Parent persona config
│   ├── gamer.yaml               # Gamer persona config
│   ├── remote_worker.yaml       # Remote worker config
│   └── privacy_conscious.yaml   # Privacy-focused config
├── templates/
│   ├── narratives.yaml          # Pre-built narrative templates
│   └── actions.yaml             # Quick action definitions
├── n8n-workflows/
│   ├── new-device-narrative.json
│   ├── threat-narrative.json
│   └── performance-narrative.json
└── tests/
    ├── test_identity_engine.py
    ├── test_narrative_engine.py
    └── test_presence_tracker.py
```

---

## Integration with Existing Components

### From Fortress (standalone, always running)

| Component | Provides to AIOCHI | API Endpoint |
|-----------|-------------------|--------------|
| QSecBit | Threat events, RAG status | `localhost:9090/stats` |
| dnsXai | Blocked domains, privacy threats | `localhost:8053/stats` |
| Device Trust Framework | Trust levels (L0-L4) | Via device_manager.py |
| Ecosystem Bubble | Same-user clusters | Via ecosystem_bubble.py |

### To Fortress (AIOCHI writes back)

| Data | Destination | Purpose |
|------|-------------|---------|
| Device labels | device_identities table | Human names for devices |
| Presence state | presence_snapshots table | Who's home tracking |
| Narratives | narratives table | Event feed |
| Quick actions | OVS + nftables | Network changes |

---

## Security Considerations

1. **AIOCHI is read-heavy, write-light** - primarily observes, rarely modifies
2. **Quick Actions require confirmation** - no accidental network changes
3. **LLM calls are optional** - templates work offline
4. **No PII in narratives** - device labels, not user data
5. **ClickHouse access is internal only** - no external exposure

---

## Future Enhancements

1. **Voice Integration** - Web Speech API for queries
2. **Mobile PWA** - Installable home screen app
3. **Family Profiles** - Per-user dashboards
4. **Anomaly Detection** - "This is unusual for Dad's phone"
5. **Predictive Insights** - "Your internet might slow down during the game tonight"
6. **AR Overlay** - Point phone at device to see its status

---

*AIOCHI - Your network speaks human now.*
