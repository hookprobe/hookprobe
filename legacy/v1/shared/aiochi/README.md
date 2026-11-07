# AIOCHI - AI Eyes (AI OCHII)

*"Your network speaks human now."*

**Version**: 1.0.0
**License**: Proprietary (Commercial License Required for SaaS/OEM)

---

## What is AIOCHI?

AIOCHI (AI Eyes, from Romanian "AI OCHII") is a **Cognitive Network Layer** that transforms the complexity of SDN, IDS/IPS, and cybersecurity into a **narrative that anyone can understand**.

Think of AIOCHI as the nervous system that feels your network and translates its sensations into human language.

## The Three Pillars

### 1. PRESENCE - "Who's Home"

Visual bubbles showing device groups:
- "Dad's Bubble": iPhone, MacBook, Apple Watch
- "Kids' Bubble": iPad, Nintendo Switch
- Same-user detection via ML clustering

### 2. PRIVACY - "What's Happening"

A Facebook-style feed of network events in plain English:
- ✅ "10:00 AM: The HomePod updated its software successfully."
- 🔒 "10:30 AM: I blocked a suspicious connection from Russia. Your camera is safe."
- 📱 "10:15 AM: A new device 'Guest_Laptop' joined the Guest WiFi."

### 3. PERFORMANCE - "How Fast"

A single health score (0-100) with AI insights:
- "Score: 85. The microwave in the kitchen is currently slowing down the HomePod."

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Ambient Mode** | Single green shield when everything's OK - zero attention required |
| **Persona-Aware Narratives** | Different tones for parents, gamers, remote workers |
| **One-Touch Actions** | "Pause Kids' Internet", "Game Mode", "Privacy Mode" |
| **Time-Pattern Learning** | "Dad usually arrives at 6:30 PM" anomaly detection |
| **Template-First Translation** | Fast, works offline (LLM fallback for complex events) |

---

## Installation

AIOCHI is installed as part of HookProbe Fortress:

```bash
sudo ./install.sh

# When prompted:
# 🔭 Do you want EYES on your network? [Y/n]: Y
```

This installs the AIOCHI stack:
- ClickHouse (event storage)
- NAPSE + AEGIS (AI-native IDS + orchestration)
- Identity Engine (device fingerprinting)
- Bubble Manager (ecosystem detection)
- Log Shipper (data pipeline)
- n8n (workflow automation) - optional
- Ollama (local LLM for AI narratives) - optional

Note: Visualization is handled by Fortress AdminLTE web UI (no Grafana needed).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       AIOCHI DATA PIPELINE                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  CAPTURE         STORE          ENRICH         TRANSLATE    DISPLAY  │
│  ┌─────┐       ┌─────┐       ┌─────┐         ┌─────┐       ┌─────┐  │
│  │NAPSE│──────▶│Click│──────▶│Ident│────────▶│n8n/ │──────▶│Admin│  │
│  │AEGIS│       │House│       │ity  │         │Templ│       │LTE  │  │
│  │     │       │     │       │     │         │ates │       │ UI  │  │
│  └─────┘       └─────┘       └─────┘         └─────┘       └─────┘  │
│                                                                      │
│  Raw Packets → Structured   → Device Labels → Human       → Fortress │
│               History        "Dad's iPhone"   Sentences     Web UI   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Components

### Backend (Python)

| File | Purpose |
|------|---------|
| `backend/identity_engine.py` | Device fingerprint → identity |
| `backend/narrative_engine.py` | Event → human sentence |
| `backend/presence_tracker.py` | Bubble presence detection |
| `backend/performance_scorer.py` | Health score calculation |
| `backend/ambient_state.py` | CALM/CURIOUS/ALERT state machine |
| `backend/quick_actions.py` | One-touch action executor |

### Containers

| Container | Purpose | Required |
|-----------|---------|----------|
| `aiochi-clickhouse` | Event analytics database | Core |
| `aiochi-napse` | Neural Adaptive Packet Synthesis Engine | Core |
| `aiochi-aegis` | Autonomous AI Orchestrator | Core |
| `aiochi-identity` | Device fingerprinting | Core |
| `aiochi-bubble` | Ecosystem detection | Core |
| `aiochi-logshipper` | Data pipeline | Core |
| `aiochi-narrative` | n8n workflow engine | Optional |
| `aiochi-ollama` | Local LLM for AI narratives | Optional |

---

## Quick Start

### Python API

```python
from shared.aiochi import IdentityEngine, NarrativeEngine

# Identify a device
identity = IdentityEngine()
device = identity.enrich(mac="00:1E:C2:12:34:56", hostname="iPhone-Dad")
print(device.human_label)  # "iPhone"

# Translate an event
narrative = NarrativeEngine(persona="parent")
story = narrative.translate(event)
print(story.narrative)  # "I blocked a suspicious connection. Your device is safe!"
```

### CLI

```bash
# Start AIOCHI containers
cd /opt/hookprobe/shared/aiochi/containers
podman-compose -f podman-compose.aiochi.yml up -d

# Access Fortress dashboard (includes AIOCHI visualization)
open https://localhost:8443  # Fortress AdminLTE web UI
```

---

## Configuration

### Personas

Configure narrative tone in `/etc/hookprobe/aiochi.conf`:

```yaml
persona: parent  # parent, gamer, worker, privacy
```

### Quick Actions

Available one-touch actions:

| Action | Effect |
|--------|--------|
| `pause_kids` | Block kids' bubble internet |
| `game_mode` | Prioritize gaming traffic |
| `privacy_mode` | Block all tracking domains |
| `boost_device` | QoS priority for device |
| `guest_lockdown` | Isolate guest network |

---

## Integration

### With Fortress

AIOCHI integrates with existing Fortress components:
- **QSecBit**: Threat detection feeds narratives
- **dnsXai**: Blocked domains contribute to privacy feed
- **Ecosystem Bubble**: Device clustering for presence
- **SLA AI**: WAN status feeds performance insights

### With External Systems

- **Webhook API**: POST events to `/webhook/new-device`
- **ClickHouse API**: Query events via HTTP (port 8123)
- **n8n Workflows**: Extend with custom automations

---

## Development

### Running Tests

```bash
pytest shared/aiochi/tests/ -v
```

### Adding Narrative Templates

Edit `templates/narratives.yaml`:

```yaml
new_device:
  parent:
    - "A new device '{device_label}' just joined your network!"
    - "Welcome! '{device_label}' is now connected."
```

---

## License

AIOCHI is **proprietary** software. Commercial license required for:
- SaaS/managed service offerings
- OEM/embedded product distribution

Free for:
- Personal/home use
- Internal business protection

Contact: qsecbit@hookprobe.com

---

*AIOCHI - Less is more for everyone, but powerful monitoring underneath.*
