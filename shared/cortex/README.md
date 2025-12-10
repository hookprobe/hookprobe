# HookProbe Cortex - Neural Command Center

**Version**: 1.0.0
**Status**: Phase 1C Complete - Production Integration
**Tagline**: *See your mesh. Command your defense.*

---

## What is Cortex?

HookProbe Cortex is the **Neural Command Center** - a real-time 3D digital twin of the entire HookProbe defense mesh. This isn't a dashboard that shows data *about* the mesh. This **IS** the mesh, visualized.

```
┌─────────────────────────────────────────────────────────────────┐
│                     HOOKPROBE CORTEX                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                                                             ││
│  │           ⬡ Nexus (ML/AI)        Attack Arc →               ││
│  │              ↓                        ↓                     ││
│  │    ⬡ Guardian ←───── Mesh ─────→ ⬡ Fortress                 ││
│  │              ↓                        ↓                     ││
│  │         ⬡ Sentinel (IoT)      ← Repelled Arc                ││
│  │                                                             ││
│  │  [NODES: 1,247]  [ATTACKS: 89]  [REPELLED: 89]  [QSECBIT]  ││
│  └─────────────────────────────────────────────────────────────┘│
│         Real-time 3D globe with attack trajectories              │
└─────────────────────────────────────────────────────────────────┘
```

| Dashboard (what we're NOT building) | Digital Twin (what we ARE building) |
|-------------------------------------|-------------------------------------|
| Shows data about nodes | Shows the nodes themselves |
| WebSocket for data transport | HTP-native, WebSocket only for last mile |
| Generic visualizations | Node pulse synced to actual heartbeat |
| Passive observer | Bridge is a mesh participant |
| Approximation of state | True reflection of state |

---

## Features

### Premium Visual Experience
- **3D Globe.gl rendering** with high-quality Earth textures
- **Breathing node animations** synced to Qsecbit status
- **Attack arc trajectories** - red for incoming, blue for repelled
- **Particle impact effects** on attack targets
- **Ripple effects** for mesh events
- **Mesh heartbeat** visualization
- **Ambient threat overlay** based on global threat level
- **Scanline effects** for cyberpunk aesthetic

### Real-Time Monitoring
- **Node health** via Qsecbit color coding (green/amber/red)
- **Tier-based visualization** (Sentinel → Guardian → Fortress → Nexus)
- **Live attack tracking** from source to target
- **Event log feed** with real-time updates

### Demo/Live Toggle
- **Demo Mode**: Simulated events for showcasing
- **Live Mode**: Real HTP mesh data (when connected)

### Production Integration (Phase 1C)
- **HTP Bridge**: Full connection to core/htp/ protocol
- **Live Qsecbit**: Real-time score updates from mesh nodes
- **Guardian Embedding**: Integrated into Guardian Flask web UI
- **MSSP Embedding**: Integrated into MSSP Django portal
- **Expanded Demo Data**: +30% more nodes, threats, and attack types

---

## Quick Start

### Demo Mode (No Mesh Required)

```bash
# Terminal 1: Backend with simulated events
cd shared/cortex/backend
pip install -r requirements.txt
python server.py --demo

# Terminal 2: Frontend
cd shared/cortex/frontend
python -m http.server 8080
# Open http://localhost:8080
```

### Production Mode (Connected to Mesh)

```bash
# Connect to MSSP mesh
python server.py --bootstrap mssp.hookprobe.com:8144 --node-id cortex-prod-001

# Or connect to local Guardian
python server.py --bootstrap localhost:8144 --node-id cortex-local

# With geographic location
python server.py --bootstrap mssp.hookprobe.com:8144 \
    --node-id cortex-hq --lat 37.7749 --lng -122.4194 --label "HQ Cortex"
```

### Server Options

```bash
python server.py [OPTIONS]

Options:
    --port          WebSocket port (default: 8765)
    --api-port      REST API port (default: 8766)
    --demo          Start in demo mode (can be toggled at runtime)
    --bootstrap     Bootstrap node(s) for HTP mesh (host:port,host:port)
    --node-id       Node ID for this Cortex instance
    --lat           Latitude for geographic placement
    --lng           Longitude for geographic placement
    --label         Human-readable label for this node
```

---

## Architecture

```
                              ┌─────────────────────────────────────┐
                              │         HookProbe Mesh              │
                              │  Sentinels, Guardians, Fortresses   │
                              │  Nexuses, MSSP                      │
                              └──────────────┬──────────────────────┘
                                             │ HTP Protocol (native)
                                             ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                              HTP Bridge                                     │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Full HTP Stack (from core/htp/)                                     │  │
│  │  - Connects as mesh participant (observer mode)                      │  │
│  │  - Receives heartbeats, Qsecbit updates, threat events               │  │
│  │  - Subscribes to DSM gossip for mesh-wide intelligence               │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    ↓                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Node Registry (Digital Twin State)                                  │  │
│  │  - NodeTwin objects for each mesh node                               │  │
│  │  - Geographic coordinates, Qsecbit history, liveness                 │  │
│  │  - Mesh topology (edges between nodes)                               │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    ↓                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Product Connectors                                                  │  │
│  │  - GuardianConnector (Flask integration)                             │  │
│  │  - FortressConnector (DSM participation)                             │  │
│  │  - NexusConnector (ML/AI metrics)                                    │  │
│  │  - MSSPConnector (Django integration)                                │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    ↓                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  WebSocket Gateway (last mile to browser)                            │  │
│  │  - Broadcasts state changes to connected browsers                    │  │
│  │  - Sends full snapshot on connect                                    │  │
│  │  - REST API for configuration                                        │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
                                             │ WebSocket
                                             ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                              Browser (Cortex)                               │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Globe.gl (Three.js wrapper)                                         │  │
│  │  - 3D Earth with premium textures                                    │  │
│  │  - Node points with breathing pulse (synced to heartbeat)            │  │
│  │  - Attack arcs (red=detected, blue=repelled)                         │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed analysis of HTP integration options.

---

## REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Server status and connection info |
| `/api/snapshot` | GET | Current mesh state snapshot |
| `/api/mode` | POST | Switch demo/live mode |
| `/api/stats` | GET | Server statistics |
| `/api/burst` | POST | Trigger demo event burst |
| `/api/health` | GET | Health check endpoint |

### Examples

```bash
# Get server status
curl http://localhost:8766/api/status

# Switch to live mode
curl -X POST http://localhost:8766/api/mode -d '{"mode": "live"}'

# Trigger attack burst (demo mode only)
curl -X POST http://localhost:8766/api/burst -d '{"count": 5}'
```

---

## Product Integration

### Guardian (Flask)

The Guardian web UI includes a Cortex module:

```python
# Already integrated in products/guardian/web/
from modules.cortex import cortex_bp
app.register_blueprint(cortex_bp)
```

**Routes:**
- `/cortex` - Full-page Cortex iframe view
- `/cortex/embedded` - Embedded tab view
- `/api/cortex/node` - Node status API
- `/api/cortex/location` - Auto-detect location from WAN IP
- `/api/cortex/events` - Recent security events
- `/api/cortex/demo/data` - Demo mesh data

### MSSP (Django)

Add the Cortex app to MSSP:

```python
# In products/mssp/web/settings.py
INSTALLED_APPS = [
    ...
    'apps.cortex',
]

# In products/mssp/web/urls.py
urlpatterns = [
    ...
    path('cortex/', include('apps.cortex.urls')),
]
```

**Routes:**
- `/cortex/` - Full Cortex page
- `/cortex/embedded/` - Embedded dashboard view
- `/cortex/fullscreen/` - Fullscreen mode
- `/cortex/api/status/` - Status API
- `/cortex/api/nodes/` - All managed nodes
- `/cortex/api/events/` - Security events
- `/cortex/api/mode/` - Demo/Live mode toggle

---

## Demo Data (Phase 1C Expanded)

### Nodes (19 total, +137% from original 8)
| Tier | Count | Locations |
|------|-------|-----------|
| Guardian | 4 | SF, NYC, LA, Miami |
| Fortress | 5 | London, Amsterdam, Paris, Tokyo, Hong Kong |
| Sentinel | 6 | Berlin, Singapore, Dublin, Toronto, Melbourne, Stockholm |
| Nexus | 3 | Frankfurt, Ashburn, Singapore |

### Threat Sources (23 locations, +188% from original 8)
- **China**: Beijing, Shanghai, Shenzhen, Guangzhou
- **Russia**: Moscow, St. Petersburg, Yekaterinburg
- **Iran**: Tehran
- **North Korea**: Pyongyang
- **Southeast Asia**: Seoul, Taipei, Manila, Ho Chi Minh City
- **South Asia**: Mumbai, New Delhi, Karachi
- **South America**: São Paulo, Buenos Aires
- **Africa**: Lagos, Johannesburg, Cairo
- **Eastern Europe**: Kyiv, Bucharest

### Attack Types (21 types, +250% from original 6)
| Category | Types |
|----------|-------|
| DDoS | Volumetric, Amplification, Slowloris |
| Scanning | Port scan, Vuln scan, Service enum |
| Brute Force | SSH, RDP, Credential stuffing |
| Malware | C2, Ransomware beacon, Botnet |
| Web Attacks | SQLi, XSS, RFI/LFI, Path traversal, CSRF |
| API | Abuse, Broken auth |
| Zero-Day | Indicators, Unknown exploits |

### Mitigation Methods (10 types)
- `xdp_drop` - XDP/eBPF kernel-level drop
- `rate_limit` - Rate limiting
- `geo_block` - Geographic blocking
- `signature_match` - IDS/IPS signature
- `ml_detection` - ML model detection
- `anomaly_block` - Anomaly-based blocking
- `reputation_block` - IP reputation
- `behavior_block` - Behavioral analysis
- `captcha_challenge` - CAPTCHA
- `honeypot_redirect` - Honeypot redirection

---

## Visual Design

### Node Representation

| Tier | Visual | Size | Behavior |
|------|--------|------|----------|
| **Sentinel** | Glowing dot | 0.3 radius | Subtle pulse (30s heartbeat) |
| **Guardian** | Shield sprite | 0.5 radius | Medium pulse (15s heartbeat) |
| **Fortress** | Fortress icon | 0.8 radius | Strong pulse (10s heartbeat) |
| **Nexus** | Neural network | 1.2 radius | Complex pulse (5s heartbeat) |

### Node Colors (Qsecbit Status)

| Status | Color | Qsecbit Range | Meaning |
|--------|-------|---------------|---------|
| **GREEN** | `#00ff88` | < 0.45 | Normal operations |
| **AMBER** | `#ffaa00` | 0.45 - 0.70 | Warning, Kali spinning up |
| **RED** | `#ff4444` | > 0.70 | Critical, full mitigation |

### Attack Visualization

| Event | Visual |
|-------|--------|
| **Attack Detected** | Red arc with particle stream from attacker to target |
| **Attack Repelled** | Arc turns blue, impact burst at target |
| **Active Attack** | Target node glows brighter, pulse rings emanate |

---

## File Structure

```
shared/cortex/
├── README.md                 # This file
├── ARCHITECTURE.md           # HTP integration analysis
├── backend/
│   ├── __init__.py
│   ├── requirements.txt      # Python dependencies
│   ├── server.py             # WebSocket + REST server
│   ├── htp_bridge.py         # HTP mesh participant
│   ├── node_registry.py      # Digital twin state
│   ├── demo_data.py          # Simulated events
│   ├── geo_resolver.py       # IP geolocation
│   └── connectors/           # Product integrations
│       ├── base.py           # ProductConnector base
│       ├── manager.py        # ConnectorManager
│       ├── guardian.py       # Guardian Flask
│       ├── fortress.py       # Fortress DSM
│       ├── nexus.py          # Nexus ML/AI
│       └── mssp.py           # MSSP Django
├── frontend/
│   ├── index.html            # Cortex main page
│   ├── css/globe.css         # Premium styling
│   └── js/
│       ├── globe.js          # Globe.gl visualization
│       ├── data-stream.js    # WebSocket client
│       ├── animations.js     # Premium effects engine
│       └── fallback-2d.js    # Mobile fallback
└── tests/
    └── test_globe_backend.py # Backend unit tests
```

---

## Testing

```bash
# Run all Cortex tests
pytest shared/cortex/tests/ -v

# Run with coverage
pytest shared/cortex/tests/ --cov=shared/cortex --cov-report=html
```

### Test Coverage
- Demo data generation and structure
- Geo resolver with fallbacks
- Node registry state management
- NodeTwin data model
- HTP bridge configuration
- Data integrity validation

---

## Roadmap

### Phase 1A: Core Infrastructure ✅
- [x] WebSocket server with demo/live toggle
- [x] Globe.gl frontend with Earth textures
- [x] 2D mobile fallback
- [x] Demo data generator
- [x] Node registry (digital twin state)
- [x] HTP bridge skeleton
- [x] Product connectors (Guardian, Fortress, Nexus, MSSP)

### Phase 1B: Visual Quality ✅
- [x] Premium CSS with Orbitron/Rajdhani fonts
- [x] Cortex branding (Neural Command Center)
- [x] Breathing node animations
- [x] Attack arc animations
- [x] Impact particle effects
- [x] Ripple effects
- [x] Mesh heartbeat animation
- [x] Ambient threat overlay
- [x] Scanline effects
- [x] Threat level indicator

### Phase 1C: Production Integration ✅
- [x] Connect to real `core/htp/`
- [x] Live Qsecbit updates from `core/qsecbit/`
- [x] Guardian dashboard embedding (Flask)
- [x] MSSP dashboard embedding (Django)
- [x] Expanded demo data (+30% nodes, threats, attack types)
- [x] REST API for configuration
- [x] Integration tests

### Phase 2: Advanced Features (Planned)
- [ ] DSM consensus visualization
- [ ] Neural resonance display
- [ ] HTP-over-WebRTC (P2P to nearby nodes)
- [ ] 8K Earth textures
- [ ] Night lights layer
- [ ] 3D attack trajectory arcs
- [ ] Threat prediction overlays

### Phase 3: WASM Client (Future)
- [ ] Browser as mesh node
- [ ] Local threat processing
- [ ] Offline operation mode

---

## Dependencies

### Backend
- Python 3.9+
- websockets >= 12.0
- aiohttp >= 3.9.0
- geoip2 >= 4.8.0 (optional)

### Frontend
- Globe.gl 2.27+ (CDN)
- Google Fonts (Orbitron, Rajdhani)
- No build step required

---

## License

Part of HookProbe v5.1 "Cortex" - see root LICENSE file.

**HookProbe Cortex - Neural Command Center**
*See your mesh. Command your defense.*
