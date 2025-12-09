# HookProbe Cortex - Neural Command Center

**Version**: 1.0.0
**Status**: Phase 1 Active Development
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
# Terminal 1: Backend connected to real HTP mesh
cd shared/cortex/backend
python server.py --bootstrap mssp.hookprobe.com:8144

# Terminal 2: Frontend (or serve via nginx)
cd shared/cortex/frontend
python -m http.server 8080
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
│  │  - Rate limiting, compression                                        │  │
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
│  │  - Impact particles, ripples, ambient effects                        │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Animation Engine (animations.js)                                    │  │
│  │  - Breathing effects for nodes                                       │  │
│  │  - Impact bursts with particle systems                               │  │
│  │  - Ripple effects, scanlines                                         │  │
│  │  - Mesh heartbeat animation                                          │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  2D Fallback (mobile/low-end)                                        │  │
│  │  - Canvas-based flat map                                             │  │
│  │  - Same data, simplified rendering                                   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed analysis of HTP integration options.

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

### Premium Effects

| Effect | Description |
|--------|-------------|
| **Breathing Nodes** | Nodes pulse based on Qsecbit status |
| **Impact Bursts** | Particle explosions on attack/repel |
| **Ripple Effects** | Expanding rings from events |
| **Scanlines** | Subtle scanning animation overlay |
| **Ambient Glow** | Global threat level colors the scene |
| **Mesh Heartbeat** | Periodic pulse across all nodes |

---

## File Structure

```
shared/cortex/
├── README.md                 # This file
├── ARCHITECTURE.md           # HTP integration analysis
├── backend/
│   ├── __init__.py
│   ├── requirements.txt      # Python dependencies
│   ├── server.py             # WebSocket server
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
    └── test_globe_backend.py
```

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

### Phase 1C: Production Integration (Next)
- [ ] Connect to real `core/htp/`
- [ ] Live Qsecbit updates
- [ ] Guardian dashboard embedding
- [ ] MSSP dashboard embedding

### Phase 2: Advanced Features
- [ ] HTP-over-WebRTC (P2P to nearby nodes)
- [ ] 8K Earth textures
- [ ] Night lights layer
- [ ] 3D attack trajectory arcs

### Phase 3: WASM Client
- [ ] Browser as mesh node
- [ ] Local threat processing

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
