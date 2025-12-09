# HookProbe Globe: Digital Twin Visualization

**Status**: Phase 1 Development (2026 Side Project)
**Version**: 0.2.0

---

## Vision: From Dashboard to Digital Twin

This isn't a dashboard that shows data *about* the mesh.
This **IS** the mesh, visualized.

| Dashboard (what we're NOT building) | Digital Twin (what we ARE building) |
|-------------------------------------|-------------------------------------|
| Shows data about nodes | Shows the nodes themselves |
| WebSocket for data transport | HTP-native, WebSocket only for last mile |
| Generic visualizations | Node pulse synced to actual heartbeat |
| Passive observer | Bridge is a mesh participant |
| Approximation of state | True reflection of state |

Every Sentinel, Guardian, Fortress, and Nexus has a living twin on the globe.
When a node's heart beats, its twin pulses. When a node blocks an attack,
you see the arc fade from red to blue at its location.

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
│  │  WebSocket Gateway (last mile to browser)                            │  │
│  │  - Broadcasts state changes to connected browsers                    │  │
│  │  - Sends full snapshot on connect                                    │  │
│  │  - Rate limiting, compression                                        │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
                                             │ WebSocket
                                             ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                              Browser                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Globe.gl (Three.js wrapper)                                         │  │
│  │  - 3D Earth with high-res textures                                   │  │
│  │  - Node points with breathing pulse (synced to heartbeat)            │  │
│  │  - Attack arcs (red=detected, blue=repelled)                         │  │
│  │  - Mesh topology lines (optional)                                    │  │
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

## Quick Start

### Demo Mode (No Mesh Required)

```bash
# Terminal 1: Backend with simulated events
cd visualization/globe/backend
pip install -r requirements.txt
python server.py --demo

# Terminal 2: Frontend
cd visualization/globe/frontend
python -m http.server 8080
# Open http://localhost:8080
```

### Production Mode (Connected to Mesh)

```bash
# Terminal 1: Backend connected to real HTP mesh
cd visualization/globe/backend
python server.py --bootstrap mssp.hookprobe.com:8144

# Terminal 2: Frontend (or serve via nginx)
cd visualization/globe/frontend
python -m http.server 8080
```

---

## Visual Design: Canvas, Not Dashboard

The goal is a visualization you want to *stare at*, not just glance at.

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
| **Attack Detected** | Red particle stream from attacker to target |
| **Attack Repelled** | Stream turns blue, particles explode at target |
| **Active Attack** | Target node glows brighter (attention level) |

---

## Digital Twin Data Model

### NodeTwin (What the browser knows)

```python
@dataclass
class NodeTwin:
    # Identity
    node_id: str              # "guardian-sf-001"
    tier: NodeTier            # sentinel | guardian | fortress | nexus

    # Geographic
    lat: float
    lng: float
    label: str                # "San Francisco"

    # Health (from Qsecbit)
    qsecbit_score: float      # 0.0 - 1.0
    qsecbit_status: str       # green | amber | red

    # Liveness (from HTP heartbeat)
    last_heartbeat: datetime
    online: bool

    # Visual state
    pulse_phase: float        # Synced to heartbeat
    attention_level: float    # 0=normal, 1=under attack
```

### Events

| Event Type | Visual Effect |
|------------|---------------|
| `node_online` | Node materializes with ripple |
| `node_offline` | Node dims, then fades |
| `qsecbit_threshold` | Color transition animation |
| `attack_detected` | Red arc from source to target |
| `attack_repelled` | Arc turns blue |

---

## File Structure

```
visualization/globe/
├── README.md                 # This file
├── ARCHITECTURE.md           # Detailed architecture analysis
├── backend/
│   ├── __init__.py
│   ├── requirements.txt      # Python dependencies
│   ├── server.py             # WebSocket server
│   ├── htp_bridge.py         # HTP mesh participant
│   ├── node_registry.py      # Digital twin state
│   ├── data_collector.py     # Legacy collectors
│   ├── demo_data.py          # Simulated events
│   └── geo_resolver.py       # IP geolocation
├── frontend/
│   ├── index.html            # Main page
│   ├── css/globe.css         # Styling
│   ├── js/
│   │   ├── globe.js          # Globe.gl
│   │   ├── data-stream.js    # WebSocket client
│   │   ├── animations.js     # Effects
│   │   └── fallback-2d.js    # Mobile fallback
│   └── assets/               # Textures
└── tests/
    └── test_globe_backend.py
```

---

## Roadmap

### Phase 1A: Smart Bridge (Current)
- [x] Basic folder structure
- [x] WebSocket server skeleton
- [x] Globe.gl frontend skeleton
- [x] 2D mobile fallback
- [x] Demo data generator
- [x] Architecture documentation
- [x] Node registry (digital twin state)
- [x] HTP bridge skeleton
- [ ] Connect to real `core/htp/`
- [ ] Qsecbit live updates

### Phase 1B: Visual Quality
- [ ] High-res Earth textures (8K)
- [ ] Night lights layer
- [ ] Node breathing animation
- [ ] Attack particle streams
- [ ] Smooth transitions

### Phase 2: HTP-over-WebRTC
- [ ] Direct P2P to nearby nodes

### Phase 3: WASM Client
- [ ] Browser as mesh node

---

## Why HTP, Not Just WebSocket?

WebSocket makes the globe a *passive observer*. Events are translated
and lose their mesh semantics.

With HTP Bridge:
1. Bridge is a **full mesh participant**
2. Events flow **natively** through the bridge
3. WebSocket is only the **last mile**

The globe becomes a window INTO the mesh, not a separate system.

---

## Dependencies

### Backend
- Python 3.9+
- websockets >= 12.0
- aiohttp >= 3.9.0
- geoip2 >= 4.8.0 (optional)

### Frontend
- Globe.gl (CDN)
- No build step required

---

## License

Part of HookProbe - see root LICENSE file.

*One node's detection -> Everyone's protection*
