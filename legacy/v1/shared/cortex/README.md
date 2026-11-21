# HookProbe Cortex - Neural Command Center

> **Transparency You Can See - Security Visualization That Empowers**

**Version**: 3.0.0
**Status**: Phase 3 Complete - Fleet Management & Premium Visual Effects
**Tagline**: *See your mesh. Command your defense.*

---

## Why Visualization Matters for Transparency

Transparent security isn't just about open source code - it's about visibility. Cortex makes your entire defense mesh visible, understandable, and controllable.

**Without Cortex:** "You're protected" (trust us)
**With Cortex:** *Watch* threats arrive from across the world and see them blocked in real-time

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

### Smart Clustering (Phase 1)
- **Supercluster-based clustering** - dynamically groups nearby nodes
- **Zoom-responsive rendering** - clusters expand/collapse on zoom
- **Click-to-drill-down** - click clusters to zoom and expand
- **Breadcrumb navigation** - track your position in the mesh
- **Keyboard shortcuts** - +/- zoom, Escape reset, Backspace back

### City-Level Map View (Phase 2)
- **Deck.gl GPU-accelerated rendering** - smooth transitions at any scale
- **MapLibre GL basemap** - free, open-source dark theme
- **Building footprints** - see nodes in city context (zoom 13+)
- **Street-level detail** - navigate to individual nodes
- **Smooth globe-to-map transition** - seamless zoom experience
- **Node search** - find nodes by name or tier (Ctrl+F)
- **Filter panel** - filter by tier, status, or online state
- **Mini-map** - overview of current viewport
- **Node popups** - detailed info on click

### Fleet Management (Phase 3)
- **Multi-tenant access control** - Global Admin, Fleet Admin, End User
- **Global Admin "God View"** - see ALL endpoints across ALL customers
- **Fleet Admin view** - see only your organization's devices
- **City-level clustering** - IP-based geolocation, city-level accuracy
- **User-declared locations** - precise locations visible only to fleet admins
- **Department breakdown** - organizational structure visualization
- **Device search and filtering** - find devices by name, tier, status
- **Bulk actions** - select and focus on multiple devices
- **Customer selector** - filter by customer (global admin only)

### Enhanced Heartbeat System (Phase 3)
- **RAG-based pulse speed** - faster heartbeat = more critical status
- **Double-bump heartbeat curve** - realistic heart rhythm animation
- **Status transition effects** - ripple and flash on status change
- **Mesh sync breathing** - collective pulse across all nodes
- **Interpolated colors** - smooth Qsecbit value gradients

### Premium Visual Effects (Phase 3)
- **Connection mesh lines** - animated data flow between nodes
- **Connection quality indicators** - latency/bandwidth visualization
- **Attack type styling** - unique visuals per attack type (DDoS, malware, etc.)
- **Severity-based intensity** - more severe = more dramatic effects
- **Impact particle effects** - burst animation on attack impact
- **Repelled celebration** - shield burst for blocked attacks

### Real-Time Monitoring
- **Node health** via Qsecbit color coding (green/amber/red)
- **Tier-based visualization** (Sentinel → Guardian → Fortress → Nexus)
- **Live attack tracking** from source to target
- **Event log feed** with real-time updates

### Demo/Live Toggle
- **Demo Mode**: Simulated events for showcasing
- **Live Mode**: Real HTP mesh data (when connected)

---

## Understanding Your Security Fabric

### The Journey from Global to Local

Cortex transforms abstract security metrics into **spatial understanding**. Your security fabric isn't just data—it's a physical network of devices protecting real locations.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ZOOM LEVEL        WHAT YOU SEE              WHAT YOU UNDERSTAND            │
├─────────────────────────────────────────────────────────────────────────────┤
│  Globe (1-4)       Continents, clusters      Global threat landscape        │
│                    "5 attacks from Asia"     Where threats originate        │
│                                                                             │
│  Region (5-8)      Countries, cities         Regional defense posture       │
│                    "London cluster: 12       Which regions need attention   │
│                     nodes, all green"                                       │
│                                                                             │
│  City (9-12)       Districts, buildings      Local network topology         │
│                    "3 Guardians in           How your offices are protected │
│                     Financial District"                                     │
│                                                                             │
│  Street (13+)      Individual nodes          Device-level security status   │
│                    "Reception Guardian:      Specific device health         │
│                     Qsecbit 0.32, GREEN"                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why City-Level View Matters

**1. See Your Actual Network**
Traditional dashboards show lists and charts. Cortex shows your Guardian protecting the hotel WiFi in Tokyo, your Fortress securing the London office, your Sentinels monitoring the warehouse in São Paulo. Security becomes *real*.

**2. Understand Geographic Risk**
When you zoom into a city, you see:
- How many nodes protect that location
- Their current health status (green/amber/red)
- Attack patterns targeting that region
- Coverage gaps that need attention

**3. Respond to Incidents Faster**
When an attack hits:
- See exactly which device is under attack
- Understand the physical location instantly
- Know what other devices are nearby to help
- Watch the mesh respond in real-time

**4. Plan Better Deployments**
City view reveals:
- Clustering of protection (too many nodes in one place?)
- Coverage gaps (unprotected branch offices?)
- Network topology (how nodes connect)
- Department distribution (IT vs. Operations vs. Executive)

### The Security Fabric Visualization

Your "security fabric" is the mesh of HookProbe nodes working together. Cortex makes this visible:

```
                    ┌─────────────────────────────────────────┐
                    │           GLOBAL VIEW                    │
                    │     See the entire mesh at once          │
                    │     • 1,247 nodes across 6 continents    │
                    │     • Real-time attack trajectories      │
                    │     • Collective defense in action       │
                    └─────────────────┬───────────────────────┘
                                      │ Zoom In
                                      ▼
                    ┌─────────────────────────────────────────┐
                    │           CITY VIEW                      │
                    │     See your local deployment            │
                    │     • Individual building placement      │
                    │     • Street-level node locations        │
                    │     • Local mesh connections             │
                    └─────────────────┬───────────────────────┘
                                      │ Click Node
                                      ▼
                    ┌─────────────────────────────────────────┐
                    │           NODE DETAIL                    │
                    │     See device-specific data             │
                    │     • Qsecbit score and history          │
                    │     • Recent threats blocked             │
                    │     • Connection quality                 │
                    │     • Last heartbeat time                │
                    └─────────────────────────────────────────┘
```

### Practical Use Cases

| Scenario | How Cortex Helps |
|----------|------------------|
| **Executive briefing** | Zoom to globe view, show global threat landscape and mesh responding |
| **Incident response** | Zoom to affected city, see attack in context, identify nearby nodes |
| **Compliance audit** | Show coverage of protected locations, demonstrate defense-in-depth |
| **Capacity planning** | Identify geographic gaps, plan new node deployments |
| **Travel security** | Zoom to destination city, see local protection status before arrival |
| **Remote office check** | Zoom to branch office, verify Guardian is healthy and protecting |

### From "Are We Protected?" to "Watch Us Protect"

**Before Cortex:**
> "The security dashboard says we blocked 89 attacks today."

**With Cortex:**
> "Watch this DDoS from Beijing hit our Tokyo Guardian. See the red arc? Now watch it turn blue—blocked in 3ms. The mesh just shared that threat signature with all 1,247 nodes worldwide. Every HookProbe device now recognizes that attack pattern."

This is the difference between *believing* you're protected and *seeing* your protection work.

---

### Production Integration (Phase 1C)
- **HTP Bridge**: Full connection to core/htp/ protocol
- **Live Qsecbit**: Real-time score updates from mesh nodes
- **Guardian Embedding**: Integrated into Guardian Flask web UI
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
# Connect to mesh network
python server.py --bootstrap mesh.hookprobe.com:8144 --node-id cortex-prod-001

# Or connect to local Guardian
python server.py --bootstrap localhost:8144 --node-id cortex-local

# With geographic location
python server.py --bootstrap mesh.hookprobe.com:8144 \
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
                              │  Nexuses                            │
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

---

## Demo Data (Phase 3 Enterprise Scale)

Demonstrates collective defense value with enterprise-scale deployment.

### Organizations (5 demo tenants)
| Organization | Industry | Tier | Nodes |
|--------------|----------|------|-------|
| ACME Corporation | Technology | Enterprise | 15 |
| Globex Industries | Manufacturing | Professional | 12 |
| Initech Systems | Financial Services | Enterprise | 15 |
| Wayne Enterprises | Conglomerate | Enterprise | 18 |
| Stark Industries | Defense/Technology | Enterprise | 15 |

### Nodes (75+ total across organizations)
| Tier | Count | Example Locations |
|------|-------|-------------------|
| Guardian | 25+ | SF, NYC, London, Tokyo, Sydney, Mumbai |
| Fortress | 15+ | Ashburn DC, Frankfurt, Singapore, São Paulo |
| Sentinel | 25+ | Lobby sensors, server rooms, edge IoT |
| Nexus | 10+ | ML clusters, AI compute nodes |

### Threat Sources (35+ locations with threat profiles)
| Threat Level | Regions | Profile |
|--------------|---------|---------|
| Critical | China (Beijing, Shanghai), Russia (Moscow), N. Korea | Nation State |
| High | Iran (Tehran), Vietnam, Ukraine | Criminal/Hacktivist |
| Medium | SE Asia, Eastern Europe | Criminal Syndicate |
| Low | Various | Script Kiddie |

### Attack Types (25+ types with categories)
| Category | Types | Weight |
|----------|-------|--------|
| DDoS | Volumetric, Amplification, Slowloris, App-layer | High |
| Credential | Brute force, Stuffing, Phishing | High |
| Malware | C2, Ransomware, Cryptominer, Botnet | Medium |
| Web | SQLi, XSS, RFI/LFI, Path traversal, CSRF, XXE | Medium |
| Scan | Port scan, Vuln scan, Service enumeration | High |
| API | Abuse, Broken auth, IDOR | Medium |
| Advanced | Zero-day, Supply chain, Unknown exploit | Low |

### Mitigation Methods (12 types with response times)
| Method | Min Response | Max Response |
|--------|-------------|--------------|
| `xdp_drop` | 1ms | 10ms |
| `rate_limit` | 5ms | 30ms |
| `geo_block` | 2ms | 15ms |
| `signature_match` | 10ms | 50ms |
| `ml_detection` | 15ms | 80ms |
| `anomaly_block` | 20ms | 100ms |
| `reputation_block` | 5ms | 25ms |
| `behavior_block` | 25ms | 150ms |
| `captcha_challenge` | 50ms | 200ms |
| `honeypot_redirect` | 30ms | 120ms |
| `waf_block` | 8ms | 40ms |
| `threat_intel_block` | 3ms | 20ms |

### Collective Defense Visualization
The demo shows how attacks on one organization trigger mesh-wide intelligence sharing:
- **Campaign tracking** - Coordinated attacks visible across targets
- **Mesh connections** - Real-time data flow between nodes
- **Threat propagation** - Watch as threat intel spreads through the mesh

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
├── PHASE2-CITY-VIEW.md       # Phase 2 architecture documentation
├── backend/
│   ├── __init__.py
│   ├── requirements.txt      # Python dependencies
│   ├── server.py             # WebSocket + REST server
│   ├── htp_bridge.py         # HTP mesh participant
│   ├── node_registry.py      # Digital twin state + cluster support
│   ├── demo_data.py          # Simulated events
│   ├── geo_resolver.py       # IP geolocation
│   ├── fleet_manager.py      # Phase 3: Fleet management & access control
│   └── connectors/           # Product integrations
│       ├── base.py           # ProductConnector base
│       ├── manager.py        # ConnectorManager
│       ├── guardian.py       # Guardian Flask
│       ├── fortress.py       # Fortress DSM
│       └── nexus.py          # Nexus ML/AI
├── frontend/
│   ├── index.html            # Cortex main page
│   ├── css/
│   │   ├── globe.css         # Premium styling + cluster styles
│   │   ├── city-view.css     # Phase 2: City view styling
│   │   └── fleet-panel.css   # Phase 3: Fleet panel styling
│   └── js/
│       ├── globe.js          # Globe.gl visualization
│       ├── data-stream.js    # WebSocket client
│       ├── animations.js     # Premium effects engine
│       ├── fallback-2d.js    # Mobile fallback
│       ├── cluster-manager.js    # Phase 1: Supercluster clustering
│       ├── zoom-controller.js    # Phase 1: Camera control
│       ├── transitions.js        # Phase 1: Cluster animations
│       ├── deck-renderer.js      # Phase 2: Deck.gl renderer
│       ├── basemap-config.js     # Phase 2: MapLibre configuration
│       ├── view-manager.js       # Phase 2: Globe ↔ Map transitions
│       ├── city-view.js          # Phase 2: City-level UI
│       ├── fleet-panel.js        # Phase 3: Fleet management UI
│       ├── heartbeat-system.js   # Phase 3: Enhanced heartbeat effects
│       ├── mesh-connections.js   # Phase 3: Connection visualization
│       └── attack-vectors.js     # Phase 3: Enhanced attack animations
└── tests/
    ├── test_globe_backend.py     # Backend unit tests
    ├── test_phase2_city_view.py  # Phase 2 tests
    └── test_fleet_manager.py     # Phase 3: Fleet management tests
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
- [x] Product connectors (Guardian, Fortress, Nexus)

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
- [x] Dashboard embedding
- [x] Expanded demo data (+30% nodes, threats, attack types)
- [x] REST API for configuration
- [x] Integration tests

### Phase 2: City-Level Map View ✅
- [x] Supercluster-based node clustering
- [x] Zoom-responsive cluster expansion
- [x] Breadcrumb navigation and zoom controls
- [x] Deck.gl GPU-accelerated renderer
- [x] MapLibre GL basemap integration
- [x] Custom dark theme with streets/buildings
- [x] Smooth globe-to-map transitions
- [x] Node search and filtering
- [x] City-level UI (popups, mini-map, filters)

### Phase 3: Fleet Management & Premium Effects ✅
- [x] Multi-tenant access control (Global Admin, Fleet Admin, End User)
- [x] Fleet management backend with customer/device models
- [x] Global Admin "God View" - all endpoints, all customers
- [x] City-level clustering with IP-based geolocation
- [x] User-declared locations (fleet-only visibility)
- [x] Enhanced heartbeat system with RAG-based pulse
- [x] Connection mesh lines between nodes
- [x] Premium attack vector animations
- [x] Attack type-specific styling (DDoS, malware, etc.)
- [x] Fleet overview panel UI
- [x] Device search and filtering
- [x] Department breakdown visualization

### Phase 4: Advanced Features (Planned)
- [ ] DSM consensus visualization
- [ ] Neural resonance display
- [ ] HTP-over-WebRTC (P2P to nearby nodes)
- [ ] 8K Earth textures
- [ ] Night lights layer
- [ ] 3D attack trajectory arcs
- [ ] Threat prediction overlays

### Phase 5: WASM Client (Future)
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

### Frontend (all loaded from CDN)
- Globe.gl 2.27+ (3D globe rendering)
- Supercluster 8.0+ (spatial clustering)
- KDBush 4.0+ (spatial indexing)
- Deck.gl 8.9+ (GPU-accelerated visualization)
- MapLibre GL 3.6+ (basemap tiles)
- Google Fonts (Orbitron, Rajdhani)
- No build step required

---

## The Cortex Difference

| Traditional Dashboards | Cortex |
|-----------------------|--------|
| Shows data *about* security | Shows security *as it happens* |
| Static snapshots | Real-time streaming |
| Abstract metrics | Geographic reality |
| Vendor black box | Open source visualization |
| "Trust us" | "See for yourself" |

**Cortex turns transparency into something you can see, understand, and trust.**

---

## License

Part of HookProbe v5.0 "Cortex" - see root LICENSE file.

**HookProbe Cortex - Neural Command Center**
*See your mesh. Command your defense. Achieve more.*
