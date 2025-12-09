# HookProbe Globe: Digital Twin Architecture

**Status**: Architecture Analysis
**Goal**: Transform visualization from "dashboard" to true digital twin of the mesh

---

## The Core Question: WebSocket vs HTP

### Current State (WebSocket)

```
┌─────────────┐     WebSocket      ┌─────────────┐     Internal     ┌─────────────┐
│   Browser   │◄──────────────────►│  WS Server  │◄───────────────►│   HTP Mesh  │
│  (passive)  │    (third-party)   │  (adapter)  │   (translation) │   (real)    │
└─────────────┘                    └─────────────┘                  └─────────────┘
      ↑
  Dashboard:
  "Shows data ABOUT the mesh"
```

**Problems**:
1. Browser is a passive observer, not a participant
2. WebSocket has no relationship to HTP semantics
3. Translation layer loses mesh-native metadata
4. No entropy echo, no Qsecbit drift, no resonance
5. It's a *representation*, not a *twin*

### Proposed State (HTP-Native)

```
┌─────────────┐     HTP/QUIC       ┌─────────────┐       HTP       ┌─────────────┐
│   Browser   │◄──────────────────►│  HTP Relay  │◄───────────────►│   Mesh Nodes│
│  (Sentinel) │    (mesh-native)   │  (Fortress) │   (native)      │   (all)     │
└─────────────┘                    └─────────────┘                  └─────────────┘
      ↑                                   ↑
  Digital Twin:                    Full mesh participant
  "IS the mesh, visualized"        Validates, relays, participates
```

---

## Architecture Options Analysis

### Option 1: HTP Bridge (Pragmatic - Phase 1)

**Concept**: WebSocket is the "last mile" only; bridge is a full mesh node.

```
┌────────────────────────────────────────────────────────────────────┐
│                         HTP Bridge Node                             │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                     Full HTP Stack                           │  │
│  │  - Entropy echo verification                                 │  │
│  │  - Qsecbit monitoring                                        │  │
│  │  - Neuro weight sync                                         │  │
│  │  - DSM consensus participation                               │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                              ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                  Event Transformer                           │  │
│  │  HTP events → Globe visualization events                     │  │
│  │  Preserves: timestamps, node IDs, Qsecbit, coordinates       │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                              ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                  WebSocket Gateway                           │  │
│  │  - Authenticated sessions (optional HTP-derived tokens)      │  │
│  │  - Event broadcast to connected browsers                     │  │
│  │  - Rate limiting, compression                                │  │
│  └─────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
         ↑ HTP                                    ↓ WebSocket
┌─────────────────┐                    ┌─────────────────────────────┐
│   Mesh Nodes    │                    │         Browsers            │
│ Sentinels, etc. │                    │    Globe Visualization      │
└─────────────────┘                    └─────────────────────────────┘
```

**Pros**:
- Works with current browser technology
- Bridge is a real mesh participant (not just observer)
- Events are authentic (not simulated)
- Gradual path to full HTP in browser

**Cons**:
- Browser still not a true mesh node
- Extra latency through bridge
- Centralization point (though can be replicated)

**Effort**: Medium (extends current work)

---

### Option 2: HTP-over-WebRTC (Future - Phase 2)

**Concept**: Use WebRTC data channels for HTP-like transport.

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Browser                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  HTP-lite Client (JavaScript)                                 │  │
│  │  - Simplified entropy echo (browser entropy sources)          │  │
│  │  - Qsecbit-lite (client-side only)                            │  │
│  │  - Event framing compatible with HTP                          │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              ↓                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  WebRTC Data Channel                                          │  │
│  │  - UDP-like semantics (unreliable, unordered option)          │  │
│  │  - DTLS encryption (maps to HTP's ChaCha20)                   │  │
│  │  - ICE for NAT traversal                                      │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                    ↑ WebRTC P2P (with TURN fallback)
┌─────────────────────────────────────────────────────────────────────┐
│                    HTP-WebRTC Gateway                                │
│  (Could be any Fortress/Nexus with WebRTC support)                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Pros**:
- P2P possible (browser ↔ node directly)
- UDP-like characteristics (good for real-time)
- Browser participates in NAT traversal

**Cons**:
- WebRTC complexity
- Still need signaling infrastructure
- Not identical to HTP (adaptation required)

**Effort**: High

---

### Option 3: HTP WASM (Ideal - Phase 3)

**Concept**: Compile HTP to WebAssembly, browser becomes a mesh node.

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Browser                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  HTP WASM Module                                              │  │
│  │  - Full HTP protocol (compiled from Python/Rust)              │  │
│  │  - Real entropy echo using Web Crypto API                     │  │
│  │  - Qsecbit running in-browser                                 │  │
│  │  - DSM light participation (validation, not consensus)        │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              ↓                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Transport Abstraction                                        │  │
│  │  - WebRTC for UDP-like (preferred)                            │  │
│  │  - WebSocket for TCP fallback                                 │  │
│  │  - WebTransport (HTTP/3) when available                       │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                    ↑ Multiple transports
┌─────────────────────────────────────────────────────────────────────┐
│                    HTP Mesh (Direct Participation)                   │
│  Browser IS a Sentinel-class node (view-only, no data collection)   │
└─────────────────────────────────────────────────────────────────────┘
```

**Pros**:
- True digital twin (browser IS a node)
- Same protocol end-to-end
- Full HTP semantics preserved
- Could even validate and relay

**Cons**:
- Massive engineering effort
- WASM + networking complexity
- Browser sandboxing limitations

**Effort**: Very High (R&D project)

---

## Recommended Phase 1 Approach: "Smart Bridge"

For a side project in 2026, we should start with Option 1 but design it properly:

### The "Smart Bridge" Architecture

```
                                   ┌─────────────────────────────────────┐
                                   │         MSSP/Nexus Cloud            │
                                   │  ┌───────────────────────────────┐  │
                                   │  │   Globe Bridge Service        │  │
                                   │  │   - HTP Full Stack            │  │
                                   │  │   - Mesh Participant          │  │
                                   │  │   - Geographic Registry       │  │
                                   │  │   - Event Aggregator          │  │
                                   │  └───────────────────────────────┘  │
                                   └──────────────┬──────────────────────┘
                                                  │
           ┌──────────────────────────────────────┼───────────────────────────────────────┐
           │                                      │                                       │
           ▼                                      ▼                                       ▼
┌─────────────────────┐              ┌─────────────────────┐              ┌─────────────────────┐
│   Sentinel Cluster  │              │   Guardian Fleet    │              │   Fortress Array    │
│   IoT devices       │              │   Travel routers    │              │   Edge routers      │
│   Report heartbeat  │              │   Report threats    │              │   Report attacks    │
│   via HTP           │              │   via HTP           │              │   via HTP           │
└─────────────────────┘              └─────────────────────┘              └─────────────────────┘
           │                                      │                                       │
           └──────────────────────────────────────┼───────────────────────────────────────┘
                                                  │ HTP Native
                                                  ▼
                                   ┌─────────────────────────────────────┐
                                   │         Globe Bridge                │
                                   │  ┌───────────────────────────────┐  │
                                   │  │   Node Registry               │  │
                                   │  │   - ID → Geo coordinates      │  │
                                   │  │   - Tier classification       │  │
                                   │  │   - Qsecbit history           │  │
                                   │  │   - Last seen timestamps      │  │
                                   │  └───────────────────────────────┘  │
                                   │  ┌───────────────────────────────┐  │
                                   │  │   Event Stream                │  │
                                   │  │   - attack_detected           │  │
                                   │  │   - attack_repelled           │  │
                                   │  │   - node_heartbeat            │  │
                                   │  │   - qsecbit_change            │  │
                                   │  │   - mesh_topology_change      │  │
                                   │  └───────────────────────────────┘  │
                                   └──────────────┬──────────────────────┘
                                                  │ WebSocket (last mile)
                                                  ▼
                                   ┌─────────────────────────────────────┐
                                   │         Browser Globe               │
                                   │  - 3D visualization                 │
                                   │  - Real-time updates                │
                                   │  - Digital twin state               │
                                   └─────────────────────────────────────┘
```

---

## Digital Twin Data Model

### Node State (What the browser needs to know)

```python
@dataclass
class NodeTwin:
    """Digital twin state for a single mesh node."""

    # Identity
    node_id: str              # "guardian-sf-001"
    tier: str                 # sentinel | guardian | fortress | nexus

    # Geographic
    lat: float                # Latitude
    lng: float                # Longitude
    label: str                # Human-readable location

    # Health (from Qsecbit)
    qsecbit_score: float      # 0.0 - 1.0
    qsecbit_status: str       # green | amber | red
    qsecbit_history: List[float]  # Last N readings for trend

    # Liveness
    last_heartbeat: datetime  # Last HTP heartbeat received
    heartbeat_interval_ms: int  # Expected interval
    online: bool              # Derived from heartbeat freshness

    # Neural (from Neuro protocol)
    neural_resonance: float   # Current resonance score
    weight_version: int       # Current weight epoch

    # Visual state
    pulse_phase: float        # For synchronized breathing animation
    attention_level: float    # 0=normal, 1=under attack
```

### Mesh Topology (Relationships)

```python
@dataclass
class MeshEdge:
    """Connection between two nodes."""

    source_id: str
    target_id: str

    # Connection quality
    latency_ms: float
    bandwidth_kbps: float
    packet_loss_pct: float

    # Type
    connection_type: str  # direct | relay | tunnel

    # Visual
    active: bool          # Currently in use
    last_traffic: datetime
```

### Events (What triggers visualization changes)

```python
# Event types that flow from HTP mesh to browser

class EventType(Enum):
    # Liveness
    NODE_ONLINE = "node_online"
    NODE_OFFLINE = "node_offline"
    HEARTBEAT = "heartbeat"

    # Security
    ATTACK_DETECTED = "attack_detected"
    ATTACK_REPELLED = "attack_repelled"
    THREAT_INTEL_SHARED = "threat_intel_shared"

    # Health
    QSECBIT_CHANGE = "qsecbit_change"
    QSECBIT_THRESHOLD_CROSSED = "qsecbit_threshold"

    # Mesh
    TOPOLOGY_CHANGE = "topology_change"
    NEW_ROUTE_ESTABLISHED = "new_route"
    ROUTE_DEGRADED = "route_degraded"

    # Neural
    WEIGHT_SYNC = "weight_sync"
    RESONANCE_ACHIEVED = "resonance_achieved"
    RESONANCE_LOST = "resonance_lost"
```

---

## Visual Quality Specifications

### From "Dashboard" to "Canvas"

| Aspect | Dashboard Quality | Canvas Quality |
|--------|------------------|----------------|
| **Earth Texture** | Single low-res image | 8K Blue Marble + bump + specular + night lights |
| **Atmosphere** | None or simple gradient | Volumetric scattering with Fresnel |
| **Nodes** | Static colored dots | Breathing spheres with tier-specific geometry |
| **Attack Arcs** | Solid colored lines | Particle streams with turbulence |
| **Lighting** | Static | Real sun position, shadows |
| **Camera** | User-controlled only | Cinematic auto-orbit with POI focus |
| **Transitions** | Instant | Eased interpolation (cubic-bezier) |
| **Sound** | None | Ambient + event cues (optional) |

### Required Assets

```
visualization/globe/frontend/assets/
├── textures/
│   ├── earth/
│   │   ├── earth-blue-marble-8k.jpg     # Daytime (NASA)
│   │   ├── earth-night-lights-8k.jpg    # City lights
│   │   ├── earth-bump-8k.jpg            # Elevation
│   │   ├── earth-specular-8k.jpg        # Ocean reflectance
│   │   └── earth-clouds-4k.png          # Cloud layer (optional)
│   └── nodes/
│       ├── sentinel-sprite.png          # Glowing dot
│       ├── guardian-sprite.png          # Shield icon
│       ├── fortress-sprite.png          # Castle icon
│       └── nexus-sprite.png             # Brain/network icon
├── shaders/
│   ├── atmosphere.glsl                  # Volumetric atmosphere
│   ├── arc-particle.glsl                # Attack particle stream
│   └── node-pulse.glsl                  # Breathing effect
└── audio/ (optional)
    ├── ambient-space.mp3                # Background
    ├── attack-incoming.mp3              # Threat alert
    └── attack-blocked.mp3               # Success chime
```

### Shader: Breathing Node Effect

```glsl
// node-pulse.glsl
uniform float u_time;
uniform float u_heartbeat_interval;  // From HTP heartbeat
uniform float u_qsecbit;             // 0.0 - 1.0
uniform vec3 u_status_color;         // Green/Amber/Red

void main() {
    // Sync pulse to actual heartbeat interval
    float phase = mod(u_time, u_heartbeat_interval) / u_heartbeat_interval;
    float pulse = 0.8 + 0.2 * sin(phase * 6.28318);

    // Intensity varies with Qsecbit (higher = more urgent)
    float intensity = mix(0.5, 1.0, u_qsecbit);

    // Glow falloff from center
    float dist = length(gl_PointCoord - vec2(0.5));
    float glow = 1.0 - smoothstep(0.0, 0.5, dist);

    gl_FragColor = vec4(u_status_color * pulse * intensity, glow);
}
```

---

## Implementation Roadmap

### Phase 1A: Smart Bridge Backend (Current Focus)

1. **Upgrade server.py to be HTP participant**
   - Import HTP from `core/htp/transport/htp.py`
   - Join mesh as observer node
   - Subscribe to mesh events via DSM gossip

2. **Create node registry**
   - Store NodeTwin state for each known node
   - Update on heartbeat, Qsecbit changes
   - Expose via WebSocket

3. **Event transformer**
   - HTP events → Globe visualization format
   - Preserve all mesh metadata
   - Add geographic enrichment

### Phase 1B: Enhanced Visualization

1. **Upgrade textures**
   - Replace CDN earth with high-res assets
   - Add night lights layer

2. **Implement node breathing**
   - Sync pulse to heartbeat interval
   - Color by Qsecbit status

3. **Attack particle streams**
   - Replace arcs with particle systems
   - Turbulence + fade effects

### Phase 2: HTP-over-WebRTC (Future)

1. **WebRTC signaling server**
2. **HTP-lite JavaScript client**
3. **Direct P2P to nearby nodes**

### Phase 3: WASM Client (Research)

1. **Port HTP to Rust/WASM**
2. **Browser as Sentinel-class node**
3. **Full mesh participation**

---

## Files to Create/Modify

```
visualization/globe/
├── ARCHITECTURE.md              # This document
├── backend/
│   ├── server.py               # Upgrade: HTP integration
│   ├── htp_bridge.py           # NEW: HTP mesh participation
│   ├── node_registry.py        # NEW: NodeTwin state management
│   └── event_transformer.py    # NEW: HTP → Globe events
├── frontend/
│   ├── js/
│   │   ├── globe.js            # Upgrade: Enhanced visuals
│   │   ├── node-twin.js        # NEW: NodeTwin state sync
│   │   └── shaders.js          # NEW: Custom shaders
│   └── assets/
│       └── textures/           # NEW: High-res assets
└── docs/
    └── DIGITAL_TWIN_SPEC.md    # NEW: Full specification
```

---

## Open Questions

1. **Authentication**: How do browsers authenticate to the bridge?
   - Option A: HTP-derived session tokens
   - Option B: Standard JWT (less pure but simpler)
   - Option C: Anonymous read-only (for public dashboards)

2. **Privacy**: Should all node locations be public?
   - Consider: Approximate locations only
   - Consider: Opt-in visibility per node
   - Consider: MSSP customers only see their nodes

3. **Scale**: How many nodes can the globe handle?
   - Globe.gl tested to ~10K points
   - Need LOD (level of detail) for global mesh
   - Cluster nodes by region at zoom-out

4. **Offline**: What happens when bridge disconnects?
   - Cache last known state
   - Show staleness indicators
   - Graceful degradation
