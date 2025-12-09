# HookProbe 3D Globe Threat Visualization

**Status**: Phase 1 Development (2026 Side Project)
**Version**: 0.1.0

## Overview

Real-time 3D globe visualization of HookProbe mesh network activity, showing:
- Active Sentinel, Guardian, Fortress, and Nexus nodes
- Attack trajectories (red arcs)
- Repelled attacks (blue arcs)
- Node health and Qsecbit status

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend (Browser)                       │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  Globe.gl (Three.js wrapper)                            ││
│  │  - 3D Earth rendering                                   ││
│  │  - Arc animations for attacks                           ││
│  │  - Point markers for nodes                              ││
│  └─────────────────────────────────────────────────────────┘│
│                          ▲                                   │
│                     WebSocket                                │
│                          │                                   │
└──────────────────────────┼──────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────┐
│                     Backend (Python)                         │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  WebSocket Server (websockets library)                  ││
│  │  - Broadcasts events to all connected clients           ││
│  │  - Aggregates data from HTP/Neuro streams               ││
│  └─────────────────────────────────────────────────────────┘│
│                          ▲                                   │
│              ┌───────────┴───────────┐                       │
│              │                       │                       │
│  ┌───────────┴─────┐     ┌──────────┴──────────┐           │
│  │  HTP Collector  │     │  Neuro Collector    │           │
│  │  (mesh events)  │     │  (neural weights)   │           │
│  └─────────────────┘     └─────────────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Backend

```bash
cd visualization/globe/backend
pip install -r requirements.txt
python server.py
```

### Frontend

Serve the frontend directory with any static server:

```bash
cd visualization/globe/frontend
python -m http.server 8080
```

Open `http://localhost:8080` in your browser.

## Event Types

| Event | Color | Description |
|-------|-------|-------------|
| `attack_detected` | Red | Incoming attack trajectory |
| `attack_repelled` | Blue | Successfully mitigated attack |
| `node_online` | Green | New node joined mesh |
| `node_offline` | Gray | Node went offline |
| `qsecbit_amber` | Orange | Node in warning state |
| `qsecbit_red` | Red | Node in critical state |

## Data Format

### WebSocket Messages

```json
{
  "type": "attack_detected",
  "source": {"lat": 39.9, "lng": 116.4, "label": "Beijing"},
  "target": {"lat": 37.7, "lng": -122.4, "label": "SF Guardian"},
  "timestamp": 1704067200,
  "severity": 0.85
}
```

### Node Status

```json
{
  "type": "node_status",
  "nodes": [
    {
      "id": "guardian-001",
      "tier": "guardian",
      "lat": 37.7749,
      "lng": -122.4194,
      "qsecbit": 0.32,
      "status": "green"
    }
  ]
}
```

## File Structure

```
visualization/globe/
├── README.md                 # This file
├── backend/
│   ├── __init__.py
│   ├── requirements.txt      # Python dependencies
│   ├── server.py             # WebSocket server
│   ├── data_collector.py     # HTP/Neuro data aggregation
│   ├── geo_resolver.py       # IP to geolocation
│   └── demo_data.py          # Demo data generator
├── frontend/
│   ├── index.html            # Main HTML page
│   ├── css/
│   │   └── globe.css         # Styling
│   ├── js/
│   │   ├── globe.js          # Globe.gl initialization
│   │   ├── data-stream.js    # WebSocket client
│   │   ├── animations.js     # Arc/point animations
│   │   └── fallback-2d.js    # Mobile 2D fallback
│   └── assets/
│       └── .gitkeep          # Placeholder for textures
└── tests/
    └── test_globe_backend.py # Backend tests
```

## Phase 1 Roadmap (2026)

- [x] Basic folder structure
- [x] WebSocket server skeleton
- [x] Globe.gl frontend skeleton
- [ ] Connect to real HTP data stream
- [ ] Connect to Neuro weight events
- [ ] IP geolocation integration
- [ ] Attack arc animations
- [ ] Node status markers
- [ ] Mobile 2D fallback
- [ ] Dark/light theme toggle

## Dependencies

### Backend
- Python 3.9+
- websockets
- aiohttp (for HTP integration)

### Frontend
- Globe.gl (CDN)
- Three.js (bundled with Globe.gl)

## License

Part of HookProbe - see root LICENSE file.
