# Phase 2: City-Level Map View with Deck.gl + MapLibre GL

**Status**: Planning
**Target**: Seamless globe-to-city transition with street/building context
**Stack**: Deck.gl (visualization) + MapLibre GL (basemap)

---

## Why Deck.gl + MapLibre GL?

| Feature | Deck.gl + MapLibre | Mapbox GL JS |
|---------|-------------------|--------------|
| **Cost** | Free (no limits) | 50k loads/month free |
| **Globe View** | Built-in GlobeView | Requires globe.gl |
| **Map View** | Built-in MapView | Native |
| **Transitions** | Unified state | Requires custom code |
| **GPU Acceleration** | WebGL2 optimized | WebGL |
| **Clustering** | Built-in layers | Requires Supercluster |
| **License** | MIT | Proprietary |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      CORTEX VISUALIZATION                        │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                      Deck.gl                                 ││
│  │  ┌─────────────────┐    ┌─────────────────┐                 ││
│  │  │   GlobeView     │ ←→ │    MapView      │                 ││
│  │  │  (altitude>0.3) │    │  (altitude<0.3) │                 ││
│  │  └─────────────────┘    └─────────────────┘                 ││
│  │           │                      │                           ││
│  │           └──────────┬───────────┘                           ││
│  │                      │                                       ││
│  │  ┌───────────────────┴───────────────────┐                  ││
│  │  │           Shared Layers               │                  ││
│  │  │  • ScatterplotLayer (nodes)           │                  ││
│  │  │  • ArcLayer (attacks)                 │                  ││
│  │  │  • IconLayer (tier icons)             │                  ││
│  │  │  • TextLayer (labels)                 │                  ││
│  │  └───────────────────────────────────────┘                  ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    MapLibre GL                              ││
│  │  • Dark basemap tiles (free)                                ││
│  │  • Streets layer                                            ││
│  │  • Buildings layer (raster footprints)                      ││
│  │  • Minimal labels                                           ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

---

## Free Basemap Options

### Option 1: MapTiler (Recommended)

- **Free tier**: 100k tiles/month
- **Dark styles available**: `dataviz-dark`, `toner-dark`
- **Buildings**: Yes (zoom 13+)
- **API**: `https://api.maptiler.com/maps/{style}/style.json?key={key}`

### Option 2: Stadia Maps

- **Free tier**: 200k tiles/month
- **Dark styles**: `alidade_smooth_dark`, `stamen_toner`
- **Buildings**: Limited
- **API**: `https://tiles.stadiamaps.com/styles/{style}.json`

### Option 3: Self-hosted (OpenMapTiles)

- **Cost**: Free (self-hosted)
- **Customization**: Full control
- **Effort**: Higher setup
- **Docker**: `openmaptiles/openmaptiles`

---

## Implementation Plan

### File Structure

```
shared/cortex/frontend/
├── js/
│   ├── globe.js              # Phase 1 (existing)
│   ├── cluster-manager.js    # Phase 1 (existing)
│   ├── zoom-controller.js    # Phase 1 (existing)
│   ├── transitions.js        # Phase 1 (existing)
│   │
│   ├── deck-renderer.js      # NEW: Deck.gl setup & layers
│   ├── view-manager.js       # NEW: Globe ↔ Map transitions
│   ├── basemap-config.js     # NEW: MapLibre GL configuration
│   └── city-view.js          # NEW: City-level enhancements
│
├── css/
│   ├── globe.css             # Phase 1 (existing)
│   └── city-view.css         # NEW: Map-specific styles
│
└── index.html                # Updated with Deck.gl deps
```

### Dependencies (CDN)

```html
<!-- Deck.gl core -->
<script src="https://unpkg.com/deck.gl@8.9/dist.min.js"></script>

<!-- MapLibre GL (free Mapbox alternative) -->
<script src="https://unpkg.com/maplibre-gl@3.6/dist/maplibre-gl.js"></script>
<link href="https://unpkg.com/maplibre-gl@3.6/dist/maplibre-gl.css" rel="stylesheet">
```

---

## Core Implementation

### 1. Deck.gl Renderer (`deck-renderer.js`)

```javascript
/**
 * Deck.gl Renderer for Cortex
 * Supports both GlobeView and MapView with shared layers
 */

class DeckRenderer {
    constructor(container, options = {}) {
        this.container = container;
        this.currentView = 'globe'; // 'globe' | 'map'
        this.transitionProgress = 0;

        // Initialize Deck.gl
        this.deck = new deck.Deck({
            parent: container,
            views: this._createViews(),
            layers: [],
            viewState: {
                longitude: 0,
                latitude: 20,
                zoom: 1,
                pitch: 0,
                bearing: 0
            },
            controller: true,
            onViewStateChange: this._onViewStateChange.bind(this),
            getTooltip: this._getTooltip.bind(this)
        });

        // MapLibre basemap (only visible in map view)
        this.maplibre = null;
        this._initMapLibre(options.mapStyle);
    }

    _createViews() {
        return [
            new deck.GlobeView({
                id: 'globe',
                resolution: 2
            }),
            new deck.MapView({
                id: 'map',
                controller: true
            })
        ];
    }

    _initMapLibre(styleUrl) {
        // MapLibre basemap for city view
        this.maplibre = new maplibregl.Map({
            container: this.container,
            style: styleUrl || BASEMAP_STYLES.maptiler_dark,
            center: [0, 20],
            zoom: 1,
            attributionControl: false
        });

        // Initially hidden (globe mode)
        this.maplibre.getCanvas().style.opacity = '0';
    }

    /**
     * Set node data
     */
    setNodes(nodes) {
        this.nodes = nodes;
        this._updateLayers();
    }

    /**
     * Set attack arcs
     */
    setArcs(arcs) {
        this.arcs = arcs;
        this._updateLayers();
    }

    /**
     * Update all layers
     */
    _updateLayers() {
        this.deck.setProps({
            layers: [
                // Node points
                new deck.ScatterplotLayer({
                    id: 'nodes',
                    data: this.nodes || [],
                    getPosition: d => [d.lng, d.lat],
                    getRadius: d => this._getNodeRadius(d),
                    getFillColor: d => this._getNodeColor(d),
                    radiusScale: this.currentView === 'globe' ? 50000 : 100,
                    radiusUnits: this.currentView === 'globe' ? 'meters' : 'pixels',
                    pickable: true,
                    onClick: this._onNodeClick.bind(this)
                }),

                // Attack arcs
                new deck.ArcLayer({
                    id: 'attacks',
                    data: this.arcs || [],
                    getSourcePosition: d => [d.source.lng, d.source.lat],
                    getTargetPosition: d => [d.target.lng, d.target.lat],
                    getSourceColor: d => d.type === 'attack'
                        ? [255, 68, 68, 200]
                        : [0, 191, 255, 200],
                    getTargetColor: d => d.type === 'attack'
                        ? [255, 68, 68, 50]
                        : [0, 191, 255, 50],
                    getWidth: 2,
                    greatCircle: true
                }),

                // Node labels (city view only)
                this.currentView === 'map' ? new deck.TextLayer({
                    id: 'labels',
                    data: this.nodes || [],
                    getPosition: d => [d.lng, d.lat],
                    getText: d => d.label,
                    getSize: 12,
                    getColor: [255, 255, 255, 200],
                    getAngle: 0,
                    getTextAnchor: 'middle',
                    getAlignmentBaseline: 'top',
                    getPixelOffset: [0, 15]
                }) : null
            ].filter(Boolean)
        });
    }

    _getNodeRadius(node) {
        const sizes = { sentinel: 4, guardian: 6, fortress: 8, nexus: 10 };
        return sizes[node.tier] || 6;
    }

    _getNodeColor(node) {
        const colors = {
            green: [0, 255, 136, 230],
            amber: [255, 170, 0, 230],
            red: [255, 68, 68, 230]
        };
        return colors[node.status] || colors.green;
    }

    /**
     * Transition to map view (city level)
     */
    async transitionToMap(targetLat, targetLng, zoom = 14) {
        this.currentView = 'map';

        // Fade in MapLibre basemap
        await this._fadeMapLibre(1, 500);

        // Update deck view
        this.deck.setProps({
            viewState: {
                longitude: targetLng,
                latitude: targetLat,
                zoom: zoom,
                pitch: 45,
                bearing: 0
            }
        });

        this._updateLayers();
    }

    /**
     * Transition to globe view
     */
    async transitionToGlobe() {
        this.currentView = 'globe';

        // Fade out MapLibre basemap
        await this._fadeMapLibre(0, 500);

        // Update deck view
        this.deck.setProps({
            viewState: {
                longitude: this.deck.viewState?.longitude || 0,
                latitude: this.deck.viewState?.latitude || 20,
                zoom: 1,
                pitch: 0,
                bearing: 0
            }
        });

        this._updateLayers();
    }

    async _fadeMapLibre(targetOpacity, duration) {
        return new Promise(resolve => {
            const canvas = this.maplibre.getCanvas();
            const start = parseFloat(canvas.style.opacity) || 0;
            const startTime = Date.now();

            const animate = () => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(1, elapsed / duration);
                const opacity = start + (targetOpacity - start) * progress;
                canvas.style.opacity = opacity;

                if (progress < 1) {
                    requestAnimationFrame(animate);
                } else {
                    resolve();
                }
            };

            requestAnimationFrame(animate);
        });
    }
}
```

### 2. Basemap Configuration (`basemap-config.js`)

```javascript
/**
 * MapLibre GL Basemap Configuration
 * Dark theme with streets and building footprints
 */

// Free basemap style URLs
const BASEMAP_STYLES = {
    // MapTiler Dark (recommended - 100k free/month)
    maptiler_dark: 'https://api.maptiler.com/maps/dataviz-dark/style.json?key=YOUR_KEY',

    // Stadia Maps Dark (200k free/month)
    stadia_dark: 'https://tiles.stadiamaps.com/styles/alidade_smooth_dark.json',

    // CartoDB Dark Matter (free, no key)
    carto_dark: 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json'
};

// Custom dark style matching Cortex theme
const CORTEX_DARK_STYLE = {
    version: 8,
    name: 'Cortex Dark',
    sources: {
        'carto': {
            type: 'vector',
            url: 'https://tiles.basemaps.cartocdn.com/vector/carto.streets/v1/tiles.json'
        }
    },
    layers: [
        // Background - match Cortex dark theme
        {
            id: 'background',
            type: 'background',
            paint: {
                'background-color': '#0a0a15'
            }
        },

        // Water - slightly lighter
        {
            id: 'water',
            type: 'fill',
            source: 'carto',
            'source-layer': 'water',
            paint: {
                'fill-color': '#0d0d1a'
            }
        },

        // Buildings - dark gray polygons
        {
            id: 'buildings',
            type: 'fill',
            source: 'carto',
            'source-layer': 'building',
            minzoom: 13,
            paint: {
                'fill-color': '#1a1a28',
                'fill-opacity': [
                    'interpolate', ['linear'], ['zoom'],
                    13, 0,
                    15, 0.8
                ]
            }
        },

        // Building outlines
        {
            id: 'building-outline',
            type: 'line',
            source: 'carto',
            'source-layer': 'building',
            minzoom: 15,
            paint: {
                'line-color': '#2a2a3a',
                'line-width': 0.5
            }
        },

        // Streets - subtle gray
        {
            id: 'streets-minor',
            type: 'line',
            source: 'carto',
            'source-layer': 'transportation',
            filter: ['in', 'class', 'minor', 'service'],
            paint: {
                'line-color': '#1a1a28',
                'line-width': [
                    'interpolate', ['linear'], ['zoom'],
                    12, 0.5,
                    16, 2
                ]
            }
        },

        // Major roads
        {
            id: 'streets-major',
            type: 'line',
            source: 'carto',
            'source-layer': 'transportation',
            filter: ['in', 'class', 'primary', 'secondary', 'tertiary'],
            paint: {
                'line-color': '#2a2a3a',
                'line-width': [
                    'interpolate', ['linear'], ['zoom'],
                    10, 1,
                    16, 4
                ]
            }
        },

        // Highways
        {
            id: 'streets-highway',
            type: 'line',
            source: 'carto',
            'source-layer': 'transportation',
            filter: ['in', 'class', 'motorway', 'trunk'],
            paint: {
                'line-color': '#3a3a4a',
                'line-width': [
                    'interpolate', ['linear'], ['zoom'],
                    8, 1,
                    16, 6
                ]
            }
        },

        // Major road labels only
        {
            id: 'road-labels',
            type: 'symbol',
            source: 'carto',
            'source-layer': 'transportation_name',
            filter: ['in', 'class', 'motorway', 'trunk', 'primary'],
            minzoom: 14,
            layout: {
                'text-field': ['get', 'name'],
                'text-size': 10,
                'text-font': ['Open Sans Regular'],
                'symbol-placement': 'line'
            },
            paint: {
                'text-color': '#4a4a5a',
                'text-halo-color': '#0a0a15',
                'text-halo-width': 1
            }
        }
    ]
};

// Export for use
window.BASEMAP_STYLES = BASEMAP_STYLES;
window.CORTEX_DARK_STYLE = CORTEX_DARK_STYLE;
```

### 3. View Manager (`view-manager.js`)

```javascript
/**
 * View Manager - Orchestrates Globe ↔ Map transitions
 * Handles the smooth crossfade between views
 */

class ViewManager {
    constructor(deckRenderer, zoomController) {
        this.deck = deckRenderer;
        this.zoom = zoomController;
        this.currentMode = 'globe';

        // Transition thresholds
        this.GLOBE_TO_MAP_ALTITUDE = 0.25; // Transition to map below this
        this.MAP_TO_GLOBE_ALTITUDE = 0.35; // Transition to globe above this

        // Listen for zoom changes
        if (this.zoom) {
            this.zoom.on('zoomChange', this._onZoomChange.bind(this));
        }
    }

    _onZoomChange(data) {
        const { altitude } = data;

        // Check for mode transitions
        if (this.currentMode === 'globe' && altitude < this.GLOBE_TO_MAP_ALTITUDE) {
            this._transitionToMap(data.lat, data.lng);
        } else if (this.currentMode === 'map' && altitude > this.MAP_TO_GLOBE_ALTITUDE) {
            this._transitionToGlobe();
        }
    }

    async _transitionToMap(lat, lng) {
        if (this.currentMode === 'map') return;

        console.log('ViewManager: Transitioning to map view');
        this.currentMode = 'map';

        // Show transition overlay
        this._showTransitionOverlay();

        // Perform transition
        await this.deck.transitionToMap(lat, lng, 14);

        // Hide overlay
        this._hideTransitionOverlay();

        // Update UI
        this._updateModeIndicator('map');
    }

    async _transitionToGlobe() {
        if (this.currentMode === 'globe') return;

        console.log('ViewManager: Transitioning to globe view');
        this.currentMode = 'globe';

        this._showTransitionOverlay();
        await this.deck.transitionToGlobe();
        this._hideTransitionOverlay();

        this._updateModeIndicator('globe');
    }

    _showTransitionOverlay() {
        const overlay = document.getElementById('view-transition-overlay');
        if (overlay) {
            overlay.classList.add('active');
        }
    }

    _hideTransitionOverlay() {
        const overlay = document.getElementById('view-transition-overlay');
        if (overlay) {
            overlay.classList.remove('active');
        }
    }

    _updateModeIndicator(mode) {
        const indicator = document.getElementById('view-mode-indicator');
        if (indicator) {
            indicator.textContent = mode === 'map' ? '2D MAP' : '3D GLOBE';
            indicator.className = `view-mode ${mode}`;
        }
    }
}
```

---

## Visual Comparison

### Globe View (Phase 1 - Current)
```
        ╭──────────────────╮
       ╱                    ╲
      │    ●  ●    ●        │     ● = Node
      │      ●    ●  ●      │     ─ = Attack arc
      │  ●──────────●       │
      │       ●             │
       ╲                    ╱
        ╰──────────────────╯
              GLOBE
```

### City View (Phase 2 - Planned)
```
    ┌────────────────────────────┐
    │ ▓▓▓░░░░░░░░░▓▓▓░░░░░░░▓▓▓ │    ▓ = Building
    │ ▓▓▓━━━━━━━━━▓▓▓━━━━━━━▓▓▓ │    ━ = Street
    │ ░░░░░░●░░░░░░░░░░░●░░░░░░ │    ● = Node
    │ ▓▓▓━━━━━━━━━▓▓▓━━━━━━━░░░ │    ░ = Dark basemap
    │ ▓▓▓░░░░░░░░░▓▓▓░░░●░░░▓▓▓ │
    │ ░░░━━━━━━━━━░░░━━━━━━━▓▓▓ │
    │ ▓▓▓░░░░●░░░░▓▓▓░░░░░░░░░░ │
    └────────────────────────────┘
           CITY MAP VIEW
```

---

## Migration Path from Phase 1

### Option A: Gradual Migration (Recommended)
1. Keep Globe.gl for globe view
2. Add Deck.gl + MapLibre for city view only
3. ViewManager handles transition between them

### Option B: Full Migration to Deck.gl
1. Replace Globe.gl entirely with Deck.gl GlobeView
2. Unified codebase for both views
3. Higher effort but cleaner architecture

---

## Estimated Implementation

| Task | Description |
|------|-------------|
| **Setup** | Add Deck.gl + MapLibre dependencies |
| **Basemap** | Configure dark style with streets/buildings |
| **DeckRenderer** | Core rendering class with layer management |
| **ViewManager** | Globe ↔ Map transition logic |
| **Integration** | Connect to existing clustering system |
| **Polish** | Smooth transitions, mobile support |

---

## Resources

- [Deck.gl Documentation](https://deck.gl/docs)
- [Deck.gl GlobeView](https://deck.gl/docs/api-reference/core/globe-view)
- [MapLibre GL JS](https://maplibre.org/maplibre-gl-js-docs/)
- [Free Basemap Providers](https://github.com/maplibre/awesome-maplibre)
- [OpenMapTiles (self-hosted)](https://openmaptiles.org/)

---

## Next Steps

When ready to implement Phase 2:

1. Obtain free API key from MapTiler (or use CartoDB)
2. Add CDN dependencies to `index.html`
3. Create `deck-renderer.js` and `basemap-config.js`
4. Implement `view-manager.js` for transitions
5. Test on various zoom levels
6. Optimize for mobile performance

---

*Document created during Phase 1 implementation - December 2025*
