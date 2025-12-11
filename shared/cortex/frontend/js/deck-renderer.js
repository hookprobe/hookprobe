/**
 * Deck.gl Renderer for Cortex - City-Level Map View
 *
 * Phase 2 Implementation: Provides GPU-accelerated visualization
 * supporting both GlobeView and MapView with shared layers.
 *
 * Features:
 * - Seamless globe-to-map transitions
 * - ScatterplotLayer for nodes
 * - ArcLayer for attack trajectories
 * - TextLayer for labels (city view only)
 * - IconLayer for tier-specific markers
 * - Integration with MapLibre GL basemap
 */

'use strict';

// View mode constants
const VIEW_MODES = {
    GLOBE: 'globe',
    MAP: 'map'
};

// Transition thresholds (in deck.gl zoom units)
const VIEW_THRESHOLDS = {
    GLOBE_TO_MAP: 8,    // Transition to map above this zoom
    MAP_TO_GLOBE: 6     // Transition to globe below this zoom
};

// Node size configuration
const NODE_SIZES = {
    sentinel: { globe: 30000, map: 6 },
    guardian: { globe: 50000, map: 10 },
    fortress: { globe: 80000, map: 14 },
    nexus: { globe: 120000, map: 18 }
};

// Status colors (RGBA)
const STATUS_COLORS = {
    green: [0, 255, 136, 230],
    amber: [255, 170, 0, 230],
    red: [255, 68, 68, 230],
    offline: [100, 100, 100, 150]
};

// Tier colors for borders/accents
const TIER_COLORS = {
    sentinel: [150, 150, 150, 255],
    guardian: [0, 191, 255, 255],
    fortress: [0, 255, 136, 255],
    nexus: [255, 170, 0, 255]
};

/**
 * Main Deck.gl Renderer Class
 */
class DeckRenderer {
    constructor(container, options = {}) {
        this.container = typeof container === 'string'
            ? document.getElementById(container)
            : container;

        this.options = {
            mapStyle: options.mapStyle || null,
            initialViewState: options.initialViewState || {
                longitude: 0,
                latitude: 20,
                zoom: 1.5,
                pitch: 0,
                bearing: 0
            },
            onViewStateChange: options.onViewStateChange || null,
            onNodeClick: options.onNodeClick || null,
            onClusterClick: options.onClusterClick || null,
            enableLabels: options.enableLabels !== false,
            enableBuildings: options.enableBuildings !== false,
            ...options
        };

        // State
        this.currentView = VIEW_MODES.GLOBE;
        this.viewState = { ...this.options.initialViewState };
        this.nodes = [];
        this.clusters = [];
        this.arcs = [];
        this.isTransitioning = false;

        // MapLibre instance (for basemap)
        this.maplibre = null;
        this.mapContainer = null;

        // Event callbacks
        this._callbacks = {
            viewChange: [],
            modeChange: [],
            nodeHover: [],
            ready: []
        };

        // Initialize
        this._init();
    }

    /**
     * Initialize the renderer
     */
    _init() {
        // Create container structure
        this._createContainers();

        // Initialize MapLibre basemap (hidden initially)
        this._initMapLibre();

        // Initialize Deck.gl
        this._initDeck();

        // Emit ready event
        setTimeout(() => this._emit('ready', { renderer: this }), 100);
    }

    /**
     * Create DOM container structure
     */
    _createContainers() {
        // Ensure container is positioned
        this.container.style.position = 'relative';

        // Create MapLibre container (underneath deck.gl)
        this.mapContainer = document.createElement('div');
        this.mapContainer.id = 'cortex-maplibre-container';
        this.mapContainer.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            transition: opacity 0.5s ease;
            z-index: 1;
        `;
        this.container.appendChild(this.mapContainer);

        // Create Deck.gl container (on top)
        this.deckContainer = document.createElement('div');
        this.deckContainer.id = 'cortex-deck-container';
        this.deckContainer.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 2;
        `;
        this.container.appendChild(this.deckContainer);
    }

    /**
     * Initialize MapLibre GL basemap
     */
    _initMapLibre() {
        if (typeof maplibregl === 'undefined') {
            console.warn('DeckRenderer: MapLibre GL not loaded, basemap disabled');
            return;
        }

        const style = this.options.mapStyle ||
            (typeof CORTEX_DARK_STYLE !== 'undefined' ? CORTEX_DARK_STYLE :
             (typeof BASEMAP_STYLES !== 'undefined' ? BASEMAP_STYLES.carto_dark : null));

        if (!style) {
            console.warn('DeckRenderer: No basemap style available');
            return;
        }

        try {
            this.maplibre = new maplibregl.Map({
                container: this.mapContainer,
                style: style,
                center: [this.viewState.longitude, this.viewState.latitude],
                zoom: this.viewState.zoom,
                pitch: this.viewState.pitch || 0,
                bearing: this.viewState.bearing || 0,
                attributionControl: false,
                interactive: false // Deck.gl handles interaction
            });

            this.maplibre.on('load', () => {
                console.log('DeckRenderer: MapLibre basemap loaded');
            });
        } catch (e) {
            console.error('DeckRenderer: Failed to initialize MapLibre:', e);
        }
    }

    /**
     * Initialize Deck.gl
     */
    _initDeck() {
        if (typeof deck === 'undefined') {
            console.error('DeckRenderer: Deck.gl not loaded');
            return;
        }

        this.deck = new deck.Deck({
            parent: this.deckContainer,
            initialViewState: this.viewState,
            controller: {
                type: deck.MapController,
                dragRotate: true,
                touchRotate: true
            },
            views: this._createView(),
            layers: [],
            onViewStateChange: ({ viewState }) => this._onViewStateChange(viewState),
            getTooltip: ({ object }) => this._getTooltip(object),
            onClick: (info, event) => this._onClick(info, event),
            onHover: (info) => this._onHover(info)
        });
    }

    /**
     * Create appropriate view based on current mode
     */
    _createView() {
        if (this.currentView === VIEW_MODES.MAP) {
            return new deck.MapView({
                id: 'map-view',
                controller: true
            });
        } else {
            return new deck.GlobeView({
                id: 'globe-view',
                resolution: 2
            });
        }
    }

    /**
     * Handle view state changes
     */
    _onViewStateChange(viewState) {
        this.viewState = viewState;

        // Sync MapLibre camera
        if (this.maplibre && this.currentView === VIEW_MODES.MAP) {
            this.maplibre.jumpTo({
                center: [viewState.longitude, viewState.latitude],
                zoom: viewState.zoom,
                pitch: viewState.pitch,
                bearing: viewState.bearing
            });
        }

        // Check for view mode transition
        this._checkViewTransition(viewState);

        // Emit event
        this._emit('viewChange', { viewState, mode: this.currentView });

        // Call external callback
        if (this.options.onViewStateChange) {
            this.options.onViewStateChange(viewState);
        }
    }

    /**
     * Check if we should transition between globe and map
     */
    _checkViewTransition(viewState) {
        if (this.isTransitioning) return;

        const zoom = viewState.zoom;

        if (this.currentView === VIEW_MODES.GLOBE && zoom > VIEW_THRESHOLDS.GLOBE_TO_MAP) {
            this._transitionToMap();
        } else if (this.currentView === VIEW_MODES.MAP && zoom < VIEW_THRESHOLDS.MAP_TO_GLOBE) {
            this._transitionToGlobe();
        }
    }

    /**
     * Transition to map view
     */
    async _transitionToMap() {
        if (this.currentView === VIEW_MODES.MAP || this.isTransitioning) return;

        this.isTransitioning = true;
        console.log('DeckRenderer: Transitioning to map view');

        // Show MapLibre basemap
        if (this.mapContainer) {
            this.mapContainer.style.opacity = '1';
        }

        // Update view
        this.currentView = VIEW_MODES.MAP;
        this.deck.setProps({ views: this._createView() });

        // Sync MapLibre
        if (this.maplibre) {
            this.maplibre.jumpTo({
                center: [this.viewState.longitude, this.viewState.latitude],
                zoom: this.viewState.zoom,
                pitch: this.viewState.pitch || 45,
                bearing: this.viewState.bearing || 0
            });
        }

        // Update layers
        this._updateLayers();

        // Emit event
        this._emit('modeChange', { mode: VIEW_MODES.MAP });

        this.isTransitioning = false;
    }

    /**
     * Transition to globe view
     */
    async _transitionToGlobe() {
        if (this.currentView === VIEW_MODES.GLOBE || this.isTransitioning) return;

        this.isTransitioning = true;
        console.log('DeckRenderer: Transitioning to globe view');

        // Hide MapLibre basemap
        if (this.mapContainer) {
            this.mapContainer.style.opacity = '0';
        }

        // Update view
        this.currentView = VIEW_MODES.GLOBE;
        this.deck.setProps({ views: this._createView() });

        // Update layers
        this._updateLayers();

        // Emit event
        this._emit('modeChange', { mode: VIEW_MODES.GLOBE });

        this.isTransitioning = false;
    }

    /**
     * Set node data
     */
    setNodes(nodes) {
        this.nodes = nodes || [];
        this._updateLayers();
    }

    /**
     * Set cluster data
     */
    setClusters(clusters) {
        this.clusters = clusters || [];
        this._updateLayers();
    }

    /**
     * Set attack arc data
     */
    setArcs(arcs) {
        this.arcs = arcs || [];
        this._updateLayers();
    }

    /**
     * Update all layers
     */
    _updateLayers() {
        if (!this.deck) return;

        const isMap = this.currentView === VIEW_MODES.MAP;
        const layers = [];

        // Node layer
        if (this.nodes.length > 0) {
            layers.push(this._createNodeLayer(isMap));
        }

        // Cluster layer
        if (this.clusters.length > 0) {
            layers.push(this._createClusterLayer(isMap));
        }

        // Arc layer (attacks)
        if (this.arcs.length > 0) {
            layers.push(this._createArcLayer(isMap));
        }

        // Labels (map view only)
        if (isMap && this.options.enableLabels && this.nodes.length > 0) {
            layers.push(this._createLabelLayer());
        }

        this.deck.setProps({ layers });
    }

    /**
     * Create node scatter layer
     */
    _createNodeLayer(isMap) {
        return new deck.ScatterplotLayer({
            id: 'nodes-layer',
            data: this.nodes,
            getPosition: d => [d.lng, d.lat],
            getRadius: d => this._getNodeRadius(d, isMap),
            getFillColor: d => this._getNodeColor(d),
            getLineColor: d => TIER_COLORS[d.tier] || TIER_COLORS.guardian,
            getLineWidth: isMap ? 2 : 1,
            stroked: true,
            radiusScale: isMap ? 1 : 1,
            radiusUnits: isMap ? 'pixels' : 'meters',
            radiusMinPixels: isMap ? 4 : 2,
            radiusMaxPixels: isMap ? 30 : 100,
            pickable: true,
            autoHighlight: true,
            highlightColor: [255, 255, 255, 100],
            updateTriggers: {
                getRadius: [isMap],
                getFillColor: [this.nodes.map(n => n.status).join(',')]
            }
        });
    }

    /**
     * Create cluster layer
     */
    _createClusterLayer(isMap) {
        return new deck.ScatterplotLayer({
            id: 'clusters-layer',
            data: this.clusters,
            getPosition: d => [d.lng || d.geometry?.coordinates[0], d.lat || d.geometry?.coordinates[1]],
            getRadius: d => this._getClusterRadius(d, isMap),
            getFillColor: d => this._getClusterColor(d),
            getLineColor: [0, 191, 255, 200],
            getLineWidth: 2,
            stroked: true,
            radiusUnits: isMap ? 'pixels' : 'meters',
            radiusMinPixels: 15,
            radiusMaxPixels: 80,
            pickable: true,
            autoHighlight: true,
            highlightColor: [0, 191, 255, 80]
        });
    }

    /**
     * Create attack arc layer
     */
    _createArcLayer(isMap) {
        return new deck.ArcLayer({
            id: 'arcs-layer',
            data: this.arcs,
            getSourcePosition: d => [d.source.lng, d.source.lat],
            getTargetPosition: d => [d.target.lng, d.target.lat],
            getSourceColor: d => d.type === 'attack'
                ? [255, 68, 68, 220]
                : [0, 191, 255, 220],
            getTargetColor: d => d.type === 'attack'
                ? [255, 68, 68, 50]
                : [0, 191, 255, 50],
            getWidth: d => d.type === 'attack' ? 3 : 2,
            getHeight: 0.5,
            greatCircle: !isMap,
            pickable: true
        });
    }

    /**
     * Create label layer (map view only)
     */
    _createLabelLayer() {
        return new deck.TextLayer({
            id: 'labels-layer',
            data: this.nodes.filter(n => n.label),
            getPosition: d => [d.lng, d.lat],
            getText: d => d.label,
            getSize: 12,
            getColor: [255, 255, 255, 200],
            getAngle: 0,
            getTextAnchor: 'middle',
            getAlignmentBaseline: 'top',
            getPixelOffset: [0, 20],
            fontFamily: 'Rajdhani, sans-serif',
            fontWeight: 600,
            outlineWidth: 2,
            outlineColor: [10, 10, 21, 200],
            pickable: false
        });
    }

    /**
     * Get node radius based on tier and view mode
     */
    _getNodeRadius(node, isMap) {
        const tier = node.tier || 'guardian';
        const sizes = NODE_SIZES[tier] || NODE_SIZES.guardian;
        return isMap ? sizes.map : sizes.globe;
    }

    /**
     * Get node color based on status
     */
    _getNodeColor(node) {
        if (!node.online) return STATUS_COLORS.offline;
        return STATUS_COLORS[node.status] || STATUS_COLORS.green;
    }

    /**
     * Get cluster radius based on point count
     */
    _getClusterRadius(cluster, isMap) {
        const count = cluster.properties?.point_count || cluster.count || 1;
        const baseSize = isMap ? 20 : 80000;
        return baseSize + Math.min(count * (isMap ? 2 : 5000), isMap ? 40 : 200000);
    }

    /**
     * Get cluster color based on status distribution
     */
    _getClusterColor(cluster) {
        const status = cluster.properties?.dominant_status || cluster.status || 'green';
        const color = [...STATUS_COLORS[status]];
        color[3] = 180; // Slightly transparent
        return color;
    }

    /**
     * Generate tooltip for hovered objects
     */
    _getTooltip(object) {
        if (!object) return null;

        // Cluster tooltip
        if (object.properties?.cluster) {
            const count = object.properties.point_count || 0;
            const status = object.properties.dominant_status || 'mixed';
            return {
                html: `
                    <div class="deck-tooltip cluster-tooltip">
                        <div class="tooltip-title">${count} Nodes</div>
                        <div class="tooltip-status status-${status}">${status.toUpperCase()}</div>
                        <div class="tooltip-hint">Click to expand</div>
                    </div>
                `,
                style: {
                    backgroundColor: 'transparent',
                    border: 'none',
                    padding: 0
                }
            };
        }

        // Node tooltip
        if (object.id || object.node_id) {
            const tier = object.tier || 'unknown';
            const status = object.status || 'unknown';
            const label = object.label || object.id || 'Unknown Node';
            const qsecbit = object.qsecbit !== undefined ? object.qsecbit.toFixed(4) : '--';

            return {
                html: `
                    <div class="deck-tooltip node-tooltip">
                        <div class="tooltip-title">${label}</div>
                        <div class="tooltip-tier tier-${tier}">${tier.toUpperCase()}</div>
                        <div class="tooltip-qsecbit">Qsecbit: ${qsecbit}</div>
                        <div class="tooltip-status status-${status}">${status.toUpperCase()}</div>
                    </div>
                `,
                style: {
                    backgroundColor: 'transparent',
                    border: 'none',
                    padding: 0
                }
            };
        }

        return null;
    }

    /**
     * Handle click events
     */
    _onClick(info, event) {
        if (!info.object) return;

        // Cluster click
        if (info.object.properties?.cluster) {
            if (this.options.onClusterClick) {
                this.options.onClusterClick(info.object, info);
            }
            return;
        }

        // Node click
        if (this.options.onNodeClick) {
            this.options.onNodeClick(info.object, info);
        }
    }

    /**
     * Handle hover events
     */
    _onHover(info) {
        this._emit('nodeHover', { object: info.object, info });
    }

    /**
     * Fly to a specific location
     */
    flyTo(options) {
        const { longitude, latitude, zoom, pitch, bearing, duration } = options;

        const newViewState = {
            ...this.viewState,
            longitude: longitude ?? this.viewState.longitude,
            latitude: latitude ?? this.viewState.latitude,
            zoom: zoom ?? this.viewState.zoom,
            pitch: pitch ?? this.viewState.pitch,
            bearing: bearing ?? this.viewState.bearing,
            transitionDuration: duration || 1000,
            transitionInterpolator: new deck.FlyToInterpolator()
        };

        this.deck.setProps({ initialViewState: newViewState });
    }

    /**
     * Zoom to fit bounds
     */
    fitBounds(bounds, options = {}) {
        const { west, south, east, north } = bounds;
        const padding = options.padding || 50;

        const viewport = new deck.WebMercatorViewport({
            width: this.container.clientWidth,
            height: this.container.clientHeight
        });

        const fitted = viewport.fitBounds(
            [[west, south], [east, north]],
            { padding }
        );

        this.flyTo({
            longitude: fitted.longitude,
            latitude: fitted.latitude,
            zoom: fitted.zoom,
            duration: options.duration || 1000
        });
    }

    /**
     * Get current view state
     */
    getViewState() {
        return { ...this.viewState };
    }

    /**
     * Get current view mode
     */
    getViewMode() {
        return this.currentView;
    }

    /**
     * Force switch to map mode
     */
    setMapMode(lat, lng, zoom = 14) {
        this.viewState = {
            ...this.viewState,
            longitude: lng,
            latitude: lat,
            zoom: zoom,
            pitch: 45,
            bearing: 0
        };
        this._transitionToMap();
    }

    /**
     * Force switch to globe mode
     */
    setGlobeMode() {
        this.viewState = {
            ...this.viewState,
            zoom: 1.5,
            pitch: 0,
            bearing: 0
        };
        this._transitionToGlobe();
    }

    /**
     * Register event callback
     */
    on(event, callback) {
        if (this._callbacks[event]) {
            this._callbacks[event].push(callback);
        }
        return this;
    }

    /**
     * Remove event callback
     */
    off(event, callback) {
        if (this._callbacks[event]) {
            const index = this._callbacks[event].indexOf(callback);
            if (index > -1) {
                this._callbacks[event].splice(index, 1);
            }
        }
        return this;
    }

    /**
     * Emit event to callbacks
     */
    _emit(event, data) {
        if (this._callbacks[event]) {
            this._callbacks[event].forEach(cb => {
                try {
                    cb(data);
                } catch (e) {
                    console.error(`DeckRenderer: Event callback error (${event}):`, e);
                }
            });
        }
    }

    /**
     * Resize handler
     */
    resize() {
        if (this.deck) {
            this.deck.redraw(true);
        }
        if (this.maplibre) {
            this.maplibre.resize();
        }
    }

    /**
     * Destroy the renderer
     */
    destroy() {
        if (this.deck) {
            this.deck.finalize();
            this.deck = null;
        }
        if (this.maplibre) {
            this.maplibre.remove();
            this.maplibre = null;
        }
        if (this.mapContainer && this.mapContainer.parentNode) {
            this.mapContainer.parentNode.removeChild(this.mapContainer);
        }
        if (this.deckContainer && this.deckContainer.parentNode) {
            this.deckContainer.parentNode.removeChild(this.deckContainer);
        }
    }
}

// Export for use
if (typeof window !== 'undefined') {
    window.DeckRenderer = DeckRenderer;
    window.VIEW_MODES = VIEW_MODES;
    window.VIEW_THRESHOLDS = VIEW_THRESHOLDS;
    window.STATUS_COLORS = STATUS_COLORS;
    window.TIER_COLORS = TIER_COLORS;
    window.NODE_SIZES = NODE_SIZES;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DeckRenderer, VIEW_MODES, VIEW_THRESHOLDS };
}
