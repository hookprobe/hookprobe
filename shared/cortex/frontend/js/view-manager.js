/**
 * View Manager - Orchestrates Globe <-> Map View Transitions
 *
 * Phase 2: Handles seamless transitions between:
 * - Globe.gl (Phase 1) for global view
 * - Deck.gl + MapLibre (Phase 2) for city-level view
 *
 * Features:
 * - Automatic view switching based on zoom level
 * - Smooth crossfade transitions
 * - State synchronization between views
 * - Support for both gradual migration and full Deck.gl mode
 */

'use strict';

// =============================================================================
// VIEW MANAGER CONFIGURATION
// =============================================================================

const VIEW_MANAGER_CONFIG = {
    // Altitude thresholds for Globe.gl (Phase 1)
    // Globe.gl altitude = (camera_distance - globe_radius) / globe_radius
    // With minDistance=101 and globe_radius~100, min altitude ≈ 0.01
    globeToMapAltitude: 0.20,      // Switch to map below this altitude (lowered from 0.25)
    mapToGlobeAltitude: 0.30,      // Switch to globe above this altitude (lowered from 0.35)

    // Zoom thresholds for Deck.gl (if using full Deck.gl mode)
    globeToMapZoom: 10,            // Increased from 8 for better transition
    mapToGlobeZoom: 7,             // Increased from 6

    // Transition settings
    transitionDuration: 600,       // ms for view switch animation
    fadeOverlayDuration: 400,      // ms for overlay fade

    // Polling interval for altitude check (ms)
    altitudeCheckInterval: 100,    // More responsive than 200ms

    // Mode settings
    useGlobeGL: true,              // Use Globe.gl for globe view (Phase 1)
    useDeckGL: true,               // Use Deck.gl for map view (Phase 2)

    // Mobile settings
    enableOnMobile: true,          // Enable view transitions on mobile
    debugMode: false               // Set true for altitude logging
};

// =============================================================================
// VIEW MANAGER CLASS
// =============================================================================

class ViewManager {
    constructor(options = {}) {
        this.config = { ...VIEW_MANAGER_CONFIG, ...options };

        // View instances
        this.globeGL = null;       // Globe.gl instance (Phase 1)
        this.deckRenderer = null;  // DeckRenderer instance (Phase 2)

        // Current state
        this.currentMode = 'globe';  // 'globe' | 'map'
        this.isTransitioning = false;
        this.lastViewState = null;

        // Integration references
        this.clusterManager = null;
        this.zoomController = null;

        // DOM elements
        this.globeContainer = null;
        this.mapContainer = null;
        this.transitionOverlay = null;

        // Event callbacks
        this._callbacks = {
            modeChange: [],
            transitionStart: [],
            transitionEnd: [],
            viewStateSync: []
        };
    }

    /**
     * Initialize with existing Globe.gl instance (Phase 1)
     */
    initWithGlobeGL(globeInstance, container) {
        this.globeGL = globeInstance;
        this.globeContainer = container;

        // Listen for Globe.gl zoom changes
        if (this.globeGL) {
            this._setupGlobeGLListeners();
        }

        console.log('ViewManager: Initialized with Globe.gl');
        return this;
    }

    /**
     * Initialize Deck.gl renderer for map view (Phase 2)
     */
    initDeckRenderer(container, options = {}) {
        this.mapContainer = container;

        // Create Deck.gl renderer if available
        if (typeof DeckRenderer !== 'undefined' && this.config.useDeckGL) {
            this.deckRenderer = new DeckRenderer(container, {
                mapStyle: options.mapStyle || getCortexMapStyle(),
                onViewStateChange: (viewState) => this._onDeckViewChange(viewState),
                onNodeClick: options.onNodeClick,
                onClusterClick: options.onClusterClick,
                ...options
            });

            // Listen for mode changes from DeckRenderer
            this.deckRenderer.on('modeChange', (data) => {
                if (data.mode === 'globe' && this.currentMode === 'map') {
                    this._onDeckRequestGlobe();
                }
            });

            // Initially hide map container
            if (this.mapContainer) {
                this.mapContainer.style.display = 'none';
            }

            console.log('ViewManager: DeckRenderer initialized');
        } else {
            console.warn('ViewManager: DeckRenderer not available, map view disabled');
        }

        return this;
    }

    /**
     * Create transition overlay element
     */
    initTransitionOverlay(parentContainer) {
        this.transitionOverlay = document.createElement('div');
        this.transitionOverlay.id = 'view-transition-overlay';
        this.transitionOverlay.className = 'cortex-view-transition';
        this.transitionOverlay.innerHTML = `
            <div class="transition-content">
                <div class="transition-spinner"></div>
                <div class="transition-text">TRANSITIONING</div>
            </div>
        `;

        parentContainer.appendChild(this.transitionOverlay);
        return this;
    }

    /**
     * Connect to ClusterManager (Phase 1)
     */
    setClusterManager(clusterManager) {
        this.clusterManager = clusterManager;
        return this;
    }

    /**
     * Connect to ZoomController (Phase 1)
     */
    setZoomController(zoomController) {
        this.zoomController = zoomController;

        // Listen for zoom level changes
        if (zoomController) {
            zoomController.on('zoomChange', (data) => this._onZoomChange(data));
        }

        return this;
    }

    /**
     * Setup Globe.gl event listeners
     */
    _setupGlobeGLListeners() {
        // Track last altitude for change detection
        this._lastAltitude = null;

        // We need to poll Globe.gl since it doesn't have clean event API
        this._globeCheckInterval = setInterval(() => {
            if (!this.globeGL || this.isTransitioning) return;

            const pov = this.globeGL.pointOfView();
            if (pov && pov.altitude !== undefined) {
                // Debug logging when enabled
                if (this.config.debugMode && this._lastAltitude !== pov.altitude) {
                    console.log('[ViewManager] Altitude:', pov.altitude.toFixed(3),
                        '| Threshold:', this.config.globeToMapAltitude);
                }
                this._lastAltitude = pov.altitude;
                this._checkGlobeAltitude(pov.altitude, pov.lat, pov.lng);
            }
        }, this.config.altitudeCheckInterval || 100);

        console.log('[ViewManager] Globe.gl listeners initialized, checking altitude every',
            this.config.altitudeCheckInterval || 100, 'ms');
    }

    /**
     * Check Globe.gl altitude for view transition
     */
    _checkGlobeAltitude(altitude, lat, lng) {
        if (this.currentMode === 'globe' && altitude < this.config.globeToMapAltitude) {
            this.transitionToMap(lat, lng);
        }
    }

    /**
     * Handle zoom changes from ZoomController
     */
    _onZoomChange(data) {
        const { altitude, level, lat, lng } = data;

        // Store for potential transitions
        this.lastViewState = { altitude, level, lat, lng };

        // Check if we should switch to map view
        if (this.currentMode === 'globe' && level === 'STREET') {
            this.transitionToMap(lat, lng);
        }
    }

    /**
     * Handle Deck.gl view state changes
     */
    _onDeckViewChange(viewState) {
        this.lastViewState = viewState;
        this._emit('viewStateSync', { viewState, mode: this.currentMode });
    }

    /**
     * Handle Deck.gl requesting globe view
     */
    _onDeckRequestGlobe() {
        this.transitionToGlobe();
    }

    /**
     * Transition from globe to map view
     */
    async transitionToMap(lat, lng, zoom = 14) {
        if (this.currentMode === 'map' || this.isTransitioning) return;
        if (!this.deckRenderer) {
            console.warn('ViewManager: No DeckRenderer available for map view');
            return;
        }

        this.isTransitioning = true;
        this._emit('transitionStart', { from: 'globe', to: 'map' });
        console.log('ViewManager: Transitioning to map view');

        // Show transition overlay
        this._showOverlay();

        // Sync data to DeckRenderer
        this._syncDataToMap();

        // Wait for overlay
        await this._wait(this.config.fadeOverlayDuration);

        // Hide Globe.gl
        if (this.globeContainer) {
            this.globeContainer.style.display = 'none';
        }

        // Show Deck.gl map
        if (this.mapContainer) {
            this.mapContainer.style.display = 'block';
        }

        // Set map view position
        this.deckRenderer.setMapMode(lat, lng, zoom);

        // Hide overlay
        await this._wait(200);
        this._hideOverlay();

        // Update state
        this.currentMode = 'map';
        this.isTransitioning = false;

        this._emit('modeChange', { mode: 'map', lat, lng, zoom });
        this._emit('transitionEnd', { mode: 'map' });

        // Update UI
        this._updateModeIndicator('map');
    }

    /**
     * Transition from map to globe view
     */
    async transitionToGlobe() {
        if (this.currentMode === 'globe' || this.isTransitioning) return;

        this.isTransitioning = true;
        this._emit('transitionStart', { from: 'map', to: 'globe' });
        console.log('ViewManager: Transitioning to globe view');

        // Show overlay
        this._showOverlay();

        await this._wait(this.config.fadeOverlayDuration);

        // Hide Deck.gl map
        if (this.mapContainer) {
            this.mapContainer.style.display = 'none';
        }

        // Show Globe.gl
        if (this.globeContainer) {
            this.globeContainer.style.display = 'block';
        }

        // Restore Globe.gl view position
        if (this.globeGL && this.lastViewState) {
            this.globeGL.pointOfView({
                lat: this.lastViewState.latitude || this.lastViewState.lat || 20,
                lng: this.lastViewState.longitude || this.lastViewState.lng || 0,
                altitude: this.config.mapToGlobeAltitude + 0.1
            }, 500);
        }

        // Hide overlay
        await this._wait(200);
        this._hideOverlay();

        // Update state
        this.currentMode = 'globe';
        this.isTransitioning = false;

        this._emit('modeChange', { mode: 'globe' });
        this._emit('transitionEnd', { mode: 'globe' });

        // Update UI
        this._updateModeIndicator('globe');
    }

    /**
     * Sync node/cluster data from Phase 1 to DeckRenderer
     */
    _syncDataToMap() {
        if (!this.deckRenderer) return;

        // Sync nodes from ClusterManager or state
        if (this.clusterManager && this.clusterManager.nodes) {
            this.deckRenderer.setNodes(this.clusterManager.nodes);
        } else if (window.state && window.state.nodes) {
            const nodes = Object.values(window.state.nodes).map(n => ({
                id: n.id,
                lat: n.lat,
                lng: n.lng,
                tier: n.tier,
                status: n.status,
                label: n.label,
                online: n.online,
                qsecbit: n.qsecbit
            }));
            this.deckRenderer.setNodes(nodes);
        }

        // Sync clusters
        if (this.clusterManager) {
            const clusters = this.clusterManager.getAllClusters(8);
            this.deckRenderer.setClusters(clusters.filter(c => c.properties?.cluster));
        }
    }

    /**
     * Update nodes in DeckRenderer
     */
    updateNodes(nodes) {
        if (this.deckRenderer && this.currentMode === 'map') {
            this.deckRenderer.setNodes(nodes);
        }
    }

    /**
     * Update clusters in DeckRenderer
     */
    updateClusters(clusters) {
        if (this.deckRenderer && this.currentMode === 'map') {
            this.deckRenderer.setClusters(clusters);
        }
    }

    /**
     * Update arcs (attacks) in DeckRenderer
     */
    updateArcs(arcs) {
        if (this.deckRenderer && this.currentMode === 'map') {
            this.deckRenderer.setArcs(arcs);
        }
    }

    /**
     * Show transition overlay
     */
    _showOverlay() {
        if (this.transitionOverlay) {
            this.transitionOverlay.classList.add('active');
        }
    }

    /**
     * Hide transition overlay
     */
    _hideOverlay() {
        if (this.transitionOverlay) {
            this.transitionOverlay.classList.remove('active');
        }
    }

    /**
     * Update mode indicator UI element
     */
    _updateModeIndicator(mode) {
        const indicator = document.getElementById('view-mode-indicator');
        if (indicator) {
            indicator.textContent = mode === 'map' ? '2D MAP' : '3D GLOBE';
            indicator.className = `view-mode-indicator ${mode}`;
        }

        // Update zoom indicator if present
        const zoomIndicator = document.getElementById('zoom-indicator');
        if (zoomIndicator) {
            if (mode === 'map') {
                zoomIndicator.classList.add('map-mode');
            } else {
                zoomIndicator.classList.remove('map-mode');
            }
        }
    }

    /**
     * Get current view mode
     */
    getMode() {
        return this.currentMode;
    }

    /**
     * Check if currently in map mode
     */
    isMapMode() {
        return this.currentMode === 'map';
    }

    /**
     * Check if currently in globe mode
     */
    isGlobeMode() {
        return this.currentMode === 'globe';
    }

    /**
     * Force specific mode
     */
    async setMode(mode, options = {}) {
        if (mode === 'map' && this.currentMode !== 'map') {
            await this.transitionToMap(
                options.lat || 0,
                options.lng || 0,
                options.zoom || 14
            );
        } else if (mode === 'globe' && this.currentMode !== 'globe') {
            await this.transitionToGlobe();
        }
    }

    /**
     * Promise-based wait utility
     */
    _wait(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
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
                    console.error(`ViewManager: Event callback error (${event}):`, e);
                }
            });
        }
    }

    /**
     * Cleanup and destroy
     */
    destroy() {
        // Clear Globe.gl polling
        if (this._globeCheckInterval) {
            clearInterval(this._globeCheckInterval);
        }

        // Destroy DeckRenderer
        if (this.deckRenderer) {
            this.deckRenderer.destroy();
            this.deckRenderer = null;
        }

        // Remove overlay
        if (this.transitionOverlay && this.transitionOverlay.parentNode) {
            this.transitionOverlay.parentNode.removeChild(this.transitionOverlay);
        }

        // Clear references
        this.globeGL = null;
        this.clusterManager = null;
        this.zoomController = null;
        this._callbacks = { modeChange: [], transitionStart: [], transitionEnd: [], viewStateSync: [] };

        console.log('ViewManager: Destroyed');
    }
}

// =============================================================================
// VIEW MODE INDICATOR COMPONENT
// =============================================================================

class ViewModeIndicator {
    constructor(container) {
        this.container = typeof container === 'string'
            ? document.getElementById(container)
            : container;

        this.element = null;
        this._create();
    }

    _create() {
        this.element = document.createElement('div');
        this.element.id = 'view-mode-indicator';
        this.element.className = 'view-mode-indicator globe';
        this.element.innerHTML = `
            <span class="mode-icon globe-icon">&#127758;</span>
            <span class="mode-icon map-icon">&#128506;</span>
            <span class="mode-text">3D GLOBE</span>
        `;

        if (this.container) {
            this.container.appendChild(this.element);
        }
    }

    setMode(mode) {
        if (!this.element) return;

        this.element.className = `view-mode-indicator ${mode}`;
        const textEl = this.element.querySelector('.mode-text');
        if (textEl) {
            textEl.textContent = mode === 'map' ? '2D MAP' : '3D GLOBE';
        }
    }

    destroy() {
        if (this.element && this.element.parentNode) {
            this.element.parentNode.removeChild(this.element);
        }
    }
}

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

/**
 * Create and initialize ViewManager with all components
 */
function createViewManager(options = {}) {
    const manager = new ViewManager(options.config);

    // Initialize with Globe.gl if provided
    if (options.globeGL && options.globeContainer) {
        manager.initWithGlobeGL(options.globeGL, options.globeContainer);
    }

    // Initialize DeckRenderer if container provided
    if (options.mapContainer) {
        manager.initDeckRenderer(options.mapContainer, options.deckOptions || {});
    }

    // Initialize transition overlay
    if (options.overlayContainer) {
        manager.initTransitionOverlay(options.overlayContainer);
    }

    // Connect ClusterManager
    if (options.clusterManager) {
        manager.setClusterManager(options.clusterManager);
    }

    // Connect ZoomController
    if (options.zoomController) {
        manager.setZoomController(options.zoomController);
    }

    return manager;
}

// =============================================================================
// EXPORTS
// =============================================================================

if (typeof window !== 'undefined') {
    window.ViewManager = ViewManager;
    window.ViewModeIndicator = ViewModeIndicator;
    window.VIEW_MANAGER_CONFIG = VIEW_MANAGER_CONFIG;
    window.createViewManager = createViewManager;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ViewManager,
        ViewModeIndicator,
        VIEW_MANAGER_CONFIG,
        createViewManager
    };
}
