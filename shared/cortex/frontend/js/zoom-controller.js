/**
 * HookProbe Cortex - Zoom Controller
 *
 * Handles zoom level detection, smooth camera transitions,
 * and coordinates between globe view and future map integration.
 *
 * Features:
 * - Altitude-based zoom level detection
 * - Smooth camera animations with easing
 * - Zoom level change events
 * - Programmatic zoom controls
 * - Auto-zoom to clusters on click
 * - Breadcrumb navigation for drill-down
 */

// Easing functions for smooth animations
const EASING = {
    // Standard easing curves
    linear: t => t,
    easeInQuad: t => t * t,
    easeOutQuad: t => t * (2 - t),
    easeInOutQuad: t => t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t,
    easeInCubic: t => t * t * t,
    easeOutCubic: t => (--t) * t * t + 1,
    easeInOutCubic: t => t < 0.5 ? 4 * t * t * t : (t - 1) * (2 * t - 2) * (2 * t - 2) + 1,
    easeOutBack: t => {
        const c1 = 1.70158;
        const c3 = c1 + 1;
        return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2);
    },
    easeOutElastic: t => {
        const c4 = (2 * Math.PI) / 3;
        return t === 0 ? 0 : t === 1 ? 1 :
            Math.pow(2, -10 * t) * Math.sin((t * 10 - 0.75) * c4) + 1;
    }
};

// Zoom transition presets
const ZOOM_PRESETS = {
    drillDown: {
        duration: 1200,
        easing: 'easeOutCubic',
        minAltitude: 0.15
    },
    zoomOut: {
        duration: 1000,
        easing: 'easeInOutQuad',
        maxAltitude: 3.0
    },
    focusNode: {
        duration: 1500,
        easing: 'easeOutBack',
        altitude: 0.4
    },
    focusCluster: {
        duration: 1200,
        easing: 'easeOutCubic',
        altitudeOffset: 0.2
    },
    resetView: {
        duration: 2000,
        easing: 'easeInOutCubic',
        altitude: 2.5,
        lat: 20,
        lng: 0
    }
};

/**
 * ZoomController - Manages camera position and zoom transitions
 */
class ZoomController {
    constructor(globe, clusterManager) {
        this.globe = globe;
        this.clusterManager = clusterManager;

        // State tracking
        this.currentZoomLevel = 'GLOBAL';
        this.currentAltitude = 2.5;
        this.isAnimating = false;
        this.animationId = null;

        // Navigation history for breadcrumb
        this.navigationHistory = [];
        this.maxHistoryLength = 10;

        // Event listeners
        this.eventListeners = new Map();

        // Throttle for zoom change events
        this.lastZoomEmit = 0;
        this.zoomEmitThrottle = 100; // ms

        // Bind methods
        this._onCameraChange = this._onCameraChange.bind(this);

        // Setup camera change listener
        this._setupCameraListener();
    }

    /**
     * Setup listener for camera changes
     */
    _setupCameraListener() {
        if (!this.globe) {
            return;
        }

        // Poll camera position since Globe.gl controls events are internal
        this._pollInterval = setInterval(() => {
            if (this.isAnimating) return;

            const pov = this.globe.pointOfView();
            if (Math.abs(pov.altitude - this.currentAltitude) > 0.01) {
                this._onCameraChange(pov);
            }
        }, 50);
    }

    /**
     * Handle camera position changes
     * @private
     */
    _onCameraChange(pov) {
        const previousLevel = this.currentZoomLevel;
        this.currentAltitude = pov.altitude;

        // Determine new zoom level
        const levelInfo = this.clusterManager
            ? this.clusterManager.getZoomLevelInfo(pov.altitude)
            : this._getZoomLevelInfo(pov.altitude);

        this.currentZoomLevel = levelInfo.name;

        // Emit throttled zoom change event
        const now = Date.now();
        if (now - this.lastZoomEmit > this.zoomEmitThrottle) {
            this.lastZoomEmit = now;

            this._emit('zoomChange', {
                altitude: pov.altitude,
                lat: pov.lat,
                lng: pov.lng,
                level: this.currentZoomLevel,
                previousLevel,
                zoom: this.clusterManager
                    ? this.clusterManager.altitudeToZoom(pov.altitude)
                    : this._altitudeToZoom(pov.altitude)
            });

            // Emit level change if changed
            if (previousLevel !== this.currentZoomLevel) {
                this._emit('zoomLevelChange', {
                    from: previousLevel,
                    to: this.currentZoomLevel,
                    altitude: pov.altitude
                });
            }
        }
    }

    /**
     * Animate camera to a new position
     * @param {Object} target - { lat, lng, altitude }
     * @param {Object} options - Animation options
     * @returns {Promise} Resolves when animation completes
     */
    animateTo(target, options = {}) {
        return new Promise((resolve, reject) => {
            if (!this.globe) {
                reject(new Error('Globe not initialized'));
                return;
            }

            const {
                duration = 1500,
                easing = 'easeOutCubic',
                onProgress = null,
                onComplete = null
            } = options;

            // Cancel any existing animation
            this.cancelAnimation();

            // Get current position
            const start = this.globe.pointOfView();
            const startTime = Date.now();

            this.isAnimating = true;
            this._emit('animationStart', { from: start, to: target, duration });

            const animate = () => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(1, elapsed / duration);
                const easedProgress = EASING[easing] ? EASING[easing](progress) : progress;

                // Interpolate position
                const current = {
                    lat: start.lat + (target.lat - start.lat) * easedProgress,
                    lng: this._interpolateLng(start.lng, target.lng, easedProgress),
                    altitude: start.altitude + (target.altitude - start.altitude) * easedProgress
                };

                this.globe.pointOfView(current, 0);

                if (onProgress) {
                    onProgress(progress, current);
                }

                if (progress < 1) {
                    this.animationId = requestAnimationFrame(animate);
                } else {
                    this.isAnimating = false;
                    this.animationId = null;

                    // Ensure exact final position
                    this.globe.pointOfView(target, 0);

                    if (onComplete) onComplete();
                    this._emit('animationComplete', { target });
                    resolve(target);
                }
            };

            this.animationId = requestAnimationFrame(animate);
        });
    }

    /**
     * Interpolate longitude handling the -180/180 wrap
     * @private
     */
    _interpolateLng(startLng, endLng, t) {
        // Handle crossing the antimeridian
        let diff = endLng - startLng;
        if (Math.abs(diff) > 180) {
            if (diff > 0) {
                startLng += 360;
            } else {
                endLng += 360;
            }
        }
        let result = startLng + (endLng - startLng) * t;
        // Normalize to -180 to 180
        while (result > 180) result -= 360;
        while (result < -180) result += 360;
        return result;
    }

    /**
     * Cancel ongoing animation
     */
    cancelAnimation() {
        if (this.animationId) {
            cancelAnimationFrame(this.animationId);
            this.animationId = null;
            this.isAnimating = false;
            this._emit('animationCancelled', {});
        }
    }

    /**
     * Drill down into a cluster
     * @param {Object} cluster - Cluster object from ClusterManager
     * @returns {Promise}
     */
    async drillDownCluster(cluster) {
        if (!cluster || !this.clusterManager) return;

        // Save current view to history
        this._pushHistory();

        // Get expansion zoom for this cluster
        const expansionZoom = cluster.expansionZoom ||
            this.clusterManager.getClusterExpansionZoom(cluster.clusterId);

        // Convert to altitude
        const targetAltitude = Math.max(
            ZOOM_PRESETS.drillDown.minAltitude,
            this.clusterManager.zoomToAltitude(expansionZoom)
        );

        this._emit('drillDown', {
            cluster,
            targetAltitude,
            expansionZoom
        });

        // Animate to cluster location
        await this.animateTo({
            lat: cluster.lat,
            lng: cluster.lng,
            altitude: targetAltitude
        }, {
            duration: ZOOM_PRESETS.drillDown.duration,
            easing: ZOOM_PRESETS.drillDown.easing
        });

        // Trigger cluster update in cluster manager
        if (this.clusterManager) {
            const zoom = this.clusterManager.altitudeToZoom(targetAltitude);
            this.clusterManager.getAllClusters(zoom);
        }
    }

    /**
     * Focus on a specific node
     * @param {Object} node - Node object
     * @returns {Promise}
     */
    async focusNode(node) {
        if (!node) return;

        this._pushHistory();

        this._emit('focusNode', { node });

        await this.animateTo({
            lat: node.lat,
            lng: node.lng,
            altitude: ZOOM_PRESETS.focusNode.altitude
        }, {
            duration: ZOOM_PRESETS.focusNode.duration,
            easing: ZOOM_PRESETS.focusNode.easing
        });
    }

    /**
     * Zoom out one level
     * @returns {Promise}
     */
    async zoomOut() {
        const pov = this.globe.pointOfView();
        const newAltitude = Math.min(
            ZOOM_PRESETS.zoomOut.maxAltitude,
            pov.altitude * 2
        );

        await this.animateTo({
            lat: pov.lat,
            lng: pov.lng,
            altitude: newAltitude
        }, {
            duration: ZOOM_PRESETS.zoomOut.duration,
            easing: ZOOM_PRESETS.zoomOut.easing
        });
    }

    /**
     * Zoom in one level
     * @returns {Promise}
     */
    async zoomIn() {
        const pov = this.globe.pointOfView();
        const newAltitude = Math.max(0.1, pov.altitude / 2);

        await this.animateTo({
            lat: pov.lat,
            lng: pov.lng,
            altitude: newAltitude
        }, {
            duration: ZOOM_PRESETS.drillDown.duration,
            easing: ZOOM_PRESETS.drillDown.easing
        });
    }

    /**
     * Go back to previous view
     * @returns {Promise}
     */
    async goBack() {
        const previous = this._popHistory();
        if (!previous) {
            return this.resetView();
        }

        this._emit('goBack', { to: previous });

        await this.animateTo(previous, {
            duration: ZOOM_PRESETS.zoomOut.duration,
            easing: ZOOM_PRESETS.zoomOut.easing
        });
    }

    /**
     * Reset to default global view
     * @returns {Promise}
     */
    async resetView() {
        this.navigationHistory = [];

        this._emit('resetView', {});

        await this.animateTo({
            lat: ZOOM_PRESETS.resetView.lat,
            lng: ZOOM_PRESETS.resetView.lng,
            altitude: ZOOM_PRESETS.resetView.altitude
        }, {
            duration: ZOOM_PRESETS.resetView.duration,
            easing: ZOOM_PRESETS.resetView.easing
        });
    }

    /**
     * Fly to a specific region
     * @param {string} region - Region name or coordinates
     * @returns {Promise}
     */
    async flyToRegion(region) {
        const regions = {
            'north-america': { lat: 40, lng: -100, altitude: 1.2 },
            'south-america': { lat: -15, lng: -60, altitude: 1.2 },
            'europe': { lat: 50, lng: 10, altitude: 0.8 },
            'africa': { lat: 5, lng: 20, altitude: 1.2 },
            'asia': { lat: 35, lng: 105, altitude: 1.2 },
            'oceania': { lat: -25, lng: 135, altitude: 1.0 }
        };

        const target = regions[region.toLowerCase()];
        if (!target) {
            console.warn(`Unknown region: ${region}`);
            return;
        }

        this._pushHistory();

        await this.animateTo(target, {
            duration: 2000,
            easing: 'easeInOutCubic'
        });
    }

    /**
     * Push current view to history
     * @private
     */
    _pushHistory() {
        if (!this.globe) return;

        const pov = this.globe.pointOfView();
        this.navigationHistory.push({
            lat: pov.lat,
            lng: pov.lng,
            altitude: pov.altitude,
            timestamp: Date.now()
        });

        // Limit history length
        if (this.navigationHistory.length > this.maxHistoryLength) {
            this.navigationHistory.shift();
        }
    }

    /**
     * Pop from history
     * @private
     */
    _popHistory() {
        return this.navigationHistory.pop();
    }

    /**
     * Get navigation breadcrumb
     * @returns {Array} Breadcrumb items
     */
    getBreadcrumb() {
        const crumbs = [{ label: 'Global', level: 'GLOBAL' }];
        const levelOrder = ['GLOBAL', 'CONTINENTAL', 'REGIONAL', 'CITY', 'STREET'];
        const currentIndex = levelOrder.indexOf(this.currentZoomLevel);

        for (let i = 1; i <= currentIndex; i++) {
            crumbs.push({
                label: ZOOM_LEVELS[levelOrder[i]].label,
                level: levelOrder[i]
            });
        }

        return crumbs;
    }

    /**
     * Fallback altitude to zoom conversion
     * @private
     */
    _altitudeToZoom(altitude) {
        return Math.max(0, Math.min(20, 14 - Math.log2(altitude * 10)));
    }

    /**
     * Fallback zoom level info
     * @private
     */
    _getZoomLevelInfo(altitude) {
        for (const [name, config] of Object.entries(ZOOM_LEVELS)) {
            if (altitude >= config.altitude) {
                return { name, ...config };
            }
        }
        return { name: 'STREET', ...ZOOM_LEVELS.STREET };
    }

    /**
     * Add event listener
     */
    on(event, callback) {
        if (!this.eventListeners.has(event)) {
            this.eventListeners.set(event, []);
        }
        this.eventListeners.get(event).push(callback);
    }

    /**
     * Remove event listener
     */
    off(event, callback) {
        if (!this.eventListeners.has(event)) return;
        const listeners = this.eventListeners.get(event);
        const index = listeners.indexOf(callback);
        if (index > -1) listeners.splice(index, 1);
    }

    /**
     * Emit event
     * @private
     */
    _emit(event, data) {
        if (!this.eventListeners.has(event)) return;
        this.eventListeners.get(event).forEach(callback => {
            try {
                callback(data);
            } catch (e) {
                console.error(`Error in ${event} listener:`, e);
            }
        });
    }

    /**
     * Cleanup
     */
    destroy() {
        this.cancelAnimation();
        if (this._pollInterval) {
            clearInterval(this._pollInterval);
        }
        this.eventListeners.clear();
    }
}

/**
 * ZoomIndicator - UI component showing current zoom level
 */
class ZoomIndicator {
    constructor(containerId, zoomController) {
        this.container = document.getElementById(containerId);
        this.zoomController = zoomController;

        if (!this.container) {
            this._createContainer();
        }

        this._setupListeners();
        this._render();
    }

    /**
     * Create indicator container if not exists
     * @private
     */
    _createContainer() {
        this.container = document.createElement('div');
        this.container.id = 'zoom-indicator';
        this.container.className = 'cortex-zoom-indicator';
        document.getElementById('app').appendChild(this.container);
    }

    /**
     * Setup event listeners
     * @private
     */
    _setupListeners() {
        if (!this.zoomController) return;

        this.zoomController.on('zoomLevelChange', (data) => {
            this._render();
            this._animateTransition(data.from, data.to);
        });

        this.zoomController.on('animationStart', () => {
            this.container.classList.add('animating');
        });

        this.zoomController.on('animationComplete', () => {
            this.container.classList.remove('animating');
        });
    }

    /**
     * Render the indicator
     * @private
     */
    _render() {
        const level = this.zoomController
            ? this.zoomController.currentZoomLevel
            : 'GLOBAL';

        const breadcrumb = this.zoomController
            ? this.zoomController.getBreadcrumb()
            : [{ label: 'Global', level: 'GLOBAL' }];

        this.container.innerHTML = `
            <div class="zoom-breadcrumb">
                ${breadcrumb.map((crumb, i) => `
                    <span class="crumb ${crumb.level === level ? 'active' : ''}"
                          onclick="window.zoomController?.flyToLevel?.('${crumb.level}')">
                        ${crumb.label}
                    </span>
                    ${i < breadcrumb.length - 1 ? '<span class="crumb-separator">›</span>' : ''}
                `).join('')}
            </div>
            <div class="zoom-controls">
                <button class="zoom-btn" onclick="window.zoomController?.zoomIn()" title="Zoom In">+</button>
                <button class="zoom-btn" onclick="window.zoomController?.zoomOut()" title="Zoom Out">−</button>
                <button class="zoom-btn" onclick="window.zoomController?.resetView()" title="Reset View">⌂</button>
            </div>
        `;
    }

    /**
     * Animate level transition
     * @private
     */
    _animateTransition(from, to) {
        this.container.classList.add('level-change');
        setTimeout(() => {
            this.container.classList.remove('level-change');
        }, 500);
    }
}

// Export for use in other modules
window.ZoomController = ZoomController;
window.ZoomIndicator = ZoomIndicator;
window.EASING = EASING;
window.ZOOM_PRESETS = ZOOM_PRESETS;
