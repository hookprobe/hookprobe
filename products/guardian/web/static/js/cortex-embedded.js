/**
 * HookProbe Cortex Embedded Globe with City-Level Zoom
 *
 * Phase 2 Implementation:
 * - Globe.gl for 3D Earth view
 * - MapLibre GL for city-level 2D map
 * - Deck.gl for GPU-accelerated point rendering
 * - Smooth transitions between views
 */

// View modes
const VIEW_MODE = {
    GLOBE: 'globe',
    MAP: 'map'
};

// Zoom thresholds
const ZOOM_THRESHOLD = {
    GLOBE_TO_MAP: 4,      // Altitude at which to switch to map
    MAP_TO_GLOBE: 0.8     // MapLibre zoom at which to switch to globe
};

// Globe instance
let globe = null;
let mapInstance = null;
let deckOverlay = null;
let isInitialized = false;
let currentViewMode = VIEW_MODE.GLOBE;

// Data state
const cortexState = {
    nodes: [],
    arcs: [],
    demoMode: true,
    guardianLocation: null,
    currentZoom: 2,
    stats: {
        attacks: 0,
        repelled: 0,
        avgQsecbit: 0,
        byTier: {
            sentinel: 0,
            guardian: 0,
            fortress: 0,
            nexus: 0
        }
    }
};

// Arc colors
const ARC_COLORS = {
    attack: ['rgba(255, 68, 68, 0.8)', 'rgba(255, 68, 68, 0.2)'],
    repelled: ['rgba(0, 191, 255, 0.8)', 'rgba(0, 191, 255, 0.2)']
};

// Node colors based on Qsecbit status
const NODE_COLORS = {
    green: [16, 185, 129],
    amber: [245, 158, 11],
    red: [239, 68, 68]
};

const NODE_COLORS_HEX = {
    green: '#10b981',
    amber: '#f59e0b',
    red: '#ef4444'
};

// Tier sizes
const TIER_SIZES = {
    sentinel: 0.3,
    guardian: 0.6,
    fortress: 0.9,
    nexus: 1.2
};

/**
 * Initialize the Cortex globe
 */
function initCortexGlobe() {
    if (isInitialized) return;

    console.log('Initializing Cortex Globe with City-Level Zoom...');

    // First fetch location
    fetchGuardianLocation().then(() => {
        // Check WebGL support
        if (!isWebGLSupported()) {
            console.warn('WebGL not supported, using 2D fallback');
            show2DFallback();
        } else {
            initGlobeGL();
            initMapView();
        }

        // Set up controls
        setupControls();

        // Initial data load
        refreshData();

        // Start polling for updates
        setInterval(refreshData, 10000);

        isInitialized = true;
    });
}

/**
 * Fetch Guardian's location from API
 */
async function fetchGuardianLocation() {
    try {
        const response = await fetch('/api/cortex/location');
        if (response.ok) {
            cortexState.guardianLocation = await response.json();
            updateLocationDisplay();
        }
    } catch (error) {
        console.error('Failed to fetch location:', error);
        cortexState.guardianLocation = { lat: 51.5074, lng: -0.1278, label: 'London, UK' };
    }
}

/**
 * Update location display
 */
function updateLocationDisplay() {
    const label = document.getElementById('cortex-node-label');
    if (label && cortexState.guardianLocation) {
        const loc = cortexState.guardianLocation;
        if (loc.city && loc.country) {
            label.textContent = `${loc.city}, ${loc.country}`;
        } else if (loc.label) {
            label.textContent = loc.label;
        }
    }
}

/**
 * Check WebGL support
 */
function isWebGLSupported() {
    try {
        const canvas = document.createElement('canvas');
        return !!(
            window.WebGLRenderingContext &&
            (canvas.getContext('webgl') || canvas.getContext('experimental-webgl'))
        );
    } catch (e) {
        return false;
    }
}

/**
 * Initialize Globe.gl
 */
function initGlobeGL() {
    const container = document.getElementById('globe-container');
    if (!container) return;

    const loading = document.getElementById('cortex-loading');

    try {
        // Create globe instance
        globe = Globe()(container)
            .globeImageUrl('https://unpkg.com/three-globe@2.24.10/example/img/earth-night.jpg')
            .bumpImageUrl('https://unpkg.com/three-globe@2.24.10/example/img/earth-topology.png')
            .backgroundImageUrl('https://unpkg.com/three-globe@2.24.10/example/img/night-sky.png')
            .showAtmosphere(true)
            .atmosphereColor('#00bfff')
            .atmosphereAltitude(0.15)
            // Node points
            .pointsData(cortexState.nodes)
            .pointLat(d => d.lat)
            .pointLng(d => d.lng)
            .pointColor(d => NODE_COLORS_HEX[d.status] || NODE_COLORS_HEX.green)
            .pointAltitude(0.01)
            .pointRadius(d => TIER_SIZES[d.tier] || 0.5)
            .pointLabel(d => `<div style="background:#111;padding:8px;border-radius:4px;border:1px solid #333;">
                <strong>${d.label}</strong><br/>
                Tier: ${d.tier}<br/>
                Qsecbit: ${d.qsecbit?.toFixed(3) || 'N/A'}<br/>
                Status: ${d.status}
            </div>`)
            // Attack arcs
            .arcsData(cortexState.arcs)
            .arcStartLat(d => d.source.lat)
            .arcStartLng(d => d.source.lng)
            .arcEndLat(d => d.target.lat)
            .arcEndLng(d => d.target.lng)
            .arcColor(d => d.type === 'attack' ? ARC_COLORS.attack : ARC_COLORS.repelled)
            .arcDashLength(0.5)
            .arcDashGap(0.1)
            .arcDashAnimateTime(1500)
            .arcStroke(d => d.type === 'attack' ? 0.5 : 0.3)
            .arcsTransitionDuration(300)
            // Click to zoom
            .onPointClick(handleNodeClick);

        // Monitor zoom level for view switching
        globe.controls().addEventListener('change', handleGlobeZoomChange);

        // Auto-rotate
        globe.controls().autoRotate = true;
        globe.controls().autoRotateSpeed = 0.3;

        // Stop rotation on interaction
        container.addEventListener('mousedown', () => {
            globe.controls().autoRotate = false;
        });

        // Resize handler
        const resizeObserver = new ResizeObserver(() => {
            if (globe && container.offsetWidth && container.offsetHeight) {
                globe.width(container.offsetWidth);
                globe.height(container.offsetHeight);
            }
        });
        resizeObserver.observe(container);

        // Point to Guardian location if available
        if (cortexState.guardianLocation && cortexState.guardianLocation.lat !== 0) {
            setTimeout(() => {
                globe.pointOfView({
                    lat: cortexState.guardianLocation.lat,
                    lng: cortexState.guardianLocation.lng,
                    altitude: 2
                }, 1000);
            }, 500);
        }

        if (loading) loading.style.display = 'none';
        console.log('Globe initialized successfully');
    } catch (error) {
        console.error('Globe initialization failed:', error);
        show2DFallback();
    }
}

/**
 * Initialize MapLibre GL for city-level view
 */
function initMapView() {
    // Create map container (hidden initially)
    let mapContainer = document.getElementById('map-container');
    if (!mapContainer) {
        mapContainer = document.createElement('div');
        mapContainer.id = 'map-container';
        mapContainer.className = 'cortex-map';
        mapContainer.style.cssText = 'position: absolute; inset: 0; display: none; z-index: 5;';

        const wrapper = document.querySelector('.cortex-globe-wrapper');
        if (wrapper) {
            wrapper.appendChild(mapContainer);
        }
    }

    // Check if MapLibre is available
    if (typeof maplibregl === 'undefined') {
        console.warn('MapLibre GL not loaded, city view disabled');
        return;
    }

    try {
        // Initialize MapLibre with dark theme
        mapInstance = new maplibregl.Map({
            container: 'map-container',
            style: {
                version: 8,
                sources: {
                    'osm-tiles': {
                        type: 'raster',
                        tiles: [
                            'https://a.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}@2x.png',
                            'https://b.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}@2x.png',
                            'https://c.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}@2x.png'
                        ],
                        tileSize: 256,
                        attribution: '&copy; OpenStreetMap contributors &copy; CARTO'
                    }
                },
                layers: [{
                    id: 'osm-tiles',
                    type: 'raster',
                    source: 'osm-tiles',
                    minzoom: 0,
                    maxzoom: 19
                }]
            },
            center: [cortexState.guardianLocation?.lng || 0, cortexState.guardianLocation?.lat || 51.5],
            zoom: 10,
            attributionControl: false
        });

        // Add navigation controls
        mapInstance.addControl(new maplibregl.NavigationControl(), 'top-right');

        // Monitor zoom for switching back to globe
        mapInstance.on('zoom', handleMapZoomChange);

        // Add Deck.gl overlay when ready
        mapInstance.on('load', initDeckOverlay);

        console.log('MapLibre GL initialized');
    } catch (error) {
        console.error('MapLibre initialization failed:', error);
    }
}

/**
 * Initialize Deck.gl overlay for GPU-accelerated rendering
 */
function initDeckOverlay() {
    if (!mapInstance || typeof deck === 'undefined') {
        console.warn('Deck.gl not available');
        return;
    }

    try {
        // Create Deck.gl overlay
        deckOverlay = new deck.MapboxOverlay({
            interleaved: true,
            layers: createDeckLayers()
        });

        mapInstance.addControl(deckOverlay);
        console.log('Deck.gl overlay initialized');
    } catch (error) {
        console.error('Deck.gl overlay failed:', error);
    }
}

/**
 * Create Deck.gl layers for city view
 */
function createDeckLayers() {
    const layers = [];

    // Scatterplot layer for nodes
    layers.push(new deck.ScatterplotLayer({
        id: 'nodes-layer',
        data: cortexState.nodes,
        pickable: true,
        opacity: 0.8,
        stroked: true,
        filled: true,
        radiusScale: 50,
        radiusMinPixels: 8,
        radiusMaxPixels: 30,
        lineWidthMinPixels: 2,
        getPosition: d => [d.lng, d.lat],
        getRadius: d => (TIER_SIZES[d.tier] || 0.5) * 100,
        getFillColor: d => [...(NODE_COLORS[d.status] || NODE_COLORS.green), 200],
        getLineColor: d => [...(NODE_COLORS[d.status] || NODE_COLORS.green), 255],
        onClick: info => {
            if (info.object) {
                showNodePopup(info.object);
            }
        }
    }));

    // Arc layer for attacks
    if (cortexState.arcs.length > 0) {
        layers.push(new deck.ArcLayer({
            id: 'arcs-layer',
            data: cortexState.arcs,
            pickable: true,
            getWidth: 3,
            getSourcePosition: d => [d.source.lng, d.source.lat],
            getTargetPosition: d => [d.target.lng, d.target.lat],
            getSourceColor: d => d.type === 'attack' ? [255, 68, 68, 200] : [0, 191, 255, 200],
            getTargetColor: d => d.type === 'attack' ? [255, 68, 68, 50] : [0, 191, 255, 50]
        }));
    }

    return layers;
}

/**
 * Handle globe zoom changes to detect when to switch to map
 */
function handleGlobeZoomChange() {
    if (!globe) return;

    const pov = globe.pointOfView();
    cortexState.currentZoom = pov.altitude;

    // Check if we should switch to map view
    if (pov.altitude < ZOOM_THRESHOLD.GLOBE_TO_MAP && currentViewMode === VIEW_MODE.GLOBE) {
        transitionToMap(pov.lat, pov.lng);
    }
}

/**
 * Handle map zoom changes to detect when to switch back to globe
 */
function handleMapZoomChange() {
    if (!mapInstance) return;

    const zoom = mapInstance.getZoom();

    // Check if we should switch back to globe
    if (zoom < ZOOM_THRESHOLD.MAP_TO_GLOBE && currentViewMode === VIEW_MODE.MAP) {
        const center = mapInstance.getCenter();
        transitionToGlobe(center.lat, center.lng);
    }
}

/**
 * Transition from Globe to Map view
 */
function transitionToMap(lat, lng) {
    if (currentViewMode === VIEW_MODE.MAP) return;

    console.log('Transitioning to city view...', { lat, lng });
    currentViewMode = VIEW_MODE.MAP;

    const globeContainer = document.getElementById('globe-container');
    const mapContainer = document.getElementById('map-container');

    // Fade out globe
    if (globeContainer) {
        globeContainer.style.transition = 'opacity 0.5s ease';
        globeContainer.style.opacity = '0';
    }

    // Position and show map
    if (mapInstance && mapContainer) {
        mapInstance.setCenter([lng, lat]);
        mapInstance.setZoom(12);

        setTimeout(() => {
            if (globeContainer) globeContainer.style.display = 'none';
            mapContainer.style.display = 'block';
            mapContainer.style.opacity = '0';
            mapContainer.style.transition = 'opacity 0.5s ease';

            requestAnimationFrame(() => {
                mapContainer.style.opacity = '1';
                mapInstance.resize();
                updateDeckLayers();
            });
        }, 400);
    }

    // Show city view indicator
    showViewModeIndicator('City View');
}

/**
 * Transition from Map to Globe view
 */
function transitionToGlobe(lat, lng) {
    if (currentViewMode === VIEW_MODE.GLOBE) return;

    console.log('Transitioning to globe view...', { lat, lng });
    currentViewMode = VIEW_MODE.GLOBE;

    const globeContainer = document.getElementById('globe-container');
    const mapContainer = document.getElementById('map-container');

    // Fade out map
    if (mapContainer) {
        mapContainer.style.transition = 'opacity 0.5s ease';
        mapContainer.style.opacity = '0';
    }

    // Show and position globe
    if (globe && globeContainer) {
        setTimeout(() => {
            if (mapContainer) mapContainer.style.display = 'none';
            globeContainer.style.display = 'block';
            globeContainer.style.opacity = '0';
            globeContainer.style.transition = 'opacity 0.5s ease';

            globe.pointOfView({ lat, lng, altitude: ZOOM_THRESHOLD.GLOBE_TO_MAP + 0.5 }, 500);

            requestAnimationFrame(() => {
                globeContainer.style.opacity = '1';
            });
        }, 400);
    }

    // Show globe view indicator
    showViewModeIndicator('Globe View');
}

/**
 * Update Deck.gl layers with current data
 */
function updateDeckLayers() {
    if (deckOverlay) {
        deckOverlay.setProps({
            layers: createDeckLayers()
        });
    }
}

/**
 * Show view mode indicator temporarily
 */
function showViewModeIndicator(mode) {
    let indicator = document.getElementById('view-mode-indicator');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'view-mode-indicator';
        indicator.style.cssText = `
            position: absolute;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(0,0,0,0.8);
            color: #00bfff;
            padding: 8px 20px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
            z-index: 100;
            transition: opacity 0.3s;
            pointer-events: none;
        `;
        document.querySelector('.cortex-globe-wrapper')?.appendChild(indicator);
    }

    indicator.textContent = mode;
    indicator.style.opacity = '1';

    setTimeout(() => {
        indicator.style.opacity = '0';
    }, 2000);
}

/**
 * Handle node click to zoom in
 */
function handleNodeClick(node) {
    if (!node) return;

    if (currentViewMode === VIEW_MODE.GLOBE) {
        // Zoom in on globe, which will trigger transition to map
        globe.pointOfView({
            lat: node.lat,
            lng: node.lng,
            altitude: ZOOM_THRESHOLD.GLOBE_TO_MAP - 1
        }, 1000);
    }
}

/**
 * Show node popup on map
 */
function showNodePopup(node) {
    if (!mapInstance) return;

    // Remove existing popups
    const existingPopups = document.querySelectorAll('.maplibregl-popup');
    existingPopups.forEach(p => p.remove());

    const popup = new maplibregl.Popup({ closeOnClick: true })
        .setLngLat([node.lng, node.lat])
        .setHTML(`
            <div style="background:#1a1d2e;padding:12px;border-radius:8px;color:#fff;min-width:180px;">
                <div style="font-weight:600;font-size:14px;margin-bottom:8px;">${node.label}</div>
                <div style="display:grid;gap:4px;font-size:12px;color:#94a3b8;">
                    <div>Tier: <span style="color:#fff;">${node.tier}</span></div>
                    <div>QSecBit: <span style="color:${NODE_COLORS_HEX[node.status]};">${node.qsecbit?.toFixed(3) || 'N/A'}</span></div>
                    <div>Status: <span style="color:${NODE_COLORS_HEX[node.status]};">${node.status}</span></div>
                </div>
            </div>
        `)
        .addTo(mapInstance);
}

/**
 * Show 2D fallback map
 */
function show2DFallback() {
    const globeContainer = document.getElementById('globe-container');
    const fallback = document.getElementById('map-fallback');
    const loading = document.getElementById('cortex-loading');

    if (globeContainer) globeContainer.style.display = 'none';
    if (fallback) fallback.style.display = 'flex';
    if (loading) loading.style.display = 'none';

    init2DMap();
}

/**
 * Initialize 2D canvas map
 */
function init2DMap() {
    const canvas = document.getElementById('fallback-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const wrapper = canvas.parentElement;

    const resize = () => {
        canvas.width = wrapper.offsetWidth - 20;
        canvas.height = Math.min(400, wrapper.offsetHeight - 40);
        draw2DMap(ctx, canvas);
    };

    resize();
    window.addEventListener('resize', resize);
}

/**
 * Draw 2D map
 */
function draw2DMap(ctx, canvas) {
    // Background
    ctx.fillStyle = '#0a0a0f';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Grid lines
    ctx.strokeStyle = '#1a1a2e';
    ctx.lineWidth = 1;

    for (let lat = -60; lat <= 60; lat += 30) {
        const y = ((90 - lat) / 180) * canvas.height;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
    }

    for (let lng = -150; lng <= 180; lng += 30) {
        const x = ((lng + 180) / 360) * canvas.width;
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
    }

    // Draw nodes
    cortexState.nodes.forEach(node => {
        const x = ((node.lng + 180) / 360) * canvas.width;
        const y = ((90 - node.lat) / 180) * canvas.height;
        const color = NODE_COLORS_HEX[node.status] || NODE_COLORS_HEX.green;
        const radius = (TIER_SIZES[node.tier] || 0.5) * 8;

        // Glow
        ctx.beginPath();
        ctx.arc(x, y, radius + 3, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.3;
        ctx.fill();
        ctx.globalAlpha = 1;

        // Node
        ctx.beginPath();
        ctx.arc(x, y, radius, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();

        // Label
        ctx.fillStyle = '#888';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, x, y + radius + 12);
    });

    // Draw arcs
    cortexState.arcs.forEach(arc => {
        const x1 = ((arc.source.lng + 180) / 360) * canvas.width;
        const y1 = ((90 - arc.source.lat) / 180) * canvas.height;
        const x2 = ((arc.target.lng + 180) / 360) * canvas.width;
        const y2 = ((90 - arc.target.lat) / 180) * canvas.height;

        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.strokeStyle = arc.type === 'attack' ? '#ff4444' : '#00bfff';
        ctx.lineWidth = 2;
        ctx.stroke();
    });
}

/**
 * Setup controls
 */
function setupControls() {
    const demoBtn = document.getElementById('cortex-demo-btn');
    const liveBtn = document.getElementById('cortex-live-btn');

    if (demoBtn) {
        demoBtn.addEventListener('click', () => {
            setMode(true);
            demoBtn.classList.add('active');
            if (liveBtn) liveBtn.classList.remove('active');
        });
    }

    if (liveBtn) {
        liveBtn.addEventListener('click', () => {
            setMode(false);
            liveBtn.classList.add('active');
            if (demoBtn) demoBtn.classList.remove('active');
        });
    }

    const clearBtn = document.getElementById('cortex-clear-events');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearEvents);
    }
}

/**
 * Set demo/live mode
 */
async function setMode(demoMode) {
    try {
        await fetch('/api/cortex/demo/toggle', { method: 'POST' });
        cortexState.demoMode = demoMode;
        refreshData();
    } catch (error) {
        console.error('Failed to toggle mode:', error);
    }
}

/**
 * Refresh data from API
 */
async function refreshData() {
    try {
        const response = await fetch('/api/cortex/demo/data');
        if (response.ok) {
            const data = await response.json();
            processData(data);
        }
    } catch (error) {
        console.error('Failed to refresh data:', error);
    }
}

/**
 * Process data from API
 */
function processData(data) {
    // Update nodes
    cortexState.nodes = data.nodes || [];
    if (globe) {
        globe.pointsData(cortexState.nodes);
    }

    // Update Deck.gl layers if in map mode
    if (currentViewMode === VIEW_MODE.MAP) {
        updateDeckLayers();
    }

    // Process events as arcs
    if (data.events && data.events.length > 0) {
        data.events.forEach(event => {
            addArc(event);
            addEventToLog(event);
        });
    }

    // Update stats
    updateStats(data);

    // Redraw 2D if in fallback mode
    const canvas = document.getElementById('fallback-canvas');
    if (canvas && canvas.offsetParent !== null) {
        const ctx = canvas.getContext('2d');
        draw2DMap(ctx, canvas);
    }
}

/**
 * Add arc to globe
 */
function addArc(event) {
    const arc = {
        id: event.id || Date.now(),
        type: event.type === 'attack_repelled' ? 'repelled' : 'attack',
        source: event.source,
        target: event.target,
        timestamp: Date.now()
    };

    cortexState.arcs.push(arc);

    // Remove arc after animation
    setTimeout(() => {
        cortexState.arcs = cortexState.arcs.filter(a => a.id !== arc.id);
        if (globe) globe.arcsData(cortexState.arcs);
        if (currentViewMode === VIEW_MODE.MAP) updateDeckLayers();
    }, 3000);

    if (globe) globe.arcsData(cortexState.arcs);
    if (currentViewMode === VIEW_MODE.MAP) updateDeckLayers();

    // Update counters
    if (arc.type === 'attack') {
        cortexState.stats.attacks++;
    } else {
        cortexState.stats.repelled++;
    }
}

/**
 * Update stats display
 */
function updateStats(data) {
    const stats = data.stats || {};
    const byTier = stats.by_tier || {};

    document.getElementById('stat-nodes').textContent = stats.total_nodes || cortexState.nodes.length;
    document.getElementById('stat-attacks').textContent = cortexState.stats.attacks;
    document.getElementById('stat-repelled').textContent = cortexState.stats.repelled;

    if (cortexState.nodes.length > 0) {
        const totalQsecbit = cortexState.nodes.reduce((sum, n) => sum + (n.qsecbit || 0), 0);
        const avg = totalQsecbit / cortexState.nodes.length;
        document.getElementById('stat-qsecbit').textContent = avg.toFixed(3);
    }

    document.getElementById('stat-sentinels').textContent = byTier.sentinel || 0;
    document.getElementById('stat-guardians').textContent = byTier.guardian || 0;
    document.getElementById('stat-fortresses').textContent = byTier.fortress || 0;
    document.getElementById('stat-nexuses').textContent = byTier.nexus || 0;
}

/**
 * Add event to log
 */
function addEventToLog(event) {
    const list = document.getElementById('event-list');
    if (!list) return;

    const placeholder = list.querySelector('.cortex-event-placeholder');
    if (placeholder) placeholder.remove();

    const li = document.createElement('li');
    li.className = 'cortex-event-item';

    const time = new Date().toLocaleTimeString();
    const icon = event.type === 'attack_repelled' ? 'repelled' : 'attack';
    const iconColor = event.type === 'attack_repelled' ? '#00bfff' : '#ff4444';
    const sourceLabel = event.source?.label || 'Unknown';
    const targetLabel = event.target?.label || 'Unknown';

    li.innerHTML = `
        <span class="event-icon" style="color: ${iconColor};">${icon === 'attack' ? '\u26A0' : '\u2713'}</span>
        <span class="event-time">${time}</span>
        <span class="event-detail">${sourceLabel} \u2192 ${targetLabel}</span>
        <span class="event-type">${event.attack_type || 'unknown'}</span>
    `;

    list.insertBefore(li, list.firstChild);

    while (list.children.length > 20) {
        list.removeChild(list.lastChild);
    }
}

/**
 * Clear events log
 */
function clearEvents() {
    const list = document.getElementById('event-list');
    if (list) {
        list.innerHTML = '<li class="cortex-event-placeholder">Waiting for events...</li>';
    }
    cortexState.stats.attacks = 0;
    cortexState.stats.repelled = 0;
    document.getElementById('stat-attacks').textContent = '0';
    document.getElementById('stat-repelled').textContent = '0';
}

/**
 * Fly to a specific location (exposed for external use)
 */
function flyToLocation(lat, lng, zoom) {
    if (currentViewMode === VIEW_MODE.GLOBE && globe) {
        const altitude = zoom ? Math.max(0.5, 10 - zoom) : 1;
        globe.pointOfView({ lat, lng, altitude }, 1500);
    } else if (currentViewMode === VIEW_MODE.MAP && mapInstance) {
        mapInstance.flyTo({
            center: [lng, lat],
            zoom: zoom || 12,
            duration: 1500
        });
    }
}

// Export for external use
window.initCortexGlobe = initCortexGlobe;
window.refreshCortexData = refreshData;
window.flyToLocation = flyToLocation;
window.transitionToMap = transitionToMap;
window.transitionToGlobe = transitionToGlobe;
