/**
 * HookProbe Cortex Embedded - Guardian Integration
 *
 * Thin wrapper around shared/cortex/ modules for Guardian web UI.
 * Uses the full Cortex visualization stack:
 * - ClusterManager for spatial clustering
 * - ZoomController for camera animations
 * - ViewManager for Globe/Map transitions
 * - DeckRenderer for city-level GPU rendering
 */

'use strict';

// Guardian Cortex state
const guardianCortex = {
    initialized: false,
    globe: null,
    clusterManager: null,
    zoomController: null,
    viewManager: null,
    zoomIndicator: null,
    guardianLocation: null,
    demoMode: true,
    nodes: [],
    arcs: [],
    currentAltitude: 2.5,  // Track current zoom altitude for dynamic sizing
    stats: {
        attacks: 0,
        repelled: 0,
        avgQsecbit: 0,
        byTier: { sentinel: 0, guardian: 0, fortress: 0, nexus: 0 }
    }
};

// Arc colors
const ARC_COLORS = {
    attack: ['rgba(255, 68, 68, 0.8)', 'rgba(255, 68, 68, 0.2)'],
    repelled: ['rgba(0, 191, 255, 0.8)', 'rgba(0, 191, 255, 0.2)']
};

// Node colors
const NODE_COLORS = {
    green: '#00ff88',
    amber: '#ffaa00',
    red: '#ff4444'
};

// Tier sizes
const TIER_SIZES = {
    sentinel: 0.3,
    guardian: 0.5,
    fortress: 0.8,
    nexus: 1.2
};

/**
 * Initialize the Cortex globe with all shared modules
 */
function initCortexGlobe() {
    if (guardianCortex.initialized) return;

    console.log('Initializing Cortex with shared modules...');

    // First fetch Guardian location
    fetchGuardianLocation().then(() => {
        // Check WebGL support
        if (!isWebGLSupported()) {
            console.warn('WebGL not supported, using 2D fallback');
            show2DFallback();
            return;
        }

        // Initialize Globe.gl
        initGlobeGL();

        // Initialize clustering system (uses shared ClusterManager)
        initClusteringSystem();

        // Initialize view manager for Globe/Map transitions
        initViewManager();

        // Setup UI controls
        setupControls();

        // Load initial data
        refreshData();

        // Start polling
        setInterval(refreshData, 10000);

        guardianCortex.initialized = true;
        console.log('Cortex initialized with shared modules');
    });
}

/**
 * Fetch Guardian's location from API
 */
async function fetchGuardianLocation() {
    try {
        const response = await fetch('/api/cortex/location');
        if (response.ok) {
            guardianCortex.guardianLocation = await response.json();
            updateLocationDisplay();
        }
    } catch (error) {
        console.error('Failed to fetch location:', error);
        guardianCortex.guardianLocation = { lat: 51.5074, lng: -0.1278, label: 'London, UK' };
    }
}

/**
 * Update location display
 */
function updateLocationDisplay() {
    const label = document.getElementById('cortex-node-label');
    if (label && guardianCortex.guardianLocation) {
        const loc = guardianCortex.guardianLocation;
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
        guardianCortex.globe = Globe()(container)
            .globeImageUrl('https://unpkg.com/three-globe@2.24.10/example/img/earth-night.jpg')
            .bumpImageUrl('https://unpkg.com/three-globe@2.24.10/example/img/earth-topology.png')
            .backgroundImageUrl('https://unpkg.com/three-globe@2.24.10/example/img/night-sky.png')
            .showAtmosphere(true)
            .atmosphereColor('#00bfff')
            .atmosphereAltitude(0.15)
            // Points data
            .pointsData([])
            .pointLat(d => d.lat)
            .pointLng(d => d.lng)
            .pointColor(d => getPointColor(d))
            .pointAltitude(0.01)
            .pointRadius(d => getPointRadius(d))
            .pointLabel(d => getPointLabel(d))
            // HTML elements for clusters
            .htmlElementsData([])
            .htmlElement(d => createClusterElement(d))
            .htmlLat(d => d.lat)
            .htmlLng(d => d.lng)
            .htmlAltitude(0.02)
            // Attack arcs
            .arcsData(guardianCortex.arcs)
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
            // Click handlers
            .onPointClick(handlePointClick);

        // Auto-rotate
        guardianCortex.globe.controls().autoRotate = true;
        guardianCortex.globe.controls().autoRotateSpeed = 0.3;

        // Stop rotation on interaction
        container.addEventListener('mousedown', () => {
            guardianCortex.globe.controls().autoRotate = false;
        });

        // Resize handler
        const resizeObserver = new ResizeObserver(() => {
            if (guardianCortex.globe && container.offsetWidth && container.offsetHeight) {
                guardianCortex.globe.width(container.offsetWidth);
                guardianCortex.globe.height(container.offsetHeight);
            }
        });
        resizeObserver.observe(container);

        // Point to Guardian location
        if (guardianCortex.guardianLocation && guardianCortex.guardianLocation.lat !== 0) {
            setTimeout(() => {
                guardianCortex.globe.pointOfView({
                    lat: guardianCortex.guardianLocation.lat,
                    lng: guardianCortex.guardianLocation.lng,
                    altitude: 2
                }, 1000);
            }, 500);
        }

        // Export globe for shared modules
        window.globe = guardianCortex.globe;

        if (loading) loading.style.display = 'none';
        console.log('Globe initialized');
    } catch (error) {
        console.error('Globe initialization failed:', error);
        show2DFallback();
    }
}

/**
 * Initialize clustering system using shared ClusterManager
 */
function initClusteringSystem() {
    console.log('[Cortex Debug] initClusteringSystem starting', {
        ClusterManagerAvailable: typeof ClusterManager !== 'undefined',
        ZoomControllerAvailable: typeof ZoomController !== 'undefined',
        ZoomIndicatorAvailable: typeof ZoomIndicator !== 'undefined',
        hasGlobe: !!guardianCortex.globe
    });

    // Initialize ClusterManager (from shared/cortex)
    if (typeof ClusterManager !== 'undefined') {
        guardianCortex.clusterManager = new ClusterManager();
        window.clusterManager = guardianCortex.clusterManager;
        console.log('[Cortex Debug] ClusterManager created');

        // Listen for cluster updates
        guardianCortex.clusterManager.on('clustersUpdated', handleClustersUpdated);
        guardianCortex.clusterManager.on('loaded', () => {
            console.log('[Cortex Debug] ClusterManager: Nodes loaded');
            updateDisplayData();
        });
    } else {
        console.warn('[Cortex Debug] ClusterManager not available, clustering disabled');
    }

    // Initialize ZoomController (from shared/cortex)
    if (typeof ZoomController !== 'undefined' && guardianCortex.globe) {
        guardianCortex.zoomController = new ZoomController(
            guardianCortex.globe,
            guardianCortex.clusterManager
        );
        window.zoomController = guardianCortex.zoomController;
        console.log('[Cortex Debug] ZoomController created');

        // Listen for zoom changes
        guardianCortex.zoomController.on('zoomChange', handleZoomChange);
        guardianCortex.zoomController.on('zoomLevelChange', handleZoomLevelChange);
        guardianCortex.zoomController.on('drillDown', handleDrillDown);
        console.log('[Cortex Debug] ZoomController event listeners attached');
    } else {
        console.warn('[Cortex Debug] ZoomController not initialized', {
            ZoomControllerAvailable: typeof ZoomController !== 'undefined',
            hasGlobe: !!guardianCortex.globe
        });
    }

    // Initialize ZoomIndicator UI (from shared/cortex)
    if (typeof ZoomIndicator !== 'undefined' && guardianCortex.zoomController) {
        guardianCortex.zoomIndicator = new ZoomIndicator('zoom-indicator', guardianCortex.zoomController);
        console.log('[Cortex Debug] ZoomIndicator created');
    }

    console.log('[Cortex Debug] Clustering system initialization complete');
}

/**
 * Initialize ViewManager for Globe/Map transitions
 */
function initViewManager() {
    if (typeof ViewManager === 'undefined') {
        console.warn('ViewManager not available, city view disabled');
        return;
    }

    const mapContainer = document.getElementById('map-container');
    const globeContainer = document.getElementById('globe-container');

    guardianCortex.viewManager = new ViewManager();
    window.viewManager = guardianCortex.viewManager;

    // Initialize with Globe.gl
    guardianCortex.viewManager.initWithGlobeGL(guardianCortex.globe, globeContainer);

    // Initialize DeckRenderer for city view
    if (mapContainer && typeof DeckRenderer !== 'undefined') {
        guardianCortex.viewManager.initDeckRenderer(mapContainer, {
            mapStyle: typeof getCortexMapStyle === 'function' ? getCortexMapStyle() : null,
            onNodeClick: handleNodeClick
        });
    }

    // Initialize transition overlay
    const wrapper = document.querySelector('.cortex-globe-wrapper');
    if (wrapper) {
        guardianCortex.viewManager.initTransitionOverlay(wrapper);
    }

    // Connect to ClusterManager
    if (guardianCortex.clusterManager) {
        guardianCortex.viewManager.setClusterManager(guardianCortex.clusterManager);
    }

    // Connect to ZoomController
    if (guardianCortex.zoomController) {
        guardianCortex.viewManager.setZoomController(guardianCortex.zoomController);
    }

    // Listen for mode changes
    guardianCortex.viewManager.on('modeChange', (data) => {
        console.log('View mode changed to:', data.mode);
    });

    console.log('ViewManager initialized with DeckRenderer');
}

/**
 * Get point color
 */
function getPointColor(d) {
    if (d.type === 'cluster') {
        return NODE_COLORS[d.worstStatus] || NODE_COLORS.green;
    }
    return NODE_COLORS[d.status] || NODE_COLORS.green;
}

/**
 * Calculate dynamic scale factor based on altitude
 * At altitude 2.5 (zoomed out) = 1.0, at 0.1 (zoomed in) = 0.2
 */
function getAltitudeScaleFactor() {
    const altitude = guardianCortex.currentAltitude || 2.5;
    // Use square root for smoother scaling, clamp minimum to 0.15
    return Math.max(0.15, Math.sqrt(altitude / 2.5));
}

function getPointRadius(d) {
    const scaleFactor = getAltitudeScaleFactor();

    if (d.type === 'cluster') {
        const count = d.count;
        let baseSize;
        if (count > 50) baseSize = 2.2;
        else if (count > 15) baseSize = 1.6;
        else if (count > 5) baseSize = 1.2;
        else baseSize = 0.8;
        return baseSize * scaleFactor;
    }
    const baseSize = TIER_SIZES[d.tier] || 0.5;
    return baseSize * scaleFactor;
}

/**
 * Get point label
 */
function getPointLabel(d) {
    if (d.type === 'cluster') {
        const tiers = d.tierCounts || {};
        const parts = [];
        if (tiers.nexus) parts.push(`${tiers.nexus} Nexus`);
        if (tiers.fortress) parts.push(`${tiers.fortress} Fortress`);
        if (tiers.guardian) parts.push(`${tiers.guardian} Guardian`);
        if (tiers.sentinel) parts.push(`${tiers.sentinel} Sentinel`);
        return `
            <div class="cluster-tooltip">
                <div class="cluster-count">${d.count} Nodes</div>
                <div class="cluster-tiers">${parts.join(' · ')}</div>
                <div class="cluster-qsecbit">Avg Qsecbit: ${(d.avgQsecbit || 0).toFixed(3)}</div>
                <div class="cluster-status ${d.worstStatus}">Status: ${(d.worstStatus || 'green').toUpperCase()}</div>
                <div class="cluster-hint">Click to zoom in</div>
            </div>
        `;
    }
    return `${d.label || 'Node'}<br/>Qsecbit: ${(d.qsecbit || 0).toFixed(3)}`;
}

/**
 * Create cluster HTML element
 */
function createClusterElement(d) {
    if (d.type !== 'cluster') return null;

    const el = document.createElement('div');
    el.className = `cortex-cluster cortex-cluster-${d.worstStatus || 'green'}`;

    // Base size based on node count
    const count = d.count;
    let baseSize = 35;
    if (count > 50) baseSize = 70;
    else if (count > 15) baseSize = 55;
    else if (count > 5) baseSize = 45;

    // Scale size based on altitude (clusters are HTML elements in pixels)
    // Use a gentler scaling for HTML elements (minimum 0.5)
    const scaleFactor = Math.max(0.5, Math.sqrt(guardianCortex.currentAltitude / 2.5));
    const size = Math.round(baseSize * scaleFactor);

    const color = NODE_COLORS[d.worstStatus] || NODE_COLORS.green;

    el.innerHTML = `
        <div class="cluster-ring cluster-ring-outer" style="border-color: ${color}40"></div>
        <div class="cluster-ring cluster-ring-middle" style="border-color: ${color}60"></div>
        <div class="cluster-ring cluster-ring-inner" style="border-color: ${color}"></div>
        <div class="cluster-core" style="background: ${color}">
            <span class="cluster-badge">${d.count}</span>
        </div>
        <div class="cluster-glow" style="background: ${color}"></div>
    `;

    el.style.width = `${size}px`;
    el.style.height = `${size}px`;

    el.addEventListener('click', (e) => {
        e.stopPropagation();
        handleClusterClick(d);
    });

    return el;
}

/**
 * Handle point click
 */
function handlePointClick(point, event) {
    if (!point) return;

    if (point.type === 'cluster') {
        handleClusterClick(point);
    } else {
        handleNodeClick(point);
    }
}

/**
 * Handle cluster click - drill down
 */
function handleClusterClick(cluster) {
    console.log('Cluster clicked:', cluster.id, `(${cluster.count} nodes)`);

    if (guardianCortex.zoomController) {
        guardianCortex.zoomController.drillDownCluster(cluster);
    } else {
        // Fallback zoom
        guardianCortex.globe.pointOfView({
            lat: cluster.lat,
            lng: cluster.lng,
            altitude: 0.5
        }, 1500);
    }
}

/**
 * Handle node click
 */
function handleNodeClick(node) {
    console.log('Node clicked:', node.id, node.label);

    if (guardianCortex.zoomController) {
        guardianCortex.zoomController.focusNode(node);
    } else {
        guardianCortex.globe.pointOfView({
            lat: node.lat,
            lng: node.lng,
            altitude: 0.4
        }, 1500);
    }
}

/**
 * Handle zoom change
 */
function handleZoomChange(data) {
    console.log('[Cortex Debug] handleZoomChange:', {
        altitude: data.altitude,
        zoom: data.zoom,
        level: data.level,
        hasClusterManager: !!guardianCortex.clusterManager
    });

    // Store altitude for dynamic node sizing
    guardianCortex.currentAltitude = data.altitude;

    if (guardianCortex.clusterManager) {
        const zoom = data.zoom || guardianCortex.clusterManager.altitudeToZoom(data.altitude);
        console.log('[Cortex Debug] Getting clusters for zoom:', zoom, 'scaleFactor:', getAltitudeScaleFactor().toFixed(2));
        guardianCortex.clusterManager.getAllClusters(zoom);
    } else if (guardianCortex.globe) {
        // No clustering - just refresh points to update sizes
        const currentPoints = guardianCortex.globe.pointsData();
        if (currentPoints && currentPoints.length > 0) {
            guardianCortex.globe.pointsData(currentPoints);
        }
    }
}

/**
 * Handle zoom level change
 */
function handleZoomLevelChange(data) {
    console.log(`Zoom level: ${data.from} → ${data.to}`);
}

/**
 * Handle drill down
 */
function handleDrillDown(data) {
    console.log('Drilling down to cluster:', data.cluster.id);
}

/**
 * Handle clusters updated
 */
function handleClustersUpdated(data) {
    console.log('[Cortex Debug] handleClustersUpdated:', {
        clustersCount: data.clusters ? data.clusters.length : 0,
        zoom: data.zoom,
        totalClusters: data.totalClusters,
        totalNodes: data.totalNodes
    });
    updateGlobeData(data.clusters);
}

/**
 * Update display data based on zoom
 */
function updateDisplayData() {
    if (!guardianCortex.clusterManager) {
        // No clustering - show all nodes
        if (guardianCortex.globe) {
            guardianCortex.globe.pointsData(guardianCortex.nodes.map(n => ({ ...n, type: 'node' })));
        }
        return;
    }

    const pov = guardianCortex.globe ? guardianCortex.globe.pointOfView() : { altitude: 2.5 };
    const zoom = guardianCortex.clusterManager.altitudeToZoom(pov.altitude);
    const displayData = guardianCortex.clusterManager.getAllClusters(zoom);
    updateGlobeData(displayData);
}

/**
 * Update globe with display data
 */
function updateGlobeData(displayData) {
    if (!guardianCortex.globe || !displayData) {
        console.log('[Cortex Debug] updateGlobeData: skipped (globe or data missing)', {
            hasGlobe: !!guardianCortex.globe,
            hasDisplayData: !!displayData
        });
        return;
    }

    const clusters = displayData.filter(d => d.type === 'cluster');
    const nodes = displayData.filter(d => d.type === 'node');
    console.log('[Cortex Debug] updateGlobeData:', {
        totalItems: displayData.length,
        clusters: clusters.length,
        nodes: nodes.length
    });

    guardianCortex.globe.pointsData(nodes);
    guardianCortex.globe.htmlElementsData(clusters);

    // Sync to ViewManager for city view
    if (guardianCortex.viewManager) {
        guardianCortex.viewManager.updateNodes(nodes);
        guardianCortex.viewManager.updateClusters(clusters);
    }
}

/**
 * Show 2D fallback
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
 * Initialize 2D canvas map (fallback)
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
    ctx.fillStyle = '#0a0a0f';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Grid
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

    // Nodes
    guardianCortex.nodes.forEach(node => {
        const x = ((node.lng + 180) / 360) * canvas.width;
        const y = ((90 - node.lat) / 180) * canvas.height;
        const color = NODE_COLORS[node.status] || NODE_COLORS.green;
        const radius = (TIER_SIZES[node.tier] || 0.5) * 8;

        ctx.beginPath();
        ctx.arc(x, y, radius + 3, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.3;
        ctx.fill();
        ctx.globalAlpha = 1;

        ctx.beginPath();
        ctx.arc(x, y, radius, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
    });
}

/**
 * Setup UI controls
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
        guardianCortex.demoMode = demoMode;
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
    guardianCortex.nodes = data.nodes || [];

    // Load into cluster manager
    if (guardianCortex.clusterManager) {
        guardianCortex.clusterManager.load(guardianCortex.nodes);
    } else {
        if (guardianCortex.globe) {
            guardianCortex.globe.pointsData(guardianCortex.nodes.map(n => ({ ...n, type: 'node' })));
        }
    }

    // Process events
    if (data.events && data.events.length > 0) {
        data.events.forEach(event => {
            addArc(event);
            addEventToLog(event);
        });
    }

    // Update stats
    updateStats(data);
}

/**
 * Add arc
 */
function addArc(event) {
    const arc = {
        id: event.id || Date.now(),
        type: event.type === 'attack_repelled' ? 'repelled' : 'attack',
        source: event.source,
        target: event.target,
        timestamp: Date.now()
    };

    guardianCortex.arcs.push(arc);

    setTimeout(() => {
        guardianCortex.arcs = guardianCortex.arcs.filter(a => a.id !== arc.id);
        if (guardianCortex.globe) guardianCortex.globe.arcsData(guardianCortex.arcs);
        if (guardianCortex.viewManager) guardianCortex.viewManager.updateArcs(guardianCortex.arcs);
    }, 3000);

    if (guardianCortex.globe) guardianCortex.globe.arcsData(guardianCortex.arcs);
    if (guardianCortex.viewManager) guardianCortex.viewManager.updateArcs(guardianCortex.arcs);

    if (arc.type === 'attack') {
        guardianCortex.stats.attacks++;
    } else {
        guardianCortex.stats.repelled++;
    }
}

/**
 * Update stats display
 */
function updateStats(data) {
    const stats = data.stats || {};
    const byTier = stats.by_tier || {};

    document.getElementById('stat-nodes').textContent = stats.total_nodes || guardianCortex.nodes.length;
    document.getElementById('stat-attacks').textContent = guardianCortex.stats.attacks;
    document.getElementById('stat-repelled').textContent = guardianCortex.stats.repelled;

    if (guardianCortex.nodes.length > 0) {
        const totalQsecbit = guardianCortex.nodes.reduce((sum, n) => sum + (n.qsecbit || 0), 0);
        const avg = totalQsecbit / guardianCortex.nodes.length;
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
    guardianCortex.stats.attacks = 0;
    guardianCortex.stats.repelled = 0;
    document.getElementById('stat-attacks').textContent = '0';
    document.getElementById('stat-repelled').textContent = '0';
}

/**
 * Fly to location (exposed for external use)
 */
function flyToLocation(lat, lng, zoom) {
    if (guardianCortex.zoomController) {
        guardianCortex.zoomController.animateTo({
            lat,
            lng,
            altitude: guardianCortex.clusterManager ? guardianCortex.clusterManager.zoomToAltitude(zoom || 10) : 0.5
        });
    } else if (guardianCortex.globe) {
        guardianCortex.globe.pointOfView({ lat, lng, altitude: zoom ? Math.max(0.5, 10 - zoom) : 1 }, 1500);
    }
}

// Export for external use
window.initCortexGlobe = initCortexGlobe;
window.refreshCortexData = refreshData;
window.flyToLocation = flyToLocation;
window.guardianCortex = guardianCortex;
