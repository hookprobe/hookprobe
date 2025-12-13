/**
 * HookProbe Cortex - Globe Visualization
 *
 * Main globe initialization and rendering using Globe.gl with
 * smart clustering, zoom-responsive rendering, and smooth transitions.
 *
 * Features:
 * - Dynamic node clustering based on zoom level
 * - Smooth zoom transitions with camera animations
 * - Click-to-drill-down on clusters
 * - Zoom level indicator and breadcrumb navigation
 * - Phase 2 integration: Deck.gl + MapLibre GL for city view
 */

// Globe instance
let globe = null;

// Clustering and zoom managers
let clusterManager = null;
let zoomController = null;
let transitionManager = null;
let clusterVisuals = null;
let zoomIndicator = null;

// Country/region data
let countriesData = null;

// Globe texture configuration - Higher resolution options
const GLOBE_TEXTURES = {
    // Dark theme (better for cybersecurity aesthetic)
    dark: {
        globe: 'https://unpkg.com/three-globe@2.31.0/example/img/earth-night.jpg',
        bump: 'https://unpkg.com/three-globe@2.31.0/example/img/earth-topology.png',
        background: 'https://unpkg.com/three-globe@2.31.0/example/img/night-sky.png'
    },
    // Blue marble (higher detail, better zoom quality)
    blueMarble: {
        globe: 'https://unpkg.com/three-globe@2.31.0/example/img/earth-blue-marble.jpg',
        bump: 'https://unpkg.com/three-globe@2.31.0/example/img/earth-topology.png',
        background: 'https://unpkg.com/three-globe@2.31.0/example/img/night-sky.png'
    },
    // Dark with borders (custom dark texture)
    darkPolitical: {
        globe: 'https://unpkg.com/three-globe@2.31.0/example/img/earth-dark.jpg',
        bump: 'https://unpkg.com/three-globe@2.31.0/example/img/earth-topology.png',
        background: 'https://unpkg.com/three-globe@2.31.0/example/img/night-sky.png'
    }
};

// Country boundaries data source (TopoJSON)
const COUNTRIES_DATA_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

// Data state
const state = {
    nodes: [],
    arcs: [],
    displayData: [], // Clusters + individual nodes for current zoom
    countries: [],   // Country polygons for boundaries
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
    },
    currentZoomLevel: 'GLOBAL',
    clusteringEnabled: true,
    showCountryBorders: true
};

// Arc colors - Premium color schemes
const ARC_COLORS = {
    // Watermelon: Green rind → Red/pink flesh (threat coming in)
    attack: ['rgba(76, 187, 23, 0.9)', 'rgba(255, 71, 87, 0.9)'],
    // Pacific Blue: Deep ocean calming blue (defense)
    repelled: ['rgba(0, 180, 216, 0.9)', 'rgba(144, 224, 239, 0.8)'],
    // Heartbeat: Cyan mesh connectivity pulses
    heartbeat: ['rgba(0, 255, 255, 0.6)', 'rgba(0, 255, 255, 0.2)']
};

// Node colors based on Qsecbit status
const NODE_COLORS = {
    green: '#00ff88',
    amber: '#ffaa00',
    red: '#ff4444'
};

// Tier sizes for individual nodes
const TIER_SIZES = {
    sentinel: 0.3,
    guardian: 0.5,
    fortress: 0.8,
    nexus: 1.2
};

// Cluster sizes based on node count
const CLUSTER_SIZES = {
    small: 0.8,    // 2-5 nodes
    medium: 1.2,   // 6-15 nodes
    large: 1.6,    // 16-50 nodes
    huge: 2.2      // 50+ nodes
};

// Tier base colors (used when node is healthy)
const TIER_COLORS = {
    sentinel: '#888888',
    guardian: '#00bfff',
    fortress: '#00ff88',
    nexus: '#ffaa00'
};

/**
 * Get arc color based on type
 * @param {string} type - 'attack', 'repelled', or 'heartbeat'
 * @returns {Array} Color gradient array [start, end]
 */
function getArcColor(type) {
    switch (type) {
        case 'attack':
            return ARC_COLORS.attack;
        case 'repelled':
            return ARC_COLORS.repelled;
        case 'heartbeat':
            return ARC_COLORS.heartbeat;
        default:
            return ARC_COLORS.repelled;
    }
}

/**
 * Detect if device is touch-enabled
 */
function isTouchDevice() {
    return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
}

/**
 * Initialize the globe with clustering support
 */
function initGlobe() {
    const container = document.getElementById('globe-container');

    // Check WebGL support
    if (!isWebGLSupported()) {
        console.warn('WebGL not supported, falling back to 2D');
        showFallback();
        return;
    }

    console.log('Initializing Globe.gl...', {
        isTouchDevice: isTouchDevice(),
        containerSize: { width: container.clientWidth, height: container.clientHeight }
    });

    // Select texture theme (dark is better for cybersecurity)
    const textures = GLOBE_TEXTURES.dark;

    // Create globe instance with improved textures
    globe = Globe()(container)
        .globeImageUrl(textures.globe)
        .bumpImageUrl(textures.bump)
        .backgroundImageUrl(textures.background)
        .showAtmosphere(true)
        .atmosphereColor('#00bfff')
        .atmosphereAltitude(0.15)
        // Country polygons for boundaries (loaded async)
        .polygonsData([])
        .polygonCapColor(() => 'rgba(0, 0, 0, 0)') // Transparent fill
        .polygonSideColor(() => 'rgba(0, 191, 255, 0.05)') // Subtle side
        .polygonStrokeColor(() => 'rgba(0, 191, 255, 0.4)') // Cyan borders
        .polygonAltitude(0.001) // Slightly above surface
        .polygonLabel(d => `<div class="country-tooltip">${d.properties?.name || ''}</div>`)
        // Points (clusters + individual nodes)
        .pointsData([])
        .pointLat(d => d.lat)
        .pointLng(d => d.lng)
        .pointColor(d => getPointColor(d))
        .pointAltitude(0.01)
        .pointRadius(d => getPointRadius(d))
        .pointLabel(d => getPointLabel(d))
        // Custom HTML elements for clusters
        .htmlElementsData([])
        .htmlElement(d => createClusterElement(d))
        .htmlLat(d => d.lat)
        .htmlLng(d => d.lng)
        .htmlAltitude(0.02)
        // Attack arcs
        .arcsData(state.arcs)
        .arcStartLat(d => d.source.lat)
        .arcStartLng(d => d.source.lng)
        .arcEndLat(d => d.target.lat)
        .arcEndLng(d => d.target.lng)
        .arcColor(d => getArcColor(d.type))
        .arcDashLength(d => d.type === 'heartbeat' ? 0.2 : 0.4)
        .arcDashGap(d => d.type === 'heartbeat' ? 0.15 : 0.1)
        .arcDashAnimateTime(d => d.type === 'heartbeat' ? 800 : 1500)
        .arcStroke(d => d.type === 'attack' ? 0.6 : d.type === 'heartbeat' ? 0.3 : 0.4)
        .arcsTransitionDuration(300)
        // Click handlers
        .onPointClick(handlePointClick)
        .onGlobeClick(handleGlobeClick);

    // Load country boundaries for better zoom detail
    loadCountryBoundaries();

    // Configure camera controls for better zoom range
    const controls = globe.controls();

    // Enable auto-rotate
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.3;

    // Configure zoom limits - allow much deeper zoom for city view transition
    // minDistance: how close you can zoom in (lower = closer)
    // maxDistance: how far you can zoom out
    controls.minDistance = 101;  // Very close zoom (altitude ~0.01)
    controls.maxDistance = 500;  // Far zoom out

    // Enable damping for smoother control
    controls.enableDamping = true;
    controls.dampingFactor = 0.1;

    // Improve touch controls
    if (isTouchDevice()) {
        controls.rotateSpeed = 0.4;     // Slower rotation for touch
        controls.zoomSpeed = 0.8;       // Slightly slower zoom for touch precision
        controls.panSpeed = 0.5;        // Pan speed
        controls.enablePan = false;     // Disable pan on touch (can be confusing)
    }

    // Stop rotation on any interaction
    container.addEventListener('mousedown', () => {
        controls.autoRotate = false;
    });

    // Touch events - stop rotation
    container.addEventListener('touchstart', () => {
        controls.autoRotate = false;
    }, { passive: true });

    // Initialize clustering system
    initClusteringSystem();

    // Resize handler
    window.addEventListener('resize', handleResize);

    // Export globe instance for external access
    window.globe = globe;
    window.state = state;

    console.log('Cortex Globe initialized with clustering support');
}

/**
 * Initialize the clustering system
 */
function initClusteringSystem() {
    // Initialize ClusterManager (requires Supercluster)
    if (typeof ClusterManager !== 'undefined') {
        clusterManager = new ClusterManager();
        clusterVisuals = new ClusterVisuals();

        // Listen for cluster updates
        clusterManager.on('clustersUpdated', handleClustersUpdated);
        clusterManager.on('loaded', () => {
            console.log('ClusterManager: Nodes loaded');
            updateDisplayData();
        });
    } else {
        console.warn('ClusterManager not available, clustering disabled');
        state.clusteringEnabled = false;
    }

    // Initialize ZoomController
    if (typeof ZoomController !== 'undefined' && globe) {
        zoomController = new ZoomController(globe, clusterManager);
        window.zoomController = zoomController;

        // Listen for zoom changes
        zoomController.on('zoomChange', handleZoomChange);
        zoomController.on('zoomLevelChange', handleZoomLevelChange);
        zoomController.on('drillDown', handleDrillDown);
    }

    // Initialize TransitionManager
    if (typeof TransitionManager !== 'undefined' && globe) {
        transitionManager = new TransitionManager(globe, clusterManager);

        transitionManager.on('transitionStart', () => {
            // Pause auto-rotate during transitions
            if (globe.controls()) {
                globe.controls().autoRotate = false;
            }
        });
    }

    // Initialize ZoomIndicator UI
    if (typeof ZoomIndicator !== 'undefined' && zoomController) {
        zoomIndicator = new ZoomIndicator('zoom-indicator', zoomController);
    }

    console.log('Clustering system initialized');
}

/**
 * Load country boundary polygons for zoom detail
 * Uses TopoJSON world atlas data for country outlines
 */
async function loadCountryBoundaries() {
    if (!state.showCountryBorders) return;

    try {
        console.log('Loading country boundaries...');
        const response = await fetch(COUNTRIES_DATA_URL);
        const topoData = await response.json();

        // Convert TopoJSON to GeoJSON features
        if (topoData.objects && topoData.objects.countries) {
            // Need topojson library for conversion
            if (typeof topojson !== 'undefined') {
                const countries = topojson.feature(topoData, topoData.objects.countries);
                countriesData = countries.features;
                state.countries = countriesData;

                // Apply to globe
                if (globe) {
                    globe.polygonsData(countriesData);
                    console.log(`Loaded ${countriesData.length} country boundaries`);
                }
            } else {
                // Fallback: try loading pre-converted GeoJSON
                const geoResponse = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
                const geoData = await geoResponse.json();

                // If it's already GeoJSON features
                if (geoData.features) {
                    countriesData = geoData.features;
                    state.countries = countriesData;
                    if (globe) {
                        globe.polygonsData(countriesData);
                        console.log(`Loaded ${countriesData.length} country boundaries (GeoJSON)`);
                    }
                }
            }
        }
    } catch (error) {
        console.warn('Could not load country boundaries:', error.message);
        // Globe still works without boundaries
    }
}

/**
 * Toggle country borders visibility
 * @param {boolean} show - Whether to show country borders
 */
function toggleCountryBorders(show) {
    state.showCountryBorders = show;

    if (globe) {
        if (show && countriesData) {
            globe.polygonsData(countriesData);
        } else {
            globe.polygonsData([]);
        }
    }
}

/**
 * Update country border visibility based on zoom level
 * Makes borders more visible when zoomed in
 * @param {number} altitude - Current camera altitude
 */
function updateCountryBorderOpacity(altitude) {
    if (!globe || !state.showCountryBorders) return;

    // Calculate opacity based on altitude (more visible when zoomed in)
    // altitude: 2.5 = far out, 0.1 = very close
    const opacity = Math.min(0.8, Math.max(0.2, 1 - (altitude / 3)));

    globe
        .polygonStrokeColor(() => `rgba(0, 191, 255, ${opacity})`)
        .polygonSideColor(() => `rgba(0, 191, 255, ${opacity * 0.1})`);
}

// Export border functions
window.toggleCountryBorders = toggleCountryBorders;

/**
 * Get point color based on type (cluster or node)
 */
function getPointColor(d) {
    if (d.type === 'cluster') {
        return NODE_COLORS[d.worstStatus] || NODE_COLORS.green;
    }
    return NODE_COLORS[d.status] || NODE_COLORS.green;
}

/**
 * Get point radius based on type
 */
function getPointRadius(d) {
    if (d.type === 'cluster') {
        const count = d.count;
        if (count > 50) return CLUSTER_SIZES.huge;
        if (count > 15) return CLUSTER_SIZES.large;
        if (count > 5) return CLUSTER_SIZES.medium;
        return CLUSTER_SIZES.small;
    }
    return TIER_SIZES[d.tier] || 0.5;
}

/**
 * Get point label/tooltip
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
 * Create custom HTML element for cluster visualization
 */
function createClusterElement(d) {
    if (d.type !== 'cluster') return null;

    const el = document.createElement('div');
    el.className = `cortex-cluster cortex-cluster-${d.worstStatus || 'green'}`;

    const size = getClusterDisplaySize(d.count);
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

    // Click handler
    el.addEventListener('click', (e) => {
        e.stopPropagation();
        handleClusterClick(d);
    });

    return el;
}

/**
 * Get cluster display size in pixels
 */
function getClusterDisplaySize(count) {
    if (count > 50) return 70;
    if (count > 15) return 55;
    if (count > 5) return 45;
    return 35;
}

/**
 * Handle point click (node or cluster)
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

    if (zoomController) {
        zoomController.drillDownCluster(cluster);
    } else {
        // Fallback: simple zoom to cluster location
        const expansionZoom = clusterManager
            ? clusterManager.getClusterExpansionZoom(cluster.clusterId)
            : 8;
        const altitude = clusterManager
            ? clusterManager.zoomToAltitude(expansionZoom)
            : 0.5;

        globe.pointOfView({
            lat: cluster.lat,
            lng: cluster.lng,
            altitude: altitude
        }, 1500);
    }
}

/**
 * Handle node click
 */
function handleNodeClick(node) {
    console.log('Node clicked:', node.id, node.label);

    if (zoomController) {
        zoomController.focusNode(node);
    } else {
        globe.pointOfView({
            lat: node.lat,
            lng: node.lng,
            altitude: 0.4
        }, 1500);
    }

    // Emit node selection event
    if (typeof onNodeSelected === 'function') {
        onNodeSelected(node);
    }
}

/**
 * Handle globe click (empty area)
 */
function handleGlobeClick(coords) {
    console.log('Globe clicked at:', coords.lat.toFixed(2), coords.lng.toFixed(2));
}

/**
 * Handle zoom change events
 */
function handleZoomChange(data) {
    // Update clustering based on new zoom level
    if (state.clusteringEnabled && clusterManager) {
        const zoom = data.zoom || clusterManager.altitudeToZoom(data.altitude);
        clusterManager.getAllClusters(zoom);
    }

    // Update country border visibility based on zoom
    if (data.altitude !== undefined) {
        updateCountryBorderOpacity(data.altitude);
    }
}

/**
 * Handle zoom level category change
 */
function handleZoomLevelChange(data) {
    console.log(`Zoom level: ${data.from} → ${data.to}`);
    state.currentZoomLevel = data.to;

    // Update UI indicator
    updateZoomLevelIndicator(data.to);

    // Emit event for external listeners
    if (typeof onZoomLevelChange === 'function') {
        onZoomLevelChange(data);
    }
}

/**
 * Handle drill down event
 */
function handleDrillDown(data) {
    console.log('Drilling down to cluster:', data.cluster.id);

    // Animate cluster expansion if transition manager available
    if (transitionManager && data.cluster.leaves) {
        const nodes = data.cluster.leaves.map(leaf => ({
            lat: leaf.geometry.coordinates[1],
            lng: leaf.geometry.coordinates[0],
            ...leaf.properties
        }));
        transitionManager.expandCluster(data.cluster, nodes);
    }
}

/**
 * Handle clusters updated event
 */
function handleClustersUpdated(data) {
    state.displayData = data.clusters;
    updateGlobeData();
}

/**
 * Update globe with current display data
 */
function updateGlobeData() {
    if (!globe) return;

    const clusters = state.displayData.filter(d => d.type === 'cluster');
    const nodes = state.displayData.filter(d => d.type === 'node');

    // Update point data (individual nodes only at high zoom)
    globe.pointsData(nodes);

    // Update HTML elements (clusters)
    globe.htmlElementsData(clusters);
}

/**
 * Update display data based on current zoom
 */
function updateDisplayData() {
    if (!clusterManager || !state.clusteringEnabled) {
        // No clustering - show all nodes
        state.displayData = state.nodes.map(n => ({ ...n, type: 'node' }));
        updateGlobeData();
        return;
    }

    const pov = globe ? globe.pointOfView() : { altitude: 2.5 };
    const zoom = clusterManager.altitudeToZoom(pov.altitude);
    state.displayData = clusterManager.getAllClusters(zoom);
    updateGlobeData();
}

/**
 * Update zoom level indicator UI
 */
function updateZoomLevelIndicator(level) {
    const indicator = document.getElementById('zoom-level-text');
    if (indicator) {
        indicator.textContent = ZOOM_LEVELS[level]?.label || level;
    }
}

/**
 * Handle window resize
 */
function handleResize() {
    const container = document.getElementById('globe-container');
    if (globe && container) {
        globe.width(container.clientWidth);
        globe.height(container.clientHeight);
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
 * Show 2D fallback
 */
function showFallback() {
    document.getElementById('globe-container').style.display = 'none';
    document.getElementById('map-fallback').style.display = 'flex';
    if (typeof init2DFallback === 'function') {
        init2DFallback();
    }
}

/**
 * Handle incoming WebSocket events
 */
function handleEvent(event) {
    switch (event.type) {
        case 'attack_detected':
            addAttackArc(event, 'attack');
            state.stats.attacks++;
            updateStats();
            addEventLog(event, 'attack');
            break;

        case 'attack_repelled':
            addAttackArc(event, 'repelled');
            state.stats.repelled++;
            updateStats();
            addEventLog(event, 'repelled');
            break;

        case 'node_status':
            updateNodes(event.nodes);
            break;

        case 'snapshot':
            handleSnapshot(event);
            break;

        case 'qsecbit_update':
            updateNodeQsecbit(event);
            break;

        case 'mode_changed':
            console.log(`Globe: Mode changed to ${event.mode}`);
            break;

        default:
            console.log('Unknown event:', event.type);
    }
}

/**
 * Add attack/repelled arc with visual correlation to target node
 */
function addAttackArc(event, type) {
    // Ensure target coordinates match an actual node in the mesh
    const targetNode = state.nodes.find(n =>
        n.id === event.target?.node_id ||
        (Math.abs(n.lat - event.target?.lat) < 0.01 && Math.abs(n.lng - event.target?.lng) < 0.01)
    );

    // Use exact node coordinates if found for precise arc targeting
    const target = targetNode ? {
        lat: targetNode.lat,
        lng: targetNode.lng,
        label: targetNode.label || event.target?.label,
        node_id: targetNode.id
    } : event.target;

    const arc = {
        id: event.id || Date.now(),
        type: type,
        source: event.source,
        target: target,
        timestamp: Date.now()
    };

    state.arcs.push(arc);

    // Trigger visual effect on target node with matching colors
    if (targetNode && typeof pulseNode === 'function') {
        // Watermelon red for attacks, Pacific blue for defense
        const color = type === 'attack' ? '#ff4757' : '#00b4d8';
        pulseNode(target.lat, target.lng, color, 2, 1500);
    }

    // Arc duration matches animation time (1.5s) plus lingering (1.5s)
    const arcDuration = 3000;
    setTimeout(() => {
        state.arcs = state.arcs.filter(a => a.id !== arc.id);
        if (globe) globe.arcsData(state.arcs);
    }, arcDuration);

    if (globe) globe.arcsData(state.arcs);

    // Log for debugging correlation
    if (targetNode) {
        console.log(`Arc ${type}: ${event.source?.label} → ${targetNode.label} (${targetNode.tier})`);
    }
}

/**
 * Update node points
 */
function updateNodes(nodes) {
    state.nodes = nodes;

    // Load nodes into cluster manager
    if (clusterManager && state.clusteringEnabled) {
        clusterManager.load(nodes);
    } else {
        state.displayData = nodes.map(n => ({ ...n, type: 'node' }));
        if (globe) globe.pointsData(state.displayData);
    }

    document.getElementById('stat-nodes').textContent = nodes.length;

    // Count nodes by tier
    state.stats.byTier = { sentinel: 0, guardian: 0, fortress: 0, nexus: 0 };
    nodes.forEach(n => {
        const tier = (n.tier || 'sentinel').toLowerCase();
        if (state.stats.byTier.hasOwnProperty(tier)) {
            state.stats.byTier[tier]++;
        }
    });

    // Calculate average Qsecbit
    const totalQsecbit = nodes.reduce((sum, n) => sum + (n.qsecbit || 0), 0);
    state.stats.avgQsecbit = nodes.length ? totalQsecbit / nodes.length : 0;
    updateStats();

    // Phase 2: Sync to ViewManager for city view
    if (window.viewManager) {
        syncToViewManager();
    }
}

/**
 * Handle snapshot event (initial state from server)
 */
function handleSnapshot(event) {
    if (event.nodes) {
        updateNodes(event.nodes);
    }

    if (event.stats && event.stats.by_tier) {
        state.stats.byTier = {
            sentinel: event.stats.by_tier.sentinel || 0,
            guardian: event.stats.by_tier.guardian || 0,
            fortress: event.stats.by_tier.fortress || 0,
            nexus: event.stats.by_tier.nexus || 0
        };
        updateStats();
    }

    console.log('Snapshot received:', event.stats?.total_nodes || 0, 'nodes');
}

/**
 * Update single node Qsecbit
 */
function updateNodeQsecbit(event) {
    const node = state.nodes.find(n => n.id === event.node_id);
    if (node) {
        node.qsecbit = event.score;
        node.status = event.status;

        // Re-cluster if enabled
        if (clusterManager && state.clusteringEnabled) {
            clusterManager.load(state.nodes);
        } else if (globe) {
            globe.pointsData(state.nodes);
        }
    }
}

/**
 * Update stats display
 */
function updateStats() {
    document.getElementById('stat-attacks').textContent = state.stats.attacks;
    document.getElementById('stat-repelled').textContent = state.stats.repelled;
    document.getElementById('stat-qsecbit').textContent =
        state.stats.avgQsecbit > 0 ? state.stats.avgQsecbit.toFixed(3) : '--';

    const tierElements = {
        'stat-sentinels': state.stats.byTier.sentinel,
        'stat-guardians': state.stats.byTier.guardian,
        'stat-fortresses': state.stats.byTier.fortress,
        'stat-nexuses': state.stats.byTier.nexus
    };

    for (const [id, count] of Object.entries(tierElements)) {
        const el = document.getElementById(id);
        if (el) el.textContent = count;
    }
}

/**
 * Add event to log
 */
function addEventLog(event, type) {
    const list = document.getElementById('event-list');
    if (!list) return;

    const li = document.createElement('li');
    const time = new Date().toLocaleTimeString();
    const icon = type === 'attack' ? 'attack' : 'repelled';
    const label = event.source?.label || 'Unknown';
    const target = event.target?.label || 'Unknown';

    li.innerHTML = `
        <span class="event-icon ${icon}"></span>
        <span class="event-time">${time}</span>
        <span>${label} → ${target}</span>
    `;

    list.insertBefore(li, list.firstChild);

    while (list.children.length > 20) {
        list.removeChild(list.lastChild);
    }
}

/**
 * Toggle clustering on/off
 */
function toggleClustering(enabled) {
    state.clusteringEnabled = enabled;

    if (enabled && clusterManager) {
        clusterManager.load(state.nodes);
    } else {
        state.displayData = state.nodes.map(n => ({ ...n, type: 'node' }));
        if (globe) {
            globe.pointsData(state.displayData);
            globe.htmlElementsData([]);
        }
    }

    console.log('Clustering:', enabled ? 'enabled' : 'disabled');
}

/**
 * Get current clustering state
 */
function getClusteringStats() {
    if (!clusterManager) {
        return { enabled: false };
    }
    return {
        enabled: state.clusteringEnabled,
        ...clusterManager.getStats()
    };
}

// Export functions for external use
window.toggleClustering = toggleClustering;
window.getClusteringStats = getClusteringStats;

// Phase 2: Export clustering instances for ViewManager integration
window.clusterManager = clusterManager;

/**
 * Phase 2: Sync current nodes to ViewManager for city view
 */
function syncToViewManager() {
    if (!window.viewManager) return;

    // Sync nodes
    window.viewManager.updateNodes(state.nodes);

    // Sync clusters at current zoom
    if (clusterManager && state.clusteringEnabled) {
        const pov = globe ? globe.pointOfView() : { altitude: 2.5 };
        const zoom = clusterManager.altitudeToZoom(pov.altitude);
        const clusters = clusterManager.getAllClusters(zoom)
            .filter(c => c.type === 'cluster');
        window.viewManager.updateClusters(clusters);
    }

    // Sync arcs
    window.viewManager.updateArcs(state.arcs);
}

/**
 * Phase 2: Check if we should transition to city view
 */
function checkCityViewTransition(altitude) {
    if (!window.viewManager) return;

    // ViewManager handles the actual transition logic
    // This just triggers a check on deep zoom
    if (altitude < 0.3 && window.viewManager.isGlobeMode()) {
        const pov = globe.pointOfView();
        console.log('Globe: Deep zoom detected, ViewManager will handle transition');
    }
}

// Export Phase 2 functions
window.syncToViewManager = syncToViewManager;

/**
 * Initialize on DOM ready
 */
document.addEventListener('DOMContentLoaded', () => {
    initGlobe();
    if (typeof initDataStream === 'function') {
        initDataStream(handleEvent);
    }
});
