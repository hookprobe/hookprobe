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

// Data state
const state = {
    nodes: [],
    arcs: [],
    displayData: [], // Clusters + individual nodes for current zoom
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
    clusteringEnabled: true
};

// Arc colors
const ARC_COLORS = {
    attack: ['rgba(255, 68, 68, 0.8)', 'rgba(255, 68, 68, 0.2)'],
    repelled: ['rgba(0, 191, 255, 0.8)', 'rgba(0, 191, 255, 0.2)']
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

    // Create globe instance
    globe = Globe()(container)
        .globeImageUrl('https://unpkg.com/three-globe@2.24.10/example/img/earth-night.jpg')
        .bumpImageUrl('https://unpkg.com/three-globe@2.24.10/example/img/earth-topology.png')
        .backgroundImageUrl('https://unpkg.com/three-globe@2.24.10/example/img/night-sky.png')
        .showAtmosphere(true)
        .atmosphereColor('#00bfff')
        .atmosphereAltitude(0.15)
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
        .arcColor(d => d.type === 'attack' ? ARC_COLORS.attack : ARC_COLORS.repelled)
        .arcDashLength(0.5)
        .arcDashGap(0.1)
        .arcDashAnimateTime(1500)
        .arcStroke(d => d.type === 'attack' ? 0.5 : 0.3)
        .arcsTransitionDuration(300)
        // Click handlers
        .onPointClick(handlePointClick)
        .onGlobeClick(handleGlobeClick);

    // Auto-rotate
    globe.controls().autoRotate = true;
    globe.controls().autoRotateSpeed = 0.3;

    // Stop rotation on interaction
    container.addEventListener('mousedown', () => {
        globe.controls().autoRotate = false;
    });

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
 * Add attack/repelled arc
 */
function addAttackArc(event, type) {
    const arc = {
        id: event.id || Date.now(),
        type: type,
        source: event.source,
        target: event.target,
        timestamp: Date.now()
    };

    state.arcs.push(arc);

    // Remove arc after animation
    setTimeout(() => {
        state.arcs = state.arcs.filter(a => a.id !== arc.id);
        if (globe) globe.arcsData(state.arcs);
    }, 3000);

    if (globe) globe.arcsData(state.arcs);
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
