/**
 * HookProbe Globe Visualization
 *
 * Main globe initialization and rendering using Globe.gl
 */

// Globe instance
let globe = null;

// Data state
const state = {
    nodes: [],
    arcs: [],
    stats: {
        attacks: 0,
        repelled: 0,
        avgQsecbit: 0
    }
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

// Tier sizes
const TIER_SIZES = {
    sentinel: 0.3,
    guardian: 0.5,
    fortress: 0.8,
    nexus: 1.2
};

/**
 * Initialize the globe
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
        // Node points
        .pointsData(state.nodes)
        .pointLat(d => d.lat)
        .pointLng(d => d.lng)
        .pointColor(d => NODE_COLORS[d.status] || NODE_COLORS.green)
        .pointAltitude(0.01)
        .pointRadius(d => TIER_SIZES[d.tier] || 0.5)
        .pointLabel(d => `${d.label}<br/>Qsecbit: ${d.qsecbit?.toFixed(3) || 'N/A'}`)
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
        .arcsTransitionDuration(300);

    // Auto-rotate
    globe.controls().autoRotate = true;
    globe.controls().autoRotateSpeed = 0.3;

    // Stop rotation on interaction
    container.addEventListener('mousedown', () => {
        globe.controls().autoRotate = false;
    });

    // Resize handler
    window.addEventListener('resize', () => {
        globe.width(container.clientWidth);
        globe.height(container.clientHeight);
    });

    console.log('Globe initialized');
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
    init2DFallback();
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

        case 'qsecbit_update':
            updateNodeQsecbit(event);
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
    if (globe) globe.pointsData(state.nodes);
    document.getElementById('stat-nodes').textContent = nodes.length;

    // Calculate average Qsecbit
    const totalQsecbit = nodes.reduce((sum, n) => sum + (n.qsecbit || 0), 0);
    state.stats.avgQsecbit = nodes.length ? totalQsecbit / nodes.length : 0;
    updateStats();
}

/**
 * Update single node Qsecbit
 */
function updateNodeQsecbit(event) {
    const node = state.nodes.find(n => n.id === event.node_id);
    if (node) {
        node.qsecbit = event.score;
        node.status = event.status;
        if (globe) globe.pointsData(state.nodes);
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
}

/**
 * Add event to log
 */
function addEventLog(event, type) {
    const list = document.getElementById('event-list');
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

    // Keep only last 20 events
    while (list.children.length > 20) {
        list.removeChild(list.lastChild);
    }
}

/**
 * Initialize on DOM ready
 */
document.addEventListener('DOMContentLoaded', () => {
    initGlobe();
    initDataStream(handleEvent);
});
