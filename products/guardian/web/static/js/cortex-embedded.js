/**
 * HookProbe Cortex Embedded Globe
 *
 * Embedded globe visualization for Guardian web UI.
 * Uses Globe.gl for 3D rendering with canvas 2D fallback.
 */

// Globe instance
let globe = null;
let isInitialized = false;

// Data state
const cortexState = {
    nodes: [],
    arcs: [],
    demoMode: true,
    guardianLocation: null,
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
    green: '#00ff88',
    amber: '#ffaa00',
    red: '#ff4444'
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

    console.log('Initializing Cortex Globe...');

    // First fetch location
    fetchGuardianLocation().then(() => {
        // Check WebGL support
        if (!isWebGLSupported()) {
            console.warn('WebGL not supported, using 2D fallback');
            show2DFallback();
        } else {
            initGlobeGL();
        }

        // Set up controls
        setupControls();

        // Initial data load
        refreshData();

        // Start polling for updates
        setInterval(refreshData, 10000); // Every 10 seconds

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
        cortexState.guardianLocation = { lat: 0, lng: 0, label: 'Unknown Location' };
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

    // Hide loading
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
            .pointColor(d => NODE_COLORS[d.status] || NODE_COLORS.green)
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
            .arcsTransitionDuration(300);

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

    // Set canvas size
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

    // Latitude lines
    for (let lat = -60; lat <= 60; lat += 30) {
        const y = ((90 - lat) / 180) * canvas.height;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
    }

    // Longitude lines
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

        const color = NODE_COLORS[node.status] || NODE_COLORS.green;
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

    // Draw arcs (simplified as lines)
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
    // Demo/Live toggle
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

    // Clear events
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
    }, 3000);

    if (globe) globe.arcsData(cortexState.arcs);

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

    // Node count
    document.getElementById('stat-nodes').textContent = stats.total_nodes || cortexState.nodes.length;

    // Attack stats
    document.getElementById('stat-attacks').textContent = cortexState.stats.attacks;
    document.getElementById('stat-repelled').textContent = cortexState.stats.repelled;

    // Average Qsecbit
    if (cortexState.nodes.length > 0) {
        const totalQsecbit = cortexState.nodes.reduce((sum, n) => sum + (n.qsecbit || 0), 0);
        const avg = totalQsecbit / cortexState.nodes.length;
        document.getElementById('stat-qsecbit').textContent = avg.toFixed(3);
    }

    // Tier counts
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

    // Remove placeholder
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
        <span class="event-icon" style="color: ${iconColor};">${icon === 'attack' ? '⚠' : '✓'}</span>
        <span class="event-time">${time}</span>
        <span class="event-detail">${sourceLabel} → ${targetLabel}</span>
        <span class="event-type">${event.attack_type || 'unknown'}</span>
    `;

    list.insertBefore(li, list.firstChild);

    // Keep only last 20 events
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

// Export for external use
window.initCortexGlobe = initCortexGlobe;
window.refreshCortexData = refreshData;
