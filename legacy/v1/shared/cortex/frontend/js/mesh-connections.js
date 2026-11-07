/**
 * HookProbe Cortex - Mesh Connection Lines Visualization
 *
 * Premium visual effects for mesh connections:
 * - Animated data flow lines between cities/nodes
 * - Pulsing connection strength indicators
 * - Connection quality visualization (latency, bandwidth)
 * - City-to-city mesh topology view
 */

// Mesh connection state
const meshConnectionState = {
    connections: [],
    cityConnections: [],
    animationEnabled: true,
    showQuality: true,
    dataFlowParticles: [],
    lastUpdate: Date.now()
};

// Connection quality colors
const CONNECTION_QUALITY = {
    excellent: {
        color: '#00ff88',
        glow: 'rgba(0, 255, 136, 0.4)',
        latencyMax: 50
    },
    good: {
        color: '#00bfff',
        glow: 'rgba(0, 191, 255, 0.4)',
        latencyMax: 150
    },
    fair: {
        color: '#ffaa00',
        glow: 'rgba(255, 170, 0, 0.4)',
        latencyMax: 300
    },
    poor: {
        color: '#ff4444',
        glow: 'rgba(255, 68, 68, 0.4)',
        latencyMax: Infinity
    }
};

/**
 * Initialize mesh connection visualization
 */
function initMeshConnections(globe) {
    // Inject CSS styles
    injectMeshConnectionStyles();

    // Start animation loop
    requestAnimationFrame(meshConnectionLoop);

    console.log('Cortex Mesh Connections initialized');
}

/**
 * Add a mesh connection between two nodes/cities
 */
function addMeshConnection(sourceId, targetId, options = {}) {
    const connection = {
        id: `${sourceId}-${targetId}`,
        sourceId,
        targetId,
        source: options.source || { lat: 0, lng: 0 },
        target: options.target || { lat: 0, lng: 0 },
        latency: options.latency || 50,
        bandwidth: options.bandwidth || 1000,
        active: options.active !== false,
        type: options.type || 'direct', // direct, relay, tunnel
        dataFlowDirection: options.direction || 'bidirectional', // in, out, bidirectional
        createdAt: Date.now()
    };

    // Calculate quality
    connection.quality = getConnectionQuality(connection.latency);

    meshConnectionState.connections.push(connection);
    updateGlobeConnections();

    return connection;
}

/**
 * Update existing connection metrics
 */
function updateMeshConnection(connectionId, updates) {
    const conn = meshConnectionState.connections.find(c => c.id === connectionId);
    if (!conn) return;

    Object.assign(conn, updates);

    if (updates.latency !== undefined) {
        conn.quality = getConnectionQuality(conn.latency);
    }

    updateGlobeConnections();
}

/**
 * Remove a mesh connection
 */
function removeMeshConnection(connectionId) {
    meshConnectionState.connections = meshConnectionState.connections.filter(
        c => c.id !== connectionId
    );
    updateGlobeConnections();
}

/**
 * Get connection quality based on latency
 */
function getConnectionQuality(latency) {
    if (latency <= CONNECTION_QUALITY.excellent.latencyMax) return 'excellent';
    if (latency <= CONNECTION_QUALITY.good.latencyMax) return 'good';
    if (latency <= CONNECTION_QUALITY.fair.latencyMax) return 'fair';
    return 'poor';
}

/**
 * Update Globe.gl connection visualization
 */
function updateGlobeConnections() {
    if (!window.globe) return;

    const activeConnections = meshConnectionState.connections.filter(c => c.active);

    // Update arcs data
    window.globe.arcsData(activeConnections.map(conn => ({
        startLat: conn.source.lat,
        startLng: conn.source.lng,
        endLat: conn.target.lat,
        endLng: conn.target.lng,
        color: [CONNECTION_QUALITY[conn.quality].color, CONNECTION_QUALITY[conn.quality].glow],
        stroke: getConnectionStroke(conn),
        dashLength: conn.type === 'relay' ? 0.3 : 0.5,
        dashGap: conn.type === 'relay' ? 0.2 : 0.1,
        dashAnimateTime: 2000 - (conn.bandwidth / 10), // Faster = more bandwidth
        altitude: getConnectionAltitude(conn),
        label: getConnectionLabel(conn)
    })));
}

/**
 * Get connection stroke width based on bandwidth
 */
function getConnectionStroke(conn) {
    // Scale 0.2 to 1.0 based on bandwidth
    const minBw = 100;
    const maxBw = 10000;
    const normalized = Math.min(1, Math.max(0, (conn.bandwidth - minBw) / (maxBw - minBw)));
    return 0.2 + (normalized * 0.8);
}

/**
 * Get connection altitude based on distance and type
 */
function getConnectionAltitude(conn) {
    // Calculate distance
    const lat1 = conn.source.lat * Math.PI / 180;
    const lat2 = conn.target.lat * Math.PI / 180;
    const dLng = (conn.target.lng - conn.source.lng) * Math.PI / 180;

    const d = Math.acos(
        Math.sin(lat1) * Math.sin(lat2) +
        Math.cos(lat1) * Math.cos(lat2) * Math.cos(dLng)
    );

    // Longer connections = higher arcs
    const baseAltitude = Math.min(0.4, Math.max(0.1, d * 0.3));

    // Relay connections are higher
    if (conn.type === 'relay') return baseAltitude * 1.3;
    if (conn.type === 'tunnel') return baseAltitude * 1.5;

    return baseAltitude;
}

/**
 * Get connection tooltip label
 */
function getConnectionLabel(conn) {
    const typeIcon = {
        direct: '⚡',
        relay: '🔄',
        tunnel: '🔒'
    }[conn.type] || '';

    return `
        <div class="mesh-connection-tooltip">
            <div class="connection-header">${typeIcon} ${conn.type.toUpperCase()}</div>
            <div class="connection-metric">
                <span class="metric-label">Latency</span>
                <span class="metric-value ${conn.quality}">${conn.latency}ms</span>
            </div>
            <div class="connection-metric">
                <span class="metric-label">Bandwidth</span>
                <span class="metric-value">${formatBandwidth(conn.bandwidth)}</span>
            </div>
        </div>
    `;
}

/**
 * Format bandwidth for display
 */
function formatBandwidth(kbps) {
    if (kbps >= 1000) {
        return `${(kbps / 1000).toFixed(1)} Mbps`;
    }
    return `${kbps} Kbps`;
}

/**
 * Animation loop for mesh connections
 */
function meshConnectionLoop(timestamp) {
    if (!meshConnectionState.animationEnabled) {
        requestAnimationFrame(meshConnectionLoop);
        return;
    }

    const deltaTime = timestamp - meshConnectionState.lastUpdate;
    meshConnectionState.lastUpdate = timestamp;

    // Update data flow particles
    updateDataFlowParticles(deltaTime);

    requestAnimationFrame(meshConnectionLoop);
}

/**
 * Create data flow particle effect
 */
function createDataFlowParticle(connectionId) {
    const conn = meshConnectionState.connections.find(c => c.id === connectionId);
    if (!conn) return;

    const particle = {
        connectionId,
        progress: 0,
        speed: 0.001 + Math.random() * 0.002,
        size: 2 + Math.random() * 2,
        opacity: 0.8,
        direction: conn.dataFlowDirection === 'out' ? 1 : -1
    };

    if (conn.dataFlowDirection === 'bidirectional') {
        particle.direction = Math.random() > 0.5 ? 1 : -1;
    }

    meshConnectionState.dataFlowParticles.push(particle);
}

/**
 * Update data flow particles
 */
function updateDataFlowParticles(deltaTime) {
    meshConnectionState.dataFlowParticles = meshConnectionState.dataFlowParticles.filter(p => {
        p.progress += p.speed * deltaTime * p.direction;

        // Remove if completed
        if (p.progress > 1 || p.progress < 0) {
            return false;
        }

        // Fade at edges
        p.opacity = Math.sin(p.progress * Math.PI) * 0.8;

        return true;
    });
}

/**
 * Create city-to-city connection summary
 */
function createCityConnections(nodes) {
    // Group nodes by city
    const cityGroups = {};
    nodes.forEach(node => {
        const cityKey = `${Math.round(node.lat)},${Math.round(node.lng)}`;
        if (!cityGroups[cityKey]) {
            cityGroups[cityKey] = {
                lat: node.lat,
                lng: node.lng,
                city: node.city || cityKey,
                nodes: []
            };
        }
        cityGroups[cityKey].nodes.push(node);
    });

    // Create connections between cities
    const cities = Object.values(cityGroups);
    const cityConnections = [];

    for (let i = 0; i < cities.length; i++) {
        for (let j = i + 1; j < cities.length; j++) {
            // Calculate connection strength based on node count
            const strength = Math.min(cities[i].nodes.length, cities[j].nodes.length);

            cityConnections.push({
                id: `city-${i}-${j}`,
                source: { lat: cities[i].lat, lng: cities[i].lng },
                target: { lat: cities[j].lat, lng: cities[j].lng },
                sourceCity: cities[i].city,
                targetCity: cities[j].city,
                strength,
                latency: 50 + Math.random() * 200,
                bandwidth: strength * 1000
            });
        }
    }

    meshConnectionState.cityConnections = cityConnections;
    return cityConnections;
}

/**
 * Show only city-level connections (for zoomed out view)
 */
function showCityConnections() {
    if (!window.globe) return;

    const cityConns = meshConnectionState.cityConnections.filter(c => c.strength >= 2);

    window.globe.arcsData(cityConns.map(conn => ({
        startLat: conn.source.lat,
        startLng: conn.source.lng,
        endLat: conn.target.lat,
        endLng: conn.target.lng,
        color: ['rgba(0, 191, 255, 0.4)', 'rgba(0, 191, 255, 0.1)'],
        stroke: Math.min(1, conn.strength * 0.1),
        dashLength: 0.5,
        dashGap: 0.1,
        dashAnimateTime: 3000,
        altitude: 0.15
    })));
}

/**
 * Inject CSS styles for mesh connections
 */
function injectMeshConnectionStyles() {
    if (document.getElementById('mesh-connection-styles')) return;

    const style = document.createElement('style');
    style.id = 'mesh-connection-styles';
    style.textContent = `
        .mesh-connection-tooltip {
            background: rgba(10, 12, 18, 0.95);
            border: 1px solid rgba(0, 191, 255, 0.3);
            border-radius: 8px;
            padding: 12px 16px;
            min-width: 140px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
        }

        .mesh-connection-tooltip .connection-header {
            font-family: 'Orbitron', monospace;
            font-size: 11px;
            font-weight: 600;
            color: #00bfff;
            letter-spacing: 1px;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid rgba(100, 120, 140, 0.2);
        }

        .mesh-connection-tooltip .connection-metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 6px 0;
        }

        .mesh-connection-tooltip .metric-label {
            font-size: 10px;
            color: #6a6a7a;
        }

        .mesh-connection-tooltip .metric-value {
            font-family: 'Orbitron', monospace;
            font-size: 12px;
            font-weight: 600;
        }

        .mesh-connection-tooltip .metric-value.excellent { color: #00ff88; }
        .mesh-connection-tooltip .metric-value.good { color: #00bfff; }
        .mesh-connection-tooltip .metric-value.fair { color: #ffaa00; }
        .mesh-connection-tooltip .metric-value.poor { color: #ff4444; }

        /* Data flow particle effect */
        .data-flow-particle {
            position: absolute;
            width: 4px;
            height: 4px;
            border-radius: 50%;
            background: #00bfff;
            box-shadow: 0 0 8px rgba(0, 191, 255, 0.8);
            pointer-events: none;
            will-change: transform, opacity;
        }

        /* Connection type indicators */
        .connection-type-direct::before { content: '⚡'; }
        .connection-type-relay::before { content: '🔄'; }
        .connection-type-tunnel::before { content: '🔒'; }
    `;

    document.head.appendChild(style);
}

// Export functions
window.initMeshConnections = initMeshConnections;
window.addMeshConnection = addMeshConnection;
window.updateMeshConnection = updateMeshConnection;
window.removeMeshConnection = removeMeshConnection;
window.createCityConnections = createCityConnections;
window.showCityConnections = showCityConnections;
window.meshConnectionState = meshConnectionState;
