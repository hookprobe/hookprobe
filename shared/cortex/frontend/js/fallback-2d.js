/**
 * HookProbe 2D Map Fallback
 *
 * Simple 2D canvas-based map for mobile and low-end devices
 * Uses a flat world map projection with dots for nodes and lines for attacks
 */

// Canvas and context
let canvas = null;
let ctx = null;

// Map state
const map2DState = {
    nodes: [],
    attacks: [],
    width: 800,
    height: 400
};

// Colors (match 3D theme)
const MAP_COLORS = {
    background: '#0a0a0f',
    land: '#1a1a2e',
    border: '#2a2a4e',
    nodeGreen: '#00ff88',
    nodeAmber: '#ffaa00',
    nodeRed: '#ff4444',
    attackLine: '#ff4444',
    repelledLine: '#00bfff',
    text: '#888888'
};

/**
 * Initialize 2D fallback map
 */
function init2DFallback() {
    canvas = document.getElementById('fallback-canvas');
    if (!canvas) return;

    // Calculate optimal canvas size based on viewport
    const calculateCanvasSize = () => {
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;

        // For mobile portrait mode, use more of the available height
        const isMobilePortrait = viewportHeight > viewportWidth && viewportWidth < 768;

        if (isMobilePortrait) {
            // Use nearly full width on mobile portrait
            map2DState.width = viewportWidth - 20;
            // Adjust height to fit below header (56px) and above mode indicator
            map2DState.height = Math.min(map2DState.width / 1.5, viewportHeight - 200);
        } else {
            // Desktop/landscape: maintain 2:1 aspect ratio
            map2DState.width = Math.min(viewportWidth - 40, 1200);
            map2DState.height = Math.min(map2DState.width / 2, viewportHeight - 180);
        }

        // Ensure minimum dimensions
        map2DState.width = Math.max(map2DState.width, 280);
        map2DState.height = Math.max(map2DState.height, 200);
    };

    calculateCanvasSize();
    canvas.width = map2DState.width;
    canvas.height = map2DState.height;

    ctx = canvas.getContext('2d');

    // Draw initial map
    drawMap();

    // Debounced resize handler
    let resizeTimeout;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
            calculateCanvasSize();
            canvas.width = map2DState.width;
            canvas.height = map2DState.height;
            drawMap();
        }, 100);
    });

    console.log('2D fallback map initialized:', map2DState.width, 'x', map2DState.height);
}

/**
 * Draw the map
 */
function drawMap() {
    if (!ctx) return;

    // Clear canvas
    ctx.fillStyle = MAP_COLORS.background;
    ctx.fillRect(0, 0, map2DState.width, map2DState.height);

    // Draw simple continents (simplified world outline)
    drawContinents();

    // Draw attacks
    map2DState.attacks.forEach(attack => {
        drawAttackLine(attack);
    });

    // Draw nodes
    map2DState.nodes.forEach(node => {
        drawNode(node);
    });
}

/**
 * Draw simplified continent outlines
 */
function drawContinents() {
    ctx.strokeStyle = MAP_COLORS.border;
    ctx.lineWidth = 1;

    // Draw latitude lines
    for (let lat = -60; lat <= 60; lat += 30) {
        const y = latToY(lat);
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(map2DState.width, y);
        ctx.globalAlpha = 0.2;
        ctx.stroke();
        ctx.globalAlpha = 1;
    }

    // Draw longitude lines
    for (let lng = -180; lng <= 180; lng += 30) {
        const x = lngToX(lng);
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, map2DState.height);
        ctx.globalAlpha = 0.2;
        ctx.stroke();
        ctx.globalAlpha = 1;
    }

    // Draw equator
    ctx.strokeStyle = MAP_COLORS.border;
    ctx.lineWidth = 2;
    ctx.globalAlpha = 0.3;
    ctx.beginPath();
    ctx.moveTo(0, map2DState.height / 2);
    ctx.lineTo(map2DState.width, map2DState.height / 2);
    ctx.stroke();
    ctx.globalAlpha = 1;
}

/**
 * Draw a node on the map
 */
function drawNode(node) {
    const x = lngToX(node.lng);
    const y = latToY(node.lat);

    // Get color based on status
    let color = MAP_COLORS.nodeGreen;
    if (node.status === 'amber') color = MAP_COLORS.nodeAmber;
    if (node.status === 'red') color = MAP_COLORS.nodeRed;

    // Get size based on tier
    let radius = 4;
    if (node.tier === 'guardian') radius = 6;
    if (node.tier === 'fortress') radius = 8;
    if (node.tier === 'nexus') radius = 10;

    // Draw glow
    ctx.beginPath();
    ctx.arc(x, y, radius + 3, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.globalAlpha = 0.3;
    ctx.fill();
    ctx.globalAlpha = 1;

    // Draw node
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();

    // Draw label
    ctx.fillStyle = MAP_COLORS.text;
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(node.label || node.id, x, y + radius + 12);
}

/**
 * Draw attack line
 */
function drawAttackLine(attack) {
    const x1 = lngToX(attack.source.lng);
    const y1 = latToY(attack.source.lat);
    const x2 = lngToX(attack.target.lng);
    const y2 = latToY(attack.target.lat);

    const color = attack.type === 'attack' ? MAP_COLORS.attackLine : MAP_COLORS.repelledLine;

    // Draw line with gradient
    const gradient = ctx.createLinearGradient(x1, y1, x2, y2);
    gradient.addColorStop(0, color);
    gradient.addColorStop(1, 'transparent');

    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.strokeStyle = gradient;
    ctx.lineWidth = 2;
    ctx.stroke();

    // Draw source point
    ctx.beginPath();
    ctx.arc(x1, y1, 3, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
}

/**
 * Convert longitude to X coordinate
 */
function lngToX(lng) {
    return ((lng + 180) / 360) * map2DState.width;
}

/**
 * Convert latitude to Y coordinate
 */
function latToY(lat) {
    return ((90 - lat) / 180) * map2DState.height;
}

/**
 * Update nodes on 2D map
 */
function update2DNodes(nodes) {
    map2DState.nodes = nodes;
    drawMap();
}

/**
 * Add attack to 2D map
 */
function add2DAttack(attack) {
    map2DState.attacks.push(attack);
    drawMap();

    // Remove after animation
    setTimeout(() => {
        map2DState.attacks = map2DState.attacks.filter(a => a.id !== attack.id);
        drawMap();
    }, 3000);
}

// Export functions
window.init2DFallback = init2DFallback;
window.update2DNodes = update2DNodes;
window.add2DAttack = add2DAttack;
