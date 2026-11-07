/**
 * HookProbe Cortex - Enhanced Heartbeat System
 *
 * Premium visual heartbeat effects that:
 * - Pulse nodes based on health check frequency
 * - Speed up for critical status (faster = more urgent)
 * - Sync across the mesh to show collective "breathing"
 * - Color transitions following RAG (Red-Amber-Green) spectrum
 */

// Heartbeat state
const heartbeatState = {
    enabled: true,
    nodes: new Map(), // nodeId -> heartbeat config
    globalPhase: 0,
    meshSyncEnabled: true,
    lastUpdate: Date.now()
};

// RAG color system with glow effects
const RAG_COLORS = {
    green: {
        primary: '#00ff88',
        glow: 'rgba(0, 255, 136, 0.6)',
        gradient: 'radial-gradient(circle, rgba(0,255,136,0.4) 0%, rgba(0,255,136,0) 70%)'
    },
    amber: {
        primary: '#ffaa00',
        glow: 'rgba(255, 170, 0, 0.6)',
        gradient: 'radial-gradient(circle, rgba(255,170,0,0.4) 0%, rgba(255,170,0,0) 70%)'
    },
    red: {
        primary: '#ff4444',
        glow: 'rgba(255, 68, 68, 0.7)',
        gradient: 'radial-gradient(circle, rgba(255,68,68,0.5) 0%, rgba(255,68,68,0) 70%)'
    }
};

// Heartbeat timing by status (milliseconds)
const HEARTBEAT_INTERVALS = {
    green: 3000,    // Calm, healthy pulse
    amber: 1500,    // Faster, warning pulse
    red: 750        // Urgent, critical pulse
};

/**
 * Initialize the heartbeat system
 */
function initHeartbeatSystem() {
    // Start the global heartbeat animation loop
    requestAnimationFrame(heartbeatLoop);
    console.log('Cortex Heartbeat System initialized');
}

/**
 * Main heartbeat animation loop
 */
function heartbeatLoop(timestamp) {
    if (!heartbeatState.enabled) {
        requestAnimationFrame(heartbeatLoop);
        return;
    }

    const deltaTime = timestamp - heartbeatState.lastUpdate;
    heartbeatState.lastUpdate = timestamp;

    // Update global phase for mesh sync
    heartbeatState.globalPhase = (heartbeatState.globalPhase + deltaTime / 1000) % (Math.PI * 2);

    // Update each node's heartbeat
    heartbeatState.nodes.forEach((config, nodeId) => {
        updateNodeHeartbeat(nodeId, config, timestamp);
    });

    requestAnimationFrame(heartbeatLoop);
}

/**
 * Register a node for heartbeat animation
 */
function registerNodeHeartbeat(nodeId, status = 'green', element = null) {
    const interval = HEARTBEAT_INTERVALS[status] || HEARTBEAT_INTERVALS.green;
    const color = RAG_COLORS[status] || RAG_COLORS.green;

    heartbeatState.nodes.set(nodeId, {
        status,
        interval,
        color,
        element,
        phase: Math.random() * Math.PI * 2, // Random start phase
        lastPulse: Date.now(),
        intensity: 1.0
    });
}

/**
 * Update a node's heartbeat status
 */
function updateNodeHeartbeatStatus(nodeId, status) {
    const config = heartbeatState.nodes.get(nodeId);
    if (!config) return;

    const oldStatus = config.status;
    config.status = status;
    config.interval = HEARTBEAT_INTERVALS[status] || HEARTBEAT_INTERVALS.green;
    config.color = RAG_COLORS[status] || RAG_COLORS.green;

    // Trigger transition effect if status changed
    if (oldStatus !== status) {
        triggerStatusTransition(nodeId, oldStatus, status);
    }
}

/**
 * Update individual node heartbeat animation
 */
function updateNodeHeartbeat(nodeId, config, timestamp) {
    if (!config.element) {
        // Try to find element by node ID
        config.element = document.querySelector(`[data-node-id="${nodeId}"] .heartbeat-pulse`);
        if (!config.element) return;
    }

    const el = config.element;
    const progress = (timestamp % config.interval) / config.interval;

    // Heartbeat curve: sharp rise, slow fall
    const heartbeatCurve = heartbeatEase(progress);

    // Calculate scale and opacity
    const baseScale = 1.0;
    const pulseScale = 0.3 * config.intensity;
    const scale = baseScale + (heartbeatCurve * pulseScale);

    const baseOpacity = 0.6;
    const pulseOpacity = 0.4 * config.intensity;
    const opacity = baseOpacity + (heartbeatCurve * pulseOpacity);

    // Apply styles
    el.style.transform = `scale(${scale})`;
    el.style.opacity = opacity;
    el.style.boxShadow = `0 0 ${15 + heartbeatCurve * 20}px ${config.color.glow}`;
    el.style.background = config.color.gradient;
}

/**
 * Heartbeat easing function - sharp rise, slow fall (like a real heartbeat)
 */
function heartbeatEase(t) {
    // Double-bump heartbeat pattern
    if (t < 0.1) {
        // First beat rise
        return Math.sin(t * Math.PI / 0.1) * 0.8;
    } else if (t < 0.2) {
        // First beat fall
        return Math.cos((t - 0.1) * Math.PI / 0.1) * 0.4 + 0.4;
    } else if (t < 0.3) {
        // Second beat rise
        return Math.sin((t - 0.2) * Math.PI / 0.1);
    } else if (t < 0.5) {
        // Second beat fall
        return Math.cos((t - 0.3) * Math.PI / 0.2) * 0.5 + 0.5;
    } else {
        // Rest period
        return 0;
    }
}

/**
 * Trigger visual transition when status changes
 */
function triggerStatusTransition(nodeId, fromStatus, toStatus) {
    const config = heartbeatState.nodes.get(nodeId);
    if (!config || !config.element) return;

    const el = config.element;
    const parent = el.parentElement;

    // Create transition ripple
    const ripple = document.createElement('div');
    ripple.className = 'status-transition-ripple';
    ripple.style.cssText = `
        position: absolute;
        top: 50%;
        left: 50%;
        width: 100%;
        height: 100%;
        border-radius: 50%;
        transform: translate(-50%, -50%) scale(1);
        border: 2px solid ${RAG_COLORS[toStatus].primary};
        opacity: 1;
        pointer-events: none;
        animation: statusRipple 1s ease-out forwards;
    `;

    parent.appendChild(ripple);
    setTimeout(() => ripple.remove(), 1000);

    // Flash effect
    el.style.transition = 'all 0.3s ease';
    el.style.filter = 'brightness(2)';
    setTimeout(() => {
        el.style.filter = 'brightness(1)';
    }, 300);

    console.log(`Cortex: Node ${nodeId} status transition ${fromStatus} → ${toStatus}`);
}

/**
 * Create mesh-wide heartbeat pulse (collective breathing)
 */
function triggerMeshHeartbeat() {
    if (!heartbeatState.meshSyncEnabled) return;

    // Synchronize all nodes to pulse together
    const now = Date.now();
    heartbeatState.nodes.forEach((config) => {
        config.lastPulse = now;
        config.intensity = 1.5; // Boost intensity

        // Decay intensity back to normal
        setTimeout(() => {
            config.intensity = 1.0;
        }, 500);
    });

    // Visual feedback
    const container = document.getElementById('globe-container');
    if (container) {
        container.style.boxShadow = 'inset 0 0 100px rgba(0, 191, 255, 0.2)';
        setTimeout(() => {
            container.style.boxShadow = '';
        }, 500);
    }
}

/**
 * Create heartbeat HTML element for a node
 */
function createHeartbeatElement(status = 'green') {
    const color = RAG_COLORS[status] || RAG_COLORS.green;

    const container = document.createElement('div');
    container.className = 'node-heartbeat-container';

    const pulse = document.createElement('div');
    pulse.className = 'heartbeat-pulse';
    pulse.style.cssText = `
        width: 100%;
        height: 100%;
        border-radius: 50%;
        background: ${color.gradient};
        box-shadow: 0 0 15px ${color.glow};
        transition: all 0.1s ease;
    `;

    const ring = document.createElement('div');
    ring.className = 'heartbeat-ring';
    ring.style.cssText = `
        position: absolute;
        inset: -4px;
        border-radius: 50%;
        border: 1px solid ${color.primary};
        opacity: 0.5;
        animation: heartbeatRing ${HEARTBEAT_INTERVALS[status]}ms ease-out infinite;
    `;

    container.appendChild(pulse);
    container.appendChild(ring);

    return container;
}

/**
 * Get color for interpolated Qsecbit value
 */
function getQsecbitColor(qsecbit) {
    if (qsecbit < 0.45) {
        // Green zone - interpolate green to amber
        const t = qsecbit / 0.45;
        return interpolateColor(RAG_COLORS.green.primary, RAG_COLORS.amber.primary, t * 0.3);
    } else if (qsecbit < 0.70) {
        // Amber zone
        const t = (qsecbit - 0.45) / 0.25;
        return interpolateColor(RAG_COLORS.amber.primary, RAG_COLORS.red.primary, t * 0.5);
    } else {
        // Red zone
        return RAG_COLORS.red.primary;
    }
}

/**
 * Interpolate between two hex colors
 */
function interpolateColor(color1, color2, factor) {
    const hex = (c) => parseInt(c.slice(1), 16);
    const r = (c) => (c >> 16) & 0xff;
    const g = (c) => (c >> 8) & 0xff;
    const b = (c) => c & 0xff;

    const c1 = hex(color1);
    const c2 = hex(color2);

    const ri = Math.round(r(c1) + (r(c2) - r(c1)) * factor);
    const gi = Math.round(g(c1) + (g(c2) - g(c1)) * factor);
    const bi = Math.round(b(c1) + (b(c2) - b(c1)) * factor);

    return `#${((ri << 16) | (gi << 8) | bi).toString(16).padStart(6, '0')}`;
}

/**
 * Enable/disable heartbeat system
 */
function setHeartbeatEnabled(enabled) {
    heartbeatState.enabled = enabled;
    console.log(`Cortex Heartbeat: ${enabled ? 'enabled' : 'disabled'}`);
}

/**
 * Enable/disable mesh sync
 */
function setMeshSyncEnabled(enabled) {
    heartbeatState.meshSyncEnabled = enabled;
}

/**
 * Inject heartbeat CSS animations
 */
function injectHeartbeatStyles() {
    if (document.getElementById('heartbeat-styles')) return;

    const style = document.createElement('style');
    style.id = 'heartbeat-styles';
    style.textContent = `
        @keyframes heartbeatRing {
            0% {
                transform: scale(1);
                opacity: 0.6;
            }
            50% {
                transform: scale(1.5);
                opacity: 0.3;
            }
            100% {
                transform: scale(2);
                opacity: 0;
            }
        }

        @keyframes statusRipple {
            0% {
                transform: translate(-50%, -50%) scale(1);
                opacity: 1;
            }
            100% {
                transform: translate(-50%, -50%) scale(3);
                opacity: 0;
            }
        }

        .node-heartbeat-container {
            position: relative;
            width: 100%;
            height: 100%;
        }

        .heartbeat-pulse {
            will-change: transform, opacity, box-shadow;
        }

        .heartbeat-ring {
            will-change: transform, opacity;
        }

        /* Status-specific heartbeat speeds */
        .node-status-green .heartbeat-ring {
            animation-duration: 3000ms;
        }

        .node-status-amber .heartbeat-ring {
            animation-duration: 1500ms;
        }

        .node-status-red .heartbeat-ring {
            animation-duration: 750ms;
        }

        /* Critical pulsing glow */
        .node-status-red .heartbeat-pulse {
            animation: criticalPulse 0.75s ease-in-out infinite;
        }

        @keyframes criticalPulse {
            0%, 100% {
                filter: brightness(1) drop-shadow(0 0 8px rgba(255, 68, 68, 0.6));
            }
            50% {
                filter: brightness(1.3) drop-shadow(0 0 20px rgba(255, 68, 68, 0.9));
            }
        }
    `;

    document.head.appendChild(style);
}

// Auto-inject styles
injectHeartbeatStyles();

// Export functions
window.initHeartbeatSystem = initHeartbeatSystem;
window.registerNodeHeartbeat = registerNodeHeartbeat;
window.updateNodeHeartbeatStatus = updateNodeHeartbeatStatus;
window.triggerMeshHeartbeat = triggerMeshHeartbeat;
window.createHeartbeatElement = createHeartbeatElement;
window.getQsecbitColor = getQsecbitColor;
window.setHeartbeatEnabled = setHeartbeatEnabled;
window.setMeshSyncEnabled = setMeshSyncEnabled;
window.heartbeatState = heartbeatState;
