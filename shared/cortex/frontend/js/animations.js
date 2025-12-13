/**
 * HookProbe Cortex - Visual Effects Engine
 *
 * Premium animation system for the digital twin visualization
 * Creates breathing nodes, particle trails, impact effects, and ripples
 */

// Three.js scene references (set by globe.js)
let scene = null;
let camera = null;
let renderer = null;

// Particle systems
const particleSystems = [];
const activeEffects = [];

// Animation frame ID
let animationFrameId = null;

/**
 * Initialize the animation engine
 * Called after Globe.gl creates the Three.js scene
 */
function initAnimationEngine(globeScene, globeCamera, globeRenderer) {
    scene = globeScene;
    camera = globeCamera;
    renderer = globeRenderer;

    // Start the animation loop
    startAnimationLoop();

    console.log('Cortex Animation Engine initialized');
}

/**
 * Main animation loop for custom effects
 */
function startAnimationLoop() {
    function animate() {
        animationFrameId = requestAnimationFrame(animate);

        const time = Date.now() * 0.001;

        // Update all active effects
        activeEffects.forEach((effect, index) => {
            if (effect.update) {
                const shouldRemove = effect.update(time);
                if (shouldRemove) {
                    if (effect.cleanup) effect.cleanup();
                    activeEffects.splice(index, 1);
                }
            }
        });

        // Update particle systems
        particleSystems.forEach(system => {
            if (system.update) system.update(time);
        });
    }

    animate();
}

/**
 * Calculate arc properties for smooth animations
 */
function calculateArcProperties(source, target) {
    // Calculate great circle distance
    const lat1 = source.lat * Math.PI / 180;
    const lat2 = target.lat * Math.PI / 180;
    const dLng = (target.lng - source.lng) * Math.PI / 180;

    const d = Math.acos(
        Math.sin(lat1) * Math.sin(lat2) +
        Math.cos(lat1) * Math.cos(lat2) * Math.cos(dLng)
    );

    // Convert to approximate km
    const distanceKm = d * 6371;

    // Calculate arc altitude based on distance
    // Longer distances = higher arcs for dramatic effect
    const altitude = Math.min(0.6, Math.max(0.15, distanceKm / 15000));

    // Calculate animation duration based on distance
    const duration = Math.min(4000, Math.max(1500, distanceKm / 1.5));

    return {
        distance: distanceKm,
        altitude,
        duration,
        strokeWidth: Math.max(0.3, Math.min(0.8, distanceKm / 10000))
    };
}

/**
 * Create breathing/pulsing glow effect for nodes
 * Premium visual: nodes "breathe" based on their Qsecbit status
 */
function createBreathingEffect(nodeElement, status, intensity = 1) {
    const baseColors = {
        green: { r: 0, g: 255, b: 136 },
        amber: { r: 255, g: 170, b: 0 },
        red: { r: 255, g: 68, b: 68 }
    };

    const color = baseColors[status] || baseColors.green;
    const breathingSpeed = status === 'red' ? 2 : status === 'amber' ? 1.5 : 1;

    const effect = {
        startTime: Date.now(),
        duration: Infinity,
        update: (time) => {
            const breathe = Math.sin(time * breathingSpeed) * 0.3 + 0.7;
            const glow = `rgba(${color.r}, ${color.g}, ${color.b}, ${breathe * intensity})`;

            if (nodeElement && nodeElement.style) {
                nodeElement.style.boxShadow = `0 0 ${20 * breathe}px ${glow}`;
            }

            return false; // Never auto-remove
        }
    };

    activeEffects.push(effect);
    return effect;
}

/**
 * Create pulsing ring effect for nodes under attack
 * Premium visual: expanding rings emanate from attacked nodes
 */
function pulseNode(lat, lng, color = '#ff4444', rings = 3, duration = 2000) {
    const pulseContainer = document.createElement('div');
    pulseContainer.className = 'cortex-pulse-container';
    pulseContainer.style.cssText = `
        position: absolute;
        pointer-events: none;
        z-index: 1000;
    `;

    for (let i = 0; i < rings; i++) {
        const ring = document.createElement('div');
        ring.className = 'cortex-pulse-ring';
        ring.style.cssText = `
            position: absolute;
            border: 2px solid ${color};
            border-radius: 50%;
            width: 20px;
            height: 20px;
            transform: translate(-50%, -50%);
            animation: cortexPulse ${duration}ms ease-out ${i * (duration / rings)}ms infinite;
            opacity: 0;
        `;
        pulseContainer.appendChild(ring);
    }

    // Inject animation styles if not present
    if (!document.getElementById('cortex-animations')) {
        const style = document.createElement('style');
        style.id = 'cortex-animations';
        style.textContent = `
            @keyframes cortexPulse {
                0% { transform: translate(-50%, -50%) scale(1); opacity: 0.8; }
                100% { transform: translate(-50%, -50%) scale(4); opacity: 0; }
            }
            @keyframes cortexImpact {
                0% { transform: translate(-50%, -50%) scale(0); opacity: 1; }
                50% { transform: translate(-50%, -50%) scale(2); opacity: 0.6; }
                100% { transform: translate(-50%, -50%) scale(3); opacity: 0; }
            }
            @keyframes cortexRipple {
                0% { transform: translate(-50%, -50%) scale(1); opacity: 0.6; border-width: 3px; }
                100% { transform: translate(-50%, -50%) scale(8); opacity: 0; border-width: 1px; }
            }
            @keyframes cortexGlow {
                0%, 100% { box-shadow: 0 0 10px currentColor; }
                50% { box-shadow: 0 0 30px currentColor, 0 0 60px currentColor; }
            }
            .cortex-node-glow {
                animation: cortexGlow 2s ease-in-out infinite;
            }
        `;
        document.head.appendChild(style);
    }

    console.log(`Cortex: Pulse effect at ${lat.toFixed(2)}, ${lng.toFixed(2)}`);

    return pulseContainer;
}

/**
 * Create explosion/impact effect at target location
 * Premium visual: particle burst when attack lands or is repelled
 */
function createImpactEffect(lat, lng, type = 'attack') {
    const colors = {
        attack: '#ff4444',
        repelled: '#00bfff',
        blocked: '#00ff88'
    };

    const color = colors[type] || colors.attack;
    const particleCount = type === 'attack' ? 20 : 15;

    // Create impact burst container
    const impact = document.createElement('div');
    impact.className = 'cortex-impact';
    impact.style.cssText = `
        position: absolute;
        width: 30px;
        height: 30px;
        border-radius: 50%;
        background: radial-gradient(circle, ${color} 0%, transparent 70%);
        transform: translate(-50%, -50%);
        animation: cortexImpact 800ms ease-out forwards;
        pointer-events: none;
    `;

    // Create particle burst
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        const angle = (i / particleCount) * Math.PI * 2;
        const distance = 30 + Math.random() * 40;
        const duration = 600 + Math.random() * 400;

        particle.style.cssText = `
            position: absolute;
            width: 4px;
            height: 4px;
            background: ${color};
            border-radius: 50%;
            left: 50%;
            top: 50%;
            transform: translate(-50%, -50%);
            animation: particle-${i} ${duration}ms ease-out forwards;
        `;

        // Dynamic keyframes for each particle
        const keyframes = `
            @keyframes particle-${i} {
                0% { transform: translate(-50%, -50%) scale(1); opacity: 1; }
                100% {
                    transform: translate(
                        calc(-50% + ${Math.cos(angle) * distance}px),
                        calc(-50% + ${Math.sin(angle) * distance}px)
                    ) scale(0);
                    opacity: 0;
                }
            }
        `;

        const style = document.createElement('style');
        style.textContent = keyframes;
        document.head.appendChild(style);

        impact.appendChild(particle);

        // Cleanup style after animation
        setTimeout(() => style.remove(), duration + 100);
    }

    // Auto-remove impact element
    setTimeout(() => impact.remove(), 1000);

    console.log(`Cortex: Impact effect (${type}) at ${lat.toFixed(2)}, ${lng.toFixed(2)}`);

    return impact;
}

/**
 * Animate camera to focus on an event
 * Premium visual: smooth cinematic camera movement
 */
function focusOnEvent(globe, lat, lng, altitude = 1.8, duration = 1500) {
    if (!globe) return;

    // Get current position
    const current = globe.pointOfView();

    // Calculate intermediate positions for smooth arc
    globe.pointOfView({
        lat,
        lng,
        altitude
    }, duration);

    console.log(`Cortex: Camera focus to ${lat.toFixed(2)}, ${lng.toFixed(2)}`);
}

/**
 * Create ripple effect from a point
 * Premium visual: water-like ripples spreading from event location
 */
function createRippleEffect(lat, lng, color = '#00bfff', duration = 2000) {
    const rippleCount = 4;
    const container = document.createElement('div');
    container.className = 'cortex-ripple-container';
    container.style.cssText = `
        position: absolute;
        pointer-events: none;
    `;

    for (let i = 0; i < rippleCount; i++) {
        const ripple = document.createElement('div');
        ripple.style.cssText = `
            position: absolute;
            border: 2px solid ${color};
            border-radius: 50%;
            width: 10px;
            height: 10px;
            transform: translate(-50%, -50%);
            animation: cortexRipple ${duration}ms ease-out ${i * (duration / rippleCount)}ms forwards;
            opacity: 0;
        `;
        container.appendChild(ripple);
    }

    // Auto-remove after all ripples complete
    setTimeout(() => container.remove(), duration * 2);

    console.log(`Cortex: Ripple effect at ${lat.toFixed(2)}, ${lng.toFixed(2)}`);

    return container;
}

/**
 * Create connection beam between two nodes
 * Premium visual: glowing beam showing mesh connections
 */
function createConnectionBeam(sourceLat, sourceLng, targetLat, targetLng, color = '#00ff88') {
    console.log(`Cortex: Connection beam ${sourceLat.toFixed(2)},${sourceLng.toFixed(2)} → ${targetLat.toFixed(2)},${targetLng.toFixed(2)}`);

    return {
        source: { lat: sourceLat, lng: sourceLng },
        target: { lat: targetLat, lng: targetLng },
        color,
        animated: true
    };
}

/**
 * Create "heartbeat" effect for the entire mesh
 * Premium visual: periodic pulse showing mesh is alive
 * Works with the actual displayed data (respects clustering state)
 */
function meshHeartbeat(globe, nodes) {
    if (!globe) return;

    // Get actual displayed data from state (respects clustering)
    const displayData = window.state?.displayData || nodes || [];
    if (displayData.length === 0) return;

    // Store original altitude for all points
    const originalAltitudes = displayData.map(d => d.pointAltitude || 0.01);

    // Expand phase - increase altitude to create "pop" effect
    displayData.forEach((point, i) => {
        point.pointAltitude = originalAltitudes[i] * 2;
    });

    // Force redraw with expanded points
    globe.pointsData([...displayData.filter(d => d.type !== 'cluster')]);

    // Also pulse HTML elements (clusters) if present
    const clusterElements = document.querySelectorAll('.cortex-cluster');
    clusterElements.forEach(el => {
        el.style.transform = 'scale(1.2)';
        el.style.transition = 'transform 0.2s ease-out';
    });

    // Contract phase
    setTimeout(() => {
        displayData.forEach((point, i) => {
            point.pointAltitude = originalAltitudes[i];
        });
        globe.pointsData([...displayData.filter(d => d.type !== 'cluster')]);

        // Reset cluster elements
        clusterElements.forEach(el => {
            el.style.transform = 'scale(1)';
        });
    }, 200);

    console.log(`Mesh heartbeat: pulsed ${displayData.length} points`);
}

/**
 * Create threat level indicator overlay
 * Premium visual: ambient glow based on global threat level
 */
function setAmbientThreatLevel(level) {
    // level: 0-1, where 0 is calm and 1 is critical
    const container = document.getElementById('globe-container');
    if (!container) return;

    const hue = 120 - (level * 120); // Green (120) to Red (0)
    const saturation = 100;
    const lightness = 10 + (level * 15);
    const alpha = 0.1 + (level * 0.15);

    container.style.boxShadow = `inset 0 0 100px hsla(${hue}, ${saturation}%, ${lightness}%, ${alpha})`;
}

/**
 * Create scanline effect
 * Premium visual: subtle scanning animation
 */
function createScanlineEffect() {
    const scanline = document.createElement('div');
    scanline.id = 'cortex-scanline';
    scanline.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg,
            transparent 0%,
            rgba(0, 191, 255, 0.3) 50%,
            transparent 100%
        );
        animation: scanline 4s linear infinite;
        pointer-events: none;
        z-index: 1000;
    `;

    // Add scanline animation
    if (!document.getElementById('cortex-scanline-style')) {
        const style = document.createElement('style');
        style.id = 'cortex-scanline-style';
        style.textContent = `
            @keyframes scanline {
                0% { top: 0; opacity: 0; }
                10% { opacity: 0.8; }
                90% { opacity: 0.8; }
                100% { top: 100vh; opacity: 0; }
            }
        `;
        document.head.appendChild(style);
    }

    document.body.appendChild(scanline);
    return scanline;
}

/**
 * Cleanup animation engine
 */
function destroyAnimationEngine() {
    if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
    }

    activeEffects.length = 0;
    particleSystems.length = 0;

    // Remove injected styles
    const styles = document.querySelectorAll('[id^="cortex-"]');
    styles.forEach(s => s.remove());
}

// Export functions
window.initAnimationEngine = initAnimationEngine;
window.calculateArcProperties = calculateArcProperties;
window.createBreathingEffect = createBreathingEffect;
window.pulseNode = pulseNode;
window.createImpactEffect = createImpactEffect;
window.focusOnEvent = focusOnEvent;
window.createRippleEffect = createRippleEffect;
window.createConnectionBeam = createConnectionBeam;
window.meshHeartbeat = meshHeartbeat;
window.setAmbientThreatLevel = setAmbientThreatLevel;
window.createScanlineEffect = createScanlineEffect;
window.destroyAnimationEngine = destroyAnimationEngine;
