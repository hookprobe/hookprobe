/**
 * HookProbe Globe Animations
 *
 * Animation utilities for attack trajectories and visual effects
 */

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
    // Longer distances = higher arcs
    const altitude = Math.min(0.5, Math.max(0.1, distanceKm / 20000));

    // Calculate animation duration based on distance
    const duration = Math.min(3000, Math.max(1000, distanceKm / 2));

    return {
        distance: distanceKm,
        altitude,
        duration
    };
}

/**
 * Create pulsing effect for nodes under attack
 */
function pulseNode(nodeId, color, duration = 2000) {
    // This would be implemented with Three.js shader effects
    // For now, we rely on Globe.gl's built-in point rendering
    console.log(`Pulse effect on node ${nodeId}`);
}

/**
 * Create explosion effect at target location
 */
function createImpactEffect(lat, lng, type) {
    // Placeholder for particle effects
    // Could use Three.js particles or CSS animations
    console.log(`Impact effect at ${lat}, ${lng} (${type})`);
}

/**
 * Animate camera to focus on an event
 */
function focusOnEvent(globe, lat, lng, altitude = 2) {
    if (!globe) return;

    globe.pointOfView({
        lat,
        lng,
        altitude
    }, 1000); // 1 second transition
}

/**
 * Create ripple effect from a point
 */
function createRippleEffect(lat, lng, color, duration = 1500) {
    // Placeholder for ripple animation
    // Would create expanding rings using Three.js
    console.log(`Ripple effect at ${lat}, ${lng}`);
}

// Export functions
window.calculateArcProperties = calculateArcProperties;
window.pulseNode = pulseNode;
window.createImpactEffect = createImpactEffect;
window.focusOnEvent = focusOnEvent;
window.createRippleEffect = createRippleEffect;
