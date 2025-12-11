/**
 * HookProbe Cortex - Enhanced Attack Vector Animations
 *
 * Premium visual effects for cyber attacks:
 * - Dynamic arc animations with threat type styling
 * - Impact effects at target locations
 * - Attack type-specific colors and patterns
 * - Severity-based visual intensity
 * - Repelled attack celebration effects
 */

// Attack vector state
const attackVectorState = {
    activeAttacks: [],
    attackHistory: [],
    maxHistory: 100,
    effectsEnabled: true,
    soundEnabled: false
};

// Attack type configurations
const ATTACK_TYPES = {
    ddos: {
        name: 'DDoS',
        color: '#ff4444',
        glowColor: 'rgba(255, 68, 68, 0.6)',
        dashLength: 0.2,
        dashGap: 0.05,
        arcWidth: 0.8,
        particleCount: 30,
        icon: '🌊'
    },
    bruteforce: {
        name: 'Brute Force',
        color: '#ff6b35',
        glowColor: 'rgba(255, 107, 53, 0.6)',
        dashLength: 0.15,
        dashGap: 0.1,
        arcWidth: 0.5,
        particleCount: 20,
        icon: '🔨'
    },
    malware: {
        name: 'Malware',
        color: '#9b59b6',
        glowColor: 'rgba(155, 89, 182, 0.6)',
        dashLength: 0.3,
        dashGap: 0.05,
        arcWidth: 0.6,
        particleCount: 25,
        icon: '🦠'
    },
    phishing: {
        name: 'Phishing',
        color: '#f39c12',
        glowColor: 'rgba(243, 156, 18, 0.6)',
        dashLength: 0.4,
        dashGap: 0.1,
        arcWidth: 0.4,
        particleCount: 15,
        icon: '🎣'
    },
    scan: {
        name: 'Port Scan',
        color: '#3498db',
        glowColor: 'rgba(52, 152, 219, 0.5)',
        dashLength: 0.1,
        dashGap: 0.05,
        arcWidth: 0.3,
        particleCount: 10,
        icon: '🔍'
    },
    exfiltration: {
        name: 'Data Exfil',
        color: '#e74c3c',
        glowColor: 'rgba(231, 76, 60, 0.7)',
        dashLength: 0.5,
        dashGap: 0.1,
        arcWidth: 0.7,
        particleCount: 35,
        icon: '📤'
    },
    unknown: {
        name: 'Unknown',
        color: '#ff4444',
        glowColor: 'rgba(255, 68, 68, 0.5)',
        dashLength: 0.3,
        dashGap: 0.1,
        arcWidth: 0.5,
        particleCount: 20,
        icon: '⚠️'
    }
};

// Repelled colors
const REPELLED_CONFIG = {
    color: '#00bfff',
    glowColor: 'rgba(0, 191, 255, 0.6)',
    dashLength: 0.4,
    dashGap: 0.15,
    arcWidth: 0.3,
    particleCount: 25,
    icon: '🛡️'
};

/**
 * Create an attack arc visualization
 */
function createAttackArc(event) {
    const attackType = event.attack_type?.toLowerCase() || 'unknown';
    const config = ATTACK_TYPES[attackType] || ATTACK_TYPES.unknown;
    const severity = event.severity || 0.5;
    const isRepelled = event.type === 'attack_repelled';

    // Choose config based on repelled status
    const visualConfig = isRepelled ? REPELLED_CONFIG : config;

    const arc = {
        id: event.id || `attack-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        type: isRepelled ? 'repelled' : 'attack',
        attackType,
        source: event.source,
        target: event.target,
        severity,
        config: visualConfig,
        createdAt: Date.now(),
        duration: calculateArcDuration(event.source, event.target),
        phase: 0
    };

    attackVectorState.activeAttacks.push(arc);

    // Add to history
    attackVectorState.attackHistory.push({
        ...arc,
        timestamp: new Date().toISOString()
    });

    // Trim history
    if (attackVectorState.attackHistory.length > attackVectorState.maxHistory) {
        attackVectorState.attackHistory.shift();
    }

    // Update globe visualization
    updateAttackArcs();

    // Create impact effect at target
    if (attackVectorState.effectsEnabled) {
        setTimeout(() => {
            createImpactEffect(arc);
        }, arc.duration * 0.8);
    }

    // Auto-remove after animation
    setTimeout(() => {
        removeAttackArc(arc.id);
    }, arc.duration + 1000);

    return arc;
}

/**
 * Calculate arc animation duration based on distance
 */
function calculateArcDuration(source, target) {
    const lat1 = source.lat * Math.PI / 180;
    const lat2 = target.lat * Math.PI / 180;
    const dLng = (target.lng - source.lng) * Math.PI / 180;

    const d = Math.acos(
        Math.sin(lat1) * Math.sin(lat2) +
        Math.cos(lat1) * Math.cos(lat2) * Math.cos(dLng)
    );

    const distanceKm = d * 6371;

    // Duration: 1.5s to 4s based on distance
    return Math.min(4000, Math.max(1500, distanceKm / 2));
}

/**
 * Remove an attack arc
 */
function removeAttackArc(arcId) {
    attackVectorState.activeAttacks = attackVectorState.activeAttacks.filter(
        a => a.id !== arcId
    );
    updateAttackArcs();
}

/**
 * Update Globe.gl with current attack arcs
 */
function updateAttackArcs() {
    if (!window.globe) return;

    // Combine attack arcs with any existing mesh connections
    const arcs = attackVectorState.activeAttacks.map(attack => ({
        startLat: attack.source.lat,
        startLng: attack.source.lng,
        endLat: attack.target.lat,
        endLng: attack.target.lng,
        color: [attack.config.color, attack.config.glowColor],
        stroke: attack.config.arcWidth * (0.8 + attack.severity * 0.4),
        dashLength: attack.config.dashLength,
        dashGap: attack.config.dashGap,
        dashAnimateTime: attack.duration,
        altitude: calculateArcAltitude(attack.source, attack.target, attack.severity),
        label: createAttackLabel(attack)
    }));

    window.globe.arcsData(arcs);
}

/**
 * Calculate arc altitude based on distance and severity
 */
function calculateArcAltitude(source, target, severity) {
    const lat1 = source.lat * Math.PI / 180;
    const lat2 = target.lat * Math.PI / 180;
    const dLng = (target.lng - source.lng) * Math.PI / 180;

    const d = Math.acos(
        Math.sin(lat1) * Math.sin(lat2) +
        Math.cos(lat1) * Math.cos(lat2) * Math.cos(dLng)
    );

    const baseAltitude = Math.min(0.5, Math.max(0.15, d * 0.25));

    // Higher severity = slightly higher arc
    return baseAltitude * (1 + severity * 0.2);
}

/**
 * Create attack tooltip label
 */
function createAttackLabel(attack) {
    const config = attack.config;
    const typeConfig = ATTACK_TYPES[attack.attackType] || ATTACK_TYPES.unknown;

    return `
        <div class="attack-tooltip ${attack.type}">
            <div class="attack-header">
                <span class="attack-icon">${typeConfig.icon}</span>
                <span class="attack-type">${typeConfig.name}</span>
            </div>
            <div class="attack-source">
                <span class="label">Source:</span>
                <span class="value">${attack.source.label || attack.source.ip || 'Unknown'}</span>
            </div>
            <div class="attack-target">
                <span class="label">Target:</span>
                <span class="value">${attack.target.label || attack.target.node_id || 'Unknown'}</span>
            </div>
            <div class="attack-severity">
                <span class="label">Severity:</span>
                <span class="value severity-${getSeverityClass(attack.severity)}">${Math.round(attack.severity * 100)}%</span>
            </div>
            <div class="attack-status ${attack.type}">
                ${attack.type === 'repelled' ? '🛡️ REPELLED' : '⚠️ DETECTED'}
            </div>
        </div>
    `;
}

/**
 * Get severity class for styling
 */
function getSeverityClass(severity) {
    if (severity >= 0.8) return 'critical';
    if (severity >= 0.5) return 'high';
    if (severity >= 0.3) return 'medium';
    return 'low';
}

/**
 * Create impact effect at target location
 */
function createImpactEffect(attack) {
    const container = document.getElementById('attack-effects-layer');
    if (!container) return;

    // Calculate screen position (approximate)
    // In production, this would use globe.getScreenCoords()

    const effect = document.createElement('div');
    effect.className = `attack-impact ${attack.type} ${attack.attackType}`;

    // Create concentric rings
    for (let i = 0; i < 3; i++) {
        const ring = document.createElement('div');
        ring.className = 'impact-ring';
        ring.style.cssText = `
            position: absolute;
            inset: 0;
            border: 2px solid ${attack.config.color};
            border-radius: 50%;
            animation: impactRing 0.8s ease-out ${i * 0.15}s forwards;
        `;
        effect.appendChild(ring);
    }

    // Create particle burst
    const particleCount = attack.config.particleCount * attack.severity;
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        const angle = (i / particleCount) * Math.PI * 2;
        const distance = 30 + Math.random() * 50;

        particle.className = 'impact-particle';
        particle.style.cssText = `
            position: absolute;
            left: 50%;
            top: 50%;
            width: ${3 + Math.random() * 3}px;
            height: ${3 + Math.random() * 3}px;
            background: ${attack.config.color};
            border-radius: 50%;
            transform: translate(-50%, -50%);
            animation: impactParticle 0.6s ease-out forwards;
            --tx: ${Math.cos(angle) * distance}px;
            --ty: ${Math.sin(angle) * distance}px;
        `;
        effect.appendChild(particle);
    }

    // Create flash
    const flash = document.createElement('div');
    flash.className = 'impact-flash';
    flash.style.cssText = `
        position: absolute;
        inset: -20px;
        background: radial-gradient(circle, ${attack.config.glowColor} 0%, transparent 70%);
        animation: impactFlash 0.4s ease-out forwards;
    `;
    effect.appendChild(flash);

    container.appendChild(effect);

    // Cleanup
    setTimeout(() => effect.remove(), 1000);

    // Log event
    console.log(`Cortex: Impact effect at ${attack.target.lat?.toFixed(2)}, ${attack.target.lng?.toFixed(2)} (${attack.attackType})`);
}

/**
 * Create celebration effect for repelled attack
 */
function createRepelledCelebration(attack) {
    if (!attackVectorState.effectsEnabled) return;

    // Shield burst effect
    const container = document.getElementById('attack-effects-layer');
    if (!container) return;

    const celebration = document.createElement('div');
    celebration.className = 'repelled-celebration';

    // Shield icon
    const shield = document.createElement('div');
    shield.className = 'shield-burst';
    shield.innerHTML = '🛡️';
    celebration.appendChild(shield);

    // Success particles (blue/cyan)
    for (let i = 0; i < 15; i++) {
        const particle = document.createElement('div');
        const angle = (i / 15) * Math.PI * 2;
        particle.className = 'success-particle';
        particle.style.setProperty('--angle', `${angle}rad`);
        celebration.appendChild(particle);
    }

    container.appendChild(celebration);
    setTimeout(() => celebration.remove(), 1500);
}

/**
 * Get attack statistics
 */
function getAttackStats() {
    const now = Date.now();
    const oneHour = 60 * 60 * 1000;

    const recentAttacks = attackVectorState.attackHistory.filter(
        a => now - a.createdAt < oneHour
    );

    const byType = {};
    const byRepelled = { attacks: 0, repelled: 0 };

    recentAttacks.forEach(a => {
        // By type
        byType[a.attackType] = (byType[a.attackType] || 0) + 1;

        // By outcome
        if (a.type === 'repelled') {
            byRepelled.repelled++;
        } else {
            byRepelled.attacks++;
        }
    });

    return {
        total: recentAttacks.length,
        byType,
        ...byRepelled,
        repelRate: byRepelled.attacks > 0
            ? byRepelled.repelled / (byRepelled.attacks + byRepelled.repelled)
            : 1
    };
}

/**
 * Inject attack vector CSS styles
 */
function injectAttackVectorStyles() {
    if (document.getElementById('attack-vector-styles')) return;

    const style = document.createElement('style');
    style.id = 'attack-vector-styles';
    style.textContent = `
        #attack-effects-layer {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            pointer-events: none;
            z-index: 500;
            overflow: hidden;
        }

        .attack-tooltip {
            background: rgba(10, 12, 18, 0.95);
            border-radius: 8px;
            padding: 12px 16px;
            min-width: 180px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
        }

        .attack-tooltip.attack {
            border: 1px solid rgba(255, 68, 68, 0.5);
        }

        .attack-tooltip.repelled {
            border: 1px solid rgba(0, 191, 255, 0.5);
        }

        .attack-header {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .attack-icon {
            font-size: 18px;
        }

        .attack-type {
            font-family: 'Orbitron', monospace;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 1px;
        }

        .attack-tooltip.attack .attack-type {
            color: #ff4444;
        }

        .attack-tooltip.repelled .attack-type {
            color: #00bfff;
        }

        .attack-source, .attack-target, .attack-severity {
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            margin: 4px 0;
        }

        .attack-tooltip .label {
            color: #6a6a7a;
        }

        .attack-tooltip .value {
            color: #e8e8ec;
        }

        .severity-critical { color: #ff4444 !important; }
        .severity-high { color: #ff6b35 !important; }
        .severity-medium { color: #ffaa00 !important; }
        .severity-low { color: #00ff88 !important; }

        .attack-status {
            margin-top: 10px;
            padding-top: 8px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            text-align: center;
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 2px;
        }

        .attack-status.attack {
            color: #ff4444;
        }

        .attack-status.repelled {
            color: #00bfff;
        }

        /* Impact animations */
        @keyframes impactRing {
            0% { transform: scale(0.5); opacity: 1; }
            100% { transform: scale(2.5); opacity: 0; }
        }

        @keyframes impactParticle {
            0% { transform: translate(-50%, -50%) scale(1); opacity: 1; }
            100% { transform: translate(calc(-50% + var(--tx)), calc(-50% + var(--ty))) scale(0); opacity: 0; }
        }

        @keyframes impactFlash {
            0% { transform: scale(0.5); opacity: 0.8; }
            100% { transform: scale(2); opacity: 0; }
        }

        .attack-impact {
            position: absolute;
            width: 40px;
            height: 40px;
        }

        /* Repelled celebration */
        .repelled-celebration {
            position: absolute;
            width: 60px;
            height: 60px;
        }

        .shield-burst {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 24px;
            animation: shieldBurst 1s ease-out forwards;
        }

        @keyframes shieldBurst {
            0% { transform: translate(-50%, -50%) scale(0); opacity: 0; }
            30% { transform: translate(-50%, -50%) scale(1.5); opacity: 1; }
            100% { transform: translate(-50%, -50%) scale(2); opacity: 0; }
        }

        .success-particle {
            position: absolute;
            top: 50%;
            left: 50%;
            width: 6px;
            height: 6px;
            background: #00bfff;
            border-radius: 50%;
            animation: successParticle 1s ease-out forwards;
        }

        @keyframes successParticle {
            0% { transform: translate(-50%, -50%) translateX(0) translateY(0); opacity: 1; }
            100% { transform: translate(-50%, -50%) translateX(calc(cos(var(--angle)) * 50px)) translateY(calc(sin(var(--angle)) * 50px)); opacity: 0; }
        }
    `;

    document.head.appendChild(style);
}

/**
 * Initialize attack effects layer
 */
function initAttackEffects() {
    // Create effects layer if it doesn't exist
    if (!document.getElementById('attack-effects-layer')) {
        const layer = document.createElement('div');
        layer.id = 'attack-effects-layer';
        document.getElementById('app')?.appendChild(layer);
    }

    // Inject styles
    injectAttackVectorStyles();

    console.log('Cortex Attack Vectors initialized');
}

// Auto-initialize
if (document.readyState === 'complete') {
    initAttackEffects();
} else {
    window.addEventListener('load', initAttackEffects);
}

// Export functions
window.createAttackArc = createAttackArc;
window.removeAttackArc = removeAttackArc;
window.createImpactEffect = createImpactEffect;
window.createRepelledCelebration = createRepelledCelebration;
window.getAttackStats = getAttackStats;
window.attackVectorState = attackVectorState;
window.ATTACK_TYPES = ATTACK_TYPES;
