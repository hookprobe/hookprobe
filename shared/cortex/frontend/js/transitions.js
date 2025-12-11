/**
 * HookProbe Cortex - Transition Effects
 *
 * Smooth animations for cluster expand/collapse, node appearances,
 * and view transitions. Creates the premium feel of drilling into
 * the mesh from globe to city level.
 *
 * Features:
 * - Cluster explosion/implosion animations
 * - Node stagger animations
 * - Morph transitions between cluster and nodes
 * - Label fade animations
 * - Connection line animations
 */

// Animation configuration
const TRANSITION_CONFIG = {
    clusterExpand: {
        duration: 800,
        staggerDelay: 40,
        easing: 'easeOutBack',
        scaleFrom: 0.2,
        scaleTo: 1.0
    },
    clusterCollapse: {
        duration: 600,
        staggerDelay: 30,
        easing: 'easeInCubic'
    },
    nodeAppear: {
        duration: 400,
        easing: 'easeOutQuad'
    },
    labelFade: {
        duration: 300,
        delay: 200
    },
    morphTransition: {
        duration: 500,
        easing: 'easeInOutCubic'
    }
};

/**
 * TransitionManager - Coordinates visual transitions
 */
class TransitionManager {
    constructor(globe, clusterManager) {
        this.globe = globe;
        this.clusterManager = clusterManager;

        // Active animations tracking
        this.activeAnimations = new Map();
        this.animationQueue = [];

        // Transition state
        this.isTransitioning = false;
        this.currentTransition = null;

        // Event listeners
        this.eventListeners = new Map();

        // DOM overlay for transition effects
        this.overlay = this._createOverlay();
    }

    /**
     * Create transition overlay element
     * @private
     */
    _createOverlay() {
        let overlay = document.getElementById('transition-overlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'transition-overlay';
            overlay.className = 'cortex-transition-overlay';
            overlay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                pointer-events: none;
                z-index: 1000;
                overflow: hidden;
            `;
            document.body.appendChild(overlay);
        }
        return overlay;
    }

    /**
     * Animate cluster expansion (drill-down)
     * @param {Object} cluster - Cluster being expanded
     * @param {Array} nodes - Child nodes being revealed
     * @param {Object} options - Animation options
     * @returns {Promise}
     */
    async expandCluster(cluster, nodes, options = {}) {
        const config = { ...TRANSITION_CONFIG.clusterExpand, ...options };

        this.isTransitioning = true;
        this._emit('transitionStart', { type: 'expand', cluster, nodes });

        // Get cluster screen position
        const clusterPos = this._getScreenPosition(cluster.lat, cluster.lng);

        // Create particle explosion from cluster center
        this._createExplosionParticles(clusterPos, nodes.length);

        // Animate each node appearing from cluster center
        const nodeAnimations = nodes.map((node, index) => {
            return new Promise(resolve => {
                const delay = index * config.staggerDelay;

                setTimeout(() => {
                    this._animateNodeAppear(node, clusterPos, config)
                        .then(resolve);
                }, delay);
            });
        });

        // Create pulsing ring at cluster location
        this._createExpandRing(clusterPos, config.duration);

        await Promise.all(nodeAnimations);

        this.isTransitioning = false;
        this._emit('transitionComplete', { type: 'expand', cluster, nodes });
    }

    /**
     * Animate cluster collapse (zoom out)
     * @param {Array} nodes - Nodes being collapsed
     * @param {Object} cluster - Target cluster
     * @param {Object} options - Animation options
     * @returns {Promise}
     */
    async collapseCluster(nodes, cluster, options = {}) {
        const config = { ...TRANSITION_CONFIG.clusterCollapse, ...options };

        this.isTransitioning = true;
        this._emit('transitionStart', { type: 'collapse', cluster, nodes });

        // Get cluster screen position
        const clusterPos = this._getScreenPosition(cluster.lat, cluster.lng);

        // Animate each node disappearing into cluster center
        const nodeAnimations = nodes.map((node, index) => {
            return new Promise(resolve => {
                const delay = index * config.staggerDelay;

                setTimeout(() => {
                    this._animateNodeDisappear(node, clusterPos, config)
                        .then(resolve);
                }, delay);
            });
        });

        await Promise.all(nodeAnimations);

        // Create implosion effect
        this._createImplosionEffect(clusterPos);

        this.isTransitioning = false;
        this._emit('transitionComplete', { type: 'collapse', cluster, nodes });
    }

    /**
     * Animate a single node appearing
     * @private
     */
    _animateNodeAppear(node, fromPos, config) {
        return new Promise(resolve => {
            const toPos = this._getScreenPosition(node.lat, node.lng);

            // Create temporary visual element for animation
            const el = document.createElement('div');
            el.className = 'cortex-node-transition';
            el.style.cssText = `
                position: fixed;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                background: ${this._getNodeColor(node)};
                box-shadow: 0 0 10px ${this._getNodeColor(node)};
                left: ${fromPos.x}px;
                top: ${fromPos.y}px;
                transform: scale(${config.scaleFrom});
                opacity: 0;
                z-index: 1001;
                pointer-events: none;
            `;
            this.overlay.appendChild(el);

            // Animate from cluster to node position
            const startTime = Date.now();

            const animate = () => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(1, elapsed / config.duration);
                const eased = EASING[config.easing](progress);

                // Position
                const x = fromPos.x + (toPos.x - fromPos.x) * eased;
                const y = fromPos.y + (toPos.y - fromPos.y) * eased;

                // Scale and opacity
                const scale = config.scaleFrom + (config.scaleTo - config.scaleFrom) * eased;
                const opacity = eased;

                el.style.left = `${x}px`;
                el.style.top = `${y}px`;
                el.style.transform = `scale(${scale})`;
                el.style.opacity = opacity;

                if (progress < 1) {
                    requestAnimationFrame(animate);
                } else {
                    // Remove transition element
                    setTimeout(() => el.remove(), 100);
                    resolve();
                }
            };

            requestAnimationFrame(animate);
        });
    }

    /**
     * Animate a single node disappearing
     * @private
     */
    _animateNodeDisappear(node, toPos, config) {
        return new Promise(resolve => {
            const fromPos = this._getScreenPosition(node.lat, node.lng);

            const el = document.createElement('div');
            el.className = 'cortex-node-transition';
            el.style.cssText = `
                position: fixed;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                background: ${this._getNodeColor(node)};
                box-shadow: 0 0 10px ${this._getNodeColor(node)};
                left: ${fromPos.x}px;
                top: ${fromPos.y}px;
                transform: scale(1);
                opacity: 1;
                z-index: 1001;
                pointer-events: none;
            `;
            this.overlay.appendChild(el);

            const startTime = Date.now();

            const animate = () => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(1, elapsed / config.duration);
                const eased = EASING[config.easing](progress);

                const x = fromPos.x + (toPos.x - fromPos.x) * eased;
                const y = fromPos.y + (toPos.y - fromPos.y) * eased;
                const scale = 1 - (0.8 * eased);
                const opacity = 1 - eased;

                el.style.left = `${x}px`;
                el.style.top = `${y}px`;
                el.style.transform = `scale(${scale})`;
                el.style.opacity = opacity;

                if (progress < 1) {
                    requestAnimationFrame(animate);
                } else {
                    el.remove();
                    resolve();
                }
            };

            requestAnimationFrame(animate);
        });
    }

    /**
     * Create explosion particles effect
     * @private
     */
    _createExplosionParticles(pos, count) {
        const particleCount = Math.min(30, count + 5);

        for (let i = 0; i < particleCount; i++) {
            const particle = document.createElement('div');
            const angle = (i / particleCount) * Math.PI * 2;
            const distance = 50 + Math.random() * 80;
            const duration = 600 + Math.random() * 400;
            const size = 3 + Math.random() * 4;

            particle.className = 'cortex-particle';
            particle.style.cssText = `
                position: fixed;
                width: ${size}px;
                height: ${size}px;
                border-radius: 50%;
                background: #00bfff;
                left: ${pos.x}px;
                top: ${pos.y}px;
                z-index: 1002;
                pointer-events: none;
            `;
            this.overlay.appendChild(particle);

            // Animate particle outward
            const startTime = Date.now();
            const targetX = pos.x + Math.cos(angle) * distance;
            const targetY = pos.y + Math.sin(angle) * distance;

            const animate = () => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(1, elapsed / duration);
                const eased = EASING.easeOutQuad(progress);

                const x = pos.x + (targetX - pos.x) * eased;
                const y = pos.y + (targetY - pos.y) * eased;
                const opacity = 1 - eased;
                const scale = 1 - (0.5 * eased);

                particle.style.left = `${x}px`;
                particle.style.top = `${y}px`;
                particle.style.opacity = opacity;
                particle.style.transform = `scale(${scale})`;

                if (progress < 1) {
                    requestAnimationFrame(animate);
                } else {
                    particle.remove();
                }
            };

            requestAnimationFrame(animate);
        }
    }

    /**
     * Create expanding ring effect
     * @private
     */
    _createExpandRing(pos, duration) {
        for (let i = 0; i < 3; i++) {
            const ring = document.createElement('div');
            ring.className = 'cortex-expand-ring';
            ring.style.cssText = `
                position: fixed;
                width: 20px;
                height: 20px;
                border: 2px solid #00bfff;
                border-radius: 50%;
                left: ${pos.x - 10}px;
                top: ${pos.y - 10}px;
                z-index: 1001;
                pointer-events: none;
                opacity: 0.8;
            `;
            this.overlay.appendChild(ring);

            const delay = i * 150;
            const ringDuration = duration + 200;

            setTimeout(() => {
                const startTime = Date.now();

                const animate = () => {
                    const elapsed = Date.now() - startTime;
                    const progress = Math.min(1, elapsed / ringDuration);
                    const eased = EASING.easeOutQuad(progress);

                    const scale = 1 + (5 * eased);
                    const opacity = 0.8 * (1 - eased);

                    ring.style.transform = `scale(${scale})`;
                    ring.style.opacity = opacity;

                    if (progress < 1) {
                        requestAnimationFrame(animate);
                    } else {
                        ring.remove();
                    }
                };

                requestAnimationFrame(animate);
            }, delay);
        }
    }

    /**
     * Create implosion effect for collapse
     * @private
     */
    _createImplosionEffect(pos) {
        // Inward-moving particles
        for (let i = 0; i < 20; i++) {
            const particle = document.createElement('div');
            const angle = (i / 20) * Math.PI * 2;
            const startDistance = 80 + Math.random() * 40;
            const duration = 400 + Math.random() * 200;
            const size = 3 + Math.random() * 3;

            const startX = pos.x + Math.cos(angle) * startDistance;
            const startY = pos.y + Math.sin(angle) * startDistance;

            particle.style.cssText = `
                position: fixed;
                width: ${size}px;
                height: ${size}px;
                border-radius: 50%;
                background: #00ff88;
                left: ${startX}px;
                top: ${startY}px;
                z-index: 1002;
                pointer-events: none;
            `;
            this.overlay.appendChild(particle);

            const startTime = Date.now();

            const animate = () => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(1, elapsed / duration);
                const eased = EASING.easeInCubic(progress);

                const x = startX + (pos.x - startX) * eased;
                const y = startY + (pos.y - startY) * eased;
                const opacity = 1 - (0.3 * eased);
                const scale = 1 + (0.5 * eased);

                particle.style.left = `${x}px`;
                particle.style.top = `${y}px`;
                particle.style.opacity = opacity;
                particle.style.transform = `scale(${scale})`;

                if (progress < 1) {
                    requestAnimationFrame(animate);
                } else {
                    particle.remove();
                }
            };

            requestAnimationFrame(animate);
        }

        // Central flash
        const flash = document.createElement('div');
        flash.style.cssText = `
            position: fixed;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            background: radial-gradient(circle, #ffffff 0%, #00ff88 50%, transparent 70%);
            left: ${pos.x - 15}px;
            top: ${pos.y - 15}px;
            z-index: 1003;
            pointer-events: none;
        `;
        this.overlay.appendChild(flash);

        const flashStart = Date.now();
        const flashDuration = 300;

        const animateFlash = () => {
            const elapsed = Date.now() - flashStart;
            const progress = Math.min(1, elapsed / flashDuration);

            const scale = 1 + (2 * progress);
            const opacity = 1 - progress;

            flash.style.transform = `scale(${scale})`;
            flash.style.opacity = opacity;

            if (progress < 1) {
                requestAnimationFrame(animateFlash);
            } else {
                flash.remove();
            }
        };

        requestAnimationFrame(animateFlash);
    }

    /**
     * Create morph transition between views
     * @param {string} fromView - Source view type
     * @param {string} toView - Target view type
     * @param {Object} options - Transition options
     * @returns {Promise}
     */
    async morphTransition(fromView, toView, options = {}) {
        const config = { ...TRANSITION_CONFIG.morphTransition, ...options };

        this.isTransitioning = true;
        this._emit('morphStart', { fromView, toView });

        // Create overlay effect
        const morphOverlay = document.createElement('div');
        morphOverlay.className = 'cortex-morph-overlay';
        morphOverlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: radial-gradient(circle at center, transparent 0%, rgba(0,0,0,0.3) 100%);
            z-index: 999;
            pointer-events: none;
            opacity: 0;
        `;
        document.body.appendChild(morphOverlay);

        // Animate overlay
        await new Promise(resolve => {
            const startTime = Date.now();
            const animate = () => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(1, elapsed / (config.duration / 2));

                if (progress < 1) {
                    morphOverlay.style.opacity = progress * 0.5;
                    requestAnimationFrame(animate);
                } else {
                    // Fade out
                    const fadeStart = Date.now();
                    const fadeOut = () => {
                        const fadeElapsed = Date.now() - fadeStart;
                        const fadeProgress = Math.min(1, fadeElapsed / (config.duration / 2));
                        morphOverlay.style.opacity = 0.5 * (1 - fadeProgress);

                        if (fadeProgress < 1) {
                            requestAnimationFrame(fadeOut);
                        } else {
                            morphOverlay.remove();
                            resolve();
                        }
                    };
                    requestAnimationFrame(fadeOut);
                }
            };
            requestAnimationFrame(animate);
        });

        this.isTransitioning = false;
        this._emit('morphComplete', { fromView, toView });
    }

    /**
     * Animate labels appearing with stagger
     * @param {Array} nodes - Nodes to show labels for
     * @returns {Promise}
     */
    async showLabels(nodes) {
        const config = TRANSITION_CONFIG.labelFade;

        await new Promise(resolve => {
            nodes.forEach((node, index) => {
                setTimeout(() => {
                    this._emit('showLabel', { node, index });
                    if (index === nodes.length - 1) {
                        setTimeout(resolve, config.duration);
                    }
                }, config.delay + (index * 50));
            });
        });
    }

    /**
     * Get screen position from lat/lng
     * @private
     */
    _getScreenPosition(lat, lng) {
        if (!this.globe) {
            return { x: window.innerWidth / 2, y: window.innerHeight / 2 };
        }

        // Get globe's Three.js scene
        const globeScene = this.globe.scene();
        const globeCamera = this.globe.camera();

        if (!globeScene || !globeCamera) {
            return { x: window.innerWidth / 2, y: window.innerHeight / 2 };
        }

        // Convert lat/lng to 3D coordinates
        const phi = (90 - lat) * (Math.PI / 180);
        const theta = (lng + 180) * (Math.PI / 180);

        const radius = 100; // Globe radius in Three.js units
        const x = -(radius * Math.sin(phi) * Math.cos(theta));
        const y = radius * Math.cos(phi);
        const z = radius * Math.sin(phi) * Math.sin(theta);

        // Create vector and project to screen
        const vector = new THREE.Vector3(x, y, z);
        vector.project(globeCamera);

        // Convert to screen coordinates
        const screenX = (vector.x + 1) / 2 * window.innerWidth;
        const screenY = -(vector.y - 1) / 2 * window.innerHeight;

        return { x: screenX, y: screenY };
    }

    /**
     * Get node color based on status
     * @private
     */
    _getNodeColor(node) {
        const colors = {
            green: '#00ff88',
            amber: '#ffaa00',
            red: '#ff4444'
        };
        return colors[node.status] || colors.green;
    }

    /**
     * Add event listener
     */
    on(event, callback) {
        if (!this.eventListeners.has(event)) {
            this.eventListeners.set(event, []);
        }
        this.eventListeners.get(event).push(callback);
    }

    /**
     * Remove event listener
     */
    off(event, callback) {
        if (!this.eventListeners.has(event)) return;
        const listeners = this.eventListeners.get(event);
        const index = listeners.indexOf(callback);
        if (index > -1) listeners.splice(index, 1);
    }

    /**
     * Emit event
     * @private
     */
    _emit(event, data) {
        if (!this.eventListeners.has(event)) return;
        this.eventListeners.get(event).forEach(callback => {
            try {
                callback(data);
            } catch (e) {
                console.error(`Error in ${event} listener:`, e);
            }
        });
    }

    /**
     * Cleanup
     */
    destroy() {
        this.overlay.remove();
        this.activeAnimations.clear();
        this.eventListeners.clear();
    }
}

/**
 * Helper: Animate value over time
 * @param {number} from - Start value
 * @param {number} to - End value
 * @param {number} duration - Duration in ms
 * @param {string} easing - Easing function name
 * @param {Function} onUpdate - Called with current value
 * @returns {Promise}
 */
function animateValue(from, to, duration, easing, onUpdate) {
    return new Promise(resolve => {
        const startTime = Date.now();
        const easingFn = EASING[easing] || EASING.linear;

        const animate = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(1, elapsed / duration);
            const eased = easingFn(progress);
            const value = from + (to - from) * eased;

            onUpdate(value, progress);

            if (progress < 1) {
                requestAnimationFrame(animate);
            } else {
                resolve();
            }
        };

        requestAnimationFrame(animate);
    });
}

// Export for use in other modules
window.TransitionManager = TransitionManager;
window.animateValue = animateValue;
window.TRANSITION_CONFIG = TRANSITION_CONFIG;
