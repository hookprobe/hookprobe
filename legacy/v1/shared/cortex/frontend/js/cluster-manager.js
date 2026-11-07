/**
 * HookProbe Cortex - Cluster Manager
 *
 * Smart clustering system for zoom-responsive node visualization.
 * Uses Supercluster for efficient spatial indexing and clustering.
 *
 * Features:
 * - Dynamic clustering based on zoom level
 * - Aggregate statistics for clusters (avg Qsecbit, node counts by tier)
 * - Smooth expand/collapse animations
 * - Click-to-drill-down functionality
 */

// Cluster configuration
const CLUSTER_CONFIG = {
    // Clustering radius in pixels at zoom level 0
    radius: 60,
    // Maximum zoom level to cluster at
    maxZoom: 16,
    // Minimum points to form a cluster
    minPoints: 2,
    // Extent of the tile (for internal calculations)
    extent: 512,
    // Size of the tile grid used for clustering
    nodeSize: 64
};

// Zoom level thresholds (altitude-based for Globe.gl)
const ZOOM_LEVELS = {
    GLOBAL: { altitude: 2.5, zoom: 2, label: 'Global', clusterRadius: 80 },
    CONTINENTAL: { altitude: 1.5, zoom: 4, label: 'Continental', clusterRadius: 60 },
    REGIONAL: { altitude: 0.8, zoom: 6, label: 'Regional', clusterRadius: 40 },
    CITY: { altitude: 0.3, zoom: 10, label: 'City', clusterRadius: 20 },
    STREET: { altitude: 0.1, zoom: 14, label: 'Street', clusterRadius: 0 }
};

/**
 * ClusterManager - Manages spatial clustering of mesh nodes
 */
class ClusterManager {
    constructor(options = {}) {
        this.config = { ...CLUSTER_CONFIG, ...options };
        this.index = null;
        this.rawNodes = [];
        this.currentZoom = 2;
        this.currentClusters = [];
        this.clusterCache = new Map();
        this.eventListeners = new Map();

        // Initialize Supercluster when library is loaded
        this._initSupercluster();
    }

    /**
     * Initialize Supercluster index
     */
    _initSupercluster() {
        if (typeof Supercluster === 'undefined') {
            console.warn('Supercluster not loaded, clustering disabled');
            return;
        }

        this.index = new Supercluster({
            radius: this.config.radius,
            maxZoom: this.config.maxZoom,
            minPoints: this.config.minPoints,
            extent: this.config.extent,
            nodeSize: this.config.nodeSize,
            // Custom reduce function to aggregate cluster properties
            map: (props) => ({
                tier: props.tier,
                qsecbit: props.qsecbit || 0,
                status: props.status || 'green',
                label: props.label,
                id: props.id,
                online: props.online !== false
            }),
            reduce: (accumulated, props) => {
                // Count nodes by tier
                accumulated.tierCounts = accumulated.tierCounts || {
                    sentinel: 0, guardian: 0, fortress: 0, nexus: 0
                };
                const tier = (props.tier || 'sentinel').toLowerCase();
                if (accumulated.tierCounts[tier] !== undefined) {
                    accumulated.tierCounts[tier]++;
                }

                // Track Qsecbit values for averaging
                accumulated.qsecbitSum = (accumulated.qsecbitSum || 0) + (props.qsecbit || 0);
                accumulated.qsecbitCount = (accumulated.qsecbitCount || 0) + 1;

                // Track worst status
                const statusPriority = { red: 3, amber: 2, green: 1 };
                const currentPriority = statusPriority[accumulated.worstStatus] || 0;
                const newPriority = statusPriority[props.status] || 1;
                if (newPriority > currentPriority) {
                    accumulated.worstStatus = props.status;
                }

                // Track online count
                accumulated.onlineCount = (accumulated.onlineCount || 0) + (props.online ? 1 : 0);
            }
        });
    }

    /**
     * Load nodes into the spatial index
     * @param {Array} nodes - Array of node objects with lat, lng, and properties
     */
    load(nodes) {
        if (!this.index) {
            console.warn('[ClusterManager] Supercluster not initialized, using raw nodes');
            this.rawNodes = nodes;
            // Still emit loaded event for compatibility
            this._emit('loaded', { nodeCount: nodes.length });
            return;
        }

        this.rawNodes = nodes;
        this.clusterCache.clear();

        // Convert nodes to GeoJSON features
        const features = nodes.map(node => ({
            type: 'Feature',
            properties: {
                id: node.id,
                tier: node.tier,
                qsecbit: node.qsecbit,
                status: node.status,
                label: node.label,
                online: node.online,
                resonance: node.resonance
            },
            geometry: {
                type: 'Point',
                coordinates: [node.lng, node.lat]
            }
        }));

        this.index.load(features);
        this._emit('loaded', { nodeCount: nodes.length });
    }

    /**
     * Get clusters/nodes for the current viewport and zoom
     * @param {Object} bounds - { west, south, east, north }
     * @param {number} zoom - Current zoom level (0-20)
     * @returns {Array} Array of clusters and individual nodes
     */
    getClusters(bounds, zoom) {
        if (!this.index) {
            // Return raw nodes with type property for compatibility
            return this.rawNodes.map(node => ({
                ...node,
                type: 'node'
            }));
        }

        // Return empty array if no data has been loaded yet
        if (this.rawNodes.length === 0) {
            return [];
        }

        this.currentZoom = zoom;
        const bbox = [bounds.west, bounds.south, bounds.east, bounds.north];
        const clusters = this.index.getClusters(bbox, Math.floor(zoom));

        // Transform clusters for visualization
        this.currentClusters = clusters.map(feature => {
            const coords = feature.geometry.coordinates;
            const props = feature.properties;

            if (props.cluster) {
                // This is a cluster
                const leaves = this.index.getLeaves(props.cluster_id, Infinity);
                const avgQsecbit = props.qsecbitSum / props.qsecbitCount;

                return {
                    type: 'cluster',
                    id: `cluster-${props.cluster_id}`,
                    clusterId: props.cluster_id,
                    lng: coords[0],
                    lat: coords[1],
                    count: props.point_count,
                    tierCounts: props.tierCounts || this._countTiers(leaves),
                    avgQsecbit: avgQsecbit,
                    worstStatus: props.worstStatus || this._getWorstStatus(leaves),
                    onlineCount: props.onlineCount || leaves.filter(l => l.properties.online).length,
                    expansionZoom: this.index.getClusterExpansionZoom(props.cluster_id),
                    leaves: leaves
                };
            } else {
                // This is an individual node
                return {
                    type: 'node',
                    id: props.id,
                    lng: coords[0],
                    lat: coords[1],
                    tier: props.tier,
                    qsecbit: props.qsecbit,
                    status: props.status,
                    label: props.label,
                    online: props.online,
                    resonance: props.resonance
                };
            }
        });

        this._emit('clustersUpdated', {
            clusters: this.currentClusters,
            zoom: zoom,
            totalClusters: this.currentClusters.filter(c => c.type === 'cluster').length,
            totalNodes: this.currentClusters.filter(c => c.type === 'node').length
        });

        return this.currentClusters;
    }

    /**
     * Get all clusters/nodes for the entire world at given zoom
     * @param {number} zoom - Zoom level
     * @returns {Array} Array of clusters and individual nodes
     */
    getAllClusters(zoom) {
        return this.getClusters({ west: -180, south: -90, east: 180, north: 90 }, zoom);
    }

    /**
     * Get the zoom level needed to expand a cluster
     * @param {number} clusterId - Cluster ID
     * @returns {number} Zoom level for expansion
     */
    getClusterExpansionZoom(clusterId) {
        if (!this.index) return 16;
        return this.index.getClusterExpansionZoom(clusterId);
    }

    /**
     * Get all leaf nodes of a cluster
     * @param {number} clusterId - Cluster ID
     * @param {number} limit - Maximum number of leaves to return
     * @returns {Array} Array of node features
     */
    getClusterLeaves(clusterId, limit = Infinity) {
        if (!this.index) return [];
        return this.index.getLeaves(clusterId, limit);
    }

    /**
     * Get cluster details by ID
     * @param {number} clusterId - Cluster ID
     * @returns {Object|null} Cluster details
     */
    getClusterDetails(clusterId) {
        const cluster = this.currentClusters.find(
            c => c.type === 'cluster' && c.clusterId === clusterId
        );

        if (!cluster) return null;

        const leaves = this.getClusterLeaves(clusterId);

        return {
            ...cluster,
            nodes: leaves.map(l => ({
                id: l.properties.id,
                tier: l.properties.tier,
                label: l.properties.label,
                qsecbit: l.properties.qsecbit,
                status: l.properties.status,
                lat: l.geometry.coordinates[1],
                lng: l.geometry.coordinates[0]
            }))
        };
    }

    /**
     * Convert Globe.gl altitude to zoom level
     * @param {number} altitude - Globe altitude (camera distance)
     * @returns {number} Approximate zoom level
     */
    altitudeToZoom(altitude) {
        // Approximate conversion: altitude 2.5 ≈ zoom 2, altitude 0.1 ≈ zoom 14
        const zoom = Math.max(0, Math.min(20, 14 - Math.log2(altitude * 10)));
        return zoom;
    }

    /**
     * Convert zoom level to Globe.gl altitude
     * @param {number} zoom - Zoom level
     * @returns {number} Globe altitude
     */
    zoomToAltitude(zoom) {
        return Math.pow(2, 14 - zoom) / 10;
    }

    /**
     * Get current zoom level category
     * @param {number} altitude - Globe altitude
     * @returns {Object} Zoom level info { name, label, clusterRadius }
     */
    getZoomLevelInfo(altitude) {
        for (const [name, config] of Object.entries(ZOOM_LEVELS)) {
            if (altitude >= config.altitude) {
                return { name, ...config };
            }
        }
        return { name: 'STREET', ...ZOOM_LEVELS.STREET };
    }

    /**
     * Count nodes by tier from leaves
     * @private
     */
    _countTiers(leaves) {
        const counts = { sentinel: 0, guardian: 0, fortress: 0, nexus: 0 };
        leaves.forEach(leaf => {
            const tier = (leaf.properties.tier || 'sentinel').toLowerCase();
            if (counts[tier] !== undefined) counts[tier]++;
        });
        return counts;
    }

    /**
     * Get worst status from leaves
     * @private
     */
    _getWorstStatus(leaves) {
        const statusPriority = { red: 3, amber: 2, green: 1 };
        let worst = 'green';
        let worstPriority = 1;

        leaves.forEach(leaf => {
            const status = leaf.properties.status || 'green';
            const priority = statusPriority[status] || 1;
            if (priority > worstPriority) {
                worst = status;
                worstPriority = priority;
            }
        });

        return worst;
    }

    /**
     * Add event listener
     * @param {string} event - Event name
     * @param {Function} callback - Callback function
     */
    on(event, callback) {
        if (!this.eventListeners.has(event)) {
            this.eventListeners.set(event, []);
        }
        this.eventListeners.get(event).push(callback);
    }

    /**
     * Remove event listener
     * @param {string} event - Event name
     * @param {Function} callback - Callback function
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
     * Get statistics about current clustering state
     * @returns {Object} Clustering statistics
     */
    getStats() {
        return {
            totalRawNodes: this.rawNodes.length,
            currentZoom: this.currentZoom,
            visibleClusters: this.currentClusters.filter(c => c.type === 'cluster').length,
            visibleNodes: this.currentClusters.filter(c => c.type === 'node').length,
            clusteringEnabled: !!this.index
        };
    }
}

/**
 * Cluster visual properties calculator
 * Determines how clusters should be rendered based on their properties
 */
class ClusterVisuals {
    constructor() {
        // Base sizes for cluster indicators
        this.baseSizes = {
            small: 0.8,    // 2-5 nodes
            medium: 1.2,   // 6-15 nodes
            large: 1.6,    // 16-50 nodes
            huge: 2.2      // 50+ nodes
        };

        // Colors by worst status in cluster
        this.statusColors = {
            green: '#00ff88',
            amber: '#ffaa00',
            red: '#ff4444'
        };

        // Tier indicator colors (for pie chart segments)
        this.tierColors = {
            sentinel: '#888888',
            guardian: '#00bfff',
            fortress: '#00ff88',
            nexus: '#ffaa00'
        };
    }

    /**
     * Calculate visual properties for a cluster
     * @param {Object} cluster - Cluster data
     * @returns {Object} Visual properties
     */
    getClusterVisuals(cluster) {
        const count = cluster.count;

        // Determine size category
        let sizeKey = 'small';
        if (count > 50) sizeKey = 'huge';
        else if (count > 15) sizeKey = 'large';
        else if (count > 5) sizeKey = 'medium';

        const baseSize = this.baseSizes[sizeKey];

        // Color based on worst status
        const color = this.statusColors[cluster.worstStatus] || this.statusColors.green;

        // Pulse speed based on status (critical = faster)
        const pulseSpeed = cluster.worstStatus === 'red' ? 2 :
                          cluster.worstStatus === 'amber' ? 1.5 : 1;

        // Tier distribution for potential pie visualization
        const tierDistribution = cluster.tierCounts;

        // Glow intensity based on node count
        const glowIntensity = Math.min(1, count / 30);

        return {
            size: baseSize,
            color,
            pulseSpeed,
            tierDistribution,
            glowIntensity,
            label: this._formatLabel(cluster),
            badge: count.toString(),
            alpha: Math.min(0.9, 0.5 + (count / 100)),
            ringCount: Math.min(3, Math.floor(count / 10))
        };
    }

    /**
     * Format cluster label for tooltip
     * @private
     */
    _formatLabel(cluster) {
        const tiers = cluster.tierCounts;
        const parts = [];

        if (tiers.nexus) parts.push(`${tiers.nexus} Nexus`);
        if (tiers.fortress) parts.push(`${tiers.fortress} Fortress`);
        if (tiers.guardian) parts.push(`${tiers.guardian} Guardian`);
        if (tiers.sentinel) parts.push(`${tiers.sentinel} Sentinel`);

        return `
            <div class="cluster-tooltip">
                <div class="cluster-count">${cluster.count} Nodes</div>
                <div class="cluster-tiers">${parts.join(' · ')}</div>
                <div class="cluster-qsecbit">Avg Qsecbit: ${cluster.avgQsecbit.toFixed(3)}</div>
                <div class="cluster-status ${cluster.worstStatus}">Status: ${cluster.worstStatus.toUpperCase()}</div>
                <div class="cluster-hint">Click to zoom</div>
            </div>
        `;
    }

    /**
     * Get node visual properties (for individual nodes)
     * @param {Object} node - Node data
     * @returns {Object} Visual properties
     */
    getNodeVisuals(node) {
        const tierSizes = {
            sentinel: 0.3,
            guardian: 0.5,
            fortress: 0.8,
            nexus: 1.2
        };

        return {
            size: tierSizes[node.tier] || 0.5,
            color: this.statusColors[node.status] || this.statusColors.green,
            label: `${node.label}<br/>Qsecbit: ${(node.qsecbit || 0).toFixed(3)}`
        };
    }
}

// Export for use in other modules
window.ClusterManager = ClusterManager;
window.ClusterVisuals = ClusterVisuals;
window.ZOOM_LEVELS = ZOOM_LEVELS;
window.CLUSTER_CONFIG = CLUSTER_CONFIG;
