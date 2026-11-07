/**
 * City View Enhancements for Cortex
 *
 * Phase 2: City-level visualization features including:
 * - Building highlighting around nodes
 * - Street-level node popups
 * - Neighborhood statistics
 * - Mini-map overview
 * - Node search and filtering
 */

'use strict';

// =============================================================================
// CITY VIEW CONFIGURATION
// =============================================================================

const CITY_VIEW_CONFIG = {
    // Building highlight radius (meters)
    buildingHighlightRadius: 200,

    // Node info popup settings
    popupOffset: [0, -20],
    popupMaxWidth: 280,

    // Mini-map settings
    miniMapSize: 150,
    miniMapZoomOffset: -4,

    // Animation settings
    pulseAnimationDuration: 2000,
    highlightFadeInDuration: 300,

    // Clustering at city level
    cityLevelClusterRadius: 30,  // pixels
    minZoomForLabels: 12
};

// =============================================================================
// CITY VIEW CONTROLLER
// =============================================================================

class CityViewController {
    constructor(viewManager, options = {}) {
        this.viewManager = viewManager;
        this.config = { ...CITY_VIEW_CONFIG, ...options };

        // State
        this.selectedNode = null;
        this.highlightedNodes = new Set();
        this.neighborhoodStats = {};

        // UI elements
        this.popup = null;
        this.miniMap = null;
        this.searchInput = null;
        this.filterPanel = null;

        // Event handlers
        this._boundHandlers = {
            onNodeClick: this._onNodeClick.bind(this),
            onMapClick: this._onMapClick.bind(this),
            onKeyDown: this._onKeyDown.bind(this)
        };

        this._init();
    }

    _init() {
        // Create UI components
        this._createPopup();
        this._createMiniMap();
        this._createSearchBar();
        this._createFilterPanel();

        // Setup event listeners
        this._setupEventListeners();

        console.log('CityViewController: Initialized');
    }

    /**
     * Setup event listeners
     */
    _setupEventListeners() {
        // Listen for view mode changes
        if (this.viewManager) {
            this.viewManager.on('modeChange', (data) => {
                if (data.mode === 'map') {
                    this._onEnterCityView();
                } else {
                    this._onExitCityView();
                }
            });
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', this._boundHandlers.onKeyDown);
    }

    /**
     * Called when entering city (map) view
     */
    _onEnterCityView() {
        this._showCityUI();
        this._updateNeighborhoodStats();
    }

    /**
     * Called when exiting city view
     */
    _onExitCityView() {
        this._hideCityUI();
        this._clearSelection();
    }

    // =========================================================================
    // POPUP COMPONENT
    // =========================================================================

    _createPopup() {
        this.popup = document.createElement('div');
        this.popup.id = 'city-node-popup';
        this.popup.className = 'cortex-city-popup';
        this.popup.style.display = 'none';
        this.popup.innerHTML = `
            <div class="popup-header">
                <span class="popup-tier"></span>
                <span class="popup-title"></span>
                <button class="popup-close">&times;</button>
            </div>
            <div class="popup-body">
                <div class="popup-stats">
                    <div class="stat-item">
                        <span class="stat-label">Qsecbit</span>
                        <span class="stat-value qsecbit-value">--</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Status</span>
                        <span class="stat-value status-value">--</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Online</span>
                        <span class="stat-value online-value">--</span>
                    </div>
                </div>
                <div class="popup-location">
                    <span class="location-icon">&#128205;</span>
                    <span class="location-text"></span>
                </div>
                <div class="popup-actions">
                    <button class="action-btn focus-btn">Focus</button>
                    <button class="action-btn details-btn">Details</button>
                </div>
            </div>
        `;

        document.body.appendChild(this.popup);

        // Close button handler
        this.popup.querySelector('.popup-close').addEventListener('click', () => {
            this.hidePopup();
        });

        // Action button handlers
        this.popup.querySelector('.focus-btn').addEventListener('click', () => {
            if (this.selectedNode) {
                this._focusOnNode(this.selectedNode);
            }
        });

        this.popup.querySelector('.details-btn').addEventListener('click', () => {
            if (this.selectedNode) {
                this._showNodeDetails(this.selectedNode);
            }
        });
    }

    showPopup(node, screenPosition) {
        if (!this.popup || !node) return;

        this.selectedNode = node;

        // Update content
        const tierEl = this.popup.querySelector('.popup-tier');
        tierEl.textContent = (node.tier || 'unknown').toUpperCase();
        tierEl.className = `popup-tier tier-${node.tier}`;

        this.popup.querySelector('.popup-title').textContent = node.label || node.id || 'Unknown';

        const qsecbitValue = node.qsecbit !== undefined ? node.qsecbit.toFixed(4) : '--';
        this.popup.querySelector('.qsecbit-value').textContent = qsecbitValue;

        const statusEl = this.popup.querySelector('.status-value');
        statusEl.textContent = (node.status || 'unknown').toUpperCase();
        statusEl.className = `stat-value status-value status-${node.status}`;

        this.popup.querySelector('.online-value').textContent = node.online ? 'YES' : 'NO';
        this.popup.querySelector('.location-text').textContent =
            `${node.lat?.toFixed(4)}, ${node.lng?.toFixed(4)}`;

        // Position popup
        if (screenPosition) {
            this.popup.style.left = `${screenPosition.x}px`;
            this.popup.style.top = `${screenPosition.y + this.config.popupOffset[1]}px`;
        }

        this.popup.style.display = 'block';
        this.popup.classList.add('visible');
    }

    hidePopup() {
        if (this.popup) {
            this.popup.classList.remove('visible');
            setTimeout(() => {
                this.popup.style.display = 'none';
            }, 200);
        }
        this.selectedNode = null;
    }

    // =========================================================================
    // MINI-MAP COMPONENT
    // =========================================================================

    _createMiniMap() {
        const container = document.createElement('div');
        container.id = 'city-mini-map';
        container.className = 'cortex-mini-map';
        container.style.display = 'none';
        container.innerHTML = `
            <div class="mini-map-header">
                <span class="mini-map-title">OVERVIEW</span>
                <button class="mini-map-toggle">&#8722;</button>
            </div>
            <div class="mini-map-canvas"></div>
            <div class="mini-map-viewport"></div>
        `;

        document.body.appendChild(container);
        this.miniMap = container;

        // Collapse toggle
        container.querySelector('.mini-map-toggle').addEventListener('click', () => {
            container.classList.toggle('collapsed');
            const btn = container.querySelector('.mini-map-toggle');
            btn.innerHTML = container.classList.contains('collapsed') ? '&#43;' : '&#8722;';
        });
    }

    updateMiniMap(bounds, viewportBounds) {
        if (!this.miniMap) return;

        // Update viewport indicator position
        const viewport = this.miniMap.querySelector('.mini-map-viewport');
        if (viewport && bounds && viewportBounds) {
            // Calculate relative position
            const left = ((viewportBounds.west - bounds.west) / (bounds.east - bounds.west)) * 100;
            const top = ((bounds.north - viewportBounds.north) / (bounds.north - bounds.south)) * 100;
            const width = ((viewportBounds.east - viewportBounds.west) / (bounds.east - bounds.west)) * 100;
            const height = ((viewportBounds.north - viewportBounds.south) / (bounds.north - bounds.south)) * 100;

            viewport.style.left = `${Math.max(0, Math.min(100 - width, left))}%`;
            viewport.style.top = `${Math.max(0, Math.min(100 - height, top))}%`;
            viewport.style.width = `${Math.min(100, width)}%`;
            viewport.style.height = `${Math.min(100, height)}%`;
        }
    }

    // =========================================================================
    // SEARCH BAR COMPONENT
    // =========================================================================

    _createSearchBar() {
        const container = document.createElement('div');
        container.id = 'city-search-bar';
        container.className = 'cortex-search-bar';
        container.style.display = 'none';
        container.innerHTML = `
            <div class="search-input-wrapper">
                <span class="search-icon">&#128269;</span>
                <input type="text" class="search-input" placeholder="Search nodes...">
                <button class="search-clear">&times;</button>
            </div>
            <div class="search-results"></div>
        `;

        document.body.appendChild(container);
        this.searchInput = container.querySelector('.search-input');

        // Search input handler
        let searchTimeout;
        this.searchInput.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                this._performSearch(e.target.value);
            }, 300);
        });

        // Clear button
        container.querySelector('.search-clear').addEventListener('click', () => {
            this.searchInput.value = '';
            this._clearSearchResults();
        });
    }

    _performSearch(query) {
        if (!query || query.length < 2) {
            this._clearSearchResults();
            return;
        }

        const results = this._searchNodes(query);
        this._displaySearchResults(results);
    }

    _searchNodes(query) {
        const lowerQuery = query.toLowerCase();
        const nodes = this._getAllNodes();

        return nodes.filter(node => {
            return (node.label && node.label.toLowerCase().includes(lowerQuery)) ||
                   (node.id && node.id.toLowerCase().includes(lowerQuery)) ||
                   (node.tier && node.tier.toLowerCase().includes(lowerQuery));
        }).slice(0, 10); // Limit results
    }

    _displaySearchResults(results) {
        const container = document.querySelector('#city-search-bar .search-results');
        if (!container) return;

        if (results.length === 0) {
            container.innerHTML = '<div class="no-results">No nodes found</div>';
            container.style.display = 'block';
            return;
        }

        container.innerHTML = results.map(node => `
            <div class="search-result-item" data-node-id="${node.id}">
                <span class="result-tier tier-${node.tier}">${(node.tier || '?')[0].toUpperCase()}</span>
                <span class="result-label">${node.label || node.id}</span>
                <span class="result-status status-${node.status}">&#9679;</span>
            </div>
        `).join('');

        container.style.display = 'block';

        // Add click handlers
        container.querySelectorAll('.search-result-item').forEach(item => {
            item.addEventListener('click', () => {
                const nodeId = item.dataset.nodeId;
                const node = this._getNodeById(nodeId);
                if (node) {
                    this._focusOnNode(node);
                    this._clearSearchResults();
                }
            });
        });
    }

    _clearSearchResults() {
        const container = document.querySelector('#city-search-bar .search-results');
        if (container) {
            container.innerHTML = '';
            container.style.display = 'none';
        }
    }

    // =========================================================================
    // FILTER PANEL COMPONENT
    // =========================================================================

    _createFilterPanel() {
        const container = document.createElement('div');
        container.id = 'city-filter-panel';
        container.className = 'cortex-filter-panel';
        container.style.display = 'none';
        container.innerHTML = `
            <div class="filter-header">
                <span class="filter-title">FILTERS</span>
                <button class="filter-reset">Reset</button>
            </div>
            <div class="filter-group">
                <label class="filter-label">Tier</label>
                <div class="filter-options tier-options">
                    <label><input type="checkbox" value="sentinel" checked> Sentinel</label>
                    <label><input type="checkbox" value="guardian" checked> Guardian</label>
                    <label><input type="checkbox" value="fortress" checked> Fortress</label>
                    <label><input type="checkbox" value="nexus" checked> Nexus</label>
                </div>
            </div>
            <div class="filter-group">
                <label class="filter-label">Status</label>
                <div class="filter-options status-options">
                    <label><input type="checkbox" value="green" checked> Green</label>
                    <label><input type="checkbox" value="amber" checked> Amber</label>
                    <label><input type="checkbox" value="red" checked> Red</label>
                </div>
            </div>
            <div class="filter-group">
                <label class="filter-label">Online</label>
                <div class="filter-options online-options">
                    <label><input type="checkbox" value="online" checked> Online</label>
                    <label><input type="checkbox" value="offline" checked> Offline</label>
                </div>
            </div>
        `;

        document.body.appendChild(container);
        this.filterPanel = container;

        // Reset button
        container.querySelector('.filter-reset').addEventListener('click', () => {
            container.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                cb.checked = true;
            });
            this._applyFilters();
        });

        // Filter change handlers
        container.querySelectorAll('input[type="checkbox"]').forEach(cb => {
            cb.addEventListener('change', () => this._applyFilters());
        });
    }

    _applyFilters() {
        const tiers = this._getCheckedValues('.tier-options');
        const statuses = this._getCheckedValues('.status-options');
        const onlineStatuses = this._getCheckedValues('.online-options');

        // Emit filter event
        const filters = { tiers, statuses, onlineStatuses };
        this._emit('filterChange', filters);

        // Apply to DeckRenderer if available
        if (this.viewManager && this.viewManager.deckRenderer) {
            const allNodes = this._getAllNodes();
            const filteredNodes = allNodes.filter(node => {
                const tierMatch = tiers.includes(node.tier);
                const statusMatch = statuses.includes(node.status);
                const onlineMatch = (node.online && onlineStatuses.includes('online')) ||
                                   (!node.online && onlineStatuses.includes('offline'));
                return tierMatch && statusMatch && onlineMatch;
            });
            this.viewManager.deckRenderer.setNodes(filteredNodes);
        }
    }

    _getCheckedValues(selector) {
        const container = this.filterPanel.querySelector(selector);
        if (!container) return [];

        return Array.from(container.querySelectorAll('input:checked'))
            .map(cb => cb.value);
    }

    // =========================================================================
    // NEIGHBORHOOD STATISTICS
    // =========================================================================

    _updateNeighborhoodStats() {
        const nodes = this._getAllNodes();
        if (nodes.length === 0) return;

        // Group by approximate grid cells
        const gridSize = 0.01; // ~1km at equator
        const grid = {};

        nodes.forEach(node => {
            const gridX = Math.floor(node.lng / gridSize);
            const gridY = Math.floor(node.lat / gridSize);
            const key = `${gridX},${gridY}`;

            if (!grid[key]) {
                grid[key] = {
                    nodes: [],
                    center: { lat: 0, lng: 0 },
                    stats: { green: 0, amber: 0, red: 0, total: 0 }
                };
            }

            grid[key].nodes.push(node);
            grid[key].stats.total++;
            if (node.status) {
                grid[key].stats[node.status]++;
            }
        });

        // Calculate centers
        Object.values(grid).forEach(cell => {
            cell.center.lat = cell.nodes.reduce((sum, n) => sum + n.lat, 0) / cell.nodes.length;
            cell.center.lng = cell.nodes.reduce((sum, n) => sum + n.lng, 0) / cell.nodes.length;
        });

        this.neighborhoodStats = grid;
    }

    getNeighborhoodAt(lat, lng) {
        const gridSize = 0.01;
        const gridX = Math.floor(lng / gridSize);
        const gridY = Math.floor(lat / gridSize);
        const key = `${gridX},${gridY}`;

        return this.neighborhoodStats[key] || null;
    }

    // =========================================================================
    // EVENT HANDLERS
    // =========================================================================

    _onNodeClick(node, info) {
        if (!node) return;

        const screenPos = info?.pixel ? { x: info.pixel[0], y: info.pixel[1] } : null;
        this.showPopup(node, screenPos);
    }

    _onMapClick(info) {
        if (!info.object) {
            this.hidePopup();
        }
    }

    _onKeyDown(e) {
        // Escape closes popup
        if (e.key === 'Escape') {
            this.hidePopup();
            this._clearSearchResults();
        }

        // Ctrl+F focuses search
        if (e.ctrlKey && e.key === 'f' && this.viewManager?.isMapMode()) {
            e.preventDefault();
            if (this.searchInput) {
                this.searchInput.focus();
            }
        }
    }

    // =========================================================================
    // UTILITY METHODS
    // =========================================================================

    _getAllNodes() {
        // Try to get nodes from various sources
        if (this.viewManager?.deckRenderer?.nodes) {
            return this.viewManager.deckRenderer.nodes;
        }
        if (this.viewManager?.clusterManager?.nodes) {
            return this.viewManager.clusterManager.nodes;
        }
        if (window.state?.nodes) {
            return Object.values(window.state.nodes);
        }
        return [];
    }

    _getNodeById(id) {
        const nodes = this._getAllNodes();
        return nodes.find(n => n.id === id || n.node_id === id);
    }

    _focusOnNode(node) {
        if (!node) return;

        if (this.viewManager?.deckRenderer) {
            this.viewManager.deckRenderer.flyTo({
                longitude: node.lng,
                latitude: node.lat,
                zoom: 16,
                duration: 800
            });
        }

        this._highlightNode(node);
    }

    _highlightNode(node) {
        this.highlightedNodes.add(node.id);
        // Trigger re-render with highlight
        setTimeout(() => {
            this.highlightedNodes.delete(node.id);
        }, 3000);
    }

    _showNodeDetails(node) {
        // Could open a modal or side panel with full node details
        console.log('Node details:', node);
        // For now, just log - can be extended with modal UI
    }

    _showCityUI() {
        ['city-search-bar', 'city-filter-panel', 'city-mini-map'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.style.display = 'block';
        });
    }

    _hideCityUI() {
        ['city-search-bar', 'city-filter-panel', 'city-mini-map', 'city-node-popup'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.style.display = 'none';
        });
    }

    _clearSelection() {
        this.selectedNode = null;
        this.highlightedNodes.clear();
        this.hidePopup();
    }

    // Event emitter
    _callbacks = {};

    on(event, callback) {
        if (!this._callbacks[event]) this._callbacks[event] = [];
        this._callbacks[event].push(callback);
        return this;
    }

    _emit(event, data) {
        if (this._callbacks[event]) {
            this._callbacks[event].forEach(cb => cb(data));
        }
    }

    /**
     * Cleanup
     */
    destroy() {
        document.removeEventListener('keydown', this._boundHandlers.onKeyDown);

        ['city-node-popup', 'city-mini-map', 'city-search-bar', 'city-filter-panel'].forEach(id => {
            const el = document.getElementById(id);
            if (el && el.parentNode) {
                el.parentNode.removeChild(el);
            }
        });

        console.log('CityViewController: Destroyed');
    }
}

// =============================================================================
// EXPORTS
// =============================================================================

if (typeof window !== 'undefined') {
    window.CityViewController = CityViewController;
    window.CITY_VIEW_CONFIG = CITY_VIEW_CONFIG;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CityViewController, CITY_VIEW_CONFIG };
}
