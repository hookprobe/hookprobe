/**
 * HookProbe Cortex - Fleet Management Panel
 *
 * MSSP Admin and Fleet Admin view for managing endpoints.
 * Provides:
 * - Customer/organization filtering
 * - Fleet overview statistics
 * - Department breakdown
 * - Bulk actions
 * - Search and filtering
 */

// Fleet panel state
const fleetState = {
    accessLevel: 'end_user', // mssp_admin, fleet_admin, end_user
    currentCustomer: null,
    customers: [],
    devices: [],
    selectedDevices: new Set(),
    filters: {
        status: 'all',
        tier: 'all',
        department: 'all',
        online: 'all',
        search: ''
    },
    sortBy: 'status',
    sortOrder: 'desc'
};

/**
 * Initialize the fleet panel
 */
function initFleetPanel(accessLevel = 'end_user') {
    fleetState.accessLevel = accessLevel;

    // Create panel UI based on access level
    if (accessLevel === 'mssp_admin') {
        createMSSPAdminPanel();
    } else if (accessLevel === 'fleet_admin') {
        createFleetAdminPanel();
    }

    console.log(`Fleet Panel initialized (${accessLevel})`);
}

/**
 * Create MSSP Admin panel (God view)
 */
function createMSSPAdminPanel() {
    const panel = document.createElement('div');
    panel.id = 'mssp-admin-panel';
    panel.className = 'cortex-fleet-panel mssp-admin';
    panel.innerHTML = `
        <div class="fleet-panel-header">
            <div class="panel-title">
                <span class="panel-icon">🛡️</span>
                <div class="panel-title-text">
                    <h3>MSSP Command Center</h3>
                    <span class="panel-subtitle">All Endpoints • All Customers</span>
                </div>
            </div>
            <button class="panel-toggle" onclick="toggleFleetPanel()">
                <span class="toggle-icon">◀</span>
            </button>
        </div>

        <div class="fleet-panel-content">
            <!-- Customer Selector -->
            <div class="customer-selector">
                <label>CUSTOMER</label>
                <select id="customer-filter" onchange="onCustomerFilterChange(this.value)">
                    <option value="">All Customers</option>
                </select>
            </div>

            <!-- Fleet Stats -->
            <div class="fleet-stats-grid" id="fleet-stats">
                <div class="fleet-stat total">
                    <span class="stat-value" id="fleet-total">0</span>
                    <span class="stat-label">Total</span>
                </div>
                <div class="fleet-stat online">
                    <span class="stat-value" id="fleet-online">0</span>
                    <span class="stat-label">Online</span>
                </div>
                <div class="fleet-stat warning">
                    <span class="stat-value" id="fleet-warning">0</span>
                    <span class="stat-label">Warning</span>
                </div>
                <div class="fleet-stat critical">
                    <span class="stat-value" id="fleet-critical">0</span>
                    <span class="stat-label">Critical</span>
                </div>
            </div>

            <!-- Tier Breakdown -->
            <div class="fleet-breakdown">
                <h4>BY TIER</h4>
                <div class="breakdown-bars" id="tier-breakdown">
                    <div class="breakdown-item nexus">
                        <span class="breakdown-label">Nexus</span>
                        <div class="breakdown-bar"><div class="breakdown-fill" style="width: 0%"></div></div>
                        <span class="breakdown-count">0</span>
                    </div>
                    <div class="breakdown-item fortress">
                        <span class="breakdown-label">Fortress</span>
                        <div class="breakdown-bar"><div class="breakdown-fill" style="width: 0%"></div></div>
                        <span class="breakdown-count">0</span>
                    </div>
                    <div class="breakdown-item guardian">
                        <span class="breakdown-label">Guardian</span>
                        <div class="breakdown-bar"><div class="breakdown-fill" style="width: 0%"></div></div>
                        <span class="breakdown-count">0</span>
                    </div>
                    <div class="breakdown-item sentinel">
                        <span class="breakdown-label">Sentinel</span>
                        <div class="breakdown-bar"><div class="breakdown-fill" style="width: 0%"></div></div>
                        <span class="breakdown-count">0</span>
                    </div>
                </div>
            </div>

            <!-- Search & Filter -->
            <div class="fleet-search">
                <input type="text" id="fleet-search-input" placeholder="Search devices..." oninput="onFleetSearch(this.value)">
                <div class="fleet-filters">
                    <select id="status-filter" onchange="onStatusFilterChange(this.value)">
                        <option value="all">All Status</option>
                        <option value="green">Healthy</option>
                        <option value="amber">Warning</option>
                        <option value="red">Critical</option>
                    </select>
                    <select id="online-filter" onchange="onOnlineFilterChange(this.value)">
                        <option value="all">All</option>
                        <option value="online">Online</option>
                        <option value="offline">Offline</option>
                    </select>
                </div>
            </div>

            <!-- Device List -->
            <div class="fleet-device-list" id="fleet-device-list">
                <div class="device-list-empty">
                    <span class="empty-icon">📡</span>
                    <span>No devices to display</span>
                </div>
            </div>

            <!-- Bulk Actions -->
            <div class="fleet-bulk-actions" id="fleet-bulk-actions" style="display: none;">
                <span class="selected-count">0 selected</span>
                <button class="bulk-btn" onclick="focusSelectedDevices()">Focus</button>
                <button class="bulk-btn secondary" onclick="clearSelection()">Clear</button>
            </div>
        </div>
    `;

    document.getElementById('app').appendChild(panel);
}

/**
 * Create Fleet Admin panel (Organization view)
 */
function createFleetAdminPanel() {
    const panel = document.createElement('div');
    panel.id = 'fleet-admin-panel';
    panel.className = 'cortex-fleet-panel fleet-admin';
    panel.innerHTML = `
        <div class="fleet-panel-header">
            <div class="panel-title">
                <span class="panel-icon">🏢</span>
                <div class="panel-title-text">
                    <h3>Fleet Overview</h3>
                    <span class="panel-subtitle" id="org-name">Your Organization</span>
                </div>
            </div>
            <button class="panel-toggle" onclick="toggleFleetPanel()">
                <span class="toggle-icon">◀</span>
            </button>
        </div>

        <div class="fleet-panel-content">
            <!-- Fleet Stats -->
            <div class="fleet-stats-grid" id="fleet-stats">
                <div class="fleet-stat total">
                    <span class="stat-value" id="fleet-total">0</span>
                    <span class="stat-label">Devices</span>
                </div>
                <div class="fleet-stat online">
                    <span class="stat-value" id="fleet-online">0</span>
                    <span class="stat-label">Online</span>
                </div>
                <div class="fleet-stat qsecbit">
                    <span class="stat-value" id="fleet-qsecbit">--</span>
                    <span class="stat-label">Avg Qsecbit</span>
                </div>
            </div>

            <!-- Department Breakdown -->
            <div class="fleet-breakdown">
                <h4>BY DEPARTMENT</h4>
                <div class="breakdown-bars" id="dept-breakdown">
                    <!-- Populated dynamically -->
                </div>
            </div>

            <!-- Search -->
            <div class="fleet-search">
                <input type="text" id="fleet-search-input" placeholder="Search devices..." oninput="onFleetSearch(this.value)">
            </div>

            <!-- Device List -->
            <div class="fleet-device-list" id="fleet-device-list">
                <div class="device-list-empty">
                    <span class="empty-icon">📡</span>
                    <span>No devices to display</span>
                </div>
            </div>
        </div>
    `;

    document.getElementById('app').appendChild(panel);
}

/**
 * Update fleet panel with data
 */
function updateFleetPanel(data) {
    if (!data) return;

    // Update customers (MSSP admin only)
    if (data.customers && fleetState.accessLevel === 'mssp_admin') {
        updateCustomerSelector(data.customers);
    }

    // Update devices
    if (data.devices) {
        fleetState.devices = data.devices;
        updateFleetStats(data.stats || calculateStats(data.devices));
        updateDeviceList(data.devices);
    }

    // Update breakdown
    if (data.stats) {
        updateTierBreakdown(data.stats.by_tier);
        if (data.stats.by_department) {
            updateDepartmentBreakdown(data.stats.by_department);
        }
    }
}

/**
 * Update customer selector dropdown
 */
function updateCustomerSelector(customers) {
    const select = document.getElementById('customer-filter');
    if (!select) return;

    fleetState.customers = customers;

    // Clear existing options (except "All")
    while (select.options.length > 1) {
        select.remove(1);
    }

    // Add customer options
    customers.forEach(c => {
        const option = document.createElement('option');
        option.value = c.id;
        option.textContent = `${c.name} (${c.device_count})`;
        if (c.worst_status === 'red') {
            option.className = 'customer-critical';
        } else if (c.worst_status === 'amber') {
            option.className = 'customer-warning';
        }
        select.appendChild(option);
    });
}

/**
 * Update fleet statistics display
 */
function updateFleetStats(stats) {
    const total = document.getElementById('fleet-total');
    const online = document.getElementById('fleet-online');
    const warning = document.getElementById('fleet-warning');
    const critical = document.getElementById('fleet-critical');
    const qsecbit = document.getElementById('fleet-qsecbit');

    if (total) total.textContent = stats.total_devices || 0;
    if (online) online.textContent = stats.online_devices || 0;
    if (warning) warning.textContent = stats.by_status?.amber || 0;
    if (critical) critical.textContent = stats.by_status?.red || 0;
    if (qsecbit) qsecbit.textContent = stats.avg_qsecbit?.toFixed(3) || '--';
}

/**
 * Update tier breakdown bars
 */
function updateTierBreakdown(tierCounts) {
    if (!tierCounts) return;

    const total = Object.values(tierCounts).reduce((a, b) => a + b, 0);
    const breakdown = document.getElementById('tier-breakdown');
    if (!breakdown) return;

    const tiers = ['nexus', 'fortress', 'guardian', 'sentinel'];
    tiers.forEach(tier => {
        const item = breakdown.querySelector(`.breakdown-item.${tier}`);
        if (item) {
            const count = tierCounts[tier] || 0;
            const pct = total > 0 ? (count / total * 100) : 0;
            item.querySelector('.breakdown-fill').style.width = `${pct}%`;
            item.querySelector('.breakdown-count').textContent = count;
        }
    });
}

/**
 * Update department breakdown
 */
function updateDepartmentBreakdown(deptCounts) {
    const container = document.getElementById('dept-breakdown');
    if (!container || !deptCounts) return;

    const total = Object.values(deptCounts).reduce((a, b) => a + b, 0);
    container.innerHTML = '';

    // Sort by count descending
    const sorted = Object.entries(deptCounts).sort((a, b) => b[1] - a[1]);

    sorted.slice(0, 5).forEach(([dept, count]) => {
        const pct = total > 0 ? (count / total * 100) : 0;
        const item = document.createElement('div');
        item.className = 'breakdown-item';
        item.innerHTML = `
            <span class="breakdown-label">${dept}</span>
            <div class="breakdown-bar"><div class="breakdown-fill" style="width: ${pct}%"></div></div>
            <span class="breakdown-count">${count}</span>
        `;
        container.appendChild(item);
    });
}

/**
 * Update device list
 */
function updateDeviceList(devices) {
    const container = document.getElementById('fleet-device-list');
    if (!container) return;

    // Apply filters
    let filtered = devices.filter(d => {
        if (fleetState.filters.status !== 'all' && d.status !== fleetState.filters.status) return false;
        if (fleetState.filters.online === 'online' && !d.online) return false;
        if (fleetState.filters.online === 'offline' && d.online) return false;
        if (fleetState.filters.search) {
            const search = fleetState.filters.search.toLowerCase();
            if (!d.label?.toLowerCase().includes(search) &&
                !d.hostname?.toLowerCase().includes(search) &&
                !d.id?.toLowerCase().includes(search)) {
                return false;
            }
        }
        return true;
    });

    // Sort
    filtered.sort((a, b) => {
        let cmp = 0;
        if (fleetState.sortBy === 'status') {
            const order = { red: 0, amber: 1, green: 2 };
            cmp = (order[a.status] || 2) - (order[b.status] || 2);
        } else if (fleetState.sortBy === 'qsecbit') {
            cmp = b.qsecbit - a.qsecbit;
        } else if (fleetState.sortBy === 'label') {
            cmp = (a.label || '').localeCompare(b.label || '');
        }
        return fleetState.sortOrder === 'desc' ? cmp : -cmp;
    });

    // Render
    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="device-list-empty">
                <span class="empty-icon">📡</span>
                <span>No devices match filters</span>
            </div>
        `;
        return;
    }

    container.innerHTML = filtered.map(d => `
        <div class="device-item ${d.status} ${d.online ? 'online' : 'offline'} ${fleetState.selectedDevices.has(d.id) ? 'selected' : ''}"
             data-device-id="${d.id}"
             onclick="onDeviceClick('${d.id}')">
            <div class="device-status-indicator"></div>
            <div class="device-info">
                <span class="device-label">${d.label || d.id}</span>
                <span class="device-meta">${d.tier} • ${d.online ? 'Online' : 'Offline'}</span>
            </div>
            <div class="device-qsecbit">
                <span class="qsecbit-value">${d.qsecbit.toFixed(3)}</span>
            </div>
            <div class="device-heartbeat" data-device-id="${d.id}">
                <span class="heartbeat-pulse"></span>
            </div>
        </div>
    `).join('');

    // Start heartbeat animations
    startDeviceHeartbeats();
}

/**
 * Calculate stats from device list
 */
function calculateStats(devices) {
    return {
        total_devices: devices.length,
        online_devices: devices.filter(d => d.online).length,
        avg_qsecbit: devices.length > 0
            ? devices.reduce((sum, d) => sum + d.qsecbit, 0) / devices.length
            : 0,
        by_tier: {
            sentinel: devices.filter(d => d.tier === 'sentinel').length,
            guardian: devices.filter(d => d.tier === 'guardian').length,
            fortress: devices.filter(d => d.tier === 'fortress').length,
            nexus: devices.filter(d => d.tier === 'nexus').length,
        },
        by_status: {
            green: devices.filter(d => d.status === 'green').length,
            amber: devices.filter(d => d.status === 'amber').length,
            red: devices.filter(d => d.status === 'red').length,
        }
    };
}

/**
 * Toggle fleet panel visibility
 */
function toggleFleetPanel() {
    const panel = document.querySelector('.cortex-fleet-panel');
    if (panel) {
        panel.classList.toggle('collapsed');
        const toggle = panel.querySelector('.toggle-icon');
        if (toggle) {
            toggle.textContent = panel.classList.contains('collapsed') ? '▶' : '◀';
        }
    }
}

/**
 * Event handlers
 */
function onCustomerFilterChange(customerId) {
    fleetState.currentCustomer = customerId || null;
    // Request filtered data from server
    if (window.dataStream) {
        window.dataStream.send(JSON.stringify({
            type: 'request_fleet_data',
            customer_filter: customerId
        }));
    }
}

function onStatusFilterChange(status) {
    fleetState.filters.status = status;
    updateDeviceList(fleetState.devices);
}

function onOnlineFilterChange(value) {
    fleetState.filters.online = value;
    updateDeviceList(fleetState.devices);
}

function onFleetSearch(value) {
    fleetState.filters.search = value;
    updateDeviceList(fleetState.devices);
}

function onDeviceClick(deviceId) {
    // Toggle selection
    if (fleetState.selectedDevices.has(deviceId)) {
        fleetState.selectedDevices.delete(deviceId);
    } else {
        fleetState.selectedDevices.add(deviceId);
    }

    // Update UI
    const item = document.querySelector(`.device-item[data-device-id="${deviceId}"]`);
    if (item) {
        item.classList.toggle('selected', fleetState.selectedDevices.has(deviceId));
    }

    // Update bulk actions
    updateBulkActions();

    // Focus on device in globe
    const device = fleetState.devices.find(d => d.id === deviceId);
    if (device && window.globe) {
        window.globe.pointOfView({
            lat: device.lat,
            lng: device.lng,
            altitude: 0.5
        }, 1000);
    }
}

function updateBulkActions() {
    const actions = document.getElementById('fleet-bulk-actions');
    if (!actions) return;

    if (fleetState.selectedDevices.size > 0) {
        actions.style.display = 'flex';
        actions.querySelector('.selected-count').textContent =
            `${fleetState.selectedDevices.size} selected`;
    } else {
        actions.style.display = 'none';
    }
}

function focusSelectedDevices() {
    // Calculate bounds of selected devices
    const selected = fleetState.devices.filter(d => fleetState.selectedDevices.has(d.id));
    if (selected.length === 0) return;

    if (selected.length === 1) {
        // Single device - zoom in
        const d = selected[0];
        if (window.globe) {
            window.globe.pointOfView({ lat: d.lat, lng: d.lng, altitude: 0.4 }, 1500);
        }
    } else {
        // Multiple devices - fit bounds
        const lats = selected.map(d => d.lat);
        const lngs = selected.map(d => d.lng);
        const centerLat = (Math.max(...lats) + Math.min(...lats)) / 2;
        const centerLng = (Math.max(...lngs) + Math.min(...lngs)) / 2;
        const span = Math.max(
            Math.max(...lats) - Math.min(...lats),
            Math.max(...lngs) - Math.min(...lngs)
        );
        const altitude = Math.max(0.3, Math.min(2.5, span / 30));

        if (window.globe) {
            window.globe.pointOfView({
                lat: centerLat,
                lng: centerLng,
                altitude: altitude
            }, 1500);
        }
    }
}

function clearSelection() {
    fleetState.selectedDevices.clear();
    document.querySelectorAll('.device-item.selected').forEach(el => {
        el.classList.remove('selected');
    });
    updateBulkActions();
}

/**
 * Start heartbeat animations for devices
 */
function startDeviceHeartbeats() {
    document.querySelectorAll('.device-heartbeat').forEach(el => {
        const deviceId = el.dataset.deviceId;
        const device = fleetState.devices.find(d => d.id === deviceId);
        if (!device || !device.online) return;

        // Heartbeat speed based on status
        const pulse = el.querySelector('.heartbeat-pulse');
        if (pulse) {
            if (device.status === 'red') {
                pulse.style.animationDuration = '0.5s';
            } else if (device.status === 'amber') {
                pulse.style.animationDuration = '1s';
            } else {
                pulse.style.animationDuration = '2s';
            }
        }
    });
}

// Export functions
window.initFleetPanel = initFleetPanel;
window.updateFleetPanel = updateFleetPanel;
window.toggleFleetPanel = toggleFleetPanel;
window.fleetState = fleetState;
