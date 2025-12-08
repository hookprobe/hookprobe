/**
 * HookProbe Guardian - Main JavaScript
 * Shared utilities and page management
 */

// ============================================
// GLOBAL STATE
// ============================================
const Guardian = {
    currentTab: 'dashboard',
    refreshInterval: null,
    apiBase: '/api',
    state: {
        dnsxai: { paused: false, disabled: false, pauseEndTime: null },
        system: { uptime: '', load: 0, memory: 0 }
    }
};

// ============================================
// INITIALIZATION
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initMobileMenu();
    initModals();
    loadInitialData();
    startBackgroundRefresh();
});

// ============================================
// NAVIGATION
// ============================================
function initNavigation() {
    // Handle nav item clicks
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            const tab = e.target.dataset.tab;
            if (tab) {
                navigateTo(tab);
            }
        });
    });

    // Handle browser back/forward
    window.addEventListener('popstate', (e) => {
        if (e.state && e.state.tab) {
            showTab(e.state.tab, false);
        }
    });

    // Check URL hash on load
    const hash = window.location.hash.slice(1);
    if (hash && document.getElementById(`tab-${hash}`)) {
        showTab(hash, false);
    }
}

function navigateTo(tab) {
    showTab(tab);
    history.pushState({ tab }, '', `#${tab}`);
}

function showTab(tabName, animate = true) {
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.tab === tabName);
    });

    // Update tab content
    document.querySelectorAll('.tab-panel').forEach(panel => {
        const isActive = panel.id === `tab-${tabName}`;
        panel.classList.toggle('active', isActive);
        if (animate && isActive) {
            panel.style.animation = 'fadeIn 0.3s ease';
        }
    });

    Guardian.currentTab = tabName;

    // Load tab-specific data
    loadTabData(tabName);

    // Close mobile menu
    closeMobileMenu();
}

function loadTabData(tabName) {
    switch (tabName) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'security':
            loadSecurityData();
            break;
        case 'dnsxai':
            loadDnsxaiData();
            break;
        case 'clients':
            loadClientsData();
            break;
        case 'config':
            loadConfigData();
            break;
        case 'vpn':
            loadVpnData();
            break;
        case 'system':
            loadSystemData();
            break;
    }
}

// ============================================
// MOBILE MENU
// ============================================
function initMobileMenu() {
    const toggle = document.querySelector('.menu-toggle');
    const nav = document.querySelector('.nav-main');

    if (toggle && nav) {
        toggle.addEventListener('click', () => {
            nav.classList.toggle('active');
            document.body.classList.toggle('menu-open');
        });
    }

    // Close on outside click
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.nav-main') && !e.target.closest('.menu-toggle')) {
            closeMobileMenu();
        }
    });
}

function closeMobileMenu() {
    const nav = document.querySelector('.nav-main');
    if (nav) {
        nav.classList.remove('active');
        document.body.classList.remove('menu-open');
    }
}

// ============================================
// MODALS
// ============================================
function initModals() {
    // Close modal on overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                closeModal(overlay.id);
            }
        });
    });

    // Close modal on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay.active').forEach(modal => {
                closeModal(modal.id);
            });
        }
    });
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

// ============================================
// API UTILITIES
// ============================================
async function apiGet(endpoint) {
    try {
        const response = await fetch(`${Guardian.apiBase}${endpoint}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`API GET ${endpoint}:`, error);
        throw error;
    }
}

async function apiPost(endpoint, data = {}) {
    try {
        const response = await fetch(`${Guardian.apiBase}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`API POST ${endpoint}:`, error);
        throw error;
    }
}

async function apiDelete(endpoint, data = {}) {
    try {
        const response = await fetch(`${Guardian.apiBase}${endpoint}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`API DELETE ${endpoint}:`, error);
        throw error;
    }
}

// ============================================
// NOTIFICATIONS / TOAST
// ============================================
function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container') || createToastContainer();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${getToastIcon(type)}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
    `;

    container.appendChild(toast);

    // Auto remove
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
    return container;
}

function getToastIcon(type) {
    const icons = {
        success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>',
        error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>',
        warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>',
        info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>'
    };
    return icons[type] || icons.info;
}

// ============================================
// DATA LOADING FUNCTIONS
// ============================================
function loadInitialData() {
    loadDashboardData();
    checkDnsxaiStatus();
}

async function loadDashboardData() {
    try {
        const [status, threats, containers, dhcp] = await Promise.all([
            apiGet('/status'),
            apiGet('/threats'),
            apiGet('/containers'),
            apiGet('/clients/dhcp').catch(() => ({ leases: [] }))
        ]);

        // Use DHCP leases count for connected clients (more reliable)
        const clientCount = (dhcp.leases || []).length;
        status.connected_clients = clientCount;

        updateDashboardStats(status, threats);
        updateContainerStatus(containers);
    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

function updateDashboardStats(status, threats) {
    // Update stat cards
    updateElement('stat-clients', status.connected_clients || 0);
    updateElement('stat-threats-blocked', threats.stats?.blocked || 0);
    updateElement('stat-uptime', status.uptime || '0:00');
    updateElement('stat-qsecbit', (threats.stats?.qsecbit_score || 0).toFixed(2));
}

function updateContainerStatus(containers) {
    const grid = document.getElementById('containers-grid');
    if (!grid) return;

    const html = Object.entries(containers).map(([key, container]) => `
        <div class="device-card">
            <div class="device-icon ${container.running ? 'text-success' : 'text-danger'}">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M21 3H3c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h18c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z"/>
                </svg>
            </div>
            <div class="device-info">
                <div class="device-name">${container.label || key}</div>
                <div class="device-ip">${container.status || 'Unknown'}</div>
            </div>
            <span class="badge ${container.running ? 'badge-success' : 'badge-danger'}">
                ${container.running ? 'Running' : 'Stopped'}
            </span>
        </div>
    `).join('');

    grid.innerHTML = html;
}

async function loadSecurityData() {
    try {
        const [threats, layers, xdp] = await Promise.all([
            apiGet('/threats'),
            apiGet('/layer_threats'),
            apiGet('/xdp_stats')
        ]);

        updateSecurityStats(threats, xdp);
        updateLayerCards(layers);
    } catch (error) {
        console.error('Failed to load security:', error);
    }
}

function updateSecurityStats(threats, xdp) {
    updateElement('security-total-threats', threats.stats?.total || 0);
    updateElement('security-blocked', threats.stats?.blocked || 0);
    updateElement('security-xdp-drops', xdp.drops || 0);
    updateElement('security-active-rules', xdp.active_rules || 0);

    // Update XDP status details
    updateElement('xdp-mode', xdp.mode || 'Not Loaded');
    updateElement('xdp-interface', xdp.interface || 'eth0');
    updateElement('xdp-packets', formatNumber(xdp.packets || 0));
    updateElement('xdp-drop-rate', `${xdp.drop_rate || 0}%`);

    // Update QSecBit score with risk label
    const score = threats.stats?.qsecbit_score || 0;
    updateQSecBitDisplay(score);
}

function formatNumber(num) {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
}

function updateQSecBitDisplay(score) {
    const scoreEl = document.getElementById('qsecbit-score-display');
    const labelEl = document.getElementById('qsecbit-risk-label');
    const progressEl = document.getElementById('qsecbit-progress');

    if (!scoreEl) return;

    // Determine risk level
    let riskLabel, riskColor, progressClass;
    if (score < 0.45) {
        riskLabel = 'RISK LOW';
        riskColor = 'var(--hp-green)';
        progressClass = 'success';
    } else if (score < 0.70) {
        riskLabel = 'RISK MEDIUM';
        riskColor = 'var(--hp-amber)';
        progressClass = 'warning';
    } else {
        riskLabel = 'RISK HIGH';
        riskColor = 'var(--hp-red)';
        progressClass = 'danger';
    }

    // Update display
    scoreEl.textContent = score.toFixed(2);
    scoreEl.style.color = riskColor;

    if (labelEl) {
        labelEl.textContent = riskLabel;
        labelEl.style.color = riskColor;
    }

    if (progressEl) {
        progressEl.style.width = `${Math.min(100, score * 100)}%`;
        progressEl.className = `progress-bar ${progressClass}`;
    }
}

function updateLayerCards(layers) {
    const grid = document.getElementById('layer-cards');
    if (!grid || !layers.layers) return;

    const layerOrder = ['L2_DATA_LINK', 'L3_NETWORK', 'L4_TRANSPORT', 'L5_SESSION', 'L6_PRESENTATION', 'L7_APPLICATION'];
    const layerNames = {
        'L2_DATA_LINK': 'Data Link',
        'L3_NETWORK': 'Network',
        'L4_TRANSPORT': 'Transport',
        'L5_SESSION': 'Session',
        'L6_PRESENTATION': 'Presentation',
        'L7_APPLICATION': 'Application'
    };

    const html = layerOrder.map(key => {
        const layer = layers.layers[key] || { total: 0, critical: 0, high: 0, medium: 0, low: 0, blocked: 0 };
        const types = (layers.detection_coverage?.[key] || []).join(', ');
        const shortKey = key.split('_')[0];

        return `
            <div class="layer-card">
                <div class="layer-card-header">
                    <div>
                        <span class="layer-badge">${shortKey}</span>
                        <span class="layer-name">${layerNames[key]}</span>
                    </div>
                    <span class="layer-threat-count">${layer.total} threats</span>
                </div>
                <div class="layer-stats">
                    <span class="layer-stat critical">${layer.critical} Crit</span>
                    <span class="layer-stat high">${layer.high} High</span>
                    <span class="layer-stat medium">${layer.medium} Med</span>
                    <span class="layer-stat low">${layer.low} Low</span>
                    <span class="layer-stat blocked">${layer.blocked} Blocked</span>
                </div>
                <div class="layer-types">
                    <strong>Detection:</strong> ${types || 'None configured'}
                </div>
            </div>
        `;
    }).join('');

    grid.innerHTML = html;
}

async function loadDnsxaiData() {
    try {
        const [stats, whitelist, sources, mlStatus] = await Promise.all([
            apiGet('/dnsxai/stats'),
            apiGet('/dnsxai/whitelist'),
            apiGet('/dnsxai/sources'),
            apiGet('/dnsxai/ml/status').catch(() => ({ available: false }))
        ]);

        updateDnsxaiStats(stats);
        updateDnsxaiWhitelist(whitelist.whitelist || []);
        updateDnsxaiSources(sources.sources || []);
        updateDnsxaiMLStatus(mlStatus, stats);
    } catch (error) {
        console.error('Failed to load dnsXai:', error);
    }
}

function updateDnsxaiStats(stats) {
    updateElement('dnsxai-queries', formatNumber(stats.total_queries || 0));
    updateElement('dnsxai-blocked', formatNumber(stats.blocked || 0));
    updateElement('dnsxai-block-rate', `${(stats.block_rate || 0).toFixed(1)}%`);
    updateElement('dnsxai-blocklist-size', formatNumber(stats.blocklist_domains || 0));
    updateElement('dnsxai-ml-hits', stats.ml_blocks || 0);
    updateElement('dnsxai-cname-hits', stats.cname_uncloaked || 0);
    updateElement('dnsxai-blocklist-hits', formatNumber(stats.blocked || 0));

    // Update level slider
    const slider = document.getElementById('dnsxai-level-slider');
    if (slider && stats.level !== undefined) {
        slider.value = stats.level;
        updateDnsxaiLevelDisplay(stats.level);
    }
}

function updateDnsxaiMLStatus(mlStatus, stats) {
    // Update ML status indicators
    const mlStatusEl = document.getElementById('ml-status-badge');
    const mlTrainBtn = document.getElementById('ml-train-btn');
    const mlTrainingSamples = document.getElementById('ml-training-samples');
    const mlConfidence = document.getElementById('ml-confidence');
    const federatedStatus = document.getElementById('federated-status');

    if (mlStatusEl) {
        if (!mlStatus.available) {
            mlStatusEl.innerHTML = '<span class="badge badge-warning">ML Not Installed</span>';
            mlStatusEl.title = 'Install numpy and scikit-learn for ML features';
        } else if (mlStatus.classifier?.is_trained) {
            mlStatusEl.innerHTML = '<span class="badge badge-success">ML Active</span>';
        } else {
            mlStatusEl.innerHTML = '<span class="badge badge-info">ML Ready</span>';
        }
    }

    if (mlTrainingSamples && mlStatus.classifier) {
        mlTrainingSamples.textContent = formatNumber(mlStatus.classifier.training_samples || 0);
    }

    if (mlConfidence && mlStatus.classifier) {
        const confidence = mlStatus.classifier.is_trained ?
            Math.min(100, Math.round((mlStatus.classifier.training_samples || 0) / 50)) : 0;
        mlConfidence.textContent = `${confidence}%`;
    }

    if (federatedStatus && mlStatus.federated) {
        federatedStatus.textContent = mlStatus.federated.federation_active ? 'Connected' : 'Local Only';
    }

    // Update CNAME stats if available
    if (mlStatus.uncloaker) {
        updateElement('dnsxai-cname-hits', mlStatus.uncloaker.total_uncloaked || 0);
    }

    // Enable/disable training button
    if (mlTrainBtn) {
        mlTrainBtn.disabled = !mlStatus.available;
    }
}

async function trainDnsxaiML() {
    const trainBtn = document.getElementById('ml-train-btn');
    if (trainBtn) {
        trainBtn.disabled = true;
        trainBtn.textContent = 'Training...';
    }

    try {
        const result = await apiPost('/dnsxai/ml/train', {
            source: 'auto',
            hours: 24,
            limit: 5000,
            use_seed_data: true  // Include known ad/tracking domains
        });

        if (result.success) {
            // Use enhanced message if available
            const message = result.message || `ML Model trained on ${result.samples_trained} domains`;
            showToast(message, 'success');
            loadDnsxaiData();
        } else {
            showToast(result.error || 'Training failed', 'error');
        }
    } catch (error) {
        showToast('Failed to train ML model: ' + (error.message || 'Unknown error'), 'error');
    } finally {
        if (trainBtn) {
            trainBtn.disabled = false;
            trainBtn.textContent = 'Train Model';
        }
    }
}

async function classifyDomain(domain) {
    if (!domain) {
        const input = document.getElementById('ml-classify-input');
        domain = input ? input.value.trim() : '';
    }

    if (!domain) {
        showToast('Enter a domain to classify', 'error');
        return;
    }

    try {
        const result = await apiPost('/dnsxai/ml/classify', { domain });

        const resultEl = document.getElementById('ml-classify-result');
        if (resultEl) {
            const threatClass = result.classification === 'malicious' ? 'danger' :
                               result.classification === 'suspicious' ? 'warning' : 'success';

            resultEl.innerHTML = `
                <div class="classify-result ${threatClass}">
                    <div class="classify-domain">${domain}</div>
                    <div class="classify-verdict">
                        <span class="badge badge-${threatClass}">${result.classification.toUpperCase()}</span>
                        <span class="text-muted">Confidence: ${Math.round(result.confidence * 100)}%</span>
                    </div>
                    <div class="classify-score">Threat Score: ${(result.threat_score * 100).toFixed(1)}%</div>
                    ${result.reasons && result.reasons.length > 0 ? `
                        <div class="classify-reasons">
                            <strong>Reasons:</strong>
                            <ul>${result.reasons.map(r => `<li>${r}</li>`).join('')}</ul>
                        </div>
                    ` : ''}
                </div>
            `;
        }
    } catch (error) {
        showToast('Classification failed', 'error');
    }
}

async function loadMLThreats() {
    try {
        const result = await apiGet('/dnsxai/ml/threats');
        const container = document.getElementById('ml-threats-list');

        if (!container) return;

        if (!result.threats || result.threats.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No threats detected yet</p></div>';
            return;
        }

        container.innerHTML = result.threats.map(threat => `
            <div class="threat-item">
                <div class="threat-domain font-mono">${threat.domain}</div>
                <div class="threat-meta">
                    <span class="badge badge-${threat.type === 'ml_detected' ? 'warning' : 'info'}">${threat.type}</span>
                    <span class="text-muted">${new Date(threat.timestamp).toLocaleTimeString()}</span>
                    <span class="confidence">Confidence: ${Math.round(threat.confidence * 100)}%</span>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load ML threats:', error);
    }
}

function updateDnsxaiWhitelist(domains) {
    const tbody = document.getElementById('dnsxai-whitelist-body');
    const countBadge = document.getElementById('dnsxai-whitelist-count');

    // Update the count badge
    if (countBadge) {
        const count = domains.length;
        countBadge.textContent = `${count} domain${count !== 1 ? 's' : ''}`;
    }

    if (!tbody) return;

    if (domains.length === 0) {
        tbody.innerHTML = '<tr><td colspan="2" class="empty-state">No whitelisted domains</td></tr>';
        return;
    }

    tbody.innerHTML = domains.map(domain => `
        <tr>
            <td class="font-mono">${domain}</td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="removeDnsxaiWhitelist('${domain}')">Remove</button>
            </td>
        </tr>
    `).join('');
}

function updateDnsxaiSources(sources) {
    const container = document.getElementById('dnsxai-sources-list');
    if (!container) return;

    if (sources.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No blocklist sources configured</p></div>';
        return;
    }

    container.innerHTML = sources.map(source => `
        <div class="flex items-center justify-between gap-2 mb-2" style="background: var(--bg-light); padding: var(--spacing-md); border-radius: var(--radius-md);">
            <div style="flex: 1; min-width: 0;">
                <strong>${source.name || 'Custom Source'}</strong>
                <div class="text-muted font-mono truncate" style="font-size: 0.8125rem;">${source.url}</div>
            </div>
            <button class="btn btn-sm btn-danger" onclick="removeDnsxaiSource('${source.url}')">Remove</button>
        </div>
    `).join('');
}

async function loadClientsData() {
    try {
        const [clients, dhcp] = await Promise.all([
            apiGet('/clients/list'),
            apiGet('/clients/dhcp')
        ]);

        const leases = dhcp.leases || [];
        const activeClients = Array.isArray(clients) ? clients.filter(c => c.status === 'connected') : [];

        // Render DHCP leases as responsive cards
        updateDhcpLeasesGrid(leases, activeClients);

        // Update stats
        updateElement('clients-total', leases.length);
        updateElement('clients-active', activeClients.length);

        // Calculate "New Today" - leases with expire time > 23 hours (fresh leases)
        const now = Date.now() / 1000;
        const oneDayAgo = now - 86400;
        const newToday = leases.filter(l => {
            // If lease expires in more than 23 hours, it was likely assigned today
            return l.expires_in > 82800;
        }).length;
        updateElement('clients-new', newToday);
    } catch (error) {
        console.error('Failed to load clients:', error);
    }
}

function updateClientsList(clients) {
    const grid = document.getElementById('clients-grid');
    if (!grid) return;

    if (!clients || clients.length === 0 || (clients.error)) {
        grid.innerHTML = '<div class="empty-state"><p>No clients connected</p></div>';
        return;
    }

    grid.innerHTML = clients.map(client => `
        <div class="device-card">
            <div class="device-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M20 18c1.1 0 1.99-.9 1.99-2L22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z"/>
                </svg>
            </div>
            <div class="device-info">
                <div class="device-name">${client.hostname || 'Unknown Device'}</div>
                <div class="device-ip font-mono">${client.ip || 'N/A'}</div>
                <div class="device-mac text-muted font-mono">${client.mac || 'N/A'}</div>
            </div>
            <div class="device-actions">
                <span class="badge ${client.status === 'connected' ? 'badge-success' : 'badge-info'}">${client.status === 'connected' ? 'Connected' : 'DHCP Lease'}</span>
                ${client.ip && client.ip !== 'N/A' ? `<button class="btn btn-sm btn-danger" onclick="disconnectClient('${client.ip}')" title="Block this client">Disconnect</button>` : ''}
            </div>
        </div>
    `).join('');
}

function updateDhcpLeasesGrid(leases, activeClients = []) {
    const grid = document.getElementById('dhcp-leases-grid');
    if (!grid) return;

    if (!leases || leases.length === 0) {
        grid.innerHTML = `
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor" style="color: var(--text-light);">
                    <path d="M4 6h18V4H4c-1.1 0-2 .9-2 2v11H0v3h14v-3H4V6zm19 2h-6c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h6c.55 0 1-.45 1-1V9c0-.55-.45-1-1-1z"/>
                </svg>
                <h3>No DHCP Leases</h3>
                <p class="text-muted">Devices will appear here when they connect to your network</p>
            </div>`;
        return;
    }

    // Create a set of active MACs for quick lookup
    const activeMacs = new Set(activeClients.map(c => c.mac?.toLowerCase()));

    grid.innerHTML = leases.map(lease => {
        const expiresIn = formatLeaseTime(lease.expires_in);
        const isActive = activeMacs.has(lease.mac?.toLowerCase());
        const statusBadge = isActive ? 'badge-success' : 'badge-info';
        const statusText = isActive ? 'Active' : 'Lease';

        return `
            <div class="device-card">
                <div class="device-icon ${isActive ? 'text-success' : ''}">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M20 18c1.1 0 1.99-.9 1.99-2L22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z"/>
                    </svg>
                </div>
                <div class="device-info">
                    <div class="device-name">${lease.hostname || 'Unknown Device'}</div>
                    <div class="device-ip font-mono">${lease.ip}</div>
                    <div class="device-mac text-muted font-mono" style="font-size: 0.75rem;">${lease.mac}</div>
                    <div class="text-muted" style="font-size: 0.75rem; margin-top: 2px;">Expires: ${expiresIn}</div>
                </div>
                <div class="device-actions">
                    <span class="badge ${statusBadge}">${statusText}</span>
                    <button class="btn btn-sm btn-danger" onclick="disconnectClientByMac('${lease.mac}')" title="Disconnect and remove lease">
                        Disconnect
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

function updateDhcpLeases(leases) {
    // Legacy function - now calls the grid version
    updateDhcpLeasesGrid(leases, []);
}

function formatLeaseTime(seconds) {
    if (!seconds || seconds <= 0) return 'Expired';
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
}

async function disconnectClient(ip) {
    if (!confirm(`Disconnect client ${ip}? This will block the device from accessing the network.`)) {
        return;
    }

    try {
        const result = await apiPost(`/clients/block/${ip}`);
        if (result.success) {
            showToast(`Client ${ip} has been disconnected`, 'success');
            loadClientsData(); // Refresh the list
        } else {
            showToast(result.error || 'Failed to disconnect client', 'error');
        }
    } catch (error) {
        showToast('Failed to disconnect client', 'error');
    }
}

async function disconnectClientByMac(mac) {
    if (!confirm(`Disconnect device ${mac}? This will deauthenticate from WiFi and remove the DHCP lease.`)) {
        return;
    }

    try {
        const result = await apiPost(`/clients/disconnect/${mac}`);
        if (result.success) {
            showToast(result.message || 'Client disconnected', 'success');
            loadClientsData(); // Refresh the list
        } else {
            showToast(result.error || 'Failed to disconnect client', 'error');
        }
    } catch (error) {
        showToast('Failed to disconnect client', 'error');
    }
}

async function unblockClient(ip) {
    try {
        const result = await apiPost(`/clients/unblock/${ip}`);
        if (result.success) {
            showToast(`Client ${ip} has been unblocked`, 'success');
            loadClientsData();
        } else {
            showToast(result.error || 'Failed to unblock client', 'error');
        }
    } catch (error) {
        showToast('Failed to unblock client', 'error');
    }
}

async function loadVpnData() {
    try {
        const vpn = await apiGet('/vpn/status');
        updateVpnStatus(vpn);
    } catch (error) {
        console.error('Failed to load VPN:', error);
    }
}

function updateVpnStatus(vpn) {
    updateElement('vpn-status', vpn.connected ? 'Connected' : 'Disconnected');
    updateElement('vpn-server', vpn.server || 'Not configured');
    updateElement('vpn-ip', vpn.public_ip || 'N/A');
}

async function loadSystemData() {
    try {
        const system = await apiGet('/system/info');
        updateSystemInfo(system);
    } catch (error) {
        console.error('Failed to load system:', error);
    }
}

function updateSystemInfo(system) {
    updateElement('system-hostname', system.hostname || 'guardian');
    updateElement('system-uptime', system.uptime || '0:00');

    // Load average - show all three values
    if (system.load && Array.isArray(system.load)) {
        const loadStr = system.load.map(l => l.toFixed(2)).join(' / ');
        updateElement('system-load', loadStr);
    } else {
        updateElement('system-load', '0.00 / 0.00 / 0.00');
    }

    // Memory - show percentage and used/total
    if (system.memory) {
        const percent = system.memory.percent || 0;
        const usedMB = Math.round((system.memory.used || 0) / (1024 * 1024));
        const totalMB = Math.round((system.memory.total || 0) / (1024 * 1024));
        updateElement('system-memory', `${percent}%`);
        updateElement('system-memory-detail', `${usedMB} / ${totalMB} MB`);
    } else {
        updateElement('system-memory', '0%');
        updateElement('system-memory-detail', '-- / -- MB');
    }

    updateElement('system-temperature', `${(system.temperature || 0).toFixed(1)}°C`);

    // Update progress bars
    updateProgressBar('memory-progress', system.memory?.percent || 0);

    // Update disk usage - format bytes to GB
    if (system.disk) {
        const used = formatBytes(system.disk.used || 0);
        const total = formatBytes(system.disk.total || 0);
        updateElement('disk-usage', `${used} / ${total} (${system.disk.percent}%)`);
        updateProgressBar('disk-progress', system.disk.percent || 0);
    }
}

async function loadConfigData() {
    try {
        const [interfaces, hotspot, dhcp] = await Promise.all([
            apiGet('/config/interfaces').catch(() => ({ interfaces: [] })),
            apiGet('/config/hotspot').catch(() => ({})),
            apiGet('/clients/dhcp').catch(() => ({ leases: [] }))
        ]);

        updateNetworkInterfaces(interfaces.interfaces || []);
        updateHotspotConfig(hotspot);
        updateElement('lan-clients', (dhcp.leases || []).length);
    } catch (error) {
        console.error('Failed to load config:', error);
    }
}

function updateNetworkInterfaces(interfaces) {
    const tbody = document.getElementById('interfaces-body');
    if (!tbody) return;

    if (!interfaces || interfaces.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No network interfaces found</td></tr>';
        return;
    }

    tbody.innerHTML = interfaces.map(iface => `
        <tr>
            <td><strong>${iface.name}</strong></td>
            <td class="font-mono">${iface.ip || 'N/A'}</td>
            <td class="font-mono">${iface.mac || 'N/A'}</td>
            <td><span class="badge ${iface.status === 'UP' ? 'badge-success' : 'badge-danger'}">${iface.status}</span></td>
        </tr>
    `).join('');
}

function updateHotspotConfig(config) {
    if (config.ssid) {
        updateElement('lan-ssid', config.ssid);
        const ssidInput = document.getElementById('hotspot-ssid');
        if (ssidInput) ssidInput.value = config.ssid;
    }
    if (config.channel) {
        const channelSelect = document.getElementById('hotspot-channel');
        if (channelSelect) channelSelect.value = config.channel;
    }
    if (config.security) {
        const securitySelect = document.getElementById('hotspot-security');
        if (securitySelect) securitySelect.value = config.security;
    }
    if (config.hidden !== undefined) {
        const hiddenCheckbox = document.getElementById('hotspot-hidden');
        if (hiddenCheckbox) hiddenCheckbox.checked = config.hidden;
    }
}

// ============================================
// DNSXAI FUNCTIONS
// ============================================
async function checkDnsxaiStatus() {
    try {
        const status = await apiGet('/dnsxai/pause');
        Guardian.state.dnsxai.paused = status.status === 'paused';
        Guardian.state.dnsxai.disabled = status.status === 'disabled';

        if (status.status === 'paused' && status.remaining_seconds > 0) {
            Guardian.state.dnsxai.pauseEndTime = Date.now() + (status.remaining_seconds * 1000);
            updateDnsxaiQuickActionsUI('paused');
            startPauseCountdown();
        } else if (status.status === 'disabled') {
            updateDnsxaiQuickActionsUI('disabled');
        } else {
            updateDnsxaiQuickActionsUI('active');
        }
    } catch (error) {
        console.error('Failed to check dnsXai status:', error);
    }
}

async function pauseDnsxai(minutes) {
    try {
        const result = await apiPost('/dnsxai/pause', { action: 'pause', minutes });
        if (result.success) {
            Guardian.state.dnsxai.pauseEndTime = Date.now() + (minutes * 60 * 1000);
            updateDnsxaiQuickActionsUI('paused');
            startPauseCountdown();
            showToast(`Protection paused for ${minutes} minutes`, 'warning');
        }
    } catch (error) {
        showToast('Failed to pause protection', 'error');
    }
}

async function resumeDnsxai() {
    try {
        const result = await apiPost('/dnsxai/pause', { action: 'resume' });
        if (result.success) {
            Guardian.state.dnsxai.pauseEndTime = null;
            Guardian.state.dnsxai.paused = false;
            Guardian.state.dnsxai.disabled = false;
            updateDnsxaiQuickActionsUI('active');
            showToast('Protection resumed', 'success');
        }
    } catch (error) {
        showToast('Failed to resume protection', 'error');
    }
}

async function toggleDnsxaiKillSwitch() {
    const action = Guardian.state.dnsxai.disabled ? 'enable' : 'disable';
    try {
        const result = await apiPost('/dnsxai/pause', { action });
        if (result.success) {
            Guardian.state.dnsxai.disabled = !Guardian.state.dnsxai.disabled;
            Guardian.state.dnsxai.pauseEndTime = null;
            updateDnsxaiQuickActionsUI(Guardian.state.dnsxai.disabled ? 'disabled' : 'active');
            showToast(Guardian.state.dnsxai.disabled ? 'Protection DISABLED' : 'Protection ENABLED',
                Guardian.state.dnsxai.disabled ? 'error' : 'success');
        }
    } catch (error) {
        showToast('Failed to toggle protection', 'error');
    }
}

function updateDnsxaiQuickActionsUI(status) {
    const icon = document.getElementById('quick-actions-icon');
    const label = document.getElementById('quick-actions-label');
    const btn = document.getElementById('killswitch-btn');
    const timer = document.getElementById('pause-timer');

    if (!icon || !label || !btn) return;

    icon.className = 'quick-actions-icon';
    label.className = 'status-label';

    if (status === 'active') {
        icon.classList.add('active');
        label.textContent = 'Protection Active';
        label.classList.add('active');
        btn.textContent = 'DISABLE';
        btn.className = 'btn btn-danger';
        if (timer) timer.style.display = 'none';
    } else if (status === 'paused') {
        icon.classList.add('paused');
        label.textContent = 'Protection Paused';
        label.classList.add('paused');
        btn.textContent = 'ENABLE';
        btn.className = 'btn btn-success';
        if (timer) timer.style.display = 'block';
    } else if (status === 'disabled') {
        icon.classList.add('disabled');
        label.textContent = 'Protection DISABLED';
        label.classList.add('disabled');
        btn.textContent = 'ENABLE';
        btn.className = 'btn btn-success';
        if (timer) timer.style.display = 'none';
    }
}

let pauseCountdownInterval = null;
function startPauseCountdown() {
    if (pauseCountdownInterval) clearInterval(pauseCountdownInterval);

    const countdown = document.getElementById('pause-countdown');
    if (!countdown) return;

    pauseCountdownInterval = setInterval(() => {
        if (!Guardian.state.dnsxai.pauseEndTime) {
            clearInterval(pauseCountdownInterval);
            return;
        }

        const remaining = Guardian.state.dnsxai.pauseEndTime - Date.now();
        if (remaining <= 0) {
            clearInterval(pauseCountdownInterval);
            resumeDnsxai();
            return;
        }

        const mins = Math.floor(remaining / 60000);
        const secs = Math.floor((remaining % 60000) / 1000);
        countdown.textContent = `${mins}:${secs.toString().padStart(2, '0')} remaining`;
    }, 1000);
}

async function setDnsxaiLevel(level) {
    try {
        const result = await apiPost('/dnsxai/level', { level: parseInt(level) });
        if (result.success) {
            updateDnsxaiLevelDisplay(level);
            showToast(`Protection level updated`, 'success');
        }
    } catch (error) {
        showToast('Failed to update protection level', 'error');
    }
}

function updateDnsxaiLevelDisplay(level) {
    const levels = ['Off', 'Base', 'Enhanced', 'Strong', 'Maximum', 'Full'];
    const colors = ['#6b7280', '#10b981', '#22c55e', '#84cc16', '#f59e0b', '#ef4444'];

    const nameEl = document.getElementById('dnsxai-level-name');
    if (nameEl) {
        nameEl.textContent = levels[level] || 'Unknown';
        nameEl.style.color = colors[level] || colors[0];
    }
}

async function addDnsxaiWhitelist() {
    const input = document.getElementById('dnsxai-whitelist-input');
    const domain = input?.value.trim().toLowerCase();

    if (!domain) {
        showToast('Please enter a domain', 'error');
        return;
    }

    try {
        const result = await apiPost('/dnsxai/whitelist', { domain });
        if (result.success) {
            input.value = '';
            loadDnsxaiData();
            showToast(`${domain} added to whitelist`, 'success');
        }
    } catch (error) {
        showToast('Failed to add domain', 'error');
    }
}

async function removeDnsxaiWhitelist(domain) {
    try {
        const result = await apiDelete('/dnsxai/whitelist', { domain });
        if (result.success) {
            loadDnsxaiData();
            showToast('Domain removed from whitelist', 'success');
        }
    } catch (error) {
        showToast('Failed to remove domain', 'error');
    }
}

async function quickWhitelist() {
    const input = document.getElementById('quick-whitelist-input');
    const domain = input?.value.trim().toLowerCase();

    if (!domain) {
        showToast('Please enter a domain', 'error');
        return;
    }

    try {
        const result = await apiPost('/dnsxai/whitelist', { domain });
        if (result.success) {
            input.value = '';
            showToast(`${domain} whitelisted`, 'success');
        }
    } catch (error) {
        showToast('Failed to whitelist domain', 'error');
    }
}

async function removeDnsxaiSource(url) {
    try {
        const result = await apiDelete('/dnsxai/sources', { url });
        if (result.success) {
            loadDnsxaiData();
            showToast('Source removed', 'success');
        }
    } catch (error) {
        showToast('Failed to remove source', 'error');
    }
}

// ============================================
// WIFI FUNCTIONS
// ============================================
async function scanWifiNetworks() {
    const btn = document.getElementById('scan-wifi-btn');
    const list = document.getElementById('wifi-networks-list');

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="loading-spinner"></span> Scanning...';
    }

    try {
        const result = await apiPost('/config/wifi/scan');
        if (result.success && result.networks) {
            updateWifiNetworksList(result.networks);
        }
    } catch (error) {
        showToast('Failed to scan networks', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Scan Networks';
        }
    }
}

function updateWifiNetworksList(networks) {
    const list = document.getElementById('wifi-networks-list');
    if (!list) return;

    if (!networks || networks.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No networks found</p></div>';
        return;
    }

    list.innerHTML = networks.map(net => `
        <div class="device-card" onclick="selectWifiNetwork('${net.ssid}')">
            <div class="device-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z"/>
                </svg>
            </div>
            <div class="device-info">
                <div class="device-name">${net.ssid}</div>
                <div class="device-ip">Signal: ${net.signal}%</div>
            </div>
            <span class="badge ${net.security ? 'badge-warning' : 'badge-success'}">
                ${net.security || 'Open'}
            </span>
        </div>
    `).join('');
}

function selectWifiNetwork(ssid) {
    document.getElementById('wifi-ssid').value = ssid;
    document.getElementById('wifi-password').focus();
}

// ============================================
// UTILITY FUNCTIONS
// ============================================
function updateElement(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function updateProgressBar(id, percent) {
    const el = document.getElementById(id);
    if (el) {
        el.style.width = `${Math.min(100, Math.max(0, percent))}%`;
        el.className = `progress-bar ${percent > 80 ? 'danger' : percent > 60 ? 'warning' : 'success'}`;
    }
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function formatBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) {
        bytes /= 1024;
        i++;
    }
    return `${bytes.toFixed(1)} ${units[i]}`;
}

// ============================================
// BACKGROUND REFRESH
// ============================================
function startBackgroundRefresh() {
    // Refresh current tab data every 30 seconds
    Guardian.refreshInterval = setInterval(() => {
        if (!document.hidden) {
            loadTabData(Guardian.currentTab);
        }
    }, 30000);

    // Also refresh on visibility change
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            loadTabData(Guardian.currentTab);
        }
    });
}

// Add CSS animation for fadeIn
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    .toast-close {
        background: none;
        border: none;
        font-size: 1.25rem;
        cursor: pointer;
        color: var(--text-secondary);
        padding: 0 0.5rem;
    }
    .toast-close:hover { color: var(--hp-red); }
    .toast-success { border-left: 4px solid var(--hp-green); }
    .toast-error { border-left: 4px solid var(--hp-red); }
    .toast-warning { border-left: 4px solid var(--hp-amber); }
    .toast-info { border-left: 4px solid var(--hp-blue); }
    .toast-icon { display: flex; align-items: center; }
    .toast-success .toast-icon { color: var(--hp-green); }
    .toast-error .toast-icon { color: var(--hp-red); }
    .toast-warning .toast-icon { color: var(--hp-amber); }
    .toast-info .toast-icon { color: var(--hp-blue); }
`;
document.head.appendChild(style);
