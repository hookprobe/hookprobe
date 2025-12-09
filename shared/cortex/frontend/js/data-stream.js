/**
 * HookProbe Data Stream
 *
 * WebSocket client for receiving real-time threat data
 * Supports dynamic demo/live mode switching
 */

// Configuration
const WS_CONFIG = {
    url: 'ws://localhost:8765',
    reconnectDelay: 2000,
    maxReconnectDelay: 30000,
    reconnectMultiplier: 1.5
};

// State
let ws = null;
let reconnectDelay = WS_CONFIG.reconnectDelay;
let eventHandler = null;
let currentMode = 'demo';  // 'demo' or 'live'
let demoInterval = 3.0;    // seconds between demo events

/**
 * Initialize the data stream
 * @param {Function} onEvent - Callback for incoming events
 */
function initDataStream(onEvent) {
    eventHandler = onEvent;
    connect();
}

/**
 * Connect to WebSocket server
 */
function connect() {
    updateConnectionStatus('connecting');

    try {
        ws = new WebSocket(WS_CONFIG.url);

        ws.onopen = handleOpen;
        ws.onclose = handleClose;
        ws.onmessage = handleMessage;
        ws.onerror = handleError;
    } catch (error) {
        console.error('WebSocket connection failed:', error);
        scheduleReconnect();
    }
}

/**
 * Handle connection open
 */
function handleOpen() {
    console.log('Connected to HookProbe server');
    updateConnectionStatus('connected');
    reconnectDelay = WS_CONFIG.reconnectDelay; // Reset delay on success
}

/**
 * Handle connection close
 */
function handleClose(event) {
    console.log('Disconnected from server:', event.reason || 'Unknown reason');
    updateConnectionStatus('disconnected');
    scheduleReconnect();
}

/**
 * Handle incoming message
 */
function handleMessage(event) {
    try {
        const data = JSON.parse(event.data);

        if (data.type === 'connected') {
            console.log(`Server: ${data.message} v${data.version}`);
            // Update mode from server state
            if (data.mode) {
                currentMode = data.mode;
                updateModeUI(currentMode);
            }
            return;
        }

        if (data.type === 'mode_changed') {
            currentMode = data.mode;
            updateModeUI(currentMode);
            console.log(`Mode changed to: ${currentMode}`);
            return;
        }

        if (eventHandler) {
            eventHandler(data);
        }
    } catch (error) {
        console.error('Failed to parse message:', error, event.data);
    }
}

/**
 * Handle WebSocket error
 */
function handleError(error) {
    console.error('WebSocket error:', error);
}

/**
 * Schedule reconnection with exponential backoff
 */
function scheduleReconnect() {
    console.log(`Reconnecting in ${reconnectDelay / 1000}s...`);

    setTimeout(() => {
        reconnectDelay = Math.min(
            reconnectDelay * WS_CONFIG.reconnectMultiplier,
            WS_CONFIG.maxReconnectDelay
        );
        connect();
    }, reconnectDelay);
}

/**
 * Update connection status UI
 */
function updateConnectionStatus(status) {
    const dot = document.getElementById('connection-status');
    const text = document.getElementById('connection-text');

    dot.className = 'status-dot ' + status;

    switch (status) {
        case 'connected':
            text.textContent = 'Connected';
            break;
        case 'connecting':
            text.textContent = 'Connecting...';
            break;
        case 'disconnected':
            text.textContent = 'Disconnected';
            break;
    }
}

/**
 * Send message to server
 */
function sendMessage(type, data = {}) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type, ...data }));
    }
}

/**
 * Request current node status
 */
function requestNodeStatus() {
    sendMessage('request_nodes');
}

/**
 * Request snapshot of current state
 */
function requestSnapshot() {
    sendMessage('request_snapshot');
}

/**
 * Set data mode (demo or live)
 * @param {string} mode - 'demo' or 'live'
 */
function setDataMode(mode) {
    if (mode !== 'demo' && mode !== 'live') {
        console.error('Invalid mode:', mode);
        return;
    }

    currentMode = mode;
    sendMessage('set_mode', { mode: mode });
    updateModeUI(mode);
    console.log(`Requested mode switch to: ${mode}`);
}

/**
 * Set demo event interval
 * @param {number} interval - Seconds between events
 */
function setDemoInterval(interval) {
    demoInterval = parseFloat(interval);
    sendMessage('set_demo_interval', { interval: demoInterval });

    // Update UI display
    const speedValue = document.getElementById('demo-speed-value');
    if (speedValue) {
        speedValue.textContent = `${demoInterval}s`;
    }

    console.log(`Demo interval set to: ${demoInterval}s`);
}

/**
 * Update mode UI elements
 * @param {string} mode - Current mode
 */
function updateModeUI(mode) {
    // Update toggle buttons
    const demoBtn = document.getElementById('mode-demo');
    const liveBtn = document.getElementById('mode-live');

    if (demoBtn && liveBtn) {
        demoBtn.classList.toggle('active', mode === 'demo');
        liveBtn.classList.toggle('active', mode === 'live');
        liveBtn.classList.toggle('live', mode === 'live');
    }

    // Update mode indicator
    const modeText = document.getElementById('mode-text');
    if (modeText) {
        modeText.textContent = mode === 'demo' ? 'DEMO MODE' : 'LIVE MODE';
    }

    const modeIndicator = document.getElementById('mode-indicator');
    if (modeIndicator) {
        modeIndicator.classList.toggle('live', mode === 'live');
    }

    // Show/hide control panel based on mode
    const controlPanel = document.getElementById('control-panel');
    if (controlPanel) {
        controlPanel.style.display = mode === 'demo' ? 'block' : 'none';
    }
}

/**
 * Get current data mode
 * @returns {string} Current mode
 */
function getCurrentMode() {
    return currentMode;
}

// Export for use in other modules
window.initDataStream = initDataStream;
window.requestNodeStatus = requestNodeStatus;
window.requestSnapshot = requestSnapshot;
window.setDataMode = setDataMode;
window.setDemoInterval = setDemoInterval;
window.getCurrentMode = getCurrentMode;
