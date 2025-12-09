/**
 * HookProbe Data Stream
 *
 * WebSocket client for receiving real-time threat data
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

// Export for use in other modules
window.initDataStream = initDataStream;
window.requestNodeStatus = requestNodeStatus;
