/**
 * HookProbe Fortress - Frontend JavaScript
 */

// Global Fortress namespace
const Fortress = {
    apiBase: '/api',

    // API helper methods
    async get(endpoint) {
        try {
            const response = await fetch(`${this.apiBase}${endpoint}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (error) {
            console.error(`API GET ${endpoint}:`, error);
            throw error;
        }
    },

    async post(endpoint, data = {}) {
        try {
            const response = await fetch(`${this.apiBase}${endpoint}`, {
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
    },

    // Toast notifications
    toast(message, type = 'info') {
        // Use AdminLTE's toastr if available, otherwise fallback to alert
        if (typeof toastr !== 'undefined') {
            toastr[type](message);
        } else {
            console.log(`[${type.toUpperCase()}] ${message}`);
        }
    },

    // Update QSecBit status badge
    updateQsecbitBadge(status) {
        const badge = document.getElementById('qsecbit-badge');
        if (badge) {
            badge.textContent = status;
            badge.style.backgroundColor =
                status === 'GREEN' ? '#28a745' :
                status === 'AMBER' ? '#ffc107' : '#dc3545';
        }
    },

    // Initialize
    init() {
        console.log('Fortress initialized');

        // Auto-dismiss alerts after 5 seconds
        setTimeout(() => {
            document.querySelectorAll('.alert-dismissible').forEach(alert => {
                $(alert).alert('close');
            });
        }, 5000);
    }
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    Fortress.init();
});
