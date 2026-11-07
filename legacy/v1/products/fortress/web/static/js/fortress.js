/**
 * HookProbe Fortress - Frontend JavaScript
 * Extends the Fortress namespace from components.js
 */

(function(window) {
    'use strict';

    // Extend existing Fortress namespace (from components.js) or create new
    const FortressCore = window.Fortress || {};

    // Add API base if not set
    FortressCore.apiBase = FortressCore.apiBase || '/api';

    // API helper methods (only add if not already defined)
    if (!FortressCore.get) {
        FortressCore.get = async function(endpoint) {
            try {
                const response = await fetch(`${this.apiBase}${endpoint}`);
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return await response.json();
            } catch (error) {
                console.error(`API GET ${endpoint}:`, error);
                throw error;
            }
        };
    }

    if (!FortressCore.post) {
        FortressCore.post = async function(endpoint, data = {}) {
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
        };
    }

    // Toast notifications - use components.js Toast if available, else toastr
    if (!FortressCore.toast) {
        FortressCore.toast = function(message, type = 'info') {
            // Use Fortress.Toast from components.js if available
            if (FortressCore.Toast && FortressCore.Toast[type]) {
                FortressCore.Toast[type](message);
            } else if (typeof toastr !== 'undefined') {
                toastr[type](message);
            } else {
                console.log(`[${type.toUpperCase()}] ${message}`);
            }
        };
    }

    // Update QSecBit status badge (uses components.css classes)
    FortressCore.updateQsecbitBadge = function(status) {
        const badge = document.getElementById('qsecbit-badge');
        const sidebarBadge = document.getElementById('sidebar-rag-badge');

        if (badge) {
            // Use new components.css status-badge classes
            badge.className = 'status-badge rag-' + status.toLowerCase();
            badge.textContent = status.toUpperCase();
        }

        if (sidebarBadge) {
            sidebarBadge.className = 'badge right badge-' +
                (status === 'GREEN' ? 'success' : status === 'AMBER' ? 'warning' : 'danger');
            sidebarBadge.textContent = status === 'GREEN' ? 'OK' : status.toUpperCase();
        }
    };

    // Initialize Fortress core functionality
    FortressCore.initCore = function() {
        console.log('Fortress core initialized');

        // Auto-dismiss alerts after 5 seconds
        setTimeout(() => {
            document.querySelectorAll('.alert-dismissible').forEach(alert => {
                if (typeof $ !== 'undefined' && $.fn.alert) {
                    $(alert).alert('close');
                } else {
                    alert.style.display = 'none';
                }
            });
        }, 5000);

        // Initialize any data-fortress components
        this.autoInitComponents();
    };

    // Auto-initialize components with data attributes
    FortressCore.autoInitComponents = function() {
        // Health bars with data attributes
        document.querySelectorAll('[data-health]').forEach(el => {
            if (FortressCore.HealthBar) {
                const value = parseFloat(el.dataset.healthValue) || 0;
                const label = el.dataset.healthLabel || '';
                new FortressCore.HealthBar(el, { value, label });
            }
        });

        // Gauges with data attributes
        document.querySelectorAll('[data-gauge]').forEach(el => {
            if (FortressCore.Gauge) {
                const value = parseFloat(el.dataset.gaugeValue) || 0;
                const max = parseFloat(el.dataset.gaugeMax) || 100;
                new FortressCore.Gauge(el, { value, max });
            }
        });
    };

    // Assign back to window
    window.Fortress = FortressCore;

    // Initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => FortressCore.initCore());
    } else {
        FortressCore.initCore();
    }

})(window);
