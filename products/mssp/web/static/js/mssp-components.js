/**
 * HookProbe MSSP Components JavaScript
 * Unified UI components and utilities
 * Version: 1.0.0
 */

(function(window, $) {
    'use strict';

    // ==========================================================================
    // Namespace
    // ==========================================================================

    window.HookProbe = window.HookProbe || {};
    const HP = window.HookProbe;

    // ==========================================================================
    // Configuration
    // ==========================================================================

    HP.config = {
        // API endpoints
        api: {
            status: '/api/v1/status/',
            devices: '/api/v1/devices/',
            alerts: '/api/v1/alerts/',
            metrics: '/api/v1/metrics/'
        },
        // Polling intervals (ms)
        polling: {
            status: 10000,      // 10 seconds
            alerts: 30000,      // 30 seconds
            devices: 60000      // 60 seconds
        },
        // Toast configuration
        toast: {
            timeOut: 4000,
            extendedTimeOut: 1000,
            positionClass: 'toast-top-right',
            progressBar: true,
            closeButton: true
        }
    };

    // ==========================================================================
    // Toastr Configuration
    // ==========================================================================

    HP.initToastr = function() {
        if (typeof toastr === 'undefined') {
            console.warn('Toastr not loaded');
            return;
        }

        toastr.options = {
            closeButton: HP.config.toast.closeButton,
            debug: false,
            newestOnTop: true,
            progressBar: HP.config.toast.progressBar,
            positionClass: HP.config.toast.positionClass,
            preventDuplicates: true,
            onclick: null,
            showDuration: '300',
            hideDuration: '300',
            timeOut: HP.config.toast.timeOut,
            extendedTimeOut: HP.config.toast.extendedTimeOut,
            showEasing: 'swing',
            hideEasing: 'linear',
            showMethod: 'slideDown',
            hideMethod: 'slideUp'
        };

        // Adjust position below navbar
        const style = document.createElement('style');
        style.textContent = '#toast-container.toast-top-right { top: 70px !important; right: 20px !important; }';
        document.head.appendChild(style);
    };

    // Toast helper methods
    HP.toast = {
        success: function(message, title) {
            toastr.success(message, title || 'Success');
        },
        error: function(message, title) {
            toastr.error(message, title || 'Error');
        },
        warning: function(message, title) {
            toastr.warning(message, title || 'Warning');
        },
        info: function(message, title) {
            toastr.info(message, title || 'Info');
        }
    };

    // ==========================================================================
    // DataTables Configuration
    // ==========================================================================

    HP.initDataTables = function() {
        if (typeof $.fn.DataTable === 'undefined') {
            console.warn('DataTables not loaded');
            return;
        }

        // Set default options
        $.extend(true, $.fn.dataTable.defaults, {
            language: {
                search: '_INPUT_',
                searchPlaceholder: 'Search...',
                lengthMenu: '_MENU_ per page',
                info: 'Showing _START_ to _END_ of _TOTAL_ entries',
                infoEmpty: 'No entries found',
                infoFiltered: '(filtered from _MAX_ total)',
                paginate: {
                    first: '<i class="fas fa-angle-double-left"></i>',
                    previous: '<i class="fas fa-angle-left"></i>',
                    next: '<i class="fas fa-angle-right"></i>',
                    last: '<i class="fas fa-angle-double-right"></i>'
                }
            },
            pageLength: 25,
            lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, 'All']],
            order: [[0, 'desc']],
            responsive: true,
            dom: '<"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6"f>>' +
                 '<"row"<"col-sm-12"tr>>' +
                 '<"row"<"col-sm-12 col-md-5"i><"col-sm-12 col-md-7"p>>',
            drawCallback: function() {
                // Re-apply dark mode styles after redraw
                if ($('body').hasClass('dark-mode')) {
                    $(this).find('th, td').css('border-color', 'var(--hp-dark-border)');
                }
            }
        });

        // Auto-initialize tables with data-datatable attribute
        $('table[data-datatable]').each(function() {
            const $table = $(this);
            const options = $table.data('datatable-options') || {};
            $table.DataTable(options);
        });
    };

    // ==========================================================================
    // Live Status Polling
    // ==========================================================================

    HP.polling = {
        intervals: {},

        start: function(name, callback, interval) {
            this.stop(name);
            callback(); // Initial call
            this.intervals[name] = setInterval(callback, interval);
        },

        stop: function(name) {
            if (this.intervals[name]) {
                clearInterval(this.intervals[name]);
                delete this.intervals[name];
            }
        },

        stopAll: function() {
            Object.keys(this.intervals).forEach(name => this.stop(name));
        }
    };

    // Status update handler
    HP.updateStatus = function() {
        $.ajax({
            url: HP.config.api.status,
            method: 'GET',
            dataType: 'json',
            timeout: 5000,
            success: function(data) {
                // Update QSecBit status badge
                if (data.qsecbit && data.qsecbit.status) {
                    HP.updateRAGBadge(data.qsecbit.status);
                }

                // Update notification count
                if (data.notification_count !== undefined) {
                    HP.updateNotificationCount(data.notification_count);
                }

                // Update device count
                if (data.device_count !== undefined) {
                    HP.updateDeviceCount(data.device_count);
                }

                // Trigger custom event for page-specific handlers
                $(document).trigger('hookprobe:status-updated', [data]);
            },
            error: function() {
                // Silent fail - don't spam console on temporary network issues
            }
        });
    };

    HP.updateRAGBadge = function(status) {
        const statusLower = status.toLowerCase();
        const $badge = $('#qsecbit-badge');
        const $sidebarBadge = $('#sidebar-rag-badge');

        if ($badge.length) {
            $badge.attr('class', 'status-badge rag-' + statusLower)
                  .text(status.toUpperCase());
        }

        if ($sidebarBadge.length) {
            $sidebarBadge.attr('class', 'badge right sidebar-rag-badge rag-' + statusLower)
                         .text(status.toUpperCase());
        }
    };

    HP.updateNotificationCount = function(count) {
        const $count = $('#notification-count');
        if ($count.length) {
            $count.text(count);
            $count.toggle(count > 0);
        }
    };

    HP.updateDeviceCount = function(count) {
        const $badge = $('#sidebar-devices-badge');
        if ($badge.length) {
            $badge.text(count);
        }
    };

    // ==========================================================================
    // Mobile Touch Support
    // ==========================================================================

    HP.initMobileSupport = function() {
        const isTouchDevice = ('ontouchstart' in window) ||
            (navigator.maxTouchPoints > 0) ||
            (navigator.msMaxTouchPoints > 0);

        if (!isTouchDevice) return;

        document.documentElement.classList.add('touch-device');

        // Fix AdminLTE sidebar toggle for touch devices
        const pushMenuBtn = document.querySelector('[data-widget="pushmenu"]');
        if (pushMenuBtn) {
            pushMenuBtn.addEventListener('touchend', function(e) {
                e.preventDefault();
                e.stopPropagation();
                if ($.fn.PushMenu) {
                    $('[data-widget="pushmenu"]').PushMenu('toggle');
                } else {
                    document.body.classList.toggle('sidebar-open');
                    document.body.classList.toggle('sidebar-collapse');
                }
            }, { passive: false });
        }

        // Fix dropdown toggles for touch
        document.querySelectorAll('[data-toggle="dropdown"]').forEach(function(el) {
            el.addEventListener('touchend', function(e) {
                e.preventDefault();
                $(this).dropdown('toggle');
            }, { passive: false });
        });

        // Close sidebar when tapping outside on mobile
        document.addEventListener('touchstart', function(e) {
            const sidebar = document.querySelector('.main-sidebar');
            const pushMenuBtn = document.querySelector('[data-widget="pushmenu"]');
            if (sidebar && document.body.classList.contains('sidebar-open')) {
                if (!sidebar.contains(e.target) && (!pushMenuBtn || !pushMenuBtn.contains(e.target))) {
                    document.body.classList.remove('sidebar-open');
                    document.body.classList.add('sidebar-collapse');
                }
            }
        }, { passive: true });
    };

    // ==========================================================================
    // Utility Functions
    // ==========================================================================

    HP.utils = {
        // Format number with commas
        formatNumber: function(num) {
            return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        },

        // Format bytes to human readable
        formatBytes: function(bytes, decimals = 2) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        },

        // Format timestamp to relative time
        timeAgo: function(timestamp) {
            const now = new Date();
            const past = new Date(timestamp);
            const seconds = Math.floor((now - past) / 1000);

            const intervals = {
                year: 31536000,
                month: 2592000,
                week: 604800,
                day: 86400,
                hour: 3600,
                minute: 60
            };

            for (const [unit, secondsInUnit] of Object.entries(intervals)) {
                const interval = Math.floor(seconds / secondsInUnit);
                if (interval >= 1) {
                    return interval + ' ' + unit + (interval !== 1 ? 's' : '') + ' ago';
                }
            }
            return 'just now';
        },

        // Debounce function
        debounce: function(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        },

        // Throttle function
        throttle: function(func, limit) {
            let inThrottle;
            return function(...args) {
                if (!inThrottle) {
                    func.apply(this, args);
                    inThrottle = true;
                    setTimeout(() => inThrottle = false, limit);
                }
            };
        },

        // Copy to clipboard
        copyToClipboard: function(text) {
            if (navigator.clipboard) {
                return navigator.clipboard.writeText(text).then(function() {
                    HP.toast.success('Copied to clipboard');
                });
            }
            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            HP.toast.success('Copied to clipboard');
        },

        // Get CSRF token from cookie
        getCsrfToken: function() {
            const name = 'csrftoken';
            let cookieValue = null;
            if (document.cookie && document.cookie !== '') {
                const cookies = document.cookie.split(';');
                for (let i = 0; i < cookies.length; i++) {
                    const cookie = cookies[i].trim();
                    if (cookie.substring(0, name.length + 1) === (name + '=')) {
                        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                        break;
                    }
                }
            }
            return cookieValue;
        }
    };

    // ==========================================================================
    // AJAX Setup
    // ==========================================================================

    HP.initAjax = function() {
        // Setup CSRF token for all AJAX requests
        $.ajaxSetup({
            beforeSend: function(xhr, settings) {
                if (!(/^(GET|HEAD|OPTIONS|TRACE)$/.test(settings.type)) && !this.crossDomain) {
                    xhr.setRequestHeader('X-CSRFToken', HP.utils.getCsrfToken());
                }
            }
        });

        // Global AJAX error handler
        $(document).ajaxError(function(event, jqXHR, settings, error) {
            if (jqXHR.status === 401) {
                HP.toast.error('Session expired. Please log in again.');
                setTimeout(function() {
                    window.location.href = '/login/';
                }, 2000);
            } else if (jqXHR.status === 403) {
                HP.toast.error('You do not have permission to perform this action.');
            } else if (jqXHR.status >= 500) {
                HP.toast.error('Server error. Please try again later.');
            }
        });
    };

    // ==========================================================================
    // Confirmation Dialogs
    // ==========================================================================

    HP.confirm = function(message, callback) {
        if (typeof Swal !== 'undefined') {
            // Use SweetAlert2 if available
            Swal.fire({
                title: 'Confirm',
                text: message,
                icon: 'question',
                showCancelButton: true,
                confirmButtonColor: '#1e3a8a',
                cancelButtonColor: '#6b7280',
                confirmButtonText: 'Yes',
                cancelButtonText: 'Cancel'
            }).then((result) => {
                if (result.isConfirmed && callback) {
                    callback();
                }
            });
        } else {
            // Fallback to browser confirm
            if (confirm(message) && callback) {
                callback();
            }
        }
    };

    // ==========================================================================
    // Loading States
    // ==========================================================================

    HP.loading = {
        show: function($element, text) {
            const spinner = '<span class="loading-spinner"></span>';
            if ($element.is('button')) {
                $element.data('original-html', $element.html());
                $element.html(spinner + (text ? ' ' + text : '')).prop('disabled', true);
            } else {
                $element.addClass('loading').append('<div class="loading-overlay">' + spinner + '</div>');
            }
        },

        hide: function($element) {
            if ($element.is('button')) {
                $element.html($element.data('original-html')).prop('disabled', false);
            } else {
                $element.removeClass('loading').find('.loading-overlay').remove();
            }
        }
    };

    // ==========================================================================
    // Chart.js Defaults (if Chart.js is loaded)
    // ==========================================================================

    HP.initChartDefaults = function() {
        if (typeof Chart === 'undefined') return;

        // Set dark mode colors
        const isDarkMode = $('body').hasClass('dark-mode');
        const textColor = isDarkMode ? '#f9fafb' : '#1f2937';
        const gridColor = isDarkMode ? '#4b5563' : '#e5e7eb';

        Chart.defaults.color = textColor;
        Chart.defaults.borderColor = gridColor;

        // HookProbe color palette for charts
        HP.chartColors = [
            '#3b82f6', // Blue
            '#22c55e', // Green
            '#f59e0b', // Amber
            '#ef4444', // Red
            '#8b5cf6', // Purple
            '#06b6d4', // Cyan
            '#f97316', // Orange
            '#ec4899', // Pink
        ];
    };

    // ==========================================================================
    // Initialization
    // ==========================================================================

    HP.init = function() {
        // Initialize components
        HP.initToastr();
        HP.initDataTables();
        HP.initAjax();
        HP.initMobileSupport();
        HP.initChartDefaults();

        // Start status polling
        HP.polling.start('status', HP.updateStatus, HP.config.polling.status);

        // Log initialization
        console.log('HookProbe MSSP Components initialized');
    };

    // Auto-initialize on document ready
    $(document).ready(function() {
        HP.init();
    });

    // Cleanup on page unload
    $(window).on('beforeunload', function() {
        HP.polling.stopAll();
    });

})(window, jQuery);
