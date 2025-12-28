/**
 * Fortress Premium Component Library
 * JavaScript interactivity for unified dashboard components
 *
 * Components:
 * - FortressGauge: Animated ring gauges with real-time updates
 * - FortressTrafficPips: Live traffic visualization
 * - FortressToggle: Switch controls with state management
 * - FortressTable: Enhanced data tables with filtering
 * - FortressTimeline: Event timeline with animations
 * - FortressPanel: Slide-in detail panels
 * - FortressToast: Notification system
 */

(function(window) {
    'use strict';

    // ============================================================
    // FORTRESS NAMESPACE
    // ============================================================
    const Fortress = {
        version: '1.0.0',
        components: {},
        initialized: false
    };

    // ============================================================
    // UTILITY FUNCTIONS
    // ============================================================
    const Utils = {
        // Debounce function calls
        debounce(fn, delay = 250) {
            let timeout;
            return (...args) => {
                clearTimeout(timeout);
                timeout = setTimeout(() => fn.apply(this, args), delay);
            };
        },

        // Throttle function calls
        throttle(fn, limit = 100) {
            let inThrottle;
            return (...args) => {
                if (!inThrottle) {
                    fn.apply(this, args);
                    inThrottle = true;
                    setTimeout(() => inThrottle = false, limit);
                }
            };
        },

        // Format numbers with K/M/B suffixes
        formatNumber(num) {
            if (num >= 1e9) return (num / 1e9).toFixed(1) + 'B';
            if (num >= 1e6) return (num / 1e6).toFixed(1) + 'M';
            if (num >= 1e3) return (num / 1e3).toFixed(1) + 'K';
            return num.toString();
        },

        // Format bytes to human readable
        formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        },

        // Format duration in seconds to human readable
        formatDuration(seconds) {
            if (seconds < 60) return seconds + 's';
            if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
            return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
        },

        // Animate number counting
        animateValue(element, start, end, duration = 1000) {
            const startTime = performance.now();
            const update = (currentTime) => {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
                const current = Math.floor(start + (end - start) * eased);
                element.textContent = Utils.formatNumber(current);
                if (progress < 1) requestAnimationFrame(update);
            };
            requestAnimationFrame(update);
        },

        // Generate unique ID
        uid() {
            return 'fts-' + Math.random().toString(36).substr(2, 9);
        },

        // Parse RAG status color
        ragColor(value, thresholds = { green: 0.45, amber: 0.70 }) {
            if (value < thresholds.green) return 'green';
            if (value < thresholds.amber) return 'amber';
            return 'red';
        }
    };

    Fortress.Utils = Utils;

    // ============================================================
    // GAUGE RING COMPONENT
    // ============================================================
    class FortressGauge {
        constructor(element, options = {}) {
            this.element = typeof element === 'string' ? document.querySelector(element) : element;
            if (!this.element) return;

            this.options = {
                value: 0,
                max: 100,
                size: 120,
                strokeWidth: 8,
                animated: true,
                duration: 1000,
                showValue: true,
                suffix: '%',
                thresholds: { green: 45, amber: 70 },
                onChange: null,
                ...options
            };

            this.init();
        }

        init() {
            this.element.classList.add('gauge-ring');
            this.render();
            if (this.options.animated) {
                this.setValue(this.options.value);
            }
        }

        render() {
            const { size, strokeWidth } = this.options;
            const radius = (size - strokeWidth) / 2;
            const circumference = 2 * Math.PI * radius;

            this.element.innerHTML = `
                <svg viewBox="0 0 ${size} ${size}" class="gauge-svg">
                    <circle class="gauge-track"
                        cx="${size / 2}" cy="${size / 2}" r="${radius}"
                        stroke-width="${strokeWidth}"
                        fill="none" />
                    <circle class="gauge-fill"
                        cx="${size / 2}" cy="${size / 2}" r="${radius}"
                        stroke-width="${strokeWidth}"
                        fill="none"
                        stroke-dasharray="${circumference}"
                        stroke-dashoffset="${circumference}"
                        transform="rotate(-90 ${size / 2} ${size / 2})" />
                </svg>
                <div class="gauge-center">
                    <span class="gauge-value">0</span>
                    <span class="gauge-label">${this.options.suffix}</span>
                </div>
            `;

            this.fillCircle = this.element.querySelector('.gauge-fill');
            this.valueEl = this.element.querySelector('.gauge-value');
            this.circumference = circumference;
        }

        setValue(value, animate = true) {
            const normalizedValue = Math.min(Math.max(value, 0), this.options.max);
            const percentage = normalizedValue / this.options.max;
            const offset = this.circumference * (1 - percentage);

            // Update color based on thresholds
            const color = Utils.ragColor(percentage, {
                green: this.options.thresholds.green / 100,
                amber: this.options.thresholds.amber / 100
            });
            this.fillCircle.setAttribute('data-status', color);

            if (animate && this.options.animated) {
                this.fillCircle.style.transition = `stroke-dashoffset ${this.options.duration}ms ease-out`;
                Utils.animateValue(this.valueEl,
                    parseInt(this.valueEl.textContent) || 0,
                    normalizedValue,
                    this.options.duration
                );
            }

            this.fillCircle.style.strokeDashoffset = offset;

            if (!animate) {
                this.valueEl.textContent = Utils.formatNumber(normalizedValue);
            }

            if (this.options.onChange) {
                this.options.onChange(normalizedValue, color);
            }
        }
    }

    Fortress.Gauge = FortressGauge;

    // ============================================================
    // TRAFFIC PIPS COMPONENT
    // ============================================================
    class FortressTrafficPips {
        constructor(element, options = {}) {
            this.element = typeof element === 'string' ? document.querySelector(element) : element;
            if (!this.element) return;

            this.options = {
                sections: [],
                animated: true,
                pulseInterval: 2000,
                maxPips: 12,
                ...options
            };

            this.init();
        }

        init() {
            this.element.classList.add('traffic-pips');
            this.render();
            if (this.options.animated) {
                this.startPulse();
            }
        }

        render() {
            this.element.innerHTML = this.options.sections.map(section => `
                <div class="pips-section" data-section="${section.id}">
                    <div class="pips-label">${section.label}</div>
                    <div class="pips-container">
                        ${this.renderPips(section.active || 0, section.status || 'nominal')}
                    </div>
                    <div class="pips-value">${section.value || ''}</div>
                </div>
            `).join('');
        }

        renderPips(active, status) {
            return Array(this.options.maxPips).fill(0).map((_, i) =>
                `<span class="pip ${i < active ? 'active' : ''}" data-status="${status}"></span>`
            ).join('');
        }

        updateSection(sectionId, data) {
            const section = this.element.querySelector(`[data-section="${sectionId}"]`);
            if (!section) return;

            const container = section.querySelector('.pips-container');
            const valueEl = section.querySelector('.pips-value');

            container.innerHTML = this.renderPips(data.active, data.status);
            if (data.value) valueEl.textContent = data.value;
        }

        startPulse() {
            this.pulseInterval = setInterval(() => {
                const activePips = this.element.querySelectorAll('.pip.active');
                activePips.forEach((pip, i) => {
                    setTimeout(() => {
                        pip.classList.add('pulse');
                        setTimeout(() => pip.classList.remove('pulse'), 500);
                    }, i * 50);
                });
            }, this.options.pulseInterval);
        }

        stopPulse() {
            if (this.pulseInterval) {
                clearInterval(this.pulseInterval);
            }
        }

        destroy() {
            this.stopPulse();
        }
    }

    Fortress.TrafficPips = FortressTrafficPips;

    // ============================================================
    // TOGGLE CONTROLS
    // ============================================================
    class FortressToggle {
        constructor(element, options = {}) {
            this.element = typeof element === 'string' ? document.querySelector(element) : element;
            if (!this.element) return;

            this.options = {
                state: false,
                disabled: false,
                confirmDanger: false,
                confirmMessage: 'Are you sure?',
                onChange: null,
                ...options
            };

            this.init();
        }

        init() {
            this.checkbox = this.element.querySelector('input[type="checkbox"]');
            if (!this.checkbox) {
                this.checkbox = document.createElement('input');
                this.checkbox.type = 'checkbox';
                this.element.insertBefore(this.checkbox, this.element.firstChild);
            }

            this.checkbox.checked = this.options.state;
            this.checkbox.disabled = this.options.disabled;

            this.checkbox.addEventListener('change', (e) => this.handleChange(e));
        }

        handleChange(e) {
            const newState = e.target.checked;

            if (this.options.confirmDanger && newState) {
                if (!confirm(this.options.confirmMessage)) {
                    e.target.checked = !newState;
                    return;
                }
            }

            if (this.options.onChange) {
                this.options.onChange(newState, this);
            }
        }

        setState(state) {
            this.checkbox.checked = state;
        }

        getState() {
            return this.checkbox.checked;
        }

        disable() {
            this.checkbox.disabled = true;
            this.element.classList.add('disabled');
        }

        enable() {
            this.checkbox.disabled = false;
            this.element.classList.remove('disabled');
        }
    }

    Fortress.Toggle = FortressToggle;

    // ============================================================
    // LEVEL SLIDER
    // ============================================================
    class FortressLevelSlider {
        constructor(element, options = {}) {
            this.element = typeof element === 'string' ? document.querySelector(element) : element;
            if (!this.element) return;

            this.options = {
                levels: [],
                current: 0,
                onChange: null,
                ...options
            };

            this.init();
        }

        init() {
            this.element.classList.add('level-slider');
            this.render();
            this.bindEvents();
        }

        render() {
            this.element.innerHTML = `
                <div class="level-track">
                    ${this.options.levels.map((level, i) => `
                        <button class="level-pip ${i === this.options.current ? 'active' : ''}"
                                data-level="${i}"
                                title="${level.label}">
                            <span class="level-label">${level.label}</span>
                        </button>
                    `).join('')}
                    <div class="level-fill" style="width: ${(this.options.current / (this.options.levels.length - 1)) * 100}%"></div>
                </div>
                <div class="level-description">${this.options.levels[this.options.current]?.description || ''}</div>
            `;

            this.fill = this.element.querySelector('.level-fill');
            this.description = this.element.querySelector('.level-description');
        }

        bindEvents() {
            this.element.querySelectorAll('.level-pip').forEach(pip => {
                pip.addEventListener('click', (e) => {
                    const level = parseInt(e.currentTarget.dataset.level);
                    this.setLevel(level);
                });
            });
        }

        setLevel(level) {
            if (level < 0 || level >= this.options.levels.length) return;

            this.options.current = level;

            // Update UI
            this.element.querySelectorAll('.level-pip').forEach((pip, i) => {
                pip.classList.toggle('active', i === level);
            });

            this.fill.style.width = `${(level / (this.options.levels.length - 1)) * 100}%`;
            this.description.textContent = this.options.levels[level]?.description || '';

            if (this.options.onChange) {
                this.options.onChange(level, this.options.levels[level]);
            }
        }

        getLevel() {
            return this.options.current;
        }
    }

    Fortress.LevelSlider = FortressLevelSlider;

    // ============================================================
    // DATA TABLE COMPONENT
    // ============================================================
    class FortressTable {
        constructor(element, options = {}) {
            this.element = typeof element === 'string' ? document.querySelector(element) : element;
            if (!this.element) return;

            this.options = {
                columns: [],
                data: [],
                sortable: true,
                filterable: true,
                pageSize: 10,
                emptyMessage: 'No data available',
                onRowClick: null,
                onSort: null,
                onFilter: null,
                ...options
            };

            this.currentSort = { column: null, direction: 'asc' };
            this.currentFilter = '';
            this.currentPage = 1;

            this.init();
        }

        init() {
            this.element.classList.add('data-table-wrapper');
            this.render();
            this.bindEvents();
        }

        render() {
            const filteredData = this.getFilteredData();
            const paginatedData = this.getPaginatedData(filteredData);

            this.element.innerHTML = `
                ${this.options.filterable ? this.renderFilter() : ''}
                <table class="data-table">
                    <thead>
                        <tr>
                            ${this.options.columns.map(col => `
                                <th class="${this.options.sortable ? 'sortable' : ''}"
                                    data-key="${col.key}"
                                    data-sort="${this.currentSort.column === col.key ? this.currentSort.direction : ''}">
                                    ${col.label}
                                    ${this.options.sortable ? '<span class="sort-icon"></span>' : ''}
                                </th>
                            `).join('')}
                        </tr>
                    </thead>
                    <tbody>
                        ${paginatedData.length ? paginatedData.map(row => this.renderRow(row)).join('') :
                          `<tr class="empty-row"><td colspan="${this.options.columns.length}">${this.options.emptyMessage}</td></tr>`}
                    </tbody>
                </table>
                ${this.renderPagination(filteredData.length)}
            `;
        }

        renderFilter() {
            return `
                <div class="filter-bar">
                    <div class="search-box">
                        <i class="fas fa-search"></i>
                        <input type="text" class="filter-input" placeholder="Search..." value="${this.currentFilter}">
                    </div>
                </div>
            `;
        }

        renderRow(row) {
            return `
                <tr data-id="${row.id || ''}" class="${this.options.onRowClick ? 'clickable' : ''}">
                    ${this.options.columns.map(col => `
                        <td data-label="${col.label}">
                            ${col.render ? col.render(row[col.key], row) : this.escapeHtml(row[col.key])}
                        </td>
                    `).join('')}
                </tr>
            `;
        }

        renderPagination(totalItems) {
            const totalPages = Math.ceil(totalItems / this.options.pageSize);
            if (totalPages <= 1) return '';

            return `
                <div class="table-pagination">
                    <button class="page-btn" data-page="prev" ${this.currentPage === 1 ? 'disabled' : ''}>
                        <i class="fas fa-chevron-left"></i>
                    </button>
                    <span class="page-info">${this.currentPage} / ${totalPages}</span>
                    <button class="page-btn" data-page="next" ${this.currentPage === totalPages ? 'disabled' : ''}>
                        <i class="fas fa-chevron-right"></i>
                    </button>
                </div>
            `;
        }

        bindEvents() {
            // Sort
            this.element.querySelectorAll('th.sortable').forEach(th => {
                th.addEventListener('click', () => this.sort(th.dataset.key));
            });

            // Filter
            const filterInput = this.element.querySelector('.filter-input');
            if (filterInput) {
                filterInput.addEventListener('input', Utils.debounce((e) => {
                    this.filter(e.target.value);
                }, 300));
            }

            // Pagination
            this.element.querySelectorAll('.page-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    if (btn.dataset.page === 'prev') this.prevPage();
                    else if (btn.dataset.page === 'next') this.nextPage();
                });
            });

            // Row click
            if (this.options.onRowClick) {
                this.element.querySelectorAll('tbody tr.clickable').forEach(row => {
                    row.addEventListener('click', () => {
                        const id = row.dataset.id;
                        const data = this.options.data.find(d => String(d.id) === id);
                        this.options.onRowClick(data, row);
                    });
                });
            }
        }

        sort(column) {
            if (this.currentSort.column === column) {
                this.currentSort.direction = this.currentSort.direction === 'asc' ? 'desc' : 'asc';
            } else {
                this.currentSort.column = column;
                this.currentSort.direction = 'asc';
            }

            if (this.options.onSort) {
                this.options.onSort(this.currentSort);
            }

            this.render();
            this.bindEvents();
        }

        filter(value) {
            this.currentFilter = value.toLowerCase();
            this.currentPage = 1;

            if (this.options.onFilter) {
                this.options.onFilter(value);
            }

            this.render();
            this.bindEvents();
        }

        getFilteredData() {
            if (!this.currentFilter) return [...this.options.data];

            return this.options.data.filter(row => {
                return this.options.columns.some(col => {
                    const value = String(row[col.key] || '').toLowerCase();
                    return value.includes(this.currentFilter);
                });
            });
        }

        getSortedData(data) {
            if (!this.currentSort.column) return data;

            return [...data].sort((a, b) => {
                const aVal = a[this.currentSort.column];
                const bVal = b[this.currentSort.column];

                if (aVal < bVal) return this.currentSort.direction === 'asc' ? -1 : 1;
                if (aVal > bVal) return this.currentSort.direction === 'asc' ? 1 : -1;
                return 0;
            });
        }

        getPaginatedData(data) {
            const sorted = this.getSortedData(data);
            const start = (this.currentPage - 1) * this.options.pageSize;
            return sorted.slice(start, start + this.options.pageSize);
        }

        prevPage() {
            if (this.currentPage > 1) {
                this.currentPage--;
                this.render();
                this.bindEvents();
            }
        }

        nextPage() {
            const totalPages = Math.ceil(this.getFilteredData().length / this.options.pageSize);
            if (this.currentPage < totalPages) {
                this.currentPage++;
                this.render();
                this.bindEvents();
            }
        }

        setData(data) {
            this.options.data = data;
            this.currentPage = 1;
            this.render();
            this.bindEvents();
        }

        escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    }

    Fortress.Table = FortressTable;

    // ============================================================
    // TIMELINE COMPONENT
    // ============================================================
    class FortressTimeline {
        constructor(element, options = {}) {
            this.element = typeof element === 'string' ? document.querySelector(element) : element;
            if (!this.element) return;

            this.options = {
                events: [],
                maxVisible: 10,
                animated: true,
                onEventClick: null,
                ...options
            };

            this.init();
        }

        init() {
            this.element.classList.add('timeline');
            this.render();
        }

        render() {
            const events = this.options.events.slice(0, this.options.maxVisible);

            this.element.innerHTML = events.map((event, i) => `
                <div class="timeline-event ${this.options.animated ? 'animate-in' : ''}"
                     data-index="${i}"
                     style="animation-delay: ${i * 50}ms">
                    <div class="timeline-marker" data-severity="${event.severity || 'info'}"></div>
                    <div class="timeline-content">
                        <div class="timeline-header">
                            <span class="timeline-time">${this.formatTime(event.timestamp)}</span>
                            <span class="timeline-type">${event.type || ''}</span>
                        </div>
                        <div class="timeline-body">${event.message}</div>
                        ${event.details ? `<div class="timeline-details">${event.details}</div>` : ''}
                    </div>
                </div>
            `).join('');

            if (this.options.onEventClick) {
                this.element.querySelectorAll('.timeline-event').forEach(el => {
                    el.addEventListener('click', () => {
                        const index = parseInt(el.dataset.index);
                        this.options.onEventClick(this.options.events[index], el);
                    });
                });
            }
        }

        formatTime(timestamp) {
            const date = new Date(timestamp);
            const now = new Date();
            const diff = now - date;

            if (diff < 60000) return 'Just now';
            if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
            if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
            return date.toLocaleDateString();
        }

        addEvent(event, prepend = true) {
            if (prepend) {
                this.options.events.unshift(event);
            } else {
                this.options.events.push(event);
            }
            this.render();
        }

        setEvents(events) {
            this.options.events = events;
            this.render();
        }
    }

    Fortress.Timeline = FortressTimeline;

    // ============================================================
    // SLIDE PANEL COMPONENT
    // ============================================================
    class FortressPanel {
        constructor(options = {}) {
            this.options = {
                position: 'right',
                width: '400px',
                overlay: true,
                closeOnOverlay: true,
                closeOnEscape: true,
                onOpen: null,
                onClose: null,
                ...options
            };

            this.isOpen = false;
            this.init();
        }

        init() {
            // Create panel element
            this.panel = document.createElement('div');
            this.panel.className = `slide-panel slide-panel-${this.options.position}`;
            this.panel.style.width = this.options.width;
            this.panel.innerHTML = `
                <div class="panel-header">
                    <h3 class="panel-title"></h3>
                    <button class="panel-close"><i class="fas fa-times"></i></button>
                </div>
                <div class="panel-content"></div>
            `;

            // Create overlay
            if (this.options.overlay) {
                this.overlay = document.createElement('div');
                this.overlay.className = 'panel-overlay';
                document.body.appendChild(this.overlay);

                if (this.options.closeOnOverlay) {
                    this.overlay.addEventListener('click', () => this.close());
                }
            }

            document.body.appendChild(this.panel);

            // Close button
            this.panel.querySelector('.panel-close').addEventListener('click', () => this.close());

            // Escape key
            if (this.options.closeOnEscape) {
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape' && this.isOpen) this.close();
                });
            }
        }

        open(title, content) {
            this.panel.querySelector('.panel-title').textContent = title;

            const contentEl = this.panel.querySelector('.panel-content');
            if (typeof content === 'string') {
                contentEl.innerHTML = content;
            } else {
                contentEl.innerHTML = '';
                contentEl.appendChild(content);
            }

            this.panel.classList.add('open');
            if (this.overlay) this.overlay.classList.add('visible');
            this.isOpen = true;

            if (this.options.onOpen) this.options.onOpen(this);
        }

        close() {
            this.panel.classList.remove('open');
            if (this.overlay) this.overlay.classList.remove('visible');
            this.isOpen = false;

            if (this.options.onClose) this.options.onClose(this);
        }

        destroy() {
            this.panel.remove();
            if (this.overlay) this.overlay.remove();
        }
    }

    Fortress.Panel = FortressPanel;

    // ============================================================
    // TOAST NOTIFICATION SYSTEM
    // ============================================================
    const Toast = {
        container: null,

        init() {
            if (this.container) return;
            this.container = document.createElement('div');
            this.container.className = 'toast-container';
            document.body.appendChild(this.container);
        },

        show(message, type = 'info', duration = 3000) {
            this.init();

            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.innerHTML = `
                <i class="toast-icon fas ${this.getIcon(type)}"></i>
                <span class="toast-message">${message}</span>
                <button class="toast-close"><i class="fas fa-times"></i></button>
            `;

            this.container.appendChild(toast);

            // Trigger animation
            requestAnimationFrame(() => toast.classList.add('show'));

            // Close button
            toast.querySelector('.toast-close').addEventListener('click', () => this.dismiss(toast));

            // Auto dismiss
            if (duration > 0) {
                setTimeout(() => this.dismiss(toast), duration);
            }

            return toast;
        },

        dismiss(toast) {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        },

        getIcon(type) {
            const icons = {
                success: 'fa-check-circle',
                error: 'fa-exclamation-circle',
                warning: 'fa-exclamation-triangle',
                info: 'fa-info-circle'
            };
            return icons[type] || icons.info;
        },

        success(message, duration) { return this.show(message, 'success', duration); },
        error(message, duration) { return this.show(message, 'error', duration); },
        warning(message, duration) { return this.show(message, 'warning', duration); },
        info(message, duration) { return this.show(message, 'info', duration); }
    };

    Fortress.Toast = Toast;

    // ============================================================
    // STATUS BADGE FACTORY
    // ============================================================
    const StatusBadge = {
        rag(status) {
            return `<span class="status-badge rag-${status.toLowerCase()}">${status}</span>`;
        },

        device(status) {
            const statusMap = {
                online: 'success',
                offline: 'danger',
                warning: 'warning',
                unknown: 'secondary'
            };
            return `<span class="status-badge device-${statusMap[status] || 'secondary'}">${status}</span>`;
        },

        wan(status) {
            return `<span class="status-badge wan-${status.toLowerCase()}">${status}</span>`;
        },

        severity(level) {
            return `<span class="status-badge severity-${level.toLowerCase()}">${level}</span>`;
        }
    };

    Fortress.StatusBadge = StatusBadge;

    // ============================================================
    // STAT CARD FACTORY
    // ============================================================
    const StatCard = {
        create(options = {}) {
            const {
                title = '',
                value = 0,
                unit = '',
                icon = 'fa-chart-line',
                trend = null,
                variant = '',
                id = Utils.uid()
            } = options;

            const trendHtml = trend ? `
                <div class="stat-trend ${trend.direction}">
                    <i class="fas fa-arrow-${trend.direction === 'up' ? 'up' : 'down'}"></i>
                    ${trend.value}
                </div>
            ` : '';

            return `
                <div class="stat-card ${variant}" id="${id}">
                    <div class="stat-icon"><i class="fas ${icon}"></i></div>
                    <div class="stat-content">
                        <div class="stat-label">${title}</div>
                        <div class="stat-value">${Utils.formatNumber(value)}<span class="stat-unit">${unit}</span></div>
                    </div>
                    ${trendHtml}
                </div>
            `;
        }
    };

    Fortress.StatCard = StatCard;

    // ============================================================
    // SUB-TABS COMPONENT
    // ============================================================
    class FortressSubTabs {
        constructor(element, options = {}) {
            this.element = typeof element === 'string' ? document.querySelector(element) : element;
            if (!this.element) return;

            this.options = {
                tabs: [],
                activeTab: 0,
                onChange: null,
                ...options
            };

            this.init();
        }

        init() {
            this.element.classList.add('sub-tabs');
            this.render();
            this.bindEvents();
        }

        render() {
            this.element.innerHTML = `
                <div class="sub-tabs-nav">
                    ${this.options.tabs.map((tab, i) => `
                        <button class="sub-tab ${i === this.options.activeTab ? 'active' : ''}"
                                data-index="${i}">
                            ${tab.icon ? `<i class="fas ${tab.icon}"></i>` : ''}
                            ${tab.label}
                        </button>
                    `).join('')}
                </div>
                <div class="sub-tabs-content">
                    ${this.options.tabs.map((tab, i) => `
                        <div class="sub-tab-pane ${i === this.options.activeTab ? 'active' : ''}"
                             data-index="${i}">
                            ${tab.content || ''}
                        </div>
                    `).join('')}
                </div>
            `;
        }

        bindEvents() {
            this.element.querySelectorAll('.sub-tab').forEach(btn => {
                btn.addEventListener('click', () => {
                    const index = parseInt(btn.dataset.index);
                    this.setActive(index);
                });
            });
        }

        setActive(index) {
            this.options.activeTab = index;

            this.element.querySelectorAll('.sub-tab').forEach((btn, i) => {
                btn.classList.toggle('active', i === index);
            });

            this.element.querySelectorAll('.sub-tab-pane').forEach((pane, i) => {
                pane.classList.toggle('active', i === index);
            });

            if (this.options.onChange) {
                this.options.onChange(index, this.options.tabs[index]);
            }
        }

        getActiveIndex() {
            return this.options.activeTab;
        }
    }

    Fortress.SubTabs = FortressSubTabs;

    // ============================================================
    // HEALTH BAR COMPONENT
    // ============================================================
    class FortressHealthBar {
        constructor(element, options = {}) {
            this.element = typeof element === 'string' ? document.querySelector(element) : element;
            if (!this.element) return;

            this.options = {
                value: 0,
                max: 100,
                label: '',
                showValue: true,
                animated: true,
                thresholds: { good: 70, warning: 40 },
                ...options
            };

            this.init();
        }

        init() {
            this.element.classList.add('health-bar');
            this.render();
            if (this.options.animated) {
                requestAnimationFrame(() => this.setValue(this.options.value));
            }
        }

        render() {
            this.element.innerHTML = `
                ${this.options.label ? `<div class="health-label">${this.options.label}</div>` : ''}
                <div class="health-track">
                    <div class="health-fill" style="width: 0%"></div>
                </div>
                ${this.options.showValue ? `<div class="health-value">0%</div>` : ''}
            `;

            this.fill = this.element.querySelector('.health-fill');
            this.valueEl = this.element.querySelector('.health-value');
        }

        setValue(value) {
            const percentage = Math.min(Math.max((value / this.options.max) * 100, 0), 100);

            // Determine status
            let status = 'critical';
            if (percentage >= this.options.thresholds.good) status = 'good';
            else if (percentage >= this.options.thresholds.warning) status = 'warning';

            this.fill.setAttribute('data-status', status);
            this.fill.style.width = `${percentage}%`;

            if (this.valueEl) {
                this.valueEl.textContent = `${Math.round(percentage)}%`;
            }
        }
    }

    Fortress.HealthBar = FortressHealthBar;

    // ============================================================
    // REAL-TIME DATA POLLER
    // ============================================================
    class FortressPoller {
        constructor(options = {}) {
            this.options = {
                url: '',
                interval: 5000,
                onData: null,
                onError: null,
                ...options
            };

            this.active = false;
            this.timer = null;
        }

        start() {
            if (this.active) return;
            this.active = true;
            this.poll();
        }

        stop() {
            this.active = false;
            if (this.timer) {
                clearTimeout(this.timer);
                this.timer = null;
            }
        }

        async poll() {
            if (!this.active) return;

            try {
                const response = await fetch(this.options.url);
                const data = await response.json();

                if (this.options.onData) {
                    this.options.onData(data);
                }
            } catch (error) {
                if (this.options.onError) {
                    this.options.onError(error);
                }
            }

            if (this.active) {
                this.timer = setTimeout(() => this.poll(), this.options.interval);
            }
        }
    }

    Fortress.Poller = FortressPoller;

    // ============================================================
    // AUTO-INITIALIZATION
    // ============================================================
    function autoInit() {
        // Auto-init gauges
        document.querySelectorAll('[data-gauge]').forEach(el => {
            const value = parseFloat(el.dataset.gaugeValue) || 0;
            const max = parseFloat(el.dataset.gaugeMax) || 100;
            new FortressGauge(el, { value, max });
        });

        // Auto-init toggles
        document.querySelectorAll('[data-toggle]').forEach(el => {
            const confirmDanger = el.dataset.toggleConfirm === 'true';
            new FortressToggle(el, { confirmDanger });
        });

        // Auto-init health bars
        document.querySelectorAll('[data-health]').forEach(el => {
            const value = parseFloat(el.dataset.healthValue) || 0;
            const label = el.dataset.healthLabel || '';
            new FortressHealthBar(el, { value, label });
        });

        Fortress.initialized = true;
    }

    // Run auto-init on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', autoInit);
    } else {
        autoInit();
    }

    // ============================================================
    // EXPORT TO WINDOW
    // ============================================================
    window.Fortress = Fortress;

})(window);
