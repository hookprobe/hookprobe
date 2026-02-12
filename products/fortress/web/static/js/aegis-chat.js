/**
 * AEGIS Chat Interface
 *
 * Handles chat messaging, status polling, quick actions,
 * and markdown rendering for the ORACLE agent.
 */

(function () {
    'use strict';

    // DOM elements
    var messagesEl = document.getElementById('chat-messages');
    var inputEl = document.getElementById('chat-input');
    var formEl = document.getElementById('chat-form');
    var sendBtn = document.getElementById('send-btn');
    var clearBtn = document.getElementById('clear-chat-btn');
    var typingEl = document.getElementById('typing-indicator');
    var sessionEl = document.getElementById('aegis-session-id');

    var sessionId = sessionEl ? sessionEl.value : '';
    var isSending = false;

    // Configure marked for safe rendering
    if (typeof marked !== 'undefined') {
        marked.setOptions({
            breaks: true,
            gfm: true,
        });
    }

    // ------------------------------------------------------------------
    // Chat messaging
    // ------------------------------------------------------------------

    function sendMessage(text) {
        if (!text || !text.trim() || isSending) return;

        text = text.trim();
        isSending = true;
        sendBtn.disabled = true;
        inputEl.disabled = true;

        // Add user message
        appendMessage('user', text);

        // Show typing indicator
        showTyping(true);

        // Send to API
        fetch('/aegis/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: text, session_id: sessionId }),
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                showTyping(false);

                if (data.session_id) {
                    sessionId = data.session_id;
                }

                var content = data.message || 'No response received.';
                var meta = data.agent || 'ORACLE';
                if (data.sources && data.sources.length) {
                    meta += ' | ' + data.sources.join(', ');
                }

                appendMessage('assistant', content, meta);
            })
            .catch(function (err) {
                showTyping(false);
                appendMessage('assistant', 'Connection error. Please try again.', 'ORACLE | error');
                console.error('AEGIS chat error:', err);
            })
            .finally(function () {
                isSending = false;
                sendBtn.disabled = false;
                inputEl.disabled = false;
                inputEl.focus();
            });
    }

    function appendMessage(role, content, meta) {
        var wrapper = document.createElement('div');
        wrapper.className = 'chat-message ' + role;

        var avatar = document.createElement('div');
        avatar.className = 'chat-avatar';
        if (role === 'assistant') {
            avatar.innerHTML = '<i class="fas fa-robot"></i>';
        } else {
            avatar.innerHTML = '<i class="fas fa-user"></i>';
        }

        var inner = document.createElement('div');

        var bubble = document.createElement('div');
        bubble.className = 'chat-bubble';

        // Render markdown for assistant messages
        if (role === 'assistant' && typeof marked !== 'undefined') {
            bubble.innerHTML = marked.parse(content);
        } else {
            bubble.textContent = content;
        }

        inner.appendChild(bubble);

        if (meta) {
            var metaEl = document.createElement('div');
            metaEl.className = 'chat-meta';
            metaEl.textContent = meta;
            inner.appendChild(metaEl);
        }

        wrapper.appendChild(avatar);
        wrapper.appendChild(inner);

        // Insert before typing indicator
        messagesEl.insertBefore(wrapper, typingEl);
        scrollToBottom();
    }

    function showTyping(show) {
        if (show) {
            typingEl.classList.add('active');
        } else {
            typingEl.classList.remove('active');
        }
        scrollToBottom();
    }

    function scrollToBottom() {
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    // ------------------------------------------------------------------
    // Status polling
    // ------------------------------------------------------------------

    function pollStatus() {
        fetch('/aegis/api/status')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var dot = document.getElementById('llm-status-dot');
                var txt = document.getElementById('llm-status-text');
                var model = document.getElementById('llm-model-name');
                var uptime = document.getElementById('llm-uptime');
                var ragBadge = document.getElementById('aegis-rag-badge');
                var tierEl = document.getElementById('llm-tier');
                var inferenceEl = document.getElementById('llm-inference-ms');

                if (data.llm_ready) {
                    dot.className = 'status-indicator online';
                    txt.textContent = 'Ready';
                } else if (data.loading) {
                    dot.className = 'status-indicator loading';
                    txt.textContent = 'Loading model...';
                } else {
                    dot.className = 'status-indicator offline';
                    txt.textContent = 'Offline (template mode)';
                }

                model.textContent = data.model_name || '—';

                if (tierEl) {
                    var tierLabels = {
                        'cloud': 'Cloud LLM',
                        'template': 'Template',
                        'loading': 'Initializing...',
                        'unavailable': 'Unavailable'
                    };
                    tierEl.textContent = tierLabels[data.tier] || data.tier || '—';
                }

                if (inferenceEl) {
                    inferenceEl.textContent = data.avg_inference_ms
                        ? Math.round(data.avg_inference_ms) + 'ms'
                        : '—';
                }

                if (data.uptime) {
                    var mins = Math.floor(data.uptime / 60);
                    var hrs = Math.floor(mins / 60);
                    if (hrs > 0) {
                        uptime.textContent = hrs + 'h ' + (mins % 60) + 'm';
                    } else {
                        uptime.textContent = mins + 'm';
                    }
                }

                // Fetch QSecBit status for the badge
                fetch('/api/status')
                    .then(function (r) { return r.json(); })
                    .then(function (status) {
                        if (status.qsecbit && status.qsecbit.status) {
                            var rag = status.qsecbit.status.toUpperCase();
                            ragBadge.textContent = rag;
                            ragBadge.className = 'badge rag-' + rag.toLowerCase();
                        }
                    })
                    .catch(function () { });
            })
            .catch(function () {
                var dot = document.getElementById('llm-status-dot');
                var txt = document.getElementById('llm-status-text');
                if (dot) dot.className = 'status-indicator offline';
                if (txt) txt.textContent = 'Unreachable';
            });
    }

    // ------------------------------------------------------------------
    // Event handlers
    // ------------------------------------------------------------------

    // Form submit
    formEl.addEventListener('submit', function (e) {
        e.preventDefault();
        sendMessage(inputEl.value);
        inputEl.value = '';
    });

    // Quick action buttons
    document.querySelectorAll('.quick-action-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var msg = this.getAttribute('data-message');
            if (msg) {
                inputEl.value = msg;
                sendMessage(msg);
                inputEl.value = '';
            }
        });
    });

    // Clear chat
    clearBtn.addEventListener('click', function () {
        fetch('/aegis/api/clear', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId }),
        }).then(function () {
            // Remove all messages except welcome and typing indicator
            var messages = messagesEl.querySelectorAll('.chat-message:not(.typing-indicator)');
            messages.forEach(function (msg, idx) {
                if (idx > 0) msg.remove(); // Keep first (welcome)
            });
            toastr.info('Conversation cleared');
        });
    });

    // Enter to send (Shift+Enter for newline not needed with single-line input)
    inputEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            formEl.dispatchEvent(new Event('submit'));
        }
    });

    // ------------------------------------------------------------------
    // Init
    // ------------------------------------------------------------------

    pollStatus();
    setInterval(pollStatus, 30000);
    inputEl.focus();

})();
