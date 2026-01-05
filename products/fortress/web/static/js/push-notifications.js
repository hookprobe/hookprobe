/**
 * AIOCHI Push Notifications
 * Client-side push notification management for AI Eyes
 */

(function() {
    'use strict';

    // VAPID public key (generated during setup)
    // This will be replaced with actual key during installation
    const VAPID_PUBLIC_KEY = 'BEl62iUYgUivxIkv69yViEuiBIa-Ib9-SkvMeAtA3LFgDzkrxZJjSgSnfckjBJuBkr3qBUYIHBQFLXYp5Nksh8U';

    const PushNotifications = {
        isSupported: false,
        subscription: null,

        /**
         * Initialize push notifications
         */
        async init() {
            // Check for support
            if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
                console.log('[AIOCHI Push] Push notifications not supported');
                return false;
            }

            // Service workers require valid HTTPS (not self-signed) or localhost
            // Skip initialization if we're on an IP address with self-signed cert
            const hostname = window.location.hostname;
            const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';
            const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

            if (isIP && !isLocalhost) {
                // Accessing via IP with likely self-signed cert - skip service worker
                console.log('[AIOCHI Push] Service workers not available on IP addresses with self-signed certificates');
                console.log('[AIOCHI Push] Use a domain with valid HTTPS or Cloudflare Tunnel for push notifications');
                return false;
            }

            this.isSupported = true;
            console.log('[AIOCHI Push] Push notifications supported');

            // Register service worker
            try {
                const registration = await navigator.serviceWorker.register('/static/js/service-worker.js');
                console.log('[AIOCHI Push] Service worker registered:', registration.scope);

                // Check current permission status
                const permission = Notification.permission;
                console.log('[AIOCHI Push] Current permission:', permission);

                if (permission === 'granted') {
                    await this.subscribe(registration);
                }

                return true;
            } catch (error) {
                // SSL certificate errors are expected when using self-signed certs
                if (error.name === 'SecurityError') {
                    console.log('[AIOCHI Push] Service worker blocked due to SSL certificate');
                    console.log('[AIOCHI Push] Configure Cloudflare Tunnel or use a valid HTTPS certificate for push notifications');
                    this.isSupported = false;
                    return false;
                }
                console.error('[AIOCHI Push] Service worker registration failed:', error);
                return false;
            }
        },

        /**
         * Request notification permission
         */
        async requestPermission() {
            if (!this.isSupported) {
                console.log('[AIOCHI Push] Not supported');
                return false;
            }

            try {
                const permission = await Notification.requestPermission();
                console.log('[AIOCHI Push] Permission result:', permission);

                if (permission === 'granted') {
                    const registration = await navigator.serviceWorker.ready;
                    await this.subscribe(registration);
                    return true;
                }

                return false;
            } catch (error) {
                console.error('[AIOCHI Push] Permission request failed:', error);
                return false;
            }
        },

        /**
         * Subscribe to push notifications
         */
        async subscribe(registration) {
            try {
                // Convert VAPID key to Uint8Array
                const applicationServerKey = this.urlBase64ToUint8Array(VAPID_PUBLIC_KEY);

                // Subscribe
                const subscription = await registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: applicationServerKey
                });

                this.subscription = subscription;
                console.log('[AIOCHI Push] Subscribed:', JSON.stringify(subscription));

                // Send subscription to server
                await this.sendSubscriptionToServer(subscription);

                return subscription;
            } catch (error) {
                console.error('[AIOCHI Push] Subscription failed:', error);
                return null;
            }
        },

        /**
         * Unsubscribe from push notifications
         */
        async unsubscribe() {
            try {
                const registration = await navigator.serviceWorker.ready;
                const subscription = await registration.pushManager.getSubscription();

                if (subscription) {
                    await subscription.unsubscribe();
                    await this.removeSubscriptionFromServer(subscription);
                    this.subscription = null;
                    console.log('[AIOCHI Push] Unsubscribed');
                    return true;
                }

                return false;
            } catch (error) {
                console.error('[AIOCHI Push] Unsubscribe failed:', error);
                return false;
            }
        },

        /**
         * Send subscription to server
         */
        async sendSubscriptionToServer(subscription) {
            try {
                const response = await fetch('/aiochi/api/push/subscribe', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        subscription: subscription.toJSON(),
                        preferences: this.getPreferences()
                    })
                });

                const data = await response.json();
                console.log('[AIOCHI Push] Server response:', data);
                return data.success;
            } catch (error) {
                console.error('[AIOCHI Push] Failed to send subscription to server:', error);
                return false;
            }
        },

        /**
         * Remove subscription from server
         */
        async removeSubscriptionFromServer(subscription) {
            try {
                await fetch('/aiochi/api/push/unsubscribe', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        endpoint: subscription.endpoint
                    })
                });
                return true;
            } catch (error) {
                console.error('[AIOCHI Push] Failed to remove subscription:', error);
                return false;
            }
        },

        /**
         * Get notification preferences from localStorage
         */
        getPreferences() {
            const defaults = {
                security_alerts: true,
                device_events: true,
                performance_alerts: true,
                quiet_hours_start: null,
                quiet_hours_end: null
            };

            try {
                const stored = localStorage.getItem('aiochi_push_preferences');
                return stored ? { ...defaults, ...JSON.parse(stored) } : defaults;
            } catch {
                return defaults;
            }
        },

        /**
         * Save notification preferences
         */
        savePreferences(preferences) {
            try {
                localStorage.setItem('aiochi_push_preferences', JSON.stringify(preferences));
                // Update server
                this.sendSubscriptionToServer(this.subscription);
                return true;
            } catch {
                return false;
            }
        },

        /**
         * Check if subscribed
         */
        async isSubscribed() {
            try {
                const registration = await navigator.serviceWorker.ready;
                const subscription = await registration.pushManager.getSubscription();
                return subscription !== null;
            } catch {
                return false;
            }
        },

        /**
         * Get current subscription
         */
        async getSubscription() {
            try {
                const registration = await navigator.serviceWorker.ready;
                return await registration.pushManager.getSubscription();
            } catch {
                return null;
            }
        },

        /**
         * Show local notification (for testing)
         */
        async showLocalNotification(title, options = {}) {
            if (Notification.permission !== 'granted') {
                console.log('[AIOCHI Push] Permission not granted');
                return false;
            }

            const registration = await navigator.serviceWorker.ready;
            await registration.showNotification(title, {
                icon: '/static/images/aiochi-icon-192.png',
                badge: '/static/images/aiochi-badge.png',
                ...options
            });

            return true;
        },

        /**
         * Convert VAPID key from base64 to Uint8Array
         */
        urlBase64ToUint8Array(base64String) {
            const padding = '='.repeat((4 - base64String.length % 4) % 4);
            const base64 = (base64String + padding)
                .replace(/-/g, '+')
                .replace(/_/g, '/');

            const rawData = window.atob(base64);
            const outputArray = new Uint8Array(rawData.length);

            for (let i = 0; i < rawData.length; ++i) {
                outputArray[i] = rawData.charCodeAt(i);
            }

            return outputArray;
        }
    };

    // Export to window
    window.AIOCHIPush = PushNotifications;

    // Auto-initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => PushNotifications.init());
    } else {
        PushNotifications.init();
    }

})();
