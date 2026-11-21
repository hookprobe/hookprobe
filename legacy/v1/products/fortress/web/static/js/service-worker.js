/**
 * AIOCHI Service Worker
 * Provides offline support and push notifications for AI Eyes dashboard
 */

const CACHE_NAME = 'aiochi-v1';
const OFFLINE_URL = '/static/offline.html';

// Resources to cache for offline use
const PRECACHE_RESOURCES = [
    '/',
    '/aiochi/',
    '/static/css/components.css',
    '/static/manifest.json',
    OFFLINE_URL,
    // CDN resources - cache for performance
    'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css',
    'https://cdn.jsdelivr.net/npm/admin-lte@3.2.0/dist/css/adminlte.min.css'
];

// Install event - precache essential resources
self.addEventListener('install', (event) => {
    console.log('[AIOCHI SW] Installing service worker...');
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('[AIOCHI SW] Precaching resources');
                return cache.addAll(PRECACHE_RESOURCES);
            })
            .then(() => self.skipWaiting())
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
    console.log('[AIOCHI SW] Activating service worker...');
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames
                    .filter((name) => name !== CACHE_NAME)
                    .map((name) => {
                        console.log('[AIOCHI SW] Deleting old cache:', name);
                        return caches.delete(name);
                    })
            );
        }).then(() => self.clients.claim())
    );
});

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', (event) => {
    // Skip non-GET requests
    if (event.request.method !== 'GET') return;

    // Skip API requests (always go to network)
    if (event.request.url.includes('/api/')) return;

    event.respondWith(
        caches.match(event.request)
            .then((cachedResponse) => {
                if (cachedResponse) {
                    // Return cached version
                    return cachedResponse;
                }

                // Fetch from network
                return fetch(event.request)
                    .then((response) => {
                        // Don't cache bad responses
                        if (!response || response.status !== 200 || response.type !== 'basic') {
                            return response;
                        }

                        // Clone the response
                        const responseToCache = response.clone();

                        // Cache the new resource
                        caches.open(CACHE_NAME)
                            .then((cache) => {
                                cache.put(event.request, responseToCache);
                            });

                        return response;
                    })
                    .catch(() => {
                        // If offline and navigating, show offline page
                        if (event.request.mode === 'navigate') {
                            return caches.match(OFFLINE_URL);
                        }
                    });
            })
    );
});

// Push notification event
self.addEventListener('push', (event) => {
    console.log('[AIOCHI SW] Push notification received');

    let data = {
        title: 'AI Eyes Alert',
        body: 'New security event detected',
        icon: '/static/images/aiochi-icon-192.png',
        badge: '/static/images/aiochi-badge.png',
        tag: 'aiochi-alert',
        requireInteraction: false,
        data: {}
    };

    if (event.data) {
        try {
            const payload = event.data.json();
            data = { ...data, ...payload };
        } catch (e) {
            data.body = event.data.text();
        }
    }

    // Customize notification based on type
    const options = {
        body: data.body,
        icon: data.icon,
        badge: data.badge,
        tag: data.tag,
        requireInteraction: data.severity === 'critical',
        vibrate: data.severity === 'critical' ? [200, 100, 200, 100, 200] : [100, 50, 100],
        data: data.data,
        actions: []
    };

    // Add actions based on notification type
    if (data.type === 'security') {
        options.actions = [
            { action: 'view', title: 'View Details', icon: '/static/images/view-icon.png' },
            { action: 'dismiss', title: 'Dismiss', icon: '/static/images/dismiss-icon.png' }
        ];
    } else if (data.type === 'device') {
        options.actions = [
            { action: 'view', title: 'View Device', icon: '/static/images/device-icon.png' },
            { action: 'block', title: 'Block', icon: '/static/images/block-icon.png' }
        ];
    }

    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

// Notification click event
self.addEventListener('notificationclick', (event) => {
    console.log('[AIOCHI SW] Notification clicked:', event.action);
    event.notification.close();

    const urlToOpen = event.notification.data?.url || '/aiochi/';

    if (event.action === 'view') {
        event.waitUntil(
            clients.matchAll({ type: 'window', includeUncontrolled: true })
                .then((windowClients) => {
                    // Focus existing window if open
                    for (const client of windowClients) {
                        if (client.url.includes('/aiochi') && 'focus' in client) {
                            return client.focus();
                        }
                    }
                    // Otherwise open new window
                    return clients.openWindow(urlToOpen);
                })
        );
    } else if (event.action === 'block') {
        // Send block action to server
        event.waitUntil(
            fetch('/aiochi/api/action/block', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    device_id: event.notification.data?.device_id,
                    source: 'push_notification'
                })
            })
        );
    } else if (event.action === 'dismiss') {
        // Just close notification (already done above)
    } else {
        // Default click - open app
        event.waitUntil(clients.openWindow(urlToOpen));
    }
});

// Background sync for offline actions
self.addEventListener('sync', (event) => {
    console.log('[AIOCHI SW] Background sync:', event.tag);

    if (event.tag === 'sync-actions') {
        event.waitUntil(syncPendingActions());
    }
});

// Sync pending offline actions
async function syncPendingActions() {
    const cache = await caches.open('aiochi-pending-actions');
    const requests = await cache.keys();

    for (const request of requests) {
        try {
            const response = await fetch(request.clone());
            if (response.ok) {
                await cache.delete(request);
                console.log('[AIOCHI SW] Synced action:', request.url);
            }
        } catch (error) {
            console.error('[AIOCHI SW] Sync failed:', error);
        }
    }
}

// Periodic background sync for status updates
self.addEventListener('periodicsync', (event) => {
    if (event.tag === 'check-status') {
        event.waitUntil(checkNetworkStatus());
    }
});

async function checkNetworkStatus() {
    try {
        const response = await fetch('/aiochi/api/status');
        const data = await response.json();

        // Show notification if there's a critical alert
        if (data.ambient?.state === 'ALERT') {
            self.registration.showNotification('AI Eyes Alert', {
                body: data.ambient.message || 'Your network needs attention',
                icon: '/static/images/aiochi-icon-192.png',
                badge: '/static/images/aiochi-badge.png',
                tag: 'status-alert',
                requireInteraction: true,
                vibrate: [200, 100, 200, 100, 200]
            });
        }
    } catch (error) {
        console.error('[AIOCHI SW] Status check failed:', error);
    }
}
