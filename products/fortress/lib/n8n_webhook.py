#!/usr/bin/env python3
"""
n8n Webhook Integration for Bubble Events

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module provides webhook notifications to n8n for bubble-related events:
- Device joins/leaves a bubble
- New device relationship detected
- Bubble created or updated
- Manual correction made (for AI learning)

Integration with n8n:
- Configure webhook URL in /etc/hookprobe/fortress.conf
- n8n workflows can trigger actions based on bubble events
- Supports authentication via Bearer token

Webhook Payload Format:
{
    "event_type": "bubble_change",
    "timestamp": "2024-01-15T10:30:00Z",
    "data": { ... event-specific data ... }
}

Event Types:
- bubble_change: Device moved between bubbles
- device_join: New device joined network and assigned to bubble
- device_leave: Device left network
- relationship_detected: High affinity relationship found
- bubble_created: New bubble created
- manual_correction: User manually corrected bubble assignment
"""

import json
import logging
import os
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from typing import Dict, List, Optional, Any, Callable
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

# Configuration defaults
DEFAULT_WEBHOOK_URL = None  # Must be configured
DEFAULT_TIMEOUT = 10  # seconds
CONFIG_FILE = Path('/etc/hookprobe/fortress.conf')


@dataclass
class WebhookEvent:
    """Webhook event to be sent to n8n."""
    event_type: str
    timestamp: datetime
    data: Dict[str, Any]

    def to_dict(self) -> Dict:
        return {
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class N8NWebhookClient:
    """
    Async webhook client for n8n integration.

    Sends events to n8n in a background thread to avoid blocking.
    Implements retry logic for failed requests.
    """

    MAX_RETRIES = 3
    RETRY_DELAY = 2.0  # seconds

    def __init__(self, webhook_url: str = None, auth_token: str = None,
                 enabled: bool = True, batch_size: int = 10):
        self.webhook_url = webhook_url or self._load_webhook_url()
        self.auth_token = auth_token or self._load_auth_token()
        self.enabled = enabled and self.webhook_url is not None
        self.batch_size = batch_size

        # Event queue for async sending
        self._event_queue: Queue[WebhookEvent] = Queue(maxsize=1000)
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

        # Callbacks for event notification
        self._callbacks: List[Callable[[WebhookEvent], None]] = []

        # Statistics
        self._events_sent = 0
        self._events_failed = 0

        if self.enabled:
            self._start_worker()

    def _load_webhook_url(self) -> Optional[str]:
        """Load webhook URL from config file."""
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, 'r') as f:
                    for line in f:
                        if line.strip().startswith('N8N_WEBHOOK_URL='):
                            url = line.split('=', 1)[1].strip().strip('"\'')
                            if url and url != 'None':
                                return url
        except Exception as e:
            logger.debug(f"Could not load webhook URL: {e}")
        return None

    def _load_auth_token(self) -> Optional[str]:
        """Load auth token from config file."""
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, 'r') as f:
                    for line in f:
                        if line.strip().startswith('N8N_AUTH_TOKEN='):
                            token = line.split('=', 1)[1].strip().strip('"\'')
                            if token and token != 'None':
                                return token
        except Exception:
            pass
        return None

    def _start_worker(self):
        """Start background worker thread."""
        self._running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        logger.info(f"n8n webhook worker started (URL: {self.webhook_url[:50]}...)")

    def _worker_loop(self):
        """Background worker that sends queued events."""
        batch: List[WebhookEvent] = []

        while self._running:
            try:
                # Get event with timeout
                event = self._event_queue.get(timeout=1.0)
                batch.append(event)

                # If batch is full, send immediately
                if len(batch) >= self.batch_size:
                    self._send_batch(batch)
                    batch = []

            except Empty:
                # Timeout - send any pending events
                if batch:
                    self._send_batch(batch)
                    batch = []

        # Drain remaining events on shutdown
        while not self._event_queue.empty():
            try:
                batch.append(self._event_queue.get_nowait())
            except Empty:
                break
        if batch:
            self._send_batch(batch)

    def _send_batch(self, events: List[WebhookEvent]):
        """Send a batch of events to the webhook."""
        for event in events:
            self._send_event(event)

    def _send_event(self, event: WebhookEvent):
        """Send a single event to the webhook."""
        if not self.webhook_url:
            return

        payload = event.to_json().encode('utf-8')

        for attempt in range(self.MAX_RETRIES):
            try:
                request = urllib.request.Request(
                    self.webhook_url,
                    data=payload,
                    headers={
                        'Content-Type': 'application/json',
                        'User-Agent': 'HookProbe-Fortress/1.0',
                    }
                )

                # Add auth header if token is configured
                if self.auth_token:
                    request.add_header('Authorization', f'Bearer {self.auth_token}')

                with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT) as response:
                    if response.status == 200:
                        self._events_sent += 1
                        logger.debug(f"Webhook sent: {event.event_type}")
                        return
                    else:
                        logger.warning(f"Webhook returned {response.status}")

            except urllib.error.HTTPError as e:
                logger.warning(f"Webhook HTTP error: {e.code}")
            except urllib.error.URLError as e:
                logger.debug(f"Webhook URL error: {e.reason}")
            except Exception as e:
                logger.debug(f"Webhook error: {e}")

            # Retry delay
            if attempt < self.MAX_RETRIES - 1:
                import time
                time.sleep(self.RETRY_DELAY)

        self._events_failed += 1
        logger.warning(f"Webhook failed after {self.MAX_RETRIES} retries: {event.event_type}")

    def send(self, event_type: str, data: Dict[str, Any], timestamp: datetime = None):
        """
        Queue an event for sending to n8n.

        Args:
            event_type: Type of event (e.g., 'bubble_change')
            data: Event data dictionary
            timestamp: Event timestamp (defaults to now)
        """
        if not self.enabled:
            return

        event = WebhookEvent(
            event_type=event_type,
            timestamp=timestamp or datetime.now(),
            data=data,
        )

        try:
            self._event_queue.put_nowait(event)
        except:
            logger.warning("Webhook event queue full - dropping event")

        # Notify local callbacks
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.debug(f"Webhook callback error: {e}")

    # =========================================================================
    # CONVENIENCE METHODS FOR SPECIFIC EVENT TYPES
    # =========================================================================

    def on_bubble_change(self, mac: str, old_bubble: str, new_bubble: str,
                         confidence: float = 0.0, reason: str = ''):
        """Notify when device moves between bubbles."""
        self.send('bubble_change', {
            'mac': mac,
            'old_bubble_id': old_bubble,
            'new_bubble_id': new_bubble,
            'confidence': confidence,
            'reason': reason,
        })

    def on_device_join(self, mac: str, ip: str, hostname: str,
                       bubble_id: str, ecosystem: str = 'unknown'):
        """Notify when device joins network and is assigned to bubble."""
        self.send('device_join', {
            'mac': mac,
            'ip': ip,
            'hostname': hostname,
            'bubble_id': bubble_id,
            'ecosystem': ecosystem,
        })

    def on_device_leave(self, mac: str, bubble_id: str, duration_minutes: int = 0):
        """Notify when device leaves network."""
        self.send('device_leave', {
            'mac': mac,
            'bubble_id': bubble_id,
            'session_duration_minutes': duration_minutes,
        })

    def on_relationship_detected(self, mac_a: str, mac_b: str,
                                  affinity_score: float,
                                  services: List[str] = None,
                                  discovery_hits: int = 0):
        """Notify when high affinity relationship is detected."""
        self.send('relationship_detected', {
            'mac_a': mac_a,
            'mac_b': mac_b,
            'affinity_score': affinity_score,
            'services': services or [],
            'discovery_hits': discovery_hits,
        })

    def on_bubble_created(self, bubble_id: str, bubble_name: str,
                          bubble_type: str, devices: List[str] = None):
        """Notify when new bubble is created."""
        self.send('bubble_created', {
            'bubble_id': bubble_id,
            'bubble_name': bubble_name,
            'bubble_type': bubble_type,
            'initial_devices': devices or [],
        })

    def on_manual_correction(self, mac: str, old_bubble: str, new_bubble: str,
                             correction_reason: str = ''):
        """
        Notify when user manually corrects bubble assignment.

        This is critical for reinforcement learning - the AI learns
        from user corrections to improve automatic assignment.
        """
        self.send('manual_correction', {
            'mac': mac,
            'old_bubble_id': old_bubble,
            'new_bubble_id': new_bubble,
            'correction_reason': correction_reason,
            'learning_feedback': True,
        })

    def on_policy_violation(self, mac: str, bubble_id: str,
                            violation_type: str, details: Dict = None):
        """Notify when device violates bubble policy."""
        self.send('policy_violation', {
            'mac': mac,
            'bubble_id': bubble_id,
            'violation_type': violation_type,
            'details': details or {},
        })

    # =========================================================================
    # CALLBACK REGISTRATION
    # =========================================================================

    def register_callback(self, callback: Callable[[WebhookEvent], None]):
        """
        Register a local callback for webhook events.

        Callbacks are invoked synchronously when events are queued.
        Useful for local integrations that need event notifications.
        """
        self._callbacks.append(callback)

    # =========================================================================
    # LIFECYCLE
    # =========================================================================

    def stop(self):
        """Stop the webhook worker and flush remaining events."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)

    def get_stats(self) -> Dict:
        """Get webhook statistics."""
        return {
            'enabled': self.enabled,
            'url_configured': self.webhook_url is not None,
            'events_sent': self._events_sent,
            'events_failed': self._events_failed,
            'queue_size': self._event_queue.qsize(),
        }


# =============================================================================
# SINGLETON
# =============================================================================

_client: Optional[N8NWebhookClient] = None
_client_lock = threading.Lock()


def get_webhook_client() -> N8NWebhookClient:
    """Get the singleton webhook client."""
    global _client

    with _client_lock:
        if _client is None:
            _client = N8NWebhookClient()
        return _client


# =============================================================================
# CLI
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='n8n Webhook Client')
    parser.add_argument('command', choices=['status', 'test', 'configure'])
    parser.add_argument('--url', help='Webhook URL for configure')
    parser.add_argument('--token', help='Auth token for configure')
    args = parser.parse_args()

    client = get_webhook_client()

    if args.command == 'status':
        stats = client.get_stats()
        print("n8n Webhook Status:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    elif args.command == 'test':
        if not client.enabled:
            print("Webhook not configured. Use 'configure' first.")
        else:
            print("Sending test event...")
            client.send('test', {
                'message': 'Hello from HookProbe Fortress!',
                'source': 'webhook_test',
            })
            import time
            time.sleep(2)  # Wait for async send
            print(f"Stats: {client.get_stats()}")

    elif args.command == 'configure':
        if not args.url:
            print("Error: --url required for configure")
        else:
            # Write to config file
            print(f"Configuring webhook URL: {args.url}")

            config_lines = []
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, 'r') as f:
                    config_lines = f.readlines()

            # Update or add config
            url_found = False
            token_found = False
            for i, line in enumerate(config_lines):
                if line.strip().startswith('N8N_WEBHOOK_URL='):
                    config_lines[i] = f'N8N_WEBHOOK_URL="{args.url}"\n'
                    url_found = True
                if args.token and line.strip().startswith('N8N_AUTH_TOKEN='):
                    config_lines[i] = f'N8N_AUTH_TOKEN="{args.token}"\n'
                    token_found = True

            if not url_found:
                config_lines.append(f'N8N_WEBHOOK_URL="{args.url}"\n')
            if args.token and not token_found:
                config_lines.append(f'N8N_AUTH_TOKEN="{args.token}"\n')

            with open(CONFIG_FILE, 'w') as f:
                f.writelines(config_lines)

            print("Configuration saved. Restart services to apply.")
