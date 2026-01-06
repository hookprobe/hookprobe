#!/usr/bin/env python3
"""
DHCP Sentinel - Low-power always-on trigger for new device detection.

This module provides a near-zero CPU hook into dnsmasq DHCP events.
When a device requests an IP, we capture:
- MAC address
- Vendor ID (from OUI)
- DHCP Option 55 (unique OS fingerprint)
- Hostname (if provided)

The hook script is called by dnsmasq on each lease event.

Usage:
    # In dnsmasq.conf:
    dhcp-script=/opt/hookprobe/fortress/scripts/dhcp-hook.sh

    # The hook script calls this module:
    python -m autopilot.dhcp_sentinel --event add --mac AA:BB:CC:DD:EE:FF ...

Copyright (c) 2024-2026 HookProbe Security
"""

import os
import sys
import json
import sqlite3
import logging
import argparse
import subprocess
from pathlib import Path
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Callable, Any
from threading import Thread, Lock
import queue

# Configuration
SENTINEL_DB = Path(os.getenv('SENTINEL_DB', '/var/lib/hookprobe/sentinel.db'))
CONFIG_FILE = Path(os.getenv('FORTRESS_CONFIG', '/etc/hookprobe/fortress.conf'))
N8N_WEBHOOK_URL = os.getenv('N8N_WEBHOOK_URL', 'http://localhost:5678/webhook/dhcp-event')
LOG_FILE = Path('/var/log/fortress/dhcp-sentinel.log')

# DHCP Option 55 fingerprint database (common patterns)
DHCP_FINGERPRINTS = {
    '1,3,6,15,26,28,51,58,59,43': 'windows',
    '1,3,6,15,119,252': 'macos',
    '1,121,3,6,15,119,252': 'macos_ventura',
    '1,3,6,15,119,95,252,44,46': 'ios',
    '1,3,6,15,119,252,95,44,46': 'ios_16',
    '1,3,6,28,33,121': 'android',
    '1,3,6,15,28,33,121': 'android_12',
    '1,3,6,12,15,17,28,40,41,42': 'linux',
    '1,28,2,3,15,6,12': 'linux_embedded',
    '1,3,6,15,44,46,47,31,33,121,249,43': 'samsung_tv',
    '1,3,6,15,28,33': 'iot_generic',
}

logger = logging.getLogger('dhcp_sentinel')


class DHCPEventType(Enum):
    """DHCP event types from dnsmasq."""
    ADD = 'add'           # New lease granted
    OLD = 'old'           # Existing lease renewed
    DEL = 'del'           # Lease expired/released
    INIT = 'init'         # dnsmasq startup
    TFTP = 'tftp'         # TFTP request (for PXE)


@dataclass
class DHCPEvent:
    """Represents a DHCP lease event."""
    event_type: DHCPEventType
    mac: str
    ip: str
    hostname: Optional[str] = None
    vendor_class: Optional[str] = None      # DHCP option 60
    option55: Optional[str] = None          # DHCP option 55 (fingerprint)
    client_id: Optional[str] = None         # DHCP option 61
    lease_time: int = 3600
    timestamp: datetime = field(default_factory=datetime.now)
    interface: str = 'FTS'

    # Derived fields
    os_fingerprint: Optional[str] = None
    is_new_device: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        d['event_type'] = self.event_type.value
        d['timestamp'] = self.timestamp.isoformat()
        return d

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dnsmasq_args(cls, args: List[str], env: Dict[str, str]) -> 'DHCPEvent':
        """
        Parse dnsmasq dhcp-script arguments.

        dnsmasq calls: script <action> <mac> <ip> [hostname]
        Environment contains additional options.
        """
        if len(args) < 3:
            raise ValueError(f"Not enough arguments: {args}")

        event_type = DHCPEventType(args[0])
        mac = args[1].upper()
        ip = args[2]
        hostname = args[3] if len(args) > 3 else None

        # Parse environment variables set by dnsmasq
        vendor_class = env.get('DNSMASQ_VENDOR_CLASS')
        option55 = env.get('DNSMASQ_REQUESTED_OPTIONS')
        client_id = env.get('DNSMASQ_CLIENT_ID')
        lease_time = int(env.get('DNSMASQ_LEASE_LENGTH', '3600'))
        interface = env.get('DNSMASQ_INTERFACE', 'FTS')

        event = cls(
            event_type=event_type,
            mac=mac,
            ip=ip,
            hostname=hostname,
            vendor_class=vendor_class,
            option55=option55,
            client_id=client_id,
            lease_time=lease_time,
            interface=interface,
        )

        # Determine OS from fingerprint
        if option55:
            event.os_fingerprint = DHCP_FINGERPRINTS.get(option55, 'unknown')

        return event


class DHCPSentinel:
    """
    Low-power DHCP lease monitor.

    CPU Impact: Negligible (only runs when dnsmasq calls the hook)
    RAM Impact: ~10MB for the Python process

    When a new device is detected, triggers n8n webhook for:
    1. On-demand probe capture
    2. Bubble assignment
    3. SDN rule update
    """

    def __init__(self, db_path: Path = SENTINEL_DB):
        self.db_path = db_path
        self._lock = Lock()
        self._callbacks: List[Callable[[DHCPEvent], None]] = []
        self._init_db()
        self._init_logging()

    def _init_logging(self):
        """Initialize logging."""
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(LOG_FILE)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def _init_db(self):
        """Initialize SQLite database for known devices."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS known_devices (
                    mac TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    hostname TEXT,
                    os_fingerprint TEXT,
                    vendor_class TEXT,
                    option55 TEXT,
                    bubble_id TEXT,
                    event_count INTEGER DEFAULT 1
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS dhcp_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    os_fingerprint TEXT,
                    is_new_device INTEGER,
                    FOREIGN KEY (mac) REFERENCES known_devices(mac)
                )
            ''')

            # Index for fast lookups
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_mac ON dhcp_events(mac)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_time ON dhcp_events(timestamp)')
            conn.commit()

    def is_known_device(self, mac: str) -> bool:
        """Check if MAC is in known devices table."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                'SELECT 1 FROM known_devices WHERE mac = ?',
                (mac.upper(),)
            )
            return cursor.fetchone() is not None

    def register_device(self, event: DHCPEvent) -> bool:
        """
        Register a device in the known devices table.

        Returns True if this is a new device, False if existing.
        """
        now = datetime.now().isoformat()
        mac = event.mac.upper()

        with sqlite3.connect(self.db_path) as conn:
            # Check if exists
            cursor = conn.execute(
                'SELECT event_count FROM known_devices WHERE mac = ?',
                (mac,)
            )
            row = cursor.fetchone()

            if row is None:
                # New device
                conn.execute('''
                    INSERT INTO known_devices
                    (mac, first_seen, last_seen, hostname, os_fingerprint, vendor_class, option55)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    mac, now, now,
                    event.hostname,
                    event.os_fingerprint,
                    event.vendor_class,
                    event.option55,
                ))
                event.is_new_device = True
                logger.info(f"New device detected: {mac} ({event.hostname or 'no hostname'})")
                return True
            else:
                # Existing device - update last_seen
                conn.execute('''
                    UPDATE known_devices
                    SET last_seen = ?,
                        hostname = COALESCE(?, hostname),
                        event_count = event_count + 1
                    WHERE mac = ?
                ''', (now, event.hostname, mac))
                event.is_new_device = False
                return False

    def log_event(self, event: DHCPEvent):
        """Log DHCP event to database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO dhcp_events
                (timestamp, event_type, mac, ip, hostname, os_fingerprint, is_new_device)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.timestamp.isoformat(),
                event.event_type.value,
                event.mac.upper(),
                event.ip,
                event.hostname,
                event.os_fingerprint,
                1 if event.is_new_device else 0,
            ))
            conn.commit()

    def process_event(self, event: DHCPEvent) -> bool:
        """
        Process a DHCP event.

        Returns True if this triggered a new device alert.
        """
        # Only process ADD events for new device detection
        if event.event_type == DHCPEventType.ADD:
            is_new = self.register_device(event)
            self.log_event(event)

            if is_new:
                # Trigger callbacks (for n8n webhook, etc.)
                for callback in self._callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

                # Send to n8n webhook
                self._send_webhook(event)
                return True

        elif event.event_type == DHCPEventType.OLD:
            # Renewal - just update timestamp
            self.register_device(event)
            self.log_event(event)

        elif event.event_type == DHCPEventType.DEL:
            # Device left - log for temporal patterns
            self.log_event(event)
            logger.info(f"Device left: {event.mac}")

        return False

    def _send_webhook(self, event: DHCPEvent):
        """Send event to n8n webhook."""
        try:
            import requests

            # Load webhook URL from config if available
            webhook_url = N8N_WEBHOOK_URL
            if CONFIG_FILE.exists():
                # Parse simple key=value config
                config = {}
                with open(CONFIG_FILE) as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            config[key.strip()] = value.strip().strip('"\'')
                webhook_url = config.get('N8N_DHCP_WEBHOOK', webhook_url)

            payload = {
                'event': 'new_device',
                'source': 'dhcp_sentinel',
                'data': event.to_dict(),
                'trigger_probe': True,
                'probe_duration': 60,
            }

            resp = requests.post(
                webhook_url,
                json=payload,
                timeout=5,
                headers={'Content-Type': 'application/json'}
            )

            if resp.status_code == 200:
                logger.info(f"Webhook sent for {event.mac}")
            else:
                logger.warning(f"Webhook failed: {resp.status_code}")

        except ImportError:
            # Fallback: use curl
            self._send_webhook_curl(event)
        except Exception as e:
            logger.error(f"Webhook error: {e}")

    def _send_webhook_curl(self, event: DHCPEvent):
        """Fallback webhook using curl."""
        try:
            payload = json.dumps({
                'event': 'new_device',
                'source': 'dhcp_sentinel',
                'data': event.to_dict(),
                'trigger_probe': True,
            })

            subprocess.run([
                'curl', '-s', '-X', 'POST',
                '-H', 'Content-Type: application/json',
                '-d', payload,
                '--connect-timeout', '5',
                N8N_WEBHOOK_URL,
            ], capture_output=True, timeout=10)

        except Exception as e:
            logger.error(f"Curl webhook error: {e}")

    def on_new_device(self, callback: Callable[[DHCPEvent], None]):
        """Register callback for new device events."""
        self._callbacks.append(callback)

    def get_device_stats(self) -> Dict[str, Any]:
        """Get statistics about known devices."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM known_devices')
            total = cursor.fetchone()[0]

            cursor = conn.execute('''
                SELECT os_fingerprint, COUNT(*)
                FROM known_devices
                GROUP BY os_fingerprint
            ''')
            by_os = dict(cursor.fetchall())

            cursor = conn.execute('''
                SELECT COUNT(*) FROM dhcp_events
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            events_24h = cursor.fetchone()[0]

            cursor = conn.execute('''
                SELECT COUNT(*) FROM dhcp_events
                WHERE is_new_device = 1 AND timestamp > datetime('now', '-24 hours')
            ''')
            new_24h = cursor.fetchone()[0]

        return {
            'total_known_devices': total,
            'devices_by_os': by_os,
            'events_last_24h': events_24h,
            'new_devices_last_24h': new_24h,
        }

    def update_bubble_assignment(self, mac: str, bubble_id: str):
        """Update device's bubble assignment."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                'UPDATE known_devices SET bubble_id = ? WHERE mac = ?',
                (bubble_id, mac.upper())
            )
            conn.commit()


# Singleton instance
_sentinel_instance: Optional[DHCPSentinel] = None
_sentinel_lock = Lock()


def get_dhcp_sentinel() -> DHCPSentinel:
    """Get singleton DHCP sentinel instance."""
    global _sentinel_instance
    with _sentinel_lock:
        if _sentinel_instance is None:
            _sentinel_instance = DHCPSentinel()
        return _sentinel_instance


def main():
    """CLI entry point for dnsmasq hook."""
    parser = argparse.ArgumentParser(description='DHCP Sentinel Hook')
    parser.add_argument('action', choices=['add', 'old', 'del', 'init', 'tftp'])
    parser.add_argument('mac', help='MAC address')
    parser.add_argument('ip', help='IP address')
    parser.add_argument('hostname', nargs='?', default=None)
    parser.add_argument('--debug', action='store_true')

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    # Create event from dnsmasq args + environment
    try:
        event = DHCPEvent.from_dnsmasq_args(
            [args.action, args.mac, args.ip] + ([args.hostname] if args.hostname else []),
            dict(os.environ)
        )

        sentinel = get_dhcp_sentinel()
        triggered = sentinel.process_event(event)

        if triggered:
            print(f"New device: {args.mac}")
            sys.exit(0)
        else:
            sys.exit(0)

    except Exception as e:
        logger.error(f"Error processing event: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
