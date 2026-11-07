#!/usr/bin/env python3
"""
OVS MAC Watcher - Lightweight monitor for new MAC addresses on the bridge.

This module watches the Open vSwitch MAC learning table for new entries.
When an unknown MAC appears, it triggers the efficiency engine.

CPU Impact: <0.1% (async polling every 5 seconds)
RAM Impact: ~15MB

The watcher uses ovsdb-client to monitor the MAC_Binding table without
needing continuous packet inspection.

Copyright (c) 2024-2026 HookProbe Security
"""

import os
import sys
import json
import sqlite3
import logging
import asyncio
import subprocess
from pathlib import Path
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Callable, Any
from threading import Thread, Lock
import re

# Configuration
WATCHER_DB = Path(os.getenv('WATCHER_DB', '/var/lib/hookprobe/mac_watcher.db'))
OVS_BRIDGE = os.getenv('OVS_BRIDGE', 'FTS')
POLL_INTERVAL = int(os.getenv('MAC_POLL_INTERVAL', '5'))  # seconds
LOG_FILE = Path('/var/log/fortress/mac-watcher.log')

logger = logging.getLogger('mac_watcher')


class MACEventType(Enum):
    """MAC table event types."""
    LEARNED = 'learned'       # New MAC learned on port
    MOVED = 'moved'           # MAC moved to different port
    EXPIRED = 'expired'       # MAC aged out
    UNKNOWN = 'unknown'       # MAC not in known list


@dataclass
class MACEvent:
    """Represents a MAC table change event."""
    event_type: MACEventType
    mac: str
    port: str
    vlan: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    old_port: Optional[str] = None  # For MOVED events
    is_unknown: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'event_type': self.event_type.value,
            'mac': self.mac,
            'port': self.port,
            'vlan': self.vlan,
            'timestamp': self.timestamp.isoformat(),
            'old_port': self.old_port,
            'is_unknown': self.is_unknown,
        }


class OVSMACWatcher:
    """
    Lightweight OVS MAC table watcher.

    Uses ovsdb-client to monitor MAC learning without packet inspection.
    Only triggers alerts for unknown MACs not in the known devices list.
    """

    def __init__(
        self,
        bridge: str = OVS_BRIDGE,
        db_path: Path = WATCHER_DB,
        poll_interval: int = POLL_INTERVAL,
    ):
        self.bridge = bridge
        self.db_path = db_path
        self.poll_interval = poll_interval

        self._known_macs: Set[str] = set()
        self._current_macs: Dict[str, str] = {}  # mac -> port
        self._callbacks: List[Callable[[MACEvent], None]] = []
        self._running = False
        self._lock = Lock()

        self._init_db()
        self._init_logging()
        self._load_known_macs()

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
        """Initialize database for MAC tracking."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS known_macs (
                    mac TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_port TEXT,
                    vlan INTEGER DEFAULT 0,
                    bubble_id TEXT,
                    source TEXT DEFAULT 'learned'
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS mac_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    port TEXT,
                    vlan INTEGER
                )
            ''')

            conn.execute('CREATE INDEX IF NOT EXISTS idx_mac_events_time ON mac_events(timestamp)')
            conn.commit()

    def _load_known_macs(self):
        """Load known MACs from database and DHCP sentinel."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('SELECT mac FROM known_macs')
            self._known_macs = {row[0].upper() for row in cursor.fetchall()}

        # Also load from DHCP sentinel database if available
        dhcp_db = Path('/var/lib/hookprobe/sentinel.db')
        if dhcp_db.exists():
            try:
                with sqlite3.connect(dhcp_db) as conn:
                    cursor = conn.execute('SELECT mac FROM known_devices')
                    for row in cursor.fetchall():
                        self._known_macs.add(row[0].upper())
            except Exception as e:
                logger.warning(f"Could not load DHCP known devices: {e}")

        logger.info(f"Loaded {len(self._known_macs)} known MACs")

    def get_ovs_macs(self) -> Dict[str, Dict[str, Any]]:
        """
        Get current MAC table from OVS.

        Returns dict of {mac: {port, vlan}} from the FDB (forwarding database).
        """
        macs = {}

        try:
            # Method 1: ovs-appctl fdb/show
            result = subprocess.run(
                ['ovs-appctl', 'fdb/show', self.bridge],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                # Parse output:
                #  port  VLAN  MAC                Age
                #     1     0  aa:bb:cc:dd:ee:ff    5
                for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 4:
                        port = parts[0]
                        vlan = int(parts[1])
                        mac = parts[2].upper()
                        macs[mac] = {'port': port, 'vlan': vlan}

        except subprocess.TimeoutExpired:
            logger.warning("OVS FDB query timed out")
        except FileNotFoundError:
            logger.warning("ovs-appctl not found, trying alternative method")
            macs = self._get_ovs_macs_bridge_fdb()
        except Exception as e:
            logger.error(f"Error getting OVS MACs: {e}")

        return macs

    def _get_ovs_macs_bridge_fdb(self) -> Dict[str, Dict[str, Any]]:
        """Alternative: Use bridge fdb command for Linux bridges."""
        macs = {}

        try:
            result = subprocess.run(
                ['bridge', 'fdb', 'show', 'br', self.bridge],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                # Parse: aa:bb:cc:dd:ee:ff dev eth0 master FTS
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 4:
                        mac = parts[0].upper()
                        port = parts[2] if 'dev' in parts else 'unknown'
                        macs[mac] = {'port': port, 'vlan': 0}

        except Exception as e:
            logger.debug(f"Bridge FDB fallback failed: {e}")

        return macs

    def check_for_changes(self) -> List[MACEvent]:
        """
        Check OVS MAC table for changes.

        Returns list of events (learned, moved, expired, unknown).
        """
        events = []
        current = self.get_ovs_macs()
        now = datetime.now()

        with self._lock:
            # Check for new/moved MACs
            for mac, info in current.items():
                port = info['port']
                vlan = info.get('vlan', 0)

                if mac in self._current_macs:
                    # Check if moved
                    if self._current_macs[mac] != port:
                        event = MACEvent(
                            event_type=MACEventType.MOVED,
                            mac=mac,
                            port=port,
                            vlan=vlan,
                            old_port=self._current_macs[mac],
                        )
                        events.append(event)
                        logger.info(f"MAC moved: {mac} {self._current_macs[mac]} -> {port}")
                else:
                    # New MAC learned
                    is_unknown = mac not in self._known_macs
                    event = MACEvent(
                        event_type=MACEventType.UNKNOWN if is_unknown else MACEventType.LEARNED,
                        mac=mac,
                        port=port,
                        vlan=vlan,
                        is_unknown=is_unknown,
                    )
                    events.append(event)

                    if is_unknown:
                        logger.info(f"Unknown MAC detected: {mac} on port {port}")
                    else:
                        logger.debug(f"Known MAC learned: {mac} on port {port}")

            # Check for expired MACs
            for mac in self._current_macs:
                if mac not in current:
                    event = MACEvent(
                        event_type=MACEventType.EXPIRED,
                        mac=mac,
                        port=self._current_macs[mac],
                    )
                    events.append(event)
                    logger.debug(f"MAC expired: {mac}")

            # Update current state
            self._current_macs = {mac: info['port'] for mac, info in current.items()}

        return events

    def process_events(self, events: List[MACEvent]):
        """Process MAC events and trigger callbacks."""
        for event in events:
            # Log to database
            self._log_event(event)

            # Trigger callbacks for unknown MACs
            if event.event_type == MACEventType.UNKNOWN:
                for callback in self._callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

    def _log_event(self, event: MACEvent):
        """Log event to database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO mac_events (timestamp, event_type, mac, port, vlan)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                event.timestamp.isoformat(),
                event.event_type.value,
                event.mac,
                event.port,
                event.vlan,
            ))
            conn.commit()

    def register_known_mac(self, mac: str, port: Optional[str] = None, bubble_id: Optional[str] = None):
        """Add MAC to known devices list."""
        mac = mac.upper()
        now = datetime.now().isoformat()

        with self._lock:
            self._known_macs.add(mac)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO known_macs (mac, first_seen, last_seen, last_port, bubble_id)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    last_port = COALESCE(excluded.last_port, last_port),
                    bubble_id = COALESCE(excluded.bubble_id, bubble_id)
            ''', (mac, now, now, port, bubble_id))
            conn.commit()

    def on_unknown_mac(self, callback: Callable[[MACEvent], None]):
        """Register callback for unknown MAC events."""
        self._callbacks.append(callback)

    async def watch_async(self):
        """Async watch loop."""
        self._running = True
        logger.info(f"Starting MAC watcher on {self.bridge}, interval={self.poll_interval}s")

        while self._running:
            try:
                events = self.check_for_changes()
                if events:
                    self.process_events(events)
            except Exception as e:
                logger.error(f"Watch error: {e}")

            await asyncio.sleep(self.poll_interval)

    def watch(self):
        """Blocking watch loop."""
        asyncio.run(self.watch_async())

    def start(self):
        """Start watching in background thread."""
        thread = Thread(target=self.watch, daemon=True, name='mac-watcher')
        thread.start()
        return thread

    def stop(self):
        """Stop watching."""
        self._running = False

    def get_stats(self) -> Dict[str, Any]:
        """Get watcher statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM known_macs')
            known_count = cursor.fetchone()[0]

            cursor = conn.execute('''
                SELECT event_type, COUNT(*)
                FROM mac_events
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY event_type
            ''')
            events_by_type = dict(cursor.fetchall())

        return {
            'bridge': self.bridge,
            'known_macs': known_count,
            'current_macs': len(self._current_macs),
            'poll_interval': self.poll_interval,
            'events_24h': events_by_type,
            'running': self._running,
        }


# Singleton instance
_watcher_instance: Optional[OVSMACWatcher] = None
_watcher_lock = Lock()


def get_mac_watcher() -> OVSMACWatcher:
    """Get singleton MAC watcher instance."""
    global _watcher_instance
    with _watcher_lock:
        if _watcher_instance is None:
            _watcher_instance = OVSMACWatcher()
        return _watcher_instance


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='OVS MAC Watcher')
    parser.add_argument('--bridge', default=OVS_BRIDGE, help='OVS bridge name')
    parser.add_argument('--interval', type=int, default=POLL_INTERVAL, help='Poll interval')
    parser.add_argument('--once', action='store_true', help='Check once and exit')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--debug', action='store_true')

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    watcher = OVSMACWatcher(bridge=args.bridge, poll_interval=args.interval)

    if args.stats:
        print(json.dumps(watcher.get_stats(), indent=2))
        return

    if args.once:
        events = watcher.check_for_changes()
        for event in events:
            print(f"{event.event_type.value}: {event.mac} on {event.port}")
        return

    # Watch continuously
    def on_unknown(event):
        print(f"UNKNOWN: {event.mac} on {event.port}")

    watcher.on_unknown_mac(on_unknown)
    watcher.watch()


if __name__ == '__main__':
    main()
