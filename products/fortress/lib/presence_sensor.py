#!/usr/bin/env python3
"""
Multi-Modal Presence Sensor - Proprietary HookProbe Technology

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module implements "Atmospheric Presence" sensing for ecosystem detection.
It combines multiple signals to detect when devices belong to the same user.

Signal Sources:
1. mDNS/Bonjour - Device IDs, service fingerprints, TXT records
2. BLE Proximity - Advertisement patterns, burst signatures
3. Spatial Correlation - Join/leave timing, AP proximity
4. AWDL Detection - Apple Wireless Direct Link patterns
5. Continuity Packets - Handoff/Universal Clipboard signatures

The goal: Detect "same account" relationships WITHOUT needing credentials.
"""

import asyncio
import hashlib
import json
import logging
import sqlite3
import struct
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum

logger = logging.getLogger(__name__)

# Optional dependencies
try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False

try:
    from bleak import BleakScanner
    HAS_BLEAK = True
except ImportError:
    HAS_BLEAK = False

# Database
PRESENCE_DB = Path('/var/lib/hookprobe/presence.db')


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class EcosystemType(Enum):
    """Detected device ecosystem."""
    APPLE = "apple"
    GOOGLE = "google"
    AMAZON = "amazon"
    SAMSUNG = "samsung"
    XIAOMI = "xiaomi"
    HUAWEI = "huawei"
    MICROSOFT = "microsoft"
    UNKNOWN = "unknown"


class PresenceState(Enum):
    """Device presence state."""
    ACTIVE = "active"           # Currently visible
    DORMANT = "dormant"         # Recently seen, likely still present
    DEPARTED = "departed"       # Left the network
    UNKNOWN = "unknown"


# Apple-specific mDNS services for ecosystem detection
APPLE_MDNS_SERVICES = [
    "_airplay._tcp",           # AirPlay
    "_raop._tcp",              # Remote Audio Output Protocol
    "_companion-link._tcp",    # Companion Link (device pairing)
    "_homekit._tcp",           # HomeKit
    "_hap._tcp",               # HomeKit Accessory Protocol
    "_airportexpress._tcp",    # AirPort Express
    "_apple-mobdev2._tcp",     # Apple Mobile Device v2
    "_sleep-proxy._udp",       # Sleep Proxy
    "_rdlink._tcp",            # Remote Desktop Link
    "_touch-able._tcp",        # Touch Remote (iTunes)
]

# Google ecosystem services
GOOGLE_MDNS_SERVICES = [
    "_googlecast._tcp",        # Chromecast
    "_googlezone._tcp",        # Google WiFi
    "_googlerpc._tcp",         # Google RPC
]

# Amazon ecosystem services
AMAZON_MDNS_SERVICES = [
    "_amzn-alexa._tcp",        # Alexa
    "_amzn-wplay._tcp",        # Amazon Whole Home Audio
]

# Samsung ecosystem services
SAMSUNG_MDNS_SERVICES = [
    "_samsung-smartcam._tcp",   # Samsung SmartCam
    "_samsungtvrc._tcp",        # Samsung TV Remote Control
    "_samsung-tv._tcp",         # Samsung Smart TV
    "_smartthings._tcp",        # SmartThings Hub
]

# Xiaomi ecosystem services
XIAOMI_MDNS_SERVICES = [
    "_miio._udp",               # Xiaomi Mi Home protocol
    "_mi-connect._tcp",         # Mi Connect (device pairing)
    "_xiaomi-gateway._tcp",     # Xiaomi Gateway
]

# Huawei ecosystem services
HUAWEI_MDNS_SERVICES = [
    "_huawei-hilink._tcp",      # Huawei HiLink
    "_hw-share._tcp",           # Huawei Share
    "_hisuite._tcp",            # HiSuite connection
]

# BLE Manufacturer IDs (Bluetooth SIG assigned)
BLE_MANUFACTURER_IDS = {
    0x004C: 'apple',           # Apple Inc.
    0x00E0: 'google',          # Google LLC
    0x0075: 'samsung',         # Samsung Electronics
    0x0157: 'xiaomi',          # Xiaomi Communications
    0x007D: 'huawei',          # Huawei Technologies
    0x0006: 'microsoft',       # Microsoft
    0x0131: 'amazon',          # Amazon.com Services
}

# BLE Service UUIDs for ecosystem detection
BLE_SERVICE_UUIDS = {
    # Samsung
    'FE07': 'samsung_smartthings',
    'FE11': 'samsung_galaxy_buds',
    'FE12': 'samsung_gear',
    # Xiaomi
    'FE95': 'xiaomi_mi_home',
    'FE9F': 'xiaomi_band',
    # Huawei
    'FE86': 'huawei_hilink',
    'FE87': 'huawei_watch',
    'FDA4': 'huawei_share',
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class DevicePresence:
    """Presence information for a single device."""
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    ecosystem: EcosystemType = EcosystemType.UNKNOWN
    state: PresenceState = PresenceState.UNKNOWN

    # mDNS data
    mdns_services: List[str] = field(default_factory=list)
    mdns_device_id: Optional[str] = None
    mdns_model: Optional[str] = None
    mdns_txt_records: Dict[str, str] = field(default_factory=dict)

    # BLE data
    ble_rssi: Optional[int] = None
    ble_manufacturer_data: Optional[bytes] = None
    ble_advertisement_pattern: Optional[str] = None

    # Spatial data
    access_point: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    session_duration: int = 0  # seconds

    # Behavior features (for clustering)
    sync_frequency: float = 0.0       # Observed sync events per hour
    handoff_count: int = 0            # Continuity handoff events
    proximity_score: float = 0.0      # How close to other devices (0-1)
    time_correlation: float = 0.0     # Join/leave timing correlation (0-1)

    # Ecosystem bubble
    bubble_id: Optional[str] = None
    bubble_confidence: float = 0.0

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['ecosystem'] = self.ecosystem.value
        d['state'] = self.state.value
        return d


@dataclass
class EcosystemBubble:
    """A group of devices belonging to the same user/account."""
    bubble_id: str
    ecosystem: EcosystemType
    devices: Set[str] = field(default_factory=set)  # MAC addresses
    confidence: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_activity: str = field(default_factory=lambda: datetime.now().isoformat())

    # Behavioral signature
    sync_pattern: Optional[str] = None
    typical_proximity: float = 0.0
    typical_timing: List[str] = field(default_factory=list)  # HH:MM patterns

    def to_dict(self) -> Dict:
        return {
            'bubble_id': self.bubble_id,
            'ecosystem': self.ecosystem.value,
            'devices': list(self.devices),
            'confidence': self.confidence,
            'created_at': self.created_at,
            'last_activity': self.last_activity,
            'device_count': len(self.devices),
        }


@dataclass
class PresenceEvent:
    """A single presence event for correlation."""
    mac: str
    event_type: str  # 'join', 'leave', 'sync', 'handoff', 'proximity'
    timestamp: str
    access_point: Optional[str] = None
    details: Dict = field(default_factory=dict)


@dataclass
class MDNSQueryRecord:
    """Track mDNS query for pairing with responses."""
    query_mac: str          # Device that made the query
    service_type: str       # e.g., "_airplay._tcp"
    query_name: str         # Full query name
    timestamp: datetime
    response_macs: List[str] = field(default_factory=list)  # Devices that responded
    paired: bool = False    # Whether response was received


@dataclass
class MDNSDiscoveryPair:
    """A paired mDNS query/response indicating device relationship."""
    querier_mac: str        # Device that queried
    responder_mac: str      # Device that responded
    service_type: str       # Service being discovered
    timestamp: datetime

    def to_dict(self) -> Dict:
        return {
            'querier': self.querier_mac,
            'responder': self.responder_mac,
            'service': self.service_type,
            'timestamp': self.timestamp.isoformat(),
        }


# =============================================================================
# MDNS LISTENER
# =============================================================================

class AppleServiceListener:
    """Listener for Apple ecosystem mDNS services."""

    def __init__(self, sensor: 'PresenceSensor'):
        self.sensor = sensor

    def add_service(self, zc: 'Zeroconf', type_: str, name: str):
        """Called when a service is discovered."""
        try:
            info = zc.get_service_info(type_, name)
            if info:
                self.sensor._process_mdns_service(info, type_, name)
        except Exception as e:
            logger.debug(f"Error processing mDNS service: {e}")

    def remove_service(self, zc: 'Zeroconf', type_: str, name: str):
        """Called when a service is removed."""
        self.sensor._handle_mdns_departure(type_, name)

    def update_service(self, zc: 'Zeroconf', type_: str, name: str):
        """Called when a service is updated."""
        self.add_service(zc, type_, name)


# =============================================================================
# PRESENCE SENSOR
# =============================================================================

class PresenceSensor:
    """
    Multi-modal presence sensor for ecosystem detection.

    Combines mDNS, BLE, and network signals to detect device presence
    and ecosystem relationships.
    """

    def __init__(self, interface: str = "FTS"):
        self.interface = interface
        self.running = False

        # Device presence tracking
        self._devices: Dict[str, DevicePresence] = {}
        self._bubbles: Dict[str, EcosystemBubble] = {}
        self._events: List[PresenceEvent] = []
        self._lock = threading.RLock()

        # mDNS
        self._zeroconf: Optional['Zeroconf'] = None
        self._browsers: List['ServiceBrowser'] = []
        self._mdns_available = False  # Set to True when mDNS sensing starts successfully

        # mDNS Query/Response Pairing
        self._pending_queries: Dict[str, MDNSQueryRecord] = {}  # query_key → record
        self._discovery_pairs: List[MDNSDiscoveryPair] = []
        self._query_timeout = 30  # Seconds to wait for response
        self._discovery_hits: Dict[Tuple[str, str], int] = {}  # (mac_a, mac_b) → hit_count

        # Event correlation
        self._event_window: List[PresenceEvent] = []
        self._correlation_window = 300  # 5 minutes

        # Callbacks for external integration
        self._discovery_callbacks: List[callable] = []

        # Initialize database
        self._init_database()

    def _init_database(self):
        """Initialize presence database."""
        try:
            PRESENCE_DB.parent.mkdir(parents=True, exist_ok=True)

            with sqlite3.connect(str(PRESENCE_DB)) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS device_presence (
                        mac TEXT PRIMARY KEY,
                        ip TEXT,
                        hostname TEXT,
                        ecosystem TEXT,
                        state TEXT,
                        mdns_device_id TEXT,
                        mdns_model TEXT,
                        bubble_id TEXT,
                        bubble_confidence REAL,
                        sync_frequency REAL,
                        proximity_score REAL,
                        time_correlation REAL,
                        first_seen TEXT,
                        last_seen TEXT,
                        session_duration INTEGER
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS ecosystem_bubbles (
                        bubble_id TEXT PRIMARY KEY,
                        ecosystem TEXT,
                        devices_json TEXT,
                        confidence REAL,
                        created_at TEXT,
                        last_activity TEXT
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS presence_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac TEXT,
                        event_type TEXT,
                        timestamp TEXT,
                        access_point TEXT,
                        details_json TEXT
                    )
                ''')
                # mDNS Discovery Pairs table for Query/Response tracking
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS mdns_discovery_pairs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        querier_mac TEXT NOT NULL,
                        responder_mac TEXT NOT NULL,
                        service_type TEXT,
                        timestamp TEXT,
                        UNIQUE(querier_mac, responder_mac, service_type, timestamp)
                    )
                ''')
                # Discovery hits aggregation (for affinity scoring)
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS discovery_hits (
                        mac_a TEXT NOT NULL,
                        mac_b TEXT NOT NULL,
                        hit_count INTEGER DEFAULT 0,
                        last_hit TEXT,
                        PRIMARY KEY (mac_a, mac_b)
                    )
                ''')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_presence_mac ON device_presence(mac)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_bubble_id ON device_presence(bubble_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_events_mac ON presence_events(mac)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_events_ts ON presence_events(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_mdns_querier ON mdns_discovery_pairs(querier_mac)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_mdns_responder ON mdns_discovery_pairs(responder_mac)')
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize presence database: {e}")

    # =========================================================================
    # MDNS SENSING
    # =========================================================================

    def start_mdns_sensing(self):
        """Start mDNS service discovery."""
        if not HAS_ZEROCONF:
            logger.warning("zeroconf not installed - mDNS sensing disabled")
            self._mdns_available = False
            return

        try:
            self._zeroconf = Zeroconf()
            listener = AppleServiceListener(self)

            # Browse all ecosystem services
            all_services = (
                APPLE_MDNS_SERVICES +
                GOOGLE_MDNS_SERVICES +
                AMAZON_MDNS_SERVICES
            )

            for service_type in all_services:
                browser = ServiceBrowser(self._zeroconf, f"{service_type}.local.", listener)
                self._browsers.append(browser)

            logger.info(f"Started mDNS sensing for {len(all_services)} service types")
            self._mdns_available = True
        except OSError as e:
            # Common case: avahi-daemon binds exclusively to port 5353
            if "Address in use" in str(e) or e.errno == 98:
                logger.error(f"Address in use when binding to ('', 5353); "
                           f"When using avahi, make sure disallow-other-stacks is set to no in avahi-daemon.conf")
                logger.warning("Bubble manager will continue without mDNS discovery - "
                             "DHCP fingerprinting and behavioral clustering still active")
            else:
                logger.error(f"Could not start mDNS sensing: {e}")
            self._mdns_available = False
        except Exception as e:
            logger.error(f"Could not start mDNS sensing: {e}")
            self._mdns_available = False

    def _process_mdns_service(self, info, service_type: str, name: str):
        """Process a discovered mDNS service."""
        with self._lock:
            try:
                # Extract IP and MAC (MAC requires ARP lookup)
                ip = None
                if info.addresses:
                    import socket
                    ip = socket.inet_ntoa(info.addresses[0])

                # Get MAC from IP (via ARP)
                mac = self._ip_to_mac(ip) if ip else None
                if not mac:
                    return

                mac = mac.upper()

                # Get or create device presence
                if mac not in self._devices:
                    self._devices[mac] = DevicePresence(
                        mac=mac,
                        first_seen=datetime.now().isoformat()
                    )

                device = self._devices[mac]
                device.ip = ip
                device.last_seen = datetime.now().isoformat()
                device.state = PresenceState.ACTIVE

                # Add service
                if service_type not in device.mdns_services:
                    device.mdns_services.append(service_type)

                # Parse TXT records for device identity
                if info.properties:
                    for key, value in info.properties.items():
                        key_str = key.decode() if isinstance(key, bytes) else str(key)
                        val_str = value.decode() if isinstance(value, bytes) else str(value)
                        device.mdns_txt_records[key_str] = val_str

                        # Look for device identifiers
                        if key_str.lower() in ('id', 'deviceid', 'device-id', 'serialnumber'):
                            device.mdns_device_id = val_str
                        elif key_str.lower() in ('model', 'md', 'am'):
                            device.mdns_model = val_str

                # Determine ecosystem
                device.ecosystem = self._determine_ecosystem(service_type, device.mdns_txt_records)

                # Record event
                self._record_event(PresenceEvent(
                    mac=mac,
                    event_type='mdns_discovery',
                    timestamp=datetime.now().isoformat(),
                    details={
                        'service': service_type,
                        'name': name,
                        'model': device.mdns_model
                    }
                ))

                # Record as mDNS response for query/response pairing
                # When a device advertises a service, it's responding to
                # any pending queries for that service type
                self.record_mdns_response(mac, service_type.replace('.local.', ''))

                logger.debug(f"mDNS: {mac} -> {device.ecosystem.value} ({service_type})")

            except Exception as e:
                logger.debug(f"Error processing mDNS service: {e}")

    def _determine_ecosystem(self, service_type: str, txt_records: Dict) -> EcosystemType:
        """Determine ecosystem from mDNS service type and records."""
        if any(s in service_type for s in ['airplay', 'raop', 'companion', 'homekit', 'hap', 'apple']):
            return EcosystemType.APPLE
        if 'google' in service_type.lower():
            return EcosystemType.GOOGLE
        if 'amzn' in service_type.lower() or 'amazon' in service_type.lower():
            return EcosystemType.AMAZON

        # Check TXT records for ecosystem hints
        txt_str = str(txt_records).lower()
        if 'apple' in txt_str or 'iphone' in txt_str or 'mac' in txt_str:
            return EcosystemType.APPLE
        if 'google' in txt_str or 'chromecast' in txt_str:
            return EcosystemType.GOOGLE
        if 'amazon' in txt_str or 'alexa' in txt_str or 'echo' in txt_str:
            return EcosystemType.AMAZON

        return EcosystemType.UNKNOWN

    def _handle_mdns_departure(self, service_type: str, name: str):
        """Handle mDNS service departure."""
        # Find device by service name pattern
        # This is imperfect but helps track departures
        pass

    # =========================================================================
    # MDNS QUERY/RESPONSE PAIRING
    # =========================================================================

    def record_mdns_query(self, querier_mac: str, service_type: str,
                          query_name: str, timestamp: datetime = None):
        """
        Record an mDNS query for later pairing with response.

        When device A queries for _airplay._tcp.local., we record it.
        If device B responds (or is advertising), we pair them.

        Args:
            querier_mac: MAC of device making the query
            service_type: Service being queried (e.g., "_airplay._tcp")
            query_name: Full query name
            timestamp: When the query was made
        """
        with self._lock:
            querier_mac = querier_mac.upper()
            timestamp = timestamp or datetime.now()

            # Create a query key based on querier + service
            query_key = f"{querier_mac}:{service_type}:{int(timestamp.timestamp())}"

            self._pending_queries[query_key] = MDNSQueryRecord(
                query_mac=querier_mac,
                service_type=service_type,
                query_name=query_name,
                timestamp=timestamp,
            )

            # Clean up old queries (beyond timeout window)
            self._cleanup_old_queries()

            logger.debug(f"mDNS Query: {querier_mac} → {service_type}")

    def record_mdns_response(self, responder_mac: str, service_type: str,
                             timestamp: datetime = None):
        """
        Record an mDNS response and pair it with pending queries.

        When device B advertises/responds to a service, we look for
        recent queries for that service and create discovery pairs.

        Args:
            responder_mac: MAC of device responding/advertising
            service_type: Service being advertised
            timestamp: When the response was seen
        """
        with self._lock:
            responder_mac = responder_mac.upper()
            timestamp = timestamp or datetime.now()

            # Find pending queries for this service type
            now = datetime.now()
            pairs_created = 0

            for query_key, query in list(self._pending_queries.items()):
                # Skip if wrong service type
                if query.service_type != service_type:
                    continue

                # Skip if same device (can't pair with self)
                if query.query_mac == responder_mac:
                    continue

                # Skip if too old
                age = (now - query.timestamp).total_seconds()
                if age > self._query_timeout:
                    continue

                # Create discovery pair!
                pair = MDNSDiscoveryPair(
                    querier_mac=query.query_mac,
                    responder_mac=responder_mac,
                    service_type=service_type,
                    timestamp=timestamp,
                )
                self._discovery_pairs.append(pair)

                # Update discovery hits (normalized key)
                hit_key = self._normalize_mac_pair(query.query_mac, responder_mac)
                self._discovery_hits[hit_key] = self._discovery_hits.get(hit_key, 0) + 1

                # Mark query as paired
                query.paired = True
                query.response_macs.append(responder_mac)
                pairs_created += 1

                # Persist to database
                self._persist_discovery_pair(pair)

                # Notify callbacks
                self._notify_discovery(pair)

                logger.debug(f"mDNS Pair: {query.query_mac} ↔ {responder_mac} via {service_type}")

            if pairs_created > 0:
                logger.info(f"Created {pairs_created} mDNS discovery pairs for {service_type}")

    def _normalize_mac_pair(self, mac_a: str, mac_b: str) -> Tuple[str, str]:
        """Normalize MAC pair for consistent ordering."""
        return tuple(sorted([mac_a.upper(), mac_b.upper()]))

    def _cleanup_old_queries(self):
        """Remove queries older than timeout."""
        now = datetime.now()
        cutoff = self._query_timeout * 2  # Keep a bit longer for analysis

        old_keys = [
            key for key, query in self._pending_queries.items()
            if (now - query.timestamp).total_seconds() > cutoff
        ]

        for key in old_keys:
            del self._pending_queries[key]

    def _persist_discovery_pair(self, pair: MDNSDiscoveryPair):
        """Persist discovery pair to database."""
        try:
            with sqlite3.connect(str(PRESENCE_DB)) as conn:
                # Insert pair record
                conn.execute('''
                    INSERT OR IGNORE INTO mdns_discovery_pairs
                    (querier_mac, responder_mac, service_type, timestamp)
                    VALUES (?, ?, ?, ?)
                ''', (
                    pair.querier_mac,
                    pair.responder_mac,
                    pair.service_type,
                    pair.timestamp.isoformat(),
                ))

                # Update discovery hits
                hit_key = self._normalize_mac_pair(pair.querier_mac, pair.responder_mac)
                conn.execute('''
                    INSERT INTO discovery_hits (mac_a, mac_b, hit_count, last_hit)
                    VALUES (?, ?, 1, ?)
                    ON CONFLICT(mac_a, mac_b) DO UPDATE SET
                        hit_count = hit_count + 1,
                        last_hit = excluded.last_hit
                ''', (hit_key[0], hit_key[1], pair.timestamp.isoformat()))

                conn.commit()
        except Exception as e:
            logger.debug(f"Could not persist discovery pair: {e}")

    def get_discovery_hits(self, mac_a: str, mac_b: str) -> int:
        """
        Get the number of mDNS discovery hits between two devices.

        This is a key metric for affinity scoring:
        - High hit count = devices frequently discover each other
        - Indicates same-user ownership or strong relationship

        Args:
            mac_a: First device MAC
            mac_b: Second device MAC

        Returns:
            Number of discovery hits (query/response pairs)
        """
        hit_key = self._normalize_mac_pair(mac_a, mac_b)
        return self._discovery_hits.get(hit_key, 0)

    def get_all_discovery_hits(self) -> Dict[Tuple[str, str], int]:
        """Get all discovery hit counts for all device pairs."""
        return dict(self._discovery_hits)

    def register_discovery_callback(self, callback: callable):
        """
        Register callback for discovery pair notifications.

        Callback receives MDNSDiscoveryPair object when new pair is detected.
        Used by connection_graph.py to update affinity scores in real-time.
        """
        self._discovery_callbacks.append(callback)

    def _notify_discovery(self, pair: MDNSDiscoveryPair):
        """Notify all registered callbacks of new discovery pair."""
        for callback in self._discovery_callbacks:
            try:
                callback(pair)
            except Exception as e:
                logger.debug(f"Discovery callback failed: {e}")

    def load_discovery_hits_from_db(self):
        """Load discovery hits from database on startup."""
        try:
            with sqlite3.connect(str(PRESENCE_DB)) as conn:
                rows = conn.execute('''
                    SELECT mac_a, mac_b, hit_count FROM discovery_hits
                ''').fetchall()

                for row in rows:
                    self._discovery_hits[(row[0], row[1])] = row[2]

                logger.debug(f"Loaded {len(rows)} discovery hit records")
        except Exception as e:
            logger.debug(f"Could not load discovery hits: {e}")

    def _ip_to_mac(self, ip: str) -> Optional[str]:
        """Convert IP to MAC via ARP table."""
        if not ip:
            return None
        try:
            # Read /proc/net/arp directly (works in containers without iproute2)
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        # Skip incomplete entries (00:00:00:00:00:00)
                        if mac and mac != '00:00:00:00:00:00':
                            return mac.upper()
        except Exception:
            pass
        return None

    # =========================================================================
    # BLE SENSING
    # =========================================================================

    async def _ble_scan_loop(self):
        """Background BLE scanning loop."""
        if not HAS_BLEAK:
            logger.warning("bleak not installed - BLE sensing disabled")
            return

        while self.running:
            try:
                devices = await BleakScanner.discover(timeout=5.0)

                for device in devices:
                    self._process_ble_device(device)

                await asyncio.sleep(10)  # Scan every 10 seconds

            except Exception as e:
                logger.debug(f"BLE scan error: {e}")
                await asyncio.sleep(30)

    def _process_ble_device(self, device):
        """Process a discovered BLE device for cross-ecosystem detection."""
        with self._lock:
            try:
                # BLE uses different addressing - we need to correlate
                if not device.metadata:
                    return

                manufacturer_data = device.metadata.get('manufacturer_data', {})
                service_uuids = device.metadata.get('uuids', [])

                # Process by manufacturer ID
                for mfr_id, ecosystem in BLE_MANUFACTURER_IDS.items():
                    if mfr_id in manufacturer_data:
                        data = manufacturer_data[mfr_id]

                        if ecosystem == 'apple':
                            self._process_apple_ble(device, data)
                        elif ecosystem == 'google':
                            self._process_google_ble(device, data)
                        elif ecosystem == 'samsung':
                            self._process_samsung_ble(device, data)
                        elif ecosystem == 'xiaomi':
                            self._process_xiaomi_ble(device, data)
                        elif ecosystem == 'huawei':
                            self._process_huawei_ble(device, data)

                # Also check service UUIDs
                for uuid in service_uuids:
                    uuid_short = uuid.upper()[-4:]  # Get short UUID
                    if uuid_short in BLE_SERVICE_UUIDS:
                        service_type = BLE_SERVICE_UUIDS[uuid_short]
                        self._record_ble_service_event(device, service_type)

            except Exception as e:
                logger.debug(f"Error processing BLE device: {e}")

    def _process_apple_ble(self, device, data: bytes):
        """Process Apple-specific BLE advertisement."""
        # Apple Continuity packet structure:
        # Byte 0: Type (0x10 = Nearby, 0x0C = Handoff, 0x05 = AirDrop, etc.)
        # Remaining bytes: Type-specific data

        if len(data) < 2:
            return

        packet_type = data[0]

        # Nearby Info (0x10) - Contains device status
        if packet_type == 0x10:
            # This indicates device presence and status
            logger.debug(f"Apple Nearby packet: {device.name}")

        # Handoff (0x0C) - Active handoff between devices
        elif packet_type == 0x0C:
            # Handoff indicates same-account devices
            logger.debug(f"Apple Handoff packet: {device.name}")
            self._record_handoff_event(device)

        # AirDrop (0x05)
        elif packet_type == 0x05:
            logger.debug(f"Apple AirDrop packet: {device.name}")

    def _process_google_ble(self, device, data: bytes):
        """Process Google-specific BLE advertisement."""
        # Google Fast Pair uses specific data patterns
        if len(data) >= 3:
            # Fast Pair model ID is in first 3 bytes
            logger.debug(f"Google BLE device: {device.name}")
            self._record_ecosystem_event(device, EcosystemType.GOOGLE, 'ble_presence')

    def _process_samsung_ble(self, device, data: bytes):
        """Process Samsung-specific BLE advertisement."""
        # Samsung SmartThings and Galaxy devices
        if len(data) >= 2:
            logger.debug(f"Samsung BLE device: {device.name}")
            self._record_ecosystem_event(device, EcosystemType.SAMSUNG, 'ble_presence')

            # Galaxy Buds connection events indicate same-user
            if len(data) >= 4 and data[0] == 0x42:  # Buds connection marker
                self._record_handoff_event(device, ecosystem='samsung')

    def _process_xiaomi_ble(self, device, data: bytes):
        """Process Xiaomi-specific BLE advertisement."""
        # Xiaomi Mi Home devices have specific packet structure
        if len(data) >= 5:
            logger.debug(f"Xiaomi BLE device: {device.name}")
            self._record_ecosystem_event(device, EcosystemType.XIAOMI, 'ble_presence')

            # Mi Band sync events (frame type 0x05)
            if data[0] == 0x05:
                self._record_sync_event(device, ecosystem='xiaomi')

    def _process_huawei_ble(self, device, data: bytes):
        """Process Huawei-specific BLE advertisement."""
        # Huawei HiLink and Watch devices
        if len(data) >= 4:
            logger.debug(f"Huawei BLE device: {device.name}")
            self._record_ecosystem_event(device, EcosystemType.HUAWEI, 'ble_presence')

            # Huawei Share proximity event
            if len(data) >= 6 and data[0] == 0x01:
                self._record_handoff_event(device, ecosystem='huawei')

    def _record_ecosystem_event(self, ble_device, ecosystem: EcosystemType, event_type: str):
        """Record an ecosystem detection event for correlation."""
        self._record_event(PresenceEvent(
            mac='BLE:' + ble_device.address,
            event_type=event_type,
            timestamp=datetime.now().isoformat(),
            details={
                'name': ble_device.name,
                'rssi': ble_device.rssi,
                'ecosystem': ecosystem.value
            }
        ))

    def _record_sync_event(self, ble_device, ecosystem: str):
        """Record a sync event (band/watch syncing with phone)."""
        self._record_event(PresenceEvent(
            mac='BLE:' + ble_device.address,
            event_type='sync',
            timestamp=datetime.now().isoformat(),
            details={
                'name': ble_device.name,
                'rssi': ble_device.rssi,
                'ecosystem': ecosystem,
                'sync_type': 'wearable'
            }
        ))

    def _record_ble_service_event(self, ble_device, service_type: str):
        """Record a BLE service UUID detection event."""
        self._record_event(PresenceEvent(
            mac='BLE:' + ble_device.address,
            event_type='ble_service',
            timestamp=datetime.now().isoformat(),
            details={
                'name': ble_device.name,
                'rssi': ble_device.rssi,
                'service': service_type
            }
        ))

    def _record_handoff_event(self, ble_device, ecosystem: str = 'apple'):
        """Record a handoff event for correlation."""
        self._record_event(PresenceEvent(
            mac='BLE:' + ble_device.address,
            event_type='handoff',
            timestamp=datetime.now().isoformat(),
            details={
                'name': ble_device.name,
                'rssi': ble_device.rssi
            }
        ))

    # =========================================================================
    # SPATIAL CORRELATION
    # =========================================================================

    def record_network_event(self, mac: str, event_type: str,
                             access_point: Optional[str] = None,
                             details: Optional[Dict] = None):
        """Record a network presence event (join/leave/roam)."""
        with self._lock:
            mac = mac.upper()
            now = datetime.now().isoformat()

            # Get or create device
            if mac not in self._devices:
                self._devices[mac] = DevicePresence(
                    mac=mac,
                    first_seen=now
                )

            device = self._devices[mac]
            device.last_seen = now
            device.access_point = access_point

            if event_type == 'join':
                device.state = PresenceState.ACTIVE
            elif event_type == 'leave':
                device.state = PresenceState.DEPARTED

            # Record event
            self._record_event(PresenceEvent(
                mac=mac,
                event_type=event_type,
                timestamp=now,
                access_point=access_point,
                details=details or {}
            ))

            # Update correlation
            self._update_time_correlation(mac)

    def _update_time_correlation(self, mac: str):
        """Update time correlation for a device based on recent events."""
        with self._lock:
            if mac not in self._devices:
                return

            device = self._devices[mac]
            now = datetime.now()
            window_start = now - timedelta(seconds=self._correlation_window)

            # Get recent events for this device
            device_events = [
                e for e in self._event_window
                if e.mac == mac and
                datetime.fromisoformat(e.timestamp) > window_start
            ]

            # Get events from other devices in same time window
            other_events = [
                e for e in self._event_window
                if e.mac != mac and
                datetime.fromisoformat(e.timestamp) > window_start
            ]

            if not device_events or not other_events:
                return

            # Calculate correlation with each other device
            correlations = []

            for other_mac in set(e.mac for e in other_events):
                other_dev_events = [e for e in other_events if e.mac == other_mac]

                # Time difference correlation
                correlation = self._calculate_event_correlation(
                    device_events, other_dev_events
                )
                if correlation > 0.5:
                    correlations.append((other_mac, correlation))

            if correlations:
                device.time_correlation = max(c[1] for c in correlations)

    def _calculate_event_correlation(self, events_a: List[PresenceEvent],
                                      events_b: List[PresenceEvent]) -> float:
        """Calculate temporal correlation between two event sets."""
        if not events_a or not events_b:
            return 0.0

        # Count events that occur within 60 seconds of each other
        correlated = 0
        total = len(events_a)

        for ea in events_a:
            ta = datetime.fromisoformat(ea.timestamp)
            for eb in events_b:
                tb = datetime.fromisoformat(eb.timestamp)
                if abs((ta - tb).total_seconds()) < 60:
                    if ea.event_type == eb.event_type:  # Same type (both join, both leave)
                        correlated += 1
                        break

        return correlated / total if total > 0 else 0.0

    # =========================================================================
    # SYNC DETECTION
    # =========================================================================

    def record_sync_activity(self, mac: str, sync_type: str,
                            peer_mac: Optional[str] = None):
        """Record sync/handoff activity between devices."""
        with self._lock:
            mac = mac.upper()
            if mac not in self._devices:
                self._devices[mac] = DevicePresence(mac=mac)

            device = self._devices[mac]
            device.sync_frequency += 1

            if sync_type == 'handoff':
                device.handoff_count += 1

            self._record_event(PresenceEvent(
                mac=mac,
                event_type='sync',
                timestamp=datetime.now().isoformat(),
                details={
                    'sync_type': sync_type,
                    'peer_mac': peer_mac
                }
            ))

    # =========================================================================
    # EVENT MANAGEMENT
    # =========================================================================

    def _record_event(self, event: PresenceEvent):
        """Record a presence event."""
        self._events.append(event)
        self._event_window.append(event)

        # Trim window
        now = datetime.now()
        cutoff = now - timedelta(seconds=self._correlation_window)
        self._event_window = [
            e for e in self._event_window
            if datetime.fromisoformat(e.timestamp) > cutoff
        ]

        # Persist to database
        try:
            with sqlite3.connect(str(PRESENCE_DB)) as conn:
                conn.execute('''
                    INSERT INTO presence_events
                    (mac, event_type, timestamp, access_point, details_json)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    event.mac,
                    event.event_type,
                    event.timestamp,
                    event.access_point,
                    json.dumps(event.details)
                ))
                conn.commit()
        except Exception as e:
            logger.debug(f"Could not persist event: {e}")

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def start(self):
        """Start all presence sensing."""
        self.running = True

        # Load persisted discovery hits
        self.load_discovery_hits_from_db()

        # Start mDNS
        self.start_mdns_sensing()

        # Start BLE in background
        if HAS_BLEAK:
            def run_ble():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._ble_scan_loop())

            ble_thread = threading.Thread(target=run_ble, daemon=True)
            ble_thread.start()

        # Start periodic persistence (every 30 seconds)
        def persist_loop():
            import time
            while self.running:
                time.sleep(30)
                self.persist_state()

        persist_thread = threading.Thread(target=persist_loop, daemon=True)
        persist_thread.start()

        logger.info("Presence sensor started")

    def stop(self):
        """Stop all presence sensing."""
        self.running = False

        if self._zeroconf:
            for browser in self._browsers:
                browser.cancel()
            self._zeroconf.close()

        logger.info("Presence sensor stopped")

    def get_device(self, mac: str) -> Optional[DevicePresence]:
        """Get presence info for a device."""
        with self._lock:
            return self._devices.get(mac.upper())

    def get_all_devices(self) -> List[DevicePresence]:
        """Get all known devices."""
        with self._lock:
            return list(self._devices.values())

    def get_ecosystem_devices(self, ecosystem: EcosystemType) -> List[DevicePresence]:
        """Get all devices in an ecosystem."""
        with self._lock:
            return [
                d for d in self._devices.values()
                if d.ecosystem == ecosystem
            ]

    def get_behavior_features(self, mac: str) -> Optional[List[float]]:
        """Get behavior features for ML clustering."""
        with self._lock:
            device = self._devices.get(mac.upper())
            if not device:
                return None

            return [
                device.time_correlation,      # 0-1
                device.proximity_score,       # 0-1
                len(device.mdns_services) / 10,  # Normalized service count
                device.sync_frequency / 100,  # Normalized sync frequency
                device.handoff_count / 10,    # Normalized handoff count
            ]

    def update_bubble_assignment(self, mac: str, bubble_id: str, confidence: float):
        """Update device's bubble assignment."""
        with self._lock:
            mac = mac.upper()
            if mac in self._devices:
                self._devices[mac].bubble_id = bubble_id
                self._devices[mac].bubble_confidence = confidence

    def persist_state(self):
        """Persist current state to database."""
        with self._lock:
            try:
                with sqlite3.connect(str(PRESENCE_DB)) as conn:
                    for device in self._devices.values():
                        conn.execute('''
                            INSERT OR REPLACE INTO device_presence
                            (mac, ip, hostname, ecosystem, state, mdns_device_id,
                             mdns_model, bubble_id, bubble_confidence, sync_frequency,
                             proximity_score, time_correlation, first_seen, last_seen,
                             session_duration)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            device.mac,
                            device.ip,
                            device.hostname,
                            device.ecosystem.value,
                            device.state.value,
                            device.mdns_device_id,
                            device.mdns_model,
                            device.bubble_id,
                            device.bubble_confidence,
                            device.sync_frequency,
                            device.proximity_score,
                            device.time_correlation,
                            device.first_seen,
                            device.last_seen,
                            device.session_duration
                        ))
                    conn.commit()
            except Exception as e:
                logger.error(f"Could not persist state: {e}")

    def get_stats(self) -> Dict:
        """Get sensor statistics."""
        with self._lock:
            ecosystems = defaultdict(int)
            for d in self._devices.values():
                ecosystems[d.ecosystem.value] += 1

            # Discovery pair stats
            total_discovery_hits = sum(self._discovery_hits.values())
            device_pairs_with_hits = len(self._discovery_hits)

            return {
                'total_devices': len(self._devices),
                'ecosystems': dict(ecosystems),
                'total_events': len(self._events),
                'window_events': len(self._event_window),
                'mdns_enabled': HAS_ZEROCONF,
                'mdns_available': self._mdns_available,
                'ble_enabled': HAS_BLEAK,
                'running': self.running,
                # mDNS Query/Response Pairing stats
                'pending_queries': len(self._pending_queries),
                'discovery_pairs': len(self._discovery_pairs),
                'total_discovery_hits': total_discovery_hits,
                'device_pairs_with_hits': device_pairs_with_hits,
            }


# =============================================================================
# SINGLETON
# =============================================================================

_sensor_instance: Optional[PresenceSensor] = None
_sensor_lock = threading.Lock()


def get_presence_sensor(interface: str = "FTS") -> PresenceSensor:
    """Get singleton presence sensor instance."""
    global _sensor_instance

    with _sensor_lock:
        if _sensor_instance is None:
            _sensor_instance = PresenceSensor(interface)
        return _sensor_instance


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse
    import signal
    import sys

    parser = argparse.ArgumentParser(description='Presence Sensor')
    parser.add_argument('--interface', default='FTS', help='Network interface')
    parser.add_argument('--scan', action='store_true', help='Run discovery scan')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon (systemd service mode)')

    args = parser.parse_args()

    # Configure logging based on mode
    if args.daemon:
        # Daemon mode: log to file with timestamps
        log_file = Path('/var/log/fortress/presence-sensor.log')
        log_file.parent.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s [presence-sensor]: %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)  # Also log to stdout for journald
            ]
        )
    else:
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    sensor = get_presence_sensor(args.interface)

    if args.stats:
        stats = sensor.get_stats()
        print("\nPresence Sensor Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    elif args.daemon:
        # Daemon mode for systemd service
        logger.info(f"Starting presence sensor daemon on interface {args.interface}")
        logger.info(f"mDNS support: {HAS_ZEROCONF}, BLE support: {HAS_BLEAK}")

        # Signal handlers for graceful shutdown
        def handle_signal(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            sensor.stop()
            sys.exit(0)

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

        sensor.start()
        try:
            while True:
                time.sleep(30)  # Periodic health check
                devices = sensor.get_all_devices()
                logger.debug(f"Active devices: {len(devices)}")
        except Exception as e:
            logger.error(f"Daemon error: {e}")
            sensor.stop()
            sys.exit(1)

    elif args.scan:
        print("Starting presence scan (Ctrl+C to stop)...")
        sensor.start()
        try:
            while True:
                time.sleep(5)
                devices = sensor.get_all_devices()
                print(f"\nDiscovered {len(devices)} devices:")
                for d in devices[:10]:
                    print(f"  {d.mac}: {d.ecosystem.value} - {d.mdns_model or 'Unknown'}")
        except KeyboardInterrupt:
            sensor.stop()

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
