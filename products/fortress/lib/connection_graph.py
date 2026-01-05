#!/usr/bin/env python3
"""
Connection Graph Analyzer - Device-to-Device Communication Detection

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module parses Zeek connection logs to detect device-to-device
communication patterns, enabling cross-ecosystem bubble detection.

The Innovation:
When Mom's iPhone shares photos with her Huawei Watch via WiFi Direct,
or when Kids' Samsung phone syncs with their Xiaomi band, these
communication patterns reveal same-user ownership REGARDLESS of ecosystem.

Detection Methods:
1. Zeek conn.log - TCP/UDP connection records between LAN devices
2. Local service traffic - mDNS, AirPlay, Spotify Connect, casting
3. High-frequency short connections - File transfers, screen mirrors
4. Bidirectional traffic patterns - Not just client→server

Data Flow:
┌─────────────────────────────────────────────────────────────────┐
│  Zeek Network Monitor (fts-zeek container)                       │
│       │                                                          │
│       ▼                                                          │
│  /var/log/zeek/current/conn.log                                  │
│       │                                                          │
│       ▼                                                          │
│  ConnectionGraphAnalyzer                                          │
│       │                                                          │
│       ├──▶ Parse connection records                              │
│       ├──▶ Filter LAN-only traffic (exclude internet)            │
│       ├──▶ Build device relationship graph                       │
│       ├──▶ Calculate D2D affinity scores                         │
│       └──▶ Return clusters for bubble formation                  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

Integration:
This module feeds into BehavioralClusteringEngine to add D2D features
that enable cross-ecosystem bubble detection.
"""

import json
import logging
import re
import sqlite3
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import ipaddress

logger = logging.getLogger(__name__)

# Zeek log locations
ZEEK_LOG_DIR = Path('/var/log/zeek/current')
ZEEK_CONN_LOG = ZEEK_LOG_DIR / 'conn.log'

# Database for D2D relationship storage
D2D_DB = Path('/var/lib/hookprobe/d2d_graph.db')

# LAN network ranges (RFC 1918)
LAN_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
]

# Local service ports that indicate D2D communication
D2D_SERVICE_PORTS = {
    # Apple ecosystem
    5353: 'mdns',                    # mDNS/Bonjour
    7000: 'airplay',                 # AirPlay
    7100: 'airplay_mirror',          # AirPlay Mirroring
    3689: 'daap',                    # iTunes sharing
    62078: 'iphone_sync',            # iPhone USB sync

    # Google ecosystem
    8008: 'chromecast',              # Chromecast
    8009: 'chromecast_ssl',          # Chromecast (SSL)
    8443: 'google_home',             # Google Home

    # Samsung ecosystem
    8001: 'samsung_smartthings',     # SmartThings
    8002: 'samsung_tv',              # Samsung TV
    55000: 'samsung_allshare',       # AllShare/DLNA

    # Xiaomi ecosystem
    54321: 'xiaomi_miio',            # Xiaomi Mi Home
    54322: 'xiaomi_gateway',         # Xiaomi Gateway

    # Generic smart home
    1900: 'upnp_ssdp',               # UPnP/SSDP
    5000: 'upnp_av',                 # UPnP AV
    10001: 'ubiquiti',               # Ubiquiti discovery

    # Media streaming
    57621: 'spotify_connect',        # Spotify Connect
    8200: 'trivial_ftp',             # GoTV/media
    1883: 'mqtt',                    # IoT MQTT
    8883: 'mqtt_ssl',                # IoT MQTT (SSL)

    # File sharing
    445: 'smb',                      # SMB/CIFS
    139: 'netbios',                  # NetBIOS
    548: 'afp',                      # Apple Filing Protocol
    2049: 'nfs',                     # NFS

    # Remote access (indicates same-user devices)
    22: 'ssh',                       # SSH
    5900: 'vnc',                     # VNC
    3389: 'rdp',                     # RDP
}

# High-affinity ports (strong indicator of same-user)
HIGH_AFFINITY_PORTS = {
    7000, 7100,  # AirPlay (almost always same user)
    62078,       # iPhone sync
    548,         # AFP (Apple file sharing)
    57621,       # Spotify Connect
    5900,        # VNC
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class D2DConnection:
    """A device-to-device connection record."""
    src_ip: str
    src_mac: str
    dst_ip: str
    dst_mac: str
    port: int
    protocol: str
    service: str
    bytes_sent: int
    bytes_recv: int
    packets: int
    duration: float
    timestamp: datetime

    @property
    def is_bidirectional(self) -> bool:
        """Check if traffic flows both ways (strong D2D indicator)."""
        return self.bytes_sent > 0 and self.bytes_recv > 0

    @property
    def is_high_affinity(self) -> bool:
        """Check if this is a high-affinity service."""
        return self.port in HIGH_AFFINITY_PORTS


@dataclass
class DeviceRelationship:
    """Relationship between two devices based on communication."""
    mac_a: str
    mac_b: str

    # Connection statistics
    connection_count: int = 0
    total_bytes: int = 0
    total_duration: float = 0.0

    # Service breakdown
    services_used: Dict[str, int] = field(default_factory=dict)

    # Affinity scoring
    bidirectional_count: int = 0
    high_affinity_count: int = 0

    # Timestamps
    first_seen: datetime = None
    last_seen: datetime = None

    # Affinity Score components (can be updated by mDNS analysis)
    discovery_hits: int = 0       # mDNS query/response pairs
    temporal_sync_score: float = 0.0  # Join/leave timing correlation

    def calculate_affinity_score(self) -> float:
        """
        Calculate D2D affinity score using weighted algorithm.

        Formula: S_aff = (Discovery Hits × 10) + (D2D Flows × 5) + (Temporal Sync × 2)

        Normalized to 0.0 - 1.0 scale.

        Components:
        - Discovery Hits: mDNS query/response exchanges (strongest indicator)
        - D2D Flows: Direct packet exchanges (AirPlay, sync, file sharing)
        - Temporal Sync: Devices join/leave network together (physical proximity)
        """
        # Raw affinity score (unbounded)
        raw_score = 0.0

        # Discovery Hits (weight: 10) - mDNS browsing indicates same ecosystem
        # Each mDNS exchange is a strong indicator
        raw_score += self.discovery_hits * 10

        # D2D Flows (weight: 5) - Direct communication
        # High-affinity services count more
        d2d_score = self.connection_count + (self.high_affinity_count * 2)
        raw_score += d2d_score * 5

        # Temporal Sync (weight: 2) - Join/leave together
        # temporal_sync_score is already 0-1, scale appropriately
        raw_score += self.temporal_sync_score * 20  # Scale up before weighting

        # Bidirectional bonus - devices that talk both ways are strongly linked
        if self.connection_count > 0:
            bidir_ratio = self.bidirectional_count / self.connection_count
            raw_score += bidir_ratio * 15

        # Service diversity bonus - multiple services = stronger relationship
        service_count = len(self.services_used)
        raw_score += min(service_count, 5) * 3

        # Recency decay - recent activity counts more
        recency_multiplier = 1.0
        if self.last_seen:
            age = datetime.now() - self.last_seen
            if age > timedelta(hours=24):
                recency_multiplier = 0.5
            elif age > timedelta(hours=1):
                recency_multiplier = 0.8

        raw_score *= recency_multiplier

        # Normalize to 0-1 scale
        # Threshold: 100 points = definitely same user (1.0)
        # 50 points = high confidence (0.5+)
        normalized = min(raw_score / 100, 1.0)

        return normalized


@dataclass
class D2DCluster:
    """A cluster of devices based on D2D communication."""
    devices: Set[str]  # MAC addresses
    affinity_matrix: Dict[Tuple[str, str], float]
    avg_affinity: float
    primary_services: List[str]

    def to_dict(self) -> Dict:
        return {
            'devices': list(self.devices),
            'device_count': len(self.devices),
            'avg_affinity': self.avg_affinity,
            'primary_services': self.primary_services,
        }


# =============================================================================
# CONNECTION GRAPH ANALYZER
# =============================================================================

class ConnectionGraphAnalyzer:
    """
    Analyzes Zeek connection logs to build device relationship graph.

    Device-to-device communication patterns reveal same-user ownership:
    - AirDrop/WiFi Direct between iPhone ↔ Samsung (sharing photos)
    - mDNS queries from Phone → Smart Band (fitness sync)
    - Local API calls between app ↔ wearable
    - File sharing between laptop ↔ phone
    """

    # Analysis parameters
    LOOKBACK_HOURS = 24           # Analyze last 24 hours of logs
    MIN_CONNECTIONS = 3           # Minimum connections to consider relationship
    AFFINITY_THRESHOLD = 0.3      # Minimum affinity for clustering

    def __init__(self, db_path: Path = D2D_DB):
        self.db_path = db_path
        self.relationships: Dict[Tuple[str, str], DeviceRelationship] = {}
        self.ip_to_mac: Dict[str, str] = {}
        self._lock = __import__('threading').Lock()

        self._ensure_db()
        self._load_ip_mac_mapping()

    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS d2d_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_mac TEXT NOT NULL,
                    dst_mac TEXT NOT NULL,
                    port INTEGER,
                    service TEXT,
                    bytes_total INTEGER,
                    is_bidirectional INTEGER,
                    timestamp TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS device_relationships (
                    mac_a TEXT NOT NULL,
                    mac_b TEXT NOT NULL,
                    connection_count INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    bidirectional_count INTEGER DEFAULT 0,
                    high_affinity_count INTEGER DEFAULT 0,
                    services_json TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    affinity_score REAL DEFAULT 0.0,
                    PRIMARY KEY (mac_a, mac_b)
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_d2d_timestamp
                ON d2d_connections(timestamp)
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_rel_affinity
                ON device_relationships(affinity_score DESC)
            ''')
            conn.commit()

    def _load_ip_mac_mapping(self):
        """Load IP to MAC mapping from ARP table."""
        try:
            result = subprocess.run(
                ['ip', 'neigh', 'show'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                # Format: 10.200.0.5 dev FTS lladdr aa:bb:cc:dd:ee:ff REACHABLE
                parts = line.split()
                if len(parts) >= 5 and 'lladdr' in parts:
                    ip = parts[0]
                    mac_idx = parts.index('lladdr') + 1
                    if mac_idx < len(parts):
                        mac = parts[mac_idx].upper()
                        self.ip_to_mac[ip] = mac

            logger.debug(f"Loaded {len(self.ip_to_mac)} IP→MAC mappings")
        except Exception as e:
            logger.warning(f"Failed to load IP→MAC mapping: {e}")

    def _is_lan_ip(self, ip: str) -> bool:
        """Check if IP is in LAN range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in LAN_NETWORKS)
        except ValueError:
            return False

    def _normalize_mac_pair(self, mac_a: str, mac_b: str) -> Tuple[str, str]:
        """Normalize MAC pair for consistent key ordering."""
        return tuple(sorted([mac_a.upper(), mac_b.upper()]))

    def parse_zeek_conn_log(self, log_path: Path = None) -> List[D2DConnection]:
        """
        Parse Zeek conn.log for device-to-device connections.

        Zeek conn.log format (tab-separated):
        ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service,
        duration, orig_bytes, resp_bytes, conn_state, ...

        Returns:
            List of D2DConnection objects for LAN traffic only
        """
        log_path = log_path or ZEEK_CONN_LOG

        if not log_path.exists():
            logger.warning(f"Zeek conn.log not found: {log_path}")
            return []

        connections = []
        cutoff = datetime.now() - timedelta(hours=self.LOOKBACK_HOURS)

        try:
            with open(log_path, 'r') as f:
                for line in f:
                    # Skip comments and headers
                    if line.startswith('#'):
                        continue

                    try:
                        conn = self._parse_conn_line(line, cutoff)
                        if conn:
                            connections.append(conn)
                    except Exception as e:
                        logger.debug(f"Failed to parse line: {e}")
                        continue
        except Exception as e:
            logger.error(f"Failed to read Zeek conn.log: {e}")

        logger.info(f"Parsed {len(connections)} D2D connections from Zeek")
        return connections

    def _parse_conn_line(self, line: str, cutoff: datetime) -> Optional[D2DConnection]:
        """Parse a single conn.log line."""
        parts = line.strip().split('\t')
        if len(parts) < 12:
            return None

        # Parse timestamp
        try:
            ts = float(parts[0])
            timestamp = datetime.fromtimestamp(ts)
            if timestamp < cutoff:
                return None
        except (ValueError, IndexError):
            return None

        # Extract IPs
        src_ip = parts[2]
        dst_ip = parts[4]

        # Only keep LAN-to-LAN traffic
        if not (self._is_lan_ip(src_ip) and self._is_lan_ip(dst_ip)):
            return None

        # Skip traffic to/from gateway (typically .1)
        if src_ip.endswith('.1') or dst_ip.endswith('.1'):
            return None

        # Get MACs
        src_mac = self.ip_to_mac.get(src_ip, '').upper()
        dst_mac = self.ip_to_mac.get(dst_ip, '').upper()

        if not src_mac or not dst_mac:
            return None

        # Skip if same device
        if src_mac == dst_mac:
            return None

        # Parse port and service
        try:
            dst_port = int(parts[5])
        except (ValueError, IndexError):
            dst_port = 0

        service = parts[7] if len(parts) > 7 and parts[7] != '-' else ''

        # Check if this is a D2D service port
        service_name = D2D_SERVICE_PORTS.get(dst_port, service)
        if not service_name and dst_port > 1024:
            service_name = 'ephemeral'

        # Parse traffic stats
        try:
            duration = float(parts[8]) if parts[8] != '-' else 0.0
            bytes_sent = int(parts[9]) if parts[9] != '-' else 0
            bytes_recv = int(parts[10]) if parts[10] != '-' else 0
        except (ValueError, IndexError):
            duration = 0.0
            bytes_sent = 0
            bytes_recv = 0

        # Parse packet count (if available)
        try:
            packets = int(parts[16]) if len(parts) > 16 and parts[16] != '-' else 1
        except (ValueError, IndexError):
            packets = 1

        return D2DConnection(
            src_ip=src_ip,
            src_mac=src_mac,
            dst_ip=dst_ip,
            dst_mac=dst_mac,
            port=dst_port,
            protocol=parts[6] if len(parts) > 6 else 'tcp',
            service=service_name,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            packets=packets,
            duration=duration,
            timestamp=timestamp,
        )

    def update_relationships(self, connections: List[D2DConnection] = None):
        """
        Update device relationships from connection data.

        This method:
        1. Parses Zeek conn.log (if connections not provided)
        2. Updates relationship statistics
        3. Calculates affinity scores
        4. Persists to database
        """
        if connections is None:
            connections = self.parse_zeek_conn_log()

        if not connections:
            logger.debug("No D2D connections to process")
            return

        with self._lock:
            # Process each connection
            for conn in connections:
                key = self._normalize_mac_pair(conn.src_mac, conn.dst_mac)

                if key not in self.relationships:
                    self.relationships[key] = DeviceRelationship(
                        mac_a=key[0],
                        mac_b=key[1],
                        first_seen=conn.timestamp,
                    )

                rel = self.relationships[key]
                rel.connection_count += 1
                rel.total_bytes += conn.bytes_sent + conn.bytes_recv
                rel.total_duration += conn.duration
                rel.last_seen = conn.timestamp

                # Track services
                if conn.service:
                    rel.services_used[conn.service] = \
                        rel.services_used.get(conn.service, 0) + 1

                # Track bidirectional and high-affinity
                if conn.is_bidirectional:
                    rel.bidirectional_count += 1
                if conn.is_high_affinity:
                    rel.high_affinity_count += 1

            # Persist to database
            self._persist_relationships()

        logger.info(f"Updated {len(self.relationships)} device relationships")

    def analyze_mdns_browsing(self):
        """
        Analyze mDNS browsing patterns to detect discovery hits.

        mDNS "browsing" is a strong indicator of same-user devices:
        - When Dad opens Remote app, iPhone queries _touch-remote._tcp
        - Apple TV responds, revealing same-ecosystem relationship

        Uses tshark for lightweight capture or parses Zeek dns.log.
        """
        # First try Zeek dns.log (if available)
        dns_log = ZEEK_LOG_DIR / 'dns.log'
        if dns_log.exists():
            self._parse_zeek_dns_log(dns_log)
            return

        # Fallback: Quick tshark capture for mDNS
        self._capture_mdns_traffic()

    def _parse_zeek_dns_log(self, log_path: Path):
        """Parse Zeek dns.log for mDNS query/response pairs."""
        try:
            cutoff = datetime.now() - timedelta(hours=self.LOOKBACK_HOURS)

            # Track queries and responses
            queries: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)  # query → [(src_mac, time)]
            responses: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)  # query → [(src_mac, time)]

            with open(log_path, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue

                    parts = line.strip().split('\t')
                    if len(parts) < 10:
                        continue

                    try:
                        ts = datetime.fromtimestamp(float(parts[0]))
                        if ts < cutoff:
                            continue
                    except (ValueError, IndexError):
                        continue

                    src_ip = parts[2]
                    query = parts[9] if len(parts) > 9 else ''

                    # Only interested in mDNS (multicast DNS)
                    if not query or '.local' not in query:
                        continue

                    # Get MAC from IP
                    src_mac = self.ip_to_mac.get(src_ip, '').upper()
                    if not src_mac:
                        continue

                    # Check if query or response (QR flag in parts[13] if available)
                    # Simplified: track all mDNS activity per device
                    queries[query].append((src_mac, ts))

            # Find devices that query/respond to same services
            for query, query_list in queries.items():
                macs = list(set(m for m, t in query_list))
                if len(macs) >= 2:
                    # These devices are interacting via mDNS
                    for i in range(len(macs)):
                        for j in range(i + 1, len(macs)):
                            key = self._normalize_mac_pair(macs[i], macs[j])
                            if key in self.relationships:
                                self.relationships[key].discovery_hits += 1
                            else:
                                self.relationships[key] = DeviceRelationship(
                                    mac_a=key[0],
                                    mac_b=key[1],
                                    discovery_hits=1,
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                )

            logger.info(f"Analyzed mDNS browsing patterns")

        except Exception as e:
            logger.warning(f"Failed to parse Zeek dns.log: {e}")

    def _capture_mdns_traffic(self, duration: int = 10):
        """
        Quick tshark capture for mDNS traffic.

        One-liner approach for lightweight mDNS analysis.
        """
        try:
            # Run tshark for quick capture
            result = subprocess.run(
                ['tshark', '-i', 'FTS', '-Y', 'mdns',
                 '-T', 'fields', '-e', 'eth.src', '-e', 'mdns.qry.name',
                 '-a', f'duration:{duration}'],
                capture_output=True, text=True, timeout=duration + 5
            )

            if result.returncode != 0:
                logger.debug(f"tshark capture failed: {result.stderr}")
                return

            # Parse output: each line is "src_mac\tquery_name"
            queries: Dict[str, Set[str]] = defaultdict(set)  # query → {macs}

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) >= 2:
                    mac = parts[0].upper().replace(':', ':')
                    query = parts[1]
                    if query and '.local' in query:
                        queries[query].add(mac)

            # Find relationships from shared mDNS queries
            for query, macs in queries.items():
                macs_list = list(macs)
                if len(macs_list) >= 2:
                    for i in range(len(macs_list)):
                        for j in range(i + 1, len(macs_list)):
                            key = self._normalize_mac_pair(macs_list[i], macs_list[j])
                            if key not in self.relationships:
                                self.relationships[key] = DeviceRelationship(
                                    mac_a=key[0],
                                    mac_b=key[1],
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                )
                            self.relationships[key].discovery_hits += 1

            logger.debug(f"Captured mDNS for {duration}s, found {len(queries)} unique queries")

        except subprocess.TimeoutExpired:
            logger.debug("tshark capture timed out")
        except FileNotFoundError:
            logger.debug("tshark not available")
        except Exception as e:
            logger.warning(f"mDNS capture failed: {e}")

    def update_temporal_sync(self, presence_events: List[Dict]):
        """
        Update temporal sync scores from presence sensor events.

        Called by the presence sensor when devices join/leave together.

        Args:
            presence_events: List of {mac, event_type, timestamp, access_point}
        """
        if len(presence_events) < 2:
            return

        # Group events by time window (60 seconds)
        windows: Dict[int, List[Dict]] = defaultdict(list)
        for event in presence_events:
            try:
                ts = datetime.fromisoformat(event['timestamp'])
                window_key = int(ts.timestamp() // 60)  # 1-minute windows
                windows[window_key].append(event)
            except (KeyError, ValueError):
                continue

        # Find correlated events (same time window, same event type)
        for window_key, events in windows.items():
            # Group by event type
            by_type: Dict[str, List[str]] = defaultdict(list)
            for e in events:
                event_type = e.get('event_type', '')
                mac = e.get('mac', '').upper()
                if event_type in ('join', 'leave') and mac:
                    by_type[event_type].append(mac)

            # Devices that join/leave together are likely same user
            for event_type, macs in by_type.items():
                if len(macs) >= 2:
                    for i in range(len(macs)):
                        for j in range(i + 1, len(macs)):
                            key = self._normalize_mac_pair(macs[i], macs[j])
                            if key not in self.relationships:
                                self.relationships[key] = DeviceRelationship(
                                    mac_a=key[0],
                                    mac_b=key[1],
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                )
                            # Increase temporal sync score
                            current = self.relationships[key].temporal_sync_score
                            # Each correlated event adds 0.1 up to max 1.0
                            self.relationships[key].temporal_sync_score = min(1.0, current + 0.1)

        logger.debug(f"Updated temporal sync from {len(presence_events)} events")

    def _persist_relationships(self):
        """Persist relationships to database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Ensure schema has new columns
                try:
                    conn.execute('ALTER TABLE device_relationships ADD COLUMN discovery_hits INTEGER DEFAULT 0')
                except sqlite3.OperationalError:
                    pass  # Column already exists
                try:
                    conn.execute('ALTER TABLE device_relationships ADD COLUMN temporal_sync REAL DEFAULT 0.0')
                except sqlite3.OperationalError:
                    pass  # Column already exists

                for key, rel in self.relationships.items():
                    affinity = rel.calculate_affinity_score()
                    conn.execute('''
                        INSERT OR REPLACE INTO device_relationships
                        (mac_a, mac_b, connection_count, total_bytes,
                         bidirectional_count, high_affinity_count,
                         services_json, first_seen, last_seen, affinity_score,
                         discovery_hits, temporal_sync)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        rel.mac_a, rel.mac_b,
                        rel.connection_count, rel.total_bytes,
                        rel.bidirectional_count, rel.high_affinity_count,
                        json.dumps(rel.services_used),
                        rel.first_seen.isoformat() if rel.first_seen else None,
                        rel.last_seen.isoformat() if rel.last_seen else None,
                        affinity,
                        rel.discovery_hits,
                        rel.temporal_sync_score,
                    ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to persist relationships: {e}")

    def load_relationships(self):
        """Load relationships from database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute('''
                    SELECT * FROM device_relationships
                    WHERE affinity_score > 0
                    ORDER BY affinity_score DESC
                ''').fetchall()

                for row in rows:
                    key = (row['mac_a'], row['mac_b'])
                    # Handle new columns that may not exist in old DB
                    discovery_hits = row['discovery_hits'] if 'discovery_hits' in row.keys() else 0
                    temporal_sync = row['temporal_sync'] if 'temporal_sync' in row.keys() else 0.0

                    self.relationships[key] = DeviceRelationship(
                        mac_a=row['mac_a'],
                        mac_b=row['mac_b'],
                        connection_count=row['connection_count'],
                        total_bytes=row['total_bytes'],
                        bidirectional_count=row['bidirectional_count'],
                        high_affinity_count=row['high_affinity_count'],
                        services_used=json.loads(row['services_json'] or '{}'),
                        first_seen=datetime.fromisoformat(row['first_seen']) if row['first_seen'] else None,
                        last_seen=datetime.fromisoformat(row['last_seen']) if row['last_seen'] else None,
                        discovery_hits=discovery_hits,
                        temporal_sync_score=temporal_sync,
                    )

                logger.debug(f"Loaded {len(self.relationships)} relationships from DB")
        except Exception as e:
            logger.warning(f"Failed to load relationships: {e}")

    def get_d2d_affinity_score(self, mac_a: str, mac_b: str) -> float:
        """
        Get D2D affinity score between two devices.

        This is the primary interface for the BehavioralClusteringEngine
        to incorporate D2D communication into clustering.

        Args:
            mac_a: First device MAC
            mac_b: Second device MAC

        Returns:
            Affinity score (0.0 - 1.0)
        """
        key = self._normalize_mac_pair(mac_a, mac_b)

        if key in self.relationships:
            return self.relationships[key].calculate_affinity_score()

        return 0.0

    def get_device_peers(self, mac: str) -> List[Tuple[str, float]]:
        """
        Get all devices that communicate with the given device.

        Args:
            mac: Device MAC address

        Returns:
            List of (peer_mac, affinity_score) tuples, sorted by affinity
        """
        mac = mac.upper()
        peers = []

        for key, rel in self.relationships.items():
            if mac in key:
                peer = key[1] if key[0] == mac else key[0]
                affinity = rel.calculate_affinity_score()
                if affinity >= self.AFFINITY_THRESHOLD:
                    peers.append((peer, affinity))

        return sorted(peers, key=lambda x: x[1], reverse=True)

    def find_d2d_clusters(self) -> List[D2DCluster]:
        """
        Find clusters of devices based on D2D communication.

        Uses a simple graph clustering approach:
        1. Build adjacency graph from relationships above threshold
        2. Find connected components
        3. Return clusters with affinity metrics

        Returns:
            List of D2DCluster objects
        """
        # Build adjacency list
        graph: Dict[str, Set[str]] = defaultdict(set)

        for key, rel in self.relationships.items():
            affinity = rel.calculate_affinity_score()
            if affinity >= self.AFFINITY_THRESHOLD:
                graph[key[0]].add(key[1])
                graph[key[1]].add(key[0])

        # Find connected components (BFS)
        visited = set()
        clusters = []

        for node in graph:
            if node in visited:
                continue

            # BFS to find component
            component = set()
            queue = [node]

            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                component.add(current)

                for neighbor in graph[current]:
                    if neighbor not in visited:
                        queue.append(neighbor)

            if len(component) >= 2:
                # Build affinity matrix for cluster
                affinity_matrix = {}
                total_affinity = 0
                count = 0
                services = defaultdict(int)

                for mac_a in component:
                    for mac_b in component:
                        if mac_a >= mac_b:
                            continue
                        key = self._normalize_mac_pair(mac_a, mac_b)
                        if key in self.relationships:
                            rel = self.relationships[key]
                            aff = rel.calculate_affinity_score()
                            affinity_matrix[(mac_a, mac_b)] = aff
                            total_affinity += aff
                            count += 1
                            for svc, cnt in rel.services_used.items():
                                services[svc] += cnt

                avg_affinity = total_affinity / count if count > 0 else 0
                primary_services = sorted(
                    services.keys(),
                    key=lambda x: services[x],
                    reverse=True
                )[:5]

                clusters.append(D2DCluster(
                    devices=component,
                    affinity_matrix=affinity_matrix,
                    avg_affinity=avg_affinity,
                    primary_services=primary_services,
                ))

        logger.info(f"Found {len(clusters)} D2D clusters")
        return clusters

    def get_stats(self) -> Dict:
        """Get D2D graph statistics."""
        total_connections = sum(r.connection_count for r in self.relationships.values())
        high_affinity = sum(
            1 for r in self.relationships.values()
            if r.calculate_affinity_score() >= 0.5
        )

        return {
            'total_relationships': len(self.relationships),
            'total_connections': total_connections,
            'high_affinity_pairs': high_affinity,
            'unique_devices': len(set(
                mac for key in self.relationships.keys() for mac in key
            )),
        }


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

_analyzer: Optional[ConnectionGraphAnalyzer] = None
_analyzer_lock = __import__('threading').Lock()


def get_connection_analyzer() -> ConnectionGraphAnalyzer:
    """Get the global ConnectionGraphAnalyzer instance."""
    global _analyzer

    with _analyzer_lock:
        if _analyzer is None:
            _analyzer = ConnectionGraphAnalyzer()
            _analyzer.load_relationships()
        return _analyzer


def analyze_d2d_connections():
    """
    Convenience function to run D2D analysis.

    Call periodically (e.g., every 5 minutes) to update relationships.
    """
    analyzer = get_connection_analyzer()
    analyzer.update_relationships()
    return analyzer.get_stats()


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='D2D Connection Graph Analyzer')
    parser.add_argument('command', choices=['analyze', 'clusters', 'stats', 'peers'])
    parser.add_argument('--mac', help='MAC address for peers command')
    args = parser.parse_args()

    analyzer = get_connection_analyzer()

    if args.command == 'analyze':
        analyzer.update_relationships()
        print(f"Analysis complete: {analyzer.get_stats()}")

    elif args.command == 'clusters':
        clusters = analyzer.find_d2d_clusters()
        for i, cluster in enumerate(clusters):
            print(f"\nCluster {i+1}:")
            print(f"  Devices: {cluster.devices}")
            print(f"  Avg Affinity: {cluster.avg_affinity:.2f}")
            print(f"  Services: {cluster.primary_services}")

    elif args.command == 'stats':
        stats = analyzer.get_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")

    elif args.command == 'peers':
        if not args.mac:
            print("Error: --mac required for peers command")
        else:
            peers = analyzer.get_device_peers(args.mac)
            print(f"Peers for {args.mac}:")
            for peer, affinity in peers:
                print(f"  {peer}: {affinity:.2f}")
