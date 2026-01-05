#!/usr/bin/env python3
"""
ClickHouse Graph Storage for Device Relationships

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module provides ClickHouse persistence for the device relationship graph,
enabling AI learning from historical relationship patterns.

Integration with AIOCHI:
- Writes to the same ClickHouse instance used by AIOCHI containers
- Tables prefixed with 'bubble_' to distinguish from core AIOCHI tables
- Can be queried via Grafana dashboards or n8n workflows

Usage:
    from products.fortress.lib.clickhouse_graph import ClickHouseGraphStore

    store = ClickHouseGraphStore()
    store.record_relationship(mac_a, mac_b, affinity_score, services)
    store.record_discovery_pair(querier_mac, responder_mac, service_type)
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ClickHouse connection settings (same as AIOCHI)
CLICKHOUSE_HOST = 'localhost'
CLICKHOUSE_PORT = 8123
CLICKHOUSE_USER = 'aiochi'
CLICKHOUSE_PASSWORD = ''
CLICKHOUSE_DATABASE = 'aiochi'

# Try to import clickhouse-connect
try:
    import clickhouse_connect
    HAS_CLICKHOUSE = True
except ImportError:
    HAS_CLICKHOUSE = False


# =============================================================================
# SCHEMA (for reference - actual tables created by clickhouse-init.sql)
# =============================================================================

BUBBLE_GRAPH_SCHEMA = '''
-- ============================================================================
-- BUBBLE GRAPH TABLES
-- Device relationship and affinity data for AI learning
-- ============================================================================

-- Device-to-Device Relationships
CREATE TABLE IF NOT EXISTS bubble_device_relationships (
    mac_a String,
    mac_b String,
    connection_count UInt32 DEFAULT 0,
    total_bytes UInt64 DEFAULT 0,
    bidirectional_count UInt32 DEFAULT 0,
    high_affinity_count UInt32 DEFAULT 0,
    services_json String,
    discovery_hits UInt32 DEFAULT 0,
    temporal_sync_score Float32 DEFAULT 0.0,
    affinity_score Float32 DEFAULT 0.0,
    first_seen DateTime DEFAULT now(),
    last_seen DateTime DEFAULT now(),

    INDEX idx_mac_a mac_a TYPE bloom_filter GRANULARITY 1,
    INDEX idx_mac_b mac_b TYPE bloom_filter GRANULARITY 1,
    INDEX idx_affinity affinity_score TYPE minmax GRANULARITY 1
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (mac_a, mac_b)
TTL last_seen + INTERVAL 180 DAY;

-- mDNS Discovery Pairs (Query/Response matching)
CREATE TABLE IF NOT EXISTS bubble_mdns_discoveries (
    timestamp DateTime DEFAULT now(),
    querier_mac String,
    responder_mac String,
    service_type String,

    INDEX idx_querier querier_mac TYPE bloom_filter GRANULARITY 1,
    INDEX idx_responder responder_mac TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, querier_mac, responder_mac)
TTL timestamp + INTERVAL 30 DAY;

-- Temporal Patterns (Device wake/sleep behavior)
CREATE TABLE IF NOT EXISTS bubble_temporal_patterns (
    mac String,
    active_hours Array(UInt8),
    wake_hours Array(UInt8),
    sleep_hours Array(UInt8),
    avg_session_duration Float32 DEFAULT 0.0,
    avg_idle_duration Float32 DEFAULT 0.0,
    last_updated DateTime DEFAULT now(),

    INDEX idx_mac mac TYPE bloom_filter GRANULARITY 1
) ENGINE = ReplacingMergeTree(last_updated)
ORDER BY (mac)
TTL last_updated + INTERVAL 90 DAY;

-- Bubble Assignments (Manual corrections for learning)
CREATE TABLE IF NOT EXISTS bubble_assignments (
    timestamp DateTime DEFAULT now(),
    mac String,
    bubble_id String,
    bubble_name String,
    assignment_type Enum8('auto' = 1, 'manual' = 2, 'learned' = 3),
    confidence Float32 DEFAULT 0.0,
    previous_bubble_id String DEFAULT '',
    corrected Bool DEFAULT false,
    correction_reason String DEFAULT '',

    INDEX idx_mac mac TYPE bloom_filter GRANULARITY 1,
    INDEX idx_bubble bubble_id TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, mac)
TTL timestamp + INTERVAL 365 DAY;

-- Affinity Score History (For trend analysis)
CREATE TABLE IF NOT EXISTS bubble_affinity_history (
    timestamp DateTime DEFAULT now(),
    mac_a String,
    mac_b String,
    affinity_score Float32,
    discovery_hits UInt32,
    temporal_sync_score Float32,
    connection_count UInt32,

    INDEX idx_pair (mac_a, mac_b) TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
ORDER BY (timestamp, mac_a, mac_b)
TTL timestamp + INTERVAL 90 DAY;

-- Materialized View: Daily relationship summary
CREATE MATERIALIZED VIEW IF NOT EXISTS bubble_relationships_daily_mv
ENGINE = SummingMergeTree()
ORDER BY (day, mac_a, mac_b)
AS SELECT
    toDate(last_seen) AS day,
    mac_a,
    mac_b,
    max(affinity_score) AS max_affinity,
    sum(connection_count) AS total_connections,
    max(discovery_hits) AS max_discovery_hits
FROM bubble_device_relationships
GROUP BY day, mac_a, mac_b;
'''


@dataclass
class GraphEvent:
    """Event to be written to ClickHouse."""
    table: str
    data: Dict[str, Any]
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class ClickHouseGraphStore:
    """
    ClickHouse storage for device relationship graphs.

    Provides high-performance time-series storage for:
    - Device relationships and affinity scores
    - mDNS discovery pairs
    - Temporal patterns
    - Bubble assignments and corrections
    """

    def __init__(self, host: str = None, port: int = None,
                 database: str = None, enabled: bool = True):
        self.host = host or CLICKHOUSE_HOST
        self.port = port or CLICKHOUSE_PORT
        self.database = database or CLICKHOUSE_DATABASE
        self.enabled = enabled and HAS_CLICKHOUSE
        self._client = None
        self._connected = False

        # Event buffer for batch writes
        self._event_buffer: List[GraphEvent] = []
        self._buffer_size = 100

        if self.enabled:
            self._connect()

    def _connect(self):
        """Connect to ClickHouse."""
        if not HAS_CLICKHOUSE:
            logger.warning("clickhouse-connect not installed - ClickHouse storage disabled")
            self._connected = False
            return

        try:
            self._client = clickhouse_connect.get_client(
                host=self.host,
                port=self.port,
                username=CLICKHOUSE_USER,
                password=CLICKHOUSE_PASSWORD,
                database=self.database,
            )
            self._connected = True
            logger.info(f"Connected to ClickHouse at {self.host}:{self.port}")
        except Exception as e:
            logger.warning(f"Could not connect to ClickHouse: {e}")
            self._connected = False

    def ensure_schema(self):
        """Ensure all graph tables exist in ClickHouse."""
        if not self._connected:
            return False

        try:
            # Create tables one by one
            statements = [s.strip() for s in BUBBLE_GRAPH_SCHEMA.split(';') if s.strip()]
            for stmt in statements:
                if stmt.startswith('--') or stmt.startswith('CREATE'):
                    try:
                        self._client.command(stmt)
                    except Exception as e:
                        if 'already exists' not in str(e).lower():
                            logger.debug(f"Schema statement failed: {e}")

            logger.info("ClickHouse graph schema ensured")
            return True
        except Exception as e:
            logger.error(f"Failed to ensure ClickHouse schema: {e}")
            return False

    def record_relationship(self, mac_a: str, mac_b: str,
                           connection_count: int = 0,
                           total_bytes: int = 0,
                           bidirectional_count: int = 0,
                           high_affinity_count: int = 0,
                           services: Dict[str, int] = None,
                           discovery_hits: int = 0,
                           temporal_sync_score: float = 0.0,
                           affinity_score: float = 0.0):
        """
        Record a device relationship to ClickHouse.

        This is the primary method for persisting relationship data.
        """
        if not self._connected:
            return

        # Normalize MAC ordering
        mac_a, mac_b = sorted([mac_a.upper(), mac_b.upper()])

        event = GraphEvent(
            table='bubble_device_relationships',
            data={
                'mac_a': mac_a,
                'mac_b': mac_b,
                'connection_count': connection_count,
                'total_bytes': total_bytes,
                'bidirectional_count': bidirectional_count,
                'high_affinity_count': high_affinity_count,
                'services_json': json.dumps(services or {}),
                'discovery_hits': discovery_hits,
                'temporal_sync_score': temporal_sync_score,
                'affinity_score': affinity_score,
            }
        )

        self._buffer_event(event)

    def record_discovery_pair(self, querier_mac: str, responder_mac: str,
                              service_type: str, timestamp: datetime = None):
        """Record an mDNS discovery pair."""
        if not self._connected:
            return

        event = GraphEvent(
            table='bubble_mdns_discoveries',
            data={
                'querier_mac': querier_mac.upper(),
                'responder_mac': responder_mac.upper(),
                'service_type': service_type,
            },
            timestamp=timestamp or datetime.now(),
        )

        self._buffer_event(event)

    def record_temporal_pattern(self, mac: str, active_hours: List[int],
                                wake_hours: List[int] = None,
                                sleep_hours: List[int] = None,
                                avg_session_duration: float = 0.0,
                                avg_idle_duration: float = 0.0):
        """Record a device's temporal pattern."""
        if not self._connected:
            return

        event = GraphEvent(
            table='bubble_temporal_patterns',
            data={
                'mac': mac.upper(),
                'active_hours': active_hours,
                'wake_hours': wake_hours or [],
                'sleep_hours': sleep_hours or [],
                'avg_session_duration': avg_session_duration,
                'avg_idle_duration': avg_idle_duration,
            }
        )

        self._buffer_event(event)

    def record_bubble_assignment(self, mac: str, bubble_id: str,
                                  bubble_name: str,
                                  assignment_type: str = 'auto',
                                  confidence: float = 0.0,
                                  previous_bubble_id: str = '',
                                  corrected: bool = False,
                                  correction_reason: str = ''):
        """
        Record a bubble assignment.

        Used for both automatic and manual assignments.
        Manual corrections are used for reinforcement learning.
        """
        if not self._connected:
            return

        # Map assignment type to enum value
        type_map = {'auto': 1, 'manual': 2, 'learned': 3}

        event = GraphEvent(
            table='bubble_assignments',
            data={
                'mac': mac.upper(),
                'bubble_id': bubble_id,
                'bubble_name': bubble_name,
                'assignment_type': assignment_type,
                'confidence': confidence,
                'previous_bubble_id': previous_bubble_id,
                'corrected': corrected,
                'correction_reason': correction_reason,
            }
        )

        self._buffer_event(event)

    def record_affinity_history(self, mac_a: str, mac_b: str,
                                affinity_score: float,
                                discovery_hits: int = 0,
                                temporal_sync_score: float = 0.0,
                                connection_count: int = 0):
        """Record affinity score snapshot for trend analysis."""
        if not self._connected:
            return

        mac_a, mac_b = sorted([mac_a.upper(), mac_b.upper()])

        event = GraphEvent(
            table='bubble_affinity_history',
            data={
                'mac_a': mac_a,
                'mac_b': mac_b,
                'affinity_score': affinity_score,
                'discovery_hits': discovery_hits,
                'temporal_sync_score': temporal_sync_score,
                'connection_count': connection_count,
            }
        )

        self._buffer_event(event)

    def _buffer_event(self, event: GraphEvent):
        """Add event to buffer and flush if needed."""
        self._event_buffer.append(event)

        if len(self._event_buffer) >= self._buffer_size:
            self.flush()

    def flush(self):
        """Flush buffered events to ClickHouse."""
        if not self._connected or not self._event_buffer:
            return

        # Group events by table
        by_table: Dict[str, List[Dict]] = {}
        for event in self._event_buffer:
            if event.table not in by_table:
                by_table[event.table] = []

            data = event.data.copy()
            data['timestamp'] = event.timestamp
            by_table[event.table].append(data)

        # Write each table batch
        for table, rows in by_table.items():
            try:
                if rows:
                    self._client.insert(table, rows, column_names=list(rows[0].keys()))
                    logger.debug(f"Flushed {len(rows)} rows to {table}")
            except Exception as e:
                logger.warning(f"Failed to flush to {table}: {e}")

        self._event_buffer = []

    def get_relationship(self, mac_a: str, mac_b: str) -> Optional[Dict]:
        """Get relationship data for a device pair."""
        if not self._connected:
            return None

        mac_a, mac_b = sorted([mac_a.upper(), mac_b.upper()])

        try:
            result = self._client.query(f'''
                SELECT * FROM bubble_device_relationships
                WHERE mac_a = '{mac_a}' AND mac_b = '{mac_b}'
                ORDER BY last_seen DESC
                LIMIT 1
            ''')

            if result.row_count > 0:
                return dict(zip(result.column_names, result.first_row))
            return None
        except Exception as e:
            logger.debug(f"Failed to get relationship: {e}")
            return None

    def get_high_affinity_pairs(self, min_score: float = 0.5,
                                limit: int = 100) -> List[Dict]:
        """Get device pairs with high affinity scores."""
        if not self._connected:
            return []

        try:
            result = self._client.query(f'''
                SELECT mac_a, mac_b, affinity_score, discovery_hits,
                       temporal_sync_score, connection_count, last_seen
                FROM bubble_device_relationships
                WHERE affinity_score >= {min_score}
                ORDER BY affinity_score DESC
                LIMIT {limit}
            ''')

            return [dict(zip(result.column_names, row)) for row in result.result_rows]
        except Exception as e:
            logger.debug(f"Failed to get high affinity pairs: {e}")
            return []

    def get_manual_corrections(self, since_hours: int = 24) -> List[Dict]:
        """
        Get manual bubble corrections for reinforcement learning.

        Returns assignments where users manually corrected the bubble.
        """
        if not self._connected:
            return []

        try:
            result = self._client.query(f'''
                SELECT * FROM bubble_assignments
                WHERE corrected = true
                  AND timestamp > now() - INTERVAL {since_hours} HOUR
                ORDER BY timestamp DESC
            ''')

            return [dict(zip(result.column_names, row)) for row in result.result_rows]
        except Exception as e:
            logger.debug(f"Failed to get corrections: {e}")
            return []

    def close(self):
        """Flush remaining events and close connection."""
        self.flush()
        if self._client:
            self._client.close()
            self._connected = False


# =============================================================================
# SINGLETON
# =============================================================================

_store: Optional[ClickHouseGraphStore] = None
_store_lock = __import__('threading').Lock()


def get_clickhouse_store() -> ClickHouseGraphStore:
    """Get the singleton ClickHouse graph store."""
    global _store

    with _store_lock:
        if _store is None:
            _store = ClickHouseGraphStore()
        return _store


# =============================================================================
# CLI
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='ClickHouse Graph Store')
    parser.add_argument('command', choices=['status', 'schema', 'pairs', 'corrections'])
    parser.add_argument('--min-score', type=float, default=0.5, help='Min affinity score')
    args = parser.parse_args()

    store = get_clickhouse_store()

    if args.command == 'status':
        print(f"Connected: {store._connected}")
        print(f"Buffer size: {len(store._event_buffer)}")

    elif args.command == 'schema':
        if store.ensure_schema():
            print("Schema created/verified")
        else:
            print("Failed to ensure schema")

    elif args.command == 'pairs':
        pairs = store.get_high_affinity_pairs(args.min_score)
        print(f"High affinity pairs (>= {args.min_score}):")
        for p in pairs:
            print(f"  {p['mac_a']} ↔ {p['mac_b']}: {p['affinity_score']:.2f}")

    elif args.command == 'corrections':
        corrections = store.get_manual_corrections()
        print(f"Manual corrections (last 24h): {len(corrections)}")
        for c in corrections:
            print(f"  {c['mac']}: {c['previous_bubble_id']} → {c['bubble_id']}")
