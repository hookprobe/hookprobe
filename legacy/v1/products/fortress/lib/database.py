#!/usr/bin/env python3
"""
Fortress Database Module

PostgreSQL database connection and query utilities for the Fortress tier.
Provides connection pooling and common database operations.
"""

import logging
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, List, Dict, Any, Generator
from dataclasses import dataclass

try:
    import psycopg2
    from psycopg2.pool import ThreadedConnectionPool
    from psycopg2.extras import RealDictCursor, execute_values
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

from .config import get_config, FortressConfig

logger = logging.getLogger(__name__)


class Database:
    """PostgreSQL database wrapper with connection pooling."""

    def __init__(self, config: Optional[FortressConfig] = None):
        self.config = config or get_config()
        self._pool: Optional['ThreadedConnectionPool'] = None
        self._initialized = False

    def initialize(self) -> bool:
        """Initialize connection pool."""
        if not PSYCOPG2_AVAILABLE:
            logger.error("psycopg2 not available - database features disabled")
            return False

        if self._initialized:
            return True

        try:
            self._pool = ThreadedConnectionPool(
                minconn=self.config.database.min_connections,
                maxconn=self.config.database.max_connections,
                host=self.config.database.host,
                port=self.config.database.port,
                database=self.config.database.database,
                user=self.config.database.user,
                password=self.config.database.password,
            )
            self._initialized = True
            logger.info("Database connection pool initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            return False

    def close(self):
        """Close all connections."""
        if self._pool:
            self._pool.closeall()
            self._pool = None
            self._initialized = False

    @contextmanager
    def get_connection(self) -> Generator:
        """Get a database connection from the pool."""
        if not self._initialized:
            if not self.initialize():
                raise RuntimeError("Database not available - connection pool not initialized")

        if self._pool is None:
            raise RuntimeError("Database connection pool is None")

        conn = self._pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self._pool.putconn(conn)

    @contextmanager
    def get_cursor(self, dict_cursor: bool = True) -> Generator:
        """Get a database cursor."""
        with self.get_connection() as conn:
            cursor_factory = RealDictCursor if dict_cursor else None
            cursor = conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cursor
            finally:
                cursor.close()

    def execute(self, query: str, params: tuple = None) -> int:
        """Execute a query and return affected row count."""
        with self.get_cursor(dict_cursor=False) as cursor:
            cursor.execute(query, params)
            return cursor.rowcount

    def fetch_one(self, query: str, params: tuple = None) -> Optional[Dict]:
        """Fetch a single row."""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchone()

    def fetch_all(self, query: str, params: tuple = None) -> List[Dict]:
        """Fetch all rows."""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()

    # ========================================
    # Device Operations
    # ========================================

    def get_device(self, mac_address: str) -> Optional[Dict]:
        """Get device by MAC address."""
        return self.fetch_one(
            "SELECT * FROM devices WHERE mac_address = %s",
            (mac_address.upper(),)
        )

    def get_devices(self, vlan_id: int = None, active_only: bool = False) -> List[Dict]:
        """Get all devices, optionally filtered by VLAN."""
        query = "SELECT * FROM devices WHERE 1=1"
        params = []

        if vlan_id is not None:
            query += " AND vlan_id = %s"
            params.append(vlan_id)

        if active_only:
            query += " AND last_seen > NOW() - INTERVAL '5 minutes'"

        query += " ORDER BY last_seen DESC"
        return self.fetch_all(query, tuple(params) if params else None)

    def upsert_device(self, mac_address: str, ip_address: str = None,
                      hostname: str = None, vlan_id: int = 40,
                      device_type: str = None, manufacturer: str = None) -> Dict:
        """Insert or update a device."""
        query = """
            INSERT INTO devices (mac_address, ip_address, hostname, vlan_id, device_type, manufacturer, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (mac_address) DO UPDATE SET
                ip_address = COALESCE(EXCLUDED.ip_address, devices.ip_address),
                hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
                device_type = COALESCE(EXCLUDED.device_type, devices.device_type),
                manufacturer = COALESCE(EXCLUDED.manufacturer, devices.manufacturer),
                last_seen = NOW()
            RETURNING *
        """
        with self.get_cursor() as cursor:
            cursor.execute(query, (mac_address.upper(), ip_address, hostname, vlan_id, device_type, manufacturer))
            return cursor.fetchone()

    def update_device_vlan(self, mac_address: str, vlan_id: int) -> bool:
        """Update device VLAN assignment."""
        rows = self.execute(
            "UPDATE devices SET vlan_id = %s, updated_at = NOW() WHERE mac_address = %s",
            (vlan_id, mac_address.upper())
        )
        return rows > 0

    def block_device(self, mac_address: str, blocked: bool = True) -> bool:
        """Block or unblock a device."""
        rows = self.execute(
            "UPDATE devices SET is_blocked = %s WHERE mac_address = %s",
            (blocked, mac_address.upper())
        )
        return rows > 0

    def get_device_count_by_vlan(self) -> Dict[int, int]:
        """Get device count per VLAN."""
        rows = self.fetch_all("""
            SELECT vlan_id, COUNT(*) as count
            FROM devices
            WHERE last_seen > NOW() - INTERVAL '24 hours'
            GROUP BY vlan_id
        """)
        return {row['vlan_id']: row['count'] for row in rows}

    # ========================================
    # VLAN Operations
    # ========================================

    def get_vlans(self) -> List[Dict]:
        """Get all VLANs."""
        return self.fetch_all("SELECT * FROM vlans ORDER BY vlan_id")

    def get_vlan(self, vlan_id: int) -> Optional[Dict]:
        """Get VLAN by ID."""
        return self.fetch_one("SELECT * FROM vlans WHERE vlan_id = %s", (vlan_id,))

    def update_vlan(self, vlan_id: int, **kwargs) -> bool:
        """Update VLAN settings."""
        allowed_fields = {
            'name', 'description', 'dns_policy', 'bandwidth_limit_mbps',
            'is_isolated', 'dhcp_enabled', 'is_logical', 'trust_floor'
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not updates:
            return False

        set_clause = ", ".join(f"{k} = %s" for k in updates)
        query = f"UPDATE vlans SET {set_clause}, updated_at = NOW() WHERE vlan_id = %s"
        params = list(updates.values()) + [vlan_id]

        return self.execute(query, tuple(params)) > 0

    # ========================================
    # Threat Operations
    # ========================================

    def record_threat(self, threat_type: str, severity: str, source_ip: str = None,
                      source_mac: str = None, description: str = None,
                      mitre_attack_id: str = None, evidence: Dict = None) -> Dict:
        """Record a detected threat."""
        query = """
            INSERT INTO threats (threat_type, severity, source_ip, source_mac, description, mitre_attack_id, evidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """
        import json
        with self.get_cursor() as cursor:
            cursor.execute(query, (
                threat_type, severity, source_ip, source_mac,
                description, mitre_attack_id, json.dumps(evidence or {})
            ))
            return cursor.fetchone()

    def get_recent_threats(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get recent threats."""
        return self.fetch_all("""
            SELECT * FROM threats
            WHERE detected_at > NOW() - INTERVAL '%s hours'
            ORDER BY detected_at DESC
            LIMIT %s
        """, (hours, limit))

    def get_threat_summary(self, hours: int = 24) -> Dict:
        """Get threat summary for dashboard."""
        row = self.fetch_one("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE severity = 'high') as high,
                COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                COUNT(*) FILTER (WHERE severity = 'low') as low,
                COUNT(*) FILTER (WHERE is_blocked) as blocked
            FROM threats
            WHERE detected_at > NOW() - INTERVAL '%s hours'
        """, (hours,))
        return dict(row) if row else {}

    # ========================================
    # QSecBit Operations
    # ========================================

    def record_qsecbit_score(self, score: float, rag_status: str,
                             components: Dict, layer_stats: Dict = None):
        """Record QSecBit score."""
        import json
        self.execute("""
            INSERT INTO qsecbit_history (score, rag_status, components, layer_stats)
            VALUES (%s, %s, %s, %s)
        """, (score, rag_status, json.dumps(components), json.dumps(layer_stats or {})))

    def get_qsecbit_history(self, hours: int = 24) -> List[Dict]:
        """Get QSecBit score history."""
        return self.fetch_all("""
            SELECT * FROM qsecbit_history
            WHERE recorded_at > NOW() - INTERVAL '%s hours'
            ORDER BY recorded_at DESC
        """, (hours,))

    def get_latest_qsecbit(self) -> Optional[Dict]:
        """Get latest QSecBit score."""
        return self.fetch_one("""
            SELECT * FROM qsecbit_history
            ORDER BY recorded_at DESC
            LIMIT 1
        """)

    # ========================================
    # DNS Operations
    # ========================================

    def record_dns_query(self, client_ip: str, domain: str, query_type: str = 'A',
                         is_blocked: bool = False, block_reason: str = None,
                         category: str = None, client_mac: str = None):
        """Record a DNS query (batch insert recommended for high volume)."""
        self.execute("""
            INSERT INTO dns_queries (client_ip, client_mac, domain, query_type, is_blocked, block_reason, category)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (client_ip, client_mac, domain, query_type, is_blocked, block_reason, category))

    def get_dns_stats(self, hours: int = 24) -> Dict:
        """Get DNS query statistics."""
        row = self.fetch_one("""
            SELECT
                COUNT(*) as total_queries,
                COUNT(*) FILTER (WHERE is_blocked) as blocked_queries,
                COUNT(DISTINCT client_ip) as unique_clients,
                COUNT(DISTINCT domain) as unique_domains
            FROM dns_queries
            WHERE queried_at > NOW() - INTERVAL '%s hours'
        """, (hours,))
        return dict(row) if row else {}

    def get_top_blocked_domains(self, limit: int = 10) -> List[Dict]:
        """Get top blocked domains."""
        return self.fetch_all("""
            SELECT domain, COUNT(*) as count
            FROM dns_queries
            WHERE is_blocked = TRUE AND queried_at > NOW() - INTERVAL '24 hours'
            GROUP BY domain
            ORDER BY count DESC
            LIMIT %s
        """, (limit,))

    # ========================================
    # Audit Operations
    # ========================================

    def audit_log(self, user_id: str, action: str, resource_type: str = None,
                  resource_id: str = None, details: Dict = None, ip_address: str = None):
        """Record an audit log entry."""
        import json
        self.execute("""
            INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, action, resource_type, resource_id, json.dumps(details or {}), ip_address))


# Global database instance
_db: Optional[Database] = None


def get_db() -> Database:
    """Get the global database instance."""
    global _db
    if _db is None:
        _db = Database()
        _db.initialize()
    return _db


def close_db():
    """Close the global database connection."""
    global _db
    if _db:
        _db.close()
        _db = None
