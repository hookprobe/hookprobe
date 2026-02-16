"""
NAPSE ClickHouse Shipper

Ships NAPSE events directly to ClickHouse (hookprobe_ids database),
eliminating the intermediate log file step.

Column names must match the live ClickHouse schema exactly (napse_alerts,
napse_conn, napse_dns tables in hookprobe_ids).

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import json
import logging
import os
import time
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Tuple

from .event_bus import (
    ConnectionRecord, DNSRecord, NapseAlert,
    EventType, NapseEventBus,
)

logger = logging.getLogger(__name__)

# ClickHouse connection settings from environment
CLICKHOUSE_HOST = os.getenv('CLICKHOUSE_HOST', 'localhost')
CLICKHOUSE_PORT = int(os.getenv('CLICKHOUSE_PORT', '8123'))
CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER', 'default')
CLICKHOUSE_DB = os.getenv('CLICKHOUSE_DATABASE', 'hookprobe_ids')

# Buffer settings
BATCH_SIZE = 100
FLUSH_INTERVAL_S = 5.0
MAX_BUFFER_SIZE = 10000


class ClickHouseShipper:
    """
    Ships NAPSE events directly to ClickHouse.

    Batches events for efficient insertion and handles connection
    failures with retry logic.
    """

    def __init__(
        self,
        host: str = CLICKHOUSE_HOST,
        port: int = CLICKHOUSE_PORT,
        user: str = CLICKHOUSE_USER,
        database: str = CLICKHOUSE_DB,
        batch_size: int = BATCH_SIZE,
        flush_interval: float = FLUSH_INTERVAL_S,
    ):
        self.host = host
        self.port = port
        self.user = user
        self.database = database
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        # Event buffers
        self._alert_buffer: Deque[Dict] = deque(maxlen=MAX_BUFFER_SIZE)
        self._conn_buffer: Deque[Dict] = deque(maxlen=MAX_BUFFER_SIZE)
        self._dns_buffer: Deque[Dict] = deque(maxlen=MAX_BUFFER_SIZE)

        self._last_flush = time.time()
        self._client = None
        self._connected = False

        self._stats = {
            'alerts_shipped': 0,
            'connections_shipped': 0,
            'dns_shipped': 0,
            'flush_count': 0,
            'errors': 0,
        }

    def _connect(self) -> bool:
        """Establish ClickHouse connection."""
        if self._connected:
            return True

        try:
            import httpx
            self._client = httpx.Client(
                base_url=f"http://{self.host}:{self.port}",
                timeout=10.0,
            )
            # Test connection
            r = self._client.get(f"/?query=SELECT%201&database={self.database}&user={self.user}")
            if r.status_code == 200:
                self._connected = True
                logger.info("Connected to ClickHouse at %s:%d", self.host, self.port)
                return True
        except ImportError:
            logger.warning("httpx not available, ClickHouse shipping disabled")
        except Exception as e:
            logger.warning("ClickHouse connection failed: %s", e)

        return False

    def register(self, event_bus: NapseEventBus) -> None:
        """Register with NAPSE event bus."""
        event_bus.subscribe(EventType.ALERT, self._buffer_alert)
        event_bus.subscribe(EventType.CONNECTION, self._buffer_connection)
        event_bus.subscribe(EventType.DNS, self._buffer_dns)
        logger.info("ClickHouseShipper registered with event bus")

    def _buffer_alert(self, _et: EventType, alert: NapseAlert) -> None:
        """Buffer an alert for batch insertion.

        Column names must match hookprobe_ids.napse_alerts exactly.
        """
        self._alert_buffer.append({
            'timestamp': alert.timestamp,
            'event_type': 'alert',
            'src_ip': alert.src_ip,
            'src_port': alert.src_port,
            'dest_ip': alert.dest_ip,
            'dest_port': alert.dest_port,
            'proto': alert.proto,
            'alert_action': alert.alert_action,
            'alert_gid': alert.alert_gid,
            'alert_signature_id': alert.alert_signature_id,
            'alert_signature': alert.alert_signature,
            'alert_category': alert.alert_category,
            'alert_severity': alert.alert_severity,
        })
        self._maybe_flush()

    def _buffer_connection(self, _et: EventType, record: ConnectionRecord) -> None:
        """Buffer a connection record for batch insertion.

        Column names must match hookprobe_ids.napse_conn exactly.
        """
        self._conn_buffer.append({
            'ts': datetime.fromtimestamp(record.ts).isoformat(),
            'uid': record.uid,
            'id_orig_h': record.id_orig_h,
            'id_orig_p': record.id_orig_p,
            'id_resp_h': record.id_resp_h,
            'id_resp_p': record.id_resp_p,
            'proto': record.proto,
            'service': record.service,
            'duration': record.duration,
            'orig_bytes': record.orig_bytes,
            'resp_bytes': record.resp_bytes,
            'conn_state': record.conn_state,
            'orig_pkts': record.orig_pkts,
            'resp_pkts': record.resp_pkts,
        })
        self._maybe_flush()

    def _buffer_dns(self, _et: EventType, record: DNSRecord) -> None:
        """Buffer a DNS record for batch insertion.

        Column names must match hookprobe_ids.napse_dns exactly.
        """
        self._dns_buffer.append({
            'ts': datetime.fromtimestamp(record.ts).isoformat(),
            'uid': record.uid,
            'id_orig_h': record.id_orig_h,
            'id_orig_p': record.id_orig_p,
            'id_resp_h': record.id_resp_h,
            'id_resp_p': record.id_resp_p,
            'proto': record.proto,
            'query': record.query,
            'qclass': record.qclass,
            'qclass_name': record.qclass_name,
            'qtype': record.qtype,
            'qtype_name': record.qtype_name,
            'rcode': record.rcode,
            'rcode_name': record.rcode_name,
            'AA': int(record.AA),
            'answers': record.answers,
            'TTLs': record.TTLs,
            'rejected': int(record.rejected),
        })
        self._maybe_flush()

    def _maybe_flush(self) -> None:
        """Flush buffers if batch size or time threshold reached."""
        now = time.time()
        total_buffered = (
            len(self._alert_buffer) +
            len(self._conn_buffer) +
            len(self._dns_buffer)
        )

        if total_buffered >= self.batch_size or (now - self._last_flush) >= self.flush_interval:
            self.flush()

    def flush(self) -> None:
        """Flush all buffers to ClickHouse."""
        if not self._connect():
            return

        self._flush_buffer('napse_alerts', self._alert_buffer, 'alerts_shipped')
        self._flush_buffer('napse_conn', self._conn_buffer, 'connections_shipped')
        self._flush_buffer('napse_dns', self._dns_buffer, 'dns_shipped')

        self._last_flush = time.time()
        self._stats['flush_count'] += 1

    def _flush_buffer(self, table: str, buffer: Deque, stat_key: str) -> None:
        """Flush a single buffer to a ClickHouse table."""
        if not buffer:
            return

        batch = []
        while buffer and len(batch) < self.batch_size:
            batch.append(buffer.popleft())

        if not batch:
            return

        try:
            data = '\n'.join(json.dumps(row, default=str) for row in batch)
            r = self._client.post(
                f"/?query=INSERT%20INTO%20{self.database}.{table}%20FORMAT%20JSONEachRow"
                f"&user={self.user}",
                content=data,
                headers={'Content-Type': 'application/json'},
            )
            if r.status_code == 200:
                self._stats[stat_key] += len(batch)
            else:
                logger.warning("ClickHouse insert failed (%d): %s", r.status_code, r.text[:200])
                self._stats['errors'] += 1
        except Exception as e:
            logger.error("ClickHouse flush error: %s", e)
            self._stats['errors'] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get shipper statistics."""
        return {
            **self._stats,
            'alert_buffer_size': len(self._alert_buffer),
            'conn_buffer_size': len(self._conn_buffer),
            'dns_buffer_size': len(self._dns_buffer),
            'connected': self._connected,
        }
