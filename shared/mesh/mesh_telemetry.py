"""Mesh / HTP gateway threat telemetry.

The HTP VPN gateway authenticates clients (Ed25519 challenge + HMAC) but
historically emitted nothing the IDS/CNO could see — auth failures, rate-limit
trips, and rekey failures were logged to stderr only, and there was no replay
detection. That made the mesh an end-to-end detection blind spot.

This module adds:
  * Async, fail-open export of mesh auth events to ClickHouse
    (<db>.mesh_auth_events) so SENTINEL/CNO can correlate mesh activity.
  * Lightweight nonce-replay tracking (observe-and-signal): a HELLO nonce
    reused within a window raises a 'replay_suspected' event. It does NOT
    drop the packet (legitimate UDP retransmits reuse a nonce) — enforcement
    is left to downstream consumers.

Everything is gated on MESH_CLICKHOUSE_URL. When unset, the telemetry object
is a no-op: zero behaviour change for deployments that don't opt in.
"""

import json
import logging
import os
import queue
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("htp.telemetry")

CLICKHOUSE_URL = os.environ.get("MESH_CLICKHOUSE_URL", "").rstrip("/")
CLICKHOUSE_DB = os.environ.get("MESH_CLICKHOUSE_DB", "hookprobe_ids")
CLICKHOUSE_USER = os.environ.get("MESH_CLICKHOUSE_USER", "ids")
CLICKHOUSE_PASSWORD = os.environ.get("MESH_CLICKHOUSE_PASSWORD", "")
FLUSH_SECS = float(os.environ.get("MESH_CLICKHOUSE_FLUSH_SECS", "5"))
BATCH = int(os.environ.get("MESH_CLICKHOUSE_BATCH", "25"))

# Replay window: a HELLO nonce seen again within this many seconds is flagged.
REPLAY_WINDOW = int(os.environ.get("MESH_REPLAY_WINDOW", "120"))
_REPLAY_MAX_TRACKED = 20000

_CH_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS {db}.mesh_auth_events (
    timestamp DateTime64(3) DEFAULT now64(3),
    event_type LowCardinality(String),
    src_ip String,
    node_id String,
    detail String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, event_type)
TTL toDateTime(timestamp) + INTERVAL 30 DAY
""".strip()


class MeshTelemetry:
    """Async exporter + replay tracker. No-op when MESH_CLICKHOUSE_URL is unset."""

    def __init__(self):
        self.enabled = bool(CLICKHOUSE_URL and CLICKHOUSE_PASSWORD)
        self._queue: "queue.Queue[str | None]" = queue.Queue(maxsize=4096)
        self._thread = None
        self.sent = 0
        self.failed = 0
        self.dropped = 0
        # nonce(hex) -> first_seen ts, for replay detection
        self._seen_nonces: dict[str, float] = {}
        self._nonce_lock = threading.Lock()

        if self.enabled:
            self._thread = threading.Thread(
                target=self._writer_loop, daemon=True, name="mesh-telemetry")
            self._thread.start()
            logger.info("mesh telemetry -> %s (%s.mesh_auth_events)",
                        CLICKHOUSE_URL, CLICKHOUSE_DB)
        else:
            logger.info("mesh telemetry: disabled (set MESH_CLICKHOUSE_URL to enable)")

    # ---- ClickHouse plumbing -------------------------------------------------

    @staticmethod
    def _ch_post(query: str, body: bytes = b""):
        url = f"{CLICKHOUSE_URL}/?{urlencode({'query': query})}"
        req = Request(url, data=body, method="POST")
        req.add_header("X-ClickHouse-User", CLICKHOUSE_USER)
        req.add_header("X-ClickHouse-Key", CLICKHOUSE_PASSWORD)
        with urlopen(req, timeout=5) as r:
            r.read()

    def _writer_loop(self):
        try:
            self._ch_post(_CH_TABLE_DDL.format(db=CLICKHOUSE_DB))
        except Exception as e:
            logger.warning("mesh telemetry DDL deferred (fail-open): %s", e)

        insert_q = (f"INSERT INTO {CLICKHOUSE_DB}.mesh_auth_events "
                    "(timestamp, event_type, src_ip, node_id, detail) FORMAT JSONEachRow")
        batch: list[str] = []

        def _flush():
            if not batch:
                return
            body = ("\n".join(batch)).encode("utf-8")
            try:
                self._ch_post(insert_q, body)
                self.sent += len(batch)
            except Exception as e:
                self.failed += len(batch)
                logger.debug("mesh telemetry insert failed (fail-open): %s", e)
            batch.clear()

        while True:
            try:
                rec = self._queue.get(timeout=FLUSH_SECS)
            except queue.Empty:
                _flush()
                continue
            if rec is None:
                _flush()
                break
            batch.append(rec)
            if len(batch) >= BATCH:
                _flush()

    # ---- public API ----------------------------------------------------------

    def record(self, event_type: str, src_ip: str, node_id: str = "", detail: str = ""):
        """Enqueue an auth event for async export. Fail-open."""
        if not self.enabled:
            return
        rec = json.dumps({
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "event_type": str(event_type)[:32],
            "src_ip": str(src_ip)[:45],
            "node_id": str(node_id)[:64],
            "detail": str(detail)[:200],
        })
        try:
            self._queue.put_nowait(rec)
        except queue.Full:
            self.dropped += 1

    def check_replay(self, nonce: bytes) -> bool:
        """Return True if this HELLO nonce was seen within REPLAY_WINDOW.

        Observe-only: callers should emit a 'replay_suspected' event but must
        not drop the packet (legitimate UDP retransmits reuse the nonce).
        """
        key = nonce.hex()
        now = time.time()
        with self._nonce_lock:
            first = self._seen_nonces.get(key)
            is_replay = first is not None and (now - first) < REPLAY_WINDOW
            if not is_replay:
                self._seen_nonces[key] = now
            # Bound memory: prune oldest when over capacity.
            if len(self._seen_nonces) > _REPLAY_MAX_TRACKED:
                cutoff = now - REPLAY_WINDOW
                for k in [k for k, t in self._seen_nonces.items() if t < cutoff]:
                    self._seen_nonces.pop(k, None)
        return is_replay

    def stop(self):
        if self.enabled and self._thread:
            try:
                self._queue.put_nowait(None)
            except Exception:
                pass


# Module-level singleton — instantiated lazily by the gateway.
_telemetry: "MeshTelemetry | None" = None


def get_telemetry() -> MeshTelemetry:
    global _telemetry
    if _telemetry is None:
        _telemetry = MeshTelemetry()
    return _telemetry
