"""
Federated Sync — Cross-Node Intelligence Coordination

Coordinates threat intelligence sharing across the HTP mesh network.
Each node contributes its local findings via Bloom filters and receives
aggregated intelligence from peers.

Sync protocol:
    1. Build local Bloom filter from HYDRA verdicts (every 5 min)
    2. Apply differential privacy noise (ε=1.0)
    3. Share noised filter via mesh heartbeat API piggyback
    4. Receive peer filters and merge into global view
    5. Enhance local scoring with global threat awareness

Integration:
    - Reads from: ClickHouse hydra_verdicts (local detections)
    - Writes to: Global Bloom filter (in-memory)
    - Shares via: MSSP heartbeat API piggyback or direct mesh peering
    - Enhances: Multi-RAG Consensus (Silo 1 global score boosted by mesh intel)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import json
import logging
import os
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from .bloom_sharing import BloomSharingEngine

logger = logging.getLogger(__name__)

# Config
SYNC_INTERVAL_S = float(os.environ.get('CNO_SYNC_INTERVAL', '300'))  # 5 min
MSSP_API_URL = os.environ.get('MSSP_API_URL', '')  # Optional: MSSP relay
NODE_ID = os.environ.get('HOOKPROBE_NODE_ID', '')

CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

# UUID format validation (compiled once at import time)
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE)


class FederatedSync:
    """Orchestrates Bloom filter sharing across the mesh network.

    Runs in a background thread, periodically building and sharing
    local threat intelligence while receiving peer updates.
    """

    def __init__(self, on_global_update: Optional[Callable] = None):
        """Initialize federated sync.

        Args:
            on_global_update: Callback(stats_dict) when global view changes.
        """
        self._bloom_engine = BloomSharingEngine()
        self._on_update = on_global_update

        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Sync state
        self._local_stats: Dict[str, Any] = {}
        self._last_sync = 0.0

        self._stats = {
            'sync_cycles': 0,
            'share_successes': 0,
            'share_failures': 0,
            'receive_successes': 0,
            'mesh_lookups': 0,
        }

        logger.info("FederatedSync initialized (interval=%.0fs, node=%s)",
                     SYNC_INTERVAL_S, NODE_ID or 'unknown')

    @property
    def bloom_engine(self) -> BloomSharingEngine:
        return self._bloom_engine

    # ------------------------------------------------------------------
    # Sync Cycle
    # ------------------------------------------------------------------

    def sync_cycle(self) -> Dict[str, Any]:
        """Execute one sync cycle: build → share → receive → validate → decay.

        Phase 18: added post-hoc accuracy validation (step 4), silence
        decay (step 5), and ClickHouse persistence (step 6).
        """
        self._stats['sync_cycles'] += 1
        start = time.monotonic()

        # Step 1: Build local Bloom filter
        ip_count = self._bloom_engine.build_local_filter()

        # Step 2: Share with peers (if configured)
        shared = False
        if MSSP_API_URL:
            shared = self._share_via_mssp()
            if shared:
                self._stats['share_successes'] += 1
            else:
                self._stats['share_failures'] += 1

        # Step 3: Receive peer filters (if available)
        received = self._receive_from_mssp() if MSSP_API_URL else 0

        # Phase 18 Step 4: validate peer accuracy against local NAPSE flows
        accuracy_checked = self._validate_peer_accuracy()

        # Phase 18 Step 5: decay trust for silent peers
        decayed = self._bloom_engine.reputation.decay_silent_peers()

        # Phase 18 Step 6: persist reputation metrics to ClickHouse
        self._persist_reputation_metrics()

        elapsed_ms = int((time.monotonic() - start) * 1000)
        self._last_sync = time.time()

        result = {
            'local_ips': ip_count,
            'shared': shared,
            'received': received,
            'accuracy_checked': accuracy_checked,
            'trust_decayed': decayed,
            'elapsed_ms': elapsed_ms,
        }

        # Notify callback
        if self._on_update and (ip_count > 0 or received > 0):
            try:
                self._on_update(self._bloom_engine.get_stats())
            except Exception as e:
                logger.error("Global update callback failed: %s", e)

        if ip_count > 0 or received > 0 or accuracy_checked > 0:
            logger.info(
                "FEDERATED SYNC: local_ips=%d, shared=%s, received=%d, "
                "accuracy=%d, decayed=%d, elapsed=%dms",
                ip_count, shared, received, accuracy_checked, decayed,
                elapsed_ms,
            )

        return result

    def _share_via_mssp(self) -> bool:
        """Share local Bloom filter via MSSP heartbeat API.

        Piggybacks the filter data on the regular heartbeat to avoid
        extra network traffic. The MSSP relays to other nodes.
        """
        if not MSSP_API_URL or not NODE_ID:
            return False

        try:
            import base64
            filter_bytes = self._bloom_engine.get_shareable_filter()
            encoded = base64.b64encode(filter_bytes).decode('ascii')

            payload = json.dumps({
                'node_id': NODE_ID,
                'type': 'bloom_filter',
                'data': encoded,
                'timestamp': time.time(),
                'stats': {
                    'count': self._bloom_engine._local_filter.count,
                    'density': round(self._bloom_engine._local_filter.bit_density(), 4),
                },
            }).encode('utf-8')

            url = f"{MSSP_API_URL}/api/mesh/intel"
            req = Request(url, data=payload, method='POST')
            req.add_header('Content-Type', 'application/json')
            with urlopen(req, timeout=10) as resp:
                return resp.status == 200

        except Exception as e:
            logger.debug("MSSP share failed: %s", e)
            return False

    def _receive_from_mssp(self) -> int:
        """Receive peer Bloom filters from MSSP relay.

        Phase 18: passes declared_ip_count for consistency validation.
        """
        if not MSSP_API_URL:
            return 0

        try:
            import base64
            url = f"{MSSP_API_URL}/api/mesh/intel?type=bloom_filter"
            req = Request(url)
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            received = 0
            for entry in data.get('filters', []):
                peer_id = entry.get('node_id', '')
                # Security audit H6: validate node_id format
                if not peer_id or not _UUID_RE.match(peer_id):
                    logger.warning("Rejecting filter with invalid node_id: %r",
                                   str(peer_id)[:64])
                    continue
                if peer_id == NODE_ID:
                    continue  # Skip our own filter

                filter_data = base64.b64decode(entry.get('data', ''))
                # Phase 18: pass declared count for consistency check
                declared_count = entry.get('stats', {}).get('count', 0)
                if self._bloom_engine.receive_peer_filter(
                        peer_id, filter_data,
                        declared_ip_count=declared_count):
                    received += 1
                    self._stats['receive_successes'] += 1

            return received

        except Exception as e:
            logger.debug("MSSP receive failed: %s", e)
            return 0

    # ------------------------------------------------------------------
    # Phase 18: Accuracy Validation & Reputation Persistence
    # ------------------------------------------------------------------

    def _validate_peer_accuracy(self) -> int:
        """Post-hoc check: did peer-flagged IPs appear in our NAPSE flows?

        Phase 18: For each peer filter, sample up to 50 IPs from our recent
        local verdicts and check if the peer also flagged them. This measures
        overlap (accuracy) — high overlap means the peer sees similar threats.
        """
        reputation = self._bloom_engine.reputation
        peer_filters = self._bloom_engine._peer_filters
        if not peer_filters:
            return 0

        # Get our recent local IPs from ClickHouse
        query = (
            f"SELECT DISTINCT src_ip "
            f"FROM {CH_DB}.hydra_verdicts "
            f"WHERE timestamp > now() - INTERVAL 1 HOUR "
            f"LIMIT 50"
        )
        result = _ch_query(query)
        if not result:
            return 0

        local_ips = [ip.strip() for ip in result.strip().split('\n')
                     if ip.strip()]
        checked = 0
        for ip in local_ips:
            for peer_id, peer_filter in peer_filters.items():
                seen = peer_filter.contains(ip)
                reputation.record_accuracy(peer_id, ip, seen)
                checked += 1

        if checked > 0:
            logger.debug("REPUTATION: validated %d peer-IP pairs", checked)
        return checked

    def _persist_reputation_metrics(self) -> None:
        """Persist peer reputation metrics to ClickHouse.

        Phase 18: batch insert current reputation state for trend analysis.
        """
        metrics = self._bloom_engine.reputation.get_peer_metrics_for_ch()
        if not metrics:
            return

        try:
            rows = []
            for m in metrics:
                rows.append(
                    f"(now64(3), '{_ch_escape(m['peer_id'])}', "
                    f"{m['trust_score']}, {m['filters_received']}, "
                    f"{m['accuracy_rate']}, {m['consistency_failures']}, "
                    f"{m['silence_seconds']})"
                )
            if not rows:
                return
            values = ', '.join(rows)
            query = (
                f"INSERT INTO {CH_DB}.cno_peer_reputation "
                f"(timestamp, peer_id, trust_score, filters_received, "
                f"accuracy_rate, consistency_failures, silence_seconds) "
                f"VALUES {values}"
            )
            _ch_post(query)
        except Exception as e:
            logger.debug("Reputation persist failed: %s", e)

    # ------------------------------------------------------------------
    # Lookup API
    # ------------------------------------------------------------------

    def is_mesh_known_threat(self, ip: str) -> Tuple[bool, str]:
        """Check if an IP is flagged by any node in the mesh.

        Phase 18: mesh threats now require BFT consensus from 2+ trusted peers.
        """
        self._stats['mesh_lookups'] += 1
        return self._bloom_engine.is_known_threat(ip)

    # ------------------------------------------------------------------
    # Background Loop
    # ------------------------------------------------------------------

    def _sync_loop(self) -> None:
        """Background sync loop."""
        logger.info("Federated sync loop started (interval=%.0fs)", SYNC_INTERVAL_S)
        while self._running:
            try:
                self.sync_cycle()
            except Exception as e:
                logger.error("Sync cycle error: %s", e)
            time.sleep(SYNC_INTERVAL_S)

    def start(self) -> None:
        """Start the background sync loop."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sync_loop, daemon=True,
                                        name="cno-federated")
        self._thread.start()
        logger.info("FederatedSync started")

    def stop(self) -> None:
        """Stop the background sync loop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("FederatedSync stopped")

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            'last_sync': self._last_sync,
            'bloom': self._bloom_engine.get_stats(),
        }


# ------------------------------------------------------------------
# ClickHouse helpers (shared with bloom_sharing.py)
# ------------------------------------------------------------------

def _ch_query(query: str) -> Optional[str]:
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.read().decode('utf-8')
    except Exception:
        return None


def _ch_post(query: str) -> bool:
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data, method='POST')
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ch_escape(s: str) -> str:
    """Escape string for ClickHouse SQL (prevents injection)."""
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "")
