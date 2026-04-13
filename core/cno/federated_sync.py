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
        """Execute one sync cycle: build → share → receive."""
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

        elapsed_ms = int((time.monotonic() - start) * 1000)
        self._last_sync = time.time()

        result = {
            'local_ips': ip_count,
            'shared': shared,
            'received': received,
            'elapsed_ms': elapsed_ms,
        }

        # Notify callback
        if self._on_update and (ip_count > 0 or received > 0):
            try:
                self._on_update(self._bloom_engine.get_stats())
            except Exception as e:
                logger.error("Global update callback failed: %s", e)

        if ip_count > 0 or received > 0:
            logger.info(
                "FEDERATED SYNC: local_ips=%d, shared=%s, received=%d, elapsed=%dms",
                ip_count, shared, received, elapsed_ms,
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
        """Receive peer Bloom filters from MSSP relay."""
        if not MSSP_API_URL:
            return 0

        try:
            import base64
            url = f"{MSSP_API_URL}/api/mesh/intel?type=bloom_filter"
            req = Request(url)
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            received = 0
            _UUID_RE = __import__('re').compile(
                r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                __import__('re').IGNORECASE)
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
                if self._bloom_engine.receive_peer_filter(peer_id, filter_data):
                    received += 1
                    self._stats['receive_successes'] += 1

            return received

        except Exception as e:
            logger.debug("MSSP receive failed: %s", e)
            return 0

    # ------------------------------------------------------------------
    # Lookup API
    # ------------------------------------------------------------------

    def is_mesh_known_threat(self, ip: str) -> Tuple[bool, str]:
        """Check if an IP is flagged by any node in the mesh.

        This enriches the Multi-RAG Consensus with federated intel.
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
