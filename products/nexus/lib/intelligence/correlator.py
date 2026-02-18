"""
Nexus Threat Correlator

Cross-device threat correlation engine. Checks if the same IOC
has been seen across multiple nodes in the mesh.

Uses in-memory threat database with TTL-based expiration.
"""

import hashlib
import logging
import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class CorrelationResult:
    """Result of cross-device correlation."""

    __slots__ = [
        "ioc_value", "ioc_type", "hit_count", "source_nodes",
        "first_seen", "last_seen", "severity_max", "is_campaign",
    ]

    def __init__(self, ioc_value: str, ioc_type: str):
        self.ioc_value = ioc_value
        self.ioc_type = ioc_type
        self.hit_count = 0
        self.source_nodes: Set[str] = set()
        self.first_seen = 0.0
        self.last_seen = 0.0
        self.severity_max = "LOW"
        self.is_campaign = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "hit_count": self.hit_count,
            "source_nodes": list(self.source_nodes),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "severity_max": self.severity_max,
            "is_campaign": self.is_campaign,
        }


class ThreatCorrelator:
    """Cross-device threat correlation engine.

    Maintains an in-memory database of IOCs and which nodes
    have reported them. Detects coordinated campaigns when
    the same IOC appears across 3+ nodes.
    """

    CAMPAIGN_THRESHOLD = 3  # 3+ nodes = likely campaign
    IOC_TTL = 86400  # 24 hours
    MAX_IOCS = 100000

    SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def __init__(self):
        self._iocs: Dict[str, CorrelationResult] = {}
        self._node_iocs: Dict[str, Set[str]] = defaultdict(set)  # node_id -> ioc set
        self._lock = threading.Lock()

    def ingest(
        self,
        ioc_value: str,
        ioc_type: str,
        source_node: str,
        severity: str = "LOW",
    ) -> CorrelationResult:
        """Ingest a new IOC observation.

        Args:
            ioc_value: The indicator (IP, domain, hash).
            ioc_type: Type of IOC (ip, domain, sha256, etc.).
            source_node: Node ID that reported this IOC.
            severity: Severity level.

        Returns:
            Updated correlation result for this IOC.
        """
        ioc_key = self._ioc_key(ioc_value, ioc_type)
        now = time.time()

        with self._lock:
            if ioc_key not in self._iocs:
                if len(self._iocs) >= self.MAX_IOCS:
                    self._evict_oldest()
                result = CorrelationResult(ioc_value, ioc_type)
                result.first_seen = now
                self._iocs[ioc_key] = result
            else:
                result = self._iocs[ioc_key]

            result.hit_count += 1
            result.source_nodes.add(source_node)
            result.last_seen = now

            # Track max severity
            if self.SEVERITY_ORDER.get(severity, 0) > self.SEVERITY_ORDER.get(result.severity_max, 0):
                result.severity_max = severity

            # Campaign detection
            result.is_campaign = len(result.source_nodes) >= self.CAMPAIGN_THRESHOLD

            # Track per-node
            self._node_iocs[source_node].add(ioc_key)

        if result.is_campaign:
            logger.info(
                "Campaign detected: %s seen on %d nodes",
                ioc_value, len(result.source_nodes),
            )

        return result

    def correlate(self, ioc_value: str, ioc_type: str = "") -> Optional[CorrelationResult]:
        """Look up correlation data for an IOC.

        Args:
            ioc_value: The indicator to look up.
            ioc_type: Optional type filter.

        Returns:
            CorrelationResult if found, None otherwise.
        """
        if ioc_type:
            ioc_key = self._ioc_key(ioc_value, ioc_type)
            with self._lock:
                return self._iocs.get(ioc_key)

        # Search across all types
        with self._lock:
            for key, result in self._iocs.items():
                if result.ioc_value == ioc_value:
                    return result
        return None

    def get_campaigns(self) -> List[CorrelationResult]:
        """Get all active campaign indicators."""
        with self._lock:
            return [r for r in self._iocs.values() if r.is_campaign]

    def get_node_iocs(self, node_id: str) -> List[str]:
        """Get all IOCs reported by a specific node."""
        with self._lock:
            return list(self._node_iocs.get(node_id, set()))

    def cleanup(self) -> int:
        """Remove expired IOCs. Returns count removed."""
        now = time.time()
        expired = []

        with self._lock:
            for key, result in self._iocs.items():
                if now - result.last_seen > self.IOC_TTL:
                    expired.append(key)

            for key in expired:
                result = self._iocs.pop(key, None)
                if result:
                    for node in result.source_nodes:
                        self._node_iocs[node].discard(key)

        return len(expired)

    def get_stats(self) -> Dict:
        with self._lock:
            campaigns = sum(1 for r in self._iocs.values() if r.is_campaign)
            return {
                "total_iocs": len(self._iocs),
                "tracked_nodes": len(self._node_iocs),
                "active_campaigns": campaigns,
            }

    @staticmethod
    def _ioc_key(ioc_value: str, ioc_type: str) -> str:
        return f"{ioc_type}:{ioc_value}"

    def _evict_oldest(self) -> None:
        """Evict the oldest IOC entry."""
        oldest_key = None
        oldest_time = float('inf')
        for key, result in self._iocs.items():
            if result.last_seen < oldest_time:
                oldest_time = result.last_seen
                oldest_key = key
        if oldest_key:
            self._iocs.pop(oldest_key, None)
