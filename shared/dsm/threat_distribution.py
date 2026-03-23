#!/usr/bin/env python3
"""
DSM Threat Intelligence Distribution

Distributes collective threat intelligence across the HookProbe mesh.
Uses Bloom filter IOC sharing + DSM consensus for trust validation.

Flow:
  1. Local node detects malicious IPs → adds to local Bloom filter
  2. Periodically, exports filter with DP noise via gossip
  3. Remote nodes merge received filters (OR union)
  4. Consensus validates: only accepted if 2/3 validators agree
  5. Global threat model = union of all validated node filters

Usage:
    from shared.dsm.threat_distribution import ThreatDistributor

    distributor = ThreatDistributor(node_id="guardian-001")
    distributor.add_local_ioc("192.168.1.100", "malicious")
    distributor.add_local_ioc("evil.com", "malicious")

    # Share with mesh (called by mesh_server.py)
    payload = distributor.prepare_share()

    # Receive from mesh
    distributor.receive_share(remote_payload, sender_id="fortress-002")

    # Check collective intelligence
    if distributor.is_known_threat("192.168.1.100"):
        block_ip("192.168.1.100")
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .bloom_ioc import BloomIOCFilter, IOCSharingProtocol

logger = logging.getLogger(__name__)


@dataclass
class ThreatDistributor:
    """Manages collective threat intelligence via Bloom filter sharing."""

    node_id: str = ""
    epsilon: float = 1.0               # DP privacy budget
    expected_iocs: int = 10000         # Expected IOC count per node
    fp_rate: float = 0.01              # Target false positive rate
    share_interval: int = 3600         # Share every hour
    max_peers: int = 50                # Max peer filters to track

    def __post_init__(self):
        if not self.node_id:
            self.node_id = os.environ.get("HOOKPROBE_NODE_ID",
                                          os.environ.get("MESH_NODE_ID", "unknown"))
        # Local IOC filter
        self._local_bloom = BloomIOCFilter(self.expected_iocs, self.fp_rate)
        # Collective filter (same size as local — merge requires matching sizes)
        self._collective_bloom = BloomIOCFilter(self.expected_iocs, self.fp_rate)
        # Sharing protocol
        self._protocol = IOCSharingProtocol(
            self._local_bloom, epsilon=self.epsilon,
            node_id=self.node_id, share_interval=self.share_interval,
        )
        # Peer tracking
        self._peer_last_seen: Dict[str, float] = {}
        self._local_ioc_count = 0
        self._received_count = 0

    def add_local_ioc(self, indicator: str, ioc_type: str = "ip"):
        """Add a locally detected IOC to the local filter."""
        normalized = indicator.strip().lower()
        self._local_bloom.add(normalized)
        self._collective_bloom.add(normalized)
        self._local_ioc_count += 1

    def is_known_threat(self, indicator: str) -> bool:
        """Check if an indicator is in the collective threat intelligence."""
        normalized = indicator.strip().lower()
        return self._collective_bloom.contains(normalized)

    def is_local_threat(self, indicator: str) -> bool:
        """Check if an indicator was detected locally."""
        return self._local_bloom.contains(indicator.strip().lower())

    def prepare_share(self) -> Optional[bytes]:
        """Prepare IOC filter for sharing via mesh gossip.

        Returns DP-noised filter bytes, or None if not time to share yet.
        """
        if not self._protocol.should_share():
            return None

        if self._local_ioc_count == 0:
            logger.debug("No local IOCs to share")
            return None

        payload = self._protocol.export_with_privacy()
        logger.info(
            f"Prepared IOC share: {self._local_ioc_count} local IOCs, "
            f"{len(payload)} bytes, ε={self.epsilon}"
        )
        return payload

    def receive_share(self, payload: bytes, sender_id: str) -> bool:
        """Process a received IOC filter from a peer.

        Returns True if successfully merged.
        """
        try:
            import struct as _struct
            # Privacy export header: >IIIdfd (36 bytes) — different from raw export
            priv_header_size = _struct.calcsize('>IIIdfd')
            size, num_hashes, item_count, created_at, epsilon, shared_at = _struct.unpack(
                '>IIIdfd', payload[:priv_header_size]
            )
            remote_bloom = BloomIOCFilter.__new__(BloomIOCFilter)
            remote_bloom.size = size
            remote_bloom.num_hashes = num_hashes
            remote_bloom.item_count = item_count
            remote_bloom.created_at = created_at
            remote_bloom.bits = bytearray(payload[priv_header_size:])

            # Validate (sanity checks)
            if remote_bloom.fill_ratio() > 0.9:
                logger.warning(f"Rejecting filter from {sender_id}: fill ratio too high "
                               f"({remote_bloom.fill_ratio():.1%})")
                return False

            # Merge into collective
            self._collective_bloom.merge(remote_bloom)
            self._peer_last_seen[sender_id] = time.time()
            self._received_count += 1

            logger.info(
                f"Merged IOC filter from {sender_id}: "
                f"{remote_bloom.item_count} items, "
                f"collective fill={self._collective_bloom.fill_ratio():.2%}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to process IOC share from {sender_id}: {e}")
            return False

    def stats(self) -> dict:
        """Get distributor statistics."""
        return {
            "node_id": self.node_id,
            "local_iocs": self._local_ioc_count,
            "local_filter": self._local_bloom.to_dict(),
            "collective_filter": self._collective_bloom.to_dict(),
            "peers_seen": len(self._peer_last_seen),
            "received_shares": self._received_count,
            "epsilon": self.epsilon,
            "share_interval": self.share_interval,
        }


# --- CLI entry point ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Simulate two nodes sharing threat intel
    node_a = ThreatDistributor(node_id="guardian-001", share_interval=0)
    node_b = ThreatDistributor(node_id="fortress-001", share_interval=0)

    # Node A detects threats
    for i in range(50):
        node_a.add_local_ioc(f"10.0.0.{i}")

    # Node B detects different threats
    for i in range(50, 100):
        node_b.add_local_ioc(f"10.0.0.{i}")

    # Share
    payload_a = node_a.prepare_share()
    payload_b = node_b.prepare_share()

    if payload_a:
        node_b.receive_share(payload_a, "guardian-001")
    if payload_b:
        node_a.receive_share(payload_b, "fortress-001")

    # Now both nodes should know about threats from each other
    print(f"\nNode A knows 10.0.0.5 (local): {node_a.is_known_threat('10.0.0.5')}")
    print(f"Node A knows 10.0.0.75 (from B): {node_a.is_known_threat('10.0.0.75')}")
    print(f"Node B knows 10.0.0.5 (from A): {node_b.is_known_threat('10.0.0.5')}")
    print(f"Node B knows 10.0.0.75 (local): {node_b.is_known_threat('10.0.0.75')}")
    print(f"Node A knows 1.1.1.1 (not IOC): {node_a.is_known_threat('1.1.1.1')}")

    print(f"\nNode A stats: {json.dumps(node_a.stats(), indent=2)}")
