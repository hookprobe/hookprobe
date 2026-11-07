"""
Entity Graph — Temporal Network Graph for SIA

Models the network as a heterogeneous temporal graph G=(V,E,T) where:
  V = IPs, MACs, Users, Processes (entity nodes)
  E = connections, auth events, API calls (weighted edges)
  T = timestamps with sliding window decay

Each entity accumulates behavioral features from network events.
Edges are weighted by frequency, recency, and protocol diversity.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import math
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class EntityType(Enum):
    """Types of entities in the graph."""
    IP = auto()
    MAC = auto()
    USER = auto()
    DOMAIN = auto()


@dataclass
class EntityNode:
    """A node in the temporal entity graph."""
    entity_id: str                    # IP address, MAC, username, etc.
    entity_type: EntityType = EntityType.IP
    first_seen: float = 0.0           # Unix timestamp
    last_seen: float = 0.0
    event_count: int = 0

    # Behavioral feature accumulators
    unique_dest_ports: Set[int] = field(default_factory=set)
    unique_dest_ips: Set[str] = field(default_factory=set)
    unique_protocols: Set[str] = field(default_factory=set)
    unique_services: Set[str] = field(default_factory=set)
    bytes_sent: int = 0
    bytes_received: int = 0
    dns_queries: int = 0
    failed_connections: int = 0
    alert_count: int = 0

    # Computed features (updated by GraphEmbedder)
    embedding: Optional[List[float]] = None

    @property
    def port_entropy(self) -> float:
        """Entropy of destination port distribution."""
        n = len(self.unique_dest_ports)
        if n <= 1:
            return 0.0
        return math.log2(n)

    @property
    def connection_rate(self) -> float:
        """Connections per second of active time."""
        duration = max(self.last_seen - self.first_seen, 1.0)
        return self.event_count / duration

    def get_feature_vector(self) -> List[float]:
        """Extract a feature vector for embedding computation."""
        duration = max(self.last_seen - self.first_seen, 1.0)
        return [
            len(self.unique_dest_ports),
            len(self.unique_dest_ips),
            len(self.unique_protocols),
            len(self.unique_services),
            self.bytes_sent / max(self.bytes_received, 1),  # Send/receive ratio
            self.dns_queries,
            self.failed_connections,
            self.alert_count,
            self.event_count / duration,                     # Event rate
            self.port_entropy,
            min(self.bytes_sent, 1e9) / 1e6,                # MB sent (capped)
            min(self.bytes_received, 1e9) / 1e6,             # MB received (capped)
            1.0 if self.alert_count > 0 else 0.0,           # Has alerts
            min(len(self.unique_dest_ports), 100) / 100.0,   # Port scan indicator
            self.connection_rate,
            duration / 3600.0,                               # Hours active
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.name,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "unique_dest_ports": len(self.unique_dest_ports),
            "unique_dest_ips": len(self.unique_dest_ips),
            "alert_count": self.alert_count,
            "port_entropy": self.port_entropy,
        }


@dataclass
class EntityEdge:
    """A weighted edge between two entities."""
    src_id: str
    dst_id: str
    weight: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    event_count: int = 0
    protocols: Set[str] = field(default_factory=set)
    services: Set[str] = field(default_factory=set)
    total_bytes: int = 0

    @property
    def key(self) -> Tuple[str, str]:
        return (self.src_id, self.dst_id)

    def update_weight(self, decay_rate: float = 0.001) -> None:
        """Recalculate edge weight based on frequency, recency, diversity."""
        recency = math.exp(-decay_rate * (time.time() - self.last_seen))
        frequency = math.log1p(self.event_count)
        diversity = len(self.protocols) + len(self.services)
        self.weight = recency * frequency * (1.0 + 0.1 * diversity)


# Feature vector size produced by EntityNode.get_feature_vector()
FEATURE_DIM = 16


class EntityGraph:
    """
    Temporal entity graph with sliding window.

    Maintains nodes (entities) and edges (connections) with
    time-based decay. Provides neighbor lookups and feature
    extraction for the GraphEmbedder.
    """

    def __init__(
        self,
        window_hours: float = 24.0,
        max_nodes: int = 10000,
        edge_decay_rate: float = 0.001,
    ):
        self._nodes: Dict[str, EntityNode] = {}
        self._edges: Dict[Tuple[str, str], EntityEdge] = {}
        self._adjacency: Dict[str, Set[str]] = defaultdict(set)
        self._lock = threading.Lock()
        self._window_seconds = window_hours * 3600
        self._max_nodes = max_nodes
        self._edge_decay_rate = edge_decay_rate

        self._stats = {
            "events_processed": 0,
            "nodes_created": 0,
            "edges_created": 0,
            "nodes_evicted": 0,
        }

        logger.info(
            "EntityGraph initialized (window=%.1fh, max_nodes=%d)",
            window_hours, max_nodes,
        )

    # ------------------------------------------------------------------
    # Event Ingestion
    # ------------------------------------------------------------------

    def add_connection_event(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str = "tcp",
        service: str = "",
        orig_bytes: int = 0,
        resp_bytes: int = 0,
        conn_state: str = "",
    ) -> None:
        """Ingest a connection event into the graph."""
        now = time.time()
        with self._lock:
            self._stats["events_processed"] += 1

            # Update source node
            src_node = self._get_or_create_node(src_ip, EntityType.IP)
            src_node.last_seen = now
            src_node.event_count += 1
            src_node.unique_dest_ports.add(dst_port)
            src_node.unique_dest_ips.add(dst_ip)
            src_node.unique_protocols.add(proto)
            if service:
                src_node.unique_services.add(service)
            src_node.bytes_sent += orig_bytes
            src_node.bytes_received += resp_bytes
            if conn_state in ("REJ", "S0", "RSTO"):
                src_node.failed_connections += 1

            # Update dest node
            dst_node = self._get_or_create_node(dst_ip, EntityType.IP)
            dst_node.last_seen = now
            dst_node.event_count += 1
            dst_node.bytes_received += orig_bytes
            dst_node.bytes_sent += resp_bytes

            # Update edge
            edge = self._get_or_create_edge(src_ip, dst_ip)
            edge.last_seen = now
            edge.event_count += 1
            edge.protocols.add(proto)
            if service:
                edge.services.add(service)
            edge.total_bytes += orig_bytes + resp_bytes
            edge.update_weight(self._edge_decay_rate)

    def add_dns_event(self, src_ip: str, query: str, answers: Optional[List[str]] = None) -> None:
        """Ingest a DNS event."""
        now = time.time()
        with self._lock:
            self._stats["events_processed"] += 1
            src_node = self._get_or_create_node(src_ip, EntityType.IP)
            src_node.last_seen = now
            src_node.dns_queries += 1
            src_node.event_count += 1

            # Create domain node and edge
            domain_node = self._get_or_create_node(query, EntityType.DOMAIN)
            domain_node.last_seen = now
            domain_node.event_count += 1

            edge = self._get_or_create_edge(src_ip, query)
            edge.last_seen = now
            edge.event_count += 1
            edge.services.add("dns")
            edge.update_weight(self._edge_decay_rate)

    def add_alert_event(self, src_ip: str, severity: str = "MEDIUM") -> None:
        """Ingest an alert event — increments alert counter."""
        with self._lock:
            self._stats["events_processed"] += 1
            node = self._get_or_create_node(src_ip, EntityType.IP)
            node.alert_count += 1
            node.last_seen = time.time()
            node.event_count += 1

    # ------------------------------------------------------------------
    # Graph Queries
    # ------------------------------------------------------------------

    def get_node(self, entity_id: str) -> Optional[EntityNode]:
        """Get a node by entity ID."""
        with self._lock:
            return self._nodes.get(entity_id)

    def get_neighbors(self, entity_id: str) -> List[str]:
        """Get neighbor entity IDs."""
        with self._lock:
            return list(self._adjacency.get(entity_id, set()))

    def get_neighbor_nodes(self, entity_id: str) -> List[EntityNode]:
        """Get neighbor EntityNode objects."""
        with self._lock:
            neighbors = self._adjacency.get(entity_id, set())
            return [self._nodes[n] for n in neighbors if n in self._nodes]

    def get_edge(self, src_id: str, dst_id: str) -> Optional[EntityEdge]:
        """Get edge between two entities."""
        with self._lock:
            return self._edges.get((src_id, dst_id)) or self._edges.get((dst_id, src_id))

    def get_node_features(self, entity_id: str) -> Optional[List[float]]:
        """Get feature vector for an entity."""
        with self._lock:
            node = self._nodes.get(entity_id)
            if node:
                return node.get_feature_vector()
            return None

    def get_subgraph(self, entity_id: str, depth: int = 1) -> Dict[str, Any]:
        """Get a subgraph centered on an entity up to given depth."""
        with self._lock:
            nodes = {}
            edges = []
            frontier = {entity_id}
            visited = set()

            for _ in range(depth):
                next_frontier = set()
                for nid in frontier:
                    if nid in visited:
                        continue
                    visited.add(nid)
                    if nid in self._nodes:
                        nodes[nid] = self._nodes[nid].to_dict()
                    for neighbor in self._adjacency.get(nid, set()):
                        next_frontier.add(neighbor)
                        edge_key = (nid, neighbor)
                        rev_key = (neighbor, nid)
                        if edge_key in self._edges:
                            edges.append({
                                "src": nid, "dst": neighbor,
                                "weight": self._edges[edge_key].weight,
                            })
                        elif rev_key in self._edges:
                            edges.append({
                                "src": neighbor, "dst": nid,
                                "weight": self._edges[rev_key].weight,
                            })
                frontier = next_frontier - visited

            return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def decay_edges(self) -> int:
        """Recalculate all edge weights with time decay."""
        decayed = 0
        with self._lock:
            for edge in self._edges.values():
                old_weight = edge.weight
                edge.update_weight(self._edge_decay_rate)
                if edge.weight != old_weight:
                    decayed += 1
        return decayed

    def evict_stale(self) -> int:
        """Remove nodes not seen within the sliding window."""
        cutoff = time.time() - self._window_seconds
        removed = 0
        with self._lock:
            stale_ids = [
                nid for nid, node in self._nodes.items()
                if node.last_seen < cutoff
            ]
            for nid in stale_ids:
                self._remove_node(nid)
                removed += 1
            self._stats["nodes_evicted"] += removed
        return removed

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "node_count": len(self._nodes),
                "edge_count": len(self._edges),
                "feature_dim": FEATURE_DIM,
            }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_or_create_node(self, entity_id: str, entity_type: EntityType) -> EntityNode:
        """Get or create a node (caller must hold lock)."""
        if entity_id not in self._nodes:
            if len(self._nodes) >= self._max_nodes:
                self._evict_oldest_node()
            self._nodes[entity_id] = EntityNode(
                entity_id=entity_id,
                entity_type=entity_type,
                first_seen=time.time(),
                last_seen=time.time(),
            )
            self._stats["nodes_created"] += 1
        return self._nodes[entity_id]

    def _get_or_create_edge(self, src_id: str, dst_id: str) -> EntityEdge:
        """Get or create an edge (caller must hold lock)."""
        key = (src_id, dst_id)
        if key not in self._edges:
            self._edges[key] = EntityEdge(
                src_id=src_id, dst_id=dst_id,
                first_seen=time.time(), last_seen=time.time(),
            )
            self._adjacency[src_id].add(dst_id)
            self._adjacency[dst_id].add(src_id)
            self._stats["edges_created"] += 1
        return self._edges[key]

    def _remove_node(self, entity_id: str) -> None:
        """Remove a node and its edges (caller must hold lock)."""
        self._nodes.pop(entity_id, None)
        neighbors = self._adjacency.pop(entity_id, set())
        for n in neighbors:
            self._adjacency.get(n, set()).discard(entity_id)
            self._edges.pop((entity_id, n), None)
            self._edges.pop((n, entity_id), None)

    def _evict_oldest_node(self) -> None:
        """Evict the least recently seen node (caller must hold lock)."""
        if not self._nodes:
            return
        oldest_id = min(self._nodes, key=lambda nid: self._nodes[nid].last_seen)
        self._remove_node(oldest_id)
        self._stats["nodes_evicted"] += 1
