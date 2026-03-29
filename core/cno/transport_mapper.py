"""
Transport Mapper — Spatial Memory (Network Topology)

Builds and maintains a real-time graph of the network topology.
Understands which hosts exist, how they connect, link latency,
and bandwidth. Provides the Cerebrum with spatial awareness for:

    - Route optimization (find fastest path between nodes)
    - Failure detection (link went down → reroute)
    - Topology anomalies (new host appeared, link disappeared)
    - Capacity planning (which links are saturated)

Data sources:
    - ClickHouse napse_flows (connection graph)
    - PacketSIEM spatial state (real-time view)
    - RDAP enrichment (IP classification)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import os
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen

from .types import BrainLayer, SynapticEvent, SynapticRoute

logger = logging.getLogger(__name__)

# ClickHouse config
CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

TOPOLOGY_WINDOW_S = 3600       # 1-hour window for topology building
REBUILD_INTERVAL_S = 300       # Rebuild every 5 minutes
MAX_NODES = 500                # Max nodes to track
MAX_EDGES_PER_NODE = 50        # Max connections per node


class TopologyNode:
    """A node in the network topology graph."""

    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen: float = time.time()
        self.last_seen: float = time.time()
        self.total_bytes_out: int = 0
        self.total_bytes_in: int = 0
        self.total_flows: int = 0
        self.services: Set[int] = set()  # Listening ports
        self.ip_type: str = ""            # datacenter, isp, cdn, etc.
        self.is_internal: bool = ip.startswith(('10.', '172.16.', '172.17.',
                                                '172.18.', '172.19.', '172.20.',
                                                '172.21.', '172.22.', '172.23.',
                                                '172.24.', '172.25.', '172.26.',
                                                '172.27.', '172.28.', '172.29.',
                                                '172.30.', '172.31.', '192.168.',
                                                '127.'))


class TopologyEdge:
    """A directed edge (connection) between two nodes."""

    def __init__(self, src: str, dst: str):
        self.src = src
        self.dst = dst
        self.flow_count: int = 0
        self.total_bytes: int = 0
        self.avg_duration: float = 0.0
        self.protocols: Set[int] = set()
        self.ports: Set[int] = set()
        self.first_seen: float = time.time()
        self.last_seen: float = time.time()
        self.is_active: bool = True


class TransportMapper:
    """Builds and maintains the network topology graph.

    The organism's "spatial memory" — understanding of network geography.
    """

    def __init__(self, submit_event=None):
        self._submit = submit_event
        self._nodes: Dict[str, TopologyNode] = {}
        self._edges: Dict[str, TopologyEdge] = {}  # "src->dst" key
        self._last_rebuild: float = 0.0

        self._stats = {
            'rebuilds': 0,
            'nodes_discovered': 0,
            'edges_discovered': 0,
            'anomalies_detected': 0,
        }

        logger.info("TransportMapper initialized")

    # ------------------------------------------------------------------
    # Topology Building
    # ------------------------------------------------------------------

    def rebuild_topology(self) -> Dict[str, int]:
        """Rebuild the topology graph from recent flow data.

        Returns {nodes, edges, new_nodes, disappeared_nodes}.
        """
        self._stats['rebuilds'] += 1
        start = time.monotonic()

        old_nodes = set(self._nodes.keys())

        # Query flow graph from ClickHouse
        query = (
            f"SELECT src_ip, dst_ip, count(*) AS flows, "
            f"sum(bytes_orig) AS bytes_out, "
            f"avg(duration) AS avg_dur, "
            f"groupUniqArray(proto) AS protos, "
            f"groupUniqArray(dst_port) AS ports "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE timestamp > now() - INTERVAL {TOPOLOGY_WINDOW_S} SECOND "
            f"GROUP BY src_ip, dst_ip "
            f"ORDER BY flows DESC "
            f"LIMIT 2000"
        )
        result = _ch_query(query)
        if not result:
            return {'nodes': len(self._nodes), 'edges': len(self._edges),
                    'new_nodes': 0, 'disappeared_nodes': 0}

        # Parse results and build graph
        seen_nodes: Set[str] = set()
        new_edges = 0

        for line in result.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 5:
                continue

            src_ip = parts[0]
            dst_ip = parts[1]

            if not _IPV4_RE.match(src_ip) or not _IPV4_RE.match(dst_ip):
                continue

            flows = int(parts[2] or 0)
            bytes_out = int(parts[3] or 0)
            avg_dur = float(parts[4] or 0)

            # Update/create nodes
            for ip in (src_ip, dst_ip):
                seen_nodes.add(ip)
                if ip not in self._nodes:
                    self._nodes[ip] = TopologyNode(ip)
                    self._stats['nodes_discovered'] += 1
                self._nodes[ip].last_seen = time.time()

            self._nodes[src_ip].total_bytes_out += bytes_out
            self._nodes[src_ip].total_flows += flows
            self._nodes[dst_ip].total_bytes_in += bytes_out

            # Update/create edge
            edge_key = f"{src_ip}->{dst_ip}"
            if edge_key not in self._edges:
                self._edges[edge_key] = TopologyEdge(src_ip, dst_ip)
                self._stats['edges_discovered'] += 1
                new_edges += 1

            edge = self._edges[edge_key]
            edge.flow_count = flows
            edge.total_bytes = bytes_out
            edge.avg_duration = avg_dur
            edge.last_seen = time.time()
            edge.is_active = True

        # Detect new and disappeared nodes
        new_nodes = seen_nodes - old_nodes
        disappeared = old_nodes - seen_nodes

        # Mark disappeared edges as inactive
        for edge_key, edge in self._edges.items():
            if edge.src not in seen_nodes or edge.dst not in seen_nodes:
                edge.is_active = False

        # Cap node count
        if len(self._nodes) > MAX_NODES:
            # Remove oldest inactive nodes
            sorted_nodes = sorted(
                self._nodes.items(),
                key=lambda x: x[1].last_seen,
            )
            for ip, _ in sorted_nodes[:len(self._nodes) - MAX_NODES]:
                del self._nodes[ip]

        self._last_rebuild = time.time()
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Emit events for new nodes (topology change)
        for ip in list(new_nodes)[:5]:  # Limit event emission
            if self._submit:
                self._submit(
                    source_layer=BrainLayer.CEREBELLUM,
                    route=SynapticRoute.TEMPORAL_MEMORY,
                    event_type='topology.new_node',
                    priority=7,
                    source_ip=ip,
                    payload={
                        'is_internal': self._nodes[ip].is_internal,
                    },
                )

        logger.info(
            "Topology rebuilt: %d nodes, %d edges, %d new, %d disappeared (%dms)",
            len(self._nodes), len(self._edges),
            len(new_nodes), len(disappeared), elapsed_ms,
        )

        return {
            'nodes': len(self._nodes),
            'edges': len(self._edges),
            'new_nodes': len(new_nodes),
            'disappeared_nodes': len(disappeared),
        }

    # ------------------------------------------------------------------
    # Topology Queries
    # ------------------------------------------------------------------

    def get_node(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get info about a specific node."""
        node = self._nodes.get(ip)
        if not node:
            return None
        return {
            'ip': node.ip,
            'is_internal': node.is_internal,
            'first_seen': node.first_seen,
            'last_seen': node.last_seen,
            'bytes_out': node.total_bytes_out,
            'bytes_in': node.total_bytes_in,
            'flows': node.total_flows,
            'services': sorted(node.services),
            'ip_type': node.ip_type,
        }

    def get_neighbors(self, ip: str) -> List[Dict[str, Any]]:
        """Get all nodes connected to a given IP."""
        neighbors = []
        for edge_key, edge in self._edges.items():
            if edge.src == ip:
                neighbors.append({
                    'ip': edge.dst,
                    'direction': 'outbound',
                    'flows': edge.flow_count,
                    'bytes': edge.total_bytes,
                    'active': edge.is_active,
                })
            elif edge.dst == ip:
                neighbors.append({
                    'ip': edge.src,
                    'direction': 'inbound',
                    'flows': edge.flow_count,
                    'bytes': edge.total_bytes,
                    'active': edge.is_active,
                })
        return sorted(neighbors, key=lambda n: n['flows'], reverse=True)

    def get_top_talkers(self, n: int = 10) -> List[Dict[str, Any]]:
        """Get the top N nodes by total traffic."""
        nodes = sorted(
            self._nodes.values(),
            key=lambda x: x.total_bytes_out + x.total_bytes_in,
            reverse=True,
        )[:n]
        return [
            {
                'ip': node.ip,
                'is_internal': node.is_internal,
                'total_bytes': node.total_bytes_out + node.total_bytes_in,
                'flows': node.total_flows,
            }
            for node in nodes
        ]

    def get_summary(self) -> Dict[str, Any]:
        """Get topology summary for dashboard."""
        internal = sum(1 for n in self._nodes.values() if n.is_internal)
        external = len(self._nodes) - internal
        active_edges = sum(1 for e in self._edges.values() if e.is_active)

        return {
            'total_nodes': len(self._nodes),
            'internal_nodes': internal,
            'external_nodes': external,
            'total_edges': len(self._edges),
            'active_edges': active_edges,
            'top_talkers': self.get_top_talkers(5),
            'last_rebuild': self._last_rebuild,
            'stats': dict(self._stats),
        }


# ------------------------------------------------------------------
# ClickHouse Helper
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
