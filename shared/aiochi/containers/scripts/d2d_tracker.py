#!/usr/bin/env python3
"""
AIOCHI D2D (Device-to-Device) Communication Tracker

Tracks which devices communicate with each other on the local network.
This data is exposed via REST API for fts-web to color devices based
on their communication patterns.

Purpose:
- Help users visualize device relationships before manual bubble assignment
- Devices that communicate frequently likely belong together
- Colors indicate communication clusters

Architecture:
    Zeek conn.log -> D2D Detection -> Communication Graph -> REST API -> fts-web coloring
"""

import hashlib
import json
import logging
import random
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# Predefined color palette for communication clusters (visually distinct)
CLUSTER_COLOR_PALETTE = [
    "#F87171",  # Red-400
    "#FB923C",  # Orange-400
    "#FBBF24",  # Amber-400
    "#A3E635",  # Lime-400
    "#34D399",  # Emerald-400
    "#22D3EE",  # Cyan-400
    "#60A5FA",  # Blue-400
    "#A78BFA",  # Violet-400
    "#F472B6",  # Pink-400
    "#E879F9",  # Fuchsia-400
    "#FB7185",  # Rose-400
    "#38BDF8",  # Sky-400
    "#4ADE80",  # Green-400
    "#FACC15",  # Yellow-400
    "#C084FC",  # Purple-400
    "#2DD4BF",  # Teal-400
]


def generate_cluster_color(cluster_id: str) -> str:
    """Generate a consistent color for a cluster based on its ID."""
    # Use hash to get consistent color for same cluster
    hash_val = int(hashlib.md5(cluster_id.encode()).hexdigest()[:8], 16)
    return CLUSTER_COLOR_PALETTE[hash_val % len(CLUSTER_COLOR_PALETTE)]


def generate_random_color() -> str:
    """Generate a random distinct color."""
    return random.choice(CLUSTER_COLOR_PALETTE)

# Persistence path
D2D_STATE_FILE = Path("/var/lib/aiochi/d2d_state.json")

# Communication thresholds for color assignment
HIGH_COMMUNICATION_THRESHOLD = 50     # connections -> strong relationship
MEDIUM_COMMUNICATION_THRESHOLD = 10   # connections -> moderate relationship
LOW_COMMUNICATION_THRESHOLD = 1       # connections -> weak relationship


class CommunicationStrength(Enum):
    """Strength of communication between devices."""
    NONE = "none"
    WEAK = "weak"       # 1-9 connections
    MODERATE = "moderate"  # 10-49 connections
    STRONG = "strong"   # 50+ connections


# Colors for communication strength visualization
COMMUNICATION_COLORS = {
    CommunicationStrength.NONE: None,
    CommunicationStrength.WEAK: "#9CA3AF",      # Gray-400
    CommunicationStrength.MODERATE: "#60A5FA",  # Blue-400
    CommunicationStrength.STRONG: "#34D399",    # Green-400
}


class EcosystemType(Enum):
    """Device ecosystem types detected from mDNS."""
    APPLE = "apple"
    GOOGLE = "google"
    SAMSUNG = "samsung"
    AMAZON = "amazon"
    MICROSOFT = "microsoft"
    UNKNOWN = "unknown"


ECOSYSTEM_COLORS = {
    EcosystemType.APPLE: "#A2AAAD",      # Apple silver
    EcosystemType.GOOGLE: "#4285F4",     # Google blue
    EcosystemType.SAMSUNG: "#1428A0",    # Samsung blue
    EcosystemType.AMAZON: "#FF9900",     # Amazon orange
    EcosystemType.MICROSOFT: "#00A4EF",  # Microsoft blue
    EcosystemType.UNKNOWN: "#6B7280",    # Gray
}


@dataclass
class Device:
    """Tracked device."""
    mac: str
    ip: str = ""
    ecosystem: EcosystemType = EcosystemType.UNKNOWN
    hostname: str = ""
    services: Set[str] = field(default_factory=set)  # mDNS services
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "ecosystem": self.ecosystem.value,
            "ecosystem_color": ECOSYSTEM_COLORS.get(self.ecosystem, "#6B7280"),
            "hostname": self.hostname,
            "services": list(self.services),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class CommunicationEdge:
    """Communication edge between two devices."""
    mac_a: str
    mac_b: str
    connection_count: int = 0
    bytes_transferred: int = 0
    services: Set[str] = field(default_factory=set)  # protocols used
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def strength(self) -> CommunicationStrength:
        """Get communication strength based on connection count."""
        if self.connection_count >= HIGH_COMMUNICATION_THRESHOLD:
            return CommunicationStrength.STRONG
        elif self.connection_count >= MEDIUM_COMMUNICATION_THRESHOLD:
            return CommunicationStrength.MODERATE
        elif self.connection_count >= LOW_COMMUNICATION_THRESHOLD:
            return CommunicationStrength.WEAK
        return CommunicationStrength.NONE

    @property
    def color(self) -> Optional[str]:
        """Get color for this communication strength."""
        return COMMUNICATION_COLORS.get(self.strength)

    def to_dict(self) -> Dict:
        return {
            "mac_a": self.mac_a,
            "mac_b": self.mac_b,
            "connection_count": self.connection_count,
            "bytes_transferred": self.bytes_transferred,
            "services": list(self.services),
            "strength": self.strength.value,
            "color": self.color,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class D2DTracker:
    """
    Tracks device-to-device communication patterns.

    Provides API for fts-web to:
    - Get communication graph (which devices talk to which)
    - Get communication colors for devices
    - Find communication clusters (devices that talk to each other)
    """

    def __init__(self):
        self._devices: Dict[str, Device] = {}         # MAC -> Device
        self._ip_to_mac: Dict[str, str] = {}          # IP -> MAC mapping
        self._edges: Dict[Tuple[str, str], CommunicationEdge] = {}  # (mac1, mac2) -> Edge

        self._lock = threading.RLock()

        # Load persisted state
        self._load_state()

        # Pre-populate IP→MAC mappings from dnsmasq leases
        self._load_dhcp_leases()

    def _load_dhcp_leases(self):
        """Load IP→MAC mappings from dnsmasq leases file."""
        leases_file = Path("/var/lib/misc/dnsmasq.leases")
        try:
            if not leases_file.exists():
                logger.debug("dnsmasq leases file not found")
                return

            with open(leases_file) as f:
                for line in f:
                    parts = line.strip().split()
                    # Format: <expiry> <mac> <ip> <hostname> <client-id>
                    if len(parts) >= 3:
                        mac = parts[1].upper()
                        ip = parts[2]
                        hostname = parts[3] if len(parts) > 3 else ""

                        with self._lock:
                            self._ip_to_mac[ip] = mac

                            # Also register device if not exists
                            if mac not in self._devices:
                                self._devices[mac] = Device(
                                    mac=mac,
                                    ip=ip,
                                    hostname=hostname,
                                )
                            else:
                                # Update IP mapping
                                self._devices[mac].ip = ip
                                if hostname:
                                    self._devices[mac].hostname = hostname

            logger.info(f"Loaded {len(self._ip_to_mac)} IP→MAC mappings from dnsmasq leases")
        except Exception as e:
            logger.warning(f"Could not load dnsmasq leases: {e}")

    # =========================================================================
    # EVENT RECORDING
    # =========================================================================

    def record_mdns_event(
        self,
        source_mac: str,
        source_ip: str,
        query: str,
        ecosystem: str,
        hostname: str = ""
    ):
        """
        Record an mDNS event to track device ecosystem.

        Args:
            source_mac: Device MAC address
            source_ip: Device IP address
            query: mDNS query/service name
            ecosystem: Detected ecosystem (apple, google, etc.)
            hostname: Device hostname if available
        """
        source_mac = source_mac.upper()

        with self._lock:
            device = self._get_or_create_device(source_mac, source_ip)
            device.last_seen = datetime.now().isoformat()
            device.services.add(query)

            # Update ecosystem
            eco = self._parse_ecosystem(ecosystem)
            if eco != EcosystemType.UNKNOWN:
                device.ecosystem = eco

            if hostname:
                device.hostname = hostname

    def record_d2d_connection(
        self,
        src_ip: str,
        dst_ip: str,
        service: str = "",
        bytes_count: int = 0
    ):
        """
        Record a device-to-device connection.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            service: Service/protocol name
            bytes_count: Bytes transferred
        """
        with self._lock:
            src_mac = self._ip_to_mac.get(src_ip)
            dst_mac = self._ip_to_mac.get(dst_ip)

            if not src_mac or not dst_mac:
                return

            if src_mac == dst_mac:
                return

            # Get or create edge (normalized ordering)
            edge = self._get_or_create_edge(src_mac, dst_mac)
            edge.connection_count += 1
            edge.bytes_transferred += bytes_count
            edge.last_seen = datetime.now().isoformat()

            if service:
                edge.services.add(service)

            # Update device last_seen
            if src_mac in self._devices:
                self._devices[src_mac].last_seen = datetime.now().isoformat()
            if dst_mac in self._devices:
                self._devices[dst_mac].last_seen = datetime.now().isoformat()

    def register_device(self, mac: str, ip: str, hostname: str = ""):
        """Register a device with IP mapping."""
        mac = mac.upper()

        with self._lock:
            device = self._get_or_create_device(mac, ip)
            device.last_seen = datetime.now().isoformat()
            if hostname:
                device.hostname = hostname

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _get_or_create_device(self, mac: str, ip: str = "") -> Device:
        """Get or create a device entry."""
        mac = mac.upper()

        if mac not in self._devices:
            self._devices[mac] = Device(mac=mac, ip=ip)

        device = self._devices[mac]

        if ip:
            device.ip = ip
            self._ip_to_mac[ip] = mac

        return device

    def _get_or_create_edge(self, mac1: str, mac2: str) -> CommunicationEdge:
        """Get or create a communication edge."""
        # Normalize ordering for consistent keys
        key = tuple(sorted([mac1.upper(), mac2.upper()]))

        if key not in self._edges:
            self._edges[key] = CommunicationEdge(mac_a=key[0], mac_b=key[1])

        return self._edges[key]

    def _parse_ecosystem(self, eco_str: str) -> EcosystemType:
        """Parse ecosystem string to enum."""
        eco_lower = eco_str.lower()
        for eco in EcosystemType:
            if eco.value in eco_lower:
                return eco
        return EcosystemType.UNKNOWN

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def get_all_devices(self) -> List[Device]:
        """Get all tracked devices."""
        with self._lock:
            return list(self._devices.values())

    def get_device(self, mac: str) -> Optional[Device]:
        """Get device by MAC."""
        mac = mac.upper()
        with self._lock:
            return self._devices.get(mac)

    def get_device_by_ip(self, ip: str) -> Optional[Device]:
        """Get device by IP."""
        with self._lock:
            mac = self._ip_to_mac.get(ip)
            if mac:
                return self._devices.get(mac)
            return None

    def get_all_edges(self) -> List[CommunicationEdge]:
        """Get all communication edges."""
        with self._lock:
            return list(self._edges.values())

    def get_device_edges(self, mac: str) -> List[CommunicationEdge]:
        """Get all communication edges involving a device."""
        mac = mac.upper()
        with self._lock:
            return [
                edge for edge in self._edges.values()
                if edge.mac_a == mac or edge.mac_b == mac
            ]

    def get_communication_strength(self, mac1: str, mac2: str) -> CommunicationStrength:
        """Get communication strength between two devices."""
        key = tuple(sorted([mac1.upper(), mac2.upper()]))
        with self._lock:
            edge = self._edges.get(key)
            if edge:
                return edge.strength
            return CommunicationStrength.NONE

    def get_device_communication_color(self, mac: str) -> Dict:
        """
        Get communication info for a device for UI coloring.

        Returns dict with:
        - ecosystem_color: Color based on device ecosystem
        - communication_peers: List of devices this device talks to with colors
        """
        mac = mac.upper()

        with self._lock:
            device = self._devices.get(mac)
            if not device:
                return {
                    "mac": mac,
                    "ecosystem_color": "#6B7280",
                    "communication_peers": [],
                }

            # Get communication peers
            peers = []
            for edge in self._edges.values():
                if edge.mac_a == mac:
                    peer_mac = edge.mac_b
                elif edge.mac_b == mac:
                    peer_mac = edge.mac_a
                else:
                    continue

                peers.append({
                    "mac": peer_mac,
                    "connection_count": edge.connection_count,
                    "strength": edge.strength.value,
                    "color": edge.color,
                })

            return {
                "mac": mac,
                "ip": device.ip,
                "hostname": device.hostname,
                "ecosystem": device.ecosystem.value,
                "ecosystem_color": ECOSYSTEM_COLORS.get(device.ecosystem, "#6B7280"),
                "communication_peers": sorted(
                    peers, key=lambda p: p["connection_count"], reverse=True
                ),
            }

    def get_communication_graph(self) -> Dict:
        """
        Get full communication graph for visualization.

        Returns:
            Dict with nodes (devices) and edges (communication links)
        """
        with self._lock:
            nodes = [
                {
                    "id": mac,
                    "ip": d.ip,
                    "hostname": d.hostname,
                    "ecosystem": d.ecosystem.value,
                    "color": ECOSYSTEM_COLORS.get(d.ecosystem, "#6B7280"),
                    "last_seen": d.last_seen,
                }
                for mac, d in self._devices.items()
            ]

            edges = [
                {
                    "source": e.mac_a,
                    "target": e.mac_b,
                    "weight": e.connection_count,
                    "strength": e.strength.value,
                    "color": e.color,
                    "services": list(e.services),
                }
                for e in self._edges.values()
                if e.connection_count > 0
            ]

            return {
                "nodes": nodes,
                "edges": edges,
                "node_count": len(nodes),
                "edge_count": len(edges),
                "timestamp": datetime.now().isoformat(),
            }

    def get_communication_clusters(self) -> List[Dict]:
        """
        Find clusters of devices that communicate with each other.
        Each cluster gets a randomly generated color for easy identification.

        Returns:
            List of clusters, each with devices, stats, and assigned color
        """
        with self._lock:
            # Build adjacency list
            adjacency: Dict[str, Set[str]] = defaultdict(set)
            for edge in self._edges.values():
                if edge.strength != CommunicationStrength.NONE:
                    adjacency[edge.mac_a].add(edge.mac_b)
                    adjacency[edge.mac_b].add(edge.mac_a)

            # Find connected components using BFS
            visited: Set[str] = set()
            clusters: List[Set[str]] = []

            for mac in self._devices.keys():
                if mac in visited:
                    continue
                if mac not in adjacency:
                    continue

                # BFS to find cluster
                cluster = set()
                queue = [mac]

                while queue:
                    current = queue.pop(0)
                    if current in visited:
                        continue

                    visited.add(current)
                    cluster.add(current)

                    for neighbor in adjacency.get(current, []):
                        if neighbor not in visited:
                            queue.append(neighbor)

                if len(cluster) >= 2:
                    clusters.append(cluster)

            # Convert to output format with colors
            result = []
            for idx, cluster in enumerate(clusters):
                # Generate cluster ID from sorted MAC addresses
                cluster_id = f"cluster-{idx}-{'-'.join(sorted(cluster)[:2])}"
                cluster_color = generate_cluster_color(cluster_id)

                devices = []
                total_connections = 0
                edge_count = 0

                for mac in cluster:
                    device = self._devices.get(mac)
                    if device:
                        device_info = device.to_dict()
                        device_info["cluster_id"] = cluster_id
                        device_info["cluster_color"] = cluster_color
                        devices.append(device_info)

                # Calculate cluster stats
                macs = list(cluster)
                for i in range(len(macs)):
                    for j in range(i + 1, len(macs)):
                        key = tuple(sorted([macs[i], macs[j]]))
                        edge = self._edges.get(key)
                        if edge:
                            total_connections += edge.connection_count
                            edge_count += 1

                avg_connections = total_connections / max(1, edge_count)

                result.append({
                    "cluster_id": cluster_id,
                    "color": cluster_color,
                    "devices": devices,
                    "device_macs": list(cluster),
                    "device_count": len(cluster),
                    "total_connections": total_connections,
                    "avg_connections": avg_connections,
                })

            return sorted(result, key=lambda c: c["total_connections"], reverse=True)

    def get_device_cluster_color(self, mac: str) -> Optional[Dict]:
        """
        Get the cluster color for a specific device.

        Returns:
            Dict with cluster_id, color, and peer devices, or None if not in cluster
        """
        mac = mac.upper()
        clusters = self.get_communication_clusters()

        for cluster in clusters:
            if mac in cluster["device_macs"]:
                return {
                    "mac": mac,
                    "cluster_id": cluster["cluster_id"],
                    "cluster_color": cluster["color"],
                    "peer_count": cluster["device_count"] - 1,
                    "peer_macs": [m for m in cluster["device_macs"] if m != mac],
                }

        return None

    def get_all_device_colors(self) -> Dict[str, Dict]:
        """
        Get cluster colors for all devices (for bulk UI update).

        Returns:
            Dict mapping MAC -> {cluster_id, cluster_color, peer_count}
        """
        clusters = self.get_communication_clusters()
        result = {}

        for cluster in clusters:
            for mac in cluster["device_macs"]:
                result[mac] = {
                    "cluster_id": cluster["cluster_id"],
                    "cluster_color": cluster["color"],
                    "peer_count": cluster["device_count"] - 1,
                }

        return result

    def _get_cluster_color(self, cluster: Set[str]) -> str:
        """Get suggested color for a cluster based on dominant ecosystem."""
        eco_counts: Dict[EcosystemType, int] = defaultdict(int)
        for mac in cluster:
            device = self._devices.get(mac)
            if device:
                eco_counts[device.ecosystem] += 1

        if not eco_counts:
            return "#6B7280"

        dominant = max(eco_counts.keys(), key=lambda e: eco_counts[e])
        return ECOSYSTEM_COLORS.get(dominant, "#6B7280")

    def get_stats(self) -> Dict:
        """Get tracker statistics."""
        with self._lock:
            strong_edges = sum(
                1 for e in self._edges.values()
                if e.strength == CommunicationStrength.STRONG
            )
            moderate_edges = sum(
                1 for e in self._edges.values()
                if e.strength == CommunicationStrength.MODERATE
            )
            weak_edges = sum(
                1 for e in self._edges.values()
                if e.strength == CommunicationStrength.WEAK
            )

            return {
                "total_devices": len(self._devices),
                "total_edges": len(self._edges),
                "strong_edges": strong_edges,
                "moderate_edges": moderate_edges,
                "weak_edges": weak_edges,
                "total_connections": sum(e.connection_count for e in self._edges.values()),
            }

    # =========================================================================
    # PERSISTENCE
    # =========================================================================

    def save_state(self):
        """Save state to disk."""
        try:
            D2D_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

            state = {
                "devices": {mac: d.to_dict() for mac, d in self._devices.items()},
                "edges": {
                    f"{e.mac_a}|{e.mac_b}": e.to_dict() for e in self._edges.values()
                },
                "ip_to_mac": self._ip_to_mac,
                "saved_at": datetime.now().isoformat(),
            }

            with open(D2D_STATE_FILE, 'w') as f:
                json.dump(state, f, indent=2)

            logger.debug(f"Saved D2D state: {len(self._devices)} devices, {len(self._edges)} edges")
        except Exception as e:
            logger.error(f"Could not save D2D state: {e}")

    def _load_state(self):
        """Load state from disk."""
        try:
            if not D2D_STATE_FILE.exists():
                return

            with open(D2D_STATE_FILE) as f:
                state = json.load(f)

            # Restore devices
            for mac, data in state.get("devices", {}).items():
                device = Device(
                    mac=data["mac"],
                    ip=data.get("ip", ""),
                    ecosystem=EcosystemType(data.get("ecosystem", "unknown")),
                    hostname=data.get("hostname", ""),
                    services=set(data.get("services", [])),
                    first_seen=data.get("first_seen", datetime.now().isoformat()),
                    last_seen=data.get("last_seen", datetime.now().isoformat()),
                )
                self._devices[mac] = device

            # Restore edges
            for key, data in state.get("edges", {}).items():
                edge = CommunicationEdge(
                    mac_a=data["mac_a"],
                    mac_b=data["mac_b"],
                    connection_count=data.get("connection_count", 0),
                    bytes_transferred=data.get("bytes_transferred", 0),
                    services=set(data.get("services", [])),
                    first_seen=data.get("first_seen", datetime.now().isoformat()),
                    last_seen=data.get("last_seen", datetime.now().isoformat()),
                )
                self._edges[(edge.mac_a, edge.mac_b)] = edge

            # Restore IP mapping
            self._ip_to_mac = state.get("ip_to_mac", {})

            logger.info(f"Loaded D2D state: {len(self._devices)} devices, {len(self._edges)} edges")
        except Exception as e:
            logger.error(f"Could not load D2D state: {e}")


# Singleton instance
_tracker_instance: Optional[D2DTracker] = None
_tracker_lock = threading.Lock()


def get_d2d_tracker() -> D2DTracker:
    """Get singleton tracker instance."""
    global _tracker_instance

    with _tracker_lock:
        if _tracker_instance is None:
            _tracker_instance = D2DTracker()
        return _tracker_instance
