#!/usr/bin/env python3
"""
AIOCHI Affinity-Based Bubble Manager

Lightweight bubble manager that forms bubbles automatically from:
- mDNS discovery pairs (device A queried service advertised by device B)
- D2D connections (device A communicated with device B)
- Ecosystem detection (Apple, Google, Samsung devices)

This runs inside the aiochi-bubble container and exposes bubbles via REST API
for consumption by fts-web (device coloring).

Architecture:
    Zeek logs -> Event Detection -> Affinity Scoring -> Bubble Formation -> REST API
"""

import json
import logging
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Persistence path
BUBBLE_STATE_FILE = Path("/var/lib/aiochi/bubbles.json")

# Affinity thresholds
MIN_AFFINITY_FOR_BUBBLE = 0.3  # Minimum affinity to consider same bubble
BUBBLE_CONFIRMATION_THRESHOLD = 0.5  # Confidence to confirm bubble


class BubbleType(Enum):
    """Bubble types for network policy."""
    AUTO = "auto"  # Auto-detected
    FAMILY = "family"
    GUEST = "guest"
    IOT = "iot"
    WORK = "work"


class EcosystemType(Enum):
    """Device ecosystem types."""
    APPLE = "apple"
    GOOGLE = "google"
    SAMSUNG = "samsung"
    AMAZON = "amazon"
    MICROSOFT = "microsoft"
    UNKNOWN = "unknown"


# Colors for bubbles based on ecosystem
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
    services: Set[str] = field(default_factory=set)  # mDNS services advertised
    queries: Set[str] = field(default_factory=set)   # mDNS services queried
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    bubble_id: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "ecosystem": self.ecosystem.value,
            "hostname": self.hostname,
            "services": list(self.services),
            "queries": list(self.queries),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "bubble_id": self.bubble_id,
        }


@dataclass
class Bubble:
    """Device bubble (group of related devices)."""
    bubble_id: str
    name: str = ""
    ecosystem: EcosystemType = EcosystemType.UNKNOWN
    bubble_type: BubbleType = BubbleType.AUTO
    devices: Set[str] = field(default_factory=set)  # MAC addresses
    confidence: float = 0.0
    color: str = "#6B7280"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_activity: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return {
            "bubble_id": self.bubble_id,
            "name": self.name,
            "ecosystem": self.ecosystem.value,
            "bubble_type": self.bubble_type.value,
            "devices": list(self.devices),
            "device_count": len(self.devices),
            "confidence": self.confidence,
            "color": self.color,
            "created_at": self.created_at,
            "last_activity": self.last_activity,
        }


class AffinityBubbleManager:
    """
    Manages device bubbles based on affinity scoring.

    Affinity is calculated from:
    1. mDNS discovery pairs (device queried service that another advertises)
    2. D2D connections (direct communication between devices)
    3. Ecosystem matching (same vendor ecosystem)
    4. Temporal correlation (devices active at same times)
    """

    # Affinity weights
    MDNS_DISCOVERY_WEIGHT = 0.4   # mDNS query/response pairing
    D2D_CONNECTION_WEIGHT = 0.3  # Direct device communication
    ECOSYSTEM_WEIGHT = 0.2       # Same ecosystem bonus
    TEMPORAL_WEIGHT = 0.1        # Active at same time

    # Clustering parameters
    CLUSTERING_INTERVAL = 30     # Seconds between clustering runs
    MAX_BUBBLE_SIZE = 20         # Maximum devices per bubble

    def __init__(self):
        self._devices: Dict[str, Device] = {}         # MAC -> Device
        self._ip_to_mac: Dict[str, str] = {}          # IP -> MAC mapping
        self._bubbles: Dict[str, Bubble] = {}         # bubble_id -> Bubble

        # Affinity tracking
        self._mdns_discoveries: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # mac -> {service: count}

        self._mdns_advertisers: Dict[str, Set[str]] = defaultdict(set)
        # service -> set of MACs that advertise it

        self._d2d_connections: Dict[Tuple[str, str], int] = defaultdict(int)
        # (mac1, mac2) -> connection count

        self._affinity_cache: Dict[Tuple[str, str], float] = {}
        # (mac1, mac2) -> affinity score

        self._lock = threading.RLock()
        self._clustering_thread: Optional[threading.Thread] = None
        self._running = False

        # Load persisted state
        self._load_state()

    def start(self):
        """Start background clustering."""
        if self._running:
            return

        self._running = True
        self._clustering_thread = threading.Thread(
            target=self._clustering_loop,
            daemon=True,
            name="BubbleClustering"
        )
        self._clustering_thread.start()
        logger.info("Affinity bubble manager started")

    def stop(self):
        """Stop background clustering."""
        self._running = False
        if self._clustering_thread:
            self._clustering_thread.join(timeout=5)
        self._save_state()
        logger.info("Affinity bubble manager stopped")

    def _clustering_loop(self):
        """Background loop for periodic clustering."""
        while self._running:
            try:
                self._run_clustering()
            except Exception as e:
                logger.error(f"Clustering error: {e}")
            time.sleep(self.CLUSTERING_INTERVAL)

    # =========================================================================
    # EVENT RECORDING
    # =========================================================================

    def record_mdns_event(
        self,
        source_mac: str,
        source_ip: str,
        query: str,
        ecosystem: str,
        is_response: bool = False,
        hostname: str = ""
    ):
        """
        Record an mDNS event.

        Args:
            source_mac: Device MAC address
            source_ip: Device IP address
            query: mDNS query/service name
            ecosystem: Detected ecosystem (apple, google, etc.)
            is_response: True if this is a service advertisement
            hostname: Device hostname if available
        """
        source_mac = source_mac.upper()

        with self._lock:
            # Get or create device
            device = self._get_or_create_device(source_mac, source_ip)
            device.last_seen = datetime.now().isoformat()

            # Update ecosystem
            eco = self._parse_ecosystem(ecosystem)
            if eco != EcosystemType.UNKNOWN:
                device.ecosystem = eco

            if hostname:
                device.hostname = hostname

            if is_response:
                # Device is advertising this service
                device.services.add(query)
                self._mdns_advertisers[query].add(source_mac)
            else:
                # Device is querying for this service
                device.queries.add(query)
                self._mdns_discoveries[source_mac][query] += 1

            # Invalidate affinity cache for this device
            self._invalidate_affinity_cache(source_mac)

    def record_d2d_connection(self, src_ip: str, dst_ip: str, service: str = ""):
        """
        Record a device-to-device connection.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            service: Service/protocol name
        """
        with self._lock:
            src_mac = self._ip_to_mac.get(src_ip)
            dst_mac = self._ip_to_mac.get(dst_ip)

            if not src_mac or not dst_mac:
                return

            if src_mac == dst_mac:
                return

            # Normalize pair ordering for consistent keys
            pair = tuple(sorted([src_mac, dst_mac]))
            self._d2d_connections[pair] += 1

            # Update last seen
            if src_mac in self._devices:
                self._devices[src_mac].last_seen = datetime.now().isoformat()
            if dst_mac in self._devices:
                self._devices[dst_mac].last_seen = datetime.now().isoformat()

            # Invalidate affinity cache
            self._invalidate_affinity_cache(src_mac)
            self._invalidate_affinity_cache(dst_mac)

    def register_device(self, mac: str, ip: str, ecosystem: str = "", hostname: str = ""):
        """Register a device (e.g., from DHCP)."""
        mac = mac.upper()

        with self._lock:
            device = self._get_or_create_device(mac, ip)
            device.last_seen = datetime.now().isoformat()

            if ecosystem:
                eco = self._parse_ecosystem(ecosystem)
                if eco != EcosystemType.UNKNOWN:
                    device.ecosystem = eco

            if hostname:
                device.hostname = hostname

    # =========================================================================
    # AFFINITY CALCULATION
    # =========================================================================

    def get_affinity_score(self, mac1: str, mac2: str) -> float:
        """
        Calculate affinity score between two devices.

        Returns:
            Affinity score between 0.0 and 1.0
        """
        mac1 = mac1.upper()
        mac2 = mac2.upper()

        if mac1 == mac2:
            return 1.0

        # Normalize pair ordering
        pair = tuple(sorted([mac1, mac2]))

        with self._lock:
            # Check cache
            if pair in self._affinity_cache:
                return self._affinity_cache[pair]

            score = self._calculate_affinity(mac1, mac2)
            self._affinity_cache[pair] = score
            return score

    def _calculate_affinity(self, mac1: str, mac2: str) -> float:
        """Calculate raw affinity score."""
        device1 = self._devices.get(mac1)
        device2 = self._devices.get(mac2)

        if not device1 or not device2:
            return 0.0

        scores = []

        # 1. mDNS discovery affinity
        mdns_score = self._calculate_mdns_affinity(mac1, mac2)
        scores.append((mdns_score, self.MDNS_DISCOVERY_WEIGHT))

        # 2. D2D connection affinity
        d2d_score = self._calculate_d2d_affinity(mac1, mac2)
        scores.append((d2d_score, self.D2D_CONNECTION_WEIGHT))

        # 3. Ecosystem affinity
        eco_score = 1.0 if device1.ecosystem == device2.ecosystem and device1.ecosystem != EcosystemType.UNKNOWN else 0.0
        scores.append((eco_score, self.ECOSYSTEM_WEIGHT))

        # 4. Temporal affinity (both seen recently)
        temporal_score = self._calculate_temporal_affinity(device1, device2)
        scores.append((temporal_score, self.TEMPORAL_WEIGHT))

        # Weighted average
        total_weight = sum(w for _, w in scores)
        if total_weight == 0:
            return 0.0

        weighted_sum = sum(s * w for s, w in scores)
        return weighted_sum / total_weight

    def _calculate_mdns_affinity(self, mac1: str, mac2: str) -> float:
        """
        Calculate mDNS-based affinity.

        High affinity if:
        - Device 1 queries services that device 2 advertises (or vice versa)
        """
        queries1 = self._mdns_discoveries.get(mac1, {})
        queries2 = self._mdns_discoveries.get(mac2, {})

        # Services advertised by each device
        services1 = self._devices.get(mac1, Device(mac=mac1)).services
        services2 = self._devices.get(mac2, Device(mac=mac2)).services

        # Check if device1 queried services that device2 advertises
        hits = 0
        total = 0

        for service, count in queries1.items():
            total += count
            if service in services2:
                hits += count

        for service, count in queries2.items():
            total += count
            if service in services1:
                hits += count

        if total == 0:
            return 0.0

        return min(1.0, hits / max(1, total) * 2)  # Scale up, cap at 1.0

    def _calculate_d2d_affinity(self, mac1: str, mac2: str) -> float:
        """Calculate D2D connection-based affinity."""
        pair = tuple(sorted([mac1, mac2]))
        conn_count = self._d2d_connections.get(pair, 0)

        if conn_count == 0:
            return 0.0

        # Logarithmic scaling: 1 conn = 0.3, 10 conn = 0.6, 100 conn = 0.9
        import math
        return min(1.0, 0.3 * math.log10(conn_count + 1) + 0.3)

    def _calculate_temporal_affinity(self, device1: Device, device2: Device) -> float:
        """Calculate temporal affinity (both active recently)."""
        try:
            last1 = datetime.fromisoformat(device1.last_seen)
            last2 = datetime.fromisoformat(device2.last_seen)

            now = datetime.now()
            age1 = (now - last1).total_seconds()
            age2 = (now - last2).total_seconds()

            # Both seen in last 5 minutes = high temporal affinity
            if age1 < 300 and age2 < 300:
                return 1.0
            elif age1 < 3600 and age2 < 3600:
                return 0.5
            else:
                return 0.0
        except Exception:
            return 0.0

    def _invalidate_affinity_cache(self, mac: str):
        """Invalidate cached affinity scores involving this MAC."""
        to_remove = [pair for pair in self._affinity_cache if mac in pair]
        for pair in to_remove:
            del self._affinity_cache[pair]

    # =========================================================================
    # CLUSTERING
    # =========================================================================

    def _run_clustering(self):
        """Run clustering algorithm to form bubbles."""
        with self._lock:
            if len(self._devices) < 2:
                return

            # Build affinity matrix
            macs = list(self._devices.keys())
            n = len(macs)

            # Find high-affinity pairs
            clusters: List[Set[str]] = []
            clustered: Set[str] = set()

            for i in range(n):
                if macs[i] in clustered:
                    continue

                # Start new cluster with this device
                cluster = {macs[i]}

                for j in range(i + 1, n):
                    if macs[j] in clustered:
                        continue

                    affinity = self.get_affinity_score(macs[i], macs[j])

                    if affinity >= MIN_AFFINITY_FOR_BUBBLE:
                        # Check affinity with existing cluster members
                        avg_affinity = sum(
                            self.get_affinity_score(macs[j], m) for m in cluster
                        ) / len(cluster)

                        if avg_affinity >= MIN_AFFINITY_FOR_BUBBLE:
                            cluster.add(macs[j])

                            if len(cluster) >= self.MAX_BUBBLE_SIZE:
                                break

                if len(cluster) >= 2:
                    clusters.append(cluster)
                    clustered.update(cluster)

            # Update bubbles
            self._update_bubbles_from_clusters(clusters)

    def _update_bubbles_from_clusters(self, clusters: List[Set[str]]):
        """Update bubble assignments from clustering results."""
        # Track which devices are in new clusters
        newly_clustered: Set[str] = set()

        for cluster in clusters:
            if len(cluster) < 2:
                continue

            # Find dominant ecosystem
            eco_counts: Dict[EcosystemType, int] = defaultdict(int)
            for mac in cluster:
                device = self._devices.get(mac)
                if device:
                    eco_counts[device.ecosystem] += 1

            dominant_eco = max(eco_counts.keys(), key=lambda e: eco_counts[e])

            # Calculate cluster confidence
            confidence = self._calculate_cluster_confidence(cluster)

            # Check if cluster matches existing bubble
            existing_bubble = self._find_matching_bubble(cluster)

            if existing_bubble:
                # Update existing bubble
                existing_bubble.devices = cluster
                existing_bubble.confidence = confidence
                existing_bubble.ecosystem = dominant_eco
                existing_bubble.color = ECOSYSTEM_COLORS.get(dominant_eco, "#6B7280")
                existing_bubble.last_activity = datetime.now().isoformat()

                bubble = existing_bubble
            else:
                # Create new bubble
                bubble_id = f"auto-{uuid.uuid4().hex[:8]}"
                bubble = Bubble(
                    bubble_id=bubble_id,
                    name=self._generate_bubble_name(cluster, dominant_eco),
                    ecosystem=dominant_eco,
                    devices=cluster,
                    confidence=confidence,
                    color=ECOSYSTEM_COLORS.get(dominant_eco, "#6B7280"),
                )
                self._bubbles[bubble_id] = bubble
                logger.info(f"Created bubble: {bubble.name} with {len(cluster)} devices")

            # Update device assignments
            for mac in cluster:
                if mac in self._devices:
                    self._devices[mac].bubble_id = bubble.bubble_id

            newly_clustered.update(cluster)

        # Remove devices from bubbles if they're no longer clustered
        for bubble in list(self._bubbles.values()):
            orphaned = bubble.devices - newly_clustered
            for mac in orphaned:
                if mac in self._devices:
                    self._devices[mac].bubble_id = None
            bubble.devices -= orphaned

            # Remove empty bubbles
            if len(bubble.devices) < 2:
                del self._bubbles[bubble.bubble_id]
                logger.info(f"Dissolved bubble: {bubble.name}")

        # Save state
        self._save_state()

    def _calculate_cluster_confidence(self, cluster: Set[str]) -> float:
        """Calculate confidence score for a cluster."""
        if len(cluster) < 2:
            return 0.0

        # Average pairwise affinity
        total_affinity = 0.0
        pairs = 0

        macs = list(cluster)
        for i in range(len(macs)):
            for j in range(i + 1, len(macs)):
                total_affinity += self.get_affinity_score(macs[i], macs[j])
                pairs += 1

        if pairs == 0:
            return 0.0

        return total_affinity / pairs

    def _find_matching_bubble(self, cluster: Set[str]) -> Optional[Bubble]:
        """Find existing bubble that matches this cluster."""
        for bubble in self._bubbles.values():
            # If >50% of devices overlap, consider it a match
            overlap = len(cluster & bubble.devices)
            if overlap > len(cluster) * 0.5 or overlap > len(bubble.devices) * 0.5:
                return bubble
        return None

    def _generate_bubble_name(self, cluster: Set[str], ecosystem: EcosystemType) -> str:
        """Generate a name for a bubble."""
        # Try to extract owner from hostnames
        for mac in cluster:
            device = self._devices.get(mac)
            if device and device.hostname:
                import re
                match = re.search(r"^(\w+)'s", device.hostname, re.IGNORECASE)
                if match:
                    return f"{match.group(1)}'s Devices"

        # Fallback to ecosystem name
        return f"{ecosystem.value.title()} Devices"

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

    def get_all_bubbles(self) -> List[Bubble]:
        """Get all active bubbles."""
        with self._lock:
            return [b for b in self._bubbles.values() if len(b.devices) >= 2]

    def get_bubble(self, bubble_id: str) -> Optional[Bubble]:
        """Get bubble by ID."""
        with self._lock:
            return self._bubbles.get(bubble_id)

    def get_all_devices(self) -> List[Device]:
        """Get all tracked devices."""
        with self._lock:
            return list(self._devices.values())

    def get_device(self, mac: str) -> Optional[Device]:
        """Get device by MAC."""
        mac = mac.upper()
        with self._lock:
            return self._devices.get(mac)

    def get_device_bubble(self, mac: str) -> Optional[Bubble]:
        """Get the bubble containing a device."""
        mac = mac.upper()
        with self._lock:
            device = self._devices.get(mac)
            if device and device.bubble_id:
                return self._bubbles.get(device.bubble_id)
            return None

    def move_device(self, mac: str, bubble_id: str) -> bool:
        """Move a device to a different bubble (manual override)."""
        mac = mac.upper()

        with self._lock:
            if bubble_id not in self._bubbles:
                return False

            device = self._devices.get(mac)
            if not device:
                return False

            # Remove from old bubble
            if device.bubble_id and device.bubble_id in self._bubbles:
                self._bubbles[device.bubble_id].devices.discard(mac)

            # Add to new bubble
            device.bubble_id = bubble_id
            self._bubbles[bubble_id].devices.add(mac)
            self._bubbles[bubble_id].last_activity = datetime.now().isoformat()

            self._save_state()
            return True

    def get_stats(self) -> Dict:
        """Get manager statistics."""
        with self._lock:
            return {
                "total_devices": len(self._devices),
                "total_bubbles": len(self._bubbles),
                "devices_in_bubbles": sum(len(b.devices) for b in self._bubbles.values()),
                "total_d2d_connections": sum(self._d2d_connections.values()),
                "total_mdns_discoveries": sum(
                    sum(q.values()) for q in self._mdns_discoveries.values()
                ),
            }

    # =========================================================================
    # PERSISTENCE
    # =========================================================================

    def _save_state(self):
        """Save state to disk."""
        try:
            BUBBLE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

            state = {
                "devices": {mac: d.to_dict() for mac, d in self._devices.items()},
                "bubbles": {bid: b.to_dict() for bid, b in self._bubbles.items()},
                "d2d_connections": {
                    f"{m1}|{m2}": count
                    for (m1, m2), count in self._d2d_connections.items()
                },
                "mdns_discoveries": {
                    mac: dict(queries) for mac, queries in self._mdns_discoveries.items()
                },
                "mdns_advertisers": {
                    service: list(macs) for service, macs in self._mdns_advertisers.items()
                },
                "saved_at": datetime.now().isoformat(),
            }

            with open(BUBBLE_STATE_FILE, 'w') as f:
                json.dump(state, f, indent=2)

            logger.debug(f"Saved state: {len(self._devices)} devices, {len(self._bubbles)} bubbles")
        except Exception as e:
            logger.error(f"Could not save state: {e}")

    def _load_state(self):
        """Load state from disk."""
        try:
            if not BUBBLE_STATE_FILE.exists():
                return

            with open(BUBBLE_STATE_FILE) as f:
                state = json.load(f)

            # Restore devices
            for mac, data in state.get("devices", {}).items():
                device = Device(
                    mac=data["mac"],
                    ip=data.get("ip", ""),
                    ecosystem=EcosystemType(data.get("ecosystem", "unknown")),
                    hostname=data.get("hostname", ""),
                    services=set(data.get("services", [])),
                    queries=set(data.get("queries", [])),
                    first_seen=data.get("first_seen", datetime.now().isoformat()),
                    last_seen=data.get("last_seen", datetime.now().isoformat()),
                    bubble_id=data.get("bubble_id"),
                )
                self._devices[mac] = device
                if device.ip:
                    self._ip_to_mac[device.ip] = mac

            # Restore bubbles
            for bid, data in state.get("bubbles", {}).items():
                bubble = Bubble(
                    bubble_id=data["bubble_id"],
                    name=data.get("name", ""),
                    ecosystem=EcosystemType(data.get("ecosystem", "unknown")),
                    bubble_type=BubbleType(data.get("bubble_type", "auto")),
                    devices=set(data.get("devices", [])),
                    confidence=data.get("confidence", 0.0),
                    color=data.get("color", "#6B7280"),
                    created_at=data.get("created_at", datetime.now().isoformat()),
                    last_activity=data.get("last_activity", datetime.now().isoformat()),
                )
                self._bubbles[bid] = bubble

            # Restore D2D connections
            for pair_str, count in state.get("d2d_connections", {}).items():
                parts = pair_str.split("|")
                if len(parts) == 2:
                    self._d2d_connections[(parts[0], parts[1])] = count

            # Restore mDNS discoveries
            for mac, queries in state.get("mdns_discoveries", {}).items():
                self._mdns_discoveries[mac] = defaultdict(int, queries)

            # Restore mDNS advertisers
            for service, macs in state.get("mdns_advertisers", {}).items():
                self._mdns_advertisers[service] = set(macs)

            logger.info(f"Loaded state: {len(self._devices)} devices, {len(self._bubbles)} bubbles")
        except Exception as e:
            logger.error(f"Could not load state: {e}")


# Singleton instance
_manager_instance: Optional[AffinityBubbleManager] = None
_manager_lock = threading.Lock()


def get_affinity_bubble_manager() -> AffinityBubbleManager:
    """Get singleton manager instance."""
    global _manager_instance

    with _manager_lock:
        if _manager_instance is None:
            _manager_instance = AffinityBubbleManager()
        return _manager_instance
