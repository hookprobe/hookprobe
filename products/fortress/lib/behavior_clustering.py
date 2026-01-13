#!/usr/bin/env python3
"""
Behavioral Clustering Engine - Proprietary HookProbe Technology

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module implements unsupervised learning to cluster devices into
"user bubbles" based on their behavioral patterns.

The Innovation:
Devices under the same account "breathe" together - they sync, handoff,
and move in correlated patterns. We use DBSCAN clustering to detect
these relationships WITHOUT needing credentials.

Features Used for Clustering:
1. Time Correlation (0-1) - Do devices join/leave together?
2. Proximity Score (0-1) - Are devices physically close?
3. Protocol Overlap (0-1) - Do they share similar services?
4. Sync Frequency - How often do they sync?
5. Handoff Count - How many handoffs observed?
6. Ecosystem Match - Are they from the same vendor?
7. mDNS Device ID similarity - Do IDs suggest same owner?
8. AP Correlation - Do they connect to same access points?

Output:
Devices clustered into "bubbles" representing same-user groupings.
"""

import hashlib
import json
import logging
import sqlite3
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import re

logger = logging.getLogger(__name__)

# Optional ML dependencies
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import silhouette_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Optional Leiden clustering (better than DBSCAN for community detection)
try:
    import leidenalg
    import igraph
    HAS_LEIDEN = True
except ImportError:
    HAS_LEIDEN = False

# Import D2D connection graph for affinity scoring
try:
    from .connection_graph import (
        get_connection_analyzer,
        DeviceType,
        classify_device_type,
        get_user_bubble_color,
        USER_BUBBLE_COLORS,
    )
    HAS_D2D = True
except ImportError:
    HAS_D2D = False
    DeviceType = None

# Database
CLUSTERING_DB = Path('/var/lib/hookprobe/clustering.db')


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class DeviceBehavior:
    """Behavioral features for a single device."""
    mac: str
    ecosystem: str = 'unknown'

    # Temporal features
    time_correlation: float = 0.0      # Correlation with other devices
    session_regularity: float = 0.0    # How regular are sessions
    active_hours: List[int] = field(default_factory=list)  # Peak hours

    # Proximity features
    proximity_score: float = 0.0       # Physical proximity to others
    ap_affinity: Dict[str, float] = field(default_factory=dict)  # AP → frequency

    # Sync features
    sync_frequency: float = 0.0        # Syncs per hour
    handoff_count: int = 0             # Total handoffs observed
    continuity_events: int = 0         # Continuity protocol events

    # Protocol features
    protocol_overlap: float = 0.0      # Service overlap with others
    mdns_services: List[str] = field(default_factory=list)

    # Identity features
    mdns_device_id: Optional[str] = None
    hostname_pattern: Optional[str] = None

    # D2D Affinity features (from Zeek connection graph)
    d2d_affinity_score: float = 0.0    # Overall D2D affinity with peers
    d2d_peer_count: int = 0            # Number of D2D communication peers
    d2d_frequency: float = 0.0         # Normalized connection frequency
    d2d_symmetry: float = 0.0          # Bidirectional traffic ratio

    # Device classification (IoT vs Personal)
    device_type: str = 'unknown'       # 'personal', 'iot', 'infra', 'unknown'
    device_type_confidence: float = 0.0

    # Bubble assignment
    bubble_color: Optional[str] = None
    suggested_bubble_id: Optional[str] = None

    def to_feature_vector(self) -> List[float]:
        """Convert to feature vector for clustering."""
        return [
            self.time_correlation,
            self.proximity_score,
            self.protocol_overlap,
            min(self.sync_frequency / 100, 1.0),  # Normalize
            min(self.handoff_count / 50, 1.0),    # Normalize
            min(self.continuity_events / 20, 1.0),  # Normalize
            self.session_regularity,
            len(self.mdns_services) / 10,         # Normalize
            # D2D features (from Trio+ recommendation)
            self.d2d_affinity_score,              # 0-1 already normalized
            min(self.d2d_peer_count / 5, 1.0),    # Normalize (5+ peers = 1.0)
            self.d2d_frequency,                    # 0-1 already normalized
            self.d2d_symmetry,                     # 0-1 already normalized
        ]

    def is_personal_device(self) -> bool:
        """Check if this is a personal device (not IoT)."""
        return self.device_type == 'personal'

    def should_suggest_bubble(self) -> bool:
        """Check if this device should get bubble suggestions."""
        # Only suggest bubbles for personal devices with D2D activity
        return (
            self.device_type == 'personal' and
            self.d2d_affinity_score >= 0.3 and
            self.d2d_peer_count >= 1
        )


@dataclass
class ClusterResult:
    """Result of clustering analysis."""
    cluster_id: int
    devices: List[str]  # MAC addresses
    ecosystem: str
    confidence: float
    centroid: List[float] = field(default_factory=list)
    silhouette: float = 0.0
    bubble_id: Optional[str] = None

    # D2D enhanced fields
    bubble_type: str = 'user'          # 'user', 'iot', 'mixed'
    bubble_color: Optional[str] = None  # Hex color for visualization
    avg_d2d_affinity: float = 0.0       # Average D2D affinity in cluster
    personal_device_count: int = 0       # Count of personal devices
    iot_device_count: int = 0            # Count of IoT devices

    def to_dict(self) -> Dict:
        return {
            'cluster_id': self.cluster_id,
            'devices': self.devices,
            'ecosystem': self.ecosystem,
            'confidence': self.confidence,
            'bubble_id': self.bubble_id,
            'device_count': len(self.devices),
            # D2D enhanced fields
            'bubble_type': self.bubble_type,
            'bubble_color': self.bubble_color,
            'avg_d2d_affinity': round(self.avg_d2d_affinity, 3),
            'personal_device_count': self.personal_device_count,
            'iot_device_count': self.iot_device_count,
        }


# =============================================================================
# BEHAVIORAL CLUSTERING ENGINE
# =============================================================================

class BehavioralClusteringEngine:
    """
    DBSCAN/Leiden-based clustering engine for ecosystem bubble detection.

    Uses unsupervised learning to group devices that "breathe together"
    into the same user bubble.

    Enhanced with D2D affinity scoring from Zeek connection graph.
    """

    # DBSCAN parameters (tuned for device clustering)
    DBSCAN_EPS = 0.5          # Maximum distance between samples
    DBSCAN_MIN_SAMPLES = 2    # Minimum cluster size (2 = pair of devices)

    # Leiden parameters (for community detection)
    LEIDEN_RESOLUTION = 0.8   # Higher = more, smaller clusters

    # Confidence thresholds
    HIGH_CONFIDENCE = 0.85
    MEDIUM_CONFIDENCE = 0.65
    LOW_CONFIDENCE = 0.45

    # D2D affinity threshold for bubble suggestion
    D2D_SUGGESTION_THRESHOLD = 0.4

    def __init__(self, use_leiden: bool = False):
        """
        Initialize clustering engine.

        Args:
            use_leiden: If True and available, use Leiden algorithm instead of DBSCAN
        """
        self._behaviors: Dict[str, DeviceBehavior] = {}
        self._clusters: Dict[int, ClusterResult] = {}
        self._lock = threading.RLock()
        self._use_leiden = use_leiden and HAS_LEIDEN
        self._bubble_color_assignments: Dict[str, str] = {}  # bubble_id -> color

        # Initialize database
        self._init_database()

    def _init_database(self):
        """Initialize clustering database."""
        try:
            CLUSTERING_DB.parent.mkdir(parents=True, exist_ok=True)

            with sqlite3.connect(str(CLUSTERING_DB)) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS device_behaviors (
                        mac TEXT PRIMARY KEY,
                        ecosystem TEXT,
                        time_correlation REAL,
                        proximity_score REAL,
                        protocol_overlap REAL,
                        sync_frequency REAL,
                        handoff_count INTEGER,
                        continuity_events INTEGER,
                        session_regularity REAL,
                        mdns_services_json TEXT,
                        mdns_device_id TEXT,
                        hostname_pattern TEXT,
                        cluster_id INTEGER,
                        bubble_id TEXT,
                        updated_at TEXT
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS cluster_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cluster_id INTEGER,
                        devices_json TEXT,
                        ecosystem TEXT,
                        confidence REAL,
                        bubble_id TEXT,
                        created_at TEXT
                    )
                ''')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_behavior_mac ON device_behaviors(mac)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_behavior_cluster ON device_behaviors(cluster_id)')
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize clustering database: {e}")

    # =========================================================================
    # FEATURE EXTRACTION
    # =========================================================================

    def update_behavior(self, mac: str, **updates):
        """Update behavioral features for a device."""
        with self._lock:
            mac = mac.upper()

            if mac not in self._behaviors:
                self._behaviors[mac] = DeviceBehavior(mac=mac)

            behavior = self._behaviors[mac]

            for key, value in updates.items():
                if hasattr(behavior, key):
                    setattr(behavior, key, value)

    def enrich_with_d2d(self):
        """
        Enrich device behaviors with D2D affinity data from connection graph.

        This is the key integration point between behavioral clustering
        and D2D network analysis (Zeek conn.log).
        """
        if not HAS_D2D:
            logger.debug("D2D module not available, skipping enrichment")
            return

        with self._lock:
            try:
                analyzer = get_connection_analyzer()

                # Get all device MACs from behaviors
                for mac, behavior in self._behaviors.items():
                    # Get D2D peers for this device
                    peers = analyzer.get_device_peers(mac)

                    if peers:
                        # Calculate aggregate D2D metrics
                        total_affinity = sum(aff for _, aff in peers)
                        avg_affinity = total_affinity / len(peers) if peers else 0.0

                        behavior.d2d_peer_count = len(peers)
                        behavior.d2d_affinity_score = avg_affinity

                        # Get detailed metrics from relationships
                        for key, rel in analyzer.relationships.items():
                            if mac in key:
                                metrics = rel.get_normalized_metrics()
                                # Take the max of each metric across all relationships
                                behavior.d2d_frequency = max(
                                    behavior.d2d_frequency,
                                    metrics.frequency
                                )
                                behavior.d2d_symmetry = max(
                                    behavior.d2d_symmetry,
                                    metrics.symmetry
                                )

                    # Classify device type (Personal vs IoT)
                    device_type, confidence = analyzer.classify_device(mac)
                    behavior.device_type = device_type.value
                    behavior.device_type_confidence = confidence

                logger.info(f"Enriched {len(self._behaviors)} devices with D2D data")

            except Exception as e:
                logger.warning(f"Failed to enrich with D2D data: {e}")

    def get_bubble_suggestions(self) -> List[Dict]:
        """
        Get bubble suggestions based on D2D affinity.

        Returns list of device pairs that should be grouped together.
        """
        if not HAS_D2D:
            return []

        try:
            analyzer = get_connection_analyzer()
            return analyzer.get_bubble_suggestions(
                min_affinity=self.D2D_SUGGESTION_THRESHOLD
            )
        except Exception as e:
            logger.warning(f"Failed to get bubble suggestions: {e}")
            return []

    def assign_bubble_color(self, bubble_id: str) -> str:
        """
        Assign a unique color to a bubble.

        Uses rotating palette from USER_BUBBLE_COLORS.
        """
        if bubble_id in self._bubble_color_assignments:
            return self._bubble_color_assignments[bubble_id]

        if HAS_D2D:
            color_idx = len(self._bubble_color_assignments)
            color = get_user_bubble_color(color_idx)
        else:
            # Fallback colors
            fallback_colors = [
                "#E91E63", "#3F51B5", "#009688", "#FF5722",
                "#673AB7", "#00BCD4", "#795548", "#607D8B"
            ]
            color_idx = len(self._bubble_color_assignments) % len(fallback_colors)
            color = fallback_colors[color_idx]

        self._bubble_color_assignments[bubble_id] = color
        return color

    def compute_protocol_overlap(self, mac_a: str, mac_b: str) -> float:
        """Compute protocol/service overlap between two devices."""
        with self._lock:
            ba = self._behaviors.get(mac_a.upper())
            bb = self._behaviors.get(mac_b.upper())

            if not ba or not bb:
                return 0.0

            services_a = set(ba.mdns_services)
            services_b = set(bb.mdns_services)

            if not services_a or not services_b:
                return 0.0

            intersection = len(services_a & services_b)
            union = len(services_a | services_b)

            return intersection / union if union > 0 else 0.0

    def compute_id_similarity(self, mac_a: str, mac_b: str) -> float:
        """Compute device ID similarity (suggests same owner)."""
        with self._lock:
            ba = self._behaviors.get(mac_a.upper())
            bb = self._behaviors.get(mac_b.upper())

            if not ba or not bb:
                return 0.0

            # Check mDNS device IDs
            if ba.mdns_device_id and bb.mdns_device_id:
                # Apple device IDs often share prefixes for same-account devices
                id_a = ba.mdns_device_id
                id_b = bb.mdns_device_id

                # Check for common prefix (first 8 chars)
                if len(id_a) >= 8 and len(id_b) >= 8:
                    if id_a[:8] == id_b[:8]:
                        return 0.8

                # Check for sequential patterns
                if self._are_sequential_ids(id_a, id_b):
                    return 0.7

            # Check hostname patterns
            if ba.hostname_pattern and bb.hostname_pattern:
                # Extract owner name from hostname
                owner_a = self._extract_owner(ba.hostname_pattern)
                owner_b = self._extract_owner(bb.hostname_pattern)

                if owner_a and owner_b and owner_a.lower() == owner_b.lower():
                    return 0.9

            return 0.0

    def _are_sequential_ids(self, id_a: str, id_b: str) -> bool:
        """Check if two IDs appear sequential (same owner)."""
        # Look for numeric suffixes that differ by 1
        match_a = re.search(r'(\d+)$', id_a)
        match_b = re.search(r'(\d+)$', id_b)

        if match_a and match_b:
            num_a = int(match_a.group(1))
            num_b = int(match_b.group(1))

            # Check if sequential
            if abs(num_a - num_b) <= 2:
                # Check if prefix matches
                prefix_a = id_a[:match_a.start()]
                prefix_b = id_b[:match_b.start()]
                if prefix_a == prefix_b:
                    return True

        return False

    def _extract_owner(self, hostname: str) -> Optional[str]:
        """Extract owner name from hostname."""
        if not hostname:
            return None

        hostname = hostname.lower()

        # Common patterns: "John's iPhone", "MacBook-Pro-John", "John-iPad"
        patterns = [
            r"^([a-z]+)'s",           # John's iPhone
            r"^([a-z]+)-s-",          # johns-macbook
            r"-([a-z]+)$",            # MacBook-John
            r"^([a-z]+)-",            # John-iPhone
        ]

        for pattern in patterns:
            match = re.search(pattern, hostname)
            if match:
                name = match.group(1)
                # Filter out device types
                if name not in ['iphone', 'ipad', 'macbook', 'mac', 'pro', 'air', 'mini']:
                    return name

        return None

    def compute_ap_correlation(self, mac_a: str, mac_b: str) -> float:
        """Compute access point usage correlation."""
        with self._lock:
            ba = self._behaviors.get(mac_a.upper())
            bb = self._behaviors.get(mac_b.upper())

            if not ba or not bb:
                return 0.0

            if not ba.ap_affinity or not bb.ap_affinity:
                return 0.0

            # Jaccard similarity of AP sets
            aps_a = set(ba.ap_affinity.keys())
            aps_b = set(bb.ap_affinity.keys())

            if not aps_a or not aps_b:
                return 0.0

            intersection = len(aps_a & aps_b)
            union = len(aps_a | aps_b)

            return intersection / union if union > 0 else 0.0

    # =========================================================================
    # CLUSTERING
    # =========================================================================

    def build_feature_matrix(self) -> Tuple[List[str], Optional[Any]]:
        """Build feature matrix for all devices."""
        with self._lock:
            if not HAS_NUMPY or not HAS_SKLEARN:
                logger.warning("NumPy/sklearn not available for clustering")
                return [], None

            macs = list(self._behaviors.keys())
            if len(macs) < 2:
                return macs, None

            # Build pairwise similarity matrix
            n = len(macs)
            features = []

            for i, mac in enumerate(macs):
                behavior = self._behaviors[mac]

                # Base features
                base_features = behavior.to_feature_vector()

                # Add pairwise features (averaged over all other devices)
                protocol_overlaps = []
                id_similarities = []
                ap_correlations = []

                for j, other_mac in enumerate(macs):
                    if i != j:
                        protocol_overlaps.append(
                            self.compute_protocol_overlap(mac, other_mac)
                        )
                        id_similarities.append(
                            self.compute_id_similarity(mac, other_mac)
                        )
                        ap_correlations.append(
                            self.compute_ap_correlation(mac, other_mac)
                        )

                # Average pairwise features
                avg_protocol = np.mean(protocol_overlaps) if protocol_overlaps else 0
                avg_id_sim = np.mean(id_similarities) if id_similarities else 0
                avg_ap_corr = np.mean(ap_correlations) if ap_correlations else 0

                # Combine features
                full_features = base_features + [avg_protocol, avg_id_sim, avg_ap_corr]
                features.append(full_features)

            X = np.array(features)

            # Standardize features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            return macs, X_scaled

    def cluster_devices(self) -> List[ClusterResult]:
        """
        Run clustering on all devices using DBSCAN or Leiden algorithm.

        Enhanced with D2D affinity enrichment and device type classification.
        """
        with self._lock:
            # First, enrich behaviors with D2D data
            self.enrich_with_d2d()

            if not HAS_NUMPY or not HAS_SKLEARN:
                logger.warning("ML libraries not available for clustering")
                return self._rule_based_clustering()

            macs, X = self.build_feature_matrix()

            if X is None or len(macs) < 2:
                return []

            # Choose clustering algorithm
            if self._use_leiden and HAS_LEIDEN:
                labels = self._leiden_cluster(macs)
            else:
                # Run DBSCAN
                dbscan = DBSCAN(
                    eps=self.DBSCAN_EPS,
                    min_samples=self.DBSCAN_MIN_SAMPLES,
                    metric='euclidean'
                )
                labels = dbscan.fit_predict(X)

            # Build cluster results
            clusters: Dict[int, List[str]] = defaultdict(list)
            for mac, label in zip(macs, labels):
                if label >= 0:  # -1 is noise
                    clusters[label].append(mac)

            results = []

            for cluster_id, devices in clusters.items():
                if len(devices) >= 2:
                    # Determine ecosystem
                    ecosystems = [
                        self._behaviors[m].ecosystem
                        for m in devices
                    ]
                    ecosystem = max(set(ecosystems), key=ecosystems.count)

                    # Calculate confidence
                    confidence = self._calculate_cluster_confidence(devices, X, macs, labels)

                    # Generate bubble ID
                    bubble_id = self._generate_bubble_id(devices, ecosystem)

                    # Assign bubble color
                    bubble_color = self.assign_bubble_color(bubble_id)

                    # Calculate D2D metrics and device type breakdown
                    personal_count = 0
                    iot_count = 0
                    d2d_affinities = []

                    for mac in devices:
                        behavior = self._behaviors.get(mac)
                        if behavior:
                            if behavior.device_type == 'personal':
                                personal_count += 1
                            elif behavior.device_type == 'iot':
                                iot_count += 1
                            if behavior.d2d_affinity_score > 0:
                                d2d_affinities.append(behavior.d2d_affinity_score)
                            # Update device with bubble color
                            behavior.bubble_color = bubble_color
                            behavior.suggested_bubble_id = bubble_id

                    avg_d2d = sum(d2d_affinities) / len(d2d_affinities) if d2d_affinities else 0.0

                    # Determine bubble type based on device composition
                    if iot_count == 0 and personal_count > 0:
                        bubble_type = 'user'
                    elif personal_count == 0 and iot_count > 0:
                        bubble_type = 'iot'
                    else:
                        bubble_type = 'mixed'

                    result = ClusterResult(
                        cluster_id=cluster_id,
                        devices=devices,
                        ecosystem=ecosystem,
                        confidence=confidence,
                        bubble_id=bubble_id,
                        bubble_type=bubble_type,
                        bubble_color=bubble_color,
                        avg_d2d_affinity=avg_d2d,
                        personal_device_count=personal_count,
                        iot_device_count=iot_count,
                    )

                    # Calculate silhouette if enough clusters
                    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
                    if n_clusters >= 2:
                        try:
                            result.silhouette = silhouette_score(X, labels)
                        except Exception:
                            pass

                    results.append(result)

                    # Update device behaviors with cluster assignment
                    for mac in devices:
                        if hasattr(self._behaviors[mac], 'cluster_id'):
                            self._behaviors[mac].cluster_id = cluster_id

            self._clusters = {r.cluster_id: r for r in results}

            # Persist results
            self._persist_clusters(results)

            return results

    def _leiden_cluster(self, macs: List[str]) -> List[int]:
        """
        Run Leiden community detection algorithm.

        Leiden is better than DBSCAN for community detection in graphs
        because it optimizes modularity directly.

        Args:
            macs: List of MAC addresses

        Returns:
            List of cluster labels (same order as macs)
        """
        if not HAS_LEIDEN or not HAS_D2D:
            return [-1] * len(macs)

        try:
            analyzer = get_connection_analyzer()

            # Build adjacency graph from D2D relationships
            mac_to_idx = {mac: i for i, mac in enumerate(macs)}
            edges = []
            weights = []

            for key, rel in analyzer.relationships.items():
                mac_a, mac_b = key
                if mac_a in mac_to_idx and mac_b in mac_to_idx:
                    affinity = rel.calculate_affinity_score()
                    if affinity >= self.D2D_SUGGESTION_THRESHOLD:
                        edges.append((mac_to_idx[mac_a], mac_to_idx[mac_b]))
                        weights.append(affinity)

            if not edges:
                return [-1] * len(macs)

            # Create igraph graph
            g = igraph.Graph(n=len(macs), edges=edges)

            # Run Leiden algorithm
            partition = leidenalg.find_partition(
                g,
                leidenalg.RBConfigurationVertexPartition,
                resolution_parameter=self.LEIDEN_RESOLUTION,
                weights=weights,
            )

            # Convert partition to labels
            labels = [-1] * len(macs)
            for cluster_id, members in enumerate(partition):
                for node_idx in members:
                    labels[node_idx] = cluster_id

            logger.info(f"Leiden found {len(partition)} communities")
            return labels

        except Exception as e:
            logger.warning(f"Leiden clustering failed: {e}")
            return [-1] * len(macs)

    def _rule_based_clustering(self) -> List[ClusterResult]:
        """Fallback rule-based clustering when ML is not available."""
        with self._lock:
            # Group by ecosystem first
            ecosystems: Dict[str, List[str]] = defaultdict(list)
            for mac, behavior in self._behaviors.items():
                ecosystems[behavior.ecosystem].append(mac)

            results = []
            cluster_id = 0

            for ecosystem, macs in ecosystems.items():
                if len(macs) < 2:
                    continue

                # Within ecosystem, cluster by high correlation
                used = set()
                for i, mac_a in enumerate(macs):
                    if mac_a in used:
                        continue

                    cluster_devices = [mac_a]
                    used.add(mac_a)

                    for mac_b in macs[i+1:]:
                        if mac_b in used:
                            continue

                        # Check if they belong together
                        id_sim = self.compute_id_similarity(mac_a, mac_b)
                        protocol_sim = self.compute_protocol_overlap(mac_a, mac_b)

                        if id_sim > 0.6 or protocol_sim > 0.5:
                            cluster_devices.append(mac_b)
                            used.add(mac_b)

                    if len(cluster_devices) >= 2:
                        bubble_id = self._generate_bubble_id(cluster_devices, ecosystem)
                        results.append(ClusterResult(
                            cluster_id=cluster_id,
                            devices=cluster_devices,
                            ecosystem=ecosystem,
                            confidence=0.7,
                            bubble_id=bubble_id
                        ))
                        cluster_id += 1

            return results

    def _calculate_cluster_confidence(self, devices: List[str],
                                       X: Any, macs: List[str],
                                       labels: Any) -> float:
        """Calculate confidence for a cluster."""
        if len(devices) < 2:
            return 0.0

        # Get indices
        indices = [macs.index(m) for m in devices]

        # Check ecosystem consistency
        ecosystems = [self._behaviors[m].ecosystem for m in devices]
        ecosystem_consistency = ecosystems.count(max(set(ecosystems), key=ecosystems.count)) / len(ecosystems)

        # Check for high pairwise similarity
        pairwise_sims = []
        for i in range(len(devices)):
            for j in range(i + 1, len(devices)):
                id_sim = self.compute_id_similarity(devices[i], devices[j])
                proto_sim = self.compute_protocol_overlap(devices[i], devices[j])
                ap_sim = self.compute_ap_correlation(devices[i], devices[j])
                pairwise_sims.append((id_sim + proto_sim + ap_sim) / 3)

        avg_sim = np.mean(pairwise_sims) if pairwise_sims else 0

        # Combine factors
        confidence = (ecosystem_consistency * 0.4 + avg_sim * 0.6)

        # Boost for small, tight clusters
        if len(devices) <= 4 and avg_sim > 0.7:
            confidence = min(0.95, confidence + 0.1)

        return min(0.99, max(0.1, confidence))

    def _generate_bubble_id(self, devices: List[str], ecosystem: str) -> str:
        """Generate a unique bubble ID."""
        # Create deterministic ID from sorted MACs
        sorted_macs = sorted(devices)
        mac_hash = hashlib.sha256(''.join(sorted_macs).encode()).hexdigest()[:12]
        return f"{ecosystem[:3].upper()}-{mac_hash}"

    def _persist_clusters(self, clusters: List[ClusterResult]):
        """Persist cluster results to database."""
        try:
            with sqlite3.connect(str(CLUSTERING_DB)) as conn:
                now = datetime.now().isoformat()

                for cluster in clusters:
                    # Update device assignments
                    for mac in cluster.devices:
                        conn.execute('''
                            UPDATE device_behaviors
                            SET cluster_id = ?, bubble_id = ?, updated_at = ?
                            WHERE mac = ?
                        ''', (cluster.cluster_id, cluster.bubble_id, now, mac))

                    # Record in history
                    conn.execute('''
                        INSERT INTO cluster_history
                        (cluster_id, devices_json, ecosystem, confidence, bubble_id, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        cluster.cluster_id,
                        json.dumps(cluster.devices),
                        cluster.ecosystem,
                        cluster.confidence,
                        cluster.bubble_id,
                        now
                    ))

                conn.commit()
        except Exception as e:
            logger.error(f"Could not persist clusters: {e}")

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def get_cluster_for_device(self, mac: str) -> Optional[ClusterResult]:
        """Get the cluster a device belongs to."""
        with self._lock:
            mac = mac.upper()
            behavior = self._behaviors.get(mac)

            if not behavior or not hasattr(behavior, 'cluster_id'):
                return None

            return self._clusters.get(behavior.cluster_id)

    def get_bubble_id(self, mac: str) -> Optional[str]:
        """Get the bubble ID for a device."""
        cluster = self.get_cluster_for_device(mac)
        return cluster.bubble_id if cluster else None

    def get_bubble_members(self, bubble_id: str) -> List[str]:
        """Get all devices in a bubble."""
        with self._lock:
            for cluster in self._clusters.values():
                if cluster.bubble_id == bubble_id:
                    return cluster.devices
            return []

    def are_same_bubble(self, mac_a: str, mac_b: str) -> Tuple[bool, float]:
        """Check if two devices are in the same bubble."""
        with self._lock:
            mac_a = mac_a.upper()
            mac_b = mac_b.upper()

            for cluster in self._clusters.values():
                if mac_a in cluster.devices and mac_b in cluster.devices:
                    return True, cluster.confidence

            return False, 0.0

    def get_all_clusters(self) -> List[ClusterResult]:
        """Get all current clusters."""
        with self._lock:
            return list(self._clusters.values())

    def persist_behaviors(self):
        """Persist all behaviors to database."""
        with self._lock:
            try:
                with sqlite3.connect(str(CLUSTERING_DB)) as conn:
                    now = datetime.now().isoformat()

                    for behavior in self._behaviors.values():
                        conn.execute('''
                            INSERT OR REPLACE INTO device_behaviors
                            (mac, ecosystem, time_correlation, proximity_score,
                             protocol_overlap, sync_frequency, handoff_count,
                             continuity_events, session_regularity,
                             mdns_services_json, mdns_device_id, hostname_pattern,
                             updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            behavior.mac,
                            behavior.ecosystem,
                            behavior.time_correlation,
                            behavior.proximity_score,
                            behavior.protocol_overlap,
                            behavior.sync_frequency,
                            behavior.handoff_count,
                            behavior.continuity_events,
                            behavior.session_regularity,
                            json.dumps(behavior.mdns_services),
                            behavior.mdns_device_id,
                            behavior.hostname_pattern,
                            now
                        ))
                    conn.commit()
            except Exception as e:
                logger.error(f"Could not persist behaviors: {e}")

    def get_stats(self) -> Dict:
        """Get clustering engine statistics."""
        with self._lock:
            # Count device types
            device_types = {'personal': 0, 'iot': 0, 'unknown': 0}
            d2d_enabled_count = 0

            for behavior in self._behaviors.values():
                if behavior.device_type == 'personal':
                    device_types['personal'] += 1
                elif behavior.device_type == 'iot':
                    device_types['iot'] += 1
                else:
                    device_types['unknown'] += 1

                if behavior.d2d_affinity_score > 0:
                    d2d_enabled_count += 1

            # Count cluster types
            user_bubbles = sum(1 for c in self._clusters.values() if c.bubble_type == 'user')
            iot_bubbles = sum(1 for c in self._clusters.values() if c.bubble_type == 'iot')
            mixed_bubbles = sum(1 for c in self._clusters.values() if c.bubble_type == 'mixed')

            return {
                'total_devices': len(self._behaviors),
                'total_clusters': len(self._clusters),
                'ml_available': HAS_NUMPY and HAS_SKLEARN,
                'leiden_available': HAS_LEIDEN,
                'd2d_available': HAS_D2D,
                'using_leiden': self._use_leiden,
                'avg_cluster_size': (
                    sum(len(c.devices) for c in self._clusters.values()) / len(self._clusters)
                    if self._clusters else 0
                ),
                'high_confidence_clusters': sum(
                    1 for c in self._clusters.values()
                    if c.confidence >= self.HIGH_CONFIDENCE
                ),
                # D2D enhanced stats
                'device_types': device_types,
                'd2d_enriched_devices': d2d_enabled_count,
                'user_bubbles': user_bubbles,
                'iot_bubbles': iot_bubbles,
                'mixed_bubbles': mixed_bubbles,
                'assigned_colors': len(self._bubble_color_assignments),
            }


# =============================================================================
# SINGLETON
# =============================================================================

_engine_instance: Optional[BehavioralClusteringEngine] = None
_engine_lock = threading.Lock()


def get_clustering_engine() -> BehavioralClusteringEngine:
    """Get singleton clustering engine instance."""
    global _engine_instance

    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = BehavioralClusteringEngine()
        return _engine_instance


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Behavioral Clustering Engine')
    parser.add_argument('--cluster', action='store_true', help='Run clustering')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--check', nargs=2, metavar=('MAC1', 'MAC2'),
                       help='Check if two devices are in same bubble')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    engine = get_clustering_engine()

    if args.stats:
        stats = engine.get_stats()
        print("\nClustering Engine Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    elif args.cluster:
        clusters = engine.cluster_devices()
        print(f"\nFound {len(clusters)} clusters:")
        for c in clusters:
            print(f"\n  Bubble: {c.bubble_id}")
            print(f"  Ecosystem: {c.ecosystem}")
            print(f"  Confidence: {c.confidence:.1%}")
            print(f"  Devices: {', '.join(c.devices)}")

    elif args.check:
        same, conf = engine.are_same_bubble(args.check[0], args.check[1])
        if same:
            print(f"YES - Same bubble (confidence: {conf:.1%})")
        else:
            print("NO - Different bubbles or not clustered")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
