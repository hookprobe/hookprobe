#!/usr/bin/env python3
"""
Ecosystem Bubble Manager - Proprietary HookProbe Technology

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module implements "Atmospheric Presence" networking - the flagship
proprietary technology of HookProbe SDN Autopilot.

The Vision:
When you walk into a room with your iPhone, the SDN "sees" your arrival.
It immediately looks up your "fingerprint cluster" and pre-opens the
network gates to your MacBook and HomePod. Your devices "breathe"
together because the network itself understands they are one entity.

Architecture:
┌─────────────────────────────────────────────────────────────────┐
│              ECOSYSTEM BUBBLE MANAGER                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │  Presence   │────▶│  Behavior   │────▶│   Bubble    │       │
│  │   Sensor    │     │  Clustering │     │   Manager   │       │
│  └─────────────┘     └─────────────┘     └─────────────┘       │
│        │                   │                   │                │
│        │                   │                   │                │
│        ▼                   ▼                   ▼                │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │   mDNS      │     │   DBSCAN    │     │    SDN      │       │
│  │   BLE       │     │   ML Model  │     │ OpenFlow    │       │
│  │   Spatial   │     │             │     │   Rules     │       │
│  └─────────────┘     └─────────────┘     └─────────────┘       │
│                                                                  │
│                    THE "BUBBLE" CONCEPT                          │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                                                             ││
│  │   ┌──────┐    ┌──────┐    ┌──────┐                        ││
│  │   │iPhone│◀──▶│ iPad │◀──▶│ Mac  │   = USER BUBBLE        ││
│  │   └──────┘    └──────┘    └──────┘                        ││
│  │       │           │           │                            ││
│  │       └───────────┴───────────┘                            ││
│  │           Full LAN Access (East-West)                      ││
│  │           AirDrop, Handoff, Universal Clipboard            ││
│  │                                                             ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  Zero Trust: Devices outside bubble = ISOLATED                  │
│  Same Bubble: Devices communicate freely                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

Key Innovation:
- No passwords or credentials needed
- AI learns "same account" relationships from behavior
- Network adapts in real-time as devices move
- Per-bubble micro-segmentation with OpenFlow
"""

import asyncio
import copy
import json
import logging
import queue
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Callable, Any

# Database timeout for SQLite operations (prevent indefinite blocking)
DB_TIMEOUT_SECONDS = 5.0

logger = logging.getLogger(__name__)

# Import our proprietary modules
# Try both 'lib.' prefix (container) and direct import (standalone)
HAS_PRESENCE = False
try:
    from lib.presence_sensor import (
        PresenceSensor, get_presence_sensor,
        DevicePresence, EcosystemType, PresenceState
    )
    HAS_PRESENCE = True
except ImportError:
    try:
        from presence_sensor import (
            PresenceSensor, get_presence_sensor,
            DevicePresence, EcosystemType, PresenceState
        )
        HAS_PRESENCE = True
    except ImportError:
        pass

if not HAS_PRESENCE:
    # Stub classes for type hints when import fails
    class DevicePresence:
        pass
    class EcosystemType:
        APPLE = 'apple'
        GOOGLE = 'google'
        UNKNOWN = 'unknown'
    class PresenceState:
        ACTIVE = 'active'
    def get_presence_sensor():
        return None

# n8n webhook integration for bubble events
HAS_WEBHOOK = False
try:
    from lib.n8n_webhook import get_webhook_client, N8NWebhookClient
    HAS_WEBHOOK = True
except ImportError:
    try:
        from n8n_webhook import get_webhook_client, N8NWebhookClient
        HAS_WEBHOOK = True
    except ImportError:
        pass

if not HAS_WEBHOOK:
    def get_webhook_client():
        return None
    N8NWebhookClient = None

# Reinforcement learning from manual corrections
HAS_REINFORCEMENT = False
try:
    from lib.reinforcement_feedback import get_feedback_engine, ReinforcementFeedbackEngine
    HAS_REINFORCEMENT = True
except ImportError:
    try:
        from reinforcement_feedback import get_feedback_engine, ReinforcementFeedbackEngine
        HAS_REINFORCEMENT = True
    except ImportError:
        pass

if not HAS_REINFORCEMENT:
    def get_feedback_engine():
        return None
    ReinforcementFeedbackEngine = None

HAS_CLUSTERING = False
try:
    from lib.behavior_clustering import (
        BehavioralClusteringEngine, get_clustering_engine,
        DeviceBehavior, ClusterResult
    )
    HAS_CLUSTERING = True
except ImportError:
    try:
        from behavior_clustering import (
            BehavioralClusteringEngine, get_clustering_engine,
            DeviceBehavior, ClusterResult
        )
        HAS_CLUSTERING = True
    except ImportError:
        pass

if not HAS_CLUSTERING:
    # Stub classes for type hints when import fails
    class BehavioralClusteringEngine:
        pass
    class DeviceBehavior:
        pass
    class ClusterResult:
        pass
    def get_clustering_engine():
        return None

# Database
BUBBLE_DB = Path('/var/lib/hookprobe/bubbles.db')

# SDN Trigger file (for host-side OVS commands)
SDN_TRIGGER_FILE = Path('/opt/hookprobe/fortress/data/.bubble_sdn_sync')


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class BubbleState(Enum):
    """Lifecycle state of an ecosystem bubble."""
    FORMING = "forming"           # Being detected, not yet confirmed
    ACTIVE = "active"             # Confirmed and enforced
    DORMANT = "dormant"           # All devices gone, preserved for return
    DISSOLVED = "dissolved"       # No longer valid


class BubblePrivilege(Enum):
    """Privilege level for bubble communication."""
    FULL = "full"                 # Full mesh connectivity within bubble
    LIMITED = "limited"           # Limited protocols only
    QUARANTINE = "quarantine"     # No intra-bubble traffic


class BubbleType(Enum):
    """Type of bubble determining default network policies."""
    FAMILY = "family"             # Full smart home access, D2D, shared devices
    GUEST = "guest"               # Internet only, isolated
    CORPORATE = "corporate"       # Separate, controlled access
    SMART_HOME = "smart_home"     # IoT devices - limited LAN
    CUSTOM = "custom"             # User-defined policies


# Default policies for each bubble type
# Note: Flat bridge architecture - segmentation via OpenFlow NAC rules, not VLANs
BUBBLE_TYPE_POLICIES = {
    BubbleType.FAMILY: {
        'internet_access': True,
        'lan_access': True,
        'smart_home_access': True,
        'd2d_allowed': True,
        'shared_devices': True,
        'qos_priority': 'high',
        'bandwidth_limit': None,  # Unlimited
        'mdns_allowed': True,
        'description': 'Full network access with smart home integration',
    },
    BubbleType.GUEST: {
        'internet_access': True,
        'lan_access': False,
        'smart_home_access': False,
        'd2d_allowed': False,
        'shared_devices': False,
        'qos_priority': 'low',
        'bandwidth_limit': 50,  # 50 Mbps
        'mdns_allowed': False,
        'description': 'Internet only - isolated from local network',
    },
    BubbleType.CORPORATE: {
        'internet_access': True,
        'lan_access': False,
        'smart_home_access': False,
        'd2d_allowed': False,
        'shared_devices': False,
        'qos_priority': 'medium',
        'bandwidth_limit': None,
        'mdns_allowed': False,
        'description': 'Work devices - isolated with internet access',
    },
    BubbleType.SMART_HOME: {
        'internet_access': True,
        'lan_access': True,
        'smart_home_access': True,
        'd2d_allowed': True,
        'shared_devices': True,
        'qos_priority': 'medium',
        'bandwidth_limit': 10,  # 10 Mbps for IoT
        'mdns_allowed': True,
        'description': 'IoT and smart home devices',
    },
    BubbleType.CUSTOM: {
        'internet_access': True,
        'lan_access': False,
        'smart_home_access': False,
        'd2d_allowed': False,
        'shared_devices': False,
        'qos_priority': 'medium',
        'bandwidth_limit': None,
        'mdns_allowed': True,
        'description': 'Custom configuration',
    },
}


# OpenFlow priorities
OFP_BUBBLE_PRIORITY = 500         # Bubble allow rules
OFP_ISOLATION_PRIORITY = 100      # Default isolation
OFP_FALLBACK_PRIORITY = 1         # Fallback


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Bubble:
    """An ecosystem bubble - a group of devices belonging to one user."""
    bubble_id: str
    ecosystem: str
    devices: Set[str] = field(default_factory=set)  # MAC addresses
    state: BubbleState = BubbleState.FORMING
    privilege: BubblePrivilege = BubblePrivilege.FULL
    confidence: float = 0.0

    # Bubble type and policies
    bubble_type: BubbleType = BubbleType.FAMILY
    policies: Dict = field(default_factory=dict)  # Override default policies
    pinned: bool = False  # If True, AI won't modify assignments

    # Lifecycle
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_activity: str = field(default_factory=lambda: datetime.now().isoformat())
    last_sdn_sync: Optional[str] = None

    # Identity hints
    owner_hint: Optional[str] = None  # Extracted from hostnames
    name: Optional[str] = None  # User-defined name (e.g., "Dad", "Mom", "Kids")
    primary_device: Optional[str] = None  # Most active device

    # Manual assignment tracking
    manually_assigned_devices: Set[str] = field(default_factory=set)  # Devices pinned by user
    is_manual: bool = False  # True if bubble was manually created

    # D2D relationship tracking
    affinity_scores: Dict[str, float] = field(default_factory=dict)  # device_pair -> score

    # Stats
    handoff_count: int = 0
    sync_count: int = 0
    total_traffic_bytes: int = 0

    def get_effective_policies(self) -> Dict:
        """Get effective policies (type defaults + overrides)."""
        base_policies = BUBBLE_TYPE_POLICIES.get(self.bubble_type, {}).copy()
        base_policies.update(self.policies)
        return base_policies

    def to_dict(self) -> Dict:
        return {
            'bubble_id': self.bubble_id,
            'ecosystem': self.ecosystem,
            'devices': list(self.devices),
            'state': self.state.value,
            'privilege': self.privilege.value,
            'confidence': self.confidence,
            'bubble_type': self.bubble_type.value,
            'policies': self.get_effective_policies(),
            'pinned': self.pinned,
            'is_manual': self.is_manual,
            'name': self.name or self.owner_hint,
            'created_at': self.created_at,
            'last_activity': self.last_activity,
            'device_count': len(self.devices),
            'owner_hint': self.owner_hint,
            'manually_assigned_devices': list(self.manually_assigned_devices),
        }


@dataclass
class BubbleEvent:
    """Event related to bubble lifecycle."""
    event_type: str  # 'created', 'device_joined', 'device_left', 'dissolved', 'handoff'
    bubble_id: str
    mac: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    details: Dict = field(default_factory=dict)


# =============================================================================
# ECOSYSTEM BUBBLE MANAGER
# =============================================================================

class EcosystemBubbleManager:
    """
    Main controller for Ecosystem Bubble networking.

    Orchestrates presence sensing, behavioral clustering, and SDN enforcement
    to create seamless same-user device communication.
    """

    # Clustering thresholds
    MIN_CLUSTER_CONFIDENCE = 0.65     # Minimum to create bubble
    CONFIRMATION_THRESHOLD = 0.85      # Confidence to confirm bubble (default)
    DORMANT_TIMEOUT = 300              # Seconds before bubble goes dormant
    DISSOLVE_TIMEOUT = 3600            # Seconds before bubble dissolves

    # Ecosystem-specific confirmation thresholds
    # Apple/Google have tighter signatures allowing lower thresholds
    # Unknown ecosystems require higher confidence
    ECOSYSTEM_THRESHOLDS = {
        'apple': 0.75,      # Tight ecosystem with consistent signatures (Continuity, AirPlay)
        'google': 0.78,     # Good signature reliability (Cast, Nearby Share)
        'amazon': 0.80,     # Moderate variance (Alexa, Fire TV)
        'samsung': 0.82,    # SmartThings ecosystem
        'microsoft': 0.85,  # Standard threshold
        'unknown': 0.90,    # Conservative for unknown ecosystems
    }

    # Ecosystem lock-in confidence boost
    # When ALL devices in bubble are same ecosystem, boost confidence
    ECOSYSTEM_LOCK_IN_BOOST = 0.10  # +10% when all same ecosystem

    # Update intervals
    CLUSTERING_INTERVAL = 60           # Run clustering every 60 seconds
    SDN_SYNC_INTERVAL = 10             # Sync SDN rules every 10 seconds
    PRESENCE_CHECK_INTERVAL = 30       # Check presence every 30 seconds

    def __init__(self):
        # Initialize components
        self.presence_sensor: Optional[PresenceSensor] = None
        self.clustering_engine: Optional[BehavioralClusteringEngine] = None

        if HAS_PRESENCE:
            self.presence_sensor = get_presence_sensor()
        if HAS_CLUSTERING:
            self.clustering_engine = get_clustering_engine()

        # Bubble management
        self._bubbles: Dict[str, Bubble] = {}
        self._device_bubble_map: Dict[str, str] = {}  # MAC -> bubble_id
        self._events: List[BubbleEvent] = []
        self._lock = threading.RLock()

        # SDN rules cache
        self._sdn_rules: Dict[str, List[Dict]] = {}  # bubble_id -> rules
        self._sdn_dirty = False

        # Callbacks
        self._on_bubble_created: List[Callable] = []
        self._on_bubble_dissolved: List[Callable] = []
        self._on_device_joined: List[Callable] = []

        # n8n webhook integration for automation
        self._webhook_client: Optional[N8NWebhookClient] = None
        if HAS_WEBHOOK:
            self._webhook_client = get_webhook_client()
            logger.info("n8n webhook integration enabled")

        # Reinforcement learning from manual corrections
        self._feedback_engine: Optional[ReinforcementFeedbackEngine] = None
        if HAS_REINFORCEMENT:
            self._feedback_engine = get_feedback_engine()
            logger.info("Reinforcement learning enabled")

        # Background tasks
        self._running = False
        self._threads: List[threading.Thread] = []

        # OVS command queue for non-blocking subprocess execution
        # This prevents OVS commands from blocking the main lock
        self._ovs_command_queue: queue.Queue = queue.Queue()
        self._ovs_worker_thread: Optional[threading.Thread] = None

        # Initialize database
        self._init_database()

    def _init_database(self):
        """Initialize bubble database."""
        try:
            BUBBLE_DB.parent.mkdir(parents=True, exist_ok=True)

            # Use timeout to prevent indefinite blocking on database operations
            with sqlite3.connect(str(BUBBLE_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS bubbles (
                        bubble_id TEXT PRIMARY KEY,
                        ecosystem TEXT,
                        devices_json TEXT,
                        state TEXT,
                        privilege TEXT,
                        confidence REAL,
                        owner_hint TEXT,
                        primary_device TEXT,
                        created_at TEXT,
                        last_activity TEXT,
                        handoff_count INTEGER,
                        sync_count INTEGER,
                        bubble_type TEXT DEFAULT 'family',
                        policies_json TEXT,
                        pinned INTEGER DEFAULT 0,
                        name TEXT,
                        is_manual INTEGER DEFAULT 0,
                        manually_assigned_json TEXT,
                        affinity_scores_json TEXT
                    )
                ''')
                # Add new columns to existing tables (migration)
                try:
                    conn.execute('ALTER TABLE bubbles ADD COLUMN bubble_type TEXT DEFAULT "family"')
                except sqlite3.OperationalError:
                    pass  # Column already exists
                try:
                    conn.execute('ALTER TABLE bubbles ADD COLUMN policies_json TEXT')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE bubbles ADD COLUMN pinned INTEGER DEFAULT 0')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE bubbles ADD COLUMN name TEXT')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE bubbles ADD COLUMN is_manual INTEGER DEFAULT 0')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE bubbles ADD COLUMN manually_assigned_json TEXT')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE bubbles ADD COLUMN affinity_scores_json TEXT')
                except sqlite3.OperationalError:
                    pass
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS bubble_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT,
                        bubble_id TEXT,
                        mac TEXT,
                        timestamp TEXT,
                        details_json TEXT
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS sdn_rules (
                        bubble_id TEXT,
                        rule_json TEXT,
                        created_at TEXT,
                        PRIMARY KEY (bubble_id)
                    )
                ''')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_bubble_state ON bubbles(state)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_events_bubble ON bubble_events(bubble_id)')
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize bubble database: {e}")

    def _get_confirmation_threshold(self, ecosystem: str) -> float:
        """Get ecosystem-specific confirmation threshold.

        Apple/Google have tight signatures allowing lower thresholds.
        Unknown ecosystems require higher confidence.
        """
        eco_lower = ecosystem.lower() if ecosystem else 'unknown'
        return self.ECOSYSTEM_THRESHOLDS.get(eco_lower, self.CONFIRMATION_THRESHOLD)

    def _apply_ecosystem_lock_in_boost(self, bubble: 'Bubble', base_confidence: float) -> float:
        """Boost confidence when all devices are same ecosystem.

        When ALL devices in bubble belong to same tight ecosystem (Apple),
        we can be more confident they belong to same user.
        """
        if not bubble.devices or len(bubble.devices) < 2:
            return base_confidence

        # Check if all devices are same ecosystem (using presence data)
        if not self.presence_sensor:
            return base_confidence

        ecosystems = set()
        for mac in bubble.devices:
            presence = self.presence_sensor.get_device(mac)
            if presence and hasattr(presence, 'ecosystem'):
                ecosystems.add(str(presence.ecosystem).lower())

        # If all devices same ecosystem, apply boost
        if len(ecosystems) == 1:
            eco = list(ecosystems)[0]
            # Only boost for tight ecosystems (apple, google)
            if eco in ['apple', 'google', 'ecosystemtype.apple', 'ecosystemtype.google']:
                boosted = min(0.98, base_confidence + self.ECOSYSTEM_LOCK_IN_BOOST)
                logger.debug(f"Ecosystem lock-in boost for {eco}: {base_confidence:.2f} -> {boosted:.2f}")
                return boosted

        return base_confidence

    # =========================================================================
    # LIFECYCLE MANAGEMENT
    # =========================================================================

    def start(self):
        """Start the bubble manager and all background tasks."""
        if self._running:
            return

        self._running = True

        # Start presence sensor
        if self.presence_sensor:
            self.presence_sensor.start()

        # Background clustering thread
        clustering_thread = threading.Thread(
            target=self._clustering_loop,
            daemon=True,
            name="BubbleClustering"
        )
        clustering_thread.start()
        self._threads.append(clustering_thread)

        # Background SDN sync thread
        sdn_thread = threading.Thread(
            target=self._sdn_sync_loop,
            daemon=True,
            name="BubbleSDN"
        )
        sdn_thread.start()
        self._threads.append(sdn_thread)

        # Presence check thread
        presence_thread = threading.Thread(
            target=self._presence_check_loop,
            daemon=True,
            name="BubblePresence"
        )
        presence_thread.start()
        self._threads.append(presence_thread)

        logger.info("Ecosystem Bubble Manager started")

    def stop(self):
        """Stop the bubble manager."""
        self._running = False

        if self.presence_sensor:
            self.presence_sensor.stop()

        # Wait for threads
        for thread in self._threads:
            thread.join(timeout=5)

        # Persist state
        self._persist_all()

        logger.info("Ecosystem Bubble Manager stopped")

    def _clustering_loop(self):
        """Background loop for device clustering."""
        while self._running:
            try:
                self._run_clustering()
            except Exception as e:
                logger.error(f"Clustering error: {e}")

            time.sleep(self.CLUSTERING_INTERVAL)

    def _sdn_sync_loop(self):
        """Background loop for SDN rule synchronization."""
        while self._running:
            try:
                if self._sdn_dirty:
                    self._sync_sdn_rules()
                    self._sdn_dirty = False
            except Exception as e:
                logger.error(f"SDN sync error: {e}")

            time.sleep(self.SDN_SYNC_INTERVAL)

    def _presence_check_loop(self):
        """Background loop for presence checking and bubble state updates."""
        while self._running:
            try:
                self._check_bubble_presence()
            except Exception as e:
                logger.error(f"Presence check error: {e}")

            time.sleep(self.PRESENCE_CHECK_INTERVAL)

    # =========================================================================
    # CLUSTERING AND BUBBLE CREATION
    # =========================================================================

    def _run_clustering(self):
        """Run device clustering and update bubbles."""
        if not self.clustering_engine:
            return

        # Sync presence data to clustering engine
        if self.presence_sensor:
            self._sync_presence_to_clustering()

        # Run DBSCAN clustering
        clusters = self.clustering_engine.cluster_devices()

        with self._lock:
            # Process each cluster
            for cluster in clusters:
                if cluster.confidence >= self.MIN_CLUSTER_CONFIDENCE:
                    self._process_cluster(cluster)

            # Check for devices that left bubbles
            self._check_bubble_membership()

    def _sync_presence_to_clustering(self):
        """Sync presence sensor data to clustering engine."""
        if not self.presence_sensor or not self.clustering_engine:
            return

        devices = self.presence_sensor.get_all_devices()

        for device in devices:
            self.clustering_engine.update_behavior(
                device.mac,
                ecosystem=device.ecosystem.value,
                time_correlation=device.time_correlation,
                proximity_score=device.proximity_score,
                sync_frequency=device.sync_frequency,
                handoff_count=device.handoff_count,
                mdns_services=device.mdns_services,
                mdns_device_id=device.mdns_device_id,
                hostname_pattern=device.hostname,
            )

    def _process_cluster(self, cluster: ClusterResult):
        """Process a cluster and create/update bubble."""
        bubble_id = cluster.bubble_id

        if bubble_id in self._bubbles:
            # Update existing bubble
            bubble = self._bubbles[bubble_id]

            # Skip updates for pinned bubbles
            if bubble.pinned:
                logger.debug(f"Skipping pinned bubble: {bubble_id}")
                return

            # Check for new devices (exclude manually assigned devices elsewhere)
            new_devices = set(cluster.devices) - bubble.devices
            left_devices = bubble.devices - set(cluster.devices)

            # Filter out manually assigned devices from movements
            for mac in list(new_devices):
                mac_upper = mac.upper()
                # Check if device is manually assigned to another bubble
                current_bubble_id = self._device_bubble_map.get(mac_upper)
                if current_bubble_id and current_bubble_id in self._bubbles:
                    current_bubble = self._bubbles[current_bubble_id]
                    if mac_upper in current_bubble.manually_assigned_devices:
                        new_devices.discard(mac)
                        logger.debug(f"Skipping manually assigned device: {mac}")

            # Don't remove manually assigned devices
            for mac in list(left_devices):
                mac_upper = mac.upper()
                if mac_upper in bubble.manually_assigned_devices:
                    left_devices.discard(mac)
                    logger.debug(f"Keeping manually assigned device: {mac}")

            for mac in new_devices:
                self._add_device_to_bubble(bubble, mac)

            for mac in left_devices:
                self._remove_device_from_bubble(bubble, mac)

            # Update confidence with ecosystem lock-in boost
            boosted_confidence = self._apply_ecosystem_lock_in_boost(bubble, cluster.confidence)
            if boosted_confidence > bubble.confidence:
                bubble.confidence = boosted_confidence

            bubble.last_activity = datetime.now().isoformat()

            # Confirm if ecosystem-specific threshold met
            if bubble.state == BubbleState.FORMING:
                threshold = self._get_confirmation_threshold(bubble.ecosystem)
                if bubble.confidence >= threshold:
                    bubble.state = BubbleState.ACTIVE
                    self._record_event(BubbleEvent(
                        event_type='confirmed',
                        bubble_id=bubble_id,
                        details={'confidence': bubble.confidence, 'threshold': threshold}
                    ))
                    logger.info(f"Bubble confirmed: {bubble_id} ({len(bubble.devices)} devices, threshold={threshold:.2f})")

        else:
            # Create new bubble
            # Filter out manually assigned devices from new bubble
            available_devices = set()
            for mac in cluster.devices:
                mac_upper = mac.upper()
                current_bubble_id = self._device_bubble_map.get(mac_upper)
                if current_bubble_id and current_bubble_id in self._bubbles:
                    current_bubble = self._bubbles[current_bubble_id]
                    if mac_upper in current_bubble.manually_assigned_devices:
                        logger.debug(f"Excluding manually assigned device from new bubble: {mac}")
                        continue
                available_devices.add(mac)

            if not available_devices:
                logger.debug(f"No available devices for new bubble: {bubble_id}")
                return

            threshold = self._get_confirmation_threshold(cluster.ecosystem)
            bubble = Bubble(
                bubble_id=bubble_id,
                ecosystem=cluster.ecosystem,
                devices=available_devices,
                confidence=cluster.confidence,
                state=BubbleState.FORMING if cluster.confidence < threshold else BubbleState.ACTIVE
            )

            # Extract owner hint
            bubble.owner_hint = self._extract_owner_hint(list(available_devices))

            self._bubbles[bubble_id] = bubble

            # Map devices to bubble
            for mac in available_devices:
                self._device_bubble_map[mac] = bubble_id

            self._record_event(BubbleEvent(
                event_type='created',
                bubble_id=bubble_id,
                details={
                    'ecosystem': cluster.ecosystem,
                    'devices': list(cluster.devices),
                    'confidence': cluster.confidence
                }
            ))

            logger.info(f"Bubble created: {bubble_id} ({len(bubble.devices)} devices)")

            # Notify callbacks
            for callback in self._on_bubble_created:
                try:
                    callback(bubble)
                except Exception as e:
                    logger.error(f"Bubble created callback error: {e}")

        # Mark SDN as dirty
        self._sdn_dirty = True

    def _extract_owner_hint(self, devices: List[str]) -> Optional[str]:
        """Try to extract owner name from device hostnames."""
        if not self.presence_sensor:
            return None

        for mac in devices:
            device = self.presence_sensor.get_device(mac)
            if device and device.hostname:
                # Look for name patterns
                import re
                match = re.search(r"^(\w+)'s", device.hostname, re.IGNORECASE)
                if match:
                    return match.group(1)

                match = re.search(r"-(\w+)$", device.hostname)
                if match and match.group(1).lower() not in ['iphone', 'ipad', 'macbook', 'pro', 'air']:
                    return match.group(1)

        return None

    def _add_device_to_bubble(self, bubble: Bubble, mac: str):
        """Add a device to a bubble."""
        if mac in bubble.devices:
            return

        bubble.devices.add(mac)
        self._device_bubble_map[mac] = bubble.bubble_id
        bubble.last_activity = datetime.now().isoformat()

        self._record_event(BubbleEvent(
            event_type='device_joined',
            bubble_id=bubble.bubble_id,
            mac=mac
        ))

        logger.debug(f"Device {mac} joined bubble {bubble.bubble_id}")

        # Notify callbacks
        for callback in self._on_device_joined:
            try:
                callback(bubble, mac)
            except Exception as e:
                logger.error(f"Device joined callback error: {e}")

        self._sdn_dirty = True

    def _remove_device_from_bubble(self, bubble: Bubble, mac: str):
        """Remove a device from a bubble."""
        if mac not in bubble.devices:
            return

        bubble.devices.discard(mac)
        if mac in self._device_bubble_map:
            del self._device_bubble_map[mac]

        self._record_event(BubbleEvent(
            event_type='device_left',
            bubble_id=bubble.bubble_id,
            mac=mac
        ))

        logger.debug(f"Device {mac} left bubble {bubble.bubble_id}")
        self._sdn_dirty = True

    def _check_bubble_membership(self):
        """Check and update bubble membership based on clustering."""
        # This is handled in _process_cluster
        pass

    def _check_bubble_presence(self):
        """Check if bubble devices are still present."""
        now = datetime.now()

        with self._lock:
            for bubble_id, bubble in list(self._bubbles.items()):
                if bubble.state == BubbleState.DISSOLVED:
                    continue

                # Check device presence
                active_devices = 0

                if self.presence_sensor:
                    for mac in bubble.devices:
                        device = self.presence_sensor.get_device(mac)
                        if device and device.state == PresenceState.ACTIVE:
                            active_devices += 1

                # Update bubble state based on presence
                if active_devices == 0:
                    last_activity = datetime.fromisoformat(bubble.last_activity)
                    idle_seconds = (now - last_activity).total_seconds()

                    if bubble.state == BubbleState.ACTIVE and idle_seconds > self.DORMANT_TIMEOUT:
                        bubble.state = BubbleState.DORMANT
                        logger.info(f"Bubble dormant: {bubble_id}")

                    elif bubble.state == BubbleState.DORMANT and idle_seconds > self.DISSOLVE_TIMEOUT:
                        self._dissolve_bubble(bubble_id)

                elif bubble.state == BubbleState.DORMANT:
                    # Reactivate
                    bubble.state = BubbleState.ACTIVE
                    bubble.last_activity = now.isoformat()
                    logger.info(f"Bubble reactivated: {bubble_id}")
                    self._sdn_dirty = True

    def _dissolve_bubble(self, bubble_id: str):
        """Dissolve a bubble."""
        with self._lock:
            if bubble_id not in self._bubbles:
                return

            bubble = self._bubbles[bubble_id]
            bubble.state = BubbleState.DISSOLVED

            # Clear device mappings
            for mac in bubble.devices:
                if mac in self._device_bubble_map:
                    del self._device_bubble_map[mac]

            # Clear SDN rules
            if bubble_id in self._sdn_rules:
                del self._sdn_rules[bubble_id]

            self._record_event(BubbleEvent(
                event_type='dissolved',
                bubble_id=bubble_id
            ))

            logger.info(f"Bubble dissolved: {bubble_id}")

            # Notify callbacks
            for callback in self._on_bubble_dissolved:
                try:
                    callback(bubble)
                except Exception as e:
                    logger.error(f"Bubble dissolved callback error: {e}")

            self._sdn_dirty = True

    # =========================================================================
    # SDN INTEGRATION
    # =========================================================================

    def _sync_sdn_rules(self):
        """Synchronize SDN rules for all active bubbles.

        Non-blocking design: Takes a quick snapshot of bubble state,
        then does heavy rule generation and file I/O outside the lock.
        """
        # Phase 1: Quick snapshot with minimal lock time
        bubbles_snapshot = []
        with self._lock:
            for bubble_id, bubble in self._bubbles.items():
                if bubble.state not in [BubbleState.ACTIVE, BubbleState.FORMING]:
                    continue
                if bubble.confidence < self.MIN_CLUSTER_CONFIDENCE:
                    continue
                # Create lightweight snapshot (just what we need for rule generation)
                bubbles_snapshot.append({
                    'bubble_id': bubble.bubble_id,
                    'devices': list(bubble.devices),  # Copy the set
                    'state': bubble.state,
                })
            active_bubble_count = len([
                b for b in self._bubbles.values()
                if b.state == BubbleState.ACTIVE
            ])

        # Phase 2: Generate rules OUTSIDE the lock (no blocking)
        rules = []
        generated_rules = {}
        for snapshot in bubbles_snapshot:
            bubble_rules = self._generate_bubble_rules_from_snapshot(snapshot)
            rules.extend(bubble_rules)
            generated_rules[snapshot['bubble_id']] = bubble_rules

        # Phase 3: Quick update of rules cache
        with self._lock:
            self._sdn_rules.update(generated_rules)

        # Phase 4: Write file OUTSIDE the lock (file I/O can be slow)
        self._write_sdn_trigger_nonblocking(rules, active_bubble_count)

    def _generate_bubble_rules_from_snapshot(self, snapshot: Dict) -> List[Dict]:
        """Generate OpenFlow rules from a bubble snapshot (lock-free)."""
        rules = []
        devices = snapshot['devices']
        bubble_id = snapshot['bubble_id']

        # For each device pair in the bubble, allow bidirectional traffic
        for i in range(len(devices)):
            for j in range(i + 1, len(devices)):
                mac_a = devices[i]
                mac_b = devices[j]

                # Allow A -> B
                rules.append({
                    'type': 'allow',
                    'priority': OFP_BUBBLE_PRIORITY,
                    'match': {
                        'eth_src': mac_a,
                        'eth_dst': mac_b,
                    },
                    'actions': ['normal'],
                    'bubble_id': bubble_id,
                    'comment': f'Bubble {bubble_id}: {mac_a} -> {mac_b}'
                })

                # Allow B -> A
                rules.append({
                    'type': 'allow',
                    'priority': OFP_BUBBLE_PRIORITY,
                    'match': {
                        'eth_src': mac_b,
                        'eth_dst': mac_a,
                    },
                    'actions': ['normal'],
                    'bubble_id': bubble_id,
                    'comment': f'Bubble {bubble_id}: {mac_b} -> {mac_a}'
                })

        return rules

    def _generate_bubble_rules(self, bubble: Bubble) -> List[Dict]:
        """Generate OpenFlow rules for bubble traffic."""
        rules = []
        devices = list(bubble.devices)

        # For each device pair in the bubble, allow bidirectional traffic
        for i in range(len(devices)):
            for j in range(i + 1, len(devices)):
                mac_a = devices[i]
                mac_b = devices[j]

                # Allow A -> B
                rules.append({
                    'type': 'allow',
                    'priority': OFP_BUBBLE_PRIORITY,
                    'match': {
                        'eth_src': mac_a,
                        'eth_dst': mac_b,
                    },
                    'actions': ['normal'],
                    'bubble_id': bubble.bubble_id,
                    'comment': f'Bubble {bubble.bubble_id}: {mac_a} -> {mac_b}'
                })

                # Allow B -> A
                rules.append({
                    'type': 'allow',
                    'priority': OFP_BUBBLE_PRIORITY,
                    'match': {
                        'eth_src': mac_b,
                        'eth_dst': mac_a,
                    },
                    'actions': ['normal'],
                    'bubble_id': bubble.bubble_id,
                    'comment': f'Bubble {bubble.bubble_id}: {mac_b} -> {mac_a}'
                })

        return rules

    def _write_sdn_trigger(self, rules: List[Dict]):
        """Write SDN rules to trigger file for host application."""
        try:
            SDN_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)

            trigger_data = {
                'timestamp': datetime.now().isoformat(),
                'rules': rules,
                'bubble_count': len([
                    b for b in self._bubbles.values()
                    if b.state == BubbleState.ACTIVE
                ])
            }

            with open(SDN_TRIGGER_FILE, 'w') as f:
                json.dump(trigger_data, f, indent=2)

            # Update bubble sync timestamps
            now = datetime.now().isoformat()
            for bubble in self._bubbles.values():
                if bubble.state == BubbleState.ACTIVE:
                    bubble.last_sdn_sync = now

            logger.debug(f"SDN trigger written: {len(rules)} rules")

        except Exception as e:
            logger.error(f"Could not write SDN trigger: {e}")

    def _write_sdn_trigger_nonblocking(self, rules: List[Dict], active_bubble_count: int):
        """Write SDN rules to trigger file (non-blocking version).

        This version does NOT access self._bubbles and can be called
        outside the lock for improved concurrency.
        """
        try:
            SDN_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)

            trigger_data = {
                'timestamp': datetime.now().isoformat(),
                'rules': rules,
                'bubble_count': active_bubble_count
            }

            with open(SDN_TRIGGER_FILE, 'w') as f:
                json.dump(trigger_data, f, indent=2)

            # Update sync timestamps with quick lock acquisition
            now = datetime.now().isoformat()
            with self._lock:
                for bubble in self._bubbles.values():
                    if bubble.state == BubbleState.ACTIVE:
                        bubble.last_sdn_sync = now

            logger.debug(f"SDN trigger written: {len(rules)} rules")

        except Exception as e:
            logger.error(f"Could not write SDN trigger: {e}")

    def apply_ovs_rules(self, bridge: str = "FTS"):
        """Apply OpenFlow rules to OVS bridge (run on host).

        Non-blocking design: Takes a quick snapshot of rules,
        then executes OVS commands outside the lock to prevent blocking.
        """
        # Phase 1: Quick snapshot with minimal lock time
        rules_to_apply = []
        with self._lock:
            for bubble_id, rules in self._sdn_rules.items():
                for rule in rules:
                    rules_to_apply.append(copy.deepcopy(rule))

        # Phase 2: Execute OVS commands OUTSIDE the lock
        # This prevents subprocess calls from blocking other threads
        for rule in rules_to_apply:
            try:
                match_str = ','.join(
                    f"{k}={v}" for k, v in rule['match'].items()
                )

                # Add flow
                cmd = [
                    'ovs-ofctl', 'add-flow', bridge,
                    f"priority={rule['priority']},{match_str},actions=normal"
                ]

                # Use timeout to prevent indefinite blocking
                subprocess.run(cmd, check=True, capture_output=True, timeout=5)

            except subprocess.TimeoutExpired:
                logger.error(f"OVS flow add timed out for rule: {rule.get('comment', 'unknown')}")
            except subprocess.CalledProcessError as e:
                logger.error(f"OVS flow add failed: {e}")

    # =========================================================================
    # EVENT MANAGEMENT
    # =========================================================================

    def _record_event(self, event: BubbleEvent):
        """Record a bubble event."""
        self._events.append(event)

        # Persist to database
        try:
            with sqlite3.connect(str(BUBBLE_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                conn.execute('''
                    INSERT INTO bubble_events
                    (event_type, bubble_id, mac, timestamp, details_json)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    event.event_type,
                    event.bubble_id,
                    event.mac,
                    event.timestamp,
                    json.dumps(event.details)
                ))
                conn.commit()
        except Exception as e:
            logger.debug(f"Could not persist event: {e}")

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def get_bubble(self, bubble_id: str) -> Optional[Bubble]:
        """Get a bubble by ID."""
        with self._lock:
            return self._bubbles.get(bubble_id)

    def get_device_bubble(self, mac: str) -> Optional[Bubble]:
        """Get the bubble for a device."""
        with self._lock:
            mac = mac.upper()
            bubble_id = self._device_bubble_map.get(mac)
            if bubble_id:
                return self._bubbles.get(bubble_id)
            return None

    def are_same_bubble(self, mac_a: str, mac_b: str) -> Tuple[bool, float]:
        """Check if two devices are in the same bubble."""
        with self._lock:
            mac_a = mac_a.upper()
            mac_b = mac_b.upper()

            bubble_a = self._device_bubble_map.get(mac_a)
            bubble_b = self._device_bubble_map.get(mac_b)

            if bubble_a and bubble_a == bubble_b:
                bubble = self._bubbles.get(bubble_a)
                return True, bubble.confidence if bubble else 0.0

            return False, 0.0

    def get_all_bubbles(self) -> List[Bubble]:
        """Get all bubbles."""
        with self._lock:
            return list(self._bubbles.values())

    def get_active_bubbles(self) -> List[Bubble]:
        """Get active bubbles only."""
        with self._lock:
            return [
                b for b in self._bubbles.values()
                if b.state == BubbleState.ACTIVE
            ]

    def get_bubbles_by_type(self, bubble_type: BubbleType) -> List[Bubble]:
        """Get all bubbles of a specific type.

        Args:
            bubble_type: The type of bubble (FAMILY, GUEST, IOT, WORK)

        Returns:
            List of matching bubbles
        """
        with self._lock:
            return [
                b for b in self._bubbles.values()
                if b.bubble_type == bubble_type and b.state == BubbleState.ACTIVE
            ]

    def get_bubbles_by_ecosystem(self, ecosystem: str) -> List[Bubble]:
        """Get all bubbles for a specific ecosystem.

        Args:
            ecosystem: Ecosystem identifier (apple, samsung, google, etc.)

        Returns:
            List of matching bubbles
        """
        with self._lock:
            ecosystem = ecosystem.lower()
            return [
                b for b in self._bubbles.values()
                if b.ecosystem == ecosystem and b.state == BubbleState.ACTIVE
            ]

    def add_device_to_bubble(self, mac: str, bubble_id: str) -> bool:
        """Add a device to an existing bubble.

        This is the public API for adding devices. It handles:
        - Removing device from old bubble
        - Adding to new bubble
        - Updating SDN rules
        - Recording the event

        Args:
            mac: Device MAC address
            bubble_id: Target bubble ID

        Returns:
            True if successful, False if bubble not found
        """
        mac = mac.upper()

        with self._lock:
            bubble = self._bubbles.get(bubble_id)
            if not bubble:
                logger.warning(f"Bubble not found: {bubble_id}")
                return False

            # Remove from old bubble if any
            old_bubble_id = self._device_bubble_map.get(mac)
            if old_bubble_id and old_bubble_id in self._bubbles:
                old_bubble = self._bubbles[old_bubble_id]
                old_bubble.devices.discard(mac)

                # Record move event with reinforcement learning
                if HAS_REINFORCEMENT:
                    try:
                        feedback_engine = get_feedback_engine()
                        if feedback_engine:
                            feedback_engine.record_correction(
                                mac=mac,
                                old_bubble_id=old_bubble_id,
                                new_bubble_id=bubble_id,
                                old_bubble_devices=list(old_bubble.devices),
                                new_bubble_devices=list(bubble.devices),
                                reason='autopilot_assignment'
                            )
                    except Exception as e:
                        logger.debug(f"Reinforcement feedback error: {e}")

            # Add to new bubble
            bubble.devices.add(mac)
            self._device_bubble_map[mac] = bubble_id
            bubble.last_activity = datetime.now().isoformat()

            # Record event
            self._record_event(BubbleEvent(
                event_type='device_added',
                bubble_id=bubble_id,
                mac=mac,
                details={'old_bubble': old_bubble_id}
            ))

            # Trigger webhook if available
            if HAS_WEBHOOK:
                try:
                    webhook = get_webhook_client()
                    if webhook:
                        webhook.on_bubble_change(
                            mac=mac,
                            old_bubble=old_bubble_id or 'none',
                            new_bubble=bubble_id,
                            confidence=bubble.confidence,
                            reason='add_device_to_bubble'
                        )
                except Exception as e:
                    logger.debug(f"Webhook error: {e}")

            # Mark SDN dirty
            self._sdn_dirty = True

            # Trigger callbacks
            for callback in self._on_device_joined:
                try:
                    callback(mac, bubble)
                except Exception as e:
                    logger.error(f"Device joined callback error: {e}")

            return True

    def force_clustering(self):
        """Force an immediate clustering run."""
        self._run_clustering()

    def record_handoff(self, mac_a: str, mac_b: str):
        """Record a handoff event between two devices."""
        with self._lock:
            mac_a = mac_a.upper()
            mac_b = mac_b.upper()

            # Update clustering engine
            if self.clustering_engine:
                self.clustering_engine.update_behavior(mac_a, handoff_count=1)
                self.clustering_engine.update_behavior(mac_b, handoff_count=1)

            # Update bubble stats
            bubble_a = self._device_bubble_map.get(mac_a)
            bubble_b = self._device_bubble_map.get(mac_b)

            if bubble_a and bubble_a == bubble_b:
                bubble = self._bubbles.get(bubble_a)
                if bubble:
                    bubble.handoff_count += 1
                    bubble.last_activity = datetime.now().isoformat()

            self._record_event(BubbleEvent(
                event_type='handoff',
                bubble_id=bubble_a or 'unknown',
                mac=mac_a,
                details={'peer': mac_b}
            ))

    def on_bubble_created(self, callback: Callable):
        """Register callback for bubble creation."""
        self._on_bubble_created.append(callback)

    def on_bubble_dissolved(self, callback: Callable):
        """Register callback for bubble dissolution."""
        self._on_bubble_dissolved.append(callback)

    def on_device_joined(self, callback: Callable):
        """Register callback for device joining bubble."""
        self._on_device_joined.append(callback)

    # =========================================================================
    # MANUAL BUBBLE MANAGEMENT
    # =========================================================================

    def create_manual_bubble(
        self,
        name: str,
        bubble_type: BubbleType = BubbleType.FAMILY,
        devices: Optional[List[str]] = None,
        policies: Optional[Dict] = None
    ) -> Bubble:
        """Create a manually-defined bubble.

        Args:
            name: Human-readable name (e.g., "Dad", "Mom", "Kids")
            bubble_type: Type determining default policies
            devices: Initial devices to add (MAC addresses)
            policies: Policy overrides

        Returns:
            The created bubble
        """
        import uuid

        bubble_id = f"manual-{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"

        with self._lock:
            bubble = Bubble(
                bubble_id=bubble_id,
                ecosystem='mixed',  # Manual bubbles can contain mixed ecosystems
                devices=set(devices or []),
                state=BubbleState.ACTIVE,
                confidence=1.0,  # Manual bubbles have full confidence
                bubble_type=bubble_type,
                policies=policies or {},
                pinned=True,  # Manual bubbles are pinned by default
                name=name,
                is_manual=True,
                manually_assigned_devices=set(devices or []),
            )

            self._bubbles[bubble_id] = bubble

            # Map devices to this bubble
            for mac in bubble.devices:
                mac = mac.upper()
                # Remove from old bubble if any
                old_bubble_id = self._device_bubble_map.get(mac)
                if old_bubble_id and old_bubble_id in self._bubbles:
                    old_bubble = self._bubbles[old_bubble_id]
                    old_bubble.devices.discard(mac)
                    old_bubble.manually_assigned_devices.discard(mac)

                self._device_bubble_map[mac] = bubble_id

            self._record_event(BubbleEvent(
                event_type='created_manual',
                bubble_id=bubble_id,
                details={'name': name, 'type': bubble_type.value, 'devices': list(bubble.devices)}
            ))

            self._sdn_dirty = True
            self._persist_bubble(bubble)

            logger.info(f"Manual bubble created: {name} ({bubble_id})")

            # Send webhook notification
            if self._webhook_client:
                self._webhook_client.on_bubble_created(
                    bubble_id=bubble_id,
                    bubble_name=name,
                    bubble_type=bubble_type.value,
                    devices=list(bubble.devices),
                )

            return bubble

    def update_bubble(
        self,
        bubble_id: str,
        name: Optional[str] = None,
        bubble_type: Optional[BubbleType] = None,
        policies: Optional[Dict] = None,
        pinned: Optional[bool] = None
    ) -> Optional[Bubble]:
        """Update bubble settings.

        Args:
            bubble_id: Bubble to update
            name: New name
            bubble_type: New type
            policies: Policy overrides
            pinned: Pin status

        Returns:
            Updated bubble or None if not found
        """
        with self._lock:
            bubble = self._bubbles.get(bubble_id)
            if not bubble:
                return None

            if name is not None:
                bubble.name = name
            if bubble_type is not None:
                bubble.bubble_type = bubble_type
            if policies is not None:
                bubble.policies = policies
            if pinned is not None:
                bubble.pinned = pinned

            bubble.last_activity = datetime.now().isoformat()

            self._record_event(BubbleEvent(
                event_type='updated',
                bubble_id=bubble_id,
                details={
                    'name': bubble.name,
                    'type': bubble.bubble_type.value,
                    'pinned': bubble.pinned
                }
            ))

            self._sdn_dirty = True
            self._persist_bubble(bubble)

            logger.info(f"Bubble updated: {bubble_id}")

            return bubble

    def move_device(self, mac: str, target_bubble_id: str, pin: bool = True) -> bool:
        """Move a device to a different bubble.

        Args:
            mac: Device MAC address
            target_bubble_id: Target bubble ID
            pin: If True, pin the device (AI won't move it back)

        Returns:
            True if successful
        """
        mac = mac.upper()

        with self._lock:
            target_bubble = self._bubbles.get(target_bubble_id)
            if not target_bubble:
                logger.warning(f"Target bubble not found: {target_bubble_id}")
                return False

            # Remove from current bubble
            current_bubble_id = self._device_bubble_map.get(mac)
            if current_bubble_id and current_bubble_id in self._bubbles:
                current_bubble = self._bubbles[current_bubble_id]
                current_bubble.devices.discard(mac)
                current_bubble.manually_assigned_devices.discard(mac)

                self._record_event(BubbleEvent(
                    event_type='device_left',
                    bubble_id=current_bubble_id,
                    mac=mac,
                    details={'reason': 'manual_move', 'target': target_bubble_id}
                ))

            # Add to target bubble
            target_bubble.devices.add(mac)
            if pin:
                target_bubble.manually_assigned_devices.add(mac)
            self._device_bubble_map[mac] = target_bubble_id
            target_bubble.last_activity = datetime.now().isoformat()

            self._record_event(BubbleEvent(
                event_type='device_joined',
                bubble_id=target_bubble_id,
                mac=mac,
                details={'reason': 'manual_move', 'pinned': pin}
            ))

            self._sdn_dirty = True
            self._persist_bubble(target_bubble)
            if current_bubble_id and current_bubble_id in self._bubbles:
                self._persist_bubble(self._bubbles[current_bubble_id])

            logger.info(f"Device {mac} moved to bubble {target_bubble_id}")

            # Send webhook notification
            if self._webhook_client:
                self._webhook_client.on_bubble_change(
                    mac=mac,
                    old_bubble=current_bubble_id or '',
                    new_bubble=target_bubble_id,
                    confidence=target_bubble.confidence,
                    reason='manual_move' if pin else 'auto_move',
                )

                # If this is a manual correction, also notify for learning
                if pin and current_bubble_id:
                    self._webhook_client.on_manual_correction(
                        mac=mac,
                        old_bubble=current_bubble_id,
                        new_bubble=target_bubble_id,
                        correction_reason='user_correction',
                    )

            # Record correction for reinforcement learning
            if self._feedback_engine and pin and current_bubble_id:
                # Get devices in old and new bubbles for learning
                old_bubble_devices = []
                if current_bubble_id in self._bubbles:
                    old_bubble_devices = list(self._bubbles[current_bubble_id].devices)

                new_bubble_devices = list(target_bubble.devices)

                self._feedback_engine.record_correction(
                    mac=mac,
                    old_bubble_id=current_bubble_id,
                    new_bubble_id=target_bubble_id,
                    old_bubble_devices=old_bubble_devices,
                    new_bubble_devices=new_bubble_devices,
                    reason='manual_move',
                )

                # Apply immediately for real-time learning
                self._feedback_engine.apply_pending_corrections()

            return True

    def pin_bubble(self, bubble_id: str, pinned: bool = True) -> bool:
        """Pin or unpin a bubble.

        Pinned bubbles won't be modified by AI clustering.

        Args:
            bubble_id: Bubble to pin/unpin
            pinned: True to pin, False to unpin

        Returns:
            True if successful
        """
        with self._lock:
            bubble = self._bubbles.get(bubble_id)
            if not bubble:
                return False

            bubble.pinned = pinned

            self._record_event(BubbleEvent(
                event_type='pinned' if pinned else 'unpinned',
                bubble_id=bubble_id
            ))

            self._persist_bubble(bubble)
            logger.info(f"Bubble {bubble_id} {'pinned' if pinned else 'unpinned'}")

            return True

    def delete_bubble(self, bubble_id: str) -> bool:
        """Delete a bubble.

        Args:
            bubble_id: Bubble to delete

        Returns:
            True if successful
        """
        with self._lock:
            bubble = self._bubbles.get(bubble_id)
            if not bubble:
                return False

            # Clear device mappings
            for mac in bubble.devices:
                if self._device_bubble_map.get(mac) == bubble_id:
                    del self._device_bubble_map[mac]

            # Clear SDN rules
            if bubble_id in self._sdn_rules:
                del self._sdn_rules[bubble_id]

            # Remove bubble
            del self._bubbles[bubble_id]

            self._record_event(BubbleEvent(
                event_type='deleted',
                bubble_id=bubble_id
            ))

            self._sdn_dirty = True

            # Delete from database
            try:
                with sqlite3.connect(str(BUBBLE_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                    conn.execute('DELETE FROM bubbles WHERE bubble_id = ?', (bubble_id,))
                    conn.commit()
            except Exception as e:
                logger.error(f"Could not delete bubble from database: {e}")

            logger.info(f"Bubble deleted: {bubble_id}")

            return True

    def get_ai_suggestions(self) -> List[Dict]:
        """Get AI suggestions for device groupings.

        Returns a list of suggested device pairs with affinity scores.

        Returns:
            List of suggestion dictionaries
        """
        suggestions = []

        # Try to use connection graph analyzer for D2D detection
        try:
            from lib.connection_graph import ConnectionGraphAnalyzer
            analyzer = ConnectionGraphAnalyzer()
            clusters = analyzer.find_d2d_clusters()

            for cluster in clusters:
                if len(cluster.devices) >= 2:
                    suggestions.append({
                        'type': 'cluster',
                        'devices': list(cluster.devices),
                        'affinity_score': cluster.average_affinity,
                        'reason': f"Detected D2D communication between {len(cluster.devices)} devices",
                        'suggested_bubble_type': 'family'
                    })
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Connection graph analysis failed: {e}")

        # Add suggestions from clustering engine
        if self.clustering_engine and HAS_CLUSTERING:
            try:
                clusters = self.clustering_engine.cluster_devices()
                for cluster in clusters:
                    if cluster.confidence >= 0.5 and len(cluster.devices) >= 2:
                        # Skip if devices already in same bubble
                        bubble_ids = set()
                        for mac in cluster.devices:
                            bid = self._device_bubble_map.get(mac.upper())
                            if bid:
                                bubble_ids.add(bid)

                        if len(bubble_ids) > 1 or not bubble_ids:
                            suggestions.append({
                                'type': 'behavioral',
                                'devices': list(cluster.devices),
                                'affinity_score': cluster.confidence,
                                'reason': f"Similar behavior patterns detected ({cluster.ecosystem} ecosystem)",
                                'suggested_bubble_type': 'family' if cluster.ecosystem in ['apple', 'google'] else 'custom'
                            })
            except Exception as e:
                logger.debug(f"Clustering suggestions failed: {e}")

        return suggestions

    def _persist_bubble(self, bubble: Bubble):
        """Persist a single bubble to database."""
        try:
            with sqlite3.connect(str(BUBBLE_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO bubbles
                    (bubble_id, ecosystem, devices_json, state, privilege,
                     confidence, owner_hint, primary_device, created_at,
                     last_activity, handoff_count, sync_count, bubble_type,
                     policies_json, pinned, name, is_manual, manually_assigned_json,
                     affinity_scores_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    bubble.bubble_id,
                    bubble.ecosystem,
                    json.dumps(list(bubble.devices)),
                    bubble.state.value,
                    bubble.privilege.value,
                    bubble.confidence,
                    bubble.owner_hint,
                    bubble.primary_device,
                    bubble.created_at,
                    bubble.last_activity,
                    bubble.handoff_count,
                    bubble.sync_count,
                    bubble.bubble_type.value,
                    json.dumps(bubble.policies),
                    1 if bubble.pinned else 0,
                    bubble.name,
                    1 if bubble.is_manual else 0,
                    json.dumps(list(bubble.manually_assigned_devices)),
                    json.dumps(bubble.affinity_scores),
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Could not persist bubble: {e}")

    def _persist_all(self):
        """Persist all state to database.

        Non-blocking design: Takes a quick snapshot of bubble data,
        then performs SQLite writes outside the lock.
        """
        # Phase 1: Quick snapshot with minimal lock time
        bubbles_data = []
        with self._lock:
            for bubble in self._bubbles.values():
                bubbles_data.append((
                    bubble.bubble_id,
                    bubble.ecosystem,
                    json.dumps(list(bubble.devices)),
                    bubble.state.value,
                    bubble.privilege.value,
                    bubble.confidence,
                    bubble.owner_hint,
                    bubble.primary_device,
                    bubble.created_at,
                    bubble.last_activity,
                    bubble.handoff_count,
                    bubble.sync_count
                ))

        # Phase 2: SQLite writes OUTSIDE the lock
        if not bubbles_data:
            return

        try:
            with sqlite3.connect(str(BUBBLE_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                conn.executemany('''
                    INSERT OR REPLACE INTO bubbles
                    (bubble_id, ecosystem, devices_json, state, privilege,
                     confidence, owner_hint, primary_device, created_at,
                     last_activity, handoff_count, sync_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', bubbles_data)
                conn.commit()
        except Exception as e:
            logger.error(f"Could not persist bubbles: {e}")

    def get_stats(self) -> Dict:
        """Get bubble manager statistics."""
        with self._lock:
            active = [b for b in self._bubbles.values() if b.state == BubbleState.ACTIVE]
            dormant = [b for b in self._bubbles.values() if b.state == BubbleState.DORMANT]

            return {
                'total_bubbles': len(self._bubbles),
                'active_bubbles': len(active),
                'dormant_bubbles': len(dormant),
                'total_devices_in_bubbles': len(self._device_bubble_map),
                'total_sdn_rules': sum(len(r) for r in self._sdn_rules.values()),
                'presence_sensor_running': self.presence_sensor.running if self.presence_sensor else False,
                'clustering_available': HAS_CLUSTERING,
                'running': self._running,
            }


# =============================================================================
# SINGLETON
# =============================================================================

_manager_instance: Optional[EcosystemBubbleManager] = None
_manager_lock = threading.Lock()


def get_bubble_manager() -> EcosystemBubbleManager:
    """Get singleton bubble manager instance."""
    global _manager_instance

    with _manager_lock:
        if _manager_instance is None:
            _manager_instance = EcosystemBubbleManager()
        return _manager_instance


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Ecosystem Bubble Manager')
    parser.add_argument('--start', '--daemon', action='store_true', help='Start manager (daemon mode)')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--list', action='store_true', help='List all bubbles')
    parser.add_argument('--check', nargs=2, metavar=('MAC1', 'MAC2'),
                       help='Check if two devices are in same bubble')
    parser.add_argument('--cluster', action='store_true', help='Force clustering run')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    manager = get_bubble_manager()

    if args.stats:
        stats = manager.get_stats()
        print("\nEcosystem Bubble Manager Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    elif args.list:
        bubbles = manager.get_all_bubbles()
        print(f"\n{len(bubbles)} Bubbles:")
        for b in bubbles:
            print(f"\n  {b.bubble_id}")
            print(f"    Ecosystem: {b.ecosystem}")
            print(f"    State: {b.state.value}")
            print(f"    Confidence: {b.confidence:.1%}")
            print(f"    Devices: {len(b.devices)}")
            if b.owner_hint:
                print(f"    Owner: {b.owner_hint}")

    elif args.check:
        same, conf = manager.are_same_bubble(args.check[0], args.check[1])
        if same:
            print(f"YES - Same bubble (confidence: {conf:.1%})")
        else:
            print("NO - Different bubbles")

    elif args.cluster:
        manager.force_clustering()
        print("Clustering complete")
        bubbles = manager.get_all_bubbles()
        print(f"Found {len(bubbles)} bubbles")

    elif args.start:
        print("Starting Ecosystem Bubble Manager...")
        manager.start()
        try:
            while True:
                time.sleep(10)
                stats = manager.get_stats()
                print(f"\rActive bubbles: {stats['active_bubbles']}, "
                      f"Devices: {stats['total_devices_in_bubbles']}, "
                      f"Rules: {stats['total_sdn_rules']}", end='')
        except KeyboardInterrupt:
            print("\nStopping...")
            manager.stop()

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
