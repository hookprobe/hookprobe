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
import json
import logging
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

logger = logging.getLogger(__name__)

# Import our proprietary modules
try:
    from presence_sensor import (
        PresenceSensor, get_presence_sensor,
        DevicePresence, EcosystemType, PresenceState
    )
    HAS_PRESENCE = True
except ImportError:
    HAS_PRESENCE = False

try:
    from behavior_clustering import (
        BehavioralClusteringEngine, get_clustering_engine,
        DeviceBehavior, ClusterResult
    )
    HAS_CLUSTERING = True
except ImportError:
    HAS_CLUSTERING = False

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

    # Lifecycle
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_activity: str = field(default_factory=lambda: datetime.now().isoformat())
    last_sdn_sync: Optional[str] = None

    # Identity hints
    owner_hint: Optional[str] = None  # Extracted from hostnames
    primary_device: Optional[str] = None  # Most active device

    # Stats
    handoff_count: int = 0
    sync_count: int = 0
    total_traffic_bytes: int = 0

    def to_dict(self) -> Dict:
        return {
            'bubble_id': self.bubble_id,
            'ecosystem': self.ecosystem,
            'devices': list(self.devices),
            'state': self.state.value,
            'privilege': self.privilege.value,
            'confidence': self.confidence,
            'created_at': self.created_at,
            'last_activity': self.last_activity,
            'device_count': len(self.devices),
            'owner_hint': self.owner_hint,
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

        # Background tasks
        self._running = False
        self._threads: List[threading.Thread] = []

        # Initialize database
        self._init_database()

    def _init_database(self):
        """Initialize bubble database."""
        try:
            BUBBLE_DB.parent.mkdir(parents=True, exist_ok=True)

            with sqlite3.connect(str(BUBBLE_DB)) as conn:
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
                        sync_count INTEGER
                    )
                ''')
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
            presence = self.presence_sensor.get_device_presence(mac)
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

            # Check for new devices
            new_devices = set(cluster.devices) - bubble.devices
            left_devices = bubble.devices - set(cluster.devices)

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
            threshold = self._get_confirmation_threshold(cluster.ecosystem)
            bubble = Bubble(
                bubble_id=bubble_id,
                ecosystem=cluster.ecosystem,
                devices=set(cluster.devices),
                confidence=cluster.confidence,
                state=BubbleState.FORMING if cluster.confidence < threshold else BubbleState.ACTIVE
            )

            # Extract owner hint
            bubble.owner_hint = self._extract_owner_hint(cluster.devices)

            self._bubbles[bubble_id] = bubble

            # Map devices to bubble
            for mac in cluster.devices:
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
        """Synchronize SDN rules for all active bubbles."""
        with self._lock:
            rules = []

            for bubble_id, bubble in self._bubbles.items():
                if bubble.state not in [BubbleState.ACTIVE, BubbleState.FORMING]:
                    continue

                if bubble.confidence < self.MIN_CLUSTER_CONFIDENCE:
                    continue

                # Generate rules for this bubble
                bubble_rules = self._generate_bubble_rules(bubble)
                rules.extend(bubble_rules)
                self._sdn_rules[bubble_id] = bubble_rules

            # Write rules to trigger file for host-side application
            self._write_sdn_trigger(rules)

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

    def apply_ovs_rules(self, bridge: str = "FTS"):
        """Apply OpenFlow rules to OVS bridge (run on host)."""
        with self._lock:
            for bubble_id, rules in self._sdn_rules.items():
                for rule in rules:
                    try:
                        match_str = ','.join(
                            f"{k}={v}" for k, v in rule['match'].items()
                        )

                        # Add flow
                        cmd = [
                            'ovs-ofctl', 'add-flow', bridge,
                            f"priority={rule['priority']},{match_str},actions=normal"
                        ]

                        subprocess.run(cmd, check=True, capture_output=True)

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
            with sqlite3.connect(str(BUBBLE_DB)) as conn:
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

    def _persist_all(self):
        """Persist all state to database."""
        with self._lock:
            try:
                with sqlite3.connect(str(BUBBLE_DB)) as conn:
                    for bubble in self._bubbles.values():
                        conn.execute('''
                            INSERT OR REPLACE INTO bubbles
                            (bubble_id, ecosystem, devices_json, state, privilege,
                             confidence, owner_hint, primary_device, created_at,
                             last_activity, handoff_count, sync_count)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                            bubble.sync_count
                        ))
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
    parser.add_argument('--start', action='store_true', help='Start manager')
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
