#!/usr/bin/env python3
"""
Digital Twin Simulator - Virtual SDN Environment

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Creates a digital twin of the Fortress OVS/SDN environment for safe
red team simulation. The twin "shadows" the real network allowing
attacks to be tested without affecting production.

Architecture:
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DIGITAL TWIN SIMULATOR                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  FORTRESS (Real)                    NEXUS (Twin)                            │
│  ┌─────────────────┐                ┌─────────────────┐                     │
│  │  OVS Bridge     │   ──sync──▶   │  Virtual OVS    │                     │
│  │  - VLANs        │                │  - VirtualDevices│                    │
│  │  - Flows        │                │  - VirtualBubbles│                    │
│  └─────────────────┘                └─────────────────┘                     │
│                                                                              │
│  Sync Components:                                                            │
│  - Device MACs/IPs                                                          │
│  - Bubble assignments                                                       │
│  - QSECBIT scores                                                           │
│  - Affinity relationships                                                   │
│  - Temporal patterns                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

The twin enables:
- Safe attack simulation without production impact
- Rapid iteration on defense strategies
- Regression testing of SDN changes
- Training data generation for ML models
"""

import copy
import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import random

logger = logging.getLogger(__name__)

# Twin data directory
TWIN_DATA_DIR = Path('/var/lib/hookprobe/nexus/twins')


class DeviceEcosystem(Enum):
    """Device ecosystem classification."""
    APPLE = "apple"
    ANDROID = "android"
    WINDOWS = "windows"
    LINUX = "linux"
    IOT = "iot"
    UNKNOWN = "unknown"


class BubbleType(Enum):
    """Bubble classification types."""
    FAMILY = "family"
    GUEST = "guest"
    IOT = "iot"
    WORK = "work"
    QUARANTINE = "quarantine"


class DeviceState(Enum):
    """Device state in the network."""
    ACTIVE = "active"
    DORMANT = "dormant"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"


@dataclass
class TwinConfig:
    """Configuration for digital twin."""
    twin_id: str = ""
    fortress_ip: str = "127.0.0.1"
    fortress_port: int = 8443
    sync_interval: int = 60  # seconds
    auto_sync: bool = True
    persist_state: bool = True
    enable_temporal: bool = True
    enable_affinity: bool = True

    def __post_init__(self):
        if not self.twin_id:
            self.twin_id = f"TWIN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"


@dataclass
class VirtualDevice:
    """Virtual representation of a network device."""
    mac: str
    ip: str
    hostname: str = ""
    vendor: str = ""
    ecosystem: DeviceEcosystem = DeviceEcosystem.UNKNOWN
    state: DeviceState = DeviceState.ACTIVE

    # Bubble assignment
    bubble_id: str = ""
    bubble_type: BubbleType = BubbleType.GUEST

    # Security scores
    qsecbit_score: float = 0.7
    trust_score: float = 0.5
    nse_resonance: float = 0.5

    # Temporal pattern
    active_hours: Set[int] = field(default_factory=set)
    wake_hour: int = 7
    sleep_hour: int = 23
    avg_session_minutes: float = 120.0

    # Affinity relationships
    affinities: Dict[str, float] = field(default_factory=dict)  # mac → score

    # DHCP fingerprint
    dhcp_option_55: List[int] = field(default_factory=list)
    os_fingerprint: str = ""

    # Last seen
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            'mac': self.mac,
            'ip': self.ip,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'ecosystem': self.ecosystem.value,
            'state': self.state.value,
            'bubble_id': self.bubble_id,
            'bubble_type': self.bubble_type.value,
            'qsecbit_score': self.qsecbit_score,
            'trust_score': self.trust_score,
            'nse_resonance': self.nse_resonance,
            'active_hours': list(self.active_hours),
            'wake_hour': self.wake_hour,
            'sleep_hour': self.sleep_hour,
            'affinities': self.affinities,
            'dhcp_option_55': self.dhcp_option_55,
            'os_fingerprint': self.os_fingerprint,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'VirtualDevice':
        device = cls(
            mac=data['mac'],
            ip=data['ip'],
            hostname=data.get('hostname', ''),
            vendor=data.get('vendor', ''),
            ecosystem=DeviceEcosystem(data.get('ecosystem', 'unknown')),
            state=DeviceState(data.get('state', 'active')),
            bubble_id=data.get('bubble_id', ''),
            bubble_type=BubbleType(data.get('bubble_type', 'guest')),
            qsecbit_score=data.get('qsecbit_score', 0.7),
            trust_score=data.get('trust_score', 0.5),
            nse_resonance=data.get('nse_resonance', 0.5),
            wake_hour=data.get('wake_hour', 7),
            sleep_hour=data.get('sleep_hour', 23),
            avg_session_minutes=data.get('avg_session_minutes', 120.0),
            affinities=data.get('affinities', {}),
            dhcp_option_55=data.get('dhcp_option_55', []),
            os_fingerprint=data.get('os_fingerprint', ''),
        )
        device.active_hours = set(data.get('active_hours', []))
        if data.get('first_seen'):
            device.first_seen = datetime.fromisoformat(data['first_seen'])
        if data.get('last_seen'):
            device.last_seen = datetime.fromisoformat(data['last_seen'])
        return device


@dataclass
class VirtualBubble:
    """Virtual representation of a device bubble."""
    bubble_id: str
    name: str
    bubble_type: BubbleType
    vlan: int
    devices: Set[str] = field(default_factory=set)  # MAC addresses

    # Policy
    internet_access: bool = True
    lan_access: bool = False
    d2d_access: bool = False

    # Statistics
    device_count: int = 0
    avg_qsecbit: float = 0.7
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            'bubble_id': self.bubble_id,
            'name': self.name,
            'bubble_type': self.bubble_type.value,
            'vlan': self.vlan,
            'devices': list(self.devices),
            'internet_access': self.internet_access,
            'lan_access': self.lan_access,
            'd2d_access': self.d2d_access,
            'device_count': self.device_count,
            'avg_qsecbit': self.avg_qsecbit,
            'created_at': self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'VirtualBubble':
        bubble = cls(
            bubble_id=data['bubble_id'],
            name=data['name'],
            bubble_type=BubbleType(data.get('bubble_type', 'guest')),
            vlan=data.get('vlan', 150),
            internet_access=data.get('internet_access', True),
            lan_access=data.get('lan_access', False),
            d2d_access=data.get('d2d_access', False),
            device_count=data.get('device_count', 0),
            avg_qsecbit=data.get('avg_qsecbit', 0.7),
        )
        bubble.devices = set(data.get('devices', []))
        if data.get('created_at'):
            bubble.created_at = datetime.fromisoformat(data['created_at'])
        return bubble


@dataclass
class VirtualOVS:
    """Virtual representation of OVS bridge configuration."""
    bridge_name: str = "FTS"
    vlans: Dict[int, str] = field(default_factory=dict)  # vlan → name
    flows: List[Dict] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)

    # Subnet configuration
    lan_subnet: str = "10.200.0.0/24"
    mgmt_subnet: str = "10.200.100.0/30"

    def to_dict(self) -> Dict:
        return {
            'bridge_name': self.bridge_name,
            'vlans': self.vlans,
            'flows': self.flows,
            'ports': self.ports,
            'lan_subnet': self.lan_subnet,
            'mgmt_subnet': self.mgmt_subnet,
        }


@dataclass
class TwinSnapshot:
    """Complete snapshot of the digital twin state."""
    twin_id: str
    timestamp: datetime
    ovs: VirtualOVS
    devices: Dict[str, VirtualDevice]  # mac → device
    bubbles: Dict[str, VirtualBubble]  # bubble_id → bubble
    affinity_matrix: Dict[Tuple[str, str], float] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'twin_id': self.twin_id,
            'timestamp': self.timestamp.isoformat(),
            'ovs': self.ovs.to_dict(),
            'devices': {mac: d.to_dict() for mac, d in self.devices.items()},
            'bubbles': {bid: b.to_dict() for bid, b in self.bubbles.items()},
            'affinity_matrix': {
                f"{k[0]}:{k[1]}": v for k, v in self.affinity_matrix.items()
            },
            'qsecbit_scores': {
                mac: d.qsecbit_score for mac, d in self.devices.items()
            },
        }


class DigitalTwinSimulator:
    """
    Digital Twin Simulator for Fortress SDN environment.

    Creates a virtual replica of the Fortress network for safe
    attack simulation and defense testing.

    Usage:
        twin = DigitalTwinSimulator(config)
        snapshot = twin.create_snapshot()
        twin.inject_device(malicious_device)
        twin.simulate_attack('ter_replay', target_bubble='family-dad')
    """

    # Default VLAN assignments
    DEFAULT_VLANS = {
        100: 'LAN',
        110: 'FAMILY',
        120: 'WORK',
        130: 'IOT',
        150: 'GUEST',
        200: 'MGMT',
        999: 'QUARANTINE',
    }

    # Sample device templates
    DEVICE_TEMPLATES = {
        'iphone': {
            'vendor': 'Apple',
            'ecosystem': DeviceEcosystem.APPLE,
            'dhcp_option_55': [1, 121, 3, 6, 15, 119, 252],
            'os_fingerprint': 'iOS 17',
        },
        'macbook': {
            'vendor': 'Apple',
            'ecosystem': DeviceEcosystem.APPLE,
            'dhcp_option_55': [1, 121, 3, 6, 15, 119, 252, 95, 44, 46],
            'os_fingerprint': 'macOS Sonoma',
        },
        'android_phone': {
            'vendor': 'Samsung',
            'ecosystem': DeviceEcosystem.ANDROID,
            'dhcp_option_55': [1, 3, 6, 15, 26, 28, 51, 58, 59, 43],
            'os_fingerprint': 'Android 14',
        },
        'windows_laptop': {
            'vendor': 'Microsoft',
            'ecosystem': DeviceEcosystem.WINDOWS,
            'dhcp_option_55': [1, 15, 3, 6, 44, 46, 47, 31, 33, 249, 43],
            'os_fingerprint': 'Windows 11',
        },
        'iot_camera': {
            'vendor': 'Nest',
            'ecosystem': DeviceEcosystem.IOT,
            'dhcp_option_55': [1, 3, 6, 15],
            'os_fingerprint': 'Linux embedded',
        },
    }

    def __init__(self, config: TwinConfig = None):
        self.config = config or TwinConfig()
        self._lock = threading.RLock()

        # Twin state
        self._ovs = VirtualOVS()
        self._devices: Dict[str, VirtualDevice] = {}
        self._bubbles: Dict[str, VirtualBubble] = {}
        self._affinity_matrix: Dict[Tuple[str, str], float] = {}

        # Sync state
        self._last_sync: Optional[datetime] = None
        self._sync_thread: Optional[threading.Thread] = None
        self._sync_running = False

        # History
        self._snapshots: List[TwinSnapshot] = []
        self._attack_log: List[Dict] = []

        # Ensure data directory
        TWIN_DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Load persisted state if available
        if self.config.persist_state:
            self._load_state()

        # Start auto-sync if enabled
        if self.config.auto_sync:
            self._start_sync()

        logger.info(f"DigitalTwinSimulator initialized: {self.config.twin_id}")

    def _start_sync(self):
        """Start background sync thread."""
        self._sync_running = True
        self._sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._sync_thread.start()

    def _sync_loop(self):
        """Background thread for periodic sync."""
        while self._sync_running:
            try:
                self.sync_from_fortress()
            except Exception as e:
                logger.debug(f"Sync error: {e}")

            time.sleep(self.config.sync_interval)

    def stop(self):
        """Stop the twin simulator."""
        self._sync_running = False
        if self._sync_thread:
            self._sync_thread.join(timeout=5.0)

    def sync_from_fortress(self) -> bool:
        """
        Sync state from the real Fortress node.

        Queries Fortress API for:
        - Device list
        - Bubble assignments
        - QSECBIT scores
        - Affinity relationships
        """
        try:
            # Try to load Fortress state from local file (shared via volume/file)
            import json
            data_file = os.environ.get(
                "FORTRESS_STATE_FILE",
                "/opt/hookprobe/data/fortress_state.json",
            )
            try:
                with open(data_file) as f:
                    state = json.load(f)
                for device_data in state.get("devices", []):
                    if hasattr(self, '_import_device'):
                        self._import_device(device_data)
                logger.info(
                    "Synced %d devices from Fortress state file",
                    len(state.get("devices", [])),
                )
            except FileNotFoundError:
                # No state file — fall back to mock data if empty
                if not self._devices:
                    self._generate_mock_network()

            self._last_sync = datetime.now()
            logger.debug("Synced from Fortress: %d devices", len(self._devices))
            return True

        except Exception as e:
            logger.warning("Fortress sync failed: %s", e)
            return False

    def _generate_mock_network(self):
        """Generate a mock network for testing."""
        with self._lock:
            # Initialize OVS
            self._ovs = VirtualOVS(
                bridge_name="FTS",
                vlans=self.DEFAULT_VLANS.copy(),
                lan_subnet="10.200.0.0/24",
            )

            # Create bubbles
            self._bubbles = {
                'family-dad': VirtualBubble(
                    bubble_id='family-dad',
                    name="Dad's Devices",
                    bubble_type=BubbleType.FAMILY,
                    vlan=110,
                    internet_access=True,
                    lan_access=True,
                    d2d_access=True,
                ),
                'family-mom': VirtualBubble(
                    bubble_id='family-mom',
                    name="Mom's Devices",
                    bubble_type=BubbleType.FAMILY,
                    vlan=110,
                    internet_access=True,
                    lan_access=True,
                    d2d_access=True,
                ),
                'family-kids': VirtualBubble(
                    bubble_id='family-kids',
                    name="Kids' Devices",
                    bubble_type=BubbleType.FAMILY,
                    vlan=110,
                    internet_access=True,
                    lan_access=True,
                    d2d_access=True,
                ),
                'guests': VirtualBubble(
                    bubble_id='guests',
                    name="Guest Devices",
                    bubble_type=BubbleType.GUEST,
                    vlan=150,
                    internet_access=True,
                    lan_access=False,
                    d2d_access=False,
                ),
                'iot': VirtualBubble(
                    bubble_id='iot',
                    name="IoT Devices",
                    bubble_type=BubbleType.IOT,
                    vlan=130,
                    internet_access=True,
                    lan_access=False,
                    d2d_access=True,
                ),
            }

            # Create devices
            devices_config = [
                # Dad's devices
                ('AA:BB:CC:DD:EE:01', '10.200.0.10', "Dad's iPhone", 'iphone', 'family-dad', 7, 23),
                ('AA:BB:CC:DD:EE:02', '10.200.0.11', "Dad's MacBook", 'macbook', 'family-dad', 8, 22),
                # Mom's devices
                ('AA:BB:CC:DD:EE:03', '10.200.0.20', "Mom's iPhone", 'iphone', 'family-mom', 6, 22),
                ('AA:BB:CC:DD:EE:04', '10.200.0.21', "Mom's iPad", 'iphone', 'family-mom', 9, 21),
                # Kids' devices
                ('AA:BB:CC:DD:EE:05', '10.200.0.30', "Kids' Samsung", 'android_phone', 'family-kids', 14, 21),
                ('AA:BB:CC:DD:EE:06', '10.200.0.31', "Gaming PC", 'windows_laptop', 'family-kids', 15, 23),
                # Guests
                ('AA:BB:CC:DD:EE:07', '10.200.0.100', "Guest Phone", 'android_phone', 'guests', 10, 18),
                # IoT
                ('AA:BB:CC:DD:EE:08', '10.200.0.200', "Living Room Camera", 'iot_camera', 'iot', 0, 24),
                ('AA:BB:CC:DD:EE:09', '10.200.0.201', "Front Door Camera", 'iot_camera', 'iot', 0, 24),
            ]

            for mac, ip, hostname, template, bubble_id, wake, sleep in devices_config:
                template_data = self.DEVICE_TEMPLATES.get(template, {})
                device = VirtualDevice(
                    mac=mac,
                    ip=ip,
                    hostname=hostname,
                    vendor=template_data.get('vendor', 'Unknown'),
                    ecosystem=template_data.get('ecosystem', DeviceEcosystem.UNKNOWN),
                    bubble_id=bubble_id,
                    bubble_type=self._bubbles[bubble_id].bubble_type,
                    qsecbit_score=random.uniform(0.65, 0.95),
                    trust_score=random.uniform(0.5, 0.9),
                    nse_resonance=random.uniform(0.4, 0.8),
                    wake_hour=wake,
                    sleep_hour=sleep,
                    dhcp_option_55=template_data.get('dhcp_option_55', []),
                    os_fingerprint=template_data.get('os_fingerprint', ''),
                )
                device.active_hours = set(range(wake, sleep))
                self._devices[mac] = device
                self._bubbles[bubble_id].devices.add(mac)
                self._bubbles[bubble_id].device_count += 1

            # Set up affinities (devices that communicate)
            # Dad's devices talk to each other
            self._affinity_matrix[('AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02')] = 0.85
            # Mom's devices talk to each other
            self._affinity_matrix[('AA:BB:CC:DD:EE:03', 'AA:BB:CC:DD:EE:04')] = 0.90
            # Kids' devices talk to each other
            self._affinity_matrix[('AA:BB:CC:DD:EE:05', 'AA:BB:CC:DD:EE:06')] = 0.75
            # IoT devices communicate
            self._affinity_matrix[('AA:BB:CC:DD:EE:08', 'AA:BB:CC:DD:EE:09')] = 0.60

            logger.info(f"Generated mock network: {len(self._devices)} devices, {len(self._bubbles)} bubbles")

    def create_snapshot(self) -> Dict:
        """
        Create a snapshot of the current twin state.

        Returns a dictionary suitable for attack simulation.
        """
        with self._lock:
            snapshot = TwinSnapshot(
                twin_id=self.config.twin_id,
                timestamp=datetime.now(),
                ovs=copy.deepcopy(self._ovs),
                devices=copy.deepcopy(self._devices),
                bubbles=copy.deepcopy(self._bubbles),
                affinity_matrix=copy.deepcopy(self._affinity_matrix),
            )
            self._snapshots.append(snapshot)
            return snapshot.to_dict()

    def get_device(self, mac: str) -> Optional[VirtualDevice]:
        """Get a device by MAC address."""
        return self._devices.get(mac.upper())

    def get_bubble(self, bubble_id: str) -> Optional[VirtualBubble]:
        """Get a bubble by ID."""
        return self._bubbles.get(bubble_id)

    def get_devices_in_bubble(self, bubble_id: str) -> List[VirtualDevice]:
        """Get all devices in a bubble."""
        bubble = self._bubbles.get(bubble_id)
        if not bubble:
            return []
        return [self._devices[mac] for mac in bubble.devices if mac in self._devices]

    def inject_device(self, device: VirtualDevice) -> bool:
        """
        Inject a device into the twin for attack simulation.

        This allows testing what happens when a malicious or unknown
        device appears on the network.
        """
        with self._lock:
            mac = device.mac.upper()
            self._devices[mac] = device

            if device.bubble_id and device.bubble_id in self._bubbles:
                self._bubbles[device.bubble_id].devices.add(mac)
                self._bubbles[device.bubble_id].device_count += 1

            self._attack_log.append({
                'action': 'inject_device',
                'mac': mac,
                'bubble': device.bubble_id,
                'timestamp': datetime.now().isoformat(),
            })

            logger.info(f"Injected device {mac} into bubble {device.bubble_id}")
            return True

    def remove_device(self, mac: str) -> bool:
        """Remove a device from the twin."""
        with self._lock:
            mac = mac.upper()
            if mac not in self._devices:
                return False

            device = self._devices.pop(mac)
            if device.bubble_id and device.bubble_id in self._bubbles:
                self._bubbles[device.bubble_id].devices.discard(mac)
                self._bubbles[device.bubble_id].device_count -= 1

            # Clean affinity matrix
            keys_to_remove = [k for k in self._affinity_matrix if mac in k]
            for key in keys_to_remove:
                del self._affinity_matrix[key]

            return True

    def move_device_to_bubble(self, mac: str, new_bubble_id: str) -> bool:
        """Move a device to a different bubble."""
        with self._lock:
            mac = mac.upper()
            if mac not in self._devices:
                return False
            if new_bubble_id not in self._bubbles:
                return False

            device = self._devices[mac]
            old_bubble_id = device.bubble_id

            # Remove from old bubble
            if old_bubble_id in self._bubbles:
                self._bubbles[old_bubble_id].devices.discard(mac)
                self._bubbles[old_bubble_id].device_count -= 1

            # Add to new bubble
            device.bubble_id = new_bubble_id
            device.bubble_type = self._bubbles[new_bubble_id].bubble_type
            self._bubbles[new_bubble_id].devices.add(mac)
            self._bubbles[new_bubble_id].device_count += 1

            self._attack_log.append({
                'action': 'move_device',
                'mac': mac,
                'old_bubble': old_bubble_id,
                'new_bubble': new_bubble_id,
                'timestamp': datetime.now().isoformat(),
            })

            return True

    def update_qsecbit_score(self, mac: str, new_score: float) -> bool:
        """Update the QSECBIT score for a device."""
        with self._lock:
            mac = mac.upper()
            if mac not in self._devices:
                return False

            old_score = self._devices[mac].qsecbit_score
            self._devices[mac].qsecbit_score = max(0.0, min(1.0, new_score))

            self._attack_log.append({
                'action': 'update_qsecbit',
                'mac': mac,
                'old_score': old_score,
                'new_score': new_score,
                'timestamp': datetime.now().isoformat(),
            })

            return True

    def update_affinity(self, mac_a: str, mac_b: str, affinity: float) -> bool:
        """Update affinity score between two devices."""
        with self._lock:
            mac_a = mac_a.upper()
            mac_b = mac_b.upper()

            if mac_a not in self._devices or mac_b not in self._devices:
                return False

            # Normalize key order
            key = tuple(sorted([mac_a, mac_b]))
            self._affinity_matrix[key] = max(0.0, min(1.0, affinity))

            # Update device affinity dicts
            self._devices[mac_a].affinities[mac_b] = affinity
            self._devices[mac_b].affinities[mac_a] = affinity

            return True

    def simulate_temporal_event(self, mac: str, event_type: str) -> Dict:
        """
        Simulate a temporal event (wake/sleep) for a device.

        Used to test temporal pattern detection.
        """
        with self._lock:
            mac = mac.upper()
            if mac not in self._devices:
                return {'error': 'Device not found'}

            device = self._devices[mac]
            now = datetime.now()
            hour = now.hour

            if event_type == 'wake':
                device.state = DeviceState.ACTIVE
                device.active_hours.add(hour)
                device.last_seen = now
            elif event_type == 'sleep':
                device.state = DeviceState.DORMANT
            else:
                return {'error': f'Unknown event type: {event_type}'}

            return {
                'mac': mac,
                'event_type': event_type,
                'timestamp': now.isoformat(),
                'state': device.state.value,
            }

    def get_affinity(self, mac_a: str, mac_b: str) -> float:
        """Get affinity score between two devices."""
        key = tuple(sorted([mac_a.upper(), mac_b.upper()]))
        return self._affinity_matrix.get(key, 0.0)

    def get_high_affinity_pairs(self, threshold: float = 0.5) -> List[Tuple[str, str, float]]:
        """Get all device pairs with affinity above threshold."""
        pairs = []
        for (mac_a, mac_b), affinity in self._affinity_matrix.items():
            if affinity >= threshold:
                pairs.append((mac_a, mac_b, affinity))
        return sorted(pairs, key=lambda x: x[2], reverse=True)

    def get_attack_log(self) -> List[Dict]:
        """Get the attack/modification log."""
        return self._attack_log.copy()

    def reset_to_snapshot(self, snapshot_index: int = 0) -> bool:
        """Reset twin state to a previous snapshot."""
        if snapshot_index >= len(self._snapshots):
            return False

        snapshot = self._snapshots[snapshot_index]
        with self._lock:
            self._ovs = copy.deepcopy(snapshot.ovs)
            self._devices = copy.deepcopy(snapshot.devices)
            self._bubbles = copy.deepcopy(snapshot.bubbles)
            self._affinity_matrix = copy.deepcopy(snapshot.affinity_matrix)

        return True

    def _save_state(self):
        """Save twin state to disk."""
        if not self.config.persist_state:
            return

        state_path = TWIN_DATA_DIR / f"{self.config.twin_id}.json"
        state = {
            'twin_id': self.config.twin_id,
            'timestamp': datetime.now().isoformat(),
            'ovs': self._ovs.to_dict(),
            'devices': {mac: d.to_dict() for mac, d in self._devices.items()},
            'bubbles': {bid: b.to_dict() for bid, b in self._bubbles.items()},
            'affinity_matrix': {f"{k[0]}:{k[1]}": v for k, v in self._affinity_matrix.items()},
        }

        with open(state_path, 'w') as f:
            json.dump(state, f, indent=2)

    def _load_state(self):
        """Load twin state from disk."""
        state_path = TWIN_DATA_DIR / f"{self.config.twin_id}.json"
        if not state_path.exists():
            return

        try:
            with open(state_path, 'r') as f:
                state = json.load(f)

            with self._lock:
                # Load OVS
                ovs_data = state.get('ovs', {})
                self._ovs = VirtualOVS(
                    bridge_name=ovs_data.get('bridge_name', 'FTS'),
                    vlans=ovs_data.get('vlans', {}),
                    flows=ovs_data.get('flows', []),
                    ports=ovs_data.get('ports', []),
                    lan_subnet=ovs_data.get('lan_subnet', '10.200.0.0/24'),
                )

                # Load devices
                for mac, device_data in state.get('devices', {}).items():
                    self._devices[mac] = VirtualDevice.from_dict(device_data)

                # Load bubbles
                for bubble_id, bubble_data in state.get('bubbles', {}).items():
                    self._bubbles[bubble_id] = VirtualBubble.from_dict(bubble_data)

                # Load affinity matrix
                for key_str, affinity in state.get('affinity_matrix', {}).items():
                    mac_a, mac_b = key_str.split(':')
                    self._affinity_matrix[(mac_a, mac_b)] = affinity

            logger.info(f"Loaded twin state: {len(self._devices)} devices")

        except Exception as e:
            logger.warning(f"Failed to load twin state: {e}")

    def get_stats(self) -> Dict:
        """Get twin statistics."""
        return {
            'twin_id': self.config.twin_id,
            'device_count': len(self._devices),
            'bubble_count': len(self._bubbles),
            'affinity_pairs': len(self._affinity_matrix),
            'snapshot_count': len(self._snapshots),
            'attack_log_entries': len(self._attack_log),
            'last_sync': self._last_sync.isoformat() if self._last_sync else None,
            'sync_running': self._sync_running,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_digital_twin(
    fortress_ip: str = "127.0.0.1",
    auto_sync: bool = True,
) -> DigitalTwinSimulator:
    """Create a digital twin with common defaults."""
    config = TwinConfig(
        fortress_ip=fortress_ip,
        auto_sync=auto_sync,
    )
    return DigitalTwinSimulator(config)


def create_test_twin() -> DigitalTwinSimulator:
    """Create a digital twin with mock data for testing."""
    config = TwinConfig(
        auto_sync=False,
        persist_state=False,
    )
    twin = DigitalTwinSimulator(config)
    twin._generate_mock_network()
    return twin


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='Digital Twin Simulator')
    parser.add_argument('command', choices=['create', 'snapshot', 'stats', 'devices', 'bubbles'])
    parser.add_argument('--fortress-ip', default='127.0.0.1', help='Fortress IP')
    args = parser.parse_args()

    twin = create_test_twin()

    if args.command == 'create':
        print(f"Created digital twin: {twin.config.twin_id}")
        print(f"Stats: {twin.get_stats()}")

    elif args.command == 'snapshot':
        snapshot = twin.create_snapshot()
        print(json.dumps(snapshot, indent=2, default=str))

    elif args.command == 'stats':
        stats = twin.get_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")

    elif args.command == 'devices':
        for mac, device in twin._devices.items():
            print(f"  {mac}: {device.hostname} ({device.bubble_id}) - QSECBIT: {device.qsecbit_score:.2f}")

    elif args.command == 'bubbles':
        for bubble_id, bubble in twin._bubbles.items():
            print(f"  {bubble_id}: {bubble.name} ({len(bubble.devices)} devices) - VLAN {bubble.vlan}")
