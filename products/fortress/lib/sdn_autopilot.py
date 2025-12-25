#!/usr/bin/env python3
"""
Fortress SDN Auto-Pilot

Intelligent device classification and automatic VLAN segmentation using:
- OUI (vendor) fingerprinting
- Protocol detection (Matter, Thread, Zigbee)
- Behavioral analysis
- OpenFlow-based micro-segmentation

Network Segments:
  VLAN 10: SecMON   - Security monitoring (NVR, SIEM, sensors)
  VLAN 20: POS      - Point of Sale terminals
  VLAN 30: Clients  - Staff devices (laptops, phones)
  VLAN 50: Cameras  - IP cameras, CCTV
  VLAN 60: IIoT     - IoT devices (thermostats, Matter/Thread)
  VLAN 99: Quarantine - Suspicious/unknown devices

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0
"""

import logging
import re
import json
import subprocess
import hashlib
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import IntEnum, Enum
from pathlib import Path

logger = logging.getLogger(__name__)


# =============================================================================
# Network Segment Definitions
# =============================================================================

class NetworkSegment(IntEnum):
    """Network segment VLAN IDs for small business deployment."""
    SECMON = 10       # Security monitoring devices
    POS = 20          # Point of Sale terminals
    CLIENTS = 30      # Staff devices (laptops, phones)
    CAMERAS = 50      # IP cameras, CCTV
    IIOT = 60         # IoT devices (Matter/Thread/Zigbee)
    GUEST = 40        # Guest WiFi
    QUARANTINE = 99   # Suspicious devices


class DeviceCategory(str, Enum):
    """Device classification categories."""
    SECMON = "secmon"           # Security monitoring
    POS = "pos"                 # Point of Sale
    CLIENT = "client"           # Staff devices
    CAMERA = "camera"           # IP cameras
    IIOT = "iiot"               # Industrial IoT
    NETWORK = "network"         # Network equipment
    PRINTER = "printer"         # Printers
    UNKNOWN = "unknown"         # Unknown devices


class ProtocolType(str, Enum):
    """IoT protocol types."""
    MATTER = "matter"
    THREAD = "thread"
    ZIGBEE = "zigbee"
    ZWAVE = "zwave"
    WIFI = "wifi"
    ETHERNET = "ethernet"


# =============================================================================
# OUI Database - Vendor Classification
# =============================================================================

# Comprehensive OUI database for device fingerprinting
# Format: 'OUI_PREFIX': ('VENDOR', DeviceCategory, NetworkSegment)
OUI_DATABASE: Dict[str, Tuple[str, DeviceCategory, NetworkSegment]] = {
    # ----- POS / Payment Terminals -----
    '00:0B:CD': ('Ingenico', DeviceCategory.POS, NetworkSegment.POS),
    '00:17:EB': ('Ingenico', DeviceCategory.POS, NetworkSegment.POS),
    '00:20:44': ('Verifone', DeviceCategory.POS, NetworkSegment.POS),
    '00:0A:27': ('Verifone', DeviceCategory.POS, NetworkSegment.POS),
    '00:13:B4': ('Verifone', DeviceCategory.POS, NetworkSegment.POS),
    '00:E0:00': ('Clover', DeviceCategory.POS, NetworkSegment.POS),
    '00:24:D1': ('PAX Technology', DeviceCategory.POS, NetworkSegment.POS),
    '00:26:57': ('Castles Technology', DeviceCategory.POS, NetworkSegment.POS),
    '64:62:66': ('Square', DeviceCategory.POS, NetworkSegment.POS),

    # ----- IP Cameras / CCTV -----
    '00:0C:F6': ('Axis Communications', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    'AC:CC:8E': ('Axis Communications', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '00:40:8C': ('Hikvision', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '28:57:BE': ('Hikvision', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '54:C4:15': ('Hikvision', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '44:19:B6': ('Hikvision', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '00:1F:54': ('Dahua', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '3C:EF:8C': ('Dahua', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    'D4:6E:5C': ('Dahua', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '00:04:A5': ('Vivotek', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '00:E0:18': ('Bosch Security', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '00:0F:3D': ('D-Link (Cameras)', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '18:AE:BB': ('Reolink', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    '9C:8E:CD': ('Amcrest', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    'B0:C5:54': ('Ubiquiti UniFi Protect', DeviceCategory.CAMERA, NetworkSegment.CAMERAS),

    # ----- NVR / Security Monitoring -----
    '00:0D:7C': ('Synology (NVR)', DeviceCategory.SECMON, NetworkSegment.SECMON),
    '00:11:32': ('Synology', DeviceCategory.SECMON, NetworkSegment.SECMON),
    '00:24:21': ('QNAP', DeviceCategory.SECMON, NetworkSegment.SECMON),
    '24:5E:BE': ('QNAP', DeviceCategory.SECMON, NetworkSegment.SECMON),
    '00:18:4D': ('Milestone Systems', DeviceCategory.SECMON, NetworkSegment.SECMON),

    # ----- IoT / Smart Home (Matter/Thread capable) -----
    'D4:F5:47': ('Google Nest', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '18:B4:30': ('Nest Labs', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '64:16:66': ('Nest Labs', DeviceCategory.IIOT, NetworkSegment.IIOT),
    'F4:F5:D8': ('Google Home', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '30:FD:38': ('Google Nest Hub', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '94:EB:2C': ('Google', DeviceCategory.IIOT, NetworkSegment.IIOT),
    'B0:FC:0D': ('Amazon Echo', DeviceCategory.IIOT, NetworkSegment.IIOT),
    'F0:F0:A4': ('Amazon Alexa', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '68:54:FD': ('Amazon Echo', DeviceCategory.IIOT, NetworkSegment.IIOT),
    'FC:65:DE': ('Amazon Echo', DeviceCategory.IIOT, NetworkSegment.IIOT),
    'D0:73:D5': ('Ring', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '0C:47:C9': ('Ring', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '34:86:5D': ('Ecobee', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '44:61:32': ('Ecobee', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '00:17:88': ('Philips Hue', DeviceCategory.IIOT, NetworkSegment.IIOT),
    'EC:B5:FA': ('Philips Hue', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '00:0D:6F': ('Ember (Zigbee)', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '84:18:26': ('Silicon Labs (Thread)', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '60:A4:23': ('Silicon Labs (Matter)', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '00:12:4B': ('Texas Instruments (Zigbee)', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '00:0B:57': ('Nordic Semiconductor (Thread)', DeviceCategory.IIOT, NetworkSegment.IIOT),
    'C4:7C:8D': ('Nordic Semiconductor', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '00:1E:C0': ('Tado', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '70:EE:50': ('Netatmo', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '00:04:74': ('Honeywell', DeviceCategory.IIOT, NetworkSegment.IIOT),
    'C0:C1:C0': ('Honeywell', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '00:18:2A': ('Schneider Electric', DeviceCategory.IIOT, NetworkSegment.IIOT),
    '00:13:A2': ('Digi International (Zigbee)', DeviceCategory.IIOT, NetworkSegment.IIOT),

    # ----- Staff Devices / Clients -----
    # Apple
    '00:1C:B3': ('Apple', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:03:93': ('Apple', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:1D:4F': ('Apple', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    'A4:5E:60': ('Apple', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    'AC:BC:32': ('Apple', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    'B0:34:95': ('Apple', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    'B8:09:8A': ('Apple', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    'D4:9A:20': ('Apple', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    'DC:2B:2A': ('Apple', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    'F0:B4:79': ('Apple', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    # Samsung
    '00:00:F0': ('Samsung', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:12:47': ('Samsung', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:15:B9': ('Samsung', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:17:D5': ('Samsung', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:21:D1': ('Samsung', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:26:37': ('Samsung', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:E0:64': ('Samsung', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    # Dell
    '00:06:5B': ('Dell', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:08:74': ('Dell', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:0B:DB': ('Dell', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:0D:56': ('Dell', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:11:43': ('Dell', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:14:22': ('Dell', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    # HP
    '00:01:E6': ('HP', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:02:A5': ('HP', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:04:EA': ('HP', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:0A:57': ('HP', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    # Lenovo
    '00:06:1B': ('Lenovo', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:09:2D': ('Lenovo', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:1A:6B': ('Lenovo', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:21:6A': ('Lenovo', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    # Intel (laptops/desktops)
    '00:02:B3': ('Intel', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:03:47': ('Intel', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    '00:13:02': ('Intel', DeviceCategory.CLIENT, NetworkSegment.CLIENTS),

    # ----- Printers -----
    '00:00:48': ('HP Printer', DeviceCategory.PRINTER, NetworkSegment.IIOT),
    '00:60:B0': ('HP Printer', DeviceCategory.PRINTER, NetworkSegment.IIOT),
    '00:80:77': ('Brother', DeviceCategory.PRINTER, NetworkSegment.IIOT),
    '00:1B:A9': ('Brother', DeviceCategory.PRINTER, NetworkSegment.IIOT),
    '00:00:74': ('Canon', DeviceCategory.PRINTER, NetworkSegment.IIOT),
    '00:1E:8F': ('Canon', DeviceCategory.PRINTER, NetworkSegment.IIOT),
    '00:00:00': ('Xerox', DeviceCategory.PRINTER, NetworkSegment.IIOT),
    '00:00:AA': ('Xerox', DeviceCategory.PRINTER, NetworkSegment.IIOT),
    '00:21:B7': ('Epson', DeviceCategory.PRINTER, NetworkSegment.IIOT),

    # ----- Network Equipment (internal monitoring) -----
    '00:00:0C': ('Cisco', DeviceCategory.NETWORK, NetworkSegment.SECMON),
    '00:01:42': ('Cisco', DeviceCategory.NETWORK, NetworkSegment.SECMON),
    '00:17:94': ('Cisco', DeviceCategory.NETWORK, NetworkSegment.SECMON),
    '00:27:19': ('TP-Link', DeviceCategory.NETWORK, NetworkSegment.SECMON),
    '14:CC:20': ('TP-Link', DeviceCategory.NETWORK, NetworkSegment.SECMON),
    '50:C7:BF': ('TP-Link', DeviceCategory.NETWORK, NetworkSegment.SECMON),
    '00:1D:7E': ('Netgear', DeviceCategory.NETWORK, NetworkSegment.SECMON),
    '20:4E:7F': ('Netgear', DeviceCategory.NETWORK, NetworkSegment.SECMON),
    'B4:FB:E4': ('Ubiquiti', DeviceCategory.NETWORK, NetworkSegment.SECMON),
    '04:18:D6': ('Ubiquiti', DeviceCategory.NETWORK, NetworkSegment.SECMON),
    'DC:9F:DB': ('Ubiquiti', DeviceCategory.NETWORK, NetworkSegment.SECMON),
}

# Hostname patterns for classification
HOSTNAME_PATTERNS: Dict[str, Tuple[DeviceCategory, NetworkSegment]] = {
    r'(?i)(pos|payment|terminal|register|till)': (DeviceCategory.POS, NetworkSegment.POS),
    r'(?i)(cam|camera|cctv|nvr|dvr|ipcam)': (DeviceCategory.CAMERA, NetworkSegment.CAMERAS),
    r'(?i)(siem|ids|ips|sensor|monitor|nvr)': (DeviceCategory.SECMON, NetworkSegment.SECMON),
    r'(?i)(nest|thermostat|ecobee|hue|alexa|echo|home)': (DeviceCategory.IIOT, NetworkSegment.IIOT),
    r'(?i)(iphone|ipad|macbook|android|galaxy|pixel)': (DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    r'(?i)(laptop|desktop|workstation|pc-|win-)': (DeviceCategory.CLIENT, NetworkSegment.CLIENTS),
    r'(?i)(printer|print|hp-|brother|canon|epson)': (DeviceCategory.PRINTER, NetworkSegment.IIOT),
}


# =============================================================================
# Device Fingerprint
# =============================================================================

@dataclass
class DeviceFingerprint:
    """Complete device fingerprint for classification."""
    mac_address: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    category: DeviceCategory = DeviceCategory.UNKNOWN
    segment: NetworkSegment = NetworkSegment.QUARANTINE
    protocol: Optional[ProtocolType] = None
    confidence: float = 0.0
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())

    # Traffic metrics
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0

    # Classification metadata
    oui_match: bool = False
    hostname_match: bool = False
    dhcp_fingerprint: Optional[str] = None
    user_assigned: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'mac_address': self.mac_address,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'category': self.category.value,
            'segment': self.segment.value,
            'segment_name': self.segment.name,
            'protocol': self.protocol.value if self.protocol else None,
            'confidence': self.confidence,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out,
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
        }


@dataclass
class SegmentStats:
    """Traffic statistics for a network segment."""
    segment: NetworkSegment
    device_count: int = 0
    active_count: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    bandwidth_mbps: float = 0.0
    # Time-series for visualization (last 60 samples)
    traffic_history: List[Dict[str, Any]] = field(default_factory=list)

    def add_sample(self, timestamp: float, bytes_in: int, bytes_out: int):
        """Add a traffic sample for visualization."""
        self.traffic_history.append({
            'ts': timestamp,
            'in': bytes_in,
            'out': bytes_out,
        })
        # Keep last 60 samples (1 minute at 1-second intervals)
        if len(self.traffic_history) > 60:
            self.traffic_history = self.traffic_history[-60:]


# =============================================================================
# SDN Auto-Pilot Engine
# =============================================================================

class SDNAutoPilot:
    """
    Intelligent SDN controller for automatic device classification and segmentation.

    Features:
    - OUI-based vendor identification
    - Protocol detection (Matter/Thread/Zigbee)
    - Behavioral fingerprinting
    - Automatic VLAN assignment
    - OpenFlow rule generation
    - Per-segment traffic monitoring
    """

    def __init__(self, ovs_bridge: str = 'FTS', config_path: str = '/etc/hookprobe'):
        self.ovs_bridge = ovs_bridge
        self.config_path = Path(config_path)

        # Device registry
        self.devices: Dict[str, DeviceFingerprint] = {}

        # Segment statistics
        self.segment_stats: Dict[NetworkSegment, SegmentStats] = {
            seg: SegmentStats(segment=seg) for seg in NetworkSegment
        }

        # User overrides (MAC -> segment)
        self.user_assignments: Dict[str, NetworkSegment] = {}

        # OpenFlow flow cache
        self._flow_cache: Set[str] = set()

        # Load persistent config
        self._load_config()

        logger.info(f"SDN Auto-Pilot initialized for bridge {ovs_bridge}")

    def _load_config(self):
        """Load persistent configuration."""
        config_file = self.config_path / 'sdn_autopilot.json'
        if config_file.exists():
            try:
                with open(config_file) as f:
                    config = json.load(f)
                self.user_assignments = {
                    mac: NetworkSegment(vlan)
                    for mac, vlan in config.get('user_assignments', {}).items()
                }
                logger.info(f"Loaded {len(self.user_assignments)} user assignments")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")

    def _save_config(self):
        """Save persistent configuration."""
        config_file = self.config_path / 'sdn_autopilot.json'
        try:
            config = {
                'user_assignments': {
                    mac: seg.value for mac, seg in self.user_assignments.items()
                }
            }
            config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save config: {e}")

    # =========================================================================
    # Device Classification
    # =========================================================================

    def classify_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
        hostname: Optional[str] = None
    ) -> DeviceFingerprint:
        """
        Classify a device and determine its network segment.

        Classification priority:
        1. User manual assignment
        2. OUI database match
        3. Hostname pattern match
        4. DHCP fingerprint
        5. Default to quarantine

        Returns:
            DeviceFingerprint with classification results
        """
        mac = mac_address.upper()
        oui = mac[:8]

        # Check if already classified
        if mac in self.devices:
            fp = self.devices[mac]
            fp.last_seen = datetime.now().isoformat()
            if ip_address:
                fp.ip_address = ip_address
            if hostname:
                fp.hostname = hostname
            return fp

        # Initialize fingerprint
        fp = DeviceFingerprint(
            mac_address=mac,
            ip_address=ip_address,
            hostname=hostname
        )

        # 1. Check user override first
        if mac in self.user_assignments:
            fp.segment = self.user_assignments[mac]
            fp.category = self._segment_to_category(fp.segment)
            fp.confidence = 1.0
            fp.user_assigned = True
            logger.info(f"Device {mac} -> VLAN {fp.segment.value} (user assigned)")

        # 2. OUI database lookup
        elif oui in OUI_DATABASE:
            vendor, category, segment = OUI_DATABASE[oui]
            fp.vendor = vendor
            fp.category = category
            fp.segment = segment
            fp.oui_match = True
            fp.confidence = 0.9
            logger.info(f"Device {mac} -> VLAN {segment.value} ({vendor}, OUI match)")

        # 3. Hostname pattern match
        elif hostname:
            for pattern, (category, segment) in HOSTNAME_PATTERNS.items():
                if re.search(pattern, hostname):
                    fp.category = category
                    fp.segment = segment
                    fp.hostname_match = True
                    fp.confidence = 0.7
                    logger.info(f"Device {mac} -> VLAN {segment.value} (hostname: {hostname})")
                    break

        # 4. Default to quarantine for unknown devices
        if fp.segment == NetworkSegment.QUARANTINE and not fp.user_assigned:
            fp.confidence = 0.3
            logger.warning(f"Unknown device {mac} -> VLAN 99 (quarantine)")

        # Store device
        self.devices[mac] = fp

        # Update segment stats
        self.segment_stats[fp.segment].device_count += 1

        return fp

    def _segment_to_category(self, segment: NetworkSegment) -> DeviceCategory:
        """Map segment to default category."""
        mapping = {
            NetworkSegment.SECMON: DeviceCategory.SECMON,
            NetworkSegment.POS: DeviceCategory.POS,
            NetworkSegment.CLIENTS: DeviceCategory.CLIENT,
            NetworkSegment.CAMERAS: DeviceCategory.CAMERA,
            NetworkSegment.IIOT: DeviceCategory.IIOT,
            NetworkSegment.GUEST: DeviceCategory.UNKNOWN,
            NetworkSegment.QUARANTINE: DeviceCategory.UNKNOWN,
        }
        return mapping.get(segment, DeviceCategory.UNKNOWN)

    def assign_device_segment(
        self,
        mac_address: str,
        segment: NetworkSegment,
        persist: bool = True
    ) -> bool:
        """
        Manually assign a device to a network segment.

        Args:
            mac_address: Device MAC address
            segment: Target network segment
            persist: Save to persistent config

        Returns:
            True if successful
        """
        mac = mac_address.upper()

        # Update or create fingerprint
        if mac in self.devices:
            old_segment = self.devices[mac].segment
            self.segment_stats[old_segment].device_count -= 1

            self.devices[mac].segment = segment
            self.devices[mac].category = self._segment_to_category(segment)
            self.devices[mac].user_assigned = True
            self.devices[mac].confidence = 1.0
        else:
            fp = DeviceFingerprint(
                mac_address=mac,
                segment=segment,
                category=self._segment_to_category(segment),
                user_assigned=True,
                confidence=1.0
            )
            self.devices[mac] = fp

        # Update segment stats
        self.segment_stats[segment].device_count += 1

        # Store user assignment
        self.user_assignments[mac] = segment

        if persist:
            self._save_config()

        # Apply OpenFlow rule
        self._apply_vlan_flow(mac, segment)

        logger.info(f"Device {mac} manually assigned to VLAN {segment.value} ({segment.name})")
        return True

    # =========================================================================
    # OpenFlow Integration
    # =========================================================================

    def _apply_vlan_flow(self, mac_address: str, segment: NetworkSegment):
        """Apply OpenFlow rule for MAC-to-VLAN mapping."""
        mac = mac_address.upper()
        vlan_id = segment.value

        # Create flow identifier for dedup
        flow_id = f"{mac}:{vlan_id}"
        if flow_id in self._flow_cache:
            return

        try:
            # Add OVS flow for VLAN tagging
            cmd = [
                'ovs-ofctl', 'add-flow', self.ovs_bridge,
                f'priority=200,dl_src={mac},actions=mod_vlan_vid:{vlan_id},normal'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                self._flow_cache.add(flow_id)
                logger.debug(f"Applied OVS flow: {mac} -> VLAN {vlan_id}")
            else:
                logger.warning(f"Failed to apply OVS flow: {result.stderr}")

        except Exception as e:
            logger.error(f"OVS flow error: {e}")

    def generate_openflow_rules(self) -> List[str]:
        """Generate all OpenFlow rules for current device mappings."""
        rules = []

        # Table 0: Ingress classification
        rules.append(f"table=0,priority=100,arp,actions=CONTROLLER")
        rules.append(f"table=0,priority=100,udp,tp_dst=67,actions=CONTROLLER")
        rules.append(f"table=0,priority=100,udp,tp_dst=68,actions=CONTROLLER")

        # Per-device VLAN rules (priority 200)
        for mac, fp in self.devices.items():
            vlan_id = fp.segment.value
            rules.append(
                f"table=0,priority=200,dl_src={mac},"
                f"actions=mod_vlan_vid:{vlan_id},goto_table:10"
            )

        # Table 10: Segment isolation
        for src_seg in NetworkSegment:
            for dst_seg in NetworkSegment:
                if src_seg == dst_seg:
                    # Same segment: allow
                    rules.append(
                        f"table=10,priority=100,dl_vlan={src_seg.value},"
                        f"actions=normal"
                    )
                elif self._allow_inter_segment(src_seg, dst_seg):
                    # Allowed cross-segment
                    rules.append(
                        f"table=10,priority=90,dl_vlan={src_seg.value},"
                        f"reg0={dst_seg.value},actions=normal"
                    )
                else:
                    # Block cross-segment (implicit drop)
                    pass

        # Default drop
        rules.append(f"table=10,priority=0,actions=drop")

        return rules

    def _allow_inter_segment(self, src: NetworkSegment, dst: NetworkSegment) -> bool:
        """Check if inter-segment traffic is allowed."""
        # Define allowed inter-segment communication
        allowed = {
            # SecMON can access all segments (for monitoring)
            (NetworkSegment.SECMON, NetworkSegment.CAMERAS): True,
            (NetworkSegment.SECMON, NetworkSegment.POS): True,
            (NetworkSegment.SECMON, NetworkSegment.CLIENTS): True,
            (NetworkSegment.SECMON, NetworkSegment.IIOT): True,
            # Clients can access printers (IIoT segment)
            (NetworkSegment.CLIENTS, NetworkSegment.IIOT): True,
            # POS is isolated (no cross-segment by default)
            # Cameras -> SecMON for NVR access
            (NetworkSegment.CAMERAS, NetworkSegment.SECMON): True,
        }
        return allowed.get((src, dst), False)

    # =========================================================================
    # Traffic Monitoring
    # =========================================================================

    def update_device_traffic(
        self,
        mac_address: str,
        bytes_in: int,
        bytes_out: int,
        packets_in: int = 0,
        packets_out: int = 0
    ):
        """Update traffic counters for a device."""
        mac = mac_address.upper()

        if mac not in self.devices:
            # Auto-classify if new
            self.classify_device(mac)

        fp = self.devices[mac]
        fp.bytes_in += bytes_in
        fp.bytes_out += bytes_out
        fp.packets_in += packets_in
        fp.packets_out += packets_out
        fp.last_seen = datetime.now().isoformat()

        # Update segment stats
        stats = self.segment_stats[fp.segment]
        stats.bytes_in += bytes_in
        stats.bytes_out += bytes_out
        stats.packets_in += packets_in
        stats.packets_out += packets_out

        # Add time-series sample
        stats.add_sample(time.time(), bytes_in, bytes_out)

    def get_segment_stats(self, segment: NetworkSegment) -> Dict[str, Any]:
        """Get statistics for a network segment."""
        stats = self.segment_stats[segment]

        # Calculate active devices (seen in last 5 minutes)
        cutoff = datetime.now() - timedelta(minutes=5)
        active = sum(
            1 for fp in self.devices.values()
            if fp.segment == segment and fp.last_seen > cutoff.isoformat()
        )
        stats.active_count = active

        return {
            'segment': segment.name,
            'vlan_id': segment.value,
            'device_count': stats.device_count,
            'active_count': stats.active_count,
            'bytes_in': stats.bytes_in,
            'bytes_out': stats.bytes_out,
            'packets_in': stats.packets_in,
            'packets_out': stats.packets_out,
            'bandwidth_mbps': stats.bandwidth_mbps,
            'traffic_history': stats.traffic_history[-60:],  # Last 60 samples
        }

    def get_all_segment_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all segments."""
        return {
            seg.name: self.get_segment_stats(seg)
            for seg in NetworkSegment
            if seg != NetworkSegment.QUARANTINE  # Exclude quarantine from dashboard
        }

    # =========================================================================
    # Device Queries
    # =========================================================================

    def get_devices_by_segment(self, segment: NetworkSegment) -> List[DeviceFingerprint]:
        """Get all devices in a segment."""
        return [
            fp for fp in self.devices.values()
            if fp.segment == segment
        ]

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Get all devices as list of dicts."""
        return [fp.to_dict() for fp in self.devices.values()]

    def get_device(self, mac_address: str) -> Optional[DeviceFingerprint]:
        """Get device by MAC address."""
        return self.devices.get(mac_address.upper())

    def get_segment_summary(self) -> Dict[str, Dict[str, Any]]:
        """Get summary for dashboard cards."""
        summary = {}
        for seg in [
            NetworkSegment.SECMON,
            NetworkSegment.CLIENTS,
            NetworkSegment.POS,
            NetworkSegment.CAMERAS,
            NetworkSegment.IIOT
        ]:
            stats = self.segment_stats[seg]
            devices = self.get_devices_by_segment(seg)

            # Calculate throughput (simplified)
            recent = stats.traffic_history[-10:] if stats.traffic_history else []
            if len(recent) >= 2:
                time_delta = recent[-1]['ts'] - recent[0]['ts']
                if time_delta > 0:
                    bytes_delta = sum(s['in'] + s['out'] for s in recent)
                    stats.bandwidth_mbps = (bytes_delta * 8) / (time_delta * 1_000_000)

            summary[seg.name] = {
                'vlan_id': seg.value,
                'name': self._segment_display_name(seg),
                'icon': self._segment_icon(seg),
                'color': self._segment_color(seg),
                'device_count': len(devices),
                'active_count': stats.active_count,
                'bytes_in': stats.bytes_in,
                'bytes_out': stats.bytes_out,
                'bandwidth_mbps': round(stats.bandwidth_mbps, 2),
                'top_devices': [
                    {
                        'mac': fp.mac_address,
                        'hostname': fp.hostname or fp.vendor or 'Unknown',
                        'bytes': fp.bytes_in + fp.bytes_out
                    }
                    for fp in sorted(devices, key=lambda x: x.bytes_in + x.bytes_out, reverse=True)[:5]
                ]
            }

        return summary

    def _segment_display_name(self, seg: NetworkSegment) -> str:
        """Get display name for segment."""
        names = {
            NetworkSegment.SECMON: 'Security Monitoring',
            NetworkSegment.CLIENTS: 'Staff Devices',
            NetworkSegment.POS: 'Point of Sale',
            NetworkSegment.CAMERAS: 'Security Cameras',
            NetworkSegment.IIOT: 'IoT / Smart Devices',
            NetworkSegment.GUEST: 'Guest Network',
            NetworkSegment.QUARANTINE: 'Quarantine',
        }
        return names.get(seg, seg.name)

    def _segment_icon(self, seg: NetworkSegment) -> str:
        """Get icon class for segment."""
        icons = {
            NetworkSegment.SECMON: 'fa-shield-alt',
            NetworkSegment.CLIENTS: 'fa-laptop',
            NetworkSegment.POS: 'fa-credit-card',
            NetworkSegment.CAMERAS: 'fa-video',
            NetworkSegment.IIOT: 'fa-thermometer-half',
            NetworkSegment.GUEST: 'fa-wifi',
            NetworkSegment.QUARANTINE: 'fa-exclamation-triangle',
        }
        return icons.get(seg, 'fa-network-wired')

    def _segment_color(self, seg: NetworkSegment) -> str:
        """Get color for segment."""
        colors = {
            NetworkSegment.SECMON: '#17a2b8',     # Info blue
            NetworkSegment.CLIENTS: '#28a745',    # Success green
            NetworkSegment.POS: '#ffc107',        # Warning yellow
            NetworkSegment.CAMERAS: '#6f42c1',    # Purple
            NetworkSegment.IIOT: '#fd7e14',       # Orange
            NetworkSegment.GUEST: '#20c997',      # Teal
            NetworkSegment.QUARANTINE: '#dc3545', # Danger red
        }
        return colors.get(seg, '#6c757d')


# =============================================================================
# Singleton Instance
# =============================================================================

_autopilot: Optional[SDNAutoPilot] = None


def get_sdn_autopilot(ovs_bridge: str = 'FTS') -> SDNAutoPilot:
    """Get the SDN Auto-Pilot singleton."""
    global _autopilot
    if _autopilot is None:
        _autopilot = SDNAutoPilot(ovs_bridge=ovs_bridge)
    return _autopilot


# =============================================================================
# CLI Interface
# =============================================================================

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='SDN Auto-Pilot CLI')
    parser.add_argument('command', choices=['classify', 'assign', 'list', 'stats', 'rules'])
    parser.add_argument('--mac', help='MAC address')
    parser.add_argument('--segment', type=int, help='VLAN segment ID')
    parser.add_argument('--ip', help='IP address')
    parser.add_argument('--hostname', help='Hostname')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    autopilot = get_sdn_autopilot()

    if args.command == 'classify' and args.mac:
        fp = autopilot.classify_device(args.mac, args.ip, args.hostname)
        print(json.dumps(fp.to_dict(), indent=2))

    elif args.command == 'assign' and args.mac and args.segment:
        seg = NetworkSegment(args.segment)
        autopilot.assign_device_segment(args.mac, seg)
        print(f"Assigned {args.mac} to VLAN {args.segment} ({seg.name})")

    elif args.command == 'list':
        devices = autopilot.get_all_devices()
        print(json.dumps(devices, indent=2))

    elif args.command == 'stats':
        stats = autopilot.get_segment_summary()
        print(json.dumps(stats, indent=2))

    elif args.command == 'rules':
        rules = autopilot.generate_openflow_rules()
        for rule in rules:
            print(rule)
