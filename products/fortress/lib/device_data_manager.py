#!/usr/bin/env python3
"""
Fortress Device Data Manager - File-based CRUD with Policy Assignment

Provides Create, Read, Update, Delete operations for device management
using JSON file storage. Merges auto-discovered devices with manual
entries and policy assignments.

Policies:
    full_access    - Full internet and LAN access (staff, trusted)
    lan_only       - LAN access only, no internet (sensors, cameras)
    internet_only  - Internet only, no LAN (guests, POS)
    isolated       - Completely isolated (quarantined)
    default        - Default policy, uses auto-classification

Version: 1.0.0
License: AGPL-3.0
"""

import json
import logging
import subprocess
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from ipaddress import ip_network
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

# Network configuration for policy enforcement
# Uses broader /16 to match ovs-post-setup.sh base rules
# Per-device rules use higher priority to override base permissive rules
DEFAULT_LAN_NETWORK = "10.200.0.0/16"
DEFAULT_GATEWAY_IP = "10.200.0.1"
CONTAINER_NETWORK = "172.20.0.0/16"
INSTALL_STATE_FILE = Path('/etc/hookprobe/install-state.conf')


def _get_network_config() -> Tuple[str, str]:
    """
    Get LAN network and gateway from install state or use defaults.

    Returns:
        Tuple of (lan_network, gateway_ip)
    """
    lan_network = DEFAULT_LAN_NETWORK
    gateway_ip = DEFAULT_GATEWAY_IP

    # Try to load from install state
    if INSTALL_STATE_FILE.exists():
        try:
            with open(INSTALL_STATE_FILE) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('LAN_SUBNET='):
                        subnet = line.split('=', 1)[1].strip('"\'')
                        # Convert user subnet to /16 for broader matching
                        # User may have /24, /23, etc. but we use /16 for OVS rules
                        try:
                            net = ip_network(subnet, strict=False)
                            # Use 10.200.0.0/16 for any 10.200.x.x subnet
                            if net.network_address.packed[0] == 10 and net.network_address.packed[1] == 200:
                                lan_network = "10.200.0.0/16"
                        except ValueError:
                            pass
                    elif line.startswith('LAN_GATEWAY='):
                        gateway_ip = line.split('=', 1)[1].strip('"\'')
        except Exception as e:
            logger.debug(f"Could not load network config: {e}")

    return lan_network, gateway_ip

# Data directories
DATA_DIR = Path('/opt/hookprobe/fortress/data')
REGISTRY_FILE = DATA_DIR / 'device_registry.json'
DEVICES_FILE = DATA_DIR / 'devices.json'

# OVS Bridge
OVS_BRIDGE = 'FTS'


class DevicePolicy(str, Enum):
    """Network access policies for devices."""
    FULL_ACCESS = "full_access"
    LAN_ONLY = "lan_only"
    INTERNET_ONLY = "internet_only"
    ISOLATED = "isolated"
    DEFAULT = "default"


class DeviceCategory(str, Enum):
    """Device categories."""
    IOT = "iot"
    CAMERA = "camera"
    POS = "pos"
    PRINTER = "printer"
    WORKSTATION = "workstation"
    MOBILE = "mobile"
    VOICE_ASSISTANT = "voice_assistant"
    NETWORK = "network"
    UNKNOWN = "unknown"


# OUI Database for manufacturer and category classification
OUI_DATABASE = {
    # IoT devices
    "B8:27:EB": ("Raspberry Pi", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "DC:A6:32": ("Raspberry Pi", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "E4:5F:01": ("Raspberry Pi", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "24:0A:C4": ("Espressif", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "24:6F:28": ("Espressif", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "3C:71:BF": ("Espressif", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "5C:CF:7F": ("Espressif", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "A4:CF:12": ("Espressif", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "10:D5:61": ("Tuya Smart", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "D8:1F:12": ("Tuya Smart", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "34:94:54": ("Shelly", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "00:17:88": ("Philips Hue", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),
    "EC:B5:FA": ("Philips Hue", DeviceCategory.IOT, DevicePolicy.LAN_ONLY),

    # Cameras
    "00:0C:B5": ("Hikvision", DeviceCategory.CAMERA, DevicePolicy.LAN_ONLY),
    "18:68:CB": ("Hikvision", DeviceCategory.CAMERA, DevicePolicy.LAN_ONLY),
    "28:57:BE": ("Hikvision", DeviceCategory.CAMERA, DevicePolicy.LAN_ONLY),
    "3C:EF:8C": ("Dahua", DeviceCategory.CAMERA, DevicePolicy.LAN_ONLY),
    "90:02:A9": ("Dahua", DeviceCategory.CAMERA, DevicePolicy.LAN_ONLY),
    "B4:6B:FC": ("Reolink", DeviceCategory.CAMERA, DevicePolicy.LAN_ONLY),
    "2C:AA:8E": ("Wyze", DeviceCategory.CAMERA, DevicePolicy.LAN_ONLY),
    "9C:76:0E": ("Ring", DeviceCategory.CAMERA, DevicePolicy.LAN_ONLY),

    # Voice Assistants - internet only, no LAN snooping
    "18:D6:C7": ("Google Nest", DeviceCategory.VOICE_ASSISTANT, DevicePolicy.INTERNET_ONLY),
    "1C:F2:9A": ("Google Nest", DeviceCategory.VOICE_ASSISTANT, DevicePolicy.INTERNET_ONLY),
    "54:60:09": ("Google Home", DeviceCategory.VOICE_ASSISTANT, DevicePolicy.INTERNET_ONLY),
    "0C:47:C9": ("Amazon Echo", DeviceCategory.VOICE_ASSISTANT, DevicePolicy.INTERNET_ONLY),
    "34:D2:70": ("Amazon Echo", DeviceCategory.VOICE_ASSISTANT, DevicePolicy.INTERNET_ONLY),
    "50:DC:E7": ("Amazon Echo", DeviceCategory.VOICE_ASSISTANT, DevicePolicy.INTERNET_ONLY),

    # POS Terminals - internet only for payment processing
    "00:50:10": ("Verifone", DeviceCategory.POS, DevicePolicy.INTERNET_ONLY),
    "00:0D:41": ("Verifone", DeviceCategory.POS, DevicePolicy.INTERNET_ONLY),
    "00:07:81": ("Ingenico", DeviceCategory.POS, DevicePolicy.INTERNET_ONLY),
    "58:E6:BA": ("Square", DeviceCategory.POS, DevicePolicy.INTERNET_ONLY),
    "04:CF:8C": ("Clover", DeviceCategory.POS, DevicePolicy.INTERNET_ONLY),

    # Printers
    "00:1E:0B": ("HP", DeviceCategory.PRINTER, DevicePolicy.LAN_ONLY),
    "00:21:5A": ("HP", DeviceCategory.PRINTER, DevicePolicy.LAN_ONLY),
    "64:51:06": ("HP", DeviceCategory.PRINTER, DevicePolicy.LAN_ONLY),
    "00:1E:8F": ("Canon", DeviceCategory.PRINTER, DevicePolicy.LAN_ONLY),
    "74:E5:43": ("Canon", DeviceCategory.PRINTER, DevicePolicy.LAN_ONLY),
    "00:26:AB": ("Epson", DeviceCategory.PRINTER, DevicePolicy.LAN_ONLY),
    "00:1B:A9": ("Brother", DeviceCategory.PRINTER, DevicePolicy.LAN_ONLY),

    # Workstations - Apple
    "00:1C:B3": ("Apple", DeviceCategory.WORKSTATION, DevicePolicy.FULL_ACCESS),
    "A4:5E:60": ("Apple", DeviceCategory.WORKSTATION, DevicePolicy.FULL_ACCESS),
    "AC:BC:32": ("Apple", DeviceCategory.WORKSTATION, DevicePolicy.FULL_ACCESS),
    "B0:34:95": ("Apple", DeviceCategory.WORKSTATION, DevicePolicy.FULL_ACCESS),

    # Mobile devices
    "3C:5A:B4": ("Google", DeviceCategory.MOBILE, DevicePolicy.FULL_ACCESS),
    "94:EB:2C": ("Google", DeviceCategory.MOBILE, DevicePolicy.FULL_ACCESS),
    "00:00:F0": ("Samsung", DeviceCategory.MOBILE, DevicePolicy.FULL_ACCESS),
    "00:07:AB": ("Samsung", DeviceCategory.MOBILE, DevicePolicy.FULL_ACCESS),

    # Network equipment - full access (trusted)
    "00:1A:2B": ("Ubiquiti", DeviceCategory.NETWORK, DevicePolicy.FULL_ACCESS),
    "24:A4:3C": ("Ubiquiti", DeviceCategory.NETWORK, DevicePolicy.FULL_ACCESS),
    "B4:FB:E4": ("Netgear", DeviceCategory.NETWORK, DevicePolicy.FULL_ACCESS),
    "00:00:0C": ("Cisco", DeviceCategory.NETWORK, DevicePolicy.FULL_ACCESS),
    "14:CC:20": ("TP-Link", DeviceCategory.NETWORK, DevicePolicy.FULL_ACCESS),

    # Intel (typically workstations)
    "00:02:B3": ("Intel", DeviceCategory.WORKSTATION, DevicePolicy.FULL_ACCESS),
    "00:03:47": ("Intel", DeviceCategory.WORKSTATION, DevicePolicy.FULL_ACCESS),
    "00:E0:4C": ("Realtek", DeviceCategory.WORKSTATION, DevicePolicy.FULL_ACCESS),
}


@dataclass
class DeviceEntry:
    """Device registry entry with policy."""
    mac_address: str
    name: str = ""
    policy: str = "default"
    category: str = "unknown"
    manufacturer: str = ""
    notes: str = ""
    is_blocked: bool = False
    is_trusted: bool = False
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at


class DeviceDataManager:
    """
    File-based device data manager with CRUD and policy assignment.

    Maintains device_registry.json for persistent storage and merges
    with auto-discovered devices from devices.json.
    """

    def __init__(self, data_dir: Path = DATA_DIR):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.registry_file = data_dir / 'device_registry.json'
        self.devices_file = data_dir / 'devices.json'
        self._registry: Dict[str, DeviceEntry] = {}
        self._load_registry()

    def _load_registry(self):
        """Load device registry from file."""
        if not self.registry_file.exists():
            self._registry = {}
            return

        try:
            with open(self.registry_file, 'r') as f:
                data = json.load(f)

            for mac, entry_data in data.items():
                self._registry[mac.upper()] = DeviceEntry(
                    mac_address=mac.upper(),
                    name=entry_data.get('name', ''),
                    policy=entry_data.get('policy', 'default'),
                    category=entry_data.get('category', 'unknown'),
                    manufacturer=entry_data.get('manufacturer', ''),
                    notes=entry_data.get('notes', ''),
                    is_blocked=entry_data.get('is_blocked', False),
                    is_trusted=entry_data.get('is_trusted', False),
                    created_at=entry_data.get('created_at', ''),
                    updated_at=entry_data.get('updated_at', ''),
                )

            logger.info(f"Loaded {len(self._registry)} devices from registry")
        except Exception as e:
            logger.error(f"Failed to load device registry: {e}")
            self._registry = {}

    def _save_registry(self):
        """Save device registry to file."""
        try:
            data = {}
            for mac, entry in self._registry.items():
                data[mac] = asdict(entry)

            with open(self.registry_file, 'w') as f:
                json.dump(data, f, indent=2)

            logger.debug(f"Saved {len(self._registry)} devices to registry")
        except Exception as e:
            logger.error(f"Failed to save device registry: {e}")

    def _get_discovered_devices(self) -> List[Dict]:
        """Load auto-discovered devices from devices.json."""
        if not self.devices_file.exists():
            return []

        try:
            with open(self.devices_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to load discovered devices: {e}")
            return []

    def _classify_device(self, mac_address: str) -> tuple:
        """
        Classify device by OUI.

        Returns: (manufacturer, category, recommended_policy)
        """
        mac = mac_address.upper().replace('-', ':')
        oui = mac[:8]

        if oui in OUI_DATABASE:
            manufacturer, category, policy = OUI_DATABASE[oui]
            return manufacturer, category.value, policy.value

        return "Unknown", DeviceCategory.UNKNOWN.value, DevicePolicy.DEFAULT.value

    # ========================================
    # CRUD Operations
    # ========================================

    def create(self, mac_address: str, name: str = "", policy: str = "default",
               notes: str = "", is_trusted: bool = False) -> DeviceEntry:
        """
        Create a new device entry.

        Args:
            mac_address: Device MAC address
            name: Friendly name for device
            policy: Network policy (full_access, lan_only, internet_only, isolated, default)
            notes: Optional notes
            is_trusted: Whether device is trusted

        Returns:
            The created DeviceEntry
        """
        mac = mac_address.upper().replace('-', ':')

        # Get classification
        manufacturer, category, rec_policy = self._classify_device(mac)

        # Use recommended policy if default
        if policy == "default":
            policy = rec_policy

        entry = DeviceEntry(
            mac_address=mac,
            name=name,
            policy=policy,
            category=category,
            manufacturer=manufacturer,
            notes=notes,
            is_blocked=False,
            is_trusted=is_trusted,
        )

        self._registry[mac] = entry
        self._save_registry()

        # Apply OpenFlow rules for policy
        self._apply_policy_rules(mac, policy)

        logger.info(f"Created device entry: {mac} policy={policy}")
        return entry

    def read(self, mac_address: str) -> Optional[Dict]:
        """
        Read a device by MAC address.

        Returns device info merged with discovery data.
        """
        mac = mac_address.upper().replace('-', ':')

        # Get registry entry
        entry = self._registry.get(mac)

        # Get discovery data
        discovered = None
        for d in self._get_discovered_devices():
            if d.get('mac_address', '').upper() == mac:
                discovered = d
                break

        if not entry and not discovered:
            return None

        # Merge data
        result = {
            'mac_address': mac,
            'ip_address': discovered.get('ip_address', '') if discovered else '',
            'hostname': discovered.get('hostname', '') if discovered else '',
            'state': discovered.get('state', 'UNKNOWN') if discovered else 'UNKNOWN',
            'interface': discovered.get('interface', '') if discovered else '',
            'last_seen': discovered.get('last_seen', '') if discovered else '',
        }

        if entry:
            result.update({
                'name': entry.name,
                'policy': entry.policy,
                'category': entry.category,
                'manufacturer': entry.manufacturer,
                'notes': entry.notes,
                'is_blocked': entry.is_blocked,
                'is_trusted': entry.is_trusted,
                'created_at': entry.created_at,
                'updated_at': entry.updated_at,
            })
        else:
            # Auto-classify
            manufacturer, category, rec_policy = self._classify_device(mac)
            result.update({
                'name': '',
                'policy': rec_policy,
                'category': category,
                'manufacturer': manufacturer or discovered.get('manufacturer', 'Unknown'),
                'notes': '',
                'is_blocked': False,
                'is_trusted': False,
            })

        return result

    def update(self, mac_address: str, **kwargs) -> Optional[DeviceEntry]:
        """
        Update a device entry.

        Args:
            mac_address: Device MAC address
            **kwargs: Fields to update (name, policy, notes, is_trusted, is_blocked)

        Returns:
            Updated DeviceEntry or None if not found
        """
        mac = mac_address.upper().replace('-', ':')

        # Create entry if not exists
        if mac not in self._registry:
            self.create(mac)

        entry = self._registry[mac]
        old_policy = entry.policy

        # Update fields
        allowed_fields = {'name', 'policy', 'notes', 'is_trusted', 'is_blocked', 'category'}
        for key, value in kwargs.items():
            if key in allowed_fields and hasattr(entry, key):
                setattr(entry, key, value)

        entry.updated_at = datetime.now().isoformat()
        self._save_registry()

        # Update OpenFlow rules if policy changed
        if 'policy' in kwargs and kwargs['policy'] != old_policy:
            self._apply_policy_rules(mac, kwargs['policy'])

        # Handle blocking
        if kwargs.get('is_blocked'):
            self._block_device(mac)
        elif 'is_blocked' in kwargs and not kwargs['is_blocked']:
            self._unblock_device(mac)

        logger.info(f"Updated device: {mac}")
        return entry

    def delete(self, mac_address: str) -> bool:
        """
        Delete a device entry.

        Args:
            mac_address: Device MAC address

        Returns:
            True if deleted, False if not found
        """
        mac = mac_address.upper().replace('-', ':')

        if mac not in self._registry:
            return False

        # Remove OpenFlow rules
        self._remove_policy_rules(mac)

        del self._registry[mac]
        self._save_registry()

        logger.info(f"Deleted device: {mac}")
        return True

    def list_all(self, include_discovered: bool = True) -> List[Dict]:
        """
        List all devices (registered + discovered).

        Args:
            include_discovered: Whether to include auto-discovered devices

        Returns:
            List of device dictionaries
        """
        devices = {}

        # Add discovered devices first
        if include_discovered:
            for d in self._get_discovered_devices():
                mac = d.get('mac_address', '').upper()
                if not mac:
                    continue

                manufacturer, category, rec_policy = self._classify_device(mac)

                devices[mac] = {
                    'mac_address': mac,
                    'ip_address': d.get('ip_address', ''),
                    'hostname': d.get('hostname', ''),
                    'state': d.get('state', 'UNKNOWN'),
                    'interface': d.get('interface', ''),
                    'last_seen': d.get('last_seen', ''),
                    'name': '',
                    'policy': rec_policy,
                    'category': category,
                    'manufacturer': manufacturer or d.get('manufacturer', 'Unknown'),
                    'notes': '',
                    'is_blocked': False,
                    'is_trusted': False,
                    'is_registered': False,
                }

        # Override/add with registered devices
        for mac, entry in self._registry.items():
            discovered = devices.get(mac, {})
            devices[mac] = {
                'mac_address': mac,
                'ip_address': discovered.get('ip_address', ''),
                'hostname': discovered.get('hostname', ''),
                'state': discovered.get('state', 'OFFLINE'),
                'interface': discovered.get('interface', ''),
                'last_seen': discovered.get('last_seen', ''),
                'name': entry.name,
                'policy': entry.policy,
                'category': entry.category,
                'manufacturer': entry.manufacturer or discovered.get('manufacturer', 'Unknown'),
                'notes': entry.notes,
                'is_blocked': entry.is_blocked,
                'is_trusted': entry.is_trusted,
                'is_registered': True,
                'created_at': entry.created_at,
                'updated_at': entry.updated_at,
            }

        return list(devices.values())

    def list_by_policy(self, policy: str) -> List[Dict]:
        """List devices with a specific policy."""
        all_devices = self.list_all()
        return [d for d in all_devices if d.get('policy') == policy]

    def list_by_category(self, category: str) -> List[Dict]:
        """List devices with a specific category."""
        all_devices = self.list_all()
        return [d for d in all_devices if d.get('category') == category]

    def get_stats(self) -> Dict:
        """Get device statistics."""
        all_devices = self.list_all()

        by_policy = {}
        by_category = {}

        for d in all_devices:
            policy = d.get('policy', 'default')
            category = d.get('category', 'unknown')

            by_policy[policy] = by_policy.get(policy, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1

        online = sum(1 for d in all_devices if d.get('state') in ['REACHABLE', 'STALE', 'DELAY'])
        blocked = sum(1 for d in all_devices if d.get('is_blocked'))
        registered = sum(1 for d in all_devices if d.get('is_registered'))

        return {
            'total': len(all_devices),
            'online': online,
            'offline': len(all_devices) - online,
            'blocked': blocked,
            'registered': registered,
            'by_policy': by_policy,
            'by_category': by_category,
        }

    # ========================================
    # Policy Enforcement
    # ========================================

    def set_policy(self, mac_address: str, policy: str) -> bool:
        """
        Set network policy for a device.

        Args:
            mac_address: Device MAC address
            policy: Policy name (full_access, lan_only, internet_only, isolated, default)

        Returns:
            True if successful
        """
        valid_policies = ['full_access', 'lan_only', 'internet_only', 'isolated', 'default']
        if policy not in valid_policies:
            logger.warning(f"Invalid policy: {policy}")
            return False

        self.update(mac_address, policy=policy)
        return True

    def block(self, mac_address: str, reason: str = "") -> bool:
        """Block a device."""
        entry = self.update(mac_address, is_blocked=True, notes=f"Blocked: {reason}")
        return entry is not None

    def unblock(self, mac_address: str) -> bool:
        """Unblock a device."""
        entry = self.update(mac_address, is_blocked=False)
        return entry is not None

    def _apply_policy_rules(self, mac: str, policy: str):
        """
        Apply OpenFlow rules for device policy.

        Policy enforcement uses IP-based rules to provide proper access control:
        - Priority 700+: Per-device policy rules (overrides base priority 500 rules)
        - Priority 500: Base LAN permissive rules (from ovs-post-setup.sh)
        - Priority 1000: ARP/DHCP essential services

        Traffic flow for each policy:
        - ISOLATED: Drop all traffic (quarantine)
        - LAN_ONLY: Allow LAN (10.200.0.0/16), block internet (non-RFC1918)
        - INTERNET_ONLY: Block LAN (except gateway), allow internet
        - FULL_ACCESS/NORMAL: Allow all (no rules needed, default allow)
        """
        try:
            # Remove existing rules for this MAC
            self._remove_policy_rules(mac)
            mac_upper = mac.upper()

            # Get network configuration
            lan_network, gateway_ip = _get_network_config()

            if policy in ("isolated", "quarantine"):
                # Priority 1000: Drop ALL traffic - highest priority quarantine
                # Bidirectional: block both outgoing and incoming
                # Allow only DHCP (for getting IP) and DNS (for captive portal)
                # Priority 1001: Allow DHCP request/response
                self._add_flow(f'priority=1001,udp,dl_src={mac_upper},tp_dst=67,actions=NORMAL')
                self._add_flow(f'priority=1001,udp,dl_dst={mac_upper},tp_src=67,actions=NORMAL')
                # Priority 1001: Allow DNS to gateway only (for captive portal redirect)
                self._add_flow(f'priority=1001,udp,dl_src={mac_upper},nw_dst={gateway_ip},tp_dst=53,actions=NORMAL')
                self._add_flow(f'priority=1001,udp,dl_dst={mac_upper},nw_src={gateway_ip},tp_src=53,actions=NORMAL')
                # Priority 1000: Drop everything else
                self._add_flow(f'priority=1000,dl_src={mac_upper},actions=drop')
                self._add_flow(f'priority=1000,dl_dst={mac_upper},actions=drop')
                logger.info(f"Applied QUARANTINE policy for {mac} - all traffic blocked except DHCP/DNS")

            elif policy == "lan_only":
                # LAN_ONLY: Can access LAN devices, gateway, but NOT internet
                # Strategy: Block traffic to non-private destinations

                # Priority 750: Allow traffic to gateway (for DHCP, DNS via gateway)
                self._add_flow(
                    f'priority=750,ip,dl_src={mac_upper},nw_dst={gateway_ip},actions=NORMAL'
                )

                # Priority 740: Allow traffic to LAN subnet (10.200.0.0/16)
                self._add_flow(
                    f'priority=740,ip,dl_src={mac_upper},nw_dst={lan_network},actions=NORMAL'
                )

                # Priority 730: Allow return traffic FROM LAN to this device
                self._add_flow(
                    f'priority=730,ip,dl_dst={mac_upper},nw_src={lan_network},actions=NORMAL'
                )

                # Priority 720: Allow container network (for local services)
                self._add_flow(
                    f'priority=720,ip,dl_src={mac_upper},nw_dst={CONTAINER_NETWORK},actions=NORMAL'
                )

                # Priority 600: DROP all other IP traffic (internet-bound)
                # This blocks traffic to public IPs while allowing LAN
                self._add_flow(
                    f'priority=600,ip,dl_src={mac_upper},actions=drop'
                )

                logger.info(f"Applied LAN_ONLY policy for {mac} - internet blocked")

            elif policy == "internet_only":
                # INTERNET_ONLY: Can access internet, but NOT other LAN devices
                # Use case: Guest devices, POS terminals (payment gateway only)
                # Strategy: Block traffic to LAN subnet except gateway

                # Priority 750: Allow traffic to gateway (required for routing)
                self._add_flow(
                    f'priority=750,ip,dl_src={mac_upper},nw_dst={gateway_ip},actions=NORMAL'
                )

                # Priority 740: Allow return traffic FROM gateway
                self._add_flow(
                    f'priority=740,ip,dl_dst={mac_upper},nw_src={gateway_ip},actions=NORMAL'
                )

                # Priority 700: Block traffic to LAN subnet (except gateway handled above)
                # This prevents device from reaching other LAN devices
                self._add_flow(
                    f'priority=700,ip,dl_src={mac_upper},nw_dst={lan_network},actions=drop'
                )

                # Priority 700: Block incoming traffic FROM other LAN devices
                # Prevents other LAN devices from initiating to this device
                self._add_flow(
                    f'priority=700,ip,dl_dst={mac_upper},nw_src={lan_network},actions=drop'
                )

                # Priority 650: Allow all other traffic (internet)
                # Lower priority than block rules, matches internet-bound traffic
                self._add_flow(
                    f'priority=650,ip,dl_src={mac_upper},actions=NORMAL'
                )

                # Priority 650: Allow return traffic from internet
                self._add_flow(
                    f'priority=650,ip,dl_dst={mac_upper},actions=NORMAL'
                )

                logger.info(f"Applied INTERNET_ONLY policy for {mac} - LAN isolated")

            elif policy in ("full_access", "normal", "default"):
                # FULL_ACCESS/NORMAL: No restrictions, use base permissive rules
                # No additional rules needed - priority 500 base rules allow all
                logger.info(f"Applied {policy.upper()} policy for {mac} - unrestricted")

            else:
                logger.warning(f"Unknown policy '{policy}' for {mac} - no rules applied")

        except Exception as e:
            logger.warning(f"Failed to apply policy rules for {mac}: {e}")

    def _add_flow(self, flow_spec: str) -> bool:
        """Add an OpenFlow rule to OVS bridge."""
        try:
            result = subprocess.run(
                ['ovs-ofctl', 'add-flow', OVS_BRIDGE, flow_spec],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                logger.debug(f"OVS add-flow failed: {result.stderr}")
                return False
            return True
        except Exception as e:
            logger.debug(f"OVS add-flow exception: {e}")
            return False

    def _remove_policy_rules(self, mac: str):
        """Remove OpenFlow rules for a device."""
        try:
            subprocess.run([
                'ovs-ofctl', 'del-flows', OVS_BRIDGE, f'dl_src={mac}'
            ], capture_output=True, timeout=5)
            subprocess.run([
                'ovs-ofctl', 'del-flows', OVS_BRIDGE, f'dl_dst={mac}'
            ], capture_output=True, timeout=5)
        except Exception as e:
            logger.debug(f"Failed to remove policy rules for {mac}: {e}")

    def _block_device(self, mac: str):
        """Block a device using OVS."""
        try:
            subprocess.run([
                'ovs-ofctl', 'add-flow', OVS_BRIDGE,
                f'priority=2000,dl_src={mac},actions=drop'
            ], capture_output=True, timeout=5)
            subprocess.run([
                'ovs-ofctl', 'add-flow', OVS_BRIDGE,
                f'priority=2000,dl_dst={mac},actions=drop'
            ], capture_output=True, timeout=5)
            logger.info(f"Blocked device: {mac}")
        except Exception as e:
            logger.warning(f"Failed to block device {mac}: {e}")

    def _unblock_device(self, mac: str):
        """Unblock a device by removing block rules."""
        try:
            subprocess.run([
                'ovs-ofctl', 'del-flows', OVS_BRIDGE,
                f'priority=2000,dl_src={mac}'
            ], capture_output=True, timeout=5)
            subprocess.run([
                'ovs-ofctl', 'del-flows', OVS_BRIDGE,
                f'priority=2000,dl_dst={mac}'
            ], capture_output=True, timeout=5)
            logger.info(f"Unblocked device: {mac}")
        except Exception as e:
            logger.warning(f"Failed to unblock device {mac}: {e}")

    def sync_policies(self):
        """Sync all device policies to OpenFlow rules."""
        logger.info("Syncing all device policies...")
        for mac, entry in self._registry.items():
            if entry.is_blocked:
                self._block_device(mac)
            else:
                self._apply_policy_rules(mac, entry.policy)
        logger.info(f"Synced {len(self._registry)} device policies")


# Singleton instance
_manager: Optional[DeviceDataManager] = None


def get_device_data_manager() -> DeviceDataManager:
    """Get the device data manager singleton."""
    global _manager
    if _manager is None:
        _manager = DeviceDataManager()
    return _manager


# Convenience functions for web API
def create_device(mac_address: str, **kwargs) -> Dict:
    """Create a device entry."""
    entry = get_device_data_manager().create(mac_address, **kwargs)
    return asdict(entry)


def get_device(mac_address: str) -> Optional[Dict]:
    """Get device by MAC address."""
    return get_device_data_manager().read(mac_address)


def update_device(mac_address: str, **kwargs) -> Optional[Dict]:
    """Update a device entry."""
    entry = get_device_data_manager().update(mac_address, **kwargs)
    return asdict(entry) if entry else None


def delete_device(mac_address: str) -> bool:
    """Delete a device entry."""
    return get_device_data_manager().delete(mac_address)


def list_devices(**filters) -> List[Dict]:
    """List all devices with optional filters."""
    manager = get_device_data_manager()

    if 'policy' in filters:
        return manager.list_by_policy(filters['policy'])
    elif 'category' in filters:
        return manager.list_by_category(filters['category'])
    else:
        return manager.list_all()


def set_device_policy(mac_address: str, policy: str) -> bool:
    """Set device network policy."""
    return get_device_data_manager().set_policy(mac_address, policy)


def block_device(mac_address: str, reason: str = "") -> bool:
    """Block a device."""
    return get_device_data_manager().block(mac_address, reason)


def unblock_device(mac_address: str) -> bool:
    """Unblock a device."""
    return get_device_data_manager().unblock(mac_address)


def get_device_stats() -> Dict:
    """Get device statistics."""
    return get_device_data_manager().get_stats()
