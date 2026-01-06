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
import re
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from ipaddress import ip_network
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


def _mask_mac(mac: str) -> str:
    """Mask MAC address for secure logging (CWE-532 mitigation)."""
    if not mac:
        return "**:**:**:**:**:**"
    mac_clean = mac.upper().replace('-', ':')
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac_clean):
        return "**:**:**:**:**:**"
    parts = mac_clean.split(':')
    return f"{parts[0]}:{parts[1]}:{parts[2]}:**:**:{parts[5]}"

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

# Policy trigger file - shared volume for container-to-host communication
# The host-side nac-policy-sync.sh reads this and applies OVS rules
POLICY_TRIGGER_FILE = DATA_DIR / '.nac_policy_sync'

# OVS Bridge (only used by host script, not directly from container)
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
    # Policy Enforcement via Trigger File
    # ========================================
    #
    # IMPORTANT: OVS runs on the host, not in the container.
    # We use a trigger file mechanism to communicate policy changes:
    # 1. Container writes policy request to POLICY_TRIGGER_FILE
    # 2. Host-side nac-policy-sync.sh reads it and applies OVS rules
    # 3. systemd timer runs the script every 5 seconds
    #
    # This ensures OVS commands are executed on the host where they work.

    def _write_policy_trigger(self, mac: str, policy: str):
        """
        Write policy trigger file for host-side OVS rule application.

        The host-side nac-policy-sync.sh script reads this file and applies
        the appropriate OpenFlow rules. This is necessary because OVS runs
        on the host, not in the container.

        Args:
            mac: Device MAC address
            policy: Policy to apply (quarantine, lan_only, internet_only, etc.)
        """
        try:
            trigger_data = {
                'mac': mac.upper(),
                'policy': policy,
                'timestamp': datetime.now().isoformat(),
            }
            POLICY_TRIGGER_FILE.write_text(json.dumps(trigger_data, indent=2))
            logger.info(f"Policy trigger written: {_mask_mac(mac)} -> {policy}")
        except Exception as e:
            logger.warning(f"Failed to write policy trigger for {_mask_mac(mac)}: {e}")

    def set_policy(self, mac_address: str, policy: str) -> bool:
        """
        Set network policy for a device.

        Args:
            mac_address: Device MAC address
            policy: Policy name (full_access, lan_only, internet_only, isolated, default)

        Returns:
            True if successful
        """
        valid_policies = ['full_access', 'lan_only', 'internet_only', 'isolated', 'quarantine', 'default', 'smart_home']
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
        Request policy application via trigger file.

        The actual OpenFlow rules are applied by the host-side
        nac-policy-sync.sh script, which reads the trigger file.

        Policy types:
        - quarantine/isolated: Block all traffic except DHCP/DNS
        - lan_only: Allow LAN, block internet
        - internet_only: Block LAN, allow internet
        - full_access/smart_home: No restrictions
        """
        mac_upper = mac.upper()

        # Normalize policy names
        policy_map = {
            'isolated': 'quarantine',
            'default': 'smart_home',
            'normal': 'smart_home',
        }
        effective_policy = policy_map.get(policy, policy)

        # Write trigger file for host-side application
        self._write_policy_trigger(mac_upper, effective_policy)
        logger.info(f"Requested {effective_policy.upper()} policy for {_mask_mac(mac)}")

    def _block_device(self, mac: str):
        """Block a device by applying quarantine policy."""
        # Use quarantine policy for blocking
        self._write_policy_trigger(mac.upper(), 'quarantine')
        logger.info(f"Block requested for device: {_mask_mac(mac)}")

    def _unblock_device(self, mac: str):
        """Unblock a device by applying smart_home policy."""
        mac_upper = mac.upper()
        entry = self._registry.get(mac_upper)
        # Restore original policy or use smart_home
        policy = entry.policy if entry and entry.policy not in ('isolated', 'quarantine') else 'smart_home'
        self._write_policy_trigger(mac_upper, policy)
        logger.info(f"Unblock requested for device: {_mask_mac(mac)}")

    def sync_policies(self):
        """
        Request sync of all device policies.

        Note: For bulk sync, we write each policy trigger sequentially.
        The host-side script processes them via the database sync.
        """
        logger.info("Requesting sync of all device policies...")
        synced = 0
        for mac, entry in self._registry.items():
            if entry.is_blocked:
                self._write_policy_trigger(mac, 'quarantine')
            elif entry.policy not in ('full_access', 'default', 'smart_home', ''):
                self._write_policy_trigger(mac, entry.policy)
            synced += 1
        logger.info(f"Requested sync for {synced} device policies")


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
