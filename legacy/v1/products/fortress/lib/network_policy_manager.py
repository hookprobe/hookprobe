#!/usr/bin/env python3
"""
HookProbe Fortress - Network Policy Manager

Manages device network policies as an alternative to VLAN-based segmentation.
Uses OUI-based classification and nftables for per-device filtering.

Policies:
    full_access    - Full internet and LAN access (staff)
    lan_only       - LAN access only, no internet (sensors, cameras)
    internet_only  - Internet only, no LAN (guests, voice assistants)
    isolated       - Completely isolated (quarantined devices)
    default        - Default policy for unknown devices

Version: 1.0.0
License: AGPL-3.0
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class NetworkPolicy(Enum):
    """Network access policies for devices."""
    FULL_ACCESS = "full_access"      # Internet + LAN
    LAN_ONLY = "lan_only"            # LAN only (no internet)
    INTERNET_ONLY = "internet_only"  # Internet only (no LAN)
    ISOLATED = "isolated"            # Completely blocked
    DEFAULT = "default"              # Default policy


class DeviceCategory(Enum):
    """Device categories based on OUI classification."""
    IOT = "iot"
    CAMERA = "camera"
    POS = "pos"
    PRINTER = "printer"
    WORKSTATION = "workstation"
    MOBILE = "mobile"
    VOICE_ASSISTANT = "voice_assistant"
    NETWORK = "network"
    UNKNOWN = "unknown"


@dataclass
class OUIEntry:
    """OUI database entry."""
    oui: str  # XX:XX:XX format
    manufacturer: str
    category: DeviceCategory
    default_policy: NetworkPolicy


@dataclass
class DevicePolicy:
    """Device network policy assignment."""
    mac_address: str
    policy: NetworkPolicy
    category: DeviceCategory = DeviceCategory.UNKNOWN
    manufacturer: str = "Unknown"
    assigned_at: datetime = field(default_factory=datetime.now)
    assigned_by: str = "auto"  # 'auto', 'manual', 'oui'


class OUIClassifier:
    """
    OUI-based device classifier.

    Classifies devices based on their MAC address OUI (first 3 bytes)
    and assigns appropriate network policies.
    """

    # Default OUI classifications
    DEFAULT_OUI_DATABASE: Dict[str, Tuple[str, DeviceCategory, NetworkPolicy]] = {
        # IoT devices -> lan_only (can't reach internet)
        "B8:27:EB": ("Raspberry Pi Foundation", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "DC:A6:32": ("Raspberry Pi Trading", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "E4:5F:01": ("Raspberry Pi Trading", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "28:CD:C1": ("Raspberry Pi Trading", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),

        # ESP8266/ESP32 (Espressif)
        "24:0A:C4": ("Espressif", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "24:6F:28": ("Espressif", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "3C:71:BF": ("Espressif", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "5C:CF:7F": ("Espressif", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "A4:CF:12": ("Espressif", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "CC:50:E3": ("Espressif", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),

        # Tuya/SmartLife
        "10:D5:61": ("Tuya Smart", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "D8:1F:12": ("Tuya Smart", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),

        # Shelly
        "34:94:54": ("Shelly", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "44:17:93": ("Shelly", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),

        # Philips Hue
        "00:17:88": ("Philips Hue", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "EC:B5:FA": ("Philips Hue", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),

        # IKEA Tradfri
        "00:0B:57": ("IKEA Tradfri", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),
        "90:FD:9F": ("IKEA Tradfri", DeviceCategory.IOT, NetworkPolicy.LAN_ONLY),

        # Security Cameras -> lan_only
        "00:0C:B5": ("Hikvision", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "18:68:CB": ("Hikvision", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "28:57:BE": ("Hikvision", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "54:C4:15": ("Hikvision", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "3C:EF:8C": ("Dahua", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "90:02:A9": ("Dahua", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "B4:6B:FC": ("Reolink", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "EC:71:DB": ("Reolink", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "2C:AA:8E": ("Wyze", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "9C:76:0E": ("Ring", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "04:B1:67": ("Ring", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),
        "48:78:5E": ("Eufy", DeviceCategory.CAMERA, NetworkPolicy.LAN_ONLY),

        # Voice Assistants -> internet_only (no LAN snooping)
        "18:D6:C7": ("Google Nest", DeviceCategory.VOICE_ASSISTANT, NetworkPolicy.INTERNET_ONLY),
        "1C:F2:9A": ("Google Nest", DeviceCategory.VOICE_ASSISTANT, NetworkPolicy.INTERNET_ONLY),
        "54:60:09": ("Google Home", DeviceCategory.VOICE_ASSISTANT, NetworkPolicy.INTERNET_ONLY),
        "F4:F5:D8": ("Google Home", DeviceCategory.VOICE_ASSISTANT, NetworkPolicy.INTERNET_ONLY),
        "0C:47:C9": ("Amazon Echo", DeviceCategory.VOICE_ASSISTANT, NetworkPolicy.INTERNET_ONLY),
        "34:D2:70": ("Amazon Echo", DeviceCategory.VOICE_ASSISTANT, NetworkPolicy.INTERNET_ONLY),
        "50:DC:E7": ("Amazon Echo", DeviceCategory.VOICE_ASSISTANT, NetworkPolicy.INTERNET_ONLY),
        "68:54:FD": ("Amazon Echo", DeviceCategory.VOICE_ASSISTANT, NetworkPolicy.INTERNET_ONLY),
        "A0:02:DC": ("Amazon Echo", DeviceCategory.VOICE_ASSISTANT, NetworkPolicy.INTERNET_ONLY),

        # POS Terminals -> internet_only (payment processing)
        "00:50:10": ("Verifone", DeviceCategory.POS, NetworkPolicy.INTERNET_ONLY),
        "00:0D:41": ("Verifone", DeviceCategory.POS, NetworkPolicy.INTERNET_ONLY),
        "00:17:E8": ("Verifone", DeviceCategory.POS, NetworkPolicy.INTERNET_ONLY),
        "00:07:81": ("Ingenico", DeviceCategory.POS, NetworkPolicy.INTERNET_ONLY),
        "00:18:0A": ("Ingenico", DeviceCategory.POS, NetworkPolicy.INTERNET_ONLY),
        "58:E6:BA": ("Square", DeviceCategory.POS, NetworkPolicy.INTERNET_ONLY),
        "04:CF:8C": ("Clover", DeviceCategory.POS, NetworkPolicy.INTERNET_ONLY),
        "00:1F:71": ("PAX", DeviceCategory.POS, NetworkPolicy.INTERNET_ONLY),

        # Printers -> lan_only
        "00:1E:0B": ("HP", DeviceCategory.PRINTER, NetworkPolicy.LAN_ONLY),
        "00:21:5A": ("HP", DeviceCategory.PRINTER, NetworkPolicy.LAN_ONLY),
        "64:51:06": ("HP", DeviceCategory.PRINTER, NetworkPolicy.LAN_ONLY),
        "00:1E:8F": ("Canon", DeviceCategory.PRINTER, NetworkPolicy.LAN_ONLY),
        "74:E5:43": ("Canon", DeviceCategory.PRINTER, NetworkPolicy.LAN_ONLY),
        "00:26:AB": ("Epson", DeviceCategory.PRINTER, NetworkPolicy.LAN_ONLY),
        "00:1B:A9": ("Brother", DeviceCategory.PRINTER, NetworkPolicy.LAN_ONLY),

        # Network Equipment -> full_access (trusted)
        "00:1A:2B": ("Ubiquiti", DeviceCategory.NETWORK, NetworkPolicy.FULL_ACCESS),
        "24:A4:3C": ("Ubiquiti", DeviceCategory.NETWORK, NetworkPolicy.FULL_ACCESS),
        "FC:EC:DA": ("Ubiquiti", DeviceCategory.NETWORK, NetworkPolicy.FULL_ACCESS),
        "B4:FB:E4": ("Netgear", DeviceCategory.NETWORK, NetworkPolicy.FULL_ACCESS),
    }

    def __init__(self, custom_oui_file: Optional[Path] = None):
        """
        Initialize OUI classifier.

        Args:
            custom_oui_file: Optional path to custom OUI database file
        """
        self.oui_database: Dict[str, OUIEntry] = {}
        self._load_default_database()

        if custom_oui_file and custom_oui_file.exists():
            self._load_custom_database(custom_oui_file)

    def _load_default_database(self):
        """Load default OUI database."""
        for oui, (manufacturer, category, policy) in self.DEFAULT_OUI_DATABASE.items():
            self.oui_database[oui.upper()] = OUIEntry(
                oui=oui.upper(),
                manufacturer=manufacturer,
                category=category,
                default_policy=policy
            )

    def _load_custom_database(self, filepath: Path):
        """Load custom OUI database from file."""
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    parts = line.split(':')
                    if len(parts) >= 4:
                        oui = ':'.join(parts[:3]).upper()
                        category_str = parts[3] if len(parts) > 3 else "unknown"
                        policy_str = parts[4] if len(parts) > 4 else "default"
                        manufacturer = parts[5] if len(parts) > 5 else "Unknown"

                        try:
                            category = DeviceCategory(category_str)
                        except ValueError:
                            category = DeviceCategory.UNKNOWN

                        try:
                            policy = NetworkPolicy(policy_str)
                        except ValueError:
                            policy = NetworkPolicy.DEFAULT

                        self.oui_database[oui] = OUIEntry(
                            oui=oui,
                            manufacturer=manufacturer,
                            category=category,
                            default_policy=policy
                        )

            logger.info(f"Loaded {len(self.oui_database)} OUI entries from {filepath}")
        except Exception as e:
            logger.error(f"Error loading custom OUI database: {e}")

    def classify(self, mac_address: str) -> Tuple[DeviceCategory, NetworkPolicy, str]:
        """
        Classify a device based on its MAC address.

        Args:
            mac_address: MAC address in any standard format

        Returns:
            Tuple of (category, recommended_policy, manufacturer)
        """
        # Normalize MAC address
        mac = mac_address.upper().replace('-', ':')
        oui = mac[:8]  # First 3 bytes (XX:XX:XX)

        if oui in self.oui_database:
            entry = self.oui_database[oui]
            return entry.category, entry.default_policy, entry.manufacturer

        return DeviceCategory.UNKNOWN, NetworkPolicy.DEFAULT, "Unknown"

    def get_manufacturer(self, mac_address: str) -> str:
        """Get manufacturer name from MAC address."""
        mac = mac_address.upper().replace('-', ':')
        oui = mac[:8]

        if oui in self.oui_database:
            return self.oui_database[oui].manufacturer

        return "Unknown"


class NetworkPolicyManager:
    """
    Manages network policies for devices.

    Provides an interface to apply and query network policies,
    integrating with nftables for enforcement.
    """

    def __init__(self,
                 state_dir: Path = Path("/var/lib/fortress/filters"),
                 use_nftables: bool = True):
        """
        Initialize policy manager.

        Args:
            state_dir: Directory for storing policy state
            use_nftables: Whether to use nftables for enforcement
        """
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.use_nftables = use_nftables
        self.policies_file = state_dir / "device_policies.json"
        self.classifier = OUIClassifier()

        # Load existing policies
        self.device_policies: Dict[str, DevicePolicy] = {}
        self._load_policies()

    def _load_policies(self):
        """Load saved device policies from file."""
        if not self.policies_file.exists():
            return

        try:
            with open(self.policies_file) as f:
                data = json.load(f)

            for mac, policy_data in data.items():
                self.device_policies[mac.upper()] = DevicePolicy(
                    mac_address=mac.upper(),
                    policy=NetworkPolicy(policy_data['policy']),
                    category=DeviceCategory(policy_data.get('category', 'unknown')),
                    manufacturer=policy_data.get('manufacturer', 'Unknown'),
                    assigned_at=datetime.fromisoformat(policy_data['assigned_at']),
                    assigned_by=policy_data.get('assigned_by', 'unknown')
                )

            logger.info(f"Loaded {len(self.device_policies)} device policies")
        except Exception as e:
            logger.error(f"Error loading device policies: {e}")

    def _save_policies(self):
        """Save device policies to file."""
        try:
            data = {}
            for mac, policy in self.device_policies.items():
                data[mac] = {
                    'policy': policy.policy.value,
                    'category': policy.category.value,
                    'manufacturer': policy.manufacturer,
                    'assigned_at': policy.assigned_at.isoformat(),
                    'assigned_by': policy.assigned_by
                }

            with open(self.policies_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving device policies: {e}")

    def set_policy(self, mac_address: str, policy: NetworkPolicy,
                   assigned_by: str = "manual") -> DevicePolicy:
        """
        Set network policy for a device.

        Args:
            mac_address: Device MAC address
            policy: Policy to apply
            assigned_by: Who assigned the policy ('manual', 'auto', 'oui')

        Returns:
            The DevicePolicy object
        """
        mac = mac_address.upper().replace('-', ':')

        # Get device classification
        category, _, manufacturer = self.classifier.classify(mac)

        device_policy = DevicePolicy(
            mac_address=mac,
            policy=policy,
            category=category,
            manufacturer=manufacturer,
            assigned_at=datetime.now(),
            assigned_by=assigned_by
        )

        self.device_policies[mac] = device_policy
        self._save_policies()

        # Apply to nftables
        if self.use_nftables:
            self._apply_nftables_policy(mac, policy)

        logger.info(f"Set policy for {mac}: {policy.value} (by {assigned_by})")
        return device_policy

    def auto_classify(self, mac_address: str) -> DevicePolicy:
        """
        Automatically classify and apply policy based on OUI.

        Args:
            mac_address: Device MAC address

        Returns:
            The DevicePolicy object
        """
        mac = mac_address.upper().replace('-', ':')
        category, policy, manufacturer = self.classifier.classify(mac)

        return self.set_policy(mac, policy, assigned_by="oui")

    def get_policy(self, mac_address: str) -> Optional[DevicePolicy]:
        """Get current policy for a device."""
        mac = mac_address.upper().replace('-', ':')
        return self.device_policies.get(mac)

    def remove_policy(self, mac_address: str):
        """Remove policy for a device."""
        mac = mac_address.upper().replace('-', ':')

        if mac in self.device_policies:
            del self.device_policies[mac]
            self._save_policies()

            # Remove from nftables
            if self.use_nftables:
                self._remove_nftables_policy(mac)

            logger.info(f"Removed policy for {mac}")

    def block_device(self, mac_address: str):
        """Block a device completely."""
        self.set_policy(mac_address, NetworkPolicy.ISOLATED, assigned_by="manual")

    def unblock_device(self, mac_address: str):
        """Unblock a device (auto-classify)."""
        self.auto_classify(mac_address)

    def get_all_policies(self) -> List[DevicePolicy]:
        """Get all device policies."""
        return list(self.device_policies.values())

    def get_policies_by_type(self, policy: NetworkPolicy) -> List[DevicePolicy]:
        """Get devices with a specific policy."""
        return [p for p in self.device_policies.values() if p.policy == policy]

    def _apply_nftables_policy(self, mac: str, policy: NetworkPolicy):
        """Apply policy to nftables."""
        set_map = {
            NetworkPolicy.FULL_ACCESS: "full_access_macs",
            NetworkPolicy.LAN_ONLY: "lan_only_macs",
            NetworkPolicy.INTERNET_ONLY: "internet_only_macs",
            NetworkPolicy.ISOLATED: "blocked_macs",
        }

        if policy == NetworkPolicy.DEFAULT:
            # Remove from all sets
            self._remove_nftables_policy(mac)
            return

        target_set = set_map.get(policy)
        if not target_set:
            return

        try:
            # Remove from all sets first
            for set_name in set_map.values():
                subprocess.run(
                    ["nft", "delete", "element", "inet", "fortress_filter",
                     set_name, "{", mac, "}"],
                    capture_output=True
                )

            # Add to target set
            subprocess.run(
                ["nft", "add", "element", "inet", "fortress_filter",
                 target_set, "{", mac, "}"],
                check=True,
                capture_output=True
            )

            logger.debug(f"Applied nftables policy: {mac} -> {target_set}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to apply nftables policy: {e}")

    def _remove_nftables_policy(self, mac: str):
        """Remove device from all nftables sets."""
        sets = ["blocked_macs", "lan_only_macs", "internet_only_macs", "full_access_macs"]

        for set_name in sets:
            try:
                subprocess.run(
                    ["nft", "delete", "element", "inet", "fortress_filter",
                     set_name, "{", mac, "}"],
                    capture_output=True
                )
            except Exception:
                pass

    def sync_to_nftables(self):
        """Sync all policies to nftables."""
        logger.info("Syncing all policies to nftables...")

        for mac, policy in self.device_policies.items():
            self._apply_nftables_policy(mac, policy.policy)

        logger.info(f"Synced {len(self.device_policies)} policies to nftables")


# Convenience functions for use in web UI

def classify_device(mac_address: str) -> dict:
    """
    Classify a device and return info dictionary.

    Returns:
        dict with keys: category, policy, manufacturer, oui
    """
    classifier = OUIClassifier()
    category, policy, manufacturer = classifier.classify(mac_address)

    return {
        'mac_address': mac_address.upper(),
        'oui': mac_address.upper()[:8],
        'category': category.value,
        'recommended_policy': policy.value,
        'manufacturer': manufacturer
    }


def get_policy_manager() -> NetworkPolicyManager:
    """Get global policy manager instance."""
    # Could use singleton pattern here for performance
    return NetworkPolicyManager()


if __name__ == "__main__":
    # Test the classifier
    import sys

    if len(sys.argv) > 1:
        mac = sys.argv[1]
        result = classify_device(mac)
        print(f"\nDevice Classification for {mac}:")
        print(f"  OUI:          {result['oui']}")
        print(f"  Manufacturer: {result['manufacturer']}")
        print(f"  Category:     {result['category']}")
        print(f"  Rec. Policy:  {result['recommended_policy']}")
    else:
        print("Usage: python network_policy_manager.py <mac_address>")
        print("\nExample:")
        print("  python network_policy_manager.py B8:27:EB:12:34:56")
