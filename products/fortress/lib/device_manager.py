#!/usr/bin/env python3
"""
Fortress Device Manager

Tracks connected devices, detects new connections, and manages device inventory.
Integrates with VLAN manager for network segmentation.
"""

import logging
import subprocess
import re
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass

from .config import get_config
from .database import get_db
from .vlan_manager import get_vlan_manager
from .device_identity import DeviceIdentityManager, get_identity_manager
from .security_utils import mask_mac

# Import mDNS resolver for Apple device name discovery
try:
    from .mdns_resolver import MDNSResolver, get_mdns_resolver
    HAS_MDNS_RESOLVER = True
except ImportError:
    HAS_MDNS_RESOLVER = False

logger = logging.getLogger(__name__)

# Path to DHCP events JSON file (updated by dhcp-event.sh)
DHCP_DEVICES_FILE = Path("/opt/hookprobe/fortress/data/devices.json")


@dataclass
class DeviceInfo:
    """Device information structure."""
    mac_address: str
    ip_address: Optional[str]
    hostname: Optional[str]
    vlan_id: int
    device_type: Optional[str]
    manufacturer: Optional[str]
    is_blocked: bool
    is_known: bool
    first_seen: datetime
    last_seen: datetime
    identity_id: Optional[str] = None
    dhcp_fingerprint: Optional[str] = None


# Common OUI (Organizationally Unique Identifier) database for manufacturer lookup
OUI_DATABASE = {
    'Apple': ['00:1C:B3', '00:03:93', '00:0A:27', '00:0A:95', '00:10:FA', '00:11:24',
              '00:14:51', '00:16:CB', '00:17:F2', '00:19:E3', '00:1B:63', '00:1D:4F',
              '00:1E:52', '00:1E:C2', '00:1F:5B', '00:1F:F3', '00:21:E9', '00:22:41',
              '00:23:12', '00:23:32', '00:23:6C', '00:23:DF', '00:24:36', '00:25:00',
              '00:25:4B', '00:25:BC', '00:26:08', '00:26:4A', '00:26:B0', '00:26:BB',
              'A4:5E:60', 'AC:BC:32', 'B0:34:95', 'B8:09:8A', 'BC:52:B7', 'C0:84:7A',
              'D4:9A:20', 'DC:2B:2A', 'E0:B9:BA', 'F0:B4:79', 'F4:5C:89'],
    'Samsung': ['00:00:F0', '00:07:AB', '00:09:18', '00:12:47', '00:12:FB', '00:13:77',
                '00:15:99', '00:15:B9', '00:16:32', '00:16:6B', '00:16:6C', '00:17:C9',
                '00:17:D5', '00:18:AF', '00:1A:8A', '00:1B:98', '00:1C:43', '00:1D:25',
                '00:1D:F6', '00:1E:7D', '00:1F:CC', '00:21:4C', '00:21:D1', '00:21:D2'],
    'Google': ['3C:5A:B4', '94:EB:2C', 'F4:F5:D8', '54:60:09', 'F8:8F:CA', '94:94:26'],
    'Intel': ['00:02:B3', '00:03:47', '00:04:23', '00:07:E9', '00:0C:F1', '00:0E:0C',
              '00:0E:35', '00:11:11', '00:12:F0', '00:13:02', '00:13:20', '00:13:CE'],
    'Realtek': ['00:E0:4C', '52:54:00', '00:20:18'],
    'Dell': ['00:06:5B', '00:08:74', '00:0B:DB', '00:0D:56', '00:0F:1F', '00:11:43'],
    'HP': ['00:01:E6', '00:02:A5', '00:04:EA', '00:08:02', '00:0A:57', '00:0B:CD'],
    'Cisco': ['00:00:0C', '00:01:42', '00:01:43', '00:01:63', '00:01:64', '00:01:96'],
    'TP-Link': ['00:27:19', '14:CC:20', '30:B5:C2', '50:C7:BF', '54:C8:0F', '60:E3:27'],
}


class DeviceManager:
    """
    Manages device discovery, tracking, and inventory.

    Features:
    - ARP-based device discovery
    - Manufacturer identification via OUI
    - Device type detection
    - VLAN assignment integration
    - New device alerts
    """

    def __init__(self):
        self.config = get_config()
        self.db = get_db()
        self.vlan_manager = get_vlan_manager()
        self.identity_manager = get_identity_manager()

        # Initialize mDNS resolver for Apple device friendly names
        self.mdns_resolver = None
        if HAS_MDNS_RESOLVER:
            try:
                self.mdns_resolver = get_mdns_resolver()
                logger.info("mDNS resolver initialized for device name discovery")
            except Exception as e:
                logger.warning(f"Could not initialize mDNS resolver: {e}")

        # Cache for recent scans
        self._last_scan: Dict[str, Dict] = {}
        self._callbacks: List[callable] = []
        self._dhcp_cache: Dict[str, Dict] = {}  # MAC -> DHCP info cache

    def _run_cmd(self, cmd: List[str], timeout: int = 30) -> Tuple[bool, str, str]:
        """Run command safely."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            logger.error(f"Command error: {e}")
            return False, "", str(e)

    # ========================================
    # Device Discovery
    # ========================================

    def scan_network(self, vlan_id: int = None) -> List[Dict]:
        """
        Scan network for devices using ARP.

        Returns list of discovered devices.
        """
        devices = []

        # Get ARP table
        success, output, _ = self._run_cmd(['ip', 'neigh', 'show'])
        if not success:
            return devices

        for line in output.strip().split('\n'):
            if not line or 'FAILED' in line:
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            ip_address = parts[0]
            mac_address = None

            # Find MAC address in output
            for i, part in enumerate(parts):
                if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', part):
                    mac_address = part.upper()
                    break

            if not mac_address:
                continue

            device = {
                'ip_address': ip_address,
                'mac_address': mac_address,
                'state': 'REACHABLE' if 'REACHABLE' in line else 'STALE',
            }

            devices.append(device)

        return devices

    def _get_dhcp_info(self, mac: str) -> Dict:
        """
        Get DHCP information for a device from the DHCP events file.

        The dhcp-event.sh script writes device info to /opt/hookprobe/fortress/data/devices.json
        This includes DHCP Option 55 fingerprint which is crucial for identity tracking.
        """
        mac_upper = mac.upper()

        # Check cache first
        if mac_upper in self._dhcp_cache:
            return self._dhcp_cache[mac_upper]

        # Load from DHCP devices file
        try:
            if DHCP_DEVICES_FILE.exists():
                with open(DHCP_DEVICES_FILE, 'r') as f:
                    devices = json.load(f)
                    if mac_upper in devices:
                        self._dhcp_cache[mac_upper] = devices[mac_upper]
                        return devices[mac_upper]
        except Exception as e:
            logger.debug(f"Could not load DHCP info for {mac}: {e}")

        return {}

    def discover_devices(self) -> List[Dict]:
        """
        Full device discovery with manufacturer identification and identity tracking.

        Returns list of new or updated devices.
        """
        discovered = []
        scanned = self.scan_network()

        for device in scanned:
            mac = device['mac_address']
            ip = device['ip_address']

            # Check if device exists
            existing = self.db.get_device(mac)

            # Get additional info - pass MAC for mDNS cache lookup
            hostname = self._resolve_hostname(ip, mac)
            manufacturer = self._lookup_manufacturer(mac)
            device_type = self._detect_device_type(mac, hostname, manufacturer)

            # Get DHCP fingerprint for identity tracking
            dhcp_info = self._get_dhcp_info(mac)
            dhcp_fingerprint = dhcp_info.get('dhcp_fingerprint')
            dhcp_vendor_class = dhcp_info.get('vendor_class')
            dhcp_hostname = dhcp_info.get('hostname') or hostname

            # Get mDNS friendly name separately (for Apple devices like "hookprobe's iPhone")
            mdns_name = self._resolve_mdns_name(ip, mac)
            if mdns_name:
                logger.info(f"Device {mask_mac(mac)} has mDNS name: '{mdns_name}'")
                # Prefer mDNS name over DHCP hostname for display
                dhcp_hostname = mdns_name

            # Link to persistent device identity (handles MAC randomization)
            identity = None
            try:
                identity = self.identity_manager.find_or_create_identity(
                    mac=mac,
                    dhcp_option55=dhcp_fingerprint,
                    mdns_name=mdns_name,  # Pass mDNS friendly name
                    hostname=dhcp_hostname,
                    ip_address=ip,
                    device_type=device_type,
                    manufacturer=manufacturer,
                )
                if identity:
                    logger.debug(f"Device {mac} linked to identity '{identity.display_name}'")
            except Exception as e:
                logger.warning(f"Could not link device {mac} to identity: {e}")

            if existing:
                # Update existing device
                self.db.upsert_device(
                    mac_address=mac,
                    ip_address=ip,
                    hostname=hostname or existing.get('hostname'),
                    device_type=device_type or existing.get('device_type'),
                    manufacturer=manufacturer or existing.get('manufacturer'),
                    vlan_id=existing['vlan_id'],
                    identity_id=identity.identity_id if identity else existing.get('identity_id'),
                    dhcp_fingerprint=dhcp_fingerprint or existing.get('dhcp_fingerprint'),
                )
            else:
                # New device - determine VLAN
                vlan_id = self.vlan_manager.auto_assign_device(mac, device_type)

                # Insert device
                self.db.upsert_device(
                    mac_address=mac,
                    ip_address=ip,
                    hostname=hostname,
                    device_type=device_type,
                    manufacturer=manufacturer,
                    vlan_id=vlan_id,
                    identity_id=identity.identity_id if identity else None,
                    dhcp_fingerprint=dhcp_fingerprint,
                )

                # Trigger new device callbacks
                self._notify_new_device(mac, ip, vlan_id, device_type)

                logger.info(f"New device discovered: {mac} ({ip}) -> VLAN {vlan_id}" +
                           (f" [Identity: {identity.display_name}]" if identity else ""))

            discovered.append({
                'mac_address': mac,
                'ip_address': ip,
                'hostname': hostname,
                'manufacturer': manufacturer,
                'device_type': device_type,
                'identity_id': identity.identity_id if identity else None,
                'identity_name': identity.display_name if identity else None,
                'dhcp_fingerprint': dhcp_fingerprint,
                'is_new': existing is None
            })

        return discovered

    def _resolve_hostname(self, ip_address: str, mac: str = None) -> Optional[str]:
        """
        Resolve hostname via mDNS first, then fall back to reverse DNS.

        For Apple devices, mDNS gives us the friendly name like "hookprobe's iPhone"
        instead of just "Johns-iPhone".
        """
        # Try mDNS first (gives us premium Apple device names)
        if self.mdns_resolver:
            try:
                mdns_result = self.mdns_resolver.resolve(ip_address, mac, timeout=2.0)
                if mdns_result and mdns_result.friendly_name:
                    logger.debug(f"mDNS resolved for {mask_mac(mac) if mac else 'unknown'}")
                    return mdns_result.friendly_name
            except Exception as e:
                logger.debug(f"mDNS resolution failed: {type(e).__name__}")

        # Fall back to reverse DNS
        try:
            import socket
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname if hostname != ip_address else None
        except Exception:
            return None

    def _resolve_mdns_name(self, ip_address: str, mac: str = None) -> Optional[str]:
        """
        Get friendly mDNS name for Apple devices like "hookprobe's iPhone".

        This is specifically for the premium device name feature.
        Returns None if mDNS is not available or device doesn't advertise.
        """
        if not self.mdns_resolver:
            return None

        try:
            mdns_result = self.mdns_resolver.resolve(ip_address, mac, timeout=2.0)
            if mdns_result and mdns_result.friendly_name:
                return mdns_result.friendly_name
        except Exception as e:
            logger.debug(f"mDNS name lookup failed for {mask_mac(mac) if mac else 'unknown'}: {type(e).__name__}")

        return None

    def _lookup_manufacturer(self, mac_address: str) -> Optional[str]:
        """Lookup manufacturer from MAC OUI."""
        mac_prefix = mac_address[:8].upper()

        for manufacturer, ouis in OUI_DATABASE.items():
            if mac_prefix in ouis:
                return manufacturer

        return None

    def _detect_device_type(self, mac: str, hostname: str, manufacturer: str) -> Optional[str]:
        """Detect device type from available information."""
        hostname_lower = (hostname or '').lower()
        manufacturer_lower = (manufacturer or '').lower()

        # Hostname-based detection
        if 'iphone' in hostname_lower or 'ipad' in hostname_lower:
            return 'mobile_phone' if 'iphone' in hostname_lower else 'tablet'
        if 'android' in hostname_lower:
            return 'mobile_phone'
        if 'macbook' in hostname_lower or 'imac' in hostname_lower:
            return 'laptop' if 'book' in hostname_lower else 'desktop'
        if 'windows' in hostname_lower or '-pc' in hostname_lower:
            return 'desktop'
        if 'printer' in hostname_lower or 'hp-' in hostname_lower:
            return 'printer'
        if 'camera' in hostname_lower or 'cam-' in hostname_lower:
            return 'camera'

        # Manufacturer-based detection
        if manufacturer_lower == 'apple':
            return 'apple_device'
        if manufacturer_lower in ['samsung', 'google']:
            return 'mobile_phone'

        return None

    def _notify_new_device(self, mac: str, ip: str, vlan_id: int, device_type: str):
        """Notify callbacks about new device."""
        for callback in self._callbacks:
            try:
                callback({
                    'mac_address': mac,
                    'ip_address': ip,
                    'vlan_id': vlan_id,
                    'device_type': device_type,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def register_callback(self, callback: callable):
        """Register callback for new device notifications."""
        self._callbacks.append(callback)

    # ========================================
    # Device Management
    # ========================================

    def get_device(self, mac_address: str) -> Optional[Dict]:
        """Get device by MAC address."""
        return self.db.get_device(mac_address)

    def get_all_devices(self, vlan_id: int = None, active_only: bool = False) -> List[Dict]:
        """Get all devices with optional filters."""
        return self.db.get_devices(vlan_id=vlan_id, active_only=active_only)

    def get_active_devices(self) -> List[Dict]:
        """Get currently active devices."""
        return self.db.get_devices(active_only=True)

    def get_device_count(self) -> Dict[str, int]:
        """Get device counts summary."""
        all_devices = self.get_all_devices()
        active_devices = self.get_active_devices()
        blocked_devices = [d for d in all_devices if d.get('is_blocked')]

        return {
            'total': len(all_devices),
            'active': len(active_devices),
            'blocked': len(blocked_devices),
            'by_vlan': self.db.get_device_count_by_vlan()
        }

    def block_device(self, mac_address: str, reason: str = None) -> bool:
        """Block a device from the network."""
        mac = mac_address.upper()

        # Update database
        success = self.db.block_device(mac, blocked=True)

        if success:
            # Add OVS flow to drop traffic from this MAC
            self._run_cmd([
                'ovs-ofctl', 'add-flow', self.config.ovs_bridge,
                f'priority=1000,dl_src={mac},actions=drop'
            ])
            self._run_cmd([
                'ovs-ofctl', 'add-flow', self.config.ovs_bridge,
                f'priority=1000,dl_dst={mac},actions=drop'
            ])

            # Audit log
            self.db.audit_log(
                user_id="system",
                action="device_blocked",
                resource_type="device",
                resource_id=mac,
                details={"reason": reason}
            )

            logger.info(f"Blocked device: {mac}")

        return success

    def unblock_device(self, mac_address: str) -> bool:
        """Unblock a device."""
        mac = mac_address.upper()

        success = self.db.block_device(mac, blocked=False)

        if success:
            # Remove block flows
            self._run_cmd([
                'ovs-ofctl', 'del-flows', self.config.ovs_bridge,
                f'dl_src={mac}'
            ])
            self._run_cmd([
                'ovs-ofctl', 'del-flows', self.config.ovs_bridge,
                f'dl_dst={mac}'
            ])

            self.db.audit_log(
                user_id="system",
                action="device_unblocked",
                resource_type="device",
                resource_id=mac
            )

            logger.info(f"Unblocked device: {mac}")

        return success

    def mark_device_known(self, mac_address: str, known: bool = True, name: str = None) -> bool:
        """Mark a device as known/trusted."""
        mac = mac_address.upper()

        with self.db.get_cursor() as cursor:
            cursor.execute(
                "UPDATE devices SET is_known = %s, hostname = COALESCE(%s, hostname) WHERE mac_address = %s",
                (known, name, mac)
            )
            return cursor.rowcount > 0

    def set_device_notes(self, mac_address: str, notes: str) -> bool:
        """Set notes for a device."""
        mac = mac_address.upper()

        with self.db.get_cursor() as cursor:
            cursor.execute(
                "UPDATE devices SET notes = %s WHERE mac_address = %s",
                (notes, mac)
            )
            return cursor.rowcount > 0

    # ========================================
    # Device Inventory Export
    # ========================================

    def export_inventory_csv(self) -> str:
        """Export device inventory as CSV."""
        import csv
        import io

        devices = self.get_all_devices()

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'MAC Address', 'IP Address', 'Hostname', 'VLAN', 'Device Type',
            'Manufacturer', 'Known', 'Blocked', 'First Seen', 'Last Seen', 'Notes'
        ])

        for device in devices:
            writer.writerow([
                device.get('mac_address', ''),
                device.get('ip_address', ''),
                device.get('hostname', ''),
                device.get('vlan_id', ''),
                device.get('device_type', ''),
                device.get('manufacturer', ''),
                'Yes' if device.get('is_known') else 'No',
                'Yes' if device.get('is_blocked') else 'No',
                device.get('first_seen', ''),
                device.get('last_seen', ''),
                device.get('notes', ''),
            ])

        return output.getvalue()

    def export_inventory_json(self) -> str:
        """Export device inventory as JSON."""
        devices = self.get_all_devices()

        # Convert datetime objects to strings
        for device in devices:
            for key in ['first_seen', 'last_seen']:
                if device.get(key):
                    device[key] = str(device[key])

        return json.dumps(devices, indent=2)


# Singleton instance
_device_manager: Optional[DeviceManager] = None


def get_device_manager() -> DeviceManager:
    """Get the device manager singleton."""
    global _device_manager
    if _device_manager is None:
        _device_manager = DeviceManager()
    return _device_manager
