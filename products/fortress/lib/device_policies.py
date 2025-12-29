#!/usr/bin/env python3
"""
Fortress Device Policy Manager - Simple SQLite-based device management

Network Policies:
- QUARANTINE: Unknown devices, no network access (default for unknowns)
- INTERNET_ONLY: Can access internet but not LAN devices
- LAN_ONLY: Can access LAN but not internet (IoT, printers)
- NORMAL: Curated IoT (HomePod, Echo, Matter/Thread bridges)
- FULL_ACCESS: Management devices on VLAN 200, can manage other devices

Storage: SQLite database at /var/lib/hookprobe/devices.db
"""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from enum import Enum
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Database path
DB_PATH = Path('/var/lib/hookprobe/devices.db')
AGENT_DATA_FILE = Path('/opt/hookprobe/fortress/data/devices.json')


class NetworkPolicy(str, Enum):
    """Network access policies for devices."""
    QUARANTINE = 'quarantine'       # No network access - unknown devices
    INTERNET_ONLY = 'internet_only' # Internet access, no LAN
    LAN_ONLY = 'lan_only'           # LAN access, no internet
    NORMAL = 'normal'               # Curated IoT (bridges, smart home)
    FULL_ACCESS = 'full_access'     # Full access, can manage others


# Policy display info
POLICY_INFO = {
    NetworkPolicy.QUARANTINE: {
        'name': 'Quarantine',
        'icon': 'fa-ban',
        'color': 'danger',
        'description': 'No network access - unknown/suspicious device',
        'internet': False,
        'lan': False,
    },
    NetworkPolicy.INTERNET_ONLY: {
        'name': 'Internet Only',
        'icon': 'fa-globe',
        'color': 'info',
        'description': 'Can access internet but not local devices',
        'internet': True,
        'lan': False,
    },
    NetworkPolicy.LAN_ONLY: {
        'name': 'LAN Only',
        'icon': 'fa-network-wired',
        'color': 'warning',
        'description': 'Can access local network but not internet',
        'internet': False,
        'lan': True,
    },
    NetworkPolicy.NORMAL: {
        'name': 'Normal',
        'icon': 'fa-home',
        'color': 'success',
        'description': 'Smart home devices with curated access',
        'internet': True,
        'lan': True,
    },
    NetworkPolicy.FULL_ACCESS: {
        'name': 'Full Access',
        'icon': 'fa-shield-alt',
        'color': 'primary',
        'description': 'Management device with full network access',
        'internet': True,
        'lan': True,
    },
}


class DevicePolicyDB:
    """SQLite-based device policy storage."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._ensure_db()

    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    mac_address TEXT PRIMARY KEY,
                    hostname TEXT,
                    manufacturer TEXT,
                    device_type TEXT,
                    policy TEXT DEFAULT 'quarantine',
                    notes TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_devices_policy ON devices(policy)
            ''')
            conn.commit()

    @contextmanager
    def _get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def get_device(self, mac: str) -> Optional[Dict]:
        """Get device by MAC address."""
        with self._get_conn() as conn:
            row = conn.execute(
                'SELECT * FROM devices WHERE mac_address = ?',
                (mac.upper(),)
            ).fetchone()
            return dict(row) if row else None

    def set_policy(self, mac: str, policy: str, hostname: str = None,
                   manufacturer: str = None, device_type: str = None,
                   notes: str = None) -> Dict:
        """Set or update device policy."""
        mac = mac.upper()
        now = datetime.now().isoformat()

        # Validate policy
        try:
            policy_enum = NetworkPolicy(policy)
        except ValueError:
            raise ValueError(f"Invalid policy: {policy}")

        with self._get_conn() as conn:
            existing = self.get_device(mac)

            if existing:
                # Update existing
                conn.execute('''
                    UPDATE devices SET
                        policy = ?,
                        hostname = COALESCE(?, hostname),
                        manufacturer = COALESCE(?, manufacturer),
                        device_type = COALESCE(?, device_type),
                        notes = COALESCE(?, notes),
                        last_seen = ?,
                        updated_at = ?
                    WHERE mac_address = ?
                ''', (policy, hostname, manufacturer, device_type, notes, now, now, mac))
            else:
                # Insert new
                conn.execute('''
                    INSERT INTO devices (mac_address, policy, hostname, manufacturer,
                                        device_type, notes, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (mac, policy, hostname, manufacturer, device_type, notes, now, now))

            conn.commit()

        return self.get_device(mac)

    def get_all_policies(self) -> Dict[str, str]:
        """Get all MAC -> policy mappings."""
        with self._get_conn() as conn:
            rows = conn.execute('SELECT mac_address, policy FROM devices').fetchall()
            return {row['mac_address']: row['policy'] for row in rows}

    def get_devices_by_policy(self, policy: str) -> List[Dict]:
        """Get all devices with a specific policy."""
        with self._get_conn() as conn:
            rows = conn.execute(
                'SELECT * FROM devices WHERE policy = ? ORDER BY last_seen DESC',
                (policy,)
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_device(self, mac: str) -> bool:
        """Delete a device from the database."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                'DELETE FROM devices WHERE mac_address = ?',
                (mac.upper(),)
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_stats(self) -> Dict:
        """Get device statistics by policy."""
        with self._get_conn() as conn:
            rows = conn.execute('''
                SELECT policy, COUNT(*) as count FROM devices GROUP BY policy
            ''').fetchall()
            stats = {p.value: 0 for p in NetworkPolicy}
            for row in rows:
                stats[row['policy']] = row['count']
            stats['total'] = sum(stats.values())
            return stats


# Global instance
_db: Optional[DevicePolicyDB] = None


def get_device_db() -> DevicePolicyDB:
    """Get the global device policy database instance."""
    global _db
    if _db is None:
        _db = DevicePolicyDB()
    return _db


def load_agent_devices() -> List[Dict]:
    """Load devices from qsecbit agent data file."""
    if not AGENT_DATA_FILE.exists():
        logger.debug(f"Agent data file not found: {AGENT_DATA_FILE}")
        return []

    try:
        data = json.loads(AGENT_DATA_FILE.read_text())
        devices = data.get('devices', []) if isinstance(data, dict) else data
        if isinstance(devices, list):
            return [d for d in devices if isinstance(d, dict)]
        return []
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to load agent devices: {e}")
        return []


def should_quarantine(device: Dict) -> bool:
    """Determine if a device should be auto-quarantined."""
    # Quarantine if: no hostname AND unknown manufacturer AND unknown type
    hostname = device.get('hostname')
    manufacturer = device.get('manufacturer', 'Unknown')
    device_type = device.get('device_type', 'unknown')

    no_hostname = not hostname or hostname in ('', '*', 'unknown', None)
    unknown_vendor = manufacturer in ('Unknown', 'Private', '', None)
    unknown_type = device_type in ('unknown', '', None)

    return no_hostname and unknown_vendor and unknown_type


def get_recommended_policy(device: Dict) -> str:
    """Get recommended policy based on device characteristics."""
    device_type = device.get('device_type', 'unknown').lower()
    manufacturer = device.get('manufacturer', '').lower()

    # Smart home hubs/bridges get NORMAL (they need both internet and LAN)
    if device_type in ('homepod', 'echo', 'google_home', 'smart_hub', 'bridge'):
        return NetworkPolicy.NORMAL.value

    # IoT devices get LAN_ONLY
    if device_type in ('iot', 'camera', 'printer', 'smart_plug', 'sensor'):
        return NetworkPolicy.LAN_ONLY.value

    # Phones, tablets, laptops get INTERNET_ONLY by default
    if device_type in ('iphone', 'android', 'phone', 'tablet', 'laptop', 'macbook'):
        return NetworkPolicy.INTERNET_ONLY.value

    # Raspberry Pi on management interface gets FULL_ACCESS
    if device_type == 'raspberry_pi':
        return NetworkPolicy.FULL_ACCESS.value

    # Unknown devices get quarantined
    if should_quarantine(device):
        return NetworkPolicy.QUARANTINE.value

    return NetworkPolicy.INTERNET_ONLY.value


def get_all_devices() -> List[Dict]:
    """Get all devices merged with their policies.

    Merges live data from agent with stored policies from database.
    Auto-assigns policies to new devices based on their characteristics.
    """
    db = get_device_db()
    agent_devices = load_agent_devices()
    stored_policies = db.get_all_policies()

    devices = []
    now = datetime.now().isoformat()

    for device in agent_devices:
        if not isinstance(device, dict):
            continue

        mac = device.get('mac_address', '').upper()
        if not mac:
            continue

        # Get stored policy or assign new one
        if mac in stored_policies:
            policy = stored_policies[mac]
            stored = db.get_device(mac)
        else:
            # New device - auto-assign policy
            policy = get_recommended_policy(device)
            stored = db.set_policy(
                mac=mac,
                policy=policy,
                hostname=device.get('hostname'),
                manufacturer=device.get('manufacturer'),
                device_type=device.get('device_type'),
            )
            logger.info(f"New device {mac}: auto-assigned policy '{policy}'")

        # Get policy info
        try:
            policy_enum = NetworkPolicy(policy)
            policy_info = POLICY_INFO.get(policy_enum, POLICY_INFO[NetworkPolicy.QUARANTINE])
        except ValueError:
            policy_info = POLICY_INFO[NetworkPolicy.QUARANTINE]

        # Merge device data
        devices.append({
            'mac_address': mac,
            'ip_address': device.get('ip_address', ''),
            'hostname': device.get('hostname') or stored.get('hostname') or f'device-{mac[-5:].replace(":", "")}',
            'manufacturer': device.get('manufacturer') or stored.get('manufacturer', 'Unknown'),
            'device_type': device.get('device_type') or stored.get('device_type', 'unknown'),
            'policy': policy,
            'policy_name': policy_info['name'],
            'policy_icon': policy_info['icon'],
            'policy_color': policy_info['color'],
            'internet_access': policy_info['internet'],
            'lan_access': policy_info['lan'],
            'is_online': device.get('state') in ('REACHABLE', 'DELAY'),
            'interface': device.get('interface', ''),
            'first_seen': stored.get('first_seen', now) if stored else now,
            'last_seen': device.get('last_seen', now),
            'notes': stored.get('notes', '') if stored else '',
        })

    return devices


def get_device_stats() -> Dict:
    """Get device statistics."""
    devices = get_all_devices()
    stats = {
        'total': len(devices),
        'online': len([d for d in devices if d['is_online']]),
        'offline': len([d for d in devices if not d['is_online']]),
        'quarantined': len([d for d in devices if d['policy'] == 'quarantine']),
        'by_policy': {},
    }
    for policy in NetworkPolicy:
        stats['by_policy'][policy.value] = len([d for d in devices if d['policy'] == policy.value])
    return stats


def set_device_policy(mac: str, policy: str) -> Dict:
    """Set device policy."""
    db = get_device_db()
    return db.set_policy(mac, policy)


def get_policy_info(policy: str) -> Dict:
    """Get policy display information."""
    try:
        policy_enum = NetworkPolicy(policy)
        return POLICY_INFO.get(policy_enum, POLICY_INFO[NetworkPolicy.QUARANTINE])
    except ValueError:
        return POLICY_INFO[NetworkPolicy.QUARANTINE]
