#!/usr/bin/env python3
"""
Fortress Device Policy Manager - Simple SQLite-based device management

Network Policies:
- QUARANTINE: Unknown devices, no network access (default for unknowns)
- INTERNET_ONLY: Can access internet but not LAN devices
- LAN_ONLY: Can access LAN but not internet (IoT, printers)
- SMART_HOME: Curated IoT (HomePod, Echo, Matter/Thread bridges)
- FULL_ACCESS: Management devices on VLAN 200, can manage other devices

Storage: SQLite database at /var/lib/hookprobe/devices.db
"""

import sqlite3
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from enum import Enum
from contextlib import contextmanager

logger = logging.getLogger(__name__)


def _decode_dnsmasq_hostname(hostname: str) -> str:
    """Decode dnsmasq octal escapes (e.g., \\123 -> ASCII char)."""
    if not hostname or '\\' not in hostname:
        return hostname
    try:
        result = b''
        i = 0
        while i < len(hostname):
            if hostname[i] == '\\' and i + 3 < len(hostname):
                octal_str = hostname[i+1:i+4]
                if all(c in '01234567' for c in octal_str):
                    result += bytes([int(octal_str, 8)])
                    i += 4
                    continue
            result += hostname[i].encode('utf-8', errors='replace')
            i += 1
        return result.decode('utf-8', errors='replace').strip()
    except Exception:
        return hostname


def _clean_device_name(hostname: str, manufacturer: str = None) -> Optional[str]:
    """Clean device hostname, returning None if unusable.

    Handles:
    - dnsmasq octal escapes (\\123)
    - Hex prefixes (F6574fcbe4474hookprobepro -> hookprobepro)
    - UUID-like strings (return None)
    - Trailing numbers with punctuation ( 652!, 9!)
    - Auto-incremented numbers from OS conflicts (Hookprobe 10, Hookprobe's iPad 119)
    """
    if not hostname:
        return None

    name = _decode_dnsmasq_hostname(hostname)
    if not name:
        return None

    # Remove .local suffix first
    if name.endswith('.local'):
        name = name[:-6]

    # Remove hex prefixes (e.g., "F6574fcbe4474hookprobepro" -> "hookprobepro")
    hex_prefix_match = re.match(r'^[0-9a-fA-F]{8,}[-_]?(.+)$', name)
    if hex_prefix_match:
        remaining = hex_prefix_match.group(1)
        # Only use if remaining part looks like a real name (has letters)
        if re.search(r'[a-zA-Z]{3,}', remaining):
            name = remaining

    # Remove hex/UUID suffixes (e.g., "device-abc123def456")
    name = re.sub(r'[-_][0-9a-fA-F]{6,}(?:[-_]\d+)?$', '', name)

    # Remove trailing numbers with punctuation (e.g., " 652!", " 9!")
    name = re.sub(r'\s+\d+[!@#$%^&*]+$', '', name)

    # Remove pure UUID-like strings - return None to use fallback
    if re.match(r'^[0-9a-fA-F]{8}[-_ ][0-9a-fA-F]{4}[-_ ][0-9a-fA-F]{4}', name):
        return None

    # Remove trailing punctuation artifacts
    name = re.sub(r'[!@#$%^&*]+$', '', name)

    # Clean up whitespace and special chars
    name = re.sub(r'[-_]+', ' ', name)
    name = re.sub(r'\s+', ' ', name).strip()

    # Remove OS auto-incremented numbers (e.g., "Hookprobe 10", "Hookprobe's iPad 119")
    # These are added when a device sees a name conflict on the network.
    # Pattern: name followed by space and number
    trailing_num_match = re.match(r'^(.+?)\s+(\d+)$', name)
    if trailing_num_match:
        base_name = trailing_num_match.group(1)
        num = int(trailing_num_match.group(2))

        # Keep legitimate product model numbers - these patterns are unlikely auto-increment
        # iPhone 15, Galaxy S24, Pixel 8, iPad Pro 12, Watch 9, etc.
        model_patterns = [
            r'(?i)\biphone\s*\d{1,2}$',        # iPhone 11, iPhone 15
            r'(?i)\bipad\s*(pro|air|mini)?\s*\d{1,2}$',  # iPad Pro 12
            r'(?i)\bgalaxy\s*[sazm]\d{1,2}$',  # Galaxy S24
            r'(?i)\bpixel\s*\d{1,2}$',         # Pixel 8
            r'(?i)\bwatch\s*(se|ultra)?\s*\d{1,2}$',  # Watch 9, Watch Ultra 2
            r'(?i)\bmacbook\s*(pro|air)?\s*\d{2,4}$', # MacBook Pro 2023
            r'(?i)\bsurface\s*(pro|go|laptop)?\s*\d{1,2}$',  # Surface Pro 9
            r'(?i)\bps\d$',                     # PS5
            r'(?i)\bxbox\s*(one|series)?\s*[sx]?$',  # Xbox Series X
            r'(?i)\becho\s*(dot|show)?\s*\d{1,2}$',  # Echo Dot 5
        ]

        is_model_number = any(re.search(p, name) for p in model_patterns)

        # Strip the number if:
        # 1. It's a high number (>20) - unlikely to be a real model number
        # 2. Name contains possessive ('s) - user's personal device with conflict number
        # 3. Base name ends with common device words but isn't a known model pattern
        is_possessive = "'s" in base_name.lower() or "'s" in base_name
        is_high_number = num > 20

        if not is_model_number and (is_high_number or is_possessive or num > 9):
            name = base_name

    # If name is mostly hex/numbers, return None for fallback
    if name and len(re.sub(r'[0-9a-fA-F\s-]', '', name)) < 3:
        return None

    if not name or len(name) < 2:
        return None

    return name


def _get_friendly_name(mac: str, hostname: str, manufacturer: str, device_type: str) -> str:
    """Generate a user-friendly device name.

    Priority:
    1. Cleaned hostname (if usable)
    2. Device type + last 4 MAC chars (e.g., "iPhone CE05")
    3. Manufacturer + last 4 MAC chars (e.g., "Apple CE05")
    4. Generic "Device CE05"
    """
    # Try cleaned hostname first
    cleaned = _clean_device_name(hostname, manufacturer)
    if cleaned:
        return cleaned

    # Get last 4 MAC chars for uniqueness
    mac_suffix = mac[-5:].replace(':', '') if mac else '????'

    # Try device type
    if device_type and device_type.lower() not in ('unknown', '', 'none'):
        # Make device type more readable
        dt = device_type.replace('_', ' ').title()
        return f"{dt} {mac_suffix}"

    # Try manufacturer
    if manufacturer and manufacturer.lower() not in ('unknown', 'private', '', 'none'):
        return f"{manufacturer} {mac_suffix}"

    # Fallback
    return f"Device {mac_suffix}"

# Database path
DB_PATH = Path('/var/lib/hookprobe/devices.db')
AGENT_DATA_FILE = Path('/opt/hookprobe/fortress/data/devices.json')


class NetworkPolicy(str, Enum):
    """Network access policies for devices."""
    QUARANTINE = 'quarantine'       # No network access - unknown devices
    INTERNET_ONLY = 'internet_only' # Internet access, no LAN
    LAN_ONLY = 'lan_only'           # LAN access, no internet
    SMART_HOME = 'smart_home'       # Curated IoT (bridges, smart home)
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
    NetworkPolicy.SMART_HOME: {
        'name': 'Smart Home',
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
        """Set or update device policy.

        This method:
        1. Stores the policy in SQLite database
        2. Applies OpenFlow rules via device_data_manager for enforcement
        """
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

        # Apply OpenFlow rules for actual network enforcement
        self._apply_openflow_rules(mac, policy)

        return self.get_device(mac)

    def _apply_openflow_rules(self, mac: str, policy: str):
        """Apply OpenFlow rules via device_data_manager for NAC enforcement.

        Policy name mapping for compatibility:
        - quarantine -> isolated (both mean block all)
        """
        # Map device_policies names to device_data_manager names
        policy_map = {
            'quarantine': 'isolated',
        }
        internal_policy = policy_map.get(policy, policy)

        try:
            # Try different import paths for flexibility
            ddm = None
            try:
                # When running from same directory or lib/ is in path
                from device_data_manager import get_device_data_manager
                ddm = get_device_data_manager()
            except ImportError:
                try:
                    # When running from web module
                    import sys
                    from pathlib import Path
                    lib_path = Path(__file__).parent
                    if str(lib_path) not in sys.path:
                        sys.path.insert(0, str(lib_path))
                    from device_data_manager import get_device_data_manager
                    ddm = get_device_data_manager()
                except ImportError:
                    pass

            if ddm:
                ddm._apply_policy_rules(mac, internal_policy)
                logger.debug(f"Applied OpenFlow rules for {mac} with policy {internal_policy}")
            else:
                logger.warning("device_data_manager not available - OpenFlow rules not applied")

        except Exception as e:
            logger.warning(f"Failed to apply OpenFlow rules for {mac}: {e}")

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

    # Smart home hubs/bridges get SMART_HOME (they need both internet and LAN)
    if device_type in ('homepod', 'echo', 'google_home', 'smart_hub', 'bridge'):
        return NetworkPolicy.SMART_HOME.value

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
        raw_hostname = device.get('hostname') or (stored.get('hostname') if stored else None)
        manufacturer = device.get('manufacturer') or (stored.get('manufacturer') if stored else 'Unknown') or 'Unknown'
        device_type = device.get('device_type') or (stored.get('device_type') if stored else 'unknown') or 'unknown'

        devices.append({
            'mac_address': mac,
            'ip_address': device.get('ip_address', ''),
            'hostname': _get_friendly_name(mac, raw_hostname, manufacturer, device_type),
            'manufacturer': manufacturer,
            'device_type': device_type,
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


def sync_all_policies() -> int:
    """
    Sync all stored policies to OpenFlow rules.

    Call this on startup to restore NAC enforcement after reboot.
    OpenFlow rules in OVS are volatile and lost on restart, but
    policies persist in SQLite database.

    Returns:
        Number of policies synced
    """
    db = get_device_db()
    policies = db.get_all_policies()

    synced = 0
    for mac, policy in policies.items():
        try:
            db._apply_openflow_rules(mac, policy)
            synced += 1
        except Exception as e:
            logger.warning(f"Failed to sync policy for {mac}: {e}")

    logger.info(f"Synced {synced}/{len(policies)} device policies to OpenFlow")
    return synced
