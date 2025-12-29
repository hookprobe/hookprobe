"""
Fortress SDN Views - Unified Device and Network Policy Management

Provides a single dashboard for managing all network devices with:
- Complete visibility: IP, MAC, vendor, policy, status
- OUI-based automatic classification
- Network policy controls (VLAN or filter mode)
- Real-time status monitoring
- Bulk operations
"""

from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime
import json

from . import sdn_bp
from ..auth.decorators import operator_required

# Import lib modules with robust fallback mechanism
# Priority 1: Import from lib package (container environment)
# Priority 2: Import via path manipulation (development)
import sys
from pathlib import Path

DB_AVAILABLE = False
POLICY_MANAGER_AVAILABLE = False
SDN_AUTOPILOT_AVAILABLE = False
DFS_AVAILABLE = False

# Add lib path for development
lib_path = Path(__file__).parent.parent.parent.parent / 'lib'
if lib_path.exists() and str(lib_path) not in sys.path:
    sys.path.insert(0, str(lib_path))

# Try to import database and device management
try:
    # Try as package first (container)
    from lib import get_db, get_device_manager, get_vlan_manager
    DB_AVAILABLE = True
except ImportError:
    try:
        # Fallback to direct import (development)
        from database import get_db
        from device_manager import get_device_manager
        from vlan_manager import get_vlan_manager
        DB_AVAILABLE = True
    except ImportError:
        pass

# Try to import network policy manager
try:
    from lib.network_policy_manager import (
        OUIClassifier,
        NetworkPolicyManager,
        NetworkPolicy,
        DeviceCategory,
    )
    POLICY_MANAGER_AVAILABLE = True
except ImportError:
    try:
        from network_policy_manager import (
            OUIClassifier,
            NetworkPolicyManager,
            NetworkPolicy,
            DeviceCategory,
        )
        POLICY_MANAGER_AVAILABLE = True
    except ImportError:
        pass

# Fallback classification function if policy manager unavailable
if POLICY_MANAGER_AVAILABLE:
    def classify_device(mac_address):
        """Classify device using OUI database."""
        classifier = OUIClassifier()
        return classifier.classify(mac_address)
else:
    def classify_device(mac_address):
        """Fallback classification when policy manager unavailable."""
        return {
            'mac_address': mac_address.upper(),
            'oui': mac_address.upper()[:8],
            'category': 'unknown',
            'recommended_policy': 'default',
            'manufacturer': 'Unknown'
        }

# SDN Auto-Pilot for segment management
try:
    from lib import get_sdn_autopilot
    from lib.sdn_autopilot import NetworkSegment, DeviceCategory as SegmentCategory
    SDN_AUTOPILOT_AVAILABLE = True
except ImportError:
    try:
        from sdn_autopilot import get_sdn_autopilot, NetworkSegment, DeviceCategory as SegmentCategory
        SDN_AUTOPILOT_AVAILABLE = True
    except ImportError:
        pass

# DFS Intelligence for WiFi channel data
try:
    # Try shared module path
    dfs_path = Path(__file__).parent.parent.parent.parent.parent.parent / 'shared' / 'wireless'
    if dfs_path.exists() and str(dfs_path) not in sys.path:
        sys.path.insert(0, str(dfs_path))
    from dfs_intelligence import DFSDatabase, ChannelScorer
    DFS_AVAILABLE = True
except ImportError:
    pass

# Device Data Manager for CRUD operations
DEVICE_DATA_MANAGER_AVAILABLE = False
try:
    from lib.device_data_manager import (
        get_device_data_manager,
        DevicePolicy as DataPolicy,
        DeviceCategory as DataCategory,
    )
    DEVICE_DATA_MANAGER_AVAILABLE = True
except ImportError:
    try:
        from device_data_manager import (
            get_device_data_manager,
            DevicePolicy as DataPolicy,
            DeviceCategory as DataCategory,
        )
        DEVICE_DATA_MANAGER_AVAILABLE = True
    except ImportError:
        pass

import subprocess
import re
import sqlite3
import logging
import os

logger = logging.getLogger(__name__)


# ============================================================
# DATA FILE PATHS (written by qsecbit agent running with host network)
# ============================================================
DATA_DIR = Path('/opt/hookprobe/fortress/data')


def _read_agent_data(filename: str, max_age_seconds: int = 60) -> dict:
    """Read data from qsecbit agent data file.

    Returns data if file exists. If data has a timestamp, checks freshness
    but still returns stale data (marked with _stale=True) rather than None.
    This ensures we always have data to display when the agent is running.
    """
    data_file = DATA_DIR / filename
    if not data_file.exists():
        logger.debug(f"Agent data file not found: {data_file}")
        return None
    try:
        data = json.loads(data_file.read_text())
        # Check if data is recent (but return stale data anyway)
        if 'timestamp' in data:
            from datetime import datetime
            file_ts = data['timestamp']
            if isinstance(file_ts, str):
                try:
                    # Parse ISO format timestamp
                    file_time = datetime.fromisoformat(file_ts.replace('Z', '+00:00'))
                    if file_time.tzinfo:
                        file_time = file_time.replace(tzinfo=None)
                    age = (datetime.now() - file_time).total_seconds()
                    if age >= max_age_seconds:
                        # Data is stale but still usable - log warning and mark as stale
                        logger.debug(f"Agent data {filename} is stale ({age:.0f}s old)")
                        data['_stale'] = True
                        data['_age_seconds'] = age
                except ValueError as e:
                    logger.debug(f"Could not parse timestamp in {filename}: {e}")
        # Always return data if we got this far
        return data
    except json.JSONDecodeError as e:
        logger.warning(f"Invalid JSON in agent data {filename}: {e}")
    except Exception as e:
        logger.debug(f"Failed to read agent data from {filename}: {e}")
    return None


# ============================================================
# REAL DATA COLLECTION - Live system data
# ============================================================

def get_real_devices():
    """
    Collect real device data from system sources with database sync.

    Priority 1: Read from devices.json written by qsecbit agent
    Priority 2: Direct ARP/DHCP collection (works if container has host network)

    Database sync:
    - Syncs detected devices to database (upsert)
    - Merges persisted data (policies, blocked status) from database

    Returns list of devices with real data.
    """
    # Priority 1: Try to read from qsecbit agent data file
    agent_data = _read_agent_data('devices.json', max_age_seconds=120)
    logger.info(f"Agent data loaded: {type(agent_data)}, keys: {list(agent_data.keys()) if isinstance(agent_data, dict) else 'N/A'}")

    # Handle both old format (list) and new format (dict with 'devices' key)
    device_list = None
    if agent_data:
        if isinstance(agent_data, dict) and 'devices' in agent_data:
            # New format: {timestamp: ..., devices: [...], count: ...}
            device_list = agent_data.get('devices', [])
            logger.info(f"Found {len(device_list)} devices in agent data (dict format)")
        elif isinstance(agent_data, list):
            # Old format: plain list of devices
            device_list = agent_data

    if device_list and len(device_list) > 0:
        # Load persisted device data from database (policies, blocked status, etc.)
        db_devices = {}
        if DB_AVAILABLE:
            try:
                db = get_db()
                all_db_devices = db.fetch_all("""
                    SELECT mac_address, network_policy, vlan_id, is_blocked, is_known,
                           internet_access, lan_access, notes, first_seen
                    FROM devices
                """)
                # Handle both dict and tuple results (psycopg2 may return either)
                for row in all_db_devices:
                    if isinstance(row, dict):
                        mac_key = row.get('mac_address', '').upper()
                        if mac_key:
                            db_devices[mac_key] = row
                    elif isinstance(row, (list, tuple)) and len(row) >= 1:
                        # Tuple format: (mac_address, network_policy, vlan_id, is_blocked, is_known, ...)
                        mac_key = str(row[0]).upper() if row[0] else ''
                        if mac_key:
                            db_devices[mac_key] = {
                                'mac_address': row[0],
                                'network_policy': row[1] if len(row) > 1 else None,
                                'vlan_id': row[2] if len(row) > 2 else None,
                                'is_blocked': row[3] if len(row) > 3 else False,
                                'is_known': row[4] if len(row) > 4 else False,
                                'internet_access': row[5] if len(row) > 5 else None,
                                'lan_access': row[6] if len(row) > 6 else None,
                                'notes': row[7] if len(row) > 7 else '',
                                'first_seen': row[8] if len(row) > 8 else None,
                            }
                logger.debug(f"Loaded {len(db_devices)} devices from database for merge")
            except Exception as e:
                logger.warning(f"Could not load database devices: {e}")
                db_devices = {}  # Continue without database data

        # Enrich with OUI classification and format for SDN display
        enriched = []
        for device in device_list:
            mac = device.get('mac_address', '').upper()
            classification = classify_device(mac)
            category = classification.get('category', 'unknown')
            manufacturer = classification.get('manufacturer', device.get('manufacturer', 'Unknown'))

            # Check for persisted data in database (safely)
            db_device = db_devices.get(mac) if isinstance(db_devices, dict) else None
            if db_device is None or not isinstance(db_device, dict):
                db_device = {}

            # Determine network policy - use database value if set, otherwise derive from category
            policy_map = {
                'iot': 'lan_only',
                'camera': 'lan_only',
                'pos': 'internet_only',
                'voice_assistant': 'internet_only',
                'printer': 'lan_only',
                'workstation': 'full_access',
                'phone': 'full_access',
                'tablet': 'full_access',
                'unknown': 'default',
            }
            default_policy = policy_map.get(category, 'default')
            network_policy = db_device.get('network_policy') or default_policy

            # Use database values for persistence, fallback to defaults
            vlan_id = db_device.get('vlan_id') or 100
            is_blocked = db_device.get('is_blocked', False)
            is_known = db_device.get('is_known', False)

            # Internet/LAN access from database or derived from policy
            if db_device.get('internet_access') is not None:
                internet_access = db_device['internet_access']
            else:
                internet_access = network_policy in ('full_access', 'internet_only')

            if db_device.get('lan_access') is not None:
                lan_access = db_device['lan_access']
            else:
                lan_access = network_policy in ('full_access', 'lan_only')

            # First seen from database if available
            first_seen = device.get('first_seen', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            if db_device.get('first_seen'):
                first_seen = str(db_device['first_seen'])

            enriched_device = {
                'mac_address': mac,
                'ip_address': device.get('ip_address', ''),
                'hostname': device.get('hostname') or f'device-{mac[-5:].replace(":", "")}',
                'device_type': category,
                'manufacturer': manufacturer,
                'network_policy': network_policy,
                'vlan_id': vlan_id,
                'internet_access': internet_access,
                'lan_access': lan_access,
                'is_blocked': is_blocked,
                'is_known': is_known,
                # Check multiple state indicators for online status
                'is_online': (
                    device.get('is_online', False) or
                    device.get('state') in ('REACHABLE', 'DELAY', 'reachable', 'delay') or
                    device.get('status') in ('online', 'ONLINE', 'active', 'ACTIVE')
                ),
                'oui_category': category,
                'auto_policy': classification.get('recommended_policy', 'default'),
                'first_seen': first_seen,
                'last_seen': device.get('last_seen', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                'bytes_sent': device.get('bytes_sent', 0),
                'bytes_received': device.get('bytes_received', 0),
                'notes': db_device.get('notes', ''),
            }
            enriched.append(enriched_device)

            # Sync to database (upsert) - only if not already in database
            if DB_AVAILABLE and mac not in db_devices:
                try:
                    db = get_db()
                    db.upsert_device(
                        mac_address=mac,
                        ip_address=device.get('ip_address'),
                        hostname=device.get('hostname'),
                        vlan_id=100,  # Default VLAN
                        device_type=category,
                        manufacturer=manufacturer
                    )
                except Exception as e:
                    logger.debug(f"Could not sync device {mac} to database: {e}")

        logger.info(f"Returning {len(enriched)} enriched devices from agent data file")
        return enriched

    # Priority 2: Fallback to direct collection (legacy, works with host network)
    logger.info("No agent data available, falling back to direct collection")
    devices = []
    arp_devices = {}
    dhcp_leases = {}
    blocked_macs = set()

    # 1. Get ARP table for live devices
    try:
        result = subprocess.run(
            ['ip', 'neigh', 'show'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if not line or 'FAILED' in line:
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue

                ip_address = parts[0]
                mac_address = None
                state = 'STALE'

                # Find MAC address
                for i, part in enumerate(parts):
                    if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', part):
                        mac_address = part.upper()
                        break

                if 'REACHABLE' in line:
                    state = 'REACHABLE'
                elif 'STALE' in line:
                    state = 'STALE'
                elif 'DELAY' in line:
                    state = 'DELAY'

                if mac_address:
                    arp_devices[mac_address] = {
                        'ip_address': ip_address,
                        'state': state,
                        'is_online': state in ('REACHABLE', 'DELAY'),
                    }
    except Exception as e:
        logger.warning(f"Failed to read ARP table: {e}")

    # 2. Get DHCP leases for hostnames
    dhcp_files = [
        '/var/lib/misc/dnsmasq.leases',
        '/var/lib/dnsmasq/dnsmasq.leases',
        '/var/lib/dhcp/dhcpd.leases',
    ]
    for dhcp_file in dhcp_files:
        try:
            with open(dhcp_file, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        # Format: timestamp MAC IP hostname client-id
                        mac = parts[1].upper()
                        ip = parts[2]
                        hostname = parts[3] if parts[3] != '*' else None
                        dhcp_leases[mac] = {
                            'ip_address': ip,
                            'hostname': hostname,
                            'lease_time': parts[0],
                        }
        except FileNotFoundError:
            continue
        except Exception as e:
            logger.warning(f"Failed to read DHCP leases from {dhcp_file}: {e}")

    # 3. Get blocked MACs from OVS flows
    try:
        result = subprocess.run(
            ['ovs-ofctl', 'dump-flows', 'FTS'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'actions=drop' in line and 'dl_src=' in line:
                    match = re.search(r'dl_src=([0-9A-Fa-f:]+)', line)
                    if match:
                        blocked_macs.add(match.group(1).upper())
    except Exception as e:
        logger.debug(f"Failed to read OVS flows: {e}")

    # 4. Merge data sources
    all_macs = set(arp_devices.keys()) | set(dhcp_leases.keys())

    for mac in all_macs:
        arp_info = arp_devices.get(mac, {})
        dhcp_info = dhcp_leases.get(mac, {})

        # Get IP from ARP first, fallback to DHCP
        ip_address = arp_info.get('ip_address') or dhcp_info.get('ip_address', '')

        # Online if in ARP table with REACHABLE/DELAY state
        is_online = arp_info.get('is_online', False)

        # Blocked if MAC is in OVS drop flows
        is_blocked = mac in blocked_macs

        # Hostname from DHCP
        hostname = dhcp_info.get('hostname', '')

        # OUI classification
        classification = classify_device(mac)
        manufacturer = classification.get('manufacturer', 'Unknown')
        category = classification.get('category', 'unknown')
        recommended_policy = classification.get('recommended_policy', 'default')

        # Determine network policy based on category
        policy_map = {
            'iot': 'lan_only',
            'camera': 'lan_only',
            'pos': 'internet_only',
            'voice_assistant': 'internet_only',
            'printer': 'lan_only',
            'workstation': 'full_access',
            'phone': 'full_access',
            'tablet': 'full_access',
            'unknown': 'default',
        }
        network_policy = policy_map.get(category, recommended_policy)

        devices.append({
            'mac_address': mac,
            'ip_address': ip_address,
            'hostname': hostname or f'device-{mac[-5:].replace(":", "")}',
            'device_type': category,
            'manufacturer': manufacturer,
            'network_policy': network_policy,
            'vlan_id': 100,  # Default LAN VLAN
            'internet_access': network_policy in ('full_access', 'internet_only'),
            'lan_access': network_policy in ('full_access', 'lan_only'),
            'is_blocked': is_blocked,
            'is_online': is_online,
            'oui_category': category,
            'auto_policy': recommended_policy,
            'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S') if is_online else '',
            'bytes_sent': 0,
            'bytes_received': 0,
        })

    return devices


def get_dfs_intelligence():
    """
    Get real DFS/WiFi intelligence data from multiple sources.

    Priority:
    1. DFS container API (fts-dfs on port 8050)
    2. DFS database file
    3. WiFi status data file (from qsecbit agent)
    4. Direct hostapd_cli query
    5. Calculate ML score from channel characteristics

    Returns dict with:
    - ml_channel_score: Current ML-based channel safety score (0-100)
    - radar_events: Count of radar events in last 30 days
    - channel_switches: Count of channel switches in last 30 days
    - current_channel: Current WiFi channel
    - next_optimization: Next scheduled optimization time
    - last_optimization: Last optimization timestamp
    """
    import urllib.request

    data = {
        'ml_channel_score': None,
        'radar_events': 0,
        'channel_switches': 0,
        'current_channel': None,
        'next_optimization': None,
        'last_optimization': None,
        'scan_mode': 'basic',
    }

    # Priority 1: Try DFS container API
    try:
        dfs_api_url = os.environ.get('DFS_API_URL', 'http://fts-dfs:8050')
        req = urllib.request.Request(f'{dfs_api_url}/api/status', timeout=3)
        with urllib.request.urlopen(req, timeout=3) as response:
            api_data = json.loads(response.read().decode())
            if api_data.get('success'):
                status = api_data.get('status', {})
                data['current_channel'] = status.get('current_channel')
                data['ml_channel_score'] = status.get('channel_score')
                data['radar_events'] = status.get('radar_events_30d', 0)
                data['channel_switches'] = status.get('channel_switches_30d', 0)
                data['last_optimization'] = status.get('last_scan')
                data['scan_mode'] = 'dfs_intelligence'
                if data['ml_channel_score'] is not None:
                    logger.debug(f"DFS API: channel={data['current_channel']} score={data['ml_channel_score']}")
                    return data
    except Exception as e:
        logger.debug(f"DFS API not available: {e}")

    # Priority 2: Try to get data from DFS database
    db_path = '/var/lib/hookprobe/dfs_intelligence.db'
    try:
        if Path(db_path).exists():
            conn = sqlite3.connect(db_path, timeout=5)
            cursor = conn.cursor()

            # Get radar events count (last 30 days)
            cursor.execute("""
                SELECT COUNT(*) FROM radar_events
                WHERE timestamp > datetime('now', '-30 days')
            """)
            row = cursor.fetchone()
            if row:
                data['radar_events'] = row[0]

            # Get channel switches count (last 30 days)
            cursor.execute("""
                SELECT COUNT(*) FROM channel_switches
                WHERE timestamp > datetime('now', '-30 days')
            """)
            row = cursor.fetchone()
            if row:
                data['channel_switches'] = row[0]

            # Get last channel switch for current channel
            cursor.execute("""
                SELECT to_channel, timestamp FROM channel_switches
                ORDER BY timestamp DESC LIMIT 1
            """)
            row = cursor.fetchone()
            if row:
                data['current_channel'] = row[0]
                data['last_optimization'] = row[1]

            conn.close()
            data['scan_mode'] = 'dfs_database'
    except Exception as e:
        logger.debug(f"Failed to read DFS database: {e}")

    # Priority 3: Get WiFi info from qsecbit agent data file
    wifi_file = DATA_DIR / 'wifi_status.json'
    if wifi_file.exists() and data['current_channel'] is None:
        try:
            wifi_data = json.loads(wifi_file.read_text())
            if wifi_data.get('primary_channel'):
                data['current_channel'] = wifi_data['primary_channel']
                logger.debug(f"Got channel from wifi_status.json: {data['current_channel']}")
        except Exception as e:
            logger.debug(f"Failed to read wifi_status.json: {e}")

    # Priority 4: Get current channel from hostapd (fallback)
    if data['current_channel'] is None:
        try:
            result = subprocess.run(
                ['hostapd_cli', '-i', 'wlan0', 'status'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('channel='):
                        data['current_channel'] = int(line.split('=')[1])
                        break
        except Exception as e:
            logger.debug(f"Failed to get hostapd status: {e}")

    # Priority 5: Calculate ML channel score
    if data['ml_channel_score'] is None and data['current_channel']:
        # Try DFS module scorer first
        if DFS_AVAILABLE:
            try:
                db = DFSDatabase(db_path)
                scorer = ChannelScorer(db)
                score = scorer.score_channel(data['current_channel'])
                if score:
                    data['ml_channel_score'] = round(score.total_score * 100)
                    data['scan_mode'] = 'dfs_intelligence'
            except Exception as e:
                logger.debug(f"DFS scorer failed: {e}")

        # Fallback: Calculate score from channel characteristics
        if data['ml_channel_score'] is None:
            channel = data['current_channel']
            score = calculate_channel_score(channel, data['radar_events'])
            data['ml_channel_score'] = score
            data['scan_mode'] = 'channel_analysis'

    # Get next optimization time from systemd timer
    try:
        result = subprocess.run(
            ['systemctl', 'show', 'fts-channel-optimize.timer', '--property=NextElapseUSecRealtime'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and '=' in result.stdout:
            timestamp = result.stdout.strip().split('=')[1]
            if timestamp and timestamp != 'n/a':
                data['next_optimization'] = timestamp
    except Exception as e:
        logger.debug(f"Failed to get optimization timer: {e}")

    return data


def calculate_channel_score(channel: int, radar_events: int = 0) -> int:
    """
    Calculate ML-style channel score based on channel characteristics.

    Factors:
    - DFS status (UNII bands)
    - Channel width capability
    - Regulatory restrictions
    - Radar event history
    - Congestion (estimated from band)

    Returns score 0-100 (higher = better)
    """
    if not channel:
        return None

    score = 100

    # 5GHz DFS channels (UNII-2A: 52-64, UNII-2C: 100-144)
    dfs_channels = list(range(52, 65)) + list(range(100, 145))
    unii1_channels = list(range(36, 49))  # Non-DFS, always safe
    unii3_channels = list(range(149, 166))  # Non-DFS, high power

    # 2.4GHz channels
    if channel <= 14:
        # 2.4GHz is typically more congested
        score = 60
        # Channels 1, 6, 11 are non-overlapping (better)
        if channel in [1, 6, 11]:
            score = 70
        return score

    # 5GHz scoring
    if channel in unii1_channels:
        # UNII-1: No DFS, indoor, typically cleaner
        score = 85
    elif channel in unii3_channels:
        # UNII-3: No DFS, high power, outdoor friendly
        score = 80
    elif channel in dfs_channels:
        # DFS channels: Good spectrum but radar risk
        score = 75

        # UNII-2C (100-144) has weather radar - higher risk
        if channel >= 100 and channel <= 144:
            score = 70

        # Penalize for radar events
        if radar_events > 0:
            score -= min(20, radar_events * 5)

    # Channel width bonus (80MHz capable channels)
    # Primary 80MHz channels: 36, 52, 100, 116, 132, 149
    primary_80mhz = [36, 52, 100, 116, 132, 149]
    if channel in primary_80mhz:
        score += 5

    # Clamp to 0-100
    return max(0, min(100, score))


def get_real_network_stats(devices):
    """
    Calculate real network statistics from device list.
    """
    stats = {
        'total_devices': len(devices),
        'online_devices': 0,
        'offline_devices': 0,
        'blocked_devices': 0,
        'policy_counts': {},
        'category_counts': {},
    }

    for device in devices:
        if device.get('is_online'):
            stats['online_devices'] += 1
        else:
            stats['offline_devices'] += 1

        if device.get('is_blocked'):
            stats['blocked_devices'] += 1

        policy = device.get('network_policy', 'default')
        stats['policy_counts'][policy] = stats['policy_counts'].get(policy, 0) + 1

        category = device.get('oui_category', 'unknown')
        stats['category_counts'][category] = stats['category_counts'].get(category, 0) + 1

    return stats


# ============================================================
# DEMO DATA (fallback only)
# ============================================================

def get_demo_devices():
    """Return demo devices with full SDN info."""
    return [
        {
            'mac_address': 'B8:27:EB:12:34:56',
            'ip_address': '192.168.1.105',
            'hostname': 'rpi-sensor-1',
            'device_type': 'iot',
            'manufacturer': 'Raspberry Pi Foundation',
            'network_policy': 'lan_only',
            'vlan_id': 99,
            'internet_access': False,
            'lan_access': True,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'iot',
            'auto_policy': 'lan_only',
            'first_seen': '2025-12-10 08:00:00',
            'last_seen': '2025-12-17 14:30:00',
            'bytes_sent': 1024000,
            'bytes_received': 2048000,
        },
        {
            'mac_address': '00:17:88:AA:BB:CC',
            'ip_address': '192.168.1.110',
            'hostname': 'hue-bridge',
            'device_type': 'iot',
            'manufacturer': 'Philips Hue',
            'network_policy': 'lan_only',
            'vlan_id': 99,
            'internet_access': False,
            'lan_access': True,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'iot',
            'auto_policy': 'lan_only',
            'first_seen': '2025-12-01 00:00:00',
            'last_seen': '2025-12-17 14:35:00',
            'bytes_sent': 512000,
            'bytes_received': 256000,
        },
        {
            'mac_address': '58:E6:BA:11:22:33',
            'ip_address': '192.168.1.50',
            'hostname': 'square-pos-1',
            'device_type': 'pos',
            'manufacturer': 'Square Inc.',
            'network_policy': 'internet_only',
            'vlan_id': 20,
            'internet_access': True,
            'lan_access': False,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'pos',
            'auto_policy': 'internet_only',
            'first_seen': '2025-12-05 09:00:00',
            'last_seen': '2025-12-17 14:40:00',
            'bytes_sent': 5120000,
            'bytes_received': 1024000,
        },
        {
            'mac_address': '0C:47:C9:AA:BB:CC',
            'ip_address': '192.168.1.120',
            'hostname': 'echo-dot-kitchen',
            'device_type': 'voice_assistant',
            'manufacturer': 'Amazon Echo',
            'network_policy': 'internet_only',
            'vlan_id': 99,
            'internet_access': True,
            'lan_access': False,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'voice_assistant',
            'auto_policy': 'internet_only',
            'first_seen': '2025-12-08 10:00:00',
            'last_seen': '2025-12-17 14:20:00',
            'bytes_sent': 2048000,
            'bytes_received': 10240000,
        },
        {
            'mac_address': '00:0C:B5:44:55:66',
            'ip_address': '192.168.1.200',
            'hostname': 'cam-front-door',
            'device_type': 'camera',
            'manufacturer': 'Hikvision',
            'network_policy': 'lan_only',
            'vlan_id': 99,
            'internet_access': False,
            'lan_access': True,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'camera',
            'auto_policy': 'lan_only',
            'first_seen': '2025-12-01 00:00:00',
            'last_seen': '2025-12-17 14:45:00',
            'bytes_sent': 102400000,
            'bytes_received': 1024000,
        },
        {
            'mac_address': '3C:06:30:DE:AD:BE',
            'ip_address': '192.168.1.25',
            'hostname': 'macbook-sarah',
            'device_type': 'workstation',
            'manufacturer': 'Apple Inc.',
            'network_policy': 'full_access',
            'vlan_id': 30,
            'internet_access': True,
            'lan_access': True,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'workstation',
            'auto_policy': 'full_access',
            'first_seen': '2025-12-12 08:30:00',
            'last_seen': '2025-12-17 14:50:00',
            'bytes_sent': 50240000,
            'bytes_received': 150720000,
        },
        {
            'mac_address': '00:1E:0B:77:88:99',
            'ip_address': '192.168.1.210',
            'hostname': 'hp-printer-office',
            'device_type': 'printer',
            'manufacturer': 'HP Inc.',
            'network_policy': 'lan_only',
            'vlan_id': 99,
            'internet_access': False,
            'lan_access': True,
            'is_blocked': False,
            'is_online': False,
            'oui_category': 'printer',
            'auto_policy': 'lan_only',
            'first_seen': '2025-12-03 00:00:00',
            'last_seen': '2025-12-17 12:00:00',
            'bytes_sent': 10240000,
            'bytes_received': 5120000,
        },
        {
            'mac_address': 'DE:AD:BE:EF:CA:FE',
            'ip_address': '192.168.1.99',
            'hostname': 'unknown-device',
            'device_type': 'unknown',
            'manufacturer': 'Unknown',
            'network_policy': 'isolated',
            'vlan_id': 40,
            'internet_access': False,
            'lan_access': False,
            'is_blocked': True,
            'is_online': False,
            'oui_category': 'unknown',
            'auto_policy': 'default',
            'first_seen': '2025-12-17 10:00:00',
            'last_seen': '2025-12-17 10:05:00',
            'bytes_sent': 1024,
            'bytes_received': 2048,
        },
    ]


def get_demo_policies():
    """Return demo network policies."""
    return [
        {
            'name': 'full_access',
            'display_name': 'Full Access',
            'description': 'Full internet and LAN access',
            'internet_access': True,
            'lan_access': True,
            'icon': 'fa-globe',
            'color': 'success',
        },
        {
            'name': 'lan_only',
            'display_name': 'LAN Only',
            'description': 'Local network only - no internet',
            'internet_access': False,
            'lan_access': True,
            'icon': 'fa-network-wired',
            'color': 'info',
        },
        {
            'name': 'internet_only',
            'display_name': 'Internet Only',
            'description': 'Internet access only - no LAN',
            'internet_access': True,
            'lan_access': False,
            'icon': 'fa-cloud',
            'color': 'primary',
        },
        {
            'name': 'isolated',
            'display_name': 'Isolated',
            'description': 'Completely isolated - no network access',
            'internet_access': False,
            'lan_access': False,
            'icon': 'fa-ban',
            'color': 'danger',
        },
        {
            'name': 'default',
            'display_name': 'Default',
            'description': 'Default policy for unclassified devices',
            'internet_access': True,
            'lan_access': True,
            'icon': 'fa-question-circle',
            'color': 'secondary',
        },
    ]


def get_demo_vlans():
    """Return demo VLANs."""
    return [
        {'vlan_id': 10, 'name': 'Management', 'subnet': '10.250.10.0/24', 'device_count': 2},
        {'vlan_id': 20, 'name': 'POS', 'subnet': '10.250.20.0/24', 'device_count': 1},
        {'vlan_id': 30, 'name': 'Staff', 'subnet': '10.250.30.0/24', 'device_count': 1},
        {'vlan_id': 40, 'name': 'Guest', 'subnet': '10.250.40.0/24', 'device_count': 1},
        {'vlan_id': 99, 'name': 'IoT', 'subnet': '10.250.99.0/24', 'device_count': 3},
    ]


def get_demo_stats():
    """Return demo statistics."""
    return {
        'total_devices': 8,
        'online_devices': 6,
        'offline_devices': 2,
        'blocked_devices': 1,
        'policy_counts': {
            'full_access': 1,
            'lan_only': 4,
            'internet_only': 2,
            'isolated': 1,
        },
        'category_counts': {
            'iot': 2,
            'camera': 1,
            'pos': 1,
            'voice_assistant': 1,
            'workstation': 1,
            'printer': 1,
            'unknown': 1,
        },
    }


def format_device_for_template(device):
    """Format device data for template consumption."""
    policy = device.get('network_policy', 'default')
    is_blocked = device.get('is_blocked', False)
    is_online = device.get('is_online', False)

    # Determine status
    if is_blocked:
        status = 'blocked'
    elif is_online:
        status = 'online'
    else:
        status = 'offline'

    # Determine access rights based on policy
    access_rights = {
        'full_access': {'lan': True, 'internet': True, 'gateway': True, 'dns': True},
        'lan_only': {'lan': True, 'internet': False, 'gateway': True, 'dns': True},
        'internet_only': {'lan': False, 'internet': True, 'gateway': True, 'dns': True},
        'isolated': {'lan': False, 'internet': False, 'gateway': True, 'dns': True},
        'default': {'lan': True, 'internet': True, 'gateway': True, 'dns': True},
    }
    rights = access_rights.get(policy, access_rights['default'])

    # Icon mapping
    icon_map = {
        'iot': 'fa-microchip',
        'camera': 'fa-video',
        'pos': 'fa-cash-register',
        'voice_assistant': 'fa-microphone',
        'workstation': 'fa-desktop',
        'printer': 'fa-print',
        'phone': 'fa-mobile-alt',
        'tablet': 'fa-tablet-alt',
        'router': 'fa-router',
        'unknown': 'fa-question-circle',
    }
    category = device.get('oui_category', device.get('device_type', 'unknown'))

    # Format bytes for display
    def format_bytes(b):
        if not b:
            return '0 B'
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024:
                return f'{b:.1f} {unit}'
            b /= 1024
        return f'{b:.1f} PB'

    return {
        'mac': device.get('mac_address', ''),
        'ip': device.get('ip_address', ''),
        'hostname': device.get('hostname', 'Unknown'),
        'vendor': device.get('manufacturer', 'Unknown'),
        'category': category,
        'policy': policy,
        'status': status,
        'is_online': is_online,
        'is_blocked': is_blocked,
        'can_access_lan': rights['lan'] and not is_blocked,
        'can_access_internet': rights['internet'] and not is_blocked,
        'can_access_gateway': rights['gateway'] and not is_blocked,
        'can_access_dns': rights['dns'] and not is_blocked,
        'icon': icon_map.get(category, 'fa-laptop'),
        'first_seen': device.get('first_seen', ''),
        'last_seen': device.get('last_seen', ''),
        'recommended_policy': device.get('auto_policy', 'default'),
        'bytes_sent': format_bytes(device.get('bytes_sent', 0)),
        'bytes_received': format_bytes(device.get('bytes_received', 0)),
        'vlan_id': device.get('vlan_id'),
        'recent_events': device.get('recent_events', []),
    }


# ============================================================
# MAIN DASHBOARD VIEW
# ============================================================

@sdn_bp.route('/')
@login_required
def index():
    """SDN Management Dashboard - unified device and policy view."""
    devices = []
    policies = []
    vlans = []
    stats = {}
    dfs_data = {}
    network_mode = 'vlan'  # Always VLAN mode
    using_real_data = False

    # Priority 1: Try to get real data from system (ARP, DHCP, OVS)
    try:
        real_devices = get_real_devices()
        if real_devices:
            devices = real_devices
            using_real_data = True
            logger.info(f"Loaded {len(devices)} devices from real system data")
    except Exception as e:
        logger.warning(f"Failed to get real device data: {e}")

    # Priority 2: Try database if real scan found nothing
    if not devices and DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            db_devices = device_mgr.get_all_devices()

            if db_devices:
                # Enrich devices with OUI classification
                for device in db_devices:
                    mac = device.get('mac_address', '')
                    classification = classify_device(mac)
                    device['oui_category'] = classification.get('category', 'unknown')
                    device['auto_policy'] = classification.get('recommended_policy', 'default')
                    device['manufacturer'] = device.get('manufacturer') or classification.get('manufacturer', 'Unknown')

                    # Convert datetime
                    for key in ['first_seen', 'last_seen']:
                        if device.get(key) and not isinstance(device[key], str):
                            device[key] = str(device[key])

                    # Determine online status (last seen within 5 minutes)
                    device['is_online'] = False  # Will be updated by ARP scan

                devices = db_devices
                using_real_data = True

            vlan_mgr = get_vlan_manager()
            vlans = vlan_mgr.get_vlans()

        except Exception as e:
            # Only log, don't flash - we'll fall back to demo data
            logger.debug(f"Database not available: {e}")

    # Priority 3: NO demo data - show empty state for real-world deployments
    # User explicitly requested: "remove the demo data, dont need any other data -- use only real data"
    if not devices:
        devices = []
        vlans = []
        logger.info("No devices found - waiting for real device data from qsecbit agent")

    # Get real DFS/WiFi intelligence data
    try:
        dfs_data = get_dfs_intelligence()
    except Exception as e:
        logger.debug(f"Failed to get DFS data: {e}")
        dfs_data = {
            'ml_channel_score': None,
            'radar_events': 0,
            'channel_switches': 0,
            'current_channel': None,
            'next_optimization': None,
            'last_optimization': None,
            'scan_mode': 'basic',
        }

    # Load network mode from state file
    try:
        state_file = Path('/etc/hookprobe/fortress-state.json')
        if state_file.exists():
            state = json.loads(state_file.read_text())
            network_mode = state.get('network_mode', 'vlan')
    except Exception:
        pass

    # Always use standard policies
    policies = get_demo_policies()
    stats = get_real_network_stats(devices) if devices else get_demo_stats()

    logger.info(f"Rendering SDN index with {len(devices)} devices, using_real_data={using_real_data}")
    if devices:
        logger.info(f"First device sample: mac={devices[0].get('mac_address')}, hostname={devices[0].get('hostname')}")

    return render_template(
        'sdn/index.html',
        devices=devices,
        policies=policies,
        vlans=vlans,
        stats=stats,
        dfs_data=dfs_data,
        network_mode=network_mode,
        db_available=DB_AVAILABLE,
        policy_manager_available=POLICY_MANAGER_AVAILABLE,
        using_real_data=using_real_data
    )


def calculate_stats(devices):
    """Calculate statistics from device list."""
    stats = {
        'total_devices': len(devices),
        'online_devices': 0,
        'offline_devices': 0,
        'blocked_devices': 0,
        'policy_counts': {},
        'category_counts': {},
    }

    for device in devices:
        if device.get('is_online'):
            stats['online_devices'] += 1
        else:
            stats['offline_devices'] += 1

        if device.get('is_blocked'):
            stats['blocked_devices'] += 1

        policy = device.get('network_policy', 'default')
        stats['policy_counts'][policy] = stats['policy_counts'].get(policy, 0) + 1

        category = device.get('oui_category', 'unknown')
        stats['category_counts'][category] = stats['category_counts'].get(category, 0) + 1

    return stats


# ============================================================
# DEVICE DETAIL
# ============================================================

@sdn_bp.route('/device/<mac_address>')
@login_required
def device_detail(mac_address):
    """Device detail view with full SDN info."""
    device = None
    policies = get_demo_policies()
    vlans = get_demo_vlans()

    if DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            raw_device = device_mgr.get_device(mac_address)
            if raw_device:
                classification = classify_device(mac_address)
                raw_device['oui_category'] = classification.get('category', 'unknown')
                raw_device['auto_policy'] = classification.get('recommended_policy', 'default')
                raw_device['manufacturer'] = raw_device.get('manufacturer') or classification.get('manufacturer', 'Unknown')
                device = format_device_for_template(raw_device)

            vlan_mgr = get_vlan_manager()
            vlans = vlan_mgr.get_vlans()
        except Exception as e:
            flash(f'Error loading device: {e}', 'warning')

    # No demo fallback - only show real devices
    if not device:
        flash('Device not found', 'warning')
        return redirect(url_for('sdn.index'))

    return render_template(
        'sdn/device_detail.html',
        device=device,
        policies=policies,
        vlans=vlans,
        db_available=DB_AVAILABLE
    )


# ============================================================
# POLICY OPERATIONS
# ============================================================

@sdn_bp.route('/set-policy', methods=['POST'])
@login_required
@operator_required
def set_policy():
    """Set network policy for a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    policy = request.form.get('policy')
    source = request.form.get('source', 'web')

    if not mac_address or not policy:
        return jsonify({'success': False, 'error': 'MAC address and policy required'}), 400

    valid_policies = ['full_access', 'lan_only', 'internet_only', 'isolated', 'default']
    if policy not in valid_policies:
        return jsonify({'success': False, 'error': f'Invalid policy: {policy}'}), 400

    try:
        # Use device data manager for persistent CRUD (primary)
        if DEVICE_DATA_MANAGER_AVAILABLE:
            ddm = get_device_data_manager()
            ddm.set_policy(mac_address, policy)

        # Legacy: policy manager for nftables
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy(policy), assigned_by=f'web:{current_user.id}')

        # Legacy: database for additional tracking
        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET network_policy = %s WHERE mac_address = %s",
                (policy, mac_address.upper())
            )
            db.audit_log(
                current_user.id,
                'set_policy',
                'device',
                mac_address,
                {'policy': policy, 'source': source},
                request.remote_addr
            )

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': f'Policy set to {policy}'})

        flash(f'Policy for {mac_address} set to {policy}', 'success')
        return redirect(url_for('sdn.device_detail', mac_address=mac_address))

    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': str(e)}), 500

        flash(f'Error setting policy: {e}', 'danger')
        return redirect(url_for('sdn.index'))


@sdn_bp.route('/auto-classify', methods=['POST'])
@login_required
@operator_required
def auto_classify():
    """Auto-classify device based on OUI (MAC from form data)."""
    mac_address = request.form.get('mac')
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        classification = classify_device(mac_address)
        recommended = classification.get('recommended_policy', 'default')

        # Use device data manager for persistent CRUD (primary)
        if DEVICE_DATA_MANAGER_AVAILABLE:
            ddm = get_device_data_manager()
            ddm.update(mac_address, policy=recommended, category=classification.get('category', 'unknown'))

        # Legacy: policy manager for nftables
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy(recommended), assigned_by='oui')

        # Legacy: database for additional tracking
        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET network_policy = %s, device_type = %s WHERE mac_address = %s",
                (recommended, classification.get('category'), mac_address.upper())
            )

        return jsonify({
            'success': True,
            'category': classification.get('category'),
            'policy': recommended,
            'policy_applied': recommended,
            'classification': classification
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@sdn_bp.route('/disconnect-device', methods=['POST'])
@login_required
@operator_required
def disconnect_device():
    """Disconnect a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        # Use device data manager for persistent CRUD (primary)
        if DEVICE_DATA_MANAGER_AVAILABLE:
            ddm = get_device_data_manager()
            ddm.set_policy(mac_address, 'isolated')

        # Legacy: policy manager for nftables
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy.ISOLATED, assigned_by=f'disconnect:{current_user.id}')

        # Legacy: database for additional tracking
        if DB_AVAILABLE:
            db = get_db()
            db.audit_log(
                current_user.id,
                'disconnect',
                'device',
                mac_address,
                {'action': 'disconnect'},
                request.remote_addr
            )

        return jsonify({'success': True, 'message': 'Device disconnected'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@sdn_bp.route('/block-device', methods=['POST'])
@login_required
@operator_required
def block_device():
    """Block a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    reason = request.form.get('reason', 'manual_block')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        # Use device data manager for persistent CRUD (primary)
        if DEVICE_DATA_MANAGER_AVAILABLE:
            ddm = get_device_data_manager()
            ddm.block(mac_address, reason)

        # Legacy: policy manager for nftables
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy.ISOLATED, assigned_by=f'block:{current_user.id}')

        # Legacy: database for additional tracking
        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET is_blocked = TRUE, network_policy = 'isolated' WHERE mac_address = %s",
                (mac_address.upper(),)
            )
            db.audit_log(
                current_user.id,
                'block',
                'device',
                mac_address,
                {'reason': reason},
                request.remote_addr
            )

        return jsonify({'success': True, 'message': 'Device blocked'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@sdn_bp.route('/unblock-device', methods=['POST'])
@login_required
@operator_required
def unblock_device():
    """Unblock a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        classification = classify_device(mac_address)
        recommended = classification.get('recommended_policy', 'default')

        # Use device data manager for persistent CRUD (primary)
        if DEVICE_DATA_MANAGER_AVAILABLE:
            ddm = get_device_data_manager()
            ddm.unblock(mac_address)

        # Legacy: policy manager for nftables
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy(recommended), assigned_by='unblock')

        # Legacy: database for additional tracking
        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET is_blocked = FALSE, network_policy = %s WHERE mac_address = %s",
                (recommended, mac_address.upper())
            )
            db.audit_log(
                current_user.id,
                'unblock',
                'device',
                mac_address,
                {'policy_restored': recommended},
                request.remote_addr
            )

        return jsonify({'success': True, 'message': f'Device unblocked, policy: {recommended}'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500




# ============================================================
# BULK OPERATIONS
# ============================================================

@sdn_bp.route('/bulk/set-policy', methods=['POST'])
@login_required
@operator_required
def bulk_set_policy():
    """Set policy for multiple devices."""
    data = request.get_json()
    mac_addresses = data.get('mac_addresses', [])
    policy = data.get('policy')

    if not mac_addresses or not policy:
        return jsonify({'success': False, 'error': 'MAC addresses and policy required'}), 400

    results = {'success': [], 'failed': []}

    for mac in mac_addresses:
        try:
            if POLICY_MANAGER_AVAILABLE:
                from network_policy_manager import NetworkPolicyManager, NetworkPolicy
                manager = NetworkPolicyManager(use_nftables=True)
                manager.set_policy(mac, NetworkPolicy(policy), assigned_by=f'bulk:{current_user.id}')

            if DB_AVAILABLE:
                db = get_db()
                db.execute(
                    "UPDATE devices SET network_policy = %s WHERE mac_address = %s",
                    (policy, mac.upper())
                )

            results['success'].append(mac)
        except Exception as e:
            results['failed'].append({'mac': mac, 'error': str(e)})

    return jsonify({
        'success': len(results['failed']) == 0,
        'results': results,
        'message': f'{len(results["success"])} devices updated'
    })


@sdn_bp.route('/bulk/auto-classify', methods=['POST'])
@login_required
@operator_required
def bulk_auto_classify():
    """Auto-classify multiple devices based on OUI."""
    data = request.get_json()
    mac_addresses = data.get('mac_addresses', [])

    if not mac_addresses:
        return jsonify({'success': False, 'error': 'MAC addresses required'}), 400

    results = {'success': [], 'failed': []}

    for mac in mac_addresses:
        try:
            classification = classify_device(mac)
            recommended = classification.get('recommended_policy', 'default')

            if POLICY_MANAGER_AVAILABLE:
                from network_policy_manager import NetworkPolicyManager, NetworkPolicy
                manager = NetworkPolicyManager(use_nftables=True)
                manager.set_policy(mac, NetworkPolicy(recommended), assigned_by='bulk_oui')

            if DB_AVAILABLE:
                db = get_db()
                db.execute(
                    "UPDATE devices SET network_policy = %s, device_type = %s WHERE mac_address = %s",
                    (recommended, classification.get('category'), mac.upper())
                )

            results['success'].append({
                'mac': mac,
                'category': classification.get('category'),
                'policy': recommended
            })
        except Exception as e:
            results['failed'].append({'mac': mac, 'error': str(e)})

    return jsonify({
        'success': len(results['failed']) == 0,
        'results': results,
        'message': f'{len(results["success"])} devices classified'
    })


# ============================================================
# DISCOVERY
# ============================================================

@sdn_bp.route('/discover', methods=['POST'])
@login_required
@operator_required
def discover_devices():
    """Trigger network device discovery."""
    if not DB_AVAILABLE:
        return jsonify({'success': False, 'error': 'Database not available'}), 503

    try:
        device_mgr = get_device_manager()
        discovered = device_mgr.discover_devices()

        # Classify new devices
        for device in discovered:
            if device.get('is_new'):
                classification = classify_device(device['mac_address'])
                device['oui_category'] = classification.get('category', 'unknown')
                device['auto_policy'] = classification.get('recommended_policy', 'default')

        new_count = len([d for d in discovered if d.get('is_new')])

        return jsonify({
            'success': True,
            'total': len(discovered),
            'new': new_count,
            'devices': discovered
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# API ENDPOINTS
# ============================================================

@sdn_bp.route('/api/devices')
@login_required
def api_devices():
    """Get all devices with SDN info (JSON)."""
    devices = []
    using_real_data = False

    # Priority 1: Try to get real data from system (ARP, DHCP, OVS)
    try:
        real_devices = get_real_devices()
        if real_devices:
            devices = real_devices
            using_real_data = True
    except Exception as e:
        logger.warning(f"Failed to get real device data: {e}")

    # Priority 2: Try database if real scan found nothing
    if not devices and DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            devices = device_mgr.get_all_devices()

            for device in devices:
                mac = device.get('mac_address', '')
                classification = classify_device(mac)
                device['oui_category'] = classification.get('category', 'unknown')
                device['auto_policy'] = classification.get('recommended_policy', 'default')

                for key in ['first_seen', 'last_seen']:
                    if device.get(key) and not isinstance(device[key], str):
                        device[key] = str(device[key])
            if devices:
                using_real_data = True
        except Exception:
            pass

    # No demo fallback - return empty if no real devices found
    if not devices:
        devices = []

    # Apply filters
    policy_filter = request.args.get('policy')
    category_filter = request.args.get('category')
    online_filter = request.args.get('online')

    if policy_filter:
        devices = [d for d in devices if d.get('network_policy') == policy_filter]
    if category_filter:
        devices = [d for d in devices if d.get('oui_category') == category_filter]
    if online_filter:
        is_online = online_filter.lower() == 'true'
        devices = [d for d in devices if d.get('is_online') == is_online]

    return jsonify({
        'success': True,
        'count': len(devices),
        'devices': devices,
        'using_real_data': using_real_data
    })


@sdn_bp.route('/api/debug/devices')
@login_required
def api_debug_devices():
    """Debug endpoint to view raw device data from agent file."""
    data_file = DATA_DIR / 'devices.json'
    result = {
        'file_path': str(data_file),
        'file_exists': data_file.exists(),
        'raw_data': None,
        'parsed_devices': None,
        'get_real_devices_result': None,
        'errors': []
    }

    if data_file.exists():
        try:
            result['raw_data'] = json.loads(data_file.read_text())
            if isinstance(result['raw_data'], dict):
                result['device_count_in_file'] = len(result['raw_data'].get('devices', []))
        except Exception as e:
            result['errors'].append(f"Failed to read raw file: {e}")

    try:
        devices = get_real_devices()
        result['get_real_devices_result'] = {
            'success': devices is not None,
            'count': len(devices) if devices else 0,
            'devices': devices[:5] if devices else []  # First 5 only
        }
    except Exception as e:
        result['errors'].append(f"get_real_devices() error: {e}")

    return jsonify(result)


@sdn_bp.route('/api/stats')
@login_required
def api_stats():
    """Get SDN statistics."""
    devices = []
    using_real_data = False

    # Priority 1: Try to get real data from system
    try:
        real_devices = get_real_devices()
        if real_devices:
            devices = real_devices
            using_real_data = True
    except Exception:
        pass

    # Priority 2: Try database if no real data
    if not devices and DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            devices = device_mgr.get_all_devices()
            for device in devices:
                classification = classify_device(device.get('mac_address', ''))
                device['oui_category'] = classification.get('category', 'unknown')
            if devices:
                using_real_data = True
        except Exception:
            pass

    if not devices:
        return jsonify({'success': True, 'stats': get_demo_stats(), 'using_real_data': False})

    stats = get_real_network_stats(devices)

    # Add DFS intelligence data
    try:
        dfs_data = get_dfs_intelligence()
        stats['dfs'] = dfs_data
    except Exception:
        stats['dfs'] = {}

    return jsonify({'success': True, 'stats': stats, 'using_real_data': using_real_data})


@sdn_bp.route('/api/classify/<mac_address>')
@login_required
def api_classify(mac_address):
    """Get OUI classification for a MAC address."""
    classification = classify_device(mac_address)
    return jsonify({
        'success': True,
        'classification': classification
    })


@sdn_bp.route('/api/policies')
@login_required
def api_policies():
    """Get available network policies."""
    return jsonify({
        'success': True,
        'policies': get_demo_policies()
    })


@sdn_bp.route('/api/wifi-intelligence')
@login_required
def api_wifi_intelligence():
    """Get WiFi channel optimization and DFS intelligence data."""
    import os
    from datetime import timedelta

    # Start with data from get_dfs_intelligence()
    dfs_data = get_dfs_intelligence()

    data = {
        'current_channel': dfs_data.get('current_channel'),
        'band': '5GHz' if dfs_data.get('current_channel') and dfs_data.get('current_channel') > 14 else '2.4GHz',
        'hw_mode': 'a' if dfs_data.get('current_channel') and dfs_data.get('current_channel') > 14 else 'g',
        'last_optimization': dfs_data.get('last_optimization'),
        'previous_channel': None,
        'next_optimization': dfs_data.get('next_optimization'),
        'time_to_next': None,
        'ml_score': dfs_data.get('ml_channel_score'),
        'radar_events': [],
        'radar_count_30d': dfs_data.get('radar_events', 0),
        'channel_switches_30d': dfs_data.get('channel_switches', 0),
        'dfs_available': DFS_AVAILABLE or Path('/usr/local/bin/dfs-channel-selector').exists(),
        'optimization_method': dfs_data.get('scan_mode', 'basic_scan'),
        'wifi_interface': None,
        'ssid': None,
        # Dual-band support
        'ssid_24ghz': None,
        'ssid_5ghz': None,
        'channel_24ghz': None,
        'channel_5ghz': None,
    }

    # Priority 1: Read from wifi_status.json written by qsecbit agent
    wifi_data = _read_agent_data('wifi_status.json', max_age_seconds=120)
    if wifi_data:
        # Support dual-band from agent data
        if wifi_data.get('ssid_24ghz') or wifi_data.get('ssid_5ghz'):
            data['ssid_24ghz'] = wifi_data.get('ssid_24ghz')
            data['ssid_5ghz'] = wifi_data.get('ssid_5ghz')
            data['channel_24ghz'] = wifi_data.get('channel_24ghz')
            data['channel_5ghz'] = wifi_data.get('channel_5ghz')
            # Use 5GHz as primary if available
            data['ssid'] = data['ssid_5ghz'] or data['ssid_24ghz']
            data['current_channel'] = data['channel_5ghz'] or data['channel_24ghz']
            data['band'] = '5GHz' if data['channel_5ghz'] else '2.4GHz'
        elif wifi_data.get('primary_ssid'):
            data['ssid'] = wifi_data.get('primary_ssid')
            data['current_channel'] = wifi_data.get('primary_channel')
            data['band'] = wifi_data.get('primary_band', '5GHz')
            data['hw_mode'] = 'a' if data['band'] == '5GHz' else 'g'

        # Process interfaces for dual-band info
        if wifi_data.get('interfaces'):
            for iface_info in wifi_data['interfaces']:
                channel = iface_info.get('channel')
                ssid = iface_info.get('ssid')
                if channel and channel <= 14:
                    data['channel_24ghz'] = channel
                    data['ssid_24ghz'] = ssid or data['ssid']
                elif channel and channel > 14:
                    data['channel_5ghz'] = channel
                    data['ssid_5ghz'] = ssid or data['ssid']
                if not data['wifi_interface']:
                    data['wifi_interface'] = iface_info.get('interface')

        logger.debug(f"Loaded WiFi status from agent data: SSID={data['ssid']} ch_24={data['channel_24ghz']} ch_5={data['channel_5ghz']}")
    else:
        # Priority 2: Fallback - Read hostapd config files directly
        # Check for dual-band configs
        hostapd_configs = [
            ('/etc/hostapd/fortress-5ghz.conf', '5GHz'),
            ('/etc/hostapd/fortress-24ghz.conf', '2.4GHz'),
            ('/etc/hostapd/fortress.conf', None),  # Single config fallback
        ]

        for conf_path, band_hint in hostapd_configs:
            if os.path.exists(conf_path):
                try:
                    conf_data = {}
                    with open(conf_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('channel='):
                                conf_data['channel'] = int(line.split('=')[1])
                            elif line.startswith('hw_mode='):
                                conf_data['hw_mode'] = line.split('=')[1]
                            elif line.startswith('interface='):
                                conf_data['interface'] = line.split('=')[1]
                            elif line.startswith('ssid='):
                                conf_data['ssid'] = line.split('=')[1]

                    # Determine band
                    ch = conf_data.get('channel')
                    is_5ghz = (band_hint == '5GHz' or
                               conf_data.get('hw_mode') == 'a' or
                               (ch and ch > 14))

                    if is_5ghz:
                        data['channel_5ghz'] = ch
                        data['ssid_5ghz'] = conf_data.get('ssid')
                    else:
                        data['channel_24ghz'] = ch
                        data['ssid_24ghz'] = conf_data.get('ssid')

                    # Set primary values
                    if not data['current_channel']:
                        data['current_channel'] = ch
                        data['hw_mode'] = conf_data.get('hw_mode', 'a' if is_5ghz else 'g')
                        data['wifi_interface'] = conf_data.get('interface')
                        data['ssid'] = conf_data.get('ssid')
                        data['band'] = '5GHz' if is_5ghz else '2.4GHz'
                except Exception:
                    pass

    # Read channel state file for optimization history
    state_file = '/var/lib/fortress/channel_state.json'
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
                data['last_optimization'] = state.get('last_scan')
                data['previous_channel'] = state.get('previous_channel')
                data['optimization_method'] = state.get('method', 'interference_score')
                if state.get('score'):
                    data['ml_score'] = state.get('score')
        except Exception:
            pass

    # Calculate next optimization time (4:00 AM)
    now = datetime.now()
    next_4am = now.replace(hour=4, minute=0, second=0, microsecond=0)
    if now.hour >= 4:
        next_4am += timedelta(days=1)
    data['next_optimization'] = next_4am.isoformat()
    time_diff = next_4am - now
    hours, remainder = divmod(int(time_diff.total_seconds()), 3600)
    minutes = remainder // 60
    data['time_to_next'] = f'{hours}h {minutes}m'
    data['time_to_next_seconds'] = int(time_diff.total_seconds())

    # Check if DFS intelligence is available
    dfs_selector = '/usr/local/bin/dfs-channel-selector'
    if os.path.exists(dfs_selector) and os.access(dfs_selector, os.X_OK):
        data['dfs_available'] = True

        # Try to get DFS status
        try:
            result = subprocess.run(
                [dfs_selector, 'status'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse status output
                for line in result.stdout.strip().split('\n'):
                    if 'radar events' in line.lower():
                        try:
                            data['radar_count_30d'] = int(line.split(':')[1].strip().split()[0])
                        except (ValueError, IndexError):
                            pass
        except Exception:
            pass

        # Try to get current channel score
        if data['current_channel'] and data['band'] == '5GHz':
            try:
                result = subprocess.run(
                    [dfs_selector, 'score', str(data['current_channel'])],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    try:
                        data['ml_score'] = float(result.stdout.strip())
                    except ValueError:
                        pass
            except Exception:
                pass

    # Read radar events from DFS log
    radar_log = '/var/lib/fortress/dfs/radar_events.jsonl'
    if os.path.exists(radar_log):
        try:
            events = []
            with open(radar_log, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        events.append(event)
                    except json.JSONDecodeError:
                        pass
            # Return last 10 events
            data['radar_events'] = events[-10:]
            # Count events in last 30 days
            cutoff = (datetime.now() - timedelta(days=30)).isoformat()
            data['radar_count_30d'] = len([e for e in events if e.get('timestamp', '') > cutoff])
        except Exception:
            pass

    # Read channel switch count from optimization log
    opt_log = '/var/log/hookprobe/channel-optimization.log'
    if os.path.exists(opt_log):
        try:
            with open(opt_log, 'r') as f:
                content = f.read()
                # Count "Updating hostapd config to channel" lines
                data['channel_switches_30d'] = content.count('Updating hostapd config to channel')
        except Exception:
            pass

    return jsonify({
        'success': True,
        'wifi_intelligence': data
    })


# ============================================================
# EXPORT
# ============================================================

@sdn_bp.route('/export')
@login_required
def export_devices():
    """Export device inventory with SDN info."""
    format_type = request.args.get('format', 'json')
    devices = []

    # Priority 1: Try to get real data from system
    try:
        real_devices = get_real_devices()
        if real_devices:
            devices = real_devices
    except Exception:
        pass

    # Priority 2: Try database if no real data
    if not devices and DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            devices = device_mgr.get_all_devices()
            for device in devices:
                classification = classify_device(device.get('mac_address', ''))
                device['oui_category'] = classification.get('category', 'unknown')
                device['auto_policy'] = classification.get('recommended_policy', 'default')

                for key in ['first_seen', 'last_seen']:
                    if device.get(key) and not isinstance(device[key], str):
                        device[key] = str(device[key])
        except Exception:
            pass

    # No demo fallback - return empty if no real devices found
    if not devices:
        devices = []

    if format_type == 'csv':
        import csv
        import io

        output = io.StringIO()
        if devices:
            writer = csv.DictWriter(output, fieldnames=devices[0].keys())
            writer.writeheader()
            writer.writerows(devices)

        return output.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename=sdn_devices.csv'
        }
    else:
        return jsonify({
            'exported_at': datetime.now().isoformat(),
            'count': len(devices),
            'devices': devices
        }), 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': 'attachment; filename=sdn_devices.json'
        }


# ============================================================
# SEGMENT DASHBOARD - Per-Category Traffic Visualization
# ============================================================

def get_demo_segment_data():
    """Return demo segment data for development."""
    import random
    import time

    base_time = time.time()
    segments = {
        'SECMON': {
            'vlan_id': 10,
            'name': 'Security Monitoring',
            'icon': 'fa-shield-alt',
            'color': '#17a2b8',
            'device_count': 3,
            'active_count': 2,
            'bytes_in': 524288000,
            'bytes_out': 1048576000,
            'bandwidth_mbps': 12.5,
            'top_devices': [
                {'mac': '00:0D:7C:12:34:56', 'hostname': 'Synology NVR', 'bytes': 800000000},
                {'mac': '00:0C:F6:AA:BB:CC', 'hostname': 'Axis Camera Hub', 'bytes': 200000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(50000, 150000), 'out': random.randint(100000, 300000)}
                for i in range(60, 0, -1)
            ]
        },
        'CLIENTS': {
            'vlan_id': 30,
            'name': 'Staff Devices',
            'icon': 'fa-laptop',
            'color': '#28a745',
            'device_count': 8,
            'active_count': 5,
            'bytes_in': 2147483648,
            'bytes_out': 536870912,
            'bandwidth_mbps': 45.2,
            'top_devices': [
                {'mac': '3C:06:30:DE:AD:BE', 'hostname': 'MacBook Sarah', 'bytes': 500000000},
                {'mac': 'A4:5E:60:11:22:33', 'hostname': 'iPhone Mike', 'bytes': 300000000},
                {'mac': '00:21:6A:44:55:66', 'hostname': 'Lenovo ThinkPad', 'bytes': 250000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(200000, 600000), 'out': random.randint(50000, 150000)}
                for i in range(60, 0, -1)
            ]
        },
        'POS': {
            'vlan_id': 20,
            'name': 'Point of Sale',
            'icon': 'fa-credit-card',
            'color': '#ffc107',
            'device_count': 2,
            'active_count': 2,
            'bytes_in': 104857600,
            'bytes_out': 52428800,
            'bandwidth_mbps': 2.1,
            'top_devices': [
                {'mac': '58:E6:BA:11:22:33', 'hostname': 'Square POS-1', 'bytes': 80000000},
                {'mac': '00:0B:CD:AA:BB:CC', 'hostname': 'Ingenico Terminal', 'bytes': 30000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(5000, 20000), 'out': random.randint(2000, 10000)}
                for i in range(60, 0, -1)
            ]
        },
        'CAMERAS': {
            'vlan_id': 50,
            'name': 'Security Cameras',
            'icon': 'fa-video',
            'color': '#6f42c1',
            'device_count': 6,
            'active_count': 6,
            'bytes_in': 10737418240,
            'bytes_out': 53687091,
            'bandwidth_mbps': 85.3,
            'top_devices': [
                {'mac': '28:57:BE:11:22:33', 'hostname': 'Hikvision Front', 'bytes': 3000000000},
                {'mac': '28:57:BE:44:55:66', 'hostname': 'Hikvision Back', 'bytes': 2500000000},
                {'mac': '3C:EF:8C:77:88:99', 'hostname': 'Dahua Parking', 'bytes': 2000000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(800000, 1200000), 'out': random.randint(5000, 15000)}
                for i in range(60, 0, -1)
            ]
        },
        'IIOT': {
            'vlan_id': 60,
            'name': 'IoT / Smart Devices',
            'icon': 'fa-thermometer-half',
            'color': '#fd7e14',
            'device_count': 12,
            'active_count': 10,
            'bytes_in': 52428800,
            'bytes_out': 26214400,
            'bandwidth_mbps': 0.8,
            'top_devices': [
                {'mac': '18:B4:30:AA:BB:CC', 'hostname': 'Nest Thermostat', 'bytes': 15000000},
                {'mac': '00:17:88:DD:EE:FF', 'hostname': 'Philips Hue Bridge', 'bytes': 10000000},
                {'mac': 'D4:F5:47:11:22:33', 'hostname': 'Google Nest Hub', 'bytes': 8000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(2000, 8000), 'out': random.randint(1000, 4000)}
                for i in range(60, 0, -1)
            ]
        },
    }
    return segments


@sdn_bp.route('/segments')
@login_required
def segments():
    """Network Segments Dashboard - Per-category traffic visualization."""
    segment_data = {}

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment_data = autopilot.get_segment_summary()
        except Exception as e:
            flash(f'Error loading segments: {e}', 'warning')
            segment_data = get_demo_segment_data()
    else:
        segment_data = get_demo_segment_data()

    return render_template(
        'sdn/segments.html',
        segments=segment_data,
        autopilot_available=SDN_AUTOPILOT_AVAILABLE
    )


@sdn_bp.route('/api/segments')
@login_required
def api_segments():
    """Get all segment statistics (JSON)."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            return jsonify({
                'success': True,
                'segments': autopilot.get_segment_summary()
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'segments': get_demo_segment_data()
        })


@sdn_bp.route('/api/segments/<segment_name>')
@login_required
def api_segment_detail(segment_name):
    """Get detailed statistics for a specific segment."""
    segment_name = segment_name.upper()

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment = NetworkSegment[segment_name]
            return jsonify({
                'success': True,
                'segment': autopilot.get_segment_stats(segment)
            })
        except KeyError:
            return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        demo = get_demo_segment_data()
        if segment_name in demo:
            return jsonify({
                'success': True,
                'segment': demo[segment_name]
            })
        return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404


@sdn_bp.route('/api/segments/<segment_name>/devices')
@login_required
def api_segment_devices(segment_name):
    """Get devices in a specific segment."""
    segment_name = segment_name.upper()

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment = NetworkSegment[segment_name]
            devices = autopilot.get_devices_by_segment(segment)
            return jsonify({
                'success': True,
                'segment': segment_name,
                'count': len(devices),
                'devices': [d.to_dict() for d in devices]
            })
        except KeyError:
            return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        # Return demo devices for the segment
        demo = get_demo_segment_data()
        if segment_name in demo:
            return jsonify({
                'success': True,
                'segment': segment_name,
                'count': len(demo[segment_name].get('top_devices', [])),
                'devices': demo[segment_name].get('top_devices', [])
            })
        return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404


@sdn_bp.route('/api/segments/<segment_name>/traffic')
@login_required
def api_segment_traffic(segment_name):
    """Get traffic history for a segment (for live chart updates)."""
    segment_name = segment_name.upper()

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment = NetworkSegment[segment_name]
            stats = autopilot.get_segment_stats(segment)
            return jsonify({
                'success': True,
                'segment': segment_name,
                'traffic_history': stats.get('traffic_history', [])
            })
        except KeyError:
            return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        demo = get_demo_segment_data()
        if segment_name in demo:
            return jsonify({
                'success': True,
                'segment': segment_name,
                'traffic_history': demo[segment_name].get('traffic_history', [])
            })
        return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404


@sdn_bp.route('/assign-segment', methods=['POST'])
@login_required
@operator_required
def assign_segment():
    """Assign a device to a network segment."""
    mac_address = request.form.get('mac')
    segment_id = request.form.get('segment')

    if not mac_address or not segment_id:
        return jsonify({'success': False, 'error': 'MAC address and segment required'}), 400

    try:
        segment_id = int(segment_id)
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid segment ID'}), 400

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment = NetworkSegment(segment_id)
            success = autopilot.assign_device_segment(mac_address, segment, persist=True)

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Device assigned to {segment.name} (VLAN {segment_id})'
                })
            else:
                return jsonify({'success': False, 'error': 'Assignment failed'}), 500

        except ValueError:
            return jsonify({'success': False, 'error': f'Invalid segment: {segment_id}'}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        # Demo mode - just return success
        return jsonify({
            'success': True,
            'message': f'Device assigned to VLAN {segment_id} (demo mode)'
        })


# ============================================================
# DEVICE TRUST FRAMEWORK - CIA Triad Authentication
# ============================================================

# Import Trust Framework
TRUST_FRAMEWORK_AVAILABLE = False
try:
    from device_trust_framework import (
        get_trust_framework,
        TrustLevel,
        DeviceTrustFramework,
    )
    TRUST_FRAMEWORK_AVAILABLE = True
except ImportError:
    pass


def get_demo_trust_data():
    """Return demo trust data for development."""
    return {
        'total_devices': 15,
        'trust_framework_enabled': True,
        # Dashboard expects lowercase keys for trust_distribution
        'trust_distribution': {
            'untrusted': 2,
            'minimal': 5,
            'standard': 4,
            'high': 3,
            'enterprise': 1,
        },
        # Keep uppercase version for backwards compatibility
        'by_trust_level': {
            'UNTRUSTED': 2,
            'MINIMAL': 5,
            'STANDARD': 4,
            'HIGH': 3,
            'ENTERPRISE': 1,
        },
        'verified_count': 8,
        'verified_percent': 53.3,
        'certificate_count': 4,
        'certificate_percent': 26.7,
        'attestation_count': 1,
        'attestation_percent': 6.7,
    }


def get_demo_trust_devices():
    """Return demo devices with trust information."""
    import random
    devices = [
        {'mac': '3C:06:30:DE:AD:BE', 'hostname': 'MacBook-Sarah', 'vendor': 'Apple', 'segment': 'CLIENTS', 'trust': 3, 'verified': True, 'cert': True},
        {'mac': 'A4:5E:60:11:22:33', 'hostname': 'iPhone-Mike', 'vendor': 'Apple', 'segment': 'CLIENTS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '00:21:6A:44:55:66', 'hostname': 'ThinkPad-T14', 'vendor': 'Lenovo', 'segment': 'CLIENTS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '58:E6:BA:11:22:33', 'hostname': 'Square-POS-1', 'vendor': 'Square', 'segment': 'POS', 'trust': 3, 'verified': True, 'cert': True},
        {'mac': '00:0B:CD:AA:BB:CC', 'hostname': 'Ingenico-Term', 'vendor': 'Ingenico', 'segment': 'POS', 'trust': 3, 'verified': True, 'cert': True},
        {'mac': '28:57:BE:11:22:33', 'hostname': 'Hikvision-Front', 'vendor': 'Hikvision', 'segment': 'CAMERAS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '3C:EF:8C:77:88:99', 'hostname': 'Dahua-Parking', 'vendor': 'Dahua', 'segment': 'CAMERAS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '00:0D:7C:12:34:56', 'hostname': 'Synology-NVR', 'vendor': 'Synology', 'segment': 'SECMON', 'trust': 4, 'verified': True, 'cert': True},
        {'mac': '18:B4:30:AA:BB:CC', 'hostname': 'Nest-Thermostat', 'vendor': 'Google Nest', 'segment': 'IIOT', 'trust': 1, 'verified': False, 'cert': False},
        {'mac': '00:17:88:DD:EE:FF', 'hostname': 'Philips-Hue', 'vendor': 'Philips', 'segment': 'IIOT', 'trust': 1, 'verified': False, 'cert': False},
        {'mac': 'AA:BB:CC:DD:EE:FF', 'hostname': 'Unknown-Device', 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'verified': False, 'cert': False},
        {'mac': '11:22:33:44:55:66', 'hostname': None, 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'verified': False, 'cert': False},
    ]

    trust_names = {0: 'UNTRUSTED', 1: 'MINIMAL', 2: 'STANDARD', 3: 'HIGH', 4: 'ENTERPRISE'}

    return [
        {
            'mac_address': d['mac'],
            'hostname': d['hostname'],
            'ip_address': f"10.200.0.{100 + i}",
            'vendor': d['vendor'],
            'segment_name': d['segment'],
            'trust_level': d['trust'],
            'trust_level_name': trust_names.get(d['trust'], 'UNKNOWN'),
            'trust_verified': d['verified'],
            'certificate_issued': d['cert'],
        }
        for i, d in enumerate(devices)
    ]


@sdn_bp.route('/trust')
@login_required
def trust_dashboard():
    """Device Trust Framework dashboard - CIA Triad authentication."""
    trust_summary = {}
    devices = []
    segment_colors = {
        'SECMON': '#17a2b8',
        'CLIENTS': '#28a745',
        'POS': '#ffc107',
        'CAMERAS': '#6f42c1',
        'IIOT': '#fd7e14',
        'GUEST': '#20c997',
        'QUARANTINE': '#dc3545',
    }

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            trust_summary = autopilot.get_trust_summary()
            devices = autopilot.get_all_devices()
        except Exception as e:
            flash(f'Error loading trust data: {e}', 'warning')
            trust_summary = get_demo_trust_data()
            devices = get_demo_trust_devices()
    else:
        trust_summary = get_demo_trust_data()
        devices = get_demo_trust_devices()

    return render_template(
        'sdn/trust.html',
        trust_summary=trust_summary,
        devices=devices,
        segment_colors=segment_colors,
        trust_available=TRUST_FRAMEWORK_AVAILABLE
    )


@sdn_bp.route('/api/trust')
@login_required
def api_trust_summary():
    """Get trust framework summary (JSON)."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            return jsonify({
                'success': True,
                'trust_summary': autopilot.get_trust_summary(),
                'trust_framework_available': TRUST_FRAMEWORK_AVAILABLE
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'trust_summary': get_demo_trust_data(),
            'trust_framework_available': False
        })


@sdn_bp.route('/api/trust/enroll', methods=['POST'])
@login_required
@operator_required
def api_enroll_device():
    """Enroll a device for certificate-based authentication."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if TRUST_FRAMEWORK_AVAILABLE:
        try:
            import secrets
            trust_framework = get_trust_framework()

            # Generate device key (in production, device would provide this)
            device_pubkey = secrets.token_bytes(32)

            # Issue certificate
            cert = trust_framework.issue_certificate(
                mac_address=mac_address,
                public_key=device_pubkey,
                trust_level=TrustLevel.STANDARD,
                validity_days=30
            )

            if cert:
                return jsonify({
                    'success': True,
                    'message': f'Device {mac_address} enrolled successfully',
                    'cert_id': cert.cert_id,
                    'expires': cert.expires_at
                })
            else:
                return jsonify({'success': False, 'error': 'Certificate issuance failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac_address} enrolled (demo mode)'
        })


@sdn_bp.route('/api/trust/revoke', methods=['POST'])
@login_required
@operator_required
def api_revoke_device():
    """Revoke a device certificate."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if TRUST_FRAMEWORK_AVAILABLE:
        try:
            trust_framework = get_trust_framework()
            success = trust_framework.revoke_certificate(mac_address, reason="admin_revoke")

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Certificate revoked for {mac_address}'
                })
            else:
                return jsonify({'success': False, 'error': 'Revocation failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Certificate revoked for {mac_address} (demo mode)'
        })


@sdn_bp.route('/api/trust/quarantine', methods=['POST'])
@login_required
@operator_required
def api_quarantine_device():
    """Move a device to quarantine."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            success = autopilot.assign_device_segment(
                mac_address,
                NetworkSegment.QUARANTINE,
                persist=True
            )

            if success:
                # Also revoke certificate if trust framework available
                if TRUST_FRAMEWORK_AVAILABLE:
                    trust_framework = get_trust_framework()
                    trust_framework.revoke_certificate(mac_address, reason="quarantine")

                return jsonify({
                    'success': True,
                    'message': f'Device {mac_address} moved to quarantine'
                })
            else:
                return jsonify({'success': False, 'error': 'Quarantine failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac_address} quarantined (demo mode)'
        })


# ============================================================
# UNIFIED SDN MANAGEMENT DASHBOARD
# ============================================================

def get_demo_wifi_data():
    """Return demo WiFi intelligence data."""
    from datetime import datetime, timedelta
    import random

    now = datetime.now()
    events = [
        {'timestamp': (now - timedelta(hours=2)).isoformat(), 'type': 'switch', 'message': 'Channel switched 36 → 149 (congestion)'},
        {'timestamp': (now - timedelta(hours=4)).isoformat(), 'type': 'radar', 'message': 'Radar detected on CH 52 (weather)'},
        {'timestamp': (now - timedelta(hours=8)).isoformat(), 'type': 'cac', 'message': 'CAC completed on CH 149'},
        {'timestamp': (now - timedelta(hours=12)).isoformat(), 'type': 'switch', 'message': 'Channel switched 44 → 36 (DFS)'},
        {'timestamp': (now - timedelta(hours=18)).isoformat(), 'type': 'radar', 'message': 'Radar detected on CH 100'},
    ]

    return {
        'channel': 149,
        'width': 80,
        'power': 23,
        'band': '5GHz',
        'dfs_status': 'clear',
        'channel_score': random.randint(75, 95),
        'radar_events_24h': 2,
        'channel_switches_24h': 5,
        'events': events,
        'ssid': 'HookProbe-Fortress',
        'clients_24': random.randint(3, 8),
        'clients_5': random.randint(10, 20),
    }


def get_demo_sdn_devices():
    """Return demo devices for SDN Management dashboard."""
    import random

    segments = ['STAFF', 'GUEST', 'POS', 'CAMERAS', 'IIOT', 'QUARANTINE', 'SECMON']
    segment_vlans = {'SECMON': 10, 'POS': 20, 'STAFF': 30, 'GUEST': 40, 'CAMERAS': 50, 'IIOT': 60, 'QUARANTINE': 99}

    devices = [
        {'mac': '3C:06:30:DE:AD:BE', 'hostname': 'MacBook-Sarah', 'vendor': 'Apple', 'segment': 'STAFF', 'trust': 3, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': 'A4:5E:60:11:22:33', 'hostname': 'iPhone-Mike', 'vendor': 'Apple', 'segment': 'STAFF', 'trust': 2, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': '00:21:6A:44:55:66', 'hostname': 'ThinkPad-T14', 'vendor': 'Lenovo', 'segment': 'STAFF', 'trust': 2, 'conn': 'lan', 'band': None},
        {'mac': '58:E6:BA:11:22:33', 'hostname': 'Square-POS-1', 'vendor': 'Square', 'segment': 'POS', 'trust': 3, 'conn': 'lan', 'band': None},
        {'mac': '00:0B:CD:AA:BB:CC', 'hostname': 'Ingenico-Term', 'vendor': 'Ingenico', 'segment': 'POS', 'trust': 3, 'conn': 'lan', 'band': None},
        {'mac': '28:57:BE:11:22:33', 'hostname': 'Hikvision-Front', 'vendor': 'Hikvision', 'segment': 'CAMERAS', 'trust': 2, 'conn': 'lan', 'band': None},
        {'mac': '3C:EF:8C:77:88:99', 'hostname': 'Dahua-Parking', 'vendor': 'Dahua', 'segment': 'CAMERAS', 'trust': 2, 'conn': 'lan', 'band': None},
        {'mac': '00:0D:7C:12:34:56', 'hostname': 'Synology-NVR', 'vendor': 'Synology', 'segment': 'SECMON', 'trust': 4, 'conn': 'lan', 'band': None},
        {'mac': '18:B4:30:AA:BB:CC', 'hostname': 'Nest-Thermostat', 'vendor': 'Google Nest', 'segment': 'IIOT', 'trust': 1, 'conn': 'wifi', 'band': '2.4GHz'},
        {'mac': '00:17:88:DD:EE:FF', 'hostname': 'Philips-Hue', 'vendor': 'Philips', 'segment': 'IIOT', 'trust': 1, 'conn': 'lan', 'band': None},
        {'mac': 'CC:50:E3:12:34:56', 'hostname': 'Samsung-Tab', 'vendor': 'Samsung', 'segment': 'GUEST', 'trust': 1, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': '48:E1:E9:AA:BB:CC', 'hostname': 'Pixel-Guest', 'vendor': 'Google', 'segment': 'GUEST', 'trust': 1, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': 'AA:BB:CC:DD:EE:FF', 'hostname': 'Unknown-Device', 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'conn': 'wifi', 'band': '2.4GHz'},
        {'mac': '11:22:33:44:55:66', 'hostname': None, 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'conn': 'lan', 'band': None},
    ]

    return [
        {
            'mac': d['mac'],
            'hostname': d['hostname'] or 'Unknown',
            'ip_address': f"10.200.0.{100 + i}",
            'vendor': d['vendor'],
            'segment': d['segment'],
            'vlan_id': segment_vlans.get(d['segment'], 40),
            'trust_level': d['trust'],
            'connection_type': d['conn'],
            'band': d['band'],
            'online': random.choice([True, True, True, False]),
        }
        for i, d in enumerate(devices)
    ]


@sdn_bp.route('/management')
@login_required
def management_dashboard():
    """Unified SDN Management Dashboard - Consolidates clients/networks/WiFi."""
    return render_template('sdn/management.html')


@sdn_bp.route('/api/sdn/devices')
@login_required
def api_sdn_devices():
    """Get all network devices for SDN Management dashboard."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            devices = autopilot.get_all_devices()

            # Transform to SDN format
            sdn_devices = []
            for device in devices:
                sdn_devices.append({
                    'mac': device.get('mac_address', ''),
                    'hostname': device.get('hostname', 'Unknown'),
                    'ip_address': device.get('ip_address', '--'),
                    'vendor': device.get('vendor', 'Unknown'),
                    'segment': device.get('segment_name', 'GUEST'),
                    'vlan_id': device.get('vlan_id', 40),
                    'trust_level': device.get('trust_level', 1),
                    'connection_type': device.get('connection_type', 'lan'),
                    'band': device.get('band'),
                    'online': device.get('is_online', False),
                })

            return jsonify({'success': True, 'devices': sdn_devices})

        except Exception as e:
            return jsonify({'success': False, 'error': str(e), 'devices': []}), 500
    else:
        # Demo mode
        return jsonify({'success': True, 'devices': get_demo_sdn_devices()})


@sdn_bp.route('/api/sdn/segments')
@login_required
def api_sdn_segments():
    """Get segment distribution statistics."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            devices = autopilot.get_all_devices()

            # Count devices per segment
            segments = {}
            for device in devices:
                seg = device.get('segment_name', 'GUEST')
                segments[seg] = segments.get(seg, 0) + 1

            return jsonify({'success': True, 'segments': segments})

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        # Demo data
        demo_devices = get_demo_sdn_devices()
        segments = {}
        for d in demo_devices:
            seg = d['segment']
            segments[seg] = segments.get(seg, 0) + 1

        return jsonify({'success': True, 'segments': segments})


@sdn_bp.route('/api/sdn/wifi')
@login_required
def api_sdn_wifi_status():
    """Get WiFi intelligence data including DFS/channel info."""
    import subprocess
    import os

    # Try to get real data from hostapd/iw
    wifi_data = None

    try:
        # Check if DFS Intelligence is available
        dfs_available = False
        try:
            from shared.wireless import ChannelScorer, DFSDatabase
            dfs_available = True
        except ImportError:
            pass

        # Try to get real WiFi status
        result = subprocess.run(
            ['iw', 'dev'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0 and result.stdout:
            # Parse iw output for channel info
            wifi_data = parse_iw_output(result.stdout)

        # Try to get DFS intelligence data
        if dfs_available and wifi_data:
            try:
                scorer = ChannelScorer()
                channel = wifi_data.get('channel', 149)
                score = scorer.score_channel(channel)
                wifi_data['channel_score'] = int(score.total_score * 100)
            except Exception:
                pass

    except Exception as e:
        # Fall back to demo data
        pass

    if not wifi_data:
        wifi_data = get_demo_wifi_data()

    return jsonify(wifi_data)


def parse_iw_output(output):
    """Parse iw dev output to extract WiFi info."""
    import re

    data = {
        'channel': None,
        'width': None,
        'power': None,
        'band': '5GHz',
        'dfs_status': 'clear',
        'channel_score': 85,
        'radar_events_24h': 0,
        'channel_switches_24h': 0,
        'events': [],
    }

    # Look for channel info
    channel_match = re.search(r'channel (\d+)', output)
    if channel_match:
        data['channel'] = int(channel_match.group(1))
        # Determine band from channel
        if data['channel'] <= 14:
            data['band'] = '2.4GHz'

    # Look for width
    width_match = re.search(r'width: (\d+)', output)
    if width_match:
        data['width'] = int(width_match.group(1))

    # Look for txpower
    power_match = re.search(r'txpower (\d+\.\d+)', output)
    if power_match:
        data['power'] = int(float(power_match.group(1)))

    return data


@sdn_bp.route('/api/sdn/move', methods=['POST'])
@login_required
@operator_required
def api_move_device():
    """Move a device to a different segment."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')
    segment = data.get('segment', '').upper()

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if not segment:
        return jsonify({'success': False, 'error': 'Segment required'}), 400

    # Map segment name to NetworkSegment enum
    segment_map = {
        'SECMON': 'SECMON',
        'POS': 'POS',
        'STAFF': 'CLIENTS',
        'CLIENTS': 'CLIENTS',
        'GUEST': 'GUEST',
        'CAMERAS': 'CAMERAS',
        'IIOT': 'IIOT',
        'QUARANTINE': 'QUARANTINE',
    }

    if segment not in segment_map:
        return jsonify({'success': False, 'error': f'Invalid segment: {segment}'}), 400

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()

            # Get the NetworkSegment enum value
            target_segment = getattr(NetworkSegment, segment_map[segment], None)
            if target_segment is None:
                return jsonify({'success': False, 'error': f'Segment not found: {segment}'}), 400

            success = autopilot.assign_device_segment(
                mac_address,
                target_segment,
                persist=True
            )

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Device {mac_address} moved to {segment}'
                })
            else:
                return jsonify({'success': False, 'error': 'Move failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac_address} moved to {segment} (demo mode)'
        })


# ============================================================
# DEVICE DATA CRUD API - Persistent device management
# ============================================================

@sdn_bp.route('/api/device/register', methods=['POST'])
@login_required
@operator_required
def api_device_register():
    """
    Create/register a device with policy assignment.

    POST data:
        mac_address: Device MAC address (required)
        name: Friendly name
        policy: Network policy (full_access, lan_only, internet_only, isolated, default)
        notes: Optional notes
        is_trusted: Whether device is trusted
    """
    data = request.get_json() or {}
    mac_address = data.get('mac_address', '').upper().strip()

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    # Validate MAC format
    import re
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac_address.replace('-', ':')):
        return jsonify({'success': False, 'error': 'Invalid MAC address format'}), 400

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            entry = manager.create(
                mac_address=mac_address,
                name=data.get('name', ''),
                policy=data.get('policy', 'default'),
                notes=data.get('notes', ''),
                is_trusted=data.get('is_trusted', False),
            )

            return jsonify({
                'success': True,
                'device': {
                    'mac_address': entry.mac_address,
                    'name': entry.name,
                    'policy': entry.policy,
                    'category': entry.category,
                    'manufacturer': entry.manufacturer,
                    'is_trusted': entry.is_trusted,
                    'created_at': entry.created_at,
                }
            })
        except Exception as e:
            logger.error(f"Failed to register device: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'device': {
                'mac_address': mac_address,
                'name': data.get('name', ''),
                'policy': data.get('policy', 'default'),
            },
            'note': 'Demo mode - device not persisted'
        })


@sdn_bp.route('/api/device/<mac_address>')
@login_required
def api_device_get(mac_address):
    """Get device details by MAC address."""
    mac = mac_address.upper().replace('-', ':')

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            device = manager.read(mac)

            if device:
                return jsonify({'success': True, 'device': device})
            else:
                return jsonify({'success': False, 'error': 'Device not found'}), 404
        except Exception as e:
            logger.error(f"Failed to get device: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        # Return demo data
        return jsonify({
            'success': True,
            'device': {
                'mac_address': mac,
                'ip_address': '',
                'name': '',
                'policy': 'default',
                'category': 'unknown',
                'manufacturer': 'Unknown',
            }
        })


@sdn_bp.route('/api/device/<mac_address>', methods=['PUT', 'PATCH'])
@login_required
@operator_required
def api_device_update(mac_address):
    """
    Update a device entry.

    PUT/PATCH data:
        name: Friendly name
        policy: Network policy
        notes: Notes
        is_trusted: Trusted flag
        is_blocked: Blocked flag
        category: Device category
    """
    mac = mac_address.upper().replace('-', ':')
    data = request.get_json() or {}

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()

            # Filter allowed fields
            allowed = {'name', 'policy', 'notes', 'is_trusted', 'is_blocked', 'category'}
            updates = {k: v for k, v in data.items() if k in allowed}

            entry = manager.update(mac, **updates)

            if entry:
                return jsonify({
                    'success': True,
                    'device': {
                        'mac_address': entry.mac_address,
                        'name': entry.name,
                        'policy': entry.policy,
                        'category': entry.category,
                        'is_blocked': entry.is_blocked,
                        'is_trusted': entry.is_trusted,
                        'updated_at': entry.updated_at,
                    }
                })
            else:
                return jsonify({'success': False, 'error': 'Update failed'}), 500
        except Exception as e:
            logger.error(f"Failed to update device: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'device': {'mac_address': mac, **data},
            'note': 'Demo mode - changes not persisted'
        })


@sdn_bp.route('/api/device/<mac_address>', methods=['DELETE'])
@login_required
@operator_required
def api_device_delete(mac_address):
    """Delete a device entry."""
    mac = mac_address.upper().replace('-', ':')

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            success = manager.delete(mac)

            if success:
                return jsonify({'success': True, 'message': f'Device {mac} deleted'})
            else:
                return jsonify({'success': False, 'error': 'Device not found'}), 404
        except Exception as e:
            logger.error(f"Failed to delete device: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac} deleted (demo mode)'
        })


@sdn_bp.route('/api/device/<mac_address>/policy', methods=['POST'])
@login_required
@operator_required
def api_device_set_policy(mac_address):
    """
    Set network policy for a device.

    POST data:
        policy: Network policy (full_access, lan_only, internet_only, isolated, default)
    """
    mac = mac_address.upper().replace('-', ':')
    data = request.get_json() or {}
    policy = data.get('policy', 'default')

    valid_policies = ['full_access', 'lan_only', 'internet_only', 'isolated', 'default']
    if policy not in valid_policies:
        return jsonify({
            'success': False,
            'error': f'Invalid policy. Must be one of: {", ".join(valid_policies)}'
        }), 400

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            success = manager.set_policy(mac, policy)

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Policy set to {policy} for {mac}'
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to set policy'}), 500
        except Exception as e:
            logger.error(f"Failed to set device policy: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Policy set to {policy} for {mac} (demo mode)'
        })


@sdn_bp.route('/api/device/<mac_address>/block', methods=['POST'])
@login_required
@operator_required
def api_device_block(mac_address):
    """Block a device."""
    mac = mac_address.upper().replace('-', ':')
    data = request.get_json() or {}
    reason = data.get('reason', '')

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            success = manager.block(mac, reason)

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Device {mac} blocked'
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to block device'}), 500
        except Exception as e:
            logger.error(f"Failed to block device: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac} blocked (demo mode)'
        })


@sdn_bp.route('/api/device/<mac_address>/unblock', methods=['POST'])
@login_required
@operator_required
def api_device_unblock(mac_address):
    """Unblock a device."""
    mac = mac_address.upper().replace('-', ':')

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            success = manager.unblock(mac)

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Device {mac} unblocked'
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to unblock device'}), 500
        except Exception as e:
            logger.error(f"Failed to unblock device: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac} unblocked (demo mode)'
        })


@sdn_bp.route('/api/device/list')
@login_required
def api_device_list():
    """
    List all devices with optional filters.

    Query params:
        policy: Filter by policy
        category: Filter by category
        online: Filter online/offline (true/false)
    """
    policy = request.args.get('policy')
    category = request.args.get('category')
    online = request.args.get('online')

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()

            if policy:
                devices = manager.list_by_policy(policy)
            elif category:
                devices = manager.list_by_category(category)
            else:
                devices = manager.list_all()

            # Filter by online status
            if online is not None:
                online_bool = online.lower() in ('true', '1', 'yes')
                devices = [
                    d for d in devices
                    if (d.get('state') in ('REACHABLE', 'DELAY')) == online_bool
                ]

            return jsonify({
                'success': True,
                'devices': devices,
                'count': len(devices),
            })
        except Exception as e:
            logger.error(f"Failed to list devices: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        # Return demo data
        return jsonify({
            'success': True,
            'devices': [],
            'count': 0,
            'note': 'Device data manager not available'
        })


@sdn_bp.route('/api/device/stats')
@login_required
def api_device_stats():
    """Get device statistics."""
    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            stats = manager.get_stats()
            return jsonify({'success': True, 'stats': stats})
        except Exception as e:
            logger.error(f"Failed to get device stats: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'stats': {
                'total': 0,
                'online': 0,
                'offline': 0,
                'blocked': 0,
                'registered': 0,
                'by_policy': {},
                'by_category': {},
            }
        })


@sdn_bp.route('/api/device/sync-policies', methods=['POST'])
@login_required
@operator_required
def api_device_sync_policies():
    """Sync all device policies to OpenFlow rules."""
    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            manager.sync_policies()
            return jsonify({
                'success': True,
                'message': 'All policies synced to network'
            })
        except Exception as e:
            logger.error(f"Failed to sync policies: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': 'Policies synced (demo mode)'
        })


@sdn_bp.route('/api/policies/available')
@login_required
def api_policies_available():
    """Get available network policies with descriptions."""
    policies = [
        {
            'id': 'full_access',
            'name': 'Full Access',
            'description': 'Full internet and LAN access (staff, trusted devices)',
            'icon': 'fas fa-globe',
            'color': 'success',
        },
        {
            'id': 'lan_only',
            'name': 'LAN Only',
            'description': 'LAN access only, no internet (cameras, printers, IoT)',
            'icon': 'fas fa-network-wired',
            'color': 'info',
        },
        {
            'id': 'internet_only',
            'name': 'Internet Only',
            'description': 'Internet only, no LAN access (guests, POS, voice assistants)',
            'icon': 'fas fa-cloud',
            'color': 'primary',
        },
        {
            'id': 'isolated',
            'name': 'Isolated',
            'description': 'Completely isolated, no network access (quarantined)',
            'icon': 'fas fa-ban',
            'color': 'danger',
        },
        {
            'id': 'default',
            'name': 'Default (Auto)',
            'description': 'Auto-classified based on device type',
            'icon': 'fas fa-magic',
            'color': 'secondary',
        },
    ]

    categories = [
        {'id': 'workstation', 'name': 'Workstation', 'icon': 'fas fa-desktop'},
        {'id': 'mobile', 'name': 'Mobile', 'icon': 'fas fa-mobile-alt'},
        {'id': 'iot', 'name': 'IoT', 'icon': 'fas fa-microchip'},
        {'id': 'camera', 'name': 'Camera', 'icon': 'fas fa-video'},
        {'id': 'printer', 'name': 'Printer', 'icon': 'fas fa-print'},
        {'id': 'pos', 'name': 'POS Terminal', 'icon': 'fas fa-cash-register'},
        {'id': 'voice_assistant', 'name': 'Voice Assistant', 'icon': 'fas fa-microphone'},
        {'id': 'network', 'name': 'Network Equipment', 'icon': 'fas fa-network-wired'},
        {'id': 'unknown', 'name': 'Unknown', 'icon': 'fas fa-question'},
    ]

    return jsonify({
        'success': True,
        'policies': policies,
        'categories': categories,
    })


# ============================================================
# DEVICE TAGGING API - Manual device classification
# ============================================================

DEVICE_TAGS_FILE = DATA_DIR / 'device_tags.json'


def load_device_tags():
    """Load manually assigned device tags."""
    if DEVICE_TAGS_FILE.exists():
        try:
            return json.loads(DEVICE_TAGS_FILE.read_text())
        except Exception:
            pass
    return {}


def save_device_tags(tags):
    """Save device tags to file."""
    try:
        DEVICE_TAGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        DEVICE_TAGS_FILE.write_text(json.dumps(tags, indent=2))
        return True
    except Exception as e:
        logger.error(f"Failed to save device tags: {e}")
        return False


@sdn_bp.route('/api/device/<mac_address>/tag', methods=['POST'])
@login_required
@operator_required
def api_device_tag(mac_address):
    """
    Manually tag a device with a device type and optional label.

    POST data:
        device_type: Device type (e.g., 'iphone', 'apple_watch', 'homepod', 'smart_tv')
        label: Optional friendly label for the device
    """
    mac = mac_address.upper().replace('-', ':')
    data = request.get_json() or {}

    device_type = data.get('device_type')
    label = data.get('label')

    if not device_type:
        return jsonify({'success': False, 'error': 'device_type is required'}), 400

    # Load existing tags
    tags = load_device_tags()

    # Update or create tag
    tags[mac] = {
        'device_type': device_type,
        'label': label,
        'tagged_at': datetime.now().isoformat(),
        'tagged_by': current_user.username if hasattr(current_user, 'username') else 'admin'
    }

    if save_device_tags(tags):
        return jsonify({
            'success': True,
            'message': f'Device {mac} tagged as {device_type}',
            'tag': tags[mac]
        })
    else:
        return jsonify({'success': False, 'error': 'Failed to save tag'}), 500


@sdn_bp.route('/api/device/<mac_address>/tag', methods=['DELETE'])
@login_required
@operator_required
def api_device_untag(mac_address):
    """Remove manual tag from a device (revert to auto-detection)."""
    mac = mac_address.upper().replace('-', ':')

    tags = load_device_tags()
    if mac in tags:
        del tags[mac]
        if save_device_tags(tags):
            return jsonify({
                'success': True,
                'message': f'Tag removed from {mac} - device will use auto-detection'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to save'}), 500
    else:
        return jsonify({'success': False, 'error': 'Device has no manual tag'}), 404


@sdn_bp.route('/api/device/tags')
@login_required
def api_device_tags_list():
    """List all manually tagged devices."""
    tags = load_device_tags()
    return jsonify({
        'success': True,
        'count': len(tags),
        'tags': tags
    })


@sdn_bp.route('/api/device/types')
@login_required
def api_device_types():
    """Get available device types for manual tagging."""
    device_types = [
        # Apple devices
        {'id': 'iphone', 'name': 'iPhone', 'icon': 'fa-mobile-alt', 'category': 'phone'},
        {'id': 'ipad', 'name': 'iPad', 'icon': 'fa-tablet-alt', 'category': 'tablet'},
        {'id': 'macbook', 'name': 'MacBook', 'icon': 'fa-laptop', 'category': 'laptop'},
        {'id': 'imac', 'name': 'iMac', 'icon': 'fa-desktop', 'category': 'desktop'},
        {'id': 'mac_mini', 'name': 'Mac mini', 'icon': 'fa-server', 'category': 'desktop'},
        {'id': 'apple_watch', 'name': 'Apple Watch', 'icon': 'fa-clock', 'category': 'wearable'},
        {'id': 'homepod', 'name': 'HomePod', 'icon': 'fa-volume-up', 'category': 'speaker'},
        {'id': 'apple_tv', 'name': 'Apple TV', 'icon': 'fa-tv', 'category': 'streaming'},
        {'id': 'airpods', 'name': 'AirPods', 'icon': 'fa-headphones', 'category': 'audio'},

        # Android devices
        {'id': 'android_phone', 'name': 'Android Phone', 'icon': 'fa-mobile-alt', 'category': 'phone'},
        {'id': 'android_tablet', 'name': 'Android Tablet', 'icon': 'fa-tablet-alt', 'category': 'tablet'},

        # Computers
        {'id': 'windows_pc', 'name': 'Windows PC', 'icon': 'fa-desktop', 'category': 'computer'},
        {'id': 'linux_pc', 'name': 'Linux PC', 'icon': 'fa-linux', 'category': 'computer'},
        {'id': 'laptop', 'name': 'Laptop', 'icon': 'fa-laptop', 'category': 'computer'},

        # Smart speakers
        {'id': 'amazon_echo', 'name': 'Amazon Echo', 'icon': 'fa-volume-up', 'category': 'speaker'},
        {'id': 'sonos_speaker', 'name': 'Sonos Speaker', 'icon': 'fa-volume-up', 'category': 'speaker'},
        {'id': 'google_home', 'name': 'Google Home', 'icon': 'fa-volume-up', 'category': 'speaker'},
        {'id': 'nest_hub', 'name': 'Nest Hub', 'icon': 'fa-tv', 'category': 'smart_display'},

        # Streaming devices
        {'id': 'smart_tv', 'name': 'Smart TV', 'icon': 'fa-tv', 'category': 'tv'},
        {'id': 'roku', 'name': 'Roku', 'icon': 'fa-tv', 'category': 'streaming'},
        {'id': 'chromecast', 'name': 'Chromecast', 'icon': 'fa-tv', 'category': 'streaming'},
        {'id': 'fire_tv', 'name': 'Fire TV', 'icon': 'fa-tv', 'category': 'streaming'},

        # IoT
        {'id': 'ip_camera', 'name': 'IP Camera', 'icon': 'fa-video', 'category': 'camera'},
        {'id': 'ring_camera', 'name': 'Ring Camera', 'icon': 'fa-video', 'category': 'camera'},
        {'id': 'smart_thermostat', 'name': 'Smart Thermostat', 'icon': 'fa-thermometer-half', 'category': 'iot'},
        {'id': 'smart_doorbell', 'name': 'Smart Doorbell', 'icon': 'fa-bell', 'category': 'iot'},
        {'id': 'smart_light', 'name': 'Smart Light', 'icon': 'fa-lightbulb', 'category': 'lighting'},
        {'id': 'raspberry_pi', 'name': 'Raspberry Pi', 'icon': 'fa-microchip', 'category': 'iot'},

        # Network devices
        {'id': 'router', 'name': 'Router', 'icon': 'fa-network-wired', 'category': 'network'},
        {'id': 'network_switch', 'name': 'Network Switch', 'icon': 'fa-network-wired', 'category': 'network'},
        {'id': 'access_point', 'name': 'Access Point', 'icon': 'fa-wifi', 'category': 'network'},

        # Printers
        {'id': 'printer', 'name': 'Printer', 'icon': 'fa-print', 'category': 'printer'},

        # Gaming
        {'id': 'playstation', 'name': 'PlayStation', 'icon': 'fa-gamepad', 'category': 'gaming'},
        {'id': 'xbox', 'name': 'Xbox', 'icon': 'fa-gamepad', 'category': 'gaming'},
        {'id': 'nintendo_switch', 'name': 'Nintendo Switch', 'icon': 'fa-gamepad', 'category': 'gaming'},

        # Generic
        {'id': 'unknown', 'name': 'Unknown Device', 'icon': 'fa-question-circle', 'category': 'unknown'},
    ]

    return jsonify({
        'success': True,
        'device_types': device_types
    })
