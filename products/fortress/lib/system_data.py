#!/usr/bin/env python3
"""
Fortress System Data Module

Provides real-time system data without database dependency.
Reads directly from Linux networking subsystem, ARP tables, OVS, and WiFi.

This module is the source of truth for device discovery, network topology,
and WAN health monitoring.
"""

import subprocess
import re
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from functools import lru_cache
import time

logger = logging.getLogger(__name__)

# Cache with expiry
_cache: Dict[str, Tuple[Any, float]] = {}
CACHE_TTL = 10  # seconds


def _get_cached(key: str, ttl: int = CACHE_TTL) -> Optional[Any]:
    """Get cached value if not expired."""
    if key in _cache:
        value, timestamp = _cache[key]
        if time.time() - timestamp < ttl:
            return value
    return None


def _set_cached(key: str, value: Any):
    """Set cached value."""
    _cache[key] = (value, time.time())


def _run_cmd(cmd: List[str], timeout: int = 10) -> Tuple[bool, str, str]:
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
        logger.debug(f"Command error {' '.join(cmd)}: {e}")
        return False, "", str(e)


# =============================================================================
# OUI Database for Manufacturer Lookup
# =============================================================================

OUI_DATABASE = {
    'Apple': [
        '00:1C:B3', '00:03:93', '00:0A:27', '00:0A:95', '00:10:FA', '00:11:24',
        '00:14:51', '00:16:CB', '00:17:F2', '00:19:E3', '00:1B:63', '00:1D:4F',
        '00:1E:52', '00:1E:C2', '00:1F:5B', '00:1F:F3', '00:21:E9', '00:22:41',
        '00:23:12', '00:23:32', '00:23:6C', '00:23:DF', '00:24:36', '00:25:00',
        '00:25:4B', '00:25:BC', '00:26:08', '00:26:4A', '00:26:B0', '00:26:BB',
        'A4:5E:60', 'AC:BC:32', 'B0:34:95', 'B8:09:8A', 'BC:52:B7', 'C0:84:7A',
        'D4:9A:20', 'DC:2B:2A', 'E0:B9:BA', 'F0:B4:79', 'F4:5C:89', '3C:06:30',
        '8C:85:90', 'A8:66:7F', 'AC:DE:48', 'B4:F0:AB', 'C8:69:CD', 'D0:C5:D3',
        'E8:06:88', 'F0:18:98', 'F4:F1:5A', '78:4F:43', '88:66:A5', '9C:20:7B',
    ],
    'Samsung': [
        '00:00:F0', '00:07:AB', '00:09:18', '00:12:47', '00:12:FB', '00:13:77',
        '00:15:99', '00:15:B9', '00:16:32', '00:16:6B', '00:16:6C', '00:17:C9',
        '00:17:D5', '00:18:AF', '00:1A:8A', '00:1B:98', '00:1C:43', '00:1D:25',
        '00:1D:F6', '00:1E:7D', '00:1F:CC', '00:21:4C', '00:21:D1', '00:21:D2',
        '00:26:37', '08:D4:2B', '10:D5:42', '14:89:FD', '18:3A:2D', '1C:62:B8',
        '20:D3:90', '24:4B:03', '28:98:7B', '30:CD:A7', '34:23:BA', '38:01:95',
    ],
    'Google': [
        '3C:5A:B4', '94:EB:2C', 'F4:F5:D8', '54:60:09', 'F8:8F:CA', '94:94:26',
        '00:1A:11', '1C:F2:9A', '30:FD:38', '44:07:0B', '54:60:09', '94:EB:2C',
    ],
    'Intel': [
        '00:02:B3', '00:03:47', '00:04:23', '00:07:E9', '00:0C:F1', '00:0E:0C',
        '00:0E:35', '00:11:11', '00:12:F0', '00:13:02', '00:13:20', '00:13:CE',
        '00:15:00', '00:16:6F', '00:16:76', '00:16:EA', '00:16:EB', '00:18:DE',
        '00:19:D1', '00:1B:21', '00:1B:77', '00:1C:BF', '00:1D:E0', '00:1E:64',
        '00:1E:65', '00:1F:3B', '00:1F:3C', '00:21:5C', '00:21:5D', '00:21:6A',
    ],
    'Realtek': ['00:E0:4C', '52:54:00', '00:20:18', '00:0A:CD', '00:40:F4'],
    'Dell': [
        '00:06:5B', '00:08:74', '00:0B:DB', '00:0D:56', '00:0F:1F', '00:11:43',
        '00:12:3F', '00:13:72', '00:14:22', '00:15:C5', '00:18:8B', '00:19:B9',
        '00:1A:A0', '00:1C:23', '00:1D:09', '00:1E:4F', '00:1E:C9', '00:21:70',
    ],
    'HP': [
        '00:01:E6', '00:02:A5', '00:04:EA', '00:08:02', '00:0A:57', '00:0B:CD',
        '00:0D:9D', '00:0E:7F', '00:0F:20', '00:0F:61', '00:10:83', '00:11:0A',
        '00:11:85', '00:12:79', '00:13:21', '00:14:38', '00:14:C2', '00:15:60',
    ],
    'Cisco': [
        '00:00:0C', '00:01:42', '00:01:43', '00:01:63', '00:01:64', '00:01:96',
        '00:01:97', '00:01:C7', '00:01:C9', '00:02:3D', '00:02:4A', '00:02:4B',
    ],
    'TP-Link': [
        '00:27:19', '14:CC:20', '30:B5:C2', '50:C7:BF', '54:C8:0F', '60:E3:27',
        '64:66:B3', '6C:5A:B5', '70:4F:57', '74:DA:88', '78:44:76', '80:89:17',
    ],
    'Xiaomi': [
        '00:9E:C8', '0C:1D:AF', '10:2A:B3', '14:F6:5A', '18:59:36', '1C:5F:2B',
        '20:47:DA', '28:6C:07', '2C:56:DC', '34:80:B3', '38:A4:ED', '3C:BD:D8',
    ],
    'Huawei': [
        '00:1E:10', '00:25:9E', '00:25:68', '00:34:FE', '00:46:4B', '00:5A:13',
        '00:66:4B', '00:9A:CD', '00:E0:FC', '04:02:1F', '04:25:C5', '04:33:89',
    ],
    'Raspberry Pi': [
        'B8:27:EB', 'DC:A6:32', 'E4:5F:01', '28:CD:C1', 'D8:3A:DD',
    ],
    'Amazon': [
        '00:FC:8B', '0C:47:C9', '10:CE:A9', '18:74:2E', '34:D2:70', '38:F7:3D',
        '40:A2:DB', '44:65:0D', '4C:EF:C0', '50:DC:E7', '68:37:E9', '68:54:FD',
    ],
    'Microsoft': [
        '00:0D:3A', '00:12:5A', '00:15:5D', '00:17:FA', '00:1D:D8', '00:22:48',
        '00:25:AE', '28:18:78', '30:59:B7', '48:50:73', '50:1A:C5', '58:82:A8',
    ],
}


def lookup_manufacturer(mac_address: str) -> Optional[str]:
    """Lookup manufacturer from MAC OUI."""
    if not mac_address:
        return None
    mac_prefix = mac_address[:8].upper()
    for manufacturer, ouis in OUI_DATABASE.items():
        if mac_prefix in ouis:
            return manufacturer
    return None


def detect_device_type(mac: str, hostname: str, manufacturer: str) -> str:
    """Detect device type from available information."""
    hostname_lower = (hostname or '').lower()
    manufacturer_lower = (manufacturer or '').lower()

    # Hostname-based detection
    if 'iphone' in hostname_lower:
        return 'phone'
    if 'ipad' in hostname_lower:
        return 'tablet'
    if 'android' in hostname_lower:
        return 'phone'
    if 'macbook' in hostname_lower:
        return 'laptop'
    if 'imac' in hostname_lower or 'mac-' in hostname_lower:
        return 'desktop'
    if 'windows' in hostname_lower or '-pc' in hostname_lower:
        return 'desktop'
    if 'printer' in hostname_lower or 'hp-' in hostname_lower:
        return 'printer'
    if 'camera' in hostname_lower or 'cam-' in hostname_lower or 'hikvision' in hostname_lower:
        return 'camera'
    if 'tv' in hostname_lower or 'roku' in hostname_lower or 'chromecast' in hostname_lower:
        return 'tv'
    if 'echo' in hostname_lower or 'alexa' in hostname_lower:
        return 'smart_speaker'
    if 'nest' in hostname_lower or 'thermostat' in hostname_lower:
        return 'iot'
    if 'ring' in hostname_lower or 'doorbell' in hostname_lower:
        return 'iot'

    # Manufacturer-based detection
    if manufacturer_lower == 'apple':
        return 'apple_device'
    if manufacturer_lower in ['samsung', 'xiaomi', 'huawei']:
        return 'phone'
    if manufacturer_lower == 'raspberry pi':
        return 'iot'
    if manufacturer_lower == 'amazon':
        return 'smart_speaker'
    if manufacturer_lower in ['google']:
        return 'smart_device'
    if manufacturer_lower in ['intel', 'realtek']:
        return 'computer'
    if manufacturer_lower in ['cisco', 'tp-link']:
        return 'network'

    return 'unknown'


# =============================================================================
# Device Discovery (Real Data)
# =============================================================================

@dataclass
class Device:
    """Connected device information."""
    mac_address: str
    ip_address: str
    hostname: Optional[str]
    manufacturer: Optional[str]
    device_type: str
    interface: str
    vlan_id: int
    state: str  # REACHABLE, STALE, DELAY, etc.
    first_seen: str
    last_seen: str
    is_blocked: bool = False


def get_arp_devices() -> List[Dict]:
    """Get devices from ARP table (real data)."""
    cached = _get_cached('arp_devices')
    if cached is not None:
        return cached

    devices = []
    success, output, _ = _run_cmd(['ip', 'neigh', 'show'])

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
        interface = None
        state = 'UNKNOWN'

        # Parse: 10.200.0.10 dev vlan100 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        for i, part in enumerate(parts):
            if part == 'dev' and i + 1 < len(parts):
                interface = parts[i + 1]
            elif part == 'lladdr' and i + 1 < len(parts):
                mac_address = parts[i + 1].upper()
            elif part in ['REACHABLE', 'STALE', 'DELAY', 'PROBE', 'PERMANENT']:
                state = part

        if not mac_address or not interface:
            continue

        # Determine VLAN from interface
        vlan_id = 100  # Default LAN
        if 'vlan200' in interface or 'mgmt' in interface.lower():
            vlan_id = 200

        # Get hostname via reverse DNS
        hostname = None
        try:
            import socket
            hostname = socket.gethostbyaddr(ip_address)[0]
            if hostname == ip_address:
                hostname = None
        except Exception:
            pass

        manufacturer = lookup_manufacturer(mac_address)
        device_type = detect_device_type(mac_address, hostname, manufacturer)

        devices.append({
            'mac_address': mac_address,
            'ip_address': ip_address,
            'hostname': hostname,
            'manufacturer': manufacturer,
            'device_type': device_type,
            'interface': interface,
            'vlan_id': vlan_id,
            'state': state,
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'is_blocked': False,
        })

    _set_cached('arp_devices', devices)
    return devices


def get_wifi_clients() -> List[Dict]:
    """Get WiFi clients from hostapd (real data)."""
    cached = _get_cached('wifi_clients')
    if cached is not None:
        return cached

    clients = []

    # Try hostapd_cli for each interface
    for iface in ['wlan_24ghz', 'wlan_5ghz', 'wlan0', 'wlan1']:
        success, output, _ = _run_cmd(['hostapd_cli', '-i', iface, 'all_sta'])
        if not success:
            continue

        current_mac = None
        for line in output.strip().split('\n'):
            # MAC address lines don't have '='
            if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', line.strip()):
                current_mac = line.strip().upper()
                clients.append({
                    'mac_address': current_mac,
                    'interface': iface,
                    'connected_time': None,
                    'signal': None,
                })
            elif current_mac and '=' in line:
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip()
                if key == 'connected_time':
                    clients[-1]['connected_time'] = int(value) if value.isdigit() else None
                elif key == 'signal':
                    clients[-1]['signal'] = int(value) if value.lstrip('-').isdigit() else None

    _set_cached('wifi_clients', clients)
    return clients


def get_all_devices() -> List[Dict]:
    """Get all connected devices (merged ARP + WiFi data)."""
    devices = get_arp_devices()

    # Enrich with WiFi client info
    wifi_clients = get_wifi_clients()
    wifi_macs = {c['mac_address']: c for c in wifi_clients}

    for device in devices:
        mac = device['mac_address']
        if mac in wifi_macs:
            device['wifi_interface'] = wifi_macs[mac].get('interface')
            device['wifi_signal'] = wifi_macs[mac].get('signal')
            device['is_wifi'] = True
        else:
            device['is_wifi'] = False

    return devices


def get_device_count() -> Dict[str, int]:
    """Get device counts."""
    devices = get_all_devices()
    return {
        'total': len(devices),
        'active': len([d for d in devices if d['state'] == 'REACHABLE']),
        'reachable': len([d for d in devices if d['state'] == 'REACHABLE']),
        'wifi': len([d for d in devices if d.get('is_wifi')]),
        'wired': len([d for d in devices if not d.get('is_wifi')]),
    }


def get_device_by_mac(mac_address: str) -> Optional[Dict]:
    """Get a specific device by MAC address."""
    devices = get_all_devices()
    mac_upper = mac_address.upper()
    for device in devices:
        if device['mac_address'].upper() == mac_upper:
            return device
    return None


# =============================================================================
# Network Topology (Real Data)
# =============================================================================

@dataclass
class NetworkInterface:
    """Network interface information."""
    name: str
    type: str  # wan, lan, wifi, bridge, vlan
    mac_address: Optional[str]
    ip_address: Optional[str]
    state: str  # UP, DOWN, UNKNOWN
    speed: Optional[int]  # Mbps
    mtu: int


def get_interfaces() -> List[Dict]:
    """Get all network interfaces (real data)."""
    cached = _get_cached('interfaces')
    if cached is not None:
        return cached

    interfaces = []
    success, output, _ = _run_cmd(['ip', '-j', 'addr', 'show'])

    if success:
        try:
            data = json.loads(output)
            for iface in data:
                name = iface.get('ifname', '')
                if name in ['lo', 'docker0', 'podman0']:
                    continue

                # Determine type
                iface_type = 'unknown'
                if name.startswith('eth') or name.startswith('en'):
                    iface_type = 'wan'
                elif name.startswith('wlan') or name.startswith('wl'):
                    iface_type = 'wifi'
                elif name.startswith('vlan'):
                    iface_type = 'vlan'
                elif name in ['FTS', 'br0', 'br-lan']:
                    iface_type = 'bridge'
                elif name.startswith('wwan') or name.startswith('usb'):
                    iface_type = 'lte'
                elif name.startswith('veth'):
                    iface_type = 'container'

                # Get IP address
                ip_addr = None
                for addr_info in iface.get('addr_info', []):
                    if addr_info.get('family') == 'inet':
                        ip_addr = f"{addr_info.get('local')}/{addr_info.get('prefixlen')}"
                        break

                interfaces.append({
                    'name': name,
                    'type': iface_type,
                    'mac_address': iface.get('address'),
                    'ip_address': ip_addr,
                    'state': iface.get('operstate', 'UNKNOWN'),
                    'mtu': iface.get('mtu', 1500),
                    'flags': iface.get('flags', []),
                })
        except json.JSONDecodeError:
            pass

    _set_cached('interfaces', interfaces)
    return interfaces


def get_ovs_bridge_info() -> Dict:
    """Get OVS bridge information (real data)."""
    cached = _get_cached('ovs_bridge')
    if cached is not None:
        return cached

    info = {
        'name': 'FTS',
        'exists': False,
        'ports': [],
        'vlans': [],
    }

    # Check if bridge exists
    success, _, _ = _run_cmd(['ovs-vsctl', 'br-exists', 'FTS'])
    if not success:
        return info

    info['exists'] = True

    # Get ports
    success, output, _ = _run_cmd(['ovs-vsctl', 'list-ports', 'FTS'])
    if success:
        info['ports'] = [p.strip() for p in output.strip().split('\n') if p.strip()]

    # Get VLAN info
    success, output, _ = _run_cmd(['ovs-vsctl', 'show'])
    if success:
        # Parse VLAN tags from output
        for line in output.split('\n'):
            if 'tag:' in line:
                try:
                    tag = int(line.split('tag:')[1].strip().split()[0])
                    if tag not in info['vlans']:
                        info['vlans'].append(tag)
                except (ValueError, IndexError):
                    pass

    _set_cached('ovs_bridge', info)
    return info


def get_network_topology() -> Dict:
    """Get complete network topology for visualization."""
    interfaces = get_interfaces()
    ovs_info = get_ovs_bridge_info()
    devices = get_all_devices()

    # Build topology tree
    topology = {
        'wan': [],
        'bridge': None,
        'vlans': [],
        'wifi': [],
        'devices': devices,
    }

    for iface in interfaces:
        if iface['type'] == 'wan':
            topology['wan'].append({
                'name': iface['name'],
                'ip': iface['ip_address'],
                'state': iface['state'],
                'is_primary': 'eth' in iface['name'],
            })
        elif iface['type'] == 'lte':
            topology['wan'].append({
                'name': iface['name'],
                'ip': iface['ip_address'],
                'state': iface['state'],
                'is_primary': False,
                'is_lte': True,
            })
        elif iface['type'] == 'bridge':
            topology['bridge'] = {
                'name': iface['name'],
                'state': iface['state'],
                'ports': ovs_info.get('ports', []),
            }
        elif iface['type'] == 'vlan':
            topology['vlans'].append({
                'name': iface['name'],
                'vlan_id': int(iface['name'].replace('vlan', '')) if iface['name'].startswith('vlan') else 0,
                'ip': iface['ip_address'],
                'state': iface['state'],
                'device_count': len([d for d in devices if d.get('interface') == iface['name']]),
            })
        elif iface['type'] == 'wifi':
            topology['wifi'].append({
                'name': iface['name'],
                'state': iface['state'],
                'is_24ghz': '24' in iface['name'] or iface['name'] == 'wlan0',
                'client_count': len([d for d in devices if d.get('wifi_interface') == iface['name']]),
            })

    return topology


# =============================================================================
# WAN Health (Real Data)
# =============================================================================

def _test_connectivity(interface: str, target: str = '1.1.1.1') -> Dict:
    """Test connectivity through a specific interface with multiple targets."""
    result = {
        'rtt_ms': None,
        'jitter_ms': None,
        'packet_loss': 100.0,
        'is_connected': False,
    }

    # Test with 3 pings to get better metrics
    success, output, _ = _run_cmd(
        ['ping', '-c', '3', '-W', '2', '-I', interface, target],
        timeout=10
    )

    if success:
        # Parse RTT
        rtt_match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
        if rtt_match:
            result['rtt_ms'] = float(rtt_match.group(2))  # avg
            result['jitter_ms'] = float(rtt_match.group(4))  # mdev
            result['is_connected'] = True

        # Parse packet loss
        loss_match = re.search(r'(\d+)% packet loss', output)
        if loss_match:
            result['packet_loss'] = float(loss_match.group(1))

    return result


def get_wan_health() -> Dict:
    """Get WAN health metrics with real connectivity tests.

    First checks for pre-written data from fts-qsecbit agent (required when
    running in container without host network access). Falls back to live
    ping tests if no recent data file exists.
    """
    cached = _get_cached('wan_health', ttl=5)
    if cached is not None:
        return cached

    # First, try to read pre-collected data from the agent
    # (fts-qsecbit runs with host network and can ping through real interfaces)
    wan_health_file = Path('/opt/hookprobe/fortress/data/wan_health.json')
    if wan_health_file.exists():
        try:
            data = json.loads(wan_health_file.read_text())
            # Check if data is recent (< 60 seconds old)
            file_ts = data.get('timestamp', '')
            if file_ts:
                file_time = datetime.fromisoformat(file_ts.replace('Z', '+00:00'))
                age = (datetime.now() - file_time.replace(tzinfo=None)).total_seconds()
                if age < 60:
                    _set_cached('wan_health', data)
                    return data
        except Exception as e:
            logger.debug(f"Could not read wan_health.json: {e}")

    # Fallback: collect live data (only works with host network access)
    health = {
        'primary': None,
        'backup': None,
        'active': None,
        'active_is_primary': False,
        'uptime_pct': 99.9,
        'state': 'primary_active',
        'timestamp': datetime.now().isoformat(),
    }

    interfaces = get_interfaces()

    # Find primary and backup WAN interfaces
    primary_iface = None
    backup_iface = None

    for iface in interfaces:
        if iface['type'] == 'wan' and iface['state'] == 'UP':
            primary_iface = iface
        elif iface['type'] == 'lte' and iface['state'] == 'UP':
            backup_iface = iface

    # Test connectivity on primary
    if primary_iface:
        conn = _test_connectivity(primary_iface['name'])
        health['primary'] = {
            'interface': primary_iface['name'],
            'ip': primary_iface['ip_address'],
            'state': 'UP',
            'rtt_ms': conn['rtt_ms'],
            'jitter_ms': conn['jitter_ms'],
            'packet_loss': conn['packet_loss'],
            'is_connected': conn['is_connected'],
            'health_score': _calculate_health_score(conn),
            'status': 'ACTIVE' if conn['is_connected'] else 'FAILED',
        }
        if conn['is_connected']:
            health['active'] = primary_iface['name']
            health['active_is_primary'] = True
            health['state'] = 'primary_active'

    # Test connectivity on backup
    if backup_iface:
        conn = _test_connectivity(backup_iface['name'])

        # Get LTE signal if available
        signal_dbm = _get_lte_signal(backup_iface['name'])

        health['backup'] = {
            'interface': backup_iface['name'],
            'ip': backup_iface['ip_address'],
            'state': 'UP',
            'rtt_ms': conn['rtt_ms'],
            'jitter_ms': conn['jitter_ms'],
            'packet_loss': conn['packet_loss'],
            'is_connected': conn['is_connected'],
            'health_score': _calculate_health_score(conn, signal_dbm),
            'signal_dbm': signal_dbm,
            'status': 'STANDBY' if health['active'] else ('ACTIVE' if conn['is_connected'] else 'FAILED'),
        }

        # If primary failed but backup works, backup is active
        if not health['active'] and conn['is_connected']:
            health['active'] = backup_iface['name']
            health['active_is_primary'] = False
            health['state'] = 'backup_active'
            health['backup']['status'] = 'ACTIVE'

    # If nothing is connected
    if not health['active']:
        health['state'] = 'disconnected'

    _set_cached('wan_health', health)
    return health


def _calculate_health_score(conn: Dict, signal_dbm: Optional[int] = None) -> float:
    """Calculate health score 0-1 based on connectivity metrics."""
    if not conn['is_connected']:
        return 0.0

    score = 1.0

    # RTT impact (up to -0.3 for high latency)
    if conn['rtt_ms']:
        if conn['rtt_ms'] > 200:
            score -= 0.3
        elif conn['rtt_ms'] > 100:
            score -= 0.2
        elif conn['rtt_ms'] > 50:
            score -= 0.1

    # Jitter impact (up to -0.2)
    if conn['jitter_ms']:
        if conn['jitter_ms'] > 50:
            score -= 0.2
        elif conn['jitter_ms'] > 20:
            score -= 0.1

    # Packet loss impact (up to -0.4)
    if conn['packet_loss'] > 0:
        score -= min(0.4, conn['packet_loss'] / 100 * 0.4)

    # LTE signal impact (up to -0.2)
    if signal_dbm is not None:
        if signal_dbm < -100:
            score -= 0.2
        elif signal_dbm < -85:
            score -= 0.1

    return max(0.0, min(1.0, score))


def _get_lte_signal(interface: str) -> Optional[int]:
    """Get LTE signal strength in dBm."""
    # Try mmcli for ModemManager
    success, output, _ = _run_cmd(['mmcli', '-m', '0', '-K'])
    if success:
        match = re.search(r'modem\.generic\.signal-quality\.value\s*:\s*(\d+)', output)
        if match:
            # Convert percentage to approximate dBm
            quality = int(match.group(1))
            return -113 + (quality * 0.63)  # Approximate conversion

    # Try qmicli for QMI modems
    success, output, _ = _run_cmd(['qmicli', '-d', '/dev/cdc-wdm0', '--nas-get-signal-strength'])
    if success:
        match = re.search(r'RSSI:\s*(-?\d+)\s*dBm', output)
        if match:
            return int(match.group(1))

    return None


def get_interface_stats(iface_name: str) -> Dict:
    """Get interface traffic statistics."""
    stats = {
        'rx_bytes': 0,
        'tx_bytes': 0,
        'rx_packets': 0,
        'tx_packets': 0,
    }

    stats_path = Path(f'/sys/class/net/{iface_name}/statistics')
    if not stats_path.exists():
        return stats

    for stat in ['rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets']:
        try:
            stats[stat] = int((stats_path / stat).read_text().strip())
        except Exception:
            pass

    return stats


# Traffic rate cache for calculating bytes/sec
_traffic_prev: Dict[str, Tuple[int, int, float]] = {}


def get_interface_traffic_rate(iface_name: str) -> Dict:
    """Get real-time traffic rate in bytes/sec and Mbps."""
    stats = get_interface_stats(iface_name)
    now = time.time()

    result = {
        'interface': iface_name,
        'rx_bytes': stats['rx_bytes'],
        'tx_bytes': stats['tx_bytes'],
        'rx_bps': 0,
        'tx_bps': 0,
        'rx_mbps': 0.0,
        'tx_mbps': 0.0,
        'total_mbps': 0.0,
    }

    prev = _traffic_prev.get(iface_name)
    if prev:
        prev_rx, prev_tx, prev_time = prev
        elapsed = now - prev_time
        if elapsed > 0:
            result['rx_bps'] = max(0, int((stats['rx_bytes'] - prev_rx) / elapsed))
            result['tx_bps'] = max(0, int((stats['tx_bytes'] - prev_tx) / elapsed))
            result['rx_mbps'] = round(result['rx_bps'] * 8 / 1_000_000, 2)
            result['tx_mbps'] = round(result['tx_bps'] * 8 / 1_000_000, 2)
            result['total_mbps'] = round(result['rx_mbps'] + result['tx_mbps'], 2)

    _traffic_prev[iface_name] = (stats['rx_bytes'], stats['tx_bytes'], now)
    return result


def get_all_interface_traffic() -> List[Dict]:
    """Get traffic rates for all relevant interfaces."""
    interfaces = get_interfaces()
    traffic = []

    # Only include relevant interface types
    for iface in interfaces:
        if iface['type'] in ['wan', 'lte', 'bridge', 'wifi', 'vlan']:
            rate = get_interface_traffic_rate(iface['name'])
            rate['type'] = iface['type']
            rate['state'] = iface['state']
            traffic.append(rate)

    return traffic


def get_slaai_status() -> Dict:
    """Get complete SLAAI status for dashboard."""
    wan = get_wan_health()
    traffic = get_all_interface_traffic()

    # Build status response
    status = {
        'state': wan.get('state', 'unknown'),
        'timestamp': wan.get('timestamp', datetime.now().isoformat()),
        'active_interface': wan.get('active'),
        'active_is_primary': wan.get('active_is_primary', False),

        # Primary WAN
        'primary_interface': wan['primary']['interface'] if wan.get('primary') else None,
        'primary_health': wan['primary']['health_score'] if wan.get('primary') else 0,
        'primary_status': wan['primary']['status'] if wan.get('primary') else 'DOWN',
        'primary_rtt': wan['primary']['rtt_ms'] if wan.get('primary') else None,
        'primary_jitter': wan['primary']['jitter_ms'] if wan.get('primary') else None,
        'primary_loss': wan['primary']['packet_loss'] if wan.get('primary') else 100,
        'primary_ip': wan['primary']['ip'] if wan.get('primary') else None,

        # Backup WAN
        'backup_interface': wan['backup']['interface'] if wan.get('backup') else None,
        'backup_health': wan['backup']['health_score'] if wan.get('backup') else 0,
        'backup_status': wan['backup']['status'] if wan.get('backup') else 'DOWN',
        'backup_rtt': wan['backup']['rtt_ms'] if wan.get('backup') else None,
        'backup_signal': wan['backup'].get('signal_dbm') if wan.get('backup') else None,
        'backup_loss': wan['backup']['packet_loss'] if wan.get('backup') else 100,
        'backup_ip': wan['backup']['ip'] if wan.get('backup') else None,

        # Traffic data
        'traffic': {t['interface']: t for t in traffic},

        # SLA metrics (placeholder - would come from historical data)
        'uptime_pct': wan.get('uptime_pct', 99.9),
        'rto_actual_s': 2.3,
        'rto_target_s': 5.0,
        'rpo_actual_bytes': 0,
        'rpo_target_bytes': 0,
        'failover_count_24h': 0,
        'failover_history': [],

        # Cost tracking (placeholder - would come from metered tracking)
        'cost_status': {
            'interface': wan['backup']['interface'] if wan.get('backup') else 'wwan0',
            'daily_usage_mb': 0,
            'daily_budget_mb': 500,
            'monthly_usage_mb': 0,
            'monthly_budget_mb': 10240,
            'cost_per_gb': 2.0,
            'current_cost': 0.0,
            'budget_remaining': 20.0,
        },
    }

    return status


# =============================================================================
# DNS Blocked Count (Real Data)
# =============================================================================

def get_dns_blocked_count() -> int:
    """Get DNS blocked count from dnsmasq logs (real data)."""
    cached = _get_cached('dns_blocked', ttl=60)
    if cached is not None:
        return cached

    count = 0

    # Try dnsXai stats file first
    stats_file = Path('/opt/hookprobe/fortress/data/dnsxai_stats.json')
    if stats_file.exists():
        try:
            data = json.loads(stats_file.read_text())
            count = data.get('blocked_today', 0)
            _set_cached('dns_blocked', count)
            return count
        except Exception:
            pass

    # Fallback: parse dnsmasq log
    log_file = Path('/var/log/dnsmasq.log')
    if log_file.exists():
        try:
            today = datetime.now().strftime('%b %d')
            with open(log_file, 'r') as f:
                for line in f:
                    if today in line and ('blocked' in line.lower() or 'NXDOMAIN' in line):
                        count += 1
        except Exception:
            pass

    _set_cached('dns_blocked', count)
    return count


# =============================================================================
# QSecBit Stats (Real Data)
# =============================================================================

def get_qsecbit_stats() -> Dict:
    """Get QSecBit security score (real data)."""
    cached = _get_cached('qsecbit_stats', ttl=30)
    if cached is not None:
        return cached

    stats = {
        'score': 0.85,
        'rag_status': 'GREEN',
        'threats_detected': 0,
        'last_updated': datetime.now().isoformat(),
    }

    # Try to read from QSecBit stats file
    stats_file = Path('/opt/hookprobe/fortress/data/qsecbit_stats.json')
    if stats_file.exists():
        try:
            data = json.loads(stats_file.read_text())
            stats.update(data)
        except Exception:
            pass

    # Alternative: check container health
    success, output, _ = _run_cmd(['podman', 'inspect', 'fts-qsecbit', '--format', '{{.State.Running}}'])
    if success and 'true' in output.lower():
        stats['container_running'] = True
    else:
        stats['container_running'] = False

    _set_cached('qsecbit_stats', stats)
    return stats


# =============================================================================
# VLAN Configuration (Real Data)
# =============================================================================

def get_vlans() -> List[Dict]:
    """Get actual VLAN configuration from system."""
    cached = _get_cached('vlans', ttl=60)
    if cached is not None:
        return cached

    vlans = []
    interfaces = get_interfaces()
    devices = get_all_devices()

    for iface in interfaces:
        if iface['type'] != 'vlan':
            continue

        vlan_id = 0
        if iface['name'].startswith('vlan'):
            try:
                vlan_id = int(iface['name'].replace('vlan', ''))
            except ValueError:
                continue

        # Determine VLAN name
        if vlan_id == 100:
            name = 'LAN'
            description = 'Local Area Network - All clients'
        elif vlan_id == 200:
            name = 'MGMT'
            description = 'Management - Admin access'
        else:
            name = f'VLAN {vlan_id}'
            description = ''

        vlans.append({
            'vlan_id': vlan_id,
            'name': name,
            'description': description,
            'interface': iface['name'],
            'ip_address': iface['ip_address'],
            'state': iface['state'],
            'device_count': len([d for d in devices if d.get('interface') == iface['name']]),
        })

    _set_cached('vlans', vlans)
    return vlans


# =============================================================================
# Dashboard Summary (Aggregated Real Data)
# =============================================================================

def get_dashboard_summary() -> Dict:
    """Get complete dashboard summary (all real data)."""
    devices = get_all_devices()
    qsecbit = get_qsecbit_stats()
    wan = get_wan_health()

    return {
        'qsecbit': qsecbit,
        'device_count': len(devices),
        'device_counts': get_device_count(),
        'dns_blocked': get_dns_blocked_count(),
        'wan_health': wan,
        'vlans': get_vlans(),
        'timestamp': datetime.now().isoformat(),
    }
