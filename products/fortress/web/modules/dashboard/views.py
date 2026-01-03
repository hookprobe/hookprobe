"""
Fortress Dashboard Views
Main overview page with widgets and stats - Uses real system data.
"""

import json
import time
import logging
from pathlib import Path
from datetime import datetime

from flask import render_template, jsonify
from flask_login import login_required

from . import dashboard_bp

logger = logging.getLogger(__name__)

# Data directory - shared volume from fts-qsecbit agent
DATA_DIR = Path('/opt/hookprobe/fortress/data')

# Cache for local data
_local_cache = {}
CACHE_TIMEOUT = 30


def _get_cached(key, ttl=CACHE_TIMEOUT):
    """Get cached value if not expired."""
    if key in _local_cache:
        value, timestamp = _local_cache[key]
        if time.time() - timestamp < ttl:
            return value
    return None


def _set_cached(key, value):
    """Set cached value."""
    _local_cache[key] = (value, time.time())


def get_tunnel_status():
    """Get Cloudflare Tunnel status."""
    config_file = Path('/opt/hookprobe/fortress/tunnel/config.json')
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            return {
                'state': 'configured',
                'hostname': config.get('hostname'),
                'cloudflared_version': None
            }
        except Exception:
            pass
    return {'state': 'unconfigured', 'hostname': None, 'cloudflared_version': None}


def get_qsecbit_stats():
    """Load QSecBit stats from file (written by fts-qsecbit agent)."""
    cached = _get_cached('qsecbit_stats', 10)
    if cached is not None:
        return cached

    stats_file = DATA_DIR / 'qsecbit_stats.json'
    try:
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                result = json.load(f)
                _set_cached('qsecbit_stats', result)
                return result
    except Exception as e:
        logger.debug(f"Could not read qsecbit_stats.json: {e}")

    # Default when no data available
    return {'score': 0, 'rag_status': 'UNKNOWN', 'threats_detected': 0, 'vlan_violations': 0}


def get_device_count():
    """Get count of connected devices from ARP table or device manager data."""
    cached = _get_cached('device_count', CACHE_TIMEOUT)
    if cached is not None:
        return cached

    # Try reading from device manager data file
    devices_file = DATA_DIR / 'devices.json'
    try:
        if devices_file.exists():
            with open(devices_file, 'r') as f:
                devices = json.load(f)
                count = len(devices) if isinstance(devices, list) else devices.get('total', 0)
                _set_cached('device_count', count)
                return count
    except Exception:
        pass

    # Fallback: count from ARP neighbor table (works in container with host network)
    try:
        import subprocess
        result = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            count = len([l for l in result.stdout.strip().split('\n') if l and 'FAILED' not in l])
            _set_cached('device_count', count)
            return count
    except Exception:
        pass

    return 0


def get_all_devices():
    """Get list of all connected devices."""
    devices_file = DATA_DIR / 'devices.json'
    try:
        if devices_file.exists():
            with open(devices_file, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
    except Exception:
        pass

    # Fallback: build from ARP table
    try:
        import subprocess
        result = subprocess.run(['ip', '-j', 'neigh', 'show'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            neighbors = json.loads(result.stdout)
            devices = []
            for n in neighbors:
                if n.get('state') and n['state'] != 'FAILED':
                    devices.append({
                        'ip_address': n.get('dst', ''),
                        'mac_address': n.get('lladdr', ''),
                        'state': n.get('state', 'UNKNOWN'),
                        'device_type': 'unknown',
                        'hostname': None,
                        'manufacturer': None,
                    })
            return devices
    except Exception:
        pass

    return []


def get_dns_blocked_count():
    """Get count of DNS queries blocked today from dnsXai."""
    cached = _get_cached('dns_blocked', CACHE_TIMEOUT)
    if cached is not None:
        return cached

    # Try to read from dnsXai stats file
    stats_file = DATA_DIR / 'dnsxai_stats.json'
    try:
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                data = json.load(f)
                result = data.get('blocked_today', 0)
                _set_cached('dns_blocked', result)
                return result
    except Exception:
        pass

    return 0


def get_vlan_count():
    """Get count of configured VLANs."""
    cached = _get_cached('vlan_count', CACHE_TIMEOUT * 2)
    if cached is not None:
        return cached

    # Try reading from config or data file
    vlans_file = DATA_DIR / 'vlans.json'
    try:
        if vlans_file.exists():
            with open(vlans_file, 'r') as f:
                vlans = json.load(f)
                count = len(vlans) if isinstance(vlans, list) else 0
                _set_cached('vlan_count', count)
                return count
    except Exception:
        pass

    # Default: assume standard VLAN setup
    return 5


def get_sdn_autopilot_summary():
    """Get SDN AutoPilot summary stats from autopilot database."""
    cached = _get_cached('sdn_autopilot_summary', CACHE_TIMEOUT)
    if cached is not None:
        return cached

    result = {
        'total_devices': 0,
        'online_devices': 0,
        'policies_applied': 0,
        'quarantined': 0,
        'internet_only': 0,
        'full_access': 0,
        'autopilot_enabled': False
    }

    # Try reading from autopilot database
    autopilot_db = Path('/var/lib/hookprobe/autopilot.db')
    try:
        if autopilot_db.exists():
            import sqlite3
            conn = sqlite3.connect(str(autopilot_db), timeout=2)
            cursor = conn.cursor()

            # Total devices
            cursor.execute("SELECT COUNT(*) FROM device_identity")
            result['total_devices'] = cursor.fetchone()[0]

            # Online devices (seen in last 5 minutes)
            cursor.execute("""
                SELECT COUNT(*) FROM device_identity
                WHERE datetime(last_seen) > datetime('now', '-5 minutes')
            """)
            result['online_devices'] = cursor.fetchone()[0]

            # Policy counts
            cursor.execute("""
                SELECT policy, COUNT(*) FROM device_identity
                WHERE policy IS NOT NULL AND policy != ''
                GROUP BY policy
            """)
            for policy, count in cursor.fetchall():
                if policy in ('quarantine', 'isolated'):
                    result['quarantined'] += count
                elif policy == 'internet_only':
                    result['internet_only'] += count
                elif policy in ('full_access', 'normal', 'smart_home'):
                    result['full_access'] += count
                result['policies_applied'] += count

            result['autopilot_enabled'] = True
            conn.close()
    except Exception as e:
        logger.debug(f"Could not read autopilot.db: {e}")

    _set_cached('sdn_autopilot_summary', result)
    return result


def get_dnsxai_summary():
    """Get dnsXai summary stats."""
    cached = _get_cached('dnsxai_summary', CACHE_TIMEOUT)
    if cached is not None:
        return cached

    result = {
        'enabled': False,
        'blocked_today': 0,
        'blocked_total': 0,
        'queries_today': 0,
        'block_rate': 0,
        'top_blocked_category': 'N/A',
        'protection_level': 'N/A'
    }

    # Try reading from dnsXai stats file
    stats_file = DATA_DIR / 'dnsxai_stats.json'
    try:
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                data = json.load(f)
                result['enabled'] = True
                result['blocked_today'] = data.get('blocked_today', 0)
                result['blocked_total'] = data.get('blocked_total', 0)
                result['queries_today'] = data.get('queries_today', 0)
                result['top_blocked_category'] = data.get('top_category', 'Ads & Trackers')
                result['protection_level'] = data.get('protection_level', 'Standard')

                # Calculate block rate
                if result['queries_today'] > 0:
                    result['block_rate'] = round(
                        (result['blocked_today'] / result['queries_today']) * 100, 1
                    )
    except Exception as e:
        logger.debug(f"Could not read dnsxai_stats.json: {e}")

    _set_cached('dnsxai_summary', result)
    return result


def get_wan_stats():
    """Get WAN interface statistics from agent data."""
    cached = _get_cached('wan_stats', 10)
    if cached is not None:
        return cached

    result = {
        'primary_health': 0,
        'backup_health': 0,
        'inbound': '0 B',
        'outbound': '0 B',
        'status': 'unknown'
    }

    # Read WAN health from agent data file
    wan_file = DATA_DIR / 'wan_health.json'
    try:
        if wan_file.exists():
            with open(wan_file, 'r') as f:
                data = json.load(f)
                primary = data.get('primary', {})
                backup = data.get('backup', {})
                result['primary_health'] = int((primary.get('health_score', 0)) * 100)
                result['backup_health'] = int((backup.get('health_score', 0)) * 100)
                result['status'] = data.get('state', 'unknown')
    except Exception:
        pass

    # Read traffic from interface_traffic.json
    traffic_file = DATA_DIR / 'interface_traffic.json'
    try:
        if traffic_file.exists():
            with open(traffic_file, 'r') as f:
                data = json.load(f)
                interfaces = data.get('interfaces', [])
                for iface in interfaces:
                    if iface.get('type') == 'wan':
                        rx = iface.get('rx_bps', 0)
                        tx = iface.get('tx_bps', 0)
                        result['inbound'] = _format_rate(rx)
                        result['outbound'] = _format_rate(tx)
                        break
    except Exception:
        pass

    _set_cached('wan_stats', result)
    return result


def _format_rate(bytes_per_sec):
    """Format bytes/sec as human readable rate."""
    if bytes_per_sec > 1e9:
        return f'{bytes_per_sec / 1e9:.1f} GB/s'
    if bytes_per_sec > 1e6:
        return f'{bytes_per_sec / 1e6:.1f} MB/s'
    if bytes_per_sec > 1e3:
        return f'{bytes_per_sec / 1e3:.1f} KB/s'
    return f'{bytes_per_sec:.0f} B/s'


def get_recent_threats():
    """Get list of recent threats from QSecBit."""
    cached = _get_cached('recent_threats', CACHE_TIMEOUT)
    if cached is not None:
        return cached

    # Try qsecbit_stats.json first (has recent_threats field)
    stats_file = DATA_DIR / 'qsecbit_stats.json'
    try:
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                data = json.load(f)
                threats = data.get('recent_threats', [])[:5]
                _set_cached('recent_threats', threats)
                return threats
    except Exception:
        pass

    # Try dedicated threats file
    threats_file = DATA_DIR / 'recent_threats.json'
    try:
        if threats_file.exists():
            with open(threats_file, 'r') as f:
                result = json.load(f)[:5]
                _set_cached('recent_threats', result)
                return result
    except Exception:
        pass

    return []


def get_recent_devices():
    """Get list of recently connected devices."""
    devices = get_all_devices()

    # Sort by state (REACHABLE first) and take top 5
    devices.sort(key=lambda x: (0 if x.get('state') == 'REACHABLE' else 1, x.get('last_seen', '')), reverse=True)

    recent = []
    for d in devices[:5]:
        vlan_id = d.get('vlan_id', 100)
        vlan_names = {100: 'LAN', 200: 'MGMT'}

        # Determine icon based on device type
        device_type = d.get('device_type', 'unknown')
        icon = 'laptop'
        if device_type in ['phone', 'apple_device']:
            icon = 'mobile-alt'
        elif device_type == 'tablet':
            icon = 'tablet-alt'
        elif device_type in ['tv', 'smart_speaker']:
            icon = 'tv'
        elif device_type == 'printer':
            icon = 'print'
        elif device_type in ['camera', 'iot']:
            icon = 'video'
        elif device_type == 'desktop':
            icon = 'desktop'

        recent.append({
            'name': d.get('hostname') or d.get('manufacturer') or 'Unknown Device',
            'ip': d.get('ip_address', ''),
            'mac': d.get('mac_address', ''),
            'vlan': vlan_names.get(vlan_id, f'VLAN {vlan_id}'),
            'state': d.get('state', 'UNKNOWN'),
            'device_type': device_type,
            'manufacturer': d.get('manufacturer'),
            'icon': icon,
            'is_wifi': d.get('is_wifi', False),
            'time': _format_time_ago(d.get('last_seen')),
        })

    return recent


def _format_time_ago(timestamp):
    """Format timestamp as relative time."""
    if not timestamp:
        return 'Unknown'
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = timestamp
        delta = datetime.now() - dt.replace(tzinfo=None)
        if delta.seconds < 60:
            return 'Just now'
        elif delta.seconds < 3600:
            return f'{delta.seconds // 60} min ago'
        elif delta.seconds < 86400:
            return f'{delta.seconds // 3600} hours ago'
        else:
            return f'{delta.days} days ago'
    except Exception:
        return 'Just now'


def _check_data_available():
    """Check if data files from agent are available."""
    qsecbit_file = DATA_DIR / 'qsecbit_stats.json'
    return qsecbit_file.exists()


@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Main dashboard page - uses real system data from agent."""
    data_available = _check_data_available()

    stats = get_qsecbit_stats()
    device_count = get_device_count()
    wan = get_wan_stats()
    tunnel = get_tunnel_status()
    sdn_summary = get_sdn_autopilot_summary()
    dnsxai_summary = get_dnsxai_summary()

    return render_template('dashboard/index.html',
                           qsecbit_score=stats.get('score', 0),
                           qsecbit_status=stats.get('rag_status', 'GREEN'),
                           device_count=device_count,
                           threats_blocked=stats.get('threats_detected', 0),
                           dns_blocked=get_dns_blocked_count(),
                           recent_devices=get_recent_devices(),
                           recent_threats=get_recent_threats(),
                           tunnel_status=tunnel,
                           vlan_count=get_vlan_count(),
                           wan_backup_health=wan.get('backup_health', 0),
                           wan_inbound=wan.get('inbound', '0 B/s'),
                           wan_outbound=wan.get('outbound', '0 B/s'),
                           wan_status=wan.get('status', 'unknown'),
                           sdn_summary=sdn_summary,
                           dnsxai_summary=dnsxai_summary,
                           system_data_available=data_available)


@dashboard_bp.route('/api/dashboard/stats')
@login_required
def api_stats():
    """API endpoint for dashboard stats with caching."""
    stats = get_qsecbit_stats()
    tunnel = get_tunnel_status()
    wan = get_wan_stats()

    return jsonify({
        'qsecbit': {
            'score': stats.get('score', 0),
            'status': stats.get('rag_status', 'GREEN'),
            'components': stats.get('components', {})
        },
        'device_count': get_device_count(),
        'threats_blocked': stats.get('threats_detected', 0),
        'dns_blocked': get_dns_blocked_count(),
        'tunnel': tunnel,
        'vlan_count': get_vlan_count(),
        'wan_status': wan.get('status', 'unknown'),
        'wan_primary_health': wan.get('primary_health', 0),
        'wan_backup_health': wan.get('backup_health', 0),
        'wan_inbound': wan.get('inbound', '0 B/s'),
        'wan_outbound': wan.get('outbound', '0 B/s'),
        'notification_count': len(get_recent_threats()),
        'data_available': _check_data_available(),
        'timestamp': datetime.now().isoformat()
    })


@dashboard_bp.route('/api/dashboard/refresh')
@login_required
def api_refresh():
    """Force refresh all cached data."""
    global _local_cache
    _local_cache.clear()
    return jsonify({'success': True, 'message': 'Cache cleared'})


def get_network_interfaces():
    """Get all network interfaces with their status."""
    interfaces = []
    try:
        import subprocess
        # Get interface list
        result = subprocess.run(['ip', '-j', 'link', 'show'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            links = json.loads(result.stdout)
            for link in links:
                name = link.get('ifname', '')
                # Skip loopback and virtual interfaces we don't care about
                if name in ('lo', 'podman0', 'veth*') or name.startswith('veth'):
                    continue

                state = link.get('operstate', 'UNKNOWN')
                interfaces.append({
                    'name': name,
                    'state': state,
                    'mac': link.get('address', ''),
                    'type': _classify_interface_type(name)
                })
    except Exception as e:
        logger.debug(f"Could not get interfaces: {e}")

    return interfaces


def _classify_interface_type(name):
    """Classify interface type based on name."""
    if name.startswith(('eth', 'enp', 'eno', 'ens')):
        return 'wan' if '0' in name or '1' in name else 'lan'
    elif name.startswith('wwan') or name.startswith('ww'):
        return 'lte'
    elif name.startswith('wlan') or name.startswith('wl'):
        return 'wifi'
    elif name.startswith('vlan'):
        return 'vlan'
    elif name in ('FTS', 'br0', 'ovs-system'):
        return 'bridge'
    return 'other'


def get_topology_data():
    """Build network topology data for D3.js visualization."""
    # Get interfaces
    interfaces = get_network_interfaces()

    # Get devices from autopilot or ARP
    devices = get_all_devices()

    # Get SDN summary for policy counts
    sdn = get_sdn_autopilot_summary()

    # Build nodes and links for D3
    nodes = []
    links = []

    # Add WAN interfaces
    wan_nodes = []
    for iface in interfaces:
        if iface['type'] in ('wan', 'lte'):
            node_id = f"wan_{iface['name']}"
            wan_nodes.append(node_id)
            nodes.append({
                'id': node_id,
                'type': 'wan',
                'subtype': iface['type'],
                'label': iface['name'].upper(),
                'status': 'online' if iface['state'] == 'UP' else 'offline',
                'icon': 'globe' if iface['type'] == 'wan' else 'signal'
            })

    # Add FTS Bridge (central hub)
    bridge_id = 'bridge_fts'
    nodes.append({
        'id': bridge_id,
        'type': 'bridge',
        'label': 'FTS Bridge',
        'status': 'online',
        'icon': 'network-wired'
    })

    # Link WANs to bridge
    for wan_id in wan_nodes:
        links.append({
            'source': wan_id,
            'target': bridge_id,
            'type': 'wan_link'
        })

    # Define policies
    policies = [
        {'id': 'policy_quarantine', 'name': 'quarantine', 'label': 'Quarantine', 'color': '#dc3545', 'icon': 'ban'},
        {'id': 'policy_internet_only', 'name': 'internet_only', 'label': 'Internet Only', 'color': '#17a2b8', 'icon': 'globe'},
        {'id': 'policy_lan_only', 'name': 'lan_only', 'label': 'LAN Only', 'color': '#ffc107', 'icon': 'home'},
        {'id': 'policy_normal', 'name': 'normal', 'label': 'Normal', 'color': '#28a745', 'icon': 'check-circle'},
        {'id': 'policy_full_access', 'name': 'full_access', 'label': 'Full Access', 'color': '#007bff', 'icon': 'shield-alt'},
    ]

    # Add policy nodes
    for policy in policies:
        nodes.append({
            'id': policy['id'],
            'type': 'policy',
            'name': policy['name'],
            'label': policy['label'],
            'color': policy['color'],
            'icon': policy['icon'],
            'device_count': 0
        })
        # Link policy to bridge
        links.append({
            'source': bridge_id,
            'target': policy['id'],
            'type': 'policy_link'
        })

    # Add VLANs
    vlans = [
        {'id': 'vlan_100', 'vlan_id': 100, 'label': 'VLAN 100 (LAN)', 'color': '#6f42c1'},
        {'id': 'vlan_200', 'vlan_id': 200, 'label': 'VLAN 200 (MGMT)', 'color': '#fd7e14'},
    ]

    for vlan in vlans:
        nodes.append({
            'id': vlan['id'],
            'type': 'vlan',
            'vlan_id': vlan['vlan_id'],
            'label': vlan['label'],
            'color': vlan['color'],
            'icon': 'layer-group'
        })

    # Add devices and link them to policies
    policy_counts = {p['name']: 0 for p in policies}

    for i, device in enumerate(devices):
        mac = device.get('mac_address', f'unknown_{i}')
        device_id = f"device_{mac.replace(':', '_')}"
        policy = device.get('policy', 'normal')
        vlan_id = device.get('vlan_id', 100)

        # Determine device icon
        device_type = device.get('device_type', 'unknown')
        icon = 'laptop'
        if device_type in ['phone', 'apple_device', 'mobile']:
            icon = 'mobile-alt'
        elif device_type == 'tablet':
            icon = 'tablet-alt'
        elif device_type in ['tv', 'smart_tv']:
            icon = 'tv'
        elif device_type == 'printer':
            icon = 'print'
        elif device_type in ['camera', 'iot', 'smart_home']:
            icon = 'video'
        elif device_type == 'desktop':
            icon = 'desktop'
        elif device_type == 'server':
            icon = 'server'
        elif device_type == 'gaming':
            icon = 'gamepad'

        nodes.append({
            'id': device_id,
            'type': 'device',
            'label': device.get('hostname') or device.get('manufacturer') or 'Unknown',
            'mac': mac,
            'ip': device.get('ip_address', ''),
            'policy': policy,
            'vlan_id': vlan_id,
            'device_type': device_type,
            'manufacturer': device.get('manufacturer'),
            'status': 'online' if device.get('state') in ['REACHABLE', 'STALE'] else 'offline',
            'icon': icon,
            'is_wifi': device.get('is_wifi', False)
        })

        # Link device to its policy
        policy_id = f"policy_{policy}"
        if policy in policy_counts:
            policy_counts[policy] += 1
        links.append({
            'source': policy_id,
            'target': device_id,
            'type': 'device_link'
        })

    # Update policy device counts
    for node in nodes:
        if node['type'] == 'policy' and node.get('name') in policy_counts:
            node['device_count'] = policy_counts[node['name']]

    return {
        'nodes': nodes,
        'links': links,
        'stats': {
            'total_devices': len(devices),
            'wan_count': len(wan_nodes),
            'policy_counts': policy_counts
        }
    }


@dashboard_bp.route('/api/dashboard/topology')
@login_required
def api_topology():
    """Get network topology data for D3.js visualization."""
    return jsonify(get_topology_data())


@dashboard_bp.route('/api/dashboard/device/<mac>/policy', methods=['PATCH'])
@login_required
def api_update_device_policy(mac):
    """Update device policy via drag-and-drop."""
    from flask import request

    data = request.get_json()
    new_policy = data.get('policy')

    if not new_policy:
        return jsonify({'success': False, 'error': 'Policy required'}), 400

    valid_policies = ['quarantine', 'internet_only', 'lan_only', 'normal', 'full_access']
    if new_policy not in valid_policies:
        return jsonify({'success': False, 'error': f'Invalid policy: {new_policy}'}), 400

    # Update in autopilot database
    autopilot_db = Path('/var/lib/hookprobe/autopilot.db')
    try:
        if autopilot_db.exists():
            import sqlite3
            conn = sqlite3.connect(str(autopilot_db), timeout=5)
            cursor = conn.cursor()

            # Normalize MAC address
            mac_normalized = mac.lower().replace('-', ':')

            cursor.execute("""
                UPDATE device_identity SET policy = ?, updated_at = datetime('now')
                WHERE LOWER(mac_address) = ?
            """, (new_policy, mac_normalized))

            if cursor.rowcount == 0:
                conn.close()
                return jsonify({'success': False, 'error': 'Device not found'}), 404

            conn.commit()
            conn.close()

            # Clear cache to reflect change
            _local_cache.clear()

            # TODO: Trigger OpenFlow rule update via network-filter-manager.sh

            return jsonify({'success': True, 'message': f'Policy updated to {new_policy}'})
    except Exception as e:
        logger.error(f"Failed to update device policy: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

    return jsonify({'success': False, 'error': 'Database not available'}), 500
