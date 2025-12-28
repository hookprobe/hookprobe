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
