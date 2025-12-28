"""
Fortress Dashboard Views
Main overview page with widgets and stats - Uses real system data.
"""

import json
import time
from pathlib import Path
from datetime import datetime

from flask import render_template, jsonify
from flask_login import login_required

from . import dashboard_bp

# Import system data module (provides real data without DB dependency)
try:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
    from system_data import (
        get_all_devices,
        get_device_count,
        get_qsecbit_stats,
        get_dns_blocked_count,
        get_wan_health,
        get_vlans,
        get_network_topology,
        get_dashboard_summary,
    )
    SYSTEM_DATA_AVAILABLE = True
except ImportError as e:
    SYSTEM_DATA_AVAILABLE = False
    import logging
    logging.warning(f"system_data module not available: {e}")


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


def get_recent_devices():
    """Get list of recently connected devices."""
    if not SYSTEM_DATA_AVAILABLE:
        return []

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


@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Main dashboard page - uses real system data."""
    if SYSTEM_DATA_AVAILABLE:
        stats = get_qsecbit_stats()
        device_count = len(get_all_devices())
        wan_health = get_wan_health()
        vlans = get_vlans()
    else:
        # Minimal fallback - no demo data
        stats = {'score': 0, 'rag_status': 'UNKNOWN', 'threats_detected': 0}
        device_count = 0
        wan_health = {'primary': None, 'backup': None, 'active': None}
        vlans = []

    tunnel = get_tunnel_status()

    return render_template('dashboard/index.html',
                           qsecbit_score=stats.get('score', 0),
                           qsecbit_status=stats.get('rag_status', 'GREEN'),
                           device_count=device_count,
                           threats_blocked=stats.get('threats_detected', 0),
                           dns_blocked=get_dns_blocked_count() if SYSTEM_DATA_AVAILABLE else 0,
                           recent_devices=get_recent_devices(),
                           wan_health=wan_health,
                           vlans=vlans,
                           tunnel_status=tunnel,
                           system_data_available=SYSTEM_DATA_AVAILABLE)


@dashboard_bp.route('/api/dashboard/stats')
@login_required
def api_stats():
    """API endpoint for dashboard stats (real data)."""
    if SYSTEM_DATA_AVAILABLE:
        summary = get_dashboard_summary()
        return jsonify({
            'success': True,
            'qsecbit': summary['qsecbit'],
            'devices': summary['device_count'],
            'device_counts': summary['device_counts'],
            'threats': summary['qsecbit'].get('threats_detected', 0),
            'dns_blocked': summary['dns_blocked'],
            'wan_health': summary['wan_health'],
            'vlans': summary['vlans'],
            'timestamp': summary['timestamp'],
        })
    else:
        return jsonify({
            'success': False,
            'error': 'System data module not available',
            'timestamp': datetime.now().isoformat(),
        })


@dashboard_bp.route('/api/dashboard/devices')
@login_required
def api_devices():
    """API endpoint for device list (real data)."""
    if SYSTEM_DATA_AVAILABLE:
        devices = get_all_devices()
        return jsonify({
            'success': True,
            'devices': devices,
            'count': len(devices),
            'timestamp': datetime.now().isoformat(),
        })
    else:
        return jsonify({
            'success': False,
            'error': 'System data module not available',
            'devices': [],
        })


@dashboard_bp.route('/api/dashboard/topology')
@login_required
def api_topology():
    """API endpoint for network topology (real data)."""
    if SYSTEM_DATA_AVAILABLE:
        topology = get_network_topology()
        return jsonify({
            'success': True,
            'topology': topology,
            'timestamp': datetime.now().isoformat(),
        })
    else:
        return jsonify({
            'success': False,
            'error': 'System data module not available',
        })


@dashboard_bp.route('/api/dashboard/wan')
@login_required
def api_wan():
    """API endpoint for WAN health (real data)."""
    if SYSTEM_DATA_AVAILABLE:
        wan = get_wan_health()
        return jsonify({
            'success': True,
            'wan': wan,
            'timestamp': datetime.now().isoformat(),
        })
    else:
        return jsonify({
            'success': False,
            'error': 'System data module not available',
        })


@dashboard_bp.route('/api/dashboard/refresh')
@login_required
def api_refresh():
    """Force refresh all cached data."""
    if SYSTEM_DATA_AVAILABLE:
        # Clear the cache in system_data module
        from system_data import _cache
        _cache.clear()
        return jsonify({'success': True, 'message': 'Cache cleared'})
    return jsonify({'success': False, 'message': 'System data not available'})
