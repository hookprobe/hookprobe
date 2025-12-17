"""
Fortress Dashboard Views
Main overview page with widgets and stats - Optimized for performance.
"""

import json
import os
import time
from pathlib import Path
from datetime import datetime, timedelta
from functools import lru_cache

from flask import render_template, jsonify
from flask_login import login_required

from . import dashboard_bp

# Cache timeouts (seconds)
CACHE_TIMEOUT = 30
_cache = {}


def _get_cached(key: str, timeout: int = CACHE_TIMEOUT):
    """Get cached value if not expired."""
    if key in _cache:
        value, timestamp = _cache[key]
        if time.time() - timestamp < timeout:
            return value
    return None


def _set_cached(key: str, value):
    """Set cached value with timestamp."""
    _cache[key] = (value, time.time())


def get_tunnel_status():
    """Get Cloudflare Tunnel status (cached)."""
    cached = _get_cached('tunnel_status', 60)
    if cached is not None:
        return cached

    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
        from cloudflare_tunnel import get_tunnel_status as _get_tunnel_status
        result = _get_tunnel_status()
        _set_cached('tunnel_status', result)
        return result
    except ImportError:
        pass

    config_file = Path('/opt/hookprobe/fortress/tunnel/config.json')
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            result = {
                'state': 'configured',
                'hostname': config.get('hostname'),
                'cloudflared_version': None
            }
            _set_cached('tunnel_status', result)
            return result
        except Exception:
            pass

    result = {'state': 'unconfigured', 'hostname': None, 'cloudflared_version': None}
    _set_cached('tunnel_status', result)
    return result


def get_qsecbit_stats():
    """Load QSecBit stats from file (cached)."""
    cached = _get_cached('qsecbit_stats', 10)
    if cached is not None:
        return cached

    stats_file = Path('/opt/hookprobe/fortress/data/qsecbit_stats.json')
    try:
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                result = json.load(f)
                _set_cached('qsecbit_stats', result)
                return result
    except Exception:
        pass

    result = {'score': 0.85, 'rag_status': 'GREEN', 'threats_detected': 0, 'vlan_violations': 0}
    _set_cached('qsecbit_stats', result)
    return result


def get_device_count():
    """Get count of connected devices from device manager."""
    cached = _get_cached('device_count', CACHE_TIMEOUT)
    if cached is not None:
        return cached

    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
        from device_manager import get_device_manager
        dm = get_device_manager()
        counts = dm.get_device_count()
        result = counts.get('total', 0)
        _set_cached('device_count', result)
        return result
    except Exception:
        pass

    # Fallback: count from ARP table
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


def get_dns_blocked_count():
    """Get count of DNS queries blocked today from dnsXai."""
    cached = _get_cached('dns_blocked', CACHE_TIMEOUT)
    if cached is not None:
        return cached

    # Try to read from dnsXai stats file
    stats_file = Path('/opt/hookprobe/fortress/data/dnsxai_stats.json')
    try:
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                data = json.load(f)
                result = data.get('blocked_today', 0)
                _set_cached('dns_blocked', result)
                return result
    except Exception:
        pass

    # Fallback: parse dnsmasq log for blocked queries
    try:
        log_file = Path('/var/log/dnsmasq.log')
        if log_file.exists():
            today = datetime.now().strftime('%b %d')
            count = 0
            with open(log_file, 'r') as f:
                for line in f:
                    if today in line and ('blocked' in line.lower() or 'NXDOMAIN' in line):
                        count += 1
            _set_cached('dns_blocked', count)
            return count
    except Exception:
        pass

    return 0


def get_recent_threats():
    """Get list of recent threats from QSecBit."""
    cached = _get_cached('recent_threats', CACHE_TIMEOUT)
    if cached is not None:
        return cached

    threats_file = Path('/opt/hookprobe/fortress/data/recent_threats.json')
    try:
        if threats_file.exists():
            with open(threats_file, 'r') as f:
                result = json.load(f)[:5]  # Limit to 5 recent
                _set_cached('recent_threats', result)
                return result
    except Exception:
        pass

    return []


def get_recent_devices():
    """Get list of recently connected devices."""
    cached = _get_cached('recent_devices', CACHE_TIMEOUT)
    if cached is not None:
        return cached

    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
        from device_manager import get_device_manager
        dm = get_device_manager()
        devices = dm.get_all_devices()

        # Sort by last_seen and take top 5
        devices.sort(key=lambda x: x.get('last_seen', ''), reverse=True)
        recent = []
        for d in devices[:5]:
            vlan_id = d.get('vlan_id', 0)
            vlan_names = {10: 'Management', 20: 'POS', 30: 'Staff', 40: 'Guest', 99: 'IoT'}
            recent.append({
                'name': d.get('hostname') or d.get('manufacturer') or 'Unknown',
                'ip': d.get('ip_address', ''),
                'vlan': vlan_names.get(vlan_id, f'VLAN {vlan_id}'),
                'time': _format_time_ago(d.get('last_seen'))
            })
        _set_cached('recent_devices', recent)
        return recent
    except Exception:
        pass

    return []


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
        return 'Unknown'


@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Main dashboard page - optimized single query."""
    stats = get_qsecbit_stats()
    tunnel = get_tunnel_status()

    return render_template('dashboard/index.html',
                           qsecbit_score=stats.get('score', 0),
                           qsecbit_status=stats.get('rag_status', 'GREEN'),
                           device_count=get_device_count(),
                           threats_blocked=stats.get('threats_detected', 0),
                           dns_blocked=get_dns_blocked_count(),
                           recent_threats=get_recent_threats(),
                           recent_devices=get_recent_devices(),
                           tunnel_status=tunnel)


@dashboard_bp.route('/api/dashboard/stats')
@login_required
def api_stats():
    """API endpoint for dashboard stats with caching."""
    stats = get_qsecbit_stats()
    tunnel = get_tunnel_status()
    return jsonify({
        'qsecbit': {
            'score': stats.get('score', 0),
            'status': stats.get('rag_status', 'GREEN'),
            'components': stats.get('components', {})
        },
        'devices': get_device_count(),
        'threats': stats.get('threats_detected', 0),
        'dns_blocked': get_dns_blocked_count(),
        'tunnel': tunnel,
        'timestamp': datetime.now().isoformat()
    })


@dashboard_bp.route('/api/dashboard/refresh')
@login_required
def api_refresh():
    """Force refresh all cached data."""
    global _cache
    _cache = {}
    return jsonify({'success': True, 'message': 'Cache cleared'})
