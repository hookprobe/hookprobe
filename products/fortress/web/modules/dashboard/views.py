"""
Fortress Dashboard Views
Main overview page with widgets and stats.
"""

import json
from pathlib import Path
from datetime import datetime

from flask import render_template, jsonify
from flask_login import login_required

from . import dashboard_bp


def get_qsecbit_stats():
    """Load QSecBit stats from file."""
    stats_file = Path('/opt/hookprobe/fortress/data/qsecbit_stats.json')
    try:
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {
        'score': 0.85,
        'rag_status': 'GREEN',
        'threats_detected': 0,
        'vlan_violations': 0
    }


def get_device_count():
    """Get count of connected devices."""
    # TODO: Integrate with actual device tracking
    return 12


def get_dns_blocked_count():
    """Get count of DNS queries blocked today."""
    # TODO: Integrate with dnsXai
    return 1234


def get_recent_threats():
    """Get list of recent threats."""
    # TODO: Integrate with QSecBit
    return [
        {'type': 'SYN Flood', 'source': '192.168.40.105', 'time': '5 min ago', 'severity': 'high'},
        {'type': 'Port Scan', 'source': '10.250.40.23', 'time': '12 min ago', 'severity': 'medium'},
        {'type': 'DNS Tunnel', 'source': '10.250.30.8', 'time': '1 hour ago', 'severity': 'low'},
    ]


def get_recent_devices():
    """Get list of recently connected devices."""
    # TODO: Integrate with device tracking
    return [
        {'name': 'iPhone 15', 'ip': '10.250.40.105', 'vlan': 'Guest', 'time': '2 min ago'},
        {'name': 'POS Terminal', 'ip': '10.250.20.10', 'vlan': 'POS', 'time': '5 min ago'},
        {'name': 'Staff Laptop', 'ip': '10.250.30.22', 'vlan': 'Staff', 'time': '15 min ago'},
    ]


@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Main dashboard page."""
    stats = get_qsecbit_stats()

    return render_template('dashboard/index.html',
                           qsecbit_score=stats.get('score', 0),
                           qsecbit_status=stats.get('rag_status', 'GREEN'),
                           device_count=get_device_count(),
                           threats_blocked=stats.get('threats_detected', 0),
                           dns_blocked=get_dns_blocked_count(),
                           recent_threats=get_recent_threats(),
                           recent_devices=get_recent_devices())


@dashboard_bp.route('/api/dashboard/stats')
@login_required
def api_stats():
    """API endpoint for dashboard stats (for real-time updates)."""
    stats = get_qsecbit_stats()
    return jsonify({
        'qsecbit': {
            'score': stats.get('score', 0),
            'status': stats.get('rag_status', 'GREEN'),
            'components': stats.get('components', {})
        },
        'devices': get_device_count(),
        'threats': stats.get('threats_detected', 0),
        'dns_blocked': get_dns_blocked_count(),
        'timestamp': datetime.now().isoformat()
    })
