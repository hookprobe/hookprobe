"""
Fortress Networks Views - VLAN API endpoints.

Network management is now part of the unified SDN AI page.
This module provides backward-compatible redirects and API endpoints.
"""

from flask import redirect, url_for, jsonify
from flask_login import login_required
from pathlib import Path

from . import networks_bp

# Import system data module (provides real data without DB dependency)
SYSTEM_DATA_AVAILABLE = False
try:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
    from system_data import (
        get_vlans,
        get_all_devices,
    )
    SYSTEM_DATA_AVAILABLE = True
except ImportError as e:
    import logging
    logging.warning(f"system_data module not available: {e}")


@networks_bp.route('/')
@login_required
def index():
    """Redirect to unified SDN AI page."""
    return redirect(url_for('sdn.index'))


@networks_bp.route('/api/stats/<int:vlan_id>')
@login_required
def api_stats(vlan_id):
    """Get VLAN statistics for AJAX requests - uses real system data."""
    if not SYSTEM_DATA_AVAILABLE:
        return jsonify({'error': 'System data not available'}), 503

    try:
        vlans = get_vlans()
        all_devices = get_all_devices()

        for vlan in vlans:
            if vlan['vlan_id'] == vlan_id:
                vlan_interface = vlan.get('interface', f'vlan{vlan_id}')
                devices = [d for d in all_devices if d.get('interface') == vlan_interface]
                return jsonify({
                    'vlan_id': vlan_id,
                    'name': vlan.get('name'),
                    'state': vlan.get('state'),
                    'device_count': len(devices),
                    'devices': devices,
                })

        return jsonify({'error': f'VLAN {vlan_id} not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
