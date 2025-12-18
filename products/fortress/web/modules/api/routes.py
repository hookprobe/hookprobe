"""
Fortress REST API Routes

Provides REST API endpoints for:
- VLAN management
- Device management
- Security metrics (QSecBit)
- DNS statistics
- System status
"""

import json
from datetime import datetime
from flask import jsonify, request
from flask_login import login_required, current_user

from . import api_bp
from ..auth.decorators import admin_required, operator_required

# Import lib modules (with fallback for development)
DB_AVAILABLE = False
try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
    from database import get_db
    from vlan_manager import get_vlan_manager
    from device_manager import get_device_manager
    DB_AVAILABLE = True
except ImportError:
    pass


def db_required(f):
    """Decorator to check database availability."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not DB_AVAILABLE:
            return jsonify({'error': 'Database not available'}), 503
        return f(*args, **kwargs)
    return decorated


# ========================================
# Health & Status
# ========================================

@api_bp.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'tier': 'fortress',
        'version': '5.4.0',
        'timestamp': datetime.now().isoformat()
    })


@api_bp.route('/version')
def version():
    """Version info."""
    return jsonify({'version': '5.4.0', 'product': 'Fortress'})


@api_bp.route('/status')
@login_required
def status():
    """System status overview."""
    data = {
        'tier': 'fortress',
        'version': '5.4.0',
        'database': DB_AVAILABLE,
        'timestamp': datetime.now().isoformat()
    }

    if DB_AVAILABLE:
        try:
            db = get_db()
            qsecbit = db.get_latest_qsecbit()
            threats = db.get_threat_summary(hours=24)
            dns = db.get_dns_stats(hours=24)
            device_counts = get_device_manager().get_device_count()

            data.update({
                'qsecbit': {
                    'score': float(qsecbit['score']) if qsecbit else 0.85,
                    'status': qsecbit['rag_status'] if qsecbit else 'GREEN'
                },
                'threats': threats,
                'dns': dns,
                'devices': device_counts
            })
        except Exception as e:
            data['error'] = str(e)

    return jsonify(data)


# ========================================
# VLAN Management API
# ========================================

@api_bp.route('/vlans')
@login_required
@db_required
def list_vlans():
    """List all VLANs."""
    vlan_mgr = get_vlan_manager()
    vlans = vlan_mgr.get_vlans()

    device_counts = get_db().get_device_count_by_vlan()
    for vlan in vlans:
        vlan['device_count'] = device_counts.get(vlan['vlan_id'], 0)

    return jsonify({'vlans': vlans})


@api_bp.route('/vlans/<int:vlan_id>')
@login_required
@db_required
def get_vlan(vlan_id):
    """Get VLAN details."""
    vlan_mgr = get_vlan_manager()
    vlan = get_db().get_vlan(vlan_id)

    if not vlan:
        return jsonify({'error': 'VLAN not found'}), 404

    status = vlan_mgr.get_vlan_status(vlan_id)
    vlan['status'] = {
        'interface_up': status.interface_up if status else False,
        'dhcp_running': status.dhcp_running if status else False,
        'device_count': status.device_count if status else 0,
    }

    return jsonify(vlan)


@api_bp.route('/vlans/<int:vlan_id>', methods=['PUT'])
@login_required
@operator_required
@db_required
def update_vlan(vlan_id):
    """Update VLAN configuration."""
    data = request.get_json() or {}

    vlan_mgr = get_vlan_manager()
    success = vlan_mgr.update_vlan_config(vlan_id, **data)

    if success:
        get_db().audit_log(
            user_id=current_user.id,
            action='vlan_updated',
            resource_type='vlan',
            resource_id=str(vlan_id),
            details=data,
            ip_address=request.remote_addr
        )
        return jsonify({'success': True})

    return jsonify({'error': 'Failed to update VLAN'}), 400


@api_bp.route('/vlans/<int:vlan_id>/stats')
@login_required
@db_required
def get_vlan_stats(vlan_id):
    """Get VLAN traffic statistics."""
    vlan_mgr = get_vlan_manager()
    stats = vlan_mgr.get_vlan_stats(vlan_id)
    return jsonify(stats)


# ========================================
# Device Management API
# ========================================

@api_bp.route('/devices')
@login_required
@db_required
def list_devices():
    """List all devices."""
    vlan_id = request.args.get('vlan_id', type=int)
    active_only = request.args.get('active', 'false').lower() == 'true'

    device_mgr = get_device_manager()
    devices = device_mgr.get_all_devices(vlan_id=vlan_id, active_only=active_only)

    for device in devices:
        for key in ['first_seen', 'last_seen']:
            if device.get(key):
                device[key] = str(device[key])

    return jsonify({'devices': devices, 'count': len(devices)})


@api_bp.route('/devices/<mac_address>')
@login_required
@db_required
def get_device(mac_address):
    """Get device by MAC address."""
    device_mgr = get_device_manager()
    device = device_mgr.get_device(mac_address)

    if not device:
        return jsonify({'error': 'Device not found'}), 404

    for key in ['first_seen', 'last_seen']:
        if device.get(key):
            device[key] = str(device[key])

    return jsonify(device)


@api_bp.route('/devices/<mac_address>/vlan', methods=['PUT'])
@login_required
@operator_required
@db_required
def assign_device_vlan(mac_address):
    """Assign device to a VLAN."""
    data = request.get_json() or {}
    vlan_id = data.get('vlan_id')

    if vlan_id is None:
        return jsonify({'error': 'vlan_id required'}), 400

    vlan_mgr = get_vlan_manager()
    success = vlan_mgr.assign_device_to_vlan(
        mac_address,
        vlan_id,
        reason=f"manual_assignment_by_{current_user.id}"
    )

    if success:
        return jsonify({'success': True})

    return jsonify({'error': 'Failed to assign VLAN'}), 400


@api_bp.route('/devices/<mac_address>/block', methods=['POST'])
@login_required
@operator_required
@db_required
def block_device(mac_address):
    """Block a device."""
    data = request.get_json() or {}
    reason = data.get('reason', 'manual_block')

    device_mgr = get_device_manager()
    success = device_mgr.block_device(mac_address, reason=reason)

    if success:
        return jsonify({'success': True})

    return jsonify({'error': 'Failed to block device'}), 400


@api_bp.route('/devices/<mac_address>/unblock', methods=['POST'])
@login_required
@operator_required
@db_required
def unblock_device(mac_address):
    """Unblock a device."""
    device_mgr = get_device_manager()
    success = device_mgr.unblock_device(mac_address)

    if success:
        return jsonify({'success': True})

    return jsonify({'error': 'Failed to unblock device'}), 400


@api_bp.route('/devices/discover', methods=['POST'])
@login_required
@operator_required
@db_required
def discover_devices():
    """Trigger device discovery scan."""
    device_mgr = get_device_manager()
    discovered = device_mgr.discover_devices()

    return jsonify({
        'discovered': len(discovered),
        'new': len([d for d in discovered if d.get('is_new')]),
        'devices': discovered
    })


@api_bp.route('/devices/export')
@login_required
@db_required
def export_devices():
    """Export device inventory."""
    format = request.args.get('format', 'json')

    device_mgr = get_device_manager()

    if format == 'csv':
        csv_data = device_mgr.export_inventory_csv()
        return csv_data, 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename=devices.csv'
        }
    else:
        json_data = device_mgr.export_inventory_json()
        return json_data, 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': 'attachment; filename=devices.json'
        }


@api_bp.route('/devices/counts')
@login_required
@db_required
def device_counts():
    """Get device count summary."""
    device_mgr = get_device_manager()
    counts = device_mgr.get_device_count()
    return jsonify(counts)


# ========================================
# Security / QSecBit API
# ========================================

@api_bp.route('/security/qsecbit')
@login_required
@db_required
def get_qsecbit():
    """Get current QSecBit score."""
    db = get_db()
    qsecbit = db.get_latest_qsecbit()

    if qsecbit:
        qsecbit['score'] = float(qsecbit['score'])
        if qsecbit.get('recorded_at'):
            qsecbit['recorded_at'] = str(qsecbit['recorded_at'])
        return jsonify(qsecbit)

    return jsonify({
        'score': 0.85,
        'rag_status': 'GREEN',
        'components': {},
        'message': 'No QSecBit data available'
    })


@api_bp.route('/security/threats')
@login_required
@db_required
def get_threats():
    """Get recent threats."""
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 100, type=int)

    db = get_db()
    threats = db.get_recent_threats(hours=hours, limit=limit)

    for threat in threats:
        if threat.get('detected_at'):
            threat['detected_at'] = str(threat['detected_at'])
        if threat.get('source_ip'):
            threat['source_ip'] = str(threat['source_ip'])

    return jsonify({'threats': threats, 'count': len(threats)})


@api_bp.route('/security/threats/summary')
@login_required
@db_required
def get_threat_summary():
    """Get threat summary for dashboard."""
    hours = request.args.get('hours', 24, type=int)

    db = get_db()
    summary = db.get_threat_summary(hours=hours)

    return jsonify(summary)


# ========================================
# DNS Statistics API
# ========================================

@api_bp.route('/dns/stats')
@login_required
@db_required
def get_dns_stats():
    """Get DNS query statistics."""
    hours = request.args.get('hours', 24, type=int)

    db = get_db()
    stats = db.get_dns_stats(hours=hours)

    return jsonify(stats)


@api_bp.route('/dns/blocked')
@login_required
@db_required
def get_blocked_domains():
    """Get top blocked domains."""
    limit = request.args.get('limit', 10, type=int)

    db = get_db()
    domains = db.get_top_blocked_domains(limit=limit)

    return jsonify({'domains': domains})
