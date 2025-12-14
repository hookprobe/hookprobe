"""
Fortress Networks Views - VLAN configuration and management.

Provides VLAN overview, configuration, DNS policies, and bandwidth limits.
"""

from flask import render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user

from . import networks_bp
from ..auth.decorators import operator_required, admin_required

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


def get_demo_vlans():
    """Return demo VLANs when database unavailable."""
    return [
        {
            'vlan_id': 10,
            'name': 'Management',
            'subnet': '10.250.10.0/24',
            'gateway': '10.250.10.1',
            'dhcp_enabled': True,
            'dns_policy': 'standard',
            'is_isolated': False,
            'device_count': 2,
            'interface_up': True,
            'dhcp_running': True,
        },
        {
            'vlan_id': 20,
            'name': 'POS',
            'subnet': '10.250.20.0/24',
            'gateway': '10.250.20.1',
            'dhcp_enabled': True,
            'dns_policy': 'strict',
            'is_isolated': True,
            'device_count': 1,
            'interface_up': True,
            'dhcp_running': True,
        },
        {
            'vlan_id': 30,
            'name': 'Staff',
            'subnet': '10.250.30.0/24',
            'gateway': '10.250.30.1',
            'dhcp_enabled': True,
            'dns_policy': 'standard',
            'is_isolated': False,
            'device_count': 1,
            'interface_up': True,
            'dhcp_running': True,
        },
        {
            'vlan_id': 40,
            'name': 'Guest',
            'subnet': '10.250.40.0/24',
            'gateway': '10.250.40.1',
            'dhcp_enabled': True,
            'dns_policy': 'strict',
            'is_isolated': True,
            'device_count': 1,
            'interface_up': True,
            'dhcp_running': True,
        },
        {
            'vlan_id': 99,
            'name': 'IoT',
            'subnet': '10.250.99.0/24',
            'gateway': '10.250.99.1',
            'dhcp_enabled': True,
            'dns_policy': 'strict',
            'is_isolated': True,
            'device_count': 1,
            'interface_up': True,
            'dhcp_running': True,
        },
    ]


@networks_bp.route('/')
@login_required
def index():
    """VLAN overview page."""
    vlans = []

    if DB_AVAILABLE:
        try:
            vlan_mgr = get_vlan_manager()
            vlans = vlan_mgr.get_vlans()

            # Add status and device counts
            device_counts = get_db().get_device_count_by_vlan()
            for vlan in vlans:
                status = vlan_mgr.get_vlan_status(vlan['vlan_id'])
                vlan['interface_up'] = status.interface_up if status else False
                vlan['dhcp_running'] = status.dhcp_running if status else False
                vlan['device_count'] = device_counts.get(vlan['vlan_id'], 0)
        except Exception as e:
            flash(f'Error loading VLANs: {e}', 'danger')
            vlans = get_demo_vlans()
    else:
        vlans = get_demo_vlans()

    # Calculate totals
    total_devices = sum(v.get('device_count', 0) for v in vlans)
    active_vlans = sum(1 for v in vlans if v.get('interface_up'))
    isolated_vlans = sum(1 for v in vlans if v.get('is_isolated'))

    return render_template(
        'networks/index.html',
        vlans=vlans,
        total_devices=total_devices,
        active_vlans=active_vlans,
        isolated_vlans=isolated_vlans,
        db_available=DB_AVAILABLE
    )


@networks_bp.route('/<int:vlan_id>')
@login_required
def detail(vlan_id):
    """VLAN detail and configuration page."""
    vlan = None
    devices = []

    if DB_AVAILABLE:
        try:
            vlan = get_db().get_vlan(vlan_id)
            vlan_mgr = get_vlan_manager()

            if vlan:
                status = vlan_mgr.get_vlan_status(vlan_id)
                vlan['interface_up'] = status.interface_up if status else False
                vlan['dhcp_running'] = status.dhcp_running if status else False
                vlan['device_count'] = status.device_count if status else 0

                # Get devices on this VLAN
                device_mgr = get_device_manager()
                devices = device_mgr.get_all_devices(vlan_id=vlan_id)
                for device in devices:
                    for key in ['first_seen', 'last_seen']:
                        if device.get(key):
                            device[key] = str(device[key])
        except Exception as e:
            flash(f'Error loading VLAN: {e}', 'danger')

    if not vlan:
        # Try demo data
        for v in get_demo_vlans():
            if v['vlan_id'] == vlan_id:
                vlan = v
                break

    if not vlan:
        flash('VLAN not found', 'warning')
        return redirect(url_for('networks.index'))

    return render_template(
        'networks/detail.html',
        vlan=vlan,
        devices=devices,
        db_available=DB_AVAILABLE
    )


@networks_bp.route('/<int:vlan_id>/configure', methods=['POST'])
@login_required
@operator_required
def configure(vlan_id):
    """Update VLAN configuration."""
    if not DB_AVAILABLE:
        flash('Database not available', 'warning')
        return redirect(url_for('networks.detail', vlan_id=vlan_id))

    try:
        vlan_mgr = get_vlan_manager()

        # Get form data
        name = request.form.get('name')
        dhcp_enabled = request.form.get('dhcp_enabled') == 'on'
        is_isolated = request.form.get('is_isolated') == 'on'

        success = vlan_mgr.update_vlan_config(
            vlan_id,
            name=name,
            dhcp_enabled=dhcp_enabled,
            is_isolated=is_isolated
        )

        if success:
            # Log the action
            get_db().audit_log(
                user_id=current_user.id,
                action='vlan_configured',
                resource_type='vlan',
                resource_id=str(vlan_id),
                details={'name': name, 'dhcp_enabled': dhcp_enabled, 'is_isolated': is_isolated},
                ip_address=request.remote_addr
            )
            flash(f'VLAN {vlan_id} configuration updated', 'success')
        else:
            flash('Failed to update VLAN configuration', 'danger')
    except Exception as e:
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('networks.detail', vlan_id=vlan_id))


@networks_bp.route('/<int:vlan_id>/dns-policy', methods=['POST'])
@login_required
@operator_required
def set_dns_policy(vlan_id):
    """Set DNS policy for a VLAN."""
    if not DB_AVAILABLE:
        flash('Database not available', 'warning')
        return redirect(url_for('networks.detail', vlan_id=vlan_id))

    policy = request.form.get('dns_policy', 'standard')

    try:
        vlan_mgr = get_vlan_manager()
        success = vlan_mgr.set_dns_policy(vlan_id, policy)

        if success:
            get_db().audit_log(
                user_id=current_user.id,
                action='dns_policy_changed',
                resource_type='vlan',
                resource_id=str(vlan_id),
                details={'policy': policy},
                ip_address=request.remote_addr
            )
            flash(f'DNS policy set to {policy} for VLAN {vlan_id}', 'success')
        else:
            flash('Failed to set DNS policy', 'danger')
    except Exception as e:
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('networks.detail', vlan_id=vlan_id))


@networks_bp.route('/<int:vlan_id>/bandwidth', methods=['POST'])
@login_required
@operator_required
def set_bandwidth(vlan_id):
    """Set bandwidth limit for a VLAN."""
    if not DB_AVAILABLE:
        flash('Database not available', 'warning')
        return redirect(url_for('networks.detail', vlan_id=vlan_id))

    limit_mbps = request.form.get('bandwidth_limit', type=int)

    if limit_mbps is None or limit_mbps < 0:
        flash('Invalid bandwidth limit', 'warning')
        return redirect(url_for('networks.detail', vlan_id=vlan_id))

    try:
        vlan_mgr = get_vlan_manager()
        success = vlan_mgr.set_bandwidth_limit(vlan_id, limit_mbps)

        if success:
            get_db().audit_log(
                user_id=current_user.id,
                action='bandwidth_limit_changed',
                resource_type='vlan',
                resource_id=str(vlan_id),
                details={'limit_mbps': limit_mbps},
                ip_address=request.remote_addr
            )
            flash(f'Bandwidth limit set to {limit_mbps} Mbps for VLAN {vlan_id}', 'success')
        else:
            flash('Failed to set bandwidth limit', 'danger')
    except Exception as e:
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('networks.detail', vlan_id=vlan_id))


@networks_bp.route('/topology')
@login_required
def topology():
    """Network topology visualization."""
    vlans = []

    if DB_AVAILABLE:
        try:
            vlan_mgr = get_vlan_manager()
            vlans = vlan_mgr.get_vlans()

            device_counts = get_db().get_device_count_by_vlan()
            for vlan in vlans:
                vlan['device_count'] = device_counts.get(vlan['vlan_id'], 0)
        except Exception:
            vlans = get_demo_vlans()
    else:
        vlans = get_demo_vlans()

    return render_template(
        'networks/topology.html',
        vlans=vlans,
        db_available=DB_AVAILABLE
    )


@networks_bp.route('/api/stats/<int:vlan_id>')
@login_required
def api_stats(vlan_id):
    """Get VLAN statistics for AJAX requests."""
    if not DB_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503

    try:
        vlan_mgr = get_vlan_manager()
        stats = vlan_mgr.get_vlan_stats(vlan_id)
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
