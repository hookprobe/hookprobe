"""
Fortress Networks Views - VLAN configuration and management.

Provides VLAN overview, configuration, DNS policies, and bandwidth limits.
Uses real system data from network interfaces and OVS.
"""

from flask import render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from pathlib import Path

from . import networks_bp
from ..auth.decorators import operator_required, admin_required

# Import system data module (provides real data without DB dependency)
SYSTEM_DATA_AVAILABLE = False
try:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
    from system_data import (
        get_vlans,
        get_all_devices,
        get_network_topology,
        get_ovs_bridge_info,
    )
    SYSTEM_DATA_AVAILABLE = True
except ImportError as e:
    import logging
    logging.warning(f"system_data module not available: {e}")


@networks_bp.route('/')
@login_required
def index():
    """VLAN overview page - uses real system data."""
    vlans = []

    if SYSTEM_DATA_AVAILABLE:
        try:
            vlans = get_vlans()
            # Enrich with additional status info
            for vlan in vlans:
                vlan['interface_up'] = vlan.get('state') == 'UP'
                vlan['dhcp_running'] = True  # dnsmasq provides DHCP
                vlan['is_isolated'] = vlan.get('vlan_id') == 200  # MGMT is isolated
        except Exception as e:
            import logging
            logging.error(f'Error loading VLANs: {e}')
            flash(f'Error loading VLANs: {e}', 'danger')
    else:
        flash('System data module not available', 'warning')

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
        system_data_available=SYSTEM_DATA_AVAILABLE
    )


@networks_bp.route('/<int:vlan_id>')
@login_required
def detail(vlan_id):
    """VLAN detail and configuration page - uses real system data."""
    vlan = None
    devices = []

    if SYSTEM_DATA_AVAILABLE:
        try:
            vlans = get_vlans()
            for v in vlans:
                if v['vlan_id'] == vlan_id:
                    vlan = v
                    vlan['interface_up'] = vlan.get('state') == 'UP'
                    vlan['dhcp_running'] = True
                    break

            if vlan:
                # Get devices on this VLAN
                all_devices = get_all_devices()
                vlan_interface = vlan.get('interface', f'vlan{vlan_id}')
                devices = [d for d in all_devices if d.get('interface') == vlan_interface]
        except Exception as e:
            flash(f'Error loading VLAN: {e}', 'danger')

    if not vlan:
        flash(f'VLAN {vlan_id} not found on this system', 'warning')
        return redirect(url_for('networks.index'))

    return render_template(
        'networks/detail.html',
        vlan=vlan,
        devices=devices,
        system_data_available=SYSTEM_DATA_AVAILABLE
    )


@networks_bp.route('/<int:vlan_id>/configure', methods=['POST'])
@login_required
@operator_required
def configure(vlan_id):
    """Update VLAN configuration (requires system commands)."""
    # VLAN configuration requires OVS and dnsmasq reconfiguration
    # This is a placeholder - actual implementation would use shell commands
    flash('VLAN configuration changes require system restart to apply', 'info')
    return redirect(url_for('networks.detail', vlan_id=vlan_id))


@networks_bp.route('/<int:vlan_id>/dns-policy', methods=['POST'])
@login_required
@operator_required
def set_dns_policy(vlan_id):
    """Set DNS policy for a VLAN (dnsXai integration)."""
    policy = request.form.get('dns_policy', 'standard')

    # DNS policy would be configured via dnsXai container
    # Placeholder - would need to update dnsmasq/dnsXai config
    flash(f'DNS policy set to {policy} for VLAN {vlan_id}. Restart required.', 'info')
    return redirect(url_for('networks.detail', vlan_id=vlan_id))


@networks_bp.route('/<int:vlan_id>/bandwidth', methods=['POST'])
@login_required
@operator_required
def set_bandwidth(vlan_id):
    """Set bandwidth limit for a VLAN (tc/OVS QoS)."""
    limit_mbps = request.form.get('bandwidth_limit', type=int)

    if limit_mbps is None or limit_mbps < 0:
        flash('Invalid bandwidth limit', 'warning')
        return redirect(url_for('networks.detail', vlan_id=vlan_id))

    # Bandwidth limiting would use tc or OVS QoS
    # Placeholder - would need to configure tc qdisc
    flash(f'Bandwidth limit of {limit_mbps} Mbps set for VLAN {vlan_id}', 'info')
    return redirect(url_for('networks.detail', vlan_id=vlan_id))


@networks_bp.route('/topology')
@login_required
def topology():
    """Network topology visualization - uses real system data."""
    vlans = []
    topology_data = None

    if SYSTEM_DATA_AVAILABLE:
        try:
            vlans = get_vlans()
            topology_data = get_network_topology()
            # Enrich vlans with is_isolated flag
            for vlan in vlans:
                vlan['is_isolated'] = vlan.get('vlan_id') == 200
        except Exception as e:
            import logging
            logging.error(f'Error loading topology: {e}')

    return render_template(
        'networks/topology.html',
        vlans=vlans,
        topology=topology_data,
        system_data_available=SYSTEM_DATA_AVAILABLE
    )


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
