"""
Fortress Clients Views - Device management with VLAN assignment.

Provides device inventory, discovery, blocking, and VLAN assignment.
Uses real system data from ARP table and network interfaces.
"""

from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from pathlib import Path

from . import clients_bp
from ..auth.decorators import operator_required

# Import system data module (provides real data without DB dependency)
SYSTEM_DATA_AVAILABLE = False
try:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
    from system_data import (
        get_all_devices,
        get_device_count,
        get_vlans,
        get_device_by_mac,
    )
    SYSTEM_DATA_AVAILABLE = True
except ImportError as e:
    import logging
    logging.warning(f"system_data module not available: {e}")


@clients_bp.route('/')
@login_required
def index():
    """Device inventory page - uses real system data."""
    devices = []
    vlans = []
    device_counts = {'total': 0, 'active': 0, 'blocked': 0}

    if SYSTEM_DATA_AVAILABLE:
        try:
            devices = get_all_devices()
            counts = get_device_count()
            device_counts = {
                'total': counts.get('total', len(devices)),
                'active': counts.get('reachable', 0),
                'blocked': 0,  # Would need iptables check
            }
            vlans = get_vlans()
        except Exception as e:
            import logging
            logging.error(f'Error loading devices: {e}')
            flash(f'Error loading devices: {e}', 'danger')
    else:
        flash('System data module not available', 'warning')

    return render_template(
        'clients/index.html',
        devices=devices,
        vlans=vlans,
        device_counts=device_counts,
        system_data_available=SYSTEM_DATA_AVAILABLE
    )


@clients_bp.route('/discover', methods=['POST'])
@login_required
@operator_required
def discover():
    """Trigger device discovery scan using ARP."""
    if not SYSTEM_DATA_AVAILABLE:
        flash('System data module not available', 'warning')
        return redirect(url_for('clients.index'))

    try:
        # Force refresh by clearing cache
        from system_data import _cache
        _cache.clear()

        devices = get_all_devices()
        flash(f'Discovery complete: {len(devices)} devices found from ARP table', 'success')
    except Exception as e:
        flash(f'Discovery failed: {e}', 'danger')

    return redirect(url_for('clients.index'))


@clients_bp.route('/<mac_address>')
@login_required
def detail(mac_address):
    """Device detail page - uses real system data."""
    device = None
    vlans = []

    if SYSTEM_DATA_AVAILABLE:
        try:
            device = get_device_by_mac(mac_address)
            vlans = get_vlans()
        except Exception as e:
            flash(f'Error loading device: {e}', 'danger')

    if not device:
        flash('Device not found or not currently connected', 'warning')
        return redirect(url_for('clients.index'))

    return render_template(
        'clients/detail.html',
        device=device,
        vlans=vlans,
        system_data_available=SYSTEM_DATA_AVAILABLE
    )


@clients_bp.route('/<mac_address>/assign-vlan', methods=['POST'])
@login_required
@operator_required
def assign_vlan(mac_address):
    """Assign device to a VLAN (requires OVS commands)."""
    vlan_id = request.form.get('vlan_id', type=int)

    if vlan_id is None:
        flash('VLAN ID required', 'warning')
        return redirect(url_for('clients.detail', mac_address=mac_address))

    # VLAN assignment would require OVS OpenFlow rules
    # For now, inform user this is a manual operation
    flash(f'VLAN assignment to {vlan_id} requires manual OVS configuration', 'info')
    return redirect(url_for('clients.detail', mac_address=mac_address))


@clients_bp.route('/<mac_address>/block', methods=['POST'])
@login_required
@operator_required
def block(mac_address):
    """Block a device using iptables/ebtables."""
    import subprocess

    try:
        # Block at Layer 2 using ebtables
        result = subprocess.run(
            ['ebtables', '-A', 'FORWARD', '-s', mac_address, '-j', 'DROP'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            flash(f'Device {mac_address} blocked', 'success')
        else:
            flash(f'Failed to block device: {result.stderr}', 'danger')
    except FileNotFoundError:
        flash('ebtables not available, cannot block device', 'warning')
    except Exception as e:
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('clients.index'))


@clients_bp.route('/<mac_address>/unblock', methods=['POST'])
@login_required
@operator_required
def unblock(mac_address):
    """Unblock a device by removing ebtables rule."""
    import subprocess

    try:
        # Remove Layer 2 block using ebtables
        result = subprocess.run(
            ['ebtables', '-D', 'FORWARD', '-s', mac_address, '-j', 'DROP'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            flash(f'Device {mac_address} unblocked', 'success')
        else:
            flash(f'Device was not blocked or rule not found', 'info')
    except FileNotFoundError:
        flash('ebtables not available', 'warning')
    except Exception as e:
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('clients.index'))


@clients_bp.route('/export')
@login_required
def export():
    """Export device inventory from real ARP data."""
    import json
    import csv
    import io

    format_type = request.args.get('format', 'csv')

    if not SYSTEM_DATA_AVAILABLE:
        flash('System data not available for export', 'warning')
        return redirect(url_for('clients.index'))

    try:
        devices = get_all_devices()

        if format_type == 'csv':
            output = io.StringIO()
            if devices:
                writer = csv.DictWriter(output, fieldnames=devices[0].keys())
                writer.writeheader()
                writer.writerows(devices)
            return output.getvalue(), 200, {
                'Content-Type': 'text/csv',
                'Content-Disposition': 'attachment; filename=devices.csv'
            }
        else:
            return json.dumps(devices, indent=2, default=str), 200, {
                'Content-Type': 'application/json',
                'Content-Disposition': 'attachment; filename=devices.json'
            }
    except Exception as e:
        flash(f'Export failed: {e}', 'danger')
        return redirect(url_for('clients.index'))
