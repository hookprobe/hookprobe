"""
Fortress Clients Views - Device management with VLAN assignment.

Provides device inventory, discovery, blocking, and VLAN assignment.
"""

from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user

from . import clients_bp
from ..auth.decorators import operator_required

# Import lib modules (with fallback for development)
DB_AVAILABLE = False
try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
    from database import get_db
    from device_manager import get_device_manager
    from vlan_manager import get_vlan_manager
    DB_AVAILABLE = True
except ImportError:
    pass


def get_demo_devices():
    """Return demo devices when database unavailable."""
    return [
        {
            'mac_address': 'AA:BB:CC:DD:EE:01',
            'ip_address': '10.250.10.100',
            'hostname': 'admin-laptop',
            'vlan_id': 10,
            'device_type': 'laptop',
            'manufacturer': 'Dell Inc.',
            'is_blocked': False,
            'first_seen': '2025-12-14 10:00:00',
            'last_seen': '2025-12-14 14:30:00',
        },
        {
            'mac_address': 'AA:BB:CC:DD:EE:02',
            'ip_address': '10.250.20.50',
            'hostname': 'pos-terminal-1',
            'vlan_id': 20,
            'device_type': 'pos',
            'manufacturer': 'Square Inc.',
            'is_blocked': False,
            'first_seen': '2025-12-10 08:00:00',
            'last_seen': '2025-12-14 14:35:00',
        },
        {
            'mac_address': 'AA:BB:CC:DD:EE:03',
            'ip_address': '10.250.30.25',
            'hostname': 'staff-phone',
            'vlan_id': 30,
            'device_type': 'phone',
            'manufacturer': 'Apple Inc.',
            'is_blocked': False,
            'first_seen': '2025-12-12 09:00:00',
            'last_seen': '2025-12-14 13:00:00',
        },
        {
            'mac_address': 'AA:BB:CC:DD:EE:04',
            'ip_address': '10.250.40.10',
            'hostname': 'guest-laptop',
            'vlan_id': 40,
            'device_type': 'laptop',
            'manufacturer': 'HP Inc.',
            'is_blocked': False,
            'first_seen': '2025-12-14 11:00:00',
            'last_seen': '2025-12-14 14:20:00',
        },
        {
            'mac_address': 'AA:BB:CC:DD:EE:05',
            'ip_address': '10.250.99.5',
            'hostname': 'security-camera-1',
            'vlan_id': 99,
            'device_type': 'camera',
            'manufacturer': 'Hikvision',
            'is_blocked': False,
            'first_seen': '2025-12-01 00:00:00',
            'last_seen': '2025-12-14 14:40:00',
        },
    ]


def get_demo_vlans():
    """Return demo VLANs for dropdown."""
    return [
        {'vlan_id': 10, 'name': 'Management'},
        {'vlan_id': 20, 'name': 'POS'},
        {'vlan_id': 30, 'name': 'Staff'},
        {'vlan_id': 40, 'name': 'Guest'},
        {'vlan_id': 99, 'name': 'IoT'},
    ]


@clients_bp.route('/')
@login_required
def index():
    """Device inventory page."""
    devices = []
    vlans = []
    device_counts = {'total': 0, 'active': 0, 'blocked': 0}

    if DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            devices = device_mgr.get_all_devices()
            device_counts = device_mgr.get_device_count()

            vlan_mgr = get_vlan_manager()
            vlans = vlan_mgr.get_vlans()

            # Convert datetime objects to strings
            for device in devices:
                for key in ['first_seen', 'last_seen']:
                    if device.get(key):
                        device[key] = str(device[key])
        except Exception as e:
            flash(f'Error loading devices: {e}', 'danger')
            devices = get_demo_devices()
            vlans = get_demo_vlans()
    else:
        devices = get_demo_devices()
        vlans = get_demo_vlans()
        device_counts = {'total': 5, 'active': 4, 'blocked': 0}

    return render_template(
        'clients/index.html',
        devices=devices,
        vlans=vlans,
        device_counts=device_counts,
        db_available=DB_AVAILABLE
    )


@clients_bp.route('/discover', methods=['POST'])
@login_required
@operator_required
def discover():
    """Trigger device discovery scan."""
    if not DB_AVAILABLE:
        flash('Database not available for discovery', 'warning')
        return redirect(url_for('clients.index'))

    try:
        device_mgr = get_device_manager()
        discovered = device_mgr.discover_devices()
        new_count = len([d for d in discovered if d.get('is_new')])
        flash(f'Discovery complete: {len(discovered)} devices found, {new_count} new', 'success')
    except Exception as e:
        flash(f'Discovery failed: {e}', 'danger')

    return redirect(url_for('clients.index'))


@clients_bp.route('/<mac_address>')
@login_required
def detail(mac_address):
    """Device detail page."""
    device = None

    if DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            device = device_mgr.get_device(mac_address)
        except Exception as e:
            flash(f'Error loading device: {e}', 'danger')

    if not device:
        # Try demo data
        for d in get_demo_devices():
            if d['mac_address'] == mac_address:
                device = d
                break

    if not device:
        flash('Device not found', 'warning')
        return redirect(url_for('clients.index'))

    vlans = get_demo_vlans()
    if DB_AVAILABLE:
        try:
            vlan_mgr = get_vlan_manager()
            vlans = vlan_mgr.get_vlans()
        except Exception:
            pass

    return render_template(
        'clients/detail.html',
        device=device,
        vlans=vlans,
        db_available=DB_AVAILABLE
    )


@clients_bp.route('/<mac_address>/assign-vlan', methods=['POST'])
@login_required
@operator_required
def assign_vlan(mac_address):
    """Assign device to a VLAN."""
    vlan_id = request.form.get('vlan_id', type=int)

    if vlan_id is None:
        flash('VLAN ID required', 'warning')
        return redirect(url_for('clients.detail', mac_address=mac_address))

    if not DB_AVAILABLE:
        flash('Database not available', 'warning')
        return redirect(url_for('clients.detail', mac_address=mac_address))

    try:
        vlan_mgr = get_vlan_manager()
        success = vlan_mgr.assign_device_to_vlan(
            mac_address,
            vlan_id,
            reason=f'manual_assignment_by_{current_user.id}'
        )

        if success:
            flash(f'Device assigned to VLAN {vlan_id}', 'success')
        else:
            flash('Failed to assign VLAN', 'danger')
    except Exception as e:
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('clients.detail', mac_address=mac_address))


@clients_bp.route('/<mac_address>/block', methods=['POST'])
@login_required
@operator_required
def block(mac_address):
    """Block a device."""
    reason = request.form.get('reason', 'manual_block')

    if not DB_AVAILABLE:
        flash('Database not available', 'warning')
        return redirect(url_for('clients.index'))

    try:
        device_mgr = get_device_manager()
        success = device_mgr.block_device(mac_address, reason=reason)

        if success:
            flash(f'Device {mac_address} blocked', 'success')
        else:
            flash('Failed to block device', 'danger')
    except Exception as e:
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('clients.index'))


@clients_bp.route('/<mac_address>/unblock', methods=['POST'])
@login_required
@operator_required
def unblock(mac_address):
    """Unblock a device."""
    if not DB_AVAILABLE:
        flash('Database not available', 'warning')
        return redirect(url_for('clients.index'))

    try:
        device_mgr = get_device_manager()
        success = device_mgr.unblock_device(mac_address)

        if success:
            flash(f'Device {mac_address} unblocked', 'success')
        else:
            flash('Failed to unblock device', 'danger')
    except Exception as e:
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('clients.index'))


@clients_bp.route('/export')
@login_required
def export():
    """Export device inventory."""
    format_type = request.args.get('format', 'csv')

    if not DB_AVAILABLE:
        flash('Database not available for export', 'warning')
        return redirect(url_for('clients.index'))

    try:
        device_mgr = get_device_manager()

        if format_type == 'csv':
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
    except Exception as e:
        flash(f'Export failed: {e}', 'danger')
        return redirect(url_for('clients.index'))
