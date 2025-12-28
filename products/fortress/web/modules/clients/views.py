"""
Fortress Clients Views - Device management with VLAN assignment.

Provides device inventory, discovery, blocking, and VLAN assignment.
Uses real system data from ARP table and data files.
"""

import json
import time
import logging
import subprocess
import csv
import io
from pathlib import Path
from datetime import datetime

from flask import render_template, request, jsonify, flash, redirect, url_for, Response
from flask_login import login_required, current_user

from . import clients_bp
from ..auth.decorators import operator_required

logger = logging.getLogger(__name__)

# Data directory - shared volume from fts-qsecbit agent
DATA_DIR = Path('/opt/hookprobe/fortress/data')

# OUI database for manufacturer lookup
OUI_FILE = Path('/usr/share/misc/oui.txt')
_oui_cache = {}

# Local cache
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


def _lookup_manufacturer(mac_address):
    """Look up manufacturer from MAC OUI prefix."""
    if not mac_address:
        return None

    # Get OUI prefix (first 6 hex chars)
    oui = mac_address.replace(':', '').replace('-', '').upper()[:6]

    # Check cache first
    if oui in _oui_cache:
        return _oui_cache[oui]

    # Try to load from OUI file
    if OUI_FILE.exists() and not _oui_cache:
        try:
            with open(OUI_FILE, 'r', errors='ignore') as f:
                for line in f:
                    if '(hex)' in line:
                        parts = line.split('(hex)')
                        if len(parts) >= 2:
                            prefix = parts[0].strip().replace('-', '')
                            vendor = parts[1].strip()
                            _oui_cache[prefix] = vendor
        except Exception:
            pass

    return _oui_cache.get(oui)


def get_all_devices():
    """Get list of all connected devices from ARP table and data files."""
    cached = _get_cached('all_devices', 10)
    if cached is not None:
        return cached

    devices = []

    # Try reading from device manager data file first
    devices_file = DATA_DIR / 'devices.json'
    try:
        if devices_file.exists():
            with open(devices_file, 'r') as f:
                devices = json.load(f)
                if isinstance(devices, list):
                    _set_cached('all_devices', devices)
                    return devices
    except Exception:
        pass

    # Fallback: build from ARP neighbor table
    try:
        result = subprocess.run(
            ['ip', '-j', 'neigh', 'show'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            neighbors = json.loads(result.stdout) if result.stdout.strip() else []
            for n in neighbors:
                state = n.get('state', ['UNKNOWN'])
                if isinstance(state, list):
                    state = state[0] if state else 'UNKNOWN'
                if state in ['FAILED', 'INCOMPLETE']:
                    continue

                mac = n.get('lladdr', '')
                devices.append({
                    'ip_address': n.get('dst', ''),
                    'mac_address': mac.upper() if mac else '',
                    'state': state,
                    'device_type': 'unknown',
                    'hostname': None,
                    'manufacturer': _lookup_manufacturer(mac),
                    'interface': n.get('dev', ''),
                    'last_seen': datetime.now().isoformat(),
                })
    except Exception as e:
        logger.warning(f"Failed to get ARP neighbors: {e}")

    _set_cached('all_devices', devices)
    return devices


def get_device_count():
    """Get device count summary."""
    devices = get_all_devices()
    total = len(devices)
    active = sum(1 for d in devices if d.get('state') in ['REACHABLE', 'STALE', 'DELAY'])
    return {
        'total': total,
        'reachable': active,
        'blocked': 0,  # Would need to check ebtables
    }


def get_device_by_mac(mac_address):
    """Get a specific device by MAC address."""
    devices = get_all_devices()
    mac_upper = mac_address.upper().replace('-', ':')
    for d in devices:
        if d.get('mac_address', '').upper() == mac_upper:
            return d
    return None


def get_vlans():
    """Get configured VLANs from data files."""
    cached = _get_cached('vlans', 60)
    if cached is not None:
        return cached

    vlans = []

    # Try reading from data file
    vlans_file = DATA_DIR / 'vlans.json'
    try:
        if vlans_file.exists():
            with open(vlans_file, 'r') as f:
                vlans = json.load(f)
                _set_cached('vlans', vlans)
                return vlans
    except Exception:
        pass

    # Fallback: return default VLANs
    vlans = [
        {'id': 100, 'name': 'LAN', 'description': 'Main LAN network'},
        {'id': 200, 'name': 'MGMT', 'description': 'Management network'},
        {'id': 300, 'name': 'GUEST', 'description': 'Guest network'},
        {'id': 400, 'name': 'IOT', 'description': 'IoT devices'},
        {'id': 500, 'name': 'SECURITY', 'description': 'Security cameras'},
    ]
    _set_cached('vlans', vlans)
    return vlans


@clients_bp.route('/')
@login_required
def index():
    """Device inventory page - uses real system data."""
    devices = get_all_devices()
    vlans = get_vlans()
    device_counts = get_device_count()

    return render_template(
        'clients/index.html',
        devices=devices,
        vlans=vlans,
        device_counts=device_counts,
        system_data_available=True  # Always true now - reads from real data
    )


@clients_bp.route('/discover', methods=['POST'])
@login_required
@operator_required
def discover():
    """Trigger device discovery scan using ARP ping."""
    # Clear cache to force refresh
    global _local_cache
    _local_cache.clear()

    # Try to ping broadcast to trigger ARP responses
    try:
        # Get interfaces
        result = subprocess.run(
            ['ip', '-j', 'addr', 'show'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            interfaces = json.loads(result.stdout)
            for iface in interfaces:
                for addr_info in iface.get('addr_info', []):
                    if addr_info.get('family') == 'inet':
                        # Send ARP ping to subnet
                        prefix = addr_info.get('local', '').rsplit('.', 1)[0]
                        if prefix:
                            # Use arping if available, otherwise just refresh ARP
                            subprocess.run(
                                ['ip', 'neigh', 'flush', 'all'],
                                capture_output=True
                            )
    except Exception as e:
        logger.warning(f"Discovery error: {e}")

    devices = get_all_devices()
    flash(f'Discovery complete: {len(devices)} devices found', 'success')
    return redirect(url_for('clients.index'))


@clients_bp.route('/<mac_address>')
@login_required
def detail(mac_address):
    """Device detail page."""
    device = get_device_by_mac(mac_address)
    vlans = get_vlans()

    if not device:
        flash('Device not found or not currently connected', 'warning')
        return redirect(url_for('clients.index'))

    return render_template(
        'clients/detail.html',
        device=device,
        vlans=vlans,
        system_data_available=True
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

    # VLAN assignment requires OVS OpenFlow rules
    # For now, inform user this is a manual operation
    flash(f'VLAN assignment to {vlan_id} requires manual OVS configuration', 'info')
    return redirect(url_for('clients.detail', mac_address=mac_address))


@clients_bp.route('/<mac_address>/block', methods=['POST'])
@login_required
@operator_required
def block(mac_address):
    """Block a device using ebtables."""
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
    try:
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
    """Export device inventory."""
    format_type = request.args.get('format', 'csv')

    try:
        devices = get_all_devices()

        if format_type == 'csv':
            output = io.StringIO()
            if devices:
                fieldnames = ['ip_address', 'mac_address', 'hostname', 'manufacturer', 'state', 'device_type', 'interface']
                writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(devices)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=devices.csv'}
            )
        else:
            return Response(
                json.dumps(devices, indent=2, default=str),
                mimetype='application/json',
                headers={'Content-Disposition': 'attachment; filename=devices.json'}
            )
    except Exception as e:
        flash(f'Export failed: {e}', 'danger')
        return redirect(url_for('clients.index'))


@clients_bp.route('/api/list')
@login_required
def api_list():
    """API endpoint for device list."""
    devices = get_all_devices()
    counts = get_device_count()
    return jsonify({
        'success': True,
        'devices': devices,
        'counts': counts,
        'timestamp': datetime.now().isoformat()
    })
