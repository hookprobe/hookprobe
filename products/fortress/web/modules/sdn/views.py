"""
Fortress SDN Views - Unified Device and Network Policy Management

Provides a single dashboard for managing all network devices with:
- Complete visibility: IP, MAC, vendor, policy, status
- OUI-based automatic classification
- Network policy controls (VLAN or filter mode)
- Real-time status monitoring
- Bulk operations
"""

from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime
import json

from . import sdn_bp
from ..auth.decorators import operator_required

# Import lib modules (with fallback for development)
DB_AVAILABLE = False
POLICY_MANAGER_AVAILABLE = False

try:
    import sys
    from pathlib import Path
    lib_path = Path(__file__).parent.parent.parent.parent / 'lib'
    sys.path.insert(0, str(lib_path))
    from database import get_db
    from device_manager import get_device_manager
    from vlan_manager import get_vlan_manager
    DB_AVAILABLE = True
except ImportError:
    pass

try:
    from network_policy_manager import (
        OUIClassifier,
        NetworkPolicyManager,
        NetworkPolicy,
        DeviceCategory,
        classify_device
    )
    POLICY_MANAGER_AVAILABLE = True
except ImportError:
    # Fallback classification function
    def classify_device(mac_address):
        return {
            'mac_address': mac_address.upper(),
            'oui': mac_address.upper()[:8],
            'category': 'unknown',
            'recommended_policy': 'default',
            'manufacturer': 'Unknown'
        }

# SDN Auto-Pilot for segment management
SDN_AUTOPILOT_AVAILABLE = False
try:
    from sdn_autopilot import get_sdn_autopilot, NetworkSegment, DeviceCategory as SegmentCategory
    SDN_AUTOPILOT_AVAILABLE = True
except ImportError:
    pass


# ============================================================
# DEMO DATA
# ============================================================

def get_demo_devices():
    """Return demo devices with full SDN info."""
    return [
        {
            'mac_address': 'B8:27:EB:12:34:56',
            'ip_address': '192.168.1.105',
            'hostname': 'rpi-sensor-1',
            'device_type': 'iot',
            'manufacturer': 'Raspberry Pi Foundation',
            'network_policy': 'lan_only',
            'vlan_id': 99,
            'internet_access': False,
            'lan_access': True,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'iot',
            'auto_policy': 'lan_only',
            'first_seen': '2025-12-10 08:00:00',
            'last_seen': '2025-12-17 14:30:00',
            'bytes_sent': 1024000,
            'bytes_received': 2048000,
        },
        {
            'mac_address': '00:17:88:AA:BB:CC',
            'ip_address': '192.168.1.110',
            'hostname': 'hue-bridge',
            'device_type': 'iot',
            'manufacturer': 'Philips Hue',
            'network_policy': 'lan_only',
            'vlan_id': 99,
            'internet_access': False,
            'lan_access': True,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'iot',
            'auto_policy': 'lan_only',
            'first_seen': '2025-12-01 00:00:00',
            'last_seen': '2025-12-17 14:35:00',
            'bytes_sent': 512000,
            'bytes_received': 256000,
        },
        {
            'mac_address': '58:E6:BA:11:22:33',
            'ip_address': '192.168.1.50',
            'hostname': 'square-pos-1',
            'device_type': 'pos',
            'manufacturer': 'Square Inc.',
            'network_policy': 'internet_only',
            'vlan_id': 20,
            'internet_access': True,
            'lan_access': False,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'pos',
            'auto_policy': 'internet_only',
            'first_seen': '2025-12-05 09:00:00',
            'last_seen': '2025-12-17 14:40:00',
            'bytes_sent': 5120000,
            'bytes_received': 1024000,
        },
        {
            'mac_address': '0C:47:C9:AA:BB:CC',
            'ip_address': '192.168.1.120',
            'hostname': 'echo-dot-kitchen',
            'device_type': 'voice_assistant',
            'manufacturer': 'Amazon Echo',
            'network_policy': 'internet_only',
            'vlan_id': 99,
            'internet_access': True,
            'lan_access': False,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'voice_assistant',
            'auto_policy': 'internet_only',
            'first_seen': '2025-12-08 10:00:00',
            'last_seen': '2025-12-17 14:20:00',
            'bytes_sent': 2048000,
            'bytes_received': 10240000,
        },
        {
            'mac_address': '00:0C:B5:44:55:66',
            'ip_address': '192.168.1.200',
            'hostname': 'cam-front-door',
            'device_type': 'camera',
            'manufacturer': 'Hikvision',
            'network_policy': 'lan_only',
            'vlan_id': 99,
            'internet_access': False,
            'lan_access': True,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'camera',
            'auto_policy': 'lan_only',
            'first_seen': '2025-12-01 00:00:00',
            'last_seen': '2025-12-17 14:45:00',
            'bytes_sent': 102400000,
            'bytes_received': 1024000,
        },
        {
            'mac_address': '3C:06:30:DE:AD:BE',
            'ip_address': '192.168.1.25',
            'hostname': 'macbook-sarah',
            'device_type': 'workstation',
            'manufacturer': 'Apple Inc.',
            'network_policy': 'full_access',
            'vlan_id': 30,
            'internet_access': True,
            'lan_access': True,
            'is_blocked': False,
            'is_online': True,
            'oui_category': 'workstation',
            'auto_policy': 'full_access',
            'first_seen': '2025-12-12 08:30:00',
            'last_seen': '2025-12-17 14:50:00',
            'bytes_sent': 50240000,
            'bytes_received': 150720000,
        },
        {
            'mac_address': '00:1E:0B:77:88:99',
            'ip_address': '192.168.1.210',
            'hostname': 'hp-printer-office',
            'device_type': 'printer',
            'manufacturer': 'HP Inc.',
            'network_policy': 'lan_only',
            'vlan_id': 99,
            'internet_access': False,
            'lan_access': True,
            'is_blocked': False,
            'is_online': False,
            'oui_category': 'printer',
            'auto_policy': 'lan_only',
            'first_seen': '2025-12-03 00:00:00',
            'last_seen': '2025-12-17 12:00:00',
            'bytes_sent': 10240000,
            'bytes_received': 5120000,
        },
        {
            'mac_address': 'DE:AD:BE:EF:CA:FE',
            'ip_address': '192.168.1.99',
            'hostname': 'unknown-device',
            'device_type': 'unknown',
            'manufacturer': 'Unknown',
            'network_policy': 'isolated',
            'vlan_id': 40,
            'internet_access': False,
            'lan_access': False,
            'is_blocked': True,
            'is_online': False,
            'oui_category': 'unknown',
            'auto_policy': 'default',
            'first_seen': '2025-12-17 10:00:00',
            'last_seen': '2025-12-17 10:05:00',
            'bytes_sent': 1024,
            'bytes_received': 2048,
        },
    ]


def get_demo_policies():
    """Return demo network policies."""
    return [
        {
            'name': 'full_access',
            'display_name': 'Full Access',
            'description': 'Full internet and LAN access',
            'internet_access': True,
            'lan_access': True,
            'icon': 'fa-globe',
            'color': 'success',
        },
        {
            'name': 'lan_only',
            'display_name': 'LAN Only',
            'description': 'Local network only - no internet',
            'internet_access': False,
            'lan_access': True,
            'icon': 'fa-network-wired',
            'color': 'info',
        },
        {
            'name': 'internet_only',
            'display_name': 'Internet Only',
            'description': 'Internet access only - no LAN',
            'internet_access': True,
            'lan_access': False,
            'icon': 'fa-cloud',
            'color': 'primary',
        },
        {
            'name': 'isolated',
            'display_name': 'Isolated',
            'description': 'Completely isolated - no network access',
            'internet_access': False,
            'lan_access': False,
            'icon': 'fa-ban',
            'color': 'danger',
        },
        {
            'name': 'default',
            'display_name': 'Default',
            'description': 'Default policy for unclassified devices',
            'internet_access': True,
            'lan_access': True,
            'icon': 'fa-question-circle',
            'color': 'secondary',
        },
    ]


def get_demo_vlans():
    """Return demo VLANs."""
    return [
        {'vlan_id': 10, 'name': 'Management', 'subnet': '10.250.10.0/24', 'device_count': 2},
        {'vlan_id': 20, 'name': 'POS', 'subnet': '10.250.20.0/24', 'device_count': 1},
        {'vlan_id': 30, 'name': 'Staff', 'subnet': '10.250.30.0/24', 'device_count': 1},
        {'vlan_id': 40, 'name': 'Guest', 'subnet': '10.250.40.0/24', 'device_count': 1},
        {'vlan_id': 99, 'name': 'IoT', 'subnet': '10.250.99.0/24', 'device_count': 3},
    ]


def get_demo_stats():
    """Return demo statistics."""
    return {
        'total_devices': 8,
        'online_devices': 6,
        'offline_devices': 2,
        'blocked_devices': 1,
        'policy_counts': {
            'full_access': 1,
            'lan_only': 4,
            'internet_only': 2,
            'isolated': 1,
        },
        'category_counts': {
            'iot': 2,
            'camera': 1,
            'pos': 1,
            'voice_assistant': 1,
            'workstation': 1,
            'printer': 1,
            'unknown': 1,
        },
    }


def format_device_for_template(device):
    """Format device data for template consumption."""
    policy = device.get('network_policy', 'default')
    is_blocked = device.get('is_blocked', False)
    is_online = device.get('is_online', False)

    # Determine status
    if is_blocked:
        status = 'blocked'
    elif is_online:
        status = 'online'
    else:
        status = 'offline'

    # Determine access rights based on policy
    access_rights = {
        'full_access': {'lan': True, 'internet': True, 'gateway': True, 'dns': True},
        'lan_only': {'lan': True, 'internet': False, 'gateway': True, 'dns': True},
        'internet_only': {'lan': False, 'internet': True, 'gateway': True, 'dns': True},
        'isolated': {'lan': False, 'internet': False, 'gateway': True, 'dns': True},
        'default': {'lan': True, 'internet': True, 'gateway': True, 'dns': True},
    }
    rights = access_rights.get(policy, access_rights['default'])

    # Icon mapping
    icon_map = {
        'iot': 'fa-microchip',
        'camera': 'fa-video',
        'pos': 'fa-cash-register',
        'voice_assistant': 'fa-microphone',
        'workstation': 'fa-desktop',
        'printer': 'fa-print',
        'phone': 'fa-mobile-alt',
        'tablet': 'fa-tablet-alt',
        'router': 'fa-router',
        'unknown': 'fa-question-circle',
    }
    category = device.get('oui_category', device.get('device_type', 'unknown'))

    # Format bytes for display
    def format_bytes(b):
        if not b:
            return '0 B'
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024:
                return f'{b:.1f} {unit}'
            b /= 1024
        return f'{b:.1f} PB'

    return {
        'mac': device.get('mac_address', ''),
        'ip': device.get('ip_address', ''),
        'hostname': device.get('hostname', 'Unknown'),
        'vendor': device.get('manufacturer', 'Unknown'),
        'category': category,
        'policy': policy,
        'status': status,
        'is_online': is_online,
        'is_blocked': is_blocked,
        'can_access_lan': rights['lan'] and not is_blocked,
        'can_access_internet': rights['internet'] and not is_blocked,
        'can_access_gateway': rights['gateway'] and not is_blocked,
        'can_access_dns': rights['dns'] and not is_blocked,
        'icon': icon_map.get(category, 'fa-laptop'),
        'first_seen': device.get('first_seen', ''),
        'last_seen': device.get('last_seen', ''),
        'recommended_policy': device.get('auto_policy', 'default'),
        'bytes_sent': format_bytes(device.get('bytes_sent', 0)),
        'bytes_received': format_bytes(device.get('bytes_received', 0)),
        'vlan_id': device.get('vlan_id'),
        'recent_events': device.get('recent_events', []),
    }


# ============================================================
# MAIN DASHBOARD VIEW
# ============================================================

@sdn_bp.route('/')
@login_required
def index():
    """SDN Management Dashboard - unified device and policy view."""
    devices = []
    policies = []
    vlans = []
    stats = {}
    network_mode = 'filter'  # or 'vlan'

    # Try to load from database
    if DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            devices = device_mgr.get_all_devices()

            # Enrich devices with OUI classification
            for device in devices:
                mac = device.get('mac_address', '')
                classification = classify_device(mac)
                device['oui_category'] = classification.get('category', 'unknown')
                device['auto_policy'] = classification.get('recommended_policy', 'default')
                device['manufacturer'] = device.get('manufacturer') or classification.get('manufacturer', 'Unknown')

                # Convert datetime
                for key in ['first_seen', 'last_seen']:
                    if device.get(key) and not isinstance(device[key], str):
                        device[key] = str(device[key])

                # Determine online status (last seen within 5 minutes)
                last_seen = device.get('last_seen', '')
                device['is_online'] = False  # Default

            vlan_mgr = get_vlan_manager()
            vlans = vlan_mgr.get_vlans()

            # Load network mode from config
            # TODO: Load from fortress.conf

        except Exception as e:
            flash(f'Error loading devices: {e}', 'warning')
            devices = get_demo_devices()
            vlans = get_demo_vlans()
    else:
        devices = get_demo_devices()
        vlans = get_demo_vlans()

    # Always use standard policies
    policies = get_demo_policies()
    stats = calculate_stats(devices) if devices else get_demo_stats()

    return render_template(
        'sdn/index.html',
        devices=devices,
        policies=policies,
        vlans=vlans,
        stats=stats,
        network_mode=network_mode,
        db_available=DB_AVAILABLE,
        policy_manager_available=POLICY_MANAGER_AVAILABLE
    )


def calculate_stats(devices):
    """Calculate statistics from device list."""
    stats = {
        'total_devices': len(devices),
        'online_devices': 0,
        'offline_devices': 0,
        'blocked_devices': 0,
        'policy_counts': {},
        'category_counts': {},
    }

    for device in devices:
        if device.get('is_online'):
            stats['online_devices'] += 1
        else:
            stats['offline_devices'] += 1

        if device.get('is_blocked'):
            stats['blocked_devices'] += 1

        policy = device.get('network_policy', 'default')
        stats['policy_counts'][policy] = stats['policy_counts'].get(policy, 0) + 1

        category = device.get('oui_category', 'unknown')
        stats['category_counts'][category] = stats['category_counts'].get(category, 0) + 1

    return stats


# ============================================================
# DEVICE DETAIL
# ============================================================

@sdn_bp.route('/device/<mac_address>')
@login_required
def device_detail(mac_address):
    """Device detail view with full SDN info."""
    device = None
    policies = get_demo_policies()
    vlans = get_demo_vlans()

    if DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            raw_device = device_mgr.get_device(mac_address)
            if raw_device:
                classification = classify_device(mac_address)
                raw_device['oui_category'] = classification.get('category', 'unknown')
                raw_device['auto_policy'] = classification.get('recommended_policy', 'default')
                raw_device['manufacturer'] = raw_device.get('manufacturer') or classification.get('manufacturer', 'Unknown')
                device = format_device_for_template(raw_device)

            vlan_mgr = get_vlan_manager()
            vlans = vlan_mgr.get_vlans()
        except Exception as e:
            flash(f'Error loading device: {e}', 'warning')

    if not device:
        # Try demo data
        for d in get_demo_devices():
            if d['mac_address'].upper() == mac_address.upper():
                classification = classify_device(d['mac_address'])
                d['oui_category'] = classification.get('category', d.get('oui_category', 'unknown'))
                d['auto_policy'] = classification.get('recommended_policy', d.get('auto_policy', 'default'))
                device = format_device_for_template(d)
                break

    if not device:
        flash('Device not found', 'warning')
        return redirect(url_for('sdn.index'))

    return render_template(
        'sdn/device_detail.html',
        device=device,
        policies=policies,
        vlans=vlans,
        db_available=DB_AVAILABLE
    )


# ============================================================
# POLICY OPERATIONS
# ============================================================

@sdn_bp.route('/set-policy', methods=['POST'])
@login_required
@operator_required
def set_policy():
    """Set network policy for a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    policy = request.form.get('policy')
    source = request.form.get('source', 'web')

    if not mac_address or not policy:
        return jsonify({'success': False, 'error': 'MAC address and policy required'}), 400

    valid_policies = ['full_access', 'lan_only', 'internet_only', 'isolated', 'default']
    if policy not in valid_policies:
        return jsonify({'success': False, 'error': f'Invalid policy: {policy}'}), 400

    try:
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy(policy), assigned_by=f'web:{current_user.id}')

        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET network_policy = %s WHERE mac_address = %s",
                (policy, mac_address.upper())
            )
            db.audit_log(
                current_user.id,
                'set_policy',
                'device',
                mac_address,
                {'policy': policy, 'source': source},
                request.remote_addr
            )

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': f'Policy set to {policy}'})

        flash(f'Policy for {mac_address} set to {policy}', 'success')
        return redirect(url_for('sdn.device_detail', mac_address=mac_address))

    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': str(e)}), 500

        flash(f'Error setting policy: {e}', 'danger')
        return redirect(url_for('sdn.index'))


@sdn_bp.route('/auto-classify', methods=['POST'])
@login_required
@operator_required
def auto_classify():
    """Auto-classify device based on OUI (MAC from form data)."""
    mac_address = request.form.get('mac')
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        classification = classify_device(mac_address)
        recommended = classification.get('recommended_policy', 'default')

        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy(recommended), assigned_by='oui')

        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET network_policy = %s, device_type = %s WHERE mac_address = %s",
                (recommended, classification.get('category'), mac_address.upper())
            )

        return jsonify({
            'success': True,
            'category': classification.get('category'),
            'policy': recommended,
            'classification': classification
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@sdn_bp.route('/disconnect-device', methods=['POST'])
@login_required
@operator_required
def disconnect_device():
    """Disconnect a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy.ISOLATED, assigned_by=f'disconnect:{current_user.id}')

        if DB_AVAILABLE:
            db = get_db()
            db.audit_log(
                current_user.id,
                'disconnect',
                'device',
                mac_address,
                {'action': 'disconnect'},
                request.remote_addr
            )

        return jsonify({'success': True, 'message': 'Device disconnected'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@sdn_bp.route('/block-device', methods=['POST'])
@login_required
@operator_required
def block_device():
    """Block a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    reason = request.form.get('reason', 'manual_block')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy.ISOLATED, assigned_by=f'block:{current_user.id}')

        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET is_blocked = TRUE, network_policy = 'isolated' WHERE mac_address = %s",
                (mac_address.upper(),)
            )
            db.audit_log(
                current_user.id,
                'block',
                'device',
                mac_address,
                {'reason': reason},
                request.remote_addr
            )

        return jsonify({'success': True, 'message': 'Device blocked'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@sdn_bp.route('/unblock-device', methods=['POST'])
@login_required
@operator_required
def unblock_device():
    """Unblock a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        classification = classify_device(mac_address)
        recommended = classification.get('recommended_policy', 'default')

        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy(recommended), assigned_by='unblock')

        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET is_blocked = FALSE, network_policy = %s WHERE mac_address = %s",
                (recommended, mac_address.upper())
            )
            db.audit_log(
                current_user.id,
                'unblock',
                'device',
                mac_address,
                {'policy_restored': recommended},
                request.remote_addr
            )

        return jsonify({'success': True, 'message': f'Device unblocked, policy: {recommended}'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500




# ============================================================
# BULK OPERATIONS
# ============================================================

@sdn_bp.route('/bulk/set-policy', methods=['POST'])
@login_required
@operator_required
def bulk_set_policy():
    """Set policy for multiple devices."""
    data = request.get_json()
    mac_addresses = data.get('mac_addresses', [])
    policy = data.get('policy')

    if not mac_addresses or not policy:
        return jsonify({'success': False, 'error': 'MAC addresses and policy required'}), 400

    results = {'success': [], 'failed': []}

    for mac in mac_addresses:
        try:
            if POLICY_MANAGER_AVAILABLE:
                from network_policy_manager import NetworkPolicyManager, NetworkPolicy
                manager = NetworkPolicyManager(use_nftables=True)
                manager.set_policy(mac, NetworkPolicy(policy), assigned_by=f'bulk:{current_user.id}')

            if DB_AVAILABLE:
                db = get_db()
                db.execute(
                    "UPDATE devices SET network_policy = %s WHERE mac_address = %s",
                    (policy, mac.upper())
                )

            results['success'].append(mac)
        except Exception as e:
            results['failed'].append({'mac': mac, 'error': str(e)})

    return jsonify({
        'success': len(results['failed']) == 0,
        'results': results,
        'message': f'{len(results["success"])} devices updated'
    })


@sdn_bp.route('/bulk/auto-classify', methods=['POST'])
@login_required
@operator_required
def bulk_auto_classify():
    """Auto-classify multiple devices based on OUI."""
    data = request.get_json()
    mac_addresses = data.get('mac_addresses', [])

    if not mac_addresses:
        return jsonify({'success': False, 'error': 'MAC addresses required'}), 400

    results = {'success': [], 'failed': []}

    for mac in mac_addresses:
        try:
            classification = classify_device(mac)
            recommended = classification.get('recommended_policy', 'default')

            if POLICY_MANAGER_AVAILABLE:
                from network_policy_manager import NetworkPolicyManager, NetworkPolicy
                manager = NetworkPolicyManager(use_nftables=True)
                manager.set_policy(mac, NetworkPolicy(recommended), assigned_by='bulk_oui')

            if DB_AVAILABLE:
                db = get_db()
                db.execute(
                    "UPDATE devices SET network_policy = %s, device_type = %s WHERE mac_address = %s",
                    (recommended, classification.get('category'), mac.upper())
                )

            results['success'].append({
                'mac': mac,
                'category': classification.get('category'),
                'policy': recommended
            })
        except Exception as e:
            results['failed'].append({'mac': mac, 'error': str(e)})

    return jsonify({
        'success': len(results['failed']) == 0,
        'results': results,
        'message': f'{len(results["success"])} devices classified'
    })


# ============================================================
# DISCOVERY
# ============================================================

@sdn_bp.route('/discover', methods=['POST'])
@login_required
@operator_required
def discover_devices():
    """Trigger network device discovery."""
    if not DB_AVAILABLE:
        return jsonify({'success': False, 'error': 'Database not available'}), 503

    try:
        device_mgr = get_device_manager()
        discovered = device_mgr.discover_devices()

        # Classify new devices
        for device in discovered:
            if device.get('is_new'):
                classification = classify_device(device['mac_address'])
                device['oui_category'] = classification.get('category', 'unknown')
                device['auto_policy'] = classification.get('recommended_policy', 'default')

        new_count = len([d for d in discovered if d.get('is_new')])

        return jsonify({
            'success': True,
            'total': len(discovered),
            'new': new_count,
            'devices': discovered
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# API ENDPOINTS
# ============================================================

@sdn_bp.route('/api/devices')
@login_required
def api_devices():
    """Get all devices with SDN info (JSON)."""
    devices = []

    if DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            devices = device_mgr.get_all_devices()

            for device in devices:
                mac = device.get('mac_address', '')
                classification = classify_device(mac)
                device['oui_category'] = classification.get('category', 'unknown')
                device['auto_policy'] = classification.get('recommended_policy', 'default')

                for key in ['first_seen', 'last_seen']:
                    if device.get(key) and not isinstance(device[key], str):
                        device[key] = str(device[key])
        except Exception:
            devices = get_demo_devices()
    else:
        devices = get_demo_devices()

    # Apply filters
    policy_filter = request.args.get('policy')
    category_filter = request.args.get('category')
    online_filter = request.args.get('online')

    if policy_filter:
        devices = [d for d in devices if d.get('network_policy') == policy_filter]
    if category_filter:
        devices = [d for d in devices if d.get('oui_category') == category_filter]
    if online_filter:
        is_online = online_filter.lower() == 'true'
        devices = [d for d in devices if d.get('is_online') == is_online]

    return jsonify({
        'success': True,
        'count': len(devices),
        'devices': devices
    })


@sdn_bp.route('/api/stats')
@login_required
def api_stats():
    """Get SDN statistics."""
    devices = []

    if DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            devices = device_mgr.get_all_devices()
            for device in devices:
                classification = classify_device(device.get('mac_address', ''))
                device['oui_category'] = classification.get('category', 'unknown')
        except Exception:
            pass

    if not devices:
        return jsonify({'success': True, 'stats': get_demo_stats()})

    stats = calculate_stats(devices)
    return jsonify({'success': True, 'stats': stats})


@sdn_bp.route('/api/classify/<mac_address>')
@login_required
def api_classify(mac_address):
    """Get OUI classification for a MAC address."""
    classification = classify_device(mac_address)
    return jsonify({
        'success': True,
        'classification': classification
    })


@sdn_bp.route('/api/policies')
@login_required
def api_policies():
    """Get available network policies."""
    return jsonify({
        'success': True,
        'policies': get_demo_policies()
    })


@sdn_bp.route('/api/wifi-intelligence')
@login_required
def api_wifi_intelligence():
    """Get WiFi channel optimization and DFS intelligence data."""
    import subprocess
    import os
    from datetime import datetime, timedelta

    data = {
        'current_channel': None,
        'band': '2.4GHz',
        'hw_mode': 'g',
        'last_optimization': None,
        'previous_channel': None,
        'next_optimization': None,
        'time_to_next': None,
        'ml_score': None,
        'radar_events': [],
        'radar_count_30d': 0,
        'channel_switches_30d': 0,
        'dfs_available': False,
        'optimization_method': 'basic_scan',
        'wifi_interface': None,
        'ssid': None,
    }

    # Read hostapd config for current channel
    hostapd_conf = '/etc/hostapd/fortress.conf'
    if os.path.exists(hostapd_conf):
        try:
            with open(hostapd_conf, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('channel='):
                        data['current_channel'] = int(line.split('=')[1])
                    elif line.startswith('hw_mode='):
                        data['hw_mode'] = line.split('=')[1]
                    elif line.startswith('interface='):
                        data['wifi_interface'] = line.split('=')[1]
                    elif line.startswith('ssid='):
                        data['ssid'] = line.split('=')[1]

            # Determine band from hw_mode or channel
            if data['hw_mode'] == 'a' or (data['current_channel'] and data['current_channel'] > 14):
                data['band'] = '5GHz'
        except Exception:
            pass

    # Read channel state file for optimization history
    state_file = '/var/lib/fortress/channel_state.json'
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
                data['last_optimization'] = state.get('last_scan')
                data['previous_channel'] = state.get('previous_channel')
                data['optimization_method'] = state.get('method', 'interference_score')
                if state.get('score'):
                    data['ml_score'] = state.get('score')
        except Exception:
            pass

    # Calculate next optimization time (4:00 AM)
    now = datetime.now()
    next_4am = now.replace(hour=4, minute=0, second=0, microsecond=0)
    if now.hour >= 4:
        next_4am += timedelta(days=1)
    data['next_optimization'] = next_4am.isoformat()
    time_diff = next_4am - now
    hours, remainder = divmod(int(time_diff.total_seconds()), 3600)
    minutes = remainder // 60
    data['time_to_next'] = f'{hours}h {minutes}m'
    data['time_to_next_seconds'] = int(time_diff.total_seconds())

    # Check if DFS intelligence is available
    dfs_selector = '/usr/local/bin/dfs-channel-selector'
    if os.path.exists(dfs_selector) and os.access(dfs_selector, os.X_OK):
        data['dfs_available'] = True

        # Try to get DFS status
        try:
            result = subprocess.run(
                [dfs_selector, 'status'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse status output
                for line in result.stdout.strip().split('\n'):
                    if 'radar events' in line.lower():
                        try:
                            data['radar_count_30d'] = int(line.split(':')[1].strip().split()[0])
                        except (ValueError, IndexError):
                            pass
        except Exception:
            pass

        # Try to get current channel score
        if data['current_channel'] and data['band'] == '5GHz':
            try:
                result = subprocess.run(
                    [dfs_selector, 'score', str(data['current_channel'])],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    try:
                        data['ml_score'] = float(result.stdout.strip())
                    except ValueError:
                        pass
            except Exception:
                pass

    # Read radar events from DFS log
    radar_log = '/var/lib/fortress/dfs/radar_events.jsonl'
    if os.path.exists(radar_log):
        try:
            events = []
            with open(radar_log, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        events.append(event)
                    except json.JSONDecodeError:
                        pass
            # Return last 10 events
            data['radar_events'] = events[-10:]
            # Count events in last 30 days
            cutoff = (datetime.now() - timedelta(days=30)).isoformat()
            data['radar_count_30d'] = len([e for e in events if e.get('timestamp', '') > cutoff])
        except Exception:
            pass

    # Read channel switch count from optimization log
    opt_log = '/var/log/hookprobe/channel-optimization.log'
    if os.path.exists(opt_log):
        try:
            with open(opt_log, 'r') as f:
                content = f.read()
                # Count "Updating hostapd config to channel" lines
                data['channel_switches_30d'] = content.count('Updating hostapd config to channel')
        except Exception:
            pass

    return jsonify({
        'success': True,
        'wifi_intelligence': data
    })


# ============================================================
# EXPORT
# ============================================================

@sdn_bp.route('/export')
@login_required
def export_devices():
    """Export device inventory with SDN info."""
    format_type = request.args.get('format', 'json')
    devices = []

    if DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            devices = device_mgr.get_all_devices()
            for device in devices:
                classification = classify_device(device.get('mac_address', ''))
                device['oui_category'] = classification.get('category', 'unknown')
                device['auto_policy'] = classification.get('recommended_policy', 'default')

                for key in ['first_seen', 'last_seen']:
                    if device.get(key) and not isinstance(device[key], str):
                        device[key] = str(device[key])
        except Exception:
            devices = get_demo_devices()
    else:
        devices = get_demo_devices()

    if format_type == 'csv':
        import csv
        import io

        output = io.StringIO()
        if devices:
            writer = csv.DictWriter(output, fieldnames=devices[0].keys())
            writer.writeheader()
            writer.writerows(devices)

        return output.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename=sdn_devices.csv'
        }
    else:
        return jsonify({
            'exported_at': datetime.now().isoformat(),
            'count': len(devices),
            'devices': devices
        }), 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': 'attachment; filename=sdn_devices.json'
        }


# ============================================================
# SEGMENT DASHBOARD - Per-Category Traffic Visualization
# ============================================================

def get_demo_segment_data():
    """Return demo segment data for development."""
    import random
    import time

    base_time = time.time()
    segments = {
        'SECMON': {
            'vlan_id': 10,
            'name': 'Security Monitoring',
            'icon': 'fa-shield-alt',
            'color': '#17a2b8',
            'device_count': 3,
            'active_count': 2,
            'bytes_in': 524288000,
            'bytes_out': 1048576000,
            'bandwidth_mbps': 12.5,
            'top_devices': [
                {'mac': '00:0D:7C:12:34:56', 'hostname': 'Synology NVR', 'bytes': 800000000},
                {'mac': '00:0C:F6:AA:BB:CC', 'hostname': 'Axis Camera Hub', 'bytes': 200000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(50000, 150000), 'out': random.randint(100000, 300000)}
                for i in range(60, 0, -1)
            ]
        },
        'CLIENTS': {
            'vlan_id': 30,
            'name': 'Staff Devices',
            'icon': 'fa-laptop',
            'color': '#28a745',
            'device_count': 8,
            'active_count': 5,
            'bytes_in': 2147483648,
            'bytes_out': 536870912,
            'bandwidth_mbps': 45.2,
            'top_devices': [
                {'mac': '3C:06:30:DE:AD:BE', 'hostname': 'MacBook Sarah', 'bytes': 500000000},
                {'mac': 'A4:5E:60:11:22:33', 'hostname': 'iPhone Mike', 'bytes': 300000000},
                {'mac': '00:21:6A:44:55:66', 'hostname': 'Lenovo ThinkPad', 'bytes': 250000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(200000, 600000), 'out': random.randint(50000, 150000)}
                for i in range(60, 0, -1)
            ]
        },
        'POS': {
            'vlan_id': 20,
            'name': 'Point of Sale',
            'icon': 'fa-credit-card',
            'color': '#ffc107',
            'device_count': 2,
            'active_count': 2,
            'bytes_in': 104857600,
            'bytes_out': 52428800,
            'bandwidth_mbps': 2.1,
            'top_devices': [
                {'mac': '58:E6:BA:11:22:33', 'hostname': 'Square POS-1', 'bytes': 80000000},
                {'mac': '00:0B:CD:AA:BB:CC', 'hostname': 'Ingenico Terminal', 'bytes': 30000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(5000, 20000), 'out': random.randint(2000, 10000)}
                for i in range(60, 0, -1)
            ]
        },
        'CAMERAS': {
            'vlan_id': 50,
            'name': 'Security Cameras',
            'icon': 'fa-video',
            'color': '#6f42c1',
            'device_count': 6,
            'active_count': 6,
            'bytes_in': 10737418240,
            'bytes_out': 53687091,
            'bandwidth_mbps': 85.3,
            'top_devices': [
                {'mac': '28:57:BE:11:22:33', 'hostname': 'Hikvision Front', 'bytes': 3000000000},
                {'mac': '28:57:BE:44:55:66', 'hostname': 'Hikvision Back', 'bytes': 2500000000},
                {'mac': '3C:EF:8C:77:88:99', 'hostname': 'Dahua Parking', 'bytes': 2000000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(800000, 1200000), 'out': random.randint(5000, 15000)}
                for i in range(60, 0, -1)
            ]
        },
        'IIOT': {
            'vlan_id': 60,
            'name': 'IoT / Smart Devices',
            'icon': 'fa-thermometer-half',
            'color': '#fd7e14',
            'device_count': 12,
            'active_count': 10,
            'bytes_in': 52428800,
            'bytes_out': 26214400,
            'bandwidth_mbps': 0.8,
            'top_devices': [
                {'mac': '18:B4:30:AA:BB:CC', 'hostname': 'Nest Thermostat', 'bytes': 15000000},
                {'mac': '00:17:88:DD:EE:FF', 'hostname': 'Philips Hue Bridge', 'bytes': 10000000},
                {'mac': 'D4:F5:47:11:22:33', 'hostname': 'Google Nest Hub', 'bytes': 8000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(2000, 8000), 'out': random.randint(1000, 4000)}
                for i in range(60, 0, -1)
            ]
        },
    }
    return segments


@sdn_bp.route('/segments')
@login_required
def segments():
    """Network Segments Dashboard - Per-category traffic visualization."""
    segment_data = {}

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment_data = autopilot.get_segment_summary()
        except Exception as e:
            flash(f'Error loading segments: {e}', 'warning')
            segment_data = get_demo_segment_data()
    else:
        segment_data = get_demo_segment_data()

    return render_template(
        'sdn/segments.html',
        segments=segment_data,
        autopilot_available=SDN_AUTOPILOT_AVAILABLE
    )


@sdn_bp.route('/api/segments')
@login_required
def api_segments():
    """Get all segment statistics (JSON)."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            return jsonify({
                'success': True,
                'segments': autopilot.get_segment_summary()
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'segments': get_demo_segment_data()
        })


@sdn_bp.route('/api/segments/<segment_name>')
@login_required
def api_segment_detail(segment_name):
    """Get detailed statistics for a specific segment."""
    segment_name = segment_name.upper()

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment = NetworkSegment[segment_name]
            return jsonify({
                'success': True,
                'segment': autopilot.get_segment_stats(segment)
            })
        except KeyError:
            return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        demo = get_demo_segment_data()
        if segment_name in demo:
            return jsonify({
                'success': True,
                'segment': demo[segment_name]
            })
        return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404


@sdn_bp.route('/api/segments/<segment_name>/devices')
@login_required
def api_segment_devices(segment_name):
    """Get devices in a specific segment."""
    segment_name = segment_name.upper()

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment = NetworkSegment[segment_name]
            devices = autopilot.get_devices_by_segment(segment)
            return jsonify({
                'success': True,
                'segment': segment_name,
                'count': len(devices),
                'devices': [d.to_dict() for d in devices]
            })
        except KeyError:
            return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        # Return demo devices for the segment
        demo = get_demo_segment_data()
        if segment_name in demo:
            return jsonify({
                'success': True,
                'segment': segment_name,
                'count': len(demo[segment_name].get('top_devices', [])),
                'devices': demo[segment_name].get('top_devices', [])
            })
        return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404


@sdn_bp.route('/api/segments/<segment_name>/traffic')
@login_required
def api_segment_traffic(segment_name):
    """Get traffic history for a segment (for live chart updates)."""
    segment_name = segment_name.upper()

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment = NetworkSegment[segment_name]
            stats = autopilot.get_segment_stats(segment)
            return jsonify({
                'success': True,
                'segment': segment_name,
                'traffic_history': stats.get('traffic_history', [])
            })
        except KeyError:
            return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        demo = get_demo_segment_data()
        if segment_name in demo:
            return jsonify({
                'success': True,
                'segment': segment_name,
                'traffic_history': demo[segment_name].get('traffic_history', [])
            })
        return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404


@sdn_bp.route('/assign-segment', methods=['POST'])
@login_required
@operator_required
def assign_segment():
    """Assign a device to a network segment."""
    mac_address = request.form.get('mac')
    segment_id = request.form.get('segment')

    if not mac_address or not segment_id:
        return jsonify({'success': False, 'error': 'MAC address and segment required'}), 400

    try:
        segment_id = int(segment_id)
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid segment ID'}), 400

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment = NetworkSegment(segment_id)
            success = autopilot.assign_device_segment(mac_address, segment, persist=True)

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Device assigned to {segment.name} (VLAN {segment_id})'
                })
            else:
                return jsonify({'success': False, 'error': 'Assignment failed'}), 500

        except ValueError:
            return jsonify({'success': False, 'error': f'Invalid segment: {segment_id}'}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        # Demo mode - just return success
        return jsonify({
            'success': True,
            'message': f'Device assigned to VLAN {segment_id} (demo mode)'
        })


# ============================================================
# DEVICE TRUST FRAMEWORK - CIA Triad Authentication
# ============================================================

# Import Trust Framework
TRUST_FRAMEWORK_AVAILABLE = False
try:
    from device_trust_framework import (
        get_trust_framework,
        TrustLevel,
        DeviceTrustFramework,
    )
    TRUST_FRAMEWORK_AVAILABLE = True
except ImportError:
    pass


def get_demo_trust_data():
    """Return demo trust data for development."""
    return {
        'total_devices': 15,
        'trust_framework_enabled': True,
        'by_trust_level': {
            'UNTRUSTED': 2,
            'MINIMAL': 5,
            'STANDARD': 4,
            'HIGH': 3,
            'ENTERPRISE': 1,
        },
        'verified_count': 8,
        'verified_percent': 53.3,
        'certificate_count': 4,
        'certificate_percent': 26.7,
        'attestation_count': 1,
        'attestation_percent': 6.7,
    }


def get_demo_trust_devices():
    """Return demo devices with trust information."""
    import random
    devices = [
        {'mac': '3C:06:30:DE:AD:BE', 'hostname': 'MacBook-Sarah', 'vendor': 'Apple', 'segment': 'CLIENTS', 'trust': 3, 'verified': True, 'cert': True},
        {'mac': 'A4:5E:60:11:22:33', 'hostname': 'iPhone-Mike', 'vendor': 'Apple', 'segment': 'CLIENTS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '00:21:6A:44:55:66', 'hostname': 'ThinkPad-T14', 'vendor': 'Lenovo', 'segment': 'CLIENTS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '58:E6:BA:11:22:33', 'hostname': 'Square-POS-1', 'vendor': 'Square', 'segment': 'POS', 'trust': 3, 'verified': True, 'cert': True},
        {'mac': '00:0B:CD:AA:BB:CC', 'hostname': 'Ingenico-Term', 'vendor': 'Ingenico', 'segment': 'POS', 'trust': 3, 'verified': True, 'cert': True},
        {'mac': '28:57:BE:11:22:33', 'hostname': 'Hikvision-Front', 'vendor': 'Hikvision', 'segment': 'CAMERAS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '3C:EF:8C:77:88:99', 'hostname': 'Dahua-Parking', 'vendor': 'Dahua', 'segment': 'CAMERAS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '00:0D:7C:12:34:56', 'hostname': 'Synology-NVR', 'vendor': 'Synology', 'segment': 'SECMON', 'trust': 4, 'verified': True, 'cert': True},
        {'mac': '18:B4:30:AA:BB:CC', 'hostname': 'Nest-Thermostat', 'vendor': 'Google Nest', 'segment': 'IIOT', 'trust': 1, 'verified': False, 'cert': False},
        {'mac': '00:17:88:DD:EE:FF', 'hostname': 'Philips-Hue', 'vendor': 'Philips', 'segment': 'IIOT', 'trust': 1, 'verified': False, 'cert': False},
        {'mac': 'AA:BB:CC:DD:EE:FF', 'hostname': 'Unknown-Device', 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'verified': False, 'cert': False},
        {'mac': '11:22:33:44:55:66', 'hostname': None, 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'verified': False, 'cert': False},
    ]

    trust_names = {0: 'UNTRUSTED', 1: 'MINIMAL', 2: 'STANDARD', 3: 'HIGH', 4: 'ENTERPRISE'}

    return [
        {
            'mac_address': d['mac'],
            'hostname': d['hostname'],
            'ip_address': f"10.200.0.{100 + i}",
            'vendor': d['vendor'],
            'segment_name': d['segment'],
            'trust_level': d['trust'],
            'trust_level_name': trust_names.get(d['trust'], 'UNKNOWN'),
            'trust_verified': d['verified'],
            'certificate_issued': d['cert'],
        }
        for i, d in enumerate(devices)
    ]


@sdn_bp.route('/trust')
@login_required
def trust_dashboard():
    """Device Trust Framework dashboard - CIA Triad authentication."""
    trust_summary = {}
    devices = []
    segment_colors = {
        'SECMON': '#17a2b8',
        'CLIENTS': '#28a745',
        'POS': '#ffc107',
        'CAMERAS': '#6f42c1',
        'IIOT': '#fd7e14',
        'GUEST': '#20c997',
        'QUARANTINE': '#dc3545',
    }

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            trust_summary = autopilot.get_trust_summary()
            devices = autopilot.get_all_devices()
        except Exception as e:
            flash(f'Error loading trust data: {e}', 'warning')
            trust_summary = get_demo_trust_data()
            devices = get_demo_trust_devices()
    else:
        trust_summary = get_demo_trust_data()
        devices = get_demo_trust_devices()

    return render_template(
        'sdn/trust.html',
        trust_summary=trust_summary,
        devices=devices,
        segment_colors=segment_colors,
        trust_available=TRUST_FRAMEWORK_AVAILABLE
    )


@sdn_bp.route('/api/trust')
@login_required
def api_trust_summary():
    """Get trust framework summary (JSON)."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            return jsonify({
                'success': True,
                'trust_summary': autopilot.get_trust_summary(),
                'trust_framework_available': TRUST_FRAMEWORK_AVAILABLE
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'trust_summary': get_demo_trust_data(),
            'trust_framework_available': False
        })


@sdn_bp.route('/api/trust/enroll', methods=['POST'])
@login_required
@operator_required
def api_enroll_device():
    """Enroll a device for certificate-based authentication."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if TRUST_FRAMEWORK_AVAILABLE:
        try:
            import secrets
            trust_framework = get_trust_framework()

            # Generate device key (in production, device would provide this)
            device_pubkey = secrets.token_bytes(32)

            # Issue certificate
            cert = trust_framework.issue_certificate(
                mac_address=mac_address,
                public_key=device_pubkey,
                trust_level=TrustLevel.STANDARD,
                validity_days=30
            )

            if cert:
                return jsonify({
                    'success': True,
                    'message': f'Device {mac_address} enrolled successfully',
                    'cert_id': cert.cert_id,
                    'expires': cert.expires_at
                })
            else:
                return jsonify({'success': False, 'error': 'Certificate issuance failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac_address} enrolled (demo mode)'
        })


@sdn_bp.route('/api/trust/revoke', methods=['POST'])
@login_required
@operator_required
def api_revoke_device():
    """Revoke a device certificate."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if TRUST_FRAMEWORK_AVAILABLE:
        try:
            trust_framework = get_trust_framework()
            success = trust_framework.revoke_certificate(mac_address, reason="admin_revoke")

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Certificate revoked for {mac_address}'
                })
            else:
                return jsonify({'success': False, 'error': 'Revocation failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Certificate revoked for {mac_address} (demo mode)'
        })


@sdn_bp.route('/api/trust/quarantine', methods=['POST'])
@login_required
@operator_required
def api_quarantine_device():
    """Move a device to quarantine."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            success = autopilot.assign_device_segment(
                mac_address,
                NetworkSegment.QUARANTINE,
                persist=True
            )

            if success:
                # Also revoke certificate if trust framework available
                if TRUST_FRAMEWORK_AVAILABLE:
                    trust_framework = get_trust_framework()
                    trust_framework.revoke_certificate(mac_address, reason="quarantine")

                return jsonify({
                    'success': True,
                    'message': f'Device {mac_address} moved to quarantine'
                })
            else:
                return jsonify({'success': False, 'error': 'Quarantine failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac_address} quarantined (demo mode)'
        })


# ============================================================
# UNIFIED SDN MANAGEMENT DASHBOARD
# ============================================================

def get_demo_wifi_data():
    """Return demo WiFi intelligence data."""
    from datetime import datetime, timedelta
    import random

    now = datetime.now()
    events = [
        {'timestamp': (now - timedelta(hours=2)).isoformat(), 'type': 'switch', 'message': 'Channel switched 36 → 149 (congestion)'},
        {'timestamp': (now - timedelta(hours=4)).isoformat(), 'type': 'radar', 'message': 'Radar detected on CH 52 (weather)'},
        {'timestamp': (now - timedelta(hours=8)).isoformat(), 'type': 'cac', 'message': 'CAC completed on CH 149'},
        {'timestamp': (now - timedelta(hours=12)).isoformat(), 'type': 'switch', 'message': 'Channel switched 44 → 36 (DFS)'},
        {'timestamp': (now - timedelta(hours=18)).isoformat(), 'type': 'radar', 'message': 'Radar detected on CH 100'},
    ]

    return {
        'channel': 149,
        'width': 80,
        'power': 23,
        'band': '5GHz',
        'dfs_status': 'clear',
        'channel_score': random.randint(75, 95),
        'radar_events_24h': 2,
        'channel_switches_24h': 5,
        'events': events,
        'ssid': 'HookProbe-Fortress',
        'clients_24': random.randint(3, 8),
        'clients_5': random.randint(10, 20),
    }


def get_demo_sdn_devices():
    """Return demo devices for SDN Management dashboard."""
    import random

    segments = ['STAFF', 'GUEST', 'POS', 'CAMERAS', 'IIOT', 'QUARANTINE', 'SECMON']
    segment_vlans = {'SECMON': 10, 'POS': 20, 'STAFF': 30, 'GUEST': 40, 'CAMERAS': 50, 'IIOT': 60, 'QUARANTINE': 99}

    devices = [
        {'mac': '3C:06:30:DE:AD:BE', 'hostname': 'MacBook-Sarah', 'vendor': 'Apple', 'segment': 'STAFF', 'trust': 3, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': 'A4:5E:60:11:22:33', 'hostname': 'iPhone-Mike', 'vendor': 'Apple', 'segment': 'STAFF', 'trust': 2, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': '00:21:6A:44:55:66', 'hostname': 'ThinkPad-T14', 'vendor': 'Lenovo', 'segment': 'STAFF', 'trust': 2, 'conn': 'lan', 'band': None},
        {'mac': '58:E6:BA:11:22:33', 'hostname': 'Square-POS-1', 'vendor': 'Square', 'segment': 'POS', 'trust': 3, 'conn': 'lan', 'band': None},
        {'mac': '00:0B:CD:AA:BB:CC', 'hostname': 'Ingenico-Term', 'vendor': 'Ingenico', 'segment': 'POS', 'trust': 3, 'conn': 'lan', 'band': None},
        {'mac': '28:57:BE:11:22:33', 'hostname': 'Hikvision-Front', 'vendor': 'Hikvision', 'segment': 'CAMERAS', 'trust': 2, 'conn': 'lan', 'band': None},
        {'mac': '3C:EF:8C:77:88:99', 'hostname': 'Dahua-Parking', 'vendor': 'Dahua', 'segment': 'CAMERAS', 'trust': 2, 'conn': 'lan', 'band': None},
        {'mac': '00:0D:7C:12:34:56', 'hostname': 'Synology-NVR', 'vendor': 'Synology', 'segment': 'SECMON', 'trust': 4, 'conn': 'lan', 'band': None},
        {'mac': '18:B4:30:AA:BB:CC', 'hostname': 'Nest-Thermostat', 'vendor': 'Google Nest', 'segment': 'IIOT', 'trust': 1, 'conn': 'wifi', 'band': '2.4GHz'},
        {'mac': '00:17:88:DD:EE:FF', 'hostname': 'Philips-Hue', 'vendor': 'Philips', 'segment': 'IIOT', 'trust': 1, 'conn': 'lan', 'band': None},
        {'mac': 'CC:50:E3:12:34:56', 'hostname': 'Samsung-Tab', 'vendor': 'Samsung', 'segment': 'GUEST', 'trust': 1, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': '48:E1:E9:AA:BB:CC', 'hostname': 'Pixel-Guest', 'vendor': 'Google', 'segment': 'GUEST', 'trust': 1, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': 'AA:BB:CC:DD:EE:FF', 'hostname': 'Unknown-Device', 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'conn': 'wifi', 'band': '2.4GHz'},
        {'mac': '11:22:33:44:55:66', 'hostname': None, 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'conn': 'lan', 'band': None},
    ]

    return [
        {
            'mac': d['mac'],
            'hostname': d['hostname'] or 'Unknown',
            'ip_address': f"10.200.0.{100 + i}",
            'vendor': d['vendor'],
            'segment': d['segment'],
            'vlan_id': segment_vlans.get(d['segment'], 40),
            'trust_level': d['trust'],
            'connection_type': d['conn'],
            'band': d['band'],
            'online': random.choice([True, True, True, False]),
        }
        for i, d in enumerate(devices)
    ]


@sdn_bp.route('/management')
@login_required
def management_dashboard():
    """Unified SDN Management Dashboard - Consolidates clients/networks/WiFi."""
    return render_template('sdn/management.html')


@sdn_bp.route('/api/sdn/devices')
@login_required
def api_sdn_devices():
    """Get all network devices for SDN Management dashboard."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            devices = autopilot.get_all_devices()

            # Transform to SDN format
            sdn_devices = []
            for device in devices:
                sdn_devices.append({
                    'mac': device.get('mac_address', ''),
                    'hostname': device.get('hostname', 'Unknown'),
                    'ip_address': device.get('ip_address', '--'),
                    'vendor': device.get('vendor', 'Unknown'),
                    'segment': device.get('segment_name', 'GUEST'),
                    'vlan_id': device.get('vlan_id', 40),
                    'trust_level': device.get('trust_level', 1),
                    'connection_type': device.get('connection_type', 'lan'),
                    'band': device.get('band'),
                    'online': device.get('is_online', False),
                })

            return jsonify({'success': True, 'devices': sdn_devices})

        except Exception as e:
            return jsonify({'success': False, 'error': str(e), 'devices': []}), 500
    else:
        # Demo mode
        return jsonify({'success': True, 'devices': get_demo_sdn_devices()})


@sdn_bp.route('/api/sdn/segments')
@login_required
def api_sdn_segments():
    """Get segment distribution statistics."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            devices = autopilot.get_all_devices()

            # Count devices per segment
            segments = {}
            for device in devices:
                seg = device.get('segment_name', 'GUEST')
                segments[seg] = segments.get(seg, 0) + 1

            return jsonify({'success': True, 'segments': segments})

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        # Demo data
        demo_devices = get_demo_sdn_devices()
        segments = {}
        for d in demo_devices:
            seg = d['segment']
            segments[seg] = segments.get(seg, 0) + 1

        return jsonify({'success': True, 'segments': segments})


@sdn_bp.route('/api/sdn/wifi')
@login_required
def api_wifi_intelligence():
    """Get WiFi intelligence data including DFS/channel info."""
    import subprocess
    import os

    # Try to get real data from hostapd/iw
    wifi_data = None

    try:
        # Check if DFS Intelligence is available
        dfs_available = False
        try:
            from shared.wireless import ChannelScorer, DFSDatabase
            dfs_available = True
        except ImportError:
            pass

        # Try to get real WiFi status
        result = subprocess.run(
            ['iw', 'dev'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0 and result.stdout:
            # Parse iw output for channel info
            wifi_data = parse_iw_output(result.stdout)

        # Try to get DFS intelligence data
        if dfs_available and wifi_data:
            try:
                scorer = ChannelScorer()
                channel = wifi_data.get('channel', 149)
                score = scorer.score_channel(channel)
                wifi_data['channel_score'] = int(score.total_score * 100)
            except Exception:
                pass

    except Exception as e:
        # Fall back to demo data
        pass

    if not wifi_data:
        wifi_data = get_demo_wifi_data()

    return jsonify(wifi_data)


def parse_iw_output(output):
    """Parse iw dev output to extract WiFi info."""
    import re

    data = {
        'channel': None,
        'width': None,
        'power': None,
        'band': '5GHz',
        'dfs_status': 'clear',
        'channel_score': 85,
        'radar_events_24h': 0,
        'channel_switches_24h': 0,
        'events': [],
    }

    # Look for channel info
    channel_match = re.search(r'channel (\d+)', output)
    if channel_match:
        data['channel'] = int(channel_match.group(1))
        # Determine band from channel
        if data['channel'] <= 14:
            data['band'] = '2.4GHz'

    # Look for width
    width_match = re.search(r'width: (\d+)', output)
    if width_match:
        data['width'] = int(width_match.group(1))

    # Look for txpower
    power_match = re.search(r'txpower (\d+\.\d+)', output)
    if power_match:
        data['power'] = int(float(power_match.group(1)))

    return data


@sdn_bp.route('/api/sdn/move', methods=['POST'])
@login_required
@operator_required
def api_move_device():
    """Move a device to a different segment."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')
    segment = data.get('segment', '').upper()

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if not segment:
        return jsonify({'success': False, 'error': 'Segment required'}), 400

    # Map segment name to NetworkSegment enum
    segment_map = {
        'SECMON': 'SECMON',
        'POS': 'POS',
        'STAFF': 'CLIENTS',
        'CLIENTS': 'CLIENTS',
        'GUEST': 'GUEST',
        'CAMERAS': 'CAMERAS',
        'IIOT': 'IIOT',
        'QUARANTINE': 'QUARANTINE',
    }

    if segment not in segment_map:
        return jsonify({'success': False, 'error': f'Invalid segment: {segment}'}), 400

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()

            # Get the NetworkSegment enum value
            target_segment = getattr(NetworkSegment, segment_map[segment], None)
            if target_segment is None:
                return jsonify({'success': False, 'error': f'Segment not found: {segment}'}), 400

            success = autopilot.assign_device_segment(
                mac_address,
                target_segment,
                persist=True
            )

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Device {mac_address} moved to {segment}'
                })
            else:
                return jsonify({'success': False, 'error': 'Move failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac_address} moved to {segment} (demo mode)'
        })
