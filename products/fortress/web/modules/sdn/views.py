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
