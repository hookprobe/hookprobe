"""
Core Module Views - Dashboard and Main Page
"""
import os
from flask import render_template, jsonify, current_app
from . import core_bp
from utils import (
    run_command, load_json_file, get_container_status,
    get_network_stats, get_system_info, format_bytes
)


@core_bp.route('/')
def index():
    """Main page - renders the SPA container."""
    context = get_dashboard_context()
    return render_template('base.html', **context)


@core_bp.route('/api/status')
def api_status():
    """Get overall system status."""
    try:
        system = get_system_info()

        # Get connected clients count from WiFi station dump
        lan_iface = current_app.config.get('LAN_INTERFACE', 'wlan0')
        output, success = run_command(f"sudo iw dev {lan_iface} station dump 2>/dev/null | grep -c Station")
        if not success or not output.strip().isdigit():
            # Try wlan1 as fallback
            output, success = run_command("sudo iw dev wlan1 station dump 2>/dev/null | grep -c Station")
        connected_clients = int(output.strip()) if success and output.strip().isdigit() else 0

        # Get network interface stats
        wan_stats = get_network_stats(current_app.config.get('WAN_INTERFACE', 'eth0'))
        lan_stats = get_network_stats(current_app.config.get('LAN_INTERFACE', 'wlan0'))

        return jsonify({
            'hostname': system['hostname'],
            'uptime': system['uptime'],
            'load': system['load'],
            'memory': system['memory'],
            'temperature': system['temperature'],
            'connected_clients': connected_clients,
            'network': {
                'wan': {
                    'rx': format_bytes(wan_stats['rx_bytes']),
                    'tx': format_bytes(wan_stats['tx_bytes'])
                },
                'lan': {
                    'rx': format_bytes(lan_stats['rx_bytes']),
                    'tx': format_bytes(lan_stats['tx_bytes'])
                }
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@core_bp.route('/api/containers')
def api_containers():
    """Get service status for all Guardian services (systemd services, not containers)."""
    import subprocess

    # Service configuration: key = display key, services = list of possible service names to try
    service_config = {
        'hostapd': {'label': 'WiFi Access Point', 'services': ['hostapd']},
        'dnsmasq': {'label': 'DNS/DHCP Server', 'services': ['dnsmasq']},
        'dhcpcd': {'label': 'DHCP Client', 'services': ['dhcpcd', 'dhcpcd5', 'dhclient', 'NetworkManager']},
        'guardian': {'label': 'Guardian Agent', 'services': ['guardian-qsecbit', 'guardian-agent', 'hookprobe-agent', 'guardian', 'guardian-webui']},
    }

    services = {}
    for key, config in service_config.items():
        is_running = False
        status = 'not installed'
        found_service = False

        # Try each possible service name
        for service_name in config['services']:
            try:
                # Use subprocess directly to capture output regardless of exit code
                # systemctl is-active returns non-zero for inactive/failed but output is valid
                result = subprocess.run(
                    ['systemctl', 'is-active', service_name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                service_status = result.stdout.strip().lower()

                # Valid statuses from systemctl is-active
                if service_status in ['active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading']:
                    found_service = True
                    if service_status == 'active':
                        is_running = True
                        status = 'active'
                        break
                    elif status == 'not installed':
                        status = service_status
            except (subprocess.TimeoutExpired, Exception):
                continue

        # Format status for display
        if is_running:
            display_status = 'Running'
        elif status == 'inactive':
            display_status = 'Stopped'
        elif status == 'failed':
            display_status = 'Failed'
        elif status == 'not installed':
            display_status = 'Not Installed'
        else:
            display_status = status.capitalize()

        services[key] = {
            'label': config['label'],
            'running': is_running,
            'status': display_status
        }

    return jsonify(services)


@core_bp.route('/api/threats')
def api_threats():
    """Get aggregated threat data."""
    threat_file = current_app.config.get('THREAT_FILE', '/var/log/hookprobe/threats/aggregated.json')
    data = load_json_file(threat_file, {
        'stats': {
            'total': 0,
            'blocked': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'qsecbit_score': 0.0
        }
    })
    return jsonify(data)


def get_dashboard_context():
    """Build context for dashboard rendering."""
    system = get_system_info()

    # Load threat data
    threat_file = current_app.config.get('THREAT_FILE', '/var/log/hookprobe/threats/aggregated.json')
    threats = load_json_file(threat_file, {'stats': {}})

    # Get connected clients (without shell pipes)
    connected_clients = _get_connected_clients_count()

    # Get layer threat data for security tab
    layer_threats = get_layer_threat_data()

    return {
        'system': system,
        'threats': threats.get('stats', {}),
        'connected_clients': connected_clients,
        'layer_threats': layer_threats
    }


def get_layer_threat_data():
    """Get threat data organized by OSI layer."""
    default_layer = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'blocked': 0}

    return {
        'layers': {
            'L2_DATA_LINK': default_layer.copy(),
            'L3_NETWORK': default_layer.copy(),
            'L4_TRANSPORT': default_layer.copy(),
            'L5_SESSION': default_layer.copy(),
            'L6_PRESENTATION': default_layer.copy(),
            'L7_APPLICATION': default_layer.copy()
        },
        'detection_coverage': {
            'L2_DATA_LINK': ['ARP Spoofing', 'MAC Flooding', 'VLAN Hopping'],
            'L3_NETWORK': ['IP Spoofing', 'ICMP Flood', 'Smurf Attack'],
            'L4_TRANSPORT': ['SYN Flood', 'Port Scan', 'TCP Reset'],
            'L5_SESSION': ['Session Hijack', 'SSL Strip'],
            'L6_PRESENTATION': ['TLS Downgrade', 'Cert Pinning Bypass'],
            'L7_APPLICATION': ['SQL Injection', 'XSS', 'DNS Tunneling', 'HTTP Flood']
        }
    }


@core_bp.route('/api/layer_threats')
def api_layer_threats():
    """Get L2-L7 layer threat breakdown."""
    return jsonify(get_layer_threat_data())


@core_bp.route('/api/core/dashboard')
def api_dashboard():
    """Get dashboard data for real-time updates including traffic stats."""
    try:
        system = get_system_info()

        # Auto-detect network interfaces if not configured
        available = _get_available_interfaces()

        # Find WAN interface (prefer config, then first wired interface)
        wan_interface = current_app.config.get('WAN_INTERFACE', '')
        if not wan_interface or not _interface_exists(wan_interface):
            # Try common wired interface names
            for iface in ['eth0', 'enp0s3', 'enp0s25', 'ens33', 'en0']:
                if _interface_exists(iface):
                    wan_interface = iface
                    break
            # Fallback to any wired interface
            if not wan_interface:
                for iface in available:
                    if iface.get('type') == 'wired' and iface.get('state') == 'up':
                        wan_interface = iface.get('name')
                        break

        # Find LAN interface (prefer config, then first wireless interface)
        lan_interface = current_app.config.get('LAN_INTERFACE', '')
        if not lan_interface or not _interface_exists(lan_interface):
            # Try common wireless interface names
            for iface in ['wlan0', 'wlan1', 'wlp2s0', 'wlp3s0']:
                if _interface_exists(iface):
                    lan_interface = iface
                    break
            # Fallback to any wireless interface
            if not lan_interface:
                for iface in available:
                    if iface.get('type') == 'wireless' and iface.get('state') == 'up':
                        lan_interface = iface.get('name')
                        break

        # Get stats for detected interfaces
        wan_stats = get_network_stats(wan_interface) if wan_interface else {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0}
        lan_stats = get_network_stats(lan_interface) if lan_interface else {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0}

        # Get list of available interfaces
        interfaces = _get_available_interfaces()

        # Load threat data
        threat_file = current_app.config.get('THREAT_FILE', '/var/log/hookprobe/threats/aggregated.json')
        threats = load_json_file(threat_file, {'stats': {'blocked': 0}})

        # Load recent blocks for visualization
        block_file = current_app.config.get('BLOCK_FILE', '/var/log/hookprobe/security/blocks.json')
        blocks = load_json_file(block_file, {'blocks': []})
        recent_blocks = blocks.get('blocks', [])[-10:]  # Last 10 blocks

        # Get connected clients (without using shell pipes)
        connected_clients = _get_connected_clients_count()

        return jsonify({
            'connected_clients': connected_clients,
            'network': {
                'rx_bytes': wan_stats.get('rx_bytes', 0),
                'tx_bytes': wan_stats.get('tx_bytes', 0),
                'interface': wan_interface
            },
            'interfaces': {
                wan_interface: {
                    'type': 'wan',
                    'rx_bytes': wan_stats.get('rx_bytes', 0),
                    'tx_bytes': wan_stats.get('tx_bytes', 0),
                    'rx_packets': wan_stats.get('rx_packets', 0),
                    'tx_packets': wan_stats.get('tx_packets', 0)
                },
                lan_interface: {
                    'type': 'lan',
                    'rx_bytes': lan_stats.get('rx_bytes', 0),
                    'tx_bytes': lan_stats.get('tx_bytes', 0),
                    'rx_packets': lan_stats.get('rx_packets', 0),
                    'tx_packets': lan_stats.get('tx_packets', 0)
                }
            },
            'available_interfaces': interfaces,
            'threats': threats.get('stats', {'blocked': 0}),
            'recent_blocks': recent_blocks,
            'system': {
                'uptime': system.get('uptime', '0:00'),
                'load': system.get('load', [0, 0, 0]),
                'temperature': system.get('temperature', 0)
            }
        })
    except Exception as e:
        # Return minimal data on error so frontend doesn't break
        return jsonify({
            'connected_clients': 0,
            'network': {'rx_bytes': 0, 'tx_bytes': 0, 'interface': 'eth0'},
            'interfaces': {},
            'available_interfaces': [],
            'threats': {'blocked': 0},
            'recent_blocks': [],
            'system': {'uptime': '0:00', 'load': [0, 0, 0], 'temperature': 0},
            'error': str(e)
        })


def _get_connected_clients_count():
    """Get count of connected clients without using shell pipes."""
    try:
        # Run ip neigh show and parse output in Python
        output, success = run_command(['ip', 'neigh', 'show'])
        if not success or not output:
            return 0

        # Count lines that don't contain "FAILED"
        count = 0
        for line in output.splitlines():
            if line.strip() and 'FAILED' not in line:
                count += 1
        return count
    except Exception:
        return 0


def _interface_exists(iface_name):
    """Check if a network interface exists."""
    if not iface_name:
        return False
    return os.path.exists(f'/sys/class/net/{iface_name}')


def _get_available_interfaces():
    """Get list of available network interfaces."""
    interfaces = []
    try:
        net_dir = '/sys/class/net'
        if os.path.exists(net_dir):
            for iface in os.listdir(net_dir):
                if iface != 'lo':  # Skip loopback
                    iface_path = os.path.join(net_dir, iface)
                    if os.path.isdir(iface_path):
                        # Check if interface is up
                        operstate_file = os.path.join(iface_path, 'operstate')
                        state = 'unknown'
                        if os.path.exists(operstate_file):
                            with open(operstate_file, 'r') as f:
                                state = f.read().strip()
                        # Determine interface type
                        iface_type = 'wired'
                        if iface.startswith(('wlan', 'wlp', 'wifi')):
                            iface_type = 'wireless'
                        elif iface.startswith(('eth', 'enp', 'ens', 'en')):
                            iface_type = 'wired'
                        interfaces.append({
                            'name': iface,
                            'state': state,
                            'type': iface_type
                        })
    except (IOError, OSError):
        pass
    return interfaces
