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

    # Get connected clients
    output, success = run_command("ip neigh show | grep -v FAILED | wc -l")
    connected_clients = int(output) if success and output.isdigit() else 0

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
