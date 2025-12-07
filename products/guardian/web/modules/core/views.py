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

        # Get connected clients count (only REACHABLE/STALE on LAN interface)
        lan_iface = current_app.config.get('LAN_INTERFACE', 'wlan0')
        output, success = run_command(f"ip neigh show dev {lan_iface} | grep -E 'REACHABLE|STALE|DELAY' | wc -l")
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
    """Get container status for all Guardian services."""
    # Map: key = display key, container_name = actual podman container name
    container_config = {
        'suricata': {'label': 'IDS/IPS (Suricata)', 'container': 'guardian-suricata'},
        'waf': {'label': 'WAF (ModSecurity)', 'container': 'guardian-waf'},
        'neuro': {'label': 'Neural Engine', 'container': 'guardian-neuro'},
        'zeek': {'label': 'Network Monitor (Zeek)', 'container': 'guardian-zeek'},
    }

    containers = {}
    for key, config in container_config.items():
        containers[key] = {
            'label': config['label'],
            'running': False,
            'status': 'Unknown'
        }
        status = get_container_status(config['container'])
        containers[key].update(status)

    return jsonify(containers)


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
