#!/usr/bin/env python3
"""
HookProbe Guardian - Local Web UI

Simple Flask app for on-device configuration.
Runs on http://192.168.4.1:8080

Version: 5.0.0
"""

import os
import subprocess
import json
import re
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template_string, request, redirect, flash, jsonify

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration paths
HOSTAPD_CONF = Path('/etc/hostapd/hostapd.conf')
WPA_SUPPLICANT_CONF = Path('/etc/wpa_supplicant/wpa_supplicant-wlan1.conf')
DNSMASQ_CONF = Path('/etc/dnsmasq.d/guardian.conf')
MODE_FILE = Path('/opt/hookprobe/guardian/mode.conf')
NEURO_STATS = Path('/opt/hookprobe/guardian/neuro/stats.json')
QSECBIT_STATS = Path('/opt/hookprobe/guardian/data/stats.json')
QSECBIT_THREATS = Path('/opt/hookprobe/guardian/data/threats.json')
OVS_CONFIG = Path('/etc/hookprobe/ovs-config.sh')


def run_command(cmd, timeout=30):
    """Run shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return result.stdout.strip(), result.returncode == 0
    except Exception as e:
        return str(e), False


def get_mode():
    """Get current Guardian mode (basic or sdn)."""
    if MODE_FILE.exists():
        return MODE_FILE.read_text().strip()
    if HOSTAPD_CONF.exists():
        content = HOSTAPD_CONF.read_text()
        if 'dynamic_vlan=1' in content:
            return 'sdn'
    return 'basic'


def scan_wifi():
    """Scan for available WiFi networks."""
    networks = []

    # Try multiple interfaces
    for iface in ['wlan1', 'wlan0']:
        # First, bring interface up and trigger scan
        run_command(f'ip link set {iface} up 2>/dev/null')
        run_command(f'iw dev {iface} scan trigger 2>/dev/null')

        # Wait briefly for scan
        import time
        time.sleep(2)

        # Get scan results using iw
        output, success = run_command(f'iw dev {iface} scan 2>/dev/null')

        if success and output:
            current_ssid = None
            current_signal = -100

            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('BSS '):
                    # Save previous network
                    if current_ssid:
                        networks.append({'ssid': current_ssid, 'signal': current_signal})
                    current_ssid = None
                    current_signal = -100
                elif 'SSID:' in line:
                    ssid = line.split('SSID:', 1)[1].strip()
                    if ssid and ssid != '\\x00' and not ssid.startswith('\\x'):
                        current_ssid = ssid
                elif 'signal:' in line:
                    try:
                        sig = line.split('signal:', 1)[1].strip()
                        current_signal = int(float(sig.split()[0]))
                    except:
                        pass

            # Don't forget last network
            if current_ssid:
                networks.append({'ssid': current_ssid, 'signal': current_signal})

        # Try iwlist as fallback
        if not networks:
            output, success = run_command(f'iwlist {iface} scan 2>/dev/null')
            if success and output:
                for match in re.finditer(r'ESSID:"([^"]+)"', output):
                    ssid = match.group(1)
                    if ssid:
                        # Try to find signal
                        signal = -70  # default
                        sig_match = re.search(rf'{re.escape(ssid)}.*?Signal level[=:](-?\d+)', output, re.DOTALL)
                        if sig_match:
                            signal = int(sig_match.group(1))
                        networks.append({'ssid': ssid, 'signal': signal})

        if networks:
            break

    # Remove duplicates and sort by signal
    seen = set()
    unique_networks = []
    for net in networks:
        if net['ssid'] not in seen:
            seen.add(net['ssid'])
            unique_networks.append(net)

    unique_networks.sort(key=lambda x: x['signal'], reverse=True)
    return unique_networks[:20]


def get_current_config():
    """Read current configuration."""
    config = {
        'hotspot_ssid': 'HookProbe-Guardian',
        'hotspot_password': '',
        'upstream_ssid': '',
        'upstream_password': '',
        'bridge_lan': True,
        'mode': get_mode(),
    }

    if HOSTAPD_CONF.exists():
        content = HOSTAPD_CONF.read_text()
        for line in content.split('\n'):
            if line.startswith('ssid='):
                config['hotspot_ssid'] = line.split('=', 1)[1]
            elif line.startswith('wpa_passphrase='):
                config['hotspot_password'] = line.split('=', 1)[1]

    if WPA_SUPPLICANT_CONF.exists():
        content = WPA_SUPPLICANT_CONF.read_text()
        ssid_match = re.search(r'ssid="([^"]*)"', content)
        psk_match = re.search(r'psk="([^"]*)"', content)
        if ssid_match:
            config['upstream_ssid'] = ssid_match.group(1)
        if psk_match:
            config['upstream_password'] = psk_match.group(1)

    return config


def get_status():
    """Get current system status."""
    status = {}

    output, _ = run_command('iw wlan1 link 2>/dev/null')
    status['upstream_connected'] = 'Connected' in output

    output, _ = run_command('hostname -I')
    status['ip_addresses'] = output.split()

    output, _ = run_command('systemctl is-active hostapd')
    status['hostapd'] = output == 'active'

    output, _ = run_command('systemctl is-active dnsmasq')
    status['dnsmasq'] = output == 'active'

    output, _ = run_command('iw dev wlan0 station dump 2>/dev/null | grep Station | wc -l')
    status['clients'] = int(output) if output.isdigit() else 0

    status['mode'] = get_mode()

    return status


def get_container_status():
    """Get status of all security containers."""
    containers = {
        'suricata': {'name': 'guardian-suricata', 'label': 'Suricata IDS', 'running': False},
        'waf': {'name': 'guardian-waf', 'label': 'ModSecurity WAF', 'running': False},
        'neuro': {'name': 'guardian-neuro', 'label': 'Neuro Protocol', 'running': False},
        'adguard': {'name': 'guardian-adguard', 'label': 'AdGuard Home', 'running': False},
    }

    output, _ = run_command('podman ps --format "{{.Names}}" 2>/dev/null')
    running = output.split('\n') if output else []

    for key, container in containers.items():
        container['running'] = container['name'] in running

        # Get service status as fallback
        svc_output, _ = run_command(f'systemctl is-active {container["name"]}')
        container['service_active'] = svc_output == 'active'

    return containers


def get_security_data():
    """Get all security-related data."""
    data = {
        'neuro': None,
        'qsecbit': None,
        'threats': [],
        'suricata_alerts': [],
        'ovs': None,
    }

    # Neuro stats
    if NEURO_STATS.exists():
        try:
            data['neuro'] = json.loads(NEURO_STATS.read_text())
        except:
            pass

    # QSecBit stats
    if QSECBIT_STATS.exists():
        try:
            data['qsecbit'] = json.loads(QSECBIT_STATS.read_text())
        except:
            pass

    # Recent threats
    if QSECBIT_THREATS.exists():
        try:
            threats = []
            for line in QSECBIT_THREATS.read_text().strip().split('\n')[-10:]:
                if line:
                    threats.append(json.loads(line))
            data['threats'] = threats
        except:
            pass

    # Suricata alerts from eve.json
    output, success = run_command('podman exec guardian-suricata tail -50 /var/log/suricata/eve.json 2>/dev/null')
    if success and output:
        alerts = []
        for line in output.split('\n'):
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    alerts.append({
                        'timestamp': event.get('timestamp', '')[:19],
                        'signature': event.get('alert', {}).get('signature', 'Unknown'),
                        'severity': event.get('alert', {}).get('severity', 0),
                        'src_ip': event.get('src_ip', ''),
                        'dest_ip': event.get('dest_ip', ''),
                    })
            except:
                pass
        data['suricata_alerts'] = alerts[-10:]  # Last 10 alerts

    # OVS config
    if OVS_CONFIG.exists():
        try:
            ovs_data = {}
            for line in OVS_CONFIG.read_text().split('\n'):
                if '=' in line and not line.startswith('#'):
                    key, val = line.split('=', 1)
                    ovs_data[key.strip()] = val.strip()
            data['ovs'] = ovs_data
        except:
            pass

    # OVS bridge info
    output, _ = run_command('ovs-vsctl show 2>/dev/null')
    if output:
        data['ovs_bridges'] = output

    return data


def get_sdn_stats():
    """Get SDN-specific statistics."""
    if get_mode() != 'sdn':
        return None

    stats = {
        'vlans': [],
        'devices': 0,
        'quarantined': 0,
    }

    output, _ = run_command("ip -br link show | grep 'br[0-9]'")
    for line in output.split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) >= 2:
                stats['vlans'].append({
                    'name': parts[0],
                    'state': parts[1]
                })

    output, _ = run_command('cat /var/lib/misc/dnsmasq.leases 2>/dev/null | wc -l')
    stats['devices'] = int(output) if output.isdigit() else 0

    return stats


# HTML Template with Tabs
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>HookProbe Guardian</title>
    <style>
        :root {
            --hp-primary: #2563eb;
            --hp-primary-dark: #1d4ed8;
            --hp-secondary: #10b981;
            --hp-warning: #f59e0b;
            --hp-danger: #ef4444;
            --hp-dark: #1f2937;
            --hp-light: #f3f4f6;
            --hp-border: #e5e7eb;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--hp-light);
            min-height: 100vh;
        }

        .header {
            background: linear-gradient(135deg, var(--hp-dark) 0%, #374151 100%);
            color: white;
            padding: 20px;
            text-align: center;
        }
        .header h1 { font-size: 24px; margin-bottom: 5px; }
        .header .subtitle { font-size: 14px; opacity: 0.8; }
        .mode-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            margin-top: 10px;
        }
        .mode-basic { background: var(--hp-primary); }
        .mode-sdn { background: var(--hp-secondary); }

        /* Tabs */
        .tabs {
            display: flex;
            background: white;
            border-bottom: 1px solid var(--hp-border);
            overflow-x: auto;
        }
        .tab {
            padding: 15px 20px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            font-weight: 500;
            color: #6b7280;
            white-space: nowrap;
            transition: all 0.2s;
        }
        .tab:hover { color: var(--hp-primary); background: var(--hp-light); }
        .tab.active {
            color: var(--hp-primary);
            border-bottom-color: var(--hp-primary);
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        .container { max-width: 900px; margin: 0 auto; padding: 20px; }

        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border: 1px solid var(--hp-border);
        }
        .card h2 {
            margin-bottom: 20px;
            color: var(--hp-dark);
            font-size: 18px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card h2::before {
            content: '';
            width: 4px;
            height: 20px;
            background: var(--hp-primary);
            border-radius: 2px;
        }
        .card h3 {
            margin: 20px 0 10px;
            font-size: 14px;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 15px;
        }
        .status-item {
            text-align: center;
            padding: 20px 15px;
            background: var(--hp-light);
            border-radius: 8px;
        }
        .status-item .value {
            font-size: 28px;
            font-weight: 700;
            color: var(--hp-primary);
        }
        .status-item .label {
            font-size: 12px;
            color: #6b7280;
            margin-top: 5px;
            text-transform: uppercase;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
        }
        .badge-success { background: #dcfce7; color: #166534; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge::before {
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        .badge-success::before { background: #22c55e; }
        .badge-danger::before { background: #ef4444; }
        .badge-warning::before { background: #f59e0b; }

        .form-group { margin-bottom: 16px; }
        label {
            display: block;
            margin-bottom: 6px;
            font-weight: 500;
            color: var(--hp-dark);
            font-size: 14px;
        }
        input, select {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--hp-border);
            border-radius: 8px;
            font-size: 15px;
        }
        input:focus, select:focus {
            outline: none;
            border-color: var(--hp-primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 500;
            transition: all 0.2s;
        }
        .btn-primary { background: var(--hp-primary); color: white; }
        .btn-primary:hover { background: var(--hp-primary-dark); }
        .btn-secondary { background: #6b7280; color: white; }
        .btn-success { background: var(--hp-secondary); color: white; }
        .btn-danger { background: var(--hp-danger); color: white; }
        .btn-sm { padding: 8px 16px; font-size: 13px; }
        .btn-group { display: flex; gap: 10px; flex-wrap: wrap; }

        /* Networks List */
        .networks {
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid var(--hp-border);
            border-radius: 8px;
            margin-top: 15px;
        }
        .network-item {
            padding: 12px 15px;
            border-bottom: 1px solid var(--hp-border);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .network-item:last-child { border-bottom: none; }
        .network-item:hover { background: var(--hp-light); }
        .network-item .ssid { font-weight: 500; }
        .network-item .signal {
            font-size: 12px;
            color: #6b7280;
            padding: 4px 8px;
            background: var(--hp-light);
            border-radius: 4px;
        }

        /* Data Table */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        .data-table th, .data-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--hp-border);
        }
        .data-table th {
            background: var(--hp-light);
            font-weight: 600;
            color: var(--hp-dark);
        }
        .data-table tr:hover { background: #f9fafb; }

        /* Container Status */
        .container-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .container-item {
            padding: 15px;
            background: var(--hp-light);
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .container-item .name { font-weight: 500; }

        /* Alert List */
        .alert-list {
            max-height: 400px;
            overflow-y: auto;
        }
        .alert-item {
            padding: 12px;
            border-bottom: 1px solid var(--hp-border);
            font-size: 13px;
        }
        .alert-item:last-child { border-bottom: none; }
        .alert-item .signature { font-weight: 500; color: var(--hp-danger); }
        .alert-item .meta { color: #6b7280; font-size: 12px; margin-top: 4px; }

        /* JSON Display */
        .json-display {
            background: #1f2937;
            color: #10b981;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 13px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .flash {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .flash-success { background: #dcfce7; color: #166534; }
        .flash-error { background: #fee2e2; color: #991b1b; }

        .footer {
            text-align: center;
            padding: 20px;
            color: #6b7280;
            font-size: 12px;
        }
        .footer a { color: var(--hp-primary); text-decoration: none; }

        @media (max-width: 600px) {
            .tabs { flex-wrap: nowrap; }
            .tab { padding: 12px 15px; font-size: 14px; }
            .status-grid { grid-template-columns: repeat(2, 1fr); }
            .btn-group { flex-direction: column; }
            .btn { width: 100%; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>HookProbe Guardian</h1>
        <div class="subtitle">Portable SDN Security Gateway</div>
        <div class="mode-badge mode-{{ config.mode }}">
            {{ 'SDN Mode' if config.mode == 'sdn' else 'Basic Mode' }}
        </div>
    </div>

    <!-- Tabs Navigation -->
    <div class="tabs">
        <div class="tab active" data-tab="dashboard">Dashboard</div>
        <div class="tab" data-tab="security">Security</div>
        <div class="tab" data-tab="wifi">WiFi</div>
        <div class="tab" data-tab="settings">Settings</div>
    </div>

    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
            <div class="flash flash-{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
        {% endwith %}

        <!-- Dashboard Tab -->
        <div id="dashboard" class="tab-content active">
            <div class="card">
                <h2>System Status</h2>
                <div class="status-grid">
                    <div class="status-item">
                        <div class="value">{{ status.clients }}</div>
                        <div class="label">Connected Clients</div>
                    </div>
                    <div class="status-item">
                        <span class="badge {% if status.hostapd %}badge-success{% else %}badge-danger{% endif %}">
                            {% if status.hostapd %}Running{% else %}Stopped{% endif %}
                        </span>
                        <div class="label">Hotspot</div>
                    </div>
                    <div class="status-item">
                        <span class="badge {% if status.upstream_connected %}badge-success{% else %}badge-warning{% endif %}">
                            {% if status.upstream_connected %}Connected{% else %}Disconnected{% endif %}
                        </span>
                        <div class="label">Upstream WiFi</div>
                    </div>
                    <div class="status-item">
                        <span class="badge {% if status.dnsmasq %}badge-success{% else %}badge-danger{% endif %}">
                            {% if status.dnsmasq %}Running{% else %}Stopped{% endif %}
                        </span>
                        <div class="label">DHCP/DNS</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Security Containers</h2>
                <div class="container-grid">
                    {% for key, container in containers.items() %}
                    <div class="container-item">
                        <span class="name">{{ container.label }}</span>
                        <span class="badge {% if container.running %}badge-success{% else %}badge-danger{% endif %}">
                            {% if container.running %}Running{% else %}Stopped{% endif %}
                        </span>
                    </div>
                    {% endfor %}
                </div>
            </div>

            {% if config.mode == 'sdn' and sdn_stats %}
            <div class="card">
                <h2>SDN Status</h2>
                <div class="status-grid">
                    <div class="status-item">
                        <div class="value">{{ sdn_stats.vlans|length }}</div>
                        <div class="label">Active VLANs</div>
                    </div>
                    <div class="status-item">
                        <div class="value">{{ sdn_stats.devices }}</div>
                        <div class="label">Total Devices</div>
                    </div>
                </div>
            </div>
            {% endif %}
        </div>

        <!-- Security Tab -->
        <div id="security" class="tab-content">
            <div class="card">
                <h2>QSecBit / Neuro Protocol</h2>

                <h3>Neuro Stats</h3>
                {% if security_data.neuro %}
                <div class="json-display">{{ security_data.neuro | tojson(indent=2) }}</div>
                {% else %}
                <p style="color: #6b7280;">No Neuro data available. Container may be starting...</p>
                {% endif %}

                <h3>QSecBit Agent Stats</h3>
                {% if security_data.qsecbit %}
                <div class="json-display">{{ security_data.qsecbit | tojson(indent=2) }}</div>
                {% else %}
                <p style="color: #6b7280;">No QSecBit data available.</p>
                {% endif %}
            </div>

            <div class="card">
                <h2>Suricata IDS Alerts</h2>
                {% if security_data.suricata_alerts %}
                <div class="alert-list">
                    {% for alert in security_data.suricata_alerts %}
                    <div class="alert-item">
                        <div class="signature">{{ alert.signature }}</div>
                        <div class="meta">
                            {{ alert.timestamp }} | Severity: {{ alert.severity }} |
                            {{ alert.src_ip }} → {{ alert.dest_ip }}
                        </div>
                    </div>
                    {% endfor %}
                </div>
                {% else %}
                <p style="color: #6b7280;">No alerts detected. Your network is secure!</p>
                {% endif %}
            </div>

            <div class="card">
                <h2>Threat Log</h2>
                {% if security_data.threats %}
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Signature</th>
                            <th>Source</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for threat in security_data.threats %}
                        <tr>
                            <td>{{ threat.timestamp[:19] if threat.timestamp else 'N/A' }}</td>
                            <td>{{ threat.signature or 'Unknown' }}</td>
                            <td>{{ threat.src_ip or 'N/A' }}</td>
                            <td>{{ threat.severity or 0 }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p style="color: #6b7280;">No threats logged.</p>
                {% endif %}
            </div>

            <div class="card">
                <h2>OVS / VXLAN Configuration</h2>
                {% if security_data.ovs %}
                <div class="json-display">{{ security_data.ovs | tojson(indent=2) }}</div>
                {% else %}
                <p style="color: #6b7280;">OVS configuration not available.</p>
                {% endif %}

                {% if security_data.ovs_bridges %}
                <h3>OVS Bridges</h3>
                <div class="json-display">{{ security_data.ovs_bridges }}</div>
                {% endif %}
            </div>
        </div>

        <!-- WiFi Tab -->
        <div id="wifi" class="tab-content">
            <div class="card">
                <h2>Connect to Upstream WiFi</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">
                    Connect Guardian to an existing WiFi network for internet access.
                </p>
                <form method="post" action="/connect">
                    <div class="form-group">
                        <label>Network Name (SSID)</label>
                        <input type="text" name="ssid" id="upstream-ssid" value="{{ config.upstream_ssid }}" placeholder="Select from list below or type manually">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" value="{{ config.upstream_password }}">
                    </div>
                    <div class="btn-group">
                        <button type="submit" class="btn btn-primary">Connect</button>
                        <a href="/scan" class="btn btn-secondary">Scan Networks</a>
                    </div>
                </form>

                {% if networks %}
                <h3>Available Networks ({{ networks|length }})</h3>
                <div class="networks">
                    {% for net in networks %}
                    <div class="network-item" onclick="document.getElementById('upstream-ssid').value='{{ net.ssid }}'">
                        <span class="ssid">{{ net.ssid }}</span>
                        <span class="signal">{{ net.signal }} dBm</span>
                    </div>
                    {% endfor %}
                </div>
                {% elif show_scan_result %}
                <h3>Scan Results</h3>
                <p style="color: #6b7280;">No networks found. Try scanning again.</p>
                {% endif %}
            </div>
        </div>

        <!-- Settings Tab -->
        <div id="settings" class="tab-content">
            <div class="card">
                <h2>Hotspot Settings</h2>
                <form method="post" action="/hotspot">
                    <div class="form-group">
                        <label>Hotspot Name (SSID)</label>
                        <input type="text" name="ssid" value="{{ config.hotspot_ssid }}" required>
                    </div>
                    <div class="form-group">
                        <label>Password (min 8 characters)</label>
                        <input type="password" name="password" value="{{ config.hotspot_password }}" minlength="8" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Save Settings</button>
                </form>
            </div>

            <div class="card">
                <h2>System Actions</h2>
                <form method="post" action="/action">
                    <div class="btn-group">
                        <button type="submit" name="action" value="restart_hostapd" class="btn btn-primary">Restart Hotspot</button>
                        <button type="submit" name="action" value="restart_containers" class="btn btn-secondary">Restart Containers</button>
                        <button type="submit" name="action" value="restart_network" class="btn btn-secondary">Restart Network</button>
                        <button type="submit" name="action" value="reboot" class="btn btn-danger" onclick="return confirm('Reboot Guardian?')">Reboot</button>
                    </div>
                </form>
            </div>

            <div class="card">
                <h2>System Info</h2>
                <table class="data-table">
                    <tr><td><strong>Mode</strong></td><td>{{ config.mode | upper }}</td></tr>
                    <tr><td><strong>IP Addresses</strong></td><td>{{ status.ip_addresses | join(', ') }}</td></tr>
                    <tr><td><strong>Hotspot SSID</strong></td><td>{{ config.hotspot_ssid }}</td></tr>
                    <tr><td><strong>Upstream WiFi</strong></td><td>{{ config.upstream_ssid or 'Not configured' }}</td></tr>
                </table>
            </div>
        </div>
    </div>

    <div class="footer">
        <p>HookProbe Guardian v5.0.0 | <a href="https://hookprobe.com" target="_blank">hookprobe.com</a></p>
    </div>

    <script>
        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });

        // Check URL hash for tab
        if (window.location.hash) {
            const tabId = window.location.hash.substring(1);
            const tab = document.querySelector(`.tab[data-tab="${tabId}"]`);
            if (tab) tab.click();
        }
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    config = get_current_config()
    status = get_status()
    sdn_stats = get_sdn_stats()
    containers = get_container_status()
    security_data = get_security_data()
    return render_template_string(
        HTML_TEMPLATE,
        config=config,
        status=status,
        networks=[],
        sdn_stats=sdn_stats,
        containers=containers,
        security_data=security_data,
        show_scan_result=False
    )


@app.route('/scan')
def scan():
    config = get_current_config()
    status = get_status()
    sdn_stats = get_sdn_stats()
    containers = get_container_status()
    security_data = get_security_data()
    networks = scan_wifi()
    return render_template_string(
        HTML_TEMPLATE,
        config=config,
        status=status,
        networks=networks,
        sdn_stats=sdn_stats,
        containers=containers,
        security_data=security_data,
        show_scan_result=True
    )


@app.route('/connect', methods=['POST'])
def connect():
    ssid = request.form.get('ssid', '').strip()
    password = request.form.get('password', '')

    if not ssid:
        flash('Please enter a network name', 'error')
        return redirect('/')

    wpa_conf = f'''
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=US

network={{
    ssid="{ssid}"
    psk="{password}"
    key_mgmt=WPA-PSK
}}
'''
    try:
        WPA_SUPPLICANT_CONF.parent.mkdir(parents=True, exist_ok=True)
        WPA_SUPPLICANT_CONF.write_text(wpa_conf)
        run_command('wpa_cli -i wlan1 reconfigure')
        flash(f'Connecting to {ssid}...', 'success')
    except Exception as e:
        flash(f'Failed to connect: {e}', 'error')

    return redirect('/')


@app.route('/hotspot', methods=['POST'])
def hotspot():
    ssid = request.form.get('ssid', '').strip()
    password = request.form.get('password', '')

    if not ssid or len(password) < 8:
        flash('Invalid SSID or password (min 8 chars)', 'error')
        return redirect('/')

    try:
        content = HOSTAPD_CONF.read_text()
        content = re.sub(r'^ssid=.*$', f'ssid={ssid}', content, flags=re.M)
        content = re.sub(r'^wpa_passphrase=.*$', f'wpa_passphrase={password}', content, flags=re.M)
        HOSTAPD_CONF.write_text(content)
        run_command('systemctl reload hostapd')
        flash('Hotspot settings updated', 'success')
    except Exception as e:
        flash(f'Failed to update: {e}', 'error')

    return redirect('/')


@app.route('/action', methods=['POST'])
def action():
    action = request.form.get('action')

    if action == 'restart_hostapd':
        run_command('systemctl restart hostapd')
        flash('Hotspot restarted', 'success')
    elif action == 'restart_containers':
        run_command('systemctl restart guardian-suricata guardian-waf guardian-neuro guardian-adguard')
        flash('Containers restarting...', 'success')
    elif action == 'restart_network':
        run_command('systemctl restart networking')
        flash('Network restarted', 'success')
    elif action == 'reboot':
        run_command('reboot')
        flash('Rebooting...', 'success')

    return redirect('/')


@app.route('/api/status')
def api_status():
    return jsonify(get_status())


@app.route('/api/security')
def api_security():
    return jsonify(get_security_data())


@app.route('/api/containers')
def api_containers():
    return jsonify(get_container_status())


@app.route('/api/scan')
def api_scan():
    return jsonify(scan_wifi())


@app.route('/api/sdn')
def api_sdn():
    stats = get_sdn_stats()
    if stats:
        return jsonify(stats)
    return jsonify({'error': 'SDN mode not enabled'}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
