#!/usr/bin/env python3
"""
HookProbe Guardian - Local Web UI

Simple Flask app for on-device configuration.
Runs on http://192.168.4.1:8080

Version: 5.1.0
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
    import time
    networks = []

    # Method 1: Try wpa_cli (works when wpa_supplicant is running)
    for iface in ['wlan1', 'wlan0']:
        run_command(f'wpa_cli -i {iface} scan 2>/dev/null', timeout=10)
        time.sleep(3)

        output, success = run_command(f'wpa_cli -i {iface} scan_results 2>/dev/null', timeout=10)
        if success and output and 'bssid' in output.lower():
            lines = output.strip().split('\n')
            for line in lines[1:]:
                parts = line.split('\t')
                if len(parts) >= 5:
                    try:
                        signal = int(parts[2]) if parts[2].lstrip('-').isdigit() else -70
                        ssid = parts[4] if len(parts) > 4 else ''
                        if ssid and ssid != '\\x00' and not ssid.startswith('\\x'):
                            networks.append({'ssid': ssid, 'signal': signal})
                    except (ValueError, IndexError):
                        pass
        if networks:
            break

    # Method 2: Try iw scan
    if not networks:
        for iface in ['wlan1', 'wlan0']:
            run_command(f'ip link set {iface} up 2>/dev/null')
            output, success = run_command(f'iw dev {iface} scan 2>/dev/null', timeout=15)

            if success and output and 'BSS' in output:
                current_ssid = None
                current_signal = -100

                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith('BSS '):
                        if current_ssid:
                            networks.append({'ssid': current_ssid, 'signal': current_signal})
                        current_ssid = None
                        current_signal = -100
                    elif line.startswith('SSID:'):
                        ssid = line.split(':', 1)[1].strip()
                        if ssid and ssid != '\\x00' and not ssid.startswith('\\x'):
                            current_ssid = ssid
                    elif line.startswith('signal:'):
                        try:
                            sig = line.split(':', 1)[1].strip()
                            current_signal = int(float(sig.split()[0]))
                        except:
                            pass

                if current_ssid:
                    networks.append({'ssid': current_ssid, 'signal': current_signal})

            if networks:
                break

    # Method 3: Try iwlist as fallback
    if not networks:
        for iface in ['wlan1', 'wlan0']:
            output, success = run_command(f'iwlist {iface} scan 2>/dev/null', timeout=15)
            if success and output and 'ESSID' in output:
                current_signal = -70
                for line in output.split('\n'):
                    line = line.strip()
                    if 'Signal level=' in line:
                        try:
                            sig = re.search(r'Signal level[=:](-?\d+)', line)
                            if sig:
                                current_signal = int(sig.group(1))
                        except:
                            pass
                    elif 'ESSID:' in line:
                        match = re.search(r'ESSID:"([^"]*)"', line)
                        if match and match.group(1):
                            networks.append({'ssid': match.group(1), 'signal': current_signal})
                            current_signal = -70

            if networks:
                break

    # Method 4: Try nmcli if available
    if not networks:
        output, success = run_command('nmcli -t -f SSID,SIGNAL dev wifi list 2>/dev/null', timeout=15)
        if success and output:
            for line in output.strip().split('\n'):
                if ':' in line:
                    parts = line.rsplit(':', 1)
                    ssid = parts[0]
                    try:
                        signal = int(parts[1]) - 100 if parts[1].isdigit() else -70
                    except:
                        signal = -70
                    if ssid:
                        networks.append({'ssid': ssid, 'signal': signal})

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

    # System info
    output, _ = run_command('uptime -p 2>/dev/null || uptime')
    status['uptime'] = output

    output, _ = run_command("free -m | awk '/Mem:/ {printf \"%.0f%%\", $3/$2*100}'")
    status['memory_usage'] = output

    output, _ = run_command("df -h / | awk 'NR==2 {print $5}'")
    status['disk_usage'] = output

    output, _ = run_command("cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null")
    if output and output.isdigit():
        status['cpu_temp'] = f"{int(output) / 1000:.1f}°C"
    else:
        status['cpu_temp'] = 'N/A'

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
        svc_output, _ = run_command(f'systemctl is-active {container["name"]}')
        container['service_active'] = svc_output == 'active'

    return containers


def get_qsecbit_data():
    """Get comprehensive QSecBit/Neuro security data with RAG status."""
    data = {
        'overall_status': 'green',  # RAG status
        'neuro': {
            'status': 'inactive',
            'mode': 'unknown',
            'timestamp': None,
            'rag': 'red'
        },
        'qsecbit': {
            'status': 'inactive',
            'connections': 0,
            'timestamp': None,
            'interfaces': {},
            'rag': 'red'
        },
        'threats': {
            'count': 0,
            'recent': [],
            'rag': 'green'
        },
        'suricata': {
            'alerts': [],
            'alert_count': 0,
            'rag': 'green'
        },
        'ovs': {
            'config': None,
            'bridges': None,
            'rag': 'amber'
        }
    }

    # Neuro stats
    if NEURO_STATS.exists():
        try:
            neuro = json.loads(NEURO_STATS.read_text())
            data['neuro']['status'] = neuro.get('status', 'unknown')
            data['neuro']['mode'] = neuro.get('mode', 'unknown')
            data['neuro']['timestamp'] = neuro.get('timestamp')
            data['neuro']['rag'] = 'green' if neuro.get('status') == 'active' else 'amber'
        except:
            pass

    # QSecBit stats
    if QSECBIT_STATS.exists():
        try:
            qsec = json.loads(QSECBIT_STATS.read_text())
            data['qsecbit']['status'] = 'active'
            data['qsecbit']['connections'] = qsec.get('connections', 0)
            data['qsecbit']['timestamp'] = qsec.get('timestamp')
            data['qsecbit']['interfaces'] = qsec.get('interfaces', {})
            data['qsecbit']['raw_stats'] = qsec.get('raw_interface_stats', '')
            data['qsecbit']['rag'] = 'green'
        except:
            pass

    # Threats
    if QSECBIT_THREATS.exists():
        try:
            threats = []
            content = QSECBIT_THREATS.read_text().strip()
            if content:
                for line in content.split('\n')[-20:]:
                    if line:
                        threats.append(json.loads(line))
            data['threats']['recent'] = threats[-10:]
            data['threats']['count'] = len(threats)
            # RAG based on threat count
            if len(threats) == 0:
                data['threats']['rag'] = 'green'
            elif len(threats) < 5:
                data['threats']['rag'] = 'amber'
            else:
                data['threats']['rag'] = 'red'
        except:
            pass

    # Suricata alerts
    output, success = run_command('podman exec guardian-suricata tail -100 /var/log/suricata/eve.json 2>/dev/null')
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
                        'category': event.get('alert', {}).get('category', ''),
                    })
            except:
                pass
        data['suricata']['alerts'] = alerts[-15:]
        data['suricata']['alert_count'] = len(alerts)
        # RAG based on severity
        high_sev = sum(1 for a in alerts if a.get('severity', 0) <= 2)
        if high_sev > 0:
            data['suricata']['rag'] = 'red'
        elif len(alerts) > 0:
            data['suricata']['rag'] = 'amber'
        else:
            data['suricata']['rag'] = 'green'

    # OVS config
    if OVS_CONFIG.exists():
        try:
            ovs_data = {}
            for line in OVS_CONFIG.read_text().split('\n'):
                if '=' in line and not line.startswith('#'):
                    key, val = line.split('=', 1)
                    ovs_data[key.strip()] = val.strip()
            data['ovs']['config'] = ovs_data
            data['ovs']['rag'] = 'green'
        except:
            pass

    output, _ = run_command('ovs-vsctl show 2>/dev/null')
    if output:
        data['ovs']['bridges'] = output
        data['ovs']['rag'] = 'green'

    # Calculate overall RAG
    rags = [data['neuro']['rag'], data['qsecbit']['rag'], data['threats']['rag'], data['suricata']['rag']]
    if 'red' in rags:
        data['overall_status'] = 'red'
    elif 'amber' in rags:
        data['overall_status'] = 'amber'
    else:
        data['overall_status'] = 'green'

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


# HTML Template with Tabs - Reorganized
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
            --hp-green: #10b981;
            --hp-amber: #f59e0b;
            --hp-red: #ef4444;
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
        .mode-sdn { background: var(--hp-green); }

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

        /* RAG Indicators */
        .rag-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 14px;
        }
        .rag-green { background: #dcfce7; color: #166534; }
        .rag-amber { background: #fef3c7; color: #92400e; }
        .rag-red { background: #fee2e2; color: #991b1b; }
        .rag-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        .rag-green .rag-dot { background: #22c55e; }
        .rag-amber .rag-dot { background: #f59e0b; }
        .rag-red .rag-dot { background: #ef4444; }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* RAG Summary Cards */
        .rag-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .rag-card {
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 2px solid;
        }
        .rag-card.green { background: #f0fdf4; border-color: #22c55e; }
        .rag-card.amber { background: #fffbeb; border-color: #f59e0b; }
        .rag-card.red { background: #fef2f2; border-color: #ef4444; }
        .rag-card .title { font-size: 12px; color: #6b7280; text-transform: uppercase; margin-bottom: 8px; }
        .rag-card .value { font-size: 24px; font-weight: 700; }
        .rag-card.green .value { color: #166534; }
        .rag-card.amber .value { color: #92400e; }
        .rag-card.red .value { color: #991b1b; }
        .rag-card .status { font-size: 13px; margin-top: 5px; }

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
        .btn-success { background: var(--hp-green); color: white; }
        .btn-danger { background: var(--hp-red); color: white; }
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
        .alert-item .signature { font-weight: 500; }
        .alert-item.sev-high .signature { color: var(--hp-red); }
        .alert-item.sev-medium .signature { color: var(--hp-amber); }
        .alert-item.sev-low .signature { color: var(--hp-green); }
        .alert-item .meta { color: #6b7280; font-size: 12px; margin-top: 4px; }

        /* Param Grid */
        .param-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }
        .param-item {
            padding: 12px;
            background: var(--hp-light);
            border-radius: 8px;
        }
        .param-item .label { font-size: 11px; color: #6b7280; text-transform: uppercase; }
        .param-item .value { font-size: 16px; font-weight: 600; color: var(--hp-dark); margin-top: 4px; }

        .flash {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .flash-success { background: #dcfce7; color: #166534; }
        .flash-error { background: #fee2e2; color: #991b1b; }

        .section-divider {
            border-top: 1px solid var(--hp-border);
            margin: 25px 0;
            padding-top: 25px;
        }

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
            .rag-grid { grid-template-columns: repeat(2, 1fr); }
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
        <div class="tab" data-tab="system">System</div>
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
                <h2>Security Overview</h2>
                <div class="rag-grid">
                    <div class="rag-card {{ qsecbit.overall_status }}">
                        <div class="title">Overall Status</div>
                        <div class="value">
                            {% if qsecbit.overall_status == 'green' %}SECURE
                            {% elif qsecbit.overall_status == 'amber' %}CAUTION
                            {% else %}ALERT{% endif %}
                        </div>
                        <div class="status">
                            {% if qsecbit.overall_status == 'green' %}All systems normal
                            {% elif qsecbit.overall_status == 'amber' %}Review recommended
                            {% else %}Immediate attention{% endif %}
                        </div>
                    </div>
                    <div class="rag-card {{ qsecbit.threats.rag }}">
                        <div class="title">Threats</div>
                        <div class="value">{{ qsecbit.threats.count }}</div>
                        <div class="status">Detected</div>
                    </div>
                    <div class="rag-card {{ qsecbit.suricata.rag }}">
                        <div class="title">IDS Alerts</div>
                        <div class="value">{{ qsecbit.suricata.alert_count }}</div>
                        <div class="status">Recent</div>
                    </div>
                    <div class="rag-card {{ qsecbit.neuro.rag }}">
                        <div class="title">Neuro Protocol</div>
                        <div class="value">{{ qsecbit.neuro.status | upper }}</div>
                        <div class="status">{{ qsecbit.neuro.mode }}</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Network Status</h2>
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
        </div>

        <!-- Security Tab -->
        <div id="security" class="tab-content">
            <div class="card">
                <h2>QSecBit Security Status</h2>

                <!-- RAG Summary -->
                <div class="rag-grid">
                    <div class="rag-card {{ qsecbit.neuro.rag }}">
                        <div class="title">Neuro Protocol</div>
                        <div class="value">{{ qsecbit.neuro.status | upper }}</div>
                    </div>
                    <div class="rag-card {{ qsecbit.qsecbit.rag }}">
                        <div class="title">QSecBit Agent</div>
                        <div class="value">{{ qsecbit.qsecbit.status | upper }}</div>
                    </div>
                    <div class="rag-card {{ qsecbit.threats.rag }}">
                        <div class="title">Threat Level</div>
                        <div class="value">
                            {% if qsecbit.threats.rag == 'green' %}LOW
                            {% elif qsecbit.threats.rag == 'amber' %}MEDIUM
                            {% else %}HIGH{% endif %}
                        </div>
                    </div>
                    <div class="rag-card {{ qsecbit.suricata.rag }}">
                        <div class="title">IDS Status</div>
                        <div class="value">
                            {% if qsecbit.suricata.rag == 'green' %}CLEAR
                            {% elif qsecbit.suricata.rag == 'amber' %}ALERTS
                            {% else %}CRITICAL{% endif %}
                        </div>
                    </div>
                </div>

                <h3>Neuro Protocol Parameters</h3>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Status</div>
                        <div class="value">{{ qsecbit.neuro.status }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Mode</div>
                        <div class="value">{{ qsecbit.neuro.mode }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Last Update</div>
                        <div class="value">{{ qsecbit.neuro.timestamp[:19] if qsecbit.neuro.timestamp else 'N/A' }}</div>
                    </div>
                </div>

                <h3>QSecBit Agent Parameters</h3>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Status</div>
                        <div class="value">{{ qsecbit.qsecbit.status }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Active Connections</div>
                        <div class="value">{{ qsecbit.qsecbit.connections }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Last Update</div>
                        <div class="value">{{ qsecbit.qsecbit.timestamp[:19] if qsecbit.qsecbit.timestamp else 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Threats Detected</div>
                        <div class="value">{{ qsecbit.threats.count }}</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Suricata IDS Alerts</h2>
                <div style="margin-bottom: 15px;">
                    <span class="rag-indicator rag-{{ qsecbit.suricata.rag }}">
                        <span class="rag-dot"></span>
                        {{ qsecbit.suricata.alert_count }} alerts detected
                    </span>
                </div>
                {% if qsecbit.suricata.alerts %}
                <div class="alert-list">
                    {% for alert in qsecbit.suricata.alerts %}
                    <div class="alert-item {% if alert.severity <= 2 %}sev-high{% elif alert.severity == 3 %}sev-medium{% else %}sev-low{% endif %}">
                        <div class="signature">{{ alert.signature }}</div>
                        <div class="meta">
                            {{ alert.timestamp }} | Severity: {{ alert.severity }} |
                            {{ alert.src_ip }} &rarr; {{ alert.dest_ip }}
                            {% if alert.category %}| {{ alert.category }}{% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
                {% else %}
                <p style="color: #6b7280;">No alerts detected. Network is secure.</p>
                {% endif %}
            </div>

            <div class="card">
                <h2>Threat Log</h2>
                <div style="margin-bottom: 15px;">
                    <span class="rag-indicator rag-{{ qsecbit.threats.rag }}">
                        <span class="rag-dot"></span>
                        {{ qsecbit.threats.count }} threats logged
                    </span>
                </div>
                {% if qsecbit.threats.recent %}
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
                        {% for threat in qsecbit.threats.recent %}
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
                <div style="margin-bottom: 15px;">
                    <span class="rag-indicator rag-{{ qsecbit.ovs.rag }}">
                        <span class="rag-dot"></span>
                        {% if qsecbit.ovs.config %}Configured{% else %}Not configured{% endif %}
                    </span>
                </div>
                {% if qsecbit.ovs.config %}
                <div class="param-grid">
                    {% for key, value in qsecbit.ovs.config.items() %}
                    <div class="param-item">
                        <div class="label">{{ key }}</div>
                        <div class="value">{{ value }}</div>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}

                {% if qsecbit.ovs.bridges %}
                <h3>OVS Bridges</h3>
                <pre style="background: #1f2937; color: #10b981; padding: 15px; border-radius: 8px; font-size: 12px; overflow-x: auto;">{{ qsecbit.ovs.bridges }}</pre>
                {% endif %}
            </div>
        </div>

        <!-- WiFi Tab - All WiFi Settings -->
        <div id="wifi" class="tab-content">
            <div class="card">
                <h2>Hotspot Settings</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">
                    Configure the WiFi hotspot that clients connect to.
                </p>
                <form method="post" action="/hotspot">
                    <div class="form-group">
                        <label>Hotspot Name (SSID)</label>
                        <input type="text" name="ssid" value="{{ config.hotspot_ssid }}" required>
                    </div>
                    <div class="form-group">
                        <label>Password (min 8 characters)</label>
                        <input type="password" name="password" value="{{ config.hotspot_password }}" minlength="8" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Save Hotspot Settings</button>
                </form>
            </div>

            <div class="card">
                <h2>Upstream WiFi Connection</h2>
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
                        <a href="/scan#wifi" class="btn btn-secondary">Scan Networks</a>
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

            <div class="card">
                <h2>WiFi Status</h2>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Hotspot</div>
                        <div class="value">
                            <span class="badge {% if status.hostapd %}badge-success{% else %}badge-danger{% endif %}">
                                {% if status.hostapd %}Running{% else %}Stopped{% endif %}
                            </span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Upstream</div>
                        <div class="value">
                            <span class="badge {% if status.upstream_connected %}badge-success{% else %}badge-warning{% endif %}">
                                {% if status.upstream_connected %}Connected{% else %}Disconnected{% endif %}
                            </span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Connected Clients</div>
                        <div class="value">{{ status.clients }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Hotspot SSID</div>
                        <div class="value">{{ config.hotspot_ssid }}</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- System Tab -->
        <div id="system" class="tab-content">
            <div class="card">
                <h2>System Information</h2>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Mode</div>
                        <div class="value">{{ config.mode | upper }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">IP Addresses</div>
                        <div class="value">{{ status.ip_addresses | join(', ') }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Uptime</div>
                        <div class="value">{{ status.uptime }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Memory Usage</div>
                        <div class="value">{{ status.memory_usage }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Disk Usage</div>
                        <div class="value">{{ status.disk_usage }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">CPU Temperature</div>
                        <div class="value">{{ status.cpu_temp }}</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Container Management</h2>
                <div class="container-grid" style="margin-bottom: 20px;">
                    {% for key, container in containers.items() %}
                    <div class="container-item">
                        <span class="name">{{ container.label }}</span>
                        <span class="badge {% if container.running %}badge-success{% else %}badge-danger{% endif %}">
                            {% if container.running %}Running{% else %}Stopped{% endif %}
                        </span>
                    </div>
                    {% endfor %}
                </div>
                <form method="post" action="/action">
                    <button type="submit" name="action" value="restart_containers" class="btn btn-secondary">Restart All Containers</button>
                </form>
            </div>

            <div class="card">
                <h2>System Actions</h2>
                <form method="post" action="/action">
                    <div class="btn-group">
                        <button type="submit" name="action" value="restart_hostapd" class="btn btn-primary">Restart Hotspot</button>
                        <button type="submit" name="action" value="restart_network" class="btn btn-secondary">Restart Network</button>
                        <button type="submit" name="action" value="restart_services" class="btn btn-secondary">Restart All Services</button>
                        <button type="submit" name="action" value="reboot" class="btn btn-danger" onclick="return confirm('Reboot Guardian?')">Reboot System</button>
                    </div>
                </form>
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
    </div>

    <div class="footer">
        <p>HookProbe Guardian v5.1.0 | <a href="https://hookprobe.com" target="_blank">hookprobe.com</a></p>
    </div>

    <script>
        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
                window.location.hash = tab.dataset.tab;
            });
        });

        // Check URL hash for tab
        if (window.location.hash) {
            const tabId = window.location.hash.substring(1);
            const tab = document.querySelector(`.tab[data-tab="${tabId}"]`);
            if (tab) tab.click();
        }

        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
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
    qsecbit = get_qsecbit_data()
    return render_template_string(
        HTML_TEMPLATE,
        config=config,
        status=status,
        networks=[],
        sdn_stats=sdn_stats,
        containers=containers,
        qsecbit=qsecbit,
        show_scan_result=False
    )


@app.route('/scan')
def scan():
    config = get_current_config()
    status = get_status()
    sdn_stats = get_sdn_stats()
    containers = get_container_status()
    qsecbit = get_qsecbit_data()
    networks = scan_wifi()
    return render_template_string(
        HTML_TEMPLATE,
        config=config,
        status=status,
        networks=networks,
        sdn_stats=sdn_stats,
        containers=containers,
        qsecbit=qsecbit,
        show_scan_result=True
    )


@app.route('/connect', methods=['POST'])
def connect():
    ssid = request.form.get('ssid', '').strip()
    password = request.form.get('password', '')

    if not ssid:
        flash('Please enter a network name', 'error')
        return redirect('/#wifi')

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

    return redirect('/#wifi')


@app.route('/hotspot', methods=['POST'])
def hotspot():
    ssid = request.form.get('ssid', '').strip()
    password = request.form.get('password', '')

    if not ssid or len(password) < 8:
        flash('Invalid SSID or password (min 8 chars)', 'error')
        return redirect('/#wifi')

    try:
        content = HOSTAPD_CONF.read_text()
        content = re.sub(r'^ssid=.*$', f'ssid={ssid}', content, flags=re.M)
        content = re.sub(r'^wpa_passphrase=.*$', f'wpa_passphrase={password}', content, flags=re.M)
        HOSTAPD_CONF.write_text(content)
        run_command('systemctl reload hostapd')
        flash('Hotspot settings updated', 'success')
    except Exception as e:
        flash(f'Failed to update: {e}', 'error')

    return redirect('/#wifi')


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
    elif action == 'restart_services':
        run_command('systemctl restart hostapd dnsmasq guardian-suricata guardian-waf guardian-neuro guardian-adguard guardian-webui')
        flash('All services restarting...', 'success')
    elif action == 'reboot':
        run_command('reboot')
        flash('Rebooting...', 'success')

    return redirect('/#system')


@app.route('/api/status')
def api_status():
    return jsonify(get_status())


@app.route('/api/security')
def api_security():
    return jsonify(get_qsecbit_data())


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
