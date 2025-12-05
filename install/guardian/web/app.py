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
from pathlib import Path

from flask import Flask, render_template_string, request, redirect, flash, jsonify

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration paths
HOSTAPD_CONF = Path('/etc/hostapd/hostapd.conf')
WPA_SUPPLICANT_CONF = Path('/etc/wpa_supplicant/wpa_supplicant-wlan1.conf')
DNSMASQ_CONF = Path('/etc/dnsmasq.d/guardian.conf')
MODE_FILE = Path('/opt/hookprobe/guardian/mode.conf')


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
    # Detect mode from hostapd config
    if HOSTAPD_CONF.exists():
        content = HOSTAPD_CONF.read_text()
        if 'dynamic_vlan=1' in content:
            return 'sdn'
    return 'basic'


def scan_wifi():
    """Scan for available WiFi networks."""
    output, success = run_command('iw wlan1 scan 2>/dev/null || iwlist wlan1 scan 2>/dev/null')
    networks = []

    if 'iw' in output or 'ESSID' in output:
        # Parse iw or iwlist output
        import re
        for match in re.finditer(r'ESSID:"([^"]*)".*?Signal level[=:](-?\d+)', output, re.DOTALL):
            ssid, signal = match.groups()
            if ssid:
                networks.append({'ssid': ssid, 'signal': int(signal)})

    # Sort by signal strength
    networks.sort(key=lambda x: x['signal'], reverse=True)
    return networks[:20]  # Top 20


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

    # Parse hostapd.conf
    if HOSTAPD_CONF.exists():
        content = HOSTAPD_CONF.read_text()
        for line in content.split('\n'):
            if line.startswith('ssid='):
                config['hotspot_ssid'] = line.split('=', 1)[1]
            elif line.startswith('wpa_passphrase='):
                config['hotspot_password'] = line.split('=', 1)[1]

    # Parse wpa_supplicant.conf
    if WPA_SUPPLICANT_CONF.exists():
        content = WPA_SUPPLICANT_CONF.read_text()
        import re
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

    # Check if upstream WiFi is connected
    output, _ = run_command('iw wlan1 link')
    status['upstream_connected'] = 'Connected' in output

    # Get IP addresses
    output, _ = run_command('hostname -I')
    status['ip_addresses'] = output.split()

    # Check hostapd status
    output, _ = run_command('systemctl is-active hostapd')
    status['hostapd'] = output == 'active'

    # Check dnsmasq status
    output, _ = run_command('systemctl is-active dnsmasq')
    status['dnsmasq'] = output == 'active'

    # Get connected clients count
    output, _ = run_command('iw dev wlan0 station dump | grep Station | wc -l')
    status['clients'] = int(output) if output.isdigit() else 0

    # Get mode
    status['mode'] = get_mode()

    return status


def get_sdn_stats():
    """Get SDN-specific statistics (only in SDN mode)."""
    if get_mode() != 'sdn':
        return None

    stats = {
        'vlans': [],
        'devices': 0,
        'quarantined': 0,
    }

    # Get VLAN interface stats
    output, _ = run_command("ip -br link show | grep 'br[0-9]'")
    for line in output.split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) >= 2:
                stats['vlans'].append({
                    'name': parts[0],
                    'state': parts[1]
                })

    # Try to get device count from DHCP leases
    output, _ = run_command('cat /var/lib/misc/dnsmasq.leases 2>/dev/null | wc -l')
    stats['devices'] = int(output) if output.isdigit() else 0

    return stats


# HTML Template - HookProbe branded
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

        /* Header */
        .header {
            background: linear-gradient(135deg, var(--hp-dark) 0%, #374151 100%);
            color: white;
            padding: 20px;
            text-align: center;
        }
        .header h1 {
            font-size: 24px;
            margin-bottom: 5px;
        }
        .header .subtitle {
            font-size: 14px;
            opacity: 0.8;
        }
        .header .version {
            font-size: 12px;
            opacity: 0.6;
            margin-top: 5px;
        }
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

        .container { max-width: 800px; margin: 0 auto; padding: 20px; }

        /* Cards */
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

        /* Status Grid */
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
            letter-spacing: 0.5px;
        }

        /* Badges */
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

        /* Forms */
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
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        input:focus, select:focus {
            outline: none;
            border-color: var(--hp-primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        /* Buttons */
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
        .btn-secondary:hover { background: #4b5563; }
        .btn-success { background: var(--hp-secondary); color: white; }
        .btn-success:hover { background: #059669; }
        .btn-danger { background: var(--hp-danger); color: white; }
        .btn-danger:hover { background: #dc2626; }

        .btn-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        /* Networks List */
        .networks {
            max-height: 200px;
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
            transition: background 0.2s;
        }
        .network-item:last-child { border-bottom: none; }
        .network-item:hover { background: var(--hp-light); }
        .network-item .signal {
            font-size: 12px;
            color: #6b7280;
        }

        /* Flash Messages */
        .flash {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .flash-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .flash-error { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }

        /* SDN Section */
        .sdn-section { display: none; }
        .sdn-enabled .sdn-section { display: block; }

        .vlan-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        .vlan-item {
            padding: 12px;
            background: var(--hp-light);
            border-radius: 8px;
            text-align: center;
        }
        .vlan-item .name {
            font-weight: 600;
            color: var(--hp-dark);
        }
        .vlan-item .state {
            font-size: 12px;
            color: #6b7280;
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 20px;
            color: #6b7280;
            font-size: 12px;
        }
        .footer a {
            color: var(--hp-primary);
            text-decoration: none;
        }

        @media (max-width: 600px) {
            .status-grid { grid-template-columns: repeat(2, 1fr); }
            .btn-group { flex-direction: column; }
            .btn { width: 100%; }
        }
    </style>
</head>
<body class="{{ 'sdn-enabled' if config.mode == 'sdn' else '' }}">
    <!-- Header -->
    <div class="header">
        <h1>HookProbe Guardian</h1>
        <div class="subtitle">Portable SDN Security Gateway</div>
        <div class="mode-badge mode-{{ config.mode }}">
            {{ 'SDN Mode' if config.mode == 'sdn' else 'Basic Mode' }}
        </div>
        <div class="version">v5.0.0</div>
    </div>

    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
            <div class="flash flash-{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
        {% endwith %}

        <!-- System Status -->
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
                    <span class="badge {% if status.upstream_connected %}badge-success{% else %}badge-danger{% endif %}">
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

        <!-- SDN Status (only in SDN mode) -->
        <div class="card sdn-section">
            <h2>SDN Status</h2>
            {% if sdn_stats %}
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
            {% if sdn_stats.vlans %}
            <div class="vlan-list">
                {% for vlan in sdn_stats.vlans %}
                <div class="vlan-item">
                    <div class="name">{{ vlan.name }}</div>
                    <div class="state">{{ vlan.state }}</div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            {% endif %}
        </div>

        <!-- Upstream WiFi -->
        <div class="card">
            <h2>Connect to Upstream WiFi</h2>
            <form method="post" action="/connect">
                <div class="form-group">
                    <label>Network Name (SSID)</label>
                    <input type="text" name="ssid" value="{{ config.upstream_ssid }}" placeholder="Your home/hotel WiFi">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" value="{{ config.upstream_password }}">
                </div>
                <div class="btn-group">
                    <button type="submit" class="btn btn-primary">Connect</button>
                    <button type="button" class="btn btn-secondary" onclick="location.href='/scan'">Scan Networks</button>
                </div>
            </form>

            {% if networks %}
            <div class="networks">
                {% for net in networks %}
                <div class="network-item" onclick="document.querySelector('input[name=ssid]').value='{{ net.ssid }}'">
                    <strong>{{ net.ssid }}</strong>
                    <span class="signal">{{ net.signal }} dBm</span>
                </div>
                {% endfor %}
            </div>
            {% endif %}
        </div>

        <!-- Hotspot Settings -->
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

        <!-- System Actions -->
        <div class="card">
            <h2>System Actions</h2>
            <form method="post" action="/action">
                <div class="btn-group">
                    <button type="submit" name="action" value="restart_hostapd" class="btn btn-primary">Restart Hotspot</button>
                    <button type="submit" name="action" value="restart_network" class="btn btn-secondary">Restart Network</button>
                    <button type="submit" name="action" value="reboot" class="btn btn-danger" onclick="return confirm('Reboot Guardian?')">Reboot</button>
                </div>
            </form>
        </div>
    </div>

    <div class="footer">
        <p>HookProbe Guardian v5.0.0 | <a href="https://hookprobe.com" target="_blank">hookprobe.com</a></p>
        <p>MIT License</p>
    </div>
</body>
</html>
'''


@app.route('/')
def index():
    config = get_current_config()
    status = get_status()
    sdn_stats = get_sdn_stats()
    return render_template_string(HTML_TEMPLATE, config=config, status=status, networks=[], sdn_stats=sdn_stats)


@app.route('/scan')
def scan():
    config = get_current_config()
    status = get_status()
    sdn_stats = get_sdn_stats()
    networks = scan_wifi()
    return render_template_string(HTML_TEMPLATE, config=config, status=status, networks=networks, sdn_stats=sdn_stats)


@app.route('/connect', methods=['POST'])
def connect():
    ssid = request.form.get('ssid', '').strip()
    password = request.form.get('password', '')

    if not ssid:
        flash('Please enter a network name', 'error')
        return redirect('/')

    # Update wpa_supplicant.conf
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
        import re
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


@app.route('/api/sdn')
def api_sdn():
    stats = get_sdn_stats()
    if stats:
        return jsonify(stats)
    return jsonify({'error': 'SDN mode not enabled'}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
