#!/usr/bin/env python3
"""
HookProbe Guardian - Local Web UI

Simple Flask app for on-device configuration.
Runs on http://192.168.1.1:8080

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

    return status


# HTML Template (embedded for simplicity)
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Guardian Setup</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; margin-bottom: 20px; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h2 { margin-bottom: 15px; color: #444; font-size: 18px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 500; }
        input, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }
        button { background: #2563eb; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #1d4ed8; }
        .btn-secondary { background: #6b7280; }
        .status { display: flex; gap: 20px; flex-wrap: wrap; }
        .status-item { flex: 1; min-width: 120px; text-align: center; padding: 15px; background: #f9f9f9; border-radius: 4px; }
        .status-item .value { font-size: 24px; font-weight: bold; color: #2563eb; }
        .status-item .label { font-size: 12px; color: #666; margin-top: 5px; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .badge-success { background: #dcfce7; color: #166534; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .networks { max-height: 200px; overflow-y: auto; }
        .network-item { padding: 10px; border-bottom: 1px solid #eee; cursor: pointer; }
        .network-item:hover { background: #f5f5f5; }
        .flash { padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .flash-success { background: #dcfce7; color: #166534; }
        .flash-error { background: #fee2e2; color: #991b1b; }
    </style>
</head>
<body>
    <div class="container">
        <h1>HookProbe Guardian Setup</h1>

        {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
            <div class="flash flash-{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
        {% endwith %}

        <!-- Status -->
        <div class="card">
            <h2>System Status</h2>
            <div class="status">
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
            </div>
        </div>

        <!-- Upstream WiFi -->
        <div class="card">
            <h2>Connect to Upstream WiFi</h2>
            <form method="post" action="/connect">
                <div class="form-group">
                    <label>Network Name (SSID)</label>
                    <input type="text" name="ssid" value="{{ config.upstream_ssid }}" placeholder="Your home WiFi">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" value="{{ config.upstream_password }}">
                </div>
                <button type="submit">Connect</button>
                <button type="button" class="btn-secondary" onclick="location.href='/scan'">Scan Networks</button>
            </form>

            {% if networks %}
            <h3 style="margin-top: 20px;">Available Networks</h3>
            <div class="networks">
                {% for net in networks %}
                <div class="network-item" onclick="document.querySelector('input[name=ssid]').value='{{ net.ssid }}'">
                    <strong>{{ net.ssid }}</strong>
                    <span style="float: right; color: #666;">{{ net.signal }} dBm</span>
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
                <button type="submit">Save Settings</button>
            </form>
        </div>

        <!-- System Actions -->
        <div class="card">
            <h2>System Actions</h2>
            <form method="post" action="/action" style="display: flex; gap: 10px; flex-wrap: wrap;">
                <button type="submit" name="action" value="restart_hostapd">Restart Hotspot</button>
                <button type="submit" name="action" value="restart_network" class="btn-secondary">Restart Network</button>
                <button type="submit" name="action" value="reboot" class="btn-secondary" onclick="return confirm('Reboot Guardian?')">Reboot</button>
            </form>
        </div>
    </div>
</body>
</html>
'''


@app.route('/')
def index():
    config = get_current_config()
    status = get_status()
    return render_template_string(HTML_TEMPLATE, config=config, status=status, networks=[])


@app.route('/scan')
def scan():
    config = get_current_config()
    status = get_status()
    networks = scan_wifi()
    return render_template_string(HTML_TEMPLATE, config=config, status=status, networks=networks)


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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
