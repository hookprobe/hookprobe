"""
Config Module Views - WiFi, Network Configuration
"""
from flask import jsonify, request
from . import config_bp
from utils import run_command


@config_bp.route('/api/wifi/scan', methods=['POST'])
def api_wifi_scan():
    """Scan for available WiFi networks."""
    try:
        output, success = run_command('iwlist wlan0 scan 2>/dev/null | grep -E "ESSID|Quality|Encryption"', timeout=30)

        networks = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()
            if 'ESSID:' in line:
                if current and current.get('ssid'):
                    networks.append(current)
                ssid = line.split('ESSID:')[1].strip('"')
                current = {'ssid': ssid, 'signal': 0, 'security': ''}
            elif 'Quality=' in line:
                # Extract signal quality
                quality_part = line.split('Quality=')[1].split()[0]
                if '/' in quality_part:
                    num, denom = quality_part.split('/')
                    current['signal'] = int(int(num) / int(denom) * 100)
            elif 'Encryption key:on' in line:
                current['security'] = 'WPA'
            elif 'Encryption key:off' in line:
                current['security'] = ''

        if current and current.get('ssid'):
            networks.append(current)

        # Remove duplicates and empty SSIDs
        seen = set()
        unique = []
        for net in networks:
            if net['ssid'] and net['ssid'] not in seen:
                seen.add(net['ssid'])
                unique.append(net)

        return jsonify({'success': True, 'networks': unique})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/api/wifi/connect', methods=['POST'])
def api_wifi_connect():
    """Connect to a WiFi network."""
    data = request.get_json()
    ssid = data.get('ssid', '').strip()
    password = data.get('password', '')

    if not ssid:
        return jsonify({'success': False, 'error': 'SSID required'}), 400

    try:
        # Create wpa_supplicant config
        config = f'''
network={{
    ssid="{ssid}"
    psk="{password}"
    key_mgmt=WPA-PSK
}}
'''
        # Save and apply
        with open('/tmp/wpa_supplicant.conf', 'w') as f:
            f.write(config)

        run_command('wpa_cli -i wlan0 reconfigure')
        return jsonify({'success': True, 'message': f'Connecting to {ssid}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/api/hotspot', methods=['GET', 'POST'])
def api_hotspot():
    """Get or update hotspot configuration."""
    if request.method == 'GET':
        try:
            # Read current hostapd config
            with open('/etc/hostapd/hostapd.conf', 'r') as f:
                content = f.read()

            config = {}
            for line in content.split('\n'):
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()

            return jsonify({
                'ssid': config.get('ssid', 'Guardian-AP'),
                'channel': config.get('channel', 'auto'),
                'security': 'wpa2' if config.get('wpa', '2') == '2' else 'wpa3',
                'hidden': config.get('ignore_broadcast_ssid', '0') == '1'
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # POST - update config
    data = request.get_json()
    ssid = data.get('ssid', 'Guardian-AP')
    password = data.get('password', '')
    channel = data.get('channel', 'auto')
    security = data.get('security', 'wpa2')
    hidden = data.get('hidden', False)

    if password and len(password) < 8:
        return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400

    try:
        config = f'''interface=wlan0
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel if channel != 'auto' else '6'}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid={'1' if hidden else '0'}
wpa=2
wpa_passphrase={password if password else 'changeme123'}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
'''
        with open('/etc/hostapd/hostapd.conf', 'w') as f:
            f.write(config)

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/api/hotspot/restart', methods=['POST'])
def api_hotspot_restart():
    """Restart the hotspot."""
    try:
        run_command('systemctl restart hostapd')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/api/interfaces')
def api_interfaces():
    """Get network interface information."""
    try:
        interfaces = []
        output, _ = run_command("ip -o addr show | grep -v '127.0.0.1' | awk '{print $2, $4}'")

        for line in output.split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[0].rstrip(':')
                ip = parts[1].split('/')[0]

                # Get MAC
                mac_output, _ = run_command(f"cat /sys/class/net/{iface}/address 2>/dev/null")
                mac = mac_output.strip() if mac_output else 'N/A'

                # Get status
                state_output, _ = run_command(f"cat /sys/class/net/{iface}/operstate 2>/dev/null")
                state = state_output.strip().upper() if state_output else 'UNKNOWN'

                interfaces.append({
                    'name': iface,
                    'ip': ip,
                    'mac': mac,
                    'status': state
                })

        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
