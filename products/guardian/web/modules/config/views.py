"""
Config Module Views - WiFi, Network Configuration
"""
from flask import jsonify, request
from . import config_bp
from utils import run_command


@config_bp.route('/wifi/scan', methods=['POST'])
def api_wifi_scan():
    """Scan for available WiFi networks."""
    try:
        # Use full iwlist output to get more details including IE info
        output, success = run_command('sudo iwlist wlan0 scan 2>/dev/null', timeout=30)

        networks = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()

            # New cell = new network
            if 'Cell ' in line and 'Address:' in line:
                if current and current.get('ssid'):
                    networks.append(current)
                current = {'ssid': '', 'signal': 0, 'security': ''}

            elif 'ESSID:' in line:
                ssid = line.split('ESSID:')[1].strip('"')
                current['ssid'] = ssid

            elif 'Quality=' in line:
                # Extract signal quality
                quality_part = line.split('Quality=')[1].split()[0]
                if '/' in quality_part:
                    num, denom = quality_part.split('/')
                    current['signal'] = int(int(num) / int(denom) * 100)

            elif 'Encryption key:on' in line:
                # Default to WPA if encryption is on
                if not current.get('security'):
                    current['security'] = 'WPA'

            elif 'Encryption key:off' in line:
                current['security'] = ''

            # Detect specific security types
            elif 'IE: IEEE 802.11i/WPA2' in line or 'WPA2' in line:
                current['security'] = 'WPA2'
            elif 'IE: WPA Version' in line:
                if current.get('security') != 'WPA2':
                    current['security'] = 'WPA'
            elif 'WPA3' in line or 'SAE' in line:
                current['security'] = 'WPA3'

        if current and current.get('ssid'):
            networks.append(current)

        # Remove duplicates and empty SSIDs, keep strongest signal for each SSID
        seen = {}
        for net in networks:
            ssid = net.get('ssid', '')
            if ssid:
                if ssid not in seen or net['signal'] > seen[ssid]['signal']:
                    seen[ssid] = net

        unique = list(seen.values())
        # Sort by signal strength
        unique.sort(key=lambda x: x['signal'], reverse=True)

        return jsonify({'success': True, 'networks': unique})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/wifi/connect', methods=['POST'])
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

        run_command('sudo wpa_cli -i wlan0 reconfigure')
        return jsonify({'success': True, 'message': f'Connecting to {ssid}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/hotspot', methods=['GET', 'POST'])
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


@config_bp.route('/hotspot/restart', methods=['POST'])
def api_hotspot_restart():
    """Restart the hotspot."""
    try:
        run_command('sudo systemctl restart hostapd')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/interfaces')
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
