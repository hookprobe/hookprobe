"""
Config Module Views - WiFi, Network Configuration

Includes offline mode management for congested environments where
Guardian needs to start AP without pre-configured WAN connectivity.
"""
import sys
from pathlib import Path
from flask import jsonify, request
from . import config_bp
from utils import run_command

# Add lib directory to path for imports
lib_path = Path(__file__).parent.parent.parent.parent / 'lib'
if str(lib_path) not in sys.path:
    sys.path.insert(0, str(lib_path))


@config_bp.route('/wifi/scan', methods=['POST'])
def api_wifi_scan():
    """Scan for available WiFi networks using wlan0 (WAN interface)."""
    try:
        # wlan0 is the WAN interface used to connect to upstream networks
        # Use full iwlist output to get more details including IE info
        output, success = run_command(['sudo', 'iwlist', 'wlan0', 'scan'], timeout=30)

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

        # wlan0 is the WAN interface
        run_command(['sudo', 'wpa_cli', '-i', 'wlan0', 'reconfigure'])
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


# =============================================================================
# OFFLINE MODE ENDPOINTS
# =============================================================================

@config_bp.route('/offline/status')
def api_offline_status():
    """
    Get offline mode status.

    Returns comprehensive status including:
    - Current state (offline_ready, online, etc.)
    - AP configuration and client count
    - WAN connectivity status
    - Last channel scan results
    """
    try:
        from offline_mode_manager import OfflineModeManager
        manager = OfflineModeManager()
        manager.load_state()
        status = manager.get_status()
        return jsonify({'success': True, **status})
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'Offline mode manager not available'
        }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/offline/init', methods=['POST'])
def api_offline_init():
    """
    Initialize offline mode.

    This triggers the full boot sequence:
    1. Scan RF environment
    2. Select optimal channel
    3. Start AP
    4. Start DHCP

    Used when manually triggering offline mode or on first boot.
    """
    try:
        from offline_mode_manager import OfflineModeManager
        manager = OfflineModeManager()
        success = manager.initialize_offline_mode()
        return jsonify({
            'success': success,
            'status': manager.get_status()
        })
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'Offline mode manager not available'
        }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/offline/scan', methods=['POST'])
def api_offline_scan():
    """
    Scan RF environment for channel congestion.

    Returns:
    - Detected networks with signal strength
    - Channel scores (lower is better)
    - Recommended channels for 2.4GHz and 5GHz
    """
    try:
        from wifi_channel_scanner import WiFiChannelScanner
        # Use wlan1 (AP interface) for channel scanning since that's the AP interface
        # Scanning from the AP interface gives better insight into what the AP will experience
        scanner = WiFiChannelScanner(interface='wlan1')
        result = scanner.scan()

        return jsonify({
            'success': True,
            'networks': [
                {
                    'ssid': n.ssid,
                    'bssid': n.bssid,
                    'channel': n.channel,
                    'signal_strength': n.signal_strength,
                    'signal_quality': n.signal_quality,
                    'security': n.security,
                    'band': n.band.value
                }
                for n in result.networks
            ],
            'channel_scores': {
                str(ch): {
                    'score': round(s.score, 1),
                    'networks_count': s.networks_count,
                    'adjacent_interference': round(s.adjacent_interference, 1),
                    'is_non_overlapping': s.is_non_overlapping
                }
                for ch, s in result.channel_scores.items()
            },
            'recommended': {
                '2.4GHz': result.recommended_channel_2_4,
                '5GHz': result.recommended_channel_5
            },
            'scan_timestamp': result.scan_timestamp
        })
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'WiFi channel scanner not available'
        }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/offline/channel', methods=['POST'])
def api_offline_channel():
    """
    Change AP channel.

    Request body:
    {
        "channel": 6  // Channel number (1-11 for 2.4GHz, 36+ for 5GHz)
    }

    If channel is "auto", performs scan and selects optimal channel.
    """
    data = request.get_json() or {}
    channel = data.get('channel', 'auto')

    try:
        from offline_mode_manager import OfflineModeManager

        manager = OfflineModeManager()
        manager.load_state()

        if channel == 'auto':
            # Scan and select best channel
            channel, score, networks = manager.scan_and_select_channel()

        # Validate channel
        if isinstance(channel, str):
            try:
                channel = int(channel)
            except ValueError:
                return jsonify({
                    'success': False,
                    'error': 'Invalid channel number'
                }), 400

        # Change channel
        success = manager.restart_ap_with_channel(channel)

        return jsonify({
            'success': success,
            'channel': channel,
            'status': manager.get_status()
        })
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'Offline mode manager not available'
        }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/offline/connect', methods=['POST'])
def api_offline_connect():
    """
    Connect to upstream WiFi network.

    Request body:
    {
        "ssid": "CoffeeShop-WiFi",
        "password": "password123"
    }

    This enables internet connectivity while keeping the local AP running.
    """
    data = request.get_json() or {}
    ssid = data.get('ssid', '').strip()
    password = data.get('password', '')

    if not ssid:
        return jsonify({
            'success': False,
            'error': 'SSID is required'
        }), 400

    try:
        from offline_mode_manager import OfflineModeManager

        manager = OfflineModeManager()
        manager.load_state()

        success, message = manager.connect_upstream(ssid, password)

        return jsonify({
            'success': success,
            'message': message,
            'status': manager.get_status()
        })
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'Offline mode manager not available'
        }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/offline/networks')
def api_offline_networks():
    """
    Get available upstream networks for connection.

    Scans for available WiFi networks that can be used as upstream/WAN.
    Similar to /wifi/scan but with additional metadata for offline mode.
    """
    try:
        from wifi_channel_scanner import WiFiChannelScanner

        scanner = WiFiChannelScanner(interface='wlan0')
        result = scanner.scan()

        # Format for upstream selection
        networks = []
        for net in result.networks:
            # Skip our own AP
            if 'HookProbe' in net.ssid or 'Guardian' in net.ssid:
                continue

            networks.append({
                'ssid': net.ssid,
                'signal': net.signal_quality,
                'signal_dbm': net.signal_strength,
                'security': net.security,
                'channel': net.channel,
                'band': net.band.value
            })

        # Sort by signal strength
        networks.sort(key=lambda x: x['signal'], reverse=True)

        # Remove duplicates (keep strongest)
        seen = set()
        unique = []
        for net in networks:
            if net['ssid'] and net['ssid'] not in seen:
                seen.add(net['ssid'])
                unique.append(net)

        return jsonify({
            'success': True,
            'networks': unique,
            'scan_timestamp': result.scan_timestamp
        })
    except ImportError:
        # Fallback to basic iwlist scan
        return api_wifi_scan()
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/offline/fix-eth0', methods=['POST'])
def api_offline_fix_eth0():
    """
    Fix eth0 DHCP issues (169.254.x.x link-local addresses).

    This attempts to:
    1. Release any existing DHCP lease
    2. Flush the interface
    3. Restart DHCP client
    4. Return the new IP address

    Use when eth0 gets stuck with 169.254.x.x address.
    """
    try:
        from offline_mode_manager import OfflineModeManager

        manager = OfflineModeManager()
        success, ip = manager.fix_eth0_dhcp()

        return jsonify({
            'success': success,
            'ip': ip,
            'message': f'eth0 now has IP: {ip}' if success else 'DHCP fix failed'
        })
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'Offline mode manager not available'
        }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/offline/route-metrics', methods=['GET', 'POST'])
def api_offline_route_metrics():
    """
    Get or configure route metrics.

    GET: Returns current route metrics and interface status
    POST: Reconfigures route metrics (eth0 priority over wlan)

    Route metric priority (lower = higher priority):
    - eth0: 100 (always preferred when connected)
    - wlan upstream: 200
    - wlan AP: 600 (no default route)
    """
    try:
        from offline_mode_manager import OfflineModeManager

        manager = OfflineModeManager()

        if request.method == 'POST':
            # Reconfigure metrics
            success = manager.configure_route_metrics()
            return jsonify({
                'success': success,
                'message': 'Route metrics configured' if success else 'Configuration failed'
            })

        # GET - return current status
        # Get current routes
        from utils import run_command
        output, _ = run_command("ip route show default")

        routes = []
        for line in output.split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            route = {'raw': line}
            if 'dev' in parts:
                route['interface'] = parts[parts.index('dev') + 1]
            if 'via' in parts:
                route['gateway'] = parts[parts.index('via') + 1]
            if 'metric' in parts:
                route['metric'] = int(parts[parts.index('metric') + 1])
            else:
                route['metric'] = 0  # No metric = highest priority
            routes.append(route)

        # Sort by metric
        routes.sort(key=lambda x: x.get('metric', 0))

        return jsonify({
            'success': True,
            'routes': routes,
            'config': {
                'eth0_metric': manager.config.eth0_metric,
                'wlan_upstream_metric': manager.config.wlan_upstream_metric,
                'wlan_ap_metric': manager.config.wlan_ap_metric
            }
        })
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'Offline mode manager not available'
        }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/offline/wan-detect')
def api_offline_wan_detect():
    """
    Detect the best WAN interface.

    Returns the highest priority working WAN interface:
    1. eth0 with valid IP (not 169.254.x.x)
    2. wlan upstream with valid IP
    3. None if no WAN available
    """
    try:
        from offline_mode_manager import OfflineModeManager

        manager = OfflineModeManager()
        interface, ip = manager.detect_wan_interface()

        if interface:
            return jsonify({
                'success': True,
                'interface': interface,
                'ip': ip,
                'has_wan': True
            })
        else:
            return jsonify({
                'success': True,
                'interface': None,
                'ip': None,
                'has_wan': False,
                'message': 'No working WAN interface found'
            })
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'Offline mode manager not available'
        }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
