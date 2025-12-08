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
    """Get network interface information (physical interfaces only)."""
    try:
        interfaces = []

        # Virtual/bridge interfaces to hide from the UI
        # These are internal networking interfaces not relevant to users
        HIDDEN_INTERFACES = {
            'lo',           # Loopback
            'podman0',      # Podman default bridge
            'docker0',      # Docker default bridge
            'virbr0',       # Libvirt default bridge
            'guardian',     # OVS bridge for VXLAN/SDN
            'br-guardian',  # OVS bridge variant
            'br-sdn',       # SDN bridge
        }

        # Prefixes for virtual interfaces to skip
        VIRTUAL_PREFIXES = (
            'veth',         # Container virtual ethernet
            'cni',          # Container network interface
            'flannel',      # Kubernetes networking
            'cali',         # Calico networking
            'tunl',         # Tunnel interfaces
            'dummy',        # Dummy interfaces
        )

        # Get list of interfaces from /sys/class/net
        import os
        net_dir = '/sys/class/net'
        if os.path.exists(net_dir):
            for iface in os.listdir(net_dir):
                # Skip hidden interfaces
                if iface in HIDDEN_INTERFACES:
                    continue

                # Skip virtual interface prefixes
                if iface.startswith(VIRTUAL_PREFIXES):
                    continue

                try:
                    # Get IP address
                    ip_output, _ = run_command(['ip', 'addr', 'show', iface])
                    ip = 'N/A'
                    for line in ip_output.split('\n'):
                        line = line.strip()
                        if line.startswith('inet ') and 'inet6' not in line:
                            # Format: inet 192.168.1.1/24 ...
                            ip = line.split()[1].split('/')[0]
                            break

                    # Get MAC address
                    mac_path = f'/sys/class/net/{iface}/address'
                    mac = 'N/A'
                    if os.path.exists(mac_path):
                        with open(mac_path, 'r') as f:
                            mac = f.read().strip()

                    # Get status
                    state_path = f'/sys/class/net/{iface}/operstate'
                    state = 'UNKNOWN'
                    if os.path.exists(state_path):
                        with open(state_path, 'r') as f:
                            state = f.read().strip().upper()

                    # Get interface type/role
                    role = 'Unknown'
                    if iface == 'eth0':
                        role = 'WAN (Primary)'
                    elif iface == 'wlan0':
                        role = 'WAN (Fallback)'
                    elif iface == 'wlan1':
                        role = 'LAN (AP)'
                    elif iface.startswith('br'):
                        role = 'Bridge'
                    elif iface.startswith('enp') or iface.startswith('eno'):
                        role = 'Ethernet'
                    elif iface.startswith('wlp'):
                        role = 'WiFi'

                    interfaces.append({
                        'name': iface,
                        'ip': ip,
                        'mac': mac,
                        'status': state,
                        'role': role
                    })
                except Exception:
                    continue

        # Sort: eth0 first, then wlan0, wlan1, others
        priority = {'eth0': 0, 'wlan0': 1, 'wlan1': 2}
        interfaces.sort(key=lambda x: priority.get(x['name'], 99))

        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'error': str(e), 'interfaces': []}), 500


# =============================================================================
# OFFLINE MODE ENDPOINTS
# =============================================================================

@config_bp.route('/offline/status')
def api_offline_status():
    """
    Get offline mode status with fallback to direct detection.

    Returns comprehensive status including:
    - Current state (offline_ready, online, etc.)
    - AP configuration and client count
    - WAN connectivity status
    - Last channel scan results
    """
    import os

    # Build status from direct detection as fallback
    status = {
        'success': True,
        'state': 'online',
        'wan_connected': False,
        'wan_ip': None,
        'wan_interface': None,
        'ap_ssid': 'HookProbe-Guardian',
        'current_channel': '--',
        'current_band': '2.4GHz',
        'clients_connected': 0,
        'networks_detected': 0,
        'last_channel_score': 0
    }

    # Check eth0 first (primary WAN)
    eth0_ip = _get_interface_ip('eth0')
    if eth0_ip and not eth0_ip.startswith('169.254.'):
        status['wan_connected'] = True
        status['wan_ip'] = eth0_ip
        status['wan_interface'] = 'eth0'
        status['state'] = 'online'

    # Check wlan0 if eth0 not connected (fallback WAN)
    if not status['wan_connected']:
        wlan0_ip = _get_interface_ip('wlan0')
        if wlan0_ip and not wlan0_ip.startswith('169.254.'):
            status['wan_connected'] = True
            status['wan_ip'] = wlan0_ip
            status['wan_interface'] = 'wlan0'
            status['state'] = 'online'
            # Try to get SSID
            ssid_out, _ = run_command(['iwgetid', 'wlan0', '-r'])
            if ssid_out:
                status['wan_ssid'] = ssid_out.strip()

    # Get AP info from hostapd config
    try:
        if os.path.exists('/etc/hostapd/hostapd.conf'):
            with open('/etc/hostapd/hostapd.conf', 'r') as f:
                for line in f:
                    if line.startswith('ssid='):
                        status['ap_ssid'] = line.split('=', 1)[1].strip()
                    elif line.startswith('channel='):
                        status['current_channel'] = line.split('=', 1)[1].strip()
    except Exception:
        pass

    # Try to get more info from offline mode manager if available
    try:
        from offline_mode_manager import OfflineModeManager
        manager = OfflineModeManager()
        manager.load_state()
        manager_status = manager.get_status()
        # Merge manager status but keep our WAN detection
        for key in ['networks_detected', 'last_channel_score', 'clients_connected']:
            if key in manager_status:
                status[key] = manager_status[key]
    except Exception:
        pass

    # Also include scan data in nested format for UI compatibility
    status['scan'] = {
        'networks_detected': status.get('networks_detected', 0),
        'channel_score': status.get('last_channel_score', 0)
    }

    # Include WAN data in nested format
    status['wan'] = {
        'connected': status.get('wan_connected', False),
        'ip': status.get('wan_ip'),
        'ssid': status.get('wan_ssid'),
        'interface': status.get('wan_interface')
    }

    # Include AP data in nested format
    status['ap'] = {
        'ssid': status.get('ap_ssid', 'HookProbe-Guardian'),
        'channel': status.get('current_channel', '--'),
        'band': status.get('current_band', '2.4GHz'),
        'clients': status.get('clients_connected', 0)
    }

    return jsonify(status)


def _get_interface_ip(interface):
    """Helper to get IP address of an interface."""
    import os
    try:
        output, success = run_command(['ip', 'addr', 'show', interface])
        if success and output:
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('inet ') and 'inet6' not in line:
                    return line.split()[1].split('/')[0]
    except Exception:
        pass
    return None


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


@config_bp.route('/offline/survey')
def api_offline_survey():
    """
    Get channel utilization from iw survey dump.

    This works while AP is running WITHOUT disconnecting clients.
    Returns noise and utilization data for the current channel.
    """
    import os

    # Find AP interface
    ap_interface = 'wlan1'
    net_dir = '/sys/class/net'
    if os.path.exists(f'{net_dir}/wlan1'):
        ap_interface = 'wlan1'
    elif os.path.exists(f'{net_dir}/wlan0'):
        ap_interface = 'wlan0'

    try:
        # Get survey dump - works while AP is running
        output, success = run_command(['sudo', 'iw', 'dev', ap_interface, 'survey', 'dump'])

        if not success or not output:
            return jsonify({'success': False, 'error': 'Survey dump failed'}), 500

        # Parse survey output
        channels = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('Survey data from'):
                if current:
                    channels.append(current)
                current = {}
            elif 'frequency:' in line:
                try:
                    freq = int(line.split(':')[1].strip().split()[0])
                    current['frequency'] = freq
                    if 2400 <= freq <= 2500:
                        current['channel'] = (freq - 2407) // 5
                        current['band'] = '2.4GHz'
                    elif freq >= 5000:
                        current['channel'] = (freq - 5000) // 5
                        current['band'] = '5GHz'
                except (ValueError, IndexError):
                    pass
            elif 'noise:' in line:
                try:
                    current['noise'] = int(line.split(':')[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif 'channel active time:' in line:
                try:
                    current['active_time'] = int(line.split(':')[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif 'channel busy time:' in line:
                try:
                    current['busy_time'] = int(line.split(':')[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif '[in use]' in line:
                current['in_use'] = True

        if current:
            channels.append(current)

        # Calculate utilization
        for ch in channels:
            if ch.get('active_time') and ch.get('busy_time'):
                ch['utilization'] = round((ch['busy_time'] / ch['active_time']) * 100, 1)
            else:
                ch['utilization'] = 0

        # Find current channel
        current_channel = next((ch for ch in channels if ch.get('in_use')), None)

        return jsonify({
            'success': True,
            'interface': ap_interface,
            'channels': channels,
            'current': current_channel,
            'source': 'survey_dump'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/offline/scan', methods=['POST'])
def api_offline_scan():
    """
    Get channel data using non-disruptive methods.

    Uses 'iw survey dump' for channel utilization data while AP is running.
    Does NOT disconnect clients. For full RF scan, use /offline/rescan.
    """
    import os
    import json

    # Get stored scan results from state file (from boot)
    state_file = '/var/lib/guardian/offline_state.json'
    stored_data = None
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                stored_data = json.load(f)
        except Exception:
            pass

    # Get current channel from hostapd config
    current_channel = 6
    try:
        if os.path.exists('/etc/hostapd/hostapd.conf'):
            with open('/etc/hostapd/hostapd.conf', 'r') as f:
                for line in f:
                    if line.startswith('channel='):
                        current_channel = int(line.split('=')[1].strip())
                        break
    except Exception:
        pass

    # Get channel utilization via survey (non-disruptive)
    ap_interface = 'wlan1' if os.path.exists('/sys/class/net/wlan1') else 'wlan0'
    survey_data = {}

    try:
        output, success = run_command(['sudo', 'iw', 'dev', ap_interface, 'survey', 'dump'])
        if success and output:
            current = {}
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('Survey data from'):
                    if current.get('channel'):
                        survey_data[current['channel']] = current
                    current = {}
                elif 'frequency:' in line:
                    try:
                        freq = int(line.split(':')[1].strip().split()[0])
                        if 2400 <= freq <= 2500:
                            current['channel'] = (freq - 2407) // 5
                    except (ValueError, IndexError):
                        pass
                elif 'noise:' in line:
                    try:
                        current['noise'] = int(line.split(':')[1].strip().split()[0])
                    except (ValueError, IndexError):
                        pass
                elif 'channel busy time:' in line:
                    try:
                        current['busy_time'] = int(line.split(':')[1].strip().split()[0])
                    except (ValueError, IndexError):
                        pass
                elif 'channel active time:' in line:
                    try:
                        current['active_time'] = int(line.split(':')[1].strip().split()[0])
                    except (ValueError, IndexError):
                        pass
            if current.get('channel'):
                survey_data[current['channel']] = current
    except Exception:
        pass

    # Build channel scores from survey data
    channel_scores = {}
    for ch in [1, 6, 11]:
        if ch in survey_data:
            sd = survey_data[ch]
            noise_score = max(0, (sd.get('noise', -90) + 90) * 2)
            busy_pct = 0
            if sd.get('active_time') and sd.get('busy_time'):
                busy_pct = (sd['busy_time'] / sd['active_time']) * 100
            score = noise_score + busy_pct
            channel_scores[str(ch)] = {
                'score': round(score, 1),
                'noise': sd.get('noise', 0),
                'utilization': round(busy_pct, 1),
                'networks_count': stored_data.get('networks_detected', 0) if stored_data else 0,
                'adjacent_interference': 0,
                'is_non_overlapping': True
            }
        else:
            channel_scores[str(ch)] = {
                'score': 0, 'noise': 0, 'utilization': 0,
                'networks_count': 0, 'adjacent_interference': 0, 'is_non_overlapping': True
            }

    # Mark current channel
    if str(current_channel) in channel_scores:
        channel_scores[str(current_channel)]['current'] = True

    # Find best channel
    best_channel = min([1, 6, 11], key=lambda c: channel_scores.get(str(c), {}).get('score', 100))

    return jsonify({
        'success': True,
        'networks': [],
        'channel_scores': channel_scores,
        'recommended': {'2.4GHz': best_channel, '5GHz': None},
        'current_channel': current_channel,
        'scan_timestamp': stored_data.get('last_scan_time') if stored_data else None,
        'networks_detected': stored_data.get('networks_detected', 0) if stored_data else 0,
        'source': 'survey_dump'
    })


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


@config_bp.route('/offline/route-metrics', methods=['GET'])
def api_offline_route_metrics():
    """
    Get route metrics showing eth0 as primary and wlan0 as fallback.

    Route metric priority (lower = higher priority):
    - eth0: 100 (Primary - always preferred when connected)
    - wlan0: 200 (Fallback - used when eth0 unavailable)
    """
    try:
        # Get current routes
        output, _ = run_command(['ip', 'route', 'show', 'default'])

        routes = []
        seen_interfaces = set()  # Track interfaces to deduplicate

        for line in output.split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            route = {'raw': line}
            if 'dev' in parts:
                iface = parts[parts.index('dev') + 1]

                # Skip bridge interfaces, virtual interfaces, and containers
                if iface.startswith(('br', 'docker', 'podman', 'veth', 'virbr', 'guardian')):
                    continue

                # Only show eth0 and wlan0
                if iface not in ['eth0', 'wlan0']:
                    continue

                # Skip duplicates - keep only first (lowest metric) route per interface
                if iface in seen_interfaces:
                    continue
                seen_interfaces.add(iface)

                route['interface'] = iface
                # Set role based on interface
                if iface == 'eth0':
                    route['role'] = 'Primary'
                elif iface == 'wlan0':
                    route['role'] = 'Fallback'
                else:
                    route['role'] = 'Other'

            if 'via' in parts:
                route['gateway'] = parts[parts.index('via') + 1]
            if 'metric' in parts:
                route['metric'] = int(parts[parts.index('metric') + 1])
            else:
                route['metric'] = 0  # No metric = highest priority

            if route.get('interface'):
                routes.append(route)

        # Sort by metric
        routes.sort(key=lambda x: x.get('metric', 0))

        return jsonify({
            'success': True,
            'routes': routes,
            'config': {
                'eth0_metric': 100,
                'wlan0_metric': 200
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'routes': []}), 500


@config_bp.route('/eth0/config', methods=['GET', 'POST'])
def api_eth0_config():
    """
    Get or set eth0 configuration (DHCP or manual).

    GET: Returns current eth0 configuration
    POST: Set eth0 to DHCP or manual IP configuration

    Request body for manual config:
    {
        "mode": "manual",
        "ip": "192.168.1.100",
        "netmask": "255.255.255.0",
        "gateway": "192.168.1.1",
        "dns": "8.8.8.8"
    }

    Request body for DHCP:
    {
        "mode": "dhcp"
    }
    """
    import os

    if request.method == 'GET':
        # Get current eth0 config
        config = {
            'mode': 'dhcp',
            'ip': _get_interface_ip('eth0') or '',
            'netmask': '255.255.255.0',
            'gateway': '',
            'dns': ''
        }

        # Check dhcpcd.conf for static config
        try:
            if os.path.exists('/etc/dhcpcd.conf'):
                with open('/etc/dhcpcd.conf', 'r') as f:
                    content = f.read()
                    if 'interface eth0' in content and 'static ip_address' in content:
                        config['mode'] = 'static'
                        # Parse static config (simplified)
                        for line in content.split('\n'):
                            if 'static ip_address=' in line:
                                ip_cidr = line.split('=')[1].strip()
                                if '/' in ip_cidr:
                                    config['ip'] = ip_cidr.split('/')[0]
                            elif 'static routers=' in line:
                                config['gateway'] = line.split('=')[1].strip()
                            elif 'static domain_name_servers=' in line:
                                config['dns'] = line.split('=')[1].strip()
        except Exception:
            pass

        # Get default gateway if not set
        if not config['gateway']:
            gw_out, _ = run_command(['ip', 'route', 'show', 'default', 'dev', 'eth0'])
            if gw_out:
                parts = gw_out.split()
                if 'via' in parts:
                    config['gateway'] = parts[parts.index('via') + 1]

        # Return config at root level for JS compatibility
        return jsonify({
            'success': True,
            'mode': config['mode'],
            'ip': config['ip'],
            'netmask': config['netmask'],
            'gateway': config['gateway'],
            'dns': config['dns']
        })

    # POST - set configuration
    data = request.get_json() or {}
    mode = data.get('mode', 'dhcp')

    try:
        if mode == 'dhcp':
            # Remove static config from dhcpcd.conf
            _set_eth0_dhcp()
            return jsonify({'success': True, 'message': 'eth0 set to DHCP'})
        elif mode == 'static':
            ip = data.get('ip', '').strip()
            netmask = data.get('netmask', '255.255.255.0').strip()
            gateway = data.get('gateway', '').strip()
            dns = data.get('dns', '8.8.8.8').strip()

            if not ip:
                return jsonify({'success': False, 'error': 'IP address required'}), 400

            # Calculate CIDR prefix from netmask
            prefix = _netmask_to_cidr(netmask)

            success = _set_eth0_static(ip, prefix, gateway, dns)
            if success:
                return jsonify({'success': True, 'message': f'eth0 set to {ip}/{prefix}'})
            else:
                return jsonify({'success': False, 'error': 'Failed to configure'}), 500
        else:
            return jsonify({'success': False, 'error': 'Invalid mode'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def _netmask_to_cidr(netmask):
    """Convert netmask to CIDR prefix."""
    try:
        parts = [int(x) for x in netmask.split('.')]
        binary = ''.join([bin(x)[2:].zfill(8) for x in parts])
        return binary.count('1')
    except Exception:
        return 24


def _set_eth0_dhcp():
    """Set eth0 to DHCP mode."""
    import os

    dhcpcd_conf = '/etc/dhcpcd.conf'
    if not os.path.exists(dhcpcd_conf):
        return True

    # Read current config
    with open(dhcpcd_conf, 'r') as f:
        lines = f.readlines()

    # Remove eth0 static config
    new_lines = []
    skip_eth0_section = False
    for line in lines:
        if line.strip() == 'interface eth0':
            skip_eth0_section = True
            continue
        if skip_eth0_section:
            if line.startswith('static ') or line.strip() == '':
                continue
            else:
                skip_eth0_section = False
        new_lines.append(line)

    # Write back
    with open('/tmp/dhcpcd.conf.new', 'w') as f:
        f.writelines(new_lines)
    run_command(['sudo', 'cp', '/tmp/dhcpcd.conf.new', dhcpcd_conf])

    # Restart networking
    run_command(['sudo', 'dhcpcd', '-n', 'eth0'])
    return True


def _set_eth0_static(ip, prefix, gateway, dns):
    """Set eth0 to static IP."""
    import os

    dhcpcd_conf = '/etc/dhcpcd.conf'

    # First remove any existing eth0 config
    _set_eth0_dhcp()

    # Add static config
    static_config = f"""
interface eth0
static ip_address={ip}/{prefix}
"""
    if gateway:
        static_config += f"static routers={gateway}\n"
    if dns:
        static_config += f"static domain_name_servers={dns}\n"

    # Append to dhcpcd.conf
    with open('/tmp/eth0_static.conf', 'w') as f:
        f.write(static_config)

    run_command(['sudo', 'bash', '-c', f'cat /tmp/eth0_static.conf >> {dhcpcd_conf}'])

    # Apply static IP immediately
    run_command(['sudo', 'ip', 'addr', 'flush', 'dev', 'eth0'])
    run_command(['sudo', 'ip', 'addr', 'add', f'{ip}/{prefix}', 'dev', 'eth0'])
    if gateway:
        run_command(['sudo', 'ip', 'route', 'add', 'default', 'via', gateway, 'dev', 'eth0', 'metric', '100'])

    return True


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
