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


@config_bp.route('/wifi/status')
def api_wifi_status():
    """Get wlan0 connection status."""
    try:
        import os

        if not os.path.exists('/sys/class/net/wlan0'):
            return jsonify({
                'connected': False,
                'interface': 'wlan0',
                'error': 'Interface not found'
            })

        result = {
            'connected': False,
            'interface': 'wlan0',
            'ssid': None,
            'ip': None,
            'state': 'DISCONNECTED',
            'bssid': None,
            'freq': None,
            'method': None
        }

        # Try NetworkManager first
        nm_output, nm_ok = run_command(['systemctl', 'is-active', 'NetworkManager'], timeout=5)
        if nm_ok and nm_output and nm_output.strip() == 'active':
            result['method'] = 'nmcli'
            # Get device status from nmcli
            dev_output, ok = run_command(
                ['nmcli', '-t', '-f', 'GENERAL.STATE,GENERAL.CONNECTION,WIRED-PROPERTIES.CARRIER',
                 'device', 'show', 'wlan0'],
                timeout=5
            )
            if ok and dev_output:
                for line in dev_output.strip().split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        if 'STATE' in key and 'connected' in value.lower():
                            result['connected'] = True
                            result['state'] = 'CONNECTED'
                        elif 'CONNECTION' in key and value and value != '--':
                            # Connection name often contains SSID
                            result['ssid'] = value.replace('guardian-', '')

            # Get more details from wifi show
            wifi_output, ok = run_command(
                ['nmcli', '-t', '-f', 'ACTIVE,SSID,BSSID,FREQ', 'device', 'wifi', 'list', 'ifname', 'wlan0'],
                timeout=5
            )
            if ok and wifi_output:
                for line in wifi_output.strip().split('\n'):
                    parts = line.split(':')
                    if len(parts) >= 4 and parts[0] == 'yes':
                        result['ssid'] = parts[1] if parts[1] else result['ssid']
                        result['bssid'] = parts[2] if parts[2] else None
                        result['freq'] = parts[3] if parts[3] else None
                        break
        else:
            result['method'] = 'wpa_supplicant'
            # Fallback to wpa_cli
            status_output, ok = run_command(['wpa_cli', '-i', 'wlan0', 'status'], timeout=5)
            if ok and status_output:
                for line in status_output.strip().split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key == 'wpa_state':
                            result['state'] = value
                            result['connected'] = (value == 'COMPLETED')
                        elif key == 'ssid':
                            result['ssid'] = value
                        elif key == 'bssid':
                            result['bssid'] = value
                        elif key == 'freq':
                            result['freq'] = value
                        elif key == 'ip_address':
                            result['ip'] = value

        # Get IP if not already set
        if not result['ip']:
            result['ip'] = _get_interface_ip('wlan0')

        # Update connected status based on IP
        if result['ip'] and not result['ip'].startswith('169.254.'):
            result['connected'] = True

        return jsonify(result)
    except Exception as e:
        return jsonify({'connected': False, 'error': str(e)}), 500


def _nmcli_available():
    """Check if NetworkManager is available and running."""
    output, ok = run_command(['systemctl', 'is-active', 'NetworkManager'], timeout=5)
    return ok and output and output.strip() == 'active'


def _get_interface_mac(interface):
    """Get the MAC address of a network interface."""
    try:
        with open(f'/sys/class/net/{interface}/address', 'r') as f:
            return f.read().strip().upper()
    except (IOError, FileNotFoundError):
        return None


def _ensure_nm_config():
    """
    Ensure NetworkManager is configured to NOT manage OVS/hostapd interfaces.
    This prevents conflicts between NM and Open vSwitch.

    Also configures MAC address preservation to prevent randomization
    from interfering with network connections.
    """
    import os
    from datetime import datetime

    nm_conf_dir = '/etc/NetworkManager/conf.d'
    guardian_conf = f'{nm_conf_dir}/guardian-unmanaged.conf'

    # Check if config already exists and is recent (within last hour)
    if os.path.exists(guardian_conf):
        try:
            mtime = os.path.getmtime(guardian_conf)
            if (datetime.now().timestamp() - mtime) < 3600:
                return True
        except OSError:
            pass

    # Detect MAC addresses for stable configuration
    wlan0_mac = _get_interface_mac('wlan0')
    wlan1_mac = _get_interface_mac('wlan1')
    eth0_mac = _get_interface_mac('eth0')

    # Build unmanaged devices string
    unmanaged = ['interface-name:wlan1', 'interface-name:br*',
                 'interface-name:ovs-*', 'interface-name:vlan*',
                 'interface-name:guardian', 'driver:openvswitch']

    # Add wlan1 MAC to unmanaged for extra safety
    if wlan1_mac:
        unmanaged.append(f'mac:{wlan1_mac}')

    unmanaged_str = ';'.join(unmanaged)

    # Create the configuration with MAC preservation
    config_content = f"""# HookProbe Guardian - NetworkManager Configuration
# Generated: {datetime.now().isoformat()}
# Prevents NM from interfering with OVS/hostapd interfaces
#
# Detected MACs:
#   wlan0: {wlan0_mac or 'not detected'} (managed - WAN WiFi)
#   wlan1: {wlan1_mac or 'not detected'} (unmanaged - AP)
#   eth0:  {eth0_mac or 'not detected'} (managed - Ethernet)

[keyfile]
# Interfaces that NetworkManager should NOT manage
unmanaged-devices={unmanaged_str}

[device]
# ============================================================
# MAC ADDRESS PRESERVATION - Disable all randomization
# ============================================================
wifi.scan-rand-mac-address=no
wifi.cloned-mac-address=preserve
ethernet.cloned-mac-address=preserve
"""

    # Add interface-specific sections with MAC matching
    if wlan0_mac:
        config_content += f"""
[device-wlan0-by-mac]
# wlan0 (WAN WiFi) - preserve MAC: {wlan0_mac}
match-device=mac:{wlan0_mac}
wifi.scan-rand-mac-address=no
wifi.cloned-mac-address=preserve
managed=1

[device-wlan0-by-name]
match-device=interface-name:wlan0
wifi.scan-rand-mac-address=no
wifi.cloned-mac-address=preserve
managed=1
"""

    if eth0_mac:
        config_content += f"""
[device-eth0-by-mac]
# eth0 (Ethernet) - preserve MAC: {eth0_mac}
match-device=mac:{eth0_mac}
ethernet.cloned-mac-address=preserve
"""

    if wlan1_mac:
        config_content += f"""
[device-wlan1-unmanaged]
# wlan1 (AP) - MUST stay unmanaged, MAC: {wlan1_mac}
match-device=mac:{wlan1_mac}
managed=0
"""

    config_content += """
[connection]
# Disable MAC randomization for all connections
wifi.cloned-mac-address=preserve
ethernet.cloned-mac-address=preserve
connection.auth-retries=3

[main]
dhcp=internal
dns=none
"""

    try:
        # Write config
        run_command(['sudo', 'mkdir', '-p', nm_conf_dir], timeout=5)

        tmp_file = '/tmp/guardian-unmanaged.conf'
        with open(tmp_file, 'w') as f:
            f.write(config_content)

        _, ok = run_command(['sudo', 'cp', tmp_file, guardian_conf], timeout=5)
        if ok:
            run_command(['sudo', 'chmod', '644', guardian_conf], timeout=5)
            # Reload NetworkManager to apply
            run_command(['sudo', 'nmcli', 'general', 'reload'], timeout=10)
            return True
    except Exception:
        pass

    return False


def _connect_with_nmcli(ssid, password, interface='wlan0'):
    """
    Connect to WiFi using NetworkManager (nmcli).
    Returns (success, message, ip_address).

    Note: Only wlan0 should be managed by NM. wlan1 (AP) and br0 (OVS)
    must remain unmanaged to avoid conflicts with hostapd and Open vSwitch.
    """
    import time

    # Ensure NM config excludes OVS/hostapd interfaces
    _ensure_nm_config()

    # Ensure wlan1 stays unmanaged (AP interface for hostapd)
    run_command(['sudo', 'nmcli', 'device', 'set', 'wlan1', 'managed', 'no'], timeout=5)

    # Ensure wlan0 (WAN) IS managed by NetworkManager
    run_command(['sudo', 'nmcli', 'device', 'set', interface, 'managed', 'yes'], timeout=5)
    time.sleep(1)

    # Delete any existing connection with same name to avoid conflicts
    run_command(['sudo', 'nmcli', 'connection', 'delete', f'guardian-{ssid}'], timeout=5)

    # Build connection command
    if password:
        # WPA/WPA2 network
        connect_cmd = [
            'sudo', 'nmcli', 'device', 'wifi', 'connect', ssid,
            'password', password,
            'ifname', interface,
            'name', f'guardian-{ssid}'
        ]
    else:
        # Open network
        connect_cmd = [
            'sudo', 'nmcli', 'device', 'wifi', 'connect', ssid,
            'ifname', interface,
            'name', f'guardian-{ssid}'
        ]

    # Attempt connection (nmcli handles auth + DHCP automatically)
    output, ok = run_command(connect_cmd, timeout=30)

    if not ok:
        # Parse common error messages
        if output:
            if 'Secrets were required' in output or 'password' in output.lower():
                return False, 'Invalid password', None
            elif 'No network with SSID' in output:
                return False, f'Network "{ssid}" not found', None
            elif 'Connection activation failed' in output:
                return False, 'Connection failed - check password or signal', None
        return False, f'Connection failed: {output}', None

    # Wait for IP address
    time.sleep(2)
    for _ in range(5):
        ip = _get_interface_ip(interface)
        if ip and not ip.startswith('169.254.'):
            return True, f'Connected to {ssid}', ip
        time.sleep(1)

    # Check connection state
    status_out, _ = run_command(['nmcli', '-t', '-f', 'GENERAL.STATE', 'device', 'show', interface], timeout=5)
    if status_out and 'connected' in status_out.lower():
        ip = _get_interface_ip(interface)
        return True, f'Connected to {ssid}', ip

    return True, f'Connected to {ssid}, waiting for IP...', None


def _connect_with_wpa_supplicant(ssid, password, interface='wlan0'):
    """
    Fallback: Connect to WiFi using wpa_supplicant directly.
    Returns (success, message, ip_address).
    """
    import os
    import time

    wpa_conf = f'/etc/wpa_supplicant/wpa_supplicant-{interface}.conf'
    wpa_dir = '/etc/wpa_supplicant'

    # Ensure directory exists
    run_command(['sudo', 'mkdir', '-p', wpa_dir], timeout=5)

    # Get country code
    country = 'US'
    try:
        with open('/etc/hostapd/hostapd.conf', 'r') as f:
            for line in f:
                if line.startswith('country_code='):
                    country = line.split('=')[1].strip()
                    break
    except:
        pass

    # Build wpa_supplicant config
    if not password:
        config = f'''ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country={country}

network={{
    ssid="{ssid}"
    key_mgmt=NONE
    scan_ssid=1
    priority=1
}}
'''
    else:
        escaped_password = password.replace('"', '\\"')
        config = f'''ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country={country}

network={{
    ssid="{ssid}"
    psk="{escaped_password}"
    key_mgmt=WPA-PSK
    scan_ssid=1
    priority=1
}}
'''

    # Write config
    tmp_conf = f'/tmp/wpa_supplicant-{interface}.conf'
    with open(tmp_conf, 'w') as f:
        f.write(config)
    os.chmod(tmp_conf, 0o600)

    _, ok = run_command(['sudo', 'cp', tmp_conf, wpa_conf], timeout=5)
    if not ok:
        return False, 'Failed to write wpa_supplicant config', None
    run_command(['sudo', 'chmod', '600', wpa_conf], timeout=5)

    # Stop existing wpa_supplicant
    run_command(['sudo', 'pkill', '-9', '-f', f'wpa_supplicant.*{interface}'], timeout=5)
    time.sleep(1)

    # Prepare interface
    run_command(['sudo', 'ip', 'link', 'set', interface, 'down'], timeout=5)
    run_command(['sudo', 'rfkill', 'unblock', 'wifi'], timeout=5)
    time.sleep(1)

    # Start wpa_supplicant
    for driver in ['nl80211', 'wext']:
        wpa_cmd = ['sudo', 'wpa_supplicant', '-B', '-i', interface, '-c', wpa_conf,
                   '-D', driver, '-P', f'/var/run/wpa_supplicant_{interface}.pid']
        output, ok = run_command(wpa_cmd, timeout=10)
        if ok:
            break
    else:
        return False, f'Failed to start wpa_supplicant', None

    # Bring interface up
    time.sleep(1)
    run_command(['sudo', 'ip', 'link', 'set', interface, 'up'], timeout=5)
    time.sleep(3)

    # Request DHCP
    for dhcp_cmd in [
        ['sudo', 'dhclient', '-v', '-4', interface],
        ['sudo', 'dhcpcd', '-4', '-w', interface],
        ['sudo', 'udhcpc', '-i', interface, '-n', '-q']
    ]:
        output, ok = run_command(dhcp_cmd, timeout=20)
        if ok:
            break

    time.sleep(2)

    # Check result
    ip = _get_interface_ip(interface)
    status_output, _ = run_command(['wpa_cli', '-i', interface, 'status'], timeout=5)
    state = 'UNKNOWN'
    if status_output:
        for line in status_output.split('\n'):
            if line.startswith('wpa_state='):
                state = line.split('=')[1].strip()
                break

    if ip and not ip.startswith('169.254.'):
        return True, f'Connected to {ssid}', ip
    elif state == 'COMPLETED':
        return True, f'Connected to {ssid}, waiting for IP...', None
    elif state in ['ASSOCIATING', 'ASSOCIATED', 'SCANNING']:
        return True, f'Connecting to {ssid}... (state: {state})', None
    else:
        return False, f'Failed to connect (state: {state}). Check password.', None


@config_bp.route('/wifi/disconnect', methods=['POST'])
def api_wifi_disconnect():
    """Disconnect wlan0 from current network."""
    try:
        import time

        if _nmcli_available():
            # Use NetworkManager - cleaner disconnect
            run_command(['sudo', 'nmcli', 'device', 'disconnect', 'wlan0'], timeout=10)
        else:
            # Fallback to manual disconnect
            run_command(['sudo', 'wpa_cli', '-i', 'wlan0', 'disconnect'], timeout=5)
            run_command(['sudo', 'pkill', '-f', 'wpa_supplicant.*wlan0'], timeout=5)
            run_command(['sudo', 'dhclient', '-r', 'wlan0'], timeout=5)
            run_command(['sudo', 'ip', 'link', 'set', 'wlan0', 'down'], timeout=5)

        time.sleep(1)
        return jsonify({'success': True, 'message': 'Disconnected from WiFi'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/wifi/connect', methods=['POST'])
def api_wifi_connect():
    """
    Connect to a WiFi network using wlan0 (WAN interface).

    Uses NetworkManager (nmcli) as primary method - it's more reliable
    and handles authentication + DHCP atomically. Falls back to
    wpa_supplicant if NetworkManager is not available.
    """
    import os

    data = request.get_json()
    ssid = data.get('ssid', '').strip()
    password = data.get('password', '')

    if not ssid:
        return jsonify({'success': False, 'error': 'SSID required'}), 400

    try:
        # Check if wlan0 exists
        if not os.path.exists('/sys/class/net/wlan0'):
            return jsonify({'success': False, 'error': 'wlan0 interface not found'}), 400

        # Unblock WiFi first
        run_command(['sudo', 'rfkill', 'unblock', 'wifi'], timeout=5)

        # Try NetworkManager first (preferred - handles everything atomically)
        if _nmcli_available():
            success, message, ip = _connect_with_nmcli(ssid, password, 'wlan0')
        else:
            # Fallback to wpa_supplicant
            success, message, ip = _connect_with_wpa_supplicant(ssid, password, 'wlan0')

        if success:
            return jsonify({
                'success': True,
                'message': message,
                'ip': ip,
                'method': 'nmcli' if _nmcli_available() else 'wpa_supplicant'
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 400

    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'trace': traceback.format_exc()}), 500


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
        # wlan1 is the AP interface, wlan0 is WAN
        config = f'''# HookProbe Guardian - Hotspot Configuration
# Generated by Guardian Web UI
interface=wlan1
driver=nl80211
bridge=br0
ssid={ssid}
hw_mode=g
channel={channel if channel != 'auto' else '6'}
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid={'1' if hidden else '0'}
wpa=2
wpa_passphrase={password if password else 'changeme123'}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
country_code=US
ieee80211d=1
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
        run_command(['sudo', 'systemctl', 'restart', 'hostapd'])
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/hotspot/status')
def api_hotspot_status():
    """Get detailed hotspot/SSID status including service state."""
    import os
    import subprocess

    status = {
        'success': True,
        'ssid': 'HookProbe-Guardian',
        'interface': 'wlan1',
        'running': False,
        'broadcasting': False,
        'clients': 0,
        'channel': '--',
        'service_status': 'unknown'
    }

    try:
        # Check hostapd service status
        result = subprocess.run(
            ['systemctl', 'is-active', 'hostapd'],
            capture_output=True, text=True, timeout=5
        )
        service_active = result.returncode == 0
        status['service_status'] = result.stdout.strip() or 'inactive'
        status['running'] = service_active

        # Read SSID from hostapd config
        if os.path.exists('/etc/hostapd/hostapd.conf'):
            with open('/etc/hostapd/hostapd.conf', 'r') as f:
                for line in f:
                    if line.startswith('ssid='):
                        status['ssid'] = line.split('=', 1)[1].strip()
                    elif line.startswith('channel='):
                        status['channel'] = line.split('=', 1)[1].strip()
                    elif line.startswith('interface='):
                        status['interface'] = line.split('=', 1)[1].strip()

        # Check if actually broadcasting (interface up and in AP mode)
        iface = status['interface']
        if os.path.exists(f'/sys/class/net/{iface}/operstate'):
            with open(f'/sys/class/net/{iface}/operstate', 'r') as f:
                operstate = f.read().strip()
            status['broadcasting'] = service_active and operstate == 'up'

        # Get connected client count from hostapd
        if service_active:
            try:
                output, _ = run_command(['sudo', 'hostapd_cli', '-i', iface, 'all_sta'], timeout=5)
                if output:
                    # Count MAC addresses (lines that look like MAC addresses)
                    import re
                    macs = re.findall(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', output)
                    status['clients'] = len(macs)
            except Exception:
                pass

        return jsonify(status)
    except Exception as e:
        status['error'] = str(e)
        return jsonify(status)


@config_bp.route('/hotspot/start', methods=['POST'])
def api_hotspot_start():
    """Start the hotspot (SSID broadcast)."""
    try:
        # First ensure guardian-wlan setup is done
        run_command(['sudo', 'systemctl', 'start', 'guardian-wlan'], timeout=30)

        # Then start hostapd
        output, success = run_command(['sudo', 'systemctl', 'start', 'hostapd'], timeout=30)

        if success:
            # Also start dnsmasq if not running
            run_command(['sudo', 'systemctl', 'start', 'dnsmasq'], timeout=15)
            return jsonify({'success': True, 'message': 'Hotspot started'})
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to start hostapd: {output}'
            }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/hotspot/stop', methods=['POST'])
def api_hotspot_stop():
    """Stop the hotspot (SSID broadcast)."""
    try:
        run_command(['sudo', 'systemctl', 'stop', 'hostapd'], timeout=15)
        return jsonify({'success': True, 'message': 'Hotspot stopped'})
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
            'ovs-system',   # OVS internal system interface
        }

        # Prefixes for virtual interfaces to skip
        VIRTUAL_PREFIXES = (
            'veth',         # Container virtual ethernet
            'cni',          # Container network interface
            'flannel',      # Kubernetes networking
            'cali',         # Calico networking
            'tunl',         # Tunnel interfaces
            'dummy',        # Dummy interfaces
            'vxlan_sys',    # VXLAN system tunnels (e.g., vxlan_sys_4789)
            'ovs-',         # OVS internal interfaces
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
        from shared.wireless import WiFiChannelScanner

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


def _nmcli_available():
    """Check if NetworkManager/nmcli is available and running."""
    import shutil
    # Check if nmcli exists
    if not shutil.which('nmcli'):
        return False
    # Check if NetworkManager is running
    output, success = run_command(['systemctl', 'is-active', 'NetworkManager'], timeout=5)
    return success and output.strip() == 'active'


def _set_eth0_dhcp():
    """Set eth0 to DHCP mode using nmcli (preferred) or dhcpcd fallback."""
    import time

    # Try NetworkManager first (preferred on modern systems)
    if _nmcli_available():
        # Delete any existing static connection for eth0
        run_command(['sudo', 'nmcli', 'connection', 'delete', 'guardian-eth0-static'], timeout=5)

        # Check if there's an existing DHCP connection for eth0
        output, _ = run_command(['nmcli', '-t', '-f', 'NAME,DEVICE', 'connection', 'show', '--active'], timeout=5)
        eth0_connection = None
        if output:
            for line in output.strip().split('\n'):
                if ':eth0' in line:
                    eth0_connection = line.split(':')[0]
                    break

        # If no active connection, create a new DHCP connection
        if not eth0_connection:
            # Create a new DHCP connection for eth0
            cmd = [
                'sudo', 'nmcli', 'connection', 'add',
                'type', 'ethernet',
                'con-name', 'guardian-eth0-dhcp',
                'ifname', 'eth0',
                'ipv4.method', 'auto'
            ]
            output, ok = run_command(cmd, timeout=10)
            if ok:
                # Activate the connection
                run_command(['sudo', 'nmcli', 'connection', 'up', 'guardian-eth0-dhcp'], timeout=15)
        else:
            # Modify existing connection to use DHCP
            run_command(['sudo', 'nmcli', 'connection', 'modify', eth0_connection, 'ipv4.method', 'auto'], timeout=5)
            run_command(['sudo', 'nmcli', 'connection', 'modify', eth0_connection, 'ipv4.addresses', ''], timeout=5)
            run_command(['sudo', 'nmcli', 'connection', 'modify', eth0_connection, 'ipv4.gateway', ''], timeout=5)
            run_command(['sudo', 'nmcli', 'connection', 'modify', eth0_connection, 'ipv4.dns', ''], timeout=5)
            # Reactivate connection
            run_command(['sudo', 'nmcli', 'connection', 'up', eth0_connection], timeout=15)

        time.sleep(2)
        return True

    # Fallback to dhcpcd for systems without NetworkManager
    import os
    dhcpcd_conf = '/etc/dhcpcd.conf'
    if not os.path.exists(dhcpcd_conf):
        # Try dhclient as another fallback
        run_command(['sudo', 'dhclient', '-r', 'eth0'], timeout=5)
        run_command(['sudo', 'dhclient', '-v', 'eth0'], timeout=30)
        return True

    # Read current config and remove static eth0 section
    with open(dhcpcd_conf, 'r') as f:
        lines = f.readlines()

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

    with open('/tmp/dhcpcd.conf.new', 'w') as f:
        f.writelines(new_lines)
    run_command(['sudo', 'cp', '/tmp/dhcpcd.conf.new', dhcpcd_conf], timeout=5)

    # Restart dhcpcd
    run_command(['sudo', 'systemctl', 'restart', 'dhcpcd'], timeout=15)
    return True


def _set_eth0_static(ip, prefix, gateway, dns):
    """Set eth0 to static IP using nmcli (preferred) or dhcpcd fallback."""
    import time

    # Try NetworkManager first (preferred on modern systems)
    if _nmcli_available():
        # Delete any existing guardian eth0 connections
        run_command(['sudo', 'nmcli', 'connection', 'delete', 'guardian-eth0-dhcp'], timeout=5)
        run_command(['sudo', 'nmcli', 'connection', 'delete', 'guardian-eth0-static'], timeout=5)

        # Build the nmcli command for static IP
        cmd = [
            'sudo', 'nmcli', 'connection', 'add',
            'type', 'ethernet',
            'con-name', 'guardian-eth0-static',
            'ifname', 'eth0',
            'ipv4.method', 'manual',
            'ipv4.addresses', f'{ip}/{prefix}'
        ]

        if gateway:
            cmd.extend(['ipv4.gateway', gateway])

        if dns:
            cmd.extend(['ipv4.dns', dns])

        # Add route metric for proper priority
        cmd.extend(['ipv4.route-metric', '100'])

        output, ok = run_command(cmd, timeout=10)
        if not ok:
            return False

        # Activate the connection
        output, ok = run_command(['sudo', 'nmcli', 'connection', 'up', 'guardian-eth0-static'], timeout=15)
        if not ok:
            # Try bringing down any existing connection first
            run_command(['sudo', 'nmcli', 'device', 'disconnect', 'eth0'], timeout=5)
            time.sleep(1)
            output, ok = run_command(['sudo', 'nmcli', 'connection', 'up', 'guardian-eth0-static'], timeout=15)

        time.sleep(2)
        return ok

    # Fallback to dhcpcd for systems without NetworkManager
    import os
    dhcpcd_conf = '/etc/dhcpcd.conf'

    # First remove any existing eth0 static config
    _set_eth0_dhcp()

    # Build static config
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

    run_command(['sudo', 'bash', '-c', f'cat /tmp/eth0_static.conf >> {dhcpcd_conf}'], timeout=5)

    # Apply static IP immediately using ip commands
    run_command(['sudo', 'ip', 'addr', 'flush', 'dev', 'eth0'], timeout=5)
    run_command(['sudo', 'ip', 'addr', 'add', f'{ip}/{prefix}', 'dev', 'eth0'], timeout=5)
    if gateway:
        run_command(['sudo', 'ip', 'route', 'add', 'default', 'via', gateway, 'dev', 'eth0', 'metric', '100'], timeout=5)

    return True


# =============================================================================
# AUTOMATIC CHANNEL OPTIMIZATION
# =============================================================================

@config_bp.route('/channel/status')
def api_channel_status():
    """
    Get automatic WiFi channel optimization status.

    Returns current channel, auto-optimization state, and channel utilization.
    Channel is automatically selected at boot and daily at 4:00 AM.
    """
    import os

    result = {
        'success': True,
        'current_channel': 6,
        'auto_enabled': True,
        'last_optimization': None,
        'next_optimization': '4:00 AM',
        'channel_scores': {}
    }

    # Get current channel from hostapd config
    try:
        if os.path.exists('/etc/hostapd/hostapd.conf'):
            with open('/etc/hostapd/hostapd.conf', 'r') as f:
                for line in f:
                    if line.startswith('channel='):
                        result['current_channel'] = int(line.split('=')[1].strip())
                        break
    except Exception:
        pass

    # Get last optimization time from state file
    state_file = '/var/lib/guardian/channel_state.json'
    if os.path.exists(state_file):
        try:
            import json
            with open(state_file, 'r') as f:
                state = json.load(f)
                result['last_optimization'] = state.get('last_optimization')
        except Exception:
            pass

    # Get channel utilization via survey dump
    ap_interface = 'wlan1' if os.path.exists('/sys/class/net/wlan1') else 'wlan0'
    try:
        output, success = run_command(['sudo', 'iw', 'dev', ap_interface, 'survey', 'dump'])
        if success and output:
            current = {}
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('Survey data from'):
                    if current.get('channel'):
                        result['channel_scores'][current['channel']] = current
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
                result['channel_scores'][current['channel']] = current

        # Calculate utilization percentages
        for ch in [1, 6, 11]:
            if ch in result['channel_scores']:
                data = result['channel_scores'][ch]
                if data.get('active_time') and data.get('busy_time'):
                    data['utilization'] = round((data['busy_time'] / data['active_time']) * 100, 1)
                else:
                    data['utilization'] = 0
            else:
                result['channel_scores'][ch] = {'utilization': 0, 'noise': 0}
    except Exception:
        # Provide default empty scores
        for ch in [1, 6, 11]:
            result['channel_scores'][ch] = {'utilization': 0, 'noise': 0}

    return jsonify(result)


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
