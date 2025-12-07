"""
Clients Module Views - Connected Devices Management
"""
from flask import jsonify
from . import clients_bp
from utils import run_command


@clients_bp.route('/api/list')
def api_clients_list():
    """Get list of connected clients."""
    try:
        clients = []
        connected_macs = set()

        # Method 1: Get connected stations from hostapd_cli
        station_output, success = run_command('hostapd_cli -i wlan0 all_sta 2>/dev/null')
        if not success:
            # Try wlan1 as fallback
            station_output, success = run_command('hostapd_cli -i wlan1 all_sta 2>/dev/null')

        if success and station_output:
            current_mac = None
            current_info = {}
            for line in station_output.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                # MAC address line (17 chars with 5 colons)
                if len(line) == 17 and line.count(':') == 5:
                    if current_mac:
                        connected_macs.add(current_mac)
                    current_mac = line.lower()
                    current_info = {'mac': current_mac, 'connected_time': 'Connected'}
                elif '=' in line and current_mac:
                    key, value = line.split('=', 1)
                    if key == 'connected_time':
                        try:
                            secs = int(value)
                            if secs < 60:
                                current_info['connected_time'] = f'{secs}s'
                            elif secs < 3600:
                                current_info['connected_time'] = f'{secs // 60}m {secs % 60}s'
                            else:
                                current_info['connected_time'] = f'{secs // 3600}h {(secs % 3600) // 60}m'
                        except ValueError:
                            pass
            if current_mac:
                connected_macs.add(current_mac)

        # Method 2: Get DHCP leases for IP and hostname info
        lease_output, _ = run_command('cat /var/lib/misc/dnsmasq.leases 2>/dev/null')
        lease_info = {}

        if lease_output:
            for line in lease_output.strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 4:
                        mac = parts[1].lower()
                        lease_info[mac] = {
                            'ip': parts[2],
                            'hostname': parts[3] if parts[3] != '*' else 'Unknown',
                        }

        # Combine information - prioritize connected stations from hostapd
        for mac in connected_macs:
            client = {
                'mac': mac,
                'ip': lease_info.get(mac, {}).get('ip', 'N/A'),
                'hostname': lease_info.get(mac, {}).get('hostname', 'Unknown'),
                'status': 'connected'
            }
            clients.append(client)

        # If hostapd_cli didn't return stations, fall back to DHCP leases
        if not clients and lease_info:
            for mac, info in lease_info.items():
                clients.append({
                    'mac': mac,
                    'ip': info.get('ip', 'N/A'),
                    'hostname': info.get('hostname', 'Unknown'),
                    'status': 'dhcp_lease'
                })

        return jsonify(clients)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@clients_bp.route('/api/dhcp')
def api_dhcp_leases():
    """Get DHCP leases."""
    try:
        leases = []
        output, success = run_command("cat /var/lib/misc/dnsmasq.leases 2>/dev/null")

        if success and output:
            for line in output.split('\n'):
                parts = line.split()
                if len(parts) >= 4:
                    expires = int(parts[0])
                    mac = parts[1]
                    ip = parts[2]
                    hostname = parts[3] if parts[3] != '*' else 'Unknown'

                    import time
                    remaining = expires - int(time.time())

                    leases.append({
                        'mac': mac,
                        'ip': ip,
                        'hostname': hostname,
                        'expires_in': max(0, remaining)
                    })

        return jsonify({'leases': leases})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@clients_bp.route('/api/block/<ip>', methods=['POST'])
def api_block_client(ip):
    """Block a client by IP."""
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return jsonify({'success': False, 'error': 'Invalid IP'}), 400

    try:
        run_command(f'iptables -A FORWARD -s {ip} -j DROP')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@clients_bp.route('/api/unblock/<ip>', methods=['POST'])
def api_unblock_client(ip):
    """Unblock a client by IP."""
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return jsonify({'success': False, 'error': 'Invalid IP'}), 400

    try:
        run_command(f'iptables -D FORWARD -s {ip} -j DROP')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
