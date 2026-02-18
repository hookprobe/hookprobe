"""
Clients Module Views - Connected Devices Management
"""
import ipaddress
import re
import tempfile

from flask import jsonify
from . import clients_bp
from utils import run_command, _safe_error
from modules.auth import require_auth


def _validate_ip(ip):
    """Validate an IPv4 address using the ipaddress module."""
    try:
        addr = ipaddress.IPv4Address(ip)
        return not addr.is_loopback and not addr.is_multicast
    except (ipaddress.AddressValueError, ValueError):
        return False


@clients_bp.route('/list')
def api_clients_list():
    """Get list of connected clients (read-only, no auth needed)."""
    try:
        clients = []
        connected_macs = set()

        # Method 1: Get connected stations from hostapd_cli
        station_output, success = run_command(['hostapd_cli', '-i', 'wlan0', 'all_sta'])
        if not success:
            station_output, success = run_command(['hostapd_cli', '-i', 'wlan1', 'all_sta'])

        if success and station_output:
            current_mac = None
            current_info = {}
            for line in station_output.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
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
        lease_output = None
        import os
        for path in ['/var/lib/misc/dnsmasq.leases', '/var/lib/dnsmasq/dnsmasq.leases']:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        lease_output = f.read()
                    break
                except (IOError, PermissionError):
                    continue

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

        for mac in connected_macs:
            client = {
                'mac': mac,
                'ip': lease_info.get(mac, {}).get('ip', 'N/A'),
                'hostname': lease_info.get(mac, {}).get('hostname', 'Unknown'),
                'status': 'connected'
            }
            clients.append(client)

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
        return jsonify({'error': _safe_error(e)}), 500


@clients_bp.route('/dhcp')
def api_dhcp_leases():
    """Get DHCP leases (read-only)."""
    import os
    import time

    try:
        leases = []

        lease_paths = [
            '/var/lib/misc/dnsmasq.leases',
            '/var/lib/dnsmasq/dnsmasq.leases',
            '/var/lib/dhcp/dnsmasq.leases',
            '/tmp/dnsmasq.leases',
            '/var/run/dnsmasq/dnsmasq.leases'
        ]

        lease_content = None
        for path in lease_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        lease_content = f.read()
                    if lease_content:
                        break
                except (IOError, PermissionError):
                    continue

        if lease_content:
            for line in lease_content.strip().split('\n'):
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        expires = int(parts[0])
                        mac = parts[1]
                        ip = parts[2]
                        hostname = parts[3] if parts[3] != '*' else 'Unknown'
                        remaining = expires - int(time.time())
                        leases.append({
                            'mac': mac,
                            'ip': ip,
                            'hostname': hostname,
                            'expires_in': max(0, remaining)
                        })
                    except (ValueError, IndexError):
                        continue

        if not leases:
            arp_output, success = run_command(['ip', 'neigh', 'show'])
            if success and arp_output:
                for line in arp_output.strip().split('\n'):
                    if 'REACHABLE' in line or 'STALE' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            ip = parts[0]
                            mac = parts[4] if len(parts) > 4 else 'unknown'
                            if ip.startswith('192.168.') or ip.startswith('10.'):
                                leases.append({
                                    'mac': mac,
                                    'ip': ip,
                                    'hostname': 'Unknown',
                                    'expires_in': 0
                                })

        return jsonify({'leases': leases})
    except Exception as e:
        return jsonify({'error': _safe_error(e)}), 500


@clients_bp.route('/block/<ip>', methods=['POST'])
@require_auth
def api_block_client(ip):
    """Block a client by IP."""
    if not _validate_ip(ip):
        return jsonify({'success': False, 'error': 'Invalid IP address'}), 400

    try:
        run_command(['iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'])
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': _safe_error(e)}), 500


@clients_bp.route('/unblock/<ip>', methods=['POST'])
@require_auth
def api_unblock_client(ip):
    """Unblock a client by IP."""
    if not _validate_ip(ip):
        return jsonify({'success': False, 'error': 'Invalid IP address'}), 400

    try:
        run_command(['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'])
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': _safe_error(e)}), 500


@clients_bp.route('/disconnect/<mac>', methods=['POST'])
@require_auth
def api_disconnect_client(mac):
    """Disconnect a client by MAC address."""
    import os

    if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address'}), 400

    mac = mac.lower()
    results = []

    try:
        # 1. Deauth client from WiFi
        for iface in ['wlan0', 'wlan1']:
            output, success = run_command(['hostapd_cli', '-i', iface, 'deauthenticate', mac])
            if success:
                results.append(f'Deauthenticated from {iface}')
                break

        # 2. Remove DHCP lease (using secure temp file)
        lease_paths = [
            '/var/lib/misc/dnsmasq.leases',
            '/var/lib/dnsmasq/dnsmasq.leases',
            '/tmp/dnsmasq.leases'
        ]

        lease_removed = False
        for lease_file in lease_paths:
            if os.path.exists(lease_file):
                try:
                    with open(lease_file, 'r') as f:
                        lines = f.readlines()

                    new_lines = [l for l in lines if mac not in l.lower()]

                    if len(new_lines) < len(lines):
                        # Use secure temp file to avoid TOCTOU
                        fd, tmp_path = tempfile.mkstemp(
                            suffix='.leases', dir='/var/run'
                        )
                        try:
                            with os.fdopen(fd, 'w') as f:
                                f.writelines(new_lines)
                            os.chmod(tmp_path, 0o600)
                            run_command(['sudo', 'cp', tmp_path, lease_file])
                        finally:
                            try:
                                os.unlink(tmp_path)
                            except OSError:
                                pass
                        lease_removed = True
                        results.append('DHCP lease removed')
                        break
                except (IOError, PermissionError):
                    continue

        if not lease_removed:
            results.append('No DHCP lease found')

        # 3. Clear ARP entry
        run_command(['sudo', 'ip', 'neigh', 'del', mac, 'nud', 'all'])

        return jsonify({
            'success': True,
            'mac': mac,
            'actions': results,
            'message': 'Client disconnected'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': _safe_error(e)}), 500


@clients_bp.route('/kick/<mac>', methods=['POST'])
@require_auth
def api_kick_client(mac):
    """Alias for disconnect."""
    return api_disconnect_client(mac)
