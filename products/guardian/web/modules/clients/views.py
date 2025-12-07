"""
Clients Module Views - Connected Devices Management
"""
from flask import jsonify
from . import clients_bp
from utils import run_command


@clients_bp.route('/api/list')
def api_clients_list():
    """Get list of connected clients."""
    import re
    try:
        clients = []

        # Get from ARP table - filter to active entries only
        output, success = run_command("ip neigh show | grep -E 'REACHABLE|STALE|DELAY'")
        if success and output:
            for line in output.split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    # Find MAC address (format: xx:xx:xx:xx:xx:xx)
                    mac = None
                    for part in parts:
                        if re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', part):
                            mac = part.lower()
                            break

                    if not mac:
                        continue

                    # Determine status from state
                    status = 'connected'
                    if 'STALE' in line:
                        status = 'idle'
                    elif 'DELAY' in line:
                        status = 'connecting'

                    # Try to get hostname from DHCP leases
                    hostname = 'Unknown'
                    lease_output, _ = run_command(f"grep -i '{mac}' /var/lib/misc/dnsmasq.leases 2>/dev/null")
                    if lease_output:
                        lease_parts = lease_output.split()
                        if len(lease_parts) >= 4:
                            hostname = lease_parts[3] if lease_parts[3] != '*' else 'Unknown'

                    clients.append({
                        'ip': ip,
                        'mac': mac,
                        'hostname': hostname,
                        'status': status
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
