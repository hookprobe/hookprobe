"""
System Module Views - System Settings and Management
"""
from flask import jsonify, request
from . import system_bp
from utils import run_command, get_system_info, format_bytes


@system_bp.route('/info')
def api_info():
    """Get system information."""
    try:
        info = get_system_info()

        # Get disk usage
        output, success = run_command("df -B1 / | tail -1 | awk '{print $2, $3, $5}'")
        if success and output:
            parts = output.split()
            if len(parts) >= 3:
                total = int(parts[0])
                used = int(parts[1])
                percent = int(parts[2].rstrip('%'))
                info['disk'] = {
                    'total': format_bytes(total),
                    'used': format_bytes(used),
                    'percent': percent
                }

        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/services')
def api_services():
    """Get service status."""
    services = ['dnsmasq', 'hostapd', 'suricata', 'guardian-agent', 'nginx']
    result = []

    for service in services:
        output, success = run_command(f'systemctl is-active {service} 2>/dev/null')
        status = output.strip() if success else 'unknown'
        result.append({
            'name': service,
            'status': status,
            'running': status == 'active'
        })

    return jsonify({'services': result})


@system_bp.route('/service/<name>/restart', methods=['POST'])
def api_restart_service(name):
    """Restart a service."""
    allowed = ['dnsmasq', 'hostapd', 'suricata', 'guardian-agent', 'nginx', 'dnsxai']
    if name not in allowed:
        return jsonify({'success': False, 'error': 'Service not allowed'}), 403

    try:
        output, success = run_command(f'sudo systemctl restart {name}')
        if success:
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@system_bp.route('/restart-services', methods=['POST'])
def api_restart_all():
    """Restart all Guardian services."""
    try:
        services = ['dnsmasq', 'hostapd', 'suricata', 'guardian-agent']
        for service in services:
            run_command(f'sudo systemctl restart {service} 2>/dev/null || true')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@system_bp.route('/updates')
def api_updates():
    """Check for system updates."""
    try:
        output, success = run_command('apt update 2>/dev/null && apt list --upgradable 2>/dev/null | wc -l')
        count = int(output.strip()) - 1 if success and output.isdigit() else 0
        return jsonify({
            'available': count > 0,
            'count': max(0, count)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/logs')
def api_logs():
    """Get recent system logs."""
    try:
        # Use journalctl without pipes (safer without shell=True)
        output, success = run_command(['journalctl', '-n', '50', '--no-pager', '-q'])
        if success and output:
            return jsonify({'logs': output})

        # Fallback: read from syslog
        import os
        for log_file in ['/var/log/syslog', '/var/log/messages']:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        lines = f.readlines()[-50:]
                        return jsonify({'logs': ''.join(lines)})
                except (IOError, PermissionError):
                    continue

        return jsonify({'logs': 'No logs available'})
    except Exception as e:
        return jsonify({'logs': str(e)})


@system_bp.route('/reboot', methods=['POST'])
def api_reboot():
    """Reboot the system."""
    try:
        run_command('sudo shutdown -r +1 "Guardian rebooting..."')
        return jsonify({'success': True, 'message': 'Rebooting in 1 minute'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@system_bp.route('/shutdown', methods=['POST'])
def api_shutdown():
    """Shutdown the system."""
    try:
        run_command('sudo shutdown -h +1 "Guardian shutting down..."')
        return jsonify({'success': True, 'message': 'Shutting down in 1 minute'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
