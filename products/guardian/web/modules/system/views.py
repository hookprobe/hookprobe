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

        # Ensure load is a list of floats (fallback if not populated)
        if not info.get('load') or info['load'] == [0, 0, 0]:
            try:
                with open('/proc/loadavg', 'r') as f:
                    parts = f.read().split()
                    info['load'] = [float(parts[0]), float(parts[1]), float(parts[2])]
            except (IOError, ValueError, IndexError):
                info['load'] = [0.0, 0.0, 0.0]

        # Ensure memory has data (fallback if not populated)
        if not info.get('memory') or info['memory'].get('percent', 0) == 0:
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            meminfo[parts[0].rstrip(':')] = int(parts[1]) * 1024
                    total = meminfo.get('MemTotal', 0)
                    available = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
                    used = total - available
                    info['memory'] = {
                        'total': total,
                        'used': used,
                        'percent': int((used / total * 100) if total > 0 else 0)
                    }
            except (IOError, ValueError):
                pass

        # Disk usage is already in get_system_info with raw bytes
        # Just ensure percent is set
        if info.get('disk') and info['disk'].get('percent') is None:
            total = info['disk'].get('total', 0)
            used = info['disk'].get('used', 0)
            if total > 0:
                info['disk']['percent'] = int((used / total * 100))

        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/services')
def api_services():
    """Get service status."""
    services = ['dnsmasq', 'hostapd', 'napse', 'guardian-qsecbit', 'guardian-webui', 'nginx']
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
    allowed = ['dnsmasq', 'hostapd', 'napse', 'guardian-qsecbit', 'guardian-webui', 'nginx', 'dnsxai']
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
        services = ['dnsmasq', 'hostapd', 'napse', 'guardian-qsecbit']
        for service in services:
            run_command(f'sudo systemctl restart {service} 2>/dev/null || true')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@system_bp.route('/updates')
def api_updates():
    """Check for system updates (apt packages)."""
    try:
        # Run apt update first (use sudo, allow failure)
        run_command(['sudo', 'apt', 'update', '-qq'], timeout=60)

        # Get list of upgradable packages
        output, success = run_command(['apt', 'list', '--upgradable'], timeout=30)

        if success and output:
            # Count lines, excluding the header "Listing..."
            lines = [l for l in output.strip().split('\n') if l and not l.startswith('Listing')]
            count = len(lines)
        else:
            count = 0

        return jsonify({
            'available': count > 0,
            'count': count
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
