"""
Fortress Settings Views - System configuration and user management.
Provides system-wide settings including WiFi, network, and security options.
"""

import json
import subprocess
from pathlib import Path

from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user

from . import settings_bp
from ..auth.decorators import admin_required


def get_system_config():
    """Load system configuration."""
    config_file = Path('/opt/hookprobe/fortress/config/fortress.json')
    defaults = {
        'wifi_ssid': 'HookProbe-Fortress',
        'wifi_channel': 'auto',
        'wifi_band': '2.4GHz',
        'network_size': '/24',
        'gateway_ip': '10.250.0.1',
        'dns_upstream': ['1.1.1.1', '8.8.8.8'],
        'lte_enabled': False,
        'lte_apn': 'internet',
        'auto_update': True,
        'timezone': 'UTC'
    }

    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                defaults.update(config)
        except Exception:
            pass

    return defaults


def save_system_config(config):
    """Save system configuration."""
    config_dir = Path('/opt/hookprobe/fortress/config')
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / 'fortress.json'

    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)


def get_system_info():
    """Get system information for display."""
    info = {
        'hostname': 'fortress',
        'version': '1.0.0',
        'uptime': 'Unknown',
        'cpu_usage': 0,
        'memory_usage': 0,
        'disk_usage': 0,
        'temperature': None
    }

    # Hostname
    try:
        result = subprocess.run(['hostname'], capture_output=True, text=True, timeout=5)
        info['hostname'] = result.stdout.strip()
    except Exception:
        pass

    # Uptime
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            info['uptime'] = f'{days}d {hours}h' if days else f'{hours}h'
    except Exception:
        pass

    # CPU usage
    try:
        result = subprocess.run(
            ['grep', 'cpu ', '/proc/stat'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            values = result.stdout.split()[1:5]
            values = [int(v) for v in values]
            idle = values[3]
            total = sum(values)
            info['cpu_usage'] = int(100 * (1 - idle / total)) if total > 0 else 0
    except Exception:
        pass

    # Memory
    try:
        with open('/proc/meminfo', 'r') as f:
            lines = f.readlines()
            mem_total = mem_available = 0
            for line in lines:
                if line.startswith('MemTotal:'):
                    mem_total = int(line.split()[1])
                elif line.startswith('MemAvailable:'):
                    mem_available = int(line.split()[1])
            if mem_total > 0:
                info['memory_usage'] = int(100 * (1 - mem_available / mem_total))
    except Exception:
        pass

    # Disk
    try:
        result = subprocess.run(['df', '/'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 5:
                    info['disk_usage'] = int(parts[4].rstrip('%'))
    except Exception:
        pass

    # Temperature (Raspberry Pi / thermal zone)
    try:
        temp_file = Path('/sys/class/thermal/thermal_zone0/temp')
        if temp_file.exists():
            with open(temp_file, 'r') as f:
                info['temperature'] = int(f.read()) // 1000
    except Exception:
        pass

    return info


@settings_bp.route('/')
@login_required
@admin_required
def index():
    """Main settings page."""
    config = get_system_config()
    system_info = get_system_info()

    return render_template('settings/index.html',
                           config=config,
                           system_info=system_info)


@settings_bp.route('/users')
@login_required
@admin_required
def users():
    """User management page."""
    from ..auth.models import User
    return render_template('settings/users.html', users=User.get_all())


@settings_bp.route('/api/config', methods=['GET'])
@login_required
@admin_required
def api_get_config():
    """Get current configuration."""
    return jsonify({'success': True, 'config': get_system_config()})


@settings_bp.route('/api/config', methods=['POST'])
@login_required
@admin_required
def api_save_config():
    """Save configuration changes."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        config = get_system_config()
        config.update(data)
        save_system_config(config)

        return jsonify({'success': True, 'message': 'Configuration saved'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/api/system', methods=['GET'])
@login_required
def api_system_info():
    """Get system information."""
    return jsonify({'success': True, 'system': get_system_info()})


@settings_bp.route('/api/restart', methods=['POST'])
@login_required
@admin_required
def api_restart_service():
    """Restart a system service."""
    service = request.json.get('service')
    allowed_services = ['dnsmasq', 'hostapd', 'fts-web', 'fts-agent']

    if service not in allowed_services:
        return jsonify({'success': False, 'error': 'Invalid service'}), 400

    try:
        subprocess.run(['systemctl', 'restart', service], check=True, timeout=30)
        return jsonify({'success': True, 'message': f'{service} restarted'})
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'error': f'Failed to restart {service}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/api/logs/<service>')
@login_required
@admin_required
def api_get_logs(service):
    """Get recent logs for a service."""
    allowed_services = ['dnsmasq', 'hostapd', 'fts-web', 'fts-agent']

    if service not in allowed_services:
        return jsonify({'success': False, 'error': 'Invalid service'}), 400

    try:
        result = subprocess.run(
            ['journalctl', '-u', service, '-n', '100', '--no-pager'],
            capture_output=True, text=True, timeout=10
        )
        return jsonify({
            'success': True,
            'logs': result.stdout.split('\n')[-100:]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
