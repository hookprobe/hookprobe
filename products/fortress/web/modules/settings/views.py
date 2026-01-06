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
        'wifi_password': '',  # WiFi password (WPA2)
        'wifi_channel': 'auto',
        'wifi_band': 'dual',  # dual, 2.4GHz, 5GHz
        'network_size': '/24',
        'gateway_ip': '10.200.0.1',  # Fixed: was 10.250.0.1, must match OVS setup
        'dns_upstream': ['1.1.1.1', '8.8.8.8'],
        'lte_enabled': False,
        'lte_apn': 'internet',
        'auto_update': True,
        'timezone': 'UTC',
        'regulatory_domain': 'US',  # WiFi regulatory domain (US, GB, DE, etc.)
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
    allowed_services = [
        'dnsmasq',
        'hostapd',
        'fts-web',
        'fts-agent',
        'fts-hostapd-24ghz',
        'fts-hostapd-5ghz',
        'fortress',
        'fortress-agent',
    ]

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


# =============================================================================
# APPLY CONFIGURATION FUNCTIONS
# These functions actually apply settings to the system
# =============================================================================

import logging
logger = logging.getLogger(__name__)

# Paths to configuration scripts
HOSTAPD_GENERATOR = Path('/opt/hookprobe/fortress/devices/common/hostapd-generator.sh')
HOSTAPD_24GHZ_CONF = Path('/etc/hostapd/hostapd-24ghz.conf')
HOSTAPD_5GHZ_CONF = Path('/etc/hostapd/hostapd-5ghz.conf')
FORTRESS_CONF = Path('/etc/hookprobe/fortress.conf')


def apply_timezone(timezone: str) -> dict:
    """Apply timezone setting using timedatectl."""
    try:
        # Validate timezone exists
        result = subprocess.run(
            ['timedatectl', 'list-timezones'],
            capture_output=True, text=True, timeout=10
        )
        valid_timezones = result.stdout.strip().split('\n')

        if timezone not in valid_timezones:
            return {'success': False, 'error': f'Invalid timezone: {timezone}'}

        # Set timezone
        result = subprocess.run(
            ['timedatectl', 'set-timezone', timezone],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode == 0:
            logger.info(f"Timezone set to {timezone}")
            return {'success': True, 'message': f'Timezone set to {timezone}'}
        else:
            return {'success': False, 'error': result.stderr or 'Failed to set timezone'}

    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Timeout setting timezone'}
    except Exception as e:
        logger.error(f"Failed to set timezone: {e}")
        return {'success': False, 'error': str(e)}


def apply_wifi_settings(ssid: str, password: str, channel: str = 'auto', band: str = 'dual') -> dict:
    """Apply WiFi settings by regenerating hostapd configuration.

    This updates the hostapd configuration files and restarts the services.
    """
    results = []
    errors = []

    # Validate inputs
    if not ssid or len(ssid) < 1 or len(ssid) > 32:
        return {'success': False, 'error': 'SSID must be 1-32 characters'}

    if password and (len(password) < 8 or len(password) > 63):
        return {'success': False, 'error': 'Password must be 8-63 characters'}

    try:
        # Method 1: Use hostapd-generator.sh if available
        if HOSTAPD_GENERATOR.exists():
            env = {
                'WIFI_SSID': ssid,
                'WIFI_PASSWORD': password or '',
                'WIFI_CHANNEL': channel if channel != 'auto' else '',
                'WIFI_BAND': band,
                'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
            }

            result = subprocess.run(
                [str(HOSTAPD_GENERATOR)],
                env=env,
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                results.append('hostapd configuration regenerated')
            else:
                errors.append(f'hostapd-generator failed: {result.stderr}')

        # Method 2: Direct config file update (fallback)
        else:
            # Update 2.4GHz config
            if HOSTAPD_24GHZ_CONF.exists():
                update_hostapd_ssid(HOSTAPD_24GHZ_CONF, ssid, password)
                results.append('2.4GHz config updated')

            # Update 5GHz config
            if HOSTAPD_5GHZ_CONF.exists():
                update_hostapd_ssid(HOSTAPD_5GHZ_CONF, ssid, password)
                results.append('5GHz config updated')

        # Restart hostapd services
        for service in ['fts-hostapd-24ghz', 'fts-hostapd-5ghz']:
            try:
                subprocess.run(['systemctl', 'restart', service], timeout=15)
                results.append(f'{service} restarted')
            except Exception as e:
                errors.append(f'Failed to restart {service}: {e}')

        if errors and not results:
            return {'success': False, 'error': '; '.join(errors)}

        return {
            'success': True,
            'message': 'WiFi settings applied',
            'details': results,
            'warnings': errors if errors else None
        }

    except Exception as e:
        logger.error(f"Failed to apply WiFi settings: {e}")
        return {'success': False, 'error': str(e)}


def update_hostapd_ssid(config_path: Path, ssid: str, password: str):
    """Update SSID and password in a hostapd config file.

    Note: WPA passphrases must be stored in clear text in hostapd config files
    for the WiFi AP to function. This is unavoidable per WPA2-PSK specification.
    File permissions are set to 600 (root read/write only) to protect credentials.
    See: CWE-312 mitigation via file permission restriction.
    """
    import os

    if not config_path.exists():
        return

    content = config_path.read_text()
    lines = content.split('\n')
    new_lines = []

    for line in lines:
        if line.startswith('ssid='):
            new_lines.append(f'ssid={ssid}')
        elif line.startswith('wpa_passphrase=') and password:
            new_lines.append(f'wpa_passphrase={password}')
        else:
            new_lines.append(line)

    config_path.write_text('\n'.join(new_lines))

    # Security: Set restrictive file permissions (600 = owner read/write only)
    # This mitigates CWE-312 by ensuring only root can read the passphrase
    try:
        os.chmod(config_path, 0o600)
    except OSError as e:
        logger.warning(f"Could not set permissions on {config_path}: {e}")


def apply_regulatory_domain(domain: str) -> dict:
    """Apply WiFi regulatory domain setting."""
    valid_domains = ['US', 'GB', 'DE', 'FR', 'AU', 'JP', 'CA', 'NZ', 'ES', 'IT', 'NL', 'BE', 'AT', 'CH', 'SE', 'NO', 'DK', 'FI', 'IE', 'PT']

    if domain not in valid_domains:
        return {'success': False, 'error': f'Invalid regulatory domain: {domain}'}

    try:
        # Set regulatory domain using iw
        result = subprocess.run(
            ['iw', 'reg', 'set', domain],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode == 0:
            logger.info(f"Regulatory domain set to {domain}")
            return {'success': True, 'message': f'Regulatory domain set to {domain}'}
        else:
            return {'success': False, 'error': result.stderr or 'Failed to set regulatory domain'}

    except Exception as e:
        logger.error(f"Failed to set regulatory domain: {e}")
        return {'success': False, 'error': str(e)}


def get_current_timezone() -> str:
    """Get the current system timezone."""
    try:
        result = subprocess.run(
            ['timedatectl', 'show', '--property=Timezone', '--value'],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() if result.returncode == 0 else 'UTC'
    except Exception:
        return 'UTC'


def get_available_timezones() -> list:
    """Get list of available timezones."""
    try:
        result = subprocess.run(
            ['timedatectl', 'list-timezones'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip().split('\n')
    except Exception:
        pass

    # Fallback to common timezones
    return [
        'UTC',
        'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
        'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Rome',
        'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Singapore', 'Asia/Dubai',
        'Australia/Sydney', 'Australia/Melbourne', 'Pacific/Auckland'
    ]


@settings_bp.route('/api/apply', methods=['POST'])
@login_required
@admin_required
def api_apply_config():
    """Apply configuration changes to the system.

    This endpoint actually applies the saved configuration to the system,
    updating hostapd, timezone, and other system settings.
    """
    try:
        config = get_system_config()
        results = []
        errors = []

        # Apply timezone
        if config.get('timezone'):
            tz_result = apply_timezone(config['timezone'])
            if tz_result['success']:
                results.append(f"Timezone: {tz_result['message']}")
            else:
                errors.append(f"Timezone: {tz_result['error']}")

        # Apply WiFi settings
        wifi_ssid = config.get('wifi_ssid')
        wifi_password = config.get('wifi_password')
        if wifi_ssid:
            wifi_result = apply_wifi_settings(
                wifi_ssid,
                wifi_password,
                config.get('wifi_channel', 'auto'),
                config.get('wifi_band', 'dual')
            )
            if wifi_result['success']:
                results.append(f"WiFi: {wifi_result['message']}")
            else:
                errors.append(f"WiFi: {wifi_result['error']}")

        # Apply regulatory domain
        reg_domain = config.get('regulatory_domain')
        if reg_domain:
            reg_result = apply_regulatory_domain(reg_domain)
            if reg_result['success']:
                results.append(f"Regulatory: {reg_result['message']}")
            else:
                errors.append(f"Regulatory: {reg_result['error']}")

        # Summary
        if errors and not results:
            return jsonify({
                'success': False,
                'error': 'All apply operations failed',
                'details': errors
            }), 500

        return jsonify({
            'success': True,
            'message': 'Configuration applied',
            'applied': results,
            'warnings': errors if errors else None
        })

    except Exception as e:
        logger.error(f"Failed to apply configuration: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/api/timezones')
@login_required
def api_get_timezones():
    """Get list of available timezones."""
    return jsonify({
        'success': True,
        'timezones': get_available_timezones(),
        'current': get_current_timezone()
    })
