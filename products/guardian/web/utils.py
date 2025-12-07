"""
Guardian Web Application Utilities
Shared helper functions used across modules
"""
import json
import os
import subprocess
from functools import wraps
from flask import current_app, jsonify


def run_command(cmd, timeout=30):
    """Execute a shell command safely and return output."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.returncode == 0
    except subprocess.TimeoutExpired:
        return "Command timed out", False
    except Exception as e:
        return str(e), False


def load_json_file(filepath, default=None):
    """Load JSON file safely."""
    if default is None:
        default = {}
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
        return default
    except (json.JSONDecodeError, IOError):
        return default


def save_json_file(filepath, data):
    """Save data to JSON file safely."""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except (IOError, OSError):
        return False


def load_text_file(filepath, default=None):
    """Load text file as list of lines."""
    if default is None:
        default = []
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return default
    except IOError:
        return default


def save_text_file(filepath, lines):
    """Save list of lines to text file."""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        return True
    except IOError:
        return False


def get_container_status(container_name):
    """Get status of a container."""
    output, success = run_command(f"podman ps -a --format '{{{{.Names}}}}:{{{{.Status}}}}' | grep '^{container_name}:'")
    if success and output:
        parts = output.split(':', 1)
        if len(parts) == 2:
            status = parts[1].lower()
            return {
                'name': container_name,
                'running': 'up' in status,
                'status': parts[1]
            }
    return {'name': container_name, 'running': False, 'status': 'Not found'}


def get_network_stats(interface):
    """Get network interface statistics."""
    stats = {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0}
    try:
        with open(f'/sys/class/net/{interface}/statistics/rx_bytes', 'r') as f:
            stats['rx_bytes'] = int(f.read().strip())
        with open(f'/sys/class/net/{interface}/statistics/tx_bytes', 'r') as f:
            stats['tx_bytes'] = int(f.read().strip())
        with open(f'/sys/class/net/{interface}/statistics/rx_packets', 'r') as f:
            stats['rx_packets'] = int(f.read().strip())
        with open(f'/sys/class/net/{interface}/statistics/tx_packets', 'r') as f:
            stats['tx_packets'] = int(f.read().strip())
    except (IOError, ValueError):
        pass
    return stats


def format_bytes(size):
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def get_system_info():
    """Get system information."""
    info = {
        'hostname': 'guardian',
        'uptime': '0:00',
        'load': [0, 0, 0],
        'memory': {'total': 0, 'used': 0, 'percent': 0},
        'disk': {'total': 0, 'used': 0, 'percent': 0},
        'cpu_percent': 0,
        'temperature': 0
    }

    # Hostname
    hostname, _ = run_command('hostname')
    info['hostname'] = hostname or 'guardian'

    # Uptime
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])
            hours = int(uptime_seconds // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            info['uptime'] = f"{hours}:{minutes:02d}"
    except (IOError, ValueError):
        pass

    # Load average
    try:
        with open('/proc/loadavg', 'r') as f:
            parts = f.read().split()
            info['load'] = [float(parts[0]), float(parts[1]), float(parts[2])]
    except (IOError, ValueError, IndexError):
        pass

    # Memory
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(':')] = int(parts[1]) * 1024
            total = meminfo.get('MemTotal', 0)
            available = meminfo.get('MemAvailable', 0)
            used = total - available
            info['memory'] = {
                'total': total,
                'used': used,
                'percent': int((used / total * 100) if total > 0 else 0)
            }
    except (IOError, ValueError):
        pass

    # CPU temperature (Raspberry Pi)
    try:
        with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
            info['temperature'] = int(f.read().strip()) / 1000
    except (IOError, ValueError):
        pass

    return info


def api_response(success=True, data=None, error=None, status_code=200):
    """Create standardized API response."""
    response = {'success': success}
    if data is not None:
        response['data'] = data
    if error is not None:
        response['error'] = error
    return jsonify(response), status_code
