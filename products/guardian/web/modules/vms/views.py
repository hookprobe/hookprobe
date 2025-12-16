"""
VMs Module Views - Virtual Machine Management API
Provides REST API for managing Home Assistant and OpenMediaVault VMs
"""
import os
import subprocess
from flask import jsonify, request, current_app
from . import vms_bp


def _run_virsh(args, timeout=30):
    """Run virsh command safely and return output."""
    try:
        cmd = ['virsh'] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.returncode == 0
    except subprocess.TimeoutExpired:
        return "Command timed out", False
    except Exception as e:
        return str(e), False


def _check_libvirt_available():
    """Check if libvirt is installed and running."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'libvirtd'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip() == 'active'
    except Exception:
        return False


def _get_vm_info(vm_name):
    """Get detailed information about a VM."""
    if not _check_libvirt_available():
        return None

    # Get VM state
    state_output, state_success = _run_virsh(['domstate', vm_name])
    if not state_success:
        return None

    state = state_output.lower()

    # Get VM info (memory, vcpus)
    info = {
        'name': vm_name,
        'state': state,
        'memory_mb': 0,
        'vcpus': 0,
        'autostart': False
    }

    # Get dominfo for detailed stats
    dominfo_output, dominfo_success = _run_virsh(['dominfo', vm_name])
    if dominfo_success:
        for line in dominfo_output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()

                if key == 'max memory':
                    # Parse memory (e.g., "1048576 KiB")
                    try:
                        mem_kb = int(value.split()[0])
                        info['memory_mb'] = mem_kb // 1024
                    except (ValueError, IndexError):
                        pass
                elif key == 'cpu(s)':
                    try:
                        info['vcpus'] = int(value)
                    except ValueError:
                        pass
                elif key == 'autostart':
                    info['autostart'] = value.lower() == 'enable'

    # Get IP address if running
    if state == 'running':
        ip = _get_vm_ip(vm_name)
        info['ip'] = ip

    return info


def _get_vm_ip(vm_name):
    """Get IP address of a running VM."""
    # Use defined DHCP reservations
    ip_map = {
        'homeassistant': '192.168.4.10',
        'openmediavault': '192.168.4.11'
    }
    return ip_map.get(vm_name, '')


def _get_vm_url(vm_name):
    """Get access URL for a VM."""
    url_map = {
        'homeassistant': 'http://192.168.4.10:8123',
        'openmediavault': 'http://192.168.4.11'
    }
    return url_map.get(vm_name, '')


@vms_bp.route('/api/vms/status')
def api_vms_status():
    """Get overall VM support status."""
    libvirt_available = _check_libvirt_available()

    # Check system RAM
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    mem_kb = int(line.split()[1])
                    ram_gb = mem_kb // 1024 // 1024
                    break
            else:
                ram_gb = 0
    except Exception:
        ram_gb = 0

    # Check if VM support is enabled (6GB+ RAM and libvirt installed)
    vm_support_available = ram_gb >= 6 and libvirt_available

    return jsonify({
        'enabled': vm_support_available,
        'libvirt_active': libvirt_available,
        'system_ram_gb': ram_gb,
        'min_ram_required': 6
    })


@vms_bp.route('/api/vms')
def api_vms_list():
    """List all Guardian-managed VMs."""
    if not _check_libvirt_available():
        return jsonify({
            'vms': [],
            'error': 'VM support not available (libvirt not running)'
        }), 503

    # Guardian manages these specific VMs
    managed_vms = ['homeassistant', 'openmediavault']

    vms = []
    for vm_name in managed_vms:
        info = _get_vm_info(vm_name)
        if info:
            info['url'] = _get_vm_url(vm_name)
            info['managed'] = True
            vms.append(info)

    return jsonify({
        'vms': vms,
        'count': len(vms)
    })


@vms_bp.route('/api/vms/<vm_name>')
def api_vm_detail(vm_name):
    """Get detailed information about a specific VM."""
    if not _check_libvirt_available():
        return jsonify({'error': 'VM support not available'}), 503

    info = _get_vm_info(vm_name)
    if not info:
        return jsonify({'error': f'VM {vm_name} not found'}), 404

    info['url'] = _get_vm_url(vm_name)

    return jsonify(info)


@vms_bp.route('/api/vms/<vm_name>/start', methods=['POST'])
def api_vm_start(vm_name):
    """Start a VM."""
    if not _check_libvirt_available():
        return jsonify({'error': 'VM support not available'}), 503

    output, success = _run_virsh(['start', vm_name])
    if success or 'already active' in output.lower():
        return jsonify({
            'success': True,
            'message': f'{vm_name} started',
            'vm': _get_vm_info(vm_name)
        })

    return jsonify({
        'success': False,
        'error': output
    }), 400


@vms_bp.route('/api/vms/<vm_name>/stop', methods=['POST'])
def api_vm_stop(vm_name):
    """Stop (graceful shutdown) a VM."""
    if not _check_libvirt_available():
        return jsonify({'error': 'VM support not available'}), 503

    output, success = _run_virsh(['shutdown', vm_name])
    if success:
        return jsonify({
            'success': True,
            'message': f'{vm_name} shutdown initiated'
        })

    return jsonify({
        'success': False,
        'error': output
    }), 400


@vms_bp.route('/api/vms/<vm_name>/force-stop', methods=['POST'])
def api_vm_force_stop(vm_name):
    """Force stop a VM (like pulling the power cord)."""
    if not _check_libvirt_available():
        return jsonify({'error': 'VM support not available'}), 503

    output, success = _run_virsh(['destroy', vm_name])
    if success:
        return jsonify({
            'success': True,
            'message': f'{vm_name} force stopped'
        })

    return jsonify({
        'success': False,
        'error': output
    }), 400


@vms_bp.route('/api/vms/<vm_name>/restart', methods=['POST'])
def api_vm_restart(vm_name):
    """Restart a VM."""
    if not _check_libvirt_available():
        return jsonify({'error': 'VM support not available'}), 503

    # Try graceful reboot first
    output, success = _run_virsh(['reboot', vm_name])
    if success:
        return jsonify({
            'success': True,
            'message': f'{vm_name} restarting'
        })

    return jsonify({
        'success': False,
        'error': output
    }), 400


@vms_bp.route('/api/vms/<vm_name>/autostart', methods=['POST'])
def api_vm_autostart(vm_name):
    """Enable/disable VM autostart."""
    if not _check_libvirt_available():
        return jsonify({'error': 'VM support not available'}), 503

    data = request.get_json() or {}
    enable = data.get('enable', True)

    if enable:
        output, success = _run_virsh(['autostart', vm_name])
    else:
        output, success = _run_virsh(['autostart', '--disable', vm_name])

    if success:
        return jsonify({
            'success': True,
            'message': f'{vm_name} autostart {"enabled" if enable else "disabled"}'
        })

    return jsonify({
        'success': False,
        'error': output
    }), 400


@vms_bp.route('/api/vms/<vm_name>/console')
def api_vm_console_info(vm_name):
    """Get VNC console connection info for a VM."""
    if not _check_libvirt_available():
        return jsonify({'error': 'VM support not available'}), 503

    # Get VNC display port
    output, success = _run_virsh(['vncdisplay', vm_name])
    if success and output:
        # Output is like ":0" or "127.0.0.1:5900"
        if output.startswith(':'):
            port = 5900 + int(output[1:])
            host = '127.0.0.1'
        else:
            parts = output.rsplit(':', 1)
            host = parts[0] if len(parts) > 1 else '127.0.0.1'
            port = int(parts[-1]) if parts[-1].isdigit() else 5900

        return jsonify({
            'type': 'vnc',
            'host': host,
            'port': port,
            'url': f'vnc://{host}:{port}'
        })

    return jsonify({
        'error': 'Console not available (VM may not be running)'
    }), 404


@vms_bp.route('/api/vms/stats')
def api_vms_stats():
    """Get resource usage stats for all VMs."""
    if not _check_libvirt_available():
        return jsonify({'error': 'VM support not available'}), 503

    managed_vms = ['homeassistant', 'openmediavault']
    stats = []

    for vm_name in managed_vms:
        vm_stats = {
            'name': vm_name,
            'cpu_percent': 0,
            'memory_used_mb': 0,
            'disk_used_gb': 0
        }

        # Get CPU stats if running
        output, success = _run_virsh(['domstate', vm_name])
        if success and output.lower() == 'running':
            # Get memory stats
            mem_output, mem_success = _run_virsh(['dommemstat', vm_name])
            if mem_success:
                for line in mem_output.split('\n'):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == 'actual':
                        try:
                            vm_stats['memory_used_mb'] = int(parts[1]) // 1024
                        except ValueError:
                            pass

        stats.append(vm_stats)

    return jsonify({
        'stats': stats,
        'total_memory_allocated_mb': sum(s['memory_used_mb'] for s in stats)
    })


@vms_bp.route('/api/vms/health')
def api_vms_health():
    """Get health status of VMs (for dashboard integration)."""
    if not _check_libvirt_available():
        return jsonify({
            'healthy': False,
            'reason': 'libvirt not running'
        })

    managed_vms = ['homeassistant', 'openmediavault']
    vm_health = []

    for vm_name in managed_vms:
        info = _get_vm_info(vm_name)
        if info:
            health = {
                'name': vm_name,
                'running': info['state'] == 'running',
                'url': _get_vm_url(vm_name),
                'accessible': False
            }

            # Quick ping check if running
            if health['running']:
                ip = _get_vm_ip(vm_name)
                if ip:
                    try:
                        result = subprocess.run(
                            ['ping', '-c', '1', '-W', '1', ip],
                            capture_output=True,
                            timeout=2
                        )
                        health['accessible'] = result.returncode == 0
                    except Exception:
                        pass

            vm_health.append(health)

    all_running = all(h['running'] for h in vm_health) if vm_health else True

    return jsonify({
        'healthy': all_running,
        'vms': vm_health
    })
