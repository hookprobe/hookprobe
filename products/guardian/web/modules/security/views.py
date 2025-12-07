"""
Security Module Views - QSecBit, Threats, XDP Stats
"""
from flask import jsonify
from . import security_bp
from ...utils import run_command, load_json_file


@security_bp.route('/api/xdp_stats')
def api_xdp_stats():
    """Get XDP/eBPF statistics."""
    try:
        # Try to get XDP stats from bpftool or custom script
        stats = {
            'mode': 'XDP-DRV',
            'interface': 'eth0',
            'drops': 0,
            'packets': 0,
            'bytes': 0,
            'active_rules': 0,
            'drop_rate': 0.0
        }

        # Check if XDP is loaded
        output, success = run_command("ip link show eth0 | grep xdp")
        if success and 'xdp' in output:
            if 'xdpdrv' in output:
                stats['mode'] = 'XDP-DRV'
            elif 'xdpgeneric' in output:
                stats['mode'] = 'XDP-SKB'
            elif 'xdpoffload' in output:
                stats['mode'] = 'XDP-HW'

        # Get packet stats from /proc/net/dev
        output, success = run_command("cat /proc/net/dev | grep eth0")
        if success and output:
            parts = output.split()
            if len(parts) >= 10:
                stats['packets'] = int(parts[2])
                stats['bytes'] = int(parts[1])

        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/api/qsecbit')
def api_qsecbit():
    """Get current QSecBit score and components."""
    try:
        qsecbit_file = '/var/log/hookprobe/qsecbit/current.json'
        data = load_json_file(qsecbit_file, {
            'score': 0.0,
            'status': 'GREEN',
            'components': {
                'drift': 0.0,
                'p_attack': 0.0,
                'decay': 0.0,
                'q_drift': 0.0,
                'energy_anomaly': 0.0
            },
            'weights': {
                'alpha': 0.25,
                'beta': 0.25,
                'gamma': 0.20,
                'delta': 0.15,
                'epsilon': 0.15
            }
        })
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/api/block_ip', methods=['POST'])
def api_block_ip():
    """Block an IP address via XDP."""
    from flask import request
    import re

    data = request.get_json() if request.is_json else {}
    ip = data.get('ip') or request.form.get('ip')

    if not ip:
        return jsonify({'error': 'IP address required'}), 400

    # Validate IP format
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address format'}), 400

    try:
        # Add to XDP blocklist
        output, success = run_command(f'/opt/hookprobe/shared/response/xdp-block.sh add {ip}')
        if success:
            return jsonify({'success': True, 'message': f'Blocked {ip}'})
        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@security_bp.route('/api/unblock_ip', methods=['POST'])
def api_unblock_ip():
    """Unblock an IP address."""
    from flask import request
    import re

    data = request.get_json() if request.is_json else {}
    ip = data.get('ip') or request.form.get('ip')

    if not ip:
        return jsonify({'error': 'IP address required'}), 400

    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address format'}), 400

    try:
        output, success = run_command(f'/opt/hookprobe/shared/response/xdp-block.sh remove {ip}')
        if success:
            return jsonify({'success': True, 'message': f'Unblocked {ip}'})
        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
