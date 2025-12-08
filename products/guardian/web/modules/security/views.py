"""
Security Module Views - QSecBit, Threats, XDP Stats
"""
from flask import jsonify
from . import security_bp
from utils import run_command, load_json_file


@security_bp.route('/xdp_stats')
def api_xdp_stats():
    """Get XDP/eBPF statistics."""
    import os
    try:
        # Try to get XDP stats from bpftool or custom script
        stats = {
            'mode': 'Not Loaded',
            'interface': 'eth0',
            'drops': 0,
            'packets': 0,
            'bytes': 0,
            'active_rules': 0,
            'drop_rate': 0.0
        }

        # Check if XDP is loaded on eth0
        output, success = run_command(['ip', 'link', 'show', 'eth0'])
        if success and output:
            if 'xdpdrv' in output:
                stats['mode'] = 'XDP-DRV'
            elif 'xdpgeneric' in output:
                stats['mode'] = 'XDP-SKB'
            elif 'xdpoffload' in output:
                stats['mode'] = 'XDP-HW'
            elif 'xdp' in output.lower():
                stats['mode'] = 'XDP-SKB'

        # Get packet stats from /sys/class/net instead of /proc/net/dev
        try:
            stats_dir = '/sys/class/net/eth0/statistics'
            if os.path.exists(stats_dir):
                with open(f'{stats_dir}/rx_packets', 'r') as f:
                    stats['packets'] = int(f.read().strip())
                with open(f'{stats_dir}/rx_bytes', 'r') as f:
                    stats['bytes'] = int(f.read().strip())
                with open(f'{stats_dir}/rx_dropped', 'r') as f:
                    stats['drops'] = int(f.read().strip())

                # Calculate drop rate
                if stats['packets'] > 0:
                    stats['drop_rate'] = round((stats['drops'] / stats['packets']) * 100, 2)
        except (IOError, ValueError):
            pass

        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/qsecbit')
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


@security_bp.route('/block_ip', methods=['POST'])
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


@security_bp.route('/unblock_ip', methods=['POST'])
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
