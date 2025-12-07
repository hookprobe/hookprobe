"""
VPN Module Views - HTP Secure Tunnel Management
Uses HookProbe Transport Protocol with weight-bound encryption + PoSF authentication
"""
import os
from flask import jsonify, request
from . import vpn_bp
from ...utils import run_command, load_json_file, save_json_file


HTP_CONFIG_DIR = '/opt/hookprobe/guardian/htp'
HTP_STATE_FILE = f'{HTP_CONFIG_DIR}/state.json'


@vpn_bp.route('/api/status')
def api_status():
    """Get HTP tunnel connection status."""
    try:
        state = load_json_file(HTP_STATE_FILE, {
            'connected': False,
            'server': None,
            'mssp_node': None,
            'public_ip': None,
            'uptime': '0:00',
            'protocol': 'HTP',
            'encryption': 'Kyber-1024 + ChaCha20-Poly1305',
            'posf_verified': False
        })

        # Check if HTP tunnel is running
        htp_output, htp_success = run_command('pgrep -f htp-tunnel 2>/dev/null')
        if htp_success and htp_output:
            state['connected'] = True

            # Get MSSP connection details
            mssp_state = load_json_file('/opt/hookprobe/guardian/mssp/connection.json', {})
            state['server'] = mssp_state.get('endpoint', 'mssp.hookprobe.com')
            state['mssp_node'] = mssp_state.get('node_id', 'Unknown')
            state['posf_verified'] = mssp_state.get('posf_verified', False)

        # Get public IP if connected
        if state['connected']:
            ip_output, _ = run_command('curl -s https://api.ipify.org --connect-timeout 5')
            if ip_output:
                state['public_ip'] = ip_output.strip()

        return jsonify(state)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@vpn_bp.route('/api/connect', methods=['POST'])
def api_connect():
    """Connect to MSSP via HTP tunnel."""
    data = request.get_json() or {}
    mssp_endpoint = data.get('endpoint', 'mssp.hookprobe.com')
    device_token = data.get('device_token', '')

    try:
        # Start HTP tunnel with MSSP
        cmd = f'/opt/hookprobe/core/htp/transport/htp-tunnel.py connect --mssp {mssp_endpoint}'
        if device_token:
            cmd += f' --token {device_token}'

        output, success = run_command(cmd, timeout=30)

        if success:
            # Update state
            state = {
                'connected': True,
                'server': mssp_endpoint,
                'protocol': 'HTP',
                'encryption': 'Kyber-1024 + ChaCha20-Poly1305',
                'posf_verified': True
            }
            save_json_file(HTP_STATE_FILE, state)
            return jsonify({'success': True, 'protocol': 'HTP', 'mssp': mssp_endpoint})

        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@vpn_bp.route('/api/disconnect', methods=['POST'])
def api_disconnect():
    """Disconnect HTP tunnel."""
    try:
        run_command('pkill -f htp-tunnel 2>/dev/null || true')

        # Update state
        state = {'connected': False, 'server': None, 'posf_verified': False}
        save_json_file(HTP_STATE_FILE, state)

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@vpn_bp.route('/api/mssp/register', methods=['POST'])
def api_mssp_register():
    """Register this Guardian node with MSSP."""
    data = request.get_json()
    mssp_endpoint = data.get('endpoint', 'mssp.hookprobe.com')
    registration_code = data.get('registration_code', '')

    if not registration_code:
        return jsonify({'success': False, 'error': 'Registration code required'}), 400

    try:
        # Register with MSSP using HTP
        cmd = f'/opt/hookprobe/core/htp/transport/htp-client.py register --mssp {mssp_endpoint} --code {registration_code}'
        output, success = run_command(cmd, timeout=60)

        if success:
            return jsonify({
                'success': True,
                'message': 'Successfully registered with MSSP',
                'device_id': output.strip() if output else 'unknown'
            })
        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@vpn_bp.route('/api/posf/status')
def api_posf_status():
    """Get Proof of Secure Function (PoSF) status."""
    try:
        posf_file = '/opt/hookprobe/guardian/posf/current.json'
        posf = load_json_file(posf_file, {
            'verified': False,
            'last_attestation': None,
            'tpm_bound': False,
            'chain_height': 0,
            'validator_count': 0
        })

        return jsonify(posf)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@vpn_bp.route('/api/posf/verify', methods=['POST'])
def api_posf_verify():
    """Trigger PoSF verification."""
    try:
        output, success = run_command('/opt/hookprobe/core/neuro/validation/posf-verify.py --attest')
        if success:
            return jsonify({'success': True, 'message': 'PoSF verification complete'})
        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@vpn_bp.route('/api/encryption/info')
def api_encryption_info():
    """Get encryption information."""
    return jsonify({
        'protocol': 'HTP (HookProbe Transport Protocol)',
        'key_exchange': 'Kyber-1024 (Post-Quantum)',
        'symmetric': 'ChaCha20-Poly1305',
        'authentication': 'PoSF (Proof of Secure Function)',
        'features': [
            'Weight-bound encryption',
            'Neural resonance protocol',
            'Quantum-resistant key exchange',
            'TPM-bound attestation',
            'Federated mesh intelligence'
        ]
    })
