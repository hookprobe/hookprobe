"""
VPN Module Views - HTP Secure Tunnel Management
Uses HookProbe Transport Protocol with weight-bound encryption + PoSF authentication
"""
import logging
import re
from flask import jsonify, request
from . import vpn_bp
from utils import run_command, load_json_file, save_json_file
from modules.auth import require_auth

logger = logging.getLogger(__name__)

HTP_CONFIG_DIR = '/opt/hookprobe/guardian/htp'
HTP_STATE_FILE = f'{HTP_CONFIG_DIR}/state.json'

# Validation patterns
_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$')
_TOKEN_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,128}$')


def _validate_endpoint(endpoint):
    """Validate mesh endpoint is a safe hostname or IP."""
    if not endpoint or len(endpoint) > 255:
        return False
    return bool(_HOSTNAME_RE.match(endpoint))


def _validate_token(token):
    """Validate token is alphanumeric with limited special chars."""
    if not token:
        return True  # Optional
    return bool(_TOKEN_RE.match(token))


@vpn_bp.route('/status')
@require_auth
def api_status():
    """Get HTP tunnel connection status."""
    try:
        state = load_json_file(HTP_STATE_FILE, {
            'connected': False,
            'server': None,
            'mesh_node': None,
            'public_ip': None,
            'uptime': '0:00',
            'protocol': 'HTP',
            'encryption': 'Kyber-1024 + ChaCha20-Poly1305',
            'posf_verified': False
        })

        # Check if HTP tunnel is running
        htp_output, htp_success = run_command(['pgrep', '-f', 'htp-tunnel'])
        if htp_success and htp_output:
            state['connected'] = True

            # Get mesh connection details
            mesh_state = load_json_file('/opt/hookprobe/guardian/mesh/connection.json', {})
            state['server'] = mesh_state.get('endpoint', 'mesh.hookprobe.com')
            state['mesh_node'] = mesh_state.get('node_id', 'Unknown')
            state['posf_verified'] = mesh_state.get('posf_verified', False)

        # Get public IP if connected (cached)
        if state['connected']:
            ip_output, _ = run_command(
                ['curl', '-s', 'https://api.ipify.org', '--connect-timeout', '5'],
                timeout=10
            )
            if ip_output:
                state['public_ip'] = ip_output.strip()

        return jsonify(state)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@vpn_bp.route('/connect', methods=['POST'])
@require_auth
def api_connect():
    """Connect to mesh via HTP tunnel."""
    data = request.get_json() or {}
    mesh_endpoint = data.get('endpoint', 'mesh.hookprobe.com')
    device_token = data.get('device_token', '')

    # Validate inputs to prevent command injection
    if not _validate_endpoint(mesh_endpoint):
        return jsonify({'success': False, 'error': 'Invalid mesh endpoint'}), 400
    if not _validate_token(device_token):
        return jsonify({'success': False, 'error': 'Invalid device token'}), 400

    try:
        # Build command as list (safe from injection)
        cmd = [
            '/opt/hookprobe/core/htp/transport/htp-tunnel.py',
            'connect', '--mesh', mesh_endpoint
        ]
        if device_token:
            cmd.extend(['--token', device_token])

        output, success = run_command(cmd, timeout=30)

        if success:
            state = {
                'connected': True,
                'server': mesh_endpoint,
                'protocol': 'HTP',
                'encryption': 'Kyber-1024 + ChaCha20-Poly1305',
                'posf_verified': True
            }
            save_json_file(HTP_STATE_FILE, state)
            return jsonify({'success': True, 'protocol': 'HTP', 'mesh': mesh_endpoint})

        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@vpn_bp.route('/disconnect', methods=['POST'])
@require_auth
def api_disconnect():
    """Disconnect HTP tunnel."""
    try:
        run_command(['pkill', '-f', 'htp-tunnel'])

        state = {'connected': False, 'server': None, 'posf_verified': False}
        save_json_file(HTP_STATE_FILE, state)

        return jsonify({'success': True})
    except Exception as e:
        logger.error("HTP disconnect error: %s", type(e).__name__)
        return jsonify({'success': False, 'error': 'An internal error occurred while disconnecting'}), 500


@vpn_bp.route('/mesh/register', methods=['POST'])
@require_auth
def api_mesh_register():
    """Register this Guardian node with mesh."""
    data = request.get_json() or {}
    mesh_endpoint = data.get('endpoint', 'mesh.hookprobe.com')
    registration_code = data.get('registration_code', '')

    if not registration_code:
        return jsonify({'success': False, 'error': 'Registration code required'}), 400

    # Validate inputs
    if not _validate_endpoint(mesh_endpoint):
        return jsonify({'success': False, 'error': 'Invalid mesh endpoint'}), 400
    if not _validate_token(registration_code):
        return jsonify({'success': False, 'error': 'Invalid registration code format'}), 400

    try:
        # Build command as list (safe from injection)
        cmd = [
            '/opt/hookprobe/core/htp/transport/htp-client.py',
            'register', '--mesh', mesh_endpoint,
            '--code', registration_code
        ]
        output, success = run_command(cmd, timeout=60)

        if success:
            return jsonify({
                'success': True,
                'message': 'Successfully registered with mesh',
                'device_id': output.strip() if output else 'unknown'
            })
        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@vpn_bp.route('/posf/status')
@require_auth
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


@vpn_bp.route('/posf/verify', methods=['POST'])
@require_auth
def api_posf_verify():
    """Trigger PoSF verification."""
    try:
        output, success = run_command(
            ['/opt/hookprobe/core/neuro/validation/posf-verify.py', '--attest']
        )
        if success:
            return jsonify({'success': True, 'message': 'PoSF verification complete'})
        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@vpn_bp.route('/encryption/info')
def api_encryption_info():
    """Get encryption information (public, no auth needed)."""
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
