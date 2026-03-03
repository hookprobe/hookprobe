"""
VPN Module Views - HTP Secure Tunnel Management
Uses HookProbe Transport Protocol with weight-bound encryption + PoSF authentication
"""
import logging
import re
import sys
import threading
from pathlib import Path
from flask import jsonify, request
from . import vpn_bp
from utils import run_command, load_json_file, save_json_file, _safe_error
from modules.auth import require_auth

logger = logging.getLogger(__name__)

# Import HTP VPN client
sys.path.insert(0, '/opt/hookprobe/guardian/lib')
try:
    from htp_vpn_client import HTPVPNClient, VPNConfig, VPNState
    HTP_VPN_AVAILABLE = True
except ImportError:
    HTP_VPN_AVAILABLE = False
    logger.warning("HTP VPN client not available")

HTP_CONFIG_DIR = '/opt/hookprobe/guardian/htp'
HTP_STATE_FILE = f'{HTP_CONFIG_DIR}/state.json'

# Validation patterns
_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$')
_TOKEN_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,128}$')

# Singleton VPN client instance (managed by web app lifecycle)
_vpn_client = None
_vpn_lock = threading.Lock()


def _get_vpn_client() -> 'HTPVPNClient':
    """Get or create VPN client singleton."""
    global _vpn_client
    if _vpn_client is None and HTP_VPN_AVAILABLE:
        with _vpn_lock:
            if _vpn_client is None:
                _vpn_client = HTPVPNClient()
    return _vpn_client


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
        client = _get_vpn_client()
        if client:
            return jsonify(client.get_status())

        # Fallback: read state file if VPN client not loaded
        state = load_json_file(HTP_STATE_FILE, {
            'connected': False,
            'state': 'stopped',
            'server': None,
            'protocol': 'HTP',
            'encryption': 'ChaCha20-Poly1305 (NSE)',
        })
        return jsonify(state)
    except Exception as e:
        return jsonify({'error': _safe_error(e)}), 500


def _default_gateway_host() -> str:
    """Resolve default VPN gateway: MSSP host from node.conf, else fallback."""
    try:
        conf = Path('/etc/hookprobe/node.conf')
        if conf.exists():
            for line in conf.read_text().splitlines():
                if line.startswith('MSSP_URL='):
                    from urllib.parse import urlparse
                    host = urlparse(line.split('=', 1)[1].strip()).hostname
                    if host:
                        return host
    except Exception:
        pass
    return 'mssp.hookprobe.com'


@vpn_bp.route('/connect', methods=['POST'])
@require_auth
def api_connect():
    """Connect to mesh via HTP tunnel."""
    data = request.get_json() or {}
    mesh_endpoint = data.get('endpoint', _default_gateway_host())
    device_token = data.get('device_token', '')
    kill_switch = data.get('kill_switch', True)

    # Validate inputs
    if not _validate_endpoint(mesh_endpoint):
        return jsonify({'success': False, 'error': 'Invalid mesh endpoint'}), 400
    if not _validate_token(device_token):
        return jsonify({'success': False, 'error': 'Invalid device token'}), 400

    if not HTP_VPN_AVAILABLE:
        return jsonify({'success': False, 'error': 'HTP VPN module not available'}), 503

    try:
        client = _get_vpn_client()
        if not client:
            return jsonify({'success': False, 'error': 'Could not initialize VPN client'}), 500

        # Update config
        client.config.gateway_host = mesh_endpoint
        client.config.device_token = device_token
        client.config.kill_switch = bool(kill_switch)
        client.config.save()

        # Start VPN in background thread (handshake may take a few seconds)
        def _connect_bg():
            if not client.start():
                logger.error("HTP VPN connection failed")

        connect_thread = threading.Thread(target=_connect_bg, daemon=True)
        connect_thread.start()

        return jsonify({
            'success': True,
            'message': 'HTP VPN connecting...',
            'protocol': 'HTP',
            'encryption': 'ChaCha20-Poly1305 (NSE)',
            'kill_switch': kill_switch,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': _safe_error(e)}), 500


@vpn_bp.route('/disconnect', methods=['POST'])
@require_auth
def api_disconnect():
    """Disconnect HTP tunnel."""
    try:
        client = _get_vpn_client()
        if client:
            client.stop()
            return jsonify({'success': True, 'message': 'HTP VPN disconnected'})

        # Fallback: kill any running VPN process
        run_command(['pkill', '-f', 'htp_vpn_client'])
        return jsonify({'success': True})
    except Exception as e:
        logger.error("HTP disconnect error: %s", type(e).__name__)
        return jsonify({'success': False, 'error': 'An internal error occurred while disconnecting'}), 500


@vpn_bp.route('/mesh/register', methods=['POST'])
@require_auth
def api_mesh_register():
    """Register this Guardian node with mesh."""
    data = request.get_json() or {}
    mesh_endpoint = data.get('endpoint', 'mssp.hookprobe.com')
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
        return jsonify({'success': False, 'error': _safe_error(e)}), 500


@vpn_bp.route('/api/mssp/register', methods=['POST'])
@require_auth
def api_mssp_register():
    """Manual MSSP registration with an existing API key."""
    data = request.get_json() or {}
    endpoint = data.get('endpoint', 'mssp.hookprobe.com')
    registration_code = data.get('registration_code', '')

    if not registration_code:
        return jsonify({'success': False, 'error': 'Registration code required'}), 400
    if not _validate_token(registration_code):
        return jsonify({'success': False, 'error': 'Invalid registration code format'}), 400
    if not _validate_endpoint(endpoint):
        return jsonify({'success': False, 'error': 'Invalid endpoint'}), 400

    mssp_url = f'https://{endpoint}'

    try:
        import os
        import tempfile
        from shared.mssp import MSSPClient
        client = MSSPClient(api_key=registration_code, mssp_url=mssp_url)
        resp = client._post('/api/nodes/heartbeat', {'status': 'online', 'version': 'guardian'})
        if resp is None:
            return jsonify({'success': False, 'error': 'Could not connect to MSSP (check key and endpoint)'}), 400

        conf_path = '/etc/hookprobe/node.conf'
        try:
            os.makedirs('/etc/hookprobe', exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(dir='/etc/hookprobe', prefix='.node.conf.tmp')
            try:
                with os.fdopen(fd, 'w') as f:
                    f.write(f'MSSP_URL={mssp_url}\n')
                    f.write(f'API_KEY={registration_code}\n')
                os.chmod(tmp_path, 0o600)
                os.rename(tmp_path, conf_path)
            except Exception:
                os.unlink(tmp_path)
                raise
        except IOError as e:
            logger.warning("Could not write node.conf: %s", e)
            return jsonify({'success': False, 'error': 'Could not save config'}), 500

        return jsonify({'success': True, 'message': f'Connected to MSSP at {endpoint}'})
    except Exception as e:
        logger.error("MSSP registration error: %s", type(e).__name__)
        return jsonify({'success': False, 'error': 'MSSP registration failed'}), 500


@vpn_bp.route('/api/mssp/provision', methods=['POST'])
@require_auth
def api_mssp_provision():
    """Start MSSP provisioning (non-blocking). Returns claim code to display."""
    try:
        from shared.mssp.bootstrap import MSSPBootstrap

        bootstrap = MSSPBootstrap(product_type='guardian')
        result = bootstrap.start_provision()
        return jsonify(result)
    except Exception as e:
        logger.error("MSSP provision error: %s", type(e).__name__)
        return jsonify({'status': 'error', 'error': 'Provisioning request failed'}), 500


@vpn_bp.route('/api/mssp/claim/check', methods=['POST'])
@require_auth
def api_mssp_claim_check():
    """Check if a pending claim code has been entered in the dashboard."""
    try:
        from shared.mssp.bootstrap import MSSPBootstrap

        data = request.get_json() or {}
        provision_id = data.get('provision_id', '')

        bootstrap = MSSPBootstrap(product_type='guardian')

        # Fall back to reading provision_id from claim file on disk
        if not provision_id:
            state = bootstrap.get_provision_state()
            provision_id = state.get('provision_id', '')

        if not provision_id:
            return jsonify({'error': 'No pending provisioning found'}), 400

        if not _validate_token(provision_id):
            return jsonify({'error': 'Invalid provision ID format'}), 400

        result = bootstrap.check_claim_status(provision_id)

        # Only expose safe fields — never raw result (may contain api_key)
        if result.get('claimed'):
            return jsonify({
                'claimed': True,
                'message': 'Guardian claimed. MSSP heartbeat will start shortly.',
            })
        return jsonify({
            'claimed': False,
            'status': result.get('status', 'pending'),
        })
    except Exception as e:
        logger.error("MSSP claim check error: %s", type(e).__name__)
        return jsonify({'error': 'Claim status check failed'}), 500


@vpn_bp.route('/api/mssp/status')
@require_auth
def api_mssp_status():
    """Get MSSP connection status and claim code if pending."""
    try:
        from shared.mssp.bootstrap import MSSPBootstrap

        bootstrap = MSSPBootstrap(product_type='guardian')
        state = bootstrap.get_provision_state()

        result = {
            'connected': state['status'] == 'provisioned',
            'provisioned': state['status'] == 'provisioned',
            'url': state.get('mssp_url', 'https://mssp.hookprobe.com'),
            'status': state['status'],
        }

        if state['status'] == 'pending_claim':
            result['claimCode'] = state.get('claim_code', '')
            result['provisionId'] = state.get('provision_id', '')

        return jsonify(result)
    except Exception as e:
        return jsonify({
            'connected': False,
            'error': str(type(e).__name__),
        })


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
        return jsonify({'error': _safe_error(e)}), 500


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
        return jsonify({'success': False, 'error': _safe_error(e)}), 500


@vpn_bp.route('/encryption/info')
@require_auth
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
