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
    """Get HTP tunnel connection status — checks actual system state."""
    try:
        import subprocess as _sp

        # Check if htp0 TUN device exists and is UP
        tun_up = False
        tun_ip = None
        try:
            result = _sp.run(
                ['ip', '-j', 'addr', 'show', 'htp0'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                import json as _json
                ifaces = _json.loads(result.stdout)
                if ifaces and ifaces[0].get('operstate', '').upper() in ('UP', 'UNKNOWN'):
                    tun_up = True
                    for addr_info in ifaces[0].get('addr_info', []):
                        if addr_info.get('family') == 'inet':
                            tun_ip = addr_info.get('local')
        except Exception:
            pass

        # Check if systemd service is active
        service_active = False
        try:
            result = _sp.run(
                ['systemctl', 'is-active', 'guardian-htp-vpn'],
                capture_output=True, text=True, timeout=5
            )
            service_active = result.stdout.strip() == 'active'
        except Exception:
            pass

        connected = tun_up and service_active

        # Load VPN config for display
        config = {}
        try:
            conf_path = Path('/etc/hookprobe/guardian_vpn.json')
            if conf_path.exists():
                import json as _json
                config = _json.loads(conf_path.read_text())
        except Exception:
            pass

        # Get uptime from service
        uptime = None
        if connected:
            try:
                result = _sp.run(
                    ['systemctl', 'show', 'guardian-htp-vpn', '--property=ActiveEnterTimestamp'],
                    capture_output=True, text=True, timeout=5
                )
                ts_line = result.stdout.strip()
                if '=' in ts_line:
                    from datetime import datetime
                    ts_str = ts_line.split('=', 1)[1].strip()
                    if ts_str:
                        start = datetime.strptime(ts_str, '%a %Y-%m-%d %H:%M:%S %Z')
                        elapsed = int((datetime.now() - start).total_seconds())
                        if elapsed > 0:
                            hours, remainder = divmod(elapsed, 3600)
                            minutes, seconds = divmod(remainder, 60)
                            uptime = f"{hours}:{minutes:02d}:{seconds:02d}"
            except Exception:
                pass

        return jsonify({
            'state': 'connected' if connected else 'stopped',
            'connected': connected,
            'server': config.get('gateway_host', 'mesh.hookprobe.com'),
            'protocol': 'HTP (HookProbe Transport Protocol)',
            'encryption': 'ChaCha20-Poly1305 (NSE)',
            'authentication': 'Ed25519 + HKDF-SHA256',
            'key_exchange': 'HKDF-SHA256 + PSK',
            'tun_device': 'htp0',
            'tun_ip': tun_ip or config.get('tun_local_ip', '10.250.0.2'),
            'kill_switch': config.get('kill_switch', True),
            'node_id': config.get('node_id', ''),
            'uptime': uptime,
            'service_active': service_active,
            'tun_up': tun_up,
        })
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
    """Connect to mesh via HTP tunnel (starts systemd service)."""
    try:
        import subprocess as _sp

        # Start the systemd VPN service
        result = _sp.run(
            ['systemctl', 'start', 'guardian-htp-vpn'],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode != 0:
            logger.error("Failed to start VPN service: %s", result.stderr.strip())
            return jsonify({
                'success': False,
                'error': 'Failed to start VPN service'
            }), 500

        return jsonify({
            'success': True,
            'message': 'HTP VPN connecting...',
            'protocol': 'HTP',
            'encryption': 'ChaCha20-Poly1305 (NSE)',
        })
    except Exception as e:
        return jsonify({'success': False, 'error': _safe_error(e)}), 500


@vpn_bp.route('/disconnect', methods=['POST'])
@require_auth
def api_disconnect():
    """Disconnect HTP tunnel — stops service and reverts to local breakout."""
    try:
        import subprocess as _sp

        # Stop the systemd VPN service (triggers graceful shutdown:
        # removes kill switch, restores default route, tears down TUN)
        result = _sp.run(
            ['systemctl', 'stop', 'guardian-htp-vpn'],
            capture_output=True, text=True, timeout=15
        )

        # Ensure kill switch is removed and default route restored
        # (belt-and-suspenders in case the service didn't clean up)
        _sp.run(['nft', 'delete', 'table', 'inet', 'guardian_vpn'],
                capture_output=True, timeout=5)
        _sp.run(['ip', 'link', 'delete', 'htp0'],
                capture_output=True, timeout=5)

        # Restore default route via local gateway if missing
        route_check = _sp.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=5
        )
        if not route_check.stdout.strip():
            try:
                import json as _json
                conf_path = Path('/etc/hookprobe/guardian_vpn.json')
                wan_iface = 'eth0'
                if conf_path.exists():
                    config = _json.loads(conf_path.read_text())
                    wan_iface = config.get('wan_interface', 'eth0')

                # Read saved original gateway from VPN state file
                state_path = Path('/opt/hookprobe/guardian/htp/vpn_state.json')
                original_gw = None
                if state_path.exists():
                    state = _json.loads(state_path.read_text())
                    original_gw = state.get('original_gateway')

                if original_gw:
                    _sp.run(['ip', 'route', 'add', 'default', 'via', original_gw, 'dev', wan_iface],
                            capture_output=True, timeout=5)
                    logger.info("Restored default route via %s dev %s (from saved state)", original_gw, wan_iface)
                else:
                    # Fallback: try DHCP proto routes
                    gw_result = _sp.run(
                        ['ip', 'route', 'show', 'dev', wan_iface, 'proto', 'dhcp'],
                        capture_output=True, text=True, timeout=5
                    )
                    for line in gw_result.stdout.splitlines():
                        if 'default via' in line:
                            gw = line.split('via')[1].split()[0]
                            _sp.run(['ip', 'route', 'add', 'default', 'via', gw, 'dev', wan_iface],
                                    capture_output=True, timeout=5)
                            logger.info("Restored default route via %s dev %s (from DHCP)", gw, wan_iface)
                            break
                    else:
                        logger.warning("No saved gateway and no DHCP route — cannot restore default route")
            except Exception as e:
                logger.warning("Route restore error: %s", e)

        if result.returncode != 0:
            logger.warning("VPN service stop returned %d: %s", result.returncode, result.stderr.strip())

        return jsonify({
            'success': True,
            'message': 'VPN disconnected — using local internet breakout'
        })
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
        logger.error("Mesh registration failed: %s", output)
        return jsonify({'success': False, 'error': 'Mesh registration failed'}), 500
    except Exception as e:
        logger.error("Mesh registration error: %s", type(e).__name__)
        return jsonify({'success': False, 'error': 'Mesh registration failed'}), 500


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
