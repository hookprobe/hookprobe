"""
Fortress VPN & Mesh Views - HTP tunnel status, peer management, mesh control,
MSSP provisioning.

Provides:
- Mesh peer server status (TCP 8144 gossip)
- HTP VPN gateway status (UDP 8144 tunnel)
- Connected peers list (Guardian/Sentinel nodes)
- Gossip statistics and threat intelligence feed
- MSSP connection management (provisioning, registration, disconnect)

Status is read from the mesh HTTP API (port 8766) running on the host
via fts-mesh container. MSSP provisioning reads/writes /etc/hookprobe/node.conf.
"""

import json
import logging
import os
import re
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from flask import render_template, jsonify, request, current_app
from flask_login import login_required

from . import vpn_bp
from ..auth.decorators import admin_required

logger = logging.getLogger(__name__)

# Validation patterns (for MSSP registration)
_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$')
_TOKEN_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,128}$')

# Paths
CONFIG_DIR = Path('/etc/hookprobe')
NODE_CONF = CONFIG_DIR / 'node.conf'
CLAIM_FILE = CONFIG_DIR / 'claim_code'
MSSP_STATUS_FILE = Path('/opt/hookprobe/fortress/data/mssp_status.json')

# Mesh HTTP API (running on host network via fts-mesh container).
# fts-web is on bridge 172.20.200.0/24; host gateway is 172.20.200.1.
# Detect container by checking if the gateway is reachable vs localhost.
def _detect_mesh_host():
    """Find the mesh API host — try container gateway first, then localhost."""
    for host in ('172.20.200.1', '127.0.0.1'):
        try:
            import socket
            s = socket.create_connection((host, 8766), timeout=2)
            s.close()
            return host
        except (OSError, socket.timeout):
            continue
    return '172.20.200.1'  # default; will fail gracefully in _mesh_api_get


_MESH_HOST = _detect_mesh_host()
MESH_API_BASE = f'http://{_MESH_HOST}:8766'


def _mesh_api_get(path, timeout=5):
    """GET request to mesh HTTP API."""
    try:
        url = f'{MESH_API_BASE}{path}'
        req = urllib.request.Request(url, method='GET')
        req.add_header('Accept', 'application/json')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode()), True
    except Exception:
        return {}, False


def _read_node_conf():
    """Read MSSP_URL and check if API_KEY is present."""
    mssp_url = ''
    has_api_key = False
    try:
        with open(str(NODE_CONF)) as f:
            for line in f:
                line = line.strip()
                if line.startswith('MSSP_URL='):
                    mssp_url = line.split('=', 1)[1].strip().strip('"').strip("'")
                elif line.startswith('API_KEY='):
                    val = line.split('=', 1)[1].strip().strip('"').strip("'")
                    has_api_key = bool(val)
    except (FileNotFoundError, PermissionError):
        pass
    return mssp_url, has_api_key


def _decode_hex_node_id(nid):
    """Decode hex-encoded node IDs (mesh uses hex of UTF-8 bytes)."""
    if nid and all(c in '0123456789abcdef' for c in nid):
        try:
            return bytes.fromhex(nid).decode('utf-8', errors='replace')
        except (ValueError, UnicodeDecodeError):
            pass
    return nid


def _get_mesh_status():
    """Aggregate mesh status from the mesh HTTP API."""
    peers = []
    gossip_stats = {}
    vpn_gateway = {'active': False, 'clients': 0}
    bootstrap_peers = ''
    uptime = 0
    node_id = ''
    api_reachable = False

    # Try the mesh HTTP API
    data, ok = _mesh_api_get('/status')
    if ok:
        api_reachable = True
        peers = data.get('peers', [])
        for peer in peers:
            peer['node_id'] = _decode_hex_node_id(peer.get('node_id', ''))
        gossip_stats = data.get('gossip', {})
        vpn_gateway = data.get('vpn_gateway', {'active': False, 'clients': 0})
        bootstrap_peers = data.get('bootstrap_peers', '')
        uptime = data.get('uptime', 0)
        node_id = data.get('node_id', '')
    else:
        # Try health endpoint as lighter check
        health, hok = _mesh_api_get('/health')
        if hok:
            api_reachable = True

    mssp_url, has_api_key = _read_node_conf()

    # Determine overall state
    if api_reachable and uptime > 5:
        state = 'connected'
    elif api_reachable:
        state = 'starting'
    else:
        state = 'offline'

    return {
        'state': state,
        'node_id': node_id,
        'uptime_seconds': uptime,
        'peer_count': len(peers),
        'peers': peers,
        'gossip': gossip_stats,
        'vpn_gateway': vpn_gateway,
        'bootstrap_peers': bootstrap_peers,
        'mssp_url': mssp_url,
        'mssp_provisioned': has_api_key,
    }


# ---- Mesh Status Routes ----

@vpn_bp.route('/')
@login_required
def index():
    """VPN & Mesh overview page."""
    status = _get_mesh_status()
    return render_template('vpn/index.html', status=status)


@vpn_bp.route('/api/status')
@login_required
def api_status():
    """JSON mesh status for AJAX polling."""
    return jsonify(_get_mesh_status())


@vpn_bp.route('/api/peers')
@login_required
def api_peers():
    """Get connected mesh peers."""
    data, ok = _mesh_api_get('/status')
    if ok:
        peers = data.get('peers', [])
        for peer in peers:
            peer['node_id'] = _decode_hex_node_id(peer.get('node_id', ''))
        return jsonify({
            'success': True,
            'peers': peers,
            'peer_count': len(peers),
        })
    return jsonify({'success': False, 'peers': [], 'peer_count': 0})


@vpn_bp.route('/api/gossip')
@login_required
def api_gossip():
    """Get gossip/threat intelligence stats."""
    data, ok = _mesh_api_get('/status')
    if ok:
        return jsonify({
            'success': True,
            'gossip': data.get('gossip', {}),
        })
    return jsonify({'success': False, 'gossip': {}})


@vpn_bp.route('/api/health')
@login_required
def api_health():
    """Quick health check of mesh service."""
    _, ok = _mesh_api_get('/health')
    return jsonify({'healthy': ok})


# ---- VPN Tunnel Control Routes (admin-only) ----
#
# fts-web runs inside a container and cannot call systemctl.
# Communication with the host VPN daemon uses shared files:
#   /etc/hookprobe/fortress_vpn.json  - config (bind-mounted RW)
#   /run/fortress/vpn-state.json      - state written by daemon (bind-mounted)
#   /etc/hookprobe/vpn_command        - control file (web writes, host reads)

VPN_STATE_FILE = Path('/etc/hookprobe/vpn-state.json')
VPN_CONFIG_FILE = Path('/etc/hookprobe/fortress_vpn.json')
VPN_COMMAND_FILE = Path('/etc/hookprobe/vpn_command')


def _read_vpn_client_state():
    """Read VPN client state from state file written by host daemon."""
    try:
        if VPN_STATE_FILE.exists():
            data = json.loads(VPN_STATE_FILE.read_text())
            # Only trust if written within last 30s
            if time.time() - data.get('ts', 0) < 30:
                return data
    except (json.JSONDecodeError, KeyError, OSError):
        pass
    return {'state': 'stopped', 'connected': False}


def _write_vpn_command(cmd: str):
    """Write a command for the host VPN service to pick up."""
    try:
        VPN_COMMAND_FILE.parent.mkdir(parents=True, exist_ok=True)
        VPN_COMMAND_FILE.write_text(json.dumps({
            'command': cmd,
            'ts': time.time(),
        }))
    except OSError as e:
        logger.warning("Cannot write VPN command: %s", e)
        raise


def _write_vpn_config(cfg: dict):
    """Write VPN config file (accessible from both container and host)."""
    VPN_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    VPN_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(str(VPN_CONFIG_FILE), 0o600)
    except OSError:
        pass


@vpn_bp.route('/api/tunnel/status')
@login_required
def api_tunnel_status():
    """Get VPN tunnel client status."""
    state = _read_vpn_client_state()

    # Read config
    try:
        if VPN_CONFIG_FILE.exists():
            cfg = json.loads(VPN_CONFIG_FILE.read_text())
            state['configured'] = True
            state['enabled'] = cfg.get('enabled', False)
            state['kill_switch'] = cfg.get('kill_switch', 'host')
            state['gateway_host'] = cfg.get('gateway_host', 'mesh.hookprobe.com')
        else:
            state['configured'] = False
    except (json.JSONDecodeError, OSError):
        state['configured'] = False

    return jsonify(state)


@vpn_bp.route('/api/tunnel/connect', methods=['POST'])
@login_required
@admin_required
def api_tunnel_connect():
    """Enable VPN tunnel by writing config + command file."""
    try:
        cfg = {}
        if VPN_CONFIG_FILE.exists():
            try:
                cfg = json.loads(VPN_CONFIG_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        cfg['enabled'] = True
        if not cfg.get('gateway_host'):
            cfg['gateway_host'] = 'mesh.hookprobe.com'
        if not cfg.get('gateway_port'):
            cfg['gateway_port'] = 8144
        if not cfg.get('kill_switch'):
            cfg['kill_switch'] = 'host'

        _write_vpn_config(cfg)
        _write_vpn_command('connect')

        return jsonify({'success': True, 'message': 'VPN connect requested'})
    except Exception as e:
        logger.error("VPN connect error: %s", type(e).__name__)
        return jsonify({'success': False, 'error': 'VPN connect failed'}), 500


@vpn_bp.route('/api/tunnel/disconnect', methods=['POST'])
@login_required
@admin_required
def api_tunnel_disconnect():
    """Disable VPN tunnel by writing command file."""
    try:
        # Update config to disabled
        cfg = {}
        if VPN_CONFIG_FILE.exists():
            try:
                cfg = json.loads(VPN_CONFIG_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        cfg['enabled'] = False
        _write_vpn_config(cfg)
        _write_vpn_command('disconnect')

        return jsonify({'success': True, 'message': 'VPN disconnect requested'})
    except Exception as e:
        logger.error("VPN disconnect error: %s", type(e).__name__)
        return jsonify({'success': False, 'error': 'VPN disconnect failed'}), 500


@vpn_bp.route('/api/tunnel/kill-switch', methods=['POST'])
@login_required
@admin_required
def api_tunnel_kill_switch():
    """Change kill switch mode (off/host/full)."""
    data = request.get_json() or {}
    mode = data.get('mode', '')

    if mode not in ('off', 'host', 'full'):
        return jsonify({'success': False, 'error': 'Invalid mode. Use: off, host, full'}), 400

    try:
        cfg = {}
        if VPN_CONFIG_FILE.exists():
            try:
                cfg = json.loads(VPN_CONFIG_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        cfg['kill_switch'] = mode
        _write_vpn_config(cfg)

        return jsonify({'success': True, 'mode': mode})
    except Exception as e:
        logger.error("Kill switch change error: %s", type(e).__name__)
        return jsonify({'success': False, 'error': 'Failed to change kill switch'}), 500


# ---- MSSP Provisioning Routes (admin-only) ----

def _add_shared_path():
    """Ensure shared/mssp is importable."""
    for candidate in [
        Path('/app/shared'),                                  # container layout
        Path(__file__).resolve().parents[4] / 'shared',       # repo layout
        Path('/opt/hookprobe/shared'),                        # deployed layout
    ]:
        if (candidate / 'mssp').is_dir() and str(candidate.parent) not in sys.path:
            sys.path.insert(0, str(candidate.parent))
            break


def _safe_error_message(exc, context=''):
    """Return a generic error message without leaking internals."""
    try:
        from ...security_utils import safe_error_message
        return safe_error_message(exc, context)
    except ImportError:
        return f'{context} error' if context else 'An error occurred'


@vpn_bp.route('/mssp/status')
@login_required
@admin_required
def mssp_status():
    """Get MSSP connection status and claim code if pending."""
    try:
        _add_shared_path()
        from shared.mssp.bootstrap import MSSPBootstrap
        bootstrap = MSSPBootstrap(product_type='fortress')
        state = bootstrap.get_provision_state()

        result = {
            'provisioned': state['status'] == 'provisioned',
            'url': state.get('mssp_url', 'https://mssp.hookprobe.com'),
            'status': state['status'],
        }

        if state['status'] == 'pending_claim':
            result['claimCode'] = state.get('claim_code', '')
            result['provisionId'] = state.get('provision_id', '')

        # Enrich with heartbeat status from fts-qsecbit
        if MSSP_STATUS_FILE.exists():
            try:
                hb = json.loads(MSSP_STATUS_FILE.read_text())
                result['heartbeatActive'] = hb.get('connected', False)
                result['lastHeartbeat'] = hb.get('timestamp', '')
            except (json.JSONDecodeError, KeyError):
                pass

        return jsonify(result)

    except Exception as e:
        logger.error("MSSP status error: %s", type(e).__name__)
        return jsonify({
            'provisioned': False,
            'status': 'error',
            'error': _safe_error_message(e, 'MSSP status'),
        })


@vpn_bp.route('/mssp/provision', methods=['POST'])
@login_required
@admin_required
def mssp_provision():
    """Start MSSP provisioning (non-blocking). Returns claim code."""
    try:
        _add_shared_path()
        from shared.mssp.bootstrap import MSSPBootstrap

        bootstrap = MSSPBootstrap(product_type='fortress')
        result = bootstrap.start_provision()

        if result['status'] == 'already_provisioned':
            return jsonify({
                'status': 'already_provisioned',
                'message': 'This Fortress is already registered with MSSP.',
            })

        if result.get('claim_code'):
            from ...app import _start_mssp_claim_poller
            _start_mssp_claim_poller(current_app._get_current_object())

        return jsonify(result)

    except Exception as e:
        logger.error("MSSP provision error: %s", type(e).__name__)
        return jsonify({
            'status': 'error',
            'error': _safe_error_message(e, 'provisioning'),
        }), 500


@vpn_bp.route('/mssp/claim/check', methods=['POST'])
@login_required
@admin_required
def mssp_claim_check():
    """Check if a pending claim code has been entered in the dashboard."""
    try:
        _add_shared_path()
        from shared.mssp.bootstrap import MSSPBootstrap

        data = request.get_json() or {}
        provision_id = data.get('provision_id', '')

        bootstrap = MSSPBootstrap(product_type='fortress')

        if not provision_id:
            state = bootstrap.get_provision_state()
            provision_id = state.get('provision_id', '')

        if not provision_id:
            return jsonify({'error': 'No pending provisioning found'}), 400

        if not _TOKEN_RE.match(provision_id):
            return jsonify({'error': 'Invalid provision ID format'}), 400

        result = bootstrap.check_claim_status(provision_id)

        if result.get('claimed'):
            return jsonify({
                'claimed': True,
                'message': 'Fortress claimed. MSSP heartbeat will start shortly.',
            })

        raw_status = result.get('status', 'pending')
        safe_status = raw_status if raw_status in ('pending', 'active', 'expired') else 'pending'
        return jsonify({
            'claimed': False,
            'status': safe_status,
        })

    except Exception as e:
        logger.error("MSSP claim check error: %s", type(e).__name__)
        return jsonify({
            'error': 'Claim status check failed',
        }), 500


@vpn_bp.route('/mssp/register', methods=['POST'])
@login_required
@admin_required
def mssp_register():
    """Manual MSSP registration with an existing API key."""
    data = request.get_json() or {}
    endpoint = data.get('endpoint', 'mssp.hookprobe.com')
    api_key = data.get('api_key', '')

    if not api_key:
        return jsonify({'success': False, 'error': 'API key is required'}), 400
    if not _TOKEN_RE.match(api_key):
        return jsonify({'success': False, 'error': 'Invalid API key format'}), 400
    if not _HOSTNAME_RE.match(endpoint):
        return jsonify({'success': False, 'error': 'Invalid endpoint'}), 400

    mssp_url = f'https://{endpoint}'

    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=str(CONFIG_DIR), prefix='.node.conf.')
        try:
            with os.fdopen(fd, 'w') as f:
                if NODE_CONF.exists():
                    for line in NODE_CONF.read_text().splitlines():
                        key = line.split('=', 1)[0].strip() if '=' in line else ''
                        if key not in ('API_KEY', 'MSSP_URL'):
                            f.write(line + '\n')
                f.write(f'MSSP_URL={mssp_url}\n')
                f.write(f'API_KEY={api_key}\n')
            os.chmod(tmp_path, 0o600)
            os.rename(tmp_path, str(NODE_CONF))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        try:
            if CLAIM_FILE.exists():
                CLAIM_FILE.unlink()
        except OSError:
            pass

        return jsonify({
            'success': True,
            'message': f'Registered with MSSP at {endpoint}',
        })

    except Exception as e:
        logger.error("MSSP registration error: %s", type(e).__name__)
        return jsonify({
            'success': False,
            'error': _safe_error_message(e, 'MSSP registration'),
        }), 500


@vpn_bp.route('/mssp/disconnect', methods=['POST'])
@login_required
@admin_required
def mssp_disconnect():
    """Disconnect from MSSP by removing API key from node.conf."""
    try:
        if NODE_CONF.exists():
            lines = NODE_CONF.read_text().splitlines()
            new_lines = [
                line for line in lines
                if not line.strip().startswith('API_KEY=')
            ]
            NODE_CONF.write_text('\n'.join(new_lines) + '\n')

        if CLAIM_FILE.exists():
            CLAIM_FILE.unlink()

        return jsonify({'success': True, 'message': 'Disconnected from MSSP'})

    except Exception as e:
        logger.error("MSSP disconnect error: %s", type(e).__name__)
        return jsonify({
            'success': False,
            'error': _safe_error_message(e, 'MSSP disconnect'),
        }), 500
