"""
Fortress MSSP Views — Claim code, status, registration endpoints.

All endpoints require admin authentication and CSRF protection.
fts-web owns all MSSP write operations (claim_code, node.conf).
fts-qsecbit reads config files as read-only consumer.
"""

import json
import logging
import os
import re
import sys
import tempfile
from pathlib import Path

from flask import render_template, request, jsonify
from flask_login import login_required

from . import mssp_bp
from ..auth.decorators import admin_required
from ...security_utils import safe_error_message

logger = logging.getLogger(__name__)

# Validation patterns
_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$')
_TOKEN_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,128}$')

# Paths
CONFIG_DIR = Path('/etc/hookprobe')
NODE_CONF = CONFIG_DIR / 'node.conf'
CLAIM_FILE = CONFIG_DIR / 'claim_code'
MSSP_STATUS_FILE = Path('/opt/hookprobe/fortress/data/mssp_status.json')


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


# ---- Page route ----

@mssp_bp.route('/')
@login_required
@admin_required
def index():
    """MSSP management page."""
    return render_template('mssp/index.html')


# ---- API routes ----

@mssp_bp.route('/api/status')
@login_required
@admin_required
def api_status():
    """Get MSSP connection status and claim code if pending.

    Reads from shared filesystem — no network calls.
    """
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
            'error': safe_error_message(e, 'MSSP status'),
        })


@mssp_bp.route('/api/provision', methods=['POST'])
@login_required
@admin_required
def api_provision():
    """Start MSSP provisioning (non-blocking). Returns claim code.

    This runs inside fts-web which has rw access to /etc/hookprobe.
    """
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

        # Start background claim poller now that a claim code exists
        if result.get('claim_code'):
            from flask import current_app
            from ...app import _start_mssp_claim_poller
            _start_mssp_claim_poller(current_app._get_current_object())

        return jsonify(result)

    except Exception as e:
        logger.error("MSSP provision error: %s", type(e).__name__)
        return jsonify({
            'status': 'error',
            'error': safe_error_message(e, 'provisioning'),
        }), 500


@mssp_bp.route('/api/claim/check', methods=['POST'])
@login_required
@admin_required
def api_claim_check():
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

        # Never return API key in JSON — it's written to disk only
        if result.get('claimed'):
            return jsonify({
                'claimed': True,
                'message': 'Fortress claimed. MSSP heartbeat will start shortly.',
            })

        return jsonify(result)

    except Exception as e:
        logger.error("MSSP claim check error: %s", type(e).__name__)
        return jsonify({
            'error': safe_error_message(e, 'claim check'),
        }), 500


@mssp_bp.route('/api/register', methods=['POST'])
@login_required
@admin_required
def api_register():
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
        # Write config atomically
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=str(CONFIG_DIR), prefix='.node.conf.')
        try:
            with os.fdopen(fd, 'w') as f:
                # Preserve existing lines that aren't API_KEY or MSSP_URL
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

        # Remove claim file if it exists
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
            'error': safe_error_message(e, 'MSSP registration'),
        }), 500


@mssp_bp.route('/api/disconnect', methods=['POST'])
@login_required
@admin_required
def api_disconnect():
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
            'error': safe_error_message(e, 'MSSP disconnect'),
        }), 500
