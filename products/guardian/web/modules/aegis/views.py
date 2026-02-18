"""
AEGIS Module Views - AI Security Assistant Endpoints

Provides REST API for interacting with AEGIS-Lite on Guardian.
"""
import logging
import uuid

from flask import jsonify, request
from . import aegis_bp
from modules.auth import require_auth

logger = logging.getLogger(__name__)

# Lazy-loaded AEGIS-Lite singleton
_aegis_lite = None
_aegis_init_attempted = False


def _get_aegis():
    """Get or initialize the AEGIS-Lite singleton."""
    global _aegis_lite, _aegis_init_attempted
    if _aegis_lite is not None:
        return _aegis_lite
    if _aegis_init_attempted:
        return None

    _aegis_init_attempted = True
    try:
        from products.guardian.lib.aegis_lite import AegisLite
        _aegis_lite = AegisLite()
        if _aegis_lite.initialize():
            logger.info("AEGIS-Lite initialized for web UI")
        else:
            logger.warning("AEGIS-Lite initialization returned False")
            _aegis_lite = None
    except ImportError:
        logger.warning("AEGIS-Lite not available (import failed)")
    except Exception as e:
        logger.warning("AEGIS-Lite init failed: %s", e)
        _aegis_lite = None

    return _aegis_lite


@aegis_bp.route('/status')
@require_auth
def api_status():
    """Get AEGIS-Lite status."""
    aegis = _get_aegis()
    if not aegis:
        return jsonify({
            'available': False,
            'reason': 'AEGIS-Lite not initialized',
            'version': None,
        })

    try:
        status = aegis.get_status()
        status['available'] = True
        return jsonify(status)
    except Exception as e:
        return jsonify({
            'available': False,
            'error': str(e),
        }), 500


@aegis_bp.route('/chat', methods=['POST'])
@require_auth
def api_chat():
    """Chat with AEGIS-Lite AI assistant."""
    aegis = _get_aegis()
    if not aegis:
        return jsonify({
            'success': False,
            'error': 'AEGIS-Lite not available'
        }), 503

    data = request.get_json() or {}
    message = data.get('message', '').strip()
    session_id = data.get('session_id') or str(uuid.uuid4())

    if not message:
        return jsonify({'success': False, 'error': 'Message required'}), 400
    if len(message) > 2000:
        return jsonify({'success': False, 'error': 'Message too long (max 2000 chars)'}), 400

    try:
        response = aegis.chat(session_id, message)
        if response:
            return jsonify({
                'success': True,
                'session_id': session_id,
                'response': response if isinstance(response, str) else str(response),
            })
        return jsonify({
            'success': False,
            'error': 'No response from AEGIS'
        }), 500
    except Exception as e:
        logger.error("AEGIS chat error: %s", e)
        return jsonify({'success': False, 'error': str(e)}), 500


@aegis_bp.route('/finding', methods=['POST'])
@require_auth
def api_submit_finding():
    """Submit a threat finding to MSSP via AEGIS-Lite."""
    aegis = _get_aegis()
    if not aegis:
        return jsonify({'success': False, 'error': 'AEGIS-Lite not available'}), 503

    data = request.get_json() or {}

    try:
        result = aegis.submit_finding(data)
        return jsonify({'success': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@aegis_bp.route('/recommendation', methods=['POST'])
@require_auth
def api_handle_recommendation():
    """Handle a recommendation from MSSP/mesh."""
    aegis = _get_aegis()
    if not aegis:
        return jsonify({'success': False, 'error': 'AEGIS-Lite not available'}), 503

    data = request.get_json() or {}

    try:
        result = aegis.handle_recommendation(data)
        return jsonify({'success': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
