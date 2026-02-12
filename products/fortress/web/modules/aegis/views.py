"""
AEGIS Views - ORACLE Chat Interface

Flask routes for the AI security assistant chat UI and API.
"""

import logging
import uuid
from flask import render_template, jsonify, request
from flask_login import login_required

from . import aegis_bp

logger = logging.getLogger(__name__)

# Lazy import AEGIS client (lib/ is at /app/lib in container)
_aegis_client = None


def _get_client():
    """Lazy-load the AegisClient singleton."""
    global _aegis_client
    if _aegis_client is None:
        try:
            from core.aegis.client import get_aegis_client
            _aegis_client = get_aegis_client()
        except ImportError:
            try:
                from lib.aegis.client import get_aegis_client
                _aegis_client = get_aegis_client()
            except ImportError as e:
                logger.error(f"AEGIS client not available: {e}")
                return None
    return _aegis_client


# ------------------------------------------------------------------
# Page Routes
# ------------------------------------------------------------------

@aegis_bp.route('/')
@login_required
def index():
    """AEGIS chat interface."""
    session_id = request.args.get('session') or str(uuid.uuid4())
    return render_template('aegis/index.html', session_id=session_id)


# ------------------------------------------------------------------
# API Routes
# ------------------------------------------------------------------

@aegis_bp.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    """Process a chat message and return ORACLE response."""
    data = request.get_json()
    if not data or not data.get('message'):
        return jsonify({'error': 'message is required'}), 400

    message = data['message'].strip()
    if not message:
        return jsonify({'error': 'message cannot be empty'}), 400

    session_id = data.get('session_id', str(uuid.uuid4()))

    client = _get_client()
    if client is None:
        return jsonify({
            'message': 'AEGIS is not available. Please check the server configuration.',
            'agent': 'ORACLE',
            'confidence': 0.0,
            'sources': [],
            'session_id': session_id,
        })

    try:
        response = client.chat(session_id, message)
        return jsonify({
            'message': response.message,
            'agent': response.agent,
            'confidence': response.confidence,
            'sources': response.sources,
            'session_id': session_id,
        })
    except Exception as e:
        logger.exception("AEGIS chat error")
        return jsonify({
            'message': 'An error occurred while processing your request.',
            'agent': 'ORACLE',
            'confidence': 0.0,
            'sources': [],
            'session_id': session_id,
        }), 500


@aegis_bp.route('/api/status')
@login_required
def api_status():
    """Get AEGIS system health status."""
    client = _get_client()
    if client is None:
        return jsonify({
            'llm_ready': False,
            'model_loaded': False,
            'model_name': 'AEGIS unavailable',
            'uptime': 0,
            'tier': 'unavailable',
            'loading': False,
            'load_error': '',
            'ram_usage_mb': 0,
            'avg_inference_ms': 0,
            'enabled': False,
        })

    status = client.get_status()
    return jsonify(status.model_dump())


@aegis_bp.route('/api/clear', methods=['POST'])
@login_required
def api_clear():
    """Clear a chat session."""
    data = request.get_json() or {}
    session_id = data.get('session_id', '')

    client = _get_client()
    if client and session_id:
        client.clear_session(session_id)

    return jsonify({'success': True})
