"""
Mesh Module Views - HTP/Neuro/NSE Mesh Status API

Provides REST API for mesh daemon status, peer list, and MSSP info.
"""
import json
import logging
from pathlib import Path

from flask import jsonify, current_app
from . import mesh_bp
from modules.auth import require_auth

logger = logging.getLogger(__name__)

MESH_STATUS_FILE = Path('/opt/hookprobe/guardian/data/mesh_status.json')


def _read_mesh_status():
    """Read mesh status from JSON file written by mesh daemon."""
    if not MESH_STATUS_FILE.exists():
        return None
    try:
        with open(MESH_STATUS_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.debug("Could not read mesh status: %s", e)
        return None


@mesh_bp.route('/status')
@require_auth
def api_mesh_status():
    """Get mesh daemon status."""
    status = _read_mesh_status()
    if status is None:
        return jsonify({
            'running': False,
            'error': 'Mesh daemon not running or status unavailable'
        })
    return jsonify(status)


@mesh_bp.route('/peers')
@require_auth
def api_mesh_peers():
    """Get mesh peer list."""
    status = _read_mesh_status()
    if status is None:
        return jsonify({'peers': [], 'count': 0})

    mesh_info = status.get('mesh', {})
    peers = mesh_info.get('peers', [])
    return jsonify({
        'peers': peers,
        'count': len(peers),
        'state': mesh_info.get('state', 'UNKNOWN'),
    })


@mesh_bp.route('/mssp')
@require_auth
def api_mesh_mssp():
    """Get MSSP/AegisLite connection status."""
    aegis = current_app.extensions.get('aegis_lite')
    if aegis is None:
        return jsonify({
            'connected': False,
            'error': 'AEGIS-Lite not initialized'
        })

    try:
        status = aegis.get_status()
        return jsonify({
            'connected': True,
            'version': status.get('version', 'unknown'),
            'profile': status.get('profile', 'lite'),
            'aegis': status.get('aegis'),
            'mssp': status.get('mssp'),
        })
    except Exception as e:
        logger.warning("MSSP status error: %s", e)
        return jsonify({
            'connected': False,
            'error': 'Status unavailable'
        })
