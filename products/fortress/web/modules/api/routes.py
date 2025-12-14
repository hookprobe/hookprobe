"""Fortress REST API Routes."""
from flask import jsonify
from flask_login import login_required
from . import api_bp

@api_bp.route('/health')
def health():
    return jsonify({'status': 'healthy', 'tier': 'fortress'})

@api_bp.route('/version')
def version():
    return jsonify({'version': '5.0.0', 'product': 'Fortress'})
