"""AIOCHI Identity Engine REST API"""
# NOTE: Using __import__ to avoid 'from' keyword which confuses buildah heredoc parsing
Flask = __import__('flask').Flask
jsonify = __import__('flask').jsonify
request = __import__('flask').request
import os
from collections import defaultdict


def create_app():
    """Create Flask application."""
    app = Flask(__name__)

    # Singleton engine instance (avoid re-creating on each request)
    _engine = None

    def get_engine():
        nonlocal _engine
        if _engine is None:
            identity_engine = __import__('backend.identity_engine', fromlist=['IdentityEngine'])
            _engine = identity_engine.IdentityEngine()
        return _engine

    @app.route('/health')
    def health():
        return jsonify({'status': 'healthy', 'service': 'identity-engine'})

    @app.route('/api/device/<mac>')
    def get_device(mac):
        """Get device identity by MAC address."""
        engine = get_engine()
        # Use enrich() which is the correct method name in IdentityEngine
        identity = engine.enrich(mac)
        if identity:
            return jsonify(identity.to_dict())
        return jsonify({'error': 'Device not found'}), 404

    @app.route('/api/devices')
    def list_devices():
        """List all known devices."""
        engine = get_engine()
        # Use get_all_devices() which is the correct method name
        devices = engine.get_all_devices()
        return jsonify([d.to_dict() for d in devices])

    @app.route('/api/ecosystems')
    def list_ecosystems():
        """List detected ecosystem bubbles grouped by ecosystem type."""
        engine = get_engine()
        devices = engine.get_all_devices()
        # Group devices by ecosystem
        ecosystems = defaultdict(list)
        for device in devices:
            eco_name = device.ecosystem.value if hasattr(device.ecosystem, 'value') else str(device.ecosystem)
            ecosystems[eco_name].append(device.to_dict())
        return jsonify(dict(ecosystems))

    @app.route('/api/feed', methods=['POST'])
    def post_feed():
        """Receive narrative events for the privacy feed."""
        data = request.get_json() or {}
        # Store/forward to narrative engine - placeholder for now
        return jsonify({'status': 'received', 'event': data.get('narrative', {}).get('id', 'unknown')})

    @app.route('/api/performance', methods=['POST'])
    def post_performance():
        """Receive performance metrics."""
        data = request.get_json() or {}
        # Store performance data - placeholder for now
        return jsonify({'status': 'received'})

    @app.route('/api/alert', methods=['POST'])
    def post_alert():
        """Receive security alerts."""
        data = request.get_json() or {}
        # Store/forward alerts - placeholder for now
        return jsonify({'status': 'received', 'alert_type': data.get('type', 'unknown')})

    @app.route('/api/presence', methods=['POST'])
    def post_presence():
        """Receive device presence updates."""
        data = request.get_json() or {}
        # Update presence tracking - placeholder for now
        return jsonify({'status': 'received'})

    @app.route('/api/feedback-request', methods=['POST'])
    def post_feedback_request():
        """Request human feedback on AI decisions."""
        data = request.get_json() or {}
        # Queue feedback request - placeholder for now
        return jsonify({'status': 'queued', 'action_id': data.get('action_id', 'unknown')})

    return app
