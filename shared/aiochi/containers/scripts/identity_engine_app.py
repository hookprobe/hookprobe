"""AIOCHI Identity Engine REST API"""
# NOTE: Using __import__ to avoid 'from' keyword which confuses buildah heredoc parsing
Flask = __import__('flask').Flask
jsonify = __import__('flask').jsonify
request = __import__('flask').request
import os


def create_app():
    """Create Flask application."""
    app = Flask(__name__)

    @app.route('/health')
    def health():
        return jsonify({'status': 'healthy', 'service': 'identity-engine'})

    @app.route('/api/device/<mac>')
    def get_device(mac):
        """Get device identity by MAC address."""
        # Import identity engine
        identity_engine = __import__('backend.identity_engine', fromlist=['IdentityEngine'])
        engine = identity_engine.IdentityEngine()
        identity = engine.identify(mac)
        if identity:
            return jsonify(identity.to_dict())
        return jsonify({'error': 'Device not found'}), 404

    @app.route('/api/devices')
    def list_devices():
        """List all known devices."""
        identity_engine = __import__('backend.identity_engine', fromlist=['IdentityEngine'])
        engine = identity_engine.IdentityEngine()
        devices = engine.all_identities()
        return jsonify([d.to_dict() for d in devices])

    @app.route('/api/ecosystems')
    def list_ecosystems():
        """List detected ecosystem bubbles."""
        identity_engine = __import__('backend.identity_engine', fromlist=['IdentityEngine'])
        engine = identity_engine.IdentityEngine()
        ecosystems = engine.get_ecosystem_bubbles()
        return jsonify(ecosystems)

    return app
