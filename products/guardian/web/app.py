#!/usr/bin/env python3
"""
HookProbe Guardian - Local Web UI

Modular Flask application with Blueprint architecture.
Runs on http://192.168.4.1:8080

Version: 5.0.0 - Modular Architecture

Changes in 5.1.0:
- Refactored to modular Flask blueprint architecture
- Beautiful responsive UI with Forty-inspired design
- Improved mobile experience
- HTP secure tunnel (no WireGuard/OpenVPN)
- Enhanced dnsXai with kill switch

Changes in 5.0.0:
- Added L2-L7 OSI layer threat detection and reporting
- Added mobile network protection for hotel/public WiFi
- QSecBit integration with layer-specific metrics
- New Security tab with layer breakdown visualization
"""

import os
from pathlib import Path
from flask import Flask, send_file

from config import Config
from modules import register_blueprints


def create_app(config_class=Config):
    """Application factory for Guardian web UI."""
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    app.config.from_object(config_class)

    # Secret key for sessions
    if app.config.get('SECRET_KEY') is None:
        app.config['SECRET_KEY'] = os.urandom(24)

    # Register all blueprints
    register_blueprints(app)

    # Static file routes
    @app.route('/logo.png')
    def serve_logo():
        """Serve HookProbe logo."""
        logo_path = Path('/opt/hookprobe/guardian/web/hookprobe-emblem.png')
        if logo_path.exists():
            return send_file(logo_path, mimetype='image/png')
        return '', 404

    @app.route('/static/cortex/<path:filename>')
    def serve_cortex_modules(filename):
        """Serve shared Cortex visualization modules."""
        # Try multiple possible paths for the shared cortex modules
        possible_paths = [
            Path('/opt/hookprobe/shared/cortex/frontend/js') / filename,
            Path('/home/user/hookprobe/shared/cortex/frontend/js') / filename,
            Path(__file__).parent.parent.parent.parent / 'shared' / 'cortex' / 'frontend' / 'js' / filename,
        ]
        for cortex_path in possible_paths:
            if cortex_path.exists():
                return send_file(cortex_path, mimetype='application/javascript')
        return '', 404

    @app.route('/favicon.ico')
    def serve_favicon():
        """Serve favicon."""
        return send_file(
            Path(app.static_folder) / 'img' / 'favicon.ico',
            mimetype='image/x-icon'
        ) if (Path(app.static_folder) / 'img' / 'favicon.ico').exists() else ('', 404)

    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        return {'error': 'Not found'}, 404

    @app.errorhandler(500)
    def server_error(e):
        return {'error': 'Internal server error'}, 500

    return app


# Create the application instance
app = create_app()


if __name__ == '__main__':
    # Development server
    app.run(
        host='0.0.0.0',
        port=8080,
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
