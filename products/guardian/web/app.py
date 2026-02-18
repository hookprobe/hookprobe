#!/usr/bin/env python3
"""
HookProbe Guardian - Local Web UI

Modular Flask application with Blueprint architecture.
Runs on http://192.168.4.1:8080

Version: 5.2.0 - Security Hardening + AEGIS Integration
"""

import os
from datetime import timedelta
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

    # Persistent secret key (survives restarts)
    secret_key = _load_secret_key()
    app.config['SECRET_KEY'] = secret_key

    # Session configuration
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)

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

    # Cortex module serving with path traversal protection
    CORTEX_BASE_PATHS = [
        Path('/opt/hookprobe/shared/cortex/frontend/js').resolve(),
        (Path(__file__).parent.parent.parent.parent / 'shared' / 'cortex' / 'frontend' / 'js').resolve(),
    ]

    @app.route('/cortex-modules/<path:filename>')
    def serve_cortex_modules(filename):
        """Serve shared Cortex visualization modules (path-safe)."""
        for base in CORTEX_BASE_PATHS:
            try:
                candidate = (base / filename).resolve()
            except (ValueError, RuntimeError):
                continue
            # Verify the resolved path is within the base directory
            if base in candidate.parents or candidate == base:
                if candidate.exists() and candidate.is_file():
                    return send_file(candidate, mimetype='application/javascript')
        app.logger.warning("Cortex module not found or path denied: %s", filename)
        return '', 404

    @app.route('/favicon.ico')
    def serve_favicon():
        """Serve favicon."""
        favicon = Path(app.static_folder) / 'img' / 'favicon.ico'
        if favicon.exists():
            return send_file(favicon, mimetype='image/x-icon')
        return '', 404

    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        return {'error': 'Not found'}, 404

    @app.errorhandler(500)
    def server_error(e):
        return {'error': 'Internal server error'}, 500

    return app


def _load_secret_key():
    """Load or generate a persistent secret key."""
    key_file = Path('/opt/hookprobe/guardian/secret_key')
    env_key = os.environ.get('GUARDIAN_SECRET_KEY')

    if env_key:
        return env_key

    if key_file.exists():
        try:
            return key_file.read_text().strip()
        except IOError:
            pass

    # Generate and persist
    import secrets
    key = secrets.token_hex(32)
    try:
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(key)
        key_file.chmod(0o600)
    except IOError:
        pass  # Fall through with ephemeral key
    return key


# Create the application instance
app = create_app()


if __name__ == '__main__':
    # Development server
    app.run(
        host='0.0.0.0',
        port=8080,
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
