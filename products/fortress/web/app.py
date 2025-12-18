#!/usr/bin/env python3
"""
HookProbe Fortress - Admin Portal

Professional admin dashboard with authentication for small businesses.
Uses AdminLTE 3.x for the UI framework.

Version: 5.0.0 - MVP
License: AGPL-3.0

Target: Small businesses (flower shops, bakeries, retail, etc.)
"""

import os
from pathlib import Path
from datetime import timedelta

from flask import Flask, redirect, url_for
from flask_login import LoginManager

from config import Config


def create_app(config_class=Config):
    """Application factory for Fortress admin portal."""
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    app.config.from_object(config_class)

    # Secret key for sessions
    if app.config.get('SECRET_KEY') is None:
        secret_file = Path('/etc/hookprobe/secrets/fortress_secret_key')
        if secret_file.exists():
            app.config['SECRET_KEY'] = secret_file.read_text().strip()
        else:
            app.config['SECRET_KEY'] = os.urandom(32)

    # Session configuration
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access the admin portal.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        from modules.auth.models import User
        return User.get(user_id)

    # Register blueprints
    from modules import register_blueprints
    register_blueprints(app)

    # Root redirect
    @app.route('/')
    def index():
        return redirect(url_for('dashboard.index'))

    # Health check endpoint
    @app.route('/health')
    def health():
        return {'status': 'healthy', 'tier': 'fortress'}, 200

    # Error handlers
    @app.errorhandler(401)
    def unauthorized(e):
        return redirect(url_for('auth.login'))

    @app.errorhandler(403)
    def forbidden(e):
        return {'error': 'Forbidden', 'message': 'You do not have permission'}, 403

    @app.errorhandler(404)
    def not_found(e):
        return {'error': 'Not found'}, 404

    @app.errorhandler(500)
    def server_error(e):
        # Log the actual error for debugging
        import traceback
        app.logger.error(f"Internal Server Error: {e}")
        app.logger.error(traceback.format_exc())
        return {'error': 'Internal server error'}, 500

    # Context processor for templates
    @app.context_processor
    def inject_globals():
        from datetime import datetime
        return {
            'now': datetime.now(),
            'app_name': 'HookProbe Fortress',
            'app_version': '5.0.0'
        }

    return app


# Create the application instance
app = create_app()


if __name__ == '__main__':
    # Development server (use gunicorn in production)
    app.run(
        host='0.0.0.0',
        port=8443,
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
        ssl_context='adhoc'  # Self-signed cert for dev
    )
