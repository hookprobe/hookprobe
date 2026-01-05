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
from datetime import timedelta

from flask import Flask, redirect, url_for
from flask_login import LoginManager

from .config import Config


def create_app(config_class=Config):
    """Application factory for Fortress admin portal."""
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    app.config.from_object(config_class)

    # Secret key for sessions - from environment or generate random
    if not app.config.get('SECRET_KEY'):
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
        from .modules.auth.models import User
        return User.get(user_id)

    # Register blueprints
    from .modules import register_blueprints
    register_blueprints(app)

    # Root redirect
    @app.route('/')
    def index():
        return redirect(url_for('dashboard.index'))

    # Health check endpoint
    @app.route('/health')
    def health():
        return {'status': 'healthy', 'tier': 'fortress'}, 200

    # Global API status endpoint for sidebar polling
    @app.route('/api/status')
    def api_status():
        """Global status API for sidebar badges.

        Returns QSecBit status and device count for sidebar updates.
        Called by base.html every 10 seconds.
        """
        from flask_login import current_user
        from flask import jsonify

        # Return minimal data if not authenticated
        if not current_user.is_authenticated:
            return jsonify({'error': 'Not authenticated'}), 401

        # Get QSecBit status
        qsecbit = {'status': 'UNKNOWN', 'score': 0}
        device_count = 0
        notification_count = 0

        try:
            from .modules.dashboard.views import (
                get_qsecbit_stats,
                get_all_devices,
                get_recent_threats
            )

            # Get QSecBit stats
            stats = get_qsecbit_stats()
            qsecbit = {
                'status': stats.get('rag_status', 'GREEN'),
                'score': stats.get('score', 0)
            }

            # Get online device count from the same source as SDN page
            devices = get_all_devices()
            device_count = len([d for d in devices if d.get('is_online', False)])

            # Get notification count (recent threats)
            notification_count = len(get_recent_threats())

        except Exception as e:
            app.logger.error(f"API status error: {e}")

        return jsonify({
            'qsecbit': qsecbit,
            'device_count': device_count,
            'notification_count': notification_count
        })

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
            'app_version': '5.5.0'
        }

    # Template filters
    @app.template_filter('format_bytes')
    def format_bytes_filter(bytes_value):
        """Format bytes for human-readable display."""
        if not bytes_value or bytes_value == 0:
            return '0 B'
        try:
            bytes_value = int(bytes_value)
        except (ValueError, TypeError):
            return '0 B'
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024:
                return f'{bytes_value:.1f} {unit}'
            bytes_value /= 1024
        return f'{bytes_value:.1f} PB'

    # Sync NAC policies to OpenFlow on startup
    # OpenFlow rules are volatile - sync from persistent database
    with app.app_context():
        try:
            import sys
            sys.path.insert(0, '/opt/hookprobe/fortress/lib')
            from device_policies import sync_all_policies
            synced = sync_all_policies()
            app.logger.info(f"NAC startup: synced {synced} device policies to OpenFlow")
        except ImportError:
            app.logger.debug("device_policies not available - skipping NAC sync")
        except Exception as e:
            app.logger.warning(f"NAC startup sync failed: {e}")

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
