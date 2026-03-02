#!/usr/bin/env python3
"""
HookProbe Guardian - Local Web UI

Modular Flask application with Blueprint architecture.
Production: gunicorn with self-signed TLS on https://192.168.4.1:8080
Development: Flask dev server on http://0.0.0.0:8080

Version: 5.5.0 - HTTPS + gunicorn + Security Hardening
"""

import os
import subprocess
from datetime import timedelta
from pathlib import Path
from flask import Flask, send_file

from config import Config
from modules import register_blueprints

# TLS certificate paths
TLS_CERT_DIR = Path('/etc/hookprobe/tls')
TLS_CERT_FILE = TLS_CERT_DIR / 'guardian.crt'
TLS_KEY_FILE = TLS_CERT_DIR / 'guardian.key'


# Routes exempt from authentication (login page, static assets, health)
AUTH_EXEMPT_PREFIXES = ('/auth/', '/static/', '/favicon.ico', '/logo.png')


def create_app(config_class=Config):
    """Application factory for Guardian web UI."""
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    app.config.from_object(config_class)

    # Persistent secret key (survives restarts)
    secret_key = _load_secret_key()
    app.config['SECRET_KEY'] = secret_key

    # Session configuration - 8 hours max
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

    # Enable secure cookies when TLS is available
    if TLS_CERT_FILE.exists() and TLS_KEY_FILE.exists():
        app.config['SESSION_COOKIE_SECURE'] = True

    # Register all blueprints
    register_blueprints(app)

    # Global auth gate — protects ALL routes except auth and static
    @app.before_request
    def enforce_authentication():
        """Require authentication for all non-exempt routes."""
        from flask import session, request, redirect, url_for, jsonify

        path = request.path
        if any(path.startswith(p) for p in AUTH_EXEMPT_PREFIXES):
            return None
        if session.get('authenticated'):
            return None
        # API requests get 401 JSON
        is_api = (
            path.startswith('/api/')
            or request.accept_mimetypes.best == 'application/json'
        )
        if is_api:
            return jsonify({'error': 'Authentication required'}), 401
        return redirect(url_for('auth.login_page'))

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

    # Security response headers (OWASP recommendations)
    @app.after_request
    def set_security_headers(response):
        """Add security headers to all responses."""
        # Prevent MIME-type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        # Control referrer leakage
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Disable dangerous browser features
        response.headers['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=(), usb=()'
        )
        # Content Security Policy — allow inline scripts/styles (templates use
        # onclick handlers and inline <script> blocks extensively).
        # FontAwesome CDN is allowed for style/font when internet is available.
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "connect-src 'self'; "
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        # HSTS — enforce HTTPS for 1 year (only when TLS is active)
        if TLS_CERT_FILE.exists():
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains'
            )
        # Prevent caching of authenticated pages
        if response.status_code == 200 and response.content_type.startswith('text/html'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
        return response

    # Wire AEGIS-Lite for signal processing
    _init_aegis_lite(app)

    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        return {'error': 'Not found'}, 404

    @app.errorhandler(500)
    def server_error(e):
        return {'error': 'Internal server error'}, 500

    return app


def _init_aegis_lite(app):
    """Initialize AEGIS-Lite and start MSSP heartbeats if provisioned."""
    import sys
    import threading

    # Ensure lib/ is importable (deployed layout: web/ is cwd, lib/ is sibling)
    lib_dir = str(Path(__file__).resolve().parent.parent / 'lib')
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)

    try:
        try:
            from products.guardian.lib.aegis_lite import AegisLite
        except ImportError:
            from aegis_lite import AegisLite

        aegis = AegisLite()
        if aegis.initialize():
            app.extensions['aegis_lite'] = aegis
            aegis.start()
            app.logger.info("AEGIS-Lite initialized and MSSP heartbeat started")
        else:
            app.logger.warning("AEGIS-Lite initialization returned False")
    except ImportError:
        app.logger.debug("AEGIS-Lite not available (missing dependencies)")
    except Exception as e:
        app.logger.warning("AEGIS-Lite init error: %s", e)

    # Background claim poller — if there's a pending claim, poll until resolved
    def _background_claim_poll():
        import time
        try:
            from shared.mssp.bootstrap import MSSPBootstrap
            bootstrap = MSSPBootstrap(product_type='guardian')
            state = bootstrap.get_provision_state()
            if state['status'] != 'pending_claim':
                return  # Nothing to poll

            provision_id = state.get('provision_id', '')
            if not provision_id:
                return

            app.logger.info("Background claim poll starting (provision_id=%s)", provision_id[:8])
            for _ in range(180):  # 15 minutes max (180 * 5s)
                time.sleep(5)
                try:
                    result = bootstrap.check_claim_status(provision_id)
                    if result.get('claimed'):
                        app.logger.info("MSSP claim completed — reloading AegisLite")
                        # Re-init AegisLite with the new API key
                        try:
                            try:
                                from products.guardian.lib.aegis_lite import AegisLite as AL
                            except ImportError:
                                from aegis_lite import AegisLite as AL
                            aegis = AL()
                            if aegis.initialize():
                                app.extensions['aegis_lite'] = aegis
                                aegis.start()
                                app.logger.info("AEGIS-Lite restarted with MSSP API key")
                        except Exception as e:
                            app.logger.warning("AegisLite re-init after claim: %s", e)
                        return
                except Exception:
                    pass  # Network errors, keep polling
        except Exception:
            pass

    thread = threading.Thread(target=_background_claim_poll, daemon=True)
    thread.start()


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


def ensure_tls_cert():
    """Generate self-signed TLS certificate if not present."""
    if TLS_CERT_FILE.exists() and TLS_KEY_FILE.exists():
        return True

    try:
        TLS_CERT_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'ec',
            '-pkeyopt', 'ec_paramgen_curve:prime256v1',
            '-keyout', str(TLS_KEY_FILE),
            '-out', str(TLS_CERT_FILE),
            '-days', '3650',
            '-nodes',
            '-subj', '/CN=guardian.local/O=HookProbe/OU=Guardian',
            '-addext', 'subjectAltName=DNS:guardian.local,IP:192.168.4.1,IP:127.0.0.1',
        ], check=True, capture_output=True, timeout=30)
        os.chmod(str(TLS_KEY_FILE), 0o600)
        os.chmod(str(TLS_CERT_FILE), 0o644)
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error("Failed to generate TLS cert: %s", e)
        return False


# Create the application instance
app = create_app()


if __name__ == '__main__':
    port = int(os.environ.get('GUARDIAN_PORT', '8080'))
    use_dev_server = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    if use_dev_server:
        # Development: Flask dev server (no TLS)
        app.run(host='0.0.0.0', port=port, debug=use_dev_server)
    else:
        # Production: self-signed TLS + gunicorn (or Flask TLS fallback)
        ensure_tls_cert()

        try:
            # Prefer gunicorn for production
            subprocess.run([
                'gunicorn',
                '--bind', f'0.0.0.0:{port}',
                '--workers', '2',
                '--threads', '4',
                '--timeout', '120',
                '--certfile', str(TLS_CERT_FILE),
                '--keyfile', str(TLS_KEY_FILE),
                '--access-logfile', '/var/log/hookprobe/guardian-web-access.log',
                '--error-logfile', '/var/log/hookprobe/guardian-web-error.log',
                'app:app',
            ], check=True)
        except FileNotFoundError:
            # Fallback: Flask with SSL context
            ssl_ctx = None
            if TLS_CERT_FILE.exists() and TLS_KEY_FILE.exists():
                ssl_ctx = (str(TLS_CERT_FILE), str(TLS_KEY_FILE))
            app.run(host='0.0.0.0', port=port, ssl_context=ssl_ctx)
