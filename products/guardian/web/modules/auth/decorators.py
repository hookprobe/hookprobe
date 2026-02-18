"""
Authentication decorators for Guardian web UI.

Provides @require_auth for protecting endpoints.
"""
from functools import wraps
from flask import session, jsonify, request, redirect, url_for


def require_auth(f):
    """Decorator to require authentication on an endpoint.

    For API endpoints (Accept: application/json or /api/ prefix),
    returns 401 JSON. For page routes, redirects to login.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            # Check if this is an API request
            is_api = (
                request.path.startswith('/api/')
                or request.accept_mimetypes.best == 'application/json'
            )
            if is_api:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login_page'))
        return f(*args, **kwargs)
    return decorated
