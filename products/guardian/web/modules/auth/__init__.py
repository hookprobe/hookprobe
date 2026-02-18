"""
Guardian Authentication Module

PIN-based authentication for the Guardian web UI.
Lightweight auth suitable for embedded deployment on RPi4.

Usage:
    from modules.auth import auth_bp, require_auth

    @some_bp.route('/sensitive')
    @require_auth
    def sensitive_endpoint():
        ...
"""
from .views import auth_bp
from .decorators import require_auth

__all__ = ['auth_bp', 'require_auth']
