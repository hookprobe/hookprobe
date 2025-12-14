"""
Fortress Tunnel Module - Cloudflare Tunnel management for remote access.

Provides setup wizard, status monitoring, and configuration for
exposing Fortress dashboard via a business subdomain.
"""

from flask import Blueprint

tunnel_bp = Blueprint(
    'tunnel',
    __name__,
    template_folder='../../templates/tunnel'
)

from . import views  # noqa: F401, E402
