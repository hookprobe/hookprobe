"""
Fortress Web Modules
Blueprint registration and module management
"""
from flask import Flask


def register_blueprints(app: Flask):
    """Register all module blueprints with the Flask app."""

    # Auth module - Login, logout, user management
    from .auth import auth_bp
    app.register_blueprint(auth_bp)

    # Dashboard module - Main overview page
    from .dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)

    # Security module - QSecBit, threats, layer stats
    from .security import security_bp
    app.register_blueprint(security_bp, url_prefix='/security')

    # Clients module - Connected devices
    from .clients import clients_bp
    app.register_blueprint(clients_bp, url_prefix='/clients')

    # Networks module - VLAN configuration
    from .networks import networks_bp
    app.register_blueprint(networks_bp, url_prefix='/networks')

    # dnsXai module - AI-powered DNS protection
    from .dnsxai import dnsxai_bp
    app.register_blueprint(dnsxai_bp, url_prefix='/dnsxai')

    # Settings module - System settings, user management
    from .settings import settings_bp
    app.register_blueprint(settings_bp, url_prefix='/settings')

    # API module - REST API endpoints
    from .api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    # Tunnel module - Cloudflare Tunnel remote access
    from .tunnel import tunnel_bp
    app.register_blueprint(tunnel_bp, url_prefix='/tunnel')

    # SDN module - Unified Software-Defined Network management
    from .sdn import sdn_bp
    app.register_blueprint(sdn_bp, url_prefix='/sdn')
