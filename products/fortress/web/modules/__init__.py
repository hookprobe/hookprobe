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

    # Reports module - Business reports
    from .reports import reports_bp
    app.register_blueprint(reports_bp, url_prefix='/reports')

    # Settings module - System settings, user management
    from .settings import settings_bp
    app.register_blueprint(settings_bp, url_prefix='/settings')

    # API module - REST API endpoints
    from .api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
