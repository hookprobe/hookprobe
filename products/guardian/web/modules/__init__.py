"""
Guardian Web Modules
Blueprint registration and module management
"""
from flask import Flask


def register_blueprints(app: Flask):
    """Register all module blueprints with the Flask app."""

    # Core module - Dashboard and base routes
    from .core import core_bp
    app.register_blueprint(core_bp)

    # Security module - QSecBit, threats, layer stats
    from .security import security_bp
    app.register_blueprint(security_bp, url_prefix='/security')

    # dnsXai module - AI-powered ad blocking
    from .dnsxai import dnsxai_bp
    app.register_blueprint(dnsxai_bp, url_prefix='/dnsxai')

    # Config module - WiFi, network configuration
    from .config import config_bp
    app.register_blueprint(config_bp, url_prefix='/config')

    # Clients module - Connected devices
    from .clients import clients_bp
    app.register_blueprint(clients_bp, url_prefix='/clients')

    # VPN module - VPN management
    from .vpn import vpn_bp
    app.register_blueprint(vpn_bp, url_prefix='/vpn')

    # System module - System settings
    from .system import system_bp
    app.register_blueprint(system_bp, url_prefix='/system')
