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
    app.register_blueprint(security_bp, url_prefix='/api')

    # dnsXai module - AI-powered ad blocking
    from .dnsxai import dnsxai_bp
    app.register_blueprint(dnsxai_bp, url_prefix='/api/dnsxai')

    # Config module - WiFi, network configuration
    from .config import config_bp
    app.register_blueprint(config_bp, url_prefix='/api/config')

    # Clients module - Connected devices
    from .clients import clients_bp
    app.register_blueprint(clients_bp, url_prefix='/api/clients')

    # VPN module - VPN management
    from .vpn import vpn_bp
    app.register_blueprint(vpn_bp, url_prefix='/api/vpn')

    # System module - System settings
    from .system import system_bp
    app.register_blueprint(system_bp, url_prefix='/api/system')

    # Cortex module - Neural Command Center integration
    from .cortex import cortex_bp
    app.register_blueprint(cortex_bp)

    # GitHub Update module - Pull updates via web UI
    from .github_update import github_update_bp
    app.register_blueprint(github_update_bp, url_prefix='/api/github')

    # Debug module - Browser-based CLI
    from .debug import debug_bp
    app.register_blueprint(debug_bp, url_prefix='/api/debug')
