"""
Fortress VPN & Mesh Module - HTP tunnel and mesh peer management.
"""

from flask import Blueprint

vpn_bp = Blueprint('vpn', __name__, url_prefix='/vpn')

from . import views  # noqa: E402, F401
