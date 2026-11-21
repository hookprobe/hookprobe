"""
VPN Module - VPN Management
"""
from flask import Blueprint

vpn_bp = Blueprint('vpn', __name__, template_folder='../../templates')

from . import views  # noqa: E402, F401
