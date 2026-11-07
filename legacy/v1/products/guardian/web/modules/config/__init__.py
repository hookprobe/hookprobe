"""
Config Module - WiFi, Network Configuration
"""
from flask import Blueprint

config_bp = Blueprint('config', __name__, template_folder='../../templates')

from . import views  # noqa: E402, F401
