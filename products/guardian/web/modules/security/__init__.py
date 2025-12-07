"""
Security Module - QSecBit, Threats, Layer Stats
"""
from flask import Blueprint

security_bp = Blueprint('security', __name__, template_folder='../../templates')

from . import views  # noqa: E402, F401
