"""
AEGIS Module - AI Security Assistant for Guardian

Provides chat, status, and recommendation endpoints for AEGIS-Lite.
"""
from flask import Blueprint

aegis_bp = Blueprint('aegis', __name__)

from . import views  # noqa: E402, F401
