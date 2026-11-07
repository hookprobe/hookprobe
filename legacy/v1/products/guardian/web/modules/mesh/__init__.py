"""
Mesh Module - HTP/Neuro/NSE Mesh Status for Guardian

Provides mesh daemon status, peer list, and MSSP connection info.
"""
from flask import Blueprint

mesh_bp = Blueprint('mesh', __name__)

from . import views  # noqa: E402, F401
