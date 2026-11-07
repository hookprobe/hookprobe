"""
Clients Module - Connected Devices Management
"""
from flask import Blueprint

clients_bp = Blueprint('clients', __name__, template_folder='../../templates')

from . import views  # noqa: E402, F401
