"""
Core Module - Dashboard and Base Routes
"""
from flask import Blueprint

core_bp = Blueprint('core', __name__, template_folder='../../templates')

from . import views  # noqa: E402, F401
