"""
System Module - System Settings and Management
"""
from flask import Blueprint

system_bp = Blueprint('system', __name__, template_folder='../../templates')

from . import views  # noqa: E402, F401
