"""
Fortress Authentication Module
"""
from flask import Blueprint

auth_bp = Blueprint('auth', __name__, template_folder='../../templates/auth')

from . import views  # noqa: E402, F401
