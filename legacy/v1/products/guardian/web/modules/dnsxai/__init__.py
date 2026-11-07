"""
dnsXai Module - AI-powered DNS Protection
"""
from flask import Blueprint

dnsxai_bp = Blueprint('dnsxai', __name__, template_folder='../../templates')

from . import views  # noqa: E402, F401
