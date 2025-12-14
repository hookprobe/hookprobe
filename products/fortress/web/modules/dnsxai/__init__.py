"""Fortress dnsXai Module"""
from flask import Blueprint
dnsxai_bp = Blueprint('dnsxai', __name__, template_folder='../../templates/dnsxai')
from . import views  # noqa
