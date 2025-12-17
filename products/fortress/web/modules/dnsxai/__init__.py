"""Fortress dnsXai Module"""
from flask import Blueprint
dnsxai_bp = Blueprint('dnsxai', __name__)
from . import views  # noqa
