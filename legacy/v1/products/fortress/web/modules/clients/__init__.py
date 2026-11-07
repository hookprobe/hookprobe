"""Fortress Clients Module"""
from flask import Blueprint
clients_bp = Blueprint('clients', __name__)
from . import views  # noqa
