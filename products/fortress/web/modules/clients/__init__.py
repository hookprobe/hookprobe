"""Fortress Clients Module"""
from flask import Blueprint
clients_bp = Blueprint('clients', __name__, template_folder='../../templates/clients')
from . import views  # noqa
