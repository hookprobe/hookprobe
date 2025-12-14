"""Fortress Networks Module"""
from flask import Blueprint
networks_bp = Blueprint('networks', __name__, template_folder='../../templates/networks')
from . import views  # noqa
