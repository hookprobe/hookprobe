"""Fortress Settings Module"""
from flask import Blueprint
settings_bp = Blueprint('settings', __name__, template_folder='../../templates/settings')
from . import views  # noqa
