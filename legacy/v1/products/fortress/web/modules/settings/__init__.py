"""Fortress Settings Module"""
from flask import Blueprint
settings_bp = Blueprint('settings', __name__)
from . import views  # noqa
