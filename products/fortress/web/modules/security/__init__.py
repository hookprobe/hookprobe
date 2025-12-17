"""Fortress Security Module"""
from flask import Blueprint
security_bp = Blueprint('security', __name__)
from . import views  # noqa
