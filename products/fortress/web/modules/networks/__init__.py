"""Fortress Networks Module"""
from flask import Blueprint
networks_bp = Blueprint('networks', __name__)
from . import views  # noqa
