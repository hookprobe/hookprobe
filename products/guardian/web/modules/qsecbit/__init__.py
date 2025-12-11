"""
Qsecbit Live Module - Real-time Qsecbit Unified Score Display

Provides a simple, focused view of the Qsecbit protection status
optimized for Raspberry Pi performance.
"""
from flask import Blueprint

qsecbit_bp = Blueprint('qsecbit', __name__, url_prefix='/qsecbit')

from . import views  # noqa: E402, F401
