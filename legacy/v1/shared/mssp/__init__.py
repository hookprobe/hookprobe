"""HookProbe MSSP Client — Single-contract piggyback architecture."""

from .client import MSSPClient
from .types import Feedback, Finding, Recommendation
from .bootstrap import MSSPBootstrap
from .telemetry_collector import TelemetryCollector

__version__ = '3.0.0'

__all__ = [
    'MSSPClient', 'Finding', 'Recommendation', 'Feedback',
    'MSSPBootstrap', 'TelemetryCollector',
]
