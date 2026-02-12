"""
AEGIS - AI-Enhanced Guardian Intelligence System

Phase 1: ORACLE Agent - Status, Q&A, and Advisory
Native local LLM-powered cybersecurity assistant for Fortress.
"""

from .types import (
    ChatMessage,
    ChatResponse,
    AegisStatus,
    NetworkSummary,
    ThreatSummary,
    DeviceInfo,
)
from .client import AegisClient, get_aegis_client
from .inference import NativeInferenceEngine, get_inference_engine

__all__ = [
    "ChatMessage",
    "ChatResponse",
    "AegisStatus",
    "NetworkSummary",
    "ThreatSummary",
    "DeviceInfo",
    "AegisClient",
    "get_aegis_client",
    "NativeInferenceEngine",
    "get_inference_engine",
]
