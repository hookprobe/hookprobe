"""
HookProbe Sentinel Library

Modules:
    aegis_pico       — AEGIS-Pico (minimal AI security, no LLM)
    sentinel_agent   — Main agent daemon
    defense          — nftables/dnsmasq defense actions
    mesh_integration — Mesh gossip + microblock validation
"""

from .mesh_integration import SentinelMeshAgent, SentinelMeshConfig
from .aegis_pico import AegisPico
from .defense import SentinelDefenseEngine
from .sentinel_agent import SentinelAgent

__all__ = [
    "SentinelMeshAgent",
    "SentinelMeshConfig",
    "AegisPico",
    "SentinelDefenseEngine",
    "SentinelAgent",
]
