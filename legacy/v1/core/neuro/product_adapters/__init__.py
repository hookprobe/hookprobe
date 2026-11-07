"""
HookProbe Product-Tier NSE Adapters

Neural Synaptic Encryption integration for all product tiers.
Each adapter is optimized for the resource constraints and capabilities
of its target tier.

"One node's detection → Everyone's protection"

Product Tiers:
- Sentinel (256MB): Lightweight validation, minimal memory footprint
- Guardian (1.5GB): Full NSE client with neural key derivation
- Fortress (4GB): NSE routing and relay capabilities
- Nexus (16GB+): ML training and weight evolution
"""

from .sentinel import SentinelNSEAdapter
from .guardian import GuardianNSEAdapter
from .fortress import FortressNSEAdapter
from .nexus import NexusNSEAdapter

__all__ = [
    'SentinelNSEAdapter',
    'GuardianNSEAdapter',
    'FortressNSEAdapter',
    'NexusNSEAdapter',
]
