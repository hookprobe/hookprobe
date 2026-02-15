"""
NAPSE - Neural Adaptive Packet Synthesis Engine

HookProbe's proprietary IDS/NSM/IPS engine with a unified 3-layer
architecture optimized for resource-constrained edge devices.

Architecture:
    Layer 0: Kernel Fast Path (eBPF/XDP) - C
    Layer 1: Protocol Engine (Rust + PyO3) - conntrack, parsers, matcher, ML
    Layer 2: Event Synthesis (Python) - event routing to HookProbe stack

Author: HookProbe Team
License: Proprietary - see LICENSING.md
Version: 1.0.0
"""

__version__ = '1.0.0'
__codename__ = 'synapse'

# Tier definitions for resource scaling
TIER_SENTINEL = 'sentinel'   # 256MB - eBPF only
TIER_GUARDIAN = 'guardian'    # 1.5GB - core parsers
TIER_FORTRESS = 'fortress'   # 4GB   - full engine
TIER_NEXUS = 'nexus'         # 16GB+ - ML + advanced
