"""
NAPSE - Neural Adaptive Packet Synthesis Engine

HookProbe's proprietary IDS/NSM/IPS engine with a split-brain
architecture optimized for resource-constrained edge devices.

Architecture:
    Layer 0: Kernel Fast Path - Zig Aegis (XDP/eBPF) + C kernel programs
    Layer 1: Classification   - Mojo brain (SIMD) -> Python Inspector (fallback)
    Layer 2: Event Synthesis  - Python event routing to HookProbe stack

Data flow:
    NIC -> Aegis (Zig/XDP) -> Ring Buffer -> Napse (Mojo/SIMD) -> Event Bus
                                                                 -> ClickHouse

Author: HookProbe Team
License: Proprietary - see LICENSING.md
Version: 2.0.0
"""

__version__ = '2.0.0'
__codename__ = 'synapse'

# Tier definitions for resource scaling
TIER_SENTINEL = 'sentinel'   # 256MB - eBPF only
TIER_GUARDIAN = 'guardian'    # 1.5GB - core parsers
TIER_FORTRESS = 'fortress'   # 4GB   - full engine
TIER_NEXUS = 'nexus'         # 16GB+ - ML + advanced
