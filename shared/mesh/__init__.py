"""
HookProbe Decentralized Security Mesh (DSM) - Unified Communication Architecture

This module provides a resilient, multi-layer communication stack that integrates:
- DSM (Decentralized Security Mesh): Byzantine fault-tolerant consensus
- Neuro (Neural Resonance Protocol): Weight-based authentication
- HTP (HookProbe Transport Protocol): Keyless adaptive transport

Key Features:
- Multi-port fallback (8144 → 443 → 853)
- Stealth mode with traffic obfuscation
- Neural resonance encoding for channel authentication
- Automatic channel switching on blocking detection
"""

from .port_manager import PortManager, PortConfig, TransportMode
from .resilient_channel import ResilientChannel, ChannelState, ChannelMetrics
from .unified_transport import UnifiedTransport, MeshPacket, PacketType
from .neuro_encoder import NeuroResonanceEncoder, ResonanceState
from .channel_selector import ChannelSelector, SelectionStrategy

__all__ = [
    # Port Management
    'PortManager',
    'PortConfig',
    'TransportMode',
    # Channel Management
    'ResilientChannel',
    'ChannelState',
    'ChannelMetrics',
    # Unified Transport
    'UnifiedTransport',
    'MeshPacket',
    'PacketType',
    # Neuro Encoding
    'NeuroResonanceEncoder',
    'ResonanceState',
    # Channel Selection
    'ChannelSelector',
    'SelectionStrategy',
]

__version__ = '5.0.0'
