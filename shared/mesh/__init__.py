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
- NAT/CGNAT traversal with STUN/ICE/TURN
- Emergent relay network for mesh continuity
- Mesh promotion protocol when cloud coordinator unavailable
- Tunnel integration (Cloudflare, ngrok, Tailscale) for public FQDN without public IP
"""

from .port_manager import PortManager, PortConfig, TransportMode
from .resilient_channel import ResilientChannel, ChannelState, ChannelMetrics
from .unified_transport import UnifiedTransport, MeshPacket, PacketType
from .neuro_encoder import NeuroResonanceEncoder, ResonanceState
from .channel_selector import ChannelSelector, SelectionStrategy
from .consciousness import (
    MeshConsciousness,
    TierRole,
    ConsciousnessState,
    ThreatIntelligence,
    ThreatCache,
    PeerNode,
    create_consciousness,
)
from .nat_traversal import (
    NATType,
    ConnectivityType,
    MeshPromotion,
    STUNClient,
    STUNResult,
    ICEAgent,
    ICECandidate,
    UDPHolePuncher,
    MeshPromotionManager,
    RendezvousPoint,
    NATTraversalManager,
    PeerEndpoint,
    PromotedNode,
)
from .relay import (
    RelayServer,
    RelayClient,
    RelayNetwork,
    RelayNodeInfo,
    RelayStats,
)
from .tunnel import (
    TunnelProvider,
    TunnelStatus,
    RegistrationStatus,
    TunnelEndpoint,
    TunnelConfig,
    TunnelManager,
    TunnelRegistry,
    TunnelRegistrationClient,
)

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
    # Consciousness
    'MeshConsciousness',
    'TierRole',
    'ConsciousnessState',
    'ThreatIntelligence',
    'ThreatCache',
    'PeerNode',
    'create_consciousness',
    # NAT Traversal
    'NATType',
    'ConnectivityType',
    'MeshPromotion',
    'STUNClient',
    'STUNResult',
    'ICEAgent',
    'ICECandidate',
    'UDPHolePuncher',
    'MeshPromotionManager',
    'RendezvousPoint',
    'NATTraversalManager',
    'PeerEndpoint',
    'PromotedNode',
    # Relay
    'RelayServer',
    'RelayClient',
    'RelayNetwork',
    'RelayNodeInfo',
    'RelayStats',
    # Tunnel
    'TunnelProvider',
    'TunnelStatus',
    'RegistrationStatus',
    'TunnelEndpoint',
    'TunnelConfig',
    'TunnelManager',
    'TunnelRegistry',
    'TunnelRegistrationClient',
]

__version__ = '5.0.0'
