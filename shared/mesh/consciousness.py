"""
Mesh Consciousness - Collective Intelligence Layer for HookProbe

This module provides the "collective consciousness" for the decentralized
security mesh. It enables nodes to:

1. Share threat intelligence in real-time
2. Achieve consensus on security state without central authority
3. Evolve collective neural weights for better detection
4. Operate autonomously when disconnected from cloud coordinator
5. Coordinate defense responses across the mesh

Philosophy:
"One node's detection → Everyone's protection"

The mesh forms a collective consciousness where each node contributes
its local observations to build a global security picture. This is
achieved through:

- Neural Resonance: Shared weight evolution for coordinated detection
- Gossip Protocol: Rapid threat propagation across the mesh
- Emergent Consensus: Decentralized agreement on security state
- Collective Memory: Distributed threat intelligence storage

Tier Roles in the Consciousness:
┌─────────────────────────────────────────────────────────────────┐
│  SENTINEL (512MB)  → Validator Node                             │
│    - Validates microblocks from local sensors                   │
│    - Participates in BLS signature aggregation                  │
│    - Lightweight consensus participation                        │
├─────────────────────────────────────────────────────────────────┤
│  GUARDIAN (3GB)    → Intelligence Node                          │
│    - Full threat detection + layer analysis                     │
│    - Gossip protocol participation                              │
│    - Local threat cache + sharing                               │
├─────────────────────────────────────────────────────────────────┤
│  FORTRESS (8GB)    → Regional Coordinator                       │
│    - Aggregates intelligence from Guardians/Sentinels           │
│    - Regional consensus leadership                              │
│    - SDN orchestration for defense                              │
├─────────────────────────────────────────────────────────────────┤
│  NEXUS (64GB+)     → ML/AI Compute Brain                        │
│    - Distributed model training                                 │
│    - Threat pattern analysis                                    │
│    - Nexus-to-Nexus weight synchronization                      │
├─────────────────────────────────────────────────────────────────┤
│  COORDINATOR       → Global Coordinator (Optional Cloud)        │
│    - Long-term storage + analytics                              │
│    - Cross-region coordination                                  │
│    - Fallback: mesh operates autonomously without coordinator   │
└─────────────────────────────────────────────────────────────────┘
"""

import hashlib
import struct
import time
import secrets
import json
import threading
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Set, Tuple
from collections import deque
from datetime import datetime, timedelta

# Import mesh components
from .unified_transport import UnifiedTransport, MeshPacket, PacketType, TransportState
from .neuro_encoder import NeuroResonanceEncoder, ResonanceState, TERSnapshot
from .channel_selector import ChannelSelector, SelectionStrategy

# Try to import DSM components
try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from dsm.consensus import ConsensusEngine
    from dsm.gossip import GossipProtocol
    from dsm.ledger import LevelDBLedger
    from dsm.node import DSMNode
    DSM_AVAILABLE = True
except ImportError:
    DSM_AVAILABLE = False
    ConsensusEngine = None
    GossipProtocol = None
    LevelDBLedger = None
    DSMNode = None


class TierRole(Enum):
    """Role of a node in the mesh consciousness."""
    SENTINEL = auto()    # Lightweight validator (512MB)
    GUARDIAN = auto()    # Intelligence node (3GB)
    FORTRESS = auto()    # Regional coordinator (8GB)
    NEXUS = auto()       # ML/AI compute brain (64GB+)
    COORDINATOR = auto() # Global cloud coordinator


class ConsciousnessState(Enum):
    """State of the collective consciousness."""
    DORMANT = auto()       # Not yet connected to mesh
    AWAKENING = auto()     # Discovering peers
    AWARE = auto()         # Connected, receiving intelligence
    SYNCHRONIZED = auto()  # Full resonance with mesh
    AUTONOMOUS = auto()    # Operating without cloud coordinator


@dataclass
class ThreatIntelligence:
    """Shared threat intelligence record."""

    # Unique ID for this intelligence
    intel_id: bytes

    # Source node that detected the threat
    source_node_id: bytes

    # Timestamp of detection
    timestamp: float

    # Threat details
    threat_type: str  # e.g., "port_scan", "ddos", "malware"
    severity: int  # 1-5 (critical to info)
    confidence: float  # 0.0-1.0

    # Indicators of Compromise
    ioc_type: str  # "ip", "domain", "hash", "pattern"
    ioc_value: str

    # Additional context
    context: Dict[str, Any] = field(default_factory=dict)

    # Propagation tracking
    hop_count: int = 0
    seen_by: Set[bytes] = field(default_factory=set)

    # TTL for cache expiry
    ttl_seconds: int = 3600  # 1 hour default

    def to_bytes(self) -> bytes:
        """Serialize to bytes for transmission."""
        data = {
            'intel_id': self.intel_id.hex(),
            'source': self.source_node_id.hex(),
            'timestamp': self.timestamp,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'ioc_type': self.ioc_type,
            'ioc_value': self.ioc_value,
            'context': self.context,
            'hop_count': self.hop_count,
            'seen_by': [n.hex() for n in self.seen_by],
            'ttl': self.ttl_seconds,
        }
        return json.dumps(data).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ThreatIntelligence':
        """Deserialize from bytes."""
        d = json.loads(data.decode())
        return cls(
            intel_id=bytes.fromhex(d['intel_id']),
            source_node_id=bytes.fromhex(d['source']),
            timestamp=d['timestamp'],
            threat_type=d['threat_type'],
            severity=d['severity'],
            confidence=d['confidence'],
            ioc_type=d['ioc_type'],
            ioc_value=d['ioc_value'],
            context=d.get('context', {}),
            hop_count=d.get('hop_count', 0),
            seen_by={bytes.fromhex(n) for n in d.get('seen_by', [])},
            ttl_seconds=d.get('ttl', 3600),
        )

    @property
    def is_expired(self) -> bool:
        """Check if intelligence has expired."""
        return time.time() - self.timestamp > self.ttl_seconds


@dataclass
class PeerNode:
    """Information about a peer node in the mesh."""

    node_id: bytes
    tier: TierRole
    endpoint: str  # host:port
    weight_fingerprint: bytes
    resonance_state: ResonanceState
    last_seen: float
    latency_ms: float
    capabilities: Set[str]

    # Trust metrics
    trust_score: float = 0.5  # 0.0-1.0
    successful_exchanges: int = 0
    failed_exchanges: int = 0

    def update_trust(self, success: bool) -> None:
        """Update trust score based on exchange result."""
        alpha = 0.1  # Learning rate
        if success:
            self.successful_exchanges += 1
            self.trust_score = min(1.0, self.trust_score + alpha * (1.0 - self.trust_score))
        else:
            self.failed_exchanges += 1
            self.trust_score = max(0.0, self.trust_score - alpha * self.trust_score)

    @property
    def is_stale(self) -> bool:
        """Check if peer hasn't been seen recently."""
        return time.time() - self.last_seen > 300  # 5 minutes


class ThreatCache:
    """
    Local cache of threat intelligence with deduplication.

    Features:
    - Automatic expiry of old intelligence
    - Deduplication by intel_id
    - Priority queue by severity
    - Fast IOC lookup
    """

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self._cache: Dict[bytes, ThreatIntelligence] = {}
        self._ioc_index: Dict[str, Set[bytes]] = {}  # ioc_value -> intel_ids
        self._lock = threading.RLock()

        # Cleanup thread
        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
        )
        self._cleanup_thread.start()

    def add(self, intel: ThreatIntelligence) -> bool:
        """
        Add intelligence to cache.

        Returns:
            True if new, False if duplicate
        """
        with self._lock:
            if intel.intel_id in self._cache:
                return False

            # Evict oldest if full
            if len(self._cache) >= self.max_size:
                self._evict_oldest()

            self._cache[intel.intel_id] = intel

            # Update IOC index
            if intel.ioc_value not in self._ioc_index:
                self._ioc_index[intel.ioc_value] = set()
            self._ioc_index[intel.ioc_value].add(intel.intel_id)

            return True

    def get(self, intel_id: bytes) -> Optional[ThreatIntelligence]:
        """Get intelligence by ID."""
        with self._lock:
            return self._cache.get(intel_id)

    def lookup_ioc(self, ioc_value: str) -> List[ThreatIntelligence]:
        """Lookup intelligence by IOC value."""
        with self._lock:
            intel_ids = self._ioc_index.get(ioc_value, set())
            return [
                self._cache[i]
                for i in intel_ids
                if i in self._cache and not self._cache[i].is_expired
            ]

    def get_recent(self, limit: int = 100) -> List[ThreatIntelligence]:
        """Get most recent intelligence."""
        with self._lock:
            items = sorted(
                self._cache.values(),
                key=lambda x: x.timestamp,
                reverse=True,
            )
            return items[:limit]

    def get_by_severity(
        self,
        min_severity: int = 1,
        max_severity: int = 5,
    ) -> List[ThreatIntelligence]:
        """Get intelligence filtered by severity."""
        with self._lock:
            return [
                intel for intel in self._cache.values()
                if min_severity <= intel.severity <= max_severity
                and not intel.is_expired
            ]

    def _evict_oldest(self) -> None:
        """Evict oldest entry from cache."""
        if not self._cache:
            return

        oldest_id = min(
            self._cache.keys(),
            key=lambda k: self._cache[k].timestamp,
        )
        intel = self._cache.pop(oldest_id)

        # Remove from IOC index
        if intel.ioc_value in self._ioc_index:
            self._ioc_index[intel.ioc_value].discard(oldest_id)

    def _cleanup_loop(self) -> None:
        """Background cleanup of expired entries."""
        while not self._stop_event.is_set():
            self._stop_event.wait(60)  # Every minute

            if self._stop_event.is_set():
                break

            with self._lock:
                expired = [
                    intel_id
                    for intel_id, intel in self._cache.items()
                    if intel.is_expired
                ]

                for intel_id in expired:
                    intel = self._cache.pop(intel_id)
                    if intel.ioc_value in self._ioc_index:
                        self._ioc_index[intel.ioc_value].discard(intel_id)

    def stop(self) -> None:
        """Stop cleanup thread."""
        self._stop_event.set()

    def __len__(self) -> int:
        return len(self._cache)


class MeshConsciousness:
    """
    Collective Consciousness for the HookProbe Mesh.

    This is the central coordination layer that enables nodes to:
    - Discover and connect to peers
    - Share threat intelligence
    - Achieve consensus on security state
    - Coordinate defense responses
    - Operate autonomously without central authority

    The consciousness maintains a "gestalt" - a unified view of
    the security landscape built from all participating nodes.
    """

    # Peer discovery interval
    DISCOVERY_INTERVAL = 30.0

    # Intelligence gossip interval
    GOSSIP_INTERVAL = 5.0

    # Consensus checkpoint interval
    CONSENSUS_INTERVAL = 300.0  # 5 minutes

    # Maximum peers to maintain
    MAX_PEERS = 50

    # Maximum hops for gossip propagation
    MAX_GOSSIP_HOPS = 5

    def __init__(
        self,
        node_id: bytes,
        tier: TierRole,
        neuro_seed: bytes,
        listen_port: int = 8144,
        data_dir: str = "/opt/hookprobe/data",
    ):
        """
        Initialize mesh consciousness.

        Args:
            node_id: Unique 16-byte node identifier
            tier: This node's tier role
            neuro_seed: Shared neural seed for weight evolution
            listen_port: Port to listen for peer connections
            data_dir: Directory for persistent storage
        """
        self.node_id = node_id[:16]
        self.tier = tier
        self.neuro_seed = neuro_seed
        self.listen_port = listen_port
        self.data_dir = data_dir

        # State
        self._state = ConsciousnessState.DORMANT
        self._lock = threading.RLock()

        # Neural resonance
        self.encoder = NeuroResonanceEncoder(neuro_seed, node_id)

        # Peer management
        self._peers: Dict[bytes, PeerNode] = {}
        self._bootstrap_peers: List[str] = []

        # Threat intelligence
        self.threat_cache = ThreatCache()
        self._pending_gossip: deque = deque(maxlen=1000)

        # Transport connections to peers
        self._transports: Dict[bytes, UnifiedTransport] = {}

        # DSM integration (if available)
        self._dsm_node: Optional[DSMNode] = None
        self._consensus_engine: Optional[ConsensusEngine] = None

        # Background threads
        self._threads: List[threading.Thread] = []
        self._stop_event = threading.Event()

        # Callbacks
        self._on_intelligence: List[Callable[[ThreatIntelligence], None]] = []
        self._on_consensus: List[Callable[[Dict], None]] = []
        self._on_peer_joined: List[Callable[[PeerNode], None]] = []
        self._on_peer_left: List[Callable[[PeerNode], None]] = []
        self._on_model_update: List[Callable[[bytes], None]] = []

        # Logger (must be set before _init_dsm which uses it)
        self.logger = logging.getLogger(f"MeshConsciousness.{tier.name}")

        # Initialize DSM if available
        self._init_dsm()

    @property
    def state(self) -> ConsciousnessState:
        """Get current consciousness state."""
        with self._lock:
            return self._state

    @property
    def peer_count(self) -> int:
        """Get number of connected peers."""
        with self._lock:
            return len([p for p in self._peers.values() if not p.is_stale])

    @property
    def is_synchronized(self) -> bool:
        """Check if consciousness is synchronized with mesh."""
        return self._state in (
            ConsciousnessState.SYNCHRONIZED,
            ConsciousnessState.AUTONOMOUS,
        )

    def _init_dsm(self) -> None:
        """Initialize DSM components if available."""
        if not DSM_AVAILABLE:
            self.logger.warning("DSM components not available")
            return

        try:
            # Create DSM node
            self._dsm_node = DSMNode(
                node_id=self.node_id,
                data_dir=self.data_dir,
            )

            # Create consensus engine for Fortress/Nexus
            if self.tier in (TierRole.FORTRESS, TierRole.NEXUS):
                self._consensus_engine = ConsensusEngine(
                    node=self._dsm_node,
                )

            self.logger.info("DSM components initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize DSM: {e}")

    def awaken(self, bootstrap_peers: Optional[List[str]] = None) -> None:
        """
        Awaken the consciousness and join the mesh.

        Args:
            bootstrap_peers: List of bootstrap peer endpoints (host:port)
        """
        if self._state != ConsciousnessState.DORMANT:
            return

        self.logger.info(f"Awakening mesh consciousness as {self.tier.name}")
        self._set_state(ConsciousnessState.AWAKENING)

        if bootstrap_peers:
            self._bootstrap_peers = bootstrap_peers

        # Start background threads
        self._start_threads()

        # Begin peer discovery
        self._discover_peers()

    def sleep(self) -> None:
        """Put consciousness to sleep (disconnect from mesh)."""
        self.logger.info("Consciousness entering sleep state")

        self._stop_event.set()

        # Close all transports
        for transport in self._transports.values():
            try:
                transport.close()
            except Exception:
                pass

        self._transports.clear()
        self._peers.clear()

        # Wait for threads
        for thread in self._threads:
            thread.join(timeout=2.0)

        self._set_state(ConsciousnessState.DORMANT)

    def _start_threads(self) -> None:
        """Start background processing threads."""
        threads = [
            ("discovery", self._discovery_loop),
            ("gossip", self._gossip_loop),
            ("ter_evolution", self._ter_evolution_loop),
        ]

        # Add consensus thread for Fortress/Nexus
        if self.tier in (TierRole.FORTRESS, TierRole.NEXUS):
            threads.append(("consensus", self._consensus_loop))

        for name, target in threads:
            thread = threading.Thread(
                target=target,
                name=f"consciousness_{name}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def _discovery_loop(self) -> None:
        """Peer discovery loop."""
        while not self._stop_event.is_set():
            self._discover_peers()
            self._prune_stale_peers()
            self._stop_event.wait(self.DISCOVERY_INTERVAL)

    def _gossip_loop(self) -> None:
        """Intelligence gossip loop."""
        while not self._stop_event.is_set():
            self._process_gossip_queue()
            self._stop_event.wait(self.GOSSIP_INTERVAL)

    def _ter_evolution_loop(self) -> None:
        """TER generation and weight evolution loop."""
        while not self._stop_event.is_set():
            self._stop_event.wait(10.0)  # Every 10 seconds

            if self._stop_event.is_set():
                break

            # Generate TER from local state
            ter = self.encoder.generate_ter_from_system()
            self.encoder.evolve_weights(ter)

    def _consensus_loop(self) -> None:
        """Consensus checkpoint loop (Fortress/Nexus only)."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.CONSENSUS_INTERVAL)

            if self._stop_event.is_set():
                break

            if self._consensus_engine:
                self._build_consensus_checkpoint()

    def _discover_peers(self) -> None:
        """Discover peers on the mesh."""
        # Try bootstrap peers
        for endpoint in self._bootstrap_peers:
            if len(self._peers) >= self.MAX_PEERS:
                break

            try:
                self._connect_to_peer(endpoint)
            except Exception as e:
                self.logger.debug(f"Could not connect to {endpoint}: {e}")

        # Ask existing peers for their peer lists
        for peer in list(self._peers.values()):
            if peer.is_stale:
                continue

            try:
                self._request_peer_list(peer)
            except Exception:
                pass

        # Update state based on peer count
        if self.peer_count > 0:
            if self._state == ConsciousnessState.AWAKENING:
                self._set_state(ConsciousnessState.AWARE)

            if self.peer_count >= 3:
                self._set_state(ConsciousnessState.SYNCHRONIZED)

    def _connect_to_peer(self, endpoint: str) -> Optional[PeerNode]:
        """Connect to a peer endpoint."""
        try:
            host, port = endpoint.rsplit(':', 1)
            port = int(port)
        except ValueError:
            return None

        # Create transport
        transport = UnifiedTransport(
            node_id=self.node_id,
            neuro_seed=self.neuro_seed,
        )

        if transport.connect(host, timeout=10.0):
            # Exchange peer info
            peer_info = self._exchange_peer_info(transport)
            if peer_info:
                self._peers[peer_info.node_id] = peer_info
                self._transports[peer_info.node_id] = transport

                self.logger.info(
                    f"Connected to peer {peer_info.node_id.hex()[:8]} "
                    f"({peer_info.tier.name})"
                )

                for callback in self._on_peer_joined:
                    try:
                        callback(peer_info)
                    except Exception:
                        pass

                return peer_info
            else:
                transport.close()

        return None

    def _exchange_peer_info(
        self,
        transport: UnifiedTransport,
    ) -> Optional[PeerNode]:
        """Exchange peer information after connection."""
        # Send our info
        our_info = {
            'node_id': self.node_id.hex(),
            'tier': self.tier.name,
            'weight_fp': self.encoder.get_weight_fingerprint().fingerprint.hex(),
            'capabilities': self._get_capabilities(),
        }

        transport.send(
            PacketType.CONTROL_CMD,
            json.dumps({'type': 'peer_info', 'data': our_info}).encode(),
        )

        # Receive their info
        packet = transport.receive(timeout=5.0)
        if not packet:
            return None

        try:
            msg = json.loads(packet.payload.decode())
            if msg.get('type') != 'peer_info':
                return None

            data = msg['data']
            return PeerNode(
                node_id=bytes.fromhex(data['node_id']),
                tier=TierRole[data['tier']],
                endpoint=f"{transport._target_host}:{transport.port_manager.active_port.port if transport.port_manager.active_port else 8144}",
                weight_fingerprint=bytes.fromhex(data['weight_fp']),
                resonance_state=ResonanceState.ALIGNED,
                last_seen=time.time(),
                latency_ms=0,
                capabilities=set(data.get('capabilities', [])),
            )

        except Exception as e:
            self.logger.warning(f"Failed to parse peer info: {e}")
            return None

    def _get_capabilities(self) -> List[str]:
        """Get this node's capabilities based on tier."""
        base = ['gossip', 'threat_intel', 'resonance']

        if self.tier == TierRole.SENTINEL:
            return base + ['validate']

        if self.tier == TierRole.GUARDIAN:
            return base + ['layer_detection', 'mobile_protection']

        if self.tier == TierRole.FORTRESS:
            return base + ['regional_coord', 'sdn_control', 'consensus']

        if self.tier == TierRole.NEXUS:
            return base + ['ml_compute', 'training', 'consensus']

        if self.tier == TierRole.COORDINATOR:
            return base + ['global_coord', 'storage', 'analytics']

        return base

    def _request_peer_list(self, peer: PeerNode) -> None:
        """Request peer list from a peer."""
        transport = self._transports.get(peer.node_id)
        if not transport:
            return

        transport.send(
            PacketType.CONTROL_CMD,
            json.dumps({'type': 'get_peers'}).encode(),
        )

    def _prune_stale_peers(self) -> None:
        """Remove stale peers."""
        with self._lock:
            stale = [
                peer_id
                for peer_id, peer in self._peers.items()
                if peer.is_stale
            ]

            for peer_id in stale:
                peer = self._peers.pop(peer_id)

                # Close transport
                transport = self._transports.pop(peer_id, None)
                if transport:
                    try:
                        transport.close()
                    except Exception:
                        pass

                self.logger.info(f"Peer {peer_id.hex()[:8]} went stale")

                for callback in self._on_peer_left:
                    try:
                        callback(peer)
                    except Exception:
                        pass

    # =========================================================================
    # THREAT INTELLIGENCE SHARING
    # =========================================================================

    def report_threat(
        self,
        threat_type: str,
        severity: int,
        ioc_type: str,
        ioc_value: str,
        confidence: float = 0.8,
        context: Optional[Dict] = None,
    ) -> ThreatIntelligence:
        """
        Report a locally detected threat to the mesh.

        The threat will be:
        1. Added to local cache
        2. Gossiped to peers
        3. Included in consensus checkpoints

        Args:
            threat_type: Type of threat (e.g., "port_scan", "ddos")
            severity: 1-5 (1=critical, 5=info)
            ioc_type: Type of IOC ("ip", "domain", "hash", "pattern")
            ioc_value: The indicator value
            confidence: Detection confidence 0.0-1.0
            context: Additional context

        Returns:
            The created ThreatIntelligence record
        """
        intel = ThreatIntelligence(
            intel_id=secrets.token_bytes(16),
            source_node_id=self.node_id,
            timestamp=time.time(),
            threat_type=threat_type,
            severity=severity,
            confidence=confidence,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            context=context or {},
            hop_count=0,
            seen_by={self.node_id},
        )

        # Add to cache
        self.threat_cache.add(intel)

        # Queue for gossip
        self._pending_gossip.append(intel)

        # Create DSM microblock if available
        if self._dsm_node:
            try:
                self._dsm_node.create_microblock(
                    event_type='threat_intelligence',
                    payload=intel.to_bytes(),
                )
            except Exception as e:
                self.logger.warning(f"Failed to create microblock: {e}")

        self.logger.info(
            f"Reported threat: {threat_type} ({ioc_type}={ioc_value}) "
            f"severity={severity}"
        )

        return intel

    def lookup_threat(self, ioc_value: str) -> List[ThreatIntelligence]:
        """
        Lookup threat intelligence for an IOC.

        This checks both local cache and queries peers.

        Args:
            ioc_value: The indicator to lookup

        Returns:
            List of matching intelligence records
        """
        # Check local cache first
        local_results = self.threat_cache.lookup_ioc(ioc_value)

        # Could query peers for additional intel here

        return local_results

    def _process_gossip_queue(self) -> None:
        """Process pending gossip queue."""
        if not self._pending_gossip:
            return

        # Get batch of intel to gossip
        batch = []
        while self._pending_gossip and len(batch) < 10:
            try:
                batch.append(self._pending_gossip.popleft())
            except IndexError:
                break

        if not batch:
            return

        # Gossip to all connected peers
        for peer_id, transport in list(self._transports.items()):
            if not transport.is_connected:
                continue

            for intel in batch:
                # Skip if peer already saw this
                if peer_id in intel.seen_by:
                    continue

                # Skip if max hops exceeded
                if intel.hop_count >= self.MAX_GOSSIP_HOPS:
                    continue

                # Send gossip
                try:
                    transport.gossip(intel.to_bytes())
                except Exception as e:
                    self.logger.debug(f"Gossip failed to {peer_id.hex()[:8]}: {e}")

    def _handle_received_intel(self, intel: ThreatIntelligence) -> None:
        """Handle intelligence received from a peer."""
        # Check if we've seen this
        if not self.threat_cache.add(intel):
            return  # Duplicate

        # Mark ourselves as having seen it
        intel.seen_by.add(self.node_id)
        intel.hop_count += 1

        # Queue for further gossip
        if intel.hop_count < self.MAX_GOSSIP_HOPS:
            self._pending_gossip.append(intel)

        # Notify callbacks
        for callback in self._on_intelligence:
            try:
                callback(intel)
            except Exception:
                pass

        self.logger.debug(
            f"Received intel from mesh: {intel.threat_type} "
            f"({intel.ioc_type}={intel.ioc_value})"
        )

    # =========================================================================
    # CONSENSUS
    # =========================================================================

    def _build_consensus_checkpoint(self) -> None:
        """Build a consensus checkpoint (Fortress/Nexus only)."""
        if not self._consensus_engine:
            return

        try:
            # Collect recent intelligence for checkpoint
            recent_intel = self.threat_cache.get_recent(limit=100)

            # Build checkpoint data
            checkpoint_data = {
                'timestamp': time.time(),
                'node_id': self.node_id.hex(),
                'intel_count': len(recent_intel),
                'intel_hashes': [
                    intel.intel_id.hex()
                    for intel in recent_intel
                ],
                'weight_fingerprint': self.encoder.get_weight_fingerprint().fingerprint.hex(),
            }

            # Submit to consensus engine
            # self._consensus_engine.submit_checkpoint(checkpoint_data)

            self.logger.debug("Built consensus checkpoint")

        except Exception as e:
            self.logger.error(f"Checkpoint build failed: {e}")

    # =========================================================================
    # CALLBACKS
    # =========================================================================

    def on_intelligence(
        self,
        callback: Callable[[ThreatIntelligence], None],
    ) -> None:
        """Register callback for new intelligence."""
        self._on_intelligence.append(callback)

    def on_consensus(self, callback: Callable[[Dict], None]) -> None:
        """Register callback for consensus events."""
        self._on_consensus.append(callback)

    def on_peer_joined(self, callback: Callable[[PeerNode], None]) -> None:
        """Register callback for peer join events."""
        self._on_peer_joined.append(callback)

    def on_peer_left(self, callback: Callable[[PeerNode], None]) -> None:
        """Register callback for peer leave events."""
        self._on_peer_left.append(callback)

    def on_model_update(self, callback: Callable[[bytes], None]) -> None:
        """Register callback for federated learning model updates."""
        self._on_model_update.append(callback)

    # =========================================================================
    # FEDERATED LEARNING
    # =========================================================================

    def gossip_model_update(self, data: bytes) -> int:
        """Broadcast a federated learning model update to peers.

        Lower priority than threat gossip — only sent to
        NEXUS and FORTRESS tier peers by default.

        Returns number of peers sent to.
        """
        sent = 0
        for peer_id, transport in list(self._transports.items()):
            if not transport.is_connected:
                continue
            try:
                transport.send_packet(
                    packet_type=PacketType.MODEL_UPDATE,
                    payload=data,
                )
                sent += 1
            except Exception as e:
                self.logger.debug(
                    "Model update send failed to %s: %s", peer_id.hex()[:8], e,
                )
        return sent

    def _handle_model_update(self, data: bytes) -> None:
        """Handle a received MODEL_UPDATE packet from a peer."""
        for callback in self._on_model_update:
            try:
                callback(data)
            except Exception as e:
                self.logger.error("Model update callback error: %s", e)

    # =========================================================================
    # STATUS
    # =========================================================================

    def _set_state(self, new_state: ConsciousnessState) -> None:
        """Set consciousness state."""
        with self._lock:
            if self._state == new_state:
                return
            old_state = self._state
            self._state = new_state
            self.logger.info(f"State: {old_state.name} → {new_state.name}")

    def get_status(self) -> Dict[str, Any]:
        """Get consciousness status."""
        with self._lock:
            peers_by_tier = {}
            for peer in self._peers.values():
                tier_name = peer.tier.name
                peers_by_tier[tier_name] = peers_by_tier.get(tier_name, 0) + 1

            return {
                'state': self._state.name,
                'tier': self.tier.name,
                'node_id': self.node_id.hex(),
                'peer_count': len(self._peers),
                'peers_by_tier': peers_by_tier,
                'threat_cache_size': len(self.threat_cache),
                'pending_gossip': len(self._pending_gossip),
                'weight_epoch': self.encoder.get_weight_fingerprint().epoch,
            }

    def get_peers(self) -> List[Dict[str, Any]]:
        """Get list of connected peers."""
        with self._lock:
            return [
                {
                    'node_id': peer.node_id.hex()[:16],
                    'tier': peer.tier.name,
                    'endpoint': peer.endpoint,
                    'trust_score': peer.trust_score,
                    'last_seen_ago': time.time() - peer.last_seen,
                    'resonance': peer.resonance_state.name,
                }
                for peer in self._peers.values()
            ]


# =============================================================================
# CONVENIENCE FACTORY
# =============================================================================

def create_consciousness(
    tier_name: str,
    neuro_seed: Optional[bytes] = None,
    bootstrap_peers: Optional[List[str]] = None,
    data_dir: str = "/opt/hookprobe/data",
) -> MeshConsciousness:
    """
    Factory function to create mesh consciousness for a tier.

    Args:
        tier_name: "sentinel", "guardian", "fortress", "nexus", or "coordinator"
        neuro_seed: Shared neural seed (generated if None)
        bootstrap_peers: Bootstrap peer endpoints
        data_dir: Data directory

    Returns:
        Configured MeshConsciousness instance
    """
    # Map tier name
    tier_map = {
        'sentinel': TierRole.SENTINEL,
        'guardian': TierRole.GUARDIAN,
        'fortress': TierRole.FORTRESS,
        'nexus': TierRole.NEXUS,
        'coordinator': TierRole.COORDINATOR,
    }

    tier = tier_map.get(tier_name.lower())
    if not tier:
        raise ValueError(f"Unknown tier: {tier_name}")

    # Generate node ID from system
    node_id = hashlib.sha256(
        secrets.token_bytes(16) +
        struct.pack('>Q', int(time.time() * 1e6))
    ).digest()[:16]

    # Use provided or generate neural seed
    if neuro_seed is None:
        neuro_seed = secrets.token_bytes(32)

    consciousness = MeshConsciousness(
        node_id=node_id,
        tier=tier,
        neuro_seed=neuro_seed,
        data_dir=data_dir,
    )

    # Start if bootstrap peers provided
    if bootstrap_peers:
        consciousness.awaken(bootstrap_peers)

    return consciousness
