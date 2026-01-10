#!/usr/bin/env python3
"""
HookProbe Sentinel Mesh Integration
"The Watchful Eye" - Lightweight Mesh Validator

Version: 5.0.0

Memory-efficient mesh integration for Sentinel nodes:
- Target: <20MB additional memory overhead
- Role: SENTINEL (validator) in the mesh consciousness
- Function: Validate microblocks, participate in lightweight consensus
- Peers: Max 5-10 connections to minimize memory

Features:
- Microblock validation from local sensors
- BLS signature contribution (partial signatures only)
- Lightweight gossip (receive-only mode optional)
- Collective threat intelligence (compact cache)
- Autonomous operation when MSSP unavailable
"""

import os
import sys
import time
import json
import socket
import hashlib
import logging
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from threading import Thread, Lock
from typing import Dict, List, Optional, Set, Tuple, Callable
from collections import deque

# Try to import mesh components
try:
    from shared.mesh import (
        MeshConsciousness,
        TierRole,
        ConsciousnessState,
        ThreatIntelligence,
        PortManager,
        UnifiedTransport,
        TransportMode,
    )
    MESH_AVAILABLE = True
except ImportError:
    MESH_AVAILABLE = False

logger = logging.getLogger("sentinel.mesh")


# ============================================================
# CONFIGURATION
# ============================================================

@dataclass
class SentinelMeshConfig:
    """Configuration for Sentinel mesh integration (memory-optimized)"""

    # Node identity
    node_id: str = field(default_factory=lambda: f"sentinel-{socket.gethostname()}")
    region: str = "unknown"

    # Mesh connectivity (limited for memory)
    neuro_seed: bytes = b"hookprobe_sentinel_mesh_seed!!"
    bootstrap_peers: List[str] = field(default_factory=list)
    max_peers: int = 5  # Lower than Guardian for memory

    # Memory optimizations
    threat_cache_max: int = 100  # Small cache
    threat_cache_ttl: int = 600  # 10 minutes
    gossip_receive_only: bool = False  # Can disable sending to save bandwidth

    # Mesh participation
    enable_mesh: bool = True
    enable_consensus: bool = True
    enable_gossip: bool = True

    # Network fallback
    fallback_ports: List[int] = field(default_factory=lambda: [8144, 443, 853])

    # Timeouts (shorter for constrained devices)
    connect_timeout: float = 5.0
    gossip_interval: float = 30.0  # Less frequent than Guardian
    heartbeat_interval: float = 60.0

    @classmethod
    def from_env(cls) -> "SentinelMeshConfig":
        """Create config from environment variables"""
        return cls(
            node_id=os.environ.get("SENTINEL_NODE_ID", f"sentinel-{socket.gethostname()}"),
            region=os.environ.get("SENTINEL_REGION", "unknown"),
            neuro_seed=os.environ.get("MESH_NEURO_SEED", "hookprobe_sentinel_mesh_seed!!").encode()[:32].ljust(32, b"!"),
            bootstrap_peers=os.environ.get("MESH_BOOTSTRAP_PEERS", "").split(",") if os.environ.get("MESH_BOOTSTRAP_PEERS") else [],
            max_peers=int(os.environ.get("MESH_MAX_PEERS", "5")),
            threat_cache_max=int(os.environ.get("MESH_CACHE_MAX", "100")),
            enable_mesh=os.environ.get("ENABLE_MESH", "true").lower() == "true",
            enable_consensus=os.environ.get("ENABLE_MESH_CONSENSUS", "true").lower() == "true",
            enable_gossip=os.environ.get("ENABLE_MESH_GOSSIP", "true").lower() == "true",
            gossip_receive_only=os.environ.get("MESH_GOSSIP_RECEIVE_ONLY", "false").lower() == "true",
        )


# ============================================================
# COMPACT THREAT CACHE (Memory Optimized)
# ============================================================

class CompactThreatEntry:
    """Compact threat entry using minimal memory (~100 bytes per entry)"""

    __slots__ = ['ioc_hash', 'severity', 'threat_type', 'timestamp', 'ttl', 'source_count']

    def __init__(self, ioc_hash: bytes, severity: int, threat_type: int,
                 timestamp: float, ttl: int = 600):
        self.ioc_hash = ioc_hash  # 8 bytes (truncated hash)
        self.severity = severity  # 1 byte
        self.threat_type = threat_type  # 1 byte
        self.timestamp = timestamp  # 8 bytes
        self.ttl = ttl  # 4 bytes
        self.source_count = 1  # Corroboration counter


class CompactThreatCache:
    """Memory-efficient threat cache for Sentinel nodes"""

    # Threat type mappings
    THREAT_TYPES = {
        "port_scan": 1, "brute_force": 2, "malware": 3, "ddos": 4,
        "exfiltration": 5, "c2": 6, "lateral": 7, "privilege": 8,
        "unknown": 0,
    }

    def __init__(self, max_size: int = 100, default_ttl: int = 600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: Dict[bytes, CompactThreatEntry] = {}
        self.lru_order: deque = deque(maxlen=max_size)
        self._lock = Lock()

    def _ioc_hash(self, ioc_value: str) -> bytes:
        """Create compact hash of IOC value"""
        return hashlib.blake2b(ioc_value.encode(), digest_size=8).digest()

    def add(self, ioc_value: str, threat_type: str, severity: int,
            ttl: int = None) -> bool:
        """Add threat to cache"""
        with self._lock:
            ioc_hash = self._ioc_hash(ioc_value)
            now = time.time()

            # Check if already exists
            if ioc_hash in self.cache:
                entry = self.cache[ioc_hash]
                entry.source_count += 1
                entry.severity = max(entry.severity, severity)
                entry.timestamp = now
                return False

            # Evict oldest if full
            while len(self.cache) >= self.max_size and self.lru_order:
                oldest = self.lru_order.popleft()
                self.cache.pop(oldest, None)

            # Add new entry
            type_id = self.THREAT_TYPES.get(threat_type, 0)
            entry = CompactThreatEntry(
                ioc_hash=ioc_hash,
                severity=severity,
                threat_type=type_id,
                timestamp=now,
                ttl=ttl or self.default_ttl
            )
            self.cache[ioc_hash] = entry
            self.lru_order.append(ioc_hash)
            return True

    def lookup(self, ioc_value: str) -> Optional[Tuple[int, int]]:
        """Lookup threat by IOC value, returns (severity, source_count) or None"""
        with self._lock:
            ioc_hash = self._ioc_hash(ioc_value)
            entry = self.cache.get(ioc_hash)

            if entry is None:
                return None

            # Check expiration
            if time.time() - entry.timestamp > entry.ttl:
                del self.cache[ioc_hash]
                return None

            return (entry.severity, entry.source_count)

    def cleanup(self) -> int:
        """Remove expired entries, returns count removed"""
        with self._lock:
            now = time.time()
            expired = [h for h, e in self.cache.items()
                      if now - e.timestamp > e.ttl]
            for h in expired:
                del self.cache[h]
            return len(expired)

    def get_stats(self) -> dict:
        """Get cache statistics"""
        with self._lock:
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "memory_estimate_bytes": len(self.cache) * 100,  # ~100 bytes per entry
            }


# ============================================================
# MICROBLOCK VALIDATOR
# ============================================================

class MicroblockType(IntEnum):
    """Types of microblocks Sentinel can validate"""
    SENSOR_DATA = 1
    THREAT_REPORT = 2
    HEARTBEAT = 3
    ATTESTATION = 4


@dataclass
class Microblock:
    """Lightweight microblock for validation"""
    block_type: MicroblockType
    timestamp: float
    source_id: bytes  # 16 bytes
    payload_hash: bytes  # 32 bytes
    signature: bytes  # 64 bytes (BLS partial)
    sequence: int

    def to_bytes(self) -> bytes:
        """Serialize to compact bytes"""
        return struct.pack(
            ">BdIQ",
            self.block_type,
            self.timestamp,
            self.sequence,
            0  # Reserved
        ) + self.source_id + self.payload_hash + self.signature

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["Microblock"]:
        """Deserialize from bytes"""
        if len(data) < 129:  # 1+8+4+8+16+32+64 = 133 min
            return None
        try:
            block_type, timestamp, sequence, _ = struct.unpack(">BdIQ", data[:21])
            return cls(
                block_type=MicroblockType(block_type),
                timestamp=timestamp,
                source_id=data[21:37],
                payload_hash=data[37:69],
                signature=data[69:133],
                sequence=sequence
            )
        except (struct.error, ValueError):
            return None


class MicroblockValidator:
    """Validates microblocks from local sensors"""

    # Validation thresholds
    MAX_CLOCK_DRIFT = 300  # 5 minutes
    MIN_SEQUENCE_GAP = 0
    MAX_SEQUENCE_GAP = 1000

    # CWE-400: Bounds for data structures to prevent resource exhaustion
    MAX_KNOWN_SOURCES = 500
    MAX_SEQUENCE_TRACKER = 500

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.known_sources: Set[bytes] = set()
        self.sequence_tracker: Dict[bytes, int] = {}
        self.stats = {
            "validated": 0,
            "rejected": 0,
            "signatures_contributed": 0,
        }
        self._lock = Lock()

    def validate(self, block: Microblock) -> Tuple[bool, str]:
        """
        Validate a microblock.

        Returns:
            (valid, reason) tuple
        """
        with self._lock:
            # Timestamp validation
            now = time.time()
            if abs(now - block.timestamp) > self.MAX_CLOCK_DRIFT:
                self.stats["rejected"] += 1
                return False, "timestamp_drift"

            # Sequence validation
            last_seq = self.sequence_tracker.get(block.source_id, -1)
            if last_seq >= 0:
                gap = block.sequence - last_seq
                if gap < self.MIN_SEQUENCE_GAP or gap > self.MAX_SEQUENCE_GAP:
                    self.stats["rejected"] += 1
                    return False, "sequence_invalid"

            # CWE-400: Enforce bounds on known_sources to prevent memory exhaustion
            if len(self.known_sources) >= self.MAX_KNOWN_SOURCES:
                # Evict oldest entry (convert to list, remove first added)
                try:
                    oldest = next(iter(self.known_sources))
                    self.known_sources.discard(oldest)
                except StopIteration:
                    pass

            # Track source and sequence
            self.known_sources.add(block.source_id)

            # CWE-400: Enforce bounds on sequence_tracker
            if len(self.sequence_tracker) >= self.MAX_SEQUENCE_TRACKER:
                # Evict oldest entry
                try:
                    oldest = next(iter(self.sequence_tracker))
                    del self.sequence_tracker[oldest]
                except (StopIteration, KeyError):
                    pass

            self.sequence_tracker[block.source_id] = block.sequence

            self.stats["validated"] += 1
            return True, "valid"

    def contribute_signature(self, block: Microblock,
                            private_key: bytes = None) -> Optional[bytes]:
        """
        Contribute partial BLS signature to a microblock.

        Note: In production, this would use actual BLS signing.
        For now, returns a placeholder signature.
        """
        # Placeholder: In production, use BLS partial signing
        sig_input = block.payload_hash + self.node_id.encode()[:16]
        partial_sig = hashlib.blake2b(sig_input, digest_size=64).digest()

        with self._lock:
            self.stats["signatures_contributed"] += 1

        return partial_sig

    def get_stats(self) -> dict:
        """Get validator statistics"""
        with self._lock:
            return {
                **self.stats,
                "known_sources": len(self.known_sources),
                "tracked_sequences": len(self.sequence_tracker),
            }


# ============================================================
# SENTINEL MESH AGENT
# ============================================================

class SentinelMeshAgent:
    """
    Lightweight mesh agent for Sentinel nodes.

    Provides:
    - Microblock validation
    - Compact threat intelligence cache
    - Lightweight gossip participation
    - Autonomous operation capability

    Memory target: <20MB additional overhead
    """

    def __init__(self, config: SentinelMeshConfig = None):
        self.config = config or SentinelMeshConfig.from_env()
        self.running = False

        # Core components
        self.threat_cache = CompactThreatCache(
            max_size=self.config.threat_cache_max,
            default_ttl=self.config.threat_cache_ttl
        )
        self.validator = MicroblockValidator(self.config.node_id)

        # Mesh connectivity
        self.consciousness: Optional[MeshConsciousness] = None
        self.port_manager: Optional[PortManager] = None
        self.peers: Dict[str, dict] = {}  # Limited peer info

        # State
        self.state = "dormant"
        self.last_gossip = 0.0
        self.last_heartbeat = 0.0
        self.mssp_available = True

        # Stats
        self.stats = {
            "threats_received": 0,
            "threats_shared": 0,
            "peers_connected": 0,
            "gossip_messages": 0,
            "start_time": None,
        }

        # Callbacks
        self._threat_handlers: List[Callable] = []
        self._lock = Lock()

        logger.info(f"[MESH] Sentinel mesh agent initialized: {self.config.node_id}")

    def start(self) -> bool:
        """Start the mesh agent"""
        if self.running:
            return True

        if not self.config.enable_mesh:
            logger.info("[MESH] Mesh disabled by configuration")
            return False

        if not MESH_AVAILABLE:
            logger.warning("[MESH] Mesh modules not available")
            return False

        try:
            # Initialize mesh consciousness with SENTINEL role
            self.consciousness = MeshConsciousness(
                tier_role=TierRole.SENTINEL,
                neuro_seed=self.config.neuro_seed,
                node_id=self.config.node_id,
                bootstrap_peers=self.config.bootstrap_peers,
                max_peers=self.config.max_peers,
            )

            # Initialize port manager for resilient connectivity
            self.port_manager = PortManager()

            # Register threat handler
            self.consciousness.on_threat_received = self._handle_mesh_threat

            # Awaken consciousness
            self.consciousness.awaken()

            self.running = True
            self.stats["start_time"] = time.time()
            self.state = "awakening"

            # Start background threads (minimal)
            if self.config.enable_gossip:
                Thread(target=self._gossip_loop, daemon=True).start()

            Thread(target=self._maintenance_loop, daemon=True).start()

            logger.info(f"[MESH] Agent started, state: {self.state}")
            return True

        except Exception as e:
            logger.error(f"[MESH] Failed to start: {e}")
            return False

    def stop(self):
        """Stop the mesh agent"""
        self.running = False
        if self.consciousness:
            self.consciousness.sleep()
        self.state = "dormant"
        logger.info("[MESH] Agent stopped")

    # ----------------------------------------
    # Threat Intelligence
    # ----------------------------------------

    # CWE-400: Rate limiting for threat reports
    THREAT_REPORT_RATE_LIMIT = 100  # Max reports per minute
    THREAT_REPORT_WINDOW = 60.0  # Rate limit window in seconds

    # CWE-20: Valid threat types whitelist
    VALID_THREAT_TYPES = frozenset([
        "port_scan", "brute_force", "malware", "ddos", "exfiltration",
        "c2", "lateral", "privilege", "rate_abuse", "malicious_request",
        "unknown"
    ])

    def report_threat(self, ioc_value: str, threat_type: str = "unknown",
                     severity: int = 2, context: dict = None) -> bool:
        """
        Report a threat to the mesh.

        Args:
            ioc_value: Indicator of compromise (IP, domain, hash)
            threat_type: Type of threat (port_scan, malware, etc.)
            severity: 1=critical, 2=high, 3=medium, 4=low
            context: Additional context (optional)

        Returns:
            True if reported successfully
        """
        # CWE-20: Validate threat_type against whitelist
        if threat_type not in self.VALID_THREAT_TYPES:
            logger.warning(f"[MESH] Invalid threat_type: {threat_type[:30]}, using 'unknown'")
            threat_type = "unknown"

        # CWE-20: Validate severity range
        if not isinstance(severity, int) or severity < 1 or severity > 5:
            logger.warning(f"[MESH] Invalid severity: {severity}, defaulting to 3")
            severity = 3

        # CWE-20: Limit context size to prevent resource exhaustion
        if context is not None:
            if not isinstance(context, dict):
                context = None
            elif len(str(context)) > 4096:
                logger.warning("[MESH] Context too large, truncating")
                context = {"error": "context_truncated"}

        # CWE-400: Simple rate limiting
        with self._lock:
            now = time.time()
            if not hasattr(self, '_threat_report_count'):
                self._threat_report_count = 0
                self._threat_report_window_start = now

            # Reset window if expired
            if now - self._threat_report_window_start > self.THREAT_REPORT_WINDOW:
                self._threat_report_count = 0
                self._threat_report_window_start = now

            # Check rate limit
            if self._threat_report_count >= self.THREAT_REPORT_RATE_LIMIT:
                logger.warning("[MESH] Threat report rate limit exceeded")
                return False

            self._threat_report_count += 1

        # Validate IOC type first
        ioc_type = self._detect_ioc_type(ioc_value)
        if ioc_type == "unknown" and ioc_value:
            # Still allow reporting but log for monitoring
            logger.debug(f"[MESH] Reporting unknown IOC type for: {ioc_value[:20]}...")

        # Add to local cache first
        self.threat_cache.add(ioc_value, threat_type, severity)

        # Share with mesh if enabled
        if self.consciousness and not self.config.gossip_receive_only:
            try:
                self.consciousness.report_threat(
                    threat_type=threat_type,
                    severity=severity,
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    confidence=0.8,
                    context=context
                )
                self.stats["threats_shared"] += 1
                return True
            except Exception as e:
                logger.warning(f"[MESH] Failed to share threat: {e}")

        return False

    def lookup_threat(self, ioc_value: str) -> Optional[dict]:
        """
        Look up a threat in local and mesh cache.

        Returns:
            Threat info dict or None
        """
        # Check local cache first
        local = self.threat_cache.lookup(ioc_value)
        if local:
            severity, count = local
            return {
                "ioc_value": ioc_value,
                "severity": severity,
                "source_count": count,
                "source": "local_cache"
            }

        # Check mesh cache if available
        if self.consciousness:
            mesh_result = self.consciousness.lookup_threat(ioc_value)
            if mesh_result:
                # Cache locally for future lookups
                self.threat_cache.add(
                    ioc_value,
                    mesh_result.get("threat_type", "unknown"),
                    mesh_result.get("severity", 3)
                )
                return {**mesh_result, "source": "mesh"}

        return None

    def on_threat(self, handler: Callable):
        """Register a threat handler callback"""
        self._threat_handlers.append(handler)

    def _handle_mesh_threat(self, intel: ThreatIntelligence):
        """Handle incoming threat from mesh"""
        with self._lock:
            self.stats["threats_received"] += 1

        # Add to local cache
        self.threat_cache.add(
            intel.ioc_value,
            intel.threat_type,
            intel.severity
        )

        # Notify handlers
        for handler in self._threat_handlers:
            try:
                handler(intel)
            except Exception as e:
                logger.warning(f"[MESH] Threat handler error: {e}")

    def _detect_ioc_type(self, ioc_value: str) -> str:
        """
        Detect IOC type from value with security validation.
        CWE-20: Validates IOC format before classification.
        """
        import re
        import ipaddress

        # SECURITY: Limit IOC length to prevent resource exhaustion
        if not ioc_value or len(ioc_value) > 256:
            return "unknown"

        # SECURITY: Reject IOCs with dangerous characters (prevent injection)
        if any(c in ioc_value for c in [';', '|', '&', '$', '`', '\n', '\r', '<', '>', '"', "'"]):
            logger.warning(f"[MESH] Rejected IOC with dangerous characters")
            return "unknown"

        # IPv4/IPv6 validation using ipaddress module
        try:
            ipaddress.ip_address(ioc_value)
            return "ip"
        except ValueError:
            pass

        # SHA256 hash (64 hex chars)
        if len(ioc_value) == 64 and re.match(r'^[0-9a-f]{64}$', ioc_value.lower()):
            return "sha256"

        # MD5 hash (32 hex chars)
        if len(ioc_value) == 32 and re.match(r'^[0-9a-f]{32}$', ioc_value.lower()):
            return "md5"

        # Domain validation (RFC 1123 compliant)
        if "." in ioc_value:
            # Valid domain: alphanumeric, hyphens, dots; no consecutive dots; valid TLD
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
            if re.match(domain_pattern, ioc_value) and len(ioc_value) <= 253:
                return "domain"

        return "unknown"

    # ----------------------------------------
    # Microblock Validation
    # ----------------------------------------

    def validate_microblock(self, data: bytes) -> Tuple[bool, str]:
        """Validate a microblock from raw bytes"""
        block = Microblock.from_bytes(data)
        if block is None:
            return False, "parse_error"

        return self.validator.validate(block)

    def sign_microblock(self, data: bytes) -> Optional[bytes]:
        """Contribute signature to a microblock"""
        block = Microblock.from_bytes(data)
        if block is None:
            return None

        valid, _ = self.validator.validate(block)
        if not valid:
            return None

        return self.validator.contribute_signature(block)

    # ----------------------------------------
    # Collective Scoring
    # ----------------------------------------

    def get_collective_score(self, local_score: float = 0.5) -> dict:
        """
        Get collective security score combining local and mesh intelligence.

        Args:
            local_score: Local QSecBit score (0.0-1.0)

        Returns:
            Dict with collective score and metadata
        """
        cache_stats = self.threat_cache.get_stats()
        threat_density = cache_stats["size"] / max(cache_stats["max_size"], 1)

        # Simplified collective calculation for Sentinel
        # (lighter weight than Guardian)
        mesh_threat_level = min(threat_density * 2, 1.0)  # Scale threat density

        # Sentinel weights local score more heavily (less mesh data)
        collective_score = (local_score * 0.7) + (mesh_threat_level * 0.3)

        # Determine RAG status
        if collective_score < 0.45:
            rag = "GREEN"
        elif collective_score < 0.70:
            rag = "AMBER"
        else:
            rag = "RED"

        return {
            "collective_score": round(collective_score, 3),
            "local_score": local_score,
            "mesh_threat_level": round(mesh_threat_level, 3),
            "rag_status": rag,
            "peer_count": len(self.peers),
            "threat_cache_size": cache_stats["size"],
            "state": self.state,
        }

    # ----------------------------------------
    # Status and Stats
    # ----------------------------------------

    def get_status(self) -> dict:
        """Get comprehensive agent status"""
        uptime = time.time() - self.stats["start_time"] if self.stats["start_time"] else 0

        return {
            "node_id": self.config.node_id,
            "region": self.config.region,
            "role": "SENTINEL",
            "state": self.state,
            "running": self.running,
            "uptime": int(uptime),
            "mesh_enabled": self.config.enable_mesh,
            "peers": len(self.peers),
            "max_peers": self.config.max_peers,
            "mssp_available": self.mssp_available,
            "stats": {
                **self.stats,
                "validator": self.validator.get_stats(),
                "threat_cache": self.threat_cache.get_stats(),
            }
        }

    # ----------------------------------------
    # Background Loops
    # ----------------------------------------

    def _gossip_loop(self):
        """Background gossip processing"""
        while self.running:
            try:
                time.sleep(self.config.gossip_interval)

                if not self.consciousness:
                    continue

                # Process any pending gossip
                if self.config.enable_gossip and not self.config.gossip_receive_only:
                    self.consciousness.gossip_tick()
                    self.stats["gossip_messages"] += 1

                # Update peer count
                if self.consciousness:
                    self.stats["peers_connected"] = len(self.consciousness.peers)

            except Exception as e:
                logger.warning(f"[MESH] Gossip loop error: {e}")

    def _maintenance_loop(self):
        """Background maintenance tasks"""
        while self.running:
            try:
                time.sleep(60)  # Every minute

                # Cleanup expired threats
                removed = self.threat_cache.cleanup()
                if removed > 0:
                    logger.debug(f"[MESH] Cleaned up {removed} expired threats")

                # Update state based on consciousness
                if self.consciousness:
                    self.state = self.consciousness.state.name.lower()

            except Exception as e:
                logger.warning(f"[MESH] Maintenance error: {e}")


# ============================================================
# SENTINEL MESH DAEMON
# ============================================================

class SentinelMeshDaemon:
    """
    Standalone daemon for running Sentinel mesh agent.

    Can be run independently or integrated with main Sentinel process.
    """

    def __init__(self, config: SentinelMeshConfig = None):
        self.config = config or SentinelMeshConfig.from_env()
        self.agent = SentinelMeshAgent(self.config)
        self.running = False

    def run(self):
        """Run the daemon (blocking)"""
        import signal

        def shutdown(sig, frame):
            logger.info("[DAEMON] Shutting down...")
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

        logger.info("=" * 50)
        logger.info("HookProbe Sentinel Mesh Daemon v5.0.0")
        logger.info("=" * 50)
        logger.info(f"Node ID: {self.config.node_id}")
        logger.info(f"Region:  {self.config.region}")
        logger.info(f"Role:    SENTINEL (Validator)")
        logger.info(f"Peers:   Max {self.config.max_peers}")
        logger.info("=" * 50)

        if not self.agent.start():
            logger.error("[DAEMON] Failed to start mesh agent")
            return

        self.running = True

        # Main loop - just keep alive
        while self.running:
            time.sleep(10)
            status = self.agent.get_status()
            logger.debug(f"[DAEMON] State: {status['state']}, Peers: {status['peers']}")

    def stop(self):
        """Stop the daemon"""
        self.running = False
        self.agent.stop()


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "SentinelMeshConfig",
    "SentinelMeshAgent",
    "SentinelMeshDaemon",
    "CompactThreatCache",
    "MicroblockValidator",
    "Microblock",
    "MicroblockType",
]


# ============================================================
# CLI ENTRY POINT
# ============================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    daemon = SentinelMeshDaemon()
    daemon.run()
