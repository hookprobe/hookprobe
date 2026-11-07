"""
HookProbe E2E Security Coordinator

Unified coordinator that orchestrates the complete end-to-end security flow:
Detection → Response → Propagation → Consensus → Visualization

This is the central integration point for:
- Qsecbit threat detection and scoring
- ResponseOrchestrator automated mitigation
- MeshBridge threat propagation
- DSM microblock creation and consensus
- Neuro authentication validation
- Cortex visualization events

"From one node's detection to everyone's protection"

Author: HookProbe Team
License: Proprietary
Version: 5.0.0
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from threading import Thread, Lock, Event
from collections import deque
import time

logger = logging.getLogger(__name__)

# Optional imports - graceful degradation if not available
try:
    from .threat_types import ThreatEvent, AttackType, ThreatSeverity, OSILayer, ResponseAction
    THREAT_TYPES_AVAILABLE = True
except ImportError:
    THREAT_TYPES_AVAILABLE = False

try:
    from .response.orchestrator import ResponseOrchestrator, ResponsePolicy, ResponseResult
    RESPONSE_AVAILABLE = True
except ImportError:
    RESPONSE_AVAILABLE = False

try:
    from .mesh_bridge import QsecbitMeshBridge, MeshBridgeConfig
    MESH_BRIDGE_AVAILABLE = True
except ImportError:
    MESH_BRIDGE_AVAILABLE = False

try:
    from shared.dsm.node import DSMNode
    from shared.dsm.gossip import GossipProtocol
    DSM_AVAILABLE = True
except ImportError:
    DSM_AVAILABLE = False

try:
    from core.neuro.dsm_bridge import NeuroDSMBridge, NeuroDSMConfig
    NEURO_BRIDGE_AVAILABLE = True
except ImportError:
    NEURO_BRIDGE_AVAILABLE = False

try:
    from shared.mesh.consciousness import MeshConsciousness, ConsciousnessState
    CONSCIOUSNESS_AVAILABLE = True
except ImportError:
    CONSCIOUSNESS_AVAILABLE = False


@dataclass
class E2EConfig:
    """Configuration for E2E coordinator."""
    # Node identification
    node_id: str = ""
    tier: str = "guardian"  # sentinel, guardian, fortress, nexus

    # Component enablement
    enable_response: bool = True
    enable_mesh: bool = True
    enable_dsm: bool = True
    enable_neuro: bool = True
    enable_cortex: bool = True

    # Storage
    data_dir: str = "/opt/hookprobe/data"
    threat_db_path: str = ""  # Auto-set from data_dir

    # Thresholds
    min_severity_for_response: str = "MEDIUM"
    min_severity_for_mesh: str = "MEDIUM"
    min_severity_for_dsm: str = "HIGH"

    # Limits
    max_threats_in_memory: int = 10000
    threat_retention_hours: int = 24

    # Timing
    cleanup_interval_seconds: int = 300
    stats_export_interval: int = 60

    def __post_init__(self):
        if not self.node_id:
            self.node_id = f"hookprobe-{os.getpid()}"
        if not self.threat_db_path:
            self.threat_db_path = os.path.join(self.data_dir, "threats.jsonl")


@dataclass
class E2EStatistics:
    """Statistics for E2E coordinator."""
    threats_detected: int = 0
    threats_responded: int = 0
    threats_blocked: int = 0
    threats_propagated: int = 0
    microblocks_created: int = 0
    consensus_participations: int = 0
    cortex_events_sent: int = 0
    errors: int = 0
    start_time: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'threats_detected': self.threats_detected,
            'threats_responded': self.threats_responded,
            'threats_blocked': self.threats_blocked,
            'threats_propagated': self.threats_propagated,
            'microblocks_created': self.microblocks_created,
            'consensus_participations': self.consensus_participations,
            'cortex_events_sent': self.cortex_events_sent,
            'errors': self.errors,
            'uptime_seconds': (datetime.now() - self.start_time).total_seconds(),
        }


class ThreatStorage:
    """
    Persistent threat storage using append-only JSON Lines format.

    Provides:
    - Fast append-only writes
    - Time-based retention
    - Query by time range
    - Memory-efficient loading
    """

    def __init__(self, db_path: str, retention_hours: int = 24):
        self.db_path = Path(db_path)
        self.retention_hours = retention_hours
        self._lock = Lock()

        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def store(self, threat: 'ThreatEvent') -> bool:
        """Store a threat event to disk."""
        try:
            record = {
                'id': threat.id,
                'timestamp': threat.timestamp.isoformat(),
                'attack_type': threat.attack_type.name,
                'layer': threat.layer.name if threat.layer else None,
                'source_ip': self._anonymize_ip(threat.source_ip),
                'severity': threat.severity.name,
                'confidence': threat.confidence,
                'blocked': threat.blocked,
                'detector': threat.detector,
                'description': threat.description[:500],  # Limit description size
                'evidence_hash': hashlib.sha256(
                    json.dumps(threat.evidence or {}, sort_keys=True).encode()
                ).hexdigest()[:16],
                'qsecbit_contribution': threat.qsecbit_contribution,
            }

            with self._lock:
                with open(self.db_path, 'a') as f:
                    f.write(json.dumps(record) + '\n')

            return True
        except Exception as e:
            logger.error(f"Failed to store threat: {e}")
            return False

    def query_recent(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Query threats from the last N hours."""
        cutoff = datetime.now() - timedelta(hours=hours)
        results = []

        if not self.db_path.exists():
            return results

        try:
            with self._lock:
                with open(self.db_path, 'r') as f:
                    for line in f:
                        try:
                            record = json.loads(line.strip())
                            ts = datetime.fromisoformat(record['timestamp'])
                            if ts >= cutoff:
                                results.append(record)
                        except (json.JSONDecodeError, KeyError, ValueError):
                            continue
        except Exception as e:
            logger.error(f"Failed to query threats: {e}")

        return results

    def cleanup_old(self) -> int:
        """Remove threats older than retention period. Returns count removed."""
        if not self.db_path.exists():
            return 0

        cutoff = datetime.now() - timedelta(hours=self.retention_hours)
        kept = []
        removed = 0

        try:
            with self._lock:
                # Read all records
                with open(self.db_path, 'r') as f:
                    for line in f:
                        try:
                            record = json.loads(line.strip())
                            ts = datetime.fromisoformat(record['timestamp'])
                            if ts >= cutoff:
                                kept.append(line)
                            else:
                                removed += 1
                        except (json.JSONDecodeError, KeyError, ValueError):
                            removed += 1

                # Rewrite file with kept records
                with open(self.db_path, 'w') as f:
                    f.writelines(kept)

            if removed > 0:
                logger.info(f"Cleaned up {removed} old threat records")

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

        return removed

    def get_statistics(self) -> Dict[str, Any]:
        """Get storage statistics."""
        if not self.db_path.exists():
            return {'record_count': 0, 'file_size_bytes': 0}

        try:
            record_count = 0
            with open(self.db_path, 'r') as f:
                for _ in f:
                    record_count += 1

            return {
                'record_count': record_count,
                'file_size_bytes': self.db_path.stat().st_size,
            }
        except Exception as e:
            logger.error(f"Failed to get storage stats: {e}")
            return {'error': str(e)}

    @staticmethod
    def _anonymize_ip(ip: Optional[str]) -> Optional[str]:
        """Anonymize IP for GDPR compliance."""
        if not ip:
            return None
        return hashlib.sha256(ip.encode()).hexdigest()[:16]


class E2ECoordinator:
    """
    Unified End-to-End Security Coordinator.

    Orchestrates the complete security flow:
    1. DETECTION: Receive threats from Qsecbit detectors
    2. RESPONSE: Execute automated mitigation via ResponseOrchestrator
    3. PROPAGATION: Share threat intel via MeshBridge
    4. CONSENSUS: Create DSM microblocks and participate in consensus
    5. AUTHENTICATION: Validate with Neuro TER proofs
    6. VISUALIZATION: Emit events to Cortex

    Usage:
        coordinator = E2ECoordinator(config)
        coordinator.start()

        # When threat detected:
        coordinator.process_threat(threat_event)

        # Get status:
        status = coordinator.get_status()

        # Shutdown:
        coordinator.stop()
    """

    def __init__(self, config: Optional[E2EConfig] = None):
        self.config = config or E2EConfig()
        self._lock = Lock()
        self._running = Event()
        self._cleanup_thread: Optional[Thread] = None

        # Initialize statistics
        self.stats = E2EStatistics()

        # Initialize storage
        self.storage = ThreatStorage(
            db_path=self.config.threat_db_path,
            retention_hours=self.config.threat_retention_hours
        )

        # In-memory threat cache for fast access
        self._threat_cache: deque = deque(maxlen=self.config.max_threats_in_memory)

        # Component references (set via connect methods)
        self.response_orchestrator: Optional['ResponseOrchestrator'] = None
        self.mesh_bridge: Optional['QsecbitMeshBridge'] = None
        self.dsm_node: Optional['DSMNode'] = None
        self.gossip: Optional['GossipProtocol'] = None
        self.neuro_bridge: Optional['NeuroDSMBridge'] = None
        self.consciousness: Optional['MeshConsciousness'] = None

        # Cortex event callbacks
        self._cortex_callbacks: List[Callable] = []

        # Severity thresholds (converted to enum values)
        self._severity_levels = {
            'CRITICAL': 1,
            'HIGH': 2,
            'MEDIUM': 3,
            'LOW': 4,
            'INFO': 5,
        }

        logger.info(f"E2ECoordinator initialized (node={self.config.node_id})")

    def connect_response(self, orchestrator: 'ResponseOrchestrator'):
        """Connect ResponseOrchestrator component."""
        self.response_orchestrator = orchestrator
        logger.info("ResponseOrchestrator connected")

    def connect_mesh(self, bridge: 'QsecbitMeshBridge'):
        """Connect MeshBridge component."""
        self.mesh_bridge = bridge
        logger.info("MeshBridge connected")

    def connect_dsm(self, node: 'DSMNode', gossip: Optional['GossipProtocol'] = None):
        """Connect DSM components."""
        self.dsm_node = node
        self.gossip = gossip or (node.gossip if hasattr(node, 'gossip') else None)
        logger.info("DSM node connected")

    def connect_neuro(self, bridge: 'NeuroDSMBridge'):
        """Connect Neuro-DSM bridge."""
        self.neuro_bridge = bridge
        logger.info("NeuroDSMBridge connected")

    def connect_consciousness(self, consciousness: 'MeshConsciousness'):
        """Connect mesh consciousness."""
        self.consciousness = consciousness
        if self.mesh_bridge:
            self.mesh_bridge.set_consciousness(consciousness)
        logger.info("MeshConsciousness connected")

    def register_cortex_callback(self, callback: Callable):
        """Register callback for Cortex visualization events."""
        self._cortex_callbacks.append(callback)
        if self.mesh_bridge:
            self.mesh_bridge.register_cortex_callback(callback)

    def start(self):
        """Start the E2E coordinator."""
        self._running.set()

        # Start cleanup thread
        self._cleanup_thread = Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="E2E-Cleanup"
        )
        self._cleanup_thread.start()

        logger.info("E2ECoordinator started")

    def stop(self):
        """Stop the E2E coordinator."""
        self._running.clear()

        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)

        # Final stats export
        self._export_stats()

        logger.info("E2ECoordinator stopped")

    def process_threat(self, threat: 'ThreatEvent') -> Dict[str, Any]:
        """
        Process a detected threat through the full E2E pipeline.

        This is the main entry point for threat processing.

        Args:
            threat: ThreatEvent from Qsecbit detection

        Returns:
            Dictionary with processing results
        """
        result = {
            'threat_id': threat.id,
            'timestamp': datetime.now().isoformat(),
            'response_executed': False,
            'mesh_propagated': False,
            'microblock_created': False,
            'cortex_notified': False,
            'stored': False,
            'errors': [],
        }

        with self._lock:
            self.stats.threats_detected += 1

        try:
            severity_level = self._severity_levels.get(threat.severity.name, 5)

            # 1. STORAGE - Always store for audit trail
            if self.storage.store(threat):
                result['stored'] = True
                self._threat_cache.append({
                    'id': threat.id,
                    'timestamp': threat.timestamp,
                    'type': threat.attack_type.name,
                    'severity': threat.severity.name,
                })

            # 2. RESPONSE - Execute mitigation if above threshold
            response_threshold = self._severity_levels.get(
                self.config.min_severity_for_response, 3
            )
            if (self.config.enable_response and
                    self.response_orchestrator and
                    severity_level <= response_threshold):
                try:
                    responses = self.response_orchestrator.respond(threat)
                    result['response_executed'] = True
                    result['responses'] = [r.action.name for r in responses]

                    with self._lock:
                        self.stats.threats_responded += 1
                        if threat.blocked:
                            self.stats.threats_blocked += 1
                except Exception as e:
                    result['errors'].append(f"Response failed: {e}")
                    self.stats.errors += 1

            # 3. MESH PROPAGATION - Share with network
            mesh_threshold = self._severity_levels.get(
                self.config.min_severity_for_mesh, 3
            )
            if (self.config.enable_mesh and
                    self.mesh_bridge and
                    severity_level <= mesh_threshold):
                try:
                    if self.mesh_bridge.report_threat(threat):
                        result['mesh_propagated'] = True
                        with self._lock:
                            self.stats.threats_propagated += 1
                except Exception as e:
                    result['errors'].append(f"Mesh propagation failed: {e}")
                    self.stats.errors += 1

            # 4. DSM MICROBLOCK - Create consensus record
            dsm_threshold = self._severity_levels.get(
                self.config.min_severity_for_dsm, 2
            )
            if (self.config.enable_dsm and
                    self.dsm_node and
                    severity_level <= dsm_threshold):
                try:
                    block_id = self._create_threat_microblock(threat)
                    if block_id:
                        result['microblock_created'] = True
                        result['microblock_id'] = block_id
                        with self._lock:
                            self.stats.microblocks_created += 1
                except Exception as e:
                    result['errors'].append(f"Microblock creation failed: {e}")
                    self.stats.errors += 1

            # 5. CORTEX NOTIFICATION - Visualization event
            if self.config.enable_cortex and self._cortex_callbacks:
                try:
                    cortex_event = self._create_cortex_event(threat)
                    for callback in self._cortex_callbacks:
                        callback(cortex_event)
                    result['cortex_notified'] = True
                    with self._lock:
                        self.stats.cortex_events_sent += 1
                except Exception as e:
                    result['errors'].append(f"Cortex notification failed: {e}")

            # 6. NEURO VALIDATION - Include TER proof if available
            if self.config.enable_neuro and self.neuro_bridge:
                try:
                    ter = self.neuro_bridge.generate_ter_and_record()
                    if ter:
                        result['neuro_ter_generated'] = True
                except Exception as e:
                    # Neuro is optional, don't fail on errors
                    logger.debug(f"Neuro TER generation skipped: {e}")

        except Exception as e:
            logger.error(f"E2E threat processing failed: {e}")
            result['errors'].append(str(e))
            self.stats.errors += 1

        return result

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive coordinator status."""
        return {
            'node_id': self.config.node_id,
            'tier': self.config.tier,
            'running': self._running.is_set(),
            'statistics': self.stats.to_dict(),
            'storage': self.storage.get_statistics(),
            'components': {
                'response': self.response_orchestrator is not None,
                'mesh_bridge': self.mesh_bridge is not None,
                'dsm': self.dsm_node is not None,
                'neuro': self.neuro_bridge is not None,
                'consciousness': self.consciousness is not None,
            },
            'cache_size': len(self._threat_cache),
            'cortex_callbacks': len(self._cortex_callbacks),
        }

    def get_recent_threats(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get threats from the last N hours."""
        return self.storage.query_recent(hours=hours)

    def _create_threat_microblock(self, threat: 'ThreatEvent') -> Optional[str]:
        """Create DSM microblock for threat."""
        if not self.dsm_node:
            return None

        # Anonymize sensitive data
        payload = {
            'event_id': threat.id,
            'timestamp': threat.timestamp.isoformat(),
            'attack_type': threat.attack_type.name,
            'layer': threat.layer.name if threat.layer else 'UNKNOWN',
            'severity': threat.severity.name,
            'confidence': threat.confidence,
            'source_hash': (
                hashlib.sha256(threat.source_ip.encode()).hexdigest()[:16]
                if threat.source_ip else None
            ),
            'blocked': threat.blocked,
            'detector': threat.detector,
        }

        return self.dsm_node.create_microblock(
            event_type='threat_event',
            payload=payload
        )

    def _create_cortex_event(self, threat: 'ThreatEvent') -> Dict[str, Any]:
        """Create Cortex visualization event."""
        event_type = 'attack_repelled' if threat.blocked else 'attack_detected'

        return {
            'type': event_type,
            'timestamp': threat.timestamp.isoformat(),
            'source': {
                'ip': threat.source_ip,
                'lat': None,  # Geo-resolved by Cortex
                'lng': None,
            },
            'target': {
                'node_id': self.config.node_id,
                'ip': threat.dest_ip,
            },
            'attack_type': threat.attack_type.name.lower(),
            'severity': threat.severity.value / 4.0,
            'confidence': threat.confidence,
            'blocked': threat.blocked,
        }

    def _cleanup_loop(self):
        """Background cleanup thread."""
        while self._running.is_set():
            try:
                # Wait for interval
                self._running.wait(timeout=self.config.cleanup_interval_seconds)

                if not self._running.is_set():
                    break

                # Cleanup old threats
                self.storage.cleanup_old()

                # Export stats periodically
                self._export_stats()

                # Cleanup ResponseOrchestrator expired blocks
                if self.response_orchestrator:
                    try:
                        self.response_orchestrator.cleanup_expired_blocks()
                    except Exception as e:
                        logger.debug(f"Response cleanup skipped: {e}")

            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")

    def _export_stats(self):
        """Export statistics to file."""
        try:
            stats_file = Path(self.config.data_dir) / "e2e_stats.json"
            with open(stats_file, 'w') as f:
                json.dump(self.get_status(), f, indent=2, default=str)
        except Exception as e:
            logger.debug(f"Stats export failed: {e}")


# Factory function for creating fully configured coordinator
def create_e2e_coordinator(
    node_id: str = "",
    tier: str = "guardian",
    data_dir: str = "/opt/hookprobe/data",
    enable_all: bool = True
) -> E2ECoordinator:
    """
    Create a fully configured E2E coordinator.

    Args:
        node_id: Unique node identifier
        tier: Product tier (sentinel, guardian, fortress, nexus)
        data_dir: Directory for persistent data
        enable_all: Enable all components

    Returns:
        Configured E2ECoordinator instance
    """
    config = E2EConfig(
        node_id=node_id or f"{tier}-{os.getpid()}",
        tier=tier,
        data_dir=data_dir,
        enable_response=enable_all,
        enable_mesh=enable_all,
        enable_dsm=enable_all,
        enable_neuro=enable_all,
        enable_cortex=enable_all,
    )

    coordinator = E2ECoordinator(config)

    # Auto-initialize available components
    if RESPONSE_AVAILABLE and enable_all:
        try:
            policy = ResponsePolicy()
            orchestrator = ResponseOrchestrator(policy=policy, data_dir=data_dir)
            coordinator.connect_response(orchestrator)
        except Exception as e:
            logger.warning(f"ResponseOrchestrator auto-init failed: {e}")

    if MESH_BRIDGE_AVAILABLE and enable_all:
        try:
            bridge_config = MeshBridgeConfig(tier=tier)
            bridge = QsecbitMeshBridge(config=bridge_config)
            coordinator.connect_mesh(bridge)
        except Exception as e:
            logger.warning(f"MeshBridge auto-init failed: {e}")

    return coordinator
