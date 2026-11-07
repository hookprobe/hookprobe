"""
Qsecbit Unified Mesh Bridge - Connects Threat Detection to Decentralized Mesh

This module bridges the gap between local Qsecbit threat detection and the
distributed mesh consciousness, enabling:

1. ThreatEvent → ThreatIntelligence conversion
2. Automatic mesh reporting of detected threats
3. Collective Qsecbit score aggregation from mesh
4. DSM microblock creation for threat events
5. Cortex visualization event publishing

"One node's detection → Everyone's protection"

Author: Andrei Toma
License: Proprietary
Version: 5.0.0
"""

import hashlib
import secrets
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field

from .threat_types import (
    ThreatEvent, AttackType, ThreatSeverity, OSILayer,
    ResponseAction, MITRE_ATTACK_MAPPING
)

logger = logging.getLogger(__name__)

# Try to import mesh components
try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'shared'))
    from mesh.consciousness import (
        MeshConsciousness, ThreatIntelligence, TierRole, ConsciousnessState
    )
    MESH_AVAILABLE = True
except ImportError:
    MESH_AVAILABLE = False
    MeshConsciousness = None
    ThreatIntelligence = None
    TierRole = None

# Try to import Cortex connector
try:
    from shared.cortex.backend.connectors.base import ThreatEvent as CortexThreatEvent
    CORTEX_AVAILABLE = True
except ImportError:
    CORTEX_AVAILABLE = False
    CortexThreatEvent = None

# Try to import DSM components
try:
    from shared.dsm.node import DSMNode
    from shared.dsm.gossip import GossipProtocol
    DSM_AVAILABLE = True
except ImportError:
    DSM_AVAILABLE = False
    DSMNode = None
    GossipProtocol = None


@dataclass
class MeshBridgeConfig:
    """Configuration for the mesh bridge."""
    # Node identification
    node_id: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    tier: str = 'guardian'  # sentinel, guardian, fortress, nexus

    # Mesh settings
    enable_mesh_reporting: bool = True
    enable_cortex_events: bool = True
    enable_dsm_microblocks: bool = True

    # Filtering
    min_severity_to_report: ThreatSeverity = ThreatSeverity.MEDIUM
    report_confidence_threshold: float = 0.6

    # TTL for shared intelligence
    intel_ttl_seconds: int = 3600

    # Callbacks
    on_mesh_intel_received: Optional[Callable] = None
    on_cortex_event: Optional[Callable] = None


class QsecbitMeshBridge:
    """
    Bridge between Qsecbit threat detection and the decentralized mesh.

    Responsibilities:
    1. Convert ThreatEvent to ThreatIntelligence format
    2. Report threats to mesh consciousness
    3. Create DSM microblocks for significant threats
    4. Publish events to Cortex visualization
    5. Aggregate collective scores from mesh peers
    """

    def __init__(
        self,
        config: Optional[MeshBridgeConfig] = None,
        mesh_consciousness: Optional['MeshConsciousness'] = None,
        dsm_node: Optional['DSMNode'] = None,
        gossip: Optional['GossipProtocol'] = None
    ):
        self.config = config or MeshBridgeConfig()
        self.consciousness = mesh_consciousness
        self.dsm_node = dsm_node
        self.gossip = gossip

        # Statistics
        self.stats = {
            'threats_reported': 0,
            'threats_received': 0,
            'microblocks_created': 0,
            'cortex_events_sent': 0,
            'conversion_errors': 0,
        }

        # Callbacks for Cortex events
        self._cortex_callbacks: List[Callable] = []

        # Map severity to mesh format (1-5, lower is more severe)
        self._severity_map = {
            ThreatSeverity.CRITICAL: 1,
            ThreatSeverity.HIGH: 2,
            ThreatSeverity.MEDIUM: 3,
            ThreatSeverity.LOW: 4,
            ThreatSeverity.INFO: 5,
        }

        logger.info(f"QsecbitMeshBridge initialized (node={self.config.node_id.hex()[:8]})")

    def set_consciousness(self, consciousness: 'MeshConsciousness'):
        """Set the mesh consciousness after initialization."""
        self.consciousness = consciousness
        if consciousness:
            consciousness.on_intelligence(self._handle_mesh_intel)
            logger.info("Mesh consciousness connected to bridge")

    def set_dsm_node(self, dsm_node: 'DSMNode', gossip: Optional['GossipProtocol'] = None):
        """Set the DSM node and gossip protocol after initialization."""
        self.dsm_node = dsm_node
        self.gossip = gossip
        logger.info("DSM node connected to bridge")

    def register_cortex_callback(self, callback: Callable):
        """Register callback for Cortex visualization events."""
        self._cortex_callbacks.append(callback)

    def threat_to_intelligence(self, threat: ThreatEvent) -> Optional['ThreatIntelligence']:
        """
        Convert Qsecbit ThreatEvent to mesh ThreatIntelligence format.

        This is the critical conversion that enables mesh-wide threat sharing.
        """
        if not MESH_AVAILABLE:
            logger.warning("Mesh components not available, cannot convert threat")
            return None

        try:
            # Generate unique ID
            intel_id = hashlib.sha256(
                f"{threat.id}{threat.timestamp.isoformat()}{self.config.node_id.hex()}".encode()
            ).digest()[:16]

            # Determine IOC type and value
            ioc_type, ioc_value = self._extract_ioc(threat)

            # Build context with rich metadata
            context = {
                'layer': threat.layer.name if threat.layer else 'UNKNOWN',
                'detector': threat.detector,
                'mitre_attack_id': threat.mitre_attack_id,
                'evidence': threat.evidence,
                'qsecbit_contribution': threat.qsecbit_contribution,
                'response_actions': [a.name for a in (threat.response_actions or [])],
                'original_attack_type': threat.attack_type.name,
            }

            # Add destination info if available
            if threat.dest_ip:
                context['target_ip'] = threat.dest_ip
            if threat.dest_port:
                context['target_port'] = threat.dest_port

            intel = ThreatIntelligence(
                intel_id=intel_id,
                source_node_id=self.config.node_id,
                timestamp=threat.timestamp.timestamp(),
                threat_type=self._map_attack_type(threat.attack_type),
                severity=self._severity_map.get(threat.severity, 3),
                confidence=threat.confidence,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                context=context,
                ttl_seconds=self.config.intel_ttl_seconds,
            )

            return intel

        except Exception as e:
            logger.error(f"Failed to convert threat to intelligence: {e}")
            self.stats['conversion_errors'] += 1
            return None

    def report_threat(self, threat: ThreatEvent) -> bool:
        """
        Report a detected threat to the mesh.

        This method:
        1. Converts ThreatEvent to ThreatIntelligence
        2. Reports to mesh consciousness (gossip propagation)
        3. Creates DSM microblock for significant threats
        4. Publishes event to Cortex visualization

        Args:
            threat: The detected ThreatEvent from Qsecbit

        Returns:
            True if successfully reported to at least one destination
        """
        reported = False

        # Check severity threshold
        if threat.severity.value > self.config.min_severity_to_report.value:
            logger.debug(f"Threat {threat.id} below severity threshold, not reporting")
            return False

        # Check confidence threshold
        if threat.confidence < self.config.report_confidence_threshold:
            logger.debug(f"Threat {threat.id} below confidence threshold, not reporting")
            return False

        # Report to mesh consciousness
        if self.config.enable_mesh_reporting and self.consciousness:
            intel = self.threat_to_intelligence(threat)
            if intel:
                try:
                    self.consciousness.report_threat(
                        threat_type=intel.threat_type,
                        severity=intel.severity,
                        ioc_type=intel.ioc_type,
                        ioc_value=intel.ioc_value,
                        confidence=intel.confidence,
                        context=intel.context,
                    )
                    self.stats['threats_reported'] += 1
                    reported = True
                    logger.info(f"Threat {threat.attack_type.name} reported to mesh")
                except Exception as e:
                    logger.error(f"Failed to report threat to mesh: {e}")

        # Publish to Cortex visualization
        if self.config.enable_cortex_events:
            cortex_event = self._create_cortex_event(threat)
            if cortex_event:
                for callback in self._cortex_callbacks:
                    try:
                        callback(cortex_event)
                        self.stats['cortex_events_sent'] += 1
                        reported = True
                    except Exception as e:
                        logger.error(f"Cortex callback failed: {e}")

        # Create DSM microblock for significant threats
        if self.config.enable_dsm_microblocks and self.dsm_node:
            # Only create microblocks for HIGH/CRITICAL severity
            if threat.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
                block_id = self._create_dsm_microblock(threat)
                if block_id:
                    reported = True
                    logger.info(f"Created DSM microblock: {block_id[:16]}...")

        return reported

    def report_threats(self, threats: List[ThreatEvent]) -> int:
        """Report multiple threats to the mesh. Returns count of successful reports."""
        reported = 0
        for threat in threats:
            if self.report_threat(threat):
                reported += 1
        return reported

    def get_collective_score(self) -> Dict[str, Any]:
        """
        Get collective Qsecbit score from mesh peers.

        Combines local score with mesh-wide threat intelligence to
        provide a unified security posture assessment.
        """
        if not self.consciousness:
            return {
                'collective_score': None,
                'local_weight': 1.0,
                'mesh_weight': 0.0,
                'peer_count': 0,
                'mesh_available': False,
            }

        # Get threat cache from consciousness
        try:
            recent_intel = list(self.consciousness.threat_cache)[:100]

            # Calculate collective threat level
            if not recent_intel:
                mesh_threat_level = 0.0
            else:
                # Weight by severity and confidence
                total_weight = sum(
                    (6 - intel.severity) * intel.confidence * 0.1
                    for intel in recent_intel
                )
                mesh_threat_level = min(1.0, total_weight / 10.0)

            peer_count = len(self.consciousness.peers) if hasattr(self.consciousness, 'peers') else 0

            return {
                'collective_score': mesh_threat_level,
                'local_weight': 0.6,  # 60% local
                'mesh_weight': 0.4,   # 40% collective
                'peer_count': peer_count,
                'recent_intel_count': len(recent_intel),
                'mesh_available': True,
                'consciousness_state': self.consciousness.state.name if hasattr(self.consciousness, 'state') else 'UNKNOWN',
            }
        except Exception as e:
            logger.error(f"Failed to get collective score: {e}")
            return {
                'collective_score': None,
                'error': str(e),
                'mesh_available': False,
            }

    def _extract_ioc(self, threat: ThreatEvent) -> tuple:
        """Extract IOC type and value from threat event."""
        # Priority: IP > MAC > Domain > Hash > Pattern
        if threat.source_ip:
            return ('ip', threat.source_ip)
        if threat.source_mac:
            return ('mac', threat.source_mac)

        # Check evidence for other IOCs
        evidence = threat.evidence or {}
        if 'domain' in evidence:
            return ('domain', evidence['domain'])
        if 'hash' in evidence:
            return ('hash', evidence['hash'])
        if 'url' in evidence:
            return ('url', evidence['url'])
        if 'pattern' in evidence:
            return ('pattern', evidence['pattern'])

        # Fallback to attack type pattern
        return ('pattern', threat.attack_type.name)

    def _map_attack_type(self, attack_type: AttackType) -> str:
        """Map Qsecbit AttackType to mesh threat type string."""
        mapping = {
            # L2 attacks
            AttackType.ARP_SPOOFING: 'arp_spoofing',
            AttackType.MAC_FLOODING: 'mac_flood',
            AttackType.VLAN_HOPPING: 'vlan_hop',
            AttackType.EVIL_TWIN: 'evil_twin',
            AttackType.ROGUE_DHCP: 'rogue_dhcp',

            # L3 attacks
            AttackType.IP_SPOOFING: 'ip_spoofing',
            AttackType.ICMP_FLOOD: 'icmp_flood',
            AttackType.SMURF_ATTACK: 'smurf',
            AttackType.ROUTING_ATTACK: 'routing_attack',
            AttackType.FRAGMENTATION_ATTACK: 'frag_attack',

            # L4 attacks
            AttackType.SYN_FLOOD: 'ddos',
            AttackType.PORT_SCAN: 'port_scan',
            AttackType.TCP_RESET: 'tcp_reset',
            AttackType.SESSION_HIJACK: 'session_hijack',
            AttackType.UDP_FLOOD: 'ddos',

            # L5 attacks
            AttackType.SSL_STRIP: 'ssl_strip',
            AttackType.TLS_DOWNGRADE: 'tls_downgrade',
            AttackType.CERT_PINNING_BYPASS: 'cert_bypass',
            AttackType.AUTH_BYPASS: 'brute_force',

            # L7 attacks
            AttackType.SQL_INJECTION: 'web_attack',
            AttackType.XSS: 'web_attack',
            AttackType.DNS_TUNNELING: 'dns_tunnel',
            AttackType.HTTP_FLOOD: 'ddos',
            AttackType.MALWARE_C2: 'malware',
            AttackType.COMMAND_INJECTION: 'web_attack',
            AttackType.PATH_TRAVERSAL: 'web_attack',
        }
        return mapping.get(attack_type, 'unknown')

    def _create_cortex_event(self, threat: ThreatEvent) -> Optional[Dict[str, Any]]:
        """Create Cortex visualization event from threat."""
        try:
            # Determine if repelled based on response actions
            repelled = bool(
                threat.response_actions and
                any(a in [ResponseAction.BLOCK_IP, ResponseAction.BLOCK_MAC, ResponseAction.RATE_LIMIT]
                    for a in threat.response_actions)
            )

            event = {
                'type': 'attack_repelled' if repelled else 'attack_detected',
                'source': {
                    'ip': threat.source_ip,
                    'mac': threat.source_mac,
                    'lat': None,  # Geo resolution done by Cortex
                    'lng': None,
                },
                'target': {
                    'node_id': self.config.node_id.hex()[:16],
                    'ip': threat.dest_ip,
                },
                'attack_type': self._map_attack_type(threat.attack_type),
                'severity': threat.severity.value / 4.0,  # Normalize to 0-1
                'confidence': threat.confidence,
                'mitigation': self._get_mitigation_method(threat),
                'timestamp': threat.timestamp.isoformat(),
                'layer': threat.layer.name if threat.layer else None,
                'mitre_id': threat.mitre_attack_id,
            }

            return event

        except Exception as e:
            logger.error(f"Failed to create Cortex event: {e}")
            return None

    def _get_mitigation_method(self, threat: ThreatEvent) -> str:
        """Get mitigation method string from threat response actions."""
        if not threat.response_actions:
            return 'monitoring'

        action_map = {
            ResponseAction.BLOCK_IP: 'xdp_drop',
            ResponseAction.BLOCK_MAC: 'mac_block',
            ResponseAction.RATE_LIMIT: 'rate_limit',
            ResponseAction.TERMINATE_SESSION: 'session_kill',
            ResponseAction.QUARANTINE: 'quarantine',
            ResponseAction.ALERT: 'alert',
        }

        for action in threat.response_actions:
            if action in action_map:
                return action_map[action]

        return 'monitoring'

    def _create_dsm_microblock(self, threat: ThreatEvent) -> Optional[str]:
        """
        Create a DSM microblock for a significant threat event.

        This creates an immutable record of the threat in the decentralized
        security mesh, enabling mesh-wide verification and consensus.

        Args:
            threat: The ThreatEvent to record

        Returns:
            Block ID if successful, None otherwise
        """
        if not DSM_AVAILABLE or not self.dsm_node:
            logger.warning("DSM not available, cannot create microblock")
            return None

        try:
            # Anonymize source IP using SHA-256 hash for privacy
            anonymized_source = None
            if threat.source_ip:
                anonymized_source = hashlib.sha256(
                    threat.source_ip.encode()
                ).hexdigest()[:16]

            # Build microblock payload
            payload = {
                'event_id': threat.id,
                'timestamp': threat.timestamp.isoformat(),
                'attack_type': threat.attack_type.name,
                'layer': threat.layer.name if threat.layer else 'UNKNOWN',
                'severity': self._severity_map.get(threat.severity, 3),
                'confidence': threat.confidence,
                'source_hash': anonymized_source,
                'mitre_id': threat.mitre_attack_id,
                'blocked': threat.blocked,
                'response_actions': [a.name for a in (threat.response_actions or [])],
                'qsecbit_contribution': threat.qsecbit_contribution,
            }

            # Add IOC information
            ioc_type, ioc_value = self._extract_ioc(threat)
            if ioc_type == 'ip':
                # Anonymize IP IOCs
                payload['ioc_type'] = 'ip_hash'
                payload['ioc_value'] = hashlib.sha256(ioc_value.encode()).hexdigest()[:16]
            else:
                payload['ioc_type'] = ioc_type
                payload['ioc_value'] = ioc_value

            # Create the microblock via DSM node
            block_id = self.dsm_node.create_microblock(
                event_type='threat_intelligence',
                payload=payload
            )

            if block_id:
                self.stats['microblocks_created'] += 1

                # Announce via gossip if available
                if self.gossip:
                    microblock = self.dsm_node.get_microblock(block_id)
                    if microblock:
                        self.gossip.announce(block_id, microblock)

                return block_id

        except Exception as e:
            logger.error(f"Failed to create DSM microblock: {e}")

        return None

    def _handle_mesh_intel(self, intel: 'ThreatIntelligence'):
        """Handle threat intelligence received from mesh peers."""
        self.stats['threats_received'] += 1

        logger.info(
            f"Received mesh intel: {intel.threat_type} from {intel.source_node_id.hex()[:8]} "
            f"(severity={intel.severity}, confidence={intel.confidence:.2f})"
        )

        # Invoke callback if configured
        if self.config.on_mesh_intel_received:
            try:
                self.config.on_mesh_intel_received(intel)
            except Exception as e:
                logger.error(f"Mesh intel callback failed: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get bridge statistics."""
        return {
            **self.stats,
            'mesh_connected': self.consciousness is not None,
            'consciousness_state': (
                self.consciousness.state.name
                if self.consciousness and hasattr(self.consciousness, 'state')
                else 'DISCONNECTED'
            ),
            'cortex_callbacks': len(self._cortex_callbacks),
        }


# Convenience function for creating bridge with common configurations
def create_mesh_bridge(
    tier: str = 'guardian',
    enable_mesh: bool = True,
    enable_cortex: bool = True,
    min_severity: str = 'MEDIUM'
) -> QsecbitMeshBridge:
    """
    Create a QsecbitMeshBridge with common configuration.

    Args:
        tier: Product tier (sentinel, guardian, fortress, nexus)
        enable_mesh: Enable mesh consciousness reporting
        enable_cortex: Enable Cortex visualization events
        min_severity: Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW, INFO)

    Returns:
        Configured QsecbitMeshBridge instance
    """
    severity_map = {
        'CRITICAL': ThreatSeverity.CRITICAL,
        'HIGH': ThreatSeverity.HIGH,
        'MEDIUM': ThreatSeverity.MEDIUM,
        'LOW': ThreatSeverity.LOW,
        'INFO': ThreatSeverity.INFO,
    }

    config = MeshBridgeConfig(
        tier=tier,
        enable_mesh_reporting=enable_mesh,
        enable_cortex_events=enable_cortex,
        min_severity_to_report=severity_map.get(min_severity.upper(), ThreatSeverity.MEDIUM),
    )

    return QsecbitMeshBridge(config)
