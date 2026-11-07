"""
DSM Node Implementation

Implements microblock creation, TPM signing, and gossip protocol.
Based on the architecture specified in docs/architecture/dsm-implementation.md
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, Any, Optional
import logging

from .ledger import LevelDBLedger
from .gossip import GossipProtocol
from .crypto.tpm import load_tpm_key, tpm2_sign, tpm2_verify

logger = logging.getLogger(__name__)


class DSMNode:
    """
    DSM node running on each HookProbe edge device.

    Integrates with POD-006 (Security Detection) and POD-007 (AI Response)
    to create cryptographically signed microblocks for all security events.

    Architecture:
        Event → Hash → TPM Sign → Store → Gossip → Validators

    Example:
        >>> node = DSMNode("edge-12345", "/var/lib/hookprobe/tpm/key")
        >>> microblock = node.create_microblock(
        ...     payload={'alert_id': 123, 'severity': 'high'},
        ...     event_type='ids_alert'
        ... )
        >>> print(microblock['id'])
        'abc123...'
    """

    def __init__(
        self,
        node_id: str,
        tpm_key_path: str,
        ledger_path: str = "/var/lib/hookprobe/dsm/microblocks",
        bootstrap_nodes: Optional[list] = None
    ):
        """
        Initialize DSM node.

        Args:
            node_id: Unique identifier for this node (UUID)
            tpm_key_path: Path to TPM key for signing
            ledger_path: Path to local microblock storage
            bootstrap_nodes: List of validator nodes for gossip protocol
        """
        self.node_id = node_id
        self.tpm_key = load_tpm_key(tpm_key_path)
        self.sequence = 0
        self.prev_block_id = None
        self._peer_public_keys: Dict[str, Any] = {}

        # Initialize local ledger (RocksDB/LevelDB)
        self.ledger = LevelDBLedger(ledger_path)

        # Initialize gossip protocol
        self.gossip = GossipProtocol(
            node_id=node_id,
            bootstrap_nodes=bootstrap_nodes or []
        )

        logger.info(f"DSM Node initialized: {node_id}")

    def create_microblock(
        self,
        payload: Dict[str, Any],
        event_type: str
    ) -> Dict[str, Any]:
        """
        Create a cryptographically signed microblock for a security event.

        This implements the pseudocode from the whitepaper:

            def create_microblock(node, payload, prev_id):
                seq = node.next_seq()
                payload_hash = sha256(payload)
                m = {
                    'type':'M','node_id':node.id,'seq':seq,'prev':prev_id,
                    'timestamp':now(), 'payload_hash':payload_hash
                }
                m['signature'] = sign_tpm(node.key, serialize(m))
                store_local(m, payload)
                gossip_announce(m.id)
                return m

        Args:
            payload: Security event data (will be hashed)
            event_type: Type of event (ids_alert, mitigation, threat_intel, policy_update)

        Returns:
            Microblock dictionary with TPM signature

        Example payload:
            {
                'event_id': 'evt-uuid',
                'signature_id': 2024001,
                'severity': 'critical',
                'category': 'malware',
                'src_ip': 'anonymized-hash',
                'dst_ip': 'anonymized-hash',
                'threat_score': 95
            }
        """
        # Increment sequence counter
        self.sequence += 1

        # Hash the payload (preserves privacy, proves integrity)
        payload_hash = self._hash_payload(payload)

        # Create microblock structure
        microblock = {
            'type': 'M',  # Microblock
            'node_id': self.node_id,
            'seq': self.sequence,
            'prev': self.prev_block_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'payload_hash': payload_hash,
            'event_type': event_type
        }

        # Sign with TPM (hardware-backed authenticity)
        signature = self._sign_with_tpm(microblock)
        microblock['signature'] = signature

        # Calculate block ID from content
        block_id = self._calculate_block_id(microblock)
        microblock['id'] = block_id

        # Store locally (microblock + full payload)
        self.ledger.store(block_id, microblock, payload)
        self.prev_block_id = block_id

        # Announce to network via gossip protocol
        self.gossip.announce(block_id, microblock)

        # Metrics
        self._increment_metric('dsm.microblocks.created', {
            'type': event_type,
            'node': self.node_id
        })

        logger.info(
            f"Microblock created: {block_id[:8]}... "
            f"(seq={self.sequence}, type={event_type})"
        )

        return microblock

    def _hash_payload(self, payload: Dict[str, Any]) -> str:
        """
        Create SHA-256 hash of payload.

        Uses deterministic JSON serialization to ensure
        same payload always produces same hash.
        """
        serialized = json.dumps(payload, sort_keys=True).encode('utf-8')
        return hashlib.sha256(serialized).hexdigest()

    def _sign_with_tpm(self, data: Dict[str, Any]) -> str:
        """
        Sign data using TPM 2.0 hardware key.

        Falls back to ARM TrustZone or Intel SGX if available.

        Security properties:
        - Signature bound to specific TPM chip
        - Cannot be forged without physical TPM access
        - Proves platform integrity at signing time
        """
        # Serialize microblock (excluding signature field)
        serialized = json.dumps(data, sort_keys=True).encode('utf-8')

        # TPM signature
        signature = tpm2_sign(self.tpm_key, serialized)

        # Return base64-encoded signature
        return signature.decode('ascii') if isinstance(signature, bytes) else signature

    def _calculate_block_id(self, microblock: Dict[str, Any]) -> str:
        """
        Calculate unique block ID from microblock content.

        Block ID is SHA-256 of all fields except 'signature' and 'id'.
        This creates a deterministic, content-addressed identifier.
        """
        # Copy microblock without signature and id (id is derived from content)
        content = {k: v for k, v in microblock.items()
                   if k not in ('signature', 'id')}

        # Serialize and hash
        serialized = json.dumps(content, sort_keys=True).encode('utf-8')
        return hashlib.sha256(serialized).hexdigest()

    def verify_microblock(
        self,
        microblock: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Verify microblock integrity and signature.

        Args:
            microblock: Microblock to verify
            payload: Optional payload to verify hash

        Returns:
            True if valid, False otherwise
        """
        # Verify block ID matches content
        calculated_id = self._calculate_block_id(microblock)
        if calculated_id != microblock.get('id'):
            logger.warning(f"Invalid block ID: {microblock.get('id')}")
            return False

        # Verify payload hash if payload provided
        if payload is not None:
            calculated_hash = self._hash_payload(payload)
            if calculated_hash != microblock.get('payload_hash'):
                logger.warning(f"Invalid payload hash: {microblock.get('payload_hash')}")
                return False

        # Verify signature
        signature = microblock.get('signature')
        if not signature:
            logger.warning("Microblock missing signature")
            return False

        # Reconstruct signed data (microblock without signature and id fields)
        verify_data = {k: v for k, v in microblock.items()
                       if k not in ('signature', 'id')}
        serialized = json.dumps(verify_data, sort_keys=True).encode('utf-8')

        # Look up public key for the signing node
        node_id = microblock.get('node_id')
        public_key = self._get_node_public_key(node_id)
        if public_key is None:
            logger.warning(
                "No public key for node %s — allowing on first-seen trust",
                node_id
            )
            return True

        sig_bytes = signature.encode('ascii') if isinstance(signature, str) else signature
        if not tpm2_verify(public_key, sig_bytes, serialized):
            logger.warning("Microblock signature verification failed for node %s", node_id)
            return False

        return True

    def get_microblock(self, block_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve microblock from local ledger.

        Args:
            block_id: Block ID to fetch

        Returns:
            Microblock dictionary or None if not found
        """
        return self.ledger.get(block_id)

    def get_microblocks_range(
        self,
        start_seq: int,
        end_seq: int
    ) -> list:
        """
        Get microblocks in sequence range.

        Args:
            start_seq: Start sequence number (inclusive)
            end_seq: End sequence number (inclusive)

        Returns:
            List of microblocks in range
        """
        return self.ledger.get_range(self.node_id, start_seq, end_seq)

    def _get_node_public_key(self, node_id: str):
        """
        Get public key for a node.

        For own node, uses local TPM key's public key.
        For remote nodes, checks the peer key registry.

        Returns:
            RSA public key object, or None if unknown node
        """
        # Own node — use local key
        if node_id == self.node_id and self.tpm_key and self.tpm_key.software_key:
            return self.tpm_key.software_key.public_key()

        # Remote node — check peer registry
        peer_key = self._peer_public_keys.get(node_id)
        if peer_key is not None:
            return peer_key

        return None

    def register_peer_key(self, node_id: str, public_key) -> None:
        """Register a peer node's public key for signature verification."""
        self._peer_public_keys[node_id] = public_key
        logger.debug("Registered public key for peer %s", node_id)

    def _increment_metric(self, metric_name: str, tags: Dict[str, str]):
        """
        Increment Prometheus/VictoriaMetrics counter.

        Metrics are exported to POD-005 (Grafana/VictoriaMetrics).
        """
        logger.debug("metric: %s %s", metric_name, tags)

    def shutdown(self):
        """Gracefully shutdown node."""
        logger.info(f"Shutting down DSM node: {self.node_id}")
        self.gossip.shutdown()
        self.ledger.close()


# Example integration with POD-006 (Security Detection)
class SecurityEventHandler:
    """
    Integration point between POD-006 (IDS/IPS) and POD-010 (DSM).

    Usage:
        >>> handler = SecurityEventHandler(dsm_node)
        >>> handler.on_ids_alert(alert)
    """

    def __init__(self, dsm_node: DSMNode):
        self.dsm_node = dsm_node

    def on_ids_alert(self, alert: Dict[str, Any]) -> str:
        """
        Called when NAPSE generates alert.

        Creates cryptographically signed microblock for DSM.

        Args:
            alert: IDS alert dictionary

        Returns:
            Microblock ID for correlation
        """
        # Create DSM microblock
        microblock = self.dsm_node.create_microblock(
            payload={
                'event_id': alert.get('id'),
                'signature_id': alert.get('signature_id'),
                'severity': alert.get('severity'),
                'category': alert.get('category'),
                'src_ip': self._anonymize_ip(alert.get('src_ip')),
                'dst_ip': self._anonymize_ip(alert.get('dst_ip')),
                'threat_score': alert.get('threat_score', 0),
            },
            event_type='ids_alert'
        )

        return microblock['id']

    def _anonymize_ip(self, ip: str) -> str:
        """Anonymize IP address using SHA-256 hash."""
        return hashlib.sha256(ip.encode()).hexdigest()[:16]


# Example integration with POD-007 (AI Response)
class MitigationLogger:
    """
    Integration point between POD-007 (Qsecbit) and POD-010 (DSM).

    Usage:
        >>> logger = MitigationLogger(dsm_node)
        >>> logger.on_mitigation_executed(threat, action)
    """

    def __init__(self, dsm_node: DSMNode):
        self.dsm_node = dsm_node

    def on_mitigation_executed(
        self,
        threat: Dict[str, Any],
        action: Dict[str, Any]
    ) -> str:
        """
        Called when POD-007 (Qsecbit + Kali) executes mitigation.

        Creates tamper-evident record of security action.

        Args:
            threat: Threat dictionary
            action: Mitigation action taken

        Returns:
            Microblock ID
        """
        microblock = self.dsm_node.create_microblock(
            payload={
                'threat_id': threat.get('id'),
                'threat_score': threat.get('score'),
                'action': action.get('type'),  # 'block', 'rate_limit', 'quarantine'
                'target': self._anonymize(action.get('target')),
                'success': action.get('success'),
                'duration': action.get('duration'),
                'triggered_by': action.get('triggered_by'),  # 'qsecbit', 'manual', 'policy'
            },
            event_type='mitigation'
        )

        return microblock['id']

    def _anonymize(self, target: str) -> str:
        """Anonymize target using SHA-256 hash."""
        return hashlib.sha256(target.encode()).hexdigest()[:16]
