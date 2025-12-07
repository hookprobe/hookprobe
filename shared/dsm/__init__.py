"""
HookProbe Decentralized Security Mesh (DSM)

A distributed, cryptographically verifiable security mesh that transforms
traditional centralized SOCs into a "one brain powered by many" architecture.

Key Components:
- DSMNode: Edge node that creates microblocks for security events
- DSMValidator: Enhanced node with validator capabilities
- ConsensusEngine: BLS signature aggregation for Byzantine fault tolerance
- NodeIdentity: TPM-backed hardware identity and attestation

Usage:
    from hookprobe.dsm import DSMNode, DSMValidator

    # Create edge node
    node = DSMNode(
        node_id="edge-12345",
        tpm_key_path="/var/lib/hookprobe/tpm/dsm-key"
    )

    # Create microblock for security event
    microblock = node.create_microblock(
        payload={'event': 'ids_alert', 'severity': 'high'},
        event_type='ids_alert'
    )
"""

__version__ = "5.0.0"
__author__ = "HookProbe Team"

from .node import DSMNode
from .validator import DSMValidator
from .consensus import ConsensusEngine
from .identity import NodeIdentity

__all__ = [
    'DSMNode',
    'DSMValidator',
    'ConsensusEngine',
    'NodeIdentity',
]
