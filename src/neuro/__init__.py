"""
HookProbe Neuro Protocol

Revolutionary cryptographic protocol using deterministic neural weight evolution
for continuous mutual authentication between Edge and Cloud.

Core Components:
- TER (Temporal Event Record): 64-byte sensor snapshots
- PoSF (Proof-of-Sensor-Fusion): Neural network signatures
- Deterministic Replay: Cloud verification of edge evolution
- E2EE Transport: ChaCha20-Poly1305 with keys from neural weights
"""

__version__ = "1.0.0-alpha"
__author__ = "Andrei Toma"
__license__ = "MIT"

from .core.ter import TER, TERGenerator, TERValidator
from .core.posf import PoSFSigner, PoSFVerifier
from .core.replay import DeterministicReplay, ReplayResult, ReplayCache
from .crypto.transport import NeuroZTransport, NeuroZServer, NeuroZSession
from .storage.dreamlog import DreamLog, DreamLogMetadata
from .neural.engine import NeuralEngine, WeightState, create_initial_weights
from .neural.fixedpoint import FixedPoint, FixedPointArray, verify_determinism

__all__ = [
    # TER components
    "TER",
    "TERGenerator",
    "TERValidator",
    # PoSF signatures
    "PoSFSigner",
    "PoSFVerifier",
    # Deterministic replay
    "DeterministicReplay",
    "ReplayResult",
    "ReplayCache",
    # E2EE transport
    "NeuroZTransport",
    "NeuroZServer",
    "NeuroZSession",
    # Dream log
    "DreamLog",
    "DreamLogMetadata",
    # Neural engine
    "NeuralEngine",
    "WeightState",
    "create_initial_weights",
    # Fixed-point math
    "FixedPoint",
    "FixedPointArray",
    "verify_determinism",
]
