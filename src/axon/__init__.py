"""
HookProbe Axon-Z Protocol

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

from .core.ter import TER, TERGenerator
from .core.posf import PoSFSigner, PoSFVerifier
from .core.replay import DeterministicReplay
from .crypto.transport import AxonZTransport
from .neural.engine import NeuralEngine, WeightState

__all__ = [
    "TER",
    "TERGenerator",
    "PoSFSigner",
    "PoSFVerifier",
    "DeterministicReplay",
    "AxonZTransport",
    "NeuralEngine",
    "WeightState",
]
