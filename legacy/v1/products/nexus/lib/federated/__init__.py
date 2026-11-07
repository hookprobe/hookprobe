"""
Federated Learning for HookProbe Nexus

Distributes model training across the mesh network using FedAvg
with differential privacy guarantees. Supports multiple model types:
dnsxai_classifier, sia_graph_embedder, sia_intent_decoder,
qsecbit_ml, behavioral_clustering.
"""

from .privacy import DifferentialPrivacy, PrivacyBudget
from .model_registry import FederatedModelRegistry, ModelType, ModelRecord
from .participant import FederatedParticipant, LocalUpdate
from .aggregation_server import FederatedAggregationServer, AggregationRound

__all__ = [
    "DifferentialPrivacy",
    "PrivacyBudget",
    "FederatedModelRegistry",
    "ModelType",
    "ModelRecord",
    "FederatedParticipant",
    "LocalUpdate",
    "FederatedAggregationServer",
    "AggregationRound",
]
