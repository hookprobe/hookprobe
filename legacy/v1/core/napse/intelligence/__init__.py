"""
NAPSE Intelligence — Semantic Intent Attribution (SIA)

Transforms detection from "what is this packet?" to "what is this entity
trying to achieve?" using temporal graph neural networks, Hidden Markov
Models, and Bayesian belief evolution.

Pipeline:
    NAPSE Events → EntityGraph → GraphEmbedder → IntentDecoder
                                                → BayesianScorer → AEGIS

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

from .entity_graph import EntityGraph, EntityNode, EntityEdge
from .graph_embedder import GraphEmbedder
from .intent_decoder import IntentDecoder, IntentPhase, IntentSequence
from .bayesian_scorer import BayesianScorer
from .sia_engine import SIAEngine

__all__ = [
    "EntityGraph",
    "EntityNode",
    "EntityEdge",
    "GraphEmbedder",
    "IntentDecoder",
    "IntentPhase",
    "IntentSequence",
    "BayesianScorer",
    "SIAEngine",
]

__version__ = "1.0.0"
