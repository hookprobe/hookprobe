"""
Graph Embedder — Message-Passing Neural Network for Entity Embeddings

Produces 64-dimensional entity embeddings via a lightweight GNN:
    h_v(t) = σ(W · AGGREGATE({h_u(t-1), ∀u ∈ N(v)} ∪ {e_uv(t)}))

Two modes:
  - Lightweight (2-layer, mean aggregation) — runs on RPi4
  - Deep (4-layer, attention aggregation) — for Nexus tier

The "Golden Harmonic" is a learned baseline embedding representing
normal network behavior. Deviation from this baseline indicates
anomalous intent.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import math
import threading
from typing import Any, Dict, List, Optional, Tuple

from .entity_graph import EntityGraph, FEATURE_DIM

logger = logging.getLogger(__name__)

# Default embedding dimension
EMBEDDING_DIM = 64


def _relu(x: float) -> float:
    return max(0.0, x)


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-min(x, 500)))
    ex = math.exp(max(x, -500))
    return ex / (1.0 + ex)


def _tanh(x: float) -> float:
    return math.tanh(x)


def _dot(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _l2_norm(v: List[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def _normalize(v: List[float]) -> List[float]:
    norm = _l2_norm(v)
    if norm < 1e-12:
        return v
    return [x / norm for x in v]


class _LinearLayer:
    """Simple linear layer: y = Wx + b (pure Python, no numpy)."""

    def __init__(self, in_dim: int, out_dim: int, seed: int = 42):
        # Xavier initialization
        limit = math.sqrt(6.0 / (in_dim + out_dim))
        rng_state = seed
        self.weight: List[List[float]] = []
        for i in range(out_dim):
            row = []
            for j in range(in_dim):
                # Simple LCG PRNG
                rng_state = (rng_state * 1103515245 + 12345) & 0x7FFFFFFF
                val = (rng_state / 0x7FFFFFFF) * 2 * limit - limit
                row.append(val)
            self.weight.append(row)
        self.bias = [0.0] * out_dim
        self.in_dim = in_dim
        self.out_dim = out_dim

    def forward(self, x: List[float]) -> List[float]:
        out = []
        for i in range(self.out_dim):
            val = self.bias[i]
            for j in range(min(len(x), self.in_dim)):
                val += self.weight[i][j] * x[j]
            out.append(val)
        return out


class GraphEmbedder:
    """
    Lightweight message-passing GNN for entity embeddings.

    Architecture:
      Layer 1: entity features (16-dim) → hidden (32-dim)
      Layer 2: hidden + neighbor aggregation (32-dim) → embedding (64-dim)

    The Golden Harmonic is computed from the first N entities seen
    during a "warm-up" period and represents normal network behavior.
    """

    def __init__(
        self,
        graph: EntityGraph,
        embedding_dim: int = EMBEDDING_DIM,
        hidden_dim: int = 32,
        num_layers: int = 2,
        seed: int = 42,
    ):
        self._graph = graph
        self._embedding_dim = embedding_dim
        self._hidden_dim = hidden_dim
        self._num_layers = num_layers
        self._lock = threading.Lock()

        # Build layers
        self._input_layer = _LinearLayer(FEATURE_DIM, hidden_dim, seed=seed)
        self._agg_layer = _LinearLayer(hidden_dim * 2, embedding_dim, seed=seed + 1)

        # Golden Harmonic baseline (computed from warm-up)
        self._golden_harmonic: Optional[List[float]] = None
        self._warmup_embeddings: List[List[float]] = []
        self._warmup_target = 50  # Entities needed for baseline
        self._warmed_up = False

        logger.info(
            "GraphEmbedder initialized (dim=%d, hidden=%d, layers=%d)",
            embedding_dim, hidden_dim, num_layers,
        )

    # ------------------------------------------------------------------
    # Embedding Computation
    # ------------------------------------------------------------------

    def embed_entity(self, entity_id: str) -> Optional[List[float]]:
        """Compute embedding for a single entity via message passing.

        h_v = σ(W₂ · [h_v^(0) ‖ AGG({h_u^(0), u ∈ N(v)})])
        where h_v^(0) = σ(W₁ · features_v)
        """
        features = self._graph.get_node_features(entity_id)
        if features is None:
            return None

        # Layer 1: Feature projection
        hidden = [_relu(x) for x in self._input_layer.forward(features)]

        # Neighbor aggregation (mean pooling)
        neighbors = self._graph.get_neighbors(entity_id)
        if neighbors:
            neighbor_hiddens = []
            for nid in neighbors[:20]:  # Cap for performance
                nfeatures = self._graph.get_node_features(nid)
                if nfeatures:
                    nh = [_relu(x) for x in self._input_layer.forward(nfeatures)]
                    neighbor_hiddens.append(nh)

            if neighbor_hiddens:
                # Mean aggregation
                agg = [0.0] * self._hidden_dim
                for nh in neighbor_hiddens:
                    for i in range(self._hidden_dim):
                        agg[i] += nh[i]
                n = len(neighbor_hiddens)
                agg = [x / n for x in agg]
            else:
                agg = [0.0] * self._hidden_dim
        else:
            agg = [0.0] * self._hidden_dim

        # Concatenate self + aggregate → final embedding
        combined = hidden + agg  # [hidden_dim * 2]
        embedding = [_tanh(x) for x in self._agg_layer.forward(combined)]
        embedding = _normalize(embedding)

        # Store on node
        node = self._graph.get_node(entity_id)
        if node:
            node.embedding = embedding

        # Warm-up phase: collect embeddings for Golden Harmonic
        if not self._warmed_up:
            self._warmup_embeddings.append(embedding)
            if len(self._warmup_embeddings) >= self._warmup_target:
                self._compute_golden_harmonic()

        return embedding

    def embed_subgraph(self, entity_id: str, depth: int = 1) -> Dict[str, List[float]]:
        """Embed all entities in a subgraph."""
        subgraph = self._graph.get_subgraph(entity_id, depth)
        embeddings = {}
        for nid in subgraph["nodes"]:
            emb = self.embed_entity(nid)
            if emb:
                embeddings[nid] = emb
        return embeddings

    # ------------------------------------------------------------------
    # Deviation from Golden Harmonic
    # ------------------------------------------------------------------

    def compute_deviation(self, entity_id: str) -> float:
        """Compute deviation from the Golden Harmonic baseline.

        Returns a value in [0, 1] where:
          0.0 = perfectly normal
          1.0 = maximally anomalous
        """
        embedding = self.embed_entity(entity_id)
        if embedding is None:
            return 0.0

        if self._golden_harmonic is None:
            return 0.0  # No baseline yet

        # Cosine distance
        cos_sim = _dot(embedding, self._golden_harmonic) / (
            max(_l2_norm(embedding), 1e-12) * max(_l2_norm(self._golden_harmonic), 1e-12)
        )
        # Convert similarity [-1, 1] to deviation [0, 1]
        deviation = (1.0 - cos_sim) / 2.0
        return min(max(deviation, 0.0), 1.0)

    def get_golden_harmonic(self) -> Optional[List[float]]:
        """Get the current Golden Harmonic baseline embedding."""
        return self._golden_harmonic

    def is_warmed_up(self) -> bool:
        """Whether the Golden Harmonic has been computed."""
        return self._warmed_up

    # ------------------------------------------------------------------
    # Golden Harmonic Computation
    # ------------------------------------------------------------------

    def _compute_golden_harmonic(self) -> None:
        """Compute Golden Harmonic as mean of warm-up embeddings."""
        if not self._warmup_embeddings:
            return

        n = len(self._warmup_embeddings)
        dim = len(self._warmup_embeddings[0])
        mean = [0.0] * dim
        for emb in self._warmup_embeddings:
            for i in range(dim):
                mean[i] += emb[i]
        mean = [x / n for x in mean]
        self._golden_harmonic = _normalize(mean)
        self._warmed_up = True
        self._warmup_embeddings = []  # Free memory
        logger.info("Golden Harmonic computed from %d entities", n)

    def set_golden_harmonic(self, harmonic: List[float]) -> None:
        """Manually set the Golden Harmonic (e.g., from federated update)."""
        self._golden_harmonic = _normalize(harmonic)
        self._warmed_up = True

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        return {
            "embedding_dim": self._embedding_dim,
            "hidden_dim": self._hidden_dim,
            "num_layers": self._num_layers,
            "warmed_up": self._warmed_up,
            "warmup_progress": (
                len(self._warmup_embeddings) / self._warmup_target
                if not self._warmed_up else 1.0
            ),
        }
