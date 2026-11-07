"""
Embedding Engine — Text-to-vector conversion for streaming RAG.

Primary: sentence-transformers MiniLM-L6-v2 (384-dim, 80MB RAM)
Fallback: Deterministic hash-based pseudo-embeddings when the model
is unavailable (for constrained devices and testing).

The hash fallback produces stable, reproducible vectors that preserve
exact-match similarity (identical strings get identical vectors) but
do NOT capture semantic similarity. This is acceptable for the streaming
RAG use case where we primarily need temporal + IP-based filtering,
with semantic search as a bonus.

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import hashlib
import logging
import math
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Optional: sentence-transformers
try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False

# Optional: numpy (for normalization)
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


# ------------------------------------------------------------------
# Embedding Engine
# ------------------------------------------------------------------

DEFAULT_MODEL = "all-MiniLM-L6-v2"
DEFAULT_DIM = 384


class EmbeddingEngine:
    """Embeds text into fixed-dimension vectors.

    Uses MiniLM-L6-v2 when available, falls back to hash-based
    pseudo-embeddings otherwise.

    Usage:
        engine = EmbeddingEngine()
        vectors = engine.embed(["some text", "another text"])
        # vectors: List[List[float]], each of length 384
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        dim: int = DEFAULT_DIM,
        force_hash: bool = False,
    ):
        """Initialize the embedding engine.

        Args:
            model_name: sentence-transformers model name.
            dim: Embedding dimension (must match model output).
            force_hash: Force hash-based fallback even if model available.
        """
        self._dim = dim
        self._model = None
        self._using_model = False

        if not force_hash and SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                self._model = SentenceTransformer(model_name)
                self._dim = self._model.get_sentence_embedding_dimension()
                self._using_model = True
                logger.info(
                    "Loaded embedding model %s (dim=%d)",
                    model_name, self._dim,
                )
            except Exception as e:
                logger.warning(
                    "Failed to load embedding model %s: %s — using hash fallback",
                    model_name, e,
                )
        else:
            if force_hash:
                logger.info("Embedding engine: hash fallback (forced)")
            else:
                logger.info("Embedding engine: hash fallback (sentence-transformers unavailable)")

    @property
    def dimension(self) -> int:
        """Return the embedding dimension."""
        return self._dim

    @property
    def using_model(self) -> bool:
        """Whether a real ML model is loaded."""
        return self._using_model

    def embed(self, texts: List[str]) -> List[List[float]]:
        """Embed a batch of texts.

        Args:
            texts: List of strings to embed.

        Returns:
            List of float vectors, each of length self.dimension.
        """
        if not texts:
            return []

        if self._using_model:
            return self._embed_model(texts)
        return self._embed_hash(texts)

    def embed_single(self, text: str) -> List[float]:
        """Embed a single text. Convenience wrapper."""
        results = self.embed([text])
        return results[0] if results else [0.0] * self._dim

    def stats(self) -> Dict[str, Any]:
        """Return engine status."""
        return {
            "using_model": self._using_model,
            "dimension": self._dim,
            "backend": "sentence-transformers" if self._using_model else "hash",
        }

    # ------------------------------------------------------------------
    # Internal: Model-based embedding
    # ------------------------------------------------------------------

    def _embed_model(self, texts: List[str]) -> List[List[float]]:
        """Embed using the sentence-transformers model."""
        try:
            embeddings = self._model.encode(
                texts,
                normalize_embeddings=True,
                show_progress_bar=False,
            )
            # Convert numpy arrays to lists
            return [emb.tolist() for emb in embeddings]
        except Exception as e:
            logger.warning("Model embedding failed: %s — falling back to hash", e)
            return self._embed_hash(texts)

    # ------------------------------------------------------------------
    # Internal: Hash-based fallback
    # ------------------------------------------------------------------

    def _embed_hash(self, texts: List[str]) -> List[List[float]]:
        """Generate deterministic pseudo-embeddings from text hashes.

        Uses SHA-512 to generate enough bytes, then converts to floats.
        Normalizes the result to unit length for cosine similarity.
        """
        results = []
        for text in texts:
            vec = self._hash_to_vector(text)
            results.append(vec)
        return results

    def _hash_to_vector(self, text: str) -> List[float]:
        """Convert text to a deterministic normalized vector.

        Uses chained SHA-512 hashes, converting each byte to a float
        in [-1, 1] range to avoid NaN/Inf issues with raw float32
        interpretation.
        """
        # Generate enough hash bytes (1 byte per dimension)
        raw_bytes = b""
        seed = text.encode("utf-8")
        while len(raw_bytes) < self._dim:
            h = hashlib.sha512(seed + raw_bytes).digest()
            raw_bytes += h
            seed = h

        # Convert bytes to floats in [-1, 1] range
        vec = [(b / 127.5) - 1.0 for b in raw_bytes[:self._dim]]

        # Normalize to unit length
        return _normalize(vec)


# ------------------------------------------------------------------
# Utility: Vector Normalization
# ------------------------------------------------------------------

def _normalize(vec: List[float]) -> List[float]:
    """Normalize a vector to unit length."""
    if NUMPY_AVAILABLE:
        arr = np.array(vec, dtype=np.float32)
        norm = np.linalg.norm(arr)
        if norm > 0:
            arr = arr / norm
        return arr.tolist()

    # Pure Python fallback
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        return [x / norm for x in vec]
    return vec


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Compute cosine similarity between two vectors.

    Both vectors should be normalized (unit length) for this to work
    as a simple dot product.
    """
    if NUMPY_AVAILABLE:
        arr_a = np.array(a, dtype=np.float32)
        arr_b = np.array(b, dtype=np.float32)
        return float(np.dot(arr_a, arr_b))

    # Pure Python dot product
    return sum(x * y for x, y in zip(a, b))
