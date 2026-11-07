"""
Vector Store — Rolling window vector database for streaming RAG.

Two implementations:
1. SQLiteVectorStore (Guardian/Fortress, 1.5-4GB): Lightweight brute-force
   cosine similarity. ~5ms for 60K vectors on RPi4.
2. ChromaVectorStore (Nexus, 16GB+): Full HNSW index via ChromaDB.
   ~2ms for 60K vectors.

Both maintain a rolling time window. Older vectors are evicted.
This is NOT a persistent knowledge base (that's AEGIS memory).
This is ephemeral situational awareness.

Memory budget:
    60s window * 1000 chunks/s * 384 dims * 4 bytes ≈ 90MB
    With metadata overhead: ~128MB (fits Fortress 4GB budget)

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
import os
import sqlite3
import struct
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from .event_chunker import EventChunk

logger = logging.getLogger(__name__)

# Optional numpy
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

# Optional chromadb
try:
    import chromadb
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False


# ------------------------------------------------------------------
# Abstract Base
# ------------------------------------------------------------------

class VectorStore(ABC):
    """Abstract base for vector storage backends."""

    @abstractmethod
    def upsert(self, chunks: List[EventChunk]) -> int:
        """Insert or update chunks. Returns number stored."""
        ...

    @abstractmethod
    def search(
        self,
        query_embedding: List[float],
        k: int = 10,
        time_window_s: float = 60.0,
    ) -> List[EventChunk]:
        """Find the k most similar chunks within the time window."""
        ...

    @abstractmethod
    def evict_older_than(self, cutoff_timestamp: float) -> int:
        """Remove chunks older than cutoff. Returns count removed."""
        ...

    @abstractmethod
    def stats(self) -> Dict[str, Any]:
        """Return store statistics."""
        ...

    @abstractmethod
    def count(self) -> int:
        """Return total number of stored chunks."""
        ...

    def clear(self) -> None:
        """Remove all chunks."""
        self.evict_older_than(time.time() + 1)


# ------------------------------------------------------------------
# SQLite + Brute-Force Vector Store
# ------------------------------------------------------------------

class SQLiteVectorStore(VectorStore):
    """SQLite-backed vector store with brute-force cosine similarity.

    Vectors are stored as BLOB (float32 packed). Search is O(N) but
    N <= 60K so brute force is fast enough (~5ms on RPi4).

    Thread-safe via SQLite's internal locking + explicit serialization.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        dimension: int = 384,
    ):
        self._db_path = db_path
        self._dim = dimension
        self._lock = threading.Lock()
        self._conn = self._init_db()

    def _init_db(self) -> sqlite3.Connection:
        """Create the SQLite database and table."""
        if self._db_path != ":memory:":
            os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)

        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vectors (
                chunk_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                source_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                raw_count INTEGER NOT NULL DEFAULT 0,
                embedding BLOB NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vectors_ts ON vectors(timestamp)"
        )
        conn.commit()
        return conn

    def upsert(self, chunks: List[EventChunk]) -> int:
        """Insert or update chunks with their embeddings."""
        if not chunks:
            return 0

        stored = 0
        with self._lock:
            for chunk in chunks:
                if chunk.embedding is None:
                    continue
                blob = _pack_vector(chunk.embedding)
                self._conn.execute(
                    "INSERT OR REPLACE INTO vectors "
                    "(chunk_id, timestamp, source_ip, event_type, summary, raw_count, embedding) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        chunk.chunk_id, chunk.timestamp, chunk.source_ip,
                        chunk.event_type, chunk.summary, chunk.raw_count, blob,
                    ),
                )
                stored += 1
            self._conn.commit()
        return stored

    def search(
        self,
        query_embedding: List[float],
        k: int = 10,
        time_window_s: float = 60.0,
    ) -> List[EventChunk]:
        """Brute-force cosine similarity search."""
        cutoff = time.time() - time_window_s

        with self._lock:
            rows = self._conn.execute(
                "SELECT chunk_id, timestamp, source_ip, event_type, "
                "summary, raw_count, embedding FROM vectors WHERE timestamp > ?",
                (cutoff,),
            ).fetchall()

        if not rows:
            return []

        # Compute similarities
        if NUMPY_AVAILABLE:
            return self._search_numpy(query_embedding, rows, k)
        return self._search_pure_python(query_embedding, rows, k)

    def evict_older_than(self, cutoff_timestamp: float) -> int:
        """Remove old vectors."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM vectors WHERE timestamp < ?",
                (cutoff_timestamp,),
            )
            self._conn.commit()
            return cursor.rowcount

    def stats(self) -> Dict[str, Any]:
        """Get store stats."""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) as cnt FROM vectors").fetchone()
            total = row["cnt"] if row else 0

            oldest = self._conn.execute(
                "SELECT MIN(timestamp) as oldest FROM vectors"
            ).fetchone()
            newest = self._conn.execute(
                "SELECT MAX(timestamp) as newest FROM vectors"
            ).fetchone()

        return {
            "backend": "sqlite",
            "total_vectors": total,
            "dimension": self._dim,
            "oldest_timestamp": oldest["oldest"] if oldest and oldest["oldest"] else None,
            "newest_timestamp": newest["newest"] if newest and newest["newest"] else None,
            "db_path": self._db_path,
        }

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) as cnt FROM vectors").fetchone()
            return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # Internal: Search implementations
    # ------------------------------------------------------------------

    def _search_numpy(
        self,
        query_embedding: List[float],
        rows: list,
        k: int,
    ) -> List[EventChunk]:
        """Vectorized cosine similarity using numpy."""
        query = np.array(query_embedding, dtype=np.float32)
        q_norm = np.linalg.norm(query)
        if q_norm > 0:
            query = query / q_norm

        # Unpack all embeddings into a matrix
        embeddings = []
        for row in rows:
            vec = _unpack_vector(row["embedding"])
            embeddings.append(vec)

        matrix = np.array(embeddings, dtype=np.float32)

        # Normalize rows
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        matrix = matrix / norms

        # Dot product = cosine similarity (both normalized)
        similarities = matrix @ query

        # Top-k indices
        if len(similarities) <= k:
            top_indices = np.argsort(-similarities)
        else:
            top_indices = np.argpartition(-similarities, k)[:k]
            top_indices = top_indices[np.argsort(-similarities[top_indices])]

        results = []
        for idx in top_indices:
            row = rows[idx]
            chunk = EventChunk(
                timestamp=row["timestamp"],
                source_ip=row["source_ip"],
                event_type=row["event_type"],
                summary=row["summary"],
                raw_count=row["raw_count"],
                key_metrics={"similarity": float(similarities[idx])},
            )
            results.append(chunk)

        return results

    def _search_pure_python(
        self,
        query_embedding: List[float],
        rows: list,
        k: int,
    ) -> List[EventChunk]:
        """Pure Python cosine similarity search."""
        # Normalize query
        q_norm = sum(x * x for x in query_embedding) ** 0.5
        if q_norm > 0:
            query = [x / q_norm for x in query_embedding]
        else:
            query = query_embedding

        scored = []
        for row in rows:
            vec = _unpack_vector(row["embedding"])
            # Normalize
            v_norm = sum(x * x for x in vec) ** 0.5
            if v_norm > 0:
                vec = [x / v_norm for x in vec]
            sim = sum(a * b for a, b in zip(query, vec))
            scored.append((sim, row))

        scored.sort(key=lambda x: -x[0])

        results = []
        for sim, row in scored[:k]:
            chunk = EventChunk(
                timestamp=row["timestamp"],
                source_ip=row["source_ip"],
                event_type=row["event_type"],
                summary=row["summary"],
                raw_count=row["raw_count"],
                key_metrics={"similarity": sim},
            )
            results.append(chunk)

        return results


# ------------------------------------------------------------------
# ChromaDB Vector Store (Nexus tier)
# ------------------------------------------------------------------

class ChromaVectorStore(VectorStore):
    """ChromaDB-backed store for Nexus tier (16GB+).

    Uses HNSW index for fast approximate nearest neighbor search.
    Falls back to SQLiteVectorStore if ChromaDB unavailable.
    """

    def __init__(
        self,
        collection_name: str = "neurokernel_streaming",
        persist_directory: Optional[str] = None,
        dimension: int = 384,
    ):
        if not CHROMADB_AVAILABLE:
            raise ImportError("chromadb is required for ChromaVectorStore")

        self._dim = dimension
        self._lock = threading.Lock()

        if persist_directory:
            self._client = chromadb.PersistentClient(path=persist_directory)
        else:
            self._client = chromadb.Client()

        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def upsert(self, chunks: List[EventChunk]) -> int:
        if not chunks:
            return 0

        ids = []
        embeddings = []
        documents = []
        metadatas = []

        for chunk in chunks:
            if chunk.embedding is None:
                continue
            ids.append(chunk.chunk_id)
            embeddings.append(chunk.embedding)
            documents.append(chunk.summary)
            metadatas.append({
                "timestamp": chunk.timestamp,
                "source_ip": chunk.source_ip,
                "event_type": chunk.event_type,
                "raw_count": chunk.raw_count,
            })

        if not ids:
            return 0

        with self._lock:
            self._collection.upsert(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas,
            )
        return len(ids)

    def search(
        self,
        query_embedding: List[float],
        k: int = 10,
        time_window_s: float = 60.0,
    ) -> List[EventChunk]:
        cutoff = time.time() - time_window_s

        with self._lock:
            results = self._collection.query(
                query_embeddings=[query_embedding],
                n_results=min(k, self._collection.count() or 1),
                where={"timestamp": {"$gte": cutoff}},
            )

        chunks = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                doc = results["documents"][0][i] if results["documents"] else ""
                dist = results["distances"][0][i] if results["distances"] else 0.0

                chunks.append(EventChunk(
                    timestamp=meta.get("timestamp", 0.0),
                    source_ip=meta.get("source_ip", ""),
                    event_type=meta.get("event_type", ""),
                    summary=doc,
                    raw_count=meta.get("raw_count", 0),
                    key_metrics={"distance": dist, "similarity": 1.0 - dist},
                ))

        return chunks

    def evict_older_than(self, cutoff_timestamp: float) -> int:
        with self._lock:
            # ChromaDB doesn't support delete by filter easily,
            # so we get IDs first then delete
            try:
                results = self._collection.get(
                    where={"timestamp": {"$lt": cutoff_timestamp}},
                )
                if results and results["ids"]:
                    self._collection.delete(ids=results["ids"])
                    return len(results["ids"])
            except Exception as e:
                logger.warning("ChromaDB eviction error: %s", e)
            return 0

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._collection.count()
        return {
            "backend": "chromadb",
            "total_vectors": total,
            "dimension": self._dim,
        }

    def count(self) -> int:
        with self._lock:
            return self._collection.count()


# ------------------------------------------------------------------
# Factory
# ------------------------------------------------------------------

def create_vector_store(
    backend: str = "sqlite",
    db_path: str = ":memory:",
    dimension: int = 384,
    **kwargs,
) -> VectorStore:
    """Create a vector store for the appropriate tier.

    Args:
        backend: "sqlite" (Guardian/Fortress) or "chromadb" (Nexus).
        db_path: Database path for SQLite backend.
        dimension: Embedding dimension.

    Returns:
        VectorStore instance.
    """
    if backend == "chromadb":
        if not CHROMADB_AVAILABLE:
            logger.warning("ChromaDB unavailable — falling back to SQLite")
            return SQLiteVectorStore(db_path=db_path, dimension=dimension)
        return ChromaVectorStore(dimension=dimension, **kwargs)

    return SQLiteVectorStore(db_path=db_path, dimension=dimension)


# ------------------------------------------------------------------
# Vector Packing/Unpacking
# ------------------------------------------------------------------

def _pack_vector(vec: List[float]) -> bytes:
    """Pack a float vector into bytes for SQLite BLOB storage."""
    return struct.pack(f"<{len(vec)}f", *vec)


def _unpack_vector(blob: bytes) -> List[float]:
    """Unpack bytes back to a float vector."""
    n = len(blob) // 4  # 4 bytes per float32
    return list(struct.unpack(f"<{n}f", blob))
