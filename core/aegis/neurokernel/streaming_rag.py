"""
Streaming eBPF-RAG Pipeline — Real-time kernel event context for LLM.

Connects the eBPF sensor manager to the vector store via the chunker
and embedding engine. Runs as a background thread, continuously
ingesting kernel events and maintaining a rolling time window.

The pipeline is pull-based from the LLM's perspective: when the LLM
needs context, it calls query() which searches the vector store.
Ingestion runs independently in the background.

Pipeline:
    SensorEvents → EventChunker → EmbeddingEngine → VectorStore
                                                      ↑
                                         LLM queries via search()

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .event_chunker import EventChunk, EventChunker
from .embedding_engine import EmbeddingEngine
from .types import SensorEvent
from .vector_store import VectorStore, create_vector_store

logger = logging.getLogger(__name__)


class StreamingRAGPipeline:
    """Background pipeline: sensors → chunks → vectors → searchable.

    Thread-safe. The background thread handles ingestion and eviction.
    query() can be called from any thread.
    """

    INGEST_INTERVAL_S = 1.0     # Process events every 1 second
    EVICTION_INTERVAL_S = 5.0   # Evict old vectors every 5 seconds
    WINDOW_SIZE_S = 60.0        # Keep 60 seconds of context
    MAX_CHUNKS_PER_TICK = 1000  # Backpressure limit
    EMBED_BATCH_SIZE = 64       # Batch size for embedding

    def __init__(
        self,
        embedder: Optional[EmbeddingEngine] = None,
        store: Optional[VectorStore] = None,
        chunker: Optional[EventChunker] = None,
        window_s: float = WINDOW_SIZE_S,
        ingest_interval_s: float = INGEST_INTERVAL_S,
    ):
        self._embedder = embedder or EmbeddingEngine(force_hash=True)
        self._store = store or create_vector_store(backend="sqlite")
        self._chunker = chunker or EventChunker(window_s=1.0)
        self._window_s = window_s
        self._ingest_interval = ingest_interval_s

        # Event buffer (thread-safe via lock)
        self._event_buffer: List[SensorEvent] = []
        self._buffer_lock = threading.Lock()

        # Background thread
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._stop_event = threading.Event()

        # Stats
        self._events_received = 0
        self._chunks_embedded = 0
        self._queries_served = 0
        self._last_ingest_time = 0.0
        self._last_eviction_time = 0.0

    # ------------------------------------------------------------------
    # Public: Event Ingestion
    # ------------------------------------------------------------------

    def ingest(self, event: SensorEvent) -> None:
        """Add a sensor event to the pipeline buffer.

        Thread-safe. Can be called from any thread (bridges, sensors).
        """
        with self._buffer_lock:
            self._event_buffer.append(event)
            self._events_received += 1

    def ingest_batch(self, events: List[SensorEvent]) -> None:
        """Add a batch of sensor events."""
        with self._buffer_lock:
            self._event_buffer.extend(events)
            self._events_received += len(events)

    # ------------------------------------------------------------------
    # Public: Query Interface
    # ------------------------------------------------------------------

    def query(self, question: str, k: int = 10) -> str:
        """Semantic search across recent kernel events.

        Args:
            question: Natural language query.
            k: Number of top results.

        Returns:
            Formatted context string for LLM injection.
        """
        self._queries_served += 1

        # Embed the query
        query_vec = self._embedder.embed_single(question)

        # Search the store
        chunks = self._store.search(
            query_embedding=query_vec,
            k=k,
            time_window_s=self._window_s,
        )

        return self._format_context(chunks)

    def query_by_ip(self, source_ip: str, k: int = 10) -> str:
        """Search for events from a specific IP address.

        Uses the IP as the query text for embedding similarity,
        which works reasonably well since chunk summaries contain IPs.
        """
        return self.query(f"events from {source_ip}", k=k)

    # ------------------------------------------------------------------
    # Public: Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background ingestion thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._background_loop,
            name="streaming-rag",
            daemon=True,
        )
        self._thread.start()
        logger.info("Streaming RAG pipeline started (window=%ds)", self._window_s)

    def stop(self) -> None:
        """Stop the background thread and flush remaining data."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        # Final flush
        self._process_tick()
        logger.info("Streaming RAG pipeline stopped")

    def tick(self) -> None:
        """Manually trigger one processing cycle (for testing)."""
        self._process_tick()

    def stats(self) -> Dict[str, Any]:
        """Return pipeline statistics."""
        return {
            "running": self._running,
            "events_received": self._events_received,
            "chunks_embedded": self._chunks_embedded,
            "queries_served": self._queries_served,
            "buffer_size": len(self._event_buffer),
            "window_s": self._window_s,
            "store": self._store.stats(),
            "chunker": self._chunker.stats(),
            "embedder": self._embedder.stats(),
        }

    @property
    def store(self) -> VectorStore:
        """Access the underlying vector store."""
        return self._store

    @property
    def embedder(self) -> EmbeddingEngine:
        """Access the embedding engine."""
        return self._embedder

    # ------------------------------------------------------------------
    # Internal: Background Loop
    # ------------------------------------------------------------------

    def _background_loop(self) -> None:
        """Main background loop: ingest, chunk, embed, store, evict."""
        while not self._stop_event.is_set():
            try:
                self._process_tick()
            except Exception as e:
                logger.error("Streaming RAG tick error: %s", e, exc_info=True)

            self._stop_event.wait(timeout=self._ingest_interval)

    def _process_tick(self) -> None:
        """One processing cycle: drain buffer → chunk → embed → store → evict."""
        now = time.time()

        # 1. Drain event buffer
        with self._buffer_lock:
            events = self._event_buffer[:]
            self._event_buffer.clear()

        # 2. Feed to chunker
        if events:
            self._chunker.ingest_batch(events)

        # 3. Flush completed chunks
        chunks = self._chunker.flush(now=now)
        if not chunks:
            # Still check eviction
            if now - self._last_eviction_time >= self.EVICTION_INTERVAL_S:
                self._evict(now)
            return

        # Limit chunks per tick (backpressure)
        if len(chunks) > self.MAX_CHUNKS_PER_TICK:
            chunks = chunks[:self.MAX_CHUNKS_PER_TICK]

        # 4. Embed chunks in batches
        summaries = [c.summary for c in chunks]
        for batch_start in range(0, len(summaries), self.EMBED_BATCH_SIZE):
            batch_end = min(batch_start + self.EMBED_BATCH_SIZE, len(summaries))
            batch_texts = summaries[batch_start:batch_end]
            batch_vecs = self._embedder.embed(batch_texts)

            for i, vec in enumerate(batch_vecs):
                chunks[batch_start + i].embedding = vec

        # 5. Store in vector DB
        stored = self._store.upsert(chunks)
        self._chunks_embedded += stored
        self._last_ingest_time = now

        # 6. Evict old vectors periodically
        if now - self._last_eviction_time >= self.EVICTION_INTERVAL_S:
            self._evict(now)

    def _evict(self, now: float) -> None:
        """Evict vectors older than the window."""
        cutoff = now - self._window_s
        evicted = self._store.evict_older_than(cutoff)
        if evicted > 0:
            logger.debug("Evicted %d old vectors (cutoff=%.0f)", evicted, cutoff)
        self._last_eviction_time = now

    # ------------------------------------------------------------------
    # Internal: Context Formatting
    # ------------------------------------------------------------------

    def _format_context(self, chunks: List[EventChunk]) -> str:
        """Format search results as LLM-injectable context."""
        if not chunks:
            return "No recent kernel events found."

        lines = [f"Recent Kernel Activity ({len(chunks)} events):"]
        for i, chunk in enumerate(chunks, 1):
            age = time.time() - chunk.timestamp
            age_str = f"{age:.0f}s ago" if age < 120 else f"{age/60:.1f}m ago"
            sim = chunk.key_metrics.get("similarity", 0.0)
            lines.append(
                f"  {i}. [{age_str}] {chunk.summary}"
                + (f" (relevance: {sim:.2f})" if sim > 0 else "")
            )

        return "\n".join(lines)
