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
        on_zero_day: Optional[Callable[[Dict[str, Any]], None]] = None,
        llm_fn: Optional[Callable[[str, str], Optional[str]]] = None,
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

        # Phase 19: zero-day detector (initialized lazily after class is defined)
        self._zero_day_callback = on_zero_day
        self._llm_fn = llm_fn
        self._zero_day_detector: Optional[Any] = None  # Set in start()

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

        # Phase 19: initialize zero-day detector
        self._zero_day_detector = ZeroDayDetector(
            pipeline=self,
            on_zero_day=self._zero_day_callback,
            llm_fn=self._llm_fn,
        )

        self._thread = threading.Thread(
            target=self._background_loop,
            name="streaming-rag",
            daemon=True,
        )
        self._thread.start()
        logger.info("Streaming RAG pipeline started (window=%ds, zero_day=%s)",
                     self._window_s, self._zero_day_detector is not None)

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
            # Phase 19: zero-day detection stats
            "zero_day": (self._zero_day_detector.get_stats()
                         if self._zero_day_detector else None),
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

        # 7. Phase 19: zero-day novelty scan
        if self._zero_day_detector:
            self._zero_day_detector.maybe_scan(now)

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


# ======================================================================
# Phase 19: Zero-Day Detection via Kernel Telemetry RAG
# ======================================================================

class ZeroDayDetector:
    """Detects novel (zero-day) patterns by scanning the vector store.

    Phase 19: Periodically queries the embedding space for chunks that
    don't match any known pattern. Uses two signals:

    1. **Isolation score**: For each recent chunk, compute its maximum
       cosine similarity to its k-nearest neighbors. Low max similarity
       means the chunk is an outlier — it doesn't look like anything
       we've seen before.

    2. **Novelty threshold**: Chunks with max_similarity below
       NOVELTY_THRESHOLD are flagged as zero-day candidates.

    Detected candidates are:
    - Routed to the LLM for natural-language hypothesis generation
    - Logged to ClickHouse for XAI audit trail
    - Fed to the organism via the on_zero_day callback

    The detector runs as part of the StreamingRAG background loop,
    not as a separate thread.
    """

    # Tuning parameters
    NOVELTY_THRESHOLD = 0.25     # Max similarity below this = novel
    SCAN_INTERVAL_S = 30.0       # Check for novelty every 30s
    K_NEIGHBORS = 5              # Compare against 5 nearest neighbors
    MIN_STORE_SIZE = 20          # Need at least 20 chunks before scanning
    MAX_CANDIDATES_PER_SCAN = 3  # Limit to avoid LLM spam
    COOLDOWN_PER_IP_S = 300.0    # Don't re-flag same IP within 5 min

    def __init__(
        self,
        pipeline: StreamingRAGPipeline,
        on_zero_day: Optional[Callable[[Dict[str, Any]], None]] = None,
        llm_fn: Optional[Callable[[str, str], Optional[str]]] = None,
    ):
        """Initialize the zero-day detector.

        Args:
            pipeline: The StreamingRAG pipeline to scan.
            on_zero_day: Callback(candidate_dict) when a novel pattern is found.
            llm_fn: Optional LLM function(system_prompt, user_prompt) -> response.
                     If None, hypothesis generation is skipped.
        """
        self._pipeline = pipeline
        self._on_zero_day = on_zero_day
        self._llm_fn = llm_fn
        self._last_scan = 0.0

        # Cooldown tracking: source_ip → last_flagged_timestamp
        self._ip_cooldown: Dict[str, float] = {}

        self._stats = {
            'scans': 0,
            'candidates_found': 0,
            'hypotheses_generated': 0,
            'callbacks_fired': 0,
        }

    def maybe_scan(self, now: float) -> List[Dict[str, Any]]:
        """Run a novelty scan if enough time has passed.

        Called from the StreamingRAG background loop.
        Returns list of zero-day candidate dicts (may be empty).
        """
        if now - self._last_scan < self.SCAN_INTERVAL_S:
            return []

        self._last_scan = now

        # Need enough data to detect novelty
        store_size = self._pipeline.store.count()
        if store_size < self.MIN_STORE_SIZE:
            return []

        self._stats['scans'] += 1
        candidates = self._find_novel_chunks(now)

        for candidate in candidates:
            self._stats['candidates_found'] += 1

            # LLM hypothesis generation
            if self._llm_fn:
                hypothesis = self._generate_hypothesis(candidate)
                if hypothesis:
                    candidate['hypothesis'] = hypothesis
                    self._stats['hypotheses_generated'] += 1

            # Fire callback to organism
            if self._on_zero_day:
                try:
                    self._on_zero_day(candidate)
                    self._stats['callbacks_fired'] += 1
                except Exception as e:
                    logger.error("Zero-day callback error: %s", e)

        if candidates:
            logger.info(
                "ZERO-DAY: %d novel patterns detected (store=%d chunks)",
                len(candidates), store_size)

        return candidates

    def _find_novel_chunks(self, now: float) -> List[Dict[str, Any]]:
        """Scan recent chunks for novelty (low similarity to neighbors).

        For each recent chunk, query its k-nearest neighbors. If the
        best match has similarity below NOVELTY_THRESHOLD, it's novel.
        """
        store = self._pipeline.store
        embedder = self._pipeline.embedder

        # Get recent chunks (last 30s window)
        recent_cutoff = now - self.SCAN_INTERVAL_S

        # Search for each recent chunk's neighbors using its own summary
        # This is O(recent_chunks * k) which is bounded by SCAN_INTERVAL_S
        candidates = []

        # Use a broad query to get all recent summaries
        # We embed "recent activity" to get a diverse sample
        probe_queries = [
            "unusual network activity",
            "novel DNS pattern",
            "anomalous TCP behavior",
        ]

        seen_ips = set()
        for probe in probe_queries:
            results = self._pipeline.query(probe, k=self.K_NEIGHBORS * 2)
            if not results or results == "No recent kernel events found.":
                continue

            # Re-query with each result's summary to check isolation
            probe_vec = embedder.embed_single(probe)
            chunks = store.search(
                query_embedding=probe_vec,
                k=self.K_NEIGHBORS * 3,
                time_window_s=self._pipeline._window_s,
            )

            for chunk in chunks:
                if chunk.source_ip in seen_ips:
                    continue

                # Check cooldown
                if self._is_cooled_down(chunk.source_ip, now):
                    continue

                # Compute isolation: search for this chunk's neighbors
                if chunk.embedding is None:
                    continue

                neighbors = store.search(
                    query_embedding=chunk.embedding,
                    k=self.K_NEIGHBORS + 1,  # +1 because it finds itself
                    time_window_s=self._pipeline._window_s,
                )

                # Remove self from results
                others = [n for n in neighbors
                          if n.chunk_id != chunk.chunk_id]

                if not others:
                    continue  # Only one chunk = can't assess novelty

                # Max similarity to any neighbor
                max_sim = max(
                    n.key_metrics.get('similarity', 0.0)
                    for n in others
                )

                if max_sim < self.NOVELTY_THRESHOLD:
                    seen_ips.add(chunk.source_ip)
                    self._ip_cooldown[chunk.source_ip] = now

                    candidates.append({
                        'timestamp': chunk.timestamp,
                        'source_ip': chunk.source_ip,
                        'event_type': chunk.event_type,
                        'summary': chunk.summary,
                        'raw_count': chunk.raw_count,
                        'max_similarity': round(max_sim, 4),
                        'novelty_score': round(1.0 - max_sim, 4),
                        'neighbor_count': len(others),
                        'hypothesis': '',
                    })

                    if len(candidates) >= self.MAX_CANDIDATES_PER_SCAN:
                        return candidates

        return candidates

    def _is_cooled_down(self, ip: str, now: float) -> bool:
        """Check if this IP was recently flagged."""
        last = self._ip_cooldown.get(ip, 0.0)
        return (now - last) < self.COOLDOWN_PER_IP_S

    def _generate_hypothesis(self, candidate: Dict[str, Any]) -> Optional[str]:
        """Use the LLM to generate a natural-language hypothesis.

        The prompt includes:
        - The novel chunk summary
        - Its nearest (but dissimilar) neighbors for contrast
        - The novelty score
        """
        system_prompt = (
            "You are a senior SOC analyst. You have been given a network "
            "traffic pattern that doesn't match any known attack signature. "
            "Generate a brief hypothesis (2-3 sentences) about what this "
            "pattern could indicate. Consider zero-day exploits, novel C2 "
            "protocols, data exfiltration techniques, or legitimate but "
            "unusual application behavior. Be specific and actionable."
        )

        user_prompt = (
            f"NOVEL PATTERN DETECTED (novelty score: {candidate['novelty_score']:.2f})\n"
            f"Source IP: {candidate['source_ip']}\n"
            f"Event type: {candidate['event_type']}\n"
            f"Summary: {candidate['summary']}\n"
            f"Raw event count: {candidate['raw_count']}\n"
            f"Max similarity to known patterns: {candidate['max_similarity']:.2f}\n"
            f"\nWhat could this pattern indicate?"
        )

        try:
            return self._llm_fn(system_prompt, user_prompt)
        except Exception as e:
            logger.debug("Zero-day LLM hypothesis failed: %s", e)
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Return detector statistics."""
        return {
            **self._stats,
            'cooldown_ips': len(self._ip_cooldown),
            'novelty_threshold': self.NOVELTY_THRESHOLD,
            'scan_interval_s': self.SCAN_INTERVAL_S,
        }
