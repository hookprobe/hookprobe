"""
Nexus Offload — Package and transport eBPF traces to Nexus for deep analysis.

When the edge device (Sentinel/Guardian/Fortress) encounters an ambiguous
threat that QSecBit cannot classify with high confidence, this module:

1. Captures the last N seconds of relevant eBPF events from streaming RAG
2. Packages them into a compact TracePackage (max 64KB)
3. Sends via HTP transport (post-quantum encrypted) or local queue
4. Waits for Nexus verdict (with timeout and fallback)

New packet types (defined but not registered until mesh transport is wired):
    KERNEL_TELEMETRY = 0x62    # eBPF trace offload to Nexus
    KERNEL_VERDICT   = 0x61    # Nexus verdict response

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .verdict import ThreatContext, VerdictAction, VerdictResult, VerdictSource

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

MAX_TRACE_SIZE_BYTES = 65536       # 64KB max per trace package
MAX_EVENTS_PER_TRACE = 500        # Cap events per package
DEFAULT_TRACE_WINDOW_S = 5.0      # Capture last 5 seconds
DEFAULT_TIMEOUT_S = 10.0          # Wait up to 10s for Nexus response
MAX_PENDING_OFFLOADS = 50         # Backpressure: max concurrent offloads


# ------------------------------------------------------------------
# Data Types
# ------------------------------------------------------------------

@dataclass
class TracePackage:
    """A compact eBPF trace package for Nexus analysis."""
    trace_id: str
    timestamp: float
    source_node: str = ""
    threat_context: Optional[Dict[str, Any]] = None
    events: List[Dict[str, Any]] = field(default_factory=list)
    event_count: int = 0
    window_s: float = DEFAULT_TRACE_WINDOW_S
    size_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "source_node": self.source_node,
            "threat_context": self.threat_context,
            "events": self.events,
            "event_count": self.event_count,
            "window_s": self.window_s,
            "size_bytes": self.size_bytes,
        }

    def to_bytes(self) -> bytes:
        """Serialize to compact JSON bytes."""
        data = json.dumps(self.to_dict(), separators=(",", ":")).encode("utf-8")
        self.size_bytes = len(data)
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> "TracePackage":
        """Deserialize from JSON bytes."""
        d = json.loads(data.decode("utf-8"))
        return cls(
            trace_id=d["trace_id"],
            timestamp=d["timestamp"],
            source_node=d.get("source_node", ""),
            threat_context=d.get("threat_context"),
            events=d.get("events", []),
            event_count=d.get("event_count", 0),
            window_s=d.get("window_s", DEFAULT_TRACE_WINDOW_S),
            size_bytes=len(data),
        )


@dataclass
class OffloadRequest:
    """A pending offload request awaiting Nexus response."""
    trace_id: str
    context: ThreatContext
    package: TracePackage
    sent_at: float = field(default_factory=time.time)
    timeout_s: float = DEFAULT_TIMEOUT_S
    verdict: Optional[VerdictResult] = None
    completed: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() - self.sent_at > self.timeout_s


# ------------------------------------------------------------------
# Nexus Offloader
# ------------------------------------------------------------------

class NexusOffloader:
    """Packages eBPF traces and routes to Nexus for deep analysis.

    Usage:
        offloader = NexusOffloader(rag_pipeline=rag)
        verdict = offloader.offload(threat_context)
        # Returns immediately with PENDING, or blocks with timeout

    For async usage:
        request = offloader.offload_async(threat_context)
        # ... do other work ...
        verdict = offloader.get_verdict(request.trace_id)

    Transport:
        Currently uses a local callback for Nexus processing.
        Future: HTP mesh transport with PacketType.KERNEL_TELEMETRY.
    """

    def __init__(
        self,
        rag_pipeline: Optional[Any] = None,
        node_id: str = "",
        trace_window_s: float = DEFAULT_TRACE_WINDOW_S,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        nexus_callback: Optional[Callable] = None,
    ):
        """Initialize the offloader.

        Args:
            rag_pipeline: StreamingRAGPipeline for event capture.
            node_id: This node's identifier.
            trace_window_s: Seconds of events to capture per trace.
            timeout_s: Default timeout waiting for Nexus verdict.
            nexus_callback: Optional callback simulating Nexus processing.
                Receives TracePackage, returns VerdictResult.
        """
        self._rag = rag_pipeline
        self._node_id = node_id or self._generate_node_id()
        self._trace_window = trace_window_s
        self._timeout = timeout_s
        self._nexus_callback = nexus_callback

        self._lock = threading.Lock()
        self._pending: Dict[str, OffloadRequest] = {}
        self._completed: List[OffloadRequest] = []

        # Stats
        self._offloads_sent = 0
        self._offloads_completed = 0
        self._offloads_timed_out = 0
        self._total_latency = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def offload(self, context: ThreatContext) -> VerdictResult:
        """Package and send a trace to Nexus, blocking until verdict.

        If no Nexus callback is configured or if the request times out,
        returns a fallback INVESTIGATE verdict.

        Args:
            context: The threat context to analyze.

        Returns:
            VerdictResult from Nexus or fallback.
        """
        start = time.time()

        # Build trace package
        package = self._build_trace_package(context)

        # Try Nexus callback (local or transport)
        if self._nexus_callback is not None:
            try:
                verdict = self._nexus_callback(package)
                if isinstance(verdict, VerdictResult):
                    verdict.latency_ms = (time.time() - start) * 1000
                    self._offloads_sent += 1
                    self._offloads_completed += 1
                    self._total_latency += verdict.latency_ms
                    return verdict
            except Exception as e:
                logger.warning("Nexus callback failed: %s", e)

        # No Nexus available — return investigate verdict
        self._offloads_sent += 1
        self._offloads_timed_out += 1
        return VerdictResult(
            action=VerdictAction.INVESTIGATE,
            confidence=0.3,
            source=VerdictSource.FALLBACK,
            reasoning="Nexus unavailable — manual investigation required",
            source_ip=context.source_ip,
            threat_type=context.event_type,
            severity=context.severity,
            latency_ms=(time.time() - start) * 1000,
        )

    def offload_async(self, context: ThreatContext) -> OffloadRequest:
        """Send a trace to Nexus without blocking.

        Returns an OffloadRequest that can be polled with get_verdict().
        """
        package = self._build_trace_package(context)

        request = OffloadRequest(
            trace_id=package.trace_id,
            context=context,
            package=package,
            timeout_s=self._timeout,
        )

        with self._lock:
            if len(self._pending) >= MAX_PENDING_OFFLOADS:
                # Evict oldest
                oldest_id = min(self._pending, key=lambda k: self._pending[k].sent_at)
                del self._pending[oldest_id]
            self._pending[request.trace_id] = request

        self._offloads_sent += 1

        # Fire callback in background if available
        if self._nexus_callback is not None:
            thread = threading.Thread(
                target=self._process_async,
                args=(request,),
                daemon=True,
            )
            thread.start()

        return request

    def get_verdict(self, trace_id: str) -> Optional[VerdictResult]:
        """Get the verdict for a pending offload, or None if not ready."""
        with self._lock:
            req = self._pending.get(trace_id)
            if req is None:
                return None
            if req.completed:
                self._pending.pop(trace_id, None)
                self._completed.append(req)
                return req.verdict
            if req.is_expired:
                self._pending.pop(trace_id, None)
                self._offloads_timed_out += 1
                return VerdictResult(
                    action=VerdictAction.INVESTIGATE,
                    confidence=0.3,
                    source=VerdictSource.FALLBACK,
                    reasoning="Nexus response timeout",
                    source_ip=req.context.source_ip,
                )
        return None

    def receive_verdict(self, trace_id: str, verdict: VerdictResult) -> bool:
        """Receive a verdict from Nexus (for transport-based usage).

        Args:
            trace_id: The trace ID this verdict corresponds to.
            verdict: The Nexus verdict.

        Returns:
            True if a pending request was matched.
        """
        with self._lock:
            req = self._pending.get(trace_id)
            if req is None:
                return False
            req.verdict = verdict
            req.completed = True
            self._offloads_completed += 1
            return True

    def stats(self) -> Dict[str, Any]:
        """Get offloader statistics."""
        avg_latency = (
            self._total_latency / self._offloads_completed
            if self._offloads_completed > 0 else 0.0
        )
        return {
            "offloads_sent": self._offloads_sent,
            "offloads_completed": self._offloads_completed,
            "offloads_timed_out": self._offloads_timed_out,
            "pending_count": len(self._pending),
            "avg_latency_ms": avg_latency,
            "node_id": self._node_id,
            "trace_window_s": self._trace_window,
        }

    # ------------------------------------------------------------------
    # Internal: Trace Building
    # ------------------------------------------------------------------

    def _build_trace_package(self, context: ThreatContext) -> TracePackage:
        """Build a compact trace package from streaming RAG events."""
        trace_id = self._make_trace_id(context)
        events: List[Dict[str, Any]] = []

        # Query streaming RAG for recent events
        if self._rag is not None:
            try:
                query = f"{context.event_type} {context.source_ip}".strip()
                # Get raw chunks from the store if available
                if hasattr(self._rag, "store") and hasattr(self._rag.store, "search"):
                    query_vec = self._rag.embedder.embed_single(query)
                    chunks = self._rag.store.search(
                        query_embedding=query_vec,
                        k=MAX_EVENTS_PER_TRACE,
                        time_window_s=self._trace_window,
                    )
                    for chunk in chunks:
                        events.append({
                            "ts": chunk.timestamp,
                            "ip": chunk.source_ip,
                            "type": chunk.event_type,
                            "summary": chunk.summary[:200],
                            "count": chunk.raw_count,
                        })
            except Exception as e:
                logger.debug("RAG query for trace failed: %s", e)

        package = TracePackage(
            trace_id=trace_id,
            timestamp=time.time(),
            source_node=self._node_id,
            threat_context=context.signal_data,
            events=events[:MAX_EVENTS_PER_TRACE],
            event_count=len(events),
            window_s=self._trace_window,
        )

        # Check size limit
        data = package.to_bytes()
        if len(data) > MAX_TRACE_SIZE_BYTES:
            # Truncate events to fit
            while len(events) > 1:
                events.pop()
                package.events = events
                package.event_count = len(events)
                data = package.to_bytes()
                if len(data) <= MAX_TRACE_SIZE_BYTES:
                    break

        return package

    # ------------------------------------------------------------------
    # Internal: Async Processing
    # ------------------------------------------------------------------

    def _process_async(self, request: OffloadRequest) -> None:
        """Process an async offload request via callback."""
        try:
            verdict = self._nexus_callback(request.package)
            if isinstance(verdict, VerdictResult):
                with self._lock:
                    request.verdict = verdict
                    request.completed = True
                    self._offloads_completed += 1
                    self._total_latency += verdict.latency_ms
        except Exception as e:
            logger.warning("Async Nexus processing failed: %s", e)

    # ------------------------------------------------------------------
    # Internal: Helpers
    # ------------------------------------------------------------------

    def _make_trace_id(self, context: ThreatContext) -> str:
        """Generate a unique trace ID."""
        data = f"trace-{context.source_ip}-{context.event_type}-{time.time()}"
        return f"tr-{hashlib.sha256(data.encode()).hexdigest()[:12]}"

    def _generate_node_id(self) -> str:
        """Generate a node ID."""
        import socket
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"
        return hashlib.sha256(hostname.encode()).hexdigest()[:8]
