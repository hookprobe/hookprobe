"""
Event Chunker — Converts raw eBPF events into embeddable text chunks.

The key insight: we do NOT embed individual syscalls. At high event rates,
that is impossible. Instead, we aggregate into configurable time windows
per (source_ip, event_type) and produce natural-language summaries.

Example output chunk:
    "10.200.0.45 made 47 TCP connections to 5 unique destinations
    in 1s, 3 to port 443, 2 to port 80, with 12 failed DNS lookups"

These text chunks are then embedded into 384-dim vectors for similarity
search when the LLM needs situational context.

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .types import SensorEvent, SensorType

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Data Types
# ------------------------------------------------------------------

@dataclass
class EventChunk:
    """A single embeddable chunk representing one aggregation window."""
    timestamp: float
    source_ip: str
    event_type: str              # "network", "syscall", "file", "dns"
    summary: str                 # Natural language summary
    raw_count: int               # Number of raw events aggregated
    key_metrics: Dict[str, float] = field(default_factory=dict)
    embedding: Optional[List[float]] = None

    @property
    def chunk_id(self) -> str:
        return f"{self.source_ip}:{self.event_type}:{int(self.timestamp)}"


# ------------------------------------------------------------------
# Aggregation Bucket
# ------------------------------------------------------------------

@dataclass
class _AggBucket:
    """Internal aggregation bucket for one (source_ip, event_type) window."""
    source_ip: str
    event_type: SensorType
    window_start: float
    count: int = 0
    dest_ips: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    ports: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    protocols: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    processes: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_bytes: int = 0
    metadata_agg: Dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------
# Protocol Names
# ------------------------------------------------------------------

_PROTO_NAMES = {
    1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6",
}


# ------------------------------------------------------------------
# Event Chunker
# ------------------------------------------------------------------

class EventChunker:
    """Aggregates raw SensorEvents into embeddable EventChunks.

    Usage:
        chunker = EventChunker(window_s=1.0)
        chunker.ingest(event1)
        chunker.ingest(event2)
        chunks = chunker.flush()  # Returns completed chunks
    """

    DEFAULT_WINDOW_S = 1.0
    MAX_BUCKETS = 10000  # Backpressure: max concurrent aggregation buckets

    def __init__(self, window_s: float = DEFAULT_WINDOW_S):
        self._window_s = window_s
        self._buckets: Dict[str, _AggBucket] = {}
        self._events_ingested: int = 0
        self._chunks_produced: int = 0

    def ingest(self, event: SensorEvent) -> None:
        """Add a sensor event to the current aggregation window.

        Events are bucketed by (source_ip, sensor_type). When flush()
        is called, all completed windows are returned as chunks.
        """
        key = f"{event.source_ip}:{event.sensor_type.value}"
        now = event.timestamp

        bucket = self._buckets.get(key)
        if bucket is None or (now - bucket.window_start) >= self._window_s:
            # Start new bucket (old one will be flushed)
            if len(self._buckets) >= self.MAX_BUCKETS:
                # Backpressure: evict oldest bucket
                oldest_key = min(self._buckets, key=lambda k: self._buckets[k].window_start)
                del self._buckets[oldest_key]

            bucket = _AggBucket(
                source_ip=event.source_ip,
                event_type=event.sensor_type,
                window_start=now,
            )
            self._buckets[key] = bucket

        # Aggregate into bucket
        bucket.count += 1
        if event.dest_ip:
            bucket.dest_ips[event.dest_ip] += 1
        if event.port:
            bucket.ports[event.port] += 1
        if event.protocol:
            bucket.protocols[event.protocol] += 1
        if event.comm:
            bucket.processes[event.comm] += 1
        bucket.total_bytes += event.payload_len

        # Merge metadata
        for k, v in event.metadata.items():
            if k not in bucket.metadata_agg:
                bucket.metadata_agg[k] = []
            if isinstance(bucket.metadata_agg[k], list) and len(bucket.metadata_agg[k]) < 20:
                bucket.metadata_agg[k].append(v)

        self._events_ingested += 1

    def ingest_batch(self, events: List[SensorEvent]) -> None:
        """Ingest a batch of events."""
        for event in events:
            self.ingest(event)

    def flush(self, now: Optional[float] = None) -> List[EventChunk]:
        """Flush completed aggregation windows as EventChunks.

        Returns chunks for windows whose time has elapsed.
        Keeps active (current) windows.
        """
        now = now or time.time()
        cutoff = now - self._window_s
        completed = []
        active_keys = []

        for key, bucket in self._buckets.items():
            if bucket.window_start <= cutoff:
                chunk = self._bucket_to_chunk(bucket)
                completed.append(chunk)
            else:
                active_keys.append(key)

        # Remove completed buckets
        self._buckets = {k: self._buckets[k] for k in active_keys}
        self._chunks_produced += len(completed)

        return completed

    def flush_all(self) -> List[EventChunk]:
        """Flush ALL buckets regardless of window completion."""
        chunks = []
        for bucket in self._buckets.values():
            chunks.append(self._bucket_to_chunk(bucket))
        self._buckets.clear()
        self._chunks_produced += len(chunks)
        return chunks

    def stats(self) -> Dict[str, Any]:
        """Get chunker statistics."""
        return {
            "events_ingested": self._events_ingested,
            "chunks_produced": self._chunks_produced,
            "active_buckets": len(self._buckets),
            "window_s": self._window_s,
        }

    # ------------------------------------------------------------------
    # Internal: Bucket → Chunk
    # ------------------------------------------------------------------

    def _bucket_to_chunk(self, bucket: _AggBucket) -> EventChunk:
        """Convert an aggregation bucket to a natural-language chunk."""
        summary = self._generate_summary(bucket)
        metrics = self._extract_metrics(bucket)

        return EventChunk(
            timestamp=bucket.window_start,
            source_ip=bucket.source_ip,
            event_type=bucket.event_type.value,
            summary=summary,
            raw_count=bucket.count,
            key_metrics=metrics,
        )

    def _generate_summary(self, bucket: _AggBucket) -> str:
        """Generate a natural-language summary of the aggregation bucket."""
        parts = []
        ip = bucket.source_ip or "unknown"
        count = bucket.count

        if bucket.event_type == SensorType.NETWORK:
            parts.append(f"{ip} generated {count} network events")

            if bucket.dest_ips:
                n_dests = len(bucket.dest_ips)
                parts.append(f"to {n_dests} unique destination{'s' if n_dests != 1 else ''}")

            if bucket.protocols:
                proto_strs = []
                for proto, n in sorted(bucket.protocols.items(), key=lambda x: -x[1])[:3]:
                    name = _PROTO_NAMES.get(proto, f"proto-{proto}")
                    proto_strs.append(f"{n} {name}")
                parts.append(f"({', '.join(proto_strs)})")

            if bucket.ports:
                top_ports = sorted(bucket.ports.items(), key=lambda x: -x[1])[:5]
                port_strs = [f"port {p}({n})" for p, n in top_ports]
                parts.append(f"top ports: {', '.join(port_strs)}")

        elif bucket.event_type == SensorType.DNS:
            parts.append(f"{ip} made {count} DNS queries")
            if bucket.metadata_agg.get("domains"):
                raw_domains = bucket.metadata_agg["domains"]
                # Flatten: metadata values may be strings or lists
                flat = []
                for d in raw_domains:
                    if isinstance(d, list):
                        flat.extend(d)
                    else:
                        flat.append(d)
                n_unique = len(set(flat))
                parts.append(f"for {n_unique} unique domain{'s' if n_unique != 1 else ''}")

        elif bucket.event_type == SensorType.SYSCALL:
            parts.append(f"{ip} (PID area) generated {count} syscall events")
            if bucket.processes:
                top_procs = sorted(bucket.processes.items(), key=lambda x: -x[1])[:3]
                proc_strs = [f"{name}({n})" for name, n in top_procs]
                parts.append(f"processes: {', '.join(proc_strs)}")

        elif bucket.event_type == SensorType.FILE:
            parts.append(f"{ip} triggered {count} file access events")
            if bucket.processes:
                top_procs = sorted(bucket.processes.items(), key=lambda x: -x[1])[:3]
                proc_strs = [f"{name}({n})" for name, n in top_procs]
                parts.append(f"by: {', '.join(proc_strs)}")

        elif bucket.event_type == SensorType.PROCESS:
            parts.append(f"{ip} spawned {count} process events")
            if bucket.processes:
                names = list(bucket.processes.keys())[:5]
                parts.append(f"including: {', '.join(names)}")

        else:
            parts.append(f"{ip}: {count} events of type {bucket.event_type.value}")

        if bucket.total_bytes > 0:
            if bucket.total_bytes > 1024 * 1024:
                parts.append(f"({bucket.total_bytes / (1024*1024):.1f} MB)")
            elif bucket.total_bytes > 1024:
                parts.append(f"({bucket.total_bytes / 1024:.1f} KB)")
            else:
                parts.append(f"({bucket.total_bytes} bytes)")

        window_str = f"in {self._window_s:.0f}s window"
        return f"{' '.join(parts)} {window_str}"

    def _extract_metrics(self, bucket: _AggBucket) -> Dict[str, float]:
        """Extract numeric metrics from a bucket for filtering."""
        return {
            "event_count": float(bucket.count),
            "unique_dests": float(len(bucket.dest_ips)),
            "unique_ports": float(len(bucket.ports)),
            "total_bytes": float(bucket.total_bytes),
            "unique_processes": float(len(bucket.processes)),
        }
