"""
AEGIS Memory — Multi-Layer Persistent Memory

Five memory layers with SQLite persistence:
  1. immediate  — In-context conversation (managed by client.py sessions)
  2. session    — Today's event summaries
  3. behavioral — Per-device learned patterns
  4. institutional — Network knowledge base
  5. threat_intel — Attack patterns and IOCs

Plus: decisions audit trail for all agent actions.
"""

import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Layer names (used as keys throughout the system)
LAYER_SESSION = "session"
LAYER_BEHAVIORAL = "behavioral"
LAYER_INSTITUTIONAL = "institutional"
LAYER_THREAT_INTEL = "threat_intel"
LAYER_STREAMING = "streaming"  # Ephemeral vector store (not persisted to SQLite)

ALL_LAYERS = [LAYER_SESSION, LAYER_BEHAVIORAL, LAYER_INSTITUTIONAL, LAYER_THREAT_INTEL]


@dataclass
class MemoryConfig:
    """Configuration for the memory subsystem."""
    db_path: str = ""  # Empty = auto-detect
    max_session_entries: int = 500
    max_device_profiles: int = 1000
    max_knowledge_entries: int = 2000
    max_threat_entries: int = 5000
    max_decision_entries: int = 10000

    def get_db_path(self) -> str:
        if self.db_path:
            return self.db_path
        # Auto-detect: prefer /app/data in container, else local
        for candidate in [
            "/app/data/aegis_memory.db",
            os.path.expanduser("~/.aegis/memory.db"),
        ]:
            parent = Path(candidate).parent
            if parent.exists() or parent == Path("/app/data"):
                return candidate
        return os.path.expanduser("~/.aegis/memory.db")


@dataclass
class MemoryEntry:
    """A single memory entry for external use."""
    layer: str
    key: str
    value: str
    source: str = "system"
    timestamp: str = ""
    ttl_days: Optional[int] = None


@dataclass
class AuditRecord:
    """An agent decision audit record."""
    id: str = ""
    timestamp: str = ""
    agent: str = ""
    action: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    reasoning: str = ""
    result: str = ""
    approved: bool = False


class MemoryManager:
    """Multi-layer persistent memory backed by SQLite.

    Thread-safe via connection-per-thread pattern.
    """

    def __init__(self, config: Optional[MemoryConfig] = None):
        self._config = config or MemoryConfig()
        self._db_path = self._config.get_db_path()
        self._local = threading.local()
        self._streaming_pipeline = None  # Set via set_streaming_pipeline()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            db_dir = Path(self._db_path).parent
            db_dir.mkdir(parents=True, exist_ok=True)
            self._local.conn = sqlite3.connect(self._db_path, timeout=10)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
        return self._local.conn

    def _init_db(self):
        """Initialize database schema."""
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            schema = schema_path.read_text()
        else:
            logger.warning("schema.sql not found, using inline schema")
            schema = self._inline_schema()

        conn = self._get_conn()
        conn.executescript(schema)
        conn.commit()

    @staticmethod
    def _inline_schema() -> str:
        return """
        CREATE TABLE IF NOT EXISTS aegis_sessions (
            id TEXT PRIMARY KEY, timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            summary TEXT NOT NULL, events_json TEXT NOT NULL DEFAULT '[]',
            ttl_days INTEGER DEFAULT 30);
        CREATE TABLE IF NOT EXISTS aegis_device_profiles (
            mac TEXT PRIMARY KEY, profile_json TEXT NOT NULL DEFAULT '{}',
            confidence REAL NOT NULL DEFAULT 0.0,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS aegis_network_knowledge (
            key TEXT PRIMARY KEY, value TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'system',
            updated_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS aegis_threat_intel (
            threat_hash TEXT PRIMARY KEY, type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'LOW',
            context_json TEXT NOT NULL DEFAULT '{}',
            first_seen TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen TEXT NOT NULL DEFAULT (datetime('now')),
            count INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS aegis_decisions (
            id TEXT PRIMARY KEY, timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            agent TEXT NOT NULL, action TEXT NOT NULL,
            params_json TEXT NOT NULL DEFAULT '{}',
            confidence REAL NOT NULL DEFAULT 0.0,
            reasoning TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '',
            approved INTEGER NOT NULL DEFAULT 0);
        """

    # ------------------------------------------------------------------
    # Store
    # ------------------------------------------------------------------

    def store(
        self,
        layer: str,
        key: str,
        value: str,
        source: str = "system",
        ttl_days: Optional[int] = None,
    ) -> bool:
        """Store a value in the specified memory layer.

        Args:
            layer: One of session, behavioral, institutional, threat_intel.
            key: Unique key within the layer.
            value: Value to store (string or JSON string).
            source: Origin of this memory (agent name, system, user).
            ttl_days: Optional TTL in days for auto-expiry.

        Returns:
            True if stored successfully.
        """
        conn = self._get_conn()
        now = datetime.utcnow().isoformat()

        try:
            if layer == LAYER_SESSION:
                conn.execute(
                    "INSERT OR REPLACE INTO aegis_sessions "
                    "(id, timestamp, summary, events_json, ttl_days) VALUES (?, ?, ?, ?, ?)",
                    (key, now, value, "[]", ttl_days or 30),
                )
            elif layer == LAYER_BEHAVIORAL:
                conn.execute(
                    "INSERT OR REPLACE INTO aegis_device_profiles "
                    "(mac, profile_json, confidence, updated_at) VALUES (?, ?, ?, ?)",
                    (key.upper(), value, 0.5, now),
                )
            elif layer == LAYER_INSTITUTIONAL:
                conn.execute(
                    "INSERT OR REPLACE INTO aegis_network_knowledge "
                    "(key, value, source, updated_at) VALUES (?, ?, ?, ?)",
                    (key, value, source, now),
                )
            elif layer == LAYER_THREAT_INTEL:
                threat_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
                # Upsert: increment count if exists
                existing = conn.execute(
                    "SELECT count FROM aegis_threat_intel WHERE threat_hash = ?",
                    (threat_hash,),
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE aegis_threat_intel SET last_seen = ?, count = count + 1, "
                        "context_json = ? WHERE threat_hash = ?",
                        (now, value, threat_hash),
                    )
                else:
                    conn.execute(
                        "INSERT INTO aegis_threat_intel "
                        "(threat_hash, type, severity, context_json, first_seen, last_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (threat_hash, key, "MEDIUM", value, now, now),
                    )
            else:
                logger.warning("Unknown memory layer: %s", layer)
                return False

            conn.commit()
            return True

        except sqlite3.Error as e:
            logger.error("Memory store error [%s/%s]: %s", layer, key, e)
            return False

    # ------------------------------------------------------------------
    # Recall
    # ------------------------------------------------------------------

    def recall(self, layer: str, key: str) -> Optional[str]:
        """Recall a value from a specific memory layer.

        Args:
            layer: Memory layer to search.
            key: Key to look up.

        Returns:
            Value string if found, None otherwise.
        """
        conn = self._get_conn()

        try:
            if layer == LAYER_SESSION:
                row = conn.execute(
                    "SELECT summary FROM aegis_sessions WHERE id = ?", (key,)
                ).fetchone()
                return row["summary"] if row else None

            elif layer == LAYER_BEHAVIORAL:
                row = conn.execute(
                    "SELECT profile_json FROM aegis_device_profiles WHERE mac = ?",
                    (key.upper(),),
                ).fetchone()
                return row["profile_json"] if row else None

            elif layer == LAYER_INSTITUTIONAL:
                row = conn.execute(
                    "SELECT value FROM aegis_network_knowledge WHERE key = ?", (key,)
                ).fetchone()
                return row["value"] if row else None

            elif layer == LAYER_THREAT_INTEL:
                threat_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
                row = conn.execute(
                    "SELECT context_json FROM aegis_threat_intel WHERE threat_hash = ?",
                    (threat_hash,),
                ).fetchone()
                return row["context_json"] if row else None

        except sqlite3.Error as e:
            logger.error("Memory recall error [%s/%s]: %s", layer, key, e)

        return None

    def recall_context(
        self,
        layers: Optional[List[str]] = None,
        max_tokens: int = 500,
    ) -> str:
        """Build a context string from memory layers for LLM injection.

        Retrieves the most recent/relevant entries from each layer
        and formats them as a concise context block.

        Args:
            layers: Which layers to include (default: all).
            max_tokens: Approximate max tokens (chars / 4).

        Returns:
            Formatted context string.
        """
        if layers is None:
            layers = ALL_LAYERS

        conn = self._get_conn()
        parts = []
        max_chars = max_tokens * 4  # Rough chars-to-tokens ratio
        chars_used = 0

        try:
            # Session: recent summaries
            if LAYER_SESSION in layers and chars_used < max_chars:
                rows = conn.execute(
                    "SELECT summary FROM aegis_sessions "
                    "ORDER BY timestamp DESC LIMIT 3"
                ).fetchall()
                if rows:
                    summaries = [r["summary"] for r in rows]
                    block = "Recent Activity:\n" + "\n".join(f"- {s}" for s in summaries)
                    parts.append(block)
                    chars_used += len(block)

            # Behavioral: known device patterns
            if LAYER_BEHAVIORAL in layers and chars_used < max_chars:
                rows = conn.execute(
                    "SELECT mac, profile_json FROM aegis_device_profiles "
                    "WHERE confidence > 0.3 ORDER BY updated_at DESC LIMIT 5"
                ).fetchall()
                if rows:
                    lines = ["Known Devices:"]
                    for r in rows:
                        try:
                            profile = json.loads(r["profile_json"])
                            name = profile.get("name", r["mac"])
                            dtype = profile.get("type", "unknown")
                            lines.append(f"- {name} ({dtype})")
                        except json.JSONDecodeError:
                            lines.append(f"- {r['mac']}")
                    block = "\n".join(lines)
                    parts.append(block)
                    chars_used += len(block)

            # Institutional: network knowledge
            if LAYER_INSTITUTIONAL in layers and chars_used < max_chars:
                rows = conn.execute(
                    "SELECT key, value FROM aegis_network_knowledge "
                    "ORDER BY updated_at DESC LIMIT 5"
                ).fetchall()
                if rows:
                    lines = ["Network Knowledge:"]
                    for r in rows:
                        val = r["value"][:100]  # Truncate long values
                        lines.append(f"- {r['key']}: {val}")
                    block = "\n".join(lines)
                    parts.append(block)
                    chars_used += len(block)

            # Threat intel: recent threats
            if LAYER_THREAT_INTEL in layers and chars_used < max_chars:
                rows = conn.execute(
                    "SELECT type, severity, count FROM aegis_threat_intel "
                    "ORDER BY last_seen DESC LIMIT 5"
                ).fetchall()
                if rows:
                    lines = ["Threat Intelligence:"]
                    for r in rows:
                        lines.append(
                            f"- {r['type']} [{r['severity']}] (seen {r['count']}x)"
                        )
                    block = "\n".join(lines)
                    parts.append(block)
                    chars_used += len(block)

        except sqlite3.Error as e:
            logger.error("Memory recall_context error: %s", e)

        return "\n\n".join(parts) if parts else ""

    # ------------------------------------------------------------------
    # Streaming RAG (Neuro-Kernel Layer 2)
    # ------------------------------------------------------------------

    def set_streaming_pipeline(self, pipeline) -> None:
        """Register the Neuro-Kernel streaming RAG pipeline.

        Args:
            pipeline: A StreamingRAGPipeline instance (or any object with
                      a query(question, k) method).
        """
        self._streaming_pipeline = pipeline
        logger.info("Streaming RAG pipeline registered with memory")

    def recall_streaming_context(
        self,
        query: str,
        time_window_s: float = 60.0,
        k: int = 10,
    ) -> str:
        """Search the streaming RAG vector store for recent kernel events.

        This is the 6th memory layer — ephemeral situational awareness
        backed by the vector store rather than SQLite.

        Args:
            query: Natural language query (e.g., "suspicious connections
                   from 10.200.0.45").
            time_window_s: How far back to search (seconds).
            k: Number of top results.

        Returns:
            Formatted context string for LLM injection, or empty string
            if the streaming pipeline is not available.
        """
        if self._streaming_pipeline is None:
            return ""
        try:
            return self._streaming_pipeline.query(query, k=k)
        except Exception as e:
            logger.error("Streaming RAG query error: %s", e)
            return ""

    # ------------------------------------------------------------------
    # Forget / Decay
    # ------------------------------------------------------------------

    def forget(self, layer: str, key: str) -> bool:
        """Remove a specific entry from a memory layer."""
        conn = self._get_conn()
        table_map = {
            LAYER_SESSION: ("aegis_sessions", "id"),
            LAYER_BEHAVIORAL: ("aegis_device_profiles", "mac"),
            LAYER_INSTITUTIONAL: ("aegis_network_knowledge", "key"),
            LAYER_THREAT_INTEL: ("aegis_threat_intel", "threat_hash"),
        }
        table_info = table_map.get(layer)
        if not table_info:
            return False

        table, col = table_info
        actual_key = key
        if layer == LAYER_THREAT_INTEL:
            actual_key = hashlib.sha256(key.encode()).hexdigest()[:16]
        elif layer == LAYER_BEHAVIORAL:
            actual_key = key.upper()

        try:
            conn.execute(f"DELETE FROM {table} WHERE {col} = ?", (actual_key,))
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("Memory forget error [%s/%s]: %s", layer, key, e)
            return False

    def decay(self, layer: str, max_age_days: int = 30) -> int:
        """Remove old entries from a memory layer.

        Args:
            layer: Memory layer to clean.
            max_age_days: Remove entries older than this.

        Returns:
            Number of entries removed.
        """
        conn = self._get_conn()
        cutoff = (datetime.utcnow() - timedelta(days=max_age_days)).isoformat()
        removed = 0

        try:
            if layer == LAYER_SESSION:
                cursor = conn.execute(
                    "DELETE FROM aegis_sessions WHERE timestamp < ?", (cutoff,)
                )
                removed = cursor.rowcount
            elif layer == LAYER_BEHAVIORAL:
                cursor = conn.execute(
                    "DELETE FROM aegis_device_profiles WHERE updated_at < ?", (cutoff,)
                )
                removed = cursor.rowcount
            elif layer == LAYER_INSTITUTIONAL:
                cursor = conn.execute(
                    "DELETE FROM aegis_network_knowledge WHERE updated_at < ?", (cutoff,)
                )
                removed = cursor.rowcount
            elif layer == LAYER_THREAT_INTEL:
                cursor = conn.execute(
                    "DELETE FROM aegis_threat_intel WHERE last_seen < ?", (cutoff,)
                )
                removed = cursor.rowcount

            conn.commit()
            if removed > 0:
                logger.info("Memory decay: removed %d entries from %s", removed, layer)

        except sqlite3.Error as e:
            logger.error("Memory decay error [%s]: %s", layer, e)

        return removed

    def decay_all(self, max_age_days: int = 30) -> Dict[str, int]:
        """Run decay on all memory layers."""
        results = {}
        for layer in ALL_LAYERS:
            results[layer] = self.decay(layer, max_age_days)
        return results

    # ------------------------------------------------------------------
    # Audit Trail
    # ------------------------------------------------------------------

    def log_decision(
        self,
        agent: str,
        action: str,
        params: Optional[Dict[str, Any]] = None,
        confidence: float = 0.0,
        reasoning: str = "",
        result: str = "",
        approved: bool = False,
    ) -> str:
        """Log an agent decision to the audit trail.

        Returns:
            Decision ID.
        """
        decision_id = str(uuid.uuid4())[:12]
        conn = self._get_conn()

        try:
            conn.execute(
                "INSERT INTO aegis_decisions "
                "(id, timestamp, agent, action, params_json, confidence, "
                "reasoning, result, approved) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    decision_id,
                    datetime.utcnow().isoformat(),
                    agent,
                    action,
                    json.dumps(params or {}),
                    confidence,
                    reasoning,
                    result,
                    1 if approved else 0,
                ),
            )
            conn.commit()
        except sqlite3.Error as e:
            logger.error("Decision log error: %s", e)

        return decision_id

    def get_recent_decisions(
        self,
        agent: Optional[str] = None,
        limit: int = 20,
    ) -> List[AuditRecord]:
        """Get recent decisions from the audit trail."""
        conn = self._get_conn()
        records = []

        try:
            if agent:
                rows = conn.execute(
                    "SELECT * FROM aegis_decisions WHERE agent = ? "
                    "ORDER BY timestamp DESC LIMIT ?",
                    (agent, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM aegis_decisions "
                    "ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ).fetchall()

            for row in rows:
                try:
                    params = json.loads(row["params_json"])
                except json.JSONDecodeError:
                    params = {}

                records.append(AuditRecord(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    agent=row["agent"],
                    action=row["action"],
                    params=params,
                    confidence=row["confidence"],
                    reasoning=row["reasoning"],
                    result=row["result"],
                    approved=bool(row["approved"]),
                ))

        except sqlite3.Error as e:
            logger.error("Decision recall error: %s", e)

        return records

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, int]:
        """Get entry counts per layer."""
        conn = self._get_conn()
        stats = {}

        tables = {
            LAYER_SESSION: "aegis_sessions",
            LAYER_BEHAVIORAL: "aegis_device_profiles",
            LAYER_INSTITUTIONAL: "aegis_network_knowledge",
            LAYER_THREAT_INTEL: "aegis_threat_intel",
            "decisions": "aegis_decisions",
        }

        for layer, table in tables.items():
            try:
                row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
                stats[layer] = row["cnt"] if row else 0
            except sqlite3.Error:
                stats[layer] = 0

        return stats

    def close(self):
        """Close the thread-local database connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# ------------------------------------------------------------------
# Singleton
# ------------------------------------------------------------------

_memory: Optional[MemoryManager] = None
_memory_lock = threading.Lock()


def get_memory_manager(config: Optional[MemoryConfig] = None) -> MemoryManager:
    """Get or create the global MemoryManager singleton."""
    global _memory
    if _memory is None:
        with _memory_lock:
            if _memory is None:
                _memory = MemoryManager(config)
    return _memory
