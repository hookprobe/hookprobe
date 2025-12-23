"""
SLA AI Database Operations

SQLite-based storage for metrics, predictions, and model weights.
Implements rolling retention and efficient querying.
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import asdict
import threading


class SLAAIDatabase:
    """
    SQLite database for SLA AI metrics and predictions.

    Features:
        - Rolling 7-day retention for metrics
        - Efficient time-series queries
        - Thread-safe operations
        - Automatic schema migrations
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._local = threading.local()

        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Initialize schema
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(
                self.db_path,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_schema(self) -> None:
        """Initialize database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Schema version tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )
        """)

        # Check current version
        cursor.execute("SELECT MAX(version) FROM schema_version")
        row = cursor.fetchone()
        current_version = row[0] if row[0] else 0

        if current_version < self.SCHEMA_VERSION:
            self._apply_schema(cursor)
            cursor.execute(
                "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
                (self.SCHEMA_VERSION,),
            )
            conn.commit()

    def _apply_schema(self, cursor: sqlite3.Cursor) -> None:
        """Apply database schema."""
        # WAN metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wan_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                interface TEXT NOT NULL,
                rtt_ms REAL,
                jitter_ms REAL,
                packet_loss_pct REAL,
                signal_rssi_dbm INTEGER,
                signal_rsrp_dbm INTEGER,
                signal_rsrq_db INTEGER,
                network_type TEXT,
                dns_response_ms REAL,
                http_response_ms REAL,
                interface_errors INTEGER,
                gateway_arp_ms REAL,
                bytes_sent INTEGER,
                bytes_received INTEGER
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_metrics_ts ON wan_metrics(timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_metrics_iface ON wan_metrics(interface)"
        )

        # Predictions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                interface TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                features_json TEXT,
                actual_outcome TEXT,
                outcome_timestamp DATETIME
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_pred_ts ON predictions(timestamp)"
        )

        # Failover events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS failover_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                from_interface TEXT NOT NULL,
                to_interface TEXT NOT NULL,
                trigger TEXT NOT NULL,
                prediction_lead_time_s REAL,
                recovery_time_s REAL,
                data_loss_bytes INTEGER,
                details_json TEXT
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_failover_ts ON failover_events(timestamp)"
        )

        # Metered usage table (daily aggregation)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metered_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE NOT NULL,
                interface TEXT NOT NULL,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_received INTEGER NOT NULL DEFAULT 0,
                estimated_cost REAL DEFAULT 0,
                UNIQUE(date, interface)
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_usage_date ON metered_usage(date)"
        )

        # LSTM model weights table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS model_weights (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                interface TEXT NOT NULL,
                model_version TEXT NOT NULL,
                weights BLOB NOT NULL,
                training_samples INTEGER,
                accuracy REAL,
                metadata_json TEXT
            )
        """)

        # DNS health table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dns_health (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                provider TEXT NOT NULL,
                server TEXT NOT NULL,
                response_ms REAL,
                success INTEGER NOT NULL,
                error TEXT
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_health(timestamp)"
        )

        # SLA state history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sla_state_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                state TEXT NOT NULL,
                active_interface TEXT,
                primary_health_score REAL,
                backup_health_score REAL,
                recommendation TEXT,
                details_json TEXT
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_state_ts ON sla_state_history(timestamp)"
        )

    # ==================== Metrics Operations ====================

    def store_metrics(self, metrics: Dict[str, Any]) -> int:
        """
        Store WAN metrics.

        Args:
            metrics: Dictionary containing metric values

        Returns:
            Row ID of inserted record
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO wan_metrics (
                timestamp, interface, rtt_ms, jitter_ms, packet_loss_pct,
                signal_rssi_dbm, signal_rsrp_dbm, signal_rsrq_db, network_type,
                dns_response_ms, http_response_ms, interface_errors,
                gateway_arp_ms, bytes_sent, bytes_received
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                metrics.get("timestamp", datetime.now()),
                metrics.get("interface", ""),
                metrics.get("rtt_ms"),
                metrics.get("jitter_ms"),
                metrics.get("packet_loss_pct"),
                metrics.get("signal_rssi_dbm"),
                metrics.get("signal_rsrp_dbm"),
                metrics.get("signal_rsrq_db"),
                metrics.get("network_type"),
                metrics.get("dns_response_ms"),
                metrics.get("http_response_ms"),
                metrics.get("interface_errors"),
                metrics.get("gateway_arp_ms"),
                metrics.get("bytes_sent"),
                metrics.get("bytes_received"),
            ),
        )
        conn.commit()
        return cursor.lastrowid

    def get_recent_metrics(
        self, interface: str, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get recent metrics for an interface.

        Args:
            interface: Interface name
            limit: Maximum number of records

        Returns:
            List of metric dictionaries
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM wan_metrics
            WHERE interface = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (interface, limit),
        )

        return [dict(row) for row in cursor.fetchall()]

    def get_metrics_window(
        self, interface: str, window_size: int
    ) -> List[Dict[str, Any]]:
        """
        Get the most recent N metrics for prediction.

        Args:
            interface: Interface name
            window_size: Number of samples to retrieve

        Returns:
            List of metric dictionaries (oldest first)
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM (
                SELECT * FROM wan_metrics
                WHERE interface = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ) ORDER BY timestamp ASC
            """,
            (interface, window_size),
        )

        return [dict(row) for row in cursor.fetchall()]

    def cleanup_old_metrics(self, retention_days: int = 7) -> int:
        """
        Remove metrics older than retention period.

        Args:
            retention_days: Number of days to retain

        Returns:
            Number of deleted rows
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now() - timedelta(days=retention_days)

        cursor.execute(
            "DELETE FROM wan_metrics WHERE timestamp < ?",
            (cutoff,),
        )
        deleted = cursor.rowcount
        conn.commit()

        return deleted

    # ==================== Prediction Operations ====================

    def store_prediction(
        self,
        interface: str,
        prediction: str,
        confidence: float,
        features: Optional[Dict] = None,
    ) -> int:
        """
        Store a prediction for later validation.

        Args:
            interface: Interface name
            prediction: Predicted state (healthy, degraded, failure)
            confidence: Prediction confidence (0-1)
            features: Feature values used for prediction

        Returns:
            Row ID of inserted record
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO predictions (
                timestamp, interface, prediction, confidence, features_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                datetime.now(),
                interface,
                prediction,
                confidence,
                json.dumps(features) if features else None,
            ),
        )
        conn.commit()
        return cursor.lastrowid

    def update_prediction_outcome(
        self, prediction_id: int, actual_outcome: str
    ) -> None:
        """
        Update a prediction with the actual outcome.

        Args:
            prediction_id: ID of prediction to update
            actual_outcome: What actually happened
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE predictions
            SET actual_outcome = ?, outcome_timestamp = ?
            WHERE id = ?
            """,
            (actual_outcome, datetime.now(), prediction_id),
        )
        conn.commit()

    def get_training_data(
        self, interface: str, min_samples: int = 1000
    ) -> List[Tuple[Dict, str]]:
        """
        Get labeled prediction data for training.

        Args:
            interface: Interface name
            min_samples: Minimum samples required

        Returns:
            List of (features, outcome) tuples
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT features_json, actual_outcome
            FROM predictions
            WHERE interface = ?
              AND actual_outcome IS NOT NULL
              AND features_json IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (interface, min_samples * 2),  # Get more for potential filtering
        )

        results = []
        for row in cursor.fetchall():
            try:
                features = json.loads(row["features_json"])
                results.append((features, row["actual_outcome"]))
            except (json.JSONDecodeError, KeyError):
                continue

        return results[:min_samples]

    def get_prediction_accuracy(
        self, interface: str, days: int = 7
    ) -> Dict[str, float]:
        """
        Calculate prediction accuracy over time period.

        Args:
            interface: Interface name
            days: Number of days to analyze

        Returns:
            Dictionary with accuracy metrics
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now() - timedelta(days=days)

        cursor.execute(
            """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN prediction = actual_outcome THEN 1 ELSE 0 END) as correct,
                SUM(CASE WHEN prediction = 'failure' AND actual_outcome = 'failure' THEN 1 ELSE 0 END) as true_positives,
                SUM(CASE WHEN prediction = 'failure' AND actual_outcome != 'failure' THEN 1 ELSE 0 END) as false_positives,
                SUM(CASE WHEN prediction != 'failure' AND actual_outcome = 'failure' THEN 1 ELSE 0 END) as false_negatives
            FROM predictions
            WHERE interface = ?
              AND timestamp > ?
              AND actual_outcome IS NOT NULL
            """,
            (interface, cutoff),
        )

        row = cursor.fetchone()
        total = row["total"] or 0
        correct = row["correct"] or 0
        tp = row["true_positives"] or 0
        fp = row["false_positives"] or 0
        fn = row["false_negatives"] or 0

        accuracy = correct / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "total_predictions": total,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fp / total if total > 0 else 0,
        }

    # ==================== Failover Events ====================

    def store_failover_event(
        self,
        from_interface: str,
        to_interface: str,
        trigger: str,
        prediction_lead_time_s: Optional[float] = None,
        details: Optional[Dict] = None,
    ) -> int:
        """
        Record a failover event.

        Args:
            from_interface: Source interface
            to_interface: Target interface
            trigger: What triggered failover (failure, prediction, manual)
            prediction_lead_time_s: How early we predicted (if applicable)
            details: Additional details

        Returns:
            Row ID of inserted record
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO failover_events (
                timestamp, from_interface, to_interface, trigger,
                prediction_lead_time_s, details_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(),
                from_interface,
                to_interface,
                trigger,
                prediction_lead_time_s,
                json.dumps(details) if details else None,
            ),
        )
        conn.commit()
        return cursor.lastrowid

    def update_failover_recovery(
        self, event_id: int, recovery_time_s: float, data_loss_bytes: int = 0
    ) -> None:
        """Update failover event with recovery metrics."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE failover_events
            SET recovery_time_s = ?, data_loss_bytes = ?
            WHERE id = ?
            """,
            (recovery_time_s, data_loss_bytes, event_id),
        )
        conn.commit()

    def get_failover_stats(self, days: int = 30) -> Dict[str, Any]:
        """Get failover statistics for time period."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now() - timedelta(days=days)

        cursor.execute(
            """
            SELECT
                COUNT(*) as total_failovers,
                AVG(recovery_time_s) as avg_recovery_time_s,
                MIN(recovery_time_s) as min_recovery_time_s,
                MAX(recovery_time_s) as max_recovery_time_s,
                SUM(data_loss_bytes) as total_data_loss_bytes,
                AVG(prediction_lead_time_s) as avg_prediction_lead_time_s
            FROM failover_events
            WHERE timestamp > ?
            """,
            (cutoff,),
        )

        row = cursor.fetchone()
        return dict(row) if row else {}

    # ==================== Cost Tracking ====================

    def update_metered_usage(
        self, interface: str, bytes_sent: int, bytes_received: int
    ) -> None:
        """
        Update daily metered usage for an interface.

        Args:
            interface: Interface name
            bytes_sent: Bytes sent (delta)
            bytes_received: Bytes received (delta)
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        today = datetime.now().date()

        cursor.execute(
            """
            INSERT INTO metered_usage (date, interface, bytes_sent, bytes_received)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(date, interface) DO UPDATE SET
                bytes_sent = bytes_sent + excluded.bytes_sent,
                bytes_received = bytes_received + excluded.bytes_received
            """,
            (today, interface, bytes_sent, bytes_received),
        )
        conn.commit()

    def get_usage_summary(
        self, interface: str, days: int = 30
    ) -> Dict[str, Any]:
        """Get usage summary for metered interface."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now().date() - timedelta(days=days)

        cursor.execute(
            """
            SELECT
                SUM(bytes_sent) as total_bytes_sent,
                SUM(bytes_received) as total_bytes_received,
                SUM(estimated_cost) as total_cost,
                COUNT(DISTINCT date) as days_used
            FROM metered_usage
            WHERE interface = ? AND date > ?
            """,
            (interface, cutoff),
        )

        row = cursor.fetchone()
        return dict(row) if row else {}

    def get_daily_usage(self, interface: str) -> Dict[str, int]:
        """Get today's usage for interface."""
        conn = self._get_connection()
        cursor = conn.cursor()

        today = datetime.now().date()

        cursor.execute(
            """
            SELECT bytes_sent, bytes_received
            FROM metered_usage
            WHERE interface = ? AND date = ?
            """,
            (interface, today),
        )

        row = cursor.fetchone()
        if row:
            return {
                "bytes_sent": row["bytes_sent"],
                "bytes_received": row["bytes_received"],
            }
        return {"bytes_sent": 0, "bytes_received": 0}

    # ==================== Model Weights ====================

    def save_model_weights(
        self,
        interface: str,
        version: str,
        weights: bytes,
        training_samples: int,
        accuracy: float,
        metadata: Optional[Dict] = None,
    ) -> int:
        """Save LSTM model weights."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO model_weights (
                timestamp, interface, model_version, weights,
                training_samples, accuracy, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(),
                interface,
                version,
                weights,
                training_samples,
                accuracy,
                json.dumps(metadata) if metadata else None,
            ),
        )
        conn.commit()
        return cursor.lastrowid

    def get_latest_model_weights(
        self, interface: str
    ) -> Optional[Tuple[bytes, str, float]]:
        """Get latest model weights for interface."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT weights, model_version, accuracy
            FROM model_weights
            WHERE interface = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (interface,),
        )

        row = cursor.fetchone()
        if row:
            return (row["weights"], row["model_version"], row["accuracy"])
        return None

    # ==================== DNS Health ====================

    def store_dns_health(
        self,
        provider: str,
        server: str,
        response_ms: Optional[float],
        success: bool,
        error: Optional[str] = None,
    ) -> None:
        """Store DNS health check result."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO dns_health (timestamp, provider, server, response_ms, success, error)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (datetime.now(), provider, server, response_ms, 1 if success else 0, error),
        )
        conn.commit()

    def get_dns_health_summary(
        self, hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Get DNS health summary by provider."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now() - timedelta(hours=hours)

        cursor.execute(
            """
            SELECT
                provider,
                server,
                AVG(response_ms) as avg_response_ms,
                MIN(response_ms) as min_response_ms,
                MAX(response_ms) as max_response_ms,
                SUM(success) * 100.0 / COUNT(*) as success_rate,
                COUNT(*) as check_count
            FROM dns_health
            WHERE timestamp > ?
            GROUP BY provider, server
            ORDER BY avg_response_ms ASC
            """,
            (cutoff,),
        )

        return [dict(row) for row in cursor.fetchall()]

    # ==================== State History ====================

    def store_state(
        self,
        state: str,
        active_interface: str,
        primary_health: float,
        backup_health: float,
        recommendation: str,
        details: Optional[Dict] = None,
    ) -> None:
        """Store SLA state for history."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO sla_state_history (
                timestamp, state, active_interface, primary_health_score,
                backup_health_score, recommendation, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(),
                state,
                active_interface,
                primary_health,
                backup_health,
                recommendation,
                json.dumps(details) if details else None,
            ),
        )
        conn.commit()

    def get_uptime_stats(self, days: int = 30) -> Dict[str, Any]:
        """Calculate uptime statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now() - timedelta(days=days)

        # Get total time and time in each state
        cursor.execute(
            """
            SELECT
                state,
                COUNT(*) as count
            FROM sla_state_history
            WHERE timestamp > ?
            GROUP BY state
            """,
            (cutoff,),
        )

        state_counts = {row["state"]: row["count"] for row in cursor.fetchall()}
        total = sum(state_counts.values())

        if total == 0:
            return {"uptime_pct": 100.0, "states": {}}

        # Calculate uptime (PRIMARY_ACTIVE + BACKUP_ACTIVE = uptime)
        uptime_count = state_counts.get("PRIMARY_ACTIVE", 0) + state_counts.get(
            "BACKUP_ACTIVE", 0
        )
        uptime_pct = (uptime_count / total) * 100

        return {
            "uptime_pct": uptime_pct,
            "primary_pct": (state_counts.get("PRIMARY_ACTIVE", 0) / total) * 100,
            "backup_pct": (state_counts.get("BACKUP_ACTIVE", 0) / total) * 100,
            "total_samples": total,
            "states": state_counts,
        }

    # ==================== Additional Helper Methods ====================

    def store_model_weights(
        self,
        interface: str,
        weights: bytes,
        version: str = "1.0",
        accuracy: float = 0.0,
    ) -> int:
        """Alias for save_model_weights for compatibility."""
        return self.save_model_weights(
            interface=interface,
            version=version,
            weights=weights,
            training_samples=0,
            accuracy=accuracy,
        )

    def get_model_weights(self, interface: str) -> Optional[bytes]:
        """Get latest model weights for interface."""
        result = self.get_latest_model_weights(interface)
        if result:
            return result[0]  # Return just the weights bytes
        return None

    def store_state_change(self, old_state: str, new_state: str) -> None:
        """Record a state transition."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO sla_state_history (
                timestamp, state, active_interface, primary_health_score,
                backup_health_score, recommendation, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(),
                new_state,
                None,
                None,
                None,
                f"Transition: {old_state} -> {new_state}",
                json.dumps({"old_state": old_state, "new_state": new_state}),
            ),
        )
        conn.commit()

    def get_failure_count(self, interface: str, hours: int = 24) -> int:
        """Count failure events for interface in time period."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = datetime.now() - timedelta(hours=hours)

        cursor.execute(
            """
            SELECT COUNT(*) as count
            FROM failover_events
            WHERE from_interface = ?
              AND timestamp > ?
              AND trigger = 'automatic'
            """,
            (interface, cutoff),
        )

        row = cursor.fetchone()
        return row["count"] if row else 0

    def store_failover_event(
        self,
        from_interface: str,
        to_interface: str,
        trigger: str,
        reason: Optional[str] = None,
        prediction_lead_time_s: Optional[float] = None,
        details: Optional[Dict] = None,
    ) -> int:
        """
        Record a failover event.

        Args:
            from_interface: Source interface
            to_interface: Target interface
            trigger: What triggered failover (automatic, failback, manual)
            reason: Human-readable reason
            prediction_lead_time_s: How early we predicted (if applicable)
            details: Additional details

        Returns:
            Row ID of inserted record
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        if details is None:
            details = {}
        if reason:
            details["reason"] = reason

        cursor.execute(
            """
            INSERT INTO failover_events (
                timestamp, from_interface, to_interface, trigger,
                prediction_lead_time_s, details_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(),
                from_interface,
                to_interface,
                trigger,
                prediction_lead_time_s,
                json.dumps(details) if details else None,
            ),
        )
        conn.commit()
        return cursor.lastrowid
