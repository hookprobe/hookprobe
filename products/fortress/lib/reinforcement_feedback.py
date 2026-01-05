#!/usr/bin/env python3
"""
Reinforcement Learning Feedback for Bubble Assignment

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module implements a reinforcement learning feedback loop that learns
from user manual corrections to improve automatic bubble assignment.

The Algorithm:
When a user manually moves a device to a different bubble, the system:
1. Records the correction as negative feedback for old assignment
2. Records the correction as positive feedback for new assignment
3. Adjusts affinity scores between devices based on feedback
4. Trains the behavior clustering model with corrected labels

Feedback Types:
- POSITIVE: User confirmed AI's suggestion (implicit or explicit)
- NEGATIVE: User corrected AI's suggestion
- NEUTRAL: No user interaction (use existing scores)

Learning Goals:
- Increase affinity between devices in same manually-created bubble
- Decrease affinity between devices manually separated
- Weight manual corrections higher than automatic inferences
"""

import json
import logging
import sqlite3
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Callable

logger = logging.getLogger(__name__)

# Database
FEEDBACK_DB = Path('/var/lib/hookprobe/feedback.db')

# Learning constants
POSITIVE_FEEDBACK_WEIGHT = 0.15    # Boost affinity by 15% on positive
NEGATIVE_FEEDBACK_WEIGHT = -0.20   # Reduce affinity by 20% on negative
DECAY_FACTOR = 0.95                # Daily decay of feedback effects
MAX_FEEDBACK_AGE_DAYS = 30         # Discard feedback older than 30 days


@dataclass
class CorrectionRecord:
    """Record of a user correction for learning."""
    id: int = 0
    timestamp: datetime = None
    mac: str = ''
    old_bubble_id: str = ''
    new_bubble_id: str = ''
    old_bubble_devices: List[str] = field(default_factory=list)
    new_bubble_devices: List[str] = field(default_factory=list)
    reason: str = ''
    applied: bool = False

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'mac': self.mac,
            'old_bubble_id': self.old_bubble_id,
            'new_bubble_id': self.new_bubble_id,
            'old_bubble_devices': self.old_bubble_devices,
            'new_bubble_devices': self.new_bubble_devices,
            'reason': self.reason,
            'applied': self.applied,
        }


@dataclass
class AffinityAdjustment:
    """Affinity adjustment from feedback."""
    mac_a: str
    mac_b: str
    adjustment: float  # Positive or negative
    source: str       # 'manual_correction', 'explicit_confirm', etc.
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class ReinforcementFeedbackEngine:
    """
    Reinforcement learning engine for bubble assignment.

    Learns from user corrections to improve automatic assignment:
    - Tracks all manual corrections
    - Adjusts affinity scores based on corrections
    - Provides weighted affinity bonuses/penalties
    - Decays old corrections over time
    """

    def __init__(self, db_path: Path = FEEDBACK_DB):
        self.db_path = db_path
        self._lock = threading.RLock()

        # Affinity adjustments: (mac_a, mac_b) -> cumulative adjustment
        self._adjustments: Dict[Tuple[str, str], float] = {}

        # Pending corrections to apply
        self._pending_corrections: List[CorrectionRecord] = []

        # Callbacks for integration
        self._on_adjustment_callbacks: List[Callable] = []

        # Initialize database
        self._ensure_db()

        # Load existing adjustments
        self.load_adjustments()

    def _ensure_db(self):
        """Create database and tables."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS corrections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    old_bubble_id TEXT,
                    new_bubble_id TEXT,
                    old_bubble_devices_json TEXT,
                    new_bubble_devices_json TEXT,
                    reason TEXT,
                    applied INTEGER DEFAULT 0
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS affinity_adjustments (
                    mac_a TEXT NOT NULL,
                    mac_b TEXT NOT NULL,
                    adjustment REAL DEFAULT 0.0,
                    source TEXT,
                    last_updated TEXT,
                    PRIMARY KEY (mac_a, mac_b)
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_corrections_mac ON corrections(mac)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_corrections_applied ON corrections(applied)')
            conn.commit()

    def record_correction(
        self,
        mac: str,
        old_bubble_id: str,
        new_bubble_id: str,
        old_bubble_devices: List[str] = None,
        new_bubble_devices: List[str] = None,
        reason: str = ''
    ):
        """
        Record a user correction for learning.

        This is called when a user manually moves a device to a different bubble.
        The correction is used to adjust affinity scores.

        Args:
            mac: Device that was moved
            old_bubble_id: Previous bubble (if any)
            new_bubble_id: New bubble
            old_bubble_devices: Other devices in old bubble (for negative feedback)
            new_bubble_devices: Other devices in new bubble (for positive feedback)
            reason: User-provided reason for correction
        """
        with self._lock:
            correction = CorrectionRecord(
                timestamp=datetime.now(),
                mac=mac.upper(),
                old_bubble_id=old_bubble_id,
                new_bubble_id=new_bubble_id,
                old_bubble_devices=[m.upper() for m in (old_bubble_devices or [])],
                new_bubble_devices=[m.upper() for m in (new_bubble_devices or [])],
                reason=reason,
            )

            # Persist to database
            try:
                with sqlite3.connect(str(self.db_path)) as conn:
                    cursor = conn.execute('''
                        INSERT INTO corrections
                        (timestamp, mac, old_bubble_id, new_bubble_id,
                         old_bubble_devices_json, new_bubble_devices_json, reason)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        correction.timestamp.isoformat(),
                        correction.mac,
                        correction.old_bubble_id,
                        correction.new_bubble_id,
                        json.dumps(correction.old_bubble_devices),
                        json.dumps(correction.new_bubble_devices),
                        correction.reason,
                    ))
                    correction.id = cursor.lastrowid
                    conn.commit()
            except Exception as e:
                logger.error(f"Failed to record correction: {e}")

            self._pending_corrections.append(correction)
            logger.info(f"Recorded correction: {mac} moved from {old_bubble_id} to {new_bubble_id}")

    def apply_pending_corrections(self):
        """
        Apply pending corrections to affinity scores.

        This is the main learning step:
        - Negative feedback: Device was wrongly grouped with old bubble devices
        - Positive feedback: Device correctly belongs with new bubble devices
        """
        with self._lock:
            for correction in self._pending_corrections:
                if correction.applied:
                    continue

                mac = correction.mac

                # Negative feedback: Reduce affinity with old bubble devices
                for other_mac in correction.old_bubble_devices:
                    if other_mac != mac:
                        self._apply_adjustment(
                            mac_a=mac,
                            mac_b=other_mac,
                            adjustment=NEGATIVE_FEEDBACK_WEIGHT,
                            source='manual_correction_negative',
                        )

                # Positive feedback: Increase affinity with new bubble devices
                for other_mac in correction.new_bubble_devices:
                    if other_mac != mac:
                        self._apply_adjustment(
                            mac_a=mac,
                            mac_b=other_mac,
                            adjustment=POSITIVE_FEEDBACK_WEIGHT,
                            source='manual_correction_positive',
                        )

                correction.applied = True

                # Mark as applied in database
                try:
                    with sqlite3.connect(str(self.db_path)) as conn:
                        conn.execute(
                            'UPDATE corrections SET applied = 1 WHERE id = ?',
                            (correction.id,)
                        )
                        conn.commit()
                except Exception as e:
                    logger.debug(f"Failed to mark correction as applied: {e}")

            # Clear pending list
            self._pending_corrections = [c for c in self._pending_corrections if not c.applied]

            # Persist adjustments
            self._persist_adjustments()

            logger.debug(f"Applied corrections, {len(self._adjustments)} adjustments total")

    def _apply_adjustment(self, mac_a: str, mac_b: str, adjustment: float, source: str):
        """Apply a single affinity adjustment."""
        # Normalize MAC pair ordering
        key = self._normalize_mac_pair(mac_a, mac_b)

        # Get current adjustment and add new one
        current = self._adjustments.get(key, 0.0)

        # Apply with saturation limits (-0.5 to +0.5)
        new_adjustment = max(-0.5, min(0.5, current + adjustment))
        self._adjustments[key] = new_adjustment

        # Notify callbacks
        adj = AffinityAdjustment(
            mac_a=key[0],
            mac_b=key[1],
            adjustment=adjustment,
            source=source,
        )
        for callback in self._on_adjustment_callbacks:
            try:
                callback(adj)
            except Exception as e:
                logger.debug(f"Adjustment callback error: {e}")

    def _normalize_mac_pair(self, mac_a: str, mac_b: str) -> Tuple[str, str]:
        """Normalize MAC pair for consistent ordering."""
        return tuple(sorted([mac_a.upper(), mac_b.upper()]))

    def get_affinity_adjustment(self, mac_a: str, mac_b: str) -> float:
        """
        Get the learned affinity adjustment for a device pair.

        This should be ADDED to the base affinity score calculated by
        the connection graph analyzer.

        Args:
            mac_a: First device MAC
            mac_b: Second device MAC

        Returns:
            Adjustment value (-0.5 to +0.5)
        """
        key = self._normalize_mac_pair(mac_a, mac_b)
        return self._adjustments.get(key, 0.0)

    def get_adjusted_affinity(self, mac_a: str, mac_b: str, base_affinity: float) -> float:
        """
        Get affinity score with reinforcement learning adjustment.

        Args:
            mac_a: First device MAC
            mac_b: Second device MAC
            base_affinity: Base affinity from connection graph (0-1)

        Returns:
            Adjusted affinity score (0-1), clamped
        """
        adjustment = self.get_affinity_adjustment(mac_a, mac_b)
        adjusted = base_affinity + adjustment
        return max(0.0, min(1.0, adjusted))

    def apply_decay(self):
        """
        Apply daily decay to all adjustments.

        Old corrections should have less influence than recent ones.
        """
        with self._lock:
            for key in self._adjustments:
                self._adjustments[key] *= DECAY_FACTOR

            # Remove negligible adjustments
            self._adjustments = {
                k: v for k, v in self._adjustments.items()
                if abs(v) > 0.01
            }

            self._persist_adjustments()

    def _persist_adjustments(self):
        """Persist adjustments to database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                for key, adjustment in self._adjustments.items():
                    conn.execute('''
                        INSERT OR REPLACE INTO affinity_adjustments
                        (mac_a, mac_b, adjustment, source, last_updated)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        key[0], key[1], adjustment,
                        'aggregated',
                        datetime.now().isoformat(),
                    ))
                conn.commit()
        except Exception as e:
            logger.debug(f"Failed to persist adjustments: {e}")

    def load_adjustments(self):
        """Load adjustments from database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                rows = conn.execute('''
                    SELECT mac_a, mac_b, adjustment FROM affinity_adjustments
                ''').fetchall()

                for row in rows:
                    key = (row[0], row[1])
                    self._adjustments[key] = row[2]

                logger.debug(f"Loaded {len(rows)} affinity adjustments")
        except Exception as e:
            logger.debug(f"Failed to load adjustments: {e}")

    def register_callback(self, callback: Callable[[AffinityAdjustment], None]):
        """Register callback for adjustment notifications."""
        self._on_adjustment_callbacks.append(callback)

    def get_correction_stats(self) -> Dict:
        """Get statistics about corrections and learning."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                total = conn.execute('SELECT COUNT(*) FROM corrections').fetchone()[0]
                applied = conn.execute(
                    'SELECT COUNT(*) FROM corrections WHERE applied = 1'
                ).fetchone()[0]
                recent = conn.execute('''
                    SELECT COUNT(*) FROM corrections
                    WHERE timestamp > datetime('now', '-7 days')
                ''').fetchone()[0]

                return {
                    'total_corrections': total,
                    'applied_corrections': applied,
                    'pending_corrections': total - applied,
                    'corrections_last_7_days': recent,
                    'active_adjustments': len(self._adjustments),
                    'avg_adjustment': sum(self._adjustments.values()) / len(self._adjustments) if self._adjustments else 0,
                }
        except Exception as e:
            logger.debug(f"Failed to get stats: {e}")
            return {}

    def get_top_adjusted_pairs(self, limit: int = 10) -> List[Tuple[str, str, float]]:
        """Get pairs with highest absolute adjustments."""
        sorted_pairs = sorted(
            self._adjustments.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )
        return [(k[0], k[1], v) for k, v in sorted_pairs[:limit]]


# =============================================================================
# INTEGRATION WITH CONNECTION GRAPH
# =============================================================================

def integrate_with_connection_graph(engine: 'ReinforcementFeedbackEngine',
                                     connection_graph: 'ConnectionGraphAnalyzer'):
    """
    Integrate reinforcement learning with the connection graph analyzer.

    This patches the affinity score calculation to include learned adjustments.
    """
    original_get_affinity = connection_graph.get_d2d_affinity_score

    def enhanced_get_affinity(mac_a: str, mac_b: str) -> float:
        base_affinity = original_get_affinity(mac_a, mac_b)
        return engine.get_adjusted_affinity(mac_a, mac_b, base_affinity)

    connection_graph.get_d2d_affinity_score = enhanced_get_affinity
    logger.info("Reinforcement learning integrated with connection graph")


# =============================================================================
# SINGLETON
# =============================================================================

_engine: Optional[ReinforcementFeedbackEngine] = None
_engine_lock = threading.Lock()


def get_feedback_engine() -> ReinforcementFeedbackEngine:
    """Get the singleton feedback engine."""
    global _engine

    with _engine_lock:
        if _engine is None:
            _engine = ReinforcementFeedbackEngine()
        return _engine


# =============================================================================
# CLI
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='Reinforcement Feedback Engine')
    parser.add_argument('command', choices=['stats', 'pairs', 'decay', 'apply'])
    parser.add_argument('--limit', type=int, default=10)
    args = parser.parse_args()

    engine = get_feedback_engine()

    if args.command == 'stats':
        stats = engine.get_correction_stats()
        print("Reinforcement Learning Stats:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    elif args.command == 'pairs':
        pairs = engine.get_top_adjusted_pairs(args.limit)
        print(f"Top {args.limit} adjusted pairs:")
        for mac_a, mac_b, adj in pairs:
            print(f"  {mac_a} ↔ {mac_b}: {adj:+.3f}")

    elif args.command == 'decay':
        print("Applying decay to adjustments...")
        engine.apply_decay()
        print(f"Active adjustments: {len(engine._adjustments)}")

    elif args.command == 'apply':
        print("Applying pending corrections...")
        engine.apply_pending_corrections()
        print(f"Applied. Active adjustments: {len(engine._adjustments)}")
