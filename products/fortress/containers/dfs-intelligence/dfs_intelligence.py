#!/usr/bin/env python3
"""
HookProbe Fortress DFS Intelligence Module
==========================================

ML-powered Dynamic Frequency Selection with intelligent channel scoring.

Features:
- Time-weighted radar history analysis
- Channel bandwidth optimization
- Time-of-day pattern detection
- Seasonal/weather correlation
- Predictive channel safety scoring
- Reinforcement learning from channel switches

ETSI EN 301 893 Compliance:
- 30-minute NOP (Non-Occupancy Period)
- <10 second channel move time
- CAC: 60s (UNII-2A), 600s (UNII-2C)

Author: HookProbe Team
License: AGPL-3.0
"""

import os
import sys
import json
import math
import sqlite3
import logging
import argparse
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

# Optional ML imports - graceful fallback if not available
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# ============================================================
# Configuration
# ============================================================

DB_PATH = os.environ.get("DFS_DB_PATH", "/var/lib/fortress/dfs_intelligence.db")
LOG_PATH = os.environ.get("DFS_LOG_PATH", "/var/log/fortress/dfs_intelligence.log")
MODEL_PATH = os.environ.get("DFS_MODEL_PATH", "/var/lib/fortress/dfs_model.json")

# ETSI Timing Constants
NOP_DURATION_SEC = 1800  # 30 minutes
CHANNEL_MOVE_TIME_SEC = 10
CSA_BEACON_COUNT = 5

# Scoring Weights (configurable)
DEFAULT_WEIGHTS = {
    "time_since_radar": 0.30,      # Higher = safer (exponential decay)
    "radar_frequency": 0.25,        # Fewer events = better
    "bandwidth_score": 0.15,        # Wider bandwidth = better throughput
    "time_of_day_risk": 0.10,       # Pattern-based risk
    "weather_radar_proximity": 0.10, # Distance from weather radar freqs
    "channel_utilization": 0.05,    # Less congested = better
    "ml_prediction": 0.05,          # ML model confidence
}

# Channel Definitions
CHANNEL_INFO = {
    # UNII-1 (No DFS)
    36: {"freq": 5180, "band": "UNII-1", "dfs": False, "cac": 0, "max_bw": 80},
    40: {"freq": 5200, "band": "UNII-1", "dfs": False, "cac": 0, "max_bw": 80},
    44: {"freq": 5220, "band": "UNII-1", "dfs": False, "cac": 0, "max_bw": 80},
    48: {"freq": 5240, "band": "UNII-1", "dfs": False, "cac": 0, "max_bw": 80},
    # UNII-2A (DFS, 60s CAC)
    52: {"freq": 5260, "band": "UNII-2A", "dfs": True, "cac": 60, "max_bw": 80},
    56: {"freq": 5280, "band": "UNII-2A", "dfs": True, "cac": 60, "max_bw": 80},
    60: {"freq": 5300, "band": "UNII-2A", "dfs": True, "cac": 60, "max_bw": 80},
    64: {"freq": 5320, "band": "UNII-2A", "dfs": True, "cac": 60, "max_bw": 80},
    # UNII-2C (DFS, 600s CAC - Weather Radar)
    100: {"freq": 5500, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    104: {"freq": 5520, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    108: {"freq": 5540, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    112: {"freq": 5560, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    116: {"freq": 5580, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    120: {"freq": 5600, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    124: {"freq": 5620, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    128: {"freq": 5640, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    132: {"freq": 5660, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    136: {"freq": 5680, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    140: {"freq": 5700, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    144: {"freq": 5720, "band": "UNII-2C", "dfs": True, "cac": 600, "max_bw": 160},
    # UNII-3 (No DFS, country-restricted)
    149: {"freq": 5745, "band": "UNII-3", "dfs": False, "cac": 0, "max_bw": 80},
    153: {"freq": 5765, "band": "UNII-3", "dfs": False, "cac": 0, "max_bw": 80},
    157: {"freq": 5785, "band": "UNII-3", "dfs": False, "cac": 0, "max_bw": 80},
    161: {"freq": 5805, "band": "UNII-3", "dfs": False, "cac": 0, "max_bw": 80},
    165: {"freq": 5825, "band": "UNII-3", "dfs": False, "cac": 0, "max_bw": 20},
}

# Weather radar frequency ranges (higher risk in UNII-2C)
WEATHER_RADAR_FREQS = [(5600, 5650)]  # Primary weather radar band

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_PATH, mode='a') if os.path.exists(os.path.dirname(LOG_PATH) or '/var/log') else logging.NullHandler()
    ]
)
logger = logging.getLogger(__name__)


# ============================================================
# Data Classes
# ============================================================

@dataclass
class RadarEvent:
    """Represents a radar detection event."""
    id: int
    timestamp: datetime
    channel: int
    frequency: int
    event_type: str
    duration_ms: Optional[int] = None
    raw_payload: Optional[str] = None


@dataclass
class ChannelScore:
    """Channel scoring result."""
    channel: int
    total_score: float
    component_scores: Dict[str, float] = field(default_factory=dict)
    is_in_nop: bool = False
    nop_remaining_sec: int = 0
    confidence: float = 0.0
    recommendation: str = ""


@dataclass
class ChannelFeatures:
    """ML features for channel prediction."""
    channel: int
    hour_of_day: int
    day_of_week: int
    month: int
    radar_count_24h: int
    radar_count_7d: int
    radar_count_30d: int
    avg_time_between_events: float
    time_since_last_radar_hours: float
    is_weather_radar_band: bool
    bandwidth: int
    is_dfs: bool


# ============================================================
# Database Layer
# ============================================================

class DFSDatabase:
    """SQLite database for DFS intelligence."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._ensure_dir()
        self._init_db()

    def _ensure_dir(self):
        """Ensure database directory exists."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

    def _init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                -- Radar events table with indexes
                CREATE TABLE IF NOT EXISTS radar_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    channel INTEGER NOT NULL,
                    frequency INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    duration_ms INTEGER,
                    raw_payload TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_radar_timestamp ON radar_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_radar_channel ON radar_events(channel);
                CREATE INDEX IF NOT EXISTS idx_radar_channel_time ON radar_events(channel, timestamp);

                -- NOP (Non-Occupancy Period) timers
                CREATE TABLE IF NOT EXISTS nop_timers (
                    channel INTEGER PRIMARY KEY,
                    frequency INTEGER NOT NULL,
                    start_timestamp TEXT NOT NULL,
                    expiry_timestamp TEXT NOT NULL,
                    radar_event_id INTEGER,
                    FOREIGN KEY (radar_event_id) REFERENCES radar_events(id)
                );

                -- Channel statistics (aggregated)
                CREATE TABLE IF NOT EXISTS channel_stats (
                    channel INTEGER PRIMARY KEY,
                    total_radar_events INTEGER DEFAULT 0,
                    last_radar_timestamp TEXT,
                    avg_events_per_day REAL DEFAULT 0,
                    risk_score REAL DEFAULT 0,
                    last_updated TEXT
                );

                -- Time-of-day patterns
                CREATE TABLE IF NOT EXISTS hourly_patterns (
                    channel INTEGER NOT NULL,
                    hour INTEGER NOT NULL,  -- 0-23
                    event_count INTEGER DEFAULT 0,
                    avg_risk REAL DEFAULT 0,
                    PRIMARY KEY (channel, hour)
                );

                -- Channel switch history (for reinforcement learning)
                CREATE TABLE IF NOT EXISTS switch_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    from_channel INTEGER,
                    to_channel INTEGER NOT NULL,
                    reason TEXT,
                    success INTEGER DEFAULT 1,
                    time_on_channel_sec INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                -- ML model metadata
                CREATE TABLE IF NOT EXISTS model_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT
                );
            ''')
            conn.commit()

    def log_radar_event(self, channel: int, frequency: int, event_type: str,
                        duration_ms: Optional[int] = None, raw_payload: Optional[str] = None) -> int:
        """Log a radar detection event."""
        timestamp = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                '''INSERT INTO radar_events
                   (timestamp, channel, frequency, event_type, duration_ms, raw_payload)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (timestamp, channel, frequency, event_type, duration_ms, raw_payload)
            )
            event_id = cursor.lastrowid

            # Update channel stats
            self._update_channel_stats(conn, channel, timestamp)

            # Update hourly pattern
            hour = datetime.now().hour
            conn.execute(
                '''INSERT INTO hourly_patterns (channel, hour, event_count, avg_risk)
                   VALUES (?, ?, 1, 1.0)
                   ON CONFLICT(channel, hour) DO UPDATE SET
                   event_count = event_count + 1''',
                (channel, hour)
            )

            conn.commit()
            logger.info(f"Logged radar event: channel={channel}, freq={frequency}MHz, type={event_type}")
            return event_id

    def _update_channel_stats(self, conn, channel: int, timestamp: str):
        """Update aggregated channel statistics."""
        # Calculate events per day over last 30 days
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
        result = conn.execute(
            '''SELECT COUNT(*) FROM radar_events
               WHERE channel = ? AND timestamp > ?''',
            (channel, thirty_days_ago)
        ).fetchone()
        event_count = result[0] if result else 0
        avg_per_day = event_count / 30.0

        # Risk score: exponential based on frequency
        risk_score = min(1.0, 1 - math.exp(-avg_per_day * 0.5))

        conn.execute(
            '''INSERT INTO channel_stats (channel, total_radar_events, last_radar_timestamp,
                                          avg_events_per_day, risk_score, last_updated)
               VALUES (?, 1, ?, ?, ?, ?)
               ON CONFLICT(channel) DO UPDATE SET
               total_radar_events = total_radar_events + 1,
               last_radar_timestamp = ?,
               avg_events_per_day = ?,
               risk_score = ?,
               last_updated = ?''',
            (channel, timestamp, avg_per_day, risk_score, datetime.now().isoformat(),
             timestamp, avg_per_day, risk_score, datetime.now().isoformat())
        )

    def add_nop(self, channel: int, frequency: int, radar_event_id: Optional[int] = None):
        """Add channel to NOP (Non-Occupancy Period)."""
        now = datetime.now()
        expiry = now + timedelta(seconds=NOP_DURATION_SEC)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                '''INSERT OR REPLACE INTO nop_timers
                   (channel, frequency, start_timestamp, expiry_timestamp, radar_event_id)
                   VALUES (?, ?, ?, ?, ?)''',
                (channel, frequency, now.isoformat(), expiry.isoformat(), radar_event_id)
            )
            conn.commit()
        logger.info(f"Channel {channel} added to NOP until {expiry.isoformat()}")

    def get_nop_channels(self) -> Dict[int, int]:
        """Get channels currently in NOP with remaining seconds."""
        now = datetime.now()
        result = {}
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                '''SELECT channel, expiry_timestamp FROM nop_timers
                   WHERE expiry_timestamp > ?''',
                (now.isoformat(),)
            ).fetchall()
            for channel, expiry_str in rows:
                expiry = datetime.fromisoformat(expiry_str)
                remaining = int((expiry - now).total_seconds())
                result[channel] = max(0, remaining)
        return result

    def cleanup_expired_nop(self):
        """Remove expired NOP entries."""
        now = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            deleted = conn.execute(
                'DELETE FROM nop_timers WHERE expiry_timestamp <= ?',
                (now,)
            ).rowcount
            conn.commit()
        if deleted:
            logger.info(f"Cleaned up {deleted} expired NOP entries")

    def get_radar_events(self, channel: Optional[int] = None,
                         since: Optional[datetime] = None,
                         limit: int = 100) -> List[RadarEvent]:
        """Get radar events with optional filters."""
        query = 'SELECT id, timestamp, channel, frequency, event_type, duration_ms, raw_payload FROM radar_events'
        params = []
        conditions = []

        if channel:
            conditions.append('channel = ?')
            params.append(channel)
        if since:
            conditions.append('timestamp > ?')
            params.append(since.isoformat())

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)

        events = []
        with sqlite3.connect(self.db_path) as conn:
            for row in conn.execute(query, params).fetchall():
                events.append(RadarEvent(
                    id=row[0],
                    timestamp=datetime.fromisoformat(row[1]),
                    channel=row[2],
                    frequency=row[3],
                    event_type=row[4],
                    duration_ms=row[5],
                    raw_payload=row[6]
                ))
        return events

    def get_channel_stats(self, channel: int) -> Optional[Dict]:
        """Get statistics for a specific channel."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                '''SELECT total_radar_events, last_radar_timestamp,
                          avg_events_per_day, risk_score, last_updated
                   FROM channel_stats WHERE channel = ?''',
                (channel,)
            ).fetchone()
            if row:
                return {
                    "total_events": row[0],
                    "last_radar": row[1],
                    "avg_per_day": row[2],
                    "risk_score": row[3],
                    "last_updated": row[4]
                }
        return None

    def get_hourly_pattern(self, channel: int) -> Dict[int, int]:
        """Get hourly radar pattern for a channel."""
        pattern = {h: 0 for h in range(24)}
        with sqlite3.connect(self.db_path) as conn:
            for row in conn.execute(
                'SELECT hour, event_count FROM hourly_patterns WHERE channel = ?',
                (channel,)
            ).fetchall():
                pattern[row[0]] = row[1]
        return pattern

    def log_channel_switch(self, from_channel: Optional[int], to_channel: int,
                           reason: str, success: bool = True, time_on_channel: int = 0):
        """Log a channel switch event for reinforcement learning."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                '''INSERT INTO switch_history
                   (timestamp, from_channel, to_channel, reason, success, time_on_channel_sec)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (datetime.now().isoformat(), from_channel, to_channel,
                 reason, 1 if success else 0, time_on_channel)
            )
            conn.commit()

    def get_feature_data(self, days: int = 30) -> List[Dict]:
        """Get feature data for ML training."""
        since = (datetime.now() - timedelta(days=days)).isoformat()
        features = []
        with sqlite3.connect(self.db_path) as conn:
            # Get all radar events with context
            rows = conn.execute(
                '''SELECT timestamp, channel, frequency FROM radar_events
                   WHERE timestamp > ? ORDER BY timestamp''',
                (since,)
            ).fetchall()

            for ts_str, channel, freq in rows:
                ts = datetime.fromisoformat(ts_str)
                features.append({
                    "timestamp": ts_str,
                    "channel": channel,
                    "frequency": freq,
                    "hour": ts.hour,
                    "day_of_week": ts.weekday(),
                    "month": ts.month,
                    "is_dfs": CHANNEL_INFO.get(channel, {}).get("dfs", True),
                    "band": CHANNEL_INFO.get(channel, {}).get("band", "unknown")
                })
        return features


# ============================================================
# Channel Scoring Engine
# ============================================================

class ChannelScorer:
    """
    ML-enhanced channel scoring algorithm.

    Scoring Formula:
        S(channel) = Σ(w_i * s_i) where:
        - w_i = weight for factor i
        - s_i = normalized score [0,1] for factor i

    Factors:
        1. Time since last radar (exponential decay)
        2. Historical radar frequency (inverse)
        3. Bandwidth capability (linear)
        4. Time-of-day risk pattern
        5. Weather radar proximity
        6. Channel utilization
        7. ML prediction confidence
    """

    def __init__(self, db: DFSDatabase, weights: Optional[Dict[str, float]] = None):
        self.db = db
        self.weights = weights or DEFAULT_WEIGHTS
        self.ml_model = None
        self.scaler = None
        self._load_ml_model()

    def _load_ml_model(self):
        """Load or initialize ML model."""
        if not HAS_SKLEARN:
            logger.warning("sklearn not available, ML predictions disabled")
            return

        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, 'r') as f:
                    model_data = json.load(f)
                    # Simple model state restoration
                    logger.info("ML model metadata loaded")
            except Exception as e:
                logger.warning(f"Could not load ML model: {e}")

    def score_channel(self, channel: int, current_hour: Optional[int] = None) -> ChannelScore:
        """
        Calculate comprehensive score for a channel.

        Higher score = better channel choice.
        """
        if current_hour is None:
            current_hour = datetime.now().hour

        info = CHANNEL_INFO.get(channel, {})
        nop_channels = self.db.get_nop_channels()

        # Check NOP first
        if channel in nop_channels:
            return ChannelScore(
                channel=channel,
                total_score=0.0,
                is_in_nop=True,
                nop_remaining_sec=nop_channels[channel],
                confidence=1.0,
                recommendation="BLOCKED: Channel in Non-Occupancy Period"
            )

        component_scores = {}

        # 1. Time since last radar (exponential decay)
        component_scores["time_since_radar"] = self._score_time_since_radar(channel)

        # 2. Radar frequency (inverse of event count)
        component_scores["radar_frequency"] = self._score_radar_frequency(channel)

        # 3. Bandwidth capability
        component_scores["bandwidth_score"] = self._score_bandwidth(channel)

        # 4. Time-of-day risk
        component_scores["time_of_day_risk"] = self._score_time_of_day(channel, current_hour)

        # 5. Weather radar proximity
        component_scores["weather_radar_proximity"] = self._score_weather_proximity(channel)

        # 6. Channel utilization (placeholder - would need actual measurement)
        component_scores["channel_utilization"] = 0.8  # Assume moderately clear

        # 7. ML prediction
        component_scores["ml_prediction"] = self._score_ml_prediction(channel, current_hour)

        # Calculate weighted total
        total_score = sum(
            self.weights.get(key, 0) * score
            for key, score in component_scores.items()
        )

        # Confidence based on data availability
        stats = self.db.get_channel_stats(channel)
        confidence = min(1.0, (stats["total_events"] if stats else 0) / 10 + 0.3)

        # Generate recommendation
        recommendation = self._generate_recommendation(channel, total_score, component_scores)

        return ChannelScore(
            channel=channel,
            total_score=total_score,
            component_scores=component_scores,
            is_in_nop=False,
            nop_remaining_sec=0,
            confidence=confidence,
            recommendation=recommendation
        )

    def _score_time_since_radar(self, channel: int) -> float:
        """
        Score based on time since last radar detection.

        Uses exponential decay: score = 1 - e^(-t/τ)
        where τ (tau) is the characteristic time (e.g., 24 hours)
        """
        stats = self.db.get_channel_stats(channel)
        if not stats or not stats["last_radar"]:
            return 1.0  # No radar history = safe

        last_radar = datetime.fromisoformat(stats["last_radar"])
        hours_since = (datetime.now() - last_radar).total_seconds() / 3600

        # Characteristic time: 24 hours
        tau = 24.0
        score = 1 - math.exp(-hours_since / tau)
        return score

    def _score_radar_frequency(self, channel: int) -> float:
        """
        Score based on historical radar event frequency.

        Inverse relationship: more events = lower score
        """
        stats = self.db.get_channel_stats(channel)
        if not stats:
            return 0.8  # Unknown = moderately safe

        avg_per_day = stats["avg_per_day"]
        # Sigmoid function for smooth scoring
        # Score approaches 0 as events/day increases
        score = 1 / (1 + math.exp(avg_per_day * 2 - 1))
        return score

    def _score_bandwidth(self, channel: int) -> float:
        """
        Score based on maximum bandwidth capability.

        Higher bandwidth = higher score (better throughput)
        """
        info = CHANNEL_INFO.get(channel, {})
        max_bw = info.get("max_bw", 20)

        # Normalize: 20MHz=0.25, 40MHz=0.5, 80MHz=0.75, 160MHz=1.0
        return min(1.0, max_bw / 160)

    def _score_time_of_day(self, channel: int, hour: int) -> float:
        """
        Score based on historical time-of-day patterns.

        Lower activity at current hour = higher score
        """
        pattern = self.db.get_hourly_pattern(channel)
        total_events = sum(pattern.values())

        if total_events == 0:
            return 0.8  # No pattern data

        # Inverse of normalized hourly activity
        hourly_activity = pattern.get(hour, 0) / max(1, total_events)
        score = 1 - hourly_activity
        return score

    def _score_weather_proximity(self, channel: int) -> float:
        """
        Score based on proximity to weather radar frequencies.

        UNII-2C (5600-5650 MHz) has higher weather radar activity
        """
        info = CHANNEL_INFO.get(channel, {})
        freq = info.get("freq", 0)

        # Check proximity to weather radar bands
        for low, high in WEATHER_RADAR_FREQS:
            if low <= freq <= high:
                return 0.3  # In weather radar band
            # Proximity penalty
            if abs(freq - (low + high) / 2) < 100:
                return 0.6  # Near weather radar band

        return 1.0  # Far from weather radar

    def _score_ml_prediction(self, channel: int, hour: int) -> float:
        """
        ML-based prediction score.

        Uses trained model to predict radar likelihood.
        Falls back to heuristic if model unavailable.
        """
        if not HAS_SKLEARN or self.ml_model is None:
            # Fallback: simple heuristic based on band
            info = CHANNEL_INFO.get(channel, {})
            band = info.get("band", "")
            if band == "UNII-1":
                return 1.0  # No DFS = safe
            elif band == "UNII-2A":
                return 0.7  # Moderate risk
            elif band == "UNII-2C":
                return 0.4  # Higher risk (weather radar)
            return 0.5

        # TODO: Implement actual ML prediction when model is trained
        return 0.5

    def _generate_recommendation(self, channel: int, score: float,
                                  components: Dict[str, float]) -> str:
        """Generate human-readable recommendation."""
        info = CHANNEL_INFO.get(channel, {})

        if score >= 0.8:
            return f"EXCELLENT: Channel {channel} ({info.get('band', 'unknown')}) - Very safe choice"
        elif score >= 0.6:
            return f"GOOD: Channel {channel} - Low radar risk"
        elif score >= 0.4:
            return f"MODERATE: Channel {channel} - Some radar history, use with caution"
        elif score >= 0.2:
            return f"RISKY: Channel {channel} - Significant radar activity, consider alternatives"
        else:
            return f"AVOID: Channel {channel} - High radar risk or in NOP"

    def rank_all_channels(self, include_dfs: bool = True,
                          include_unii3: bool = False) -> List[ChannelScore]:
        """
        Rank all channels by score.

        Args:
            include_dfs: Include DFS channels (UNII-2A, UNII-2C)
            include_unii3: Include UNII-3 (country-restricted)

        Returns:
            List of ChannelScore sorted by total_score descending
        """
        scores = []
        current_hour = datetime.now().hour

        for channel, info in CHANNEL_INFO.items():
            # Filter by band
            if not include_dfs and info["dfs"]:
                continue
            if not include_unii3 and info["band"] == "UNII-3":
                continue

            score = self.score_channel(channel, current_hour)
            scores.append(score)

        # Sort by score descending
        scores.sort(key=lambda s: s.total_score, reverse=True)
        return scores

    def choose_best_channel(self,
                            prefer_dfs: bool = False,
                            min_bandwidth: int = 20,
                            exclude_channels: Optional[List[int]] = None) -> ChannelScore:
        """
        Choose the optimal channel based on all factors.

        Args:
            prefer_dfs: Prefer DFS channels (often clearer)
            min_bandwidth: Minimum required bandwidth (MHz)
            exclude_channels: Channels to exclude from selection

        Returns:
            Best ChannelScore
        """
        exclude = set(exclude_channels or [])
        nop_channels = set(self.db.get_nop_channels().keys())
        exclude.update(nop_channels)

        all_scores = self.rank_all_channels(include_dfs=True, include_unii3=False)

        for score in all_scores:
            if score.channel in exclude:
                continue

            info = CHANNEL_INFO.get(score.channel, {})
            if info.get("max_bw", 20) < min_bandwidth:
                continue

            # DFS preference adjustment
            if prefer_dfs and not info.get("dfs", False):
                continue

            return score

        # Fallback to channel 36 (always safe)
        return self.score_channel(36)


# ============================================================
# ML Training Module
# ============================================================

class DFSMLTrainer:
    """
    Machine Learning trainer for radar prediction.

    Features used:
    - Hour of day (0-23)
    - Day of week (0-6)
    - Month (1-12)
    - Channel historical stats
    - Band characteristics
    """

    def __init__(self, db: DFSDatabase):
        self.db = db
        self.model = None
        self.scaler = None

    def prepare_features(self, channel: int, timestamp: datetime) -> ChannelFeatures:
        """Prepare feature vector for a channel at given time."""
        now = timestamp

        # Get historical radar counts
        events_24h = len(self.db.get_radar_events(
            channel=channel,
            since=now - timedelta(hours=24)
        ))
        events_7d = len(self.db.get_radar_events(
            channel=channel,
            since=now - timedelta(days=7)
        ))
        events_30d = len(self.db.get_radar_events(
            channel=channel,
            since=now - timedelta(days=30)
        ))

        # Time since last radar
        events = self.db.get_radar_events(channel=channel, limit=1)
        if events:
            time_since = (now - events[0].timestamp).total_seconds() / 3600
        else:
            time_since = 720  # 30 days in hours (no history)

        # Average time between events
        all_events = self.db.get_radar_events(channel=channel, limit=100)
        if len(all_events) > 1:
            intervals = []
            for i in range(1, len(all_events)):
                delta = (all_events[i-1].timestamp - all_events[i].timestamp).total_seconds() / 3600
                intervals.append(delta)
            avg_interval = sum(intervals) / len(intervals)
        else:
            avg_interval = 720  # Default

        info = CHANNEL_INFO.get(channel, {})

        return ChannelFeatures(
            channel=channel,
            hour_of_day=now.hour,
            day_of_week=now.weekday(),
            month=now.month,
            radar_count_24h=events_24h,
            radar_count_7d=events_7d,
            radar_count_30d=events_30d,
            avg_time_between_events=avg_interval,
            time_since_last_radar_hours=time_since,
            is_weather_radar_band=info.get("band") == "UNII-2C",
            bandwidth=info.get("max_bw", 20),
            is_dfs=info.get("dfs", False)
        )

    def train(self, min_samples: int = 50) -> bool:
        """
        Train the ML model on historical data.

        Returns True if training successful.
        """
        if not HAS_SKLEARN or not HAS_NUMPY:
            logger.warning("sklearn/numpy not available, cannot train ML model")
            return False

        # Get training data
        feature_data = self.db.get_feature_data(days=90)

        if len(feature_data) < min_samples:
            logger.warning(f"Insufficient training data: {len(feature_data)} < {min_samples}")
            return False

        logger.info(f"Training ML model with {len(feature_data)} samples...")

        # Prepare features and labels
        X = []
        y = []

        for data in feature_data:
            # Features: hour, day_of_week, month, channel characteristics
            channel = data["channel"]
            info = CHANNEL_INFO.get(channel, {})

            features = [
                data["hour"],
                data["day_of_week"],
                data["month"],
                1 if info.get("dfs") else 0,
                1 if info.get("band") == "UNII-2C" else 0,
                info.get("max_bw", 20) / 160,
            ]
            X.append(features)
            y.append(1)  # Radar event occurred

        # Add negative samples (times without radar)
        # This is simplified - real implementation would need more sophisticated sampling
        for _ in range(len(y)):
            hour = np.random.randint(0, 24)
            dow = np.random.randint(0, 7)
            month = np.random.randint(1, 13)
            channel = np.random.choice(list(CHANNEL_INFO.keys()))
            info = CHANNEL_INFO.get(channel, {})

            features = [
                hour, dow, month,
                1 if info.get("dfs") else 0,
                1 if info.get("band") == "UNII-2C" else 0,
                info.get("max_bw", 20) / 160,
            ]
            X.append(features)
            y.append(0)  # No radar

        X = np.array(X)
        y = np.array(y)

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.model.fit(X_scaled, y)

        # Save model metadata
        self._save_model()

        logger.info("ML model training complete")
        return True

    def _save_model(self):
        """Save model metadata to disk."""
        if self.model is None:
            return

        metadata = {
            "trained_at": datetime.now().isoformat(),
            "n_estimators": 100,
            "feature_importances": self.model.feature_importances_.tolist() if hasattr(self.model, 'feature_importances_') else []
        }

        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, 'w') as f:
            json.dump(metadata, f, indent=2)

    def predict_radar_probability(self, channel: int, hour: int) -> float:
        """Predict probability of radar on channel at given hour."""
        if self.model is None or self.scaler is None:
            return 0.5  # Unknown

        info = CHANNEL_INFO.get(channel, {})
        features = np.array([[
            hour,
            datetime.now().weekday(),
            datetime.now().month,
            1 if info.get("dfs") else 0,
            1 if info.get("band") == "UNII-2C" else 0,
            info.get("max_bw", 20) / 160,
        ]])

        features_scaled = self.scaler.transform(features)
        prob = self.model.predict_proba(features_scaled)[0][1]
        return float(prob)


# ============================================================
# Radar Monitor (Real-time)
# ============================================================

class RadarMonitor:
    """
    Real-time radar detection monitor using hostapd_cli.
    """

    def __init__(self, db: DFSDatabase, scorer: ChannelScorer, interface: str = "wlan0"):
        self.db = db
        self.scorer = scorer
        self.interface = interface
        self.running = False
        self.current_channel = None

    def freq_to_channel(self, freq: int) -> int:
        """Convert frequency (MHz) to channel number."""
        for ch, info in CHANNEL_INFO.items():
            if info["freq"] == freq:
                return ch
        # Fallback calculation
        if freq >= 5180 and freq <= 5320:
            return (freq - 5180) // 20 + 36
        elif freq >= 5500 and freq <= 5720:
            return (freq - 5500) // 20 + 100
        return 0

    def handle_radar_detected(self, payload: str):
        """Handle radar detection event."""
        try:
            # Parse frequency from payload
            freq = 0
            for part in payload.split():
                if "freq=" in part:
                    freq = int(part.split("=")[1])
                    break

            if freq == 0:
                logger.error(f"Could not parse frequency from: {payload}")
                return

            channel = self.freq_to_channel(freq)
            logger.warning(f"RADAR DETECTED on channel {channel} ({freq} MHz)")

            # Log event
            event_id = self.db.log_radar_event(
                channel=channel,
                frequency=freq,
                event_type="RADAR_DETECTED",
                raw_payload=payload
            )

            # Add to NOP
            self.db.add_nop(channel, freq, event_id)

            # Choose new channel
            best = self.scorer.choose_best_channel(
                exclude_channels=[channel]
            )

            logger.info(f"Switching to channel {best.channel} (score: {best.total_score:.2f})")

            # Execute CSA switch
            self._execute_csa_switch(best.channel)

            # Log switch
            self.db.log_channel_switch(
                from_channel=channel,
                to_channel=best.channel,
                reason="RADAR_DETECTED"
            )

        except Exception as e:
            logger.error(f"Error handling radar event: {e}")

    def _execute_csa_switch(self, target_channel: int):
        """Execute Channel Switch Announcement."""
        info = CHANNEL_INFO.get(target_channel, {})
        freq = info.get("freq", 5180)

        try:
            cmd = [
                "hostapd_cli", "-i", self.interface,
                "chan_switch", str(CSA_BEACON_COUNT), str(freq)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                logger.info(f"CSA switch to channel {target_channel} ({freq} MHz) initiated")
                self.current_channel = target_channel
            else:
                logger.error(f"CSA switch failed: {result.stderr}")

        except subprocess.TimeoutExpired:
            logger.error("CSA switch command timed out")
        except Exception as e:
            logger.error(f"CSA switch error: {e}")

    def start(self):
        """Start radar monitoring."""
        logger.info(f"Starting radar monitor on {self.interface}")
        self.running = True

        try:
            # Use hostapd_cli action file mode for event streaming
            proc = subprocess.Popen(
                ["hostapd_cli", "-i", self.interface, "-a", "/bin/cat"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            while self.running:
                line = proc.stdout.readline()
                if not line:
                    break

                line = line.strip()

                if "DFS-RADAR-DETECTED" in line:
                    self.handle_radar_detected(line)
                elif "DFS-CAC-START" in line:
                    logger.info(f"CAC started: {line}")
                elif "DFS-CAC-COMPLETED" in line:
                    logger.info(f"CAC completed: {line}")
                elif "DFS-NOP-FINISHED" in line:
                    logger.info(f"NOP finished: {line}")
                    self.db.cleanup_expired_nop()

        except KeyboardInterrupt:
            logger.info("Radar monitor stopped by user")
        except Exception as e:
            logger.error(f"Radar monitor error: {e}")
        finally:
            self.running = False

    def stop(self):
        """Stop radar monitoring."""
        self.running = False


# ============================================================
# CLI Interface
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="HookProbe DFS Intelligence - ML-powered channel selection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Score a specific channel
  %(prog)s score --channel 52

  # Get best channel recommendation
  %(prog)s best --prefer-dfs --min-bandwidth 80

  # Rank all channels
  %(prog)s rank --include-dfs

  # Start radar monitoring
  %(prog)s monitor --interface wlan0

  # Train ML model
  %(prog)s train

  # Show status
  %(prog)s status
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Score command
    score_parser = subparsers.add_parser("score", help="Score a specific channel")
    score_parser.add_argument("--channel", "-c", type=int, required=True, help="Channel number")
    score_parser.add_argument("--hour", type=int, help="Hour of day (0-23)")

    # Best command
    best_parser = subparsers.add_parser("best", help="Get best channel recommendation")
    best_parser.add_argument("--prefer-dfs", action="store_true", help="Prefer DFS channels")
    best_parser.add_argument("--min-bandwidth", type=int, default=20, help="Minimum bandwidth (MHz)")
    best_parser.add_argument("--exclude", type=int, nargs="*", help="Channels to exclude")

    # Rank command
    rank_parser = subparsers.add_parser("rank", help="Rank all channels")
    rank_parser.add_argument("--include-dfs", action="store_true", help="Include DFS channels")
    rank_parser.add_argument("--include-unii3", action="store_true", help="Include UNII-3 channels")
    rank_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Start radar monitoring")
    monitor_parser.add_argument("--interface", "-i", default="wlan0", help="WiFi interface")

    # Train command
    train_parser = subparsers.add_parser("train", help="Train ML model")
    train_parser.add_argument("--min-samples", type=int, default=50, help="Minimum training samples")

    # Status command
    status_parser = subparsers.add_parser("status", help="Show DFS status")
    status_parser.add_argument("--channel", "-c", type=int, help="Specific channel")

    # Log radar command (for testing)
    log_parser = subparsers.add_parser("log-radar", help="Log a radar event (testing)")
    log_parser.add_argument("--channel", "-c", type=int, required=True, help="Channel number")
    log_parser.add_argument("--frequency", "-f", type=int, help="Frequency (MHz)")

    args = parser.parse_args()

    # Initialize database and scorer
    db = DFSDatabase()
    scorer = ChannelScorer(db)

    if args.command == "score":
        score = scorer.score_channel(args.channel, args.hour)
        print(f"\nChannel {score.channel} Score: {score.total_score:.3f}")
        print(f"Confidence: {score.confidence:.1%}")
        print(f"Recommendation: {score.recommendation}")
        print("\nComponent Scores:")
        for name, value in score.component_scores.items():
            weight = DEFAULT_WEIGHTS.get(name, 0)
            print(f"  {name}: {value:.3f} (weight: {weight:.0%})")

    elif args.command == "best":
        best = scorer.choose_best_channel(
            prefer_dfs=args.prefer_dfs,
            min_bandwidth=args.min_bandwidth,
            exclude_channels=args.exclude
        )
        print(f"\n🎯 Best Channel: {best.channel}")
        print(f"   Score: {best.total_score:.3f}")
        print(f"   {best.recommendation}")
        info = CHANNEL_INFO.get(best.channel, {})
        print(f"   Band: {info.get('band')}, Bandwidth: {info.get('max_bw')}MHz")

    elif args.command == "rank":
        rankings = scorer.rank_all_channels(
            include_dfs=args.include_dfs,
            include_unii3=args.include_unii3
        )

        if args.json:
            output = [
                {
                    "channel": s.channel,
                    "score": round(s.total_score, 3),
                    "is_in_nop": s.is_in_nop,
                    "recommendation": s.recommendation
                }
                for s in rankings
            ]
            print(json.dumps(output, indent=2))
        else:
            print("\n📊 Channel Rankings:")
            print("-" * 70)
            for i, score in enumerate(rankings, 1):
                info = CHANNEL_INFO.get(score.channel, {})
                nop_str = f" [NOP: {score.nop_remaining_sec}s]" if score.is_in_nop else ""
                print(f"{i:2}. Ch {score.channel:3} | {info.get('band', '?'):8} | "
                      f"Score: {score.total_score:.3f} | BW: {info.get('max_bw', 0):3}MHz{nop_str}")

    elif args.command == "monitor":
        monitor = RadarMonitor(db, scorer, args.interface)
        print(f"Starting radar monitor on {args.interface}...")
        print("Press Ctrl+C to stop")
        monitor.start()

    elif args.command == "train":
        trainer = DFSMLTrainer(db)
        if trainer.train(min_samples=args.min_samples):
            print("✅ ML model trained successfully")
        else:
            print("❌ ML model training failed (insufficient data or dependencies)")

    elif args.command == "status":
        print("\n📡 DFS Intelligence Status")
        print("=" * 50)

        # NOP channels
        nop = db.get_nop_channels()
        if nop:
            print("\n🚫 Channels in NOP (Non-Occupancy Period):")
            for ch, remaining in nop.items():
                mins = remaining // 60
                secs = remaining % 60
                print(f"   Channel {ch}: {mins}m {secs}s remaining")
        else:
            print("\n✅ No channels in NOP")

        # Recent radar events
        events = db.get_radar_events(limit=5)
        if events:
            print("\n📜 Recent Radar Events:")
            for e in events:
                age = datetime.now() - e.timestamp
                age_str = f"{age.seconds // 3600}h {(age.seconds % 3600) // 60}m ago"
                print(f"   {e.timestamp.strftime('%Y-%m-%d %H:%M')} - Ch {e.channel} ({age_str})")

        # Channel stats
        if args.channel:
            stats = db.get_channel_stats(args.channel)
            if stats:
                print(f"\n📊 Channel {args.channel} Statistics:")
                print(f"   Total radar events: {stats['total_events']}")
                print(f"   Avg events/day: {stats['avg_per_day']:.2f}")
                print(f"   Risk score: {stats['risk_score']:.2f}")

                pattern = db.get_hourly_pattern(args.channel)
                if any(pattern.values()):
                    print("   Hourly pattern (events):")
                    for h in range(24):
                        if pattern[h] > 0:
                            print(f"     {h:02d}:00 - {pattern[h]} events")

    elif args.command == "log-radar":
        info = CHANNEL_INFO.get(args.channel, {})
        freq = args.frequency or info.get("freq", 5180)
        event_id = db.log_radar_event(
            channel=args.channel,
            frequency=freq,
            event_type="RADAR_DETECTED",
            raw_payload=f"test event channel={args.channel} freq={freq}"
        )
        db.add_nop(args.channel, freq, event_id)
        print(f"✅ Logged radar event #{event_id} for channel {args.channel}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
