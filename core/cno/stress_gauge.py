"""
Stress Gauge — The Hypothalamus

Aggregates five weighted stress signals into a single organism-wide
stress state that controls the Brainstem's autonomic responses.

Signals & Weights:
    XDP drop rate       30%   — High packet drops = under attack
    Active incidents    25%   — Unresolved AEGIS cognition entries
    Max risk velocity   20%   — Fastest-accelerating threat
    CPU load            15%   — System resource pressure
    Anomaly score dist  10%   — Distribution of anomaly scores

Output:
    StressState → written to BPF stress_level map every cycle
    Controls: Flow Control (traffic prioritization), Camouflage (Phase 2)

Hysteresis:
    30-second minimum dwell time in each state prevents oscillation.
    State transitions require sustained signal change.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import os
import re
import struct
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

from .types import BrainLayer, StressSignal, StressState, SynapticEvent, SynapticRoute

logger = logging.getLogger(__name__)

# ClickHouse config
CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# Validate CH_DB is a safe identifier
if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

# Stress thresholds (composite score 0.0 - 1.0)
THRESHOLD_CALM = 0.15         # Below this = CALM
THRESHOLD_ALERT = 0.35        # 0.15 - 0.35 = ALERT
THRESHOLD_FIGHT = 0.60        # 0.35 - 0.60 = FIGHT
# Above 0.60 = FIGHT (no separate RECOVERY threshold — recovery is time-based)

HYSTERESIS_SECONDS = 30.0     # Min time in a state before transition
RECOVERY_MAX_SECONDS = 300.0  # Max 5 min in RECOVERY before auto-transition to CALM
GAUGE_INTERVAL_S = 5.0        # Compute stress every 5 seconds
HISTORY_WINDOW = 60           # Keep 60 samples (5 min at 5s intervals)


class StressGauge:
    """The hypothalamus — converts raw metrics into organism stress state.

    Runs in a background thread, polling ClickHouse and system metrics.
    Notifies the SynapticController when state transitions occur.
    """

    # Signal weights (must sum to 1.0)
    WEIGHT_XDP_DROP_RATE = 0.30
    WEIGHT_ACTIVE_INCIDENTS = 0.25
    WEIGHT_RISK_VELOCITY = 0.20
    WEIGHT_CPU_LOAD = 0.15
    WEIGHT_ANOMALY_DIST = 0.10

    def __init__(self, on_state_change=None):
        """Initialize the stress gauge.

        Args:
            on_state_change: Callback(old_state, new_state, score) invoked
                on state transitions. Typically wired to SynapticController.
        """
        self._state = StressState.CALM
        self._composite_score = 0.0
        self._state_entered_at = time.monotonic()
        self._on_state_change = on_state_change

        # Per-signal current values
        self._signals: Dict[str, float] = {
            'xdp_drop_rate': 0.0,
            'active_incidents': 0.0,
            'risk_velocity': 0.0,
            'cpu_load': 0.0,
            'anomaly_dist': 0.0,
        }

        # History for trend analysis
        self._history: deque = deque(maxlen=HISTORY_WINDOW)

        # Thread control
        self._running = False
        self._thread: Optional[threading.Thread] = None

        logger.info("StressGauge initialized (thresholds: calm<%.2f, alert<%.2f, fight<%.2f)",
                     THRESHOLD_CALM, THRESHOLD_ALERT, THRESHOLD_FIGHT)

    @property
    def state(self) -> StressState:
        return self._state

    @property
    def composite_score(self) -> float:
        return self._composite_score

    @property
    def signals(self) -> Dict[str, float]:
        return dict(self._signals)

    # ------------------------------------------------------------------
    # Signal Collection
    # ------------------------------------------------------------------

    def _collect_xdp_drop_rate(self) -> float:
        """Query XDP stats for packet drop rate (0.0 - 1.0).

        Normalized: 0% drops = 0.0, >10% drops = 1.0
        """
        try:
            query = (
                f"SELECT "
                f"  sumIf(delta_packets, action='drop') AS drops, "
                f"  sum(delta_packets) AS total "
                f"FROM {CH_DB}.xdp_stats "
                f"WHERE timestamp > now() - INTERVAL 60 SECOND"
            )
            result = _ch_query(query)
            if result:
                parts = result.strip().split('\t')
                if len(parts) >= 2:
                    drops = float(parts[0] or 0)
                    total = float(parts[1] or 1)
                    if total > 0:
                        rate = drops / total
                        return min(rate / 0.10, 1.0)  # Normalize: 10% drops = 1.0
        except Exception as e:
            logger.debug("XDP drop rate query failed: %s", e)
        return 0.0

    def _collect_active_incidents(self) -> float:
        """Count recent unresolved malicious verdicts (0.0 - 1.0).

        Uses ClickHouse hydra_verdicts (not PostgreSQL) since the CNO
        container has no access to the rootless podman network.

        Alexandria fix: Previous normalization (÷10) meant 10 distinct
        malicious IPs = max stress. On an internet-facing server, 50-150
        distinct malicious IPs per 5 minutes is NORMAL background noise
        from scanners/bots. This was pegging the signal permanently at 1.0.
        Raised to ÷200 so only a genuine attack spike (200+ novel IPs)
        triggers full stress. Normal background (~100 IPs) reads ~0.5.
        """
        try:
            query = (
                f"SELECT count(DISTINCT src_ip) "
                f"FROM {CH_DB}.hydra_verdicts "
                f"WHERE timestamp > now() - INTERVAL 300 SECOND "
                f"AND verdict = 'malicious' "
                f"AND action_taken NOT IN ('block', 'blocked')"
            )
            result = _ch_query(query)
            if result:
                count = int(result.strip() or 0)
                return min(count / 200.0, 1.0)
        except Exception as e:
            logger.debug("Active incidents query failed: %s", e)
        return 0.0

    def _collect_risk_velocity(self) -> float:
        """Get maximum risk velocity across all IPs (0.0 - 1.0).

        Normalized: 0 = 0.0, >=0.30 = 1.0 (catastrophic reflex threshold)
        """
        try:
            query = (
                f"SELECT max(abs(risk_velocity)) "
                f"FROM {CH_DB}.ip_risk_scores "
                f"WHERE timestamp > now() - INTERVAL 300 SECOND"
            )
            result = _ch_query(query)
            if result:
                max_vel = float(result.strip() or 0)
                return min(max_vel / 0.30, 1.0)
        except Exception as e:
            logger.debug("Risk velocity query failed: %s", e)
        return 0.0

    def _collect_cpu_load(self) -> float:
        """Read system CPU load (0.0 - 1.0).

        Uses /proc/loadavg 1-minute average normalized by CPU count.
        """
        try:
            with open('/proc/loadavg', 'r') as f:
                load_1m = float(f.read().split()[0])
            cpu_count = os.cpu_count() or 1
            normalized = load_1m / cpu_count
            return min(normalized, 1.0)
        except Exception:
            return 0.0

    def _collect_anomaly_distribution(self) -> float:
        """Get fraction of IPs scored as suspicious/malicious (0.0 - 1.0).

        Alexandria fix: Previous threshold (20%) was too low for an
        internet-facing IDS — SENTINEL classifies 50-70% of external
        traffic as suspicious/malicious (scanners, bots, known-bad IPs).
        This pegged the signal permanently at 1.0. Raised to 80% so only
        a true anomalous spike (nearly ALL traffic is malicious) triggers
        full stress. Normal internet background (~60%) reads ~0.75.
        """
        try:
            query = (
                f"SELECT "
                f"  countIf(verdict IN ('suspicious', 'malicious')) AS threats, "
                f"  count(*) AS total "
                f"FROM {CH_DB}.hydra_verdicts "
                f"WHERE timestamp > now() - INTERVAL 300 SECOND"
            )
            result = _ch_query(query)
            if result:
                parts = result.strip().split('\t')
                if len(parts) >= 2:
                    threats = float(parts[0] or 0)
                    total = float(parts[1] or 1)
                    if total > 0:
                        ratio = threats / total
                        return min(ratio / 0.80, 1.0)
        except Exception as e:
            logger.debug("Anomaly distribution query failed: %s", e)
        return 0.0

    # ------------------------------------------------------------------
    # Composite Score & State Transition
    # ------------------------------------------------------------------

    def compute_composite(self) -> float:
        """Compute weighted composite stress score."""
        self._signals['xdp_drop_rate'] = self._collect_xdp_drop_rate()
        self._signals['active_incidents'] = self._collect_active_incidents()
        self._signals['risk_velocity'] = self._collect_risk_velocity()
        self._signals['cpu_load'] = self._collect_cpu_load()
        self._signals['anomaly_dist'] = self._collect_anomaly_distribution()

        score = (
            self._signals['xdp_drop_rate'] * self.WEIGHT_XDP_DROP_RATE +
            self._signals['active_incidents'] * self.WEIGHT_ACTIVE_INCIDENTS +
            self._signals['risk_velocity'] * self.WEIGHT_RISK_VELOCITY +
            self._signals['cpu_load'] * self.WEIGHT_CPU_LOAD +
            self._signals['anomaly_dist'] * self.WEIGHT_ANOMALY_DIST
        )

        self._composite_score = round(score, 4)
        self._history.append((time.time(), self._composite_score, dict(self._signals)))

        return self._composite_score

    def _score_to_state(self, score: float) -> StressState:
        """Map composite score to stress state."""
        if score < THRESHOLD_CALM:
            return StressState.CALM
        elif score < THRESHOLD_ALERT:
            return StressState.ALERT
        elif score < THRESHOLD_FIGHT:
            # Check if we're in RECOVERY (post-fight cooldown)
            if self._state == StressState.FIGHT:
                # Transition to RECOVERY first, not directly to ALERT
                return StressState.RECOVERY
            return StressState.ALERT
        else:
            return StressState.FIGHT

    def evaluate(self) -> Tuple[StressState, float]:
        """Compute stress and evaluate state transition with hysteresis.

        Returns (new_state, composite_score).
        """
        score = self.compute_composite()
        candidate_state = self._score_to_state(score)

        # Must compute now BEFORE RECOVERY check (NameError fix)
        now = time.monotonic()
        dwell = now - self._state_entered_at

        # Recovery → CALM transition when score drops below CALM threshold
        # OR after max dwell time in RECOVERY with score below ALERT threshold
        if self._state == StressState.RECOVERY:
            if score < THRESHOLD_CALM:
                candidate_state = StressState.CALM
            elif (score < THRESHOLD_ALERT and
                  dwell >= RECOVERY_MAX_SECONDS):
                candidate_state = StressState.CALM

        if candidate_state != self._state and dwell >= HYSTERESIS_SECONDS:
            old_state = self._state
            self._state = candidate_state
            self._state_entered_at = now

            logger.info(
                "STRESS TRANSITION: %s → %s (score=%.3f, dwell=%.1fs)",
                old_state.value, candidate_state.value, score, dwell,
            )

            # Notify callback
            if self._on_state_change:
                try:
                    self._on_state_change(old_state, candidate_state, score)
                except Exception as e:
                    logger.error("State change callback failed: %s", e)

            # Log to ClickHouse
            self._log_transition(old_state, candidate_state, score)

        return self._state, score

    def _log_transition(self, old: StressState, new: StressState,
                        score: float) -> None:
        """Log stress transition to ClickHouse."""
        try:
            import json
            signals_json = json.dumps(self._signals)
            query = (
                f"INSERT INTO {CH_DB}.cno_stress_history "
                f"(timestamp, old_state, new_state, composite_score, signals) "
                f"VALUES (now64(3), '{old.value}', '{new.value}', "
                f"{score}, '{_ch_escape(signals_json)}')"
            )
            _ch_post(query)
        except Exception as e:
            logger.debug("Stress log failed: %s", e)

    # ------------------------------------------------------------------
    # Background Loop
    # ------------------------------------------------------------------

    def _gauge_loop(self) -> None:
        """Background loop that periodically evaluates stress."""
        logger.info("StressGauge loop started (interval=%.1fs)", GAUGE_INTERVAL_S)
        while self._running:
            try:
                state, score = self.evaluate()
                logger.debug("Stress: %s (%.3f) signals=%s",
                             state.value, score, self._signals)
            except Exception as e:
                logger.error("Stress gauge cycle failed: %s", e)

            time.sleep(GAUGE_INTERVAL_S)

    def start(self) -> None:
        """Start the background stress evaluation loop."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._gauge_loop, daemon=True,
                                        name="cno-stress")
        self._thread.start()
        logger.info("StressGauge started")

    def stop(self) -> None:
        """Stop the background loop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("StressGauge stopped")

    def get_status(self) -> Dict[str, Any]:
        """Return current stress gauge status."""
        return {
            'state': self._state.value,
            'composite_score': self._composite_score,
            'signals': dict(self._signals),
            'history_samples': len(self._history),
            'state_dwell_s': round(time.monotonic() - self._state_entered_at, 1),
            'running': self._running,
        }


# ------------------------------------------------------------------
# Database Helpers
# ------------------------------------------------------------------

def _ch_escape(s: str) -> str:
    if not s:
        return ''
    return (s.replace('\\', '\\\\').replace("'", "\\'")
             .replace('\n', '\\n').replace('\r', '\\r')
             .replace('\t', '\\t').replace('\0', ''))


def _ch_query(query: str) -> Optional[str]:
    """Execute a ClickHouse SELECT and return the result text."""
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.read().decode('utf-8')
    except Exception:
        return None


def _ch_post(query: str) -> bool:
    """POST an INSERT query to ClickHouse."""
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


