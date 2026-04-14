"""
Predictive Coder — Phase 23

The cerebral cortex's delta rule analog. Real brains operate on predictive
coding: each layer predicts the input to the layer below and updates
its internal model proportional to prediction error.

This module consumes closed episodes from Phase 22 and applies a bounded
delta rule to:
  - Multi-RAG silo weights (global/local/psychology)
  - Consensus thresholds (ACTION, ESCALATE)
  - AttackerPsychologySilo TTP_PATTERNS severity values

Learning rate η=0.01. Weights are re-normalized to sum=1.0 after each
update. Thresholds are bounded within safe ranges to prevent runaway drift.

This is what converts the CNO from a reactive state machine into a
genuinely learning organism. Silo weights in Berlin drift differently
from weights in São Paulo because each deployment sees different
adversaries.

Author: HookProbe Team
License: Proprietary
Version: 23.0.0
"""

import logging
import os
import re
import threading
import time
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# ClickHouse config
CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

# Learning hyperparameters
LEARNING_RATE_ETA = 0.01         # Delta rule step size
WEIGHT_MIN = 0.15                # No single silo drops below 15%
WEIGHT_MAX = 0.60                # No single silo exceeds 60%
THRESHOLD_ACTION_BOUNDS = (0.30, 0.80)
THRESHOLD_ESCALATE_BOUNDS = (0.85, 0.99)
TTP_SEVERITY_BOUNDS = (0.10, 1.00)

# Drift persistence
DRIFT_PERSIST_INTERVAL_S = 300   # Write drift history every 5 min


class PredictiveCoder:
    """Delta-rule learning driven by episodic memory outcomes.

    Given a closed episode (predicted_score, actual_score), compute
    error and apply bounded gradient update to model parameters.

    Thread-safe. Operates on references to the consensus module's
    global constants so updates take effect on next verdict.
    """

    def __init__(self, consensus_module=None, psychology_silo=None):
        """
        Args:
            consensus_module: multi_rag_consensus module (for weight refs)
            psychology_silo: AttackerPsychologySilo instance (for TTP refs)
        """
        self._consensus_mod = consensus_module
        self._psych_silo = psychology_silo
        self._lock = threading.Lock()
        self._last_persist_ts = 0.0

        self._stats = {
            'updates_applied': 0,
            'total_error_magnitude': 0.0,
            'weight_updates': 0,
            'threshold_updates': 0,
            'ttp_severity_updates': 0,
            'drift_persist_writes': 0,
            'errors': 0,
        }

        # Capture initial weights for drift magnitude calculation
        self._initial_weights = self._snapshot_weights()

    def on_episode_closed(self, episode: Dict[str, Any]) -> None:
        """Callback from Phase 22 EpisodicMemory when an episode closes.

        Applies delta-rule update to silo weights + thresholds + TTP severities
        based on the episode's prediction_error.
        """
        outcome = episode.get('final_outcome', 'pending')
        if outcome == 'pending':
            return

        predicted = float(episode.get('initial_consensus_score', 0.5))
        actual = float(episode.get('actual_outcome_score', predicted))
        error = actual - predicted  # signed: positive means under-predicted

        if abs(error) < 0.05:
            return  # Ignore noise-level errors

        with self._lock:
            self._stats['updates_applied'] += 1
            self._stats['total_error_magnitude'] += abs(error)

        # Determine which silo agreed most with actual outcome and reward it
        silo_scores_str = episode.get('initial_silo_scores_json', '{}')
        try:
            import json as _json
            silo_scores = _json.loads(silo_scores_str)
        except Exception:
            silo_scores = {}

        if silo_scores and self._consensus_mod:
            self._update_silo_weights(silo_scores, actual, error)

        # Update TTP severities based on outcome
        ttp_sequence = episode.get('ttp_sequence', [])
        if ttp_sequence and self._psych_silo:
            self._update_ttp_severities(ttp_sequence, actual, error)

        # Update consensus thresholds
        if self._consensus_mod:
            self._update_thresholds(error)

        # Persist drift history periodically
        now = time.time()
        if now - self._last_persist_ts > DRIFT_PERSIST_INTERVAL_S:
            self._persist_drift_history()
            self._last_persist_ts = now

    def _update_silo_weights(self, silo_scores: Dict[str, float],
                              actual: float, error: float) -> None:
        """Reward silos whose predictions were closer to actual outcome."""
        if not hasattr(self._consensus_mod, 'WEIGHT_GLOBAL'):
            return

        # Compute per-silo error
        silo_errors = {}
        for name, score in silo_scores.items():
            silo_errors[name] = abs(actual - float(score))

        # Best silo: lowest error; worst silo: highest error
        if not silo_errors:
            return

        best = min(silo_errors, key=silo_errors.get)
        worst = max(silo_errors, key=silo_errors.get)
        if best == worst:
            return  # No differential signal

        weight_map = {
            'global': 'WEIGHT_GLOBAL',
            'global_threat': 'WEIGHT_GLOBAL',
            'local': 'WEIGHT_LOCAL',
            'local_baseline': 'WEIGHT_LOCAL',
            'psych': 'WEIGHT_PSYCHOLOGY',
            'attacker_psychology': 'WEIGHT_PSYCHOLOGY',
            'psychology': 'WEIGHT_PSYCHOLOGY',
        }
        best_key = weight_map.get(best)
        worst_key = weight_map.get(worst)
        if not best_key or not worst_key or best_key == worst_key:
            return

        with self._lock:
            try:
                wb = getattr(self._consensus_mod, best_key)
                ww = getattr(self._consensus_mod, worst_key)

                # Small transfer from worst to best, bounded
                delta = LEARNING_RATE_ETA * abs(error)
                new_wb = min(WEIGHT_MAX, wb + delta)
                new_ww = max(WEIGHT_MIN, ww - delta)

                # Only apply if both bounds respected
                if new_wb != wb and new_ww != ww:
                    setattr(self._consensus_mod, best_key, new_wb)
                    setattr(self._consensus_mod, worst_key, new_ww)
                    self._renormalize_weights()
                    self._stats['weight_updates'] += 1
                    logger.info(
                        "PREDICTIVE_CODER: %s %.3f→%.3f, %s %.3f→%.3f (err=%+.3f)",
                        best_key, wb, new_wb, worst_key, ww, new_ww, error)
            except Exception as e:
                logger.debug("Silo weight update error: %s", e)
                self._stats['errors'] += 1

    def _renormalize_weights(self) -> None:
        """Ensure WEIGHT_GLOBAL + WEIGHT_LOCAL + WEIGHT_PSYCHOLOGY = 1.0"""
        try:
            wg = getattr(self._consensus_mod, 'WEIGHT_GLOBAL')
            wl = getattr(self._consensus_mod, 'WEIGHT_LOCAL')
            wp = getattr(self._consensus_mod, 'WEIGHT_PSYCHOLOGY')
            total = wg + wl + wp
            if total > 0:
                setattr(self._consensus_mod, 'WEIGHT_GLOBAL', wg / total)
                setattr(self._consensus_mod, 'WEIGHT_LOCAL', wl / total)
                setattr(self._consensus_mod, 'WEIGHT_PSYCHOLOGY', wp / total)
        except Exception:
            pass

    def _update_ttp_severities(self, ttp_sequence, actual: float,
                                error: float) -> None:
        """Reward/penalize TTP severities based on outcome."""
        if not hasattr(self._psych_silo, 'TTP_PATTERNS'):
            return

        # Extract TTP keys from ttp_sequence (format: "T1071 - Application Layer Protocol")
        ttp_keys = []
        for item in ttp_sequence if isinstance(ttp_sequence, list) else []:
            # Match to TTP_PATTERNS keys (heuristic)
            if isinstance(item, str) and item.startswith('token:'):
                key = item.split(':', 1)[1].strip().upper()
                if key in self._psych_silo.TTP_PATTERNS:
                    ttp_keys.append(key)

        if not ttp_keys:
            return

        # If actual was high (threat real), bump severity up; else down
        delta = LEARNING_RATE_ETA * error  # error is signed

        with self._lock:
            for key in ttp_keys:
                try:
                    cur = self._psych_silo.TTP_PATTERNS[key]['severity']
                    new = max(TTP_SEVERITY_BOUNDS[0],
                              min(TTP_SEVERITY_BOUNDS[1], cur + delta))
                    if new != cur:
                        self._psych_silo.TTP_PATTERNS[key]['severity'] = new
                        self._stats['ttp_severity_updates'] += 1
                        logger.debug("TTP %s severity: %.3f→%.3f",
                                      key, cur, new)
                except Exception:
                    pass

    def _update_thresholds(self, error: float) -> None:
        """Shift consensus thresholds slightly based on error direction."""
        # If we consistently over-predict (error negative) → raise action threshold
        # If we consistently under-predict (error positive) → lower it
        delta = LEARNING_RATE_ETA * (-error) * 0.5  # Half rate for thresholds

        with self._lock:
            try:
                if hasattr(self._consensus_mod, 'THRESHOLD_ACTION'):
                    cur = getattr(self._consensus_mod, 'THRESHOLD_ACTION')
                    lo, hi = THRESHOLD_ACTION_BOUNDS
                    new = max(lo, min(hi, cur + delta))
                    if new != cur:
                        setattr(self._consensus_mod, 'THRESHOLD_ACTION', new)
                        self._stats['threshold_updates'] += 1
            except Exception:
                pass

    def _snapshot_weights(self) -> Dict[str, float]:
        """Capture current weight values for drift magnitude."""
        if not self._consensus_mod:
            return {}
        try:
            return {
                'global': getattr(self._consensus_mod, 'WEIGHT_GLOBAL', 0),
                'local': getattr(self._consensus_mod, 'WEIGHT_LOCAL', 0),
                'psychology': getattr(self._consensus_mod,
                                       'WEIGHT_PSYCHOLOGY', 0),
            }
        except Exception:
            return {}

    def _persist_drift_history(self) -> None:
        """Write current weight state to cno_weight_history for audit trail."""
        try:
            current = self._snapshot_weights()
            if not current:
                return
            initial = self._initial_weights
            drift = sum(abs(current[k] - initial.get(k, 0))
                        for k in current)
            query = (
                f"INSERT INTO {CH_DB}.cno_weight_history "
                f"(timestamp, weight_global, weight_local, weight_psychology, "
                f"drift_magnitude, updates_applied) VALUES ("
                f"now64(3), {current.get('global', 0)}, "
                f"{current.get('local', 0)}, "
                f"{current.get('psychology', 0)}, {drift}, "
                f"{self._stats['updates_applied']})"
            )
            _ch_post(query)
            self._stats['drift_persist_writes'] += 1
        except Exception as e:
            logger.debug("Drift persist failed: %s", e)
            self._stats['errors'] += 1

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            current = self._snapshot_weights()
            drift = sum(abs(current.get(k, 0) - self._initial_weights.get(k, 0))
                        for k in current)
            return {
                **self._stats,
                'current_weights': current,
                'initial_weights': self._initial_weights,
                'drift_magnitude': round(drift, 4),
                'learning_rate': LEARNING_RATE_ETA,
            }


def _ch_post(query: str) -> bool:
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data, method='POST')
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False
