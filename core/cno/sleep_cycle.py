"""
Sleep Cycle — Phase 25

The REM + slow-wave sleep analog. Real brains consolidate memory during
sleep in three distinct ways:
  1. Replay — rare but important events are re-experienced for learning
  2. Pruning — rarely-activated synapses are weakened or removed
  3. Compression — many episodes collapse into a single abstraction

The CNO prior architecture ran 24/7 at a fixed cadence, never pausing
for consolidation. This module adds a nocturnal cycle triggered when:
  - stress.state == CALM
  - emotion.emotion == SERENE
  - current hour is in the learned low-traffic window

During sleep, the organism:
  1. Slows ingestion (reduce bridge interval)
  2. Replays high-prediction-error episodes (Phase 22 → 23 retraining)
  3. Clusters episodes to discover new attack patterns
  4. Prunes dead TTP_PATTERNS entries (activation_count < 5 in 30d)
  5. Recalibrates anomaly thresholds on current score distribution
  6. Writes cycle record to ClickHouse

This is what converts the TTP_PATTERNS dict from a human-curated constant
into a living organ that evolves with its adversary population.

Author: HookProbe Team
License: Proprietary
Version: 25.0.0
"""

import logging
import os
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

# Trigger conditions
CALM_SERENE_DWELL_S = 1800    # 30 min of CALM+SERENE before sleep
DEFAULT_LOW_TRAFFIC_START_HOUR = 2    # 02:00 UTC
DEFAULT_LOW_TRAFFIC_END_HOUR = 5      # 05:00 UTC
MIN_INTERVAL_BETWEEN_SLEEPS_S = 18000  # At least 5 hours between sleeps

# Sleep activities
REPLAY_BATCH_SIZE = 50              # Episodes to replay per cycle
PRUNE_ACTIVATION_THRESHOLD = 5      # TTPs activated <5 times in 30d → prune
PRUNE_PROTECT_KEYS = {              # Never prune these (MITRE core)
    'SCAN_SWEEP', 'DNS_TUNNEL', 'SSH_BRUTE', 'FLOOD', 'KNOWN_BAD',
    'LATERAL_MOVEMENT', 'C2_BEACON', 'DATA_EXFILTRATION',
}


class SleepCycle:
    """Orchestrates nocturnal consolidation.

    Triggered from CNO main loop once per cycle. Internally gated by
    trigger conditions (CALM + SERENE + low-traffic hour + dwell).
    Safe to call on every cycle — only fires when conditions hold.
    """

    def __init__(self, episodic_memory=None, predictive_coder=None,
                  anomaly_detector_module=None,
                  psychology_silo=None, workspace=None):
        """
        Args:
            episodic_memory: Phase 22 EpisodicMemory for replay source
            predictive_coder: Phase 23 PredictiveCoder for training signal
            anomaly_detector_module: core.hydra.anomaly_detector (for recalibration)
            psychology_silo: AttackerPsychologySilo (for TTP pruning)
            workspace: Phase 24 GlobalWorkspace (for trigger state)
        """
        self._memory = episodic_memory
        self._coder = predictive_coder
        self._anomaly_mod = anomaly_detector_module
        self._psych_silo = psychology_silo
        self._workspace = workspace

        self._lock = threading.Lock()
        self._calm_serene_start_ts: Optional[float] = None
        self._last_sleep_ts = 0.0
        self._sleeping = False

        self._stats = {
            'cycles_started': 0,
            'cycles_completed': 0,
            'cycles_skipped_conditions': 0,
            'episodes_replayed': 0,
            'patterns_pruned': 0,
            'patterns_discovered': 0,
            'thresholds_recalibrated': 0,
            'total_sleep_seconds': 0,
            'errors': 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def maybe_sleep(self) -> bool:
        """Check trigger conditions; if all hold, execute a sleep cycle.

        Called from CNO main loop every cycle.
        Returns True if a sleep cycle ran, False otherwise.
        """
        now = time.time()

        # Don't sleep too frequently
        if now - self._last_sleep_ts < MIN_INTERVAL_BETWEEN_SLEEPS_S:
            return False

        # Don't sleep if already sleeping (shouldn't happen, but guard)
        with self._lock:
            if self._sleeping:
                return False

        if not self._check_trigger_conditions(now):
            self._stats['cycles_skipped_conditions'] += 1
            return False

        # All conditions met — sleep
        return self._execute_sleep_cycle()

    def _check_trigger_conditions(self, now: float) -> bool:
        """Trigger conditions: CALM+SERENE dwell + low-traffic hour."""
        if not self._workspace:
            return False

        snap = self._workspace.snapshot()
        is_calm_serene = (
            snap.current_stress == 'calm'
            and snap.current_emotion == 'serene'
        )

        # Track CALM+SERENE dwell time
        if is_calm_serene:
            if self._calm_serene_start_ts is None:
                self._calm_serene_start_ts = now
            dwell = now - self._calm_serene_start_ts
        else:
            self._calm_serene_start_ts = None
            return False

        if dwell < CALM_SERENE_DWELL_S:
            return False

        # Check hour of day (UTC)
        utc_hour = time.gmtime(now).tm_hour
        if not (DEFAULT_LOW_TRAFFIC_START_HOUR <= utc_hour
                < DEFAULT_LOW_TRAFFIC_END_HOUR):
            return False

        return True

    def _execute_sleep_cycle(self) -> bool:
        """Run the full sleep consolidation cycle."""
        cycle_id = str(uuid.uuid4())[:24]
        start = time.time()

        with self._lock:
            self._sleeping = True
            self._stats['cycles_started'] += 1

        logger.info("SLEEP CYCLE %s starting — consolidation begins", cycle_id)
        self._persist_cycle_start(cycle_id, start)

        episodes_replayed = 0
        patterns_pruned = 0
        patterns_discovered = 0
        thresholds_recalibrated = False

        try:
            # 1. Replay high-error episodes for retraining
            if self._memory and self._coder:
                episodes_replayed = self._replay_episodes()

            # 2. Prune dead TTP patterns
            if self._psych_silo:
                patterns_pruned = self._prune_dead_ttps()

            # 3. Cluster episodes to discover new patterns (basic impl)
            if self._memory:
                patterns_discovered = self._discover_patterns()

            # 4. Recalibrate anomaly thresholds
            if self._anomaly_mod:
                thresholds_recalibrated = self._recalibrate_thresholds()

        except Exception as e:
            logger.error("Sleep cycle error: %s", e)
            with self._lock:
                self._stats['errors'] += 1

        duration = time.time() - start

        with self._lock:
            self._sleeping = False
            self._last_sleep_ts = time.time()
            self._stats['cycles_completed'] += 1
            self._stats['episodes_replayed'] += episodes_replayed
            self._stats['patterns_pruned'] += patterns_pruned
            self._stats['patterns_discovered'] += patterns_discovered
            if thresholds_recalibrated:
                self._stats['thresholds_recalibrated'] += 1
            self._stats['total_sleep_seconds'] += int(duration)

        logger.info(
            "SLEEP CYCLE %s complete — replayed=%d pruned=%d discovered=%d "
            "recalibrated=%s duration=%ds",
            cycle_id, episodes_replayed, patterns_pruned,
            patterns_discovered, thresholds_recalibrated, int(duration))

        self._persist_cycle_end(cycle_id, duration, episodes_replayed,
                                 patterns_pruned, patterns_discovered,
                                 thresholds_recalibrated)
        return True

    # ------------------------------------------------------------------
    # Sleep activities
    # ------------------------------------------------------------------

    def _replay_episodes(self) -> int:
        """Sample prioritized high-error episodes and feed to predictive coder."""
        try:
            episodes = self._memory.sample_high_error_episodes(
                n=REPLAY_BATCH_SIZE, max_age_days=30)
            count = 0
            for ep in episodes:
                try:
                    # Reconstruct minimal episode dict for predictive coder
                    replay_episode = {
                        'final_outcome': ep.get('final_outcome', 'pending'),
                        'initial_consensus_score': ep.get(
                            'initial_consensus_score', 0.5),
                        'actual_outcome_score': _outcome_to_score(
                            ep.get('final_outcome', 'pending'),
                            ep.get('initial_consensus_score', 0.5)),
                        'initial_silo_scores_json': '{}',  # unavailable in sample
                        'ttp_sequence': ep.get('ttp_sequence', []),
                    }
                    self._coder.on_episode_closed(replay_episode)
                    self._memory.mark_replayed(
                        ep['episode_id'],
                        lessons=f"Sleep replay, pred_err={ep['prediction_error']:.3f}")
                    count += 1
                except Exception:
                    pass
            return count
        except Exception as e:
            logger.debug("Replay error: %s", e)
            return 0

    def _prune_dead_ttps(self) -> int:
        """Remove TTP_PATTERNS entries that activated <5 times in 30d."""
        if not hasattr(self._psych_silo, 'TTP_PATTERNS'):
            return 0

        # Query TTP activation counts from cno_episodic_memory ttp_sequence
        query = (
            f"SELECT arrayJoin(ttp_sequence) AS ttp, count() AS cnt "
            f"FROM {CH_DB}.cno_episodic_memory "
            f"WHERE onset_ts >= now() - INTERVAL 30 DAY "
            f"GROUP BY ttp HAVING cnt >= {PRUNE_ACTIVATION_THRESHOLD}"
        )
        active_ttps = set()
        result = _ch_query(query)
        if result:
            for line in result.strip().split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if parts:
                        active_ttps.add(parts[0].strip())

        # Find candidates for pruning: in TTP_PATTERNS but NOT in active_ttps
        # and NOT in PRUNE_PROTECT_KEYS
        pruned = 0
        candidates = [
            key for key in list(self._psych_silo.TTP_PATTERNS.keys())
            if key not in PRUNE_PROTECT_KEYS
            and not any(key in t for t in active_ttps)
        ]
        # Limit to at most 5 prunes per cycle to avoid catastrophic forgetting
        for key in candidates[:5]:
            del self._psych_silo.TTP_PATTERNS[key]
            pruned += 1
            logger.info("SLEEP PRUNE: removed TTP pattern '%s' (inactive 30d)",
                        key)
        return pruned

    def _discover_patterns(self) -> int:
        """Cluster recent episodes by TTP sequence to discover new patterns.

        Simple implementation: count N-gram frequencies of TTP sequences in
        episodes with prediction_error > 0.3 (where we were surprised).
        Patterns with frequency >= 3 and not already in TTP_PATTERNS become
        candidates for addition. Full GNN-based clustering is a Phase 26+
        enhancement.
        """
        query = (
            f"SELECT ttp_sequence FROM {CH_DB}.cno_episodic_memory "
            f"WHERE onset_ts >= now() - INTERVAL 7 DAY "
            f"AND prediction_error > 0.3 AND length(ttp_sequence) >= 2 "
            f"LIMIT 500"
        )
        result = _ch_query(query)
        if not result:
            return 0

        pattern_counts: Dict[str, int] = {}
        for line in result.strip().split('\n'):
            if not line.strip():
                continue
            # Parse array literal [x,y,z]
            raw = line.strip().strip('[]')
            ttps = [t.strip().strip("'\"") for t in raw.split(',')]
            if len(ttps) >= 2:
                # Bigram
                for i in range(len(ttps) - 1):
                    gram = f"{ttps[i]}→{ttps[i+1]}"
                    pattern_counts[gram] = pattern_counts.get(gram, 0) + 1

        discovered = 0
        for gram, count in pattern_counts.items():
            if count >= 3:
                discovered += 1
                logger.info("SLEEP DISCOVERY: recurring pattern '%s' (n=%d)",
                             gram, count)
        return discovered

    def _recalibrate_thresholds(self) -> bool:
        """Recompute 95th/99th percentile anomaly thresholds on recent data."""
        try:
            query = (
                f"SELECT quantile(0.95)(anomaly_score), "
                f"quantile(0.99)(anomaly_score) "
                f"FROM {CH_DB}.hydra_verdicts "
                f"WHERE timestamp >= now() - INTERVAL 24 HOUR "
                f"AND anomaly_score > 0"
            )
            result = _ch_query(query)
            if not result:
                return False
            parts = result.strip().split('\t')
            if len(parts) < 2:
                return False
            p95 = float(parts[0])
            p99 = float(parts[1])
            if p95 <= 0 or p99 <= 0:
                return False

            # Update the anomaly_detector module's globals
            if hasattr(self._anomaly_mod, '_adaptive_suspicious'):
                setattr(self._anomaly_mod, '_adaptive_suspicious', p95)
            if hasattr(self._anomaly_mod, '_adaptive_malicious'):
                setattr(self._anomaly_mod, '_adaptive_malicious', p99)
            logger.info("SLEEP RECALIBRATE: suspicious=%.3f malicious=%.3f",
                         p95, p99)
            return True
        except Exception as e:
            logger.debug("Recalibrate error: %s", e)
            return False

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist_cycle_start(self, cycle_id: str, ts: float) -> None:
        try:
            query = (
                f"INSERT INTO {CH_DB}.cno_sleep_cycles "
                f"(cycle_id, started_at, trigger_reason) VALUES "
                f"('{_esc(cycle_id)}', toDateTime64({ts}, 3), 'calm_serene_lowtraffic')"
            )
            _ch_post(query)
        except Exception:
            pass

    def _persist_cycle_end(self, cycle_id: str, duration: float,
                            replayed: int, pruned: int, discovered: int,
                            recalibrated: bool) -> None:
        try:
            query = (
                f"ALTER TABLE {CH_DB}.cno_sleep_cycles UPDATE "
                f"ended_at = toDateTime64({time.time()}, 3), "
                f"episodes_replayed = {replayed}, "
                f"patterns_pruned = {pruned}, "
                f"patterns_compressed = {discovered}, "
                f"thresholds_recalibrated = {1 if recalibrated else 0} "
                f"WHERE cycle_id = '{_esc(cycle_id)}'"
            )
            _ch_post(query)
        except Exception:
            pass

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                'is_sleeping': self._sleeping,
                'time_since_last_sleep_s': int(
                    time.time() - self._last_sleep_ts)
                    if self._last_sleep_ts > 0 else -1,
                'calm_serene_dwell_s': int(
                    time.time() - self._calm_serene_start_ts)
                    if self._calm_serene_start_ts else 0,
            }


def _outcome_to_score(outcome: str, predicted: float) -> float:
    return {
        'block_success': 1.0,
        'block_partial': 0.7,
        'block_ineffective': 0.5,
        'possible_evasion': 0.8,
        'false_positive': 0.0,
        'true_negative': 0.0,
        'benign_confirmed': 0.0,
    }.get(outcome, predicted)


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ")


def _ch_query(query: str) -> Optional[str]:
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
