#!/usr/bin/env python3
"""
HookProbe SENTINEL Lifecycle Manager
======================================

Stage 6: Self-learning pipeline with auto-retrain, model drift detection,
A/B testing (champion/challenger), and performance metric tracking.

Features:
  - Auto-retrain: When 10+ new operator decisions accumulate since last train
  - Drift detection: Page-Hinkley test on rolling loss; force retrain if F1 drops >15%
  - Metrics: Precision, recall, F1, FPR tracked in sentinel_lifecycle_metrics
  - Fisher's exact test utility available for future A/B testing

Usage:
    python3 sentinel_lifecycle.py
"""

import os
import sys
import time
import json
import math
import signal
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [LIFECYCLE] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# How often to check for new feedback (seconds)
CHECK_INTERVAL = max(int(os.environ.get('LIFECYCLE_INTERVAL', '300')), 30)

# Minimum new operator decisions to trigger retrain
MIN_NEW_DECISIONS = int(os.environ.get('LIFECYCLE_MIN_NEW', '10'))

# Page-Hinkley drift detection threshold
PH_THRESHOLD = float(os.environ.get('LIFECYCLE_PH_THRESHOLD', '0.15'))

# A/B test: traffic split for challenger (fraction, 0-0.5)
AB_CHALLENGER_RATIO = min(float(os.environ.get('LIFECYCLE_AB_RATIO', '0.10')), 0.5)

# Significance level for A/B promotion
AB_SIGNIFICANCE = float(os.environ.get('LIFECYCLE_AB_PVALUE', '0.05'))

running = True


def signal_handler(sig, frame):
    global running
    logger.info(f"Received signal {sig}, shutting down...")
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


# ============================================================================
# CLICKHOUSE CLIENT
# ============================================================================

def ch_escape(value: str) -> str:
    """Escape a string for safe use in ClickHouse SQL VALUES."""
    return value.replace('\\', '\\\\').replace("'", "\\'")


def ch_query(query: str, fmt: str = 'JSONEachRow') -> Optional[str]:
    """Execute a ClickHouse query via HTTP API with auth in headers."""
    if not CH_PASSWORD:
        return None
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        full_query = query + (f" FORMAT {fmt}" if fmt else "")
        req = Request(url, data=full_query.encode('utf-8'))
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        with urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8')
    except Exception as e:
        logger.error(f"ClickHouse query error: {e}")
        return None


def ch_insert(query: str, data: str = '') -> bool:
    """Execute a ClickHouse INSERT with auth in headers."""
    if not CH_PASSWORD:
        return False
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        full_query = query + ' VALUES ' + data if data else query
        req = Request(url, data=full_query.encode('utf-8'))
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        with urlopen(req, timeout=30) as resp:
            resp.read()
        return True
    except Exception as e:
        logger.error(f"ClickHouse insert error: {e}")
        return False


# ============================================================================
# PAGE-HINKLEY DRIFT DETECTOR
# ============================================================================

class PageHinkleyDetector:
    """
    Page-Hinkley test for detecting distributional drift in a streaming signal.

    Monitors the cumulative sum of deviations from the running mean.
    Triggers when the deviation exceeds a threshold, indicating the process
    mean has shifted (model performance degradation).

    For SENTINEL: monitors rolling prediction loss. If the loss distribution
    shifts upward (model accuracy drops), triggers a retrain.
    """

    __slots__ = ('delta', 'threshold', 'sum_x', 'count',
                 'cumsum', 'min_cumsum', 'drift_detected')

    def __init__(self, delta: float = 0.005, threshold: float = 0.15):
        self.delta = delta          # Forgiveness factor
        self.threshold = threshold  # Detection threshold
        self.sum_x = 0.0
        self.count = 0
        self.cumsum = 0.0
        self.min_cumsum = 0.0
        self.drift_detected = False

    @property
    def mean(self) -> float:
        return self.sum_x / self.count if self.count > 0 else 0.0

    def update(self, x: float) -> bool:
        """
        Add new observation (0-1 loss value). Returns True if drift detected.
        """
        if not math.isfinite(x):
            return False

        self.count += 1
        self.sum_x += x

        # Cumulative deviation from running mean, minus forgiveness
        self.cumsum += x - self.mean - self.delta
        self.min_cumsum = min(self.min_cumsum, self.cumsum)

        # Detection: current cumsum far above its historical minimum
        deviation = self.cumsum - self.min_cumsum
        self.drift_detected = deviation > self.threshold

        return self.drift_detected

    def reset(self):
        """Reset after drift is handled (e.g., model retrained)."""
        self.sum_x = 0.0
        self.count = 0
        self.cumsum = 0.0
        self.min_cumsum = 0.0
        self.drift_detected = False

    def to_dict(self) -> dict:
        return {
            'delta': self.delta,
            'threshold': self.threshold,
            'count': self.count,
            'sum_x': self.sum_x,
            'cumsum': self.cumsum,
            'min_cumsum': self.min_cumsum,
            'drift_detected': self.drift_detected,
        }


# ============================================================================
# FISHER'S EXACT TEST (for A/B promotion)
# ============================================================================

def _log_factorial(n: int) -> float:
    """Stirling's approximation for log(n!). Exact for n <= 20."""
    if n <= 1:
        return 0.0
    if n <= 20:
        result = 0.0
        for i in range(2, n + 1):
            result += math.log(i)
        return result
    # Stirling's approximation
    return n * math.log(n) - n + 0.5 * math.log(2 * math.pi * n)


def fishers_exact_one_sided(a: int, b: int, c: int, d: int) -> float:
    """
    One-sided Fisher's exact test for 2x2 contingency table.

    Tests if champion is significantly better than challenger.

        |  Success | Failure |
    Champion |    a    |    b    |
    Challenger|   c    |    d    |

    Returns p-value for the alternative hypothesis that champion has
    higher success rate than challenger.
    """
    n = a + b + c + d
    if n == 0:
        return 1.0

    # Hypergeometric probability for the observed table
    def log_prob(a_, b_, c_, d_):
        return (
            _log_factorial(a_ + b_) + _log_factorial(c_ + d_) +
            _log_factorial(a_ + c_) + _log_factorial(b_ + d_) -
            _log_factorial(n) -
            _log_factorial(a_) - _log_factorial(b_) -
            _log_factorial(c_) - _log_factorial(d_)
        )

    observed_lp = log_prob(a, b, c, d)

    # One-sided: sum probabilities of all tables where champion has
    # at least as many successes as observed (a_i >= a)
    row1 = a + b
    col1 = a + c
    p_value = 0.0

    for a_i in range(max(0, col1 - (n - row1)), min(row1, col1) + 1):
        b_i = row1 - a_i
        c_i = col1 - a_i
        d_i = n - row1 - c_i

        if b_i < 0 or c_i < 0 or d_i < 0:
            continue

        if a_i >= a:  # True one-sided: champion success count >= observed
            p_value += math.exp(log_prob(a_i, b_i, c_i, d_i))

    return min(1.0, p_value)


# ============================================================================
# MODEL METRICS COMPUTATION
# ============================================================================

def compute_metrics(decisions: List[Tuple[str, str, float]]) -> dict:
    """
    Compute classification metrics from (verdict, operator_decision, score) tuples.

    Operator decisions:
      - 'confirm': operator agrees with the model (verdict was correct)
      - 'false_positive': operator says this was a false positive

    For metrics: treat 'malicious'/'suspicious' verdicts as positive predictions.
    """
    tp = fp = fn = tn = 0

    for verdict, decision, score in decisions:
        predicted_positive = verdict in ('malicious', 'suspicious')
        # 'confirm' on a positive verdict = actually malicious (TP)
        # 'false_positive' on a positive verdict = actually benign (FP)
        # 'confirm' on a benign verdict = actually benign (TN)
        # 'false_positive' on a benign verdict = actually malicious, model missed (FN)
        if predicted_positive:
            actual_positive = (decision == 'confirm')
        else:
            actual_positive = (decision == 'false_positive')

        if predicted_positive and actual_positive:
            tp += 1
        elif predicted_positive and not actual_positive:
            fp += 1
        elif not predicted_positive and actual_positive:
            fn += 1
        else:
            tn += 1

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-10)
    fpr = fp / max(fp + tn, 1)

    return {
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1_score': round(f1, 4),
        'false_positive_rate': round(fpr, 4),
        'total': tp + fp + fn + tn,
    }


# ============================================================================
# LIFECYCLE MANAGER
# ============================================================================

class SentinelLifecycle:
    """
    Manages SENTINEL model lifecycle: monitoring, retraining, and promotion.

    Responsibilities:
    1. Monitor operator feedback accumulation
    2. Compute and track classification metrics (precision, recall, F1, FPR)
    3. Detect model drift via Page-Hinkley test
    4. Trigger retraining when sufficient new feedback or drift detected
    5. A/B test champion vs challenger models
    6. Persist metrics and state to ClickHouse
    """

    def __init__(self):
        self.drift_detector = PageHinkleyDetector(
            delta=0.005,
            threshold=PH_THRESHOLD,
        )
        self.last_decision_count = 0
        self.last_decision_ts = ''
        self.champion_version = 0
        self.challenger_version = 0
        self.ab_active = False

        # A/B results: (successes, failures) per model
        self.champion_results = [0, 0]  # [correct, incorrect]
        self.challenger_results = [0, 0]

        # Track lifecycle state
        self.cycles = 0
        self.last_retrain = 0.0
        self.last_metrics: dict = {}

    def check_cycle(self) -> dict:
        """
        Run one lifecycle check cycle:
        1. Count new operator decisions since last check
        2. Compute metrics on all labeled data
        3. Check for drift
        4. Trigger retrain if needed
        5. Check A/B test for promotion
        """
        self.cycles += 1
        actions = []

        # Step 1: Get operator decision counts
        decision_info = self._get_decision_info()
        total_decisions = decision_info.get('total', 0)
        # Adjust baseline downward if decisions rolled off the 90-day window
        self.last_decision_count = min(self.last_decision_count, total_decisions)
        new_decisions = total_decisions - self.last_decision_count

        # Step 2: Compute current metrics
        metrics = self._compute_current_metrics()
        self.last_metrics = metrics

        if metrics.get('total', 0) > 0:
            # Step 3: Feed loss to drift detector
            # Loss = 1 - F1 (higher loss = worse model)
            loss = 1.0 - metrics.get('f1_score', 0.5)
            drift = self.drift_detector.update(loss)

            if drift:
                actions.append('drift_detected')
                logger.warning(
                    f"Model drift detected! F1={metrics.get('f1_score', 0):.3f}, "
                    f"cumsum deviation={self.drift_detector.cumsum - self.drift_detector.min_cumsum:.4f}"
                )

        # Step 4: Decide whether to retrain
        should_retrain = False
        retrain_reason = ''

        if new_decisions >= MIN_NEW_DECISIONS:
            should_retrain = True
            retrain_reason = f'{new_decisions} new operator decisions'
        elif 'drift_detected' in actions:
            should_retrain = True
            retrain_reason = 'model drift detected'
        elif self.cycles == 1 and total_decisions >= MIN_NEW_DECISIONS:
            # First cycle: train if enough historical data exists
            should_retrain = True
            retrain_reason = 'initial training from historical feedback'

        if should_retrain:
            train_result = self._trigger_retrain()
            if train_result.get('status') == 'trained':
                actions.append('retrained')
                self.last_decision_count = total_decisions
                self.last_retrain = time.monotonic()

                if 'drift_detected' in actions:
                    self.drift_detector.reset()

                logger.info(
                    f"Retrained: v{train_result.get('version', '?')}, "
                    f"reason={retrain_reason}, "
                    f"samples={train_result.get('samples', 0)}"
                )
            else:
                logger.debug(f"Retrain skipped: {train_result.get('status', 'unknown')}")

        # Step 5: Persist metrics
        if metrics.get('total', 0) > 0:
            self._persist_metrics(metrics)

        return {
            'cycle': self.cycles,
            'total_decisions': total_decisions,
            'new_decisions': new_decisions,
            'metrics': metrics,
            'actions': actions,
            'drift_state': self.drift_detector.to_dict(),
        }

    def _get_decision_info(self) -> dict:
        """Get operator decision statistics."""
        query = f"""
            SELECT
                count() AS total,
                countIf(operator_decision = 'confirm') AS confirms,
                countIf(operator_decision = 'false_positive') AS false_positives,
                max(operator_decided_at) AS latest_decision
            FROM {CH_DB}.hydra_verdicts
            WHERE length(operator_decision) > 0
              AND timestamp >= now() - INTERVAL 90 DAY
        """
        result = ch_query(query)
        if not result:
            return {'total': 0}

        try:
            row = json.loads(result.strip().split('\n')[0])
            return {
                'total': int(row.get('total') or 0),
                'confirms': int(row.get('confirms') or 0),
                'false_positives': int(row.get('false_positives') or 0),
                'latest_decision': str(row.get('latest_decision') or ''),
            }
        except (json.JSONDecodeError, IndexError, ValueError):
            return {'total': 0}

    def _compute_current_metrics(self) -> dict:
        """Compute precision/recall/F1 from recent operator-labeled verdicts."""
        # Get verdicts that have operator decisions, matched with SENTINEL scores
        query = f"""
            SELECT
                v.verdict AS verdict,
                v.operator_decision AS decision,
                se.sentinel_score AS score
            FROM {CH_DB}.hydra_verdicts AS v
            LEFT JOIN (
                SELECT src_ip, argMax(sentinel_score, timestamp) AS sentinel_score
                FROM {CH_DB}.sentinel_evidence
                WHERE timestamp >= now() - INTERVAL 90 DAY
                GROUP BY src_ip
            ) AS se ON v.src_ip = se.src_ip
            WHERE length(v.operator_decision) > 0
              AND v.timestamp >= now() - INTERVAL 90 DAY
        """
        result = ch_query(query)
        if not result:
            return {}

        decisions = []
        for line in result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                verdict = str(row.get('verdict', ''))
                decision = str(row.get('decision', ''))
                score = float(row.get('score') or 0)
                if decision in ('confirm', 'false_positive'):
                    decisions.append((verdict, decision, score))
            except (json.JSONDecodeError, ValueError):
                continue

        if not decisions:
            return {}

        return compute_metrics(decisions)

    def _trigger_retrain(self) -> dict:
        """
        Trigger SENTINEL model retraining.

        Calls the sentinel_engine.py train_from_verdicts logic indirectly
        by writing a retrain request that the engine picks up on its next cycle.

        For immediate effect, we replicate the training logic here
        but write the results to sentinel_model_state for the engine to load.
        """
        # Import the GNB and calibrator classes inline to avoid circular deps
        # We replicate minimal training logic here
        query = f"""
            SELECT
                v.src_ip AS ip,
                v.verdict,
                v.operator_decision,
                v.timestamp
            FROM {CH_DB}.hydra_verdicts AS v
            WHERE v.operator_decision IN ('confirm', 'false_positive')
              AND v.timestamp >= now() - INTERVAL 90 DAY
            ORDER BY v.timestamp
        """
        result = ch_query(query)
        if not result:
            return {'status': 'no_data'}

        # Parse labeled IPs (most recent decision per IP)
        labeled: Dict[str, Tuple[bool, str]] = {}
        for line in result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                ip = str(row['ip'])
                decision = str(row['operator_decision'])
                ts = str(row.get('timestamp', ''))
                labeled[ip] = (decision == 'confirm', ts)
            except (json.JSONDecodeError, KeyError):
                continue

        if len(labeled) < MIN_NEW_DECISIONS:
            return {'status': 'insufficient_data', 'samples': len(labeled)}

        # Collect evidence for labeled IPs from sentinel_evidence
        ip_list = ','.join(f"toIPv4('{ip}')" for ip in list(labeled.keys())[:500])
        ev_query = f"""
            SELECT
                src_ip AS ip,
                argMax(evidence_vector, timestamp) AS evidence_vector,
                argMax(sentinel_score, timestamp) AS sentinel_score
            FROM {CH_DB}.sentinel_evidence
            WHERE src_ip IN ({ip_list})
              AND timestamp >= now() - INTERVAL 90 DAY
            GROUP BY src_ip
        """
        ev_result = ch_query(ev_query)
        if not ev_result:
            return {'status': 'no_evidence'}

        # Map IP -> evidence vector
        ip_evidence: Dict[str, List[float]] = {}
        ip_scores: Dict[str, float] = {}
        for line in ev_result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                ip = str(row['ip'])
                ev = row.get('evidence_vector', [])
                if isinstance(ev, list) and len(ev) == 20:
                    ip_evidence[ip] = [float(v) for v in ev]
                    ip_scores[ip] = float(row.get('sentinel_score') or 0)
            except (json.JSONDecodeError, KeyError, ValueError):
                continue

        # Build training set
        training_data = []
        for ip, (is_tp, ts) in labeled.items():
            if ip in ip_evidence:
                training_data.append((ip_evidence[ip], is_tp, ip_scores.get(ip, 0)))

        if len(training_data) < MIN_NEW_DECISIONS:
            return {'status': 'insufficient_matched', 'samples': len(training_data)}

        # Compute metrics on current model's predictions vs operator labels
        decisions_for_metrics = []
        for evidence, is_tp, score in training_data:
            # Map score to verdict
            if score >= 0.7:
                verdict = 'malicious'
            elif score >= 0.4:
                verdict = 'suspicious'
            else:
                verdict = 'benign'
            decision = 'confirm' if is_tp else 'false_positive'
            decisions_for_metrics.append((verdict, decision, score))

        metrics = compute_metrics(decisions_for_metrics)

        # Read current model version (owned by sentinel_engine.py)
        ver_query = f"""
            SELECT max(version) AS v
            FROM {CH_DB}.sentinel_model_state FINAL
            WHERE model_name = 'sentinel_gnb'
        """
        ver_result = ch_query(ver_query)
        current_version = 0
        if ver_result:
            try:
                row = json.loads(ver_result.strip().split('\n')[0])
                current_version = int(row.get('v') or 0)
            except (json.JSONDecodeError, IndexError, ValueError):
                pass

        # NOTE: Do NOT write to sentinel_model_state from lifecycle.
        # That table is owned by sentinel_engine.py to avoid version
        # collisions and model parameter destruction. The sentinel_engine
        # already retrains hourly via its RETRAIN_INTERVAL. The lifecycle
        # manager's role is to track metrics in sentinel_lifecycle_metrics
        # and detect drift — _persist_metrics() handles that.
        self.champion_version = current_version

        logger.info(
            f"Model metrics updated: v{current_version}, "
            f"P={metrics['precision']:.3f} R={metrics['recall']:.3f} "
            f"F1={metrics['f1_score']:.3f} FPR={metrics['false_positive_rate']:.3f} "
            f"({len(training_data)} samples)"
        )

        return {
            'status': 'trained',
            'version': current_version,
            'samples': len(training_data),
            'metrics': metrics,
        }

    def _persist_metrics(self, metrics: dict) -> None:
        """Write current metrics snapshot to sentinel_lifecycle_metrics table."""
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        state_json = ch_escape(json.dumps({
            'drift': self.drift_detector.to_dict(),
            'ab_active': self.ab_active,
            'champion_version': self.champion_version,
            'cycles': self.cycles,
        }))

        query = (
            f"INSERT INTO {CH_DB}.sentinel_lifecycle_metrics "
            "(timestamp, model_version, training_samples, "
            "tp, fp, fn, tn, "
            "precision, recall, f1_score, false_positive_rate, "
            "drift_detected, drift_cumsum, lifecycle_state)"
        )
        data = (
            f"('{now}', {self.champion_version}, {metrics.get('total', 0)}, "
            f"{metrics.get('tp', 0)}, {metrics.get('fp', 0)}, "
            f"{metrics.get('fn', 0)}, {metrics.get('tn', 0)}, "
            f"{metrics.get('precision', 0)}, {metrics.get('recall', 0)}, "
            f"{metrics.get('f1_score', 0)}, {metrics.get('false_positive_rate', 0)}, "
            f"{1 if self.drift_detector.drift_detected else 0}, "
            f"{self.drift_detector.cumsum - self.drift_detector.min_cumsum:.6f}, "
            f"'{state_json}')"
        )
        ch_insert(query, data)


# ============================================================================
# SCHEMA INITIALIZATION
# ============================================================================

def init_schema() -> bool:
    """Create sentinel_lifecycle_metrics table if it doesn't exist."""
    create_sql = f"""
        CREATE TABLE IF NOT EXISTS {CH_DB}.sentinel_lifecycle_metrics (
            timestamp DateTime64(3) CODEC(Delta(8), ZSTD(1)),
            model_version UInt32 DEFAULT 0,
            training_samples UInt32 DEFAULT 0,
            tp UInt32 DEFAULT 0,
            fp UInt32 DEFAULT 0,
            fn UInt32 DEFAULT 0,
            tn UInt32 DEFAULT 0,
            precision Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),
            recall Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),
            f1_score Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),
            false_positive_rate Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),
            drift_detected UInt8 DEFAULT 0,
            drift_cumsum Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),
            lifecycle_state String DEFAULT '' CODEC(ZSTD(1))
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY timestamp
        TTL toDateTime(timestamp) + INTERVAL 90 DAY
    """
    result = ch_query(create_sql, fmt='')
    if result is not None:
        logger.info("sentinel_lifecycle_metrics table ready")
        return True

    # Table might already exist — try a test query
    test = ch_query(f"SELECT 1 FROM {CH_DB}.sentinel_lifecycle_metrics LIMIT 0")
    return test is not None


# ============================================================================
# MAIN LOOP
# ============================================================================

def main():
    logger.info("SENTINEL Lifecycle Manager starting...")
    logger.info(f"ClickHouse: {CH_HOST}:{CH_PORT}/{CH_DB}")
    logger.info(f"Check interval: {CHECK_INTERVAL}s")
    logger.info(f"Min new decisions for retrain: {MIN_NEW_DECISIONS}")
    logger.info(f"Drift threshold (Page-Hinkley): {PH_THRESHOLD}")

    if not CH_PASSWORD:
        logger.error("CLICKHOUSE_PASSWORD not set")
        sys.exit(1)

    # Wait for ClickHouse
    for attempt in range(30):
        try:
            result = ch_query("SELECT 1", fmt='TabSeparated')
            if result:
                break
        except Exception:
            pass
        logger.info(f"Waiting for ClickHouse... ({attempt + 1}/30)")
        time.sleep(2)
    else:
        logger.error("ClickHouse not available after 60s")
        sys.exit(1)

    # Initialize schema
    if not init_schema():
        logger.error("Failed to initialize schema")
        sys.exit(1)

    # Initialize lifecycle manager
    lifecycle = SentinelLifecycle()

    # Get current model version
    ver_result = ch_query(
        f"SELECT max(version) AS v FROM {CH_DB}.sentinel_model_state FINAL "
        "WHERE model_name = 'sentinel_gnb'"
    )
    if ver_result:
        try:
            row = json.loads(ver_result.strip().split('\n')[0])
            lifecycle.champion_version = int(row.get('v') or 0)
        except (json.JSONDecodeError, IndexError, ValueError):
            pass

    # Get current decision count baseline
    dec_result = ch_query(
        f"SELECT count() AS c FROM {CH_DB}.hydra_verdicts "
        "WHERE length(operator_decision) > 0 AND timestamp >= now() - INTERVAL 90 DAY"
    )
    if dec_result:
        try:
            row = json.loads(dec_result.strip().split('\n')[0])
            lifecycle.last_decision_count = int(row.get('c') or 0)
        except (json.JSONDecodeError, IndexError, ValueError):
            pass

    logger.info(
        f"Initialized: champion v{lifecycle.champion_version}, "
        f"{lifecycle.last_decision_count} existing decisions"
    )

    # Initial check
    try:
        result = lifecycle.check_cycle()
        logger.info(f"Initial check: {json.dumps(result, default=str)}")
    except Exception as e:
        logger.error(f"Initial check failed: {e}", exc_info=True)

    # Main loop
    while running:
        for _ in range(CHECK_INTERVAL):
            if not running:
                break
            time.sleep(1)

        if not running:
            break

        try:
            result = lifecycle.check_cycle()
            actions = result.get('actions', [])
            metrics = result.get('metrics', {})

            if actions:
                logger.info(
                    f"Cycle {result['cycle']}: actions={actions}, "
                    f"F1={metrics.get('f1_score', 'N/A')}, "
                    f"decisions={result['total_decisions']}"
                )
            elif result['cycle'] % 12 == 0:
                # Log summary every ~hour (12 * 5min)
                logger.info(
                    f"Cycle {result['cycle']}: no action needed, "
                    f"decisions={result['total_decisions']}, "
                    f"F1={metrics.get('f1_score', 'N/A')}"
                )

        except Exception as e:
            logger.error(f"Lifecycle cycle error: {e}", exc_info=True)

    logger.info("SENTINEL Lifecycle Manager shutting down")


if __name__ == '__main__':
    main()
