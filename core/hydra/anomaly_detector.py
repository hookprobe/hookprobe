#!/usr/bin/env python3
"""
HookProbe HYDRA Anomaly Detector
==================================

Isolation Forest anomaly detection on 24-feature IP behavior vectors.

Modes:
  - BASELINE: Collects normal traffic features for initial model training
  - DETECT:   Scores new observations against trained model
  - RETRAIN:  Periodically retrains on labeled data (operator feedback)

Scoring:
  - anomaly_score < 0.5   → benign
  - anomaly_score 0.5-0.7 → suspicious (alert only)
  - anomaly_score > 0.7   → malicious  (auto-block if 3+ consecutive windows)

Output:
  - ClickHouse: hydra_verdicts table
  - Discord alerts for malicious verdicts

Usage:
    python3 anomaly_detector.py [--mode baseline|detect]
"""

import os
import sys
import time
import json
import math
import signal
import pickle
import logging
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [ANOMALY] %(levelname)s: %(message)s'
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

DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK_URL', '')

# Detection interval (seconds) — how often to score new features
DETECT_INTERVAL = int(os.environ.get('DETECT_INTERVAL', '300'))  # 5 minutes

# Minimum training samples before model is usable
MIN_TRAINING_SAMPLES = int(os.environ.get('MIN_TRAINING_SAMPLES', '100'))

# Baseline collection period (hours) — how long to collect before first train
BASELINE_HOURS = int(os.environ.get('BASELINE_HOURS', '24'))

# Retrain interval (hours)
RETRAIN_HOURS = int(os.environ.get('RETRAIN_HOURS', '168'))  # Weekly

# Model persistence path
MODEL_DIR = Path(os.environ.get('MODEL_DIR', '/app/models'))
MODEL_PATH = MODEL_DIR / 'isolation_forest.pkl'
SCALER_PATH = MODEL_DIR / 'feature_scaler.pkl'
META_PATH = MODEL_DIR / 'model_meta.json'

# Thresholds
SCORE_SUSPICIOUS = 0.5
SCORE_MALICIOUS = 0.7

# Number of features (must match feature_extractor.py)
N_FEATURES = 24

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

def ch_query(query: str, fmt: str = 'JSONEachRow') -> Optional[str]:
    """Execute a ClickHouse query via HTTP API."""
    if not CH_PASSWORD:
        return None

    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        params = urlencode({
            'query': query + (f" FORMAT {fmt}" if fmt else ""),
            'user': CH_USER,
            'password': CH_PASSWORD,
        })
        full_url = f"{url}?{params}"

        req = Request(full_url)
        with urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8')

    except Exception as e:
        logger.error(f"ClickHouse query error: {e}")
        return None


def ch_insert(query: str, data: str = '') -> bool:
    """Execute a ClickHouse INSERT."""
    if not CH_PASSWORD:
        return False

    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        params = urlencode({
            'query': query,
            'user': CH_USER,
            'password': CH_PASSWORD,
        })
        full_url = f"{url}?{params}"

        req = Request(full_url)
        if data:
            req.data = data.encode('utf-8')
            req.add_header('Content-Type', 'text/plain')

        with urlopen(req, timeout=30) as resp:
            resp.read()
        return True

    except Exception as e:
        logger.error(f"ClickHouse insert error: {e}")
        return False


# ============================================================================
# FEATURE LOADING
# ============================================================================

def load_recent_features(window_seconds: int) -> Tuple[List[str], List[List[float]]]:
    """
    Load feature vectors from hydra_ip_features for the given time window.
    Returns (ips, feature_vectors).
    """
    query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            feature_vector
        FROM {CH_DB}.hydra_ip_features
        WHERE timestamp >= now() - INTERVAL {window_seconds} SECOND
          AND length(feature_vector) = {N_FEATURES}
        ORDER BY timestamp DESC
    """

    result = ch_query(query)
    if not result:
        return [], []

    ips = []
    vectors = []
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            vec = row['feature_vector']
            if len(vec) == N_FEATURES:
                ips.append(ip)
                vectors.append([float(v) for v in vec])
        except (json.JSONDecodeError, KeyError, TypeError):
            continue

    return ips, vectors


def load_training_data(hours: int) -> List[List[float]]:
    """
    Load training data from the last N hours.
    Excludes IPs that have been marked as malicious by operators.
    """
    query = f"""
        SELECT feature_vector
        FROM {CH_DB}.hydra_ip_features
        WHERE timestamp >= now() - INTERVAL {hours} HOUR
          AND length(feature_vector) = {N_FEATURES}
          AND src_ip NOT IN (
              SELECT src_ip
              FROM {CH_DB}.hydra_verdicts
              WHERE operator_decision = 'confirm'
                AND verdict = 'malicious'
                AND timestamp >= now() - INTERVAL {hours} HOUR
          )
        ORDER BY timestamp
    """

    result = ch_query(query)
    if not result:
        return []

    vectors = []
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            vec = row['feature_vector']
            if len(vec) == N_FEATURES:
                vectors.append([float(v) for v in vec])
        except (json.JSONDecodeError, KeyError, TypeError):
            continue

    return vectors


# ============================================================================
# ISOLATION FOREST (Pure Python — no scikit-learn dependency)
# ============================================================================
# scikit-learn is 200MB+ installed — too heavy for a container that only needs
# Isolation Forest. This pure-Python implementation follows the original
# Liu et al. 2008 paper exactly.

import random


def _c(n: int) -> float:
    """Average path length of unsuccessful search in BST (Eq. 1 from paper)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    # H(n-1) ≈ ln(n-1) + euler_gamma
    return 2.0 * (math.log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n


class IsolationTree:
    """A single isolation tree."""

    __slots__ = ('left', 'right', 'split_feature', 'split_value', 'size', 'height')

    def __init__(self):
        self.left: Optional['IsolationTree'] = None
        self.right: Optional['IsolationTree'] = None
        self.split_feature: int = -1
        self.split_value: float = 0.0
        self.size: int = 0
        self.height: int = 0

    @staticmethod
    def build(data: List[List[float]], height_limit: int, current_height: int = 0) -> 'IsolationTree':
        node = IsolationTree()
        node.size = len(data)
        node.height = current_height

        if len(data) <= 1 or current_height >= height_limit:
            return node

        n_features = len(data[0])

        # Shuffle all feature indices and try each once (no replacement)
        feature_order = list(range(n_features))
        random.shuffle(feature_order)
        q, min_val, max_val = -1, 0.0, 0.0
        for f in feature_order:
            col = [row[f] for row in data]
            lo = min(col)
            hi = max(col)
            if hi > lo:
                q, min_val, max_val = f, lo, hi
                break
        else:
            return node

        node.split_feature = q
        node.split_value = min_val + random.random() * (max_val - min_val)

        left_data = [row for row in data if row[q] < node.split_value]
        right_data = [row for row in data if row[q] >= node.split_value]

        # Avoid degenerate splits
        if len(left_data) == 0 or len(right_data) == 0:
            return node

        node.left = IsolationTree.build(left_data, height_limit, current_height + 1)
        node.right = IsolationTree.build(right_data, height_limit, current_height + 1)

        return node

    def path_length(self, x: List[float]) -> float:
        """Compute path length for a single observation."""
        if self.left is None or self.right is None or self.split_feature < 0:
            return float(self.height) + _c(self.size)

        if x[self.split_feature] < self.split_value:
            return self.left.path_length(x)
        else:
            return self.right.path_length(x)


class IsolationForest:
    """
    Isolation Forest — Liu et al. 2008.

    Pure Python implementation suitable for modest-scale network anomaly detection.
    """

    def __init__(self, n_trees: int = 100, sample_size: int = 256):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.trees: List[IsolationTree] = []
        self._n_train: int = 0

    def fit(self, data: List[List[float]]) -> 'IsolationForest':
        """Train the forest on the provided data."""
        if not data:
            raise ValueError("Cannot fit on empty data")

        self._n_train = len(data)
        psi = min(self.sample_size, len(data))
        height_limit = int(math.ceil(math.log2(max(psi, 2))))

        self.trees = []
        for _ in range(self.n_trees):
            sample = random.sample(data, psi) if len(data) > psi else list(data)
            tree = IsolationTree.build(sample, height_limit)
            self.trees.append(tree)

        logger.info(f"Trained forest: {self.n_trees} trees, "
                     f"sample_size={psi}, height_limit={height_limit}, "
                     f"n_train={self._n_train}")
        return self

    def score_samples(self, data: List[List[float]]) -> List[float]:
        """
        Compute anomaly scores for each observation.

        Returns scores in [0, 1]:
          - Close to 1.0 = anomaly
          - Close to 0.5 = normal
          - Close to 0.0 = very normal (dense region)
        """
        if not self.trees:
            return [0.5] * len(data)

        psi = min(self.sample_size, self._n_train)
        c_psi = _c(psi)
        if c_psi == 0:
            return [0.5] * len(data)

        scores = []
        for x in data:
            avg_path = sum(tree.path_length(x) for tree in self.trees) / len(self.trees)
            # Anomaly score: s(x, psi) = 2^(-E(h(x)) / c(psi))
            score = 2.0 ** (-avg_path / c_psi)
            scores.append(score)

        return scores


# ============================================================================
# FEATURE NORMALIZATION (Z-Score)
# ============================================================================

class FeatureScaler:
    """Online Z-score scaler with running mean/variance."""

    def __init__(self, n_features: int):
        self.n = n_features
        self.count = 0
        self.mean = [0.0] * n_features
        self.m2 = [0.0] * n_features  # Running sum of squared differences

    def partial_fit(self, data: List[List[float]]) -> None:
        """Update running statistics with new data (Welford's)."""
        for x in data:
            self.count += 1
            for i in range(self.n):
                delta = x[i] - self.mean[i]
                self.mean[i] += delta / self.count
                delta2 = x[i] - self.mean[i]
                self.m2[i] += delta * delta2

    def transform(self, data: List[List[float]]) -> List[List[float]]:
        """Z-score normalize using current statistics."""
        if self.count < 2:
            return data

        std = [math.sqrt(self.m2[i] / self.count) if self.m2[i] > 0 else 0.0
               for i in range(self.n)]

        result = []
        for x in data:
            scaled = [(x[i] - self.mean[i]) / std[i] if std[i] > 0 else 0.0
                      for i in range(self.n)]
            result.append(scaled)
        return result

    def fit_transform(self, data: List[List[float]]) -> List[List[float]]:
        """Fit and transform in one step."""
        self.count = 0
        self.mean = [0.0] * self.n
        self.m2 = [0.0] * self.n
        self.partial_fit(data)
        return self.transform(data)


# ============================================================================
# MODEL PERSISTENCE
# ============================================================================

def save_model(forest: IsolationForest, scaler: FeatureScaler,
               meta: dict) -> bool:
    """Save model, scaler, and metadata to disk."""
    try:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)

        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(forest, f, protocol=pickle.HIGHEST_PROTOCOL)

        with open(SCALER_PATH, 'wb') as f:
            pickle.dump(scaler, f, protocol=pickle.HIGHEST_PROTOCOL)

        with open(META_PATH, 'w') as f:
            json.dump(meta, f, indent=2)

        logger.info(f"Model saved to {MODEL_DIR}")
        return True

    except Exception as e:
        logger.error(f"Failed to save model: {e}")
        return False


def load_model() -> Tuple[Optional[IsolationForest], Optional[FeatureScaler], dict]:
    """Load model from disk if available."""
    try:
        if not MODEL_PATH.exists():
            return None, None, {}

        if not SCALER_PATH.exists():
            logger.warning("Model file exists but scaler is missing — removing orphaned model")
            MODEL_PATH.unlink(missing_ok=True)
            return None, None, {}

        with open(MODEL_PATH, 'rb') as f:
            forest = pickle.load(f)

        with open(SCALER_PATH, 'rb') as f:
            scaler = pickle.load(f)

        meta = {}
        if META_PATH.exists():
            with open(META_PATH) as f:
                meta = json.load(f)

        logger.info(f"Loaded model from {MODEL_DIR} "
                     f"(trained: {meta.get('trained_at', 'unknown')})")
        return forest, scaler, meta

    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return None, None, {}


# ============================================================================
# VERDICT WRITING
# ============================================================================

def write_verdicts(verdicts: List[dict]) -> int:
    """Write anomaly verdicts to ClickHouse."""
    if not verdicts:
        return 0

    rows = []
    for v in verdicts:
        ts = v['timestamp']
        ip = v['ip']
        score = v['anomaly_score']
        model_scores = "[" + ",".join(f"{s:.6f}" for s in v.get('model_scores', [score])) + "]"
        verdict = v['verdict']
        action = v.get('action', 'none')

        rows.append(
            f"('{ts}', IPv4StringToNum('{ip}'), {score:.6f}, "
            f"{model_scores}, '{verdict}', '{action}', '', NULL)"
        )

    if not rows:
        return 0

    query = (
        f"INSERT INTO {CH_DB}.hydra_verdicts "
        "(timestamp, src_ip, anomaly_score, model_scores, verdict, "
        "action_taken, operator_decision, operator_decided_at) VALUES "
        + ", ".join(rows)
    )

    if ch_insert(query):
        return len(rows)
    return 0


# ============================================================================
# DISCORD ALERTS
# ============================================================================

def send_discord_alert(ip: str, score: float, verdict: str, action: str) -> None:
    """Send a Discord alert for malicious verdicts."""
    if not DISCORD_WEBHOOK:
        return

    try:
        embed = {
            "embeds": [{
                "title": "HYDRA ML Alert",
                "color": 0xFF6B6B if verdict == 'malicious' else 0xFFAA00,
                "fields": [
                    {"name": "Source IP", "value": f"`{ip}`", "inline": True},
                    {"name": "Anomaly Score", "value": f"{score:.3f}", "inline": True},
                    {"name": "Verdict", "value": verdict.upper(), "inline": True},
                    {"name": "Action", "value": action, "inline": True},
                ],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": "HookProbe HYDRA Anomaly Detector"}
            }]
        }

        data = json.dumps(embed).encode('utf-8')
        req = Request(DISCORD_WEBHOOK, data=data)
        req.add_header('Content-Type', 'application/json')

        with urlopen(req, timeout=10) as resp:
            resp.read()

    except Exception as e:
        logger.debug(f"Discord alert failed: {e}")


# ============================================================================
# TRACKING: Consecutive malicious detections per IP
# ============================================================================

# Track consecutive malicious windows per IP for graduated response
consecutive_malicious: Dict[str, int] = {}


def determine_action(ip: str, verdict: str) -> str:
    """
    Determine action based on verdict and history.

    - First malicious window: alert
    - Second consecutive: throttle (log for manual review)
    - Third+ consecutive: block (add to nftables via hydra_blocks)
    """
    if verdict == 'malicious':
        consecutive_malicious[ip] = consecutive_malicious.get(ip, 0) + 1
        count = consecutive_malicious[ip]

        if count >= 3:
            return 'block'
        elif count >= 2:
            return 'throttle'
        else:
            return 'alert'

    elif verdict == 'suspicious':
        # Don't reset counter on suspicious, but don't increment either
        return 'alert'

    else:
        # Benign — reset counter
        consecutive_malicious.pop(ip, None)
        return 'none'


def write_block_request(ip: str, reason: str) -> None:
    """Write a block request to hydra_blocks for nftables-sync to pick up."""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    query = (
        f"INSERT INTO {CH_DB}.hydra_blocks "
        "(timestamp, src_ip, duration_seconds, reason, source, auto_expired, event_count) VALUES "
        f"('{now}', IPv4StringToNum('{ip}'), 3600, '{reason}', 'ml', 0, 0)"
    )
    ch_insert(query)


# ============================================================================
# MAIN DETECTION LOOP
# ============================================================================

def train_model(hours: int = None) -> Tuple[Optional[IsolationForest], Optional[FeatureScaler]]:
    """Train or retrain the Isolation Forest model."""
    if hours is None:
        hours = BASELINE_HOURS

    logger.info(f"Loading training data (last {hours} hours)...")
    data = load_training_data(hours)

    if len(data) < MIN_TRAINING_SAMPLES:
        logger.warning(f"Insufficient training data: {len(data)}/{MIN_TRAINING_SAMPLES}")
        return None, None

    logger.info(f"Training on {len(data)} samples...")

    # Normalize features
    scaler = FeatureScaler(N_FEATURES)
    scaled_data = scaler.fit_transform(data)

    # Train Isolation Forest
    # sample_size=256 is the standard from the original paper
    # n_trees=100 gives good precision/speed tradeoff
    forest = IsolationForest(n_trees=100, sample_size=256)
    forest.fit(scaled_data)

    # Save model
    meta = {
        'trained_at': datetime.now(timezone.utc).isoformat(),
        'n_samples': len(data),
        'n_features': N_FEATURES,
        'n_trees': 100,
        'sample_size': 256,
        'baseline_hours': hours,
        'version': '1.0.0',
    }
    save_model(forest, scaler, meta)

    logger.info(f"Model trained and saved ({len(data)} samples, 100 trees)")
    return forest, scaler


def detect_cycle(forest: IsolationForest, scaler: FeatureScaler) -> int:
    """
    Run one detection cycle:
    1. Load feature vectors from the last detection interval
    2. Score with Isolation Forest
    3. Write verdicts to ClickHouse
    4. Send alerts for malicious detections
    """
    # Load features from the last interval window
    ips, vectors = load_recent_features(DETECT_INTERVAL)
    if not vectors:
        logger.debug("No feature vectors available for scoring")
        return 0

    # Normalize
    scaled = scaler.transform(vectors)

    # Score
    scores = forest.score_samples(scaled)

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    verdicts = []
    n_suspicious = 0
    n_malicious = 0

    for ip, score in zip(ips, scores):
        # Classify
        if score > SCORE_MALICIOUS:
            verdict = 'malicious'
            n_malicious += 1
        elif score > SCORE_SUSPICIOUS:
            verdict = 'suspicious'
            n_suspicious += 1
        else:
            verdict = 'benign'

        action = determine_action(ip, verdict)

        verdicts.append({
            'timestamp': now,
            'ip': ip,
            'anomaly_score': score,
            'model_scores': [score],  # Single model for now
            'verdict': verdict,
            'action': action,
        })

        # Auto-block on escalation
        if action == 'block':
            write_block_request(ip, 'ml_anomaly_escalation')
            send_discord_alert(ip, score, verdict, action)
        elif action == 'throttle':
            send_discord_alert(ip, score, verdict, action)

    # Write verdicts
    written = write_verdicts(verdicts)

    if n_suspicious > 0 or n_malicious > 0:
        logger.info(f"Scored {len(ips)} IPs: "
                     f"{n_malicious} malicious, {n_suspicious} suspicious, "
                     f"{len(ips) - n_malicious - n_suspicious} benign")
    else:
        logger.debug(f"Scored {len(ips)} IPs: all benign")

    return written


def main():
    logger.info("HYDRA Anomaly Detector starting...")
    logger.info(f"ClickHouse: {CH_HOST}:{CH_PORT}/{CH_DB}")
    logger.info(f"Detection interval: {DETECT_INTERVAL}s")
    logger.info(f"Thresholds: suspicious={SCORE_SUSPICIOUS}, malicious={SCORE_MALICIOUS}")

    if not CH_PASSWORD:
        logger.error("CLICKHOUSE_PASSWORD not set")
        sys.exit(1)

    # Try to load existing model
    forest, scaler, meta = load_model()

    if forest is None:
        logger.info(f"No trained model found. Collecting baseline ({BASELINE_HOURS}h)...")
        logger.info("Will attempt training once enough data accumulates.")

    last_train_time = time.time()
    retrain_interval = RETRAIN_HOURS * 3600

    while running:
        try:
            # Check if we need to train/retrain
            if forest is None:
                # Try initial training
                forest, scaler = train_model(BASELINE_HOURS)
                if forest:
                    last_train_time = time.time()
                    logger.info("Initial model training complete — entering detection mode")

            elif time.time() - last_train_time > retrain_interval:
                # Periodic retrain — always update timestamp to avoid retry spam
                logger.info("Scheduled retrain...")
                new_forest, new_scaler = train_model(RETRAIN_HOURS)
                last_train_time = time.time()
                if new_forest:
                    forest = new_forest
                    scaler = new_scaler
                    logger.info("Retrain complete")
                else:
                    logger.warning("Retrain failed — keeping existing model, "
                                   "will retry in %dh", RETRAIN_HOURS)

            # Run detection if model is available
            if forest and scaler:
                detect_cycle(forest, scaler)

        except Exception as e:
            logger.error(f"Detection cycle failed: {e}")

        # Wait for next cycle
        for _ in range(DETECT_INTERVAL):
            if not running:
                break
            time.sleep(1)

    logger.info("Anomaly Detector shutting down")


if __name__ == '__main__':
    main()
