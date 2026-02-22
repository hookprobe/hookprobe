#!/usr/bin/env python3
"""
HookProbe SENTINEL Engine
============================

Stage 3: Bayesian ensemble engine combining statistical baselines, CVE-enriched
threat context, per-IP behavioral memory, and operator feedback into calibrated
P(true_positive | evidence) probabilities.

Evidence sources:
  - baseline_profiler.py: Per-IP Z-scores, diurnal anomaly, profile deviation
  - cve_enricher.py: CVE relevance per (port, intent_class)
  - rdap_cache: IP type (datacenter/VPN/Tor/ISP/CDN), weighted score
  - hydra_events: Raw event statistics per window
  - hydra_verdicts: Historical verdict ratios, operator feedback

Scoring:
  sentinel_score = w_bayes * P_bayes(TP|E) + w_profile * profile_score + w_cve * cve_score
  Output calibrated via isotonic regression on operator feedback.

Output:
  - ClickHouse: sentinel_evidence table
  - In-memory score cache for anomaly_detector.py integration

Usage:
    python3 sentinel_engine.py
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
from urllib.parse import urlencode

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SENTINEL] %(levelname)s: %(message)s'
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

# Scoring interval (seconds) — floor at 10s to prevent tight loops
SCORING_INTERVAL = max(int(os.environ.get('SENTINEL_INTERVAL', '300')), 10)

# Minimum operator decisions to train the model
MIN_TRAINING_DECISIONS = int(os.environ.get('SENTINEL_MIN_TRAINING', '10'))

# Feature toggle for gradual rollout
SENTINEL_ENABLED = os.environ.get('SENTINEL_ENABLED', 'true').lower() == 'true'

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
    """Execute a ClickHouse INSERT with auth in headers, body for VALUES data."""
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
# RDAP TYPE SCORING
# ============================================================================

# RDAP types and their base threat multipliers
# Datacenter/VPN/Tor IPs are more likely to be threats than residential ISPs
RDAP_TYPE_SCORES: Dict[str, float] = {
    'tor_exit': 0.85,
    'vpn': 0.70,
    'proxy': 0.70,
    'hosting': 0.65,
    'datacenter': 0.60,
    'cloud': 0.55,
    'education': 0.20,
    'government': 0.15,
    'isp': 0.25,
    'business': 0.30,
    'cdn': 0.10,
    'unknown': 0.40,
}


def rdap_type_score(rdap_type: str) -> float:
    """Convert RDAP type to a threat prior (0-1)."""
    return RDAP_TYPE_SCORES.get(rdap_type.lower(), 0.40)


# ============================================================================
# GAUSSIAN NAIVE BAYES (Pure Python)
# ============================================================================

class GaussianFeature:
    """
    Per-feature Gaussian distribution tracker for a single class.

    Uses Welford's algorithm for numerically stable online updates.
    """

    __slots__ = ('count', 'mean', 'm2')

    def __init__(self, count: int = 0, mean: float = 0.0, m2: float = 0.0):
        self.count = count
        self.mean = mean
        self.m2 = m2

    def update(self, x: float) -> None:
        """Add a new sample."""
        if not math.isfinite(x):
            return
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        """Population variance with minimum floor to prevent division by zero."""
        if self.count < 2:
            return 1.0  # Uninformed prior
        return max(self.m2 / self.count, 1e-8)

    def log_likelihood(self, x: float) -> float:
        """Log probability density of x under this Gaussian."""
        if not math.isfinite(x):
            return -10.0  # Penalty for invalid input
        var = self.variance
        # log N(x | mu, sigma^2) = -0.5 * [log(2*pi*var) + (x-mu)^2/var]
        return -0.5 * (math.log(2 * math.pi * var) + (x - self.mean) ** 2 / var)

    def to_dict(self) -> dict:
        return {'count': self.count, 'mean': self.mean, 'm2': self.m2}

    @classmethod
    def from_dict(cls, d: dict) -> 'GaussianFeature':
        return cls(
            count=int(d.get('count', 0)),
            mean=float(d.get('mean', 0.0)),
            m2=float(d.get('m2', 0.0)),
        )


class GaussianNaiveBayes:
    """
    Gaussian Naive Bayes classifier for binary classification (TP vs FP).

    Assumes feature independence (naive) with per-feature Gaussian distributions.
    Tracks separate distributions for positive (TP) and negative (FP) classes.
    """

    def __init__(self, n_features: int):
        self.n_features = n_features
        self.pos_features: List[GaussianFeature] = [
            GaussianFeature() for _ in range(n_features)
        ]
        self.neg_features: List[GaussianFeature] = [
            GaussianFeature() for _ in range(n_features)
        ]
        self.pos_count = 0
        self.neg_count = 0

    @property
    def total_samples(self) -> int:
        return self.pos_count + self.neg_count

    def update(self, features: List[float], is_positive: bool) -> None:
        """Update model with a labeled sample."""
        if len(features) != self.n_features:
            return

        if is_positive:
            self.pos_count += 1
            for i, x in enumerate(features):
                self.pos_features[i].update(x)
        else:
            self.neg_count += 1
            for i, x in enumerate(features):
                self.neg_features[i].update(x)

    def predict_log_odds(self, features: List[float]) -> float:
        """
        Compute log-odds ratio: log(P(TP|evidence) / P(FP|evidence)).

        Positive = more likely TP, negative = more likely FP.
        """
        if len(features) != self.n_features:
            return 0.0
        if self.pos_count < 2 or self.neg_count < 2:
            return 0.0  # Uninformed

        # Log prior
        log_prior_ratio = math.log(max(self.pos_count, 1) / max(self.neg_count, 1))

        # Sum of per-feature log-likelihood ratios
        log_likelihood_ratio = 0.0
        for i in range(self.n_features):
            ll_pos = self.pos_features[i].log_likelihood(features[i])
            ll_neg = self.neg_features[i].log_likelihood(features[i])
            log_likelihood_ratio += ll_pos - ll_neg

        return log_prior_ratio + log_likelihood_ratio

    def predict_proba(self, features: List[float]) -> float:
        """
        Compute P(TP | evidence) using Bayes' rule.

        Returns probability in [0, 1]. Uses log-sum-exp for numerical stability.
        """
        log_odds = self.predict_log_odds(features)

        # Clamp to prevent overflow
        log_odds = max(-20.0, min(20.0, log_odds))

        # Sigmoid: P = 1 / (1 + exp(-log_odds))
        return 1.0 / (1.0 + math.exp(-log_odds))

    def to_dict(self) -> dict:
        return {
            'n_features': self.n_features,
            'pos_count': self.pos_count,
            'neg_count': self.neg_count,
            'pos_features': [f.to_dict() for f in self.pos_features],
            'neg_features': [f.to_dict() for f in self.neg_features],
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'GaussianNaiveBayes':
        n = int(d.get('n_features', 0))
        gnb = cls(n)
        gnb.pos_count = int(d.get('pos_count', 0))
        gnb.neg_count = int(d.get('neg_count', 0))
        for i, fd in enumerate(d.get('pos_features', [])):
            if i < n:
                gnb.pos_features[i] = GaussianFeature.from_dict(fd)
        for i, fd in enumerate(d.get('neg_features', [])):
            if i < n:
                gnb.neg_features[i] = GaussianFeature.from_dict(fd)
        return gnb


# ============================================================================
# ISOTONIC CALIBRATION (Pool Adjacent Violators Algorithm)
# ============================================================================

class IsotonicCalibrator:
    """
    Isotonic regression calibrator using Pool Adjacent Violators Algorithm.

    Maps raw model scores to calibrated probabilities using a monotonically
    increasing step function learned from labeled data.
    """

    def __init__(self):
        self.bins: List[Tuple[float, float]] = []  # [(score, calibrated_prob), ...]
        self.n_samples = 0

    def fit(self, scores: List[float], labels: List[int]) -> None:
        """
        Fit calibrator on (raw_score, true_label) pairs.

        labels: 1 = true positive, 0 = false positive
        """
        if len(scores) != len(labels) or len(scores) < 2:
            return

        self.n_samples = len(scores)

        # Sort by score
        pairs = sorted(zip(scores, labels))

        # Pool Adjacent Violators
        blocks: List[List[Tuple[float, int]]] = [[(s, l)] for s, l in pairs]

        i = 0
        while i < len(blocks) - 1:
            # Compute block averages
            avg_current = sum(l for _, l in blocks[i]) / len(blocks[i])
            avg_next = sum(l for _, l in blocks[i + 1]) / len(blocks[i + 1])

            if avg_current > avg_next:
                # Violation: merge blocks
                blocks[i].extend(blocks[i + 1])
                del blocks[i + 1]
                # Step back to check for new violations
                if i > 0:
                    i -= 1
            else:
                i += 1

        # Build calibration map
        self.bins = []
        for block in blocks:
            avg_score = sum(s for s, _ in block) / len(block)
            avg_label = sum(l for _, l in block) / len(block)
            self.bins.append((avg_score, avg_label))

    def calibrate(self, score: float) -> float:
        """Map a raw score to a calibrated probability."""
        if not self.bins:
            return score  # Passthrough if uncalibrated

        # Binary search for the right bin
        if score <= self.bins[0][0]:
            return self.bins[0][1]
        if score >= self.bins[-1][0]:
            return self.bins[-1][1]

        # Linear interpolation between bins
        for i in range(len(self.bins) - 1):
            s0, p0 = self.bins[i]
            s1, p1 = self.bins[i + 1]
            if s0 <= score <= s1:
                if s1 - s0 < 1e-10:
                    return p0
                t = (score - s0) / (s1 - s0)
                return p0 + t * (p1 - p0)

        return self.bins[-1][1]

    def to_dict(self) -> dict:
        return {
            'bins': self.bins,
            'n_samples': self.n_samples,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'IsotonicCalibrator':
        cal = cls()
        cal.bins = [(float(s), float(p)) for s, p in d.get('bins', [])]
        cal.n_samples = int(d.get('n_samples', 0))
        return cal


# ============================================================================
# EVIDENCE COLLECTION
# ============================================================================

# Evidence feature names (20 features as per plan)
EVIDENCE_NAMES = [
    'if_score',           # 0: Isolation Forest score (0 if unavailable)
    'rdap_type_score',    # 1: RDAP type threat prior (0-1)
    'rdap_weighted',      # 2: RDAP weighted score (0-1000 normalized)
    'z_event_count',      # 3: Profile Z-score: event count
    'z_event_rate',       # 4: Profile Z-score: event rate
    'z_unique_ports',     # 5: Profile Z-score: unique destination ports
    'z_syn_ratio',        # 6: Profile Z-score: SYN flag ratio
    'cve_relevance',      # 7: CVE relevance score (0-1)
    'max_cvss',           # 8: Max CVSS score for port (0-10 normalized)
    'diurnal_anomaly',    # 9: Time-of-day anomaly factor (0-1)
    'event_count_norm',   # 10: Raw event count (log-normalized)
    'unique_ports_norm',  # 11: Unique dest ports (log-normalized)
    'blocklist_ratio',    # 12: Fraction of events matching threat feeds
    'syn_flag_ratio',     # 13: SYN flag ratio
    'profile_deviation',  # 14: Mean squared Z-score distance
    'in_threat_feed',     # 15: IP found in threat feed (0/1)
    'historical_verdict', # 16: Historical malicious verdict ratio (0-1)
    'ip_age_days',        # 17: Days since first seen (log-normalized)
    'dst_port_entropy',   # 18: Destination port entropy
    'bytes_ratio',        # 19: Bytes ratio (outbound/total)
]
N_EVIDENCE = len(EVIDENCE_NAMES)


def collect_evidence_batch(window_seconds: int) -> List[dict]:
    """
    Collect evidence vectors for all active IPs in the current window.

    Queries hydra_events for per-IP statistics, then enriches with:
    - Profile Z-scores from sentinel_ip_profiles
    - CVE relevance from sentinel_cve_context
    - RDAP metadata from rdap_cache
    - Historical verdicts from hydra_verdicts
    """
    # Step 1: Per-IP event statistics from hydra_events
    ip_stats_query = f"""
        SELECT
            src_ip AS ip,
            count() AS event_count,
            uniq(dst_port) AS unique_ports,
            uniq(proto) AS unique_protos,
            countIf(feed_source != '') / greatest(count(), 1) AS blocklist_ratio,
            countIf(bitAnd(tcp_flags, 2) > 0) / greatest(count(), 1) AS syn_ratio,
            entropy(dst_port) AS port_entropy,
            sum(1) AS flow_count,
            anyIf(feed_source, feed_source != '') AS feed_src,
            any(dst_port) AS primary_port
        FROM {CH_DB}.hydra_events
        WHERE timestamp >= now() - INTERVAL {window_seconds} SECOND
        GROUP BY src_ip
        HAVING event_count >= 3
    """

    result = ch_query(ip_stats_query)
    if not result:
        return []

    ip_data: Dict[str, dict] = {}
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            ip_data[ip] = {
                'ip': ip,
                'event_count': int(row.get('event_count') or 0),
                'unique_ports': int(row.get('unique_ports') or 0),
                'unique_protos': int(row.get('unique_protos') or 0),
                'blocklist_ratio': float(row.get('blocklist_ratio') or 0),
                'syn_ratio': float(row.get('syn_ratio') or 0),
                'port_entropy': float(row.get('port_entropy') or 0),
                'flow_count': int(row.get('flow_count') or 0),
                'feed_src': str(row.get('feed_src') or ''),
                'primary_port': int(row.get('primary_port') or 0),
            }
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue

    if not ip_data:
        return []

    # Step 2: Load RDAP data for these IPs
    rdap_data = _load_rdap_batch(list(ip_data.keys()))

    # Step 3: Load profile data for these IPs
    profile_data = _load_profile_batch(list(ip_data.keys()))

    # Step 4: Load CVE context for active ports
    active_ports = set()
    for d in ip_data.values():
        if d['primary_port'] > 0:
            active_ports.add(d['primary_port'])
    cve_data = _load_cve_batch(active_ports)

    # Step 5: Load historical verdict ratios
    verdict_data = _load_verdict_history(list(ip_data.keys()))

    # Step 6: Build evidence vectors
    now_hour = datetime.now(timezone.utc).hour
    results = []

    for ip, stats in ip_data.items():
        evidence = [0.0] * N_EVIDENCE

        # Feature 0: IF score (not available standalone — set to 0)
        evidence[0] = 0.0

        # Features 1-2: RDAP
        rdap = rdap_data.get(ip, {})
        evidence[1] = rdap_type_score(rdap.get('rdap_type', 'unknown'))
        evidence[2] = min(float(rdap.get('weighted_score') or 0) / 1000.0, 1.0)

        # Features 3-6: Profile Z-scores
        profile = profile_data.get(ip)
        if profile:
            # Build a mini feature vector matching baseline_profiler's format
            event_rate = stats['event_count'] / max(window_seconds, 1)
            feature_vec = [
                float(stats['event_count']),
                event_rate,
                float(stats['unique_ports']),
                float(stats['unique_protos']),
                stats['blocklist_ratio'],
                stats['syn_ratio'],
                stats['port_entropy'],
                float(stats['flow_count']),
                0.0,  # total_bytes (not in hydra_events)
                0.0,  # avg_flow_duration
                math.sin(2 * math.pi * now_hour / 24.0),
                math.cos(2 * math.pi * now_hour / 24.0),
            ]

            z_scores = _compute_z_scores_from_profile(profile, feature_vec)
            evidence[3] = _clamp_z(z_scores[0])  # event_count Z
            evidence[4] = _clamp_z(z_scores[1])  # event_rate Z
            evidence[5] = _clamp_z(z_scores[2])  # unique_ports Z
            evidence[6] = _clamp_z(z_scores[5])  # syn_ratio Z

            # Feature 9: Diurnal anomaly
            evidence[9] = _diurnal_anomaly_from_profile(profile, now_hour)

            # Feature 14: Profile deviation (RMS of Z-scores)
            # Exclude indices 7-9 (flow_count, total_bytes, avg_flow_duration)
            # which come from napse_flows — sentinel builds feature_vec from
            # hydra_events so those z_scores would be wildly incorrect.
            EXCLUDE_Z = {7, 8, 9}
            valid_z = [z for i, z in enumerate(z_scores)
                        if i not in EXCLUDE_Z and math.isfinite(z)]
            if valid_z:
                evidence[14] = math.sqrt(sum(z * z for z in valid_z) / len(valid_z))

            # Feature 17: IP age
            first_seen = profile.get('first_seen', '')
            if first_seen:
                try:
                    fs_dt = datetime.fromisoformat(
                        first_seen.replace(' ', 'T')).replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - fs_dt).total_seconds() / 86400
                    evidence[17] = math.log1p(max(age_days, 0))
                except (ValueError, TypeError):
                    pass

        # Features 7-8: CVE relevance
        port = stats['primary_port']
        cve = cve_data.get(port, {})
        evidence[7] = float(cve.get('cve_relevance_score') or 0)
        evidence[8] = float(cve.get('max_cvss_score') or 0) / 10.0

        # Feature 10-11: Normalized event/port counts
        evidence[10] = math.log1p(stats['event_count'])
        evidence[11] = math.log1p(stats['unique_ports'])

        # Features 12-13: Raw ratios
        evidence[12] = stats['blocklist_ratio']
        evidence[13] = stats['syn_ratio']

        # Feature 15: In threat feed
        evidence[15] = 1.0 if stats['feed_src'] else 0.0

        # Feature 16: Historical verdict ratio
        evidence[16] = verdict_data.get(ip, 0.0)

        # Feature 18: Port entropy
        evidence[18] = stats['port_entropy']

        # Feature 19: Bytes ratio (not available from hydra_events, use 0)
        evidence[19] = 0.0

        # Sanitize: replace NaN/Inf with 0
        for i in range(N_EVIDENCE):
            if not math.isfinite(evidence[i]):
                evidence[i] = 0.0

        results.append({
            'ip': ip,
            'evidence': evidence,
            'event_count': stats['event_count'],
            'primary_port': port,
            'rdap_type': rdap.get('rdap_type', 'unknown'),
            'cve_relevance': evidence[7],
            'profile_deviation': evidence[14],
        })

    # Enrich with temporal signals (drift, campaigns, intents)
    temporal_data = _load_temporal_batch(list(ip_data.keys()))
    for item in results:
        ip = item['ip']
        temporal = temporal_data.get(ip, {})
        item['temporal'] = {
            'drift_score': float(temporal.get('drift_score') or 0),
            'campaign_reputation': float(temporal.get('campaign_reputation') or 0),
            'campaign_id': str(temporal.get('campaign_id') or ''),
            'intent_entropy': float(temporal.get('intent_entropy') or 0),
            'diurnal_anomaly': float(temporal.get('diurnal_anomaly') or 0),
        }

    return results


def _clamp_z(z: float, limit: float = 5.0) -> float:
    """Clamp Z-score to [-limit, limit] and replace non-finite with 0."""
    if not math.isfinite(z):
        return 0.0
    return max(-limit, min(limit, z))


def _load_rdap_batch(ips: List[str]) -> Dict[str, dict]:
    """Load RDAP data for a batch of IPs."""
    if not ips:
        return {}

    # Build IN clause with IP strings
    ip_list = ','.join(f"toIPv4('{ip}')" for ip in ips[:500])
    query = f"""
        SELECT
            ip,
            rdap_type, weighted_score, asn, country
        FROM {CH_DB}.rdap_cache FINAL
        WHERE ip IN ({ip_list})
    """
    result = ch_query(query)
    if not result:
        return {}

    rdap = {}
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            rdap[row['ip']] = row
        except (json.JSONDecodeError, KeyError):
            continue
    return rdap


def _load_profile_batch(ips: List[str]) -> Dict[str, dict]:
    """Load profile data for a batch of IPs from sentinel_ip_profiles."""
    if not ips:
        return {}

    ip_list = ','.join(f"toIPv4('{ip}')" for ip in ips[:500])
    query = f"""
        SELECT
            ip,
            window_count, feature_means, feature_m2s, feature_counts,
            diurnal_counts, first_seen, last_seen, rdap_type
        FROM {CH_DB}.sentinel_ip_profiles FINAL
        WHERE ip IN ({ip_list})
          AND window_count >= 3
    """
    result = ch_query(query)
    if not result:
        return {}

    profiles = {}
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            profiles[row['ip']] = row
        except (json.JSONDecodeError, KeyError):
            continue
    return profiles


def _compute_z_scores_from_profile(profile: dict, feature_vec: List[float]) -> List[float]:
    """Compute Z-scores using profile's Welford statistics."""
    means = profile.get('feature_means', [])
    m2s = profile.get('feature_m2s', [])
    counts = profile.get('feature_counts', [])

    n = min(len(feature_vec), len(means), len(m2s), len(counts))
    z_scores = []

    for i in range(n):
        count = int(counts[i]) if i < len(counts) else 0
        if count < 3:
            z_scores.append(0.0)
            continue

        mean = float(means[i])
        m2 = float(m2s[i])
        variance = m2 / count if count > 1 else 0.0
        stddev = math.sqrt(variance) if variance > 0 else 0.0

        if stddev < 1e-10:
            z_scores.append(0.0)
        else:
            z = (feature_vec[i] - mean) / stddev
            z_scores.append(z if math.isfinite(z) else 0.0)

    # Pad to full length
    while len(z_scores) < len(feature_vec):
        z_scores.append(0.0)

    return z_scores


def _diurnal_anomaly_from_profile(profile: dict, hour: int) -> float:
    """Compute diurnal anomaly factor from profile's hourly histogram."""
    diurnal = profile.get('diurnal_counts', [])
    if len(diurnal) != 24:
        return 0.0

    total = sum(diurnal)
    if total < 10 or hour < 0 or hour >= 24:
        return 0.0

    # Laplace-smoothed frequency
    smoothed = (diurnal[hour] + 1) / (total + 24)
    return max(0.0, 1.0 - smoothed * 24)


def _load_cve_batch(ports: set) -> Dict[int, dict]:
    """Load latest CVE context for active ports."""
    if not ports:
        return {}

    port_list = ','.join(str(int(p)) for p in ports if 0 < p < 65536)
    if not port_list:
        return {}

    query = f"""
        SELECT
            dst_port,
            argMax(cve_relevance_score, timestamp) AS cve_relevance_score,
            argMax(max_cvss_score, timestamp) AS max_cvss_score,
            argMax(matched_cve_count, timestamp) AS matched_cve_count,
            argMax(has_kev, timestamp) AS has_kev
        FROM {CH_DB}.sentinel_cve_context
        WHERE dst_port IN ({port_list})
          AND timestamp >= now() - INTERVAL 1 DAY
        GROUP BY dst_port
    """
    result = ch_query(query)
    if not result:
        return {}

    cve_map = {}
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            port = int(row['dst_port'])
            cve_map[port] = row
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue
    return cve_map


def _load_verdict_history(ips: List[str]) -> Dict[str, float]:
    """Load historical malicious verdict ratios per IP."""
    if not ips:
        return {}

    ip_list = ','.join(f"toIPv4('{ip}')" for ip in ips[:500])
    query = f"""
        SELECT
            src_ip AS ip,
            countIf(verdict = 'malicious') / greatest(count(), 1) AS mal_ratio
        FROM {CH_DB}.hydra_verdicts
        WHERE src_ip IN ({ip_list})
          AND timestamp >= now() - INTERVAL 30 DAY
        GROUP BY src_ip
        HAVING count() >= 2
    """
    result = ch_query(query)
    if not result:
        return {}

    ratios = {}
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ratios[row['ip']] = float(row.get('mal_ratio') or 0)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue
    return ratios


def _load_temporal_batch(ips: List[str]) -> Dict[str, dict]:
    """Load latest temporal signals (drift, campaigns, intents) per IP."""
    if not ips:
        return {}

    ip_list = ','.join(f"toIPv4('{ip}')" for ip in ips[:500])
    query = f"""
        SELECT
            ip,
            argMax(drift_score, timestamp) AS drift_score,
            argMax(diurnal_anomaly, timestamp) AS diurnal_anomaly,
            argMax(intent_entropy, timestamp) AS intent_entropy,
            argMax(campaign_id, timestamp) AS campaign_id,
            argMax(campaign_reputation, timestamp) AS campaign_reputation
        FROM {CH_DB}.sentinel_temporal
        WHERE ip IN ({ip_list})
          AND timestamp >= now() - INTERVAL 1 HOUR
        GROUP BY ip
    """
    result = ch_query(query)
    if not result:
        return {}

    temporal = {}
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            temporal[row['ip']] = row
        except (json.JSONDecodeError, KeyError):
            continue
    return temporal


# ============================================================================
# SENTINEL ENGINE
# ============================================================================

class SentinelEngine:
    """
    Core SENTINEL engine combining multiple evidence sources into
    calibrated P(true_positive | evidence) probabilities.

    Ensemble formula:
      sentinel_score = w_bayes * bayes_score + w_heuristic * heuristic_score

    Where:
      - bayes_score: P(TP|evidence) from Gaussian Naive Bayes
      - heuristic_score: weighted combination of strongest individual signals
    """

    def __init__(self):
        self.gnb = GaussianNaiveBayes(N_EVIDENCE)
        self.calibrator = IsotonicCalibrator()
        self.version = 0
        self.last_trained = ''

        # Ensemble weights (defaults, updated by training)
        self.w_bayes = 0.5
        self.w_heuristic = 0.5

        # Heuristic sub-weights for individual signals
        self.hw_profile = 0.25   # Profile deviation
        self.hw_cve = 0.20      # CVE relevance
        self.hw_rdap = 0.15     # RDAP type score
        self.hw_feed = 0.20     # Threat feed match
        self.hw_behavior = 0.20 # Behavioral signals (Z-scores, entropy)

    def predict(self, evidence: List[float],
                temporal: Optional[dict] = None) -> dict:
        """
        Score an evidence vector with optional temporal enrichment.

        Args:
            evidence: 20-feature evidence vector
            temporal: Optional dict with drift_score, campaign_reputation,
                     intent_entropy, diurnal_anomaly from temporal_memory

        Returns dict with sentinel_score, bayes_score, heuristic_score,
        verdict, and confidence.
        """
        # Bayes score (learned from operator feedback)
        if self.gnb.total_samples >= MIN_TRAINING_DECISIONS:
            raw_bayes = self.gnb.predict_proba(evidence)
            bayes_score = self.calibrator.calibrate(raw_bayes) \
                if self.calibrator.bins else raw_bayes
        else:
            bayes_score = 0.5  # Uninformed prior

        # Heuristic score (rule-based, always available)
        heuristic_score = self._heuristic_score(evidence, temporal)

        # Ensemble
        if self.gnb.total_samples >= MIN_TRAINING_DECISIONS:
            sentinel_score = (self.w_bayes * bayes_score +
                              self.w_heuristic * heuristic_score)
        else:
            # Before training: rely entirely on heuristics
            sentinel_score = heuristic_score

        # Clamp
        sentinel_score = max(0.0, min(1.0, sentinel_score))

        # Verdict
        if sentinel_score >= 0.7:
            verdict = 'malicious'
        elif sentinel_score >= 0.4:
            verdict = 'suspicious'
        else:
            verdict = 'benign'

        # Confidence: how far from the decision boundary
        if verdict == 'malicious':
            confidence = min(1.0, (sentinel_score - 0.7) / 0.3 * 0.5 + 0.5)
        elif verdict == 'suspicious':
            confidence = 0.3 + (sentinel_score - 0.4) / 0.3 * 0.2
        else:
            confidence = min(1.0, (0.4 - sentinel_score) / 0.4 * 0.5 + 0.5)

        return {
            'sentinel_score': round(sentinel_score, 6),
            'bayes_score': round(bayes_score, 6),
            'heuristic_score': round(heuristic_score, 6),
            'verdict': verdict,
            'confidence': round(confidence, 4),
        }

    def _heuristic_score(self, evidence: List[float],
                         temporal: Optional[dict] = None) -> float:
        """
        Compute heuristic threat score from evidence + temporal signals.

        Uses weighted combination of strongest signals. Always available
        even without trained Bayes model.

        Temporal signals (from temporal_memory.py):
          - drift_score: KL divergence from historical baseline (0-10)
          - campaign_reputation: propagated from confirmed malicious (0-1)
          - intent_entropy: diversity of attack intents (0-1)
          - diurnal_anomaly: activity at unusual hour (0-1)
        """
        # Profile deviation score (feature 14): higher = more anomalous
        profile_dev = evidence[14] if len(evidence) > 14 else 0.0
        profile_score = min(1.0, profile_dev / 3.0)  # Z > 3 = max threat

        # CVE relevance (feature 7)
        cve_score = evidence[7] if len(evidence) > 7 else 0.0

        # RDAP type threat prior (feature 1)
        rdap_score = evidence[1] if len(evidence) > 1 else 0.4

        # Threat feed match (feature 15)
        feed_score = evidence[15] if len(evidence) > 15 else 0.0

        # Behavioral signals
        z_event = abs(evidence[3]) if len(evidence) > 3 else 0.0
        z_ports = abs(evidence[5]) if len(evidence) > 5 else 0.0
        z_syn = abs(evidence[6]) if len(evidence) > 6 else 0.0
        blocklist = evidence[12] if len(evidence) > 12 else 0.0
        syn_ratio = evidence[13] if len(evidence) > 13 else 0.0

        # Behavioral composite: max Z-score normalized + raw suspicious ratios
        max_z = max(z_event, z_ports, z_syn)
        behavior_score = min(1.0, max_z / 3.0) * 0.4 + blocklist * 0.3 + syn_ratio * 0.3

        # Base heuristic (5 components, weights sum to 1.0)
        base_heuristic = (
            self.hw_profile * profile_score +
            self.hw_cve * cve_score +
            self.hw_rdap * rdap_score +
            self.hw_feed * feed_score +
            self.hw_behavior * behavior_score
        )

        # Temporal overlay (additive boost, capped)
        temporal_boost = 0.0
        if temporal:
            # Drift: behavioral shift from historical baseline
            # High KL divergence = recently changed behavior = more suspicious
            drift = float(temporal.get('drift_score') or 0)
            temporal_boost += min(0.15, drift / 5.0 * 0.15)

            # Campaign reputation: propagated from confirmed malicious peers
            # Direct evidence of coordinated attack
            camp_rep = float(temporal.get('campaign_reputation') or 0)
            temporal_boost += camp_rep * 0.20

            # Diurnal anomaly: activity at unusual hour for this IP
            diurnal = float(temporal.get('diurnal_anomaly') or 0)
            temporal_boost += diurnal * 0.05

            # Intent entropy: diverse attack patterns = automated scanner
            intent_ent = float(temporal.get('intent_entropy') or 0)
            temporal_boost += intent_ent * 0.05

        # Combined score: base + temporal boost, capped at 1.0
        heuristic = base_heuristic + temporal_boost

        return max(0.0, min(1.0, heuristic))

    def train_from_verdicts(self) -> dict:
        """
        Train the Bayes model from operator-labeled verdicts.

        Returns training statistics.
        """
        # Load operator decisions
        query = f"""
            SELECT
                src_ip AS ip,
                anomaly_score,
                verdict,
                operator_decision,
                timestamp
            FROM {CH_DB}.hydra_verdicts
            WHERE operator_decision IN ('confirm', 'false_positive')
              AND timestamp >= now() - INTERVAL 90 DAY
            ORDER BY timestamp
        """
        result = ch_query(query)
        if not result:
            return {'status': 'no_data', 'samples': 0}

        # Parse decisions: keep most recent decision + its timestamp per IP
        labeled_ips: Dict[str, Tuple[bool, str]] = {}  # ip -> (is_tp, timestamp)
        for line in result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                ip = row['ip']
                decision = row['operator_decision']
                ts = str(row.get('timestamp', ''))
                labeled_ips[ip] = (decision == 'confirm', ts)
            except (json.JSONDecodeError, KeyError):
                continue

        if len(labeled_ips) < MIN_TRAINING_DECISIONS:
            return {
                'status': 'insufficient_data',
                'samples': len(labeled_ips),
                'required': MIN_TRAINING_DECISIONS,
            }

        # Collect evidence for labeled IPs using events around verdict time
        scores_for_cal = []
        labels_for_cal = []

        gnb = GaussianNaiveBayes(N_EVIDENCE)

        for ip, (is_tp, verdict_ts) in labeled_ips.items():
            evidence = _collect_historical_evidence(ip, verdict_ts)
            if evidence is None:
                continue

            gnb.update(evidence, is_tp)
            raw_score = gnb.predict_proba(evidence) if gnb.total_samples >= 4 else 0.5
            scores_for_cal.append(raw_score)
            labels_for_cal.append(1 if is_tp else 0)

        if gnb.total_samples < MIN_TRAINING_DECISIONS:
            return {
                'status': 'insufficient_evidence',
                'samples': gnb.total_samples,
            }

        # Calibrate
        calibrator = IsotonicCalibrator()
        if len(scores_for_cal) >= 5:
            calibrator.fit(scores_for_cal, labels_for_cal)

        # Update engine
        self.gnb = gnb
        self.calibrator = calibrator
        self.version += 1
        self.last_trained = datetime.now(timezone.utc).isoformat()

        # Compute training metrics
        tp = sum(1 for l in labels_for_cal if l == 1)
        fp = sum(1 for l in labels_for_cal if l == 0)

        stats = {
            'status': 'trained',
            'version': self.version,
            'samples': gnb.total_samples,
            'true_positives': tp,
            'false_positives': fp,
            'n_features': N_EVIDENCE,
        }

        # Persist model state to ClickHouse
        self._persist_model_state(stats)

        logger.info(f"SENTINEL model trained: v{self.version}, "
                     f"{gnb.total_samples} samples ({tp} TP, {fp} FP)")

        return stats

    def _persist_model_state(self, stats: dict) -> None:
        """Save model state to sentinel_model_state table."""
        model_json = json.dumps(self.to_dict())
        safe_json = ch_escape(model_json)

        importance = json.dumps({
            name: {
                'pos_mean': self.gnb.pos_features[i].mean,
                'neg_mean': self.gnb.neg_features[i].mean,
                'discriminative_power': abs(
                    self.gnb.pos_features[i].mean - self.gnb.neg_features[i].mean
                ) / max(
                    math.sqrt(self.gnb.pos_features[i].variance +
                              self.gnb.neg_features[i].variance),
                    1e-6
                )
            }
            for i, name in enumerate(EVIDENCE_NAMES)
            if self.gnb.pos_features[i].count > 0
        })
        safe_importance = ch_escape(importance)

        query = (
            f"INSERT INTO {CH_DB}.sentinel_model_state "
            "(model_name, version, training_samples, model_params, "
            "precision, recall, f1_score, false_positive_rate, feature_importance)"
        )
        data = (
            f"('sentinel_gnb', {self.version}, {stats.get('samples', 0)}, "
            f"'{safe_json}', 0, 0, 0, 0, '{safe_importance}')"
        )
        ch_insert(query, data)

    def to_dict(self) -> dict:
        return {
            'version': self.version,
            'last_trained': self.last_trained,
            'gnb': self.gnb.to_dict(),
            'calibrator': self.calibrator.to_dict(),
            'w_bayes': self.w_bayes,
            'w_heuristic': self.w_heuristic,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'SentinelEngine':
        engine = cls()
        engine.version = int(d.get('version', 0))
        engine.last_trained = str(d.get('last_trained', ''))
        if 'gnb' in d:
            engine.gnb = GaussianNaiveBayes.from_dict(d['gnb'])
        if 'calibrator' in d:
            engine.calibrator = IsotonicCalibrator.from_dict(d['calibrator'])
        engine.w_bayes = float(d.get('w_bayes', 0.5))
        engine.w_heuristic = float(d.get('w_heuristic', 0.5))
        return engine

    def load_from_ch(self) -> bool:
        """Load latest model state from ClickHouse."""
        query = f"""
            SELECT model_params
            FROM {CH_DB}.sentinel_model_state FINAL
            WHERE model_name = 'sentinel_gnb'
            ORDER BY version DESC
            LIMIT 1
        """
        result = ch_query(query)
        if not result:
            return False

        for line in result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                params = json.loads(row.get('model_params', '{}'))
                if params:
                    loaded = SentinelEngine.from_dict(params)
                    self.gnb = loaded.gnb
                    self.calibrator = loaded.calibrator
                    self.version = loaded.version
                    self.last_trained = loaded.last_trained
                    self.w_bayes = loaded.w_bayes
                    self.w_heuristic = loaded.w_heuristic
                    logger.info(f"Loaded SENTINEL model v{self.version} "
                                 f"({self.gnb.total_samples} samples)")
                    return True
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                continue
        return False


def _collect_historical_evidence(ip: str, verdict_ts: str = '') -> Optional[List[float]]:
    """Collect evidence for a single IP from events around its verdict timestamp."""
    # Use events in a 2-hour window centered on the verdict timestamp
    # (1 hour before to 1 hour after the operator decision)
    if verdict_ts:
        safe_ts = ch_escape(verdict_ts[:23])  # Truncate to DateTime64(3) format
        time_filter = (
            f"AND timestamp >= parseDateTimeBestEffort('{safe_ts}') - INTERVAL 1 HOUR "
            f"AND timestamp <= parseDateTimeBestEffort('{safe_ts}') + INTERVAL 1 HOUR"
        )
    else:
        time_filter = "AND timestamp >= now() - INTERVAL 1 DAY"

    query = f"""
        SELECT
            count() AS event_count,
            uniq(dst_port) AS unique_ports,
            uniq(proto) AS unique_protos,
            countIf(feed_source != '') / greatest(count(), 1) AS blocklist_ratio,
            countIf(bitAnd(tcp_flags, 2) > 0) / greatest(count(), 1) AS syn_ratio,
            entropy(dst_port) AS port_entropy,
            any(feed_source) AS feed_src,
            any(dst_port) AS primary_port
        FROM {CH_DB}.hydra_events
        WHERE src_ip = toIPv4('{ip}')
          {time_filter}
    """
    result = ch_query(query)
    if not result:
        return None

    try:
        row = json.loads(result.strip().split('\n')[0])
        if int(row.get('event_count') or 0) < 1:
            return None

        evidence = [0.0] * N_EVIDENCE

        # Fill what we can from event stats
        evidence[10] = math.log1p(int(row.get('event_count') or 0))
        evidence[11] = math.log1p(int(row.get('unique_ports') or 0))
        evidence[12] = float(row.get('blocklist_ratio') or 0)
        evidence[13] = float(row.get('syn_ratio') or 0)
        evidence[15] = 1.0 if row.get('feed_src') else 0.0
        evidence[18] = float(row.get('port_entropy') or 0)

        # RDAP
        rdap = _load_rdap_batch([ip])
        if ip in rdap:
            evidence[1] = rdap_type_score(rdap[ip].get('rdap_type', 'unknown'))
            evidence[2] = min(float(rdap[ip].get('weighted_score') or 0) / 1000.0, 1.0)

        # CVE
        port = int(row.get('primary_port') or 0)
        if port > 0:
            cve = _load_cve_batch({port})
            if port in cve:
                evidence[7] = float(cve[port].get('cve_relevance_score') or 0)
                evidence[8] = float(cve[port].get('max_cvss_score') or 0) / 10.0

        # Sanitize
        for i in range(N_EVIDENCE):
            if not math.isfinite(evidence[i]):
                evidence[i] = 0.0

        return evidence

    except (json.JSONDecodeError, IndexError, KeyError, ValueError, TypeError):
        return None


# ============================================================================
# VERDICT DEDUPLICATION
# ============================================================================

# Prevent flooding hydra_verdicts with repeated entries for the same IP.
# An IP gets at most one verdict per dedup window (30 min by default).
_verdict_dedup: Dict[str, float] = {}  # ip -> monotonic time of last write
VERDICT_DEDUP_SECONDS = 1800


def _should_write_verdict(ip: str) -> bool:
    """Return True if this IP hasn't had a verdict written recently."""
    now_mono = time.monotonic()
    if ip in _verdict_dedup and now_mono - _verdict_dedup[ip] < VERDICT_DEDUP_SECONDS:
        return False
    _verdict_dedup[ip] = now_mono
    # Periodic cleanup to bound memory
    if len(_verdict_dedup) > 2000:
        cutoff = now_mono - VERDICT_DEDUP_SECONDS
        for k in list(_verdict_dedup):
            if _verdict_dedup[k] < cutoff:
                del _verdict_dedup[k]
    return True


# ============================================================================
# SCORING CYCLE
# ============================================================================

def scoring_cycle(engine: SentinelEngine) -> dict:
    """
    Run one SENTINEL scoring cycle:
    1. Collect evidence for all active IPs
    2. Score with SENTINEL engine
    3. Write results to sentinel_evidence
    4. Return summary statistics
    """
    evidence_batch = collect_evidence_batch(SCORING_INTERVAL)
    if not evidence_batch:
        return {'scored': 0}

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    rows = []
    verdicts = {'benign': 0, 'suspicious': 0, 'malicious': 0}

    for item in evidence_batch:
        ip = item['ip']
        evidence = item['evidence']
        result = engine.predict(evidence, item.get('temporal'))

        verdicts[result['verdict']] = verdicts.get(result['verdict'], 0) + 1

        # Build evidence array string
        ev_str = '[' + ','.join(f'{v:.6f}' for v in evidence) + ']'

        rows.append(
            f"('{now}', toIPv4('{ip}'), "
            f"0, "  # if_score (not available standalone)
            f"{result['bayes_score']:.6f}, "
            f"{result['sentinel_score']:.6f}, "
            f"{ev_str}, "
            f"'{result['verdict']}', "
            f"{result['confidence']:.4f}, "
            f"{item.get('profile_deviation', 0):.6f}, "
            f"{item.get('cve_relevance', 0):.6f})"
        )

    # Insert in batches
    total = 0
    query = (
        f"INSERT INTO {CH_DB}.sentinel_evidence "
        "(timestamp, src_ip, if_score, bayes_score, sentinel_score, "
        "evidence_vector, verdict, confidence, profile_deviation, cve_relevance)"
    )

    for i in range(0, len(rows), 100):
        batch = rows[i:i + 100]
        if ch_insert(query, ', '.join(batch)):
            total += len(batch)

    # Write verdicts for suspicious/malicious IPs to hydra_verdicts
    # This closes the operator feedback loop: SENTINEL scores → verdicts →
    # operator confirm/FP → model retrains from feedback
    verdict_rows = []
    for item in evidence_batch:
        result = engine.predict(item['evidence'], item.get('temporal'))
        if result['verdict'] in ('suspicious', 'malicious'):
            ip = item['ip']
            if not _should_write_verdict(ip):
                continue
            action = 'escalate' if result['verdict'] == 'malicious' else 'alert'
            ms = ','.join(f"{v:.6f}" for v in [
                0.0, result['bayes_score'], result['sentinel_score']
            ])
            verdict_rows.append(
                f"('{now}', toIPv4('{ip}'), "
                f"{result['sentinel_score']:.6f}, "
                f"[{ms}], "
                f"'{result['verdict']}', "
                f"'{action}')"
            )

    verdict_count = 0
    if verdict_rows:
        vq = (
            f"INSERT INTO {CH_DB}.hydra_verdicts "
            "(timestamp, src_ip, anomaly_score, model_scores, "
            "verdict, action_taken)"
        )
        for i in range(0, len(verdict_rows), 100):
            batch = verdict_rows[i:i + 100]
            if ch_insert(vq, ', '.join(batch)):
                verdict_count += len(batch)

    # Write benign IP cache for inspector fast-path
    _write_benign_cache(evidence_batch, engine)

    return {
        'scored': total,
        'verdicts': verdicts,
        'verdict_count': verdict_count,
        'total_evidence': len(evidence_batch),
    }


BENIGN_CACHE_PATH = '/app/models/sentinel_benign_cache.txt'


def _write_benign_cache(evidence_batch: List[dict], engine: SentinelEngine):
    """Write confirmed-benign IPs to cache file for inspector fast-path."""
    try:
        benign_ips = []
        for item in evidence_batch:
            result = engine.predict(item['evidence'], item.get('temporal'))
            # Only cache IPs with high benign confidence (score < 0.2)
            if result['sentinel_score'] < 0.2 and result['confidence'] > 0.8:
                benign_ips.append(item['ip'])

        if benign_ips:
            with open(BENIGN_CACHE_PATH, 'w') as f:
                f.write(f"# SENTINEL benign cache, updated {datetime.now(timezone.utc).isoformat()}\n")
                for ip in sorted(set(benign_ips)):
                    f.write(f"{ip}\n")
    except Exception as e:
        logger.debug(f"Benign cache write failed (non-critical): {e}")


# ============================================================================
# MAIN LOOP
# ============================================================================

def main():
    logger.info("SENTINEL Engine starting...")
    logger.info(f"ClickHouse: {CH_HOST}:{CH_PORT}/{CH_DB}")
    logger.info(f"Scoring interval: {SCORING_INTERVAL}s")
    logger.info(f"Feature toggle: {'ENABLED' if SENTINEL_ENABLED else 'DISABLED'}")
    logger.info(f"Evidence features: {N_EVIDENCE}")

    if not CH_PASSWORD:
        logger.error("CLICKHOUSE_PASSWORD not set")
        sys.exit(1)

    if not SENTINEL_ENABLED:
        logger.info("SENTINEL is disabled via SENTINEL_ENABLED=false. Sleeping...")
        while running:
            time.sleep(60)
        return

    # Initialize engine
    engine = SentinelEngine()

    # Try to load existing model
    if engine.load_from_ch():
        logger.info(f"Loaded existing model v{engine.version}")
    else:
        logger.info("No existing model found — starting with heuristics only")

    # Try initial training from any existing operator feedback
    train_result = engine.train_from_verdicts()
    logger.info(f"Initial training: {train_result}")

    # Initial scoring cycle
    result = scoring_cycle(engine)
    logger.info(f"Initial scoring: {result}")

    # Main loop
    cycle_count = 0
    last_train = time.monotonic()
    RETRAIN_INTERVAL = 3600  # Retrain hourly if new feedback exists

    while running:
        # Wait for next cycle
        for _ in range(SCORING_INTERVAL):
            if not running:
                break
            time.sleep(1)

        if not running:
            break

        cycle_count += 1

        try:
            # Score
            result = scoring_cycle(engine)
            if result['scored'] > 0:
                v = result.get('verdicts', {})
                vc = result.get('verdict_count', 0)
                vc_str = f", {vc} verdicts" if vc > 0 else ""
                logger.info(
                    f"Cycle {cycle_count}: scored {result['scored']} IPs "
                    f"(B:{v.get('benign', 0)} S:{v.get('suspicious', 0)} "
                    f"M:{v.get('malicious', 0)}{vc_str})"
                )

            # Periodic retrain
            if time.monotonic() - last_train > RETRAIN_INTERVAL:
                train_result = engine.train_from_verdicts()
                last_train = time.monotonic()
                if train_result.get('status') == 'trained':
                    logger.info(f"Retrained: v{engine.version}, "
                                 f"{train_result['samples']} samples")

        except Exception as e:
            logger.error(f"Scoring cycle error: {e}", exc_info=True)

    logger.info("SENTINEL Engine shutting down")


if __name__ == '__main__':
    main()
