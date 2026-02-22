#!/usr/bin/env python3
"""
HookProbe SENTINEL Baseline Profiler
=====================================

Stage 1 of the SENTINEL engine: builds per-IP statistical profiles
from historical ClickHouse data using Welford's online algorithm.

Core capabilities:
  - Per-IP rolling statistics (mean, variance) via Welford's algorithm
  - Diurnal profiles (24-hour event distribution per IP)
  - Z-score computation for anomaly significance
  - RDAP enrichment integration (type, ASN, country from rdap_cache)
  - Logistic meta-regression on operator feedback (when available)
  - Profile persistence to ClickHouse sentinel_ip_profiles

Data sources:
  - hydra_events: XDP block/alert events (primary)
  - napse_flows: Flow summaries with service classification
  - rdap_cache: IP ownership classification
  - hydra_verdicts: Operator feedback for meta-regression

Feature vector (12 features per IP per window):
  0: event_count       - Total events in window
  1: event_rate        - Events per second
  2: unique_dst_ports  - Port diversity
  3: unique_protocols  - Protocol diversity
  4: blocklist_ratio   - Fraction from blocklist (vs score_drop)
  5: syn_flag_ratio    - Fraction with SYN flag set
  6: dst_port_entropy  - Shannon entropy of port distribution
  7: flow_count        - Number of flows (from napse_flows)
  8: total_bytes       - Total bytes transferred
  9: avg_flow_duration - Average flow duration
  10: hour_sin         - sin(2*pi*hour/24) for cyclical encoding
  11: hour_cos         - cos(2*pi*hour/24) for cyclical encoding

Usage:
    python3 baseline_profiler.py [--mode profile|backfill] [--interval 300]
"""

import os
import sys
import time
import json
import math
import signal
import hashlib
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

# Profiling interval (seconds) — how often to profile new windows
PROFILE_INTERVAL = int(os.environ.get('PROFILE_INTERVAL', '300'))  # 5 minutes

# Window size for feature extraction (seconds)
WINDOW_SIZE = int(os.environ.get('WINDOW_SIZE', '300'))  # 5 minutes

# Minimum events per IP per window to include in profiling
MIN_EVENTS = int(os.environ.get('MIN_EVENTS', '3'))

# Maximum IPs to track in memory (evict least-recently-seen)
MAX_TRACKED_IPS = int(os.environ.get('MAX_TRACKED_IPS', '5000'))

# How often to persist profiles to ClickHouse (every N cycles)
PERSIST_EVERY = int(os.environ.get('PERSIST_EVERY', '6'))  # every 30 min at 5-min intervals

# Feature names (must match feature vector indices)
FEATURE_NAMES = [
    'event_count', 'event_rate', 'unique_dst_ports', 'unique_protocols',
    'blocklist_ratio', 'syn_flag_ratio', 'dst_port_entropy',
    'flow_count', 'total_bytes', 'avg_flow_duration',
    'hour_sin', 'hour_cos',
]
N_FEATURES = len(FEATURE_NAMES)

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
        params = urlencode({
            'query': query + (f" FORMAT {fmt}" if fmt else ""),
        })
        full_url = f"{url}?{params}"

        req = Request(full_url)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        with urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8')

    except HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')[:500]
        logger.error(f"ClickHouse query error: {e} - {body}")
        return None
    except Exception as e:
        logger.error(f"ClickHouse query error: {e}")
        return None


def ch_insert(query: str, data: str = '') -> bool:
    """Execute a ClickHouse INSERT with auth in headers."""
    if not CH_PASSWORD:
        return False

    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        params = urlencode({'query': query})
        full_url = f"{url}?{params}"

        req = Request(full_url)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        if data:
            req.data = data.encode('utf-8')
            req.add_header('Content-Type', 'text/plain')

        with urlopen(req, timeout=30) as resp:
            resp.read()
        return True

    except HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')[:500]
        logger.error(f"ClickHouse insert error: {e} - {body}")
        return False
    except Exception as e:
        logger.error(f"ClickHouse insert error: {e}")
        return False


# ============================================================================
# WELFORD'S ONLINE ALGORITHM
# ============================================================================

class WelfordAccumulator:
    """
    Welford's online algorithm for computing running mean and variance.

    Numerically stable single-pass algorithm. Supports:
      - Incremental updates (one sample at a time)
      - Z-score computation against current statistics
      - Serialization to/from arrays for ClickHouse storage
    """

    __slots__ = ('count', 'mean', 'm2')

    def __init__(self, count: int = 0, mean: float = 0.0, m2: float = 0.0):
        self.count = count
        self.mean = mean
        self.m2 = m2

    def update(self, x: float) -> None:
        """Add a new sample."""
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        """Population variance."""
        return self.m2 / self.count if self.count > 1 else 0.0

    @property
    def stddev(self) -> float:
        """Population standard deviation."""
        return math.sqrt(self.variance)

    def z_score(self, x: float) -> float:
        """Compute Z-score of x against current distribution."""
        sd = self.stddev
        if sd < 1e-10:
            return 0.0
        return (x - self.mean) / sd


class IPProfile:
    """
    Statistical profile for a single IP address.

    Tracks per-feature Welford accumulators and a 24-hour diurnal histogram.
    """

    __slots__ = (
        'ip', 'first_seen', 'last_seen', 'window_count',
        'features', 'diurnal', 'rdap_type', 'asn', 'country',
    )

    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = datetime.now(timezone.utc)
        self.last_seen = datetime.now(timezone.utc)
        self.window_count = 0
        self.features: List[WelfordAccumulator] = [
            WelfordAccumulator() for _ in range(N_FEATURES)
        ]
        self.diurnal: List[int] = [0] * 24  # hourly event counts
        self.rdap_type = 'unknown'
        self.asn = 0
        self.country = ''

    def update(self, feature_vector: List[float], hour: int) -> None:
        """Update profile with a new window's feature vector."""
        if len(feature_vector) != N_FEATURES:
            return

        self.window_count += 1
        self.last_seen = datetime.now(timezone.utc)

        for i, val in enumerate(feature_vector):
            self.features[i].update(val)

        if 0 <= hour < 24:
            self.diurnal[hour] += 1

    def z_scores(self, feature_vector: List[float]) -> List[float]:
        """Compute Z-scores for a feature vector against this profile."""
        if len(feature_vector) != N_FEATURES:
            return [0.0] * N_FEATURES
        return [self.features[i].z_score(feature_vector[i])
                for i in range(N_FEATURES)]

    def max_abs_z(self, feature_vector: List[float]) -> float:
        """Maximum absolute Z-score across all features."""
        zs = self.z_scores(feature_vector)
        return max(abs(z) for z in zs) if zs else 0.0

    def profile_deviation(self, feature_vector: List[float]) -> float:
        """Mean squared Z-score (Mahalanobis-like distance)."""
        zs = self.z_scores(feature_vector)
        if not zs:
            return 0.0
        return math.sqrt(sum(z * z for z in zs) / len(zs))

    def diurnal_anomaly(self, hour: int) -> float:
        """
        How unusual is activity at this hour for this IP?

        Returns a factor 0-1 where 1 = completely unexpected hour.
        Based on relative frequency vs the IP's own diurnal pattern.
        """
        total = sum(self.diurnal)
        if total < 10 or hour < 0 or hour >= 24:
            return 0.0

        # Laplace-smoothed frequency: avoids 0 for hours never seen
        smoothed = (self.diurnal[hour] + 1) / (total + 24)
        # Low frequency hours get high anomaly factor
        return max(0.0, 1.0 - smoothed * 24)

    def ip_age_days(self) -> float:
        """Days since first seen."""
        delta = datetime.now(timezone.utc) - self.first_seen
        return delta.total_seconds() / 86400.0

    def profile_hash(self) -> str:
        """Content hash for change detection."""
        data = json.dumps({
            'wc': self.window_count,
            'means': [f.mean for f in self.features],
            'm2s': [f.m2 for f in self.features],
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_ch_values(self) -> str:
        """Serialize to ClickHouse VALUES row."""
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        first = self.first_seen.strftime('%Y-%m-%d %H:%M:%S')
        last = self.last_seen.strftime('%Y-%m-%d %H:%M:%S')

        means = '[' + ','.join(f'{f.mean:.8f}' for f in self.features) + ']'
        m2s = '[' + ','.join(f'{f.m2:.8f}' for f in self.features) + ']'
        counts = '[' + ','.join(str(f.count) for f in self.features) + ']'
        names = '[' + ','.join(f"'{n}'" for n in FEATURE_NAMES) + ']'
        diurnal = '[' + ','.join(str(d) for d in self.diurnal) + ']'

        rdap_safe = ch_escape(self.rdap_type)[:20]
        country_safe = ch_escape(self.country)[:5]
        phash = self.profile_hash()

        return (
            f"(IPv4StringToNum('{self.ip}'), '{now}', {self.window_count}, "
            f"{names}, {means}, {m2s}, {counts}, {diurnal}, "
            f"'{first}', '{last}', '{rdap_safe}', {int(self.asn)}, "
            f"'{country_safe}', '{phash}')"
        )

    @classmethod
    def from_ch_row(cls, row: dict) -> 'IPProfile':
        """Deserialize from a ClickHouse JSON row."""
        ip = row.get('ip', '0.0.0.0')
        prof = cls(ip)

        prof.window_count = int(row.get('window_count', 0))

        # Parse timestamps
        for field, attr in [('first_seen', 'first_seen'), ('last_seen', 'last_seen')]:
            ts_str = row.get(field, '')
            if ts_str:
                try:
                    setattr(prof, attr, datetime.fromisoformat(
                        ts_str.replace(' ', 'T')).replace(tzinfo=timezone.utc))
                except ValueError:
                    pass

        # Restore Welford accumulators
        means = row.get('feature_means', [])
        m2s = row.get('feature_m2s', [])
        counts = row.get('feature_counts', [])

        for i in range(min(N_FEATURES, len(means), len(m2s), len(counts))):
            prof.features[i] = WelfordAccumulator(
                count=int(counts[i]),
                mean=float(means[i]),
                m2=float(m2s[i]),
            )

        # Restore diurnal histogram
        diurnal = row.get('diurnal_counts', [])
        for i in range(min(24, len(diurnal))):
            prof.diurnal[i] = int(diurnal[i])

        # RDAP metadata
        prof.rdap_type = str(row.get('rdap_type', 'unknown'))
        prof.asn = int(row.get('asn', 0))
        prof.country = str(row.get('country', ''))

        return prof


# ============================================================================
# FEATURE EXTRACTION FROM CLICKHOUSE
# ============================================================================

def shannon_entropy(counts: Dict[int, int]) -> float:
    """Compute Shannon entropy of a distribution given as {value: count}."""
    total = sum(counts.values())
    if total <= 1:
        return 0.0
    entropy = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def extract_window_features(window_seconds: int) -> Dict[str, Tuple[List[float], int]]:
    """
    Extract per-IP feature vectors from the last window of hydra_events.

    Returns {ip: (feature_vector, hour)} where feature_vector has N_FEATURES elements.
    """
    # Query hydra_events for per-IP aggregates
    event_query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            count() AS event_count,
            uniq(dst_port) AS unique_dst_ports,
            uniq(proto) AS unique_protocols,
            countIf(reason = 'blocklist') AS blocklist_count,
            countIf(bitAnd(tcp_flags, 2) = 2) AS syn_count,
            entropy(dst_port) AS dst_port_entropy,
            toHour(max(timestamp)) AS last_hour
        FROM {CH_DB}.hydra_events
        WHERE timestamp >= now() - INTERVAL {int(window_seconds)} SECOND
        GROUP BY src_ip
        HAVING event_count >= {int(MIN_EVENTS)}
    """

    event_result = ch_query(event_query)
    if not event_result:
        return {}

    # Parse event data
    ip_events = {}
    for line in event_result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            ec = float(row['event_count'])
            ip_events[ip] = {
                'event_count': ec,
                'event_rate': ec / window_seconds,
                'unique_dst_ports': int(row['unique_dst_ports']),
                'unique_protocols': int(row['unique_protocols']),
                'blocklist_ratio': float(row['blocklist_count']) / ec if ec > 0 else 0,
                'syn_flag_ratio': float(row['syn_count']) / ec if ec > 0 else 0,
                'dst_port_entropy': float(row.get('dst_port_entropy') or 0),
                'hour': int(row.get('last_hour', 0)),
            }
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue

    # Query napse_flows for per-IP flow stats (may be empty)
    flow_query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            count() AS flow_count,
            sum(bytes_orig + bytes_resp) AS total_bytes,
            avg(duration) AS avg_duration
        FROM {CH_DB}.napse_flows
        WHERE timestamp >= now() - INTERVAL {int(window_seconds)} SECOND
        GROUP BY src_ip
    """

    flow_data: Dict[str, dict] = {}
    flow_result = ch_query(flow_query)
    if flow_result:
        for line in flow_result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                flow_data[row['ip']] = {
                    'flow_count': float(row.get('flow_count') or 0),
                    'total_bytes': float(row.get('total_bytes') or 0),
                    'avg_duration': float(row.get('avg_duration') or 0),
                }
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                continue

    # Build feature vectors
    result: Dict[str, Tuple[List[float], int]] = {}
    for ip, evt in ip_events.items():
        hour = evt['hour']
        hour_rad = 2.0 * math.pi * hour / 24.0
        flow = flow_data.get(ip, {})

        vec = [
            evt['event_count'],
            evt['event_rate'],
            float(evt['unique_dst_ports']),
            float(evt['unique_protocols']),
            evt['blocklist_ratio'],
            evt['syn_flag_ratio'],
            evt['dst_port_entropy'],
            flow.get('flow_count', 0.0),
            flow.get('total_bytes', 0.0),
            flow.get('avg_duration', 0.0),
            math.sin(hour_rad),
            math.cos(hour_rad),
        ]
        result[ip] = (vec, hour)

    return result


def extract_backfill_features(hours: int) -> List[Tuple[str, List[float], int]]:
    """
    Extract per-IP per-hour feature vectors from historical data for backfill.

    Returns [(ip, feature_vector, hour), ...] for all historical windows.
    """
    query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            toStartOfHour(timestamp) AS window_start,
            toHour(toStartOfHour(timestamp)) AS hour,
            count() AS event_count,
            uniq(dst_port) AS unique_dst_ports,
            uniq(proto) AS unique_protocols,
            countIf(reason = 'blocklist') AS blocklist_count,
            countIf(bitAnd(tcp_flags, 2) = 2) AS syn_count
        FROM {CH_DB}.hydra_events
        WHERE timestamp >= now() - INTERVAL {int(hours)} HOUR
        GROUP BY src_ip, window_start
        HAVING event_count >= {int(MIN_EVENTS)}
        ORDER BY window_start
    """

    result = ch_query(query)
    if not result:
        return []

    # Also get historical flow data
    flow_query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            toStartOfHour(timestamp) AS window_start,
            count() AS flow_count,
            sum(bytes_orig + bytes_resp) AS total_bytes,
            avg(duration) AS avg_duration
        FROM {CH_DB}.napse_flows
        WHERE timestamp >= now() - INTERVAL {int(hours)} HOUR
        GROUP BY src_ip, window_start
    """

    flow_data: Dict[str, dict] = {}
    flow_result = ch_query(flow_query)
    if flow_result:
        for line in flow_result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                key = f"{row['ip']}_{row['window_start']}"
                flow_data[key] = {
                    'flow_count': float(row.get('flow_count') or 0),
                    'total_bytes': float(row.get('total_bytes') or 0),
                    'avg_duration': float(row.get('avg_duration') or 0),
                }
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                continue

    samples = []
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            hour = int(row['hour'])
            ec = float(row['event_count'])
            window_key = f"{ip}_{row['window_start']}"
            flow = flow_data.get(window_key, {})

            hour_rad = 2.0 * math.pi * hour / 24.0
            vec = [
                ec,
                ec / 3600.0,  # per-hour window
                float(row['unique_dst_ports']),
                float(row['unique_protocols']),
                float(row['blocklist_count']) / ec if ec > 0 else 0,
                float(row['syn_count']) / ec if ec > 0 else 0,
                0.0,  # entropy not available in hourly aggregate
                flow.get('flow_count', 0.0),
                flow.get('total_bytes', 0.0),
                flow.get('avg_duration', 0.0),
                math.sin(hour_rad),
                math.cos(hour_rad),
            ]
            samples.append((ip, vec, hour))
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue

    return samples


def load_rdap_enrichment() -> Dict[str, dict]:
    """Load RDAP type/ASN/country for all cached IPs."""
    query = f"""
        SELECT
            IPv4NumToString(ip) AS ip,
            rdap_type, asn, country
        FROM {CH_DB}.rdap_cache
        FINAL
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
            rdap[row['ip']] = {
                'rdap_type': row.get('rdap_type', 'unknown'),
                'asn': int(row.get('asn', 0)),
                'country': row.get('country', ''),
            }
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue

    return rdap


# ============================================================================
# PROFILE MANAGEMENT
# ============================================================================

# In-memory profile store
profiles: Dict[str, IPProfile] = {}


def evict_stale_profiles() -> int:
    """Evict oldest profiles if we exceed MAX_TRACKED_IPS."""
    if len(profiles) <= MAX_TRACKED_IPS:
        return 0

    # Sort by last_seen, evict oldest
    sorted_ips = sorted(profiles.keys(),
                        key=lambda ip: profiles[ip].last_seen)
    to_evict = len(profiles) - MAX_TRACKED_IPS
    evicted = 0
    for ip in sorted_ips[:to_evict]:
        del profiles[ip]
        evicted += 1

    return evicted


def load_profiles_from_ch() -> int:
    """Load existing profiles from ClickHouse into memory."""
    query = f"""
        SELECT
            IPv4NumToString(ip) AS ip,
            window_count,
            feature_names,
            feature_means,
            feature_m2s,
            feature_counts,
            diurnal_counts,
            toString(first_seen) AS first_seen,
            toString(last_seen) AS last_seen,
            rdap_type,
            asn,
            country,
            profile_hash
        FROM {CH_DB}.sentinel_ip_profiles
        FINAL
    """

    result = ch_query(query)
    if not result:
        return 0

    loaded = 0
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            prof = IPProfile.from_ch_row(row)
            if prof.window_count > 0:
                profiles[prof.ip] = prof
                loaded += 1
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.debug(f"Failed to load profile: {e}")
            continue

    return loaded


def persist_profiles() -> int:
    """Write all dirty profiles to ClickHouse."""
    if not profiles:
        return 0

    rows = []
    for ip, prof in profiles.items():
        if prof.window_count > 0:
            rows.append(prof.to_ch_values())

    if not rows:
        return 0

    # Batch insert (ReplacingMergeTree will deduplicate by ip)
    query = (
        f"INSERT INTO {CH_DB}.sentinel_ip_profiles "
        "(ip, updated_at, window_count, feature_names, feature_means, "
        "feature_m2s, feature_counts, diurnal_counts, first_seen, last_seen, "
        "rdap_type, asn, country, profile_hash) VALUES"
    )

    # Insert in batches of 100
    total = 0
    for i in range(0, len(rows), 100):
        batch = rows[i:i + 100]
        data = ", ".join(batch)
        if ch_insert(query, data):
            total += len(batch)

    return total


def update_profiles_with_window(features: Dict[str, Tuple[List[float], int]]) -> int:
    """Update in-memory profiles with a new window's features."""
    updated = 0
    for ip, (vec, hour) in features.items():
        if ip not in profiles:
            profiles[ip] = IPProfile(ip)

        profiles[ip].update(vec, hour)
        updated += 1

    return updated


def enrich_profiles_with_rdap() -> int:
    """Enrich profiles with RDAP data from rdap_cache."""
    rdap = load_rdap_enrichment()
    enriched = 0
    for ip, prof in profiles.items():
        if ip in rdap:
            r = rdap[ip]
            prof.rdap_type = r.get('rdap_type', prof.rdap_type)
            prof.asn = r.get('asn', prof.asn)
            prof.country = r.get('country', prof.country)
            enriched += 1
    return enriched


# ============================================================================
# LOGISTIC META-REGRESSION (operator feedback)
# ============================================================================

class LogisticRegression:
    """
    Minimal logistic regression for learning feature weights from
    operator feedback (confirm/false_positive labels).

    Pure Python, no dependencies. Uses gradient descent with L2 regularization.
    """

    def __init__(self, n_features: int, learning_rate: float = 0.01,
                 l2_lambda: float = 0.01):
        self.weights = [0.0] * n_features
        self.bias = 0.0
        self.lr = learning_rate
        self.l2 = l2_lambda
        self.n_features = n_features
        self.trained_samples = 0

    @staticmethod
    def _sigmoid(z: float) -> float:
        """Numerically stable sigmoid."""
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        ez = math.exp(z)
        return ez / (1.0 + ez)

    def predict_proba(self, x: List[float]) -> float:
        """Predict P(true_positive | features)."""
        z = self.bias + sum(w * xi for w, xi in zip(self.weights, x))
        return self._sigmoid(z)

    def fit(self, X: List[List[float]], y: List[int],
            epochs: int = 100) -> dict:
        """
        Train on labeled data.

        X: feature vectors (z-scores from profiles)
        y: labels (1 = true positive / confirm, 0 = false positive)

        Returns training metrics.
        """
        if not X or not y or len(X) != len(y):
            return {'samples': 0}

        n = len(X)
        for _ in range(epochs):
            for i in range(n):
                pred = self.predict_proba(X[i])
                error = y[i] - pred

                # Gradient descent with L2 regularization
                self.bias += self.lr * error
                for j in range(min(self.n_features, len(X[i]))):
                    self.weights[j] += self.lr * (
                        error * X[i][j] - self.l2 * self.weights[j]
                    )

        self.trained_samples = n

        # Compute metrics on training set
        tp = fp = fn = tn = 0
        for i in range(n):
            pred = 1 if self.predict_proba(X[i]) >= 0.5 else 0
            if pred == 1 and y[i] == 1:
                tp += 1
            elif pred == 1 and y[i] == 0:
                fp += 1
            elif pred == 0 and y[i] == 1:
                fn += 1
            else:
                tn += 1

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-10)

        return {
            'samples': n,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'false_positive_rate': fp / max(fp + tn, 1),
        }

    def feature_importance(self) -> Dict[str, float]:
        """Return feature importance as absolute weight magnitude."""
        return {FEATURE_NAMES[i]: abs(self.weights[i])
                for i in range(min(self.n_features, len(FEATURE_NAMES)))}

    def to_json(self) -> str:
        """Serialize model to JSON (NaN-safe)."""
        weights_safe = [w if math.isfinite(w) else 0.0 for w in self.weights]
        bias_safe = self.bias if math.isfinite(self.bias) else 0.0
        return json.dumps({
            'weights': weights_safe,
            'bias': bias_safe,
            'lr': self.lr,
            'l2': self.l2,
            'trained_samples': self.trained_samples,
        })

    @classmethod
    def from_json(cls, data: str) -> 'LogisticRegression':
        """Deserialize model from JSON."""
        d = json.loads(data)
        model = cls(len(d['weights']), d.get('lr', 0.01), d.get('l2', 0.01))
        model.weights = [w if isinstance(w, (int, float)) and math.isfinite(w) else 0.0
                         for w in d['weights']]
        bias = d.get('bias', 0.0)
        model.bias = bias if isinstance(bias, (int, float)) and math.isfinite(bias) else 0.0
        model.trained_samples = d.get('trained_samples', 0)
        return model


# Global meta-regression model
meta_model: Optional[LogisticRegression] = None


def load_training_data_from_verdicts() -> Tuple[List[List[float]], List[int]]:
    """
    Load operator-labeled verdicts and compute Z-score feature vectors.

    Returns (X, y) where:
      X = list of Z-score vectors
      y = list of labels (1=TP, 0=FP)
    """
    query = f"""
        SELECT
            IPv4NumToString(v.src_ip) AS ip,
            v.anomaly_score,
            v.verdict,
            v.operator_decision,
            f.feature_vector
        FROM {CH_DB}.hydra_verdicts v
        LEFT JOIN (
            SELECT src_ip, feature_vector,
                   row_number() OVER (PARTITION BY src_ip ORDER BY timestamp DESC) AS rn
            FROM {CH_DB}.hydra_ip_features
        ) f ON v.src_ip = f.src_ip AND f.rn = 1
        WHERE v.operator_decision IN ('confirm', 'false_positive')
        ORDER BY v.timestamp DESC
        LIMIT 1000
    """

    result = ch_query(query)
    if not result:
        return [], []

    X = []
    y = []
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            decision = row['operator_decision']

            # Label: 1 = confirm (true positive), 0 = false_positive
            label = 1 if decision == 'confirm' else 0

            # Get Z-scores from profile if available
            if ip in profiles and profiles[ip].window_count >= 3:
                prof = profiles[ip]
                fvec = row.get('feature_vector', [])
                if fvec and len(fvec) == 24:
                    # Map 24-feature to our 12-feature space
                    mapped = [
                        fvec[0],   # pps
                        fvec[1],   # bps
                        fvec[2],   # unique_dst_ports
                        fvec[3],   # unique_dst_ips
                        fvec[4],   # syn_ratio
                        fvec[5],   # rst_ratio
                        fvec[6],   # avg_pkt_size
                        0.0, 0.0, 0.0,  # flow features (unavailable)
                        fvec[18] if len(fvec) > 18 else 0.0,  # temporal
                        fvec[19] if len(fvec) > 19 else 0.0,  # temporal
                    ]
                    z = prof.z_scores(mapped)
                else:
                    z = [0.0] * N_FEATURES
            else:
                z = [0.0] * N_FEATURES

            # Guard against NaN from degenerate profiles
            if any(not math.isfinite(v) for v in z):
                z = [0.0] * N_FEATURES

            X.append(z)
            y.append(label)

        except (json.JSONDecodeError, KeyError, ValueError):
            continue

    return X, y


def train_meta_regression() -> Optional[dict]:
    """Train the logistic meta-regression if enough labeled data exists."""
    global meta_model

    X, y = load_training_data_from_verdicts()
    if len(X) < 10:
        logger.info(f"Insufficient labeled data for meta-regression "
                     f"({len(X)} samples, need 10+)")
        return None

    if meta_model is None:
        meta_model = LogisticRegression(N_FEATURES)

    metrics = meta_model.fit(X, y, epochs=200)
    logger.info(f"Meta-regression trained: {metrics}")

    # Save model state to ClickHouse
    model_json = ch_escape(meta_model.to_json())
    importance_json = ch_escape(json.dumps(meta_model.feature_importance()))
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    version_query = f"""
        SELECT max(version) AS v FROM {CH_DB}.sentinel_model_state
        WHERE model_name = 'logistic_meta'
    """
    ver_result = ch_query(version_query, fmt='JSONEachRow')
    version = 1
    if ver_result:
        for line in ver_result.strip().split('\n'):
            if line:
                try:
                    version = int(json.loads(line).get('v') or 0) + 1
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass

    ch_insert(
        f"INSERT INTO {CH_DB}.sentinel_model_state "
        "(model_name, version, trained_at, training_samples, model_params, "
        "precision, recall, f1_score, false_positive_rate, feature_importance) VALUES",
        f"('logistic_meta', {version}, '{now}', {metrics['samples']}, "
        f"'{model_json}', {metrics['precision']:.6f}, {metrics['recall']:.6f}, "
        f"{metrics['f1']:.6f}, {metrics['false_positive_rate']:.6f}, "
        f"'{importance_json}')"
    )

    return metrics


# ============================================================================
# PUBLIC API (for sentinel_engine.py import)
# ============================================================================

def get_profile(ip: str) -> Optional[IPProfile]:
    """Get the profile for an IP, or None if not profiled."""
    return profiles.get(ip)


def compute_z_scores(ip: str, feature_vector: List[float]) -> List[float]:
    """Compute Z-scores for a feature vector against an IP's profile."""
    prof = profiles.get(ip)
    if prof is None or prof.window_count < 3:
        return [0.0] * N_FEATURES
    return prof.z_scores(feature_vector)


def get_meta_prediction(z_scores: List[float]) -> float:
    """Get meta-regression P(TP|evidence) from Z-scores. Returns 0.5 if untrained."""
    if meta_model is None or meta_model.trained_samples < 10:
        return 0.5
    return meta_model.predict_proba(z_scores)


def get_profile_summary() -> dict:
    """Summary stats for dashboard/monitoring."""
    if not profiles:
        return {'total_profiles': 0}

    type_counts: Dict[str, int] = {}
    total_windows = 0
    for prof in profiles.values():
        type_counts[prof.rdap_type] = type_counts.get(prof.rdap_type, 0) + 1
        total_windows += prof.window_count

    return {
        'total_profiles': len(profiles),
        'total_windows': total_windows,
        'type_distribution': type_counts,
        'meta_model_trained': meta_model is not None and meta_model.trained_samples >= 10,
        'meta_model_samples': meta_model.trained_samples if meta_model else 0,
    }


# ============================================================================
# MAIN LOOP
# ============================================================================

def backfill_profiles(hours: int = 72) -> int:
    """Backfill profiles from historical data."""
    logger.info(f"Backfilling profiles from last {hours} hours...")
    samples = extract_backfill_features(hours)

    if not samples:
        logger.info("No historical data to backfill")
        return 0

    for ip, vec, hour in samples:
        if ip not in profiles:
            profiles[ip] = IPProfile(ip)
        profiles[ip].update(vec, hour)

    logger.info(f"Backfilled {len(samples)} windows for {len(profiles)} IPs")
    return len(samples)


def profile_cycle() -> dict:
    """Run one profiling cycle: extract features, update profiles, persist."""
    # Extract features from the current window
    features = extract_window_features(WINDOW_SIZE)
    if not features:
        return {'updated': 0, 'features': 0}

    # Update profiles
    updated = update_profiles_with_window(features)

    # Evict if needed
    evicted = evict_stale_profiles()
    if evicted:
        logger.info(f"Evicted {evicted} stale profiles")

    return {
        'updated': updated,
        'features': len(features),
        'total_profiles': len(profiles),
    }


def main():
    logger.info("SENTINEL Baseline Profiler starting...")
    logger.info(f"Profile interval: {PROFILE_INTERVAL}s")
    logger.info(f"Window size: {WINDOW_SIZE}s")
    logger.info(f"Features: {N_FEATURES} ({', '.join(FEATURE_NAMES)})")

    if not CH_PASSWORD:
        logger.error("CLICKHOUSE_PASSWORD not set, cannot proceed")
        sys.exit(1)

    # Load existing profiles from ClickHouse
    loaded = load_profiles_from_ch()
    logger.info(f"Loaded {loaded} existing profiles from ClickHouse")

    # Backfill from historical data if we have few profiles
    if loaded < 50:
        backfill_profiles(hours=72)

    # Enrich with RDAP data
    enriched = enrich_profiles_with_rdap()
    logger.info(f"RDAP-enriched {enriched} profiles")

    # Persist initial state
    persisted = persist_profiles()
    logger.info(f"Persisted {persisted} profiles to ClickHouse")

    # Try training meta-regression
    train_meta_regression()

    cycle_count = 0

    while running:
        # Wait for next cycle
        for _ in range(PROFILE_INTERVAL):
            if not running:
                break
            time.sleep(1)

        if not running:
            break

        cycle_count += 1

        try:
            result = profile_cycle()
            logger.info(
                f"Cycle {cycle_count}: {result['updated']} IPs updated, "
                f"{result['total_profiles']} total profiles"
            )

            # Persist periodically
            if cycle_count % PERSIST_EVERY == 0:
                persisted = persist_profiles()
                logger.info(f"Persisted {persisted} profiles")

                # Re-enrich with RDAP (new IPs may have been queried)
                enrich_profiles_with_rdap()

            # Retrain meta-regression every 12 cycles (1 hour at 5-min intervals)
            if cycle_count % 12 == 0:
                train_meta_regression()

        except Exception as e:
            logger.error(f"Profile cycle error: {e}", exc_info=True)

    # Final persist before shutdown
    logger.info("Persisting profiles before shutdown...")
    persist_profiles()
    logger.info("SENTINEL Baseline Profiler shutting down")


if __name__ == '__main__':
    main()
