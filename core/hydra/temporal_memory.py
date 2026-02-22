#!/usr/bin/env python3
"""
HookProbe SENTINEL Temporal Memory Engine
==========================================

Stage 4: Temporal pattern learning, behavioral drift detection,
and campaign co-occurrence analysis.

Core capabilities:
  - IP Behavioral Drift: KL divergence between current and historical
    feature distributions per IP (sliding 7-day windows)
  - Diurnal Rhythm Analysis: Per-IP hourly activity patterns. Activity
    outside learned rhythms increases suspicion.
  - Campaign Detection: IP co-occurrence graph — IPs appearing together
    in the same 5-minute attack windows share "campaign edges."
    Confirming one IP as malicious propagates reputation through the graph.
  - Intent Sequence Analysis: Track intent class transitions per IP
    (e.g., scan → brute_force → exploit) to predict attack chains.

Data sources:
  - hydra_events: Raw network events with timestamps, IPs, ports, flags
  - sentinel_ip_profiles: Per-IP Welford statistics from baseline_profiler
  - sentinel_evidence: SENTINEL scoring history per IP
  - hydra_verdicts: Operator feedback (confirm / false_positive)

Output:
  - ClickHouse: sentinel_temporal table (drift scores, campaign IDs)
  - In-memory campaign graph and IP reputation overlay
  - Public API consumed by sentinel_engine.py for evidence enrichment

Memory budget:
  - IP drift history: ~4KB per IP x 2000 IPs = ~8MB
  - Campaign graph: sparse adjacency, ~200KB
  - Intent transitions: ~100B per IP x 2000 IPs = ~200KB
  - Total: ~9MB

Usage:
    python3 temporal_memory.py
"""

import os
import sys
import time
import json
import math
import signal
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [TEMPORAL] %(levelname)s: %(message)s'
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

# Analysis interval (seconds)
ANALYSIS_INTERVAL = max(int(os.environ.get('TEMPORAL_INTERVAL', '600')), 30)

# Campaign co-occurrence window (seconds)
COOCCURRENCE_WINDOW = 300  # 5 minutes

# Drift detection: number of recent windows to compare against historical
DRIFT_RECENT_WINDOWS = 6     # Last 30 min (6 x 5min)
DRIFT_HISTORY_DAYS = 7       # Compare against 7 days of history

# Maximum IPs to track in memory (LRU eviction beyond this)
MAX_TRACKED_IPS = 2000

# Campaign graph parameters
CAMPAIGN_MIN_COOCCURRENCE = 3     # Min shared windows to form edge
CAMPAIGN_REPUTATION_DECAY = 0.6   # Transitive decay per hop
CAMPAIGN_MAX_HOPS = 3             # Max propagation depth

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


def ch_ddl(query: str) -> bool:
    """Execute a DDL statement (CREATE TABLE, etc.)."""
    if not CH_PASSWORD:
        return False
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        req = Request(url, data=query.encode('utf-8'))
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        with urlopen(req, timeout=30) as resp:
            resp.read()
        return True
    except Exception as e:
        logger.error(f"ClickHouse DDL error: {e}")
        return False


# ============================================================================
# TABLES
# ============================================================================

def ensure_tables():
    """Create sentinel_temporal and sentinel_campaigns tables if needed."""
    ch_ddl(f"""
        CREATE TABLE IF NOT EXISTS {CH_DB}.sentinel_temporal (
            timestamp DateTime64(3) DEFAULT now64(3),
            ip IPv4,
            drift_score Float32,
            diurnal_anomaly Float32,
            intent_entropy Float32,
            campaign_id String DEFAULT '',
            campaign_reputation Float32 DEFAULT 0,
            recent_event_rate Float32 DEFAULT 0,
            recent_port_diversity UInt16 DEFAULT 0,
            recent_syn_ratio Float32 DEFAULT 0,
            intent_sequence String DEFAULT '',
            verdict_context LowCardinality(String) DEFAULT ''
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (ip, timestamp)
        TTL toDateTime(timestamp) + INTERVAL 30 DAY
    """)

    ch_ddl(f"""
        CREATE TABLE IF NOT EXISTS {CH_DB}.sentinel_campaigns (
            discovered_at DateTime DEFAULT now(),
            campaign_id String,
            member_ips Array(IPv4),
            member_count UInt16,
            total_cooccurrences UInt32,
            max_reputation Float32,
            intent_classes Array(String),
            active UInt8 DEFAULT 1
        ) ENGINE = ReplacingMergeTree(discovered_at)
        ORDER BY campaign_id
        TTL discovered_at + INTERVAL 60 DAY
    """)


# ============================================================================
# BEHAVIORAL DRIFT DETECTION
# ============================================================================

class DriftDetector:
    """
    Detects behavioral drift per IP by comparing recent feature distributions
    against historical baselines using symmetric KL divergence.

    For each IP, computes:
      - Recent stats: last 30 min of activity (6 x 5-min windows)
      - Historical stats: from sentinel_ip_profiles (Welford accumulators)
      - KL divergence between the two Gaussian distributions

    A high KL divergence means the IP's recent behavior significantly
    differs from its historical norm — either a new attack pattern or
    a previously benign IP turning malicious.
    """

    @staticmethod
    def compute_kl_divergence(mu1: float, var1: float,
                              mu2: float, var2: float) -> float:
        """
        Symmetric KL divergence between two univariate Gaussians.

        (D_KL(P||Q) + D_KL(Q||P)) / 2

        Returns 0 if either variance is near-zero (insufficient data).
        """
        # Floor variances to avoid division by zero
        var1 = max(var1, 1e-8)
        var2 = max(var2, 1e-8)

        # Forward KL: D(P||Q)
        kl_fwd = 0.5 * (var1 / var2 + (mu2 - mu1) ** 2 / var2 - 1 + math.log(var2 / var1))

        # Reverse KL: D(Q||P)
        kl_rev = 0.5 * (var2 / var1 + (mu1 - mu2) ** 2 / var1 - 1 + math.log(var1 / var2))

        # Symmetric average
        kl = (kl_fwd + kl_rev) / 2.0

        if not math.isfinite(kl):
            return 0.0

        return max(0.0, kl)

    @staticmethod
    def compute_drift_score(recent_stats: dict, profile: dict) -> float:
        """
        Compute overall drift score as RMS of per-feature KL divergences.

        Features analyzed (from baseline_profiler):
          0: event_count, 1: event_rate, 2: unique_dst_ports,
          3: unique_protocols, 4: blocklist_ratio, 5: syn_flag_ratio,
          6: dst_port_entropy

        Excludes features 7-9 (flow-based, not in hydra_events) and
        10-11 (cyclical hour encoding, not meaningful for drift).
        """
        means = profile.get('feature_means', [])
        m2s = profile.get('feature_m2s', [])
        counts = profile.get('feature_counts', [])

        # Features to compare (indices in baseline_profiler feature vector)
        DRIFT_FEATURES = [0, 1, 2, 3, 4, 5, 6]

        kl_scores = []
        for idx in DRIFT_FEATURES:
            if idx >= len(means) or idx >= len(m2s) or idx >= len(counts):
                continue

            hist_count = int(counts[idx])
            if hist_count < 5:
                continue  # Not enough historical data

            hist_mean = float(means[idx])
            hist_var = float(m2s[idx]) / hist_count if hist_count > 1 else 1e-8

            # Get recent stats for this feature
            recent_key = f'f{idx}'
            rec = recent_stats.get(recent_key)
            if rec is None or rec.get('count', 0) < 2:
                continue

            recent_mean = rec['mean']
            recent_var = rec['variance']

            kl = DriftDetector.compute_kl_divergence(
                recent_mean, recent_var, hist_mean, hist_var)
            kl_scores.append(kl)

        if not kl_scores:
            return 0.0

        # RMS of KL divergences, capped at 10
        rms = math.sqrt(sum(k * k for k in kl_scores) / len(kl_scores))
        return min(10.0, rms)


def compute_recent_stats(window_seconds: int = 1800) -> Dict[str, dict]:
    """
    Compute per-IP recent feature statistics from the last N seconds.

    Returns: {ip: {f0: {mean, variance, count}, f1: ..., event_rate, ...}}
    """
    # Use 5-minute sub-windows for aggregation
    query = f"""
        SELECT
            src_ip AS ip,
            toStartOfFiveMinutes(timestamp) AS window,
            count() AS event_count,
            count() / 300.0 AS event_rate,
            uniq(dst_port) AS unique_ports,
            uniq(proto) AS unique_protos,
            countIf(feed_source != '') / greatest(count(), 1) AS blocklist_ratio,
            countIf(bitAnd(tcp_flags, 2) > 0) / greatest(count(), 1) AS syn_ratio,
            entropy(dst_port) AS port_entropy
        FROM {CH_DB}.hydra_events
        WHERE timestamp >= now() - INTERVAL {window_seconds} SECOND
        GROUP BY src_ip, window
        HAVING event_count >= 3
    """
    result = ch_query(query)
    if not result:
        return {}

    # Accumulate per-IP statistics across sub-windows using Welford
    ip_accum: Dict[str, dict] = {}

    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']

            if ip not in ip_accum:
                ip_accum[ip] = {
                    'windows': 0,
                    'total_events': 0,
                    'total_ports': 0,
                    'total_syn_ratio': 0.0,
                }
                for fi in range(7):
                    ip_accum[ip][f'f{fi}'] = {
                        'count': 0, 'mean': 0.0, 'm2': 0.0
                    }

            acc = ip_accum[ip]
            acc['windows'] += 1
            acc['total_events'] += int(row.get('event_count') or 0)
            acc['total_ports'] += int(row.get('unique_ports') or 0)
            acc['total_syn_ratio'] += float(row.get('syn_ratio') or 0)

            # Feature values for this sub-window
            features = [
                float(row.get('event_count') or 0),
                float(row.get('event_rate') or 0),
                float(row.get('unique_ports') or 0),
                float(row.get('unique_protos') or 0),
                float(row.get('blocklist_ratio') or 0),
                float(row.get('syn_ratio') or 0),
                float(row.get('port_entropy') or 0),
            ]

            # Welford update for each feature
            for fi, val in enumerate(features):
                f = acc[f'f{fi}']
                f['count'] += 1
                delta = val - f['mean']
                f['mean'] += delta / f['count']
                delta2 = val - f['mean']
                f['m2'] += delta * delta2

        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue

    # Compute final variances
    result_map = {}
    for ip, acc in ip_accum.items():
        ip_stats = {
            'windows': acc['windows'],
            'event_rate': acc['total_events'] / max(acc['windows'] * 300, 1),
            'port_diversity': acc['total_ports'],
            'syn_ratio': acc['total_syn_ratio'] / max(acc['windows'], 1),
        }
        for fi in range(7):
            f = acc[f'f{fi}']
            if f['count'] > 1:
                ip_stats[f'f{fi}'] = {
                    'mean': f['mean'],
                    'variance': f['m2'] / f['count'],  # population variance (matches baseline_profiler)
                    'count': f['count'],
                }
            elif f['count'] == 1:
                ip_stats[f'f{fi}'] = {
                    'mean': f['mean'],
                    'variance': 0.0,
                    'count': 1,
                }
        result_map[ip] = ip_stats

    return result_map


def load_profiles_batch(ips: List[str]) -> Dict[str, dict]:
    """Load historical profiles for drift comparison."""
    if not ips:
        return {}

    ip_list = ','.join(f"toIPv4('{ip}')" for ip in ips[:500])
    query = f"""
        SELECT
            ip,
            window_count, feature_means, feature_m2s, feature_counts,
            diurnal_counts, first_seen
        FROM {CH_DB}.sentinel_ip_profiles FINAL
        WHERE ip IN ({ip_list})
          AND window_count >= 5
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


# ============================================================================
# DIURNAL RHYTHM ANALYSIS
# ============================================================================

def compute_diurnal_anomaly(profile: dict, hour: int) -> float:
    """
    Compute how anomalous the current hour is for this IP.

    Uses Laplace-smoothed frequency from the IP's diurnal histogram.
    Returns 0.0 (normal) to 1.0 (very unusual hour for this IP).
    """
    diurnal = profile.get('diurnal_counts', [])
    if len(diurnal) != 24:
        return 0.0

    total = sum(diurnal)
    if total < 20 or hour < 0 or hour >= 24:
        return 0.0

    # Laplace-smoothed expected frequency
    smoothed = (diurnal[hour] + 1) / (total + 24)

    # Anomaly: 1 - (observed_frequency * 24)
    # If uniformly distributed, smoothed*24 = 1.0, anomaly = 0
    # If this hour has 0 events, smoothed*24 ≈ 1/total, anomaly ≈ 1
    return max(0.0, min(1.0, 1.0 - smoothed * 24))


# ============================================================================
# CAMPAIGN CO-OCCURRENCE GRAPH
# ============================================================================

class CampaignGraph:
    """
    Sparse undirected graph tracking IP co-occurrence in attack windows.

    Edges are weighted by the number of shared 5-minute windows.
    When an operator confirms an IP as malicious, reputation propagates
    through the graph with exponential decay per hop.

    Memory: ~200 bytes per edge, target < 200KB total.
    """

    def __init__(self):
        # {ip: {peer_ip: cooccurrence_count}}
        self.edges: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # {ip: reputation_score} from operator feedback propagation
        self.reputation: Dict[str, float] = {}
        # Campaign memberships: {campaign_id: set(ips)}
        self.campaigns: Dict[str, Set[str]] = {}
        # IP -> campaign_id mapping
        self.ip_campaign: Dict[str, str] = {}
        # Confirmed malicious IPs (from operator feedback)
        self.confirmed_malicious: Set[str] = set()

    def update_cooccurrence(self, window_ips: List[str]):
        """
        Update co-occurrence counts for all IP pairs in a window.

        Only creates edges between IPs in the same 5-min window,
        indicating potential coordinated activity.
        """
        # Deduplicate and cap at 50 IPs per window to bound O(n^2)
        unique_ips = sorted(set(window_ips))[:50]
        if len(unique_ips) < 2:
            return

        for i, ip_a in enumerate(unique_ips):
            for ip_b in unique_ips[i + 1:]:
                self.edges[ip_a][ip_b] += 1
                self.edges[ip_b][ip_a] += 1

    def build_from_events(self, hours: int = 24):
        """
        Build co-occurrence graph from recent hydra_events.

        Groups events into 5-minute windows and counts IP pairs.
        """
        query = f"""
            SELECT
                toStartOfFiveMinutes(timestamp) AS window,
                groupArray(50)(DISTINCT src_ip) AS ips
            FROM {CH_DB}.hydra_events
            WHERE timestamp >= now() - INTERVAL {hours} HOUR
            GROUP BY window
            HAVING length(ips) >= 2
            ORDER BY window
        """
        result = ch_query(query)
        if not result:
            return

        for line in result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                ips = row.get('ips', [])
                if len(ips) >= 2:
                    self.update_cooccurrence(ips)
            except (json.JSONDecodeError, KeyError):
                continue

    def detect_campaigns(self) -> List[dict]:
        """
        Detect campaigns via connected-component analysis on strong edges.

        Only considers edges with cooccurrence >= CAMPAIGN_MIN_COOCCURRENCE.
        Uses union-find for O(E * α(V)) component detection.
        """
        # Build strong-edge adjacency
        strong_adj: Dict[str, Set[str]] = defaultdict(set)
        for ip_a, peers in self.edges.items():
            for ip_b, count in peers.items():
                if count >= CAMPAIGN_MIN_COOCCURRENCE:
                    strong_adj[ip_a].add(ip_b)
                    strong_adj[ip_b].add(ip_a)

        if not strong_adj:
            return []

        # Union-Find
        parent: Dict[str, str] = {}

        def find(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent[x], parent[x])  # Path compression
                x = parent[x]
            return x

        def union(x: str, y: str):
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[rx] = ry

        for ip_a in strong_adj:
            if ip_a not in parent:
                parent[ip_a] = ip_a
            for ip_b in strong_adj[ip_a]:
                if ip_b not in parent:
                    parent[ip_b] = ip_b
                union(ip_a, ip_b)

        # Group into components
        components: Dict[str, Set[str]] = defaultdict(set)
        for ip in parent:
            components[find(ip)].add(ip)

        # Only keep components with 2+ members
        campaigns = []
        self.campaigns.clear()
        self.ip_campaign.clear()

        for root, members in components.items():
            if len(members) < 2:
                continue

            # Compute total co-occurrence weight within campaign
            total_weight = 0
            for ip_a in members:
                for ip_b in members:
                    if ip_a < ip_b:
                        total_weight += self.edges.get(ip_a, {}).get(ip_b, 0)

            safe_root = root.replace('.', '_')
            campaign_id = f"C-{safe_root}-{len(members)}"

            self.campaigns[campaign_id] = members
            for ip in members:
                self.ip_campaign[ip] = campaign_id

            campaigns.append({
                'campaign_id': campaign_id,
                'members': sorted(members),
                'member_count': len(members),
                'total_cooccurrences': total_weight,
            })

        return campaigns

    def propagate_reputation(self, confirmed_ip: str, base_reputation: float = 1.0):
        """
        Propagate malicious reputation from a confirmed IP through the graph.

        Uses BFS with exponential decay per hop.
        IP_A confirmed → IP_B gets base * edge_weight * DECAY^1
                       → IP_C gets base * edge_weight * DECAY^2
        """
        self.confirmed_malicious.add(confirmed_ip)
        self.reputation[confirmed_ip] = base_reputation

        # BFS propagation
        visited = {confirmed_ip}
        frontier = deque([(confirmed_ip, base_reputation, 0)])  # (ip, rep, depth)

        while frontier:
            current_ip, current_rep, depth = frontier.popleft()

            if depth >= CAMPAIGN_MAX_HOPS:
                continue

            peers = self.edges.get(current_ip, {})
            for peer_ip, cooccurrence in peers.items():
                if peer_ip in visited:
                    continue
                visited.add(peer_ip)

                # Reputation decays with distance and scales with co-occurrence strength
                edge_strength = min(1.0, cooccurrence / 10.0)
                propagated = current_rep * CAMPAIGN_REPUTATION_DECAY * edge_strength

                if propagated < 0.01:
                    continue

                # Accumulate (don't replace — multiple confirmed sources stack)
                self.reputation[peer_ip] = min(
                    1.0, self.reputation.get(peer_ip, 0) + propagated)
                frontier.append((peer_ip, propagated, depth + 1))

    def load_operator_feedback(self):
        """
        Load confirmed malicious IPs from operator verdicts and propagate.
        """
        query = f"""
            SELECT DISTINCT src_ip AS ip
            FROM {CH_DB}.hydra_verdicts
            WHERE operator_decision = 'confirm'
              AND timestamp >= now() - INTERVAL 7 DAY
        """
        result = ch_query(query)
        if not result:
            return

        for line in result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                ip = row.get('ip', '')
                if ip and ip not in self.confirmed_malicious:
                    self.propagate_reputation(ip)
            except (json.JSONDecodeError, KeyError):
                continue

    def get_reputation(self, ip: str) -> float:
        """Get campaign-propagated reputation for an IP (0 = unknown, 1 = confirmed malicious)."""
        return self.reputation.get(ip, 0.0)

    def get_campaign_id(self, ip: str) -> str:
        """Get campaign ID for an IP, or empty string."""
        return self.ip_campaign.get(ip, '')

    def prune_weak_edges(self, min_weight: int = 2):
        """Remove edges below minimum co-occurrence weight."""
        to_remove = []
        for ip_a, peers in self.edges.items():
            weak = [ip_b for ip_b, count in peers.items() if count < min_weight]
            for ip_b in weak:
                del peers[ip_b]
            if not peers:
                to_remove.append(ip_a)
        for ip in to_remove:
            del self.edges[ip]

    def persist_campaigns(self, campaigns: List[dict]):
        """Write campaign data to ClickHouse."""
        if not campaigns:
            return

        rows = []
        for c in campaigns[:100]:  # Cap at 100 campaigns
            members_sql = '[' + ','.join(
                f"toIPv4('{ch_escape(ip)}')" for ip in c['members'][:200]
            ) + ']'
            max_rep = max(
                (self.reputation.get(ip, 0) for ip in c['members']),
                default=0.0
            )
            # Collect intent classes from recent sentinel_evidence for these IPs
            intent_arr = '[]'
            rows.append(
                f"(now(), '{ch_escape(c['campaign_id'])}', "
                f"{members_sql}, {c['member_count']}, "
                f"{c['total_cooccurrences']}, {max_rep:.4f}, "
                f"{intent_arr}, 1)"
            )

        if rows:
            query = (
                f"INSERT INTO {CH_DB}.sentinel_campaigns "
                "(discovered_at, campaign_id, member_ips, member_count, "
                "total_cooccurrences, max_reputation, intent_classes, active)"
            )
            ch_insert(query, ', '.join(rows))


# ============================================================================
# INTENT SEQUENCE TRACKING
# ============================================================================

class IntentTracker:
    """
    Tracks sequences of intent classifications per IP to detect
    attack chain progression (e.g., scan → brute_force → exploit).

    Uses a simplified transition matrix to compute P(next_intent | current_intent)
    and an entropy measure of intent diversity per IP.
    """

    # Common intent classes from NAPSE/HYDRA
    INTENT_CLASSES = [
        'scan', 'brute_force', 'exploit', 'ddos',
        'c2', 'data_exfil', 'unknown'
    ]
    N_INTENTS = len(INTENT_CLASSES)
    INTENT_IDX = {name: i for i, name in enumerate(INTENT_CLASSES)}

    def __init__(self):
        # Global transition matrix: transitions[from][to] = count
        self.transitions = [[0] * self.N_INTENTS for _ in range(self.N_INTENTS)]
        # Per-IP last known intent
        self.ip_last_intent: Dict[str, int] = {}
        # Per-IP intent histogram (for entropy computation)
        self.ip_intent_counts: Dict[str, List[int]] = {}

    def update(self, ip: str, intent_class: str):
        """Record an intent observation for an IP."""
        idx = self.INTENT_IDX.get(intent_class.lower(), self.N_INTENTS - 1)

        # Update transition matrix
        if ip in self.ip_last_intent:
            prev = self.ip_last_intent[ip]
            self.transitions[prev][idx] += 1

        self.ip_last_intent[ip] = idx

        # Update per-IP histogram
        if ip not in self.ip_intent_counts:
            self.ip_intent_counts[ip] = [0] * self.N_INTENTS
        self.ip_intent_counts[ip][idx] += 1

    def get_intent_entropy(self, ip: str) -> float:
        """
        Compute Shannon entropy of intent distribution for an IP.

        High entropy = diverse attack patterns (likely automated scanner).
        Low entropy = focused attack (single intent, possibly targeted).
        Returns 0-1 normalized by log(N_INTENTS).
        """
        counts = self.ip_intent_counts.get(ip)
        if not counts:
            return 0.0

        total = sum(counts)
        if total < 2:
            return 0.0

        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / total
                entropy -= p * math.log(p)

        # Normalize to [0, 1]
        max_entropy = math.log(self.N_INTENTS)
        return entropy / max_entropy if max_entropy > 0 else 0.0

    def get_escalation_score(self, ip: str) -> float:
        """
        Compute attack escalation score based on intent transitions.

        Scan → brute_force → exploit is a classic escalation.
        Returns 0.0-1.0 where 1.0 = full escalation chain observed.
        """
        counts = self.ip_intent_counts.get(ip)
        if not counts:
            return 0.0

        # Check for escalation chain presence
        has_scan = counts[self.INTENT_IDX['scan']] > 0
        has_bf = counts[self.INTENT_IDX['brute_force']] > 0
        has_exploit = counts[self.INTENT_IDX['exploit']] > 0
        has_c2 = counts[self.INTENT_IDX['c2']] > 0
        has_exfil = counts[self.INTENT_IDX['data_exfil']] > 0

        # Score escalation stages
        score = 0.0
        if has_scan:
            score += 0.15
        if has_bf:
            score += 0.20
        if has_exploit:
            score += 0.30
        if has_c2:
            score += 0.20
        if has_exfil:
            score += 0.15

        return min(1.0, score)

    def get_intent_sequence(self, ip: str, max_len: int = 5) -> str:
        """Get the intent class name for recent activity."""
        counts = self.ip_intent_counts.get(ip)
        if not counts:
            return ''

        # Return top intents by frequency
        pairs = [(c, self.INTENT_CLASSES[i])
                 for i, c in enumerate(counts) if c > 0]
        pairs.sort(reverse=True)
        return ','.join(name for _, name in pairs[:max_len])

    def load_from_events(self, hours: int = 24):
        """
        Bootstrap intent data from hydra_events action/reason fields.

        Maps event actions to intent classes:
          - 'block_feed' / 'block_score' → depends on reason
          - reason containing 'scan' → scan
          - reason containing 'brute' → brute_force
          - dst_port 22 with high SYN → brute_force
          - dst_port 443/80 → potential exploit
        """
        query = f"""
            SELECT
                src_ip AS ip,
                action,
                reason,
                dst_port,
                count() AS cnt
            FROM {CH_DB}.hydra_events
            WHERE timestamp >= now() - INTERVAL {hours} HOUR
            GROUP BY src_ip, action, reason, dst_port
            HAVING cnt >= 2
            ORDER BY src_ip, cnt DESC
        """
        result = ch_query(query)
        if not result:
            return

        for line in result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                ip = row['ip']
                reason = str(row.get('reason', '')).lower()
                dst_port = int(row.get('dst_port') or 0)

                # Map to intent class
                intent = 'unknown'
                if 'scan' in reason or 'probe' in reason:
                    intent = 'scan'
                elif 'brute' in reason or (dst_port == 22 and int(row.get('cnt') or 0) > 20):
                    intent = 'brute_force'
                elif 'exploit' in reason or 'cve' in reason:
                    intent = 'exploit'
                elif 'ddos' in reason or 'flood' in reason:
                    intent = 'ddos'
                elif 'c2' in reason or 'beacon' in reason:
                    intent = 'c2'
                elif 'exfil' in reason:
                    intent = 'data_exfil'
                elif 'feed' in reason or 'blocklist' in reason:
                    intent = 'scan'  # Threat feed IPs are typically scanners

                self.update(ip, intent)
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                continue


# ============================================================================
# TEMPORAL ANALYSIS ENGINE
# ============================================================================

class TemporalEngine:
    """
    Orchestrates drift detection, campaign analysis, and intent tracking.

    Public API consumed by sentinel_engine.py:
      - get_temporal_signals(ip) -> dict with drift_score, campaign_rep, etc.
    """

    def __init__(self):
        self.drift = DriftDetector()
        self.campaigns = CampaignGraph()
        self.intents = IntentTracker()

        # Cache of latest temporal signals per IP
        self.signals_cache: Dict[str, dict] = {}
        self.last_analysis = 0.0

    def analyze(self) -> dict:
        """
        Run a full temporal analysis cycle:
        1. Compute recent stats per IP
        2. Load historical profiles
        3. Compute drift scores
        4. Build/update campaign graph
        5. Detect campaigns
        6. Load operator feedback & propagate reputation
        7. Track intent sequences
        8. Write results to ClickHouse

        Returns summary statistics.
        """
        start = time.monotonic()

        # Step 1: Recent IP statistics (last 30 min)
        recent_stats = compute_recent_stats(1800)
        if not recent_stats:
            return {'status': 'no_recent_data', 'ips': 0}

        active_ips = list(recent_stats.keys())
        logger.info(f"Analyzing {len(active_ips)} active IPs")

        # Step 2: Load historical profiles
        profiles = load_profiles_batch(active_ips)

        # Step 3: Compute drift scores
        drift_scores: Dict[str, float] = {}
        diurnal_scores: Dict[str, float] = {}
        now_hour = datetime.now(timezone.utc).hour

        for ip in active_ips:
            profile = profiles.get(ip)
            if profile:
                drift_scores[ip] = self.drift.compute_drift_score(
                    recent_stats[ip], profile)
                diurnal_scores[ip] = compute_diurnal_anomaly(profile, now_hour)

        # Step 4: Build/update campaign graph
        # First cycle: full 24h rebuild. Subsequent: incremental 1h update.
        if not self.campaigns.edges:
            self.campaigns.build_from_events(hours=24)
        else:
            self.campaigns.build_from_events(hours=1)
        self.campaigns.prune_weak_edges(min_weight=2)

        # Step 5: Detect campaigns
        campaign_list = self.campaigns.detect_campaigns()

        # Step 6: Operator feedback propagation
        self.campaigns.load_operator_feedback()

        # Step 7: Intent tracking (incremental: first=24h, subsequent=1h)
        if not self.intents.ip_intent_counts:
            self.intents.load_from_events(hours=24)
        else:
            self.intents.load_from_events(hours=1)

        # Step 8: Build signals cache and write to ClickHouse
        self.signals_cache.clear()
        rows = []
        now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        for ip in active_ips:
            drift = drift_scores.get(ip, 0.0)
            diurnal = diurnal_scores.get(ip, 0.0)
            campaign_rep = self.campaigns.get_reputation(ip)
            campaign_id = self.campaigns.get_campaign_id(ip)
            intent_entropy = self.intents.get_intent_entropy(ip)
            intent_seq = self.intents.get_intent_sequence(ip)

            rec_stats = recent_stats.get(ip, {})

            signals = {
                'drift_score': drift,
                'diurnal_anomaly': diurnal,
                'campaign_reputation': campaign_rep,
                'campaign_id': campaign_id,
                'intent_entropy': intent_entropy,
                'escalation_score': self.intents.get_escalation_score(ip),
                'intent_sequence': intent_seq,
                'event_rate': rec_stats.get('event_rate', 0.0),
                'port_diversity': rec_stats.get('port_diversity', 0),
                'syn_ratio': rec_stats.get('syn_ratio', 0.0),
            }
            self.signals_cache[ip] = signals

            # Build ClickHouse row
            safe_campaign = ch_escape(campaign_id)
            safe_intent = ch_escape(intent_seq[:200])
            rows.append(
                f"('{now_ts}', toIPv4('{ip}'), "
                f"{drift:.4f}, {diurnal:.4f}, {intent_entropy:.4f}, "
                f"'{safe_campaign}', {campaign_rep:.4f}, "
                f"{rec_stats.get('event_rate', 0):.4f}, "
                f"{rec_stats.get('port_diversity', 0)}, "
                f"{rec_stats.get('syn_ratio', 0):.4f}, "
                f"'{safe_intent}', '')"
            )

        # Batch insert
        total_written = 0
        if rows:
            query = (
                f"INSERT INTO {CH_DB}.sentinel_temporal "
                "(timestamp, ip, drift_score, diurnal_anomaly, intent_entropy, "
                "campaign_id, campaign_reputation, recent_event_rate, "
                "recent_port_diversity, recent_syn_ratio, intent_sequence, "
                "verdict_context)"
            )
            for i in range(0, len(rows), 100):
                batch = rows[i:i + 100]
                if ch_insert(query, ', '.join(batch)):
                    total_written += len(batch)

        # Persist campaigns
        if campaign_list:
            self.campaigns.persist_campaigns(campaign_list)

        elapsed = time.monotonic() - start
        self.last_analysis = time.monotonic()

        stats = {
            'status': 'ok',
            'ips_analyzed': len(active_ips),
            'ips_with_profiles': len(profiles),
            'ips_with_drift': sum(1 for d in drift_scores.values() if d > 0.5),
            'campaigns_detected': len(campaign_list),
            'campaign_members': sum(c['member_count'] for c in campaign_list),
            'ips_with_reputation': sum(1 for r in self.campaigns.reputation.values() if r > 0),
            'intents_tracked': len(self.intents.ip_intent_counts),
            'rows_written': total_written,
            'elapsed_sec': round(elapsed, 2),
        }

        return stats

    def get_temporal_signals(self, ip: str) -> dict:
        """
        Get temporal signals for an IP. Used by sentinel_engine.py
        for evidence enrichment.

        Returns empty dict if IP not in cache.
        """
        return self.signals_cache.get(ip, {})


# ============================================================================
# MAIN LOOP
# ============================================================================

def main():
    logger.info("SENTINEL Temporal Memory Engine starting...")
    logger.info(f"ClickHouse: {CH_HOST}:{CH_PORT}/{CH_DB}")
    logger.info(f"Analysis interval: {ANALYSIS_INTERVAL}s")

    if not CH_PASSWORD:
        logger.error("CLICKHOUSE_PASSWORD not set")
        sys.exit(1)

    # Create tables
    ensure_tables()
    logger.info("Tables verified")

    engine = TemporalEngine()

    # Initial analysis
    try:
        result = engine.analyze()
        logger.info(f"Initial analysis: {result}")
    except Exception as e:
        logger.error(f"Initial analysis failed: {e}", exc_info=True)

    # Main loop
    cycle_count = 0

    while running:
        for _ in range(ANALYSIS_INTERVAL):
            if not running:
                break
            time.sleep(1)

        if not running:
            break

        cycle_count += 1

        try:
            result = engine.analyze()
            if result.get('ips_analyzed', 0) > 0:
                logger.info(
                    f"Cycle {cycle_count}: "
                    f"{result['ips_analyzed']} IPs, "
                    f"{result.get('ips_with_drift', 0)} drifted, "
                    f"{result.get('campaigns_detected', 0)} campaigns "
                    f"({result.get('campaign_members', 0)} members), "
                    f"{result.get('intents_tracked', 0)} intents "
                    f"[{result.get('elapsed_sec', 0)}s]"
                )
        except Exception as e:
            logger.error(f"Analysis cycle error: {e}", exc_info=True)

    logger.info("Temporal Memory Engine shutting down")


if __name__ == '__main__':
    main()
