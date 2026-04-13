#!/usr/bin/env python3
"""
HookProbe HYDRA Predictor Engine
==================================

Continuous learning orchestrator that mines attack patterns from historical data,
generates predictive alerts, auto-creates IoCs/incidents, and manages model
retraining across the HYDRA/SENTINEL pipeline.

Runs on a 15-minute cycle with 4 analysis phases:
  Phase 1: Pattern Mining (hourly) - Extract recurring attack signatures
  Phase 2: Attack Prediction (15 min) - Match current activity against patterns
  Phase 3: IoC/Incident Generation (15 min) - Create from correlated signals
  Phase 4: Auto-Labeling (30 min) - Generate training labels from objective signals

Output:
  - sentinel_attack_patterns: Learned attack pattern library
  - predictive_alerts: Predicted future attacks
  - iocs: Auto-generated from campaigns, SENTINEL, XDP
  - incidents: Correlated multi-signal incidents
  - hydra_verdicts: Auto-labels for model training

Usage:
    python3 predictor_engine.py
"""

import os
import sys
import time
import json
import math
import random
import signal
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [PREDICTOR] %(levelname)s: %(message)s'
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

# Main prediction cycle (seconds)
PREDICT_INTERVAL = max(int(os.environ.get('PREDICTOR_INTERVAL', '900')), 60)  # 15 min

# Pattern mining runs hourly (every N prediction cycles)
PATTERN_MINE_EVERY = max(int(os.environ.get('PATTERN_MINE_INTERVAL', '3600')) // PREDICT_INTERVAL, 1)

# Auto-labeling runs every 30 min
AUTO_LABEL_EVERY = max(int(os.environ.get('AUTO_LABEL_INTERVAL', '1800')) // PREDICT_INTERVAL, 1)

# Escalation prediction threshold
ESCALATION_THRESHOLD = float(os.environ.get('ESCALATION_THRESHOLD', '0.4'))

# Minimum campaign members to generate incident
MIN_CAMPAIGN_MEMBERS = int(os.environ.get('MIN_CAMPAIGN_MEMBERS', '5'))

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
    """Execute a ClickHouse query via HTTP API."""
    if not CH_PASSWORD:
        return None
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        full_query = query + (f" FORMAT {fmt}" if fmt else "")
        req = Request(url, data=full_query.encode('utf-8'))
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        with urlopen(req, timeout=60) as resp:
            return resp.read().decode('utf-8')
    except HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')[:300]
        logger.error(f"ClickHouse query error: {e} - {body}")
        return None
    except Exception as e:
        logger.error(f"ClickHouse query error: {e}")
        return None


def ch_insert(query: str, data: str = '') -> bool:
    """Execute a ClickHouse INSERT. VALUES data goes in POST body."""
    if not CH_PASSWORD:
        return False
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        req = Request(url, data=(query + (' VALUES ' + data if data else '')).encode('utf-8'))
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        with urlopen(req, timeout=30) as resp:
            resp.read()
        return True
    except HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')[:300]
        logger.error(f"ClickHouse insert error: {e} - {body}")
        return False
    except Exception as e:
        logger.error(f"ClickHouse insert error: {e}")
        return False


def ch_ddl(query: str) -> bool:
    """Execute a DDL statement."""
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


def parse_rows(result: Optional[str]) -> List[dict]:
    """Parse JSONEachRow result into list of dicts."""
    if not result:
        return []
    rows = []
    for line in result.strip().split('\n'):
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


# ============================================================================
# SCHEMA INITIALIZATION
# ============================================================================

def ensure_tables():
    """Create predictor-specific tables."""
    ch_ddl(f"""
        CREATE TABLE IF NOT EXISTS {CH_DB}.sentinel_attack_patterns (
            pattern_id String,
            discovered_at DateTime64(3) DEFAULT now64(3),
            updated_at DateTime64(3) DEFAULT now64(3),
            pattern_type LowCardinality(String),
            description String DEFAULT '',
            hour_distribution Array(Float32) DEFAULT [],
            day_of_week_distribution Array(Float32) DEFAULT [],
            feature_centroid Array(Float32) DEFAULT [],
            feature_stddev Array(Float32) DEFAULT [],
            intent_sequence Array(String) DEFAULT [],
            transition_probabilities String DEFAULT '',
            typical_member_count UInt16 DEFAULT 0,
            typical_cooccurrence UInt32 DEFAULT 0,
            observation_count UInt32 DEFAULT 0,
            last_match_at DateTime64(3) DEFAULT now64(3),
            confidence Float32 DEFAULT 0,
            threat_category LowCardinality(String) DEFAULT '',
            mitre_tactics Array(String) DEFAULT [],
            severity LowCardinality(String) DEFAULT 'medium'
        ) ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY pattern_id
        TTL toDateTime(updated_at) + INTERVAL 180 DAY
    """)

    ch_ddl(f"""
        CREATE TABLE IF NOT EXISTS {CH_DB}.predictive_alerts (
            id UUID DEFAULT generateUUIDv4(),
            created_at DateTime64(3) DEFAULT now64(3),
            pattern_id String DEFAULT '',
            alert_type LowCardinality(String),
            description String DEFAULT '',
            severity LowCardinality(String) DEFAULT 'medium',
            confidence Float32 DEFAULT 0,
            involved_ips Array(IPv4) DEFAULT [],
            predicted_action LowCardinality(String) DEFAULT '',
            time_horizon_minutes UInt16 DEFAULT 60,
            status LowCardinality(String) DEFAULT 'open',
            resolved_at Nullable(DateTime64(3))
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(created_at)
        ORDER BY (created_at, severity)
        TTL toDateTime(created_at) + INTERVAL 30 DAY
    """)


# ============================================================================
# PHASE 1: PATTERN MINING
# ============================================================================

def _kmeans_1d(data: List[float], k: int, max_iter: int = 20) -> List[Tuple[float, List[int]]]:
    """Simple 1D k-means. Returns [(centroid, [indices]), ...]."""
    if not data or k < 1:
        return []
    k = min(k, len(data))
    # Initialize centroids by sampling
    centroids = sorted(random.sample(data, k))
    assignments = [0] * len(data)

    for _ in range(max_iter):
        # Assign
        for i, x in enumerate(data):
            best = min(range(k), key=lambda c: abs(x - centroids[c]))
            assignments[i] = best
        # Update
        new_centroids = []
        for c in range(k):
            members = [data[i] for i in range(len(data)) if assignments[i] == c]
            new_centroids.append(sum(members) / len(members) if members else centroids[c])
        if new_centroids == centroids:
            break
        centroids = new_centroids

    clusters = []
    for c in range(k):
        indices = [i for i in range(len(data)) if assignments[i] == c]
        clusters.append((centroids[c], indices))
    return clusters


def mine_temporal_patterns(days: int = 14) -> int:
    """Mine temporal attack patterns from hourly event distributions."""
    query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            toHour(timestamp) AS hour,
            count() AS events
        FROM {CH_DB}.hydra_events
        WHERE timestamp >= now() - INTERVAL {days} DAY
        GROUP BY src_ip, hour
        HAVING events >= 10
    """
    rows = parse_rows(ch_query(query))
    if not rows:
        return 0

    # Build per-IP hourly histograms
    ip_histograms: Dict[str, List[int]] = defaultdict(lambda: [0] * 24)
    for r in rows:
        ip = r.get('ip', '')
        hour = int(r.get('hour', 0))
        events = int(r.get('events', 0))
        if 0 <= hour < 24:
            ip_histograms[ip][hour] += events

    # Normalize histograms and compute dominant hour
    ip_dominant_hours = {}
    for ip, hist in ip_histograms.items():
        total = sum(hist)
        if total > 0:
            dominant = max(range(24), key=lambda h: hist[h])
            ip_dominant_hours[ip] = dominant

    if len(ip_dominant_hours) < 5:
        return 0

    # Cluster IPs by dominant attack hour
    hours_list = list(ip_dominant_hours.values())
    ips_list = list(ip_dominant_hours.keys())

    clusters = _kmeans_1d(hours_list, min(5, len(hours_list) // 3 + 1))

    patterns_written = 0
    now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    for centroid, indices in clusters:
        if len(indices) < 3:
            continue

        # Aggregate histogram for this cluster
        cluster_hist = [0] * 24
        for idx in indices:
            ip = ips_list[idx]
            for h in range(24):
                cluster_hist[h] += ip_histograms[ip][h]

        total = sum(cluster_hist)
        normalized = [h / total for h in cluster_hist] if total > 0 else [0.0] * 24

        peak_hour = max(range(24), key=lambda h: normalized[h])
        pattern_id = f"temporal-h{peak_hour:02d}-n{len(indices)}"

        hist_str = '[' + ','.join(f'{v:.6f}' for v in normalized) + ']'
        desc = (f"Cluster of {len(indices)} IPs attacking primarily at "
                f"{peak_hour:02d}:00 UTC ({total} total events)")

        query = (
            f"INSERT INTO {CH_DB}.sentinel_attack_patterns "
            "(pattern_id, discovered_at, updated_at, pattern_type, description, "
            "hour_distribution, observation_count, confidence, threat_category, severity)"
        )
        data = (
            f"('{ch_escape(pattern_id)}', '{now_ts}', '{now_ts}', 'temporal', "
            f"'{ch_escape(desc)}', {hist_str}, {len(indices)}, "
            f"{min(len(indices) / 20.0, 0.95):.4f}, 'timed_attack', "
            f"'{'high' if len(indices) > 50 else 'medium'}')"
        )
        if ch_insert(query, data):
            patterns_written += 1

    return patterns_written


def mine_sequential_patterns(days: int = 14) -> int:
    """Mine intent transition patterns (attack chains)."""
    query = f"""
        SELECT
            intent_sequence,
            count() AS occurrences
        FROM {CH_DB}.sentinel_temporal
        WHERE timestamp >= now() - INTERVAL {days} DAY
          AND intent_sequence != ''
        GROUP BY intent_sequence
        HAVING occurrences >= 5
        ORDER BY occurrences DESC
        LIMIT 50
    """
    rows = parse_rows(ch_query(query))
    if not rows:
        return 0

    patterns_written = 0
    now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    # Build transition matrix from all sequences
    transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in rows:
        seq = str(r.get('intent_sequence', ''))
        intents = [s.strip() for s in seq.split(',') if s.strip()]
        for i in range(len(intents) - 1):
            transitions[intents[i]][intents[i + 1]] += int(r.get('occurrences', 1))

    # Find escalation chains
    escalation_order = {'scan': 0, 'brute_force': 1, 'exploit': 2, 'c2': 3, 'data_exfil': 4}

    for from_intent, targets in transitions.items():
        total = sum(targets.values())
        if total < 5:
            continue

        for to_intent, count in targets.items():
            prob = count / total
            if prob < 0.1:
                continue

            # Check if this is an escalation
            from_order = escalation_order.get(from_intent, -1)
            to_order = escalation_order.get(to_intent, -1)
            is_escalation = to_order > from_order >= 0

            pattern_id = f"seq-{from_intent}-{to_intent}-p{prob:.0%}"
            severity = 'high' if is_escalation else 'medium'

            intent_arr = f"['{ch_escape(from_intent)}','{ch_escape(to_intent)}']"
            trans_json = json.dumps({from_intent: {to_intent: round(prob, 4)}})

            desc = (f"After {from_intent}, {prob:.0%} probability of {to_intent} "
                    f"(observed {count} times)")

            query_str = (
                f"INSERT INTO {CH_DB}.sentinel_attack_patterns "
                "(pattern_id, discovered_at, updated_at, pattern_type, description, "
                "intent_sequence, transition_probabilities, observation_count, "
                "confidence, threat_category, severity)"
            )
            data = (
                f"('{ch_escape(pattern_id)}', '{now_ts}', '{now_ts}', 'sequential', "
                f"'{ch_escape(desc)}', {intent_arr}, '{ch_escape(trans_json)}', "
                f"{count}, {prob:.4f}, "
                f"'{'attack_escalation' if is_escalation else 'intent_transition'}', "
                f"'{severity}')"
            )
            if ch_insert(query_str, data):
                patterns_written += 1

    return patterns_written


def mine_campaign_signatures() -> int:
    """Mine campaign behavioral signatures."""
    query = f"""
        SELECT
            campaign_id,
            member_count,
            total_cooccurrences,
            max_reputation,
            length(member_ips) as actual_members
        FROM {CH_DB}.sentinel_campaigns FINAL
        WHERE active = 1
          AND member_count >= 3
        ORDER BY total_cooccurrences DESC
        LIMIT 20
    """
    rows = parse_rows(ch_query(query))
    if not rows:
        return 0

    patterns_written = 0
    now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    # Compute average campaign profile
    sizes = [int(r.get('member_count', 0)) for r in rows]
    coocs = [int(r.get('total_cooccurrences', 0)) for r in rows]

    avg_size = sum(sizes) / len(sizes) if sizes else 0
    avg_cooc = sum(coocs) / len(coocs) if coocs else 0

    pattern_id = f"campaign-avg-n{len(rows)}"
    desc = (f"Average campaign profile from {len(rows)} active campaigns: "
            f"~{avg_size:.0f} members, ~{avg_cooc:.0f} co-occurrences")

    query_str = (
        f"INSERT INTO {CH_DB}.sentinel_attack_patterns "
        "(pattern_id, discovered_at, updated_at, pattern_type, description, "
        "typical_member_count, typical_cooccurrence, observation_count, "
        "confidence, threat_category, severity)"
    )
    data = (
        f"('{ch_escape(pattern_id)}', '{now_ts}', '{now_ts}', 'campaign', "
        f"'{ch_escape(desc)}', {int(avg_size)}, {int(avg_cooc)}, {len(rows)}, "
        f"0.7000, 'coordinated_attack', 'high')"
    )
    if ch_insert(query_str, data):
        patterns_written += 1

    return patterns_written


# ============================================================================
# PHASE 2: ATTACK PREDICTION
# ============================================================================

def predict_escalations() -> List[dict]:
    """Predict which IPs will escalate based on intent sequences."""
    # Find IPs with recent scan/brute_force activity
    query = f"""
        SELECT
            IPv4NumToString(ip) AS ip_str,
            intent_sequence,
            drift_score,
            campaign_reputation
        FROM {CH_DB}.sentinel_temporal
        WHERE timestamp >= now() - INTERVAL 30 MINUTE
          AND intent_sequence != ''
        ORDER BY timestamp DESC
        LIMIT 200
    """
    rows = parse_rows(ch_query(query))
    if not rows:
        return []

    # Load transition probabilities from patterns
    pattern_query = f"""
        SELECT
            transition_probabilities
        FROM {CH_DB}.sentinel_attack_patterns FINAL
        WHERE pattern_type = 'sequential'
          AND confidence >= {ESCALATION_THRESHOLD}
    """
    patterns = parse_rows(ch_query(pattern_query))

    # Build global transition probability map
    global_trans: Dict[str, Dict[str, float]] = {}
    for p in patterns:
        try:
            trans = json.loads(p.get('transition_probabilities', '{}'))
            for from_i, targets in trans.items():
                if from_i not in global_trans:
                    global_trans[from_i] = {}
                for to_i, prob in targets.items():
                    global_trans[from_i][to_i] = max(
                        global_trans[from_i].get(to_i, 0), prob)
        except (json.JSONDecodeError, AttributeError):
            continue

    predictions = []
    seen_ips: Set[str] = set()

    for r in rows:
        ip = r.get('ip_str', '')
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)

        seq = str(r.get('intent_sequence', ''))
        intents = [s.strip() for s in seq.split(',') if s.strip()]
        if not intents:
            continue

        current_intent = intents[0]  # Most frequent intent
        drift = float(r.get('drift_score', 0))
        campaign_rep = float(r.get('campaign_reputation', 0))

        # Check if escalation is predicted
        next_intents = global_trans.get(current_intent, {})
        for next_intent, prob in next_intents.items():
            # Boost probability if IP is drifting or in a campaign
            adjusted_prob = prob * (1.0 + drift * 0.1 + campaign_rep * 0.2)
            if adjusted_prob >= ESCALATION_THRESHOLD:
                predictions.append({
                    'ip': ip,
                    'current_intent': current_intent,
                    'predicted_intent': next_intent,
                    'probability': min(adjusted_prob, 0.99),
                    'drift_score': drift,
                    'campaign_reputation': campaign_rep,
                })

    return predictions


def predict_campaign_formation() -> List[dict]:
    """Detect emerging campaigns from IP co-occurrence patterns."""
    query = f"""
        SELECT
            campaign_id,
            member_count,
            total_cooccurrences,
            max_reputation
        FROM {CH_DB}.sentinel_campaigns FINAL
        WHERE active = 1
          AND discovered_at >= now() - INTERVAL 1 HOUR
          AND member_count >= 3
        ORDER BY member_count DESC
        LIMIT 10
    """
    rows = parse_rows(ch_query(query))
    predictions = []

    for r in rows:
        members = int(r.get('member_count', 0))
        coocs = int(r.get('total_cooccurrences', 0))
        rep = float(r.get('max_reputation', 0))
        campaign_id = str(r.get('campaign_id', ''))

        # Predict campaign will grow if it has high co-occurrence density
        density = coocs / max(members * (members - 1) / 2, 1)
        if density > 0.3 and members >= MIN_CAMPAIGN_MEMBERS:
            predictions.append({
                'campaign_id': campaign_id,
                'current_members': members,
                'density': density,
                'reputation': rep,
                'severity': 'high' if rep > 0.5 else 'medium',
            })

    return predictions


def write_predictive_alerts(escalations: List[dict], campaigns: List[dict]) -> int:
    """Write predictive alerts to ClickHouse."""
    now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    rows = []

    # Deduplicate against existing alerts
    existing_query = f"""
        SELECT arrayJoin(involved_ips) AS ip
        FROM {CH_DB}.predictive_alerts
        WHERE created_at >= now() - INTERVAL 1 HOUR
          AND status = 'open'
    """
    existing_ips: Set[str] = set()
    for r in parse_rows(ch_query(existing_query)):
        existing_ips.add(str(r.get('ip', '')))

    for e in escalations:
        if e['ip'] in existing_ips:
            continue
        desc = (f"IP {e['ip']} currently performing {e['current_intent']}, "
                f"predicted to escalate to {e['predicted_intent']} "
                f"(P={e['probability']:.2f})")
        severity = 'high' if e['predicted_intent'] in ('exploit', 'c2', 'data_exfil') else 'medium'
        rows.append(
            f"('{now_ts}', '', 'escalation_predicted', "
            f"'{ch_escape(desc)}', '{severity}', {e['probability']:.4f}, "
            f"[toIPv4('{e['ip']}')], '{ch_escape(e['predicted_intent'])}', "
            f"60, 'open', NULL)"
        )

    for c in campaigns:
        rows.append(
            f"('{now_ts}', '{ch_escape(c['campaign_id'])}', 'campaign_forming', "
            f"'Campaign {ch_escape(c['campaign_id'])} with {c['current_members']} members, "
            f"density {c['density']:.2f}, reputation {c['reputation']:.2f}', "
            f"'{c['severity']}', {c['density']:.4f}, "
            f"[], 'coordinated_attack', 120, 'open', NULL)"
        )

    if not rows:
        return 0

    query = (
        f"INSERT INTO {CH_DB}.predictive_alerts "
        "(created_at, pattern_id, alert_type, description, severity, confidence, "
        "involved_ips, predicted_action, time_horizon_minutes, status, resolved_at)"
    )

    written = 0
    for i in range(0, len(rows), 50):
        batch = rows[i:i + 50]
        if ch_insert(query, ', '.join(batch)):
            written += len(batch)

    return written


# ============================================================================
# PHASE 3: AUTO-LABELING FOR MODEL TRAINING
# ============================================================================

def auto_label_from_threat_feeds() -> int:
    """Auto-label verdicts based on threat feed membership."""
    # IPs blocked by threat feeds are objectively malicious
    query = f"""
        SELECT DISTINCT
            src_ip,
            IPv4NumToString(src_ip) AS ip_str
        FROM {CH_DB}.hydra_events
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND feed_source != ''
          AND src_ip NOT IN (
              SELECT src_ip FROM {CH_DB}.hydra_verdicts
              WHERE operator_decision != ''
                AND timestamp >= now() - INTERVAL 7 DAY
          )
        LIMIT 100
    """
    rows = parse_rows(ch_query(query))
    if not rows:
        return 0

    now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    values = []
    for r in rows:
        ip = r.get('ip_str', '')
        if not ip:
            continue
        values.append(
            f"('{now_ts}', IPv4StringToNum('{ip}'), 0.9, [0.9], "
            f"'malicious', 'none', 'auto_confirm', '{now_ts}')"
        )

    if not values:
        return 0

    query_str = (
        f"INSERT INTO {CH_DB}.hydra_verdicts "
        "(timestamp, src_ip, anomaly_score, model_scores, verdict, "
        "action_taken, operator_decision, operator_decided_at)"
    )

    written = 0
    for i in range(0, len(values), 50):
        batch = values[i:i + 50]
        if ch_insert(query_str, ', '.join(batch)):
            written += len(batch)

    return written


def auto_label_from_rdap() -> int:
    """Auto-label based on RDAP classification (Tor, VPN = likely malicious)."""
    query = f"""
        SELECT DISTINCT
            IPv4NumToString(r.ip) AS ip_str,
            r.rdap_type
        FROM {CH_DB}.rdap_cache r FINAL
        JOIN (
            SELECT DISTINCT src_ip
            FROM {CH_DB}.hydra_events
            WHERE timestamp >= now() - INTERVAL 24 HOUR
        ) e ON r.ip = e.src_ip
        WHERE r.rdap_type IN ('tor', 'vpn')
          AND r.ip NOT IN (
              SELECT src_ip FROM {CH_DB}.hydra_verdicts
              WHERE operator_decision != ''
                AND timestamp >= now() - INTERVAL 7 DAY
          )
        LIMIT 50
    """
    rows = parse_rows(ch_query(query))
    if not rows:
        return 0

    now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    values = []
    for r in rows:
        ip = r.get('ip_str', '')
        if not ip:
            continue
        values.append(
            f"('{now_ts}', IPv4StringToNum('{ip}'), 0.8, [0.8], "
            f"'suspicious', 'none', 'auto_confirm', '{now_ts}')"
        )

    if not values:
        return 0

    query_str = (
        f"INSERT INTO {CH_DB}.hydra_verdicts "
        "(timestamp, src_ip, anomaly_score, model_scores, verdict, "
        "action_taken, operator_decision, operator_decided_at)"
    )

    written = 0
    for i in range(0, len(values), 50):
        batch = values[i:i + 50]
        if ch_insert(query_str, ', '.join(batch)):
            written += len(batch)

    return written


def auto_label_benign_cdn() -> int:
    """Auto-label CDN/ISP IPs with no threat history as false positives."""
    query = f"""
        SELECT DISTINCT
            IPv4NumToString(r.ip) AS ip_str
        FROM {CH_DB}.rdap_cache r FINAL
        JOIN (
            SELECT src_ip, count() AS cnt
            FROM {CH_DB}.hydra_verdicts
            WHERE verdict IN ('suspicious', 'malicious')
              AND operator_decision = ''
              AND timestamp >= now() - INTERVAL 7 DAY
            GROUP BY src_ip
            HAVING cnt <= 2
        ) v ON r.ip = v.src_ip
        WHERE r.rdap_type IN ('cdn', 'isp')
          AND r.ip NOT IN (
              SELECT src_ip FROM {CH_DB}.hydra_events
              WHERE timestamp >= now() - INTERVAL 7 DAY
                AND action = 'drop'
              GROUP BY src_ip
              HAVING count() >= 10
          )
        LIMIT 30
    """
    rows = parse_rows(ch_query(query))
    if not rows:
        return 0

    now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    values = []
    for r in rows:
        ip = r.get('ip_str', '')
        if not ip:
            continue
        values.append(
            f"('{now_ts}', IPv4StringToNum('{ip}'), 0.2, [0.2], "
            f"'benign', 'none', 'auto_false_positive', '{now_ts}')"
        )

    if not values:
        return 0

    query_str = (
        f"INSERT INTO {CH_DB}.hydra_verdicts "
        "(timestamp, src_ip, anomaly_score, model_scores, verdict, "
        "action_taken, operator_decision, operator_decided_at)"
    )

    written = 0
    for i in range(0, len(values), 50):
        batch = values[i:i + 50]
        if ch_insert(query_str, ', '.join(batch)):
            written += len(batch)

    return written


# ============================================================================
# DISCORD ALERTS
# ============================================================================

def send_discord_prediction(predictions: List[dict], campaigns: List[dict]) -> None:
    """Send Discord alert for high-confidence predictions."""
    if not DISCORD_WEBHOOK:
        return

    high_conf = [p for p in predictions if p['probability'] >= 0.6]
    if not high_conf and not campaigns:
        return

    try:
        fields = []
        for p in high_conf[:5]:
            fields.append({
                "name": f"Escalation: {p['ip']}",
                "value": (f"{p['current_intent']} -> {p['predicted_intent']} "
                          f"(P={p['probability']:.0%})"),
                "inline": True,
            })
        for c in campaigns[:3]:
            fields.append({
                "name": f"Campaign: {c['campaign_id'][:30]}",
                "value": f"{c['current_members']} members, rep={c['reputation']:.2f}",
                "inline": True,
            })

        embed = {
            "embeds": [{
                "title": "HYDRA Predictive Alert",
                "color": 0xFFAA00,
                "fields": fields,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": "HookProbe HYDRA Predictor"}
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
# EXPIRE OLD ALERTS
# ============================================================================

def expire_old_alerts() -> int:
    """Mark old predictive alerts as expired."""
    query = f"""
        ALTER TABLE {CH_DB}.predictive_alerts
        UPDATE status = 'expired', resolved_at = now64(3)
        WHERE status = 'open'
          AND created_at < now() - INTERVAL 2 HOUR
    """
    # ALTER TABLE UPDATE is async in ClickHouse
    ch_ddl(query)
    return 0  # Can't easily get count from async mutation


# ============================================================================
# MAIN LOOP
# ============================================================================

def main():
    logger.info("HYDRA Predictor Engine starting...")
    logger.info(f"ClickHouse: {CH_HOST}:{CH_PORT}/{CH_DB}")
    logger.info(f"Prediction interval: {PREDICT_INTERVAL}s")
    logger.info(f"Pattern mining every: {PATTERN_MINE_EVERY} cycles")
    logger.info(f"Auto-labeling every: {AUTO_LABEL_EVERY} cycles")

    if not CH_PASSWORD:
        logger.error("CLICKHOUSE_PASSWORD not set")
        sys.exit(1)

    # Initialize tables
    ensure_tables()
    logger.info("Tables verified")

    # Initialize Risk Velocity + Flash-RAG engine
    try:
        from risk_velocity import RiskVelocityEngine
        risk_engine = RiskVelocityEngine()
        logger.info("Risk Velocity engine initialized (Flash-RAG enabled)")
    except ImportError:
        logger.warning("risk_velocity module not available, creating stub")
        class _StubEngine:
            def compute_velocities(self): return []
            def flash_rag_lookback(self, _): return []
        risk_engine = _StubEngine()

    # Initialize Cognitive Defense Loop (Autonomous Organism)
    try:
        from cognitive_defense import CognitiveDefenseLoop
        cognitive = CognitiveDefenseLoop()
        logger.info("Cognitive Defense Loop initialized (Reflex + Reasoning + Neuroplasticity)")
    except ImportError:
        logger.warning("cognitive_defense module not available, creating stub")
        class _StubCognitive:
            def process_cycle(self, *a): return []
            def get_stats(self): return {}
        cognitive = _StubCognitive()

    cycle_count = 0

    # Initial pattern mining
    try:
        t_patterns = mine_temporal_patterns()
        s_patterns = mine_sequential_patterns()
        c_patterns = mine_campaign_signatures()
        logger.info(f"Initial pattern mining: {t_patterns} temporal, "
                     f"{s_patterns} sequential, {c_patterns} campaign")
    except Exception as e:
        logger.error(f"Initial pattern mining failed: {e}", exc_info=True)

    # Initial auto-labeling
    try:
        feed_labels = auto_label_from_threat_feeds()
        rdap_labels = auto_label_from_rdap()
        benign_labels = auto_label_benign_cdn()
        logger.info(f"Initial auto-labeling: {feed_labels} feed, "
                     f"{rdap_labels} RDAP, {benign_labels} benign")
    except Exception as e:
        logger.error(f"Initial auto-labeling failed: {e}", exc_info=True)

    while running:
        # Wait for next cycle
        for _ in range(PREDICT_INTERVAL):
            if not running:
                break
            time.sleep(1)

        if not running:
            break

        cycle_count += 1

        try:
            # Phase 2: Prediction (every cycle)
            escalations = predict_escalations()
            campaigns = predict_campaign_formation()

            alerts_written = write_predictive_alerts(escalations, campaigns)
            expire_old_alerts()

            if escalations or campaigns:
                send_discord_prediction(escalations, campaigns)

            # Phase 1: Pattern mining (periodic)
            patterns_total = 0
            if cycle_count % PATTERN_MINE_EVERY == 0:
                patterns_total += mine_temporal_patterns()
                patterns_total += mine_sequential_patterns()
                patterns_total += mine_campaign_signatures()

            # Phase 3: Auto-labeling (periodic)
            labels_total = 0
            if cycle_count % AUTO_LABEL_EVERY == 0:
                labels_total += auto_label_from_threat_feeds()
                labels_total += auto_label_from_rdap()
                labels_total += auto_label_benign_cdn()

            # Phase 4: Risk Velocity + Flash-RAG (every cycle)
            velocity_count = 0
            rag_count = 0
            cognitive_actions = 0
            try:
                velocity_results = risk_engine.compute_velocities()
                velocity_count = len(velocity_results)

                # Gap 3 fix: persist velocity scores to ip_risk_scores.
                # compute_velocities() computes and returns results but
                # _write_risk_scores() was NEVER called — the table was
                # stale since April 6 because velocities were computed,
                # passed to CognitiveDefense, but never written to CH.
                if velocity_results:
                    from datetime import datetime, timezone
                    now_ts = datetime.now(timezone.utc).strftime(
                        '%Y-%m-%d %H:%M:%S.%f')[:-3]
                    risk_engine._write_risk_scores(velocity_results, now_ts)

                rag_contexts = risk_engine.flash_rag_lookback(velocity_results)
                rag_count = len(rag_contexts)

                # Phase 5: Cognitive Defense Loop (Autonomous Organism)
                actions = cognitive.process_cycle(velocity_results, rag_contexts)
                cognitive_actions = len(actions)

            except Exception as e:
                logger.error(f"Risk velocity/Cognitive error: {e}")

            logger.info(
                f"Cycle {cycle_count}: "
                f"{len(escalations)} escalations, {len(campaigns)} campaigns, "
                f"{alerts_written} alerts written"
                + (f", {patterns_total} patterns mined" if patterns_total else "")
                + (f", {labels_total} auto-labels" if labels_total else "")
                + (f", {velocity_count} velocities, {rag_count} RAG, {cognitive_actions} actions" if velocity_count else "")
            )

        except Exception as e:
            logger.error(f"Prediction cycle error: {e}", exc_info=True)

    logger.info("HYDRA Predictor Engine shutting down")


if __name__ == '__main__':
    main()
