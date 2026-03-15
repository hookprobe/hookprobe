#!/usr/bin/env python3
"""
HookProbe HYDRA Risk Velocity Engine
======================================

Computes per-IP Risk Velocity (ΔRisk/Δt) using OLS regression over
the last N scoring windows. When velocity exceeds threshold, triggers
Flash-RAG lookback against ClickHouse vector similarity index.

This is the "Recursive Inference Loop" — the system that lets the
Neural-Kernel predict attacks before they happen.

Architecture:
    hydra_verdicts (scores over time)
        ↓ OLS regression
    risk_velocity (β₁ = slope of risk curve)
        ↓ threshold check
    Flash-RAG query (ClickHouse VectorSimilarity)
        ↓ top-5 historical parallels
    LLM prompt context (for Tier 3 SOC analyst reasoning)
        ↓ action recommendation
    XDP map update (blocklist/allowlist write-back)

Meta-Regression Formula:
    y = β₀ + β₁·t + ε
    where y = anomaly_score, t = time (seconds since window start)
    β₁ > 0 means risk is INCREASING (attack escalating)
    β₁ < 0 means risk is DECREASING (attack subsiding)

Usage:
    from risk_velocity import RiskVelocityEngine
    engine = RiskVelocityEngine()
    results = engine.compute_velocities()
    rag_contexts = engine.flash_rag_lookback(results)
"""

import os
import json
import math
import re
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

# IPv4 validation regex (prevents SQL injection in ClickHouse queries)
_IPV4_RE = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$')


def _safe_ip(ip: str) -> str:
    """Validate and return IPv4 address. Raises ValueError if invalid.

    Prevents SQL injection via IPv4StringToNum('{ip}') patterns.
    """
    if not ip or not _IPV4_RE.match(ip):
        raise ValueError(f"Invalid IPv4 address: {ip!r}")
    return ip


CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# Risk velocity thresholds
VELOCITY_SUSPICIOUS = float(os.environ.get('VELOCITY_SUSPICIOUS', '0.05'))  # per minute
VELOCITY_CRITICAL = float(os.environ.get('VELOCITY_CRITICAL', '0.15'))       # per minute
VELOCITY_RAG_TRIGGER = float(os.environ.get('VELOCITY_RAG_TRIGGER', '0.10'))

# OLS regression window
OLS_WINDOWS = int(os.environ.get('OLS_WINDOWS', '12'))  # Last 12 windows (1 hour at 5-min)
OLS_MIN_POINTS = 4  # Minimum data points for regression (3 has no statistical power)

# Flash-RAG settings
RAG_TOP_K = int(os.environ.get('RAG_TOP_K', '5'))

# Behavioral token codebook (mirrors Mojo SemanticTokenizer)
FLOW_NAMES = ['BULK_TRANSFER', 'INTERACTIVE', 'SCAN_SWEEP', 'DRIP_FEED',
              'BURST', 'TRICKLE', 'FLOOD', 'MIXED']
ENTROPY_NAMES = ['LOW_ENTROPY', 'MEDIUM_ENTROPY', 'HIGH_ENTROPY', 'RANDOM_ENTROPY']
TIMING_NAMES = ['REGULAR_TIMING', 'BURSTY', 'SLOW_AND_LOW', 'HIGH_JITTER', 'PERIODIC', 'CHAOTIC']
PROTO_NAMES = ['HTTP_NORMAL', 'DNS_TUNNEL', 'TLS_DOWNGRADE', 'SSH_BRUTE', 'QUIC_FLOOD', 'MIXED_PROTO']
REP_NAMES = ['KNOWN_GOOD', 'NEUTRAL', 'SUSPICIOUS', 'TOR_EXIT', 'VPN_PROXY', 'KNOWN_BAD']
TREND_NAMES = ['STABLE', 'ACCELERATING', 'DECELERATING', 'SPIKE', 'OSCILLATING']


# ============================================================================
# CLICKHOUSE CLIENT
# ============================================================================

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
        with urlopen(req, timeout=30) as resp:
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
    except Exception as e:
        logger.error(f"ClickHouse insert error: {e}")
        return False


def parse_rows(result: Optional[str]) -> List[dict]:
    """Parse JSONEachRow result."""
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
# OLS REGRESSION (Pure Python — no numpy dependency)
# ============================================================================

def ols_slope(times: List[float], scores: List[float]) -> Tuple[float, float, float]:
    """Ordinary Least Squares regression: y = β₀ + β₁·t

    Returns (β₀, β₁, r²) where:
        β₁ = Σ(t - t̄)(s - s̄) / Σ(t - t̄)²
        β₀ = s̄ - β₁·t̄
        r² = coefficient of determination

    Uses numerically stable computation (centered values).
    """
    n = len(times)
    if n < OLS_MIN_POINTS:
        return 0.0, 0.0, 0.0

    # Center the data for numerical stability
    t_mean = sum(times) / n
    s_mean = sum(scores) / n

    # Compute β₁ (slope)
    numerator = sum((t - t_mean) * (s - s_mean) for t, s in zip(times, scores))
    denominator = sum((t - t_mean) ** 2 for t in times)

    if denominator < 1e-10:
        return s_mean, 0.0, 0.0

    beta_1 = numerator / denominator
    beta_0 = s_mean - beta_1 * t_mean

    # Compute R² (goodness of fit)
    ss_res = sum((s - (beta_0 + beta_1 * t)) ** 2 for t, s in zip(times, scores))
    ss_tot = sum((s - s_mean) ** 2 for s in scores)
    r_squared = 1.0 - (ss_res / ss_tot) if ss_tot > 1e-10 else 0.0

    return beta_0, beta_1, max(0.0, r_squared)


# ============================================================================
# BEHAVIORAL TOKENIZER (Python fallback for Mojo)
# ============================================================================

def tokenize_features(features: List[float], reputation: int = 1,
                      risk_velocity: float = 0.0) -> dict:
    """Python implementation of Mojo SemanticTokenizer.

    Mirrors the Mojo tokenizer for environments where Mojo isn't available.
    Returns dict with token names and composite ID.
    """
    if len(features) < 24:
        features = features + [0.0] * (24 - len(features))

    # Feature positions (from feature_extractor.py 24-dim layout)
    pps = features[0]
    bps = features[1]
    unique_ports = features[2]
    unique_ips = features[3]
    syn_ratio = features[4]
    avg_pkt_size = features[7] if len(features) > 7 else 0
    iat_entropy = features[10] if len(features) > 10 else 0
    port_diversity = features[14] if len(features) > 14 else 0
    protocol_mix = features[15] if len(features) > 15 else 0
    dns_ratio = features[16] if len(features) > 16 else 0
    threat_ratio = features[19] if len(features) > 19 else 0

    # Flow shape
    if pps > 5000:
        flow = 6 if syn_ratio > 0.8 else 4  # FLOOD or BURST
    elif pps > 1000:
        flow = 2 if unique_ports > 20 else 0  # SCAN or BULK
    elif pps < 10:
        flow = 3 if bps > 0 else 1  # DRIP or INTERACTIVE
    elif bps > 100000 and pps < 100:
        flow = 5  # TRICKLE (steady upload)
    else:
        flow = 7  # MIXED

    # Entropy band
    if iat_entropy > 3.5:
        entropy = 3  # RANDOM
    elif iat_entropy > 2.5:
        entropy = 2  # HIGH
    elif iat_entropy > 1.0:
        entropy = 1  # MEDIUM
    else:
        entropy = 0  # LOW

    # Timing pattern
    if iat_entropy < 0.5:
        timing = 0  # REGULAR
    elif pps < 1 and bps < 100:
        timing = 2  # SLOW_AND_LOW
    elif iat_entropy > 3.0:
        timing = 5  # CHAOTIC
    elif iat_entropy > 2.0:
        timing = 3  # HIGH_JITTER
    else:
        timing = 1  # BURSTY

    # Protocol behavior
    if dns_ratio > 0.5 and pps > 100:
        proto = 1  # DNS_TUNNEL
    elif syn_ratio > 0.5 and unique_ports < 5:
        proto = 3  # SSH_BRUTE
    elif protocol_mix > 1.5:
        proto = 5  # MIXED_PROTO
    else:
        proto = 0  # HTTP_NORMAL

    # Temporal trend
    if risk_velocity > 0.2:
        trend = 3  # SPIKE
    elif risk_velocity > 0.1:
        trend = 1  # ACCELERATING
    elif risk_velocity < -0.1:
        trend = 2  # DECELERATING
    elif abs(risk_velocity) > 0.05:
        trend = 4  # OSCILLATING
    else:
        trend = 0  # STABLE

    # Composite token (17-bit layout, stored as uint32)
    # Matches Mojo to_composite(): flow<<14 | entropy<<12 | timing<<9 | proto<<6 | rep<<3 | trend
    reputation = min(reputation, 5)  # Clamp to valid range
    composite = ((flow & 0x07) << 14) | ((entropy & 0x03) << 12) | \
                ((timing & 0x07) << 9) | ((proto & 0x07) << 6) | \
                ((reputation & 0x07) << 3) | (trend & 0x07)

    narrative = (f"[{FLOW_NAMES[flow]} | {ENTROPY_NAMES[entropy]} | "
                 f"{TIMING_NAMES[timing]} | {PROTO_NAMES[proto]} | "
                 f"{REP_NAMES[reputation]} | {TREND_NAMES[trend]}]")

    return {
        'flow_shape': flow,
        'entropy_band': entropy,
        'timing_pattern': timing,
        'protocol_behavior': proto,
        'reputation_class': reputation,
        'temporal_trend': trend,
        'composite_token': composite,
        'narrative': narrative,
    }


# ============================================================================
# RISK VELOCITY ENGINE
# ============================================================================

class RiskVelocityEngine:
    """Computes per-IP Risk Velocity and triggers Flash-RAG lookback.

    The Recursive Inference Loop:
    1. Load anomaly scores from last N windows
    2. OLS regression → β₁ (risk slope per minute)
    3. If β₁ > threshold → trigger Flash-RAG
    4. Flash-RAG finds top-5 similar historical IPs
    5. Generate LLM prompt context
    6. Write results to ip_risk_scores + rag_contexts
    """

    def __init__(self):
        self.total_computed = 0
        self.total_rag_triggered = 0

    def compute_velocities(self) -> List[dict]:
        """Compute risk velocity for all IPs with recent verdicts.

        Returns list of {ip, beta_0, beta_1, r_squared, risk_velocity,
                         latest_score, trend, rag_triggered}
        """
        # Get IPs with recent anomaly scores (last N windows)
        window_seconds = OLS_WINDOWS * 300  # 5-min windows
        query = f"""
            SELECT
                IPv4NumToString(src_ip) AS ip,
                arraySort(x -> x.1, arrayZip(
                    groupArray(toUnixTimestamp(timestamp)),
                    groupArray(anomaly_score)
                )).2 AS scores,
                arraySort(groupArray(toUnixTimestamp(timestamp))) AS timestamps
            FROM {CH_DB}.hydra_verdicts
            WHERE timestamp >= now() - INTERVAL {window_seconds} SECOND
              AND verdict != ''
            GROUP BY src_ip
            HAVING length(scores) >= {OLS_MIN_POINTS}
            ORDER BY length(scores) DESC
            LIMIT 500
        """
        rows = parse_rows(ch_query(query))
        if not rows:
            return []

        results = []
        now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        for row in rows:
            ip = row.get('ip', '')
            if not ip:
                continue

            scores = [float(s) for s in row.get('scores', [])]
            timestamps = [float(t) for t in row.get('timestamps', [])]

            if len(scores) < OLS_MIN_POINTS:
                continue

            # Normalize timestamps to minutes from first observation
            t_min = min(timestamps)
            times_min = [(t - t_min) / 60.0 for t in timestamps]

            # OLS regression: score = β₀ + β₁·time_minutes
            beta_0, beta_1, r_squared = ols_slope(times_min, scores)

            # Risk velocity = β₁ (score change per minute)
            risk_velocity = beta_1

            # Determine trend
            if risk_velocity > VELOCITY_CRITICAL:
                trend = 'critical_acceleration'
            elif risk_velocity > VELOCITY_SUSPICIOUS:
                trend = 'accelerating'
            elif risk_velocity < -VELOCITY_SUSPICIOUS:
                trend = 'decelerating'
            else:
                trend = 'stable'

            # Should we trigger RAG lookback?
            rag_triggered = abs(risk_velocity) > VELOCITY_RAG_TRIGGER

            result = {
                'ip': ip,
                'beta_0': round(beta_0, 6),
                'beta_1': round(beta_1, 6),
                'r_squared': round(r_squared, 4),
                'risk_velocity': round(risk_velocity, 6),
                'latest_score': scores[-1] if scores else 0,
                'trend': trend,
                'rag_triggered': rag_triggered,
                'n_windows': len(scores),
            }
            results.append(result)

            self.total_computed += 1
            if rag_triggered:
                self.total_rag_triggered += 1

        # Write risk scores to ClickHouse
        self._write_risk_scores(results, now_ts)

        logger.info(f"Risk Velocity: {len(results)} IPs computed, "
                    f"{sum(1 for r in results if r['rag_triggered'])} RAG triggered")

        return results

    def _write_risk_scores(self, results: List[dict], now_ts: str) -> int:
        """Write risk velocity scores to ip_risk_scores table."""
        if not results:
            return 0

        rows = []
        for r in results:
            trend_code = {
                'stable': 0, 'accelerating': 1, 'decelerating': 2,
                'critical_acceleration': 3
            }.get(r['trend'], 0)

            rows.append(
                f"('{now_ts}', IPv4StringToNum('{_safe_ip(r['ip'])}'), "
                f"{r['latest_score']:.6f}, 0, {r['latest_score']:.6f}, "
                f"{r['risk_velocity']:.6f}, {r['beta_0']:.6f}, {r['beta_1']:.6f}, "
                f"[], 'unknown', 0, {1 if r['rag_triggered'] else 0})"
            )

        if not rows:
            return 0

        query = (
            f"INSERT INTO {CH_DB}.ip_risk_scores "
            "(timestamp, src_ip, anomaly_score, sentinel_score, composite_risk, "
            "risk_velocity, beta_0, beta_1, token_sequence, kill_chain_state, "
            "kill_chain_confidence, rag_triggered)"
        )

        written = 0
        for i in range(0, len(rows), 100):
            batch = rows[i:i + 100]
            if ch_insert(query, ', '.join(batch)):
                written += len(batch)

        return written

    def flash_rag_lookback(self, velocity_results: List[dict]) -> List[dict]:
        """Execute Flash-RAG queries for IPs with high risk velocity.

        Uses ClickHouse VectorSimilarity index (if available) or
        falls back to cosine distance computation.

        Returns list of RAG contexts ready for LLM prompt injection.
        """
        rag_ips = [r for r in velocity_results if r['rag_triggered']]
        if not rag_ips:
            return []

        contexts = []
        now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        for r in rag_ips:
            ip = r['ip']

            # Get current feature vector for this IP
            feat_query = f"""
                SELECT feature_vector
                FROM {CH_DB}.hydra_ip_features
                WHERE src_ip = IPv4StringToNum('{_safe_ip(ip)}')
                ORDER BY timestamp DESC
                LIMIT 1
            """
            feat_rows = parse_rows(ch_query(feat_query))
            if not feat_rows or not feat_rows[0].get('feature_vector'):
                continue

            current_features = feat_rows[0]['feature_vector']
            if not isinstance(current_features, list) or len(current_features) < 24:
                continue

            # Flash-RAG: Find top-K similar historical feature vectors
            # Uses cosineDistance (VectorSimilarity index accelerates this)
            vec_str = '[' + ','.join(f'{float(v):.6f}' for v in current_features) + ']'
            rag_query = f"""
                SELECT
                    IPv4NumToString(src_ip) AS similar_ip,
                    cosineDistance(feature_vector, {vec_str}) AS distance,
                    timestamp AS seen_at
                FROM {CH_DB}.hydra_ip_features
                WHERE timestamp >= now() - INTERVAL 30 DAY
                  AND src_ip != IPv4StringToNum('{_safe_ip(ip)}')
                  AND length(feature_vector) = {len(current_features)}
                ORDER BY distance ASC
                LIMIT {RAG_TOP_K}
            """
            similar_rows = parse_rows(ch_query(rag_query))

            if not similar_rows:
                continue

            # Get verdicts for similar IPs
            similar_ips = [row['similar_ip'] for row in similar_rows]
            similar_scores = [1.0 - float(row.get('distance', 1.0)) for row in similar_rows]

            ip_list = ', '.join(f"IPv4StringToNum('{_safe_ip(sip)}')" for sip in similar_ips)
            verdict_query = f"""
                SELECT
                    IPv4NumToString(src_ip) AS ip,
                    argMax(verdict, timestamp) AS latest_verdict,
                    argMax(action_taken, timestamp) AS latest_action
                FROM {CH_DB}.hydra_verdicts
                WHERE src_ip IN ({ip_list})
                  AND timestamp >= now() - INTERVAL 30 DAY
                GROUP BY src_ip
            """
            verdict_rows = parse_rows(ch_query(verdict_query))
            verdict_map = {row['ip']: row for row in verdict_rows}

            # Build LLM prompt context
            similar_verdicts = []
            context_lines = []
            for sip, score in zip(similar_ips, similar_scores):
                v = verdict_map.get(sip, {})
                verdict = v.get('latest_verdict', 'unknown')
                action = v.get('latest_action', 'none')
                similar_verdicts.append(verdict)
                context_lines.append(
                    f"  - {sip}: similarity={score:.2%}, verdict={verdict}, action={action}"
                )

            # Generate behavioral token for current IP
            token = tokenize_features(current_features, reputation=2,
                                      risk_velocity=r['risk_velocity'])

            prompt_context = (
                f"ALERT: IP {ip} has risk velocity β₁={r['risk_velocity']:.4f}/min "
                f"(trend: {r['trend']}, R²={r['r_squared']:.3f})\n"
                f"Current behavior: {token['narrative']}\n"
                f"Latest anomaly score: {r['latest_score']:.3f}\n"
                f"\nHistorical parallels (top-{len(similar_ips)} by cosine similarity):\n"
                + '\n'.join(context_lines)
                + f"\n\nHistorical outcomes: "
                + ', '.join(f"{v}({similar_verdicts.count(v)})" for v in set(similar_verdicts))
            )

            # Determine trigger type
            if r['risk_velocity'] > VELOCITY_CRITICAL:
                trigger_type = 'risk_velocity_critical'
            else:
                trigger_type = 'risk_velocity'

            context = {
                'ip': ip,
                'trigger_type': trigger_type,
                'risk_velocity': r['risk_velocity'],
                'similar_ips': similar_ips,
                'similar_scores': similar_scores,
                'similar_verdicts': similar_verdicts,
                'prompt_context': prompt_context,
                'token': token,
            }
            contexts.append(context)

            # Write RAG context to ClickHouse
            self._write_rag_context(context, now_ts)

        logger.info(f"Flash-RAG: {len(contexts)} lookbacks completed")
        return contexts

    def _write_rag_context(self, ctx: dict, now_ts: str) -> bool:
        """Write a RAG context to ClickHouse for LLM consumption."""
        ip = ctx['ip']

        def _ch_escape(s: str) -> str:
            """Escape string for safe ClickHouse SQL VALUES."""
            return str(s).replace('\\', '\\\\').replace("'", "\\'")

        # Validate IPs before interpolation (HIGH-4 fix)
        safe_similar = []
        for sip in ctx.get('similar_ips', []):
            try:
                safe_similar.append(_safe_ip(sip))
            except ValueError:
                continue

        similar_ips_arr = "[" + ",".join(f"'{s}'" for s in safe_similar) + "]"
        similar_scores_arr = "[" + ",".join(f"{float(s):.6f}" for s in ctx.get('similar_scores', [])) + "]"

        # Escape verdicts (prevent SQL injection via verdict strings)
        similar_verdicts_arr = "[" + ",".join(
            f"'{_ch_escape(v)}'" for v in ctx.get('similar_verdicts', [])
        ) + "]"

        prompt = _ch_escape(ctx.get('prompt_context', ''))
        trigger = _ch_escape(ctx.get('trigger_type', 'risk_velocity'))

        query = (
            f"INSERT INTO {CH_DB}.rag_contexts "
            "(timestamp, src_ip, trigger_type, risk_velocity, "
            "similar_ips, similar_scores, similar_verdicts, prompt_context)"
        )
        data = (
            f"('{now_ts}', IPv4StringToNum('{_safe_ip(ip)}'), '{trigger}', "
            f"{float(ctx.get('risk_velocity', 0)):.6f}, {similar_ips_arr}, {similar_scores_arr}, "
            f"{similar_verdicts_arr}, '{prompt}')"
        )

        return ch_insert(query, data)
