#!/usr/bin/env python3
"""
HookProbe HYDRA Feature Extractor
===================================

Extracts 24-feature vectors per IP per 5-minute window for ML anomaly detection.

Features are grouped into 4 categories:
  - Network (8): pps, bps, unique_dst_ports, unique_dst_ips, syn_ratio, rst_ratio, etc.
  - Temporal (6): iat_mean, iat_stddev, iat_entropy, burst_count, etc.
  - Behavioral (7): port_diversity, protocol_mix, payload_entropy_mean, etc.
  - Reputation (3): ip_score, total_events, escalation_level

Data sources:
  - ClickHouse: napse_intents (preferred) or napse_flows (fallback), hydra_events
  - BPF maps: iat_map (read via bpf_map_ops if available)
  - PostgreSQL: ip_reputation table

Output:
  - ClickHouse: hydra_ip_features table

Usage:
    python3 feature_extractor.py [--interval 300] [--window 300]
"""

import os
import sys
import time
import json
import math
import signal
import logging
import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.parse import urlencode

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [FEATURES] %(levelname)s: %(message)s'
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

# Extraction interval (seconds) — how often to run extraction
EXTRACT_INTERVAL = int(os.environ.get('EXTRACT_INTERVAL', '300'))  # 5 minutes

# Feature window (seconds) — how far back to look for each extraction
FEATURE_WINDOW = int(os.environ.get('FEATURE_WINDOW', '300'))  # 5 minutes

# Minimum packets for an IP to be considered for feature extraction
MIN_PACKETS = int(os.environ.get('MIN_PACKETS', '10'))

# IAT histogram bucket count (must match xdp_hydra.c)
IAT_BUCKETS = 16

# IAT bucket boundaries in nanoseconds (log10 scale)
IAT_BOUNDARIES_NS = [
    1000, 3162, 10000, 100000, 316228, 1000000,
    3162278, 10000000, 31622776, 100000000,
    316227766, 1000000000, 3162277660, 10000000000,
    31622776602
]

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
    """Execute a ClickHouse query via HTTP API with auth in headers (not URL)."""
    if not CH_PASSWORD:
        return None

    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        params = urlencode({
            'query': query + (f" FORMAT {fmt}" if fmt else ""),
        })
        full_url = f"{url}?{params}"

        req = Request(full_url)
        # Auth via headers instead of URL params (avoids password in logs)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        with urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8')

    except Exception as e:
        logger.error(f"ClickHouse query error: {e}")
        return None


def ch_insert(query: str, data: str = '') -> bool:
    """Execute a ClickHouse INSERT with auth in headers (not URL).

    Splits INSERT ... VALUES ... so the VALUES data goes in the POST body.
    """
    if not CH_PASSWORD:
        return False

    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"

        # Split at VALUES boundary: header in URL param, data in POST body
        if ' VALUES ' in query and not data:
            parts = query.split(' VALUES ', 1)
            url_query = parts[0] + ' VALUES'
            body = parts[1]
        else:
            url_query = query
            body = data

        params = urlencode({'query': url_query})
        full_url = f"{url}?{params}"

        req = Request(full_url)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        if body:
            req.data = body.encode('utf-8')
            req.add_header('Content-Type', 'text/plain')
        else:
            req.data = b''  # Force POST (GET is readonly in ClickHouse)

        with urlopen(req, timeout=30) as resp:
            resp.read()
        return True

    except Exception as e:
        logger.error(f"ClickHouse insert error: {e}")
        return False


# ============================================================================
# FEATURE EXTRACTION — NETWORK FEATURES (8)
# ============================================================================

def extract_network_features(window_seconds: int) -> Dict[str, dict]:
    """
    Extract network features from napse_intents (packet-level), falling back
    to napse_flows (flow-level summaries) when napse_intents is unavailable.

    Per IP: pps, bps, unique_dst_ports, unique_dst_ips, syn_ratio,
            rst_ratio, avg_pkt_size, small_pkt_ratio
    """
    # Try packet-level table first (has TCP flags for syn/rst ratios)
    features = _extract_from_napse_intents(window_seconds)
    if features:
        return features

    # Fallback to flow-level table (no TCP flags, but has flow summaries)
    logger.debug("napse_intents empty/unavailable, falling back to napse_flows")
    return _extract_from_napse_flows(window_seconds)


def _extract_from_napse_intents(window_seconds: int) -> Dict[str, dict]:
    """Extract features from aegis_observations (packet-level data with TCP flags)."""
    query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            count() AS total_packets,
            sum(payload_len) AS total_bytes,
            uniq(dst_port) AS unique_dst_ports,
            uniq(dst_ip) AS unique_dst_ips,
            countIf(tcp_flags = 2) AS syn_count,
            countIf(tcp_flags = 4) AS rst_count,
            avg(payload_len) AS avg_pkt_size,
            countIf(payload_len < 100) AS small_pkts
        FROM {CH_DB}.aegis_observations
        WHERE timestamp >= now() - INTERVAL {window_seconds} SECOND
        GROUP BY src_ip
        HAVING total_packets >= {MIN_PACKETS}
    """

    result = ch_query(query)
    if not result:
        return {}

    features = {}
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            total = float(row['total_packets'])
            features[ip] = {
                'pps': total / window_seconds,
                'bps': float(row['total_bytes']) * 8 / window_seconds,
                'unique_dst_ports': int(row['unique_dst_ports']),
                'unique_dst_ips': int(row['unique_dst_ips']),
                'syn_ratio': float(row['syn_count']) / total if total > 0 else 0,
                'rst_ratio': float(row['rst_count']) / total if total > 0 else 0,
                'avg_pkt_size': float(row['avg_pkt_size']),
                'small_pkt_ratio': float(row['small_pkts']) / total if total > 0 else 0,
            }
        except (json.JSONDecodeError, KeyError, ZeroDivisionError):
            continue

    return features


def _extract_from_napse_flows(window_seconds: int) -> Dict[str, dict]:
    """Extract features from napse_flows (flow-level summaries from inspector)."""
    query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            count() AS total_flows,
            sum(pkts_orig) AS total_packets,
            sum(bytes_orig) AS total_bytes,
            uniq(dst_port) AS unique_dst_ports,
            uniq(dst_ip) AS unique_dst_ips,
            countIf(proto = 6) AS tcp_flows,
            avg(bytes_orig / greatest(pkts_orig, 1)) AS avg_pkt_size,
            countIf(bytes_orig < 200) AS small_flows
        FROM {CH_DB}.napse_flows
        WHERE timestamp >= now() - INTERVAL {window_seconds} SECOND
        GROUP BY src_ip
        HAVING total_packets >= {MIN_PACKETS}
    """

    result = ch_query(query)
    if not result:
        return {}

    features = {}
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            total_pkts = float(row['total_packets'])
            total_flows = float(row['total_flows'])
            features[ip] = {
                'pps': total_pkts / window_seconds,
                'bps': float(row['total_bytes']) * 8 / window_seconds,
                'unique_dst_ports': int(row['unique_dst_ports']),
                'unique_dst_ips': int(row['unique_dst_ips']),
                'syn_ratio': 0.0,  # Not available at flow level
                'rst_ratio': 0.0,  # Not available at flow level
                'avg_pkt_size': float(row['avg_pkt_size']),
                'small_pkt_ratio': float(row['small_flows']) / total_flows if total_flows > 0 else 0,
            }
        except (json.JSONDecodeError, KeyError, ZeroDivisionError):
            continue

    return features


# ============================================================================
# FEATURE EXTRACTION — TEMPORAL FEATURES (6)
# ============================================================================

def compute_histogram_entropy(histogram: List[int]) -> float:
    """Compute Shannon entropy of a histogram distribution."""
    total = sum(histogram)
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in histogram:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    return entropy


def compute_histogram_stats(histogram: List[int]) -> dict:
    """
    Compute mean, stddev, entropy from an IAT histogram.

    Uses bin midpoints (geometric mean of boundaries) for estimation.
    """
    total = sum(histogram)
    if total == 0:
        return {'iat_mean': 0, 'iat_stddev': 0, 'iat_entropy': 0,
                'burst_count': 0, 'iat_range_ratio': 0, 'iat_concentration': 0}

    # Bin midpoints in nanoseconds (geometric mean of boundaries)
    midpoints = [500]  # bucket 0: [0, 1us) -> 500ns
    for i in range(len(IAT_BOUNDARIES_NS) - 1):
        midpoints.append(int(math.sqrt(IAT_BOUNDARIES_NS[i] * IAT_BOUNDARIES_NS[i + 1])))
    midpoints.append(100000000000)  # bucket 15: 100s

    # Weighted mean
    mean = sum(midpoints[i] * histogram[i] for i in range(min(IAT_BUCKETS, len(midpoints)))) / total

    # Weighted variance
    variance = sum(histogram[i] * (midpoints[i] - mean) ** 2
                   for i in range(min(IAT_BUCKETS, len(midpoints)))) / total
    stddev = math.sqrt(variance)

    # Shannon entropy
    entropy = compute_histogram_entropy(histogram)

    # Burst count: number of samples in sub-millisecond buckets (0-5)
    burst_count = sum(histogram[:6])

    # Range ratio: max_bucket / min_bucket distance (spread indicator)
    non_zero = [i for i in range(IAT_BUCKETS) if histogram[i] > 0]
    iat_range_ratio = (non_zero[-1] - non_zero[0] + 1) / IAT_BUCKETS if non_zero else 0

    # Concentration: fraction of samples in top 2 buckets
    sorted_hist = sorted(histogram, reverse=True)
    top2 = (sorted_hist[0] + sorted_hist[1]) / total if len(sorted_hist) >= 2 else 1.0

    return {
        'iat_mean': mean / 1e6,  # Convert to milliseconds
        'iat_stddev': stddev / 1e6,
        'iat_entropy': entropy,
        'burst_count': burst_count,
        'iat_range_ratio': iat_range_ratio,
        'iat_concentration': top2,
    }


def extract_temporal_features_from_ch(window_seconds: int) -> Dict[str, dict]:
    """
    Extract temporal features from ClickHouse flow data.
    Fallback when BPF IAT map is not accessible.
    """
    query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            count() AS flow_count,
            min(timestamp) AS first_seen,
            max(timestamp) AS last_seen,
            uniq(toStartOfMinute(timestamp)) AS active_minutes,
            stddevPop(bytes_orig) AS pkt_size_stddev
        FROM {CH_DB}.napse_flows
        WHERE timestamp >= now() - INTERVAL {window_seconds} SECOND
        GROUP BY src_ip
        HAVING flow_count >= {MIN_PACKETS}
    """

    result = ch_query(query)
    if not result:
        return {}

    features = {}
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            flow_count = int(row['flow_count'])

            features[ip] = {
                'iat_mean': 0.0,  # Would come from BPF map
                'iat_stddev': 0.0,
                'iat_entropy': 0.0,
                'burst_count': 0,
                'iat_range_ratio': 0.0,
                'iat_concentration': 0.0,
            }

            # Approximate IAT from flow timing if we have timestamps
            active_min = int(row.get('active_minutes', 1))
            if active_min > 0 and flow_count > 1:
                avg_iat_ms = (window_seconds * 1000.0) / flow_count
                features[ip]['iat_mean'] = avg_iat_ms

        except (json.JSONDecodeError, KeyError):
            continue

    return features


def try_read_bpf_iat_map() -> Dict[str, List[int]]:
    """
    Try to read IAT histograms from XDP BPF map via bpf_map_ops (raw syscalls).
    Returns {ip: [histogram_buckets]} or empty dict on failure.
    """
    try:
        from bpf_map_ops import get_bpf_ops
        import ipaddress

        ops = get_bpf_ops()
        iat_map_id = ops.find_map_by_name('iat_map')
        if iat_map_id is None:
            return {}

        entries = ops.map_dump(iat_map_id)
        histograms = {}

        for key_bytes, val_bytes in entries:
            if len(key_bytes) < 4:
                continue

            ip = str(ipaddress.IPv4Address(key_bytes[:4]))

            # struct iat_state: 5 * u64 + IAT_BUCKETS * u32
            # = 40 + 64 = 104 bytes
            if len(val_bytes) < 40 + IAT_BUCKETS * 4:
                continue

            # Extract histogram (starts at offset 40)
            histogram = list(struct.unpack_from(f'<{IAT_BUCKETS}I', val_bytes, 40))
            if sum(histogram) > 0:
                histograms[ip] = histogram

        return histograms

    except Exception as e:
        logger.debug(f"BPF IAT map read failed: {e}")
        return {}


# ============================================================================
# FEATURE EXTRACTION — BEHAVIORAL FEATURES (7)
# ============================================================================

def extract_behavioral_features(window_seconds: int) -> Dict[str, dict]:
    """
    Extract behavioral features from flow data.

    Per IP: port_diversity, protocol_mix, dns_query_ratio,
            session_duration_avg, unique_services, payload_entropy_approx,
            connection_reuse_ratio
    """
    query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            uniq(dst_port) AS unique_ports,
            count() AS total,
            countIf(proto = 6) AS tcp_count,
            countIf(proto = 17) AS udp_count,
            countIf(proto = 1) AS icmp_count,
            countIf(dst_port = 53) AS dns_count,
            uniq(dst_ip, dst_port) AS unique_services,
            uniq(src_port) AS unique_src_ports,
            countIf(intent_class != '' AND intent_class != 'benign') AS threat_events
        FROM {CH_DB}.napse_flows
        WHERE timestamp >= now() - INTERVAL {window_seconds} SECOND
        GROUP BY src_ip
        HAVING total >= {MIN_PACKETS}
    """

    result = ch_query(query)
    if not result:
        return {}

    features = {}
    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            total = float(row['total'])
            tcp = float(row['tcp_count'])
            udp = float(row['udp_count'])
            icmp = float(row['icmp_count'])

            # Port diversity: unique_ports / log2(total+1) — normalized
            unique_ports = int(row['unique_ports'])
            port_diversity = unique_ports / math.log2(total + 1) if total > 0 else 0

            # Protocol mix entropy
            proto_counts = [tcp, udp, icmp, total - tcp - udp - icmp]
            proto_probs = [c / total for c in proto_counts if c > 0]
            protocol_mix = -sum(p * math.log2(p) for p in proto_probs if p > 0)

            # Connection reuse: total / unique_src_ports
            unique_src = max(int(row['unique_src_ports']), 1)
            conn_reuse = total / unique_src

            features[ip] = {
                'port_diversity': port_diversity,
                'protocol_mix': protocol_mix,
                'dns_query_ratio': float(row['dns_count']) / total if total > 0 else 0,
                'session_duration': window_seconds,  # Approximate
                'unique_services': int(row['unique_services']),
                'threat_ratio': float(row['threat_events']) / total if total > 0 else 0,
                'connection_reuse': conn_reuse,
            }
        except (json.JSONDecodeError, KeyError, ValueError):
            continue

    return features


# ============================================================================
# FEATURE EXTRACTION — REPUTATION FEATURES (3)
# ============================================================================

def extract_reputation_features(ips: List[str]) -> Dict[str, dict]:
    """
    Extract reputation features from ClickHouse/PostgreSQL.
    Falls back to default values if ip_reputation table is not accessible.
    """
    # Query hydra_events for historical block data
    if not ips:
        return {}

    ip_list = ", ".join(f"IPv4StringToNum('{ip}')" for ip in ips[:1000])
    query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            count() AS total_events,
            countIf(action = 'drop') AS block_count,
            uniq(reason) AS unique_reasons
        FROM {CH_DB}.hydra_events
        WHERE src_ip IN ({ip_list})
          AND timestamp >= now() - INTERVAL 7 DAY
        GROUP BY src_ip
    """

    result = ch_query(query)
    rep_data = {}
    if result:
        for line in result.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
                rep_data[row['ip']] = row
            except (json.JSONDecodeError, KeyError):
                continue

    features = {}
    for ip in ips:
        data = rep_data.get(ip, {})
        features[ip] = {
            'ip_reputation_score': 500,  # Default neutral score
            'total_historical_events': int(data.get('total_events', 0)),
            'escalation_level': 0,
        }

    return features


# ============================================================================
# FEATURE VECTOR ASSEMBLY
# ============================================================================

# Feature order (must match hydra_ip_features schema and anomaly_detector)
FEATURE_NAMES = [
    # Network (8)
    'pps', 'bps', 'unique_dst_ports', 'unique_dst_ips',
    'syn_ratio', 'rst_ratio', 'avg_pkt_size', 'small_pkt_ratio',
    # Temporal (6)
    'iat_mean', 'iat_stddev', 'iat_entropy',
    'burst_count', 'iat_range_ratio', 'iat_concentration',
    # Behavioral (7)
    'port_diversity', 'protocol_mix', 'dns_query_ratio',
    'session_duration', 'unique_services', 'threat_ratio', 'connection_reuse',
    # Reputation (3)
    'ip_reputation_score', 'total_historical_events', 'escalation_level',
]

assert len(FEATURE_NAMES) == 24, f"Expected 24 features, got {len(FEATURE_NAMES)}"


def assemble_features(
    network: Dict[str, dict],
    temporal: Dict[str, dict],
    behavioral: Dict[str, dict],
    reputation: Dict[str, dict],
) -> Dict[str, List[float]]:
    """Assemble feature vectors for all IPs."""
    all_ips = set(network.keys()) | set(behavioral.keys())
    vectors = {}

    for ip in all_ips:
        net = network.get(ip, {})
        temp = temporal.get(ip, {})
        behav = behavioral.get(ip, {})
        rep = reputation.get(ip, {})

        vector = []
        for fname in FEATURE_NAMES:
            # Use explicit 'in' check — Python 'or' treats 0.0 as falsy,
            # which corrupts feature vectors for benign quiet IPs
            val = 0.0
            for src in (net, temp, behav, rep):
                if fname in src:
                    val = src[fname]
                    break
            vector.append(float(val))

        vectors[ip] = vector

    return vectors


# ============================================================================
# CLICKHOUSE OUTPUT
# ============================================================================

def write_features_to_clickhouse(vectors: Dict[str, List[float]]) -> int:
    """Write feature vectors to hydra_ip_features table."""
    if not vectors:
        return 0

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    rows = []

    for ip, vector in vectors.items():
        # Build individual feature columns
        vals = {FEATURE_NAMES[i]: vector[i] for i in range(len(FEATURE_NAMES))}

        # Array representation for ML consumption
        vec_str = "[" + ",".join(f"{v:.6f}" for v in vector) + "]"

        row = (
            f"('{now}', "
            f"IPv4StringToNum('{ip}'), "
            f"{vals.get('pps', 0):.4f}, "
            f"{vals.get('bps', 0):.4f}, "
            f"{vals.get('unique_dst_ports', 0):.0f}, "
            f"{vals.get('unique_dst_ips', 0):.0f}, "
            f"{vals.get('syn_ratio', 0):.6f}, "
            f"{vals.get('avg_pkt_size', 0):.2f}, "
            f"{vals.get('port_diversity', 0):.4f}, "
            f"{vals.get('protocol_mix', 0):.4f}, "
            f"{vals.get('iat_mean', 0):.4f}, "
            f"{vals.get('iat_entropy', 0):.4f}, "
            f"{vals.get('burst_count', 0):.0f}, "
            f"{vec_str})"
        )
        rows.append(row)

    if not rows:
        return 0

    query = (
        f"INSERT INTO {CH_DB}.hydra_ip_features "
        "(timestamp, src_ip, pps, bps, unique_dst_ports, unique_dst_ips, "
        "syn_ratio, avg_pkt_size, port_diversity, protocol_mix, "
        "iat_mean, iat_entropy, burst_count, feature_vector) VALUES "
        + ", ".join(rows)
    )

    if ch_insert(query):
        return len(rows)
    return 0


# ============================================================================
# MAIN LOOP
# ============================================================================

def extract_verdict_features(window_seconds: int) -> Dict[str, dict]:
    """
    Extract minimal feature vectors for IPs that have SENTINEL verdicts
    but no sustained flows (e.g., short-burst scanners, SYN probes).
    This fills the gap where flow-driven extraction misses ephemeral connections.
    """
    # Find IPs with recent verdicts that DON'T have recent feature vectors.
    # Fixed: LEFT ANTI JOIN causes HTTP 400 on some ClickHouse versions
    # when sent via URL-encoded HTTP query. Use NOT IN subquery instead.
    query = (
        f"SELECT IPv4NumToString(src_ip) AS ip, "
        f"count() AS verdict_count, "
        f"avg(anomaly_score) AS avg_score, "
        f"countIf(verdict = 'malicious') AS malicious_count, "
        f"countIf(verdict = 'suspicious') AS suspicious_count, "
        f"countIf(verdict = 'benign') AS benign_count, "
        f"uniq(action_taken) AS unique_actions, "
        f"max(anomaly_score) AS max_score "
        f"FROM {CH_DB}.hydra_verdicts "
        f"WHERE timestamp >= now() - INTERVAL {window_seconds} SECOND "
        f"AND src_ip NOT IN ("
        f"  SELECT DISTINCT src_ip FROM {CH_DB}.hydra_ip_features "
        f"  WHERE timestamp >= now() - INTERVAL {window_seconds} SECOND"
        f") "
        f"GROUP BY src_ip "
        f"ORDER BY verdict_count DESC LIMIT 50"
    )

    result = ch_query(query)
    features = {}
    if not result:
        return features

    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            vc = float(row.get('verdict_count', 0))
            avg_s = float(row.get('avg_score', 0))
            mal = float(row.get('malicious_count', 0))
            sus = float(row.get('suspicious_count', 0))
            ben = float(row.get('benign_count', 0))

            # Build synthetic network features from verdict metadata
            features[ip] = {
                'pps': min(vc / max(window_seconds, 1), 100),  # verdicts as proxy
                'bps': 0.0,
                'unique_dst_ports': 1.0,
                'unique_dst_ips': 1.0,
                'syn_ratio': 0.8 if mal > ben else 0.2,
                'rst_ratio': 0.0,
                'avg_pkt_size': 64.0,  # assume small probe packets
                'small_pkt_ratio': 0.9,
                # Temporal (sparse)
                'iat_mean': 0.1,
                'iat_stddev': 0.05,
                'iat_entropy': 0.5,
                'burst_count': max(1, int(vc / 10)),
                'iat_range_ratio': 0.5,
                'iat_concentration': 0.5,
                # Behavioral
                'port_diversity': 0.3,
                'protocol_mix': 0.2,
                'dns_query_ratio': 0.0,
                'session_duration': 1.0,
                'unique_services': 1.0,
                'threat_ratio': mal / max(vc, 1),
                'connection_reuse': 0.1,
                # Reputation
                'ip_reputation_score': 100 if mal > sus + ben else 500,
                'total_historical_events': int(vc),
                'escalation_level': 2 if mal > 0 else 0,
            }
        except (json.JSONDecodeError, KeyError, ValueError):
            continue

    return features


def extract_cycle():
    """Run one feature extraction cycle."""
    logger.info(f"Starting feature extraction (window={FEATURE_WINDOW}s)...")

    # Extract features from all sources
    network = extract_network_features(FEATURE_WINDOW)
    logger.info(f"Network features: {len(network)} IPs")

    # Try BPF IAT map first, fall back to ClickHouse estimation
    iat_histograms = try_read_bpf_iat_map()
    if iat_histograms:
        temporal = {}
        for ip, histogram in iat_histograms.items():
            temporal[ip] = compute_histogram_stats(histogram)
        logger.info(f"Temporal features: {len(temporal)} IPs (from BPF map)")
    else:
        temporal = extract_temporal_features_from_ch(FEATURE_WINDOW)
        logger.info(f"Temporal features: {len(temporal)} IPs (from ClickHouse)")

    behavioral = extract_behavioral_features(FEATURE_WINDOW)
    logger.info(f"Behavioral features: {len(behavioral)} IPs")

    all_ips = list(set(network.keys()) | set(behavioral.keys()))
    reputation = extract_reputation_features(all_ips)
    logger.info(f"Reputation features: {len(reputation)} IPs")

    # Verdict-driven: catch IPs classified by SENTINEL but missing from flows
    verdict_features = extract_verdict_features(FEATURE_WINDOW)
    if verdict_features:
        logger.info(f"Verdict-only features: {len(verdict_features)} IPs (no flow data)")
        # Merge into network/behavioral so they get assembled
        for ip, feats in verdict_features.items():
            if ip not in network:
                network[ip] = {k: feats[k] for k in feats
                               if k in ('pps', 'bps', 'unique_dst_ports', 'unique_dst_ips',
                                        'syn_ratio', 'rst_ratio', 'avg_pkt_size', 'small_pkt_ratio')}
            if ip not in temporal:
                temporal[ip] = {k: feats[k] for k in feats
                                if k in ('iat_mean', 'iat_stddev', 'iat_entropy',
                                         'burst_count', 'iat_range_ratio', 'iat_concentration')}
            if ip not in behavioral:
                behavioral[ip] = {k: feats[k] for k in feats
                                  if k in ('port_diversity', 'protocol_mix', 'dns_query_ratio',
                                           'session_duration', 'unique_services', 'threat_ratio',
                                           'connection_reuse')}
            if ip not in reputation:
                reputation[ip] = {k: feats[k] for k in feats
                                  if k in ('ip_reputation_score', 'total_historical_events',
                                           'escalation_level')}
        all_ips = list(set(all_ips) | set(verdict_features.keys()))

    # Assemble and write
    vectors = assemble_features(network, temporal, behavioral, reputation)
    written = write_features_to_clickhouse(vectors)
    logger.info(f"Wrote {written} feature vectors to ClickHouse")

    return written


def main():
    logger.info("HYDRA Feature Extractor starting...")
    logger.info(f"ClickHouse: {CH_HOST}:{CH_PORT}/{CH_DB}")
    logger.info(f"Interval: {EXTRACT_INTERVAL}s, Window: {FEATURE_WINDOW}s")

    if not CH_PASSWORD:
        logger.error("CLICKHOUSE_PASSWORD not set")
        sys.exit(1)

    while running:
        try:
            extract_cycle()
        except Exception as e:
            logger.error(f"Extraction cycle failed: {e}")

        # Wait for next cycle
        for _ in range(EXTRACT_INTERVAL):
            if not running:
                break
            time.sleep(1)

    logger.info("Feature Extractor shutting down")


if __name__ == '__main__':
    main()
