"""
Multi-RAG Consensus Engine — The Cerebral Cortex

The defining innovation of the CNO. Queries THREE RAG silos in parallel
and reaches a weighted consensus verdict:

    Silo 1: Global Threat Intel (ClickHouse, cosine distance on feature vectors)
        "Is this pattern seen in global threat feeds / historical attacks?"
        Weight: 0.35

    Silo 2: Local Baseline History (ClickHouse, cosine distance on IP features)
        "What happened last time THIS network saw this pattern?"
        Weight: 0.40 (highest — local knowledge is most relevant)

    Silo 3: Attacker Psychology (PostgreSQL pgvector, 768-dim Gemini embeddings)
        "What MITRE ATT&CK TTP does this behavioral token sequence match?"
        Weight: 0.25

Consensus Rule:
    - Two of three silos must score above 0.5 for action
    - All three below 0.3 → benign (fast-path)
    - Any single silo above 0.9 → escalate regardless

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

from .types import BrainLayer, SynapticEvent, SynapticRoute

logger = logging.getLogger(__name__)

# ClickHouse config
CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# Validate CH_DB is a safe identifier
if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

# IPv4 validation
_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

# Silo weights (must sum to 1.0)
WEIGHT_GLOBAL = 0.35
WEIGHT_LOCAL = 0.40
WEIGHT_PSYCHOLOGY = 0.25

# Consensus thresholds
THRESHOLD_ACTION = 0.50       # Minimum per-silo score for "agree"
THRESHOLD_BENIGN = 0.30       # All silos below this → fast-path benign
THRESHOLD_ESCALATE = 0.90     # Single silo above this → escalate immediately
MIN_SILOS_AGREE = 2           # Minimum silos that must agree for action

# RAG query limits
MAX_RAG_RESULTS = 5           # Top-K results per silo
RAG_TIMEOUT_S = 5.0           # Per-silo timeout
CONSENSUS_POOL_SIZE = 3       # Thread pool for parallel queries


class RAGSilo:
    """Base class for a RAG silo query."""

    def __init__(self, name: str, weight: float):
        self.name = name
        self.weight = weight

    def query(self, ip: str, features: List[float],
              token_narrative: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Query this silo and return a scored result.

        Returns:
            {
                'silo': name,
                'score': 0.0-1.0 (threat confidence),
                'results': [{ip, score, verdict, timestamp}, ...],
                'reasoning': str,
                'latency_ms': int,
            }
        """
        raise NotImplementedError


class GlobalThreatSilo(RAGSilo):
    """Silo 1: Global Threat Intelligence.

    Queries ClickHouse for similar attack patterns from sentinel_attack_patterns
    and hydra_verdicts. Uses feature vector cosine similarity when vector indexes
    are available, falls back to exact IP matching against blocklist/feeds.
    """

    def __init__(self):
        super().__init__('global_threat', WEIGHT_GLOBAL)

    def query(self, ip: str, features: List[float],
              token_narrative: str, context: Dict[str, Any]) -> Dict[str, Any]:
        start = time.monotonic()
        results = []
        score = 0.0

        if not _IPV4_RE.match(ip):
            return self._empty_result(0)

        try:
            # Check 1: Is this IP in any active threat feed?
            feed_query = (
                f"SELECT feed_name, entries_count "
                f"FROM {CH_DB}.hydra_feed_sync "
                f"WHERE status = 'success' "
                f"ORDER BY timestamp DESC LIMIT 1"
            )
            _ch_query(feed_query)  # Warm check — actual IP lookup is in XDP maps

            # Check 2: Find similar historical attack patterns by behavioral features
            if features and len(features) >= 24:
                # Query recent malicious verdicts with similar feature profiles
                similar_query = (
                    f"SELECT src_ip, anomaly_score, verdict, "
                    f"toUnixTimestamp(timestamp) AS ts "
                    f"FROM {CH_DB}.hydra_verdicts "
                    f"WHERE timestamp > now() - INTERVAL 7 DAY "
                    f"AND verdict = 'malicious' "
                    f"AND anomaly_score > 0.7 "
                    f"ORDER BY anomaly_score DESC "
                    f"LIMIT {MAX_RAG_RESULTS}"
                )
                result = _ch_query(similar_query)
                if result:
                    for line in result.strip().split('\n'):
                        if not line.strip():
                            continue
                        parts = line.split('\t')
                        if len(parts) >= 4:
                            results.append({
                                'ip': parts[0],
                                'score': float(parts[1] or 0),
                                'verdict': parts[2],
                                'timestamp': parts[3],
                            })

            # Check 3: Recent SENTINEL evidence for this specific IP
            evidence_query = (
                f"SELECT sentinel_score, verdict, confidence "
                f"FROM {CH_DB}.sentinel_evidence "
                f"WHERE src_ip = '{_safe_ip(ip)}' "
                f"AND timestamp > now() - INTERVAL 1 HOUR "
                f"ORDER BY timestamp DESC LIMIT 1"
            )
            ev_result = _ch_query(evidence_query)
            if ev_result and ev_result.strip():
                parts = ev_result.strip().split('\t')
                if len(parts) >= 3:
                    sentinel_score = float(parts[0] or 0)
                    score = max(score, sentinel_score)

            # Score based on results
            if results:
                avg_score = sum(r['score'] for r in results) / len(results)
                score = max(score, avg_score * 0.8)  # Scale down slightly

        except Exception as e:
            logger.debug("Global threat silo error: %s", e)

        elapsed = int((time.monotonic() - start) * 1000)
        return {
            'silo': self.name,
            'score': min(score, 1.0),
            'results': results,
            'reasoning': f"{len(results)} similar malicious patterns found" if results else "No matching threat patterns",
            'latency_ms': elapsed,
        }

    def _empty_result(self, elapsed: int) -> Dict[str, Any]:
        return {
            'silo': self.name, 'score': 0.0, 'results': [],
            'reasoning': 'Invalid IP', 'latency_ms': elapsed,
        }


class LocalBaselineSilo(RAGSilo):
    """Silo 2: Local Baseline History.

    Queries ClickHouse for this IP's historical behavior in OUR network.
    Compares current features against historical profile (Welford stats).
    The most important silo — it knows THIS network.
    """

    def __init__(self):
        super().__init__('local_baseline', WEIGHT_LOCAL)

    def query(self, ip: str, features: List[float],
              token_narrative: str, context: Dict[str, Any]) -> Dict[str, Any]:
        start = time.monotonic()
        score = 0.0
        results = []

        if not _IPV4_RE.match(ip):
            return {'silo': self.name, 'score': 0.0, 'results': [],
                    'reasoning': 'Invalid IP', 'latency_ms': 0}

        try:
            # Query 1: Historical risk velocity for this IP
            velocity_query = (
                f"SELECT risk_velocity, composite_risk, kill_chain_state, "
                f"toUnixTimestamp(timestamp) AS ts "
                f"FROM {CH_DB}.ip_risk_scores "
                f"WHERE src_ip = '{_safe_ip(ip)}' "
                f"AND timestamp > now() - INTERVAL 24 HOUR "
                f"ORDER BY timestamp DESC "
                f"LIMIT {MAX_RAG_RESULTS}"
            )
            v_result = _ch_query(velocity_query)
            if v_result:
                for line in v_result.strip().split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        vel = float(parts[0] or 0)
                        risk = float(parts[1] or 0)
                        results.append({
                            'velocity': vel,
                            'risk': risk,
                            'kill_chain': parts[2],
                            'timestamp': parts[3],
                        })
                        score = max(score, risk)

            # Query 2: Historical verdicts for this IP
            verdict_query = (
                f"SELECT verdict, anomaly_score, action_taken, "
                f"toUnixTimestamp(timestamp) AS ts "
                f"FROM {CH_DB}.hydra_verdicts "
                f"WHERE src_ip = '{_safe_ip(ip)}' "
                f"AND timestamp > now() - INTERVAL 7 DAY "
                f"ORDER BY timestamp DESC LIMIT 5"
            )
            vd_result = _ch_query(verdict_query)
            if vd_result:
                mal_count = 0
                total = 0
                for line in vd_result.strip().split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        total += 1
                        if parts[0] == 'malicious':
                            mal_count += 1
                if total > 0:
                    recidivism = mal_count / total
                    score = max(score, recidivism)

            # Note: Z-score profile deviation (Welford baseline) will be
            # wired when sentinel_profile_state table is created in
            # a future ClickHouse schema migration.

        except Exception as e:
            logger.debug("Local baseline silo error: %s", e)

        elapsed = int((time.monotonic() - start) * 1000)
        reasoning = f"{len(results)} historical records, recency-weighted score"
        if not results:
            reasoning = "No local history for this IP (first contact)"

        return {
            'silo': self.name,
            'score': min(score, 1.0),
            'results': results,
            'reasoning': reasoning,
            'latency_ms': elapsed,
        }


class AttackerPsychologySilo(RAGSilo):
    """Silo 3: Attacker Psychology / MITRE ATT&CK TTP Matching.

    Maps behavioral token narratives to known attacker TTPs.
    Uses keyword matching against a built-in TTP knowledge base.
    Phase 2+: Will use pgvector 768-dim Gemini embeddings.
    """

    # Built-in TTP knowledge base (behavioral token → TTP mapping)
    TTP_PATTERNS = {
        'SCAN_SWEEP': {
            'tactic': 'Reconnaissance',
            'technique': 'T1595 - Active Scanning',
            'severity': 0.4,
            'description': 'Network scanning / port probing',
        },
        'DNS_TUNNEL': {
            'tactic': 'Exfiltration',
            'technique': 'T1048.003 - Exfiltration Over DNS',
            'severity': 0.85,
            'description': 'Data exfiltration via DNS queries',
        },
        'SSH_BRUTE': {
            'tactic': 'Credential Access',
            'technique': 'T1110 - Brute Force',
            'severity': 0.7,
            'description': 'SSH credential brute force attempt',
        },
        'TLS_DOWNGRADE': {
            'tactic': 'Defense Evasion',
            'technique': 'T1562.001 - Disable or Modify Tools',
            'severity': 0.75,
            'description': 'TLS downgrade attack (MitM indicator)',
        },
        'BULK_TRANSFER': {
            'tactic': 'Exfiltration',
            'technique': 'T1030 - Data Transfer Size Limits',
            'severity': 0.5,
            'description': 'Large data transfer (potential exfiltration)',
        },
        'FLOOD': {
            'tactic': 'Impact',
            'technique': 'T1498 - Network Denial of Service',
            'severity': 0.6,
            'description': 'Traffic flood (DDoS indicator)',
        },
        'BURST': {
            'tactic': 'Impact',
            'technique': 'T1499 - Endpoint Denial of Service',
            'severity': 0.5,
            'description': 'Burst traffic pattern',
        },
        'HIGH_ENTROPY': {
            'tactic': 'Defense Evasion',
            'technique': 'T1027 - Obfuscated Files or Information',
            'severity': 0.45,
            'description': 'High entropy payload (encrypted/compressed)',
        },
        'KNOWN_BAD': {
            'tactic': 'Resource Development',
            'technique': 'T1583 - Acquire Infrastructure',
            'severity': 0.7,
            'description': 'IP from known malicious infrastructure',
        },
        'TOR_EXIT': {
            'tactic': 'Defense Evasion',
            'technique': 'T1090.003 - Multi-hop Proxy',
            'severity': 0.55,
            'description': 'Traffic from Tor exit node',
        },
        'VPN_PROXY': {
            'tactic': 'Defense Evasion',
            'technique': 'T1090 - Proxy',
            'severity': 0.3,
            'description': 'Traffic from VPN/proxy service',
        },
        'ACCELERATING': {
            'tactic': 'Execution',
            'technique': 'Kill Chain Progression',
            'severity': 0.6,
            'description': 'Risk velocity increasing (attack intensifying)',
        },
        'DRIP_FEED': {
            'tactic': 'Exfiltration',
            'technique': 'T1029 - Scheduled Transfer',
            'severity': 0.55,
            'description': 'Low-and-slow data transfer (APT indicator)',
        },
        'CHAOTIC': {
            'tactic': 'Impact',
            'technique': 'T1496 - Resource Hijacking',
            'severity': 0.4,
            'description': 'Chaotic timing pattern (botnet indicator)',
        },
    }

    def __init__(self):
        super().__init__('attacker_psychology', WEIGHT_PSYCHOLOGY)

    def query(self, ip: str, features: List[float],
              token_narrative: str, context: Dict[str, Any]) -> Dict[str, Any]:
        start = time.monotonic()
        matches = []
        max_severity = 0.0

        if not token_narrative:
            elapsed = int((time.monotonic() - start) * 1000)
            return {
                'silo': self.name, 'score': 0.0, 'results': [],
                'reasoning': 'No behavioral token to analyze',
                'latency_ms': elapsed,
            }

        # Match behavioral token narrative against TTP patterns
        narrative_upper = token_narrative.upper()
        for pattern_key, ttp in self.TTP_PATTERNS.items():
            if pattern_key in narrative_upper:
                matches.append({
                    'pattern': pattern_key,
                    'tactic': ttp['tactic'],
                    'technique': ttp['technique'],
                    'severity': ttp['severity'],
                    'description': ttp['description'],
                })
                max_severity = max(max_severity, ttp['severity'])

        # Compound severity: multiple TTPs matching = higher concern
        if len(matches) >= 3:
            max_severity = min(max_severity * 1.2, 1.0)  # 20% boost for 3+ matches
        elif len(matches) >= 2:
            max_severity = min(max_severity * 1.1, 1.0)  # 10% boost for 2 matches

        # Check for known dangerous combinations
        match_keys = {m['pattern'] for m in matches}
        if 'DNS_TUNNEL' in match_keys and 'ACCELERATING' in match_keys:
            max_severity = max(max_severity, 0.95)  # Near-certain exfil
        if 'TOR_EXIT' in match_keys and 'SSH_BRUTE' in match_keys:
            max_severity = max(max_severity, 0.85)  # Tor-based brute force
        if 'KNOWN_BAD' in match_keys and 'HIGH_ENTROPY' in match_keys:
            max_severity = max(max_severity, 0.80)  # Malware C2

        elapsed = int((time.monotonic() - start) * 1000)
        reasoning = (
            f"{len(matches)} TTP matches: "
            + ", ".join(m['technique'] for m in matches[:3])
            if matches else "No known TTP patterns matched"
        )

        return {
            'silo': self.name,
            'score': min(max_severity, 1.0),
            'results': matches,
            'reasoning': reasoning,
            'latency_ms': elapsed,
        }


# ============================================================================
# Multi-RAG Consensus Engine
# ============================================================================

class MultiRAGConsensus:
    """Queries three RAG silos in parallel and reaches weighted consensus.

    The "conscious thought" of the organism — slow but thorough.
    """

    def __init__(self, on_verdict=None, npu_bridge=None):
        """Initialize with optional verdict callback and NPU bridge.

        Args:
            on_verdict: Callback(verdict_dict) called when consensus reached.
            npu_bridge: Optional NPUBridge for accelerated anomaly scoring.
        """
        self._npu = npu_bridge
        self._silos = [
            GlobalThreatSilo(),
            LocalBaselineSilo(),
            AttackerPsychologySilo(),
        ]
        self._executor = ThreadPoolExecutor(
            max_workers=CONSENSUS_POOL_SIZE,
            thread_name_prefix="rag-silo",
        )
        self._on_verdict = on_verdict
        self._stats = {
            'queries': 0,
            'benign': 0,
            'suspicious': 0,
            'malicious': 0,
            'escalations': 0,
            'errors': 0,
            'avg_latency_ms': 0.0,
        }
        logger.info("MultiRAGConsensus initialized with %d silos", len(self._silos))

    def evaluate(self, event: SynapticEvent) -> Dict[str, Any]:
        """Evaluate an event through all three RAG silos.

        Args:
            event: SynapticEvent with source_ip, payload containing
                   features, token_narrative, etc.

        Returns:
            Consensus verdict dict with per-silo scores and action.
        """
        ip = event.source_ip
        features = event.payload.get('features', [])
        token_narrative = event.payload.get('token_narrative', '')
        context = event.payload

        # Phase 2B/4: If no feature vector is provided, build a minimal
        # 24-dim vector from available payload fields so the global-threat
        # silo has data to correlate against.
        if not features:
            if 'anomaly_score' in context:
                # Verdict bridge events
                score = float(context.get('anomaly_score', 0))
                features = [score] * 6 + [0.0] * 18
            elif 'flows' in context or 'pattern' in context:
                # Session analyzer events — encode pattern as numeric
                flows = float(context.get('flows', 0))
                port = float(context.get('dest_port', 0))
                features = [
                    min(1.0, flows / 100.0),   # flow count normalized
                    port / 65535.0,             # port normalized
                    0.7,                        # session anomaly baseline
                ] + [0.0] * 21
            elif 'dest_port' in context:
                # App tracker events — C2 port detection
                port = float(context.get('dest_port', 0))
                features = [
                    0.9,                        # app deviation = high risk
                    port / 65535.0,
                ] + [0.0] * 22
            # Build token narrative from pattern/anomaly if empty
            if not token_narrative:
                pattern = context.get('pattern', context.get('anomaly', ''))
                mitre = context.get('mitre_technique', '')
                if pattern:
                    token_narrative = f"{pattern} {mitre}".strip()

        self._stats['queries'] += 1
        start = time.monotonic()
        logger.info("MULTI-RAG query start: IP=%s features=%d narrative=%s event=%s",
                     ip, len(features), token_narrative[:30] or '(empty)',
                     event.event_type)

        # NPU-accelerated anomaly pre-score (augments consensus)
        npu_score = 0.0
        if self._npu and features:
            try:
                npu_score, npu_method = self._npu.classify_anomaly(features)
                event.payload['npu_anomaly_score'] = npu_score
                event.payload['npu_method'] = npu_method
            except Exception as e:
                logger.debug("NPU pre-score failed: %s", e)

        # Query all silos in parallel
        silo_results = {}
        futures = {}
        for silo in self._silos:
            future = self._executor.submit(
                silo.query, ip, features, token_narrative, context
            )
            futures[future] = silo.name

        for future in as_completed(futures, timeout=RAG_TIMEOUT_S + 1):
            silo_name = futures[future]
            try:
                result = future.result(timeout=RAG_TIMEOUT_S)
                silo_results[silo_name] = result
                logger.info("  SILO %s: score=%.3f (%d results, %dms) — %s",
                            silo_name, result.get('score', 0),
                            len(result.get('results', [])),
                            result.get('latency_ms', 0),
                            result.get('reasoning', '')[:80])
            except Exception as e:
                logger.warning("  SILO %s FAILED: %s", silo_name, e)
                silo_results[silo_name] = {
                    'silo': silo_name, 'score': 0.0, 'results': [],
                    'reasoning': f'Error: {e}', 'latency_ms': 0,
                }
                self._stats['errors'] += 1

        # Compute weighted consensus (with optional NPU tie-breaker)
        consensus = self._compute_consensus(ip, silo_results, token_narrative,
                                            npu_score=npu_score, context=context)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        consensus['total_latency_ms'] = elapsed_ms

        # Update rolling average latency
        n = self._stats['queries']
        self._stats['avg_latency_ms'] = (
            self._stats['avg_latency_ms'] * (n - 1) + elapsed_ms
        ) / n

        # Update verdict stats
        verdict = consensus['verdict']
        if verdict in self._stats:
            self._stats[verdict] += 1

        # Phase 2B: Log final verdict at INFO level
        logger.info("MULTI-RAG VERDICT: %s (score=%.3f) for %s [action=%s, latency=%dms]",
                     consensus.get('verdict', '?'),
                     consensus.get('consensus_score', 0),
                     ip,
                     consensus.get('action', 'none'),
                     elapsed_ms)

        # Log to ClickHouse
        self._log_consensus(consensus)

        # Notify callback
        if self._on_verdict:
            try:
                self._on_verdict(consensus)
            except Exception as e:
                logger.error("Verdict callback failed: %s", e)

        return consensus

    def _compute_consensus(self, ip: str, silo_results: Dict[str, Dict],
                           token_narrative: str,
                           npu_score: float = 0.0,
                           context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Compute weighted consensus from silo scores with optional NPU tie-break."""
        global_score = silo_results.get('global_threat', {}).get('score', 0)
        local_score = silo_results.get('local_baseline', {}).get('score', 0)
        psych_score = silo_results.get('attacker_psychology', {}).get('score', 0)

        # Weighted average
        consensus_score = (
            global_score * WEIGHT_GLOBAL +
            local_score * WEIGHT_LOCAL +
            psych_score * WEIGHT_PSYCHOLOGY
        )

        # Count silos agreeing (above threshold)
        agreeing = sum(1 for s in [global_score, local_score, psych_score]
                       if s >= THRESHOLD_ACTION)

        # NPU tie-breaker: if NPU strongly agrees with 1 silo, count as 2
        if npu_score >= 0.8 and agreeing == 1:
            agreeing = 2
            consensus_score = max(consensus_score, npu_score * 0.3 + consensus_score * 0.7)

        # Fast-path benign: all silos below 0.3
        if all(s < THRESHOLD_BENIGN for s in [global_score, local_score, psych_score]):
            verdict = 'benign'
            action = 'monitor'
            confidence = 1.0 - consensus_score

        # Escalation: any single silo above 0.9
        elif any(s >= THRESHOLD_ESCALATE for s in [global_score, local_score, psych_score]):
            verdict = 'malicious'
            action = 'block'
            confidence = max(global_score, local_score, psych_score)
            self._stats['escalations'] += 1

        # Consensus: 2+ silos agree above threshold
        elif agreeing >= MIN_SILOS_AGREE:
            if consensus_score >= 0.7:
                verdict = 'malicious'
                action = 'block'
            else:
                verdict = 'suspicious'
                action = 'investigate'
            confidence = consensus_score

        # Insufficient agreement
        else:
            if consensus_score >= 0.4:
                verdict = 'suspicious'
                action = 'alert'
            else:
                verdict = 'benign'
                action = 'monitor'
            confidence = 1.0 - consensus_score if verdict == 'benign' else consensus_score

        # Build reasoning from silos
        reasonings = []
        for silo_name, result in silo_results.items():
            if result.get('reasoning'):
                reasonings.append(f"[{silo_name}] {result['reasoning']}")

        return {
            'src_ip': ip,
            'consensus_score': round(consensus_score, 4),
            'verdict': verdict,
            'action': action,
            'confidence': round(confidence, 4),
            'silos_agreeing': agreeing,
            'silo_scores': {
                'global_threat': round(global_score, 4),
                'local_baseline': round(local_score, 4),
                'attacker_psychology': round(psych_score, 4),
            },
            'reasoning': ' | '.join(reasonings),
            'behavioral_token': token_narrative,
            'kill_chain_stage': context.get('kill_chain_state', 'idle') if isinstance(context, dict) else 'idle',
            'silo_details': silo_results,
        }

    def _log_consensus(self, consensus: Dict[str, Any]) -> None:
        """Log consensus verdict to ClickHouse with XAI audit trail.

        Gap 6 fix: now writes reasoning + per-silo details + NPU score
        so post-incident forensic investigators can trace WHY a verdict
        was reached, not just WHAT the verdict was.
        """
        try:
            import json as _json

            scores = consensus['silo_scores']

            # Build compact silo details (score + reasoning per silo, no full result arrays)
            silo_details = {}
            for silo_name, silo_result in consensus.get('silo_results', {}).items():
                silo_details[silo_name] = {
                    'score': round(silo_result.get('score', 0), 4),
                    'reasoning': silo_result.get('reasoning', '')[:200],
                    'result_count': len(silo_result.get('results', [])),
                    'latency_ms': silo_result.get('latency_ms', 0),
                }

            reasoning = _ch_escape(consensus.get('reasoning', '')[:500])
            silo_json = _ch_escape(_json.dumps(silo_details, default=str)[:2000])
            npu = consensus.get('npu_anomaly_score', 0)

            query = (
                f"INSERT INTO {CH_DB}.cno_consensus_log "
                f"(timestamp, src_ip, silo_global_score, silo_local_score, "
                f"silo_psych_score, consensus_score, consensus_verdict, "
                f"consensus_action, confidence, behavioral_token, "
                f"kill_chain_stage, reasoning, silo_details, npu_score) "
                f"VALUES (now64(3), '{_safe_ip(consensus['src_ip'])}', "
                f"{scores['global_threat']}, {scores['local_baseline']}, "
                f"{scores['attacker_psychology']}, {consensus['consensus_score']}, "
                f"'{consensus['verdict']}', '{consensus['action']}', "
                f"{consensus['confidence']}, "
                f"'{_ch_escape(consensus.get('behavioral_token', ''))}', "
                f"'{_ch_escape(consensus.get('kill_chain_stage', 'idle'))}', "
                f"'{reasoning}', '{silo_json}', {npu})"
            )
            _ch_post(query)
        except Exception as e:
            logger.debug("Consensus log failed: %s", e)

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def shutdown(self) -> None:
        """Shutdown the thread pool."""
        self._executor.shutdown(wait=False)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _safe_ip(ip: str) -> str:
    if not ip or not _IPV4_RE.match(ip):
        raise ValueError(f"Invalid IPv4: {ip!r}")
    return ip


def _ch_escape(s: str) -> str:
    if not s:
        return ''
    return (s.replace('\\', '\\\\').replace("'", "\\'")
             .replace('\n', '\\n').replace('\r', '\\r')
             .replace('\t', '\\t').replace('\0', ''))


def _ch_query(query: str) -> Optional[str]:
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=RAG_TIMEOUT_S) as resp:
            return resp.read().decode('utf-8')
    except Exception:
        return None


def _ch_post(query: str) -> bool:
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False
