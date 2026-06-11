"""
Outcome Observer — Phase 23a

The true-positive feedback loop the CNO was missing. After the organism
blocks an IP, this module measures whether the block ACTUALLY reduced
attack volume from that source, and feeds the result back as an
emotional stimulus + a learning signal for the predictive coder.

The key insight: prior architecture blocked IPs and assumed success.
The anomaly detector reset `consecutive_malicious` counters as IPs went
quiet — but that's because they were BLOCKED, not because they gave up.
The organism couldn't distinguish "block worked" from "attacker pivoted
to a new IP from the same ASN."

This module makes that distinction. Called every 10 minutes by the main
loop; queries napse_flows for packet rates pre/post block.

Author: HookProbe Team
License: Proprietary
Version: 23.0.0
"""

import ipaddress
import logging
import os
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")


# Thresholds
RATE_DROP_SUCCESS = 0.80     # >80% drop = block worked
RATE_DROP_PARTIAL = 0.40     # >40% drop = partial success
OBSERVATION_WINDOW_S = 600   # Observe 10 min post-block
ASN_PIVOT_CHECK = True       # Check for attacker pivoting within same ASN

# SSOL (Ch 28 Sprint 1) — write weak ground-truth labels to cno_outcome_ledger
SSOL_LEDGER_ENABLED = os.environ.get('SSOL_LEDGER_ENABLED', 'true').lower() == 'true'
SCAN_FANOUT_PORTS = 15       # unique dst ports/hr that look like scanning
_BENIGN_RDAP = ('isp', 'cdn', 'edu', 'gov')
# A.5 (Sprint 2) — also reconcile a sample of ALLOWED IPs each cycle. Blocks
# are malicious-by-construction, so blocks-only labeling can never produce the
# BENIGN outcome-labels Gate A needs (the ledger was 100% malicious). Sampling
# the highest-scoring benign/suspicious verdicts (the ambiguous band) yields
# both correct-allows (BENIGN) and missed-attacks (FALSE NEGATIVE → malicious).
ALLOW_SAMPLE_LIMIT = int(os.environ.get('SSOL_ALLOW_SAMPLE', '50'))


class OutcomeObserver:
    """Measures block outcomes and feeds results to emotion + learning.

    Runs on a timer (called from CNO main loop every 10 min). For each IP
    blocked in the last 15 minutes, compares pre/post packet rates from
    napse_flows and classifies the outcome.

    Outcomes feed:
      - Emotion engine (block_success → positive stimulus,
                        block_ineffective → negative stimulus)
      - Phase 22 episodic memory (outcome reconciliation)
      - Phase 23 predictive coder (via episode close callback)
    """

    def __init__(self, emotion_engine=None):
        """
        Args:
            emotion_engine: CNO EmotionEngine for stimulus feedback.
        """
        self._emotion = emotion_engine
        self._lock = threading.Lock()
        self._last_scan_ts = 0.0
        self._recently_observed: Dict[str, float] = {}  # ip → last_check_ts

        self._stats = {
            'observations': 0,
            'block_success': 0,
            'block_partial': 0,
            'block_ineffective': 0,
            'possible_evasion': 0,
            'no_data': 0,
            'errors': 0,
            'ledger_written': 0,
            'ledger_malicious': 0,
            'ledger_benign': 0,
            'ledger_ambiguous': 0,
        }

    def observe_recent_blocks(self) -> Dict[str, int]:
        """Query recent blocks and measure their outcomes.

        Called from CNO main loop every 10 minutes.
        Returns per-outcome counts for this observation pass.
        """
        now = time.time()
        # Autonomous-defense blocks from hydra_blocks (ml/neural_kernel/aegis/
        # cno_organism). cno_synaptic_log bpf_write rows do NOT record the
        # blocked IP (source_ip is empty, and the IP is absent from the details
        # JSON), so the prior query here returned nothing — the observer (and
        # therefore the SSOL ledger) never fired. hydra_blocks carries the real
        # src_ip (IPv4), the decider in `source`, and the block timestamp; it is
        # also higher-volume, making it the authoritative block-decision source.
        # We label the DECISION regardless of auto_expired (enforcement success
        # is a separate concern; weak labels derive from independent evidence).
        query = (
            f"SELECT IPv4NumToString(src_ip) AS ip, source, toString(timestamp) AS ts "
            f"FROM {CH_DB}.hydra_blocks "
            f"WHERE timestamp >= now() - INTERVAL 15 MINUTE "
            f"AND timestamp <  now() - INTERVAL 10 MINUTE "
            f"ORDER BY timestamp DESC LIMIT 100"
        )
        result = _ch_query(query)

        pass_counts = {
            'block_success': 0,
            'block_partial': 0,
            'block_ineffective': 0,
            'possible_evasion': 0,
        }

        for line in (result.strip().split('\n') if result else []):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            src_ip = parts[0].strip()
            decider = (parts[1].strip() or 'unknown')
            block_ts = parts[2]
            if not src_ip:
                continue

            # Skip recently-observed IPs (avoid duplicate work)
            with self._lock:
                if src_ip in self._recently_observed:
                    last = self._recently_observed[src_ip]
                    if now - last < OBSERVATION_WINDOW_S:
                        continue
                self._recently_observed[src_ip] = now

            try:
                outcome = self._measure_outcome(src_ip, block_ts)
                pass_counts[outcome] = pass_counts.get(outcome, 0) + 1
                with self._lock:
                    self._stats[outcome] = self._stats.get(outcome, 0) + 1
                    self._stats['observations'] += 1

                # Feed emotional stimulus
                self._feed_emotion_stimulus(outcome, src_ip)

                # SSOL (Ch 28 Sprint 1) — turn this reconciled block into a
                # weak, confidence-scored ground-truth label for the trainers.
                if SSOL_LEDGER_ENABLED:
                    self._write_outcome_ledger(src_ip, outcome, decider)

            except Exception as e:
                logger.debug("Outcome observation error for %s: %s",
                              src_ip, e)
                with self._lock:
                    self._stats['errors'] += 1

        # A.5 — reconcile a sample of ALLOWS every cycle (runs even when there
        # were no blocks). This is what gives the ledger its BENIGN labels.
        if SSOL_LEDGER_ENABLED:
            try:
                self.reconcile_allows(now)
            except Exception as e:
                logger.debug("Allow reconciliation error: %s", e)

        # Prune recently_observed dict
        with self._lock:
            cutoff = now - OBSERVATION_WINDOW_S * 2
            self._recently_observed = {
                ip: ts for ip, ts in self._recently_observed.items()
                if ts > cutoff
            }

        if any(v > 0 for v in pass_counts.values()):
            logger.info(
                "OUTCOME OBSERVER: %s",
                ", ".join(f"{k}={v}" for k, v in pass_counts.items() if v > 0))

        return pass_counts

    def reconcile_allows(self, now: float) -> None:
        """A.5 — sample high-risk ALLOWED IPs (scored benign/suspicious, not
        blocked) and write a weak outcome-label for each.

        Blocks are malicious-by-construction, so blocks-only labeling can never
        produce benign outcome-labels — the ledger was 100% malicious and Gate A
        (both classes) was unreachable. We bias the sample toward the highest-
        scoring benign/suspicious verdicts (the ambiguous band) because that is
        where both correct-allows (→ BENIGN) and missed attacks (→ FALSE
        NEGATIVE / malicious) hide. Shares the _recently_observed dedup with the
        block path so an IP is never double-labelled in a cycle.
        """
        query = (
            f"SELECT IPv4NumToString(src_ip) AS ip "
            f"FROM {CH_DB}.hydra_verdicts "
            f"WHERE timestamp >= now() - INTERVAL 15 MINUTE "
            f"AND timestamp <  now() - INTERVAL 10 MINUTE "
            f"AND verdict IN ('benign', 'suspicious') "
            f"ORDER BY anomaly_score DESC LIMIT {ALLOW_SAMPLE_LIMIT}"
        )
        result = _ch_query(query)
        if not result:
            return

        reconciled = 0
        for line in result.strip().split('\n'):
            ip = line.split('\t')[0].strip() if line.strip() else ''
            if not ip:
                continue
            with self._lock:
                last = self._recently_observed.get(ip)
                if last is not None and now - last < OBSERVATION_WINDOW_S:
                    continue
                self._recently_observed[ip] = now
            try:
                self._write_outcome_ledger(ip, 'allow_reconcile', 'anomaly_ml',
                                           action='allow')
                reconciled += 1
            except Exception as e:
                logger.debug("Allow reconcile error for %s: %s", ip, e)

        if reconciled:
            logger.info("ALLOW RECONCILE: labelled %d allows", reconciled)

    def _measure_outcome(self, src_ip: str, block_ts: str) -> str:
        """Query pre/post packet rates and classify outcome."""
        # Pre-block rate (10 min before block_ts)
        pre_query = (
            f"SELECT coalesce(sum(pkts_orig + pkts_resp), 0) / 600 AS pps "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE src_ip = '{_esc(src_ip)}' "
            f"AND timestamp >= parseDateTime64BestEffort('{_esc(block_ts)}') - INTERVAL 10 MINUTE "
            f"AND timestamp <  parseDateTime64BestEffort('{_esc(block_ts)}')"
        )
        # Post-block rate (10 min after block_ts)
        post_query = (
            f"SELECT coalesce(sum(pkts_orig + pkts_resp), 0) / 600 AS pps "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE src_ip = '{_esc(src_ip)}' "
            f"AND timestamp >  parseDateTime64BestEffort('{_esc(block_ts)}') "
            f"AND timestamp <= parseDateTime64BestEffort('{_esc(block_ts)}') + INTERVAL 10 MINUTE"
        )

        pre_result = _ch_query(pre_query) or '0'
        post_result = _ch_query(post_query) or '0'

        try:
            pre_rate = float(pre_result.strip())
            post_rate = float(post_result.strip())
        except (ValueError, TypeError):
            return 'no_data'

        if pre_rate <= 0:
            return 'no_data'

        drop_pct = (pre_rate - post_rate) / pre_rate

        if drop_pct > RATE_DROP_SUCCESS:
            return 'block_success'
        elif drop_pct > RATE_DROP_PARTIAL:
            return 'block_partial'
        else:
            return 'block_ineffective'

    def _feed_emotion_stimulus(self, outcome: str, src_ip: str) -> None:
        """Feed outcome back as emotional stimulus."""
        if not self._emotion:
            return

        try:
            if outcome == 'block_success':
                # Positive reinforcement — we were effective
                self._emotion.process_stimulus(
                    'block_success', 0.1,
                    {'src_ip': src_ip, 'outcome': outcome})
            elif outcome == 'block_ineffective':
                # Mild anxiety — our block didn't work
                self._emotion.process_stimulus(
                    'block_ineffective', 0.15,
                    {'src_ip': src_ip, 'outcome': outcome})
            elif outcome == 'possible_evasion':
                # Higher anxiety — attacker pivoted
                self._emotion.process_stimulus(
                    'evasion_detected', 0.20,
                    {'src_ip': src_ip, 'outcome': outcome})
        except Exception as e:
            logger.debug("Emotion stimulus error: %s", e)

    def _write_outcome_ledger(self, src_ip: str, outcome: str, decider: str = 'unknown',
                              action: str = 'block') -> None:
        """Derive a weak, confidence-scored label for a reconciled block OR allow
        and persist it to cno_outcome_ledger (SSOL keystone, Ch 28 Sprint 1).

        Evidence is observable signal, NOT a human verdict:
          - threat-feed / IoC membership and historical malicious verdicts
            → strong malicious
          - operator false-positive override → strong benign (human ground truth)
          - high unique-port fan-out from a non-ISP/CDN source → scan → malicious
          - quiet ISP/CDN/edu/gov source with no feed/verdict history → benign
          - otherwise ambiguous
        Operator labels stay the high-weight anchor downstream; these weak
        labels enter training at conf-scaled weight.
        """
        if not _valid_ip(src_ip):
            return

        ipq = f"toIPv4('{src_ip}')"

        # Evidence 1 — verdict history: latest score, malicious count, operator FP
        vrow = _ch_row(
            f"SELECT argMax(anomaly_score, timestamp), "
            f"countIf(verdict = 'malicious'), "
            f"countIf(operator_decision = 'false_positive') "
            f"FROM {CH_DB}.hydra_verdicts "
            f"WHERE src_ip = {ipq} AND timestamp >= now() - INTERVAL 7 DAY"
        )
        last_score = _to_float(vrow[0]) if len(vrow) > 0 else 0.0
        hist_mal = _to_int(vrow[1]) if len(vrow) > 1 else 0
        op_fp = _to_int(vrow[2]) if len(vrow) > 2 else 0

        # Evidence 2 — recent events: feed membership, volume, port fan-out
        erow = _ch_row(
            f"SELECT countIf(feed_source != ''), count(), uniq(dst_port) "
            f"FROM {CH_DB}.hydra_events "
            f"WHERE src_ip = {ipq} AND timestamp >= now() - INTERVAL 1 HOUR"
        )
        feed_hits = _to_int(erow[0]) if len(erow) > 0 else 0
        ports = _to_int(erow[2]) if len(erow) > 2 else 0

        # Evidence 3 — RDAP class
        rrow = _ch_row(
            f"SELECT rdap_type FROM {CH_DB}.rdap_cache FINAL "
            f"WHERE ip = {ipq} LIMIT 1"
        )
        rdap_type = (rrow[0].strip() if rrow and rrow[0] else 'unknown')
        benign_rdap = rdap_type in _BENIGN_RDAP

        # Classify (same evidence for blocks and allows). The benign branch is
        # action-aware: for a BLOCK we only call it benign with positive RDAP
        # corroboration (conservative — don't rubber-stamp a block as an FP); for
        # an ALLOW, the ABSENCE of any adverse signal is itself the benign signal
        # (the system was right to let it through) — this is what finally yields
        # the BENIGN labels Gate A needs.
        adverse = (feed_hits > 0 or hist_mal > 0)
        if adverse:
            # block: justified. allow: a FALSE NEGATIVE — we let a known-bad IP in.
            why = f'feed={feed_hits},histmal={hist_mal}'
            label, conf, why = 'malicious', 0.9, (f'FN_{why}' if action == 'allow' else why)
        elif op_fp > 0:
            label, conf, why = 'benign', 0.85, 'operator_fp'
        elif ports >= SCAN_FANOUT_PORTS and not benign_rdap:
            label, conf, why = 'malicious', 0.6, f'scan_fanout ports={ports}'
        elif benign_rdap and ports < SCAN_FANOUT_PORTS:
            label, conf, why = 'benign', 0.5, f'benign_rdap={rdap_type}'
        elif action == 'allow' and ports < SCAN_FANOUT_PORTS:
            # A reconciled allow with no adverse signal — correctly allowed.
            label, conf, why = 'benign', 0.4, 'allow_no_adverse_signal'
        else:
            label, conf, why = 'ambiguous', 0.3, 'insufficient_signal'

        evidence = f'{why};outcome={outcome};rdap={rdap_type}'

        safe_decider = decider if re.match(r'^[A-Za-z0-9_]+$', decider or '') else 'unknown'
        safe_action = action if action in ('block', 'allow', 'quarantine') else 'block'
        insert = (
            f"INSERT INTO {CH_DB}.cno_outcome_ledger "
            f"(src_ip, action, decider, pre_score, weak_label, label_conf, evidence) "
            f"VALUES ('{_esc(src_ip)}', '{safe_action}', '{safe_decider}', "
            f"{last_score:.6f}, '{label}', {conf:.3f}, '{_esc(evidence)}')"
        )
        if _ch_query(insert) is not None:
            with self._lock:
                self._stats['ledger_written'] += 1
                self._stats[f'ledger_{label}'] = self._stats.get(f'ledger_{label}', 0) + 1

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ")


def _valid_ip(s: str) -> bool:
    """Strict IPv4/IPv6 validation before interpolating into SQL."""
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False


def _to_int(s: Any) -> int:
    try:
        return int(float(str(s).strip()))
    except (ValueError, TypeError):
        return 0


def _to_float(s: Any) -> float:
    try:
        return float(str(s).strip())
    except (ValueError, TypeError):
        return 0.0


def _ch_row(query: str) -> List[str]:
    """Run a single-row query, return its tab-separated columns as a list.

    The module's _ch_query() returns TabSeparated (no FORMAT appended), so a
    one-row aggregate SELECT comes back as 'c1\\tc2\\tc3'. Returns [] on error
    or empty result.
    """
    raw = _ch_query(query)
    if not raw:
        return []
    first = raw.strip().split('\n')[0] if raw.strip() else ''
    if not first:
        return []
    return first.split('\t')


def _ch_query(query: str) -> Optional[str]:
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=5) as resp:
            return resp.read().decode('utf-8')
    except Exception as e:
        logger.debug("_ch_query failed: %s", e)
        return None
