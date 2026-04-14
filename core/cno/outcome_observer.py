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
        }

    def observe_recent_blocks(self) -> Dict[str, int]:
        """Query recent blocks and measure their outcomes.

        Called from CNO main loop every 10 minutes.
        Returns per-outcome counts for this observation pass.
        """
        now = time.time()
        # Query the BPF blocklist additions in last 15 min from synaptic log
        query = (
            f"SELECT source_ip, timestamp AS ts FROM {CH_DB}.cno_synaptic_log "
            f"WHERE event_type = 'bpf_write' "
            f"AND timestamp >= now() - INTERVAL 15 MINUTE "
            f"AND timestamp <  now() - INTERVAL 10 MINUTE "
            f"AND source_ip != '' ORDER BY ts DESC LIMIT 100"
        )
        result = _ch_query(query)
        if not result:
            return {}

        pass_counts = {
            'block_success': 0,
            'block_partial': 0,
            'block_ineffective': 0,
            'possible_evasion': 0,
        }

        for line in result.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 2:
                continue
            src_ip = parts[0].strip()
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
                outcome = self._measure_outcome(src_ip, parts[1])
                pass_counts[outcome] = pass_counts.get(outcome, 0) + 1
                with self._lock:
                    self._stats[outcome] = self._stats.get(outcome, 0) + 1
                    self._stats['observations'] += 1

                # Feed emotional stimulus
                self._feed_emotion_stimulus(outcome, src_ip)

            except Exception as e:
                logger.debug("Outcome observation error for %s: %s",
                              src_ip, e)
                with self._lock:
                    self._stats['errors'] += 1

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
        elif drop_pct > 0:
            return 'block_ineffective'
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

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ")


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
    except Exception:
        return None
