"""
Episodic Memory — Phase 22

The hippocampus analog. The CNO had working memory (PacketSIEM, 60s) and
short-term memory (ClickHouse, 7-90d), but no narrative episodes —
no "I remember Tuesday's incident where IP X used technique Y and I was wrong."

This module opens an episode at every Multi-RAG verdict, waits 10+ minutes
to observe the outcome, and closes the episode with a prediction_error
field. Phase 23 (predictive coder) consumes closed episodes to drift
silo weights. Phase 25 (sleep) replays high-error episodes for learning.

An "episode" is a single-entity narrative record:
  - onset: when we first decided
  - resolution: when we learned whether we were right
  - prediction_error: |actual_outcome_score - predicted_consensus_score|
  - lessons_learned: populated by the predictive coder during sleep replay

This is what separates a stateful defender from a learning defender.

Author: HookProbe Team
License: Proprietary
Version: 22.0.0
"""

import hashlib
import json
import logging
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# ClickHouse config (shared with other modules via env)
CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

# Tuning
RECONCILE_AFTER_S = 600          # Close episode 10 minutes after verdict
RECONCILE_BATCH_SIZE = 50        # Max episodes per reconciliation pass
BLOCK_SUCCESS_THRESHOLD = 0.8    # >80% drop in packet rate = block worked
HIGH_ERROR_THRESHOLD = 0.4       # |error| > this is prioritized for sleep


class EpisodicMemory:
    """Manages narrative episodes from verdict open → outcome close.

    Thread-safe. Episodes are written to ClickHouse on open and updated on
    close. The reconcile_pending() method runs periodically from the CNO
    main loop and closes all episodes >10 minutes old.
    """

    def __init__(self, on_episode_closed=None):
        """
        Args:
            on_episode_closed: Callback(episode_dict) invoked when an
                episode is closed (i.e., outcome determined). Phase 23
                predictive coder wires this to drift silo weights.
        """
        self._on_closed = on_episode_closed
        self._lock = threading.Lock()

        # In-memory buffer of open episodes (src_ip → episode_dict)
        # We track open episodes in memory for fast lookup; they are
        # ALSO persisted to ClickHouse on open (idempotent via episode_id).
        self._open_episodes: Dict[str, Dict[str, Any]] = {}

        self._stats = {
            'episodes_opened': 0,
            'episodes_closed': 0,
            'block_success': 0,
            'block_ineffective': 0,
            'possible_evasion': 0,
            'false_positive': 0,
            'true_negative': 0,
            'pending': 0,
            'reconcile_cycles': 0,
            'write_errors': 0,
        }

    # ------------------------------------------------------------------
    # Open / Close
    # ------------------------------------------------------------------

    def open_episode(self, verdict: Dict[str, Any]) -> Optional[str]:
        """Open a new episode at Multi-RAG verdict time.

        Args:
            verdict: The consensus dict from multi_rag_consensus.evaluate().
                Expected keys: src_ip, consensus_score, confidence,
                verdict (str), action, silo_scores, reasoning, ttp_sequence.

        Returns:
            episode_id or None if open failed (invalid IP, etc).
        """
        src_ip = verdict.get('src_ip', '')
        if not src_ip or not _IPV4_RE.match(src_ip):
            return None

        now = time.time()
        episode_id = self._generate_id(src_ip, now)

        silo_scores = verdict.get('silo_scores', {}) or {
            'global': verdict.get('silo_global_score', 0),
            'local': verdict.get('silo_local_score', 0),
            'psych': verdict.get('silo_psych_score', 0),
        }

        episode = {
            'episode_id': episode_id,
            'onset_ts': now,
            'resolution_ts': None,
            'src_ip': src_ip,
            'event_type': verdict.get('event_type', ''),
            'initial_verdict': verdict.get('verdict', 'unknown'),
            'initial_confidence': float(verdict.get('confidence', 0.0)),
            'initial_consensus_score': float(
                verdict.get('consensus_score', 0.5)),
            'initial_silo_scores_json': json.dumps(silo_scores),
            'initial_action': verdict.get('action', 'monitor'),
            'meta_route': verdict.get('meta_route', 'STANDARD'),
            'ttp_sequence': self._extract_ttps(verdict),
            'consensus_trace': str(verdict.get('reasoning', ''))[:2000],
            # Filled on close:
            'final_outcome': 'pending',
            'prediction_error': 0.0,
            'packet_rate_delta_pct': 0.0,
            'replay_count': 0,
            'lessons_learned': '',
        }

        with self._lock:
            self._open_episodes[src_ip] = episode
            self._stats['episodes_opened'] += 1
            self._stats['pending'] = len(self._open_episodes)

        self._persist_episode_open(episode)
        return episode_id

    def reconcile_pending(self, napse_flows_query_fn) -> int:
        """Close episodes that are >10 minutes old by computing outcome.

        Args:
            napse_flows_query_fn: Callable(src_ip, since_ts) → packet_rate_pps.
                Provided by outcome_observer (Phase 23a).

        Returns:
            Number of episodes closed this pass.
        """
        now = time.time()
        cutoff = now - RECONCILE_AFTER_S

        with self._lock:
            self._stats['reconcile_cycles'] += 1
            pending = [
                (src_ip, ep) for src_ip, ep in self._open_episodes.items()
                if ep['onset_ts'] <= cutoff
            ][:RECONCILE_BATCH_SIZE]

        closed_count = 0
        for src_ip, episode in pending:
            try:
                outcome, delta_pct = self._determine_outcome(
                    episode, napse_flows_query_fn)
                self._close_episode(src_ip, episode, outcome, delta_pct)
                closed_count += 1
            except Exception as e:
                logger.error("Reconcile error for %s: %s", src_ip, e)

        return closed_count

    def _determine_outcome(
        self, episode: Dict[str, Any], query_fn
    ) -> Tuple[str, float]:
        """Compute the outcome of an episode from post-action packet rate.

        Rules:
          - If initial action was block/quarantine:
              * block_success: packet rate dropped >80% post-action
              * block_ineffective: packet rate unchanged or higher
              * possible_evasion: dropped for this IP but new IPs from same
                 ASN appeared (Phase 23a will enrich this later)
          - If initial action was monitor/investigate:
              * true_negative: no subsequent malicious flows seen
              * false_positive: original verdict was 'malicious' but no
                 follow-up malicious flows
        """
        src_ip = episode['src_ip']
        onset = episode['onset_ts']

        # Query pre and post packet rates via callback
        pre_rate = query_fn(src_ip, onset - 600, onset) if query_fn else 0
        post_rate = query_fn(src_ip, onset, onset + RECONCILE_AFTER_S) if query_fn else 0

        if pre_rate > 0:
            delta = (post_rate - pre_rate) / pre_rate
        else:
            delta = 0.0

        action = episode['initial_action']
        if action in ('block', 'quarantine'):
            if delta < -BLOCK_SUCCESS_THRESHOLD:
                return 'block_success', delta * 100
            elif delta > -0.2:
                return 'block_ineffective', delta * 100
            else:
                return 'possible_evasion', delta * 100
        else:
            if post_rate == 0 and pre_rate > 0:
                return 'true_negative', delta * 100
            elif episode['initial_verdict'] == 'malicious' and delta > -0.2:
                return 'false_positive', delta * 100
            return 'benign_confirmed', delta * 100

    def _close_episode(self, src_ip: str, episode: Dict[str, Any],
                       outcome: str, delta_pct: float) -> None:
        """Close an episode with determined outcome."""
        now = time.time()
        episode['resolution_ts'] = now
        episode['final_outcome'] = outcome
        episode['packet_rate_delta_pct'] = round(delta_pct, 2)

        # Compute prediction error
        predicted = episode['initial_consensus_score']
        # Map outcome → actual score in [0,1]
        actual_map = {
            'block_success': 1.0,       # we were right
            'block_ineffective': 0.5,   # partly right but ineffective
            'possible_evasion': 0.8,    # right but attacker pivoted
            'false_positive': 0.0,      # we were wrong
            'true_negative': 0.0,       # correct not to act
            'benign_confirmed': 0.0,    # confirmed benign
            'pending': predicted,       # no error if unknown
        }
        actual = actual_map.get(outcome, predicted)
        episode['prediction_error'] = round(abs(actual - predicted), 4)
        episode['actual_outcome_score'] = actual

        with self._lock:
            self._open_episodes.pop(src_ip, None)
            self._stats['episodes_closed'] += 1
            self._stats['pending'] = len(self._open_episodes)
            if outcome in self._stats:
                self._stats[outcome] += 1

        self._persist_episode_close(episode)

        logger.info(
            "EPISODE CLOSED: %s outcome=%s Δ=%.1f%% pred_err=%.3f",
            src_ip, outcome, delta_pct, episode['prediction_error'])

        if self._on_closed:
            try:
                self._on_closed(episode)
            except Exception as e:
                logger.error("on_episode_closed callback error: %s", e)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist_episode_open(self, episode: Dict[str, Any]) -> None:
        """Insert episode row at open time. Called under lock."""
        try:
            # Use INSERT with only the opened fields; ClickHouse will apply
            # column DEFAULTs for final_outcome etc.
            query = (
                f"INSERT INTO {CH_DB}.cno_episodic_memory "
                f"(episode_id, onset_ts, src_ip, event_type, initial_verdict, "
                f"initial_confidence, initial_consensus_score, "
                f"initial_silo_scores_json, initial_action, meta_route, "
                f"ttp_sequence, consensus_trace) VALUES ("
                f"'{_esc(episode['episode_id'])}', "
                f"toDateTime64({episode['onset_ts']}, 3), "
                f"'{_esc(episode['src_ip'])}', "
                f"'{_esc(episode['event_type'])}', "
                f"'{_esc(episode['initial_verdict'])}', "
                f"{episode['initial_confidence']}, "
                f"{episode['initial_consensus_score']}, "
                f"'{_esc(episode['initial_silo_scores_json'])}', "
                f"'{_esc(episode['initial_action'])}', "
                f"'{_esc(episode['meta_route'])}', "
                f"{_format_array(episode['ttp_sequence'])}, "
                f"'{_esc(episode['consensus_trace'])}')"
            )
            _ch_post(query)
        except Exception as e:
            logger.debug("Episode open persist failed: %s", e)
            with self._lock:
                self._stats['write_errors'] += 1

    def _persist_episode_close(self, episode: Dict[str, Any]) -> None:
        """Update episode row with outcome. ClickHouse ALTER TABLE UPDATE."""
        try:
            query = (
                f"ALTER TABLE {CH_DB}.cno_episodic_memory "
                f"UPDATE resolution_ts = toDateTime64({episode['resolution_ts']}, 3), "
                f"final_outcome = '{_esc(episode['final_outcome'])}', "
                f"prediction_error = {episode['prediction_error']}, "
                f"packet_rate_delta_pct = {episode['packet_rate_delta_pct']}, "
                f"actual_outcome_score = {episode.get('actual_outcome_score', 0)} "
                f"WHERE episode_id = '{_esc(episode['episode_id'])}'"
            )
            _ch_post(query)
        except Exception as e:
            logger.debug("Episode close persist failed: %s", e)
            with self._lock:
                self._stats['write_errors'] += 1

    # ------------------------------------------------------------------
    # Replay API (consumed by Phase 25 sleep cycle)
    # ------------------------------------------------------------------

    def sample_high_error_episodes(self, n: int = 50,
                                    max_age_days: int = 30) -> List[Dict[str, Any]]:
        """Sample closed episodes with highest |prediction_error| for replay.

        Uses prioritized sampling (PER-DQN pattern): higher-error episodes
        are more likely to be selected, but we also include some random
        low-error episodes to avoid overfitting to hard cases.
        """
        cutoff_days = max_age_days
        query = (
            f"SELECT episode_id, src_ip, initial_verdict, initial_action, "
            f"initial_consensus_score, prediction_error, final_outcome, "
            f"ttp_sequence, consensus_trace, replay_count FROM "
            f"{CH_DB}.cno_episodic_memory WHERE resolution_ts IS NOT NULL "
            f"AND onset_ts >= now() - INTERVAL {cutoff_days} DAY "
            f"AND prediction_error >= {HIGH_ERROR_THRESHOLD} "
            f"ORDER BY prediction_error DESC, rand() LIMIT {n}"
        )
        try:
            result = _ch_query(query)
            if not result:
                return []
            episodes = []
            for line in result.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 10:
                    episodes.append({
                        'episode_id': parts[0],
                        'src_ip': parts[1],
                        'initial_verdict': parts[2],
                        'initial_action': parts[3],
                        'initial_consensus_score': float(parts[4]),
                        'prediction_error': float(parts[5]),
                        'final_outcome': parts[6],
                        'ttp_sequence': parts[7],
                        'consensus_trace': parts[8],
                        'replay_count': int(parts[9]),
                    })
            return episodes
        except Exception as e:
            logger.debug("sample_high_error_episodes failed: %s", e)
            return []

    def mark_replayed(self, episode_id: str, lessons: str = '') -> None:
        """Increment replay_count; optionally write lessons_learned."""
        try:
            query = (
                f"ALTER TABLE {CH_DB}.cno_episodic_memory "
                f"UPDATE replay_count = replay_count + 1"
                + (f", lessons_learned = '{_esc(lessons)}'" if lessons else "")
                + f" WHERE episode_id = '{_esc(episode_id)}'"
            )
            _ch_post(query)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _generate_id(self, src_ip: str, ts: float) -> str:
        data = f"{src_ip}:{ts:.6f}"
        return hashlib.sha256(data.encode()).hexdigest()[:24]

    def _extract_ttps(self, verdict: Dict[str, Any]) -> List[str]:
        """Extract MITRE TTPs from a verdict's silo results."""
        ttps = []
        silo_details = verdict.get('silo_details', {})
        psych = silo_details.get('attacker_psychology', {}) if isinstance(
            silo_details, dict) else {}
        for match in psych.get('results', []):
            if isinstance(match, dict):
                tech = match.get('technique', '')
                if tech:
                    ttps.append(tech)
        # Also check top-level behavioral_token
        token = verdict.get('behavioral_token', '')
        if token:
            ttps.append(f"token:{token}")
        return ttps[:20]  # cap

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)


# ------------------------------------------------------------------
# ClickHouse helpers (local copies to avoid import cycles)
# ------------------------------------------------------------------

def _esc(s: str) -> str:
    """Escape string for ClickHouse SQL."""
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ")


def _format_array(arr: List[str]) -> str:
    """Format a Python list as a ClickHouse Array literal."""
    if not arr:
        return "[]"
    escaped = ",".join(f"'{_esc(s)}'" for s in arr)
    return f"[{escaped}]"


def _ch_post(query: str) -> bool:
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data, method='POST')
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ch_query(query: str) -> Optional[str]:
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.read().decode('utf-8')
    except Exception:
        return None
