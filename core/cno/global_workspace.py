"""
Global Workspace — Phase 24

Dehaene's Global Workspace Theory applied to the CNO. Prior architecture
had parallel subsystems (stress, emotion, consensus, session analyzer)
broadcasting into the synaptic queue independently. They did NOT see each
other's state: a FEARFUL organism's psychology silo didn't know it was
fearful; Multi-RAG didn't know current stress when scoring.

This module maintains a single shared coherent state — the "global
workspace" — read by all subsystems. The winning coalition of information
broadcasts to the rest of the system, producing context-aware behavior:

  - LocalBaselineSilo raises focus_ip's history weight when FEARFUL
  - AttackerPsychologySilo boosts APT-TTP severity when novel_flag set
  - GlobalThreatSilo raises threshold when ANGRY (known enemy, already
    in FIGHT — don't over-alert)

This is what makes Phases 21-23 mutually informative instead of
independent. Without the workspace, each phase is an island.

Author: HookProbe Team
License: Proprietary
Version: 24.0.0
"""

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional, Set
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

WORKSPACE_PERSIST_INTERVAL_S = 30.0


@dataclass
class WorkspaceState:
    """The currently-dominant coalition state of the organism.

    Updated every dispatch cycle. Read by all silos, handlers, and
    response modules. This IS the organism's "conscious" state.
    """
    focus_ip: str = ""                      # Currently most-salient entity
    focus_score: float = 0.0                # Winning coalition strength
    current_emotion: str = "serene"         # Current emotion state
    current_stress: str = "calm"            # Current stress state
    emotion_valence: float = 0.0
    emotion_arousal: float = 0.0
    novel_pattern_flag: bool = False
    working_hypothesis: str = ""            # What the organism thinks is happening
    recent_tactics: Set[str] = field(default_factory=set)  # MITRE tactics last 5 min
    last_zero_day_ts: float = 0.0
    last_update: float = field(default_factory=time.time)


class GlobalWorkspace:
    """Singleton shared-state broadcast layer (thread-safe).

    RWLock pattern: many readers (silos), few writers (emotion, stress,
    zero_day_detector, consensus winners). Uses an RLock because Python's
    threading.RWLock isn't stdlib — a reentrant lock is sufficient given
    the sub-millisecond update rate.
    """

    NOVEL_FLAG_TTL_S = 300  # Novel pattern flag expires 5 min after set
    TACTIC_TTL_S = 300      # Tactics in recent_tactics expire after 5 min

    def __init__(self):
        self._state = WorkspaceState()
        self._lock = threading.RLock()
        # Track when each tactic was added for TTL expiry
        self._tactic_timestamps: Dict[str, float] = {}
        self._last_persist_ts = 0.0

        self._stats = {
            'reads': 0,
            'writes': 0,
            'focus_changes': 0,
            'persists': 0,
            'novel_flag_set_count': 0,
        }

    # ------------------------------------------------------------------
    # Reader API
    # ------------------------------------------------------------------

    def snapshot(self) -> WorkspaceState:
        """Return a consistent snapshot of current state. Thread-safe."""
        with self._lock:
            self._stats['reads'] += 1
            # Return a copy to prevent mutation by caller
            return WorkspaceState(
                focus_ip=self._state.focus_ip,
                focus_score=self._state.focus_score,
                current_emotion=self._state.current_emotion,
                current_stress=self._state.current_stress,
                emotion_valence=self._state.emotion_valence,
                emotion_arousal=self._state.emotion_arousal,
                novel_pattern_flag=self._state.novel_pattern_flag,
                working_hypothesis=self._state.working_hypothesis,
                recent_tactics=set(self._state.recent_tactics),
                last_zero_day_ts=self._state.last_zero_day_ts,
                last_update=self._state.last_update,
            )

    # ------------------------------------------------------------------
    # Writer API (called by subsystems)
    # ------------------------------------------------------------------

    def update_emotion(self, emotion: str, valence: float, arousal: float) -> None:
        """Called by EmotionEngine on state transition."""
        with self._lock:
            self._state.current_emotion = emotion
            self._state.emotion_valence = float(valence)
            self._state.emotion_arousal = float(arousal)
            self._state.last_update = time.time()
            self._stats['writes'] += 1

    def update_stress(self, state: str) -> None:
        """Called by StressGauge on state transition."""
        with self._lock:
            self._state.current_stress = state
            self._state.last_update = time.time()
            self._stats['writes'] += 1

    def update_focus(self, ip: str, score: float,
                     hypothesis: str = "") -> None:
        """Called by Multi-RAG when winning coalition emerges."""
        with self._lock:
            old_focus = self._state.focus_ip
            # Winner-take-all: keep focus on highest-scoring entity
            if score >= self._state.focus_score * 0.95:  # within 5%
                self._state.focus_ip = ip
                self._state.focus_score = float(score)
                if hypothesis:
                    self._state.working_hypothesis = hypothesis[:500]
                if old_focus != ip:
                    self._stats['focus_changes'] += 1
                self._state.last_update = time.time()
                self._stats['writes'] += 1

    def flag_novel_pattern(self) -> None:
        """Called by ZeroDayDetector when novel pattern found."""
        with self._lock:
            self._state.novel_pattern_flag = True
            self._state.last_zero_day_ts = time.time()
            self._state.last_update = time.time()
            self._stats['novel_flag_set_count'] += 1
            self._stats['writes'] += 1

    def add_tactic(self, tactic: str) -> None:
        """Called by silo query when MITRE tactic observed."""
        if not tactic:
            return
        with self._lock:
            self._state.recent_tactics.add(tactic)
            self._tactic_timestamps[tactic] = time.time()
            self._state.last_update = time.time()
            self._stats['writes'] += 1

    def tick(self) -> None:
        """Called every dispatch cycle for TTL maintenance + persist."""
        now = time.time()
        with self._lock:
            # Expire novel flag
            if (self._state.novel_pattern_flag
                    and now - self._state.last_zero_day_ts > self.NOVEL_FLAG_TTL_S):
                self._state.novel_pattern_flag = False

            # Expire old tactics
            expired = [t for t, ts in self._tactic_timestamps.items()
                       if now - ts > self.TACTIC_TTL_S]
            for t in expired:
                self._state.recent_tactics.discard(t)
                del self._tactic_timestamps[t]

        # Periodic persist to ClickHouse
        if now - self._last_persist_ts >= WORKSPACE_PERSIST_INTERVAL_S:
            self._persist_state()
            self._last_persist_ts = now

    def _persist_state(self) -> None:
        """Write current workspace state to ClickHouse for audit/dashboards."""
        try:
            with self._lock:
                snap = self.snapshot()
                self._stats['persists'] += 1
            query = (
                f"INSERT INTO {CH_DB}.cno_workspace_state "
                f"(timestamp, focus_ip, focus_score, current_emotion, "
                f"current_stress, emotion_valence, emotion_arousal, "
                f"novel_pattern_flag, working_hypothesis, recent_tactics) "
                f"VALUES (now64(3), "
                f"'{_esc(snap.focus_ip)}', {snap.focus_score:.4f}, "
                f"'{_esc(snap.current_emotion)}', "
                f"'{_esc(snap.current_stress)}', "
                f"{snap.emotion_valence:.4f}, {snap.emotion_arousal:.4f}, "
                f"{'1' if snap.novel_pattern_flag else '0'}, "
                f"'{_esc(snap.working_hypothesis)}', "
                f"{_format_array(list(snap.recent_tactics))})"
            )
            _ch_post(query)
        except Exception as e:
            logger.debug("Workspace persist failed: %s", e)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            snap = self.snapshot()
            return {
                **self._stats,
                'current_state': {
                    'focus_ip': snap.focus_ip,
                    'focus_score': snap.focus_score,
                    'emotion': snap.current_emotion,
                    'stress': snap.current_stress,
                    'novel_flag': snap.novel_pattern_flag,
                    'tactics_count': len(snap.recent_tactics),
                    'working_hypothesis': snap.working_hypothesis[:200],
                },
            }


# ------------------------------------------------------------------
# Context-aware silo modifiers
# ------------------------------------------------------------------

def emotion_weight_modifier(emotion: str, silo_name: str) -> float:
    """Return a multiplicative modifier for silo weight based on emotion.

    Called by silo.query() wrappers. Returns a value in [0.7, 1.3] that
    scales the silo's raw score based on current emotional context.
    """
    # FEARFUL: psychology silo gets boosted (pattern-matching emphasis)
    # ANGRY: global silo gets slight dampening (we're already fighting,
    #        don't over-alert on already-known patterns)
    # VIGILANT: neutral (baseline attention)
    # SERENE: no modifier (system is relaxed)

    if emotion == 'fearful':
        if silo_name in ('attacker_psychology', 'psychology'):
            return 1.20
        if silo_name in ('local_baseline', 'local'):
            return 1.10
    elif emotion == 'angry':
        if silo_name in ('global_threat', 'global'):
            return 0.90
        if silo_name in ('attacker_psychology', 'psychology'):
            return 1.05  # Keep watching for new tactics
    elif emotion == 'anxious':
        return 1.05  # Generally more alert

    return 1.0


def novel_flag_modifier(novel: bool, silo_name: str) -> float:
    """Boost psychology silo when novel pattern active."""
    if novel and silo_name in ('attacker_psychology', 'psychology'):
        return 1.15
    return 1.0


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ")


def _format_array(arr: list) -> str:
    if not arr:
        return "[]"
    escaped = ",".join(f"'{_esc(str(s))}'" for s in arr)
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
