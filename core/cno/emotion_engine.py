"""
Emotion Engine — The Amygdala

Maps network stress and threat intelligence into an emotional state
using Russell's circumplex model (valence + arousal dimensions).

Emotional States:
    SERENE:     Low arousal, positive valence — normal operations, no camo
    VIGILANT:   Medium arousal, neutral valence — enhanced monitoring
    ANXIOUS:    High arousal, negative valence — TTL jitter, window randomization
    FEARFUL:    Very high arousal, very negative valence — full camo + honeypots
    ANGRY:      High arousal, negative valence — active counter-intelligence

This is NOT anthropomorphization — it is a control theory mechanism for
adaptive defensive posture. Each emotion maps to specific camouflage
and deception behaviors in the Adaptive Camouflage system.

The Emotion Engine differs from the Stress Gauge:
    - Stress Gauge: raw signal aggregation (hypothalamus, simple)
    - Emotion Engine: contextual interpretation (amygdala, nuanced)

    Same stress level can produce different emotions:
    - High stress from DDoS → ANGRY (we know how to fight this)
    - High stress from novel APT → FEARFUL (unknown threat, maximize camo)
    - High stress from scan burst → ANXIOUS (reconnaissance, uncertain intent)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import math
import os
import time
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.request import Request, urlopen

from .types import EmotionState, StressState

logger = logging.getLogger(__name__)

# ClickHouse config
CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# Circumplex parameters
VALENCE_DECAY = 0.05           # Valence drifts toward 0 per cycle (neutral)
AROUSAL_DECAY = 0.08           # Arousal decays faster (organism calms down)
EMOTION_HYSTERESIS_S = 20.0    # Min dwell time before emotion transition
EMOTION_EVAL_INTERVAL_S = 5.0  # Evaluate every 5 seconds


class EmotionEngine:
    """The amygdala — interprets stress context into emotional state.

    Uses Russell's circumplex model with two continuous dimensions:
        valence: -1.0 (negative/threat) to +1.0 (positive/safe)
        arousal: 0.0 (calm/sleepy) to 1.0 (activated/alert)

    The (valence, arousal) point maps to discrete emotions:
        SERENE:   valence > 0.2, arousal < 0.3
        VIGILANT: |valence| < 0.3, 0.3 <= arousal < 0.6
        ANXIOUS:  valence < -0.2, 0.4 <= arousal < 0.7
        FEARFUL:  valence < -0.4, arousal >= 0.7
        ANGRY:    valence < -0.3, arousal >= 0.6, has_known_threat=True
    """

    def __init__(self, on_emotion_change: Optional[Callable] = None):
        self._valence = 0.5       # Start positive (safe)
        self._arousal = 0.1       # Start calm
        self._emotion = EmotionState.SERENE
        self._emotion_entered_at = time.monotonic()
        self._on_change = on_emotion_change

        # Context flags that influence emotion selection
        self._has_known_threat = False    # We recognize the attack type
        self._has_novel_threat = False    # Unknown/zero-day pattern
        self._active_scan = False        # Reconnaissance detected
        self._data_exfil = False         # Exfiltration detected

        self._stats = {
            'evaluations': 0,
            'transitions': 0,
        }

        logger.info("EmotionEngine initialized (valence=%.1f, arousal=%.1f)",
                     self._valence, self._arousal)

    @property
    def emotion(self) -> EmotionState:
        return self._emotion

    @property
    def valence(self) -> float:
        return self._valence

    @property
    def arousal(self) -> float:
        return self._arousal

    # ------------------------------------------------------------------
    # Stimulus Processing
    # ------------------------------------------------------------------

    def process_stimulus(self, stimulus_type: str, intensity: float,
                         context: Optional[Dict[str, Any]] = None) -> None:
        """Process a threat stimulus and update valence/arousal.

        Args:
            stimulus_type: Type of stimulus (see below)
            intensity: 0.0 - 1.0 (stimulus strength)
            context: Optional context dict
        """
        ctx = context or {}

        # Clamp intensity
        intensity = max(0.0, min(1.0, intensity))

        if stimulus_type == 'threat_detected':
            # Threat pushes valence negative, arousal up
            self._valence -= intensity * 0.3
            self._arousal += intensity * 0.4
            if ctx.get('kill_chain_stage') in ('command_control', 'action_on_objectives'):
                self._has_known_threat = True
                self._arousal += 0.15  # Known late-stage = higher arousal

        elif stimulus_type == 'novel_pattern':
            # Unknown pattern → anxiety (negative valence, high arousal)
            self._valence -= intensity * 0.25
            self._arousal += intensity * 0.35
            self._has_novel_threat = True

        elif stimulus_type == 'scan_detected':
            # Scanning → vigilance
            self._valence -= intensity * 0.1
            self._arousal += intensity * 0.2
            self._active_scan = True

        elif stimulus_type == 'exfiltration_detected':
            # Data exfiltration → fear
            self._valence -= intensity * 0.5
            self._arousal += intensity * 0.5
            self._data_exfil = True

        elif stimulus_type == 'ddos_detected':
            # DDoS → anger (we know how to fight this)
            self._valence -= intensity * 0.2
            self._arousal += intensity * 0.3
            self._has_known_threat = True

        elif stimulus_type == 'threat_resolved':
            # Resolution → positive shift
            self._valence += intensity * 0.3
            self._arousal -= intensity * 0.2

        elif stimulus_type == 'all_clear':
            # No threats for extended period
            self._valence += 0.1
            self._arousal -= 0.15

        elif stimulus_type == 'stress_change':
            # Direct stress state mapping
            stress = ctx.get('stress_state')
            if stress == StressState.CALM:
                self._valence += 0.05
                self._arousal -= 0.1
            elif stress == StressState.ALERT:
                self._valence -= 0.05
                self._arousal += 0.1
            elif stress == StressState.FIGHT:
                self._valence -= 0.2
                self._arousal += 0.3
            elif stress == StressState.RECOVERY:
                self._valence += 0.1
                self._arousal -= 0.05

        # Clamp to valid ranges
        self._valence = max(-1.0, min(1.0, self._valence))
        self._arousal = max(0.0, min(1.0, self._arousal))

    def decay(self) -> None:
        """Apply natural decay — organism calms down over time."""
        # Valence drifts toward neutral (0)
        if self._valence > 0:
            self._valence = max(0.0, self._valence - VALENCE_DECAY)
        elif self._valence < 0:
            self._valence = min(0.0, self._valence + VALENCE_DECAY)

        # Arousal decays toward 0 (calm)
        self._arousal = max(0.0, self._arousal - AROUSAL_DECAY)

        # Reset context flags gradually
        if self._arousal < 0.2:
            self._has_known_threat = False
            self._has_novel_threat = False
            self._active_scan = False
            self._data_exfil = False

    # ------------------------------------------------------------------
    # Emotion Classification
    # ------------------------------------------------------------------

    def _classify_emotion(self) -> EmotionState:
        """Map (valence, arousal) + context to discrete emotion."""
        v = self._valence
        a = self._arousal

        # ANGRY: negative valence, high arousal, AND we recognize the threat
        # (we're angry because we know what it is and can fight it)
        if v < -0.3 and a >= 0.6 and self._has_known_threat and not self._has_novel_threat:
            return EmotionState.ANGRY

        # FEARFUL: very negative valence, very high arousal
        # (novel/unknown threats, or data exfiltration detected)
        if v < -0.4 and a >= 0.7:
            return EmotionState.FEARFUL
        if self._data_exfil and a >= 0.5:
            return EmotionState.FEARFUL

        # ANXIOUS: negative valence, moderate-high arousal
        # (uncertain situation, reconnaissance, unknown intent)
        if v < -0.2 and 0.4 <= a < 0.7:
            return EmotionState.ANXIOUS
        if self._active_scan and a >= 0.3:
            return EmotionState.ANXIOUS

        # VIGILANT: near-neutral valence, moderate arousal
        # (something is happening, but not clearly threatening)
        if abs(v) < 0.3 and 0.3 <= a < 0.6:
            return EmotionState.VIGILANT

        # SERENE: positive valence, low arousal (all is well)
        return EmotionState.SERENE

    def evaluate(self) -> Tuple[EmotionState, float, float]:
        """Evaluate current emotion with hysteresis.

        Returns (emotion, valence, arousal).
        """
        self._stats['evaluations'] += 1
        self.decay()

        candidate = self._classify_emotion()
        now = time.monotonic()
        dwell = now - self._emotion_entered_at

        if candidate != self._emotion and dwell >= EMOTION_HYSTERESIS_S:
            old = self._emotion
            self._emotion = candidate
            self._emotion_entered_at = now
            self._stats['transitions'] += 1

            logger.info(
                "EMOTION: %s → %s (valence=%.2f, arousal=%.2f, dwell=%.1fs)",
                old.value, candidate.value, self._valence, self._arousal, dwell,
            )

            # Log transition
            self._log_transition(old, candidate)

            # Notify callback
            if self._on_change:
                try:
                    self._on_change(old, candidate, self._valence, self._arousal)
                except Exception as e:
                    logger.error("Emotion change callback failed: %s", e)

        return self._emotion, self._valence, self._arousal

    def _log_transition(self, old: EmotionState, new: EmotionState) -> None:
        """Log emotion transition to ClickHouse."""
        try:
            import json
            actions = self.get_camouflage_profile().get('techniques', [])
            actions_json = json.dumps(actions)
            query = (
                f"INSERT INTO {CH_DB}.cno_emotion_log "
                f"(timestamp, old_emotion, new_emotion, valence, arousal, "
                f"trigger_event, camouflage_actions) "
                f"VALUES (now64(3), '{old.value}', '{new.value}', "
                f"{self._valence}, {self._arousal}, "
                f"'emotion_transition', '{_ch_escape(actions_json)}')"
            )
            _ch_post(query)
        except Exception as e:
            logger.debug("Emotion log failed: %s", e)

    # ------------------------------------------------------------------
    # Camouflage Profile (what the Adaptive Camouflage system should do)
    # ------------------------------------------------------------------

    def get_camouflage_profile(self) -> Dict[str, Any]:
        """Return the camouflage configuration for the current emotion.

        Each emotion maps to specific defensive techniques.
        """
        profiles = {
            EmotionState.SERENE: {
                'level': 0,
                'techniques': [],
                'description': 'No camouflage — normal operations',
            },
            EmotionState.VIGILANT: {
                'level': 1,
                'techniques': ['enhanced_logging'],
                'description': 'Enhanced logging, no active camouflage',
            },
            EmotionState.ANXIOUS: {
                'level': 2,
                'techniques': [
                    'ttl_jitter',          # ±16 TTL randomization
                    'window_randomize',     # TCP window size variation
                ],
                'description': 'Passive camouflage — defeat OS fingerprinting',
            },
            EmotionState.FEARFUL: {
                'level': 3,
                'techniques': [
                    'ttl_jitter',
                    'window_randomize',
                    'banner_mutation',      # Randomize service banners
                    'honeypot_deploy',      # Spin up decoy services
                    'timing_perturbation',  # Vary response times
                ],
                'description': 'Full camouflage — maximum deception',
            },
            EmotionState.ANGRY: {
                'level': 4,
                'techniques': [
                    'ttl_jitter',
                    'window_randomize',
                    'banner_mutation',
                    'tarpit_activation',    # Slow down attacker connections
                    'canary_tokens',        # Deploy tracking tokens
                    'attacker_fingerprint', # Detailed interaction logging
                ],
                'description': 'Active counter-intelligence — hunt the hunter',
            },
        }
        return profiles.get(self._emotion, profiles[EmotionState.SERENE])

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        profile = self.get_camouflage_profile()
        return {
            'emotion': self._emotion.value,
            'valence': round(self._valence, 3),
            'arousal': round(self._arousal, 3),
            'camouflage_level': profile['level'],
            'active_techniques': profile['techniques'],
            'context': {
                'has_known_threat': self._has_known_threat,
                'has_novel_threat': self._has_novel_threat,
                'active_scan': self._active_scan,
                'data_exfil': self._data_exfil,
            },
            'dwell_s': round(time.monotonic() - self._emotion_entered_at, 1),
            'stats': dict(self._stats),
        }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _ch_escape(s: str) -> str:
    if not s:
        return ''
    return (s.replace('\\', '\\\\').replace("'", "\\'")
             .replace('\n', '\\n').replace('\r', '\\r')
             .replace('\t', '\\t').replace('\0', ''))


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
