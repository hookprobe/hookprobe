#!/usr/bin/env python3
"""
HookProbe Cognitive Defense Loop
==================================

The "Frontal Lobe" of the Neural-Kernel — an autonomous Reflex-vs-Reason
system that uses OpenRouter LLM as the executive function.

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    COGNITIVE DEFENSE LOOP                     │
    │                                                               │
    │  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐   │
    │  │  REFLEX   │    │   REASONING  │    │  NEUROPLASTICITY │   │
    │  │  ARC      │    │   LOOP       │    │  PIPELINE        │   │
    │  │ (μs)      │    │  (sub-sec)   │    │  (minutes)       │   │
    │  │           │    │              │    │                  │   │
    │  │ XDP maps  │◄───│ LLM validates│◄───│ Weight tuning   │   │
    │  │ direct    │    │ reflex       │    │ Model retrain   │   │
    │  │ update    │    │ decisions    │    │ Shadow attacker  │   │
    │  └──────────┘    └──────────────┘    └──────────────────┘   │
    └─────────────────────────────────────────────────────────────┘

The system distinguishes between:
    REFLEX: Catastrophic risk velocity → immediate XDP block (no LLM needed)
    REASON: Elevated risk → LLM analyzes behavioral tokens + RAG context
    LEARN:  Operator overrides → LLM explains "why" and tunes weights

LLM Provider: OpenRouter (multi-model with failover)
    - Primary: reasoning model (for SOC analyst simulation)
    - Fallback: creative model (for narrative generation)
    - Fast: nano model (for quick validation)

Usage:
    from cognitive_defense import CognitiveDefenseLoop
    loop = CognitiveDefenseLoop()
    actions = loop.process_cycle(velocity_results, rag_contexts)
"""

import os
import re
import json
import time
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# IPv4 validation (prevents SQL injection in ClickHouse queries)
_IPV4_RE = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$')


def _safe_ip(ip: str) -> str:
    """Validate IPv4 address for safe SQL interpolation."""
    if not ip or not _IPV4_RE.match(ip):
        raise ValueError(f"Invalid IPv4: {ip!r}")
    return ip

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# OpenRouter configuration
# Phase 10: Updated model defaults to working free-tier models (April 2026).
# Previous defaults (deepseek-r1t2-chimera, nemotron-3-nano) returned 404.
# Free models rotate frequently — env overrides are the primary config.
OR_API_KEY = os.environ.get('OPENROUTER_API_KEY', '')
OR_ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions'
OR_MODEL_REASONING = os.environ.get('OPENROUTER_MODEL_REASONING',
                                     'google/gemma-3-27b-it:free')
OR_MODEL_CREATIVE = os.environ.get('OPENROUTER_MODEL_CREATIVE',
                                    'meta-llama/llama-3.3-70b-instruct:free')
OR_MODEL_FAST = os.environ.get('OPENROUTER_MODEL_FAST',
                                'google/gemma-3-4b-it:free')

# Reflex thresholds (bypass LLM — direct XDP action)
REFLEX_VELOCITY = float(os.environ.get('REFLEX_VELOCITY', '0.30'))  # Catastrophic
REFLEX_SCORE = float(os.environ.get('REFLEX_SCORE', '0.95'))        # Near-certain threat

# Reasoning thresholds (engage LLM for analysis)
REASON_VELOCITY = float(os.environ.get('REASON_VELOCITY', '0.10'))  # Elevated risk
REASON_SCORE = float(os.environ.get('REASON_SCORE', '0.70'))        # Suspicious

# LLM rate limiting — free tier is 16 req/min. Cap at 8 to leave headroom.
MAX_LLM_CALLS_PER_CYCLE = int(os.environ.get('MAX_LLM_CALLS', '3'))
LLM_TIMEOUT = int(os.environ.get('LLM_TIMEOUT', '20'))

# Phase 10: LLM response cache — avoid re-analyzing the same IP within 5 min
_LLM_CACHE: Dict[str, Tuple[float, Dict]] = {}  # ip → (timestamp, result)
_LLM_CACHE_TTL = 300  # 5 minutes
_LLM_CALLS_THIS_MINUTE = 0
_LLM_MINUTE_RESET = 0.0

# ============================================================================
# OPENROUTER LLM CLIENT
# ============================================================================

def call_openrouter(prompt: str, system_prompt: str = '',
                    max_tokens: int = 500, temperature: float = 0.3,
                    model: str = '') -> Optional[str]:
    """Call OpenRouter API with multi-model failover + rate limiting.

    Phase 10: Added per-minute rate limiter (8 req/min for free tier
    which allows 16). Also uses IP-level response caching so the same
    IP isn't re-analyzed within 5 minutes.

    Tries: preferred model → reasoning → creative → fast
    Returns LLM response text or None on failure.
    """
    global _LLM_CALLS_THIS_MINUTE, _LLM_MINUTE_RESET

    if not OR_API_KEY:
        logger.debug("OpenRouter API key not configured")
        return None

    # Rate limiter: max 8 calls per minute (free tier = 16, keep headroom)
    now = time.time()
    if now - _LLM_MINUTE_RESET > 60:
        _LLM_CALLS_THIS_MINUTE = 0
        _LLM_MINUTE_RESET = now
    if _LLM_CALLS_THIS_MINUTE >= 8:
        logger.debug("LLM rate limit: %d calls this minute, skipping",
                     _LLM_CALLS_THIS_MINUTE)
        return None

    preferred = model or OR_MODEL_REASONING
    models = [preferred]
    if preferred != OR_MODEL_REASONING:
        models.append(OR_MODEL_REASONING)
    if preferred != OR_MODEL_CREATIVE:
        models.append(OR_MODEL_CREATIVE)
    if preferred != OR_MODEL_FAST:
        models.append(OR_MODEL_FAST)

    messages = []
    if system_prompt:
        messages.append({'role': 'system', 'content': system_prompt})
    messages.append({'role': 'user', 'content': prompt})

    for m in models:
        try:
            _LLM_CALLS_THIS_MINUTE += 1

            payload = json.dumps({
                'model': m,
                'messages': messages,
                'max_tokens': max_tokens,
                'temperature': temperature,
            }).encode('utf-8')

            req = Request(OR_ENDPOINT, data=payload)
            req.add_header('Content-Type', 'application/json')
            req.add_header('Authorization', f'Bearer {OR_API_KEY}')
            req.add_header('HTTP-Referer', 'https://hookprobe.com')
            req.add_header('X-Title', 'HookProbe Neural-Kernel')

            with urlopen(req, timeout=LLM_TIMEOUT) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                content = data.get('choices', [{}])[0].get('message', {}).get('content')
                if content:
                    logger.info("OpenRouter [%s]: %d chars (call %d/min)",
                                m, len(content), _LLM_CALLS_THIS_MINUTE)
                    return content

        except HTTPError as e:
            if e.code == 429:
                logger.debug("OpenRouter [%s]: 429 rate limited", m)
                continue  # Rate limited — try next model
            logger.debug("OpenRouter [%s] HTTP %d", m, e.code)
            continue
        except Exception as e:
            logger.debug("OpenRouter [%s] error: %s", m, e)
            continue

    return None


def get_cached_llm_result(ip: str) -> Optional[Dict]:
    """Return cached LLM result for an IP if still fresh."""
    entry = _LLM_CACHE.get(ip)
    if entry and (time.time() - entry[0]) < _LLM_CACHE_TTL:
        return entry[1]
    return None


def cache_llm_result(ip: str, result: Dict) -> None:
    """Cache an LLM result for an IP."""
    _LLM_CACHE[ip] = (time.time(), result)
    # Evict old entries every 100 caches
    if len(_LLM_CACHE) > 500:
        cutoff = time.time() - _LLM_CACHE_TTL
        stale = [k for k, (t, _) in _LLM_CACHE.items() if t < cutoff]
        for k in stale:
            del _LLM_CACHE[k]


# ============================================================================
# SYSTEM PROMPTS — The "Frontal Lobe" Personality
# ============================================================================

SYSTEM_PROMPT_SOC_ANALYST = """You are an autonomous Tier 3 SOC Analyst embedded in HookProbe's Neural-Kernel defense system.

You analyze behavioral tokens and risk velocity data from the HYDRA threat detection pipeline.
Your responses MUST be structured JSON with these fields:
- "action": one of "block_subnet", "block_ip", "throttle", "alert", "investigate", "monitor", "ignore"
- "confidence": 0.0 to 1.0
- "reasoning": 1-2 sentence explanation of WHY (not what)
- "kill_chain_stage": predicted Cyber Kill Chain stage
- "ttl_seconds": how long the action should persist (0 = permanent)

Rules:
- NEVER block CDN, ISP, or cloud provider IPs without overwhelming evidence
- A high risk velocity from a KNOWN_GOOD IP = investigate, not block
- DNS_TUNNEL + ACCELERATING + KNOWN_BAD = immediate block
- Consider historical parallels from RAG context
- When uncertain, recommend "investigate" over "block"
- Tor exit nodes require 3+ threat signals before blocking"""

SYSTEM_PROMPT_NEUROPLAST = """You are HookProbe's Neuroplasticity Engine — the self-evolution system.

When an operator overrides a machine decision, you analyze:
1. Why did the system make the wrong call?
2. Which feature weights need adjustment?
3. What new behavioral pattern should be learned?

Respond with structured JSON:
- "root_cause": why the original decision was wrong
- "feature_adjustment": dict of feature_name → weight_delta (e.g., {"syn_ratio": -0.1})
- "new_pattern": description of the behavioral pattern that was missed
- "retrain_recommended": boolean
- "severity": "cosmetic", "functional", "critical" """


# ============================================================================
# REFLEX ARC — Sub-millisecond autonomous response
# ============================================================================

class ReflexArc:
    """Handles catastrophic threats that require immediate XDP action.

    No LLM involved — pure algorithmic response when:
    - Risk velocity exceeds catastrophic threshold
    - Anomaly score near-certain (> 0.95)
    - Kill chain at stage 6+ (command_control or action_on_objectives)

    The LLM is NOTIFIED after the fact, not consulted.
    """

    def __init__(self):
        self.reflexes_fired = 0
        self.false_positives_corrected = 0

    def should_reflex(self, ip: str, velocity: float, score: float,
                      token: dict, reputation: int) -> Optional[dict]:
        """Determine if a reflex action should be fired.

        Returns action dict if reflex triggered, None if reasoning needed.
        """
        # Never reflex-block known-good IPs (CDN, ISP)
        if reputation == 0:  # KNOWN_GOOD
            return None

        # Catastrophic velocity + high score = immediate block
        if velocity > REFLEX_VELOCITY and score > REFLEX_SCORE:
            self.reflexes_fired += 1
            return {
                'type': 'reflex',
                'action': 'block_ip',
                'ip': ip,
                'reason': f'Catastrophic risk velocity ({velocity:.3f}/min) + '
                          f'anomaly score {score:.3f}',
                'ttl_seconds': 3600,  # 1 hour block
                'confidence': min(score, 0.99),
            }

        # Known-bad + accelerating = immediate throttle
        if reputation >= 5 and velocity > REASON_VELOCITY:
            self.reflexes_fired += 1
            return {
                'type': 'reflex',
                'action': 'throttle',
                'ip': ip,
                'reason': f'KNOWN_BAD IP with accelerating risk ({velocity:.3f}/min)',
                'ttl_seconds': 1800,
                'confidence': 0.85,
            }

        # DNS tunnel + flood = immediate block (data exfiltration)
        flow_shape = token.get('flow_shape', 7)
        proto_behavior = token.get('protocol_behavior', 5)
        if proto_behavior == 1 and flow_shape in (4, 6):  # DNS_TUNNEL + BURST/FLOOD
            self.reflexes_fired += 1
            return {
                'type': 'reflex',
                'action': 'block_ip',
                'ip': ip,
                'reason': 'DNS tunnel with flood pattern — active exfiltration',
                'ttl_seconds': 7200,
                'confidence': 0.90,
            }

        return None


# ============================================================================
# REASONING LOOP — LLM-powered analysis
# ============================================================================

class ReasoningLoop:
    """Engages the LLM for nuanced threat analysis.

    Called when risk is elevated but not catastrophic — the "gray zone"
    where algorithmic rules are insufficient and contextual reasoning
    is needed.
    """

    def __init__(self):
        self.analyses_completed = 0
        self.llm_calls = 0

    def analyze(self, ip: str, velocity: float, score: float,
                token: dict, rag_context: Optional[dict]) -> Optional[dict]:
        """Ask the LLM to analyze a threat and recommend action.

        Constructs a prompt from behavioral tokens + RAG context,
        then parses the LLM's structured JSON response.
        """
        narrative = token.get('narrative', '[UNKNOWN]')
        prompt_parts = [
            f"THREAT ANALYSIS REQUEST",
            f"IP: {ip}",
            f"Risk Velocity: {velocity:+.4f}/min (β₁)",
            f"Anomaly Score: {score:.3f}",
            f"Behavioral Token: {narrative}",
        ]

        # Add RAG context if available
        if rag_context and rag_context.get('prompt_context'):
            prompt_parts.append(f"\nRAG Context:\n{rag_context['prompt_context']}")

        # Add recent history
        prompt_parts.append(
            f"\nBased on the behavioral token, risk velocity, and historical parallels, "
            f"determine the appropriate defensive action. "
            f"Respond with valid JSON only."
        )

        prompt = '\n'.join(prompt_parts)

        self.llm_calls += 1
        response = call_openrouter(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_SOC_ANALYST,
            max_tokens=300,
            temperature=0.2,
        )

        if not response:
            logger.warning(f"LLM analysis failed for {ip}, falling back to heuristic")
            return self._heuristic_fallback(ip, velocity, score, token)

        # Parse LLM response
        action = self._parse_llm_response(response, ip, velocity, score)
        if action:
            self.analyses_completed += 1
        return action

    def _parse_llm_response(self, response: str, ip: str,
                            velocity: float, score: float) -> Optional[dict]:
        """Parse structured JSON from LLM response."""
        # Try to extract JSON from response (LLM might wrap in markdown)
        json_str = response.strip()
        if '```json' in json_str:
            json_str = json_str.split('```json')[1].split('```')[0].strip()
        elif '```' in json_str:
            json_str = json_str.split('```')[1].split('```')[0].strip()

        # Find JSON object boundaries
        start = json_str.find('{')
        end = json_str.rfind('}')
        if start >= 0 and end > start:
            json_str = json_str[start:end + 1]

        try:
            data = json.loads(json_str)
            action = data.get('action', 'monitor')
            confidence = float(data.get('confidence', 0.5))
            reasoning = data.get('reasoning', '')
            kill_chain = data.get('kill_chain_stage', 'unknown')
            ttl = int(data.get('ttl_seconds', 3600))

            # Validate action is in allowed set
            valid_actions = {'block_subnet', 'block_ip', 'throttle',
                            'alert', 'investigate', 'monitor', 'ignore'}
            if action not in valid_actions:
                action = 'monitor'

            return {
                'type': 'reasoning',
                'action': action,
                'ip': ip,
                'confidence': confidence,
                'reasoning': reasoning,
                'kill_chain_stage': kill_chain,
                'ttl_seconds': ttl,
                'llm_raw': response[:500],
                'velocity': velocity,
                'score': score,
            }

        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logger.warning(f"LLM response parse failed: {e}")
            logger.debug(f"Raw response: {response[:200]}")
            return self._heuristic_fallback(ip, velocity, score, {})

    def _heuristic_fallback(self, ip: str, velocity: float,
                            score: float, token: dict) -> dict:
        """Fallback when LLM is unavailable — algorithmic decision."""
        if score > 0.85 and velocity > 0.15:
            action = 'block_ip'
            confidence = 0.75
        elif score > 0.7:
            action = 'throttle'
            confidence = 0.65
        elif velocity > 0.15:
            action = 'alert'
            confidence = 0.60
        else:
            action = 'monitor'
            confidence = 0.50

        return {
            'type': 'heuristic_fallback',
            'action': action,
            'ip': ip,
            'confidence': confidence,
            'reasoning': f'LLM unavailable. Heuristic: score={score:.3f}, velocity={velocity:.3f}/min',
            'kill_chain_stage': 'unknown',
            'ttl_seconds': 1800,
        }


# ============================================================================
# NEUROPLASTICITY PIPELINE — Self-evolution from operator feedback
# ============================================================================

class NeuroplasticityEngine:
    """Learns from operator overrides to prevent repeat mistakes.

    When an operator corrects a machine decision (e.g., unblocks an IP
    that was wrongly flagged), this engine:
    1. Asks the LLM to analyze why the error occurred
    2. Suggests feature weight adjustments
    3. Records the learning for model retraining

    This is the "adversarial self-play" system — the organism learns
    from its own mistakes.
    """

    def __init__(self):
        self.lessons_learned = 0
        self.weight_adjustments = 0

    def learn_from_override(self, original_action: dict,
                            operator_action: str) -> Optional[dict]:
        """Analyze an operator override and extract learning.

        Args:
            original_action: The machine's original decision
            operator_action: What the operator did instead
                ('confirm', 'false_positive', 'escalate', 'downgrade')
        """
        if operator_action == 'confirm':
            return None  # Machine was correct, nothing to learn

        ip = original_action.get('ip', 'unknown')
        machine_action = original_action.get('action', 'unknown')
        reasoning = original_action.get('reasoning', '')
        score = original_action.get('score', 0)
        velocity = original_action.get('velocity', 0)

        prompt = (
            f"LEARNING FROM OPERATOR OVERRIDE\n\n"
            f"Machine Decision: {machine_action} on IP {ip}\n"
            f"Machine Reasoning: {reasoning}\n"
            f"Anomaly Score: {score:.3f}\n"
            f"Risk Velocity: {velocity:.4f}/min\n"
            f"\nOperator Override: {operator_action}\n"
            f"(The operator {'released a blocked IP' if operator_action == 'false_positive' else 'escalated a monitored IP'})\n"
            f"\nAnalyze: Why was the machine wrong? What should change?"
        )

        response = call_openrouter(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_NEUROPLAST,
            max_tokens=400,
            temperature=0.3,
        )

        if not response:
            return None

        # Parse learning
        lesson = self._parse_learning(response, original_action, operator_action)
        if lesson:
            self.lessons_learned += 1
            self._record_lesson(lesson)
        return lesson

    def _parse_learning(self, response: str, original: dict,
                        override: str) -> Optional[dict]:
        """Parse neuroplasticity learning from LLM response."""
        json_str = response.strip()
        start = json_str.find('{')
        end = json_str.rfind('}')
        if start >= 0 and end > start:
            json_str = json_str[start:end + 1]

        try:
            data = json.loads(json_str)
            return {
                'ip': original.get('ip', ''),
                'original_action': original.get('action', ''),
                'operator_override': override,
                'root_cause': data.get('root_cause', 'unknown'),
                'feature_adjustments': data.get('feature_adjustment', {}),
                'new_pattern': data.get('new_pattern', ''),
                'retrain_recommended': data.get('retrain_recommended', False),
                'severity': data.get('severity', 'functional'),
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
        except (json.JSONDecodeError, ValueError):
            return {
                'ip': original.get('ip', ''),
                'original_action': original.get('action', ''),
                'operator_override': override,
                'root_cause': response[:200],
                'feature_adjustments': {},
                'new_pattern': '',
                'retrain_recommended': False,
                'severity': 'unknown',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }

    def _record_lesson(self, lesson: dict) -> None:
        """Write lesson to ClickHouse for the retraining pipeline."""
        if not CH_PASSWORD:
            return

        now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        ip = lesson.get('ip', '0.0.0.0')
        root_cause = lesson.get('root_cause', '').replace('\\', '\\\\').replace("'", "\\'")
        new_pattern = lesson.get('new_pattern', '').replace('\\', '\\\\').replace("'", "\\'")
        severity = lesson.get('severity', 'functional')

        from risk_velocity import ch_insert, ch_query
        query = (
            f"INSERT INTO {CH_DB}.rag_contexts "
            "(timestamp, src_ip, trigger_type, risk_velocity, prompt_context, "
            "llm_response, llm_action, operator_action)"
        )
        def _esc(s: str) -> str:
            return str(s).replace('\\', '\\\\').replace("'", "\\'")

        override = _esc(lesson.get('operator_override', ''))
        sev = _esc(severity)
        data = (
            f"('{now_ts}', IPv4StringToNum('{_safe_ip(ip)}'), 'neuroplasticity', 0, "
            f"'Override: {override}', "
            f"'{root_cause[:500]}', '{sev}', '{override}')"
        )
        ch_insert(query, data)

    def check_for_overrides(self) -> List[dict]:
        """Check ClickHouse for recent operator overrides to learn from."""
        from risk_velocity import ch_query, parse_rows

        query = f"""
            SELECT
                IPv4NumToString(src_ip) AS ip,
                operator_decision,
                argMax(verdict, timestamp) AS machine_verdict,
                argMax(anomaly_score, timestamp) AS score,
                argMax(action_taken, timestamp) AS machine_action
            FROM {CH_DB}.hydra_verdicts
            WHERE operator_decision != ''
              AND operator_decided_at >= now() - INTERVAL 1 HOUR
            GROUP BY src_ip, operator_decision
            LIMIT 10
        """
        rows = parse_rows(ch_query(query))

        lessons = []
        for row in rows:
            override = row.get('operator_decision', '')
            if override in ('confirm', ''):
                continue

            original = {
                'ip': row.get('ip', ''),
                'action': row.get('machine_action', 'unknown'),
                'reasoning': f"Machine verdict: {row.get('machine_verdict', 'unknown')}",
                'score': float(row.get('score', 0)),
                'velocity': 0,
            }

            lesson = self.learn_from_override(original, override)
            if lesson:
                lessons.append(lesson)

        return lessons


# ============================================================================
# ACTION ENFORCEMENT ENGINE — The "Muscles" of the Organism
# ============================================================================

class ActionEnforcer:
    """Enforces cognitive defense actions by writing to XDP BPF maps and ClickHouse.

    This is the critical bridge between the Neural-Kernel's decisions and
    the actual network defense. Without this, the organism can think but
    not act.

    Enforcement channels:
    1. ClickHouse hydra_blocks → picked up by feed_sync.py → XDP blocklist
    2. ClickHouse hydra_verdicts → audit trail for operator review
    3. Discord alerts → human notification for high-severity actions

    TTL management: Actions with ttl_seconds > 0 are ephemeral.
    A cleanup cycle removes expired blocks.
    """

    _MAX_ACTIVE_BLOCKS = 10000  # Prevent unbounded memory under DDoS

    def __init__(self):
        self.enforced_count = 0
        self.blocked_ips = 0
        self.throttled_ips = 0
        self.alerts_sent = 0
        # Track active ephemeral blocks for TTL expiry
        self._active_blocks: Dict[str, float] = {}  # ip → expiry_timestamp

    def enforce(self, actions: List[dict]) -> int:
        """Execute a list of cognitive defense actions.

        Returns number of actions successfully enforced.
        """
        if not actions:
            return 0

        enforced = 0
        now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        for action in actions:
            act = action.get('action', 'monitor')
            ip = action.get('ip', '')
            if not ip:
                continue

            try:
                if act in ('block_ip', 'block_subnet'):
                    if self._enforce_block(action, now_ts):
                        enforced += 1
                        self.blocked_ips += 1
                elif act == 'throttle':
                    if self._enforce_throttle(action, now_ts):
                        enforced += 1
                        self.throttled_ips += 1
                elif act == 'alert':
                    if self._enforce_alert(action, now_ts):
                        enforced += 1
                        self.alerts_sent += 1
                elif act in ('investigate', 'monitor'):
                    # Write to verdicts for operator dashboard, no active enforcement
                    self._write_verdict(action, now_ts)
                    enforced += 1
                # 'ignore' → do nothing
            except Exception as e:
                logger.error(f"Action enforcement failed for {ip}: {e}")

        self.enforced_count += enforced

        # Cleanup expired blocks
        self._expire_blocks(now_ts)

        return enforced

    def _enforce_block(self, action: dict, now_ts: str) -> bool:
        """Block an IP by writing to hydra_blocks table.

        feed_sync.py reads hydra_blocks and pushes to XDP LPM_TRIE blocklist.
        """
        ip = action['ip']
        ttl = action.get('ttl_seconds', 3600)
        reason = action.get('reasoning', '')[:200].replace('\\', '\\\\').replace("'", "\\'")
        source = action.get('type', 'cognitive')
        confidence = action.get('confidence', 0.5)

        from risk_velocity import ch_insert

        # Write to hydra_blocks (feed_sync.py picks this up for XDP enforcement)
        query = (
            f"INSERT INTO {CH_DB}.hydra_blocks "
            "(timestamp, src_ip, duration_seconds, reason, source, auto_expired, event_count)"
        )
        data = (
            f"('{now_ts}', IPv4StringToNum('{_safe_ip(ip)}'), {ttl}, "
            f"'cognitive_{source}: {reason}', 'neural_kernel', 0, 0)"
        )
        success = ch_insert(query, data)

        if success:
            # Track TTL for expiry (with capacity limit)
            import time
            self._active_blocks[ip] = time.time() + ttl
            # Evict oldest blocks if capacity exceeded (DDoS protection)
            if len(self._active_blocks) > self._MAX_ACTIVE_BLOCKS:
                oldest_ip = min(self._active_blocks, key=self._active_blocks.get)
                self._active_blocks.pop(oldest_ip, None)
            logger.info(f"ENFORCED block_ip: {ip} (TTL={ttl}s, confidence={confidence:.2f})")

        # Write verdict for audit trail
        self._write_verdict(action, now_ts, action_taken='block')

        return success

    def _enforce_throttle(self, action: dict, now_ts: str) -> bool:
        """Throttle an IP by writing a short-duration block.

        Throttle = 300s block (5 min) — gives the system time to reassess.
        """
        ip = action['ip']
        ttl = min(action.get('ttl_seconds', 300), 600)  # Cap at 10 min

        from risk_velocity import ch_insert

        query = (
            f"INSERT INTO {CH_DB}.hydra_blocks "
            "(timestamp, src_ip, duration_seconds, reason, source, auto_expired, event_count)"
        )
        data = (
            f"('{now_ts}', IPv4StringToNum('{_safe_ip(ip)}'), {ttl}, "
            f"'cognitive_throttle', 'neural_kernel', 0, 0)"
        )
        success = ch_insert(query, data)

        if success:
            import time
            self._active_blocks[ip] = time.time() + ttl

        self._write_verdict(action, now_ts, action_taken='throttle')
        return success

    def _enforce_alert(self, action: dict, now_ts: str) -> bool:
        """Send a Discord alert for elevated but non-blocking threats."""
        self._write_verdict(action, now_ts, action_taken='alert')

        webhook = os.environ.get('DISCORD_WEBHOOK_URL', '')
        if not webhook:
            return True  # No Discord configured, still count as enforced

        ip = action['ip']
        reasoning = action.get('reasoning', 'No reasoning provided')
        confidence = action.get('confidence', 0)
        source_type = action.get('type', 'unknown')
        kill_chain = action.get('kill_chain_stage', 'unknown')

        try:
            embed = {
                "embeds": [{
                    "title": f"Neural-Kernel Alert [{source_type.upper()}]",
                    "color": 0xFFAA00,
                    "fields": [
                        {"name": "Source IP", "value": f"`{ip}`", "inline": True},
                        {"name": "Confidence", "value": f"{confidence:.0%}", "inline": True},
                        {"name": "Kill Chain", "value": kill_chain, "inline": True},
                        {"name": "Reasoning", "value": reasoning[:200]},
                    ],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "footer": {"text": "HookProbe Neural-Kernel Cognitive Defense"}
                }]
            }

            payload = json.dumps(embed).encode('utf-8')
            req = Request(webhook, data=payload)
            req.add_header('Content-Type', 'application/json')
            with urlopen(req, timeout=10) as resp:
                resp.read()
            return True
        except Exception as e:
            logger.debug(f"Discord alert failed: {e}")
            return True  # Non-critical failure

    def _write_verdict(self, action: dict, now_ts: str,
                       action_taken: str = 'none') -> bool:
        """Write cognitive defense verdict to hydra_verdicts for audit trail."""
        ip = action.get('ip', '0.0.0.0')
        score = action.get('score', action.get('confidence', 0.5))
        verdict = 'malicious' if action_taken in ('block', 'throttle') else \
                  'suspicious' if action_taken == 'alert' else 'benign'

        from risk_velocity import ch_insert

        query = (
            f"INSERT INTO {CH_DB}.hydra_verdicts "
            "(timestamp, src_ip, anomaly_score, model_scores, verdict, "
            "action_taken, operator_decision, operator_decided_at)"
        )
        data = (
            f"('{now_ts}', IPv4StringToNum('{_safe_ip(ip)}'), {float(score):.6f}, "
            f"[{float(score):.6f}], '{verdict}', "
            f"'cognitive_{action_taken}', '', NULL)"
        )
        return ch_insert(query, data)

    def _expire_blocks(self, now_ts: str) -> int:
        """Remove expired ephemeral blocks.

        Writes auto_expired=1 to hydra_blocks for feed_sync.py to clean up.
        """
        import time
        now = time.time()
        expired = [ip for ip, exp_time in self._active_blocks.items() if now >= exp_time]

        if not expired:
            return 0

        from risk_velocity import ch_query

        # Batch all IPs into a single ALTER TABLE mutation (HIGH-8 fix)
        ip_conditions = ' OR '.join(
            f"src_ip = IPv4StringToNum('{_safe_ip(ip)}')" for ip in expired
        )
        query = (
            f"ALTER TABLE {CH_DB}.hydra_blocks UPDATE auto_expired = 1 "
            f"WHERE ({ip_conditions}) AND source = 'neural_kernel' "
            f"AND auto_expired = 0"
        )
        result = ch_query(query, fmt='')

        # Only remove from tracking if ClickHouse accepted the mutation (CRIT-4 fix)
        if result is not None:
            for ip in expired:
                self._active_blocks.pop(ip, None)
        else:
            logger.warning(f"TTL expiry mutation failed, {len(expired)} blocks still tracked")

        if expired:
            logger.info(f"TTL expired: {len(expired)} cognitive blocks released")

        return len(expired)


# ============================================================================
# COGNITIVE DEFENSE LOOP — The Main Organism
# ============================================================================

class CognitiveDefenseLoop:
    """The autonomous defense organism that ties everything together.

    Processing order per cycle:
    1. REFLEX: Check for catastrophic threats → immediate XDP action
    2. REASON: Elevated threats → LLM analysis → recommended action
    3. LEARN: Check operator overrides → neuroplasticity learning

    The system is self-correcting: operator feedback tunes the
    reflex thresholds and reasoning prompts over time.
    """

    def __init__(self):
        self.reflex = ReflexArc()
        self.reasoning = ReasoningLoop()
        self.neuroplast = NeuroplasticityEngine()
        self.enforcer = ActionEnforcer()
        self.cycle_count = 0
        self.total_actions = 0

    def process_cycle(self, velocity_results: List[dict],
                      rag_contexts: List[dict]) -> List[dict]:
        """Run one cognitive defense cycle.

        Args:
            velocity_results: From RiskVelocityEngine.compute_velocities()
            rag_contexts: From RiskVelocityEngine.flash_rag_lookback()

        Returns:
            List of action dicts to be executed
        """
        self.cycle_count += 1
        actions = []
        llm_calls_this_cycle = 0

        # Build RAG lookup by IP
        rag_by_ip = {ctx['ip']: ctx for ctx in rag_contexts}

        # Import tokenizer and helpers
        from risk_velocity import tokenize_features, ch_query, parse_rows

        # Batch-load real features + reputation for all IPs in this cycle
        ip_features = self._load_ip_features(velocity_results)
        ip_reputations = self._load_ip_reputations(velocity_results)

        for result in velocity_results:
            ip = result['ip']
            velocity = result['risk_velocity']
            score = result['latest_score']

            # Use real features from hydra_ip_features (fallback to minimal)
            features = ip_features.get(ip, [score] + [0.0] * 23)
            reputation = ip_reputations.get(ip, 1)  # 1 = NEUTRAL

            # Generate behavioral token from real features
            token = tokenize_features(features, reputation=reputation,
                                      risk_velocity=velocity)

            # ---- PHASE 1: REFLEX ----
            reflex_action = self.reflex.should_reflex(
                ip, velocity, score, token, reputation
            )
            if reflex_action:
                actions.append(reflex_action)
                logger.info(f"REFLEX: {reflex_action['action']} on {ip} "
                           f"(velocity={velocity:.3f}, score={score:.3f})")
                continue

            # ---- PHASE 2: REASONING ----
            if (velocity > REASON_VELOCITY or score > REASON_SCORE) \
                    and llm_calls_this_cycle < MAX_LLM_CALLS_PER_CYCLE:
                # Phase 10: check IP cache before calling LLM
                cached = get_cached_llm_result(ip)
                if cached:
                    actions.append(cached)
                    logger.info(
                        "REASONING (cached): %s on %s",
                        cached['action'], ip)
                    continue

                rag = rag_by_ip.get(ip)
                reason_action = self.reasoning.analyze(
                    ip, velocity, score, token, rag
                )
                if reason_action:
                    actions.append(reason_action)
                    cache_llm_result(ip, reason_action)  # Phase 10: cache result
                    llm_calls_this_cycle += 1
                    logger.info(
                        "REASONING: %s on %s (confidence=%.2f, reason=%s)",
                        reason_action['action'], ip,
                        reason_action['confidence'],
                        reason_action.get('reasoning', '')[:80]
                    )

        # ---- PHASE 3: NEUROPLASTICITY ----
        # Check every 4th cycle (every hour at 15-min intervals)
        if self.cycle_count % 4 == 0:
            try:
                lessons = self.neuroplast.check_for_overrides()
                if lessons:
                    logger.info(f"NEUROPLASTICITY: {len(lessons)} lessons learned "
                               f"from operator overrides")
            except Exception as e:
                logger.error(f"Neuroplasticity error: {e}")

        # ---- PHASE 4: ENFORCE ----
        # Execute all actions (block/throttle/alert → XDP maps + ClickHouse + Discord)
        enforced = 0
        if actions:
            enforced = self.enforcer.enforce(actions)

        self.total_actions += len(actions)

        # Log cycle summary
        reflex_count = sum(1 for a in actions if a.get('type') == 'reflex')
        reason_count = sum(1 for a in actions if a.get('type') == 'reasoning')
        logger.info(
            f"Cognitive cycle {self.cycle_count}: "
            f"{len(actions)} actions ({reflex_count} reflex, {reason_count} reasoning, "
            f"{llm_calls_this_cycle} LLM calls, {enforced} enforced)"
        )

        return actions

    def _load_ip_features(self, velocity_results: List[dict]) -> Dict[str, List[float]]:
        """Batch-load real feature vectors from hydra_ip_features."""
        if not velocity_results:
            return {}

        from risk_velocity import ch_query, parse_rows

        ips = [r['ip'] for r in velocity_results if r.get('ip')]
        if not ips:
            return {}

        ip_list = ', '.join(f"IPv4StringToNum('{_safe_ip(ip)}')" for ip in ips[:200])
        query = f"""
            SELECT
                IPv4NumToString(src_ip) AS ip,
                feature_vector
            FROM {CH_DB}.hydra_ip_features
            WHERE src_ip IN ({ip_list})
              AND timestamp >= now() - INTERVAL 30 MINUTE
              AND length(feature_vector) = 24
            ORDER BY timestamp DESC
            LIMIT 1 BY src_ip
        """

        features = {}
        try:
            rows = parse_rows(ch_query(query))
            for row in rows:
                ip = row.get('ip', '')
                vec = row.get('feature_vector', [])
                if ip and isinstance(vec, list) and len(vec) == 24:
                    features[ip] = [float(v) for v in vec]
        except Exception as e:
            logger.debug(f"Feature load error: {e}")

        return features

    def _load_ip_reputations(self, velocity_results: List[dict]) -> Dict[str, int]:
        """Batch-load RDAP reputation classes from rdap_cache."""
        if not velocity_results:
            return {}

        from risk_velocity import ch_query, parse_rows

        ips = [r['ip'] for r in velocity_results if r.get('ip')]
        if not ips:
            return {}

        ip_list = ', '.join(f"IPv4StringToNum('{_safe_ip(ip)}')" for ip in ips[:200])
        query = f"""
            SELECT
                IPv4NumToString(ip) AS ip_str,
                rdap_type
            FROM {CH_DB}.rdap_cache FINAL
            WHERE ip IN ({ip_list})
        """

        # Map RDAP types to reputation codes (must match semantic_tokenizer)
        rdap_to_rep = {
            'cdn': 0, 'isp': 0, 'edu': 0, 'gov': 0,  # KNOWN_GOOD
            'unknown': 1,                                 # NEUTRAL
            'datacenter': 2,                              # SUSPICIOUS
            'tor': 3,                                     # TOR_EXIT
            'vpn': 4,                                     # VPN_PROXY
        }

        reputations = {}
        try:
            rows = parse_rows(ch_query(query))
            for row in rows:
                ip = row.get('ip_str', '')
                rdap_type = row.get('rdap_type', 'unknown')
                reputations[ip] = rdap_to_rep.get(rdap_type, 1)

            # Check blocklist for KNOWN_BAD (score 5)
            bl_query = f"""
                SELECT DISTINCT IPv4NumToString(src_ip) AS ip
                FROM {CH_DB}.hydra_events
                WHERE src_ip IN ({ip_list})
                  AND feed_source != ''
                  AND timestamp >= now() - INTERVAL 7 DAY
            """
            bl_rows = parse_rows(ch_query(bl_query))
            for row in bl_rows:
                ip = row.get('ip', '')
                if ip:
                    reputations[ip] = 5  # KNOWN_BAD

        except Exception as e:
            logger.debug(f"Reputation load error: {e}")

        return reputations

    def get_stats(self) -> dict:
        """Return cognitive defense statistics."""
        return {
            'cycles': self.cycle_count,
            'total_actions': self.total_actions,
            'reflexes_fired': self.reflex.reflexes_fired,
            'reflex_fps_corrected': self.reflex.false_positives_corrected,
            'llm_analyses': self.reasoning.analyses_completed,
            'llm_calls': self.reasoning.llm_calls,
            'lessons_learned': self.neuroplast.lessons_learned,
            'enforced': self.enforcer.enforced_count,
            'blocked_ips': self.enforcer.blocked_ips,
            'throttled_ips': self.enforcer.throttled_ips,
            'alerts_sent': self.enforcer.alerts_sent,
            'active_blocks': len(self.enforcer._active_blocks),
        }
