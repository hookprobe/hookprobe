"""
L1 SOC Autonomous Agent

AI-driven decision making for L1 security events.
Uses OpenRouter LLM for uncertain situations.

Philosophy: "Less is more automation"
- AI handles 95% of decisions automatically
- Narrative notifications for user awareness
- Only prompt user when genuinely uncertain
- Learn from user corrections

Integration:
- OpenRouter API for AI reasoning
- Gemini 3 Flash for quick validation
- Narrative engine for human-friendly alerts
"""

import logging
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict, Any, Callable
import asyncio
import os

logger = logging.getLogger(__name__)


class DecisionConfidence(Enum):
    """Confidence levels for autonomous decisions."""
    HIGH = 'high'           # > 85% - Act automatically
    MEDIUM = 'medium'       # 60-85% - Act but notify
    LOW = 'low'             # 30-60% - Notify and suggest
    UNCERTAIN = 'uncertain' # < 30% - Ask user


class ActionResult(Enum):
    """Result of autonomous action."""
    EXECUTED = 'executed'
    NOTIFIED = 'notified'
    ASKED_USER = 'asked_user'
    DEFERRED = 'deferred'
    BLOCKED = 'blocked'


@dataclass
class AutonomousDecision:
    """A decision made by the autonomous agent."""
    id: str
    timestamp: datetime
    event_type: str
    event_data: Dict

    # Decision
    action: str
    confidence: DecisionConfidence
    reasoning: str

    # Outcome
    result: ActionResult
    user_overrode: bool = False
    user_feedback: Optional[str] = None

    # Learning
    learned_from: bool = False


@dataclass
class UserPrompt:
    """A prompt shown to the user when AI is uncertain."""
    id: str
    timestamp: datetime
    question: str
    context: str
    options: List[Dict[str, str]]  # [{"label": "...", "action": "..."}]
    urgency: str  # "low", "normal", "high"
    expires_at: Optional[datetime] = None
    answered: bool = False
    answer: Optional[str] = None


class L1AutonomousAgent:
    """
    Autonomous AI agent for L1 SOC decisions.

    Decision Framework:
    1. Analyze event using local rules
    2. Calculate confidence score
    3. If confident (>85%): Act automatically, send narrative
    4. If medium (60-85%): Act, notify with "I did X because Y"
    5. If low (30-60%): Notify, suggest action, auto-execute after timeout
    6. If uncertain (<30%): Ask user via prompt (with timeout fallback)

    Learning:
    - Track user corrections
    - Adjust confidence thresholds based on feedback
    - Use OpenRouter for complex reasoning when needed
    """

    # Confidence thresholds
    HIGH_CONFIDENCE = 0.85
    MEDIUM_CONFIDENCE = 0.60
    LOW_CONFIDENCE = 0.30

    # Timeouts
    LOW_CONFIDENCE_TIMEOUT_SEC = 120  # Auto-execute after 2 min
    USER_PROMPT_TIMEOUT_SEC = 300     # 5 min timeout for user response

    # OpenRouter settings
    OPENROUTER_MODEL = "google/gemini-2.0-flash-001"  # Fast, good reasoning
    OPENROUTER_FALLBACK = "google/gemini-2.5-flash-preview-05-20"

    def __init__(
        self,
        openrouter_api_key: Optional[str] = None,
        narrative_callback: Optional[Callable] = None,
        prompt_callback: Optional[Callable] = None,
        action_callback: Optional[Callable] = None,
    ):
        self.api_key = openrouter_api_key or os.environ.get('OPENROUTER_API_KEY')

        # Callbacks
        self._narrative_callback = narrative_callback  # Send narrative to user
        self._prompt_callback = prompt_callback        # Show prompt to user
        self._action_callback = action_callback        # Execute action

        # History for learning
        self._decisions: List[AutonomousDecision] = []
        self._pending_prompts: Dict[str, UserPrompt] = {}

        # Learned adjustments (from user feedback)
        self._confidence_adjustments: Dict[str, float] = {}

    async def process_event(
        self,
        event_type: str,
        event_data: Dict,
        l1_trust_score: float,
        anomaly_indicators: int,
    ) -> AutonomousDecision:
        """
        Process an L1 security event and decide what to do.

        Args:
            event_type: Type of event (e.g., "unknown_tower", "jamming")
            event_data: Event details
            l1_trust_score: Current L1 Trust Score
            anomaly_indicators: Number of corroborating indicators

        Returns:
            Decision made by the agent
        """
        # 1. Calculate base confidence from rules
        confidence, suggested_action, reasoning = self._evaluate_rules(
            event_type, event_data, l1_trust_score, anomaly_indicators
        )

        # 2. Apply learned adjustments
        adjusted_confidence = self._apply_learned_adjustments(
            event_type, confidence
        )

        # 3. Determine confidence level
        conf_level = self._get_confidence_level(adjusted_confidence)

        # 4. Create decision record
        decision = AutonomousDecision(
            id=f"decision-{datetime.now().timestamp()}",
            timestamp=datetime.now(),
            event_type=event_type,
            event_data=event_data,
            action=suggested_action,
            confidence=conf_level,
            reasoning=reasoning,
            result=ActionResult.DEFERRED,
        )

        # 5. Execute based on confidence level
        if conf_level == DecisionConfidence.HIGH:
            # Act automatically, just notify via narrative
            await self._execute_autonomous(decision, notify=True)

        elif conf_level == DecisionConfidence.MEDIUM:
            # Act and explain why
            await self._execute_with_explanation(decision)

        elif conf_level == DecisionConfidence.LOW:
            # Notify, suggest, auto-execute after timeout
            await self._suggest_and_wait(decision)

        else:  # UNCERTAIN
            # Ask user (or use OpenRouter for complex reasoning)
            await self._ask_for_guidance(decision)

        self._decisions.append(decision)
        return decision

    def _evaluate_rules(
        self,
        event_type: str,
        event_data: Dict,
        l1_trust_score: float,
        indicators: int,
    ) -> tuple[float, str, str]:
        """
        Evaluate local rules to determine action and confidence.

        Returns: (confidence, action, reasoning)
        """
        # Rule-based evaluation
        if event_type == "rogue_tower":
            if indicators >= 3:
                return (0.95, "blacklist_and_survival",
                       "Tower has 3+ rogue indicators - confirmed threat")
            elif indicators >= 2:
                return (0.75, "blacklist_tower",
                       "Tower shows suspicious behavior (2 indicators)")
            else:
                return (0.40, "monitor_tower",
                       "Single indicator - could be new legitimate tower")

        elif event_type == "unknown_tower":
            if l1_trust_score < 30:
                return (0.80, "avoid_tower",
                       "Unknown tower + low trust score")
            elif l1_trust_score < 50:
                return (0.50, "monitor_tower",
                       "Unknown tower but trust score acceptable")
            else:
                return (0.30, "learn_tower",
                       "Unknown tower but everything else looks normal")

        elif event_type == "jamming":
            if indicators >= 2:
                return (0.90, "band_switch_and_notify",
                       "Clear jamming signature detected")
            else:
                return (0.60, "band_switch",
                       "Possible jamming - switching bands as precaution")

        elif event_type == "imsi_catcher":
            # IMSI catcher is always high priority
            if indicators >= 2:
                return (0.95, "survival_mode",
                       "IMSI catcher confirmed - entering survival mode")
            else:
                return (0.70, "protocol_lockdown",
                       "IMSI catcher suspected - locking to 4G+")

        elif event_type == "downgrade_attack":
            return (0.85, "protocol_lockdown",
                   "Crypto downgrade detected - blocking weak protocols")

        elif event_type == "handover_storm":
            if indicators >= 2:
                return (0.75, "investigate_cells",
                       "Excessive handovers - possible tracking attack")
            else:
                return (0.40, "monitor",
                       "High handover rate but could be legitimate mobility")

        # Default: uncertain
        return (0.25, "monitor", "Unfamiliar event - monitoring")

    def _apply_learned_adjustments(
        self,
        event_type: str,
        base_confidence: float,
    ) -> float:
        """Apply adjustments from user feedback."""
        adjustment = self._confidence_adjustments.get(event_type, 0.0)
        return max(0.0, min(1.0, base_confidence + adjustment))

    def _get_confidence_level(self, confidence: float) -> DecisionConfidence:
        """Convert numeric confidence to level."""
        if confidence >= self.HIGH_CONFIDENCE:
            return DecisionConfidence.HIGH
        elif confidence >= self.MEDIUM_CONFIDENCE:
            return DecisionConfidence.MEDIUM
        elif confidence >= self.LOW_CONFIDENCE:
            return DecisionConfidence.LOW
        else:
            return DecisionConfidence.UNCERTAIN

    async def _execute_autonomous(
        self,
        decision: AutonomousDecision,
        notify: bool = True,
    ):
        """Execute action autonomously with optional notification."""
        logger.info(f"Auto-executing: {decision.action} (confidence: HIGH)")

        # Execute action
        if self._action_callback:
            try:
                await self._action_callback(decision.action, decision.event_data)
                decision.result = ActionResult.EXECUTED
            except Exception as e:
                logger.error(f"Action failed: {e}")
                decision.result = ActionResult.BLOCKED

        # Send narrative (brief, informative)
        if notify and self._narrative_callback:
            narrative = self._generate_narrative(decision, style="brief")
            await self._narrative_callback(narrative)

    async def _execute_with_explanation(self, decision: AutonomousDecision):
        """Execute action and explain why."""
        logger.info(f"Executing with explanation: {decision.action}")

        # Execute
        if self._action_callback:
            try:
                await self._action_callback(decision.action, decision.event_data)
                decision.result = ActionResult.EXECUTED
            except Exception as e:
                logger.error(f"Action failed: {e}")
                decision.result = ActionResult.BLOCKED
                return

        # Send explanatory narrative
        if self._narrative_callback:
            narrative = self._generate_narrative(decision, style="explanation")
            await self._narrative_callback(narrative)

    async def _suggest_and_wait(self, decision: AutonomousDecision):
        """Suggest action, wait for user, auto-execute after timeout."""
        logger.info(f"Suggesting: {decision.action} (will auto-execute in {self.LOW_CONFIDENCE_TIMEOUT_SEC}s)")

        # Send notification with suggestion
        if self._narrative_callback:
            narrative = self._generate_narrative(decision, style="suggestion")
            narrative['auto_execute_in'] = self.LOW_CONFIDENCE_TIMEOUT_SEC
            await self._narrative_callback(narrative)

        decision.result = ActionResult.NOTIFIED

        # Schedule auto-execution
        await asyncio.sleep(self.LOW_CONFIDENCE_TIMEOUT_SEC)

        # Check if user responded
        if not decision.user_overrode:
            logger.info(f"Auto-executing after timeout: {decision.action}")
            if self._action_callback:
                await self._action_callback(decision.action, decision.event_data)
            decision.result = ActionResult.EXECUTED

    async def _ask_for_guidance(self, decision: AutonomousDecision):
        """Ask user for guidance when uncertain."""
        logger.info(f"Asking user for guidance: {decision.event_type}")

        # First, try to use OpenRouter for reasoning
        if self.api_key:
            ai_suggestion = await self._get_ai_reasoning(decision)
            if ai_suggestion and ai_suggestion['confidence'] >= self.MEDIUM_CONFIDENCE:
                # AI is confident, follow its suggestion
                decision.action = ai_suggestion['action']
                decision.reasoning = ai_suggestion['reasoning']
                decision.confidence = DecisionConfidence.MEDIUM
                await self._execute_with_explanation(decision)
                return

        # AI also uncertain or unavailable - ask user
        prompt = UserPrompt(
            id=f"prompt-{datetime.now().timestamp()}",
            timestamp=datetime.now(),
            question=self._generate_question(decision),
            context=self._generate_context(decision),
            options=self._generate_options(decision),
            urgency="normal" if decision.confidence == DecisionConfidence.UNCERTAIN else "high",
            expires_at=datetime.now() + timedelta(seconds=self.USER_PROMPT_TIMEOUT_SEC),
        )

        self._pending_prompts[prompt.id] = prompt

        if self._prompt_callback:
            await self._prompt_callback(prompt)

        decision.result = ActionResult.ASKED_USER

    async def _get_ai_reasoning(self, decision: AutonomousDecision) -> Optional[Dict]:
        """Use OpenRouter to get AI reasoning for uncertain situations."""
        try:
            import httpx

            prompt = f"""You are an L1 SOC (Physical Layer Security Operations Center) AI.

Event: {decision.event_type}
Data: {json.dumps(decision.event_data, indent=2)}
Current reasoning: {decision.reasoning}

Based on this cellular security event, what action should be taken?

Options:
1. blacklist_tower - Block this cell tower
2. survival_mode - Enter full survival mode (VPN, protocol lockdown)
3. protocol_lockdown - Disable 2G/3G only
4. band_switch - Switch to different frequency band
5. monitor - Just monitor, take no action
6. learn_tower - Add tower to learning queue for future whitelist

Respond with JSON:
{{"action": "...", "confidence": 0.0-1.0, "reasoning": "..."}}
"""
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.OPENROUTER_MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.3,  # Low temp for consistent decisions
                    },
                    timeout=10.0,
                )

                if response.status_code == 200:
                    data = response.json()
                    content = data['choices'][0]['message']['content']
                    # Parse JSON from response
                    try:
                        return json.loads(content)
                    except json.JSONDecodeError:
                        # Try to extract JSON from markdown
                        import re
                        match = re.search(r'\{[^}]+\}', content)
                        if match:
                            return json.loads(match.group())

        except Exception as e:
            logger.warning(f"OpenRouter reasoning failed: {e}")

        return None

    def _generate_narrative(
        self,
        decision: AutonomousDecision,
        style: str,
    ) -> Dict[str, Any]:
        """Generate human-friendly narrative for decision."""
        base = {
            "timestamp": decision.timestamp.isoformat(),
            "event_type": decision.event_type,
            "action": decision.action,
            "severity": self._get_severity(decision),
        }

        if style == "brief":
            # Just inform, no explanation needed
            base["headline"] = self._get_brief_headline(decision)
            base["show_details"] = False

        elif style == "explanation":
            # Explain what was done and why
            base["headline"] = self._get_explanation_headline(decision)
            base["explanation"] = decision.reasoning
            base["show_details"] = True

        elif style == "suggestion":
            # Suggest action, explain, offer override
            base["headline"] = self._get_suggestion_headline(decision)
            base["explanation"] = decision.reasoning
            base["suggested_action"] = decision.action
            base["allow_override"] = True
            base["show_details"] = True

        return base

    def _get_brief_headline(self, decision: AutonomousDecision) -> str:
        """Get brief headline for autonomous action."""
        headlines = {
            "blacklist_and_survival": "Blocked dangerous tower, protection active",
            "blacklist_tower": "Blocked suspicious tower",
            "survival_mode": "Emergency protection activated",
            "protocol_lockdown": "Secured connection (disabled weak protocols)",
            "band_switch": "Switched to clearer frequency",
            "monitor_tower": "Monitoring new tower",
            "avoid_tower": "Avoiding suspicious tower",
        }
        return headlines.get(decision.action, f"Action taken: {decision.action}")

    def _get_explanation_headline(self, decision: AutonomousDecision) -> str:
        """Get headline with 'because' explanation."""
        action_names = {
            "blacklist_tower": "blocked a suspicious tower",
            "survival_mode": "activated emergency protection",
            "protocol_lockdown": "secured your connection",
            "band_switch": "switched frequencies",
        }
        action_name = action_names.get(decision.action, decision.action)
        return f"I {action_name} because {decision.reasoning.lower()}"

    def _get_suggestion_headline(self, decision: AutonomousDecision) -> str:
        """Get headline for suggestion."""
        return f"I think I should {decision.action.replace('_', ' ')}"

    def _get_severity(self, decision: AutonomousDecision) -> str:
        """Get severity level for narrative."""
        high_severity = ["survival_mode", "blacklist_and_survival"]
        medium_severity = ["blacklist_tower", "protocol_lockdown"]

        if decision.action in high_severity:
            return "high"
        elif decision.action in medium_severity:
            return "medium"
        else:
            return "low"

    def _generate_question(self, decision: AutonomousDecision) -> str:
        """Generate question for user prompt."""
        questions = {
            "unknown_tower": "I found an unfamiliar cell tower. What should I do?",
            "handover_storm": "Your phone keeps switching towers rapidly. Is this expected?",
            "jamming": "Something might be blocking your signal. Should I try to work around it?",
        }
        return questions.get(
            decision.event_type,
            f"I'm unsure about: {decision.event_type}. What would you like me to do?"
        )

    def _generate_context(self, decision: AutonomousDecision) -> str:
        """Generate context explanation for user prompt."""
        return decision.reasoning

    def _generate_options(self, decision: AutonomousDecision) -> List[Dict[str, str]]:
        """Generate options for user prompt."""
        # Default options based on event type
        return [
            {"label": "Trust this tower", "action": "whitelist_tower"},
            {"label": "Block this tower", "action": "blacklist_tower"},
            {"label": "Keep monitoring", "action": "monitor"},
            {"label": "Let AI decide", "action": "ai_decide"},
        ]

    def record_user_feedback(
        self,
        decision_id: str,
        user_action: str,
        feedback: str = "",
    ):
        """
        Record user feedback for learning.

        Called when user overrides or corrects AI decision.
        """
        # Find decision
        for d in self._decisions:
            if d.id == decision_id:
                d.user_overrode = True
                d.user_feedback = feedback
                d.learned_from = True

                # Adjust confidence for this event type
                if user_action != d.action:
                    # User disagreed - lower confidence for this event type
                    current = self._confidence_adjustments.get(d.event_type, 0.0)
                    self._confidence_adjustments[d.event_type] = current - 0.05
                    logger.info(f"Lowered confidence for {d.event_type} (user correction)")
                else:
                    # User agreed - increase confidence
                    current = self._confidence_adjustments.get(d.event_type, 0.0)
                    self._confidence_adjustments[d.event_type] = current + 0.02
                    logger.info(f"Raised confidence for {d.event_type} (user confirmed)")

                break

    def answer_prompt(self, prompt_id: str, answer: str):
        """Handle user answer to a prompt."""
        if prompt_id in self._pending_prompts:
            prompt = self._pending_prompts[prompt_id]
            prompt.answered = True
            prompt.answer = answer
            logger.info(f"User answered prompt {prompt_id}: {answer}")
