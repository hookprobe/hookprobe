"""
MSSP Recommendation Handler

Receives, validates, and executes recommended actions from MSSP/Nexus.
Works with all tiers via the AEGIS principle guard pipeline.

Flow:
    MSSP/Mesh → verify signature → principle guard → execute → feedback

Security:
    - Ed25519 signature verification (or HMAC fallback)
    - AEGIS principle guard (never disable protection, etc.)
    - Rate limiting on incoming recommendations
    - Audit trail for every action
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .auth import verify_recommendation_signature
from .types import ExecutionFeedback, RecommendedAction

logger = logging.getLogger(__name__)

# Rate limiting
MAX_RECOMMENDATIONS_PER_MINUTE = 20
RATE_WINDOW = 60.0

# AEGIS principle guard: forbidden actions
FORBIDDEN_ACTIONS = frozenset({
    "disable_firewall",
    "disable_ids",
    "disable_napse",
    "stop_aegis",
    "expose_credentials",
    "disable_encryption",
})


class RecommendationHandler:
    """Validates and executes MSSP recommendations on edge nodes.

    Provides a tier-agnostic execution pipeline:
    1. Signature verification
    2. Principle guard check
    3. Action execution via callbacks
    4. Feedback reporting
    """

    def __init__(
        self,
        mssp_client=None,
        execute_callback: Optional[Callable[[Dict], bool]] = None,
    ):
        self._mssp_client = mssp_client
        self._execute_callback = execute_callback

        # Rate limiting
        self._rate_counter = 0
        self._rate_window_start = time.time()
        self._lock = threading.Lock()

        # Statistics
        self._stats = {
            "received": 0,
            "verified": 0,
            "rejected_signature": 0,
            "rejected_principle": 0,
            "rejected_rate_limit": 0,
            "executed": 0,
            "failed": 0,
        }

        # Audit trail
        self._audit: List[Dict] = []

    def handle(self, action: RecommendedAction) -> bool:
        """Handle a single recommendation through the full pipeline.

        Args:
            action: The recommended action to process.

        Returns:
            True if the action was executed successfully.
        """
        self._stats["received"] += 1
        action_dict = action.to_dict()

        # Step 1: Rate limit check
        if not self._check_rate_limit():
            self._stats["rejected_rate_limit"] += 1
            logger.warning("Recommendation rate limit exceeded")
            return False

        # Step 2: Signature verification
        if not verify_recommendation_signature(action_dict):
            self._stats["rejected_signature"] += 1
            self._audit_log("rejected", action.action_id, "invalid_signature")
            logger.warning(
                "Rejected recommendation %s: invalid signature",
                action.action_id,
            )
            return False

        self._stats["verified"] += 1

        # Step 3: Principle guard
        if not self._check_principles(action):
            self._stats["rejected_principle"] += 1
            self._audit_log("rejected", action.action_id, "principle_violation")
            logger.warning(
                "Rejected recommendation %s: violates AEGIS principles",
                action.action_id,
            )
            return False

        # Step 4: Acknowledge receipt
        if self._mssp_client:
            try:
                self._mssp_client.acknowledge_recommendation(action.action_id)
            except Exception as e:
                logger.debug("Acknowledgement failed: %s", e)

        # Step 5: Execute
        success = self._execute(action)

        # Step 6: Report feedback
        if self._mssp_client:
            self._report_feedback(action, success)

        return success

    def handle_batch(self, actions: List[RecommendedAction]) -> Dict[str, bool]:
        """Handle multiple recommendations.

        Returns:
            Dict mapping action_id to success status.
        """
        results = {}
        # Sort by priority (lower = higher priority)
        sorted_actions = sorted(actions, key=lambda a: a.priority)
        for action in sorted_actions:
            results[action.action_id] = self.handle(action)
        return results

    def set_execute_callback(self, callback: Callable[[Dict], bool]) -> None:
        """Set the callback for executing defense actions."""
        self._execute_callback = callback

    def set_mssp_client(self, client) -> None:
        """Set the MSSP client for acknowledgements and feedback."""
        self._mssp_client = client

    def get_stats(self) -> Dict:
        """Get handler statistics."""
        return {**self._stats}

    def get_audit_trail(self, limit: int = 50) -> List[Dict]:
        """Get recent audit entries."""
        return self._audit[-limit:]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_rate_limit(self) -> bool:
        """Check if we're within the rate limit."""
        with self._lock:
            now = time.time()
            if now - self._rate_window_start > RATE_WINDOW:
                self._rate_counter = 0
                self._rate_window_start = now

            if self._rate_counter >= MAX_RECOMMENDATIONS_PER_MINUTE:
                return False

            self._rate_counter += 1
            return True

    def _check_principles(self, action: RecommendedAction) -> bool:
        """Check recommendation against AEGIS principles."""
        # Forbidden action types
        if action.action_type in FORBIDDEN_ACTIONS:
            return False

        # Don't execute with zero confidence
        if action.confidence <= 0.0:
            logger.warning("Rejecting recommendation with zero confidence")
            return False

        # TTL sanity check (max 7 days)
        if action.ttl_seconds > 604800:
            logger.warning("Rejecting recommendation with TTL > 7 days")
            return False

        return True

    def _execute(self, action: RecommendedAction) -> bool:
        """Execute a validated recommendation."""
        if not self._execute_callback:
            logger.warning("No execute callback configured")
            return False

        action_dict = {
            "action_type": action.action_type,
            "target": action.target,
            "reasoning": action.reasoning,
            "ttl_seconds": action.ttl_seconds,
            "priority": action.priority,
            "confidence": action.confidence,
        }

        try:
            success = self._execute_callback(action_dict)
            if success:
                self._stats["executed"] += 1
                self._audit_log("executed", action.action_id, action.action_type)
                logger.info(
                    "Executed recommendation %s: %s on %s",
                    action.action_id, action.action_type, action.target,
                )
            else:
                self._stats["failed"] += 1
                self._audit_log("failed", action.action_id, action.action_type)

            return success

        except Exception as e:
            self._stats["failed"] += 1
            self._audit_log("error", action.action_id, str(e))
            logger.error("Execution error for %s: %s", action.action_id, e)
            return False

    def _report_feedback(self, action: RecommendedAction, success: bool) -> None:
        """Report execution feedback to MSSP."""
        try:
            feedback = ExecutionFeedback(
                action_id=action.action_id,
                success=success,
                effect_observed="executed" if success else "execution_failed",
            )
            self._mssp_client.submit_feedback(feedback)
        except Exception as e:
            logger.debug("Feedback submission failed: %s", e)

    def _audit_log(self, status: str, action_id: str, detail: str) -> None:
        """Add entry to audit trail."""
        self._audit.append({
            "timestamp": time.time(),
            "status": status,
            "action_id": action_id,
            "detail": detail,
        })
        # Keep last 500 entries
        if len(self._audit) > 500:
            self._audit = self._audit[-500:]
