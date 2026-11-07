"""
SLA AI Failback Intelligence

Intelligent failback decision-making with:
- Cost awareness for metered connections
- Hysteresis to prevent flapping
- LSTM prediction integration
- Health stability verification
"""

import os
import asyncio
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class FailbackState(Enum):
    """Failback decision states."""
    NOT_READY = "not_ready"           # Conditions not met
    EVALUATING = "evaluating"          # Checking primary stability
    READY = "ready"                    # Ready to failback
    IN_PROGRESS = "in_progress"        # Failback in progress
    COMPLETED = "completed"            # Failback done
    BLOCKED = "blocked"                # Blocked by prediction or policy


@dataclass
class HealthCheck:
    """Result of a single health check."""
    timestamp: datetime
    interface: str
    rtt_ms: float
    packet_loss_pct: float
    is_healthy: bool
    confidence: float = 1.0


@dataclass
class FailbackDecision:
    """Failback decision with reasoning."""
    should_failback: bool
    state: FailbackState
    reason: str
    confidence: float
    primary_health_score: float
    backup_cost_pressure: float
    recommended_wait_s: int = 0

    def to_dict(self) -> Dict:
        return {
            "should_failback": self.should_failback,
            "state": self.state.value,
            "reason": self.reason,
            "confidence": self.confidence,
            "primary_health_score": self.primary_health_score,
            "backup_cost_pressure": self.backup_cost_pressure,
            "recommended_wait_s": self.recommended_wait_s,
        }


@dataclass
class FailbackPolicy:
    """Policy configuration for failback decisions."""
    # Minimum time on backup before considering failback
    min_backup_duration_s: int = 120

    # Primary must be healthy for this long before failback
    primary_stable_duration_s: int = 60

    # Number of successful health checks required
    health_checks_required: int = 5

    # Health check interval
    health_check_interval_s: int = 10

    # Thresholds for "healthy" status
    max_rtt_ms: float = 150.0
    max_packet_loss_pct: float = 2.0
    max_jitter_ms: float = 30.0

    # Metered connection awareness
    metered_failback_urgency: float = 1.5

    # Business hours multiplier (more aggressive failback)
    business_hours: Tuple[int, int] = (9, 18)  # 9 AM to 6 PM
    business_hours_multiplier: float = 1.2

    # LSTM prediction requirements
    min_primary_health_confidence: float = 0.75

    # Flap prevention
    min_time_between_switches_s: int = 300  # 5 minutes
    max_switches_per_hour: int = 4


class FailbackIntelligence:
    """
    Intelligent failback decision engine.

    Makes smart decisions about when to switch back to primary WAN
    based on:
        - Primary WAN health stability over time
        - Backup WAN cost pressure (metered usage)
        - LSTM predictions for primary reliability
        - Business hours and usage patterns
        - Flap prevention
    """

    def __init__(
        self,
        policy: Optional[FailbackPolicy] = None,
        cost_tracker=None,
        predictor=None,
        database=None,
    ):
        """
        Initialize failback intelligence.

        Args:
            policy: Failback policy configuration
            cost_tracker: CostTracker instance for metered awareness
            predictor: LSTMPredictor instance for health predictions
            database: SLAAIDatabase for historical data
        """
        self.policy = policy or FailbackPolicy()
        self.cost_tracker = cost_tracker
        self.predictor = predictor
        self.database = database

        # State tracking
        self._health_checks: Dict[str, List[HealthCheck]] = {}
        self._failover_timestamp: Optional[datetime] = None
        self._last_switch_timestamp: Optional[datetime] = None
        self._switch_count_hour: int = 0
        self._switch_count_reset: Optional[datetime] = None
        self._current_state: FailbackState = FailbackState.NOT_READY

        # Current active interfaces
        self._primary_interface: Optional[str] = None
        self._backup_interface: Optional[str] = None

    def set_interfaces(self, primary: str, backup: str) -> None:
        """Set primary and backup interface names."""
        self._primary_interface = primary
        self._backup_interface = backup
        logger.info(f"Failback interfaces: primary={primary}, backup={backup}")

    def record_failover(self, from_interface: str, to_interface: str) -> None:
        """Record that a failover has occurred."""
        self._failover_timestamp = datetime.now()
        self._current_state = FailbackState.NOT_READY
        self._health_checks.clear()

        # Track switch count for flap prevention
        now = datetime.now()
        if self._switch_count_reset is None or now - self._switch_count_reset > timedelta(hours=1):
            self._switch_count_reset = now
            self._switch_count_hour = 0

        self._switch_count_hour += 1
        self._last_switch_timestamp = now

        logger.info(
            f"Failover recorded: {from_interface} -> {to_interface} "
            f"(switches this hour: {self._switch_count_hour})"
        )

    def record_health_check(self, check: HealthCheck) -> None:
        """Record a health check result."""
        if check.interface not in self._health_checks:
            self._health_checks[check.interface] = []

        self._health_checks[check.interface].append(check)

        # Keep only recent checks (based on policy)
        max_age = timedelta(seconds=self.policy.primary_stable_duration_s * 2)
        cutoff = datetime.now() - max_age
        self._health_checks[check.interface] = [
            c for c in self._health_checks[check.interface]
            if c.timestamp > cutoff
        ]

    def evaluate(self, current_on_backup: bool = True) -> FailbackDecision:
        """
        Evaluate whether failback should occur.

        Args:
            current_on_backup: True if currently using backup WAN

        Returns:
            FailbackDecision with recommendation and reasoning
        """
        if not current_on_backup:
            return FailbackDecision(
                should_failback=False,
                state=FailbackState.NOT_READY,
                reason="Already on primary WAN",
                confidence=1.0,
                primary_health_score=1.0,
                backup_cost_pressure=0.0,
            )

        # Check flap prevention
        if not self._check_flap_prevention():
            return FailbackDecision(
                should_failback=False,
                state=FailbackState.BLOCKED,
                reason=f"Flap prevention: {self._switch_count_hour} switches in last hour",
                confidence=1.0,
                primary_health_score=0.0,
                backup_cost_pressure=self._get_cost_pressure(),
                recommended_wait_s=self._get_flap_wait_time(),
            )

        # Check minimum backup duration
        if not self._check_min_backup_duration():
            wait_time = self._get_min_duration_wait()
            return FailbackDecision(
                should_failback=False,
                state=FailbackState.NOT_READY,
                reason=f"Minimum backup duration not met ({wait_time}s remaining)",
                confidence=1.0,
                primary_health_score=0.0,
                backup_cost_pressure=self._get_cost_pressure(),
                recommended_wait_s=wait_time,
            )

        # Check primary health stability
        health_score, health_reason = self._evaluate_primary_health()

        if health_score < 0.7:
            self._current_state = FailbackState.NOT_READY
            return FailbackDecision(
                should_failback=False,
                state=FailbackState.NOT_READY,
                reason=f"Primary unhealthy: {health_reason}",
                confidence=1.0 - health_score,
                primary_health_score=health_score,
                backup_cost_pressure=self._get_cost_pressure(),
            )

        # Check LSTM prediction if available
        prediction_ok, prediction_reason = self._check_prediction()
        if not prediction_ok:
            self._current_state = FailbackState.BLOCKED
            return FailbackDecision(
                should_failback=False,
                state=FailbackState.BLOCKED,
                reason=f"Prediction warns: {prediction_reason}",
                confidence=0.7,
                primary_health_score=health_score,
                backup_cost_pressure=self._get_cost_pressure(),
                recommended_wait_s=60,
            )

        # Calculate urgency based on cost pressure
        cost_pressure = self._get_cost_pressure()
        urgency_multiplier = self._calculate_urgency_multiplier(cost_pressure)

        # Determine if we have enough healthy checks
        required_checks = max(1, int(self.policy.health_checks_required / urgency_multiplier))
        healthy_checks = self._count_healthy_checks()

        if healthy_checks < required_checks:
            self._current_state = FailbackState.EVALUATING
            return FailbackDecision(
                should_failback=False,
                state=FailbackState.EVALUATING,
                reason=f"Need {required_checks - healthy_checks} more healthy checks",
                confidence=healthy_checks / required_checks,
                primary_health_score=health_score,
                backup_cost_pressure=cost_pressure,
                recommended_wait_s=self.policy.health_check_interval_s,
            )

        # All conditions met - recommend failback
        self._current_state = FailbackState.READY
        confidence = min(1.0, health_score * (0.8 + 0.2 * cost_pressure))

        return FailbackDecision(
            should_failback=True,
            state=FailbackState.READY,
            reason=self._build_failback_reason(health_score, cost_pressure, urgency_multiplier),
            confidence=confidence,
            primary_health_score=health_score,
            backup_cost_pressure=cost_pressure,
        )

    def _check_flap_prevention(self) -> bool:
        """Check if flap prevention allows switching."""
        # Check max switches per hour
        if self._switch_count_hour >= self.policy.max_switches_per_hour:
            return False

        # Check minimum time between switches
        if self._last_switch_timestamp:
            elapsed = (datetime.now() - self._last_switch_timestamp).total_seconds()
            if elapsed < self.policy.min_time_between_switches_s:
                return False

        return True

    def _get_flap_wait_time(self) -> int:
        """Get seconds to wait for flap prevention."""
        if self._last_switch_timestamp:
            elapsed = (datetime.now() - self._last_switch_timestamp).total_seconds()
            remaining = self.policy.min_time_between_switches_s - elapsed
            return max(0, int(remaining))
        return 0

    def _check_min_backup_duration(self) -> bool:
        """Check if minimum backup duration has passed."""
        if not self._failover_timestamp:
            return True

        elapsed = (datetime.now() - self._failover_timestamp).total_seconds()
        return elapsed >= self.policy.min_backup_duration_s

    def _get_min_duration_wait(self) -> int:
        """Get seconds remaining for minimum backup duration."""
        if not self._failover_timestamp:
            return 0

        elapsed = (datetime.now() - self._failover_timestamp).total_seconds()
        remaining = self.policy.min_backup_duration_s - elapsed
        return max(0, int(remaining))

    def _evaluate_primary_health(self) -> Tuple[float, str]:
        """
        Evaluate primary interface health.

        Returns:
            Tuple of (health_score 0-1, reason_string)
        """
        if not self._primary_interface:
            return 0.0, "Primary interface not set"

        checks = self._health_checks.get(self._primary_interface, [])

        if not checks:
            return 0.0, "No health checks recorded"

        # Need checks spanning stability duration
        now = datetime.now()
        stability_window = timedelta(seconds=self.policy.primary_stable_duration_s)
        recent_checks = [c for c in checks if now - c.timestamp <= stability_window]

        if len(recent_checks) < 3:
            return 0.3, f"Only {len(recent_checks)} checks in stability window"

        # Calculate health metrics
        healthy_count = sum(1 for c in recent_checks if c.is_healthy)
        healthy_ratio = healthy_count / len(recent_checks)

        avg_rtt = sum(c.rtt_ms for c in recent_checks) / len(recent_checks)
        avg_loss = sum(c.packet_loss_pct for c in recent_checks) / len(recent_checks)

        # Calculate composite score
        rtt_score = max(0, 1 - (avg_rtt / self.policy.max_rtt_ms))
        loss_score = max(0, 1 - (avg_loss / self.policy.max_packet_loss_pct))

        health_score = (healthy_ratio * 0.4 + rtt_score * 0.3 + loss_score * 0.3)

        reason = f"RTT={avg_rtt:.0f}ms, loss={avg_loss:.1f}%, healthy={healthy_ratio*100:.0f}%"

        return health_score, reason

    def _check_prediction(self) -> Tuple[bool, str]:
        """
        Check LSTM prediction for primary interface.

        Returns:
            Tuple of (is_ok, reason_string)
        """
        if not self.predictor or not self._primary_interface:
            return True, "No predictor available"

        try:
            prediction = self.predictor.predict(self._primary_interface)

            if prediction.state == "failure" and prediction.confidence > 0.6:
                return False, f"Failure predicted ({prediction.confidence*100:.0f}% confidence)"

            if prediction.state == "degraded" and prediction.confidence > 0.8:
                return False, f"Degradation predicted ({prediction.confidence*100:.0f}% confidence)"

            if prediction.state == "healthy" and prediction.confidence >= self.policy.min_primary_health_confidence:
                return True, f"Healthy predicted ({prediction.confidence*100:.0f}% confidence)"

            return True, f"Prediction unclear: {prediction.state} ({prediction.confidence*100:.0f}%)"

        except Exception as e:
            logger.warning(f"Prediction check failed: {e}")
            return True, "Prediction unavailable"

    def _get_cost_pressure(self) -> float:
        """
        Get cost pressure from metered backup connection.

        Returns:
            Pressure score 0-1 (higher = more urgent to failback)
        """
        if not self.cost_tracker or not self._backup_interface:
            return 0.0

        try:
            status = self.cost_tracker.get_status(self._backup_interface)
            return status.urgency_score
        except Exception as e:
            logger.warning(f"Cost pressure check failed: {e}")
            return 0.0

    def _calculate_urgency_multiplier(self, cost_pressure: float) -> float:
        """
        Calculate urgency multiplier for failback.

        Higher multiplier = faster failback.
        """
        multiplier = 1.0

        # Add cost pressure (metered connection urgency)
        if cost_pressure > 0:
            multiplier += cost_pressure * (self.policy.metered_failback_urgency - 1)

        # Add business hours multiplier
        if self._is_business_hours():
            multiplier *= self.policy.business_hours_multiplier

        return min(3.0, multiplier)

    def _is_business_hours(self) -> bool:
        """Check if current time is within business hours."""
        hour = datetime.now().hour
        start, end = self.policy.business_hours
        return start <= hour < end

    def _count_healthy_checks(self) -> int:
        """Count healthy checks for primary in stability window."""
        if not self._primary_interface:
            return 0

        checks = self._health_checks.get(self._primary_interface, [])
        now = datetime.now()
        stability_window = timedelta(seconds=self.policy.primary_stable_duration_s)

        return sum(
            1 for c in checks
            if c.is_healthy and now - c.timestamp <= stability_window
        )

    def _build_failback_reason(
        self,
        health_score: float,
        cost_pressure: float,
        urgency: float,
    ) -> str:
        """Build human-readable failback reason."""
        reasons = []

        reasons.append(f"Primary healthy ({health_score*100:.0f}%)")

        if cost_pressure > 0.5:
            reasons.append(f"High backup cost pressure ({cost_pressure*100:.0f}%)")
        elif cost_pressure > 0.2:
            reasons.append(f"Moderate backup cost ({cost_pressure*100:.0f}%)")

        if urgency > 1.5:
            reasons.append(f"Urgency multiplier {urgency:.1f}x")

        if self._is_business_hours():
            reasons.append("Business hours priority")

        return "; ".join(reasons)

    async def monitor_and_decide(
        self,
        check_interval_s: Optional[int] = None,
        on_decision: Optional[callable] = None,
    ) -> None:
        """
        Continuous monitoring loop for failback decisions.

        Args:
            check_interval_s: Override policy check interval
            on_decision: Callback for decisions (async or sync)
        """
        interval = check_interval_s or self.policy.health_check_interval_s

        while True:
            try:
                decision = self.evaluate(current_on_backup=True)

                if on_decision:
                    if asyncio.iscoroutinefunction(on_decision):
                        await on_decision(decision)
                    else:
                        on_decision(decision)

                if decision.should_failback:
                    logger.info(f"Failback recommended: {decision.reason}")
                    break

            except Exception as e:
                logger.error(f"Failback evaluation error: {e}")

            await asyncio.sleep(interval)

    def get_state(self) -> Dict:
        """Get current failback state for status reporting."""
        return {
            "state": self._current_state.value,
            "primary_interface": self._primary_interface,
            "backup_interface": self._backup_interface,
            "failover_timestamp": self._failover_timestamp.isoformat() if self._failover_timestamp else None,
            "switch_count_hour": self._switch_count_hour,
            "health_checks": {
                iface: len(checks)
                for iface, checks in self._health_checks.items()
            },
        }
