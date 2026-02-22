"""
SLA AI Engine

Central coordinator for intelligent network monitoring and failover.

Integrates:
    - Metrics collection
    - LSTM prediction
    - Cost-aware failback
    - DNS intelligence
    - PBR integration

The engine is the main entry point for SLA AI.
"""

import asyncio
import json
import os
import signal
import logging
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, Optional, Callable
from enum import Enum

from .config import SLAAIConfig, load_config
from .database import SLAAIDatabase
from .metrics_collector import MetricsCollector, WANMetrics
from .predictor import LSTMPredictor, Prediction
from .failback import FailbackIntelligence, HealthCheck, FailbackPolicy
from .cost_tracker import CostTracker
from .dns_intelligence import DNSIntelligence

logger = logging.getLogger(__name__)


class SLAState(Enum):
    """SLA AI system states."""
    INITIALIZING = "initializing"
    PRIMARY_ACTIVE = "primary_active"
    FAILOVER_IN_PROGRESS = "failover_in_progress"
    BACKUP_ACTIVE = "backup_active"
    FAILBACK_IN_PROGRESS = "failback_in_progress"
    DEGRADED = "degraded"
    ERROR = "error"


@dataclass
class SLAStatus:
    """Current SLA status for reporting."""
    state: str
    timestamp: datetime
    primary_interface: str
    backup_interface: str
    active_interface: str
    primary_health: float
    backup_health: float
    prediction: Optional[Dict] = None
    cost_status: Optional[Dict] = None
    dns_status: Optional[Dict] = None
    failback_status: Optional[Dict] = None
    uptime_pct: float = 100.0
    failover_count_24h: int = 0

    def to_dict(self) -> Dict:
        return {
            "state": self.state,
            "timestamp": self.timestamp.isoformat(),
            "primary_interface": self.primary_interface,
            "backup_interface": self.backup_interface,
            "active_interface": self.active_interface,
            "primary_health": self.primary_health,
            "backup_health": self.backup_health,
            "prediction": self.prediction,
            "cost_status": self.cost_status,
            "dns_status": self.dns_status,
            "failback_status": self.failback_status,
            "uptime_pct": self.uptime_pct,
            "failover_count_24h": self.failover_count_24h,
        }


class SLAEngine:
    """
    SLA AI Engine - Central coordinator.

    Responsibilities:
        - Collect metrics from all WAN interfaces
        - Run LSTM predictions for failure detection
        - Make intelligent failover/failback decisions
        - Track costs for metered connections
        - Manage DNS provider selection
        - Integrate with PBR for route switching
    """

    # State file for PBR integration
    STATE_FILE = "/run/fortress/slaai-recommendation.json"
    STATE_DIR = "/run/fortress"

    def __init__(
        self,
        config: Optional[SLAAIConfig] = None,
        config_path: Optional[str] = None,
    ):
        """
        Initialize SLA engine.

        Args:
            config: Configuration object
            config_path: Path to config file (if config not provided)
        """
        self.config = config or load_config(config_path)
        self._running = False
        self._state = SLAState.INITIALIZING

        # Initialize components
        self.database = SLAAIDatabase(self.config.database_path)

        self.metrics = MetricsCollector(
            ping_targets=self.config.ping_targets,
            dns_test_servers=["1.1.1.1", "8.8.8.8"],
            database=self.database,
        )

        self.predictor = LSTMPredictor(
            database=self.database,
            model_path=self.config.predictor.model_path if self.config.predictor else None,
            window_size=self.config.predictor.lookback_window if self.config.predictor else 12,
        )

        self.cost_tracker = CostTracker(database=self.database)

        # Setup cost budgets for metered interfaces
        if self.config.backup and self.config.backup.metered:
            self.cost_tracker.set_budget(
                self.config.backup.name,
                daily_mb=self.config.backup.daily_budget_mb,
                monthly_mb=self.config.backup.monthly_budget_mb,
                cost_per_gb=self.config.backup.cost_per_gb,
            )

        # Failback policy
        failback_policy = FailbackPolicy(
            min_backup_duration_s=self.config.failback.min_failover_duration_s if self.config.failback else 120,
            primary_stable_duration_s=self.config.failback.min_primary_stable_s if self.config.failback else 60,
            health_checks_required=self.config.failback.health_checks_required if self.config.failback else 5,
            metered_failback_urgency=self.config.failback.metered_urgency_multiplier if self.config.failback else 1.5,
        )

        self.failback = FailbackIntelligence(
            policy=failback_policy,
            cost_tracker=self.cost_tracker,
            predictor=self.predictor,
            database=self.database,
        )

        self.dns = DNSIntelligence(
            database=self.database,
            check_interval_s=self.config.dns.health_check_interval_s if self.config.dns else 60,
        )

        # Interface tracking
        self._primary_interface = self.config.primary.name if self.config.primary else "eth0"
        self._backup_interface = self.config.backup.name if self.config.backup else "wwan0"
        self._active_interface = self._primary_interface

        # Set interfaces on failback
        self.failback.set_interfaces(self._primary_interface, self._backup_interface)

        # Metrics history
        self._latest_metrics: Dict[str, WANMetrics] = {}
        self._latest_predictions: Dict[str, Prediction] = {}

        # Callbacks
        self._on_failover: Optional[Callable] = None
        self._on_failback: Optional[Callable] = None
        self._on_state_change: Optional[Callable] = None

        # Statistics
        self._start_time: Optional[datetime] = None
        self._failover_count = 0
        self._downtime_seconds = 0

        logger.info(
            f"SLA Engine initialized: primary={self._primary_interface}, "
            f"backup={self._backup_interface}"
        )

    def set_callbacks(
        self,
        on_failover: Optional[Callable] = None,
        on_failback: Optional[Callable] = None,
        on_state_change: Optional[Callable] = None,
    ) -> None:
        """Set callback functions for events."""
        self._on_failover = on_failover
        self._on_failback = on_failback
        self._on_state_change = on_state_change

    async def run(self) -> None:
        """Main engine loop."""
        self._running = True
        self._start_time = datetime.now()

        # Ensure state directory exists
        os.makedirs(self.STATE_DIR, exist_ok=True)

        # Initial state
        await self._set_state(SLAState.PRIMARY_ACTIVE)

        # Start background tasks
        tasks = [
            asyncio.create_task(self._metrics_loop()),
            asyncio.create_task(self._prediction_loop()),
            asyncio.create_task(self._decision_loop()),
            asyncio.create_task(self._dns_loop()),
            asyncio.create_task(self._status_loop()),
        ]

        logger.info("SLA AI Engine started")

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("SLA AI Engine stopping...")
        finally:
            self._running = False
            for task in tasks:
                task.cancel()

    async def stop(self) -> None:
        """Stop the engine."""
        self._running = False

    async def _metrics_loop(self) -> None:
        """Collect metrics periodically."""
        interval = self.config.check_interval_s

        while self._running:
            try:
                # Collect from all interfaces
                for interface in [self._primary_interface, self._backup_interface]:
                    metrics = await self.metrics.collect(interface)
                    self._latest_metrics[interface] = metrics

                    # Update predictor with new metrics
                    self.predictor.update_features(interface, metrics)

                    # Update cost tracker if metered
                    if self.cost_tracker.is_metered(interface):
                        self.cost_tracker.record_usage(
                            interface,
                            metrics.bytes_sent,
                            metrics.bytes_received,
                        )

                    # Store in database
                    self.database.store_metrics(metrics)

                    # Create health check for failback
                    is_healthy = (
                        metrics.packet_loss_pct < 5 and
                        (metrics.rtt_ms or 0) < 200 and
                        (metrics.jitter_ms or 0) < 50
                    )

                    health_check = HealthCheck(
                        timestamp=datetime.now(),
                        interface=interface,
                        rtt_ms=metrics.rtt_ms or 0,
                        packet_loss_pct=metrics.packet_loss_pct,
                        is_healthy=is_healthy,
                    )
                    self.failback.record_health_check(health_check)

            except Exception as e:
                logger.error(f"Metrics collection error: {e}")

            await asyncio.sleep(interval)

    async def _prediction_loop(self) -> None:
        """Run predictions periodically."""
        if not self.config.predictor or not self.config.predictor.enabled:
            return

        interval = self.config.prediction_interval_s

        while self._running:
            try:
                for interface in [self._primary_interface, self._backup_interface]:
                    prediction = self.predictor.predict(interface)
                    self._latest_predictions[interface] = prediction

                    logger.debug(
                        f"Prediction for {interface}: {prediction.state} "
                        f"({prediction.confidence*100:.0f}%)"
                    )

            except Exception as e:
                logger.error(f"Prediction error: {e}")

            await asyncio.sleep(interval)

    async def _decision_loop(self) -> None:
        """Make failover/failback decisions."""
        interval = self.config.check_interval_s

        while self._running:
            try:
                await self._evaluate_and_act()
            except Exception as e:
                logger.error(f"Decision error: {e}")

            await asyncio.sleep(interval)

    async def _evaluate_and_act(self) -> None:
        """Evaluate current state and take action if needed."""
        primary_metrics = self._latest_metrics.get(self._primary_interface)
        primary_prediction = self._latest_predictions.get(self._primary_interface)

        # Calculate health scores
        primary_health = self._calculate_health(primary_metrics)

        # Current state handling
        if self._state == SLAState.PRIMARY_ACTIVE:
            # Check if failover needed
            should_failover, reason = self._should_failover(
                primary_metrics, primary_prediction, primary_health
            )

            if should_failover:
                await self._do_failover(reason)

        elif self._state == SLAState.BACKUP_ACTIVE:
            # Evaluate failback
            decision = self.failback.evaluate(current_on_backup=True)

            if decision.should_failback:
                await self._do_failback(decision.reason)

        # Write state file for PBR
        await self._write_state_file()

    def _calculate_health(self, metrics: Optional[WANMetrics]) -> float:
        """Calculate health score 0-1 from metrics."""
        if not metrics:
            return 0.0

        score = 1.0

        # RTT penalty
        if metrics.rtt_ms:
            if metrics.rtt_ms > 200:
                score -= 0.3
            elif metrics.rtt_ms > 100:
                score -= 0.1

        # Packet loss penalty
        if metrics.packet_loss_pct > 10:
            score -= 0.5
        elif metrics.packet_loss_pct > 2:
            score -= 0.2

        # Jitter penalty
        if metrics.jitter_ms and metrics.jitter_ms > 50:
            score -= 0.2

        return max(0.0, score)

    def _should_failover(
        self,
        metrics: Optional[WANMetrics],
        prediction: Optional[Prediction],
        health: float,
    ) -> tuple:
        """Determine if failover is needed."""
        if not metrics:
            return True, "No metrics from primary"

        # Immediate failover on high packet loss
        if metrics.packet_loss_pct > 50:
            return True, f"High packet loss: {metrics.packet_loss_pct}%"

        # Failover on connection timeout
        if metrics.rtt_ms is None or metrics.rtt_ms > 1000:
            return True, "Primary timeout or very high latency"

        # Prediction-based failover
        if prediction:
            threshold = self.config.failover.prediction_threshold if self.config.failover else 0.6
            immediate = self.config.failover.immediate_threshold if self.config.failover else 0.8

            if prediction.state == "failure":
                if prediction.confidence >= immediate:
                    return True, f"Failure predicted ({prediction.confidence*100:.0f}%)"
                elif prediction.confidence >= threshold:
                    logger.warning(
                        f"Potential failure predicted ({prediction.confidence*100:.0f}%), monitoring..."
                    )

        # Health-based failover
        if health < 0.3:
            return True, f"Primary health critical: {health*100:.0f}%"

        return False, ""

    async def _do_failover(self, reason: str) -> None:
        """Execute failover to backup."""
        logger.warning(f"FAILOVER: {self._primary_interface} -> {self._backup_interface}: {reason}")

        await self._set_state(SLAState.FAILOVER_IN_PROGRESS)

        # Record failover event
        self.failback.record_failover(self._primary_interface, self._backup_interface)
        self._failover_count += 1

        # Store in database
        self.database.store_failover_event(
            from_interface=self._primary_interface,
            to_interface=self._backup_interface,
            trigger="automatic",
            reason=reason,
        )

        # Update active interface
        self._active_interface = self._backup_interface

        # Call callback
        if self._on_failover:
            try:
                if asyncio.iscoroutinefunction(self._on_failover):
                    await self._on_failover(self._primary_interface, self._backup_interface, reason)
                else:
                    self._on_failover(self._primary_interface, self._backup_interface, reason)
            except Exception as e:
                logger.error(f"Failover callback error: {e}")

        await self._set_state(SLAState.BACKUP_ACTIVE)

    async def _do_failback(self, reason: str) -> None:
        """Execute failback to primary."""
        logger.info(f"FAILBACK: {self._backup_interface} -> {self._primary_interface}: {reason}")

        await self._set_state(SLAState.FAILBACK_IN_PROGRESS)

        # Store in database
        self.database.store_failover_event(
            from_interface=self._backup_interface,
            to_interface=self._primary_interface,
            trigger="failback",
            reason=reason,
        )

        # Update active interface
        self._active_interface = self._primary_interface

        # Call callback
        if self._on_failback:
            try:
                if asyncio.iscoroutinefunction(self._on_failback):
                    await self._on_failback(self._backup_interface, self._primary_interface, reason)
                else:
                    self._on_failback(self._backup_interface, self._primary_interface, reason)
            except Exception as e:
                logger.error(f"Failback callback error: {e}")

        await self._set_state(SLAState.PRIMARY_ACTIVE)

    async def _set_state(self, new_state: SLAState) -> None:
        """Update engine state."""
        if new_state == self._state:
            return

        old_state = self._state
        self._state = new_state

        logger.info(f"State change: {old_state.value} -> {new_state.value}")

        # Store state history
        self.database.store_state_change(old_state.value, new_state.value)

        # Call callback
        if self._on_state_change:
            try:
                if asyncio.iscoroutinefunction(self._on_state_change):
                    await self._on_state_change(old_state.value, new_state.value)
                else:
                    self._on_state_change(old_state.value, new_state.value)
            except Exception as e:
                logger.error(f"State change callback error: {e}")

    async def _dns_loop(self) -> None:
        """Monitor and update DNS."""
        if not self.config.dns or not self.config.dns.enabled:
            return

        while self._running:
            try:
                changed = await self.dns.update_if_needed()
                if changed:
                    logger.info("DNS providers updated")
            except Exception as e:
                logger.error(f"DNS update error: {e}")

            await asyncio.sleep(self.config.dns.health_check_interval_s)

    async def _status_loop(self) -> None:
        """Periodically write status file."""
        while self._running:
            try:
                await self._write_state_file()
            except Exception as e:
                logger.error(f"Status write error: {e}")

            await asyncio.sleep(10)  # Every 10 seconds

    async def _write_state_file(self) -> None:
        """Write recommendation to state file for PBR integration."""
        primary_metrics = self._latest_metrics.get(self._primary_interface)
        backup_metrics = self._latest_metrics.get(self._backup_interface)
        primary_prediction = self._latest_predictions.get(self._primary_interface)

        # Determine recommendation
        if self._state == SLAState.BACKUP_ACTIVE:
            decision = self.failback.evaluate(current_on_backup=True)
            recommendation = "failback" if decision.should_failback else "hold"
            confidence = decision.confidence
            reason = decision.reason
        elif self._state == SLAState.PRIMARY_ACTIVE:
            primary_health = self._calculate_health(primary_metrics)
            should_failover, failover_reason = self._should_failover(
                primary_metrics, primary_prediction, primary_health
            )
            recommendation = "failover" if should_failover else "hold"
            confidence = 0.9 if should_failover else 0.5
            reason = failover_reason if should_failover else "Primary healthy"
        else:
            recommendation = "hold"
            confidence = 0.5
            reason = f"State: {self._state.value}"

        # Build state data
        state_data = {
            "timestamp": datetime.now().isoformat(),
            "recommendation": recommendation,
            "confidence": confidence,
            "reason": reason,
            "active_interface": self._active_interface,
            "state": self._state.value,
            "primary_status": self._metrics_to_dict(primary_metrics),
            "backup_status": self._metrics_to_dict(backup_metrics),
        }

        # Add cost status if on metered backup
        if self._active_interface == self._backup_interface:
            cost_status = self.cost_tracker.get_status(self._backup_interface)
            state_data["cost_status"] = {
                "daily_usage_mb": cost_status.daily_bytes / (1024 * 1024),
                "daily_budget_mb": cost_status.daily_limit_bytes / (1024 * 1024),
                "monthly_usage_mb": cost_status.monthly_bytes / (1024 * 1024),
                "monthly_budget_mb": cost_status.monthly_limit_bytes / (1024 * 1024),
                "urgency_score": cost_status.urgency_score,
            }

        # Write to file
        try:
            with open(self.STATE_FILE, "w") as f:
                json.dump(state_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write state file: {e}")

    def _metrics_to_dict(self, metrics: Optional[WANMetrics]) -> Dict:
        """Convert metrics to dict for state file."""
        if not metrics:
            return {"health": "unknown"}

        health = self._calculate_health(metrics)
        health_label = "healthy" if health > 0.7 else "degraded" if health > 0.4 else "critical"

        return {
            "health": health_label,
            "health_score": health,
            "rtt_ms": metrics.rtt_ms,
            "packet_loss_pct": metrics.packet_loss_pct,
            "jitter_ms": metrics.jitter_ms,
            "signal_rssi_dbm": metrics.signal_rssi_dbm,
            "network_type": metrics.network_type,
        }

    def get_status(self) -> SLAStatus:
        """Get current SLA status."""
        primary_metrics = self._latest_metrics.get(self._primary_interface)
        backup_metrics = self._latest_metrics.get(self._backup_interface)

        primary_health = self._calculate_health(primary_metrics)
        backup_health = self._calculate_health(backup_metrics)

        # Get prediction for primary
        prediction = None
        if self._primary_interface in self._latest_predictions:
            pred = self._latest_predictions[self._primary_interface]
            prediction = pred.to_dict()

        # Get cost status if on backup
        cost_status = None
        if self._active_interface == self._backup_interface:
            status = self.cost_tracker.get_status(self._backup_interface)
            cost_status = {
                "daily_pct": status.daily_pct,
                "monthly_pct": status.monthly_pct,
                "estimated_cost": status.estimated_monthly_cost,
            }

        # Calculate uptime
        uptime_pct = 100.0
        if self._start_time and self._downtime_seconds > 0:
            total_seconds = (datetime.now() - self._start_time).total_seconds()
            if total_seconds > 0:
                uptime_pct = ((total_seconds - self._downtime_seconds) / total_seconds) * 100

        return SLAStatus(
            state=self._state.value,
            timestamp=datetime.now(),
            primary_interface=self._primary_interface,
            backup_interface=self._backup_interface,
            active_interface=self._active_interface,
            primary_health=primary_health,
            backup_health=backup_health,
            prediction=prediction,
            cost_status=cost_status,
            dns_status=self.dns.get_summary() if self.config.dns and self.config.dns.enabled else None,
            failback_status=self.failback.get_state(),
            uptime_pct=uptime_pct,
            failover_count_24h=self._failover_count,
        )

    def get_metrics(self, interface: str) -> Optional[WANMetrics]:
        """Get latest metrics for an interface."""
        return self._latest_metrics.get(interface)

    def get_prediction(self, interface: str) -> Optional[Prediction]:
        """Get latest prediction for an interface."""
        return self._latest_predictions.get(interface)


async def main():
    """Main entry point for standalone execution."""
    import argparse

    parser = argparse.ArgumentParser(description="SLA AI Engine")
    parser.add_argument("--config", "-c", help="Path to config file")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Setup logging
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Load config
    config = load_config(args.config)

    # Create engine
    engine = SLAEngine(config=config)

    # Setup signal handlers
    loop = asyncio.get_event_loop()

    def handle_signal():
        asyncio.create_task(engine.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)

    # Run engine
    await engine.run()


if __name__ == "__main__":
    asyncio.run(main())
