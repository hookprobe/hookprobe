"""
SLA AI Cost Tracker

Tracks data usage on metered connections (LTE) and provides
cost-aware recommendations for failover/failback decisions.
"""

import os
from datetime import datetime, date, timedelta
from dataclasses import dataclass
from typing import Dict, Optional, List
import logging

logger = logging.getLogger(__name__)


@dataclass
class UsageBudget:
    """Data usage budget for a metered interface."""
    daily_limit_bytes: int = 0
    monthly_limit_bytes: int = 0
    cost_per_gb: float = 0.0
    overage_cost_per_gb: float = 0.0  # Cost after exceeding budget


@dataclass
class UsageStatus:
    """Current usage status for an interface."""
    interface: str
    daily_bytes: int = 0
    daily_limit_bytes: int = 0
    daily_pct: float = 0.0
    monthly_bytes: int = 0
    monthly_limit_bytes: int = 0
    monthly_pct: float = 0.0
    estimated_daily_cost: float = 0.0
    estimated_monthly_cost: float = 0.0
    is_over_daily_budget: bool = False
    is_over_monthly_budget: bool = False
    urgency_score: float = 0.0  # 0-1, higher = more urgent to failback


class CostTracker:
    """
    Tracks metered connection usage and provides cost-aware decisions.

    Features:
        - Daily and monthly budget tracking
        - Cost estimation
        - Urgency scoring for failback decisions
        - Usage prediction based on trends
    """

    def __init__(self, database=None):
        """
        Initialize cost tracker.

        Args:
            database: SLAAIDatabase instance for persistent storage
        """
        self.database = database
        self._budgets: Dict[str, UsageBudget] = {}
        self._session_usage: Dict[str, Dict[str, int]] = {}  # Per-session tracking

    def set_budget(
        self,
        interface: str,
        daily_mb: int = 0,
        monthly_mb: int = 0,
        cost_per_gb: float = 0.0,
        overage_cost_per_gb: float = 0.0,
    ) -> None:
        """
        Set usage budget for an interface.

        Args:
            interface: Interface name
            daily_mb: Daily budget in MB
            monthly_mb: Monthly budget in MB
            cost_per_gb: Cost per GB in local currency
            overage_cost_per_gb: Cost per GB after exceeding budget
        """
        self._budgets[interface] = UsageBudget(
            daily_limit_bytes=daily_mb * 1024 * 1024,
            monthly_limit_bytes=monthly_mb * 1024 * 1024,
            cost_per_gb=cost_per_gb,
            overage_cost_per_gb=overage_cost_per_gb or cost_per_gb * 2,
        )
        logger.info(
            f"Budget set for {interface}: {daily_mb}MB/day, {monthly_mb}MB/month, "
            f"${cost_per_gb}/GB"
        )

    def is_metered(self, interface: str) -> bool:
        """Check if an interface is metered (has a budget)."""
        if interface in self._budgets:
            budget = self._budgets[interface]
            return budget.daily_limit_bytes > 0 or budget.monthly_limit_bytes > 0
        return False

    def record_usage(
        self, interface: str, bytes_sent: int, bytes_received: int
    ) -> None:
        """
        Record data usage for an interface.

        Args:
            interface: Interface name
            bytes_sent: Bytes transmitted
            bytes_received: Bytes received
        """
        if not self.is_metered(interface):
            return

        # Track in session
        if interface not in self._session_usage:
            self._session_usage[interface] = {"sent": 0, "received": 0}

        self._session_usage[interface]["sent"] += bytes_sent
        self._session_usage[interface]["received"] += bytes_received

        # Store in database
        if self.database:
            self.database.update_metered_usage(interface, bytes_sent, bytes_received)

    def get_status(self, interface: str) -> UsageStatus:
        """
        Get current usage status for an interface.

        Args:
            interface: Interface name

        Returns:
            UsageStatus with current metrics
        """
        status = UsageStatus(interface=interface)

        if not self.is_metered(interface):
            return status

        budget = self._budgets[interface]
        status.daily_limit_bytes = budget.daily_limit_bytes
        status.monthly_limit_bytes = budget.monthly_limit_bytes

        # Get usage from database or session
        if self.database:
            daily = self.database.get_daily_usage(interface)
            status.daily_bytes = daily["bytes_sent"] + daily["bytes_received"]

            # Get monthly total
            monthly = self.database.get_usage_summary(interface, days=30)
            total_bytes = (monthly.get("total_bytes_sent", 0) or 0) + (
                monthly.get("total_bytes_received", 0) or 0
            )
            status.monthly_bytes = total_bytes
        else:
            # Use session data
            session = self._session_usage.get(interface, {})
            status.daily_bytes = session.get("sent", 0) + session.get("received", 0)
            status.monthly_bytes = status.daily_bytes

        # Calculate percentages
        if status.daily_limit_bytes > 0:
            status.daily_pct = (status.daily_bytes / status.daily_limit_bytes) * 100
            status.is_over_daily_budget = status.daily_pct > 100

        if status.monthly_limit_bytes > 0:
            status.monthly_pct = (status.monthly_bytes / status.monthly_limit_bytes) * 100
            status.is_over_monthly_budget = status.monthly_pct > 100

        # Estimate costs
        bytes_to_gb = status.monthly_bytes / (1024 * 1024 * 1024)

        if status.monthly_limit_bytes > 0 and status.monthly_bytes > status.monthly_limit_bytes:
            # Over budget - calculate with overage rate
            budget_gb = status.monthly_limit_bytes / (1024 * 1024 * 1024)
            overage_gb = bytes_to_gb - budget_gb
            status.estimated_monthly_cost = (
                budget_gb * budget.cost_per_gb + overage_gb * budget.overage_cost_per_gb
            )
        else:
            status.estimated_monthly_cost = bytes_to_gb * budget.cost_per_gb

        # Daily cost estimate
        daily_gb = status.daily_bytes / (1024 * 1024 * 1024)
        status.estimated_daily_cost = daily_gb * budget.cost_per_gb

        # Calculate urgency score (0-1, higher = more urgent to failback)
        status.urgency_score = self._calculate_urgency(status)

        return status

    def _calculate_urgency(self, status: UsageStatus) -> float:
        """
        Calculate failback urgency based on usage status.

        Higher score = more urgent to switch back to primary.

        Factors:
            - Percentage of daily budget used
            - Percentage of monthly budget used
            - Whether already over budget
            - Time of month (more urgent near end of billing cycle)
        """
        urgency = 0.0

        # Daily budget pressure (30% weight)
        if status.daily_limit_bytes > 0:
            daily_factor = min(1.0, status.daily_pct / 100)
            if status.is_over_daily_budget:
                daily_factor = 1.0
            urgency += daily_factor * 0.3

        # Monthly budget pressure (50% weight)
        if status.monthly_limit_bytes > 0:
            monthly_factor = min(1.0, status.monthly_pct / 100)
            if status.is_over_monthly_budget:
                monthly_factor = 1.0
            urgency += monthly_factor * 0.5

        # Time of month factor (20% weight)
        # More urgent near end of month (days 25-31)
        day_of_month = datetime.now().day
        if day_of_month >= 25:
            time_factor = (day_of_month - 24) / 7  # 0 to 1 over days 25-31
            urgency += time_factor * 0.2

        return min(1.0, urgency)

    def get_failback_urgency_multiplier(self, interface: str) -> float:
        """
        Get urgency multiplier for failback decisions.

        Returns a value >= 1.0 that can be used to speed up failback
        when on metered connection.

        Args:
            interface: Metered interface name

        Returns:
            Multiplier (1.0 = no urgency, 2.0 = very urgent)
        """
        if not self.is_metered(interface):
            return 1.0

        status = self.get_status(interface)

        # Base multiplier from urgency score
        # urgency 0 = multiplier 1.0
        # urgency 1 = multiplier 2.0
        multiplier = 1.0 + status.urgency_score

        # Extra penalty if over budget
        if status.is_over_daily_budget:
            multiplier += 0.3
        if status.is_over_monthly_budget:
            multiplier += 0.5

        return min(3.0, multiplier)  # Cap at 3x

    def estimate_remaining_budget(
        self, interface: str
    ) -> Dict[str, float]:
        """
        Estimate remaining budget and time until exhaustion.

        Args:
            interface: Interface name

        Returns:
            Dictionary with remaining MB and hours estimates
        """
        if not self.is_metered(interface):
            return {"daily_remaining_mb": float("inf"), "monthly_remaining_mb": float("inf")}

        status = self.get_status(interface)
        result = {}

        # Remaining daily
        if status.daily_limit_bytes > 0:
            remaining_daily = max(0, status.daily_limit_bytes - status.daily_bytes)
            result["daily_remaining_mb"] = remaining_daily / (1024 * 1024)
        else:
            result["daily_remaining_mb"] = float("inf")

        # Remaining monthly
        if status.monthly_limit_bytes > 0:
            remaining_monthly = max(0, status.monthly_limit_bytes - status.monthly_bytes)
            result["monthly_remaining_mb"] = remaining_monthly / (1024 * 1024)
        else:
            result["monthly_remaining_mb"] = float("inf")

        # Estimate hours until daily exhaustion (based on session rate)
        if interface in self._session_usage and result["daily_remaining_mb"] < float("inf"):
            session = self._session_usage[interface]
            total_session = session["sent"] + session["received"]
            if total_session > 0:
                # Rough estimate - would need proper time tracking for accuracy
                result["hours_until_daily_exhaustion"] = result["daily_remaining_mb"] / (
                    total_session / (1024 * 1024)
                )

        return result

    def should_warn_usage(self, interface: str) -> Optional[str]:
        """
        Check if usage warrants a warning.

        Args:
            interface: Interface name

        Returns:
            Warning message if threshold exceeded, None otherwise
        """
        if not self.is_metered(interface):
            return None

        status = self.get_status(interface)

        if status.is_over_monthly_budget:
            return (
                f"CRITICAL: Monthly budget exceeded on {interface}! "
                f"Used {status.monthly_bytes / (1024*1024):.1f}MB of "
                f"{status.monthly_limit_bytes / (1024*1024):.1f}MB "
                f"(${status.estimated_monthly_cost:.2f})"
            )

        if status.is_over_daily_budget:
            return (
                f"WARNING: Daily budget exceeded on {interface}! "
                f"Used {status.daily_bytes / (1024*1024):.1f}MB of "
                f"{status.daily_limit_bytes / (1024*1024):.1f}MB"
            )

        if status.monthly_pct > 80:
            return (
                f"NOTICE: {interface} at {status.monthly_pct:.0f}% of monthly budget. "
                f"Consider reducing backup WAN usage."
            )

        if status.daily_pct > 80:
            return (
                f"NOTICE: {interface} at {status.daily_pct:.0f}% of daily budget."
            )

        return None

    def get_summary(self) -> Dict[str, UsageStatus]:
        """Get usage summary for all metered interfaces."""
        return {iface: self.get_status(iface) for iface in self._budgets}

    def reset_daily(self) -> None:
        """Reset daily counters (called at midnight)."""
        # Daily reset is handled by database date-based storage
        # This just clears session counters
        for iface in self._session_usage:
            self._session_usage[iface] = {"sent": 0, "received": 0}
        logger.info("Daily usage counters reset")
