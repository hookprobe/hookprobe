"""
AIOCHI Performance Scorer
Calculates network health scores and provides insights.

The goal: Turn complex network metrics into a single 0-100 health score
with human-readable insights like "The microwave is slowing down your WiFi."
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class HealthLevel(Enum):
    """Health score levels."""
    EXCELLENT = "excellent"  # 90-100
    GOOD = "good"            # 70-89
    FAIR = "fair"            # 50-69
    POOR = "poor"            # 30-49
    CRITICAL = "critical"    # 0-29


@dataclass
class PerformanceMetrics:
    """Raw performance metrics for a device or network."""
    latency_ms: float = 0.0          # Round-trip time
    jitter_ms: float = 0.0           # Latency variation
    packet_loss_pct: float = 0.0     # Packet loss percentage
    signal_dbm: int = -100           # WiFi signal strength
    bandwidth_mbps: float = 0.0      # Available bandwidth
    interference_score: float = 0.0  # WiFi interference (0-1)
    congestion_score: float = 0.0    # Network congestion (0-1)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "latency_ms": self.latency_ms,
            "jitter_ms": self.jitter_ms,
            "packet_loss_pct": self.packet_loss_pct,
            "signal_dbm": self.signal_dbm,
            "bandwidth_mbps": self.bandwidth_mbps,
            "interference_score": self.interference_score,
            "congestion_score": self.congestion_score,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class HealthScore:
    """Health score with insight."""
    score: int = 100                      # 0-100
    level: HealthLevel = HealthLevel.EXCELLENT
    headline: str = ""                    # Short summary
    insight: str = ""                     # Detailed explanation
    factors: List[str] = field(default_factory=list)  # Contributing factors
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value,
            "headline": self.headline,
            "insight": self.insight,
            "factors": self.factors,
            "recommendations": self.recommendations,
            "timestamp": self.timestamp.isoformat(),
        }


# Score weights for different metrics
SCORE_WEIGHTS = {
    "latency": 0.25,       # Lower is better
    "jitter": 0.15,        # Lower is better
    "packet_loss": 0.20,   # Lower is better
    "signal": 0.15,        # Higher is better
    "bandwidth": 0.15,     # Higher is better
    "interference": 0.05,  # Lower is better
    "congestion": 0.05,    # Lower is better
}

# Thresholds for metric scoring
THRESHOLDS = {
    "latency_ms": {
        "excellent": 20,
        "good": 50,
        "fair": 100,
        "poor": 200,
    },
    "jitter_ms": {
        "excellent": 5,
        "good": 15,
        "fair": 30,
        "poor": 50,
    },
    "packet_loss_pct": {
        "excellent": 0.1,
        "good": 1.0,
        "fair": 3.0,
        "poor": 5.0,
    },
    "signal_dbm": {
        "excellent": -50,
        "good": -60,
        "fair": -70,
        "poor": -80,
    },
    "bandwidth_mbps": {
        "excellent": 100,
        "good": 50,
        "fair": 25,
        "poor": 10,
    },
}

# Insight templates based on detected issues
INSIGHT_TEMPLATES = {
    "high_latency": {
        "headline": "Slow response times detected",
        "insight": "Your internet is taking longer than usual to respond. This might affect video calls and gaming.",
        "recommendations": [
            "Check if someone is downloading large files",
            "Restart your router",
            "Contact your ISP if problem persists",
        ],
    },
    "high_jitter": {
        "headline": "Unstable connection",
        "insight": "Your connection speed is fluctuating. Video calls might freeze or buffer.",
        "recommendations": [
            "Move closer to your router",
            "Switch to a wired connection if possible",
            "Check for WiFi interference",
        ],
    },
    "packet_loss": {
        "headline": "Data packets being lost",
        "insight": "Some data isn't reaching its destination. This can cause audio dropouts and video freezing.",
        "recommendations": [
            "Check your WiFi signal strength",
            "Restart your router",
            "Check for interference from other devices",
        ],
    },
    "weak_signal": {
        "headline": "Weak WiFi signal",
        "insight": "Your device has a weak connection to the router. Moving closer would help.",
        "recommendations": [
            "Move closer to your router",
            "Consider a WiFi extender or mesh system",
            "Check for obstacles blocking the signal",
        ],
    },
    "low_bandwidth": {
        "headline": "Limited bandwidth available",
        "insight": "Your available internet speed is lower than expected. Someone might be using a lot of bandwidth.",
        "recommendations": [
            "Check which devices are using the most bandwidth",
            "Pause or limit streaming on other devices",
            "Consider upgrading your internet plan",
        ],
    },
    "interference": {
        "headline": "WiFi interference detected",
        "insight": "Something nearby is interfering with your WiFi signal. Common culprits: microwave, baby monitor, Bluetooth.",
        "recommendations": [
            "Turn off the microwave if you're using it",
            "Move 2.4GHz devices away from the router",
            "Switch to 5GHz WiFi if available",
        ],
    },
    "congestion": {
        "headline": "Network is congested",
        "insight": "Too many devices are competing for bandwidth. I'm managing traffic to keep things running.",
        "recommendations": [
            "Disconnect devices you're not using",
            "Schedule large downloads for off-peak hours",
            "Enable QoS for priority devices",
        ],
    },
    "all_good": {
        "headline": "Everything is running smoothly",
        "insight": "Your network is performing well. No issues detected.",
        "recommendations": [],
    },
}


class PerformanceScorer:
    """
    Calculates network health scores and generates insights.

    Features:
    - Single 0-100 health score
    - Human-readable insights
    - Device-specific recommendations
    - Historical tracking for trend detection
    """

    def __init__(
        self,
        use_slaai: bool = True,
    ):
        """
        Initialize the Performance Scorer.

        Args:
            use_slaai: Use SLA AI metrics if available
        """
        self.use_slaai = use_slaai

        # Historical metrics for trend analysis
        self._history: List[Tuple[datetime, int]] = []
        self._max_history = 288  # 24 hours at 5-min intervals

        # Device-specific metrics
        self._device_metrics: Dict[str, PerformanceMetrics] = {}

        # Try to use SLA AI
        self._slaai_collector = None
        if use_slaai:
            try:
                from shared.slaai.metrics_collector import MetricsCollector
                self._slaai_collector = MetricsCollector()
                logger.info("Using SLA AI metrics collector")
            except ImportError:
                logger.warning("SLA AI not available, using basic metrics")

    def calculate_score(
        self,
        metrics: Optional[PerformanceMetrics] = None,
    ) -> HealthScore:
        """
        Calculate overall network health score.

        Args:
            metrics: Raw performance metrics (if None, will collect)

        Returns:
            HealthScore with score, insight, and recommendations
        """
        if metrics is None:
            metrics = self._collect_metrics()

        # Calculate component scores (0-100 each)
        component_scores = self._calculate_component_scores(metrics)

        # Weighted average
        total_score = 0.0
        for metric, weight in SCORE_WEIGHTS.items():
            total_score += component_scores.get(metric, 100) * weight

        score = int(round(total_score))
        score = max(0, min(100, score))  # Clamp to 0-100

        # Determine level
        level = self._score_to_level(score)

        # Generate insight based on issues
        issues = self._detect_issues(metrics, component_scores)
        headline, insight, recommendations, factors = self._generate_insight(issues)

        health = HealthScore(
            score=score,
            level=level,
            headline=headline,
            insight=insight,
            factors=factors,
            recommendations=recommendations,
        )

        # Track history
        self._history.append((datetime.now(), score))
        if len(self._history) > self._max_history:
            self._history.pop(0)

        return health

    def calculate_device_score(
        self,
        mac: str,
        metrics: Optional[PerformanceMetrics] = None,
    ) -> HealthScore:
        """
        Calculate health score for a specific device.

        Args:
            mac: Device MAC address
            metrics: Device-specific metrics (if None, uses cached)

        Returns:
            Device-specific HealthScore
        """
        mac = mac.upper().replace("-", ":")

        if metrics:
            self._device_metrics[mac] = metrics
        elif mac not in self._device_metrics:
            # Create default metrics
            self._device_metrics[mac] = PerformanceMetrics()

        return self.calculate_score(self._device_metrics.get(mac))

    def update_device_metrics(
        self,
        mac: str,
        latency_ms: Optional[float] = None,
        jitter_ms: Optional[float] = None,
        packet_loss_pct: Optional[float] = None,
        signal_dbm: Optional[int] = None,
        bandwidth_mbps: Optional[float] = None,
    ) -> None:
        """
        Update metrics for a specific device.

        Args:
            mac: Device MAC address
            latency_ms: Round-trip time
            jitter_ms: Latency variation
            packet_loss_pct: Packet loss percentage
            signal_dbm: WiFi signal strength
            bandwidth_mbps: Available bandwidth
        """
        mac = mac.upper().replace("-", ":")

        if mac not in self._device_metrics:
            self._device_metrics[mac] = PerformanceMetrics()

        metrics = self._device_metrics[mac]

        if latency_ms is not None:
            metrics.latency_ms = latency_ms
        if jitter_ms is not None:
            metrics.jitter_ms = jitter_ms
        if packet_loss_pct is not None:
            metrics.packet_loss_pct = packet_loss_pct
        if signal_dbm is not None:
            metrics.signal_dbm = signal_dbm
        if bandwidth_mbps is not None:
            metrics.bandwidth_mbps = bandwidth_mbps

        metrics.timestamp = datetime.now()

    def get_trend(self, hours: int = 1) -> str:
        """
        Get score trend over recent history.

        Args:
            hours: Number of hours to analyze

        Returns:
            "improving", "stable", or "degrading"
        """
        if len(self._history) < 2:
            return "stable"

        cutoff = datetime.now() - timedelta(hours=hours)
        recent = [s for t, s in self._history if t > cutoff]

        if len(recent) < 2:
            return "stable"

        # Calculate trend
        first_avg = sum(recent[:len(recent)//2]) / (len(recent)//2)
        second_avg = sum(recent[len(recent)//2:]) / (len(recent) - len(recent)//2)

        diff = second_avg - first_avg

        if diff > 5:
            return "improving"
        elif diff < -5:
            return "degrading"
        else:
            return "stable"

    def get_summary(self) -> Dict[str, Any]:
        """
        Get performance summary for dashboard.

        Returns:
            Dictionary with current score, trend, and insights
        """
        current = self.calculate_score()
        trend = self.get_trend()

        return {
            "score": current.score,
            "level": current.level.value,
            "headline": current.headline,
            "insight": current.insight,
            "trend": trend,
            "recommendations": current.recommendations,
            "device_count": len(self._device_metrics),
            "timestamp": current.timestamp.isoformat(),
        }

    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current network metrics."""
        if self._slaai_collector:
            try:
                wan_metrics = self._slaai_collector.collect()
                return PerformanceMetrics(
                    latency_ms=wan_metrics.rtt_ms,
                    jitter_ms=wan_metrics.jitter_ms,
                    packet_loss_pct=wan_metrics.packet_loss_pct,
                    bandwidth_mbps=wan_metrics.bandwidth_mbps or 0,
                )
            except Exception as e:
                logger.warning(f"SLA AI metrics collection failed: {e}")

        # Return default metrics if collection fails
        return PerformanceMetrics()

    def _calculate_component_scores(
        self,
        metrics: PerformanceMetrics,
    ) -> Dict[str, float]:
        """Calculate individual component scores."""
        scores = {}

        # Latency (lower is better)
        scores["latency"] = self._metric_to_score(
            metrics.latency_ms,
            THRESHOLDS["latency_ms"],
            inverse=True,
        )

        # Jitter (lower is better)
        scores["jitter"] = self._metric_to_score(
            metrics.jitter_ms,
            THRESHOLDS["jitter_ms"],
            inverse=True,
        )

        # Packet loss (lower is better)
        scores["packet_loss"] = self._metric_to_score(
            metrics.packet_loss_pct,
            THRESHOLDS["packet_loss_pct"],
            inverse=True,
        )

        # Signal (higher is better, but values are negative)
        scores["signal"] = self._metric_to_score(
            metrics.signal_dbm,
            THRESHOLDS["signal_dbm"],
            inverse=False,
        )

        # Bandwidth (higher is better)
        scores["bandwidth"] = self._metric_to_score(
            metrics.bandwidth_mbps,
            THRESHOLDS["bandwidth_mbps"],
            inverse=False,
        )

        # Interference (lower is better)
        scores["interference"] = 100 - (metrics.interference_score * 100)

        # Congestion (lower is better)
        scores["congestion"] = 100 - (metrics.congestion_score * 100)

        return scores

    def _metric_to_score(
        self,
        value: float,
        thresholds: Dict[str, float],
        inverse: bool = False,
    ) -> float:
        """
        Convert a metric value to a 0-100 score.

        Args:
            value: Metric value
            thresholds: Threshold dictionary
            inverse: True if lower values are better

        Returns:
            Score 0-100
        """
        if inverse:
            # For metrics where lower is better (latency, jitter, packet_loss)
            if value <= thresholds["excellent"]:
                return 100
            elif value <= thresholds["good"]:
                return 85
            elif value <= thresholds["fair"]:
                return 65
            elif value <= thresholds["poor"]:
                return 40
            else:
                return 20
        else:
            # For metrics where higher is better (signal, bandwidth)
            # Note: signal is negative, so this works differently
            if value >= thresholds["excellent"]:
                return 100
            elif value >= thresholds["good"]:
                return 85
            elif value >= thresholds["fair"]:
                return 65
            elif value >= thresholds["poor"]:
                return 40
            else:
                return 20

    def _score_to_level(self, score: int) -> HealthLevel:
        """Convert numeric score to health level."""
        if score >= 90:
            return HealthLevel.EXCELLENT
        elif score >= 70:
            return HealthLevel.GOOD
        elif score >= 50:
            return HealthLevel.FAIR
        elif score >= 30:
            return HealthLevel.POOR
        else:
            return HealthLevel.CRITICAL

    def _detect_issues(
        self,
        metrics: PerformanceMetrics,
        component_scores: Dict[str, float],
    ) -> List[str]:
        """Detect issues based on metrics and scores."""
        issues = []

        if component_scores.get("latency", 100) < 70:
            issues.append("high_latency")

        if component_scores.get("jitter", 100) < 70:
            issues.append("high_jitter")

        if component_scores.get("packet_loss", 100) < 70:
            issues.append("packet_loss")

        if component_scores.get("signal", 100) < 70:
            issues.append("weak_signal")

        if component_scores.get("bandwidth", 100) < 70:
            issues.append("low_bandwidth")

        if metrics.interference_score > 0.3:
            issues.append("interference")

        if metrics.congestion_score > 0.3:
            issues.append("congestion")

        return issues

    def _generate_insight(
        self,
        issues: List[str],
    ) -> Tuple[str, str, List[str], List[str]]:
        """
        Generate insight based on detected issues.

        Returns:
            Tuple of (headline, insight, recommendations, factors)
        """
        if not issues:
            template = INSIGHT_TEMPLATES["all_good"]
            return (
                template["headline"],
                template["insight"],
                template["recommendations"],
                [],
            )

        # Use the most impactful issue for the main insight
        primary_issue = issues[0]
        template = INSIGHT_TEMPLATES.get(primary_issue, INSIGHT_TEMPLATES["all_good"])

        # Collect all recommendations
        all_recommendations = []
        for issue in issues:
            issue_template = INSIGHT_TEMPLATES.get(issue, {})
            all_recommendations.extend(issue_template.get("recommendations", []))

        # Deduplicate recommendations
        all_recommendations = list(dict.fromkeys(all_recommendations))[:5]

        # Format factors
        factors = [issue.replace("_", " ").title() for issue in issues]

        return (
            template["headline"],
            template["insight"],
            all_recommendations,
            factors,
        )


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    scorer = PerformanceScorer(use_slaai=False)

    # Create sample metrics
    metrics = PerformanceMetrics(
        latency_ms=35.0,
        jitter_ms=8.0,
        packet_loss_pct=0.5,
        signal_dbm=-55,
        bandwidth_mbps=85.0,
        interference_score=0.1,
        congestion_score=0.2,
    )

    # Calculate score
    health = scorer.calculate_score(metrics)

    print(f"Health Score: {health.score}/100 ({health.level.value})")
    print(f"Headline: {health.headline}")
    print(f"Insight: {health.insight}")
    if health.factors:
        print(f"Factors: {', '.join(health.factors)}")
    if health.recommendations:
        print("Recommendations:")
        for rec in health.recommendations:
            print(f"  - {rec}")
