"""
AEGIS Inner Psyche — Reflection & Learning

The introspective layer that reviews past decisions, learns from
corrections, calibrates confidence, and suggests improvements.

Runs as an autonomous nightly task to make AEGIS smarter over time.
"""

import json
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ReflectionReport:
    """Summary of a reflection cycle."""
    period: str  # "daily", "weekly"
    decisions_reviewed: int = 0
    patterns_found: List[str] = field(default_factory=list)
    confidence_accuracy: float = 0.0
    false_positives: int = 0
    false_negatives: int = 0
    suggestions: List[str] = field(default_factory=list)
    timestamp: str = ""


class InnerPsyche:
    """AEGIS introspective engine for self-improvement.

    Reviews decisions, learns from corrections, calibrates confidence,
    and proactively suggests improvements to the system.
    """

    def __init__(self):
        self._memory = None
        self._last_reflection: float = 0
        self._corrections: List[Dict[str, Any]] = []
        self._confidence_log: List[Dict[str, float]] = []

    def set_memory(self, memory) -> None:
        """Wire to the MemoryManager."""
        self._memory = memory

    # ------------------------------------------------------------------
    # Reflection
    # ------------------------------------------------------------------

    def reflect(self, period: str = "daily") -> ReflectionReport:
        """Review past decisions and find patterns.

        Args:
            period: "daily" reviews last 24h, "weekly" last 7 days.

        Returns:
            ReflectionReport with findings and suggestions.
        """
        report = ReflectionReport(
            period=period,
            timestamp=datetime.utcnow().isoformat(),
        )

        if not self._memory:
            report.suggestions.append("Memory not connected — cannot reflect")
            return report

        # Get recent decisions
        limit = 100 if period == "daily" else 500
        decisions = self._memory.get_recent_decisions(limit=limit)
        report.decisions_reviewed = len(decisions)

        if not decisions:
            report.suggestions.append("No decisions to review")
            return report

        # Analyze agent activity distribution
        agent_counts = Counter(d.agent for d in decisions)
        action_counts = Counter(d.action for d in decisions)

        # Find overactive agents
        total = len(decisions)
        for agent, count in agent_counts.most_common(3):
            pct = count / total * 100
            if pct > 60:
                report.patterns_found.append(
                    f"{agent} handled {pct:.0f}% of decisions — may be over-triggered"
                )

        # Find repeated actions (possible loops)
        for action, count in action_counts.most_common(3):
            if count > 10:
                report.patterns_found.append(
                    f"Action '{action}' executed {count} times — check for loops"
                )

        # Analyze confidence distribution
        confidences = [d.confidence for d in decisions if d.confidence > 0]
        if confidences:
            avg_conf = sum(confidences) / len(confidences)
            report.confidence_accuracy = avg_conf

            low_conf = sum(1 for c in confidences if c < 0.5)
            if low_conf > len(confidences) * 0.3:
                report.suggestions.append(
                    f"{low_conf} decisions ({low_conf/len(confidences)*100:.0f}%) "
                    "had low confidence — consider improving signal quality"
                )

        # Find unapproved actions (potential false positives)
        unapproved = [d for d in decisions if not d.approved and d.action]
        report.false_positives = len(unapproved)
        if report.false_positives > total * 0.2:
            report.suggestions.append(
                f"{report.false_positives} unapproved actions — "
                "raise confidence thresholds or improve detection"
            )

        # Check for agent diversity
        if len(agent_counts) < 3 and total > 20:
            active = ", ".join(agent_counts.keys())
            report.suggestions.append(
                f"Only {len(agent_counts)} agents active ({active}) — "
                "verify signal routing to other agents"
            )

        # Store reflection in memory
        self._store_reflection(report)
        self._last_reflection = time.time()

        return report

    def _store_reflection(self, report: ReflectionReport) -> None:
        """Store reflection findings in institutional memory."""
        if not self._memory:
            return

        summary = (
            f"Reflection ({report.period}): "
            f"Reviewed {report.decisions_reviewed} decisions. "
            f"Avg confidence: {report.confidence_accuracy:.0%}. "
            f"Patterns: {len(report.patterns_found)}. "
            f"Suggestions: {len(report.suggestions)}."
        )

        self._memory.store(
            "session",
            f"reflection_{report.period}_{int(time.time())}",
            summary,
            source="inner_psyche",
        )

        if report.patterns_found:
            self._memory.store(
                "institutional",
                f"patterns_{report.period}",
                json.dumps(report.patterns_found),
                source="inner_psyche",
            )

    # ------------------------------------------------------------------
    # Learn from corrections
    # ------------------------------------------------------------------

    def learn_from_correction(
        self,
        decision_id: str,
        feedback: str,
        correct_action: str = "",
    ) -> None:
        """Learn when a user corrects a decision.

        Args:
            decision_id: ID of the original decision.
            feedback: "false_alarm", "wrong_action", "missed_threat", "good".
            correct_action: What the correct action should have been.
        """
        correction = {
            "decision_id": decision_id,
            "feedback": feedback,
            "correct_action": correct_action,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._corrections.append(correction)

        if not self._memory:
            return

        # Store correction in memory
        self._memory.store(
            "session",
            f"correction_{decision_id}",
            json.dumps(correction),
            source="user_feedback",
        )

        # If it was a false alarm, store pattern to avoid repeating
        if feedback == "false_alarm":
            # Look up the original decision
            decisions = self._memory.get_recent_decisions(limit=50)
            original = next((d for d in decisions if d.id == decision_id), None)
            if original:
                self._memory.store(
                    "institutional",
                    f"false_alarm_{original.agent}_{original.action}",
                    json.dumps({
                        "agent": original.agent,
                        "action": original.action,
                        "params": original.params,
                        "reasoning": original.reasoning,
                        "feedback": feedback,
                    }),
                    source="correction",
                )
                logger.info(
                    "Learned from correction: %s.%s was a false alarm",
                    original.agent, original.action,
                )

    # ------------------------------------------------------------------
    # Confidence calibration
    # ------------------------------------------------------------------

    def confidence_calibration(self) -> Dict[str, Any]:
        """Compare predicted confidence vs actual outcomes.

        Returns:
            Calibration report showing over/under-confidence per agent.
        """
        if not self._memory:
            return {"error": "Memory not connected"}

        decisions = self._memory.get_recent_decisions(limit=200)
        if not decisions:
            return {"message": "No decisions to calibrate"}

        # Group by agent
        agent_stats: Dict[str, Dict[str, Any]] = {}
        for d in decisions:
            if d.agent not in agent_stats:
                agent_stats[d.agent] = {
                    "total": 0,
                    "approved": 0,
                    "avg_confidence": 0.0,
                    "confidences": [],
                }
            stats = agent_stats[d.agent]
            stats["total"] += 1
            if d.approved:
                stats["approved"] += 1
            if d.confidence > 0:
                stats["confidences"].append(d.confidence)

        calibration = {}
        for agent, stats in agent_stats.items():
            confs = stats["confidences"]
            if not confs:
                continue

            avg_conf = sum(confs) / len(confs)
            approval_rate = stats["approved"] / stats["total"] if stats["total"] else 0

            calibration[agent] = {
                "avg_confidence": round(avg_conf, 3),
                "approval_rate": round(approval_rate, 3),
                "total_decisions": stats["total"],
                "calibration_gap": round(avg_conf - approval_rate, 3),
                "assessment": self._assess_calibration(avg_conf, approval_rate),
            }

        return calibration

    @staticmethod
    def _assess_calibration(confidence: float, approval_rate: float) -> str:
        """Assess calibration quality."""
        gap = confidence - approval_rate
        if abs(gap) < 0.1:
            return "well_calibrated"
        elif gap > 0.2:
            return "overconfident"
        elif gap < -0.2:
            return "underconfident"
        elif gap > 0:
            return "slightly_overconfident"
        else:
            return "slightly_underconfident"

    # ------------------------------------------------------------------
    # Proactive suggestions
    # ------------------------------------------------------------------

    def suggest_improvements(self) -> List[str]:
        """Generate proactive recommendations based on system state.

        Returns:
            List of improvement suggestions.
        """
        suggestions = []

        if not self._memory:
            return ["Connect memory for full introspection capability"]

        stats = self._memory.get_stats()

        # Check memory health
        if stats.get("threat_intel", 0) == 0:
            suggestions.append(
                "No threat intelligence stored — signal bridges may not be running"
            )
        if stats.get("behavioral", 0) == 0:
            suggestions.append(
                "No device profiles learned — SHIELD agent needs more data"
            )
        if stats.get("institutional", 0) < 3:
            suggestions.append(
                "Institutional memory is sparse — run system discovery"
            )

        # Check corrections
        false_alarms = sum(
            1 for c in self._corrections if c.get("feedback") == "false_alarm"
        )
        if false_alarms > 5:
            suggestions.append(
                f"{false_alarms} false alarms recorded — "
                "consider raising confidence thresholds"
            )

        # Check decision volume
        if stats.get("decisions", 0) > 5000:
            suggestions.append(
                "Decision audit trail is large — consider running decay"
            )

        return suggestions

    # ------------------------------------------------------------------
    # Dream — Background reprocessing
    # ------------------------------------------------------------------

    def dream(self) -> Dict[str, Any]:
        """Background processing: re-analyze old events with current knowledge.

        'Dreaming' consolidates learning by:
        1. Reviewing old threat intel with new patterns
        2. Updating device profiles with accumulated observations
        3. Identifying stale institutional knowledge

        Returns:
            Summary of dream cycle findings.
        """
        findings: Dict[str, Any] = {
            "threats_reconsidered": 0,
            "profiles_updated": 0,
            "knowledge_refreshed": 0,
            "insights": [],
        }

        if not self._memory:
            return findings

        conn = self._memory._get_conn()

        try:
            # 1. Find threat patterns — repeated threats from same source
            rows = conn.execute(
                "SELECT type, severity, count, context_json FROM aegis_threat_intel "
                "WHERE count >= 3 ORDER BY count DESC LIMIT 20"
            ).fetchall()

            for row in rows:
                findings["threats_reconsidered"] += 1
                if row["count"] >= 10:
                    findings["insights"].append(
                        f"Persistent threat: {row['type']} [{row['severity']}] "
                        f"seen {row['count']}x — consider permanent block"
                    )

            # 2. Find stale device profiles (not updated in 7+ days)
            cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
            stale_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM aegis_device_profiles "
                "WHERE updated_at < ?",
                (cutoff,),
            ).fetchone()

            if stale_count and stale_count["cnt"] > 0:
                findings["profiles_updated"] = stale_count["cnt"]
                findings["insights"].append(
                    f"{stale_count['cnt']} device profiles are stale (>7 days) — "
                    "schedule re-fingerprinting"
                )

            # 3. Find stale knowledge (not updated in 14+ days)
            cutoff_knowledge = (datetime.utcnow() - timedelta(days=14)).isoformat()
            stale_knowledge = conn.execute(
                "SELECT COUNT(*) as cnt FROM aegis_network_knowledge "
                "WHERE updated_at < ?",
                (cutoff_knowledge,),
            ).fetchone()

            if stale_knowledge and stale_knowledge["cnt"] > 0:
                findings["knowledge_refreshed"] = stale_knowledge["cnt"]
                findings["insights"].append(
                    f"{stale_knowledge['cnt']} knowledge entries are stale (>14 days) — "
                    "run system discovery to refresh"
                )

        except Exception as e:
            logger.error("Dream cycle error: %s", e)
            findings["insights"].append(f"Dream interrupted: {e}")

        # Store dream results
        if findings["insights"]:
            self._memory.store(
                "session",
                f"dream_{int(time.time())}",
                f"Dream cycle: {len(findings['insights'])} insights. "
                + "; ".join(findings["insights"][:3]),
                source="inner_psyche",
            )

        return findings

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Get inner psyche statistics."""
        return {
            "corrections_recorded": len(self._corrections),
            "last_reflection": self._last_reflection,
            "confidence_samples": len(self._confidence_log),
        }
