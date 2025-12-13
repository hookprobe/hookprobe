"""
Security Alert System - Designer Notifications

Notifies security team and designers when:
1. New vulnerabilities are discovered
2. Risk levels change
3. Mitigations are needed urgently
4. Continuous testing finds regressions
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path

from .analyzer import Vulnerability, VulnerabilitySeverity

logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    """Alert severity levels."""
    INFO = "info"           # Informational
    WARNING = "warning"     # Needs attention
    URGENT = "urgent"       # Needs prompt attention
    CRITICAL = "critical"   # Immediate action required
    EMERGENCY = "emergency" # Stop everything and fix


class AlertChannel(Enum):
    """Alert delivery channels."""
    LOG = "log"
    FILE = "file"
    WEBHOOK = "webhook"
    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"


@dataclass
class SecurityAlert:
    """
    A security alert for designers/operators.
    """
    id: str
    level: AlertLevel
    title: str
    description: str
    timestamp: datetime = field(default_factory=datetime.now)

    # Context
    vulnerability_id: Optional[str] = None
    attack_vector: Optional[str] = None
    cvss_score: float = 0.0

    # Actions
    recommended_actions: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)

    # Tracking
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved: bool = False
    resolved_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'level': self.level.value,
            'title': self.title,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'vulnerability_id': self.vulnerability_id,
            'cvss_score': self.cvss_score,
            'recommended_actions': self.recommended_actions,
            'acknowledged': self.acknowledged,
            'resolved': self.resolved,
        }

    def to_slack_message(self) -> Dict[str, Any]:
        """Format alert for Slack."""
        emoji = {
            AlertLevel.INFO: "ℹ️",
            AlertLevel.WARNING: "⚠️",
            AlertLevel.URGENT: "🔶",
            AlertLevel.CRITICAL: "🔴",
            AlertLevel.EMERGENCY: "🚨",
        }.get(self.level, "•")

        color = {
            AlertLevel.INFO: "#36a64f",
            AlertLevel.WARNING: "#f2c744",
            AlertLevel.URGENT: "#ff9800",
            AlertLevel.CRITICAL: "#ff0000",
            AlertLevel.EMERGENCY: "#8b0000",
        }.get(self.level, "#808080")

        return {
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} {self.title}",
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": self.description,
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Level:* {self.level.value.upper()}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*CVSS:* {self.cvss_score}"
                            },
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Recommended Actions:*\n" + "\n".join(
                                f"• {a}" for a in self.recommended_actions
                            )
                        }
                    },
                ]
            }]
        }


class SecurityAlertSystem:
    """
    Manages security alerts and notifications.
    """

    def __init__(
        self,
        alert_file: Optional[str] = None,
        min_alert_level: AlertLevel = AlertLevel.WARNING,
    ):
        self.alerts: Dict[str, SecurityAlert] = {}
        self._alert_counter = 0
        self.alert_file = Path(alert_file) if alert_file else None
        self.min_alert_level = min_alert_level

        # Callback handlers for different channels
        self._handlers: Dict[AlertChannel, List[Callable]] = {
            channel: [] for channel in AlertChannel
        }

        # Always log
        self._handlers[AlertChannel.LOG].append(self._log_alert)

        # File output if configured
        if self.alert_file:
            self._handlers[AlertChannel.FILE].append(self._write_to_file)
            self.alert_file.parent.mkdir(parents=True, exist_ok=True)

    def register_handler(
        self,
        channel: AlertChannel,
        handler: Callable[[SecurityAlert], None]
    ):
        """Register a handler for an alert channel."""
        self._handlers[channel].append(handler)

    def create_alert(
        self,
        level: AlertLevel,
        title: str,
        description: str,
        vulnerability: Optional[Vulnerability] = None,
        recommended_actions: Optional[List[str]] = None,
    ) -> SecurityAlert:
        """
        Create and dispatch a new alert.

        Args:
            level: Alert severity level
            title: Alert title
            description: Detailed description
            vulnerability: Related vulnerability (optional)
            recommended_actions: List of recommended actions

        Returns:
            Created alert
        """
        # Check minimum level
        level_order = list(AlertLevel)
        if level_order.index(level) < level_order.index(self.min_alert_level):
            logger.debug(f"Alert {title} below minimum level, skipping")
            return None

        self._alert_counter += 1
        alert_id = f"ALERT-{self._alert_counter:05d}"

        alert = SecurityAlert(
            id=alert_id,
            level=level,
            title=title,
            description=description,
            vulnerability_id=vulnerability.id if vulnerability else None,
            attack_vector=vulnerability.attack_vector if vulnerability else None,
            cvss_score=vulnerability.cvss_score if vulnerability else 0.0,
            recommended_actions=recommended_actions or [],
            affected_components=vulnerability.affected_components if vulnerability else [],
        )

        self.alerts[alert_id] = alert

        # Dispatch to handlers
        self._dispatch_alert(alert)

        return alert

    def alert_from_vulnerability(self, vulnerability: Vulnerability) -> SecurityAlert:
        """Create an alert from a vulnerability."""
        level = {
            VulnerabilitySeverity.CRITICAL: AlertLevel.EMERGENCY,
            VulnerabilitySeverity.HIGH: AlertLevel.CRITICAL,
            VulnerabilitySeverity.MEDIUM: AlertLevel.URGENT,
            VulnerabilitySeverity.LOW: AlertLevel.WARNING,
            VulnerabilitySeverity.NONE: AlertLevel.INFO,
        }.get(vulnerability.severity, AlertLevel.WARNING)

        actions = [
            f"Review vulnerability {vulnerability.id}",
            "Run mitigation suggester for recommendations",
            "Update security risk assessment",
        ]

        if vulnerability.severity in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH):
            actions.insert(0, "IMMEDIATE: Assess exposure and consider temporary mitigations")

        return self.create_alert(
            level=level,
            title=f"NSE Vulnerability: {vulnerability.title}",
            description=vulnerability.description,
            vulnerability=vulnerability,
            recommended_actions=actions,
        )

    def alert_risk_change(
        self,
        old_risk: str,
        new_risk: str,
        reason: str
    ) -> SecurityAlert:
        """Alert on risk level changes."""
        risk_levels = ['LOW', 'LOW-MEDIUM', 'MEDIUM', 'HIGH', 'CRITICAL']

        try:
            old_idx = risk_levels.index(old_risk)
            new_idx = risk_levels.index(new_risk)
        except ValueError:
            old_idx = new_idx = 0

        if new_idx > old_idx:
            # Risk increased
            level = AlertLevel.URGENT if new_risk in ('HIGH', 'CRITICAL') else AlertLevel.WARNING
            title = f"Risk Level Increased: {old_risk} → {new_risk}"
        else:
            # Risk decreased
            level = AlertLevel.INFO
            title = f"Risk Level Decreased: {old_risk} → {new_risk}"

        return self.create_alert(
            level=level,
            title=title,
            description=reason,
            recommended_actions=[
                "Review recent vulnerability changes",
                "Update security documentation",
                "Notify stakeholders if significant",
            ],
        )

    def alert_regression(
        self,
        vulnerability_id: str,
        details: str
    ) -> SecurityAlert:
        """Alert when a previously fixed vulnerability regresses."""
        return self.create_alert(
            level=AlertLevel.CRITICAL,
            title=f"Security Regression: {vulnerability_id}",
            description=f"Previously mitigated vulnerability has regressed. {details}",
            recommended_actions=[
                "IMMEDIATE: Verify regression is not in production",
                "Identify code change that caused regression",
                "Re-apply mitigation",
                "Add regression test to CI/CD",
            ],
        )

    def _dispatch_alert(self, alert: SecurityAlert):
        """Dispatch alert to all registered handlers."""
        for channel, handlers in self._handlers.items():
            for handler in handlers:
                try:
                    handler(alert)
                except Exception as e:
                    logger.error(f"Alert handler {channel.value} failed: {e}")

    def _log_alert(self, alert: SecurityAlert):
        """Log alert."""
        log_fn = {
            AlertLevel.INFO: logger.info,
            AlertLevel.WARNING: logger.warning,
            AlertLevel.URGENT: logger.warning,
            AlertLevel.CRITICAL: logger.error,
            AlertLevel.EMERGENCY: logger.critical,
        }.get(alert.level, logger.info)

        log_fn(f"[{alert.level.value.upper()}] {alert.title}: {alert.description}")

    def _write_to_file(self, alert: SecurityAlert):
        """Write alert to file."""
        if self.alert_file:
            with open(self.alert_file, 'a') as f:
                f.write(json.dumps(alert.to_dict()) + '\n')

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledge an alert."""
        if alert_id not in self.alerts:
            return False

        alert = self.alerts[alert_id]
        alert.acknowledged = True
        alert.acknowledged_by = acknowledged_by
        alert.acknowledged_at = datetime.now()

        logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
        return True

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert."""
        if alert_id not in self.alerts:
            return False

        alert = self.alerts[alert_id]
        alert.resolved = True
        alert.resolved_at = datetime.now()

        logger.info(f"Alert {alert_id} resolved")
        return True

    def get_active_alerts(self) -> List[SecurityAlert]:
        """Get all unresolved alerts."""
        return [a for a in self.alerts.values() if not a.resolved]

    def get_alerts_by_level(self, level: AlertLevel) -> List[SecurityAlert]:
        """Get alerts by severity level."""
        return [a for a in self.alerts.values() if a.level == level]

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        active = self.get_active_alerts()

        stats_by_level = {}
        for level in AlertLevel:
            count = len([a for a in active if a.level == level])
            if count > 0:
                stats_by_level[level.value] = count

        return {
            'total_alerts': len(self.alerts),
            'active_alerts': len(active),
            'acknowledged': len([a for a in active if a.acknowledged]),
            'by_level': stats_by_level,
            'oldest_unresolved': min(
                (a.timestamp for a in active),
                default=None
            ),
        }

    def generate_summary(self) -> str:
        """Generate alert summary."""
        stats = self.get_alert_statistics()
        active = self.get_active_alerts()

        lines = [
            "# Security Alert Summary",
            f"Generated: {datetime.now().isoformat()}",
            "",
            f"## Overview",
            f"- Total Alerts: {stats['total_alerts']}",
            f"- Active: {stats['active_alerts']}",
            f"- Acknowledged: {stats['acknowledged']}",
            "",
            "## Active Alerts by Level",
        ]

        for level_name, count in stats.get('by_level', {}).items():
            lines.append(f"- {level_name.upper()}: {count}")

        if active:
            lines.extend(["", "## Active Alerts"])
            for alert in sorted(active, key=lambda a: a.timestamp, reverse=True)[:10]:
                lines.extend([
                    f"### {alert.id}: {alert.title}",
                    f"- Level: {alert.level.value}",
                    f"- Time: {alert.timestamp.isoformat()}",
                    f"- Acknowledged: {'Yes' if alert.acknowledged else 'No'}",
                    "",
                ])

        return '\n'.join(lines)


# Convenience functions for quick alerting
def create_security_alert(
    title: str,
    description: str,
    level: AlertLevel = AlertLevel.WARNING,
    alert_system: Optional[SecurityAlertSystem] = None
) -> SecurityAlert:
    """Quick function to create an alert."""
    system = alert_system or SecurityAlertSystem()
    return system.create_alert(
        level=level,
        title=title,
        description=description,
    )
