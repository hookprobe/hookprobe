"""
Intelligence Feedback — TTP Extraction & Distribution

Converts attacker interactions from AdaptiveHoneypot and MirageOrchestrator
into actionable intelligence:
- QSecBit ThreatEvents for scoring
- dnsXai negative examples for ML training
- Mesh gossip for collective defense
- ClickHouse records for analytics

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import hashlib
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class IntelType(Enum):
    """Types of intelligence extracted from deception."""
    SCAN_PATTERN = "scan_pattern"
    CREDENTIAL_SET = "credential_set"
    TOOL_SIGNATURE = "tool_signature"
    PAYLOAD_HASH = "payload_hash"
    C2_INDICATOR = "c2_indicator"
    TTP_CHAIN = "ttp_chain"
    DNS_IOC = "dns_ioc"


@dataclass
class ThreatIntel:
    """A single piece of threat intelligence from deception."""
    intel_type: IntelType
    source_ip: str
    confidence: float  # 0.0 - 1.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    ioc_value: str = ""
    ioc_type: str = ""  # ip, domain, hash, url

    @property
    def intel_id(self) -> str:
        raw = f"{self.intel_type.value}:{self.source_ip}:{self.ioc_value}:{self.timestamp.isoformat()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intel_id": self.intel_id,
            "intel_type": self.intel_type.value,
            "source_ip": self.source_ip,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "mitre_techniques": self.mitre_techniques,
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
        }


@dataclass
class AttackerTTPProfile:
    """Aggregated TTP profile for an attacker based on deception intel."""
    source_ip: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    sophistication: str = "NAIVE"
    techniques: Set[str] = field(default_factory=set)
    tools_identified: List[str] = field(default_factory=list)
    credentials_used: int = 0
    payloads_captured: int = 0
    commands_executed: int = 0
    intel_items: List[ThreatIntel] = field(default_factory=list)

    @property
    def threat_score(self) -> float:
        """Calculate threat score 0.0-1.0 from observed behavior."""
        score = 0.0
        score += min(len(self.techniques) * 0.1, 0.3)
        score += min(self.payloads_captured * 0.15, 0.3)
        score += min(self.commands_executed * 0.02, 0.2)
        score += 0.1 if self.sophistication == "INTERMEDIATE" else 0.0
        score += 0.2 if self.sophistication == "ADVANCED" else 0.0
        return min(score, 1.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "sophistication": self.sophistication,
            "techniques": list(self.techniques),
            "tools_identified": self.tools_identified,
            "credentials_used": self.credentials_used,
            "payloads_captured": self.payloads_captured,
            "commands_executed": self.commands_executed,
            "threat_score": self.threat_score,
            "intel_count": len(self.intel_items),
        }


# MITRE technique mapping for common deception observations
DECEPTION_MITRE_MAP = {
    "port_scan": ["T1046"],                      # Network Service Scanning
    "credential_brute": ["T1110.001"],            # Brute Force: Password Guessing
    "credential_spray": ["T1110.003"],            # Password Spraying
    "credential_default": ["T1078.001"],          # Default Accounts
    "file_discovery": ["T1083"],                  # File and Directory Discovery
    "system_info": ["T1082"],                     # System Information Discovery
    "account_discovery": ["T1087"],               # Account Discovery
    "process_discovery": ["T1057"],               # Process Discovery
    "network_discovery": ["T1016"],               # System Network Configuration Discovery
    "lateral_attempt": ["T1021"],                 # Remote Services
    "tool_download": ["T1105"],                   # Ingress Tool Transfer
    "reverse_shell": ["T1059.004"],               # Unix Shell
    "data_collection": ["T1005"],                 # Data from Local System
    "cron_persistence": ["T1053.003"],            # Scheduled Task/Job: Cron
}


class IntelligenceFeedback:
    """
    Converts deception interactions into distributable intelligence.

    Wired to MirageOrchestrator and AdaptiveHoneypot callbacks.
    Outputs to QSecBit, dnsXai, Mesh gossip, and ClickHouse.
    """

    def __init__(self, orchestrator=None):
        self._orchestrator = orchestrator
        self._profiles: Dict[str, AttackerTTPProfile] = {}
        self._intel_queue: List[ThreatIntel] = []
        self._consumers: Dict[str, Callable] = {}

        self._stats = {
            "intel_generated": 0,
            "profiles_created": 0,
            "qsecbit_events_emitted": 0,
            "mesh_gossip_sent": 0,
            "dns_iocs_extracted": 0,
        }

        logger.info("IntelligenceFeedback initialized")

    # ------------------------------------------------------------------
    # Consumer Registration
    # ------------------------------------------------------------------

    def register_consumer(self, name: str, callback: Callable) -> None:
        """Register an intelligence consumer.

        Consumers: 'qsecbit', 'dnsxai', 'mesh', 'clickhouse'
        """
        self._consumers[name] = callback
        logger.info("Intel consumer registered: %s", name)

    # ------------------------------------------------------------------
    # Event Handlers (wired to MirageOrchestrator / AdaptiveHoneypot)
    # ------------------------------------------------------------------

    def on_scan_detected(self, event: str, tracker) -> None:
        """Called when MirageOrchestrator detects a scan."""
        profile = self._get_or_create_profile(tracker.source_ip)
        profile.techniques.update(DECEPTION_MITRE_MAP["port_scan"])

        intel = ThreatIntel(
            intel_type=IntelType.SCAN_PATTERN,
            source_ip=tracker.source_ip,
            confidence=0.7,
            data={
                "ports_probed": list(tracker.ports_probed),
                "dark_port_hits": tracker.dark_port_count,
                "scan_rate": tracker.dark_port_count / max(
                    (datetime.utcnow() - tracker.first_seen).total_seconds(), 1
                ),
            },
            mitre_techniques=["T1046"],
            ioc_value=tracker.source_ip,
            ioc_type="ip",
        )
        self._publish_intel(intel)

    def on_honeypot_deployed(self, event: str, tracker) -> None:
        """Called when a honeypot is auto-deployed for an attacker."""
        profile = self._get_or_create_profile(tracker.source_ip)
        profile.last_seen = datetime.utcnow()

    def on_attacker_profiled(self, event: str, tracker) -> None:
        """Called when attacker moves to PROFILING state."""
        profile = self._get_or_create_profile(tracker.source_ip)
        profile.last_seen = datetime.utcnow()

        # Emit aggregated TTP profile
        intel = ThreatIntel(
            intel_type=IntelType.TTP_CHAIN,
            source_ip=tracker.source_ip,
            confidence=0.85,
            data=profile.to_dict(),
            mitre_techniques=list(profile.techniques),
            ioc_value=tracker.source_ip,
            ioc_type="ip",
        )
        self._publish_intel(intel)

    def on_session_closed(self, event: str, session) -> None:
        """Called when AdaptiveHoneypot closes a session."""
        profile = self._get_or_create_profile(session.source_ip)
        profile.sophistication = session.sophistication.name
        profile.commands_executed += len(session.commands_received)
        profile.credentials_used += len(session.credentials_tried)
        profile.payloads_captured += len(session.payloads_captured)
        profile.last_seen = datetime.utcnow()

        # Extract TTPs from commands
        self._extract_command_ttps(session, profile)

        # Transition orchestrator to LEARNING if appropriate
        if self._orchestrator and profile.threat_score >= 0.5:
            self._orchestrator.transition_to_learning(session.source_ip)

    def on_payload_captured(self, event: str, session) -> None:
        """Called when a payload is captured."""
        profile = self._get_or_create_profile(session.source_ip)

        for payload_hash in session.payloads_captured[-1:]:
            intel = ThreatIntel(
                intel_type=IntelType.PAYLOAD_HASH,
                source_ip=session.source_ip,
                confidence=0.9,
                data={
                    "payload_hash": payload_hash,
                    "captured_command": session.commands_received[-1] if session.commands_received else "",
                },
                mitre_techniques=["T1105"],
                ioc_value=payload_hash,
                ioc_type="hash",
            )
            self._publish_intel(intel)

    def on_sophistication_changed(self, event: str, session) -> None:
        """Called when sophistication level changes."""
        profile = self._get_or_create_profile(session.source_ip)
        profile.sophistication = session.sophistication.name

    # ------------------------------------------------------------------
    # TTP Extraction
    # ------------------------------------------------------------------

    def _extract_command_ttps(self, session, profile: AttackerTTPProfile) -> None:
        """Extract MITRE TTPs from executed commands."""
        for cmd in session.commands_received:
            cmd_lower = cmd.lower()

            if any(k in cmd_lower for k in ("cat /etc/passwd", "cat /etc/shadow", "/etc/group")):
                profile.techniques.update(DECEPTION_MITRE_MAP["account_discovery"])

            if any(k in cmd_lower for k in ("ls ", "find ", "locate ", "tree ")):
                profile.techniques.update(DECEPTION_MITRE_MAP["file_discovery"])

            if any(k in cmd_lower for k in ("uname", "hostname", "cat /proc", "lsb_release")):
                profile.techniques.update(DECEPTION_MITRE_MAP["system_info"])

            if any(k in cmd_lower for k in ("ps ", "top ", "pgrep")):
                profile.techniques.update(DECEPTION_MITRE_MAP["process_discovery"])

            if any(k in cmd_lower for k in ("ifconfig", "ip addr", "netstat", "ss ")):
                profile.techniques.update(DECEPTION_MITRE_MAP["network_discovery"])

            if any(k in cmd_lower for k in ("wget ", "curl ", "scp ", "tftp")):
                profile.techniques.update(DECEPTION_MITRE_MAP["tool_download"])

            if any(k in cmd_lower for k in ("/dev/tcp", "nc -e", "bash -i", "mkfifo")):
                profile.techniques.update(DECEPTION_MITRE_MAP["reverse_shell"])

            if any(k in cmd_lower for k in ("crontab", "/etc/cron")):
                profile.techniques.update(DECEPTION_MITRE_MAP["cron_persistence"])

    # ------------------------------------------------------------------
    # Intelligence Distribution
    # ------------------------------------------------------------------

    def _publish_intel(self, intel: ThreatIntel) -> None:
        """Distribute intelligence to all registered consumers."""
        self._intel_queue.append(intel)
        self._stats["intel_generated"] += 1

        for name, consumer in self._consumers.items():
            try:
                consumer(intel)
                if name == "qsecbit":
                    self._stats["qsecbit_events_emitted"] += 1
                elif name == "mesh":
                    self._stats["mesh_gossip_sent"] += 1
            except Exception as e:
                logger.error("Intel consumer '%s' error: %s", name, e)

        logger.debug(
            "Intel published: %s from %s (confidence=%.2f)",
            intel.intel_type.value, intel.source_ip, intel.confidence,
        )

    def create_qsecbit_threat_event(self, intel: ThreatIntel) -> Dict[str, Any]:
        """Convert ThreatIntel to a QSecBit-compatible ThreatEvent dict."""
        severity_map = {
            IntelType.SCAN_PATTERN: "MEDIUM",
            IntelType.CREDENTIAL_SET: "HIGH",
            IntelType.TOOL_SIGNATURE: "MEDIUM",
            IntelType.PAYLOAD_HASH: "HIGH",
            IntelType.C2_INDICATOR: "CRITICAL",
            IntelType.TTP_CHAIN: "HIGH",
            IntelType.DNS_IOC: "MEDIUM",
        }
        return {
            "source": "mirage",
            "type": f"deception_{intel.intel_type.value}",
            "severity": severity_map.get(intel.intel_type, "MEDIUM"),
            "confidence": intel.confidence,
            "source_ip": intel.source_ip,
            "timestamp": intel.timestamp.isoformat(),
            "mitre_techniques": intel.mitre_techniques,
            "evidence": intel.data,
            "ioc_type": intel.ioc_type,
            "ioc_value": intel.ioc_value,
        }

    def create_mesh_gossip_payload(self, intel: ThreatIntel) -> Dict[str, Any]:
        """Convert ThreatIntel to a mesh gossip payload."""
        return {
            "type": "mirage_intel",
            "intel_id": intel.intel_id,
            "source_ip": intel.source_ip,
            "intel_type": intel.intel_type.value,
            "confidence": intel.confidence,
            "mitre": intel.mitre_techniques,
            "ioc_type": intel.ioc_type,
            "ioc_value": intel.ioc_value,
            "timestamp": intel.timestamp.isoformat(),
        }

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_profile(self, source_ip: str) -> Optional[AttackerTTPProfile]:
        return self._profiles.get(source_ip)

    def get_all_profiles(self) -> List[AttackerTTPProfile]:
        return list(self._profiles.values())

    def get_recent_intel(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [i.to_dict() for i in self._intel_queue[-limit:]]

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "profiles": len(self._profiles),
            "intel_queue_size": len(self._intel_queue),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_or_create_profile(self, source_ip: str) -> AttackerTTPProfile:
        if source_ip not in self._profiles:
            self._profiles[source_ip] = AttackerTTPProfile(source_ip=source_ip)
            self._stats["profiles_created"] += 1
        return self._profiles[source_ip]
