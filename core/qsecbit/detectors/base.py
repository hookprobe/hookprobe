"""
Qsecbit Unified - Base Detector Class

Abstract base class for all layer-specific threat detectors.
Provides common utilities for threat detection, logging, and event creation.

Author: HookProbe Team
License: Proprietary
Version: 5.0.0
"""

import os
import re
import json
import shlex
import subprocess
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple, Union
from collections import deque

from ..threat_types import (
    ThreatEvent, AttackType, ThreatSeverity, OSILayer,
    ResponseAction, ATTACK_LAYER_MAP, MITRE_ATTACK_MAP, DEFAULT_SEVERITY_MAP
)


class BaseDetector(ABC):
    """
    Abstract base class for all layer-specific threat detectors.

    Provides:
    - Common command execution with security measures
    - Threat event creation and tracking
    - Rate limiting for detection (avoid alert fatigue)
    - Evidence collection utilities
    """

    def __init__(
        self,
        name: str,
        layer: OSILayer,
        data_dir: str = "/opt/hookprobe/data",
        max_history: int = 1000,
        dedup_window_seconds: int = 60
    ):
        """
        Initialize base detector.

        Args:
            name: Detector name (e.g., "L2DataLinkDetector")
            layer: Primary OSI layer this detector handles
            data_dir: Directory for persistent state
            max_history: Maximum threats to keep in memory
            dedup_window_seconds: Time window for deduplication
        """
        self.name = name
        self.layer = layer
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.max_history = max_history
        self.dedup_window = timedelta(seconds=dedup_window_seconds)

        # Threat history
        self.threats: deque = deque(maxlen=max_history)
        self.recent_detections: Dict[str, datetime] = {}  # For deduplication

        # Statistics
        self.total_detections = 0
        self.blocked_count = 0
        self.last_detection_time: Optional[datetime] = None

        # Log paths
        self.suricata_log = Path("/var/log/suricata/eve.json")
        self.zeek_log_dir = Path("/var/log/zeek/current")

    def _run_command(
        self,
        cmd: Union[str, List[str]],
        timeout: int = 10
    ) -> Tuple[str, bool]:
        """
        Run command safely without shell=True to prevent command injection.

        Args:
            cmd: Command string or list of arguments
            timeout: Timeout in seconds

        Returns:
            Tuple of (stdout, success)
        """
        try:
            if isinstance(cmd, str):
                cmd_list = shlex.split(cmd)
            else:
                cmd_list = cmd

            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip(), result.returncode == 0
        except subprocess.TimeoutExpired:
            return "Command timed out", False
        except FileNotFoundError:
            return "Command not found", False
        except Exception as e:
            return str(e), False

    def _read_proc_file(self, path: str) -> Tuple[str, bool]:
        """Read a /proc file safely."""
        try:
            with open(path, 'r') as f:
                return f.read().strip(), True
        except Exception as e:
            return str(e), False

    def _create_threat_event(
        self,
        attack_type: AttackType,
        description: str,
        confidence: float = 0.8,
        source_ip: Optional[str] = None,
        source_mac: Optional[str] = None,
        dest_ip: Optional[str] = None,
        dest_port: Optional[int] = None,
        evidence: Optional[Dict[str, Any]] = None,
        severity_override: Optional[ThreatSeverity] = None
    ) -> ThreatEvent:
        """
        Create a standardized ThreatEvent.

        Args:
            attack_type: Type of attack detected
            description: Human-readable description
            confidence: Detection confidence (0.0-1.0)
            source_ip: Attacker IP address
            source_mac: Attacker MAC address
            dest_ip: Target IP address
            dest_port: Target port
            evidence: Additional evidence dictionary
            severity_override: Override default severity

        Returns:
            ThreatEvent object
        """
        event_id = str(uuid.uuid4())
        layer = ATTACK_LAYER_MAP.get(attack_type, self.layer)
        severity = severity_override or DEFAULT_SEVERITY_MAP.get(attack_type, ThreatSeverity.MEDIUM)
        mitre_id = MITRE_ATTACK_MAP.get(attack_type, "")

        return ThreatEvent(
            id=event_id,
            timestamp=datetime.now(),
            attack_type=attack_type,
            layer=layer,
            severity=severity,
            source_ip=source_ip,
            source_mac=source_mac,
            dest_ip=dest_ip,
            dest_port=dest_port,
            description=description,
            confidence=confidence,
            detector=self.name,
            evidence=evidence or {},
            mitre_attack_id=mitre_id,
        )

    def _should_deduplicate(self, key: str) -> bool:
        """
        Check if we should skip this detection (already detected recently).

        Args:
            key: Unique key for this detection (e.g., "arp_spoof:192.168.1.1")

        Returns:
            True if should skip (already detected recently)
        """
        now = datetime.now()

        # Clean old entries
        expired = [k for k, t in self.recent_detections.items()
                   if now - t > self.dedup_window]
        for k in expired:
            del self.recent_detections[k]

        if key in self.recent_detections:
            return True

        self.recent_detections[key] = now
        return False

    def _add_threat(self, threat: ThreatEvent) -> bool:
        """
        Add a threat event to history.

        Args:
            threat: ThreatEvent to add

        Returns:
            True if added (not deduplicated)
        """
        # Create dedup key
        dedup_key = f"{threat.attack_type.name}:{threat.source_ip or threat.source_mac or 'unknown'}"

        if self._should_deduplicate(dedup_key):
            return False

        self.threats.append(threat)
        self.total_detections += 1
        self.last_detection_time = threat.timestamp

        if threat.blocked:
            self.blocked_count += 1

        return True

    def _parse_ip_from_line(self, line: str) -> Optional[str]:
        """Extract first IP address from a log line."""
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        return match.group(1) if match else None

    def _parse_mac_from_line(self, line: str) -> Optional[str]:
        """Extract first MAC address from a log line."""
        match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
        return match.group(0).lower() if match else None

    def _read_suricata_alerts(
        self,
        patterns: List[str],
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Read and filter Suricata EVE JSON alerts.

        Args:
            patterns: List of regex patterns to match against signatures
            limit: Maximum alerts to return

        Returns:
            List of matching alert events
        """
        if not self.suricata_log.exists():
            return []

        alerts = []
        try:
            # Use tail to get recent entries
            output, success = self._run_command(
                f'tail -500 {self.suricata_log}'
            )
            if not success:
                return []

            for line in output.split('\n'):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if event.get('event_type') != 'alert':
                        continue

                    signature = event.get('alert', {}).get('signature', '').lower()
                    for pattern in patterns:
                        if re.search(pattern, signature, re.IGNORECASE):
                            alerts.append(event)
                            break

                    if len(alerts) >= limit:
                        break
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass

        return alerts

    def _read_zeek_log(
        self,
        log_name: str,
        limit: int = 200
    ) -> List[List[str]]:
        """
        Read and parse a Zeek log file.

        Args:
            log_name: Log file name (e.g., "conn.log", "dns.log")
            limit: Maximum lines to read

        Returns:
            List of parsed log entries (tab-separated fields)
        """
        log_path = self.zeek_log_dir / log_name
        if not log_path.exists():
            return []

        entries = []
        try:
            output, success = self._run_command(f'tail -{limit} {log_path}')
            if not success:
                return []

            for line in output.split('\n'):
                if line.startswith('#') or not line.strip():
                    continue
                entries.append(line.split('\t'))
        except Exception:
            pass

        return entries

    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics."""
        threat_counts = {
            ThreatSeverity.CRITICAL: 0,
            ThreatSeverity.HIGH: 0,
            ThreatSeverity.MEDIUM: 0,
            ThreatSeverity.LOW: 0,
            ThreatSeverity.INFO: 0,
        }
        attack_types: Dict[AttackType, int] = {}

        for threat in self.threats:
            threat_counts[threat.severity] += 1
            attack_types[threat.attack_type] = attack_types.get(threat.attack_type, 0) + 1

        return {
            'name': self.name,
            'layer': self.layer.name,
            'total_detections': self.total_detections,
            'blocked_count': self.blocked_count,
            'active_threats': len(self.threats),
            'last_detection': self.last_detection_time.isoformat() if self.last_detection_time else None,
            'severity_breakdown': {k.name: v for k, v in threat_counts.items()},
            'attack_types': {k.name: v for k, v in attack_types.items()},
        }

    @abstractmethod
    def detect(self) -> List[ThreatEvent]:
        """
        Run detection and return list of new threat events.

        This method must be implemented by each layer-specific detector.

        Returns:
            List of ThreatEvent objects for newly detected threats
        """
        pass

    def get_recent_threats(self, limit: int = 20) -> List[ThreatEvent]:
        """Get most recent threats."""
        return list(self.threats)[-limit:]

    def get_layer_score(self) -> float:
        """
        Calculate normalized threat score for this layer (0.0-1.0).

        Uses weighted sum of severity counts, normalized to 1.0.
        """
        if not self.threats:
            return 0.0

        # Only count threats from last hour
        cutoff = datetime.now() - timedelta(hours=1)
        recent = [t for t in self.threats if t.timestamp > cutoff]

        if not recent:
            return 0.0

        critical = sum(1 for t in recent if t.severity == ThreatSeverity.CRITICAL)
        high = sum(1 for t in recent if t.severity == ThreatSeverity.HIGH)
        medium = sum(1 for t in recent if t.severity == ThreatSeverity.MEDIUM)
        low = sum(1 for t in recent if t.severity == ThreatSeverity.LOW)

        # Weighted score
        weighted = critical * 1.0 + high * 0.6 + medium * 0.3 + low * 0.1

        # Normalize (5 weighted threats = 1.0)
        return min(1.0, weighted / 5.0)
