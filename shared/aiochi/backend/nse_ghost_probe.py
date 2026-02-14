"""
AIOCHI NSE Ghost Probe Service
Active interrogation using Nmap Scripting Engine to verify suspicious devices.

Philosophy: Most systems are passive until an alert fires. Ghost Probe uses
NSE as a proactive verification tool - when NAPSE triggers, we instantly
fingerprint the source to catch masquerading (T1036).

MITRE Coverage:
- T1036 (Masquerading) - Detect devices pretending to be something else
- T1584 (Compromised Infrastructure) - Identify compromised internal hosts
- T1041 (Exfiltration Over C2) - Verify C2 channel authenticity

Innovation: Single-packet NSE probes that verify device identity without
triggering attacker detection. A "printer" running Metasploit = instant Red Zone.

Usage:
    from nse_ghost_probe import NSEGhostProbe
    probe = NSEGhostProbe()
    result = probe.probe("10.200.0.50")  # Instant fingerprint
"""

import json
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from xml.etree import ElementTree

logger = logging.getLogger(__name__)


class ProbeVerdict(Enum):
    """Verdict from ghost probe analysis."""
    CLEAN = "clean"           # Device matches expected profile
    SUSPICIOUS = "suspicious"  # Minor discrepancies found
    MASQUERADING = "masq"     # Device pretending to be something else
    COMPROMISED = "compromised"  # Signs of active compromise
    UNKNOWN = "unknown"       # Could not determine


@dataclass
class ProbeResult:
    """Result of a ghost probe operation."""
    target_ip: str
    timestamp: datetime = field(default_factory=datetime.now)
    verdict: ProbeVerdict = ProbeVerdict.UNKNOWN
    confidence: float = 0.0  # 0-1 confidence in verdict
    duration_ms: float = 0.0

    # Fingerprint data
    os_guess: str = ""
    os_accuracy: int = 0
    device_type: str = ""
    vendor: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)

    # Analysis
    discrepancies: List[str] = field(default_factory=list)
    suspicious_services: List[str] = field(default_factory=list)
    mitre_indicators: List[str] = field(default_factory=list)

    # Raw data
    raw_xml: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "timestamp": self.timestamp.isoformat(),
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "duration_ms": self.duration_ms,
            "os_guess": self.os_guess,
            "os_accuracy": self.os_accuracy,
            "device_type": self.device_type,
            "vendor": self.vendor,
            "open_ports": self.open_ports,
            "services": self.services,
            "discrepancies": self.discrepancies,
            "suspicious_services": self.suspicious_services,
            "mitre_indicators": self.mitre_indicators,
            "error": self.error,
        }


# Known suspicious service signatures
SUSPICIOUS_SERVICE_PATTERNS = [
    # Metasploit/Meterpreter indicators
    (r"metasploit", "Metasploit framework detected", "T1059"),
    (r"meterpreter", "Meterpreter payload detected", "T1059"),
    (r"msf|msfconsole", "MSF console signature", "T1059"),

    # Cobalt Strike indicators
    (r"beacon", "Possible Cobalt Strike beacon", "T1071.001"),
    (r"cobaltstrike", "Cobalt Strike detected", "T1071.001"),

    # C2 framework indicators
    (r"empire", "Empire C2 framework", "T1071.001"),
    (r"pupy", "Pupy RAT signature", "T1071.001"),
    (r"covenant", "Covenant C2 framework", "T1071.001"),

    # Reverse shell indicators
    (r"netcat|nc\s+-e", "Netcat reverse shell", "T1059"),
    (r"bash.*-i.*>&.*tcp", "Bash reverse shell", "T1059"),

    # Exploitation framework indicators
    (r"exploit|shellcode", "Exploitation activity", "T1203"),
    (r"payload.*stage", "Staged payload delivery", "T1059"),

    # Suspicious web services
    (r"php.*cli", "PHP CLI server (unusual)", "T1505"),
    (r"python.*http\.server", "Python HTTP server", "T1505"),

    # Credential theft tools
    (r"mimikatz|sekurlsa", "Mimikatz detected", "T1003"),
    (r"lazagne", "LaZagne credential harvester", "T1003"),
]

# Expected device profiles (for masquerading detection)
DEVICE_PROFILES = {
    "printer": {
        "expected_ports": [9100, 515, 631],
        "unexpected_ports": [22, 23, 445, 3389, 4444, 5555],
        "expected_vendors": ["HP", "Canon", "Epson", "Brother", "Xerox"],
    },
    "camera": {
        "expected_ports": [80, 443, 554],
        "unexpected_ports": [22, 23, 445, 3389],
        "expected_vendors": ["Hikvision", "Dahua", "Axis", "Foscam", "Amcrest"],
    },
    "pos_terminal": {
        "expected_ports": [443, 8443],
        "unexpected_ports": [22, 23, 3389, 4444],
        "expected_vendors": ["Square", "Clover", "Verifone", "Ingenico"],
    },
    "iot_device": {
        "expected_ports": [80, 443, 8080],
        "unexpected_ports": [22, 23, 445, 3389, 4444, 5555],
        "expected_vendors": [],
    },
}


class NSEGhostProbe:
    """
    NSE Ghost Probe Service for active device interrogation.

    Launches targeted Nmap probes to verify device identity and
    catch masquerading or compromised hosts.
    """

    # NSE scripts to run (lightweight, fast)
    DEFAULT_SCRIPTS = [
        "banner",           # Grab service banners
        "http-title",       # Web page titles
        "ssl-cert",         # SSL certificate info
        "smb-os-discovery", # SMB OS detection
    ]

    # Aggressive scripts for deep investigation
    AGGRESSIVE_SCRIPTS = [
        "vulners",          # CVE detection
        "http-enum",        # Web enumeration
        "smb-enum-shares",  # SMB share enumeration
        "ssh-auth-methods", # SSH authentication
    ]

    def __init__(
        self,
        dry_run: bool = False,
        timeout_seconds: int = 30,
        max_concurrent_probes: int = 5,
        aggressive_mode: bool = False,
    ):
        """
        Initialize the Ghost Probe service.

        Args:
            dry_run: Log commands instead of executing
            timeout_seconds: Probe timeout
            max_concurrent_probes: Max concurrent probes
            aggressive_mode: Use aggressive NSE scripts
        """
        self.dry_run = dry_run
        self.timeout_seconds = timeout_seconds
        self.aggressive_mode = aggressive_mode

        # Thread pool for concurrent probes
        self._executor = ThreadPoolExecutor(max_workers=max_concurrent_probes)

        # Probe cache (avoid re-probing same IP within window)
        self._cache: Dict[str, ProbeResult] = {}
        self._cache_ttl_seconds = 300  # 5 minutes

        # Callbacks for probe results
        self._callbacks: List[Callable[[ProbeResult], None]] = []

        # Statistics
        self._stats = {
            "probes_launched": 0,
            "probes_completed": 0,
            "probes_timeout": 0,
            "masquerading_detected": 0,
            "compromised_detected": 0,
        }

        # Lock for thread safety
        self._lock = threading.Lock()

        logger.info("NSE Ghost Probe initialized")

    def probe(
        self,
        target_ip: str,
        expected_device_type: Optional[str] = None,
        ports: Optional[List[int]] = None,
        use_cache: bool = True,
    ) -> ProbeResult:
        """
        Launch a ghost probe against a target.

        Args:
            target_ip: Target IP address
            expected_device_type: Expected device type for comparison
            ports: Specific ports to probe (default: common ports)
            use_cache: Use cached results if available

        Returns:
            ProbeResult with fingerprint and verdict
        """
        # Check cache
        if use_cache:
            cached = self._get_cached(target_ip)
            if cached:
                return cached

        start_time = time.time()
        self._stats["probes_launched"] += 1

        result = ProbeResult(target_ip=target_ip)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would probe {target_ip}")
            result.verdict = ProbeVerdict.UNKNOWN
            result.confidence = 0.0
            return result

        try:
            # Run nmap with NSE scripts
            raw_xml = self._run_nmap(target_ip, ports)
            result.raw_xml = raw_xml
            result.duration_ms = (time.time() - start_time) * 1000

            # Parse results
            self._parse_nmap_xml(result, raw_xml)

            # Analyze for suspicious activity
            self._analyze_services(result)

            # Check for masquerading
            if expected_device_type:
                self._check_masquerading(result, expected_device_type)

            # Determine final verdict
            self._calculate_verdict(result)

            self._stats["probes_completed"] += 1

        except subprocess.TimeoutExpired:
            result.error = "Probe timeout"
            result.verdict = ProbeVerdict.UNKNOWN
            self._stats["probes_timeout"] += 1

        except Exception as e:
            result.error = str(e)
            result.verdict = ProbeVerdict.UNKNOWN
            logger.error(f"Probe error for {target_ip}: {e}")

        # Cache result
        with self._lock:
            self._cache[target_ip] = result

        # Update stats
        if result.verdict == ProbeVerdict.MASQUERADING:
            self._stats["masquerading_detected"] += 1
        elif result.verdict == ProbeVerdict.COMPROMISED:
            self._stats["compromised_detected"] += 1

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        logger.info(
            f"Probe {target_ip}: verdict={result.verdict.value}, "
            f"confidence={result.confidence:.0%}, duration={result.duration_ms:.0f}ms"
        )

        return result

    def probe_async(
        self,
        target_ip: str,
        expected_device_type: Optional[str] = None,
        callback: Optional[Callable[[ProbeResult], None]] = None,
    ):
        """
        Launch asynchronous probe.

        Args:
            target_ip: Target IP address
            expected_device_type: Expected device type
            callback: Callback function for result
        """
        def _probe_and_callback():
            result = self.probe(target_ip, expected_device_type)
            if callback:
                callback(result)
            return result

        return self._executor.submit(_probe_and_callback)

    def _run_nmap(
        self,
        target_ip: str,
        ports: Optional[List[int]] = None,
    ) -> str:
        """Run nmap scan and return XML output."""
        scripts = self.AGGRESSIVE_SCRIPTS if self.aggressive_mode else self.DEFAULT_SCRIPTS

        cmd = [
            "nmap",
            "-Pn",              # Skip host discovery
            "-sV",              # Version detection
            "-O",               # OS detection
            "--osscan-guess",   # Aggressive OS guessing
            f"--script={','.join(scripts)}",
            "-oX", "-",         # XML to stdout
        ]

        # Add port specification
        if ports:
            cmd.extend(["-p", ",".join(str(p) for p in ports)])
        else:
            # Default: top 100 ports plus suspicious ones
            cmd.extend(["-F"])  # Fast scan (top 100 ports)

        cmd.append(target_ip)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )

        return result.stdout

    def _parse_nmap_xml(self, result: ProbeResult, xml_str: str) -> None:
        """Parse nmap XML output into ProbeResult."""
        try:
            root = ElementTree.fromstring(xml_str)

            # Find host element
            host = root.find(".//host")
            if host is None:
                return

            # Parse OS detection
            os_match = host.find(".//osmatch")
            if os_match is not None:
                result.os_guess = os_match.get("name", "")
                result.os_accuracy = int(os_match.get("accuracy", 0))

            # Parse device type
            os_class = host.find(".//osclass")
            if os_class is not None:
                result.device_type = os_class.get("type", "")
                result.vendor = os_class.get("vendor", "")

            # Parse open ports and services
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_id = int(port.get("portid", 0))
                    result.open_ports.append(port_id)

                    service = port.find("service")
                    if service is not None:
                        service_name = service.get("name", "unknown")
                        product = service.get("product", "")
                        version = service.get("version", "")
                        service_str = f"{service_name}"
                        if product:
                            service_str += f" ({product} {version})"
                        result.services[port_id] = service_str

            # Parse script output
            for script in host.findall(".//script"):
                script_id = script.get("id", "")
                output = script.get("output", "")

                # Check for suspicious patterns in script output
                for pattern, desc, mitre_id in SUSPICIOUS_SERVICE_PATTERNS:
                    if re.search(pattern, output, re.IGNORECASE):
                        result.suspicious_services.append(f"{script_id}: {desc}")
                        if mitre_id not in result.mitre_indicators:
                            result.mitre_indicators.append(mitre_id)

        except Exception as e:
            logger.error(f"XML parsing error: {e}")

    def _analyze_services(self, result: ProbeResult) -> None:
        """Analyze services for suspicious patterns."""
        for port, service in result.services.items():
            service_lower = service.lower()

            # Check against suspicious patterns
            for pattern, desc, mitre_id in SUSPICIOUS_SERVICE_PATTERNS:
                if re.search(pattern, service_lower, re.IGNORECASE):
                    result.suspicious_services.append(f"Port {port}: {desc}")
                    if mitre_id not in result.mitre_indicators:
                        result.mitre_indicators.append(mitre_id)

            # Check for common attacker tools on unexpected ports
            suspicious_combos = [
                (4444, "Metasploit default handler"),
                (5555, "Possible ADB or RAT"),
                (1234, "Common reverse shell port"),
                (6666, "Suspicious port"),
                (6667, "IRC (possible C2)"),
                (8888, "Alternative HTTP (possible C2)"),
            ]

            for sus_port, desc in suspicious_combos:
                if port == sus_port:
                    result.suspicious_services.append(f"Port {port}: {desc}")

    def _check_masquerading(
        self,
        result: ProbeResult,
        expected_type: str,
    ) -> None:
        """Check if device is masquerading as expected type."""
        profile = DEVICE_PROFILES.get(expected_type, {})
        if not profile:
            return

        expected_ports = set(profile.get("expected_ports", []))
        unexpected_ports = set(profile.get("unexpected_ports", []))
        expected_vendors = profile.get("expected_vendors", [])

        open_ports = set(result.open_ports)

        # Check for unexpected open ports
        unexpected_found = open_ports.intersection(unexpected_ports)
        if unexpected_found:
            result.discrepancies.append(
                f"Unexpected ports for {expected_type}: {list(unexpected_found)}"
            )
            result.mitre_indicators.append("T1036")

        # Check for missing expected ports
        missing_expected = expected_ports - open_ports
        if missing_expected and len(missing_expected) == len(expected_ports):
            result.discrepancies.append(
                f"Missing all expected ports for {expected_type}"
            )

        # Check vendor mismatch
        if expected_vendors and result.vendor:
            vendor_match = any(
                v.lower() in result.vendor.lower()
                for v in expected_vendors
            )
            if not vendor_match:
                result.discrepancies.append(
                    f"Vendor mismatch: expected {expected_vendors}, got {result.vendor}"
                )
                result.mitre_indicators.append("T1036")

    def _calculate_verdict(self, result: ProbeResult) -> None:
        """Calculate final verdict based on analysis."""
        # Start with clean assumption
        verdict = ProbeVerdict.CLEAN
        confidence = 0.5

        # Check for compromised indicators (highest priority)
        if result.suspicious_services:
            if any("Metasploit" in s or "Meterpreter" in s for s in result.suspicious_services):
                verdict = ProbeVerdict.COMPROMISED
                confidence = 0.95
            elif any("Cobalt Strike" in s or "beacon" in s for s in result.suspicious_services):
                verdict = ProbeVerdict.COMPROMISED
                confidence = 0.95
            elif len(result.suspicious_services) >= 2:
                verdict = ProbeVerdict.COMPROMISED
                confidence = 0.85
            else:
                verdict = ProbeVerdict.SUSPICIOUS
                confidence = 0.70

        # Check for masquerading
        elif result.discrepancies:
            if "T1036" in result.mitre_indicators:
                verdict = ProbeVerdict.MASQUERADING
                confidence = 0.80
            elif len(result.discrepancies) >= 2:
                verdict = ProbeVerdict.SUSPICIOUS
                confidence = 0.65
            else:
                verdict = ProbeVerdict.SUSPICIOUS
                confidence = 0.55

        # If nothing suspicious, but low OS accuracy
        elif result.os_accuracy < 50 and result.os_accuracy > 0:
            verdict = ProbeVerdict.SUSPICIOUS
            confidence = 0.40

        # Clean
        else:
            verdict = ProbeVerdict.CLEAN
            confidence = 0.75 + (result.os_accuracy / 400)  # Boost confidence with OS accuracy

        result.verdict = verdict
        result.confidence = min(confidence, 1.0)

    def _get_cached(self, target_ip: str) -> Optional[ProbeResult]:
        """Get cached probe result if still valid."""
        with self._lock:
            cached = self._cache.get(target_ip)
            if cached:
                age_seconds = (datetime.now() - cached.timestamp).total_seconds()
                if age_seconds < self._cache_ttl_seconds:
                    return cached
        return None

    # =========================================================================
    # Integration with Playbook Engine
    # =========================================================================

    def handle_alert(
        self,
        alert: Dict[str, Any],
        expected_device_type: Optional[str] = None,
    ) -> Optional[ProbeResult]:
        """
        Handle IDS alert by probing the source.

        Args:
            alert: NAPSE alert
            expected_device_type: Expected device type for the source IP

        Returns:
            ProbeResult if probe completed
        """
        src_ip = alert.get("src_ip", "")
        if not src_ip:
            return None

        # Only probe internal sources
        if not src_ip.startswith(("10.", "192.168.", "172.")):
            return None

        logger.info(f"Ghost probing alert source: {src_ip}")
        return self.probe(src_ip, expected_device_type)

    def add_callback(self, callback: Callable[[ProbeResult], None]) -> None:
        """Add callback for probe results."""
        self._callbacks.append(callback)

    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        return {
            **self._stats,
            "cache_size": len(self._cache),
            "aggressive_mode": self.aggressive_mode,
        }

    def clear_cache(self) -> None:
        """Clear probe cache."""
        with self._lock:
            self._cache.clear()


# Singleton instance
_probe_service: Optional[NSEGhostProbe] = None


def get_ghost_probe(dry_run: bool = False) -> NSEGhostProbe:
    """Get or create singleton ghost probe service."""
    global _probe_service

    if _probe_service is None:
        _probe_service = NSEGhostProbe(dry_run=dry_run)

    return _probe_service


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    probe = NSEGhostProbe(dry_run=True)

    print("NSE Ghost Probe Demo")
    print("=" * 60)

    # Simulate a probe result for demonstration
    result = ProbeResult(
        target_ip="10.200.0.50",
        verdict=ProbeVerdict.SUSPICIOUS,
        confidence=0.75,
        os_guess="Linux 4.x",
        os_accuracy=85,
        device_type="general purpose",
        vendor="Generic",
        open_ports=[22, 80, 443, 4444],
        services={
            22: "OpenSSH 8.4 (Ubuntu)",
            80: "nginx 1.18",
            443: "nginx 1.18",
            4444: "Metasploit handler",
        },
        suspicious_services=["Port 4444: Metasploit default handler"],
        mitre_indicators=["T1059"],
    )

    print(f"\nProbe Result for {result.target_ip}:")
    print(f"  Verdict: {result.verdict.value}")
    print(f"  Confidence: {result.confidence:.0%}")
    print(f"  OS: {result.os_guess} ({result.os_accuracy}% accuracy)")
    print(f"  Open Ports: {result.open_ports}")
    print(f"  Suspicious: {result.suspicious_services}")
    print(f"  MITRE: {result.mitre_indicators}")

    # Show suspicious patterns we detect
    print("\n" + "=" * 60)
    print("Suspicious Patterns We Detect:")
    for pattern, desc, mitre in SUSPICIOUS_SERVICE_PATTERNS[:5]:
        print(f"  - {desc} ({mitre})")

    print("\n" + "=" * 60)
    print("Device Profiles for Masquerading Detection:")
    for device_type, profile in DEVICE_PROFILES.items():
        print(f"  {device_type}:")
        print(f"    Expected ports: {profile['expected_ports']}")
        print(f"    Suspicious ports: {profile['unexpected_ports'][:5]}...")
