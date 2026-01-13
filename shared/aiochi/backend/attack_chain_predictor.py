"""
AIOCHI Attack Chain Predictor
Neuro-predictive "Chain Breaking" - predict and prevent next attack step.

Philosophy: Traditional playbooks react to what happened. Chain Breaking
reacts to what is LIKELY to happen next. By monitoring MITRE ATT&CK technique
sequences, we can predict the next logical step and pre-emptively harden.

Example Chain:
    T1595 (Recon) → T1190 (Exploit) → T1003 (Credential Dump)

When we see T1595 → T1190, we PREDICT T1003 and lock down LSASS/credentials
BEFORE the attacker gets there.

Innovation: Rule-based chain patterns combined with Markov probability
model for attack flow prediction.

Usage:
    from attack_chain_predictor import AttackChainPredictor
    predictor = AttackChainPredictor()
    predictor.observe("10.200.0.50", "T1595")  # Recon observed
    predictor.observe("10.200.0.50", "T1190")  # Exploit observed
    prediction = predictor.predict("10.200.0.50")  # Returns T1003 with actions
"""

import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class AttackChain:
    """Represents an observed attack chain for a device."""
    device_ip: str
    device_mac: Optional[str] = None
    techniques: List[Tuple[str, datetime]] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    predicted_next: List[str] = field(default_factory=list)
    hardening_applied: List[str] = field(default_factory=list)

    def add_technique(self, technique_id: str) -> None:
        """Add observed technique to chain."""
        now = datetime.now()
        self.techniques.append((technique_id, now))
        self.last_seen = now

    def get_sequence(self) -> List[str]:
        """Get ordered sequence of techniques."""
        return [t[0] for t in self.techniques]


@dataclass
class ChainPrediction:
    """Prediction of next likely attack technique."""
    device_ip: str
    predicted_technique: str
    confidence: float  # 0-1
    probability: float  # 0-1
    reason: str
    hardening_actions: List[str] = field(default_factory=list)
    chain_so_far: List[str] = field(default_factory=list)
    mitre_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_ip": self.device_ip,
            "predicted_technique": self.predicted_technique,
            "confidence": self.confidence,
            "probability": self.probability,
            "reason": self.reason,
            "hardening_actions": self.hardening_actions,
            "chain_so_far": self.chain_so_far,
            "mitre_name": self.mitre_name,
        }


# =============================================================================
# ATTACK CHAIN PATTERNS (Rule-Based)
# Based on real-world attack flows from MITRE ATT&CK
# =============================================================================

# Common attack chains: (trigger_sequence, next_technique, hardening_actions)
CHAIN_PATTERNS: List[Tuple[List[str], str, List[str]]] = [
    # -------------------------------------------------------------------------
    # Reconnaissance → Initial Access → Credential Theft
    # -------------------------------------------------------------------------
    (
        ["T1595", "T1190"],  # Recon + Exploit Public App
        "T1003",             # OS Credential Dumping
        ["lock_lsass", "enable_credential_guard", "monitor_sam"]
    ),
    (
        ["T1046", "T1110"],  # Port Scan + Brute Force
        "T1078",             # Valid Accounts (compromised creds)
        ["force_mfa", "lock_account_temp", "alert_it"]
    ),

    # -------------------------------------------------------------------------
    # Phishing → Execution → Persistence
    # -------------------------------------------------------------------------
    (
        ["T1566", "T1204"],  # Phishing + User Execution
        "T1059",             # Command/Scripting
        ["block_powershell_downloads", "enable_script_logging"]
    ),
    (
        ["T1566", "T1059"],  # Phishing + Scripting
        "T1547",             # Boot Persistence
        ["monitor_startup", "lock_registry_keys", "snapshot_scheduled_tasks"]
    ),

    # -------------------------------------------------------------------------
    # Lateral Movement Chains
    # -------------------------------------------------------------------------
    (
        ["T1021", "T1018"],  # Remote Services + Remote Discovery
        "T1570",             # Lateral Tool Transfer
        ["isolate_segment", "block_smb_lateral", "monitor_file_shares"]
    ),
    (
        ["T1046", "T1021"],  # Port Scan + Remote Services
        "T1047",             # WMI Execution
        ["disable_wmi_remote", "enable_wmi_logging"]
    ),
    (
        ["T1078", "T1021"],  # Valid Accounts + Remote Services
        "T1486",             # Ransomware
        ["quarantine_device", "disable_smb_writes", "alert_critical"]
    ),

    # -------------------------------------------------------------------------
    # Exfiltration Chains
    # -------------------------------------------------------------------------
    (
        ["T1083", "T1005"],  # File Discovery + Local Collection
        "T1048",             # Exfiltration Alternative Protocol
        ["throttle_egress", "block_dns_tunnel", "capture_pcap"]
    ),
    (
        ["T1119", "T1074"],  # Automated Collection + Staged
        "T1567",             # Exfil to Cloud Storage
        ["block_cloud_upload", "throttle_bandwidth", "alert_dlp"]
    ),

    # -------------------------------------------------------------------------
    # C2 Establishment Chains
    # -------------------------------------------------------------------------
    (
        ["T1059", "T1071"],  # Scripting + App Layer Protocol
        "T1573",             # Encrypted C2 Channel
        ["block_known_c2", "enable_ssl_inspection", "dns_sinkhole"]
    ),
    (
        ["T1071", "T1568"],  # App Protocol + Dynamic Resolution (DGA)
        "T1102",             # Web Service C2
        ["block_dga_domains", "quarantine_device", "capture_traffic"]
    ),

    # -------------------------------------------------------------------------
    # Defense Evasion Chains
    # -------------------------------------------------------------------------
    (
        ["T1059", "T1562"],  # Scripting + Impair Defenses
        "T1070",             # Indicator Removal
        ["protect_logs", "snapshot_event_logs", "alert_critical"]
    ),

    # -------------------------------------------------------------------------
    # Small Business Specific Chains
    # -------------------------------------------------------------------------
    (
        ["T1566", "T1119"],  # Phishing + Auto Collection (POS focus)
        "T1041",             # Exfil Over C2
        ["isolate_pos", "block_external", "alert_critical"]
    ),
]

# MITRE technique names for human-readable output
MITRE_NAMES: Dict[str, str] = {
    "T1595": "Active Scanning",
    "T1190": "Exploit Public-Facing Application",
    "T1003": "OS Credential Dumping",
    "T1046": "Network Service Scanning",
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1566": "Phishing",
    "T1204": "User Execution",
    "T1059": "Command and Scripting Interpreter",
    "T1547": "Boot or Logon Autostart Execution",
    "T1021": "Remote Services",
    "T1018": "Remote System Discovery",
    "T1570": "Lateral Tool Transfer",
    "T1047": "Windows Management Instrumentation",
    "T1486": "Data Encrypted for Impact",
    "T1083": "File and Directory Discovery",
    "T1005": "Data from Local System",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1119": "Automated Collection",
    "T1074": "Data Staged",
    "T1567": "Exfiltration to Cloud Storage",
    "T1071": "Application Layer Protocol",
    "T1573": "Encrypted Channel",
    "T1568": "Dynamic Resolution",
    "T1102": "Web Service",
    "T1562": "Impair Defenses",
    "T1070": "Indicator Removal",
    "T1041": "Exfiltration Over C2 Channel",
}

# Hardening action descriptions
HARDENING_DESCRIPTIONS: Dict[str, str] = {
    "lock_lsass": "Lock LSASS process to prevent credential dumping",
    "enable_credential_guard": "Enable Windows Credential Guard",
    "monitor_sam": "Enable monitoring on SAM database",
    "force_mfa": "Force multi-factor authentication",
    "lock_account_temp": "Temporarily lock targeted accounts",
    "alert_it": "Alert IT/Security team",
    "block_powershell_downloads": "Block PowerShell download cradles",
    "enable_script_logging": "Enable enhanced script logging",
    "monitor_startup": "Monitor startup/autorun locations",
    "lock_registry_keys": "Lock sensitive registry keys",
    "snapshot_scheduled_tasks": "Snapshot scheduled tasks for comparison",
    "isolate_segment": "Isolate network segment",
    "block_smb_lateral": "Block SMB lateral movement",
    "monitor_file_shares": "Enable file share access monitoring",
    "disable_wmi_remote": "Disable remote WMI access",
    "enable_wmi_logging": "Enable WMI command logging",
    "quarantine_device": "Quarantine the device immediately",
    "disable_smb_writes": "Disable SMB write access",
    "alert_critical": "Send critical security alert",
    "throttle_egress": "Throttle egress bandwidth",
    "block_dns_tunnel": "Block DNS tunneling patterns",
    "capture_pcap": "Capture traffic for analysis",
    "block_cloud_upload": "Block uploads to cloud storage",
    "throttle_bandwidth": "Apply bandwidth throttling",
    "alert_dlp": "Trigger DLP alert",
    "block_known_c2": "Block known C2 infrastructure",
    "enable_ssl_inspection": "Enable SSL/TLS inspection",
    "dns_sinkhole": "Sinkhole suspicious DNS queries",
    "block_dga_domains": "Block DGA-generated domains",
    "capture_traffic": "Capture all device traffic",
    "protect_logs": "Protect audit logs from deletion",
    "snapshot_event_logs": "Snapshot current event logs",
    "isolate_pos": "Isolate POS systems from network",
    "block_external": "Block all external connections",
}


class AttackChainPredictor:
    """
    Attack Chain Predictor using rule-based pattern matching
    and Markov transition probabilities.
    """

    # Transition probability matrix (simplified Markov model)
    # Format: source_technique -> {target_technique: probability}
    TRANSITION_PROBS: Dict[str, Dict[str, float]] = {
        "T1595": {"T1190": 0.4, "T1046": 0.3, "T1566": 0.2, "T1133": 0.1},
        "T1046": {"T1110": 0.3, "T1021": 0.3, "T1078": 0.2, "T1190": 0.2},
        "T1566": {"T1204": 0.5, "T1059": 0.3, "T1119": 0.2},
        "T1204": {"T1059": 0.4, "T1547": 0.3, "T1071": 0.3},
        "T1059": {"T1071": 0.3, "T1547": 0.2, "T1562": 0.2, "T1003": 0.3},
        "T1190": {"T1003": 0.4, "T1059": 0.3, "T1078": 0.3},
        "T1110": {"T1078": 0.6, "T1021": 0.4},
        "T1078": {"T1021": 0.4, "T1486": 0.3, "T1018": 0.3},
        "T1021": {"T1570": 0.3, "T1047": 0.3, "T1018": 0.2, "T1486": 0.2},
        "T1018": {"T1570": 0.4, "T1021": 0.3, "T1083": 0.3},
        "T1083": {"T1005": 0.5, "T1074": 0.3, "T1119": 0.2},
        "T1005": {"T1048": 0.4, "T1074": 0.3, "T1567": 0.3},
        "T1119": {"T1074": 0.4, "T1041": 0.3, "T1048": 0.3},
        "T1074": {"T1048": 0.4, "T1567": 0.3, "T1041": 0.3},
        "T1071": {"T1573": 0.4, "T1568": 0.3, "T1102": 0.3},
        "T1562": {"T1070": 0.5, "T1486": 0.3, "T1071": 0.2},
    }

    def __init__(
        self,
        chain_timeout_minutes: int = 60,
        min_confidence: float = 0.5,
        auto_harden: bool = True,
    ):
        """
        Initialize the Attack Chain Predictor.

        Args:
            chain_timeout_minutes: Time window for chain observation
            min_confidence: Minimum confidence for predictions
            auto_harden: Automatically execute hardening actions
        """
        self.chain_timeout_minutes = chain_timeout_minutes
        self.min_confidence = min_confidence
        self.auto_harden = auto_harden

        # Active chains per device
        self._chains: Dict[str, AttackChain] = {}

        # Callbacks for predictions
        self._callbacks: List[Callable[[ChainPrediction], None]] = []

        # Hardening action executors
        self._hardening_executors: Dict[str, Callable[[], bool]] = {}

        # Statistics
        self._stats = {
            "techniques_observed": 0,
            "chains_tracked": 0,
            "predictions_made": 0,
            "hardening_applied": 0,
        }

        # Lock for thread safety
        self._lock = threading.Lock()

        logger.info("Attack Chain Predictor initialized")

    def observe(
        self,
        device_ip: str,
        technique_id: str,
        device_mac: Optional[str] = None,
    ) -> Optional[ChainPrediction]:
        """
        Observe a MITRE technique on a device.

        Args:
            device_ip: Device IP address
            technique_id: MITRE ATT&CK technique ID
            device_mac: Optional device MAC

        Returns:
            ChainPrediction if prediction threshold met
        """
        with self._lock:
            self._stats["techniques_observed"] += 1

            # Get or create chain for this device
            if device_ip not in self._chains:
                self._chains[device_ip] = AttackChain(
                    device_ip=device_ip,
                    device_mac=device_mac,
                )
                self._stats["chains_tracked"] += 1

            chain = self._chains[device_ip]

            # Check if chain is stale
            if self._is_chain_stale(chain):
                chain.techniques.clear()

            # Add technique to chain
            chain.add_technique(technique_id)

            logger.info(
                f"Observed {technique_id} on {device_ip}. "
                f"Chain: {chain.get_sequence()}"
            )

            # Check for pattern match and predict
            prediction = self._check_patterns(chain)
            if prediction:
                self._stats["predictions_made"] += 1

                # Notify callbacks
                for callback in self._callbacks:
                    try:
                        callback(prediction)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

                # Auto-harden if enabled
                if self.auto_harden:
                    self._execute_hardening(prediction, chain)

                return prediction

            return None

    def predict(self, device_ip: str) -> Optional[ChainPrediction]:
        """
        Get prediction for next likely technique on a device.

        Args:
            device_ip: Device IP address

        Returns:
            ChainPrediction or None if no chain exists
        """
        with self._lock:
            chain = self._chains.get(device_ip)
            if not chain or self._is_chain_stale(chain):
                return None

            return self._check_patterns(chain)

    def _check_patterns(self, chain: AttackChain) -> Optional[ChainPrediction]:
        """Check chain against known patterns and Markov model."""
        sequence = chain.get_sequence()
        if not sequence:
            return None

        # First check rule-based patterns
        for trigger_seq, next_tech, actions in CHAIN_PATTERNS:
            if self._matches_pattern(sequence, trigger_seq):
                # Already predicted and hardened?
                if next_tech in chain.hardening_applied:
                    continue

                return ChainPrediction(
                    device_ip=chain.device_ip,
                    predicted_technique=next_tech,
                    confidence=0.85,  # Rule-based = high confidence
                    probability=0.75,
                    reason=f"Pattern match: {trigger_seq} → {next_tech}",
                    hardening_actions=actions,
                    chain_so_far=sequence,
                    mitre_name=MITRE_NAMES.get(next_tech, next_tech),
                )

        # Fall back to Markov prediction
        last_technique = sequence[-1]
        transitions = self.TRANSITION_PROBS.get(last_technique, {})

        if transitions:
            # Get highest probability transition
            sorted_trans = sorted(
                transitions.items(),
                key=lambda x: x[1],
                reverse=True
            )

            if sorted_trans:
                next_tech, prob = sorted_trans[0]

                # Skip if already predicted
                if next_tech in chain.hardening_applied:
                    if len(sorted_trans) > 1:
                        next_tech, prob = sorted_trans[1]
                    else:
                        return None

                # Look up hardening actions
                actions = self._get_hardening_for_technique(next_tech)

                return ChainPrediction(
                    device_ip=chain.device_ip,
                    predicted_technique=next_tech,
                    confidence=0.6 + (prob * 0.3),  # Scale confidence
                    probability=prob,
                    reason=f"Markov prediction from {last_technique}",
                    hardening_actions=actions,
                    chain_so_far=sequence,
                    mitre_name=MITRE_NAMES.get(next_tech, next_tech),
                )

        return None

    def _matches_pattern(self, sequence: List[str], pattern: List[str]) -> bool:
        """Check if sequence ends with pattern."""
        if len(sequence) < len(pattern):
            return False

        # Check if pattern is suffix of sequence
        for i, tech in enumerate(pattern):
            seq_idx = len(sequence) - len(pattern) + i
            if sequence[seq_idx] != tech:
                return False

        return True

    def _get_hardening_for_technique(self, technique_id: str) -> List[str]:
        """Get hardening actions for a specific technique."""
        # Default hardening per technique category
        hardening_map = {
            "T1003": ["lock_lsass", "enable_credential_guard", "alert_critical"],
            "T1486": ["quarantine_device", "disable_smb_writes", "alert_critical"],
            "T1048": ["throttle_egress", "block_dns_tunnel", "capture_pcap"],
            "T1567": ["block_cloud_upload", "throttle_bandwidth", "alert_dlp"],
            "T1070": ["protect_logs", "snapshot_event_logs", "alert_critical"],
            "T1078": ["force_mfa", "lock_account_temp", "alert_it"],
            "T1570": ["isolate_segment", "block_smb_lateral", "monitor_file_shares"],
            "T1573": ["block_known_c2", "enable_ssl_inspection", "dns_sinkhole"],
        }

        return hardening_map.get(technique_id, ["alert_it", "monitor_device"])

    def _execute_hardening(
        self,
        prediction: ChainPrediction,
        chain: AttackChain,
    ) -> None:
        """Execute hardening actions for a prediction."""
        for action in prediction.hardening_actions:
            executor = self._hardening_executors.get(action)
            if executor:
                try:
                    success = executor()
                    if success:
                        logger.info(f"Hardening {action} applied for {chain.device_ip}")
                        self._stats["hardening_applied"] += 1
                except Exception as e:
                    logger.error(f"Hardening {action} failed: {e}")
            else:
                # Log the hardening action (would execute in production)
                logger.info(
                    f"[HARDENING] {chain.device_ip}: {action} - "
                    f"{HARDENING_DESCRIPTIONS.get(action, action)}"
                )

        # Mark technique as handled
        chain.hardening_applied.append(prediction.predicted_technique)

    def _is_chain_stale(self, chain: AttackChain) -> bool:
        """Check if chain has timed out."""
        age = datetime.now() - chain.last_seen
        return age > timedelta(minutes=self.chain_timeout_minutes)

    # =========================================================================
    # Integration
    # =========================================================================

    def handle_suricata_alert(self, alert: Dict[str, Any]) -> Optional[ChainPrediction]:
        """
        Handle Suricata alert and update chain.

        Args:
            alert: Suricata EVE JSON alert

        Returns:
            ChainPrediction if threshold met
        """
        src_ip = alert.get("src_ip", "")
        if not src_ip:
            return None

        # Get MITRE ID from alert
        try:
            from .mitre_mapping import get_mitre_mapper
            mapper = get_mitre_mapper()
            sid = alert.get("alert", {}).get("signature_id", 0)
            mitre_info = mapper.get_by_sid(sid)
            if mitre_info:
                return self.observe(src_ip, mitre_info["mitre_id"])
        except ImportError:
            pass

        return None

    def register_hardening_executor(
        self,
        action_name: str,
        executor: Callable[[], bool],
    ) -> None:
        """Register a hardening action executor."""
        self._hardening_executors[action_name] = executor

    def add_callback(self, callback: Callable[[ChainPrediction], None]) -> None:
        """Add callback for predictions."""
        self._callbacks.append(callback)

    def get_chain(self, device_ip: str) -> Optional[AttackChain]:
        """Get chain for a device."""
        return self._chains.get(device_ip)

    def get_all_chains(self) -> Dict[str, AttackChain]:
        """Get all active chains."""
        return dict(self._chains)

    def clear_chain(self, device_ip: str) -> None:
        """Clear chain for a device."""
        with self._lock:
            if device_ip in self._chains:
                del self._chains[device_ip]

    def get_stats(self) -> Dict[str, Any]:
        """Get predictor statistics."""
        return {
            **self._stats,
            "active_chains": len(self._chains),
            "pattern_count": len(CHAIN_PATTERNS),
        }


# Singleton instance
_predictor: Optional[AttackChainPredictor] = None


def get_chain_predictor() -> AttackChainPredictor:
    """Get or create singleton chain predictor."""
    global _predictor

    if _predictor is None:
        _predictor = AttackChainPredictor()

    return _predictor


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    predictor = AttackChainPredictor()

    print("Attack Chain Predictor Demo")
    print("=" * 60)

    # Simulate an attack chain
    print("\nSimulating attack chain on 10.200.0.50:")

    # Step 1: Reconnaissance
    print("\n[1] Observing T1595 (Active Scanning)...")
    predictor.observe("10.200.0.50", "T1595")

    # Step 2: Exploitation
    print("[2] Observing T1190 (Exploit Public App)...")
    result = predictor.observe("10.200.0.50", "T1190")

    if result:
        print(f"\n*** PREDICTION TRIGGERED ***")
        print(f"  Predicted: {result.predicted_technique} ({result.mitre_name})")
        print(f"  Confidence: {result.confidence:.0%}")
        print(f"  Probability: {result.probability:.0%}")
        print(f"  Reason: {result.reason}")
        print(f"  Chain so far: {result.chain_so_far}")
        print(f"\n  Hardening Actions:")
        for action in result.hardening_actions:
            desc = HARDENING_DESCRIPTIONS.get(action, action)
            print(f"    - {action}: {desc}")

    # Show known patterns
    print("\n" + "=" * 60)
    print("Known Attack Chain Patterns:")
    for trigger, next_tech, actions in CHAIN_PATTERNS[:5]:
        trigger_names = [MITRE_NAMES.get(t, t) for t in trigger]
        next_name = MITRE_NAMES.get(next_tech, next_tech)
        print(f"  {trigger} → {next_tech}")
        print(f"    {trigger_names} → {next_name}")

    # Show stats
    print("\n" + "=" * 60)
    stats = predictor.get_stats()
    print(f"Statistics:")
    for k, v in stats.items():
        print(f"  {k}: {v}")
