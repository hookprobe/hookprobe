"""
AIOCHI MITRE ATT&CK Mapping Table
Maps Suricata SIDs to MITRE techniques, playbooks, and human-friendly narratives.

Philosophy: Small businesses need to understand threats without a security degree.
A flower shop owner shouldn't need to know what T1486 means.

Usage:
    from mitre_mapping import MitreMapper
    mapper = MitreMapper()

    # Get technique info
    info = mapper.get_technique("T1486")
    print(info["owner_friendly"])  # "Someone is trying to lock your files for ransom"

    # Get from Suricata SID
    info = mapper.get_by_sid(9000011)
    print(info["playbook_id"])  # "ransomware_airgap"
"""

import json
import logging
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class MitreTechnique:
    """A MITRE ATT&CK technique with human-friendly context."""
    mitre_id: str
    name: str
    tactic: str
    description: str
    owner_friendly: str
    icon: str  # Emoji for UI
    severity: str  # low, medium, high, critical
    playbook_id: Optional[str] = None
    suricata_sids: List[int] = None
    indicators: List[str] = None

    def __post_init__(self):
        if self.suricata_sids is None:
            self.suricata_sids = []
        if self.indicators is None:
            self.indicators = []

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# MITRE ATT&CK TECHNIQUE DATABASE
# Focused on techniques relevant to small businesses
# =============================================================================

MITRE_TECHNIQUES: Dict[str, MitreTechnique] = {

    # =========================================================================
    # INITIAL ACCESS (TA0001)
    # =========================================================================

    "T1566": MitreTechnique(
        mitre_id="T1566",
        name="Phishing",
        tactic="Initial Access",
        description="Adversary attempts to trick users into revealing credentials or running malware",
        owner_friendly="Someone sent a trick email trying to steal login info or install bad software",
        icon="🎣",
        severity="high",
        playbook_id="phish_hook",
        suricata_sids=[9000051, 9000052, 9000053],
        indicators=["suspicious_email", "fake_login_page", "typosquatting"],
    ),

    "T1566.001": MitreTechnique(
        mitre_id="T1566.001",
        name="Spearphishing Attachment",
        tactic="Initial Access",
        description="Malicious attachment sent via email",
        owner_friendly="A dangerous email attachment was detected - it may contain a virus",
        icon="📎",
        severity="high",
        playbook_id="phish_hook",
        suricata_sids=[9000051],
    ),

    "T1204": MitreTechnique(
        mitre_id="T1204",
        name="User Execution",
        tactic="Execution",
        description="User tricked into running malicious code",
        owner_friendly="A device tried to run a suspicious program",
        icon="▶️",
        severity="high",
        playbook_id="phish_hook",
        suricata_sids=[9000053],
    ),

    "T1204.002": MitreTechnique(
        mitre_id="T1204.002",
        name="Malicious File",
        tactic="Execution",
        description="User executes a malicious file",
        owner_friendly="Someone downloaded a dangerous file - I blocked it",
        icon="📁",
        severity="high",
        playbook_id="phish_hook",
        suricata_sids=[9000053],
    ),

    # =========================================================================
    # EXECUTION (TA0002)
    # =========================================================================

    "T1059": MitreTechnique(
        mitre_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversary uses scripts or command-line to execute malicious commands",
        owner_friendly="A device is running suspicious commands that could be malware",
        icon="💻",
        severity="high",
        playbook_id=None,
        suricata_sids=[9000052],
    ),

    "T1059.001": MitreTechnique(
        mitre_id="T1059.001",
        name="PowerShell",
        tactic="Execution",
        description="Adversary uses PowerShell for malicious activities",
        owner_friendly="A device is running hidden PowerShell commands - often used by attackers",
        icon="⚡",
        severity="high",
        playbook_id=None,
        suricata_sids=[9000052],
    ),

    # =========================================================================
    # CREDENTIAL ACCESS (TA0006)
    # =========================================================================

    "T1110": MitreTechnique(
        mitre_id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        description="Adversary attempts to guess passwords",
        owner_friendly="Someone is trying to guess passwords to break into your systems",
        icon="🔐",
        severity="high",
        playbook_id="brute_force_shield",
        suricata_sids=[9000044, 9000045, 1000001],  # 1000001 = SSH Brute Force
    ),

    "T1110.001": MitreTechnique(
        mitre_id="T1110.001",
        name="Password Guessing",
        tactic="Credential Access",
        description="Adversary attempts to access accounts using common passwords",
        owner_friendly="Someone is trying common passwords to break into your computers",
        icon="🔑",
        severity="high",
        playbook_id=None,
        suricata_sids=[9000044, 9000045],
    ),

    "T1110.003": MitreTechnique(
        mitre_id="T1110.003",
        name="Password Spraying",
        tactic="Credential Access",
        description="Adversary tries one password against many accounts",
        owner_friendly="Someone is testing passwords across multiple accounts",
        icon="🌧️",
        severity="high",
        playbook_id=None,
        suricata_sids=[9000043],
    ),

    "T1187": MitreTechnique(
        mitre_id="T1187",
        name="Forced Authentication",
        tactic="Credential Access",
        description="Adversary forces authentication to capture credentials",
        owner_friendly="Someone is trying to trick your computer into revealing login info",
        icon="🎭",
        severity="high",
        playbook_id=None,
        suricata_sids=[9000041],
    ),

    "T1558.003": MitreTechnique(
        mitre_id="T1558.003",
        name="Kerberoasting",
        tactic="Credential Access",
        description="Adversary attempts to crack service account passwords",
        owner_friendly="Someone is trying to crack your network passwords using a technical attack",
        icon="🔓",
        severity="critical",
        playbook_id=None,
        suricata_sids=[9000042],
    ),

    # =========================================================================
    # LATERAL MOVEMENT (TA0008)
    # =========================================================================

    "T1021": MitreTechnique(
        mitre_id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        description="Adversary moves between systems using remote access",
        owner_friendly="A device is trying to access other computers on your network",
        icon="🔀",
        severity="high",
        playbook_id="guest_wall",
        suricata_sids=[9000062, 9000063],
    ),

    "T1021.002": MitreTechnique(
        mitre_id="T1021.002",
        name="SMB/Windows Admin Shares",
        tactic="Lateral Movement",
        description="Adversary accesses SMB shares for lateral movement",
        owner_friendly="A device is accessing file shares on other computers - could be an attacker spreading",
        icon="📂",
        severity="high",
        playbook_id="guest_wall",
        suricata_sids=[9000062],
    ),

    "T1046": MitreTechnique(
        mitre_id="T1046",
        name="Network Service Scanning",
        tactic="Discovery",
        description="Adversary scans for services on the network",
        owner_friendly="Someone is scanning your network looking for vulnerable systems",
        icon="🔍",
        severity="medium",
        playbook_id="guest_wall",
        suricata_sids=[9000061, 9000092, 1000003],  # 1000003 = Internal Port Scan
    ),

    "T1047": MitreTechnique(
        mitre_id="T1047",
        name="Windows Management Instrumentation",
        tactic="Execution",
        description="Adversary uses WMI for remote execution",
        owner_friendly="A device is trying to remotely control other computers",
        icon="🎛️",
        severity="high",
        playbook_id="guest_wall",
        suricata_sids=[9000063],
    ),

    "T1016.001": MitreTechnique(
        mitre_id="T1016.001",
        name="Internet Connection Discovery",
        tactic="Discovery",
        description="Adversary enumerates network connections",
        owner_friendly="A device is scanning to map your entire network",
        icon="🗺️",
        severity="medium",
        playbook_id="guest_wall",
        suricata_sids=[9000091],
    ),

    # =========================================================================
    # EXFILTRATION (TA0010)
    # =========================================================================

    "T1041": MitreTechnique(
        mitre_id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description="Data stolen through command and control channel",
        owner_friendly="A device is sending your data to attackers",
        icon="📤",
        severity="critical",
        playbook_id="data_sieve",
        suricata_sids=[9000004],
    ),

    "T1048": MitreTechnique(
        mitre_id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="Exfiltration",
        description="Data stolen using non-standard protocols",
        owner_friendly="Someone is trying to steal your data through a hidden channel",
        icon="🕵️",
        severity="critical",
        playbook_id="data_sieve",
        suricata_sids=[9000031, 9000033, 9000034],
    ),

    "T1048.001": MitreTechnique(
        mitre_id="T1048.001",
        name="Exfiltration Over HTTP",
        tactic="Exfiltration",
        description="Data stolen via web traffic",
        owner_friendly="Someone is uploading your files to the internet without permission",
        icon="🌐",
        severity="critical",
        playbook_id="data_sieve",
        suricata_sids=[9000033],
    ),

    "T1048.003": MitreTechnique(
        mitre_id="T1048.003",
        name="Exfiltration Over DNS",
        tactic="Exfiltration",
        description="Data stolen hidden in DNS queries",
        owner_friendly="Someone is hiding stolen data in internet lookups",
        icon="📡",
        severity="critical",
        playbook_id="data_sieve",
        suricata_sids=[9000031],
    ),

    "T1567": MitreTechnique(
        mitre_id="T1567",
        name="Exfiltration to Cloud Storage",
        tactic="Exfiltration",
        description="Data uploaded to cloud storage",
        owner_friendly="Someone is uploading your files to cloud storage",
        icon="☁️",
        severity="high",
        playbook_id="data_sieve",
        suricata_sids=[9000035, 9000036],
    ),

    "T1567.002": MitreTechnique(
        mitre_id="T1567.002",
        name="Exfiltration to Cloud Storage Service",
        tactic="Exfiltration",
        description="Data uploaded to services like S3 or Google Cloud",
        owner_friendly="Large files are being uploaded to cloud storage - could be data theft",
        icon="📦",
        severity="high",
        playbook_id="data_sieve",
        suricata_sids=[9000035, 9000036],
    ),

    "T1132.001": MitreTechnique(
        mitre_id="T1132.001",
        name="Standard Encoding",
        tactic="Command and Control",
        description="Data encoded to evade detection",
        owner_friendly="Someone is trying to hide data by scrambling it before sending",
        icon="🔢",
        severity="high",
        playbook_id="data_sieve",
        suricata_sids=[9000034],
    ),

    "T1568.002": MitreTechnique(
        mitre_id="T1568.002",
        name="Domain Generation Algorithms",
        tactic="Command and Control",
        description="Malware generates random domains to contact attackers",
        owner_friendly="A device is using random-looking websites to contact attackers",
        icon="🎲",
        severity="critical",
        playbook_id="data_sieve",
        suricata_sids=[9000032],
    ),

    # =========================================================================
    # COMMAND AND CONTROL (TA0011)
    # =========================================================================

    "T1071": MitreTechnique(
        mitre_id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        description="Adversary uses common protocols for command and control",
        owner_friendly="A device is secretly communicating with attackers",
        icon="📞",
        severity="critical",
        playbook_id="ransomware_airgap",
        suricata_sids=[9000021, 9000022, 9000023, 9000024],
    ),

    "T1071.001": MitreTechnique(
        mitre_id="T1071.001",
        name="Web Protocols",
        tactic="Command and Control",
        description="Adversary uses HTTP/HTTPS for C2",
        owner_friendly="A device is receiving commands from hackers via web traffic",
        icon="🌍",
        severity="critical",
        playbook_id="ransomware_airgap",
        suricata_sids=[9000021, 9000022, 9000023, 9000024, 9000026, 1000005, 1000007],  # 1000005=IoT Beaconing, 1000007=C2 Beaconing
    ),

    "T1071.004": MitreTechnique(
        mitre_id="T1071.004",
        name="DNS",
        tactic="Command and Control",
        description="Adversary uses DNS for C2",
        owner_friendly="A device is being controlled through hidden DNS messages",
        icon="🔤",
        severity="critical",
        playbook_id="ransomware_airgap",
        suricata_sids=[9000025, 1000002, 1000004],  # 1000002=DNS Tunneling, 1000004=DNS Non-Std Port
    ),

    # =========================================================================
    # IMPACT (TA0040)
    # =========================================================================

    "T1486": MitreTechnique(
        mitre_id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        description="Adversary encrypts data to demand ransom",
        owner_friendly="RANSOMWARE DETECTED - Someone is trying to lock your files and demand payment",
        icon="🔒",
        severity="critical",
        playbook_id="ransomware_airgap",
        suricata_sids=[9000011, 9000012, 9000013, 9000014, 9000015, 9000016, 9000017],
        indicators=["locked_files", "ransom_note", "bitcoin_demand"],
    ),

    "T1496": MitreTechnique(
        mitre_id="T1496",
        name="Resource Hijacking",
        tactic="Impact",
        description="Adversary uses your resources for cryptocurrency mining",
        owner_friendly="Someone is using your computers to mine cryptocurrency - slowing everything down",
        icon="⛏️",
        severity="medium",
        playbook_id=None,
        suricata_sids=[9000081, 9000082, 9000083, 1000006],  # 1000006 = Cryptomining
    ),

    # =========================================================================
    # POS/PAYMENT (Custom category for small business)
    # =========================================================================

    "T1119": MitreTechnique(
        mitre_id="T1119",
        name="Automated Collection",
        tactic="Collection",
        description="Adversary automatically collects data",
        owner_friendly="Your payment terminal may be compromised - card data is being collected",
        icon="💳",
        severity="critical",
        playbook_id="cashier_guard",
        suricata_sids=[9000001, 9000002],
    ),

    "T1005": MitreTechnique(
        mitre_id="T1005",
        name="Data from Local System",
        tactic="Collection",
        description="Adversary collects data from local storage",
        owner_friendly="Someone is stealing data directly from your payment terminal",
        icon="💾",
        severity="critical",
        playbook_id="cashier_guard",
        suricata_sids=[9000002],
    ),

    "T1557.001": MitreTechnique(
        mitre_id="T1557.001",
        name="Payment Card Data Theft",
        tactic="Collection",
        description="Adversary steals payment card data",
        owner_friendly="ALERT: Payment card data theft detected - customer cards may be at risk",
        icon="💳",
        severity="critical",
        playbook_id="cashier_guard",
        suricata_sids=[9000001, 9000003],
    ),

    # =========================================================================
    # DEFENSE EVASION (TA0005)
    # =========================================================================

    "T1070": MitreTechnique(
        mitre_id="T1070",
        name="Indicator Removal",
        tactic="Defense Evasion",
        description="Adversary deletes evidence of their activities",
        owner_friendly="Someone is trying to cover their tracks by deleting logs",
        icon="🧹",
        severity="high",
        playbook_id=None,
        suricata_sids=[9000071],
    ),

    "T1070.001": MitreTechnique(
        mitre_id="T1070.001",
        name="Clear Windows Event Logs",
        tactic="Defense Evasion",
        description="Adversary clears Windows logs",
        owner_friendly="Someone is deleting security logs - a sign of an active attack",
        icon="📋",
        severity="high",
        playbook_id=None,
        suricata_sids=[9000071],
    ),

    "T1562": MitreTechnique(
        mitre_id="T1562",
        name="Impair Defenses",
        tactic="Defense Evasion",
        description="Adversary disables security tools",
        owner_friendly="Someone is trying to turn off your security protection",
        icon="🛡️",
        severity="critical",
        playbook_id=None,
        suricata_sids=[9000072],
    ),

    "T1562.001": MitreTechnique(
        mitre_id="T1562.001",
        name="Disable or Modify Tools",
        tactic="Defense Evasion",
        description="Adversary stops antivirus or security tools",
        owner_friendly="Someone is trying to stop your antivirus - this is dangerous",
        icon="🚫",
        severity="critical",
        playbook_id=None,
        suricata_sids=[9000072],
    ),
}


# =============================================================================
# SID TO MITRE MAPPING (Reverse lookup for Suricata alerts)
# =============================================================================

SID_TO_MITRE: Dict[int, str] = {}

# Build reverse mapping
for mitre_id, technique in MITRE_TECHNIQUES.items():
    for sid in technique.suricata_sids:
        SID_TO_MITRE[sid] = mitre_id


# =============================================================================
# PLAYBOOK TO MITRE MAPPING
# =============================================================================

PLAYBOOK_TO_MITRE: Dict[str, List[str]] = {
    "phish_hook": ["T1566", "T1566.001", "T1204", "T1204.002"],
    "cashier_guard": ["T1119", "T1005", "T1557.001", "T1041"],
    "ransomware_airgap": ["T1486", "T1071", "T1071.001", "T1021.002"],
    "guest_wall": ["T1021", "T1021.002", "T1046", "T1016.001"],
    "data_sieve": ["T1048", "T1048.001", "T1048.003", "T1567", "T1567.002"],
}


# =============================================================================
# MITRE MAPPER CLASS
# =============================================================================

class MitreMapper:
    """
    Maps between Suricata SIDs, MITRE ATT&CK techniques, and playbooks.

    Provides human-friendly descriptions for non-technical users.
    """

    def __init__(self):
        self._techniques = MITRE_TECHNIQUES
        self._sid_to_mitre = SID_TO_MITRE
        self._playbook_to_mitre = PLAYBOOK_TO_MITRE

        logger.debug(f"MitreMapper initialized with {len(self._techniques)} techniques")

    def get_technique(self, mitre_id: str) -> Optional[Dict[str, Any]]:
        """
        Get technique information by MITRE ID.

        Args:
            mitre_id: MITRE ATT&CK ID (e.g., "T1486")

        Returns:
            Technique dictionary or None
        """
        technique = self._techniques.get(mitre_id)
        if technique:
            return technique.to_dict()
        return None

    def get_by_sid(self, sid: int) -> Optional[Dict[str, Any]]:
        """
        Get technique information by Suricata SID.

        Args:
            sid: Suricata rule SID

        Returns:
            Technique dictionary or None
        """
        mitre_id = self._sid_to_mitre.get(sid)
        if mitre_id:
            return self.get_technique(mitre_id)
        return None

    def get_by_playbook(self, playbook_id: str) -> List[Dict[str, Any]]:
        """
        Get all techniques mapped to a playbook.

        Args:
            playbook_id: Playbook ID (e.g., "ransomware_airgap")

        Returns:
            List of technique dictionaries
        """
        mitre_ids = self._playbook_to_mitre.get(playbook_id, [])
        return [
            self.get_technique(mid)
            for mid in mitre_ids
            if self.get_technique(mid)
        ]

    def get_owner_friendly(self, mitre_id: str) -> str:
        """
        Get human-friendly explanation for a flower shop owner.

        Args:
            mitre_id: MITRE ATT&CK ID

        Returns:
            Simple explanation string
        """
        technique = self._techniques.get(mitre_id)
        if technique:
            return technique.owner_friendly
        return "A security event was detected on your network"

    def get_severity(self, mitre_id: str) -> str:
        """
        Get severity level for a technique.

        Args:
            mitre_id: MITRE ATT&CK ID

        Returns:
            Severity level (low, medium, high, critical)
        """
        technique = self._techniques.get(mitre_id)
        if technique:
            return technique.severity
        return "medium"

    def get_playbook_for_technique(self, mitre_id: str) -> Optional[str]:
        """
        Get recommended playbook for a technique.

        Args:
            mitre_id: MITRE ATT&CK ID

        Returns:
            Playbook ID or None
        """
        technique = self._techniques.get(mitre_id)
        if technique:
            return technique.playbook_id
        return None

    def get_icon(self, mitre_id: str) -> str:
        """
        Get emoji icon for technique (for UI display).

        Args:
            mitre_id: MITRE ATT&CK ID

        Returns:
            Emoji string
        """
        technique = self._techniques.get(mitre_id)
        if technique:
            return technique.icon
        return "⚠️"

    def search_techniques(
        self,
        tactic: Optional[str] = None,
        severity: Optional[str] = None,
        has_playbook: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Search techniques by criteria.

        Args:
            tactic: Filter by tactic (e.g., "Impact")
            severity: Filter by severity level
            has_playbook: Only return techniques with playbooks

        Returns:
            List of matching technique dictionaries
        """
        results = []

        for technique in self._techniques.values():
            if tactic and technique.tactic.lower() != tactic.lower():
                continue
            if severity and technique.severity != severity:
                continue
            if has_playbook and not technique.playbook_id:
                continue
            results.append(technique.to_dict())

        return results

    def get_all_tactics(self) -> List[str]:
        """Get list of all MITRE tactics covered."""
        tactics = set()
        for technique in self._techniques.values():
            tactics.add(technique.tactic)
        return sorted(list(tactics))

    def get_stats(self) -> Dict[str, Any]:
        """Get mapping statistics."""
        techniques_with_playbook = sum(
            1 for t in self._techniques.values() if t.playbook_id
        )

        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for technique in self._techniques.values():
            severity_counts[technique.severity] += 1

        return {
            "total_techniques": len(self._techniques),
            "techniques_with_playbook": techniques_with_playbook,
            "total_sids_mapped": len(self._sid_to_mitre),
            "tactics_covered": len(self.get_all_tactics()),
            "severity_distribution": severity_counts,
        }

    def to_json(self) -> str:
        """Export all mappings as JSON."""
        return json.dumps({
            "techniques": {
                k: v.to_dict() for k, v in self._techniques.items()
            },
            "sid_to_mitre": self._sid_to_mitre,
            "playbook_to_mitre": self._playbook_to_mitre,
            "stats": self.get_stats(),
        }, indent=2)


# Singleton instance
_mapper: Optional[MitreMapper] = None


def get_mitre_mapper() -> MitreMapper:
    """Get or create the singleton MITRE mapper."""
    global _mapper

    if _mapper is None:
        _mapper = MitreMapper()

    return _mapper


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    mapper = MitreMapper()

    print("MITRE ATT&CK Mapper Demo")
    print("=" * 60)

    # Show stats
    stats = mapper.get_stats()
    print(f"\nStatistics:")
    print(f"  Total techniques: {stats['total_techniques']}")
    print(f"  With playbooks: {stats['techniques_with_playbook']}")
    print(f"  Suricata SIDs mapped: {stats['total_sids_mapped']}")
    print(f"  Tactics covered: {stats['tactics_covered']}")
    print(f"  Severity distribution: {stats['severity_distribution']}")

    # Test SID lookup
    print(f"\n\nLooking up SID 9000017 (Ransomware SMB):")
    info = mapper.get_by_sid(9000017)
    if info:
        print(f"  MITRE ID: {info['mitre_id']}")
        print(f"  Name: {info['name']}")
        print(f"  Icon: {info['icon']}")
        print(f"  Owner-friendly: {info['owner_friendly']}")
        print(f"  Playbook: {info['playbook_id']}")

    # Test technique lookup
    print(f"\n\nLooking up T1566 (Phishing):")
    info = mapper.get_technique("T1566")
    if info:
        print(f"  Tactic: {info['tactic']}")
        print(f"  Severity: {info['severity']}")
        print(f"  Description: {info['description']}")
        print(f"  Owner-friendly: {info['owner_friendly']}")

    # Test playbook lookup
    print(f"\n\nTechniques for 'ransomware_airgap' playbook:")
    techniques = mapper.get_by_playbook("ransomware_airgap")
    for t in techniques:
        print(f"  {t['icon']} {t['mitre_id']}: {t['name']}")

    # Show all tactics
    print(f"\n\nTactics covered:")
    for tactic in mapper.get_all_tactics():
        count = len(mapper.search_techniques(tactic=tactic))
        print(f"  - {tactic}: {count} techniques")
