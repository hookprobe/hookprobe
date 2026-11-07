"""
Attack Library — Parameterized Attack Templates for Shadow Pentester.

Provides a catalogue of attack scenarios that the shadow pentester can
execute within the digital twin. Each template is parameterized so the
LLM can adapt it to discovered network topology.

Attack categories map to MITRE ATT&CK framework:
  - Reconnaissance (TA0043)
  - Initial Access (TA0001)
  - Lateral Movement (TA0008)
  - Exfiltration (TA0010)
  - Command and Control (TA0011)

Security: These templates ONLY describe attack logic for twin execution.
They cannot interact with the production network — enforcement is in
ShadowPentester and PrincipleGuard.

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------

class AttackCategory(str, Enum):
    """MITRE ATT&CK tactic categories."""
    RECONNAISSANCE = "reconnaissance"       # TA0043
    INITIAL_ACCESS = "initial_access"       # TA0001
    EXECUTION = "execution"                 # TA0002
    PERSISTENCE = "persistence"             # TA0003
    LATERAL_MOVEMENT = "lateral_movement"   # TA0008
    COLLECTION = "collection"               # TA0009
    EXFILTRATION = "exfiltration"           # TA0010
    COMMAND_AND_CONTROL = "c2"              # TA0011
    IMPACT = "impact"                       # TA0040


class AttackDifficulty(str, Enum):
    """How complex the attack is to execute."""
    TRIVIAL = "trivial"       # Script kiddie level
    MODERATE = "moderate"     # Requires some knowledge
    ADVANCED = "advanced"     # APT-level sophistication
    EXPERT = "expert"         # Nation-state level


class ExpectedDetection(str, Enum):
    """What QSecBit layer should detect this."""
    L2_DATA_LINK = "L2"
    L3_NETWORK = "L3"
    L4_TRANSPORT = "L4"
    L5_SESSION = "L5"
    L7_APPLICATION = "L7"
    BEHAVIORAL = "behavioral"
    NONE = "none"             # Should NOT be detected (evasion test)


# ------------------------------------------------------------------
# Data Types
# ------------------------------------------------------------------

@dataclass
class AttackParameter:
    """A single configurable parameter for an attack template."""
    name: str
    description: str
    param_type: str = "str"   # str, int, float, ip, port, list
    default: Any = None
    required: bool = False


@dataclass
class AttackTemplate:
    """A parameterized attack scenario for twin execution."""
    name: str
    description: str
    category: AttackCategory
    difficulty: AttackDifficulty
    mitre_id: str                  # e.g., "T1046" for Network Service Scan
    mitre_technique: str           # Human-readable technique name
    expected_detection: ExpectedDetection
    expected_severity: str = "MEDIUM"  # Expected QSecBit severity
    parameters: List[AttackParameter] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)

    @property
    def template_id(self) -> str:
        return f"atk-{self.category.value}-{self.name}"


@dataclass
class AttackExecution:
    """Record of an attack template execution in the twin."""
    template_id: str
    template_name: str
    category: str
    parameters: Dict[str, Any]
    target_ip: str = ""
    success: bool = False
    detected: bool = False
    detection_layer: str = ""
    detection_latency_ms: float = 0.0
    severity_assigned: str = ""
    notes: str = ""

    @property
    def evaded_detection(self) -> bool:
        """True if attack succeeded but was NOT detected."""
        return self.success and not self.detected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "category": self.category,
            "parameters": self.parameters,
            "target_ip": self.target_ip,
            "success": self.success,
            "detected": self.detected,
            "detection_layer": self.detection_layer,
            "detection_latency_ms": self.detection_latency_ms,
            "severity_assigned": self.severity_assigned,
            "evaded_detection": self.evaded_detection,
            "notes": self.notes,
        }


# ------------------------------------------------------------------
# Attack Library
# ------------------------------------------------------------------

class AttackLibrary:
    """Registry of parameterized attack templates.

    Provides attack scenarios organized by MITRE ATT&CK categories.
    The shadow pentester selects and parameterizes templates based
    on the target network topology from streaming RAG reconnaissance.
    """

    def __init__(self):
        self._templates: Dict[str, AttackTemplate] = {}
        self._register_builtins()

    def register(self, template: AttackTemplate) -> None:
        """Register an attack template."""
        self._templates[template.template_id] = template

    def get(self, template_id: str) -> Optional[AttackTemplate]:
        """Get a template by ID."""
        return self._templates.get(template_id)

    def get_by_name(self, name: str) -> Optional[AttackTemplate]:
        """Get a template by name."""
        for t in self._templates.values():
            if t.name == name:
                return t
        return None

    def get_by_category(self, category: AttackCategory) -> List[AttackTemplate]:
        """Get all templates in a category."""
        return [t for t in self._templates.values() if t.category == category]

    def get_by_difficulty(self, max_difficulty: AttackDifficulty) -> List[AttackTemplate]:
        """Get templates up to a given difficulty level."""
        levels = list(AttackDifficulty)
        max_idx = levels.index(max_difficulty)
        return [
            t for t in self._templates.values()
            if levels.index(t.difficulty) <= max_idx
        ]

    def list_templates(self) -> List[Dict[str, str]]:
        """List all templates with basic info."""
        return [
            {
                "template_id": t.template_id,
                "name": t.name,
                "category": t.category.value,
                "difficulty": t.difficulty.value,
                "mitre_id": t.mitre_id,
                "expected_detection": t.expected_detection.value,
            }
            for t in sorted(self._templates.values(), key=lambda x: x.category.value)
        ]

    def __len__(self) -> int:
        return len(self._templates)

    # ------------------------------------------------------------------
    # Built-in Attack Templates
    # ------------------------------------------------------------------

    def _register_builtins(self) -> None:
        """Register the built-in attack template catalogue."""

        # --- Reconnaissance ---

        self.register(AttackTemplate(
            name="port_scan",
            description="TCP SYN scan of target host to discover open services",
            category=AttackCategory.RECONNAISSANCE,
            difficulty=AttackDifficulty.TRIVIAL,
            mitre_id="T1046",
            mitre_technique="Network Service Discovery",
            expected_detection=ExpectedDetection.L4_TRANSPORT,
            expected_severity="MEDIUM",
            parameters=[
                AttackParameter("target_ip", "Target IP address", "ip", required=True),
                AttackParameter("port_range", "Port range to scan", "str", "1-1024"),
                AttackParameter("scan_rate", "Packets per second", "int", 100),
            ],
            steps=[
                "Send SYN packets to target port range",
                "Collect SYN-ACK responses (open ports)",
                "Collect RST responses (closed ports)",
                "Timeout = filtered ports",
            ],
            indicators=["High SYN rate from single IP", "Sequential port access"],
        ))

        self.register(AttackTemplate(
            name="arp_scan",
            description="ARP sweep to discover live hosts on subnet",
            category=AttackCategory.RECONNAISSANCE,
            difficulty=AttackDifficulty.TRIVIAL,
            mitre_id="T1018",
            mitre_technique="Remote System Discovery",
            expected_detection=ExpectedDetection.L2_DATA_LINK,
            expected_severity="LOW",
            parameters=[
                AttackParameter("subnet", "Target subnet CIDR", "str", required=True),
            ],
            steps=[
                "Send ARP who-has for each IP in subnet",
                "Record MAC-to-IP mappings from responses",
            ],
            indicators=["ARP broadcast storm", "Sequential ARP queries"],
        ))

        self.register(AttackTemplate(
            name="dns_enumeration",
            description="DNS zone transfer and subdomain enumeration",
            category=AttackCategory.RECONNAISSANCE,
            difficulty=AttackDifficulty.MODERATE,
            mitre_id="T1596.001",
            mitre_technique="Search Open Technical Databases: DNS/Passive DNS",
            expected_detection=ExpectedDetection.L7_APPLICATION,
            expected_severity="LOW",
            parameters=[
                AttackParameter("domain", "Target domain", "str", required=True),
                AttackParameter("wordlist_size", "Subdomain brute-force size", "int", 100),
            ],
            steps=[
                "Attempt AXFR zone transfer",
                "Enumerate subdomains via brute-force DNS queries",
                "Check for wildcard DNS responses",
            ],
            indicators=["AXFR attempt", "High DNS query rate", "Sequential subdomains"],
        ))

        # --- Initial Access / Spoofing ---

        self.register(AttackTemplate(
            name="arp_spoof",
            description="ARP cache poisoning to MITM traffic between two hosts",
            category=AttackCategory.INITIAL_ACCESS,
            difficulty=AttackDifficulty.MODERATE,
            mitre_id="T1557.002",
            mitre_technique="Adversary-in-the-Middle: ARP Cache Poisoning",
            expected_detection=ExpectedDetection.L2_DATA_LINK,
            expected_severity="HIGH",
            parameters=[
                AttackParameter("victim_ip", "Victim IP", "ip", required=True),
                AttackParameter("gateway_ip", "Gateway IP", "ip", required=True),
                AttackParameter("attacker_mac", "Attacker MAC", "str", "aa:bb:cc:dd:ee:ff"),
            ],
            steps=[
                "Send gratuitous ARP to victim: gateway_ip is-at attacker_mac",
                "Send gratuitous ARP to gateway: victim_ip is-at attacker_mac",
                "Forward intercepted traffic (selective MITM)",
            ],
            indicators=["ARP reply without request", "MAC address change for known IP"],
        ))

        self.register(AttackTemplate(
            name="rogue_dhcp",
            description="Set up rogue DHCP server to redirect default gateway",
            category=AttackCategory.INITIAL_ACCESS,
            difficulty=AttackDifficulty.MODERATE,
            mitre_id="T1557",
            mitre_technique="Adversary-in-the-Middle",
            expected_detection=ExpectedDetection.L2_DATA_LINK,
            expected_severity="CRITICAL",
            parameters=[
                AttackParameter("attacker_ip", "Rogue DHCP server IP", "ip", required=True),
                AttackParameter("offered_gateway", "Gateway to offer", "ip", required=True),
                AttackParameter("offered_dns", "DNS server to offer", "ip", ""),
            ],
            steps=[
                "Listen for DHCP DISCOVER broadcasts",
                "Race legitimate DHCP server with OFFER containing attacker gateway",
                "Serve DHCP ACK if client accepts",
            ],
            indicators=["Multiple DHCP servers on subnet", "Unexpected DHCP offer source"],
        ))

        # --- Flood / DoS ---

        self.register(AttackTemplate(
            name="syn_flood",
            description="TCP SYN flood to exhaust target connection table",
            category=AttackCategory.IMPACT,
            difficulty=AttackDifficulty.TRIVIAL,
            mitre_id="T1499.001",
            mitre_technique="Endpoint Denial of Service: OS Exhaustion Flood",
            expected_detection=ExpectedDetection.L4_TRANSPORT,
            expected_severity="HIGH",
            parameters=[
                AttackParameter("target_ip", "Target IP", "ip", required=True),
                AttackParameter("target_port", "Target port", "int", 80),
                AttackParameter("rate_pps", "Packets per second", "int", 10000),
                AttackParameter("duration_s", "Duration in seconds", "int", 10),
            ],
            steps=[
                "Send SYN packets with spoofed source IPs",
                "Target allocates half-open connections",
                "Connection table exhaustion prevents legitimate connections",
            ],
            indicators=["SYN rate spike", "Many half-open connections", "Source IP entropy"],
        ))

        self.register(AttackTemplate(
            name="udp_flood",
            description="UDP volumetric flood targeting application ports",
            category=AttackCategory.IMPACT,
            difficulty=AttackDifficulty.TRIVIAL,
            mitre_id="T1499.001",
            mitre_technique="Endpoint Denial of Service: OS Exhaustion Flood",
            expected_detection=ExpectedDetection.L4_TRANSPORT,
            expected_severity="HIGH",
            parameters=[
                AttackParameter("target_ip", "Target IP", "ip", required=True),
                AttackParameter("target_port", "Target port", "int", 53),
                AttackParameter("rate_pps", "Packets per second", "int", 50000),
            ],
            steps=[
                "Send high-rate UDP packets to target port",
                "Target wastes resources generating ICMP unreachable",
                "Bandwidth and CPU exhaustion",
            ],
            indicators=["UDP rate spike", "ICMP unreachable flood"],
        ))

        # --- C2 / Exfiltration ---

        self.register(AttackTemplate(
            name="dns_tunnel",
            description="Exfiltrate data via DNS TXT record queries to attacker domain",
            category=AttackCategory.EXFILTRATION,
            difficulty=AttackDifficulty.ADVANCED,
            mitre_id="T1048.003",
            mitre_technique="Exfiltration Over Alternative Protocol: DNS",
            expected_detection=ExpectedDetection.L7_APPLICATION,
            expected_severity="CRITICAL",
            parameters=[
                AttackParameter("c2_domain", "Attacker C2 domain", "str", required=True),
                AttackParameter("data_size_kb", "Data to exfiltrate (KB)", "int", 10),
                AttackParameter("encoding", "Encoding method", "str", "base32"),
            ],
            steps=[
                "Encode data payload as base32/hex subdomains",
                "Send DNS queries: <encoded>.c2_domain",
                "Receive responses via TXT records",
                "Reassemble on C2 server",
            ],
            indicators=[
                "High-entropy subdomains",
                "Long DNS query names (>60 chars)",
                "High DNS query rate to single domain",
                "TXT record queries",
            ],
        ))

        self.register(AttackTemplate(
            name="dga_c2",
            description="Domain Generation Algorithm for resilient C2 communication",
            category=AttackCategory.COMMAND_AND_CONTROL,
            difficulty=AttackDifficulty.ADVANCED,
            mitre_id="T1568.002",
            mitre_technique="Dynamic Resolution: Domain Generation Algorithms",
            expected_detection=ExpectedDetection.L7_APPLICATION,
            expected_severity="CRITICAL",
            parameters=[
                AttackParameter("seed", "DGA seed value", "str", "shadow-test"),
                AttackParameter("domain_count", "Domains to generate", "int", 50),
                AttackParameter("tld", "Top-level domain", "str", ".com"),
            ],
            steps=[
                "Generate pseudo-random domain names from seed + date",
                "Attempt DNS resolution for each generated domain",
                "Attacker registers one domain to receive C2 traffic",
            ],
            indicators=[
                "NXDomain burst from single IP",
                "High-entropy domain names",
                "Sequential DNS failures",
            ],
        ))

        # --- Lateral Movement ---

        self.register(AttackTemplate(
            name="vlan_hop",
            description="802.1Q double-tagging to hop between VLANs",
            category=AttackCategory.LATERAL_MOVEMENT,
            difficulty=AttackDifficulty.ADVANCED,
            mitre_id="T1599",
            mitre_technique="Network Boundary Bridging",
            expected_detection=ExpectedDetection.L2_DATA_LINK,
            expected_severity="CRITICAL",
            parameters=[
                AttackParameter("target_vlan", "VLAN to hop to", "int", required=True),
                AttackParameter("native_vlan", "Native VLAN of trunk port", "int", 1),
            ],
            steps=[
                "Craft frame with double 802.1Q tags",
                "Outer tag = native VLAN (stripped by switch)",
                "Inner tag = target VLAN (forwarded)",
                "Packet reaches target VLAN without authorization",
            ],
            indicators=["Double-tagged 802.1Q frames", "Unexpected VLAN traffic"],
        ))

        self.register(AttackTemplate(
            name="mdns_spoof",
            description="mDNS response spoofing to redirect local service discovery",
            category=AttackCategory.LATERAL_MOVEMENT,
            difficulty=AttackDifficulty.MODERATE,
            mitre_id="T1557",
            mitre_technique="Adversary-in-the-Middle",
            expected_detection=ExpectedDetection.L7_APPLICATION,
            expected_severity="MEDIUM",
            parameters=[
                AttackParameter("service_type", "mDNS service to spoof", "str", "_http._tcp"),
                AttackParameter("spoofed_name", "Fake service name", "str", "Fake-Printer"),
                AttackParameter("attacker_ip", "Attacker IP", "ip", required=True),
            ],
            steps=[
                "Listen for mDNS queries on multicast 224.0.0.251",
                "Respond with spoofed service record pointing to attacker",
                "Intercept connections to spoofed service",
            ],
            indicators=["Unexpected mDNS responses", "Service name change for known host"],
        ))

        # --- Evasion (should NOT be detected) ---

        self.register(AttackTemplate(
            name="slow_scan",
            description="Ultra-slow port scan to evade rate-based detection",
            category=AttackCategory.RECONNAISSANCE,
            difficulty=AttackDifficulty.ADVANCED,
            mitre_id="T1046",
            mitre_technique="Network Service Discovery",
            expected_detection=ExpectedDetection.NONE,
            expected_severity="LOW",
            parameters=[
                AttackParameter("target_ip", "Target IP", "ip", required=True),
                AttackParameter("ports", "Ports to scan (comma-separated)", "str", "22,80,443"),
                AttackParameter("interval_s", "Seconds between probes", "int", 300),
            ],
            steps=[
                "Send one SYN probe every 5 minutes",
                "Randomize source port per probe",
                "Use different TTL values",
                "Below rate detection threshold",
            ],
            indicators=["Very difficult to detect at individual packet level"],
        ))

        self.register(AttackTemplate(
            name="encrypted_exfil",
            description="Exfiltrate data hidden in legitimate HTTPS traffic patterns",
            category=AttackCategory.EXFILTRATION,
            difficulty=AttackDifficulty.EXPERT,
            mitre_id="T1048.002",
            mitre_technique="Exfiltration Over Alternative Protocol: Asymmetric Encrypted",
            expected_detection=ExpectedDetection.NONE,
            expected_severity="LOW",
            parameters=[
                AttackParameter("target_url", "Legitimate-looking HTTPS URL", "str", required=True),
                AttackParameter("data_size_kb", "Data to exfiltrate (KB)", "int", 1),
                AttackParameter("timing_jitter_s", "Random delay between requests", "float", 30.0),
            ],
            steps=[
                "Encode data into legitimate-looking HTTPS request parameters",
                "Use real TLS to legitimate-looking domain",
                "Vary timing to match normal browsing patterns",
                "Keep data volume under statistical anomaly threshold",
            ],
            indicators=["Extremely hard — mimics legitimate traffic"],
        ))

        logger.debug("Attack library initialized with %d templates", len(self._templates))
