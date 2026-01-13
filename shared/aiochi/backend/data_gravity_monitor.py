"""
Data Gravity Monitor - Sensitive File Exfiltration Detection
============================================================

Connects DSM (Data Security Management) directly to Zeek's file-extraction
logs to track sensitive data movement and prevent exfiltration.

Data Gravity Concept:
- Files have "mass" based on sensitivity (PII, financials, credentials)
- High-mass files resist movement toward internet egress
- QSecBit score acts as gravitational modifier
- Low QSecBit + high file mass + internet direction = BLOCK

Integration Points:
- Zeek files.log: Real-time file transfer detection
- QSecBit scores: Device trustworthiness
- OVS flows: Instant exfil blocking
- DSM policies: Sensitivity classification rules

MITRE ATT&CK Coverage:
- T1048 (Exfiltration Over Alternative Protocol)
- T1041 (Exfiltration Over C2 Channel)
- T1020 (Automated Exfiltration)
- T1567 (Exfiltration to Cloud Storage)
- T1071 (Application Layer Protocol)
"""

import asyncio
import logging
import json
import subprocess
import re
import mimetypes
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)


class SensitivityLevel(Enum):
    """Data sensitivity classification levels."""
    PUBLIC = "public"           # Public info, no restrictions
    INTERNAL = "internal"       # Internal use, monitor movement
    CONFIDENTIAL = "confidential"  # Business sensitive, restrict egress
    RESTRICTED = "restricted"   # Highly sensitive, block all egress
    SECRET = "secret"          # Critical secrets, immediate alert + block


class DataType(Enum):
    """Categories of sensitive data types."""
    PII = "pii"                # Personal Identifiable Information
    PCI = "pci"                # Payment Card Industry data
    PHI = "phi"                # Protected Health Information
    CREDENTIALS = "credentials" # Passwords, keys, tokens
    FINANCIAL = "financial"    # Financial records
    IP = "ip"                  # Intellectual property
    CONFIG = "config"          # Configuration files
    DATABASE = "database"      # Database exports
    SOURCE_CODE = "source"     # Source code files
    ARCHIVE = "archive"        # Compressed archives


class ExfilDirection(Enum):
    """Direction of data movement."""
    INTERNAL = "internal"      # Within trusted network
    DMZ = "dmz"               # To/from DMZ
    EGRESS = "egress"         # Toward internet
    UNKNOWN = "unknown"


class ActionTaken(Enum):
    """Response actions for exfil attempts."""
    ALLOW = "allow"           # Permitted transfer
    LOG = "log"               # Log only (monitoring)
    THROTTLE = "throttle"     # Slow down transfer
    BLOCK = "block"           # Block transfer
    QUARANTINE = "quarantine" # Block + isolate device


@dataclass
class FileTransfer:
    """Record of a file transfer event from Zeek."""
    timestamp: datetime
    uid: str                  # Zeek connection UID
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    fuid: str                # Zeek file UID
    filename: Optional[str]
    mime_type: Optional[str]
    file_size: int
    md5: Optional[str]
    sha256: Optional[str]
    extracted: bool = False

    @property
    def key(self) -> str:
        return f"{self.uid}:{self.fuid}"


@dataclass
class SensitiveFile:
    """Metadata for a tracked sensitive file."""
    file_hash: str            # SHA256 or MD5
    filename_pattern: str     # Regex pattern matching filename
    sensitivity: SensitivityLevel
    data_types: List[DataType]
    gravity_mass: float       # 0.0 to 1.0, higher = more restricted
    description: str
    first_seen: datetime
    last_seen: datetime
    transfer_count: int = 0
    blocked_count: int = 0

    @classmethod
    def from_pattern(
        cls,
        pattern: str,
        sensitivity: SensitivityLevel,
        data_types: List[DataType],
        description: str = "",
    ) -> "SensitiveFile":
        """Create from filename pattern."""
        # Calculate gravity mass from sensitivity
        mass_map = {
            SensitivityLevel.PUBLIC: 0.1,
            SensitivityLevel.INTERNAL: 0.3,
            SensitivityLevel.CONFIDENTIAL: 0.6,
            SensitivityLevel.RESTRICTED: 0.85,
            SensitivityLevel.SECRET: 1.0,
        }
        return cls(
            file_hash="",
            filename_pattern=pattern,
            sensitivity=sensitivity,
            data_types=data_types,
            gravity_mass=mass_map.get(sensitivity, 0.5),
            description=description,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
        )


@dataclass
class ExfilEvent:
    """Record of a potential exfiltration event."""
    timestamp: datetime
    transfer: FileTransfer
    sensitivity: SensitivityLevel
    data_types: List[DataType]
    direction: ExfilDirection
    device_qsecbit: float
    gravity_mass: float
    risk_score: float          # Calculated risk 0.0-1.0
    action_taken: ActionTaken
    mitre_techniques: List[str]
    blocked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.transfer.source_ip,
            "dest_ip": self.transfer.dest_ip,
            "filename": self.transfer.filename,
            "file_size": self.transfer.file_size,
            "sensitivity": self.sensitivity.value,
            "data_types": [dt.value for dt in self.data_types],
            "direction": self.direction.value,
            "device_qsecbit": self.device_qsecbit,
            "gravity_mass": self.gravity_mass,
            "risk_score": self.risk_score,
            "action_taken": self.action_taken.value,
            "mitre_techniques": self.mitre_techniques,
            "blocked": self.blocked,
        }


# File pattern matchers for sensitive data detection
SENSITIVE_PATTERNS: List[Tuple[str, SensitivityLevel, List[DataType], str]] = [
    # Credentials and secrets
    (r"\.pem$", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "Private key"),
    (r"\.key$", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "Private key"),
    (r"\.ppk$", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "PuTTY private key"),
    (r"id_rsa", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "SSH private key"),
    (r"\.pfx$", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "PKCS#12 certificate"),
    (r"\.p12$", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "PKCS#12 certificate"),
    (r"\.env$", SensitivityLevel.RESTRICTED, [DataType.CREDENTIALS, DataType.CONFIG], "Environment config"),
    (r"password", SensitivityLevel.RESTRICTED, [DataType.CREDENTIALS], "Password file"),
    (r"credentials?\.json", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "Credentials JSON"),
    (r"secrets?\.ya?ml", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "Secrets config"),
    (r"\.htpasswd", SensitivityLevel.RESTRICTED, [DataType.CREDENTIALS], "Apache passwords"),
    (r"shadow$", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "Unix shadow file"),
    (r"sam$", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "Windows SAM"),
    (r"ntds\.dit", SensitivityLevel.SECRET, [DataType.CREDENTIALS], "Active Directory database"),

    # PII patterns
    (r"ssn", SensitivityLevel.RESTRICTED, [DataType.PII], "Social Security Numbers"),
    (r"drivers?[-_]?license", SensitivityLevel.RESTRICTED, [DataType.PII], "Driver's licenses"),
    (r"passport", SensitivityLevel.RESTRICTED, [DataType.PII], "Passport data"),
    (r"employee", SensitivityLevel.CONFIDENTIAL, [DataType.PII], "Employee records"),
    (r"customer", SensitivityLevel.CONFIDENTIAL, [DataType.PII], "Customer data"),
    (r"patient", SensitivityLevel.RESTRICTED, [DataType.PII, DataType.PHI], "Patient records"),
    (r"medical", SensitivityLevel.RESTRICTED, [DataType.PHI], "Medical records"),
    (r"hipaa", SensitivityLevel.RESTRICTED, [DataType.PHI], "HIPAA protected data"),
    (r"hr[-_]?data", SensitivityLevel.CONFIDENTIAL, [DataType.PII], "HR data"),

    # Financial data
    (r"credit[-_]?card", SensitivityLevel.RESTRICTED, [DataType.PCI], "Credit card data"),
    (r"\.qb[bw]$", SensitivityLevel.CONFIDENTIAL, [DataType.FINANCIAL], "QuickBooks file"),
    (r"invoice", SensitivityLevel.INTERNAL, [DataType.FINANCIAL], "Invoices"),
    (r"payroll", SensitivityLevel.RESTRICTED, [DataType.FINANCIAL, DataType.PII], "Payroll data"),
    (r"tax[-_]?return", SensitivityLevel.RESTRICTED, [DataType.FINANCIAL, DataType.PII], "Tax returns"),
    (r"w[-_]?2", SensitivityLevel.RESTRICTED, [DataType.FINANCIAL, DataType.PII], "W-2 forms"),
    (r"1099", SensitivityLevel.RESTRICTED, [DataType.FINANCIAL, DataType.PII], "1099 forms"),
    (r"bank[-_]?statement", SensitivityLevel.CONFIDENTIAL, [DataType.FINANCIAL], "Bank statements"),

    # Database files
    (r"\.sql$", SensitivityLevel.CONFIDENTIAL, [DataType.DATABASE], "SQL dump"),
    (r"\.mdb$", SensitivityLevel.CONFIDENTIAL, [DataType.DATABASE], "Access database"),
    (r"\.accdb$", SensitivityLevel.CONFIDENTIAL, [DataType.DATABASE], "Access database"),
    (r"\.sqlite", SensitivityLevel.CONFIDENTIAL, [DataType.DATABASE], "SQLite database"),
    (r"\.bak$", SensitivityLevel.CONFIDENTIAL, [DataType.DATABASE], "Database backup"),
    (r"dump\.sql", SensitivityLevel.CONFIDENTIAL, [DataType.DATABASE], "Database dump"),

    # Source code and IP
    (r"\.git/", SensitivityLevel.CONFIDENTIAL, [DataType.SOURCE_CODE], "Git repository"),
    (r"\.svn/", SensitivityLevel.CONFIDENTIAL, [DataType.SOURCE_CODE], "SVN repository"),
    (r"proprietary", SensitivityLevel.RESTRICTED, [DataType.IP], "Proprietary data"),
    (r"trade[-_]?secret", SensitivityLevel.SECRET, [DataType.IP], "Trade secrets"),
    (r"patent", SensitivityLevel.CONFIDENTIAL, [DataType.IP], "Patent data"),
    (r"design[-_]?doc", SensitivityLevel.CONFIDENTIAL, [DataType.IP], "Design documents"),

    # Configuration files
    (r"config\.(json|ya?ml|xml|ini)$", SensitivityLevel.INTERNAL, [DataType.CONFIG], "Configuration"),
    (r"settings\.(json|ya?ml|xml)$", SensitivityLevel.INTERNAL, [DataType.CONFIG], "Settings"),
    (r"\.conf$", SensitivityLevel.INTERNAL, [DataType.CONFIG], "Config file"),
    (r"web\.config", SensitivityLevel.CONFIDENTIAL, [DataType.CONFIG], "ASP.NET config"),
    (r"wp-config\.php", SensitivityLevel.CONFIDENTIAL, [DataType.CONFIG, DataType.CREDENTIALS], "WordPress config"),

    # Archives (potential bulk exfil)
    (r"\.(zip|rar|7z|tar|gz|bz2)$", SensitivityLevel.INTERNAL, [DataType.ARCHIVE], "Compressed archive"),
    (r"backup.*\.(zip|tar|gz)", SensitivityLevel.CONFIDENTIAL, [DataType.ARCHIVE], "Backup archive"),
]

# MIME types indicating sensitive content
SENSITIVE_MIME_TYPES: Dict[str, Tuple[SensitivityLevel, List[DataType]]] = {
    "application/x-x509-ca-cert": (SensitivityLevel.SECRET, [DataType.CREDENTIALS]),
    "application/pkcs12": (SensitivityLevel.SECRET, [DataType.CREDENTIALS]),
    "application/x-pkcs12": (SensitivityLevel.SECRET, [DataType.CREDENTIALS]),
    "application/vnd.ms-excel": (SensitivityLevel.INTERNAL, [DataType.FINANCIAL]),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": (SensitivityLevel.INTERNAL, [DataType.FINANCIAL]),
    "application/vnd.ms-access": (SensitivityLevel.CONFIDENTIAL, [DataType.DATABASE]),
    "application/x-sqlite3": (SensitivityLevel.CONFIDENTIAL, [DataType.DATABASE]),
    "application/sql": (SensitivityLevel.CONFIDENTIAL, [DataType.DATABASE]),
}

# Exfiltration-related MITRE techniques
EXFIL_MITRE_MAP = {
    DataType.PII: ["T1048", "T1041", "T1567"],
    DataType.PCI: ["T1048", "T1041", "T1020"],
    DataType.PHI: ["T1048", "T1041", "T1567"],
    DataType.CREDENTIALS: ["T1048", "T1003", "T1552"],
    DataType.FINANCIAL: ["T1048", "T1041", "T1020"],
    DataType.IP: ["T1048", "T1041", "T1048.003"],
    DataType.CONFIG: ["T1048", "T1005", "T1039"],
    DataType.DATABASE: ["T1048", "T1005", "T1020"],
    DataType.SOURCE_CODE: ["T1048", "T1213", "T1039"],
    DataType.ARCHIVE: ["T1048", "T1560", "T1020"],
}

# Known cloud storage/exfil destinations
KNOWN_EXFIL_DESTINATIONS = [
    r"\.dropbox\.com$",
    r"\.wetransfer\.com$",
    r"\.mega\.nz$",
    r"\.sendspace\.com$",
    r"\.zippyshare\.com$",
    r"\.mediafire\.com$",
    r"pastebin\.com$",
    r"ghostbin\.com$",
    r"privatebin\.net$",
    r"file\.io$",
    r"transfer\.sh$",
    r"temp\.sh$",
    r"0x0\.st$",
    r"catbox\.moe$",
]


class DataGravityMonitor:
    """
    Monitors file transfers and prevents sensitive data exfiltration.

    Uses "data gravity" concept where sensitive files have mass that
    resists movement toward untrusted destinations.
    """

    def __init__(
        self,
        ovs_bridge: str = "br-mesh",
        zeek_files_log: str = "/var/log/zeek/current/files.log",
        state_file: str = "/var/lib/aiochi/data_gravity.json",
        qsecbit_callback: Optional[Callable[[str], float]] = None,
    ):
        self.ovs_bridge = ovs_bridge
        self.zeek_files_log = Path(zeek_files_log)
        self.state_file = Path(state_file)
        self.qsecbit_callback = qsecbit_callback

        # State
        self.sensitive_files: Dict[str, SensitiveFile] = {}
        self.exfil_events: List[ExfilEvent] = []
        self.blocked_transfers: Set[str] = set()  # fuid set
        self._lock = asyncio.Lock()

        # Network zones
        self.internal_networks: List[str] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        self.dmz_networks: List[str] = []
        self.egress_points: List[str] = []  # Gateway IPs

        # Callbacks
        self._exfil_callbacks: List[Callable] = []

        # Compiled patterns
        self._pattern_cache: List[Tuple[re.Pattern, SensitiveFile]] = []
        self._compile_patterns()

        logger.info(f"DataGravityMonitor initialized: zeek_log={zeek_files_log}")

    def _compile_patterns(self):
        """Compile sensitive file patterns for faster matching."""
        self._pattern_cache.clear()

        for pattern, sensitivity, data_types, description in SENSITIVE_PATTERNS:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                sf = SensitiveFile.from_pattern(pattern, sensitivity, data_types, description)
                self._pattern_cache.append((regex, sf))
            except re.error:
                # CWE-532/CWE-209: Don't log pattern or exception details
                logger.warning(f"Invalid regex pattern in SENSITIVE_PATTERNS (index {len(self._pattern_cache)})")

    def register_exfil_callback(self, callback: Callable):
        """Register callback for exfiltration detection events."""
        self._exfil_callbacks.append(callback)

    def set_internal_networks(self, networks: List[str]):
        """Set internal network CIDR ranges."""
        self.internal_networks = networks

    def set_dmz_networks(self, networks: List[str]):
        """Set DMZ network CIDR ranges."""
        self.dmz_networks = networks

    def set_egress_points(self, gateways: List[str]):
        """Set gateway/egress point IPs."""
        self.egress_points = gateways

    async def get_qsecbit_score(self, ip: str) -> float:
        """Get QSecBit score for an IP address."""
        if self.qsecbit_callback:
            try:
                score = self.qsecbit_callback(ip)
                return float(score)
            except Exception as e:
                logger.debug(f"QSecBit callback error for {ip}: {e}")

        # Default score if no callback (neutral)
        return 0.5

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is in internal networks."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)

            for cidr in self.internal_networks:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True

            return False
        except Exception:
            return False

    def _is_dmz_ip(self, ip: str) -> bool:
        """Check if IP is in DMZ networks."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)

            for cidr in self.dmz_networks:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True

            return False
        except Exception:
            return False

    def _determine_direction(self, source_ip: str, dest_ip: str) -> ExfilDirection:
        """Determine the direction of a file transfer."""
        src_internal = self._is_internal_ip(source_ip)
        dst_internal = self._is_internal_ip(dest_ip)
        dst_dmz = self._is_dmz_ip(dest_ip)

        if src_internal and dst_internal:
            return ExfilDirection.INTERNAL
        elif src_internal and dst_dmz:
            return ExfilDirection.DMZ
        elif src_internal and not dst_internal:
            return ExfilDirection.EGRESS
        else:
            return ExfilDirection.UNKNOWN

    def _classify_file(
        self,
        filename: Optional[str],
        mime_type: Optional[str],
    ) -> Tuple[SensitivityLevel, List[DataType], float, str]:
        """
        Classify a file's sensitivity based on name and MIME type.

        Returns:
            Tuple of (sensitivity, data_types, gravity_mass, description)
        """
        sensitivity = SensitivityLevel.PUBLIC
        data_types = []
        gravity_mass = 0.0
        description = "Unknown file"

        # Check filename patterns
        if filename:
            for regex, sf in self._pattern_cache:
                if regex.search(filename):
                    if sf.gravity_mass > gravity_mass:
                        sensitivity = sf.sensitivity
                        data_types = sf.data_types
                        gravity_mass = sf.gravity_mass
                        description = sf.description

        # Check MIME type
        if mime_type and mime_type in SENSITIVE_MIME_TYPES:
            mime_sens, mime_types = SENSITIVE_MIME_TYPES[mime_type]

            # Take higher sensitivity
            sens_order = [
                SensitivityLevel.PUBLIC,
                SensitivityLevel.INTERNAL,
                SensitivityLevel.CONFIDENTIAL,
                SensitivityLevel.RESTRICTED,
                SensitivityLevel.SECRET,
            ]
            if sens_order.index(mime_sens) > sens_order.index(sensitivity):
                sensitivity = mime_sens
                data_types = mime_types
                gravity_mass = {
                    SensitivityLevel.PUBLIC: 0.1,
                    SensitivityLevel.INTERNAL: 0.3,
                    SensitivityLevel.CONFIDENTIAL: 0.6,
                    SensitivityLevel.RESTRICTED: 0.85,
                    SensitivityLevel.SECRET: 1.0,
                }[sensitivity]
                description = f"Sensitive MIME: {mime_type}"

        return sensitivity, data_types, gravity_mass, description

    def _calculate_risk_score(
        self,
        gravity_mass: float,
        qsecbit: float,
        direction: ExfilDirection,
        file_size: int,
    ) -> float:
        """
        Calculate exfiltration risk score.

        Formula: risk = gravity_mass * qsecbit * direction_weight * size_factor

        Where:
        - gravity_mass: File sensitivity (0-1)
        - qsecbit: Device suspicion score (0-1, higher = more suspicious)
        - direction_weight: Transfer direction factor
        - size_factor: Large file bonus
        """
        direction_weights = {
            ExfilDirection.INTERNAL: 0.2,
            ExfilDirection.DMZ: 0.6,
            ExfilDirection.EGRESS: 1.0,
            ExfilDirection.UNKNOWN: 0.8,
        }
        direction_weight = direction_weights.get(direction, 0.8)

        # Size factor: larger files slightly increase risk
        size_factor = 1.0
        if file_size > 10 * 1024 * 1024:  # > 10MB
            size_factor = 1.2
        elif file_size > 100 * 1024 * 1024:  # > 100MB
            size_factor = 1.4

        # Risk calculation
        risk = gravity_mass * qsecbit * direction_weight * size_factor

        # Clamp to 0-1
        return min(1.0, max(0.0, risk))

    def _determine_action(
        self,
        risk_score: float,
        sensitivity: SensitivityLevel,
        direction: ExfilDirection,
    ) -> ActionTaken:
        """Determine response action based on risk assessment."""

        # SECRET data: always block egress
        if sensitivity == SensitivityLevel.SECRET and direction == ExfilDirection.EGRESS:
            return ActionTaken.QUARANTINE

        # RESTRICTED data: block high-risk egress
        if sensitivity == SensitivityLevel.RESTRICTED:
            if direction == ExfilDirection.EGRESS and risk_score > 0.5:
                return ActionTaken.BLOCK
            elif direction == ExfilDirection.EGRESS:
                return ActionTaken.THROTTLE

        # CONFIDENTIAL data: based on risk score
        if sensitivity == SensitivityLevel.CONFIDENTIAL:
            if risk_score > 0.8:
                return ActionTaken.BLOCK
            elif risk_score > 0.5:
                return ActionTaken.THROTTLE
            else:
                return ActionTaken.LOG

        # INTERNAL/PUBLIC: log only
        if risk_score > 0.9:
            return ActionTaken.THROTTLE

        return ActionTaken.ALLOW

    async def analyze_transfer(
        self,
        transfer: FileTransfer,
    ) -> Optional[ExfilEvent]:
        """
        Analyze a file transfer for potential exfiltration.

        Args:
            transfer: File transfer record from Zeek

        Returns:
            ExfilEvent if sensitive, None if public/allowed
        """
        # Classify the file
        sensitivity, data_types, gravity_mass, description = self._classify_file(
            transfer.filename,
            transfer.mime_type,
        )

        # Skip public files
        if sensitivity == SensitivityLevel.PUBLIC and gravity_mass < 0.1:
            return None

        # Get device QSecBit score
        qsecbit = await self.get_qsecbit_score(transfer.source_ip)

        # Determine direction
        direction = self._determine_direction(transfer.source_ip, transfer.dest_ip)

        # Calculate risk
        risk_score = self._calculate_risk_score(
            gravity_mass, qsecbit, direction, transfer.file_size
        )

        # Determine action
        action = self._determine_action(risk_score, sensitivity, direction)

        # Get MITRE techniques
        mitre_techniques = []
        for dt in data_types:
            mitre_techniques.extend(EXFIL_MITRE_MAP.get(dt, ["T1048"]))
        mitre_techniques = list(set(mitre_techniques))

        # Create event
        event = ExfilEvent(
            timestamp=datetime.now(),
            transfer=transfer,
            sensitivity=sensitivity,
            data_types=data_types,
            direction=direction,
            device_qsecbit=qsecbit,
            gravity_mass=gravity_mass,
            risk_score=risk_score,
            action_taken=action,
            mitre_techniques=mitre_techniques,
            blocked=action in [ActionTaken.BLOCK, ActionTaken.QUARANTINE],
        )

        async with self._lock:
            self.exfil_events.append(event)

            if event.blocked:
                self.blocked_transfers.add(transfer.fuid)
                await self._block_transfer(transfer)

        # Notify callbacks
        for callback in self._exfil_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.error(f"Exfil callback error: {e}")

        # Log significant events
        if action != ActionTaken.ALLOW:
            logger.warning(
                f"Exfil detected: {transfer.source_ip} -> {transfer.dest_ip} "
                f"file={transfer.filename} sens={sensitivity.value} "
                f"risk={risk_score:.2f} action={action.value}"
            )

        return event

    async def _block_transfer(self, transfer: FileTransfer) -> bool:
        """Block an active file transfer via OVS."""
        try:
            # Drop rule for specific connection
            match = (
                f"ip,nw_src={transfer.source_ip},nw_dst={transfer.dest_ip},"
                f"tp_src={transfer.source_port},tp_dst={transfer.dest_port}"
            )

            cmd = [
                "ovs-ofctl", "add-flow", self.ovs_bridge,
                f"priority=65000,{match},actions=drop",
                "-O", "OpenFlow13"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode != 0:
                logger.error(f"Failed to block transfer: {result.stderr}")
                return False

            logger.info(f"Blocked exfil: {transfer.source_ip}:{transfer.source_port} -> "
                       f"{transfer.dest_ip}:{transfer.dest_port}")
            return True

        except Exception as e:
            logger.error(f"Error blocking transfer: {e}")
            return False

    async def process_zeek_log_line(self, line: str) -> Optional[ExfilEvent]:
        """
        Process a single line from Zeek files.log.

        Zeek files.log format (tab-separated):
        ts, fuid, tx_hosts, rx_hosts, conn_uids, source, depth, analyzers,
        mime_type, filename, duration, local_orig, is_orig, seen_bytes,
        total_bytes, missing_bytes, overflow_bytes, timedout, parent_fuid,
        md5, sha1, sha256, extracted, extracted_cutoff, extracted_size
        """
        try:
            if line.startswith("#"):
                return None

            fields = line.strip().split("\t")
            if len(fields) < 20:
                return None

            # Parse relevant fields
            ts = float(fields[0])
            fuid = fields[1]
            tx_hosts = fields[2].split(",") if fields[2] != "-" else []
            rx_hosts = fields[3].split(",") if fields[3] != "-" else []
            conn_uids = fields[4].split(",") if fields[4] != "-" else []
            mime_type = fields[8] if fields[8] != "-" else None
            filename = fields[9] if fields[9] != "-" else None
            seen_bytes = int(fields[13]) if fields[13] != "-" else 0
            md5_hash = fields[19] if len(fields) > 19 and fields[19] != "-" else None
            sha256_hash = fields[21] if len(fields) > 21 and fields[21] != "-" else None
            extracted = fields[22] == "T" if len(fields) > 22 else False

            # Need at least one transmitter and receiver
            if not tx_hosts or not rx_hosts:
                return None

            # Create transfer record
            transfer = FileTransfer(
                timestamp=datetime.fromtimestamp(ts),
                uid=conn_uids[0] if conn_uids else "",
                source_ip=tx_hosts[0],
                source_port=0,  # Not available in files.log
                dest_ip=rx_hosts[0],
                dest_port=0,
                fuid=fuid,
                filename=filename,
                mime_type=mime_type,
                file_size=seen_bytes,
                md5=md5_hash,
                sha256=sha256_hash,
                extracted=extracted,
            )

            return await self.analyze_transfer(transfer)

        except Exception as e:
            logger.debug(f"Error parsing Zeek log line: {e}")
            return None

    async def watch_zeek_log(self):
        """
        Watch Zeek files.log for new entries and analyze in real-time.

        Uses tail -f approach for streaming.
        """
        logger.info(f"Starting Zeek log watcher: {self.zeek_files_log}")

        while True:
            try:
                if not self.zeek_files_log.exists():
                    logger.warning(f"Zeek log not found: {self.zeek_files_log}")
                    await asyncio.sleep(5)
                    continue

                proc = await asyncio.create_subprocess_exec(
                    "tail", "-F", str(self.zeek_files_log),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )

                async for line in proc.stdout:
                    try:
                        await self.process_zeek_log_line(line.decode("utf-8", errors="ignore"))
                    except Exception as e:
                        logger.debug(f"Line processing error: {e}")

            except Exception as e:
                logger.error(f"Zeek watcher error: {e}")
                await asyncio.sleep(5)

    async def get_recent_events(
        self,
        hours: int = 1,
        min_risk: float = 0.0,
    ) -> List[ExfilEvent]:
        """Get recent exfiltration events."""
        cutoff = datetime.now() - timedelta(hours=hours)

        return [
            e for e in self.exfil_events
            if e.timestamp > cutoff and e.risk_score >= min_risk
        ]

    async def get_high_risk_sources(
        self,
        threshold: float = 0.7,
    ) -> Dict[str, Dict[str, Any]]:
        """Get sources with high-risk exfiltration activity."""
        sources: Dict[str, Dict[str, Any]] = {}

        for event in self.exfil_events:
            ip = event.transfer.source_ip
            if ip not in sources:
                sources[ip] = {
                    "ip": ip,
                    "events": 0,
                    "blocked": 0,
                    "max_risk": 0.0,
                    "data_types": set(),
                    "total_bytes": 0,
                }

            sources[ip]["events"] += 1
            if event.blocked:
                sources[ip]["blocked"] += 1
            sources[ip]["max_risk"] = max(sources[ip]["max_risk"], event.risk_score)
            sources[ip]["data_types"].update(dt.value for dt in event.data_types)
            sources[ip]["total_bytes"] += event.transfer.file_size

        # Filter to high-risk and convert sets to lists
        result = {}
        for ip, data in sources.items():
            if data["max_risk"] >= threshold:
                data["data_types"] = list(data["data_types"])
                result[ip] = data

        return result

    async def save_state(self):
        """Persist monitor state to disk."""
        state = {
            "blocked_transfers": list(self.blocked_transfers),
            "recent_events": [
                e.to_dict() for e in self.exfil_events[-100:]
            ],
            "saved_at": datetime.now().isoformat(),
        }

        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)

        logger.info(f"Saved data gravity state to {self.state_file}")

    def get_stats(self) -> Dict[str, Any]:
        """Get monitor statistics."""
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        recent = [e for e in self.exfil_events if e.timestamp > hour_ago]

        return {
            "total_events": len(self.exfil_events),
            "events_last_hour": len(recent),
            "blocked_transfers": len(self.blocked_transfers),
            "blocked_last_hour": len([e for e in recent if e.blocked]),
            "events_by_sensitivity": {
                s.value: len([e for e in self.exfil_events if e.sensitivity == s])
                for s in SensitivityLevel
            },
            "events_by_direction": {
                d.value: len([e for e in self.exfil_events if e.direction == d])
                for d in ExfilDirection
            },
        }


# Convenience function for integration
async def create_data_gravity_monitor(
    ovs_bridge: str = "br-mesh",
    zeek_log: str = "/var/log/zeek/current/files.log",
    internal_networks: List[str] = None,
    qsecbit_callback: Callable[[str], float] = None,
) -> DataGravityMonitor:
    """
    Quick setup for data gravity monitoring.

    Example:
        monitor = await create_data_gravity_monitor(
            internal_networks=["10.0.0.0/8", "192.168.0.0/16"],
            qsecbit_callback=lambda ip: device_scores.get(ip, 0.5),
        )
        asyncio.create_task(monitor.watch_zeek_log())
    """
    monitor = DataGravityMonitor(
        ovs_bridge=ovs_bridge,
        zeek_files_log=zeek_log,
        qsecbit_callback=qsecbit_callback,
    )

    if internal_networks:
        monitor.set_internal_networks(internal_networks)

    return monitor
