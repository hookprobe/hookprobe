"""
Honeypot Mesh - Distributed Dark Port Deception System
=====================================================

Turns the entire mesh network into a minefield of "Ghost Services" using
dark ports that should never receive legitimate traffic.

Architecture:
- Dark Ports: Unused ports (445, 3389, 22, 23, 1433, 3306) on wrong VLANs
- Holographic Response: When triggered, route to central honeypot
- Mesh Distribution: Every node advertises decoy services
- Attacker Confusion: Responses come from different nodes than expected

Key Detection Capabilities:
- T1046 (Network Service Scanning) - Any dark port touch = scanner
- T1021 (Remote Services) - Lateral movement attempts to honeypots
- T1571 (Non-Standard Port) - Traffic to unused ports
- T1595 (Active Scanning) - Reconnaissance activity

Integration:
- OVS flow rules redirect dark port traffic to honeypot
- Mesh nodes share hit information in real-time
- NAPSE alerts correlated with honeypot touches
"""

import asyncio
import logging
import json
import subprocess
import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)


class HoneypotType(Enum):
    """Types of honeypot services to emulate."""
    SMB = "smb"           # Port 445 - File shares
    RDP = "rdp"           # Port 3389 - Remote desktop
    SSH = "ssh"           # Port 22 - Secure shell
    TELNET = "telnet"     # Port 23 - Legacy remote access
    SMTP = "smtp"         # Port 25 - Email server
    MSSQL = "mssql"       # Port 1433 - SQL Server
    MYSQL = "mysql"       # Port 3306 - MySQL
    HTTP = "http"         # Port 80 - Web server
    HTTPS = "https"       # Port 443 - Secure web
    FTP = "ftp"           # Port 21 - File transfer
    PRINTER = "printer"   # Port 9100 - Network printer


class ThreatLevel(Enum):
    """Threat assessment levels for honeypot touches."""
    LOW = "low"           # Single port probe
    MEDIUM = "medium"     # Multiple port probes
    HIGH = "high"         # Service interaction attempt
    CRITICAL = "critical" # Exploitation attempt detected


@dataclass
class DarkPort:
    """Configuration for a dark port honeypot."""
    port: int
    protocol: str  # tcp or udp
    service_type: HoneypotType
    vlan_id: int
    node_id: str
    enabled: bool = True

    @property
    def key(self) -> str:
        return f"{self.node_id}:{self.vlan_id}:{self.port}/{self.protocol}"


@dataclass
class HoneypotTouch:
    """Record of an attacker touching a honeypot."""
    timestamp: datetime
    source_ip: str
    source_port: int
    dest_port: int
    protocol: str
    service_type: HoneypotType
    node_id: str
    vlan_id: int
    payload_hash: Optional[str] = None
    payload_size: int = 0
    threat_level: ThreatLevel = ThreatLevel.LOW
    mitre_techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "service_type": self.service_type.value,
            "node_id": self.node_id,
            "vlan_id": self.vlan_id,
            "payload_hash": self.payload_hash,
            "payload_size": self.payload_size,
            "threat_level": self.threat_level.value,
            "mitre_techniques": self.mitre_techniques,
        }


@dataclass
class AttackerProfile:
    """Profile of an attacker based on honeypot interactions."""
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    touches: List[HoneypotTouch] = field(default_factory=list)
    ports_probed: Set[int] = field(default_factory=set)
    nodes_touched: Set[str] = field(default_factory=set)
    vlans_touched: Set[int] = field(default_factory=set)
    total_touches: int = 0
    threat_level: ThreatLevel = ThreatLevel.LOW

    def update_threat_level(self):
        """Update threat level based on behavior."""
        if len(self.ports_probed) >= 10 or len(self.nodes_touched) >= 3:
            self.threat_level = ThreatLevel.CRITICAL
        elif len(self.ports_probed) >= 5 or len(self.nodes_touched) >= 2:
            self.threat_level = ThreatLevel.HIGH
        elif len(self.ports_probed) >= 2:
            self.threat_level = ThreatLevel.MEDIUM
        else:
            self.threat_level = ThreatLevel.LOW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "ports_probed": list(self.ports_probed),
            "nodes_touched": list(self.nodes_touched),
            "vlans_touched": list(self.vlans_touched),
            "total_touches": self.total_touches,
            "threat_level": self.threat_level.value,
        }


# Default dark port configuration per honeypot type
DEFAULT_DARK_PORTS = {
    HoneypotType.SMB: [445, 139],
    HoneypotType.RDP: [3389],
    HoneypotType.SSH: [22, 2222],
    HoneypotType.TELNET: [23],
    HoneypotType.MSSQL: [1433, 1434],
    HoneypotType.MYSQL: [3306],
    HoneypotType.HTTP: [80, 8080, 8000],
    HoneypotType.HTTPS: [443, 8443],
    HoneypotType.FTP: [21, 20],
    HoneypotType.PRINTER: [9100, 515, 631],
}

# MITRE techniques associated with each honeypot type
HONEYPOT_MITRE_MAP = {
    HoneypotType.SMB: ["T1021.002", "T1570", "T1135"],  # SMB/Windows Admin Shares
    HoneypotType.RDP: ["T1021.001", "T1563.002"],       # Remote Desktop
    HoneypotType.SSH: ["T1021.004", "T1098.004"],       # SSH
    HoneypotType.TELNET: ["T1021", "T1059"],            # Remote Services
    HoneypotType.MSSQL: ["T1505.001", "T1059.001"],     # SQL Stored Procedures
    HoneypotType.MYSQL: ["T1505.001", "T1190"],         # SQL injection
    HoneypotType.HTTP: ["T1190", "T1133"],              # Web exploitation
    HoneypotType.HTTPS: ["T1190", "T1133"],             # Web exploitation
    HoneypotType.FTP: ["T1048.003", "T1071.002"],       # Exfiltration/FTP
    HoneypotType.PRINTER: ["T1020", "T1048"],           # Automated Exfiltration
}

# Service banners for honeypot responses
SERVICE_BANNERS = {
    HoneypotType.SSH: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    HoneypotType.FTP: b"220 Microsoft FTP Service\r\n",
    HoneypotType.TELNET: b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27",
    HoneypotType.SMTP: b"220 mail.internal.local ESMTP Postfix\r\n",
    HoneypotType.HTTP: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
    HoneypotType.MYSQL: b"\x4a\x00\x00\x00\x0a5.7.32-0ubuntu0.18.04.1",
}


class HoneypotMesh:
    """
    Distributed honeypot mesh controller.

    Coordinates dark port deployment across mesh nodes and aggregates
    touch events for threat intelligence.
    """

    def __init__(
        self,
        ovs_bridge: str = "br-mesh",
        honeypot_server: str = "10.0.0.250",
        state_file: str = "/var/lib/aiochi/honeypot_mesh.json",
        touch_retention_hours: int = 24,
    ):
        self.ovs_bridge = ovs_bridge
        self.honeypot_server = honeypot_server
        self.state_file = Path(state_file)
        self.touch_retention = timedelta(hours=touch_retention_hours)

        # State
        self.dark_ports: Dict[str, DarkPort] = {}  # key -> DarkPort
        self.touches: List[HoneypotTouch] = []
        self.attacker_profiles: Dict[str, AttackerProfile] = {}  # IP -> Profile
        self.mesh_nodes: Set[str] = set()
        self._lock = asyncio.Lock()

        # Callbacks
        self._touch_callbacks: List[callable] = []
        self._threat_callbacks: List[callable] = []

        logger.info(f"HoneypotMesh initialized: bridge={ovs_bridge}, server={honeypot_server}")

    def register_touch_callback(self, callback: callable):
        """Register callback for honeypot touch events."""
        self._touch_callbacks.append(callback)

    def register_threat_callback(self, callback: callable):
        """Register callback for threat level escalations."""
        self._threat_callbacks.append(callback)

    async def add_mesh_node(
        self,
        node_id: str,
        vlans: List[int],
        service_types: Optional[List[HoneypotType]] = None,
    ) -> int:
        """
        Add a mesh node and deploy dark ports.

        Args:
            node_id: Unique identifier for the mesh node
            vlans: VLANs where dark ports should be deployed
            service_types: Types of honeypots to deploy (default: all)

        Returns:
            Number of dark ports deployed
        """
        if service_types is None:
            service_types = list(HoneypotType)

        async with self._lock:
            self.mesh_nodes.add(node_id)
            deployed = 0

            for vlan in vlans:
                for service_type in service_types:
                    ports = DEFAULT_DARK_PORTS.get(service_type, [])
                    for port in ports:
                        dark_port = DarkPort(
                            port=port,
                            protocol="tcp",
                            service_type=service_type,
                            vlan_id=vlan,
                            node_id=node_id,
                        )

                        if dark_port.key not in self.dark_ports:
                            self.dark_ports[dark_port.key] = dark_port
                            await self._install_ovs_trap(dark_port)
                            deployed += 1

            logger.info(f"Added mesh node {node_id}: {deployed} dark ports on VLANs {vlans}")
            return deployed

    async def _install_ovs_trap(self, dark_port: DarkPort) -> bool:
        """
        Install OVS flow rule to trap and redirect dark port traffic.

        Traffic flow:
        1. Match: packets to dark port on specific VLAN
        2. Action: Clone to honeypot server, log to controller
        """
        try:
            # Create flow match criteria
            match = (
                f"dl_vlan={dark_port.vlan_id},"
                f"tcp,tp_dst={dark_port.port}"
            )

            # Action: redirect to honeypot server while keeping original for logging
            actions = (
                f"mod_dl_dst:{await self._get_honeypot_mac()},"
                f"mod_nw_dst:{self.honeypot_server},"
                f"output:LOCAL"
            )

            # High priority to catch before normal forwarding
            priority = 60000

            cmd = [
                "ovs-ofctl", "add-flow", self.ovs_bridge,
                f"priority={priority},{match},actions={actions}",
                "-O", "OpenFlow13"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode != 0:
                logger.error(f"Failed to install dark port trap: {result.stderr}")
                return False

            logger.debug(f"Installed trap: {dark_port.key}")
            return True

        except Exception as e:
            logger.error(f"Error installing OVS trap for {dark_port.key}: {e}")
            return False

    async def _get_honeypot_mac(self) -> str:
        """Get MAC address of honeypot server (or generate consistent fake)."""
        # Generate consistent MAC based on IP for reproducibility
        ip_bytes = socket.inet_aton(self.honeypot_server)
        mac_suffix = hashlib.md5(ip_bytes).hexdigest()[:6]
        return f"02:00:{mac_suffix[0:2]}:{mac_suffix[2:4]}:{mac_suffix[4:6]}:00"

    async def record_touch(
        self,
        source_ip: str,
        source_port: int,
        dest_port: int,
        protocol: str = "tcp",
        node_id: Optional[str] = None,
        vlan_id: Optional[int] = None,
        payload: Optional[bytes] = None,
    ) -> HoneypotTouch:
        """
        Record a honeypot touch event.

        Args:
            source_ip: Attacker's source IP
            source_port: Attacker's source port
            dest_port: Dark port that was touched
            protocol: Protocol (tcp/udp)
            node_id: Mesh node that detected the touch
            vlan_id: VLAN where touch occurred
            payload: Optional captured payload bytes

        Returns:
            HoneypotTouch record with threat assessment
        """
        # Determine service type from port
        service_type = self._port_to_service(dest_port)

        # Calculate payload hash if provided
        payload_hash = None
        payload_size = 0
        if payload:
            payload_hash = hashlib.sha256(payload).hexdigest()[:16]
            payload_size = len(payload)

        # Get associated MITRE techniques
        mitre_techniques = HONEYPOT_MITRE_MAP.get(service_type, ["T1046"])
        mitre_techniques = ["T1046"] + mitre_techniques  # Always include scanning

        touch = HoneypotTouch(
            timestamp=datetime.now(),
            source_ip=source_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            service_type=service_type,
            node_id=node_id or "unknown",
            vlan_id=vlan_id or 0,
            payload_hash=payload_hash,
            payload_size=payload_size,
            mitre_techniques=list(set(mitre_techniques)),
        )

        async with self._lock:
            # Assess threat level based on payload
            touch.threat_level = self._assess_touch_threat(touch, payload)

            # Store touch
            self.touches.append(touch)

            # Update attacker profile
            await self._update_attacker_profile(touch)

            # Cleanup old touches
            await self._cleanup_old_touches()

        # Notify callbacks
        for callback in self._touch_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(touch)
                else:
                    callback(touch)
            except Exception as e:
                logger.error(f"Touch callback error: {e}")

        logger.info(
            f"Honeypot touch: {source_ip}:{source_port} -> :{dest_port} "
            f"[{service_type.value}] threat={touch.threat_level.value}"
        )

        return touch

    def _port_to_service(self, port: int) -> HoneypotType:
        """Map port number to honeypot service type."""
        for service_type, ports in DEFAULT_DARK_PORTS.items():
            if port in ports:
                return service_type
        return HoneypotType.HTTP  # Default fallback

    def _assess_touch_threat(
        self,
        touch: HoneypotTouch,
        payload: Optional[bytes],
    ) -> ThreatLevel:
        """Assess threat level based on touch characteristics."""
        threat = ThreatLevel.LOW

        # Check for exploitation payloads
        if payload:
            payload_lower = payload.lower()

            # Critical exploitation patterns
            exploitation_patterns = [
                b"exploit",
                b"metasploit",
                b"meterpreter",
                b"shellcode",
                b"cmd.exe",
                b"/bin/sh",
                b"powershell",
                b"$env:",
                b"eternalblue",
                b"ms17-010",
            ]

            for pattern in exploitation_patterns:
                if pattern in payload_lower:
                    return ThreatLevel.CRITICAL

            # High-threat patterns (authentication attempts)
            auth_patterns = [
                b"admin",
                b"password",
                b"root",
                b"login",
                b"AUTH",
            ]

            for pattern in auth_patterns:
                if pattern in payload_lower:
                    threat = ThreatLevel.HIGH
                    break

            # Medium threat if substantial payload
            if len(payload) > 100 and threat == ThreatLevel.LOW:
                threat = ThreatLevel.MEDIUM

        # High-value targets get elevated threat
        high_value_ports = [445, 3389, 1433, 22]
        if touch.dest_port in high_value_ports and threat == ThreatLevel.LOW:
            threat = ThreatLevel.MEDIUM

        return threat

    async def _update_attacker_profile(self, touch: HoneypotTouch):
        """Update attacker profile with new touch."""
        ip = touch.source_ip

        if ip not in self.attacker_profiles:
            self.attacker_profiles[ip] = AttackerProfile(
                source_ip=ip,
                first_seen=touch.timestamp,
                last_seen=touch.timestamp,
            )

        profile = self.attacker_profiles[ip]
        profile.last_seen = touch.timestamp
        profile.touches.append(touch)
        profile.ports_probed.add(touch.dest_port)
        profile.nodes_touched.add(touch.node_id)
        profile.vlans_touched.add(touch.vlan_id)
        profile.total_touches += 1

        # Check for threat escalation
        old_threat = profile.threat_level
        profile.update_threat_level()

        if profile.threat_level.value != old_threat.value:
            logger.warning(
                f"Threat escalation for {ip}: {old_threat.value} -> {profile.threat_level.value}"
            )

            # Notify threat callbacks
            for callback in self._threat_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(profile)
                    else:
                        callback(profile)
                except Exception as e:
                    logger.error(f"Threat callback error: {e}")

    async def _cleanup_old_touches(self):
        """Remove touches older than retention period."""
        cutoff = datetime.now() - self.touch_retention
        self.touches = [t for t in self.touches if t.timestamp > cutoff]

    async def get_attacker_profile(self, ip: str) -> Optional[AttackerProfile]:
        """Get attacker profile by IP address."""
        return self.attacker_profiles.get(ip)

    async def get_active_threats(
        self,
        min_level: ThreatLevel = ThreatLevel.MEDIUM,
    ) -> List[AttackerProfile]:
        """Get all attackers above a threat threshold."""
        level_order = {
            ThreatLevel.LOW: 0,
            ThreatLevel.MEDIUM: 1,
            ThreatLevel.HIGH: 2,
            ThreatLevel.CRITICAL: 3,
        }
        min_value = level_order[min_level]

        return [
            p for p in self.attacker_profiles.values()
            if level_order[p.threat_level] >= min_value
        ]

    async def get_recent_touches(
        self,
        hours: int = 1,
        service_type: Optional[HoneypotType] = None,
    ) -> List[HoneypotTouch]:
        """Get recent honeypot touches."""
        cutoff = datetime.now() - timedelta(hours=hours)
        touches = [t for t in self.touches if t.timestamp > cutoff]

        if service_type:
            touches = [t for t in touches if t.service_type == service_type]

        return sorted(touches, key=lambda t: t.timestamp, reverse=True)

    async def generate_holographic_response(
        self,
        touch: HoneypotTouch,
        responding_node: str,
    ) -> Optional[bytes]:
        """
        Generate a honeypot response that appears to come from a different node.

        This creates the "holographic" effect where the attacker thinks they're
        talking to one node but responses come from another.
        """
        banner = SERVICE_BANNERS.get(touch.service_type)

        if not banner:
            # Generic response for unknown services
            banner = b"Service ready\r\n"

        # Add node identifier for correlation (hidden in response)
        node_marker = f"<!-- n:{responding_node} -->".encode()

        if touch.service_type in [HoneypotType.HTTP, HoneypotType.HTTPS]:
            return banner + node_marker + b"\r\n"

        return banner

    async def deploy_minefield(
        self,
        vlans: List[int],
        density: str = "medium",
    ) -> Dict[str, int]:
        """
        Deploy honeypots across all mesh nodes with specified density.

        Args:
            vlans: VLANs to protect
            density: "low" (SSH/SMB only), "medium" (common), "high" (all)

        Returns:
            Dict of node_id -> dark ports deployed
        """
        density_map = {
            "low": [HoneypotType.SSH, HoneypotType.SMB],
            "medium": [
                HoneypotType.SSH, HoneypotType.SMB, HoneypotType.RDP,
                HoneypotType.HTTP, HoneypotType.MYSQL,
            ],
            "high": list(HoneypotType),
        }

        service_types = density_map.get(density, density_map["medium"])
        results = {}

        for node_id in self.mesh_nodes:
            count = await self.add_mesh_node(node_id, vlans, service_types)
            results[node_id] = count

        total = sum(results.values())
        logger.info(f"Deployed minefield: {total} dark ports across {len(results)} nodes")

        return results

    async def save_state(self):
        """Persist mesh state to disk."""
        state = {
            "dark_ports": [
                {
                    "port": dp.port,
                    "protocol": dp.protocol,
                    "service_type": dp.service_type.value,
                    "vlan_id": dp.vlan_id,
                    "node_id": dp.node_id,
                    "enabled": dp.enabled,
                }
                for dp in self.dark_ports.values()
            ],
            "mesh_nodes": list(self.mesh_nodes),
            "attacker_profiles": {
                ip: profile.to_dict()
                for ip, profile in self.attacker_profiles.items()
            },
            "saved_at": datetime.now().isoformat(),
        }

        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)

        logger.info(f"Saved mesh state to {self.state_file}")

    async def load_state(self):
        """Load mesh state from disk."""
        if not self.state_file.exists():
            logger.info("No saved state found")
            return

        try:
            with open(self.state_file, "r") as f:
                state = json.load(f)

            self.mesh_nodes = set(state.get("mesh_nodes", []))

            for dp_data in state.get("dark_ports", []):
                dark_port = DarkPort(
                    port=dp_data["port"],
                    protocol=dp_data["protocol"],
                    service_type=HoneypotType(dp_data["service_type"]),
                    vlan_id=dp_data["vlan_id"],
                    node_id=dp_data["node_id"],
                    enabled=dp_data.get("enabled", True),
                )
                self.dark_ports[dark_port.key] = dark_port

            logger.info(f"Loaded mesh state: {len(self.dark_ports)} dark ports")

        except Exception as e:
            logger.error(f"Failed to load state: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get mesh statistics."""
        return {
            "mesh_nodes": len(self.mesh_nodes),
            "dark_ports": len(self.dark_ports),
            "total_touches": len(self.touches),
            "attacker_profiles": len(self.attacker_profiles),
            "active_threats": len([
                p for p in self.attacker_profiles.values()
                if p.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
            ]),
            "ports_by_service": {
                st.value: len([dp for dp in self.dark_ports.values() if dp.service_type == st])
                for st in HoneypotType
            },
        }


class HoneypotResponder:
    """
    Lightweight honeypot responder that handles attacker connections.

    Runs on the central honeypot server to interact with redirected traffic.
    """

    def __init__(self, mesh: HoneypotMesh):
        self.mesh = mesh
        self.servers: Dict[int, asyncio.Server] = {}
        self._running = False

    async def start(self, ports: Optional[List[int]] = None):
        """Start honeypot responders on specified ports."""
        if ports is None:
            # All dark ports
            ports = list(set(
                port
                for ports in DEFAULT_DARK_PORTS.values()
                for port in ports
            ))

        self._running = True

        for port in ports:
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=port: self._handle_connection(r, w, p),
                    "0.0.0.0",
                    port,
                )
                self.servers[port] = server
                logger.info(f"Honeypot responder listening on port {port}")
            except OSError as e:
                logger.warning(f"Could not bind port {port}: {e}")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Handle an incoming honeypot connection."""
        peer = writer.get_extra_info("peername")
        sock = writer.get_extra_info("socket")
        local_port = sock.getsockname()[1] if sock else 0

        try:
            source_ip, source_port = peer if peer else ("unknown", 0)

            # Read initial payload with timeout
            try:
                payload = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            except asyncio.TimeoutError:
                payload = None

            # Record the touch
            touch = await self.mesh.record_touch(
                source_ip=source_ip,
                source_port=source_port,
                dest_port=local_port,
                payload=payload,
            )

            # Generate response
            response = await self.mesh.generate_holographic_response(
                touch,
                responding_node="honeypot-central",
            )

            if response:
                writer.write(response)
                await writer.drain()

            # Keep connection open briefly for more payload
            try:
                await asyncio.wait_for(reader.read(4096), timeout=2.0)
            except asyncio.TimeoutError:
                pass

        except Exception as e:
            logger.debug(f"Honeypot connection error: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

    async def stop(self):
        """Stop all honeypot responders."""
        self._running = False

        for port, server in self.servers.items():
            server.close()
            await server.wait_closed()
            logger.info(f"Stopped honeypot responder on port {port}")

        self.servers.clear()


# Convenience function for integration
async def create_mesh_minefield(
    ovs_bridge: str = "br-mesh",
    honeypot_server: str = "10.0.0.250",
    nodes: List[str] = None,
    vlans: List[int] = None,
    density: str = "medium",
) -> HoneypotMesh:
    """
    Quick setup for honeypot mesh deployment.

    Example:
        mesh = await create_mesh_minefield(
            nodes=["node1", "node2", "node3"],
            vlans=[10, 20, 30],
            density="high",
        )
    """
    mesh = HoneypotMesh(
        ovs_bridge=ovs_bridge,
        honeypot_server=honeypot_server,
    )

    if nodes is None:
        nodes = ["mesh-node-1"]
    if vlans is None:
        vlans = [100]

    # Register all nodes first
    for node_id in nodes:
        mesh.mesh_nodes.add(node_id)

    # Deploy minefield
    await mesh.deploy_minefield(vlans, density)

    return mesh
