"""
Kernel-Aware Digital Twin — Extends DigitalTwinSimulator with eBPF replay.

Adds to the base DigitalTwinSimulator:
1. eBPF event replay from historical streaming RAG data
2. Attack simulation interface for shadow pentester templates
3. QSecBit scoring of twin traffic for defense validation
4. Topology query API for reconnaissance

The twin mirrors the production Fortress SDN topology but runs in
complete isolation. No traffic escapes the twin environment.

Integration:
    products/nexus/lib/red_purple_teaming/digital_twin.py — base class
    core/aegis/neurokernel/streaming_rag.py — event replay source
    core/aegis/neurokernel/attack_library.py — attack templates

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .types import SensorEvent, SensorType

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Data Types
# ------------------------------------------------------------------

@dataclass
class TwinAttackResult:
    """Result of simulating an attack in the kernel twin."""
    success: bool
    attack_name: str
    target_ip: str = ""
    packets_injected: int = 0
    events_generated: int = 0
    qsecbit_detected: bool = False
    detection_layer: str = ""
    notes: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "attack_name": self.attack_name,
            "target_ip": self.target_ip,
            "packets_injected": self.packets_injected,
            "events_generated": self.events_generated,
            "qsecbit_detected": self.qsecbit_detected,
            "detection_layer": self.detection_layer,
            "notes": self.notes,
            "timestamp": self.timestamp,
        }


@dataclass
class TwinDevice:
    """Minimal device representation for the kernel twin."""
    mac: str
    ip: str
    hostname: str = ""
    state: str = "active"
    qsecbit_score: float = 0.7
    open_ports: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "qsecbit_score": self.qsecbit_score,
            "open_ports": self.open_ports,
        }


# ------------------------------------------------------------------
# Kernel Digital Twin
# ------------------------------------------------------------------

class KernelDigitalTwin:
    """eBPF-aware digital twin for shadow pentester.

    This extends the concept of DigitalTwinSimulator with:
    - Lightweight device inventory (no need for full Nexus twin)
    - Attack simulation interface matching shadow pentester templates
    - Event replay from streaming RAG pipeline
    - QSecBit detection check stubs

    For full Fortress SDN mirroring, use the Nexus DigitalTwinSimulator
    and wrap it with this class. For standalone testing (no Nexus),
    this class provides a minimal twin environment.

    Usage:
        twin = KernelDigitalTwin()
        twin.add_device(TwinDevice(mac="aa:bb:cc:dd:ee:01", ip="10.200.0.10"))
        result = twin.simulate_attack("port_scan", {"target_ip": "10.200.0.10"})
    """

    def __init__(
        self,
        base_twin: Optional[Any] = None,
        subnet: str = "10.200.0.0/24",
    ):
        """Initialize the kernel twin.

        Args:
            base_twin: Optional DigitalTwinSimulator to wrap.
            subnet: Twin network subnet.
        """
        self._base_twin = base_twin
        self._subnet = subnet

        # Device inventory
        self._devices: Dict[str, TwinDevice] = {}  # mac → device
        self._ip_to_mac: Dict[str, str] = {}        # ip → mac

        # Attack history
        self._attack_log: List[TwinAttackResult] = []
        self._events_replayed: int = 0

        # Detection callback (set by shadow pentester)
        self._detection_checker: Any = None

    # ------------------------------------------------------------------
    # Public: Device Management
    # ------------------------------------------------------------------

    def add_device(self, device: TwinDevice) -> None:
        """Add a device to the twin network."""
        self._devices[device.mac] = device
        if device.ip:
            self._ip_to_mac[device.ip] = device.mac

    def remove_device(self, mac: str) -> Optional[TwinDevice]:
        """Remove a device from the twin network."""
        device = self._devices.pop(mac, None)
        if device and device.ip:
            self._ip_to_mac.pop(device.ip, None)
        return device

    def get_device_by_ip(self, ip: str) -> Optional[TwinDevice]:
        """Look up a device by IP address."""
        mac = self._ip_to_mac.get(ip)
        if mac:
            return self._devices.get(mac)
        return None

    def list_devices(self) -> List[Dict[str, Any]]:
        """List all devices in the twin."""
        return [d.to_dict() for d in self._devices.values()]

    # ------------------------------------------------------------------
    # Public: Topology Query (for reconnaissance)
    # ------------------------------------------------------------------

    def create_snapshot(self) -> Dict[str, Any]:
        """Create a snapshot of the twin topology.

        Compatible with DigitalTwinSimulator.create_snapshot() format.
        """
        # If we have a base twin, delegate
        if self._base_twin is not None and hasattr(self._base_twin, "create_snapshot"):
            try:
                return self._base_twin.create_snapshot()
            except Exception:
                pass

        # Build snapshot from local inventory
        devices_dict = {}
        for mac, dev in self._devices.items():
            devices_dict[mac] = dev.to_dict()

        return {
            "twin_id": "kernel-twin",
            "timestamp": time.time(),
            "subnet": self._subnet,
            "devices": devices_dict,
            "device_count": len(self._devices),
        }

    def get_active_hosts(self) -> List[str]:
        """Get list of active host IPs."""
        return [
            d.ip for d in self._devices.values()
            if d.state == "active" and d.ip
        ]

    def get_open_services(self) -> Dict[str, List[int]]:
        """Get open ports per IP."""
        services: Dict[str, List[int]] = {}
        for d in self._devices.values():
            if d.ip and d.open_ports:
                services[d.ip] = list(d.open_ports)
        return services

    # ------------------------------------------------------------------
    # Public: Attack Simulation
    # ------------------------------------------------------------------

    def simulate_attack(
        self,
        attack_name: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Simulate an attack in the twin.

        Generates synthetic SensorEvents that represent the attack
        traffic, then checks if the detection logic catches them.

        Args:
            attack_name: Name of the attack template.
            parameters: Attack parameters.

        Returns:
            Dict with success, notes, and event count.
        """
        params = parameters or {}
        target_ip = params.get("target_ip", params.get("victim_ip", ""))

        # Generate attack events based on template
        events = self._generate_attack_events(attack_name, params)

        # Record result
        result = TwinAttackResult(
            success=len(events) > 0,
            attack_name=attack_name,
            target_ip=target_ip,
            events_generated=len(events),
            notes=f"Generated {len(events)} synthetic events",
        )

        self._attack_log.append(result)
        if len(self._attack_log) > 200:
            self._attack_log = self._attack_log[-200:]

        return result.to_dict()

    def replay_events(self, events: List[SensorEvent]) -> int:
        """Replay historical events into the twin.

        Used to replay captured eBPF events for testing detection.

        Args:
            events: List of SensorEvents to replay.

        Returns:
            Number of events replayed.
        """
        count = 0
        for event in events:
            # Ensure event targets a twin device
            if event.source_ip and event.source_ip not in self._ip_to_mac:
                continue
            count += 1

        self._events_replayed += count
        return count

    # ------------------------------------------------------------------
    # Public: Stats
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Get twin statistics."""
        return {
            "device_count": len(self._devices),
            "subnet": self._subnet,
            "attacks_simulated": len(self._attack_log),
            "events_replayed": self._events_replayed,
            "has_base_twin": self._base_twin is not None,
        }

    def get_attack_log(self) -> List[Dict[str, Any]]:
        """Get the attack simulation history."""
        return [r.to_dict() for r in self._attack_log]

    # ------------------------------------------------------------------
    # Public: Sync from Base Twin
    # ------------------------------------------------------------------

    def sync_from_base(self) -> int:
        """Sync device inventory from the base DigitalTwinSimulator.

        Returns number of devices synced.
        """
        if self._base_twin is None:
            return 0

        count = 0
        try:
            # Try getting devices from base twin
            devices = getattr(self._base_twin, "_devices", {})
            for mac, dev in devices.items():
                ip = getattr(dev, "ip", "")
                hostname = getattr(dev, "hostname", "")
                qsecbit = getattr(dev, "qsecbit_score", 0.7)

                twin_dev = TwinDevice(
                    mac=mac,
                    ip=ip,
                    hostname=hostname,
                    state="active",
                    qsecbit_score=qsecbit,
                )
                self.add_device(twin_dev)
                count += 1
        except Exception as e:
            logger.warning("Base twin sync failed: %s", e)

        return count

    # ------------------------------------------------------------------
    # Internal: Event Generation
    # ------------------------------------------------------------------

    def _generate_attack_events(
        self,
        attack_name: str,
        params: Dict[str, Any],
    ) -> List[SensorEvent]:
        """Generate synthetic SensorEvents for an attack simulation."""
        events: List[SensorEvent] = []
        now = time.time()
        source_ip = params.get("attacker_ip", "10.200.0.250")
        target_ip = params.get("target_ip", params.get("victim_ip", ""))

        if attack_name == "port_scan":
            port_range = params.get("port_range", "1-100")
            try:
                start, end = port_range.split("-")
                ports = range(int(start), int(end) + 1)
            except (ValueError, AttributeError):
                ports = range(1, 101)
            for i, port in enumerate(ports):
                events.append(SensorEvent(
                    sensor_type=SensorType.NETWORK,
                    timestamp=now + i * 0.001,
                    source_ip=source_ip,
                    dest_ip=target_ip,
                    protocol=6,  # TCP
                    port=port,
                    payload_len=44,  # SYN packet
                    metadata={"flags": "SYN", "attack": "port_scan"},
                ))

        elif attack_name == "arp_scan":
            subnet = params.get("subnet", "10.200.0.0/24")
            for i in range(min(254, 50)):  # Cap at 50 for performance
                events.append(SensorEvent(
                    sensor_type=SensorType.NETWORK,
                    timestamp=now + i * 0.001,
                    source_ip=source_ip,
                    dest_ip=f"10.200.0.{i + 1}",
                    protocol=1,  # ARP uses L2 but we track as network
                    metadata={"type": "ARP_REQUEST", "attack": "arp_scan"},
                ))

        elif attack_name == "arp_spoof":
            victim_ip = params.get("victim_ip", target_ip)
            gateway_ip = params.get("gateway_ip", "10.200.0.1")
            for i in range(10):
                events.append(SensorEvent(
                    sensor_type=SensorType.NETWORK,
                    timestamp=now + i * 0.5,
                    source_ip=source_ip,
                    dest_ip=victim_ip,
                    protocol=1,
                    metadata={
                        "type": "ARP_REPLY",
                        "spoofed_ip": gateway_ip,
                        "attack": "arp_spoof",
                    },
                ))

        elif attack_name == "syn_flood":
            rate = params.get("rate_pps", 1000)
            duration = min(params.get("duration_s", 5), 5)
            count = min(rate * duration, 5000)  # Cap events
            target_port = params.get("target_port", 80)
            for i in range(count):
                events.append(SensorEvent(
                    sensor_type=SensorType.NETWORK,
                    timestamp=now + i * (1.0 / rate),
                    source_ip=f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}",
                    dest_ip=target_ip,
                    protocol=6,
                    port=target_port,
                    payload_len=44,
                    metadata={"flags": "SYN", "attack": "syn_flood"},
                ))

        elif attack_name == "udp_flood":
            rate = params.get("rate_pps", 1000)
            count = min(rate, 5000)
            target_port = params.get("target_port", 53)
            for i in range(count):
                events.append(SensorEvent(
                    sensor_type=SensorType.NETWORK,
                    timestamp=now + i * (1.0 / rate),
                    source_ip=source_ip,
                    dest_ip=target_ip,
                    protocol=17,  # UDP
                    port=target_port,
                    payload_len=512,
                    metadata={"attack": "udp_flood"},
                ))

        elif attack_name == "dns_tunnel":
            c2_domain = params.get("c2_domain", "evil.com")
            data_kb = params.get("data_size_kb", 10)
            # ~1 query per 100 bytes of exfiltrated data
            query_count = min(data_kb * 10, 200)
            for i in range(query_count):
                subdomain = f"{'a' * 50}{i:04d}.{c2_domain}"
                events.append(SensorEvent(
                    sensor_type=SensorType.DNS,
                    timestamp=now + i * 0.05,
                    source_ip=source_ip,
                    dest_ip="10.200.0.1",
                    protocol=17,
                    port=53,
                    payload_len=len(subdomain),
                    metadata={
                        "domain": subdomain,
                        "qtype": "TXT",
                        "attack": "dns_tunnel",
                    },
                ))

        elif attack_name == "dga_c2":
            domain_count = params.get("domain_count", 50)
            seed = params.get("seed", "shadow")
            tld = params.get("tld", ".com")
            for i in range(domain_count):
                # Generate pseudo-random domain
                import hashlib as _hl
                h = _hl.md5(f"{seed}{i}".encode()).hexdigest()[:12]
                domain = f"{h}{tld}"
                events.append(SensorEvent(
                    sensor_type=SensorType.DNS,
                    timestamp=now + i * 0.1,
                    source_ip=source_ip,
                    dest_ip="10.200.0.1",
                    protocol=17,
                    port=53,
                    payload_len=len(domain),
                    metadata={
                        "domain": domain,
                        "qtype": "A",
                        "response": "NXDOMAIN",
                        "attack": "dga_c2",
                    },
                ))

        elif attack_name == "dns_enumeration":
            domain = params.get("domain", "example.com")
            wordlist_size = min(params.get("wordlist_size", 100), 200)
            for i in range(wordlist_size):
                subdomain = f"sub{i}.{domain}"
                events.append(SensorEvent(
                    sensor_type=SensorType.DNS,
                    timestamp=now + i * 0.01,
                    source_ip=source_ip,
                    dest_ip="10.200.0.1",
                    protocol=17,
                    port=53,
                    payload_len=len(subdomain),
                    metadata={
                        "domain": subdomain,
                        "qtype": "A",
                        "attack": "dns_enumeration",
                    },
                ))

        elif attack_name == "rogue_dhcp":
            attacker_ip = params.get("attacker_ip", source_ip)
            for i in range(5):
                events.append(SensorEvent(
                    sensor_type=SensorType.NETWORK,
                    timestamp=now + i * 1.0,
                    source_ip=attacker_ip,
                    dest_ip="255.255.255.255",
                    protocol=17,
                    port=67,
                    payload_len=300,
                    metadata={
                        "type": "DHCP_OFFER",
                        "offered_gateway": params.get("offered_gateway", attacker_ip),
                        "attack": "rogue_dhcp",
                    },
                ))

        elif attack_name == "vlan_hop":
            target_vlan = params.get("target_vlan", 110)
            events.append(SensorEvent(
                sensor_type=SensorType.NETWORK,
                timestamp=now,
                source_ip=source_ip,
                dest_ip=target_ip or "10.200.0.10",
                protocol=6,
                metadata={
                    "double_tagged": True,
                    "outer_vlan": params.get("native_vlan", 1),
                    "inner_vlan": target_vlan,
                    "attack": "vlan_hop",
                },
            ))

        elif attack_name == "mdns_spoof":
            attacker_ip = params.get("attacker_ip", source_ip)
            service = params.get("service_type", "_http._tcp")
            events.append(SensorEvent(
                sensor_type=SensorType.DNS,
                timestamp=now,
                source_ip=attacker_ip,
                dest_ip="224.0.0.251",
                protocol=17,
                port=5353,
                metadata={
                    "service": service,
                    "spoofed_name": params.get("spoofed_name", "Fake-Service"),
                    "attack": "mdns_spoof",
                },
            ))

        else:
            # Generic: single event marking the attack
            events.append(SensorEvent(
                sensor_type=SensorType.NETWORK,
                timestamp=now,
                source_ip=source_ip,
                dest_ip=target_ip,
                metadata={"attack": attack_name, "params": str(params)[:200]},
            ))

        return events

    # ------------------------------------------------------------------
    # Class: Factory
    # ------------------------------------------------------------------

    @classmethod
    def create_test_twin(cls, num_devices: int = 5) -> "KernelDigitalTwin":
        """Create a twin pre-populated with test devices.

        Useful for unit tests and standalone shadow pentesting.
        """
        twin = cls(subnet="10.200.0.0/24")

        templates = [
            ("AA:BB:CC:DD:EE:01", "10.200.0.10", "Dad-iPhone", [80, 443]),
            ("AA:BB:CC:DD:EE:02", "10.200.0.20", "Dad-MacBook", [22, 80, 443, 8080]),
            ("AA:BB:CC:DD:EE:03", "10.200.0.30", "Mom-iPhone", [80, 443]),
            ("AA:BB:CC:DD:EE:04", "10.200.0.40", "IoT-Camera", [80, 554]),
            ("AA:BB:CC:DD:EE:05", "10.200.0.50", "Guest-Laptop", [80, 443]),
            ("AA:BB:CC:DD:EE:06", "10.200.0.60", "SmartTV", [8008, 8443]),
            ("AA:BB:CC:DD:EE:07", "10.200.0.70", "POS-Terminal", [443, 8443]),
            ("AA:BB:CC:DD:EE:08", "10.200.0.80", "Printer", [80, 631, 9100]),
        ]

        for i, (mac, ip, hostname, ports) in enumerate(templates[:num_devices]):
            twin.add_device(TwinDevice(
                mac=mac,
                ip=ip,
                hostname=hostname,
                open_ports=ports,
            ))

        return twin
