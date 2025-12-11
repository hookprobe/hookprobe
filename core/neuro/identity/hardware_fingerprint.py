"""
HookProbe Hardware Fingerprinting - Cortex Version

Creates unique hardware identifier when TPM is not available.
Combines multiple hardware characteristics for device uniqueness.

Fingerprint includes:
- CPU model and serial (if available)
- MAC addresses (network interfaces)
- Disk serial numbers
- DMI/SMBIOS information
- Timestamp binding for anti-replay
"""

import os
import hashlib
import subprocess
import uuid
import platform
from typing import Optional, Dict, List
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class HardwareFingerprint:
    """Unique hardware fingerprint for device identification."""
    fingerprint_id: str  # SHA256 hash of combined hardware IDs
    cpu_id: str
    mac_addresses: List[str]
    disk_serials: List[str]
    dmi_uuid: str
    hostname: str
    created_timestamp: int  # Unix microseconds
    raw_data: Dict[str, any]  # Original hardware data


class HardwareFingerprintGenerator:
    """
    Generate hardware fingerprint without TPM.

    Simple, effective approach:
    1. Collect stable hardware IDs
    2. Hash together for unique fingerprint
    3. Bind with timestamp for MSSP tracking
    """

    def __init__(self):
        """Initialize hardware fingerprint generator."""
        self.platform = platform.system().lower()

    def generate(self) -> HardwareFingerprint:
        """
        Generate hardware fingerprint.

        Returns:
            Hardware fingerprint with unique ID
        """
        # Collect hardware information
        cpu_id = self._get_cpu_id()
        mac_addresses = self._get_mac_addresses()
        disk_serials = self._get_disk_serials()
        dmi_uuid = self._get_dmi_uuid()
        hostname = platform.node()

        # Create timestamp
        timestamp = int(datetime.now(timezone.utc).timestamp() * 1e6)

        # Build raw data
        raw_data = {
            'cpu_id': cpu_id,
            'mac_addresses': mac_addresses,
            'disk_serials': disk_serials,
            'dmi_uuid': dmi_uuid,
            'hostname': hostname,
            'platform': self.platform,
            'architecture': platform.machine(),
        }

        # Generate fingerprint hash
        fingerprint_id = self._hash_hardware_data(raw_data, timestamp)

        return HardwareFingerprint(
            fingerprint_id=fingerprint_id,
            cpu_id=cpu_id,
            mac_addresses=mac_addresses,
            disk_serials=disk_serials,
            dmi_uuid=dmi_uuid,
            hostname=hostname,
            created_timestamp=timestamp,
            raw_data=raw_data
        )

    def verify(self, stored_fingerprint: HardwareFingerprint, tolerance: int = 2) -> Dict[str, any]:
        """
        Verify current hardware matches stored fingerprint.

        Args:
            stored_fingerprint: Previously stored fingerprint
            tolerance: Number of allowed mismatches (default 2)

        Returns:
            Verification result with details
        """
        current = self.generate()

        mismatches = []

        # Check CPU
        if current.cpu_id != stored_fingerprint.cpu_id:
            mismatches.append('cpu_id')

        # Check MACs (at least one must match)
        common_macs = set(current.mac_addresses) & set(stored_fingerprint.mac_addresses)
        if not common_macs:
            mismatches.append('mac_addresses')

        # Check disks (at least one must match)
        common_disks = set(current.disk_serials) & set(stored_fingerprint.disk_serials)
        if not common_disks:
            mismatches.append('disk_serials')

        # Check DMI UUID
        if current.dmi_uuid != stored_fingerprint.dmi_uuid:
            mismatches.append('dmi_uuid')

        # Result
        is_valid = len(mismatches) <= tolerance

        return {
            'valid': is_valid,
            'mismatches': mismatches,
            'mismatch_count': len(mismatches),
            'tolerance': tolerance,
            'current_fingerprint': current.fingerprint_id,
            'stored_fingerprint': stored_fingerprint.fingerprint_id
        }

    def _get_cpu_id(self) -> str:
        """Get CPU identifier."""
        try:
            if self.platform == 'linux':
                # Try to get CPU serial from /proc/cpuinfo
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if 'Serial' in line:
                            return line.split(':')[1].strip()
                        elif 'model name' in line:
                            # Use model name as fallback
                            return hashlib.sha256(line.encode()).hexdigest()[:16]

            # Fallback: use processor info
            cpu_info = f"{platform.processor()}-{platform.machine()}"
            return hashlib.sha256(cpu_info.encode()).hexdigest()[:16]

        except Exception:
            return "unknown-cpu"

    def _get_mac_addresses(self) -> List[str]:
        """Get all MAC addresses from network interfaces."""
        macs = []

        try:
            if self.platform == 'linux':
                # Read from /sys/class/net
                net_dir = '/sys/class/net'
                if os.path.exists(net_dir):
                    for iface in os.listdir(net_dir):
                        if iface == 'lo':  # Skip loopback
                            continue
                        mac_file = f"{net_dir}/{iface}/address"
                        if os.path.exists(mac_file):
                            with open(mac_file, 'r') as f:
                                mac = f.read().strip()
                                if mac and mac != '00:00:00:00:00:00':
                                    macs.append(mac)

            # Fallback: use uuid.getnode()
            if not macs:
                node = uuid.getnode()
                mac = ':'.join(['{:02x}'.format((node >> i) & 0xff) for i in range(0, 48, 8)][::-1])
                macs.append(mac)

        except Exception:
            pass

        return macs if macs else ['unknown-mac']

    def _get_disk_serials(self) -> List[str]:
        """Get disk serial numbers."""
        serials = []

        try:
            if self.platform == 'linux':
                # Use lsblk to get disk serials
                result = subprocess.run(
                    ['lsblk', '-d', '-o', 'SERIAL', '-n'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        serial = line.strip()
                        if serial and serial not in ['', 'SERIAL']:
                            serials.append(serial)

        except Exception:
            pass

        return serials if serials else ['unknown-disk']

    def _get_dmi_uuid(self) -> str:
        """Get DMI/SMBIOS UUID."""
        try:
            if self.platform == 'linux':
                # Try reading DMI UUID
                dmi_paths = [
                    '/sys/class/dmi/id/product_uuid',
                    '/sys/devices/virtual/dmi/id/product_uuid'
                ]

                for path in dmi_paths:
                    if os.path.exists(path):
                        try:
                            with open(path, 'r') as f:
                                dmi_uuid = f.read().strip()
                                if dmi_uuid:
                                    return dmi_uuid
                        except PermissionError:
                            # Try with sudo
                            result = subprocess.run(
                                ['sudo', 'cat', path],
                                capture_output=True,
                                text=True,
                                timeout=5
                            )
                            if result.returncode == 0:
                                return result.stdout.strip()

            # Fallback: generate from hostname
            return str(uuid.uuid5(uuid.NAMESPACE_DNS, platform.node()))

        except Exception:
            return str(uuid.uuid4())

    def _hash_hardware_data(self, raw_data: Dict, timestamp: int) -> str:
        """
        Create deterministic hash of hardware data.

        Args:
            raw_data: Hardware information
            timestamp: Creation timestamp

        Returns:
            SHA256 hash as hex string
        """
        # Build canonical representation
        parts = []

        parts.append(raw_data.get('cpu_id', ''))
        parts.extend(sorted(raw_data.get('mac_addresses', [])))
        parts.extend(sorted(raw_data.get('disk_serials', [])))
        parts.append(raw_data.get('dmi_uuid', ''))
        parts.append(raw_data.get('hostname', ''))
        parts.append(str(timestamp))

        # Hash
        data = '|'.join(parts).encode('utf-8')
        return hashlib.sha256(data).hexdigest()


# Example usage
if __name__ == '__main__':
    print("=== HookProbe Hardware Fingerprinting ===\n")

    generator = HardwareFingerprintGenerator()

    print("1. Generating hardware fingerprint...")
    fingerprint = generator.generate()

    print(f"   Fingerprint ID: {fingerprint.fingerprint_id[:32]}...")
    print(f"   CPU ID: {fingerprint.cpu_id}")
    print(f"   MAC Addresses: {', '.join(fingerprint.mac_addresses)}")
    print(f"   Disk Serials: {', '.join(fingerprint.disk_serials)}")
    print(f"   DMI UUID: {fingerprint.dmi_uuid}")
    print(f"   Hostname: {fingerprint.hostname}")
    print(f"   Timestamp: {fingerprint.created_timestamp}\n")

    print("2. Verifying fingerprint (simulating later verification)...")
    result = generator.verify(fingerprint, tolerance=2)

    print(f"   Valid: {result['valid']}")
    print(f"   Mismatches: {result['mismatch_count']}/{result['tolerance']} allowed")
    if result['mismatches']:
        print(f"   Mismatch fields: {', '.join(result['mismatches'])}")

    print("\n✓ Hardware fingerprinting test complete")
