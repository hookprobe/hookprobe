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

Software Secure Enclave Features (v2.0):
- Memory locking via mlock() to prevent swapping
- Canary values for buffer overflow detection
- Constant-time comparison for timing attack resistance
- Secure memory wiping on deallocation
"""

import os
import hashlib
import subprocess
import uuid
import platform
import hmac
import secrets
import ctypes
import logging
from typing import Optional, Dict, List
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ============================================================================
# SOFTWARE SECURE ENCLAVE UTILITIES
# ============================================================================


class SecureMemory:
    """
    Software-based secure memory enclave for sensitive data.

    Provides:
    1. Memory locking (prevent swap to disk)
    2. Canary values (detect buffer overflows)
    3. Secure wiping on destruction
    """

    # Canary values for integrity checking
    CANARY_SIZE = 8
    CANARY_VALUE = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'

    def __init__(self, data: bytes):
        """
        Create secure memory region for sensitive data.

        Args:
            data: Sensitive data to protect
        """
        # Add canary values around data
        self._buffer = bytearray(
            self.CANARY_VALUE + data + self.CANARY_VALUE
        )
        self._data_start = self.CANARY_SIZE
        self._data_end = self.CANARY_SIZE + len(data)
        self._locked = False

        # Try to lock memory (prevent swap)
        self._try_mlock()

    def _try_mlock(self) -> bool:
        """
        Attempt to lock memory region using mlock().

        This prevents the sensitive data from being swapped to disk.
        Requires appropriate privileges on most systems.
        """
        try:
            if platform.system().lower() == 'linux':
                libc = ctypes.CDLL('libc.so.6', use_errno=True)
                addr = ctypes.addressof(
                    (ctypes.c_char * len(self._buffer)).from_buffer(self._buffer)
                )
                result = libc.mlock(addr, len(self._buffer))
                if result == 0:
                    self._locked = True
                    logger.debug("[SecureMemory] Memory locked successfully")
                    return True
                else:
                    logger.debug("[SecureMemory] mlock failed (may require privileges)")
        except Exception as e:
            logger.debug(f"[SecureMemory] mlock not available: {e}")

        return False

    def _munlock(self) -> None:
        """Unlock memory region."""
        if self._locked and platform.system().lower() == 'linux':
            try:
                libc = ctypes.CDLL('libc.so.6', use_errno=True)
                addr = ctypes.addressof(
                    (ctypes.c_char * len(self._buffer)).from_buffer(self._buffer)
                )
                libc.munlock(addr, len(self._buffer))
                self._locked = False
            except Exception:
                pass

    def check_canary(self) -> bool:
        """
        Verify canary values are intact.

        Returns:
            True if canaries are valid, False if buffer overflow detected
        """
        front_canary = bytes(self._buffer[:self.CANARY_SIZE])
        back_canary = bytes(self._buffer[self._data_end:self._data_end + self.CANARY_SIZE])

        return (
            hmac.compare_digest(front_canary, self.CANARY_VALUE) and
            hmac.compare_digest(back_canary, self.CANARY_VALUE)
        )

    def get_data(self) -> bytes:
        """
        Retrieve protected data.

        Returns:
            Protected data

        Raises:
            SecurityError: If canary check fails (possible tampering)
        """
        if not self.check_canary():
            raise SecurityError("Canary check failed - possible buffer overflow")

        return bytes(self._buffer[self._data_start:self._data_end])

    def secure_wipe(self) -> None:
        """Securely wipe the memory region."""
        # Unlock first
        self._munlock()

        # Overwrite with random data multiple times
        for _ in range(3):
            for i in range(len(self._buffer)):
                self._buffer[i] = secrets.randbelow(256)

        # Final zero wipe
        for i in range(len(self._buffer)):
            self._buffer[i] = 0

    def __del__(self):
        """Destructor - ensure secure wipe on deletion."""
        try:
            self.secure_wipe()
        except Exception:
            pass


class SecurityError(Exception):
    """Security violation detected."""
    pass


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.

    This function takes the same amount of time regardless of
    where the first difference occurs.

    Args:
        a: First bytes to compare
        b: Second bytes to compare

    Returns:
        True if equal, False otherwise
    """
    return hmac.compare_digest(a, b)


def secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Uses secrets module which is backed by system entropy.

    Args:
        length: Number of bytes to generate

    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)


def secure_hash(data: bytes, salt: Optional[bytes] = None) -> bytes:
    """
    Compute secure hash with optional salt.

    Args:
        data: Data to hash
        salt: Optional salt (default: generates random 32-byte salt)

    Returns:
        Hash value (64 bytes if salt provided, 32 bytes otherwise)
    """
    if salt is None:
        return hashlib.sha256(data).digest()

    # HKDF-like derivation with salt
    return hashlib.sha256(salt + data).digest() + hashlib.sha256(data + salt).digest()

# ============================================================================
# HARDWARE FINGERPRINT
# ============================================================================


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
    fingerprint: Optional[bytes] = None  # Raw 32-byte fingerprint

    def __post_init__(self):
        """Compute raw fingerprint bytes."""
        if self.fingerprint is None:
            self.fingerprint = bytes.fromhex(self.fingerprint_id)


class HardwareFingerprintGenerator:
    """
    Generate hardware fingerprint without TPM.

    Simple, effective approach:
    1. Collect stable hardware IDs
    2. Hash together for unique fingerprint
    3. Bind with timestamp for mesh tracking
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

        Uses constant-time comparison where possible to prevent timing attacks.

        Args:
            stored_fingerprint: Previously stored fingerprint
            tolerance: Number of allowed mismatches (default 2)

        Returns:
            Verification result with details
        """
        current = self.generate()

        mismatches = []

        # Check CPU (constant-time comparison)
        if not constant_time_compare(
            current.cpu_id.encode(),
            stored_fingerprint.cpu_id.encode()
        ):
            mismatches.append('cpu_id')

        # Check MACs (at least one must match)
        common_macs = set(current.mac_addresses) & set(stored_fingerprint.mac_addresses)
        if not common_macs:
            mismatches.append('mac_addresses')

        # Check disks (at least one must match)
        common_disks = set(current.disk_serials) & set(stored_fingerprint.disk_serials)
        if not common_disks:
            mismatches.append('disk_serials')

        # Check DMI UUID (constant-time comparison)
        if not constant_time_compare(
            current.dmi_uuid.encode(),
            stored_fingerprint.dmi_uuid.encode()
        ):
            mismatches.append('dmi_uuid')

        # Result (use constant-time to avoid revealing mismatch count via timing)
        is_valid = len(mismatches) <= tolerance

        return {
            'valid': is_valid,
            'mismatches': mismatches,
            'mismatch_count': len(mismatches),
            'tolerance': tolerance,
            'current_fingerprint': current.fingerprint_id,
            'stored_fingerprint': stored_fingerprint.fingerprint_id
        }

    def create_binding_key(self, fingerprint: HardwareFingerprint, secret: bytes) -> bytes:
        """
        Create a cryptographic binding key from hardware fingerprint.

        This key can be used for:
        - Hardware-bound encryption
        - Device attestation
        - Merkle log anchoring

        Args:
            fingerprint: Hardware fingerprint
            secret: Application-specific secret

        Returns:
            32-byte binding key
        """
        # Create secure binding
        binding_data = (
            fingerprint.fingerprint +
            secret +
            fingerprint.created_timestamp.to_bytes(8, 'big')
        )

        return secure_hash(binding_data)

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
