"""
Device Identity & Root-of-Trust using TPM/Secure Element

Each device has a secure element/TPM that generates an attested device key pair.
DeviceKey is used for signing attestations and is not extractable.

Attestation includes:
- Hardware-signed PCRs/measurements
- Firmware version and hash
- Secure boot state
- Device certificate chain
"""

import hashlib
import struct
from typing import Optional, List, Dict
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    import tpm2_pytss
    TPM_AVAILABLE = True
except ImportError:
    TPM_AVAILABLE = False
    print("WARNING: TPM library not available. Using software fallback (NOT SECURE)")


@dataclass
class DeviceKey:
    """Device key pair backed by TPM/SE (not extractable)."""
    key_id: bytes  # TPM key handle or SE key ID
    public_key: bytes  # Ed25519 public key (32 bytes)
    attestation_cert: bytes  # X.509 certificate from OEM CA


@dataclass
class PCRSnapshot:
    """TPM Platform Configuration Register snapshot."""
    pcr_index: int
    pcr_value: bytes  # SHA256 hash (32 bytes)
    pcr_name: str  # e.g., "BIOS", "Bootloader", "Kernel", "Firmware"


@dataclass
class DeviceAttestation:
    """
    Complete device attestation package.

    Contains cryptographic proof of device state:
    - Device identity (TPM-backed key)
    - Platform measurements (PCRs)
    - Firmware integrity
    - Timestamp and nonce (freshness)
    """
    device_id: str
    device_key_public: bytes  # Ed25519 public key

    # TPM attestation
    pcrs: List[PCRSnapshot]  # Platform measurements
    firmware_version: str
    firmware_hash: bytes  # SHA256 of firmware
    secure_boot_enabled: bool

    # Freshness
    timestamp: int  # Unix timestamp (microseconds)
    nonce: bytes  # Challenge nonce from validator

    # Network fingerprint (optional, privacy-preserving)
    network_fingerprint_hash: Optional[bytes]  # SHA256 of encrypted report

    # Telemetry (ML features, privacy-preserving)
    telemetry_feature_hash: Optional[bytes]  # Hash of feature vector

    # Signature
    signature: bytes  # Ed25519 signature over entire attestation


class DeviceIdentity:
    """
    Device identity manager using TPM/Secure Element.

    Manages device key generation, attestation creation, and signing.
    """

    def __init__(self, device_id: str, use_tpm: bool = True, use_puf: bool = False):
        """
        Args:
            device_id: Unique device identifier
            use_tpm: Use hardware TPM if available
            use_puf: Use PUF-derived identity (hardware-anchored, never stored)
        """
        self.device_id = device_id
        self.use_tpm = use_tpm and TPM_AVAILABLE
        self.use_puf = use_puf
        self.device_key: Optional[DeviceKey] = None
        self._puf_identity = None  # Lazy-loaded CompositeIdentity

        if not self.use_tpm and not self.use_puf:
            print("WARNING: Running in software fallback mode (NOT PRODUCTION SECURE)")

    def provision_device_key(self) -> DeviceKey:
        """
        Provision device key in TPM/SE/PUF (one-time during manufacturing/enrollment).

        Priority: TPM > PUF > Software fallback.

        Returns:
            Device key with public key and attestation certificate
        """
        if self.use_tpm:
            return self._provision_tpm_key()
        elif self.use_puf:
            return self._provision_puf_key()
        else:
            return self._provision_software_key()

    def _provision_puf_key(self) -> DeviceKey:
        """Provision key using PUF-derived identity (never stored)."""
        from core.neuro.puf.composite_identity import (
            CompositeIdentity, PufSource,
        )
        from core.neuro.puf.clock_drift_puf import ClockDriftPuf
        from core.neuro.puf.cache_timing_puf import CacheTimingPuf

        # Build composite identity from available PUF sources
        identity = CompositeIdentity()

        # Clock drift works on all hardware including VMs
        identity.add_source(PufSource.CLOCK_DRIFT, ClockDriftPuf(num_measurements=32))

        # Cache timing is supplementary
        identity.add_source(PufSource.CACHE_TIMING, CacheTimingPuf(iterations=64))

        # Try SRAM PUF (requires /dev/mem access)
        try:
            from core.neuro.puf.sram_puf import SRAMPuf
            sram = SRAMPuf()
            identity.add_source(PufSource.SRAM, sram)
        except Exception:
            pass  # SRAM not available (VM or no /dev/mem)

        # Generate composite response with Ed25519 keypair
        response = identity.generate()
        self._puf_identity = identity

        key_id = hashlib.sha256(f"puf-key-{self.device_id}".encode()).digest()[:16]

        from cryptography.hazmat.primitives.asymmetric import ed25519
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(response.ed25519_seed[:32])
        public_key = private_key.public_key()

        attestation_cert = self._generate_mock_attestation_cert(public_key)

        device_key = DeviceKey(
            key_id=key_id,
            public_key=public_key.public_bytes_raw(),
            attestation_cert=attestation_cert,
        )

        self.device_key = device_key
        self._software_private_key = private_key  # PUF-derived, regenerated each boot
        return device_key

    def _provision_tpm_key(self) -> DeviceKey:
        """Provision key using TPM 2.0."""
        # In production, this would:
        # 1. Create restricted signing key in TPM
        # 2. Make key persistent
        # 3. Get endorsement certificate
        # 4. Request attestation cert from OEM CA

        # Placeholder for TPM key creation
        key_id = hashlib.sha256(f"tpm-key-{self.device_id}".encode()).digest()[:16]

        # Generate Ed25519 key pair in TPM
        # (TPM 2.0 supports Ed25519 via TPM2_Create with proper template)
        from cryptography.hazmat.primitives.asymmetric import ed25519
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # In production: Get real attestation cert from OEM
        attestation_cert = self._generate_mock_attestation_cert(public_key)

        device_key = DeviceKey(
            key_id=key_id,
            public_key=public_key.public_bytes_raw(),
            attestation_cert=attestation_cert
        )

        self.device_key = device_key
        return device_key

    def _provision_software_key(self) -> DeviceKey:
        """Software fallback (NOT SECURE - for testing only)."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        # Deterministic key generation for testing
        seed = hashlib.sha256(f"device-{self.device_id}".encode()).digest()
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        public_key = private_key.public_key()

        key_id = hashlib.sha256(f"sw-key-{self.device_id}".encode()).digest()[:16]
        attestation_cert = self._generate_mock_attestation_cert(public_key)

        device_key = DeviceKey(
            key_id=key_id,
            public_key=public_key.public_bytes_raw(),
            attestation_cert=attestation_cert
        )

        self.device_key = device_key
        self._software_private_key = private_key  # Store for signing

        return device_key

    def create_attestation(
        self,
        challenge_nonce: bytes,
        network_fingerprint: Optional[bytes] = None,
        telemetry_features: Optional[bytes] = None
    ) -> DeviceAttestation:
        """
        Create device attestation with TPM measurements.

        Args:
            challenge_nonce: Fresh nonce from validator (16 bytes)
            network_fingerprint: Optional encrypted network report
            telemetry_features: Optional ML feature vector

        Returns:
            Signed device attestation
        """
        if not self.device_key:
            raise ValueError("Device key not provisioned. Call provision_device_key() first.")

        # Read PCRs from TPM
        pcrs = self._read_pcrs()

        # Get firmware info
        firmware_version, firmware_hash = self._get_firmware_info()

        # Check secure boot status
        secure_boot = self._check_secure_boot()

        # Get timestamp
        timestamp = int(datetime.now(timezone.utc).timestamp() * 1e6)

        # Hash optional privacy-preserving data
        network_fp_hash = hashlib.sha256(network_fingerprint).digest() if network_fingerprint else None
        telemetry_hash = hashlib.sha256(telemetry_features).digest() if telemetry_features else None

        # Build attestation (unsigned)
        attestation = DeviceAttestation(
            device_id=self.device_id,
            device_key_public=self.device_key.public_key,
            pcrs=pcrs,
            firmware_version=firmware_version,
            firmware_hash=firmware_hash,
            secure_boot_enabled=secure_boot,
            timestamp=timestamp,
            nonce=challenge_nonce,
            network_fingerprint_hash=network_fp_hash,
            telemetry_feature_hash=telemetry_hash,
            signature=b''  # Will be filled by signing
        )

        # Sign attestation with device key
        signature = self._sign_attestation(attestation)
        attestation.signature = signature

        return attestation

    def _read_pcrs(self) -> List[PCRSnapshot]:
        """Read Platform Configuration Registers from TPM."""
        if self.use_tpm:
            # In production: Use tpm2_pytss to read actual PCRs
            # Example: TPM2_PCR_Read for PCRs 0-7 (firmware), 8-15 (OS)
            pass

        # Mock PCRs for testing
        mock_pcrs = [
            PCRSnapshot(0, hashlib.sha256(b"BIOS-measurement").digest(), "BIOS"),
            PCRSnapshot(1, hashlib.sha256(b"UEFI-platform-config").digest(), "UEFI Platform"),
            PCRSnapshot(2, hashlib.sha256(b"UEFI-driver-config").digest(), "UEFI Drivers"),
            PCRSnapshot(4, hashlib.sha256(b"bootloader-grub").digest(), "Bootloader"),
            PCRSnapshot(8, hashlib.sha256(b"kernel-cmdline").digest(), "Kernel Command Line"),
            PCRSnapshot(9, hashlib.sha256(b"initrd-hash").digest(), "InitRD"),
        ]

        return mock_pcrs

    def _get_firmware_info(self) -> tuple[str, bytes]:
        """Get firmware version and hash."""
        # In production: Read from /sys/firmware or UEFI variables
        version = "1.0.0"
        firmware_hash = hashlib.sha256(f"firmware-{version}".encode()).digest()
        return version, firmware_hash

    def _check_secure_boot(self) -> bool:
        """Check if Secure Boot is enabled."""
        # In production: Check UEFI Secure Boot status
        # Read from /sys/firmware/efi/efivars/SecureBoot-*
        return True  # Mock: assume enabled

    def _sign_attestation(self, attestation: DeviceAttestation) -> bytes:
        """Sign attestation with device key."""
        # Serialize attestation for signing
        message = self._serialize_attestation_for_signing(attestation)

        if self.use_tpm:
            # In production: Use TPM2_Sign with device key handle
            signature = self._tpm_sign(message)
        else:
            # Software fallback
            signature = self._software_private_key.sign(message)

        return signature

    def _tpm_sign(self, message: bytes) -> bytes:
        """Sign using TPM key."""
        # Placeholder: In production use tpm2_pytss.ESAPI().sign()
        # For now, use software fallback
        from cryptography.hazmat.primitives.asymmetric import ed25519
        seed = hashlib.sha256(f"device-{self.device_id}".encode()).digest()
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        return private_key.sign(message)

    def _serialize_attestation_for_signing(self, attestation: DeviceAttestation) -> bytes:
        """Serialize attestation into canonical byte format for signing."""
        # Build message: device_id || public_key || PCRs || firmware || timestamp || nonce
        message = bytearray()

        message.extend(attestation.device_id.encode('utf-8')[:32].ljust(32, b'\x00'))
        message.extend(attestation.device_key_public)

        # Add PCRs
        for pcr in attestation.pcrs:
            message.extend(struct.pack('<I', pcr.pcr_index))
            message.extend(pcr.pcr_value)

        # Add firmware info
        message.extend(attestation.firmware_version.encode('utf-8')[:32].ljust(32, b'\x00'))
        message.extend(attestation.firmware_hash)
        message.extend(struct.pack('<?', attestation.secure_boot_enabled))

        # Add freshness
        message.extend(struct.pack('<Q', attestation.timestamp))
        message.extend(attestation.nonce)

        # Add optional hashes
        if attestation.network_fingerprint_hash:
            message.extend(attestation.network_fingerprint_hash)
        if attestation.telemetry_feature_hash:
            message.extend(attestation.telemetry_feature_hash)

        return bytes(message)

    def _generate_mock_attestation_cert(self, public_key) -> bytes:
        """Generate mock attestation certificate (OEM CA in production)."""
        # In production: This would be a real X.509 cert from OEM CA
        cert_data = {
            'subject': f'CN=HookProbe-Device-{self.device_id}',
            'issuer': 'CN=HookProbe-OEM-CA',
            'public_key': public_key.public_bytes_raw().hex(),
            'serial': hashlib.sha256(self.device_id.encode()).hexdigest()[:16]
        }

        return str(cert_data).encode('utf-8')


class AttestationVerifier:
    """
    Validator-side attestation verification.

    Verifies device attestation signatures and measurements.
    """

    def __init__(self, trusted_oem_cas: List[bytes]):
        """
        Args:
            trusted_oem_cas: List of trusted OEM CA certificates
        """
        self.trusted_oem_cas = trusted_oem_cas

    def verify_attestation(
        self,
        attestation: DeviceAttestation,
        expected_pcrs: Optional[Dict[int, bytes]] = None
    ) -> Dict[str, any]:
        """
        Verify device attestation.

        Args:
            attestation: Device attestation to verify
            expected_pcrs: Optional expected PCR values (policy enforcement)

        Returns:
            Verification result with details
        """
        result = {
            'valid': False,
            'device_id': attestation.device_id,
            'errors': [],
            'warnings': []
        }

        # 1. Verify signature
        try:
            message = self._reconstruct_signed_message(attestation)
            self._verify_ed25519_signature(
                public_key=attestation.device_key_public,
                message=message,
                signature=attestation.signature
            )
        except Exception as e:
            result['errors'].append(f"Signature verification failed: {e}")
            return result

        # 2. Verify attestation certificate chain (OEM CA)
        # In production: Verify X.509 cert chain to trusted OEM CA
        # For now, assume valid

        # 3. Check nonce freshness (prevent replay)
        # Validator should track used nonces and reject reused ones

        # 4. Verify PCRs against policy (if provided)
        if expected_pcrs:
            for pcr in attestation.pcrs:
                if pcr.pcr_index in expected_pcrs:
                    if pcr.pcr_value != expected_pcrs[pcr.pcr_index]:
                        result['errors'].append(
                            f"PCR {pcr.pcr_index} mismatch: expected {expected_pcrs[pcr.pcr_index].hex()[:16]}..., "
                            f"got {pcr.pcr_value.hex()[:16]}..."
                        )

        # 5. Check secure boot enabled
        if not attestation.secure_boot_enabled:
            result['warnings'].append("Secure Boot disabled")

        # 6. Verify firmware hash (if known-good list available)
        # In production: Check against database of approved firmware

        # If no errors, mark as valid
        if not result['errors']:
            result['valid'] = True

        return result

    def _reconstruct_signed_message(self, attestation: DeviceAttestation) -> bytes:
        """Reconstruct message that was signed."""
        # Must match _serialize_attestation_for_signing exactly
        identity = DeviceIdentity(attestation.device_id, use_tpm=False)
        return identity._serialize_attestation_for_signing(attestation)

    def _verify_ed25519_signature(self, public_key: bytes, message: bytes, signature: bytes):
        """Verify Ed25519 signature."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        public_key_obj.verify(signature, message)  # Raises exception if invalid


# Example usage
if __name__ == '__main__':
    print("=== Device Identity & Attestation Test ===\n")

    # Device enrollment
    device = DeviceIdentity(device_id='edge-001', use_tpm=False)

    print("1. Provisioning device key...")
    device_key = device.provision_device_key()
    print(f"   Device Key ID: {device_key.key_id.hex()[:16]}...")
    print(f"   Public Key: {device_key.public_key.hex()[:32]}...\n")

    # Validator sends challenge
    challenge_nonce = hashlib.sha256(b"validator-challenge-12345").digest()[:16]
    print(f"2. Validator challenge: {challenge_nonce.hex()[:16]}...\n")

    # Device creates attestation
    print("3. Creating attestation...")
    attestation = device.create_attestation(
        challenge_nonce=challenge_nonce,
        telemetry_features=b"cpu:0.5,mem:0.3,net:0.1"
    )
    print(f"   PCRs: {len(attestation.pcrs)} measurements")
    print(f"   Firmware: {attestation.firmware_version}")
    print(f"   Secure Boot: {attestation.secure_boot_enabled}")
    print(f"   Signature: {attestation.signature.hex()[:32]}...\n")

    # Validator verifies attestation
    print("4. Verifying attestation...")
    verifier = AttestationVerifier(trusted_oem_cas=[])
    result = verifier.verify_attestation(attestation)

    print(f"   Valid: {result['valid']}")
    if result['errors']:
        for error in result['errors']:
            print(f"   Error: {error}")
    if result['warnings']:
        for warning in result['warnings']:
            print(f"   Warning: {warning}")

    if result['valid']:
        print("\n✓ Attestation verification PASSED")
    else:
        print("\n✗ Attestation verification FAILED")
