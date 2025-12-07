"""
VPN Certificate Manager

Manages X.509 certificates for IKEv2 EAP-TLS authentication.
Certificates are signed by the Nexus CA and embedded in VPN profiles.
"""

import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Tuple, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from django.conf import settings
from django.contrib.auth.models import User


class CertificateManager:
    """
    Manages VPN certificates for IKEv2 authentication.

    Handles:
    - CA certificate management
    - User certificate issuance
    - Certificate revocation
    - Private key encryption/decryption
    """

    # Certificate validity periods
    USER_CERT_VALIDITY_DAYS = 365
    CA_CERT_VALIDITY_DAYS = 3650  # 10 years

    def __init__(self):
        """Initialize certificate manager."""
        self.ca_key = None
        self.ca_cert = None
        self._load_ca()

        # Key encryption key (should come from secure vault in production)
        self.kek = self._get_key_encryption_key()

    def _get_key_encryption_key(self) -> bytes:
        """
        Get key encryption key for protecting private keys.

        In production, this should come from HSM or secure vault.
        """
        kek_hex = os.getenv('VPN_KEY_ENCRYPTION_KEY', '')
        if kek_hex:
            return bytes.fromhex(kek_hex)

        # Development fallback - generate deterministic key
        # WARNING: Not secure for production
        seed = os.getenv('SECRET_KEY', 'hookprobe-dev-key')
        return hashlib.sha256(f"vpn-kek-{seed}".encode()).digest()

    def _load_ca(self):
        """Load or generate CA certificate."""
        ca_cert_path = os.getenv('VPN_CA_CERT_PATH', '/etc/hookprobe/vpn/ca.crt')
        ca_key_path = os.getenv('VPN_CA_KEY_PATH', '/etc/hookprobe/vpn/ca.key')

        try:
            # Try to load existing CA
            with open(ca_cert_path, 'rb') as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            with open(ca_key_path, 'rb') as f:
                self.ca_key = serialization.load_pem_private_key(
                    f.read(),
                    password=os.getenv('VPN_CA_KEY_PASSWORD', '').encode() or None
                )
        except FileNotFoundError:
            # Generate new CA for development
            self.ca_key, self.ca_cert = self._generate_ca()

    def _generate_ca(self) -> Tuple:
        """
        Generate self-signed CA certificate.

        Returns:
            Tuple of (private_key, certificate)
        """
        # Generate EC key (P-384 for stronger security)
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

        # Build CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HookProbe"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Nexus VPN CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "HookProbe Nexus VPN CA"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=self.CA_CERT_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False
            )
            .sign(private_key, hashes.SHA384())
        )

        return private_key, cert

    def issue_user_certificate(
        self,
        user: User,
        device_name: str = ""
    ) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Issue a new user certificate for VPN authentication.

        Args:
            user: Django user object
            device_name: Optional device identifier

        Returns:
            Tuple of (certificate_pem, public_key_pem, encrypted_private_key, iv)
        """
        # Generate user key pair (ECDSA P-256 for mobile compatibility)
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Build certificate
        cn = user.email or user.username
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HookProbe"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "VPN Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])

        # SAN includes email and optional device identifier
        san_list = [x509.RFC822Name(user.email)] if user.email else []
        if device_name:
            san_list.append(x509.DNSName(f"{device_name}.vpn.hookprobe.local"))

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=self.USER_CERT_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False
            )
        )

        if san_list:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )

        cert = builder.sign(self.ca_key, hashes.SHA256())

        # Serialize certificate and keys
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        public_key_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key_der = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        # Encrypt private key with KEK
        encrypted_key, iv = self._encrypt_private_key(private_key_der)

        return cert_pem, public_key_pem, encrypted_key, iv

    def _encrypt_private_key(self, private_key_der: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt private key with AES-256-GCM.

        Args:
            private_key_der: Private key in DER format

        Returns:
            Tuple of (encrypted_key, iv)
        """
        iv = secrets.token_bytes(12)
        aesgcm = AESGCM(self.kek)
        encrypted = aesgcm.encrypt(iv, private_key_der, None)
        return encrypted, iv

    def decrypt_private_key(self, encrypted_key: bytes, iv: bytes) -> bytes:
        """
        Decrypt private key.

        Args:
            encrypted_key: AES-256-GCM encrypted private key
            iv: Initialization vector

        Returns:
            Decrypted private key in DER format
        """
        aesgcm = AESGCM(self.kek)
        return aesgcm.decrypt(iv, encrypted_key, None)

    def get_ca_certificate_pem(self) -> bytes:
        """Get CA certificate in PEM format."""
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    def get_certificate_fingerprint(self, cert_pem: bytes) -> str:
        """
        Get SHA256 fingerprint of certificate.

        Args:
            cert_pem: Certificate in PEM format

        Returns:
            Hex-encoded SHA256 fingerprint
        """
        cert = x509.load_pem_x509_certificate(cert_pem)
        return cert.fingerprint(hashes.SHA256()).hex()

    def get_serial_number(self, cert_pem: bytes) -> str:
        """
        Get serial number from certificate.

        Args:
            cert_pem: Certificate in PEM format

        Returns:
            Hex-encoded serial number
        """
        cert = x509.load_pem_x509_certificate(cert_pem)
        return format(cert.serial_number, 'x')

    def create_pkcs12(
        self,
        cert_pem: bytes,
        encrypted_private_key: bytes,
        iv: bytes,
        password: Optional[str] = None
    ) -> bytes:
        """
        Create PKCS#12 bundle for certificate import.

        Args:
            cert_pem: User certificate in PEM format
            encrypted_private_key: Encrypted private key
            iv: IV for decryption
            password: Optional password for PKCS#12

        Returns:
            PKCS#12 bundle bytes
        """
        from cryptography.hazmat.primitives.serialization import pkcs12

        # Decrypt private key
        private_key_der = self.decrypt_private_key(encrypted_private_key, iv)

        # Load objects
        cert = x509.load_pem_x509_certificate(cert_pem)
        private_key = serialization.load_der_private_key(private_key_der, None)

        # Create PKCS#12
        p12_password = password.encode() if password else None
        p12 = pkcs12.serialize_key_and_certificates(
            name=b"HookProbe VPN",
            key=private_key,
            cert=cert,
            cas=[self.ca_cert],
            encryption_algorithm=(
                serialization.BestAvailableEncryption(p12_password)
                if p12_password else serialization.NoEncryption()
            )
        )

        return p12
