"""
HookProbe Transport Protocol (HTP)

The trust fabric for the HookProbe federated security mesh.
Provides secure, reliable UDP communication with neural resonance authentication.

Submodules:
- transport: Core HTP protocol, file transfer, VPN
- crypto: ChaCha20-Poly1305, Kyber post-quantum encryption

Full Documentation: docs/architecture/HOOKPROBE-ARCHITECTURE.md
"""

from .transport.htp_file import (
    HTPFileTransfer,
    HTPFileServer,
    FileOperation,
    FileFlags,
    FileErrorCode,
    FileTransferHeader,
    FileMetadata,
    DirectoryEntry,
    TransferState,
    HTPFileError,
    IntegrityError,
    TransferError,
)

__all__ = [
    # File Transfer
    'HTPFileTransfer',
    'HTPFileServer',
    'FileOperation',
    'FileFlags',
    'FileErrorCode',
    'FileTransferHeader',
    'FileMetadata',
    'DirectoryEntry',
    'TransferState',
    'HTPFileError',
    'IntegrityError',
    'TransferError',
]

__version__ = '5.0.0'
