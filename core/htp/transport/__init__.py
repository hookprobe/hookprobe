"""
HTP Transport Layer

Core HookProbe Transport Protocol implementation including:
- htp.py: Base HTP protocol (9 message types, UDP 4719)
- htp_file.py: File transfer CRUD extension
- htp_vpn.py: VPN tunnel implementation

Full Documentation: docs/architecture/HOOKPROBE-ARCHITECTURE.md
"""

from .htp_file import (
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
    DEFAULT_CHUNK_SIZE,
    MAX_FILE_SIZE,
    TRANSFER_TIMEOUT,
    MAX_CONCURRENT_TRANSFERS,
)

__all__ = [
    # File Transfer Classes
    'HTPFileTransfer',
    'HTPFileServer',

    # Enums
    'FileOperation',
    'FileFlags',
    'FileErrorCode',

    # Data Structures
    'FileTransferHeader',
    'FileMetadata',
    'DirectoryEntry',
    'TransferState',

    # Exceptions
    'HTPFileError',
    'IntegrityError',
    'TransferError',

    # Constants
    'DEFAULT_CHUNK_SIZE',
    'MAX_FILE_SIZE',
    'TRANSFER_TIMEOUT',
    'MAX_CONCURRENT_TRANSFERS',
]
