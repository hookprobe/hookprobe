#!/usr/bin/env python3
"""
HTP File Transfer Extension for HookProbe Transport Protocol

Version: 1.0-Liberty
Author: HookProbe Team
License: MIT

This module extends HTP with CRUD file operations while maintaining
all security properties of the Neuro Protocol:
- Weight-bound session encryption (ChaCha20-Poly1305)
- PoSF authentication (neural network signatures)
- Integrity verification (SHA256 + weight divergence detection)
- NAT/CGNAT traversal (UDP heartbeat)

File Operations:
- CREATE (0x30): Create new file on remote
- READ   (0x31): Retrieve file from remote  
- UPDATE (0x32): Update existing file
- DELETE (0x33): Delete file on remote
- STAT   (0x34): Get file metadata
- LIST   (0x35): List directory contents
- CHUNK  (0x36): File data chunk
- COMPLETE (0x37): Transfer complete signal
- ERROR  (0x38): File operation error

Usage:
    from htp_file import HTPFileTransfer, HTPFileServer
    
    # Client side
    async with HTPFileTransfer(htp_session) as ft:
        await ft.create('/remote/path/file.txt', b'file contents')
        data = await ft.read('/remote/path/file.txt')
        await ft.update('/remote/path/file.txt', b'new contents')
        await ft.delete('/remote/path/file.txt')
    
    # Server side
    server = HTPFileServer(htp_session, base_path='/data')
    await server.handle_requests()
"""

import asyncio
import hashlib
import struct
import os
import time
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Dict, List, Generator, Tuple, Callable, Any
from pathlib import Path
import zlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("htp_file")


# =============================================================================
# CONSTANTS
# =============================================================================

# Chunk size optimized for SBC memory (8KB default, tunable)
DEFAULT_CHUNK_SIZE = 8192

# Maximum file size (1GB default)
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024

# Transfer timeout (5 minutes)
TRANSFER_TIMEOUT = 300

# Maximum concurrent transfers
MAX_CONCURRENT_TRANSFERS = 16

# Header sizes
FILE_HEADER_SIZE = 16  # Additional bytes for file operations
FULL_HEADER_SIZE = 48  # 32 (base HTP) + 16 (file extension)


# =============================================================================
# ENUMS
# =============================================================================

class FileOperation(IntEnum):
    """HTP File Operation codes (0x30-0x38)"""
    CREATE = 0x30
    READ = 0x31
    UPDATE = 0x32
    DELETE = 0x33
    STAT = 0x34
    LIST = 0x35
    CHUNK = 0x36
    COMPLETE = 0x37
    ERROR = 0x38


class FileFlags(IntEnum):
    """File operation flags (bitmask)"""
    NONE = 0x00
    COMPRESSED = 0x01      # Data is zlib compressed
    ENCRYPTED = 0x02       # Data is encrypted (always on in HTP)
    APPEND = 0x04          # Append mode for UPDATE
    CREATE_DIRS = 0x08     # Create parent directories
    OVERWRITE = 0x10       # Overwrite existing file
    RECURSIVE = 0x20       # Recursive for LIST/DELETE
    VERIFY_HASH = 0x40     # Require hash verification
    ATOMIC = 0x80          # Atomic write (write to temp, then rename)


class FileErrorCode(IntEnum):
    """File operation error codes"""
    SUCCESS = 0x00
    NOT_FOUND = 0x01
    PERMISSION_DENIED = 0x02
    ALREADY_EXISTS = 0x03
    INVALID_PATH = 0x04
    TRANSFER_FAILED = 0x05
    HASH_MISMATCH = 0x06
    TIMEOUT = 0x07
    QUOTA_EXCEEDED = 0x08
    IO_ERROR = 0x09
    INVALID_OPERATION = 0x0A
    TRANSFER_CANCELLED = 0x0B
    CHUNK_MISSING = 0x0C
    INTEGRITY_FAILURE = 0x0D


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class FileTransferHeader:
    """
    Extended HTP header for file operations (16 bytes).
    
    Structure:
        file_op     (1 byte):  FileOperation enum
        flags       (1 byte):  FileFlags bitmask
        chunk_index (2 bytes): Current chunk index (0-65535)
        file_id     (4 bytes): Unique transfer ID
        total_chunks(4 bytes): Total chunks in transfer
        file_hash   (4 bytes): First 4 bytes of SHA256 (quick verify)
    """
    file_op: FileOperation
    flags: int
    chunk_index: int
    file_id: int
    total_chunks: int
    file_hash: bytes  # 4 bytes
    
    def pack(self) -> bytes:
        """Pack header to 16 bytes."""
        return struct.pack(
            '<BBHII4s',
            self.file_op,
            self.flags,
            self.chunk_index,
            self.file_id,
            self.total_chunks,
            self.file_hash[:4].ljust(4, b'\x00')
        )
    
    @classmethod
    def unpack(cls, data: bytes) -> 'FileTransferHeader':
        """Unpack 16 bytes to header."""
        if len(data) < 16:
            raise ValueError(f"Header too short: {len(data)} < 16")
        
        file_op, flags, chunk_index, file_id, total_chunks, file_hash = struct.unpack(
            '<BBHII4s', data[:16]
        )
        
        return cls(
            file_op=FileOperation(file_op),
            flags=flags,
            chunk_index=chunk_index,
            file_id=file_id,
            total_chunks=total_chunks,
            file_hash=file_hash
        )


@dataclass
class FileMetadata:
    """File metadata returned by STAT operation."""
    path: str
    size: int
    hash_sha256: bytes
    mtime: int          # Unix timestamp (microseconds)
    ctime: int          # Creation time
    permissions: int    # Unix permissions
    is_directory: bool
    
    def pack(self) -> bytes:
        """Pack metadata for transmission."""
        path_bytes = self.path.encode('utf-8')
        return struct.pack(
            '<H',  # path length
            len(path_bytes)
        ) + path_bytes + struct.pack(
            '<Q32sQQI?',
            self.size,
            self.hash_sha256,
            self.mtime,
            self.ctime,
            self.permissions,
            self.is_directory
        )
    
    @classmethod
    def unpack(cls, data: bytes) -> 'FileMetadata':
        """Unpack metadata from transmission."""
        path_len = struct.unpack('<H', data[:2])[0]
        path = data[2:2+path_len].decode('utf-8')
        offset = 2 + path_len
        
        size, hash_sha256, mtime, ctime, permissions, is_directory = struct.unpack(
            '<Q32sQQI?',
            data[offset:offset+61]
        )
        
        return cls(
            path=path,
            size=size,
            hash_sha256=hash_sha256,
            mtime=mtime,
            ctime=ctime,
            permissions=permissions,
            is_directory=is_directory
        )


@dataclass
class DirectoryEntry:
    """Single entry in directory listing."""
    name: str
    is_directory: bool
    size: int
    mtime: int
    
    def pack(self) -> bytes:
        """Pack entry for transmission."""
        name_bytes = self.name.encode('utf-8')
        return struct.pack('<H', len(name_bytes)) + name_bytes + struct.pack(
            '<? Q Q',
            self.is_directory,
            self.size,
            self.mtime
        )
    
    @classmethod
    def unpack(cls, data: bytes, offset: int = 0) -> Tuple['DirectoryEntry', int]:
        """Unpack entry, return (entry, bytes_consumed)."""
        name_len = struct.unpack('<H', data[offset:offset+2])[0]
        name = data[offset+2:offset+2+name_len].decode('utf-8')
        offset += 2 + name_len
        
        is_directory, size, mtime = struct.unpack('<? Q Q', data[offset:offset+17])
        
        return cls(
            name=name,
            is_directory=is_directory,
            size=size,
            mtime=mtime
        ), offset + 17


@dataclass
class TransferState:
    """Track state of an ongoing transfer."""
    file_id: int
    path: str
    operation: FileOperation
    total_size: int
    total_chunks: int
    received_chunks: Dict[int, bytes] = field(default_factory=dict)
    expected_hash: bytes = b''
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    
    @property
    def is_complete(self) -> bool:
        return len(self.received_chunks) == self.total_chunks
    
    @property
    def progress(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        return len(self.received_chunks) / self.total_chunks
    
    @property
    def is_expired(self) -> bool:
        return time.time() - self.last_activity > TRANSFER_TIMEOUT
    
    def get_data(self) -> bytes:
        """Reassemble chunks into complete data."""
        if not self.is_complete:
            raise ValueError("Transfer not complete")
        return b''.join(
            self.received_chunks[i] 
            for i in range(self.total_chunks)
        )


# =============================================================================
# EXCEPTIONS
# =============================================================================

class HTPFileError(Exception):
    """Base exception for HTP file operations."""
    def __init__(self, code: FileErrorCode, message: str):
        self.code = code
        self.message = message
        super().__init__(f"[{code.name}] {message}")


class IntegrityError(HTPFileError):
    """File integrity verification failed."""
    def __init__(self, message: str):
        super().__init__(FileErrorCode.INTEGRITY_FAILURE, message)


class TransferError(HTPFileError):
    """File transfer failed."""
    def __init__(self, message: str):
        super().__init__(FileErrorCode.TRANSFER_FAILED, message)


# =============================================================================
# HTP FILE TRANSFER CLIENT
# =============================================================================

class HTPFileTransfer:
    """
    File transfer client for HookProbe Transport Protocol.
    
    Provides CRUD operations over HTP while maintaining all security
    properties of the Neuro Protocol:
    - Weight-bound session encryption
    - PoSF authentication
    - Integrity verification
    - NAT/CGNAT traversal
    
    Usage:
        async with HTPFileTransfer(htp_session) as ft:
            await ft.create('/path/file.txt', b'content')
            data = await ft.read('/path/file.txt')
    """
    
    def __init__(
        self,
        htp_session: Any,  # HookProbeTransport instance
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        compress: bool = False,
        verify_hash: bool = True
    ):
        """
        Initialize file transfer client.
        
        Args:
            htp_session: Active HTP session (must be authenticated)
            chunk_size: Size of file chunks (default 8KB)
            compress: Enable zlib compression
            verify_hash: Verify SHA256 hash on completion
        """
        self.htp = htp_session
        self.chunk_size = chunk_size
        self.compress = compress
        self.verify_hash = verify_hash
        self.file_id_counter = 0
        self.pending_transfers: Dict[int, TransferState] = {}
        self._lock = asyncio.Lock()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Cancel any pending transfers
        for transfer in self.pending_transfers.values():
            await self._send_error(
                transfer.file_id,
                FileErrorCode.TRANSFER_CANCELLED,
                "Session closed"
            )
        self.pending_transfers.clear()
    
    # =========================================================================
    # CRUD OPERATIONS
    # =========================================================================
    
    async def create(
        self,
        remote_path: str,
        data: bytes,
        create_dirs: bool = True,
        overwrite: bool = False
    ) -> bool:
        """
        Create a new file on remote peer.
        
        CRUD: CREATE
        
        Args:
            remote_path: Destination path on remote
            data: File contents
            create_dirs: Create parent directories if needed
            overwrite: Overwrite existing file
            
        Returns:
            True if successful
            
        Raises:
            HTPFileError: On failure
        """
        logger.info(f"CREATE: {remote_path} ({len(data)} bytes)")
        
        # Validate
        if len(data) > MAX_FILE_SIZE:
            raise HTPFileError(
                FileErrorCode.QUOTA_EXCEEDED,
                f"File too large: {len(data)} > {MAX_FILE_SIZE}"
            )
        
        # Prepare data
        file_data = data
        if self.compress:
            file_data = zlib.compress(data, level=6)
            logger.debug(f"Compressed: {len(data)} -> {len(file_data)} bytes")
        
        # Calculate metadata
        file_id = self._next_file_id()
        total_chunks = (len(file_data) + self.chunk_size - 1) // self.chunk_size
        file_hash = hashlib.sha256(data).digest()  # Hash of original data
        
        # Build flags
        flags = FileFlags.ENCRYPTED
        if self.compress:
            flags |= FileFlags.COMPRESSED
        if create_dirs:
            flags |= FileFlags.CREATE_DIRS
        if overwrite:
            flags |= FileFlags.OVERWRITE
        if self.verify_hash:
            flags |= FileFlags.VERIFY_HASH
        
        # Send CREATE request
        header = FileTransferHeader(
            file_op=FileOperation.CREATE,
            flags=flags,
            chunk_index=0,
            file_id=file_id,
            total_chunks=total_chunks,
            file_hash=file_hash[:4]
        )
        
        payload = self._build_create_payload(header, remote_path, len(data), file_hash)
        await self._send_packet(header, payload)
        
        # Wait for ACK
        response = await self._receive_response(file_id)
        if response.get('error'):
            raise HTPFileError(
                FileErrorCode(response['error_code']),
                response.get('message', 'Create failed')
            )
        
        # Send chunks
        for chunk_index, chunk in enumerate(self._chunk_data(file_data)):
            await self._send_chunk(file_id, chunk_index, total_chunks, chunk)
            
            # Brief yield to allow other tasks
            if chunk_index % 10 == 0:
                await asyncio.sleep(0)
        
        # Send COMPLETE
        await self._send_complete(file_id, file_hash)
        
        # Wait for final verification
        final_response = await self._receive_response(file_id)
        if final_response.get('error'):
            raise HTPFileError(
                FileErrorCode(final_response['error_code']),
                final_response.get('message', 'Transfer verification failed')
            )
        
        logger.info(f"CREATE complete: {remote_path}")
        return True
    
    async def read(self, remote_path: str) -> bytes:
        """
        Read a file from remote peer.
        
        CRUD: RETRIEVE
        
        Args:
            remote_path: Path to file on remote
            
        Returns:
            File contents as bytes
            
        Raises:
            HTPFileError: On failure
        """
        logger.info(f"READ: {remote_path}")
        
        file_id = self._next_file_id()
        
        # Build flags
        flags = FileFlags.ENCRYPTED
        if self.verify_hash:
            flags |= FileFlags.VERIFY_HASH
        
        # Send READ request
        header = FileTransferHeader(
            file_op=FileOperation.READ,
            flags=flags,
            chunk_index=0,
            file_id=file_id,
            total_chunks=0,
            file_hash=b'\x00\x00\x00\x00'
        )
        
        payload = self._build_path_payload(remote_path)
        await self._send_packet(header, payload)
        
        # Receive metadata response
        meta_response = await self._receive_response(file_id)
        if meta_response.get('error'):
            raise HTPFileError(
                FileErrorCode(meta_response['error_code']),
                meta_response.get('message', 'Read failed')
            )
        
        total_chunks = meta_response['total_chunks']
        expected_hash = meta_response['file_hash']
        is_compressed = meta_response.get('compressed', False)
        
        # Create transfer state
        transfer = TransferState(
            file_id=file_id,
            path=remote_path,
            operation=FileOperation.READ,
            total_size=meta_response['size'],
            total_chunks=total_chunks,
            expected_hash=expected_hash
        )
        self.pending_transfers[file_id] = transfer
        
        # Receive chunks
        while not transfer.is_complete:
            if transfer.is_expired:
                del self.pending_transfers[file_id]
                raise HTPFileError(FileErrorCode.TIMEOUT, "Transfer timeout")
            
            chunk_response = await self._receive_response(file_id)
            if chunk_response.get('error'):
                del self.pending_transfers[file_id]
                raise HTPFileError(
                    FileErrorCode(chunk_response['error_code']),
                    chunk_response.get('message', 'Chunk receive failed')
                )
            
            chunk_index = chunk_response['chunk_index']
            chunk_data = chunk_response['data']
            transfer.received_chunks[chunk_index] = chunk_data
            transfer.last_activity = time.time()
        
        # Reassemble data
        file_data = transfer.get_data()
        del self.pending_transfers[file_id]
        
        # Decompress if needed
        if is_compressed:
            file_data = zlib.decompress(file_data)
        
        # Verify hash
        if self.verify_hash:
            actual_hash = hashlib.sha256(file_data).digest()
            if actual_hash != expected_hash:
                raise IntegrityError(
                    f"Hash mismatch: expected {expected_hash.hex()[:16]}..., "
                    f"got {actual_hash.hex()[:16]}..."
                )
        
        logger.info(f"READ complete: {remote_path} ({len(file_data)} bytes)")
        return file_data
    
    async def update(
        self,
        remote_path: str,
        data: bytes,
        append: bool = False,
        atomic: bool = True
    ) -> bool:
        """
        Update an existing file on remote peer.
        
        CRUD: UPDATE
        
        Args:
            remote_path: Path to file on remote
            data: New file contents (or data to append)
            append: Append to existing file instead of replace
            atomic: Use atomic write (write to temp, then rename)
            
        Returns:
            True if successful
            
        Raises:
            HTPFileError: On failure
        """
        logger.info(f"UPDATE: {remote_path} ({len(data)} bytes, append={append})")
        
        # Prepare data
        file_data = data
        if self.compress:
            file_data = zlib.compress(data, level=6)
        
        file_id = self._next_file_id()
        total_chunks = (len(file_data) + self.chunk_size - 1) // self.chunk_size
        file_hash = hashlib.sha256(data).digest()
        
        # Build flags
        flags = FileFlags.ENCRYPTED
        if self.compress:
            flags |= FileFlags.COMPRESSED
        if append:
            flags |= FileFlags.APPEND
        if atomic:
            flags |= FileFlags.ATOMIC
        if self.verify_hash:
            flags |= FileFlags.VERIFY_HASH
        
        # Send UPDATE request
        header = FileTransferHeader(
            file_op=FileOperation.UPDATE,
            flags=flags,
            chunk_index=0,
            file_id=file_id,
            total_chunks=total_chunks,
            file_hash=file_hash[:4]
        )
        
        payload = self._build_create_payload(header, remote_path, len(data), file_hash)
        await self._send_packet(header, payload)
        
        # Wait for ACK
        response = await self._receive_response(file_id)
        if response.get('error'):
            raise HTPFileError(
                FileErrorCode(response['error_code']),
                response.get('message', 'Update failed')
            )
        
        # Send chunks
        for chunk_index, chunk in enumerate(self._chunk_data(file_data)):
            await self._send_chunk(file_id, chunk_index, total_chunks, chunk)
        
        # Send COMPLETE
        await self._send_complete(file_id, file_hash)
        
        # Wait for final verification
        final_response = await self._receive_response(file_id)
        if final_response.get('error'):
            raise HTPFileError(
                FileErrorCode(final_response['error_code']),
                final_response.get('message', 'Update verification failed')
            )
        
        logger.info(f"UPDATE complete: {remote_path}")
        return True
    
    async def delete(self, remote_path: str, recursive: bool = False) -> bool:
        """
        Delete a file or directory on remote peer.
        
        CRUD: DELETE
        
        Args:
            remote_path: Path to delete
            recursive: Recursively delete directories
            
        Returns:
            True if successful
            
        Raises:
            HTPFileError: On failure
        """
        logger.info(f"DELETE: {remote_path} (recursive={recursive})")
        
        file_id = self._next_file_id()
        
        flags = FileFlags.ENCRYPTED
        if recursive:
            flags |= FileFlags.RECURSIVE
        
        header = FileTransferHeader(
            file_op=FileOperation.DELETE,
            flags=flags,
            chunk_index=0,
            file_id=file_id,
            total_chunks=0,
            file_hash=b'\x00\x00\x00\x00'
        )
        
        payload = self._build_path_payload(remote_path)
        await self._send_packet(header, payload)
        
        response = await self._receive_response(file_id)
        if response.get('error'):
            raise HTPFileError(
                FileErrorCode(response['error_code']),
                response.get('message', 'Delete failed')
            )
        
        logger.info(f"DELETE complete: {remote_path}")
        return True
    
    async def stat(self, remote_path: str) -> FileMetadata:
        """
        Get file metadata from remote peer.
        
        Args:
            remote_path: Path to file/directory
            
        Returns:
            FileMetadata object
            
        Raises:
            HTPFileError: On failure
        """
        logger.info(f"STAT: {remote_path}")
        
        file_id = self._next_file_id()
        
        header = FileTransferHeader(
            file_op=FileOperation.STAT,
            flags=FileFlags.ENCRYPTED,
            chunk_index=0,
            file_id=file_id,
            total_chunks=0,
            file_hash=b'\x00\x00\x00\x00'
        )
        
        payload = self._build_path_payload(remote_path)
        await self._send_packet(header, payload)
        
        response = await self._receive_response(file_id)
        if response.get('error'):
            raise HTPFileError(
                FileErrorCode(response['error_code']),
                response.get('message', 'Stat failed')
            )
        
        return FileMetadata(
            path=remote_path,
            size=response['size'],
            hash_sha256=response['hash'],
            mtime=response['mtime'],
            ctime=response['ctime'],
            permissions=response['permissions'],
            is_directory=response['is_directory']
        )
    
    async def list(self, remote_path: str, recursive: bool = False) -> List[DirectoryEntry]:
        """
        List directory contents on remote peer.
        
        Args:
            remote_path: Path to directory
            recursive: Include subdirectories recursively
            
        Returns:
            List of DirectoryEntry objects
            
        Raises:
            HTPFileError: On failure
        """
        logger.info(f"LIST: {remote_path} (recursive={recursive})")
        
        file_id = self._next_file_id()
        
        flags = FileFlags.ENCRYPTED
        if recursive:
            flags |= FileFlags.RECURSIVE
        
        header = FileTransferHeader(
            file_op=FileOperation.LIST,
            flags=flags,
            chunk_index=0,
            file_id=file_id,
            total_chunks=0,
            file_hash=b'\x00\x00\x00\x00'
        )
        
        payload = self._build_path_payload(remote_path)
        await self._send_packet(header, payload)
        
        response = await self._receive_response(file_id)
        if response.get('error'):
            raise HTPFileError(
                FileErrorCode(response['error_code']),
                response.get('message', 'List failed')
            )
        
        return response.get('entries', [])
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _next_file_id(self) -> int:
        """Generate unique file ID."""
        self.file_id_counter = (self.file_id_counter + 1) % (2**32)
        return self.file_id_counter
    
    def _chunk_data(self, data: bytes) -> Generator[bytes, None, None]:
        """Split data into chunks."""
        for i in range(0, len(data), self.chunk_size):
            yield data[i:i + self.chunk_size]
    
    def _build_create_payload(
        self,
        header: FileTransferHeader,
        path: str,
        original_size: int,
        full_hash: bytes
    ) -> bytes:
        """Build payload for CREATE/UPDATE operations."""
        path_bytes = path.encode('utf-8')
        return struct.pack(
            '<HQI',
            len(path_bytes),
            original_size,
            header.total_chunks
        ) + path_bytes + full_hash
    
    def _build_path_payload(self, path: str) -> bytes:
        """Build payload containing just a path."""
        path_bytes = path.encode('utf-8')
        return struct.pack('<H', len(path_bytes)) + path_bytes
    
    async def _send_packet(self, header: FileTransferHeader, payload: bytes):
        """Send packet over HTP session."""
        packet = header.pack() + payload
        
        # Use HTP's built-in encryption and send
        # The HTP session handles ChaCha20-Poly1305 encryption
        await self.htp.send_data({
            'type': 'file_transfer',
            'header': header.pack().hex(),
            'payload': payload.hex()
        })
    
    async def _send_chunk(
        self,
        file_id: int,
        chunk_index: int,
        total_chunks: int,
        data: bytes
    ):
        """Send a single data chunk."""
        header = FileTransferHeader(
            file_op=FileOperation.CHUNK,
            flags=FileFlags.ENCRYPTED,
            chunk_index=chunk_index,
            file_id=file_id,
            total_chunks=total_chunks,
            file_hash=b'\x00\x00\x00\x00'
        )
        
        await self.htp.send_data({
            'type': 'file_chunk',
            'header': header.pack().hex(),
            'data': data.hex()
        })
    
    async def _send_complete(self, file_id: int, full_hash: bytes):
        """Send transfer complete signal."""
        header = FileTransferHeader(
            file_op=FileOperation.COMPLETE,
            flags=FileFlags.ENCRYPTED | FileFlags.VERIFY_HASH,
            chunk_index=0,
            file_id=file_id,
            total_chunks=0,
            file_hash=full_hash[:4]
        )
        
        await self.htp.send_data({
            'type': 'file_complete',
            'header': header.pack().hex(),
            'full_hash': full_hash.hex()
        })
    
    async def _send_error(self, file_id: int, code: FileErrorCode, message: str):
        """Send error response."""
        header = FileTransferHeader(
            file_op=FileOperation.ERROR,
            flags=FileFlags.ENCRYPTED,
            chunk_index=0,
            file_id=file_id,
            total_chunks=0,
            file_hash=b'\x00\x00\x00\x00'
        )
        
        message_bytes = message.encode('utf-8')[:255]
        payload = struct.pack('<BB', code, len(message_bytes)) + message_bytes
        
        await self.htp.send_data({
            'type': 'file_error',
            'header': header.pack().hex(),
            'payload': payload.hex()
        })
    
    async def _receive_response(self, file_id: int, timeout: float = 30.0) -> dict:
        """Receive response for a specific file_id."""
        try:
            response = await asyncio.wait_for(
                self.htp.receive_data(),
                timeout=timeout
            )
            return response
        except asyncio.TimeoutError:
            raise HTPFileError(FileErrorCode.TIMEOUT, "Response timeout")


# =============================================================================
# HTP FILE TRANSFER SERVER
# =============================================================================

class HTPFileServer:
    """
    File transfer server for HookProbe Transport Protocol.
    
    Handles incoming file operations from remote HTP clients.
    Implements security checks and path validation.
    
    Usage:
        server = HTPFileServer(htp_session, base_path='/data/files')
        await server.handle_requests()
    """
    
    def __init__(
        self,
        htp_session: Any,
        base_path: str,
        allowed_extensions: Optional[List[str]] = None,
        max_file_size: int = MAX_FILE_SIZE,
        read_only: bool = False
    ):
        """
        Initialize file server.
        
        Args:
            htp_session: Active HTP session
            base_path: Root directory for file operations
            allowed_extensions: List of allowed file extensions (None = all)
            max_file_size: Maximum file size in bytes
            read_only: Only allow read operations
        """
        self.htp = htp_session
        self.base_path = Path(base_path).resolve()
        self.allowed_extensions = allowed_extensions
        self.max_file_size = max_file_size
        self.read_only = read_only
        self.active_transfers: Dict[int, TransferState] = {}
        
        # Ensure base path exists
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    async def handle_requests(self):
        """Main request handling loop."""
        logger.info(f"HTP File Server started: {self.base_path}")
        
        while True:
            try:
                request = await self.htp.receive_data()
                await self._handle_request(request)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Request handling error: {e}")
    
    async def _handle_request(self, request: dict):
        """Route request to appropriate handler."""
        req_type = request.get('type', '')
        
        if req_type == 'file_transfer':
            header = FileTransferHeader.unpack(bytes.fromhex(request['header']))
            payload = bytes.fromhex(request['payload'])
            
            handlers = {
                FileOperation.CREATE: self._handle_create,
                FileOperation.READ: self._handle_read,
                FileOperation.UPDATE: self._handle_update,
                FileOperation.DELETE: self._handle_delete,
                FileOperation.STAT: self._handle_stat,
                FileOperation.LIST: self._handle_list,
            }
            
            handler = handlers.get(header.file_op)
            if handler:
                await handler(header, payload)
            else:
                await self._send_error(
                    header.file_id,
                    FileErrorCode.INVALID_OPERATION,
                    f"Unknown operation: {header.file_op}"
                )
        
        elif req_type == 'file_chunk':
            await self._handle_chunk(request)
        
        elif req_type == 'file_complete':
            await self._handle_complete(request)
    
    def _validate_path(self, path: str) -> Path:
        """
        Validate and resolve path within base_path.
        
        Prevents path traversal attacks.
        """
        # Remove leading slashes and resolve
        clean_path = path.lstrip('/')
        full_path = (self.base_path / clean_path).resolve()
        
        # Ensure path is within base_path
        try:
            full_path.relative_to(self.base_path)
        except ValueError:
            raise HTPFileError(
                FileErrorCode.INVALID_PATH,
                f"Path traversal attempt: {path}"
            )
        
        return full_path
    
    def _check_extension(self, path: Path):
        """Check if file extension is allowed."""
        if self.allowed_extensions is None:
            return
        
        ext = path.suffix.lower()
        if ext not in self.allowed_extensions:
            raise HTPFileError(
                FileErrorCode.PERMISSION_DENIED,
                f"Extension not allowed: {ext}"
            )
    
    async def _handle_create(self, header: FileTransferHeader, payload: bytes):
        """Handle CREATE operation."""
        if self.read_only:
            await self._send_error(
                header.file_id,
                FileErrorCode.PERMISSION_DENIED,
                "Server is read-only"
            )
            return
        
        # Parse payload
        path_len, original_size, total_chunks = struct.unpack('<HQI', payload[:14])
        path = payload[14:14+path_len].decode('utf-8')
        full_hash = payload[14+path_len:14+path_len+32]
        
        try:
            full_path = self._validate_path(path)
            self._check_extension(full_path)
            
            # Check size limit
            if original_size > self.max_file_size:
                await self._send_error(
                    header.file_id,
                    FileErrorCode.QUOTA_EXCEEDED,
                    f"File too large: {original_size}"
                )
                return
            
            # Check if exists and overwrite not set
            if full_path.exists() and not (header.flags & FileFlags.OVERWRITE):
                await self._send_error(
                    header.file_id,
                    FileErrorCode.ALREADY_EXISTS,
                    f"File exists: {path}"
                )
                return
            
            # Create parent directories if requested
            if header.flags & FileFlags.CREATE_DIRS:
                full_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Initialize transfer state
            self.active_transfers[header.file_id] = TransferState(
                file_id=header.file_id,
                path=str(full_path),
                operation=FileOperation.CREATE,
                total_size=original_size,
                total_chunks=total_chunks,
                expected_hash=full_hash
            )
            
            # Send ACK
            await self.htp.send_data({
                'file_id': header.file_id,
                'ready': True
            })
            
        except HTPFileError as e:
            await self._send_error(header.file_id, e.code, e.message)
    
    async def _handle_read(self, header: FileTransferHeader, payload: bytes):
        """Handle READ operation."""
        path_len = struct.unpack('<H', payload[:2])[0]
        path = payload[2:2+path_len].decode('utf-8')
        
        try:
            full_path = self._validate_path(path)
            
            if not full_path.exists():
                await self._send_error(
                    header.file_id,
                    FileErrorCode.NOT_FOUND,
                    f"File not found: {path}"
                )
                return
            
            if full_path.is_dir():
                await self._send_error(
                    header.file_id,
                    FileErrorCode.INVALID_PATH,
                    f"Path is directory: {path}"
                )
                return
            
            # Read file
            data = full_path.read_bytes()
            file_hash = hashlib.sha256(data).digest()
            
            # Compress if beneficial
            compressed = zlib.compress(data, level=6)
            use_compression = len(compressed) < len(data) * 0.9
            
            if use_compression:
                send_data = compressed
            else:
                send_data = data
            
            chunk_size = DEFAULT_CHUNK_SIZE
            total_chunks = (len(send_data) + chunk_size - 1) // chunk_size
            
            # Send metadata response
            await self.htp.send_data({
                'file_id': header.file_id,
                'size': len(data),
                'total_chunks': total_chunks,
                'file_hash': file_hash,
                'compressed': use_compression
            })
            
            # Send chunks
            for i in range(0, len(send_data), chunk_size):
                chunk_index = i // chunk_size
                chunk_data = send_data[i:i+chunk_size]
                
                await self.htp.send_data({
                    'file_id': header.file_id,
                    'chunk_index': chunk_index,
                    'data': chunk_data
                })
            
        except HTPFileError as e:
            await self._send_error(header.file_id, e.code, e.message)
        except Exception as e:
            await self._send_error(
                header.file_id,
                FileErrorCode.IO_ERROR,
                str(e)
            )
    
    async def _handle_update(self, header: FileTransferHeader, payload: bytes):
        """Handle UPDATE operation."""
        if self.read_only:
            await self._send_error(
                header.file_id,
                FileErrorCode.PERMISSION_DENIED,
                "Server is read-only"
            )
            return
        
        # Parse payload (same as CREATE)
        path_len, original_size, total_chunks = struct.unpack('<HQI', payload[:14])
        path = payload[14:14+path_len].decode('utf-8')
        full_hash = payload[14+path_len:14+path_len+32]
        
        try:
            full_path = self._validate_path(path)
            self._check_extension(full_path)
            
            # For UPDATE, file must exist (unless CREATE_DIRS is set)
            if not full_path.exists() and not (header.flags & FileFlags.CREATE_DIRS):
                await self._send_error(
                    header.file_id,
                    FileErrorCode.NOT_FOUND,
                    f"File not found: {path}"
                )
                return
            
            # Initialize transfer state
            transfer = TransferState(
                file_id=header.file_id,
                path=str(full_path),
                operation=FileOperation.UPDATE,
                total_size=original_size,
                total_chunks=total_chunks,
                expected_hash=full_hash
            )
            
            # Store append flag
            transfer.append_mode = bool(header.flags & FileFlags.APPEND)
            transfer.atomic = bool(header.flags & FileFlags.ATOMIC)
            
            self.active_transfers[header.file_id] = transfer
            
            # Send ACK
            await self.htp.send_data({
                'file_id': header.file_id,
                'ready': True
            })
            
        except HTPFileError as e:
            await self._send_error(header.file_id, e.code, e.message)
    
    async def _handle_delete(self, header: FileTransferHeader, payload: bytes):
        """Handle DELETE operation."""
        if self.read_only:
            await self._send_error(
                header.file_id,
                FileErrorCode.PERMISSION_DENIED,
                "Server is read-only"
            )
            return
        
        path_len = struct.unpack('<H', payload[:2])[0]
        path = payload[2:2+path_len].decode('utf-8')
        
        try:
            full_path = self._validate_path(path)
            
            if not full_path.exists():
                await self._send_error(
                    header.file_id,
                    FileErrorCode.NOT_FOUND,
                    f"Not found: {path}"
                )
                return
            
            if full_path.is_dir():
                if header.flags & FileFlags.RECURSIVE:
                    import shutil
                    shutil.rmtree(full_path)
                else:
                    full_path.rmdir()  # Will fail if not empty
            else:
                full_path.unlink()
            
            await self.htp.send_data({
                'file_id': header.file_id,
                'deleted': True
            })
            
        except HTPFileError as e:
            await self._send_error(header.file_id, e.code, e.message)
        except OSError as e:
            await self._send_error(
                header.file_id,
                FileErrorCode.IO_ERROR,
                str(e)
            )
    
    async def _handle_stat(self, header: FileTransferHeader, payload: bytes):
        """Handle STAT operation."""
        path_len = struct.unpack('<H', payload[:2])[0]
        path = payload[2:2+path_len].decode('utf-8')
        
        try:
            full_path = self._validate_path(path)
            
            if not full_path.exists():
                await self._send_error(
                    header.file_id,
                    FileErrorCode.NOT_FOUND,
                    f"Not found: {path}"
                )
                return
            
            stat = full_path.stat()
            
            if full_path.is_file():
                file_hash = hashlib.sha256(full_path.read_bytes()).digest()
            else:
                file_hash = b'\x00' * 32
            
            await self.htp.send_data({
                'file_id': header.file_id,
                'size': stat.st_size,
                'hash': file_hash,
                'mtime': int(stat.st_mtime * 1_000_000),
                'ctime': int(stat.st_ctime * 1_000_000),
                'permissions': stat.st_mode,
                'is_directory': full_path.is_dir()
            })
            
        except HTPFileError as e:
            await self._send_error(header.file_id, e.code, e.message)
    
    async def _handle_list(self, header: FileTransferHeader, payload: bytes):
        """Handle LIST operation."""
        path_len = struct.unpack('<H', payload[:2])[0]
        path = payload[2:2+path_len].decode('utf-8')
        
        try:
            full_path = self._validate_path(path)
            
            if not full_path.exists():
                await self._send_error(
                    header.file_id,
                    FileErrorCode.NOT_FOUND,
                    f"Not found: {path}"
                )
                return
            
            if not full_path.is_dir():
                await self._send_error(
                    header.file_id,
                    FileErrorCode.INVALID_PATH,
                    f"Not a directory: {path}"
                )
                return
            
            entries = []
            
            if header.flags & FileFlags.RECURSIVE:
                for item in full_path.rglob('*'):
                    rel_path = item.relative_to(full_path)
                    stat = item.stat()
                    entries.append(DirectoryEntry(
                        name=str(rel_path),
                        is_directory=item.is_dir(),
                        size=stat.st_size if item.is_file() else 0,
                        mtime=int(stat.st_mtime * 1_000_000)
                    ))
            else:
                for item in full_path.iterdir():
                    stat = item.stat()
                    entries.append(DirectoryEntry(
                        name=item.name,
                        is_directory=item.is_dir(),
                        size=stat.st_size if item.is_file() else 0,
                        mtime=int(stat.st_mtime * 1_000_000)
                    ))
            
            await self.htp.send_data({
                'file_id': header.file_id,
                'entries': entries
            })
            
        except HTPFileError as e:
            await self._send_error(header.file_id, e.code, e.message)
    
    async def _handle_chunk(self, request: dict):
        """Handle incoming chunk."""
        header = FileTransferHeader.unpack(bytes.fromhex(request['header']))
        chunk_data = bytes.fromhex(request['data'])
        
        transfer = self.active_transfers.get(header.file_id)
        if not transfer:
            await self._send_error(
                header.file_id,
                FileErrorCode.INVALID_OPERATION,
                "Unknown transfer"
            )
            return
        
        transfer.received_chunks[header.chunk_index] = chunk_data
        transfer.last_activity = time.time()
    
    async def _handle_complete(self, request: dict):
        """Handle transfer complete."""
        header = FileTransferHeader.unpack(bytes.fromhex(request['header']))
        full_hash = bytes.fromhex(request['full_hash'])
        
        transfer = self.active_transfers.get(header.file_id)
        if not transfer:
            await self._send_error(
                header.file_id,
                FileErrorCode.INVALID_OPERATION,
                "Unknown transfer"
            )
            return
        
        try:
            # Check all chunks received
            if not transfer.is_complete:
                missing = [
                    i for i in range(transfer.total_chunks)
                    if i not in transfer.received_chunks
                ]
                await self._send_error(
                    header.file_id,
                    FileErrorCode.CHUNK_MISSING,
                    f"Missing chunks: {missing[:10]}"
                )
                return
            
            # Reassemble data
            file_data = transfer.get_data()
            
            # Decompress if needed (check if first bytes are zlib header)
            if file_data[:2] == b'\x78\x9c':  # zlib default compression
                file_data = zlib.decompress(file_data)
            
            # Verify hash
            actual_hash = hashlib.sha256(file_data).digest()
            if actual_hash != full_hash:
                await self._send_error(
                    header.file_id,
                    FileErrorCode.HASH_MISMATCH,
                    f"Hash mismatch"
                )
                return
            
            # Write file
            path = Path(transfer.path)
            
            if hasattr(transfer, 'atomic') and transfer.atomic:
                # Atomic write
                temp_path = path.with_suffix('.tmp')
                if hasattr(transfer, 'append_mode') and transfer.append_mode:
                    temp_path.write_bytes(path.read_bytes() + file_data)
                else:
                    temp_path.write_bytes(file_data)
                temp_path.rename(path)
            else:
                if hasattr(transfer, 'append_mode') and transfer.append_mode:
                    with open(path, 'ab') as f:
                        f.write(file_data)
                else:
                    path.write_bytes(file_data)
            
            # Cleanup
            del self.active_transfers[header.file_id]
            
            await self.htp.send_data({
                'file_id': header.file_id,
                'verified': True,
                'size': len(file_data)
            })
            
            logger.info(f"Transfer complete: {transfer.path} ({len(file_data)} bytes)")
            
        except Exception as e:
            await self._send_error(
                header.file_id,
                FileErrorCode.IO_ERROR,
                str(e)
            )
    
    async def _send_error(self, file_id: int, code: FileErrorCode, message: str):
        """Send error response."""
        logger.warning(f"File error [{code.name}]: {message}")
        await self.htp.send_data({
            'file_id': file_id,
            'error': True,
            'error_code': code,
            'message': message
        })


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

async def transfer_file(
    htp_session: Any,
    local_path: str,
    remote_path: str,
    direction: str = 'upload'
) -> bool:
    """
    Simple file transfer utility.
    
    Args:
        htp_session: Active HTP session
        local_path: Local file path
        remote_path: Remote file path
        direction: 'upload' or 'download'
        
    Returns:
        True if successful
    """
    async with HTPFileTransfer(htp_session) as ft:
        if direction == 'upload':
            with open(local_path, 'rb') as f:
                data = f.read()
            return await ft.create(remote_path, data)
        else:
            data = await ft.read(remote_path)
            with open(local_path, 'wb') as f:
                f.write(data)
            return True


async def sync_directory(
    htp_session: Any,
    local_dir: str,
    remote_dir: str,
    direction: str = 'upload'
) -> Dict[str, bool]:
    """
    Sync a directory over HTP.
    
    Args:
        htp_session: Active HTP session
        local_dir: Local directory path
        remote_dir: Remote directory path
        direction: 'upload' or 'download'
        
    Returns:
        Dict mapping file paths to success status
    """
    results = {}
    local_path = Path(local_dir)
    
    async with HTPFileTransfer(htp_session) as ft:
        if direction == 'upload':
            for file_path in local_path.rglob('*'):
                if file_path.is_file():
                    rel_path = file_path.relative_to(local_path)
                    remote_path = f"{remote_dir}/{rel_path}"
                    try:
                        with open(file_path, 'rb') as f:
                            data = f.read()
                        await ft.create(remote_path, data, create_dirs=True)
                        results[str(rel_path)] = True
                    except Exception as e:
                        logger.error(f"Failed to upload {rel_path}: {e}")
                        results[str(rel_path)] = False
        else:
            entries = await ft.list(remote_dir, recursive=True)
            for entry in entries:
                if not entry.is_directory:
                    remote_path = f"{remote_dir}/{entry.name}"
                    local_file = local_path / entry.name
                    try:
                        local_file.parent.mkdir(parents=True, exist_ok=True)
                        data = await ft.read(remote_path)
                        local_file.write_bytes(data)
                        results[entry.name] = True
                    except Exception as e:
                        logger.error(f"Failed to download {entry.name}: {e}")
                        results[entry.name] = False
    
    return results


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    import sys
    
    print("=" * 70)
    print("HTP FILE TRANSFER MODULE")
    print("HookProbe Transport Protocol - File Operations Extension")
    print("=" * 70)
    print()
    print("This module extends HTP with CRUD file operations:")
    print()
    print("  CREATE (0x30) - Create new file on remote")
    print("  READ   (0x31) - Retrieve file from remote")
    print("  UPDATE (0x32) - Update existing file")
    print("  DELETE (0x33) - Delete file on remote")
    print("  STAT   (0x34) - Get file metadata")
    print("  LIST   (0x35) - List directory contents")
    print()
    print("Security Properties (inherited from HTP):")
    print("  ✓ Weight-bound session encryption (ChaCha20-Poly1305)")
    print("  ✓ PoSF authentication (neural network signatures)")
    print("  ✓ Integrity verification (SHA256 + weight divergence)")
    print("  ✓ NAT/CGNAT traversal (UDP heartbeat)")
    print()
    print("Usage:")
    print("  from htp_file import HTPFileTransfer")
    print()
    print("  async with HTPFileTransfer(htp_session) as ft:")
    print("      await ft.create('/path/file.txt', b'content')")
    print("      data = await ft.read('/path/file.txt')")
    print()
    print("=" * 70)
    
    # Quick self-test of data structures
    print("\nRunning self-tests...")
    
    # Test header packing/unpacking
    header = FileTransferHeader(
        file_op=FileOperation.CREATE,
        flags=FileFlags.ENCRYPTED | FileFlags.COMPRESSED,
        chunk_index=42,
        file_id=12345,
        total_chunks=100,
        file_hash=b'\xde\xad\xbe\xef'
    )
    
    packed = header.pack()
    assert len(packed) == 16, f"Header size wrong: {len(packed)}"
    
    unpacked = FileTransferHeader.unpack(packed)
    assert unpacked.file_op == FileOperation.CREATE
    assert unpacked.flags == (FileFlags.ENCRYPTED | FileFlags.COMPRESSED)
    assert unpacked.chunk_index == 42
    assert unpacked.file_id == 12345
    assert unpacked.total_chunks == 100
    
    print("  ✓ Header pack/unpack: OK")
    
    # Test file metadata
    meta = FileMetadata(
        path="/test/file.txt",
        size=1024,
        hash_sha256=b'\x00' * 32,
        mtime=1700000000000000,
        ctime=1699999999000000,
        permissions=0o644,
        is_directory=False
    )
    
    packed_meta = meta.pack()
    unpacked_meta = FileMetadata.unpack(packed_meta)
    assert unpacked_meta.path == meta.path
    assert unpacked_meta.size == meta.size
    
    print("  ✓ Metadata pack/unpack: OK")
    
    # Test directory entry
    entry = DirectoryEntry(
        name="test.txt",
        is_directory=False,
        size=512,
        mtime=1700000000000000
    )
    
    packed_entry = entry.pack()
    unpacked_entry, consumed = DirectoryEntry.unpack(packed_entry)
    assert unpacked_entry.name == entry.name
    assert unpacked_entry.size == entry.size
    
    print("  ✓ DirectoryEntry pack/unpack: OK")
    
    # Test transfer state
    transfer = TransferState(
        file_id=1,
        path="/test",
        operation=FileOperation.CREATE,
        total_size=1000,
        total_chunks=3
    )
    
    transfer.received_chunks[0] = b'chunk0'
    transfer.received_chunks[1] = b'chunk1'
    transfer.received_chunks[2] = b'chunk2'
    
    assert transfer.is_complete
    assert transfer.get_data() == b'chunk0chunk1chunk2'
    
    print("  ✓ TransferState: OK")
    
    print()
    print("All self-tests passed!")
    print("=" * 70)
