#!/usr/bin/env python3
"""
BPF Map Operations via raw syscalls (no bpftool dependency)
=============================================================

Provides map enumeration, lookup, update, and dump operations for BPF maps
using the bpf() syscall directly via ctypes. This eliminates the need for
bpftool, which is often unavailable on Oracle/ARM kernels.

Usage:
    from bpf_map_ops import BpfMapOps

    ops = BpfMapOps()
    map_id = ops.find_map_by_name('ip_scores')
    ops.map_update(map_id, key_bytes, value_bytes)
"""

import ctypes
import ctypes.util
import ipaddress
import logging
import os
import platform
import struct
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# BPF syscall numbers by architecture
_BPF_SYSCALL_NR = {
    'aarch64': 280,
    'x86_64': 321,
}

# BPF commands
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_GET_NEXT_KEY = 4
BPF_MAP_GET_NEXT_ID = 12
BPF_MAP_GET_FD_BY_ID = 14
BPF_OBJ_GET_INFO_BY_FD = 15

# BPF map types
BPF_MAP_TYPE_HASH = 1
BPF_MAP_TYPE_ARRAY = 2
BPF_MAP_TYPE_PERCPU_ARRAY = 6
BPF_MAP_TYPE_LRU_HASH = 9
BPF_MAP_TYPE_LPM_TRIE = 11
BPF_MAP_TYPE_RINGBUF = 27

MAP_TYPE_NAMES = {
    1: 'HASH', 2: 'ARRAY', 6: 'PERCPU_ARRAY', 9: 'LRU_HASH',
    11: 'LPM_TRIE', 27: 'RINGBUF',
}

# Update flags
BPF_ANY = 0
BPF_NOEXIST = 1
BPF_EXIST = 2


class BpfMapOps:
    """BPF map operations using raw bpf() syscall."""

    def __init__(self):
        arch = platform.machine()
        self._syscall_nr = _BPF_SYSCALL_NR.get(arch)
        if self._syscall_nr is None:
            raise RuntimeError(f"Unsupported architecture: {arch}")

        self._libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        self._map_cache: Dict[str, int] = {}  # name -> map_id
        self._map_info_cache: Dict[int, dict] = {}  # map_id -> info
        logger.debug(f"BpfMapOps initialized (arch={arch}, syscall={self._syscall_nr})")

    def _bpf(self, cmd: int, attr_bytes: bytes, size: int = 128) -> Tuple[int, int, bytes]:
        """Call bpf() syscall. Returns (ret, errno, raw_output)."""
        buf = ctypes.create_string_buffer(attr_bytes, size)
        ret = self._libc.syscall(self._syscall_nr, cmd, buf, size)
        errno = ctypes.get_errno() if ret < 0 else 0
        return ret, errno, buf.raw

    # ------------------------------------------------------------------
    # Map enumeration
    # ------------------------------------------------------------------

    def enumerate_maps(self) -> List[dict]:
        """Enumerate all BPF maps in the system. Returns list of map info dicts."""
        maps = []
        map_id = 0
        while True:
            attr = struct.pack('I', map_id) + b'\x00' * 124
            ret, errno, raw = self._bpf(BPF_MAP_GET_NEXT_ID, attr)
            if ret < 0:
                break
            next_id = struct.unpack('I', raw[4:8])[0]
            map_id = next_id

            info = self._get_map_info_by_id(next_id)
            if info:
                maps.append(info)

        return maps

    def _get_map_info_by_id(self, map_id: int) -> Optional[dict]:
        """Get map info by map ID."""
        if map_id in self._map_info_cache:
            return self._map_info_cache[map_id]

        # Get FD from ID
        attr = struct.pack('I', map_id) + b'\x00' * 124
        fd_ret, fd_errno, _ = self._bpf(BPF_MAP_GET_FD_BY_ID, attr)
        if fd_ret < 0:
            return None
        fd = fd_ret

        try:
            info = self._get_info_by_fd(fd)
            if info:
                self._map_info_cache[map_id] = info
                # Also cache by name
                if info.get('name'):
                    self._map_cache[info['name']] = map_id
            return info
        finally:
            os.close(fd)

    def _get_info_by_fd(self, fd: int) -> Optional[dict]:
        """Get BPF object info by file descriptor."""
        info_buf = ctypes.create_string_buffer(256)
        info_ptr = ctypes.addressof(info_buf)
        attr = struct.pack('IIQ', fd, 256, info_ptr)
        attr += b'\x00' * (128 - len(attr))

        ret, errno, _ = self._bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
        if ret < 0:
            return None

        raw = info_buf.raw
        # struct bpf_map_info layout:
        # u32 type, u32 id, u32 key_size, u32 value_size, u32 max_entries,
        # u32 map_flags, char name[16], ...
        map_type = struct.unpack('I', raw[0:4])[0]
        mid = struct.unpack('I', raw[4:8])[0]
        key_size = struct.unpack('I', raw[8:12])[0]
        val_size = struct.unpack('I', raw[12:16])[0]
        max_entries = struct.unpack('I', raw[16:20])[0]
        map_flags = struct.unpack('I', raw[20:24])[0]
        name = raw[24:40].split(b'\x00')[0].decode('ascii', errors='replace')

        return {
            'id': mid,
            'type': map_type,
            'type_name': MAP_TYPE_NAMES.get(map_type, f'unknown({map_type})'),
            'name': name,
            'key_size': key_size,
            'value_size': val_size,
            'max_entries': max_entries,
            'flags': map_flags,
        }

    def find_map_by_name(self, name: str) -> Optional[int]:
        """Find BPF map ID by name. Result is cached."""
        if name in self._map_cache:
            return self._map_cache[name]

        # Enumerate all maps to find it
        self.enumerate_maps()
        return self._map_cache.get(name)

    # ------------------------------------------------------------------
    # Map operations
    # ------------------------------------------------------------------

    def _get_map_fd(self, map_id: int) -> int:
        """Get a file descriptor for a map by ID. Caller must close it."""
        attr = struct.pack('I', map_id) + b'\x00' * 124
        fd_ret, fd_errno, _ = self._bpf(BPF_MAP_GET_FD_BY_ID, attr)
        if fd_ret < 0:
            raise OSError(fd_errno, f"BPF_MAP_GET_FD_BY_ID failed for map {map_id}")
        return fd_ret

    def map_update(self, map_id: int, key: bytes, value: bytes,
                   flags: int = BPF_ANY) -> bool:
        """Update a single entry in a BPF map.

        Args:
            map_id: BPF map ID
            key: Key bytes (must match map's key_size)
            value: Value bytes (must match map's value_size)
            flags: BPF_ANY (0), BPF_NOEXIST (1), or BPF_EXIST (2)

        Returns:
            True on success, False on failure
        """
        fd = self._get_map_fd(map_id)
        try:
            key_buf = ctypes.create_string_buffer(key, len(key))
            val_buf = ctypes.create_string_buffer(value, len(value))

            # BPF_MAP_UPDATE_ELEM: { map_fd(u32), pad(u32), key(u64), value(u64), flags(u64) }
            attr = struct.pack('II', fd, 0)  # map_fd + pad
            attr += struct.pack('Q', ctypes.addressof(key_buf))  # key ptr
            attr += struct.pack('Q', ctypes.addressof(val_buf))  # value ptr
            attr += struct.pack('Q', flags)  # flags
            attr += b'\x00' * (128 - len(attr))

            ret, errno, _ = self._bpf(BPF_MAP_UPDATE_ELEM, attr)
            return ret >= 0
        finally:
            os.close(fd)

    def map_lookup(self, map_id: int, key: bytes, value_size: int) -> Optional[bytes]:
        """Lookup a single entry in a BPF map.

        Args:
            map_id: BPF map ID
            key: Key bytes
            value_size: Expected value size in bytes

        Returns:
            Value bytes on success, None if not found
        """
        fd = self._get_map_fd(map_id)
        try:
            key_buf = ctypes.create_string_buffer(key, len(key))
            val_buf = ctypes.create_string_buffer(value_size)

            # BPF_MAP_LOOKUP_ELEM: { map_fd(u32), pad(u32), key(u64), value(u64) }
            attr = struct.pack('II', fd, 0)
            attr += struct.pack('Q', ctypes.addressof(key_buf))
            attr += struct.pack('Q', ctypes.addressof(val_buf))
            attr += b'\x00' * (128 - len(attr))

            ret, errno, _ = self._bpf(BPF_MAP_LOOKUP_ELEM, attr)
            if ret < 0:
                return None
            return val_buf.raw
        finally:
            os.close(fd)

    def map_lookup_percpu(self, map_id: int, key: bytes,
                          value_size: int) -> Optional[List[bytes]]:
        """Lookup a PERCPU map entry, returning per-CPU values.

        For PERCPU_ARRAY and PERCPU_HASH maps, the kernel returns
        value_size_aligned * num_cpus bytes. Each CPU's value is
        aligned to 8 bytes minimum.

        Returns list of per-CPU value bytes, or None if not found.
        """
        ncpus = os.cpu_count() or 1
        aligned_val = max(value_size, 8)
        total_size = aligned_val * ncpus

        fd = self._get_map_fd(map_id)
        try:
            key_buf = ctypes.create_string_buffer(key, len(key))
            val_buf = ctypes.create_string_buffer(total_size)

            attr = struct.pack('II', fd, 0)
            attr += struct.pack('Q', ctypes.addressof(key_buf))
            attr += struct.pack('Q', ctypes.addressof(val_buf))
            attr += b'\x00' * (128 - len(attr))

            ret, errno, _ = self._bpf(BPF_MAP_LOOKUP_ELEM, attr)
            if ret < 0:
                return None

            results = []
            for cpu in range(ncpus):
                offset = cpu * aligned_val
                results.append(val_buf.raw[offset:offset + value_size])
            return results
        finally:
            os.close(fd)

    def read_percpu_u64(self, map_name: str, key_idx: int) -> int:
        """Read a PERCPU_ARRAY u64 value, summed across all CPUs."""
        map_id = self.find_map_by_name(map_name)
        if map_id is None:
            return 0
        key = struct.pack('<I', key_idx)
        per_cpu = self.map_lookup_percpu(map_id, key, 8)
        if not per_cpu:
            return 0
        total = 0
        for cpu_val in per_cpu:
            total += struct.unpack('<Q', cpu_val)[0]
        return total

    def map_delete(self, map_id: int, key: bytes) -> bool:
        """Delete a single entry from a BPF map."""
        fd = self._get_map_fd(map_id)
        try:
            key_buf = ctypes.create_string_buffer(key, len(key))

            # BPF_MAP_DELETE_ELEM: { map_fd(u32), pad(u32), key(u64) }
            attr = struct.pack('II', fd, 0)
            attr += struct.pack('Q', ctypes.addressof(key_buf))
            attr += b'\x00' * (128 - len(attr))

            ret, errno, _ = self._bpf(BPF_MAP_DELETE_ELEM, attr)
            return ret >= 0
        finally:
            os.close(fd)

    def map_get_next_key(self, map_id: int, key: Optional[bytes],
                         key_size: int) -> Optional[bytes]:
        """Get the next key in a BPF map (for iteration).

        Args:
            map_id: BPF map ID
            key: Current key bytes (None to get first key)
            key_size: Size of keys in this map

        Returns:
            Next key bytes, or None if no more keys
        """
        fd = self._get_map_fd(map_id)
        try:
            next_key_buf = ctypes.create_string_buffer(key_size)

            # BPF_MAP_GET_NEXT_KEY: { map_fd(u32), pad(u32), key(u64), next_key(u64) }
            attr = struct.pack('II', fd, 0)
            if key is not None:
                key_buf = ctypes.create_string_buffer(key, len(key))
                attr += struct.pack('Q', ctypes.addressof(key_buf))
            else:
                attr += struct.pack('Q', 0)  # NULL key = get first
            attr += struct.pack('Q', ctypes.addressof(next_key_buf))
            attr += b'\x00' * (128 - len(attr))

            ret, errno, _ = self._bpf(BPF_MAP_GET_NEXT_KEY, attr)
            if ret < 0:
                return None
            return next_key_buf.raw
        finally:
            os.close(fd)

    def map_dump(self, map_id: int) -> List[Tuple[bytes, bytes]]:
        """Dump all entries from a BPF map.

        Returns list of (key, value) byte tuples.
        Note: For PERCPU_ARRAY, value contains all CPUs' data concatenated.
        """
        info = self._get_map_info_by_id(map_id)
        if not info:
            return []

        key_size = info['key_size']
        val_size = info['value_size']
        entries = []

        current_key = None
        while True:
            next_key = self.map_get_next_key(map_id, current_key, key_size)
            if next_key is None:
                break

            value = self.map_lookup(map_id, next_key, val_size)
            if value is not None:
                entries.append((next_key, value))

            current_key = next_key

        return entries

    # ------------------------------------------------------------------
    # High-level helpers
    # ------------------------------------------------------------------

    def update_ip_score(self, map_name: str, ip_str: str,
                        score: int, tags: int) -> bool:
        """Push a score+tags for an IPv4 address to the ip_scores BPF map.

        Key: 4 bytes IPv4 (network byte order)
        Value: struct ip_score_val { u16 score, u8 tags, u8 reserved }
        """
        map_id = self.find_map_by_name(map_name)
        if map_id is None:
            return False

        ip_addr = ipaddress.IPv4Address(ip_str)
        key = ip_addr.packed  # 4 bytes, big-endian (network order)

        # struct ip_score_val in little-endian (aarch64)
        score_clamped = min(max(score, 0), 65535)
        value = struct.pack('<HBB', score_clamped, tags & 0xFF, 0)

        return self.map_update(map_id, key, value)

    def update_lpm_trie(self, map_name: str, cidr: str,
                        value: int = 1) -> bool:
        """Add a CIDR to an LPM_TRIE BPF map.

        Key: 4 bytes prefixlen (LE) + 4 bytes IPv4 addr (network order)
        Value: 1 byte
        """
        map_id = self.find_map_by_name(map_name)
        if map_id is None:
            return False

        net = ipaddress.ip_network(cidr, strict=False)
        # LPM_TRIE key: prefixlen (u32 LE) + addr (network byte order)
        key = struct.pack('<I', net.prefixlen) + net.network_address.packed
        val = struct.pack('B', value & 0xFF)

        return self.map_update(map_id, key, val)

    def update_lpm_trie_batch(self, map_name: str, cidrs,
                              value: int = 1) -> Tuple[int, int]:
        """Add a batch of CIDRs to an LPM_TRIE BPF map.

        Returns (success_count, error_count).
        """
        map_id = self.find_map_by_name(map_name)
        if map_id is None:
            return 0, len(cidrs) if hasattr(cidrs, '__len__') else 0

        # Get FD once, reuse for all updates
        fd = self._get_map_fd(map_id)
        success = 0
        errors = 0

        try:
            for cidr in cidrs:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    key = struct.pack('<I', net.prefixlen) + net.network_address.packed
                    val = struct.pack('B', value & 0xFF)

                    key_buf = ctypes.create_string_buffer(key, len(key))
                    val_buf = ctypes.create_string_buffer(val, len(val))

                    attr = struct.pack('II', fd, 0)
                    attr += struct.pack('Q', ctypes.addressof(key_buf))
                    attr += struct.pack('Q', ctypes.addressof(val_buf))
                    attr += struct.pack('Q', BPF_ANY)
                    attr += b'\x00' * (128 - len(attr))

                    ret, errno, _ = self._bpf(BPF_MAP_UPDATE_ELEM, attr)
                    if ret >= 0:
                        success += 1
                    else:
                        errors += 1
                except Exception:
                    errors += 1
        finally:
            os.close(fd)

        return success, errors

    def update_config(self, map_name: str, key_idx: int, value: int) -> bool:
        """Update a config array entry. Key is u32 index, value is u64."""
        map_id = self.find_map_by_name(map_name)
        if map_id is None:
            return False

        key = struct.pack('<I', key_idx)
        val = struct.pack('<Q', value)
        return self.map_update(map_id, key, val)

    def lookup_lpm_trie(self, map_name: str, ip_str: str) -> bool:
        """Check if an IP matches any entry in an LPM_TRIE map.

        Uses /32 prefix for exact match lookup (LPM does longest prefix match).
        """
        map_id = self.find_map_by_name(map_name)
        if map_id is None:
            return False

        ip_addr = ipaddress.IPv4Address(ip_str)
        # LPM lookup uses /32 key
        key = struct.pack('<I', 32) + ip_addr.packed
        result = self.map_lookup(map_id, key, 1)  # value is 1 byte
        return result is not None


# Singleton instance for convenience
_instance: Optional[BpfMapOps] = None

def get_bpf_ops() -> BpfMapOps:
    """Get singleton BpfMapOps instance."""
    global _instance
    if _instance is None:
        _instance = BpfMapOps()
    return _instance
