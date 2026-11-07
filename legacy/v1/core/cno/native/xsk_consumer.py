"""
Phase 27e: Python wrapper for AF_XDP zero-copy consumer.

Usage:
    from core.cno.native.xsk_consumer import XSKConsumer

    with XSKConsumer('dummy-mirror', queue_id=0) as xsk:
        while running:
            frames = xsk.recv(max=64)
            for f in frames:
                process_frame(f)  # f is XSKFrameDesc namedtuple
            xsk.release(frames)

Frame access:
    f.src_ip, f.dst_ip      → IPv4 in network byte order (use socket.ntohl)
    f.src_port, f.dst_port  → ports in network byte order
    f.proto                 → 6=TCP, 17=UDP, 1=ICMP
    f.tcp_flags             → bitfield: FIN/SYN/RST/PSH/ACK/URG
    f.len                   → frame length
    f.addr                  → UMEM offset (for raw packet bytes)

Author: HookProbe Team
License: Proprietary
Version: 27.0.0
"""
import ctypes
import logging
import os
import socket
from collections import namedtuple

logger = logging.getLogger(__name__)

_NATIVE_DIR = os.path.dirname(os.path.abspath(__file__))
_LIB_PATH = os.path.join(_NATIVE_DIR, 'libxsk_consumer.so')

XSKFrameDesc = namedtuple('XSKFrameDesc',
    'addr len src_ip dst_ip src_port dst_port proto tcp_flags')


class _CFrameDesc(ctypes.Structure):
    """Mirrors struct xsk_frame_desc in xsk_consumer.c (32-byte aligned)."""
    _pack_ = 1
    _fields_ = [
        ('addr',      ctypes.c_uint64),
        ('len',       ctypes.c_uint32),
        ('src_ip',    ctypes.c_uint32),
        ('dst_ip',    ctypes.c_uint32),
        ('src_port',  ctypes.c_uint16),
        ('dst_port',  ctypes.c_uint16),
        ('proto',     ctypes.c_uint8),
        ('tcp_flags', ctypes.c_uint8),
        ('_pad',      ctypes.c_uint16),
    ]


_lib = None
HAVE_XSK = False

try:
    if os.path.exists(_LIB_PATH):
        _lib = ctypes.CDLL(_LIB_PATH)
        _lib.xsk_consumer_open.restype = ctypes.c_void_p
        _lib.xsk_consumer_open.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
        _lib.xsk_consumer_recv.restype = ctypes.c_int
        _lib.xsk_consumer_recv.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_CFrameDesc), ctypes.c_int]
        _lib.xsk_consumer_release_frames.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_CFrameDesc), ctypes.c_int]
        _lib.xsk_consumer_get_data.restype = ctypes.c_void_p
        _lib.xsk_consumer_get_data.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64]
        _lib.xsk_consumer_fd.restype = ctypes.c_int
        _lib.xsk_consumer_fd.argtypes = [ctypes.c_void_p]
        _lib.xsk_consumer_close.argtypes = [ctypes.c_void_p]
        HAVE_XSK = True
        logger.info("AF_XDP consumer loaded from %s", _LIB_PATH)
    else:
        logger.info("libxsk_consumer.so not found — AF_XDP unavailable")
except Exception as e:
    logger.warning("AF_XDP consumer failed to load: %s", e)


class XSKConsumer:
    """High-level Python wrapper around the C AF_XDP consumer.

    Designed for batch-mode operation — each .recv() returns a list of
    XSKFrameDesc namedtuples, then .release() returns the UMEM frames
    back to the kernel's fill ring in a single batch syscall.

    Performance contract:
      - 1 syscall (or 0 in busy-poll mode) per batch of up to 64 frames
      - Per-frame Python cost: ~0.5µs (namedtuple construction + 8 ints)
      - Compare to RINGBUF path: 9 copies, ~5µs per event
    """

    def __init__(self, ifname: str, queue_id: int = 0):
        if not HAVE_XSK:
            raise RuntimeError(
                "AF_XDP consumer not available (libxsk_consumer.so missing). "
                "Run `make` in core/cno/native/")
        self.ifname = ifname
        self.queue_id = queue_id
        self._handle = None
        self._batch_buf = (_CFrameDesc * 64)()

    def open(self) -> None:
        handle = _lib.xsk_consumer_open(
            self.ifname.encode('utf-8'), self.queue_id)
        if not handle:
            raise OSError(
                f"AF_XDP open failed on {self.ifname} queue {self.queue_id}. "
                f"Verify XDP program is loaded with xsks_map; check "
                f"CAP_NET_ADMIN; try queue 0.")
        self._handle = handle

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def recv(self, max_frames: int = 64) -> list:
        """Receive up to max_frames packets. Returns list of XSKFrameDesc.

        Returns empty list if no packets ready (non-blocking).
        """
        if max_frames > 64:
            max_frames = 64
        n = _lib.xsk_consumer_recv(self._handle, self._batch_buf, max_frames)
        if n <= 0:
            return []
        out = []
        for i in range(n):
            d = self._batch_buf[i]
            out.append(XSKFrameDesc(
                addr=d.addr, len=d.len,
                src_ip=d.src_ip, dst_ip=d.dst_ip,
                src_port=d.src_port, dst_port=d.dst_port,
                proto=d.proto, tcp_flags=d.tcp_flags,
            ))
        return out

    def release(self, frames: list) -> None:
        """Return frame UMEM addresses to the kernel's FILL ring.

        Caller MUST do this after processing each batch from recv().
        """
        n = len(frames)
        if n == 0:
            return
        # Repopulate the C array with addresses
        for i, f in enumerate(frames[:64]):
            self._batch_buf[i].addr = f.addr
        _lib.xsk_consumer_release_frames(
            self._handle, self._batch_buf, min(n, 64))

    def get_data(self, addr: int, length: int) -> bytes:
        """Read `length` bytes from UMEM offset `addr`.

        Only call if you actually need the packet bytes; otherwise the
        parsed L3/L4 fields in XSKFrameDesc are enough.
        """
        ptr = _lib.xsk_consumer_get_data(self._handle, addr)
        if not ptr:
            return b''
        return ctypes.string_at(ptr, length)

    def fileno(self) -> int:
        """AF_XDP socket fd (for select/poll/epoll)."""
        return _lib.xsk_consumer_fd(self._handle)

    def close(self) -> None:
        if self._handle is not None:
            _lib.xsk_consumer_close(self._handle)
            self._handle = None


def ip_to_str(net_byte_order_ip: int) -> str:
    """Convert network byte order u32 IP to dotted string."""
    return socket.inet_ntoa(net_byte_order_ip.to_bytes(4, 'little'))
