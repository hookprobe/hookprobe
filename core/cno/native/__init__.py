"""
Phase 27 native extensions for the CNO.

Currently:
  - popcount: __builtin_popcountll-based bit density for BloomFilter
              (100x faster than Python sum(bin(b).count('1')))
"""
import ctypes
import logging
import os

logger = logging.getLogger(__name__)

_NATIVE_DIR = os.path.dirname(os.path.abspath(__file__))
_POPCOUNT_LIB = os.path.join(_NATIVE_DIR, 'libpopcount.so')

_lib = None
HAVE_NATIVE_POPCOUNT = False

try:
    if os.path.exists(_POPCOUNT_LIB):
        _lib = ctypes.CDLL(_POPCOUNT_LIB)
        _lib.popcount_buffer.restype = ctypes.c_uint64
        _lib.popcount_buffer.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _lib.bit_density.restype = ctypes.c_double
        _lib.bit_density.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _lib.buffer_and.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        _lib.buffer_or.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        HAVE_NATIVE_POPCOUNT = True
        logger.info("Native popcount loaded from %s", _POPCOUNT_LIB)
    else:
        logger.info("Native popcount not built (run `make` in core/cno/native/)")
except Exception as e:
    logger.warning("Native popcount unavailable, falling back to Python: %s", e)


def popcount(buf: bytes) -> int:
    """Count set bits in a byte buffer.

    Uses native __builtin_popcountll() if available (100x faster),
    falls back to Python pure-bit-count otherwise.
    """
    if HAVE_NATIVE_POPCOUNT and _lib:
        return _lib.popcount_buffer(buf, len(buf))
    return sum(bin(b).count('1') for b in buf)


def bit_density(buf: bytes) -> float:
    """Fraction of bits set in a byte buffer (0.0 - 1.0)."""
    if not buf:
        return 0.0
    if HAVE_NATIVE_POPCOUNT and _lib:
        return _lib.bit_density(buf, len(buf))
    bits = popcount(buf)
    return bits / (len(buf) * 8)


def buffer_or_inplace(dst: bytearray, src: bytes) -> None:
    """In-place bitwise OR for Bloom filter merge.

    Native call avoids byte-by-byte Python loop.
    """
    if HAVE_NATIVE_POPCOUNT and _lib and len(dst) == len(src):
        # ctypes from bytearray
        dst_addr = (ctypes.c_uint8 * len(dst)).from_buffer(dst)
        _lib.buffer_or(dst_addr, src, len(dst))
    else:
        for i in range(min(len(dst), len(src))):
            dst[i] |= src[i]
