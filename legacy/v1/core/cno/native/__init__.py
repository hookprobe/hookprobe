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
_SORT_LIB = os.path.join(_NATIVE_DIR, 'libsynaptic_sort.so')

_lib = None
_sort_lib = None
HAVE_NATIVE_POPCOUNT = False
HAVE_NATIVE_SORT = False

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

try:
    if os.path.exists(_SORT_LIB):
        _sort_lib = ctypes.CDLL(_SORT_LIB)
        _sort_lib.radix_sort_priorities.restype = None
        _sort_lib.radix_sort_priorities.argtypes = [
            ctypes.c_void_p,  # priorities (u8*)
            ctypes.c_void_p,  # indices    (u16*)
            ctypes.c_size_t,  # n
        ]
        HAVE_NATIVE_SORT = True
        logger.info("Native synaptic_sort loaded from %s", _SORT_LIB)
    else:
        logger.info("Native synaptic_sort not built")
except Exception as e:
    logger.warning("Native sort unavailable: %s", e)


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


def sort_events_by_priority(events: list) -> list:
    """Phase 27d: O(n) radix sort on event priority (u8).

    Returns a new list sorted ascending by event.priority.
    Native: ~5µs for 500 events. Python fallback: ~5ms (lambda Timsort).

    The native path moves only u16 indices, not the event objects —
    no ctypes marshaling of Python objects required.
    """
    n = len(events)
    if n == 0:
        return events
    if n > 65535 or not HAVE_NATIVE_SORT or _sort_lib is None:
        # Fallback: Python sort
        return sorted(events, key=lambda e: e.priority)

    # Build a packed u8 priority buffer + ctypes index buffer
    priorities = (ctypes.c_uint8 * n)()
    for i in range(n):
        # Clamp to 0-255 (priorities are typically 0-10)
        p = events[i].priority
        priorities[i] = max(0, min(255, p))

    indices = (ctypes.c_uint16 * n)()
    _sort_lib.radix_sort_priorities(priorities, indices, n)

    return [events[indices[i]] for i in range(n)]
