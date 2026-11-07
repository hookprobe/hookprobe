/*
 * Phase 27c: Hand-tuned bit-density extension for BloomFilter.
 *
 * Replaces the pure-Python:
 *     set_bits = sum(bin(b).count('1') for b in self._bits)
 * which performs 131,072 iterations + .count() per call (1.5-2ms).
 *
 * This C extension uses __builtin_popcountll() — a single CPU instruction
 * on x86 (POPCNT, since Nehalem 2008) and ARM (CNT, ARMv8). 100x faster.
 *
 * Build:
 *   gcc -O3 -shared -fPIC -o libpopcount.so popcount.c -march=native
 *
 * Load via ctypes from Python:
 *   lib = ctypes.CDLL('./libpopcount.so')
 *   lib.popcount_buffer.restype = ctypes.c_uint64
 *   lib.popcount_buffer.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
 *
 * Author: HookProbe Team
 * License: Proprietary
 * Version: 27.0.0
 */

#include <stdint.h>
#include <stddef.h>

/*
 * Count set bits across a byte buffer.
 * Processes 8 bytes at a time via __builtin_popcountll.
 * Tail bytes processed individually.
 */
uint64_t popcount_buffer(const void *buf, size_t len) {
    if (buf == NULL || len == 0) return 0;
    const uint8_t *p = (const uint8_t *)buf;
    const uint64_t *p64 = (const uint64_t *)buf;
    uint64_t count = 0;
    size_t i;
    size_t n64 = len / 8;
    size_t tail_start = n64 * 8;

    /* Hot loop: 8 bytes per iter via popcntq */
    for (i = 0; i < n64; i++) {
        count += __builtin_popcountll(p64[i]);
    }

    /* Tail (0-7 bytes) */
    for (i = tail_start; i < len; i++) {
        count += __builtin_popcount(p[i]);
    }

    return count;
}

/*
 * Bit density as a normalized float [0.0, 1.0].
 * Equivalent to: popcount_buffer(buf, len) / (len * 8.0)
 */
double bit_density(const void *buf, size_t len) {
    if (len == 0) return 0.0;
    uint64_t bits = popcount_buffer(buf, len);
    return (double)bits / (double)(len * 8);
}

/*
 * Bitwise AND of two buffers in-place: dst[i] &= src[i].
 * Used for fast Bloom filter intersection.
 */
void buffer_and(void *dst, const void *src, size_t len) {
    uint64_t *d64 = (uint64_t *)dst;
    const uint64_t *s64 = (const uint64_t *)src;
    size_t n64 = len / 8;
    size_t i;
    for (i = 0; i < n64; i++) {
        d64[i] &= s64[i];
    }
    uint8_t *d8 = (uint8_t *)dst;
    const uint8_t *s8 = (const uint8_t *)src;
    for (i = n64 * 8; i < len; i++) {
        d8[i] &= s8[i];
    }
}

/*
 * Bitwise OR of two buffers: dst[i] |= src[i].
 * Used for fast Bloom filter union (merge).
 */
void buffer_or(void *dst, const void *src, size_t len) {
    uint64_t *d64 = (uint64_t *)dst;
    const uint64_t *s64 = (const uint64_t *)src;
    size_t n64 = len / 8;
    size_t i;
    for (i = 0; i < n64; i++) {
        d64[i] |= s64[i];
    }
    uint8_t *d8 = (uint8_t *)dst;
    const uint8_t *s8 = (const uint8_t *)src;
    for (i = n64 * 8; i < len; i++) {
        d8[i] |= s8[i];
    }
}
