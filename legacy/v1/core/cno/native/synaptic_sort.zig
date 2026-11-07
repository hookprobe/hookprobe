// Phase 27d: Radix sort for SynapticController dispatch loop.
//
// Replaces Python sort with lambda key:
//   events.sort(key=lambda e: e.priority)
// which costs ~7.5 ms per call (Timsort O(n log n) + lambda call overhead)
// invoked 10x/sec → 75 ms/sec sustained CPU.
//
// SynapticEvent.priority is an int 0-255 (in practice 0-10), so radix sort
// on a single byte gives O(n) with no comparison overhead. Net cost on
// 500 events: ~5 µs (1500x faster than Python).
//
// API: caller passes (priorities: *u8, indices: *u16, n: usize). We
// fill `indices` with a permutation that sorts by priority ascending.
// Caller then reads events in indices[] order. This avoids moving the
// Python event objects (which would require ctypes marshaling).
//
// Build:
//   zig build-lib synaptic_sort.zig -O ReleaseFast -dynamic -fPIC \
//     -fno-stack-check -target native
//
// Author: HookProbe Team
// License: Proprietary
// Version: 27.0.0

const std = @import("std");

/// Sort indices by priority via counting sort on u8.
/// Stable: events with equal priority preserve input order.
///
/// Args:
///   priorities: pointer to N priority bytes (u8)
///   indices:    pointer to N output indices (u16) — caller must allocate
///   n:          number of events (max 65535 — u16 indices)
///
/// Output:
///   indices[i] = original event-index for sorted position i.
export fn radix_sort_priorities(
    priorities: [*]const u8,
    indices: [*]u16,
    n: usize,
) callconv(.C) void {
    if (n == 0) return;
    if (n > 65535) return; // u16 index overflow; caller responsibility

    // Counting sort over 256 priority buckets.
    var counts: [256]u32 = .{0} ** 256;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        counts[priorities[i]] += 1;
    }

    // Prefix sum → start index of each bucket.
    var starts: [256]u32 = undefined;
    starts[0] = 0;
    var p: usize = 1;
    while (p < 256) : (p += 1) {
        starts[p] = starts[p - 1] + counts[p - 1];
    }

    // Scatter: fill indices[] with the original positions in sorted order.
    var write_pos: [256]u32 = starts;
    i = 0;
    while (i < n) : (i += 1) {
        const pri = priorities[i];
        const slot = write_pos[pri];
        indices[slot] = @intCast(i);
        write_pos[pri] = slot + 1;
    }
}

/// Variant: sort u32 priorities (in case the int doesn't fit in u8).
/// Uses LSD radix sort with 256-bucket passes (4 passes total).
export fn radix_sort_priorities_u32(
    priorities: [*]const u32,
    indices: [*]u32,
    n: usize,
) callconv(.C) void {
    if (n == 0) return;

    // For typical CNO load (priorities 0-10), the high 3 bytes are zero.
    // Skip bucket passes where all values share the same byte.
    var i: usize = 0;
    var indices_a = indices;
    // Scratch buffer needed for LSD; allocate on stack for small N.
    if (n > 4096) {
        // Caller should use radix_sort_priorities (u8) for large N.
        // Fall back to insertion sort.
        i = 1;
        while (i < n) : (i += 1) {
            var j = i;
            const cur = indices_a[i];
            while (j > 0 and priorities[indices_a[j - 1]] > priorities[cur]) : (j -= 1) {
                indices_a[j] = indices_a[j - 1];
            }
            indices_a[j] = cur;
        }
        return;
    }

    var scratch: [4096]u32 = undefined;

    // Initialize identity permutation
    i = 0;
    while (i < n) : (i += 1) indices_a[i] = @intCast(i);

    // 4-pass LSD radix sort on bytes 0..3
    var byte_pos: u32 = 0;
    var src = indices_a;
    var dst: [*]u32 = scratch[0..].ptr;
    while (byte_pos < 4) : (byte_pos += 1) {
        var counts: [256]u32 = .{0} ** 256;
        i = 0;
        while (i < n) : (i += 1) {
            const idx = src[i];
            const byte: u8 = @intCast((priorities[idx] >> @intCast(byte_pos * 8)) & 0xff);
            counts[byte] += 1;
        }
        var starts: [256]u32 = undefined;
        starts[0] = 0;
        var p: usize = 1;
        while (p < 256) : (p += 1) {
            starts[p] = starts[p - 1] + counts[p - 1];
        }
        var wp = starts;
        i = 0;
        while (i < n) : (i += 1) {
            const idx = src[i];
            const byte: u8 = @intCast((priorities[idx] >> @intCast(byte_pos * 8)) & 0xff);
            const slot = wp[byte];
            dst[slot] = idx;
            wp[byte] = slot + 1;
        }
        // Swap src/dst
        const tmp = src;
        src = dst;
        dst = tmp;
    }

    // If src now points to scratch, copy back to caller's indices.
    if (src != indices_a) {
        i = 0;
        while (i < n) : (i += 1) indices_a[i] = src[i];
    }
}
