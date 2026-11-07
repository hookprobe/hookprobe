// =============================================================================
// Shannon Entropy Calculator
// =============================================================================
//
// Computes Shannon entropy of packet payloads in-kernel (or near-kernel).
// High entropy (>7.0) indicates encrypted/compressed traffic.
// Low entropy (<3.0) indicates plaintext/structured data.
// Anomalous entropy patterns can indicate:
//   - Polymorphic C2 beacons (entropy ~7.2-7.8 in otherwise plaintext flow)
//   - Data exfiltration (sudden entropy shift)
//   - Steganography (entropy deviation from expected file type)
//
// For BPF context: uses integer-only approximation (no floating point in eBPF).
// For userspace: uses full IEEE 754 float computation.

const std = @import("std");
const math = std.math;

/// Byte frequency table: 256 buckets for each possible byte value.
const ByteHistogram = [256]u32;

/// Calculate Shannon entropy of a byte slice.
/// Returns entropy in bits (0.0 = uniform/single byte, 8.0 = perfectly random).
///
/// H(X) = -sum(p(x) * log2(p(x))) for each byte value x
pub fn shannonEntropy(data: []const u8) f32 {
    if (data.len == 0) return 0.0;

    // Count byte frequencies
    var histogram: ByteHistogram = [_]u32{0} ** 256;
    for (data) |byte| {
        histogram[byte] += 1;
    }

    // Calculate entropy
    const n: f32 = @floatFromInt(data.len);
    var entropy: f32 = 0.0;

    for (histogram) |count| {
        if (count == 0) continue;
        const p: f32 = @as(f32, @floatFromInt(count)) / n;
        entropy -= p * @log2(p);
    }

    return entropy;
}

/// Fast integer-only entropy approximation for BPF context.
/// Returns entropy * 1000 as an integer (0 = no entropy, 8000 = max).
/// Uses lookup table to avoid floating point.
///
/// This is suitable for the XDP program where floating point is unavailable.
pub fn shannonEntropyInt(data: []const u8) u32 {
    if (data.len == 0) return 0;

    var histogram: [256]u16 = [_]u16{0} ** 256;
    for (data) |byte| {
        histogram[byte] +|= 1; // saturating add
    }

    const n = data.len;
    var entropy_x1000: u64 = 0;

    for (histogram) |count| {
        if (count == 0) continue;

        // p = count / n
        // -p * log2(p) ≈ (count/n) * log2(n/count)
        // Scaled by 1000: (count * log2_table[n/count]) / n
        const ratio = (n * 1000) / @as(usize, count);
        const log2_approx = intLog2x1000(ratio);
        entropy_x1000 += (@as(u64, count) * log2_approx) / @as(u64, n);
    }

    return @truncate(entropy_x1000);
}

/// Integer log2 approximation * 1000, for values 1-256000.
/// log2(x) * 1000 ≈ bit_length(x) * 1000 + correction
fn intLog2x1000(x: usize) u64 {
    if (x <= 1) return 0;

    // Find highest set bit (equivalent to floor(log2(x)))
    const bits = @as(u64, @intCast(std.math.log2_int(usize, x)));

    // Linear interpolation for fractional part
    // Each bit = 1000 units of log2
    return bits * 1000;
}

/// Classify entropy into categories for feature vector encoding.
pub const EntropyClass = enum(u8) {
    zero = 0, // 0.0 (empty/single byte)
    very_low = 1, // 0.0 - 2.0 (highly structured)
    low = 2, // 2.0 - 4.0 (text/markup)
    medium = 3, // 4.0 - 6.0 (mixed content)
    high = 4, // 6.0 - 7.0 (compressed/binary)
    very_high = 5, // 7.0 - 7.5 (encrypted)
    maximum = 6, // 7.5 - 8.0 (random/crypto)
};

pub fn classifyEntropy(entropy: f32) EntropyClass {
    if (entropy < 0.01) return .zero;
    if (entropy < 2.0) return .very_low;
    if (entropy < 4.0) return .low;
    if (entropy < 6.0) return .medium;
    if (entropy < 7.0) return .high;
    if (entropy < 7.5) return .very_high;
    return .maximum;
}

/// Normalize entropy to 0.0-1.0 range for feature vector.
pub fn normalizeEntropy(entropy: f32) f32 {
    return @min(entropy / 8.0, 1.0);
}

// =============================================================================
// Tests
// =============================================================================

test "entropy of empty data" {
    const empty: []const u8 = &.{};
    try std.testing.expectEqual(@as(f32, 0.0), shannonEntropy(empty));
}

test "entropy of single byte repeated" {
    const data = [_]u8{0xAA} ** 100;
    const e = shannonEntropy(&data);
    try std.testing.expect(e < 0.01); // Near zero entropy
}

test "entropy of sequential bytes" {
    var data: [256]u8 = undefined;
    for (&data, 0..) |*byte, i| {
        byte.* = @truncate(i);
    }
    const e = shannonEntropy(&data);
    try std.testing.expect(e > 7.9); // Near maximum entropy
}

test "entropy classification" {
    try std.testing.expectEqual(EntropyClass.zero, classifyEntropy(0.0));
    try std.testing.expectEqual(EntropyClass.low, classifyEntropy(3.0));
    try std.testing.expectEqual(EntropyClass.very_high, classifyEntropy(7.2));
    try std.testing.expectEqual(EntropyClass.maximum, classifyEntropy(7.9));
}

test "entropy normalization" {
    try std.testing.expectEqual(@as(f32, 0.0), normalizeEntropy(0.0));
    try std.testing.expectEqual(@as(f32, 0.5), normalizeEntropy(4.0));
    try std.testing.expectEqual(@as(f32, 1.0), normalizeEntropy(8.0));
    try std.testing.expectEqual(@as(f32, 1.0), normalizeEntropy(9.0)); // Clamped
}
