// =============================================================================
// Feature Vector Extraction Engine
// =============================================================================
//
// Extracts a 32-dimensional feature vector from raw packet metadata.
// This vector is the "language" that Aegis speaks to Napse.
//
// Feature dimensions:
//   [0]  src_ip_hash         Normalized hash of source IP
//   [1]  dst_ip_hash         Normalized hash of destination IP
//   [2]  entropy             Shannon entropy (normalized 0-1)
//   [3]  payload_length      Payload bytes / MTU
//   [4]  tcp_syn             SYN flag (0.0 or 1.0)
//   [5]  tcp_ack             ACK flag
//   [6]  tcp_fin             FIN flag
//   [7]  tcp_rst             RST flag
//   [8]  tcp_psh             PSH flag
//   [9]  port_category       Encoded port class (0-7)
//   [10] protocol            TCP=0.0, UDP=0.33, ICMP=0.66, Other=1.0
//   [11] packet_rate         Log-scaled packets/sec for src_ip
//   [12] ttl                 Time-to-live / 255
//   [13] window_size         TCP window / 65535
//   [14] ip_frag             IP fragmentation flag
//   [15] ip_df               Don't Fragment flag
//   [16] payload_uniformity  Byte distribution uniformity score
//   [17] inter_arrival_ns    Log-scaled inter-arrival time
//   [18] dns_query_type      DNS-specific: query type encoded
//   [19] http_method         HTTP-specific: method encoded
//   [20] tls_version         TLS-specific: version encoded
//   [21] tls_cipher_strength TLS cipher strength normalized
//   [22] ssh_version         SSH version encoded
//   [23] quic_version        QUIC version encoded
//   [24] htp_packet_type     HTP protocol packet type
//   [25] bytes_ratio         Bytes-to-server / total-bytes
//   [26] flow_packet_count   Log-scaled packets in flow
//   [27] flow_duration       Log-scaled flow duration
//   [28] src_port_ephemeral  1.0 if src_port > 1024
//   [29] dst_port_well_known 1.0 if dst_port < 1024
//   [30] reserved_0          Reserved for model tuning
//   [31] reserved_1          Reserved for model tuning

const std = @import("std");
const ring_buffer = @import("ring_buffer.zig");
const entropy_mod = @import("entropy.zig");

pub const FEATURE_DIMS = ring_buffer.FEATURE_DIMS;

/// Port category classification for feature encoding.
pub const PortCategory = enum(u8) {
    http = 0, // 80, 8080
    https = 1, // 443, 8443
    dns = 2, // 53
    ssh = 3, // 22
    vpn = 4, // 51820, 1194
    htp = 5, // 4719, 8144, 853, 3478
    smtp = 6, // 25, 465, 587
    other = 7,
};

pub fn classifyPort(port: u16) PortCategory {
    return switch (port) {
        80, 8080 => .http,
        443, 8443 => .https,
        53 => .dns,
        22 => .ssh,
        51820, 1194 => .vpn,
        4719, 8144, 853, 3478 => .htp,
        25, 465, 587 => .smtp,
        else => .other,
    };
}

/// Raw packet metadata input for feature extraction.
pub const PacketMeta = struct {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    tcp_flags: u8,
    ttl: u8,
    window_size: u16,
    ip_flags: u8,
    payload: []const u8,
    packet_rate: f32, // Packets/sec for this src_ip (from rate tracker)
    inter_arrival_ns: u64,
    flow_packets: u64,
    flow_duration_ns: u64,
    flow_bytes_orig: u64,
    flow_bytes_total: u64,
};

/// Extract a 32-dimensional feature vector from packet metadata.
pub fn extractFeatures(meta: *const PacketMeta) [FEATURE_DIMS]f32 {
    var features: [FEATURE_DIMS]f32 = [_]f32{0.0} ** FEATURE_DIMS;

    // [0] src_ip_hash (normalized to 0-1)
    features[0] = @as(f32, @floatFromInt(hashIP(meta.src_ip))) / @as(f32, @floatFromInt(std.math.maxInt(u32)));

    // [1] dst_ip_hash
    features[1] = @as(f32, @floatFromInt(hashIP(meta.dst_ip))) / @as(f32, @floatFromInt(std.math.maxInt(u32)));

    // [2] entropy (normalized)
    features[2] = entropy_mod.normalizeEntropy(entropy_mod.shannonEntropy(meta.payload));

    // [3] payload_length / MTU
    features[3] = @as(f32, @floatFromInt(@min(meta.payload.len, 1500))) / 1500.0;

    // [4-8] TCP flags (one-hot)
    features[4] = if (meta.tcp_flags & 0x02 != 0) 1.0 else 0.0; // SYN
    features[5] = if (meta.tcp_flags & 0x10 != 0) 1.0 else 0.0; // ACK
    features[6] = if (meta.tcp_flags & 0x01 != 0) 1.0 else 0.0; // FIN
    features[7] = if (meta.tcp_flags & 0x04 != 0) 1.0 else 0.0; // RST
    features[8] = if (meta.tcp_flags & 0x08 != 0) 1.0 else 0.0; // PSH

    // [9] port_category
    features[9] = @as(f32, @floatFromInt(@intFromEnum(classifyPort(meta.dst_port)))) / 7.0;

    // [10] protocol
    features[10] = switch (meta.proto) {
        6 => 0.0, // TCP
        17 => 0.33, // UDP
        1 => 0.66, // ICMP
        else => 1.0,
    };

    // [11] packet_rate (log-scaled)
    features[11] = logScale(meta.packet_rate, 10000.0);

    // [12] ttl
    features[12] = @as(f32, @floatFromInt(meta.ttl)) / 255.0;

    // [13] window_size
    features[13] = @as(f32, @floatFromInt(meta.window_size)) / 65535.0;

    // [14] IP fragmentation
    features[14] = if (meta.ip_flags & 0x20 != 0) 1.0 else 0.0; // MF flag

    // [15] Don't Fragment
    features[15] = if (meta.ip_flags & 0x40 != 0) 1.0 else 0.0; // DF flag

    // [16] payload byte uniformity
    features[16] = calculateUniformity(meta.payload);

    // [17] inter-arrival time (log-scaled nanoseconds)
    features[17] = logScale(@as(f32, @floatFromInt(@min(meta.inter_arrival_ns, 10_000_000_000))), 10_000_000_000.0);

    // [25] bytes ratio (orig / total)
    if (meta.flow_bytes_total > 0) {
        features[25] = @as(f32, @floatFromInt(meta.flow_bytes_orig)) / @as(f32, @floatFromInt(meta.flow_bytes_total));
    }

    // [26] flow packet count (log-scaled)
    features[26] = logScale(@as(f32, @floatFromInt(@min(meta.flow_packets, 1_000_000))), 1_000_000.0);

    // [27] flow duration (log-scaled)
    features[27] = logScale(@as(f32, @floatFromInt(@min(meta.flow_duration_ns, 3_600_000_000_000))), 3_600_000_000_000.0);

    // [28] ephemeral source port
    features[28] = if (meta.src_port > 1024) 1.0 else 0.0;

    // [29] well-known destination port
    features[29] = if (meta.dst_port < 1024) 1.0 else 0.0;

    return features;
}

// =============================================================================
// Helpers
// =============================================================================

/// Simple hash for IP address (fnv1a-like).
fn hashIP(ip: u32) u32 {
    var h: u32 = 2166136261;
    const bytes = std.mem.asBytes(&ip);
    for (bytes) |b| {
        h ^= b;
        h *%= 16777619;
    }
    return h;
}

/// Log-scale a value to 0.0-1.0 range.
/// logScale(x, max) = log(1 + x) / log(1 + max)
fn logScale(value: f32, max: f32) f32 {
    if (value <= 0.0) return 0.0;
    return @log(1.0 + value) / @log(1.0 + max);
}

/// Calculate byte distribution uniformity (0.0 = perfectly uniform, 1.0 = single byte).
fn calculateUniformity(data: []const u8) f32 {
    if (data.len < 2) return 0.0;

    var histogram: [256]u32 = [_]u32{0} ** 256;
    for (data) |byte| {
        histogram[byte] += 1;
    }

    // Chi-squared test against uniform distribution
    const expected: f32 = @as(f32, @floatFromInt(data.len)) / 256.0;
    var chi_sq: f32 = 0.0;
    for (histogram) |count| {
        const observed: f32 = @floatFromInt(count);
        const diff = observed - expected;
        chi_sq += (diff * diff) / @max(expected, 0.001);
    }

    // Normalize: 0 = uniform, 1 = concentrated
    return @min(chi_sq / @as(f32, @floatFromInt(data.len)), 1.0);
}

// =============================================================================
// Tests
// =============================================================================

test "port classification" {
    try std.testing.expectEqual(PortCategory.http, classifyPort(80));
    try std.testing.expectEqual(PortCategory.https, classifyPort(443));
    try std.testing.expectEqual(PortCategory.dns, classifyPort(53));
    try std.testing.expectEqual(PortCategory.htp, classifyPort(4719));
    try std.testing.expectEqual(PortCategory.other, classifyPort(12345));
}

test "log scale" {
    try std.testing.expect(logScale(0.0, 100.0) == 0.0);
    try std.testing.expect(logScale(100.0, 100.0) > 0.9);
    try std.testing.expect(logScale(50.0, 100.0) > 0.5);
}
