// =============================================================================
// Aegis XDP Program - Kernel-Level Packet Inspection
// =============================================================================
//
// This is the eBPF/XDP program that runs inside the Linux kernel at the
// Express Data Path (pre-network-stack). It intercepts every packet before
// the kernel's TCP/IP stack processes it.
//
// Architecture:
//   NIC -> XDP (this program) -> Ring Buffer -> Napse (userspace)
//                              -> XDP_PASS (packet continues to stack)
//
// Key innovations over Suricata:
//   1. Zero context switches - runs in kernel space
//   2. Zero-copy inspection - views packet in NIC DMA buffer
//   3. Comptime protocol parsers - optimized at build time
//   4. Feature vector extraction - feeds AI directly
//
// Compile target: BPF (bpfel-freestanding-none)
// Loaded via: aegis-loader (userspace)

const std = @import("std");
const ring_buffer = @import("ring_buffer.zig");
const entropy_mod = @import("entropy.zig");

// =============================================================================
// BPF Map Definitions
// =============================================================================

// NOTE: In actual BPF compilation, these would use @import("zbpf") map types.
// This file serves as the reference implementation. The actual BPF binary
// is compiled from this source targeting bpfel.

/// BPF ring buffer for Aegis -> Napse feature vector communication.
/// Capacity: 16MB (configurable via aegis.toml)
pub const RING_BUF_SIZE: u32 = 16 * 1024 * 1024;

/// Protocol statistics (per-CPU array for lock-free counting).
pub const ProtoIndex = enum(u32) {
    tcp = 0,
    udp = 1,
    icmp = 2,
    other = 3,
};
pub const PROTO_MAX: u32 = 4;

/// Port category statistics.
pub const PortIndex = enum(u32) {
    http = 0,
    https = 1,
    dns = 2,
    ssh = 3,
    vpn = 4,
    htp = 5,
    smtp = 6,
    other = 7,
};
pub const PORT_MAX: u32 = 8;

/// Rate tracking window (1 second in nanoseconds).
pub const RATE_WINDOW_NS: u64 = 1_000_000_000;

// =============================================================================
// Packet Parsing Structures
// =============================================================================

pub const EthHeader = extern struct {
    h_dest: [6]u8,
    h_source: [6]u8,
    h_proto: u16, // Network byte order
};

pub const IPv4Header = extern struct {
    ver_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,

    pub fn ihl(self: *const IPv4Header) u8 {
        return (self.ver_ihl & 0x0F) * 4;
    }
};

pub const TCPHeader = extern struct {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,

    pub fn flags(self: *const TCPHeader) u8 {
        return @truncate(std.mem.nativeToBig(u16, self.doff_flags));
    }
};

pub const UDPHeader = extern struct {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
};

// =============================================================================
// XDP Program Entry Point
// =============================================================================

/// XDP return actions.
pub const XdpAction = enum(u32) {
    aborted = 0,
    drop = 1,
    pass = 2,
    tx = 3, // Bounce back out same interface
    redirect = 4,
};

/// The main XDP processing function.
/// In BPF context, this is the SEC("xdp") entry point.
///
/// Process flow:
///   1. Parse Ethernet header
///   2. Parse IP header (v4/v6)
///   3. Parse transport header (TCP/UDP/ICMP)
///   4. Calculate Shannon entropy of payload
///   5. Extract 32-dimensional feature vector
///   6. Push feature vector to ring buffer for Napse
///   7. Update per-CPU statistics
///   8. Return XDP_PASS (always - we're passive inspection)
///
pub fn xdpPassiveInspect(
    data: [*]const u8,
    data_end: [*]const u8,
    timestamp: u64,
) struct { action: XdpAction, entry: ?ring_buffer.RingEntry } {
    const pkt_len = @intFromPtr(data_end) - @intFromPtr(data);
    if (pkt_len < @sizeOf(EthHeader)) {
        return .{ .action = .pass, .entry = null };
    }

    // Parse Ethernet
    const eth: *const EthHeader = @ptrCast(@alignCast(data));
    const eth_proto = std.mem.bigToNative(u16, eth.h_proto);

    // Only process IPv4 for now (IPv6 support via comptime extension)
    if (eth_proto != 0x0800) {
        return .{ .action = .pass, .entry = null };
    }

    const ip_start = data + @sizeOf(EthHeader);
    if (@intFromPtr(ip_start) + @sizeOf(IPv4Header) > @intFromPtr(data_end)) {
        return .{ .action = .pass, .entry = null };
    }

    const iph: *const IPv4Header = @ptrCast(@alignCast(ip_start));
    const ip_hdr_len = iph.ihl();

    // Build ring buffer entry
    var entry = ring_buffer.RingEntry{
        .sequence = 0, // Set by ring buffer producer
        .timestamp = timestamp,
        .feature_vector = [_]f32{0.0} ** ring_buffer.FEATURE_DIMS,
        .raw_slice = [_]u8{0} ** ring_buffer.MAX_RAW_SLICE,
        .raw_len = @truncate(@min(pkt_len, ring_buffer.MAX_RAW_SLICE)),
        .src_ip = iph.saddr,
        .dst_ip = iph.daddr,
        .src_port = 0,
        .dst_port = 0,
        .proto = iph.protocol,
        .entropy = 0.0,
        .tcp_flags = 0,
    };

    // Copy raw packet (bounded)
    const copy_len = @min(pkt_len, ring_buffer.MAX_RAW_SLICE);
    @memcpy(entry.raw_slice[0..copy_len], data[0..copy_len]);

    // Parse transport layer
    const transport_start = ip_start + ip_hdr_len;
    if (@intFromPtr(transport_start) < @intFromPtr(data_end)) {
        switch (iph.protocol) {
            6 => { // TCP
                if (@intFromPtr(transport_start) + @sizeOf(TCPHeader) <= @intFromPtr(data_end)) {
                    const tcph: *const TCPHeader = @ptrCast(@alignCast(transport_start));
                    entry.src_port = std.mem.bigToNative(u16, tcph.source);
                    entry.dst_port = std.mem.bigToNative(u16, tcph.dest);
                    entry.tcp_flags = tcph.flags();

                    // Feature vector: TCP flags one-hot
                    entry.feature_vector[4] = if (entry.tcp_flags & 0x02 != 0) 1.0 else 0.0; // SYN
                    entry.feature_vector[5] = if (entry.tcp_flags & 0x10 != 0) 1.0 else 0.0; // ACK
                    entry.feature_vector[6] = if (entry.tcp_flags & 0x01 != 0) 1.0 else 0.0; // FIN
                    entry.feature_vector[7] = if (entry.tcp_flags & 0x04 != 0) 1.0 else 0.0; // RST
                    entry.feature_vector[8] = if (entry.tcp_flags & 0x08 != 0) 1.0 else 0.0; // PSH

                    // Window size (normalized)
                    entry.feature_vector[13] = @as(f32, @floatFromInt(std.mem.bigToNative(u16, tcph.window))) / 65535.0;
                }
            },
            17 => { // UDP
                if (@intFromPtr(transport_start) + @sizeOf(UDPHeader) <= @intFromPtr(data_end)) {
                    const udph: *const UDPHeader = @ptrCast(@alignCast(transport_start));
                    entry.src_port = std.mem.bigToNative(u16, udph.source);
                    entry.dst_port = std.mem.bigToNative(u16, udph.dest);
                }
            },
            else => {},
        }
    }

    // Calculate payload entropy
    const payload_offset = @sizeOf(EthHeader) + ip_hdr_len + transportHeaderLen(iph.protocol);
    if (payload_offset < pkt_len) {
        const payload = data[payload_offset..@min(pkt_len, payload_offset + 256)]; // First 256 bytes
        entry.entropy = entropy_mod.shannonEntropy(payload);
    }

    // Feature vector: common fields
    entry.feature_vector[2] = entropy_mod.normalizeEntropy(entry.entropy);
    entry.feature_vector[3] = @as(f32, @floatFromInt(@min(pkt_len, 1500))) / 1500.0;
    entry.feature_vector[10] = switch (iph.protocol) {
        6 => 0.0,
        17 => 0.33,
        1 => 0.66,
        else => 1.0,
    };
    entry.feature_vector[12] = @as(f32, @floatFromInt(iph.ttl)) / 255.0;
    entry.feature_vector[28] = if (entry.src_port > 1024) 1.0 else 0.0;
    entry.feature_vector[29] = if (entry.dst_port < 1024) 1.0 else 0.0;

    return .{ .action = .pass, .entry = entry };
}

fn transportHeaderLen(proto: u8) usize {
    return switch (proto) {
        6 => @sizeOf(TCPHeader), // TCP (minimum, no options)
        17 => @sizeOf(UDPHeader),
        else => 0,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "XDP program with short packet returns pass" {
    const data = [_]u8{0} ** 10;
    const result = xdpPassiveInspect(&data, @as([*]const u8, &data) + data.len, 0);
    try std.testing.expectEqual(XdpAction.pass, result.action);
    try std.testing.expect(result.entry == null);
}
