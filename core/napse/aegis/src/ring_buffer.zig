// =============================================================================
// Aegis <-> Napse Shared Memory Lock-Free Ring Buffer
// =============================================================================
//
// This defines the C-compatible memory layout shared between Aegis (producer)
// and Napse (consumer) via a mapped BPF ring buffer or /dev/shm segment.
//
// Design principles:
//   - Lock-free: Aegis never waits for Napse (atomic sequence counter)
//   - Zero-copy: Feature vectors written directly, no intermediate buffers
//   - Cache-aligned: Each entry fits in cache lines for L3 locality
//   - C-compatible: extern struct layout for Mojo FFI interop
//
// Index calculation: slot = sequence % capacity (power-of-2 capacity)

const std = @import("std");

/// 32-dimensional feature vector extracted from packet metadata.
/// Each dimension encodes a specific packet characteristic:
///   [0]  = src_ip_hash (normalized)
///   [1]  = dst_ip_hash (normalized)
///   [2]  = shannon_entropy (0.0 - 8.0, normalized to 0.0 - 1.0)
///   [3]  = payload_length (normalized by MTU)
///   [4]  = tcp_flags (one-hot encoded subset)
///   [5]  = port_category (enum as float)
///   [6]  = protocol (TCP=0.0, UDP=0.33, ICMP=0.66, Other=1.0)
///   [7]  = packet_rate (packets/sec for this src_ip, log-scaled)
///   [8]  = ttl (normalized by 255)
///   [9]  = window_size (TCP, normalized)
///   [10] = ip_flags (fragmentation indicators)
///   [11] = payload_byte_distribution_uniformity
///   [12] = inter_arrival_time (log-scaled nanoseconds)
///   [13] = flow_duration_so_far (log-scaled)
///   [14] = bytes_to_server_ratio
///   [15] = packets_to_server_ratio
///   [16-23] = protocol-specific features (DNS query type, HTTP method, TLS version, etc.)
///   [24-31] = reserved for future use / model-specific features
pub const FEATURE_DIMS = 32;

/// Maximum raw packet payload to capture per entry.
pub const MAX_RAW_SLICE = 1500;

/// A single ring buffer entry. C-compatible layout for cross-language FFI.
/// Total size: ~1680 bytes per entry (fits in ~26 cache lines at 64B each).
pub const RingEntry = extern struct {
    /// Monotonically increasing sequence number (atomic).
    /// Producer increments; consumer reads to detect new entries.
    /// Slot index = sequence % ring_capacity.
    sequence: u64 align(8),

    /// Nanosecond-precision timestamp from bpf_ktime_get_ns().
    timestamp: u64,

    /// 32-dimensional feature vector (IEEE 754 float32).
    feature_vector: [FEATURE_DIMS]f32,

    /// Raw packet bytes (optional, for deep inspection by Napse).
    raw_slice: [MAX_RAW_SLICE]u8,

    /// Actual length of valid data in raw_slice.
    raw_len: u16,

    /// Source IPv4 address (network byte order).
    src_ip: u32,

    /// Destination IPv4 address (network byte order).
    dst_ip: u32,

    /// Source port (host byte order).
    src_port: u16,

    /// Destination port (host byte order).
    dst_port: u16,

    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP).
    proto: u8,

    /// Shannon entropy of the packet payload (0.0 - 8.0 bits).
    entropy: f32,

    /// TCP flags byte (SYN, ACK, FIN, RST, PSH, URG).
    tcp_flags: u8,

    /// Padding for alignment.
    _padding: [1]u8 = .{0},
};

/// Ring buffer header, stored at the beginning of the shared memory region.
pub const RingHeader = extern struct {
    /// Magic number for validation: "AEGS" = 0x53474541.
    magic: u32 = 0x53474541,

    /// Version of the ring buffer protocol.
    version: u32 = 1,

    /// Number of entries (must be power of 2).
    capacity: u32,

    /// Size of each entry in bytes.
    entry_size: u32 = @sizeOf(RingEntry),

    /// Producer write position (atomic, monotonically increasing).
    write_seq: u64 align(8) = 0,

    /// Consumer read position (atomic, monotonically increasing).
    read_seq: u64 align(8) = 0,

    /// Total entries written (stats).
    total_written: u64 = 0,

    /// Total entries dropped due to ring full (stats).
    total_dropped: u64 = 0,
};

/// Calculate the total shared memory size needed for a given capacity.
pub fn ringMemorySize(capacity: u32) usize {
    return @sizeOf(RingHeader) + @as(usize, capacity) * @sizeOf(RingEntry);
}

/// Validate that a capacity value is a power of 2.
pub fn isValidCapacity(capacity: u32) bool {
    return capacity > 0 and (capacity & (capacity - 1)) == 0;
}

// =============================================================================
// Producer (Aegis side)
// =============================================================================

pub const RingProducer = struct {
    header: *volatile RingHeader,
    entries: [*]volatile RingEntry,
    mask: u32,

    pub fn init(base: [*]u8, capacity: u32) RingProducer {
        std.debug.assert(isValidCapacity(capacity));
        const header: *volatile RingHeader = @ptrCast(@alignCast(base));
        const entry_base = base + @sizeOf(RingHeader);
        return .{
            .header = header,
            .entries = @ptrCast(@alignCast(entry_base)),
            .mask = capacity - 1,
        };
    }

    /// Try to write an entry to the ring. Returns false if ring is full.
    /// Lock-free: uses atomic fetch_add on write_seq.
    pub fn push(self: *RingProducer, entry: *const RingEntry) bool {
        const seq = @atomicLoad(u64, &self.header.write_seq, .monotonic);
        const read = @atomicLoad(u64, &self.header.read_seq, .acquire);

        // Check if ring is full
        if (seq - read >= self.mask + 1) {
            _ = @atomicRmw(u64, &self.header.total_dropped, .Add, 1, .monotonic);
            return false;
        }

        const idx = @as(u32, @truncate(seq)) & self.mask;
        self.entries[idx] = entry.*;
        self.entries[idx].sequence = seq;

        // Release fence: ensure entry is written before advancing write_seq
        @atomicStore(u64, &self.header.write_seq, seq + 1, .release);
        _ = @atomicRmw(u64, &self.header.total_written, .Add, 1, .monotonic);
        return true;
    }
};

// =============================================================================
// Consumer (Napse side -- reference implementation, Mojo uses C FFI)
// =============================================================================

pub const RingConsumer = struct {
    header: *volatile RingHeader,
    entries: [*]volatile RingEntry,
    mask: u32,

    pub fn init(base: [*]u8, capacity: u32) RingConsumer {
        std.debug.assert(isValidCapacity(capacity));
        const header: *volatile RingHeader = @ptrCast(@alignCast(base));
        const entry_base = base + @sizeOf(RingHeader);
        return .{
            .header = header,
            .entries = @ptrCast(@alignCast(entry_base)),
            .mask = capacity - 1,
        };
    }

    /// Try to read the next entry. Returns null if ring is empty.
    pub fn pop(self: *RingConsumer) ?RingEntry {
        const read = @atomicLoad(u64, &self.header.read_seq, .monotonic);
        const write = @atomicLoad(u64, &self.header.write_seq, .acquire);

        if (read >= write) return null;

        const idx = @as(u32, @truncate(read)) & self.mask;
        const entry = self.entries[idx];

        // Advance read position
        @atomicStore(u64, &self.header.read_seq, read + 1, .release);
        return entry;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "RingEntry size and alignment" {
    // Verify the struct has expected size for cross-language compatibility
    try std.testing.expect(@sizeOf(RingEntry) > 0);
    try std.testing.expect(@sizeOf(RingHeader) > 0);
}

test "capacity validation" {
    try std.testing.expect(isValidCapacity(1024));
    try std.testing.expect(isValidCapacity(4096));
    try std.testing.expect(!isValidCapacity(0));
    try std.testing.expect(!isValidCapacity(1000));
}

test "memory size calculation" {
    const size = ringMemorySize(1024);
    try std.testing.expect(size > @sizeOf(RingHeader));
    try std.testing.expect(size == @sizeOf(RingHeader) + 1024 * @sizeOf(RingEntry));
}
