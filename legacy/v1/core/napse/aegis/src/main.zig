// =============================================================================
// Aegis - Adaptive Endpoint Guardian Intake System
// =============================================================================
//
// HookProbe's kernel-level packet capture engine built with Zig and eBPF/XDP.
// Aegis is the "muscle" of the split-brain IDS architecture:
//
//   Aegis (kernel, Zig) ─── Ring Buffer ───> Napse (userspace, Mojo)
//        ↑ XDP                                    ↓ Intent Classification
//     NIC/dummy-mirror                       ClickHouse + MSSP API
//
// Responsibilities:
//   1. Attach XDP program to capture interface
//   2. Parse packets at wire speed (zero-copy)
//   3. Extract 32-dimensional feature vectors
//   4. Calculate Shannon entropy per payload
//   5. Push feature vectors to shared ring buffer
//   6. Export per-CPU statistics to ClickHouse
//
// Usage:
//   aegis-loader --config /etc/aegis/aegis.toml --interface dummy-mirror
//   aegis-loader --help

const std = @import("std");
const ring_buffer = @import("ring_buffer.zig");
const entropy = @import("entropy.zig");
const feature_extract = @import("feature_extract.zig");
const xdp_program = @import("xdp_program.zig");

const VERSION = "1.0.0";

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    _ = allocator;

    const stdout = std.io.getStdOut().writer();

    try stdout.print(
        \\
        \\  ╔═══════════════════════════════════════════════════════╗
        \\  ║             AEGIS - Packet Capture Engine             ║
        \\  ║       HookProbe Zig/eBPF XDP Intake System           ║
        \\  ║                  Version {s}                       ║
        \\  ╚═══════════════════════════════════════════════════════╝
        \\
        \\  Architecture:
        \\    NIC ──> XDP (kernel) ──> Ring Buffer ──> Napse (Mojo)
        \\
        \\  Features:
        \\    - Zero-copy packet inspection via XDP
        \\    - Shannon entropy computation per payload
        \\    - 32-dimensional feature vector extraction
        \\    - Lock-free ring buffer (Aegis -> Napse)
        \\    - Comptime-optimized protocol parsers
        \\
        \\  Ring Buffer Entry: {d} bytes ({d}-dim feature vector)
        \\  Ring Buffer Header: {d} bytes
        \\
        \\  Status: Scaffold ready. Awaiting Zig eBPF toolchain.
        \\
        \\  To build and load:
        \\    zig build              # Compile XDP + loader
        \\    sudo ./aegis-loader    # Attach XDP to interface
        \\
    , .{
        VERSION,
        @sizeOf(ring_buffer.RingEntry),
        ring_buffer.FEATURE_DIMS,
        @sizeOf(ring_buffer.RingHeader),
    });
}

// =============================================================================
// Tests
// =============================================================================

test "all modules compile" {
    // Verify all submodules are importable and compile
    _ = ring_buffer.RingEntry;
    _ = ring_buffer.RingHeader;
    _ = entropy.shannonEntropy;
    _ = feature_extract.extractFeatures;
    _ = xdp_program.xdpPassiveInspect;
}

test {
    // Run all tests from submodules
    std.testing.refAllDecls(@This());
    _ = @import("ring_buffer.zig");
    _ = @import("entropy.zig");
    _ = @import("feature_extract.zig");
    _ = @import("xdp_program.zig");
}
