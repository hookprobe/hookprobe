//! P8 — threat-feed blocklist: the SECOND stateful BPF helper, proving the
//! substrate generalizes beyond a counter to a keyed LOOKUP. A signed rule passes
//! an IP source; this returns 1 if it matches any blocked CIDR prefix. Mirrors
//! HookProbe's WAN ingress-threat blocklist (ADR-0005: "threat-feed blocklist,
//! LPM-trie, hourly HYDRA sync"). v1 does a linear longest-prefix scan over a
//! small SIGNED seed set (a production build syncs the trie from HYDRA); the
//! mechanism + the signed-seed model are the point.

/// Network-order (big-endian) IPv4 address `a.b.c.d` as a u32.
const fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}

/// The signed block set: (network-order prefix, prefix length). Examples use the
/// documentation/TEST-NET ranges + a stand-in C2 subnet; a real deployment
/// replaces this with the HYDRA-synced feed.
const BLOCKS: &[(u32, u8)] = &[
    (ip(192, 0, 2, 0), 24),    // TEST-NET-1 (RFC 5737) — example malicious range
    (ip(198, 51, 100, 0), 24), // TEST-NET-2
    (ip(203, 0, 113, 0), 24),  // TEST-NET-3
    (ip(10, 66, 66, 0), 24),   // stand-in C2 subnet
];

/// Helper #2 dispatch: `R0 = ip_blocked(R1 = IP source)`. `ip_le` is the value a
/// BPF `LDX_W` produced from the packet (little-endian byte assembly), so we swap
/// it back to network order before the prefix scan. Returns 1 if blocked, else 0.
pub fn ip_blocked(ip_le: u64) -> u64 {
    let net = (ip_le as u32).swap_bytes();
    for &(prefix, len) in BLOCKS {
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
        if (net & mask) == (prefix & mask) {
            return 1;
        }
    }
    0
}
