//! P8 / L7 — deep-packet L7 signature matching in the VERIFIED fast-path. Home/
//! farm automation threats are at L7 (malformed MQTT payloads, unauthorized CoAP
//! commands to open a gate, Modbus-TCP function codes). This helper (#3) matches a
//! SIGNED byte pattern against the packet at a rule-supplied pointer, so L7
//! detection runs in the kernel BEFORE waking the EL0 automation services (P17) —
//! a malformed MQTT CONNECT never reaches the actuator layer.
//!
//! Safety: the helper does a raw compare at `ptr`; the calling RULE must first
//! touch-load the LAST pattern byte (a normal LDX the verifier bounds / the
//! interpreter aborts on OOB), so by the time `payload_match` runs the bytes are
//! proven in-bounds. Signed first-party rules guarantee that structure.

/// A signed L7 pattern (id → bytes). MQTT/Modbus/CoAP field probes; the corpus is
/// pluggable + HYDRA-synced in production.
struct Pat {
    bytes: &'static [u8],
}
static PATTERNS: &[Pat] = &[
    Pat { bytes: b"MQTT" }, // 0: the MQTT protocol name (CONNECT var-header @ payload+4)
];

/// Helper #3: `R0 = payload_match(R1 = ptr, R2 = pattern_id)` — 1 on match, else 0.
/// Bounds are the caller's responsibility (touch-LDX before the call).
pub fn payload_match(ptr: u64, pattern_id: u64) -> u64 {
    let p = match PATTERNS.get(pattern_id as usize) {
        Some(p) => p,
        None => return 0,
    };
    for (k, &b) in p.bytes.iter().enumerate() {
        if unsafe { core::ptr::read_volatile((ptr as usize + k) as *const u8) } != b {
            return 0;
        }
    }
    1
}
