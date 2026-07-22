//! P8 — stateful detection substrate: a fixed-window per-key rate limiter, the
//! FIRST BPF helper (kernel-owned state a signed rule can consult via a `CALL`).
//! This is what single-packet rules can't do — decide on a RATE. It unlocks the
//! stateful WAN tier: SYN-flood rate-limit (first user), and later connection-
//! rate limiting, an LPM threat-feed blocklist, and conntrack-style flow state.
//!
//! v1 keys into a small fixed table and windows on the ARM generic counter
//! (`cntpct_el0`, ~1 s per `cntfrq_el0`). The BPF `CALL` opcode dispatches here;
//! the JIT declines programs that use `CALL` (interpreter-only), which is fine —
//! rate-checked packets (SYNs) are a small fraction of the datapath.

use core::sync::atomic::{AtomicU64, Ordering};

const SLOTS: usize = 64;
static WIN_START: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static COUNT: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];

#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}
#[inline]
fn cntfrq() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Fixed-window rate check: bump `key`'s counter and return 1 if the count now
/// EXCEEDS `limit` within the current ~1 s window, else 0. The window resets once
/// `cntfrq` ticks have elapsed since it opened, so a sustained flood trips it but
/// a normal low rate never accumulates across windows.
pub fn syn_rate_over(key: u64, limit: u64) -> u64 {
    let i = (key as usize) % SLOTS;
    let now = cntpct();
    let win = cntfrq().max(1); // ~1 second in counter ticks
    let start = WIN_START[i].load(Ordering::Relaxed);
    if now.wrapping_sub(start) >= win {
        // New window: reset to this packet.
        WIN_START[i].store(now, Ordering::Relaxed);
        COUNT[i].store(1, Ordering::Relaxed);
        return 0;
    }
    let c = COUNT[i].fetch_add(1, Ordering::Relaxed) + 1;
    if c > limit {
        1
    } else {
        0
    }
}

/// BPF `CALL` (opcode 0x85) dispatch: `R0 = helper(imm)(R1, R2)`. Only signed,
/// verifier-approved helper ids are reachable; an unknown id returns a benign 0
/// (the verifier already rejects programs that call an unknown helper).
pub fn call_helper(id: u32, r1: u64, r2: u64) -> u64 {
    match id {
        HELPER_SYN_RATE_OVER => syn_rate_over(r1, r2),
        HELPER_IP_BLOCKED => crate::blocklist::ip_blocked(r1),
        HELPER_PAYLOAD_MATCH => crate::l7::payload_match(r1, r2),
        _ => 0,
    }
}

/// Helper id: `R0 = syn_rate_over(R1=key, R2=limit)`.
pub const HELPER_SYN_RATE_OVER: u32 = 1;
/// Helper id: `R0 = ip_blocked(R1=IP source)` — threat-feed blocklist lookup.
pub const HELPER_IP_BLOCKED: u32 = 2;
/// Helper id: `R0 = payload_match(R1=ptr, R2=pattern_id)` — L7 signature match.
pub const HELPER_PAYLOAD_MATCH: u32 = 3;
/// Highest valid helper id (the verifier bounds `CALL imm` by this).
pub const MAX_HELPER_ID: u32 = 3;
