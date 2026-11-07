//! Anti-rollback: a security-version floor with a pluggable persistence
//! backend (the `SecureCounter` abstraction).
//!
//! The EFFECTIVE floor HBoot enforces is `max(COMPILE_FLOOR, hardware_floor())`.
//! A validly-signed image whose `svn` is below the effective floor is refused
//! (rollback protection); because `svn` is bound into the signed message, the
//! version cannot be edited to slip past.
//!
//! Backends, honestly stated:
//!  - **compile-time** (active now): `COMPILE_FLOOR` baked into HBoot, the root
//!    of trust. Advancing it = bump + rebuild + reflash HBoot.
//!  - **BCM2712 OTP fuses** (hardware monotonic): would make the floor a true
//!    one-way hardware counter. Writing OTP is IRREVERSIBLE and VPU-mediated —
//!    `provision_otp_floor` below is the (deliberately unused) write path; it
//!    must be an explicit operator action, never automatic. Reading is safe.
//!  - **eMMC RPMB** (replay-protected block): needs an SDHCI driver HBoot does
//!    not yet have — a separate project.
//!
//! Until OTP/RPMB is provisioned, `hardware_floor()` returns 0, so the effective
//! floor equals the compile-time floor. The abstraction is what lets the
//! hardware backend drop in later without touching the header, the signature
//! binding, or the `svn >= floor` comparison.

/// Compile-time floor (root of trust). Bump for a release that fixes a
/// vulnerability you never want rolled back past.
pub const COMPILE_FLOOR: u64 = 1;

/// Back-compat alias used elsewhere in HBoot.
pub const MIN_SVN: u64 = COMPILE_FLOOR;

/// P7d-c FAIL-CLOSED watermark: the highest OTP hardware floor ever provisioned
/// on the fleet, baked into HBoot. It MUST be bumped to the new level every time
/// `advance_floor` blows the OTP counter in production (part of the same
/// deliberate release action). Its purpose: make the OTP read fail-CLOSED. Even
/// if an attacker forces the VC-mailbox OTP read to fail, `effective_floor()`
/// can never drop below this watermark — so a forced read-failure can no longer
/// roll an advanced floor back to the compile floor. 0 until the floor is first
/// advanced (block 3 blank ⇒ real hardware floor is 0 anyway).
pub const EXPECTED_MIN_HW_FLOOR: u64 = 0;

use core::sync::atomic::{AtomicBool, Ordering};
/// Set by `effective_floor()` when the live OTP read could not be completed.
static FLOOR_READ_FAILED: AtomicBool = AtomicBool::new(false);
/// Whether the most recent `effective_floor()` failed to read the OTP counter
/// (a security-relevant condition — the floor fell back to the fail-closed
/// watermark). HBoot logs it; a stricter policy could refuse to boot.
pub fn floor_read_failed() -> bool {
    FLOOR_READ_FAILED.load(Ordering::Relaxed)
}

/// Read the OTP block-3 thermometer with a bounded retry. Returns None only if
/// EVERY attempt to reach the VC mailbox fails — distinct from a genuine floor
/// of 0 (a blank counter reads Some(0)).
fn read_otp_floor() -> Option<u64> {
    for _ in 0..3 {
        if let Some(words) = crate::mailbox::otp_device_key() {
            return Some(words.iter().map(|w| u64::from(w.count_ones())).sum());
        }
    }
    None
}

/// A persistent, monotonic security-version floor.
pub trait SecureCounter {
    /// Current hardware floor (0 if not provisioned / backend unavailable).
    fn floor(&self) -> u64;
    /// Whether this backend is a real hardware monotonic store.
    fn is_hardware(&self) -> bool;
    /// Short label for logging.
    fn name(&self) -> &'static str;
}

/// The not-yet-provisioned backend: no hardware store wired, floor = 0. Honest
/// placeholder that keeps the effective floor at the compile-time value.
pub struct Unprovisioned;
impl SecureCounter for Unprovisioned {
    fn floor(&self) -> u64 {
        0
    }
    fn is_hardware(&self) -> bool {
        false
    }
    fn name(&self) -> &'static str {
        "unprovisioned (OTP/RPMB pending)"
    }
}

/// P7d-c: hardware monotonic floor from BCM2712 **OTP block 3**, read as a
/// THERMOMETER counter — `floor = popcount(blown bits)`. OTP fuses are one-way
/// (0→1), so popcount can only ever rise → monotonic + tamper-evident (nobody
/// can lower it). Block 3 (not block 1) is used because block 1 now holds the
/// B-1 AK secret (~half its bits already set — useless as a counter); block 3 is
/// blank, so a fresh board reads floor 0 and the effective floor stays at the
/// compile-time value until the floor is deliberately advanced. Reading here is
/// non-destructive; advancing (blowing bits) is `advance_floor`, an explicit
/// operator action that is NEVER called automatically.
pub struct OtpCounter;
impl SecureCounter for OtpCounter {
    fn floor(&self) -> u64 {
        // Thermometer level with a bounded retry; unreadable ⇒ 0 here, but the
        // fail-CLOSED policy lives in `effective_floor` (which clamps to the
        // EXPECTED_MIN_HW_FLOOR watermark so a forced read-failure cannot roll an
        // advanced floor back). See P7d-c.
        read_otp_floor().unwrap_or(0)
    }
    fn is_hardware(&self) -> bool {
        true
    }
    fn name(&self) -> &'static str {
        "BCM2712 OTP block3 (hardware monotonic thermometer)"
    }
}

/// The active backend — reads the OTP thermometer (blank block 3 ⇒ floor 0, so
/// behavior is unchanged until the floor is advanced).
pub fn backend() -> impl SecureCounter {
    OtpCounter
}

/// DELIBERATE, IRREVERSIBLE: advance the hardware floor to `target` by blowing
/// `target - current` currently-zero bits in OTP block 3. One-way — the floor
/// can never be lowered, and every increment permanently consumes fuse bits
/// (block 3 holds 512, so up to 512 levels). NEVER called from the boot path;
/// only an explicit operator action should invoke it. Returns the new floor, or
/// None on failure (nothing burned). Idempotent: `target <= current` is a no-op.
pub fn advance_floor(target: u64) -> Option<u64> {
    let mut words = crate::mailbox::otp_device_key()?;
    let current: u64 = words.iter().map(|w| u64::from(w.count_ones())).sum();
    if target <= current {
        return Some(current); // already at/above target — nothing to burn
    }
    let mut need = target - current;
    // Set `need` currently-zero bits (lowest word/bit first — deterministic).
    'outer: for w in words.iter_mut() {
        for b in 0..32 {
            if need == 0 {
                break 'outer;
            }
            if *w & (1 << b) == 0 {
                *w |= 1 << b;
                need -= 1;
            }
        }
    }
    if need != 0 {
        return None; // not enough spare fuse bits for the requested floor
    }
    if !crate::mailbox::set_device_otp(&words) {
        return None; // firmware rejected the write — nothing usable burned
    }
    // Ground truth: read back the actual popcount.
    let after = crate::mailbox::otp_device_key()?;
    Some(after.iter().map(|w| u64::from(w.count_ones())).sum())
}

/// Effective anti-rollback floor = max(compile floor, fail-closed watermark,
/// live OTP thermometer). FAIL-CLOSED (P7d-c): if the OTP read cannot be
/// completed, the floor falls back to `max(COMPILE_FLOOR, EXPECTED_MIN_HW_FLOOR)`
/// — never to 0 and never below the last provisioned level, so a forced
/// read-failure can never roll an advanced floor back. Records the read failure
/// (see `floor_read_failed`) so HBoot can log/escalate it.
pub fn effective_floor() -> u64 {
    let base = if COMPILE_FLOOR > EXPECTED_MIN_HW_FLOOR { COMPILE_FLOOR } else { EXPECTED_MIN_HW_FLOOR };
    match read_otp_floor() {
        Some(hw) => {
            FLOOR_READ_FAILED.store(false, Ordering::Relaxed);
            if hw > base {
                hw
            } else {
                base
            }
        }
        None => {
            FLOOR_READ_FAILED.store(true, Ordering::Relaxed);
            base // fail-closed: hold the watermark, never drop to 0
        }
    }
}
