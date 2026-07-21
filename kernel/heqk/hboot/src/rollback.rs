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

/// The active backend. Swap for an `OtpCounter` / `RpmbCounter` when a hardware
/// store is wired — nothing else in the boot path changes.
pub fn backend() -> impl SecureCounter {
    Unprovisioned
}

/// Effective anti-rollback floor = max(compile-time, hardware).
pub fn effective_floor() -> u64 {
    let hw = backend().floor();
    if hw > COMPILE_FLOOR {
        hw
    } else {
        COMPILE_FLOOR
    }
}
