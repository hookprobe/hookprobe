//! M4.3 #6 — entropy source abstraction (the auditor's highest-consequence item).
//!
//! The M4.2b security-auditor review (docs/design/heqk-control-plane.md §"M4.2b
//! … tracked conditions", item 1) flagged entropy as the single most dangerous
//! wiring surface in the whole secure channel:
//!
//! > The KATs pass identically for a seed or a TRNG — a wiring slip that lets a
//! > seeded path reach metal gives the whole fleet reused ephemerals behind a
//! > green gate (total confidentiality break).
//!
//! This module makes that slip **structurally impossible on the metal profile**,
//! not merely improbable:
//!
//!   1. **One production source, and it FAILS CLOSED.** `MetalEntropy` is the ONLY
//!      `EntropySource` that compiles outside the selftest feature. It draws from
//!      the hardware TRNG (`RawTrng`) and returns `Err` — never a seed, never a
//!      timer, never zeros — if the TRNG is unavailable or fails its health check.
//!   2. **No seeded source can be built on metal.** The deterministic `TestEntropy`
//!      (fixed seed) and the `StubTrng`/`AbsentTrng` test doubles live behind the
//!      `securechannel-selftest` feature, and a `compile_error!` refuses to build
//!      if that feature is ever enabled together with the metal (`cm5`) profile.
//!      So on a real device the seeded path does not merely go unused — it does
//!      not exist in the binary.
//!   3. **Boot-time entropy-health assertion.** `boot_health_assert()` constructs
//!      the production source and runs the startup health check; on metal it MUST
//!      be called before any secure-channel keygen, and a failure means the secure
//!      channel refuses to operate (fail-closed) rather than proceeding on weak
//!      entropy. In QEMU this same assertion is exercised to PROVE it fails closed
//!      when there is no TRNG (the `[P19-enroll]` gate).
//!
//! HONESTY (Track-C): the `RawTrng` HARDWARE leaf (`HwTrng`) is Gate R — the
//! BCM2712 RNG200 / any FEAT_RNG source on the CM5's A76 is not modelled in QEMU,
//! so `HwTrng` fails closed on every non-`cm5` target by construction (there is no
//! TRNG to read, and substituting one would be the exact defect this module
//! forbids). What IS proven in QEMU is the entropy ASSEMBLY + health-check logic +
//! the fail-closed structure, exercised through `RawTrng` test doubles.

#![cfg(feature = "securechannel")]

// The hard compile barrier: the seeded / deterministic entropy path (TestEntropy,
// StubTrng) is a SELFTEST-ONLY facility. If it is ever enabled on the metal
// profile, refuse to build — a green build is never worth a fleet-wide reused
// ephemeral. This is the load-bearing guarantee that no seeded source reaches metal.
#[cfg(all(feature = "securechannel-selftest", feature = "cm5"))]
compile_error!(
    "securechannel-selftest (seeded/deterministic entropy) must NEVER be enabled on the \
     metal (cm5) profile: it would let a fixed seed feed real ephemeral key generation, \
     giving the fleet reused ephemerals behind a green gate. Build the metal image WITHOUT \
     securechannel-selftest."
);

/// Why entropy could not be produced. Both are terminal (fail-closed) — there is
/// deliberately NO variant that means "used a fallback".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    /// The hardware TRNG is absent, not ready, or stopped yielding words.
    Unavailable,
    /// The TRNG yielded words but failed the startup health check (e.g. stuck
    /// output). A working-but-biased source is refused, not de-biased-and-trusted.
    HealthCheckFailed,
}

/// An entropy source. Object-safe on purpose so the production ephemeral path can
/// take `&mut dyn EntropySource` — one code path, no seeded monomorphization to
/// slip in. Every method fails closed; none can silently substitute weak bytes.
pub trait EntropySource {
    /// Fill `out` with cryptographic-quality random bytes, or fail closed.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError>;

    /// Convenience: a fresh 32-byte secret (an ephemeral scalar / KEM seed).
    fn fill_32(&mut self) -> Result<[u8; 32], EntropyError> {
        let mut b = [0u8; 32];
        self.fill(&mut b)?;
        Ok(b)
    }

    /// Startup health check (called by `boot_health_assert`). Default: draw a
    /// window of raw words and reject an unavailable or stuck source.
    fn health_check(&mut self) -> Result<(), EntropyError>;
}

// ---------------------------------------------------------------------------
// The raw hardware-word leaf. This is the ONLY place a real TRNG is read; the
// health check + byte assembly live above it in MetalEntropy and are testable.
// ---------------------------------------------------------------------------

/// A raw 64-bit hardware-random word source. `next_word` returns `None` when the
/// TRNG is unavailable / not ready — the fail-closed signal. An implementation
/// MUST NEVER return a timer, counter, or constant here: that would be the seeded
/// path this whole module exists to forbid.
pub trait RawTrng {
    fn next_word(&mut self) -> Option<u64>;
}

/// The production hardware TRNG leaf (Gate R).
///
/// On `cm5` this is where the BCM2712 RNG200 (or a FEAT_RNG `RNDR` read, if the
/// SoC implements it) is wired — a real device driver, not exercisable in QEMU.
/// Until that driver lands it returns `None`, so the metal secure channel FAILS
/// CLOSED (refuses) rather than running on weak entropy — the correct posture.
/// On every non-`cm5` target there is no hardware TRNG at all, so it returns
/// `None` by construction: MetalEntropy over `HwTrng` fails closed in QEMU, which
/// is exactly what the `[P19-enroll]` negative case proves.
pub struct HwTrng {
    _priv: (),
}

impl HwTrng {
    pub const fn new() -> Self {
        HwTrng { _priv: () }
    }
}

impl RawTrng for HwTrng {
    #[inline]
    fn next_word(&mut self) -> Option<u64> {
        // On metal: the STRICT BCM2712 rng200 leaf. It shares HBoot's proven
        // register map but NOT its policy — HBoot folds CNTPCT in and degrades to
        // counter bytes so a wedged TRNG can never deadlock the boot chain, which
        // is right for boot and wrong for keys. `next_word_strict` returns `None`
        // for absent / wedged / NIST-failed / half-drained, so a device with a
        // dead TRNG REFUSES rather than running weak (M4.2b review condition #6).
        //
        // Still deliberately NO shortcut to a timer/counter on any target — that
        // would be the seeded slip. Off-cm5 there is no rng200, so this stays
        // fail-closed by construction.
        #[cfg(feature = "cm5")]
        {
            arch_aarch64::rng200::next_word_strict()
        }
        #[cfg(not(feature = "cm5"))]
        {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// MetalEntropy — the ONLY production EntropySource. Byte assembly + health check
// over a RawTrng; fails closed the instant the raw source stops yielding words.
// ---------------------------------------------------------------------------

/// The one production entropy source. Generic over the raw TRNG leaf so the
/// assembly + health logic is unit-testable via a `RawTrng` double, while the
/// hardware leaf (`HwTrng`) stays Gate R. There is intentionally no `Default`,
/// no `from_seed`, no seeded constructor: the only way to obtain bytes is a real
/// (or, in a selftest, a simulated-hardware) TRNG, and if it is dry you get `Err`.
pub struct MetalEntropy<R: RawTrng> {
    raw: R,
}

impl<R: RawTrng> MetalEntropy<R> {
    pub const fn new(raw: R) -> Self {
        MetalEntropy { raw }
    }
}

/// Startup health-check window / stuck-output thresholds (SP 800-90B-style
/// repetition-count spirit; deliberately conservative for a startup gate).
const HEALTH_SAMPLES: usize = 16;
const MAX_CONSECUTIVE_REPEAT: usize = 4;

impl<R: RawTrng> EntropySource for MetalEntropy<R> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        let mut i = 0usize;
        while i < out.len() {
            // A single dry word fails the WHOLE request — never a partial/padded
            // fill. Callers get either full-quality bytes or an error.
            let w = self.raw.next_word().ok_or(EntropyError::Unavailable)?;
            let b = w.to_le_bytes();
            let n = core::cmp::min(8, out.len() - i);
            out[i..i + n].copy_from_slice(&b[..n]);
            i += n;
        }
        Ok(())
    }

    fn health_check(&mut self) -> Result<(), EntropyError> {
        let mut prev: Option<u64> = None;
        let mut run = 1usize;
        for _ in 0..HEALTH_SAMPLES {
            let w = self.raw.next_word().ok_or(EntropyError::Unavailable)?;
            if Some(w) == prev {
                run += 1;
                if run >= MAX_CONSECUTIVE_REPEAT {
                    return Err(EntropyError::HealthCheckFailed); // stuck output
                }
            } else {
                run = 1;
            }
            prev = Some(w);
        }
        Ok(())
    }
}

/// The boot-time entropy-health assertion (auditor condition #6). Constructs the
/// PRODUCTION source (`MetalEntropy<HwTrng>`) and runs its startup health check.
///
/// On metal this MUST gate any secure-channel keygen: `Ok` ⇒ the TRNG is present
/// and healthy; `Err` ⇒ the secure channel refuses to operate (fail-closed). It
/// never returns a "degraded but continue" state. In QEMU it returns
/// `Err(Unavailable)` (no TRNG), which the `[P19-enroll]` gate asserts — proving
/// the fail-closed wiring end to end without a real TRNG.
pub fn boot_health_assert() -> Result<(), EntropyError> {
    let mut src = MetalEntropy::new(HwTrng::new());
    src.health_check()
}

// ===========================================================================
// SELFTEST-ONLY facilities — compiled OUT of the metal profile (see the
// compile_error! guard above). None of the below can reach a real device.
// ===========================================================================

/// A deterministic, fixed-seed entropy source for KATs. Produces a reproducible
/// stream (SHA-256 CTR over a label) so the handshake selftests are QEMU-stable.
/// SELFTEST-ONLY: it is the "seed" the auditor warns must never touch metal, and
/// the `compile_error!` guarantees it cannot be built there.
#[cfg(feature = "securechannel-selftest")]
pub struct TestEntropy {
    label: [u8; 32],
    ctr: u64,
}

#[cfg(feature = "securechannel-selftest")]
impl TestEntropy {
    pub fn from_label(label: &[u8]) -> Self {
        TestEntropy {
            label: boot_abi::sha256::digest(label),
            ctr: 0,
        }
    }
}

#[cfg(feature = "securechannel-selftest")]
impl EntropySource for TestEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        let mut i = 0usize;
        while i < out.len() {
            let mut h = boot_abi::sha256::Hasher::new();
            h.update(&self.label);
            h.update(&self.ctr.to_le_bytes());
            let block = h.finish();
            self.ctr = self.ctr.wrapping_add(1);
            let n = core::cmp::min(block.len(), out.len() - i);
            out[i..i + n].copy_from_slice(&block[..n]);
            i += n;
        }
        Ok(())
    }
    fn health_check(&mut self) -> Result<(), EntropyError> {
        Ok(()) // a deterministic stream is "healthy" by definition
    }
}

/// A `RawTrng` double that SIMULATES a working hardware TRNG (distinct words each
/// call). Lets the `[P19-enroll]` gate prove `MetalEntropy`'s PRODUCTION assembly
/// + health-check + `from_entropy` path works when a TRNG IS present — the
/// positive counterpart to `AbsentTrng`. SELFTEST-ONLY.
#[cfg(feature = "securechannel-selftest")]
pub struct StubTrng {
    state: u64,
}

#[cfg(feature = "securechannel-selftest")]
impl StubTrng {
    pub fn from_label(label: &[u8]) -> Self {
        let d = boot_abi::sha256::digest(label);
        StubTrng {
            state: u64::from_le_bytes(d[..8].try_into().unwrap()),
        }
    }
}

#[cfg(feature = "securechannel-selftest")]
impl RawTrng for StubTrng {
    fn next_word(&mut self) -> Option<u64> {
        // A splitmix64-style step: distinct, non-stuck words (passes health_check).
        // This models a HEALTHY hardware TRNG; it is NOT a production fallback
        // (it is a RawTrng leaf reachable only under securechannel-selftest).
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Some(z ^ (z >> 31))
    }
}

/// A `RawTrng` double that models an ABSENT / failed TRNG (always `None`) — the
/// input that proves `MetalEntropy` FAILS CLOSED. SELFTEST-ONLY.
#[cfg(feature = "securechannel-selftest")]
pub struct AbsentTrng;

#[cfg(feature = "securechannel-selftest")]
impl RawTrng for AbsentTrng {
    fn next_word(&mut self) -> Option<u64> {
        None
    }
}

/// A `RawTrng` double that yields a STUCK word forever — proves `health_check`
/// rejects a working-but-broken source. SELFTEST-ONLY.
#[cfg(feature = "securechannel-selftest")]
pub struct StuckTrng;

#[cfg(feature = "securechannel-selftest")]
impl RawTrng for StuckTrng {
    fn next_word(&mut self) -> Option<u64> {
        Some(0xA5A5_A5A5_A5A5_A5A5)
    }
}
