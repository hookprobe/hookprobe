//! M3.4 — on-device A/B OTA orchestrator + state machine (kernel-side).
//!
//! The device already owns the ROLLBACK half of A/B: HBoot's EL2 PM-watchdog
//! trial boot (`hboot/src/watchdog.rs`), the firmware one-shot `tryboot` flag,
//! and the SVN anti-rollback floor (`hboot/src/rollback.rs`). M3.4 adds the FRONT
//! half — on-device pull → inactive-slot write → verify → flip → confirm/rollback
//! — replacing the host-PC `cm5-boot/ab-update.sh`.
//!
//! ## State machine (persisted, survives reboot via the M3.2 fslog)
//! ```text
//!            stage(verify OK)         flip                 healthy trial
//!   Idle ───────────────────► Staged ─────► Trying ─────────────────► Committed
//!     ▲   verify FAIL: stay      │            │   failed trial (watchdog)
//!     │   (no write, no flip)    │            └───────────────────────► RolledBack
//!     └──────────────────────────┴──────────── new cycle ◄──────────────┘
//! ```
//! A verify FAILURE (bad signature OR `svn < floor`) never leaves `Staged`: the
//! candidate is not written, the active slot and the tryboot flag are untouched.
//!
//! ## What is QEMU-proven here vs metal (Gate R) — honest split
//! Proven in QEMU over the `hal::BlockDev` trait (the identical trait the metal
//! eMMC slots into): the state transitions, the inactive-slot candidate WRITE
//! through the M3.1 multi-region guard (brick-safety: the active slot / LBA 0 are
//! refused), the pre-flight VERIFY (the SHARED `boot_abi::verify` — HBoot's exact
//! verifier + trust root), the persisted try-slot flip flag, and the
//! confirm/rollback DECISIONS. NOT proven here (reused from hboot/metal, Gate R):
//! the REAL firmware one-shot `tryboot` slot flip, the REAL PM-watchdog trial-boot
//! reset, and a real power cycle. This module drives those — it does not
//! reimplement them.
//!
//! ## The "pull" source
//! The candidate SOURCE is abstracted for QEMU (a RAM buffer / embedded fixture /
//! the virtio-blk backing). The real network fetch from the registry / control
//! plane is M4; here the state machine + inactive-slot write + verify + flip +
//! rollback DECISIONS are the deliverable, not the transport.

use crate::store::{RegionKind, SealedStore, StoreErr};
use boot_abi::verify::{self, VerifyErr, Verified};
use boot_abi::PayloadHeader;
use core::mem::size_of;
use hal::BlockDev;

/// SLOT A — the last known-good HEQK (`config.txt` → `heqk8.img`), booted normally.
pub const SLOT_A: u8 = 0;
/// SLOT B — the OTA candidate (`tryboot.txt` → `heqk8-b.img`), booted once via the
/// firmware one-shot `tryboot`.
pub const SLOT_B: u8 = 1;
/// No pending trial (the `try_slot` sentinel).
pub const SLOT_NONE: u8 = 0xFF;

/// OTA lifecycle phase (persisted). `#[repr(u8)]` so it serializes to one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OtaPhase {
    /// No update in flight; `active_slot` is running normally.
    Idle = 0,
    /// A verified candidate is written to the INACTIVE slot, not yet flipped.
    Staged = 1,
    /// The tryboot flip is set; the candidate is on a (one-shot) trial boot.
    Trying = 2,
    /// The trial boot was healthy — the candidate is promoted to active.
    Committed = 3,
    /// The trial failed (watchdog / health-fail) — reverted to the prior slot.
    RolledBack = 4,
}

impl OtaPhase {
    fn from_u8(b: u8) -> Option<OtaPhase> {
        Some(match b {
            0 => OtaPhase::Idle,
            1 => OtaPhase::Staged,
            2 => OtaPhase::Trying,
            3 => OtaPhase::Committed,
            4 => OtaPhase::RolledBack,
            _ => return None,
        })
    }
}

/// The persisted OTA state. Serialized into a single fslog record payload.
#[derive(Debug, Clone, Copy)]
pub struct OtaState {
    pub phase: OtaPhase,
    /// The slot currently booted / promoted as known-good.
    pub active_slot: u8,
    /// The slot on a pending trial boot, or `SLOT_NONE`.
    pub try_slot: u8,
    /// The candidate's SVN (0 when none staged) — for the operator/audit log.
    pub candidate_svn: u64,
    /// Monotonic generation, bumped on every persisted transition (audit trail).
    pub generation: u64,
}

impl OtaState {
    /// The cold-start default: SLOT A active, nothing in flight.
    pub fn initial() -> OtaState {
        OtaState {
            phase: OtaPhase::Idle,
            active_slot: SLOT_A,
            try_slot: SLOT_NONE,
            candidate_svn: 0,
            generation: 0,
        }
    }

    /// Record-payload magic ("OTA1" LE) so a foreign record is not misread.
    const MAGIC: u32 = 0x3141_544F;
    /// Serialized length (well under fslog's 480-B MAX_PAYLOAD).
    pub const WIRE_LEN: usize = 24;

    /// Serialize into a fixed 24-byte payload.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut b = [0u8; Self::WIRE_LEN];
        b[0..4].copy_from_slice(&Self::MAGIC.to_le_bytes());
        b[4] = self.phase as u8;
        b[5] = self.active_slot;
        b[6] = self.try_slot;
        // b[7] reserved
        b[8..16].copy_from_slice(&self.candidate_svn.to_le_bytes());
        b[16..24].copy_from_slice(&self.generation.to_le_bytes());
        b
    }

    /// Parse a 24-byte payload back into a state (validates magic + phase tag).
    pub fn from_bytes(b: &[u8]) -> Option<OtaState> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        if u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != Self::MAGIC {
            return None;
        }
        let phase = OtaPhase::from_u8(b[4])?;
        Some(OtaState {
            phase,
            active_slot: b[5],
            try_slot: b[6],
            candidate_svn: u64::from_le_bytes(b[8..16].try_into().ok()?),
            generation: u64::from_le_bytes(b[16..24].try_into().ok()?),
        })
    }
}

/// Failure modes of the OTA orchestrator (distinct so the log / a test can name
/// the exact cause).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaErr {
    /// The candidate failed the shared hboot verify (bad sig OR svn < floor).
    VerifyRejected(VerifyErr),
    /// The candidate buffer is smaller than its own declared header + body.
    ShortCandidate,
    /// The candidate does not fit the inactive-slot region.
    SlotTooSmall,
    /// A guarded write did not land in the InactiveSlot region — brick-safety
    /// tripped (the write would have escaped to the active slot / MBR / a gap).
    NotInactiveSlot,
    /// A block read/write / read-back-verify failed under the store.
    Io,
    /// An illegal state transition was requested (e.g. flip before stage).
    BadTransition,
}

impl From<StoreErr> for OtaErr {
    fn from(_: StoreErr) -> Self {
        OtaErr::Io
    }
}

/// Header length of a candidate payload = `size_of::<PayloadHeader>()` (7992 B).
pub const CAND_HDR_LEN: usize = size_of::<PayloadHeader>();

/// PRE-FLIGHT VERIFY — the candidate must pass the SAME verification HBoot runs
/// at boot: hybrid ed25519 + SLH-DSA over `SHA-256(LE64(svn) || sha256(body))`
/// AND `svn >= floor`. This calls the SHARED `boot_abi::verify::verify_payload`
/// — the identical code + embedded trust root HBoot uses — so there is no second
/// verifier and no second trust root. A `&PayloadHeader` view is taken over the
/// candidate's first `CAND_HDR_LEN` bytes; `candidate` must be 8-byte aligned
/// (the caller wraps the fixture in a `#[repr(align(8))]` newtype).
///
/// # Safety of the header view
/// `candidate.as_ptr()` must be 8-aligned and `candidate.len() >= CAND_HDR_LEN`.
pub fn verify_candidate(candidate: &[u8], floor: u64) -> Result<Verified, OtaErr> {
    if candidate.len() < CAND_HDR_LEN {
        return Err(OtaErr::ShortCandidate);
    }
    // Safe: length checked; alignment guaranteed by the caller's aligned newtype.
    // PayloadHeader is repr(C) POD with no padding, so this reinterpretation is
    // sound and avoids copying the 7856-B SLH-DSA signature onto the stack.
    debug_assert_eq!(candidate.as_ptr() as usize % 8, 0, "candidate must be 8-aligned");
    let hdr: &PayloadHeader = unsafe { &*(candidate.as_ptr() as *const PayloadHeader) };
    let body = &candidate[CAND_HDR_LEN..];
    verify::verify_payload(hdr, body, floor).map_err(OtaErr::VerifyRejected)
}

/// Write a verified candidate to the INACTIVE slot region `[lo, hi)`, sector by
/// sector, THROUGH the M3.1 guard. Every sector's write is asserted to land in
/// `RegionKind::InactiveSlot` — a write that resolves to any other region (the
/// active slot, the data volume, the keystore) or escapes the allowlist (LBA 0 /
/// a gap) returns `NotInactiveSlot` and stops. Brick-safety by construction: this
/// function can only ever touch the inactive slot. Returns the sector count
/// written.
pub fn write_candidate_to_inactive<D: BlockDev>(
    store: &mut SealedStore<D>,
    lo: u64,
    hi: u64,
    candidate: &[u8],
) -> Result<u64, OtaErr> {
    let total = candidate.len();
    let nsec = (total.div_ceil(512)) as u64;
    if lo + nsec > hi {
        return Err(OtaErr::SlotTooSmall);
    }
    for i in 0..nsec {
        let lba = lo + i;
        // The guard MUST classify this as the inactive slot; anything else means
        // the target escaped the intended region — refuse rather than write.
        let mut sec = [0u8; 512];
        let off = (i as usize) * 512;
        let n = (total - off).min(512);
        sec[..n].copy_from_slice(&candidate[off..off + n]);
        match store.store_sector(lba, &sec)? {
            RegionKind::InactiveSlot => {}
            _ => return Err(OtaErr::NotInactiveSlot),
        }
    }
    Ok(nsec)
}

/// STAGE — verify a candidate, and on success write it to the inactive slot and
/// advance the state to `Staged` (recording the candidate SVN). On a verify
/// FAILURE the state is returned UNCHANGED and NOTHING is written (the active
/// slot + tryboot flag are untouched) — this is the verify-before-flip guarantee.
/// The returned state is NOT yet persisted; the caller persists it (so persist is
/// one code path, testable).
pub fn stage<D: BlockDev>(
    store: &mut SealedStore<D>,
    st: &OtaState,
    inactive_lo: u64,
    inactive_hi: u64,
    candidate: &[u8],
    floor: u64,
) -> Result<OtaState, OtaErr> {
    // 1. VERIFY FIRST — never write/flip an unverified candidate.
    let v = verify_candidate(candidate, floor)?;
    // 2. Write to the INACTIVE slot only (brick-safe by the guard assertion).
    write_candidate_to_inactive(store, inactive_lo, inactive_hi, candidate)?;
    // 3. Advance to Staged.
    Ok(OtaState {
        phase: OtaPhase::Staged,
        active_slot: st.active_slot,
        try_slot: SLOT_NONE,
        candidate_svn: v.svn,
        generation: st.generation + 1,
    })
}

/// FLIP — arm the one-shot trial boot for the staged candidate. Only legal from
/// `Staged`. Sets `try_slot` to the inactive slot and moves to `Trying`. On metal
/// this corresponds to writing the firmware one-shot (`reboot "0 tryboot"` via the
/// EL2 `hvc #0` gate) so the NEXT boot uses `tryboot.txt` (SLOT B); the persisted
/// `try_slot` is the kernel's durable record of that pending trial. The actual
/// firmware one-shot + the PM-watchdog arming are hboot/firmware (Gate R).
pub fn flip(st: &OtaState) -> Result<OtaState, OtaErr> {
    if st.phase != OtaPhase::Staged {
        return Err(OtaErr::BadTransition);
    }
    let inactive = other_slot(st.active_slot);
    Ok(OtaState {
        phase: OtaPhase::Trying,
        active_slot: st.active_slot,
        try_slot: inactive,
        candidate_svn: st.candidate_svn,
        generation: st.generation + 1,
    })
}

/// CONFIRM — the trial boot reached health (on metal: the kernel's `hvc #1`
/// disarmed HBoot's PM watchdog). COMMIT: promote the trial slot to active, clear
/// the pending trial, move to `Committed`. Only legal from `Trying`.
pub fn confirm(st: &OtaState) -> Result<OtaState, OtaErr> {
    if st.phase != OtaPhase::Trying || st.try_slot == SLOT_NONE {
        return Err(OtaErr::BadTransition);
    }
    Ok(OtaState {
        phase: OtaPhase::Committed,
        active_slot: st.try_slot, // the trial slot is now the known-good slot
        try_slot: SLOT_NONE,
        candidate_svn: st.candidate_svn,
        generation: st.generation + 1,
    })
}

/// ROLLBACK — the trial boot failed (on metal: it hung/panicked before `hvc #1`,
/// so HBoot's PM watchdog full-reset the SoC and the CONSUMED one-shot booted the
/// known-good slot). Revert: keep the OLD active slot, clear the pending trial,
/// move to `RolledBack`. Only legal from `Trying`. The SVN floor is what stops a
/// downgrade attack from ever reaching this path — a below-floor candidate is
/// refused at `stage` and never flipped.
pub fn rollback(st: &OtaState) -> Result<OtaState, OtaErr> {
    if st.phase != OtaPhase::Trying {
        return Err(OtaErr::BadTransition);
    }
    Ok(OtaState {
        phase: OtaPhase::RolledBack,
        active_slot: st.active_slot, // unchanged — the old slot stays known-good
        try_slot: SLOT_NONE,
        candidate_svn: st.candidate_svn,
        generation: st.generation + 1,
    })
}

/// The other A/B slot.
#[inline]
pub fn other_slot(slot: u8) -> u8 {
    if slot == SLOT_A {
        SLOT_B
    } else {
        SLOT_A
    }
}
