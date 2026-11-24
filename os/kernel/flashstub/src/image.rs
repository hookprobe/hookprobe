// SPDX-License-Identifier: AGPL-3.0-only
//! The slot-image checks (ADR 0070 D3.1, D3.2, D3.5): the stub's call into the SHARED boot verifier, the HBoot-prefix
//! rule, and the both-slot check on the written medium.
//!
//! A slot file (`heqk8-a.img` / `heqk8-b.img`) is the combined boot image: HBoot padded with zeros to
//! `HBOOT_PAYLOAD_OFFSET`, the 7,992-byte hybrid-signed `PayloadHeader`, then the payload. The checks are the OTA
//! pre-flight's (`kernel/src/otaimg.rs` checks 1, 2 and 4), applied to an image held in RAM instead of the eMMC
//! staging region — that file lives in the kernel binary crate, so its three checks are restated here against the
//! same `boot_abi` constants and the same `boot_abi::verify::{check_header, verify_digest}`. There is no second
//! verifier and no second key set: the signatures and the trust root are `boot_abi::verify`'s.

use boot_abi::sha256::{self, Hasher};
use boot_abi::verify::{self, VerifyErr};
use boot_abi::{PayloadHeader, HBOOT_IMAGE_BASE, HBOOT_IMAGE_END_MAX, HBOOT_PAYLOAD_OFFSET};
use core::mem::size_of;

/// Bytes in front of the header: HBoot, zero-padded (not covered by the payload signature).
pub const OFF: usize = HBOOT_PAYLOAD_OFFSET;
pub const HDR_LEN: usize = size_of::<PayloadHeader>();
/// Largest slot image the boot chain loads (5 MiB) — `otaimg::IMG_MAX`.
pub const IMG_MAX: usize = HBOOT_IMAGE_END_MAX - HBOOT_IMAGE_BASE;
/// Smallest slot image with a non-empty payload — `otaimg::IMG_MIN`.
pub const IMG_MIN: usize = OFF + HDR_LEN + 1;

/// What a positive verdict proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub svn: u64,
    /// SHA-256 the verifier recomputed over the payload body (never the header's stored copy).
    pub hash: [u8; 32],
}

/// Why an image was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Length outside the load window, length != header, or the header's magic / size / geometry.
    BadHeader,
    /// One of the two signatures did not verify against the compiled-in trust root.
    SigFail,
    /// Validly signed, svn below the stub's floor.
    Rollback,
    /// The HBoot bytes in front of the payload are not the HBoot this stub was booted with.
    HbootMismatch,
}

/// The running HBoot, as the stub knows it. The HBoot prefix is not covered by the payload signature (OTA rule 4),
/// so a slot is accepted only if its prefix is byte-identical to the HBoot that booted the stub.
pub trait HbootRef {
    /// `prefix` = the first `OFF` bytes of a slot image.
    fn matches(&self, prefix: &[u8]) -> bool;
}

/// Exact bytes (host tests; any caller that holds the running HBoot's image).
pub struct HbootBytes<'a>(pub &'a [u8]);
impl HbootRef for HbootBytes<'_> {
    fn matches(&self, prefix: &[u8]) -> bool {
        prefix.len() == OFF && self.0.len() <= OFF && prefix[..self.0.len()] == *self.0 && prefix[self.0.len()..].iter().all(|&b| b == 0)
    }
}

/// The running HBoot by its measurement: HBoot's own `EV_HBOOT_SELF` event (PCR0) is SHA-256 over its loaded bytes
/// `[HBOOT_IMAGE_BASE, __hboot_load_end)` = `hboot.bin`, and `mkimage-hboot.sh` pads `hboot.bin` with zeros up to
/// `OFF`. EL1 cannot read HBoot's RAM (stage-2 hole 0x200000..0x800000), so the stub matches against the digest:
/// a prefix is accepted iff, for some `L`, `SHA-256(prefix[..L]) == digest` and `prefix[L..]` is all zeros. `L`
/// is not handed over, so it is searched from the last non-zero byte up to `MAX_TRAILING_ZEROS` further (zero bytes
/// at the very end of `hboot.bin`). Accepting needs a SHA-256 preimage of HBoot's own measurement, so this is
/// byte-identity, not a heuristic.
pub struct MeasuredHboot {
    /// None = HBoot's self-measurement was not found: every image is refused (fail-closed).
    pub digest: Option<[u8; 32]>,
}

/// How many zero bytes `hboot.bin` may end with (the search window above).
pub const MAX_TRAILING_ZEROS: usize = 64 * 1024;

/// A bitwise copy of a running hasher (the boot-abi `Hasher` is plain data — arrays and integers, no `Drop` —
/// but does not implement `Clone`, and boot-abi is a pinned boot-loader crate, so it is not changed for this).
fn dup(h: &Hasher) -> Hasher {
    // SAFETY: `Hasher` holds only `[u32; 8]`, `[u8; 64]`, `usize` and `u64`; it has no destructor and no
    // interior pointers, so a bitwise copy is a valid, independent value.
    unsafe { core::ptr::read(h) }
}

impl HbootRef for MeasuredHboot {
    fn matches(&self, prefix: &[u8]) -> bool {
        let Some(want) = self.digest else { return false };
        if prefix.len() != OFF {
            return false;
        }
        let lc = prefix.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        if lc == 0 {
            return false; // no HBoot at all
        }
        let mut h = Hasher::new();
        h.update(&prefix[..lc]);
        let top = (lc + MAX_TRAILING_ZEROS).min(OFF);
        for l in lc..=top {
            if l > lc {
                h.update(&[0]);
            }
            if dup(&h).finish() == want {
                return true;
            }
        }
        false
    }
}

#[repr(C, align(8))]
struct HdrBuf([u8; HDR_LEN]);

/// The header at `OFF` of an image (copied into an aligned buffer; every bit pattern is a valid `PayloadHeader`).
fn with_header<T>(img: &[u8], f: impl FnOnce(&PayloadHeader) -> T) -> Option<T> {
    if img.len() < OFF + HDR_LEN {
        return None;
    }
    let mut b = HdrBuf([0; HDR_LEN]);
    b.0.copy_from_slice(&img[OFF..OFF + HDR_LEN]);
    // SAFETY: HdrBuf is 8-aligned and exactly size_of::<PayloadHeader>() bytes; PayloadHeader is repr(C) of
    // integers and byte arrays, so any bytes form a valid value.
    Some(f(unsafe { &*(b.0.as_ptr() as *const PayloadHeader) }))
}

/// The payload length the header at `OFF` declares, if the header is sane (`check_header`).
pub fn declared_len(img_head: &[u8]) -> Option<usize> {
    with_header(img_head, |h| verify::check_header(h).ok().map(|_| OFF + HDR_LEN + h.size as usize)).flatten()
}

/// Checks 1, 2 and 4 of the OTA pre-flight on a slot image held in RAM:
///  1. `IMG_MIN <= len <= IMG_MAX`, the header sane, and `len == OFF + HDR_LEN + hdr.size`;
///  2. `boot_abi::verify::verify_digest` over the recomputed payload SHA-256 — both signatures and `svn >= floor`;
///  4. the HBoot prefix byte-identical to the running HBoot.
pub fn verify_slot_image(img: &[u8], floor: u64, hboot: &dyn HbootRef) -> Result<Verdict, Refusal> {
    if !(IMG_MIN..=IMG_MAX).contains(&img.len()) {
        return Err(Refusal::BadHeader);
    }
    let r = with_header(img, |hdr| {
        verify::check_header(hdr).map_err(|_| Refusal::BadHeader)?;
        if OFF + HDR_LEN + hdr.size as usize != img.len() {
            return Err(Refusal::BadHeader);
        }
        let body = sha256::digest(&img[OFF + HDR_LEN..]);
        verify::verify_digest(hdr, &body, floor).map_err(|e| match e {
            VerifyErr::BelowFloor => Refusal::Rollback,
            VerifyErr::BadEd25519 | VerifyErr::BadSlhDsa => Refusal::SigFail,
            _ => Refusal::BadHeader,
        })
    })
    .ok_or(Refusal::BadHeader)??;
    if !hboot.matches(&img[..OFF]) {
        return Err(Refusal::HbootMismatch);
    }
    Ok(Verdict { svn: r.svn, hash: r.hash })
}

/// Slot flags of a written medium (ADR 0070 D3.5): bit 0 = `HEQK8-A.IMG`, bit 1 = `HEQK8-B.IMG` holds an image that
/// passes `verify_slot_image` (the verified payload, or another payload that verifies under the same rules).
/// The files are found through FAT on the medium itself (`hal::abslot`, the walk OTA's Gate 1 uses), never from a
/// manifest. `read(lba, out)` reads `out.len() / 512` sectors; `scratch` holds one slot image (>= IMG_MAX bytes).
pub fn slot_flags(
    read: &mut dyn FnMut(u64, &mut [u8]) -> bool,
    scratch: &mut [u8],
    floor: u64,
    hboot: &dyn HbootRef,
) -> u8 {
    let Some(run) = hal::abslot::inactive_slot_run(|l, b| read(l, &mut b[..])) else { return 0 };
    // (slot letter, first sector, sector after the run, the size the directory gives — None for the active slot)
    let (inactive, active) = if run.active == b'a' { (b'b', b'a') } else { (b'a', b'b') };
    let slots = [(active, run.active_lo, run.active_hi, None), (inactive, run.lo, run.hi, Some(run.size as usize))];
    let mut flags = 0u8;
    for (letter, lo, hi, dir_size) in slots {
        let room = ((hi - lo) as usize * 512).min(scratch.len());
        let head = OFF + HDR_LEN;
        let need_head = head.div_ceil(512) * 512;
        if room < need_head || !read(lo, &mut scratch[..need_head]) {
            continue;
        }
        let Some(len) = declared_len(&scratch[..head]) else { continue };
        if len > room || dir_size.is_some_and(|d| len > d) {
            continue; // the firmware loads exactly the directory size: the image must fit it
        }
        let n = len.div_ceil(512) * 512;
        if !read(lo, &mut scratch[..n]) {
            continue;
        }
        if verify_slot_image(&scratch[..len], floor, hboot).is_ok() {
            flags |= if letter == b'a' { 1 } else { 2 };
        }
    }
    flags
}
