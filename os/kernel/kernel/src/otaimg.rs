//! OS-image update over the upload channel (ADR 0056 phase 2 / production phase 1, step 4).
//!
//! The uploaded container is the signed boot image itself (`heqk8.img`: HBoot padded to
//! `HBOOT_PAYLOAD_OFFSET`, the 7,992-byte hybrid-signed header, the kernel payload) — it carries its
//! own signature, so there is no `.SIG` prefix. It lands in the Staging region in 512-byte sectors
//! (never in RAM as a whole), and nothing reaches a boot slot until every check below passes:
//!
//! 1. length = HBoot prefix + header + `hdr.size`, within the HBoot load window;
//! 2. the SHARED boot verifier (`boot_abi::verify::verify_digest`) over a streamed SHA-256 of the
//!    body: both signatures (Ed25519 + SLH-DSA) and `svn >= max(BootInfo floor, running SVN)` —
//!    never a downgrade, not even one the floor would allow;
//! 3. the factory A/B layout (`hal::abslot`): the inactive slot is the file `config.txt` does not
//!    name, one contiguous run, and the image fits its directory size (the firmware loads exactly
//!    that many bytes);
//! 4. the HBoot prefix equals the installed one byte for byte — the HBoot bytes are not covered by
//!    the payload signature, so a boot-loader change stays a USB reflash;
//! 5. `tryboot.txt` names the inactive slot (the trial boot will run the new image), and the device
//!    is running its cold-boot slot (a trial in progress is never overwritten: its fallback is the
//!    slot we would write).
//!
//! `install` then copies Staging into the slot run the eMMC driver admits on its own
//! (`BlockDev::admit_inactive_slot`), and re-hashes the payload FROM THE SLOT — the bytes the
//! firmware will load — before anyone may flip. The running slot is never written.

use boot_abi::verify::{self, VerifyErr};
use boot_abi::{sha256::Hasher, PayloadHeader, HBOOT_IMAGE_BASE, HBOOT_IMAGE_END_MAX, HBOOT_PAYLOAD_OFFSET};
use core::mem::size_of;
use hal::BlockDev;

const HDR_LEN: u64 = size_of::<PayloadHeader>() as u64;
const OFF: u64 = HBOOT_PAYLOAD_OFFSET as u64;
/// Largest image the boot chain loads (5 MiB).
pub const IMG_MAX: u64 = (HBOOT_IMAGE_END_MAX - HBOOT_IMAGE_BASE) as u64;
/// Smallest image with a non-empty payload.
pub const IMG_MIN: u64 = OFF + HDR_LEN + 1;

#[repr(align(8))]
struct HdrBuf([u8; size_of::<PayloadHeader>()]);
static mut HDR: HdrBuf = HdrBuf([0; size_of::<PayloadHeader>()]);
static mut BUF: [u8; 4096] = [0; 4096];

/// What `check` proved, and where `install` writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub svn: u64,
    pub hash: [u8; 32],
    pub len: u64,
    pub lo: u64,
    pub hi: u64,
    /// The cold-boot slot (`config.txt`), b'a' or b'b' — the one never written.
    pub active: u8,
}

/// Visit bytes [off, off+len) of the image that starts at sector `base`, in order.
fn each<D: BlockDev>(d: &D, base: u64, off: u64, len: u64, f: &mut dyn FnMut(&[u8])) -> bool {
    // SAFETY: single-threaded (the AP loop / a self-test); BUF is only used inside this function.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    let (mut pos, end) = (off, off + len);
    while pos < end {
        let lba = base + pos / 512;
        let skip = (pos % 512) as usize;
        let want = ((end - pos) as usize + skip).min(buf.len());
        let n = want.div_ceil(512) * 512;
        if d.read_blocks(lba, &mut buf[..n]).is_err() {
            return false;
        }
        let take = want - skip;
        f(&buf[skip..skip + take]);
        pos += take as u64;
    }
    true
}

fn hash<D: BlockDev>(d: &D, base: u64, off: u64, len: u64) -> Option<[u8; 32]> {
    let mut h = Hasher::new();
    each(d, base, off, len, &mut |b| h.update(b)).then(|| h.finish())
}

/// Read the header of the image at sector `base` into the static buffer.
fn header<D: BlockDev>(d: &D, base: u64) -> Option<&'static PayloadHeader> {
    // SAFETY: single-threaded; HDR is 8-aligned and exactly header-sized.
    let hb = unsafe { &mut *core::ptr::addr_of_mut!(HDR) };
    let mut at = 0usize;
    if !each(d, base, OFF, HDR_LEN, &mut |b| {
        hb.0[at..at + b.len()].copy_from_slice(b);
        at += b.len();
    }) {
        return None;
    }
    Some(unsafe { &*(hb.0.as_ptr() as *const PayloadHeader) })
}

/// SHA-256 of the payload of the image at sector `base` (the measurement HBoot reports).
fn payload_hash<D: BlockDev>(d: &D, base: u64) -> Option<[u8; 32]> {
    let size = header(d, base)?.size;
    if size == 0 || size > verify::MAX_PAYLOAD_BODY {
        return None;
    }
    hash(d, base, OFF + HDR_LEN, size)
}

/// Checks 1-5 on the image staged at sector `slo` (`len` bytes). `floor` = max(BootInfo floor,
/// running SVN); `running` = the payload hash HBoot measured for this boot (None without HBoot:
/// QEMU, where every boot is a cold boot).
pub fn check<D: BlockDev>(d: &D, slo: u64, len: u64, floor: u64, running: Option<[u8; 32]>) -> Result<Plan, &'static str> {
    if !(IMG_MIN..=IMG_MAX).contains(&len) {
        return Err("not a boot image (size outside the boot loader's load window)");
    }
    let hdr = header(d, slo).ok_or("staging read failed")?;
    verify::check_header(hdr).map_err(|_| "not a heqk boot image (header magic / size / geometry)")?;
    if OFF + HDR_LEN + hdr.size != len {
        return Err("image length does not match its header");
    }
    let body = hash(d, slo, OFF + HDR_LEN, hdr.size).ok_or("staging read failed")?;
    let v = verify::verify_digest(hdr, &body, floor).map_err(|e| match e {
        VerifyErr::BelowFloor => "rollback refused: security version below the running image / floor",
        VerifyErr::BadEd25519 | VerifyErr::BadSlhDsa => "bad signature (not the release keys)",
        _ => "not a heqk boot image",
    })?;
    let run = hal::abslot::inactive_slot_run(|l, b| d.read_block(l, b).is_ok())
        .ok_or("not the factory A/B layout — reflash over USB once")?;
    if len > run.size as u64 {
        return Err("image larger than the slot file");
    }
    if hash(d, slo, 0, OFF) != hash(d, run.active_lo, 0, OFF) {
        return Err("boot loader differs from the installed one (boot-loader updates are USB-only)");
    }
    let mut mbr = [0u8; 512];
    d.read_block(0, &mut mbr).map_err(|_| "MBR read failed")?;
    let p1 = crate::store::parse_mbr(&mbr)[0].start;
    let want = if run.active == b'a' { crate::abboot::Slot::B } else { crate::abboot::Slot::A };
    if crate::abboot::trial(d, p1) != Ok(want) {
        return Err("tryboot.txt does not name the inactive slot");
    }
    if let Some(r) = running {
        if payload_hash(d, run.active_lo) != Some(r) {
            return Err("a trial boot is running — commit or reboot before the next update");
        }
    }
    Ok(Plan { svn: v.svn, hash: v.hash, len, lo: run.lo, hi: run.hi, active: run.active })
}

/// Copy the checked image into the inactive slot through the driver's own admission, then re-hash
/// the payload from the slot. On any failure the running slot is untouched; the inactive slot may
/// hold a partial image, which HBoot refuses (hash) — the next trial would fall back.
pub fn install<D: BlockDev>(d: &mut D, slo: u64, plan: &Plan) -> Result<(), &'static str> {
    match d.admit_inactive_slot() {
        Some((lo, hi, _)) if lo == plan.lo && hi == plan.hi => {}
        _ => {
            d.revoke_inactive_slot();
            return Err("the storage driver did not admit the inactive slot");
        }
    }
    let mut s = [0u8; 512];
    let n = plan.len.div_ceil(512);
    for i in 0..n {
        if d.read_block(slo + i, &mut s).is_err() || d.write_block(plan.lo + i, &s).is_err() {
            d.revoke_inactive_slot();
            return Err("slot write failed — the running slot is untouched");
        }
    }
    d.revoke_inactive_slot();
    if payload_hash(&*d, plan.lo) != Some(plan.hash) {
        return Err("slot read-back does not match the verified image");
    }
    Ok(())
}

/// Is this boot a TRIAL of the inactive slot? (HBoot measured a payload different from the one
/// the cold-boot slot holds.) None = unknown (no A/B layout / read error).
pub fn running_trial<D: BlockDev>(d: &D, running: [u8; 32]) -> Option<bool> {
    let run = hal::abslot::inactive_slot_run(|l, b| d.read_block(l, b).is_ok())?;
    if payload_hash(d, run.active_lo)? == running {
        return Some(false);
    }
    (payload_hash(d, run.lo)? == running).then_some(true)
}
