// SPDX-License-Identifier: AGPL-3.0-only
//! Durable monotonic values for C1: the delegation counter and the revocation epoch.
//!
//! **One mechanism, ADR 0069's.** The heqk kernel already keeps a monotonic counter that is proven on CM5 metal
//! (`os/kernel/kernel/src/g19ctr.rs`, DataVolume region `G19Ctr`). This module uses the same record scheme, so
//! the system has one way to keep a monotonic value:
//!
//! ```text
//! two 512-byte sectors, written alternately (slot = value % 2):
//!   magic[8] | value LE64 | sha256(the 16 bytes before)[32] | zero padding
//! ```
//!
//! The newest valid record wins, so a torn write leaves the previous value. [`advance`] writes `value + 1` into the
//! older sector and reads it back before returning it, so a value that is not durable is never used.
//! `tests/c1.rs` checks the layout against the kernel's source (a drift gate), and checks power loss at every
//! step.
//!
//! The kernel integration (which sectors, which eMMC write window) is HomePods' (`KERNEL_REQUESTS.md`, KR-3).
//! Here the device is the [`BlockDev`] trait, the same shape as the kernel's `hal::BlockDev`.

use crate::crypto::sha256;

/// A sector could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;

/// The sector interface the kernel's `hal::BlockDev` provides (512-byte sectors).
pub trait BlockDev {
    fn read_block(&self, lba: u64, out: &mut [u8; 512]) -> Result<(), IoError>;
    fn write_block(&mut self, lba: u64, data: &[u8; 512]) -> Result<(), IoError>;
}

/// Record magics. `G19` is the kernel's (for the drift test); the Conductor's two are new and differ only in the
/// tag, so a sector written for one use can never be read as another.
pub const MAGIC_G19: &[u8; 8] = b"HQG19C1\0";
pub const MAGIC_DELEGATION: &[u8; 8] = b"HQCDLG1\0";
pub const MAGIC_EPOCH: &[u8; 8] = b"HQCEPO1\0";
/// The worker side (C2): its replay high-water mark per paired device, and the newest epoch it has seen.
pub const MAGIC_WORKER_HWM: &[u8; 8] = b"HQWHWM1\0";
pub const MAGIC_WORKER_EPOCH: &[u8; 8] = b"HQWEPO1\0";

pub fn encode(magic: &[u8; 8], value: u64) -> [u8; 512] {
    let mut s = [0u8; 512];
    if let Some(d) = s.get_mut(..8) {
        d.copy_from_slice(magic);
    }
    if let Some(d) = s.get_mut(8..16) {
        d.copy_from_slice(&value.to_le_bytes());
    }
    let h = sha256(&[s.get(..16).unwrap_or(&[])]);
    if let Some(d) = s.get_mut(16..48) {
        d.copy_from_slice(&h);
    }
    s
}

pub fn decode(magic: &[u8; 8], s: &[u8; 512]) -> Option<u64> {
    let head = s.get(..16)?;
    if s.get(..8)? != magic || sha256(&[head]).get(..)? != s.get(16..48)? {
        return None;
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(s.get(8..16)?);
    Some(u64::from_le_bytes(v))
}

/// The highest valid value in the two sectors at `lo` (0 = never written, or both torn). `Err` only when
/// neither sector can be read at all.
pub fn load<D: BlockDev + ?Sized>(d: &D, magic: &[u8; 8], lo: u64) -> Result<u64, IoError> {
    let mut best = 0u64;
    let mut read_any = false;
    for i in 0..2u64 {
        let mut s = [0u8; 512];
        if d.read_block(lo.checked_add(i).ok_or(IoError)?, &mut s).is_ok() {
            read_any = true;
            if let Some(c) = decode(magic, &s) {
                best = best.max(c);
            }
        }
    }
    if read_any {
        Ok(best)
    } else {
        Err(IoError)
    }
}

/// Persist `current + 1` into the older sector and read it back. `None` = not durable: the caller must not use
/// a value (no signature leaves, no epoch is announced).
pub fn advance<D: BlockDev + ?Sized>(d: &mut D, magic: &[u8; 8], lo: u64) -> Option<u64> {
    let cur = load(d, magic, lo).ok()?;
    let next = cur.checked_add(1)?;
    let lba = lo.checked_add(next % 2)?;
    let s = encode(magic, next);
    d.write_block(lba, &s).ok()?;
    let mut r = [0u8; 512];
    d.read_block(lba, &mut r).ok()?;
    (r == s).then_some(next)
}


/// Persist `value` if it is above the stored one (a high-water mark that jumps, such as a worker's replay
/// mark). It overwrites the sector that does NOT hold the current maximum and reads it back, so a torn write
/// leaves the previous maximum intact. Returns the durable maximum (`value`, or the larger stored one); `None`
/// = not durable, the caller must not act on `value`.
///
/// [`advance`] is the special case `value = current + 1`, where the slot rule `value % 2` picks the same
/// sector; it keeps the kernel's exact form for the drift gate.
pub fn raise<D: BlockDev + ?Sized>(d: &mut D, magic: &[u8; 8], lo: u64, value: u64) -> Option<u64> {
    let mut v = [None, None];
    for (i, slot) in v.iter_mut().enumerate() {
        let mut s = [0u8; 512];
        d.read_block(lo.checked_add(i as u64)?, &mut s).ok()?;
        *slot = decode(magic, &s);
    }
    let [a, b] = v;
    let cur = a.unwrap_or(0).max(b.unwrap_or(0));
    if value <= cur {
        return Some(cur);
    }
    // Overwrite the sector that does not hold `cur` (an invalid one first).
    let slot: u64 = match (a, b) {
        (None, _) => 0,
        (_, None) => 1,
        (Some(x), Some(y)) => u64::from(x >= y),
    };
    let lba = lo.checked_add(slot)?;
    let s = encode(magic, value);
    d.write_block(lba, &s).ok()?;
    let mut r = [0u8; 512];
    d.read_block(lba, &mut r).ok()?;
    (r == s).then_some(value)
}

/// The signer's sealed state on one device: the delegation counter at `counter_lo`, the epoch at `epoch_lo`
/// (two sectors each, in the regions KR-3 asks HomePods to register).
pub struct Sealed<D: BlockDev> {
    pub dev: D,
    pub counter_lo: u64,
    pub epoch_lo: u64,
}

#[cfg(feature = "signer")]
impl<D: BlockDev> crate::signer::CounterStore for Sealed<D> {
    fn advance(&mut self) -> Option<u64> {
        advance(&mut self.dev, MAGIC_DELEGATION, self.counter_lo)
    }
    fn epoch(&self) -> Option<u32> {
        let v = load(&self.dev, MAGIC_EPOCH, self.epoch_lo).ok()?;
        u32::try_from(v.max(1)).ok()
    }
    fn bump_epoch(&mut self) -> Option<u32> {
        // A fresh store reads 0 and means epoch 1, so the first bump writes 1 and then 2.
        if load(&self.dev, MAGIC_EPOCH, self.epoch_lo).ok()? == 0 {
            advance(&mut self.dev, MAGIC_EPOCH, self.epoch_lo)?;
        }
        u32::try_from(advance(&mut self.dev, MAGIC_EPOCH, self.epoch_lo)?).ok()
    }
}
