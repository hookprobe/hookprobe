//! P15 — sealed storage on a block device: MBR-derived write guard + the
//! read/scan path (always) and the store/write path (behind `p15-write`).
//!
//! The write-safety model (SEALED_STORAGE.md): the ONLY sectors ever written are
//! the reserved window LBA 2016..2047 — 2015 sectors clear of the MBR (LBA 0) and
//! butting against, never entering, the first partition (LBA 2048). Two
//! INDEPENDENT gates protect this: (1) `LbaGuard` here, derived at runtime from
//! the actual MBR; (2) the driver's own one-shot narrowing window (arch `emmc`)
//! or, in tests, the RamDisk's own bounds assert. A store-layer arithmetic bug
//! cannot escape gate (2), and a driver bug cannot escape gate (1).

use hal::BlockDev;

/// Reserved write window (SEALED_STORAGE.md), half-open [lo, hi).
pub const RESERVED_LBA_LO: u64 = 2016;
pub const RESERVED_LBA_HI: u64 = 2048;
/// Minimum acceptable first-partition start (sfdisk 1 MiB alignment).
pub const MIN_PART_LBA: u64 = 2048;
/// MBR partition type marking a GPT protective entry — refuse (we don't parse GPT).
pub const PTYPE_GPT_PROTECTIVE: u8 = 0xEE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardErr {
    /// No 0x55AA boot signature at bytes 510..512.
    NoSignature,
    /// A GPT protective (0xEE) partition entry — this parser handles MBR only.
    GptDetected,
    /// A partition starts below LBA 2048 (would collide with the reserved window).
    PartitionTooLow,
    /// A partition extends beyond the device capacity.
    OutOfCapacity,
    /// No non-empty partition — refuse to guess a layout.
    NoPartition,
    /// The reserved window is not entirely below the first partition.
    WindowOverlap,
    /// Reading LBA 0 failed.
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErr {
    /// Blob does not fit in the reserved window.
    TooBig,
    /// A target LBA is outside the guard window (gate 1 caught it).
    WindowEscape,
    /// A block read/write failed.
    Io,
    /// Read-back did not match what was written.
    VerifyFailed,
}

#[derive(Clone, Copy)]
pub struct Partition {
    pub ptype: u8,
    pub start: u64,
    pub count: u64,
}

/// The runtime-derived write guard: writes are permitted ONLY in [lo, hi).
#[derive(Clone, Copy)]
pub struct LbaGuard {
    pub lo: u64,
    pub hi: u64,
    pub capacity: u64,
    pub first_part: u64,
}

impl LbaGuard {
    #[inline]
    pub fn allows(&self, lba: u64) -> bool {
        lba >= self.lo && lba < self.hi
    }
}

#[inline]
fn le32(b: &[u8], off: usize) -> u64 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as u64
}

/// Parse the four MBR primary-partition entries (bytes 446..510).
pub fn parse_mbr(sector: &[u8; 512]) -> [Partition; 4] {
    let mut parts = [Partition {
        ptype: 0,
        start: 0,
        count: 0,
    }; 4];
    for (i, p) in parts.iter_mut().enumerate() {
        let off = 446 + i * 16;
        p.ptype = sector[off + 4];
        p.start = le32(sector, off + 8);
        p.count = le32(sector, off + 12);
    }
    parts
}

/// Build the write guard from LBA 0, checking every write-safety precondition.
pub fn guard_from_mbr(sector: &[u8; 512], capacity: u64) -> Result<LbaGuard, GuardErr> {
    if sector[510] != 0x55 || sector[511] != 0xAA {
        return Err(GuardErr::NoSignature);
    }
    let parts = parse_mbr(sector);
    let mut first = u64::MAX;
    let mut any = false;
    for p in &parts {
        if p.ptype == PTYPE_GPT_PROTECTIVE {
            return Err(GuardErr::GptDetected);
        }
        let present = p.ptype != 0 || p.count != 0 || p.start != 0;
        if present {
            any = true;
            if p.start < MIN_PART_LBA {
                return Err(GuardErr::PartitionTooLow);
            }
            if p.start.saturating_add(p.count) > capacity {
                return Err(GuardErr::OutOfCapacity);
            }
            if p.start < first {
                first = p.start;
            }
        }
    }
    if !any {
        return Err(GuardErr::NoPartition);
    }
    // The reserved window must be entirely below the first partition.
    if RESERVED_LBA_HI > first {
        return Err(GuardErr::WindowOverlap);
    }
    Ok(LbaGuard {
        lo: RESERVED_LBA_LO,
        hi: RESERVED_LBA_HI,
        capacity,
        first_part: first,
    })
}

/// A sealed store over a block device: opens by reading + guarding the MBR, then
/// exposes a read/scan path (always) and a store path (behind `p15-write`).
pub struct SealedStore<'d, D: BlockDev> {
    dev: &'d mut D,
    guard: LbaGuard,
}

impl<'d, D: BlockDev> SealedStore<'d, D> {
    /// Open the store: read LBA 0, derive + validate the guard.
    pub fn open(dev: &'d mut D) -> Result<Self, GuardErr> {
        let mut mbr = [0u8; 512];
        dev.read_block(0, &mut mbr).map_err(|_| GuardErr::Io)?;
        let cap = dev.block_count();
        let guard = guard_from_mbr(&mbr, cap)?;
        Ok(SealedStore { dev, guard })
    }

    pub fn guard(&self) -> &LbaGuard {
        &self.guard
    }

    /// Scan the reserved window for a `HQKSEAL1` blob and copy it into `out`.
    /// Read-only. Returns the blob length, or None if the window holds no blob.
    pub fn load(&self, out: &mut [u8]) -> Option<usize> {
        let lo = self.guard.lo;
        let mut sec = [0u8; 512];
        if self.dev.read_block(lo, &mut sec).is_err() {
            return None;
        }
        if &sec[..8] != crate::seal::SEAL_MAGIC {
            return None;
        }
        // ct_len is at header offset 68 (little-endian).
        let ct_len = u32::from_le_bytes([sec[68], sec[69], sec[70], sec[71]]) as usize;
        let total = crate::seal::SEAL_HDR_LEN + ct_len;
        if total > out.len() || total > crate::seal::SEAL_MAX_BLOB {
            return None;
        }
        let nsec = total.div_ceil(512) as u64;
        if lo + nsec > self.guard.hi {
            return None;
        }
        for i in 0..nsec {
            let mut s = [0u8; 512];
            if self.dev.read_block(lo + i, &mut s).is_err() {
                return None;
            }
            let off = (i as usize) * 512;
            let n = (total - off).min(512);
            out[off..off + n].copy_from_slice(&s[..n]);
        }
        Some(total)
    }

    /// Store a sealed blob into the reserved window (behind `p15-write`).
    /// Gate 1 (this layer): every target LBA must satisfy the guard AND the hard
    /// reserved clamp. Gate 2 (the device): the driver's own window / RamDisk
    /// bounds assert. Each sector is read back and verified after writing.
    #[cfg(feature = "p15-write")]
    pub fn store(&mut self, blob: &[u8]) -> Result<(), StoreErr> {
        let lo = self.guard.lo;
        let total = blob.len();
        let nsec = total.div_ceil(512) as u64;
        if lo + nsec > self.guard.hi {
            return Err(StoreErr::TooBig);
        }
        for i in 0..nsec {
            let lba = lo + i;
            // Gate 1 — never trust arithmetic: re-check every LBA at the door.
            if !self.guard.allows(lba) || lba < RESERVED_LBA_LO || lba >= RESERVED_LBA_HI {
                return Err(StoreErr::WindowEscape);
            }
            let off = (i as usize) * 512;
            let n = (total - off).min(512);
            let mut s = [0u8; 512];
            s[..n].copy_from_slice(&blob[off..off + n]);
            self.dev.write_block(lba, &s).map_err(|_| StoreErr::Io)?;
            // Read-back verify.
            let mut rb = [0u8; 512];
            self.dev.read_block(lba, &mut rb).map_err(|_| StoreErr::Io)?;
            if rb != s {
                return Err(StoreErr::VerifyFailed);
            }
        }
        Ok(())
    }
}
