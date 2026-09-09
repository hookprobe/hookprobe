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
#[cfg(feature = "p15-write")]
use hal::BlockErr; // only the guarded write path maps the driver's gate-2 refusal

/// Reserved write window (SEALED_STORAGE.md), half-open [lo, hi).
pub const RESERVED_LBA_LO: u64 = 2016;
pub const RESERVED_LBA_HI: u64 = 2048;
/// Minimum acceptable first-partition start (sfdisk 1 MiB alignment).
pub const MIN_PART_LBA: u64 = 2048;
/// MBR partition type marking a GPT protective entry — refuse (we don't parse GPT).
pub const PTYPE_GPT_PROTECTIVE: u8 = 0xEE;
/// MBR partition type marking the heqk DataVolume (raw log store: evidence graph, QSecBit
/// history, reach-floor). 0xDA = "Non-FS data" — a raw, filesystem-less partition, exactly
/// what the log-structured DataVolume store wants. The image factory / provisioning sets it.
pub const PTYPE_DATAVOLUME: u8 = 0xDA;

/// Find the heqk DataVolume partition (MBR type 0xDA) and return its `[start, start+count)` LBA
/// range, or `None` if there is no such partition. The kernel registers this as the writable
/// DataVolume region (`SealedStore::add_region` + `emmc::set_data_volume`) instead of a
/// hardcoded LBA — the partition table is now the single source of truth for the layout.
pub fn datavolume_from_mbr(sector: &[u8; 512]) -> Option<(u64, u64)> {
    for p in parse_mbr(sector).iter() {
        if p.ptype == PTYPE_DATAVOLUME && p.count != 0 && p.start >= MIN_PART_LBA {
            return Some((p.start, p.start.saturating_add(p.count)));
        }
    }
    None
}

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

/// M3.0 — the kind of a WRITABLE region in the multi-region allowlist. Every
/// writable byte on the device belongs to exactly one of these; nothing else is
/// writable (allowlist, never denylist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// The 16 KiB sealing-key window in the MBR alignment gap (LBA 2016..2047) —
    /// key material only (the existing P15 keystore).
    Keystore,
    /// The persistent data partition: evidence graph + QSecBit history (M3).
    DataVolume,
    /// The INACTIVE A/B boot slot — OTA stages a candidate here; the ACTIVE slot
    /// is never registered, so it is refused by default (brick-safety).
    InactiveSlot,
}

/// A half-open writable region [lo, hi).
#[derive(Clone, Copy)]
pub struct Region {
    pub lo: u64,
    pub hi: u64,
    pub kind: RegionKind,
}
impl Region {
    #[inline]
    fn contains(&self, lba: u64) -> bool {
        lba >= self.lo && lba < self.hi
    }
}

/// Max writable regions (keystore + data volume + inactive slot + one spare).
pub const MAX_REGIONS: usize = 4;

/// The runtime-derived write guard (M3.0 multi-region allowlist). `lo`/`hi` keep
/// naming the keystore window for the existing single-blob store()/load() path;
/// `regions` is the strict allowlist that authorizes every OTHER guarded write.
/// A write is permitted ONLY if its LBA falls inside a REGISTERED region — LBA 0
/// (MBR / partition table), the active boot slot, the active FAT partition, and
/// every unregistered gap stay `WriteRefused` by construction.
#[derive(Clone, Copy)]
pub struct LbaGuard {
    pub lo: u64,
    pub hi: u64,
    pub capacity: u64,
    // The first partition's start + length — the anchor the M3.2 FS/OTA layout
    // layer reads to size the data volume / place the A/B slots. Carried now so
    // that layer needs no MBR re-parse; not read inside the kernel yet.
    #[allow(dead_code)]
    pub first_part: u64,
    #[allow(dead_code)]
    pub first_part_count: u64,
    regions: [Region; MAX_REGIONS],
    nregions: usize,
}

impl LbaGuard {
    /// The ONE predicate that authorizes a write. Allowlist: true iff `lba` lies
    /// in a registered writable region — and NEVER LBA 0 (MBR/partition table),
    /// however a region were mis-registered. Everything unregistered is refused.
    #[inline]
    pub fn allows(&self, lba: u64) -> bool {
        if lba == 0 {
            return false; // MBR / partition table — never writable, defensively
        }
        for r in &self.regions[..self.nregions] {
            if r.contains(lba) {
                return true;
            }
        }
        false
    }

    /// Which region kind owns `lba`, or None if it is not writable.
    #[inline]
    pub fn region_of(&self, lba: u64) -> Option<RegionKind> {
        if lba == 0 {
            return None;
        }
        for r in &self.regions[..self.nregions] {
            if r.contains(lba) {
                return Some(r.kind);
            }
        }
        None
    }

    /// Register a writable region (chainable builder). Refuses: LBA 0 inclusion,
    /// an empty/inverted range, a range past capacity, an overlap with any
    /// already-registered region, or exceeding MAX_REGIONS. A conflict is refused
    /// (fail-closed) rather than silently clamped — a bad layout must not weaken
    /// the guard.
    pub fn with_region(mut self, lo: u64, hi: u64, kind: RegionKind) -> Result<Self, GuardErr> {
        if lo == 0 || hi <= lo || hi > self.capacity {
            return Err(GuardErr::WindowOverlap);
        }
        if self.nregions >= MAX_REGIONS {
            return Err(GuardErr::WindowOverlap);
        }
        for r in &self.regions[..self.nregions] {
            // Overlap iff the ranges intersect.
            if lo < r.hi && r.lo < hi {
                return Err(GuardErr::WindowOverlap);
            }
        }
        self.regions[self.nregions] = Region { lo, hi, kind };
        self.nregions += 1;
        Ok(self)
    }

    /// Number of registered writable regions (for tests/logging).
    #[inline]
    pub fn region_count(&self) -> usize {
        self.nregions
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
    let mut first_count = 0u64;
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
                first_count = p.count;
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
    let mut g = LbaGuard {
        lo: RESERVED_LBA_LO,
        hi: RESERVED_LBA_HI,
        capacity,
        first_part: first,
        first_part_count: first_count,
        regions: [Region {
            lo: 0,
            hi: 0,
            kind: RegionKind::Keystore,
        }; MAX_REGIONS],
        nregions: 0,
    };
    // Region 0 is ALWAYS the keystore window — the one region present on every
    // device, in the alignment gap below the first partition.
    g.regions[0] = Region {
        lo: RESERVED_LBA_LO,
        hi: RESERVED_LBA_HI,
        kind: RegionKind::Keystore,
    };
    g.nregions = 1;
    Ok(g)
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

    /// M3.0 — register an additional writable region (data volume / inactive slot)
    /// into this store's guard. The layout module supplies these from the on-disk
    /// layout; overlap with LBA 0, the keystore, or an existing region is refused.
    pub fn add_region(&mut self, lo: u64, hi: u64, kind: RegionKind) -> Result<(), GuardErr> {
        self.guard = self.guard.with_region(lo, hi, kind)?;
        Ok(())
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

    /// Read one 512-byte sector at `lba` (always available — reads are never
    /// guarded). Thin pass-through so callers persisting the data volume / an OTA
    /// slot go through the store, not the raw device.
    pub fn read_sector(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), StoreErr> {
        self.dev.read_block(lba, buf).map_err(|_| StoreErr::Io)
    }

    /// M3.0 — write one sector to a REGISTERED writable region (behind
    /// `p15-write`). Gate 1: `region_of(lba)` must resolve (the allowlist); a
    /// write outside every registered region — LBA 0, the active slot, the active
    /// partition, any gap — is `WindowEscape`.
    ///
    /// Gate 2 — the device driver's OWN independent refusal — differs by backend and
    /// is reported HONESTLY: virtio-blk (QEMU) refuses only LBA 0, so above LBA 0 the
    /// allowlist is the sole gate; the current eMMC scaffold (metal) hard-clamps to the
    /// reserved KEYSTORE window [2016,2048) — so a DataVolume/InactiveSlot/OTA write on
    /// real eMMC returns `BlockErr::WriteRefused`, which we surface as the DISTINCT
    /// `StoreErr::WindowEscape` (a region the driver won't take), NOT a generic `Io`
    /// fault, so a metal "region unsupported" failure is never disguised. The real
    /// multi-region eMMC driver (arming the full registered layout as gate 2) is Gate-R
    /// metal work — see docs/design/heqk-persistence.md. Read-back verified on success.
    #[cfg(feature = "p15-write")]
    pub fn store_sector(&mut self, lba: u64, buf: &[u8; 512]) -> Result<RegionKind, StoreErr> {
        let kind = match self.guard.region_of(lba) {
            Some(k) => k,
            None => return Err(StoreErr::WindowEscape),
        };
        self.dev.write_block(lba, buf).map_err(|e| match e {
            // Gate-2 driver refusal (e.g. the eMMC reserved-window clamp) is a WINDOW
            // decision, not an I/O fault — keep it distinct so metal failures are honest.
            BlockErr::WriteRefused => StoreErr::WindowEscape,
            _ => StoreErr::Io,
        })?;
        let mut rb = [0u8; 512];
        self.dev.read_block(lba, &mut rb).map_err(|_| StoreErr::Io)?;
        if &rb != buf {
            return Err(StoreErr::VerifyFailed);
        }
        Ok(kind)
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
            self.dev.write_block(lba, &s).map_err(|e| match e {
                BlockErr::WriteRefused => StoreErr::WindowEscape,
                _ => StoreErr::Io,
            })?;
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
