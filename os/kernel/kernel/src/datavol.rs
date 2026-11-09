//! #54 — the DataVolume region registry: ONE fixed layout for the raw p2 partition (MBR type 0xDA, created by
//! the image factory over the rest of the eMMC), so every writer has its own named, bounded region instead of
//! picking LBAs ad hoc (BOI adversarial review A3.2) — and the 16 KiB keystore window stops being the only
//! durable home on metal.
//!
//! The eMMC driver's gates are unchanged: Gate 1 admits the reserved keystore window or the registered
//! DataVolume, Gate 2 is a one-shot NARROWING window. Each consumer arms Gate 2 with `region()` of ITS region
//! only, so a bug in one consumer cannot write another's region.
//!
//! Layout (sectors, relative to the partition start):
//!
//! | Region | Offset | Size | Writer |
//! |---|---|---|---|
//! | `ReachFloor` | 0 | 16 | segmentation reach-floor log (existing, M4.5) |
//! | (reserved) | 16 | 2032 | bench self-tests (offset 1024, p15-bench) — never a product writer |
//! | `Header` | 2048 | 8 | layout magic + version (format-on-first-use) |
//! | `Journal` | 4096 | 512 | ADR 0055 owner policy journal (append area + A/B checkpoints), 256 KiB |
//! | `Store` | 8192 | 2 x 56 MiB | ADR 0056 artifact store: A/B slot per artifact type + manifest |
//! | `Staging` | after Store | 20 MiB | ADR 0056 upload staging |
//! | `Evidence` | after Staging | the rest (>= 64 MiB) | M3 evidence log (fslog) |

/// Sector offsets / sizes inside the partition. `const` so the layout is reviewable in one place.
pub const REACH_FLOOR: (u64, u64) = (0, 16);
pub const HEADER: (u64, u64) = (2048, 8);
pub const JOURNAL: (u64, u64) = (4096, 512);
pub const STORE_SLOT_SECT: u64 = 56 * 2048; // 56 MiB per A/B half: every ADR 0056 type at its cap, with room
pub const STORE: (u64, u64) = (8192, 2 * STORE_SLOT_SECT);
pub const STAGING: (u64, u64) = (STORE.0 + STORE.1, 20 * 2048);
pub const EVIDENCE_OFF: u64 = STAGING.0 + STAGING.1;
pub const EVIDENCE_MIN: u64 = 64 * 2048;
/// Smallest DataVolume the registry accepts (a CM5 eMMC is >= 8 GB; the factory gives p2 the rest of it).
pub const MIN_SECT: u64 = EVIDENCE_OFF + EVIDENCE_MIN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    ReachFloor,
    Header,
    Journal,
    Store,
    Staging,
    Evidence,
}

/// The DataVolume partition as found in the MBR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataVol {
    start: u64,
    sect: u64,
}

impl DataVol {
    /// From the MBR sector: the 0xDA partition, if it exists and is big enough for the whole layout.
    pub fn from_mbr(mbr: &[u8; 512]) -> Option<DataVol> {
        let (lo, hi) = crate::store::datavolume_from_mbr(mbr)?;
        let sect = hi - lo;
        (sect >= MIN_SECT).then_some(DataVol { start: lo, sect })
    }

    /// The ABSOLUTE `[lo, hi)` LBA range of a region (always inside the partition).
    pub fn region(&self, r: Region) -> (u64, u64) {
        let (off, len) = match r {
            Region::ReachFloor => REACH_FLOOR,
            Region::Header => HEADER,
            Region::Journal => JOURNAL,
            Region::Store => STORE,
            Region::Staging => STAGING,
            Region::Evidence => (EVIDENCE_OFF, self.sect - EVIDENCE_OFF),
        };
        (self.start + off, self.start + off + len)
    }

    /// The whole partition (what `emmc::set_data_volume` registers as Gate-1's second region).
    pub fn bounds(&self) -> (u64, u64) {
        (self.start, self.start + self.sect)
    }
}

/// `[P-datavol]`
pub fn selftest() -> bool {
    let mut mbr = [0u8; 512];
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    let part = |m: &mut [u8; 512], i: usize, ptype: u8, start: u32, count: u32| {
        let e = 446 + 16 * i;
        m[e + 4] = ptype;
        m[e + 8..e + 12].copy_from_slice(&start.to_le_bytes());
        m[e + 12..e + 16].copy_from_slice(&count.to_le_bytes());
    };
    // p1 FAT32 64 MiB @8192, p2 0xDA = the rest of an 8 GB eMMC
    part(&mut mbr, 0, 0x0c, 8192, 131_072);
    let p2 = 8192 + 131_072;
    part(&mut mbr, 1, 0xDA, p2, 15_000_000);
    let dv = DataVol::from_mbr(&mbr);
    let found = dv.map(|d| d.bounds()) == Some((p2 as u64, p2 as u64 + 15_000_000));
    let regions = [Region::ReachFloor, Region::Header, Region::Journal, Region::Store, Region::Staging, Region::Evidence];
    let (mut inside, mut disjoint) = (true, true);
    if let Some(d) = dv {
        let (blo, bhi) = d.bounds();
        for (i, a) in regions.iter().enumerate() {
            let (alo, ahi) = d.region(*a);
            inside &= alo >= blo && ahi <= bhi && alo < ahi;
            for b in &regions[i + 1..] {
                let (clo, chi) = d.region(*b);
                disjoint &= ahi <= clo || chi <= alo;
            }
        }
        // the existing reach-floor home is unchanged: the first 16 sectors of the partition
        inside &= d.region(Region::ReachFloor) == (blo, blo + 16);
    }
    // too small, wrong type, no partition: refused
    let mut small = mbr;
    part(&mut small, 1, 0xDA, p2, (MIN_SECT - 1) as u32);
    let mut wrong = mbr;
    part(&mut wrong, 1, 0x83, p2, 15_000_000);
    let refused = DataVol::from_mbr(&small).is_none() && DataVol::from_mbr(&wrong).is_none();
    let pass = found && inside && disjoint && refused;
    arch_aarch64::_print(format_args!(
        " [P-datavol] {} — #54 DataVolume region registry (one fixed layout in the 0xDA partition: reach-floor, header, owner journal, artifact store A/B, upload staging, evidence log): found from the MBR={} every region inside the partition={} regions disjoint={} too-small / wrong-type refused={} (min {} MiB)\n",
        if pass { "PASS" } else { "FAIL" }, found, inside, disjoint, refused, MIN_SECT / 2048
    ));
    pass
}
