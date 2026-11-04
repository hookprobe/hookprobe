//! A/B boot COMMIT that survives a cold boot (BuildPlan M3 / audit B2).
//!
//! The firmware cold-boots whatever `config.txt`'s `kernel=` line names and one-shot trial-boots
//! `tryboot.txt`'s. `ota::confirm` used to update only heqk's keystore record, so after an
//! on-device "commit to B" the NEXT COLD BOOT still ran A — and the next OTA would have staged
//! over the image actually booting. Here the commit changes what the firmware boots:
//!
//! - The image factory names the slots `heqk8-a.img` / `heqk8-b.img` (EQUAL length) and emits
//!   `config.txt` / `tryboot.txt` whose `kernel=` lines differ only in that letter, each line
//!   inside ONE 512-byte sector. So a commit is a same-size, single-sector, in-place rewrite of
//!   each file — no FAT writer, no metadata change (`fat.rs` stays read-only).
//! - ORDER: `config.txt` first (THE commit point — one sector write), then `tryboot.txt`. A power
//!   loss between them leaves both naming the new slot; `plan_repair` detects "trial == active"
//!   at the next boot and re-points `tryboot.txt` at the other slot.
//! - Every write goes through the brick-safety guard as `RegionKind::BootConfig`, registered for
//!   exactly the one sector it rewrites.
//!
//! Locating (`plan_*`, read-only over `&D`) is split from writing (`apply`, through the
//! `SealedStore` that owns the device), because the store holds the device mutably.

use crate::fat;
#[cfg(feature = "p15-write")]
use crate::store::{RegionKind, SealedStore};
use hal::BlockDev;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }
    fn letter(self) -> u8 {
        match self {
            Slot::A => b'a',
            Slot::B => b'b',
        }
    }
    /// The slot image's 8.3 name on the boot partition.
    pub fn file_8_3(self) -> &'static [u8; 11] {
        match self {
            Slot::A => b"HEQK8-A IMG",
            Slot::B => b"HEQK8-B IMG",
        }
    }
}

pub const CONFIG_8_3: &[u8; 11] = b"CONFIG  TXT";
pub const TRYBOOT_8_3: &[u8; 11] = b"TRYBOOT TXT";
const KEY: &[u8] = b"kernel=heqk8-";
const LINE_LEN: usize = 18; // "kernel=heqk8-a.img"
/// Boot configs are a few KiB; refuse anything bigger (fail-closed).
const MAX_CFG_SECTORS: u64 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbErr {
    /// MBR / FAT / file not found, or the file is fragmented.
    NotFound,
    /// No `kernel=heqk8-[ab].img` line (or two of them) — not a factory A/B config.
    NoSlotLine,
    /// The `kernel=` line crosses a sector boundary — refuse a two-sector (non-atomic) rewrite.
    LineSplit,
    Io,
    /// The guard refused the write, or classified it as something other than `BootConfig`.
    Refused,
    /// The rewritten sector did not read back identical.
    Readback,
}

/// Where a config file's slot line lives, and which slot it names.
#[derive(Clone, Copy, Debug)]
pub struct SlotLine {
    pub lba: u64,
    pub offset: usize,
    pub slot: Slot,
    pub sector: [u8; 512],
}

/// Find the `kernel=heqk8-[ab].img` line of `name_8_3` on the partition at `part`.
pub fn locate_line<D: BlockDev>(dev: &D, part: u64, name_8_3: &[u8; 11]) -> Result<SlotLine, AbErr> {
    let (lo, n) = fat::locate_contiguous(dev, part, name_8_3).ok_or(AbErr::NotFound)?;
    if n == 0 || n > MAX_CFG_SECTORS {
        return Err(AbErr::NotFound);
    }
    let mut found: Option<SlotLine> = None;
    let mut sec = [0u8; 512];
    for i in 0..n {
        dev.read_block(lo + i, &mut sec).map_err(|_| AbErr::Io)?;
        // A line split across sectors shows up as a KEY prefix at the end of one sector.
        let tail = &sec[512 - (KEY.len() - 1)..];
        if (1..KEY.len()).any(|k| tail.ends_with(&KEY[..k])) && i + 1 < n {
            return Err(AbErr::LineSplit);
        }
        let mut o = 0usize;
        while let Some(p) = sec[o..].windows(KEY.len()).position(|w| w == KEY) {
            let at = o + p;
            if at + LINE_LEN > 512 {
                return Err(AbErr::LineSplit);
            }
            let line = &sec[at..at + LINE_LEN];
            let slot = match (line[13], &line[14..18]) {
                (b'a', b".img") => Slot::A,
                (b'b', b".img") => Slot::B,
                _ => return Err(AbErr::NoSlotLine),
            };
            // Only an UNCOMMENTED line counts (start of file or after a newline).
            let line_start = at == 0 || sec[at - 1] == b'\n';
            if line_start {
                if found.is_some() {
                    return Err(AbErr::NoSlotLine); // two slot lines: ambiguous, refuse
                }
                found = Some(SlotLine { lba: lo + i, offset: at, slot, sector: sec });
            }
            o = at + LINE_LEN;
        }
    }
    found.ok_or(AbErr::NoSlotLine)
}

/// The slot the firmware COLD-boots (`config.txt`).
pub fn active<D: BlockDev>(dev: &D, part: u64) -> Result<Slot, AbErr> {
    Ok(locate_line(dev, part, CONFIG_8_3)?.slot)
}

/// The slot the firmware one-shot TRIAL-boots (`tryboot.txt`).
pub fn trial<D: BlockDev>(dev: &D, part: u64) -> Result<Slot, AbErr> {
    Ok(locate_line(dev, part, TRYBOOT_8_3)?.slot)
}

/// One sector rewrite: the sector at `lba` with its slot letter changed.
#[derive(Clone, Copy, Debug)]
pub struct Write1 {
    pub lba: u64,
    pub sector: [u8; 512],
}

fn retarget(l: &SlotLine, to: Slot) -> Option<Write1> {
    if l.slot == to {
        return None;
    }
    let mut sector = l.sector;
    sector[l.offset + 13] = to.letter();
    Some(Write1 { lba: l.lba, sector })
}

/// Plan a COMMIT to `new_active`: config.txt → `new_active` (first), tryboot.txt → the other slot.
/// Read-only. Writes that are already in the desired state are omitted (idempotent).
pub fn plan_commit<D: BlockDev>(dev: &D, part: u64, new_active: Slot) -> Result<[Option<Write1>; 2], AbErr> {
    let cfg = locate_line(dev, part, CONFIG_8_3)?;
    let tb = locate_line(dev, part, TRYBOOT_8_3)?;
    Ok([retarget(&cfg, new_active), retarget(&tb, new_active.other())])
}

/// Plan the boot-time REPAIR of an interrupted commit: if tryboot.txt names the active slot (power
/// lost between the two commit writes), re-point it at the other slot. `None` = consistent.
pub fn plan_repair<D: BlockDev>(dev: &D, part: u64) -> Result<Option<Write1>, AbErr> {
    let cfg = locate_line(dev, part, CONFIG_8_3)?;
    let tb = locate_line(dev, part, TRYBOOT_8_3)?;
    Ok(if tb.slot == cfg.slot { retarget(&tb, cfg.slot.other()) } else { None })
}

/// Apply planned writes IN ORDER through the guard (write path: `p15-write` builds only). Each sector is registered as `BootConfig`
/// for exactly that LBA, must be classified as such, and must read back identical.
#[cfg(feature = "p15-write")]
pub fn apply<D: BlockDev>(store: &mut SealedStore<D>, writes: &[Option<Write1>]) -> Result<usize, AbErr> {
    let mut n = 0;
    for w in writes.iter().flatten() {
        if store.guard().region_of(w.lba) != Some(RegionKind::BootConfig) {
            store.add_region(w.lba, w.lba + 1, RegionKind::BootConfig).map_err(|_| AbErr::Refused)?;
        }
        match store.store_sector(w.lba, &w.sector) {
            Ok(RegionKind::BootConfig) => {}
            _ => return Err(AbErr::Refused),
        }
        let mut back = [0u8; 512];
        store.read_sector(w.lba, &mut back).map_err(|_| AbErr::Io)?;
        if back != w.sector {
            return Err(AbErr::Readback);
        }
        n += 1;
    }
    Ok(n)
}

/// The driver's Gate-1 content rule (`hal::is_slot_letter_flip`) against fixed vectors: only a
/// single a<->b flip of the one uncommented `kernel=heqk8-?.img` line is ever writable.
pub fn content_rule_vectors() -> bool {
    fn sec(text: &[u8]) -> [u8; 512] {
        let mut s = [0u8; 512];
        s[..text.len()].copy_from_slice(text);
        s
    }
    let cur = sec(b"# heqk\nkernel=heqk8-a.img\narm_64bit=1\n");
    let p = 7 + 13;
    let mut flip = cur;
    flip[p] = b'b';
    let mut flip_plus = flip;
    flip_plus[40] = b'X';
    let mut other = cur;
    other[2] = b'X';
    let mut to_c = cur;
    to_c[p] = b'c';
    let commented = sec(b"#kernel=heqk8-a.img\n");
    let mut commented_flip = commented;
    commented_flip[14] = b'b';
    let two = sec(b"kernel=heqk8-a.img\nkernel=heqk8-a.img\n");
    let mut two_flip = two;
    two_flip[13] = b'b';
    hal::slot_line_letter(&cur) == Some(p)
        && hal::is_slot_letter_flip(&cur, &flip)
        && hal::is_slot_letter_flip(&flip, &cur)
        && !hal::is_slot_letter_flip(&cur, &cur)
        && !hal::is_slot_letter_flip(&cur, &flip_plus)
        && !hal::is_slot_letter_flip(&cur, &other)
        && !hal::is_slot_letter_flip(&cur, &to_c)
        && !hal::is_slot_letter_flip(&commented, &commented_flip)
        && !hal::is_slot_letter_flip(&two, &two_flip)
}

/// `[P15-abcommit]` — TWO-BOOT proof over a factory-layout FAT boot partition (virtio-blk,
/// p15-write). The disk's own state says which boot this is:
/// - boot 1 (config=A, tryboot=B): commit to B but write ONLY config.txt — a simulated power loss
///   between the two commit writes;
/// - boot 2 (config=B, tryboot=B — the crash state, read back from the disk after a real reboot):
///   the repair must re-point tryboot.txt at A; then a FULL commit back to A must leave config=A,
///   tryboot=B. PASS = the commit survived the reboot AND the interrupted commit was repaired.
#[cfg(all(not(feature = "cm5"), feature = "p15-write"))]
pub fn abcommit_selftest() {
    macro_rules! kprint { ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) }; }
    let Some(mut dev) = arch_aarch64::virtio_blk::VirtioBlk::open() else {
        kprint!(" [P15-abcommit] SKIP — no virtio-blk device\n");
        return;
    };
    let mut mbr = [0u8; 512];
    if dev.read_block(0, &mut mbr).is_err() {
        kprint!(" [P15-abcommit] SKIP — MBR read failed\n");
        return;
    }
    let p1 = crate::store::parse_mbr(&mbr)[0].start;
    let (a, t) = match (active(&dev, p1), trial(&dev, p1)) {
        (Ok(a), Ok(t)) => (a, t),
        _ => {
            kprint!(" [P15-abcommit] SKIP — no factory A/B boot config on this disk\n");
            return;
        }
    };
    match (a, t) {
        (Slot::A, Slot::B) => {
            let plan = match plan_commit(&dev, p1, Slot::B) {
                Ok(p) => p,
                Err(e) => return kprint!(" [P15-abcommit] FAIL — plan_commit: {:?}\n", e),
            };
            let mut store = match SealedStore::open(&mut dev) {
                Ok(s) => s,
                Err(e) => return kprint!(" [P15-abcommit] FAIL — guard: {:?}\n", e),
            };
            // Apply ONLY the first write (config.txt, the commit point): power "lost" before tryboot.
            match apply(&mut store, &plan[..1]) {
                Ok(1) => kprint!(" [P15-abcommit] boot 1: committed config.txt -> B, power lost before tryboot.txt (simulated); reboot next\n"),
                r => kprint!(" [P15-abcommit] FAIL — boot-1 apply: {:?}\n", r),
            }
        }
        (Slot::B, Slot::B) => {
            // The commit SURVIVED the reboot (cold boot now names B); repair the half-done commit.
            let repaired = match plan_repair(&dev, p1) {
                Ok(Some(w)) => {
                    let mut store = match SealedStore::open(&mut dev) {
                        Ok(s) => s,
                        Err(e) => return kprint!(" [P15-abcommit] FAIL — guard: {:?}\n", e),
                    };
                    apply(&mut store, &[Some(w)]) == Ok(1)
                }
                r => return kprint!(" [P15-abcommit] FAIL — repair plan: {:?}\n", r),
            };
            let after_repair = (active(&dev, p1), trial(&dev, p1)) == (Ok(Slot::B), Ok(Slot::A));
            // A FULL commit back to A (both writes).
            let full = match plan_commit(&dev, p1, Slot::A) {
                Ok(plan) => match SealedStore::open(&mut dev) {
                    Ok(mut store) => apply(&mut store, &plan) == Ok(2),
                    Err(_) => false,
                },
                Err(_) => false,
            };
            let after_full = (active(&dev, p1), trial(&dev, p1)) == (Ok(Slot::A), Ok(Slot::B));
            // Idempotence: committing to the already-active slot writes nothing.
            let idem = plan_commit(&dev, p1, Slot::A).map(|p| p.iter().all(|w| w.is_none())) == Ok(true);
            let rule = content_rule_vectors();
            let pass = repaired && after_repair && full && after_full && idem && rule;
            kprint!(" [P15-abcommit] {} — A/B commit survives a cold boot: boot-2 cold-boot slot = B (the commit persisted across a real reboot), interrupted commit repaired (tryboot re-pointed)={} full commit back to A={} (config=A, tryboot=B: {}), idempotent={}, driver content rule (only a single a<->b slot-letter flip writable)={}; every write a single in-place sector through the guard as BootConfig\n",
                if pass { "PASS" } else { "FAIL" }, repaired && after_repair, full, after_full, idem, rule);
        }
        other => kprint!(" [P15-abcommit] FAIL — unexpected disk state (active, trial) = {:?}\n", other),
    }
}

/// `[P15-abcommit-metal]` — the SAME two-boot proof on the CM5's real eMMC, with a real power
/// cycle between the boots (bench feature `abcommit-metal`; it rewrites config.txt/tryboot.txt on
/// every boot, so it is never shipped — reflash the production image afterwards). Both slots hold
/// the same signed image, so whichever one the firmware cold-boots is a valid heqk.
///
/// Every write goes through BOTH guards: the store layer (`RegionKind::BootConfig`, exactly that
/// sector) and the driver's independent Gate 1 (`admit_boot_config`: p1 FAT data area, one-shot,
/// content-pinned to a single a<->b slot-letter flip). Boot 1 also proves the driver REFUSES:
/// admitting LBA 0 / the FAT32 boot sector / the root directory, and a write to a config sector
/// that was never admitted (identical content, so a wrong accept would be harmless).
#[cfg(all(feature = "cm5", feature = "abcommit-metal"))]
pub fn abcommit_metal_selftest() {
    macro_rules! kprint { ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) }; }
    use arch_aarch64::emmc::Emmc;
    let mut dev = match Emmc::probe() {
        Ok(d) => d,
        Err(e) => return kprint!(" [P15-abcommit-metal] SKIP — eMMC probe failed: {:?}\n", e),
    };
    let mut mbr = [0u8; 512];
    if dev.read_block(0, &mut mbr).is_err() {
        return kprint!(" [P15-abcommit-metal] FAIL — MBR read failed\n");
    }
    let p1 = crate::store::parse_mbr(&mbr)[0].start;
    let (a, t) = match (active(&dev, p1), trial(&dev, p1)) {
        (Ok(a), Ok(t)) => (a, t),
        r => return kprint!(" [P15-abcommit-metal] FAIL — no factory A/B config on the eMMC: {:?}\n", r),
    };
    kprint!(" [P15-abcommit-metal] eMMC boot config: config.txt -> {:?}, tryboot.txt -> {:?}\n", a, t);
    let rule = content_rule_vectors();
    // Admit + apply each planned write through both guards.
    fn admit_apply(dev: &mut Emmc, writes: &[Option<Write1>]) -> Result<usize, AbErr> {
        for w in writes.iter().flatten() {
            if !dev.admit_boot_config(w.lba) {
                return Err(AbErr::Refused);
            }
        }
        let mut store = SealedStore::open(dev).map_err(|_| AbErr::Refused)?;
        apply(&mut store, writes)
    }
    match (a, t) {
        (Slot::A, Slot::B) => {
            // Negative driver checks first (no write lands if they behave; harmless if not).
            let lba0 = !dev.admit_boot_config(0);
            let bpb = !dev.admit_boot_config(p1);
            let cfg = match locate_line(&dev, p1, CONFIG_8_3) {
                Ok(l) => l,
                Err(e) => return kprint!(" [P15-abcommit-metal] FAIL — locate config.txt: {:?}\n", e),
            };
            let unadmitted = dev.write_block(cfg.lba, &cfg.sector).is_err();
            let plan = match plan_commit(&dev, p1, Slot::B) {
                Ok(p) => p,
                Err(e) => return kprint!(" [P15-abcommit-metal] FAIL — plan_commit: {:?}\n", e),
            };
            let wrote = admit_apply(&mut dev, &plan[..1]);
            // The admission was one-shot: re-writing the ORIGINAL sector now must be refused.
            let oneshot = dev.write_block(cfg.lba, &cfg.sector).is_err();
            let now = active(&dev, p1);
            let ok = lba0 && bpb && unadmitted && wrote == Ok(1) && oneshot && now == Ok(Slot::B) && rule;
            kprint!(" [P15-abcommit-metal] boot 1: {} — committed config.txt -> B on the eMMC (power lost before tryboot.txt, simulated); driver refused LBA0={} BPB={} un-admitted write={} reuse of a spent admission={}; content rule={}. POWER-CYCLE NOW: the firmware must cold-boot slot B\n",
                if ok { "OK" } else { "FAIL" }, lba0, bpb, unadmitted, oneshot, rule);
        }
        (Slot::B, Slot::B) => {
            let repaired = match plan_repair(&dev, p1) {
                Ok(Some(w)) => admit_apply(&mut dev, &[Some(w)]) == Ok(1),
                r => return kprint!(" [P15-abcommit-metal] FAIL — repair plan: {:?}\n", r),
            };
            let after_repair = (active(&dev, p1), trial(&dev, p1)) == (Ok(Slot::B), Ok(Slot::A));
            let full = match plan_commit(&dev, p1, Slot::A) {
                Ok(plan) => admit_apply(&mut dev, &plan) == Ok(2),
                Err(_) => false,
            };
            let after_full = (active(&dev, p1), trial(&dev, p1)) == (Ok(Slot::A), Ok(Slot::B));
            let idem = plan_commit(&dev, p1, Slot::A).map(|p| p.iter().all(|w| w.is_none())) == Ok(true);
            let pass = repaired && after_repair && full && after_full && idem && rule;
            kprint!(" [P15-abcommit-metal] {} — A/B commit survives a REAL power cycle on CM5 eMMC: this cold boot ran slot B (config.txt committed on the previous boot), interrupted commit repaired={} full commit back to A={} (config=A, tryboot=B: {}), idempotent={}, content rule={}; every write through the store guard AND the driver's content-pinned one-shot Gate 1\n",
                if pass { "PASS" } else { "FAIL" }, repaired && after_repair, full, after_full, idem, rule);
        }
        other => kprint!(" [P15-abcommit-metal] FAIL — unexpected eMMC state (active, trial) = {:?}\n", other),
    }
}
