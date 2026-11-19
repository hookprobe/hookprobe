// SPDX-License-Identifier: AGPL-3.0-only
//! #54 — the evidence log on the AP image: every detection is kept, SEALED, in a bounded ring in the
//! DataVolume `Evidence` region (fslog M3.2 framing + M3.3 HQKSEAL1 records), so Mission Control's history
//! survives a power cycle well beyond the 64-event G12 snapshot.
//!
//! * Region: the first `EVLOG_SECT` sectors of `Evidence` (superblock + `EVLOG_SECT - 1` record slots); a ring,
//!   oldest overwritten — bounded boot scan, honest retention (the count of evicted records is reported).
//! * Records: up to `PER_REC` 16-byte event images (the snapshot / export image, `IMG_EPOCH` = wall-clock ms)
//!   sealed under a volume key `HKDF(SRK, "HQ-evidence-log-v1")` bound to the boot measurement policy — a raw
//!   read of the eMMC yields ciphertext; an edit fails the seal and the record is dropped (fail-closed).
//! * Wear: events are batched in RAM and written when a record fills, or at most once a minute.
//! * Time: a batch waits for the wall clock (SNTP) so its events carry real time; a full batch before any
//!   clock is written with "time unknown" (never a fake time).

use crate::export::EV_IMAGE_LEN;
use crate::fslog::{self, LogStore, SealCtx, MAX_SEALED_PAYLOAD, RT_EVIDENCE, RT_EVIDENCE_B, RT_EVIDENCE_C};
use crate::seal::Policy;
use crate::snapshot::IMG_EPOCH;
use crate::store::SealedStore;
use hal::BlockDev;

/// 1 superblock + 4096 record slots (2 MiB): ~82k detections at 20 per record (it was 21 before each record also
/// named the configuration in force, ADR 0067 D10). Bounded by the boot scan (every
/// slot is read at mount): ~1.5 s at the 25 MHz data clock (it was 22 s at the old 390 kHz clock, 2026-11-09).
pub const EVLOG_SECT: u64 = 4097;
pub const PER_REC: usize = (MAX_SEALED_PAYLOAD - BUILD_TAG_LEN - PROV_LEN) / EV_IMAGE_LEN; // 20 (+ build tag + provenance)
/// Bytes of the build tag at the head of an `RT_EVIDENCE_B` / `RT_EVIDENCE_C` record.
pub const BUILD_TAG_LEN: usize = 16;
/// Bytes of provenance after the build tag in an `RT_EVIDENCE_C` record.
pub const PROV_LEN: usize = 16;

/// The configuration a batch of detections was made under (ADR 0067 D10): the sealed-config generation and the
/// first 8 bytes of the SHA-256 of the config bundle in force. The detection rules are part of the build, which the
/// build tag names. `UNKNOWN` (all ones) = not recorded: a record written before provenance existed, a batch whose
/// configuration changed before it could be written, or a boot that has not told the log yet. Never a guess.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Prov {
    pub cfg_gen: u64,
    pub cfg: [u8; 8],
}
impl Prov {
    pub const UNKNOWN: Prov = Prov { cfg_gen: u64::MAX, cfg: [0xff; 8] };
    /// What cfgd has in force now (generation 0 with a zero digest = no sealed bundle: the built-in defaults).
    pub fn current() -> Prov {
        let d = crate::cfgd::bundle_digest();
        Prov { cfg_gen: crate::cfgd::generation(), cfg: d[..8].try_into().unwrap() }
    }
    fn to_bytes(self) -> [u8; PROV_LEN] {
        let mut b = [0u8; PROV_LEN];
        b[..8].copy_from_slice(&self.cfg_gen.to_le_bytes());
        b[8..].copy_from_slice(&self.cfg);
        b
    }
    fn from_bytes(b: &[u8]) -> Prov {
        Prov { cfg_gen: u64::from_le_bytes(b[..8].try_into().unwrap()), cfg: b[8..16].try_into().unwrap() }
    }
}

/// This build's evidence tag: `HEQK_BUILD_ID` (first 16 bytes), zero-padded; all zero when the build has no id.
pub fn build_tag() -> [u8; BUILD_TAG_LEN] {
    let mut t = [0u8; BUILD_TAG_LEN];
    if let Some(b) = option_env!("HEQK_BUILD_ID") {
        let n = b.len().min(BUILD_TAG_LEN);
        t[..n].copy_from_slice(&b.as_bytes()[..n]);
    }
    t
}
const FLUSH_S: u64 = 60;

/// The log's RAM side: the volume key, the pending batch, counters.
pub struct EvLog {
    pub log: LogStore,
    vek: [u8; 32],
    policy: Policy,
    pend: [[u8; EV_IMAGE_LEN]; PER_REC],
    npend: usize,
    /// The configuration in force now, and the one the pending batch belongs to.
    prov: Prov,
    pend_prov: Prov,
    last_flush_s: u64,
    pub written: u64,
    pub failed: u64,
}

/// EVID-01 (decision C): the seal policy of the evidence log and the snapshot — device id only. `Policy::digest` hashes
/// the floor and the selected PCRs, so both are zeroed here: a later build, a rollback or a raised floor derives the
/// SAME key and reads the history (it was STRICT = PCR0|1|2 + floor: every OTA opened an empty log, MB16).
pub fn evidence_policy(device_id: u64) -> Policy {
    Policy { mask: boot_abi::SEAL_POLICY_DEVICE, device_id, svn_floor: 0, pcr: [[0u8; 32]; boot_abi::NUM_PCR] }
}

pub fn vek_of(srk: &[u8; 32]) -> [u8; 32] {
    let prk = boot_abi::kdf::hkdf_extract(b"HQ-evidence-log", srk);
    boot_abi::kdf::hkdf_expand32(&prk, b"HQ-evidence-log-v1")
}

impl EvLog {
    /// Mount (sealed) or format the ring at `[lo, lo + EVLOG_SECT)`.
    #[cfg(feature = "p15-write")]
    pub fn open<D: BlockDev>(store: &mut SealedStore<D>, lo: u64, hi: u64, srk: &[u8; 32], policy: Policy) -> Result<EvLog, fslog::FsErr> {
        let vek = vek_of(srk);
        let log = match LogStore::mount_sealed(store, &SealCtx { vek: &vek, policy: &policy }, lo, hi) {
            Ok(l) => l,
            Err(fslog::FsErr::NotFormatted) => fslog::format(store, lo, hi)?,
            Err(e) => return Err(e),
        };
        Ok(EvLog { log, vek, policy, pend: [[0; EV_IMAGE_LEN]; PER_REC], npend: 0, prov: Prov::UNKNOWN, pend_prov: Prov::UNKNOWN, last_flush_s: 0, written: 0, failed: 0 })
    }

    /// Every stored event, oldest first: `cb(build tag, image)`. The tag is all zero for records written before
    /// evidence was tagged (`RT_EVIDENCE`): "unknown build", never a guessed one.
    pub fn for_each<D: BlockDev>(&self, store: &SealedStore<D>, cb: &mut dyn FnMut(&[u8; BUILD_TAG_LEN], &[u8; EV_IMAGE_LEN])) -> u64 {
        self.for_each_prov(store, &mut |tag, _, img| cb(tag, img))
    }

    /// `for_each` plus the configuration each event was made under: `cb(build tag, provenance, image)`.
    /// `Prov::UNKNOWN` for records written before provenance was recorded (`RT_EVIDENCE`, `RT_EVIDENCE_B`).
    pub fn for_each_prov<D: BlockDev>(&self, store: &SealedStore<D>, cb: &mut dyn FnMut(&[u8; BUILD_TAG_LEN], &Prov, &[u8; EV_IMAGE_LEN])) -> u64 {
        const HEAD_C: usize = BUILD_TAG_LEN + PROV_LEN;
        let mut n = 0u64;
        let _ = self.log.for_each_sealed(store, &SealCtx { vek: &self.vek, policy: &self.policy }, |_, rt, pt| {
            let (tag, prov, body) = match rt {
                RT_EVIDENCE => ([0u8; BUILD_TAG_LEN], Prov::UNKNOWN, pt),
                RT_EVIDENCE_B if pt.len() >= BUILD_TAG_LEN => (pt[..BUILD_TAG_LEN].try_into().unwrap(), Prov::UNKNOWN, &pt[BUILD_TAG_LEN..]),
                RT_EVIDENCE_C if pt.len() >= HEAD_C => (pt[..BUILD_TAG_LEN].try_into().unwrap(), Prov::from_bytes(&pt[BUILD_TAG_LEN..HEAD_C]), &pt[HEAD_C..]),
                _ => return,
            };
            for c in body.chunks_exact(EV_IMAGE_LEN) {
                let img: &[u8; EV_IMAGE_LEN] = c.try_into().unwrap();
                cb(&tag, &prov, img);
                n += 1;
            }
        });
        n
    }

    /// Tell the log which configuration is in force (call before `push`; cheap when nothing changed). A batch never
    /// mixes configurations: if events are pending under another one they are written now, under the one they were
    /// made with. Without a wall clock a forced write would cost those events their time, so the pending batch is
    /// kept and marked `Prov::UNKNOWN` instead. Returns true when it wrote a record.
    #[cfg(feature = "p15-write")]
    pub fn set_prov<D: BlockDev>(&mut self, store: &mut SealedStore<D>, clock_known: bool, p: Prov) -> bool {
        if p == self.prov {
            return false;
        }
        self.prov = p;
        if self.npend == 0 {
            return false;
        }
        if !clock_known {
            self.pend_prov = Prov::UNKNOWN;
            return false;
        }
        let at = self.last_flush_s; // not a timed flush: the once-a-minute pacing is unchanged
        self.maybe_flush(store, at, true, true)
    }

    /// Queue one event image (from `ProdFull::image_of`).
    pub fn push(&mut self, img: [u8; EV_IMAGE_LEN]) -> bool {
        if self.npend < PER_REC {
            if self.npend == 0 {
                self.pend_prov = self.prov;
            }
            self.pend[self.npend] = img;
            self.npend += 1;
        }
        self.npend == PER_REC
    }

    /// The wall clock became known: this boot's pending tick-stamped images become wall-clock ms.
    pub fn anchor(&mut self, to_ms: &dyn Fn(u64) -> u64) {
        for img in self.pend[..self.npend].iter_mut() {
            if img[15] & IMG_EPOCH == 0 {
                let ts = u64::from_le_bytes(img[0..8].try_into().unwrap());
                img[0..8].copy_from_slice(&to_ms(ts).to_le_bytes());
                img[15] |= IMG_EPOCH;
            }
        }
    }

    /// Write the batch when it is full, or (with a clock) at most once per `FLUSH_S`. `force` = write now.
    #[cfg(feature = "p15-write")]
    pub fn maybe_flush<D: BlockDev>(&mut self, store: &mut SealedStore<D>, now_s: u64, clock_known: bool, force: bool) -> bool {
        if self.npend == 0 {
            return false;
        }
        let full = self.npend == PER_REC;
        if !(force || full || (clock_known && now_s.saturating_sub(self.last_flush_s) >= FLUSH_S)) {
            return false;
        }
        let mut pt = [0u8; MAX_SEALED_PAYLOAD];
        const HEAD: usize = BUILD_TAG_LEN + PROV_LEN;
        pt[..BUILD_TAG_LEN].copy_from_slice(&build_tag());
        pt[BUILD_TAG_LEN..HEAD].copy_from_slice(&self.pend_prov.to_bytes());
        for (i, img) in self.pend[..self.npend].iter().enumerate() {
            let mut im = *img;
            if im[15] & IMG_EPOCH == 0 {
                // a full batch before any clock: written as "time unknown", never a fake time
                im[0..8].copy_from_slice(&0u64.to_le_bytes());
                im[15] |= IMG_EPOCH;
            }
            let o = HEAD + i * EV_IMAGE_LEN;
            pt[o..o + EV_IMAGE_LEN].copy_from_slice(&im);
        }
        let n = HEAD + self.npend * EV_IMAGE_LEN;
        let ok = self.log.append_sealed(store, &SealCtx { vek: &self.vek, policy: &self.policy }, RT_EVIDENCE_C, &pt[..n]).is_ok();
        if ok {
            self.written += self.npend as u64;
        } else {
            self.failed += self.npend as u64;
        }
        self.npend = 0;
        self.last_flush_s = now_s;
        ok
    }
}

// ---- the AP image's instance (its own eMMC handle, Gate 2 = the evidence ring only) -------------------------

#[cfg(feature = "appersist")]
mod ap {
    use super::*;
    pub static mut DEV: Option<arch_aarch64::emmc::Emmc> = None;
    pub static mut STORE: Option<SealedStore<'static, arch_aarch64::emmc::Emmc>> = None;
    pub static mut LOG: Option<EvLog> = None;
}

/// Boot: open the ring in the DataVolume `Evidence` region. Returns (records, events) or None.
#[cfg(feature = "appersist")]
pub fn install(srk: &[u8; 32], policy: Policy) -> Option<(u64, u64)> {
    use ap::*;
    let mut dev = arch_aarch64::emmc::Emmc::probe().ok()?;
    let mut mbr = [0u8; 512];
    dev.read_block(0, &mut mbr).ok()?;
    let dv = crate::datavol::DataVol::from_mbr(&mbr)?;
    dv.note();
    let (elo, ehi) = dv.region(crate::datavol::Region::Evidence);
    let (lo, hi) = (elo, (elo + EVLOG_SECT).min(ehi));
    let (blo, bhi) = dv.bounds();
    dev.set_data_volume(blo, bhi);
    if dev.arm_write_window(lo, hi) != (lo, hi) {
        return None;
    }
    unsafe {
        let d = (*core::ptr::addr_of_mut!(DEV)).insert(dev);
        let s = (*core::ptr::addr_of_mut!(STORE)).insert(SealedStore::open(d).ok()?);
        // the store layer's allowlist (Gate 1) = the evidence ring only, matching the driver's Gate 2
        s.add_region(lo, hi, crate::store::RegionKind::DataVolume).ok()?;
        let l = (*core::ptr::addr_of_mut!(LOG)).insert(EvLog::open(s, lo, hi, srk, policy).ok()?);
        Some((l.log.count(), l.log.count() * PER_REC as u64))
    }
}

#[cfg(feature = "appersist")]
pub fn with(f: &mut dyn FnMut(&mut EvLog, &mut SealedStore<'static, arch_aarch64::emmc::Emmc>)) -> bool {
    use ap::*;
    unsafe {
        match ((*core::ptr::addr_of_mut!(LOG)).as_mut(), (*core::ptr::addr_of_mut!(STORE)).as_mut()) {
            (Some(l), Some(s)) => {
                f(l, s);
                true
            }
            _ => false,
        }
    }
}

// ---- [P-evlog] ----------------------------------------------------------------------------------------------

#[cfg(feature = "p15-write")]
pub fn selftest() -> bool {
    use crate::events::Event;
    let d = crate::artstore::test_disk();
    let mut mbr = [0u8; 512];
    let _ = d.read_block(0, &mut mbr);
    let Some(dv) = crate::datavol::DataVol::from_mbr(&mbr) else { arch_aarch64::_print(format_args!(" [P-evlog] FAIL — step 1\n")); return false };
    let (lo, _) = dv.region(crate::datavol::Region::Evidence);
    let hi = lo + 1 + 8; // a small ring for the test: 8 records
    let srk = [0x5a; 32];
    let pol = evidence_policy(7);
    let Ok(mut store) = SealedStore::open(&mut *d) else {
        arch_aarch64::_print(format_args!(" [P-evlog] FAIL — test store\n"));
        return false;
    };
    if store.add_region(lo, hi, crate::store::RegionKind::DataVolume).is_err() {
        return false;
    }
    let Ok(mut l) = EvLog::open(&mut store, lo, hi, &srk, pol) else { arch_aarch64::_print(format_args!(" [P-evlog] FAIL — step 2\n")); return false };
    let fresh = l.log.count() == 0;
    let ev = |i: u32| Event { ts: 1_000 + i as u64, src: 0x0a63_0000 + i, rule_id: 100 + (i % 7) as u16, severity: 3, verdict: 1, class: 0, dport: 443, dst: 0 };
    let img = |e: &Event, ms: u64| {
        let mut b = crate::export::ev_to_image(e);
        b[0..8].copy_from_slice(&ms.to_le_bytes());
        b[15] |= IMG_EPOCH;
        b
    };
    // 50 events with a clock: two full records (42) + a partial one flushed after a minute
    let mut flushed = 0;
    for i in 0..50u32 {
        if l.push(img(&ev(i), 1_762_000_000_000 + i as u64)) && l.maybe_flush(&mut store, 10, true, false) {
            flushed += 1;
        }
    }
    let held = !l.maybe_flush(&mut store, 30, true, false); // < 60 s since the last write: held
    let minute = l.maybe_flush(&mut store, 75, true, false);
    let batched = flushed == 2 && held && minute && l.written == 50 && l.log.count() == 3;
    // ciphertext at rest: no plaintext rule id / source in the raw sectors
    let mut raw = [0u8; 512];
    let mut clear = false;
    for s in lo + 1..hi {
        let _ = store.read_sector(s, &mut raw);
        clear |= raw.windows(4).any(|w| w == (0x0a63_0001u32).to_le_bytes());
    }
    // "reboot": mount again and read every event back, oldest first
    drop(l);
    let Ok(l2) = EvLog::open(&mut store, lo, hi, &srk, pol) else { arch_aarch64::_print(format_args!(" [P-evlog] FAIL — step 3\n")); return false };
    let mut got = 0u32;
    let mut order = true;
    let mut tagged = true;
    l2.for_each(&store, &mut |tag, b| {
        let e = crate::export::image_to_ev(b);
        order &= e.map_or(false, |e| e.src == 0x0a63_0000 + got && e.rule_id == 100 + (got % 7) as u16);
        tagged &= *tag == build_tag();
        got += 1;
    });
    let survives = got == 50 && order;
    // every record names the build that wrote it; a record from before the tag (RT_EVIDENCE) reads as "unknown"
    let mut legacy = [0u8; 2 * EV_IMAGE_LEN];
    legacy[..EV_IMAGE_LEN].copy_from_slice(&img(&ev(9000), 1_762_000_200_000));
    legacy[EV_IMAGE_LEN..].copy_from_slice(&img(&ev(9001), 1_762_000_200_001));
    let mut l2w = l2;
    let (vek_c, pol_c) = (l2w.vek, l2w.policy);
    let wrote_legacy = l2w.log.append_sealed(&mut store, &SealCtx { vek: &vek_c, policy: &pol_c }, RT_EVIDENCE, &legacy).is_ok();
    let (mut old_unknown, mut old_n) = (true, 0u32);
    l2w.for_each(&store, &mut |tag, b| {
        if crate::export::image_to_ev(b).map_or(false, |e| e.src >= 0x0a63_0000 + 9000) {
            old_unknown &= *tag == [0u8; BUILD_TAG_LEN];
            old_n += 1;
        }
    });
    let build_tags = tagged && wrote_legacy && old_unknown && old_n == 2;
    drop(l2w);
    // EVID-01: the next boot after an OTA update (other PCR values, a raised SVN floor, same device) builds its policy
    // the same way and reads the whole history; the old STRICT binding opened an empty log here
    let strict = |pcr: u8, floor: u64| Policy { mask: boot_abi::SEAL_POLICY_STRICT, device_id: 7, svn_floor: floor, pcr: [[pcr; 32]; boot_abi::NUM_PCR] };
    let after_ota = evidence_policy(7).digest() == pol.digest() && strict(1, 1).digest() != strict(2, 5).digest();
    let mut got2 = 0u32;
    if let Ok(l2b) = EvLog::open(&mut store, lo, hi, &srk, evidence_policy(7)) {
        l2b.for_each(&store, &mut |_, _| got2 += 1);
    }
    let ota = after_ota && got2 == 52; // the 50 + the 2 untagged ones
    // another device id on the same SRK reads nothing (the binding that stays)
    let other_dev = EvLog::open(&mut store, lo, hi, &srk, evidence_policy(8)).map_or(false, |o| o.log.count() == 0);
    // another device key reads nothing (the records are sealed under HKDF(SRK))
    let Ok(other) = EvLog::open(&mut store, lo, hi, &[0x11; 32], pol) else { return false };
    let foreign = other.log.count() == 0;
    // a flipped ciphertext byte: that record is dropped (fail-closed), the others survive
    let _ = store.read_sector(lo + 2, &mut raw);
    raw[200] ^= 1;
    let mut s2 = store;
    let _ = s2.store_sector(lo + 2, &raw);
    let Ok(l3) = EvLog::open(&mut s2, lo, hi, &srk, pol) else { arch_aarch64::_print(format_args!(" [P-evlog] FAIL — step 4\n")); return false };
    let tamper = l3.log.count() == 3; // 4 records (3 tagged + the untagged one), one flipped
    // ring: 9 more full records into 8 slots — the oldest are overwritten, the count stays bounded
    let Ok(mut l4) = EvLog::open(&mut s2, lo, hi, &srk, pol) else { arch_aarch64::_print(format_args!(" [P-evlog] FAIL — step 5\n")); return false };
    for r in 0..9u32 {
        for i in 0..PER_REC as u32 {
            l4.push(img(&ev(1000 + r * 100 + i), 1_762_000_100_000));
        }
        let _ = l4.maybe_flush(&mut s2, 1000 + r as u64, true, false);
    }
    let ring = l4.log.count() == 8;
    // before any clock: a full batch is written as "time unknown", never as a fake time
    let mut l5 = l4;
    for i in 0..PER_REC as u32 {
        l5.push(crate::export::ev_to_image(&ev(5000 + i)));
    }
    let _ = l5.maybe_flush(&mut s2, 2000, false, false);
    let mut unknown_ok = true;
    l5.for_each(&s2, &mut |_, b| {
        if crate::export::image_to_ev(b).map_or(false, |e| e.src >= 0x0a63_0000 + 5000) {
            unknown_ok &= b[15] & IMG_EPOCH != 0 && b[0..8] == [0u8; 8];
        }
    });
    // ADR 0067 D10: each record names the configuration its events were made under
    let (pa, pb) = (Prov { cfg_gen: 41, cfg: [0xa1; 8] }, Prov { cfg_gen: 42, cfg: [0xb2; 8] });
    let t_ms = 1_762_000_300_000u64;
    let quiet = !l5.set_prov(&mut s2, true, pa); // nothing pending: nothing written
    for i in 0..3u32 {
        l5.push(img(&ev(7000 + i), t_ms));
    }
    let same = !l5.set_prov(&mut s2, true, pa); // unchanged: the batch keeps filling
    let split = l5.set_prov(&mut s2, true, pb); // changed: the three are written now, under A
    for i in 3..5u32 {
        l5.push(img(&ev(7000 + i), t_ms));
    }
    let _ = l5.maybe_flush(&mut s2, 3000, true, true);
    // no wall clock yet: the pending batch is kept (its events keep their chance of a real time) and marked unknown
    for i in 5..7u32 {
        l5.push(crate::export::ev_to_image(&ev(7000 + i)));
    }
    let kept = !l5.set_prov(&mut s2, false, pa);
    l5.push(crate::export::ev_to_image(&ev(7007)));
    let _ = l5.maybe_flush(&mut s2, 3001, false, true);
    // a record from before provenance (build tag only) reads as unknown
    let mut oldb = [0u8; BUILD_TAG_LEN + EV_IMAGE_LEN];
    oldb[..BUILD_TAG_LEN].copy_from_slice(&build_tag());
    oldb[BUILD_TAG_LEN..].copy_from_slice(&img(&ev(7100), t_ms));
    let (vek_p, pol_p) = (l5.vek, l5.policy);
    let wrote_b = l5.log.append_sealed(&mut s2, &SealCtx { vek: &vek_p, policy: &pol_p }, RT_EVIDENCE_B, &oldb).is_ok();
    let (mut prov_ok, mut prov_n) = (true, 0u32);
    l5.for_each_prov(&s2, &mut |tag, p, b| {
        if let Some(e) = crate::export::image_to_ev(b) {
            let want = match e.src.wrapping_sub(0x0a63_0000) {
                7000..=7002 => pa,
                7003..=7004 => pb,
                7005..=7007 | 7100 => Prov::UNKNOWN,
                _ => return,
            };
            prov_ok &= *p == want && *tag == build_tag();
            prov_n += 1;
        }
    });
    let provenance = quiet && same && split && kept && wrote_b && prov_ok && prov_n == 9;
    let pass = fresh && batched && !clear && survives && build_tags && ota && other_dev && foreign && tamper && ring && unknown_ok && provenance;
    arch_aarch64::_print(format_args!(
        " [P-evlog] {} — #54 sealed evidence log (fslog ring in the DataVolume Evidence region, HQKSEAL1 records under HKDF(SRK)): formatted on first use={} batched {} events/record, held < 60 s then flushed={} ciphertext at rest (no plaintext source)={} remount reads every event back in order={} each record names its build, an untagged older record reads as unknown={} EVID-01: the boot after an OTA (other PCRs, raised floor) reads the whole history={} another device id reads nothing={} another device key reads nothing={} flipped ciphertext byte drops only that record={} bounded ring (oldest overwritten)={} pre-clock batch = time unknown={}\n",
        if pass { "PASS" } else { "FAIL" }, fresh, PER_REC, batched, !clear, survives, build_tags, ota, other_dev, foreign, tamper, ring, unknown_ok
    ));
    arch_aarch64::_print(format_args!(
        "   provenance (ADR 0067 D10): each record names the config generation + bundle digest in force={} (no write when nothing is pending={} or nothing changed={}, a change writes the pending batch under the OLD config={}, with no clock the batch is kept and marked unknown={}, a build-tag-only record reads as unknown={}, {} events checked)\n",
        provenance, quiet, same, split, kept, wrote_b && prov_ok, prov_n
    ));
    pass
}
