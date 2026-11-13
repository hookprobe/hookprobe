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
use crate::fslog::{self, LogStore, SealCtx, MAX_SEALED_PAYLOAD, RT_EVIDENCE};
use crate::seal::Policy;
use crate::snapshot::IMG_EPOCH;
use crate::store::SealedStore;
use hal::BlockDev;

/// 1 superblock + 4096 record slots (2 MiB): ~90k detections at 22 per record. Bounded by the boot scan (every
/// slot is read at mount): ~1.5 s at the 25 MHz data clock (it was 22 s at the old 390 kHz clock, 2026-11-09).
pub const EVLOG_SECT: u64 = 4097;
pub const PER_REC: usize = MAX_SEALED_PAYLOAD / EV_IMAGE_LEN; // 22
const FLUSH_S: u64 = 60;

/// The log's RAM side: the volume key, the pending batch, counters.
pub struct EvLog {
    pub log: LogStore,
    vek: [u8; 32],
    policy: Policy,
    pend: [[u8; EV_IMAGE_LEN]; PER_REC],
    npend: usize,
    last_flush_s: u64,
    pub written: u64,
    pub failed: u64,
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
        Ok(EvLog { log, vek, policy, pend: [[0; EV_IMAGE_LEN]; PER_REC], npend: 0, last_flush_s: 0, written: 0, failed: 0 })
    }

    /// Every stored event, oldest first: `cb(image)`.
    pub fn for_each<D: BlockDev>(&self, store: &SealedStore<D>, cb: &mut dyn FnMut(&[u8; EV_IMAGE_LEN])) -> u64 {
        let mut n = 0u64;
        let _ = self.log.for_each_sealed(store, &SealCtx { vek: &self.vek, policy: &self.policy }, |_, rt, pt| {
            if rt != RT_EVIDENCE {
                return;
            }
            for c in pt.chunks_exact(EV_IMAGE_LEN) {
                let img: &[u8; EV_IMAGE_LEN] = c.try_into().unwrap();
                cb(img);
                n += 1;
            }
        });
        n
    }

    /// Queue one event image (from `ProdFull::image_of`).
    pub fn push(&mut self, img: [u8; EV_IMAGE_LEN]) -> bool {
        if self.npend < PER_REC {
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
        for (i, img) in self.pend[..self.npend].iter().enumerate() {
            let mut im = *img;
            if im[15] & IMG_EPOCH == 0 {
                // a full batch before any clock: written as "time unknown", never a fake time
                im[0..8].copy_from_slice(&0u64.to_le_bytes());
                im[15] |= IMG_EPOCH;
            }
            pt[i * EV_IMAGE_LEN..(i + 1) * EV_IMAGE_LEN].copy_from_slice(&im);
        }
        let n = self.npend * EV_IMAGE_LEN;
        let ok = self.log.append_sealed(store, &SealCtx { vek: &self.vek, policy: &self.policy }, RT_EVIDENCE, &pt[..n]).is_ok();
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
    let pol = Policy { mask: 0, device_id: 7, svn_floor: 0, pcr: [[0u8; 32]; boot_abi::NUM_PCR] };
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
    // 50 events with a clock: two full records (44) + a partial one flushed after a minute
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
    l2.for_each(&store, &mut |b| {
        let e = crate::export::image_to_ev(b);
        order &= e.map_or(false, |e| e.src == 0x0a63_0000 + got && e.rule_id == 100 + (got % 7) as u16);
        got += 1;
    });
    let survives = got == 50 && order;
    // another device key reads nothing (the records are sealed under HKDF(SRK))
    let Ok(other) = EvLog::open(&mut store, lo, hi, &[0x11; 32], pol) else { return false };
    let foreign = other.log.count() == 0;
    // a flipped ciphertext byte: that record is dropped (fail-closed), the others survive
    let _ = store.read_sector(lo + 2, &mut raw);
    raw[200] ^= 1;
    let mut s2 = store;
    let _ = s2.store_sector(lo + 2, &raw);
    let Ok(l3) = EvLog::open(&mut s2, lo, hi, &srk, pol) else { arch_aarch64::_print(format_args!(" [P-evlog] FAIL — step 4\n")); return false };
    let tamper = l3.log.count() == 2;
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
    l5.for_each(&s2, &mut |b| {
        if crate::export::image_to_ev(b).map_or(false, |e| e.src >= 0x0a63_0000 + 5000) {
            unknown_ok &= b[15] & IMG_EPOCH != 0 && b[0..8] == [0u8; 8];
        }
    });
    let pass = fresh && batched && !clear && survives && foreign && tamper && ring && unknown_ok;
    arch_aarch64::_print(format_args!(
        " [P-evlog] {} — #54 sealed evidence log (fslog ring in the DataVolume Evidence region, HQKSEAL1 records under HKDF(SRK)): formatted on first use={} batched {} events/record, held < 60 s then flushed={} ciphertext at rest (no plaintext source)={} remount reads every event back in order={} another device key reads nothing={} flipped ciphertext byte drops only that record={} bounded ring (oldest overwritten)={} pre-clock batch = time unknown={}\n",
        if pass { "PASS" } else { "FAIL" }, fresh, PER_REC, batched, !clear, survives, foreign, tamper, ring, unknown_ok
    ));
    pass
}
