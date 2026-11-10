//! Factory reset (Phase 7) — the boot-time wipe.
//!
//! `POST /api/factory-reset` (ownerapi::factory_reset) only appends a sealed `FactoryReset` record and reboots.
//! On the next boot, right after the journal replays and BEFORE anything is served, `run` erases the owner's data
//! in this order — each region through its OWN eMMC handle whose Gate-2 window covers only that region:
//!   1. the sealed evidence ring (every sector of `[Evidence.lo, + EVLOG_SECT)` zeroed; the next mount formats);
//!   2. the artifact-store manifest (`MAN_SECT` sectors: every activated pack is forgotten — the signed packs in
//!      the image apply again; the slot payloads are operator-signed public data, not owner data);
//!   3. the sealed snapshot in the reserved window — an EMPTY snapshot is sealed into BOTH A/B slots through the
//!      normal persist path (never a raw write over the keystore window, so the floors there are untouched);
//!   4. LAST the owner journal (rules, Shield profiles, alert hook, owner-key rotation, and the request itself).
//! A power cut anywhere before step 4 leaves the request in the journal, so the whole wipe runs again; one during
//! step 4 leaves an empty journal (the record chain breaks at the first zeroed sector). Then one more reboot, so
//! the device comes up exactly as shipped: OWNER.TXT is the owner key again, nothing restored.
//!   (the enrolled owner configuration key is NOT cleared — ADR 0059 Phase 0.6; a reflash resets it);
//! Never touched: boot slots, POLICY.TXT / WAN.TXT, the device key (SRK), anti-rollback floors, OTP.

macro_rules! kprint {
    ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
}

use hal::BlockDev;

/// Zero `[lo, hi)` of the DataVolume through a fresh handle armed for exactly that range. Returns sectors zeroed.
fn zero_dv(lo: u64, hi: u64) -> Result<u64, &'static str> {
    let mut dev = arch_aarch64::emmc::Emmc::probe().map_err(|_| "eMMC probe")?;
    let mut mbr = [0u8; 512];
    dev.read_block(0, &mut mbr).map_err(|_| "MBR read")?;
    let dv = crate::datavol::DataVol::from_mbr(&mbr).ok_or("no DataVolume")?;
    let (blo, bhi) = dv.bounds();
    dev.set_data_volume(blo, bhi);
    if dev.arm_write_window(lo, hi) != (lo, hi) {
        return Err("write window refused");
    }
    let z = [0u8; 512];
    for lba in lo..hi {
        dev.write_block(lba, &z).map_err(|_| "write failed")?;
    }
    Ok(hi - lo)
}

fn region(r: crate::datavol::Region) -> Option<(u64, u64)> {
    let dev = arch_aarch64::emmc::Emmc::probe().ok()?;
    let mut mbr = [0u8; 512];
    dev.read_block(0, &mut mbr).ok()?;
    Some(crate::datavol::DataVol::from_mbr(&mbr)?.region(r))
}

/// Run the wipe if the replayed journal asked for one. Reboots when the wipe completed; returns when there was
/// nothing to do, or when a step failed (the request stays in the journal and the next boot retries — a failing
/// eMMC must never turn into a reboot loop).
pub fn run(pf: &mut crate::prodfull::ProdFull) {
    if !crate::ownerjournal::factory_reset_requested() {
        return;
    }
    kprint!(" [FACTORY-RESET] requested by the owner (sealed journal record) — erasing owner data before serving anything\n");
    let ev = region(crate::datavol::Region::Evidence)
        .ok_or("no DataVolume")
        .and_then(|(lo, hi)| zero_dv(lo, (lo + crate::evlog::EVLOG_SECT).min(hi)));
    kprint!(" [FACTORY-RESET] 1/4 sealed evidence log: {:?}\n", ev);
    let man = region(crate::datavol::Region::Store)
        .ok_or("no DataVolume")
        .and_then(|(lo, _)| zero_dv(lo, lo + crate::artstore::MAN_SECT));
    kprint!(" [FACTORY-RESET] 2/4 artifact manifest: {:?}\n", man);
    // The enrolled owner configuration key STAYS (ADR 0059 Phase 0.6): the owner TOKEN alone must not be able to
    // drop the owner KEY and enroll another. A full reflash (physical access) still resets it; an owner-signed
    // reset (HQRST1) is ADR 0059 Phase 2.
    let own: Result<(), &str> = Ok(());
    let snap = pf.erase_snapshot();
    kprint!(" [FACTORY-RESET] 3/4 sealed snapshot (both A/B slots rewritten empty): {}\n", snap);
    if ev.is_err() || man.is_err() || own.is_err() || !snap {
        // never a reboot loop on a failing eMMC: boot normally, keep the request, retry on the next boot
        kprint!(" [FACTORY-RESET] a step failed — the request is KEPT (journal untouched); booting normally, the wipe retries next boot\n");
        return;
    }
    match crate::ownerapi::wipe_journal() {
        Ok(n) => {
            kprint!(" [FACTORY-RESET] 4/4 owner journal: {} sectors zeroed — DONE, rebooting as shipped\n", n);
            reboot();
        }
        Err(e) => kprint!(" [FACTORY-RESET] 4/4 owner journal: {} — request kept; booting normally, retry next boot\n", e),
    }
}

/// The same reset the watchdog self-heal uses (HBoot's EL2 `hvc #0` vector resets the SoC).
fn reboot() -> ! {
    let _ = arch_aarch64::mailbox::notify_reboot();
    unsafe { core::arch::asm!("hvc #0", options(noreturn)) }
}
