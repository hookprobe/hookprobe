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

/// `[P15-otaimg]` — the OS-image update path end to end on a factory-layout disk (virtio-blk,
/// p15-write; validate.sh builds the disk: slot A = a real-size signed image, slot B = junk of the
/// same size, config=A / tryboot=B). Stages the image into a scratch range past p1 exactly as the
/// upload chunks would, then: `check` accepts it and names slot B; it refuses SVN below the floor,
/// a flipped payload byte, a different HBoot prefix, a wrong length and a "running" trial;
/// `install` writes slot B only (slot A byte-identical), and the payload read back FROM slot B
/// hashes to the verified digest; `running_trial` then recognises a boot of slot B as the trial.
#[cfg(not(feature = "cm5"))]
pub fn selftest() {
    macro_rules! kprint { ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) }; }
    let Some(mut dev) = arch_aarch64::virtio_blk::VirtioBlk::open() else { return };
    let Some(run) = hal::abslot::inactive_slot_run(|l, b| dev.read_block(l, b).is_ok()) else { return };
    if (run.size as u64) < IMG_MIN || run.active != b'a' {
        return; // not the OTA test disk (the abcommit disk has 64 KiB slots)
    }
    let d = &mut dev;
    // The image = slot A's own bytes (prefix + header + payload); its length from the header.
    let Some(h) = header(&*d, run.active_lo) else { return kprint!(" [P15-otaimg] FAIL — slot A header unreadable\n") };
    let len = OFF + HDR_LEN + h.size;
    let n = len.div_ceil(512);
    let slo = d.block_count().saturating_sub(n + 8);
    let mut s = [0u8; 512];
    let copy = |d: &mut arch_aarch64::virtio_blk::VirtioBlk, s: &mut [u8; 512]| -> bool {
        (0..n).all(|i| d.read_block(run.active_lo + i, s).is_ok() && d.write_block(slo + i, s).is_ok())
    };
    if !copy(d, &mut s) {
        return kprint!(" [P15-otaimg] FAIL — staging write\n");
    }
    let a_before = hash(&*d, run.active_lo, 0, len);
    let ok = check(&*d, slo, len, 1, None);
    let good = matches!(ok, Ok(p) if p.lo == run.lo && p.hi == run.hi && p.active == b'a' && p.svn == 2 && p.len == len);
    let floor = check(&*d, slo, len, 3, None) == Err("rollback refused: security version below the running image / floor");
    let short = check(&*d, slo, len - 1, 1, None) == Err("image length does not match its header");
    let trial_running = check(&*d, slo, len, 1, Some([7; 32])) == Err("a trial boot is running — commit or reboot before the next update");
    // Flip one payload byte, then one HBoot-prefix byte (restored after each).
    let flip = |d: &mut arch_aarch64::virtio_blk::VirtioBlk, lba: u64, s: &mut [u8; 512]| {
        let _ = d.read_block(lba, s);
        s[100] ^= 0x40;
        let _ = d.write_block(lba, s);
    };
    let pay = slo + (OFF + HDR_LEN) / 512 + 64;
    flip(d, pay, &mut s);
    let badsig = check(&*d, slo, len, 1, None) == Err("bad signature (not the release keys)");
    flip(d, pay, &mut s);
    flip(d, slo + 3, &mut s);
    let hboot = check(&*d, slo, len, 1, None) == Err("boot loader differs from the installed one (boot-loader updates are USB-only)");
    flip(d, slo + 3, &mut s);
    let installed = match ok {
        Ok(p) => install(d, slo, &p).is_ok() && payload_hash(&*d, run.lo) == Some(p.hash),
        Err(_) => false,
    };
    let a_same = hash(&*d, run.active_lo, 0, len) == a_before && a_before.is_some();
    let trial = match ok {
        Ok(p) => running_trial(&*d, p.hash) == Some(false), // slot A holds the same image: a cold boot
        Err(_) => false,
    };
    // Step 5: a boot of the new image is a TRIAL of slot B until the commit, then the cold-boot slot.
    let committed = match ok {
        Ok(p) => {
            // Both slots hold the same image here, so make slot A's stored digest differ (the test
            // disk is scratch): a boot whose measurement matches only slot B is then its trial.
            let same = classify(&*d, p.hash) == Boot::Cold;
            let hl = run.active_lo + (OFF + 40) / 512; // the header's sha256 field (offset 40)
            let mut x = [0u8; 512];
            let _ = d.read_block(hl, &mut x);
            x[((OFF + 40) % 512) as usize] ^= 0xff;
            let _ = d.write_block(hl, &x);
            let before = same && classify(&*d, p.hash) == Boot::Trial(b'b');
            let mut mbr = [0u8; 512];
            let _ = d.read_block(0, &mut mbr);
            let p1 = crate::store::parse_mbr(&mbr)[0].start;
            let wrote = match crate::abboot::plan_commit(&*d, p1, crate::abboot::Slot::B) {
                Ok(plan) => match crate::store::SealedStore::open(&mut *d) {
                    Ok(mut st) => crate::abboot::apply(&mut st, &plan) == Ok(2),
                    Err(_) => false,
                },
                Err(_) => false,
            };
            before && wrote && classify(&*d, p.hash) == Boot::Cold
        }
        Err(_) => false,
    };
    let pass = good && floor && short && trial_running && badsig && hboot && installed && a_same && trial && committed;
    kprint!(" [P15-otaimg] {} — OS-image update on a factory A/B disk: a {}-byte signed image staged sector by sector, checked (shared verifier over a streamed digest, SVN floor, A/B layout, HBoot prefix pinned, tryboot names the inactive slot) -> slot B={} ; refused: svn<floor={} wrong length={} flipped payload byte={} different HBoot prefix={} trial in progress={} ; installed into slot B + payload re-hashed from the slot={} ; slot A untouched={} ; boot identity check={} ; trial of B -> commit (config=B, tryboot=A) -> cold boot of B={}\n",
        if pass { "PASS" } else { "FAIL" }, len, good, floor, short, badsig, hboot, trial_running, installed, a_same, trial, committed);
}


/// The payload hash stored in the header of the image at sector `base` (the signed-bound digest
/// HBoot compares against): enough to tell which slot this boot is running without re-hashing.
pub fn stored_hash<D: BlockDev>(d: &D, base: u64) -> Option<[u8; 32]> {
    header(d, base).map(|h| h.sha256)
}

/// Which A/B situation this boot is in (production phase 1, step 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boot {
    /// Running the slot config.txt names.
    Cold,
    /// Running the OTHER slot: a tryboot trial of an update (letter of the running slot).
    Trial(u8),
    /// No factory A/B layout, or the running image matches neither slot header.
    Unknown,
}

/// `GET /api/system`: this boot as `classify` found it — the running slot's letter (b'a' / b'b'), bit 7 = a trial not
/// committed yet (cleared by `committed`). 0 = never classified (no HBoot, no factory A/B layout, or Unknown).
static mut RUNNING: u8 = 0;
pub fn running() -> u8 {
    unsafe { RUNNING }
}
/// The trial gate committed the running slot: it is now the cold-boot slot.
pub fn committed() {
    unsafe { RUNNING &= 0x7f }
}

/// Classify this boot from HBoot's measurement and the two slot headers.
pub fn classify<D: BlockDev>(d: &D, running: [u8; 32]) -> Boot {
    let Some(run) = hal::abslot::inactive_slot_run(|l, b| d.read_block(l, b).is_ok()) else { return Boot::Unknown };
    if stored_hash(d, run.active_lo) == Some(running) {
        unsafe { RUNNING = run.active };
        return Boot::Cold;
    }
    if stored_hash(d, run.lo) == Some(running) {
        let l = if run.active == b'a' { b'b' } else { b'a' };
        unsafe { RUNNING = l | 0x80 };
        return Boot::Trial(l);
    }
    Boot::Unknown
}

/// Release plan workstream 2 (OTA trust chain): a trial image commits only when BOTH the WAN is usable AND the Wi-Fi AP
/// serves, continuously for COMMIT_STABLE_S (a transient never commits); past COMMIT_LIMIT_S without that the device
/// reboots to the previous slot. Only this gate commits — the runtime watchdog never does.
pub const COMMIT_STABLE_S: u64 = 30;
pub const COMMIT_LIMIT_S: u64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Wait,
    Commit,
    Revert,
}

/// A DFS channel's channel-availability check (CAC) silences the AP — the BSS is "up" but sends no beacons and no
/// client can join (task #88: the gate committed during the ~60 s CAC on ch52). While the firmware reports CAC the AP
/// does not count as serving, and the revert deadline moves out by the CAC time seen, up to this allowance (EN 301 893:
/// 60 s CAC, 600 s on the 5600–5650 MHz weather channels; 660 s leaves a margin).
pub const COMMIT_CAC_ALLOW_S: u64 = 660;

/// Whether the firmware DFS state lets the AP serve: CAC (1, 4, 5, 6) and a channel switch (3) do not; idle (0, a
/// non-DFS channel) and in-service monitoring (2) do. `None` (no answer) = unknown: the BSS-up test alone decides.
pub fn dfs_lets_ap_serve(state: Option<u32>) -> bool {
    !matches!(state, Some(1) | Some(3) | Some(4) | Some(5) | Some(6))
}

pub struct CommitGate {
    healthy_since: Option<u64>,
    last_s: Option<u64>,
    cac_s: u64,
}

impl CommitGate {
    pub const fn new() -> Self {
        CommitGate { healthy_since: None, last_s: None, cac_s: 0 }
    }
    /// `now_s` / `t0_s` = seconds now / at the trial boot; `wan` = WAN usable; `ap` = the AP serves (BSS up and
    /// beaconing in AP mode, no Wi-Fi firmware halt since this boot); `cac` = the firmware reports a DFS CAC / channel
    /// switch (the AP is silent whatever the BSS state says).
    pub fn step(&mut self, now_s: u64, t0_s: u64, wan: bool, ap: bool, cac: bool) -> Gate {
        if cac {
            if let Some(l) = self.last_s {
                self.cac_s = self.cac_s.saturating_add(now_s.saturating_sub(l));
            }
        }
        self.last_s = Some(now_s);
        if wan && ap && !cac {
            let since = *self.healthy_since.get_or_insert(now_s);
            if now_s.saturating_sub(since) >= COMMIT_STABLE_S {
                return Gate::Commit;
            }
        } else {
            self.healthy_since = None; // any dip (or a CAC) restarts the stability window
        }
        if now_s.saturating_sub(t0_s) > COMMIT_LIMIT_S + self.cac_s.min(COMMIT_CAC_ALLOW_S) {
            Gate::Revert
        } else {
            Gate::Wait
        }
    }
    /// Seconds of DFS CAC seen during this trial (the deadline extension, before the cap).
    pub fn cac_s(&self) -> u64 {
        self.cac_s
    }
}

/// `[P-otagate]`: the commit gate's decisions.
#[cfg(not(feature = "cm5"))]
pub fn gate_selftest() -> bool {
    // WAN usable but the AP down: never commits, reverts after the limit
    let mut g = CommitGate::new();
    let wan_only = (0..=COMMIT_LIMIT_S).all(|t| g.step(t, 0, true, false, false) == Gate::Wait) && g.step(COMMIT_LIMIT_S + 1, 0, true, false, false) == Gate::Revert;
    // AP serving but no WAN: same
    let mut g = CommitGate::new();
    let ap_only = (0..=COMMIT_LIMIT_S).all(|t| g.step(t, 0, false, true, false) == Gate::Wait) && g.step(COMMIT_LIMIT_S + 1, 0, false, true, false) == Gate::Revert;
    // both healthy: commits only after the stability window
    let mut g = CommitGate::new();
    let early = (10..10 + COMMIT_STABLE_S).all(|t| g.step(t, 0, true, true, false) == Gate::Wait);
    let both = early && g.step(10 + COMMIT_STABLE_S, 0, true, true, false) == Gate::Commit;
    // a dip restarts the window
    let mut g = CommitGate::new();
    let _ = g.step(10, 0, true, true, false);
    let _ = g.step(35, 0, true, false, false);
    let dip = g.step(36, 0, true, true, false) == Gate::Wait && g.step(36 + COMMIT_STABLE_S - 1, 0, true, true, false) == Gate::Wait
        && g.step(36 + COMMIT_STABLE_S, 0, true, true, false) == Gate::Commit;
    // healthy only near the end: the limit wins once it passes without a full stable window
    let mut g = CommitGate::new();
    let late = g.step(COMMIT_LIMIT_S - 5, 0, true, true, false) == Gate::Wait && g.step(COMMIT_LIMIT_S + 1, 0, true, true, false) == Gate::Revert;
        // task #88: a DFS CAC (BSS up, AP silent) never commits; the trial then commits once in service
    let mut g = CommitGate::new();
    let cac60 = (0..60).all(|t| g.step(t, 0, true, true, true) == Gate::Wait)
        && (60..60 + COMMIT_STABLE_S).all(|t| g.step(t, 0, true, true, false) == Gate::Wait)
        && g.step(60 + COMMIT_STABLE_S, 0, true, true, false) == Gate::Commit;
    // a 600 s weather-channel CAC moves the deadline out: no revert at the plain limit, commit after it
    let mut g = CommitGate::new();
    let weather = (0..600).all(|t| g.step(t, 0, true, true, true) == Gate::Wait)
        && (600..600 + COMMIT_STABLE_S).all(|t| g.step(t, 0, true, true, false) == Gate::Wait)
        && g.step(600 + COMMIT_STABLE_S, 0, true, true, false) == Gate::Commit;
    // a CAC that never ends still reverts, at the limit + the capped allowance
    let mut g = CommitGate::new();
    let lim = COMMIT_LIMIT_S + COMMIT_CAC_ALLOW_S;
    let endless = (0..=lim).all(|t| g.step(t, 0, true, true, true) == Gate::Wait) && g.step(lim + 1, 0, true, true, true) == Gate::Revert;
    let states = dfs_lets_ap_serve(None) && dfs_lets_ap_serve(Some(0)) && dfs_lets_ap_serve(Some(2))
        && [1u32, 3, 4, 5, 6].iter().all(|&x| !dfs_lets_ap_serve(Some(x)));
let pass = wan_only && ap_only && both && dip && late && cac60 && weather && endless && states;
    arch_aarch64::_print(format_args!(
        " [P-otagate] {} — OTA trial commit gate: WAN usable but AP down never commits (reverts after {} s)={} AP serving but no WAN never commits={} both healthy for {} s commits={} a dip restarts the stability window={} the limit wins over a late short recovery={} a 60 s DFS CAC never commits, then commits in service={} a 600 s weather CAC moves the deadline={} an endless CAC reverts at {} s={} DFS states classified={}\n",
        if pass { "PASS" } else { "FAIL" }, COMMIT_LIMIT_S, wan_only, ap_only, COMMIT_STABLE_S, both, dip, late, cac60, weather, lim, endless, states
    ));
    pass
}
