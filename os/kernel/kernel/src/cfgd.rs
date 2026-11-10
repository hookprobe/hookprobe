//! cfgd — the single writer of the device configuration (ADR 0059 step 3; assessment Phase 2).
//!
//! A new HQCFG1 bundle (upload type `config`, ADR 0056 staging -> artifact store) is committed to the manifest as
//! PENDING. The next boot runs it as a TRIAL:
//!
//! ```text
//! boot: active entry PENDING, trials == 0  -> trials = 1, load it, start the health window
//!       active entry PENDING, trials >= 1  -> a second boot while PENDING: REVERT to the last-known-good half
//!       active entry ACTIVE                -> load it (committed / last-known-good)
//!       nothing verifies                    -> the per-file configuration (WAN/WIFI/POLICY .TXT) as before
//! run:  healthy (WAN usable; Mission Control is served on the LAN / AP regardless) -> COMMIT: state ACTIVE,
//!       the bundle floor rises to this generation
//!       not healthy within WINDOW_S                                             -> REVERT, then reboot
//!       the owner may COMMIT early (/api/config/confirm) or REVERT (/api/config/rollback)
//! ```
//!
//! The loaders (WAN, Wi-Fi, POLICY) read a section from here first: one signed unit, verified once at boot, kept
//! in one 16 KiB static buffer. The kernel never parses past a section's table length. A REVERT that finds no
//! verified previous half clears the entry: the device falls back to its boot-partition files, then the DHCP default.

use crate::artstore::{self, Ty, STATE_ACTIVE, STATE_PENDING};
use crate::cfgbundle;
use hal::BlockDev;

pub const WINDOW_S: u64 = 300;

/// The device's REAL management paths: (interface, the device's own address there, prefix) — registered where the
/// kernel brings each interface up (the Wi-Fi AP, the management VLAN; Mission Control is not served on eth1). Empty = the shipped LAN
/// addressing (10.99.0.1/24) is assumed.
static mut PATHS: [(u8, [u8; 4], u8); 4] = [(0xff, [0; 4], 0); 4];
pub fn set_path(ifc: hal::policy::If, dev_ip: [u8; 4], prefix: u8) {
    unsafe {
        let p = &mut *core::ptr::addr_of_mut!(PATHS);
        p[ifc.idx()] = (ifc.idx() as u8, dev_ip, prefix.min(30));
    }
}

/// ADR 0059 D7 invariant (peer review 2026-11-10): a bundle must keep at least one REAL management path — HTTPS to
/// the device's own address on an interface, from a client in that interface's subnet (a subnet host, or the
/// management floor where it lies inside that subnet). Probing the running addressing, never sample constants.
/// Checked at STAGE (a bundle that could only fail never becomes a trial).
pub fn keeps_mgmt_path(policy_section: Option<&[u8]>) -> bool {
    use hal::policy::{Act, Addr, Dir, If, Pkt};
    let Some(sec) = policy_section else { return true }; // no policy section: the policy in force is unchanged
    let mut file = [0u8; 4096];
    if !cfgbundle::policy_file(sec, &mut file) {
        return false;
    }
    static mut SCRATCH: hal::policy::Policy = hal::policy::Policy::new();
    let pol = unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) };
    *pol = hal::policy::Policy::new();
    if hal::policy::parse_policy(&file, pol).is_err() {
        return false; // an unparseable policy would lock management down at boot
    }
    let mut paths = unsafe { *core::ptr::addr_of!(PATHS) };
    #[cfg(feature = "cm5")]
    if let Some(m) = unsafe { *core::ptr::addr_of!(arch_aarch64::uplink::MGMT) } {
        if m.ip != [0; 4] {
            paths[If::Mgmt.idx()] = (If::Mgmt.idx() as u8, m.ip, m.prefix);
        }
    }
    if paths.iter().all(|p| p.0 == 0xff) {
        paths[If::Lan.idx()] = (If::Lan.idx() as u8, [10, 99, 0, 1], 24);
    }
    let (fnet, flen, fset) = crate::verdict::mgmt_floor();
    let ifs = [If::Lan, If::Eth1, If::Wan, If::Mgmt];
    paths.iter().filter(|p| p.0 != 0xff).any(|&(i, dev, pl)| {
        let ifc = ifs[i as usize];
        let mask = if pl == 0 { 0 } else { u32::MAX << (32 - pl as u32) };
        let d = u32::from_be_bytes(dev);
        let net = d & mask;
        // clients inside this interface's subnet: two hosts that are not the device, and the floor's first host when
        // the floor lies inside the subnet
        let mut cands = [0u32; 3];
        let mut n = 0;
        for h in [net | 2, net | 3] {
            if h != d && n < 2 {
                cands[n] = h;
                n += 1;
            }
        }
        if fset && flen >= pl as u32 && (fnet & mask) == net && (fnet | 1) != d {
            cands[n] = fnet | 1;
            n += 1;
        }
        cands[..n].iter().any(|&c| {
            let p = Pkt { proto: 6, src: Addr::v4(c.to_be_bytes()), dst: Addr::v4(dev), dport: 443 };
            pol.check(ifc, Dir::In, &p).0 == Act::Allow
        })
    })
}

/// Peer review 2026-11-10 (ADR 0059 §B.5): a bundle that touches the management plane (management VLAN / link keys
/// in the wan section, or a policy binding on `mgmt`) is NEVER auto-committed on "WAN usable" — a site managed
/// over the management VLAN could keep internet and lose its management path. It needs the owner's
/// /api/config/confirm within the window, else it reverts.
pub fn touches_mgmt() -> bool {
    let wan = section(cfgbundle::KIND_WAN).unwrap_or(b"");
    let pol = section(cfgbundle::KIND_POLICY).unwrap_or(b"");
    wan.split(|&b| b == b'\n').any(|l| l.starts_with(b"mgmt") || l.starts_with(b"vlan") || l.starts_with(b"pcp"))
        || pol.split(|&b| b == b'\n').any(|l| l.starts_with(b"interface mgmt ") || (l.starts_with(b"route ") && l.windows(9).any(|w| w == b" via mgmt")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boot {
    /// No bundle in the store.
    None,
    /// The committed (last-known-good) bundle is in force.
    Committed(u64),
    /// A new bundle on trial this boot.
    Trial(u64),
    /// A trial failed (second boot while PENDING, or it would not verify): reverted; `to` = the generation now in
    /// force (0 = none, the per-file configuration).
    Reverted { from: u64, to: u64 },
    /// A committed bundle that no longer verifies (tampered at rest): ignored, the per-file configuration applies.
    Refused,
}

static mut BUF: [u8; cfgbundle::MAX_BUNDLE] = [0; cfgbundle::MAX_BUNDLE];
static mut SECS: [(u8, usize, usize); 3] = [(0, 0, 0); 3];
static mut NSEC: usize = 0;
static mut STATE: Boot = Boot::None;
static mut GEN: u64 = 0;
static mut T0: u64 = 0;
static mut TRIAL: bool = false;

pub fn state() -> Boot {
    unsafe { STATE }
}
pub fn generation() -> u64 {
    unsafe { GEN }
}
pub fn on_trial() -> bool {
    unsafe { TRIAL }
}
pub fn trial_elapsed(now_s: u64) -> u64 {
    now_s.saturating_sub(unsafe { T0 })
}
static mut LAST: u64 = 0;
/// Seconds the trial has run, as of the last tick (the AP loop's clock).
pub fn elapsed_s() -> u64 {
    trial_elapsed(unsafe { LAST })
}

/// The verified section of `kind` of the bundle in force (None = no bundle / no such section).
pub fn section(kind: u8) -> Option<&'static [u8]> {
    unsafe {
        let b = &*core::ptr::addr_of!(BUF);
        let s = &*core::ptr::addr_of!(SECS);
        s[..NSEC].iter().find(|x| x.0 == kind).map(|&(_, o, l)| &b[o..o + l])
    }
}

/// Load + verify one half into BUF. Some(gen) on success.
fn load_half<D: BlockDev + ?Sized>(dev: &D, half: u8, key: &[u8; 32], min_gen: u64) -> Option<u64> {
    let store = artstore::store_region(dev)?;
    let (sl, dl) = artstore::slot(store, Ty::Config, half);
    let mut sig = [0u8; 512];
    dev.read_block(sl, &mut sig).ok()?;
    let len = u32::from_le_bytes([sig[9], sig[10], sig[11], sig[12]]) as usize;
    if !(cfgbundle::HDR..=cfgbundle::MAX_BUNDLE).contains(&len) {
        return None;
    }
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    let mut sec = [0u8; 512];
    for k in 0..len.div_ceil(512) {
        dev.read_block(dl + k as u64, &mut sec).ok()?;
        let n = (len - k * 512).min(512);
        buf[k * 512..k * 512 + n].copy_from_slice(&sec[..n]);
    }
    let v = cfgbundle::verify(&buf[..len], &sig, key, &crate::config_device_id(), min_gen.saturating_sub(1)).ok()?;
    let mut secs = [(0u8, 0usize, 0usize); 3];
    let mut n = 0;
    for (k, b) in v.sections() {
        secs[n] = (k, b.as_ptr() as usize - buf.as_ptr() as usize, b.len());
        n += 1;
    }
    unsafe {
        SECS = secs;
        NSEC = n;
        GEN = v.generation;
    }
    Some(v.generation)
}

fn clear() {
    unsafe {
        NSEC = 0;
        GEN = 0;
        TRIAL = false;
    }
}

/// Revert: the OTHER half if it verifies at or above the committed floor (state ACTIVE), else clear the entry.
fn revert<D: BlockDev + ?Sized>(dev: &mut D, key: &[u8; 32], floor: u64) -> u64 {
    let Some(e) = artstore::entry(dev, Ty::Config) else { return 0 };
    let other = if e.half == 1 { 2 } else { 1 };
    let to = artstore::verify_half(dev, Ty::Config, other, key).filter(|&(g, _, _)| g >= floor && g < e.gen);
    let r = match to {
        Some((g, l, _)) => artstore::set_entry(dev, Ty::Config, |x| {
            x.half = other;
            x.gen = g;
            x.len = l;
            x.state = STATE_ACTIVE;
            x.trials = 0;
        })
        .map(|_| g),
        None => artstore::set_entry(dev, Ty::Config, |x| *x = artstore::Entry { half: 0, gen: 0, len: 0, digest: [0; 32], state: STATE_ACTIVE, trials: 0 }).map(|_| 0),
    };
    r.unwrap_or(0)
}

/// Boot step (before the WAN / Wi-Fi / POLICY loaders). `floor` = the committed bundle floor (anchor).
pub fn boot<D: BlockDev + ?Sized>(dev: &mut D, key: Option<[u8; 32]>, floor: u64, now_s: u64) -> Boot {
    clear();
    let r = (|| {
        let key = key?;
        let e = artstore::entry(dev, Ty::Config)?;
        if e.half == 0 {
            return Some(Boot::None);
        }
        if e.state == STATE_PENDING {
            if e.trials >= 1 {
                // the trial boot never came back healthy (crash / power cut / reboot loop): last-known-good
                let to = revert(dev, &key, floor);
                if to != 0 && load_half(dev, artstore::entry(dev, Ty::Config)?.half, &key, floor).is_none() {
                    clear();
                }
                return Some(Boot::Reverted { from: e.gen, to });
            }
            artstore::set_entry(dev, Ty::Config, |x| x.trials = x.trials.saturating_add(1)).ok()?;
            return Some(match load_half(dev, e.half, &key, floor + 1) {
                Some(g) => {
                    unsafe {
                        TRIAL = true;
                        T0 = now_s;
                    }
                    Boot::Trial(g)
                }
                None => {
                    let to = revert(dev, &key, floor);
                    if to != 0 {
                        let _ = load_half(dev, artstore::entry(dev, Ty::Config)?.half, &key, floor);
                    }
                    Boot::Reverted { from: e.gen, to }
                }
            });
        }
        Some(match load_half(dev, e.half, &key, floor) {
            Some(g) => Boot::Committed(g),
            None => {
                // ADR 0059 §B.7: the committed bundle no longer verifies -> the other half first, per-file only after
                clear();
                let to = revert(dev, &key, floor);
                if to != 0 && load_half(dev, artstore::entry(dev, Ty::Config)?.half, &key, floor).is_some() {
                    Boot::Reverted { from: e.gen, to }
                } else {
                    clear();
                    Boot::Refused
                }
            }
        })
    })()
    .unwrap_or(Boot::None);
    unsafe { STATE = r };
    r
}

/// COMMIT the trial: state ACTIVE, the bundle floor rises (anchor). Also the owner's early confirm.
pub fn commit<D: BlockDev + ?Sized>(dev: &mut D) -> Result<u64, &'static str> {
    if !on_trial() {
        return Err("no configuration on trial");
    }
    artstore::set_entry(dev, Ty::Config, |x| {
        x.state = STATE_ACTIVE;
        x.trials = 0;
    })
    .map_err(|_| "store write failed")?;
    let g = generation();
    crate::anchor::commit_cfg_floor(g);
    unsafe {
        TRIAL = false;
        STATE = Boot::Committed(g);
    }
    Ok(g)
}

/// REVERT now (trial timeout, or the owner): the previous half becomes active for the NEXT boot.
pub fn revert_now<D: BlockDev + ?Sized>(dev: &mut D, key: Option<[u8; 32]>) -> Result<u64, &'static str> {
    let key = key.ok_or("no configuration key")?;
    let e = artstore::entry(dev, Ty::Config).ok_or("no artifact store")?;
    if e.half == 0 {
        return Err("no configuration bundle in force");
    }
    let to = revert(dev, &key, crate::anchor::cfg_gens().cfg_floor);
    unsafe {
        TRIAL = false;
        STATE = Boot::Reverted { from: e.gen, to };
    }
    Ok(to)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick {
    Idle,
    Committed(u64),
    /// The window passed without health: reverted — the caller reboots into the last-known-good configuration.
    RevertReboot,
}

/// Called from the AP loop: commit once healthy, revert after the window.
pub fn tick<D: BlockDev + ?Sized>(dev: &mut D, now_s: u64, healthy: bool) -> Tick {
    unsafe { LAST = now_s };
    if !on_trial() {
        return Tick::Idle;
    }
    if healthy && !touches_mgmt() {
        return match commit(dev) {
            Ok(g) => Tick::Committed(g),
            Err(_) => Tick::Idle,
        };
    }
    if trial_elapsed(now_s) > WINDOW_S {
        let _ = revert_now(dev, crate::policysig::config_key());
        return Tick::RevertReboot;
    }
    Tick::Idle
}

// ---- [P-cfgd] -----------------------------------------------------------------------------------------------

/// The lifecycle on the RAM store with the shared-vector key: stage -> trial -> commit (floor up); a second boot
/// while PENDING reverts to last-known-good; a timeout reverts; an older bundle never becomes a trial.
#[cfg(not(feature = "cm5"))]
pub fn selftest() -> bool {
    use crate::cfgbundle::{KIND_POLICY, KIND_WAN};
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x61; 32]));
    let key: [u8; 32] = *kp.pk;
    let d = artstore::test_disk();
    let mk = |gen: u64, wan: &[u8]| -> ([u8; 512], [u8; 512], usize) {
        // a minimal bundle: wan + policy sections
        let pol = b"acl A seq 10 allow any any any\n";
        let mut b = [0u8; 512];
        b[..8].copy_from_slice(cfgbundle::MAGIC);
        b[8..10].copy_from_slice(&0x0100u16.to_le_bytes());
        b[12..20].copy_from_slice(&gen.to_le_bytes());
        b[36..44].copy_from_slice(&cfgbundle::key_id(&key));
        b[44] = 2;
        b[48] = KIND_WAN;
        b[50..52].copy_from_slice(&(wan.len() as u16).to_le_bytes());
        b[52] = KIND_POLICY;
        b[54..56].copy_from_slice(&(pol.len() as u16).to_le_bytes());
        b[56..56 + wan.len()].copy_from_slice(wan);
        b[56 + wan.len()..56 + wan.len() + pol.len()].copy_from_slice(pol);
        let n = 56 + wan.len() + pol.len();
        let dg = boot_abi::sha256::digest(&b[..n]);
        let mut m = [0u8; 42];
        m[..10].copy_from_slice(cfgbundle::SIG_TAG);
        m[10..].copy_from_slice(&dg);
        let sg = kp.sk.sign(&m[..], Some(ed25519_compact::Noise::from_slice(&[3u8; 16]).unwrap()));
        let mut sig = [0u8; 512];
        sig[..8].copy_from_slice(cfgbundle::SIG_MAGIC);
        sig[8] = 1;
        sig[9..13].copy_from_slice(&(n as u32).to_le_bytes());
        sig[13..45].copy_from_slice(&dg);
        sig[45..109].copy_from_slice(&sg[..]);
        (b, sig, n)
    };
    let stage = |d: &mut artstore::SparseDisk, gen: u64, wan: &[u8]| -> bool {
        let (b, sig, n) = mk(gen, wan);
        let at = artstore::store_region(&*d).map_or(0, |s| s.1 + 40);
        let _ = d.write_block(at, &b);
        artstore::activate(d, Ty::Config, &sig, at, gen, n as u64, &sig[13..45].try_into().unwrap()).is_ok()
    };
    let saved_cfg = crate::anchor::cfg_gens();
    crate::policysig::selftest_key(Some(key));
    // 1. stage gen 5 -> PENDING; boot = trial; the loaders see its wan section; healthy -> commit (floor 5)
    let s1 = stage(d, 5, b"mode=dhcp\n") && artstore::entry(&*d, Ty::Config).is_some_and(|e| e.state == STATE_PENDING);
    let b1 = boot(d, Some(key), 0, 100) == Boot::Trial(5) && section(KIND_WAN) == Some(&b"mode=dhcp\n"[..]);
    let c1 = tick(d, 101, true) == Tick::Committed(5) && artstore::entry(&*d, Ty::Config).is_some_and(|e| e.state == STATE_ACTIVE)
        && crate::anchor::cfg_gens().cfg_floor >= 5;
    let floor = crate::anchor::cfg_gens().cfg_floor;
    let r1 = boot(d, Some(key), floor, 200) == Boot::Committed(5);
    // 2. stage gen 6 (a WAN that never comes up) -> trial; the window passes -> revert to 5, reboot
    let s2 = stage(d, 6, b"mode=static\nip=192.0.2.9/24\ngw=192.0.2.1\n");
    let b2 = boot(d, Some(key), floor, 300) == Boot::Trial(6);
    let t2 = tick(d, 300 + WINDOW_S / 2, false) == Tick::Idle && tick(d, 301 + WINDOW_S, false) == Tick::RevertReboot;
    let back = boot(d, Some(key), floor, 900) == Boot::Committed(5) && section(KIND_WAN) == Some(&b"mode=dhcp\n"[..]);
    // 3. stage gen 7; the trial boot crashes (no tick); the NEXT boot (still PENDING, trials 1) reverts to 5
    let s3 = stage(d, 7, b"mode=dhcp\nvlan=7\n");
    let b3 = boot(d, Some(key), floor, 1000) == Boot::Trial(7);
    let crash = boot(d, Some(key), floor, 1100) == Boot::Reverted { from: 7, to: 5 } && generation() == 5;
    // 4. an older bundle (gen 4 < floor 5) never becomes a trial
    let s4 = stage(d, 4, b"mode=dhcp\n");
    let old = !matches!(boot(d, Some(key), floor, 1200), Boot::Trial(4));
    // 5. peer review: a bundle touching the management VLAN is NOT auto-committed (healthy alone is not enough);
    //    the owner's confirm commits it
    let s5 = stage(d, 8, b"mode=dhcp\nmgmt_vlan=200\nmgmt=dhcp\n");
    let b5 = boot(d, Some(key), crate::anchor::cfg_gens().cfg_floor, 1300) == Boot::Trial(8) && touches_mgmt();
    let held = tick(d, 1301, true) == Tick::Idle && on_trial() && commit(d) == Ok(8);
    // 6. D7: a policy that refuses HTTPS to the device on every management interface is refused at stage
    let lock = keeps_mgmt_path(Some(b"acl X default drop\ninterface lan acl in X\ninterface eth1 acl in X\ninterface mgmt acl in X\n"));
    let fine = keeps_mgmt_path(Some(b"acl X default drop\ninterface mgmt acl in X\n")) && keeps_mgmt_path(None);
    // the peer's counter-example: the device LAN (10.99.0.1/24) blocked to its own clients, 192.168.1.0/24 left open
    // — a sample-constant probe would pass it; the real addressing refuses it
    let lan_lock = keeps_mgmt_path(Some(b"acl X seq 10 block any 10.99.0.0/24 any\nacl X seq 20 allow any any any\ninterface lan acl in X\ninterface eth1 acl in X\ninterface mgmt acl in X\n"));
    let d7 = !lock && fine && !lan_lock;
    crate::policysig::selftest_key(None);
    clear();
    unsafe { STATE = Boot::None };
    crate::anchor::test_set_cfg(saved_cfg);
    let pass = s1 && b1 && c1 && r1 && s2 && b2 && t2 && back && s3 && b3 && crash && s4 && old && s5 && b5 && held && d7;
    arch_aarch64::_print(format_args!(
        " [P-cfgd] {} — ADR 0059 step 3 cfgd (single writer, staged -> trial -> commit / revert): a staged bundle boots as a TRIAL and the loaders read its sections={} healthy -> COMMIT, the bundle floor rises={} committed bundle on the next boot={} a trial that never gets healthy reverts after the window={} the next boot runs the last-known-good={} a second boot while PENDING (crash / power cut) reverts={} an older bundle never becomes a trial={} a bundle touching the management VLAN waits for the owner's confirm (never auto-committed)={} D7: a policy that leaves no management path is refused at stage={}\n",
        if pass { "PASS" } else { "FAIL" }, s1 && b1, c1, r1, s2 && b2 && t2, back, s3 && b3 && crash, s4 && old, s5 && b5 && held, d7
    ));
    pass
}

// ---- CM5 glue: cfgd's own eMMC handle, write-armed over Store only ------------------------------------------

#[cfg(all(feature = "cm5", feature = "p15-write"))]
static mut DEV: Option<arch_aarch64::emmc::Emmc> = None;

#[cfg(all(feature = "cm5", feature = "p15-write"))]
fn device() -> Option<&'static mut arch_aarch64::emmc::Emmc> {
    unsafe {
        if (*core::ptr::addr_of!(DEV)).is_none() {
            let mut dev = arch_aarch64::emmc::Emmc::probe().ok()?;
            let mut mbr = [0u8; 512];
            dev.read_block(0, &mut mbr).ok()?;
            let dv = crate::datavol::DataVol::from_mbr(&mbr)?;
            let (blo, bhi) = dv.bounds();
            dev.set_data_volume(blo, bhi);
            let (lo, hi) = dv.region(crate::datavol::Region::Store);
            if dev.arm_write_window(lo, hi) != (lo, hi) {
                return None;
            }
            DEV = Some(dev);
        }
        (*core::ptr::addr_of_mut!(DEV)).as_mut()
    }
}

/// Boot: run the lifecycle on the device store (after the anchor is pinned, before the configuration loaders).
pub fn boot_device(now_s: u64) -> Boot {
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some(d) = device() {
        return boot(d, crate::policysig::config_key(), crate::anchor::cfg_gens().cfg_floor, now_s);
    }
    let _ = now_s;
    Boot::None
}
pub fn tick_device(now_s: u64, healthy: bool) -> Tick {
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some(d) = device() {
        return tick(d, now_s, healthy);
    }
    let _ = (now_s, healthy);
    Tick::Idle
}
pub fn confirm_device() -> Result<u64, &'static str> {
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some(d) = device() {
        return commit(d);
    }
    Err("no configuration store on this device")
}
pub fn revert_device() -> Result<u64, &'static str> {
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some(d) = device() {
        return revert_now(d, crate::policysig::config_key());
    }
    Err("no configuration store on this device")
}
