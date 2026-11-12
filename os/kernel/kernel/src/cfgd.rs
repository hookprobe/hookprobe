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
    keeps_mgmt_path_parsed(pol)
}

/// F-e (sealed-config design §0): the address the authenticated owner manages the device from — recorded when an
/// owner-authenticated upload begins or a configuration confirm arrives. A policy must keep THAT client's path too,
/// not only sample hosts of the subnet (a `/32` block of the owner's own client used to pass).
static mut OWNER: [u8; 4] = [0; 4];
pub fn note_owner(peer: [u8; 4]) {
    if peer != [0; 4] && peer != [127, 0, 0, 1] {
        unsafe { OWNER = peer };
    }
}
#[cfg(not(feature = "cm5"))]
pub fn owner() -> [u8; 4] {
    unsafe { OWNER }
}

/// The D7 probe on an already-parsed policy (stage check, and the live policy executor's re-probe before the swap).
pub fn keeps_mgmt_path_parsed(pol: &mut hal::policy::Policy) -> bool {
    use hal::policy::{Act, Addr, Dir, If, Pkt};
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
    let any = paths.iter().filter(|p| p.0 != 0xff).any(|&(i, dev, pl)| {
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
    });
    // F-e: the owner's own client keeps its path — on the interface whose subnet holds it, else (routed in from
    // elsewhere) on the management VLAN when there is one
    let owner = unsafe { OWNER };
    if !any || owner == [0; 4] {
        return any;
    }
    let o = u32::from_be_bytes(owner);
    let on = paths.iter().filter(|p| p.0 != 0xff).find(|&&(_, dev, pl)| {
        let mask = if pl == 0 { 0 } else { u32::MAX << (32 - pl as u32) };
        (o & mask) == (u32::from_be_bytes(dev) & mask)
    });
    let path = on.or_else(|| paths.iter().find(|p| p.0 as usize == If::Mgmt.idx()));
    match path {
        Some(&(i, dev, _)) => {
            let p = Pkt { proto: 6, src: Addr::v4(owner), dst: Addr::v4(dev), dport: 443 };
            pol.check(ifs[i as usize], Dir::In, &p).0 == Act::Allow
        }
        None => true, // the owner is not on any of the device's management paths (unknown topology): the subnet probe stands
    }
}

/// Step 7, the live policy executor: parse into `scratch`; refuse (keeping the policy in force) when it does not
/// parse or would cut the management path / the owner's own client; otherwise swap it in with one struct copy and
/// bump the policy generation. Never a live lockdown. Established flows are kept (Q4).
pub fn swap_policy(file: &[u8], live: &mut hal::policy::Policy, scratch: &mut hal::policy::Policy) -> bool {
    *scratch = hal::policy::Policy::new();
    hal::policy::parse_policy(file, scratch).is_ok() && install_policy(live, scratch)
}

/// The second half of the swap, for a policy already parsed into `scratch` (the per-file chain).
pub fn install_policy(live: &mut hal::policy::Policy, scratch: &mut hal::policy::Policy) -> bool {
    if !keeps_mgmt_path_parsed(scratch) {
        return false;
    }
    // the probe's own counts are not traffic
    scratch.pl_drops = [0; hal::policy::BIND_MAX];
    for a in scratch.acl.iter_mut() {
        a.hits = [0; hal::policy::ACL_ENTRIES];
        a.default_hits = 0;
    }
    *live = *scratch;
    unsafe { POLICY_GEN += 1 };
    true
}

/// Bumped on every live policy swap (the hook for SMP publication later, ADR 0060 D7).
pub static mut POLICY_GEN: u64 = 0;
pub fn policy_gen() -> u64 {
    unsafe { POLICY_GEN }
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
    // a sealed bundle is read through the plaintext view (seal MAC first, then cfgbundle's own signature check)
    let dev = &artstore::Plain::new(dev);
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
        None => artstore::set_entry(dev, Ty::Config, |x| *x = artstore::E0).map(|_| 0),
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
        if PHASE == Phase::Trial {
            PHASE = Phase::Idle;
            LAST_RESULT = (1, g);
        }
    }
    Ok(g)
}

/// REVERT now (trial timeout, or the owner): the previous half becomes active for the NEXT boot.
pub fn revert_now<D: BlockDev + ?Sized>(dev: &mut D, key: Option<[u8; 32]>) -> Result<u64, &'static str> {
    if unsafe { PHASE } == Phase::Trial {
        start_live_revert(dev);
        return Ok(unsafe { REVERT_GEN });
    }
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

// ---- live apply (design docs/design heqk-sealed-config-live-apply, step 6): "move the chairs without leaving" ----
// A new bundle is applied in place by the AP loop's executors (policy, then WAN, then Wi-Fi — only what changed),
// runs a live trial, commits when healthy (or on the owner's confirm), and otherwise REVERTS LIVE to the
// last-known-good. The manifest semantics are the boot path's: `trials = 1` is persisted BEFORE anything is
// applied, so a crash / power cut / watchdog during the live trial boots into the last-known-good. A reboot is the
// last resort only (the revert's executors failed).

/// Changed-subsystem bits (apply order: policy, WAN, Wi-Fi).
pub const CH_POLICY: u8 = 1;
pub const CH_WAN: u8 = 2;
pub const CH_WIFI: u8 = 4;
/// Trial window for a change that may commit by itself (WAN usable + management path) — confirm-bound changes keep
/// WINDOW_S.
pub const TRIAL_AUTO_S: u64 = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    /// A verified bundle is loaded; the executors run on the next loop iteration (after the HTTP reply went out).
    Queued,
    Applying,
    Trial,
    /// The manifest already points at the last-known-good; its sections are loaded; the executors re-apply them.
    RevertQueued,
    Reverting,
}

/// What the AP loop must (re-)apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub changed: u8,
    pub revert: bool,
    pub generation: u64,
}

static mut PHASE: Phase = Phase::Idle;
static mut CHANGED: u8 = 0;
static mut NEEDS_CONFIRM: bool = false;
static mut REVERT_GEN: u64 = 0;
/// (result, generation): 0 none, 1 committed, 2 reverted live, 3 revert failed (reboot into the last-known-good).
static mut LAST_RESULT: (u8, u64) = (0, 0);

pub fn phase() -> Phase {
    unsafe { PHASE }
}
pub fn changes() -> u8 {
    unsafe { CHANGED }
}
pub fn needs_confirm() -> bool {
    unsafe { NEEDS_CONFIRM }
}
pub fn last_result() -> (u8, u64) {
    unsafe { LAST_RESULT }
}

/// The digest of each section kind of the bundle in force ([0; 32] = absent: the per-file source applies).
fn section_digests() -> [[u8; 32]; 3] {
    let mut d = [[0u8; 32]; 3];
    for (i, k) in [cfgbundle::KIND_POLICY, cfgbundle::KIND_WAN, cfgbundle::KIND_WIFI].iter().enumerate() {
        if let Some(b) = section(*k) {
            d[i] = boot_abi::sha256::digest(b);
        }
    }
    d
}

/// The subsystems this build applies LIVE (grows with the executors: WAN step 9, Wi-Fi step 10). A bundle that changes
/// anything else keeps the next-boot PENDING trial (step 8).
pub const LIVE_CAPABLE: u8 = CH_POLICY;

/// Which subsystems a verified bundle's sections would change against the sections in force (stage time).
pub fn changes_vs(pol: Option<&[u8]>, wan: Option<&[u8]>, wifi: Option<&[u8]>) -> u8 {
    let cur = section_digests();
    let mut ch = 0u8;
    for (i, (sec, bit)) in [(pol, CH_POLICY), (wan, CH_WAN), (wifi, CH_WIFI)].iter().enumerate() {
        if sec.map_or([0u8; 32], boot_abi::sha256::digest) != cur[i] {
            ch |= bit;
        }
    }
    ch
}

/// Queue a just-activated (PENDING, never tried) bundle for live apply. `floor` = the committed bundle floor.
pub fn queue_live<D: BlockDev + ?Sized>(dev: &mut D, key: Option<[u8; 32]>, floor: u64) -> Result<u64, &'static str> {
    if unsafe { PHASE } != Phase::Idle || on_trial() {
        return Err("a configuration change is already in progress");
    }
    let key = key.ok_or("no configuration key")?;
    let e = artstore::entry(dev, Ty::Config).ok_or("no artifact store")?;
    if e.half == 0 || e.state != STATE_PENDING || e.trials != 0 {
        return Err("no new configuration to apply");
    }
    // persisted FIRST: from here on a crash / power cut / watchdog boots into the last-known-good
    artstore::set_entry(dev, Ty::Config, |x| x.trials = 1).map_err(|_| "store write failed")?;
    let old = section_digests();
    let Some(g) = load_half(dev, e.half, &key, floor + 1) else {
        // does not verify (or not above the floor): back to the last-known-good, nothing was applied
        let to = revert(dev, &key, floor);
        if to == 0 || load_half(dev, artstore::entry(dev, Ty::Config).map_or(0, |x| x.half), &key, floor).is_none() {
            clear();
        }
        return Err("the configuration does not verify");
    };
    let new = section_digests();
    let mut ch = 0u8;
    for (i, bit) in [CH_POLICY, CH_WAN, CH_WIFI].iter().enumerate() {
        if old[i] != new[i] {
            ch |= bit;
        }
    }
    unsafe {
        CHANGED = ch;
        // the AP is a management path: a Wi-Fi change commits only when the owner confirms after re-joining
        NEEDS_CONFIRM = touches_mgmt() || ch & CH_WIFI != 0;
        PHASE = Phase::Queued;
        STATE = Boot::Trial(g);
    }
    Ok(g)
}

/// The AP loop: what to (re-)apply now, if anything (the executors read `section()`: the new bundle, or after a
/// revert the last-known-good / the per-file sources).
pub fn take_apply() -> Option<Plan> {
    unsafe {
        match PHASE {
            Phase::Queued => {
                PHASE = Phase::Applying;
                Some(Plan { changed: CHANGED, revert: false, generation: GEN })
            }
            Phase::RevertQueued => {
                PHASE = Phase::Reverting;
                Some(Plan { changed: CHANGED, revert: true, generation: REVERT_GEN })
            }
            _ => None,
        }
    }
}

/// Live revert: the manifest flips to the last-known-good FIRST, then its sections are loaded for the executors.
fn start_live_revert<D: BlockDev + ?Sized>(dev: &mut D) {
    let floor = crate::anchor::cfg_gens().cfg_floor;
    let to = match crate::policysig::config_key() {
        Some(k) => {
            let to = revert(dev, &k, floor);
            if to == 0 || load_half(dev, artstore::entry(dev, Ty::Config).map_or(0, |x| x.half), &k, floor).is_none() {
                clear();
                0
            } else {
                to
            }
        }
        None => {
            clear();
            0
        }
    };
    unsafe {
        TRIAL = false;
        REVERT_GEN = to;
        PHASE = Phase::RevertQueued;
    }
}

/// The executors' outcome for the plan `take_apply` returned. `Tick::RevertReboot` = even the last-known-good could
/// not be re-applied: reboot (the manifest already points at it).
pub fn applied<D: BlockDev + ?Sized>(dev: &mut D, ok: bool, now_s: u64) -> Tick {
    unsafe {
        match PHASE {
            Phase::Applying if ok => {
                PHASE = Phase::Trial;
                TRIAL = true;
                T0 = now_s;
                LAST = now_s;
                Tick::Idle
            }
            Phase::Applying => {
                start_live_revert(dev);
                Tick::Reverting
            }
            Phase::Reverting if ok => {
                PHASE = Phase::Idle;
                LAST_RESULT = (2, REVERT_GEN);
                STATE = if REVERT_GEN == 0 { Boot::None } else { Boot::Committed(REVERT_GEN) };
                Tick::Reverted(REVERT_GEN)
            }
            Phase::Reverting => {
                PHASE = Phase::Idle;
                LAST_RESULT = (3, REVERT_GEN);
                Tick::RevertReboot
            }
            _ => Tick::Idle,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick {
    /// Live trial: the window passed / the owner rolled back — the last-known-good is queued for the executors.
    Reverting,
    /// Live revert done: the last-known-good (this generation, 0 = per-file) is in force again, no reboot.
    Reverted(u64),
    Idle,
    Committed(u64),
    /// The window passed without health: reverted — the caller reboots into the last-known-good configuration.
    RevertReboot,
}

/// Called from the AP loop: commit once healthy, revert after the window.
pub fn tick<D: BlockDev + ?Sized>(dev: &mut D, now_s: u64, healthy: bool) -> Tick {
    unsafe { LAST = now_s };
    if unsafe { PHASE } == Phase::Trial {
        if healthy && !needs_confirm() {
            return match commit(dev) {
                Ok(g) => Tick::Committed(g),
                Err(_) => Tick::Idle,
            };
        }
        let window = if needs_confirm() { WINDOW_S } else { TRIAL_AUTO_S };
        if trial_elapsed(now_s) > window {
            start_live_revert(dev);
            return Tick::Reverting;
        }
        return Tick::Idle;
    }
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
        && crate::anchor::cfg_gens().cfg_floor >= 5
        // metal batch 61: the upload path's "active generation" of a bundle is the manifest's, not HQCSIG1 [8..16]
        && artstore::active_gen(&*d, 0, Ty::Config) == 5;
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

// ---- [P-cfgd-live] (step 6) ---------------------------------------------------------------------------------

/// The live engine on the RAM store with mock executors: only changed subsystems are applied; healthy -> commit
/// without a reboot; an unhealthy WAN reverts LIVE after the window to the last-known-good sections; a Wi-Fi change
/// waits for the owner's confirm; a failed apply reverts live; a failed revert asks for the reboot; one change at a
/// time; a crash during the live trial boots into the last-known-good.
#[cfg(not(feature = "cm5"))]
pub fn live_selftest() -> bool {
    use crate::cfgbundle::{KIND_POLICY, KIND_WAN, KIND_WIFI};
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x62; 32]));
    let key: [u8; 32] = *kp.pk;
    let d = artstore::test_disk();
    let mk = |gen: u64, wan: &[u8], wifi: &[u8], pol: &[u8]| -> ([u8; 1024], [u8; 512], usize) {
        let secs: [(u8, &[u8]); 3] = [(KIND_WAN, wan), (KIND_WIFI, wifi), (KIND_POLICY, pol)];
        let present: usize = secs.iter().filter(|x| !x.1.is_empty()).count();
        let mut b = [0u8; 1024];
        b[..8].copy_from_slice(cfgbundle::MAGIC);
        b[8..10].copy_from_slice(&0x0100u16.to_le_bytes());
        b[12..20].copy_from_slice(&gen.to_le_bytes());
        b[36..44].copy_from_slice(&cfgbundle::key_id(&key));
        b[44] = present as u8;
        let mut t = 48;
        let mut o = 48 + 4 * present;
        for (k, body) in secs.iter().filter(|x| !x.1.is_empty()) {
            b[t] = *k;
            b[t + 2..t + 4].copy_from_slice(&(body.len() as u16).to_le_bytes());
            b[o..o + body.len()].copy_from_slice(body);
            t += 4;
            o += body.len();
        }
        let dg = boot_abi::sha256::digest(&b[..o]);
        let mut m = [0u8; 42];
        m[..10].copy_from_slice(cfgbundle::SIG_TAG);
        m[10..].copy_from_slice(&dg);
        let sg = kp.sk.sign(&m[..], Some(ed25519_compact::Noise::from_slice(&[4u8; 16]).unwrap()));
        let mut sig = [0u8; 512];
        sig[..8].copy_from_slice(cfgbundle::SIG_MAGIC);
        sig[8] = 1;
        sig[9..13].copy_from_slice(&(o as u32).to_le_bytes());
        sig[13..45].copy_from_slice(&dg);
        sig[45..109].copy_from_slice(&sg[..]);
        (b, sig, o)
    };
    let stage = |d: &mut artstore::SparseDisk, gen: u64, wan: &[u8], wifi: &[u8], pol: &[u8]| -> bool {
        let (b, sig, n) = mk(gen, wan, wifi, pol);
        let at = artstore::store_region(&*d).map_or(0, |s| s.1 + 40);
        let mut s0 = [0u8; 512];
        let mut s1 = [0u8; 512];
        s0.copy_from_slice(&b[..512]);
        s1.copy_from_slice(&b[512..]);
        let _ = d.write_block(at, &s0);
        let _ = d.write_block(at + 1, &s1);
        artstore::activate(d, Ty::Config, &sig, at, gen, n as u64, &sig[13..45].try_into().unwrap()).is_ok()
    };
    let saved_cfg = crate::anchor::cfg_gens();
    crate::policysig::selftest_key(Some(key));
    clear();
    let (w1, w2) = (&b"mode=dhcp\n"[..], &b"mode=static\nip=192.0.2.9/24\ngw=192.0.2.1\n"[..]);
    let (f1, f2) = (&b"ssid=home\npsk=correct horse 1\n"[..], &b"ssid=home\npsk=correct horse 2\n"[..]);
    let (p1, p2) = (&b"acl A seq 10 allow any any any\n"[..], &b"acl A seq 10 allow any any any\nacl A seq 20 drop tcp any any 23\n"[..]);
    // baseline: gen 5 committed through the boot path
    let base = stage(d, 5, w1, f1, p1) && boot(d, Some(key), 0, 10) == Boot::Trial(5) && tick(d, 11, true) == Tick::Committed(5);
    let mut fl = crate::anchor::cfg_gens().cfg_floor;
    // 1. policy-only change: only the policy is (re)applied; healthy -> committed live, no reboot
    let s1 = stage(d, 6, w1, f1, p2) && queue_live(d, Some(key), fl) == Ok(6);
    let p_1 = take_apply() == Some(Plan { changed: CH_POLICY, revert: false, generation: 6 }) && section(KIND_POLICY) == Some(p2);
    let c1 = applied(d, true, 100) == Tick::Idle && phase() == Phase::Trial && tick(d, 101, true) == Tick::Committed(6)
        && phase() == Phase::Idle && last_result() == (1, 6) && artstore::entry(&*d, Ty::Config).is_some_and(|e| e.state == STATE_ACTIVE && e.gen == 6);
    fl = crate::anchor::cfg_gens().cfg_floor;
    // 2. a WAN that never becomes usable: the window passes -> LIVE revert to gen 6 (its WAN section re-applied)
    let s2 = stage(d, 7, w2, f1, p2) && queue_live(d, Some(key), fl) == Ok(7);
    let p_2 = take_apply() == Some(Plan { changed: CH_WAN, revert: false, generation: 7 });
    let t2 = applied(d, true, 200) == Tick::Idle && tick(d, 200 + TRIAL_AUTO_S / 2, false) == Tick::Idle
        && tick(d, 201 + TRIAL_AUTO_S, false) == Tick::Reverting;
    let r2 = take_apply() == Some(Plan { changed: CH_WAN, revert: true, generation: 6 }) && section(KIND_WAN) == Some(w1)
        && applied(d, true, 400) == Tick::Reverted(6) && phase() == Phase::Idle && last_result() == (2, 6)
        && artstore::entry(&*d, Ty::Config).is_some_and(|e| e.state == STATE_ACTIVE && e.gen == 6);
    // 3. a Wi-Fi change: healthy is not enough (the AP is a management path) — the owner's confirm commits it
    let s3 = stage(d, 8, w1, f2, p2) && queue_live(d, Some(key), fl) == Ok(8) && needs_confirm();
    let c3 = take_apply().is_some_and(|p| p.changed == CH_WIFI) && applied(d, true, 500) == Tick::Idle
        && tick(d, 501, true) == Tick::Idle && phase() == Phase::Trial && commit(d) == Ok(8) && phase() == Phase::Idle;
    fl = crate::anchor::cfg_gens().cfg_floor;
    // 4. one change at a time
    let s4 = stage(d, 9, w2, f2, p2) && queue_live(d, Some(key), fl) == Ok(9);
    let busy = queue_live(d, Some(key), fl).is_err();
    // 5. the apply fails -> LIVE revert to 8; then (gen 10) the revert itself fails -> reboot into the LKG
    let f5 = take_apply().is_some() && applied(d, false, 600) == Tick::Reverting
        && take_apply() == Some(Plan { changed: CH_WAN, revert: true, generation: 8 }) && applied(d, true, 601) == Tick::Reverted(8);
    let s5 = stage(d, 10, w2, f2, p2) && queue_live(d, Some(key), fl) == Ok(10);
    let rb = take_apply().is_some() && applied(d, false, 700) == Tick::Reverting && take_apply().is_some_and(|p| p.revert)
        && applied(d, false, 701) == Tick::RevertReboot && last_result() == (3, 8)
        && artstore::entry(&*d, Ty::Config).is_some_and(|e| e.gen == 8 && e.state == STATE_ACTIVE);
    // 6. a crash during a live trial: trials=1 was persisted first -> the next boot reverts to the last-known-good
    let s6 = stage(d, 11, w2, f2, p2) && queue_live(d, Some(key), fl) == Ok(11) && take_apply().is_some() && applied(d, true, 800) == Tick::Idle;
    unsafe { PHASE = Phase::Idle };
    let crash = boot(d, Some(key), fl, 900) == Boot::Reverted { from: 11, to: 8 };
    crate::policysig::selftest_key(None);
    clear();
    unsafe {
        STATE = Boot::None;
        PHASE = Phase::Idle;
        LAST_RESULT = (0, 0);
    }
    crate::anchor::test_set_cfg(saved_cfg);
    let pass = base && s1 && p_1 && c1 && s2 && p_2 && t2 && r2 && s3 && c3 && s4 && busy && f5 && s5 && rb && s6 && crash;
    arch_aarch64::_print(format_args!(
        " [P-cfgd-live] {} — sealed-config / live-apply step 6, the cfgd live engine (mock executors): only the changed subsystem is applied={} healthy -> committed live, no reboot={} an unusable WAN reverts LIVE after the window to the last-known-good sections={} a Wi-Fi change waits for the owner's confirm={} one change at a time={} a failed apply reverts live={} a failed revert asks for the reboot (manifest already at the LKG)={} a crash during the live trial boots the last-known-good={}\n",
        if pass { "PASS" } else { "FAIL" }, base && s1 && p_1, c1, s2 && p_2 && t2 && r2, s3 && c3, s4 && busy, f5, s5 && rb, s6 && crash
    ));
    pass
}

/// [P-cfgd-policy] (step 7): the live policy executor and the owner-address probe (F-e).
#[cfg(not(feature = "cm5"))]
pub fn policy_selftest() -> bool {
    use hal::policy::Policy;
    static mut LIVE: Policy = Policy::new();
    static mut SCR: Policy = Policy::new();
    let live = unsafe { &mut *core::ptr::addr_of_mut!(LIVE) };
    let scr = unsafe { &mut *core::ptr::addr_of_mut!(SCR) };
    let saved = unsafe { OWNER };
    unsafe { OWNER = [0; 4] };
    let p1: &[u8] = b"HQPOL1\nacl A seq 10 allow any any any\ninterface lan acl in A\n";
    let p2: &[u8] = b"HQPOL1\nacl A seq 10 drop tcp any any 23\nacl A seq 20 allow any any any\ninterface lan acl in A\n";
    // blocks ONE client (the owner's) from the device's HTTPS; every other LAN host still reaches it
    let own: &[u8] = b"HQPOL1\nacl A seq 10 drop tcp 10.99.0.50/32 any 443\nacl A seq 20 allow any any any\ninterface lan acl in A\n";
    let lock: &[u8] = b"HQPOL1\nacl A default drop\ninterface lan acl in A\ninterface eth1 acl in A\ninterface mgmt acl in A\n";
    *live = Policy::new();
    let g0 = policy_gen();
    // 1. a good policy swaps in (one struct copy), the policy generation advances
    let good = swap_policy(p1, live, scr) && live.nacl == 1 && policy_gen() == g0 + 1;
    // 2. an unparseable policy is refused: the policy in force is kept, no generation bump, never a lockdown
    let bad = !swap_policy(b"HQPOL1\nacl A seq 10 frobnicate\n", live, scr) && live.nacl == 1 && policy_gen() == g0 + 1;
    // 3. a policy that cuts every management path is refused live too
    let cut = !swap_policy(lock, live, scr) && live.nacl == 1;
    // 4. F-e: without a known owner the /32 block passes the subnet probe; once the owner's client is known it is
    //    refused (stage check and live swap alike)
    let before = swap_policy(own, live, scr);
    let _ = swap_policy(p1, live, scr);
    note_owner([10, 99, 0, 50]);
    let owner_ok = owner() == [10, 99, 0, 50] && !swap_policy(own, live, scr) && live.nacl == 1;
    // another client of the owner's subnet blocked is fine (the owner's path stands)
    let other = swap_policy(b"HQPOL1\nacl A seq 10 drop tcp 10.99.0.77/32 any 443\nacl A seq 20 allow any any any\ninterface lan acl in A\n", live, scr);
    // 5. a tighter policy swaps in (established flows are kept: the swap touches only the rule table)
    let tight = swap_policy(p2, live, scr) && live.nacl == 1 && live.acl[0].n == 2;
    unsafe { OWNER = saved };
    // step 8 gate: against no bundle in force, a policy-only bundle is live-capable; one with a WAN or Wi-Fi section
    // keeps the next-boot trial until those executors exist (steps 9, 10)
    clear();
    let pol_only = changes_vs(Some(b"acl A seq 10 allow any any any\n"), None, None);
    let with_wan = changes_vs(Some(b"acl A seq 10 allow any any any\n"), Some(b"mode=dhcp\n"), None);
    let gate = pol_only == CH_POLICY && pol_only & !LIVE_CAPABLE == 0 && with_wan & !LIVE_CAPABLE != 0
        && changes_vs(None, None, None) == 0;
    let pass = good && bad && cut && before && owner_ok && other && tight && gate;
    arch_aarch64::_print(format_args!(
        " [P-cfgd-policy] {} — sealed-config / live-apply step 7, the live policy executor: a good policy swaps in and the policy generation advances={} an unparseable policy is refused and the policy in force kept (never a live lockdown)={} a policy cutting every management path is refused live={} F-e the owner's own client keeps its HTTPS path (a /32 block of it is refused once the owner is known)={} another client's /32 is fine={} a tighter policy swaps in={} step 8: only a policy-only change is applied live, WAN / Wi-Fi changes keep the next-boot trial={}\n",
        if pass { "PASS" } else { "FAIL" }, good, bad, cut, before && owner_ok, other, tight, gate
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
/// Step 8: queue the just-activated bundle for live apply on the device store.
pub fn queue_live_device() -> Result<u64, &'static str> {
    if in_selftest() {
        return Err("self-test: no state change");
    }
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some(d) = device() {
        return queue_live(d, crate::policysig::config_key(), crate::anchor::cfg_gens().cfg_floor);
    }
    Err("no configuration store on this device")
}
/// Step 8: report the executors' result for the plan `take_apply` handed out.
pub fn applied_device(ok: bool, now_s: u64) -> Tick {
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some(d) = device() {
        return applied(d, ok, now_s);
    }
    let _ = (ok, now_s);
    Tick::Idle
}
/// Read access for an executor that falls back to the per-file sources (the sealed view over cfgd's handle).
#[cfg(all(feature = "cm5", feature = "p15-write"))]
pub fn with_device<R>(f: impl FnOnce(&arch_aarch64::emmc::Emmc) -> R) -> Option<R> {
    device().map(|d| f(&*d))
}

/// Self-tests exercise the ABI paths that would confirm / roll back: while set, those refuse WITHOUT touching the
/// device's real configuration state (metal batch 60: a boot self-test committed a live trial).
static mut SELFTEST: bool = false;
pub fn set_selftest(on: bool) {
    unsafe { SELFTEST = on };
}
fn in_selftest() -> bool {
    unsafe { SELFTEST }
}

pub fn confirm_device() -> Result<u64, &'static str> {
    if in_selftest() {
        return Err("self-test: no state change");
    }
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some(d) = device() {
        return commit(d);
    }
    Err("no configuration store on this device")
}
pub fn revert_device() -> Result<u64, &'static str> {
    if in_selftest() {
        return Err("self-test: no state change");
    }
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some(d) = device() {
        return revert_now(d, crate::policysig::config_key());
    }
    Err("no configuration store on this device")
}
