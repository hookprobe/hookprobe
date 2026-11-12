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
#[cfg_attr(not(any(feature = "mcserve", feature = "netsvc")), allow(dead_code))]
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
/// Step 11: a digest of the management-plane lines of the sections in force (WAN mgmt / VLAN / PCP keys, policy
/// bindings and routes on `mgmt`). A change in EITHER direction — added, changed or REMOVED — needs the owner's
/// confirm: a bundle that drops the management VLAN can cut the very path the owner manages the device over.
fn mgmt_fp() -> [u8; 32] {
    let mut h = boot_abi::sha256::Hasher::new();
    for l in section(cfgbundle::KIND_WAN).unwrap_or(b"").split(|&b| b == b'\n') {
        if l.starts_with(b"mgmt") || l.starts_with(b"vlan") || l.starts_with(b"pcp") {
            h.update(l);
            h.update(b"\n");
        }
    }
    h.update(b"\x00");
    for l in section(cfgbundle::KIND_POLICY).unwrap_or(b"").split(|&b| b == b'\n') {
        if l.starts_with(b"interface mgmt ") || (l.starts_with(b"route ") && l.windows(9).any(|w| w == b" via mgmt")) {
            h.update(l);
            h.update(b"\n");
        }
    }
    h.finish()
}

/// Step 11: the running device has a management sub-interface (from a bundle or the per-file WAN.TXT).
fn mgmt_running() -> bool {
    #[cfg(feature = "cm5")]
    return unsafe { (*core::ptr::addr_of!(arch_aarch64::uplink::MGMT)).is_some() };
    #[cfg(not(feature = "cm5"))]
    unsafe {
        TEST_MGMT_RUNNING
    }
}
#[cfg(not(feature = "cm5"))]
static mut TEST_MGMT_RUNNING: bool = false;

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
/// SHA-256 of the HQCFG1 bundle in force (zeros = none): what an owner's confirm / rollback envelope binds to.
#[cfg_attr(not(feature = "mcserve"), allow(dead_code))]
static mut DIGEST: [u8; 32] = [0; 32];

pub fn state() -> Boot {
    unsafe { STATE }
}
pub fn generation() -> u64 {
    unsafe { GEN }
}
/// The digest of the bundle in force (on trial or committed; zeros = none) — the same SHA-256 the bundle's HQCSIG1
/// record carries, so the owner computes it from the file they staged (`sha256(bundle)`).
#[cfg_attr(not(feature = "mcserve"), allow(dead_code))]
pub fn bundle_digest() -> [u8; 32] {
    unsafe { DIGEST }
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
        DIGEST = boot_abi::sha256::digest(&buf[..len]);
        VOLATILE = false;
    }
    Some(v.generation)
}

fn clear() {
    unsafe {
        NSEC = 0;
        GEN = 0;
        DIGEST = [0; 32];
        TRIAL = false;
        VOLATILE = false;
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
    let g = generation();
    // Q3: a RAM-only bundle commits in RAM only — no manifest write, no floor (the persisted configuration, which a
    // reboot returns to, must keep verifying above the floor)
    if !volatile() {
        artstore::set_entry(dev, Ty::Config, |x| {
            x.state = STATE_ACTIVE;
            x.trials = 0;
        })
        .map_err(|_| "store write failed")?;
        crate::anchor::commit_cfg_floor(g);
    }
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
    if unsafe { PHASE } == Phase::Trial || (volatile() && unsafe { PHASE } == Phase::Idle) {
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
/// A configuration change is in flight (queued, applying, on trial — live or at boot — or reverting): a new bundle must
/// not be activated now. Activation writes the INACTIVE half — the last-known-good this change reverts to — and
/// re-points the manifest, so the change's revert would take the bundle on trial for the last-known-good (metal
/// 2026-11-12: a failed trial became the committed configuration).
pub fn busy() -> bool {
    (unsafe { PHASE }) != Phase::Idle || on_trial()
}
pub fn last_result() -> (u8, u64) {
    unsafe { LAST_RESULT }
}

/// The window of the trial in force: a live trial uses WINDOW_S when the owner must confirm, else TRIAL_AUTO_S; a
/// boot trial (and no trial: the API's long-standing value) WINDOW_S.
pub fn window_s() -> u64 {
    if on_trial() && unsafe { PHASE } == Phase::Trial && !needs_confirm() {
        TRIAL_AUTO_S
    } else {
        WINDOW_S
    }
}
/// Whether the trial in force waits for the owner's confirm (live: the queue-time rule; boot: management lines).
pub fn confirm_required() -> bool {
    on_trial() && (needs_confirm() || touches_mgmt())
}
/// For the API: the live engine's phase as a word.
pub fn phase_name() -> &'static str {
    match phase() {
        Phase::Idle => "idle",
        Phase::Queued | Phase::Applying => "applying",
        Phase::Trial => "trial",
        Phase::RevertQueued | Phase::Reverting => "reverting",
    }
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
pub const LIVE_CAPABLE: u8 = CH_POLICY | CH_WAN | CH_WIFI;

/// An executor found that the change it applies touches the management plane after all (step 9: the WAN executor when
/// the management sub-interface / floor actually changes, incl. its removal): the trial never auto-commits.
pub fn require_confirm() {
    unsafe {
        if PHASE == Phase::Applying {
            NEEDS_CONFIRM = true;
        }
    }
}

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
    let mgmt_before = mgmt_fp();
    let Some(g) = load_half(dev, e.half, &key, floor + 1) else {
        // does not verify (or not above the floor): back to the last-known-good, nothing was applied
        let to = revert(dev, &key, floor);
        if to == 0 || load_half(dev, artstore::entry(dev, Ty::Config).map_or(0, |x| x.half), &key, floor).is_none() {
            clear();
        }
        return Err("the configuration does not verify");
    };
    Ok(queued(old, mgmt_before, g))
}

/// The common tail of a queued live change: what changed, whether the owner must confirm, the trial state.
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
fn queued(old: [[u8; 32]; 3], mgmt_before: [u8; 32], g: u64) -> u64 {
    let new = section_digests();
    let mut ch = 0u8;
    for (i, bit) in [CH_POLICY, CH_WAN, CH_WIFI].iter().enumerate() {
        if old[i] != new[i] {
            ch |= bit;
        }
    }
    unsafe {
        FAIL_NOW = false;
        MGMT_OK = None;
        CHANGED = ch;
        // the AP is a management path: a Wi-Fi change commits only when the owner confirms after re-joining
        // step 11: also when the management lines changed or were REMOVED, or the running management sub-interface
        // would lose its keys (it came from the per-file WAN.TXT and the bundle's WAN section has none)
        NEEDS_CONFIRM = touches_mgmt()
            || ch & CH_WIFI != 0
            || mgmt_fp() != mgmt_before
            || (ch & CH_WAN != 0 && mgmt_running() && !section(cfgbundle::KIND_WAN).unwrap_or(b"").split(|&b| b == b'\n').any(|l| l.starts_with(b"mgmt")));
        PHASE = Phase::Queued;
        STATE = Boot::Trial(g);
    }
    g
}

// ---- Q3: RAM-only live apply when there is no device key (live-apply follow-up) -----------------------------
// A secret-bearing bundle (a Wi-Fi section, a PPPoE password) cannot be sealed without the per-device SRK and is never
// written in plaintext. It may still be applied LIVE, held in RAM only: verified exactly like a stored bundle
// (signature before any parse, above the committed floor), run through the same live trial, and on commit kept in RAM
// — no manifest write, no floor rise. A reboot returns to the persisted configuration. The API reports it as
// `volatile_ram_only`, never as protected or persisted. A later persisted bundle's live revert goes back to the
// persisted last-known-good, never to the volatile one.
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
static mut VOLATILE: bool = false;
/// The bundle in force (on trial or committed) lives in RAM only.
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
pub fn volatile() -> bool {
    unsafe { VOLATILE }
}

/// Queue a verified secret-bearing container (`cont` = the HQCSIG1 sector ‖ the bundle) for a RAM-only live apply.
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
pub fn queue_live_volatile(key: Option<[u8; 32]>, floor: u64, cont: &[u8]) -> Result<u64, &'static str> {
    if unsafe { PHASE } != Phase::Idle || on_trial() {
        return Err("a configuration change is already in progress");
    }
    let key = key.ok_or("no configuration key")?;
    let sig: &[u8; 512] = cont.get(..512).and_then(|s| s.try_into().ok()).ok_or("the configuration does not verify")?;
    let len = u32::from_le_bytes([sig[9], sig[10], sig[11], sig[12]]) as usize;
    if !(cfgbundle::HDR..=cfgbundle::MAX_BUNDLE).contains(&len) || cont.len() < 512 + len {
        return Err("the configuration does not verify");
    }
    let bundle = &cont[512..512 + len];
    // signature (and device binding, generation above the committed floor) BEFORE anything is parsed or replaced
    let v = cfgbundle::verify(bundle, sig, &key, &crate::config_device_id(), floor).map_err(|_| "the configuration does not verify")?;
    let mut secs = [(0u8, 0usize, 0usize); 3];
    let mut n = 0;
    for (k, b) in v.sections() {
        secs[n] = (k, b.as_ptr() as usize - bundle.as_ptr() as usize, b.len());
        n += 1;
    }
    let g = v.generation;
    let old = section_digests();
    let mgmt_before = mgmt_fp();
    unsafe {
        let buf = &mut *core::ptr::addr_of_mut!(BUF);
        buf[..len].copy_from_slice(bundle);
        SECS = secs;
        NSEC = n;
        GEN = g;
        DIGEST = boot_abi::sha256::digest(bundle);
        VOLATILE = true;
    }
    Ok(queued(old, mgmt_before, g))
}

// ---- the trial's health beyond "WAN usable" (live-apply follow-up) ------------------------------------------
// Q5 in the loop: the PPPoE dial is no longer blocking, so a definitive authentication reject arrives after the
// executor returned — the loop reports it here and the live trial reverts at once (no window).
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
static mut FAIL_NOW: bool = false;
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
pub fn wan_auth_rejected() {
    unsafe {
        if matches!(PHASE, Phase::Applying | Phase::Trial) && CHANGED & CH_WAN != 0 {
            FAIL_NOW = true;
        }
    }
}
/// Rule 7 after a WAN change: the management re-probe (`wanlive::mgmt_reprobe` — the management sub-interface's
/// address / next hop and the owner's own client path), fed by the loop while a trial runs. Some(false) holds the
/// trial (never auto-committed: it reverts at the window); None = not probed.
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
static mut MGMT_OK: Option<bool> = None;
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
static mut MGMT_WHY: &str = "";
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
pub fn set_mgmt_health(ok: Option<bool>, why: &'static str) {
    unsafe {
        MGMT_OK = ok;
        MGMT_WHY = why;
    }
}
/// For the API: (management re-probe result, its reason) while a trial runs.
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
pub fn mgmt_health() -> (Option<bool>, &'static str) {
    if on_trial() {
        unsafe { (MGMT_OK, MGMT_WHY) }
    } else {
        (None, "")
    }
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
    let key = crate::policysig::config_key();
    let to = if volatile() {
        // Q3: nothing of the RAM-only bundle was persisted — the persisted entry IS the last-known-good (no flip)
        let e = artstore::entry(dev, Ty::Config).unwrap_or(artstore::E0);
        match key.filter(|_| e.half != 0 && e.state == STATE_ACTIVE).and_then(|k| load_half(dev, e.half, &k, floor)) {
            Some(g) => g,
            None => {
                clear();
                0
            }
        }
    } else {
        match key {
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
        }
    };
    unsafe {
        TRIAL = false;
        FAIL_NOW = false;
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
    // a WAN that comes up but loses the management path is NOT healthy (rule 7)
    let healthy = healthy && unsafe { MGMT_OK } != Some(false);
    if unsafe { PHASE } == Phase::Trial {
        if unsafe { FAIL_NOW } {
            start_live_revert(dev); // Q5: the PPPoE authentication was rejected — revert now, not at the window
            return Tick::Reverting;
        }
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
    // 7. step 11: a bundle that REMOVES the management VLAN needs the owner's confirm (as does adding it); so does a
    //    WAN change while a per-file management sub-interface runs and the bundle carries no mgmt keys
    let wm = &b"mode=dhcp\nmgmt_vlan=20\nmgmt_ip=192.168.200.146/24\n"[..];
    let fl7 = crate::anchor::cfg_gens().cfg_floor;
    let add = stage(d, 12, wm, f2, p2) && queue_live(d, Some(key), fl7) == Ok(12) && needs_confirm()
        && take_apply().is_some() && applied(d, true, 1000) == Tick::Idle && commit(d) == Ok(12);
    let fl7 = crate::anchor::cfg_gens().cfg_floor;
    let removed = stage(d, 13, w1, f2, p2) && queue_live(d, Some(key), fl7) == Ok(13) && needs_confirm()
        && take_apply().is_some() && applied(d, true, 1100) == Tick::Idle && commit(d) == Ok(13);
    let fl7 = crate::anchor::cfg_gens().cfg_floor;
    unsafe { TEST_MGMT_RUNNING = true };
    let perfile = stage(d, 14, w2, f2, p2) && queue_live(d, Some(key), fl7) == Ok(14) && needs_confirm();
    unsafe { TEST_MGMT_RUNNING = false };
    let _ = take_apply();
    let _ = applied(d, true, 1200);
    let _ = commit(d);
    let fl7 = crate::anchor::cfg_gens().cfg_floor;
    let plain = stage(d, 15, w1, f2, p2) && queue_live(d, Some(key), fl7) == Ok(15) && !needs_confirm()
        && take_apply().is_some() && applied(d, true, 1300) == Tick::Idle && tick(d, 1301, true) == Tick::Committed(15);
    let mgmt11 = add && removed && perfile && plain;
    let (mg, q5) = live_mgmt_checks(d, key, &stage);
    let vol = live_volatile_checks(d, key, &mk);
    crate::policysig::selftest_key(None);
    clear();
    unsafe {
        STATE = Boot::None;
        PHASE = Phase::Idle;
        LAST_RESULT = (0, 0);
    }
    crate::anchor::test_set_cfg(saved_cfg);
    let pass = base && s1 && p_1 && c1 && s2 && p_2 && t2 && r2 && s3 && c3 && s4 && busy && f5 && s5 && rb && s6 && crash && mgmt11;
    let pm = mg.iter().all(|&x| x) && q5;
    arch_aarch64::_print(format_args!(
        " [P-cfgd-mgmt] {} — live-apply follow-up, rule 7 after a WAN change (WAN reachability is not management reachability): the re-probe sees a management sub-interface without an address / without a resolved gateway / the owner's on-link client unresolved / a routed owner without a management gateway as LOST, the owner on the AP, resolved, or routed over a resolved gateway as kept={} a live WAN trial whose management is lost is NOT auto-committed although the WAN is usable, the API reports it, the window reverts it live={} the same change with management kept auto-commits={} Q5 in the loop: a PPPoE authentication reject reported after the executor returned reverts the live trial at once (no window)={}\n",
        if pm { "PASS" } else { "FAIL" }, mg[0], mg[1], mg[2], q5
    ));
    let pv = vol.iter().all(|&x| x);
    arch_aarch64::_print(format_args!(
        " [P-cfgd-volatile] {} — live-apply follow-up, Q3 RAM-only apply (no device key): a tampered or not-newer-than-the-floor bundle is refused before anything is replaced={} a verified secret-bearing bundle applies live from RAM and commits in RAM only — manifest entry, floor and disk unchanged, the secret never on disk, reported volatile={} a live rollback of it re-loads the persisted last-known-good without a manifest flip={} a RAM-only trial that is not healthy reverts live at the window={} a reboot after a RAM-only commit returns to the persisted configuration={}\n",
        if pv { "PASS" } else { "FAIL" }, vol[0], vol[1], vol[2], vol[3], vol[4]
    ));
    let pass = pass && pm && pv;
    arch_aarch64::_print(format_args!(
        " [P-cfgd-live] {} — sealed-config / live-apply step 6, the cfgd live engine (mock executors): only the changed subsystem is applied={} healthy -> committed live, no reboot={} an unusable WAN reverts LIVE after the window to the last-known-good sections={} a Wi-Fi change waits for the owner's confirm={} one change at a time={} a failed apply reverts live={} a failed revert asks for the reboot (manifest already at the LKG)={} a crash during the live trial boots the last-known-good={} step 11: adding OR removing the management VLAN (or dropping a per-file one) needs the owner's confirm, a plain WAN change does not={}\n",
        if pass { "PASS" } else { "FAIL" }, base && s1 && p_1, c1, s2 && p_2 && t2 && r2, s3 && c3, s4 && busy, f5, s5 && rb, s6 && crash, mgmt11
    ));
    pass
}

/// [P-cfgd-mgmt]: the management re-probe (pure) and its effect on a live WAN trial; Q5 from the loop. Runs on the
/// live self-test's disk after generation 15 committed. Returns ([pure probe, lost -> held + reverted, kept ->
/// committed], Q5).
#[cfg(not(feature = "cm5"))]
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
fn live_mgmt_checks(d: &mut artstore::SparseDisk, key: [u8; 32], stage: &dyn Fn(&mut artstore::SparseDisk, u64, &[u8], &[u8], &[u8]) -> bool) -> ([bool; 3], bool) {
    use crate::wanlive::{mgmt_reprobe, MgmtProbe as P, MgmtSeen};
    let lan = ([10, 99, 0, 1], 24);
    let seen = |mgmt: Option<([u8; 4], u8, [u8; 4], bool)>, owner: [u8; 4], owner_resolved: bool| MgmtSeen { mgmt, lan, owner, owner_resolved };
    let m = Some(([192, 168, 200, 2], 24, [192, 168, 200, 1], true));
    let pure = mgmt_reprobe(&seen(None, [10, 99, 0, 50], false)) == P::Ok
        && mgmt_reprobe(&seen(Some(([0; 4], 0, [0; 4], false)), [0; 4], false)) == P::NoAddress
        && mgmt_reprobe(&seen(Some(([192, 168, 200, 2], 24, [192, 168, 200, 1], false)), [10, 99, 0, 50], false)) == P::NoNextHop
        && mgmt_reprobe(&seen(m, [192, 168, 200, 50], false)) == P::OwnerLost
        && mgmt_reprobe(&seen(m, [192, 168, 200, 50], true)) == P::Ok
        && mgmt_reprobe(&seen(m, [172, 16, 0, 9], false)) == P::Ok
        && mgmt_reprobe(&seen(Some(([192, 168, 200, 2], 24, [0; 4], true)), [172, 16, 0, 9], false)) == P::OwnerLost
        && mgmt_reprobe(&seen(m, [10, 99, 0, 50], false)) == P::Ok
        && mgmt_reprobe(&seen(None, [172, 16, 0, 9], false)) == P::Ok
        && P::Ok.word() == "ok" && P::NoNextHop.word() != P::OwnerLost.word();
    let (w1, w3) = (&b"mode=dhcp\n"[..], &b"mode=static\nip=192.0.2.10/24\ngw=192.0.2.1\n"[..]);
    let f2 = &b"ssid=home\npsk=correct horse 2\n"[..];
    let p2 = &b"acl A seq 10 allow any any any\nacl A seq 20 drop tcp any any 23\n"[..];
    let fl = crate::anchor::cfg_gens().cfg_floor;
    // a plain WAN change (auto-commit): usable WAN, management LOST -> held, reported, reverted live at the window
    let lost = stage(d, 16, w3, f2, p2) && queue_live(d, Some(key), fl) == Ok(16) && !needs_confirm() && take_apply().is_some()
        && applied(d, true, 2000) == Tick::Idle && {
            set_mgmt_health(Some(false), P::NoNextHop.word());
            tick(d, 2001, true) == Tick::Idle
        }
        && phase() == Phase::Trial && mgmt_health() == (Some(false), P::NoNextHop.word())
        && tick(d, 2002 + TRIAL_AUTO_S, true) == Tick::Reverting && take_apply().is_some_and(|p| p.revert && p.generation == 15)
        && applied(d, true, 2200) == Tick::Reverted(15) && mgmt_health() == (None, "");
    let fl = crate::anchor::cfg_gens().cfg_floor;
    let kept = stage(d, 17, w3, f2, p2) && queue_live(d, Some(key), fl) == Ok(17) && take_apply().is_some() && applied(d, true, 2300) == Tick::Idle
        && {
            set_mgmt_health(Some(true), P::Ok.word());
            tick(d, 2301, true) == Tick::Committed(17)
        };
    // Q5: the dial is stepped by the loop now, so the reject arrives after the executor returned
    wan_auth_rejected(); // no trial: ignored
    let fl = crate::anchor::cfg_gens().cfg_floor;
    let wp = &b"mode=pppoe\npppoe_user=u@isp\npppoe_pass=wrong\n"[..];
    let q5 = stage(d, 18, wp, f2, p2) && queue_live(d, Some(key), fl) == Ok(18) && take_apply().is_some() && applied(d, true, 2400) == Tick::Idle
        && tick(d, 2401, false) == Tick::Idle && {
            wan_auth_rejected();
            tick(d, 2402, false) == Tick::Reverting
        }
        && take_apply().is_some_and(|p| p.revert && p.generation == 17) && applied(d, true, 2403) == Tick::Reverted(17);
    let _ = w1;
    ([pure, lost, kept], q5)
}

/// [P-cfgd-volatile]: Q3 RAM-only live apply on the live self-test's disk (generation 17 persisted + committed).
#[cfg(not(feature = "cm5"))]
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
fn live_volatile_checks(d: &mut artstore::SparseDisk, key: [u8; 32], mk: &dyn Fn(u64, &[u8], &[u8], &[u8]) -> ([u8; 1024], [u8; 512], usize)) -> [bool; 5] {
    use crate::cfgbundle::KIND_WAN;
    let f2 = &b"ssid=home\npsk=correct horse 2\n"[..];
    let p2 = &b"acl A seq 10 allow any any any\nacl A seq 20 drop tcp any any 23\n"[..];
    let wv = &b"mode=pppoe\npppoe_user=v@isp\npppoe_pass=v0latile\n"[..];
    let fl = crate::anchor::cfg_gens().cfg_floor;
    let cont = |gen: u64| {
        let (b, sig, n) = mk(gen, wv, f2, p2);
        let mut c = [0u8; 512 + 1024];
        c[..512].copy_from_slice(&sig);
        c[512..512 + n].copy_from_slice(&b[..n]);
        (c, 512 + n)
    };
    let e0 = artstore::entry(&*d, Ty::Config);
    let same = |d: &artstore::SparseDisk| artstore::entry(d, Ty::Config) == e0 && crate::anchor::cfg_gens().cfg_floor == fl && !artstore::on_disk(d, b"v0latile");
    // 1. verified BEFORE anything is replaced: a flipped bundle byte, a generation not above the floor
    let (mut bad, n) = cont(19);
    bad[512 + 60] ^= 1;
    let (old, no) = cont(fl);
    let refused = queue_live_volatile(Some(key), fl, &bad[..n]).is_err() && queue_live_volatile(Some(key), fl, &old[..no]).is_err()
        && queue_live_volatile(None, fl, &cont(19).0[..n]).is_err()
        && generation() == 17 && !volatile() && phase() == Phase::Idle && section(KIND_WAN) != Some(wv);
    // 2. applied live from RAM; the commit stays in RAM (no manifest write, no floor, nothing on disk)
    let (c, n) = cont(19);
    let applied_ram = queue_live_volatile(Some(key), fl, &c[..n]) == Ok(19) && volatile() && section(KIND_WAN) == Some(wv)
        && take_apply() == Some(Plan { changed: CH_WAN, revert: false, generation: 19 }) && applied(d, true, 2500) == Tick::Idle
        && tick(d, 2501, true) == Tick::Committed(19) && volatile() && generation() == 19 && same(d);
    // 3. the owner rolls it back live: the persisted entry IS the last-known-good (no flip)
    let rolled = revert_now(d, Some(key)) == Ok(17) && take_apply().is_some_and(|p| p.revert && p.generation == 17)
        && applied(d, true, 2502) == Tick::Reverted(17) && !volatile() && generation() == 17 && section(KIND_WAN) != Some(wv) && same(d);
    // 4. a RAM-only trial that never gets healthy reverts live at the window
    let window = queue_live_volatile(Some(key), fl, &c[..n]) == Ok(19) && take_apply().is_some() && applied(d, true, 2600) == Tick::Idle
        && tick(d, 2601 + TRIAL_AUTO_S, false) == Tick::Reverting && take_apply().is_some() && applied(d, true, 2700) == Tick::Reverted(17)
        && !volatile() && same(d);
    // 5. a reboot after a RAM-only commit: the persisted configuration, nothing volatile
    let reboot = queue_live_volatile(Some(key), fl, &c[..n]) == Ok(19) && take_apply().is_some() && applied(d, true, 2800) == Tick::Idle
        && tick(d, 2801, true) == Tick::Committed(19) && same(d) && boot(d, Some(key), fl, 2900) == Boot::Committed(17) && !volatile()
        && generation() == 17;
    [refused, applied_ram, rolled, window, reboot]
}

/// [P-cfgd-lkg] (metal 2026-11-12, cm5-cfgd-live-check C2): the live revert's target is the PERSISTED last-known-good.
/// gen 1 auto-commits -> gen 2 (management lines) is confirmed by the owner -> gen 3 (dead gateway) never gets
/// healthy: the live revert goes to gen 2 and a reboot keeps gen 2 — the failed bundle is never committed. Again with
/// gen 2 never confirmed (its window reverts it to gen 1; gen 3's revert also goes to gen 1). Plaintext and sealed. Gens
/// 2 and 3 carry vlan= / mgmt_ lines (as the bench bundles do), so they are NEEDS-CONFIRM trials (`touches_mgmt`, 300 s);
/// gen 3 is the metal path: a needs-confirm trial that fails health. The metal defect itself (a bundle uploaded during
/// a trial overwrote the last-known-good half) is reproduced through the upload path in [P-upload].
#[cfg(not(feature = "cm5"))]
pub fn lkg_selftest() -> bool {
    use crate::cfgbundle::{KIND_POLICY, KIND_WAN};
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x63; 32]));
    let key: [u8; 32] = *kp.pk;
    let mk = |gen: u64, wan: &[u8], pol: &[u8]| -> ([u8; 1024], usize) {
        // container: HQCSIG1 sector ‖ the bundle
        let secs: [(u8, &[u8]); 2] = [(KIND_WAN, wan), (KIND_POLICY, pol)];
        let present = secs.iter().filter(|x| !x.1.is_empty()).count();
        let mut c = [0u8; 1024];
        let b = &mut c[512..];
        b[..8].copy_from_slice(cfgbundle::MAGIC);
        b[8..10].copy_from_slice(&0x0100u16.to_le_bytes());
        b[12..20].copy_from_slice(&gen.to_le_bytes());
        b[36..44].copy_from_slice(&cfgbundle::key_id(&key));
        b[44] = present as u8;
        let (mut t, mut o) = (48, 48 + 4 * present);
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
        let sg = kp.sk.sign(&m[..], Some(ed25519_compact::Noise::from_slice(&[6u8; 16]).unwrap()));
        c[..8].copy_from_slice(cfgbundle::SIG_MAGIC);
        c[8] = 1;
        c[9..13].copy_from_slice(&(o as u32).to_le_bytes());
        c[13..45].copy_from_slice(&dg);
        c[45..109].copy_from_slice(&sg[..]);
        (c, o)
    };
    // an upload's activation: sealed into the inactive half with a device key, else the signed plaintext
    let stage = |d: &mut artstore::SparseDisk, sealed: bool, gen: u64, wan: &[u8], pol: &[u8]| -> bool {
        let (c, n) = mk(gen, wan, pol);
        if sealed {
            return artstore::activate_sealed(d, Ty::Config, &c[..512 + n], gen, n as u64).is_ok();
        }
        let sig: [u8; 512] = c[..512].try_into().unwrap();
        artstore::activate_from(d, Ty::Config, &sig, artstore::Src::Ram(&c[512..512 + n]), gen, n as u64, &sig[13..45].try_into().unwrap()).is_ok()
    };
    let fl = || crate::anchor::cfg_gens().cfg_floor;
    let pol = &b"acl A seq 10 allow any any any\n"[..];
    let w2 = &b"mode=static\nip=10.100.0.200/24\ngw=10.100.0.1\nvlan=100\nmgmt_vlan=200\nmgmt=dhcp\n"[..];
    let w3 = &b"mode=static\nip=10.100.0.200/24\ngw=10.100.0.254\nvlan=100\nmgmt_vlan=200\nmgmt=dhcp\n"[..];
    let saved_cfg = crate::anchor::cfg_gens();
    crate::policysig::selftest_key(Some(key));
    let mut r = [false; 4];
    for (i, &(sealed, confirm)) in [(false, true), (true, true), (false, false), (true, false)].iter().enumerate() {
        let d = artstore::test_disk();
        crate::anchor::test_set_cfg(crate::anchor::CfgGens::ZERO);
        if sealed {
            artstore::set_cfg_seal(Some([0x3c; 32]), 0x1eaf);
        } else {
            artstore::set_cfg_seal(None, 0);
        }
        clear();
        unsafe {
            STATE = Boot::None;
            PHASE = Phase::Idle;
        }
        let t = 10_000 * i as u64;
        // gen 1: policy only, auto-commits live
        let g1 = stage(d, sealed, 1, b"", pol) && queue_live(d, Some(key), fl()) == Ok(1) && take_apply().is_some()
            && applied(d, true, t + 1) == Tick::Idle && tick(d, t + 2, true) == Tick::Committed(1);
        // gen 2: static WAN with the management lines — live, waits for the owner's confirm
        let q2 = stage(d, sealed, 2, w2, pol) && queue_live(d, Some(key), fl()) == Ok(2) && needs_confirm() && take_apply().is_some()
            && applied(d, true, t + 10) == Tick::Idle && tick(d, t + 11, true) == Tick::Idle;
        let (g2, lkg) = if confirm {
            (q2 && commit(d) == Ok(2) && fl() == 2, 2)
        } else {
            // never confirmed: the window reverts it live to gen 1
            (q2 && tick(d, t + 12 + WINDOW_S, true) == Tick::Reverting && take_apply().is_some_and(|p| p.revert && p.generation == 1)
                && applied(d, true, t + 13 + WINDOW_S) == Tick::Reverted(1), 1)
        };
        // gen 3: the gateway never answers — the window reverts it LIVE to the persisted last-known-good
        let t3 = t + 1000;
        let g3 = stage(d, sealed, 3, w3, pol) && queue_live(d, Some(key), fl()) == Ok(3) && take_apply().is_some()
            && applied(d, true, t3) == Tick::Idle && tick(d, t3 + 1, false) == Tick::Idle
            && tick(d, t3 + 2 + WINDOW_S, false) == Tick::Reverting;
        let rv = take_apply().is_some_and(|p| p.revert && p.generation == lkg) && applied(d, true, t3 + 3 + WINDOW_S) == Tick::Reverted(lkg)
            && generation() == lkg && artstore::entry(&*d, Ty::Config).is_some_and(|e| e.gen == lkg && e.state == STATE_ACTIVE);
        // a reboot keeps the last-known-good; the failed bundle is never in force
        let rb = boot(d, Some(key), fl(), t3 + 5000) == Boot::Committed(lkg) && section(KIND_WAN) == if confirm { Some(w2) } else { None };
        r[i] = g1 && g2 && g3 && rv && rb;
        if !r[i] {
            arch_aarch64::_print(format_args!(" [P-cfgd-lkg] case {} (sealed={} confirmed={}): gen1={} gen2={} gen3 trial={} live revert={} (to {}) reboot={} (gen {})\n",
                i, sealed, confirm, g1, g2, g3, rv, last_result().1, rb, generation()));
        }
    }
    artstore::clear_cfg_seal();
    crate::policysig::selftest_key(None);
    clear();
    unsafe {
        STATE = Boot::None;
        PHASE = Phase::Idle;
        LAST_RESULT = (0, 0);
    }
    crate::anchor::test_set_cfg(saved_cfg);
    let pass = r.iter().all(|&x| x);
    arch_aarch64::_print(format_args!(
        " [P-cfgd-lkg] {} — a live trial that never gets healthy reverts LIVE to the PERSISTED last-known-good and a reboot keeps it (the failed bundle is never committed): owner-confirmed gen 2, plaintext={} sealed={}; gen 2 never confirmed (reverted to gen 1), plaintext={} sealed={}\n",
        if pass { "PASS" } else { "FAIL" }, r[0], r[1], r[2], r[3]
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
    // step 8 gate: against no bundle in force, a policy-only bundle is live-capable, (step 9) one with a WAN section
    // too, and (step 10) one with a Wi-Fi section — which also always needs the owner's confirm (queue_live)
    clear();
    let pol_only = changes_vs(Some(b"acl A seq 10 allow any any any\n"), None, None);
    let with_wan = changes_vs(Some(b"acl A seq 10 allow any any any\n"), Some(b"mode=dhcp\n"), None);
    let with_wifi = changes_vs(None, Some(b"mode=dhcp\n"), Some(b"ssid=home\npsk=correct horse 1\n"));
    let gate = pol_only == CH_POLICY && pol_only & !LIVE_CAPABLE == 0 && with_wan == CH_POLICY | CH_WAN && with_wan & !LIVE_CAPABLE == 0
        && with_wifi == CH_WAN | CH_WIFI && with_wifi & !LIVE_CAPABLE == 0 && LIVE_CAPABLE == CH_POLICY | CH_WAN | CH_WIFI
        && changes_vs(None, None, None) == 0;
    let pass = good && bad && cut && before && owner_ok && other && tight && gate;
    arch_aarch64::_print(format_args!(
        " [P-cfgd-policy] {} — sealed-config / live-apply step 7, the live policy executor: a good policy swaps in and the policy generation advances={} an unparseable policy is refused and the policy in force kept (never a live lockdown)={} a policy cutting every management path is refused live={} F-e the owner's own client keeps its HTTPS path (a /32 block of it is refused once the owner is known)={} another client's /32 is fine={} a tighter policy swaps in={} step 8/9/10: policy, WAN and Wi-Fi changes are applied live={}\n",
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
/// Upload self-test hook (QEMU): the live queue runs on the self-test disk, so `[P-upload]` proves the activation
/// hand-off end to end (the #1001 merge had silently dropped it).
#[cfg(not(feature = "cm5"))]
static mut TEST_LIVE: bool = false;
#[cfg(not(feature = "cm5"))]
pub fn set_test_live(on: bool) {
    unsafe {
        TEST_LIVE = on;
        if !on {
            PHASE = Phase::Idle;
            STATE = Boot::None;
            CHANGED = 0;
            NEEDS_CONFIRM = false;
            MGMT_OK = None;
            FAIL_NOW = false;
        }
    }
    if !on {
        clear();
    }
}

/// Step 8: queue the just-activated bundle for live apply on the device store.
pub fn queue_live_device() -> Result<u64, &'static str> {
    #[cfg(not(feature = "cm5"))]
    if unsafe { TEST_LIVE } {
        let d = unsafe { &mut *core::ptr::addr_of_mut!(artstore::TEST_DISK) };
        return queue_live(d, crate::policysig::config_key(), crate::anchor::cfg_gens().cfg_floor);
    }
    if in_selftest() {
        return Err("self-test: no state change");
    }
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some(d) = device() {
        return queue_live(d, crate::policysig::config_key(), crate::anchor::cfg_gens().cfg_floor);
    }
    Err("no configuration store on this device")
}
/// Q3: queue a secret-bearing bundle for a RAM-only live apply (no device key). Needs the device's configuration
/// store all the same: the live revert re-loads the persisted last-known-good from it.
#[cfg_attr(not(feature = "netsvc"), allow(dead_code))]
pub fn queue_live_volatile_device(cont: &[u8]) -> Result<u64, &'static str> {
    #[cfg(not(feature = "cm5"))]
    if unsafe { TEST_LIVE } {
        return queue_live_volatile(crate::policysig::config_key(), crate::anchor::cfg_gens().cfg_floor, cont);
    }
    if in_selftest() {
        return Err("self-test: no state change");
    }
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if device().is_some() {
        return queue_live_volatile(crate::policysig::config_key(), crate::anchor::cfg_gens().cfg_floor, cont);
    }
    let _ = cont;
    Err("not stored: no device key — secrets are never written in plaintext")
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

/// QEMU self-tests only: pose a bundle in force (`gen`, `digest`, on trial or not) for the envelope binding checks,
/// and put it back afterwards. Never in a CM5 build.
#[cfg(all(not(feature = "cm5"), feature = "hsh"))]
pub fn test_pose(gen: u64, digest: [u8; 32], trial: bool) -> (u64, [u8; 32], bool) {
    unsafe {
        let was = (GEN, DIGEST, TRIAL);
        GEN = gen;
        DIGEST = digest;
        TRIAL = trial;
        was
    }
}

pub fn confirm_device() -> Result<u64, &'static str> {
    if in_selftest() {
        return Err("self-test: no state change");
    }
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some(d) = device() {
        let r = commit(d);
        if let Ok(g) = r {
            arch_aarch64::_print(format_args!(" [CFGD] bundle generation {} COMMITTED (owner confirm)\n", g));
        }
        return r;
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
