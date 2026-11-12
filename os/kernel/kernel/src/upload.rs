//! ADR 0056 — the device-side upload interface (phase 1: signed data packs).
//!
//! `POST /api/upload/begin` (owner re-auth) → `POST /api/upload/chunk?id=&off=` (raw bytes, in order) →
//! `POST /api/upload/finish` (digest + the module's own signature verifier + anti-rollback) →
//! `POST /api/upload/activate` (owner re-auth; artifact store A/B + live reload, rollback on refusal) |
//! `POST /api/upload/abort`. One upload in flight; idle uploads expire after 10 minutes.
//!
//! The upload is a CONTAINER: the pack's 512-byte signature file followed by the file itself
//! (`cat X.SIG X.TXT`). The client never chooses a path: the type picks the slot.
//!
//! Every guard of the owner-rules API applies (session, Origin = Host, CSRF, per-session seq on the
//! begin / finish / activate / abort steps; chunks are bound to the upload id, the session and the exact
//! offset). Nothing here is trusted: the operator signature is the authority (ADR 0049 D1 key).

use crate::actionapi::{form_get, origin_ok, Ctx};
use crate::artstore::{self, Ty};
use hal::{BlockDev, BlockErr};

pub const CHUNK_MAX: usize = crate::httpreq::UPLOAD_CHUNK_MAX;
const IDLE_MS: u64 = 10 * 60 * 1000;

/// A `Sized` handle on the store device (the loaders are generic over `D: BlockDev`).
pub struct DevRef(*mut dyn BlockDev);
impl BlockDev for DevRef {
    fn block_count(&self) -> u64 {
        unsafe { (*self.0).block_count() }
    }
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr> {
        unsafe { (*self.0).read_block(lba, buf) }
    }
    fn write_block(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), BlockErr> {
        unsafe { (*self.0).write_block(lba, buf) }
    }
    fn read_blocks(&self, lba: u64, out: &mut [u8]) -> Result<(), BlockErr> {
        unsafe { (*self.0).read_blocks(lba, out) }
    }
    fn admit_inactive_slot(&mut self) -> Option<(u64, u64, u32)> {
        unsafe { (*self.0).admit_inactive_slot() }
    }
    fn revoke_inactive_slot(&mut self) {
        unsafe { (*self.0).revoke_inactive_slot() }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Receiving,
    Verified,
}

struct Up {
    id: u64,
    session: [u8; 4],
    ty: Ty,
    size: u64,
    sha: [u8; 32],
    got: u64,
    h: boot_abi::sha256::Hasher,
    part: [u8; 512],
    plen: usize,
    last_ms: u64,
    phase: Phase,
    gen: u64,
    len: u64,
    /// An OS image (`os_image`), not a data pack: the container is the signed boot image itself.
    os: bool,
    /// Q3 (set at finish): the verified configuration carries a secret (PPPoE password / any Wi-Fi).
    secret: bool,
    /// R6 = D (set at finish): the staged content's SHA-256 (os_image: the image digest) — what the owner's activate
    /// envelope binds.
    digest: [u8; 32],
    #[cfg(feature = "p15-write")]
    plan: Option<crate::otaimg::Plan>,
}

/// Audit code of the upload in flight (an OS image has no pack type).
const OS_CODE: u8 = 0xfe;
fn code(ty: Option<Ty>, os: bool) -> u8 {
    if os { OS_CODE } else { ty.map_or(0xff, |t| t as u8) }
}
fn cur_code() -> u8 {
    up().as_ref().map_or(0xff, |u| code(Some(u.ty), u.os))
}

/// Set by an `os_image` activation: the AP loop reboots into the trial slot once the HTTP
/// response has gone out (`take_trial_reboot`).
static mut TRIAL_REBOOT: bool = false;
pub fn take_trial_reboot() -> bool {
    unsafe { core::mem::replace(&mut *core::ptr::addr_of_mut!(TRIAL_REBOOT), false) }
}

/// (running SVN, anti-rollback floor for an update, payload hash HBoot measured). Without an HBoot
/// handoff (QEMU) there is no running measurement and the floor is the compile-time 1.
fn boot_facts() -> (u64, u64, Option<[u8; 32]>) {
    #[cfg(feature = "hboot")]
    {
        use boot_abi::{BootInfo, BOOTINFO_ADDR, BOOTINFO_MAGIC};
        let bi = unsafe { &*(BOOTINFO_ADDR as *const BootInfo) };
        if bi.magic == BOOTINFO_MAGIC {
            return (bi.svn, bi.svn.max(bi.svn_floor).max(1), Some(bi.kernel_hash));
        }
    }
    (0, 1, None)
}

static mut DEV: Option<DevRef> = None;
static mut UP: Option<Up> = None;

// ---- staged configuration uploads stay in RAM (design heqk-sealed-config-live-apply F-b) ----
// A WAN / Wi-Fi / POLICY / CONFIG container (signature sector ‖ file, at most 512 + 16 KiB) is received here, never
// into the eMMC Staging region; it is verified from here and scrubbed when the upload ends.
const STAGE_LEN: usize = 512 + crate::cfgbundle::MAX_BUNDLE;
static mut STAGE_RAM: [u8; STAGE_LEN] = [0; STAGE_LEN];
fn stage_ram() -> &'static mut [u8; STAGE_LEN] {
    unsafe { &mut *core::ptr::addr_of_mut!(STAGE_RAM) }
}
/// The verifiers read the RAM container as a block device: LBA 0 = the signature sector, LBA 1.. = the file.
struct RamStage;
impl BlockDev for RamStage {
    fn block_count(&self) -> u64 {
        (STAGE_LEN / 512) as u64
    }
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr> {
        let o = (lba as usize).checked_mul(512).filter(|o| o + 512 <= STAGE_LEN).ok_or(BlockErr::OutOfRange)?;
        buf.copy_from_slice(&stage_ram()[o..o + 512]);
        Ok(())
    }
}
static mut RAMSTAGE: RamStage = RamStage;
fn ram_dev() -> DevRef {
    DevRef(core::ptr::addr_of_mut!(RAMSTAGE) as *mut dyn BlockDev)
}
fn ram_staged(u: &Up) -> bool {
    !u.os && u.ty.staged()
}
/// End the upload in flight and scrub the RAM stage (it may hold a secret).
fn end() {
    *up() = None;
    for b in stage_ram().iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}
static mut CTR: u64 = 0;

// ---- audit ring (RAM; activations are ALSO durable journal records) ----
#[derive(Clone, Copy)]
struct Ev {
    ms: u64,
    session: [u8; 4],
    step: &'static str,
    ty: u8,
    ok: bool,
    why: &'static str,
    gen: u64,
}
const EV0: Ev = Ev { ms: 0, session: [0; 4], step: "", ty: 0xff, ok: false, why: "", gen: 0 };
static mut EVS: [Ev; 32] = [EV0; 32];
static mut EHEAD: usize = 0;

fn audit(c: &Ctx, step: &'static str, ty: u8, ok: bool, why: &'static str, gen: u64) {
    unsafe {
        EVS[EHEAD % 32] = Ev { ms: c.now_ms, session: crate::mcauth::session_tag(c.session), step, ty, ok, why, gen };
        EHEAD += 1;
    }
}

/// The store device: an eMMC handle whose write window covers ONLY Store ∪ Staging.
pub fn install(dev: &'static mut dyn BlockDev) {
    unsafe { DEV = Some(DevRef(dev as *mut dyn BlockDev)) };
}
pub fn installed() -> bool {
    unsafe { (*core::ptr::addr_of!(DEV)).is_some() }
}

fn dev() -> Option<&'static mut DevRef> {
    unsafe { (*core::ptr::addr_of_mut!(DEV)).as_mut() }
}
fn up() -> &'static mut Option<Up> {
    unsafe { &mut *core::ptr::addr_of_mut!(UP) }
}

fn staging(d: &DevRef) -> Option<(u64, u64)> {
    let mut mbr = [0u8; 512];
    d.read_block(0, &mut mbr).ok()?;
    Some(crate::datavol::DataVol::from_mbr(&mbr)?.region(crate::datavol::Region::Staging))
}
fn p1(d: &DevRef) -> u64 {
    let mut mbr = [0u8; 512];
    if d.read_block(0, &mut mbr).is_ok() { crate::store::parse_mbr(&mbr)[0].start } else { 0 }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut o = [0u8; 32];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(o)
}
fn id_of(s: &str) -> Option<u64> {
    (s.len() == 16).then(|| u64::from_str_radix(s, 16).ok()).flatten()
}

/// Shared guards for the form steps (begin / finish / activate / abort).
fn guards(c: &Ctx, body: &[u8]) -> Result<(), &'static str> {
    if !origin_ok(c.origin, c.host) {
        return Err("origin");
    }
    if !crate::mcauth::csrf_ok(c.session, c.csrf) {
        return Err("csrf");
    }
    let mut b = [0u8; 192];
    let seq: u64 = form_get(body, "seq", &mut b).and_then(|v| v.parse().ok()).unwrap_or(0);
    if !crate::actions::accept_seq(crate::mcauth::session_tag(c.session), seq) {
        return Err("replay");
    }
    Ok(())
}

/// Drop an upload idle for more than 10 min (also run by `GET /api/upload`, so a stalled upload never
/// lingers in the status after its window).
pub fn expire(now_ms: u64) {
    if let Some(u) = up() {
        if now_ms.saturating_sub(u.last_ms) > IDLE_MS {
            end();
        }
    }
}

/// The in-flight upload for this request's `id` and session.
fn mine(c: &Ctx, id: Option<u64>) -> Result<&'static mut Up, &'static str> {
    let tag = crate::mcauth::session_tag(c.session);
    match up() {
        Some(u) if Some(u.id) == id && u.session == tag => Ok(u),
        _ => Err("unknown upload id"),
    }
}

pub struct Begun {
    pub id: u64,
}

/// `begin`: type, size (container bytes = 512 + file), sha256 (hex, over the container), owner_key, seq.
pub fn begin(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<Begun, &'static str> {
    let r = begin_inner(c, body, auth);
    let mut b = [0u8; 192];
    let name = form_get(body, "type", &mut b);
    let ty = name.and_then(Ty::from_name);
    audit(c, "begin", code(ty, name == Some("os_image")), r.is_ok(), r.as_ref().err().copied().unwrap_or(""), 0);
    r
}
fn begin_inner(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<Begun, &'static str> {
    guards(c, body)?;
    expire(c.now_ms);
    let mut b = [[0u8; 192]; 4];
    let [ref mut b0, ref mut b1, ref mut b2, ref mut b3] = b;
    let name = form_get(body, "type", b0).ok_or("type")?;
    let os = name == "os_image";
    #[cfg(not(feature = "p15-write"))]
    if os {
        return Err("this image cannot update its OS over the network (read-only build)");
    }
    let ty = if os { Ty::Block } else { Ty::from_name(name).ok_or("type")? };
    let size: u64 = form_get(body, "size", b1).and_then(|v| v.parse().ok()).ok_or("size")?;
    let sha = form_get(body, "sha256", b2).and_then(hex32).ok_or("sha256")?;
    let key = form_get(body, "owner_key", b3).unwrap_or("");
    if artstore::key_for(ty).is_none() {
        return Err("no operator key in this image: unsigned packs are never accepted over the network");
    }
    // ADR 0059: while an HQCFG1 bundle is in force its sections win over the per-file WAN / Wi-Fi / POLICY — a
    // per-file upload would be silently ignored (metal batch 60). Refuse it, and say what to do instead.
    if matches!(ty, Ty::Wan | Ty::Wifi | Ty::Policy) && dev().and_then(|d| artstore::entry(&*d, Ty::Config)).is_some_and(|e| e.half != 0) {
        return Err("a configuration bundle is in force: change this with a new bundle (type config), or roll the bundle back first");
    }
    #[cfg(feature = "p15-write")]
    if os && !(crate::otaimg::IMG_MIN..=crate::otaimg::IMG_MAX).contains(&size) {
        return Err("size");
    }
    if !os && (size <= 512 || size > 512 + ty.info().cap) {
        return Err("size");
    }
    let d = dev().ok_or("no artifact store (no DataVolume or a RAM-only image)")?;
    let (slo, shi) = staging(d).ok_or("no staging region")?;
    if size.div_ceil(512) > shi - slo {
        return Err("size");
    }
    if up().is_some() {
        return Err("another upload is in flight");
    }
    if !auth.reauth(key.trim().as_bytes(), c.now_ms) {
        return Err("re-authentication failed");
    }
    let tag = crate::mcauth::session_tag(c.session);
    let id = unsafe {
        CTR += 1;
        let mut m = [0u8; 24];
        m[..4].copy_from_slice(&tag);
        m[4..12].copy_from_slice(&c.now_ms.to_le_bytes());
        m[12..20].copy_from_slice(&CTR.to_le_bytes());
        u64::from_le_bytes(boot_abi::sha256::digest(&m)[..8].try_into().unwrap()) | 1
    };
    end();
    *up() = Some(Up { id, session: tag, ty, size, sha, got: 0, h: boot_abi::sha256::Hasher::new(), part: [0; 512], plen: 0, last_ms: c.now_ms, phase: Phase::Receiving, gen: 0, len: 0, os, secret: false, digest: [0; 32], #[cfg(feature = "p15-write")] plan: None });
    Ok(Begun { id })
}

/// `chunk?id=&off=`: the next `body` bytes (≤ CHUNK_MAX) at exactly `off`.
pub fn chunk(c: &Ctx, query: &str, body: &[u8]) -> Result<u64, &'static str> {
    if !origin_ok(c.origin, c.host) {
        return Err("origin");
    }
    if !crate::mcauth::csrf_ok(c.session, c.csrf) {
        return Err("csrf");
    }
    expire(c.now_ms);
    let id = query.split('&').find_map(|kv| kv.strip_prefix("id=")).and_then(id_of);
    let off: u64 = query.split('&').find_map(|kv| kv.strip_prefix("off=")).and_then(|v| v.parse().ok()).ok_or("off")?;
    let u = mine(c, id)?;
    if u.phase != Phase::Receiving || off != u.got || body.is_empty() || body.len() > CHUNK_MAX || u.got + body.len() as u64 > u.size {
        return Err("chunk out of order or too large");
    }
    let d = dev().ok_or("no artifact store")?;
    let (slo, _) = staging(d).ok_or("no staging region")?;
    u.h.update(body);
    if ram_staged(u) {
        // configuration: RAM only (begin bounds size <= 512 + cap <= STAGE_LEN)
        let o = u.got as usize;
        stage_ram()[o..o + body.len()].copy_from_slice(body);
        u.got += body.len() as u64;
        u.last_ms = c.now_ms;
        return Ok(u.got);
    }
    for &byte in body {
        u.part[u.plen] = byte;
        u.plen += 1;
        if u.plen == 512 {
            let lba = slo + u.got / 512;
            if d.write_block(lba, &u.part).is_err() {
                end();
                return Err("staging write failed");
            }
            u.plen = 0;
        }
        u.got += 1;
    }
    u.last_ms = c.now_ms;
    Ok(u.got)
}

pub struct Finished {
    pub gen: u64,
    pub active_gen: u64,
    pub len: u64,
    /// R6 = D: the staged content's SHA-256 — the activate envelope binds it (with the type code and generation).
    pub digest: [u8; 32],
}

/// The content digest inside a pack's signature sector: POLICY.SIG has no length field (digest at 16..48, over the
/// whole 4 KiB file); HQCSIG1 carries sha256(bundle) at 13..45; every other format carries len at 16..24 and the
/// digest at 24..56. The same digest the owner computes over the file it signed.
fn content_digest(ty: Ty, sig: &[u8; 512]) -> [u8; 32] {
    match ty {
        Ty::Policy => sig[16..48].try_into().unwrap(),
        Ty::Config => sig[13..45].try_into().unwrap(),
        _ => sig[24..56].try_into().unwrap(),
    }
}


/// `finish`: id, seq. Digest, then the module's own verifier, then anti-rollback (gen ≥ active).
pub fn finish(c: &Ctx, body: &[u8]) -> Result<Finished, &'static str> {
    let ty = cur_code();
    let r = finish_inner(c, body);
    audit(c, "finish", ty, r.is_ok(), r.as_ref().err().copied().unwrap_or(""), r.as_ref().map_or(0, |f| f.gen));
    if r.is_err() {
        end(); // a failed verification ends the upload
    }
    r
}
fn finish_inner(c: &Ctx, body: &[u8]) -> Result<Finished, &'static str> {
    guards(c, body)?;
    let mut b = [0u8; 192];
    let id = form_get(body, "id", &mut b).and_then(id_of);
    let u = mine(c, id)?;
    if u.phase != Phase::Receiving || u.got != u.size {
        return Err("incomplete");
    }
    let d = dev().ok_or("no artifact store")?;
    let (slo, _) = staging(d).ok_or("no staging region")?;
    if u.plen > 0 {
        for x in u.part[u.plen..].iter_mut() {
            *x = 0;
        }
        if d.write_block(slo + u.got / 512, &u.part).is_err() {
            return Err("staging write failed");
        }
        u.plen = 0;
    }
    let h = core::mem::replace(&mut u.h, boot_abi::sha256::Hasher::new());
    if h.finish() != u.sha {
        return Err("sha256 mismatch");
    }
    #[cfg(feature = "p15-write")]
    if u.os {
        let (svn, floor, running) = boot_facts();
        let plan = crate::otaimg::check(&*d, slo, u.size, floor, running)?;
        u.plan = Some(plan);
        u.phase = Phase::Verified;
        u.gen = plan.svn;
        u.len = plan.len;
        u.digest = plan.hash;
        u.last_ms = c.now_ms;
        return Ok(Finished { gen: plan.svn, active_gen: svn, len: plan.len, digest: plan.hash });
    }
    let mut sig = [0u8; 512];
    let ram = ram_dev();
    let (src, at): (&DevRef, u64) = if ram_staged(u) { (&ram, 0) } else { (&*d, slo) };
    src.read_block(at, &mut sig).map_err(|_| "staging read failed")?;
    let key = artstore::key_for(u.ty).ok_or("no operator key")?;
    let (gen, len) = artstore::verify(src, u.ty, &sig, at + 1, &key).map_err(|e| match e {
        crate::shield::LoadErr::DigestMismatch => "signature digest does not match the file",
        crate::shield::LoadErr::BadSignature => "bad signature (not the operator key, or a different pack type)",
        crate::shield::LoadErr::TooBig => "too big",
        crate::shield::LoadErr::Io => "file shorter than its signature says",
        _ => "malformed signature",
    })?;
    if len + 512 > u.size {
        return Err("file shorter than its signature says");
    }
    if matches!(u.ty, Ty::Policy | Ty::Config) {
        if let Some(e) = artstore::policy_refused() {
            return Err(match e {
                hal::policy::PolicyErr::Unsupported(_) => "refused: the policy has a route forwarding cannot honour (via lan / eth1, or an IPv6 route other than `via wan` without a gateway) — it would be refused at boot",
                hal::policy::PolicyErr::Full(_) => "refused: the policy has more entries than the device holds — it would be refused at boot",
                _ => "refused: the policy does not parse — it would be refused at boot (management lockdown)",
            });
        }
    }
    if u.ty == Ty::Config && !artstore::config_mgmt_ok() {
        return Err("refused: this configuration would leave no management path (HTTPS to the device on LAN / Wi-Fi, eth1 or the management VLAN)");
    }
    let active = artstore::active_gen(&artstore::Plain::new(&*d), p1(d), u.ty);
    if gen < active {
        return Err("rollback refused: generation older than the active pack");
    }
    u.secret = match u.ty {
        Ty::Wan => artstore::wan_has_secret(&stage_ram()[512..512 + len as usize]),
        Ty::Wifi => true,
        Ty::Config => artstore::config_secret(),
        _ => false,
    };
    u.phase = Phase::Verified;
    u.gen = gen;
    u.len = len;
    u.digest = content_digest(u.ty, &sig);
    u.last_ms = c.now_ms;
    Ok(Finished { gen, active_gen: active, len, digest: u.digest })
}

pub struct Activated {
    pub gen: u64,
    pub journal_seq: Option<u64>,
    /// ADR 0058: a staged type (wan / wifi / policy) applies at the next boot, not now.
    pub staged: bool,
    /// Design heqk-sealed-config-live-apply §3.8: how a staged configuration is stored ("sealed" | "plaintext_signed").
    pub at_rest: Option<&'static str>,
    /// Step 8: a configuration bundle applied LIVE (no reboot), on trial now.
    pub live: bool,
    /// Step 11: the live trial waits for the owner's /api/config/confirm (management plane or Wi-Fi changed).
    pub needs_confirm: bool,
}

/// `activate`: id, envelope, seq. Store A/B write + readback + manifest commit + live reload.
pub fn activate(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<Activated, &'static str> {
    let ty = cur_code();
    let r = activate_inner(c, body, auth);
    audit(c, "activate", ty, r.is_ok(), r.as_ref().err().copied().unwrap_or(""), r.as_ref().map_or(0, |a| a.gen));
    r
}
fn activate_inner(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<Activated, &'static str> {
    guards(c, body)?;
    let mut b = [[0u8; 192]; 2];
    let [ref mut b0, ref mut b1] = b;
    let id = form_get(body, "id", b0).and_then(id_of);
    let _ = (b1, auth);
    let u = mine(c, id)?;
    if u.phase != Phase::Verified {
        return Err("not verified (finish first)");
    }
    // R6 = D (operator 2026-11-12): authorised ONLY by an owner-signed HQMGMT1 envelope (UPLOAD_ACTIVATE) bound to the
    // type code, the staged generation and the staged content digest (finish reports both). Not the owner token.
    let mut env = [0u8; hal::mgmtabi::ENV_LEN];
    let given = crate::mgmtenv::from_form(body, &mut env);
    crate::mgmtenv::authorise(hal::mgmtabi::UPLOAD_ACTIVATE, code(Some(u.ty), u.os) as u64, u.gen, &u.digest, if given { &env[..] } else { &[] },
        crate::mcauth::session_tag(c.session), c.now_ms)?;
    activate_by_id(crate::mcauth::session_tag(c.session), c.now_ms, id.unwrap_or(0))
}

/// The type of the caller's VERIFIED upload `id` (None = unknown / not the caller's / not verified).
pub fn verified_type(tag: [u8; 4], id: u64) -> Option<Ty> {
    match up() {
        Some(u) if u.id == id && u.session == tag && u.phase == Phase::Verified && !u.os => Some(u.ty),
        _ => None,
    }
}

/// Activate the caller's VERIFIED upload `id` (ADR 0059 step 4b: one path for Mission Control after its guards +
/// re-authentication, and for the management ABI's CFG_STAGE after the kernel's role check). The upload must belong
/// to the caller's session (`tag`).
pub fn activate_by_id(tag: [u8; 4], now_ms: u64, id: u64) -> Result<Activated, &'static str> {
    rbt_clear();
    let u = match up() {
        Some(u) if u.id == id && u.session == tag => u,
        _ => return Err("unknown upload id"),
    };
    if u.phase != Phase::Verified {
        return Err("not verified (finish first)");
    }
    // metal 2026-11-12: never while a configuration change is in flight — writing the inactive half would overwrite
    // the last-known-good that change reverts to (checked before anything is written). The upload is dropped (the
    // staged bytes wiped) so the next one can begin; the owner re-uploads once the change resolves.
    if u.ty == Ty::Config && crate::cfgd::busy() {
        end();
        return Err("a configuration change is already in progress");
    }
    let d = dev().ok_or("no artifact store")?;
    let (slo, _) = staging(d).ok_or("no staging region")?;
    #[cfg(feature = "p15-write")]
    if u.os {
        let plan = u.plan.ok_or("not verified (finish first)")?;
        end();
        let (svn, _, _) = boot_facts();
        let mut reason = [0u8; 64];
        let rl = {
            use core::fmt::Write;
            let mut w = crate::mcstate::JsonBuf::new(&mut reason);
            let _ = write!(w, "svn {}->{} slot {} sha256:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", svn, plan.svn,
                if plan.active == b'a' { 'b' } else { 'a' }, plan.hash[0], plan.hash[1], plan.hash[2], plan.hash[3], plan.hash[4], plan.hash[5], plan.hash[6], plan.hash[7]);
            w.len
        };
        let tag = tag;
        return match crate::otaimg::install(d, slo, &plan) {
            Ok(()) => {
                unsafe { TRIAL_REBOOT = true };
                Ok(Activated { gen: plan.svn, journal_seq: crate::ownerapi::audit_artifact("os_image", 1, &reason[..rl], tag, now_ms), staged: true, at_rest: None, live: false, needs_confirm: false })
            }
            Err(e) => {
                let _ = crate::ownerapi::audit_artifact("os_image", 2, &reason[..rl], tag, now_ms);
                Err(e)
            }
        };
    }
    let mut sig = [0u8; 512];
    let staged = ram_staged(u);
    if staged {
        sig.copy_from_slice(&stage_ram()[..512]);
    } else {
        d.read_block(slo, &mut sig).map_err(|_| "staging read failed")?;
    }
    let (ty, gen, len, secret) = (u.ty, u.gen, u.len, u.secret);
    let old = artstore::active_gen(&artstore::Plain::new(&*d), p1(d), ty);
    // the content digest inside the signature sector: POLICY.SIG has no length field (digest at 16..48, over the
    // whole 4 KiB file); every other format carries len at 16..24 and the digest at 24..56
    let mut digest: [u8; 32] = content_digest(ty, &sig);
    let mut at_rest = None;
    let res = if !staged {
        artstore::activate(d, ty, &sig, slo + 1, gen, len, &digest)
    } else if artstore::cfg_seal_available() {
        at_rest = Some("sealed");
        // sealed at rest; the audit records the digest of the SEALED image, never the plaintext's (F-a)
        let r = artstore::activate_sealed(d, ty, &stage_ram()[..512 + len as usize], gen, len);
        if let Ok(m) = &r {
            digest = m.e[ty as usize].digest;
        }
        r
    } else if secret && ty == Ty::Config && artstore::config_changes() & !crate::cfgd::LIVE_CAPABLE == 0 {
        // Q3 (operator decision): no device key — a secret-bearing bundle is applied LIVE but RAM-only: verified again
        // by cfgd, never written to the store (no manifest, no floor), a reboot returns to the persisted configuration
        let r = crate::cfgd::queue_live_volatile_device(&stage_ram()[..512 + len as usize]);
        end();
        let g = r?;
        let mut reason = [0u8; 64];
        let rl = {
            use core::fmt::Write;
            let mut w = crate::mcstate::JsonBuf::new(&mut reason);
            let _ = write!(w, "gen {}->{} volatile_ram_only (not persisted)", old, g); // no digest: F-a
            w.len
        };
        let needs_confirm = crate::cfgd::needs_confirm();
        #[cfg(not(feature = "cm5"))]
        unsafe {
            LAST_LIVE = (true, false, needs_confirm);
            LAST_AT_REST = "volatile_ram_only";
        };
        let journal_seq = crate::ownerapi::audit_artifact(ty.info().name, 1, &reason[..rl], tag, now_ms);
        return Ok(Activated { gen: g, journal_seq, staged: false, at_rest: Some("volatile_ram_only"), live: true, needs_confirm });
    } else if secret {
        // Q3: no device key (blank OTP) — a secret is never written in plaintext (and a per-file upload is next-boot)
        end();
        return Err("not stored: no device key — secrets are never written in plaintext");
    } else {
        at_rest = Some("plaintext_signed");
        artstore::activate_from(d, ty, &sig, artstore::Src::Ram(&stage_ram()[512..512 + len as usize]), gen, len, &digest)
    };
    if staged && res.is_ok() {
        artstore::refresh(&*d, None);
    }
    end();
    let mut reason = [0u8; 64];
    let rl = {
        use core::fmt::Write;
        let mut w = crate::mcstate::JsonBuf::new(&mut reason);
        let _ = write!(w, "gen {}->{} sha256:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", old, gen, digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]);
        w.len
    };
    let tag = tag;
    match res {
        Ok(_) => {
            let journal_seq = crate::ownerapi::audit_artifact(ty.info().name, 1, &reason[..rl], tag, now_ms);
            // step 8: a bundle that changes only what this build applies live goes on a LIVE trial now (the AP loop's
            // executors run after this reply); anything else keeps the next-boot trial. Restored 2026-11-12: the merge
            // of #1001 (8142b7bf) had dropped this hand-off, so live apply never ran.
            let live = ty == Ty::Config
                && artstore::config_changes() & !crate::cfgd::LIVE_CAPABLE == 0
                && crate::cfgd::queue_live_device().is_ok();
            let needs_confirm = live && crate::cfgd::needs_confirm();
            #[cfg(not(feature = "cm5"))]
            unsafe {
                LAST_LIVE = (live, ty.staged() && !live, needs_confirm)
            };
            Ok(Activated { gen, journal_seq, staged: ty.staged() && !live, at_rest, live, needs_confirm })
        }
        Err(artstore::ActErr::LoaderRefused) => {
            let _ = crate::ownerapi::audit_artifact(ty.info().name, 2, &reason[..rl], tag, now_ms);
            Err("the loader refused the new pack — rolled back to the previous one")
        }
        Err(artstore::ActErr::NoStore) => Err("no artifact store"),
        Err(_) => Err("store write / readback failed — the previous pack stays active"),
    }
}

/// ADR 0058 `POST /api/upload/rollback`: type, envelope (R6 = D; the owner token no longer authorises it), seq. Re-activates the OTHER half of that type (the
/// previous generation) after verifying it again with the type's own verifier; staged types apply at the next
/// boot. Owner re-authentication; POLICY never goes below its persisted generation floor.
pub fn rollback(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<Activated, &'static str> {
    let r = rollback_inner(c, body, auth);
    let ty = r.as_ref().map_or(0xff, |a| a.1);
    audit(c, "rollback", ty, r.is_ok(), r.as_ref().err().copied().unwrap_or(""), r.as_ref().map_or(0, |a| a.0.gen));
    r.map(|a| a.0)
}
fn rollback_inner(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<(Activated, u8), &'static str> {
    guards(c, body)?;
    let mut b = [[0u8; 192]; 2];
    let [ref mut b0, ref mut b1] = b;
    let ty = form_get(body, "type", b0).and_then(Ty::from_name).ok_or("type")?;
    let _ = (b1, auth);
    if up().is_some() {
        return Err("an upload is in flight (finish or abort it first)");
    }
    // R6 = D (operator 2026-11-12): authorised ONLY by an owner-signed HQMGMT1 envelope (UPLOAD_ROLLBACK) bound to the
    // type code and the generation it rolls back TO. The signature, device, boot and sequence first (nothing touched);
    // the target generation once the store says what the previous half is. Not the owner token.
    let tag = crate::mcauth::session_tag(c.session);
    let mut env = [0u8; hal::mgmtabi::ENV_LEN];
    let given = crate::mgmtenv::from_form(body, &mut env);
    let e = crate::mgmtenv::verify(hal::mgmtabi::UPLOAD_ROLLBACK, ty as u64, if given { &env[..] } else { &[] }).map_err(|why| {
        crate::mgmtenv::journal(hal::mgmtabi::UPLOAD_ROLLBACK, false, 0, why, tag, c.now_ms);
        why
    })?;
    let d = dev().ok_or("no artifact store")?;
    let opk = artstore::key_for(ty).ok_or("no operator key")?;
    let target = artstore::rollback_target(&*d, ty, &opk).ok_or("nothing to roll back to (no verified previous generation)")?;
    if e.generation != target || e.digest != [0; 32] {
        crate::mgmtenv::journal(hal::mgmtabi::UPLOAD_ROLLBACK, false, target, crate::mgmtenv::OTHER_TARGET, tag, c.now_ms);
        return Err(crate::mgmtenv::OTHER_TARGET);
    }
    let old = artstore::active_gen(&artstore::Plain::new(&*d), p1(d), ty);
    rbt_clear();
    let res = artstore::rollback(d, ty, &opk);
    if res.is_ok() && ty.staged() {
        artstore::refresh(&*d, None);
    }
    let mut reason = [0u8; 64];
    let mut rl = 0;
    if let Ok(gen) = res {
        use core::fmt::Write;
        let mut w = crate::mcstate::JsonBuf::new(&mut reason);
        let _ = write!(w, "rollback gen {}->{}", old, gen);
        rl = w.len;
    }
    match res {
        Ok(gen) => Ok((Activated { gen, journal_seq: crate::ownerapi::audit_artifact(ty.info().name, 1, &reason[..rl], tag, c.now_ms), staged: ty.staged(), at_rest: None, live: false, needs_confirm: false }, ty as u8)),
        Err(artstore::ActErr::NothingToRollBack) => Err("nothing to roll back to (no verified previous generation)"),
        Err(artstore::ActErr::LoaderRefused) => Err("the loader refused the previous pack — the current one stays active"),
        Err(artstore::ActErr::NoStore) => Err("no artifact store"),
        Err(_) => Err("store write / readback failed — the current pack stays active"),
    }
}

/// `abort`: id, seq.
pub fn abort(c: &Ctx, body: &[u8]) -> Result<(), &'static str> {
    let ty = cur_code();
    let r = (|| {
        guards(c, body)?;
        let mut b = [0u8; 192];
        let id = form_get(body, "id", &mut b).and_then(id_of);
        mine(c, id)?;
        end();
        Ok(())
    })();
    audit(c, "abort", ty, r.is_ok(), r.err().unwrap_or(""), 0);
    r
}

// "rollback_to" (R6 = D): `artstore::rollback_target` re-verifies (hashes) the whole previous half, so GET caches it
// per type: [half | state << 8 | 1 << 16, active gen, verifier key prefix, target + 1 (0 = none)]. Every activation /
// rollback clears it first. Zero-initialised (.bss, not the payload).
static mut RBT: [[u64; 4]; artstore::NTY] = [[0; 4]; artstore::NTY];
fn rbt_clear() {
    unsafe { RBT = [[0; 4]; artstore::NTY] };
}
/// The generation `POST /api/upload/rollback` would go to for `t` (what its envelope must bind), or None.
fn rollback_to(d: &DevRef, t: Ty) -> Option<u64> {
    let opk = artstore::key_for(t)?;
    let e = artstore::entry(d, t)?;
    let k = [e.half as u64 | (e.state as u64) << 8 | 1 << 16, e.gen, u64::from_le_bytes(opk[..8].try_into().ok()?)];
    let c = unsafe { &mut (*core::ptr::addr_of_mut!(RBT))[t as usize] };
    if c[..3] != k {
        let v = artstore::rollback_target(d, t, &opk);
        *c = [k[0], k[1], k[2], v.map_or(0, |g| g + 1)];
    }
    c[3].checked_sub(1)
}

/// Owner-journal artifact record value → result: 1 done (activation, rollback, accepted envelope), 2 refused.
pub fn result_label(v: u8) -> &'static str {
    match v {
        1 => "ok",
        2 => "refused",
        _ => "unknown",
    }
}

/// `GET /api/upload`: what each type is running (generation + source) and the recent upload trail.
pub fn render(w: &mut crate::mcstate::JsonBuf) {
    use core::fmt::Write;
    let _ = write!(w, "{{\"store\":{},\"chunk_max\":{},\"types\":[", installed(), CHUNK_MAX);
    for (i, t) in artstore::ALL.iter().enumerate() {
        let (g, src, rb) = match dev() {
            Some(d) => {
                let p = p1(d);
                let pv = artstore::Plain::new(&*d);
                (artstore::active_gen(&pv, p, *t), if artstore::from_store(&pv, p, *t) { "store" } else { "boot" }, rollback_to(d, *t))
            }
            None => (0, "boot", None),
        };
        let _ = write!(w, "{}{{\"type\":\"{}\",\"cap\":{},\"generation\":{},\"source\":\"{}\",\"applies\":\"{}\",\"rollback_to\":", if i > 0 { "," } else { "" }, t.info().name, t.info().cap, g, src,
            if t.staged() { "next_boot" } else { "now" });
        match rb {
            Some(r) => {
                let _ = write!(w, "{}}}", r);
            }
            None => w.raw("null}"),
        }
    }
    w.raw("],\"in_flight\":");
    match up() {
        Some(u) => {
            let _ = write!(w, "{{\"id\":\"{:016x}\",\"type\":\"{}\",\"size\":{},\"received\":{},\"verified\":{}", u.id, if u.os { "os_image" } else { u.ty.info().name }, u.size, u.got, u.phase == Phase::Verified);
            // R6 = D (additive): once verified, what the activate envelope binds (type code, generation, digest)
            if u.phase == Phase::Verified {
                let _ = write!(w, ",\"type_code\":{},\"generation\":{},\"digest\":\"", code(Some(u.ty), u.os), u.gen);
                for b in u.digest {
                    let _ = write!(w, "{:02x}", b);
                }
                w.raw("\"");
            }
            w.raw("}");
        }
        None => w.raw("null"),
    }
    w.raw(",\"recent\":[");
    let n = unsafe { EHEAD };
    for (k, i) in (n.saturating_sub(16)..n).rev().enumerate() {
        let e = unsafe { EVS[i % 32] };
        let tn = if e.ty == OS_CODE { "os_image" } else { Ty::from_u8(e.ty).map_or("?", |t| t.info().name) };
        let _ = write!(w, "{}{{\"ms\":{},\"session\":\"{:02x}{:02x}{:02x}{:02x}\",\"step\":\"{}\",\"type\":\"{}\",\"ok\":{},\"generation\":{},\"why\":",
            if k > 0 { "," } else { "" }, e.ms, e.session[0], e.session[1], e.session[2], e.session[3], e.step, tn, e.ok, e.gen);
        w.string(e.why);
        w.raw("}");
    }
    w.raw("],\"activations\":[");
    let mut k = 0;
    crate::ownerjournal::for_each_artifact(&mut |r| {
        let _ = write!(w, "{}{{\"seq\":{},\"ms\":{},\"type\":", if k > 0 { "," } else { "" }, r.seq, r.ms);
        w.string(core::str::from_utf8(r.target()).unwrap_or("?"));
        let _ = write!(w, ",\"result\":\"{}\",\"detail\":", result_label(r.value));
        w.string(core::str::from_utf8(&r.reason[..r.rlen as usize]).unwrap_or(""));
        w.raw("}");
        k += 1;
    });
    w.raw("]}");
}

// ---- [P-upload] ------------------------------------------------------------------------------------------

pub fn selftest() -> bool {
    use crate::mcauth::{session_hex, verifier_for, Auth, Owner};
    let token: &[u8] = b"owner-key-for-the-upload-test";
    let salt = [9u8; 16];
    let mut auth = Auth::new(Some(Owner { salt, verifier: verifier_for(&salt, token) }));
    let sid = match auth.login(token, 5_000, || Some([0x31; 16])) {
        Ok(i) => i,
        Err(e) => {
            arch_aarch64::_print(format_args!(" [P-upload] FAIL — self-test login refused ({:?})\n", e));
            return false;
        }
    };
    let mut hex = [0u8; 32];
    session_hex(&sid, &mut hex);
    let sess = core::str::from_utf8(&hex).unwrap_or("");
    let mut tok = [0u8; 32];
    let _ = crate::mcauth::csrf_token(Some(sess), &mut tok);
    let csrf = core::str::from_utf8(&tok).unwrap_or("");
    let c = Ctx { session: Some(sess), origin: "https://10.99.0.1", host: "10.99.0.1", csrf, now_ms: 5_000 };
    // operator key + store on the sparse test disk; the owner journal in RAM
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x42; 32]));
    crate::policysig::selftest_key(Some(*kp.pk));
    // R6 = D: a TEST owner key K_own signs the activate / rollback envelopes (restored afterwards)
    let kown = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x6b; 32]));
    let saved_owner = (crate::anchor::owner(), crate::anchor::owner_gen());
    crate::anchor::install_owner(Some(*kown.pk), 1);
    crate::mgmtenv::test_reset();
    let disk = artstore::test_disk();
    install(disk);
    crate::ownerapi::install_ram(&[0x31u8; 32]);
    crate::devpolicy::load_text(b"");
    // the container: DEVICES.SIG (512) || DEVICES.TXT
    let body = b"02:00:00:00:00:71 quarantine uploaded-over-https\n";
    let sig = artstore::test_sig(b"HQDSIG1\0", b"HQDEV1", 3, body, &kp);
    let mut cont = [0u8; 512 + 64];
    cont[..512].copy_from_slice(&sig);
    cont[512..512 + body.len()].copy_from_slice(body);
    let cont = &cont[..512 + body.len()];
    let sha = boot_abi::sha256::digest(cont);
    let mut shex = [0u8; 64];
    for (i, b) in sha.iter().enumerate() {
        shex[i * 2] = b"0123456789abcdef"[(b >> 4) as usize];
        shex[i * 2 + 1] = b"0123456789abcdef"[(b & 15) as usize];
    }
    let shex = core::str::from_utf8(&shex).unwrap_or("");
    let k = "owner-key-for-the-upload-test";
    let mut seq = 10u64;
    let mut b = [0u8; 400];
    macro_rules! f {
        ($($a:tt)*) => {{
            use core::fmt::Write;
            let mut w = crate::mcstate::JsonBuf::new(&mut b);
            let _ = write!(w, $($a)*);
            let n = w.len;
            &b[..n]
        }};
    }
    // refusals before anything is staged
    seq += 1;
    // `policy` is not an upload type (next-boot only, ADR 0056 phase 1); an `os_image` must be a whole boot
    // image. Every form step consumes its seq, even when refused (replay guard).
    let bad_type = begin(&c, f!("type=kernel&size=600&sha256={}&owner_key={}&seq={}", shex, k, seq), &mut auth).err() == Some("type");
    seq += 1;
    let small_os = begin(&c, f!("type=os_image&size=600&sha256={}&owner_key={}&seq={}", shex, k, seq), &mut auth).err()
        == Some(if cfg!(feature = "p15-write") { "size" } else { "this image cannot update its OS over the network (read-only build)" });
    let bad_type = bad_type && small_os;
    seq += 1;
    let too_big = begin(&c, f!("type=devices&size=99999999&sha256={}&owner_key={}&seq={}", shex, k, seq), &mut auth).err() == Some("size");
    seq += 1;
    let reauth = begin(&c, f!("type=devices&size={}&sha256={}&owner_key=wrong&seq={}", cont.len(), shex, seq), &mut auth).err() == Some("re-authentication failed");
    // the happy path
    seq += 1;
    let id = begin(&c, f!("type=devices&size={}&sha256={}&owner_key={}&seq={}", cont.len(), shex, k, seq), &mut auth).map(|b| b.id).unwrap_or(0);
    let mut q = [0u8; 64];
    macro_rules! qf {
        ($($a:tt)*) => {{
            use core::fmt::Write;
            let mut w = crate::mcstate::JsonBuf::new(&mut q);
            let _ = write!(w, $($a)*);
            let n = w.len;
            core::str::from_utf8(&q[..n]).unwrap_or("")
        }};
    }
    let out_of_order = chunk(&c, qf!("id={:016x}&off=7", id), &cont[7..100]).is_err();
    let mut off = 0usize;
    let mut chunks_ok = true;
    while off < cont.len() {
        let end = (off + 300).min(cont.len());
        chunks_ok &= chunk(&c, qf!("id={:016x}&off={}", id, off), &cont[off..end]) == Ok(end as u64);
        off = end;
    }
    seq += 1;
    let early = activate(&c, f!("id={:016x}&owner_key={}&seq={}", id, k, seq), &mut auth).err() == Some("not verified (finish first)");
    seq += 1;
    let finr = finish(&c, f!("id={:016x}&seq={}", id, seq)).map(|f| (f.gen, f.active_gen, f.len, f.digest));
    let fin = finr.is_ok_and(|f| f.0 == 3 && f.1 == 0 && f.2 == body.len() as u64 && f.3 == boot_abi::sha256::digest(body));
    let staged_only = crate::devpolicy::policy_of(&[2, 0, 0, 0, 0, 0x71]) == crate::devpolicy::Pol::Full;
    let dg = finr.map_or([0; 32], |f| f.3);
    let mut eh = [0u8; 2 * hal::mgmtabi::ENV_LEN];
    // R6 = D: the owner token alone no longer activates; an envelope for another generation is refused; the owner's
    // envelope bound to (devices, 3, digest) activates
    seq += 1;
    let token_only = activate(&c, f!("id={:016x}&owner_key={}&seq={}", id, k, seq), &mut auth).err() == Some(crate::mgmtenv::REASONS[0]);
    crate::mgmtenv::test_sign_hex(&kown, hal::mgmtabi::UPLOAD_ACTIVATE, Ty::Devices as u64, 4, dg, &mut eh);
    seq += 1;
    let other_gen = activate(&c, f!("id={:016x}&envelope={}&seq={}", id, core::str::from_utf8(&eh).unwrap_or(""), seq), &mut auth).err() == Some(crate::mgmtenv::OTHER_TARGET);
    crate::mgmtenv::test_sign_hex(&kown, hal::mgmtabi::UPLOAD_ACTIVATE, Ty::Devices as u64, 3, dg, &mut eh);
    seq += 1;
    let act = token_only && other_gen
        && activate(&c, f!("id={:016x}&envelope={}&seq={}", id, core::str::from_utf8(&eh).unwrap_or(""), seq), &mut auth).is_ok_and(|a| a.gen == 3)
        && crate::devpolicy::policy_of(&[2, 0, 0, 0, 0, 0x71]) == crate::devpolicy::Pol::Quarantine;
    let mut audited = false;
    crate::ownerjournal::for_each_artifact(&mut |r| audited |= r.target() == b"devices" && r.value == 1);
    // anti-rollback: an older generation verifies but is refused at finish
    let old = artstore::test_sig(b"HQDSIG1\0", b"HQDEV1", 2, body, &kp);
    let mut cont2 = [0u8; 512 + 64];
    cont2[..512].copy_from_slice(&old);
    cont2[512..512 + body.len()].copy_from_slice(body);
    let rollback = run_one(&c, &mut auth, &cont2[..512 + body.len()], "devices", &mut seq, false) == Err("rollback refused: generation older than the active pack");
    // a pack signed as DEVICES declared as an IOC pack: the IOC verifier refuses it
    let cross = run_one(&c, &mut auth, cont, "ioc", &mut seq, false).map_or_else(|e| e.starts_with("malformed") || e.starts_with("bad signature"), |_| false);
    // tampered byte after signing: the module's own verifier refuses (digest)
    let mut cont3 = [0u8; 512 + 64];
    cont3[..512 + body.len()].copy_from_slice(cont);
    cont3[520] ^= 1;
    let tampered = run_one(&c, &mut auth, &cont3[..512 + body.len()], "devices", &mut seq, false).is_err();
    // foreign Origin
    let foreign = begin(&Ctx { origin: "https://evil.example", ..Ctx { ..c } }, b"type=devices&size=600&seq=999", &mut auth).err() == Some("origin");
    // R6 = D review: GET "rollback_to" is what the rollback handler accepts; a refused activation reads "refused"
    let rb_none = dev().is_some_and(|d| rollback_to(d, Ty::Devices).is_none()); // only gen 3 stored so far
    let new4 = artstore::test_sig(b"HQDSIG1\0", b"HQDEV1", 4, body, &kp);
    cont2[..512].copy_from_slice(&new4);
    let act4 = run_one(&c, &mut auth, &cont2[..512 + body.len()], "devices", &mut seq, true) == Ok(4);
    let to = dev().and_then(|d| rollback_to(d, Ty::Devices));
    let mut rb = |gen: u64, seq: u64| {
        crate::mgmtenv::test_sign_hex(&kown, hal::mgmtabi::UPLOAD_ROLLBACK, Ty::Devices as u64, gen, [0; 32], &mut eh);
        self::rollback(&c, f!("type=devices&envelope={}&seq={}", core::str::from_utf8(&eh).unwrap_or(""), seq), &mut auth).map(|a| a.gen)
    };
    seq += 1;
    let rb_wrong = rb(4, seq) == Err(crate::mgmtenv::OTHER_TARGET);
    seq += 1;
    let rb_ok = to == Some(3) && rb(3, seq) == Ok(3);
    let mut jb = [0u8; 4096];
    let js = {
        unsafe { EHEAD = 0 };
        let mut w = crate::mcstate::JsonBuf::new(&mut jb);
        render(&mut w);
        let n = if w.overflow { 0 } else { w.len };
        &jb[..n]
    };
    let has = |x: &[u8]| js.windows(x.len()).any(|w| w == x);
    // after the rollback the gen-4 half is the previous one (the cache was cleared); no other type has one
    let rb_json = has(b"\"generation\":3,\"source\":\"store\",\"applies\":\"now\",\"rollback_to\":4}") && has(b"\"type\":\"ioc\",\"cap\":16777216,\"generation\":0,\"source\":\"boot\",\"applies\":\"now\",\"rollback_to\":null}");
    let labels = has(b"\"result\":\"refused\",\"detail\":\"activate gen 3") && has(b"\"result\":\"ok\",\"detail\":\"rollback gen 4->3\"") && !has(b"rolled back");
    let rbt = rb_none && act4 && rb_wrong && rb_ok && rb_json && labels;
    // design heqk-sealed-config-live-apply step 3: a configuration upload is staged in RAM only and sealed at rest
    let cfg = cfg_selftest(&c, &mut auth, &kp, &mut seq);
    // clean up: nothing of the test survives into the running image
    artstore::clear_cfg_seal();
    end();
    unsafe {
        DEV = None;
        UP = None;
        EHEAD = 0;
    }
    crate::policysig::selftest_key(None);
    crate::devpolicy::load_text(b"");
    crate::ownerjournal::clear();
    crate::anchor::install_owner(saved_owner.0, saved_owner.1);
    crate::mgmtenv::test_reset();
    let pass = bad_type && too_big && reauth && out_of_order && chunks_ok && early && fin && staged_only && act && audited && rollback && cross && tampered && foreign && rbt && cfg.iter().all(|&x| x);
    arch_aarch64::_print(format_args!(
        " [P-upload] {} — ADR 0056 signed data-pack upload (begin/chunk/finish/activate over the owner session): unknown type / oversize / wrong owner key refused={} out-of-order chunk refused={} chunks staged={} activate before finish refused={} finish = sha256 + the module's own verifier (gen 3)={} nothing applied until activate={} activate (R6 = D: owner token alone refused, envelope for another generation refused, the owner's envelope activates): store A/B + live reload (device quarantined)={} durable journal audit record={} older generation refused (anti-rollback)={} cross-type pack refused={} tampered byte refused={} foreign Origin refused={} rollback_to = what rollback accepts, refused labelled refused={:?} config upload: staging sectors unchanged + no secret on disk={} sealed at rest, audit = ciphertext digest={} no device key: secret refused for persistence={} no device key: non-secret stored signed={} a config bundle is handed to the live engine (policy-only: applies live, no reboot, auto-commit; management binding: live + owner confirm)={} no device key: a secret-bearing bundle applies live RAM-only (at_rest volatile_ram_only, nothing on disk, manifest untouched)={}\n",
        if pass { "PASS" } else { "FAIL" }, bad_type && too_big && reauth, out_of_order, chunks_ok, early, fin, staged_only, act, audited, rollback, cross, tampered, foreign,
        [rb_none, act4, rb_wrong, rb_ok, rb_json, labels],
        cfg[0], cfg[1], cfg[2], cfg[3], cfg[4], cfg[5]
    ));
    pass
}

/// [P-upload] step 3: WAN uploads (the container in RAM, never the disk Staging region; sealed when there is a device
/// key; Q3 without one). Returns [staging untouched + no secret on disk, sealed + ciphertext audit digest, no key:
/// secret refused, no key: non-secret stored].
/// (live, staged, needs_confirm) of the last successful activation — read by the upload self-test.
#[cfg(not(feature = "cm5"))]
static mut LAST_LIVE: (bool, bool, bool) = (false, false, false);
/// The `at_rest` of the last RAM-only (Q3) activation — read by the upload self-test.
#[cfg(not(feature = "cm5"))]
static mut LAST_AT_REST: &str = "";

/// A signed HQCFG1 bundle container (HQCSIG1 sector + bundle) with one POLICY section, for the upload self-test.
#[cfg(not(feature = "cm5"))]
fn test_cfg_container(kp: &ed25519_compact::KeyPair, gen: u64, kind: u8, pol: &[u8], out: &mut [u8; 1024]) -> usize {
    use crate::cfgbundle as cb;
    let key: [u8; 32] = *kp.pk;
    let mut b = [0u8; 512];
    b[..8].copy_from_slice(cb::MAGIC);
    b[8..10].copy_from_slice(&0x0100u16.to_le_bytes());
    b[12..20].copy_from_slice(&gen.to_le_bytes());
    b[36..44].copy_from_slice(&cb::key_id(&key));
    b[44] = 1;
    b[48] = kind;
    b[50..52].copy_from_slice(&(pol.len() as u16).to_le_bytes());
    b[52..52 + pol.len()].copy_from_slice(pol);
    let n = 52 + pol.len();
    let dg = boot_abi::sha256::digest(&b[..n]);
    let mut m = [0u8; 42];
    m[..10].copy_from_slice(cb::SIG_TAG);
    m[10..].copy_from_slice(&dg);
    let sg = kp.sk.sign(&m[..], Some(ed25519_compact::Noise::from_slice(&[5u8; 16]).unwrap()));
    *out = [0u8; 1024];
    out[..8].copy_from_slice(cb::SIG_MAGIC);
    out[8] = 1;
    out[9..13].copy_from_slice(&(n as u32).to_le_bytes());
    out[13..45].copy_from_slice(&dg);
    out[45..109].copy_from_slice(&sg[..]);
    out[512..512 + n].copy_from_slice(&b[..n]);
    512 + n
}

fn cfg_selftest(c: &Ctx, auth: &mut crate::mcauth::Auth, kp: &ed25519_compact::KeyPair, seq: &mut u64) -> [bool; 7] {
    let disk = || unsafe { &*core::ptr::addr_of!(artstore::TEST_DISK) };
    let (slo, shi) = dev().and_then(|d| staging(d)).unwrap_or((0, 0));
    let stage_hash = || {
        let d = disk();
        let mut h = boot_abi::sha256::Hasher::new();
        for i in 0..d.n {
            if (slo..shi).contains(&d.lba[i]) {
                h.update(&d.lba[i].to_le_bytes());
                h.update(&d.data[i]);
            }
        }
        h.finish()
    };
    let wan = |gen: u64, body: &[u8], seq: &mut u64, auth: &mut crate::mcauth::Auth| {
        let mut cont = [0u8; 1024];
        cont[..512].copy_from_slice(&artstore::test_sig(b"HQNSIG1\0", b"HQWAN1", gen, body, kp));
        cont[512..512 + body.len()].copy_from_slice(body);
        run_one(c, auth, &cont[..512 + body.len()], "wan", seq, true)
    };
    let entry = || dev().and_then(|d| artstore::entry(&*d, Ty::Wan)).unwrap_or(artstore::E0);
    artstore::set_cfg_seal(Some([0x5c; 32]), 0x77);
    let before = stage_hash();
    let body = b"mode=pppoe\npppoe_user=up\npppoe_pass=s3cret\n";
    let r = wan(5, body, seq, auth);
    let e = entry();
    let staging = r == Ok(5) && stage_hash() == before && !artstore::on_disk(disk(), b"s3cret") && !artstore::on_disk(disk(), b"pppoe_user=up");
    // the journal's activation record names the SEALED image's digest, not the plaintext's
    let hex8 = |d: &[u8; 32], out: &mut [u8; 23]| {
        out[..7].copy_from_slice(b"sha256:");
        for i in 0..8 {
            out[7 + 2 * i] = b"0123456789abcdef"[(d[i] >> 4) as usize];
            out[8 + 2 * i] = b"0123456789abcdef"[(d[i] & 15) as usize];
        }
    };
    let (mut want, mut plain) = ([0u8; 23], [0u8; 23]);
    hex8(&e.digest, &mut want);
    hex8(&boot_abi::sha256::digest(body), &mut plain);
    let mut last: Option<([u8; 64], usize)> = None;
    crate::ownerjournal::for_each_artifact(&mut |rec| {
        if rec.target() == b"wan" && rec.value == 1 {
            let mut b = [0u8; 64];
            let n = (rec.rlen as usize).min(64);
            b[..n].copy_from_slice(&rec.reason[..n]);
            last = Some((b, n));
        }
    });
    let has = |r: &[u8], n: &[u8]| r.windows(n.len()).any(|w| w == n);
    let sealed = e.sealed == 1 && e.gen == 5 && last.is_some_and(|(b, n)| has(&b[..n], &want) && !has(&b[..n], &plain));
    // Q3: no device key — a PPPoE password is not persisted; a WAN without a secret keeps the signed plaintext path
    artstore::set_cfg_seal(None, 0);
    let refused = wan(6, b"mode=pppoe\npppoe_user=x\npppoe_pass=other\n", seq, auth) == Err("not stored: no device key — secrets are never written in plaintext")
        && entry().gen == 5 && !artstore::on_disk(disk(), b"other");
    let stored = wan(7, b"mode=dhcp\n", seq, auth) == Ok(7) && entry().gen == 7 && entry().sealed == 0 && stage_hash() == before;
    // LAST (a bundle in the store makes the per-file WAN uploads above refuse) — steps 8 + 11 (restored after the #1001 merge dropped it): a policy-only bundle activates LIVE (not staged for
    // the next boot) and auto-commits; one with a management binding is live too but waits for the owner's confirm
    #[cfg(not(feature = "cm5"))]
    let handoff = {
        let mut cont = [0u8; 1024];
        crate::cfgd::set_test_live(true);
        let n = test_cfg_container(kp, 40, crate::cfgbundle::KIND_POLICY, b"acl A seq 10 allow any any any\ninterface lan acl in A\n", &mut cont);
        let live = run_one(c, auth, &cont[..n], "config", seq, true) == Ok(40) && unsafe { LAST_LIVE } == (true, false, false);
        crate::cfgd::set_test_live(false);
        crate::cfgd::set_test_live(true);
        let n = test_cfg_container(kp, 41, crate::cfgbundle::KIND_POLICY, b"acl M seq 10 allow any any any\ninterface mgmt acl in M\n", &mut cont);
        let confirm = run_one(c, auth, &cont[..n], "config", seq, true) == Ok(41) && unsafe { LAST_LIVE } == (true, false, true);
        crate::cfgd::set_test_live(false);
        live && confirm
    };
    #[cfg(feature = "cm5")]
    let handoff = true; // the hand-off is exercised on QEMU (the self-test disk); metal proves it with cm5-cfgd-live-check
    // Q3 (live-apply follow-up), still no device key: a secret-bearing BUNDLE is applied live, RAM-only — the reply says
    // volatile_ram_only, the secret and the bundle never reach the disk, the manifest entry is untouched
    #[cfg(not(feature = "cm5"))]
    let volatile = {
        let mut cont = [0u8; 1024];
        crate::cfgd::set_test_live(true);
        let e0 = dev().and_then(|d| artstore::entry(&*d, Ty::Config));
        let n = test_cfg_container(kp, 50, crate::cfgbundle::KIND_WAN, b"mode=pppoe\npppoe_user=v@isp\npppoe_pass=v0latile\n", &mut cont);
        let r = run_one(c, auth, &cont[..n], "config", seq, true) == Ok(50) && unsafe { LAST_LIVE } == (true, false, false)
            && unsafe { LAST_AT_REST } == "volatile_ram_only" && crate::cfgd::volatile() && crate::cfgd::generation() == 50
            && dev().and_then(|d| artstore::entry(&*d, Ty::Config)) == e0 && !artstore::on_disk(disk(), b"v0latile")
            && !artstore::on_disk(disk(), b"pppoe_user=v@isp") && stage_hash() == before;
        crate::cfgd::set_test_live(false);
        r && !crate::cfgd::volatile()
    };
    #[cfg(feature = "cm5")]
    let volatile = true;
    // metal 2026-11-12 (cm5-cfgd-live-check C2 -> E1) through the REAL upload path, sealed at rest: a bundle uploaded
    // while another is on trial must be REFUSED before anything is written — it used to overwrite the last-known-good
    // half and become the manifest entry, so the trial's revert then took the FAILED trial bundle for the last-known-good
    // (and a reboot committed it). gen 60 auto-commits; gen 61 (management lines) is on trial, gen 62 arrives -> refused;
    // confirmed: gen 63 (dead gateway) on trial, gen 64 arrives -> refused; the window reverts LIVE to 61, a reboot keeps
    // 61. Unconfirmed: gen 61's window reverts to 60. The metal path: every bench WAN bundle carries vlan= / mgmt_ lines,
    // so it is a NEEDS-CONFIRM trial (cfgd::touches_mgmt, 300 s window); the dead-gateway gen fails health there.
    #[cfg(not(feature = "cm5"))]
    let lkg = {
        use crate::cfgd::{self as cd, Boot, Tick};
        let t = || unsafe { &mut *core::ptr::addr_of_mut!(artstore::TEST_DISK) };
        let mut cont = [0u8; 1024];
        artstore::set_cfg_seal(Some([0x5c; 32]), 0x77);
        let key = crate::policysig::config_key();
        let e = || artstore::entry(&*t(), Ty::Config).unwrap_or(artstore::E0);
        let w_ok = &b"mode=static\nip=10.100.0.200/24\ngw=10.100.0.1\nvlan=100\nmgmt_vlan=200\nmgmt=dhcp\n"[..];
        let w_dead = &b"mode=static\nip=10.100.0.200/24\ngw=10.100.0.254\nvlan=100\nmgmt_vlan=200\nmgmt=dhcp\n"[..];
        let w_dhcp = &b"mode=dhcp\nvlan=100\nmgmt_vlan=200\nmgmt=dhcp\n"[..];
        let mut up = |g: u64, kind: u8, body: &[u8], seq: &mut u64, auth: &mut crate::mcauth::Auth| {
            let n = test_cfg_container(kp, g, kind, body, &mut cont);
            run_one(c, auth, &cont[..n], "config", seq, true)
        };
        let mut r = [false; 2];
        for (i, confirm) in [true, false].into_iter().enumerate() {
            cd::set_test_live(true);
            let b = 60 + 10 * i as u64;
            let ts = 10_000 * i as u64;
            let g0 = up(b, crate::cfgbundle::KIND_POLICY, b"acl A seq 10 allow any any any\n", seq, auth) == Ok(b) && cd::take_apply().is_some()
                && cd::applied(t(), true, ts + 1) == Tick::Idle && cd::tick(t(), ts + 2, true) == Tick::Committed(b);
            let g1 = up(b + 1, crate::cfgbundle::KIND_WAN, w_ok, seq, auth) == Ok(b + 1) && cd::take_apply().is_some()
                && cd::applied(t(), true, ts + 10) == Tick::Idle && cd::tick(t(), ts + 11, true) == Tick::Idle;
            // a new bundle while gen b+1 is on trial: refused, the store untouched
            let e1 = e();
            let busy1 = up(b + 2, crate::cfgbundle::KIND_WAN, w_dhcp, seq, auth).is_err() && e() == e1 && cd::on_trial() && cd::generation() == b + 1;
            let (lkg, flow) = if confirm {
                let c1 = cd::commit(t()) == Ok(b + 1);
                let g3 = up(b + 3, crate::cfgbundle::KIND_WAN, w_dead, seq, auth) == Ok(b + 3) && cd::take_apply().is_some()
                    && cd::applied(t(), true, ts + 20) == Tick::Idle && cd::tick(t(), ts + 21, false) == Tick::Idle;
                let e3 = e();
                let busy3 = up(b + 4, crate::cfgbundle::KIND_WAN, w_dhcp, seq, auth).is_err() && e() == e3;
                (b + 1, c1 && g3 && busy3 && cd::tick(t(), ts + 22 + cd::WINDOW_S, false) == Tick::Reverting)
            } else {
                (b, cd::tick(t(), ts + 22 + cd::WINDOW_S, true) == Tick::Reverting)
            };
            let rv = cd::take_apply().map_or(0, |p| p.generation);
            let back = cd::applied(t(), true, ts + 23 + cd::WINDOW_S);
            let ent = e();
            let boot = cd::boot(t(), key, crate::anchor::cfg_gens().cfg_floor, ts + 5000);
            r[i] = g0 && g1 && busy1 && flow && rv == lkg && back == Tick::Reverted(lkg) && ent.gen == lkg && ent.state == artstore::STATE_ACTIVE
                && boot == Boot::Committed(lkg);
            if !r[i] {
                arch_aarch64::_print(format_args!(" [P-upload] lkg confirm={}: base={} trial={} upload-during-trial refused={} flow={} live revert -> gen {} ({:?}) entry gen {} boot {:?} (want {})\n",
                    confirm, g0, g1, busy1, flow, rv, back, ent.gen, boot, lkg));
            }
            cd::set_test_live(false);
        }
        artstore::set_cfg_seal(None, 0);
        r[0] && r[1]
    };
    #[cfg(feature = "cm5")]
    let lkg = true;
    [staging, sealed, refused, stored, handoff, volatile, lkg]
}

/// Test helper: begin + chunks + finish (+ activate when `act`) for one container. Ok(gen) or the refusal.
fn run_one(c: &Ctx, auth: &mut crate::mcauth::Auth, cont: &[u8], ty: &str, seq: &mut u64, act: bool) -> Result<u64, &'static str> {
    use core::fmt::Write;
    let sha = boot_abi::sha256::digest(cont);
    let mut fb = [0u8; 300];
    let n = {
        let mut w = crate::mcstate::JsonBuf::new(&mut fb);
        *seq += 1;
        let _ = write!(w, "type={}&size={}&sha256=", ty, cont.len());
        for b in sha {
            let _ = write!(w, "{:02x}", b);
        }
        let _ = write!(w, "&owner_key=owner-key-for-the-upload-test&seq={}", *seq);
        w.len
    };
    let id = begin(c, &fb[..n], auth)?.id;
    let mut off = 0;
    while off < cont.len() {
        let end = (off + 512).min(cont.len());
        let mut q = [0u8; 64];
        let ql = {
            let mut w = crate::mcstate::JsonBuf::new(&mut q);
            let _ = write!(w, "id={:016x}&off={}", id, off);
            w.len
        };
        chunk(c, core::str::from_utf8(&q[..ql]).unwrap_or(""), &cont[off..end])?;
        off = end;
    }
    let n = {
        let mut w = crate::mcstate::JsonBuf::new(&mut fb);
        *seq += 1;
        let _ = write!(w, "id={:016x}&seq={}", id, *seq);
        w.len
    };
    let r = finish(c, &fb[..n]).map(|f| (f.gen, f.digest));
    if r.is_err() || !act {
        end();
        return r.map(|f| f.0);
    }
    let (gen, dg) = r.unwrap_or((0, [0; 32]));
    // R6 = D: the activate envelope, signed with the self-test's K_own (installed by `selftest`)
    let kown = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x6b; 32]));
    let mut eh = [0u8; 2 * hal::mgmtabi::ENV_LEN];
    let tc = Ty::from_name(ty).map_or(0xff, |t| t as u64);
    crate::mgmtenv::test_sign_hex(&kown, hal::mgmtabi::UPLOAD_ACTIVATE, tc, gen, dg, &mut eh);
    let mut ab = [0u8; 400];
    let n = {
        let mut w = crate::mcstate::JsonBuf::new(&mut ab);
        *seq += 1;
        let _ = write!(w, "id={:016x}&envelope={}&seq={}", id, core::str::from_utf8(&eh).unwrap_or(""), *seq);
        w.len
    };
    activate(c, &ab[..n], auth).map(|a| a.gen)
}
