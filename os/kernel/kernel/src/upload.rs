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

pub const CHUNK_MAX: usize = 2048;
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

fn expire(now_ms: u64) {
    if let Some(u) = up() {
        if now_ms.saturating_sub(u.last_ms) > IDLE_MS {
            *up() = None;
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
    if crate::policysig::key().is_none() {
        return Err("no operator key in this image: unsigned packs are never accepted over the network");
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
    *up() = Some(Up { id, session: tag, ty, size, sha, got: 0, h: boot_abi::sha256::Hasher::new(), part: [0; 512], plen: 0, last_ms: c.now_ms, phase: Phase::Receiving, gen: 0, len: 0, os, #[cfg(feature = "p15-write")] plan: None });
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
    for &byte in body {
        u.part[u.plen] = byte;
        u.plen += 1;
        if u.plen == 512 {
            let lba = slo + u.got / 512;
            if d.write_block(lba, &u.part).is_err() {
                *up() = None;
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
}

/// `finish`: id, seq. Digest, then the module's own verifier, then anti-rollback (gen ≥ active).
pub fn finish(c: &Ctx, body: &[u8]) -> Result<Finished, &'static str> {
    let ty = cur_code();
    let r = finish_inner(c, body);
    audit(c, "finish", ty, r.is_ok(), r.as_ref().err().copied().unwrap_or(""), r.as_ref().map_or(0, |f| f.gen));
    if r.is_err() {
        *up() = None; // a failed verification ends the upload
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
        u.last_ms = c.now_ms;
        return Ok(Finished { gen: plan.svn, active_gen: svn, len: plan.len });
    }
    let mut sig = [0u8; 512];
    d.read_block(slo, &mut sig).map_err(|_| "staging read failed")?;
    let key = crate::policysig::key().ok_or("no operator key")?;
    let (gen, len) = artstore::verify(&*d, u.ty, &sig, slo + 1, &key).map_err(|e| match e {
        crate::shield::LoadErr::DigestMismatch => "signature digest does not match the file",
        crate::shield::LoadErr::BadSignature => "bad signature (not the operator key, or a different pack type)",
        crate::shield::LoadErr::TooBig => "too big",
        crate::shield::LoadErr::Io => "file shorter than its signature says",
        _ => "malformed signature",
    })?;
    if len + 512 > u.size {
        return Err("file shorter than its signature says");
    }
    let active = artstore::active_gen(&*d, p1(d), u.ty);
    if gen < active {
        return Err("rollback refused: generation older than the active pack");
    }
    u.phase = Phase::Verified;
    u.gen = gen;
    u.len = len;
    u.last_ms = c.now_ms;
    Ok(Finished { gen, active_gen: active, len })
}

pub struct Activated {
    pub gen: u64,
    pub journal_seq: Option<u64>,
}

/// `activate`: id, owner_key, seq. Store A/B write + readback + manifest commit + live reload.
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
    let key = form_get(body, "owner_key", b1).unwrap_or("");
    let u = mine(c, id)?;
    if u.phase != Phase::Verified {
        return Err("not verified (finish first)");
    }
    if !auth.reauth(key.trim().as_bytes(), c.now_ms) {
        return Err("re-authentication failed");
    }
    let d = dev().ok_or("no artifact store")?;
    let (slo, _) = staging(d).ok_or("no staging region")?;
    #[cfg(feature = "p15-write")]
    if u.os {
        let plan = u.plan.ok_or("not verified (finish first)")?;
        *up() = None;
        let (svn, _, _) = boot_facts();
        let mut reason = [0u8; 64];
        let rl = {
            use core::fmt::Write;
            let mut w = crate::mcstate::JsonBuf::new(&mut reason);
            let _ = write!(w, "svn {}->{} slot {} sha256:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", svn, plan.svn,
                if plan.active == b'a' { 'b' } else { 'a' }, plan.hash[0], plan.hash[1], plan.hash[2], plan.hash[3], plan.hash[4], plan.hash[5], plan.hash[6], plan.hash[7]);
            w.len
        };
        let tag = crate::mcauth::session_tag(c.session);
        return match crate::otaimg::install(d, slo, &plan) {
            Ok(()) => {
                unsafe { TRIAL_REBOOT = true };
                Ok(Activated { gen: plan.svn, journal_seq: crate::ownerapi::audit_artifact("os_image", 1, &reason[..rl], tag, c.now_ms) })
            }
            Err(e) => {
                let _ = crate::ownerapi::audit_artifact("os_image", 2, &reason[..rl], tag, c.now_ms);
                Err(e)
            }
        };
    }
    let mut sig = [0u8; 512];
    d.read_block(slo, &mut sig).map_err(|_| "staging read failed")?;
    let (ty, gen, len) = (u.ty, u.gen, u.len);
    let old = artstore::active_gen(&*d, p1(d), ty);
    let digest: [u8; 32] = sig[24..56].try_into().unwrap();
    let res = artstore::activate(d, ty, &sig, slo + 1, gen, len, &digest);
    *up() = None;
    let mut reason = [0u8; 64];
    let rl = {
        use core::fmt::Write;
        let mut w = crate::mcstate::JsonBuf::new(&mut reason);
        let _ = write!(w, "gen {}->{} sha256:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", old, gen, digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]);
        w.len
    };
    let tag = crate::mcauth::session_tag(c.session);
    match res {
        Ok(_) => Ok(Activated { gen, journal_seq: crate::ownerapi::audit_artifact(ty.info().name, 1, &reason[..rl], tag, c.now_ms) }),
        Err(artstore::ActErr::LoaderRefused) => {
            let _ = crate::ownerapi::audit_artifact(ty.info().name, 2, &reason[..rl], tag, c.now_ms);
            Err("the loader refused the new pack — rolled back to the previous one")
        }
        Err(artstore::ActErr::NoStore) => Err("no artifact store"),
        Err(_) => Err("store write / readback failed — the previous pack stays active"),
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
        *up() = None;
        Ok(())
    })();
    audit(c, "abort", ty, r.is_ok(), r.err().unwrap_or(""), 0);
    r
}

/// `GET /api/upload`: what each type is running (generation + source) and the recent upload trail.
pub fn render(w: &mut crate::mcstate::JsonBuf) {
    use core::fmt::Write;
    let _ = write!(w, "{{\"store\":{},\"chunk_max\":{},\"types\":[", installed(), CHUNK_MAX);
    for (i, t) in artstore::ALL.iter().enumerate() {
        let (g, src) = match dev() {
            Some(d) => {
                let p = p1(d);
                (artstore::active_gen(&*d, p, *t), if artstore::from_store(&*d, p, *t) { "store" } else { "boot" })
            }
            None => (0, "boot"),
        };
        let _ = write!(w, "{}{{\"type\":\"{}\",\"cap\":{},\"generation\":{},\"source\":\"{}\"}}", if i > 0 { "," } else { "" }, t.info().name, t.info().cap, g, src);
    }
    w.raw("],\"in_flight\":");
    match up() {
        Some(u) => {
            let _ = write!(w, "{{\"id\":\"{:016x}\",\"type\":\"{}\",\"size\":{},\"received\":{},\"verified\":{}}}", u.id, if u.os { "os_image" } else { u.ty.info().name }, u.size, u.got, u.phase == Phase::Verified);
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
        let _ = write!(w, ",\"result\":\"{}\",\"detail\":", if r.value == 1 { "activated" } else { "rolled back" });
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
    let bad_type = begin(&c, f!("type=policy&size=600&sha256={}&owner_key={}&seq={}", shex, k, seq), &mut auth).err() == Some("type");
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
    let fin = finish(&c, f!("id={:016x}&seq={}", id, seq)).is_ok_and(|f| f.gen == 3 && f.active_gen == 0 && f.len == body.len() as u64);
    let staged_only = crate::devpolicy::policy_of(&[2, 0, 0, 0, 0, 0x71]) == crate::devpolicy::Pol::Full;
    seq += 1;
    let act = activate(&c, f!("id={:016x}&owner_key={}&seq={}", id, k, seq), &mut auth).is_ok_and(|a| a.gen == 3) && crate::devpolicy::policy_of(&[2, 0, 0, 0, 0, 0x71]) == crate::devpolicy::Pol::Quarantine;
    let mut audited = false;
    crate::ownerjournal::for_each_artifact(&mut |r| audited |= r.target() == b"devices" && r.value == 1);
    // anti-rollback: an older generation verifies but is refused at finish
    let old = artstore::test_sig(b"HQDSIG1\0", b"HQDEV1", 2, body, &kp);
    let mut cont2 = [0u8; 512 + 64];
    cont2[..512].copy_from_slice(&old);
    cont2[512..512 + body.len()].copy_from_slice(body);
    let rollback = run_one(&c, &mut auth, &cont2[..512 + body.len()], "devices", &mut seq) == Err("rollback refused: generation older than the active pack");
    // a pack signed as DEVICES declared as an IOC pack: the IOC verifier refuses it
    let cross = run_one(&c, &mut auth, cont, "ioc", &mut seq).map_or_else(|e| e.starts_with("malformed") || e.starts_with("bad signature"), |_| false);
    // tampered byte after signing: the module's own verifier refuses (digest)
    let mut cont3 = [0u8; 512 + 64];
    cont3[..512 + body.len()].copy_from_slice(cont);
    cont3[520] ^= 1;
    let tampered = run_one(&c, &mut auth, &cont3[..512 + body.len()], "devices", &mut seq).is_err();
    // foreign Origin
    let foreign = begin(&Ctx { origin: "https://evil.example", ..Ctx { ..c } }, b"type=devices&size=600&seq=999", &mut auth).err() == Some("origin");
    // clean up: nothing of the test survives into the running image
    unsafe {
        DEV = None;
        UP = None;
        EHEAD = 0;
    }
    crate::policysig::selftest_key(None);
    crate::devpolicy::load_text(b"");
    crate::ownerjournal::clear();
    let pass = bad_type && too_big && reauth && out_of_order && chunks_ok && early && fin && staged_only && act && audited && rollback && cross && tampered && foreign;
    arch_aarch64::_print(format_args!(
        " [P-upload] {} — ADR 0056 signed data-pack upload (begin/chunk/finish/activate over the owner session): unknown type / oversize / wrong owner key refused={} out-of-order chunk refused={} chunks staged={} activate before finish refused={} finish = sha256 + the module's own verifier (gen 3)={} nothing applied until activate={} activate: store A/B + live reload (device quarantined)={} durable journal audit record={} older generation refused (anti-rollback)={} cross-type pack refused={} tampered byte refused={} foreign Origin refused={}\n",
        if pass { "PASS" } else { "FAIL" }, bad_type && too_big && reauth, out_of_order, chunks_ok, early, fin, staged_only, act, audited, rollback, cross, tampered, foreign
    ));
    pass
}

/// Test helper: begin + chunks + finish (no activate) for one container. Ok(gen) or the refusal.
fn run_one(c: &Ctx, auth: &mut crate::mcauth::Auth, cont: &[u8], ty: &str, seq: &mut u64) -> Result<u64, &'static str> {
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
    let r = finish(c, &fb[..n]).map(|f| f.gen);
    *up() = None;
    r
}
