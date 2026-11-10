//! ADR 0055 stage B — the owner-rules API over the journal (`ownerjournal.rs`).
//!
//! `POST /api/owner-rules` (form body): `op=set|remove`, `kind=device_policy|shield_allow|shield_block|
//! shield_profile`, `target` (MAC or domain), `value` (policy / profile name; set only), `reason` (≥ 3 chars),
//! `permanent=true` (REQUIRED for a set — the explicit confirmation), `owner_key` (re-authentication, ALWAYS:
//! every journal write is a durable change), `seq`, optional `dry_run=1` (preview only, nothing written).
//! Guards are ADR 0053's: same Origin, CSRF, strictly increasing per-session seq. Accepted changes are journal
//! records (their own audit); REFUSALS go to a RAM ring here — never to the eMMC, so an attacker cannot fill
//! the journal with refused attempts.
//! `GET /api/owner-rules`: every active rule with its effective result (`effective` / `shadowed_by`), the
//! journal status, and the recent refusals.
use crate::actionapi::{form_get, origin_ok, Ctx};
use crate::devpolicy::{Pol, ShieldProfile};
use crate::ownerjournal::{self as oj, Kind, OP_CLEAR, OP_REMOVE, OP_SET};
use hal::{BlockDev, BlockErr};

/// A RAM block store for QEMU / images without persistence (the API and its guards stay testable).
struct RamStore {
    s: [[u8; 512]; 64],
}
impl BlockDev for RamStore {
    fn block_count(&self) -> u64 {
        64
    }
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr> {
        *buf = *self.s.get(lba as usize).ok_or(BlockErr::OutOfRange)?;
        Ok(())
    }
    fn write_block(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), BlockErr> {
        *self.s.get_mut(lba as usize).ok_or(BlockErr::OutOfRange)? = *buf;
        Ok(())
    }
}

static mut RAM: RamStore = RamStore { s: [[0u8; 512]; 64] };
static mut DEV: Option<&'static mut dyn BlockDev> = None;
static mut J: Option<oj::Journal> = None;

/// ADR 0056 D6: a durable audit record for an artifact activation (or its rollback). Returns the journal
/// seq, or None when the journal is RAM-only / full / failed (the activation itself is not undone).
pub fn audit_artifact(ty: &str, value: u8, reason: &[u8], session: [u8; 4], ms: u64) -> Option<u64> {
    let mut r = oj::rec(Kind::Artifact, OP_SET, ty.as_bytes(), value, reason);
    r.session = u32::from_le_bytes(session);
    r.ms = ms;
    unsafe {
        match ((*core::ptr::addr_of_mut!(J)).as_mut(), (*core::ptr::addr_of_mut!(DEV)).as_mut()) {
            (Some(j), Some(d)) => j.append(&mut **d, r).ok(),
            _ => None,
        }
    }
}
static mut PERSISTENT: bool = false;
static mut LAST_REPLAY: oj::Replay = oj::Replay { records: 0, damaged: false, full: false };

/// Install the persistent store (AP image boot): `dev` armed for `[lo, hi)`, keyed by the device SRK.
#[cfg_attr(not(feature = "appersist"), allow(dead_code))]
pub fn install(dev: &'static mut dyn BlockDev, lo: u64, hi: u64, srk: &[u8; 32]) -> oj::Replay {
    let mut j = oj::Journal::new(lo, hi, srk);
    let r = j.replay(&*dev);
    unsafe {
        DEV = Some(dev);
        J = Some(j);
        PERSISTENT = true;
        LAST_REPLAY = r;
    }
    r
}

/// No persistent store: a RAM journal (rules last until reboot; the API says `persistent: false`).
pub fn install_ram(srk: &[u8; 32]) {
    unsafe {
        let ram: &'static mut RamStore = &mut *core::ptr::addr_of_mut!(RAM);
        ram.s = [[0u8; 512]; 64];
        J = Some(oj::Journal::new(0, 64, srk));
        DEV = Some(ram);
        PERSISTENT = false;
        LAST_REPLAY = oj::Replay::default();
    }
}

// ---- refusal ring (RAM) ----
#[derive(Clone, Copy)]
struct Refusal {
    ms: u64,
    session: [u8; 4],
    why: &'static str,
}
const RF0: Refusal = Refusal { ms: 0, session: [0; 4], why: "" };
static mut REFUSED: [Refusal; 16] = [RF0; 16];
static mut RHEAD: usize = 0;

fn refuse(c: &Ctx, why: &'static str) -> Result<Outcome, &'static str> {
    unsafe {
        REFUSED[RHEAD % 16] = Refusal { ms: c.now_ms, session: crate::mcauth::session_tag(c.session), why };
        RHEAD += 1;
    }
    Err(why)
}

/// What a write did (or, for a dry run, would do).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub seq: u64, // 0 for a dry run
    pub before: &'static str,
    pub after: &'static str,
    pub shadowed_by: &'static str, // "" when the rule takes effect
}

fn mac(s: &str) -> Option<[u8; 6]> {
    let mut m = [0u8; 6];
    let mut it = s.split([':', '-']);
    for b in m.iter_mut() {
        *b = u8::from_str_radix(it.next()?, 16).ok()?;
    }
    if it.next().is_some() || m[0] & 1 != 0 || m == [0; 6] {
        return None; // multicast / broadcast / zero refused (the DEVICES.TXT rules)
    }
    Some(m)
}

fn domain(s: &str) -> Option<&str> {
    let d = s.trim().trim_end_matches('.');
    let ok = d.len() >= 3 && d.len() <= oj::TARGET_MAX && d.contains('.') && !d.starts_with('.') && !d.contains("..")
        && d.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_')
        && !d.bytes().all(|c| c.is_ascii_digit() || c == b'.');
    ok.then_some(d)
}

fn pol_name(p: Pol) -> &'static str {
    p.name()
}

/// Run every guard, then preview or append. Ok(outcome) or Err(why refused).
pub fn submit(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<Outcome, &'static str> {
    let mut b = [[0u8; 192]; 9];
    let [ref mut b0, ref mut b1, ref mut b2, ref mut b3, ref mut b4, ref mut b5, ref mut b6, ref mut b7, ref mut b8] = b;
    let op = form_get(body, "op", b0).unwrap_or("");
    let kind_s = form_get(body, "kind", b1).unwrap_or("");
    let target_s = form_get(body, "target", b2).unwrap_or("");
    let value_s = form_get(body, "value", b3).unwrap_or("");
    let reason = form_get(body, "reason", b4).unwrap_or("");
    let permanent = form_get(body, "permanent", b5) == Some("true");
    let key = form_get(body, "owner_key", b6).unwrap_or("");
    let seq: u64 = form_get(body, "seq", b7).and_then(|v| v.parse().ok()).unwrap_or(0);
    let dry = form_get(body, "dry_run", b8) == Some("1");
    let tag = crate::mcauth::session_tag(c.session);
    if unsafe { (*core::ptr::addr_of!(J)).is_none() } {
        install_ram(&[0u8; 32]); // an image without persistence: rules last until reboot (`persistent: false`)
    }
    if !origin_ok(c.origin, c.host) {
        return refuse(c, "origin");
    }
    if !crate::mcauth::csrf_ok(c.session, c.csrf) {
        return refuse(c, "csrf");
    }
    if !crate::actions::rate_ok(tag, c.now_ms) {
        return refuse(c, "rate limited: at most 20 writes a minute per session");
    }
    if !crate::actions::accept_seq(tag, seq) {
        return refuse(c, "replay");
    }
    // ADR 0055 D7/D8: revoke every owner rule at once (the signed baseline + management floor are untouched).
    if op == "revoke_all" {
        if reason.trim().len() < 3 {
            return refuse(c, "reason required");
        }
        let mut n = 0usize;
        oj::for_each(&mut |_r: &oj::Rule| n += 1);
        let preview = Outcome { seq: 0, before: "owner rules active", after: "no owner rules (signed baseline only)", shadowed_by: "" };
        if dry {
            return Ok(preview);
        }
        if !permanent {
            return refuse(c, "permanent=true required");
        }
        if !auth.reauth(key.trim().as_bytes(), c.now_ms) {
            return refuse(c, "re-authentication failed");
        }
        let _ = n;
        let mut r = oj::rec(Kind::DevicePolicy, OP_CLEAR, b"*", 0, reason.as_bytes());
        r.session = u32::from_le_bytes(tag);
        r.ms = c.now_ms;
        let res = unsafe {
            match ((*core::ptr::addr_of_mut!(J)).as_mut(), (*core::ptr::addr_of_mut!(DEV)).as_mut()) {
                (Some(j), Some(d)) => j.append(&mut **d, r),
                _ => return refuse(c, "no journal"),
            }
        };
        return match res {
            Ok(seq) => Ok(Outcome { seq, ..preview }),
            Err(oj::JErr::Full) => refuse(c, "journal full"),
            Err(_) => refuse(c, "storage error"),
        };
    }
    let opc = match op {
        "set" => OP_SET,
        "remove" => OP_REMOVE,
        _ => return refuse(c, "op"),
    };
    let kind = match kind_s {
        "device_policy" => Kind::DevicePolicy,
        "shield_allow" => Kind::ShieldAllow,
        "shield_block" => Kind::ShieldBlock,
        "shield_profile" => Kind::ShieldProfile,
        _ => return refuse(c, "kind"),
    };
    if reason.trim().len() < 3 {
        return refuse(c, "reason required");
    }
    // target + value (and the before/after preview)
    let mut tbuf = [0u8; oj::TARGET_MAX];
    let (tlen, value, before, after, shadow): (usize, u8, &'static str, &'static str, &'static str) = match kind {
        Kind::Artifact | Kind::OwnerKey | Kind::AlertHook => return refuse(c, "kind"),
        Kind::DevicePolicy | Kind::ShieldProfile => {
            let Some(m) = mac(target_s) else { return refuse(c, "target") };
            tbuf[..6].copy_from_slice(&m);
            if kind == Kind::DevicePolicy {
                let v = match (opc, value_s) {
                    (OP_REMOVE, _) => Pol::Full,
                    (_, "full") => Pol::Full,
                    (_, "internet_only") => Pol::InternetOnly,
                    (_, "lan_only") => Pol::LanOnly,
                    (_, "quarantine") => Pol::Quarantine,
                    _ => return refuse(c, "value"),
                };
                let (signed, pinned) = crate::devpolicy::signed_policy(&m);
                let now = crate::devpolicy::policy_of(&m);
                let would = if opc == OP_REMOVE { signed } else if v.strictness_pub() > signed.strictness_pub() || !pinned { v } else { signed };
                let sh = if opc == OP_SET && would != v { "signed DEVICES.TXT line (pinned)" } else { "" };
                (6, v as u8, pol_name(now), pol_name(would), sh)
            } else {
                let v = match (opc, ShieldProfile::from_name(value_s.as_bytes())) {
                    (OP_REMOVE, _) => ShieldProfile::Standard,
                    (_, Some(v)) => v,
                    _ => return refuse(c, "value"),
                };
                let now = crate::devpolicy::shield_profile(&m);
                let pinned = crate::devpolicy::signed_policy(&m).1;
                let (would, sh) = if pinned && opc == OP_SET { (now, "signed DEVICES.TXT line (pinned)") } else { (v, "") };
                (6, v as u8, now.name(), would.name(), sh)
            }
        }
        Kind::ShieldAllow | Kind::ShieldBlock => {
            let Some(d) = domain(target_s) else { return refuse(c, "target") };
            let lower = d.as_bytes();
            for (i, ch) in lower.iter().enumerate() {
                tbuf[i] = ch.to_ascii_lowercase();
            }
            let n = lower.len();
            let now = crate::shield::decide(&tbuf[..n]).name();
            let malicious = crate::ioc::domain_listed(&tbuf[..n]) || crate::shield::cat_malicious(crate::shield::category_of(&tbuf[..n]));
            let (after, sh) = match (kind, opc) {
                (Kind::ShieldAllow, OP_SET) if malicious => (now, "confirmed malicious (threat-intel IOC or malware / phishing list)"),
                (Kind::ShieldAllow, OP_SET) => ("allow-rule", ""),
                (Kind::ShieldBlock, OP_SET) => ("blocked", ""),
                _ => ("baseline", ""),
            };
            (n, 1, now, after, sh)
        }
    };
    let preview = Outcome { seq: 0, before, after, shadowed_by: shadow };
    if dry {
        return Ok(preview);
    }
    if opc == OP_SET && !permanent {
        return refuse(c, "permanent=true required (or use a temporary action)");
    }
    if !auth.reauth(key.trim().as_bytes(), c.now_ms) {
        return refuse(c, "re-authentication failed");
    }
    let mut r = oj::rec(kind, opc, &tbuf[..tlen], value, reason.as_bytes());
    r.session = u32::from_le_bytes(tag);
    r.ms = c.now_ms;
    let res = unsafe {
        match ((*core::ptr::addr_of_mut!(J)).as_mut(), (*core::ptr::addr_of_mut!(DEV)).as_mut()) {
            (Some(j), Some(d)) => j.append(&mut **d, r),
            _ => return refuse(c, "no journal"),
        }
    };
    match res {
        Ok(seq) => Ok(Outcome { seq, ..preview }),
        Err(oj::JErr::Full) => refuse(c, "journal full"),
        Err(oj::JErr::TooManyRules) => refuse(c, "too many rules"),
        Err(_) => refuse(c, "storage error"),
    }
}

fn kind_name(k: u8) -> &'static str {
    Kind::from_u8(k).map_or("?", |k| k.name())
}

/// `GET /api/owner-rules`
pub fn render(w: &mut crate::mcstate::JsonBuf) {
    use core::fmt::Write;
    let (persistent, rp) = unsafe { (PERSISTENT, LAST_REPLAY) };
    let _ = write!(w, "{{\"persistent\":{},\"journal\":{{\"records\":{},\"damaged\":{},\"full\":{}}},\"rules\":[", persistent, rp.records, rp.damaged, rp.full);
    let mut first = true;
    oj::for_each(&mut |r: &oj::Rule| {
        if !first {
            w.raw(",");
        }
        first = false;
        let _ = write!(w, "{{\"seq\":{},\"kind\":\"{}\",\"target\":", r.seq, kind_name(r.kind));
        let t = &r.target[..r.tlen as usize];
        match Kind::from_u8(r.kind) {
            Some(Kind::DevicePolicy) | Some(Kind::ShieldProfile) if t.len() == 6 => {
                let _ = write!(w, "\"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\"", t[0], t[1], t[2], t[3], t[4], t[5]);
            }
            _ => w.string(core::str::from_utf8(t).unwrap_or("")),
        }
        let (value, effective, shadow): (&str, bool, &str) = match Kind::from_u8(r.kind) {
            Some(Kind::DevicePolicy) => {
                let v = Pol::from_u8(r.value).unwrap_or(Pol::Full);
                let mut m = [0u8; 6];
                m.copy_from_slice(&t[..6]);
                let eff = crate::devpolicy::policy_of(&m) == v;
                (v.name(), eff, if eff { "" } else { "signed DEVICES.TXT line (pinned)" })
            }
            Some(Kind::ShieldProfile) => {
                let v = ShieldProfile::from_u8(r.value).unwrap_or(ShieldProfile::Standard);
                let mut m = [0u8; 6];
                m.copy_from_slice(&t[..6]);
                let eff = crate::devpolicy::shield_profile(&m) == v;
                (v.name(), eff, if eff { "" } else { "signed DEVICES.TXT line (pinned)" })
            }
            Some(Kind::ShieldAllow) => {
                let mal = crate::ioc::domain_listed(t) || crate::shield::cat_malicious(crate::shield::category_of(t));
                ("allow", !mal, if mal { "confirmed malicious (threat-intel IOC or malware / phishing list)" } else { "" })
            }
            _ => ("block", true, ""),
        };
        let _ = write!(w, ",\"value\":\"{}\",\"effective\":{},\"shadowed_by\":", value, effective);
        if shadow.is_empty() { w.raw("null") } else { w.string(shadow) }
        w.raw("}");
    });
    w.raw("],\"refused\":[");
    let n = unsafe { RHEAD };
    for (k, i) in (n.saturating_sub(16)..n).rev().enumerate() {
        let r = unsafe { REFUSED[i % 16] };
        let _ = write!(w, "{}{{\"ms\":{},\"session\":\"{:02x}{:02x}{:02x}{:02x}\",\"why\":", if k > 0 { "," } else { "" }, r.ms, r.session[0], r.session[1], r.session[2], r.session[3]);
        w.string(r.why);
        w.raw("}");
    }
    w.raw("]}");
}

/// G28 owner-key rotation (`POST /api/owner-key`): the owner replaces the Mission Control owner key. Same guards as
/// every owner write (origin, CSRF, rate, replay) + re-authentication with the CURRENT key + `permanent=true`. The
/// device stores only a fresh salt and verifier (never the key) as a sealed journal record, swaps the live verifier
/// and ends EVERY session. The record names the OWNER.TXT it replaced, so re-flashing OWNER.TXT still recovers.
pub fn rotate_owner_key(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth, salt: Option<[u8; 16]>) -> Result<u64, &'static str> {
    let (mut b0, mut b1, mut b2, mut b3, mut b4) = ([0u8; 192], [0u8; 192], [0u8; 192], [0u8; 192], [0u8; 192]);
    let key = form_get(body, "owner_key", &mut b0).unwrap_or("");
    let new_key = form_get(body, "new_owner_key", &mut b1).unwrap_or("");
    let reason = form_get(body, "reason", &mut b2).unwrap_or("");
    let permanent = form_get(body, "permanent", &mut b3) == Some("true");
    let seq: u64 = form_get(body, "seq", &mut b4).and_then(|v| v.parse().ok()).unwrap_or(0);
    let tag = crate::mcauth::session_tag(c.session);
    if !origin_ok(c.origin, c.host) {
        return Err("origin");
    }
    if !crate::mcauth::csrf_ok(c.session, c.csrf) {
        return Err("csrf");
    }
    if !crate::actions::rate_ok(tag, c.now_ms) {
        return Err("rate limited: at most 20 writes a minute per session");
    }
    if !crate::actions::accept_seq(tag, seq) {
        return Err("replay");
    }
    if reason.trim().len() < 3 {
        return Err("reason required");
    }
    if !permanent {
        return Err("permanent=true required");
    }
    let nk = new_key.trim().as_bytes();
    if nk.len() < 16 || nk.len() > 128 || nk == key.trim().as_bytes() {
        return Err("new_owner_key: 16-128 characters, different from the current key");
    }
    if !auth.reauth(key.trim().as_bytes(), c.now_ms) {
        return Err("re-authentication failed");
    }
    let Some(salt) = salt else { return Err("no entropy for a new salt") };
    let verifier = crate::mcauth::verifier_for(&salt, nk);
    let mut t = [0u8; oj::TARGET_MAX];
    t[..16].copy_from_slice(&salt);
    t[16..48].copy_from_slice(&verifier);
    t[48..64].copy_from_slice(&crate::mcauth::owner_file_hash()[..16]);
    let mut r = oj::rec(Kind::OwnerKey, oj::OP_SET, &t, 0, reason.as_bytes());
    r.session = u32::from_le_bytes(tag);
    r.ms = c.now_ms;
    let res = unsafe {
        match ((*core::ptr::addr_of_mut!(J)).as_mut(), (*core::ptr::addr_of_mut!(DEV)).as_mut()) {
            (Some(j), Some(d)) => j.append(&mut **d, r),
            _ => return Err("no journal: the rotation would not survive a reboot"),
        }
    };
    match res {
        Ok(seq) => {
            // every session ends (the browser that rotated signs in again with the new key)
            *auth = crate::mcauth::Auth::new(Some(crate::mcauth::Owner { salt, verifier }));
            Ok(seq)
        }
        Err(oj::JErr::Full) => Err("journal full"),
        Err(_) => Err("storage error"),
    }
}

/// Owner alert webhook (operator 2026-11-10): `POST /api/alert-hook` — `op=set` with ip, port, format
/// (ntfy|gotify|json), path (the topic / endpoint), secret (the signing secret, >= 16 chars; only its hash is kept),
/// min_severity (critical|high|medium|low), or `op=remove`. Same guards + re-auth as every owner write.
pub fn alert_hook(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<u64, &'static str> {
    use crate::alerthook::{Hook, FMT_GOTIFY, FMT_JSON, FMT_NTFY, PATH_MAX};
    let mut b = [[0u8; 192]; 11];
    let [ref mut b0, ref mut b1, ref mut b2, ref mut b3, ref mut b4, ref mut b5, ref mut b6, ref mut b7, ref mut b8, ref mut b9, ref mut b10] = b;
    let op = form_get(body, "op", b0).unwrap_or("");
    let key = form_get(body, "owner_key", b1).unwrap_or("");
    let reason = form_get(body, "reason", b2).unwrap_or("");
    let permanent = form_get(body, "permanent", b3) == Some("true");
    let seq: u64 = form_get(body, "seq", b4).and_then(|v| v.parse().ok()).unwrap_or(0);
    let ip_s = form_get(body, "ip", b5).unwrap_or("");
    let port: u16 = form_get(body, "port", b6).and_then(|v| v.parse().ok()).unwrap_or(0);
    let fmt_s = form_get(body, "format", b7).unwrap_or("ntfy");
    let path = form_get(body, "path", b8).unwrap_or("");
    let secret = form_get(body, "secret", b9).unwrap_or("");
    let sev_s = form_get(body, "min_severity", b10).unwrap_or("high");
    let tag = crate::mcauth::session_tag(c.session);
    if !origin_ok(c.origin, c.host) {
        return Err("origin");
    }
    if !crate::mcauth::csrf_ok(c.session, c.csrf) {
        return Err("csrf");
    }
    if !crate::actions::rate_ok(tag, c.now_ms) {
        return Err("rate limited: at most 20 writes a minute per session");
    }
    if !crate::actions::accept_seq(tag, seq) {
        return Err("replay");
    }
    if reason.trim().len() < 3 {
        return Err("reason required");
    }
    if !permanent {
        return Err("permanent=true required");
    }
    let r = match op {
        "remove" => oj::rec(Kind::AlertHook, oj::OP_REMOVE, b"-", 0, b"/"),
        "set" => {
            let mut ip = [0u8; 4];
            let mut parts = ip_s.split('.');
            for o in ip.iter_mut() {
                *o = parts.next().and_then(|p| p.parse().ok()).ok_or("ip: a.b.c.d")?;
            }
            if parts.next().is_some() {
                return Err("ip: a.b.c.d");
            }
            let fmt = match fmt_s { "ntfy" => FMT_NTFY, "gotify" => FMT_GOTIFY, "json" => FMT_JSON, _ => return Err("format: ntfy|gotify|json") };
            let min_sev = match sev_s { "critical" => 1, "high" => 2, "medium" => 3, "low" => 4, _ => return Err("min_severity: critical|high|medium|low") };
            if secret.trim().len() < 16 {
                return Err("secret: at least 16 characters (the receiver verifies X-HQ-Signature with it)");
            }
            if path.len() > PATH_MAX {
                return Err("path too long");
            }
            let h = Hook { ip, port, fmt, min_sev, key: boot_abi::sha256::digest(secret.trim().as_bytes()), path: [0; PATH_MAX], plen: 0 };
            let enc = h.encode();
            Hook::decode(&enc, path.as_bytes()).ok_or("target: ip + port (not 0) and a path starting with /")?;
            oj::rec(Kind::AlertHook, oj::OP_SET, &enc, 0, path.as_bytes())
        }
        _ => return Err("op: set|remove"),
    };
    if !auth.reauth(key.trim().as_bytes(), c.now_ms) {
        return Err("re-authentication failed");
    }
    let mut r = r;
    r.session = u32::from_le_bytes(tag);
    r.ms = c.now_ms;
    let res = unsafe {
        match ((*core::ptr::addr_of_mut!(J)).as_mut(), (*core::ptr::addr_of_mut!(DEV)).as_mut()) {
            (Some(j), Some(d)) => j.append(&mut **d, r),
            _ => return Err("no journal"),
        }
    };
    match res {
        Ok(seq) => Ok(seq),
        Err(oj::JErr::Full) => Err("journal full"),
        Err(_) => Err("storage error"),
    }
}

/// G28 at boot: the owner that Mission Control uses — a journal rotation when it names THIS OWNER.TXT, else the
/// file's owner (an OWNER.TXT re-flashed since the rotation is the physical-access recovery and wins).
pub fn effective_owner(file_owner: Option<crate::mcauth::Owner>) -> (Option<crate::mcauth::Owner>, &'static str) {
    match oj::owner_rotation() {
        Some(t) if t[48..64] == crate::mcauth::owner_file_hash()[..16] => {
            let mut salt = [0u8; 16];
            let mut verifier = [0u8; 32];
            salt.copy_from_slice(&t[..16]);
            verifier.copy_from_slice(&t[16..48]);
            (Some(crate::mcauth::Owner { salt, verifier }), "rotated by the owner (journal) — OWNER.TXT superseded")
        }
        Some(_) => (file_owner, "OWNER.TXT changed since the owner's rotation (re-flash recovery) — the rotation is ignored"),
        None => (file_owner, "OWNER.TXT"),
    }
}

/// `[P-owner-rotate]` (G28)
pub fn rotate_selftest() -> bool {
    use crate::mcauth::{session_hex, verifier_for, Auth, Owner};
    let (old, new) = (b"old-owner-key-for-rotation-test" as &[u8], "new-owner-key-for-rotation-0001");
    let salt = [9u8; 16];
    let file_owner = Owner { salt, verifier: verifier_for(&salt, old) };
    crate::mcauth::set_owner_file_hash([0x11; 32]);
    let mut auth = Auth::new(Some(file_owner));
    let id = match auth.login(old, 7_000, || Some([0x31; 16])) { Ok(i) => i, Err(_) => return false };
    let mut hex = [0u8; 32];
    session_hex(&id, &mut hex);
    let sess = core::str::from_utf8(&hex).unwrap_or("");
    let mut tok = [0u8; 32];
    let _ = crate::mcauth::csrf_token(Some(sess), &mut tok);
    let csrf = core::str::from_utf8(&tok).unwrap_or("");
    let c = Ctx { session: Some(sess), origin: "https://10.99.0.1", host: "10.99.0.1", csrf, now_ms: 7_000 };
    install_ram(&[0x42u8; 32]);
    oj::clear();
    let base = crate::actions::last_seq(crate::mcauth::session_tag(Some(sess))) + 1;
    let mut buf = [0u8; 300];
    fn form(buf: &mut [u8; 300], s: &str, q: u64) -> usize {
        let mut n = s.len();
        buf[..n].copy_from_slice(s.as_bytes());
        buf[n..n + 5].copy_from_slice(b"&seq=");
        n += 5;
        let mut d = [0u8; 20];
        let (mut k, mut v) = (20, q);
        loop {
            k -= 1;
            d[k] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        buf[n..n + 20 - k].copy_from_slice(&d[k..]);
        n + 20 - k
    }
    let n = form(&mut buf, "owner_key=wrong-key-xxxxxxxxxxxxx&new_owner_key=new-owner-key-for-rotation-0001&reason=rotate&permanent=true", base);
    let bad_reauth = rotate_owner_key(&c, &buf[..n], &mut auth, Some([5; 16])) == Err("re-authentication failed");
    let n = form(&mut buf, "owner_key=old-owner-key-for-rotation-test&new_owner_key=short&reason=rotate&permanent=true", base + 1);
    let weak = rotate_owner_key(&c, &buf[..n], &mut auth, Some([5; 16])).is_err();
    let n = form(&mut buf, "owner_key=old-owner-key-for-rotation-test&new_owner_key=new-owner-key-for-rotation-0001&reason=rotate&permanent=true", base + 2);
    let rotated = rotate_owner_key(&c, &buf[..n], &mut auth, Some([5; 16])).is_ok();
    let sessions_ended = !auth.check(Some(sess), 7_100);
    let old_refused = auth.login(old, 7_200, || Some([0x32; 16])).is_err();
    let new_ok = auth.login(new.as_bytes(), 7_300, || Some([0x33; 16])).is_ok();
    // revoke-all keeps the rotation; boot precedence: same OWNER.TXT -> rotated, a re-flashed one -> the file
    let kept = oj::owner_rotation().is_some();
    let (eff, _) = effective_owner(Some(file_owner));
    let boot_rotated = eff.is_some_and(|o| o.verifier == verifier_for(&[5; 16], new.as_bytes()));
    crate::mcauth::set_owner_file_hash([0x22; 32]);
    let (eff2, _) = effective_owner(Some(file_owner));
    let reflash_wins = eff2 == Some(file_owner);
    // alert hook set with the NEW key, then churn the journal until it compacts: both settings must survive
    // compaction and a replay (each carried record keeps its own sequence number)
    let sess2 = auth.login(new.as_bytes(), 8_000, || Some([0x34; 16])).ok();
    let hook_ok = sess2.is_some_and(|id| {
        let mut hx = [0u8; 32];
        session_hex(&id, &mut hx);
        let s2 = core::str::from_utf8(&hx).unwrap_or("");
        let mut t2 = [0u8; 32];
        let _ = crate::mcauth::csrf_token(Some(s2), &mut t2);
        let c2 = Ctx { session: Some(s2), origin: "https://10.99.0.1", host: "10.99.0.1", csrf: core::str::from_utf8(&t2).unwrap_or(""), now_ms: 8_000 };
        let q = crate::actions::last_seq(crate::mcauth::session_tag(Some(s2))) + 1;
        let n = form(&mut buf, "op=set&ip=10.99.0.20&port=8080&format=ntfy&path=/heqk&secret=sixteen-chars-secret&min_severity=high&reason=alerts&permanent=true&owner_key=new-owner-key-for-rotation-0001", q);
        alert_hook(&c2, &buf[..n], &mut auth).is_ok()
    });
    let hook_set = crate::alerthook::get().is_some_and(|h| h.port == 8080 && h.path() == "/heqk");
    let mut churn = true;
    for k in 0..90u32 {
        let mut r = oj::rec(Kind::ShieldBlock, if k % 2 == 0 { oj::OP_SET } else { oj::OP_REMOVE }, b"churn.example", 1, b"churn");
        r.ms = 9_000 + k as u64;
        churn &= unsafe {
            match ((*core::ptr::addr_of_mut!(J)).as_mut(), (*core::ptr::addr_of_mut!(DEV)).as_mut()) {
                (Some(j), Some(d)) => j.append(&mut **d, r).is_ok(),
                _ => false,
            }
        };
    }
    let compacted = unsafe { (*core::ptr::addr_of!(J)).as_ref().is_some_and(|j| j.epoch() > 1) };
    let replay_clean = unsafe {
        match ((*core::ptr::addr_of_mut!(J)).as_mut(), (*core::ptr::addr_of_mut!(DEV)).as_mut()) {
            (Some(j), Some(d)) => !j.replay(&**d).damaged,
            _ => false,
        }
    };
    let carried = oj::owner_rotation().is_some() && crate::alerthook::get().is_some_and(|h| h.port == 8080);
    let survive = hook_ok && hook_set && churn && compacted && replay_clean && carried;
    oj::clear();
    let pass = bad_reauth && weak && rotated && sessions_ended && old_refused && new_ok && kept && boot_rotated && reflash_wins && survive;
    arch_aarch64::_print(format_args!(
        " [P-owner-rotate] {} — G28 owner-key rotation: wrong current key refused={} weak new key refused={} rotated={} every session ended={} old key refused={} new key signs in={} kept in the journal={} next boot uses it={} a re-flashed OWNER.TXT wins={} | alert hook set + both settings survive compaction and replay={}\n",
        if pass { "PASS" } else { "FAIL" }, bad_reauth, weak, rotated, sessions_ended, old_refused, new_ok, kept, boot_rotated, reflash_wins, survive));
    pass
}

/// `[P-ownerapi]`
pub fn selftest() -> bool {
    use crate::mcauth::{session_hex, verifier_for, Auth, Owner};
    let token: &[u8] = b"owner-key-for-the-journal-test";
    let salt = [7u8; 16];
    let mut auth = Auth::new(Some(Owner { salt, verifier: verifier_for(&salt, token) }));
    let id = match auth.login(token, 5_000, || Some([0x24; 16])) { Ok(i) => i, Err(_) => return false };
    let mut hex = [0u8; 32];
    session_hex(&id, &mut hex);
    let sess = core::str::from_utf8(&hex).unwrap_or("");
    let mut tok = [0u8; 32];
    let _ = crate::mcauth::csrf_token(Some(sess), &mut tok);
    let csrf = core::str::from_utf8(&tok).unwrap_or("");
    let good = Ctx { session: Some(sess), origin: "https://10.99.0.1", host: "10.99.0.1", csrf, now_ms: 5_000 };
    install_ram(&[0x24u8; 32]);
    oj::clear();
    let k = "&owner_key=owner-key-for-the-journal-test";
    let mut buf = [0u8; 400];
    fn fill(buf: &mut [u8; 400], s: &[&str]) -> usize {
        let mut n = 0;
        for p in s {
            buf[n..n + p.len()].copy_from_slice(p.as_bytes());
            n += p.len();
        }
        n
    }
    let n = fill(&mut buf, &["op=set&kind=shield_allow&target=School.Example&reason=wrongly+blocked&permanent=true", k, "&seq=1"]);
    let set = submit(&good, &buf[..n], &mut auth).is_ok_and(|o| o.seq == 1) && oj::shield_allowed(b"school.example");
    let n = fill(&mut buf, &["op=set&kind=shield_block&target=games.example&reason=homework", k, "&seq=2"]);
    let unconfirmed = submit(&good, &buf[..n], &mut auth) == Err("permanent=true required (or use a temporary action)") && !oj::shield_blocked(b"games.example");
    let n = fill(&mut buf, &["op=set&kind=shield_block&target=games.example&reason=homework&permanent=true&owner_key=wrong&seq=3"]);
    let reauth = submit(&good, &buf[..n], &mut auth) == Err("re-authentication failed");
    let n = fill(&mut buf, &["op=set&kind=device_policy&target=02:00:00:00:00:51&value=quarantine&reason=preview&dry_run=1&seq=4"]);
    let dry = submit(&good, &buf[..n], &mut auth).is_ok_and(|o| o.seq == 0 && o.before == "full" && o.after == "quarantine") && oj::device_policy(&[2, 0, 0, 0, 0, 0x51]).is_none();
    let n = fill(&mut buf, &["op=set&kind=device_policy&target=ff:ff:ff:ff:ff:ff&value=full&reason=xyz&permanent=true", k, "&seq=5"]);
    let bad_mac = submit(&good, &buf[..n], &mut auth) == Err("target");
    let n = fill(&mut buf, &["op=set&kind=shield_allow&target=a.example&reason=xyz&permanent=true", k, "&seq=5"]);
    let replay = submit(&good, &buf[..n], &mut auth) == Err("replay");
    let bad_origin = submit(&Ctx { origin: "https://evil.example", ..Ctx { ..good } }, b"op=set&kind=shield_allow&target=a.example&reason=xyz&permanent=true&seq=9", &mut auth) == Err("origin");
    // ADR 0055 D7/D8: revoke ALL owner rules — re-auth required, then nothing the owner set remains
    let n = fill(&mut buf, &["op=set&kind=shield_block&target=games.example&reason=homework&permanent=true", k, "&seq=10"]);
    let two = submit(&good, &buf[..n], &mut auth).is_ok() && oj::shield_blocked(b"games.example") && oj::shield_allowed(b"school.example");
    let n = fill(&mut buf, &["op=revoke_all&reason=start+over&permanent=true&owner_key=wrong&seq=11"]);
    let ra_reauth = submit(&good, &buf[..n], &mut auth) == Err("re-authentication failed") && oj::shield_blocked(b"games.example");
    let n = fill(&mut buf, &["op=revoke_all&reason=start+over&permanent=true", k, "&seq=12"]);
    let revoked = submit(&good, &buf[..n], &mut auth).is_ok_and(|o| o.seq > 0) && !oj::shield_blocked(b"games.example") && !oj::shield_allowed(b"school.example");
    let revoke_all = two && ra_reauth && revoked;
    oj::clear();
    let pass = set && unconfirmed && reauth && dry && bad_mac && replay && bad_origin && revoke_all;
    arch_aarch64::_print(format_args!(
        " [P-ownerapi] {} — ADR 0055 owner-rules API: permanent set (re-auth + permanent=true) lands in the journal={} unconfirmed set refused={} wrong owner key refused={} dry run previews without writing={} broadcast MAC refused={} replayed seq refused={} foreign Origin refused={} revoke-all (re-auth, then no owner rule left)={}\n",
        if pass { "PASS" } else { "FAIL" }, set, unconfirmed, reauth, dry, bad_mac, replay, bad_origin, revoke_all
    ));
    pass
}
