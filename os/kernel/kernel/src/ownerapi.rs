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
static mut LAST_REPLAY: oj::Replay = oj::Replay { records: 0, damaged: false, full: false, rollback: false, anchor: 0 };

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
            Err(oj::JErr::RolledBack) => refuse(c, "rolled back: this journal is older than its anchored state — a factory reset is required before new owner changes"),
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
        "device_label" => Kind::DeviceLabel,
        _ => return refuse(c, "kind"),
    };
    if reason.trim().len() < 3 {
        return refuse(c, "reason required");
    }
    // target + value (and the before/after preview)
    let mut tbuf = [0u8; oj::TARGET_MAX];
    let (tlen, value, before, after, shadow): (usize, u8, &'static str, &'static str, &'static str) = match kind {
        Kind::Artifact | Kind::OwnerKey | Kind::AlertHook | Kind::FactoryReset => return refuse(c, "kind"),
        Kind::DeviceLabel => {
            // G47: target = the device's MAC, value = the new label (owner_label grammar); remove = back to DEVICES.TXT
            let Some(m) = mac(target_s) else { return refuse(c, "target") };
            tbuf[..6].copy_from_slice(&m);
            let mut cur = [0u8; oj::LABEL_MAX];
            let had = oj::owner_label(&m, &mut cur) > 0 || crate::devpolicy::signed_label(&m);
            let before = if had { "labelled" } else { "unlabelled" };
            if opc == OP_REMOVE {
                (6, 0, before, if crate::devpolicy::signed_label(&m) { "signed DEVICES.TXT label" } else { "unlabelled" }, "")
            } else {
                let v = value_s.trim().as_bytes();
                if !oj::label_ok(v) {
                    return refuse(c, "value: 1-31 characters: letters, digits, space . _ - ' ( ) ,");
                }
                tbuf[6..6 + v.len()].copy_from_slice(v);
                (6 + v.len(), 0, before, "labelled", "")
            }
        }
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
        Err(oj::JErr::RolledBack) => refuse(c, "rolled back: this journal is older than its anchored state — a factory reset is required before new owner changes"),
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
    // D-RPMB: `rollback` = an older copy of the journal was restored (owner rules from it are not applied; a factory
    // reset recovers); `anchor` = none | verified | caught_up | first | faulted
    let anchor = ["none", "verified", "caught_up", "first", "faulted"].get(rp.anchor as usize).copied().unwrap_or("none");
    let _ = write!(w, "{{\"persistent\":{},\"journal\":{{\"records\":{},\"damaged\":{},\"full\":{},\"rollback\":{},\"anchor\":\"{}\"}},\"rules\":[", persistent, rp.records, rp.damaged, rp.full, rp.rollback, anchor);
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
    // G47: owner device labels (cosmetic, always effective)
    oj::for_each_label(&mut |l: &oj::Label| {
        if !first {
            w.raw(",");
        }
        first = false;
        let m = l.mac;
        let _ = write!(w, "{{\"seq\":{},\"kind\":\"device_label\",\"target\":\"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\",\"value\":", l.seq, m[0], m[1], m[2], m[3], m[4], m[5]);
        w.string(core::str::from_utf8(&l.label[..l.len as usize]).unwrap_or(""));
        w.raw(",\"effective\":true,\"shadowed_by\":null}");
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
        Err(oj::JErr::RolledBack) => Err("rolled back: this journal is older than its anchored state — a factory reset is required before new owner changes"),
        Err(_) => Err("storage error"),
    }
}

/// Set by an accepted factory reset: the AP loop reboots once the HTTP response has gone out.
static mut RESET_REBOOT: bool = false;
pub fn take_reset_reboot() -> bool {
    unsafe { core::mem::replace(&mut *core::ptr::addr_of_mut!(RESET_REBOOT), false) }
}

/// Factory reset (Phase 7): `POST /api/factory-reset` with `confirm=ERASE`, a reason, `permanent=true` and
/// re-authentication with the owner key, behind the owner-write guards (origin, CSRF, rate, replay). It only
/// appends a `FactoryReset` record to the sealed journal and asks for a reboot: the wipe itself runs at the
/// next boot (`factoryreset::run`), before anything is served, so it is the same code path after a power cut.
/// Erased: owner rules / Shield profiles / alert hook / owner-key rotation (the journal), the sealed evidence
/// log, the sealed snapshot (both A/B slots), the artifact manifest (packs fall back to the signed image).
/// Kept: the boot slots, the signed POLICY.TXT / WAN.TXT, the label credential (OWNER.TXT), the device key and
/// every anti-rollback floor — a reset device is the shipped device, never a downgraded one.
pub fn factory_reset(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<u64, &'static str> {
    let (mut b0, mut b1, mut b2, mut b3, mut b4) = ([0u8; 192], [0u8; 192], [0u8; 192], [0u8; 192], [0u8; 192]);
    let key = form_get(body, "owner_key", &mut b0).unwrap_or("");
    let confirm = form_get(body, "confirm", &mut b1).unwrap_or("");
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
    if confirm != "ERASE" {
        return Err("confirm=ERASE required");
    }
    if reason.trim().len() < 3 {
        return Err("reason required");
    }
    if !permanent {
        return Err("permanent=true required");
    }
    if !auth.reauth(key.trim().as_bytes(), c.now_ms) {
        return Err("re-authentication failed");
    }
    if unsafe { !PERSISTENT } {
        return Err("no persistent journal: nothing durable to erase (a reboot already forgets every owner change)");
    }
    let mut r = oj::rec(Kind::FactoryReset, oj::OP_SET, b"erase", 0, reason.as_bytes());
    r.session = u32::from_le_bytes(tag);
    r.ms = c.now_ms;
    let res = unsafe {
        match ((*core::ptr::addr_of_mut!(J)).as_mut(), (*core::ptr::addr_of_mut!(DEV)).as_mut()) {
            (Some(j), Some(d)) => j.append(&mut **d, r),
            _ => return Err("no journal"),
        }
    };
    match res {
        Ok(seq) => {
            *auth = crate::mcauth::Auth::new(None); // every session ends now; the device reboots into the wipe
            unsafe { RESET_REBOOT = true };
            Ok(seq)
        }
        Err(oj::JErr::Full) => Err("journal full"),
        Err(oj::JErr::RolledBack) => Err("rolled back: this journal is older than its anchored state — a factory reset is required before new owner changes"),
        Err(_) => Err("storage error"),
    }
}

/// Set by an accepted owner reboot (G49, ADR 0058 "Apply now"): the AP loop reboots once the response has gone out.
static mut OWNER_REBOOT: bool = false;
pub fn take_owner_reboot() -> bool {
    unsafe { core::mem::replace(&mut *core::ptr::addr_of_mut!(OWNER_REBOOT), false) }
}

fn hexn<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim().as_bytes();
    if s.len() != 2 * N {
        return None;
    }
    let mut o = [0u8; N];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(core::str::from_utf8(&s[2 * i..2 * i + 2]).ok()?, 16).ok()?;
    }
    Some(o)
}

/// ADR 0058 D3 `POST /api/anchor/enroll` (public_key, proof) and `POST /api/anchor/rotate` (public_key, proof,
/// generation, signature): owner-write guards + re-authentication. Enroll is one-shot (initial provisioning, operator
/// 2026-11-10 rule 3); afterwards only a rotation signed by the enrolled key. The device verifies every signature;
/// the session only decides whether to try. Returns the owner-key generation now in force.
pub fn anchor_set(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth, rotate: bool) -> Result<u64, &'static str> {
    let (mut b0, mut b1, mut b2, mut b3, mut b4, mut b5) = ([0u8; 192], [0u8; 192], [0u8; 192], [0u8; 192], [0u8; 192], [0u8; 192]);
    let key = form_get(body, "owner_key", &mut b0).unwrap_or("");
    let pk = form_get(body, "public_key", &mut b1).and_then(hexn::<32>);
    let proof = form_get(body, "proof", &mut b2).and_then(hexn::<64>);
    let seq: u64 = form_get(body, "seq", &mut b3).and_then(|v| v.parse().ok()).unwrap_or(0);
    let gen: Option<u64> = form_get(body, "generation", &mut b4).and_then(|v| v.parse().ok());
    let sig = form_get(body, "signature", &mut b5).and_then(hexn::<64>);
    let tag = crate::mcauth::session_tag(c.session);
    if !origin_ok(c.origin, c.host) {
        return refuse(c, "origin").map(|_| 0);
    }
    if !crate::mcauth::csrf_ok(c.session, c.csrf) {
        return refuse(c, "csrf").map(|_| 0);
    }
    if !crate::actions::rate_ok(tag, c.now_ms) {
        return refuse(c, "rate limited: at most 20 writes a minute per session").map(|_| 0);
    }
    if !crate::actions::accept_seq(tag, seq) {
        return refuse(c, "replay").map(|_| 0);
    }
    let (Some(pk), Some(proof)) = (pk, proof) else { return refuse(c, "public_key (64 hex) and proof (128 hex) required").map(|_| 0) };
    let rot = if rotate {
        match (gen, sig) {
            (Some(g), Some(s)) => Some((g, s)),
            _ => return refuse(c, "generation and signature (128 hex) required").map(|_| 0),
        }
    } else {
        None
    };
    if !auth.reauth(key.trim().as_bytes(), c.now_ms) {
        return refuse(c, "re-authentication failed").map(|_| 0);
    }
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    {
        let r = crate::anchor::set_owner(&pk, &proof, rot);
        let fp = u32::from_be_bytes([pk[0], pk[1], pk[2], pk[3]]);
        let mut reason = [0u8; 64];
        let rl = {
            use core::fmt::Write;
            let mut w = crate::mcstate::JsonBuf::new(&mut reason);
            let _ = write!(w, "{} owner key {:08x}", if rotate { "rotate" } else { "enroll" }, fp);
            w.len
        };
        let _ = audit_artifact("anchor", if r.is_ok() { 1 } else { 2 }, &reason[..rl], tag, c.now_ms);
        arch_aarch64::_print(format_args!(" [ANCHOR] owner key {} {:08x}…: {:?}\n", if rotate { "rotation" } else { "enrollment" }, fp, r));
        return match r {
            Ok(g) => Ok(g),
            Err(e) => refuse(c, e).map(|_| 0),
        };
    }
    #[allow(unreachable_code)]
    {
        let _ = (pk, proof, rot);
        refuse(c, "no DataVolume: nothing can be pinned on this device").map(|_| 0)
    }
}

/// ADR 0059 step 3: `POST /api/config/confirm` (commit the trial now) and `/api/config/rollback` (the previous
/// bundle for the next boot): reason + permanent=true behind the owner-write guards (session, Origin, CSRF, rate,
/// sequence) — the transport gate — and (R6 = D) an `envelope` signed by the enrolled owner key that binds the bundle
/// in force: the ONLY authority for the change (the owner token re-authentication no longer is).
pub fn config_action(c: &Ctx, body: &[u8], confirm: bool) -> Result<u64, &'static str> {
    let (mut b1, mut b2, mut b3) = ([0u8; 192], [0u8; 192], [0u8; 192]);
    let reason = form_get(body, "reason", &mut b1).unwrap_or("");
    let permanent = form_get(body, "permanent", &mut b2) == Some("true");
    let seq: u64 = form_get(body, "seq", &mut b3).and_then(|v| v.parse().ok()).unwrap_or(0);
    let tag = crate::mcauth::session_tag(c.session);
    if !origin_ok(c.origin, c.host) {
        return refuse(c, "origin").map(|_| 0);
    }
    if !crate::mcauth::csrf_ok(c.session, c.csrf) {
        return refuse(c, "csrf").map(|_| 0);
    }
    if !crate::actions::rate_ok(tag, c.now_ms) {
        return refuse(c, "rate limited: at most 20 writes a minute per session").map(|_| 0);
    }
    if !crate::actions::accept_seq(tag, seq) {
        return refuse(c, "replay").map(|_| 0);
    }
    if reason.trim().len() < 3 {
        return refuse(c, "reason required").map(|_| 0);
    }
    if !permanent {
        return refuse(c, "permanent=true required").map(|_| 0);
    }
    // R6 = D (hard switch, operator 2026-11-12): the owner token no longer authorises a change — no re-authentication
    // here, an `owner_key` field is ignored. The change is authorised ONLY by the owner-signed envelope (form field
    // `envelope`, 312 hex = HQMGMT1, bound to this device, this boot, a fresh sequence and the bundle in force),
    // verified by the management ABI: the same decision and journal record as `hsh`. The session guards above only
    // gate the transport. A missing / malformed field is passed on as "no envelope", so the refusal is journaled too.
    #[cfg_attr(not(feature = "mcserve"), allow(unused_mut, unused_variables))]
    let mut env = [0u8; hal::mgmtabi::ENV_LEN];
    #[cfg(feature = "mcserve")]
    let env_given = body
        .split(|&b| b == b'&')
        .find_map(|kv| kv.strip_prefix(b"envelope="))
        .is_some_and(|v| crate::mgmtabi::unhex_envelope(v, &mut env));
    let msg = if confirm { hal::mgmtabi::CFG_CONFIRM } else { hal::mgmtabi::CFG_ROLLBACK };
    #[cfg_attr(not(feature = "mcserve"), allow(unused_mut))]
    let mut rec = [0u8; hal::mgmtabi::ACT_LEN];
    #[cfg(feature = "mcserve")]
    let (res, n) = crate::mgmtabi::dispatch(msg, hal::mgmtabi::ROLE_VIEW, tag, c.now_ms, 0, if env_given { &env[..] } else { &[] }, &mut rec);
    // builds without Mission Control's server have no envelope verifier: nothing can authorise a change (fail closed)
    #[cfg(not(feature = "mcserve"))]
    let (res, n) = {
        let _ = (msg, tag, &env);
        (hal::mgmtabi::R_UNAVAILABLE, 0)
    };
    if res != hal::mgmtabi::R_OK || n != hal::mgmtabi::ACT_LEN {
        return refuse(c, "management service unavailable").map(|_| 0);
    }
    let a = hal::mgmtabi::Act::decode(&rec);
    if a.ok {
        Ok(a.generation)
    } else {
        // the reason is the envelope / cfgd / upload refusal, as one of the static strings Mission Control shows
        let why = a.reason_str();
        #[cfg(feature = "mcserve")]
        if let Some(r) = crate::mgmtabi::ENV_REASONS.iter().find(|r| **r == why) {
            return refuse(c, r).map(|_| 0);
        }
        refuse(c, if why.starts_with("no configuration store") { "no configuration store on this device" } else if why.starts_with("no configuration on trial") { "no configuration on trial" } else if why.starts_with("no configuration bundle") { "no configuration bundle in force" } else { "refused by cfgd" }).map(|_| 0)
    }
}

/// G49: `POST /api/reboot` — reason + `permanent=true` + re-authentication, behind the owner-write guards (origin,
/// CSRF, rate, replay). A plain restart: nothing is erased; staged configuration (A/B store) applies on the way up.
pub fn reboot(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<(), &'static str> {
    let (mut b0, mut b1, mut b2, mut b3) = ([0u8; 192], [0u8; 192], [0u8; 192], [0u8; 192]);
    let key = form_get(body, "owner_key", &mut b0).unwrap_or("");
    let reason = form_get(body, "reason", &mut b1).unwrap_or("");
    let permanent = form_get(body, "permanent", &mut b2) == Some("true");
    let seq: u64 = form_get(body, "seq", &mut b3).and_then(|v| v.parse().ok()).unwrap_or(0);
    let tag = crate::mcauth::session_tag(c.session);
    if !origin_ok(c.origin, c.host) {
        return refuse(c, "origin").map(|_| ());
    }
    if !crate::mcauth::csrf_ok(c.session, c.csrf) {
        return refuse(c, "csrf").map(|_| ());
    }
    if !crate::actions::rate_ok(tag, c.now_ms) {
        return refuse(c, "rate limited: at most 20 writes a minute per session").map(|_| ());
    }
    if !crate::actions::accept_seq(tag, seq) {
        return refuse(c, "replay").map(|_| ());
    }
    if reason.trim().len() < 3 {
        return refuse(c, "reason required").map(|_| ());
    }
    if !permanent {
        return refuse(c, "permanent=true required").map(|_| ());
    }
    if !auth.reauth(key.trim().as_bytes(), c.now_ms) {
        return refuse(c, "re-authentication failed").map(|_| ());
    }
    arch_aarch64::_print(format_args!(" [OWNER] reboot requested by the owner ({}) — restarting in 2 s\n", reason.trim()));
    unsafe { OWNER_REBOOT = true };
    Ok(())
}

/// Boot-time half of the factory reset: zero the journal region (called last, after the other stores).
pub fn wipe_journal() -> Result<u64, &'static str> {
    unsafe {
        match ((*core::ptr::addr_of_mut!(J)).as_mut(), (*core::ptr::addr_of_mut!(DEV)).as_mut()) {
            (Some(j), Some(d)) if PERSISTENT => j.wipe(&mut **d).map_err(|_| "journal write failed"),
            _ => Err("no persistent journal"),
        }
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
        Err(oj::JErr::RolledBack) => Err("rolled back: this journal is older than its anchored state — a factory reset is required before new owner changes"),
        Err(_) => Err("storage error"),
    }
}

/// G28 at boot: the owner that Mission Control uses — a journal rotation when it names THIS OWNER.TXT, else the
/// file's owner (an OWNER.TXT re-flashed since the rotation is the physical-access recovery and wins).
pub fn effective_owner(file_owner: Option<crate::mcauth::Owner>) -> (Option<crate::mcauth::Owner>, &'static str) {
    match oj::owner_rotation() {
        Some(t) if t[48..64] == crate::mcauth::owner_file_hash()[..16] => {
            // Journal record layout: salt[0..16] ‖ verifier[16..48] ‖ OWNER.TXT hash prefix[48..64].
            let (Ok(salt), Ok(verifier)) = (<[u8; 16]>::try_from(&t[..16]), <[u8; 32]>::try_from(&t[16..48])) else {
                return (file_owner, "OWNER.TXT");
            };
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
    let Ok(salt) = <[u8; 16]>::try_from(&boot_abi::sha256::digest(old)[..16]) else { return false };
    // The new owner's salt: in production rand16() (TRNG, fail-closed); here a derived test value.
    let Ok(test_salt) = <[u8; 16]>::try_from(&boot_abi::sha256::digest(b"P-owner-rotate test salt")[..16]) else { return false };
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
    let bad_reauth = rotate_owner_key(&c, &buf[..n], &mut auth, Some(test_salt)) == Err("re-authentication failed");
    let n = form(&mut buf, "owner_key=old-owner-key-for-rotation-test&new_owner_key=short&reason=rotate&permanent=true", base + 1);
    let weak = rotate_owner_key(&c, &buf[..n], &mut auth, Some(test_salt)).is_err();
    let n = form(&mut buf, "owner_key=old-owner-key-for-rotation-test&new_owner_key=new-owner-key-for-rotation-0001&reason=rotate&permanent=true", base + 2);
    let rotated = rotate_owner_key(&c, &buf[..n], &mut auth, Some(test_salt)).is_ok();
    let sessions_ended = !auth.check(Some(sess), 7_100);
    let old_refused = auth.login(old, 7_200, || Some([0x32; 16])).is_err();
    let new_ok = auth.login(new.as_bytes(), 7_300, || Some([0x33; 16])).is_ok();
    // revoke-all keeps the rotation; boot precedence: same OWNER.TXT -> rotated, a re-flashed one -> the file
    let kept = oj::owner_rotation().is_some();
    let (eff, _) = effective_owner(Some(file_owner));
    let boot_rotated = eff.is_some_and(|o| o.verifier == verifier_for(&test_salt, new.as_bytes()));
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
