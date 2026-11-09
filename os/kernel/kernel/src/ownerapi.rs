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
use crate::ownerjournal::{self as oj, Kind, OP_REMOVE, OP_SET};
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
        Kind::Artifact => return refuse(c, "kind"),
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
    oj::clear();
    let pass = set && unconfirmed && reauth && dry && bad_mac && replay && bad_origin;
    arch_aarch64::_print(format_args!(
        " [P-ownerapi] {} — ADR 0055 owner-rules API: permanent set (re-auth + permanent=true) lands in the journal={} unconfirmed set refused={} wrong owner key refused={} dry run previews without writing={} broadcast MAC refused={} replayed seq refused={} foreign Origin refused={}\n",
        if pass { "PASS" } else { "FAIL" }, set, unconfirmed, reauth, dry, bad_mac, replay, bad_origin
    ));
    pass
}
