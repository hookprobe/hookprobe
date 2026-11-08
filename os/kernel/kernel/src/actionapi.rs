//! The write path for ADR 0053 actions: form parsing + every guard, in order, with the outcome audited.
//! Kept apart from `http.rs` so it is testable without a socket.

use crate::actions::{self, Kind, Target};

/// One form field, percent/plus-decoded into `buf`.
pub fn form_get<'b>(body: &[u8], key: &str, buf: &'b mut [u8; 192]) -> Option<&'b str> {
    let s = core::str::from_utf8(body).ok()?;
    let v = s.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v))?;
    let b = v.as_bytes();
    let (mut i, mut n) = (0usize, 0usize);
    while i < b.len() {
        let c = match b[i] {
            b'%' => {
                let h = |x: u8| (x as char).to_digit(16);
                let v = h(*b.get(i + 1)?)? * 16 + h(*b.get(i + 2)?)?;
                i += 3;
                v as u8
            }
            b'+' => {
                i += 1;
                b' '
            }
            c => {
                i += 1;
                c
            }
        };
        *buf.get_mut(n)? = c;
        n += 1;
    }
    core::str::from_utf8(&buf[..n]).ok()
}

fn ipv4(s: &str) -> Option<u32> {
    let s = s.strip_prefix("inc:heqk:").unwrap_or(s);
    let mut v = 0u32;
    let mut parts = 0;
    for t in s.split('.') {
        if t.is_empty() || t.len() > 3 || !t.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let o: u32 = t.parse().ok()?;
        if o > 255 {
            return None;
        }
        v = (v << 8) | o;
        parts += 1;
    }
    (parts == 4 && v != 0).then_some(v)
}

fn mac(s: &str) -> Option<[u8; 6]> {
    let b = s.as_bytes();
    if b.len() != 17 {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, part) in b.split(|&c| c == b':' || c == b'-').enumerate() {
        if i >= 6 || part.len() != 2 {
            return None;
        }
        let h = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        m[i] = h(part[0])? << 4 | h(part[1])?;
    }
    (m != [0; 6] && m[0] & 1 == 0).then_some(m)
}

fn domain_hash(s: &str) -> Option<u64> {
    let d = s.strip_suffix('.').unwrap_or(s).as_bytes();
    if d.len() < 3 || d.len() > 253 || !d.contains(&b'.') || !d.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_')) {
        return None;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in d {
        h ^= b.to_ascii_lowercase() as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Some(h)
}

/// Does `origin` ("https://host[:port]") name the same host as the request's `Host` header?
pub fn origin_ok(origin: &str, host: &str) -> bool {
    let o = origin.strip_prefix("https://").or_else(|| origin.strip_prefix("http://"));
    matches!(o, Some(o) if !host.is_empty() && o == host)
}

/// The request facts the guards need.
pub struct Ctx<'a> {
    pub session: Option<&'a str>,
    pub origin: &'a str,
    pub host: &'a str,
    pub csrf: &'a str,
    pub now_ms: u64,
}

/// Run every guard and, if all pass, record the action. Ok(id) or Err(why refused); audited either way.
pub fn submit(c: &Ctx, body: &[u8], auth: &mut crate::mcauth::Auth) -> Result<u32, &'static str> {
    let tag = crate::mcauth::session_tag(c.session);
    let mut kb = [0u8; 192];
    let mut tb = [0u8; 192];
    let mut rb = [0u8; 192];
    let kind = form_get(body, "kind", &mut kb).and_then(Kind::parse);
    let target_s = form_get(body, "target", &mut tb).unwrap_or("");
    let reason = form_get(body, "reason", &mut rb).unwrap_or("");
    let mut nb = [0u8; 192];
    let ttl_s: u64 = form_get(body, "ttl", &mut nb).and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut sb = [0u8; 192];
    let seq: u64 = form_get(body, "seq", &mut sb).and_then(|v| v.parse().ok()).unwrap_or(0);
    let k = kind.unwrap_or(Kind::Ack);
    let target = match k {
        Kind::Ack | Kind::HoldIp => ipv4(target_s).map(|v| if k == Kind::Ack { Target::Incident(v) } else { Target::Ip(v) }),
        Kind::Isolate => mac(target_s).map(Target::Mac),
        Kind::ShieldAllow => domain_hash(target_s).map(Target::Domain),
    };
    let refuse = |why: &'static str| {
        actions::audit(tag, k, target.unwrap_or(Target::Incident(0)), ttl_s, false, why, reason.as_bytes());
        Err(why)
    };
    if !origin_ok(c.origin, c.host) {
        return refuse("origin");
    }
    if !crate::mcauth::csrf_ok(c.session, c.csrf) {
        return refuse("csrf");
    }
    if !actions::accept_seq(tag, seq) {
        return refuse("replay");
    }
    if kind.is_none() {
        return refuse("kind");
    }
    if reason.trim().len() < 3 {
        return refuse("reason required");
    }
    let Some(target) = target else { return refuse("target") };
    if let Target::Ip(ip) = target {
        // The management path always passes (operator rule, ADR 0023): a session can never hold it.
        if crate::verdict::is_allowlisted(ip) {
            return refuse("management floor");
        }
        if ip == 0 || ip >= 0xE000_0000 {
            return refuse("target");
        }
    }
    if k.has_ttl() && !(actions::MIN_TTL_S..=actions::MAX_TTL_S).contains(&ttl_s) {
        return refuse("ttl out of bounds");
    }
    if k.needs_reauth() {
        let mut ob = [0u8; 192];
        let key = form_get(body, "owner_key", &mut ob).unwrap_or("");
        if !auth.reauth(key.trim().as_bytes(), c.now_ms) {
            return refuse("re-authentication failed");
        }
    }
    match actions::add(k, target, ttl_s) {
        Some(id) => {
            actions::audit(tag, k, target, ttl_s, true, "", reason.as_bytes());
            Ok(id)
        }
        None => refuse("store full"),
    }
}

/// End an action early (same origin / CSRF / replay guards); audited either way.
pub fn revoke(c: &Ctx, body: &[u8]) -> Result<(), &'static str> {
    let tag = crate::mcauth::session_tag(c.session);
    let mut ib = [0u8; 192];
    let id: u32 = form_get(body, "id", &mut ib).and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut sb = [0u8; 192];
    let seq: u64 = form_get(body, "seq", &mut sb).and_then(|v| v.parse().ok()).unwrap_or(0);
    let why = if !origin_ok(c.origin, c.host) {
        Some("origin")
    } else if !crate::mcauth::csrf_ok(c.session, c.csrf) {
        Some("csrf")
    } else if !actions::accept_seq(tag, seq) {
        Some("replay")
    } else if !actions::revoke(id) {
        Some("no such active action")
    } else {
        None
    };
    actions::audit(tag, Kind::Ack, Target::Incident(id), 0, why.is_none(), why.unwrap_or("revoked"), b"revoke");
    match why {
        None => Ok(()),
        Some(w) => Err(w),
    }
}

/// `[P-actions]` — ADR 0053 guards and effects.
pub fn selftest() -> bool {
    use crate::mcauth::{session_hex, verifier_for, Auth, Owner};
    actions::reset();
    actions::reset_audit();
    actions::tick(1_000);
    let token: &[u8] = b"owner-key-for-the-actions-test";
    let salt = [9u8; 16];
    let mut auth = Auth::new(Some(Owner { salt, verifier: verifier_for(&salt, token) }));
    let id = match auth.login(token, 1_000, || Some([0x42; 16])) { Ok(i) => i, Err(_) => return false };
    let mut hex = [0u8; 32];
    session_hex(&id, &mut hex);
    let sess = core::str::from_utf8(&hex).unwrap_or("");
    let mut tok = [0u8; 32];
    let _ = crate::mcauth::csrf_token(Some(sess), &mut tok);
    let csrf = core::str::from_utf8(&tok).unwrap_or("");
    let good = Ctx { session: Some(sess), origin: "https://10.99.0.1", host: "10.99.0.1", csrf, now_ms: 1_000 };

    // guards, each refused for the right reason
    let bad_origin = Ctx { origin: "https://evil.example", ..Ctx { ..good } };
    let o = submit(&bad_origin, b"kind=ack&target=10.0.0.5&reason=seen+it&seq=1", &mut auth) == Err("origin");
    let no_origin = submit(&Ctx { origin: "", ..Ctx { ..good } }, b"kind=ack&target=10.0.0.5&reason=seen+it&seq=1", &mut auth) == Err("origin");
    let bad_csrf = submit(&Ctx { csrf: "00000000000000000000000000000000", ..Ctx { ..good } }, b"kind=ack&target=10.0.0.5&reason=seen+it&seq=1", &mut auth) == Err("csrf");
    let ack = submit(&good, b"kind=ack&target=inc%3Aheqk%3A10.0.0.5&reason=seen+it&seq=1", &mut auth).is_ok() && actions::acked(0x0A00_0005);
    let replay = submit(&good, b"kind=ack&target=10.0.0.6&reason=again&seq=1", &mut auth) == Err("replay");
    let no_reason = submit(&good, b"kind=hold_ip&target=203.0.113.9&ttl=600&reason=&seq=2", &mut auth) == Err("reason required");
    let ttl_hi = submit(&good, b"kind=hold_ip&target=203.0.113.9&ttl=90000&reason=scanner&seq=3", &mut auth) == Err("ttl out of bounds");
    let ttl_lo = submit(&good, b"kind=hold_ip&target=203.0.113.9&ttl=5&reason=scanner&seq=4", &mut auth) == Err("ttl out of bounds");
    let hold = submit(&good, b"kind=hold_ip&target=203.0.113.9&ttl=600&reason=scanner&seq=5", &mut auth).is_ok() && actions::ip_held(0xCB00_7109);
    // high impact needs the owner key again
    let iso_noauth = submit(&good, b"kind=isolate&target=02:00:00:00:00:07&ttl=3600&reason=infected&seq=6", &mut auth) == Err("re-authentication failed");
    let iso = submit(&good, b"kind=isolate&target=02:00:00:00:00:07&ttl=3600&reason=infected&owner_key=owner-key-for-the-actions-test&seq=7", &mut auth).is_ok()
        && !crate::devpolicy::check(&[2, 0, 0, 0, 0, 7], crate::devpolicy::Dest::Internet)
        && crate::devpolicy::check(&[2, 0, 0, 0, 0, 7], crate::devpolicy::Dest::Infra);
    let allow = submit(&good, b"kind=shield_allow&target=Ads.Example.com&ttl=600&reason=false+positive&owner_key=owner-key-for-the-actions-test&seq=8", &mut auth).is_ok()
        && actions::shield_allowed(domain_hash("ads.example.com").unwrap_or(0));
    let bad_target = submit(&good, b"kind=isolate&target=ff:ff:ff:ff:ff:ff&ttl=3600&reason=x+y+z&owner_key=owner-key-for-the-actions-test&seq=9", &mut auth) == Err("target");
    let unknown = submit(&good, b"kind=disable_ips&target=10.0.0.1&ttl=60&reason=nope&seq=10", &mut auth) == Err("kind");
    // expiry is the kernel's, not the UI's; revoke ends early
    actions::tick(1_000 + 599_000);
    let still = actions::ip_held(0xCB00_7109);
    actions::tick(1_000 + 601_000);
    let expired = !actions::ip_held(0xCB00_7109) && actions::isolated(&[2, 0, 0, 0, 0, 7]);
    let mut iso_id = 0;
    actions::for_each(&mut |e, _| if e.kind == Kind::Isolate { iso_id = e.id });
    let mut body = [0u8; 64];
    let n = { let s = b"id="; body[..3].copy_from_slice(s); let mut d = [0u8; 10]; let mut k = 0; let mut v = iso_id; loop { d[k] = b'0' + (v % 10) as u8; k += 1; v /= 10; if v == 0 { break; } } for i in 0..k { body[3 + i] = d[k - 1 - i]; } let t = b"&seq=11"; body[3 + k..3 + k + t.len()].copy_from_slice(t); 3 + k + t.len() };
    let revoked = revoke(&good, &body[..n]).is_ok() && !actions::isolated(&[2, 0, 0, 0, 0, 7]);
    // the management floor can never be held: refused at submit, and ignored by the hook even if stored
    let (fnet, _, _) = crate::verdict::mgmt_floor();
    let fip = fnet | 7;
    let mut mb = [0u8; 96];
    let head = b"kind=hold_ip&target=";
    mb[..head.len()].copy_from_slice(head);
    let mut m = head.len();
    for (i, oct) in fip.to_be_bytes().iter().enumerate() {
        if i > 0 {
            mb[m] = b'.';
            m += 1;
        }
        let mut v = *oct;
        let mut d = [0u8; 3];
        let mut k = 0;
        loop { d[k] = b'0' + v % 10; k += 1; v /= 10; if v == 0 { break; } }
        for j in 0..k { mb[m] = d[k - 1 - j]; m += 1; }
    }
    let tail = b"&ttl=600&reason=lockout+test&seq=12";
    mb[m..m + tail.len()].copy_from_slice(tail);
    m += tail.len();
    let floor_refused = submit(&good, &mb[..m], &mut auth) == Err("management floor");
    let floor_hook = actions::add(Kind::HoldIp, Target::Ip(fip), 600).is_some() && !actions::ip_held(fip);
    let floor = floor_refused && floor_hook;
    // every attempt is audited, refusals included
    let mut total = 0;
    let mut refused = 0;
    actions::for_each_audit(&mut |a| { total += 1; if !a.ok { refused += 1; } });
    let audited = total >= 15 && refused >= 10;
    let pass = o && no_origin && bad_csrf && ack && replay && no_reason && ttl_hi && ttl_lo && hold && iso_noauth && iso && allow && bad_target && unknown && still && expired && revoked && audited && floor;
    actions::reset();
    actions::reset_audit();
    arch_aarch64::_print(format_args!(
        " [P-actions] {} — ADR 0053 operator actions: refused for origin={} missing origin={} csrf={} replay={} no reason={} TTL > 24 h={} TTL < 60 s={} bad target={} unknown kind={} | ack={} hold_ip={} isolate needs the owner key again={} isolate -> quarantine policy (DHCP/DNS still work)={} shield exception={} | expiry by the kernel clock={}/{} revoke={} management floor never held={} every attempt audited incl. refusals={}\n",
        if pass { "PASS" } else { "FAIL" }, o, no_origin, bad_csrf, replay, no_reason, ttl_hi, ttl_lo, bad_target, unknown, ack, hold, iso_noauth, iso, allow, still, expired, revoked, floor, audited
    ));
    pass
}
