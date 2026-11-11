//! The management ABI dispatcher (ADR 0059 D9; hsh spec §14, R3): every `hal::mgmtabi` message is served HERE, by the
//! SAME producers as `GET /api/*` (McState, cfgd, the anchor, the EL0 servers' counters), as fixed records — so
//! Mission Control and `hsh` see identical numbers and get the same authorisation decision. Role-checked: a message
//! the caller's role does not cover is DENIED (the shell only hides commands; this enforces).

use hal::mgmtabi as m;

/// Serve `msg` for a caller holding `role` (session `tag`, argument `arg`) into `out`. Returns (result code, record
/// length). Configuration operations are journaled HERE — allowed or refused — so Mission Control and `hsh` leave the
/// same record for the same operation.
pub fn dispatch(msg: u16, role: u8, tag: [u8; 4], now_ms: u64, arg: u64, payload: &[u8], out: &mut [u8]) -> (u8, usize) {
    let role = role.max(elevated(tag, now_ms));
    let need = m::role_for(msg);
    if need == u8::MAX {
        return (m::R_UNKNOWN, 0);
    }
    if role < need {
        if matches!(msg, m::CFG_CONFIRM | m::CFG_ROLLBACK | m::CFG_STAGE) {
            journal(msg, false, 0, "denied: role", tag, now_ms);
        }
        return (m::R_DENIED, 0);
    }
    if msg == m::OWNER_CHALLENGE {
        let c = challenge(tag, now_ms);
        let e = c.encode();
        out[..e.len()].copy_from_slice(&e);
        return (m::R_OK, e.len());
    }
    if msg == m::OWNER_ELEVATE {
        let r = elevate(tag, now_ms, payload);
        let a = match r {
            Ok(()) => m::Act::new(true, crate::anchor::owner_gen(), "owner role granted for 15 minutes"),
            Err(e) => m::Act::new(false, 0, e),
        };
        let mut b = [0u8; 64];
        let n = {
            use core::fmt::Write;
            let mut w = crate::mcstate::JsonBuf::new(&mut b);
            let _ = write!(w, "elevate {}", a.reason_str());
            w.len
        };
        let _ = crate::ownerapi::audit_artifact("hsh", if a.ok { 1 } else { 2 }, &b[..n], tag, now_ms);
        let e = a.encode();
        out[..e.len()].copy_from_slice(&e);
        return (m::R_OK, e.len());
    }
    if matches!(msg, m::CFG_CONFIRM | m::CFG_ROLLBACK | m::CFG_STAGE) {
        let r: Result<u64, &str> = match msg {
            m::CFG_CONFIRM => crate::cfgd::confirm_device(),
            m::CFG_ROLLBACK => crate::cfgd::revert_device(),
            _ => match crate::upload::verified_type(tag, arg) {
                Some(crate::artstore::Ty::Config) => crate::upload::activate_by_id(tag, now_ms, arg).map(|a| a.gen),
                Some(_) => Err("not a configuration bundle (upload type config)"),
                None => Err("unknown or unverified upload id"),
            },
        };
        let a = match r {
            Ok(g) => m::Act::new(true, g, if msg == m::CFG_STAGE { "staged: trial at the next boot" } else { "done" }),
            Err(e) => m::Act::new(false, 0, e),
        };
        journal(msg, a.ok, a.generation, a.reason_str(), tag, now_ms);
        let e = a.encode();
        out[..e.len()].copy_from_slice(&e);
        return (m::R_OK, e.len());
    }
    match msg {
        m::GET_INFO => {
            let st = crate::mcserve::state();
            let mut build = [0u8; 24];
            let b = option_env!("HEQK_BUILD_ID").unwrap_or("dev").as_bytes();
            build[..b.len().min(24)].copy_from_slice(&b[..b.len().min(24)]);
            let cfg_state = match crate::cfgd::state() {
                crate::cfgd::Boot::None => 0,
                crate::cfgd::Boot::Committed(_) => 1,
                crate::cfgd::Boot::Trial(_) => if crate::cfgd::on_trial() { 2 } else { 1 },
                crate::cfgd::Boot::Reverted { .. } => 3,
                crate::cfgd::Boot::Refused => 4,
            };
            let i = m::Info {
                build,
                uptime_s: now_ms / 1000,
                rules_active: crate::rules::active_rules() as u32,
                seen: st.seen,
                forwarded: st.forwarded,
                dropped: st.dropped,
                detections: st.detections() as u32,
                clock_synced: st.clock_synced,
                config_protected: crate::policysig::config_key().is_some(),
                owner_enrolled: crate::anchor::owner().is_some(),
                cfg_state,
                cfg_gen: crate::cfgd::generation(),
            };
            let e = i.encode();
            let n = e.len();
            out[..n].copy_from_slice(&e);
            return (m::R_OK, n);
        }
        m::GET_WAN => {
            let w = match crate::mcserve::state().wan() {
                Some(f) => m::Wan { present: true, up: f.up, mode: f.mode, ipv6: f.ipv6, ip: f.ip, clients: f.clients, pkts_out: f.pkts_out, pkts_in: f.pkts_in, dns_inspected: f.dns_inspected, dns_blocked: f.dns_blocked },
                None => m::Wan::default(),
            };
            let e = w.encode();
            out[..e.len()].copy_from_slice(&e);
            return (m::R_OK, e.len());
        }
        m::GET_QSECBIT => {
            let q = match crate::mcserve::state().qsecbit_latest() {
                Some((r, band, n)) => {
                    let mut b = [0u8; 8];
                    b[..band.len().min(8)].copy_from_slice(&band.as_bytes()[..band.len().min(8)]);
                    m::Qs { present: true, score_milli: r, band: b, samples: n }
                }
                None => m::Qs::default(),
            };
            let e = q.encode();
            out[..e.len()].copy_from_slice(&e);
            return (m::R_OK, e.len());
        }
        m::GET_CONFIG => {
            let g = crate::anchor::cfg_gens();
            let state = match crate::cfgd::state() {
                crate::cfgd::Boot::None => 0,
                crate::cfgd::Boot::Committed(_) => 1,
                crate::cfgd::Boot::Trial(_) => if crate::cfgd::on_trial() { 2 } else { 1 },
                crate::cfgd::Boot::Reverted { .. } => 3,
                crate::cfgd::Boot::Refused => 4,
            };
            let c = m::Cfg {
                state,
                on_trial: crate::cfgd::on_trial(),
                needs_confirm: crate::cfgd::on_trial() && crate::cfgd::touches_mgmt(),
                generation: crate::cfgd::generation(),
                floor: g.cfg_floor,
                elapsed_s: if crate::cfgd::on_trial() { crate::cfgd::elapsed_s() } else { 0 },
                window_s: crate::cfgd::WINDOW_S,
                wan_cur: g.wan_cur,
                wan_floor: g.wan_floor,
                wifi_cur: g.wifi_cur,
                wifi_floor: g.wifi_floor,
                policy_floor: crate::policysig::floor(),
            };
            let e = c.encode();
            out[..e.len()].copy_from_slice(&e);
            return (m::R_OK, e.len());
        }
        m::GET_ANCHOR => {
            let fp = |k: [u8; 32]| -> [u8; 8] { k[..8].try_into().unwrap() };
            let a = m::Anchor {
                protected: crate::policysig::config_key().is_some(),
                vendor: crate::policysig::key().map(fp),
                owner: crate::anchor::owner().map(fp),
                owner_gen: crate::anchor::owner_gen(),
            };
            let e = a.encode();
            out[..e.len()].copy_from_slice(&e);
            return (m::R_OK, e.len());
        }
        m::GET_PARSERS => {
            let (lw, lc, lf, lr, lk) = crate::lansvc::stats();
            #[allow(unused_mut)]
            let mut p = m::Parsers { lan_el0: lw == "el0", lan_calls: lc, lan_faults: lf, lan_restarts: lr, lan_in_kernel: lk, ..Default::default() };
            #[cfg(feature = "mctls")]
            {
                let (n, f) = crate::tlshost::http_el0_stats();
                p.http_el0 = crate::tlshost::host().is_some();
                p.http_requests = n;
                p.http_faults = f;
            }
            let e = p.encode();
            out[..e.len()].copy_from_slice(&e);
            return (m::R_OK, e.len());
        }
        _ => (m::R_UNKNOWN, 0),
    }
}

/// One owner-journal record per configuration operation (the same for every client).
fn journal(msg: u16, ok: bool, gen: u64, why: &str, tag: [u8; 4], now_ms: u64) {
    let op = match msg {
        m::CFG_CONFIRM => "confirm",
        m::CFG_ROLLBACK => "rollback",
        _ => "stage",
    };
    let mut b = [0u8; 64];
    let n = {
        use core::fmt::Write;
        let mut w = crate::mcstate::JsonBuf::new(&mut b);
        let _ = write!(w, "{} gen {} {}", op, gen, why);
        w.len
    };
    let _ = crate::ownerapi::audit_artifact("config", if ok { 1 } else { 2 }, &b[..n], tag, now_ms);
}

// ---- step 4c: owner elevation (HQCHAL1) -----------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Pending {
    tag: [u8; 4],
    nonce: [u8; 16],
    until_ms: u64,
}
const SLOTS: usize = 4;
static mut CHALLENGES: [Option<Pending>; SLOTS] = [None; SLOTS];
static mut ELEVATED: [Option<([u8; 4], u64)>; SLOTS] = [None; SLOTS];
static mut NONCE_CTR: u64 = 0;

/// The role a session holds through elevation (0 = none / expired).
pub fn elevated(tag: [u8; 4], now_ms: u64) -> u8 {
    let e = unsafe { &*core::ptr::addr_of!(ELEVATED) };
    if e.iter().flatten().any(|&(t, until)| t == tag && now_ms < until) { m::ROLE_OWNER } else { 0 }
}

/// A fresh single-use nonce for this session (one outstanding per session; the oldest slot is reused).
fn challenge(tag: [u8; 4], now_ms: u64) -> m::Challenge {
    let dev = crate::config_device_id();
    let ctr = unsafe {
        NONCE_CTR += 1;
        NONCE_CTR
    };
    let mut h = boot_abi::sha256::Hasher::new();
    h.update(b"HQCHAL1-nonce");
    h.update(&dev);
    h.update(&tag);
    h.update(&now_ms.to_le_bytes());
    h.update(&ctr.to_le_bytes());
    let d = h.finish();
    let nonce: [u8; 16] = d[..16].try_into().unwrap();
    let c = unsafe { &mut *core::ptr::addr_of_mut!(CHALLENGES) };
    let slot = c.iter().position(|p| p.is_none_or(|p| p.tag == tag || now_ms >= p.until_ms)).unwrap_or((ctr as usize) % SLOTS);
    c[slot] = Some(Pending { tag, nonce, until_ms: now_ms + m::CHALLENGE_TTL_S * 1000 });
    m::Challenge { device_id: dev, nonce, ttl_s: m::CHALLENGE_TTL_S as u32, owner_enrolled: crate::anchor::owner().is_some() }
}

/// Verify the owner's signature over this session's outstanding challenge; single-use (consumed either way).
fn elevate(tag: [u8; 4], now_ms: u64, sig: &[u8]) -> Result<(), &'static str> {
    let owner = crate::anchor::owner().ok_or("no owner key enrolled (enroll in Mission Control first)")?;
    let c = unsafe { &mut *core::ptr::addr_of_mut!(CHALLENGES) };
    let i = c.iter().position(|p| p.is_some_and(|p| p.tag == tag)).ok_or("no challenge outstanding (run owner challenge)")?;
    let p = c[i].take().unwrap();
    if now_ms >= p.until_ms {
        return Err("challenge expired");
    }
    if sig.len() != 64 {
        return Err("signature must be 64 bytes");
    }
    let msg = m::challenge_msg(&crate::config_device_id(), &p.nonce);
    let ok = match (ed25519_compact::PublicKey::from_slice(&owner), ed25519_compact::Signature::from_slice(sig)) {
        (Ok(k), Ok(s)) => k.verify(&msg[..], &s).is_ok(),
        _ => false,
    };
    if !ok {
        return Err("signature does not verify with the enrolled owner key");
    }
    let e = unsafe { &mut *core::ptr::addr_of_mut!(ELEVATED) };
    let slot = e.iter().position(|x| x.is_none_or(|(t, u)| t == tag || now_ms >= u)).unwrap_or(0);
    e[slot] = Some((tag, now_ms + m::ELEVATE_TTL_S * 1000));
    Ok(())
}

/// Self-tests: drop every challenge / elevation.
pub fn test_reset() {
    unsafe {
        CHALLENGES = [None; SLOTS];
        ELEVATED = [None; SLOTS];
    }
}
