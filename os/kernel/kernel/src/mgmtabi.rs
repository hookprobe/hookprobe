//! The management ABI dispatcher (ADR 0059 D9; hsh spec §14, R3): every `hal::mgmtabi` message is served HERE, by the
//! SAME producers as `GET /api/*` (McState, cfgd, the anchor, the EL0 servers' counters), as fixed records — so
//! Mission Control and `hsh` see identical numbers and get the same authorisation decision.
//!
//! Authority (R6 = D, operator 2026-11-12): view messages need the view role (the carrier's authenticated session);
//! EVERY message above view is authorised ONLY by an HQMGMT1 envelope signed by the enrolled owner key K_own (the
//! device holds only its public half), verified HERE in EL1 before anything runs — whatever the carrier (the web
//! console, Mission Control's confirm / rollback, a future CLI). The session's role never authorises a change.
//!
//! Replay: a per-boot EPOCH (8 bytes from the hardware TRNG on the CM5, drawn on first use) + a RAM sequence floor.
//! Each accepted-for-verification envelope consumes its sequence (the floor rises to it). The floor need not persist:
//! a reboot draws a new epoch, so every envelope signed for an earlier boot no longer matches (no eMMC write per
//! operation, nothing to roll back). No TRNG word = no epoch = every privileged operation refused (fail-closed).

use hal::mgmtabi as m;

/// Serve `msg` for a caller holding `role` (session `tag`, argument `arg`, the carrier's envelope `env`, empty = none)
/// into `out`. Returns (result code, record length). Configuration operations are journaled HERE — allowed or refused
/// — so Mission Control and `hsh` leave the same record for the same operation.
pub fn dispatch(msg: u16, role: u8, tag: [u8; 4], now_ms: u64, arg: u64, env: &[u8], out: &mut [u8]) -> (u8, usize) {
    let need = m::role_for(msg);
    if need == u8::MAX {
        return (m::R_UNKNOWN, 0);
    }
    if need <= m::ROLE_VIEW && role < need {
        return (m::R_DENIED, 0);
    }
    if msg == m::OWNER_CHALLENGE {
        let c = challenge();
        let e = c.encode();
        out[..e.len()].copy_from_slice(&e);
        return (m::R_OK, e.len());
    }
    if matches!(msg, m::CFG_CONFIRM | m::CFG_ROLLBACK | m::CFG_STAGE) {
        // the envelope is the ONLY authority for a change (the session's role is not consulted)
        let r: Result<u64, &str> = match verify_envelope(msg, arg, env) {
            Err(e) => Err(e),
            Ok(()) => match msg {
                m::CFG_CONFIRM => crate::cfgd::confirm_device(),
                m::CFG_ROLLBACK => crate::cfgd::revert_device(),
                _ => match crate::upload::verified_type(tag, arg) {
                    Some(crate::artstore::Ty::Config) => crate::upload::activate_by_id(tag, now_ms, arg).map(|a| a.gen),
                    Some(_) => Err("not a configuration bundle (upload type config)"),
                    None => Err("unknown or unverified upload id"),
                },
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
    if role < need {
        return (m::R_DENIED, 0);
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

/// One owner-journal record per configuration operation (the same for every client), allowed or refused.
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
    unsafe {
        JOURNALED += 1;
        LAST_JOURNAL = (msg, ok);
    }
}
static mut JOURNALED: u64 = 0;
static mut LAST_JOURNAL: (u16, bool) = (0, false);
/// Self-tests (QEMU): how many configuration operations were journaled, and the last one (message, allowed).
#[cfg(not(feature = "cm5"))]
pub fn journaled() -> (u64, u16, bool) {
    unsafe { (JOURNALED, LAST_JOURNAL.0, LAST_JOURNAL.1) }
}

// ---- R6 = D: HQMGMT1 owner-signed command envelopes -------------------------------------------------------------

static mut EPOCH: Option<[u8; 8]> = None;
static mut FLOOR: u64 = 0;

/// This boot's epoch (drawn once from the TRNG; None = no entropy: privileged operations are refused).
pub fn epoch() -> Option<[u8; 8]> {
    unsafe {
        let e = &mut *core::ptr::addr_of_mut!(EPOCH);
        if e.is_none() {
            *e = crate::mcserve::rand16().map(|r| r[..8].try_into().unwrap());
        }
        *e
    }
}
/// The lowest sequence the next envelope may carry.
pub fn next_seq() -> u64 {
    unsafe { FLOOR + 1 }
}

/// What the next envelope must bind (OWNER_CHALLENGE; /api/config's `mgmt` object reads the same).
pub fn challenge() -> m::Challenge {
    m::Challenge {
        device_id: crate::config_device_id(),
        epoch: epoch().unwrap_or([0; 8]),
        next_seq: next_seq(),
        generation: crate::cfgd::generation(),
        digest: crate::cfgd::bundle_digest(),
        on_trial: crate::cfgd::on_trial(),
        owner_enrolled: crate::anchor::owner().is_some(),
    }
}

/// Every refusal `verify_envelope` can give (static, so Mission Control's JSON can name it).
pub const ENV_REASONS: [&str; 11] = [
    "refused: needs an owner-signed envelope",
    "refused: no owner key enrolled",
    "refused: malformed envelope",
    "refused: signature is not the owner key's",
    "refused: envelope is for another device",
    "refused: no entropy for the boot epoch",
    "refused: envelope from another boot",
    "refused: replayed or stale sequence",
    "refused: envelope is for another operation",
    "refused: something else is on trial",
    "refused: something else is in force",
];
const IN_FORCE: &str = ENV_REASONS[10];

/// Decode a carrier's envelope: exactly 2 * ENV_LEN hex digits (either case), nothing else.
pub fn unhex_envelope(h: &[u8], out: &mut [u8; m::ENV_LEN]) -> bool {
    if h.len() != 2 * m::ENV_LEN {
        return false;
    }
    let v = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    for (o, p) in out.iter_mut().zip(h.chunks(2)) {
        match (v(p[0]), v(p[1])) {
            (Some(a), Some(b)) => *o = a << 4 | b,
            _ => return false,
        }
    }
    true
}

/// Verify the carrier's envelope for (`msg`, `arg`): structure, the enrolled owner key's signature, this device, this
/// boot, a fresh sequence (consumed once the signature verifies), the operation, and — for confirm / rollback — the
/// exact bundle in force. Reasons fit the 56-byte Act record.
pub fn verify_envelope(msg: u16, arg: u64, env: &[u8]) -> Result<(), &'static str> {
    if env.is_empty() {
        return Err("refused: needs an owner-signed envelope");
    }
    let owner = crate::anchor::owner().ok_or("refused: no owner key enrolled")?;
    let (e, sig) = m::Envelope::parse(env).ok_or("refused: malformed envelope")?;
    let signed = m::envelope_msg(&e.body());
    let ok = match (ed25519_compact::PublicKey::from_slice(&owner), ed25519_compact::Signature::from_slice(&sig)) {
        (Ok(k), Ok(s)) => k.verify(&signed[..], &s).is_ok(),
        _ => false,
    };
    if !ok {
        return Err("refused: signature is not the owner key's");
    }
    if e.device_id != crate::config_device_id() {
        return Err("refused: envelope is for another device");
    }
    let ep = epoch().ok_or("refused: no entropy for the boot epoch")?;
    if e.epoch != ep {
        return Err("refused: envelope from another boot");
    }
    if e.seq <= unsafe { FLOOR } {
        return Err("refused: replayed or stale sequence");
    }
    unsafe { FLOOR = e.seq }; // consumed: valid signature, this device, this boot
    if e.msg != msg || e.arg != arg {
        return Err("refused: envelope is for another operation");
    }
    if matches!(msg, m::CFG_CONFIRM | m::CFG_ROLLBACK) {
        if msg == m::CFG_CONFIRM && !crate::cfgd::on_trial() {
            return Err("no configuration on trial");
        }
        if e.generation != crate::cfgd::generation() || e.digest != crate::cfgd::bundle_digest() {
            return Err(if crate::cfgd::on_trial() { ENV_REASONS[9] } else { IN_FORCE });
        }
    } else if e.generation != 0 || e.digest != [0; 32] {
        return Err("refused: envelope is for another operation");
    }
    Ok(())
}

/// Self-tests: a fresh epoch / floor (the next real envelope must use what OWNER_CHALLENGE then reports).
pub fn test_reset() {
    unsafe {
        FLOOR = 0;
        EPOCH = None;
    }
}
