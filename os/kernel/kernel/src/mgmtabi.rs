//! The management ABI dispatcher (ADR 0059 D9; hsh spec §14, R3): every `hal::mgmtabi` message is served HERE, by the
//! SAME producers as `GET /api/*` (McState, cfgd, the anchor, the EL0 servers' counters), as fixed records — so
//! Mission Control and `hsh` see identical numbers and get the same authorisation decision.
//!
//! Authority (R6 = D, operator 2026-11-12): view messages need the view role (the carrier's authenticated session);
//! EVERY message above view is authorised ONLY by an HQMGMT1 envelope signed by the enrolled owner key K_own (the
//! device holds only its public half), verified HERE in EL1 before anything runs — whatever the carrier (the web
//! console, Mission Control's confirm / rollback, a future CLI). The session's role never authorises a change.
//!
//! The verifier (signature, device, per-boot epoch, sequence floor) is `mgmtenv`, shared with Mission Control's own
//! owner endpoints.

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
        crate::mgmtenv::journal(msg, a.ok, a.generation, a.reason_str(), tag, now_ms);
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

pub use crate::mgmtenv::{epoch, next_seq};

/// What the next envelope must bind (OWNER_CHALLENGE; /api/config's `envelope` object reads the same).
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

/// The carrier's envelope for a configuration message: the shared verifier (`mgmtenv`), then the binding — for
/// confirm / rollback the exact bundle in force, otherwise no generation / digest. Reasons fit the 56-byte Act record.
pub fn verify_envelope(msg: u16, arg: u64, env: &[u8]) -> Result<(), &'static str> {
    let e = crate::mgmtenv::verify(msg, arg, env)?;
    if matches!(msg, m::CFG_CONFIRM | m::CFG_ROLLBACK) {
        if msg == m::CFG_CONFIRM && !crate::cfgd::on_trial() {
            return Err("no configuration on trial");
        }
        if e.generation != crate::cfgd::generation() || e.digest != crate::cfgd::bundle_digest() {
            return Err(if crate::cfgd::on_trial() { crate::mgmtenv::ON_TRIAL } else { crate::mgmtenv::IN_FORCE });
        }
    } else if e.generation != 0 || e.digest != [0; 32] {
        return Err(crate::mgmtenv::OTHER_TARGET);
    }
    Ok(())
}

/// Self-tests: a fresh epoch / floor (the next real envelope must use what OWNER_CHALLENGE then reports).
pub fn test_reset() {
    crate::mgmtenv::test_reset();
}
