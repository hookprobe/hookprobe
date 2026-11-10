//! The management ABI dispatcher (ADR 0059 D9; hsh spec §14, R3): every `hal::mgmtabi` message is served HERE, by the
//! SAME producers as `GET /api/*` (McState, cfgd, the anchor, the EL0 servers' counters), as fixed records — so
//! Mission Control and `hsh` see identical numbers and get the same authorisation decision. Role-checked: a message
//! the caller's role does not cover is DENIED (the shell only hides commands; this enforces).

use hal::mgmtabi as m;

/// Serve `msg` for a caller holding `role` into `out`. Returns (result code, record length).
pub fn dispatch(msg: u16, role: u8, now_ms: u64, out: &mut [u8]) -> (u8, usize) {
    let need = m::role_for(msg);
    if need == u8::MAX {
        return (m::R_UNKNOWN, 0);
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
