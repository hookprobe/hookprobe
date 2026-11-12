//! Sealed-config / live apply step 9 — the WAN executor (the repo-root sealed-config / live-apply design, §3).
//!
//! A verified HQCFG1 bundle whose WAN section changed is applied in place, from the AP loop, after the HTTP reply:
//!
//! ```text
//! verify + parse FIRST (mode + link keys)        refused -> false, NOTHING touched (the WAN in force stays up)
//! teardown: PPPoE PADT, PPP / DORA / RENEW / WAN6 state, the MSS default, nat::flush_wan(old WAN address)
//! link: internet VLAN tags; the management sub-interface / floor ONLY when they change (-> owner confirm)
//! start: DHCP / static in the loop (non-blocking), PPPoE the bounded dial (blocking, watchdog-petted)
//! PPPoE authentication rejected (Q5)              -> false at once: cfgd reverts live without waiting out the window
//! ```
//!
//! cfgd's trial then commits on `up.usable()` or reverts live (this executor re-runs with the last-known-good).
//! The Wi-Fi AP and eth1 are never touched: Mission Control on the AP stays reachable throughout (rule 7).

/// The hardware side (the metal `uplink`; a mock in [P-cfgd-wan]).
pub trait WanPort {
    /// PADT an open PPPoE session; reset the PPP / DORA / RENEW / WAN6 / next-hop state; the old WAN address (0 = none).
    fn teardown(&mut self) -> [u8; 4];
    /// Internet sub-interface tags (and the management VLAN id, from `l.mgmt`).
    fn link(&mut self, l: &hal::WanLink);
    /// The management sub-interface in force.
    fn mgmt(&self) -> Option<hal::MgmtIf>;
    fn set_mgmt(&mut self, m: Option<hal::MgmtIf>);
    /// Start the WAN in `mode`; true when a PPPoE dial ended on a definitive authentication failure.
    fn start(&mut self, mode: &hal::WanMode) -> bool;
}

/// Parse a verified WAN body (`HQWAN1` …; None = no WAN configuration at all: DHCP, untagged). None = refused.
pub fn parse(body: Option<&[u8]>) -> Option<(hal::WanMode, hal::WanLink)> {
    match body {
        None => Some((hal::WanMode::Dhcp, hal::WanLink::default())),
        Some(b) => Some((hal::parse_wan_cfg(b).ok()?, hal::parse_wan_link(b).ok()?)),
    }
}

/// The management floor a link asks for (as at boot: `mgmt_floor=`, else the static management subnet).
fn floor_of(l: &hal::WanLink) -> Option<([u8; 4], u8)> {
    l.floor.or_else(|| l.mgmt.and_then(|mg| mg.stat.map(|(ip, pl, _)| (ip, pl))))
}

/// Apply a parsed configuration (`cfg` None = it did not verify / parse: nothing is touched). Returns
/// (applied, the WAN mode now in force when the WAN was re-brought up).
pub fn apply<P: WanPort>(port: &mut P, cfg: Option<(hal::WanMode, hal::WanLink)>) -> (bool, Option<hal::WanMode>) {
    let Some((mode, l)) = cfg else { return (false, None) };
    let old = port.teardown();
    arch_aarch64::nat::flush_wan(old);
    arch_aarch64::nat::set_mss_limit(0); // PPPoE sets its 1452 again when it opens
    let cur = port.mgmt();
    port.link(&l);
    // the management plane changes only when its keys do — and then never auto-commits (owner confirm)
    let mut mgmt_changed = false;
    if l.mgmt != cur {
        port.set_mgmt(l.mgmt);
        mgmt_changed = true;
    }
    let (fnet, flen, fset) = crate::verdict::mgmt_floor();
    match floor_of(&l) {
        Some((ip, pl)) => {
            let mask = if pl >= 32 { u32::MAX } else { u32::MAX << (32 - pl as u32) };
            if !fset || flen != pl as u32 || fnet != u32::from_be_bytes(ip) & mask {
                mgmt_changed |= crate::verdict::set_mgmt_floor(u32::from_be_bytes(ip), pl as u32);
            }
        }
        None if fset => {
            crate::verdict::reset_mgmt_floor();
            mgmt_changed = true;
        }
        None => {}
    }
    if mgmt_changed {
        crate::cfgd::require_confirm();
    }
    let rejected = port.start(&mode);
    (!rejected, Some(mode))
}

// ---- [P-cfgd-wan] -------------------------------------------------------------------------------------------

#[cfg(not(feature = "cm5"))]
struct Mock {
    /// call log: t(eardown) l(ink) m(gmt) s(tart)
    log: [u8; 8],
    n: usize,
    mgmt: Option<hal::MgmtIf>,
    /// the "uplink" state teardown resets: (PPPoE session id, DORA state, WAN6 ran, WAN address held)
    st: (u16, u8, bool, [u8; 4]),
    vlan: u16,
    /// how a PPPoE dial ends (the real engine classifies it)
    ppp_why: arch_aarch64::pppoe::DownWhy,
}
#[cfg(not(feature = "cm5"))]
impl Mock {
    fn note(&mut self, c: u8) {
        if self.n < 8 {
            self.log[self.n] = c;
            self.n += 1;
        }
    }
}
#[cfg(not(feature = "cm5"))]
impl WanPort for Mock {
    fn teardown(&mut self) -> [u8; 4] {
        self.note(b't');
        let old = self.st.3;
        self.st = (0, 0, false, [0; 4]);
        old
    }
    fn link(&mut self, l: &hal::WanLink) {
        self.note(b'l');
        self.vlan = l.vlan;
    }
    fn mgmt(&self) -> Option<hal::MgmtIf> {
        self.mgmt
    }
    fn set_mgmt(&mut self, m: Option<hal::MgmtIf>) {
        self.note(b'm');
        self.mgmt = m;
    }
    fn start(&mut self, mode: &hal::WanMode) -> bool {
        self.note(b's');
        let hal::WanMode::Pppoe { user, user_len, pass, pass_len } = *mode else { return false };
        let mut e = arch_aarch64::pppoe::Pppoe::new([2, 0, 0, 0, 0, 2], &user[..user_len as usize], &pass[..pass_len as usize], 1, 2);
        e.phase = arch_aarch64::pppoe::Phase::Down;
        e.why = self.ppp_why;
        e.auth_failed()
    }
}

/// [P-cfgd-wan] (step 9): the pure half of the WAN executor (QEMU has no GEM WAN; metal proves the bring-ups).
#[cfg(not(feature = "cm5"))]
pub fn selftest() -> bool {
    use arch_aarch64::pppoe::{DownWhy, Pppoe, Tx};
    let live = || Mock { log: [0; 8], n: 0, mgmt: None, st: (0x1234, 3, true, [192, 0, 2, 77]), vlan: 0, ppp_why: DownWhy::None };
    let saved_floor = crate::verdict::mgmt_floor();
    crate::verdict::reset_mgmt_floor();
    // 1. verify / parse first: a body that does not parse is refused and NOTHING is touched (no teardown, link, start)
    let mut m = live();
    arch_aarch64::nat::set_mss_limit(1452);
    let bad = parse(Some(b"HQWAN1\nmode=static\nip=10.0.0.5/31\ngw=10.0.0.4\n"));
    let (ok, mo) = apply(&mut m, bad);
    let refused = bad.is_none() && !ok && mo.is_none() && m.n == 0 && m.st == (0x1234, 3, true, [192, 0, 2, 77])
        && arch_aarch64::nat::mss_limit() == 1452
        && parse(Some(b"HQWAN1\nmode=dhcp\nvlan=5000\n")).is_none() && parse(None) == Some((hal::WanMode::Dhcp, hal::WanLink::default()));
    // 2. a good static bundle: teardown -> link -> start, the WAN state reset, the MSS back to the default, the new mode
    let st = parse(Some(b"HQWAN1\nmode=static\nip=192.0.2.9/24\ngw=192.0.2.1\nvlan=7\n"));
    let (ok2, mo2) = apply(&mut m, st);
    let order = ok2 && mo2.is_some_and(|x| matches!(x, hal::WanMode::Static { .. })) && &m.log[..m.n] == b"tls"
        && m.st == (0, 0, false, [0; 4]) && m.vlan == 7 && arch_aarch64::nat::mss_limit() == 0
        && !crate::verdict::mgmt_floor().2;
    // the real PADT the metal teardown sends for an open session: PPPoE discovery, code 0xa7, the session id
    let mut eng = Pppoe::new([2, 0, 0, 0, 0, 2], b"u", b"p", 1, 2);
    eng.sid = 0x1234;
    eng.ac_mac = [2, 0xac, 0, 0, 0, 1];
    let mut tx = Tx::new();
    eng.padt(&mut tx);
    let f = tx.frame(0);
    let padt = tx.n == 1 && f[0..6] == [2, 0xac, 0, 0, 0, 1] && f[12..14] == [0x88, 0x63] && f[15] == 0xa7 && f[16..18] == [0x12, 0x34];
    // 3. NAT: only the old WAN address's mappings are flushed
    let nat = arch_aarch64::nat::flush_wan_selftest();
    // 4. Q5: a PPPoE dial whose authentication is rejected -> false at once (cfgd reverts live, early); a dial that
    //    only timed out (no PADO) is not definitive — the trial window and the in-loop retry decide
    let ppp = parse(Some(b"HQWAN1\nmode=pppoe\npppoe_user=u@isp\npppoe_pass=wrong\n"));
    let mut m4 = live();
    m4.ppp_why = DownWhy::AuthRejected;
    let (ok4, mo4) = apply(&mut m4, ppp);
    let mut m4b = live();
    m4b.ppp_why = DownWhy::NoPado;
    let (ok4b, _) = apply(&mut m4b, ppp);
    let reject = !ok4 && mo4.is_some_and(|x| matches!(x, hal::WanMode::Pppoe { .. })) && ok4b;
    // 5. the management sub-interface is re-configured only when its keys change (and then needs the owner's confirm)
    let mut m5 = live();
    let mg = hal::MgmtIf { vlan: 200, stat: Some(([10, 20, 0, 2], 24, [10, 20, 0, 1])) };
    m5.mgmt = Some(mg);
    let (ok5, _) = apply(&mut m5, parse(Some(b"HQWAN1\nmode=dhcp\nmgmt_vlan=200\nmgmt=static\nmgmt_ip=10.20.0.2/24\nmgmt_gw=10.20.0.1\n")));
    let same = ok5 && &m5.log[..m5.n] == b"tls";
    let mut m6 = live();
    m6.mgmt = Some(mg);
    let (ok6, _) = apply(&mut m6, parse(Some(b"HQWAN1\nmode=dhcp\n")));
    let changed = ok6 && &m6.log[..m6.n] == b"tlms" && m6.mgmt.is_none();
    // 6. the LIVE_CAPABLE gate: a WAN bundle is applied live (and, since step 10, a Wi-Fi section too)
    let gate = crate::cfgd::CH_WAN & !crate::cfgd::LIVE_CAPABLE == 0 && crate::cfgd::CH_WIFI & !crate::cfgd::LIVE_CAPABLE == 0;
    let (fnet, flen, fset) = saved_floor;
    crate::verdict::reset_mgmt_floor();
    if fset {
        let _ = crate::verdict::set_mgmt_floor(fnet, flen);
    }
    arch_aarch64::nat::set_mss_limit(0);
    let pass = refused && order && padt && nat && reject && same && changed && gate;
    arch_aarch64::_print(format_args!(
        " [P-cfgd-wan] {} — sealed-config / live-apply step 9, the WAN executor: a WAN that does not verify / parse is refused and nothing is touched={} teardown -> link -> start, the PPP / DORA / WAN6 state reset and the MSS default restored={} the PADT for an open PPPoE session={} the NAT flush removes only the old WAN address's mappings={} a rejected PPPoE password fails the apply at once (live revert, no window)={} the management sub-interface is re-configured only when its keys change={} WAN (and Wi-Fi) bundles apply live={}\n",
        if pass { "PASS" } else { "FAIL" }, refused, order, padt, nat, reject, same && changed, gate
    ));
    pass
}
