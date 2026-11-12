//! Sealed-config / live apply step 10 — the Wi-Fi executor (the repo-root sealed-config / live-apply design, §3).
//!
//! A verified HQCFG1 bundle whose Wi-Fi section changed (SSID / passphrase / security mode / max_clients) is applied
//! in place, from the AP loop, after the HTTP reply:
//!
//! ```text
//! resolve: the bundle's wifi section (verified by cfgd) -> parse; absent -> WIFI.TXT -> the default, as boot does
//!          a section that does not parse                      refused -> false, the radio is NOT touched
//! derive FIRST: the PMK (PBKDF2 / the raw 64-hex PMK), a TRNG GTK, the SAE password element (WPA3 modes)
//!          any failure                                        refused -> false, the radio is NOT touched
//! bounce:  ap_stop -> forget every station's SAE state -> ap_set_security -> max_clients -> ap_start on the
//!          CURRENT chanspec (no new channel scan: reboot-only) -> ap_install_gtk
//!          not serve-ready / GTK refused                      false -> cfgd reverts LIVE (this executor, the LKG)
//! ```
//!
//! `max_clients` is set before `ap_start`: the firmware's `maxassoc` is applied inside the bring-up.
//! The AP address / LAN addressing, the WAN and eth1 are never touched. The firmware is NOT re-downloaded (`ap_stop` is
//! `WLC_DOWN`; `ap_start` re-configures the running image), so the REL-08 in-RAM PMKID correction stays in place.
//! A Wi-Fi change is a management-path change: cfgd already holds it for the owner's confirm (never auto-commits).
//! Secrets (passphrase, PMK, GTK scratch) are wiped with volatile writes after use and never logged; the new PMK reaches
//! the EL0 authenticator only through the existing per-handshake path (the AP loop's `pmk`).

use crate::wificfg::{WifiCfg, SEC_DEFAULT};

/// What the AP should run (resolved like the boot path; `security` is a `wificfg::SEC_*` other than `SEC_DEFAULT`).
#[derive(Clone, Copy)]
pub struct Want {
    pub ssid: [u8; 32],
    pub ssid_len: u8,
    /// WPA2 passphrase 8..63, or exactly 64 hex digits (a raw PMK).
    pub pass: [u8; 64],
    pub pass_len: u8,
    pub security: u8,
    pub max_clients: u8,
    /// The configured channel (0 = auto). Informational: a live bounce stays on the current chanspec.
    pub channel: u8,
    /// True = the per-device setup credential / the build env default (no Wi-Fi configuration at all).
    pub default: bool,
}

impl Want {
    pub fn from_cfg(c: &WifiCfg, sec_default: u8) -> Want {
        Want {
            ssid: c.ssid,
            ssid_len: c.ssid_len,
            pass: c.psk,
            pass_len: c.psk_len,
            security: if c.security == SEC_DEFAULT { sec_default } else { c.security },
            max_clients: c.max_clients,
            channel: c.channel,
            default: false,
        }
    }
    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len as usize]
    }
    pub fn pass(&self) -> &[u8] {
        &self.pass[..self.pass_len as usize]
    }
    pub fn wipe(&mut self) {
        hal::wpaauth::wipe(&mut self.pass);
        self.pass_len = 0;
    }
}

/// The new key material, derived before the radio is touched (wiped after use).
pub struct Keys {
    pub pmk: [u8; 32],
    pub gtk: [u8; 16],
}

impl Keys {
    pub const fn new() -> Keys {
        Keys { pmk: [0; 32], gtk: [0; 16] }
    }
    pub fn wipe(&mut self) {
        hal::wpaauth::wipe(&mut self.pmk);
        hal::wpaauth::wipe(&mut self.gtk);
    }
    #[cfg(not(feature = "cm5"))]
    fn is_zero(&self) -> bool {
        self.pmk == [0; 32] && self.gtk == [0; 16]
    }
}

/// Resolve what the AP should run, exactly as the boot chooses it: the bundle's wifi section (a section that does
/// not parse is REFUSED — never a silent fallback live), else the per-file WIFI.TXT (refused / absent -> the default),
/// else the default (the per-device setup credential or the build env). None = refused / nothing to run.
pub fn resolve(
    section: Option<&[u8]>,
    sec_default: u8,
    file: impl FnOnce() -> Option<Result<WifiCfg, crate::wificfg::CfgErr>>,
    default: impl FnOnce() -> Option<Want>,
) -> Option<Want> {
    let mut c = match section {
        Some(s) => crate::wificfg::parse(s).ok()?,
        None => match file() {
            Some(Ok(c)) => c,
            _ => return default(),
        },
    };
    let w = Want::from_cfg(&c, sec_default);
    hal::wpaauth::wipe(&mut c.psk);
    Some(w)
}

/// The radio side (cyw43 on metal; a mock in [P-cfgd-wifi]).
pub trait WifiPort {
    /// The PMK: PBKDF2(passphrase, SSID), or the raw 64-hex PMK. False = cannot derive.
    fn pmk(&mut self, pass: &[u8], ssid: &[u8], out: &mut [u8; 32]) -> bool;
    /// 16 bytes from the hardware TRNG (strict). False = the TRNG refused.
    fn gtk(&mut self, out: &mut [u8; 16]) -> bool;
    /// Prepare the security mode (WPA3: the SAE password element) without touching the radio; the mode it will run
    /// (a raw PMK cannot do SAE: WPA2). None = cannot derive.
    fn prepare_security(&mut self, mode: u8, ssid: &[u8], pass: &[u8]) -> Option<u8>;
    /// Take the BSS down (`WLC_DOWN`).
    fn stop(&mut self) -> bool;
    /// Forget every station's host-side SAE state (and the firmware's PMKSA).
    fn forget_stations(&mut self);
    /// Install the prepared security mode.
    fn install_security(&mut self, ssid: &[u8], pass: &[u8]);
    fn set_max_clients(&mut self, n: u8);
    /// Bring the BSS up on `chanspec`; true = serve-ready.
    fn start(&mut self, ssid: &[u8], chanspec: u16) -> bool;
    fn install_gtk(&mut self, gtk: &[u8; 16]) -> bool;
}

/// Apply `want` (None = refused upstream: nothing is touched). On success the AP loop's `pmk` / `gtk` are replaced;
/// `want`'s passphrase and `scratch` are wiped either way. Returns (applied, the mode now running when bounced).
pub fn apply<P: WifiPort>(port: &mut P, want: &mut Option<Want>, chanspec: u16, pmk: &mut [u8; 32], gtk: &mut [u8; 16], scratch: &mut Keys) -> (bool, Option<u8>) {
    let Some(w) = want.as_mut() else { return (false, None) };
    let r = bounce(port, w, chanspec, pmk, gtk, scratch);
    w.wipe();
    scratch.wipe();
    r
}

fn bounce<P: WifiPort>(port: &mut P, w: &Want, chanspec: u16, pmk: &mut [u8; 32], gtk: &mut [u8; 16], k: &mut Keys) -> (bool, Option<u8>) {
    // everything that can fail, BEFORE the radio is touched
    if w.ssid_len == 0 || w.pass_len < 8 || chanspec == 0 || !port.pmk(w.pass(), w.ssid(), &mut k.pmk) || !port.gtk(&mut k.gtk) {
        return (false, None);
    }
    let Some(mode) = port.prepare_security(w.security, w.ssid(), w.pass()) else { return (false, None) };
    // the bounce: stations drop and re-join with the new settings
    let _ = port.stop();
    port.forget_stations();
    port.install_security(w.ssid(), w.pass());
    port.set_max_clients(w.max_clients);
    let ready = port.start(w.ssid(), chanspec);
    let keyed = ready && port.install_gtk(&k.gtk);
    if !keyed {
        if ready {
            let _ = port.stop(); // a BSS that cannot key clients must not keep beaconing
        }
        return (false, Some(mode));
    }
    pmk.copy_from_slice(&k.pmk);
    gtk.copy_from_slice(&k.gtk);
    (true, Some(mode))
}

/// The PMK as the boot derives it: a 64-hex PSK is the PMK itself (WPA2), else PBKDF2(passphrase, SSID).
#[cfg_attr(not(all(feature = "cm5", feature = "p15-write")), allow(dead_code))]
pub fn derive_pmk(pass: &[u8], ssid: &[u8], out: &mut [u8; 32]) -> bool {
    if pass.len() == 64 {
        for (i, b) in out.iter_mut().enumerate() {
            let h = |c: u8| (c as char).to_digit(16);
            match (h(pass[2 * i]), h(pass[2 * i + 1])) {
                (Some(a), Some(c)) => *b = (a << 4 | c) as u8,
                _ => return false,
            }
        }
        return true;
    }
    if !(8..=63).contains(&pass.len()) || ssid.is_empty() {
        return false;
    }
    *out = hal::wpa::wpa_pmk(pass, ssid);
    true
}

// ---- [P-cfgd-wifi] ------------------------------------------------------------------------------------------

#[cfg(not(feature = "cm5"))]
struct Mock {
    /// call log: p(mk) g(tk) y(prepare) s(top) f(orget) e(security) m(ax) u(p) k(gtk)
    log: [u8; 12],
    n: usize,
    pmk_ok: bool,
    sae_ok: bool,
    ready: bool,
    gtk_ok: bool,
    /// the "radio": (ssid, ssid_len, security, max_clients, chanspec, gtk, up)
    ssid: [u8; 32],
    ssid_len: usize,
    sec: u8,
    pending: u8,
    maxc: u8,
    cs: u16,
    gtk: [u8; 16],
    up: bool,
    forgot: bool,
}
#[cfg(not(feature = "cm5"))]
impl Mock {
    fn new() -> Mock {
        Mock { log: [0; 12], n: 0, pmk_ok: true, sae_ok: true, ready: true, gtk_ok: true, ssid: [0; 32], ssid_len: 0, sec: 0, pending: 0, maxc: 0, cs: 0, gtk: [0; 16], up: true, forgot: false }
    }
    fn note(&mut self, c: u8) {
        if self.n < self.log.len() {
            self.log[self.n] = c;
            self.n += 1;
        }
    }
    fn calls(&self) -> &[u8] {
        &self.log[..self.n]
    }
    fn radio(&self) -> usize {
        self.calls().iter().filter(|c| !matches!(c, b'p' | b'g' | b'y')).count()
    }
}
#[cfg(not(feature = "cm5"))]
impl WifiPort for Mock {
    fn pmk(&mut self, pass: &[u8], ssid: &[u8], out: &mut [u8; 32]) -> bool {
        self.note(b'p');
        // the real derivation for a raw PMK; a cheap stand-in for PBKDF2 (4096 rounds is metal's job)
        if pass.len() == 64 {
            return self.pmk_ok && derive_pmk(pass, ssid, out);
        }
        for (i, b) in out.iter_mut().enumerate() {
            *b = pass[i % pass.len()] ^ ssid[i % ssid.len()] ^ 0x5a;
        }
        self.pmk_ok
    }
    fn gtk(&mut self, out: &mut [u8; 16]) -> bool {
        self.note(b'g');
        *out = [0xa7; 16];
        true
    }
    fn prepare_security(&mut self, mode: u8, _ssid: &[u8], pass: &[u8]) -> Option<u8> {
        self.note(b'y');
        if !self.sae_ok {
            return None;
        }
        self.pending = if pass.len() == 64 { crate::wificfg::SEC_WPA2 } else { mode };
        Some(self.pending)
    }
    fn stop(&mut self) -> bool {
        self.note(b's');
        self.up = false;
        true
    }
    fn forget_stations(&mut self) {
        self.note(b'f');
        self.forgot = true;
    }
    fn install_security(&mut self, ssid: &[u8], _pass: &[u8]) {
        self.note(b'e');
        self.sec = self.pending;
        self.ssid[..ssid.len()].copy_from_slice(ssid);
        self.ssid_len = ssid.len();
    }
    fn set_max_clients(&mut self, n: u8) {
        self.note(b'm');
        self.maxc = n;
    }
    fn start(&mut self, _ssid: &[u8], chanspec: u16) -> bool {
        self.note(b'u');
        self.cs = chanspec;
        self.up = self.ready;
        self.ready
    }
    fn install_gtk(&mut self, gtk: &[u8; 16]) -> bool {
        self.note(b'k');
        self.gtk = *gtk;
        self.gtk_ok
    }
}

/// [P-cfgd-wifi] (step 10): the pure half of the Wi-Fi executor (QEMU has no CYW43455; metal proves the bounce).
#[cfg(not(feature = "cm5"))]
pub fn selftest() -> bool {
    use crate::wificfg::{SEC_WPA2, SEC_WPA3, SEC_WPA3_TRANSITION};
    const CS: u16 = 0xe12a; // ch 40, 80 MHz (the boot's ACS choice: the "current" chanspec)
    let no_file = || None;
    let no_default = || None;
    let mut pmk = [0x11u8; 32];
    let mut gtk = [0x22u8; 16];
    let mut k = Keys::new();
    // 1. a Wi-Fi section that does not parse is refused: nothing derived, zero radio calls, the loop's keys kept
    let mut m = Mock::new();
    let mut w = resolve(Some(b"ssid=x\npsk=short\n"), SEC_WPA3_TRANSITION, no_file, no_default);
    let (ok, mo) = apply(&mut m, &mut w, CS, &mut pmk, &mut gtk, &mut k);
    let refused = w.is_none() && !ok && mo.is_none() && m.n == 0 && m.up && pmk == [0x11; 32] && gtk == [0x22; 16];
    // 2. the PMK (or the SAE element) cannot be derived -> refused BEFORE ap_stop: the BSS keeps beaconing
    let good: &[u8] = b"ssid=Home Network\npsk=correct horse battery\nsecurity=wpa3\nmax_clients=12\n";
    let mut m2 = Mock::new();
    m2.pmk_ok = false;
    let mut w2 = resolve(Some(good), SEC_WPA3_TRANSITION, no_file, no_default);
    let (ok2, _) = apply(&mut m2, &mut w2, CS, &mut pmk, &mut gtk, &mut k);
    let mut m2b = Mock::new();
    m2b.sae_ok = false;
    let mut w2b = resolve(Some(good), SEC_WPA3_TRANSITION, no_file, no_default);
    let (ok2b, _) = apply(&mut m2b, &mut w2b, CS, &mut pmk, &mut gtk, &mut k);
    let pre = !ok2 && m2.radio() == 0 && m2.up && !ok2b && m2b.radio() == 0 && m2b.up && pmk == [0x11; 32] && gtk == [0x22; 16];
    // 3. a good change: derive (pmk, gtk, SAE) -> stop -> forget -> security -> max_clients -> start on the SAME
    //    chanspec -> gtk; the loop's PMK / GTK replaced; the passphrase and the scratch keys wiped afterwards
    let mut m3 = Mock::new();
    let mut w3 = resolve(Some(good), SEC_WPA3_TRANSITION, no_file, no_default);
    let (ok3, mo3) = apply(&mut m3, &mut w3, CS, &mut pmk, &mut gtk, &mut k);
    let mut exp = [0u8; 32];
    for (i, b) in exp.iter_mut().enumerate() {
        *b = b"correct horse battery"[i % 21] ^ b"Home Network"[i % 12] ^ 0x5a;
    }
    let order = ok3 && mo3 == Some(SEC_WPA3) && m3.calls() == b"pgysfemuk" && m3.cs == CS && m3.up && m3.forgot
        && &m3.ssid[..m3.ssid_len] == b"Home Network" && m3.sec == SEC_WPA3 && m3.maxc == 12 && m3.gtk == [0xa7; 16]
        && pmk == exp && gtk == [0xa7; 16];
    let wiped = k.is_zero() && w3.is_some_and(|x| x.pass == [0; 64] && x.pass_len == 0);
    // 4. the BSS comes up but is not serve-ready (or the GTK is refused) -> false: cfgd reverts live; the loop's
    //    keys are not replaced by keys no BSS runs
    let (p0, g0) = (pmk, gtk);
    let other: &[u8] = b"ssid=Other\npsk=another passphrase\n";
    let mut m4 = Mock::new();
    m4.ready = false;
    let mut w4 = resolve(Some(other), SEC_WPA2, no_file, no_default);
    let (ok4, _) = apply(&mut m4, &mut w4, CS, &mut pmk, &mut gtk, &mut k);
    let mut m4b = Mock::new();
    m4b.gtk_ok = false;
    let mut w4b = resolve(Some(other), SEC_WPA2, no_file, no_default);
    let (ok4b, _) = apply(&mut m4b, &mut w4b, CS, &mut pmk, &mut gtk, &mut k);
    let notready = !ok4 && m4.calls() == b"pgysfemu" && !ok4b && m4b.calls() == b"pgysfemuks" && !m4b.up
        && pmk == p0 && gtk == g0 && k.is_zero() && w4.is_some_and(|x| x.pass_len == 0);
    // 5. the live revert: the last-known-good is resolved as boot resolves it — no section -> the per-file WIFI.TXT,
    //    a refused / absent WIFI.TXT -> the default credential — and re-applied by the same bounce
    let file_cfg = crate::wificfg::parse(b"ssid=Before\npsk=the old passphrase\nsecurity=wpa2\n");
    let mut m5 = Mock::new();
    let mut w5 = resolve(None, SEC_WPA3_TRANSITION, || Some(file_cfg), no_default);
    let (ok5, mo5) = apply(&mut m5, &mut w5, CS, &mut pmk, &mut gtk, &mut k);
    let lkg_file = ok5 && mo5 == Some(SEC_WPA2) && &m5.ssid[..m5.ssid_len] == b"Before" && m5.calls() == b"pgysfemuk";
    let dflt = || {
        let mut d = Want { ssid: [0; 32], ssid_len: 8, pass: [0; 64], pass_len: 20, security: SEC_WPA3_TRANSITION, max_clients: 0, channel: 0, default: true };
        d.ssid[..8].copy_from_slice(b"heqk-a1b");
        d.pass[..20].copy_from_slice(b"setup-cred-passphras");
        Some(d)
    };
    let mut m6 = Mock::new();
    let mut w6 = resolve(None, SEC_WPA3_TRANSITION, || Some(Err(crate::wificfg::CfgErr::BadPsk)), dflt);
    let (ok6, mo6) = apply(&mut m6, &mut w6, CS, &mut pmk, &mut gtk, &mut k);
    let lkg_default = ok6 && mo6 == Some(SEC_WPA3_TRANSITION) && &m6.ssid[..m6.ssid_len] == b"heqk-a1b" && m6.maxc == 0
        && w6.is_some_and(|x| x.default && x.pass_len == 0);
    // a security= default resolves to the build's default; a raw 64-hex PMK runs WPA2 (no SAE) and is the PMK itself
    let hexp: &[u8] = b"ssid=x\npsk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    let mut m7 = Mock::new();
    let mut w7 = resolve(Some(hexp), SEC_WPA2, no_file, no_default);
    let (ok7, mo7) = apply(&mut m7, &mut w7, CS, &mut pmk, &mut gtk, &mut k);
    let raw = ok7 && mo7 == Some(SEC_WPA2) && pmk[0] == 0x01 && pmk[31] == 0xef;
    let revert = lkg_file && lkg_default && raw;
    // 6. the LIVE_CAPABLE gate: policy, WAN and Wi-Fi all apply live now (a Wi-Fi change still waits for the owner)
    let gate = crate::cfgd::LIVE_CAPABLE == crate::cfgd::CH_POLICY | crate::cfgd::CH_WAN | crate::cfgd::CH_WIFI;
    hal::wpaauth::wipe(&mut pmk);
    hal::wpaauth::wipe(&mut gtk);
    let pass = refused && pre && order && wiped && notready && revert && gate;
    arch_aarch64::_print(format_args!(
        " [P-cfgd-wifi] {} — sealed-config / live-apply step 10, the Wi-Fi executor: a Wi-Fi section that does not parse is refused with zero radio calls={} a PMK / SAE derivation failure is refused before ap_stop={} derive -> stop -> forget -> security -> max_clients -> start on the same chanspec -> GTK, the loop's PMK / GTK replaced={} passphrase + scratch keys zeroed afterwards={} not serve-ready / GTK refused -> false, the loop's keys kept={} the live revert re-applies the last-known-good (WIFI.TXT, the default credential, a raw PMK as WPA2)={} policy, WAN and Wi-Fi bundles apply live={}\n",
        if pass { "PASS" } else { "FAIL" }, refused, pre, order, wiped, notready, revert, gate
    ));
    pass
}

/// [P-cfgd-wifi-after] (live-apply follow-up): what must follow a live Wi-Fi bounce — where Mission Control is served
/// (re-evaluated from what runs NOW, never the boot decision) and the per-station IPv6 state of the bounced BSS.
#[cfg(not(feature = "cm5"))]
pub fn after_selftest() -> bool {
    use arch_aarch64::ip6lan::V6Lan;
    use crate::mcmgmt::serve_on_wifi;
    // 1. G12-M re-evaluated: boot = client AP + management VLAN -> management only; a live revert to the setup
    //    credential -> Wi-Fi again (onboarding); a live WAN change removing the management sub-interface -> Wi-Fi again;
    //    one adding it on a client AP -> management only
    let boot = !serve_on_wifi(false, true);
    let to_setup = serve_on_wifi(true, true);
    let mgmt_removed = serve_on_wifi(false, false);
    let mgmt_added = !serve_on_wifi(false, true) && serve_on_wifi(true, false);
    let mc = boot && to_setup && mgmt_removed && mgmt_added;
    // 2. IPv6 at an AP restart: a station's SAVI binding (first-come) refuses another MAC its address; after the
    //    bounce every binding is gone (a station re-joining with a new private MAC gets its address), the LAN
    //    numbering is kept and the RA burst restarts at once
    static mut V: V6Lan = V6Lan::new();
    let v = unsafe { &mut *core::ptr::addr_of_mut!(V) };
    *v = V6Lan::new();
    let mut pd = [0u8; 16];
    pd[..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x10]);
    v.configure(&pd, 56, 86_400, &[2, 0xa9, 0, 0, 0, 1], None);
    let (sta, other) = ([2u8, 0x51, 0, 0, 0, 7], [2u8, 0x51, 0, 0, 0, 8]);
    let mut ll = [0u8; 16];
    ll[..2].copy_from_slice(&[0xfe, 0x80]);
    ll[8..].copy_from_slice(&[0, 0x51, 0, 0xff, 0xfe, 0, 0, 7]);
    let frame = |mac: &[u8; 6], f: &mut [u8; 64]| {
        *f = [0; 64];
        f[..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 1]);
        f[6..12].copy_from_slice(mac);
        f[12..14].copy_from_slice(&[0x86, 0xdd]);
        f[14] = 0x60;
        f[19] = 8; // payload length
        f[20] = 17;
        f[21] = 255;
        f[22..38].copy_from_slice(&ll);
        f[38..54].copy_from_slice(&[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    };
    let mut f = [0u8; 64];
    let mut out = [0u8; 200];
    frame(&sta, &mut f);
    let _ = v.on_lan(&f[..62], 1_000, &mut out);
    let bound = v.mac_of(&ll) == Some(sta);
    frame(&other, &mut f);
    let _ = v.on_lan(&f[..62], 1_100, &mut out);
    let savi = v.stats.savi_refused == 1 && v.mac_of(&ll) == Some(sta);
    let _ = v.ra_due(1_200);
    let quiet = !v.ra_due(1_300);
    v.forget_all_stations();
    let cleared = v.mac_of(&ll).is_none() && v.up && v.prefix[..8] == pd[..8] && v.ra_due(1_400);
    let _ = v.on_lan(&f[..62], 1_500, &mut out);
    let rejoin = v.stats.savi_refused == 1 && v.mac_of(&ll) == Some(other);
    let v6 = bound && savi && quiet && cleared && rejoin;
    let pass = mc && v6;
    arch_aarch64::_print(format_args!(
        " [P-cfgd-wifi-after] {} — live-apply follow-up, after a live Wi-Fi / WAN apply: where Mission Control is served is re-evaluated from what runs now (client AP + management VLAN -> management only; back to the setup credential or the management VLAN removed -> Wi-Fi again)={} IPv6 at an AP restart: the bounce clears every station's SAVI binding / neighbour entry / pinhole (a station re-joining with a new MAC gets its address), the LAN numbering is kept, the RA burst restarts={}\n",
        if pass { "PASS" } else { "FAIL" }, mc, v6
    ));
    pass
}
