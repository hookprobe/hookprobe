//! L-02 (operator 2026-11-17): the device answers mDNS for its own names, so `https://heqk.local` and the
//! unit-unique `https://<label>.heqk.local` (both in the Mission Control certificate) work whatever its addresses
//! are. Aligned with the legacy fortress's Avahi setup (survey 2026-11-17): IPv4 address records only, published
//! on the LAN side only (here: the Wi-Fi AP and the management VLAN, never the WAN), no services, no reflector.
//! The station-to-station discovery relay (`lanrelay`) is unchanged.
//!
//! Who gets an answer:
//! * on Wi-Fi, only while Mission Control is served to Wi-Fi (G12-M `serve_on_wifi`: the setup AP, or no management
//!   VLAN — the name must lead somewhere that answers): a station whose device policy lets it reach the device's own services (not `internet_only` /
//!   `quarantine` — legacy dropped mDNS for `internet_only` devices too);
//! * on the management VLAN: a host the `mgmt in` ACL lets in (the caller has applied it).
//!
//! Rate-limited (one window per second, shared), so the device can never be made to flood a network.
// the Wi-Fi entry point is called by the CM5 AP loop only (as apcore's AP paths)
#![cfg_attr(not(feature = "apmode"), allow(dead_code))]
use hal::mdns;

/// Answers per second, all interfaces together.
const RATE: u32 = 20;
static mut WIN: (u64, u32) = (0, 0);
/// (answered on Wi-Fi, answered on management, refused by device policy, rate-limited)
static mut COUNTS: [u64; 4] = [0; 4];
/// The unit-unique name, once derived: `<label>.heqk.local` (len 0 = not derivable on this build).
static mut UNIT: ([u8; 32], usize) = ([0; 32], usize::MAX);

/// `<label>.heqk.local`, the label being the setup SSID's 4-character suffix (lowercase) — the same name
/// provisioning puts in the certificate (`tools/provisioning`, `tls_default_names`).
fn unit_name() -> &'static [u8] {
    let u = unsafe { &mut *core::ptr::addr_of_mut!(UNIT) };
    if u.1 == usize::MAX {
        u.1 = 0;
        // the SRK exists only under HBoot (QEMU / non-hboot builds answer heqk.local alone)
        #[cfg(feature = "hboot")]
        if let Some(c) = crate::seal_srk().and_then(|k| crate::apcred::derive(&k)) {
            let lab = &c.ssid[c.ssid.len() - 4..];
            let n = lab.len();
            for (i, b) in lab.iter().enumerate() {
                u.0[i] = b.to_ascii_lowercase();
            }
            u.0[n..n + 11].copy_from_slice(b".heqk.local");
            u.1 = n + 11;
        }
    }
    let u: &'static ([u8; 32], usize) = unsafe { &*core::ptr::addr_of!(UNIT) };
    &u.0[..u.1]
}

fn rate_ok(now_s: u64) -> bool {
    let w = unsafe { &mut *core::ptr::addr_of_mut!(WIN) };
    if w.0 != now_s {
        *w = (now_s, 0);
    }
    if w.1 >= RATE {
        unsafe { COUNTS[3] += 1 };
        return false;
    }
    w.1 += 1;
    true
}

/// One mDNS query as received: source MAC, source IP, source port, UDP payload.
struct Query<'a> {
    sm: [u8; 6],
    si: [u8; 4],
    sp: u16,
    q: &'a [u8],
}

/// An mDNS query frame (Ethernet / IPv4 / UDP to 5353)?
fn query(frame: &[u8]) -> Option<Query<'_>> {
    if frame.len() < 42 || frame[12..14] != [0x08, 0x00] || frame[23] != 17 {
        return None;
    }
    let ihl = ((frame[14] & 0x0f) as usize) * 4;
    let u = 14 + ihl;
    if frame.len() < u + 8 || u16::from_be_bytes([frame[u + 2], frame[u + 3]]) != mdns::PORT {
        return None;
    }
    let mut sm = [0u8; 6];
    sm.copy_from_slice(&frame[6..12]);
    let si = [frame[26], frame[27], frame[28], frame[29]];
    let sp = u16::from_be_bytes([frame[u], frame[u + 1]]);
    let ul = (u16::from_be_bytes([frame[u + 4], frame[u + 5]]) as usize).min(frame.len() - u);
    Some(Query { sm, si, sp, q: frame.get(u + 8..u + ul.max(8))? })
}

/// One frame received on an interface whose address is `ip` (MAC `me`): the answer frame in `out`, if any.
fn respond(frame: &[u8], me: &[u8; 6], ip: [u8; 4], now_s: u64, wifi: bool, out: &mut [u8]) -> Option<usize> {
    let Query { sm, si, sp, q } = query(frame)?;
    if wifi && !crate::devpolicy::check(&sm, crate::devpolicy::Dest::DeviceMgmt) {
        // decide on the names first: only a question for US counts as refused
        let mut tmp = [0u8; 512];
        if mdns::answer(q, sp, &[b"heqk.local", unit_name()], ip, &mut tmp).is_some() {
            unsafe { COUNTS[2] += 1 };
        }
        return None;
    }
    let mut body = [0u8; 512];
    let names: [&[u8]; 2] = [b"heqk.local", unit_name()];
    let n_names = if names[1].is_empty() { 1 } else { 2 };
    let (n, dest) = mdns::answer(q, sp, &names[..n_names], ip, &mut body)?;
    if !rate_ok(now_s) {
        return None;
    }
    let (dmac, dip, dport) = match dest {
        mdns::Dest::Multicast => (mdns::GROUP4_MAC, mdns::GROUP4, mdns::PORT),
        mdns::Dest::Unicast => (sm, si, mdns::PORT),
        mdns::Dest::Legacy => (sm, si, sp),
    };
    let k = mdns::frame4(me, &dmac, ip, dip, mdns::PORT, dport, &body[..n], out)?;
    unsafe { COUNTS[if wifi { 0 } else { 1 }] += 1 };
    Some(k)
}

/// A Wi-Fi station's frame: answer if it asks for our names (the AP address `ip`, the BSSID `me`).
pub fn on_wifi(frame: &[u8], me: &[u8; 6], ip: [u8; 4], now_s: u64, out: &mut [u8]) -> Option<usize> {
    respond(frame, me, ip, now_s, true, out)
}

/// A management-VLAN frame that `mgmt in` let in: answer if it asks for our names (the management address).
pub fn on_mgmt(frame: &[u8], me: &[u8; 6], ip: [u8; 4], now_s: u64, out: &mut [u8]) -> Option<usize> {
    respond(frame, me, ip, now_s, false, out)
}

/// (answered on Wi-Fi, answered on management, refused by device policy, rate-limited)
pub fn counts() -> [u64; 4] {
    unsafe { COUNTS }
}

/// Seconds on the data path's counter (`cntpct_el0`) — the rate window; no driver clock needed.
pub fn now_s() -> u64 {
    let (v, f): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack));
    }
    v / f.max(1)
}
