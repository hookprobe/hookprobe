//! A-01 (operator decision 2026-11-17): Wi-Fi / LAN clients are refused **upstream private networks** (RFC 1918,
//! 169.254/16, IPv6 ULA) unless an exception covers them. Every refusal is attributed (device, destination, port,
//! count, first / last seen) so Mission Control can explain it and offer the exception (`GET /api/lan-access`).
//!
//! Exceptions come from the owner (owner journal, `kind=lan_access`, scoped + expiring) or from the signed POLICY:
//! an explicit `allow` entry of the ACL on the LAN interface, or a specific (non-default) route to the destination. Guardrails that no exception can lift:
//! * the management network (the management gateway, and the management address's /24) is never opened;
//! * a device whose own policy refuses the LAN (`internet_only`, `quarantine`) is not opened by an exception.
//!
//! DNS (port 53) is not this module's business: Shield answers / redirects every client DNS query.
// the API readers live in Mission Control (mcserve) and the selftest runs in the QEMU validation build only
#![cfg_attr(not(feature = "mcserve"), allow(dead_code))]
use hal::lanaccess::{upstream_private, Blocks, Table};
use hal::policy::Addr;

static mut TABLE: Table = Table::new();
static mut BLOCKS: Blocks = Blocks::new();
/// (refused, allowed by an owner exception, allowed by a POLICY ACL entry, exception refused by a guardrail)
static mut COUNTS: [u64; 4] = [0; 4];

/// The decision for one client packet to an upstream address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not an upstream private destination: not A-01's business.
    NotPrivate,
    /// Allowed by an exception (owner) or an explicit POLICY ACL `allow`.
    Excepted,
    /// Refused (the caller answers the client at once and drops the frame).
    Refused,
}

/// Is `dst` on the management network (never exceptable)?
fn on_mgmt(dst: &Addr, mgmt: Option<([u8; 4], [u8; 4])>) -> bool {
    match mgmt {
        Some((ip, gw)) if !dst.v6 => {
            let d = [dst.a[0], dst.a[1], dst.a[2], dst.a[3]];
            d == gw || d == ip || d[..3] == ip[..3]
        }
        _ => false,
    }
}

/// The management (address, gateway) the data path last reported — for the owner-exception guardrail.
static mut MGMT_SEEN: Option<([u8; 4], [u8; 4])> = None;

/// Why an owner exception for `dst` must be refused (None = acceptable): not upstream private, too broad, or the
/// management network / the device's own addresses.
pub fn exception_refusal(dst: &hal::policy::Prefix, any_device: bool) -> Option<&'static str> {
    if !upstream_private(&dst.addr) {
        return Some("value: only upstream private networks (RFC 1918, 169.254/16, IPv6 ULA) need an exception");
    }
    let floor = match (dst.addr.v6, any_device) {
        (false, false) => 8,
        (false, true) => 16,
        (true, false) => 32,
        (true, true) => 48,
    };
    if dst.len < floor {
        return Some("value: prefix too broad (any device: /16 or narrower; one device: /8 or narrower; IPv6 /48 or /32)");
    }
    if !dst.addr.v6 {
        let a = [dst.addr.a[0], dst.addr.a[1], dst.addr.a[2], dst.addr.a[3]];
        if let Some((ip, gw)) = unsafe { MGMT_SEEN } {
            let p = |x: [u8; 4]| dst.contains(&Addr::v4(x));
            if p(ip) || p(gw) || on_mgmt(&dst.addr, Some((ip, gw))) {
                return Some("value: the management network is never opened to Wi-Fi clients");
            }
        }
        if crate::ratelimit::prefix_has_local_ip(u32::from_be_bytes(a), dst.len) {
            return Some("value: the device's own addresses are not reached through an exception");
        }
    }
    None
}

/// A temporary owner grant (RAM only — a reboot ends it): in force for `dur_s` seconds from now. Resolves the
/// attributed blocks it covers.
pub fn grant_temporary(mut x: hal::lanaccess::Exception, dur_s: u32) -> bool {
    let now = now_ms();
    x.expires_ms = now + dur_s as u64 * 1000;
    let ok = table().add(x);
    if ok {
        unsafe { (*core::ptr::addr_of_mut!(BLOCKS)).resolve(&x, now) };
    }
    ok
}

/// R4 (code review 2026-11-18): can one more exception of this scope be held? Expired temporary grants are dropped
/// first (they used to occupy slots until someone opened `/api/lan-access`).
pub fn can_add(x: &hal::lanaccess::Exception) -> bool {
    let t = table();
    t.prune(now_ms());
    t.has_room(x)
}

/// An always-grant was journaled (the journal applied it): forget the blocks it covers.
pub fn resolve_blocks(x: &hal::lanaccess::Exception) {
    unsafe { (*core::ptr::addr_of_mut!(BLOCKS)).resolve(x, now_ms()) };
}

/// One client packet from `mac` (`src`) to `dst`:`dport`/`proto`. `acl_allow` = an explicit `allow` entry of the
/// POLICY ACL on the client's interface matched (not the ACL's default). `mgmt` = (management address, gateway).
#[allow(clippy::too_many_arguments)]
pub fn check(mac: &[u8; 6], src: Addr, dst: Addr, dport: u16, proto: u8, acl_allow: bool, mgmt: Option<([u8; 4], [u8; 4])>, now_ms: u64) -> Verdict {
    if mgmt.is_some() {
        unsafe { MGMT_SEEN = mgmt };
    }
    if !upstream_private(&dst) || dport == 53 && (proto == 17 || proto == 6) {
        return Verdict::NotPrivate;
    }
    let owner = unsafe { (*core::ptr::addr_of!(TABLE)).allows(mac, &dst, dport, now_ms) };
    if owner || acl_allow {
        if on_mgmt(&dst, mgmt) || !crate::devpolicy::check(mac, crate::devpolicy::Dest::Lan) {
            unsafe { COUNTS[3] += 1 };
        } else {
            unsafe { COUNTS[if owner { 1 } else { 2 }] += 1 };
            return Verdict::Excepted;
        }
    }
    unsafe {
        COUNTS[0] += 1;
        (*core::ptr::addr_of_mut!(BLOCKS)).record(*mac, src, dst, dport, proto, now_ms);
    }
    Verdict::Refused
}

/// The owner exceptions (for the owner-rules path and the API).
pub fn table() -> &'static mut Table {
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE) }
}

pub fn blocks() -> &'static Blocks {
    unsafe { &*core::ptr::addr_of!(BLOCKS) }
}

/// (refused, allowed by owner exception, allowed by POLICY ACL, exception refused by a guardrail)
pub fn counts() -> [u64; 4] {
    unsafe { COUNTS }
}

/// QEMU selftest `[P-lanaccess]`: the default block, DNS left to Shield, an owner exception, an ACL allow, and
/// both guardrails.
#[allow(dead_code)]
pub fn selftest() -> bool {
    let m1 = [2, 0, 0, 0, 0xa0, 1];
    let src = Addr::v4([10, 99, 0, 10]);
    let printer = Addr::v4([192, 168, 1, 50]);
    let mgmt = Some(([192, 168, 200, 146], [192, 168, 200, 1]));
    // runs on every boot (CM5 too): leave no trace in what Mission Control shows
    let (c0, b_save, t_save, m_save) = unsafe { (COUNTS, *core::ptr::addr_of!(BLOCKS), *core::ptr::addr_of!(TABLE), MGMT_SEEN) };
    let b0 = blocks().n;
    let public = check(&m1, src, Addr::v4([1, 1, 1, 1]), 443, 6, false, mgmt, 1) == Verdict::NotPrivate;
    let dns = check(&m1, src, Addr::v4([192, 168, 1, 1]), 53, 17, false, mgmt, 1) == Verdict::NotPrivate;
    let refused = check(&m1, src, printer, 631, 6, false, mgmt, 1) == Verdict::Refused;
    let attributed = blocks().n == b0 + 1;
    let x = hal::lanaccess::Exception { device: Some(m1), dst: hal::policy::Prefix { addr: printer, len: 32 }, ports: (631, 631), expires_ms: 100 };
    let _ = table().add(x);
    let excepted = check(&m1, src, printer, 631, 6, false, mgmt, 2) == Verdict::Excepted;
    let expired = check(&m1, src, printer, 631, 6, false, mgmt, 100) == Verdict::Refused;
    let acl = check(&m1, src, Addr::v4([10, 0, 0, 5]), 80, 6, true, mgmt, 3) == Verdict::Excepted;
    let mgmt_guard = check(&m1, src, Addr::v4([192, 168, 200, 1]), 443, 6, true, mgmt, 4) == Verdict::Refused;
    let mut ula = [0u8; 16];
    ula[0] = 0xfd;
    let v6 = check(&m1, Addr::v6([0x20; 16]), Addr::v6(ula), 443, 6, false, mgmt, 5) == Verdict::Refused;
    // R5: a prefix that CONTAINS one of the device's own addresses is refused (not only its network address)
    let own = crate::ratelimit::first_local_ip();
    let own_net_refused = own.is_none_or(|ip| {
        let net = hal::policy::Prefix { addr: Addr::v4((ip & 0xffff_ff00).to_be_bytes()), len: 24 };
        !upstream_private(&net.addr) || exception_refusal(&net, false).is_some()
    });
    let c1 = counts();
    unsafe {
        COUNTS = c0;
        BLOCKS = b_save;
        TABLE = t_save;
        // R2 (code review 2026-11-18): the self-test's fake management network must not outlive it — a device with no
        // management VLAN would otherwise refuse real exceptions to 192.168.200.0/24
        MGMT_SEEN = m_save;
    }
    let mgmt_restored = unsafe { MGMT_SEEN } == m_save; // R2
    let ok = public && dns && refused && attributed && excepted && expired && acl && mgmt_guard && v6 && c1[3] > c0[3] && own_net_refused && mgmt_restored;
    arch_aarch64::_print(format_args!(
        " [P-lanaccess] {} — A-01 upstream private networks refused by default: public untouched={} DNS left to Shield={} refused + attributed={}/{} owner exception (scoped, expiring)={}/{} POLICY ACL allow={} management network never opened={} IPv6 ULA refused={} own network refused={} self-test leaves no management network behind={}\n",
        if ok { "PASS" } else { "FAIL" }, public, dns, refused, attributed, excepted, expired, acl, mgmt_guard, v6, own_net_refused, mgmt_restored));
    ok
}

/// The data path's clock in ms (`cntpct_el0`, as `ApNic::now` on the CM5): ages for the API.
pub fn now_ms() -> u64 {
    let (v, f): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack));
    }
    v.saturating_mul(1000) / f.max(1)
}
