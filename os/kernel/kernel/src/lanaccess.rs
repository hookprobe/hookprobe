//! A-01 (operator decision 2026-11-17): Wi-Fi / LAN clients are refused **upstream private networks** (RFC 1918,
//! 169.254/16, IPv6 ULA) unless an exception covers them. Every refusal is attributed (device, destination, port,
//! count, first / last seen) so Mission Control can explain it and offer the exception (`GET /api/lan-access`).
//!
//! Exceptions come from the owner (owner journal, `kind=lan_access`, scoped + expiring) or from an explicit `allow`
//! entry of the signed POLICY ACL on the LAN interface. Guardrails that no exception can lift:
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

/// One client packet from `mac` (`src`) to `dst`:`dport`/`proto`. `acl_allow` = an explicit `allow` entry of the
/// POLICY ACL on the client's interface matched (not the ACL's default). `mgmt` = (management address, gateway).
#[allow(clippy::too_many_arguments)]
pub fn check(mac: &[u8; 6], src: Addr, dst: Addr, dport: u16, proto: u8, acl_allow: bool, mgmt: Option<([u8; 4], [u8; 4])>, now_ms: u64) -> Verdict {
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
    let (c0, b_save, t_save) = unsafe { (COUNTS, *core::ptr::addr_of!(BLOCKS), *core::ptr::addr_of!(TABLE)) };
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
    let c1 = counts();
    unsafe {
        COUNTS = c0;
        BLOCKS = b_save;
        TABLE = t_save;
    }
    let ok = public && dns && refused && attributed && excepted && expired && acl && mgmt_guard && v6 && c1[3] > c0[3];
    arch_aarch64::_print(format_args!(
        " [P-lanaccess] {} — A-01 upstream private networks refused by default: public untouched={} DNS left to Shield={} refused + attributed={}/{} owner exception (scoped, expiring)={}/{} POLICY ACL allow={} management network never opened={} IPv6 ULA refused={}\n",
        if ok { "PASS" } else { "FAIL" }, public, dns, refused, attributed, excepted, expired, acl, mgmt_guard, v6));
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
