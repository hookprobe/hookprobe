//! IDS/IPS cost benchmark — `packet::verdict` (every detection tier the AP runs on a forwarded frame) timed
//! on a realistic mix, so optimisations are measured on the real core, not guessed. Prints ns per packet
//! per frame kind and the mix average. Frames are neutral for the stateful tiers: one TEST-NET source,
//! established-flow ACK/data (no SYN storm, no port sweep), so the bench never trips a detection.

fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("isb", "mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}
fn cntfrq() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}

const SRC: [u8; 4] = [100, 64, 0, 77]; // RFC 6598, on no threat list: the bench times NORMAL traffic, not an IOC alert
const DST: [u8; 4] = [198, 51, 100, 10]; // TEST-NET-2

fn eth(out: &mut [u8], et: u16) {
    out[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    out[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x77]);
    out[12..14].copy_from_slice(&et.to_be_bytes());
}

fn ipv4(out: &mut [u8], proto: u8, l4len: usize) {
    out[14] = 0x45;
    out[16..18].copy_from_slice(&((20 + l4len) as u16).to_be_bytes());
    out[22] = 64;
    out[23] = proto;
    out[26..30].copy_from_slice(&SRC);
    out[30..34].copy_from_slice(&DST);
}

/// Kinds: 0 TCP data (1400 B), 1 TCP ACK, 2 UDP DNS query, 3 IPv6 TCP data, 4 ARP request.
fn build(kind: usize, out: &mut [u8; 1514]) -> usize {
    out.fill(0);
    match kind {
        0 | 1 => {
            let pay = if kind == 0 { 1400 - 54 } else { 0 };
            eth(out, 0x0800);
            ipv4(out, 6, 20 + pay);
            out[34..36].copy_from_slice(&443u16.to_be_bytes());
            out[36..38].copy_from_slice(&51000u16.to_be_bytes());
            out[46] = 0x50;
            out[47] = if kind == 0 { 0x18 } else { 0x10 }; // PSH|ACK / ACK
            54 + pay
        }
        2 => {
            eth(out, 0x0800);
            let q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
            ipv4(out, 17, 8 + q.len());
            out[34..36].copy_from_slice(&53000u16.to_be_bytes());
            out[36..38].copy_from_slice(&53u16.to_be_bytes());
            out[38..40].copy_from_slice(&((8 + q.len()) as u16).to_be_bytes());
            out[42..42 + q.len()].copy_from_slice(q);
            42 + q.len()
        }
        3 => {
            eth(out, 0x86dd);
            let pay = 1200;
            out[14] = 0x60;
            out[18..20].copy_from_slice(&((20 + pay) as u16).to_be_bytes());
            out[20] = 6;
            out[21] = 64;
            out[22..24].copy_from_slice(&[0x20, 0x01]);
            out[38..40].copy_from_slice(&[0x20, 0x01]);
            out[54..56].copy_from_slice(&443u16.to_be_bytes());
            out[56..58].copy_from_slice(&52000u16.to_be_bytes());
            out[66] = 0x50;
            out[67] = 0x18;
            74 + pay
        }
        _ => {
            eth(out, 0x0806);
            out[0..6].fill(0xff);
            out[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
            out[22..28].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x77]);
            out[28..32].copy_from_slice(&SRC);
            out[38..42].copy_from_slice(&DST);
            60
        }
    }
}

/// Run the bench: `iters` verdicts per kind. Returns the mix-average ns/packet (0 if the timer is unusable).
pub fn run(iters: u32) -> u64 {
    const NAMES: [&str; 5] = ["tcp-data-1400", "tcp-ack", "udp-dns", "ipv6-tcp-1274", "arp"];
    let fr = cntfrq().max(1);
    let mut f = [0u8; 1514];
    let mut ns = [0u64; 5];
    for (k, slot) in ns.iter_mut().enumerate() {
        let n = build(k, &mut f);
        let _ = crate::packet::verdict(&f[..n]); // warm
        let t0 = cntpct();
        let mut acc = 0u32;
        for _ in 0..iters {
            acc = acc.wrapping_add(crate::packet::verdict(&f[..n]).1 as u32);
        }
        let dt = cntpct().wrapping_sub(t0);
        core::hint::black_box(acc);
        *slot = dt.saturating_mul(1_000_000_000) / fr / iters.max(1) as u64;
    }
    // mix: 60 % data, 20 % ACK, 10 % DNS, 8 % IPv6 data, 2 % ARP (a home WAN mix)
    let mix = (ns[0] * 60 + ns[1] * 20 + ns[2] * 10 + ns[3] * 8 + ns[4] * 2) / 100;
    arch_aarch64::_print(format_args!(
        " [IDS-BENCH] packet::verdict ns/pkt (all detection tiers, {} iters each): {}={} {}={} {}={} {}={} {}={} | mix avg={} ns -> {} kpps/core ({} Mbps at 1400 B)\n",
        iters, NAMES[0], ns[0], NAMES[1], ns[1], NAMES[2], ns[2], NAMES[3], ns[3], NAMES[4], ns[4],
        mix, 1_000_000u64.checked_div(mix).unwrap_or(0), 1_000_000u64.checked_div(mix).map_or(0, |k| k * 1400 * 8 / 1000)
    ));
    tiers(iters);
    mix
}

/// Where the time goes: each tier the datapath runs on the dominant frame (TCP data, 60 % of the mix), timed
/// alone on the same frame. Sum ≈ the verdict cost minus dispatch; tells the next optimisation what to target.
fn tiers(iters: u32) {
    use crate::rules as r;
    let fr = cntfrq().max(1);
    let mut f = [0u8; 1514];
    let n = build(0, &mut f);
    let fr_ = &f[..n];
    let src = crate::net::eth_ipv4_src(fr_);
    let role = crate::verdict::port_role_for(0);
    let l4off = 34usize;
    let pay = 54usize;
    let mut t = [0u64; 10];
    let time = |k: &mut u64, g: &mut dyn FnMut() -> u32| {
        let _ = g();
        let t0 = cntpct();
        let mut acc = 0u32;
        for _ in 0..iters {
            acc = acc.wrapping_add(g());
        }
        let dt = cntpct().wrapping_sub(t0);
        core::hint::black_box(acc);
        *k = dt.saturating_mul(1_000_000_000) / fr / iters.max(1) as u64;
    };
    time(&mut t[0], &mut || crate::net::parse(fr_).map_or(0, |m| m.dst_port as u32));
    time(&mut t[1], &mut || r::l2_stateful_verdict(fr_, src, 0, role).map_or(0, |v| v.is_drop() as u32));
    time(&mut t[2], &mut || r::run_l2(fr_, src) as u32);
    time(&mut t[3], &mut || r::run_flow(fr_, src) as u32);
    time(&mut t[4], &mut || r::flow_scan_verdict(fr_, src).map_or(0, |v| v.is_drop() as u32));
    time(&mut t[5], &mut || r::conn_rate_shed_verdict(fr_, src).map_or(0, |v| v.is_drop() as u32));
    time(&mut t[6], &mut || r::resource_shed_verdict(src).map_or(0, |v| v.is_drop() as u32));
    time(&mut t[7], &mut || {
        crate::ja4::observe(&fr_[pay..], src);
        0
    });
    time(&mut t[8], &mut || r::run_tcp(&fr_[l4off..], src) as u32);
    time(&mut t[9], &mut || r::run_l4(&fr_[l4off..], src) as u32);
    let sum: u64 = t.iter().sum();
    arch_aarch64::_print(format_args!(
        " [IDS-TIERS] tcp-data ns per tier: parse={} l2-stateful={} l2={} flow={} scan={} conn-rate={} resource-shed={} ja4={} tcp-flags={} l4-rules={} | sum={}\n",
        t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], t[9], sum
    ));
}
