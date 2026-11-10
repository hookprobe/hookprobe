//! Passive TLS client fingerprint (FoxIO JA4) + SNI from a ClientHello — detection + device identity.
//!
//! Ported from the linux-tier `napse-capture` dpi.rs (whose JA4 was cross-checked against the FoxIO
//! reference implementation, including its two documented reference-vs-prose choices: JA4_a's extension
//! count includes SNI/ALPN, and the ALPN field collapses to "99" when the first byte is non-ASCII), to a
//! no_std, fixed-buffer form: at most 64 ciphers / 32 extensions / 32 signature algorithms are kept (a
//! longer hello is still fingerprinted, flagged `truncated`). Nothing allocates; every read is bounded.
//! Legacy V1's JA3 capture was never started; this runs inline on every TLS ClientHello heqk forwards.

pub use crate::tlshello::*;

/// `[P-ja4]`: the linux-tier / FoxIO-reference vector, GREASE handling, and hostile input.
pub fn selftest() -> bool {
    // the exact ClientHello of linux-tier dpi.rs `client_hello_record()`
    fn ext(t: u16, d: &[u8], out: &mut [u8], n: &mut usize) {
        out[*n..*n + 2].copy_from_slice(&t.to_be_bytes());
        out[*n + 2..*n + 4].copy_from_slice(&(d.len() as u16).to_be_bytes());
        out[*n + 4..*n + 4 + d.len()].copy_from_slice(d);
        *n += 4 + d.len();
    }
    let build = |grease_too: bool, out: &mut [u8; 256]| -> usize {
        let mut exts = [0u8; 128];
        let mut en = 0;
        if grease_too {
            ext(0x1a1a, &[], &mut exts, &mut en);
        }
        ext(0x0000, b"\x00\x0e\x00\x00\x0bexample.com", &mut exts, &mut en);
        ext(0x002b, b"\x02\x03\x04", &mut exts, &mut en);
        ext(0x000d, b"\x00\x02\x04\x03", &mut exts, &mut en);
        ext(0x0010, b"\x00\x03\x02h2", &mut exts, &mut en);
        let mut body = [0u8; 200];
        let mut b = 0;
        body[0..2].copy_from_slice(&0x0303u16.to_be_bytes());
        b += 2 + 32; // random
        body[b] = 0; // session id length
        b += 1;
        let cs: &[u16] = if grease_too { &[0x2a2a, 0x1302, 0x1301] } else { &[0x1302, 0x1301] };
        body[b..b + 2].copy_from_slice(&((cs.len() * 2) as u16).to_be_bytes());
        b += 2;
        for c in cs {
            body[b..b + 2].copy_from_slice(&c.to_be_bytes());
            b += 2;
        }
        body[b] = 1;
        body[b + 1] = 0;
        b += 2;
        body[b..b + 2].copy_from_slice(&(en as u16).to_be_bytes());
        b += 2;
        body[b..b + en].copy_from_slice(&exts[..en]);
        b += en;
        out[0] = 22;
        out[1..3].copy_from_slice(&0x0301u16.to_be_bytes());
        out[3..5].copy_from_slice(&((4 + b) as u16).to_be_bytes());
        out[5] = 1;
        out[6] = 0;
        out[7..9].copy_from_slice(&(b as u16).to_be_bytes());
        out[9..9 + b].copy_from_slice(&body[..b]);
        9 + b
    };
    let mut rec = [0u8; 256];
    let n = build(false, &mut rec);
    let kat = client_hello(&rec[..n]).is_some_and(|h| h.ja4_str() == "t13d0204h2_62ed6f6ca7ad_3953dc75acc4" && h.sni_str() == "example.com" && !h.truncated);
    // GREASE in ciphers and extensions changes nothing
    let mut rg = [0u8; 256];
    let ng = build(true, &mut rg);
    let gr = client_hello(&rg[..ng]).is_some_and(|h| h.ja4_str() == "t13d0204h2_62ed6f6ca7ad_3953dc75acc4");
    // hostile input: every truncation, a non-handshake record, garbage — never a panic, never a wrong Some
    let mut safe = true;
    for cut in 0..n {
        if let Some(h) = client_hello(&rec[..cut]) {
            safe &= h.ja4[0] == b't';
        }
    }
    let mut junk = rec;
    junk[0] = 23;
    safe &= client_hello(&junk[..n]).is_none() && client_hello(&[0xff; 300]).is_none();
    // IPv6 leg: the same hello inside Ethernet/IPv6/TCP is fingerprinted under its v6 source + lease.
    let mut f = [0u8; 74 + 256];
    f[12] = 0x86;
    f[13] = 0xdd;
    f[14] = 0x60;
    f[18..20].copy_from_slice(&((20 + n) as u16).to_be_bytes());
    f[20] = 6;
    f[21] = 64;
    f[22] = 0x20;
    f[23] = 0x01;
    f[37] = 0x77; // src 2001::77
    f[66] = 0x50; // TCP data offset 5
    f[67] = 0x18;
    f[74..74 + n].copy_from_slice(&rec[..n]);
    let before = hellos();
    observe6(&f[..74 + n], 0x0a63_0042);
    let mut seen6 = false;
    for_each(&mut |e| seen6 |= e.client6[0] == 0x20 && e.client6[15] == 0x77 && e.client == 0x0a63_0042);
    let v6 = hellos() == before + 1 && seen6;
    // leave the live table as it was: the device's /api/tls must never show a selftest client
    for e in unsafe { (*core::ptr::addr_of_mut!(SEEN)).iter_mut() } {
        if e.client6[0] == 0x20 && e.client6[15] == 0x77 && e.client == 0x0a63_0042 {
            *e = S0;
        }
    }
    // Rule 126 enforcement (operator 2026-11-10): block a DNS bypass ONLY to a name the device's Shield blocks.
    crate::shield::load_text(b"example.com\n", b"");
    let _ = crate::devpolicy::load_text(b"02:00:00:00:00:a1 full shield=off\n");
    let (std_mac, off_mac) = ([0x02u8, 0, 0, 0, 0, 0xc3], [0x02u8, 0, 0, 0, 0, 0xa1]);
    let blocks0 = sni_blocks();
    let enforced = observe_at(&rec[..n], 0x0a63_0050, [0; 16], Some(std_mac));
    let logged = sni_blocks() == blocks0 + 1;
    let off_passes = !observe_at(&rec[..n], 0x0a63_0051, [0; 16], Some(off_mac)); // Shield off for that device
    let wan_passes = !observe_at(&rec[..n], 0x0808_0808, [0; 16], Some(std_mac)); // not a LAN source
    crate::shield::load_text(b"", b"");
    let allowed_passes = !observe_at(&rec[..n], 0x0a63_0052, [0; 16], Some(std_mac)); // bypass to an allowed name
    let _ = crate::devpolicy::load_text(b"");
    for e in unsafe { (*core::ptr::addr_of_mut!(SEEN)).iter_mut() } {
        if (0x0a63_0050..=0x0a63_0052).contains(&e.client) || e.client == 0x0808_0808 {
            *e = S0;
        }
    }
    unsafe { SNI_BLOCKS = blocks0 };
    let sni = enforced && logged && off_passes && wan_passes && allowed_passes;
    arch_aarch64::_print(format_args!(
        " [P-sni-block] {} — rule 126 enforcement (operator 2026-11-10): DNS bypass to a Shield-blocked name refused + logged={} a device whose Shield is off passes={} a non-LAN source passes={} a bypass to an allowed name passes={}\n",
        if sni { "PASS" } else { "FAIL" }, enforced && logged, off_passes, wan_passes, allowed_passes));
    unsafe { HELLOS = before };
    let pass = kat && gr && safe && v6 && sni;
    arch_aarch64::_print(format_args!(
        " [P-ja4] {} — passive TLS ClientHello fingerprint (FoxIO JA4, linux-tier/reference vector) t13d0204h2_62ed6f6ca7ad_3953dc75acc4 + SNI={} | GREASE ignored={} | every truncation + non-handshake + garbage safe={} | IPv6 client fingerprinted={}\n",
        if pass { "PASS" } else { "FAIL" }, kat, gr, safe, v6
    ));
    pass
}


// ---- observation: the last TLS clients seen (per client + fingerprint), served at /api/tls ----

#[derive(Clone, Copy)]
pub struct Seen {
    /// IPv4 client (for an IPv6 client: the same device's IPv4 lease, 0 if it has none)
    pub client: u32,
    /// IPv6 client address (all-zero for an IPv4 observation)
    pub client6: [u8; 16],
    pub ja4: [u8; 36],
    pub sni: [u8; 64],
    pub sni_len: u8,
    pub count: u32,
    pub first_ms: u64,
    pub last_ms: u64,
    pub ioc: bool,
    pub bypass: bool,
}
const S0: Seen = Seen { client: 0, client6: [0; 16], ja4: [0; 36], sni: [0; 64], sni_len: 0, count: 0, first_ms: 0, last_ms: 0, ioc: false, bypass: false };
const RING: usize = 64;
static mut SEEN: [Seen; RING] = [S0; RING];
static mut HELLOS: u64 = 0;

fn ms() -> u64 {
    let (c, f) = (crate::clock::ticks(), crate::clock::freq());
    c.saturating_mul(1000) / f.max(1)
}

/// Every forwarded TCP segment from `src`: if its payload is a TLS ClientHello, fingerprint + record it.
/// Rule 125 (a known-bad JA4 from the signed IOC pack) and rule 126 (SNI is a name Shield blocks — the
/// device reached it without Shield: DoH, a hard-coded IP or a stale answer) fire observe-only.
/// Cost on every other segment: two byte compares.
/// Returns true when the ClientHello must be DROPPED (rule 126 enforcement, operator 2026-11-10): the device
/// bypassed DNS to a name its Shield decision BLOCKS (a block category / owner block, per device — never a device
/// whose Shield is off for that category, never an owner allow, never a non-LAN source). The bypass itself is
/// always only observed (rule 126 alert); a bypass to an allowed name always passes (ADR 0023).
pub fn observe(payload: &[u8], src: u32) -> bool {
    observe_at(payload, src, [0; 16], None)
}

/// As `observe`, with the client's MAC (its DEVICES.TXT Shield profile decides).
pub fn observe_dev(payload: &[u8], src: u32, mac: &[u8; 6]) -> bool {
    observe_at(payload, src, [0; 16], Some(*mac))
}

/// An IPv6 TCP frame from a LAN client (Ethernet/IPv6, no extension headers on the TLS path). `attrib` is the
/// device's IPv4 lease (by MAC) so detections land on the device the owner knows; 0 when it has none.
pub fn observe6(frame: &[u8], attrib: u32) -> bool {
    let Some(m) = crate::net::parse(frame) else { return false };
    if m.ethertype != crate::net::ETHERTYPE_IPV6 || m.ip_proto != crate::net::IPPROTO_TCP || frame.len() < 38 {
        return false;
    }
    let Some(&off) = frame.get(m.l4_off + 12) else { return false };
    let pay = m.l4_off + ((off >> 4) as usize) * 4;
    if pay >= frame.len() {
        return false;
    }
    let mut s6 = [0u8; 16];
    s6.copy_from_slice(&frame[22..38]);
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[6..12]);
    observe_at(&frame[pay..], attrib, s6, Some(mac))
}

/// LAN-side source (RFC 1918 / CGNAT): rule 126 enforcement only ever judges the protected network's own devices.
fn lan_src(ip: u32) -> bool {
    let b = ip.to_be_bytes();
    b[0] == 10 || (b[0] == 172 && (16..32).contains(&b[1])) || (b[0] == 192 && b[1] == 168) || (b[0] == 100 && (64..128).contains(&b[1]))
}

static mut SNI_BLOCKS: u64 = 0;
/// TLS connections refused by rule 126 enforcement since boot.
pub fn sni_blocks() -> u64 {
    unsafe { SNI_BLOCKS }
}

fn observe_at(payload: &[u8], src: u32, src6: [u8; 16], mac: Option<[u8; 6]>) -> bool {
    if payload.len() < 43 || payload[0] != 22 || payload[5] != 1 {
        return false;
    }
    let Some(h) = client_hello(payload) else { return false };
    unsafe { HELLOS += 1 };
    let ioc = crate::ioc::ja4_listed(&h.ja4);
    let bypass = h.sni_len > 0 && crate::shield::decide(&h.sni[..h.sni_len as usize]) == crate::shield::Verdict::Blocked;
    let now = ms();
    let t = unsafe { &mut *core::ptr::addr_of_mut!(SEEN) };
    let slot = t.iter().position(|e| e.count > 0 && e.client == src && e.client6 == src6 && e.ja4 == h.ja4 && e.sni[..e.sni_len as usize] == h.sni[..h.sni_len as usize])
        .or_else(|| t.iter().position(|e| e.count == 0))
        .unwrap_or_else(|| (0..RING).min_by_key(|&i| t[i].last_ms).unwrap_or(0));
    let e = &mut t[slot];
    if e.count == 0 || e.client != src || e.client6 != src6 || e.ja4 != h.ja4 {
        *e = Seen { client: src, client6: src6, ja4: h.ja4, sni: h.sni, sni_len: h.sni_len, count: 0, first_ms: now, last_ms: now, ioc, bypass };
    }
    e.count = e.count.saturating_add(1);
    e.last_ms = now;
    if let Some(m) = mac {
        crate::ja4id::note(&m, &h.ja4, now); // G32: the device's set of TLS stacks (a rotation hint)
    }
    if ioc {
        crate::rules::tls_ioc_verdict(src);
    }
    if bypass {
        crate::rules::tls_bypass_verdict(src);
    }
    // Enforcement: only a name the DEVICE's Shield decision blocks (category / owner block), only a LAN source.
    let block = h.sni_len > 0 && src != 0 && lan_src(src) && {
        let sni = &h.sni[..h.sni_len as usize];
        let v = match mac {
            Some(m) => crate::shield::decide_for_dev(sni, src, &m),
            None => crate::shield::decide_for(sni, src),
        };
        v == crate::shield::Verdict::Blocked
    };
    if block {
        unsafe { SNI_BLOCKS += 1 };
        if e.count == 1 {
            // once per (device, fingerprint, name): the retransmitted ClientHellos are refused silently
            crate::shield::record_tls_block(src, &h.sni[..h.sni_len as usize]);
        }
    }
    block
}

pub fn hellos() -> u64 {
    unsafe { HELLOS }
}

/// Visit the ring, most recent first.
pub fn for_each(f: &mut dyn FnMut(&Seen)) {
    let t = unsafe { &*core::ptr::addr_of!(SEEN) };
    let mut idx: [usize; RING] = core::array::from_fn(|i| i);
    idx.sort_unstable_by_key(|&i| core::cmp::Reverse(t[i].last_ms));
    for &i in idx.iter() {
        if t[i].count > 0 {
            f(&t[i]);
        }
    }
}
