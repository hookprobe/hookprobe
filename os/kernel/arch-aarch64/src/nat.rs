//! M-NAT1 — a bounded, no-alloc IPv4 source-NAT (masquerade) between the WiFi-AP /
//! eth1-LAN side (10.99.0.0/24, heqk = 10.99.0.1) and the end0 WAN lease.
//!
//! Shape (uplink/NAT deep review 2026-09-11, B3/B4/B5): a fixed table of `N` entries
//! keyed on (proto, inside ip, inside port-or-icmp-id); the OUTSIDE port/id is simply
//! `EXT_BASE + index`, so the reverse lookup is O(1) and never needs a hash. Every
//! rewrite recomputes the IPv4 + L4 checksums in full (segments are small — the SDIO
//! data path caps a WiFi-bound frame at ~496 B, so the TCP MSS is clamped on every SYN
//! / SYN-ACK crossing the WiFi leg). TTL is decremented (drop at ≤1). GEM RX frames
//! carry the 4-byte FCS (NCFGR bit 17 not set): the inbound path trims to the IPv4
//! total length before forwarding. Entries expire by `last` (cntpct) and are LRU-
//! evicted when full.

use hal::{csum_adjust, inet_csum, pseudo_sum};

/// Concurrent IPv4 mappings (audit 2026-11-10 A7: a household's phones, TVs and IoT easily hold more than
/// the old 256 flows; the forward lookup is hashed, so the size no longer costs per-packet time).
const N: usize = 4096;
/// Forward index: open addressing over `HN` buckets (load <= 50 %), value = entry index + 1 (0 = empty).
const HN: usize = 2 * N;
/// First outside port / ICMP id; entry `i` owns `EXT_BASE + i`.
pub const EXT_BASE: u16 = 40000;
/// Largest ethernet frame the WiFi data path can SEND to a station: one byte-mode CMD53
/// (512 B) minus the 16-B SDPCM/BDC header. RX now takes full-MTU frames (chunked remainder
/// reads, proven on metal); TX beyond this must wait for a proven block-mode CMD53 —
/// chunked writes desynchronised the firmware (metal 2026-10-09). Bigger inbound frames are
/// dropped and counted (`in_too_big`); the MSS clamp keeps TCP under it.
#[cfg(not(feature = "wifi-bigtx"))]
pub const WIFI_MAX_FRAME: usize = 496;
/// Bench build: block-mode CMD53 carries full-MTU frames to a station.
#[cfg(feature = "wifi-bigtx")]
pub const WIFI_MAX_FRAME: usize = 1514;
/// MSS advertised to both ends. Kept at the pre-M-NAT4 value for this image as the hedge:
/// TCP stays provably within one 512-B transfer either way, while big UDP (QUIC) is the
/// first traffic to exercise the chunked path. Raise to ~1400 once metal proves chunking.
#[cfg(not(feature = "wifi-bigtx"))]
pub const MSS_CLAMP: u16 = 430;
/// With block-mode TX (the Linux-traced sequence, metal-proven 2026-11-04: 1,773 full-MTU frames
/// to an iPhone, 0 failures) a station takes full 1514-B frames: the standard MSS for a 1500-B
/// MTU. The clamp still lowers larger advertisements; it never raises one.
#[cfg(feature = "wifi-bigtx")]
pub const MSS_CLAMP: u16 = 1460;

/// Inside link ids (`Entry.in_if`): replies go back out the link the flow came in on.
pub const IF_WIFI: u8 = 0;
pub const IF_ETH1: u8 = 1;

#[derive(Clone, Copy)]
struct Entry {
    used: bool,
    proto: u8,
    in_if: u8,
    in_mac: [u8; 6],
    in_ip: [u8; 4],
    in_port: u16, // TCP/UDP src port, or ICMP echo id
    last: u64,    // cntpct of the last packet either way
    /// DNS redirect: the address the client actually queried (the AP's own IP) when the query
    /// was forwarded to the upstream resolver — replies get it back as their source. 0 = none.
    dnat_from: [u8; 4],
    /// The remote addresses this mapping has SENT to (last 4, round-robin). Inbound is admitted only
    /// from one of them — address-dependent filtering (RFC 4787 §5). Peer review SEC-M2: with the mapping
    /// keyed on the external port alone, ANY internet host spraying the (sequential) ports 40000.. reached
    /// a client with a live session and bypassed `wan in`.
    remotes: [[u8; 4]; 4],
    rnext: u8,
    /// DNS redirect: the upstream resolver the query was forwarded to (re-review P3).
    dnat_to: [u8; 4],
    /// Flow view (Observe): when the mapping was made, the first destination port it sent to, and
    /// the IP bytes carried each way.
    first: u64,
    dport: u16,
    bytes_out: u64,
    bytes_in: u64,
    /// The WAN address this mapping was translated to (sealed-config step 9: `flush_wan` after a live WAN change).
    wan: [u8; 4],
}
const EMPTY: Entry = Entry { used: false, proto: 0, in_if: 0, in_mac: [0; 6], in_ip: [0; 4], in_port: 0, last: 0, dnat_from: [0; 4], remotes: [[0; 4]; 4], rnext: 0, dnat_to: [0; 4], first: 0, dport: 0, bytes_out: 0, bytes_in: 0, wan: [0; 4] };
static mut TABLE: [Entry; N] = [EMPTY; N];
static mut HIDX: [u16; HN] = [0; HN];
/// ADR 0067 D1 work counters: the most table entries one new flow examined, and the bytes the last
/// rewrite checksummed.
static mut SCAN_MAX: u32 = 0;
/// New-flow slot allocation without a table scan (ADR 0067 E3). Slots `FRESH..N` were never used;
/// `FREE[..NFREE]` are slots `flush_wan` released; `HAND` is where the full-table sweep resumes.
/// Invariant: a slot is unused exactly when it is `>= FRESH` or on the `FREE` stack.
const SWEEP: usize = 32;
static mut FRESH: u16 = 0;
static mut FREE: [u16; N] = [0; N];
static mut NFREE: u16 = 0;
static mut HAND: u16 = 0;

/// Forget every mapping (the boot self-tests, which own the table before any traffic).
fn reset_all() {
    unsafe {
        for e in (*core::ptr::addr_of_mut!(TABLE)).iter_mut() {
            *e = EMPTY;
        }
        (*core::ptr::addr_of_mut!(HIDX)).fill(0);
        FRESH = 0;
        NFREE = 0;
        HAND = 0;
    }
}
static mut CSUM_BYTES: u32 = 0;

#[inline]
fn hkey(proto: u8, in_ip: &[u8; 4], in_port: u16) -> usize {
    let mut x = (proto as u64) << 48 | (in_port as u64) << 32 | u32::from_be_bytes(*in_ip) as u64;
    // splitmix64 finalizer: every key bit reaches the bucket (see ratelimit::slot)
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    (x as usize) & (HN - 1)
}

/// The entry index for a key, through the hash index (O(1) expected).
fn index_find(t: &[Entry; N], proto: u8, in_ip: &[u8; 4], in_port: u16) -> Option<usize> {
    let h = unsafe { &*core::ptr::addr_of!(HIDX) };
    let mut b = hkey(proto, in_ip, in_port);
    for _ in 0..HN {
        let v = h[b];
        if v == 0 {
            return None;
        }
        let i = v as usize - 1;
        let e = &t[i];
        if e.used && e.proto == proto && e.in_ip == *in_ip && e.in_port == in_port {
            return Some(i);
        }
        b = (b + 1) & (HN - 1);
    }
    None
}

fn index_insert(proto: u8, in_ip: &[u8; 4], in_port: u16, i: usize) {
    let h = unsafe { &mut *core::ptr::addr_of_mut!(HIDX) };
    let mut b = hkey(proto, in_ip, in_port);
    while h[b] != 0 {
        b = (b + 1) & (HN - 1);
    }
    h[b] = (i + 1) as u16;
}

/// Remove entry `i` (whose key is in `t[i]`) from the index — backward-shift deletion, no tombstones.
fn index_remove(t: &[Entry; N], i: usize) {
    let h = unsafe { &mut *core::ptr::addr_of_mut!(HIDX) };
    let e = &t[i];
    let mut b = hkey(e.proto, &e.in_ip, e.in_port);
    let mut n = 0;
    while h[b] != (i + 1) as u16 {
        if h[b] == 0 || n == HN {
            return; // not indexed
        }
        b = (b + 1) & (HN - 1);
        n += 1;
    }
    let mut hole = b;
    let mut j = (hole + 1) & (HN - 1);
    loop {
        let v = h[j];
        if v == 0 {
            break;
        }
        let k = &t[v as usize - 1];
        let home = hkey(k.proto, &k.in_ip, k.in_port);
        // move j back into the hole unless its home lies cyclically in (hole, j]
        let in_range = if hole <= j { home > hole && home <= j } else { home > hole || home <= j };
        if !in_range {
            h[hole] = v;
            hole = j;
        }
        j = (j + 1) & (HN - 1);
    }
    h[hole] = 0;
}

#[derive(Default)]
pub struct NatStats {
    pub out_fwd: u32,
    pub in_fwd: u32,
    pub out_drop: u32,     // not IPv4 / TTL / unsupported proto / for us
    pub in_drop: u32,      // no matching entry / not for the lease
    pub in_too_big: u32,   // inbound frame > WIFI_MAX_FRAME after trim (dropped)
    pub mss_clamped: u32,
    pub table_alloc: u32,
    pub table_evict: u32,
    /// DNS queries to the AP address forwarded to the upstream resolver.
    pub dns_redirect: u32,
    /// Inbound ICMP errors (unreachable / frag-needed / time-exceeded / param-problem) translated back
    /// to the client whose flow they quote (RFC 5508) — PMTU discovery + traceroute through the NAT.
    pub icmp_err_in: u32,
}

#[inline]
fn ticks_secs(s: u64) -> u64 {
    let f: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
    f.max(1).saturating_mul(s)
}

/// Idle timeout per proto (seconds) — short, self-reverting (ADR 0023 spirit: state is
/// a bounded cache, never a durable claim).
fn timeout(proto: u8) -> u64 {
    match proto {
        6 => ticks_secs(300),
        17 => ticks_secs(60),
        _ => ticks_secs(30),
    }
}

/// Find or allocate the entry for (proto, in_ip, in_port). Returns the index.
fn lookup_or_alloc(proto: u8, in_if: u8, in_mac: &[u8; 6], in_ip: &[u8; 4], in_port: u16, now: u64, st: &mut NatStats) -> usize {
    let t = unsafe { &mut *core::ptr::addr_of_mut!(TABLE) };
    if let Some(i) = index_find(t, proto, in_ip, in_port) {
        t[i].last = now;
        t[i].in_mac = *in_mac;
        t[i].in_if = in_if;
        return i;
    }
    // A NEW flow (once per mapping, not per packet). ADR 0067 E3: no table scan.
    //   1. a slot `flush_wan` released, 2. a slot never used yet, 3. the table is full: look at the
    //   next SWEEP slots from a rotating hand and take the first expired one, else the least recently
    //   used of those SWEEP. A flood of new flows therefore costs a bounded SWEEP entries each (it was
    //   the whole table, 4,096 entries of ~100 bytes, per new flow).
    let mut scanned = 0u32;
    let i = unsafe {
        if NFREE > 0 {
            NFREE -= 1;
            (*core::ptr::addr_of!(FREE))[NFREE as usize] as usize
        } else if (FRESH as usize) < N {
            FRESH += 1;
            FRESH as usize - 1
        } else {
            let mut pick: Option<usize> = None;
            let mut oldest = (HAND as usize, u64::MAX);
            for k in 0..SWEEP {
                let i = (HAND as usize + k) % N;
                let e = &t[i];
                scanned += 1;
                if now.wrapping_sub(e.last) > timeout(e.proto) {
                    pick = Some(i); // expired — reusable
                    break;
                }
                if e.last < oldest.1 {
                    oldest = (i, e.last);
                }
            }
            let i = match pick {
                Some(i) => i,
                None => {
                    st.table_evict += 1;
                    oldest.0
                }
            };
            HAND = ((i + 1) % N) as u16;
            i
        }
    };
    unsafe {
        if scanned > SCAN_MAX {
            SCAN_MAX = scanned;
        }
    }
    if t[i].used {
        index_remove(t, i);
    }
    t[i] = Entry { used: true, proto, in_if, in_mac: *in_mac, in_ip: *in_ip, in_port, last: now, dnat_from: [0; 4], remotes: [[0; 4]; 4], rnext: 0, dnat_to: [0; 4], first: now, dport: 0, bytes_out: 0, bytes_in: 0, wan: [0; 4] };
    index_insert(proto, in_ip, in_port, i);
    st.table_alloc += 1;
    i
}

/// Remember that mapping `i` sent to `remote` (no-op if already known).
fn note_remote(i: usize, remote: &[u8; 4]) {
    let t = unsafe { &mut *core::ptr::addr_of_mut!(TABLE) };
    let e = &mut t[i];
    if e.remotes.iter().any(|r| r == remote) {
        return;
    }
    e.remotes[(e.rnext as usize) % 4] = *remote;
    e.rnext = e.rnext.wrapping_add(1);
}

impl Entry {
    fn knows(&self, remote: &[u8]) -> bool {
        self.remotes.iter().any(|r| r[..] == remote[..4] && *r != [0; 4])
    }
}

fn entry_for_ext(proto: u8, ext: u16, now: u64) -> Option<Entry> {
    let i = (ext as usize).checked_sub(EXT_BASE as usize)?;
    if i >= N {
        return None;
    }
    let t = unsafe { &mut *core::ptr::addr_of_mut!(TABLE) };
    let e = t[i];
    if !e.used || e.proto != proto {
        return None;
    }
    if now.wrapping_sub(e.last) > timeout(proto) {
        return None;
    }
    t[i].last = now;
    Some(e)
}

/// Clamp TCP option MSS (kind 2) on a SYN. `tcp` = the TCP header (+options) slice.
/// Runtime MSS ceiling below MSS_CLAMP (0 = none): the WAN sets 1452 when it runs PPPoE (MTU 1492).
static MSS_LIMIT: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);
pub fn set_mss_limit(v: u16) {
    MSS_LIMIT.store(v, core::sync::atomic::Ordering::Relaxed);
}
pub fn mss_limit() -> u16 {
    MSS_LIMIT.load(core::sync::atomic::Ordering::Relaxed)
}
fn mss_ceiling() -> u16 {
    match MSS_LIMIT.load(core::sync::atomic::Ordering::Relaxed) {
        0 => MSS_CLAMP,
        l => l.min(MSS_CLAMP),
    }
}

fn clamp_mss(tcp: &mut [u8], st: &mut NatStats) {
    if tcp.len() < 20 || tcp[13] & 0x02 == 0 {
        return; // not a SYN
    }
    let doff = ((tcp[12] >> 4) as usize) * 4;
    if doff < 20 || doff > tcp.len() {
        return;
    }
    let mut p = 20;
    while p < doff {
        match tcp[p] {
            0 => break,
            1 => p += 1,
            2 if p + 4 <= doff => {
                let mss = u16::from_be_bytes([tcp[p + 2], tcp[p + 3]]);
                if mss > mss_ceiling() {
                    tcp[p + 2..p + 4].copy_from_slice(&mss_ceiling().to_be_bytes());
                    st.mss_clamped += 1;
                }
                return;
            }
            _ => {
                if p + 1 >= doff {
                    break;
                }
                let l = tcp[p + 1] as usize;
                if l < 2 {
                    break;
                }
                p += l;
            }
        }
    }
}

/// Recompute the IPv4 header checksum and the L4 checksum (TCP/UDP pseudo-header, ICMP
/// plain) over `f` (a complete ethernet frame, IPv4 at 14). `ip_end` bounds the datagram.
fn fix_csums(f: &mut [u8], ihl: usize, ip_end: usize) {
    let proto = f[23];
    f[24] = 0;
    f[25] = 0;
    let ipc = inet_csum(&f[14..14 + ihl], 0);
    f[24..26].copy_from_slice(&ipc.to_be_bytes());
    let l4 = 14 + ihl;
    if l4 > ip_end {
        return;
    }
    let l4len = (ip_end - l4) as u16;
    unsafe { CSUM_BYTES = (ip_end - 14) as u32 };
    let mut sip = [0u8; 4];
    sip.copy_from_slice(&f[26..30]);
    let mut dip = [0u8; 4];
    dip.copy_from_slice(&f[30..34]);
    match proto {
        6 if l4 + 20 <= ip_end => {
            f[l4 + 16] = 0;
            f[l4 + 17] = 0;
            let c = inet_csum(&f[l4..ip_end], pseudo_sum(&sip, &dip, 6, l4len));
            f[l4 + 16..l4 + 18].copy_from_slice(&c.to_be_bytes());
        }
        17 if l4 + 8 <= ip_end => {
            let had = f[l4 + 6] != 0 || f[l4 + 7] != 0;
            if had {
                f[l4 + 6] = 0;
                f[l4 + 7] = 0;
                let mut c = inet_csum(&f[l4..ip_end], pseudo_sum(&sip, &dip, 17, l4len));
                if c == 0 {
                    c = 0xffff;
                }
                f[l4 + 6..l4 + 8].copy_from_slice(&c.to_be_bytes());
            }
        }
        1 if l4 + 8 <= ip_end => {
            f[l4 + 2] = 0;
            f[l4 + 3] = 0;
            let c = inet_csum(&f[l4..ip_end], 0);
            f[l4 + 2..l4 + 4].copy_from_slice(&c.to_be_bytes());
        }
        _ => {}
    }
}

/// ADR 0067 E4 — the per-packet checksum fix-up, incremental (RFC 1624). `f` is the frame as received
/// (its checksums as the sender wrote them), `out` the rewritten copy. Only the 16-bit words the NAT
/// rewrote are summed: the TTL word and the addresses for the IPv4 header; the addresses (pseudo
/// header), the ports and, on a SYN, the TCP options (the MSS clamp) for TCP; addresses and ports for
/// UDP (a zero UDP checksum stays zero); the echo id for ICMP. `fix_csums` re-summed the whole
/// datagram per packet; it stays as the self-test oracle and for the rare ICMP-error translation.
/// A checksum that was wrong on arrival stays wrong: the receiver drops it, as without a NAT.
fn fix_csums_incr(f: &[u8], out: &mut [u8], ihl: usize, ip_end: usize) {
    let mut c = u16::from_be_bytes([f[24], f[25]]);
    c = csum_adjust(c, &f[22..24], &out[22..24]);
    c = csum_adjust(c, &f[26..34], &out[26..34]);
    out[24..26].copy_from_slice(&c.to_be_bytes());
    let mut summed = 10usize;
    let l4 = 14 + ihl;
    match f[23] {
        6 if l4 + 20 <= ip_end => {
            let mut c = u16::from_be_bytes([f[l4 + 16], f[l4 + 17]]);
            c = csum_adjust(c, &f[26..34], &out[26..34]);
            c = csum_adjust(c, &f[l4..l4 + 4], &out[l4..l4 + 4]);
            summed += 12;
            let doff = ((f[l4 + 12] >> 4) as usize) * 4;
            if f[l4 + 13] & 0x02 != 0 && doff > 20 && l4 + doff <= ip_end {
                c = csum_adjust(c, &f[l4 + 20..l4 + doff], &out[l4 + 20..l4 + doff]);
                summed += doff - 20;
            }
            out[l4 + 16..l4 + 18].copy_from_slice(&c.to_be_bytes());
        }
        17 if l4 + 8 <= ip_end => {
            let had = u16::from_be_bytes([f[l4 + 6], f[l4 + 7]]);
            if had != 0 {
                let mut c = csum_adjust(had, &f[26..34], &out[26..34]);
                c = csum_adjust(c, &f[l4..l4 + 4], &out[l4..l4 + 4]);
                if c == 0 {
                    c = 0xffff;
                }
                out[l4 + 6..l4 + 8].copy_from_slice(&c.to_be_bytes());
                summed += 12;
            }
        }
        1 if l4 + 8 <= ip_end => {
            let c = csum_adjust(u16::from_be_bytes([f[l4 + 2], f[l4 + 3]]), &f[l4 + 4..l4 + 6], &out[l4 + 4..l4 + 6]);
            out[l4 + 2..l4 + 4].copy_from_slice(&c.to_be_bytes());
            summed += 2;
        }
        _ => {}
    }
    unsafe { CSUM_BYTES = summed as u32 };
}

/// Parse an IPv4 frame: (ihl, ip_end bounded by the frame, proto). None if not IPv4 /
/// truncated / fragmented (fragments are not NATed in v1).
fn parse_v4(f: &[u8]) -> Option<(usize, usize, u8)> {
    if f.len() < 34 || f[12] != 0x08 || f[13] != 0x00 || f[14] >> 4 != 4 {
        return None;
    }
    let ihl = ((f[14] & 0x0f) as usize) * 4;
    if ihl < 20 || 14 + ihl > f.len() {
        return None;
    }
    let tot = u16::from_be_bytes([f[16], f[17]]) as usize;
    if tot < ihl {
        return None;
    }
    let ip_end = (14 + tot).min(f.len());
    let flags_frag = u16::from_be_bytes([f[20], f[21]]);
    if flags_frag & 0x3fff != 0 {
        return None; // MF set or a non-zero fragment offset
    }
    Some((ihl, ip_end, f[23]))
}

/// OUTBOUND (inside → WAN): rewrite a client frame into `out` addressed to the gateway,
/// sourced from the lease. Returns the frame length to transmit on end0, or None (not
/// NATable: not IPv4, TTL exhausted, unsupported proto, or destined for our own subnet).
pub fn outbound(f: &[u8], in_if: u8, inside_net: &[u8; 3], wan_ip: &[u8; 4], wan_mac: &[u8; 6], gw_mac: &[u8; 6], out: &mut [u8], now: u64, st: &mut NatStats) -> Option<usize> {
    outbound_redirect(f, in_if, inside_net, None, wan_ip, wan_mac, gw_mac, out, now, st)
}

/// `outbound` plus the AP's DNS service: a UDP query to `dns.0` (the AP's own address, which the
/// AP's DHCP advertises as the resolver) port 53 is forwarded to `dns.1` (the upstream resolver
/// from the WAN lease) through the same SNAT, and the entry remembers it so `inbound` restores
/// the AP address as the reply's source. Every gate before NAT (lease binding, IDS verdict) has
/// already run on the client's original frame.
pub fn outbound_redirect(f: &[u8], in_if: u8, inside_net: &[u8; 3], dns: Option<(&[u8; 4], &[u8; 4])>, wan_ip: &[u8; 4], wan_mac: &[u8; 6], gw_mac: &[u8; 6], out: &mut [u8], now: u64, st: &mut NatStats) -> Option<usize> {
    let (ihl, ip_end, proto) = match parse_v4(f) {
        Some(t) => t,
        None => {
            st.out_drop += 1;
            return None;
        }
    };
    let l4p = 14 + ihl;
    let redirect = match dns {
        Some((ap_ip, resolver)) if proto == 17 && f[30..34] == ap_ip[..] && l4p + 4 <= ip_end
            && u16::from_be_bytes([f[l4p + 2], f[l4p + 3]]) == 53 => Some((*ap_ip, *resolver)),
        _ => None,
    };
    if redirect.is_none() && (f[30..33] == inside_net[..] || f[30..34] == [255; 4] || f[30] >= 224 || f[22] <= 1) {
        st.out_drop += 1;
        return None; // local subnet / broadcast / multicast / TTL exhausted
    }
    if ip_end > out.len() {
        st.out_drop += 1;
        return None;
    }
    let l4 = 14 + ihl;
    let in_port = match proto {
        6 | 17 if l4 + 8 <= ip_end => u16::from_be_bytes([f[l4], f[l4 + 1]]),
        1 if l4 + 8 <= ip_end && f[l4] == 8 => u16::from_be_bytes([f[l4 + 4], f[l4 + 5]]), // echo request id
        _ => {
            st.out_drop += 1;
            return None;
        }
    };
    let mut in_mac = [0u8; 6];
    in_mac.copy_from_slice(&f[6..12]);
    let mut in_ip = [0u8; 4];
    in_ip.copy_from_slice(&f[26..30]);
    if f[22] <= 1 {
        st.out_drop += 1;
        return None;
    }
    let idx = lookup_or_alloc(proto, in_if, &in_mac, &in_ip, in_port, now, st);
    let ext = EXT_BASE + idx as u16;
    unsafe {
        let t = &mut *core::ptr::addr_of_mut!(TABLE);
        t[idx].dnat_from = match redirect { Some((ap, _)) => ap, None => [0; 4] };
        t[idx].dnat_to = match redirect { Some((_, r)) => r, None => [0; 4] };
        t[idx].wan = *wan_ip;
    }

    out[..ip_end].copy_from_slice(&f[..ip_end]);
    out[0..6].copy_from_slice(gw_mac);
    out[6..12].copy_from_slice(wan_mac);
    out[22] -= 1; // TTL
    out[26..30].copy_from_slice(wan_ip);
    if let Some((_, resolver)) = redirect {
        out[30..34].copy_from_slice(&resolver);
        st.dns_redirect += 1;
    }
    match proto {
        6 => {
            out[l4..l4 + 2].copy_from_slice(&ext.to_be_bytes());
            clamp_mss(&mut out[l4..ip_end], st);
        }
        17 => out[l4..l4 + 2].copy_from_slice(&ext.to_be_bytes()),
        _ => out[l4 + 4..l4 + 6].copy_from_slice(&ext.to_be_bytes()),
    }
    {
        let mut d = [0u8; 4];
        d.copy_from_slice(&out[30..34]);
        note_remote(idx, &d);
        let t = unsafe { &mut *core::ptr::addr_of_mut!(TABLE) };
        let e = &mut t[idx];
        if e.dport == 0 && proto != 1 {
            e.dport = u16::from_be_bytes([f[l4 + 2], f[l4 + 3]]);
        }
        e.bytes_out += (ip_end - 14) as u64;
    }
    fix_csums_incr(f, out, ihl, ip_end);
    st.out_fwd += 1;
    Some(ip_end)
}

/// INBOUND (WAN → inside): a frame received on end0 for the lease. Rewrites it into `out`
/// addressed to the inside client (from the table) and sourced from that link's MAC
/// (`inside_macs[in_if]`). Returns (frame length, inside link id), or None (not for us /
/// no entry). The CALLER enforces the per-link size cap (the WiFi leg carries ≤
/// `WIFI_MAX_FRAME`; eth1 a full MTU) and counts `in_too_big`.
pub fn inbound(f: &[u8], wan_ip: &[u8; 4], wan_mac: &[u8; 6], inside_macs: [&[u8; 6]; 2], out: &mut [u8], now: u64, st: &mut NatStats) -> Option<(usize, u8)> {
    if f.len() < 14 || (f[0..6] != wan_mac[..]) {
        return None; // promiscuous GEM: not addressed to us (no stat — that's the wire's noise)
    }
    let (ihl, ip_end, proto) = match parse_v4(f) {
        Some(t) => t,
        None => return None,
    };
    if f[30..34] != wan_ip[..] {
        return None;
    }
    if f[22] <= 1 || ip_end > out.len() {
        st.in_drop += 1;
        return None;
    }
    let l4 = 14 + ihl;
    // RFC 5508 §7: an ICMP ERROR quoting one of OUR outbound packets (quoted source = the NAT address,
    // quoted source port / echo id = a session) goes back to that client with the outer destination AND
    // the quoted source address/port translated — otherwise "fragmentation needed" never reaches the
    // client (PMTU black hole: metal 2026-11-06, a 1448-B segment retransmitted until the client's own
    // heuristic shrank it), traceroute never sees time-exceeded, and UDP waits instead of failing fast.
    if proto == 1 && l4 + 8 <= ip_end && matches!(f[l4], 3 | 11 | 12) {
        let q = l4 + 8;
        if q + 20 > ip_end || f[q] >> 4 != 4 {
            st.in_drop += 1;
            return None;
        }
        let qihl = ((f[q] & 0x0f) as usize) * 4;
        let ql4 = q + qihl;
        if qihl < 20 || ql4 + 8 > ip_end || f[q + 12..q + 16] != wan_ip[..] {
            st.in_drop += 1;
            return None;
        }
        let qproto = f[q + 9];
        let qext = match qproto {
            6 | 17 => u16::from_be_bytes([f[ql4], f[ql4 + 1]]),
            1 if f[ql4] == 8 => u16::from_be_bytes([f[ql4 + 4], f[ql4 + 5]]),
            _ => {
                st.in_drop += 1;
                return None;
            }
        };
        let e = match entry_for_ext(qproto, qext, now) {
            Some(e) if e.knows(&f[q + 16..q + 20]) => e, // the quoted packet went to a remote we talked to
            _ => {
                st.in_drop += 1;
                return None;
            }
        };
        let inside_mac = inside_macs[(e.in_if as usize).min(1)];
        out[..ip_end].copy_from_slice(&f[..ip_end]);
        out[0..6].copy_from_slice(&e.in_mac);
        out[6..12].copy_from_slice(inside_mac);
        out[22] -= 1;
        out[30..34].copy_from_slice(&e.in_ip); // outer destination -> the client
        out[q + 12..q + 16].copy_from_slice(&e.in_ip); // quoted source -> the client
        match qproto {
            6 | 17 => out[ql4..ql4 + 2].copy_from_slice(&e.in_port.to_be_bytes()),
            _ => out[ql4 + 4..ql4 + 6].copy_from_slice(&e.in_port.to_be_bytes()),
        }
        // DNS-redirected session: the client sent to the AP, not to the resolver — quote what IT sent
        // (peer review SEC-P2), or its stack cannot match the error to the query.
        if e.dnat_from != [0; 4] && qproto == 17 && u16::from_be_bytes([f[ql4 + 2], f[ql4 + 3]]) == 53 && f[q + 16..q + 20] == e.dnat_to {
            out[q + 16..q + 20].copy_from_slice(&e.dnat_from);
        }
        // quoted IP header checksum; the (truncated) quoted L4 checksum is left as received
        out[q + 10] = 0;
        out[q + 11] = 0;
        let qc = inet_csum(&out[q..q + qihl], 0);
        out[q + 10..q + 12].copy_from_slice(&qc.to_be_bytes());
        fix_csums(out, ihl, ip_end); // outer IP + the whole ICMP message
        st.in_fwd += 1;
        st.icmp_err_in += 1;
        return Some((ip_end, e.in_if));
    }
    let ext = match proto {
        6 | 17 if l4 + 8 <= ip_end => u16::from_be_bytes([f[l4 + 2], f[l4 + 3]]),
        1 if l4 + 8 <= ip_end && f[l4] == 0 => u16::from_be_bytes([f[l4 + 4], f[l4 + 5]]), // echo reply id
        _ => {
            st.in_drop += 1;
            return None;
        }
    };
    let e = match entry_for_ext(proto, ext, now) {
        Some(e) if e.knows(&f[26..30]) => e,
        _ => {
            st.in_drop += 1;
            return None;
        }
    };
    let inside_mac = inside_macs[(e.in_if as usize).min(1)];
    // Trim to the IPv4 total length: the GEM hands us the FCS too.
    out[..ip_end].copy_from_slice(&f[..ip_end]);
    out[0..6].copy_from_slice(&e.in_mac);
    out[6..12].copy_from_slice(inside_mac);
    out[22] -= 1;
    out[30..34].copy_from_slice(&e.in_ip);
    match proto {
        6 => {
            out[l4 + 2..l4 + 4].copy_from_slice(&e.in_port.to_be_bytes());
            clamp_mss(&mut out[l4..ip_end], st); // SYN-ACK: keep the client's segments small too
        }
        17 => out[l4 + 2..l4 + 4].copy_from_slice(&e.in_port.to_be_bytes()),
        _ => out[l4 + 4..l4 + 6].copy_from_slice(&e.in_port.to_be_bytes()),
    }
    // DNS redirect: the client asked the AP — the answer must come FROM the AP.
    if e.dnat_from != [0; 4] && proto == 17 && u16::from_be_bytes([f[l4], f[l4 + 1]]) == 53 {
        out[26..30].copy_from_slice(&e.dnat_from);
    }
    fix_csums_incr(f, out, ihl, ip_end);
    if let Some(i) = (ext as usize).checked_sub(EXT_BASE as usize).filter(|&i| i < N) {
        unsafe { (*core::ptr::addr_of_mut!(TABLE))[i].bytes_in += (ip_end - 14) as u64 };
    }
    st.in_fwd += 1;
    Some((ip_end, e.in_if))
}

/// Sealed-config step 9 (live WAN change): drop every mapping translated to the OLD WAN address — the flows through
/// it are dead anyway (the upstream no longer routes it to us), and a stale mapping must not answer on the new one.
/// Mappings made on another address are kept. Returns the number removed.
pub fn flush_wan(old: [u8; 4]) -> usize {
    if old == [0; 4] {
        return 0;
    }
    let t = unsafe { &mut *core::ptr::addr_of_mut!(TABLE) };
    let mut n = 0;
    for i in 0..N {
        if t[i].used && t[i].wan == old {
            index_remove(t, i);
            t[i] = EMPTY;
            unsafe {
                (*core::ptr::addr_of_mut!(FREE))[NFREE as usize] = i as u16;
                NFREE += 1;
            }
            n += 1;
        }
    }
    n
}

/// `flush_wan` on the live table (for [P-cfgd-wan]): mappings on two WAN addresses, the old one flushed — only its
/// entries are gone and the index still resolves every other mapping to its own slot. Leaves no test entries.
#[cfg(not(feature = "cm5"))]
pub fn flush_wan_selftest() -> bool {
    let (a, b) = ([192, 0, 2, 77], [198, 51, 100, 77]);
    let mut st = NatStats::default();
    let key = |k: usize| ([10u8, 99, 0xfe, k as u8], 61000 + k as u16);
    let mut idx = [0usize; 8];
    for k in 0..8 {
        let (ip, port) = key(k);
        idx[k] = lookup_or_alloc(17, 0, &[0; 6], &ip, port, 1, &mut st);
        unsafe { (*core::ptr::addr_of_mut!(TABLE))[idx[k]].wan = if k % 2 == 0 { a } else { b } };
    }
    let removed = flush_wan(a) == 4 && flush_wan([0; 4]) == 0;
    let t = unsafe { &*core::ptr::addr_of!(TABLE) };
    let only = (0..8).all(|k| {
        let (ip, port) = key(k);
        let f = index_find(t, 17, &ip, port);
        if k % 2 == 0 { f.is_none() && !t[idx[k]].used } else { f == Some(idx[k]) }
    });
    let rest = flush_wan(b) == 4;
    removed && only && rest
}

/// `[P-nat-csum]` (ADR 0067 E4) — the incremental checksum fix-up equals the full recompute. Frames
/// with valid checksums go through the SNAT rewrite and back; each result is compared byte for byte
/// with the same frame after `fix_csums` (the full recompute, the oracle).
fn csum_selftest() -> bool {
    // (protocol, IPv4 total length, TCP SYN carrying an MSS option, UDP sent without a checksum)
    const CASES: [(u8, usize, bool, bool); 7] =
        [(6, 1500, false, false), (6, 44, true, false), (6, 41, false, false), (17, 1500, false, false), (17, 61, false, false), (17, 60, false, true), (1, 84, false, false)];
    #[allow(clippy::too_many_arguments)]
    fn build(f: &mut [u8; 1514], proto: u8, tot: usize, syn: bool, udp0: bool, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, reply: bool) {
        f.fill(0);
        f[12] = 0x08;
        f[14] = 0x45;
        f[16..18].copy_from_slice(&(tot as u16).to_be_bytes());
        f[22] = 64;
        f[23] = proto;
        f[26..30].copy_from_slice(&src);
        f[30..34].copy_from_slice(&dst);
        for (i, b) in f.iter_mut().enumerate().take(14 + tot).skip(34) {
            *b = (i * 7 + 3) as u8;
        }
        match proto {
            6 => {
                f[34..36].copy_from_slice(&sport.to_be_bytes());
                f[36..38].copy_from_slice(&dport.to_be_bytes());
                f[46] = if syn { 0x60 } else { 0x50 };
                f[47] = if syn && reply { 0x12 } else if syn { 0x02 } else { 0x10 };
                f[50] = 0;
                f[51] = 0;
                if syn {
                    f[54..58].copy_from_slice(&[2, 4, 0x23, 0x28]); // MSS 9000: always above the clamp
                }
            }
            17 => {
                f[34..36].copy_from_slice(&sport.to_be_bytes());
                f[36..38].copy_from_slice(&dport.to_be_bytes());
                f[38..40].copy_from_slice(&((tot - 20) as u16).to_be_bytes());
                f[40] = 0;
                f[41] = if udp0 { 0 } else { 1 }; // non-zero: `fix_csums` then computes it
            }
            _ => {
                f[34] = if reply { 0 } else { 8 };
                f[35] = 0;
                f[36] = 0;
                f[37] = 0;
                f[38..40].copy_from_slice(&(if reply { dport } else { sport }).to_be_bytes());
            }
        }
        fix_csums(&mut f[..], 20, 14 + tot);
    }
    let (wan, remote, client) = ([192u8, 0, 2, 1], [93u8, 184, 216, 34], [10u8, 66, 0, 5]);
    let (mut f, mut out, mut want) = ([0u8; 1514], [0u8; 1514], [0u8; 1514]);
    let mut st = NatStats::default();
    let (mut out_ok, mut in_ok, mut big) = (true, true, 0u32);
    for (k, &(proto, tot, syn, udp0)) in CASES.iter().enumerate() {
        let sport = 50_000 + k as u16;
        build(&mut f, proto, tot, syn, udp0, client, remote, sport, 443, false);
        let n = match outbound(&f[..14 + tot], IF_ETH1, &[10, 66, 0], &wan, &[2; 6], &[4; 6], &mut out, 200_000, &mut st) {
            Some(n) => n,
            None => {
                out_ok = false;
                continue;
            }
        };
        if k == 0 {
            big = unsafe { CSUM_BYTES };
        }
        want[..n].copy_from_slice(&out[..n]);
        fix_csums(&mut want[..], 20, n);
        out_ok &= out[..n] == want[..n] && (!udp0 || (out[40] == 0 && out[41] == 0));
        // the reply, addressed to the external port the mapping got
        let ext = if proto == 1 { u16::from_be_bytes([out[38], out[39]]) } else { u16::from_be_bytes([out[34], out[35]]) };
        build(&mut f, proto, tot, syn, udp0, remote, wan, 443, ext, true);
        match inbound(&f[..14 + tot], &wan, &[0; 6], [&[6; 6], &[8; 6]], &mut out, 200_001, &mut st) {
            Some((n, _)) => {
                want[..n].copy_from_slice(&out[..n]);
                fix_csums(&mut want[..], 20, n);
                in_ok &= out[..n] == want[..n] && out[30..34] == client;
            }
            None => in_ok = false,
        }
    }
    let clamped = st.mss_clamped == 2; // the SYN out and the SYN-ACK back: the option path was exercised
    // a checksum that was wrong on arrival is not repaired
    build(&mut f, 6, 1500, false, false, client, remote, 50_100, 443, false);
    f[50] ^= 0x01;
    let kept_wrong = match outbound(&f[..1514], IF_ETH1, &[10, 66, 0], &wan, &[2; 6], &[4; 6], &mut out, 200_002, &mut st) {
        Some(n) => {
            want[..n].copy_from_slice(&out[..n]);
            fix_csums(&mut want[..], 20, n);
            out[..n] != want[..n] && out[14..50] == want[14..50]
        }
        None => false,
    };
    crate::perfctr::emit("nat_rewrite_csum_bytes", big as u64);
    let pass = out_ok && in_ok && clamped && kept_wrong && big <= 22;
    crate::_print(format_args!(
        " [P-nat-csum] {} — ADR 0067 E4: the NAT rewrite updates checksums incrementally (RFC 1624) over the words it changed, not the whole datagram: outbound equals the full recompute over TCP / TCP SYN with a clamped MSS / odd length / UDP / UDP without a checksum (stays zero) / ICMP echo={} the replies inbound equal it too={} the MSS option path ran both ways={} a checksum wrong on arrival is not repaired={} bytes summed for a 1,500-byte TCP segment={} (was 1500)\n",
        if pass { "PASS" } else { "FAIL" }, out_ok, in_ok, clamped, kept_wrong, big));
    pass
}

/// One translated flow, read-only (Observe → flows). `dst` is the first destination the mapping
/// sent to (a mapping is endpoint-independent: it may have reached more); times are cntpct.
#[derive(Clone, Copy, Debug)]
pub struct FlowView {
    pub slot: u16,
    pub proto: u8,
    pub src: [u8; 4],
    pub sport: u16,
    pub dst: [u8; 4],
    pub dport: u16,
    pub first: u64,
    pub last: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// Every live (not expired at `now`) mapping, in table order.
pub fn for_each_flow(now: u64, f: &mut dyn FnMut(&FlowView)) {
    let t = unsafe { &*core::ptr::addr_of!(TABLE) };
    for (i, e) in t.iter().enumerate() {
        if !e.used || now.wrapping_sub(e.last) > timeout(e.proto) {
            continue;
        }
        let dst = if e.dnat_to != [0; 4] { e.dnat_to } else { e.remotes[0] };
        f(&FlowView { slot: i as u16, proto: e.proto, src: e.in_ip, sport: e.in_port, dst, dport: e.dport,
            first: e.first, last: e.last, bytes_out: e.bytes_out, bytes_in: e.bytes_in });
    }
}

/// `[P-nat-index]`: the hashed forward index stays exact through a full table, evictions and slot reuse:
/// every live mapping resolves to its own entry, and a reused slot never answers for its old key.
pub fn index_selftest() -> bool {
    let t = unsafe { &mut *core::ptr::addr_of_mut!(TABLE) };
    // runs at boot before any NAT traffic (the table is empty before and after; no 400 KB stack copy)
    reset_all();
    let mut st = NatStats::default();
    unsafe { SCAN_MAX = 0 };
    let key = |k: usize| ([10u8, 99, (k >> 8) as u8, k as u8], 1024 + (k % 7000) as u16);
    // 1. fill the table: N distinct flows, each gets its own slot, each lookup returns it
    let mut fill = true;
    for k in 0..N {
        let (ip, port) = key(k);
        let i = lookup_or_alloc(6, 0, &[0; 6], &ip, port, 1000 + k as u64, &mut st);
        fill &= i == k;
    }
    let mut hits = true;
    for k in 0..N {
        let (ip, port) = key(k);
        hits &= lookup_or_alloc(6, 0, &[0; 6], &ip, port, 1000 + k as u64, &mut st) == k;
    }
    // 2. 512 new flows on a full table evict the least recently used; the evicted keys are gone,
    //    every other live key still resolves to its own slot
    for k in N..N + 512 {
        let (ip, port) = key(k);
        let _ = lookup_or_alloc(6, 0, &[0; 6], &ip, port, 100_000 + k as u64, &mut st);
    }
    let mut consistent = st.table_evict == 512;
    for i in 0..N {
        let e = t[i];
        consistent &= e.used && index_find(t, e.proto, &e.in_ip, e.in_port) == Some(i);
    }
    let gone = (0..512).all(|k| {
        let (ip, port) = key(k);
        index_find(t, 6, &ip, port).is_none()
    });
    // 3. ADR 0067 E3: no new flow examined more than SWEEP entries (it was the whole table), and a slot
    //    `flush_wan` released is the next one handed out, with no sweep
    let scan_max = unsafe { SCAN_MAX };
    let bounded = scan_max as usize <= SWEEP;
    t[7].wan = [203, 0, 113, 7];
    let evicts = st.table_evict;
    let reuse = flush_wan([203, 0, 113, 7]) == 1
        && lookup_or_alloc(6, 0, &[0; 6], &[10, 98, 0, 1], 4242, 200_000, &mut st) == 7
        && st.table_evict == evicts;
    crate::perfctr::emit("nat_newflow_scan_max", scan_max as u64);
    let csum = csum_selftest();
    reset_all();
    let pass = fill && hits && consistent && gone && bounded && reuse && csum;
    crate::_print(format_args!(
        " [P-nat-index] {} — NAT table {} mappings with a hashed forward index (was 256 with a linear scan per packet): full table each flow in its own slot={} every lookup O(1) to its entry={} 512 evictions keep the index exact={} evicted keys no longer resolve={}\n",
        if pass { "PASS" } else { "FAIL" }, N, fill, hits, consistent, gone));
    crate::_print(format_args!(
        "   new-flow allocation (ADR 0067 E3): entries examined per new flow max={} bounded to {}={} a released slot is reused with no eviction={}\n",
        scan_max, SWEEP, bounded, reuse));
    pass
}
