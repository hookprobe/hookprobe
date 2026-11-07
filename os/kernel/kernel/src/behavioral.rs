//! M2.4 — L7 / behavioral OBSERVE-ONLY detectors (the LAST M2 detection-parity port).
//!
//! These detectors close the DETECTION half of the separation-matrix behavioral rows
//! (A10 beacon/lateral, L8 NTP-beacon exemption, plus exfil + DNS analytics). They are
//! **observe-only BY CONSTRUCTION** (CLAUDE.md / ADR 0023): a C2 beacon, an east-west
//! lateral sweep, a bulk-exfil flow, and a tunneled/DGA DNS name are all things the SOC
//! must SEE, but none is a suspicion-free confirmed drop — so every one routes through
//! `verdict::decide(FindingClass::Behavioral, …)`, which maps UNCONDITIONALLY to
//! `Verdict::Observe` (PASS on the wire). There is **zero legit-drop risk**: even a false
//! positive here only emits a SOAR alert, never a wire action. This mirrors the Linux
//! posture exactly — `napse_loader::{beacon,lateral}` run in the userspace observation
//! stream (`bin/napse-dpi.rs`), never in the tc-bpf drop fast-path.
//!
//! Parity source (Linux, metal-proven): `modules/napse-capture/loader/src/beacon.rs`
//! (rule 1000040), `.../lateral.rs` (1000041), the exfil rule (1000025), and the DNS
//! analytics band (1000002/1000021/1000011).
//!
//! `no_std` discipline (no float, no alloc): the Linux beacon uses a floating-point
//! coefficient-of-variation (stddev/mean). heqk has neither float nor `libm` in the
//! kernel, so this port uses an INTEGER mean-absolute-deviation proxy (`mad*100/mean`
//! vs a percentage bar) — a sound, slightly-more-permissive stand-in for CV that catches
//! a `sleep(N)+jitter%` implant while rejecting bursty/human traffic. This is an honest
//! heuristic, documented as such, not a claim of Shannon-entropy/statistical parity.
//!
//! State discipline (identical to M2.1–M2.3): direct-mapped, gen-tagged, windowed,
//! lock-free per-source/per-key tables; a colliding key EVICTS the slot's prior occupant
//! (never counts against it); `src == 0` (no IPv4 attribution) never accrues state, so
//! the datapath's src==0 short-circuit keeps PHprod/PH6-net green. Tests use isolated
//! ids (TEST-NET / RFC1918 ranges used nowhere else) and an injected clock where the
//! window boundary must be deterministic.

use core::sync::atomic::{AtomicU64, Ordering};

#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}
#[inline]
fn cntfrq() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Monotonic seconds since boot — the real-clock source for the live behavioral tier
/// (beacon needs a `now`). Same clock the internal detectors already use.
#[inline]
pub fn now_secs() -> u64 {
    cntpct() / cntfrq().max(1)
}

/// RFC1918 + loopback "internal" test on a HOST-ORDER IPv4 u32 — parity with
/// `napse_loader::lateral::is_private_ipv4` (which also treats 127/8 as private). Used by
/// the lateral (internal→internal) and exfil (internal→external) direction guards.
#[inline]
pub fn is_internal(ip: u32) -> bool {
    let o = ip.to_be_bytes();
    match o[0] {
        10 | 127 => true,
        172 => (16..=31).contains(&o[1]),
        192 => o[1] == 168,
        _ => false,
    }
}

// =====================================================================================
// BEACON (rule 1000040 / matrix A10 detection-half + L8 NTP exemption)
// Per-(src,dst,port) timing periodicity. Fires when connection inter-arrival intervals
// are both NUMEROUS (>= MIN_CONNECTIONS) and REGULAR (integer MAD/mean proxy for CV).
// NTP (dst port 123) is exempt FIRST, before any state is touched (FP guard #4 / L8).
// =====================================================================================

/// FP guard #2 parity — a couple of coincidental reconnects can't trip a pattern.
pub const BEACON_MIN_CONNECTIONS: u64 = 6;
/// Integer MAD/mean bar (percent). Parity intent with the Linux `max_cv = 0.15`: a
/// `sleep(N)+jitter%` loop clusters intervals within ~±15% of the mean; human/bursty
/// traffic sits far above. MAD <= stddev, so this is a marginally looser (safe, still
/// observe-only) integer proxy for the CV bar.
pub const BEACON_MAX_MAD_PCT: u64 = 15;
/// FP guard #3 parity — a rapid low-jitter retry storm (sub-interval) is NOT a beacon,
/// however regular. Real C2 sleeps are seconds-to-minutes. Same unit as the injected
/// `now` (whole "seconds" in the test / the live wrapper).
pub const BEACON_MIN_MEAN_INTERVAL: u64 = 8;
/// NTP — exempt by default regardless of how regular the interval (FP guard #4 / L8).
pub const BEACON_NTP_PORT: u16 = 123;

const BEACON_KEYS: usize = 256;
/// Ring depth: last N timestamps → up to N-1 intervals. 8 holds MIN_CONNECTIONS (6) with
/// headroom while keeping the per-key state tiny.
const BEACON_RING: usize = 8;

static BC_KEY: [AtomicU64; BEACON_KEYS] = [const { AtomicU64::new(0) }; BEACON_KEYS];
static BC_FILL: [AtomicU64; BEACON_KEYS] = [const { AtomicU64::new(0) }; BEACON_KEYS];
static BC_POS: [AtomicU64; BEACON_KEYS] = [const { AtomicU64::new(0) }; BEACON_KEYS];
static BC_TS: [[AtomicU64; BEACON_RING]; BEACON_KEYS] =
    [const { [const { AtomicU64::new(0) }; BEACON_RING] }; BEACON_KEYS];

/// Fold (src,dst,port) into a non-zero per-destination key (bit 48 set distinguishes any
/// real key from the empty-slot sentinel). Per-`(src,dst,port)` scoping mirrors the Linux
/// tracker: independent periodic services on one host are judged separately, never
/// conflated. Direct-mapped by `key % BEACON_KEYS`; a colliding key evicts (documented).
#[inline]
pub fn beacon_key(src: u32, dst: u32, port: u16) -> u64 {
    (((src as u64) ^ ((dst as u64) << 16) ^ ((port as u64) << 33)) & ((1u64 << 48) - 1)) | (1u64 << 48)
}

/// Beacon observe with an INJECTED clock (`now` in whole "seconds") — the deterministic,
/// QEMU-provable entry point. Returns `true` the moment this destination's interval
/// sequence reads as regular-enough beaconing. NTP (dst port 123) returns `false` FIRST,
/// touching no state (L8 exemption). `src == 0` never accrues state.
pub fn beacon_observe_at(src: u32, dst: u32, dst_port: u16, now: u64) -> bool {
    // FP guard #4 / matrix L8 — NTP is allowlisted before any state is touched.
    if dst_port == BEACON_NTP_PORT {
        return false;
    }
    if src == 0 {
        return false;
    }
    let key = beacon_key(src, dst, dst_port);
    let i = (key as usize) % BEACON_KEYS;
    // Collision-reset: a different (src,dst,port) aliasing this slot evicts the prior
    // occupant's ring so one destination's timing is never counted against another's.
    if BC_KEY[i].load(Ordering::Relaxed) != key {
        BC_KEY[i].store(key, Ordering::Relaxed);
        BC_FILL[i].store(0, Ordering::Relaxed);
        BC_POS[i].store(0, Ordering::Relaxed);
    }
    // Push `now` into the circular ring.
    let pos = BC_POS[i].load(Ordering::Relaxed) as usize % BEACON_RING;
    BC_TS[i][pos].store(now, Ordering::Relaxed);
    BC_POS[i].store(((pos + 1) % BEACON_RING) as u64, Ordering::Relaxed);
    let fill = {
        let f = BC_FILL[i].load(Ordering::Relaxed);
        let nf = (f + 1).min(BEACON_RING as u64);
        BC_FILL[i].store(nf, Ordering::Relaxed);
        nf
    };

    // FP guard #2 — not enough samples for the statistics to mean anything yet.
    if fill < BEACON_MIN_CONNECTIONS {
        return false;
    }

    // Reconstruct the ordered (oldest→newest) timestamps and their inter-arrival intervals.
    let head = BC_POS[i].load(Ordering::Relaxed) as usize; // one past the newest
    let fill_u = fill as usize;
    let mut prev = 0u64;
    let mut sum = 0u64;
    let n_int = fill_u - 1;
    // First pass: mean of intervals.
    for k in 0..fill_u {
        let idx = (head + BEACON_RING - fill_u + k) % BEACON_RING;
        let ts = BC_TS[i][idx].load(Ordering::Relaxed);
        if k > 0 {
            sum += ts.wrapping_sub(prev);
        }
        prev = ts;
    }
    let mean = sum / (n_int as u64);
    // FP guard #3 — exclude rapid retry-storm patterns regardless of jitter.
    if mean < BEACON_MIN_MEAN_INTERVAL {
        return false;
    }
    // Second pass: mean absolute deviation of the intervals.
    let mut mad_sum = 0u64;
    prev = 0;
    for k in 0..fill_u {
        let idx = (head + BEACON_RING - fill_u + k) % BEACON_RING;
        let ts = BC_TS[i][idx].load(Ordering::Relaxed);
        if k > 0 {
            let iv = ts.wrapping_sub(prev);
            mad_sum += if iv >= mean { iv - mean } else { mean - iv };
        }
        prev = ts;
    }
    let mad = mad_sum / (n_int as u64);
    // Regular enough? mad/mean <= MAX_MAD_PCT% (integer, div-safe: mean >= MIN_MEAN > 0).
    mad.saturating_mul(100) <= BEACON_MAX_MAD_PCT.saturating_mul(mean)
}

/// Live beacon observe — the metal wrapper on the ARM generic-counter clock, converting
/// `cntpct` ticks to whole seconds so the same integer bars apply. Honest note: beacon
/// periodicity only becomes visible over LONG windows (tens of minutes), so this live
/// path is real but slow to trip; the deterministic QEMU proof is `beacon_observe_at`.
/// Not exercised by the QEMU selftest (which injects the clock), hence `allow(dead_code)`
/// — it is the metal datapath entry point for when the observation stream is wired in.
#[allow(dead_code)]
pub fn beacon_observe(src: u32, dst: u32, dst_port: u16) -> bool {
    let secs = cntpct() / cntfrq().max(1);
    beacon_observe_at(src, dst, dst_port, secs)
}

// =====================================================================================
// LATERAL MOVEMENT (rule 1000041 / matrix A10 detection-half)
// One INTERNAL source fanning out across many DISTINCT INTERNAL peers on admin ports.
// FP guards (Linux parity): internal→internal only; distinct-PEER (not per-connection)
// threshold; short window; self-connections never count.
// =====================================================================================

/// Admin / remote-access ports lateral movement rides — SMB, RDP, VNC, WinRM(http/https),
/// SSH. Parity with `napse_loader::lateral::LATERAL_PORTS`.
pub const LATERAL_PORTS: &[u16] = &[22, 445, 3389, 5900, 5985, 5986];
/// Distinct internal peers (on any tracked port) within the window that trigger the
/// finding. Parity with `DEFAULT_LATERAL_THRESHOLD` (a normal client touches ONE file
/// server / jump host → distinct==1, can never cross this).
pub const LATERAL_THRESHOLD: u64 = 5;

const LAT_SRCS: usize = 64;
const LAT_PEER_SET: usize = 64;
/// A short window — a real sweep is fast (parity with `DEFAULT_LATERAL_WINDOW_SECS`=300s).
const LAT_WINDOW_SECS: u64 = 300;

static LAT_WIN: [AtomicU64; LAT_SRCS] = [const { AtomicU64::new(0) }; LAT_SRCS];
static LAT_GEN: [AtomicU64; LAT_SRCS] = [const { AtomicU64::new(1) }; LAT_SRCS];
static LAT_SRC: [AtomicU64; LAT_SRCS] = [const { AtomicU64::new(0) }; LAT_SRCS];
static LAT_DISTINCT: [AtomicU64; LAT_SRCS] = [const { AtomicU64::new(0) }; LAT_SRCS];
static LAT_PEER_GEN: [[AtomicU64; LAT_PEER_SET]; LAT_SRCS] =
    [const { [const { AtomicU64::new(0) }; LAT_PEER_SET] }; LAT_SRCS];
static LAT_PEER_KEY: [[AtomicU64; LAT_PEER_SET]; LAT_SRCS] =
    [const { [const { AtomicU64::new(0) }; LAT_PEER_SET] }; LAT_SRCS];

#[inline]
fn lat_is_tracked_port(port: u16) -> bool {
    let mut i = 0;
    while i < LATERAL_PORTS.len() {
        if LATERAL_PORTS[i] == port {
            return true;
        }
        i += 1;
    }
    false
}

#[inline]
fn lat_touch(src: u64) -> usize {
    let s = (src as usize) % LAT_SRCS;
    let now = cntpct();
    let win = cntfrq().max(1).saturating_mul(LAT_WINDOW_SECS);
    let start = LAT_WIN[s].load(Ordering::Relaxed);
    if LAT_SRC[s].load(Ordering::Relaxed) != src || now.wrapping_sub(start) >= win {
        LAT_SRC[s].store(src, Ordering::Relaxed);
        LAT_WIN[s].store(now, Ordering::Relaxed);
        LAT_GEN[s].fetch_add(1, Ordering::Relaxed);
        LAT_DISTINCT[s].store(0, Ordering::Relaxed);
    }
    s
}

/// Observe one internal→internal connection ATTEMPT on a tracked admin port; add the
/// distinct internal PEER to the source's window set; return `true` once the distinct
/// peer count EXCEEDS `LATERAL_THRESHOLD`. All FP guards applied before any state is
/// touched: non-tracked port, non-internal src/dst, or a self-connection returns `false`.
pub fn lateral_observe(src: u32, dst: u32, dst_port: u16) -> bool {
    if src == 0 {
        return false;
    }
    // FP guard #1/#4: tracked port, internal→internal, not a self-connection.
    if !lat_is_tracked_port(dst_port) || !is_internal(src) || !is_internal(dst) || src == dst {
        return false;
    }
    let s = lat_touch(src as u64);
    let gen = LAT_GEN[s].load(Ordering::Relaxed);
    let pk = (dst as u64) | (1u64 << 48); // non-zero peer key
    let i = (dst as usize) % LAT_PEER_SET;
    let seen = LAT_PEER_GEN[s][i].load(Ordering::Relaxed) == gen
        && LAT_PEER_KEY[s][i].load(Ordering::Relaxed) == pk;
    if !seen {
        LAT_PEER_GEN[s][i].store(gen, Ordering::Relaxed);
        LAT_PEER_KEY[s][i].store(pk, Ordering::Relaxed);
        LAT_DISTINCT[s].fetch_add(1, Ordering::Relaxed);
    }
    LAT_DISTINCT[s].load(Ordering::Relaxed) > LATERAL_THRESHOLD
}

/// Distinct internal-peer count for `src` this window (0 if evicted / unattributed) — for
/// the selftest / SIEM context.
pub fn lateral_distinct_peers(src: u32) -> u64 {
    if src == 0 {
        return 0;
    }
    let s = (src as usize) % LAT_SRCS;
    if LAT_SRC[s].load(Ordering::Relaxed) != src as u64 {
        return 0;
    }
    LAT_DISTINCT[s].load(Ordering::Relaxed)
}

// =====================================================================================
// EXFIL (rule 1000025 / bulk outbound volume) — anomalous OUTBOUND (internal→external)
// byte volume from one source within a window. Volume-based; the upload/download RATIO
// refinement needs bidirectional flow accounting heqk does not yet carry (deferred, §2).
// =====================================================================================

/// Bytes from one source (internal→external) within the window before it's flagged as a
/// bulk-exfil candidate. A conservative bar; observe-only, so a generous default only
/// affects alert volume, never the wire.
pub const EXFIL_BYTES_THRESH: u64 = 50_000_000; // 50 MB / window
const EXFIL_SRCS: usize = 64;
const EXFIL_WINDOW_SECS: u64 = 60;

static EX_WIN: [AtomicU64; EXFIL_SRCS] = [const { AtomicU64::new(0) }; EXFIL_SRCS];
static EX_SRC: [AtomicU64; EXFIL_SRCS] = [const { AtomicU64::new(0) }; EXFIL_SRCS];
static EX_BYTES: [AtomicU64; EXFIL_SRCS] = [const { AtomicU64::new(0) }; EXFIL_SRCS];

/// Observe `bytes` of OUTBOUND traffic from `src`. Direction guard: internal source,
/// EXTERNAL destination (an internal→internal transfer is not exfil; an inbound flow is
/// not either). Accumulates per-source per-window; returns `true` once the window total
/// EXCEEDS `EXFIL_BYTES_THRESH`. Self-reverting by the window.
pub fn exfil_observe(src: u32, dst: u32, bytes: u64) -> bool {
    if src == 0 {
        return false;
    }
    // Outbound only: internal src → external dst.
    if !is_internal(src) || is_internal(dst) {
        return false;
    }
    let s = (src as usize) % EXFIL_SRCS;
    let now = cntpct();
    let win = cntfrq().max(1).saturating_mul(EXFIL_WINDOW_SECS);
    let start = EX_WIN[s].load(Ordering::Relaxed);
    if EX_SRC[s].load(Ordering::Relaxed) != src as u64 || now.wrapping_sub(start) >= win {
        EX_SRC[s].store(src as u64, Ordering::Relaxed);
        EX_WIN[s].store(now, Ordering::Relaxed);
        EX_BYTES[s].store(bytes, Ordering::Relaxed);
        return bytes > EXFIL_BYTES_THRESH;
    }
    let total = EX_BYTES[s].fetch_add(bytes, Ordering::Relaxed) + bytes;
    total > EXFIL_BYTES_THRESH
}

// =====================================================================================
// DNS ANALYTICS (rules 1000002 / 1000021 / 1000011) — tunneling / DGA / high-entropy
// QNAME. FEASIBLE on heqk: `net::parse` locates the UDP L4 header; the DNS message
// follows the 8-byte UDP header, so the QNAME is parsable in-kernel. Heuristic (honest):
//   * TUNNELING — an excessively long total QNAME, or one very long label (base32/base64
//     data smuggled as a hostname).
//   * DGA / high-entropy — a long label whose byte-diversity is near its length AND that
//     mixes digits (the tell of an algorithmically-generated domain vs a dictionary word).
// DEFERRED (noted, not faked): true Shannon-entropy / n-gram / NN DGA scoring, and DNS
// name-compression-pointer following — this reads the QNAME up to the first pointer.
// =====================================================================================

pub const DNS_PORT: u16 = 53;
/// Total QNAME length above which the name is tunneling-shaped.
pub const DNS_TUNNEL_QNAME_LEN: usize = 100;
/// A single label longer than this is data-smuggling-shaped (base32/64 blob).
pub const DNS_TUNNEL_LABEL_LEN: usize = 50;
/// A label must be at least this long before DGA/entropy scoring applies.
pub const DNS_DGA_MIN_LABEL: usize = 12;

/// Analyze the QNAME of a DNS query/response frame. `None` = not a DNS packet (or
/// unparseable) — the caller emits nothing. `Some(true)` = tunneling/DGA/high-entropy
/// shaped; `Some(false)` = a normal-looking name. Pure, stateless, bounds-checked
/// (`.get()` everywhere) — no OOB on a crafted/truncated frame.
pub fn dns_qname_anomaly(frame: &[u8]) -> Option<bool> {
    let meta = crate::net::parse(frame)?;
    if meta.ip_proto != crate::net::IPPROTO_UDP || !meta.has_l4_ports() {
        return None;
    }
    if meta.dst_port != DNS_PORT && meta.src_port != DNS_PORT {
        return None;
    }
    // DNS message = UDP payload = l4_off + 8 (UDP header). Need the 12-byte DNS header.
    let dns = meta.l4_off + 8;
    if dns + 12 > frame.len() {
        return None;
    }
    // QNAME begins right after the fixed 12-byte header.
    let mut off = dns + 12;
    let mut total_len = 0usize;
    let mut longest_len = 0usize;
    let mut longest_distinct = 0u32;
    let mut longest_digits = 0usize;
    // Bound the label walk (a legit QNAME has few labels; this also caps a hostile loop).
    for _ in 0..64 {
        let len = *frame.get(off)? as usize;
        if len == 0 {
            break; // end of name
        }
        if len & 0xc0 != 0 {
            break; // compression pointer / reserved — stop (deferred: pointer following)
        }
        let label = frame.get(off + 1..off + 1 + len)?;
        total_len += len + 1;
        if len > longest_len {
            longest_len = len;
            // Byte-diversity (distinct byte values) + digit count over this label.
            let mut seen = [0u64; 4]; // 256-bit presence bitset, no alloc
            let mut distinct = 0u32;
            let mut digits = 0usize;
            for &b in label {
                let w = (b >> 6) as usize;
                let bit = 1u64 << (b & 0x3f);
                if seen[w] & bit == 0 {
                    seen[w] |= bit;
                    distinct += 1;
                }
                if b.is_ascii_digit() {
                    digits += 1;
                }
            }
            longest_distinct = distinct;
            longest_digits = digits;
        }
        off += 1 + len;
    }

    // TUNNELING — an over-long total name or a single over-long label.
    if total_len > DNS_TUNNEL_QNAME_LEN || longest_len > DNS_TUNNEL_LABEL_LEN {
        return Some(true);
    }
    // DGA / high-entropy — a long label whose byte-diversity is near its length AND that
    // mixes in digits (dictionary words are low-diversity and rarely digit-laden).
    if longest_len >= DNS_DGA_MIN_LABEL
        && (longest_distinct as usize) * 4 >= longest_len * 3
        && longest_digits * 4 >= longest_len
    {
        return Some(true);
    }
    Some(false)
}

// ---- test-only reset hooks (isolate the injected-clock beacon table between assertions)
#[cfg(not(feature = "cm5"))]
pub fn beacon_reset_for_test() {
    let mut i = 0;
    while i < BEACON_KEYS {
        BC_KEY[i].store(0, Ordering::Relaxed);
        BC_FILL[i].store(0, Ordering::Relaxed);
        BC_POS[i].store(0, Ordering::Relaxed);
        i += 1;
    }
}
