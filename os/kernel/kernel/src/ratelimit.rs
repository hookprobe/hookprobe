//! P8 — stateful detection substrate: a fixed-window per-key rate limiter, the
//! FIRST BPF helper (kernel-owned state a signed rule can consult via a `CALL`).
//! This is what single-packet rules can't do — decide on a RATE. It unlocks the
//! stateful WAN tier: SYN-flood rate-limit (first user), and later connection-
//! rate limiting, an LPM threat-feed blocklist, and conntrack-style flow state.
//!
//! v1 keys into a small fixed table and windows on the ARM generic counter
//! (`cntpct_el0`, ~1 s per `cntfrq_el0`). The BPF `CALL` opcode dispatches here;
//! the JIT declines programs that use `CALL` (interpreter-only), which is fine —
//! rate-checked packets (SYNs) are a small fraction of the datapath.

use core::sync::atomic::{AtomicU64, Ordering};

// DET-5/XC-12: a per-slot KEY tag turns the shared `key % SLOTS` counters into
// per-key state. Without it, distinct sources that alias the same slot share a
// counter: an attacker could pick a source IP colliding with a victim's and inflate
// the victim's SYN budget (false DROP / targeted DoS) or deflate his own across
// non-colliding keys. Larger table + tag makes collisions rare and, when they do
// happen, a mismatch RESETS the slot to the new key so one key's traffic can never
// be counted against another's. Residual (documented): a colliding key can still
// EVICT another's in-flight window — acceptable vs the count-min complexity at this
// tier; enlarge SLOTS or move to a sketch if that eviction ever matters.
const SLOTS: usize = 256; // power of two
static WIN_START: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static COUNT: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static KEY: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];

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

/// Fixed-window rate check: bump `key`'s counter and return 1 if the count now
/// EXCEEDS `limit` within the current ~1 s window, else 0. The window resets once
/// `cntfrq` ticks have elapsed since it opened, so a sustained flood trips it but
/// a normal low rate never accumulates across windows.
pub fn syn_rate_over(key: u64, limit: u64) -> u64 {
    let i = (key as usize) % SLOTS;
    let now = cntpct();
    let win = cntfrq().max(1); // ~1 second in counter ticks
    let start = WIN_START[i].load(Ordering::Relaxed);
    // DET-5/XC-12: reset the slot for a NEW window OR when a different key aliases
    // this slot — so one source's SYNs are never counted against another's.
    if KEY[i].load(Ordering::Relaxed) != key || now.wrapping_sub(start) >= win {
        KEY[i].store(key, Ordering::Relaxed);
        WIN_START[i].store(now, Ordering::Relaxed);
        COUNT[i].store(1, Ordering::Relaxed);
        return 0;
    }
    let c = COUNT[i].fetch_add(1, Ordering::Relaxed) + 1;
    if c > limit {
        1
    } else {
        0
    }
}

/// BPF `CALL` (opcode 0x85) dispatch: `R0 = helper(imm)(R1, R2)`. Only signed,
/// verifier-approved helper ids are reachable; an unknown id returns a benign 0
/// (the verifier already rejects programs that call an unknown helper).
pub fn call_helper(id: u32, r1: u64, r2: u64) -> u64 {
    match id {
        HELPER_SYN_RATE_OVER => syn_rate_over(r1, r2),
        HELPER_IP_BLOCKED => crate::blocklist::ip_blocked(r1),
        HELPER_PAYLOAD_MATCH => crate::l7::payload_match(r1, r2),
        _ => 0,
    }
}

/// Helper id: `R0 = syn_rate_over(R1=key, R2=limit)`.
pub const HELPER_SYN_RATE_OVER: u32 = 1;
/// Helper id: `R0 = ip_blocked(R1=IP source)` — threat-feed blocklist lookup.
pub const HELPER_IP_BLOCKED: u32 = 2;
/// Helper id: `R0 = payload_match(R1=ptr, R2=pattern_id)` — L7 signature match.
pub const HELPER_PAYLOAD_MATCH: u32 = 3;
/// Highest valid helper id (the verifier bounds `CALL imm` by this).
pub const MAX_HELPER_ID: u32 = 3;

// =====================================================================================
// M2.1 — L2 fan-out state (the SEED of the M2.2 flow table, scoped to exactly what
// mac-flood + broadcast-storm need). Per-PORT, windowed, `no_std`, lock-free.
// =====================================================================================

/// How many ports carry independent fan-out state (QEMU has one NIC = port 0; tests
/// use higher ids to stay isolated). Sourced per-interface from the manifest in
/// production (M2 follow-on).
const FANOUT_PORTS: usize = 8;
/// Per-port direct-mapped distinct-source-MAC set (gen-tagged so a new window costs
/// O(1), never an O(N) clear). 512 slots hold the uplink/AP bar (>300) with headroom.
const MAC_SET: usize = 512;
/// The fan-out measurement window (distinct MACs / broadcast rate accrue over this).
const FANOUT_WINDOW_SECS: u64 = 10;

static MAC_WIN: [AtomicU64; FANOUT_PORTS] = [const { AtomicU64::new(0) }; FANOUT_PORTS];
static MAC_GEN: [AtomicU64; FANOUT_PORTS] = [const { AtomicU64::new(1) }; FANOUT_PORTS];
static MAC_DISTINCT: [AtomicU64; FANOUT_PORTS] = [const { AtomicU64::new(0) }; FANOUT_PORTS];
static MAC_SLOT_GEN: [[AtomicU64; MAC_SET]; FANOUT_PORTS] =
    [const { [const { AtomicU64::new(0) }; MAC_SET] }; FANOUT_PORTS];
static MAC_SLOT_KEY: [[AtomicU64; MAC_SET]; FANOUT_PORTS] =
    [const { [const { AtomicU64::new(0) }; MAC_SET] }; FANOUT_PORTS];

static BCAST_WIN: [AtomicU64; FANOUT_PORTS] = [const { AtomicU64::new(0) }; FANOUT_PORTS];
static BCAST_COUNT: [AtomicU64; FANOUT_PORTS] = [const { AtomicU64::new(0) }; FANOUT_PORTS];

/// Fold a 6-byte MAC into a non-zero u64 key (bit 48 set distinguishes any real MAC
/// from the `0` empty-slot sentinel).
pub fn mac_hash(mac: &[u8]) -> u64 {
    let mut h = 0u64;
    for (i, &b) in mac.iter().take(6).enumerate() {
        h |= (b as u64) << (i * 8);
    }
    h | (1u64 << 48)
}

/// mac-flood: count DISTINCT source MACs seen on `port` within the window; return 1
/// once the distinct count EXCEEDS `threshold`, else 0. A new window bumps the port's
/// generation (O(1), invalidating every slot) and resets the distinct count, so a
/// sustained fan-out trips it but ordinary churn never accumulates across windows.
pub fn mac_flood_over(port: u64, mac_key: u64, threshold: u64) -> u64 {
    let p = (port as usize) % FANOUT_PORTS;
    let now = cntpct();
    let win = cntfrq().max(1).saturating_mul(FANOUT_WINDOW_SECS);
    let start = MAC_WIN[p].load(Ordering::Relaxed);
    if now.wrapping_sub(start) >= win {
        MAC_WIN[p].store(now, Ordering::Relaxed);
        MAC_GEN[p].fetch_add(1, Ordering::Relaxed);
        MAC_DISTINCT[p].store(0, Ordering::Relaxed);
    }
    let gen = MAC_GEN[p].load(Ordering::Relaxed);
    let i = (mac_key as usize) % MAC_SET;
    let seen = MAC_SLOT_GEN[p][i].load(Ordering::Relaxed) == gen
        && MAC_SLOT_KEY[p][i].load(Ordering::Relaxed) == mac_key;
    if !seen {
        MAC_SLOT_GEN[p][i].store(gen, Ordering::Relaxed);
        MAC_SLOT_KEY[p][i].store(mac_key, Ordering::Relaxed);
        MAC_DISTINCT[p].fetch_add(1, Ordering::Relaxed);
    }
    if MAC_DISTINCT[p].load(Ordering::Relaxed) > threshold {
        1
    } else {
        0
    }
}

/// broadcast-storm: count broadcast/multicast frames on `port` within the window;
/// return 1 once the count EXCEEDS `threshold`. The caller pre-filters exempt groups
/// (mDNS/SSDP/LLMNR) so they never even reach this counter.
pub fn bcast_over(port: u64, threshold: u64) -> u64 {
    let p = (port as usize) % FANOUT_PORTS;
    let now = cntpct();
    let win = cntfrq().max(1).saturating_mul(FANOUT_WINDOW_SECS);
    let start = BCAST_WIN[p].load(Ordering::Relaxed);
    if now.wrapping_sub(start) >= win {
        BCAST_WIN[p].store(now, Ordering::Relaxed);
        BCAST_COUNT[p].store(1, Ordering::Relaxed);
        return 0;
    }
    let c = BCAST_COUNT[p].fetch_add(1, Ordering::Relaxed) + 1;
    if c > threshold {
        1
    } else {
        0
    }
}

// =====================================================================================
// M2.2 — FLOW STATE (the conntrack-equivalent). Per-SOURCE state, gen-tagged + windowed
// exactly like the M2.1 mac-flood seed, but keyed on the L3 IPv4 source. Two facts per
// source: a DISTINCT SYN-only dst-port set (rule 1000003 port-scan counter), and an
// ESTABLISHED-flow count (heqk's handshake-completed signal — the ADR-0018 confirmation
// input `decide()` needs). Plus a pure flow-table saturation evaluator (A7 signal).
//
// LEGIT-SAFETY KEYSTONE. Every escalation below is gated on `est == 0` (zero
// established flows). An ESTABLISHED (handshake-completed) flow is definitionally NOT a
// scan, so a legit busy source — a NAS with 150 concurrent established flows, a phone
// doing a 100/s web-load burst — can NEVER cross the RateLimit or Confirm bar, however
// many distinct ports its SYNs briefly touch. The verdict keys on scan SHAPE (SYN-only
// to many distinct ports WITHOUT establishment), never on flow COUNT. This deliberately
// favors MISSING a scanner that found one open port over DROPPING a legit source — the
// operator's hard rule (ADR 0023): a legitimate customer connection must ALWAYS pass.
// =====================================================================================

/// Distinct source slots (direct-mapped by IP low bits, gen-tagged, collision-reset —
/// a colliding source EVICTS the slot's prior occupant, never counts against it).
const FLOW_SRCS: usize = 16;
/// Per-source distinct-dst-port set (gen-tagged so a new window is an O(1) generation
/// bump, never an O(N) clear). 256 slots hold the confirm bar (>=100) with headroom.
const SCAN_PORT_SET: usize = 256;
/// The scan measurement window (distinct SYN-only ports accrue over this).
const SCAN_WINDOW_SECS: u64 = 10;

/// Distinct SYN-only dst-port bars (rule 1000003 parity). Crossing RATELIMIT (with zero
/// establishment) is a bounded, self-reverting cap; crossing the higher CONFIRM bar
/// (still zero establishment) is a durable Quarantine — a thorough sweep is stronger
/// evidence, and the anti-spoof cost of a durable block is only paid once confirmation
/// is unambiguous.
pub const SCAN_PORTS_RATELIMIT: u64 = 50;
pub const SCAN_PORTS_CONFIRM: u64 = 100;
/// Establishment holds scan escalation off only when it is SUBSTANTIAL relative to the sweep:
/// `established × RATIO >= distinct answered ports`, where "established" = distinct ports with a real
/// handshake (target SYN-ACK seen, then the source's ACK — ADR 0049 D3). (Audit 2026-10-08 "connect-scan gap": the hold used to
/// be `established == 0`, so a connect() scan that completed ONE handshake on an open port — or a scanner
/// that opened one real connection first — disabled detection for the whole window.) A legit busy host
/// (many established segments, few distinct SYN ports) stays held; zero establishment = unchanged.
pub const SCAN_EST_RATIO: u64 = 8;

/// Blanket per-source new-connection rate ceiling — parity with the Linux
/// `scan_responder::DEFAULT_NEW_CONN_PPS`. A legit heavy burst (~100/s) sits far under
/// it; the self-reverting meter that ENFORCES this is M2.3 (here it is the reconciled
/// cap VALUE only, so a legit burst is provably under the wall).
pub const DEFAULT_NEW_CONN_PPS: u64 = 400;

/// The flow-table saturation shed wall (A7 / L9), a RESOURCE-REALITY percentage — never
/// keyed on identity. The self-reverting per-source top-talker shed ACTION is M2.3; M2.2
/// supplies the SIGNAL + the verdict map only.
pub const SATURATION_SHED_PCT: u64 = 80;

static SCAN_WIN: [AtomicU64; FLOW_SRCS] = [const { AtomicU64::new(0) }; FLOW_SRCS];
static SCAN_GEN: [AtomicU64; FLOW_SRCS] = [const { AtomicU64::new(1) }; FLOW_SRCS];
static SCAN_SRC: [AtomicU64; FLOW_SRCS] = [const { AtomicU64::new(0) }; FLOW_SRCS];
static SCAN_DISTINCT: [AtomicU64; FLOW_SRCS] = [const { AtomicU64::new(0) }; FLOW_SRCS];
static SCAN_EST: [AtomicU64; FLOW_SRCS] = [const { AtomicU64::new(0) }; FLOW_SRCS];
static SCAN_PORT_GEN: [[AtomicU64; SCAN_PORT_SET]; FLOW_SRCS] =
    [const { [const { AtomicU64::new(0) }; SCAN_PORT_SET] }; FLOW_SRCS];
static SCAN_PORT_KEY: [[AtomicU64; SCAN_PORT_SET]; FLOW_SRCS] =
    [const { [const { AtomicU64::new(0) }; SCAN_PORT_SET] }; FLOW_SRCS];
/// ADR 0049 D3 — per (source, port) evidence bits, valid when the entry's gen + key match.
static SCAN_PORT_FLAGS: [[AtomicU64; SCAN_PORT_SET]; FLOW_SRCS] =
    [const { [const { AtomicU64::new(0) }; SCAN_PORT_SET] }; FLOW_SRCS];
const P_SYN: u64 = 1; // the source sent a SYN-only probe to this port
const P_ANS: u64 = 2; // the target answered it (RST or SYN-ACK) — or the target is this device
const P_SYNACK: u64 = 4; // the target accepted (SYN-ACK seen)
const P_EST: u64 = 8; // the source ACKed after the SYN-ACK: a real handshake (credit, once per port)

/// This device's own addresses (WAN lease, AP / LAN address, management address): a probe to one of them
/// needs no observed response — the device knows its own port state (ADR 0049 D3).
static LOCAL_IPS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// Register (or clear with 0) local address slot `i` (host-order IPv4).
pub fn set_local_ip(i: usize, ip: u32) {
    if let Some(a) = LOCAL_IPS.get(i) {
        a.store(ip as u64, Ordering::Relaxed);
    }
}

pub fn is_local_ip(ip: u32) -> bool {
    ip != 0 && LOCAL_IPS.iter().any(|a| a.load(Ordering::Relaxed) == ip as u64)
}

/// The GLOBAL flow-table occupancy GAUGE (the conntrack-equivalent fill) behind the A7
/// saturation signal. heqk tracks no teardown, so occupancy is measured as NEW flows
/// (SYN-only segments) inside a sliding `FLOW_IDLE_SECS` horizon — two buckets, the
/// previous one weighted by its remaining overlap. It DECAYS on its own: once new-flow
/// arrivals stop, the gauge reaches 0 within 2×horizon, so the shed self-reverts.
///
/// (Was a lifetime counter bumped on every ACK-bearing segment and never decremented:
/// ~80k ACKs — one large download — latched `saturated` true until reboot and turned the
/// shed into a durable legit-drop, violating ADR 0023.)
pub const FLOW_IDLE_SECS: u64 = 60;
static FLOW_BUCKET_START: AtomicU64 = AtomicU64::new(0);
static FLOW_CUR: AtomicU64 = AtomicU64::new(0);
static FLOW_PREV: AtomicU64 = AtomicU64::new(0);

/// Advance the two-bucket window to `now`; returns ticks elapsed in the current bucket.
#[inline]
fn flow_roll(now: u64, win: u64) -> u64 {
    let start = FLOW_BUCKET_START.load(Ordering::Relaxed);
    let el = now.wrapping_sub(start);
    if el >= win.saturating_mul(2) {
        FLOW_PREV.store(0, Ordering::Relaxed);
        FLOW_CUR.store(0, Ordering::Relaxed);
        FLOW_BUCKET_START.store(now, Ordering::Relaxed);
        0
    } else if el >= win {
        FLOW_PREV.store(FLOW_CUR.load(Ordering::Relaxed), Ordering::Relaxed);
        FLOW_CUR.store(0, Ordering::Relaxed);
        FLOW_BUCKET_START.store(start.wrapping_add(win), Ordering::Relaxed);
        el - win
    } else {
        el
    }
}

/// Record a NEW flow (a SYN-only connection attempt) at an INJECTED clock.
pub fn flow_new_at(now: u64, win: u64) {
    flow_roll(now, win);
    FLOW_CUR.fetch_add(1, Ordering::Relaxed);
}

/// Occupancy gauge at an INJECTED clock (so the decay is QEMU-provable without sleeping).
pub fn flow_count_at(now: u64, win: u64) -> u64 {
    let win = win.max(1);
    let el = flow_roll(now, win);
    let prev = FLOW_PREV.load(Ordering::Relaxed);
    FLOW_CUR.load(Ordering::Relaxed) + prev.saturating_mul(win - el.min(win)) / win
}

#[inline]
fn flow_win() -> u64 {
    cntfrq().max(1).saturating_mul(FLOW_IDLE_SECS)
}

/// Record a new flow on the live ARM generic-counter clock.
pub fn flow_new() {
    flow_new_at(cntpct(), flow_win());
}

/// Locate + refresh source `src`'s slot for the CURRENT window. A new source aliasing
/// the slot, or an expired window, resets the slot (generation bump invalidates the
/// distinct-port set in O(1), and the distinct + established counters reset). Mirrors the
/// `syn_rate_over` / `mac_flood_over` collision-reset discipline so one source's state is
/// never counted against another's.
#[inline]
fn touch_scan_slot(src: u64) -> usize {
    let s = (src as usize) % FLOW_SRCS;
    let now = cntpct();
    let win = cntfrq().max(1).saturating_mul(SCAN_WINDOW_SECS);
    let start = SCAN_WIN[s].load(Ordering::Relaxed);
    if SCAN_SRC[s].load(Ordering::Relaxed) != src || now.wrapping_sub(start) >= win {
        SCAN_SRC[s].store(src, Ordering::Relaxed);
        SCAN_WIN[s].store(now, Ordering::Relaxed);
        SCAN_GEN[s].fetch_add(1, Ordering::Relaxed);
        SCAN_DISTINCT[s].store(0, Ordering::Relaxed);
        SCAN_EST[s].store(0, Ordering::Relaxed);
    }
    s
}

/// The port entry for `dst_port` in slot `s` (current generation), created when `create`.
fn port_entry(s: usize, dst_port: u16, create: bool) -> Option<usize> {
    let gen = SCAN_GEN[s].load(Ordering::Relaxed);
    let pk = (dst_port as u64) | (1u64 << 48); // non-zero key (port 0 is a real port)
    let i = (dst_port as usize) % SCAN_PORT_SET;
    let live = SCAN_PORT_GEN[s][i].load(Ordering::Relaxed) == gen && SCAN_PORT_KEY[s][i].load(Ordering::Relaxed) == pk;
    if live {
        return Some(i);
    }
    if !create {
        return None;
    }
    SCAN_PORT_GEN[s][i].store(gen, Ordering::Relaxed);
    SCAN_PORT_KEY[s][i].store(pk, Ordering::Relaxed);
    SCAN_PORT_FLAGS[s][i].store(0, Ordering::Relaxed);
    Some(i)
}

/// Set `bit` on the entry; returns true if it was newly set.
fn set_flag(s: usize, i: usize, bit: u64) -> bool {
    SCAN_PORT_FLAGS[s][i].fetch_or(bit, Ordering::Relaxed) & bit == 0
}

/// Record a SYN-only probe from `src` to `dst_port` (host-order IPv4). ADR 0049 D3: the port COUNTS toward
/// the scan only once the target is seen answering (`scan_response_observe`) — or at once when the target is
/// this device (`local_target`). One-sided / spoofed SYN traffic never counts. Returns the distinct
/// answered-probe count.
pub fn syn_scan_observe(src: u64, dst_port: u16, local_target: bool) -> u64 {
    if src == 0 {
        return 0;
    }
    let s = touch_scan_slot(src);
    if let Some(i) = port_entry(s, dst_port, true) {
        set_flag(s, i, P_SYN);
        if local_target && set_flag(s, i, P_ANS) {
            SCAN_DISTINCT[s].fetch_add(1, Ordering::Relaxed);
        }
    }
    SCAN_DISTINCT[s].load(Ordering::Relaxed)
}

/// The TARGET answered `scanner`'s probe to `port`: an RST (closed) or a SYN-ACK (`synack`, open). Only an
/// outstanding probe in the scanner's current window is credited — an unsolicited response creates nothing.
pub fn scan_response_observe(scanner: u64, port: u16, synack: bool) {
    if scanner == 0 {
        return;
    }
    let s = (scanner as usize) % FLOW_SRCS;
    if SCAN_SRC[s].load(Ordering::Relaxed) != scanner {
        return;
    }
    let Some(i) = port_entry(s, port, false) else { return };
    if SCAN_PORT_FLAGS[s][i].load(Ordering::Relaxed) & P_SYN == 0 {
        return;
    }
    if set_flag(s, i, P_ANS) {
        SCAN_DISTINCT[s].fetch_add(1, Ordering::Relaxed);
    }
    if synack {
        set_flag(s, i, P_SYNACK);
    }
}

/// An ACK from `src` to `dst_port`. ADR 0049 D3: it earns establishment credit ONLY after the target's
/// SYN-ACK was seen for that port, and only once per port — stray ACKs (the padding evasion) earn nothing.
pub fn flow_ack_observe(src: u64, dst_port: u16) {
    if src == 0 {
        return;
    }
    let s = (src as usize) % FLOW_SRCS;
    if SCAN_SRC[s].load(Ordering::Relaxed) != src {
        return;
    }
    let Some(i) = port_entry(s, dst_port, false) else { return };
    if SCAN_PORT_FLAGS[s][i].load(Ordering::Relaxed) & P_SYNACK != 0 && set_flag(s, i, P_EST) {
        SCAN_EST[s].fetch_add(1, Ordering::Relaxed);
    }
}

/// Distinct ANSWERED-probe dst-port count for `src` in the current window (0 if the slot was
/// evicted by another source, or no attribution).
pub fn scan_distinct_ports(src: u64) -> u64 {
    if src == 0 {
        return 0;
    }
    let s = (src as usize) % FLOW_SRCS;
    if SCAN_SRC[s].load(Ordering::Relaxed) != src {
        return 0;
    }
    SCAN_DISTINCT[s].load(Ordering::Relaxed)
}

/// Established-flow count for `src` in the current window (0 if evicted / unattributed).
pub fn flow_established_count(src: u64) -> u64 {
    if src == 0 {
        return 0;
    }
    let s = (src as usize) % FLOW_SRCS;
    if SCAN_SRC[s].load(Ordering::Relaxed) != src {
        return 0;
    }
    SCAN_EST[s].load(Ordering::Relaxed)
}

/// The bounded-RateLimit gate: a SYN-only distinct-port scan crossed the RATELIMIT bar
/// WITH ZERO establishment. Keyed on scan SHAPE + no-establishment, never flow count.
pub fn scan_over_ratelimit(src: u64) -> bool {
    let d = scan_distinct_ports(src);
    d >= SCAN_PORTS_RATELIMIT && flow_established_count(src).saturating_mul(SCAN_EST_RATIO) < d
}

/// The ADR-0018 CONFIRMATION signal for a durable Quarantine: a SYN-only sweep to
/// >= CONFIRM distinct ports from one source WITH ZERO establishment. Any establishment
/// (a single completed handshake) holds this at `false` forever within the window — this
/// is precisely why a legit busy source (150 established flows) can NEVER be confirmed.
pub fn scan_confirmed(src: u64) -> bool {
    let d = scan_distinct_ports(src);
    d >= SCAN_PORTS_CONFIRM && flow_established_count(src).saturating_mul(SCAN_EST_RATIO) < d
}

/// Live flow-table fill as a percentage (0..=100) — the A7 conntrack-saturation SIGNAL.
pub fn flow_saturation_pct() -> u64 {
    saturation_pct(flow_count(), flow_table_max())
}

/// Live flow-table occupancy count — the A7 saturation numerator, for the datapath's
/// per-frame `resource_shed_verdict`.
#[inline]
pub fn flow_count() -> u64 {
    flow_count_at(cntpct(), flow_win())
}

/// The logical flow-table capacity used for the live saturation percentage. Sourced from
/// the manifest per-platform in production (M2 follow-on); a conservative default here.
#[inline]
pub fn flow_table_max() -> u64 {
    100_000
}

/// Pure, deterministic saturation evaluator (mirrors the Linux
/// `evaluate_resource_reality` conntrack ratio): `count/max` as a percentage. Used by the
/// verdict map + selftest so the A7/L9 rows are provable without wall-clock/global state.
pub fn saturation_pct(count: u64, max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    count.saturating_mul(100) / max
}

/// Does the flow-table fill cross the resource-reality shed wall (>= 80%)? Keyed on
/// RESOURCE REALITY (table fill), never identity — a legit busy source in an un-saturated
/// table (L9) is never a shed candidate.
pub fn table_saturated(count: u64, max: u64) -> bool {
    saturation_pct(count, max) >= SATURATION_SHED_PCT
}

// =====================================================================================
// M2.3 — RESOURCE-SHED. ADR 0023's FOURTH suspicion-free inline drop: a SELF-REVERTING
// drop keyed on MEASURED RESOURCE REALITY (rate / table-fill / scheduler pressure),
// NEVER on identity. This is where the M2.2 saturation SIGNAL becomes a shed ACTION and
// where a `RateLimit` gets its self-reverting wire meter. Three layers (Linux parity):
//   L1 — a blanket per-source new-connection-rate cap (self-reverting by the ~1s window)
//   L2 — a conntrack-saturation top-talker shed (self-reverting as the table drains)
//   L3 — a heqk-native PSI-equivalent scheduler-pressure shed (top-talker sheds first)
// EVERY shed routes through `decide()` (FloodRate → RateLimit{over_limit}); the mgmt
// `Allowlisted` floor short-circuits there, so a mgmt source is NEVER shed however hot.
// The TRIGGERS below are deliberately IDENTITY-BLIND (they measure only rate/fill/
// pressure + a source's measured SHARE); the floor is applied at the verdict layer.
// =====================================================================================

// ---- L1: the blanket per-source new-connection-rate cap ----

/// Per-source new-conn meter slots (direct-mapped, collision-reset like `syn_rate_over`).
const CR_SLOTS: usize = 256;
static CR_WIN: [AtomicU64; CR_SLOTS] = [const { AtomicU64::new(0) }; CR_SLOTS];
static CR_KEY: [AtomicU64; CR_SLOTS] = [const { AtomicU64::new(0) }; CR_SLOTS];
static CR_COUNT: [AtomicU64; CR_SLOTS] = [const { AtomicU64::new(0) }; CR_SLOTS];

/// L1 core — the windowed per-source new-conn meter with an INJECTED clock (so the
/// self-revert property is deterministically provable in QEMU without a wall-clock
/// sleep). Bumps `src`'s counter; returns true iff it now EXCEEDS `cap` within the
/// window `[start, start+win)`. SELF-REVERTING: crossing a window boundary
/// (`now - start >= win`) resets the counter to 1, so a source back under `cap` next
/// window immediately returns false (PASS) — the shed reverts the instant the rate
/// falls, never a durable block. Keyed on RATE reality; `src == 0` never sheds.
pub fn conn_rate_over_at(src: u64, cap: u64, now: u64, win: u64) -> bool {
    if src == 0 {
        return false;
    }
    let i = (src as usize) % CR_SLOTS;
    let start = CR_WIN[i].load(Ordering::Relaxed);
    if CR_KEY[i].load(Ordering::Relaxed) != src || now.wrapping_sub(start) >= win {
        CR_KEY[i].store(src, Ordering::Relaxed);
        CR_WIN[i].store(now, Ordering::Relaxed);
        CR_COUNT[i].store(1, Ordering::Relaxed);
        return false; // first conn of a fresh window is always under cap
    }
    let c = CR_COUNT[i].fetch_add(1, Ordering::Relaxed) + 1;
    c > cap
}

/// L1 live wrapper — the blanket new-conn-rate cap on the real ARM generic-counter clock
/// (~1 s window). `cap` is `DEFAULT_NEW_CONN_PPS` (400/s) at the call site; a legit heavy
/// burst (~100/s) sits far under it.
pub fn conn_rate_over(src: u64, cap: u64) -> bool {
    conn_rate_over_at(src, cap, cntpct(), cntfrq().max(1))
}

// ---- A9-3: per-(port, source-MAC) Router-Advertisement rate meter (RFC 4861 pacing) ----
//
// The security-auditor A9 ruling (heqk-detection-parity.md §5, 2026-09-11) embargoes the
// first-sight Access-port RA FrameDrop but APPROVES this arm now, on any port: a legit
// router paces its RAs (MinRtrAdvInterval >= 3 s, MIN_DELAY_BETWEEN_RAS 3 s, 3 initial
// RAs <= 16 s apart per RFC 4861 §6.2.4/§6.2.6) so it emits at most ~4 per 10 s even
// while answering solicitations; `fake_router6`/`mitm6` flood hundreds per second. So
// the count EXCEEDING `RA_FLOOD_THRESH` in a `RA_FLOOD_WINDOW_SECS` window is RATE
// REALITY (ADR 0023 D3), identity-blind, self-reverting at the window boundary, and it
// isolates the flooder: the meter is keyed on (port, src MAC), so a legit router beside
// a flooder on the same port keeps its own under-threshold budget.

const RA_SLOTS: usize = 64;
static RA_WIN: [AtomicU64; RA_SLOTS] = [const { AtomicU64::new(0) }; RA_SLOTS];
static RA_KEY: [AtomicU64; RA_SLOTS] = [const { AtomicU64::new(0) }; RA_SLOTS];
static RA_COUNT: [AtomicU64; RA_SLOTS] = [const { AtomicU64::new(0) }; RA_SLOTS];
/// RAs per window per (port, src MAC) before it is a flood — 2.5x the RFC 4861 maximum
/// legit pacing (~4 per 10 s), 1-2 orders below any flooding tool.
pub const RA_FLOOD_THRESH: u64 = 10;
pub const RA_FLOOD_WINDOW_SECS: u64 = 10;

/// RA meter core with an INJECTED clock (deterministic self-revert proof in QEMU, as
/// `conn_rate_over_at`). Bumps `key`'s counter; true iff it now EXCEEDS `limit` within
/// `[start, start+win)`. A new window or a slot re-keyed by an aliasing key resets to
/// 1 (never counts one key's RAs against another's). `key == 0` never trips.
pub fn ra_rate_over_at(key: u64, limit: u64, now: u64, win: u64) -> bool {
    if key == 0 {
        return false;
    }
    let i = (key as usize) % RA_SLOTS;
    let start = RA_WIN[i].load(Ordering::Relaxed);
    if RA_KEY[i].load(Ordering::Relaxed) != key || now.wrapping_sub(start) >= win {
        RA_KEY[i].store(key, Ordering::Relaxed);
        RA_WIN[i].store(now, Ordering::Relaxed);
        RA_COUNT[i].store(1, Ordering::Relaxed);
        return false;
    }
    let c = RA_COUNT[i].fetch_add(1, Ordering::Relaxed) + 1;
    c > limit
}

/// The (port, src-MAC) RA-meter key: `mac_hash` occupies bits 0..48, the port id sits
/// above it, so the same MAC on two ports meters independently.
#[inline]
pub fn ra_key(port: u64, mac_key: u64) -> u64 {
    mac_key ^ ((port & 0xff) << 56)
}

/// Live RA meter on the real generic-counter clock (`RA_FLOOD_WINDOW_SECS` window).
pub fn ra_rate_over(port: u64, mac_key: u64, limit: u64) -> bool {
    let win = cntfrq().max(1).saturating_mul(RA_FLOOD_WINDOW_SECS);
    ra_rate_over_at(ra_key(port, mac_key), limit, cntpct(), win)
}

// ---- L2/L3 shared: the top-talker (highest new-conn/flow-rate source) tracker ----

/// A source below this measured flow/conn count is NEVER treated as a shed-worthy
/// top-talker, even if it is the current maximum in a saturated table — so a saturated
/// table full of many SMALL legit sources sheds none of them (only a genuine flood).
pub const SHED_TOPTALKER_MIN_FLOWS: u64 = 100;

/// The scheduler-pressure shed wall (parity with the Linux PSI `some avg60 >= 40%`).
pub const PSI_SHED_PCT: u64 = 40;

const CT_WINDOW_SECS: u64 = 10;
static CT_WIN: [AtomicU64; FLOW_SRCS] = [const { AtomicU64::new(0) }; FLOW_SRCS];
static CT_SRC: [AtomicU64; FLOW_SRCS] = [const { AtomicU64::new(0) }; FLOW_SRCS];
static CT_COUNT: [AtomicU64; FLOW_SRCS] = [const { AtomicU64::new(0) }; FLOW_SRCS];
static TOP_SRC: AtomicU64 = AtomicU64::new(0);
static TOP_FLOWS: AtomicU64 = AtomicU64::new(0);
static TOP_WIN: AtomicU64 = AtomicU64::new(0);

#[inline]
fn ct_touch(src: u64) -> usize {
    let s = (src as usize) % FLOW_SRCS;
    let now = cntpct();
    let win = cntfrq().max(1).saturating_mul(CT_WINDOW_SECS);
    let start = CT_WIN[s].load(Ordering::Relaxed);
    if CT_SRC[s].load(Ordering::Relaxed) != src || now.wrapping_sub(start) >= win {
        CT_SRC[s].store(src, Ordering::Relaxed);
        CT_WIN[s].store(now, Ordering::Relaxed);
        CT_COUNT[s].store(0, Ordering::Relaxed);
    }
    s
}

/// Record one new connection/flow from `src` for the top-talker census. Bumps the
/// per-source windowed count and, if it becomes the new maximum, promotes `src` to the
/// current top-talker. The census + top slot are windowed, so the "top" self-reverts as
/// traffic ages out. `src == 0` (no attribution) is ignored.
pub fn flow_record(src: u64) {
    if src == 0 {
        return;
    }
    // Window the global top slot alongside the per-source census.
    let now = cntpct();
    let win = cntfrq().max(1).saturating_mul(CT_WINDOW_SECS);
    if now.wrapping_sub(TOP_WIN.load(Ordering::Relaxed)) >= win {
        TOP_WIN.store(now, Ordering::Relaxed);
        TOP_SRC.store(0, Ordering::Relaxed);
        TOP_FLOWS.store(0, Ordering::Relaxed);
    }
    let s = ct_touch(src);
    let c = CT_COUNT[s].fetch_add(1, Ordering::Relaxed) + 1;
    if c > TOP_FLOWS.load(Ordering::Relaxed) {
        TOP_FLOWS.store(c, Ordering::Relaxed);
        TOP_SRC.store(src, Ordering::Relaxed);
    }
}

/// The current top-talker source key (0 if none this window).
pub fn top_talker() -> u64 {
    TOP_SRC.load(Ordering::Relaxed)
}

/// The top-talker's measured new-conn/flow count this window.
pub fn top_talker_flows() -> u64 {
    TOP_FLOWS.load(Ordering::Relaxed)
}

/// Is `src` the current measured top-talker (and a real one, above the dominance floor)?
pub fn is_top_talker(src: u64) -> bool {
    src != 0 && TOP_SRC.load(Ordering::Relaxed) == src && TOP_FLOWS.load(Ordering::Relaxed) >= SHED_TOPTALKER_MIN_FLOWS
}

// ---- L2: conntrack-saturation top-talker shed ----

/// L2 — the conntrack-saturation shed TRIGGER for `src` (identity-blind). Fires iff the
/// flow table is SATURATED (`table_count/table_max >= 80%`) AND `src` is the measured
/// dominant top-talker. Keyed on FILL REALITY + the source's measured share, never
/// identity. SELF-REVERTING: as the table drains below the wall, `table_saturated` goes
/// false and this returns false — the source PASSes again with no durable mark. A legit
/// source in an un-saturated table (L9), or a small source in a saturated one, never
/// fires. The `Allowlisted` floor is applied by `shed_verdict`, not here.
pub fn saturation_shed(src: u64, table_count: u64, table_max: u64) -> bool {
    table_saturated(table_count, table_max) && is_top_talker(src)
}

// ---- L3: heqk-native PSI-equivalent (scheduler-pressure) shed ----

/// Synthetic pressure override (0..=100). `SYNTH_UNSET` = not injected → derive from the
/// real scheduler. The selftest injects a value so the shed LOGIC is QEMU-provable
/// deterministically; production/metal leaves it unset and derives real pressure.
const SYNTH_UNSET: u64 = u64::MAX;
static SYNTH_PSI: AtomicU64 = AtomicU64::new(SYNTH_UNSET);

/// TEST/GATE-R hook — inject a synthetic CPU-pressure percentage (0..=100). When set it
/// is AUTHORITATIVE (the QEMU path has no real contention to measure), so the shed logic
/// is deterministically provable. Metal leaves it unset (see `cpu_pressure_pct`).
pub fn set_synthetic_pressure(pct: u64) {
    SYNTH_PSI.store(pct.min(100), Ordering::Relaxed);
}

/// TEST hook — clear the synthetic override, restoring the real (metal) derivation.
pub fn clear_synthetic_pressure() {
    SYNTH_PSI.store(SYNTH_UNSET, Ordering::Relaxed);
}

/// heqk-native CPU-pressure percentage (0..=100) — the PSI-equivalent. heqk IS the
/// scheduler, so there is no `/proc/pressure` to read; it EXPOSES its own signal.
///
/// HONEST QEMU-vs-METAL SPLIT: when a synthetic value is injected (selftest / Gate-R
/// harness) it is authoritative and the shed LOGIC is fully QEMU-provable. Otherwise the
/// signal is DERIVED from the real runqueue depth (runnable-but-waiting threads — the
/// classic CPU-pressure proxy) via `scheduler::runnable_depth`. Under QEMU with no
/// contention that depth is ~0, so the REAL pressure signal only becomes meaningful under
/// genuine metal load (Gate R). A future refinement folds in allocator/frame-pool
/// occupancy; that is NOT claimed here. No metal pressure is fabricated.
pub fn cpu_pressure_pct() -> u64 {
    let synth = SYNTH_PSI.load(Ordering::Relaxed);
    if synth != SYNTH_UNSET {
        return synth; // QEMU / Gate-R: the injected signal is authoritative
    }
    // METAL: real runqueue-depth-derived pressure (each runnable-but-waiting thread ≈ 10%,
    // capped). ~0 under QEMU idle; rises only under real contention.
    let rq = crate::scheduler::runnable_depth() as u64;
    rq.saturating_mul(10).min(100)
}

/// Is the scheduler under sustained CPU pressure (>= `PSI_SHED_PCT`)?
pub fn under_pressure() -> bool {
    cpu_pressure_pct() >= PSI_SHED_PCT
}

/// L3 / A8 — the scheduler-pressure shed TRIGGER for `src` (identity-blind): under CPU
/// pressure, the measured TOP-TALKER sheds first. Keyed on PRESSURE REALITY + the highest-
/// rate source, never identity. SELF-REVERTING: pressure clears → false. The `Allowlisted`
/// floor is applied by `shed_verdict`, not here.
pub fn pressure_shed(src: u64) -> bool {
    under_pressure() && is_top_talker(src)
}
