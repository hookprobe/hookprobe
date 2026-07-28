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

/// A GLOBAL flow-table fill counter (the conntrack-equivalent occupancy). Bumped on each
/// established flow; a real gauge would also decrement on teardown (M2.3). Exposed for
/// the live saturation SIGNAL; the deterministic verdict map takes count/max as params.
static FLOW_COUNT: AtomicU64 = AtomicU64::new(0);

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

/// Record a SYN-only (connection-attempt) packet to `dst_port` from `src` (host-order
/// IPv4). Adds the port to the source's distinct set; returns the running distinct count.
/// `src == 0` (no attribution) is ignored — the port-scan verdict requires an identity.
pub fn syn_scan_observe(src: u64, dst_port: u16) -> u64 {
    if src == 0 {
        return 0;
    }
    let s = touch_scan_slot(src);
    let gen = SCAN_GEN[s].load(Ordering::Relaxed);
    let pk = (dst_port as u64) | (1u64 << 48); // non-zero key (port 0 is a real port)
    let i = (dst_port as usize) % SCAN_PORT_SET;
    let seen = SCAN_PORT_GEN[s][i].load(Ordering::Relaxed) == gen
        && SCAN_PORT_KEY[s][i].load(Ordering::Relaxed) == pk;
    if !seen {
        SCAN_PORT_GEN[s][i].store(gen, Ordering::Relaxed);
        SCAN_PORT_KEY[s][i].store(pk, Ordering::Relaxed);
        SCAN_DISTINCT[s].fetch_add(1, Ordering::Relaxed);
    }
    SCAN_DISTINCT[s].load(Ordering::Relaxed)
}

/// Record that a flow from `src` reached ESTABLISHED (handshake completed — heqk's
/// cheapest proxy is an ACK-bearing segment on an existing flow). Bumps the source's
/// established count AND the global flow-table fill. An established source is
/// definitionally NOT a scanner: `est > 0` holds every scan escalation OFF (below).
pub fn flow_established(src: u64) {
    FLOW_COUNT.fetch_add(1, Ordering::Relaxed);
    if src == 0 {
        return;
    }
    let s = touch_scan_slot(src);
    SCAN_EST[s].fetch_add(1, Ordering::Relaxed);
}

/// Distinct SYN-only dst-port count for `src` in the current window (0 if the slot was
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
    flow_established_count(src) == 0 && scan_distinct_ports(src) >= SCAN_PORTS_RATELIMIT
}

/// The ADR-0018 CONFIRMATION signal for a durable Quarantine: a SYN-only sweep to
/// >= CONFIRM distinct ports from one source WITH ZERO establishment. Any establishment
/// (a single completed handshake) holds this at `false` forever within the window — this
/// is precisely why a legit busy source (150 established flows) can NEVER be confirmed.
pub fn scan_confirmed(src: u64) -> bool {
    flow_established_count(src) == 0 && scan_distinct_ports(src) >= SCAN_PORTS_CONFIRM
}

/// Live flow-table fill as a percentage (0..=100) — the A7 conntrack-saturation SIGNAL.
pub fn flow_saturation_pct() -> u64 {
    saturation_pct(FLOW_COUNT.load(Ordering::Relaxed), flow_table_max())
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
