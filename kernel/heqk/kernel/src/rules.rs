//! P8 — HookProbe rule plane: a registry of signed BPF threat rules, each
//! statically verified (PREVAIL) and JIT-compiled at load, run on every packet's
//! L4 header. **Rule parity**: the SAME RFC 9669 bytecode that runs on the
//! Linux/FreeBSD/QNX HookProbe substrates runs here unchanged — the corpus is
//! pluggable; this is the mechanism. On a target without a ready JIT backend
//! (e.g. CM5 metal, whose runtime frame allocator differs) a rule falls back to
//! the bounds-checked interpreter — same verdict, slower.

use crate::verdict::{self, DecideCtx, FindingClass, PortRole, Verdict};
use crate::{bpf, telemetry};
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Severity → QSecBit points added when the rule fires on live traffic.
pub const SEV_LOW: u32 = 1;
pub const SEV_MED: u32 = 3;
pub const SEV_HIGH: u32 = 5;

pub struct Rule {
    pub id: u16,
    pub name: &'static str,
    pub prog: &'static [u64],
    pub severity: u32,
    /// DET-SEP — what firing this rule MEANS. `run_set` feeds it to `verdict::decide`
    /// so a match is an ALERT graduated to a tri-state verdict, never an inline drop.
    pub class: FindingClass,
}

/// The signed L4 corpus. R1 = the L4 header (net.rs normalizes eth/VLAN/IHL
/// away), so every rule reads dst-port at a fixed offset regardless of framing.
pub static RULES: &[Rule] = &[
    Rule { id: 1, name: "block-port-4444", prog: &bpf::THREAT_RULE, severity: SEV_HIGH, class: FindingClass::Signature },
    Rule { id: 2, name: "block-telnet-23", prog: &bpf::BLOCK_TELNET, severity: SEV_MED, class: FindingClass::Signature },
    Rule { id: 3, name: "block-backdoor-31337", prog: &bpf::BLOCK_BACKDOOR, severity: SEV_HIGH, class: FindingClass::Signature },
];

/// The signed L2 corpus — parity with HookProbe `napse-l2guard` (Ring-0
/// deterministic frame/ARP enforcement). R1 = the raw L2 FRAME start; these run
/// on EVERY frame (before the L4 tier), mirroring `dpi::ArpObs` predicates.
pub static L2_RULES: &[Rule] = &[
    Rule { id: 101, name: "arp-malformed", prog: &bpf::ARP_MALFORMED, severity: SEV_MED, class: FindingClass::MalformedFrame },
    // DET-SEP / matrix row L3: a single-packet eth-src≠sender-mac is the shape a
    // legit gratuitous/proxy/NAT-rebind ARP ALSO presents; observe, never FrameDrop.
    Rule { id: 102, name: "arp-spoof", prog: &bpf::ARP_SPOOF, severity: SEV_HIGH, class: FindingClass::IdentitySpoof },
];

/// The signed TCP corpus — stateless anomalous-flag scan detection (Nmap/
/// Suricata-style). R1 = the TCP header; classify runs these ONLY on TCP.
pub static TCP_RULES: &[Rule] = &[
    Rule { id: 201, name: "tcp-null-scan", prog: &bpf::TCP_NULL_SCAN, severity: SEV_HIGH, class: FindingClass::ScanShape },
    Rule { id: 202, name: "tcp-fin-scan", prog: &bpf::TCP_FIN_SCAN, severity: SEV_MED, class: FindingClass::ScanShape },
    Rule { id: 203, name: "tcp-xmas-scan", prog: &bpf::TCP_XMAS_SCAN, severity: SEV_HIGH, class: FindingClass::ScanShape },
    Rule { id: 204, name: "tcp-syn-fin", prog: &bpf::TCP_SYNFIN, severity: SEV_HIGH, class: FindingClass::ScanShape },
];

/// The signed FLOW corpus — STATEFUL rules on the full L2 frame (R1 = frame),
/// keyed per-source via the rate-limiter CALL helper. Runs on every frame; each
/// rule self-parses (IPv4/TCP/…) and PASSes non-matching traffic.
pub static FLOW_RULES: &[Rule] = &[
    // Fires only when the per-source SYN RATE wall is crossed this window → a bounded,
    // self-reverting drop keyed on rate reality (ADR 0023 D2/D3), never identity.
    Rule { id: 301, name: "syn-flood-per-src", prog: &bpf::TCP_SYN_FLOOD_SRC, severity: SEV_HIGH, class: FindingClass::FloodRate },
    // DET-SEP / matrix row L11: a single threat-feed IOC hit must never drop a
    // customer; observe (corroboration → higher verdict is the M2 follow-on).
    Rule { id: 302, name: "ip-blocklist", prog: &bpf::IP_BLOCKLIST, severity: SEV_HIGH, class: FindingClass::IdentityReputation },
];

const MAX_RULES: usize = 16;
#[derive(Clone, Copy)]
struct RState {
    verified: bool,
    min_len: u64,
    jit: usize, // compiled fn VA, or 0 => interpreter only
}
static mut RSTATE: [RState; MAX_RULES] =
    [RState { verified: false, min_len: 0, jit: 0 }; MAX_RULES];
static mut RSTATE_L2: [RState; MAX_RULES] =
    [RState { verified: false, min_len: 0, jit: 0 }; MAX_RULES];
static mut RSTATE_TCP: [RState; MAX_RULES] =
    [RState { verified: false, min_len: 0, jit: 0 }; MAX_RULES];
static mut RSTATE_FLOW: [RState; MAX_RULES] =
    [RState { verified: false, min_len: 0, jit: 0 }; MAX_RULES];
static NRULES: AtomicUsize = AtomicUsize::new(0);
static NRULES_L2: AtomicUsize = AtomicUsize::new(0);
static NRULES_TCP: AtomicUsize = AtomicUsize::new(0);
static NRULES_FLOW: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn rstate(state: *mut RState, i: usize) -> RState {
    unsafe { state.add(i).read() }
}

/// Verify + JIT-compile a rule set into `state`. A rule that fails verification
/// is DISABLED (never run) — the plane admits only statically-proven-safe rules.
/// Returns (verified, jitted).
///
/// DET-2 — INTEGRITY MODEL. The corpus passed here is `&'static` bytecode baked into
/// the kernel image, and the image is **hybrid-signed (ed25519 + SLH-DSA) and measured
/// into PCR1** by HBoot. So a rule cannot be tampered without breaking the image
/// signature: "signed rule" is backed by IMAGE-LEVEL signing + measured boot for the
/// static corpus, NOT by a per-rule signature. `verify_prevail` here proves memory
/// SAFETY (an independent property); it is not an authenticity check.
///
/// HARD PREREQUISITE for any future DYNAMIC rule source (loaded from storage / HYDRA,
/// i.e. NOT this static corpus): a per-rule authenticity gate MUST be added at the top
/// of this function — verify an ed25519 / FIPS-205 signature over the rule bytecode
/// (reuse `attest_svc`) and refuse any rule whose signature does not verify — BEFORE
/// `verify_prevail`. Until that gate exists, there must be no code path that feeds a
/// non-static rule into `compile_set`.
fn compile_set(rules: &[Rule], state: *mut RState) -> (usize, usize) {
    let mut verified = 0usize;
    let mut jitted = 0usize;
    let n = rules.len().min(MAX_RULES);
    for i in 0..n {
        let st = match bpf::verify_prevail(rules[i].prog) {
            Ok(min_len) => {
                verified += 1;
                let jit = arch_aarch64::bpf_jit::compile(rules[i].prog).unwrap_or(0);
                if jit != 0 {
                    jitted += 1;
                }
                RState { verified: true, min_len, jit }
            }
            Err(_) => RState { verified: false, min_len: 0, jit: 0 },
        };
        unsafe { state.add(i).write(st) };
    }
    (verified, jitted)
}

/// Verify + JIT-compile the L4 AND L2 corpora once, at boot. Returns the combined
/// (verified_count, jitted_count) across both tiers.
pub fn init() -> (usize, usize) {
    let (v4, j4) = compile_set(RULES, addr_of_mut!(RSTATE).cast::<RState>());
    NRULES.store(RULES.len().min(MAX_RULES), Ordering::Relaxed);
    let (v2, j2) = compile_set(L2_RULES, addr_of_mut!(RSTATE_L2).cast::<RState>());
    NRULES_L2.store(L2_RULES.len().min(MAX_RULES), Ordering::Relaxed);
    let (vt, jt) = compile_set(TCP_RULES, addr_of_mut!(RSTATE_TCP).cast::<RState>());
    NRULES_TCP.store(TCP_RULES.len().min(MAX_RULES), Ordering::Relaxed);
    let (vf, jf) = compile_set(FLOW_RULES, addr_of_mut!(RSTATE_FLOW).cast::<RState>());
    NRULES_FLOW.store(FLOW_RULES.len().min(MAX_RULES), Ordering::Relaxed);
    (v4 + v2 + vt + vf, j4 + j2 + jt + jf)
}

/// DET-SEP — run a rule set against a byte view `pkt` (R1 = pkt start) and return
/// the TRI-STATE verdict. A matching rule is an ALERT: its `FindingClass` is fed to
/// `decide_fn` (`verdict::decide` or `decide_l2`), whose default is `Observe`
/// (PASS). `None` = no rule fired (clean). Uses the JIT when `pkt` is long enough
/// for the rule's proven `min_len`, else the bounds-checked interpreter.
///
/// A DROP-verdict is authoritative and short-circuits; an OBSERVE-verdict is
/// recorded but scanning CONTINUES (a later rule may be a genuine structural drop —
/// e.g. a blocklisted source whose frame is ALSO malformed must still FrameDrop).
/// Only a drop-verdict scores a QSecBit hit; every fire (observe or drop) is
/// exported to the SOAR ring with its REAL wire verdict, so an observed threat is
/// still reported to the SIEM without touching the wire.
fn run_set_verdict(
    rules: &[Rule],
    state: *mut RState,
    n: usize,
    pkt: &[u8],
    src: u32,
    decide_fn: fn(FindingClass, DecideCtx) -> Verdict,
) -> Option<Verdict> {
    let ctx = DecideCtx::for_src(src);
    let mut observed: Option<Verdict> = None;
    for i in 0..n {
        let st = rstate(state, i);
        if !st.verified {
            continue;
        }
        let v = if st.jit != 0 && pkt.len() as u64 >= st.min_len {
            let f: extern "C" fn(*const u8) -> u64 =
                unsafe { core::mem::transmute::<usize, extern "C" fn(*const u8) -> u64>(st.jit) };
            f(pkt.as_ptr())
        } else {
            bpf::run(rules[i].prog, pkt.as_ptr(), pkt.len())
        };
        if v == bpf::DROP {
            // The rule MATCHED — an alert, not a wire action. decide() graduates it.
            let verdict = decide_fn(rules[i].class, ctx);
            fire(rules[i].id, rules[i].severity, verdict, src);
            if verdict.is_drop() {
                return Some(verdict);
            }
            // Observed (observe-by-default): keep scanning for a genuine drop.
            if observed.is_none() {
                observed = Some(verdict);
            }
        } else if v != bpf::PASS {
            // DET-9: v == INVALID (VM fault: OOB / step-limit / unknown op on a
            // malformed frame). Fail CLOSED as a STRUCTURAL FrameDrop, but do NOT
            // attribute it to a signed rule firing (that inflated QSecBit and
            // mislabelled a parse fault as a detection). Emit a distinct Fault event.
            telemetry::emit(telemetry::Event::Fault);
            return Some(Verdict::FrameDrop);
        }
    }
    observed
}

// ---- Tri-state verdict entry points (for the enforcement-separation matrix) ----

/// L4-header tier verdict. `src` = host-order IPv4 source (DET-11 attribution + the
/// `Allowlisted` floor). `None` = clean.
pub fn verdict_l4(l4: &[u8], src: u32) -> Option<Verdict> {
    run_set_verdict(RULES, addr_of_mut!(RSTATE).cast::<RState>(), NRULES.load(Ordering::Relaxed), l4, src, verdict::decide)
}

/// L2 frame-tier verdict (`napse-l2guard` parity: malformed-ARP / ARP-spoof).
pub fn verdict_l2(frame: &[u8], src: u32) -> Option<Verdict> {
    run_set_verdict(L2_RULES, addr_of_mut!(RSTATE_L2).cast::<RState>(), NRULES_L2.load(Ordering::Relaxed), frame, src, verdict::decide_l2)
}

/// TCP-flag scan-tier verdict (NULL/FIN/Xmas/SYN-FIN). classify runs this ONLY on TCP.
pub fn verdict_tcp(tcp: &[u8], src: u32) -> Option<Verdict> {
    run_set_verdict(TCP_RULES, addr_of_mut!(RSTATE_TCP).cast::<RState>(), NRULES_TCP.load(Ordering::Relaxed), tcp, src, verdict::decide)
}

/// Stateful flow-tier verdict (per-source SYN-flood rate-limit, blocklist).
pub fn verdict_flow(frame: &[u8], src: u32) -> Option<Verdict> {
    run_set_verdict(FLOW_RULES, addr_of_mut!(RSTATE_FLOW).cast::<RState>(), NRULES_FLOW.load(Ordering::Relaxed), frame, src, verdict::decide)
}

// ---- On-wire (u16) wrappers — the datapath (`packet::classify`, `netq`) consumes
// these; each derives its wire int from the tri-state verdict above. `None`/observe
// → PASS; only a drop-verdict → DROP. ----

/// Run the L4-header rule set against `l4` (R1 = L4 header). Wire verdict.
pub fn run_l4(l4: &[u8], src: u32) -> u16 {
    verdict_l4(l4, src).map_or(crate::packet::PASS, Verdict::to_wire)
}

/// Run the L2 rule set against the raw `frame` (R1 = L2 start). Wire verdict.
pub fn run_l2(frame: &[u8], src: u32) -> u16 {
    verdict_l2(frame, src).map_or(crate::packet::PASS, Verdict::to_wire)
}

/// Run the TCP-flag scan tier against the TCP header `tcp` (R1 = TCP header). Wire verdict.
pub fn run_tcp(tcp: &[u8], src: u32) -> u16 {
    verdict_tcp(tcp, src).map_or(crate::packet::PASS, Verdict::to_wire)
}

/// Run the STATEFUL flow tier against the raw `frame` (R1 = L2 start). Wire verdict.
pub fn run_flow(frame: &[u8], src: u32) -> u16 {
    verdict_flow(frame, src).map_or(crate::packet::PASS, Verdict::to_wire)
}

/// DET-SEP — a detector FIRED: export the SOAR event with the REAL wire verdict
/// (PASS for an observed finding) and score a QSecBit hit ONLY on an enforced
/// (wire-DROP) verdict. Shared by the bytecode tiers and the M2.1 stateful L2 tier.
fn fire(rule_id: u16, severity: u32, v: Verdict, src: u32) {
    let wire = v.to_wire();
    crate::events::push_hit(rule_id, severity as u8, wire as u8, src);
    if wire == crate::packet::DROP {
        telemetry::emit_rule_hit(severity);
    }
}

// ---- M2.1: the structural + stateful L2 tier (F6/F7/F8 + mac-flood + broadcast-storm)
// ----

/// Rule IDs for the M2.1 tier (kept distinct from the bytecode L2 corpus 101/102).
pub const RULE_STRUCT_ANOMALY: u16 = 110;
pub const RULE_MAC_FLOOD: u16 = 111;
pub const RULE_BCAST_STORM: u16 = 112;

/// Distinct-source-MAC-per-window thresholds (ADR 0023 D12). Access is tight; the
/// uplink/AP bar is deliberately far higher (many client MACs are legitimate there).
const MAC_FLOOD_ACCESS: u64 = 20;
const MAC_FLOOD_UPLINK: u64 = 300;
/// Broadcast/multicast frames per window before it's a storm (well above legit ARP/
/// DHCP rates; a genuine storm floods far past it).
const BCAST_STORM_THRESH: u64 = 50;

/// M2.1 — structural + stateful L2 tier. Runs on the ORIGINAL frame (MAC offsets,
/// length, and VLAN-tag depth are pre-normalization facts). EVERY finding routes
/// through `verdict::decide_l2` — no rule drops inline. Returns the tri-state verdict
/// (or `None` if nothing fired). `port` = the ingress port id (fan-out state is
/// per-port); `port_role` gates the mac-flood FP guard.
pub fn l2_stateful_verdict(frame: &[u8], src: u32, port: u64, port_role: PortRole) -> Option<Verdict> {
    let ctx = DecideCtx::for_l2(src, port_role);

    // F6/F7/F8 — a STRUCTURAL fact (multicast-src / oversize / double-tag) → a
    // MalformedFrame FrameDrop keyed on WHAT THE FRAME IS. Authoritative; the
    // Allowlisted floor correctly does not exempt it.
    if crate::net::structural_anomaly(frame) {
        let v = verdict::decide_l2(FindingClass::MalformedFrame, ctx);
        fire(RULE_STRUCT_ANOMALY, SEV_MED, v, src);
        return Some(v);
    }

    let mut observed: Option<Verdict> = None;

    // mac-flood — DISTINCT source MACs per port within the window. On an Access port
    // a genuine fan-out → RateLimit (drop); on an Uplink/AP port it stays Observe
    // (decide_l2 D12) so a busy radio's many legit client MACs are NEVER wire-dropped.
    if frame.len() >= 12 {
        let key = crate::ratelimit::mac_hash(&frame[6..12]);
        let threshold = match port_role {
            PortRole::Access => MAC_FLOOD_ACCESS,
            PortRole::Uplink => MAC_FLOOD_UPLINK,
        };
        if crate::ratelimit::mac_flood_over(port, key, threshold) == 1 {
            let v = verdict::decide_l2(FindingClass::L2Flood, ctx);
            fire(RULE_MAC_FLOOD, SEV_MED, v, src);
            if v.is_drop() {
                return Some(v);
            }
            observed = Some(v);
        }
    }

    // broadcast-storm — count only NON-EXEMPT broadcast/multicast dst frames (mDNS/
    // SSDP/LLMNR are exempt before counting, so a chatty-but-legit device is never a
    // storm). A genuine flood on an Access port → RateLimit; Uplink → Observe.
    if crate::net::dst_is_bcast_or_mcast(frame) && !is_exempt_multicast(&frame[0..6]) {
        if crate::ratelimit::bcast_over(port, BCAST_STORM_THRESH) == 1 {
            let v = verdict::decide_l2(FindingClass::L2Flood, ctx);
            fire(RULE_BCAST_STORM, SEV_MED, v, src);
            if v.is_drop() {
                return Some(v);
            }
            if observed.is_none() {
                observed = Some(v);
            }
        }
    }

    observed
}

/// mDNS / SSDP / LLMNR and IPv6-multicast destination groups — well-known service
/// discovery a chatty-but-legit device emits; EXEMPT from the storm counter before it
/// can ever reach a drop path (ADR 0023 D13 / the matrix broadcast LEGIT row).
fn is_exempt_multicast(dst: &[u8]) -> bool {
    if dst.len() < 6 {
        return false;
    }
    // IPv6 multicast (33:33:xx:xx:xx:xx) — includes mDNSv6 (ff02::fb → 33:33:00:00:00:fb).
    if dst[0] == 0x33 && dst[1] == 0x33 {
        return true;
    }
    // IPv4 link-local multicast (01:00:5e:..): mDNS .fb, LLMNR .fc, SSDP .fa.
    if dst[0] == 0x01 && dst[1] == 0x00 && dst[2] == 0x5e {
        let g = [dst[3], dst[4], dst[5]];
        return g == [0x00, 0x00, 0xfb] || g == [0x00, 0x00, 0xfc] || g == [0x7f, 0xff, 0xfa];
    }
    false
}

/// DET-6 — a view of one VERIFIED + JIT-compiled live rule, for the boot-time
/// JIT<->interpreter differential self-test. `jit` is the native entry VA already
/// published by `init()` (reused, NOT recompiled — no extra exec pages).
#[cfg(not(feature = "cm5"))]
#[derive(Clone, Copy)]
pub struct JittedRule {
    pub name: &'static str,
    pub prog: &'static [u64],
    pub min_len: u64,
    pub jit: usize,
}

/// DET-6 — enumerate EVERY verified + JIT-compiled rule across the L4/L2/TCP
/// corpora into `out`, returning the count. The FLOW corpus is deliberately
/// excluded: its rules use the `CALL` helper (opcode 0x85) which the JIT rejects
/// (`compile` -> None => `jit == 0`), so they run interpreter-only and there is no
/// native codegen to cross-check. The `jit != 0` guard below also excludes any
/// such interpreter-only rule regardless of tier. MUST be called after `init()`.
#[cfg(not(feature = "cm5"))]
pub fn jitted_rules(out: &mut [JittedRule]) -> usize {
    let mut k = 0usize;
    let sets: [(&[Rule], *mut RState, &AtomicUsize); 3] = [
        (RULES, addr_of_mut!(RSTATE).cast::<RState>(), &NRULES),
        (L2_RULES, addr_of_mut!(RSTATE_L2).cast::<RState>(), &NRULES_L2),
        (TCP_RULES, addr_of_mut!(RSTATE_TCP).cast::<RState>(), &NRULES_TCP),
    ];
    for (rules, state, n) in sets {
        let cnt = n.load(Ordering::Relaxed).min(rules.len());
        for i in 0..cnt {
            let st = rstate(state, i);
            if st.verified && st.jit != 0 && k < out.len() {
                out[k] = JittedRule {
                    name: rules[i].name,
                    prog: rules[i].prog,
                    min_len: st.min_len,
                    jit: st.jit,
                };
                k += 1;
            }
        }
    }
    k
}

/// How many rules are active (verified) across all tiers — for the boot report.
pub fn active() -> usize {
    let a = (0..NRULES.load(Ordering::Relaxed))
        .filter(|&i| rstate(addr_of_mut!(RSTATE).cast::<RState>(), i).verified).count();
    let b = (0..NRULES_L2.load(Ordering::Relaxed))
        .filter(|&i| rstate(addr_of_mut!(RSTATE_L2).cast::<RState>(), i).verified).count();
    let c = (0..NRULES_TCP.load(Ordering::Relaxed))
        .filter(|&i| rstate(addr_of_mut!(RSTATE_TCP).cast::<RState>(), i).verified).count();
    let d = (0..NRULES_FLOW.load(Ordering::Relaxed))
        .filter(|&i| rstate(addr_of_mut!(RSTATE_FLOW).cast::<RState>(), i).verified).count();
    a + b + c + d
}
