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
/// A11 corroboration: when a source has tripped >= CORR_CRITICAL_AXES independent axes,
/// its alerts are stamped CRITICAL for the SOC/QSECBIT. This is a SEVERITY escalation
/// ONLY — the wire verdict is unchanged (corroboration never drops; security-auditor
/// 2026-09-08). Higher than SEV_HIGH so the SOC can rank corroborated sources first.
pub const SEV_CRIT: u32 = 7;

/// Map a fired rule's `FindingClass` to a corroboration axis (None = not a corroboration
/// axis, e.g. a structural/signature/spoof finding). REPUTATION (blocklist/IOC) and
/// SCAN are the axes carried by signed rules; BEACON/LATERAL/EXFIL/DNS are recorded at
/// their behavioral wrappers.
#[inline]
fn axis_for_class(c: FindingClass) -> Option<u32> {
    match c {
        FindingClass::IdentityReputation => Some(crate::corroboration::AXIS_REPUTATION),
        FindingClass::ScanShape => Some(crate::corroboration::AXIS_SCAN),
        _ => None,
    }
}

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
/// DET-2 — the PINNED dynamic-rule signing ROOT (the fixture's pubkey today; a real
/// deployment bakes the HYDRA/operator rule-root here). A presented key is NEVER trusted —
/// the gate verifies against THIS pinned key, the confused-deputy a trust root avoids.
const RULE_ROOT_PK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fixture_rule.pk"));
/// DET-2 — the signed dynamic-rule fixture (valid BPF bytecode + its signature), for the
/// [P8-det2] gate proof (a real dynamic source would supply these from storage/HYDRA).
pub const DYN_RULE_BIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fixture_rule.bin"));
pub const DYN_RULE_SIG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fixture_rule.sig"));

/// DET-2 — the per-rule AUTHENTICITY GATE (the HARD PREREQUISITE for any dynamic rule
/// source named in compile_set's integrity note). Verify an Ed25519 signature over the rule
/// BYTECODE against the PINNED rule-signing root. Returns `true` iff authentic; a tampered or
/// unsigned rule is refused fail-closed and must NEVER reach verify_prevail or the datapath.
/// This is authenticity (provenance); `verify_prevail` remains the separate memory-safety leg.
pub fn rule_sig_ok(prog: &[u8], sig: &[u8]) -> bool {
    use ed25519_compact::{PublicKey, Signature};
    (|| {
        let pk = PublicKey::from_slice(RULE_ROOT_PK).ok()?;
        let s = Signature::from_slice(sig).ok()?;
        pk.verify(prog, &s).ok()
    })()
    .is_some()
}

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
        // XC-11/DET-1 — CLOSE THE KERNEL-READ ORACLE on the interpreter path. `min_len` is
        // the verifier-proven lower bound for EVERY in-bounds access this rule makes —
        // including helper POINTER args (payload_match derefs R1 for pattern_len bytes with
        // no internal bounds check; the verifier folds that length into min_len). The JIT
        // path was already gated on `pkt.len() >= min_len`, but the interpreter FALLBACK ran
        // UNCONDITIONALLY — so a rule that omits a touch-load could drive payload_match's read
        // OOB on a short packet (an arbitrary-kernel-read oracle, CVE-2021-4204 class). Latent
        // while the rule corpus is static+trusted; live the moment untrusted/dynamic rules
        // load. Enforce min_len on BOTH backends: a packet shorter than the rule's proven
        // minimum cannot satisfy it, so SKIP it — fail-closed, never a spurious match, and it
        // makes the verifier's `min_len` a runtime reality independent of a rule's structure.
        if (pkt.len() as u64) < st.min_len {
            continue;
        }
        let v = if st.jit != 0 {
            let f: extern "C" fn(*const u8) -> u64 =
                unsafe { core::mem::transmute::<usize, extern "C" fn(*const u8) -> u64>(st.jit) };
            f(pkt.as_ptr())
        } else {
            bpf::run(rules[i].prog, pkt.as_ptr(), pkt.len())
        };
        if v == bpf::DROP {
            // The rule MATCHED — an alert, not a wire action. decide() graduates it.
            let verdict = decide_fn(rules[i].class, ctx);
            // A11 corroboration (SEVERITY only, never the wire): record this axis for the
            // source and, if it is now corroborated across >= K axes, stamp the alert
            // CRITICAL. `verdict` is UNCHANGED — decide_fn already mapped a reputation/scan
            // finding to its own (observe/graduated) verdict; corroboration does not touch it.
            let sev = match axis_for_class(rules[i].class) {
                Some(ax) => {
                    crate::corroboration::corr_observe(src as u64, ax);
                    if crate::corroboration::is_corroborated(src as u64) {
                        SEV_CRIT
                    } else {
                        rules[i].severity
                    }
                }
                None => rules[i].severity,
            };
            fire(rules[i].id, sev, verdict, src);
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
/// RA-guard (RFC 6105): a rogue ICMPv6 Router Advertisement on a non-router port
/// (matrix A9); a legit RA on an uplink is Observed (L4). Kept distinct from the L2
/// tier 110-112 and the truncated/behavioral ids.
pub const RULE_ROGUE_RA: u16 = 121;

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

    // RA-guard (RFC 6105 / matrix L4 legit + A9 rogue): an ICMPv6 Router Advertisement
    // is legitimate ONLY from a designated router/uplink port. Port-role-gated via
    // decide_l2(RaGuard): Access → FrameDrop (a RA on a client-only port is a rogue
    // gateway-hijack), Uplink → Observe (the legit downstream-router RA, accepted +
    // logged). Fail-safe: the live aggregate port defaults Uplink, so a real RA is
    // never dropped until a manifest marks a specific access interface.
    if crate::net::is_icmpv6_ra(frame) {
        let v = verdict::decide_l2(FindingClass::RaGuard, ctx);
        fire(RULE_ROGUE_RA, SEV_HIGH, v, src);
        if v.is_drop() {
            return Some(v);
        }
        if observed.is_none() {
            observed = Some(v);
        }
    }

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
            // A3 FIX: a NON-EXEMPT broadcast/multicast FLOOD is resource-exhaustion, not
            // legit many-client traffic (legit mDNS/SSDP/LLMNR are exempted above, row L1).
            // So it is a rate wall crossed → FindingClass::FloodRate → a bounded, self-
            // reverting RateLimit on ANY port (mgmt floor still honored), NOT L2Flood's
            // port-role gate (which is correct only for mac-flood's legit-many-MACs case).
            let v = verdict::decide_l2(FindingClass::FloodRate, ctx);
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

// ---- M2.2: the stateful distinct-dst-port scan tier (rule 1000003 parity) ----

/// Rule ID for the M2.2 distinct-dst-port scan detector (Linux rule 1000003 parity;
/// kept distinct from the M2.1 L2 tier 110-112 and the bytecode corpus 101/102/201-204).
pub const RULE_PORT_SCAN: u16 = 113;

/// M2.2 — the STATEFUL distinct-dst-port scan detector (rule 1000003), the
/// conntrack-equivalent scan counter. Runs on the VLAN-NORMALIZED frame (R1 = L2 start);
/// self-parses IPv4/TCP. Only SYN-only (SYN set, ACK clear) segments — connection
/// ATTEMPTS — feed the per-source distinct-dst-port set; an ACK-bearing segment marks the
/// flow ESTABLISHED (heqk's handshake-completed proxy). Returns the tri-state verdict via
/// `decide()` (or `None` below the scan bar / no attribution).
///
/// LEGIT-SAFETY (ADR 0023 keystone): the escalation keys on scan SHAPE — SYN-only to many
/// DISTINCT ports WITHOUT establishment — never on flow COUNT. `ratelimit::scan_confirmed`
/// / `scan_over_ratelimit` gate every escalation on `est == 0`, so a legit busy source
/// (a NAS with 150 established flows, a phone's 100/s web-load burst) can NEVER reach
/// `RateLimit`/`Quarantine`: an ESTABLISHED flow is definitionally not a scan.
pub fn flow_scan_verdict(frame: &[u8], src: u32) -> Option<Verdict> {
    if src == 0 {
        return None; // the port-scan verdict is identity-keyed; no attribution → nothing
    }
    let meta = crate::net::parse(frame)?;
    if meta.ip_proto != crate::net::IPPROTO_TCP || !meta.has_l4_ports() {
        return None; // only TCP carries the SYN/ACK scan shape
    }
    // TCP flags live at L4 offset + 13; bounds-checked read.
    let flags = *frame.get(meta.l4_off + 13)?;
    const TCP_SYN: u8 = 0x02;
    const TCP_ACK: u8 = 0x10;
    let src64 = src as u64;
    if flags & TCP_ACK != 0 {
        // An ACK-bearing segment ⇒ an existing/established flow. Records establishment,
        // which holds the scan escalation off for this source (legit-safety).
        crate::ratelimit::flow_established(src64);
    } else if flags & TCP_SYN != 0 {
        // A SYN-only connection attempt ⇒ a scan-shape probe. Counts the distinct dst port.
        crate::ratelimit::syn_scan_observe(src64, meta.dst_port);
    }

    if !crate::ratelimit::scan_over_ratelimit(src64) {
        return None; // below the distinct-port wall (or established) → clean/Observe
    }
    // The distinct-port wall is crossed with zero establishment. Build the ctx: `for_src`
    // already sources `confirmed` from `scan_confirmed` (>= CONFIRM ports ⇒ durable
    // Quarantine); set `over_limit` so the sub-confirm case is a bounded cap that touches
    // the wire (a real sweep), not a mere Observe.
    let mut ctx = DecideCtx::for_src(src);
    ctx.over_limit = true;
    let v = verdict::decide(FindingClass::ScanShape, ctx);
    // A11 corroboration (SEVERITY only): record the SCAN axis; stamp CRITICAL if the source
    // is now corroborated across >= K axes. `v` is UNCHANGED (the scan's own graduated
    // verdict stands — corroboration never escalates the wire action).
    crate::corroboration::corr_observe(src64, crate::corroboration::AXIS_SCAN);
    let sev = if crate::corroboration::is_corroborated(src64) { SEV_CRIT } else { SEV_HIGH };
    fire(RULE_PORT_SCAN, sev, v, src);
    Some(v)
}

// ---- M2.3: resource-shed verdict routing (ADR 0023's fourth suspicion-free drop) ----

/// Rule IDs for the M2.3 resource-shed layers (distinct from the M2.1/M2.2 tiers).
pub const RULE_CONN_RATE_SHED: u16 = 114; // L1 blanket per-source new-conn cap
pub const RULE_RESOURCE_SHED: u16 = 115; // L2 saturation / L3 pressure top-talker shed

/// M2.3 — map a resource-shed TRIGGER (rate / saturation / pressure — all identity-blind)
/// to a tri-state verdict via `decide()`, so the mgmt `Allowlisted` floor is HONORED: a
/// mgmt-path source is NEVER shed however hot it is (ADR 0022 D2 — never self-lock-out),
/// while any other source over a genuine resource wall gets a bounded, self-reverting
/// `RateLimit` (wire DROP). `triggered == false` → `Observe` (PASS). The FloodRate class
/// is the right one: a shed is a rate/resource-reality event, not an identity finding.
pub fn shed_verdict(rule_id: u16, src: u32, triggered: bool) -> Verdict {
    if !triggered {
        return Verdict::Observe;
    }
    let mut ctx = DecideCtx::for_src(src);
    ctx.over_limit = true;
    // decide(FloodRate): allowlisted → Allowlisted (floor, PASS); else RateLimit{true} (DROP).
    let v = verdict::decide(FindingClass::FloodRate, ctx);
    fire(rule_id, SEV_MED, v, src);
    v
}

/// M2.3 / L1 — the blanket per-source new-connection-rate cap on the live datapath, on
/// the VLAN-normalized frame. Self-parses TCP; only SYN-only (new-conn ATTEMPT) segments
/// are metered. Over `DEFAULT_NEW_CONN_PPS` (400/s) this window → a SELF-REVERTING
/// `RateLimit` (wire DROP), reverting the instant the source's rate falls next window.
/// Routes through `shed_verdict` so the mgmt floor is honored. Returns the verdict or None.
pub fn conn_rate_shed_verdict(frame: &[u8], src: u32) -> Option<Verdict> {
    if src == 0 {
        return None; // datapath src=0 short-circuits (never poisons; PHprod/PH6-net clean)
    }
    let meta = crate::net::parse(frame)?;
    if meta.ip_proto != crate::net::IPPROTO_TCP || !meta.has_l4_ports() {
        return None;
    }
    let flags = *frame.get(meta.l4_off + 13)?;
    const TCP_SYN: u8 = 0x02;
    const TCP_ACK: u8 = 0x10;
    if !(flags & TCP_SYN != 0 && flags & TCP_ACK == 0) {
        return None; // only new-connection attempts count toward the blanket cap
    }
    let over = crate::ratelimit::conn_rate_over(src as u64, crate::ratelimit::DEFAULT_NEW_CONN_PPS);
    if !over {
        return None;
    }
    Some(shed_verdict(RULE_CONN_RATE_SHED, src, true))
}

// ---- M2.4: L7 / behavioral OBSERVE-ONLY detectors (detection parity, NEVER a drop) ----

/// Rule IDs for the M2.4 behavioral tier (distinct from 110-115). Comments carry the
/// Linux parity rule numbers (1000040/1000041/1000025/1000002) these mirror.
pub const RULE_BEACON: u16 = 116; // parity: napse-capture beacon 1000040 (A10/L8)
pub const RULE_LATERAL: u16 = 117; // parity: napse-capture lateral 1000041 (A10)
pub const RULE_EXFIL: u16 = 118; // parity: bulk outbound exfil 1000025
pub const RULE_DNS: u16 = 119; // parity: DNS tunneling/DGA 1000002/1000021/1000011
pub const RULE_TRUNCATED: u16 = 120; // SG-2: net::parse None -> fail-closed drop (matrix F4)

/// M2.3 L2/L3 RESOURCE-SHED (matrix A7 conntrack-saturation / A8 scheduler-pressure / L9
/// legit-heavy-no-shed) — wired live off the connection stream. Records `src` into the
/// top-talker census, then sheds IFF a real resource wall is crossed AND `src` is the
/// dominant top-talker: A7 = flow-table >=80% full, A8 = CPU/scheduler pressure >= the PSI
/// floor. Identity-BLIND + SELF-REVERTING (windowed top + re-checked every frame → the
/// source PASSes again the moment the wall clears; L9's legit heavy source in an
/// un-saturated table / low-PSI box never fires). mgmt `Allowlisted` floor honored in
/// `shed_verdict`. Returns `None` (no shed) in the common case.
pub fn resource_shed_verdict(src: u32) -> Option<Verdict> {
    if src == 0 {
        return None;
    }
    let s = src as u64;
    crate::ratelimit::flow_record(s); // top-talker census (windowed → self-reverting)
    let saturated = crate::ratelimit::saturation_shed(
        s,
        crate::ratelimit::flow_count(),
        crate::ratelimit::flow_table_max(),
    );
    let pressured = crate::ratelimit::pressure_shed(s);
    if saturated || pressured {
        Some(shed_verdict(RULE_RESOURCE_SHED, src, true))
    } else {
        None
    }
}

/// M2.4 shared verdict step: a behavioral detector FIRED → route through `decide()` as
/// `FindingClass::Behavioral`, which is OBSERVE-ONLY by construction (always `Observe`,
/// PASS on the wire — zero legit-drop risk). `fire()` still exports the SOAR alert so the
/// SOC SEES the behavior; the wire is never touched. This is the whole M2.4 contract:
/// detection parity WITHOUT enforcement.
#[inline]
fn behavioral_verdict(rule_id: u16, src: u32, axis: u32) -> Verdict {
    let v = verdict::decide(FindingClass::Behavioral, DecideCtx::for_src(src));
    // A11 corroboration (SEVERITY only): record this behavioral axis; a source corroborated
    // across >= K axes is stamped CRITICAL for the SOC. `v` stays `Observe` — behavioral is
    // observe-only by construction, and corroboration NEVER changes the wire verdict.
    crate::corroboration::corr_observe(src as u64, axis);
    let sev = if crate::corroboration::is_corroborated(src as u64) { SEV_CRIT } else { SEV_MED };
    fire(rule_id, sev, v, src);
    v
}

/// M2.4 / BEACON (A10 detection-half + L8 NTP exemption) — C2 beacon periodicity, with an
/// INJECTED clock (`now` in whole seconds) for deterministic proof. Fed from the connection
/// observation stream (src/dst/dst_port), NOT the drop fast-path — parity with the Linux
/// beacon tracker that runs in userspace. NTP (dst port 123) is exempt inside
/// `beacon_observe_at` (returns None here). Always `Some(Observe)` when it fires.
pub fn beacon_verdict_at(src: u32, dst: u32, dst_port: u16, now: u64) -> Option<Verdict> {
    if !crate::behavioral::beacon_observe_at(src, dst, dst_port, now) {
        return None;
    }
    Some(behavioral_verdict(RULE_BEACON, src, crate::corroboration::AXIS_BEACON))
}

/// Live-clock wrapper for the datapath (M2.4 A10/L8 wiring): same as `beacon_verdict_at`
/// but sources `now` from the real monotonic clock instead of an injected test value.
pub fn beacon_verdict(src: u32, dst: u32, dst_port: u16) -> Option<Verdict> {
    beacon_verdict_at(src, dst, dst_port, crate::behavioral::now_secs())
}

/// M2.4 / LATERAL (A10 detection-half) — one internal source fanning out across many
/// distinct internal peers on admin ports. FP guards (internal→internal, distinct-peer,
/// self-conn) live in `lateral_observe`. Always `Some(Observe)` when it fires.
pub fn lateral_verdict(src: u32, dst: u32, dst_port: u16) -> Option<Verdict> {
    if !crate::behavioral::lateral_observe(src, dst, dst_port) {
        return None;
    }
    Some(behavioral_verdict(RULE_LATERAL, src, crate::corroboration::AXIS_LATERAL))
}

/// M2.4 / EXFIL — anomalous OUTBOUND (internal→external) byte volume from one source.
/// Direction + windowing guards live in `exfil_observe`. Always `Some(Observe)` when it fires.
pub fn exfil_verdict(src: u32, dst: u32, bytes: u64) -> Option<Verdict> {
    if !crate::behavioral::exfil_observe(src, dst, bytes) {
        return None;
    }
    Some(behavioral_verdict(RULE_EXFIL, src, crate::corroboration::AXIS_EXFIL))
}

/// M2.4 / DNS ANALYTICS — tunneling / DGA / high-entropy QNAME. Self-parses the frame
/// (UDP:53) and the QNAME. `None` = not DNS or a normal name; a hostile-shaped name →
/// `Some(Observe)` (detected, PASS). `src` is attributed from the frame for the SOAR alert.
pub fn dns_verdict(frame: &[u8]) -> Option<Verdict> {
    if crate::behavioral::dns_qname_anomaly(frame)? {
        let src = crate::net::eth_ipv4_src(frame);
        Some(behavioral_verdict(RULE_DNS, src, crate::corroboration::AXIS_DNS))
    } else {
        None // parsed as DNS but the name is normal
    }
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
