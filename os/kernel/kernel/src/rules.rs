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
pub(crate) struct RState {
    pub(crate) verified: bool,
    pub(crate) min_len: u64,
    pub(crate) jit: usize, // compiled fn VA, or 0 => interpreter only
}
impl RState {
    pub(crate) const EMPTY: RState = RState { verified: false, min_len: 0, jit: 0 };
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
    for (i, rule) in rules.iter().enumerate().take(n) {
        let st = match bpf::verify_prevail(rule.prog) {
            Ok(min_len) => {
                verified += 1;
                let jit = arch_aarch64::bpf_jit::compile_with_helper(rule.prog, crate::ratelimit::call_helper_c as *const () as usize, crate::ratelimit::JIT_HELPERS).unwrap_or(0);
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

/// Rules VERIFIED and active across all tiers (0 until `init` runs). Until `init`, every rule is
/// `verified=false` and skipped, so `packet::verdict` PASSES EVERYTHING — an entry path that
/// forgets `init` runs an IPS that detects nothing. Surface this count (heartbeat, `/api/health`)
/// so an unarmed rule plane is never silent.
pub fn active_rules() -> usize {
    VERIFIED_TOTAL.load(Ordering::Relaxed)
}
static VERIFIED_TOTAL: AtomicUsize = AtomicUsize::new(0);

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
    VERIFIED_TOTAL.store(v4 + v2 + vt + vf, Ordering::Relaxed);
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
/// The shared evaluation step, for the signed dynamic rule pack (parity G6) — same min_len gate,
/// JIT/interpreter choice, decide() graduation and alerting as the built-in corpus.
pub(crate) fn run_set_verdict_pub(rules: &[Rule], state: *mut RState, n: usize, pkt: &[u8], src: u32, decide_fn: fn(FindingClass, DecideCtx) -> Verdict) -> Option<Verdict> {
    run_set_verdict(rules, state, n, pkt, src, decide_fn)
}

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
        .or_else(|| crate::rulepack::verdict(0, l4, src, verdict::decide))
}

/// L2 frame-tier verdict (`napse-l2guard` parity: malformed-ARP / ARP-spoof).
pub fn verdict_l2(frame: &[u8], src: u32) -> Option<Verdict> {
    run_set_verdict(L2_RULES, addr_of_mut!(RSTATE_L2).cast::<RState>(), NRULES_L2.load(Ordering::Relaxed), frame, src, verdict::decide_l2)
        .or_else(|| crate::rulepack::verdict(1, frame, src, verdict::decide_l2))
}

/// TCP-flag scan-tier verdict (NULL/FIN/Xmas/SYN-FIN). classify runs this ONLY on TCP.
pub fn verdict_tcp(tcp: &[u8], src: u32) -> Option<Verdict> {
    run_set_verdict(TCP_RULES, addr_of_mut!(RSTATE_TCP).cast::<RState>(), NRULES_TCP.load(Ordering::Relaxed), tcp, src, verdict::decide)
        .or_else(|| crate::rulepack::verdict(2, tcp, src, verdict::decide))
}

/// Stateful flow-tier verdict (per-source SYN-flood rate-limit, blocklist).
pub fn verdict_flow(frame: &[u8], src: u32) -> Option<Verdict> {
    run_set_verdict(FLOW_RULES, addr_of_mut!(RSTATE_FLOW).cast::<RState>(), NRULES_FLOW.load(Ordering::Relaxed), frame, src, verdict::decide)
        .or_else(|| crate::rulepack::verdict(3, frame, src, verdict::decide))
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
    // Alert de-duplication (detection benchmark 2026-11-09: one port scan raised 974 events, one flow to a
    // blocklisted address 9,001 — each evicting the 256-row detection ring). The WIRE verdict is untouched
    // (a drop still drops every packet); only a repeat EVENT for the same (rule, source) within
    // `ALERT_DEDUP_SECS` is suppressed and counted. Behavioral rules keep their own longer cooldown.
    if !alert_ok(rule_id, src, crate::behavioral::now_secs()) {
        return;
    }
    let wire = v.to_wire();
    crate::events::push_hit(rule_id, severity as u8, wire as u8, v.class_code(), src);
    // Parity G5: every detection scores by SEVERITY, whatever its wire verdict — an observed beacon,
    // lateral sweep or ARP spoof is a threat even though ADR 0023 forbids dropping it. (Behavioral
    // repeats are already throttled by the refire cooldown, so one noisy source cannot pin the score.)
    telemetry::emit_rule_hit(severity);
}

// ---- M2.1: the structural + stateful L2 tier (F6/F7/F8 + mac-flood + broadcast-storm)
// ----

/// ARP cache poisoning: an ARP reply / announcement claiming an IPv4 address that was bound to a DIFFERENT
/// MAC within `ARP_BIND_SECS`, UNSOLICITED (a reply answering a who-has from the last 2 s is proxy ARP — a
/// router / range extender — not poisoning; real-traffic benchmark 2026-11-09). Observe-only.
pub const RULE_ARP_POISON: u16 = 127;
const ARP_BIND_SECS: u64 = 600;
const ARP_N: usize = 128;
const ARP_REQ_N: usize = 64;
static ARP_REQ_IP: [core::sync::atomic::AtomicU64; ARP_REQ_N] = [const { core::sync::atomic::AtomicU64::new(0) }; ARP_REQ_N];
static ARP_REQ_AT: [core::sync::atomic::AtomicU64; ARP_REQ_N] = [const { core::sync::atomic::AtomicU64::new(0) }; ARP_REQ_N];
fn now_ms() -> u64 {
    crate::clock::ticks().saturating_mul(1000) / crate::clock::freq().max(1)
}
static ARP_IP: [core::sync::atomic::AtomicU64; ARP_N] = [const { core::sync::atomic::AtomicU64::new(0) }; ARP_N];
static ARP_MAC: [core::sync::atomic::AtomicU64; ARP_N] = [const { core::sync::atomic::AtomicU64::new(0) }; ARP_N];
static ARP_AT: [core::sync::atomic::AtomicU64; ARP_N] = [const { core::sync::atomic::AtomicU64::new(0) }; ARP_N];

/// Learn IP -> MAC from ARP replies / gratuitous ARPs; return the claimed IP when a claim conflicts with a
/// recent binding (a re-bind after `ARP_BIND_SECS` — a DHCP address reused by a new device — is learned
/// silently). Requests asking for someone else teach nothing.
pub fn arp_binding_conflict(f: &[u8], now: u64) -> Option<u32> {
    use core::sync::atomic::Ordering::Relaxed;
    if f.len() < 42 || f[12] != 0x08 || f[13] != 0x06 || f[14..16] != [0, 1] || f[16..18] != [8, 0] {
        return None;
    }
    let op = u16::from_be_bytes([f[20], f[21]]);
    let sip = u32::from_be_bytes([f[28], f[29], f[30], f[31]]);
    let tip = u32::from_be_bytes([f[38], f[39], f[40], f[41]]);
    // a who-has for `tip`: remember it — a reply that ANSWERS a recent request is solicited (proxy ARP by a
    // router / range extender answers requests; poisoning tools send unsolicited replies)
    if op == 1 && sip != tip {
        let j = crate::ratelimit::slot(tip as u64 | (2 << 40), ARP_REQ_N);
        ARP_REQ_IP[j].store(tip as u64 | (2 << 40), Relaxed);
        ARP_REQ_AT[j].store(now_ms(), Relaxed);
        return None;
    }
    if sip == 0 || !(op == 2 || (op == 1 && sip == tip)) {
        return None;
    }
    let solicited = op == 2 && {
        let j = crate::ratelimit::slot(sip as u64 | (2 << 40), ARP_REQ_N);
        ARP_REQ_IP[j].load(Relaxed) == sip as u64 | (2 << 40) && now_ms().saturating_sub(ARP_REQ_AT[j].load(Relaxed)) < 2_000
    };
    let mac = crate::ratelimit::mac_hash(&f[22..28]);
    let i = crate::ratelimit::slot(sip as u64 | (1 << 40), ARP_N);
    let (kip, kmac, kat) = (ARP_IP[i].load(Relaxed), ARP_MAC[i].load(Relaxed), ARP_AT[i].load(Relaxed));
    let key = sip as u64 | (1 << 40);
    let conflict = kip == key && kmac != mac && now.saturating_sub(kat) < ARP_BIND_SECS && !solicited;
    if !conflict {
        ARP_IP[i].store(key, Relaxed);
        ARP_MAC[i].store(mac, Relaxed);
        ARP_AT[i].store(now, Relaxed);
    }
    conflict.then_some(sip)
}

/// Test hook.
#[cfg_attr(not(feature = "detbench"), allow(dead_code))]
pub fn arp_binding_reset() {
    use core::sync::atomic::Ordering::Relaxed;
    for a in &ARP_IP {
        a.store(0, Relaxed);
    }
}

/// Rule IDs for the M2.1 tier (kept distinct from the bytecode L2 corpus 101/102).
pub const RULE_STRUCT_ANOMALY: u16 = 110;
pub const RULE_MAC_FLOOD: u16 = 111;
pub const RULE_BCAST_STORM: u16 = 112;
/// RA-guard (RFC 6105): a rogue ICMPv6 Router Advertisement on a non-router port
/// (matrix A9); a legit RA on an uplink is Observed (L4). Kept distinct from the L2
/// tier 110-112 and the truncated/behavioral ids.
pub const RULE_ROGUE_RA: u16 = 121;
/// A9-3: an RA FLOOD from one source MAC on one port (> `ratelimit::RA_FLOOD_THRESH`
/// per window) → `FloodRate` → self-reverting `RateLimit` on ANY port — rate reality,
/// identity-blind, the one RA arm the security-auditor ruling approved to arm now.
pub const RULE_RA_FLOOD: u16 = 122;
/// A9-7: an IPv6 frame whose extension chain `parse_ipv6` refuses (evasion made
/// VISIBLE, observe-only — never a drop).
pub const RULE_IPV6_UNPARSEABLE: u16 = 123;

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
    // never dropped until a manifest marks a specific access interface. The IPv4 mgmt
    // floor does NOT cover this path (`src` is 0 for IPv6 frames) and the Access
    // FrameDrop arm is embargoed from arming — see heqk-detection-parity.md §5 (A9).
    // Guards ICMPv6 type 134 only (Redirect 137 / NA-Override 136 / DHCPv6 scoped-absent).
    //
    // A9-5 attribution: an IPv6 frame has no IPv4 `src`, so rules 121-123 carry the
    // low 32 bits of `ratelimit::mac_hash(src MAC)` in `Event.src` instead (documented
    // rule-keyed interpretation in events.rs) — without it the D16 promote/confirm loop
    // is impossible and a guard-caused outage undiagnosable.
    let mac_attr = if frame.len() >= 12 { crate::ratelimit::mac_hash(&frame[6..12]) } else { 0 };
    if crate::net::is_icmpv6_ra(frame) {
        let v = verdict::decide_l2(FindingClass::RaGuard, ctx);
        fire(RULE_ROGUE_RA, SEV_HIGH, v, mac_attr as u32);
        if v.is_drop() {
            return Some(v);
        }
        if observed.is_none() {
            observed = Some(v);
        }
        // A9-3: the RA FLOOD arm — approved to arm NOW on any port. A legit router paces
        // to ~4 RAs / 10 s (RFC 4861); exceeding RA_FLOOD_THRESH from ONE source MAC on
        // this port is a rate wall crossed → FloodRate → bounded, self-reverting
        // RateLimit (the same shape as the A3 broadcast-storm shed). Keyed per
        // (port, src MAC): a legit router beside the flooder keeps its own budget.
        if crate::ratelimit::ra_rate_over(port, mac_attr, crate::ratelimit::RA_FLOOD_THRESH) {
            let v = verdict::decide_l2(FindingClass::FloodRate, ctx);
            fire(RULE_RA_FLOOD, SEV_HIGH, v, mac_attr as u32);
            if v.is_drop() {
                return Some(v);
            }
        }
    } else if crate::net::ipv6_unparseable(frame) {
        // A9-7: an IPv6 extension chain parse_ipv6 refuses is INVISIBLE to the RA-guard
        // (an RA behind a padded Hop-by-Hop chain bypasses it silently). Surface it as
        // an observe-level finding so evasion is SEEN — never a drop (legit ext-header
        // users exist; Behavioral is Observe by construction).
        let v = verdict::decide_l2(FindingClass::Behavioral, ctx);
        fire(RULE_IPV6_UNPARSEABLE, SEV_LOW, v, mac_attr as u32);
        if observed.is_none() {
            observed = Some(v);
        }
    }

    // ARP cache poisoning (detection benchmark 2026-11-09: rule 102 only catches an ARP whose sender MAC
    // disagrees with the Ethernet source; a poisoner sends consistent MACs). Observe-only (ADR 0023).
    if let Some(claim) = arp_binding_conflict(frame, crate::behavioral::now_secs()) {
        let v = verdict::decide(FindingClass::Behavioral, DecideCtx::for_src(claim));
        fire(RULE_ARP_POISON, SEV_HIGH, v, claim);
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
    // storm), PER SOURCE MAC (V1 l2guard parity — many devices' normal broadcasts never add up to one). A genuine flood on an Access port → RateLimit; Uplink → Observe.
    if crate::net::dst_is_bcast_or_mcast(frame) && !is_exempt_multicast(&frame[0..6])
        && frame.len() >= 12
        && crate::ratelimit::bcast_over_src(port, crate::ratelimit::mac_hash(&frame[6..12]), BCAST_STORM_THRESH) == 1 {
            // attribute the flooder: an ARP storm has no IPv4 header — take the ARP sender address
            let src = if src == 0 && frame.len() >= 32 && frame[12] == 0x08 && frame[13] == 0x06 {
                u32::from_be_bytes([frame[28], frame[29], frame[30], frame[31]])
            } else {
                src
            };
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
    const TCP_RST: u8 = 0x04;
    // ADR 0049 D3 — scans count only with evidence the probe reached a real host, and establishment credit
    // needs the target's SYN-ACK. The responder's frame (SYN-ACK / RST) is keyed on its DESTINATION (the
    // prober) and its SOURCE port (the probed port).
    let dst = crate::net::eth_ipv4_dst(frame).unwrap_or(0);
    if flags & TCP_RST != 0 || (flags & TCP_SYN != 0 && flags & TCP_ACK != 0) {
        crate::ratelimit::scan_response_observe(dst as u64, meta.src_port, flags & TCP_SYN != 0);
        // slow-scan tier: a CLOSED-port answer (RST) to `dst`'s probe, counted over 30 minutes. Observe-only:
        // the fast tier owns enforcement; this only makes a patient sweep visible.
        if flags & TCP_RST != 0 && crate::ratelimit::slow_scan_observe(dst as u64, meta.src_port, crate::behavioral::now_secs()) {
            let v = verdict::decide(FindingClass::Behavioral, DecideCtx::for_src(dst));
            fire(RULE_PORT_SCAN, SEV_MED, v, dst);
        }
    } else if flags & TCP_ACK != 0 {
        // An ACK on a flow: establishment credit for this (source, port) — only after a SYN-ACK.
        crate::ratelimit::flow_ack_observe(src64, meta.dst_port);
    } else if flags & TCP_SYN != 0 {
        // A SYN-only connection attempt ⇒ a NEW flow (occupancy gauge) and a probe of this port.
        crate::ratelimit::flow_new();
        crate::ratelimit::syn_scan_observe(src64, meta.dst_port, crate::ratelimit::is_local_ip(dst));
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

/// ADR 0049 D2 (parity G24a/G18) — the same scan SHAPE for an IPv6 TCP frame, OBSERVE-ONLY. `src` is the
/// tagged key of the frame's sender (`srckey::dev` on our LAN, `srckey::v6net` from the internet) and
/// `dst` the key of its receiver — used when the frame is an ANSWER (RST / SYN-ACK), which credits the prober
/// exactly as `flow_scan_verdict` does for IPv4 (ADR 0049 D3: no answer, no count). Never a wire action:
/// IPv6 sources stay observe-only until the separation matrix has its IPv6 rows on metal. Returns true when
/// `src` is over the scan wall.
pub fn flow_scan_observe6(frame: &[u8], src: u64, dst: u64) -> bool {
    if src == 0 {
        return false;
    }
    let Some(meta) = crate::net::parse(frame) else { return false };
    if meta.ethertype != crate::net::ETHERTYPE_IPV6 || meta.ip_proto != crate::net::IPPROTO_TCP || !meta.has_l4_ports() {
        return false;
    }
    let Some(&flags) = frame.get(meta.l4_off + 13) else { return false };
    if flags & 0x04 != 0 || (flags & 0x02 != 0 && flags & 0x10 != 0) {
        crate::ratelimit::scan_response_observe(dst, meta.src_port, flags & 0x02 != 0);
        return false;
    } else if flags & 0x10 != 0 {
        crate::ratelimit::flow_ack_observe(src, meta.dst_port);
    } else if flags & 0x02 != 0 {
        crate::ratelimit::syn_scan_observe(src, meta.dst_port, false);
    }
    if crate::ratelimit::scan_over_ratelimit(src) {
        crate::srckey::note_v6_scan(src, crate::ratelimit::scan_confirmed(src));
        return true;
    }
    false
}

/// G36: the IPv6 half of the behavioural tier for a dual-stack LAN device. Its IPv6 connection attempts
/// (pure SYNs) feed beacon + brute force under the device's IPv4 `lease` (the identity the owner knows),
/// the peer folded by `srckey::v6_peer`. Observe-only like the IPv4 tier; a device with no lease is skipped.
pub fn behavioral_observe6(frame: &[u8], lease: u32) {
    if lease == 0 || frame.len() < 54 {
        return;
    }
    let Some(m) = crate::net::parse(frame) else { return };
    if m.ethertype != crate::net::ETHERTYPE_IPV6 || m.ip_proto != crate::net::IPPROTO_TCP || !m.has_l4_ports() {
        return;
    }
    if frame.get(m.l4_off + 13).is_none_or(|&f| f & 0x12 != 0x02) {
        return;
    }
    let mut d6 = [0u8; 16];
    d6.copy_from_slice(&frame[38..54]);
    let peer = crate::srckey::v6_peer(&d6);
    let _ = beacon_verdict(lease, peer, m.dst_port);
    let _ = brute_verdict(lease, peer, m.dst_port);
}

/// G36 / audit Phase 4: IPv6 LATERAL movement between two LAN devices (the station-to-station relay). A pure
/// SYN from one device's IPv6 address to another's feeds the same lateral tier as IPv4, keyed on both
/// devices' IPv4 leases (the identities the owner knows) — so a dual-stack worm sweeping SMB / RDP / SSH over
/// IPv6 is no longer invisible. Observe-only, like every behavioural finding. Returns true when it fired.
pub fn lateral_observe6(frame: &[u8], src_lease: u32, dst_lease: u32) -> bool {
    if src_lease == 0 || dst_lease == 0 || frame.len() < 54 {
        return false;
    }
    let Some(m) = crate::net::parse(frame) else { return false };
    if m.ethertype != crate::net::ETHERTYPE_IPV6 || m.ip_proto != crate::net::IPPROTO_TCP || !m.has_l4_ports() {
        return false;
    }
    if frame.get(m.l4_off + 13).is_none_or(|&f| f & 0x12 != 0x02) {
        return false;
    }
    lateral_verdict(src_lease, dst_lease, m.dst_port).is_some()
}

/// Phase 4 (device baseline): a single-purpose device used a service it never used before (rule 128).
/// Behavioral → observe-only (never a drop).
pub fn baseline_change(src: u32) {
    let v = verdict::decide(FindingClass::Behavioral, DecideCtx::for_src(src));
    fire(crate::devbase::RULE_BASELINE, SEV_MED, v, src);
}

/// G24a: an IPv6 peer on the signed IOC pack — the same observe-only IOC detection (rule 302, identity
/// reputation: never a drop) the IPv4 flow tier raises, attributed to the LAN device's IPv4 lease.
pub fn ioc_v6_hit(lease: u32, peer: &[u8; 16]) -> bool {
    if lease == 0 || !crate::ioc::ip6_listed(peer) {
        return false;
    }
    let v = verdict::decide(FindingClass::IdentityReputation, DecideCtx::for_src(lease));
    if refire_ok(302, lease, crate::behavioral::now_secs()) {
        fire(302, SEV_HIGH, v, lease);
    }
    true
}

/// G36: an inbound IPv6 SYN-ACK to a LAN device = the D3 evidence that the service it is hammering exists.
pub fn brute_answer6(frame: &[u8], lease: u32) {
    if lease == 0 || frame.len() < 54 {
        return;
    }
    let Some(m) = crate::net::parse(frame) else { return };
    if m.ethertype != crate::net::ETHERTYPE_IPV6 || m.ip_proto != crate::net::IPPROTO_TCP || !m.has_l4_ports() {
        return;
    }
    if frame.get(m.l4_off + 13).is_none_or(|&f| f & 0x12 != 0x12) {
        return;
    }
    let mut s6 = [0u8; 16];
    s6.copy_from_slice(&frame[22..38]);
    crate::behavioral::brute_answer_at(crate::srckey::v6_peer(&s6), lease, m.src_port, crate::behavioral::now_secs());
}

/// ADR 0049 D3 on the AP's NAT path: the IDS sees inbound answers BEFORE un-NAT (addressed to the WAN IP),
/// so a LAN client's probes could never be matched. The un-NATed frame (addressed to the client) is fed here
/// so the target's RST / SYN-ACK credits the right prober. Observation only — no verdict.
pub fn scan_response_hook(frame: &[u8]) {
    let Some(meta) = crate::net::parse(frame) else { return };
    if meta.ip_proto != crate::net::IPPROTO_TCP || !meta.has_l4_ports() {
        return;
    }
    let Some(&flags) = frame.get(meta.l4_off + 13) else { return };
    if flags & 0x04 != 0 || (flags & 0x02 != 0 && flags & 0x10 != 0) {
        let dst = crate::net::eth_ipv4_dst(frame).unwrap_or(0);
        crate::ratelimit::scan_response_observe(dst as u64, meta.src_port, flags & 0x02 != 0);
        // Rule 124's evidence too: on the AP the IDS sees the server's SYN-ACK BEFORE un-NAT (addressed to the
        // WAN IP), so the answer must be credited here, to the real LAN client (metal 2026-11-08: a 30-attempt
        // SSH burst from a LAN client was missed until this).
        if flags & 0x12 == 0x12 {
            let server = crate::net::eth_ipv4_src(frame);
            crate::behavioral::brute_answer_at(server, dst, meta.src_port, crate::behavioral::now_secs());
        }
    }
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
pub const RULE_TLS_IOC: u16 = 125; // known-malicious TLS client (JA4 in the signed IOC pack)
pub const RULE_TLS_BYPASS: u16 = 126; // TLS to a name Shield blocks: the device resolved it without Shield
pub const RULE_BRUTE: u16 = 124; // brute force on one admin service (T1110), observe-only
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
    // G34: both triggers below also require `s` to be THE top talker — two atomic loads. Almost every packet
    // is not, so answer that first and skip the flow-count clock read and the run-queue query (same verdict).
    if !crate::ratelimit::is_top_talker(s) {
        return None;
    }
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

/// Behavioral alert refire cooldown (parity G4): once a (rule, source) has alerted, further trips within
/// this window are counted (corroboration still sees them) but raise no new event — a regular beacon or
/// a sustained transfer would otherwise alert on every packet and evict the 256-row detection ring.
pub const BEHAVIORAL_COOLDOWN_SECS: u64 = 300;
const COOL_N: usize = 128;
static COOL_KEY: [core::sync::atomic::AtomicU64; COOL_N] = [const { core::sync::atomic::AtomicU64::new(0) }; COOL_N];
static COOL_AT: [core::sync::atomic::AtomicU64; COOL_N] = [const { core::sync::atomic::AtomicU64::new(0) }; COOL_N];
pub static COOL_SUPPRESSED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// True if (rule, src) may raise an event now (and arms the cooldown). `now` in seconds.
pub fn refire_ok(rule_id: u16, src: u32, now: u64) -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    let key = ((rule_id as u64) << 32) | src as u64 | (1u64 << 63);
    let i = (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 57) as usize % COOL_N;
    if COOL_KEY[i].load(Relaxed) == key && now.saturating_sub(COOL_AT[i].load(Relaxed)) < BEHAVIORAL_COOLDOWN_SECS {
        COOL_SUPPRESSED.fetch_add(1, Relaxed);
        return false;
    }
    COOL_KEY[i].store(key, Relaxed);
    COOL_AT[i].store(now, Relaxed);
    true
}

/// Repeat-event window for `fire()` (all rules): one event per (rule, source) per minute.
pub const ALERT_DEDUP_SECS: u64 = 60;
const DEDUP_N: usize = 512;
static DEDUP_KEY: [core::sync::atomic::AtomicU64; DEDUP_N] = [const { core::sync::atomic::AtomicU64::new(0) }; DEDUP_N];
static DEDUP_AT: [core::sync::atomic::AtomicU64; DEDUP_N] = [const { core::sync::atomic::AtomicU64::new(0) }; DEDUP_N];
pub static DEDUP_SUPPRESSED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static DEDUP_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);

/// True if (rule, src) may raise an event now (and arms the window). An aliasing pair just evicts — at worst
/// one extra event, never a lost one.
pub fn alert_ok(rule_id: u16, src: u32, now: u64) -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    if !DEDUP_ON.load(Relaxed) {
        return true;
    }
    let key = ((rule_id as u64) << 32) | src as u64 | (1u64 << 62);
    let i = crate::ratelimit::slot(key, DEDUP_N);
    if DEDUP_KEY[i].load(Relaxed) == key && now.saturating_sub(DEDUP_AT[i].load(Relaxed)) < ALERT_DEDUP_SECS {
        DEDUP_SUPPRESSED.fetch_add(1, Relaxed);
        return false;
    }
    DEDUP_KEY[i].store(key, Relaxed);
    DEDUP_AT[i].store(now, Relaxed);
    true
}

/// Self-tests that count individual events switch the de-duplication off (and back on).
pub fn alert_dedup(on: bool) {
    DEDUP_ON.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// `[P-alert-dedup]` — one event per (rule, source) per window; the wire verdict is untouched.
#[cfg_attr(not(feature = "securechannel-selftest"), allow(dead_code))]
pub fn dedup_selftest() -> bool {
    refire_reset();
    let mut evs = [crate::events::Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0, class: 0, dport: 0, dst: 0 }; 64];
    let _ = crate::events::drain(&mut evs);
    let first = alert_ok(113, 0x0a63_0042, 1000);
    let repeats = (0..50).all(|i| !alert_ok(113, 0x0a63_0042, 1000 + i));
    let other_src = alert_ok(113, 0x0a63_0043, 1001);
    let other_rule = alert_ok(124, 0x0a63_0042, 1001);
    let after = alert_ok(113, 0x0a63_0042, 1000 + ALERT_DEDUP_SECS);
    let suppressed = DEDUP_SUPPRESSED.load(core::sync::atomic::Ordering::Relaxed) >= 50;
    refire_reset();
    let pass = first && repeats && other_src && other_rule && after && suppressed;
    arch_aarch64::_print(format_args!(
        " [P-alert-dedup] {} — repeat alerts collapse to one event per (rule, source) per {} s (a port scan raised 974 events, a blocklisted flow 9,001 — detection benchmark 2026-11-09): first alert={} 50 repeats suppressed + counted={} another source still alerts={} another rule still alerts={} next window alerts again={}\n",
        if pass { "PASS" } else { "FAIL" }, ALERT_DEDUP_SECS, first, repeats && suppressed, other_src, other_rule, after
    ));
    pass
}

/// Test hook: clear the cooldown table.
pub fn refire_reset() {
    use core::sync::atomic::Ordering::Relaxed;
    for i in 0..COOL_N {
        COOL_KEY[i].store(0, Relaxed);
        COOL_AT[i].store(0, Relaxed);
    }
    for i in 0..DEDUP_N {
        DEDUP_KEY[i].store(0, Relaxed);
        DEDUP_AT[i].store(0, Relaxed);
    }
}

/// M2.4 shared verdict step: a behavioral detector FIRED → route through `decide()` as
/// `FindingClass::Behavioral`, OBSERVE-ONLY by construction; `fire()` exports the alert (subject to
/// the refire cooldown); the wire is never touched — detection parity WITHOUT enforcement.
#[inline]
fn behavioral_verdict(rule_id: u16, src: u32, axis: u32) -> Verdict {
    behavioral_verdict_at(rule_id, src, axis, crate::behavioral::now_secs())
}

fn behavioral_verdict_at(rule_id: u16, src: u32, axis: u32, now: u64) -> Verdict {
    let v = verdict::decide(FindingClass::Behavioral, DecideCtx::for_src(src));
    // A11 corroboration (SEVERITY only): record this behavioral axis; a source corroborated
    // across >= K axes is stamped CRITICAL for the SOC. `v` stays `Observe` — behavioral is
    // observe-only by construction, and corroboration NEVER changes the wire verdict.
    crate::corroboration::corr_observe(src as u64, axis);
    let sev = if crate::corroboration::is_corroborated(src as u64) { SEV_CRIT } else { SEV_MED };
    if refire_ok(rule_id, src, now) {
        fire(rule_id, sev, v, src);
    }
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
    Some(behavioral_verdict_at(RULE_BEACON, src, crate::corroboration::AXIS_BEACON, now))
}

/// Live-clock wrapper for the datapath (M2.4 A10/L8 wiring): same as `beacon_verdict_at`
/// but sources `now` from the real monotonic clock instead of an injected test value.
pub fn beacon_verdict(src: u32, dst: u32, dst_port: u16) -> Option<Verdict> {
    beacon_verdict_at(src, dst, dst_port, crate::behavioral::now_secs())
}

/// Rule 125 — a TLS ClientHello whose JA4 is in the signed IOC pack (observe-only, like every IOC match).
pub fn tls_ioc_verdict(src: u32) {
    let _ = behavioral_verdict(RULE_TLS_IOC, src, crate::corroboration::AXIS_BEACON);
}

/// Rule 126 — TLS to a Shield-blocked name: DNS protection was bypassed (DoH / hard-coded IP / stale
/// answer). Observe-only; enforcing on SNI would be a separate policy decision.
pub fn tls_bypass_verdict(src: u32) {
    let _ = behavioral_verdict(RULE_TLS_BYPASS, src, crate::corroboration::AXIS_BEACON);
}

/// Rule 124 brute force — a connection ATTEMPT (SYN-only) to an admin service; fires (observe-only) once per
/// answered burst. `brute_answer` records the server's SYN-ACK (the D3 evidence the service exists).
pub fn brute_verdict(src: u32, dst: u32, dst_port: u16) -> Option<Verdict> {
    if !crate::behavioral::brute_attempt_at(src, dst, dst_port, crate::behavioral::now_secs()) {
        return None;
    }
    Some(behavioral_verdict(RULE_BRUTE, src, crate::corroboration::AXIS_LATERAL))
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

/// Parity G7: a Shield query for an IOC-pack domain — `ioc_match` (rule 302's catalogue entry),
/// observe-only + refire-cooled per source (identity-based intel never drops, ADR 0023).
pub fn ioc_domain_verdict(src: u32) -> Verdict {
    behavioral_verdict(302, src, crate::corroboration::AXIS_DNS)
}

/// Parity G8: a Shield query whose name scored as DGA / lookalike / tunnel (`dga::score`). Observe-only
/// (`dns_dga`), refire-cooled per source; the name itself is still answered normally.
pub fn shield_dga_verdict(src: u32) -> Verdict {
    behavioral_verdict(RULE_DNS, src, crate::corroboration::AXIS_DNS)
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

/// `[P8-JIT-CALL]` — the JIT's BPF CALL support, differential against the interpreter (QEMU + metal):
/// (1) `ip-blocklist` (helper 2) over 4096 frames — listed / unlisted sources, non-IPv4; (2) `syn-flood-per-src`
/// (helper 1, stateful) — the same verdict sequence across the rate limit from a fresh key on each side;
/// (3) register preservation — R3..R9 set, a CALL, then summed: 42 on both; (4) plain `compile` still declines.
pub fn jit_call_selftest() -> bool {
    use crate::bpf::{insn, run, IP_BLOCKLIST, SYN_LIMIT, TCP_SYN_FLOOD_SRC};
    let comp = |p: &[u64]| arch_aarch64::bpf_jit::compile_with_helper(p, crate::ratelimit::call_helper_c as *const () as usize, crate::ratelimit::JIT_HELPERS);
    let call = |va: usize, f: &[u8]| -> u64 {
        let fun: extern "C" fn(*const u8) -> u64 = unsafe { core::mem::transmute::<usize, extern "C" fn(*const u8) -> u64>(va) };
        fun(f.as_ptr())
    };
    let mut f = [0u8; 64];
    let ipv4 = |f: &mut [u8; 64], src: [u8; 4], proto: u8, flags: u8| {
        f.fill(0);
        f[12] = 0x08;
        f[14] = 0x45;
        f[23] = proto;
        f[26..30].copy_from_slice(&src);
        f[47] = flags;
    };
    // (1) blocklist
    let mut bl_ok = false;
    let mut bl_mis = 0u32;
    let mut bl_hits = 0u32;
    if let Some(va) = comp(&IP_BLOCKLIST) {
        bl_ok = true;
        for i in 0u32..4096 {
            let b = (i & 0xff) as u8;
            let src = match i % 5 {
                0 => [192, 0, 2, b],
                1 => [10, 66, 66, b],
                2 => [203, 0, 113, b],
                3 => [100, 64, (i >> 8) as u8, b],
                _ => [b, (i >> 8) as u8, 7, 9],
            };
            ipv4(&mut f, src, 6, 0x10);
            if i % 97 == 0 {
                f[12] = 0x08;
                f[13] = 0x06; // ARP: the no-call path
            }
            let (j, r) = (call(va, &f), run(&IP_BLOCKLIST, f.as_ptr(), f.len()));
            bl_hits += (r == crate::bpf::DROP) as u32;
            if j != r {
                bl_mis += 1;
            }
        }
    }
    // (2) per-source SYN flood: interpreter on key A, JIT on key B, same sequence
    let mut syn_ok = false;
    let mut syn_mis = 0u32;
    let mut drops = 0u32;
    if let Some(va) = comp(&TCP_SYN_FLOOD_SRC) {
        syn_ok = true;
        let n = SYN_LIMIT as usize + 20;
        let mut seq = [0u64; 512];
        ipv4(&mut f, [100, 127, 1, 1], 6, 0x02);
        for v in seq.iter_mut().take(n) {
            *v = run(&TCP_SYN_FLOOD_SRC, f.as_ptr(), f.len());
        }
        ipv4(&mut f, [100, 127, 1, 2], 6, 0x02);
        for v in seq.iter().take(n) {
            let j = call(va, &f);
            drops += (j == crate::bpf::DROP) as u32;
            syn_mis += (j != *v) as u32;
        }
    }
    // (2b) regression: a flooder on a busy LAN. The slot used to be the FIRST octet, so 10.0.0.10's SYNs reset
    // 10.0.0.66's count and the per-source limiter never tripped. Now it must.
    let mut busy_drops = 0u32;
    for k in 0..(SYN_LIMIT as u32 + 40) {
        ipv4(&mut f, [10, 0, 0, 66], 6, 0x02);
        busy_drops += (run(&TCP_SYN_FLOOD_SRC, f.as_ptr(), f.len()) == crate::bpf::DROP) as u32;
        if k % 4 == 0 {
            ipv4(&mut f, [10, 0, 0, 10], 6, 0x02);
            let _ = run(&TCP_SYN_FLOOD_SRC, f.as_ptr(), f.len());
        }
    }
    // (3) register preservation across CALL
    let prog: [u64; 18] = [
        insn(0xb7, 3, 0, 0, 3),
        insn(0xb7, 4, 0, 0, 4),
        insn(0xb7, 5, 0, 0, 5),
        insn(0xb7, 6, 0, 0, 6),
        insn(0xb7, 7, 0, 0, 7),
        insn(0xb7, 8, 0, 0, 8),
        insn(0xb7, 9, 0, 0, 9),
        insn(0xb7, 1, 0, 0, 0),
        insn(0xb7, 2, 0, 0, 0),
        insn(0x85, 0, 0, 0, crate::ratelimit::HELPER_IP_BLOCKED as i32),
        insn(0x0f, 0, 3, 0, 0),
        insn(0x0f, 0, 4, 0, 0),
        insn(0x0f, 0, 5, 0, 0),
        insn(0x0f, 0, 6, 0, 0),
        insn(0x0f, 0, 7, 0, 0),
        insn(0x0f, 0, 8, 0, 0),
        insn(0x0f, 0, 9, 0, 0),
        insn(0x95, 0, 0, 0, 0),
    ];
    let interp = run(&prog, f.as_ptr(), f.len());
    let regs = comp(&prog).map(|va| call(va, &f));
    let regs_ok = interp == 42 && regs == Some(42);
    // (4) the call-less entry point still declines CALL; a helper outside the allowlist declines too
    let declines = arch_aarch64::bpf_jit::compile(&TCP_SYN_FLOOD_SRC).is_none()
        && arch_aarch64::bpf_jit::compile_with_helper(&IP_BLOCKLIST, crate::ratelimit::call_helper_c as *const () as usize, 1 << crate::ratelimit::HELPER_SYN_RATE_OVER).is_none();
    let pass = bl_ok && bl_mis == 0 && bl_hits > 0 && syn_ok && syn_mis == 0 && drops > 0 && busy_drops > 0 && regs_ok && declines;
    arch_aarch64::_print(format_args!(
        " [P8-JIT-CALL] {} — BPF CALL in the JIT (scalar helpers 1/2, x1..x10 preserved, frame per calling rule): ip-blocklist 4096 frames {} mismatches ({} listed) | syn-flood-per-src {} SYNs {} mismatches ({} over the limit) | busy-LAN flooder trips the limiter ({} drops) | registers across CALL interp={} jit={:?} | call-less compile + off-allowlist helper decline={}\n",
        if pass { "PASS" } else { "FAIL" }, bl_mis, bl_hits, SYN_LIMIT as u32 + 20, syn_mis, drops, busy_drops, interp, regs, declines
    ));
    pass
}

/// `[P-lateral6]` — IPv6 lateral movement between LAN devices is detected under their IPv4 leases.
pub fn lateral6_selftest() -> bool {
    fn syn6(dport: u16, d: u8) -> [u8; 74] {
        let mut f = [0u8; 74];
        f[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, d]);
        f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x50]);
        f[12..14].copy_from_slice(&[0x86, 0xdd]);
        f[14] = 0x60;
        f[18..20].copy_from_slice(&20u16.to_be_bytes()); // payload length
        f[20] = 6; // TCP
        f[21] = 64;
        f[22..24].copy_from_slice(&[0xfe, 0x80]);
        f[37] = 0x50;
        f[38..40].copy_from_slice(&[0xfe, 0x80]);
        f[53] = d;
        f[54..56].copy_from_slice(&49152u16.to_be_bytes());
        f[56..58].copy_from_slice(&dport.to_be_bytes());
        f[66] = 0x50; // data offset 5
        f[67] = 0x02; // SYN
        f
    }
    let src = u32::from_be_bytes([10, 99, 0, 50]);
    // an SMB sweep over IPv6 to 8 devices: fires once more than LATERAL_THRESHOLD peers were touched
    let mut fired = false;
    for d in 0..8u8 {
        fired |= lateral_observe6(&syn6(445, 0x60 + d), src, u32::from_be_bytes([10, 99, 0, 60 + d]));
    }
    // a device talking SMB to ONE file server over IPv6, many times: never lateral
    let one = u32::from_be_bytes([10, 99, 0, 51]);
    let quiet = (0..8).all(|_| !lateral_observe6(&syn6(445, 0x70), one, u32::from_be_bytes([10, 99, 0, 70])));
    // a web port is not a lateral-movement port; unknown leases are skipped
    let web = !lateral_observe6(&syn6(443, 0x71), u32::from_be_bytes([10, 99, 0, 52]), u32::from_be_bytes([10, 99, 0, 71]))
        && !lateral_observe6(&syn6(445, 0x72), 0, u32::from_be_bytes([10, 99, 0, 72]));
    let pass = fired && quiet && web;
    arch_aarch64::_print(format_args!(
        " [P-lateral6] {} — IPv6 lateral movement between LAN devices (station relay, G36): an SMB sweep over IPv6 to 8 devices raises the lateral finding under the sender's IPv4 lease={} ; repeated SMB to one file server stays quiet={} ; a web port / an unknown lease never counts={} (observe-only)\n",
        if pass { "PASS" } else { "FAIL" }, fired, quiet, web));
    pass
}
