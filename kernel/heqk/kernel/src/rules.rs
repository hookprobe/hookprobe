//! P8 — HookProbe rule plane: a registry of signed BPF threat rules, each
//! statically verified (PREVAIL) and JIT-compiled at load, run on every packet's
//! L4 header. **Rule parity**: the SAME RFC 9669 bytecode that runs on the
//! Linux/FreeBSD/QNX HookProbe substrates runs here unchanged — the corpus is
//! pluggable; this is the mechanism. On a target without a ready JIT backend
//! (e.g. CM5 metal, whose runtime frame allocator differs) a rule falls back to
//! the bounds-checked interpreter — same verdict, slower.

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
}

/// The signed L4 corpus. R1 = the L4 header (net.rs normalizes eth/VLAN/IHL
/// away), so every rule reads dst-port at a fixed offset regardless of framing.
pub static RULES: &[Rule] = &[
    Rule { id: 1, name: "block-port-4444", prog: &bpf::THREAT_RULE, severity: SEV_HIGH },
    Rule { id: 2, name: "block-telnet-23", prog: &bpf::BLOCK_TELNET, severity: SEV_MED },
    Rule { id: 3, name: "block-backdoor-31337", prog: &bpf::BLOCK_BACKDOOR, severity: SEV_HIGH },
];

/// The signed L2 corpus — parity with HookProbe `napse-l2guard` (Ring-0
/// deterministic frame/ARP enforcement). R1 = the raw L2 FRAME start; these run
/// on EVERY frame (before the L4 tier), mirroring `dpi::ArpObs` predicates.
pub static L2_RULES: &[Rule] = &[
    Rule { id: 101, name: "arp-malformed", prog: &bpf::ARP_MALFORMED, severity: SEV_MED },
    Rule { id: 102, name: "arp-spoof", prog: &bpf::ARP_SPOOF, severity: SEV_HIGH },
];

/// The signed TCP corpus — stateless anomalous-flag scan detection (Nmap/
/// Suricata-style). R1 = the TCP header; classify runs these ONLY on TCP.
pub static TCP_RULES: &[Rule] = &[
    Rule { id: 201, name: "tcp-null-scan", prog: &bpf::TCP_NULL_SCAN, severity: SEV_HIGH },
    Rule { id: 202, name: "tcp-fin-scan", prog: &bpf::TCP_FIN_SCAN, severity: SEV_MED },
    Rule { id: 203, name: "tcp-xmas-scan", prog: &bpf::TCP_XMAS_SCAN, severity: SEV_HIGH },
    Rule { id: 204, name: "tcp-syn-fin", prog: &bpf::TCP_SYNFIN, severity: SEV_HIGH },
];

/// The signed FLOW corpus — STATEFUL rules on the full L2 frame (R1 = frame),
/// keyed per-source via the rate-limiter CALL helper. Runs on every frame; each
/// rule self-parses (IPv4/TCP/…) and PASSes non-matching traffic.
pub static FLOW_RULES: &[Rule] = &[
    Rule { id: 301, name: "syn-flood-per-src", prog: &bpf::TCP_SYN_FLOOD_SRC, severity: SEV_HIGH },
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

/// Run a rule set against a byte view `pkt` (R1 = pkt start). Returns the packet
/// verdict — `packet::DROP` on the first rule that fires, else `packet::PASS`.
/// Uses the JIT when `pkt` is long enough for the rule's proven `min_len`, else
/// the bounds-checked interpreter; a DROP scores a severity-weighted QSecBit hit.
fn run_set(rules: &[Rule], state: *mut RState, n: usize, pkt: &[u8]) -> u16 {
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
        if v != bpf::PASS {
            telemetry::emit_rule_hit(rules[i].severity);
            return crate::packet::DROP;
        }
    }
    crate::packet::PASS
}

/// Run the L4-header rule set against `l4` (R1 = L4 header).
pub fn run_l4(l4: &[u8]) -> u16 {
    run_set(RULES, addr_of_mut!(RSTATE).cast::<RState>(), NRULES.load(Ordering::Relaxed), l4)
}

/// Run the L2 rule set against the raw `frame` (R1 = L2 start) — the
/// `napse-l2guard` parity tier (malformed-ARP / ARP-spoof). Runs on every frame.
pub fn run_l2(frame: &[u8]) -> u16 {
    run_set(L2_RULES, addr_of_mut!(RSTATE_L2).cast::<RState>(), NRULES_L2.load(Ordering::Relaxed), frame)
}

/// Run the TCP-flag scan tier against the TCP header `tcp` (R1 = TCP header).
/// classify runs this ONLY when the L4 protocol is TCP.
pub fn run_tcp(tcp: &[u8]) -> u16 {
    run_set(TCP_RULES, addr_of_mut!(RSTATE_TCP).cast::<RState>(), NRULES_TCP.load(Ordering::Relaxed), tcp)
}

/// Run the STATEFUL flow tier against the raw `frame` (R1 = L2 start) — per-source
/// SYN-flood rate-limit etc. Runs on every frame; each rule self-parses and
/// PASSes non-matching traffic.
pub fn run_flow(frame: &[u8]) -> u16 {
    run_set(FLOW_RULES, addr_of_mut!(RSTATE_FLOW).cast::<RState>(), NRULES_FLOW.load(Ordering::Relaxed), frame)
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
