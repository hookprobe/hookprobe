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

/// The signed corpus. R1 = the L4 header (net.rs normalizes eth/VLAN/IHL away),
/// so every rule reads dst-port at a fixed offset regardless of framing.
pub static RULES: &[Rule] = &[
    Rule { id: 1, name: "block-port-4444", prog: &bpf::THREAT_RULE, severity: SEV_HIGH },
    Rule { id: 2, name: "block-telnet-23", prog: &bpf::BLOCK_TELNET, severity: SEV_MED },
    Rule { id: 3, name: "block-backdoor-31337", prog: &bpf::BLOCK_BACKDOOR, severity: SEV_HIGH },
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
static NRULES: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn rstate(i: usize) -> RState {
    unsafe { addr_of_mut!(RSTATE).cast::<RState>().add(i).read() }
}

/// Verify + JIT-compile every rule once, at boot. A rule that fails verification
/// is DISABLED (never run) — the plane admits only statically-proven-safe rules.
/// Returns (verified_count, jitted_count).
pub fn init() -> (usize, usize) {
    let mut verified = 0usize;
    let mut jitted = 0usize;
    let n = RULES.len().min(MAX_RULES);
    for i in 0..n {
        let st = match bpf::verify_prevail(RULES[i].prog) {
            Ok(min_len) => {
                verified += 1;
                let jit = arch_aarch64::bpf_jit::compile(RULES[i].prog).unwrap_or(0);
                if jit != 0 {
                    jitted += 1;
                }
                RState { verified: true, min_len, jit }
            }
            Err(_) => RState { verified: false, min_len: 0, jit: 0 },
        };
        unsafe { addr_of_mut!(RSTATE).cast::<RState>().add(i).write(st) };
    }
    NRULES.store(n, Ordering::Relaxed);
    (verified, jitted)
}

/// Run the whole signed rule set against an L4 header `l4`. Returns the packet
/// verdict — `packet::DROP` on the first rule that fires, else `packet::PASS`.
/// Uses the JIT when the packet is long enough for the rule's proven `min_len`,
/// else the bounds-checked interpreter. Emits a severity-weighted QSecBit hit on
/// a DROP ("the OS is the sensor").
pub fn run_l4(l4: &[u8]) -> u16 {
    let n = NRULES.load(Ordering::Relaxed);
    for i in 0..n {
        let st = rstate(i);
        if !st.verified {
            continue;
        }
        let v = if st.jit != 0 && l4.len() as u64 >= st.min_len {
            let f: extern "C" fn(*const u8) -> u64 =
                unsafe { core::mem::transmute::<usize, extern "C" fn(*const u8) -> u64>(st.jit) };
            f(l4.as_ptr())
        } else {
            bpf::run(RULES[i].prog, l4.as_ptr(), l4.len())
        };
        if v != bpf::PASS {
            // DROP or INVALID (sandbox) -> fail-safe DROP + a scored threat signal.
            telemetry::emit_rule_hit(RULES[i].severity);
            return crate::packet::DROP;
        }
    }
    crate::packet::PASS
}

/// How many rules are active (verified) — for the boot report.
pub fn active() -> usize {
    let n = NRULES.load(Ordering::Relaxed);
    (0..n).filter(|&i| rstate(i).verified).count()
}
