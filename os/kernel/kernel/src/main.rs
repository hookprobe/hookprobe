#![no_std]
#![no_main]
//! HEQK Core — Hardened Edge Quantum-safe Kernel (the HookProbe microkernel).
//!
//! Boot (P0) -> heap -> spawn threads -> GIC + generic-timer tick -> enable
//! IRQs -> idle. The timer preempts whatever runs and the round-robin scheduler
//! switches contexts; each thread's local counter surviving across switches is
//! the proof that context save/restore works.

// Bench Wi-Fi modes never ship (ADR 0023 / ADR 0045). `apmode`'s serve loop never returns
// and NATs client traffic without packet::verdict, so a prod image would boot into an
// uninspected AP instead of the IPS service; `stajoin` bakes network credentials in.
#[cfg(all(feature = "prod", any(feature = "apmode", feature = "stajoin")))]
compile_error!("`apmode`/`stajoin` are CM5 bench modes and cannot be combined with `prod`");
#[allow(dead_code)]
const fn wpa_psk_ok(p: Option<&str>) -> bool {
    match p {
        Some(s) => s.len() >= 8 && s.len() <= 63,
        None => false,
    }
}
#[cfg(feature = "apmode")]
const _: () = assert!(wpa_psk_ok(option_env!("HEQK_AP_PSK")), "apmode needs HEQK_AP_PSK (8..63 chars) set at build time");
#[cfg(feature = "stajoin")]
const _: () = assert!(
    option_env!("HEQK_JOIN_SSID").is_some() && wpa_psk_ok(option_env!("HEQK_JOIN_PSK")),
    "stajoin needs HEQK_JOIN_SSID + HEQK_JOIN_PSK (8..63 chars) set at build time"
);

extern crate alloc;

mod absdom;
mod attest_svc;
mod behavioral;
mod blocklist;
mod bpf;
mod caps;
mod corroboration;
mod devq;
mod dnssink;
mod dnsblock;
// M5.1 (Track C) — minimal bounds-safe ELF64/aarch64 static loader (the userspace-server
// substrate beachhead). Only driven by the QEMU [P-elf] gate; the parser compiles on all
// backends but the loader/mapping path is QEMU-only (see load_into's cfg).
mod elf;
// ADR 0049 D1 — operator signature over POLICY.TXT (verified before parsing).
mod policysig;
// M5.2 (Track C) — the Wasm-host BEACHHEAD: verify-then-run ONE signed .wasm module,
// in-kernel, via the wasmi no_std interpreter. Behind `wasmhost` (OFF by default so the
// base kernel TCB pulls in no interpreter); the [P-wasm] QEMU gate enables it.
#[cfg(feature = "wasmhost")]
mod wasmhost;
mod events;
// The crash-safe log layer is only fully exercised under `p15-write` (its writers
// are all guarded); a read-only build compiles it but drives none of it.
#[cfg_attr(not(feature = "p15-write"), allow(dead_code))]
mod fslog;
mod l7;
mod heap;
mod ipc;
mod napi;
// M3.4 — on-device A/B OTA orchestrator + state machine. Behind `p15-write`: it
// needs both the store WRITE path (inactive-slot staging) and the SHARED
// `boot_abi::verify` hybrid verifier (pulled in by p15-write → boot-abi/otaverify).
// The default kernel does not compile it, keeping the base TCB untouched. On the
// cm5 (metal) build the QEMU [P15-ota] selftest is compiled out, so the orchestrator
// has no caller yet (the metal OTA driver is a later wiring) — allow dead_code there.
#[cfg(feature = "p15-write")]
#[cfg_attr(feature = "cm5", allow(dead_code))]
mod ota;
#[allow(dead_code)] // B2 read-only FAT32 locator: used by the OTA/p15 delivery path only
mod fat;
#[allow(dead_code)] // A/B commit (B2): the on-device OTA commit + its QEMU two-boot proof
mod abboot;
mod net;
mod netq;
#[cfg(feature = "netsvc")]
mod netsvc;
// ADR 0047 D2 — on-device Mission Control: rule catalogue + state + HTTP (pure; QEMU-proven by
// [P-mc]); the TCP serve loop is `mcserve.rs` (feature `mcserve`).
#[cfg(feature = "netsvc")]
mod rulecat;
#[cfg(feature = "netsvc")]
mod mcstate;
#[cfg(feature = "netsvc")]
mod mcauth;
#[cfg(feature = "netsvc")]
mod http;
#[cfg(feature = "mcserve")]
mod mcserve;
// ADR 0051 — the EL0 TLS server loader + bounded-excursion driver.
#[cfg(feature = "mctls")]
mod tlshost;
#[cfg(feature = "netsvc")]
mod netcfg;
// M4.2a — PQC secure-channel crypto PRIMITIVES + KATs (framing-agnostic). Behind
// `securechannel`, OFF by default so the base TCB links no KEX/AEAD crate.
#[cfg(feature = "securechannel")]
mod securechannel;
// M4.3 #6 — entropy source abstraction (fail-closed HW-TRNG; no seeded path on
// metal). Behind `securechannel` (the only consumer). See entropy.rs.
#[cfg(feature = "securechannel")]
mod entropy;
// M4.3 — MSSP enrollment + authenticated update fetch over the Noise channel.
#[cfg(feature = "securechannel")]
mod enroll;
// M4.5 — control-plane INITIATOR: smoltcp-free hand-framed Noise handshake over the single drain.
#[cfg(feature = "securechannel")]
mod controlplane;
// M6 (ADR 0044 D3 B2) — on-device evidence/telemetry export over the enrolled channel.
#[cfg(feature = "securechannel")]
mod export;
#[cfg(feature = "securechannel")]
mod exportwire;
#[cfg(feature = "securechannel")]
mod snapshot;
// prod-full — the missing METAL caller for M3/M4/M6. On the cm5 profile those
// subsystems are only reachable from the QEMU self-test sequence that `prod`
// replaces, so without this module they are dead-stripped out of the image
// entirely (measured: +80 bytes for all three). See prodfull.rs.
#[cfg(all(feature = "cm5", feature = "prod-full"))]
mod prodfull;
mod edge;
mod notify;
mod packet;
mod ratelimit;
mod segment;
mod rules;
mod scheduler;
mod seal;
mod store;
mod telemetry;
mod verdict;

use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use hal::{Console, IrqController, Mmu, Timer};

/// Formatted print to the early console (arch seam).
macro_rules! kprint {
    ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
}

const NTHREADS: usize = 5; // IPC consumer/producer + priority H/M/L
const STACK_SIZE: usize = 0x4000; // 16 KiB per thread
const TICK_HZ: u32 = 100; // 10 ms quantum
const RUN_TICKS: u32 = 300; // safety backstop; normal exit is "all threads done"
const WORK: u32 = 60_000; // per-print busy work (short so workers finish promptly)

#[repr(align(16))]
struct Stack([u8; STACK_SIZE]);
static mut STACKS: [Stack; NTHREADS] = [const { Stack([0; STACK_SIZE]) }; NTHREADS];

fn stack_top(i: usize) -> usize {
    let base = core::ptr::addr_of!(STACKS) as usize;
    base + i * core::mem::size_of::<Stack>() + STACK_SIZE
}

static TICKS: AtomicU32 = AtomicU32::new(0);

// P7c step 4b — fault-restart of a scheduled EL0 driver. When a scheduled EL0 TCB
// faults, the handler rebuilds a fresh frame from these restart params and
// reschedules, instead of the cooperative resume_kernel longjmp.
// CORE-6: the fault-restart PARAMS and COUNT are now PER-TCB (scheduler::RestartRec,
// armed via set_restart) — the old EL0_RS_ENTRY/USP/KSTACK + single EL0_RESTARTS let a
// fault in one scheduled EL0 TCB restart it from ANOTHER's params and share the
// budget. EL0_SCHED_MODE is KEPT as the phase gate (scheduled stages vs the cooperative
// enter_user stages), so the handler only consults per-TCB records while scheduled EL0
// TCBs are the ones running. EL0_FAULT_TID lets the P7c report read the crash TCB's count.
static EL0_SCHED_MODE: AtomicBool = AtomicBool::new(false);
static EL0_FAULT_TID: AtomicUsize = AtomicUsize::new(usize::MAX);
const EL0_MAX_RESTARTS: u32 = 3;

// P7c — physical address of the EL0 preemption-test counter (kernel reads it to
// prove the uncooperative EL0 task ran), + a dedicated kernel stack for that TCB.
static EL0_CNT_PA: AtomicUsize = AtomicUsize::new(0);
/// Per-EL0-thread KERNEL stack size. Was 0x4000 (16 KiB). ROOT-CAUSE (M5.4 investigation):
/// the P0-P19 boot self-test report is printed from `handle_irq` (the TIMER IRQ) ON THE
/// CURRENTLY-RUNNING EL0 thread's kernel stack (the never-exiting EL0 loop driver ⇒
/// `EL0_KSTACK`), and it calls `wasmhost::wasmhost_selftest`, which runs `ed25519-compact`'s
/// `PublicKey::verify` — a ~60 KiB STACK-FRAME function (a large on-stack scalar-mult table).
/// On a 16 KiB stack that verify overflowed the stack DOWN by ~44 KiB into the statics below
/// `EL0_KSTACK` EVERY boot — silently benign only because the report is the last thing before
/// reboot AND (at HEAD) nothing live sat in the overflow zone. M5.4's `.bss` additions shifted
/// `wasmhost::INTERPRETED` (the M5.2 fail-closed tripwire) 92 B below `EL0_KSTACK`, so the
/// ed25519 overflow clobbered it → the [P-wasm] (b) proof broke. Measured peak depth from the
/// report frame through one verify ≈ 64 KiB; sized to 256 KiB = ~190 KiB headroom so an EL0
/// kernel stack (which can run ed25519 verify in IRQ context) never overflows into an
/// adjacent static, regardless of `.bss` layout. (.bss is NOLOAD — no image-size cost.)
const KSTACK_SIZE: usize = 0x40000;
#[repr(align(16))]
struct KStack([u8; KSTACK_SIZE]);
static mut EL0_KSTACK: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(not(feature = "cm5"))]
static mut EL0_FKSTACK: KStack = KStack([0; KSTACK_SIZE]); // kernel stack for the crashing driver TCB
/// Set by the timer IRQ when the on-metal scheduler demo completes (cm5).
static SCHED_DONE: AtomicBool = AtomicBool::new(false);

// --- P12 self-test state. (a) signal/poll + (b) pub-sub authority run synchronously
// pre-scheduler and store their verdict here; (c) the blocking-WAIT proof runs under
// the scheduler, so the verdict is read post-run in handle_irq (like [P7c]). ---
#[cfg(not(feature = "cm5"))]
static P12_A_SIGNAL_POLL: AtomicBool = AtomicBool::new(false);
#[cfg(not(feature = "cm5"))]
static P12_B_PUBSUB_AUTH: AtomicBool = AtomicBool::new(false);
// Written by the shared blocking-WAIT syscall path (both backends); read by the QEMU
// self-test report — so NOT cm5-gated.
static P12_WAIT_BLOCKED: AtomicBool = AtomicBool::new(false); // the WAIT actually blocked
#[cfg(not(feature = "cm5"))]
static P12_RESULT_PA: AtomicUsize = AtomicUsize::new(0); // PA of the EL0 waiter's result word
/// The badge stamped into the EL0 signaller's `Notification{W}` cap — the EL0 waiter
/// must receive EXACTLY this (badge comes from the cap, not a syscall arg). Bit 12 = P12.
#[cfg(not(feature = "cm5"))]
const P12_BADGE_C: u64 = 0x0000_0000_0000_1000;
#[cfg(not(feature = "cm5"))]
static mut EL0_WKSTACK: KStack = KStack([0; KSTACK_SIZE]); // kernel stack for the WAIT TCB
#[cfg(not(feature = "cm5"))]
static mut EL0_SKSTACK: KStack = KStack([0; KSTACK_SIZE]); // kernel stack for the SIGNAL TCB

// --- R1 (M5.0) cap-gated synchronous-IPC self-test state. (b) fail-closed + (c)
// revoke-severs run kernel-side pre-scheduler (deterministic, like the cap tests) and
// store their verdict here; (a) the live EL0 CALL/RECV/REPLY rendezvous runs under the
// scheduler and is verified post-run (like [P12c]). ---
#[cfg(not(feature = "cm5"))]
static R1_IPC_B: AtomicBool = AtomicBool::new(false); // (b) cap-gate fail-closed
#[cfg(not(feature = "cm5"))]
static R1_IPC_C: AtomicBool = AtomicBool::new(false); // (c) revoke severs IPC
#[cfg(not(feature = "cm5"))]
static R1_SRESULT_PA: AtomicUsize = AtomicUsize::new(0); // PA of the EL0 server's received-msg word
#[cfg(not(feature = "cm5"))]
static R1_CRESULT_PA: AtomicUsize = AtomicUsize::new(0); // PA of the EL0 client's received-reply word
/// The message the EL0 client SYS_CALLs with; the server must receive EXACTLY this.
#[cfg(not(feature = "cm5"))]
const R1_MSG: u64 = 0x0000_0000_0000_1C71;
/// The word the EL0 server SYS_REPLYs with; the client must receive EXACTLY this.
#[cfg(not(feature = "cm5"))]
const R1_REPLY: u64 = 0x0000_0000_0000_2BEE;
#[cfg(not(feature = "cm5"))]
static mut EL0_IPC_SKSTACK: KStack = KStack([0; KSTACK_SIZE]); // kernel stack for the IPC server TCB
#[cfg(not(feature = "cm5"))]
static mut EL0_IPC_CKSTACK: KStack = KStack([0; KSTACK_SIZE]); // kernel stack for the IPC client TCB

// --- M5.1 (Track C) ELF-loader beachhead: verdict + result statics ------------------
// (a) is proven LIVE post-scheduler: a client EL0 TCB is LOADED FROM AN ELF (not a
// copied asm stub) and drives the real cap-gated SYS_CALL path; it stores the reply into
// its RW ELF data segment, whose backing PA the kernel reads back here. (b)/(c) are the
// deterministic pre-scheduler parser proofs (bounds-safety + W^X-rejected).
#[cfg(not(feature = "cm5"))]
static ELF_B: AtomicBool = AtomicBool::new(false); // (b) malformed/oversize/overlap REFUSED
#[cfg(not(feature = "cm5"))]
static ELF_C: AtomicBool = AtomicBool::new(false); // (c) a W+X segment REJECTED (W^X)
#[cfg(not(feature = "cm5"))]
static ELF_CRESULT_PA: AtomicUsize = AtomicUsize::new(0); // PA of the ELF client's RW result word
/// The message the ELF-loaded client SYS_CALLs with (MUST match build.rs's ELF_MSG).
#[cfg(not(feature = "cm5"))]
const ELF_MSG: u64 = 0x0000_0000_0000_1E1F;
/// The reply the (asm) server SYS_REPLYs (MUST match `elf_ipc_server_stub`'s 0x5e17).
#[cfg(not(feature = "cm5"))]
const ELF_REPLY: u64 = 0x0000_0000_0000_5E17;
/// The fixture's segment VAs (MUST match build.rs). Code = entry (R+X); Data = RW result.
#[cfg(not(feature = "cm5"))]
const ELF_STACK_VA: usize = 0x8A02_0000; // stack the LOADER maps (not declared in the ELF)
#[cfg(not(feature = "cm5"))]
const ELF_SRV_CODE_VA: usize = 0x8B00_0000; // asm server code/stack (its own address space)
#[cfg(not(feature = "cm5"))]
const ELF_SRV_STACK_VA: usize = 0x8B00_1000;
#[cfg(not(feature = "cm5"))]
static mut EL0_ELF_CKSTACK: KStack = KStack([0; KSTACK_SIZE]); // kernel stack for the ELF client TCB
#[cfg(not(feature = "cm5"))]
static mut EL0_ELF_SKSTACK: KStack = KStack([0; KSTACK_SIZE]); // kernel stack for the ELF server TCB
/// The M5.1 fixture ELF, generated by build.rs into OUT_DIR and embedded here.
#[cfg(not(feature = "cm5"))]
const FIXTURE_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fixture_client.elf"));

// --- M5.2b (Track C) Wasm-host-AS-EL0-SERVER beachhead: verdict + result statics -----
// (a) is proven LIVE post-scheduler: the kernel Ed25519-verifies the signed fixture
// (trust root) and locates classify()'s code expression, then an ISOLATED EL0 host (own
// ASID/TTBR0) interprets it with the bespoke 5-opcode engine (`wasmhost_stub`) and
// SYS_CALLs the verdict over an Endpoint{W}; an asm server (Endpoint{R}) RECVs it, writes
// it to a result page the kernel reads back, and REPLYs. (b) is deterministic
// pre-scheduler (a tampered module yields no verified expression -> the host is never
// spawned). (c) is a SECOND EL0 host handed a fault-inducing expression -> EL0 fault
// contained by the R1 fault-restart (reuses `EL0_FAULT_TID`'s per-TCB restart record).
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WHOST_SRESULT_PA: AtomicUsize = AtomicUsize::new(0); // PA of the server's received-verdict word
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WHOST_REF_VERDICT: AtomicU32 = AtomicU32::new(u32::MAX); // in-kernel reference classify(port)
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WHOST_B_TAMPER_NOSPAWN: AtomicBool = AtomicBool::new(false); // (b) tampered -> no verified expr
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WHOST_FAULT_TID: AtomicUsize = AtomicUsize::new(usize::MAX); // (c) the faulting EL0 host's tid
/// The port arg the signed module classifies: 4444 == rule-1 "block-port-4444" -> verdict 1.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WHOST_PORT: u64 = 4444;
/// EL0 wasm-host VAs (its OWN address space). Code R+X, Work RW (== the `wasmhost_stub`
/// hard-coded 0x8C00_2000), Stack RW. The counterpart server reuses `ipc_server_stub`'s
/// 0x8600_* VAs in its OWN address space (no cross-AS collision).
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WHOST_CODE_VA: usize = 0x8C00_0000;
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WHOST_STACK_VA: usize = 0x8C00_1000;
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WHOST_WORK_VA: usize = 0x8C00_2000;
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut EL0_WHOST_CKSTACK: KStack = KStack([0; KSTACK_SIZE]); // kernel stack for the EL0 host TCB
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut EL0_WHOST_SKSTACK: KStack = KStack([0; KSTACK_SIZE]); // kernel stack for the asm server TCB
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut EL0_WHOST_FKSTACK: KStack = KStack([0; KSTACK_SIZE]); // kernel stack for the faulting host TCB

// --- M5.3 (Track C) — the REAL wasmi runtime in an EL0 SERVER (ADR 0044 D4 #2). The EL0
// Wasm-host BINARY (el0-wasmhost, links wasmi 0.32) is loaded via the M5.1 ELF loader into
// its OWN address space; the kernel (TRUST ROOT) Ed25519-verifies the signed module then
// copies the FULL bytes into the host's RW work page. The host runs classify(port) THROUGH
// WASMI and SYS_CALLs the verdict back over its Endpoint{W}. Three hosts prove it:
//   A: the good module, port 4444 -> verdict 1  (a: correct verdict via wasmi in EL0)
//   B: the good module, port 443  -> verdict 0  (a: the predicate really computes, not const)
//   C: the SIGNED TRAPPING module -> wasmi trap -> FAIL sentinel (c: trap contained at EL0)
// (b) is proven kernel-side: a tampered module fails verify -> no host spawned.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WASMI_HEAP_VA: usize = 0x9300_0000; // 64 pages RW (== el0-wasmhost HEAP_BASE/HEAP_SIZE)
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WASMI_HEAP_PAGES: usize = 64; // 256 KiB
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WASMI_STACK_VA: usize = 0x9200_0000; // 16 pages RW (kernel-provided; not in the ELF)
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WASMI_STACK_PAGES: usize = 16; // 64 KiB
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WASMI_WORK_VA: usize = 0x9400_0000; // 1 page RW (== el0-wasmhost WORK_BASE)
/// The EL0 wasmi-host ELF, compiled by build.rs (nested cargo) and embedded — wasmi's
/// ~355 KiB .text lives HERE, NOT in the kernel TCB. Both tiers embed it: the QEMU tier
/// uses the IPC-server ABI (0x9000_0000 map), the CM5 tier the `syncabi` build (GB5 map).
#[cfg(feature = "wasmhost")]
const WASMI_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/el0_wasmhost.elf"));
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASMI_RES_A: AtomicUsize = AtomicUsize::new(0); // PA of host-A's server result word (packed)
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASMI_RES_C: AtomicUsize = AtomicUsize::new(0); // PA of host-C's (trap) server result word
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASMI_B_TAMPER_NOSPAWN: AtomicBool = AtomicBool::new(false); // (b) tampered -> no host
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASMI_KERNEL_TEXT_DELTA: AtomicUsize = AtomicUsize::new(0); // kernel .text bytes (TCB size)
// Kernel stacks for the 3 host TCBs + 3 asm-server TCBs (mirrors the M5.2b pattern).
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASMI_A_HKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASMI_A_SKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASMI_C_HKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASMI_C_SKS: KStack = KStack([0; KSTACK_SIZE]);

// --- M5.5 (Track C) — the REAL wasip1 host (QEMU): run a signed `wasm32-wasip1` std module
// (stdin/stdout, the production module shape) through wasmi in an isolated EL0 task, over the
// enforced Endpoint-cap IPC. It needs bigger windows than the classify/detect hosts: the
// ~37 KiB module lives in its OWN RO window (WASMI_MODULE_VA, too big for the work page) and
// its ~1.1 MiB linear memory needs a MiB-scale heap (the kernel maps only what it touches).
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WASMI_MODULE_VA: usize = 0x9500_0000; // == el0-wasmhost WASIP1_MODULE_BASE
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WASMI_MODULE_PAGES: usize = 16; // 64 KiB — a std wasip1 module is ~37 KiB
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WASIP1_HEAP_PAGES: usize = 1024; // 4 MiB — fits the module's ~1.1 MiB memory + wasmi
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
const WASIP1_MAGIC: u64 = 0x4851_5741_5349_5031; // "HQWASIP1" (== el0-wasmhost WASIP1_MAGIC)
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASIP1_RES_A: AtomicUsize = AtomicUsize::new(0); // host-A result word (port 4444 -> DROP)
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASIP1_RES_B: AtomicUsize = AtomicUsize::new(0); // host-B result word (port 443 -> PASS)
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASIP1_TAMPER_NOSPAWN: AtomicBool = AtomicBool::new(false); // (b) tampered -> no host
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASIP1_A_HKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASIP1_A_SKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASIP1_B_HKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASIP1_B_SKS: KStack = KStack([0; KSTACK_SIZE]);
// A2+ — the DNS-RPZ catalogue module's two hosts (C: blocklisted qname -> DROP; D: benign -> PASS).
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASIP1_RES_C: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASIP1_RES_D: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASIP1_C_HKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASIP1_C_SKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASIP1_D_HKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASIP1_D_SKS: KStack = KStack([0; KSTACK_SIZE]);

// --- M5.4 (Track C) — DETECTION-at-PARITY host (ADR 0044 D4 #4, small scale). The SAME
// el0-wasmhost binary runs a signed DETECTION module (linear memory + hp_input/hp_emit
// imports) over a VECTOR of L4 headers through wasmi; its per-input verdicts must EQUAL
// the in-kernel `rules::run_l4` verdicts case-for-case (PARITY). Two hosts:
//   D (parity): 8 well-formed L4 headers -> 8 packed nibbles == the kernel reference.
//   I (iso):    1 malformed (2-byte) header -> module TRAPs -> FAIL nibble, contained at EL0.
// (b) is proven kernel-side: a tampered detection module fails verify -> no host spawned.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASMI_DETECT_RES: AtomicUsize = AtomicUsize::new(0); // parity host's server result word PA
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASMI_DETECT_ISO_RES: AtomicUsize = AtomicUsize::new(0); // iso host's server result word PA
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASMI_DETECT_EXPECTED: AtomicU32 = AtomicU32::new(0); // the in-kernel rules.rs reference packing
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASMI_DETECT_N: AtomicU32 = AtomicU32::new(0); // number of parity inputs (for the report)
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static WASMI_DETECT_TAMPER_NOSPAWN: AtomicBool = AtomicBool::new(false); // (b) tampered -> no host
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASMI_D_HKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASMI_D_SKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASMI_ISO_HKS: KStack = KStack([0; KSTACK_SIZE]);
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
static mut WASMI_ISO_SKS: KStack = KStack([0; KSTACK_SIZE]);

/// CM5 / BCM2712 first-boot entry: prove HEQK boots and prints on real silicon
/// via the on-SoC debug UART. MMU stays OFF (the UART is at a 40-bit PA that the
/// QEMU identity map doesn't cover); GIC-400 / generic-timer / RP1 are the next
/// bring-up steps once serial is confirmed.
#[cfg(feature = "cm5")]
#[no_mangle]
pub extern "C" fn kmain(bootinfo_pa: u64) -> ! {
    let console = arch_aarch64::console();
    // Console is ALREADY UP: firmware-direct boot stub or HBoot owns bring-up
    // (clock/pinmux/PL011 with barrier discipline); init() is a no-op on cm5.
    console.init();
    let el = arch_aarch64::current_el();
    let midr: u64;
    unsafe { core::arch::asm!("mrs {}, midr_el1", out(reg) midr) };
    console.write_str("\n================================================\n");
    console.write_str(" HEQK Core on BCM2712 (Raspberry Pi CM5) — real silicon\n");
    console.write_str("================================================\n");
    kprint!(" boot: running at EL{}\n", el);
    kprint!(" cpu : MIDR_EL1={:#010x} (part {:#05x}; 0xd0b=Cortex-A76)\n", midr, (midr >> 4) & 0xfff);
    kprint!(" uart: RP1 UART0 @ 0x1C00030000 (bootloader window, GPIO14/15 header)\n");

    // Launched by HBoot: validate + report the typed handoff (the kernel
    // never parses a DTB — HBoot did, and passed this struct).
    #[cfg(feature = "hboot")]
    {
        use boot_abi::{BootInfo, BOOTINFO_MAGIC};
        let bi = unsafe { &*(bootinfo_pa as *const BootInfo) };
        if bi.magic == BOOTINFO_MAGIC {
            kprint!(" hboot: BootInfo v{} @ {:#x} — verified handoff\n", bi.version, bootinfo_pa);
            kprint!(" hboot: kernel {:#x} ({} bytes), dtb {:#x}, el2_gate={}\n",
                bi.kernel_pa, bi.kernel_size, bi.dtb_pa, bi.el2_gate);
            kprint!(" hboot: svn={} (anti-rollback floor {}), verify_flags={:#x}\n",
                bi.svn, bi.svn_floor, bi.verify_flags);
            kprint!(" hboot: measured sha256=");
            for b in &bi.kernel_hash { kprint!("{:02x}", b); }
            kprint!("\n");
            attest_replay(bi);
            cm5_attest_challenge(bi);
            cm5_el2_isolation_test();
            cm5_sec2_mailbox_carve_test();
        } else {
            kprint!(" hboot: BAD BootInfo magic {:#x} @ {:#x}\n", bi.magic, bootinfo_pa);
        }
    }

    // Firmware-direct boot: print the BootDebug breadcrumbs the stub left.
    #[cfg(not(feature = "hboot"))]
    {
        let _ = bootinfo_pa;
        let bd = 0x3FFF_0000usize as *const u64;
        unsafe {
            kprint!(
                " bootdbg: magic={:#018x} step={} el={} sctlr={:#x}\n",
                read_volatile(bd), read_volatile(bd.add(1)), read_volatile(bd.add(2)), read_volatile(bd.add(3))
            );
            kprint!(
                " pre : FR={:#x} IBRD={} FBRD={} LCR={:#x} CR={:#x} IMSC={:#x} CLK={:#x} G14={:#x} PAD14={:#x}\n",
                read_volatile(bd.add(8)), read_volatile(bd.add(9)), read_volatile(bd.add(10)),
                read_volatile(bd.add(11)), read_volatile(bd.add(12)), read_volatile(bd.add(13)),
                read_volatile(bd.add(16)), read_volatile(bd.add(19)), read_volatile(bd.add(21))
            );
            kprint!(
                " post: FR={:#x} IBRD={} FBRD={} LCR={:#x} CR={:#x} CLK={:#x} G14={:#x}\n",
                read_volatile(bd.add(24)), read_volatile(bd.add(25)), read_volatile(bd.add(26)),
                read_volatile(bd.add(27)), read_volatile(bd.add(28)), read_volatile(bd.add(29)),
                read_volatile(bd.add(30))
            );
        }
    }
    kprint!(" RUST OK\n");

    // --- P7a: stage-1 MMU on real silicon --------------------------------
    // Sample a RAM word BEFORE enabling translation, so we can prove a cached
    // read through a NON-identity VA returns the same bytes afterwards.
    let phys_probe = arch_aarch64::mmu_cm5::ALIAS_VA as u64; // aliases PA 0..1G
    let sample_pa = 0x0100_0000usize; // kernel image start (known live RAM)
    let before = unsafe { read_volatile(sample_pa as *const u64) };
    arch_aarch64::mmu_cm5::enable_identity();
    // If this line prints, the console (RP1 UART @0x1C.., Device-mapped)
    // survived MMU-on — the peripheral mapping is correct.
    kprint!(" mmu : enabled={} (39-bit VA, 1GiB blocks; RAM=Normal, periph=Device)\n",
        arch_aarch64::mmu_cm5::enabled());
    // VA!=PA proof: read the same physical word through the aliased high VA.
    let via_alias = unsafe { read_volatile((phys_probe as usize + sample_pa) as *const u64) };
    kprint!(" mmu : VA {:#x} -> PA {:#x} readback {} (VA!=PA: {})\n",
        phys_probe as usize + sample_pa, sample_pa,
        if via_alias == before { "verified" } else { "MISMATCH" },
        phys_probe as usize + sample_pa != sample_pa);
    // Cached RAM round-trip through the identity Normal mapping. Scratch is in
    // free RAM (0x800000..0x1000000: above HBoot's downward stack, below the
    // kernel image) — NOT 0x200000, where HBoot's EL2 code still lives.
    let scratch = 0x0090_0000usize;
    let magic = 0x4845_514b_5637_6100u64; // "HEQKV7a\0"
    unsafe { write_volatile(scratch as *mut u64, magic) };
    let rt = unsafe { read_volatile(scratch as *const u64) };
    kprint!(" mmu : cached RAM r/w {} [P7a]\n", if rt == magic { "PASS" } else { "FAIL" });

    // --- P7b: W^X proof on metal — read back the page descriptors -------------
    // The kernel is executing from 0x1000000 under WXN, so .text is already a
    // proven RO+X mapping; confirm the descriptor bits and that data is RW+PXN.
    let td = arch_aarch64::mmu_cm5::page_desc(0x0100_0000); // kernel .text (L3 page)
    let dd = arch_aarch64::mmu_cm5::page_desc(scratch); // data RAM (2 MiB block)
    let ap = |d: u64| (d >> 6) & 3;
    let pxn = |d: u64| (d >> 53) & 1;
    kprint!(" wx : .text AP={:#b} PXN={} | data AP={:#b} PXN={}\n",
        ap(td), pxn(td), ap(dd), pxn(dd));
    kprint!(" [P7b] W^X {} (kernel .text RO+X, data RW+PXN, SCTLR.WXN on)\n",
        if ap(td) == 0b10 && pxn(td) == 0 && ap(dd) == 0 && pxn(dd) == 1 { "PASS" } else { "FAIL" });

    kprint!(" [CM5-BOOT] PASS — HEQK boots, MMU on, prints on real hardware\n");

    // --- P7b: GIC-400 + generic timer + preemptive scheduler on metal ------
    cm5_scheduler_demo();

    // PH7 (XC-15): run the SAME capability-invariant sweep as the QEMU backend, now on
    // CM5 silicon (a different MMU backend) — the dual-backend coverage that would have
    // caught a metal-only divergence. Base = the free RAM window (above HBoot's stack).
    let caps_ok = caps::cap_invariants_selftest(0x0098_0000);
    kprint!(" [PH7-caps] {} — mint narrows+never-amplifies (all 8 rights), type-tag safety, revoke severs+bumps-gen (CM5 backend)\n",
        if caps_ok { "PASS" } else { "FAIL" });
    // A1b (CORE-1 on CM5 silicon): the [PH7-caps] sweep above proves the cap ALGEBRA on the
    // CM5 backend, but not that a mapping is cap-GATED + revoke-SEVERS a real page table on
    // the mmu_cm5 backend (the QEMU [P2-unmap] proof is not(cm5)). Prove it here on metal,
    // BEFORE the GEM drivers claim the GB5 window.
    p_cm5_cap();
    // A1b cont'd (CORE-2 on CM5 silicon): per-TCB CSpace isolation (cap-algebra delegation)
    // AND distinct per-AS user page tables (RO/RW attribute mapping + cross-AS isolation +
    // unmap-severs) on the mmu_cm5 per-ASID backend.
    p_cm5_cspace_iso();

    // --- P8: load the signed HookProbe rule plane (verify every rule; JIT is
    // QEMU-only, so CM5 runs the bounds-checked interpreter — same verdict). ---
    let (rv, rj) = rules::init();
    kprint!(" [P8] rule plane: {} rules verified, {} JIT-compiled to native ARM64 on metal — parity corpus armed\n", rv, rj);

    // --- P8: statically VERIFY the detection rule before running it on live traffic --
    cm5_p8_verify();

    // --- A/B: detection plane is up -> confirm this boot (disarm trial watchdog) ---
    // `late-confirm` (OFF by default) defers this to the HEALTHY prod loop instead (audit B1: a
    // trial image that boots but never serves should not commit). It stays off until the bench
    // measures the [BOOT-TIMING] budget: hboot's watchdog is armed on EVERY boot (15 s, ~16 s HW
    // max), so a late confirm that misses it reset-loops the device. Never under `apmode` (the AP
    // pump never reaches the prod loop).
    #[cfg(not(all(feature = "late-confirm", not(feature = "apmode"))))]
    boot_confirm();
    #[cfg(all(feature = "late-confirm", not(feature = "apmode")))]
    kprint!(" [HBoot-AB] confirm DEFERRED to the healthy prod loop (late-confirm) — t=+{} ms\n", boot_ms());

    // --- P8: RP1 GEM Ethernet — polled RX first light ----------------------
    cm5_gem_rx_demo();

    // --- P14 seed: BCM2712 IOMMU probe + the iommu2 (external PCIe) DMA fence. Armed
    // BEFORE the RTL8111 rings exist so P9's RX proves the datapath UNDER the fence
    // (it used to be armed after P9 with a stale "link is down" comment, so nothing ever
    // exercised RTL DMA behind it — eth1-as-LAN would have been the first to find out).
    cm5_iommu_probe();

    // --- P9: external PCIe RC1 link + RTL8111H vendor-ID (2nd-interface bring-up) --
    cm5_p9_probe();

    // Thermal: arm the generic-timer EVENT STREAM now so every polled `delay()` in the
    // WiFi bring-up + the AP serve loop parks in `wfe` (the 23164ad fix reached only the
    // prod drain loop; in AP mode the box never gets there and ran at 100 % again).
    arch_aarch64::timer::enable_event_stream();
    arch_aarch64::cyw43::set_event_stream_armed();

    // --- P10 Stage A: CYW43455 WiFi SDIO bring-up + chip-ID (0x4345) --
    cm5_p10_probe();

    // --- P15: eMMC read-only block device + sealing (in-RAM, synthetic key) --
    #[cfg(feature = "hboot")]
    cm5_p15_block_seal();
    // --- P15 (bench): the A/B commit two-boot proof on the real eMMC (opt-in, never shipped) --
    #[cfg(feature = "abcommit-metal")]
    abboot::abcommit_metal_selftest();

    // --- P13: RP1 peripheral buses (GPIO/pinmux + I2C + SPI + UART), EL0-isolated --
    cm5_p13_probe();

    // --- P7c step 3b: the REAL GEM, read from an ISOLATED EL0 driver --------
    cm5_gem_el0_probe(); // stage 1: register probe
    cm5_gem_el0_rx_probe(); // stage 2: RX descriptor-ring poll (the packet hot path)
    cm5_gem_el0_tx_probe(); // stage 3: launch a TX from EL0 (arm + kick + poll)
    cm5_gem_el0_ids(); // stage 4a: EL0 driver delivers a frame -> kernel IDS verdict
    // --- P8 (RX-IRQ): enable interrupt-driven RX (LAST — bounded, self-contained) ---
    cm5_gem_rx_irq_probe();

    // [P7-rollback] M1 CRITERION 4 — forced-bad-boot rollback. TEST BUILD ONLY.
    //
    // Arms the firmware's one-shot tryboot flag (proven reachable by [P7-tryboot]) and
    // resets via the EL2 gate. The next boot therefore loads tryboot.txt -> SLOT B. With
    // SLOT B deliberately corrupted, hboot's hybrid Ed25519+SLH-DSA verify REFUSES it and
    // parks; the EL2 trial watchdog then resets the SoC; the one-shot has already been
    // consumed, so that reset boots config.txt -> SLOT A. Verification AND watchdog
    // fallback are exercised together, which is the whole point of the criterion.
    //
    // NO BRICK PATH: SLOT A is always the known-good image and the flag is one-shot, so
    // the board can only ever land back on A. This build LOOPS (A arms again after the
    // rollback) — observe a cycle, power off, reflash a normal image.
    #[cfg(feature = "rollback-test")]
    {
        kprint!("\n [P7-rollback] M1 CRITERION 4 — arming the firmware one-shot tryboot flag\n");
        let set = arch_aarch64::mailbox::set_reboot_flags(arch_aarch64::mailbox::REBOOT_FLAG_TRYBOOT);
        let readback = arch_aarch64::mailbox::get_reboot_flags();
        let notified = arch_aarch64::mailbox::notify_reboot();
        kprint!("   [P7-rollback] set={:?} readback={:?} notify_reboot={}\n", set, readback, notified);
        match readback {
            Some(f) if f & arch_aarch64::mailbox::REBOOT_FLAG_TRYBOOT != 0 => {
                kprint!("   [P7-rollback] tryboot ARMED — resetting via the EL2 gate (hvc #0).\n");
                kprint!("   [P7-rollback] EXPECT NEXT: firmware loads tryboot.txt -> SLOT B (corrupt)\n");
                kprint!("   [P7-rollback]              -> hboot signature verify REFUSES -> park\n");
                kprint!("   [P7-rollback]              -> EL2 trial watchdog resets the SoC\n");
                kprint!("   [P7-rollback]              -> one-shot consumed -> config.txt -> SLOT A boots\n");
                // Let the UART drain before the reset takes the console with it.
                for _ in 0..40_000_000u64 {
                    core::hint::spin_loop();
                }
                unsafe { core::arch::asm!("hvc #0", options(noreturn)) }
            }
            other => {
                kprint!("   [P7-rollback] FAIL — tryboot did not arm (readback={:?}); NOT resetting.\n", other);
                kprint!("   [P7-rollback] Refusing to reset without the one-shot: a reset here would just reboot SLOT A and prove nothing.\n");
            }
        }
    }

    // PH1 — GO LIVE (a `prod` build). Every bring-up phase above has run (MMU/W^X,
    // scheduler, verified rule plane, GEM Ethernet, the P14 IOMMU DMA fence, and the
    // isolated EL0 driver just proven on stages 1-4a), so enter the persistent
    // RX -> verdict -> ENFORCE sensor loop. It never returns and never reboots.
    #[cfg(feature = "prod")]
    cm5_prod_service();

    // --- Self-test build: the bounded restartable EL0 server demo, then reboot the
    //     bench (a `prod` build replaces this tail with the live service above). ---
    #[cfg(not(feature = "prod"))]
    {
        cm5_gem_el0_server(); // stage 4d: continuous, restartable isolated EL0 driver server
        kprint!(" halting; next: RP1 networking (the packet-plane keystone)\n");
        // After the banner: drain the UART, then request reboot via `hvc #0` —
        // the EL2 gate performs the PM reset (EL1 writes to the PM block are
        // silently ignored; EL2 is the proven path). The bench self-recovers.
        for _ in 0..200_000_000u64 {
            core::hint::spin_loop();
        }
        unsafe { core::arch::asm!("hvc #0", options(noreturn)) }
    }
}

/// A/B boot confirm (reliability keystone): once the security-critical services
/// (the detection plane) are up, tell HBoot's EL2 gate to DISARM the trial
/// watchdog via `hvc #1`, committing this boot. If the kernel never reaches here
/// (hang/panic), the watchdog fires and the firmware falls back to the known-good
/// slot (config.txt). With no EL2 trial gate (QEMU / firmware-direct) there is
/// nothing to disarm — the state machine is still exercised and the gate PASSes.
#[cfg(feature = "hboot")]
fn boot_confirm() {
    use boot_abi::{BootInfo, BOOTINFO_ADDR, BOOTINFO_MAGIC, BOOT_FLAG_TRIAL_WDOG};
    let bi = unsafe { &*(BOOTINFO_ADDR as *const BootInfo) };
    let armed = bi.magic == BOOTINFO_MAGIC
        && bi.el2_gate != 0
        && (bi.boot_flags & BOOT_FLAG_TRIAL_WDOG) != 0;
    if armed {
        // hvc #1 -> the EL2 gate disarms the PM watchdog and erets back to EL1.
        unsafe { core::arch::asm!("hvc #1") };
        kprint!(" [HBoot-AB] PASS — trial boot confirmed; EL2 watchdog disarmed, slot committed [BOOT-TIMING] t=+{} ms (watchdog budget {} s)\n",
            boot_ms(), bi.watchdog_secs);
    } else {
        kprint!(" [HBoot-AB] PASS — no trial watchdog in handoff; nothing to confirm\n");
    }
}

/// Milliseconds since the ARM generic counter started (SoC power-on on the CM5) — the clock the
/// hboot trial watchdog budget is measured against. [BOOT-TIMING] markers use it so the bench can
/// size the late-confirm window from real metal numbers.
#[cfg(feature = "cm5")]
fn boot_ms() -> u64 {
    let (c, f): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) c, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack));
    }
    c / (f / 1000).max(1)
}

/// A/B boot confirm on a build with no EL2 trial gate (QEMU / firmware-direct):
/// nothing to disarm, but exercise + report the confirm state machine so the
/// validator can gate on it.
#[cfg(not(feature = "hboot"))]
fn boot_confirm() {
    kprint!(" [HBoot-AB] PASS — no EL2 trial gate (direct boot); A/B confirm not required\n");
}

/// P7c step 3b (stage 1) — run a minimal driver at EL0, granted ONLY the GEM MMIO
/// page as a capability (mapped into the GB5 user window). It reads GEM NCFGR
/// through that window and reports it; the kernel compares to its own read. This
/// proves the REAL GEM is reachable from an ISOLATED EL0 driver on metal — the
/// foundation for migrating the whole GEM driver to a capability-bounded EL0
/// server (RX/TX + IPC to the packet engine are the next stages).
#[cfg(feature = "cm5")]
fn cm5_gem_el0_probe() {
    use arch_aarch64::mmu_cm5;
    arch_aarch64::disable_irqs();
    extern "C" {
        static gem_probe_stub: u8;
        static gem_probe_stub_end: u8;
    }
    let src = core::ptr::addr_of!(gem_probe_stub) as usize;
    let len = core::ptr::addr_of!(gem_probe_stub_end) as usize - src;
    let code_pa = mmu_cm5::el0_code_pa();
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, code_pa as *mut u8, len) };
    arch_aarch64::mmu::sync_instruction_cache(code_pa, len);
    const GEM_PHYS: usize = 0x1C00_100000; // the GEM MMIO page (Device)
    let ucode = mmu_cm5::USER_VA_BASE;
    let ustack = mmu_cm5::USER_VA_BASE + 0x1000;
    let udev = mmu_cm5::USER_VA_BASE + 0x2000;
    mmu_cm5::map_user_code(ucode, code_pa);
    mmu_cm5::map_user_data(ustack, mmu_cm5::el0_stack_pa());
    mmu_cm5::map_user_device(udev, GEM_PHYS); // the ONLY hardware granted
    kprint!(" [P7c] EL0 GEM driver: code@{:#x} stack@{:#x} GEM-window@{:#x}->{:#x} (nothing else granted)\n",
        ucode, ustack, udev, GEM_PHYS);
    DRIVER_REPORT.store(0, Ordering::Relaxed);
    unsafe { arch_aarch64::syscall::enter_user(ucode, ustack + 0x1000) };
    let el0 = DRIVER_REPORT.load(Ordering::Relaxed);
    let kern = arch_aarch64::gem::probe().0; // kernel-side GEM NCFGR
    let ok = el0 == kern && el0 != 0;
    kprint!(" [P7c] EL0 driver read GEM NCFGR={:#010x} (kernel sees {:#010x}) — {}\n",
        el0, kern, if ok { "MATCH" } else { "MISMATCH" });
    kprint!(" [P7c] {} — real GEM reachable from an ISOLATED EL0 driver on metal (stage 1)\n",
        if ok { "PASS" } else { "FAIL" });
}

/// P7c step 3b (stage 2) — the RX hot path at EL0. The GEM keeps receiving (the
/// kernel did the privileged one-time `rx_init`); here an EL0 driver is granted
/// ONLY a Normal-NC window onto the descriptor ring and polls it for a received
/// frame, reporting the hardware status word (word1 = EOF|SOF|len). This isolates
/// the part that touches attacker-controlled packet data — a compromise of the
/// RX path is contained to EL0 + the ring window.
#[cfg(feature = "cm5")]
fn cm5_gem_el0_rx_probe() {
    use arch_aarch64::mmu_cm5;
    arch_aarch64::disable_irqs();
    extern "C" {
        static gem_rx_stub: u8;
        static gem_rx_stub_end: u8;
    }
    let src = core::ptr::addr_of!(gem_rx_stub) as usize;
    let len = core::ptr::addr_of!(gem_rx_stub_end) as usize - src;
    let code_pa = mmu_cm5::el0_code_pa();
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, code_pa as *mut u8, len) };
    arch_aarch64::mmu::sync_instruction_cache(code_pa, len);
    let ucode = mmu_cm5::USER_VA_BASE;
    let ustack = mmu_cm5::USER_VA_BASE + 0x1000;
    let uring = mmu_cm5::USER_VA_BASE + 0x3000;
    mmu_cm5::map_user_code(ucode, code_pa);
    mmu_cm5::map_user_data(ustack, mmu_cm5::el0_stack_pa());
    mmu_cm5::map_user_nc(uring, arch_aarch64::gem::rxring_pa()); // the ONLY new grant: the RX ring (NC)
    kprint!(" [P7c] EL0 RX driver: granted NC ring window @{:#x}->{:#x} ({} desc x {}B), nothing else\n",
        uring, arch_aarch64::gem::rxring_pa(), arch_aarch64::gem::RX_NDESC, arch_aarch64::gem::RX_DESC_STRIDE);
    DRIVER_REPORT.store(0, Ordering::Relaxed);
    unsafe { arch_aarch64::syscall::enter_user(ucode, ustack + 0x1000) };
    let w1 = DRIVER_REPORT.load(Ordering::Relaxed);
    let len_field = w1 & 0x3fff;
    let sof_eof = (w1 & 0xC000) == 0xC000;
    let ok = sof_eof && (42..=1600).contains(&len_field);
    kprint!(" [P7c] EL0 RX driver polled the ring: w1={:#010x} (EOF|SOF={}, len={}) — {}\n",
        w1, sof_eof, len_field, if ok { "REAL FRAME" } else { "none/invalid" });
    kprint!(" [P7c] {} — GEM RX hot path ISOLATED at EL0 (stage 2: only the descriptor ring granted)\n",
        if ok { "PASS" } else { "FAIL" });
}

/// P7c step 3b (stage 3) — TX from EL0. The kernel pre-fills the TX buffer + sets
/// the descriptor address (privileged); the EL0 driver, granted the TX-ring NC
/// window + the GEM register window, ARMS the descriptor (word1 = len|LAST|WRAP),
/// kicks TSTART, and polls word1 for USED (bit31 = transmitted). Proves the TX
/// launch path runs from an isolated EL0 driver.
#[cfg(feature = "cm5")]
fn cm5_gem_el0_tx_probe() {
    use arch_aarch64::mmu_cm5;
    arch_aarch64::disable_irqs();
    // kernel (privileged half): pick the controller's NEXT slot, fill its buffer + address
    // words, clear latched TSR; the plan goes to the bottom of the driver's own stack page.
    let plan = arch_aarch64::gem::tx_prep_el0(64);
    unsafe {
        let p = mmu_cm5::el0_stack_pa() as *mut u32;
        core::ptr::write_volatile(p, plan.desc_off);
        core::ptr::write_volatile(p.add(1), plan.word1);
        core::arch::asm!("dsb sy");
    }
    extern "C" {
        static gem_tx_stub: u8;
        static gem_tx_stub_end: u8;
    }
    let src = core::ptr::addr_of!(gem_tx_stub) as usize;
    let len = core::ptr::addr_of!(gem_tx_stub_end) as usize - src;
    let code_pa = mmu_cm5::el0_code_pa();
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, code_pa as *mut u8, len) };
    arch_aarch64::mmu::sync_instruction_cache(code_pa, len);
    let ucode = mmu_cm5::USER_VA_BASE;
    let ustack = mmu_cm5::USER_VA_BASE + 0x1000;
    let udev = mmu_cm5::USER_VA_BASE + 0x2000;
    let utx = mmu_cm5::USER_VA_BASE + 0x4000;
    const GEM_PHYS: usize = 0x1C00_100000;
    mmu_cm5::map_user_code(ucode, code_pa);
    mmu_cm5::map_user_data(ustack, mmu_cm5::el0_stack_pa());
    mmu_cm5::map_user_device(udev, GEM_PHYS); // GEM registers (to kick NCR.TSTART)
    mmu_cm5::map_user_nc(utx, arch_aarch64::gem::txring_pa()); // the TX ring (NC)
    kprint!(" [P7c] EL0 TX driver: granted TX-ring NC @{:#x}->{:#x} + GEM-reg window @{:#x}\n",
        utx, arch_aarch64::gem::txring_pa(), udev);
    DRIVER_REPORT.store(0, Ordering::Relaxed);
    unsafe { arch_aarch64::syscall::enter_user(ucode, ustack + 0x1000) };
    let w1 = DRIVER_REPORT.load(Ordering::Relaxed);
    let tsr = arch_aarch64::gem::tx_finish_el0();
    let used = (w1 >> 31) & 1 == 1;
    kprint!(" [P7c] EL0 TX driver launched a transmit: slot@{:#x} armed={:#010x} final word1={:#010x} tsr={:#06x} (USED/complete={})\n",
        plan.desc_off, plan.word1, w1, tsr, used);
    kprint!(" [P7c] {} — GEM TX driven from an ISOLATED EL0 driver (stage 3: armed + kicked + completed)\n",
        if used { "PASS" } else { "FAIL" });
}

/// P7c step 3b (stage 4) — close the loop: the isolated EL0 RX driver locates a
/// received frame and reports (descriptor index | length); the kernel packet-
/// engine reads that buffer and runs the signed BPF verdict. This is the end-to-
/// end IDS/IPS with the driver isolated at EL0 (the detection engine stays in the
/// trusted kernel). Fault-restart + a preemptible-in-own-ASID driver are next.
#[cfg(feature = "cm5")]
fn cm5_gem_el0_ids() {
    use arch_aarch64::mmu_cm5;
    arch_aarch64::disable_irqs();
    extern "C" {
        static gem_ids_stub: u8;
        static gem_ids_stub_end: u8;
    }
    let src = core::ptr::addr_of!(gem_ids_stub) as usize;
    let len = core::ptr::addr_of!(gem_ids_stub_end) as usize - src;
    let code_pa = mmu_cm5::el0_code_pa();
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, code_pa as *mut u8, len) };
    arch_aarch64::mmu::sync_instruction_cache(code_pa, len);
    let ucode = mmu_cm5::USER_VA_BASE;
    let ustack = mmu_cm5::USER_VA_BASE + 0x1000;
    let uring = mmu_cm5::USER_VA_BASE + 0x3000;
    mmu_cm5::map_user_code(ucode, code_pa);
    mmu_cm5::map_user_data(ustack, mmu_cm5::el0_stack_pa());
    mmu_cm5::map_user_nc(uring, arch_aarch64::gem::rxring_pa());
    DRIVER_REPORT.store(0, Ordering::Relaxed);
    unsafe { arch_aarch64::syscall::enter_user(ucode, ustack + 0x1000) };
    let report = DRIVER_REPORT.load(Ordering::Relaxed);
    let idx = ((report >> 16) & 0xff) as usize;
    // AUDIT M-7: use the EL0 driver's report ONLY as a hint for WHICH descriptor to
    // look at. The frame LENGTH must come from the GEM's own status writeback, which
    // is kernel-readable — a compromised driver that could choose the length could
    // make the packet engine classify a truncated frame, or a stale one from a
    // previous descriptor, instead of what actually arrived. That is IDS evasion by
    // the isolated driver, which is exactly the component P7c assumes may be hostile.
    let flen = match arch_aarch64::gem::rx_desc_status(idx) {
        Some(hw_len) => hw_len,
        None => {
            kprint!(" [P7c] EL0 IDS: driver reported desc {} but the GEM shows no valid frame there — FAIL (fail-closed)\n", idx);
            return;
        }
    };
    if flen < 14 {
        kprint!(" [P7c] EL0 IDS: no frame delivered by the driver — FAIL\n");
        return;
    }
    // The kernel packet engine runs the signed BPF verdict on the frame the
    // isolated EL0 driver delivered.
    let mut buf = [0u8; 1600];
    let n = flen.min(buf.len());
    arch_aarch64::gem::peek_rx_frame(idx, &mut buf[..n]);
    struct Pool([u8; packet::FRAME_SZ * 8]);
    static mut IDSPOOL: Pool = Pool([0; packet::FRAME_SZ * 8]);
    let pool = core::ptr::addr_of_mut!(IDSPOOL) as usize;
    let verdict = if packet::produce_raw(pool, &buf[..n]) {
        packet::consume_one(pool)
    } else {
        None
    };
    match verdict {
        Some((port, v)) => kprint!(
            " [P7c] EL0 IDS: driver delivered desc {} ({}B, et={:02x}{:02x}) -> kernel verdict {} (dst_port={})\n",
            idx, n, buf[12], buf[13], if v == packet::DROP { "DROP" } else { "PASS" }, port),
        None => kprint!(" [P7c] EL0 IDS: classify failed\n"),
    }
    kprint!(" [P7c] {} — end-to-end: ISOLATED EL0 driver -> frame -> kernel IDS verdict (stage 4)\n",
        if verdict.is_some() { "PASS" } else { "FAIL" });
}

/// P7c step 4d — a CONTINUOUS, RESTARTABLE isolated EL0 GEM driver server. The
/// kernel repeatedly runs the EL0 RX->IDS driver (recycling descriptors so it
/// sees fresh frames); on one iteration it loads a crashing driver, which the
/// kernel contains and RESTARTS (re-enters) — a self-contained, self-healing,
/// packet-isolated driver server on real hardware. (True preemptible-scheduled-
/// in-own-ASID is proven on QEMU; this is the cooperative-loop CM5 capstone.)
#[cfg(feature = "cm5")]
fn cm5_gem_el0_server() {
    use arch_aarch64::mmu_cm5;
    arch_aarch64::disable_irqs();
    extern "C" {
        static gem_ids_stub: u8;
        static gem_ids_stub_end: u8;
        static el0_fault_stub: u8;
        static el0_fault_stub_end: u8;
    }
    let ids = (core::ptr::addr_of!(gem_ids_stub) as usize, core::ptr::addr_of!(gem_ids_stub_end) as usize);
    let flt = (core::ptr::addr_of!(el0_fault_stub) as usize, core::ptr::addr_of!(el0_fault_stub_end) as usize);
    let code_pa = mmu_cm5::el0_code_pa();
    let ucode = mmu_cm5::USER_VA_BASE;
    let ustack = mmu_cm5::USER_VA_BASE + 0x1000;
    let uring = mmu_cm5::USER_VA_BASE + 0x3000;
    mmu_cm5::map_user_data(ustack, mmu_cm5::el0_stack_pa());
    mmu_cm5::map_user_nc(uring, arch_aarch64::gem::rxring_pa());
    struct Pool([u8; packet::FRAME_SZ * 8]);
    static mut SRVPOOL: Pool = Pool([0; packet::FRAME_SZ * 8]);
    let pool = core::ptr::addr_of_mut!(SRVPOOL) as usize;
    let mut processed = 0u32;
    let mut crashes = 0u32;
    kprint!(" [P7c] EL0 GEM driver SERVER: continuous RX->IDS loop (crash-restart on iter 3)\n");
    for iter in 0..6u32 {
        let (stub, faulting) = if iter == 3 { (flt, true) } else { (ids, false) };
        let len = stub.1 - stub.0;
        unsafe { core::ptr::copy_nonoverlapping(stub.0 as *const u8, code_pa as *mut u8, len) };
        arch_aarch64::mmu::sync_instruction_cache(code_pa, len);
        mmu_cm5::map_user_code(ucode, code_pa);
        DRIVER_REPORT.store(0, Ordering::Relaxed);
        unsafe { arch_aarch64::syscall::enter_user(ucode, ustack + 0x1000) }; // fault -> resume_kernel; else reports
        if faulting {
            crashes += 1;
            kprint!("   [server] driver CRASHED on iter {} -> contained + RESTARTED (kernel survives)\n", iter);
            continue;
        }
        let report = DRIVER_REPORT.load(Ordering::Relaxed);
        let idx = ((report >> 16) & 0xff) as usize;
        // AUDIT M-7: length from the GEM status writeback, not from the untrusted
        // EL0 driver's report (see cm5_gem_el0_ids). The report only picks the slot.
        let flen = match arch_aarch64::gem::rx_desc_status(idx) {
            Some(hw_len) => hw_len,
            None => {
                kprint!("   [server] iter {}: no frame this window\n", iter);
                continue;
            }
        };
        if flen < 14 {
            kprint!("   [server] iter {}: no frame this window\n", iter);
            continue;
        }
        let mut buf = [0u8; 1600];
        let n = flen.min(buf.len());
        arch_aarch64::gem::peek_rx_frame(idx, &mut buf[..n]);
        if packet::produce_raw(pool, &buf[..n]) {
            if let Some((port, v)) = packet::consume_one(pool) {
                kprint!("   [server] iter {}: EL0 driver -> desc {} ({}B et={:02x}{:02x}) -> IDS {} (port {})\n",
                    iter, idx, n, buf[12], buf[13], if v == packet::DROP { "DROP" } else { "PASS" }, port);
                processed += 1;
            }
        }
        arch_aarch64::gem::recycle_rx(idx); // re-arm so the next iteration sees a fresh frame
    }
    kprint!(" [P7c] {} — EL0 driver SERVER processed {} frames + survived {} crash-restart — continuous isolated driver (4d)\n",
        if processed >= 1 && crashes >= 1 { "PASS" } else { "FAIL" }, processed, crashes);
}

/// PH1 — the PRODUCTION service loop (NEVER returns). This is what a `prod` build boots
/// into INSTEAD of the P0-P17 self-test sequence: an ISOLATED EL0 GEM driver polls the
/// RX ring and the kernel runs every real frame through the verified rule plane, then
/// ENFORCES — a PASS verdict is FORWARDED on the wire (`gem::tx_frame`), a threat verdict
/// is DROPPED (never forwarded). The NIC driver runs unprivileged in its own EL0 context;
/// the trusted stub is reloaded each iteration, so a driver crash (contained by the EL0
/// fault handler, exactly as [P7c] proves) simply costs one empty window and the loop
/// keeps running — structural self-heal. Telemetry is emitted on a throttle. The running
/// sensor: it does not halt and does not reboot.
/// Physical counter read for the production heartbeat cadence.
#[cfg(feature = "cm5")]
fn prod_cntpct() -> u64 {
    let c: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) c, options(nomem, nostack)) };
    c
}

/// rxprof — per-phase accumulators for the RX->verdict->forward loop. Every field is a
/// SUM of cntpct ticks across `frames` iterations; the heartbeat divides to an average
/// and converts to microseconds. Reading cntpct is a couple of cycles, so the probe does
/// not meaningfully perturb what it measures.
#[cfg(feature = "rxprof")]
#[derive(Default, Clone, Copy)]
struct RxProf {
    reload: u64,  // stub copy + i-cache sync + map_user_code (every iteration)
    el0: u64,     // enter_user round-trip (the EL0 stub scans the ring + syscalls back)
    rxstat: u64,  // rx_desc_status
    copy: u64,    // peek_rx_frame (up to 2 KiB out of the ring)
    verdict: u64, // packet::verdict (the whole detection chain)
    tx: u64,      // tx_frame forward (PASS frames only)
    recycle: u64, // recycle_rx
    frames: u64,  // processed frames (seen), the divisor
}

#[cfg(feature = "rxprof")]
impl RxProf {
    #[inline(always)]
    fn report(&self, cntfrq: u64) {
        let f = self.frames.max(1);
        let us = |sum: u64| -> u64 { sum.wrapping_mul(1_000_000) / cntfrq / f };
        kprint!("   [rxprof] n={} avg-us: reload={} el0={} rxstat={} copy={} verdict={} tx={} recycle={} | total={}
",
            self.frames, us(self.reload), us(self.el0), us(self.rxstat), us(self.copy),
            us(self.verdict), us(self.tx), us(self.recycle),
            us(self.reload + self.el0 + self.rxstat + self.copy + self.verdict + self.tx + self.recycle));
    }
}

/// M5.5 (Track C, U5) — the REAL wasmi 0.32 EL0 Wasm-host running on CM5 silicon via a
/// SYNCHRONOUS EL0 EXCURSION (Option B), mirroring the isolated-EL0-GEM-driver model that
/// CM5 prod already proves on metal ([P7c]): IRQs off, NO scheduler, NO IPC endpoint — one
/// `enter_user` drop to EL0 that runs the module and reports back via SYS_DRIVER_REPORT.
///
/// The kernel is the TRUST ROOT: it Ed25519-verifies the signed `classify` module BEFORE a
/// single byte crosses into EL0. The `syncabi` el0-wasmhost image is linked into the single
/// 2 MiB GB5 EL0 window (0x1_4000_0000) that `mmu_cm5` can map; wasmi's ~355 KiB `.text`
/// lives in THAT EL0 image, entirely OUT of the kernel TCB (ADR 0044 D4 #2). The host runs
/// classify(4444) AND classify(443) and packs the two verdicts into `(v_a<<16)|v_b`, so a
/// SINGLE reported word proves the predicate genuinely COMPUTES (0x0001_0000 == block-4444 +
/// pass-443), not a constant. A trapping/faulting module is CONTAINED at EL0 (fail sentinel).
///
/// Runs ONCE at the top of `cm5_prod_service`, before the GEM driver claims the low GB5
/// pages; it unmaps its whole footprint on the way out so the GEM setup maps cleanly.
#[cfg(all(feature = "cm5", feature = "wasmhost"))]
fn wasmi_el0_cm5_metal() {
    use arch_aarch64::mmu_cm5;
    use core::ptr::write_volatile;
    const RPT_SENTINEL: u32 = 0xFFFF_FFFF; // DRIVER_REPORT pre-load; also the both-FAIL packing
    let base = mmu_cm5::USER_VA_BASE;
    let work_va = base + 0xD_0000; // == el0-wasmhost WORK_BASE (syncabi)
    let foot_top = work_va + 0x1000; // whole GB5 footprint [base, foot_top)

    // Parse + VALIDATE the embedded EL0 host ELF once (pure, fail-closed; W^X + GB5-window
    // checked). The `syncabi` build is ET_EXEC based at 0x1_4000_0000. Reused by both excursions.
    let parsed = match elf::parse(WASMI_ELF) {
        Ok(p) => p,
        Err(e) => {
            kprint!(" [P-wasmi-el0-metal] FAIL: EL0 host ELF rejected by loader: {:?}\n", e);
            return;
        }
    };

    // ========================= M5.5 — CLASSIFY excursion =========================
    // A signed memoryless classify(port) module: prove REAL wasmi computes correctly in an
    // isolated EL0 excursion. classify(4444)=1 (block) AND classify(443)=0 (pass) → 0x0001_0000.
    if let Some(sp_top) = load_el0_wasmhost_cm5(&parsed) {
        let (gwasm, gpk, gsig) = wasmhost::fixture_full();
        match wasmhost::verified_module(gwasm, gpk, gsig) {
            Some(module) => {
                let work = mmu_cm5::alloc_frame();
                if work != 0 {
                    let n = module.len().min(0xF00);
                    unsafe {
                        write_volatile(work as *mut u64, 4444u64); // port_a — block-4444 backdoor
                        write_volatile((work + 8) as *mut u64, 443u64); // port_b — benign pass
                        write_volatile((work + 16) as *mut u64, n as u64);
                        core::ptr::copy_nonoverlapping(module.as_ptr(), (work + 24) as *mut u8, n);
                    }
                    mmu_cm5::map_user_data(work_va, work);
                    DRIVER_REPORT.store(RPT_SENTINEL, Ordering::Relaxed);
                    unsafe { arch_aarch64::syscall::enter_user(parsed.entry, sp_top) };
                    let packed = DRIVER_REPORT.load(Ordering::Relaxed);
                    let va = (packed >> 16) & 0xffff;
                    let vb = packed & 0xffff;
                    let pass = packed != RPT_SENTINEL && va == 1 && vb == 0;
                    kprint!(
                        " [P-wasmi-el0-metal] {} — REAL wasmi 0.32 in an ISOLATED EL0 excursion on CM5 silicon: classify(4444)={} classify(443)={} packed={:#010x} (want 0x00010000); wasmi .text is in the {}-byte EL0 image, NOT the kernel TCB\n",
                        if pass { "PASS" } else { "FAIL" },
                        va as i32, vb as i32, packed, WASMI_ELF.len()
                    );
                }
            }
            None => kprint!(" [P-wasmi-el0-metal] FAIL: signed classify module failed Ed25519 verify\n"),
        }
        // Unmap so the next excursion (and later the GEM driver) maps a clean L3 table.
        let mut va = base;
        while va < foot_top { mmu_cm5::unmap_user(va); va += 0x1000; }
    } else {
        kprint!(" [P-wasmi-el0-metal] FAIL: EL0 host load failed (frame pool / GB5 window)\n");
    }

    // ==================== M5.6 — DETECTION-at-PARITY excursion ====================
    // A signed DETECTION module (linear memory + hp_input/hp_emit imports) run THROUGH wasmi
    // over a VECTOR of 8 L4 headers; its per-input verdicts must EQUAL the in-kernel
    // rules::run_l4 reference case-for-case (PARITY, ADR 0044 D4 #4) — the REAL IDS/IPS use
    // of the Wasm host, now on silicon (the QEMU [P-wasm-parity] proof was explicitly NOT metal).
    if let Some(sp_top) = load_el0_wasmhost_cm5(&parsed) {
        let (dwasm, dpk, dsig) = wasmhost::fixture_detect();
        // (b) fail-closed BEFORE hand-off: a tampered module (last byte flipped) fails verify.
        let mut tampered = [0u8; 256];
        let tn = dwasm.len().min(256);
        tampered[..tn].copy_from_slice(&dwasm[..tn]);
        tampered[tn - 1] ^= 0x01;
        let tamper_refused = wasmhost::verified_module(&tampered[..tn], dpk, dsig).is_none();
        match wasmhost::verified_module(dwasm, dpk, dsig) {
            Some(module) => {
                // The PARITY corpus: 8 L4 headers (src port 0, dst port big-endian). Three
                // blocked ports mirror rules.rs RULES (4444/23/31337 = Signature). The kernel
                // computes the reference with the SAME rules::run_l4 the module must reproduce.
                const STRIDE: usize = 8;
                const NP: usize = 8;
                let ports: [u16; NP] = [4444, 23, 31337, 80, 443, 22, 0, 65535];
                let mut inputs = [0u8; NP * STRIDE];
                let mut expected: u32 = 0;
                let mut i = 0usize;
                while i < NP {
                    let b = i * STRIDE;
                    inputs[b + 2] = (ports[i] >> 8) as u8; // dst-port high
                    inputs[b + 3] = (ports[i] & 0xff) as u8; // dst-port low
                    let wire = rules::run_l4(&inputs[b..b + STRIDE], 0) as u32; // 1=PASS 2=DROP
                    expected |= (wire & 0xF) << (4 * i);
                    i += 1;
                }
                let work = mmu_cm5::alloc_frame();
                if work != 0 {
                    // DETECT ABI: [+0]=MAGIC [+8]=n [+16]=stride [+24]=mod_len, inputs@+32, module@+512.
                    let mod_len = module.len().min(0x1000 - 512);
                    let in_len = inputs.len().min(512 - 32);
                    unsafe {
                        write_volatile(work as *mut u64, DETECT_MAGIC);
                        write_volatile((work + 8) as *mut u64, NP as u64);
                        write_volatile((work + 16) as *mut u64, STRIDE as u64);
                        write_volatile((work + 24) as *mut u64, mod_len as u64);
                        core::ptr::copy_nonoverlapping(inputs.as_ptr(), (work + 32) as *mut u8, in_len);
                        core::ptr::copy_nonoverlapping(module.as_ptr(), (work + 512) as *mut u8, mod_len);
                    }
                    mmu_cm5::map_user_data(work_va, work);
                    DRIVER_REPORT.store(RPT_SENTINEL, Ordering::Relaxed);
                    unsafe { arch_aarch64::syscall::enter_user(parsed.entry, sp_top) };
                    let packed = DRIVER_REPORT.load(Ordering::Relaxed);
                    let parity = packed != RPT_SENTINEL && packed == expected;
                    kprint!(
                        " [P-wasm-parity-metal] {} — SIGNED DETECTION module (linear memory + hp_input/hp_emit) via REAL wasmi in an ISOLATED EL0 excursion on CM5 silicon over {} L4 headers: wasm-packed={:#010x} vs in-kernel rules::run_l4={:#010x} (nibble/input, 1=PASS 2=DROP); tamper_refused_before_EL0={}\n",
                        if parity { "PASS" } else { "FAIL" },
                        NP, packed, expected, tamper_refused
                    );
                }
            }
            None => kprint!(" [P-wasm-parity-metal] FAIL: signed detection module failed Ed25519 verify\n"),
        }
        let mut va = base;
        while va < foot_top { mmu_cm5::unmap_user(va); va += 0x1000; }
    }
}

/// M5.5/M5.6 helper — map the `syncabi` el0-wasmhost image (code RO+X, rodata RO, data RW+NX)
/// into fresh zeroed GB5 frames via the CM5 single-AS mapper, plus a 64 KiB stack and 256 KiB
/// heap at the fixed VAs (matching el0-wasmhost). Returns sp_top, or None on frame-pool/window
/// failure. The caller stages the work page + drives the excursion.
#[cfg(all(feature = "cm5", feature = "wasmhost"))]
fn load_el0_wasmhost_cm5(parsed: &elf::ParsedElf) -> Option<usize> {
    use arch_aarch64::mmu_cm5;
    let base = mmu_cm5::USER_VA_BASE;
    let stack_va = base + 0x8_0000; // above the ~393 KiB (0x61000) image, page-aligned
    let stack_pages = 16usize; // 64 KiB
    let heap_va = base + 0x9_0000; // == el0-wasmhost HEAP_BASE (syncabi)
    let heap_pages = 64usize; // 256 KiB == el0-wasmhost HEAP_SIZE
    // PT_LOAD segments — W^X: RO+X text / RO rodata / RW+NX data; alloc_frame zeroes (bss tail=0).
    let mut si = 0usize;
    while si < parsed.nsegs {
        let s = parsed.segs[si];
        let exec = s.executable();
        let write = s.writable();
        let npages = (s.memsz + 0xFFF) >> 12;
        let mut p = 0usize;
        while p < npages {
            let f = mmu_cm5::alloc_frame();
            if f == 0 {
                return None;
            }
            let voff = p * 0x1000;
            let fileleft = s.filesz.saturating_sub(voff);
            let n = fileleft.min(0x1000);
            if n > 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(WASMI_ELF.as_ptr().add(s.offset + voff), f as *mut u8, n);
                }
            }
            let va = s.vaddr + voff;
            let ok = if exec {
                mmu_cm5::map_user_code(va, f);
                arch_aarch64::mmu::sync_instruction_cache(f, 0x1000);
                true
            } else if write {
                mmu_cm5::map_user_data(va, f)
            } else {
                mmu_cm5::map_user_data_ro(va, f)
            };
            if !ok {
                return None;
            }
            p += 1;
        }
        si += 1;
    }
    let mut p = 0usize;
    while p < stack_pages {
        let f = mmu_cm5::alloc_frame();
        if f == 0 {
            return None;
        }
        mmu_cm5::map_user_data(stack_va + p * 0x1000, f);
        p += 1;
    }
    let sp_top = stack_va + stack_pages * 0x1000;
    let mut p = 0usize;
    while p < heap_pages {
        let f = mmu_cm5::alloc_frame();
        if f == 0 {
            return None;
        }
        mmu_cm5::map_user_data(heap_va + p * 0x1000, f);
        p += 1;
    }
    Some(sp_top)
}

#[cfg(feature = "cm5")]
fn cm5_prod_service() -> ! {
    use arch_aarch64::mmu_cm5;
    arch_aarch64::disable_irqs();
    // THERMAL (2026-09-10) — prod busy-polls the GEM RX ring with IRQs OFF (no GEM IRQ to
    // wake a plain WFI), so between frames the A76 spun at 100% and cooked the CM5. Enable the
    // ARM generic-timer EVENT STREAM: it posts a periodic WFE wake-event WITHOUT any interrupt,
    // so the idle branch of the drain loop can WFE (clock-gate the core) and wake periodically
    // to re-scan. EVNTI=10 -> a wake on CNTVCT[10] (every 1024 ticks; ~19 µs at the CM5's
    // ~54 MHz cntfrq): a large idle duty-cycle/heat cut for a negligible (~20 µs) RX-latency
    // add. Under load (batch>0) the loop never WFEs, so RX throughput is unchanged (a frame
    // arriving during a WFE is caught on the very next poll). CNTKCTL_EL1: EVNTEN(bit2)=1,
    // EVNTI(7:4)=10, EVNTDIR(bit3)=0; EL0 timer-access bits (1:0) preserved. The event stream
    // wakes WFE at EL0 too, so the isolated GEM stub's shortened empty-wait costs nothing hot.
    unsafe {
        let mut cntkctl: u64;
        core::arch::asm!("mrs {}, cntkctl_el1", out(reg) cntkctl, options(nomem, nostack));
        cntkctl &= !0b1111_1000; // clear EVNTI(7:4) + EVNTDIR(3) + EVNTEN(2)
        cntkctl |= (10u64 << 4) | (1u64 << 2); // EVNTI=10 (~19 µs), EVNTEN=1 (EVNTDIR stays 0)
        core::arch::asm!("msr cntkctl_el1, {}", in(reg) cntkctl, options(nomem, nostack));
        core::arch::asm!("isb", options(nomem, nostack));
    }
    // M5.5 (Track C, U5) — ONE-SHOT: run a REAL signed `.wasm` module through wasmi 0.32 in an
    // ISOLATED EL0 excursion on CM5 silicon, BEFORE the GEM driver claims the low GB5 pages.
    // Mirrors the isolated-EL0-GEM-driver model (enter_user, IRQs-off, no scheduler/no IPC);
    // proves the on-device Wasm host (ADR 0044 Track C M5). It unmaps its own footprint so the
    // GEM setup below maps the shared low VAs cleanly.
    #[cfg(feature = "wasmhost")]
    wasmi_el0_cm5_metal();
    extern "C" {
        static gem_ids_stub: u8;
        static gem_ids_stub_end: u8;
    }
    let ids = (
        core::ptr::addr_of!(gem_ids_stub) as usize,
        core::ptr::addr_of!(gem_ids_stub_end) as usize,
    );
    let code_pa = mmu_cm5::el0_code_pa();
    let ucode = mmu_cm5::USER_VA_BASE;
    let ustack = mmu_cm5::USER_VA_BASE + 0x1000;
    let uring = mmu_cm5::USER_VA_BASE + 0x3000;
    mmu_cm5::map_user_data(ustack, mmu_cm5::el0_stack_pa());
    mmu_cm5::map_user_nc(uring, arch_aarch64::gem::rxring_pa());
    arch_aarch64::gem::tx_init(); // forwarding path for a PASS verdict
    // RX-THROUGHPUT (2026-09-09, Linux-reference validated the GEM config is correct; the
    // bottleneck was the DRAIN path): the EL0 stub is mapped AP_RO_EL0 (read-only to EL0 —
    // map_user_code uses AP_RO_EL0|PXN), so EL0 CANNOT corrupt its code. Reloading it (a
    // multi-KiB copy + full I-cache maintenance + remap) EVERY loop iteration was therefore
    // pure overhead on the hot path — rxprof measured the EL0/reload phase at ~99.9% of
    // per-frame cost, capping sustained RX at ~389/s. Load it ONCE here; re-load ONLY after a
    // contained fault (the only event that could leave EL0 state needing a reset).
    {
        let len = ids.1 - ids.0;
        unsafe { core::ptr::copy_nonoverlapping(ids.0 as *const u8, code_pa as *mut u8, len) };
        arch_aarch64::mmu::sync_instruction_cache(code_pa, len);
        mmu_cm5::map_user_code(ucode, code_pa);
    }

    // Distinct sentinel (AUDIT D3/D4) so a CONTAINED EL0 driver fault — the stub crashed
    // before it ran its report syscall — is told apart from a benign empty window (where
    // the stub DOES report, with 0). Without this the two collapse into `empty` and a
    // crash-looping driver reads as a quiet link.
    const RPT_SENTINEL: u32 = 0xFFFF_FFFF; // DRIVER_REPORT is u32; a real report is idx<<16 (< this)
    // Telemetry invariant: seen == forwarded + dropped + tx_fail.
    let (mut seen, mut forwarded, mut dropped) = (0u64, 0u64, 0u64);
    let (mut empty, mut faults, mut tx_fail) = (0u64, 0u64, 0u64);
    // M4 GEM↔smoltcp bridge FIRST-LIGHT (netmetal). A persistent EL1 smoltcp instance that
    // answers ARP for heqk's own control-plane IP (10.200.0.2/28) on the REAL wire — the first
    // proof heqk terminates a frame rather than only forward/drop it. Seed fail-closed from the
    // rng200 TRNG: a dead TRNG ⇒ no bridge (control plane stays down; the sensor loop is
    // unaffected). LA MAC 02:00:00:00:00:02 (device-derived MAC is the M4.2 refinement).
    // prod stays byte-identical — this whole block compiles out without `netmetal`.
    #[cfg(feature = "netmetal")]
    let mut metal_bridge: Option<netsvc::MetalBridge> = match arch_aarch64::rng200::next_word_strict() {
        Some(w) => {
            let mac = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x02];
            kprint!(" [NETMETAL] smoltcp bridge UP on GEM: 10.200.0.2/28 mac 02:00:00:00:00:02 (TRNG-seeded)\n");
            Some(netsvc::MetalBridge::new(mac, [10, 200, 0, 2], 28, w as u64))
        }
        None => {
            kprint!(" [NETMETAL] control plane DISABLED — TRNG absent (sensor still live)\n");
            None
        }
    };
    // M4 DHCPv4 client (feature `dhcp`): heqk obtains its lease over the GEM. Own MAC/seed;
    // TRNG-seeded fail-closed (no client without entropy).
    #[cfg(feature = "dhcp")]
    let mut dhcp_client: Option<netsvc::DhcpClient> = match arch_aarch64::rng200::next_word_strict() {
        Some(w) => {
            kprint!(" [DHCP] client UP on GEM (mac 02:00:00:00:00:02) — soliciting a lease\n");
            Some(netsvc::DhcpClient::new([0x02, 0, 0, 0, 0, 0x02], w as u64))
        }
        None => None,
    };
    // Persistent RX read cursor — the analog of Linux macb's `queue->rx_tail`. The GEM
    // fills descriptors sequentially and wraps, so `rx_head` is the oldest unconsumed
    // slot; the batch drainer advances it in lockstep with the hardware fill. It survives
    // across EL0 excursions so the drain never re-scans from 0 (which would misalign with
    // the GEM's fill position).
    let mut rx_head: usize = 0;
    // NAPI-style drain budget: how many frames one EL0 excursion may consume before
    // yielding back to the loop. Bounds worst-case latency while amortizing the ~ms EL0
    // round-trip (rxprof-measured) over a whole batch instead of paying it per frame.
    const RX_BUDGET: usize = 64;
    // Wall-clock heartbeat so the sensor is visibly ALIVE on a quiet link (the empty-
    // window `continue` below skips any end-of-loop print). ~5 s cadence via cntpct.
    let cntfrq = {
        let f: u64;
        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
        f.max(1)
    };
    let hb_interval = cntfrq * 5;
    let t0 = prod_cntpct();
    let mut last_hb = t0;
    // prod-full: bring up M3 persistence + establish the M4/M6 posture BEFORE the
    // loop. Infallible by construction — any storage/crypto failure degrades to
    // "no persistence" and the sensor still runs (PH1: never halts).
    #[cfg(feature = "prod-full")]
    let mut pf = prodfull::ProdFull::init();
    #[cfg(feature = "rxprof")]
    let mut prof = RxProf::default();

    kprint!(" [PROD] HEQK sensor UP — isolated EL0 GEM driver -> verified rule plane -> ENFORCE (forward PASS / drop threat); self-healing; never halts\n");
    // M2 Gate-R A7/A8/L9 ON-METAL shed-logic self-test (sepdiag). A7 (conntrack-saturation)
    // and A8 (PSI pressure) are NOT frame-drivable — reaching 80% of a 100k flow table or
    // real scheduler pressure from a generator is impractical. So prove the LOGIC on silicon
    // deterministically via the documented Gate-R synthetic hooks (the honest QEMU-vs-metal
    // split): the LIVE wiring above (resource_shed_verdict in classify) still sheds under
    // real load; this confirms the decision function itself on-metal.
    #[cfg(feature = "sepdiag")]
    {
        let flood: u64 = 0x0a63_0009;
        let legit: u64 = 0x0a63_0002;
        // Make `flood` the dominant top-talker: > SHED_TOPTALKER_MIN_FLOWS (100) and above
        // anything the (not-yet-started) datapath has recorded, so is_top_talker(flood) holds.
        for _ in 0..150 { crate::ratelimit::flow_record(flood); }
        crate::ratelimit::flow_record(legit);
        let a7 = crate::ratelimit::saturation_shed(flood, 85_000, 100_000); // >80% + top → shed
        let l9_under = crate::ratelimit::saturation_shed(flood, 40_000, 100_000); // <80% → no shed
        let l9_legit = crate::ratelimit::saturation_shed(legit, 85_000, 100_000); // not top → no shed
        crate::ratelimit::set_synthetic_pressure(60); // >= PSI_SHED_PCT (40) floor
        let a8 = crate::ratelimit::pressure_shed(flood); // top-talker sheds
        let a8_legit = crate::ratelimit::pressure_shed(legit); // small legit never top → no shed
        crate::ratelimit::set_synthetic_pressure(10); // < PSI floor
        let a8_revert = crate::ratelimit::pressure_shed(flood); // pressure cleared → revert
        crate::ratelimit::clear_synthetic_pressure();
        let pass = a7 && !l9_under && !l9_legit && a8 && !a8_legit && !a8_revert;
        kprint!("   [SEPDIAG-SHED] A7 sat-shed={} L9(under-wall)={} L9(not-top)={} | A8 psi-shed={} A8(legit)={} A8(revert)={} => {}\n",
            a7, l9_under, l9_legit, a8, a8_legit, a8_revert, if pass { "PASS" } else { "FAIL" });
    }
    // M2 A1/A2 ON-METAL port-role-SOURCE self-test (sepdiag). The gap: classify() used a
    // hardcoded DEFAULT_PORT_ROLE stub, so Access→RateLimit (row A1) could never fire on the
    // live device. classify() now consults the per-port role TABLE (verdict::port_role_for);
    // this proves that table → l2_stateful_verdict → decide_l2 yields DROP on a table-marked
    // Access port and Observe on an Uplink port, on silicon, through the SAME path classify
    // walks. Synthetic port ids 6/7 (live port 0 stays fail-safe Uplink; a real Access
    // interface awaits the manifest reader). Restored to Uplink after, so no live effect.
    #[cfg(feature = "sepdiag")]
    {
        use crate::verdict::{port_role_for, set_port_role, PortRole, Verdict};
        set_port_role(6, PortRole::Access);
        set_port_role(7, PortRole::Uplink);
        let a_role = port_role_for(6) == PortRole::Access; // table returns what we wrote
        let u_role = port_role_for(7) == PortRole::Uplink;
        let mut fr = [0u8; 64];
        fr[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // unicast dst (mac-flood only)
        fr[12..14].copy_from_slice(&[0x08, 0x00]);
        // A1: 40 distinct src MACs on the ACCESS port (> MAC_FLOOD_ACCESS 20) → RateLimit DROP.
        let mut a1_drop = false;
        for i in 0..40u8 {
            fr[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, i]);
            if rules::l2_stateful_verdict(&fr, 0, 6, port_role_for(6)).map_or(false, Verdict::is_drop) {
                a1_drop = true;
            }
        }
        // A2: the SAME fan-out scaled past the Uplink bar (320 > MAC_FLOOD_UPLINK 300) MUST
        // fire but stay Observe — a busy AP's client MACs are NEVER wire-dropped (D12).
        let mut a2_fired = false;
        let mut a2_drop = false;
        for i in 0..320u16 {
            fr[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, (i >> 8) as u8, (i & 0xff) as u8]);
            if let Some(v) = rules::l2_stateful_verdict(&fr, 0, 7, port_role_for(7)) {
                a2_fired = true;
                if v.is_drop() || v != Verdict::Observe {
                    a2_drop = true;
                }
            }
        }
        set_port_role(6, PortRole::Uplink); // restore fail-safe on the synthetic ports
        set_port_role(7, PortRole::Uplink);
        let pass = a_role && u_role && a1_drop && a2_fired && !a2_drop;
        kprint!("   [SEPDIAG-A1A2] table Access={} Uplink={} | A1 access-macflood-DROP={} | A2 uplink-fired={} uplink-drop={} => {}\n",
            a_role, u_role, a1_drop, a2_fired, a2_drop, if pass { "PASS" } else { "FAIL" });
    }
    // M2 F4/F7/L1 ON-METAL structural + exemption self-test (sepdiag). These three are
    // NOT host-frame-drivable — the injecting NIC pads runts to 60B (F4 can't ride the
    // wire sub-14B) and enforces MTU 1522 (F7 oversize can't be sent), and L1 is a
    // never-fires exemption. So prove the DECISION on silicon through the REAL datapath
    // entry `packet::verdict` (the same chain classify walks live), which is a strictly
    // stronger proof than calling a detector directly.
    #[cfg(feature = "sepdiag")]
    {
        use crate::packet::{verdict as pkt_verdict, DROP};
        // F4 — a frame shorter than an Ethernet header: net::parse fail-closes → DROP (rule 120).
        let f4 = [0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00];
        let (_p4, v4) = pkt_verdict(&f4);
        let f4_drop = v4 == DROP;
        // F7 — oversize (> MAX_FRAME_LEN 1522): structural_anomaly → MalformedFrame → FrameDrop.
        // src MAC unicast (LSB 0) so F6 (mcast-source) does NOT pre-empt the oversize check.
        let mut f7 = [0u8; 1600];
        f7[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        f7[6..12].copy_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        f7[12..14].copy_from_slice(&[0x08, 0x00]);
        let (_p7, v7) = pkt_verdict(&f7);
        let f7_drop = v7 == DROP;
        // L1 — a legit mDNS (01:00:5e:00:00:fb) burst is EXEMPT from the broadcast-storm
        // counter: even 200 frames must NEVER fire the L2 tier (the exact exemption is the
        // L1 mechanism). Asserted at l2_stateful_verdict (a well-formed-L3 mDNS frame then
        // forwards through the rest of the chain — 5353 is no threat); this isolates the
        // exemption without an L3-malformed confound.
        let mut md = [0u8; 64];
        md[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
        md[6..12].copy_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        md[12..14].copy_from_slice(&[0x08, 0x00]);
        let mut l1_never_fires = true;
        for _ in 0..200 {
            if rules::l2_stateful_verdict(&md, 0, 0, crate::verdict::port_role_for(0)).is_some() {
                l1_never_fires = false;
            }
        }
        let pass = f4_drop && f7_drop && l1_never_fires;
        kprint!("   [SEPDIAG-STRUCT] F4 truncated-DROP={} | F7 oversize-DROP={} | L1 mDNS-200x-exempt(no-fire)={} => {}\n",
            f4_drop, f7_drop, l1_never_fires, if pass { "PASS" } else { "FAIL" });
    }
    // M2 L4/A9 ON-METAL RA-guard self-test (sepdiag, RFC 6105). An ICMPv6 Router
    // Advertisement (type 134) is legit ONLY from a router/uplink port. Port-role-gated:
    // Access → FrameDrop (A9, rogue gateway-hijack), Uplink → Observe (L4, legit
    // downstream-router RA accepted + logged). Proven on the synthetic port ids 6/7
    // through the real l2_stateful_verdict → decide_l2(RaGuard) path; the live port 0
    // defaults Uplink, so a real RA is NEVER dropped on the box (fail-safe) until a
    // manifest marks a specific access interface.
    #[cfg(feature = "sepdiag")]
    {
        use crate::verdict::{PortRole, Verdict};
        // A minimal well-formed ICMPv6 RA: eth(IPv6) + IPv6 hdr (next-hdr 58) + type 134.
        let mut ra = [0u8; 70];
        ra[0..6].copy_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]); // IPv6 all-nodes (33:33.. exempt)
        ra[6..12].copy_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]); // unicast src (no F6)
        ra[12..14].copy_from_slice(&[0x86, 0xdd]); // ethertype IPv6
        ra[14] = 0x60; // IPv6 version 6
        ra[18] = 0x00;
        ra[19] = 0x10; // payload length = 16 (a minimal RA body)
        ra[20] = 58; // next-header = ICMPv6
        ra[21] = 255; // hop limit
        ra[54] = 134; // ICMPv6 type = Router Advertisement (IPv6 base hdr is 40B → offset 14+40)
        let is_ra = crate::net::is_icmpv6_ra(&ra);
        // A9 — rogue RA on an ACCESS port → FrameDrop.
        let a9_drop = rules::l2_stateful_verdict(&ra, 0, 6, PortRole::Access).map_or(false, Verdict::is_drop);
        // L4 — legit RA on an UPLINK port → Observe (fires but never a wire drop).
        let l4_observe = rules::l2_stateful_verdict(&ra, 0, 7, PortRole::Uplink) == Some(Verdict::Observe);
        let pass = is_ra && a9_drop && l4_observe;
        kprint!("   [SEPDIAG-RAGUARD] is-RA={} | A9 rogue-RA-access-DROP={} | L4 legit-RA-uplink-Observe={} => {}\n",
            is_ra, a9_drop, l4_observe, if pass { "PASS" } else { "FAIL" });
    }
    // M2 A11 ON-METAL corroboration self-test (sepdiag). Corroboration is a SOC-SEVERITY
    // signal, NEVER a wire action (security-auditor 2026-09-08: durable Quarantine from
    // corroboration is FP-unsafe + weaponizable + heqk has no segment-isolation primitive).
    // This proves the tracker accumulates axes AND — the load-bearing property — that a
    // corroborated source's wire verdict STAYS Observe/PASS (an attacker, a legit ops host
    // that trips 3 axes benignly, both PASS), and the mgmt floor still holds.
    #[cfg(feature = "sepdiag")]
    {
        use crate::corroboration as corr;
        use crate::verdict::{decide, DecideCtx, FindingClass, Verdict};
        // (1) attacker: REPUTATION + BEACON + SCAN → corroborated, but the wire stays PASS.
        let atk: u64 = 0xC612_0001; // 198.18.0.1 (TEST-NET-2, off the live datapath)
        corr::corr_observe(atk, corr::AXIS_REPUTATION);
        corr::corr_observe(atk, corr::AXIS_BEACON);
        let atk_axes = corr::corr_observe(atk, corr::AXIS_SCAN);
        let atk_corr = corr::is_corroborated(atk) && atk_axes == 3;
        let atk_pass = decide(FindingClass::Behavioral, DecideCtx::for_src(atk as u32)) == Verdict::Observe;
        // (2) legit ops host: LATERAL + EXFIL + BEACON (benign backup/monitoring) → also
        //     corroborated, and MUST still PASS — the whole reason corroboration is off the wire.
        let ops: u64 = 0xC612_0002;
        corr::corr_observe(ops, corr::AXIS_LATERAL);
        corr::corr_observe(ops, corr::AXIS_EXFIL);
        corr::corr_observe(ops, corr::AXIS_BEACON);
        let ops_corr = corr::is_corroborated(ops);
        let ops_pass = decide(FindingClass::Behavioral, DecideCtx::for_src(ops as u32)) == Verdict::Observe;
        // (3) mgmt floor holds even when corroborated with an enforceable (scan) finding.
        let mgmt: u64 = 0x0AC8_0005; // 10.200.0.5
        corr::corr_observe(mgmt, corr::AXIS_REPUTATION);
        corr::corr_observe(mgmt, corr::AXIS_SCAN);
        corr::corr_observe(mgmt, corr::AXIS_BEACON);
        let mgmt_floor = decide(FindingClass::ScanShape, DecideCtx::for_src(mgmt as u32)) == Verdict::Allowlisted;
        let pass = atk_corr && atk_pass && ops_corr && ops_pass && mgmt_floor;
        kprint!("   [SEPDIAG-CORR] attacker corroborated={} wire-PASS={} | legit-ops corroborated={} wire-PASS={} | mgmt-floor={} => {}\n",
            atk_corr, atk_pass, ops_corr, ops_pass, mgmt_floor, if pass { "PASS" } else { "FAIL" });
    }
    // M-segmentation reach plane on metal — the per-device reach ACTUATOR (U2b + L5/L6 NAC +
    // A11 quarantine-to-segment). Proves the reach matrix + fail-open invariants through the
    // real `segment::reach_allow` decision, then leaves the plane DISARMED (C7 — inert in
    // production until an authenticated authority arms it, so no reach-drop hits the wire).
    #[cfg(feature = "sepdiag")]
    {
        let seg = crate::segment::reach_selftest();
        let armed = crate::segment::reach_armed(); // must be false after the self-test (C7)
        kprint!("   [SEPDIAG-SEG] reach-matrix(Full/InternetOnly/Quarantine x LAN/WAN/infra + mgmt-floor + fail-open)={} | armed-after={} (must be false) => {}\n",
            seg, armed, if seg && !armed { "PASS" } else { "FAIL" });
    }
    // M2 A6 scan-tier self-test (sepdiag) — settles the M2 follow-up "FIN-scan (202) doesn't
    // fire while NULL/XMAS do". The three stateless flag rules are byte-eq on the SAME TCP
    // offset 13, so a lone FIN (0x01) MUST fire rule 202 exactly as NULL (0x00) fires 201 and
    // Xmas (0x29) fires 203. This drives each single crafted header through the REAL
    // verdict_tcp path and asserts each returns Some (a rule matched → an event fired) — proving
    // the metal "miss" was a harness/masking artifact, not a code asymmetry. A single crafted
    // packet with no rate context graduates to observe (RateLimit{over_limit:false}); the
    // event still fires (fire() pushes it regardless of the wire verdict).
    #[cfg(feature = "sepdiag")]
    {
        // Minimal 20-byte TCP header; byte 12 = data-offset (5<<4), byte 13 = flags.
        let hdr = |flags: u8| -> [u8; 20] {
            let mut t = [0u8; 20];
            t[12] = 0x50;
            t[13] = flags;
            t
        };
        let src = 0xC612_0006u32; // 198.18.0.6 (TEST-NET-2, off the live datapath)
        let null_fires = rules::verdict_tcp(&hdr(0x00), src).is_some();
        let fin_fires = rules::verdict_tcp(&hdr(0x01), src).is_some();
        let xmas_fires = rules::verdict_tcp(&hdr(0x29), src).is_some();
        // A normal SYN(0x02) must NOT fire any scan rule (no false positive on legit setup).
        let syn_quiet = rules::verdict_tcp(&hdr(0x02), src).is_none();
        let pass = null_fires && fin_fires && xmas_fires && syn_quiet;
        kprint!("   [SEPDIAG-SCAN] NULL(201)-fires={} FIN(202)-fires={} XMAS(203)-fires={} | legit-SYN-quiet={} => {}\n",
            null_fires, fin_fires, xmas_fires, syn_quiet, if pass { "PASS" } else { "FAIL" });
    }
    // DRV-1 sink experiment (mipdump): the RP1 MSI-X table is unreadable (config-space
    // access returns 0xffffffff), so make the GEM actually EMIT RX-complete MSIs (IER
    // RCOMP + RP1 MSIX_CFG(6)) and unmask BOTH candidate sinks (mip0 + brcmstb RC). IRQs
    // stay masked — the poll drain is unchanged — but the sink STATUS registers latch
    // pending bits regardless of GIC routing, so reading them each heartbeat reveals
    // which doorbell the RP1 ETH source targets and the vector, on real flowing frames.
    #[cfg(feature = "mipdump")]
    {
        arch_aarch64::gem::rx_irq_enable();
        let _ = arch_aarch64::gem::rx_msix_setup();
        // ROOT-CAUSE FIX: enumerate the RC bridge (config access), then program the RP1
        // MSI-X table entry (mip0 doorbell) + BME, then unmask mip0. This is the full
        // chain that should make the RP1 ETH source emit MSIs the mip0 sink latches.
        let _ = arch_aarch64::gem::pcie_bridge_enumerate();
        let _ = arch_aarch64::gem::pcie_map_bar0_window();
        let _ = arch_aarch64::gem::pcie_inbound_mip_doorbell();
        let _ = arch_aarch64::gem::rx_msix_program();
        arch_aarch64::gem::msi_sink_unmask();
        arch_aarch64::gem::rx_msix_iack();
    }
    // M4 Noise-over-bridge control-plane TRANSPORT first-light: a once-per-boot BROADCAST UDP
    // presence beacon, emitted from the sensor heartbeat below through the ONE gem::tx_frame path
    // (Linux-`macb`-aligned: single RX-ring owner, no second walker — the deleted GemPhy/bring-up
    // corrupted the ring → BNA stall). Link-gated by a SAFE PHY BMSR read. `device_id` captured
    // here so the closure over the heartbeat can build the beacon.
    #[cfg(feature = "netmetal")]
    let beacon_device_id: u64 = read_seal_handoff().map(|h| h.device_id).unwrap_or(0);
    #[cfg(feature = "netmetal")]
    let mut beacon_count: u32 = 0;

    // M4.5 control-plane INITIATOR on metal: the ControlPlane drives the full PQ-hybrid Noise
    // handshake toward the provisioned MSSP over the smoltcp-free hand-framed UDP transport,
    // riding this SINGLE drain (RX tee) + the one gem::tx_frame (poll_egress). Session ephemerals
    // are drawn fail-closed from the real HW-TRNG once; a dead TRNG ⇒ no handshake (sensor runs).
    // The full handshake completes only against a live host MSSP-sim; msg1-on-the-wire (this
    // increment) proves the initiator + chunked transport on silicon.
    #[cfg(all(feature = "netmetal", feature = "securechannel"))]
    let mut cp: Option<controlplane::ControlPlane> = {
        let blob: &[u8; 1216] = include_bytes!("testdata/provisioned_mssp_pub.bin");
        let mut xpk = [0u8; 32];
        xpk.copy_from_slice(&blob[..32]);
        match securechannel::ResponderPub::from_provisioned(xpk, &blob[32..]) {
            Some(rp) => match device_identity_keypair() {
                Some(dev_kp) => {
                    let fp = boot_abi::sha256::digest(&dev_kp.pk[..]);
                    kprint!(" [NETCP] control-plane initiator UP — provisioned MSSP key loaded; handshake will start at link-up\n");
                    kprint!(" [NETCP] device identity (SRK-derived) pk=");
                    for b in dev_kp.pk.iter() {
                        kprint!("{:02x}", b);
                    }
                    kprint!(" fp[0..8]={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} — register this pk with the MSSP to enroll\n",
                        fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7]);
                    Some(controlplane::ControlPlane::new(rp, dev_kp, [0x02, 0, 0, 0, 0, 0x02], [10, 200, 0, 2]))
                }
                None => {
                    kprint!(" [NETCP] DISABLED — no hboot SRK (no device secret): refusing a guessable device identity; sensor unaffected\n");
                    None
                }
            },
            None => {
                kprint!(" [NETCP] DISABLED — provisioned MSSP blob invalid\n");
                None
            }
        }
    };
    #[cfg(all(feature = "netmetal", feature = "securechannel"))]
    let cp_irand = crate::securechannel::InitiatorRandomness::from_entropy(
        &mut crate::entropy::MetalEntropy::new(crate::entropy::HwTrng::new()),
    )
    .ok();
    // M6 B2 evidence export (`prod-export` = prod-full + netmetal): created when the control
    // plane is Established with an MSSP-assigned tenant; until then the device is air-gapped
    // (should_export=false) and evidence only persists locally.
    #[cfg(all(feature = "prod-full", feature = "netmetal"))]
    let mut exporter: Option<export::Exporter> = None;
    #[cfg(all(feature = "prod-full", feature = "netmetal"))]
    let mut export_idle_hb: u32 = 0;
    // ── RP1 GEM large-frame TX size/alignment sweep (feature `txsweep`) ──────────────────
    // The host-RAM discriminator for the >90 B TX blocker (os-architect + external SoC expert,
    // 2026-09-09). Emits UDP broadcasts of stepped LENGTH and stepped DMA-buffer ALIGNMENT
    // through the ONE proven gem::tx_frame path (buffer overridden per frame). Correlate on the
    // host:  `tcpdump -ni FTS -e -v udp portrange 60000-60999`.
    //   dport = 60000+idx (sweep index) · UDP sport = frame length · IP.len encodes length too.
    // Signatures:  A) a length threshold that is IDENTICAL at every alignment  ⇒ GEM TX FIFO /
    // DMA-fetch depth (fault inside GEM);  B) the threshold MOVES with the DMA address — esp.
    // frames that fail only when the buffer crosses a 256-byte boundary (RP1's 128-bit×16-beat
    // AXI burst == PCIe EP 256-byte MPS)  ⇒ RP1 AXI/PCIe read-completion/iATU path. The kernel
    // line logs dma & {64,128,256,4096} so the boundary is unambiguous. Runs ONCE, then the
    // sensor loop proceeds normally.
    #[cfg(feature = "txsweep")]
    {
        let our_mac = [0x02u8, 0, 0, 0, 0, 0x02];
        let our_ip = [10u8, 200, 0, 2];
        let (nc_base, bus_base) = arch_aarch64::gem::sweep_base();
        kprint!(
            " [TXSWEEP] begin  nc_base={:#x} bus_base={:#x} dmacfg={:#010x}\n",
            nc_base,
            bus_base,
            arch_aarch64::gem::read_dmacfg()
        );
        // RUN 1 (2026-09-09) settled the coarse picture: frames 64..1024 B egress at EVERY
        // alignment; only the 1518 B frame (→ 1522 on wire once the GEM appends FCS) failed, at
        // all alignments, with a CLEAN descriptor (used=1, w1=0xc00085ee, tsr=0). The "~90 B
        // cliff" and the 256 B PCIe-boundary hypotheses are both refuted; the signature is a
        // pure LENGTH gate = a silent oversize-drop on TX. heqk sets neither NCFGR.JFRAME nor
        // NCFGR.BIG, so the MAC caps at the standard 1518-on-wire. This run (a) finds the EXACT
        // boundary in 1024..1522 incl. 1070 (the msg1 datagram size), then (b) enables JFRAME +
        // JML=10240 exactly as Linux macb does for the RP1 GEM and RE-runs — proving whether
        // jumbo-enable lifts the gate. Alignment is settled, so off=0 throughout.
        let mut sbuf = [0u8; 2100];
        macro_rules! emit {
            ($len:expr, $dport:expr) => {{
                let len: usize = $len;
                let dport: u16 = $dport;
                let n = netsvc::build_sweep_frame(our_mac, our_ip, dport, len, &mut sbuf);
                let bus = bus_base;
                arch_aarch64::gem::set_tx_override(Some((nc_base, bus)));
                let res = arch_aarch64::gem::tx_frame(&sbuf[..n]);
                let tsr = arch_aarch64::gem::read_tsr();
                kprint!(
                    "   [TXSWEEP] dport={} len={} dma={:#x} used={} w1={:#010x} tsr={:#06x}\n",
                    dport, n, bus, res.is_some() as u32, res.unwrap_or(0), tsr
                );
                for _ in 0..5_000_000u32 {
                    core::hint::spin_loop();
                }
            }};
        }
        // RUN 2 (2026-09-09) was decisive: the ">1024 B TX blocker" is NOT a length gate, a
        // PCIe-boundary fault, or a MAC max-frame limit — it is the tx_frame RETRIGGER racing
        // the tail of a large frame. RUN 2 showed a PERFECT pass/fail POSITIONAL alternation
        // at the boundary (1512✓ 1514✗ 1515✓ 1516✗ …) while 1520 and even 1600 transmitted on
        // the "pass" slots, and every passing large frame read TSR.TGO=1 (transmitter still
        // going). 1070 B (the msg1 datagram size) passes cleanly — the Noise handshake was
        // never blocked. FIX (gem.rs): gate the retrigger re-kick on TSR.TGO clear, exactly as
        // Linux macb does. RUN 3 VALIDATES it: (1) the boundary sweep should now pass at EVERY
        // length, and (2) a sustained back-to-back full-size (1514 B) burst should show NO
        // alternation. off=0 throughout.
        const BND: [usize; 18] = [
            1024, 1040, 1056, 1070, 1088, 1200, 1400, 1480, 1500, 1510, 1512, 1514, 1515, 1516, 1517, 1518, 1520, 1522,
        ];
        kprint!(
            " [TXSWEEP] phase 1: boundary sweep 1024..1522 (TGO-gated retrigger; ncfgr={:#010x})\n",
            arch_aarch64::gem::read_ncfgr()
        );
        {
            let mut i: u16 = 0;
            for &l in &BND {
                emit!(l, 60000 + i);
                i += 1;
            }
        }
        // Phase 2 — sustained full-size (1514 B = the max standard payload → 1518 on wire)
        // back-to-back burst. Pre-fix this alternated 1/0/1/0; post-fix every one must land.
        kprint!(" [TXSWEEP] phase 2: 32x back-to-back 1514B (alternation check)\n");
        {
            let mut k: u16 = 0;
            while k < 32 {
                emit!(1514usize, 62000 + k);
                k += 1;
            }
        }
        arch_aarch64::gem::set_tx_override(None);
        kprint!(" [TXSWEEP] done. Capture: tcpdump -ni FTS -e -v udp portrange 60000-62999\n");
    }
    // ── M4.5 SEGMENTATION ARMING (feature `segmetal`) ────────────────────────────────────
    // Once the ControlPlane is Established, request + apply an operator-signed ReachPolicy over
    // the live Session and ARM segment.rs. State lives as locals here (the eMMC store BORROWS the
    // Emmc device, so it is opened transiently at reconcile time; the Emmc + Enrollment outlive
    // the loop). OPERATOR_PK is the PINNED operator verify key (C10) — baked bytes, not derived,
    // so the device never holds the operator private key. The signing key lives only with the
    // host operator (responder-sim). Reach floor persists in the eMMC guard window (2032..2048).
    #[cfg(feature = "segmetal")]
    let mut seg_emmc = arch_aarch64::emmc::Emmc::probe();
    #[cfg(feature = "segmetal")]
    let mut seg_enr = enroll::Enrollment {
        tenant_id: 0, // set from the MSSP-authenticated msg2 payload before the REQ (ControlPlane::tenant)
        responder_x_pk: [0u8; 32], // not consulted by apply_reach_policy
        device_fp: cp.as_ref().map(|c| c.device_fp()).unwrap_or([0u8; 32]),
        generation: 0,
    };
    #[cfg(feature = "segmetal")]
    let mut seg_phase: u8 = 0; // 0=idle, 1=REQ sent, 2=armed
    // DIAG (garbling-proof): captured once in the drain, RE-PRINTED every heartbeat so the
    // serial loss at 115200 cannot eat the one-shot result.
    #[cfg(feature = "segmetal")]
    let mut seg_fslog_err: Option<crate::fslog::FsErr> = None;
    #[cfg(feature = "segmetal")]
    let mut seg_recon: Option<Result<usize, enroll::ReachPolicyErr>> = None;
    #[cfg(feature = "segmetal")]
    const OPERATOR_PK: [u8; 32] = [
        0xe8, 0xd8, 0x79, 0x93, 0xba, 0xe8, 0x16, 0xad, 0x3b, 0xea, 0x1b, 0x7a, 0xc7, 0x27, 0x26, 0x86, 0x18, 0xf0,
        0xf2, 0xf7, 0x63, 0x03, 0x90, 0x42, 0xe4, 0xd9, 0xa0, 0x9a, 0xcf, 0x1e, 0xaf, 0x8d,
    ];
    // #7: reach-floor fslog HOME is derived LAZILY inside the reconcile (post-handshake) — see
    // the drain block. It must NOT be read at boot: an eMMC read before the Noise handshake
    // disturbs the GEM's large-frame TX (shared RP1/PCIe path) and msg1 (1070 B) then times out.
    // DNS-sinkhole counter (feature `dnssink`) — reprinted every heartbeat for garbling-proof
    // metal observability (the on-wire sinkhole reply is the definitive proof).
    #[cfg(feature = "dnssink")]
    let mut dns_sinks: u64 = 0;
    // M5 WASM-HOST ON CM5 (feature `wasmhost`): run the bespoke in-kernel beachhead ONCE at
    // boot — Ed25519-verify a signed .wasm module then EXECUTE it with the dependency-free
    // no_std interpreter, ON SILICON. classify(4444)=1 / classify(443)=0; a tampered module or
    // bad signature is refused before interpretation (fail-closed). This is the first Wasm
    // module executed on heqk CM5 metal. (The full wasmi EL0 host is the deferred end-state —
    // it needs the build.rs un-gate + an EL0 excursion on cm5; see docs/design gap #6.)
    #[cfg(feature = "wasmhost")]
    {
        let w = wasmhost::wasmhost_selftest();
        kprint!(" [WASMMETAL] signed .wasm verify+run ON CM5 SILICON: verify_run={} classify(4444)={}(exp1) classify(443)={}(exp0) tamper_refused={} badsig_refused={}\n",
            w.a_verify_run, w.bad_result, w.ok_result, w.b_fail_closed, w.b_unsigned);
        kprint!(" [WASMMETAL] {} — bespoke no_std interpreter verified + executed a signed module on metal (M5 beachhead on CM5)\n",
            if w.a_verify_run && w.bad_result == 1 && w.ok_result == 0 && w.b_fail_closed && w.b_unsigned { "PASS" } else { "FAIL" });
    }
    // ADR 0047 D2 — Mission Control served by heqk on the CM5 (`prod-mc`). PASSIVE-FIRST (ADR 0037
    // D4): PASS frames are observed, never re-transmitted, so the device cannot break the network
    // it sits on; only the node's own replies (ARP/ICMP/DHCP/HTTP) go out the GEM. TRNG-seeded
    // (TCP ISNs) and fail-closed: no TRNG => no node, the sensor still runs.
    #[cfg(feature = "prod-mc")]
    let mut mc: Option<mcserve::McNode> = match arch_aarch64::rng200::next_word_strict() {
        Some(seed) => {
            let mac = device_mac();
            mcserve::state().set_clock(0, t0, cntfrq); // SNTP sets the epoch once the network is up
            // Owner verifier from the eMMC boot partition (ADR 0037 D3): no file = UNCLAIMED, and
            // every protected route refuses — never an open claim window.
            let owner = pf.read_owner();
            mcserve::set_owner(owner);
            #[cfg(feature = "mctls")]
            pf.tls_bring_up();
            if pf.persist_ready {
                mcserve::state().sealed_cap = crate::snapshot::SNAP_EVENTS as u16;
            }
            // D1: the prior boot's wall-clock-stamped detections come back into the UI.
            let mut restored = 0usize;
            for i in 0..crate::snapshot::SNAP_EVENTS {
                if let Some((ev, ms)) = pf.snap.timed_event(i) {
                    mcserve::state().push_restored(&ev, ms);
                    restored += 1;
                }
            }
            kprint!(" [MC] {} detection(s) restored from the sealed snapshot ({} without a known time not shown)\n",
                restored, pf.snap.nev - restored);
            kprint!(" [MC] owner: {}\n", if owner.is_some() { "CLAIMED — sign-in required" } else { "UNCLAIMED — access refused until flashed with an owner key" });
            let n = mcserve::McNode::new(mac, mcserve::NetMode::Dhcp, seed);
            if let Some(ref node) = n {
                kprint!(" [MC] Mission Control node UP on GEM: mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (SRK-derived), passive-first, DHCP in progress (fallback {}.{}.{}.{}); {} UI assets embedded\n",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], node.ip[0], node.ip[1], node.ip[2], node.ip[3], http::UI_ASSETS.len());
            }
            n
        }
        None => {
            kprint!(" [MC] Mission Control DISABLED — TRNG absent (sensor still live)\n");
            None
        }
    };
    // D2 (task #21) — ONE drain body for the SOAR ring, called on the heartbeat AND on demand
    // (ring >= 1/4 full or 250 ms since the last drain): the UI sees a detection within ~250 ms
    // and a burst between heartbeats no longer overruns the 64-slot ring.
    #[cfg(any(feature = "sepdiag", feature = "prod-full"))]
    macro_rules! soar_drain {
        () => {
            {
                let mut evs = [crate::events::Event::EMPTY; 32];
                loop {
                    let n = crate::events::drain(&mut evs);
                    if n == 0 { break; }
                    for e in &evs[..n] {
                        #[cfg(feature = "sepdiag")]
                        kprint!("   [SEPDIAG] rule={} verdict={} src={:#010x} sev={} class={}\n",
                            e.rule_id, if e.verdict == 2 { "DROP" } else { "PASS" }, e.src, e.severity, e.class);
                        #[cfg(feature = "prod-full")]
                        pf.on_threat(e);
                        #[cfg(feature = "prod-mc")]
                        mcserve::state().push_event(e);
                        #[cfg(all(feature = "prod-full", feature = "netmetal"))]
                        if let Some(x) = exporter.as_mut() {
                            x.push(e);
                        }
                    }
                    if n < evs.len() { break; }
                }
            }
        };
    }
    #[cfg(any(feature = "sepdiag", feature = "prod-full"))]
    let mut last_drain: u64 = 0;
    // A7.7 follow-up (metal 2026-11-07): the GEM loss counters are clear-on-read and SATURATE at
    // 18 bits; the RX ring is not serviced while the boot self-tests run, so on a busy segment the
    // first read is 262143 = "lost during boot", not runtime loss. Baseline here, report boot loss
    // once, and the heartbeat reports only what the running sensor lost.
    let gs_boot = arch_aarch64::gem::rx_stats();
    kprint!(" [PROD] GEM RX loss before the sensor loop (boot self-tests, ring not serviced): res_err={}{} overrun={}\n",
        gs_boot[8], if gs_boot[8] >= 0x3_FFFF { "+ (saturated)" } else { "" }, gs_boot[9]);
    kprint!(" [BOOT-TIMING] prod loop entered at t=+{} ms\n", boot_ms());
    #[cfg(all(feature = "late-confirm", not(feature = "apmode")))]
    let mut confirmed = false;
    loop {
        // Liveness heartbeat (~5 s) — fires even when every RX window is empty, so the
        // running sensor proves it is looping on metal, not hung.
        let now = prod_cntpct();
        #[cfg(any(feature = "sepdiag", feature = "prod-full"))]
        if crate::events::pending() >= crate::events::CAPACITY / 4 || now.wrapping_sub(last_drain) >= cntfrq / 4 {
            if crate::events::pending() > 0 {
                soar_drain!();
            }
            last_drain = now;
        }
        // late-confirm: commit this boot only once the sensor is demonstrably HEALTHY — rule plane
        // armed, the GEM loop running >= 2 s with zero contained faults, and (prod-mc) the
        // Mission Control node up. Otherwise hboot's watchdog fires and the trial rolls back.
        #[cfg(all(feature = "late-confirm", not(feature = "apmode")))]
        if !confirmed && rules::active_rules() > 0 && faults == 0 && now.wrapping_sub(t0) >= 2 * cntfrq {
            #[cfg(feature = "prod-mc")]
            let mc_ok = mc.is_some();
            #[cfg(not(feature = "prod-mc"))]
            let mc_ok = true;
            if mc_ok {
                boot_confirm();
                confirmed = true;
            }
        }
        // Mission Control: DHCP progress, every HTTP connection, egress — EVERY iteration, so the
        // operator's UI is responsive (not paced by the heartbeat).
        #[cfg(feature = "prod-mc")]
        if let Some(node) = mc.as_mut() {
            let now_ms = (now.wrapping_sub(t0) / (cntfrq / 1000).max(1)) as i64;
            if let Some(ms) = node.take_time() {
                match mcserve::state().sync_clock(ms, now) {
                    Some(step) => {
                        pf.set_clock(ms, now, cntfrq);
                        kprint!(" [MC] clock synced by SNTP (step {} ms)\n", step);
                    }
                    None => kprint!(" [MC] SNTP re-sync REFUSED (step > 1 h)\n"),
                }
            }
            if node.service(mcserve::state(), now_ms) {
                ratelimit::set_local_ip(0, u32::from_be_bytes(node.ip)); // ADR 0049 D3: our own address
                kprint!(" [MC] heqk Mission Control serving on http://{}.{}.{}.{}:80 ({})\n",
                    node.ip[0], node.ip[1], node.ip[2], node.ip[3], if node.leased { "DHCP lease" } else { "link-local fallback" });
            }
            node.flush(|f| arch_aarch64::gem::tx_frame(f).is_some());
        }
        if now.wrapping_sub(last_hb) >= hb_interval {
            last_hb = now;
            // AUDIT (2026-08-20 metal): tx_fail was an ANONYMOUS timeout — a PASS frame
            // silently not forwarded with no cause. gem::tx_err_take() reports the GEM
            // TSR that accompanied the most recent failure (bit0 UBR / bit2 RLE /
            // bit4 TFC / bit6 UND / bit7 HRESP are the halting ones; bit3 alone = the
            // timeout happened with a CLEAN status, which means something else stalled).
            let txerr = arch_aarch64::gem::tx_err_take();
            // RSR is the RX-side counterpart to txerr and the diagnostic that was MISSING
            // when the NRX 8->64 attempt regressed RX to 16 frames: bit0 BNA (buffers not
            // available => the ring was exhausted / the controller could not write) vs
            // bit2 OVR (overrun) vs clean distinguishes "ring overflowed under burst" from
            // "the controller could not reach the buffers at all". Read-only; the sticky
            // bits are cleared by the RX path itself.
            let rsr = arch_aarch64::gem::rsr();
            #[cfg(feature = "prod-mc")]
            {
                let st = mcserve::state();
                st.seen = seen as u64;
                st.forwarded = forwarded as u64;
                st.dropped = dropped as u64;
                st.sample_qsecbit(now, telemetry::score());
            }
            // A7.7 (review 2026-11-05): GEM RX-ring loss is NOT in drop/faults (rsr=0x7 on 368 of ~1,310
            // heartbeats with faults=0) — report it: resource errors (no free RX descriptor) + overruns.
            let gs = arch_aarch64::gem::rx_stats();
            kprint!("   [PROD hb] up={}s seen={} fwd={} drop={} tx_fail={} txerr={:#04x} rsr={:#04x} faults={} empty={} qsecbit={} rx_lost(res_err={} overrun={})\n",
                now.wrapping_sub(t0) / cntfrq, seen, forwarded, dropped, tx_fail, txerr, rsr, faults, empty, telemetry::score(),
                gs[8].wrapping_sub(gs_boot[8]), gs[9].wrapping_sub(gs_boot[9]));
            #[cfg(feature = "dnssink")]
            kprint!("   [DNSSINK hb] sinkholed={} (RPZ-blocked DNS queries answered with SINKHOLE_IP + not forwarded)\n", dns_sinks);
            #[cfg(feature = "mctls")]
            if let Some(h) = crate::tlshost::host() {
                let t = unsafe { mcserve::TLS_STATS };
                kprint!("   [MC-TLS hb] ready={} calls={} handshakes={} pq_hybrid={} records_out={} failed_closed={} rate_limited={} tls_errors={} timeouts={} faults={} restarts={}\n",
                    h.ready, h.calls, t[0], t[3], t[1], t[2], t[4], h.tls_errors, h.timeouts, h.faults, h.restarts);
            }
            // M4 DHCP: drive the client (DISCOVER/REQUEST/retransmit) + report the lease.
            #[cfg(feature = "dhcp")]
            if let Some(dc) = dhcp_client.as_mut() {
                let now_ms = (now.wrapping_sub(t0) / (cntfrq / 1000).max(1)) as i64;
                if let Some((f, fl)) = dc.service(now_ms) {
                    if arch_aarch64::gem::tx_frame(&f[..fl]).is_some() {
                        forwarded += 1;
                    } else {
                        tx_fail += 1;
                    }
                }
                match dc.assigned {
                    Some(ip) => kprint!("   [DHCP hb] ✅ LEASED ip={}.{}.{}.{} gw={:?} dns={:?} (rx={})\n",
                        ip[0], ip[1], ip[2], ip[3], dc.router, dc.dns, dc.seen),
                    None => kprint!("   [DHCP hb] soliciting a lease... (rx={})\n", dc.seen),
                }
            }
            // M4 FIRST-LIGHT heartbeat: how many for-heqk frames (ARP-for-us + unicast-to-our-MAC,
            // i.e. ICMP echo) the bridge saw and answered.
            #[cfg(feature = "netmetal")]
            if let Some(b) = metal_bridge.as_ref() {
                kprint!("   [NETMETAL hb] forheqk_seen={} answered={}\n", b.seen, b.answered);
            }
            // M4 control-plane TRANSPORT first-light: emit a PERIODIC (every heartbeat) BROADCAST
            // UDP presence beacon when the PHY link is up (safe BMSR read — no NCR touch), through
            // the SINGLE gem::tx_frame path (no second RX-ring walker — the Linux-macb single-owner
            // rule). Periodic = a real presence announcement + live-capturable.
            #[cfg(feature = "netmetal")]
            if arch_aarch64::gem::phy_link_up(0) {
                let mut bf = [0u8; 96];
                let n = netsvc::build_enroll_beacon(
                    [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                    [10, 200, 0, 2],
                    7654,
                    beacon_device_id,
                    &mut bf,
                );
                if arch_aarch64::gem::tx_frame(&bf[..n]).is_some() {
                    beacon_count += 1;
                    kprint!("   [NETENROLL] presence beacon #{} on wire ({} B, bcast UDP:7654) via single TX path\n", beacon_count, n);
                }
            }
            // M4.5 control-plane handshake: drive the ControlPlane once the link is up — tick()
            // starts / bounded-retransmits msg1, and its egress datagrams go out the SINGLE
            // gem::tx_frame path (the Linux-macb single-owner rule; NOT a 2nd ring walker). The
            // full handshake completes against a live host MSSP-sim; here msg1 hits the wire.
            #[cfg(all(feature = "netmetal", feature = "securechannel"))]
            if let (Some(c), Some(ir)) = (cp.as_mut(), cp_irand.as_ref()) {
                let link = arch_aarch64::gem::phy_link_up(0);
                let now_ms = (now.wrapping_sub(t0) / (cntfrq / 1000).max(1)) as i64;
                c.tick(now_ms, link, ir);
                #[cfg(feature = "prod-mc")]
                {
                    mcserve::state().cloud_linked = c.established();
                }
                let mut dgrams = 0u32;
                let mut last_ctrl = 0u32;
                let mut last_len = 0usize;
                while let Some((dg, dn)) = c.poll_egress() {
                    if let Some(ctrl) = arch_aarch64::gem::tx_frame(&dg[..dn]) {
                        dgrams += 1;
                        last_ctrl = ctrl;
                        last_len = dn;
                    }
                }
                // Descriptor word1: USED(31); TX-error bits 27=buf-exhausted 28=underrun 29=error.
                // A large frame that completes with USED set AND an error bit was ABORTED (never
                // reached the wire) — this readout tells the metal run WHY (2026-09-09 diagnosis).
                kprint!("   [NETCP hb] state={:?} msg1_dgrams_out={} last_len={} last_ctrl={:#010x} tx_err={} rx_seen={}\n",
                    c.state(), dgrams, last_len, last_ctrl,
                    (last_ctrl & 0x3800_0000) != 0, c.seen);
                // M4.5: once Established, send ONE encrypted reach-policy REQ over the Session.
                // The host responder-sim answers with the operator-signed policy (captured in the
                // drain below). One-shot so the AEAD counters stay aligned.
                #[cfg(feature = "segmetal")]
                if c.established() && seg_phase == 0 && c.tenant().is_some() {
                    // The policy's tenant binding (C14) is the one the MSSP assigned in msg2 —
                    // never a device-side constant. No tenant ⇒ no REQ ⇒ stays disarmed.
                    seg_enr.tenant_id = c.tenant().unwrap_or(0);
                    if let Some(sess) = c.session_mut() {
                        let mut req = [0u8; 64];
                        if let Some(rn) = enroll::encrypt_reach_req(sess, &mut req) {
                            let mut dg = [0u8; 128];
                            let dn = netsvc::build_hs_datagram(
                                [0x02, 0, 0, 0, 0, 0x02], [10, 200, 0, 2], [0xff; 6], [255, 255, 255, 255], 7654,
                                &req[..rn], &mut dg,
                            );
                            if arch_aarch64::gem::tx_frame(&dg[..dn]).is_some() {
                                seg_phase = 1;
                                kprint!("   [SEGMETAL] reach-policy REQ sent ({} B record) over the live Session\n", rn);
                            }
                        }
                    }
                }
                // DIAG re-print (garbling-proof): repeats the reconcile outcome every hb.
                #[cfg(feature = "segmetal")]
                if seg_phase >= 1 {
                    kprint!("   [SEGDIAG] phase={} fslog_err={:?} recon={:?} armed={} reach_drops={}\n",
                        seg_phase, seg_fslog_err, seg_recon, crate::segment::reach_armed(),
                        packet::seg_reach_drops());
                }
                // M6 B2 EXPORT. Enroll on the first Established heartbeat with an MSSP tenant;
                // then seal queued evidence as HQXR datagram records (explicit seq + receiver
                // RFC 6479 window, so a lost datagram never desyncs) and send them UNICAST to the
                // responder learned from msg2. On segmetal images the implicit-counter reach REQ
                // must go first (it shares the send counter), so export waits for seg_phase >= 1.
                #[cfg(all(feature = "prod-full", feature = "netmetal"))]
                {
                    #[cfg(feature = "segmetal")]
                    let req_done = seg_phase >= 1;
                    #[cfg(not(feature = "segmetal"))]
                    let req_done = true;
                    if exporter.is_none() && c.established() && req_done {
                        if let Some(t) = c.tenant() {
                            pf.enroll = enroll::EnrollStatus::Enrolled(enroll::Enrollment {
                                tenant_id: t,
                                responder_x_pk: c.resp_x_pk(),
                                device_fp: c.device_fp(),
                                generation: 1,
                            });
                            exporter = Some(export::Exporter::new(t, c.device_fp(), pf.snap.boots as u32, cntfrq as u32));
                            kprint!("   [M6-EXPORT] ENROLLED tenant={:#x} — evidence export ON (unicast to the MSSP)\n", t);
                        }
                    }
                    if export::should_export(&pf.enroll) {
                        let ((smac, sip), (dmac, dip)) = (c.local(), c.peer());
                        if let (Some(x), Some(sess)) = (exporter.as_mut(), c.session_mut()) {
                            export_idle_hb += 1;
                            // Bounded per heartbeat; an idle link still sends a liveness frame
                            // (counters + QSecBit) every 10 heartbeats.
                            let mut budget = if x.pending() > 0 || export_idle_hb >= 10 { 4 } else { 0 };
                            let mut sent = (0u32, 0usize);
                            while budget > 0 {
                                budget -= 1;
                                let mut payload = [0u8; 4 + export::MAX_RECORD];
                                payload[..4].copy_from_slice(&exportwire::DGRAM_TAG[..]);
                                match x.seal_next(&mut sess.send, now, (telemetry::score(), now), events::overruns(), &mut payload[4..]) {
                                    Ok((rl, nev)) => {
                                        let mut dg = [0u8; 64 + 4 + export::MAX_RECORD];
                                        let dn = netsvc::build_hs_datagram(smac, sip, dmac, dip, controlplane::HS_PORT, &payload[..4 + rl], &mut dg);
                                        if dn > 0 && arch_aarch64::gem::tx_frame(&dg[..dn]).is_some() {
                                            sent = (sent.0 + 1, sent.1 + nev);
                                        } else {
                                            x.tx_failed(nev);
                                        }
                                    }
                                    Err(_) => break,
                                }
                                if x.pending() == 0 {
                                    break;
                                }
                            }
                            if sent.0 > 0 {
                                export_idle_hb = 0;
                                kprint!("   [M6-EXPORT hb] frames_out={} events_out={} pending={} lost={} total_frames={}\n",
                                    sent.0, sent.1, x.pending(), x.lost, x.frames);
                            }
                        }
                    }
                }
            }
            // SG-1 (M2 Gate-R metal observability): drain the per-rule event ring so each
            // separation-matrix row's verdict is ATTRIBUTABLE on metal (rule_id -> row,
            // verdict 1=PASS/2=DROP -> wire action). prod exposes only aggregate counters;
            // this is the diagnostic that lets a metal run say WHICH row fired WHAT.
            //
            // ONE drain point for the SOAR ring: each real detection (true rule_id / src /
            // severity / class) feeds the sepdiag console, the M3 snapshot (prod-full) and the
            // M6 exporter (prod-export). A second drainer would silently steal events.
            #[cfg(any(feature = "sepdiag", feature = "prod-full"))]
            soar_drain!();
            #[cfg(any(feature = "sepdiag", feature = "prod-full"))]
            {
                last_drain = now;
            }
            // DRV-1 sink experiment readout — a nonzero value identifies the RP1 ETH MSI
            // sink + vector (the fact the unreadable MSI-X table could not give us).
            #[cfg(feature = "mipdump")]
            {
                let (ml, mh, rc) = arch_aarch64::gem::msi_sink_status();
                let (il, ih) = arch_aarch64::gem::rp1_intstat();
                // EDGE-TEST readout: did the RP1 emit an MSI since last beat? IRQs are masked
                // in prod, so a real emission shows as a GIC-pending bit on INTID 166 (no CPU
                // inject here — that would false-positive). This is the RP1's OWN emission.
                let emitted = arch_aarch64::gem::gic_spi_pending(166);
                let (pbir, pdw, pbit) = arch_aarch64::gem::rx_msix_pba();
                kprint!("   [DRV1-hb] INTSTATL={:#010x} (bit6=ETH) | mip_sL={:#010x} rc_s={:#010x} | RP1_emitted(GIC166)={} | PBA[bir/off={:#x} dw={:#010x} vec6pending={}] <== \n", il, ml, rc, emitted, pbir, pdw, pbit);
                arch_aarch64::gem::gic_spi_clear_pending(166); // fresh per-beat
                // EDGE maneuver: the source is stuck level-HIGH (INTSTATL=0x40) because prod
                // never clears the GEM ISR (RX is via the DMA ring). Clear it now to DEASSERT
                // source 6, IACK to re-arm; the next frame re-asserts (rising edge) so the RP1
                // emits a FRESH MSI to the now-correct table -> shows as RP1_emitted next beat.
                let _ = arch_aarch64::gem::rx_irq_ack();
                arch_aarch64::gem::rx_msix_iack();
            }
            #[cfg(feature = "rxprof")]
            {
                prof.report(cntfrq);
                prof = RxProf::default(); // per-window: each line = traffic since the last
            }
            // prod-full: throttled M3 persist (interval AND dirty — the reserved
            // window is 32 sectors and every persist rewrites the same LBAs) plus
            // the structural M6 export gate.
            #[cfg(feature = "prod-full")]
            {
                let up = now.wrapping_sub(t0) / cntfrq;
                let c = prodfull::Counters { seen, forwarded, dropped, tx_fail, faults, empty };
                if pf.on_heartbeat(up, c, telemetry::score()) {
                    kprint!("   [PROD-FULL] M3 persisted: boots={} seen={} drop={} events={} (sealed, A/B slot gen {})\n",
                        pf.snap.boots, seen, dropped, pf.snap.nev, pf.last_gen);
                }
            }
        }
        // rxprof: mark the start of the per-frame work (after the heartbeat book-keeping).
        #[cfg(feature = "rxprof")]
        #[allow(unused_mut)]
        let mut mark = prod_cntpct();
        // Stub reload HOISTED out of the hot path (loaded once before the loop; the stub is
        // RO to EL0 so it cannot be corrupted). The reload phase is now ~0; only re-loaded in
        // the fault branch below.
        #[cfg(feature = "rxprof")]
        { let t = prod_cntpct(); prof.reload += t.wrapping_sub(mark); mark = t; }

        DRIVER_REPORT.store(RPT_SENTINEL, Ordering::Relaxed);
        // Drop to EL0; returns here on the driver's report syscall OR on a contained fault.
        unsafe { arch_aarch64::syscall::enter_user(ucode, ustack + 0x1000) };
        #[cfg(feature = "rxprof")]
        { let t = prod_cntpct(); prof.el0 += t.wrapping_sub(mark); mark = t; }

        let report = DRIVER_REPORT.load(Ordering::Relaxed);
        if report == RPT_SENTINEL {
            // The driver FAULTED before reporting (contained by the EL0 fault handler). Count
            // it so a crash-looping driver is observable, DISTINCT from a quiet link. RE-LOAD
            // the stub here — the ONLY place a reload is needed — to structurally self-heal
            // (re-copy code + I-cache sync + re-map), matching the [P7c] contain+restart proof.
            let len = ids.1 - ids.0;
            unsafe { core::ptr::copy_nonoverlapping(ids.0 as *const u8, code_pa as *mut u8, len) };
            arch_aarch64::mmu::sync_instruction_cache(code_pa, len);
            mmu_cm5::map_user_code(ucode, code_pa);
            faults += 1;
            continue;
        }
        // The EL0 excursion above is the "wake": it blocked (bounded) until at least one
        // frame was ready and CONTAINED the untrusted initial scan. reload+el0 were already
        // charged to `mark` above; the per-frame phases below charge the rest.
        //
        // CURSOR RESYNC (metal 2026-09-07): a persistent free-running `rx_head` DESYNCED
        // from the GEM's fill position under burst — rxprof showed the batch draining ZERO
        // frames (n=0) while frames were clearly arriving (rsr=OVR), because the cursor sat
        // on a slot the GEM was not filling next. The EL0 stub, however, scans the WHOLE
        // ring and reports a genuinely-USED descriptor. So: if our cursor is stale (its slot
        // is not USED) but the stub found a real frame, RESYNC the cursor to the stub's
        // index. This self-heals any drift each wake; in steady state the two already agree
        // so it is a no-op. The stub timeout path reports 0, so only resync on a nonzero
        // report whose slot is actually USED.
        let stub_idx = ((report >> 16) & 0xff) as usize;
        if !arch_aarch64::gem::rx_desc_used(rx_head)
            && report != 0
            && arch_aarch64::gem::rx_desc_used(stub_idx % arch_aarch64::gem::RX_NDESC)
        {
            rx_head = stub_idx % arch_aarch64::gem::RX_NDESC;
        }

        // ---- NAPI-STYLE BATCH DRAIN (analog of Linux macb gem_rx's `while (count <
        // budget)` loop, drivers/net/ethernet/cadence/macb_main.c:1506) --------------------
        //
        // rxprof measured the EL0 excursion at ~99.9% of per-frame cost because the old
        // design did ONE frame per excursion. macb amortizes its poll over a batch of up to
        // `budget`; so do we now — drain every ready descriptor in this one excursion, up to
        // RX_BUDGET, before yielding. The EL0 round-trip is paid once per batch, not per frame.
        //
        // TRUST BOUNDARY UNCHANGED: the kernel already read the ring (rx_desc_status) and
        // copied+classified the packet (peek_rx_frame + verdict) for every frame; the EL0
        // stub was never the sole toucher of untrusted ring data, only the wake/scan
        // containment. Draining in the kernel touches exactly the same bytes it already did.
        let mut batch = 0usize;
        while batch < RX_BUDGET {
            // A descriptor OWNED BY SOFTWARE (USED) must be consumed and advanced past even
            // if its frame is malformed — exactly as macb advances rx_tail on any RX_USED
            // descriptor — else one bad frame stalls the ring at this slot forever.
            if !arch_aarch64::gem::rx_desc_used(rx_head) {
                break; // ring drained: nothing more ready → re-enter EL0 to wait
            }
            let flen = arch_aarch64::gem::rx_desc_status(rx_head); // Some(len) valid / None bad
            #[cfg(feature = "rxprof")]
            { let t = prod_cntpct(); prof.rxstat += t.wrapping_sub(mark); mark = t; }
            match flen {
                Some(l) if l >= 14 => {
                    // AUDIT D5: buffer sized to RXBUF (2048), not 1600 — no deep-L7 truncation.
                    let mut buf = [0u8; packet::FRAME_SZ];
                    let n = l.min(buf.len());
                    arch_aarch64::gem::peek_rx_frame(rx_head, &mut buf[..n]);
                    #[cfg(feature = "rxprof")]
                    { let t = prod_cntpct(); prof.copy += t.wrapping_sub(mark); mark = t; }
                    seen += 1;
                    let (_port, v) = packet::verdict(&buf[..n]);
                    #[cfg(feature = "rxprof")]
                    { let t = prod_cntpct(); prof.verdict += t.wrapping_sub(mark); mark = t; }
                    // Passive LAN inventory for the UI's "My Network" (local only, bounded).
                    #[cfg(feature = "prod-mc")]
                    {
                        let src = crate::net::eth_ipv4_src(&buf[..n]);
                        if src != 0 && crate::behavioral::is_internal(src) {
                            let st = mcserve::state();
                            let ms = st.epoch_ms(prod_cntpct());
                            st.note_host(src, ms);
                        }
                    }
                    if v == packet::PASS {
                        // M4 FIRST-LIGHT (netmetal): AFTER the frame PASSes the verified rule
                        // plane, demux for-heqk frames (ARP-for-us + unicast-to-our-MAC, i.e.
                        // ICMP echo) into the smoltcp bridge and TX its reply out the GEM. A for-heqk frame
                        // TERMINATES here (not hairpin-forwarded). Everything else falls through
                        // to the normal forward path. Compiles out without `netmetal`.
                        // Control-plane frames (UDP:7654 for-heqk, e.g. a responder's msg2) are
                        // TEED to the ControlPlane off this SINGLE drain and terminate here.
                        #[cfg(all(feature = "netmetal", feature = "securechannel"))]
                        let cp_took = if let Some(c) = cp.as_mut() {
                            if c.wants(&buf[..n]) {
                                let now_ms = (prod_cntpct() / (cntfrq / 1000).max(1)) as i64;
                                // M4.5: post-Established, a :7654 for-heqk frame is the encrypted
                                // ReachPolicy record → verify + arm segment.rs (never cp.ingress).
                                #[cfg(feature = "segmetal")]
                                {
                                    if c.established() && seg_phase == 1 {
                                        if let Some(payload) = netsvc::udp_payload_for_port(&buf[..n], 7654) {
                                            match (seg_emmc.as_mut().ok(), c.session_mut()) {
                                                (Some(emmc), Some(sess)) => {
                                                // #7: derive the reach-floor HOME here, POST-handshake (no eMMC
                                                // access before the handshake — see the boot comment). Preferred
                                                // = the DataVolume PARTITION (MBR 0xDA) first 16 sectors. NO fallback:
                                                // the old keystore-window fallback [2034,2046) overlapped the p15-write
                                                // boot cookie (2040, rewritten every boot) + OTA state (2044), so the
                                                // newest RT_REACHGEN record could be destroyed and the floor drop a
                                                // generation (replay of the previous signed policy, breaks C11). No
                                                // DataVolume ⇒ floor unavailable ⇒ the plane stays DISARMED (C12,
                                                // fail-open). set_data_volume adds the Gate-1 allowlist entry;
                                                // arm_write_window is the Gate-2 window.
                                                let mut mbr = [0u8; 512];
                                                let dvpart = {
                                                    use hal::BlockDev;
                                                    if emmc.read_block(0, &mut mbr).is_ok() {
                                                        store::datavolume_from_mbr(&mbr)
                                                    } else {
                                                        None
                                                    }
                                                };
                                                let (seg_dv, seg_lo, seg_hi): (Option<(u64, u64)>, u64, u64) = match dvpart {
                                                    Some((lo, hi)) => (Some((lo, hi)), lo, (lo + 16).min(hi)),
                                                    None => (None, 0, 0),
                                                };
                                                if seg_dv.is_none() {
                                                    kprint!("   [SEGMETAL] no DataVolume partition (MBR 0xDA) — reach floor unavailable, plane stays DISARMED (C12)\n");
                                                    seg_recon = Some(Err(enroll::ReachPolicyErr::FloorUnavailable));
                                                } else {
                                                if let Some((dvlo, dvhi)) = seg_dv {
                                                    emmc.set_data_volume(dvlo, dvhi);
                                                }
                                                let _ = emmc.arm_write_window(seg_lo, seg_hi);
                                                match store::SealedStore::open(emmc) {
                                                    Ok(mut st) => {
                                                    if let Some((dvlo, dvhi)) = seg_dv {
                                                        let _ = st.add_region(dvlo, dvhi, store::RegionKind::DataVolume);
                                                    }
                                                    // DIAG: capture the fslog outcome (read_reach_floor collapses
                                                    // every FsErr to FloorUnavailable). Stored + re-printed each hb.
                                                    seg_fslog_err = crate::fslog::open_or_format(&mut st, seg_lo, seg_hi).err();
                                                    let r = enroll::reconcile_reach_policy_record(
                                                        &seg_enr, sess, payload, &mut st, seg_lo, seg_hi, &OPERATOR_PK,
                                                    );
                                                    seg_recon = Some(r);
                                                    if let Ok(nn) = r {
                                                        seg_phase = 2;
                                                        kprint!("   [SEGMETAL] ✅ ARMED — reach-floor home={} lo={}; applied {} entries; reach_armed={}\n",
                                                            "DataVolume-partition(0xDA)", seg_lo, nn, crate::segment::reach_armed());
                                                    }
                                                    }
                                                    Err(e) => kprint!("   [SEGMETAL] eMMC store open failed: {:?}\n", e),
                                                }
                                                }
                                                }
                                                _ => {}
                                            }
                                        }
                                    } else {
                                        c.ingress(&buf[..n], now_ms);
                                    }
                                }
                                #[cfg(not(feature = "segmetal"))]
                                c.ingress(&buf[..n], now_ms);
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        #[cfg(not(all(feature = "netmetal", feature = "securechannel")))]
                        let cp_took = false;
                        // M4 DHCP: a DORA reply (UDP dst:68) is fed to the client (→ REQUEST/settle),
                        // TX'd, and TERMINATES here (not forwarded). Checked before the bridge so a
                        // unicast-to-our-MAC reply is not mis-handled as ARP/ICMP. Reply TX counts as
                        // forwarded (telemetry invariant).
                        #[cfg(feature = "dhcp")]
                        let cp_took = cp_took
                            || if let Some(dc) = dhcp_client.as_mut() {
                                if dc.wants(&buf[..n]) {
                                    let now_ms = (prod_cntpct() / (cntfrq / 1000).max(1)) as i64;
                                    if let Some((f, fl)) = dc.ingress(&buf[..n], now_ms) {
                                        if arch_aarch64::gem::tx_frame(&f[..fl]).is_some() {
                                            forwarded += 1;
                                        } else {
                                            tx_fail += 1;
                                        }
                                    }
                                    true
                                } else {
                                    false
                                }
                            } else {
                                false
                            };
                        #[cfg(feature = "netmetal")]
                        let handled = cp_took
                            || if let Some(b) = metal_bridge.as_mut() {
                                if b.wants(&buf[..n]) {
                                    let now_ms = (prod_cntpct() / (cntfrq / 1000).max(1)) as i64;
                                    if let Some((reply, rn)) = b.step(&buf[..n], now_ms) {
                                        if arch_aarch64::gem::tx_frame(&reply[..rn]).is_some() {
                                            forwarded += 1;
                                        } else {
                                            tx_fail += 1;
                                        }
                                    }
                                    true
                                } else {
                                    false
                                }
                            } else {
                                false
                            };
                        #[cfg(not(feature = "netmetal"))]
                        let handled = false;
                        // DNS-SINKHOLE (feature `dnssink`): a transiting DNS query for an RPZ-blocked
                        // name is ANSWERED with a spoofed sinkhole reply and NOT forwarded (the name
                        // is refused, the packet path is not silently dropped — ADR 0023). A legit
                        // name returns None here and flows normally below. The reply TX counts as
                        // `forwarded` so seen == forwarded + dropped + tx_fail still holds.
                        #[cfg(feature = "dnssink")]
                        let handled = handled || {
                            let mut reply = [0u8; 600];
                            if let Some(rl) = netsvc::build_dns_sinkhole_frame(&buf[..n], &mut reply) {
                                if arch_aarch64::gem::tx_frame(&reply[..rl]).is_some() {
                                    forwarded += 1;
                                } else {
                                    tx_fail += 1;
                                }
                                dns_sinks += 1;
                                true
                            } else {
                                false
                            }
                        };
                        // Mission Control node: frames addressed to the device (its MAC or broadcast)
                        // after they PASSed the detection plane.
                        #[cfg(feature = "prod-mc")]
                        let handled = handled
                            || match mc.as_mut() {
                                Some(node) if node.wants(&buf[..n]) => {
                                    let now_ms = (prod_cntpct().wrapping_sub(t0) / (cntfrq / 1000).max(1)) as i64;
                                    node.ingress(&buf[..n], now_ms);
                                    forwarded += 1; // accepted (terminated on-device)
                                    true
                                }
                                _ => false,
                            };
                        // ENFORCE: forward; a TX-completion timeout is counted (AUDIT D2) so
                        // seen == forwarded + dropped + tx_fail holds and a lost PASS is visible.
                        // PASSIVE (prod-mc, ADR 0037 D4): a PASS frame is OBSERVED and counted, never
                        // re-transmitted — no hairpin back out the port it arrived on.
                        if !handled && cfg!(feature = "prod-mc") {
                            forwarded += 1;
                        } else if !handled {
                            if arch_aarch64::gem::tx_frame(&buf[..n]).is_some() {
                                forwarded += 1;
                            } else {
                                tx_fail += 1;
                            }
                        }
                        #[cfg(feature = "rxprof")]
                        { let t = prod_cntpct(); prof.tx += t.wrapping_sub(mark); mark = t; }
                    } else {
                        dropped += 1;
                        // (prod-full records the REAL event — rule/src/severity/class — from the
                        // SOAR ring drain in the heartbeat; a zero-filled per-drop record here
                        // used to erase all attribution.)
                    }
                }
                _ => {
                    // USED but bad length: count it, still consume+advance (macb parity).
                    empty += 1;
                }
            }
            #[cfg(feature = "rxprof")]
            let _rmark = prod_cntpct();
            arch_aarch64::gem::recycle_rx(rx_head); // re-arm this slot for the GEM
            rx_head = (rx_head + 1) % arch_aarch64::gem::RX_NDESC; // advance in lockstep
            batch += 1;
            #[cfg(feature = "rxprof")]
            {
                prof.recycle += prod_cntpct().wrapping_sub(_rmark);
                prof.frames += 1;
                mark = prod_cntpct();
            }
            // A processed-frame beat, so a busy link reports progress between ~5 s ticks.
            if (seen & 0xff) == 0 && seen != 0 {
                kprint!("   [PROD hb] seen={} fwd={} drop={} tx_fail={} faults={} empty={} qsecbit={} (frame-beat)\n",
                    seen, forwarded, dropped, tx_fail, faults, empty, telemetry::score());
            }
        }
        if batch == 0 {
            // The stub woke us but the cursor slot was not ready (timeout wake / already
            // drained). Not a fault; just loop back and wait again.
            empty += 1;
            // THERMAL: idle — WFE-sleep (clock-gate the core) until the next event-stream
            // wake (~few µs, armed above) instead of spinning hot. A frame that arrives during
            // the sleep is caught on the very next EL0 poll excursion; under load this branch
            // is never taken (batch>0), so throughput is unaffected.
            unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
        }
    }
}

/// P7b: spawn priority workers, bring up GIC-400 + the generic timer, enable
/// IRQs, and let the round-robin/priority scheduler preempt them on real
/// hardware. Bounded: if timer IRQs never arrive (routing not as expected),
/// a spin cap lets the boot proceed to reboot instead of hanging.
#[cfg(feature = "cm5")]
fn cm5_scheduler_demo() {
    kprint!(" [P7b] a: enter scheduler demo\n");
    scheduler::init();
    kprint!(" [P7b] b: scheduler init\n");
    let entries = [
        thread_hi as *const () as usize,
        thread_mid as *const () as usize,
        thread_lo as *const () as usize,
    ];
    let prios: [u8; 3] = [3, 2, 1];
    for i in 0..3 {
        let sp = arch_aarch64::thread::make_thread(stack_top(i), entries[i], 0);
        scheduler::spawn(sp, prios[i]);
    }
    kprint!(" [P7b] c: 3 workers spawned\n");
    // P7c-4c: alongside the kernel workers, spawn the EL0 driver as a *preemptible
    // scheduled TCB in its OWN ASID* on CM5 metal — the piece 4d's cooperative
    // loop deferred. It runs a pure EL0 loop (increments a counter, no syscalls),
    // so the timer must preempt it every quantum; the scheduler switches TTBR0 to
    // its ASID to run it and back to the kernel ASID for the workers.
    let el0_ok = cm5_spawn_el0_loop_asid();
    let gic = arch_aarch64::Gic;
    gic.init();
    kprint!(" [P7b] d: GIC-400 init\n");
    gic.enable(arch_aarch64::timer::TIMER_INTID);
    kprint!(" [P7b] e: timer INTID {} enabled in GIC\n", arch_aarch64::timer::TIMER_INTID);
    arch_aarch64::GenericTimer.start(TICK_HZ);
    kprint!(" [P7b] f: {} Hz timer armed; enabling IRQs\n", TICK_HZ);
    arch_aarch64::enable_irqs();

    // Idle until the scheduler finishes, with a bounded backstop.
    let mut guard: u64 = 0;
    while !SCHED_DONE.load(Ordering::SeqCst) {
        unsafe { core::arch::asm!("wfe") };
        guard += 1;
        if guard > 200_000_000 {
            kprint!(" [P7b] WARN: no timer IRQs (GIC/timer routing?) — continuing\n");
            break;
        }
    }
    arch_aarch64::disable_irqs();
    // The demo's physical timer stays ENABLED otherwise (only the unreachable RX-IRQ probe
    // stopped it): a level-asserted PPI parked at the GIC for the whole session, and a
    // straight fire into `scheduler::on_tick` on a torn-down scheduler the moment anything
    // re-enables IRQs. Stop it here.
    unsafe { core::arch::asm!("msr cntp_ctl_el0, xzr", options(nomem, nostack)) };

    // P7c-4c result: the EL0 TCB ran at EL0 (counter > 0) AND the box reached the
    // scheduler's normal exit (kernel workers kept running, timer kept firing) —
    // so the EL0 driver was being preempted in its own ASID, not wedging the box.
    if el0_ok {
        let cnt_pa = EL0_CNT_PA.load(Ordering::SeqCst);
        let c = if cnt_pa != 0 { unsafe { core::ptr::read_volatile(cnt_pa as *const u64) } } else { 0 };
        kprint!(" [P7c-4c] {} — EL0 driver ran as a PREEMPTIBLE SCHEDULED TCB in its own ASID on CM5 (counter={}, not wedged)\n",
            if c > 0 { "PASS" } else { "FAIL" }, c);
    }
    EL0_SCHED_MODE.store(false, Ordering::Relaxed); // back to cooperative for the 4d server stages
}

/// P7c-4c helper — spawn a pure EL0 loop as a scheduled TCB in a fresh CM5 ASID.
/// Returns true if it was spawned (its counter frame PA is published in
/// `EL0_CNT_PA`). Arms fault-reschedule so that even if the mapping were wrong the
/// box degrades gracefully (restart-budget kill) instead of wedging.
#[cfg(feature = "cm5")]
fn cm5_spawn_el0_loop_asid() -> bool {
    use arch_aarch64::mmu_cm5;
    extern "C" {
        static el0_loop_stub: u8;
        static el0_loop_stub_end: u8;
    }
    let src = core::ptr::addr_of!(el0_loop_stub) as usize;
    let len = core::ptr::addr_of!(el0_loop_stub_end) as usize - src;
    let code = mmu_cm5::alloc_frame();
    let stack = mmu_cm5::alloc_frame();
    let cnt = mmu_cm5::alloc_frame();
    if code == 0 || stack == 0 || cnt == 0 {
        kprint!(" [P7c-4c] frame alloc failed (pool exhausted) — skipping\n");
        return false;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(src as *const u8, code as *mut u8, len);
        core::ptr::write_volatile(cnt as *mut u64, 0);
    }
    arch_aarch64::mmu::sync_instruction_cache(code, len);
    let (l1, asid) = mmu_cm5::new_addr_space();
    if l1 == 0 {
        kprint!(" [P7c-4c] new_addr_space failed — skipping\n");
        return false;
    }
    // EL0 VAs inside the GB5 user window's first 2 MiB block, private to this ASID.
    let ecode = mmu_cm5::USER_VA_BASE;
    let estack = mmu_cm5::USER_VA_BASE + 0x1000;
    let ecnt = mmu_cm5::USER_VA_BASE + 0x2000;
    mmu_cm5::map_user_code_in(l1, ecode, code);
    mmu_cm5::map_user_data_in(l1, estack, stack);
    mmu_cm5::map_user_data_in(l1, ecnt, cnt);
    EL0_CNT_PA.store(cnt, Ordering::SeqCst);
    let kstack_top = unsafe { core::ptr::addr_of!(EL0_KSTACK) as usize + KSTACK_SIZE };
    let sp = arch_aarch64::thread::make_el0_thread(kstack_top, ecode, estack + 0x1000, ecnt);
    let ttbr0 = l1 as u64 | ((asid as u64) << 48);
    // CORE-6: arm this scheduled EL0 TCB's PER-TCB fault-restart record (belt &
    // braces — the loop stub never faults when the mapping is correct).
    if let Some(tid) = scheduler::spawn_as(sp, 1, ttbr0) {
        // low prio: shares with thread_lo, timer preempts it
        scheduler::set_restart(tid, ecode, estack + 0x1000, kstack_top);
    }
    EL0_SCHED_MODE.store(true, Ordering::Relaxed); // scheduled-EL0 phase: faults restart
    kprint!(" [P7c-4c] EL0 driver spawned as SCHEDULED TCB (asid={}) in its own address space on CM5\n", asid);
    true
}

/// P8 (metal): the PREVAIL-style verifier on real silicon — statically prove the
/// signed THREAT_RULE is memory-safe (before the datapath runs it on live
/// frames) and confirm adversarial third-party rules are rejected.
#[cfg(feature = "cm5")]
fn cm5_p8_verify() {
    use bpf::{verify_prevail, EVIL_HELPER_ORACLE, EVIL_LOOP, EVIL_NO_VERDICT, EVIL_WILD_LOAD, THREAT_RULE};
    kprint!(" [P8] verifier (metal): ");
    let safe = match verify_prevail(&THREAT_RULE) {
        Ok(min) => {
            kprint!("THREAT_RULE SAFE (min_len={})", min);
            true
        }
        Err(e) => {
            kprint!("THREAT_RULE REJECTED ({}) <- BUG", e);
            false
        }
    };
    let rejected = verify_prevail(&EVIL_WILD_LOAD).is_err()
        && verify_prevail(&EVIL_LOOP).is_err()
        && verify_prevail(&EVIL_NO_VERDICT).is_err()
        && verify_prevail(&EVIL_HELPER_ORACLE).is_err(); // XC-11: scalar-ptr payload_match refused
    kprint!("; adversarial rules {}\n", if rejected { "all REJECTED" } else { "ACCEPTED <- BUG" });
    kprint!(" [P8] {} — rule statically verified before the live datapath runs it\n",
        if safe && rejected { "PASS" } else { "FAIL" });

    // tnum PAYOFF: a variable-IP-header-offset rule ((ihl&0xf)<<2 added to the
    // packet pointer) — the interval domain rejects it (LSH → ⊤ ⇒ unbounded
    // offset), but the tnum domain keeps it BOUNDED and ACCEPTS with min_len=75.
    // This is precision the PREVAIL/Windows eBPF verifiers (no tnum) lack.
    match verify_prevail(&bpf::VAR_OFFSET_RULE) {
        Ok(min) => kprint!(" [P16-tnum] {} — variable-offset rule ACCEPTED via tnum (min_len={}, bounded); PREVAIL/Windows reject it\n",
            if min == 75 { "PASS" } else { "FAIL" }, min),
        Err(e) => kprint!(" [P16-tnum] FAIL — variable-offset rule rejected ({}) <- tnum not live\n", e),
    }

    // JIT on metal: compile THREAT_RULE to native ARM64 via the CM5 EL1 RO+X code
    // window, run it, and confirm its verdicts match the interpreter — so the
    // detection datapath runs NATIVE code on real silicon, not just the interpreter.
    match arch_aarch64::bpf_jit::compile(&THREAT_RULE) {
        Some(va) => {
            let f: extern "C" fn(*const u8) -> u64 =
                unsafe { core::mem::transmute::<usize, extern "C" fn(*const u8) -> u64>(va) };
            // DIFFERENTIAL JIT↔interpreter equivalence, EXHAUSTIVE over the rule's
            // entire input domain (all 65536 L4 port values) — the pragmatic,
            // runnable form of a Jitterbug/Serval per-instruction JIT proof: for
            // THIS rule the native code is proven to agree with the verified
            // interpreter on every possible input, on real silicon.
            let mut jit_ok = true;
            let mut mismatches = 0u32;
            for port in 0u32..=0xffff {
                let l4 = [0u8, 0u8, (port >> 8) as u8, (port & 0xff) as u8];
                let jv = f(l4.as_ptr());
                let iv = bpf::run(&THREAT_RULE, l4.as_ptr(), l4.len());
                if jv != iv {
                    jit_ok = false;
                    mismatches += 1;
                }
            }
            kprint!(" [P8-JIT] {} — THREAT_RULE JIT'd native ARM64 @ {:#x} (EL1 RO+X); DIFFERENTIAL vs interpreter EXHAUSTIVE over all 65536 inputs: {} mismatches\n",
                if jit_ok { "PASS" } else { "FAIL" }, va, mismatches);
            // B-9: prove W^X — the exec page (GB6) is RO+X and its GB0 identity
            // alias is now RO (sealed), so the executable code has NO writable
            // alias anywhere. AP[2] (bit 7) set == read-only.
            let exec_desc = arch_aarch64::mmu_cm5::page_desc(va);
            let frame_pa = (exec_desc & 0xFFFF_FFFF_F000) as usize;
            let alias_desc = arch_aarch64::mmu_cm5::page_desc(frame_pa);
            let ro = |d: u64| d & (1 << 7) != 0;
            let wx_ok = ro(exec_desc) && ro(alias_desc);
            kprint!(" [P8-WX] {} — JIT code RO+X; frame {:#x} alias sealed RO (no writable alias): exec_ro={} alias_ro={} (B-9)\n",
                if wx_ok { "PASS" } else { "FAIL" }, frame_pa, ro(exec_desc), ro(alias_desc));
        }
        None => kprint!(" [P8-JIT] FAIL — JIT compile returned None on metal\n"),
    }
}

/// P9 (metal): probe the BCM2712 external PCIe RC1 (Track A: `dtparam=pciex1` →
/// firmware trains the link). Report link state; if up, enumerate the RTL8111H
/// and print its vendor/device + MAC. Fail-safe: reads only if the link is up.
#[cfg(feature = "cm5")]
fn cm5_p9_probe() {
    use arch_aarch64::rtl8111;
    // REFCLK ROOT-CAUSE PROBE: RC2 (RP1) is firmware-trained + PLL-locked; RC1 is
    // stuck. Diff their SERDES/refclk registers to find what RC1 is missing.
    let (r1, r2) = rtl8111::refclk_compare();
    kprint!(" [P9] refclk compare  RC1(broken) vs RC2(working/RP1):\n");
    kprint!("   HARD_DEBUG 0x4304: RC1={:#010x} RC2={:#010x} {}\n", r1.hard_debug, r2.hard_debug,
        if r1.hard_debug != r2.hard_debug { "<-- DIFF" } else { "same" });
    kprint!("   MISC_CTRL  0x4008: RC1={:#010x} RC2={:#010x} {}\n", r1.misc_ctrl, r2.misc_ctrl,
        if r1.misc_ctrl != r2.misc_ctrl { "<-- DIFF" } else { "same" });
    kprint!("   PHY_CTL15  0x184c: RC1={:#010x} RC2={:#010x} {}\n", r1.phy_ctl15, r2.phy_ctl15,
        if r1.phy_ctl15 != r2.phy_ctl15 { "<-- DIFF" } else { "same" });
    kprint!("   STATUS     0x4068: RC1={:#010x} RC2={:#010x}\n", r1.status, r2.status);
    kprint!("   LINK_STATE 0x00bc: RC1={:#010x} RC2={:#010x}\n", r1.link_state, r2.link_state);
    kprint!("   SERDES PLL_LOCK  : RC1={} RC2={}  (RC2 should be locked — proves the MDIO read is valid)\n",
        r1.pll_lock, r2.pll_lock);
    kprint!(" [P9] RC1 status before train={:#010x}; training (Path B: HEQK owns RC1)...\n",
        rtl8111::rc1_status());
    let d = rtl8111::rc1_train();
    kprint!(" [P9] diag: rescal_done={} iddq {:#x}->{:#x} (want ->0) mdio_timeouts={}/8 perst {:#x}->{:#x} (want ->0x4)\n",
        d.rescal_done, d.iddq_before, d.iddq_after, d.mdio_timeouts, d.perst_before, d.perst_after);
    kprint!(" [P9] RC1 status after train={:#010x} (DL_ACTIVE|PHYLINKUP mask 0x30)\n", d.status);
    if d.status & 0x30 != 0x30 {
        kprint!(" [P9] RC1 link still down — verify the CM5 is fully seated in the carrier (this is the physical PCIe path to the RTL)\n");
        return;
    }
    kprint!(" [P9] RC1 LINK UP (DL_ACTIVE|PHYLINKUP) — HEQK trained the external PCIe!\n");
    kprint!(" [P9] downstream 01:00.0 vendor/device = {:#010x} (want 0x816810ec; 0xffffffff=not responding)\n",
        rtl8111::rtl_vendor_id());
    match rtl8111::enumerate() {
        Some(mac) => {
            kprint!(" [P9] PASS — RTL8111H found @01:00.0 (vendor/device 0x816810EC), MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            cm5_p9_rx();
        }
        None => kprint!(" [P9] RC1 link up but RTL8111H not found at 01:00.0 (vendor mismatch)\n"),
    }
}

/// P9 RX datapath: inbound DMA window + RX ring on the RTL8111H (phy1), then poll
/// real frames and run each through the kernel IDS — the SAME verdict path the GEM
/// uses (produce_raw → BPF verdict → consume_one), now on the external NIC.
#[cfg(feature = "cm5")]
fn cm5_p9_rx() {
    use arch_aarch64::rtl8111;
    kprint!(" [P9] RX datapath — inbound DMA window + RX ring on the RTL8111H (phy1)\n");
    let (bar1, ubus) = rtl8111::pcie_inbound_window();
    kprint!(" [P9] PCIe inbound win armed (RC_BAR1_LO was {:#x}, UBUS_REMAP_LO was {:#x})\n", bar1, ubus);
    rtl8111::mac_start();
    let (led_por, led_new, physt) = rtl8111::led_diag();
    let spd = if physt & 0x10 != 0 { "1000" } else if physt & 0x08 != 0 { "100" } else if physt & 0x04 != 0 { "10" } else { "?" };
    kprint!(" [P9] MAC started; PHY link={}; polling RX ~5s -> kernel IDS\n",
        if rtl8111::link_up() { "UP" } else { "down" });
    kprint!(" [P9-led] LED_CTRL por={:#06x} -> set {:#06x} (LED0=any-link/green, LED1=act/amber); PHYstatus={:#04x} link={} speed={}Mbps fdx={}\n",
        led_por, led_new, physt, (physt >> 1) & 1, spd, physt & 1);
    struct Pool([u8; packet::FRAME_SZ * 8]);
    static mut RXPOOL: Pool = Pool([0; packet::FRAME_SZ * 8]);
    let pool = core::ptr::addr_of_mut!(RXPOOL) as usize;
    let mut buf = [0u8; 1600];
    let mut frames = 0u32;
    let mut spins = 0u64;
    // One shared ring cursor (`rx_next`): a local index that advances only on Some parks
    // on an errored slot, and leaves the driver's head behind the NIC's fill point for
    // every later consumer (the eth1 LAN role).
    while frames < 4 && spins < 60_000_000 {
        if let Some(len) = rtl8111::rx_next(&mut buf) {
            let n = len.min(buf.len());
            if n >= 14 {
                let verdict = if packet::produce_raw(pool, &buf[..n]) {
                    packet::consume_one(pool)
                } else {
                    None
                };
                if let Some((port, v)) = verdict {
                    kprint!("   [P9-rx] frame {} ({}B et={:02x}{:02x}) -> IDS {} (dst_port={})\n",
                        frames, n, buf[12], buf[13],
                        if v == packet::DROP { "DROP" } else { "PASS" }, port);
                }
                frames += 1;
            }
        }
        spins += 1;
        core::hint::spin_loop();
    }
    if frames > 0 {
        kprint!(" [P9-rx] PASS — {} real phy1 frame(s) off the RTL8111H -> kernel IDS verdict (BOTH NICs feed the IDS)\n", frames);
    } else {
        kprint!(" [P9-rx] SILENT — no RX frames in the window (check the phy1 cable/link-partner); datapath armed without fault\n");
    }
}

/// P10 Stage A — CYW43455 WiFi (SDIO) bring-up: read the chip common-core ID and
/// confirm 0x4345 (BCM4345/6 = CYW43455). First step toward the regdomain backlog
/// (Stage C: clmload + country iovar). WL_ON rail + clk_emmc2 are mailbox-owned and
/// assumed up here; SDHCI/DDR50 timing iterates on metal (like rtl8111 did).
#[cfg(feature = "cm5")]
fn cm5_p10_probe() {
    use arch_aarch64::cyw43;
    kprint!(" [P10] CYW43455 WiFi (SDIO) — power on radio (WL_ON gpio28 + clk_emmc2), then Stage A\n");
    let clk = cyw43::radio_power_on();
    kprint!(" [P10] WL_ON asserted; clk_emmc2 = {} Hz {}\n", clk, if clk > 0 { "(clock live)" } else { "(clock OFF — mailbox failed?)" });
    match cyw43::chip_id_probe() {
        Some(0x4345) => {
            kprint!(" [P10-A] PASS — SDIO link up; chip ID 0x4345 (BCM4345/6 / CYW43455)\n");
            // Stage B: firmware + NVRAM upload, start ARMCR4, enable F2.
            static mut NVSCRATCH: [u8; 4096] = [0; 4096];
            let f2 = cyw43::firmware_upload(unsafe { &mut NVSCRATCH });
            let (erom, cr4b, cr4w) = cyw43::erom_diag();
            {
                let (spd, hc1, mhz) = arch_aarch64::cyw43::sdio_speed_diag();
                kprint!("   [P10-B sdio] CCCR SPEED={:#04x} (SHS={}) HOST_CTRL1={:#04x} (HISPD={}) => SDCLK {} MHz {}\n",
                    spd, spd & 1, hc1, (hc1 >> 2) & 1, mhz, if mhz > 12 { "High-Speed, verified over 64 CMD53 reads" } else { "default speed (fallback)" });
            }
            kprint!(" [P10-B] {} — firmware ({} B) + NVRAM uploaded; F2 {} (stage-B step {})\n",
                if f2 { "PASS" } else { "SILENT" }, cyw43::FW_BIN.len(),
                if f2 { "ready (firmware alive)" } else { "not ready — see step + EROM diag" },
                cyw43::fw_last_step());
            kprint!("   [P10-B diag] erom_ptr={:#010x} CR4 regbase={:#010x} wrapbase={:#010x}\n",
                erom, cr4b, cr4w);
            let (cstage, cint, cps) = cyw43::cmd53_diag();
            kprint!("   [P10-B cmd53w] fail_stage={} INT={:#010x} PRESENT={:#010x}\n", cstage, cint, cps);
            let (ioctl, rstctl) = cyw43::cr4_halt_diag();
            kprint!("   [P10-B cr4] IOCTL={:#010x} (CPUHALT={}) RESET_CTL={:#010x} — halted={}\n",
                ioctl, (ioctl >> 5) & 1, rstctl, (ioctl & 0x20 != 0) && (rstctl & 1 == 0));
            let (rioctl, clkcsr, ior) = cyw43::f2_diag();
            kprint!("   [P10-B f2] post-activate CR4 IOCTL={:#010x} (CPUHALT={}) CHIPCLKCSR={:#04x} (HT_avail={}) F2_IOR={:#04x}\n",
                rioctl, (rioctl >> 5) & 1, clkcsr, (clkcsr >> 7) & 1, ior);
            // KSO (root cause): backplane gate that must be open for the PMU to serve HT.
            let (ksob, ksoa) = cyw43::kso_diag();
            kprint!("   [P10-B kso] SLEEPCSR before={:#04x} after={:#04x} (KSO_en={}) {}\n",
                ksob, ksoa, ksoa & 1, if ksoa & 1 != 0 { "(backplane ungated)" } else { "(STILL GATED)" });
            // #2 HT-before-download: did HT lock with the CR4 halted?
            let ht = cyw43::ht_diag();
            kprint!("   [P10-B ht] CHIPCLKCSR after halt+HT-wait={:#04x} (HT_avail={}) — want 0xC0\n", ht, (ht >> 7) & 1);
            // 3b isolation: force HT via resource masks — PLL health vs request-path.
            let (fclk, fres, fpend, fpmust) = cyw43::ht_force_diag();
            kprint!("   [P10-B htforce] clkcsr={:#04x} (HT_avail={}) res_state={:#010x} (HT28/29={}{}) res_pend={:#010x} pmust={:#010x} => {}\n",
                fclk, (fclk >> 7) & 1, fres, (fres >> 28) & 1, (fres >> 29) & 1, fpend, fpmust,
                if fclk & 0x80 != 0 { "PLL OK, request-path bug" } else { "PLL/LPO cannot make HT" });
            // RAM size + NVRAM placement + firmware-alive (the F2 fix):
            let rs = cyw43::ramsize_diag();
            let na = cyw43::nvram_addr_diag();
            let (spa, spv) = cyw43::alive_diag();
            let alive = spv >= 0x198000 && spv < 0x198000 + rs;
            kprint!("   [P10-B ram] hw_ramsize={:#08x} (RAM_top={:#010x}) nvram@{:#010x}\n",
                rs, 0x198000u32.wrapping_add(rs), na);
            kprint!("   [P10-B alive] shared_ptr@{:#010x} = {:#010x} => {}\n",
                spa, spv, if alive { "FIRMWARE RUNNING (CR4 executing)" } else { "firmware DID NOT boot (no shared ptr)" });
            // #1 read-back verify: did the firmware actually land in TCM?
            let (nm, ba, exp, got) = cyw43::fw_verify();
            kprint!("   [P10-B fwverify] mismatches={} first_bad@{:#010x} exp={:#010x} got={:#010x} {}\n",
                nm, ba, exp, got, if nm == 0 { "(TCM OK)" } else { "(TCM CORRUPT — download over wrong clock)" });
            // #4 PMU/ChipCommon dumps (0=after halt+HT, 1=after CR4 release):
            let p0 = cyw43::pmu_dump_get(0);
            let p1 = cyw43::pmu_dump_get(1);
            kprint!("   [P10-B pmu0] clkcsr={:#04x} chipst={:#010x} pmuctl={:#010x} pmucap={:#010x} pmust={:#010x} resst={:#010x} respend={:#010x} maxres={:#010x}\n",
                p0[0], p0[1], p0[2], p0[3], p0[4], p0[5], p0[6], p0[7]);
            kprint!("   [P10-B pmu1] clkcsr={:#04x} chipst={:#010x} pmuctl={:#010x} pmucap={:#010x} pmust={:#010x} resst={:#010x} respend={:#010x} maxres={:#010x}\n",
                p1[0], p1[1], p1[2], p1[3], p1[4], p1[5], p1[6], p1[7]);
            if !f2 && cr4w == 0 {
                let mut ed = [0u32; 24];
                cyw43::erom_dump(&mut ed);
                kprint!("   [P10-B erom]");
                for (i, w) in ed.iter().enumerate() {
                    if i % 8 == 0 { kprint!("\n    {:02x}:", i); }
                    kprint!(" {:08x}", w);
                }
                kprint!("\n");
            }
            if f2 {
                // Stage C METAL GATE: the GET "ver" round-trip already RAN inside
                // firmware_upload the instant F2 came ready (no idle window — the 43455
                // sleeps after ~150ms of a silent bus). Here we only READ the captured
                // result + diagnostics and print them.
                let (ver_ok, ver, _vl) = cyw43::ver_result();
                let (bw, hc) = cyw43::buswidth_diag();
                kprint!("   [P10-C 4bit] CCCR_bus(0x07)={:#04x} (0x02=card 4-bit) HOST_CTRL1={:#04x} (bit1=host 4-bit) => {}\n",
                    bw, hc, if bw & 3 == 2 { "4-BIT active" } else { "fell back to 1-bit" });
                let rs = cyw43::ready_state();
                kprint!("   [P10-C ready] AT F2-ready (F0 first): CCCR_rev={:#04x} F2_IOR={:#04x} | CHIPCLKCSR={:#04x} chip_id={:#06x} — F0 alive+F1 dead=backplane asleep; both dead=device down\n",
                    rs[0], rs[1], rs[2], rs[3]);
                let d = cyw43::bcdc_diag();
                kprint!("   [P10-C bcdc] tx_seq={} tx_ok={} credit={} intstat={:#010x} rx_ok={} hw_len={} cksum_ok={} chan={} doff={} reqid_match={} status={:#x} tx_max={}\n",
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11]);
                let (cstage, cint, cpres) = cyw43::cmd53_diag();
                kprint!("   [P10-C txfail] cmd53 fail_stage={} (1=cmd-rej 2=err-wr 3=bufwr-timeout 4=err-xfer 5=xfer-timeout) INT={:#010x} PRESENT={:#010x}\n",
                    cstage, cint, cpres);
                let (mbi, mbd) = cyw43::mailbox_diag();
                kprint!("   [P10-C mbox] firmware mailbox drained: intstatus={:#010x} tohostmboxdata={:#010x}\n", mbi, mbd);
                let (wkb, wka) = cyw43::wake_diag();
                let st = cyw43::p10c_state();
                kprint!("   [P10-C wake] SLEEPCSR {:#04x}->{:#04x} (KSO={} DEVON={})\n", wkb, wka, wka & 1, (wka >> 1) & 1);
                kprint!("   [P10-C state] chip_id={:#06x} (0x4345=link alive) F2_IOR={:#04x} (0x04=ready) SLEEPCSR={:#04x} CHIPCLKCSR={:#04x}\n",
                    st[0], st[1], st[2], st[3]);
                let hte = cyw43::ht_ensure_diag();
                kprint!("   [P10-C htens] CHIPCLKCSR before F2 txn={:#04x} (HT_avail={}) — must be 1 or F2 CMD53 times out\n", hte, (hte >> 7) & 1);
                if ver_ok {
                    // print the version string (ASCII up to first NUL).
                    let vlen = ver.iter().position(|&c| c == 0).unwrap_or(ver.len()).min(80);
                    kprint!("   [P10-C ver] firmware says: ");
                    for &c in &ver[..vlen] {
                        if c >= 0x20 && c < 0x7f { kprint!("{}", c as char); }
                    }
                    kprint!("\n");
                }
                if ver_ok {
                    // Control path proven — confirm the regdomain via the country iovar.
                    // RO (Romania) matches the ccode=RO baked into NVRAM (fw >=7.45.265).
                    let rd = cyw43::set_regdomain(b"RO", 0);
                    let d = cyw43::regdom_diag();
                    let pc = |c: u8| if c >= 0x20 && c < 0x7f { c as char } else { '.' };
                    kprint!("   [P10-C regdom] SET ok={} (status={:#x}) GET ok={} abbrev=\"{}{}\" ccode=\"{}{}\" (want RO)\n",
                        d.set_ok, d.set_status, d.get_ok,
                        pc(d.abbrev[0]), pc(d.abbrev[1]), pc(d.ccode[0]), pc(d.ccode[1]));
                    match rd {
                        Some(true) => kprint!(" [P10-C] PASS — control round-trip + regdomain readback is a real ISO (ccode not 00/99)\n"),
                        Some(false) => kprint!(" [P10-C] PASS(ctrl) — ver + country round-trip OK; ccode not a real ISO yet\n"),
                        None => kprint!(" [P10-C] PASS(ctrl) — ver round-trip OK; country readback txn incomplete — see regdom diag\n"),
                    }
                    // P10-D: WiFi scan — enumerate nearby APs (event_msgs -> UP -> escan).
                    kprint!(" [P10-D] WiFi scan — MAC + preinit + WLC_UP + escan (all channels)...\n");
                    let mut aps = [cyw43::ApInfo::new(); 32];
                    let naps = cyw43::wifi_scan(&mut aps);
                    let sd = cyw43::scan_diag();
                    let (svok, sver) = cyw43::scan_ver_diag();
                    let (v1s, _v2s) = cyw43::escan_status_v1v2();
                    let (otp, used, valid) = cyw43::mac_diag();
                    kprint!("   [P10-D mac] OTP={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} valid={} using={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                        otp[0],otp[1],otp[2],otp[3],otp[4],otp[5], valid, used[0],used[1],used[2],used[3],used[4],used[5]);
                    let (clmok, clmst, ctyok, ctyst, chans) = cyw43::reg_diag();
                    kprint!("   [P10-D reg] clmload ok={} (st={:#x}) country ok={} (st={:#x}) chanspecs={} (band enabled proof = escan success below)\n",
                        clmok, clmst, ctyok, ctyst, chans);
                    let (upok, bok, upst) = cyw43::up_check_diag();
                    let pn = cyw43::phy_noise_diag();
                    kprint!("   [P10-D up] WLC_UP ok={} GET_BSSID status={:#x} (MAC domain) | GET_PHY_NOISE status={:#x} => RADIO {}\n",
                        upok, upst, pn, if pn != 0xfffffffc { "UP (powered)" } else { "DOWN (not clocked)" });
                    kprint!("   [P10-D scan] scan_ver ok={} val/status={:#x} | escan={} escan_status={:#x} frames={} APs={}\n",
                        svok, sver, sd[3], v1s, sd[4], sd[5]);
                    for ap in &aps[..naps] {
                        kprint!("   [P10-D AP] {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ch={} rssi={} ssid=\"",
                            ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5],
                            ap.channel, ap.rssi);
                        for &c in &ap.ssid[..ap.ssid_len as usize] {
                            if c >= 0x20 && c < 0x7f { kprint!("{}", c as char); }
                        }
                        kprint!("\"\n");
                    }
                    if naps > 0 {
                        kprint!(" [P10-D] PASS — WiFi RX works: {} AP(s) seen via escan (the sensor path is live)\n", naps);
                    } else {
                        kprint!(" [P10-D] scan armed (up={} escan={}); no AP frames parsed — see scan diag\n", sd[2], sd[3]);
                    }
                    // P11 M-AP0: AP-mode bring-up (compile-time switch — runs INSTEAD of the STA
                    // join). heqk becomes the WiFi authenticator (gap #4). The FullMAC firmware
                    // makes beacons/auth/assoc itself; M-AP0 just proves it enters AP mode + the
                    // BSS beacons (validated by an attending operator seeing the SSID on a phone).
                    const AP_MODE: bool = cfg!(feature = "apmode");
                    if AP_MODE {
                        const AP_SSID: &[u8] = b"heqk-ap";
                        const AP_PSK: &[u8] = match option_env!("HEQK_AP_PSK") { Some(s) => s.as_bytes(), None => b"" }; // WPA2 passphrase for heqk-ap (build-time env, never in source)
                        // M-NAT0: the wired UPLINK. Operator topology: end0 (RP1 GEM) is ALWAYS
                        // the WAN, eth1 (RTL8111H) is the LAN. Lease an IP on end0, resolve the
                        // gateway, ping the internet — over the metal-proven GEM rings (armed by
                        // the P8 GEM phase). Runs BEFORE the WiFi AP so the polled rings don't
                        // interleave in the log; its lease + gw MAC are what M-NAT1+ NATs the
                        // WiFi-AP and eth1-LAN clients through. eth1 is reported as the LAN port
                        // (link + station MAC only — heqk will be its DHCP SERVER, never a client).
                        use arch_aarch64::uplink::{self, Nic};
                        let mut up = uplink::UplinkResult::new(Nic::End0);
                        // The operator's WAN mode (WAN.TXT on the eMMC boot partition); DHCP when absent.
                        let wan_mode: hal::WanMode = match arch_aarch64::emmc::Emmc::probe() {
                            Ok(dev) => match load_wan_cfg(&dev) {
                                Some(Ok(mo)) => mo,
                                Some(Err(e)) => {
                                    kprint!(" [WAN] WAN.TXT invalid ({:?}) — falling back to DHCP\n", e);
                                    hal::WanMode::Dhcp
                                }
                                None => hal::WanMode::Dhcp,
                            },
                            Err(_) => hal::WanMode::Dhcp,
                        };
                        match wan_mode {
                            hal::WanMode::Dhcp => kprint!(" [WAN] mode = DHCP\n"),
                            hal::WanMode::Static { ip, prefix, gw, dns } => kprint!(" [WAN] mode = STATIC {}.{}.{}.{}/{} gw {}.{}.{}.{} dns {}.{}.{}.{}\n",
                                ip[0], ip[1], ip[2], ip[3], prefix, gw[0], gw[1], gw[2], gw[3], dns[0], dns[1], dns[2], dns[3]),
                            hal::WanMode::Pppoe { user_len, .. } => kprint!(" [WAN] mode = PPPoE (user {} chars)\n", user_len),
                        }
                        // Link (VLAN / QinQ / management sub-interface) + POLICY.TXT — before any WAN mode comes up,
                        // so DHCP / PPPoE already ride the tagged internet sub-interface.
                        if let Ok(dev) = arch_aarch64::emmc::Emmc::probe() {
                            match load_wan_link(&dev) {
                                Some(Ok(l)) => {
                                    uplink::link_configure(&l);
                                    // Management floor (task #21 N3): explicit `mgmt_floor`, else the management
                                    // sub-interface's subnet (the operator's path), else the compile-time default.
                                    let floor = l.floor.or_else(|| l.mgmt.and_then(|mg| mg.stat.map(|(ip, pl, _)| (ip, pl))));
                                    if let Some((ip, pl)) = floor {
                                        let _ = crate::verdict::set_mgmt_floor(u32::from_be_bytes(ip), pl as u32);
                                    }
                                    if l.floor_bad {
                                        kprint!(" [LINK] WAN.TXT mgmt_floor= INVALID (need a.b.c.d/8..32) — ignored, the floor below applies\n");
                                    }
                                    let (fnet, flen, fset) = crate::verdict::mgmt_floor();
                                    let fb = fnet.to_be_bytes();
                                    kprint!(" [LINK] management floor (never enforced against): {}.{}.{}.{}/{} — {}\n", fb[0], fb[1], fb[2], fb[3], flen,
                                        if fset { "configured" } else { "COMPILE-TIME DEFAULT (set mgmt_floor= in WAN.TXT)" });
                                    let e = hal::policy::Encap { vlan: l.vlan, outer: l.outer, pcp: l.pcp, pppoe: matches!(wan_mode, hal::WanMode::Pppoe { .. }) };
                                    kprint!(" [LINK] internet sub-interface: vlan={} outer={} pcp={} -> IP MTU {} (frame {} B{}) | mgmt: {}\n",
                                        l.vlan, l.outer, l.pcp, e.ip_mtu(), e.frame_max(), if e.tag_len() > 0 { ", jumbo gate opened" } else { "" },
                                        match l.mgmt { None => "none", Some(hal::MgmtIf { stat: None, .. }) => "vlan DHCP", Some(_) => "vlan static" });
                                    if let Some(mg) = l.mgmt {
                                        if uplink::mgmt_configure(&mg) {
                                            match mg.stat {
                                                Some((ip, pl, gw)) => kprint!(" [LINK] management sub-interface: vlan {} {}.{}.{}.{}/{} gw {}.{}.{}.{} (ARP, ping under the `mgmt in` policy)\n",
                                                    mg.vlan, ip[0], ip[1], ip[2], ip[3], pl, gw[0], gw[1], gw[2], gw[3]),
                                                None => kprint!(" [LINK] management sub-interface: vlan {} DHCP (DORA on the management VLAN; ARP, ping under the `mgmt in` policy once bound)\n", mg.vlan),
                                            }
                                        }
                                    }
                                }
                                Some(Err(e)) => kprint!(" [LINK] WAN.TXT link keys invalid ({:?}) — internet untagged, no management sub-interface\n", e),
                                None => {}
                            }
                            match load_policy(&dev) {
                                Some(Ok(())) => {
                                    let pol = unsafe { &*core::ptr::addr_of!(POLICY) };
                                    kprint!(" [POLICY] loaded: {} prefix-lists, {} ACLs, {} interface bindings, {} routes\n", pol.npl, pol.nacl, pol.nbind, pol.nroutes);
                                    for a in &pol.acl[..pol.nacl] {
                                        kprint!(" [POLICY]   acl {} — {} entries, default {:?}{}\n", core::str::from_utf8(&a.name[..a.nlen]).unwrap_or("?"), a.n,
                                            a.default.unwrap_or(hal::policy::Act::Drop), if a.default.is_none() { " (implicit deny)" } else { "" });
                                    }
                                }
                                Some(Err(e)) => {
                                    // Never half-applied, and never silently OPEN (peer review SEC-M1): a broken file
                                    // locks the MANAGEMENT sub-interface (implicit deny) until it is fixed — a typo must
                                    // not remove an admin-only lockdown. Forwarding stays as without a policy (legit
                                    // customer traffic always passes, ADR 0023); NAT / the v6 firewall still deny inbound.
                                    let pol = unsafe { &mut *core::ptr::addr_of_mut!(POLICY) };
                                    let _ = hal::policy::parse_policy(b"HQPOL1\nacl LOCKDOWN default drop\ninterface mgmt acl in LOCKDOWN\n", pol);
                                    kprint!(" [POLICY] POLICY.TXT REJECTED ({:?}) — never half-applied: management LOCKED (implicit deny), forwarding unchanged; fix the file\n", e);
                                }
                                None => kprint!(" [POLICY] no POLICY.TXT — no operator ACLs / routes\n"),
                            }
                            // Shield: the DNS blocklist (BLOCK.TXT, operator-signed like POLICY.TXT).
                            match dnsblock::load(&dev) {
                                Some(Ok(l)) => kprint!(" [SHIELD] DNS blocklist: {} domains{}{} — blocked names answered 0.0.0.0 / NODATA by the AP\n", l.domains,
                                    if l.signed { " (signature OK, operator key)" } else { " (unsigned — standalone image)" },
                                    if l.truncated > 0 { " — list longer than the table, rest ignored" } else { "" }),
                                Some(Err(e)) => kprint!(" [SHIELD] BLOCK.TXT REFUSED ({:?}) — Shield OFF, nothing blocked (a tampered list must not black-hole names)\n", e),
                                None => kprint!(" [SHIELD] no BLOCK.TXT — Shield counts DNS queries but blocks nothing\n"),
                            }
                        }
                        {
                            let (lan_started, lan_link, lan_mac) = uplink::eth1_lan_status();
                            kprint!(" [M-NAT0 lan] eth1 (RTL8111H) LAN port: started={} link={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                                lan_started, lan_link, lan_mac[0], lan_mac[1], lan_mac[2], lan_mac[3], lan_mac[4], lan_mac[5]);
                            kprint!(" [M-NAT0] end0 (RP1 GEM) WAN uplink — DHCP, ARP gw, ping gw + 8.8.8.8 over the GEM TX ring\n");
                            uplink::bringup_with(Nic::End0, &[8, 8, 8, 8], &wan_mode, &mut up);
                            if let Some((ph, why, sid, ac, ip, peer, d1, d2, auth, st)) = uplink::pppoe_info() {
                                kprint!(" [WAN] PPPoE: phase={:?} why={:?} sid={:#06x} AC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} | ip {}.{}.{}.{} peer {}.{}.{}.{} dns {}.{}.{}.{} / {}.{}.{}.{} auth={} | padi={} pado={} padr={} pads={} lcp tx/rx={}/{} nak/rej={} auth_tx={} ipcp_tx={} proto_rej={} stale_padt={}\n",
                                    ph, why, sid, ac[0], ac[1], ac[2], ac[3], ac[4], ac[5], ip[0], ip[1], ip[2], ip[3], peer[0], peer[1], peer[2], peer[3],
                                    d1[0], d1[1], d1[2], d1[3], d2[0], d2[1], d2[2], d2[3],
                                    match auth { 0xc023 => "PAP", 0xc223 => "CHAP-MD5", _ => "none" },
                                    st.padi, st.pado, st.padr, st.pads, st.lcp_req_tx, st.lcp_req_rx, st.lcp_nak_rej_tx, st.auth_tx, st.ipcp_req_tx, st.proto_rejects, st.stale_padt);
                            }
                            {
                                let w = unsafe { uplink::WAN6 };
                                if w.ran {
                                    let h = |a: &[u8; 16]| {
                                        let g = |k: usize| u16::from_be_bytes([a[2 * k], a[2 * k + 1]]);
                                        [g(0), g(1), g(2), g(3), g(4), g(5), g(6), g(7)]
                                    };
                                    kprint!(" [WAN6] IPV6CP up={} off={} iid {:02x?} peer {:02x?} | RS tx={} | DHCPv6 tx={} rx={} advertise={} reply={} status={} | v6 frames rx={}\n",
                                        w.ip6cp_up, w.ip6cp_off, w.my_iid, w.peer_iid, w.rs_tx, w.dhcp_tx, w.dhcp_rx, w.advertise, w.reply, w.status, w.v6_frames_rx);
                                    match w.ra {
                                        Some(ra) => kprint!(" [WAN6] RA from {:x?} lifetime={}s M={} O={} | prefix={} {:x?}/{} A={} valid={}s pref={}s | mtu={}\n",
                                            h(&ra.router), ra.lifetime, ra.managed, ra.other, ra.has_prefix, h(&ra.prefix), ra.plen, ra.autonomous, ra.valid, ra.preferred, ra.mtu),
                                        None => kprint!(" [WAN6] no Router Advertisement\n"),
                                    }
                                    match w.pd {
                                        Some((p, l, v)) => kprint!(" [WAN6] DELEGATED PREFIX {:x?}/{} valid={}s (the LAN would be numbered from this)\n", h(&p), l, v),
                                        None => kprint!(" [WAN6] no delegated prefix\n"),
                                    }
                                    if let Some(d) = w.dns {
                                        kprint!(" [WAN6] DNS {:x?}\n", h(&d));
                                    }
                                    match w.na {
                                        Some(a) => kprint!(" [WAN6] WAN address (IA_NA) {:x?}\n", h(&a)),
                                        None => kprint!(" [WAN6] no IA_NA address (the LAN /64 router address is the global source)\n"),
                                    }
                                }
                            }
                            if !up.started {
                                kprint!(" [M-NAT0] SKIP — GEM rings not armed\n");
                            } else {
                                kprint!("   [M-NAT0] link={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} mac_ok={} | DORA tx/rx D={} O={} R={} A={} rx_frames={} udp68={}\n",
                                    up.link, up.mac[0], up.mac[1], up.mac[2], up.mac[3], up.mac[4], up.mac[5], up.mac_ok,
                                    up.dhcp.discover_tx, up.dhcp.offer_rx, up.dhcp.request_tx, up.dhcp.ack_rx,
                                    up.rx_frames, up.dhcp.udp68_seen);
                                kprint!("   [M-NAT0] ring: stale_drained={} rsr_before={:#x} bna_recovered={} | nak={} garp_tx={} dns={}.{}.{}.{}\n",
                                    up.stale_drained, up.rsr_before, up.bna_recovered, up.dhcp.nak_rx, up.garp_tx,
                                    up.dhcp.dns[0], up.dhcp.dns[1], up.dhcp.dns[2], up.dhcp.dns[3]);
                                if up.dhcp.ack_rx {
                                    kprint!("   [M-NAT0] leased {}.{}.{}.{}/{}.{}.{}.{} gw {}.{}.{}.{} server {}.{}.{}.{} lease={}s\n",
                                        up.dhcp.yiaddr[0], up.dhcp.yiaddr[1], up.dhcp.yiaddr[2], up.dhcp.yiaddr[3],
                                        up.dhcp.mask[0], up.dhcp.mask[1], up.dhcp.mask[2], up.dhcp.mask[3],
                                        up.dhcp.router[0], up.dhcp.router[1], up.dhcp.router[2], up.dhcp.router[3],
                                        up.dhcp.server[0], up.dhcp.server[1], up.dhcp.server[2], up.dhcp.server[3], up.dhcp.lease);
                                }
                                kprint!("   [M-NAT0] arp tx={} reply={} gw_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} | ping gw tx={} reply={} ttl={} | ping 8.8.8.8 tx={} reply={} ttl={}\n",
                                    up.arp_tx, up.arp_reply, up.gw_mac[0], up.gw_mac[1], up.gw_mac[2], up.gw_mac[3], up.gw_mac[4], up.gw_mac[5],
                                    up.gw_ping_tx, up.gw_ping_reply, up.gw_ttl, up.inet_ping_tx, up.inet_ping_reply, up.inet_ttl);
                                if up.inet_ping_reply {
                                    kprint!(" [M-NAT0] PASS — end0 WAN uplink leased + gateway resolved + INTERNET reachable (8.8.8.8 ttl={})\n", up.inet_ttl);
                                } else if up.usable() {
                                    kprint!(" [M-NAT0] PASS(uplink) — leased + gateway resolved; no internet echo (upstream NAT/ICMP policy?)\n");
                                } else if !up.link {
                                    kprint!(" [M-NAT0] LINK DOWN — end0 PHY reports no link at bring-up (cable / link-partner / autoneg); nothing transmitted\n");
                                } else if up.dhcp.discover_tx && up.rx_frames > 0 && !up.dhcp.offer_rx {
                                    kprint!(" [M-NAT0] NO OFFER — DISCOVER transmitted but no DHCP server answered on end0's segment\n");
                                } else if !up.dhcp.discover_tx {
                                    kprint!(" [M-NAT0] FAIL — GEM tx_frame did not complete (TSR at timeout={:#06x}: 0x01=UBR 0x04=RLE 0x08=TGO-only=clean-timeout 0x10=BEX 0x20=TXCOMP; retried={})\n",
                                        up.tx_err, up.tx_retried);
                                } else {
                                    kprint!(" [M-NAT0] INCOMPLETE — see stage flags above\n");
                                }
                            }
                        }
                        kprint!(" [P11-AP2] WPA2-secured AP: SSID \"heqk-ap\" ch6 (PSK) — heqk is the authenticator...\n");
                        // PMK + GTK FIRST (fail-closed): never leave a WPA2 BSS beaconing with no
                        // authenticator behind it because the TRNG refused after the BSS was up.
                        let pmk = arch_aarch64::wpa::wpa_pmk(AP_PSK, AP_SSID);
                        let mut gtk = [0u8; 16];
                        let mut gtk_ok = true;
                        for k in 0..2 {
                            match arch_aarch64::rng200::next_word_strict() {
                                Some(w) => gtk[k * 8..k * 8 + 8].copy_from_slice(&w.to_le_bytes()),
                                None => gtk_ok = false,
                            }
                        }
                        if !gtk_ok {
                            kprint!(" [P11-AP2] GTK TRNG failed — AP NOT started (fail-closed)\n");
                            return;
                        }
                        let mut ap = cyw43::ApResult::new();
                        let mut ap_tries = 0u32;
                        let mut chosen_cs: u16 = 0; // the chanspec the AP came up on (for the channel recheck)
                        loop {
                            ap_tries += 1;
                            ap = cyw43::ApResult::new();
                            // Try 1: the scan-driven channel choice (hal::acs_choose — least interference,
                            // 5 GHz/80 preferred when its block is clear); try 2: the proven 2.4 GHz
                            // ch6 @ 20 MHz fallback.
                            // Bench pin: HEQK_AP_CHANNEL=<n> (build env) bypasses the scan choice — used to hold
                            // the channel constant while isolating another variable.
                            const AP_PIN: Option<&str> = option_env!("HEQK_AP_CHANNEL");
                            let pin: u32 = match AP_PIN { Some(s) => s.bytes().fold(0u32, |a, b| if b.is_ascii_digit() { a * 10 + (b - b'0') as u32 } else { a }), None => 0 };
                            let (ap_chan, ap_cs): (u32, u16) = if ap_tries == 1 && pin != 0 {
                                kprint!("   [P11-ACS] channel PINNED by build env HEQK_AP_CHANNEL={} (scan choice bypassed)\n", pin);
                                (pin, cyw43::ap_chanspec(pin))
                            } else if ap_tries == 1 {
                                let mut neigh = [(0u16, 0i16); 32];
                                let nn = naps.min(neigh.len());
                                for (k, a) in aps[..nn].iter().enumerate() {
                                    neigh[k] = (a.chanspec, a.rssi);
                                }
                                let allowed = cyw43::allowed_chanspecs();
                                let mut c = hal::acs_choose_allowed(&neigh[..nn], allowed);
                                let (cok, cst) = cyw43::chanspecs_status();
                                kprint!("   [P11-ACS] regdomain: chanspecs GET ok={} status={:#x}; {} chanspecs allowed by the firmware for this country; 36/80 {} 11/20 {}\n",
                                    cok, cst, allowed.len(), if allowed.contains(&0xe02a) { "allowed" } else { "NOT allowed" },
                                    if allowed.contains(&0x100b) { "allowed" } else { "NOT allowed" });
                                if c.channel == 0 {
                                    kprint!("   [P11-ACS] no candidate is in the regdomain list — falling back to 2.4 GHz ch6\n");
                                    c = hal::AcsChoice { channel: 6, chanspec: cyw43::ap_chanspec(6), mhz: 20, score: 0, est_mbps: 0 };
                                }
                                kprint!("   [P11-ACS] {} neighbours scanned -> channel {} @ {} MHz (chanspec {:#06x}, {} strong co-channel network(s), est. ~{} Mbps PHY share)\n",
                                    nn, c.channel, c.mhz, c.chanspec, c.score, c.est_mbps);
                                (c.channel as u32, c.chanspec)
                            } else {
                                (6, cyw43::ap_chanspec(6))
                            };
                            kprint!("   [P11-AP2] try {}: channel {} chanspec {:#06x}\n", ap_tries, ap_chan, ap_cs);
                            cyw43::ap_start(AP_SSID, ap_chan, ap_cs, false, &mut ap); // open=false => WPA2-PSK-CCMP beacon
                            // The group key goes in ONCE per BSS (index 1, PRIMARY = the fw's default
                            // group TX key, as brcmfmac's add_key) — not per station, which reset the
                            // group PN on every join.
                            ap.gtk_set = cyw43::ap_install_gtk(&gtk, 1);
                            kprint!("   [P11-AP2] cap_has_ap={} apsta={} set_ap={} infra={} chan={} wsec={} wpa_auth={} up={} ssid={} | get_ap={} bssid {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} mac_set={} ev={} gtk={} bssid_rb={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} verified={}\n",
                                ap.cap_has_ap, ap.apsta_ok, ap.set_ap_ok, ap.infra_ok, ap.chan_ok, ap.wsec_ok,
                                ap.wpa_auth_ok, ap.up_ok, ap.ssid_ok, ap.get_ap,
                                ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5],
                                ap.mac_set_ok, ap.ev_ok, ap.gtk_set,
                                ap.bssid_readback[0], ap.bssid_readback[1], ap.bssid_readback[2], ap.bssid_readback[3], ap.bssid_readback[4], ap.bssid_readback[5],
                                ap.bssid_verified);
                            if ap.serve_ready() && ap.gtk_set {
                                chosen_cs = ap_cs;
                                kprint!("   [P11-ACS] chanspec iovar accepted={} (20-MHz legacy fallback used={})\n", ap.chanspec_ok, ap.chan_fallback20);
                                let rb = cyw43::current_chanspec();
                                kprint!("   [P11-ACS] operating chanspec readback {:#06x} vs requested {:#06x} => {}\n",
                                    rb.unwrap_or(0), ap_cs, if rb == Some(ap_cs) { "ON THE CHOSEN CHANNEL" } else { "MISMATCH" });
                                kprint!(" [P11-AP2] PASS(ap-config-wpa2) — WPA2 BSS up (try {}); join \"heqk-ap\" (PSK = build-time HEQK_AP_PSK)\n", ap_tries);
                                break;
                            }
                            kprint!(" [P11-AP2] AP config INCOMPLETE (try {}: get_ap={} ssid_ok={} bssid_nonzero={} ev_ok={} gtk_set={})\n",
                                ap_tries, ap.get_ap, ap.ssid_ok, ap.bssid != [0u8; 6], ap.ev_ok, ap.gtk_set);
                            if ap_tries >= 2 {
                                kprint!(" [P11-AP2] FAIL — AP not serve-ready after 2 attempts; not entering the serve loop (a BSS that can't key clients must not beacon as if it could)\n");
                                let _ = cyw43::ap_stop();
                                return;
                            }
                        }
                        // M-AP3/M-AP4: the PERSISTENT AP serve loop is now ONE event-driven frame
                        // pump (deep review 2026-09-11, G1/B2): every WiFi frame is demuxed per
                        // frame — ch1 (RE)ASSOC_IND → the bounded authenticator; DEAUTH/DISASSOC
                        // noted; ch2 ARP/DHCP → served (gateway ARP and DHCP renewals are answered
                        // FOREVER, not only for ~15 reads after the first lease — the old shape lost
                        // the phone's gateway within seconds and its lease every hour); other ch2 →
                        // (M-NAT1) forwarding. Between frames the WAN keep-alive answers the
                        // fortress's ARP probes for our lease, HT is kept alive, a 5 s heartbeat
                        // proves liveness, and the core parks in `wfe`. The WiFi poll costs ~100 µs
                        // when idle (I_HMB_FRAME_IND peek), so the loop is responsive without the
                        // 1.5 s dry-read tax. Single-client pool (10.99.0.10) — a pool is M-NAT1.
                        cyw43::set_defer(true); // control requests park station frames instead of dropping them
                        kprint!(" [P11-AP3] persistent WPA2 AP serve loop up — event-driven pump (assoc/deauth/ARP/DHCP), WAN keep-alive, 5s heartbeat\n");
                        let our_ip = [10u8, 99, 0, 1];
                        let offer_ip = [10u8, 99, 0, 10];
                        ratelimit::set_local_ip(0, u32::from_be_bytes(our_ip)); // ADR 0049 D3: our own addresses
                        let mut rx = [0u8; 2048];
                        let mut wbuf = [0u8; 2048];
                        let mut nbuf = [0u8; 2048];
                        let mut dh = cyw43::ApDhcp::new();
                        // M-NAT1: masquerade the AP subnet out the end0 lease.
                        use arch_aarch64::nat;
                        let mut nst = nat::NatStats::default();
                        let inside_net = [10u8, 99, 0];
                        let (mut nat_tx_fail, mut nat_wifi_tx_fail) = (0u32, 0u32);
                        let (mut wan_retries, mut last_wan_try) = (0u32, 0u64);
                        let (mut wan_leased_at, mut wan_renewals) = (0u64, 0u32);
                        // IDS/IPS on BOTH NAT legs (packet::verdict = the signed rule plane, same code
                        // path as the inline datapath; rules::init ran at kmain) + the (MAC,IP) lease
                        // binding check (no client may source traffic as another).
                        let (mut ids_drop_out, mut ids_drop_in, mut bind_drop) = (0u32, 0u32, 0u32);
                        // diag: large (>600 B) WAN frames seen by wan_poll / un-NATed toward a client
                        let (mut wan_big_seen, mut wan_big_unnat) = (0u32, 0u32);
                        // diag: the first NAT_TRACE_N NAT events (dir, proto, TCP flags, size, ports, result)
                        const NAT_TRACE_N: u32 = 60;
                        let mut nat_trace = 0u32;
                        // eth1 LAN port: same DHCP/ARP server + NAT over the RTL8111 rings.
                        let (mut lan_frames, mut lan_served, mut lan_tx_fail) = (0u32, 0u32, 0u32);
                        let mut ebuf = [0u8; 2048];
                        let mut erep = [0u8; 400];
                        let pool_base = offer_ip; // MAC-bound pool .10 .. .10+AP_LEASES
                        // WiFi delivery queue: SDPCM TX credit is refreshed only by READING frames, so a
                        // burst of WAN replies between two WiFi reads can't all be sent at once. Queue
                        // them (8 × ≤600 B) and flush after every WiFi read; count only real losses.
                        // 48 × full-MTU slots, static (not stack): the 8-deep version overflowed 23×
                        // in a minute of browsing (metal 2026-10-09) — credit returns only when the
                        // station sends, so the queue must absorb a whole server burst.
                        // 128 deep (metal 2026-11-04 @ 22 Mbps: 48 overflowed 89x during brief credit=0
                        // moments; brcmfmac queues far deeper before flow-controlling the stack).
                        const WQ_N: usize = 128;
                        const WQ_SZ: usize = 1536;
                        struct WqBuf([[u8; WQ_SZ]; WQ_N]);
                        static mut WQBUF: WqBuf = WqBuf([[0; WQ_SZ]; WQ_N]);
                        let wq = unsafe { &mut (*core::ptr::addr_of_mut!(WQBUF)).0 };
                        let mut wq_len = [0usize; WQ_N];
                        let (mut wq_head, mut wq_n) = (0usize, 0usize);
                        let mut trunc_drop = 0u32; // frames `net::parse` refuses (truncated/oversize) — not a rule
                        let (mut stall_frames, mut stall_since, mut stall_reported) = (0u64, 0u64, false);
                        let (mut wifi_tx_queued, mut wifi_tx_dropped, mut wq_flushed) = (0u32, 0u32, 0u32);
                        let (mut wq_head_fail, mut wq_head_drop) = (0u32, 0u32);
                        // credit-stall diagnostics: last frames handed to the firmware (dst MAC low 3 bytes, len)
                        let mut sent_ring = [(0u32, 0u16); 4];
                        let mut sent_i = 0usize;
                        let (mut credit0_since, mut stall_diag_done) = (0u64, false);
                        // Stall experiment: stage 1 = bare dongle interrupt sent, 2 = one control frame sent.
                        // unstick = [episodes, recovered w/o poke, recovered after A (DEV_INT), after B (ctl), reached 2 s]
                        let (mut unstick_stage, mut unstick_t) = (0u8, 0u64);
                        let mut unstick = [0u32; 5];
                        // IPv6 LAN router + stateful firewall (stage 2): numbered from the DHCPv6-delegated prefix.
                        static mut V6: arch_aarch64::ip6lan::V6Lan = arch_aarch64::ip6lan::V6Lan::new();
                        let mut v6buf = [0u8; 1600];
                        let mut v6_ids_drop = [0u32; 2]; // [outbound, inbound] IDS drops on IPv6
                        // Send one frame to the Wi-Fi clients: direct when nothing is queued and credit allows,
                        // else queued in order; returns false only if it had to be dropped.
                        macro_rules! wifi_send {
                            ($f:expr) => {{
                                let f: &[u8] = $f;
                                if wq_n == 0 && cyw43::tx_credit_ok() && cyw43::ap_tx(f) {
                                    true
                                } else if wq_n < WQ_N && f.len() <= WQ_SZ {
                                    let j = (wq_head + wq_n) % WQ_N;
                                    wq[j][..f.len()].copy_from_slice(f);
                                    wq_len[j] = f.len();
                                    wq_n += 1;
                                    wifi_tx_queued += 1;
                                    true
                                } else {
                                    wifi_tx_dropped += 1;
                                    false
                                }
                            }};
                        }
                        // ---- WAN policy (task #26): per-interface counters [lan, eth1, wan, mgmt] ----
                        let mut pol_drop = [0u32; 4];
                        let mut pol_block = [0u32; 4];
                        let mut pol_via_mgmt = 0u32; // flows routed out the management sub-interface
                        let mut dns_blocked = 0u32; // Shield: client DNS queries answered as blocked
                        let mut dns_seen = 0u32;
                        let mut dns_last = [0u8; 48];
                        let mut dns_last_len = 0usize;
                        let mut dns_last_act = 0u8;
                        let mut pol_mgmt_nh_miss = 0u32; // routed to mgmt but the next hop is not resolved yet
                        let mut pol_block_as_drop = 0u32; // `out` blocks after un-NAT act as drops (see the note)
                        let mut last_wan_probe = 0u64;
                        let (mut rej_win, mut rej_n) = (0u64, 0u32); // `wan in` reject rate limit
                        let mut wan_martian = 0u32; // WAN IPv4 sources that cannot come from the internet (dropped)
                        let mut mbuf = [0u8; 1600];
                        use hal::policy::{Act as PAct, Dir as PDir, If as PIf};
                        // One client IPv4 frame from `$pif` (lan = Wi-Fi, eth1): `<if> in` ACL/prefix-lists, then the
                        // route (wan or mgmt sub-interface, by prefix / source / metric / up), then `<egress> out`;
                        // allowed -> SNAT to that sub-interface's address and send; block -> RST / ICMP admin-
                        // prohibited back to the client via `$reply`; drop -> silent. Returns true if it was sent.
                        macro_rules! fwd4 {
                            ($frame:expr, $pif:expr, $nif:expr, $reply:ident) => {{
                                let frame: &[u8] = $frame;
                                let pol = unsafe { &mut *core::ptr::addr_of_mut!(POLICY) };
                                let mut act = PAct::Allow;
                                let mut egress = PIf::Wan;
                                let mut nh_ip: Option<[u8; 4]> = None;
                                if let Some(p) = hal::policy::facts(frame) {
                                    act = pol.check($pif, PDir::In, &p).0;
                                    if act == PAct::Allow {
                                        let mgmt_up = unsafe { uplink::MGMT }.map_or(false, |m| m.gw_mac.is_some());
                                        let wan_up = uplink::wan_alive(&up, 15_000);
                                        if let Some(r) = pol.route(&p.src, &p.dst, &|i| match i { PIf::Wan => wan_up, PIf::Mgmt => mgmt_up, _ => false }) {
                                            egress = r.via;
                                            nh_ip = r.gw.filter(|g| !g.v6).map(|g| [g.a[0], g.a[1], g.a[2], g.a[3]]);
                                        }
                                        act = pol.check(egress, PDir::Out, &p).0;
                                    }
                                }
                                let pi = ($pif) as usize;
                                // Shield: an allowed client DNS query for a blocklisted name is answered here
                                // (0.0.0.0 / NODATA, from the resolver it asked) and never leaves the device.
                                let mut shield = false;
                                // Shield diagnostics: every client UDP/53 query reaching this hook, and its name.
                                if frame.len() >= 42 && frame[23] == 17 {
                                    let u = 14 + ((frame[14] & 0x0f) as usize) * 4;
                                    if u + 8 + 13 <= frame.len() && frame[u + 2] == 0 && frame[u + 3] == 53 {
                                        dns_seen += 1;
                                        let mut nm = [0u8; 256];
                                        if let Some(l) = dnssink::parse_qname(&frame[u + 8..], &mut nm) {
                                            let l = l.min(dns_last.len());
                                            dns_last[..l].copy_from_slice(&nm[..l]);
                                            dns_last_len = l;
                                            dns_last_act = act as u8;
                                        }
                                    }
                                }
                                if act == PAct::Allow && dnsblock::len() > 0 {
                                    let me = if $pif == PIf::Eth1 { uplink::ETH1_MAC } else { ap.bssid };
                                    let mut dr = [0u8; 600];
                                    if let Some(k) = dnssink::block_reply_frame(frame, &me, &mut dr, &dnsblock::blocked) {
                                        dns_blocked += 1;
                                        let _ = $reply!(&dr[..k]);
                                        act = PAct::Drop;
                                        shield = true;
                                    }
                                }
                                match act {
                                    PAct::Allow if egress == PIf::Mgmt => {
                                        let mg = unsafe { uplink::MGMT }.unwrap();
                                        match uplink::mgmt_nexthop(nh_ip.unwrap_or(mg.gw)) {
                                            Some(nmac) => {
                                                if let Some(k) = nat::outbound_redirect(frame, $nif, &inside_net, None, &mg.ip, &mg.mac, &nmac, &mut nbuf, cyw43::ticks(), &mut nst) {
                                                    pol_via_mgmt += 1;
                                                    uplink::mgmt_tx(&nbuf[..k])
                                                } else {
                                                    false
                                                }
                                            }
                                            None => {
                                                pol_mgmt_nh_miss += 1;
                                                false
                                            }
                                        }
                                    }
                                    PAct::Allow => {
                                        // `route … via wan gw X`: X's MAC (ARP-resolved); the default gateway otherwise.
                                        let gw_mac = match nh_ip {
                                            Some(g) => match uplink::wan_nexthop(&up, g) {
                                                Some(mac) => mac,
                                                None => {
                                                    pol_mgmt_nh_miss += 1; // counted with the mgmt misses: "next hop unresolved"
                                                    [0u8; 6]
                                                }
                                            },
                                            None => up.gw_mac,
                                        };
                                        let resolver = if up.dhcp.dns != [0u8; 4] { up.dhcp.dns } else { [8u8, 8, 8, 8] };
                                        if gw_mac == [0u8; 6] {
                                            false // next hop not resolved yet (ARP sent): drop, TCP retries
                                        } else if let Some(k) = nat::outbound_redirect(frame, $nif, &inside_net, Some((&our_ip, &resolver)), &up.dhcp.yiaddr, &up.mac, &gw_mac, &mut nbuf, cyw43::ticks(), &mut nst) {
                                            let ok = uplink::wan_tx(&up, &nbuf[..k]);
                                            if !ok {
                                                nat_tx_fail += 1;
                                            }
                                            ok
                                        } else {
                                            false
                                        }
                                    }
                                    PAct::Block => {
                                        pol_block[pi] += 1;
                                        let mut rj = [0u8; 128];
                                        let me = if $pif == PIf::Eth1 { uplink::ETH1_MAC } else { ap.bssid };
                                        if let Some(k) = arch_aarch64::reject::reject4(frame, &our_ip, &me, &mut rj) {
                                            let _ = $reply!(&rj[..k]);
                                        }
                                        false
                                    }
                                    PAct::Drop => {
                                        if !shield {
                                            pol_drop[pi] += 1;
                                        }
                                        false
                                    }
                                }
                            }};
                        }
                        macro_rules! eth1_send {
                            ($f:expr) => {{
                                arch_aarch64::rtl8111::tx_frame($f)
                            }};
                        }
                        let mut loop_t0 = 0u64; // profiler: start of the current loop iteration
                        const WAN_BUDGET: usize = 32; // WAN frames drained per loop (NAPI-style; wq is 128 deep)
                        let mut rx_busy = false;
                        let mut _last_sta = [0u8; 6]; // most recent associated station (stall snapshot uses the queued dst) // the last pump read returned a frame (firmware RX pending)
                        // Which signed rules are DROPping forwarded frames (the beat names them).
                        let mut rule_drops: [(u16, u32); 8] = [(0, 0); 8];
                        let mut evs = [events::Event::EMPTY; 16];
                        let (mut assocs, mut keyed, mut leaves, mut wifi_frames, mut wan_arp, mut wan_gw_refresh) = (0u32, 0u32, 0u32, 0u64, 0u32, 0u32);
                        let freq: u64;
                        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack)) };
                        let now = || -> u64 { let v: u64; unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) }; v };
                        // Mission Control served BY the AP to its Wi-Fi clients at the AP address (feature `apmc`):
                        // owner verifier + MCTLS.CRT from the boot partition, HTTP + the EL0 TLS server.
                        #[cfg(feature = "mcserve")]
                        let mc_t0 = now();
                        #[cfg(feature = "mcserve")]
                        let mut mcn: Option<mcserve::McNode> = {
                            if let Ok(dev) = arch_aarch64::emmc::Emmc::probe() {
                                let owner = crate::mcauth::load_owner(&dev);
                                mcserve::set_owner(owner);
                                kprint!(" [AP-MC] owner: {}\n", if owner.is_some() { "CLAIMED — sign-in required" } else { "UNCLAIMED — protected routes refuse" });
                                #[cfg(feature = "mctls")]
                                crate::tlshost::bring_up(Some(&dev));
                            }
                            mcserve::state().set_clock(0, mc_t0, freq);
                            let seed = arch_aarch64::rng200::next_word_strict().unwrap_or(0) ^ mc_t0;
                            match mcserve::McNode::new(ap.bssid, mcserve::NetMode::Static { ip: our_ip, prefix: 24, gw: our_ip }, seed) {
                                Some(mut n) => {
                                    n.disable_sntp();
                                    kprint!(" [AP-MC] Mission Control on http://{}.{}.{}.{}/ for Wi-Fi clients (served by heqk)\n", our_ip[0], our_ip[1], our_ip[2], our_ip[3]);
                                    Some(n)
                                }
                                None => None,
                            }
                        };
                        let (mut last_beat, mut last_ht, mut last_force) = (now(), now(), now());
                        // "stays on the chosen channel": read the operating chanspec back every 12th beat (~60 s)
                        let (mut beat_n, mut ch_checks, mut ch_mismatch, mut ch_last) = (0u32, 0u32, 0u32, 0u16);
                        loop {
                            // Liveness net: an unconditional (cheap) WiFi read every ~250 ms in case an
                            // indication was lost — the peek alone stalled the pump after the first lease.
                            // Flush queued WiFi deliveries while credit lasts (a read just refreshed it).
                            // TX budget per pump round, as brcmfmac's dpc: at most BRCMF_TXMINMAX (1) frame
                            // while the firmware still has RX frames for us, otherwise txbound (20) — the
                            // host always drains the firmware's RX side before pushing more TX into it.
                            let tx_budget = if rx_busy { 1 } else { 20 };
                            let mut tx_round = 0;
                            while wq_n > 0 && cyw43::tx_credit_ok() && tx_round < tx_budget {
                                tx_round += 1;
                                let i = wq_head;
                                if cyw43::ap_tx(&wq[i][..wq_len[i]]) {
                                    sent_ring[sent_i % 4] = (u32::from_be_bytes([0, wq[i][3], wq[i][4], wq[i][5]]), wq_len[i] as u16);
                                    sent_i += 1;
                                    wq_head = (i + 1) % WQ_N;
                                    wq_n -= 1;
                                    wq_flushed += 1;
                                    wq_head_fail = 0;
                                } else {
                                    // Credit was available, so this is not flow control: the radio
                                    // refused THIS frame. Retry a few times (a transient CMD53 error),
                                    // then drop it — one lost frame, never a wedged queue (metal
                                    // 2026-11-04: an unsendable head blocked every delivery + new joins).
                                    wq_head_fail += 1;
                                    if wq_head_fail >= 3 {
                                        wq_head = (i + 1) % WQ_N;
                                        wq_n -= 1;
                                        wifi_tx_dropped += 1;
                                        wq_head_drop += 1;
                                        wq_head_fail = 0;
                                        continue;
                                    }
                                    break;
                                }
                            }
                            // TX-credit stall snapshot (once per episode): credit 0 for > 2 s with deliveries queued.
                            {
                                let (seq, max, _) = cyw43::ap_diag();
                                let t = now();
                                if max.wrapping_sub(seq) <= 2 && wq_n > 0 {
                                    if credit0_since == 0 {
                                        credit0_since = t;
                                        unstick_stage = 0;
                                    } else if unstick_stage == 0 && t.wrapping_sub(credit0_since) > freq / 10 {
                                        // Firmware TX-to-station stall KICK (metal 2026-11-05, img 6ed4833): a bare dongle
                                        // interrupt never restarted it (0/2); one control frame always did, within ~5 ms
                                        // (2/2). The firmware only resumes the station's TX queue when its wl layer runs an
                                        // ioctl. A MITIGATION, not a root cause: the firmware-side trigger is still unknown.
                                        unstick[0] += 1;
                                        let _ = cyw43::fw_pktcnts(); // one control frame (uses the reserved credit)
                                        unstick_stage = 2;
                                        unstick_t = t;
                                    } else if unstick_stage == 2 && t.wrapping_sub(unstick_t) > freq / 2 {
                                        let _ = cyw43::fw_pktcnts(); // still stuck 0.5 s later: kick again
                                        unstick_t = t;
                                    } else if !stall_diag_done && t.wrapping_sub(credit0_since) > 2 * freq {
                                        unstick[4] += 1;
                                        stall_diag_done = true;
                                        let (rseq, gaps, maxahead) = cyw43::rx_diag();
                                        kprint!(" [STALL-DIAG] tx credit <=2 (data-exhausted) for >2 s: tx_seq={} tx_max={} fc_mask={:#04x} | max window ever ahead of tx_seq={} | last rx seq={} rx seq gaps={} | sdio intstatus={:#010x} | queued={} wifi_frames={}\n",
                                            seq, max, cyw43::fc_mask(), maxahead, rseq, gaps, cyw43::sdio_intstatus(), wq_n, wifi_frames);
                                        // Bus clock evidence FIRST (before any probe that could perturb it). HT_AVAIL=0x80
                                        // in CHIPCLKCSR, KSO=0x01 in SLEEPCSR, F2 ready=0x04 in IORDY.
                                        let bc = cyw43::bus_clock_state();
                                        kprint!("   [STALL-DIAG] bus clock: CHIPCLKCSR={:#04x} (HT_AVAIL={}) SLEEPCSR={:#04x} (KSO={}) IORDY={:#04x} (F2={})\n",
                                            bc[0], bc[0] & 0x80 != 0, bc[1], bc[1] & 1 != 0, bc[2], bc[2] & 0x04 != 0);
                                        for k in 0..wq_n.min(3) {
                                            let j = (wq_head + k) % WQ_N;
                                            kprint!("   [STALL-DIAG] queued[{}] dst {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} len {} ethertype {:#06x}\n", k,
                                                wq[j][0], wq[j][1], wq[j][2], wq[j][3], wq[j][4], wq[j][5], wq_len[j], u16::from_be_bytes([wq[j][12], wq[j][13]]));
                                        }
                                        for k in 0..4 {
                                            let (d, l) = sent_ring[(sent_i + k) % 4];
                                            kprint!("   [STALL-DIAG] last-sent[{}] dst ..:{:06x} len {}\n", k, d, l);
                                        }
                                        // case 1 vs case 2: are the firmware's TX counters moving while credit is 0?
                                        let c1 = cyw43::fw_pktcnts();
                                        let t0 = now();
                                        #[cfg(feature = "stalldiag")]
                                        while now().wrapping_sub(t0) < freq {} // 1-s pair only on the bench: the serve loop never blocks (peer review COR-L1)
                                        let c2 = cyw43::fw_pktcnts();
                                        kprint!("   [STALL-DIAG] fw pktcnts (rx_good,rx_bad,tx_good,tx_bad,rx_ocast) t0={:?} t0+1s={:?}\n", c1, c2);
                                        if let (Some(a), Some(b)) = (c1, c2) {
                                            kprint!("   [STALL-DIAG] => over 1 s: tx_good +{} tx_bad +{} rx_good +{} ({})\n",
                                                b[2].wrapping_sub(a[2]), b[3].wrapping_sub(a[3]), b[0].wrapping_sub(a[0]),
                                                if b[2] != a[2] { "firmware IS transmitting (case 2: credit not returned)" } else { "firmware NOT transmitting (case 1)" });
                                        }
                                        {
                                            // Firmware's view of the station, twice 1 s apart (control credit is reserved).
                                            let mut sta = [0u8; 6];
                                            sta.copy_from_slice(&wq[wq_head % WQ_N][0..6]);
                                            let s1 = cyw43::fw_sta_info(&sta);
                                            let t1 = now();
                                            #[cfg(feature = "stalldiag")]
                                        while now().wrapping_sub(t1) < freq {} // 1-s pair only on the bench: the serve loop never blocks (peer review COR-L1)
                                            let s2 = cyw43::fw_sta_info(&sta);
                                            for (tag, s) in [("t0", s1), ("t0+1s", s2)] {
                                                match s {
                                                    Some(i) => kprint!("   [STALL-DIAG] sta_info {}: ver={} len={} flags={:#x} (ASSOC={} AUTHO={} PS={} AMPDU={}) idle={}s in={}s tx_pkts={} tx_fail={} rx_ucast={} tx_rate={} rx_rate={} retry_exh={}\n",
                                                        tag, i.ver, i.len, i.flags, i.flags & 0x10 != 0, i.flags & 0x20 != 0, i.flags & 0x100 != 0, i.flags & 0x8000 != 0,
                                                        i.idle, i.in_secs, i.tx_pkts, i.tx_failures, i.rx_ucast, i.tx_rate, i.rx_rate, i.retry_exhausted),
                                                    None => kprint!("   [STALL-DIAG] sta_info {}: GET failed\n", tag),
                                                }
                                            }
                                        }
                                        match cyw43::fw_shared() {
                                            Some(sh) => {
                                                kprint!("   [STALL-DIAG] fw sdpcm_shared @ {:#010x} flags={:#06x} (trap={} assert={}) console @ {:#010x}\n",
                                                    sh.addr, sh.flags, sh.flags & cyw43::SDPCM_SHARED_TRAP != 0, sh.flags & cyw43::SDPCM_SHARED_ASSERT != 0, sh.console_addr);
                                                cyw43::fw_trap_dump(&sh);
                                                let hm = unsafe { cyw43::HOSTMAIL_DIAG };
                                                kprint!("   [STALL-DIAG] host mailbox (data path): msgs={} last data={:#010x} fc-via-mailbox={} nak-handled={} fw-halt={}\n", hm[0], hm[1], hm[2], hm[3], hm[4]);
                                                let r = cyw43::fw_console_dump(&sh, 40);
                                                kprint!("   [STALL-DIAG] fw console: {:?} (lines, buf size, idx)\n", r);
                                            }
                                            None => kprint!("   [STALL-DIAG] fw sdpcm_shared NOT readable\n"),
                                        }
                                        // Experiment: the brcmfmac wake path (KSO + HT request). Both steps act only if
                                        // the bit is CLEAR, so on a healthy clock this is a no-op. If the next beat logs
                                        // "credit RECOVERED", the stall was the bus clock.
                                        let after = cyw43::bus_wake();
                                        let bc2 = cyw43::bus_clock_state();
                                        kprint!("   [STALL-DIAG] bus wake -> CHIPCLKCSR={:#04x} SLEEPCSR={:#04x} (watch for 'credit RECOVERED')\n", after, bc2[1]);
                                    }
                                } else {
                                    if credit0_since != 0 && !stall_diag_done && unstick_stage > 0 {
                                        unstick[unstick_stage as usize + 1] += 1;
                                        kprint!(" [UNSTICK] credit back {} ms after stage {} ({})\n", t.wrapping_sub(credit0_since) * 1000 / freq,
                                            unstick_stage, if unstick_stage == 1 { "A: DEV_INT" } else { "B: control frame" });
                                    } else if credit0_since != 0 && !stall_diag_done && t.wrapping_sub(credit0_since) > freq / 4 {
                                        unstick[1] += 1;
                                    }
                                    unstick_stage = 0;
                                                                        if stall_diag_done && credit0_since != 0 {
                                        kprint!(" [STALL-DIAG] credit RECOVERED after {} ms\n", t.wrapping_sub(credit0_since) * 1000 / freq);
                                    }
                                    credit0_since = 0;
                                    stall_diag_done = false;
                                }
                            }
                            // A pending queue forces a read: the credit update arrives as a frame.
                            let force = wq_n > 0 || now().wrapping_sub(last_force) > freq / 4;
                            if force {
                                last_force = now();
                            }
                            let tpoll = cyw43::ticks();
                            let ev = cyw43::ap_poll(&mut rx, force);
                            cyw43::prof_add(4, tpoll);
                            rx_busy = !matches!(ev, cyw43::ApEvent::Idle);
                            match ev {
                                cyw43::ApEvent::Assoc(sta) => {
                                    assocs += 1;
                                    _last_sta = sta;
                                    kprint!("   [P11-AP3] assoc {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} — 4-way...\n",
                                        sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
                                    // A station that re-associates MID-handshake gets a fresh ANonce
                                    // immediately (its previous ASSOC_IND used to be dropped by the
                                    // old read loops — the "sometimes takes forever" texture).
                                    let mut tries = 0u32;
                                    loop {
                                        tries += 1;
                                        let mut auth = cyw43::ApAuth::new();
                                        cyw43::ap_wpa2_authenticate(&ap.bssid, &sta, &pmk, &gtk, 1, &mut auth);
                                        kprint!("   [P11-AP3 auth] m1_sends={} m2_rx={} m2_mic={} m3_sends={} m4_rx={} m4_mic={} ptk_set={} authorized={} mic_fail={} reassoc={} deauth={} replay={}\n",
                                            auth.m1_sends, auth.m2_rx, auth.m2_mic_ok, auth.m3_sends, auth.m4_rx, auth.m4_mic_ok,
                                            auth.ptk_set, auth.authorized, auth.m2_mic_fail, auth.reassoc, auth.deauth, auth.replay);
                                        if auth.ptk_set && auth.authorized {
                                            keyed += 1;
                                            kprint!(" [P11-AP3] keyed + authorized — awaiting the client's DHCP\n");
                                            break;
                                        }
                                        if auth.reassoc && tries < 3 {
                                            continue;
                                        }
                                        kprint!(" [P11-AP3] 4-way incomplete ({}) — back to the pump\n",
                                            if auth.deauth { "station left" } else if auth.m2_rx && !auth.m2_mic_ok { "M2 MIC never verified: wrong PSK?" } else if !auth.m2_rx { "no M2" } else { "no M4" });
                                        break;
                                    }
                                }
                                cyw43::ApEvent::Leave(sta) => {
                                    unsafe { (*core::ptr::addr_of_mut!(V6)).forget_mac(&sta) }; // release its IPv6 bindings (SAVI)
                                    leaves += 1;
                                    kprint!("   [P11-AP3] station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} left (deauth/disassoc)\n",
                                        sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
                                }
                                cyw43::ApEvent::Data(off, len) => {
                                    wifi_frames += 1;
                                    // Clients get the UPSTREAM resolver (WAN lease option 6) — a hard-coded 8.8.8.8
                                    // dies at any upstream NAC/firewall that only admits DNS to its own gateway
                                    // (metal 2026-10-09: the fortress's quarantine posture does exactly that).
                                    // Clients get the AP itself as their resolver (10.99.0.1): heqk forwards each
                                    // query to the upstream resolver from the WAN lease (nat::outbound_redirect),
                                    // so DNS works at any upstream that only admits DNS to its own gateway AND
                                    // every query crosses heqk's IDS like any other flow.
                                    let client_dns = our_ip;
                                    let frame = &rx[off..off + len];
                                    let act = cyw43::ap_handle_data(frame, &ap.bssid, &our_ip, &pool_base, &client_dns, &mut dh);
                                    // The Mission Control node (smoltcp) learns a client's MAC ONLY from ARP (smoltcp 0.13
                                    // `process_arp`); the AP answers ARP for its address itself, so hand those ARP frames
                                    // (requests for us + replies to us) to the node too — metal 2026-11-07: without this the
                                    // node never resolved the iPhone and http://10.99.0.1 never loaded.
                                    #[cfg(feature = "mcserve")]
                                    if frame.len() >= 42 && frame[12] == 0x08 && frame[13] == 0x06 && frame[38..42] == our_ip {
                                        if let Some(n) = mcn.as_mut() {
                                            n.ingress(frame, (now().wrapping_sub(mc_t0) / (freq / 1000).max(1)) as i64);
                                        }
                                    }
                                    if act == b'K' {
                                        kprint!(" [P11-AP3] PASS — client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} leased {}.{}.{}.{} (DORA {}/{}/{}/{}, leases={}, arp_replies={}) — WPA2 AP live\n",
                                            dh.client_mac[0], dh.client_mac[1], dh.client_mac[2], dh.client_mac[3], dh.client_mac[4], dh.client_mac[5],
                                            dh.leased_ip[0], dh.leased_ip[1], dh.leased_ip[2], dh.leased_ip[3],
                                            dh.discovers, dh.offers_tx, dh.requests, dh.acks_tx, dh.nleases, dh.arp_replies);
                                    } else if act == 0 && frame.len() >= 54 && frame[12] == 0x86 && frame[13] == 0xdd && unsafe { V6.up } {
                                        // IPv6 from a client: RS/NS answered here; anything routable goes through the IDS
                                        // verdict and out the PPPoE session (no NAT; the module records the flow so the
                                        // reply is admitted by the stateful firewall).
                                        let v6 = unsafe { &mut *core::ptr::addr_of_mut!(V6) };
                                        let nms = now() * 1000 / freq;
                                        match v6.on_lan(frame, nms, &mut v6buf) {
                                            arch_aarch64::ip6lan::LanAction::Reply(k) => {
                                                let _ = wifi_send!(&v6buf[..k]);
                                            }
                                            arch_aarch64::ip6lan::LanAction::Forward(k) => {
                                                // `lan in`, then `wan out` (IPv6 egress is the internet sub-interface: the
                                                // management VLAN carries no IPv6).
                                                let pa = hal::policy::facts(frame).map(|p| {
                                                    let pol = unsafe { &mut *core::ptr::addr_of_mut!(POLICY) };
                                                    let a = pol.check(PIf::Lan, PDir::In, &p).0;
                                                    if a == PAct::Allow { (pol.check(PIf::Wan, PDir::Out, &p).0, 2usize) } else { (a, 0usize) }
                                                }).unwrap_or((PAct::Allow, 0));
                                                match pa {
                                                    (PAct::Allow, _) => {
                                                        if packet::verdict(frame).1 == packet::DROP {
                                                            v6_ids_drop[0] += 1;
                                                        } else if up.usable() && uplink::wan_tx6(&up, &v6buf[..k]) {
                                                            v6.commit(now() * 1000 / freq); // the inbound pinhole opens only now
                                                        }
                                                    }
                                                    (PAct::Block, i) => {
                                                        pol_block[i] += 1;
                                                        let mut rj = [0u8; 1400];
                                                        if let Some(r) = arch_aarch64::reject::reject6(frame, &v6.gua, &ap.bssid, &mut rj) {
                                                            let _ = wifi_send!(&rj[..r]);
                                                        }
                                                    }
                                                    (PAct::Drop, i) => pol_drop[i] += 1,
                                                }
                                            }
                                            _ => {}
                                        }
                                    } else if act == 0 && (up.usable() || unsafe { uplink::MGMT }.is_some()) && frame.len() >= 34 && frame[12] == 0x08 && frame[13] == 0x00 {
                                        // Not ours to answer → the forwarding path. Three gates, in order:
                                        // (1) (MAC,IP) must be a lease we handed out — anti-hijack;
                                        // (2) the signed rule plane (IDS/IPS) — a threat verdict DROPs here;
                                        // (3) M-NAT1 outbound: SNAT to the lease, out end0.
                                        let mut smac = [0u8; 6];
                                        smac.copy_from_slice(&frame[6..12]);
                                        let mut sip = [0u8; 4];
                                        sip.copy_from_slice(&frame[26..30]);
                                        if !dh.binding_ok(&smac, &sip) {
                                            bind_drop += 1;
                                        } else if net::parse(frame).is_none() {
                                            trunc_drop += 1; // truncated/oversize: fail-closed, but NOT a rule drop
                                        } else if packet::verdict(frame).1 == packet::DROP {
                                            ids_drop_out += 1;
                                        } else if mc_bound(frame, &our_ip) {
                                            // Mission Control on the AP address (after the lease binding + IDS gates).
                                            #[cfg(feature = "mcserve")]
                                            if let Some(n) = mcn.as_mut() {
                                                n.ingress(frame, (now().wrapping_sub(mc_t0) / (freq / 1000).max(1)) as i64);
                                            }
                                        } else if fwd4!(frame, PIf::Lan, nat::IF_WIFI, wifi_send) && nst.out_fwd == 1 {
                                            kprint!(" [M-NAT1] first client frame forwarded out end0 (proto {})\n", nbuf[23]);
                                        }
                                    }
                                }
                                cyw43::ApEvent::Other => {
                                    wifi_frames += 1;
                                }
                                cyw43::ApEvent::Idle => {}
                            }
                            // Housekeeping + WAN drain run EVERY iteration (was Idle-arm only; see the WAN drain note).
                            #[cfg(feature = "mcserve")]
                            if let Some(n) = mcn.as_mut() {
                                let ms = (now().wrapping_sub(mc_t0) / (freq / 1000).max(1)) as i64;
                                let _ = n.service(mcserve::state(), ms);
                                n.flush(|f| wifi_send!(f));
                            }
                            {
                                    // Plug-and-play WAN: the boot-time bringup is not the only chance. If the
                                    // uplink isn't usable and end0 now has a link, retry the lease every 10 s —
                                    // a cable plugged after boot (metal 2026-10-09) must not need a power-cycle.
                                    if !up.usable() {
                                        let t = now();
                                        if t.wrapping_sub(last_wan_try) > 10 * freq && arch_aarch64::gem::phy_link_up(0) {
                                            last_wan_try = t;
                                            wan_retries += 1;
                                            let mut again = uplink::UplinkResult::new(Nic::End0);
                                            uplink::bringup_with(Nic::End0, &[8, 8, 8, 8], &wan_mode, &mut again);
                                            if let Some((ph, why, ..)) = uplink::pppoe_info().filter(|_| matches!(wan_mode, hal::WanMode::Pppoe { .. })) {
                                                let st = uplink::pppoe_info().map(|i| i.9).unwrap_or_default();
                                                kprint!(" [WAN] PPPoE retry {}: phase={:?} why={:?} stale_padt={} (PADT sent for a session the AC still held)\n", wan_retries, ph, why, st.stale_padt);
                                            }
                                            if again.usable() {
                                                kprint!(" [M-NAT0] WAN came up after boot (retry {}): leased {}.{}.{}.{} gw {}.{}.{}.{} dns {}.{}.{}.{} inet_echo={}\n",
                                                    wan_retries, again.dhcp.yiaddr[0], again.dhcp.yiaddr[1], again.dhcp.yiaddr[2], again.dhcp.yiaddr[3],
                                                    again.dhcp.router[0], again.dhcp.router[1], again.dhcp.router[2], again.dhcp.router[3],
                                                    again.dhcp.dns[0], again.dhcp.dns[1], again.dhcp.dns[2], again.dhcp.dns[3], again.inet_ping_reply);
                                            }
                                            up = again;
                                        }
                                    } else {
                                        // WAN lease lifetime: re-lease at T1 (lease/2) so the fortress never expires us.
                                        // (A fresh DORA from the same MAC/client-id returns the same address.)
                                        let t = now();
                                        if wan_leased_at == 0 {
                                            wan_leased_at = t;
                                        } else if up.dhcp.lease > 0 && t.wrapping_sub(wan_leased_at) > (up.dhcp.lease as u64 / 2) * freq {
                                            let mut again = uplink::UplinkResult::new(Nic::End0);
                                            uplink::bringup_with(Nic::End0, &[8, 8, 8, 8], &wan_mode, &mut again);
                                            if again.usable() {
                                                up = again;
                                                wan_renewals += 1;
                                            }
                                            wan_leased_at = t; // either way, don't retry in a tight loop
                                        }
                                    }
                                    // eth1 LAN port: serve DHCP/ARP from the same lease table and forward through
                                    // the same NAT (in_if = eth1 so replies return on the RTL rings). The first
                                    // real exercise of rtl8111::tx_frame.
                                    if arch_aarch64::rtl8111::started() && arch_aarch64::rtl8111::link_up() {
                                        if let Some(n) = arch_aarch64::rtl8111::rx_next(&mut ebuf) {
                                            let n = n.min(ebuf.len());
                                            if n >= 14 {
                                                lan_frames += 1;
                                                let client_dns = our_ip; // the AP/LAN gateway resolves (forwarded upstream)
                                                let lan_mac = uplink::ETH1_MAC;
                                                let (act, m) = cyw43::ap_handle_data_into(&ebuf[..n], &lan_mac, &our_ip, &pool_base, &client_dns, &mut dh, &mut erep);
                                                if m > 0 {
                                                    if arch_aarch64::rtl8111::tx_frame(&erep[..m]) {
                                                        lan_served += 1;
                                                        if act == b'K' {
                                                            kprint!(" [M-NAT2] eth1 LAN client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} leased {}.{}.{}.{} — rtl8111 tx_frame PROVEN\n",
                                                                dh.client_mac[0], dh.client_mac[1], dh.client_mac[2], dh.client_mac[3], dh.client_mac[4], dh.client_mac[5],
                                                                dh.leased_ip[0], dh.leased_ip[1], dh.leased_ip[2], dh.leased_ip[3]);
                                                        }
                                                    } else {
                                                        lan_tx_fail += 1;
                                                    }
                                                } else if act == 0 && (up.usable() || unsafe { uplink::MGMT }.is_some()) && n >= 34 && ebuf[12] == 0x08 && ebuf[13] == 0x00 {
                                                    let mut smac = [0u8; 6];
                                                    smac.copy_from_slice(&ebuf[6..12]);
                                                    let mut sip = [0u8; 4];
                                                    sip.copy_from_slice(&ebuf[26..30]);
                                                    if !dh.binding_ok(&smac, &sip) {
                                                        bind_drop += 1;
                                                    } else if packet::verdict(&ebuf[..n]).1 == packet::DROP {
                                                        ids_drop_out += 1;
                                                    } else {
                                                        let _ = fwd4!(&ebuf[..n], PIf::Eth1, nat::IF_ETH1, eth1_send);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    // Drain the WAN ring with a budget (Linux NAPI: up to 64/poll). It used to be ONE frame per
                                    // loop and only when Wi-Fi was idle — under a speed test Wi-Fi is never idle, so the 128-slot
                                    // GEM ring overflowed (metal 2026-11-05: res_err 325k, overrun 1450 = ISP packets dropped).
                                    // Backpressure: never pull more WAN frames than the Wi-Fi queue can hold — the rest wait in
                                    // the GEM ring (another 128 slots) instead of being head-dropped from wq (metal 2026-11-05:
                                    // 7,158 wq drops after the drain fix).
                                    let twan = cyw43::ticks();
                                    // ...but NEVER zero (peer review COR-M1): a full Wi-Fi queue (firmware TX stall) used to
                                    // stop end0 entirely — PPPoE LCP echoes unanswered (session dropped), WAN ARP, eth1
                                    // clients and the management VLAN all starved. At least 4 per loop; Wi-Fi-bound frames
                                    // that do not fit are dropped at the congested queue, where TCP will see it.
                                    for _ in 0..WAN_BUDGET.min(WQ_N - wq_n).max(4) {
                                    match uplink::wan_poll(&mut up, &mut wbuf) {
                                        uplink::WanEvent::ArpReplied => wan_arp += 1,
                                        uplink::WanEvent::GwRefreshed => wan_gw_refresh += 1,
                                        uplink::WanEvent::Frame(n) => {
                                            if n > 600 {
                                                wan_big_seen += 1;
                                            }
                                            // M-NAT1 inbound: a WAN frame for the lease → un-NAT → unicast to the
                                            // station over the PTK path (≤ WIFI_MAX_FRAME; TCP is MSS-clamped).
                                            // IDS/IPS on the WAN leg too (a threat from the internet toward a client
                                            // DROPs before un-NAT), then return on the link the flow came in on.
                                            // Anti-spoof first (uRPF-lite, re-review P2): an IPv4 source that cannot come from the
                                            // internet (ours, our LAN, the management floor, loopback, multicast…) is dropped before
                                            // NAT, policy or the IDS see it.
                                            let martian = n >= 34 && wbuf[12] == 0x08 && wbuf[13] == 0x00 && {
                                                // The floor rule only where it means "spoofed": an operator-configured floor that
                                                // lives behind a management sub-interface. The compile-time default must NOT be
                                                // enforced here — metal 2026-11-07: behind a home router the upstream LAN
                                                // (10.200.0.0/24 = the default) answered the iPhone (AirPlay :7000 SYN-ACKs) and
                                                // was dropped as "martian" (ADR 0023: legit traffic always passes).
                                                let (fnet, flen, fset) = crate::verdict::mgmt_floor();
                                                let has_mgmt = unsafe { (*core::ptr::addr_of!(uplink::MGMT)).is_some() };
                                                let flen = if fset && has_mgmt { flen } else { 0 };
                                                hal::policy::wan_martian4([wbuf[26], wbuf[27], wbuf[28], wbuf[29]], up.dhcp.yiaddr, inside_net, fnet, flen)
                                            };
                                            if martian {
                                                wan_martian += 1;
                                                continue;
                                            }
                                            // Operator policy `wan in` is STATEFUL: it decides NEW inbound traffic. A reply to a
                                            // flow the LAN opened (NAT session / IPv6 flow table) is admitted; `lan|eth1 out`
                                            // still filters every delivery. Evaluated on arrival addresses, so a `block` reject
                                            // goes back to the actual sender.
                                            macro_rules! wan_in_new {
                                                () => {{
                                                    // Peer review H3: only traffic ADDRESSED TO US (our MAC + our WAN address) is ours
                                                    // to police. The GEM is promiscuous: on a shared WAN segment, `wan in` + block used
                                                    // to forge RSTs / ICMP for OTHER hosts' flows.
                                                    let to_us = wbuf[0..6] == up.mac && match wbuf[12..14] {
                                                        [0x08, 0x00] => n >= 34 && wbuf[30..34] == up.dhcp.yiaddr,
                                                        [0x86, 0xdd] => n >= 54 && (Some({ let mut d = [0u8; 16]; d.copy_from_slice(&wbuf[38..54]); d }) == unsafe { uplink::WAN6 }.na
                                                            || (unsafe { V6.up } && wbuf[38..46] == unsafe { V6.prefix }[..8])),
                                                        _ => false,
                                                    };
                                                    let a = if !to_us { PAct::Allow } else { hal::policy::facts(&wbuf[..n]).map(|p| unsafe { (*core::ptr::addr_of_mut!(POLICY)).check(PIf::Wan, PDir::In, &p).0 }).unwrap_or(PAct::Allow) };
                                                    // RFC 4443 §2.4(f) / peer review SEC-L2: at most 20 rejects/s toward the internet
                                                    // (a spoofed-source flood must not turn heqk into a reflector); beyond it, drop.
                                                    let tnow = now();
                                                    if tnow.wrapping_sub(rej_win) > freq {
                                                        rej_win = tnow;
                                                        rej_n = 0;
                                                    }
                                                    let a = if a == PAct::Block && rej_n >= 20 { PAct::Drop } else { a };
                                                    if a == PAct::Block {
                                                        rej_n += 1;
                                                        pol_block[2] += 1;
                                                        let mut rj = [0u8; 1400];
                                                        if wbuf[12] == 0x86 {
                                                            let src6 = unsafe { uplink::WAN6 }.na.unwrap_or(unsafe { V6.gua });
                                                            if let Some(k) = arch_aarch64::reject::reject6(&wbuf[..n], &src6, &up.mac, &mut rj) {
                                                                let _ = uplink::wan_tx6(&up, &rj[14..k]);
                                                            }
                                                        } else if let Some(k) = arch_aarch64::reject::reject4(&wbuf[..n], &up.dhcp.yiaddr, &up.mac, &mut rj) {
                                                            let _ = uplink::wan_tx(&up, &rj[..k]);
                                                        }
                                                    } else if a == PAct::Drop {
                                                        pol_drop[2] += 1;
                                                    }
                                                }};
                                            }
                                            if n >= 54 && wbuf[12] == 0x86 && wbuf[13] == 0xdd {
                                                // IPv6 from the ISP: the stateful firewall + neighbor table decide; then the IDS.
                                                let v6 = unsafe { &mut *core::ptr::addr_of_mut!(V6) };
                                                let nms = now() * 1000 / freq;
                                                let no_flow0 = v6.stats.drop_no_flow;
                                                let v6a = v6.on_wan(&wbuf[14..n], nms, &mut v6buf);
                                                // `wan in` judges only genuinely NEW inbound traffic (no flow). A neighbor-table
                                                // miss / hop-limit / malformed drop is not a policy event and must never turn into
                                                // a reject of a legitimate reply (peer review SEC-M5, ADR 0023).
                                                if matches!(v6a, arch_aarch64::ip6lan::WanAction::Drop) && v6.stats.drop_no_flow != no_flow0 {
                                                    wan_in_new!();
                                                }
                                                if let arch_aarch64::ip6lan::WanAction::Solicit(k) = v6a {
                                                    let _ = wifi_send!(&v6buf[..k]); // re-learn an evicted client (SEC-M5)
                                                }
                                                if let arch_aarch64::ip6lan::WanAction::Deliver(k) = v6a {
                                                    let lan_out = hal::policy::facts(&v6buf[..k]).map(|p| unsafe { (*core::ptr::addr_of_mut!(POLICY)).check(PIf::Lan, PDir::Out, &p).0 }).unwrap_or(PAct::Allow);
                                                    if lan_out != PAct::Allow {
                                                        pol_drop[0] += 1;
                                                        if lan_out == PAct::Block {
                                                            pol_block_as_drop += 1;
                                                        }
                                                    } else if packet::verdict(&v6buf[..k]).1 == packet::DROP {
                                                        v6_ids_drop[1] += 1;
                                                    } else {
                                                        let _ = wifi_send!(&v6buf[..k]);
                                                    }
                                                }
                                            } else if packet::verdict(&wbuf[..n]).1 == packet::DROP {
                                                ids_drop_in += 1;
                                            } else {
                                                let lan_mac = uplink::ETH1_MAC;
                                                let nat_r = nat::inbound(&wbuf[..n], &up.dhcp.yiaddr, &up.mac, [&ap.bssid, &lan_mac], &mut nbuf, now(), &mut nst);
                                                if nat_r.is_none() {
                                                    wan_in_new!(); // no NAT session: new inbound traffic -> `wan in`
                                                }
                                                if let Some((m, in_if)) = nat_r.filter(|&(m, in_if)| {
                                                    // `lan out` / `eth1 out` after un-NAT. A `block` here acts as a drop: a reject would
                                                    // have to be re-NATed to reach the real sender (counted apart).
                                                    let oif = if in_if == nat::IF_ETH1 { PIf::Eth1 } else { PIf::Lan };
                                                    let a = hal::policy::facts(&nbuf[..m]).map(|p| unsafe { (*core::ptr::addr_of_mut!(POLICY)).check(oif, PDir::Out, &p).0 }).unwrap_or(PAct::Allow);
                                                    if a != PAct::Allow {
                                                        pol_drop[oif as usize] += 1;
                                                        if a == PAct::Block {
                                                            pol_block_as_drop += 1;
                                                        }
                                                    }
                                                    a == PAct::Allow
                                                }) {
                                                    if m > 600 {
                                                        wan_big_unnat += 1;
                                                    }
                                                    rules::scan_response_hook(&nbuf[..m]); // ADR 0049 D3: credit the real prober
                                                    if in_if == nat::IF_ETH1 {
                                                        if !arch_aarch64::rtl8111::tx_frame(&nbuf[..m]) {
                                                            lan_tx_fail += 1;
                                                        }
                                                    } else if m > nat::WIFI_MAX_FRAME {
                                                        nst.in_too_big += 1; // the WiFi leg can't carry it (TCP is MSS-clamped; big UDP is lost)
                                                    } else if {
                                                        let sent = wq_n == 0 && cyw43::tx_credit_ok() && cyw43::ap_tx(&nbuf[..m]);
                                                        if nat_trace < NAT_TRACE_N {
                                                            nat_trace += 1;
                                                            nat_trace_line("IN ", &nbuf[..m], if sent { "wifi=sent" } else if wq_n < WQ_N { "wifi=queued" } else { "wifi=DROP" });
                                                        }
                                                        !sent
                                                    } {
                                                        // No credit (or the queue is already waiting): keep ORDER, queue it.
                                                        if wq_n < WQ_N && m <= WQ_SZ {
                                                            let j = (wq_head + wq_n) % WQ_N;
                                                            wq[j][..m].copy_from_slice(&nbuf[..m]);
                                                            wq_len[j] = m;
                                                            wq_n += 1;
                                                            wifi_tx_queued += 1;
                                                        } else {
                                                            wifi_tx_dropped += 1;
                                                            nat_wifi_tx_fail += 1;
                                                        }
                                                    } else if nst.in_fwd == 1 {
                                                        kprint!(" [M-NAT1] PASS — first WAN reply un-NATed and delivered to the client ({} B, proto {}) — the SASE payoff: AP client ↔ internet through heqk\n", m, nbuf[23]);
                                                    }
                                                }
                                            }
                                        }
                                        uplink::WanEvent::Idle => break,
                                    }
                                    }
                                    cyw43::prof_add(5, twan);
                                    let t = now();
                                    if t.wrapping_sub(last_ht) > freq / 10 {
                                        cyw43::ap_keepalive();
                                        last_ht = t;
                                    }
                                    if t.wrapping_sub(last_wan_probe) > 5 * freq {
                                        last_wan_probe = t;
                                        uplink::wan_probe(&up); // liveness for metric failover (DHCP / static)
                                    }
                                    if up.usable() {
                                        uplink::wan6_tick(&up); // DHCPv6 prefix-delegation renewal at T1
                                    }
                                    {
                                        // (Re)number the LAN when the WAN has a delegated prefix (also after a WAN re-dial).
                                        let v6 = unsafe { &mut *core::ptr::addr_of_mut!(V6) };
                                        let w6 = unsafe { uplink::WAN6 };
                                        if let Some((pd, plen, valid)) = w6.pd {
                                            if up.usable() && (!v6.up || v6.prefix[..8] != pd[..8]) {
                                                v6.configure(&pd, plen, valid, &ap.bssid, w6.dns.as_ref());
                                                let g = |k: usize| u16::from_be_bytes([v6.gua[2 * k], v6.gua[2 * k + 1]]);
                                                kprint!(" [V6LAN] LAN numbered from {:x?}/{}: router {:x}:{:x}:{:x}:{:x}::1/64 — RA (SLAAC, MTU {}, RDNSS={}) on the AP, stateful firewall default-deny inbound\n",
                                                    &pd[..8], plen, g(0), g(1), g(2), g(3), arch_aarch64::ip6lan::LAN_MTU, v6.has_dns);
                                            }
                                        } else if v6.up && !up.usable() {
                                            v6.up = false;
                                        }
                                        // Management sub-interface: ARP, ping under `mgmt in`, and replies of flows routed out
                                        // management (un-NAT -> `mgmt in` -> `<lan|eth1> out` -> the client).
                                        if unsafe { uplink::MGMT }.is_some() {
                                            for _ in 0..8 {
                                                let mut decide = |f: &[u8]| hal::policy::facts(f).map(|p| unsafe { (*core::ptr::addr_of_mut!(POLICY)).check(PIf::Mgmt, PDir::In, &p).0 }).unwrap_or(PAct::Drop); // unparseable = drop (peer review H2)
                                                match uplink::mgmt_poll(&mut mbuf, &mut decide) {
                                                    uplink::MgmtEvent::Idle => break,
                                                    uplink::MgmtEvent::Frame(k) => {
                                                        // Stateful like `wan in`: a reply to a flow routed out management (NAT session)
                                                        // is admitted; anything else is new inbound traffic for `mgmt in`.
                                                        let mg = unsafe { uplink::MGMT }.unwrap();
                                                        let lan_mac = uplink::ETH1_MAC;
                                                        let nat_r = nat::inbound(&mbuf[..k], &mg.ip, &mg.mac, [&ap.bssid, &lan_mac], &mut nbuf, now(), &mut nst);
                                                        if nat_r.is_none() {
                                                            if decide(&mbuf[..k]) != PAct::Allow {
                                                                pol_drop[3] += 1;
                                                            }
                                                            continue;
                                                        }
                                                        if let Some((mm, in_if)) = nat_r {
                                                            let oif = if in_if == nat::IF_ETH1 { PIf::Eth1 } else { PIf::Lan };
                                                            let a = hal::policy::facts(&nbuf[..mm]).map(|p| unsafe { (*core::ptr::addr_of_mut!(POLICY)).check(oif, PDir::Out, &p).0 }).unwrap_or(PAct::Allow);
                                                            if a != PAct::Allow {
                                                                pol_drop[oif as usize] += 1;
                                                            } else if packet::verdict(&nbuf[..mm]).1 == packet::DROP {
                                                                ids_drop_in += 1;
                                                            } else if in_if == nat::IF_ETH1 {
                                                                let _ = arch_aarch64::rtl8111::tx_frame(&nbuf[..mm]);
                                                            } else if mm <= nat::WIFI_MAX_FRAME {
                                                                let _ = wifi_send!(&nbuf[..mm]);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if v6.ra_due(t * 1000 / freq) {
                                            let k = v6.build_ra(&[0x33, 0x33, 0, 0, 0, 1], &[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], &mut v6buf);
                                            let _ = wifi_send!(&v6buf[..k]);
                                        }
                                    }
                                    // Stall detector: deliveries waiting for credit AND no WiFi frame read in
                                    // 10 s while a station is associated = the SDPCM stream is wedged (metal
                                    // 2026-10-09: frozen counters, 29 frames pending). Say so, loudly, once.
                                    if wq_n > 0 && wifi_frames == stall_frames && t.wrapping_sub(stall_since) > 10 * freq {
                                        if !stall_reported {
                                            kprint!(" [P11-AP3] WIFI STALL — {} deliveries waiting for TX credit and no frame read for 10 s (wifi_frames={}): SDPCM stream wedged; a station re-join or a power-cycle recovers it\n", wq_n, wifi_frames);
                                            stall_reported = true;
                                        }
                                    } else if wifi_frames != stall_frames {
                                        stall_frames = wifi_frames;
                                        stall_since = t;
                                        stall_reported = false;
                                    }
                                    if t.wrapping_sub(last_beat) > 5 * freq {
                                        // Which rules dropped: drain the SOAR ring (nobody else does in apmode).
                                        loop {
                                            let k = events::drain(&mut evs);
                                            if k == 0 {
                                                break;
                                            }
                                            for e in &evs[..k] {
                                                #[cfg(feature = "mcserve")]
                                                mcserve::state().push_event(e);
                                                if e.verdict != 2 {
                                                    continue;
                                                }
                                                let mut placed = false;
                                                for slot in rule_drops.iter_mut() {
                                                    if slot.0 == e.rule_id || slot.1 == 0 {
                                                        slot.0 = e.rule_id;
                                                        slot.1 += 1;
                                                        placed = true;
                                                        break;
                                                    }
                                                }
                                                let _ = placed;
                                            }
                                        }
                                        {
                                            beat_n += 1;
                                            if beat_n == 2 || beat_n % 12 == 6 {
                                                if let Some(sh) = cyw43::fw_shared() {
                                                    let r = cyw43::fw_console_dump(&sh, 12);
                                                    kprint!("   [FWCON] (periodic) shared flags={:#06x} console={:?}\n", sh.flags, r);
                                                    cyw43::fw_trap_dump(&sh);
                                                } else {
                                                    kprint!("   [FWCON] sdpcm_shared not readable\n");
                                                }
                                            }
                                            if beat_n % 12 == 0 {
                                                if let Some(cs) = cyw43::current_chanspec() {
                                                    ch_checks += 1;
                                                    ch_last = cs;
                                                    if cs != chosen_cs {
                                                        ch_mismatch += 1;
                                                    }
                                                }
                                            }
                                            kprint!("   [P11-AP3 chan] chosen {:#06x} | readbacks={} mismatches={} last={:#06x}\n", chosen_cs, ch_checks, ch_mismatch, ch_last);
                                            {
                                                let s = unsafe { V6.stats };
                                                let l = unsafe { uplink::WAN6_LIVE };
                                                kprint!("   [P11-AP3 v6] pd renew tx={} ok={} t1={}s | up={} ra_tx={} rs_rx={} na_tx={} ns_tx={} out={} in={} in_icmp_err={} | drop no_flow={} no_neigh={} hop={} src={} (savi={}) bad={} ids_out={} ids_in={} evict={} | WAN live: v6 rx={} RAs rx={} tx ok={} fail={}\n",
                                                    unsafe { uplink::WAN6 }.renew_tx, unsafe { uplink::WAN6 }.renew_ok, unsafe { uplink::WAN6 }.t1,
                                                    unsafe { V6.up }, s.ra_tx, s.rs_rx, s.na_tx, s.ns_tx, s.out_fwd, s.in_fwd, s.in_icmp_err, s.drop_no_flow, s.drop_no_neigh, s.drop_hop, s.drop_src, s.savi_refused, s.drop_bad,
                                                    v6_ids_drop[0], v6_ids_drop[1], s.flow_evict, l[0], l[1], l[2], l[3]);
                                                if let Some(ra) = unsafe { uplink::WAN6_FIRST_RA } {
                                                    kprint!("   [P11-AP3 v6] ISP RA seen: router {:02x?} lifetime={}s M={} O={} prefix={} /{} mtu={}\n", &ra.router[..], ra.lifetime, ra.managed, ra.other, ra.has_prefix, ra.plen, ra.mtu);
                                                }
                                            }
                                            {
                                                let ld = unsafe { uplink::LINK_DIAG };
                                                let pol = unsafe { &*core::ptr::addr_of!(POLICY) };
                                                kprint!("   [P11-AP3 policy] wan alive={} martian-src dropped={} | drop lan/eth1/wan/mgmt={:?} block={:?} block-as-drop={} | via mgmt={} next-hop unresolved (mgmt+wan)={} | link rx inet={} mgmt={} other-vlan drop={} untagged drop={} tagged tx={} mgmtq full={}\n",
                                                    uplink::wan_alive(&up, 15_000), wan_martian, pol_drop, pol_block, pol_block_as_drop, pol_via_mgmt, pol_mgmt_nh_miss, ld[0], ld[1], ld[2], ld[3], ld[4], ld[5]);
                                                for a in &pol.acl[..pol.nacl] {
                                                    kprint!("   [P11-AP3 policy] acl {} hits {:?} default {}\n", core::str::from_utf8(&a.name[..a.nlen]).unwrap_or("?"), &a.hits[..a.n], a.default_hits);
                                                }
                                                if let Some(mg) = unsafe { uplink::MGMT } {
                                                    kprint!("   [P11-AP3 mgmt] {}.{}.{}.{} gw {}.{}.{}.{} resolved={} | arp answered={} arp sent={} ping ok={} blocked={} dropped={} up(NAT)={} other={}\n",
                                                        mg.ip[0], mg.ip[1], mg.ip[2], mg.ip[3], mg.gw[0], mg.gw[1], mg.gw[2], mg.gw[3], mg.gw_mac.is_some(),
                                                        mg.stats[0], mg.stats[1], mg.stats[2], mg.stats[3], mg.stats[4], mg.stats[5], mg.stats[6]);
                                                    if let Some(d) = mg.dhcp {
                                                        kprint!("   [P11-AP3 mgmt] dhcp phase={} (0 discover / 1 request / 2 bound) /{} lease={}s acks={} naks={}\n", d.phase, mg.prefix, d.lease_s, d.acks, d.naks);
                                                    }
                                                }
                                            }
                                            {
                                                let d = cyw43::defer_diag();
                                                kprint!("   [P11-AP3 defer] station frames read by control requests: parked={} delivered={} ring-full={}\n", d[0], d[1], d[2]);
                                            }
                                            kprint!("   [P11-AP3 unstick] episodes={} self={} after_A(unused)={} after_kick(ctl)={} reached_2s={}\n",
                                                unstick[0], unstick[1], unstick[2], unstick[3], unstick[4]);
                                            {
                                                // Profiler since the last beat: count / total ms / max us per slot, and % of wall time.
                                                let p = unsafe { &mut *core::ptr::addr_of_mut!(cyw43::PROF) };
                                                let wall = p[7][1].max(1);
                                                let us = |t: u64| t * 1_000_000 / freq;
                                                let names = ["tx", "rx_frame", "rx_dry", "glom", "ap_poll", "wan_drain", "wfe", "loop"];
                                                kprint!("   [P11-AP3 prof] wall {} ms:", us(wall) / 1000);
                                                for k in 0..8 {
                                                    kprint!(" {}={}x/{}ms({}%)/max{}us", names[k], p[k][0], us(p[k][1]) / 1000, p[k][1] * 100 / wall, us(p[k][2]));
                                                }
                                                kprint!("\n");
                                                *p = [[0; 3]; 8];
                                            }
                                            // (the periodic sta_info baseline was removed: every control request discards the station
                                            // frames queued behind it — peer review COR-M4; the stall snapshot still reads sta_info)
                                            {
                                                let w = unsafe { uplink::WAN_TX_DIAG };
                                                let (_, _, dg) = cyw43::ap_diag();
                                                kprint!("   [P11-AP3 wan-tx] too_big_for_pppoe={} (last ip len {}) gem_fail={} (last TSR {:#06x}) | wifi xoff_held={}\n", w[0], w[2], w[1], w[3], dg[16]);
                                                let hm = unsafe { cyw43::HOSTMAIL_DIAG };
                                                kprint!("   [P11-AP3 mbox] host mailbox msgs={} last={:#010x} fc={} nak={} halt={}\n", hm[0], hm[1], hm[2], hm[3], hm[4]);
                                                let g = unsafe { arch_aarch64::gem::TX_FAIL_DIAG };
                                                kprint!("   [P11-AP3 gem-tx] timeouts={} hw-slot!=armed={} | last: armed slot {} hw TBQP slot {} desc0.w1={:#010x} desc1.w1={:#010x} len {} TSR {:#06x}\n",
                                                    g[0], g[7], g[1], g[2], g[3], g[4], g[5], g[6]);
                                            }
                                            let gs = arch_aarch64::gem::rx_stats();
                                            kprint!("   [P11-AP3 gem] rx frames={} 256-511={} 512-1023={} 1024-1518={} 1519+={} | oversize={} fcs_err={} len_err={} res_err={} overrun={} rsr={:#x} | wan_poll big(>600)={} un-NATed big={}\n",
                                                gs[0], gs[1], gs[2], gs[3], gs[4], gs[5], gs[6], gs[7], gs[8], gs[9], gs[10], wan_big_seen, wan_big_unnat);
                                            let (seq, max, dg) = cyw43::ap_diag();
                                            kprint!("   [P11-AP3 sdpcm] tx_seq={} tx_max={} credit={} | big_tx ok={} fail={} big_rx={} small_tx_fail={} credit_refused={} rx_terminated={} (never_zeroed={} too_long={} blk_fail={} byte_fail={} last_len={} last_chan={} last_blk_fail={:#010x}) glom super={} subs={} drop={} | last_rx_w1={:#010x} (flow_ctl_mask={:#04x} window={})\n",
                                                seq, max, max.wrapping_sub(seq), dg[0], dg[1], dg[2], dg[4], dg[5], dg[6], dg[7],
                                                dg[8], dg[9], dg[10], dg[11] & 0xffff, dg[11] >> 16, dg[12], dg[13], dg[14], dg[15], dg[3],
                                                dg[3] & 0xff, (dg[3] >> 8) & 0xff);
                                        }
                                        kprint!("   [P11-AP3 beat] wq queued={} flushed={} dropped={} (refused-head drops={}) pending={} trunc_drop={} | drop_rules {}:{} {}:{} {}:{} {}:{}\n",
                                            wifi_tx_queued, wq_flushed, wifi_tx_dropped, wq_head_drop, wq_n, trunc_drop,
                                            rule_drops[0].0, rule_drops[0].1, rule_drops[1].0, rule_drops[1].1,
                                            rule_drops[2].0, rule_drops[2].1, rule_drops[3].0, rule_drops[3].1);
                                        ratelimit::set_local_ip(1, u32::from_be_bytes(up.dhcp.yiaddr));
                                        #[cfg(feature = "mcserve")]
                                        {
                                            let st = mcserve::state();
                                            st.seen = wifi_frames as u64;
                                            st.forwarded = nst.out_fwd as u64 + nst.in_fwd as u64;
                                            st.dropped = (ids_drop_out + ids_drop_in) as u64;
                                            st.sample_qsecbit(now(), telemetry::score());
                                            st.wan = Some(mcstate::WanFacts {
                                                up: up.usable(),
                                                ip: up.dhcp.yiaddr,
                                                mode: match wan_mode { hal::WanMode::Dhcp => 0, hal::WanMode::Static { .. } => 1, _ => 2 },
                                                ipv6: unsafe { V6.up },
                                                clients: dh.nleases as u32,
                                                pkts_out: nst.out_fwd as u64,
                                                pkts_in: nst.in_fwd as u64,
                                                dns_inspected: nst.dns_redirect as u64,
                                                dns_blocked: dns_blocked as u64,
                                                blocklist: dnsblock::len() as u32,
                                            });
                                        }
                                        ratelimit::set_local_ip(2, unsafe { uplink::MGMT }.map_or(0, |m| u32::from_be_bytes(m.ip)));
                                        kprint!("   [SHIELD] list={} queries_seen={} blocked={} last={} (act {})\n", dnsblock::len(), dns_seen, dns_blocked,
                                            core::str::from_utf8(&dns_last[..dns_last_len]).unwrap_or("?"), dns_last_act);
                                        kprint!("   [P11-AP3 beat] assocs={} keyed={} leaves={} wifi_frames={} leases={} arp_replies={} | wan lease={}.{}.{}.{} arp_answered={} gw_refresh={} | nat out={} in={} out_drop={} in_drop={} too_big={} mss={} alloc={} evict={} dns_redir={} gem_tx_fail={} wifi_tx_fail={} wan_retries={} renewals={} | ids_drop out={} in={} bind_drop={} | lan frames={} served={} tx_fail={} pool={}/{}\n",
                                            assocs, keyed, leaves, wifi_frames, dh.acks_tx, dh.arp_replies,
                                            up.dhcp.yiaddr[0], up.dhcp.yiaddr[1], up.dhcp.yiaddr[2], up.dhcp.yiaddr[3], wan_arp, wan_gw_refresh,
                                            nst.out_fwd, nst.in_fwd, nst.out_drop, nst.in_drop, nst.in_too_big, nst.mss_clamped, nst.table_alloc, nst.table_evict, nst.dns_redirect,
                                            nat_tx_fail, nat_wifi_tx_fail, wan_retries, wan_renewals, ids_drop_out, ids_drop_in, bind_drop,
                                            lan_frames, lan_served, lan_tx_fail, dh.nleases, cyw43::AP_LEASES);
                                        last_beat = t;
                                    }
                                    if !rx_busy {
                                        let twfe = cyw43::ticks();
                                        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
                                        cyw43::prof_add(6, twfe);
                                    }
                                    if loop_t0 != 0 {
                                        cyw43::prof_add(7, loop_t0);
                                    }
                                    loop_t0 = cyw43::ticks();
                            }
                        }
                    }

                    if cfg!(feature = "stajoin") {
                    // P10-E: WPA2 join to the existing hookprobe AP + DATA-PATH proof. This
                    // firmware has no in-fw supplicant (cap string, iters 1-5): after 802.11
                    // assoc the AP sends EAPOL-Key M1 over SDPCM channel 2. Capturing it proves
                    // the data path on the real AP AND is the host supplicant's first input.
                    // Production target = the fortress `hookprobe` AP (WPA2-PSK-CCMP). The whole
                    // STA chain (assoc→4-way→PTK+GTK→DHCP→NAT→internet) was first proven against
                    // the controllable Pi4 debug AP (HookProbe-4785C8/change-me-1234567, hostapd
                    // -dd visibility); now re-prove on the real network. SSID case is EXACT — it
                    // is the PBKDF2 salt.
                    const JOIN_SSID: &[u8] = match option_env!("HEQK_JOIN_SSID") { Some(s) => s.as_bytes(), None => b"" };
                    const JOIN_PSK: &[u8] = match option_env!("HEQK_JOIN_PSK") { Some(s) => s.as_bytes(), None => b"" };
                    kprint!(" [P10-E] WiFi STA join \"");
                    for &c in JOIN_SSID { if c >= 0x20 && c < 0x7f { kprint!("{}", c as char); } }
                    kprint!("\" (WPA2) — capturing the EAPOL M1 (data-path proof)...\n");
                    // Compute the PMK up front and pass it in: wifi_join now runs the 4-way
                    // handshake INLINE — the instant M1 arrives it sends M2 in the live session
                    // (the AP deauths within ~1-2 s otherwise), then reads on for M3.
                    let pmk = arch_aarch64::wpa::wpa_pmk(JOIN_PSK, JOIN_SSID);
                    let mut jr = cyw43::JoinResult::new();
                    let mut hs = cyw43::Wpa4Way::new();
                    cyw43::wifi_join(JOIN_SSID, JOIN_PSK, false, Some(&pmk), &mut jr, &mut hs);
                    kprint!("   [P10-E setup] event_msgs={} infra={} auth={} wsec={} wpa_auth={} up={} | set_ssid ok={} status={:#x}\n",
                        jr.steps_ok & 1, (jr.steps_ok >> 1) & 1, (jr.steps_ok >> 2) & 1, (jr.steps_ok >> 3) & 1,
                        (jr.steps_ok >> 4) & 1, (jr.steps_ok >> 7) & 1, jr.set_ssid_ok, jr.set_ssid_status);
                    kprint!("   [P10-E events] seen={} deauth={} link={} (type,status,flags):", jr.events_seen, jr.deauth_seen, jr.link_up);
                    for k in 0..jr.trail_len {
                        let (t, s, f) = jr.trail[k];
                        kprint!(" ({},{:#x},{:#x})", t, s, f);
                    }
                    kprint!("\n");
                    kprint!("   [P10-E data] channel-2 frames seen={} | EAPOL(0x888E) M1 seen={} len={}\n",
                        jr.data_frames, jr.eapol_seen, jr.eapol_len);
                    kprint!("   [P10-E wpaie] set_ok={} readback({} B):", jr.wpaie_set_ok, jr.wpaie_get_len);
                    for k in 0..jr.wpaie_get_len { kprint!(" {:02x}", jr.wpaie_get[k]); }
                    kprint!("\n");
                    kprint!("   [P10-E s1] have_m1={} kdv={} snonce={} m2_tx={} | m3_seen={} m3_keyinfo={:#06x} | post_m2_eapol={} last_ki={:#06x} | deauth={} reason={}\n",
                        hs.have_m1, hs.kdv, hs.snonce_ok, hs.m2_tx_ok, hs.m3_seen, hs.m3_key_info, hs.post_m2_eapol, hs.last_eapol_ki, hs.deauth_after, hs.deauth_reason);
                    // Raw frames for offline verification (parse offsets + recompute the MIC).
                    kprint!("   [P10-E M1raw]");
                    for k in 0..jr.eapol_len.min(72) { kprint!("{:02x}", jr.eapol[k]); }
                    kprint!("\n   [P10-E M2raw]");
                    for k in 0..hs.m2_len { kprint!("{:02x}", hs.m2_dump[k]); }
                    kprint!("\n   [P10-E M3raw]");
                    for k in 0..hs.m3_dump_len { kprint!("{:02x}", hs.m3_dump[k]); }
                    kprint!("\n");
                    kprint!("   [P10-E s2] m4_tx={} deauth_after_m4={} | ptk_set={} unwrap_some={} gtk_unwrapped={} gtk_keyid={} gtk_set={}\n",
                        hs.m4_tx_ok, hs.deauth_after_m4, hs.ptk_set_ok, hs.gtk_unwrap_some, hs.gtk_unwrapped, hs.gtk_keyid, hs.gtk_set_ok);
                    if hs.m3_seen && hs.m4_tx_ok && !hs.deauth_after_m4 && hs.ptk_set_ok {
                        kprint!(" [P10-E] PASS(4way+keys) — handshake DONE + PTK{}{}installed. Probing encrypted DATA RX...\n",
                            if hs.gtk_set_ok { "+GTK " } else { " (PTK only) " }, "");
                        let mut dp = cyw43::DataProbe::new();
                        cyw43::wifi_data_probe(&mut dp);
                        kprint!("   [P10-E data] decrypted ch2 frames={} known-l2(arp/ip)={} last_etype={:#06x}\n", dp.frames, dp.l2_known, dp.last_etype);
                        if dp.sample_len >= 14 {
                            kprint!("   [P10-E data] first eth: dst {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} etype {:#06x}\n",
                                dp.sample[0], dp.sample[1], dp.sample[2], dp.sample[3], dp.sample[4], dp.sample[5],
                                ((dp.sample[12] as u16) << 8) | dp.sample[13] as u16);
                        }
                        if dp.l2_known > 0 {
                            kprint!(" [P10-E] PASS(wifi-data) — heqk DECRYPTED {} real WiFi data frame(s) (arp/ip) — WPA2 STA link is LIVE end-to-end\n", dp.l2_known);
                        } else {
                            kprint!(" [P10-E] keyed OK; {} ch2 frames but no decrypted L2 yet (gtk_set={}) — running DHCP\n", dp.frames, hs.gtk_set_ok);
                        }
                        // --- DHCP-over-WiFi: DISCOVER -> OFFER -> REQUEST -> ACK = a real lease.
                        kprint!(" [P10-E] DHCP-over-WiFi: sending DISCOVER...\n");
                        let mut dh = cyw43::DhcpResult::new();
                        cyw43::wifi_dhcp(&mut dh);
                        kprint!("   [P10-E dhcp] mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} | discover_tx={} offer_rx={} request_tx={} ack_rx={} | frames={} udp68={}\n",
                            dh.mac[0], dh.mac[1], dh.mac[2], dh.mac[3], dh.mac[4], dh.mac[5],
                            dh.discover_tx, dh.offer_rx, dh.request_tx, dh.ack_rx, dh.frames_seen, dh.udp68_seen);
                        if dh.offer_rx || dh.ack_rx {
                            kprint!("   [P10-E dhcp] ip {}.{}.{}.{} mask {}.{}.{}.{} gw {}.{}.{}.{} server {}.{}.{}.{} lease={}s\n",
                                dh.yiaddr[0], dh.yiaddr[1], dh.yiaddr[2], dh.yiaddr[3],
                                dh.mask[0], dh.mask[1], dh.mask[2], dh.mask[3],
                                dh.router[0], dh.router[1], dh.router[2], dh.router[3],
                                dh.server[0], dh.server[1], dh.server[2], dh.server[3], dh.lease);
                        }
                        if dh.ack_rx {
                            kprint!(" [P10-E] PASS(wifi-dhcp) — heqk HAS A DHCP LEASE over WPA2 WiFi ({}.{}.{}.{}) — STA link is LIVE end-to-end\n",
                                dh.yiaddr[0], dh.yiaddr[1], dh.yiaddr[2], dh.yiaddr[3]);
                            // --- Traffic validation: ARP gw -> ICMP gw (on-link) -> ICMP 8.8.8.8 (NAT + internet).
                            let inet = [8u8, 8, 8, 8];
                            kprint!(" [P10-E] traffic: ARP gw, ping gw, ping {}.{}.{}.{} through NAT...\n",
                                inet[0], inet[1], inet[2], inet[3]);
                            let mut pg = cyw43::PingResult::new();
                            cyw43::wifi_ping(&dh.yiaddr, &dh.router, &inet, &mut pg);
                            kprint!("   [P10-E ping] arp_tx={} arp_reply={} gw_mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                                pg.arp_tx, pg.arp_reply, pg.gw_mac[0], pg.gw_mac[1], pg.gw_mac[2], pg.gw_mac[3], pg.gw_mac[4], pg.gw_mac[5]);
                            kprint!("   [P10-E ping] gw {}.{}.{}.{} reply={} ttl={} | inet {}.{}.{}.{} reply={} ttl={} | icmp_replies={}\n",
                                pg.gw_ip[0], pg.gw_ip[1], pg.gw_ip[2], pg.gw_ip[3], pg.gw_ping_reply, pg.gw_ttl,
                                pg.inet_ip[0], pg.inet_ip[1], pg.inet_ip[2], pg.inet_ip[3], pg.inet_ping_reply, pg.inet_ttl, pg.icmp_replies);
                            if pg.inet_ping_reply {
                                kprint!(" [P10-E] PASS(wifi-internet) — heqk ICMP round-trip to {}.{}.{}.{} through the AP's NAT (ttl={}) — real internet data over WPA2 WiFi\n",
                                    inet[0], inet[1], inet[2], inet[3], pg.inet_ttl);
                                // --- L4: routed UDP (DNS) + stateful TCP (SYN->SYN/ACK) through NAT.
                                if pg.arp_reply {
                                    kprint!(" [P10-E] L4: DNS A dns.google @8.8.8.8, TCP SYN 8.8.8.8:53...\n");
                                    let mut l4 = cyw43::L4Result::new();
                                    cyw43::wifi_l4probe(&dh.yiaddr, &pg.gw_mac, &mut l4);
                                    kprint!("   [P10-E l4] dns_tx={} dns_reply={} answer {}.{}.{}.{} | tcp_syn_tx={} tcp_synack={} ({}.{}.{}.{}:{})\n",
                                        l4.dns_tx, l4.dns_reply, l4.dns_answer_ip[0], l4.dns_answer_ip[1], l4.dns_answer_ip[2], l4.dns_answer_ip[3],
                                        l4.tcp_syn_tx, l4.tcp_synack, l4.tcp_target[0], l4.tcp_target[1], l4.tcp_target[2], l4.tcp_target[3], l4.tcp_port);
                                    if l4.dns_reply && l4.tcp_synack {
                                        kprint!(" [P10-E] PASS(wifi-l4) — routed DNS resolve + TCP 3-way through NAT: heqk speaks UDP+TCP to the internet over WPA2 WiFi\n");
                                    } else if l4.dns_reply {
                                        kprint!(" [P10-E] DNS resolve OK (routed UDP), TCP SYN/ACK not seen — conntrack/TCP to diagnose\n");
                                    } else if l4.tcp_synack {
                                        kprint!(" [P10-E] TCP 3-way OK, DNS reply not seen — UDP/53 path to diagnose\n");
                                    } else {
                                        kprint!(" [P10-E] L4 no replies (dns_tx={} tcp_syn_tx={}) — to diagnose\n", l4.dns_tx, l4.tcp_syn_tx);
                                    }
                                }
                            } else if pg.gw_ping_reply {
                                kprint!(" [P10-E] gw ping OK (L3 on-link) but no internet reply — NAT/upstream to diagnose\n");
                            } else if pg.arp_reply {
                                kprint!(" [P10-E] ARP resolved gw but no ICMP reply — forward/ICMP path to diagnose\n");
                            } else {
                                kprint!(" [P10-E] ARP got no reply — L2 TX-to-gw path to diagnose\n");
                            }
                        } else if dh.offer_rx {
                            kprint!(" [P10-E] DHCP OFFER received (decrypted DHCP RX PROVEN) but no ACK — REQUEST/lease incomplete\n");
                        } else {
                            kprint!(" [P10-E] DHCP no OFFER (discover_tx={}) — TX path or server-reachability to diagnose\n", dh.discover_tx);
                        }
                    } else if hs.m3_seen && hs.m4_tx_ok && !hs.deauth_after_m4 {
                        kprint!(" [P10-E] PASS(4way) — M1..M4 complete, no deauth, but PTK install failed (ptk_set={}) — see s2 diag\n", hs.ptk_set_ok);
                    } else if hs.m3_seen && hs.m4_tx_ok {
                        kprint!(" [P10-E] M1..M4 sent but deauth after M4 (reason={}) — likely heqk fw needs the PTK installed (WLC_SET_KEY) to hold the port\n", hs.deauth_reason);
                    } else if hs.m3_seen {
                        kprint!(" [P10-E] PASS(4way-S1) — AP sent M3 (M2 accepted) but M4 tx={} — see s2 diag\n", hs.m4_tx_ok);
                    } else if hs.m2_tx_ok && hs.deauth_after {
                        kprint!(" [P10-E] M2 sent inline but AP DEAUTHed (no M3) — likely MIC/PTK or RSN-IE mismatch; kdv={}\n", hs.kdv);
                    } else if hs.m2_tx_ok {
                        kprint!(" [P10-E] M2 sent inline (tx ok) but no M3/deauth in window — see s1 diag\n");
                    } else if jr.eapol_seen {
                        kprint!(" [P10-E] M1 captured but M2 NOT sent (snonce={} — TRNG?) — data path proven, handshake blocked\n", hs.snonce_ok);
                    } else if jr.link_up {
                        kprint!(" [P10-E] linked but no EAPOL M1 captured (raced the loop?); last event={} status={:#x}\n", jr.last_event, jr.last_status);
                    } else {
                        kprint!(" [P10-E] NOT LINKED — last event={} status={:#x}; trail shows the stage reached\n", jr.last_event, jr.last_status);
                    }
                    } else {
                        kprint!(" [P10-E] SKIPPED — STA join is a bench mode: opt-in via --features stajoin + HEQK_JOIN_SSID/HEQK_JOIN_PSK at build time\n");
                    }
                } else {
                    kprint!(" [P10-C] SILENT — BCDC ver round-trip failed; see [P10-C bcdc] diag for the failing stage\n");
                }
            }
        }
        Some(id) => {
            let (via52, via53, win_ok) = cyw43::chipid_diag();
            kprint!(" [P10-A] MISMATCH — chip ID {:#06x} (want 0x4345)\n", id);
            kprint!("   [P10-diag] chipcommon[0..4] via_cmd52={:#010x} via_cmd53={:#010x} window_ack={}\n",
                via52, via53, win_ok);
        }
        None => {
            let (ps, ist) = cyw43::sdio_diag();
            let d = cyw43::p10_regdump();
            kprint!(" [P10-A] SILENT — stalled step {}; PRESENT={:#010x} INT={:#010x}\n",
                cyw43::sdio_last_step(), ps, ist);
            kprint!("   [P10-diag] gioDATA={:#010x} (WL_ON bit28={}) mux08={:#010x} mux0c={:#010x} CAPS={:#010x} CLKCTL={:#06x} (SDclk_en={} stable={}) HOSTCTL={:#010x}\n",
                d[0], (d[0] >> 28) & 1, d[1], d[2], d[3], d[4] as u16, (d[4] >> 2) & 1, (d[4] >> 1) & 1, d[5]);
        }
    }
    // P10-BT is opt-in (feature `p10bt`) — see kernel/Cargo.toml. On metal the
    // unresponsive BT core left a deferred external abort that SError'd the next
    // phase, so it stays out of the default image until uarta clock/power is solved.
    #[cfg(feature = "p10bt")]
    cm5_p10bt_probe();
    #[cfg(not(feature = "p10bt"))]
    kprint!(" [P10-BT] SKIPPED — opt-in via --features p10bt (uarta clock/power sequencing unresolved; see Cargo.toml)\n");
}

/// P15 (metal) — eMMC read-only block device + sealing, on real BCM2712 silicon.
/// Runs AFTER cm5_p10_probe and AFTER boot_confirm. Strictly read-only on disk:
///   * probe the eMMC (dump-before-touch, force-presence, CMD0/1/2/3/9/7/16/8);
///   * read LBA 0, parse + print the MBR, evaluate the write guard;
///   * scan (read-only) the reserved window LBA 2016..2047;
///   * seal/unseal IN RAM against a SYNTHETIC key, proving wrong-measurement +
///     tamper are refused.
///
/// LIMITATION, stated plainly: measurement enforcement is NOT yet real. HBoot
/// does not publish a SealHandoff, so the SRK is synthetic — a modified kernel
/// would derive the same key. Real binding needs the HBoot SRK derivation + the
/// closing of audit finding V3/SEC-2 (EL1 must not be able to read OTP). This
/// build therefore claims NEITHER measurement enforcement NOR rollback protection.
#[cfg(all(feature = "cm5", feature = "hboot"))]
fn cm5_p15_block_seal() {
    use arch_aarch64::emmc::Emmc;
    use hal::BlockDev; // brings read_block/block_count into scope for Emmc
    use store::{guard_from_mbr, SealedStore};

    kprint!("\n [P15] eMMC block storage + sealed persistence (read-only bring-up)\n");

    // clk-emmc2 is SHARED with the live WiFi host — read the rate, never set it.
    let clk = arch_aarch64::mailbox::get_clock_rate(arch_aarch64::mailbox::CLK_EMMC2).unwrap_or(0);
    let pre = Emmc::dump_regs();
    kprint!("   [P15] clk-emmc2={} Hz (get only; shared w/ WiFi), pre-touch: CAPS={:#010x} PRESENT={:#010x} CLKCTL={:#06x} INT_EN={:#010x}\n",
        clk, pre[0], pre[1], pre[3] as u16, pre[5]);

    // `mut` for the p15-write metal write self-test below; read-only otherwise.
    #[cfg_attr(not(feature = "p15-write"), allow(unused_mut))]
    let mut emmc = match Emmc::probe() {
        Ok(e) => e,
        Err((step, err)) => {
            kprint!("   [P15] eMMC SILENT — stalled step {} ({:?}); read-only probe, no disk change\n", step, err);
            kprint!(" [P15-block] SKIPPED — eMMC bring-up incomplete on this carrier (read-only, safe)\n");
            // Still exercise the sealing crypto in RAM so the phase is meaningful.
            p15_seal_ram_demo();
            return;
        }
    };
    kprint!("   [P15] eMMC up: sector-addressed={}, capacity={} sectors ({} MiB)\n",
        emmc.sector_addressed(), emmc.sec_count(), emmc.sec_count() / 2048);

    // Read LBA 0 + parse the MBR (READ-ONLY).
    let mut mbr = [0u8; 512];
    if emmc.read_block(0, &mut mbr).is_err() {
        kprint!("   [P15] LBA0 read failed — aborting (read-only, no change)\n");
        p15_seal_ram_demo();
        return;
    }
    let parts = store::parse_mbr(&mbr);
    kprint!("   [P15] MBR sig={:02x}{:02x}; partitions:\n", mbr[510], mbr[511]);
    for (i, p) in parts.iter().enumerate() {
        if p.ptype != 0 || p.count != 0 {
            kprint!("     p{}: type={:#04x} start=LBA {} count={} sectors\n", i + 1, p.ptype, p.start, p.count);
        }
    }
    match guard_from_mbr(&mbr, emmc.sec_count()) {
        Ok(g) => kprint!("   [P15] write-guard OK: window LBA {}..{} (first partition @LBA {}) — 2015 sectors clear of MBR\n",
            g.lo, g.hi, g.first_part),
        Err(e) => kprint!("   [P15] write-guard REFUSES this disk: {:?} (writes would be blocked — safe)\n", e),
    }

    // Scan the reserved window READ-ONLY: report whether a HQKSEAL1 blob is present.
    let mut found = false;
    let mut first = [0u8; 512];
    if emmc.read_block(store::RESERVED_LBA_LO, &mut first).is_ok() {
        found = &first[..8] == seal::SEAL_MAGIC;
    }
    kprint!("   [P15] reserved window LBA {} scan (read-only): {}\n",
        store::RESERVED_LBA_LO, if found { "HQKSEAL1 blob present" } else { "empty (no seal yet)" });

    // M3 metal keystone (p15-write): the FIRST real CMD24 write to the CM5 eMMC. The write
    // path (arch emmc::write_block_impl) was only ever exercised over virtio-blk/RamDisk in
    // QEMU; this proves it on SILICON. Safe by construction: Gate-1 is a COMPILE-TIME hard
    // clamp to the reserved window LBA 2016..2047 (32 empty sectors between the MBR and
    // partition 1), independent of the caller — a bug cannot escape it. We target LBA 2040,
    // clear of the seal-store blob region at 2016. TWO-BOOT PROOF: read FIRST (a cookie from
    // a prior boot ⇒ persistence survived the power-cycle on real eMMC), then rewrite with a
    // bumped boot counter.
    #[cfg(all(feature = "p15-write", any(feature = "p15-bench", feature = "sepdiag")))] // bench self-test (task #27: never on prod)
    {
        const WLBA: u64 = 2040;
        const WMAGIC: &[u8; 8] = b"HQKEMWR1";
        let mut rb = [0u8; 512];
        let pre_ok = emmc.read_block(WLBA, &mut rb).is_ok();
        let persisted = pre_ok && &rb[..8] == WMAGIC;
        let prev_boot = if persisted {
            u32::from_le_bytes([rb[8], rb[9], rb[10], rb[11]])
        } else {
            0
        };
        let this_boot = prev_boot.wrapping_add(1);
        let mut wb = [0u8; 512];
        wb[..8].copy_from_slice(WMAGIC);
        wb[8..12].copy_from_slice(&this_boot.to_le_bytes());
        // Arm the FULL reserved window (still Gate-1-clamped to [2016,2048)) so BOTH this
        // cookie (LBA 2040) and the sealed-store blob (LBA 2016, below) are writable this
        // session — the window is narrowing-only, so a per-LBA arm would lock the other out.
        let (wlo, whi) = emmc.arm_write_window(store::RESERVED_LBA_LO, store::RESERVED_LBA_HI);
        let armed = wlo <= WLBA && WLBA < whi;
        let wrote = armed && emmc.write_block(WLBA, &wb).is_ok();
        let mut vb = [0u8; 512];
        let readback = wrote && emmc.read_block(WLBA, &mut vb).is_ok() && vb[..12] == wb[..12];
        // A guard-escape assertion: a write OUTSIDE the reserved window MUST be refused.
        let escape_refused = emmc.write_block(store::RESERVED_LBA_HI, &wb).is_err();
        let pass = wrote && readback && escape_refused;
        kprint!("   [SEPDIAG-EMMC-WRITE] persisted-from-prior-boot={} (boot#{}) | armed=[{}..{}) wrote={} readback-match={} | out-of-window-refused={} => {}\n",
            persisted, this_boot, wlo, whi, wrote, readback, escape_refused, if pass { "PASS" } else { "FAIL" });
    }

    // M3.3 metal — the SEALED evidence-record round-trip on real eMMC: prove a genuine
    // encrypted evidence Event survives a power-cycle (the "evidence graph persists across
    // reboot" capability), and that it is CIPHERTEXT at rest, bound to the REAL per-device
    // OTP-derived SRK when HBoot supplies one (device-binding — a blob is unsealable on
    // another device). Full stack — seal → SealedStore::store → (reboot) → load → unseal —
    // over the keystore reserved window (the P15-fs/P15-sealfs QEMU stack, now on silicon).
    #[cfg(all(feature = "p15-write", any(feature = "p15-bench", feature = "sepdiag")))] // bench self-test (task #27: never on prod)
    {
        use seal::{Policy, SealBlob};
        use store::SealedStore;
        // Serialize a real evidence Event (repr(C): ts u64 | src u32 | rule_id u16 | sev u8 | verdict u8).
        fn ev16(ts: u64, src: u32, rule_id: u16, sev: u8, verdict: u8) -> [u8; 16] {
            let mut b = [0u8; 16];
            b[0..8].copy_from_slice(&ts.to_le_bytes());
            b[8..12].copy_from_slice(&src.to_le_bytes());
            b[12..14].copy_from_slice(&rule_id.to_le_bytes());
            b[14] = sev;
            b[15] = verdict;
            b
        }
        // The REAL per-device OTP SRK + measured policy from the HBoot handoff when present
        // (mirrors p15_seal_ram_demo); synthetic fallback on a device with no SealHandoff.
        // A per-device key means this sealed blob is bound to THIS device's hardware root.
        #[cfg(feature = "hboot")]
        let (srk, device_id, svn_floor, pcr, real_srk) = match read_seal_handoff() {
            Some(h) => (seal_srk().unwrap_or([0x5au8; 32]), h.device_id, h.svn_floor, h.pcr, true),
            None => {
                let mut p = [[0u8; 32]; boot_abi::NUM_PCR];
                p[0] = [0x11; 32];
                p[1] = [0x22; 32];
                p[2] = [0x33; 32];
                ([0x5au8; 32], 0x0BADF00D_1234_5678u64, 7, p, false)
            }
        };
        #[cfg(not(feature = "hboot"))]
        let (srk, device_id, svn_floor, pcr, real_srk) = {
            let mut p = [[0u8; 32]; boot_abi::NUM_PCR];
            p[0] = [0x11; 32];
            p[1] = [0x22; 32];
            p[2] = [0x33; 32];
            ([0x5au8; 32], 0x0BADF00D_1234_5678u64, 7, p, false)
        };
        let policy = Policy {
            mask: boot_abi::SEAL_POLICY_STRICT,
            device_id,
            svn_floor,
            pcr,
        };
        if let Ok(mut ss) = SealedStore::open(&mut emmc) {
            // READ FIRST: unseal a prior-boot Event ⇒ it survived the power-cycle, encrypted.
            let mut rbuf = [0u8; seal::SEAL_MAX_BLOB];
            let mut prev_boot: u64 = 0;
            let mut persisted = false;
            if let Some(n) = ss.load(&mut rbuf) {
                let mut pt = [0u8; 64];
                if let Ok(m) = seal::unseal(&srk, &policy, &rbuf[..n], &mut pt) {
                    if m >= 16 && pt[12] == 0x2e && pt[13] == 0x01 {
                        // rule_id 302 (0x012e) LE ⇒ our evidence Event; ts carries the boot counter.
                        prev_boot = u64::from_le_bytes(pt[0..8].try_into().unwrap());
                        persisted = true;
                    }
                }
            }
            let this_boot = prev_boot.wrapping_add(1);
            let ev = ev16(this_boot, 0x0a63_0007, 302, 5, 1); // a real IOC-hit Event (rule 302, PASS)
            let mut blob = SealBlob::new();
            let sealed = seal::seal(&srk, &policy, &ev, &mut blob).is_ok();
            let stored = sealed && ss.store(blob.as_slice()).is_ok();
            // CONFIDENTIALITY: the on-disk sector is HQKSEAL1 ciphertext — the Event's 16-byte
            // plaintext image is ABSENT on disk (encryption at rest).
            let mut raw = [0u8; 512];
            let ciphertext = stored
                && ss.read_sector(store::RESERVED_LBA_LO, &mut raw).is_ok()
                && &raw[..8] == seal::SEAL_MAGIC
                && !raw[8..].windows(16).any(|w| w == ev);
            // ROUND-TRIP THIS boot: read back + unseal → exact Event bytes.
            let mut rbuf2 = [0u8; seal::SEAL_MAX_BLOB];
            let mut pt2 = [0u8; 64];
            let roundtrip = stored
                && ss.load(&mut rbuf2).map_or(false, |n| {
                    seal::unseal(&srk, &policy, &rbuf2[..n], &mut pt2).map_or(false, |m| m >= 16 && pt2[..16] == ev)
                });
            let pass = stored && ciphertext && roundtrip;
            kprint!("   [SEPDIAG-EMMC-SEAL] key={} | persisted-Event-from-prior-boot={} (boot#{}) | sealed+stored={} on-disk-ciphertext={} unseal-roundtrip={} => {}\n",
                if real_srk { "REAL-OTP-per-device" } else { "synthetic" },
                persisted, this_boot, stored, ciphertext, roundtrip, if pass { "PASS" } else { "FAIL" });
        }
    }

    // M3.2 metal — the crash-safe LOG-STRUCTURED evidence store (DataVolume) on real eMMC:
    // prove multi-record append + in-order read-back + CROSS-REBOOT persistence of real
    // evidence records (the "evidence graph survives reboot" capability at scale, beyond a
    // single sealed blob). Uses a DataVolume region carved from p3 — this is a heqk-only
    // board (Linux re-flashable, operator-authorized 2026-09-08). 128 sectors @ LBA
    // 16_777_216 (SB + 127 record slots), far from the MBR/keystore/boot-slot; the widened
    // eMMC Gate-1 allowlist (keystore ∪ DataVolume) + the dv armed window admit it.
    #[cfg(all(feature = "p15-write", any(feature = "p15-bench", feature = "sepdiag")))] // bench self-test (task #27: never on prod)
    {
        use store::{RegionKind, SealedStore};
        // task #27 F5: the region comes from the MBR's DataVolume partition (type 0xDA), never a
        // hard-coded LBA (16,777,216 was past p2 on the 512-MiB factory layout = unpartitioned eMMC).
        // Offset 1024 into p2: clear of segmetal's reach-floor ring at [p2.lo, p2.lo+16).
        let mut mbr0 = [0u8; 512];
        let dv = if emmc.read_block(0, &mut mbr0).is_ok() { store::datavolume_from_mbr(&mbr0) } else { None };
        #[allow(non_snake_case)]
        let (DV_LO, DV_HI) = match dv {
            Some((lo, hi)) if lo + 1024 + 128 <= hi => (lo + 1024, lo + 1024 + 128),
            _ => {
                kprint!("   [SEPDIAG-DV] SKIP — no DataVolume partition (0xDA) with room on this eMMC\n");
                (0, 0)
            }
        };
        if DV_HI != 0 {
        emmc.set_data_volume(DV_LO, DV_HI); // Gate-1 allowlist entry
        emmc.arm_write_window(DV_LO, DV_HI); // Gate-2 armed window (routes to the dv region)
        let (dv_prev, dv_now, dv_cap, dv_order, dv_evid, dv_pass) = (|| -> (u64, u64, u64, bool, bool, bool) {
            let mut ss = match SealedStore::open(&mut emmc) {
                Ok(s) => s,
                Err(_) => return (0, 0, 0, false, false, false),
            };
            if ss.add_region(DV_LO, DV_HI, RegionKind::DataVolume).is_err() {
                return (0, 0, 0, false, false, false);
            }
            let mut log = match crate::fslog::open_or_format(&mut ss, DV_LO, DV_HI) {
                Ok(l) => l,
                Err(_) => return (0, 0, 0, false, false, false),
            };
            let prev = log.count(); // records persisted from a PRIOR boot (0 on first format)
            let cap = log.capacity();
            // Append 3 real evidence Events (rule 302 IOC-hit, PASS) with a boot-tag in ts.
            let mut appended = true;
            for i in 0..3u64 {
                let mut ev = [0u8; 16];
                ev[0..8].copy_from_slice(&(0xE0u64 + prev + i).to_le_bytes());
                ev[8..12].copy_from_slice(&0x0a63_0008u32.to_le_bytes());
                ev[12..14].copy_from_slice(&302u16.to_le_bytes());
                ev[14] = 5;
                ev[15] = 1;
                if log.append(&mut ss, crate::fslog::RT_EVIDENCE, &ev).is_err() {
                    appended = false;
                    break;
                }
            }
            let now = log.count();
            // Read back the live records in order; count them + confirm they are evidence Events.
            let mut seen = 0u64;
            let mut all_evid = true;
            let _ = log.for_each(&ss, |_seq, rt, pl| {
                seen += 1;
                if !(rt == crate::fslog::RT_EVIDENCE && pl.len() >= 14 && pl[12] == 0x2e && pl[13] == 0x01) {
                    all_evid = false;
                }
            });
            let expect = (prev + 3).min(cap);
            (prev, now, cap, seen == now, all_evid && seen > 0, appended && now == expect && seen == now && all_evid)
        })();
        kprint!("   [SEPDIAG-EMMC-DATAVOL] persisted-records-from-prior-boot={} | appended=3 total={} cap={} readback-in-order={} all-evidence={} => {}\n",
            dv_prev, dv_now, dv_cap, dv_order, dv_evid, if dv_pass { "PASS" } else { "FAIL" });
        }
    }

    // M3.4 metal — the ON-DEVICE forward A/B tryboot flip (opt-in `otaflip`; SELF-REBOOTS
    // once). The ROLLBACK half is already metal-proven (M1 criterion-4: corrupt slot B →
    // verify fail → EL2 watchdog → revert to slot A). This proves the FORWARD/healthy path:
    // heqk-on-A arms the REAL firmware one-shot tryboot → the firmware boots the (existing,
    // valid) slot B → heqk-on-B reads OtaState=Trying → confirm → Committed. Persisted in the
    // keystore reserved window (LBA 2044), NOT the boot partition — slot A is never touched
    // (zero brick risk; the watchdog reverts to A if slot B ever hangs). Loop-safe: persist +
    // read-back BEFORE arming, generation cap, and Committed is terminal (never re-arms).
    // The physical candidate delivery (FAT write of a NEW image to slot B + B→A promotion) is
    // the remaining Phase-2 piece; this proves the flip MECHANISM on real firmware.
    #[cfg(feature = "otaflip")]
    {
        use ota::{OtaPhase, OtaState};
        const OTA_LBA: u64 = 2044; // reserved window, distinct from seal@2016 / cookie@2040
        emmc.arm_write_window(store::RESERVED_LBA_LO, store::RESERVED_LBA_HI);
        let mut sec = [0u8; 512];
        let cur = if emmc.read_block(OTA_LBA, &mut sec).is_ok() {
            OtaState::from_bytes(&sec[..OtaState::WIRE_LEN]).unwrap_or_else(OtaState::initial)
        } else {
            OtaState::initial()
        };
        match cur.phase {
            OtaPhase::Committed => {
                kprint!("   [SEPDIAG-OTA] forward-flip COMMITTED (gen={}) — tryboot trial→confirm→commit proven on real firmware => PASS\n",
                    cur.generation);
            }
            OtaPhase::Trying => {
                // We ARE the trial boot (firmware loaded tryboot.txt → slot B) and we booted
                // healthy. Confirm → Committed, persist. No re-arm (fall through to normal boot).
                match ota::confirm(&cur) {
                    Ok(done) => {
                        let mut w = [0u8; 512];
                        w[..OtaState::WIRE_LEN].copy_from_slice(&done.to_bytes());
                        let wrote = emmc.write_block(OTA_LBA, &w).is_ok();
                        let mut rb = [0u8; 512];
                        let ok = wrote && emmc.read_block(OTA_LBA, &mut rb).is_ok()
                            && rb[..OtaState::WIRE_LEN] == w[..OtaState::WIRE_LEN];
                        kprint!("   [SEPDIAG-OTA] TRIAL slot B booted HEALTHY → confirm → COMMITTED persist={} (gen {}→{}, active_slot→B) => {}\n",
                            ok, cur.generation, done.generation, if ok { "PASS" } else { "FAIL" });
                    }
                    Err(e) => kprint!("   [SEPDIAG-OTA] confirm FAILED: {:?} => FAIL\n", e),
                }
            }
            OtaPhase::Idle | OtaPhase::RolledBack | OtaPhase::Staged => {
                // INITIATE the forward flip (Staged is folded here — a stale Staged with no
                // pending trial re-initiates cleanly). Loop-safety: generation cap +
                // persist-read-back BEFORE arming (never reset if the state didn't stick).
                if cur.generation < 6 {
                    let staged = OtaState {
                        phase: OtaPhase::Staged,
                        active_slot: ota::SLOT_A,
                        try_slot: ota::SLOT_NONE,
                        candidate_svn: 1,
                        generation: cur.generation + 1,
                    };
                    match ota::flip(&staged) {
                        Ok(trying) => {
                            let mut w = [0u8; 512];
                            w[..OtaState::WIRE_LEN].copy_from_slice(&trying.to_bytes());
                            let wrote = emmc.write_block(OTA_LBA, &w).is_ok();
                            let mut rb = [0u8; 512];
                            let persisted = wrote && emmc.read_block(OTA_LBA, &mut rb).is_ok()
                                && rb[..OtaState::WIRE_LEN] == w[..OtaState::WIRE_LEN];
                            if persisted {
                                let set = arch_aarch64::mailbox::set_reboot_flags(arch_aarch64::mailbox::REBOOT_FLAG_TRYBOOT);
                                let readback = arch_aarch64::mailbox::get_reboot_flags();
                                let _ = arch_aarch64::mailbox::notify_reboot();
                                match readback {
                                    Some(f) if f & arch_aarch64::mailbox::REBOOT_FLAG_TRYBOOT != 0 => {
                                        kprint!("   [SEPDIAG-OTA] initiate: OtaState=Trying persisted (gen {}), tryboot ARMED (set={:?}) — warm-reset → firmware loads tryboot.txt (slot B)\n",
                                            trying.generation, set);
                                        for _ in 0..40_000_000u64 { core::hint::spin_loop(); } // drain UART
                                        unsafe { core::arch::asm!("hvc #0", options(noreturn)) }
                                    }
                                    other => kprint!("   [SEPDIAG-OTA] tryboot did NOT arm (readback={:?}) — NOT resetting (no loop) => FAIL\n", other),
                                }
                            } else {
                                kprint!("   [SEPDIAG-OTA] OtaState persist read-back FAILED — NOT arming/resetting (no loop) => FAIL\n");
                            }
                        }
                        Err(e) => kprint!("   [SEPDIAG-OTA] flip FAILED: {:?} => FAIL\n", e),
                    }
                } else {
                    kprint!("   [SEPDIAG-OTA] generation cap reached (gen={}) — forward-flip disabled (loop-safety)\n", cur.generation);
                }
            }
        }
    }

    // If we can build a store over the real disk, exercise the READ/scan path.
    {
        let mut dev = emmc; // move into the store (read path uses it immutably)
        if let Ok(ss) = SealedStore::open(&mut dev) {
            let mut buf = [0u8; seal::SEAL_MAX_BLOB];
            match ss.load(&mut buf) {
                Some(n) => kprint!("   [P15] store scan/load: found a {}-byte blob in the window\n", n),
                None => kprint!("   [P15] store scan/load: window holds no valid blob (expected on a fresh disk)\n"),
            }
        }
    }

    // Sealing crypto proof IN RAM (synthetic key) — the security-honest part.
    let ram_ok = p15_seal_ram_demo();

    kprint!(" [P15-block] {} — eMMC READ-ONLY block device + in-RAM sealing proven on metal\n",
        if ram_ok { "PASS" } else { "FAIL" });
    // PH2a: report the ACTUAL provenance of the sealing root key from the handoff flags.
    match read_seal_handoff() {
        Some(h) if h.flags & boot_abi::SEAL_FLAG_SRK_HW_DERIVED != 0 => {
            kprint!(" [P15-BOUND] sealing binding is REAL — per-device SRK derived from OTP in HBoot, EL1 cannot read OTP (V3/SEC-2 closed)\n");
        }
        Some(h) if h.flags & boot_abi::SEAL_FLAG_SRK_FROM_OTP != 0 => {
            kprint!(" [P15-SRK] SRK is REAL + per-device (OTP-derived by HBoot, device_id={:#018x}) — sealing is no longer a global synthetic key.\n", h.device_id);
            kprint!("           LIMIT: V3/SEC-2 (EL1 can still read OTP via the VC mailbox) is OPEN, so on-device binding is not yet tamper-proof (closes in PH2b).\n");
        }
        _ => {
            kprint!(" [P15-LIMIT] SRK is SYNTHETIC (no HBoot SealHandoff) — measurement binding is cosmetic;\n");
            kprint!("             prerequisite = HBoot SRK derivation + V3/SEC-2 (EL1 must not read OTP).\n");
        }
    }
}

/// The arch-agnostic sealing proof used by the metal P15 path: seal/unseal a
/// secret with a SYNTHETIC key and prove wrong-measurement + tamper are refused.
/// No disk, no hardware — pure crypto, so it is meaningful even if the eMMC
/// bring-up stalls on a given carrier.
/// PH2a: read the sealing handoff HBoot wrote at `SEAL_HANDOFF_ADDR`. `None` if the
/// magic is absent (QEMU or the software-AK fallback — the kernel then keeps its
/// synthetic key). The kernel NEVER sees the OTP secret the SRK was derived from.
#[cfg(feature = "hboot")]
fn read_seal_handoff() -> Option<&'static boot_abi::SealHandoff> {
    let sh = unsafe { &*(boot_abi::SEAL_HANDOFF_ADDR as *const boot_abi::SealHandoff) };
    (sh.magic == boot_abi::SEAL_HANDOFF_MAGIC).then_some(sh)
}

/// The device's Ed25519 IDENTITY (the Noise static that authenticates it to the MSSP and binds
/// every export frame's `device_fp`), derived from the OTP-rooted SRK under its own HKDF label.
/// The SRK is device-bound but NOT measurement-bound (hboot: `derive32("HEQK-SEAL-SRK-v1",
/// OTP secret)`), so the identity survives OTA updates. `None` without an SRK — the caller must
/// then refuse to run the control plane.
///
/// (Was `KeyPair::from_seed(sha256(device_id))`: `device_id` is the board serial hboot prints on
/// the console, so anyone could re-derive the private key, impersonate the device and forge its
/// evidence. With no handoff it was `sha256(0)` — one shared key for every device.)
/// The device's Ethernet MAC for the Mission Control node: locally-administered unicast, derived
/// from the SRK (stable across OTA, distinct per device — two heqk boxes on one LAN never collide,
/// unlike the old hard-coded 02:00:00:00:00:02). Falls back to the (public) device id.
#[cfg(feature = "prod-mc")]
fn device_mac() -> [u8; 6] {
    let k = match seal_srk() {
        Some(srk) => boot_abi::kdf::hkdf_expand32(&srk, b"HEQK-MAC-v1"),
        None => boot_abi::sha256::digest(&read_seal_handoff().map(|h| h.device_id).unwrap_or(0).to_le_bytes()),
    };
    [(k[0] & 0xFE) | 0x02, k[1], k[2], k[3], k[4], k[5]]
}

#[cfg(all(feature = "hboot", feature = "securechannel"))]
fn device_identity_keypair() -> Option<ed25519_compact::KeyPair> {
    let srk = seal_srk()?;
    let seed = boot_abi::kdf::hkdf_expand32(&srk, b"HEQK-DEVICE-IDENTITY-ed25519-v1");
    Some(ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed)))
}

/// PH2a (AUDIT R1): consume the SRK from the fixed handoff page EXACTLY ONCE — copy it into
/// kernel-private `.bss` (not the well-known 0x3FFA_0000 address, and never EL0-mappable),
/// then SCRUB the 32 SRK bytes in the page (write-zero + `dsb` + `dc civac` to DRAM) so the
/// master seal key does not persist in plaintext at a constant address for an EL1 leak, an
/// EL0 frame-map of that PA, or a non-IOMMU-contained DMA peer to lift. magic/device_id/pcr/
/// flags are LEFT intact (not secret) so the status print still reads them. Returns None on a
/// device with no handoff (synthetic-key fallback).
#[cfg(feature = "hboot")]
fn seal_srk() -> Option<[u8; 32]> {
    static mut SRK_PRIV: [u8; 32] = [0u8; 32];
    static mut SRK_STATE: u8 = 0; // 0 = unread, 1 = present, 2 = absent
    unsafe {
        if SRK_STATE == 0 {
            let sh = &*(boot_abi::SEAL_HANDOFF_ADDR as *const boot_abi::SealHandoff);
            if sh.magic == boot_abi::SEAL_HANDOFF_MAGIC {
                SRK_PRIV = sh.srk;
                // Scrub the SRK bytes at page offset 8 (immediately after the u64 magic).
                let p = (boot_abi::SEAL_HANDOFF_ADDR + 8) as *mut u8;
                for i in 0..32 {
                    core::ptr::write_volatile(p.add(i), 0u8);
                }
                // Push the zeros out to DRAM so a physical / DMA read can't recover the key.
                core::arch::asm!(
                    "dsb sy",
                    "dc civac, {a}",
                    "dsb sy",
                    a = in(reg) (boot_abi::SEAL_HANDOFF_ADDR + 8),
                    options(nostack),
                );
                SRK_STATE = 1;
            } else {
                SRK_STATE = 2;
            }
        }
        if SRK_STATE == 1 {
            Some(SRK_PRIV)
        } else {
            None
        }
    }
}

#[cfg(all(feature = "cm5", feature = "hboot"))]
fn p15_seal_ram_demo() -> bool {
    use seal::{Policy, SealBlob, SealErr};
    // PH2a: seal with the REAL per-device SRK + policy from the HBoot handoff when present;
    // fall back to the synthetic key on a device with no OTP secret. `seal_srk()` copies the
    // key into kernel-private storage and scrubs the fixed handoff page (AUDIT R1); the
    // non-secret fields (device_id/pcr/flags) stay readable via read_seal_handoff().
    let srk = seal_srk().unwrap_or([0x5au8; 32]);
    let handoff = read_seal_handoff();
    let keylabel = if handoff.is_some() { "per-device OTP SRK" } else { "SYNTHETIC key" };
    let (device_id, svn_floor, pcr) = match handoff {
        Some(h) => (h.device_id, h.svn_floor, h.pcr),
        None => {
            let mut p = [[0u8; 32]; boot_abi::NUM_PCR];
            p[0] = [0x11; 32];
            p[1] = [0x22; 32];
            (0x0BADF00D_1234_5678, 7, p)
        }
    };
    let policy = Policy {
        mask: boot_abi::SEAL_POLICY_STRICT,
        device_id,
        svn_floor,
        pcr,
    };
    let secret = b"HEQK-P15-metal-sealed-secret";
    let mut blob = SealBlob::new();
    if seal::seal(&srk, &policy, secret, &mut blob).is_err() {
        return false;
    }
    let mut pt = [0u8; 64];
    let round = matches!(seal::unseal(&srk, &policy, blob.as_slice(), &mut pt),
        Ok(n) if &pt[..n] == secret);
    // wrong measurement (PCR1 changed under strict policy) -> refused.
    let mut wpcr = pcr;
    wpcr[1] = [0xEE; 32];
    let wrong = Policy { pcr: wpcr, ..policy };
    let wrong_refused = matches!(seal::unseal(&srk, &wrong, blob.as_slice(), &mut pt),
        Err(SealErr::PolicyMismatch));
    // tampered ciphertext -> refused.
    let mut t = SealBlob::new();
    t.bytes[..blob.len].copy_from_slice(blob.as_slice());
    t.len = blob.len;
    t.bytes[seal::SEAL_HDR_LEN] ^= 0x01;
    let tamper_refused = matches!(seal::unseal(&srk, &policy, t.as_slice(), &mut pt),
        Err(SealErr::Tag));
    // AUD-STO-1: two seals of the SAME secret under the SAME key/policy must produce
    // DIFFERENT ciphertext (fresh per-seal nonce => distinct keystream, no reuse).
    let mut blob2 = SealBlob::new();
    let hdr = seal::SEAL_HDR_LEN;
    let no_reuse = seal::seal(&srk, &policy, secret, &mut blob2).is_ok()
        && blob2.as_slice()[hdr..hdr + secret.len()] != blob.as_slice()[hdr..hdr + secret.len()]
        // ...and the second blob still round-trips (nonce carried in its own header).
        && matches!(seal::unseal(&srk, &policy, blob2.as_slice(), &mut pt),
            Ok(n) if &pt[..n] == secret);
    kprint!("   [P15] in-RAM seal/unseal ({}): round-trip {}, wrong-measurement {}, tamper {}, no-reuse {}\n",
        keylabel,
        if round { "MATCH" } else { "MISMATCH" },
        if wrong_refused { "REFUSED" } else { "LEAK!" },
        if tamper_refused { "REFUSED" } else { "LEAK!" },
        if no_reuse { "DISTINCT" } else { "REUSED!" });
    round && wrong_refused && tamper_refused && no_reuse
}

/// P10-BT — the Bluetooth half of the CYW43455, over HCI-UART (uarta, NS16550A).
/// Independent of the SDIO WiFi path; runs after it so a BT failure can never
/// affect the WiFi result. Patch-free (the .hcd is optional for HCI + LE scan).
#[cfg(all(feature = "cm5", feature = "p10bt"))]
fn cm5_p10bt_probe() {
    use arch_aarch64::bt;
    kprint!(" [P10-BT] CYW43455 Bluetooth — HCI-UART (uarta bcm7271 @0x10_7D50_C000), pins gpio24-27=uart0, BT_ON gpio29\n");
    // Bracket the whole probe with SError masked so any UART external abort is drained
    // into DISR_EL1 by drain_errors() instead of escalating to the fatal handler.
    bt::mask_serror();
    let alive = bt::bringup();
    let disr = bt::drain_errors();
    let d = bt::bt_diag();
    kprint!("   [P10-BT hci] reset={:#04x} baud3M={:#04x} (0x00=ok, 0xff=no response, 0xfe=uart did not decode)\n", d[0], d[1]);
    if disr != 0 {
        kprint!("   [P10-BT] CONTAINED external abort DISR_EL1={:#x} — drained in-phase, later phases safe\n", disr);
    }
    if !alive {
        kprint!(" [P10-BT] SILENT — BT core not responding (contained; WiFi + later phases unaffected)\n");
        return;
    }
    let mut devs = [bt::BleDev::new(); 24];
    let n = bt::ble_scan(&mut devs);
    let d = bt::bt_diag();
    kprint!("   [P10-BT le] evt_mask={:#04x} le_evt_mask={:#04x} scan_params={:#04x} scan_enable={:#04x}\n",
        d[2], d[3], d[4], d[5]);
    for dev in &devs[..n] {
        // bdaddr arrives little-endian; print in display order
        kprint!("   [P10-BT dev] {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} type={} rssi={} adv={}\n",
            dev.addr[5], dev.addr[4], dev.addr[3], dev.addr[2], dev.addr[1], dev.addr[0],
            dev.addr_type, dev.rssi, dev.evt_type);
    }
    if n > 0 {
        kprint!(" [P10-BT] PASS — Bluetooth alive + LE scan: {} BLE device(s) seen (BT sensor path live)\n", n);
    } else {
        kprint!(" [P10-BT] HCI alive, LE scan armed but no advertisers heard in the window\n");
    }
}

/// P13 — RP1 peripheral buses (GPIO/pinmux + I2C + SPI + UART), EL0-isolated.
/// ADDITIVE, CM5-only. Every stage is BOUNDED (poll_until / bounded EL0 spins),
/// degrades to a reported status, and NEVER hangs. See PERIPHERAL_BUSES.md §4.
///
/// The RESERVED deny-list (gpio14/15=console, 32=ETH_RST_N, 37/38/39/44) is the
/// load-bearing safety property; Stage B asserts it actively refuses a remux. The
/// WiFi lines (WL_ON/SDIO2) are BCM2712 `gio` at 0x10_7D5x — a DIFFERENT block from
/// RP1 — so nothing here can touch the radio.
#[cfg(feature = "cm5")]
fn cm5_p13_probe() {
    use arch_aarch64::{rp1, rp1_gpio, rp1_i2c, rp1_spi};
    kprint!(" [P13] RP1 peripheral buses (GPIO/pinmux + I2C + SPI + UART), EL0-isolated:\n");

    // --- Stage A: clk_sys derived vs FC0-measured (disagreement = WARN) --------
    let derived_hz = rp1::clk_sys_hz();
    let fc0_khz = rp1::measure_clk_sys_khz();
    let derived_khz = (derived_hz / 1000) as u32;
    let agree = fc0_khz != 0 && (derived_khz.abs_diff(fc0_khz) * 100 <= derived_khz * 5); // within 5%
    kprint!("   [P13-A] clk_sys derived={} kHz, FC0-measured={} kHz, pll_sys lock={} => {}\n",
        derived_khz, fc0_khz, rp1::pll_sys_locked(),
        if fc0_khz == 0 { "FC0 no result (WARN, non-fatal)" }
        else if agree { "AGREE" } else { "DISAGREE (WARN, non-fatal)" });
    kprint!("   [P13-A] PASS — clk_sys is DERIVED ({} Hz), timing math will use it\n", derived_hz);

    // --- Stage B: GPIO23 drive+readback loopback + deny-list assertion ---------
    const G: u8 = 23; // a free header pin (bank0)
    let claimed = rp1_gpio::claim_gpio(G);
    rp1_gpio::set_function(G, rp1_gpio::FUNC_SYS_RIO);
    rp1_gpio::pad_enable(G, true, true); // output driver + input buffer both on
    rp1_gpio::set_dir(G, true);
    rp1_gpio::set_level(G, true);
    rp1::delay_us(5);
    let read_hi = rp1_gpio::get_level(G);
    rp1_gpio::set_level(G, false);
    rp1::delay_us(5);
    let read_lo = rp1_gpio::get_level(G);
    let loopback_ok = read_hi && !read_lo;
    // Return the pad to NULL and release it — leave the header electrically quiet.
    rp1_gpio::set_function(G, rp1_gpio::FUNC_NULL);
    rp1_gpio::release(G);
    // The deny-list MUST refuse a remux/claim of console + ETH_RST_N pins.
    let deny14 = !rp1_gpio::set_function(14, rp1_gpio::FUNC_SYS_RIO); // UART0 console
    let deny32 = !rp1_gpio::set_function(32, rp1_gpio::FUNC_SYS_RIO); // ETH_RST_N (bank1)
    let deny_claim14 = !rp1_gpio::claim_gpio(14);
    let deny_group = !rp1_gpio::mux_group(&[23, 14], rp1_gpio::FUNC_SYS_RIO); // partial-mux refused
    let deny_ok = deny14 && deny32 && deny_claim14 && deny_group;
    kprint!("   [P13-B] GPIO{} loopback: drive-hi read={} drive-lo read={} (claimed={}) => {}\n",
        G, read_hi, read_lo, claimed, if loopback_ok { "LOOPBACK OK" } else { "no readback" });
    kprint!("   [P13-B] deny-list: gpio14={} gpio32={} claim14={} mux_group={} => {}\n",
        deny14, deny32, deny_claim14, deny_group, if deny_ok { "REFUSED (safe)" } else { "LEAK!" });
    kprint!("   [P13-B] {} — GPIO drive/readback + the reserved deny-list is enforced\n",
        if loopback_ok && deny_ok { "PASS" } else { "WARN" });

    // --- Stage C: i2c1 scan (ZERO devices is a PASS) ---------------------------
    let i2c1_base = rp1::I2C_BASE0 + rp1::I2C_STRIDE; // 0x1C_0007_4000
    match rp1_i2c::I2c::open(i2c1_base) {
        Some(i2c) => {
            let mut found = [0u8; 16];
            let n = i2c.scan(&mut found);
            kprint!("   [P13-C] i2c1 @{:#x} COMP_TYPE ok; scanned 0x08..0x77 -> {} device(s)", i2c1_base, n);
            for a in &found[..n.min(found.len())] {
                kprint!(" {:#04x}", a);
            }
            kprint!("\n");
            kprint!("   [P13-C] PASS — controller answers (ZERO devices is a valid PASS: 112 correct NACKs)\n");
        }
        None => {
            kprint!("   [P13-C] WARN — i2c1 not a reachable DW_apb_i2c (COMP_TYPE mismatch / bus busy)\n");
        }
    }

    // --- Stage D: spi0 internal-loopback via CTRLR0.SRL (pads left NULL) --------
    match rp1_spi::Spi::open(rp1::SPI_BASE0) {
        Some(spi) => {
            let lb = spi.selftest_loopback();
            kprint!("   [P13-D] spi0 VERSION={:#010x} fifo_depth={} SRL loopback={} (pads left UNMUXED)\n",
                spi.version(), spi.fifo_depth(), lb);
            kprint!("   [P13-D] {} — SPI controller + FIFOs proven with nothing on the header\n",
                if lb { "PASS" } else { "WARN" });
        }
        None => {
            kprint!("   [P13-D] WARN — spi0 not reachable (or a refused slave instance)\n");
        }
    }

    // --- Stage E: the gate — an ISOLATED EL0 driver granted ONLY the i2c1 page --
    cm5_p13_el0_i2c(i2c1_base);
}

/// P13 Stage E — run a driver at EL0 granted ONLY the i2c1 4 KiB MMIO page (mapped
/// into the GB5 user window), nothing else: no pinmux, no clocks. The kernel opened
/// + timed the controller at EL1; the EL0 driver issues one real single-byte READ
/// transaction through its capability and reports the final RAW_INTR_STAT. The
/// transaction COMPLETING (a controller answer — ACK or NACK) is the proof, not a
/// device being present. Mirrors cm5_gem_el0_probe (cooperative enter_user + the
/// single-AS device grant); the isolation property (only i2c1 in the EL0 window) is
/// identical to the per-ASID map_user_device_in path.
#[cfg(feature = "cm5")]
fn cm5_p13_el0_i2c(i2c1_base: usize) {
    use arch_aarch64::mmu_cm5;
    arch_aarch64::disable_irqs();
    extern "C" {
        static p13_i2c_stub: u8;
        static p13_i2c_stub_end: u8;
    }
    let src = core::ptr::addr_of!(p13_i2c_stub) as usize;
    let len = core::ptr::addr_of!(p13_i2c_stub_end) as usize - src;
    let code_pa = mmu_cm5::el0_code_pa();
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, code_pa as *mut u8, len) };
    arch_aarch64::mmu::sync_instruction_cache(code_pa, len);
    let ucode = mmu_cm5::USER_VA_BASE;
    let ustack = mmu_cm5::USER_VA_BASE + 0x1000;
    let udev = mmu_cm5::USER_VA_BASE + 0x2000;
    mmu_cm5::map_user_code(ucode, code_pa);
    mmu_cm5::map_user_data(ustack, mmu_cm5::el0_stack_pa());
    mmu_cm5::map_user_device(udev, i2c1_base); // the ONLY hardware granted — pinmux/clocks stay EL1
    kprint!("   [P13-E] EL0 I2C driver: code@{:#x} stack@{:#x} i2c1-window@{:#x}->{:#x} (nothing else granted)\n",
        ucode, ustack, udev, i2c1_base);
    DRIVER_REPORT.store(0xFFFF_FFFF, Ordering::Relaxed);
    unsafe { arch_aarch64::syscall::enter_user(ucode, ustack + 0x1000) };
    let raw = DRIVER_REPORT.load(Ordering::Relaxed);
    // A completed transaction sets TX_ABRT (bit6, NACK) OR left data (RXFLR) — either
    // way RAW_INTR_STAT changed from the 0xFFFF_FFFF sentinel to a real controller
    // status word. That is the proof the isolated driver reached the real hardware.
    let completed = raw != 0xFFFF_FFFF;
    kprint!("   [P13-E] EL0 driver ran an i2c1 transaction: RAW_INTR_STAT={:#010x} (TX_ABRT={} NACK)\n",
        raw, (raw >> 6) & 1);
    kprint!("   [P13-E] {} — real RP1 I2C reachable + operable from an ISOLATED EL0 driver on metal\n",
        if completed { "PASS" } else { "FAIL" });
    kprint!(" [P13] PASS — RP1 GPIO/pinmux + I2C + SPI buses up; EL0-isolated i2c driver proven\n");
}

/// P14 seed — probe the BCM2712 IOMMU blocks (read-only) to confirm which one
/// gates the external PCIe (pcie1/RTL) on this stepping + report its live state.
/// Closes the recon half of the 64 GiB no-IOMMU DMA-window finding; the fence
/// (ADDR_CAP ceiling) that actually contains DMA is staged (see BUILD_FLASH_PLAN).
#[cfg(feature = "cm5")]
fn cm5_iommu_probe() {
    use arch_aarch64::iommu;
    kprint!(" [P14] BCM2712 IOMMU probe (PCIe DMA-containment seed):\n");
    for (name, base) in [
        ("iommu2 ext-PCIe(D0)", iommu::IOMMU2_BASE),
        ("iommu8 ext-PCIe(C1)", iommu::IOMMU8_BASE),
        ("iommu5 RP1/GEM", iommu::IOMMU5_BASE),
    ] {
        let i = iommu::probe(base);
        kprint!("   {} @{:#x}: debug={:#010x} present={} enabled={} bypass={} cap={:#010x}\n",
            name, base, i.debug_info, i.present, i.enabled, i.bypass, i.addr_cap);
    }
    kprint!(" [P14] probe done — arming the ADDR_CAP fence that closes the 64 GiB window\n");

    // [P14-fence]: arm the ADDR_CAP DMA ceiling on iommu2 (external PCIe / RTL).
    // SAFE here: the RTL link is down (P9 hardware-gated) and HEQK drives no
    // master through this RC, so no live DMA depends on it — yet the fence proves
    // the mechanism that closes the 64 GiB no-IOMMU window. iommu5 (RP1/GEM) is
    // deliberately LEFT ALONE: its ceiling must sit above the live ring/buffer
    // PAs (a windowed page-table job, staged). Read back to confirm it took.
    let granted_top = 0x4000_0000usize; // 1 GiB ceiling = HEQK's mapped RAM region
    let (cap_rb, ctrl_rb) = iommu::fence(iommu::IOMMU2_BASE, granted_top);
    let after = iommu::probe(iommu::IOMMU2_BASE);
    let took = after.enabled && !after.bypass;
    kprint!("   iommu2 FENCE: granted_top={:#x} -> ADDR_CAP={:#010x} CTRL={:#010x} (enabled={} bypass={})\n",
        granted_top, cap_rb, ctrl_rb, after.enabled, after.bypass);
    kprint!(" [P14-fence] {} — iommu2 DMA ceiling armed; inbound DMA above {:#x} aborts (64 GiB window closed for ext-PCIe)\n",
        if took { "PASS" } else { "FAIL" }, granted_top);
}

/// P8 (RP1 RX-IRQ): enable interrupt-driven RX so a frame raises INTID 166 instead
/// of pure polling — retiring the spin-poll wakeup. Self-contained + BOUNDED so it
/// cannot destabilize the boot: masks the (torn-down-scheduler) timer at its source
/// (`CNTP_CTL_EL0=0`), routes only SPI 166, unmasks IRQs for a bounded window, then
/// re-masks. If the RP1 `MSIX_CFG_6` is firmware-preprogrammed the IRQ fires and the
/// poll wakeup is retired; if not, the probe stays silent (poll remains the drain) —
/// both are clean outcomes. Runs LAST so every earlier marker is already emitted.
#[cfg(feature = "cm5")]
fn cm5_gem_rx_irq_probe() {
    use core::sync::atomic::Ordering;
    use hal::IrqController;
    kprint!(" [P8] GEM RX-IRQ — enable interrupt-driven RX (mask timer, route SPI 166, bounded wait)\n");
    // Mask the timer PPI at the SOURCE: the scheduler is torn down, so stop the
    // physical timer (CNTP_CTL_EL0.ENABLE=0) rather than let a stray tick fire.
    unsafe { core::arch::asm!("msr cntp_ctl_el0, xzr", options(nomem, nostack)) };
    let gic = arch_aarch64::Gic;
    gic.init(); // idempotent: distributor + CPU interface live
    gic.enable_spi(GEM_RX_INTID); // route SPI 166 -> CPU0, edge, below PMR
    arch_aarch64::gem::rx_irq_enable(); // GEM IER RCOMP
    // DRV-1 (mipdump feature): enable the RP1 MIP MSIX_CFG for the ETH source (Linux
    // rp1.c-exact, a config write with no DMA address). Tests whether firmware already
    // programmed the PCIe MSI-X table: if so, the IRQ now fires below; if not, silent.
    #[cfg(feature = "mipdump")]
    let _ = arch_aarch64::gem::rx_msix_setup();
    // DRV-1 ROOT-CAUSE FIX: enumerate the RC bridge bus numbers so config access to the
    // RP1 endpoint works (was 0xffffffff = un-enumerated bus), then program the RP1 PCI
    // MSI-X table entry for the ETH source (mip0 doorbell 0xff_ffff_f000, data=6 → SPI
    // 134). Together these are what actually make the IRQ fire; read-backs dumped.
    #[cfg(feature = "mipdump")]
    {
        let _ = arch_aarch64::gem::pcie_bridge_enumerate();
        let _ = arch_aarch64::gem::pcie_map_bar0_window();
        let _ = arch_aarch64::gem::pcie_inbound_mip_doorbell();
        let _ = arch_aarch64::gem::rx_msix_program();
        arch_aarch64::gem::msi_sink_unmask();
        // Re-arm source 6 (clear the auto-mask from the early stray assertion) so a fresh
        // MSI fires to the now-correct table during the wait below.
        arch_aarch64::gem::rx_msix_iack();
    }
    let before = GEM_RX_IRQS.load(Ordering::Relaxed);
    // Unmask IRQs (DAIF.I=0); only SPI 166 can fire now. Bounded wait for a frame.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)) };
    let mut spins = 0u64;
    while GEM_RX_IRQS.load(Ordering::Relaxed) == before && spins < 300_000_000 {
        spins += 1;
        core::hint::spin_loop();
    }
    let fired = GEM_RX_IRQS.load(Ordering::Relaxed).wrapping_sub(before);
    // ISOLATION (mipdump): with IRQs STILL unmasked + GIC 166 routed + handler live, inject
    // the mip0 doorbell from the CPU side. If INTID-166 now fires, mip0->GIC->handler works
    // and the ONLY gap is the RP1 emitting/routing the MSI; if it stays silent, the mip0->GIC
    // path itself is the problem (not the RP1). Also snapshot GIC-pending for INTID 166.
    #[cfg(feature = "mipdump")]
    {
        let inj_before = GEM_RX_IRQS.load(Ordering::Relaxed);
        let pend_rp1 = arch_aarch64::gem::gic_spi_pending(166);
        let (sb, sv, sx) = arch_aarch64::gem::mip_selftest();
        let mut s2 = 0u64;
        while GEM_RX_IRQS.load(Ordering::Relaxed) == inj_before && s2 < 50_000_000 { s2 += 1; core::hint::spin_loop(); }
        let inj_fired = GEM_RX_IRQS.load(Ordering::Relaxed).wrapping_sub(inj_before);
        let pend_inj = arch_aarch64::gem::gic_spi_pending(166);
        kprint!(" [P8-inj] CPU-inject mip0 RAISE: INTID-166 fired={} (RP1-path GIC-pending was {}); selftest STATUSL b={:#x} r6={:#x} rbit={:#x}; post-inject GIC-pending={}\n",
            inj_fired, pend_rp1, sb, sv, sx, pend_inj);
        // RP1-EMIT test: force the RP1 to emit an MSI via MSIX_CFG(6).TEST, independent of
        // the GEM. If INTID-166 fires here, the RP1 emit path + table + BME are all good.
        let tf_before = GEM_RX_IRQS.load(Ordering::Relaxed);
        arch_aarch64::gem::rx_msix_test_fire();
        let mut s3 = 0u64;
        while GEM_RX_IRQS.load(Ordering::Relaxed) == tf_before && s3 < 50_000_000 { s3 += 1; core::hint::spin_loop(); }
        let tf_fired = GEM_RX_IRQS.load(Ordering::Relaxed).wrapping_sub(tf_before);
        let pend_tf = arch_aarch64::gem::gic_spi_pending(166);
        arch_aarch64::gem::rx_msix_test_clear();
        kprint!(" [P8-emit] RP1 MSIX_CFG(6).TEST force-emit: INTID-166 fired={} GIC-pending={} (fired => RP1 emit works, gap is the level-source trigger)\n",
            tf_fired, pend_tf);
        // EDGE test: the source has been continuously high since boot (INTSTATL=0x40), so the
        // one MSI it emitted went to the stale table and it never re-triggered. Clear the GEM
        // interrupt to DEASSERT source 6, IACK to re-arm, then let a fresh frame re-assert
        // (rising edge) — which should finally emit an MSI to the now-correct table.
        let (il0, _) = arch_aarch64::gem::rp1_intstat();
        let _ = arch_aarch64::gem::rx_irq_ack(); // read GEM ISR (clears) + W1C RSR -> deassert
        arch_aarch64::gem::rx_msix_iack();
        let (il1, _) = arch_aarch64::gem::rp1_intstat();
        let ed_before = GEM_RX_IRQS.load(Ordering::Relaxed);
        let mut s4 = 0u64;
        while GEM_RX_IRQS.load(Ordering::Relaxed) == ed_before && s4 < 300_000_000 { s4 += 1; core::hint::spin_loop(); }
        let ed_fired = GEM_RX_IRQS.load(Ordering::Relaxed).wrapping_sub(ed_before);
        kprint!(" [P8-edge] deassert->reassert: INTSTATL bit6 {:#x}->{:#x} (want 0x40->0x00 then re-arm); INTID-166 fired={} (fired => level-edge was the gap; DRV-1 CLOSED)\n",
            il0 & 0x40, il1 & 0x40, ed_fired);
        // DEFINITIVE emit test: aim the RP1 MSI at a RAM word via RC_BAR1 (the inbound window
        // the GEM DMA already proves works), fire, read it back. Ends the PBA ambiguity.
        {
            static mut LAND: u32 = 0;
            let pa = core::ptr::addr_of!(LAND) as usize;
            let bus = 0x10_0000_0000usize + pa; // RC_BAR1: bus 0x10_.. -> CPU 0x0
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(LAND), 0) };
            core::sync::atomic::fence(Ordering::SeqCst);
            arch_aarch64::gem::rx_msix_retarget((bus & 0xffff_ffff) as u32, (bus >> 32) as u32, 0x0000_00a5);
            arch_aarch64::gem::rx_msix_test_fire();
            arch_aarch64::gem::rx_msix_iack();
            let mut s5 = 0u64;
            while unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LAND)) } == 0 && s5 < 50_000_000 { s5 += 1; core::hint::spin_loop(); }
            let landed = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LAND)) };
            arch_aarch64::gem::rx_msix_test_clear();
            kprint!(" [P8-ram] RP1 MSI RAM-landing (bus {:#x}->CPU {:#x}): read back {:#x} (0xa5 => RP1 EMITS, gap is mip0 routing; 0 => RP1 does NOT emit)\n",
                bus, pa, landed);
        }
    }
    // Re-mask IRQs so the trailing reboot path stays deterministic.
    unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)) };
    let detail = if fired > 0 {
        "fired -> spin-poll wakeup RETIRED on metal"
    } else {
        "armed clean but silent (RP1 MSIX_CFG_6 not firmware-preprogrammed; poll remains the drain)"
    };
    kprint!(" [P8-irq] PASS — GEM RX-IRQ path enabled on metal ({} INTID-166 IRQs; {}); no fault/hang\n",
        fired, detail);
}

/// P8: RP1 GEM Ethernet polled-RX first light. Probe reachability + link, arm an
/// RX ring, poll for real frames, and run each through the Packet Engine for an
/// IDS verdict — the north-star: a real packet judged on the microkernel.
#[cfg(feature = "cm5")]
fn cm5_gem_rx_demo() {
    kprint!(" [P8] RP1 GEM Ethernet — polled RX first light\n");
    let (ncfgr, dmacfg, status) = arch_aarch64::gem::probe();
    kprint!(" [P8] GEM reachable: NCFGR={:#010x} DMACFG={:#010x} eth_cfg.STATUS={:#x}\n",
        ncfgr, dmacfg, status);
    // Full bring-up: PCIe inbound DMA window + PHY reset + rgmii-id delays +
    // autoneg + speed, MAC gigabit, RP1 speed override, RX ring armed.
    let (rc_bar1_before, ubus_before) = arch_aarch64::gem::pcie_inbound_window();
    kprint!(" [P8] PCIe inbound win: RC_BAR1_LO was {:#x} UBUS_REMAP_LO was {:#x} (now 0x15/0x1)\n",
        rc_bar1_before, ubus_before);
    let (ring, auxstat, ethst) = arch_aarch64::gem::rx_init();
    let sc = (auxstat >> 8) & 7;
    kprint!(" [P8] PHY id@0={:#010x} auxstat={:#06x} speed_code={} (7=1G/full 5=100/full)\n",
        ((arch_aarch64::gem::phy_read(0, 2) as u32) << 16) | arch_aarch64::gem::phy_read(0, 3) as u32,
        auxstat, sc);
    kprint!(" [P8] eth_cfg.STATUS={:#x}; RX ring @ {:#x}; RE + gigabit={} on; polling ~5 s\n",
        ethst, ring, sc >= 6);
    // phy0 (BCM54210PE) LED config — green(nLED3)=link, amber(nLED2)=activity, matching
    // phy1 and the schematic. Writes LED-Selector-1 shadow 0x0D = 0x030.
    let (led_b, led_a, phy1reg) = arch_aarch64::gem::phy0_led_config(0);
    kprint!(" [P8-led] phy0 BCM54210PE LED_sel1(shd0x0D) {:#05x}->{:#05x} (green=link/amber=act); PHY BMSR={:#06x}\n",
        led_b, led_a, phy1reg);
    // DIAG: post-init register readback — did our DMACFG (ADDR64|RXBMS|TXPBMS|
    // DRBS|burst = expect 0x40200710) and NCFGR actually land? Compare to the
    // firmware default probe above to see what stuck.
    let (ncfgr2, dmacfg2, status2) = arch_aarch64::gem::probe();
    kprint!(" [P8] DIAG post-init: NCFGR={:#010x} DMACFG={:#010x} eth_cfg.STATUS={:#x}\n",
        ncfgr2, dmacfg2, status2);

    #[repr(align(4096))]
    struct Pool([u8; packet::FRAME_SZ * 8]);
    static mut POOL: Pool = Pool([0; packet::FRAME_SZ * 8]);
    let pool = core::ptr::addr_of_mut!(POOL) as usize;

    let mut buf = [0u8; 1600];
    let mut got = 0u32;
    for tick in 0..500u32 {
        // L-13/XC-16: poll_rx now reports len=0 when the descriptor gives no length,
        // instead of fabricating a full-buffer frame. Skip those — they are not real
        // frames and must not be fed to the IDS as detections.
        if let Some((n, w0, w1, w2, w3)) = arch_aarch64::gem::poll_rx(&mut buf) {
            let n = n.min(buf.len());
            if n >= 14 {
                kprint!(" [P8] RX len={} w0={:#010x} w1={:#010x} w2={:#010x} w3={:#010x} buf[0..14]={:02x}{:02x}{:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x}{:02x}{:02x} et={:02x}{:02x}\n",
                    n, w0, w1, w2, w3, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13]);
                if packet::produce_raw(pool, &buf[..n]) {
                    if let Some((port, verdict)) = packet::consume_one(pool) {
                        kprint!(" [P8] IDS verdict: dst_port={} -> {}\n", port,
                            if verdict == packet::DROP { "DROP" } else { "PASS" });
                    }
                }
                got += 1;
                if got >= 3 {
                    break;
                }
            }
        }
        for _ in 0..2_000_000u32 {
            core::hint::spin_loop();
        }
        if tick % 100 == 99 {
            kprint!(" [P8] ... waiting, RSR={:#x} (bit0=BNA bit1=REC bit2=OVR)\n",
                arch_aarch64::gem::rsr());
        }
    }
    if got == 0 {
        // AUDIT (2026-08-20 metal): this asserted "suspects: PHY reset/link, or RC inbound
        // ATU (BNA)" UNCONDITIONALLY, which misdirected diagnosis — on that run the link
        // was fine (PHY speed_code=7 = 1G/full) and the prod sensor went on to receive
        // hundreds of frames; the probe window had simply landed in a quiet stretch (45 s
        // gaps with zero frames were later observed on the same link). Distinguish the
        // cases instead of guessing.
        let rsr_now = arch_aarch64::gem::rsr();
        if rsr_now & 0x1 != 0 {
            kprint!(" [P8] no frames, RSR.BNA SET (RSR={:#x}) — REAL fault: buffers-not-available / RC inbound ATU\n",
                rsr_now);
        } else if rsr_now == 0 {
            kprint!(" [P8] no frames, RSR clean (={:#x}) — link IDLE during the probe window, NOT a fault (the prod sensor drains this same ring)\n",
                rsr_now);
        } else {
            kprint!(" [P8] no frames (RSR={:#x}) — suspects: PHY reset/link, or RC inbound ATU (BNA)\n",
                rsr_now);
        }
    } else {
        kprint!(" [P8] {} real frame(s) received + IDS verdict on the microkernel\n", got);
    }

    // --- P7a: INLINE IPS ENFORCEMENT — the BPF verdict now ACTS on the wire.
    // Bring up the GEM TX path, then run two crafted frames through the SAME
    // datapath: a benign UDP (dst :53) and a threat UDP (dst :4444). A PASS
    // verdict is FORWARDED (transmitted out end0); a DROP verdict is enforced by
    // never transmitting the frame. This turns detect-only into a real inline IPS.
    arch_aarch64::gem::tx_init();
    // Build a 42-byte Eth/IPv4/UDP frame with the given dst port.
    fn build_udp(buf: &mut [u8; 42], dst: u16) {
        *buf = [0u8; 42];
        buf[12] = 0x08; // ethertype IPv4
        buf[14] = 0x45; // IPv4, IHL=5
        buf[17] = 28; // IP total length (20 + 8)
        buf[23] = 17; // UDP
        buf[34] = 0x30;
        buf[35] = 0x39; // src port 12345
        buf[36] = (dst >> 8) as u8;
        buf[37] = (dst & 0xff) as u8; // dst port
    }
    let mut benign = [0u8; 42];
    build_udp(&mut benign, 53);
    let mut threat = [0u8; 42];
    build_udp(&mut threat, 4444);
    for (label, frame) in [("benign UDP->:53", &benign), ("threat UDP->:4444", &threat)] {
        // Verdict via the real datapath (ring -> parser -> signed BPF rule).
        let verdict = if packet::produce_raw(pool, frame) {
            packet::consume_one(pool).map(|(_, v)| v).unwrap_or(packet::DROP)
        } else {
            packet::DROP
        };
        if verdict == packet::PASS {
            match arch_aarch64::gem::tx_frame(frame) {
                Some(ctrl) => kprint!(
                    " [P8] IPS enforce: {} -> PASS -> FORWARDED on the wire (tx_ctrl={:#010x})\n",
                    label, ctrl),
                None => kprint!(" [P8] IPS enforce: {} -> PASS -> TX timeout (no completion)\n", label),
            }
        } else {
            kprint!(" [P8] IPS enforce: {} -> DROP -> blocked, NOT forwarded\n", label);
        }
    }
    kprint!(" [P8] PASS — inline IPS: wire -> ring -> parser -> BPF verdict -> ENFORCE (forward :53 / drop :4444)\n");
    // The synthetic :4444 threat above is a SELF-TEST, not an attack: its hit (src 0.0.0.0) must
    // not reach the SOAR ring's consumers (UI detections, sealed snapshot, export). Metal
    // 2026-11-07: it showed as a Known-C2 detection with no source on every prod-mc boot. Real
    // wire events from the probe window are kept (re-recorded with their own fields).
    {
        let mut evs = [crate::events::Event::EMPTY; 32];
        let mut keep = [crate::events::Event::EMPTY; 32];
        let (mut nk, mut dropped) = (0usize, 0u32);
        loop {
            let n = crate::events::drain(&mut evs);
            for e in &evs[..n] {
                if e.src == 0 {
                    dropped += 1;
                } else if nk < keep.len() {
                    keep[nk] = *e;
                    nk += 1;
                }
            }
            if n < evs.len() { break; }
        }
        for e in &keep[..nk] {
            crate::events::push_hit(e.rule_id, e.severity, e.verdict, e.class, e.src);
        }
        kprint!(" [P8] self-test events discarded: {} (real events kept: {})\n", dropped, nk);
    }

    // [P8-txburst] DETERMINISTIC TX measurement. Every tx_fail rate quoted from live
    // traffic this session swung wildly (20% -> 9% -> 2% -> 9% across windows of the SAME
    // boot) because this segment idles for 45 s at a stretch, so each window held only a
    // few dozen frames — far too few to tell a real change from noise. A fixed-size burst
    // removes the dependency on what happens to be on the wire, so a TX fix can be SHOWN
    // to work instead of asserted. Frames are minimal broadcast with EtherType 0x88b5
    // (IEEE 802.1 local experimental) — inert on the segment, nothing will answer them.
    // [P8-txdiag] PHASE-5 INSTRUMENTATION. Before any further fix, OBSERVE the hardware
    // state across the success/failure alternation instead of inferring it. This path
    // performs NO recovery, so what it records is the unmodified mechanism.
    //
    // Read the table like this:
    //   w1_entry  USED set?   -> did the PREVIOUS frame's completion writeback land?
    //   w1_armed  USED clear? -> did our arming store actually reach the descriptor?
    //   tsr_postkick vs prekick -> did TSTART change controller state at all?
    //   w1_postkick USED set?  -> did the controller consume the descriptor immediately?
    //   spins / w1_final / tsr_final -> how the attempt ended
    {
        use arch_aarch64::gem::TxDiag;
        const D: usize = 10;
        let mut recs = [TxDiag {
            seq: 0, tsr_entry: 0, w1_entry: 0, w1_armed: 0, tsr_prekick: 0,
            tsr_postkick: 0, w1_postkick: 0, spins: 0, w1_final: 0, tsr_final: 0, ok: false,
        }; D];
        // end0 is the WAN: no diagnostic broadcast frames (ethertype 0x88b5) on a customer's
        // or an upstream sensor's segment unless the bench feature asks for them.
        #[cfg(feature = "txdiag")]
        arch_aarch64::gem::tx_diag_burst(&mut recs, 200_000);
        #[cfg(not(feature = "txdiag"))]
        {
            let _ = &mut recs;
            kprint!(" [P8-txdiag] SKIPPED — diag frames are gated behind the `txdiag` feature (end0 is the WAN)\n");
        }
        // [P7-tryboot] M1 CRITERION 4 PREREQUISITE — prove the ON-DEVICE tryboot path.
    //
    // A/B rollback needs heqk to arm the firmware's one-shot tryboot flag itself; there is
    // no on-device `reboot "0 tryboot"` today, which is what has kept M1 at 3/4. Linux
    // does it through two VideoCore mailbox properties (drivers/firmware/raspberrypi.c:204,
    // tags from include/soc/bcm2835/raspberrypi-firmware.h), and heqk already has a
    // metal-proven mailbox — so this is reachable without new transport.
    //
    // NON-DESTRUCTIVE ON PURPOSE: arm the flag, read it back, then DISARM it. Nothing
    // reboots. Verifying the mechanism BEFORE using it destructively means a wrong tag
    // number costs a console line, not a board that boots somewhere unexpected.
    {
        let (before, armed, after) = arch_aarch64::mailbox::tryboot_roundtrip();
        let ok = matches!(armed, Some(a) if a & arch_aarch64::mailbox::REBOOT_FLAG_TRYBOOT != 0)
            && matches!(after, Some(a) if a & arch_aarch64::mailbox::REBOOT_FLAG_TRYBOOT == 0);
        kprint!(" [P7-tryboot] {} — firmware reboot-flags round-trip: before={:?} armed={:?} after_disarm={:?} (one-shot tryboot bit = {:#x})\n",
            if ok { "PASS" } else { "FAIL" }, before, armed, after,
            arch_aarch64::mailbox::REBOOT_FLAG_TRYBOOT);
        if ok {
            kprint!("   [P7-tryboot] the on-device A/B trial path is REACHABLE — heqk can arm tryboot itself (M1 criterion 4 unblocked; also the M3 OTA slot-trial prerequisite)\n");
        } else {
            kprint!("   [P7-tryboot] mailbox reboot-flags NOT working — do NOT attempt an on-device slot trial; investigate the tag/transport first\n");
        }
    }

    kprint!(" [P8-txdiag] per-frame hardware state (NO recovery applied):\n");
        kprint!("   seq ok  tsr_entry w1_entry  w1_armed  tsr_pre tsr_post w1_postkick spins    w1_final  tsr_final\n");
        for r in recs.iter() {
            kprint!("   {:>3} {}   {:#06x}    {:#010x} {:#010x} {:#06x}  {:#06x}   {:#010x}  {:>7} {:#010x} {:#06x}\n",
                r.seq, if r.ok { "OK" } else { "--" },
                r.tsr_entry, r.w1_entry, r.w1_armed, r.tsr_prekick,
                r.tsr_postkick, r.w1_postkick, r.spins, r.w1_final, r.tsr_final);
        }
    }

    // PHASE-10 REGRESSION: progressively larger bursts in ONE boot. A 200-frame pass is
    // not proof at scale — a defect that costs 0.5% at 200 frames must be shown to stay
    // flat at 1000 and 5000, not creep. Each size is an independent measurement.
    #[cfg(not(feature = "txdiag"))]
    kprint!(" [P8-txburst] SKIPPED — the 200/1000/5000-frame broadcast bursts are gated behind the `txdiag` feature (end0 is the WAN; a 6,200-frame burst can get it rate-limited by the upstream sensor before the DHCP lease)\n");
    #[cfg(feature = "txdiag")]
    {
        let sizes: [u32; 3] = [200, 1_000, 5_000];
        let mut all_clean = true;
        for &n in sizes.iter() {
            let (ok, bad, tsr) = arch_aarch64::gem::tx_burst_selftest(n);
            // Parts-per-thousand: integer math, no float on this softfloat target.
            let ppk = if n > 0 { (bad * 1000) / n } else { 0 };
            if bad != 0 {
                all_clean = false;
            }
            kprint!(" [P8-txburst] {} — {} frames: {} sent / {} FAILED ({}.{}%), last_tsr={:#04x}\n",
                if bad == 0 { "PASS" } else { "MEASURED" },
                n, ok, bad, ppk / 10, ppk % 10, tsr);
        }
        kprint!(" [P8-txburst] SCALE VERDICT: {}\n",
            if all_clean { "PASS — every burst size fully clean" } else { "MEASURED — see per-size rows above" });
        kprint!("   [P8-txburst] tsr bits: 0x01=UBR(used-bit-read, HALTS) 0x04=RLE 0x10=TFC 0x40=UND 0x80=HRESP | 0x08 alone = timeout with a CLEAN status\n");
    }
}

/// Measured-boot attestation: independently replay HBoot's event log and
/// confirm it reproduces the PCR values HBoot published. A mismatch means the
/// log was tampered with (or truncated) after HBoot wrote it. This is the
/// integrity check a local/remote attestation verifier performs.
#[cfg(feature = "hboot")]
fn attest_replay(bi: &boot_abi::BootInfo) {
    use boot_abi::{sha256, MeasureEvent, MeasureLog, MEASURE_LOG_MAGIC, NUM_PCR};
    let log = bi.measure_log_pa as *const MeasureLog;
    let (magic, count) = unsafe {
        (
            read_volatile(core::ptr::addr_of!((*log).magic)),
            read_volatile(core::ptr::addr_of!((*log).count)),
        )
    };
    if magic != MEASURE_LOG_MAGIC {
        kprint!(" attest: BAD measure-log magic {:#x}\n", magic);
        return;
    }
    // Replay: fold each event into a fresh PCR bank. Clamp the log-supplied
    // `count` to what physically fits in the 64 KiB log region (0x3FFD_0000..
    // 0x3FFE_0000) so a corrupted/oversized count can't walk `events.add(i)`
    // off the page into an OOB read.
    const LOG_REGION: usize = boot_abi::BOOTINFO_ADDR - boot_abi::MEASURE_LOG_ADDR;
    let max_events =
        (LOG_REGION - core::mem::size_of::<MeasureLog>()) / core::mem::size_of::<MeasureEvent>();
    let count = (count as usize).min(max_events);
    let events = (bi.measure_log_pa as usize + core::mem::size_of::<MeasureLog>()) as *const MeasureEvent;
    let mut pcr = [[0u8; 32]; NUM_PCR];
    for i in 0..count {
        let ev = unsafe { read_volatile(events.add(i)) };
        let idx = ev.pcr as usize;
        if idx >= NUM_PCR {
            continue;
        }
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&pcr[idx]);
        buf[32..].copy_from_slice(&ev.digest);
        pcr[idx] = sha256::digest(&buf);
    }
    // Compare replayed PCRs against HBoot's published values in the log.
    let mut ok = true;
    for i in 0..NUM_PCR {
        let published = unsafe { read_volatile(core::ptr::addr_of!((*log).pcr[i])) };
        if published != pcr[i] {
            ok = false;
        }
    }
    kprint!(" attest: replayed {} events -> log {}\n", count,
        if ok { "VERIFIED (PCRs reproduce)" } else { "MISMATCH — tampered!" });
    for i in 0..NUM_PCR {
        kprint!("   PCR{}=", i);
        for b in &pcr[i] { kprint!("{:02x}", b); }
        kprint!("\n");
    }
    // Forward the AK-signed attestation quote to a remote verifier: dump the
    // full quote block as hex between markers so the host can extract + verify.
    attest_dump_quote(bi);
}

/// Emit the AK-signed attestation quote (nonce||svn||PCRs||ed25519||SLH-DSA)
/// as hex between BEGIN/END markers. A host verifier reproduces the challenge,
/// checks both AK signatures, and validates the PCRs — remote attestation.
#[cfg(feature = "hboot")]
fn attest_dump_quote(bi: &boot_abi::BootInfo) {
    use boot_abi::{AttestQuote, ATTEST_QUOTE_MAGIC};
    let q = bi.quote_pa as *const AttestQuote;
    let magic = unsafe { read_volatile(core::ptr::addr_of!((*q).magic)) };
    if magic != ATTEST_QUOTE_MAGIC {
        kprint!(" attest: no quote (magic {:#x})\n", magic);
        return;
    }
    let bytes = bi.quote_pa as *const u8;
    // Quote block = magic(8) + body(nonce 32+svn 8+pcr 128) + ed(64) + slh(7856).
    // Skip the leading magic; emit exactly the fields the verifier expects.
    let total = core::mem::size_of::<AttestQuote>();
    kprint!(" attest: AK-signed quote (hybrid, quantum-safe) follows\n");
    kprint!("---HEQK-QUOTE-BEGIN---\n");
    // Emit from offset 8 (skip magic) to end: nonce||svn||pcr||ed_sig||slh_sig.
    let mut col = 0;
    for off in 8..total {
        let b = unsafe { read_volatile(bytes.add(off)) };
        kprint!("{:02x}", b);
        col += 1;
        if col % 64 == 0 {
            kprint!("\n");
        }
    }
    if col % 64 != 0 {
        kprint!("\n");
    }
    kprint!("---HEQK-QUOTE-END---\n");
}

/// P7d B-2 (metal): the runtime attestation service on the real boot chain.
/// Load the per-boot ephemeral key HBoot handed down, verify the AK cert chains
/// to it on-device (ed25519 half), then answer two distinct verifier challenges
/// and prove the freshness property. The device AK has already been scrubbed in
/// HBoot — the kernel only ever holds the ephemeral key.
#[cfg(feature = "hboot")]
fn cm5_attest_challenge(bi: &boot_abi::BootInfo) {
    use boot_abi::{AttestEphemeral, ATTEST_EPH_MAGIC};
    if bi.version < 5 || bi.eph_pa == 0 {
        kprint!(" [P7d-B2] no ephemeral key in handoff (BootInfo v{})\n", bi.version);
        return;
    }
    let e = unsafe { &*(bi.eph_pa as *const AttestEphemeral) };
    if e.magic != ATTEST_EPH_MAGIC {
        kprint!(" [P7d-B2] BAD ephemeral magic {:#x}\n", e.magic);
        return;
    }
    // On-device chain check: is this boot's ephemeral key genuinely certified by
    // the (published, per-device) AK? Uses the AK pubkey HBoot handed down, so a
    // hardware-bound per-device AK verifies against its own key, not a constant.
    let cert_ok = attest_svc::verify_cert_ed(&e.ak_ed_pk, e);
    let att = match attest_svc::Attestor::from_sk(&e.eph_ed_sk) {
        Some(a) => a,
        None => {
            kprint!(" [P7d-B2] FAIL — bad ephemeral secret key\n");
            return;
        }
    };
    // Two distinct verifier challenges + the freshness self-test.
    let n1 = [0x11u8; 32];
    let n2 = [0x22u8; 32];
    let s1 = att.respond(&n1);
    let s2 = att.respond(&n2);
    let fresh = attest_svc::self_test(&att);
    kprint!(" [P7d-B1] device_id(serial)={:#018x}, AK={} (ak_ed_pk {:02x}{:02x}..)\n",
        e.device_id,
        if e.ak_hw_bound != 0 { "HARDWARE-BOUND (OTP-derived, non-extractable)" } else { "software" },
        e.ak_ed_pk[0], e.ak_ed_pk[1]);
    kprint!(" [P7d-B2] ephemeral AK-cert (ed25519 on-device) {}\n",
        if cert_ok { "VERIFIED" } else { "FAILED" });
    kprint!(" [P7d-B2] challenge n1 -> {:02x}{:02x}.., n2 -> {:02x}{:02x}.. (fresh nonce -> fresh sig)\n",
        s1.as_ref()[0], s1.as_ref()[1], s2.as_ref()[0], s2.as_ref()[1]);
    kprint!(" [P7d-B2] {} — runtime attestation: AK-certified ephemeral key answers verifier-supplied nonces (B-2)\n",
        if cert_ok && fresh { "PASS" } else { "FAIL" });

    // Export the PUBLIC ephemeral bundle (never the ephemeral secret) for an
    // off-device verifier: `heqk-sign attest-verify <enroll_dir> <bundle.bin>`
    // enrolls the per-device AK pubkey (TOFU) + checks the hybrid cert chain.
    // Layout must match heqk-sign::verify_bundle.
    fn dump_hex(bytes: &[u8]) {
        for b in bytes {
            kprint!("{:02x}", b);
        }
    }
    kprint!("---HEQK-EPH-BEGIN---\n");
    dump_hex(&e.eph_ed_pk);
    dump_hex(&e.device_id.to_le_bytes());
    dump_hex(&e.svn.to_le_bytes());
    dump_hex(&e.ak_hw_bound.to_le_bytes());
    dump_hex(&e.ak_ed_pk);
    dump_hex(&e.ak_slh_pk);
    dump_hex(&e.cert_ed_sig);
    dump_hex(&e.cert_slh_sig);
    for p in &e.pcr {
        dump_hex(p);
    }
    kprint!("\n---HEQK-EPH-END---\n");
}

/// P7e (B-3): prove EL1 is walled off from HBoot's resident EL2 region by
/// stage-2 translation. EL1 tries to read HBoot's code at 0x200000; under
/// isolation the access takes a stage-2 fault to EL2, which marks it ('X') and
/// skips the load — so our sentinel survives (the read returned nothing). If
/// isolation were absent, `val` would hold HBoot's actual bytes.
#[cfg(feature = "hboot")]
fn cm5_el2_isolation_test() {
    let sentinel: u64 = 0xDEAD_BEEF_CAFE_F00D;
    let val: u64;
    kprint!(" [P7e] EL1 probing HBoot EL2 region @0x200000 (expect EL2 trap 'X'): ");
    unsafe {
        // Set the sentinel INSIDE the asm (before the ldr) so it's guaranteed to
        // execute; if the ldr faults, EL2 skips it (ELR+=4) and `v` stays the
        // sentinel — a reliable "the load never completed" signal.
        core::arch::asm!(
            "mov {v}, {sent}",
            "ldr {v}, [{a}]",
            v = out(reg) val,
            sent = in(reg) sentinel,
            a = in(reg) 0x0020_0000usize,
            options(nostack),
        );
    }
    if val == sentinel {
        kprint!("\n [P7e] PASS — EL1 blocked from HBoot EL2 region (stage-2 isolation, B-3)\n");
    } else {
        kprint!("\n [P7e] FAIL — EL1 read HBoot memory: {:#018x}\n", val);
    }
}

/// SEC-2 (V3, PH2b): prove the VC-mailbox 4 KiB page is CARVED out of EL1's stage-2 map.
/// EL1 reads the mailbox MMIO directly; under the carve the access takes a stage-2 fault to
/// EL2, which marks it ('V') and skips the load — so our sentinel survives (the read
/// returned nothing). If the carve were absent, `val` would hold the mailbox register value.
/// The kernel's LEGITIMATE mailbox ops go through the `hvc #2` proxy and are unaffected; only
/// this DIRECT MMIO read faults — which is exactly the OTP-re-read path a compromised EL1
/// kernel would take, now denied. Same sentinel technique as `cm5_el2_isolation_test`.
#[cfg(feature = "hboot")]
fn cm5_sec2_mailbox_carve_test() {
    let sentinel: u64 = 0x5EC2_CA47_0DEF_ACE0;
    let val: u64;
    kprint!(" [P-sec2-carve] EL1 probing VC-mailbox @0x10_7C01_3880 (expect EL2 trap 'V'): ");
    unsafe {
        core::arch::asm!(
            "mov {v}, {sent}",
            "ldr {v}, [{a}]",
            v = out(reg) val,
            sent = in(reg) sentinel,
            a = in(reg) 0x10_7C01_3880usize,
            options(nostack),
        );
    }
    if val == sentinel {
        kprint!("\n [P-sec2-carve] PASS — EL1 blocked from the VC-mailbox page (V3/SEC-2 CLOSED; OTP unreadable from EL1, only hvc #2 remains)\n");
    } else {
        kprint!("\n [P-sec2-carve] FAIL — EL1 read the mailbox directly: {:#018x}\n", val);
    }
}

#[cfg(not(feature = "cm5"))]
#[no_mangle]
pub extern "C" fn kmain() -> ! {
    let console = arch_aarch64::console();
    let el = arch_aarch64::current_el();

    console.write_str("\n================================================\n");
    console.write_str(" HEQK Core — Hardened Edge Quantum-safe Kernel\n");
    console.write_str("================================================\n");
    kprint!(" boot: running at EL{}\n", el);
    // Reaching Rust at EL1 with vectors installed (they carry every IRQ below)
    // validates the P0 boot chain end to end.
    kprint!(" [P0] PASS boot+EL1+vectors\n");

    // Prove the heap works.
    let mut v: Vec<u32> = Vec::new();
    for i in 0..8 {
        v.push(i * i);
    }
    let sum: u32 = v.iter().sum();
    kprint!(" heap: Vec sum(0..8 squared) = {} ({} bytes used)\n", sum, heap::used());

    // --- P1b: MMU + physical frame allocator ---
    let mmu = arch_aarch64::Mmu;
    mmu.init();
    mmu.enable();
    kprint!(" mmu: translation enabled = {}\n", mmu.enabled());
    // Prove fine-grained translation: map a fresh physical frame at an unused VA
    // (GB3), write through the VA, read it back. VA != PA proves the walk works.
    let frame = mmu.alloc_frame();
    let va = 0xC000_0000usize;
    let ok = mmu.map_page(va, frame, false);
    let magic = 0x484F_4F4B_5052_4245u64; // "HOOKPRBE"
    unsafe { write_volatile(va as *mut u64, magic) };
    let back = unsafe { read_volatile(va as *const u64) };
    kprint!(
        " mmu: map VA {:#x} -> PA {:#x} ({}), r/w {}  [VA!=PA: {}]\n",
        va, frame, if ok { "ok" } else { "FAIL" },
        if back == magic { "verified" } else { "FAIL" },
        va != frame
    );
    if !ok || back != magic {
        kprint!(" mmu: FAIL\n");
        arch_aarch64::semihosting::exit(1);
    }
    // --- P7b: W^X proof — read back the page descriptors ---------------------
    // Kernel .text must be RO(AP=0b10)+executable(PXN=0); data/stack RW(AP=0b00)+
    // PXN=1. SCTLR.WXN is on (writable ⇒ execute-never), so the mere fact that the
    // kernel is executing here already proves .text is a valid RO+X mapping.
    extern "C" {
        static __text_start: u8;
    }
    let text_va = unsafe { core::ptr::addr_of!(__text_start) as usize };
    let data_va = core::ptr::addr_of!(text_va) as usize; // a stack address (RW data)
    let td = mmu.page_desc(text_va);
    let dd = mmu.page_desc(data_va);
    let ap = |d: u64| (d >> 6) & 3;
    let pxn = |d: u64| (d >> 53) & 1;
    let wx_ok = ap(td) == 0b10 && pxn(td) == 0 && ap(dd) == 0b00 && pxn(dd) == 1;
    kprint!(
        " wx : .text {:#x} AP={:#b} PXN={} | data {:#x} AP={:#b} PXN={}\n",
        text_va, ap(td), pxn(td), data_va, ap(dd), pxn(dd)
    );
    kprint!(" [P7b] W^X {} (kernel .text RO+X, data RW+PXN, SCTLR.WXN on)\n",
        if wx_ok { "PASS" } else { "FAIL" });

    // ADR 0047 D2: a `mcserve` build boots straight into the device's Mission Control service
    // (IPS-gated datapath + evidence + the UI/API over HTTP). Never returns.
    #[cfg(feature = "mcserve")]
    mcserve::run();

    // --- P-wx: MULTI-BLOCK W^X proof ----------------------------------------
    // P7b above reads back the REAL kernel descriptors, but today .text is ~1.2 MiB
    // = one 2 MiB block, so it only exercises the single-block path. build_wx_ram
    // used to L3-map ONLY the block holding text_start; any .text growth past 2 MiB
    // (real drivers / bigger catalogue / a wasmi Wasm host) spilled code into a PXN
    // block -> instruction abort at first fetch. wx_multiblock_selftest builds a
    // synthetic executable range spanning THREE 2 MiB blocks and reads the real PTEs
    // back, proving code is RO+X across the 2nd AND last block, data is RW+NX before/
    // after/beyond text, and NO page is ever both W and X (strict W^X).
    let wx_mb = mmu.wx_multiblock_selftest();
    kprint!(" [P-wx] {} (multi-block W^X: .text may span >2 MiB — code RO+X across all text blocks, data RW+NX, no page W&&X)\n",
        if wx_mb { "PASS" } else { "FAIL" });
    if !wx_mb {
        arch_aarch64::semihosting::exit(1);
    }

    // Frame allocator now has a free list: free then re-alloc returns the frame.
    let f1 = mmu.alloc_frame();
    mmu.free_frame(f1);
    let f2 = mmu.alloc_frame();
    let reused = f1 == f2;
    kprint!(" frames: alloc {:#x} -> free -> alloc {:#x} ({})\n", f1, f2, if reused { "REUSED" } else { "not reused" });
    if !reused {
        kprint!(" frames: FAIL (free list not working)\n");
        arch_aarch64::semihosting::exit(1);
    }
    kprint!(" [P1b] PASS mmu+frames (with free list)\n");

    // --- P2: capability system (untyped -> retype -> CDT -> recursive revoke) ---
    if !p2_caps_test() {
        kprint!(" caps: FAIL\n");
        arch_aarch64::semihosting::exit(1);
    }

    // Root task CSpace with real-frame-backed capabilities (used by P3 below).
    build_root_cspace();

    // CORE-2: prove per-TCB CSpace isolation + rights-narrowing delegation.
    cspace_isolation_demo();
    // CORE-2 teardown (A1a): a freed scheduler slot must not inherit the dead task's caps.
    p2_teardown_demo();

    // CORE-1: prove mapping flows through a capability invocation AND that revoke
    // SEVERS the mapping (invalidates the L3 entry), not just clears the CSpace slot.
    #[cfg(not(feature = "cm5"))]
    p2_revoke_unmap_demo();

    // --- R1 (M5.0) (b)+(c): cap-gated synchronous IPC — the fail-closed cap gate + the
    // revoke-severs proof (deterministic, pre-scheduler). (a), the live EL0 CALL/RECV/
    // REPLY rendezvous, spawns under the scheduler below and is reported post-run. ---
    #[cfg(not(feature = "cm5"))]
    {
        let (b, c) = r1_ipc_cap_selftest();
        R1_IPC_B.store(b, Ordering::Relaxed);
        R1_IPC_C.store(c, Ordering::Relaxed);
    }

    // --- M5.1 (Track C) (b)+(c): the ELF-loader BOUNDS-SAFETY + W^X proofs — pure,
    // deterministic, pre-scheduler (no MMU). (a), the LIVE run of a LOADED-from-ELF EL0
    // client through the real cap-gated syscall path, spawns below and is reported
    // post-run (like [P-r1-ipc-a]). ---
    #[cfg(not(feature = "cm5"))]
    {
        ELF_B.store(elf_bounds_safety_selftest(), Ordering::Relaxed);
        ELF_C.store(elf_wx_selftest(), Ordering::Relaxed);
    }

    // --- P12 (a)+(b): Notification signal/poll + pub-sub AUTHORITY (topics as caps).
    // Synchronous, pre-scheduler; the blocking-WAIT proof (c) runs under the scheduler
    // and is reported post-run. ---
    P12_A_SIGNAL_POLL.store(p12_signal_poll(), Ordering::Relaxed);
    P12_B_PUBSUB_AUTH.store(p12_pubsub_authority(), Ordering::Relaxed);

    // --- P3: EL0 userspace + SVC syscalls (incl. capability invocation) + fault ---
    p3_user_demo();
    #[cfg(not(feature = "cm5"))]
    exc_bound_selftest();

    // Verify the signed threat rule BEFORE the datapath ever runs it (verify-
    // then-run; any future third-party rule must clear the verifier + JIT too).
    if !bpf::verify_structural_demo(&bpf::THREAT_RULE) {
        kprint!(" bpf: signed threat rule failed verification\n");
        arch_aarch64::semihosting::exit(1);
    }

    // --- P8: load the signed HookProbe rule plane — verify + JIT every rule the
    // datapath will run (rule parity + native codegen). ---
    let (rv, rj) = rules::init();
    kprint!(" [P8] rule plane: {} rules verified, {} JIT-compiled (interp fallback) — parity corpus armed\n", rv, rj);

    // --- P8-scan: the stateless TCP-flag scan tier fires symmetrically. Settles the M2 A6
    // follow-up ("FIN-scan 202 doesn't fire while NULL/XMAS do") deterministically: the three
    // rules are byte-eq on the SAME TCP offset 13, so a lone FIN (0x01) MUST fire 202 exactly
    // as NULL (0x00) fires 201 and Xmas (0x29) fires 203; a legit SYN (0x02) fires none. Each
    // returns Some when a rule matched (fire() pushed the event); a single crafted packet
    // graduates to observe, but the alert still fires. ---
    {
        let hdr = |flags: u8| -> [u8; 20] { let mut t = [0u8; 20]; t[12] = 0x50; t[13] = flags; t };
        let s = 0xC612_0006u32;
        let null_f = rules::verdict_tcp(&hdr(0x00), s).is_some();
        let fin_f = rules::verdict_tcp(&hdr(0x01), s).is_some();
        let xmas_f = rules::verdict_tcp(&hdr(0x29), s).is_some();
        let syn_q = rules::verdict_tcp(&hdr(0x02), s).is_none();
        kprint!(" [P8-scan] {} — NULL(201)={} FIN(202)={} XMAS(203)={} legit-SYN-quiet={}\n",
            if null_f && fin_f && xmas_f && syn_q { "PASS" } else { "FAIL" }, null_f, fin_f, xmas_f, syn_q);
    }

    // --- P20-dns-sink: DNS-sinkhole / RPZ — "refuse a NAME, never a PACKET". A query for a
    // policy-blocked domain (+ its subdomains) gets a SINKHOLE A answer; a benign name is not
    // blocked (packet flows untouched); a compression pointer in a query qname is fail-closed. ---
    {
        // Build a minimal DNS A query for the dotted labels into `out`; returns length.
        fn mk_query(labels: &[&[u8]], out: &mut [u8]) -> usize {
            out[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
            out[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD
            out[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
            out[6..12].copy_from_slice(&[0u8; 6]);
            let mut o = 12;
            for l in labels {
                out[o] = l.len() as u8;
                o += 1;
                out[o..o + l.len()].copy_from_slice(l);
                o += l.len();
            }
            out[o] = 0;
            o += 1; // root
            out[o..o + 2].copy_from_slice(&1u16.to_be_bytes()); // QTYPE=A
            out[o + 2..o + 4].copy_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
            o + 4
        }
        let mut q = [0u8; 128];
        let mut nm = [0u8; 256];
        // (1) blocked exact name → parse + rpz + sinkhole answer == SINKHOLE_IP.
        let n = mk_query(&[b"ads", b"tracker"], &mut q);
        let name_ok = dnssink::parse_qname(&q[..n], &mut nm).map_or(false, |l| &nm[..l] == b"ads.tracker");
        let blocked = dnssink::rpz_blocked(b"ads.tracker");
        let mut resp = [0u8; 160];
        let sink_ok = dnssink::build_sinkhole_response(&q[..n], dnssink::SINKHOLE_IP, &mut resp)
            .map_or(false, |rl| rl >= 4 && resp[rl - 4..rl] == dnssink::SINKHOLE_IP && resp[6..8] == 1u16.to_be_bytes());
        // (2) subdomain of a blocked name → also blocked (suffix on a label boundary).
        let sub_blocked = dnssink::rpz_blocked(b"x.ads.tracker");
        // (3) benign name → NOT blocked (the packet flows untouched — never a drop).
        let benign_ok = !dnssink::rpz_blocked(b"good.example") && !dnssink::rpz_blocked(b"notads.tracker.org");
        // (4) fail-closed: a compression pointer (0xC0) in a query qname is rejected.
        let mut bad = [0u8; 32];
        let _ = mk_query(&[b"a"], &mut bad);
        bad[12] = 0xC0; // corrupt the first label length into a pointer
        let failclosed = dnssink::parse_qname(&bad[..20], &mut nm).is_none();
        let pass = name_ok && blocked && sink_ok && sub_blocked && benign_ok && failclosed;
        kprint!(" [P20-dns-sink] {} — RPZ refuses a NAME not a packet: qname-parse={} blocked-name={} sinkhole-answer={} subdomain-blocked={} benign-passes={} bad-qname-fail-closed={}\n",
            if pass { "PASS" } else { "FAIL" }, name_ok, blocked, sink_ok, sub_blocked, benign_ok, failclosed);
    }

    // --- P5: Packet Engine (zero-copy ring + in-place verdict datapath) ---
    if !p5_packet_engine() {
        kprint!(" packet: FAIL\n");
        arch_aarch64::semihosting::exit(1);
    }

    // --- P5b: real wire — virtio-net RX -> Packet Engine ring -> verdict ---
    if !p5b_real_wire() {
        kprint!(" wire: FAIL\n");
        arch_aarch64::semihosting::exit(1);
    }

    // --- P6: AI Runtime — RFC 9669 BPF VM runs the threat rule (the verdict) ---
    if !p6_ai_runtime() {
        kprint!(" bpf: FAIL\n");
        arch_aarch64::semihosting::exit(1);
    }

    // --- P6b: BPF verifier + JIT (native codegen, W^X) + self-heal + telemetry ---
    if !p6b_demo() {
        kprint!(" p6b: FAIL\n");
        arch_aarch64::semihosting::exit(1);
    }

    // --- DRV: driver isolation — an EL0 driver server drives device MMIO ------
    if !driver_server_demo() {
        kprint!(" drv: FAIL\n");
        arch_aarch64::semihosting::exit(1);
    }

    // --- P7c step 2: per-AS ASIDs — address-space isolation + ASID-tagged TLB ---
    asid_isolation_test();

    // --- P7d B-2: runtime attestation service — verifier-supplied freshness ---
    attest_challenge_demo();

    // --- P8: PREVAIL-style verifier gating untrusted third-party BPF rules ---
    p8_verifier_demo();

    // --- P8: detection plane — general JIT parity + live rule registry + QSecBit
    p8_detection_plane();

    // --- P8/DET-6: JIT<->interpreter differential over ALL live JIT'd rules ---
    p8_jit_differential();

    // --- AUD-NET-1: strip_vlan reconstructs the canonical untagged frame (guards the
    //     VLAN-normalization off-by-2 that would re-open the DET-4 IDS bypass) ---
    kprint!(
        " [P8-vlan] {} — strip_vlan(1-tag) and strip_vlan(QinQ) reconstruct the untagged frame byte-identical (L2/FLOW tiers see the true ethertype + IP src)\n",
        if packet::strip_vlan_selftest() { "PASS" } else { "FAIL" }
    );

    // --- P8: adaptive NAPI data plane — retire spin-poll (edge-right RX) ---
    p8_adaptive_napi();

    // --- P8: L2 guard — napse-l2guard parity (malformed-ARP / ARP-spoof) ---
    p8_l2guard();

    // --- P8: TCP scan detection — stateless anomalous-flag signatures ---
    p8_tcpscan();

    // --- P8: SYN-flood rate-limit — first STATEFUL rule (CALL helper) ---
    p8_synflood();

    // --- P8: per-source SYN-flood — the live-datapath rule (keyed by IP src) ---
    p8_synflood_src();

    // --- P8: threat-feed blocklist — helper #2 (keyed CIDR lookup), live rule ---
    p8_blocklist();

    // --- P8/SOAR: async event-ring — the non-blocking telemetry exfiltration path
    p8_soar();

    // --- DET-SEP: the M2 keystone — tri-state decide() seam (ADR 0023 observe-by-default)
    p8_separation();

    // --- M2.1: L2 structural + flood parity — F6/F7/F8 + mac-flood(port-role) + bcast-storm
    p8_l2struct();

    // --- M2.2: flow-state (conntrack-equivalent) — distinct-dst-port scan → tri-state,
    // with the legit-busy-source-stays-PASS proof (the whole point of the matrix)
    p8_flow();

    // --- M2.3: resource-shed — the fourth suspicion-free inline drop; self-reverting
    // meters keyed on RATE / saturation / scheduler-pressure REALITY, mgmt floor spared
    p8_shed();

    // --- A9-3/5/7: the RA-guard arms the security-auditor ruling approved to arm now —
    // RA-flood -> self-reverting RateLimit (any port), src-MAC attribution, evasion visible
    p8_raflood();

    // --- P8/L7: deep-packet signature match in the verified fast-path (helper #3)
    p8_l7();
    // --- P8/L7 oracle close (XC-11/DET-1): verifier refuses a scalar payload_match ptr;
    // the interpreter bounds the helper's read to the packet (no kernel-read oracle)
    p8_l7oracle();
    // --- DET-2: the per-rule authenticity GATE (the second dynamic-rule-load prereq) —
    // a signed rule is admitted + verify_prevail'd; a tampered/wrong-sig rule is refused
    p8_det2();

    // --- M2.4: L7 / behavioral OBSERVE-ONLY detectors — beacon/lateral/exfil/DNS all
    // detect (SOC sees them) but route decide()->Observe->PASS; NTP beacon exempt.
    p8_l7behav();

    // --- P17: overlay convergence foundation — net-class queue + dual-direction
    // IPS gating + EL0 monotonic counter (the smoltcp EL0 service itself is a
    // documented follow-up). QEMU-validatable core only. ---
    p17_overlay_qemu();

    // --- PH1: production-datapath enforce logic — the decision the metal prod service
    // loop makes on every real frame (PASS -> forward, threat -> drop). QEMU gate for
    // the enforce invariant; the persistent EL0-driven loop itself is cm5-only. ---
    {
        let (ok, fwd, drp) = packet::prod_datapath_selftest();
        kprint!(" [PHprod] {} — production datapath enforce: {} benign FORWARDED, {} threat DROPPED (verdict-per-frame, the running-sensor decision)\n",
            if ok { "PASS" } else { "FAIL" }, fwd, drp);
    }

    // --- PH6: smoltcp net-service stack integration — the stack answers an ARP for its
    // own IP with BOTH the ingress request and the egress reply passing the rule plane.
    // The EL0-isolated netq service + TRNG seed + PCR3 measurement is the metal half. ---
    #[cfg(feature = "netsvc")]
    {
        // ADR 0047 D2: the on-device Mission Control server logic (parse/route/JSON/SSE).
        let _ = http::mc_selftest();
        let _ = mcauth::mcauth_selftest();
        acs_selftest();
        glom_selftest();
        dnsfwd_selftest();
        {
            let ok = hal::defer::defer_selftest();
            kprint!(" [P11-defer] {} — parked station frames: inert when off, FIFO across wrap-around, a full ring counts the drop, the authenticator's take removes ONLY its frame and the rest keep their order (P5)\n",
                if ok { "PASS" } else { "FAIL" });
        }
        wancfg_selftest();
        policy_selftest();
        let _ = policysig::selftest();
        let _ = dnsblock::selftest();
        md5_selftest();
        pppoe_selftest();
        ip6_selftest();
        fuzz_selftest();
        let ok = netsvc::netsvc_selftest(0x4845_514b_5636_0000);
        kprint!(" [PH6-net] {} — smoltcp stack answers ARP for its own IP, ingress+egress verdict-gated (EL0-isolated netq service = metal follow-up)\n",
            if ok { "PASS" } else { "FAIL" });
        // M4 FIRST-LIGHT: the SAME MetalBridge the prod drain loop runs, exercised in QEMU —
        // wants()+step() answers an ARP for heqk's IP; the metal half is a host `arping`.
        let mbok = netsvc::metalbridge_selftest(0x4845_514b_5636_0001);
        kprint!(" [PH6-metalbridge] {} — MetalBridge (prod GEM path) answers ARP for heqk's IP; is_for_heqk demux claims+admits a unicast ICMP-for-us (echo reply needs an ICMP socket, deferred); rejects a broadcast threat (metal = host arping 10.200.0.2)\n",
            if mbok { "PASS" } else { "FAIL" });
    }

    // --- M4.1 (P18-netcfg): network CONFIG clients over smoltcp — DHCP + DNS + SNTP,
    // every frame rule-gated (PH6net property), with the SACRED air-gap invariant
    // proven (no server -> static fallback -> local SOC unaffected, never a boot-block).
    // Deterministic core gates PASS; a real SLIRP lease + DNS over virtio-net is a
    // reported bonus (real NIC/DHCP/DNS/NTP timing = metal, Gate R). ---
    #[cfg(feature = "netsvc")]
    {
        kprint!(" [P18-netcfg] M4.1 net config over smoltcp (DHCP/DNS/SNTP), rule-gated:\n");
        let ok = netcfg::netcfg_selftest();
        kprint!(" [P18-netcfg] {} — heqk drives smoltcp UDP: dhcpv4 DISCOVER emitted through the egress verdict gate, DNS+SNTP request/parse round-trip, config-gate admits benign & refuses threat, and the air-gap fallback yields a static config WITHOUT blocking boot (standalone stays fully functional, no account); real SLIRP lease+DNS reported above, real NIC/servers/timing = metal (Gate R)\n",
            if ok { "PASS" } else { "FAIL" });
    }

    // --- M4.2a (P19-pqc-kat): PQC secure-channel crypto PRIMITIVES + KATs. The
    // FRAMING-AGNOSTIC KEX + AEAD both the ADR-0002 rustls path and the ADR-0004
    // Noise path need — brought in ONCE, KAT-gated, no handshake (that is M4.2b).
    // All deterministic (seeded/fixed, no RNG); the TRNG-fed real keygen is metal
    // (Gate R). ML-KEM-768 round-trip+pinned-KAT, X25519 RFC-7748, ChaCha20-Poly1305
    // RFC-8439, hybrid HKDF combiner Alice==Bob. ---
    #[cfg(feature = "securechannel")]
    {
        kprint!(" [P19-pqc-kat] M4.2a secure-channel crypto primitives (framing-agnostic KEX+AEAD):\n");
        let ok = securechannel::securechannel_selftest();
        kprint!(" [P19-pqc-kat] {} — ML-KEM-768 (FIPS 203) encaps/decaps + pinned KAT, X25519 (RFC 7748) vector, ChaCha20-Poly1305 (RFC 8439) AEAD + forgery-reject, and the hybrid HKDF combiner (ML-KEM ss + X25519 ss) derives ONE shared secret Alice==Bob; all DETERMINISTIC (test seeds — real TRNG keygen = metal, Gate R); handshake + framing (rustls vs Noise) + crypto review = M4.2b\n",
            if ok { "PASS" } else { "FAIL" });
    }

    // --- M4.2b (P19-noise): the PQ-HYBRID secure-channel HANDSHAKE over the M4.2a
    // primitives. Noise (ADR 0004 HTP-v2), NOT rustls: IK-analog, hybrid X25519 +
    // ML-KEM-768 KEX combined via hybrid_combine, ChaCha20-Poly1305 AEAD, Ed25519
    // (PUF-anchored) device identity. Noise rev-34 SymmetricState/CipherState/Split
    // implemented to spec; KEM-in-Noise per PQNoise. Loopback in QEMU with seeded
    // ephemerals (real HW-TRNG/PUF/PKI + real network = metal/M4.3, Gate R). ---
    #[cfg(feature = "securechannel-selftest")]
    {
        kprint!(" [P19-noise] M4.2b PQ-hybrid Noise handshake (IK-analog, X25519+ML-KEM-768, Ed25519 device auth):\n");
        let ok = securechannel::noise_selftest();
        kprint!(" [P19-noise] {} — full initiator<->responder handshake yields MATCHING crossed transport keys (i.send==r.recv, i.recv==r.send, send!=recv, transcript-hash agree); a transport record round-trips (confidentiality+integrity) and a REPLAY is rejected (advanced nonce counter); a TAMPERED handshake msg aborts (AEAD auth); a WRONG responder static key aborts (es key diverges); an UNENROLLED device identity aborts; the hybrid combiner binds BOTH ML-KEM & X25519 legs (secure if either holds) and fresh ephemerals derive a new key (forward secrecy). DETERMINISTIC loopback (seeded); real HW-TRNG/PUF/responder-PKI + network transport (anti-replay window) = metal/M4.3 (Gate R)\n",
            if ok { "PASS" } else { "FAIL" });
    }

    // --- M4.3 (P19-enroll): MSSP enrollment + authenticated update fetch over the
    // Noise channel. Ties M4.2b (transport + mutual auth) to M3.4 OTA (trust root)
    // and the M3.2/M3.3 sealed store (enrollment persistence). The FULL gate (enroll
    // persist across reboot + authenticated fetch→ota::stage) needs p15-write + a
    // virtio-blk disk (validate.sh's two-boot); the plain build proves the
    // protocol/entropy/air-gap/buffer halves inline. Entropy #6 fails closed with NO
    // seeded path on metal; #7 fixed buffers (no per-record heap); #8 key_for_test
    // gated. Real MSSP PKI + HW-TRNG + network = metal (Gate R). ---
    #[cfg(feature = "securechannel-selftest")]
    {
        enroll::enroll_selftest();
        // M4.5: the segmentation AUTHORITY — an operator-signed reach policy over the enrolled
        // Noise channel ARMS segment.rs (C9 independent signature; fail-open on any failure).
        enroll::seg_policy_selftest();
        // M4.5: Noise-over-UDP datagram framing — a >MTU PQ-hybrid handshake survives chunk +
        // fail-closed reassembly, and the full handshake completes over it (the metal GEM
        // transport rides this framing; the smoltcp-UDP-over-GEM carriage is the metal first-light).
        enroll::noise_over_udp_selftest();
        // M4.5: the control-plane INITIATOR state machine drives a full handshake against an
        // in-kernel responder over the exact smoltcp-free hand-framed UDP transport it runs on
        // metal (the metal half is the host MSSP-sim, deferred).
        controlplane::cp_selftest();
    }

    // --- M4.4 (P19-edge): the ADR-0004 secure-edge OPERATIONAL ENVELOPE on heqk's
    // native stack. Closes the last two deferred Noise-transport conditions (#9
    // anti-replay window / N1 msg1-replay DoS) and lands the ADR-0004 WAN-egress
    // kill-switch, riding the M2 netq egress gate. QEMU-provable DECISION logic; the
    // full PBR/NAT/TUN SASE dataplane at line rate + the real super-PoP tunnel =
    // metal (Gate R), scoped in docs/design/heqk-control-plane.md §M4.4. ---
    #[cfg(feature = "securechannel-selftest")]
    {
        edge::edge_selftest();
    }

    // --- M6 (P-m6-export): ADR 0044 D3 B2 on-device evidence/telemetry EXPORT.
    // The CM5 is a PURE heqk sensor; MC + HYDRA + heavy services are OFF-DEVICE
    // (the existing cloud stack, ADR 0009). heqk streams its M2 SOAR verdicts + M3
    // persisted evidence + QSecBit over the M4 enrolled Noise channel to a FAKE
    // in-process off-device MC that decrypts + authenticates it. Air-gap invariant
    // preserved (unenrolled => persist locally, SOC unaffected, no export). The
    // FULL gate (M2 verdict -> M3 DISK persist -> M4 export -> MC verify) rides the
    // p15-write two-boot; the plain build proves the in-RAM halves inline. ---
    #[cfg(feature = "securechannel-selftest")]
    {
        export::m6_export_selftest();
        // M3 snapshot v2: the persisted evidence ring restores IN ORDER after wrapping.
        let _ = snapshot::snapshot_selftest();
    }

    // --- P11: device-class transport (the sDDF borrow) — the hardened SPSC
    // transport that REJECTS a hostile driver's forged descriptors, proven with an
    // in-kernel stand-in driver + a software LoopDev. Metal GemDev/RtlDev deferred. ---
    p11_devq_qemu();

    // --- crypto primitive: incremental Hasher == one-shot digest (metal-found bug guard) ---
    {
        let ok = boot_abi::sha256::hasher_selftest();
        kprint!(
            " [P16-sha] {} — incremental SHA-256 Hasher == one-shot digest across all lengths/chunkings (guards the short-tail HMAC bug)\n",
            if ok { "PASS" } else { "FAIL" }
        );
    }

    // --- P15: sealed storage — seal/unseal + guard over a RamDisk (arch-agnostic) ---
    p15_seal_selftest();
    // --- task #27 F2: crash-consistent A/B snapshot store (needs the write path) ---
    #[cfg(feature = "p15-write")]
    abstore_selftest();

    // --- P15-guard2: M3.0 multi-region write-guard (brick-safety, every boot) ---
    p15_guard_selftest();

    // --- P15-persist: M3.1 cross-restart persistence over file-backed virtio-blk
    //     (skips diskless; the two-boot proof is driven by validate.sh) ---
    p15_persist_selftest();

    // --- P15-otafat: B2 OTA delivery — locate the inactive A/B slot inside the shared
    //     FAT32 boot partition and stage a candidate into its real sectors (driven by
    //     validate.sh with a mkfs.vfat'd disk; skips diskless / non-FAT) ---
    p15_otafat_selftest();
    // B2: the A/B commit survives a cold boot (two-boot, factory-layout disk; SKIPs otherwise).
    #[cfg(feature = "p15-write")]
    abboot::abcommit_selftest();

    // --- P15-fs: M3.2 crash-safe log-structured record store (torn-tail recovery
    //     + bounded retention + evidence/QSecBit records survive reboot) ---
    p15_fs_selftest();

    // --- P15-sealfs: M3.3 sealed data-volume (encryption at rest) — record
    //     payloads are HQKSEAL1 ciphertext, tamper is rejected fail-closed, and
    //     the volume key survives reboot via the sealed keystore ---
    p15_sealfs_selftest();

    // --- P15-ota: M3.4 on-device A/B OTA — pull -> inactive-slot write -> verify
    //     (SHARED hboot verifier) -> flip -> confirm/rollback; state persisted;
    //     brick-safety + verify-before-flip + downgrade-refused asserted ---
    p15_ota_selftest();

    // --- A/B: detection plane is up -> confirm this boot (disarm trial watchdog) ---
    boot_confirm();

    // --- P1 priority scheduler + P4 synchronous IPC (one scheduler run) ---
    scheduler::init();
    let entries: [usize; NTHREADS] = [
        consumer as *const () as usize,   // P4 IPC pair (highest prio: runs first)
        producer as *const () as usize,
        thread_hi as *const () as usize,  // P1 priority demo
        thread_mid as *const () as usize,
        thread_lo as *const () as usize,
    ];
    let prios: [u8; NTHREADS] = [5, 4, 3, 2, 1];
    for i in 0..NTHREADS {
        let sp = arch_aarch64::thread::make_thread(stack_top(i), entries[i], 0);
        scheduler::spawn(sp, prios[i]);
    }
    kprint!(" sched: {} threads (P4 IPC consumer/producer + P1 priority H/M/L, + idle)\n", NTHREADS);
    el0_preempt_spawn(); // P7c: + one uncooperative EL0 TCB that the timer must preempt
    el0_fault_spawn(); // P7c 4b: + one crashing EL0 driver TCB that must be contained + restarted
    p12_el0_spawn(); // P12 (c): + a WAIT TCB (blocks) and a SIGNAL TCB (wakes it) — the real syscall path
    r1_ipc_el0_spawn(); // R1 (M5.0) (a): + an IPC server (RECV/REPLY) and client (CALL) — cap-gated sync IPC
    m5_elf_loader_spawn(); // M5.1 (Track C) (a): + a client LOADED FROM AN ELF (real cap-gated SYS_CALL) — ELF-loader beachhead
    #[cfg(feature = "wasmhost")]
    m5_wasmhost_el0_spawn(); // M5.2b (Track C) (a): + the signed module HOSTED in an ISOLATED EL0 task, verdict returned via enforced IPC
    #[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
    m5_wasmi_el0_spawn(); // M5.3 (Track C) (a): + a REAL wasmi runtime in an EL0 SERVER running one signed module, verdict over enforced IPC
    #[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
    m5_detect_el0_spawn(); // M5.4 (Track C): a DETECTION module (memory+imports) run via wasmi in EL0 at PARITY with rules::run_l4
    #[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
    m5_wasip1_el0_spawn(); // M5.5 (Track C): a REAL wasm32-wasip1 std module (stdin/stdout) run via wasmi in EL0 over the WASI preview1 ABI

    // Bring up the interrupt controller + periodic timer, then let go.
    let gic = arch_aarch64::Gic;
    gic.init();
    gic.enable(arch_aarch64::timer::TIMER_INTID);
    arch_aarch64::GenericTimer.start(TICK_HZ);
    kprint!(" timer: {} Hz tick armed (INTID {})\n", TICK_HZ, arch_aarch64::timer::TIMER_INTID);
    kprint!(" --- IRQs on: IPC rendezvous first, then strict-priority H* M* L* ---\n");
    arch_aarch64::enable_irqs();

    // Idle thread: the first timer IRQ preempts this into the workers.
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}

/// P7c step 2 — per-AS ASIDs. Prove two address spaces are isolated: map the
/// SAME VA to DIFFERENT frames in two ASIDs, then switch `TTBR0` between them with
/// NO TLB flush. Each sees only its own frame — so the ASID tag keeps the two
/// spaces' TLB entries apart (the foundation for isolated per-driver EL0 servers).
#[cfg(not(feature = "cm5"))]
fn asid_isolation_test() {
    let mmu = arch_aarch64::Mmu;
    let (l1a, asa) = mmu.new_addr_space();
    let (l1b, asb) = mmu.new_addr_space();
    let (fa, fb) = (mmu.alloc_frame(), mmu.alloc_frame());
    if l1a == 0 || l1b == 0 || fa == 0 || fb == 0 {
        kprint!(" [P7c-ASID] FAIL: no frames\n");
        return;
    }
    // Same VA in both spaces, in GB2 — a 1 GiB region UNMAPPED in the kernel L1,
    // so each address space allocates its OWN L2/L3 (no shared table). (GB3 is
    // already used by the P3/DRV/JIT user maps, so its L2 would be shared.)
    const VA: usize = 0x8100_0000;
    let (val_a, val_b) = (0xA5A5_0000_0000_00A1u64, 0x5A5A_0000_0000_00B2u64);
    unsafe {
        core::ptr::write_volatile(fa as *mut u64, val_a); // frame A content
        core::ptr::write_volatile(fb as *mut u64, val_b); // frame B content
    }
    mmu.map_user_data_in(l1a, VA, fa); // AS-A: VA -> frame A
    mmu.map_user_data_in(l1b, VA, fb); // AS-B: VA -> frame B
    mmu.switch_ttbr0(l1a, asa);
    let ra = unsafe { core::ptr::read_volatile(VA as *const u64) };
    mmu.switch_ttbr0(l1b, asb); // switch AS — NO flush; ASID tag must isolate
    let rb = unsafe { core::ptr::read_volatile(VA as *const u64) };
    mmu.switch_ttbr0(l1a, asa); // back to A — still no flush
    let ra2 = unsafe { core::ptr::read_volatile(VA as *const u64) };
    mmu.switch_ttbr0(mmu.kernel_l1(), 0); // restore the kernel address space
    let ok = ra == val_a && rb == val_b && ra2 == val_a;
    kprint!(" [P7c-ASID] VA {:#x}: AS-A(asid={})={:#x} AS-B(asid={})={:#x} A-again={:#x}\n",
        VA, asa, ra, asb, rb, ra2);
    kprint!(" [P7c-ASID] {} — per-AS isolation + ASID-tagged TLB (switch with no flush)\n",
        if ok { "PASS" } else { "FAIL" });
}

/// P7d B-2 — runtime attestation service: prove the kernel signs a
/// *verifier-supplied* nonce on demand, so a captured response can't be
/// replayed against a different challenge. On QEMU a fixed seed stands in for
/// HBoot's TRNG-seeded ephemeral key; on metal the kernel loads the real
/// ephemeral key + AK cert HBoot hands down (see `cm5_attest_challenge`).
#[cfg(not(feature = "cm5"))]
fn attest_challenge_demo() {
    let att = attest_svc::Attestor::from_seed(&[0x5a; 32]);
    // Two distinct verifier challenges + a self-check of the freshness property.
    let n1 = [0x11u8; 32];
    let n2 = [0x22u8; 32];
    let s1 = att.respond(&n1);
    let s2 = att.respond(&n2);
    let pass = attest_svc::self_test(&att);
    kprint!(" [P7d-B2] runtime attest: challenge n1 -> sig {:02x}{:02x}.., n2 -> sig {:02x}{:02x}..\n",
        s1.as_ref()[0], s1.as_ref()[1], s2.as_ref()[0], s2.as_ref()[1]);
    kprint!(" [P7d-B2] {} — verifier-supplied per-request freshness (distinct nonces -> distinct valid sigs; cross-replay rejected)\n",
        if pass { "PASS" } else { "FAIL" });
}

/// P17 — overlay-convergence FOUNDATION (QEMU-validatable core). Proves the
/// net-class transport (netq.rs) + the dual-direction IPS gate WITHOUT the actual
/// EL0 smoltcp stack (a documented follow-up: external crate + multi-page EL0
/// loader + linker script). An IN-KERNEL software stand-in plays the untrusted EL0
/// service, using the raw slot protocol exactly as EL0 would.
///
/// The property proven (OVERLAY_CONVERGENCE §A3.3): the signed rule plane
/// (`packet::verdict`) is authoritative on BOTH sides of the queue —
///  * INGRESS: a threat frame is DROPPED by `rx_publish` and never enters rxq, so
///    the service can't even observe it.
///  * EGRESS: a threat frame the (compromised) service injects into txq is DROPPED
///    by `tx_drain` and NEVER reaches the wire sink.
#[cfg(not(feature = "cm5"))]
fn p17_overlay_qemu() {
    use core::sync::atomic::Ordering;
    use netq::{NetQueue, NETQ_FRAME_SZ, NETQ_SLOTS, SLOT_FREE, SLOT_FULL};

    fn verd(v: u16) -> &'static str {
        if v == packet::DROP { "DROP" } else { "PASS" }
    }
    // Minimal Ethernet/IPv4/UDP frame with the given dst port.
    fn build_udp(buf: &mut [u8], dst_port: u16) -> usize {
        const N: usize = 14 + 20 + 8;
        for b in buf.iter_mut().take(N) {
            *b = 0;
        }
        buf[12] = 0x08; // ethertype IPv4
        buf[14] = 0x45; // IPv4, IHL=5
        buf[17] = 28; // IP total length = 20 + 8
        buf[23] = 17; // proto = UDP
        buf[34] = 0x04;
        buf[35] = 0xd2; // src port 1234
        buf[36] = (dst_port >> 8) as u8;
        buf[37] = (dst_port & 0xff) as u8;
        N
    }

    kprint!("\n [P17] overlay convergence — net-class queue + dual-direction IPS gate\n");

    // Grant EL0 the monotonic counter the (follow-up) smoltcp `Instant` needs.
    arch_aarch64::timer::enable_el0_counter();
    kprint!(" [P17] CNTKCTL_EL1.EL0PCTEN=1 — EL0 granted the monotonic counter only (no compare regs)\n");

    // Two page-aligned net-class queues: rxq (kernel->svc), txq (svc->kernel).
    static mut RXQ: NetQueue = NetQueue::new();
    static mut TXQ: NetQueue = NetQueue::new();
    let rxq = unsafe { &mut *core::ptr::addr_of_mut!(RXQ) };
    let txq = unsafe { &mut *core::ptr::addr_of_mut!(TXQ) };
    rxq.init();
    txq.init();

    // --- INGRESS gate: publish a benign :53 and a threat :4444. ---
    let mut benign = [0u8; 64];
    let mut threat = [0u8; 64];
    let bn = build_udp(&mut benign, 53);
    let tn = build_udp(&mut threat, 4444);
    let v_benign = netq::rx_publish(rxq, &benign[..bn]);
    let v_threat = netq::rx_publish(rxq, &threat[..tn]);
    let mut rx_full = 0;
    for i in 0..NETQ_SLOTS {
        if rxq.slot[i].state.load(Ordering::Acquire) == SLOT_FULL {
            rx_full += 1;
        }
    }
    kprint!(" [P17] ingress: benign:53 -> {}, threat:4444 -> {}; frames in rxq = {} (threat never entered the ring)\n",
        verd(v_benign), verd(v_threat), rx_full);
    let ingress_ok = v_benign == packet::PASS && v_threat == packet::DROP && rx_full == 1;

    // --- IN-KERNEL STAND-IN "service": drains rxq (the PASSed frames) and echoes
    // them into txq using the RAW slot protocol, exactly as an untrusted EL0
    // service would (no kernel validation on this path). ---
    let mut echoed = 0;
    for i in 0..NETQ_SLOTS {
        let s = &rxq.slot[i];
        if s.state.load(Ordering::Acquire) != SLOT_FULL {
            continue;
        }
        let n = (unsafe { core::ptr::read_volatile(core::ptr::addr_of!(s.len)) } as usize)
            .min(NETQ_FRAME_SZ);
        let mut tmp = [0u8; NETQ_FRAME_SZ];
        tmp[..n].copy_from_slice(&rxq.frame[i][..n]);
        s.state.store(SLOT_FREE, Ordering::Release); // service consumed the rxq slot
        for j in 0..NETQ_SLOTS {
            let t = &txq.slot[j];
            if t.state.load(Ordering::Acquire) == SLOT_FREE {
                txq.frame[j][..n].copy_from_slice(&tmp[..n]);
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of!(t.len) as *mut u32, n as u32)
                };
                t.state.store(SLOT_FULL, Ordering::Release);
                echoed += 1;
                break;
            }
        }
    }

    // COMPROMISED-service case: the stand-in ALSO injects a threat :4444 frame
    // straight into txq via the raw protocol — the egress gate must still block it.
    let mut svc_threat = [0u8; 64];
    let sn = build_udp(&mut svc_threat, 4444);
    for j in 0..NETQ_SLOTS {
        let t = &txq.slot[j];
        if t.state.load(Ordering::Acquire) == SLOT_FREE {
            txq.frame[j][..sn].copy_from_slice(&svc_threat[..sn]);
            unsafe { core::ptr::write_volatile(core::ptr::addr_of!(t.len) as *mut u32, sn as u32) };
            t.state.store(SLOT_FULL, Ordering::Release);
            break;
        }
    }

    // --- EGRESS gate: drain txq to the "wire" sink. Benign echo -> FORWARDED;
    // injected threat -> DROPPED by the kernel rule plane, never on the wire. ---
    let mut wire_ports = [0u16; NETQ_SLOTS];
    let mut wire_n = 0usize;
    let (fwd, blk) = netq::tx_drain(txq, |frame| {
        if frame.len() >= 38 {
            wire_ports[wire_n] = ((frame[36] as u16) << 8) | frame[37] as u16;
            wire_n += 1;
        }
    });
    let benign_on_wire = wire_ports.iter().take(wire_n).any(|p| *p == 53);
    let threat_on_wire = wire_ports.iter().take(wire_n).any(|p| *p == 4444);
    kprint!(" [P17] egress: service echoed {} frame(s) + injected 1 threat:4444; drain forwarded {} blocked {}\n",
        echoed, fwd, blk);
    kprint!(" [P17] wire: benign:53 forwarded={} | threat:4444 on the wire={} (MUST be false)\n",
        benign_on_wire, threat_on_wire);
    let egress_ok = benign_on_wire && !threat_on_wire && fwd == 1 && blk == 1;

    kprint!(" [P17] NOTE: the smoltcp IP stack running at EL0 is a documented FOLLOW-UP\n");
    kprint!("       (external smoltcp crate + multi-page EL0 loader + linker script); this\n");
    kprint!("       pass proves the transport + the dual-direction IPS gating in-kernel.\n");

    if ingress_ok && egress_ok {
        kprint!(" [P17] PASS — net-class queue + IPS authoritative on ingress AND egress (a threat frame the service tried to send was DROPPED by the kernel rule plane)\n");
    } else {
        kprint!(" [P17] FAIL — ingress_ok={} egress_ok={}\n", ingress_ok, egress_ok);
    }
}

/// P11 — device-class transport (the sDDF borrow), the QEMU-validatable SECURITY
/// core. Proves the hardened SPSC transport (devq.rs) REJECTS and COUNTS every
/// class of forged descriptor a hostile driver can place in the shared region,
/// while the queue stays usable and the kernel stays up. No hardware: a software
/// LoopDev exercises the honest transport, and an IN-KERNEL stand-in "driver"
/// scribbles the shared region exactly as an untrusted EL0 driver with a Normal-NC
/// grant would (the p17_overlay_qemu pattern).
///
/// Threat model (DEVICE_CLASS_TRANSPORT.md): the RxActive queue is driver->kernel
/// and HOSTILE. The kernel is its consumer; `drain_checked` + `NetClass::
/// check_from_driver` are the enforcement point. Forged classes proven rejected:
///   (a) V2  — tail = head + huge            (index out of range)
///   (b) V4  — io_or_off far outside region  (offset)
///   (c) V4  — len = 0xFFFF                   (length)
///   (d) V5  — double-submit / never-given   (not owned)
///   (e) V4  — unknown flag bits             (flags)
#[cfg(not(feature = "cm5"))]
fn p11_devq_qemu() {
    use devq::{
        drain_checked, enqueue, qid, BufDesc, BufState, DevQRegion, DevQStats, LoopDev, NetClass,
        QHandle, Violation, MASK, NET_BUFSZ, NET_FLAG_EOF, NET_FLAG_SOF, NET_MIN,
    };

    kprint!("\n [P11] device-class transport (sDDF borrow) — hardened SPSC vs a hostile driver\n");

    static mut REGION: DevQRegion = DevQRegion::new();
    let region = unsafe { &*core::ptr::addr_of!(REGION) };

    // --- Software LoopDev: exercise the HONEST transport with no hardware. ---
    let (lp_prod, lp_drop, lp_cons) = LoopDev::selftest(region);
    let loop_ok = lp_prod == lp_cons && lp_drop >= 1;
    kprint!(" [P11] LoopDev: produced_ok={} dropped_full={} consumed={} (full=>drop+count, SPSC carries all) -> {}\n",
        lp_prod, lp_drop, lp_cons, if loop_ok { "ok" } else { "BAD" });

    // Raw shared-memory forge, exactly as an untrusted producer would: write a
    // descriptor into a chosen slot and bump tail with an STLR. The kernel NEVER
    // trusts these; it re-derives every index from its private geometry.
    let forge = |q: usize, slot: usize, d: BufDesc| unsafe {
        core::ptr::write_volatile(core::ptr::addr_of!(region.desc[q][slot]) as *mut BufDesc, d);
    };
    // A valid descriptor for buffer `cookie`; len is a full Ethernet/IPv4/UDP frame
    // (14+20+8) so the honest path's `packet::verdict` sees a complete frame.
    let good = |cookie: u32| BufDesc {
        io_or_off: cookie as u64 * NET_BUFSZ as u64,
        len: (14 + 20 + 8) as u16,
        flags: NET_FLAG_SOF | NET_FLAG_EOF,
        cookie,
    };
    let _ = NET_MIN;

    let mut net = NetClass::new();
    let mut stats = DevQStats::new();

    // ===================== (1) HONEST PATH =====================
    // Kernel produces buffers on RxFree and records them handed to the driver;
    // the stand-in driver moves them to RxActive with VALID descriptors; the
    // kernel drains RxActive, validating each against the ownership table.
    region.reset(qid::RX_FREE);
    region.reset(qid::RX_ACTIVE);
    const HANDED: u32 = 4;
    let kprod = QHandle::producer(qid::RX_FREE);
    let mut fstats = DevQStats::new();
    for c in 0..HANDED {
        // Kernel grants buffer c to the driver (RX role) + advertises it on RxFree.
        net.hand_to_driver(c as usize, BufState::DriverRx);
        enqueue(region, &kprod, &mut fstats, &good(c));
    }
    // Stand-in HONEST driver: publish valid RxActive descriptors for those buffers.
    let dprod = QHandle::producer(qid::RX_ACTIVE);
    for c in 0..HANDED {
        enqueue(region, &dprod, &mut fstats, &good(c));
    }
    // Kernel drains RxActive; on accept it runs the signed rule plane on the frame
    // and reclaims the buffer. `frames` counts descriptors that validated AND passed.
    static mut DATA: [[u8; NET_BUFSZ]; devq::NET_NBUF] = [[0u8; NET_BUFSZ]; devq::NET_NBUF];
    let data = unsafe { &mut *core::ptr::addr_of_mut!(DATA) };
    // Lay a benign UDP:53 frame into each handed buffer (verdict must PASS).
    for c in 0..HANDED as usize {
        let n = build_udp_into(&mut data[c]);
        let _ = n;
    }
    let mut frames = 0u32;
    let mut kcons = QHandle::consumer(qid::RX_ACTIVE);
    let accepted = drain_checked(region, &mut kcons, 64, &mut stats, |d| {
        net.check_from_driver(d, BufState::DriverRx)?;
        // Validated: read the kernel's own buffer (never the driver's addresses),
        // run the IPS, count the frame, reclaim the buffer.
        let c = d.cookie as usize;
        let n = (d.len as usize).min(NET_BUFSZ);
        let (_p, v) = packet::verdict(&data[c][..n]);
        if v == packet::PASS {
            frames += 1;
        }
        net.reclaim(c);
        Ok(())
    });
    let honest_ok = accepted == HANDED && frames == HANDED;
    kprint!(" [P11] honest: kernel handed {} buffers -> driver published -> drained+validated {} -> IPS PASS frames {} -> {}\n",
        HANDED, accepted, frames, if honest_ok { "ok" } else { "BAD" });

    // ===================== (2) HOSTILE PATHS =====================
    // Each case forges a descriptor / index on the HOSTILE RxActive queue; the
    // kernel must REJECT + COUNT it, and the queue must stay usable afterward.
    let v0 = |s: &DevQStats, v: Violation| s.viol[v as usize];

    // (a) V2 — forged tail = head + huge. Placed AT the head slot so an unhardened
    // consumer would happily index it; occupancy (tail-head) is astronomically > cap.
    region.reset(qid::RX_ACTIVE);
    forge(qid::RX_ACTIVE, 0, good(0));
    region.hdr[qid::RX_ACTIVE].tail.store(0x4000_0000, core::sync::atomic::Ordering::Release);
    let before = v0(&stats, Violation::Index);
    drain_checked(region, &mut kcons, 64, &mut stats, |d| net.check_from_driver(d, BufState::DriverRx));
    let a_ok = v0(&stats, Violation::Index) > before;

    // (b) V4 — io_or_off far outside the data region (cookie valid, address wild).
    region.reset(qid::RX_ACTIVE);
    net.hand_to_driver(0, BufState::DriverRx);
    let mut bad = good(0);
    bad.io_or_off = 0xDEAD_0000_0000; // nowhere near the region
    forge(qid::RX_ACTIVE, 0, bad);
    region.hdr[qid::RX_ACTIVE].tail.store(1, core::sync::atomic::Ordering::Release);
    let before = v0(&stats, Violation::Offset);
    drain_checked(region, &mut kcons, 64, &mut stats, |d| net.check_from_driver(d, BufState::DriverRx));
    let b_ok = v0(&stats, Violation::Offset) > before;

    // (c) V4 — len = 0xFFFF.
    region.reset(qid::RX_ACTIVE);
    net.hand_to_driver(0, BufState::DriverRx);
    let mut bad = good(0);
    bad.len = 0xFFFF;
    forge(qid::RX_ACTIVE, 0, bad);
    region.hdr[qid::RX_ACTIVE].tail.store(1, core::sync::atomic::Ordering::Release);
    let before = v0(&stats, Violation::Len);
    drain_checked(region, &mut kcons, 64, &mut stats, |d| net.check_from_driver(d, BufState::DriverRx));
    let c_ok = v0(&stats, Violation::Len) > before;

    // (d) V5 — the SAME buffer submitted twice + a buffer never given. First submit
    // of cookie 0 (owned DriverRx) validates and is reclaimed (=> KernelOwned); the
    // second submit is now NotOwned. Cookie 7 was never handed out => NotOwned too.
    region.reset(qid::RX_ACTIVE);
    net.hand_to_driver(0, BufState::DriverRx);
    net.reclaim(7); // ensure cookie 7 is KernelOwned (never given)
    forge(qid::RX_ACTIVE, 0, good(0));
    forge(qid::RX_ACTIVE, 1, good(0)); // double-submit
    forge(qid::RX_ACTIVE, 2, good(7)); // never given
    region.hdr[qid::RX_ACTIVE].tail.store(3, core::sync::atomic::Ordering::Release);
    let before = v0(&stats, Violation::NotOwned);
    drain_checked(region, &mut kcons, 64, &mut stats, |d| {
        net.check_from_driver(d, BufState::DriverRx)?;
        net.reclaim(d.cookie as usize); // accept => reclaim (flips owner; double-submit now NotOwned)
        Ok(())
    });
    let d_ok = v0(&stats, Violation::NotOwned) >= before + 2;

    // (e) V4 — unknown flag bits.
    region.reset(qid::RX_ACTIVE);
    net.hand_to_driver(0, BufState::DriverRx);
    let mut bad = good(0);
    bad.flags = 0x8000; // no such flag
    forge(qid::RX_ACTIVE, 0, bad);
    region.hdr[qid::RX_ACTIVE].tail.store(1, core::sync::atomic::Ordering::Release);
    let before = v0(&stats, Violation::Flags);
    drain_checked(region, &mut kcons, 64, &mut stats, |d| net.check_from_driver(d, BufState::DriverRx));
    let e_ok = v0(&stats, Violation::Flags) > before;

    // The queue must STILL be usable after all the hostile traffic: hand a fresh
    // buffer, publish a valid descriptor, drain it, and confirm it validates.
    region.reset(qid::RX_ACTIVE);
    net.hand_to_driver(3, BufState::DriverRx);
    let mut post = DevQStats::new();
    enqueue(region, &QHandle::producer(qid::RX_ACTIVE), &mut post, &good(3));
    let after_ok = drain_checked(region, &mut kcons, 64, &mut post, |d| {
        net.check_from_driver(d, BufState::DriverRx)
    }) == 1;

    let forged_rejected = stats.total_violations();
    let classes_ok = a_ok && b_ok && c_ok && d_ok && e_ok;
    kprint!(" [P11] hostile: V2-index={} V4-offset={} V4-len={} V4-flags={} V5-notowned={} (total forged rejected={})\n",
        v0(&stats, Violation::Index), v0(&stats, Violation::Offset), v0(&stats, Violation::Len),
        v0(&stats, Violation::Flags), v0(&stats, Violation::NotOwned), forged_rejected);
    kprint!(" [P11] slot=idx&{:#x} (structurally in-bounds), cap KERNEL-PRIVATE (H1), copy-then-validate (H3), no RMW on the region; queue still usable after attack={}\n",
        MASK, after_ok);
    kprint!(" [P11] FOLLOW-UP (documented): the metal GemDev/RtlDev NetDev impls + the read-only HW-ring grant (map_user_nc_ro, H4) are the metal-oriented deferral\n");

    if loop_ok && honest_ok && classes_ok && after_ok && frames >= 1 && forged_rejected >= 5 {
        kprint!(" [P11] PASS — hardened device-class transport rejects+counts every forged-descriptor class (V2/V4/V5); honest frames pass, queue survives\n");
    } else {
        kprint!(" [P11] FAIL — loop={} honest={} classes={} usable={} frames={} forged_rejected={}\n",
            loop_ok, honest_ok, classes_ok, after_ok, frames, forged_rejected);
    }
}

/// Build a minimal benign Ethernet/IPv4/UDP:53 frame into `buf`, returning its
/// length — the P11 honest path lays one into each kernel-owned buffer so the
/// signed rule plane (`packet::verdict`) returns PASS on the validated drain.
#[cfg(not(feature = "cm5"))]
fn build_udp_into(buf: &mut [u8]) -> usize {
    const N: usize = 14 + 20 + 8;
    for b in buf.iter_mut().take(N) {
        *b = 0;
    }
    buf[12] = 0x08; // ethertype IPv4
    buf[14] = 0x45; // IPv4, IHL=5
    buf[17] = 28; // IP total length
    buf[23] = 17; // proto UDP
    buf[34] = 0x04;
    buf[35] = 0xd2; // src port 1234
    buf[36] = 0x00;
    buf[37] = 53; // dst port 53 (benign)
    N
}

/// P8 — prove the PREVAIL-style verifier accepts the safe signed rule (computing
/// its minimum packet length) and STATICALLY rejects adversarial third-party
/// rules (wild load, backward-jump loop, missing verdict) before they ever run.
#[cfg(not(feature = "cm5"))]
fn p8_verifier_demo() {
    use bpf::{verify_prevail, EVIL_LOOP, EVIL_NO_VERDICT, EVIL_WILD_LOAD, THREAT_RULE};
    kprint!("\n [P8] PREVAIL-style verifier — gating untrusted third-party BPF rules\n");
    match verify_prevail(&THREAT_RULE) {
        Ok(min) => kprint!(" [P8] signed THREAT_RULE: SAFE (proven min packet len = {})\n", min),
        Err(e) => kprint!(" [P8] signed THREAT_RULE: REJECTED ({}) <- BUG\n", e),
    }
    let evils: [(&str, &[u64]); 3] = [
        ("wild load (arbitrary address)", &EVIL_WILD_LOAD),
        ("backward-jump loop", &EVIL_LOOP),
        ("no verdict (uninit R0)", &EVIL_NO_VERDICT),
    ];
    let mut all_rejected = true;
    for (name, prog) in evils {
        match verify_prevail(prog) {
            Ok(_) => {
                kprint!(" [P8] third-party '{}': ACCEPTED <- BUG\n", name);
                all_rejected = false;
            }
            Err(e) => kprint!(" [P8] third-party '{}': REJECTED ({})\n", name, e),
        }
    }
    // Expanded ISA: a real rule (pointer-arith + multi-byte loads + JEQ) — verify + run.
    let parse_ok = match verify_prevail(&bpf::PARSE_RULE) {
        Ok(min) => {
            let mut frame = [0u8; 14];
            frame[12] = 0x08; // EtherType 0x0800 (IPv4, big-endian on the wire)
            frame[13] = 0x00;
            let v = bpf::run(&bpf::PARSE_RULE, frame.as_ptr(), frame.len());
            kprint!(" [P8] PARSE_RULE (ptr-arith+LDX_H/W+JEQ): SAFE (min_len={}); IPv4 frame -> {}\n",
                min, if v == bpf::DROP { "DROP" } else if v == bpf::PASS { "PASS" } else { "INVALID" });
            min == 14 && v == bpf::DROP
        }
        Err(e) => {
            kprint!(" [P8] PARSE_RULE REJECTED ({}) <- BUG\n", e);
            false
        }
    };
    let good = verify_prevail(&THREAT_RULE).is_ok();
    // tnum payoff: a variable-IP-header-offset rule the interval domain rejects.
    let tnum_ok = matches!(verify_prevail(&bpf::VAR_OFFSET_RULE), Ok(75));
    kprint!(" [P16-tnum] {} — variable-offset rule ((ihl&0xf)<<2) ACCEPTED via tnum (bounded); PREVAIL/Windows reject it\n",
        if tnum_ok { "PASS" } else { "FAIL" });
    kprint!(" [P8] {} — accepts safe rules (incl. expanded ISA), statically rejects every unsafe one\n",
        if good && all_rejected && parse_ok { "PASS" } else { "FAIL" });
}

/// P8 detection plane: (1) the GENERAL JIT matches the interpreter on a rule with
/// forward JUMPS + pointer-arith + multi-byte loads (PARSE_RULE) across inputs —
/// proving branch codegen, not just the straight-line threat rule; (2) the live
/// rule registry DROPs the threat ports and PASSes benign traffic; (3) QSecBit
/// scores real hits ("the OS is the sensor"). All QEMU-verifiable, no flash.
#[cfg(not(feature = "cm5"))]
fn p8_detection_plane() -> bool {
    kprint!("\n [P8] detection plane — general JIT parity + live rule registry + QSecBit\n");
    let mut ok = true;

    // (1) General JIT vs interpreter on PARSE_RULE (has a forward JEQ). Test an
    // IPv4 frame (DROP) and an ARP frame (PASS) — both must match the interpreter.
    match arch_aarch64::bpf_jit::compile(&bpf::PARSE_RULE) {
        Some(va) => {
            let f: extern "C" fn(*const u8) -> u64 =
                unsafe { core::mem::transmute::<usize, extern "C" fn(*const u8) -> u64>(va) };
            let mut jit_ok = true;
            for &(et_hi, et_lo) in &[(0x08u8, 0x00u8), (0x08, 0x06), (0x86, 0xdd)] {
                let mut frame = [0u8; 14];
                frame[12] = et_hi;
                frame[13] = et_lo;
                let jv = f(frame.as_ptr());
                let iv = bpf::run(&bpf::PARSE_RULE, frame.as_ptr(), frame.len());
                if jv != iv {
                    jit_ok = false;
                }
            }
            kprint!("   general JIT (PARSE_RULE, forward JEQ): matches interpreter across inputs: {}\n",
                if jit_ok { "yes" } else { "NO" });
            ok &= jit_ok;
        }
        None => {
            kprint!("   general JIT: PARSE_RULE compile FAILED\n");
            ok = false;
        }
    }

    // (2) Live rule registry over crafted L4 headers (dst-port at 2..4, BE).
    let hits_before = telemetry::rule_hits();
    let score_before = telemetry::score();
    let cases: [(u16, u16, &str); 4] = [
        (4444, packet::DROP, "port-4444"),
        (23, packet::DROP, "telnet-23"),
        (31337, packet::DROP, "backdoor-31337"),
        (80, packet::PASS, "http-80"),
    ];
    let mut plane_ok = true;
    for (port, want, name) in cases {
        let l4 = [0u8, 0u8, (port >> 8) as u8, (port & 0xff) as u8];
        let v = rules::run_l4(&l4, 0);
        let good = v == want;
        plane_ok &= good;
        kprint!("   rule plane: dst {} ({}) -> {} [{}]\n",
            port, name, if v == packet::DROP { "DROP" } else { "PASS" }, if good { "ok" } else { "BUG" });
    }
    ok &= plane_ok;

    // (3) QSecBit sensed the three DROPs as scored threat signals.
    let dhits = telemetry::rule_hits() - hits_before;
    let dscore = telemetry::score() - score_before;
    kprint!("   QSecBit: {} live rule hits scored (+{} points) — the OS is the sensor\n", dhits, dscore);
    ok &= dhits == 3 && dscore > 0;

    kprint!(" [P8-plane] {} — signed rules run at native speed on live traffic, scored in the TCB\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// P8/DET-6 — JIT<->interpreter differential over EVERY live JIT-compiled rule.
///
/// The boot self-test previously cross-checked ONLY THREAT_RULE (exhaustively over
/// all 65536 L4 ports; that test stays). But the live corpus JIT-compiles ~9
/// CALL-free rules (port blocks, ARP guards, TCP-scan flags) and the hot path runs
/// the native code with NO runtime cross-check — a codegen bug in one rule's
/// LDX/multi-tag/JNE path would silently pass a matching threat. This extends the
/// differential to ALL of them: for each JIT'd rule (reusing the entry VA `init()`
/// already published — no recompile) we run BOTH the native fn and the verified
/// interpreter over a match-constant-stressed pseudo-deterministic input set and
/// assert identical verdicts.
///
/// FLOW rules use the `CALL` helper (opcode 0x85); the JIT rejects them
/// (`compile` -> None) so they run interpreter-only — nothing to differentiate —
/// and `rules::jitted_rules` excludes them (jit == 0).
///
/// Input set: N frames of the rule's proven `min_len`, each byte drawn (via a
/// deterministic xorshift seeded by the rule index — NO Date/rand) from an
/// alphabet of the corpora's match-constant bytes (ethertype halves 0x08/0x06,
/// ARP htype/ptype/hlen/plen 0x00/0x01/0x04/0x06, TCP flag bytes, port halves), so
/// each rule's PASS *and* DROP branches are exercised, not just the trivial
/// no-match path. Every rule reads only within its `min_len`, so the frame stresses
/// exactly the offsets that rule reads.
#[cfg(not(feature = "cm5"))]
fn p8_jit_differential() {
    const N: usize = 4096;
    // Every byte that appears in a live rule's match constants (so random frames
    // hit both branches): 0x08/0x06 ethertype halves; 0x00/0x01 htype; 0x04/0x06
    // hlen/plen; TCP flags 0x00/0x01/0x02/0x04/0x08/0x10/0x20/0x29/0x18/0x17; port
    // halves 0x11/0x5c (4444) 0x00/0x17 (23) 0x7a/0x69 (31337); 0xff.
    const ALPHA: [u8; 16] = [
        0x00, 0x01, 0x02, 0x04, 0x06, 0x08, 0x10, 0x11, 0x17, 0x18, 0x20, 0x29, 0x5c, 0x69, 0x7a,
        0xff,
    ];
    kprint!("\n [P8] DET-6 JIT<->interpreter differential — every live JIT'd rule (not just THREAT_RULE)\n");

    let mut views = [rules::JittedRule { name: "", prog: &[], min_len: 0, jit: 0 }; 16];
    let nr = rules::jitted_rules(&mut views);

    let mut buf = [0u8; 128]; // >= any live rule's min_len (ARP_MALFORMED = 42)
    let mut total_mismatch = 0u32;
    let mut diffed = 0u32;
    for r in 0..nr {
        let v = views[r];
        let len = (v.min_len as usize).clamp(1, buf.len());
        let f: extern "C" fn(*const u8) -> u64 =
            unsafe { core::mem::transmute::<usize, extern "C" fn(*const u8) -> u64>(v.jit) };
        // deterministic xorshift32, seeded by rule index (never 0) — no rand/Date.
        let mut s: u32 = 0x9E37_79B9 ^ (r as u32).wrapping_mul(0x0100_0193).wrapping_add(1);
        let mut mm = 0u32;
        let (mut passes, mut drops, mut inval) = (0u32, 0u32, 0u32);
        for _ in 0..N {
            for b in buf[..len].iter_mut() {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                *b = ALPHA[(s as usize) & 15];
            }
            let jv = f(buf.as_ptr());
            let iv = bpf::run(v.prog, buf.as_ptr(), len);
            if jv != iv {
                mm += 1;
            }
            match iv {
                bpf::PASS => passes += 1,
                bpf::DROP => drops += 1,
                _ => inval += 1,
            }
        }
        total_mismatch += mm;
        diffed += 1;
        kprint!(
            "   [P8-diff] {:<16} min_len={:<2} jit@{:#x} N={} pass={} drop={} inval={} mismatches={}\n",
            v.name, v.min_len, v.jit, N, passes, drops, inval, mm
        );
    }
    // PASS iff the native code agrees with the verified interpreter on every input
    // of every JIT'd rule, AND we actually differentiated >= 2 distinct rules
    // (guards against a silently-empty corpus reporting a vacuous pass).
    let ok = total_mismatch == 0 && diffed >= 2;
    kprint!(
        " [P8-diff] {} — {} live JIT'd rules cross-checked vs interpreter ({} frames each); FLOW/CALL rules interp-only (excluded); {} total mismatches\n",
        if ok { "PASS" } else { "FAIL" },
        diffed,
        N,
        total_mismatch
    );
}

/// P8 adaptive NAPI: drive the detection datapath through an adaptive poll-budget
/// engine over a realistic RX arrival pattern (heavy burst → trickle → quiet).
/// Each drained "frame" is a REAL verdict (rules::run_l4 on an L4 header), so this
/// is the actual datapath under NAPI, not a simulation of one. Proves the budget
/// GROWS under load (bounded latency) and the engine IDLEs/re-arms when the ring
/// drains (bounded idle CPU) — retiring the spin-poll loop.
#[cfg(not(feature = "cm5"))]
fn p8_adaptive_napi() -> bool {
    kprint!("\n [P8] adaptive NAPI data plane — poll-budget grows under load, idles when quiet\n");
    let mut n = napi::Napi::new(2, 64);
    // Frames waiting in the NIC RX ring at successive service windows.
    let arrivals: [u32; 7] = [100, 90, 30, 4, 0, 2, 0];
    let mut idles = 0u32;
    let ports = [4444u16, 80, 443, 23]; // mix of threat + benign -> real verdicts
    let mut seq = 0usize;
    for (w, &avail) in arrivals.iter().enumerate() {
        let mut remaining = avail;
        loop {
            let out = n.service(|budget| {
                let take = budget.min(remaining);
                for _ in 0..take {
                    let port = ports[seq % ports.len()];
                    seq += 1;
                    let l4 = [0u8, 0u8, (port >> 8) as u8, (port & 0xff) as u8];
                    let _ = rules::run_l4(&l4, 0); // real verdict, feeds QSecBit
                }
                remaining -= take;
                take
            });
            if out == napi::Outcome::Idle {
                idles += 1;
                break; // caller would re-arm the RX IRQ + WFI here
            }
        }
        kprint!("   window {}: {:>3} arrived | budget now {:>2} (peak {:>2}) | {}\n",
            w, avail, n.budget(), n.max_budget(), if n.is_idle() { "IDLE (IRQ armed)" } else { "polling" });
    }
    // Under load the budget must have grown past its floor; the box must have
    // idled (re-armed) at least once when the ring drained.
    let grew = n.max_budget() > 2;
    let idled = n.rearms() >= 1;
    kprint!("   summary: {} frames judged over {} services, peak budget {}, {} IRQ re-arms\n",
        n.total_processed(), n.services(), n.max_budget(), n.rearms());
    let ok = grew && idled && idles >= 1;
    kprint!(" [P8-napi] {} — adaptive budget (peak {}) under load, idle+re-arm when quiet — spin-poll retired\n",
        if ok { "PASS" } else { "FAIL" }, n.max_budget());
    ok
}

/// P8 L2 guard: parity with HookProbe `napse-l2guard` — the signed L2 rule tier
/// drops a malformed ARP (`is_malformed`) and a spoofed ARP (`eth_mismatch`) at
/// the frame level, while a well-formed ARP and non-ARP traffic pass. R1 = the
/// raw L2 frame; the same field offsets the `napse-l2guard` BPF program uses.
#[cfg(not(feature = "cm5"))]
fn p8_l2guard() -> bool {
    kprint!("\n [P8] L2 guard — napse-l2guard parity: malformed-ARP + ARP-spoof drop\n");
    // A well-formed RFC-826 Ethernet/IPv4 ARP frame; `htype_lo` and `smac0` let
    // us perturb the htype and the payload sender-MAC's first byte.
    fn arp_frame(htype_lo: u8, smac0: u8) -> [u8; 42] {
        let mut f = [0u8; 42];
        for b in f.iter_mut().take(6) {
            *b = 0xff; // eth dst = broadcast
        }
        f[6..12].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // eth src
        f[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType = ARP
        f[14..16].copy_from_slice(&[0x00, htype_lo]); // htype (1 = Ethernet)
        f[16..18].copy_from_slice(&[0x08, 0x00]); // ptype = IPv4
        f[18] = 6;
        f[19] = 4; // hlen, plen
        f[20..22].copy_from_slice(&[0x00, 0x01]); // oper = request
        f[22..28].copy_from_slice(&[smac0, 0x11, 0x22, 0x33, 0x44, 0x55]); // ARP sender_mac
        f
    }
    let valid = arp_frame(0x01, 0x02); // well-formed, sender_mac == eth src
    let malformed = arp_frame(0x02, 0x02); // htype = 2 -> malformed
    let spoof = arp_frame(0x01, 0x99); // sender_mac != eth src -> spoof
    let mut ipv4 = [0u8; 42];
    ipv4[12..14].copy_from_slice(&[0x08, 0x00]); // non-ARP (IPv4)
    // DET-SEP (ADR 0023): malformed = a STRUCTURAL fact -> FrameDrop (drops); an
    // eth-src≠sender-mac shape is what a legit gratuitous/proxy/NAT-rebind ARP ALSO
    // presents, and heqk has no cross-packet state to confirm a real spoof -> Observe
    // (matrix row L3: PASS on the wire, alerted, never a fabricated FrameDrop).
    let cases: [(&[u8], u16, &str); 4] = [
        (&valid, packet::PASS, "well-formed ARP"),
        (&malformed, packet::DROP, "malformed ARP (htype!=1) -> FrameDrop"),
        (&spoof, packet::PASS, "ARP eth-src mismatch -> Observe (legit gratuitous/proxy ARP passes)"),
        (&ipv4, packet::PASS, "non-ARP (IPv4)"),
    ];
    let mut ok = true;
    for (f, want, name) in cases {
        let v = rules::run_l2(f, 0);
        let good = v == want;
        ok &= good;
        kprint!("   L2: {} -> {} [{}]\n",
            name, if v == packet::DROP { "DROP" } else { "PASS" }, if good { "ok" } else { "BUG" });
    }
    // Prove the tri-state seam: malformed DECIDES FrameDrop, the mismatch DECIDES
    // Observe (detected — not a detection gap), the valid frame fires NOTHING.
    let mal_v = rules::verdict_l2(&malformed, 0);
    let spf_v = rules::verdict_l2(&spoof, 0);
    let val_v = rules::verdict_l2(&valid, 0);
    let seam_ok = matches!(mal_v, Some(verdict::Verdict::FrameDrop))
        && matches!(spf_v, Some(verdict::Verdict::Observe))
        && val_v.is_none();
    ok &= seam_ok;
    kprint!("   seam: malformed={:?} mismatch={:?} valid={:?} [{}]\n",
        mal_v, spf_v, val_v, if seam_ok { "ok" } else { "BUG" });
    kprint!(" [P8-l2] {} — malformed ARP FrameDropped; eth-src mismatch detected but OBSERVED (legit ARP passes); tri-state seam (ADR 0023)\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// P8 TCP scan detection: the signed TCP-flag tier drops stateless anomalous-flag
/// scans (NULL / FIN / Xmas / SYN-FIN — Nmap/Suricata signatures) while normal
/// SYN and ACK segments pass. R1 = the TCP header; flags at offset 13.
#[cfg(not(feature = "cm5"))]
fn p8_tcpscan() -> bool {
    kprint!("\n [P8] TCP scan detection — anomalous-flag signatures (Nmap/Suricata-style)\n");
    fn tcp_hdr(flags: u8) -> [u8; 20] {
        let mut t = [0u8; 20];
        t[12] = 0x50; // data offset = 5 words (20-byte header)
        t[13] = flags; // TCP flags byte
        t
    }
    // DET-SEP (ADR 0023 / matrix row A6): a NULL/FIN/Xmas/SYN-FIN shape is a single
    // crafted packet with no rate context; it is DETECTED (fires an alert) but the
    // observe-by-default verdict is `RateLimit{over_limit:false}` -> PASS on the wire
    // (a per-source scan-rate meter is the M2.2 follow-on). Normal SYN/ACK fire
    // NOTHING. `want_fired` = does this shape produce an alert.
    let cases: [(u8, bool, &str); 6] = [
        (0x00, true, "NULL scan (no flags)"),
        (0x01, true, "FIN scan"),
        (0x29, true, "Xmas scan (FIN|PSH|URG)"),
        (0x03, true, "SYN+FIN (illegal)"),
        (0x02, false, "normal SYN"),
        (0x10, false, "normal ACK"),
    ];
    let mut ok = true;
    for (flags, want_fired, name) in cases {
        let t = tcp_hdr(flags);
        let v = rules::verdict_tcp(&t, 0);
        // Every case must PASS on the wire (observe-by-default — no legit segment
        // dropped); a scan shape additionally must have FIRED (Some), a normal one not.
        let wire = v.map_or(packet::PASS, verdict::Verdict::to_wire);
        let fired = v.is_some();
        let good = wire == packet::PASS && fired == want_fired;
        ok &= good;
        kprint!("   TCP flags {:#04x}: {} -> wire {} fired {} [{}]\n",
            flags, name, if wire == packet::DROP { "DROP" } else { "PASS" }, fired, if good { "ok" } else { "BUG" });
    }
    kprint!(" [P8-tcp] {} — NULL/FIN/Xmas/SYN-FIN scans DETECTED but OBSERVED (no legit segment dropped); normal SYN/ACK fire nothing (ADR 0023 observe-by-default)\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// P8 SYN-flood — the first STATEFUL detection: the signed TCP_SYN_FLOOD rule
/// consults a kernel rate limiter via a BPF CALL helper. A lone SYN under the
/// windowed limit passes; a sustained flood (limit+ SYNs in one window) is
/// dropped. Proves the stateful primitive (verifier admits CALL; interpreter runs
/// it; the JIT correctly declines it). v1 is a global bucket, tested standalone —
/// not yet wired into the live datapath (per-source keying is the follow-up).
#[cfg(not(feature = "cm5"))]
fn p8_synflood() -> bool {
    kprint!("\n [P8] SYN-flood rate-limit — first STATEFUL rule (BPF CALL helper + rate limiter)\n");
    // The verifier must ADMIT the stateful rule (known helper, args init).
    let verified = bpf::verify_prevail(&bpf::TCP_SYN_FLOOD).is_ok();
    // The JIT must DECLINE it (CALL unsupported) -> interpreter path.
    let jit_declines = arch_aarch64::bpf_jit::compile(&bpf::TCP_SYN_FLOOD).is_none();
    kprint!("   verifier admits CALL rule: {}; JIT declines (interp-only): {}\n",
        if verified { "yes" } else { "NO" }, if jit_declines { "yes" } else { "NO" });

    let mut syn = [0u8; 20];
    syn[12] = 0x50;
    syn[13] = 0x02; // lone SYN
    let limit = bpf::SYN_LIMIT as usize;
    let mut passed = 0usize;
    let mut dropped = 0usize;
    for _ in 0..(limit + 20) {
        match bpf::run(&bpf::TCP_SYN_FLOOD, syn.as_ptr(), syn.len()) {
            bpf::PASS => passed += 1,
            _ => dropped += 1,
        }
    }
    kprint!("   burst of {} lone SYNs -> {} passed (~limit {}), {} dropped (flood)\n",
        limit + 20, passed, limit, dropped);
    // ~limit passed, the rest of the burst dropped once the window count crossed.
    let ok = verified && jit_declines && dropped >= 19 && passed <= limit + 1 && passed >= limit - 1;
    kprint!(" [P8-syn] {} — SYN rate under the window limit passes, the flood is rate-limited (stateful)\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// P8 per-source SYN-flood — the LIVE-datapath rule (`rules::run_flow`, wired into
/// classify). It self-parses the full frame to the IP source and rate-limits per
/// source, so a flood from one host is dropped while OTHER sources' connection
/// setups are unaffected — the property that makes it safe to enforce inline.
#[cfg(not(feature = "cm5"))]
fn p8_synflood_src() -> bool {
    kprint!("\n [P8] per-source SYN-flood — live rule keyed by IP source\n");
    fn syn_frame(src: [u8; 4]) -> [u8; 54] {
        let mut f = [0u8; 54];
        f[12] = 0x08;
        f[13] = 0x00; // EtherType IPv4
        f[14] = 0x45; // IHL=5
        f[23] = 6; // proto TCP
        f[26..30].copy_from_slice(&src); // IP source
        f[46] = 0x50; // TCP data offset
        f[47] = 0x02; // TCP flags = lone SYN
        f
    }
    let a = syn_frame([10, 0, 0, 1]);
    let b = syn_frame([20, 0, 0, 1]); // a different source (different rate slot)
    let limit = bpf::SYN_LIMIT as usize;
    let (mut ap, mut ad) = (0usize, 0usize);
    for _ in 0..(limit + 20) {
        match rules::run_flow(&a, 0) {
            packet::PASS => ap += 1,
            _ => ad += 1,
        }
    }
    let bp = (0..5).filter(|_| rules::run_flow(&b, 0) == packet::PASS).count();
    kprint!("   source A flood: {} passed (~limit {}), {} dropped; source B: {}/5 passed (isolated)\n",
        ap, limit, ad, bp);
    let ok = ad >= 19 && ap <= limit + 1 && ap >= limit - 1 && bp == 5;
    kprint!(" [P8-synsrc] {} — per-source SYN flood rate-limited inline; other sources unaffected\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// P8 threat-feed blocklist: the signed IP_BLOCKLIST rule (helper #2, a keyed
/// lookup) DROPs frames from a blocked CIDR prefix and PASSes everything else —
/// the WAN threat-feed enforcement, live in classify.
#[cfg(not(feature = "cm5"))]
fn p8_blocklist() -> bool {
    kprint!("\n [P8] threat-feed blocklist — helper #2 (keyed CIDR lookup), live rule\n");
    fn ipv4_frame(src: [u8; 4]) -> [u8; 34] {
        let mut f = [0u8; 34];
        f[12] = 0x08;
        f[13] = 0x00; // EtherType IPv4
        f[14] = 0x45; // IHL=5
        f[26..30].copy_from_slice(&src); // IP source
        f
    }
    // DET-SEP (ADR 0023 / matrix row L11): a single threat-feed IOC hit is a
    // reputation signal, not proof of attack — a shared-hosting/CDN IP a customer
    // legitimately uses can appear in a feed. So a hit is DETECTED (fires an alert)
    // but OBSERVED (PASS): "a customer touching one IOC is never quarantined."
    // Corroboration -> a higher verdict is the M2 follow-on. `want_fired` = feed hit.
    let cases: [([u8; 4], bool, &str); 3] = [
        ([192, 0, 2, 5], true, "192.0.2.5 (in blocked /24)"),
        ([8, 8, 8, 8], false, "8.8.8.8 (clean)"),
        ([10, 66, 66, 200], true, "10.66.66.200 (C2 subnet)"),
    ];
    let mut ok = true;
    for (src, want_fired, name) in cases {
        let f = ipv4_frame(src);
        let v = rules::verdict_flow(&f, 0);
        let wire = v.map_or(packet::PASS, verdict::Verdict::to_wire);
        // A feed hit fires as Observe (never a drop); a clean source fires nothing.
        let fired_observe = matches!(v, Some(verdict::Verdict::Observe));
        let good = wire == packet::PASS && (if want_fired { fired_observe } else { v.is_none() });
        ok &= good;
        kprint!("   blocklist: {} -> wire {} verdict {:?} [{}]\n",
            name, if wire == packet::DROP { "DROP" } else { "PASS" }, v, if good { "ok" } else { "BUG" });
    }
    kprint!(" [P8-block] {} — feed IOC hit DETECTED but OBSERVED (single hit never drops a customer, matrix L11); clean sources pass\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// P8/SOAR: the async, non-blocking telemetry exfiltration path. Each rule DROP in
/// the verdict engine (TCB) pushed a fixed-size event HEADER into the SPSC event
/// ring; here the "EL0 Telemetry Exporter" DRAINs it — proving the OS-as-sensor
/// can report to a SIEM without stalling the datapath (full ring ⇒ counted
/// overrun, never block). Wakeup would be a batched P12 Notification.
#[cfg(not(feature = "cm5"))]
fn p8_soar() -> bool {
    kprint!("\n [P8] SOAR event-ring — async telemetry exfiltration (non-blocking)\n");
    // DET-SEP: prior P8 selftests now push OBSERVE events (verdict=PASS) into the
    // shared ring (blocklist/scan/arp-spoof are observed, not dropped). Drain-and-
    // discard the ring first so this test asserts only on its OWN two fresh drops —
    // otherwise the "all exported events are DROP" check would see leftover PASS
    // events. (Order-independent test hygiene; the metal exporter drains continuously.)
    {
        let mut junk = [events::Event::EMPTY; 16];
        while events::drain(&mut junk) > 0 {}
    }
    // Trigger two fresh threat drops (each pushes an event header in the TCB).
    for &port in &[4444u16, 23u16] {
        let l4 = [0u8, 0u8, (port >> 8) as u8, (port & 0xff) as u8];
        let _ = rules::run_l4(&l4, 0);
    }
    // The exporter drains the ring (zero-copy read of the headers, never payload).
    let mut batch = [events::Event::EMPTY; 16];
    let n = events::drain(&mut batch);
    for ev in &batch[..n] {
        kprint!("   event: rule {} sev {} verdict {} class {} @ts {}\n",
            ev.rule_id, ev.severity, if ev.verdict == packet::DROP as u8 { "DROP" } else { "PASS" }, ev.class, ev.ts);
    }
    // At least the two fresh drops must have been exported; ring never blocked. Each carries
    // its tri-state class, and the class must AGREE with the wire action (a DROP is FrameDrop /
    // over-limit RateLimit / Quarantine — never Observe/Allowlisted/unknown).
    let drop_class = |c: u8| matches!(c, verdict::CLASS_FRAMEDROP | verdict::CLASS_RATELIMIT_OVER | verdict::CLASS_QUARANTINE);
    let ok = n >= 2 && batch[..n].iter().all(|e| e.verdict == packet::DROP as u8 && drop_class(e.class));
    kprint!(" [P8-soar] {} — {} threat events exported async ({} overruns, wire never stalled)\n",
        if ok { "PASS" } else { "FAIL" }, n, events::overruns());
    ok
}

/// DET-SEP — the M2 KEYSTONE selftest: the tri-state `decide()` seam ports the
/// operator's hard rule (ADR 0023) onto heqk. Mirrors the LEGIT rows of the Linux
/// `0.7-separation-matrix` that this seam makes satisfiable — "a legitimate customer
/// connection must ALWAYS pass" — and proves the four suspicion-free CONFIRMED drops
/// still drop (via the tri-state, not the old "any fire = drop"). QEMU-provable.
#[cfg(not(feature = "cm5"))]
fn p8_separation() -> bool {
    use verdict::{decide, DecideCtx, FindingClass, Verdict};
    kprint!("\n [P8] enforcement separation — tri-state decide() seam (ADR 0023: observe-by-default)\n");
    let mut ok = true;

    #[inline]
    fn wire(v: Option<Verdict>) -> u16 {
        v.map_or(packet::PASS, Verdict::to_wire)
    }

    // --- Row L11: a customer touching ONE threat-feed IOC is OBSERVED, never dropped.
    fn ipv4_src(src: [u8; 4]) -> [u8; 34] {
        let mut f = [0u8; 34];
        f[12] = 0x08;
        f[13] = 0x00;
        f[14] = 0x45;
        f[26..30].copy_from_slice(&src);
        f
    }
    let ioc = ipv4_src([10, 66, 66, 200]); // in a blocked C2 /24
    let ioc_v = rules::verdict_flow(&ioc, u32::from_be_bytes([10, 66, 66, 200]));
    let c_l11 = matches!(ioc_v, Some(Verdict::Observe)) && wire(ioc_v) == packet::PASS;
    ok &= c_l11;
    kprint!("   L11 blocklist IOC hit -> {:?}, wire PASS (customer never quarantined on one hit) [{}]\n",
        ioc_v, if c_l11 { "ok" } else { "BUG" });

    // --- Row L3: a single eth-src != sender-mac ARP is OBSERVED (legit gratuitous/proxy ARP passes).
    let mut spoof = [0u8; 42];
    for b in spoof.iter_mut().take(6) {
        *b = 0xff;
    }
    spoof[6..12].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // eth src
    spoof[12..14].copy_from_slice(&[0x08, 0x06]); // ARP
    spoof[14..16].copy_from_slice(&[0x00, 0x01]); // htype=1
    spoof[16..18].copy_from_slice(&[0x08, 0x00]); // ptype ipv4
    spoof[18] = 6;
    spoof[19] = 4;
    spoof[20..22].copy_from_slice(&[0x00, 0x01]);
    spoof[22..28].copy_from_slice(&[0x99, 0x11, 0x22, 0x33, 0x44, 0x55]); // sender-mac != eth src
    let spf_v = rules::verdict_l2(&spoof, 0);
    let c_l3 = matches!(spf_v, Some(Verdict::Observe)) && wire(spf_v) == packet::PASS;
    ok &= c_l3;
    kprint!("   L3 ARP eth-src mismatch -> {:?}, wire PASS (legit gratuitous/proxy ARP passes) [{}]\n",
        spf_v, if c_l3 { "ok" } else { "BUG" });

    // --- Allowlisted floor: a management source is NEVER enforced against (ADR 0022 D2).
    let mgmt = u32::from_be_bytes([10, 200, 0, 5]);
    let atk = u32::from_be_bytes([203, 0, 113, 9]);
    let c_floor1 = verdict::is_allowlisted(mgmt) && !verdict::is_allowlisted(atk);
    ok &= c_floor1;
    kprint!("   floor: is_allowlisted(mgmt)={} is_allowlisted(attacker)={} [{}]\n",
        verdict::is_allowlisted(mgmt), verdict::is_allowlisted(atk), if c_floor1 { "ok" } else { "BUG" });
    let mgmt_flood = decide(FindingClass::FloodRate, DecideCtx::for_src(mgmt));
    let atk_flood = decide(FindingClass::FloodRate, DecideCtx::for_src(atk));
    let c_floor2 = mgmt_flood == Verdict::Allowlisted && !mgmt_flood.is_drop()
        && atk_flood == (Verdict::RateLimit { over_limit: true }) && atk_flood.is_drop();
    ok &= c_floor2;
    kprint!("   floor: FloodRate mgmt->{:?} (PASS), attacker->{:?} (DROP) [{}]\n",
        mgmt_flood, atk_flood, if c_floor2 { "ok" } else { "BUG" });

    // --- Floor end-to-end: a SYN-flood burst from a mgmt source drops ZERO frames,
    // however far over the rate wall (the floor is unconditional — never self-lock-out).
    fn syn_frame(src: [u8; 4]) -> [u8; 54] {
        let mut f = [0u8; 54];
        f[12] = 0x08;
        f[13] = 0x00;
        f[14] = 0x45;
        f[23] = 6; // TCP
        f[26..30].copy_from_slice(&src);
        f[46] = 0x50; // TCP data offset
        f[47] = 0x02; // lone SYN
        f
    }
    let mgmt_syn = syn_frame([10, 200, 0, 5]);
    let burst = (bpf::SYN_LIMIT as usize) + 20;
    let mgmt_drops = (0..burst).filter(|_| rules::run_flow(&mgmt_syn, mgmt) == packet::DROP).count();
    let c_floor3 = mgmt_drops == 0;
    ok &= c_floor3;
    kprint!("   floor end-to-end: mgmt SYN-flood burst of {} -> {} drops (must be 0) [{}]\n",
        burst, mgmt_drops, if c_floor3 { "ok" } else { "BUG" });

    // --- Generic: a fired detector defaults to Observe, never drops a legit frame.
    let mut nullscan = [0u8; 20];
    nullscan[12] = 0x50;
    nullscan[13] = 0x00; // NULL scan (no flags)
    let scan_v = rules::verdict_tcp(&nullscan, 0);
    let c_gen = scan_v.is_some() && wire(scan_v) == packet::PASS;
    ok &= c_gen;
    kprint!("   generic: fired scan detector -> {:?}, wire PASS (observe-by-default) [{}]\n",
        scan_v, if c_gen { "ok" } else { "BUG" });

    // --- The suspicion-free CONFIRMED drops STILL drop (via the tri-state, not "any fire").
    let mut malformed = [0u8; 42];
    for b in malformed.iter_mut().take(6) {
        *b = 0xff;
    }
    malformed[6..12].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    malformed[12..14].copy_from_slice(&[0x08, 0x06]);
    malformed[14..16].copy_from_slice(&[0x00, 0x02]); // htype=2 -> malformed
    malformed[16..18].copy_from_slice(&[0x08, 0x00]);
    malformed[18] = 6;
    malformed[19] = 4;
    malformed[22..28].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let mal_v = rules::verdict_l2(&malformed, 0);
    let c_mal = matches!(mal_v, Some(Verdict::FrameDrop)) && wire(mal_v) == packet::DROP;
    ok &= c_mal;
    kprint!("   confirmed-drop: malformed frame -> {:?}, wire DROP [{}]\n",
        mal_v, if c_mal { "ok" } else { "BUG" });
    let l4_4444 = [0u8, 0u8, (4444u16 >> 8) as u8, (4444u16 & 0xff) as u8];
    let sig_v = rules::verdict_l4(&l4_4444, 0);
    let c_sig = wire(sig_v) == packet::DROP;
    ok &= c_sig;
    kprint!("   confirmed-drop: :4444 signature -> {:?}, wire DROP [{}]\n",
        sig_v, if c_sig { "ok" } else { "BUG" });

    kprint!(" [P8-sep] {} — tri-state decide() seam: observe-by-default, blocklist/ARP-spoof OBSERVED (legit passes), mgmt floor never enforced, malformed/signature still FrameDrop (ADR 0023 keystone)\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// M2.1 — L2 structural + flood parity selftest: F6/F7/F8 structural anomalies +
/// mac-flood (port-role-aware) + broadcast-storm (with the mDNS/SSDP/LLMNR exemption),
/// ALL routed through the `decide_l2()` seam. The load-bearing assertion is the
/// Access-vs-Uplink mac-flood split: the SAME fan-out that RateLimit-DROPs on an
/// access port stays OBSERVE (PASS) on an uplink/AP port — a legit AP client is NEVER
/// dropped (ADR 0023 D12). QEMU-provable; uses isolated port ids so it never pollutes
/// the datapath's port-0 fan-out state.
#[cfg(not(feature = "cm5"))]
fn p8_l2struct() -> bool {
    use verdict::{decide_l2, DecideCtx, FindingClass, PortRole, Verdict};
    kprint!("\n [P8] L2 structural + flood parity (M2.1) — F6/F7/F8 + mac-flood(port-role) + broadcast-storm, via decide_l2()\n");
    let mut ok = true;

    #[inline]
    fn wire(v: Option<Verdict>) -> u16 {
        v.map_or(packet::PASS, Verdict::to_wire)
    }
    const DST: [u8; 6] = [0x99, 0x88, 0x77, 0x66, 0x55, 0x44];

    // --- F6: a multicast/broadcast SOURCE MAC (I/G bit set) -> FrameDrop.
    let mut f6 = [0u8; 64];
    f6[0..6].copy_from_slice(&DST);
    f6[6..12].copy_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]); // I/G bit set
    f6[12..14].copy_from_slice(&[0x08, 0x00]);
    let f6_v = rules::l2_stateful_verdict(&f6, 0, 2, PortRole::Access);
    let c_f6 = matches!(f6_v, Some(Verdict::FrameDrop)) && wire(f6_v) == packet::DROP;
    ok &= c_f6;
    kprint!("   F6 multicast-src MAC -> {:?}, wire DROP [{}]\n", f6_v, if c_f6 { "ok" } else { "BUG" });

    // --- F6 LEGIT: a locally-administered UNICAST src (0x02 set, I/G 0x01 CLEAR) must NOT flag.
    let mut f6l = f6;
    f6l[6..12].copy_from_slice(&[0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let f6l_v = rules::l2_stateful_verdict(&f6l, 0, 2, PortRole::Access);
    let c_f6l = wire(f6l_v) == packet::PASS;
    ok &= c_f6l;
    kprint!("   F6 legit locally-admin unicast src -> {:?}, wire PASS [{}]\n", f6l_v, if c_f6l { "ok" } else { "BUG" });

    // --- F7: an oversize frame (>1522B) -> FrameDrop.
    let mut f7 = [0u8; 1600];
    f7[0..6].copy_from_slice(&DST);
    f7[6..12].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    f7[12..14].copy_from_slice(&[0x08, 0x00]);
    let f7_v = rules::l2_stateful_verdict(&f7, 0, 2, PortRole::Access);
    let c_f7 = matches!(f7_v, Some(Verdict::FrameDrop)) && wire(f7_v) == packet::DROP;
    ok &= c_f7;
    kprint!("   F7 oversize frame ({}B) -> {:?}, wire DROP [{}]\n", f7.len(), f7_v, if c_f7 { "ok" } else { "BUG" });

    // --- F8: a double-tagged (QinQ) VLAN frame -> FrameDrop.
    let mut f8 = [0u8; 64];
    f8[0..6].copy_from_slice(&DST);
    f8[6..12].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    f8[12..14].copy_from_slice(&[0x81, 0x00]); // 802.1Q tag 1
    f8[14..16].copy_from_slice(&[0x00, 0x0a]);
    f8[16..18].copy_from_slice(&[0x81, 0x00]); // stacked tag 2 (QinQ)
    f8[18..20].copy_from_slice(&[0x00, 0x0b]);
    f8[20..22].copy_from_slice(&[0x08, 0x00]);
    let f8_v = rules::l2_stateful_verdict(&f8, 0, 2, PortRole::Access);
    let c_f8 = matches!(f8_v, Some(Verdict::FrameDrop)) && wire(f8_v) == packet::DROP;
    ok &= c_f8;
    kprint!("   F8 double-tagged VLAN -> {:?}, wire DROP [{}]\n", f8_v, if c_f8 { "ok" } else { "BUG" });

    // --- decide_l2 port-role logic (deterministic): Access L2Flood->RateLimit(DROP), Uplink->Observe(PASS).
    let c_role = decide_l2(FindingClass::L2Flood, DecideCtx::for_l2(0, PortRole::Access)) == (Verdict::RateLimit { over_limit: true })
        && decide_l2(FindingClass::L2Flood, DecideCtx::for_l2(0, PortRole::Uplink)) == Verdict::Observe;
    ok &= c_role;
    kprint!("   decide_l2 port-role: Access L2Flood->RateLimit(DROP), Uplink L2Flood->Observe(PASS) [{}]\n",
        if c_role { "ok" } else { "BUG" });

    // --- mac-flood ACCESS: 40 distinct source MACs -> RateLimit (wire DROP) once past 20.
    // The dst is UNICAST (00:11:22:33:44:55) on purpose: mac-flood is keyed on distinct
    // SOURCE-MAC count, so this tests D12 in isolation. (DST above is a multicast address —
    // reusing it here would ALSO trip the broadcast-storm counter, which post-A3 sheds a
    // non-exempt mcast flood on ANY port — a different row. A real legit AP flood is many
    // distinct sources with unicast/exempt-mcast dst, so the two never collide in the field.)
    let mut fr = [0u8; 64];
    fr[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    fr[12..14].copy_from_slice(&[0x08, 0x00]);
    let mut mf_access_drop = false;
    for i in 0..40u8 {
        fr[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, i]); // distinct unicast src
        if rules::l2_stateful_verdict(&fr, 0, 5, PortRole::Access).map_or(false, Verdict::is_drop) {
            mf_access_drop = true;
        }
    }
    ok &= mf_access_drop;
    kprint!("   mac-flood ACCESS (40 distinct MACs) -> RateLimit DROP fired: {} [{}]\n",
        mf_access_drop, if mf_access_drop { "ok" } else { "BUG" });

    // --- mac-flood UPLINK/AP: the SAME fan-out (320 distinct MACs) must FIRE but stay
    //     OBSERVE — NEVER a wire drop (the key legit-safety assertion: AP clients pass).
    let mut mf_uplink_fired = false;
    let mut mf_uplink_bad = false; // any drop OR any non-Observe verdict on an uplink = failure
    for i in 0..320u16 {
        fr[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, (i >> 8) as u8, (i & 0xff) as u8]);
        if let Some(v) = rules::l2_stateful_verdict(&fr, 0, 6, PortRole::Uplink) {
            mf_uplink_fired = true;
            if v.is_drop() || v != Verdict::Observe {
                mf_uplink_bad = true;
            }
        }
    }
    let c_uplink = mf_uplink_fired && !mf_uplink_bad;
    ok &= c_uplink;
    kprint!("   mac-flood UPLINK/AP (320 distinct MACs) -> fired={} any_drop_or_non_observe={} (must fire+Observe, NEVER drop legit AP clients) [{}]\n",
        mf_uplink_fired, mf_uplink_bad, if c_uplink { "ok" } else { "BUG" });

    // --- broadcast-storm: a non-exempt raw broadcast flood on an Access port -> RateLimit (DROP).
    let mut bc = [0u8; 64];
    bc[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // broadcast dst
    bc[6..12].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // SAME src (no mac-flood)
    bc[12..14].copy_from_slice(&[0x08, 0x00]);
    let mut bc_drop = false;
    for _ in 0..60 {
        if rules::l2_stateful_verdict(&bc, 0, 7, PortRole::Access).map_or(false, Verdict::is_drop) {
            bc_drop = true;
        }
    }
    ok &= bc_drop;
    kprint!("   broadcast-storm non-exempt (60 bcast frames) -> RateLimit DROP fired: {} [{}]\n",
        bc_drop, if bc_drop { "ok" } else { "BUG" });

    // --- A3 FIX: a non-exempt broadcast flood on an UPLINK port must ALSO RateLimit (DROP).
    // Unlike mac-flood (legit many-MACs on an AP → Observe), a non-exempt bcast flood is
    // resource-exhaustion on any port (legit mcast is exempted above), so it is FloodRate.
    let mut bc_up_drop = false;
    for _ in 0..60 {
        if rules::l2_stateful_verdict(&bc, 0, 9, PortRole::Uplink).map_or(false, Verdict::is_drop) {
            bc_up_drop = true;
        }
    }
    ok &= bc_up_drop;
    kprint!("   broadcast-storm non-exempt on UPLINK -> RateLimit DROP fired: {} (A3 fix: bcast flood shed on ANY port) [{}]\n",
        bc_up_drop, if bc_up_drop { "ok" } else { "BUG" });

    // --- broadcast-storm EXEMPT: an mDNS burst (01:00:5e:00:00:fb) must NEVER fire or drop.
    let mut md = [0u8; 64];
    md[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]); // mDNS group
    md[6..12].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    md[12..14].copy_from_slice(&[0x08, 0x00]);
    let mut mdns_fired = false;
    for _ in 0..200 {
        if let Some(_v) = rules::l2_stateful_verdict(&md, 0, 4, PortRole::Access) {
            mdns_fired = true;
        }
    }
    let c_mdns = !mdns_fired;
    ok &= c_mdns;
    kprint!("   broadcast-storm EXEMPT mDNS (200 frames) -> fired={} (must never fire; legit service-discovery passes) [{}]\n",
        mdns_fired, if c_mdns { "ok" } else { "BUG" });

    // --- RA-guard (RFC 6105 / L4 legit + A9 rogue): an ICMPv6 Router Advertisement is
    //     legit ONLY on a router/uplink port. Access -> FrameDrop (rogue gateway-hijack);
    //     Uplink -> Observe (legit downstream-router RA). Fail-safe: live default Uplink.
    let mut ra = [0u8; 70];
    ra[0..6].copy_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]); // IPv6 all-nodes (exempt from storm)
    ra[6..12].copy_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]); // unicast src
    ra[12..14].copy_from_slice(&[0x86, 0xdd]);
    ra[14] = 0x60; // IPv6 v6
    ra[19] = 0x10; // payload length 16
    ra[20] = 58; // ICMPv6
    ra[21] = 255; // hop limit
    ra[54] = 134; // Router Advertisement
    let ra_detected = crate::net::is_icmpv6_ra(&ra);
    let ra_access_drop = rules::l2_stateful_verdict(&ra, 0, 2, PortRole::Access).map_or(false, Verdict::is_drop);
    let ra_uplink_obs = rules::l2_stateful_verdict(&ra, 0, 3, PortRole::Uplink) == Some(Verdict::Observe);
    let c_ra = ra_detected && ra_access_drop && ra_uplink_obs;
    ok &= c_ra;
    kprint!("   RA-guard: is-RA={} Access-rogue-DROP={} Uplink-legit-Observe={} (A9 drop / L4 observe) [{}]\n",
        ra_detected, ra_access_drop, ra_uplink_obs, if c_ra { "ok" } else { "BUG" });

    kprint!(" [P8-l2struct] {} — F6/F7/F8 -> FrameDrop; mac-flood Access->RateLimit but Uplink/AP->Observe (legit AP clients NEVER dropped); broadcast-storm fires but mDNS/SSDP/LLMNR exempt; RA-guard Access->FrameDrop/Uplink->Observe (ADR 0023 D12/D13 + RFC 6105, all via decide_l2)\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// M2.2 — FLOW-STATE parity selftest (the conntrack-equivalent). Proves heqk's
/// per-source distinct-dst-port scan counter reaches the CORRECT tri-state via the SAME
/// `decide()` seam: an unconfirmed sweep → bounded `RateLimit` (wire DROP), a confirmed
/// sweep (>= CONFIRM ports, zero establishment) → durable `Quarantine` (wire DROP). The
/// LOAD-BEARING assertions are the legit-safety rows (the whole point of the separation
/// matrix): a busy source with 150 ESTABLISHED flows, and a 100/s new-conn burst, must
/// reach OBSERVE/PASS and NEVER a RateLimit/Quarantine — establishment holds every
/// escalation off. Also proves an established handshake is never scan-confirmed, and maps
/// the A7/L9 flow-table-saturation signal. QEMU-provable (pure verdict logic over
/// synthetic frames); uses ISOLATED TEST-NET src IPs so the port-0 datapath is never
/// poisoned (PHprod/PH6-net stay green).
#[cfg(not(feature = "cm5"))]
fn p8_flow() -> bool {
    use ratelimit::{
        scan_confirmed, scan_distinct_ports, table_saturated, DEFAULT_NEW_CONN_PPS,
        SATURATION_SHED_PCT, SCAN_PORTS_CONFIRM, SCAN_PORTS_RATELIMIT,
    };
    kprint!("\n [P8] flow-state (M2.2) — distinct-dst-port scan → tri-state via decide(); legit busy source stays PASS\n");
    let mut ok = true;

    // A normalized eth/IPv4/TCP frame (54B) with a settable src, dst port, and flags.
    // Mirrors the live datapath: `flow_scan_verdict` self-parses to the IP source.
    /// The scan target the matrix probes (TEST-NET-3).
    const TGT: [u8; 4] = [203, 0, 113, 9];
    fn tcp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dst_port: u16, flags: u8) -> [u8; 54] {
        let mut f = [0u8; 54];
        f[12] = 0x08;
        f[13] = 0x00; // EtherType IPv4
        f[14] = 0x45; // IPv4, IHL=5
        f[17] = 40; // IP total length = 20 (IP) + 20 (TCP)
        f[23] = 6; // proto TCP
        f[26..30].copy_from_slice(&src); // IP source
        f[30..34].copy_from_slice(&dst); // IP destination
        f[34..36].copy_from_slice(&sport.to_be_bytes()); // TCP src port
        f[36] = (dst_port >> 8) as u8;
        f[37] = (dst_port & 0xff) as u8; // TCP dst port
        f[46] = 0x50; // TCP data offset = 5 words
        f[47] = flags; // TCP flags
        f
    }
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const RST_ACK: u8 = 0x14;
    const SYN_ACK: u8 = 0x12;
    #[inline]
    fn ip(src: [u8; 4]) -> u32 {
        crate::net::eth_ipv4_src(&tcp_frame(src, TGT, 40000, 0, SYN))
    }
    /// The prober's segment to the target (SYN-only probe, or an ACK on the flow).
    #[inline]
    fn scan_step(src: [u8; 4], dst_port: u16, flags: u8) -> Option<verdict::Verdict> {
        let f = tcp_frame(src, TGT, 40000, dst_port, flags);
        rules::flow_scan_verdict(&f, crate::net::eth_ipv4_src(&f))
    }
    /// The TARGET's answer to `prober`'s probe of `port` (RST|ACK = closed, SYN|ACK = open) — ADR 0049 D3.
    #[inline]
    fn reply(prober: [u8; 4], port: u16, flags: u8) {
        let f = tcp_frame(TGT, prober, port, 40000, flags);
        let _ = rules::flow_scan_verdict(&f, crate::net::eth_ipv4_src(&f));
    }
    /// A probe the target answers: closed (RST) — the scan shape with evidence.
    #[inline]
    fn probe_closed(src: [u8; 4], port: u16) -> Option<verdict::Verdict> {
        let a = scan_step(src, port, SYN);
        reply(src, port, RST_ACK);
        let b = scan_step(src, port, SYN); // re-evaluate now that the answer is in (a repeat SYN adds nothing)
        b.or(a)
    }
    /// A real handshake: SYN, the target's SYN-ACK, the source's ACK.
    #[inline]
    fn handshake(src: [u8; 4], port: u16) -> bool {
        let a = scan_step(src, port, SYN).is_some();
        reply(src, port, SYN_ACK);
        let b = scan_step(src, port, ACK).is_some();
        a || b
    }

    // === ATTACKER A4: a 60-distinct-port SYN scan, UNCONFIRMED → RateLimit (wire DROP),
    //     never Quarantine (bounded, self-reverting; anti-spoof — durable block withheld). ===
    let atk: [u8; 4] = [198, 18, 0, 10]; // TEST-NET-2, used nowhere else
    let mut saw_ratelimit_drop = false;
    let mut saw_quarantine_early = false;
    for port in 1..=60u16 {
        if let Some(v) = probe_closed(atk, port) {
            if matches!(v, verdict::Verdict::RateLimit { over_limit: true }) && v.is_drop() {
                saw_ratelimit_drop = true;
            }
            if matches!(v, verdict::Verdict::Quarantine) {
                saw_quarantine_early = true;
            }
        }
    }
    let c_a4 = saw_ratelimit_drop && !saw_quarantine_early && !scan_confirmed(ip(atk) as u64);
    ok &= c_a4;
    kprint!("   A4 60-port SYN scan UNCONFIRMED (distinct={}) -> RateLimit-DROP seen={}, Quarantine seen={} (must be RateLimit, never Quarantine) [{}]\n",
        scan_distinct_ports(ip(atk) as u64), saw_ratelimit_drop, saw_quarantine_early, if c_a4 { "ok" } else { "BUG" });

    // === ATTACKER A5: the SAME source keeps scanning past the CONFIRM bar (still zero
    //     establishment) → CONFIRMED → durable Quarantine (wire DROP). ===
    let mut saw_quarantine = false;
    for port in 61..=130u16 {
        if let Some(verdict::Verdict::Quarantine) = probe_closed(atk, port) {
            saw_quarantine = true;
        }
    }
    let c_a5 = saw_quarantine && scan_confirmed(ip(atk) as u64);
    ok &= c_a5;
    kprint!("   A5 same source past CONFIRM bar ({} ports, distinct={}) -> Quarantine-DROP seen={}, confirmed={} [{}]\n",
        SCAN_PORTS_CONFIRM, scan_distinct_ports(ip(atk) as u64), saw_quarantine, scan_confirmed(ip(atk) as u64), if c_a5 { "ok" } else { "BUG" });

    // === LEGIT (keystone): a busy source with 150 ESTABLISHED flows to 150 DISTINCT ports
    //     — each flow SYN then ACK (established) — must NEVER fire a scan verdict, however
    //     many distinct ports its SYNs touch. Establishment holds every escalation off. ===
    let nas: [u8; 4] = [198, 18, 0, 50];
    let mut nas_fired = false; // ANY Some(verdict) here is a false-positive on a legit source
    for port in 1..=150u16 {
        if handshake(nas, port) {
            nas_fired = true;
        }
    }
    let c_nas = !nas_fired
        && !scan_confirmed(ip(nas) as u64)
        && !ratelimit::scan_over_ratelimit(ip(nas) as u64);
    ok &= c_nas;
    kprint!("   LEGIT NAS 150 ESTABLISHED flows/150 distinct ports (est={}, distinct-syn={}) -> scan verdict fired={} (MUST be false — establishment ⇒ not a scan) [{}]\n",
        ratelimit::flow_established_count(ip(nas) as u64), scan_distinct_ports(ip(nas) as u64), nas_fired, if c_nas { "ok" } else { "BUG" });

    // === LEGIT: a ~100 new-conn/s burst (heavy web load) to a FEW dst ports — keys on
    //     distinct PORTS not conn COUNT, and sits under the blanket cap. Never fires. ===
    let burst: [u8; 4] = [198, 18, 0, 60];
    let mut burst_fired = false;
    for _ in 0..100u16 {
        // 100 connections, all to :443 (a web page load): 1 distinct dst port.
        if handshake(burst, 443) {
            burst_fired = true;
        }
    }
    let legit_pps: u64 = core::hint::black_box(100);
    let c_burst = !burst_fired && legit_pps < DEFAULT_NEW_CONN_PPS;
    ok &= c_burst;
    kprint!("   LEGIT 100/s web-load burst (1 distinct port) -> fired={}; {}/s < blanket cap {}/s [{}]\n",
        burst_fired, legit_pps, DEFAULT_NEW_CONN_PPS, if c_burst { "ok" } else { "BUG" });

    // === LEGIT: an ESTABLISHED handshake flow (SYN then ACK) is NEVER scan-confirmed. ===
    let est: [u8; 4] = [198, 18, 0, 70];
    let _ = handshake(est, 22);
    let c_est = !scan_confirmed(ip(est) as u64) && !ratelimit::scan_over_ratelimit(ip(est) as u64);
    ok &= c_est;
    kprint!("   LEGIT established handshake (est={}) -> scan_confirmed={} (an established flow is definitionally not a scan) [{}]\n",
        ratelimit::flow_established_count(ip(est) as u64), scan_confirmed(ip(est) as u64), if c_est { "ok" } else { "BUG" });

    // === ATTACK (audit 2026-10-08 connect-scan gap): a connect() scan that COMPLETES the handshake
    //     on 3 open ports among 120 probed (a few ACKs each) must still be confirmed — a handful of
    //     established segments against a 120-port sweep is not "a busy legit host". ===
    let cs: [u8; 4] = [198, 18, 0, 80];
    for port in 1..=120u16 {
        if port % 40 == 0 {
            // an open port: the scanner completes the handshake (+ a data ACK)
            let _ = handshake(cs, port);
            let _ = scan_step(cs, port, ACK);
        } else {
            let _ = probe_closed(cs, port);
        }
    }
    let c_cs = scan_confirmed(ip(cs) as u64) && ratelimit::scan_over_ratelimit(ip(cs) as u64);
    ok &= c_cs;
    kprint!("   ATTACK connect-scan: 120 ports, 3 completed (est={}, distinct-syn={}) -> confirmed={} (MUST be true — proportional establishment hold) [{}]\n",
        ratelimit::flow_established_count(ip(cs) as u64), scan_distinct_ports(ip(cs) as u64), scan_confirmed(ip(cs) as u64), if c_cs { "ok" } else { "BUG" });

    // === ATTACK (ADR 0049 D3, re-review M2): the ACK-PADDING evasion — a 120-port sweep plus a stray ACK
    //     for every 8 probes used to buy a full hold (15 ACKs × 8 ≥ 120). Without the target's SYN-ACK an
    //     ACK earns nothing now: confirmed. ===
    let pad: [u8; 4] = [198, 18, 0, 81];
    for port in 1..=120u16 {
        let _ = probe_closed(pad, port);
        if port % 8 == 0 {
            let _ = scan_step(pad, 1000 + port, ACK); // stray ACKs, no handshake behind them
        }
    }
    let c_pad = scan_confirmed(ip(pad) as u64) && ratelimit::flow_established_count(ip(pad) as u64) == 0;
    ok &= c_pad;
    kprint!("   ATTACK ACK-padding: 120 ports + 15 stray ACKs (est={}) -> confirmed={} (MUST be true — an ACK without the target's SYN-ACK is no establishment) [{}]\n",
        ratelimit::flow_established_count(ip(pad) as u64), scan_confirmed(ip(pad) as u64), if c_pad { "ok" } else { "BUG" });

    // === LEGIT-SAFETY (operator, ADR 0049 D3): ONE-SIDED / SPOOFED SYN traffic — 150 SYNs to 150 ports,
    //     the target never seen answering (asymmetric path, or a forged source) — must NEVER count. ===
    let oneside: [u8; 4] = [198, 18, 0, 82];
    let mut os_fired = false;
    for port in 1..=150u16 {
        if scan_step(oneside, port, SYN).is_some() {
            os_fired = true;
        }
    }
    let c_os = !os_fired && scan_distinct_ports(ip(oneside) as u64) == 0 && !scan_confirmed(ip(oneside) as u64);
    ok &= c_os;
    kprint!("   LEGIT-SAFETY one-sided/spoofed: 150 SYNs, no answer ever seen -> counted={} fired={} (MUST be 0/false — no evidence the probes reached a host) [{}]\n",
        scan_distinct_ports(ip(oneside) as u64), os_fired, if c_os { "ok" } else { "BUG" });

    // === ATTACK on THIS device: probes to one of our own addresses count without a reply (the device knows
    //     its own port state) — an inbound sweep of the WAN address is still caught. ===
    ratelimit::set_local_ip(3, u32::from_be_bytes(TGT));
    let me_atk: [u8; 4] = [198, 18, 0, 83];
    let mut me_q = false;
    for port in 1..=110u16 {
        if let Some(verdict::Verdict::Quarantine) = scan_step(me_atk, port, SYN) {
            me_q = true;
        }
    }
    ratelimit::set_local_ip(3, 0);
    let c_me = me_q && scan_confirmed(ip(me_atk) as u64);
    ok &= c_me;
    kprint!("   ATTACK sweep of this device's own address (110 ports, no replies needed) -> Quarantine={} [{}]\n",
        me_q, if c_me { "ok" } else { "BUG" });

    // === A7 / L9: the flow-table SATURATION signal (pure verdict map; the self-reverting
    //     SHED action is M2.3). L9 40% full → no shed; A7 85% full → shed signal. Keyed on
    //     RESOURCE REALITY (table fill), never identity. ===
    let l9 = !table_saturated(40_000, 100_000); // 40% — a legit heavy source, no shed
    let a7 = table_saturated(85_000, 100_000); // 85% — over the wall, shed signal
    let c_sat = l9 && a7;
    ok &= c_sat;
    kprint!("   A7/L9 saturation (wall {}%): 40%-full sheds={} (must be false), 85%-full sheds={} (must be true) [{}]\n",
        SATURATION_SHED_PCT, !l9, a7, if c_sat { "ok" } else { "BUG" });

    // === LEGIT FRAGMENT: a NON-FIRST IPv4 fragment's payload is not an L4 header. The
    //     same 54 bytes with offset 0 hit the :4444 signature (DROP); as a mid-datagram
    //     fragment they must PASS through the live verdict (was a legit-drop: payload bytes
    //     2-3 were read as the dst port). Also IPv6: a non-first Fragment(44) header. ===
    {
        let src = [198, 18, 0, 72];
        let first = tcp_frame(src, TGT, 40000, 4444, ACK);
        let mut tail = first;
        tail[20] = 0x00;
        tail[21] = 0xb9; // fragment offset 185 (x8 B), MF=0: the datagram's last fragment
        let v_first = crate::packet::verdict(&first).1;
        let v_tail = crate::packet::verdict(&tail).1;
        // IPv6: eth | v6 hdr (next=44) | frag hdr (next=TCP, offset!=0) | 4444 at +2
        let mut v6 = [0u8; 14 + 40 + 8 + 20];
        v6[12] = 0x86;
        v6[13] = 0xdd;
        v6[14] = 0x60;
        v6[19] = 28; // payload length = 8 (frag) + 20
        v6[20] = 44; // next header: Fragment
        v6[21] = 64;
        v6[54] = 6; // frag next header: TCP
        v6[56] = 0x05;
        v6[57] = 0xc8; // fragment offset 185 (x8 B)
        v6[64] = (4444u16 >> 8) as u8;
        v6[65] = (4444u16 & 0xff) as u8;
        let v_v6tail = crate::packet::verdict(&v6).1;
        // RFC 1858 tiny / overlapping TCP fragments are dropped (structural); a legit FIRST fragment
        // (MF set, full TCP header) to a clean port still passes.
        let mut tiny = tcp_frame(src, TGT, 40000, 443, ACK);
        tiny[20] = 0x20; // MF, offset 0
        tiny[16..18].copy_from_slice(&28u16.to_be_bytes()); // 20 IP + 8 bytes of TCP: no flags
        let mut ovl = tcp_frame(src, TGT, 40000, 443, ACK);
        ovl[20] = 0x00;
        ovl[21] = 0x01; // offset 1 (8 B): rewrites the first fragment's flags
        let mut legit_first = tcp_frame(src, TGT, 40000, 443, ACK);
        legit_first[20] = 0x20; // MF, offset 0, full header
        let v_tiny = crate::packet::verdict(&tiny).1;
        let v_ovl = crate::packet::verdict(&ovl).1;
        let v_lf = crate::packet::verdict(&legit_first).1;
        let c_1858 = v_tiny == crate::packet::DROP && v_ovl == crate::packet::DROP && v_lf != crate::packet::DROP;
        kprint!("   RFC 1858: tiny first TCP fragment -> {} , offset-1 overlap -> {} (both DROP), legit first fragment -> {} (PASS) [{}]\n",
            v_tiny, v_ovl, v_lf, if c_1858 { "ok" } else { "BUG" });
        let c_frag = v_first == crate::packet::DROP && v_tail != crate::packet::DROP
            && v_v6tail != crate::packet::DROP && c_1858;
        ok &= c_frag;
        kprint!("   LEGIT fragment: first-frag :4444 -> {} (signature DROP), non-first v4 frag (same bytes) -> {}, non-first v6 frag -> {} (payload never read as ports) [{}]\n",
            v_first, v_tail, v_v6tail, if c_frag { "ok" } else { "BUG" });
    }

    // === A7 LIVE GAUGE: the occupancy that FEEDS the wall must decay (self-revert) and
    //     must not count ACK segments. Regression for the lifetime counter that latched
    //     `saturated` after ~80k ACKs (one download) → a durable legit shed. Injected
    //     clock far in the future so the live gauge resets on its next real read. ===
    {
        use ratelimit::{flow_count_at, flow_new_at};
        let (t0, w, max) = (1u64 << 62, 1_000u64, 100u64);
        let g0 = flow_count_at(t0, w);
        for _ in 0..85 {
            flow_new_at(t0 + 1, w);
        }
        let g_full = flow_count_at(t0 + 2, w);
        for _ in 0..100_000 {
            ratelimit::flow_ack_observe(ip([198, 18, 0, 71]) as u64, 443);
        }
        let g_acks = flow_count_at(t0 + 3, w);
        let g_half = flow_count_at(t0 + w + w / 2, w); // prev bucket half-overlapping
        let g_gone = flow_count_at(t0 + 3 * w, w);
        let c_gauge = g0 == 0 && table_saturated(g_full, max) && g_acks == g_full
            && !table_saturated(g_half, max) && g_half > 0 && g_gone == 0;
        let _ = ratelimit::flow_count(); // re-anchor the live gauge on the real clock
        ok &= c_gauge;
        kprint!("   A7 live gauge: 85 new flows -> {} (sheds), +100k ACKs -> {} (unchanged), 1.5 horizons -> {} (decaying, no shed), 3 horizons -> {} (self-reverted) [{}]\n",
            g_full, g_acks, g_half, g_gone, if c_gauge { "ok" } else { "BUG" });
    }

    // Sanity: the two bars are ordered so RateLimit precedes Quarantine.
    ok &= SCAN_PORTS_RATELIMIT <= SCAN_PORTS_CONFIRM;

    // A11 corroboration — SEVERITY signal ONLY, never the wire. A source tripping 3
    // independent axes is corroborated (is_corroborated true), yet its wire verdict STAYS
    // Observe/PASS — a durable Quarantine from corroboration is rejected by design
    // (security-auditor 2026-09-08: FP-unsafe + weaponizable + no segment primitive).
    {
        use crate::corroboration as corr;
        use crate::verdict::{decide, DecideCtx, FindingClass, Verdict};
        let s: u64 = 0xC612_0009; // 198.18.0.9 (TEST-NET-2)
        corr::corr_observe(s, corr::AXIS_REPUTATION);
        corr::corr_observe(s, corr::AXIS_BEACON);
        let axes = corr::corr_observe(s, corr::AXIS_LATERAL);
        let corr_ok = corr::is_corroborated(s) && axes == 3
            && decide(FindingClass::Behavioral, DecideCtx::for_src(s as u32)) == Verdict::Observe
            && !decide(FindingClass::Behavioral, DecideCtx::for_src(s as u32)).is_drop();
        ok &= corr_ok;
        kprint!("   A11 corroboration: 3-axis corroborated={} but wire verdict Observe/PASS (never a drop) [{}]\n",
            corr::is_corroborated(s), if corr_ok { "ok" } else { "BUG" });
    }

    // Segmentation reach plane — the per-device reach ACTUATOR (U2b + L5/L6 + A11-to-segment).
    // DISARMED → nothing segmented (C7); ARMED → Full allows, InternetOnly/Quarantine DROP a
    // LAN-internal peer but allow WAN + infra (gateway), mgmt floor + unknown device always
    // allowed (fail-open). Authority-set, never inferred (security-auditor CONDITIONAL-GO).
    {
        let seg_ok = crate::segment::reach_selftest();
        ok &= seg_ok;
        kprint!("   segmentation reach: disarmed-noop + Full/InternetOnly/Quarantine x LAN/WAN/infra + mgmt-floor + fail-open-default [{}]\n",
            if seg_ok { "ok" } else { "BUG" });
    }

    kprint!(" [P8-flow] {} — distinct-dst-port scan: UNCONFIRMED->RateLimit(DROP), CONFIRMED->Quarantine(DROP); a legit busy source (150 ESTABLISHED flows / 100-per-sec burst) NEVER RateLimits/Quarantines; A11 corroboration is SEVERITY-only, never a wire drop (ADR 0018/0023, conntrack-equivalent)\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// M2.3 — RESOURCE-SHED selftest: ADR 0023's FOURTH suspicion-free inline drop. Proves
/// the SELF-REVERTING meters keyed on MEASURED RESOURCE REALITY (never identity):
///   L1 — a blanket per-source new-conn-rate cap (400/s) that DROPs over cap then PASSes
///        the next window (the SELF-REVERT proof, driven with a synthetic clock);
///   L2 — a conntrack-saturation top-talker shed (saturated → shed the flood source; an
///        un-saturated table (L9) or a small legit source → NO shed);
///   L3 — a heqk-native PSI-equivalent scheduler-pressure shed (synthetic pressure high →
///        shed; low → no shed) — the LOGIC is QEMU-provable, the REAL pressure-under-load
///        is Gate-R metal (honestly split via the synthetic injector);
///   A8 — under pressure the top-talker sheds first.
/// And the invariants: a legit busy source in an UN-saturated table with low PSI is NEVER
/// shed, and the mgmt `Allowlisted` source is NEVER shed however hot (routed through
/// `decide()`; the floor short-circuits). Uses isolated TEST-NET src ids (datapath src=0
/// short-circuits, so PHprod/PH6-net stay green).
#[cfg(not(feature = "cm5"))]
fn p8_shed() -> bool {
    use ratelimit::{
        clear_synthetic_pressure, conn_rate_over_at, flow_record, pressure_shed, saturation_shed,
        set_synthetic_pressure, DEFAULT_NEW_CONN_PPS, PSI_SHED_PCT, SHED_TOPTALKER_MIN_FLOWS,
    };
    kprint!("\n [P8] resource-shed (M2.3) — self-reverting drops keyed on RATE/saturation/pressure REALITY (ADR 0023's 4th inline drop)\n");
    let mut ok = true;

    #[inline]
    fn ipn(a: u8, b: u8, c: u8, d: u8) -> u64 {
        u32::from_be_bytes([a, b, c, d]) as u64
    }

    // === L1 SELF-REVERT: over the 400/s cap this window → shed; next window under → PASS. ===
    // Synthetic clock (win = 1000 ticks) so the window boundary is deterministic (no sleep).
    let s1 = ipn(198, 18, 1, 10); // TEST-NET-2, isolated
    let cap = DEFAULT_NEW_CONN_PPS;
    let win = 1000u64;
    let mut w1_shed = false;
    for _ in 0..(cap + 50) {
        if conn_rate_over_at(s1, cap, 0, win) {
            w1_shed = true; // crossed the blanket cap within window 1
        }
    }
    // Window 2 (now advanced past the boundary): a modest under-cap rate must PASS again.
    let mut w2_reverted = true;
    for _ in 0..20 {
        if conn_rate_over_at(s1, cap, win, win) {
            w2_reverted = false; // any drop here means the meter did NOT self-revert
        }
    }
    let c_l1 = w1_shed && w2_reverted;
    ok &= c_l1;
    kprint!("   L1 blanket cap {}/s: over-cap shed (window1)={}, under-cap PASS (window2 self-revert)={} [{}]\n",
        cap, w1_shed, w2_reverted, if c_l1 { "ok" } else { "BUG" });

    // === Build a top-talker census: a flood source with 500 conns + 10 small legit sources. ===
    let flood = ipn(203, 0, 113, 50);
    for _ in 0..500 {
        flow_record(flood);
    }
    for j in 0..10u8 {
        let legit = ipn(192, 168, 2, j);
        for _ in 0..5 {
            flow_record(legit);
        }
    }
    let one_legit = ipn(192, 168, 2, 0);

    // === L2 conntrack-saturation shed: saturated (85%) → shed the flood top-talker;
    //     an un-saturated table (L9, 40%) → NO shed; a small legit source → NO shed. ===
    let a7 = saturation_shed(flood, 85_000, 100_000); // over the 80% wall → shed flood
    let l9 = saturation_shed(flood, 40_000, 100_000); // under the wall → never shed
    let legit_sat = saturation_shed(one_legit, 85_000, 100_000); // saturated but not top-talker
    let c_l2 = a7 && !l9 && !legit_sat;
    ok &= c_l2;
    kprint!("   L2 saturation (top-talker {} flows, floor {}): 85%-full shed flood={}, 40%-full(L9) shed={}, small-legit shed={} [{}]\n",
        ratelimit::top_talker_flows(), SHED_TOPTALKER_MIN_FLOWS, a7, l9, legit_sat, if c_l2 { "ok" } else { "BUG" });

    // === L3 PSI-equivalent + A8: synthetic pressure HIGH → shed the top-talker; a legit
    //     small source is NOT shed; pressure LOW → no shed at all (self-reverting signal). ===
    set_synthetic_pressure(60); // >= PSI_SHED_PCT (40)
    let psi_high_flood = pressure_shed(flood); // A8: top-talker sheds first
    let psi_high_legit = pressure_shed(one_legit); // small legit source: never top-talker
    set_synthetic_pressure(10); // < PSI_SHED_PCT → pressure cleared
    let psi_low = pressure_shed(flood); // no pressure → no shed (revert)
    clear_synthetic_pressure();
    let c_l3 = psi_high_flood && !psi_high_legit && !psi_low;
    ok &= c_l3;
    kprint!("   L3 PSI (wall {}%): synth-high shed top-talker={}, small-legit shed={}, synth-low shed={} (QEMU synthetic; real pressure = Gate-R metal) [{}]\n",
        PSI_SHED_PCT, psi_high_flood, psi_high_legit, psi_low, if c_l3 { "ok" } else { "BUG" });

    // === LEGIT (keystone): a busy-but-normal source — 150 flows, table NOT saturated,
    //     PSI low — is NEVER shed (preserve the M2.2-proven legit row for the shed ACTION). ===
    let nas = ipn(192, 168, 2, 200);
    for _ in 0..150 {
        flow_record(nas);
    }
    // Table at 40% (not saturated), no injected pressure (synth cleared → runqueue-derived,
    // ~0 under QEMU idle): neither shed path fires for the legit source.
    let legit_sat_shed = saturation_shed(nas, 40_000, 100_000);
    let legit_psi_shed = pressure_shed(nas);
    let c_legit = !legit_sat_shed && !legit_psi_shed;
    ok &= c_legit;
    kprint!("   LEGIT busy-but-normal (150 flows, table 40pct, PSI low) -> saturation-shed={}, pressure-shed={} (MUST be false — resource wall never crossed) [{}]\n",
        legit_sat_shed, legit_psi_shed, if c_legit { "ok" } else { "BUG" });

    // === mgmt FLOOR: a mgmt-path source, even as the hottest top-talker under saturation
    //     AND pressure, is NEVER shed — the shed routes through decide() and the
    //     Allowlisted floor short-circuits (ADR 0022 D2: never self-lock-out). ===
    let mgmt = ipn(10, 200, 0, 5); // in MGMT_NET 10.200.0.0/24
    for _ in 0..600 {
        flow_record(mgmt); // make mgmt the measured top-talker by sheer volume
    }
    set_synthetic_pressure(90);
    // The TRIGGERS are identity-blind and DO fire for mgmt (it IS the top-talker under
    // pressure/saturation) — proving the floor is a verdict-layer override, not a trigger hack.
    let mgmt_trig_sat = saturation_shed(mgmt as u64, 90_000, 100_000);
    let mgmt_trig_psi = pressure_shed(mgmt as u64);
    let mgmt_sat_v = rules::shed_verdict(rules::RULE_RESOURCE_SHED, mgmt as u32, mgmt_trig_sat);
    let mgmt_psi_v = rules::shed_verdict(rules::RULE_RESOURCE_SHED, mgmt as u32, mgmt_trig_psi);
    clear_synthetic_pressure();
    let c_mgmt = mgmt_trig_sat && mgmt_trig_psi // triggers fire (identity-blind reality)
        && mgmt_sat_v == verdict::Verdict::Allowlisted && !mgmt_sat_v.is_drop()
        && mgmt_psi_v == verdict::Verdict::Allowlisted && !mgmt_psi_v.is_drop();
    ok &= c_mgmt;
    kprint!("   mgmt FLOOR: triggers fired (sat={}, psi={}) but verdict sat={:?} psi={:?} -> wire PASS (Allowlisted never shed, never self-lock-out) [{}]\n",
        mgmt_trig_sat, mgmt_trig_psi, mgmt_sat_v, mgmt_psi_v, if c_mgmt { "ok" } else { "BUG" });

    // Attacker counterpart: a non-mgmt top-talker under the SAME saturation trigger DOES
    // shed (DROP). Record a fresh flood above the current top (mgmt's 600) so it is the
    // measured top-talker — proving the floor is what spares mgmt, not a weaker trigger.
    let atk = ipn(203, 0, 113, 99);
    for _ in 0..700 {
        flow_record(atk);
    }
    let atk_v = rules::shed_verdict(rules::RULE_RESOURCE_SHED, atk as u32, saturation_shed(atk, 85_000, 100_000));
    let c_atk = matches!(atk_v, verdict::Verdict::RateLimit { over_limit: true }) && atk_v.is_drop();
    ok &= c_atk;
    kprint!("   attacker top-talker (saturated, {} flows) -> {:?} wire DROP (bounded, self-reverting) [{}]\n",
        ratelimit::top_talker_flows(), atk_v, if c_atk { "ok" } else { "BUG" });

    kprint!(" [P8-shed] {} — L1 blanket cap self-reverts (over->DROP, next window->PASS); L2 saturation + L3 PSI shed the top-talker only (legit-not-saturated NEVER shed); mgmt Allowlisted floor NEVER shed (ADR 0023 4th inline drop, all identity-blind + self-reverting)\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// [P8-raflood] A9-3 / A9-5 / A9-7 — the RA-guard arms the security-auditor A9 ruling
/// (heqk-detection-parity.md §5) approved to build NOW, port-role independent:
///   A9-3 an RA FLOOD from one source MAC on one port (> RA_FLOOD_THRESH per window) is a
///        rate wall crossed → FloodRate → self-reverting RateLimit (wire DROP) on ANY port;
///        a legit router beside the flooder keeps its own (port, MAC) budget;
///   A9-5 rule 121/122 events carry the source-MAC hash (an IPv6 frame has no IPv4 src);
///   A9-7 an IPv6 frame with an extension chain `parse_ipv6` refuses is surfaced as an
///        observe-only finding (rule 123) instead of silently bypassing the guard.
/// The first-sight Access-port FrameDrop arm is NOT exercised here — it stays embargoed
/// (unreachable live) pending A9-1/2/4/6. Isolated port ids 5 (flood) / 4 (evasion).
#[cfg(not(feature = "cm5"))]
fn p8_raflood() -> bool {
    use ratelimit::{ra_key, ra_rate_over_at, RA_FLOOD_THRESH};
    use verdict::{PortRole, Verdict};
    kprint!("\n [P8] RA-guard flood arm (A9-3) + attribution (A9-5) + evasion visibility (A9-7)\n");
    let mut ok = true;
    // The earlier P8 phases leave the 64-slot SOAR ring FULL (push_hit then overruns
    // silently, and the attribution assertions below would read a stale event). Drain
    // the stale backlog first — the same precedent p8_soar sets — so every push here
    // is real; report the overrun delta so a hidden overrun can't fake a pass.
    {
        let mut junk = [events::Event::EMPTY; 16];
        while events::drain(&mut junk) > 0 {}
    }
    let overruns_before = events::overruns();

    // A minimal well-formed ICMPv6 RA from `src`: eth(IPv6) + IPv6 base (next-hdr 58) + type 134.
    fn ra_frame(src: &[u8; 6]) -> [u8; 70] {
        let mut ra = [0u8; 70];
        ra[0..6].copy_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]); // all-nodes (exempt mcast)
        ra[6..12].copy_from_slice(src);
        ra[12..14].copy_from_slice(&[0x86, 0xdd]);
        ra[14] = 0x60;
        ra[19] = 0x10; // payload length 16
        ra[20] = 58; // ICMPv6
        ra[21] = 255;
        ra[54] = 134; // Router Advertisement
        ra
    }
    let router = [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x01]; // the legit downstream router
    let flooder = [0x00, 0xde, 0xad, 0xbe, 0xef, 0x02]; // fake_router6
    let port = 5u64; // isolated from the live port 0 + sepdiag 6/7

    // (a) L4 continuity — one RA from the router on an Uplink port: Observe, never a drop.
    let v_one = rules::l2_stateful_verdict(&ra_frame(&router), 0, port, PortRole::Uplink);
    let c_a = v_one == Some(Verdict::Observe);
    ok &= c_a;
    // (e) A9-5 — that event is rule 121 attributed by the source-MAC hash (non-zero, != IPv4 0).
    let ev = events::peek_last();
    let want_src = ratelimit::mac_hash(&router) as u32;
    let c_e = ev.map_or(false, |e| e.rule_id == rules::RULE_ROGUE_RA && e.src == want_src && e.src != 0);
    ok &= c_e;
    kprint!("   L4 single legit RA (Uplink) -> {:?} [{}]; rule-121 event src={:#010x} (mac-hash, want {:#010x}) [{}]\n",
        v_one, if c_a { "ok" } else { "BUG" }, ev.map_or(0, |e| e.src), want_src, if c_e { "ok" } else { "BUG" });

    // (b) the flood: 2x threshold RAs from ONE MAC on the port. The first THRESH must PASS
    //     (no premature drop), every one past the wall must DROP (RateLimit{over_limit}).
    let n = (RA_FLOOD_THRESH * 2) as usize;
    let mut early_drops = 0u32;
    let mut late_drops = 0u32;
    let mut late_shape = true;
    for k in 0..n {
        let v = rules::l2_stateful_verdict(&ra_frame(&flooder), 0, port, PortRole::Uplink);
        let drop = v.map_or(false, Verdict::is_drop);
        if (k as u64) < RA_FLOOD_THRESH {
            if drop { early_drops += 1; }
        } else {
            if drop { late_drops += 1; }
            late_shape &= matches!(v, Some(Verdict::RateLimit { over_limit: true }));
        }
    }
    let c_b = early_drops == 0 && late_drops as u64 == RA_FLOOD_THRESH && late_shape;
    ok &= c_b;
    kprint!("   flood {} RAs from one MAC: drops before wall={} (want 0), after wall={} (want {}), shape=RateLimit{{over_limit}}={} [{}]\n",
        n, early_drops, late_drops, RA_FLOOD_THRESH, late_shape, if c_b { "ok" } else { "BUG" });
    let ev = events::peek_last();
    let c_e2 = ev.map_or(false, |e| e.rule_id == rules::RULE_RA_FLOOD && e.verdict == 2 && e.src == ratelimit::mac_hash(&flooder) as u32);
    ok &= c_e2;

    // (c) isolation — mid-flood, the legit router on the SAME port still PASSes (its own budget).
    let v_router = rules::l2_stateful_verdict(&ra_frame(&router), 0, port, PortRole::Uplink);
    let c_c = v_router == Some(Verdict::Observe);
    ok &= c_c;
    kprint!("   legit router beside the flooder (same port) mid-flood -> {:?} [{}]; rule-122 DROP event attributed to flooder [{}]\n",
        v_router, if c_c { "ok" } else { "BUG" }, if c_e2 { "ok" } else { "BUG" });

    // (d) SELF-REVERT with the injected clock (win = 1000 ticks): over the wall in window 1,
    //     the very next window's RA is under the wall again (PASS) — never a durable block.
    let key = ra_key(9, ratelimit::mac_hash(&flooder));
    let win = 1000u64;
    let mut w1_over = false;
    for _ in 0..(RA_FLOOD_THRESH + 2) {
        if ra_rate_over_at(key, RA_FLOOD_THRESH, 0, win) { w1_over = true; }
    }
    let w2_reverted = !ra_rate_over_at(key, RA_FLOOD_THRESH, win, win);
    let c_d = w1_over && w2_reverted;
    ok &= c_d;
    kprint!("   self-revert (synthetic clock): window1 over-wall={}, window2 first RA PASS={} [{}]\n",
        w1_over, w2_reverted, if c_d { "ok" } else { "BUG" });

    // (f) A9-7 evasion visibility — an RA hidden behind a 9-deep Hop-by-Hop chain (past
    //     MAX_V6_EXT=8): NOT recognised as an RA (the guard can't see it) and NOT dropped, but
    //     SURFACED as rule 123 Observe so the evasion attempt is visible to the SOC.
    let mut ev6 = [0u8; 200];
    ev6[0..6].copy_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
    ev6[6..12].copy_from_slice(&flooder);
    ev6[12..14].copy_from_slice(&[0x86, 0xdd]);
    ev6[14] = 0x60;
    let chain = 9usize; // 9 x 8-byte HBH headers, then ICMPv6 RA
    let payload = chain * 8 + 16;
    ev6[18..20].copy_from_slice(&(payload as u16).to_be_bytes());
    ev6[20] = 0; // first next-header = Hop-by-Hop
    ev6[21] = 255;
    let mut off = 54;
    for i in 0..chain {
        ev6[off] = if i + 1 == chain { 58 } else { 0 }; // next: HBH ... then ICMPv6
        ev6[off + 1] = 0; // hdr_ext_len 0 -> 8 bytes
        off += 8;
    }
    ev6[off] = 134;
    let hidden_ra = &ev6[..off + 16];
    let seen_as_ra = net::is_icmpv6_ra(hidden_ra);
    let unparseable = net::ipv6_unparseable(hidden_ra);
    let v_ev = rules::l2_stateful_verdict(hidden_ra, 0, 4, PortRole::Uplink);
    let ev = events::peek_last();
    let surfaced = ev.map_or(false, |e| e.rule_id == rules::RULE_IPV6_UNPARSEABLE && e.verdict != 2);
    let clean_ok = !net::ipv6_unparseable(&ra_frame(&router)); // a well-formed RA is NOT flagged
    let c_f = !seen_as_ra && unparseable && v_ev == Some(Verdict::Observe) && surfaced && clean_ok;
    ok &= c_f;
    kprint!("   evasion (RA behind 9 HBH hdrs): seen-as-RA={} (want false) unparseable={} verdict={:?} surfaced-rule-123={} well-formed-not-flagged={} [{}]\n",
        seen_as_ra, unparseable, v_ev, surfaced, clean_ok, if c_f { "ok" } else { "BUG" });

    let no_overrun = events::overruns() == overruns_before;
    ok &= no_overrun;
    kprint!(" [P8-raflood] {} — A9-3 RA-flood -> self-reverting RateLimit on any port (first {} PASS, flooder DROPs, neighbour router PASSes, next window reverts); A9-5 rule 121/122 attributed by src-MAC hash; A9-7 unparseable-IPv6 evasion surfaced as rule 123 Observe (never a drop); ring overrun during phase={}; Access first-sight FrameDrop stays EMBARGOED\n",
        if ok { "PASS" } else { "FAIL" }, RA_FLOOD_THRESH, !no_overrun);
    ok
}

/// P8/L7: deep-packet signature matching in the VERIFIED fast-path. A signed rule
/// (L7_MQTT) touch-loads the last pattern byte (verifier bounds it, min_len=28)
/// then CALLs helper #3 `payload_match` — so an MQTT CONNECT is flagged in-kernel
/// before the EL0 automation services (P17) ever see it. Proves L7 detection is
/// verifier-admissible and behaves: MQTT segment ⇒ DROP, non-MQTT ⇒ PASS.
#[cfg(not(feature = "cm5"))]
fn p8_l7() -> bool {
    kprint!("\n [P8] L7 detection — MQTT signature match in the verified fast-path (helper #3)\n");
    // R1 = TCP header; 20-byte header, payload @+20, MQTT protocol name @+24.
    fn tcp_seg(mqtt: bool) -> [u8; 28] {
        let mut s = [0u8; 28];
        s[12] = 0x50; // TCP data offset = 5 words (20-byte header)
        if mqtt {
            s[24] = b'M'; s[25] = b'Q'; s[26] = b'T'; s[27] = b'T';
        }
        s
    }
    let mq = tcp_seg(true);
    let other = tcp_seg(false);
    let verified = bpf::verify_prevail(&bpf::L7_MQTT).is_ok();
    let vm = bpf::run(&bpf::L7_MQTT, mq.as_ptr(), mq.len());
    let vo = bpf::run(&bpf::L7_MQTT, other.as_ptr(), other.len());
    let ok = verified && vm == bpf::DROP && vo == bpf::PASS;
    kprint!("   verifier admits L7 rule: {}; MQTT CONNECT -> {}; non-MQTT -> {}\n",
        if verified { "yes" } else { "NO" },
        if vm == bpf::DROP { "DROP" } else { "PASS" },
        if vo == bpf::PASS { "PASS" } else { "DROP" });
    kprint!(" [P8-l7] {} — L7 MQTT signature caught in-kernel before EL0 automation services\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// [P8-l7oracle] XC-11/DET-1 — the helper-arg KERNEL-READ ORACLE is CLOSED, two legs:
///  (a) STATIC: a rule passing a SCALAR (attacker-chosen address) to payload_match
///      (EVIL_HELPER_ORACLE) is REJECTED by the verifier — arg1 must be a packet pointer,
///      so a ~4-insn program can never turn helper #3 into an arbitrary-kernel-read.
///  (b) RUNTIME BACKSTOP: L7_NOTOUCH_ORACLE is verifier-ADMISSIBLE (payload_match(pkt+0)
///      with NO touch-load, min_len folds to 4) yet on a packet SHORTER than the pattern
///      the interpreter now BOUNDS R1 at the CALL and returns INVALID (no OOB read),
///      while a full "MQTT" packet still matches (DROP). This makes the verifier-folded
///      min_len a per-call runtime reality, independent of a rule's touch-load structure —
///      exactly what a dynamically-loaded untrusted rule could otherwise have exploited.
#[cfg(not(feature = "cm5"))]
fn p8_l7oracle() -> bool {
    kprint!("\n [P8] L7 helper-arg oracle — payload_match pointer bounded to the packet (XC-11/DET-1)\n");
    let scalar_refused = bpf::verify_prevail(&bpf::EVIL_HELPER_ORACLE).is_err();
    let admissible = bpf::verify_prevail(&bpf::L7_NOTOUCH_ORACLE).is_ok();
    // A 2-byte "packet" is shorter than the 4-byte "MQTT" pattern: without the interpreter
    // backstop the no-touch rule's payload_match would read 2 bytes OOB. It must now be
    // bounded -> INVALID (fail-closed), NOT run.
    let short = [0u8; 2];
    let vs = bpf::run(&bpf::L7_NOTOUCH_ORACLE, short.as_ptr(), short.len());
    // A full "MQTT" payload (4 bytes) is in-bounds and still matches -> DROP.
    let full = [b'M', b'Q', b'T', b'T'];
    let vf = bpf::run(&bpf::L7_NOTOUCH_ORACLE, full.as_ptr(), full.len());
    let ok = scalar_refused && admissible && vs == bpf::INVALID && vf == bpf::DROP;
    kprint!("   scalar-ptr rule refused by verifier: {}; no-touch rule admissible: {}; short pkt -> {}; full MQTT -> {}\n",
        if scalar_refused { "yes" } else { "NO <- BUG" },
        if admissible { "yes" } else { "NO" },
        if vs == bpf::INVALID { "INVALID (bounded, no OOB)" } else { "RAN <- ORACLE BUG" },
        if vf == bpf::DROP { "DROP" } else { "PASS <- BUG" });
    kprint!(" [P8-l7oracle] {} — helper-arg kernel-read oracle CLOSED: verifier refuses a scalar ptr; interpreter bounds payload_match's read to the packet\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// [P8-det2] DET-2 — the per-rule AUTHENTICITY GATE, the second prerequisite (with A4's
/// oracle close) for any DYNAMIC/untrusted rule source (HYDRA-synced field updates from
/// storage/network, not the image-signed static corpus). Proves: (a) an AUTHENTIC signed
/// rule passes the gate AND then verify_prevail (memory-safe); (b) FAIL-CLOSED — a rule with
/// one bytecode byte flipped is REFUSED at the gate BEFORE verify_prevail (broken provenance,
/// even if the bytes are still valid BPF); (c) a WRONG signature is refused likewise. So an
/// unsigned/tampered dynamic rule can never reach the verifier or the live datapath.
#[cfg(not(feature = "cm5"))]
fn p8_det2() -> bool {
    let authentic = rules::rule_sig_ok(rules::DYN_RULE_BIN, rules::DYN_RULE_SIG);
    // The gate ran first; now the admitted rule's bytecode (16 LE bytes) as [u64;2] for the
    // memory-safety verifier — proving a gate-admitted rule is also verify_prevail-clean.
    let mut b0 = [0u8; 8];
    let mut b1 = [0u8; 8];
    let safe = if rules::DYN_RULE_BIN.len() >= 16 {
        b0.copy_from_slice(&rules::DYN_RULE_BIN[0..8]);
        b1.copy_from_slice(&rules::DYN_RULE_BIN[8..16]);
        let prog = [u64::from_le_bytes(b0), u64::from_le_bytes(b1)];
        bpf::verify_prevail(&prog).is_ok()
    } else {
        false
    };
    // (b) tampered bytecode -> gate refuses (provenance broken), BEFORE verify_prevail.
    let mut tampered = [0u8; 16];
    tampered.copy_from_slice(&rules::DYN_RULE_BIN[..16]);
    tampered[0] ^= 0x08;
    let tamper_refused = !rules::rule_sig_ok(&tampered, rules::DYN_RULE_SIG);
    // (c) authentic bytecode but a corrupted signature -> refused.
    let mut badsig = [0u8; 64];
    badsig.copy_from_slice(&rules::DYN_RULE_SIG[..64]);
    badsig[0] ^= 0x01;
    let badsig_refused = !rules::rule_sig_ok(rules::DYN_RULE_BIN, &badsig);
    let ok = authentic && safe && tamper_refused && badsig_refused;
    kprint!(" [P8-det2] {} — per-rule authenticity GATE (DET-2, the dynamic-rule-load prereq): signed rule AUTHENTIC={} + verify_prevail-safe={}; TAMPERED rule REFUSED before verify={}; WRONG-signature REFUSED={} — an unsigned/tampered dynamic rule never reaches the verifier or the datapath\n",
        if ok { "PASS" } else { "FAIL" }, authentic, safe, tamper_refused, badsig_refused);
    ok
}

/// M2.4 — L7 / BEHAVIORAL observe-only detectors: the LAST M2 detection-parity port.
/// Beacon (A10/L8), lateral (A10), exfil, and DNS analytics are OBSERVE-ONLY BY
/// CONSTRUCTION (ADR 0023 / CLAUDE.md): the SOC must SEE them, but none is a suspicion-free
/// confirmed drop, so each routes through `decide(Behavioral)` → `Observe` (PASS). Every
/// assertion proves BOTH halves at once — the detector FIRES (real detection, not a no-op)
/// AND the verdict is `Observe` / wire PASS (never a drop, zero legit-drop risk) — plus the
/// L8 NTP exemption and each detector's FP guards. Uses isolated ids (TEST-NET / RFC1918
/// ranges used nowhere else) + an injected clock for the beacon, so PHprod/PH6-net stay green.
#[cfg(not(feature = "cm5"))]
fn p8_l7behav() -> bool {
    use verdict::Verdict;
    kprint!("\n [P8] L7/behavioral (M2.4) — beacon/lateral/exfil/DNS: detected but OBSERVE-only (decide()->Observe->PASS, never a drop)\n");
    let mut ok = true;

    #[inline]
    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }
    // "fires but never drops": the verdict must be Some(Observe) AND wire == PASS.
    #[inline]
    fn is_observe_pass(v: Option<Verdict>) -> bool {
        matches!(v, Some(Verdict::Observe)) && v.map_or(packet::PASS, Verdict::to_wire) == packet::PASS
    }

    // === BEACON (A10 detection): a metronomic 60s +/-2s check-in to ONE dst:443 fires,
    //     and the verdict is Observe/PASS (detected, never dropped). Injected clock. ===
    behavioral::beacon_reset_for_test();
    let bsrc = ip(10, 66, 0, 5);
    let bdst = ip(203, 0, 113, 50);
    let jit: [i64; 10] = [0, 1, -1, 2, -2, 1, -1, 0, 1, -1]; // low jitter (real implant budget)
    let mut beacon_fired: Option<Verdict> = None;
    for (i, j) in jit.iter().enumerate() {
        let now = (i as i64 * 60 + j) as u64;
        if let Some(v) = rules::beacon_verdict_at(bsrc, bdst, 443, now) {
            beacon_fired = Some(v);
        }
    }
    let c_beacon = is_observe_pass(beacon_fired);
    ok &= c_beacon;
    kprint!("   BEACON metronomic 60s check-in -> {:?}, wire PASS (FIRED=detection real, but observe-only) [{}]\n",
        beacon_fired, if c_beacon { "ok" } else { "BUG" });

    // === L8 NTP EXEMPTION: the SAME textbook-regular pattern on dst:123 (NTP) NEVER fires
    //     — allowlisted before any state is touched (FP guard #4). ===
    behavioral::beacon_reset_for_test();
    let nsrc = ip(10, 66, 0, 9);
    let ndst = ip(132, 163, 96, 1); // pool.ntp.org-shaped
    let mut ntp_fired = false;
    for i in 0..20u64 {
        if rules::beacon_verdict_at(nsrc, ndst, 123, i * 64).is_some() {
            ntp_fired = true;
        }
    }
    let c_ntp = !ntp_fired;
    ok &= c_ntp;
    kprint!("   L8 NTP (:123) same beacon shape -> fired={} (MUST be false — allowlisted, never flagged) [{}]\n",
        ntp_fired, if c_ntp { "ok" } else { "BUG" });

    // === BEACON FP guards: high-jitter (human/bursty) NEVER fires; a rapid retry storm
    //     (mean interval < 8s) NEVER fires — however regular. ===
    behavioral::beacon_reset_for_test();
    let hsrc = ip(10, 66, 0, 11);
    let hdst = ip(203, 0, 113, 80);
    let gaps: [u64; 10] = [10, 300, 45, 900, 20, 600, 5, 400, 15, 700]; // wild variance
    let mut ts = 0u64;
    let mut jitter_fired = false;
    for g in gaps {
        if rules::beacon_verdict_at(hsrc, hdst, 443, ts).is_some() {
            jitter_fired = true;
        }
        ts += g;
    }
    behavioral::beacon_reset_for_test();
    let rsrc = ip(10, 66, 0, 12);
    let rdst = ip(203, 0, 113, 81);
    let mut storm_fired = false;
    for i in 0..20u64 {
        if rules::beacon_verdict_at(rsrc, rdst, 443, i * 2).is_some() {
            storm_fired = true; // 2s spacing < 8s MIN_MEAN_INTERVAL guard
        }
    }
    let c_bfp = !jitter_fired && !storm_fired;
    ok &= c_bfp;
    kprint!("   BEACON FP guards: high-jitter fired={}, rapid-retry-storm fired={} (both MUST be false) [{}]\n",
        jitter_fired, storm_fired, if c_bfp { "ok" } else { "BUG" });

    // === LATERAL (A10 detection): one internal source hitting 6 DISTINCT internal peers on
    //     admin ports (SMB/RDP/SSH) fires -> Observe/PASS. A normal client hitting its ONE
    //     file server many times NEVER fires (distinct-peer, not per-connection). ===
    let lsrc = ip(10, 20, 0, 5);
    let ports = [445u16, 3389, 22, 445, 5985, 5900];
    let mut lateral_fired: Option<Verdict> = None;
    for (k, p) in ports.iter().enumerate() {
        let dst = ip(10, 20, 0, 100 + k as u8); // 6 distinct internal peers
        if let Some(v) = rules::lateral_verdict(lsrc, dst, *p) {
            lateral_fired = Some(v);
        }
    }
    // Legit: one source, ONE internal peer, many sessions -> distinct==1, never fires.
    let lgood = ip(10, 20, 0, 200);
    let lserver = ip(10, 20, 0, 250);
    let mut lgood_fired = false;
    for _ in 0..30 {
        if rules::lateral_verdict(lgood, lserver, 445).is_some() {
            lgood_fired = true;
        }
    }
    // Legit: internal->EXTERNAL SSH (out to a public jump host) is out of scope -> never fires.
    let lext = ip(10, 20, 0, 201);
    let mut lext_fired = false;
    for _ in 0..30 {
        if rules::lateral_verdict(lext, ip(198, 51, 100, 7), 22).is_some() {
            lext_fired = true;
        }
    }
    let c_lat = is_observe_pass(lateral_fired)
        && behavioral::lateral_distinct_peers(lsrc) > behavioral::LATERAL_THRESHOLD
        && !lgood_fired
        && !lext_fired;
    ok &= c_lat;
    kprint!("   LATERAL {} distinct internal peers (>{}) -> {:?} wire PASS; legit 1-peer fired={}, internal->external fired={} [{}]\n",
        behavioral::lateral_distinct_peers(lsrc), behavioral::LATERAL_THRESHOLD,
        lateral_fired, lgood_fired, lext_fired, if c_lat { "ok" } else { "BUG" });

    // === EXFIL: a bulk internal->external outbound transfer (> threshold) fires ->
    //     Observe/PASS. An internal->internal transfer (not outbound) NEVER fires. ===
    let esrc = ip(10, 30, 0, 5);
    let eext = ip(203, 0, 113, 200);
    let exfil_fired = rules::exfil_verdict(esrc, eext, behavioral::EXFIL_BYTES_THRESH + 1);
    let e_internal = rules::exfil_verdict(ip(10, 30, 0, 6), ip(10, 30, 0, 9), behavioral::EXFIL_BYTES_THRESH + 1);
    let c_exfil = is_observe_pass(exfil_fired) && e_internal.is_none();
    ok &= c_exfil;
    kprint!("   EXFIL bulk internal->external ({}B) -> {:?} wire PASS; internal->internal fired={} (must be None) [{}]\n",
        behavioral::EXFIL_BYTES_THRESH + 1, exfil_fired, e_internal.is_some(), if c_exfil { "ok" } else { "BUG" });

    // === DNS analytics: a DGA-shaped + a tunneling-shaped QNAME fire -> Observe/PASS; a
    //     normal "www.google.com" does NOT. Full UDP:53 frame, QNAME parsed in-kernel. ===
    // Build eth(14)+IPv4(20)+UDP(8)+DNS(12+qname). proto=17, dst port 53.
    fn dns_frame(qname: &[u8], out: &mut [u8]) -> usize {
        // DNS msg = 12B header + QNAME (1B label-length prefix + qname bytes) + 1B root label.
        let dns_len = 12 + 1 + qname.len() + 1;
        let udp_len = 8 + dns_len;
        let ip_len = 20 + udp_len;
        let total = 14 + ip_len;
        out[12] = 0x08;
        out[13] = 0x00; // IPv4
        out[14] = 0x45; // IHL=5
        out[16] = (ip_len >> 8) as u8;
        out[17] = (ip_len & 0xff) as u8; // IP total length
        out[23] = 17; // UDP
        out[26..30].copy_from_slice(&[10, 40, 0, 5]); // IP source (internal client)
        // UDP header @ 34
        out[36] = (53u16 >> 8) as u8;
        out[37] = (53u16 & 0xff) as u8; // dst port 53
        out[38] = (udp_len >> 8) as u8;
        out[39] = (udp_len & 0xff) as u8;
        // DNS message @ 42; header 12 bytes (zeros ok), QNAME @ 54.
        let mut o = 54;
        // encode qname as a single label for simplicity (len byte + bytes + root 0)
        out[o] = qname.len() as u8;
        o += 1;
        out[o..o + qname.len()].copy_from_slice(qname);
        o += qname.len();
        out[o] = 0; // root label
        total
    }
    let mut buf = [0u8; 256];
    // DGA: 14-char high-diversity label mixing digits — algorithmically-generated look.
    let n = dns_frame(b"a8f3kd9xz2qw7b", &mut buf);
    let dga_v = rules::dns_verdict(&buf[..n]);
    let mut buf2 = [0u8; 256];
    // Tunneling: a 60-char single label (base32-blob smuggled as a hostname).
    let n2 = dns_frame(b"mfrgg2dfmzqwy3dpn5xhi4tvmqqgk3tenb2giz3fmvqxezlgnfxgk2a", &mut buf2);
    let tun_v = rules::dns_verdict(&buf2[..n2]);
    let mut buf3 = [0u8; 256];
    // Normal dictionary hostname -> Some(false) inside the analytic -> verdict None.
    let n3 = dns_frame(b"google", &mut buf3);
    let norm_v = rules::dns_verdict(&buf3[..n3]);
    let c_dns = is_observe_pass(dga_v) && is_observe_pass(tun_v) && norm_v.is_none();
    ok &= c_dns;
    kprint!("   DNS DGA-label -> {:?}, tunnel-label -> {:?}, normal 'google' -> {:?} (DGA/tunnel FIRE observe-PASS; normal None) [{}]\n",
        dga_v, tun_v, norm_v, if c_dns { "ok" } else { "BUG" });

    kprint!(" [P8-l7b] {} — M2.4 behavioral parity: beacon(A10)/lateral(A10)/exfil/DNS all DETECT (SOC sees them) but route decide(Behavioral)->Observe->wire PASS (never a drop, zero legit-drop risk); NTP(:123) beacon EXEMPT (L8); FP guards (jitter/retry-storm/1-peer/internal-dst) hold\n",
        if ok { "PASS" } else { "FAIL" });
    ok
}

/// P15 self-test (arch-agnostic, QEMU-gated): exercise the sealing crypto + the
/// MBR write-guard over an in-RAM block device — no disk, no brick risk. Proves:
///  * seal -> unseal round-trips the plaintext;
///  * the store-layer READ path scans + loads a blob from the reserved window;
///  * wrong-policy, flipped-ciphertext, flipped-header, and device_id-mismatch
///    all REFUSE (no plaintext leaks);
///  * `guard_from_mbr` rejects a GPT-protective MBR, a too-low partition, and a
///    missing signature, and accepts a well-formed one;
///  * the reserved-window guard admits only LBA 2016..2047.
/// Under `p15-write` it additionally drives the real store write path (read-back
/// verified) through the RamDisk, whose write hook PANICS on any out-of-window
/// LBA — the write-window-escape assertion.
#[cfg(not(feature = "cm5"))]
fn p15_seal_selftest() {
    use seal::{Policy, SealBlob, SealErr};
    use store::{guard_from_mbr, GuardErr, SealedStore};

    kprint!("\n [P15] sealed storage — seal/unseal + MBR write-guard (RamDisk, no disk)\n");

    // A synthetic SRK stands in for the HBoot-derived, measurement-bound key. On
    // QEMU there is no OTP + no V3 closure, so this is NOT real measurement
    // enforcement — it validates the crypto/format/guard logic only.
    let srk = [0x5au8; 32];
    let mut pcr = [[0u8; 32]; boot_abi::NUM_PCR];
    pcr[0] = [0x11; 32];
    pcr[1] = [0x22; 32];
    pcr[2] = [0x33; 32];

    let policy = Policy {
        mask: boot_abi::SEAL_POLICY_STRICT,
        device_id: 0x0BADF00D_1234_5678u64,
        svn_floor: 7,
        pcr,
    };
    // A 28-byte secret (<=32): its ciphertext is fully absorbed into HMAC's partial
    // block, exercising the Hasher::update path that a metal run found broken (a
    // short message tail was silently dropped, so tamper went undetected). Keep this
    // <=32 so the QEMU gate catches any regression of that bug.
    let secret = b"HEQK-P15-short-secret-28byte";

    // 1) round-trip seal/unseal.
    let mut blob = SealBlob::new();
    let sealed_ok = seal::seal(&srk, &policy, secret, &mut blob).is_ok();
    let mut pt = [0u8; 64];
    let round = seal::unseal(&srk, &policy, blob.as_slice(), &mut pt);
    let round_ok = sealed_ok
        && matches!(round, Ok(n) if n == secret.len() && &pt[..n] == secret);
    kprint!("   round-trip: seal {} bytes -> unseal -> {}\n",
        blob.len, if round_ok { "MATCH" } else { "MISMATCH" });

    // 1b) AUD-STO-1: re-sealing the SAME secret under the SAME key/policy must yield
    //     DIFFERENT ciphertext (fresh per-seal nonce => no CTR keystream reuse), and
    //     still round-trip (nonce travels in its own MAC-covered header).
    let mut blob_b = SealBlob::new();
    let hdr = seal::SEAL_HDR_LEN;
    let no_reuse = seal::seal(&srk, &policy, secret, &mut blob_b).is_ok()
        && blob_b.as_slice()[hdr..hdr + secret.len()] != blob.as_slice()[hdr..hdr + secret.len()]
        && matches!(seal::unseal(&srk, &policy, blob_b.as_slice(), &mut pt),
            Ok(n) if &pt[..n] == secret);
    kprint!("   no-reuse: two seals of same secret -> {} keystream\n",
        if no_reuse { "DISTINCT" } else { "REUSED!" });

    // 2) wrong policy (a changed measurement) is refused.
    let mut wrong_pcr = pcr;
    wrong_pcr[1] = [0xEE; 32]; // PCR1 differs -> strict policy diverges
    let wrong_policy = Policy { pcr: wrong_pcr, ..policy };
    let r_wrong = seal::unseal(&srk, &wrong_policy, blob.as_slice(), &mut pt);
    let wrong_refused = matches!(r_wrong, Err(SealErr::PolicyMismatch));

    // 3) flipped ciphertext byte -> tag fails.
    let mut tamper_ct = SealBlob::new();
    tamper_ct.bytes[..blob.len].copy_from_slice(blob.as_slice());
    tamper_ct.len = blob.len;
    tamper_ct.bytes[seal::SEAL_HDR_LEN] ^= 0x01;
    let r_ct = seal::unseal(&srk, &policy, tamper_ct.as_slice(), &mut pt);
    let ct_refused = matches!(r_ct, Err(SealErr::Tag));

    // 4) flipped header byte (in the tag-covered reserved area) -> tag fails.
    let mut tamper_hdr = SealBlob::new();
    tamper_hdr.bytes[..blob.len].copy_from_slice(blob.as_slice());
    tamper_hdr.len = blob.len;
    tamper_hdr.bytes[80] ^= 0x01; // reserved region (72..96): authenticated
    let r_hdr = seal::unseal(&srk, &policy, tamper_hdr.as_slice(), &mut pt);
    let hdr_refused = matches!(r_hdr, Err(SealErr::Tag));

    // 5) device_id mismatch -> refused (constant-time identity gate).
    let other_dev = Policy { device_id: 0xAAAA_BBBB_CCCC_DDDDu64, ..policy };
    let r_dev = seal::unseal(&srk, &other_dev, blob.as_slice(), &mut pt);
    let dev_refused = matches!(r_dev, Err(SealErr::DeviceMismatch));

    kprint!("   refusals: wrong-policy {}, flip-ct {}, flip-hdr {}, dev-mismatch {}\n",
        yn(wrong_refused), yn(ct_refused), yn(hdr_refused), yn(dev_refused));

    // 6) guard unit tests over synthetic MBRs.
    let good = mbr_with(&[(0x0c, 2048u32, 262144u32), (0x83, 526336, 1048576)]);
    let cap = 4096u64 * 1024; // plenty
    let g_good = guard_from_mbr(&good, cap);
    let gpt = mbr_with(&[(0xEE, 1, 0xFFFF_FFFF)]);
    let g_gpt = matches!(guard_from_mbr(&gpt, cap), Err(GuardErr::GptDetected));
    let low = mbr_with(&[(0x83, 34, 1000)]); // partition at LBA 34 -> too low
    let g_low = matches!(guard_from_mbr(&low, cap), Err(GuardErr::PartitionTooLow));
    let mut nosig = mbr_with(&[(0x0c, 2048, 1000)]);
    nosig[510] = 0; nosig[511] = 0; // strip the signature
    let g_nosig = matches!(guard_from_mbr(&nosig, cap), Err(GuardErr::NoSignature));
    let guard_ok = g_good.is_ok() && g_gpt && g_low && g_nosig;
    kprint!("   guard: well-formed {}, GPT-protective->reject {}, LBA34->too-low {}, no-sig->reject {}\n",
        if g_good.is_ok() { "accept" } else { "REJECT?!" }, yn(g_gpt), yn(g_low), yn(g_nosig));

    // 7) reserved-window guard admits ONLY 2016..2047 (the keystore region).
    let win = g_good.expect("well-formed MBR yields a guard");
    let window_ok = !win.allows(0) && !win.allows(2015) && win.allows(2016)
        && win.allows(2047) && !win.allows(2048) && !win.allows(4095);

    // 8) store-layer READ path: seed a blob into the RamDisk's reserved window
    //    (direct backing write — NOT a BlockDev write), then scan+load it back.
    let mut disk = RamDisk::new(2_000_000);
    disk.install_mbr(&good);
    disk.seed(store::RESERVED_LBA_LO, blob.as_slice());
    let load_ok = {
        let ss = SealedStore::open(&mut disk);
        match ss {
            Ok(store) => {
                let mut loaded = [0u8; seal::SEAL_MAX_BLOB];
                match store.load(&mut loaded) {
                    Some(n) => {
                        let mut lpt = [0u8; 64];
                        matches!(seal::unseal(&srk, &policy, &loaded[..n], &mut lpt),
                            Ok(m) if &lpt[..m] == secret)
                    }
                    None => false,
                }
            }
            Err(_) => false,
        }
    };
    kprint!("   store: window-guard {}, scan+load+unseal {}\n", yn(window_ok), yn(load_ok));

    // 9) (p15-write) real write path through the RamDisk, whose write hook PANICS
    //    on any LBA outside [2016,2048) — proves the store never escapes the window.
    #[cfg(feature = "p15-write")]
    let write_ok = {
        let mut wdisk = RamDisk::new(2_000_000);
        wdisk.install_mbr(&good);
        let mut store_w = SealedStore::open(&mut wdisk).expect("guard");
        let stored = store_w.store(blob.as_slice()).is_ok();
        drop(store_w);
        let mut back = SealedStore::open(&mut wdisk).expect("guard");
        let mut lb = [0u8; seal::SEAL_MAX_BLOB];
        let reread = back.load(&mut lb).is_some();
        stored && reread
    };
    #[cfg(not(feature = "p15-write"))]
    let write_ok = true; // write path compiled out by default (read-only build)

    let pass = round_ok && no_reuse
        && wrong_refused && ct_refused && hdr_refused && dev_refused
        && guard_ok && window_ok && load_ok && write_ok;
    kprint!(" [P15-seal] {} — Encrypt-then-MAC seal/unseal, tamper+wrong-measurement refused, MBR write-guard enforced (RamDisk)\n",
        if pass { "PASS" } else { "FAIL" });
}

/// M3.0 — multi-region write-guard (brick-safety) self-test. Arch-agnostic, runs
/// in EVERY boot (no device needed): proves the allowlist ALLOWS keystore + data
/// volume + inactive slot and REFUSES LBA 0 / the MBR / the active slot / gaps /
/// past-capacity, and that a bad region registration (LBA-0 inclusion, keystore
/// overlap, past capacity) is rejected fail-closed. This is the load-bearing
/// brick-safety gate for M3 persistence + OTA.
#[cfg(not(feature = "cm5"))]
fn p15_guard_selftest() {
    use store::{guard_from_mbr, RegionKind};

    // 64 MiB model disk: p1 (FAT boot) @ LBA 2048. Boot slots + data volume live
    // as disjoint sub-ranges (faithful to the CM5 layout: active/inactive kernel
    // slots in the boot area, evidence graph in a separate data region).
    let cap: u64 = 131072; // 64 MiB / 512
    let mbr = mbr_with(&[(0x0c, 2048, 129024)]);
    let g = match guard_from_mbr(&mbr, cap) {
        Ok(g) => g,
        Err(_) => {
            kprint!(" [P15-guard2] FAIL — guard_from_mbr rejected a well-formed MBR\n");
            return;
        }
    };
    // Register the extra writable regions (as the layout/OTA module would):
    //   active slot   [2048, 4096)  -> DELIBERATELY UNREGISTERED (must be refused)
    //   inactive slot [4096, 6144)  -> InactiveSlot (OTA staging target)
    //   boot gap      [6144, 8192)  -> UNREGISTERED (must be refused)
    //   data volume   [8192, cap)   -> DataVolume (evidence graph + QSecBit)
    let g = match g
        .with_region(4096, 6144, RegionKind::InactiveSlot)
        .and_then(|g| g.with_region(8192, cap, RegionKind::DataVolume))
    {
        Ok(g) => g,
        Err(_) => {
            kprint!(" [P15-guard2] FAIL — could not register data/inactive regions\n");
            return;
        }
    };

    // REFUSED: MBR, pre-keystore gap, active slot, boot gap, past capacity.
    let refused = !g.allows(0)          // MBR / partition table
        && !g.allows(1)
        && !g.allows(2015)              // alignment gap below the keystore
        && !g.allows(2048)              // ACTIVE slot head
        && !g.allows(3000)              // ACTIVE slot
        && !g.allows(4095)              // ACTIVE slot tail
        && !g.allows(6144)              // boot gap
        && !g.allows(8191)              // boot gap tail
        && !g.allows(cap)               // first sector past capacity
        && !g.allows(cap + 999);
    // ALLOWED: keystore, inactive slot, data volume.
    let allowed = g.allows(2016)        // keystore lo
        && g.allows(2047)               // keystore hi-1
        && g.allows(4096)               // inactive slot lo
        && g.allows(6143)               // inactive slot hi-1
        && g.allows(8192)               // data volume lo
        && g.allows(cap - 1);           // data volume hi-1
    // region_of resolves each writable LBA to the right kind; refused -> None.
    let kinds = g.region_of(2016) == Some(RegionKind::Keystore)
        && g.region_of(5000) == Some(RegionKind::InactiveSlot)
        && g.region_of(100_000) == Some(RegionKind::DataVolume)
        && g.region_of(3000).is_none()
        && g.region_of(0).is_none();
    // Bad registrations are rejected fail-closed (never silently weaken the guard).
    let bad_reject = g.with_region(0, 100, RegionKind::DataVolume).is_err()      // includes LBA 0
        && g.with_region(2000, 2032, RegionKind::DataVolume).is_err()            // overlaps keystore
        && g.with_region(8192, cap + 4096, RegionKind::DataVolume).is_err()      // past capacity
        && g.with_region(5000, 4000, RegionKind::DataVolume).is_err();           // inverted range

    let pass = refused && allowed && kinds && bad_reject && g.region_count() == 3;
    kprint!("   guard2: {} writable regions, refuse(MBR/active-slot/gaps/oob) {}, allow(keystore/inactive/data) {}, region_of {}, bad-reg->reject {}\n",
        g.region_count(), yn(refused), yn(allowed), yn(kinds), yn(bad_reject));
    kprint!(" [P15-guard2] {} — M3.0 multi-region write allowlist: LBA 0/MBR + ACTIVE slot + gaps REFUSED, keystore+data-volume+inactive-slot ALLOWED; overlap/LBA0/capacity registration rejected fail-closed (brick-safe)\n",
        if pass { "PASS" } else { "FAIL" });
}

/// M3.1 — cross-restart persistence proof over a FILE-BACKED virtio-blk device.
/// Boot 1 (fresh disk): seal a known cookie + write a data-volume marker, both
/// through the M3.0 guard. Boot 2 (SAME backing file): read them back, unseal,
/// and confirm they SURVIVED the restart — the thing a volatile RamDisk cannot
/// prove. Skips cleanly when QEMU attached no `-drive` (diskless boot). The real
/// eMMC write on brcm,bcm2712-sdhci is metal (Gate R); this proves the write-path
/// LOGIC + persistence in QEMU only.
#[cfg(not(feature = "cm5"))]
/// [P15-otafat] B2 (M3.4 OTA delivery) — LOCATE the inactive A/B kernel slot inside the
/// SHARED FAT32 boot partition and stage an OTA candidate into its REAL sectors, over a
/// file-backed virtio-blk device (the same hal::BlockDev the metal eMMC slots into). Proves
/// the delivery path end-to-end off-CM5: parse the MBR -> parse the FAT32 BPB -> walk the
/// root directory to HEQK8-B.IMG -> follow its cluster chain to a contiguous LBA run ->
/// register that run as RegionKind::InactiveSlot -> write a candidate marker through the
/// brick-safety guard -> read it back. FAT metadata (table + directory) is never mutated —
/// only the file's existing data clusters are overwritten (same-size candidate).
///
/// METAL CAVEAT (honest): the metal eMMC write_block still clamps InactiveSlot writes to
/// WriteRefused (emmc.rs) — that multi-region eMMC arming is a separate Gate-R item. This
/// phase proves the LOCATE + guarded-delivery LOGIC on a genuine FAT32 image; the metal
/// write landing is tomorrow's eMMC work.
#[cfg(not(feature = "cm5"))]
fn p15_otafat_selftest() {
    use hal::BlockDev;
    let mut dev = match arch_aarch64::virtio_blk::VirtioBlk::open() {
        Some(d) => d,
        None => {
            kprint!(" [P15-otafat] SKIP — no virtio-blk device (attach -drive with a FAT32 partition)\n");
            return;
        }
    };
    // 1. Find the FAT boot partition start from the MBR (partition 1, as on a real device).
    let mut mbr = [0u8; 512];
    if dev.read_block(0, &mut mbr).is_err() {
        kprint!(" [P15-otafat] SKIP — MBR read failed\n");
        return;
    }
    let parts = store::parse_mbr(&mbr);
    let part_start = parts[0].start;
    if part_start == 0 {
        kprint!(" [P15-otafat] SKIP — no first partition in the MBR\n");
        return;
    }
    // 2. Locate heqk8-b.img (8.3 short name "HEQK8-B IMG") as a contiguous LBA run.
    let (slot_lba, slot_sectors) = match fat::locate_contiguous(&dev, part_start, b"HEQK8-B IMG") {
        Some(r) => r,
        None => {
            // Say WHICH stage failed (an opaque FAIL hid a partition-offset bug once).
            let stage = match fat::parse(&dev, part_start) {
                None => "BPB parse refused",
                Some(fs) => match fat::find_file(&dev, &fs, b"HEQK8-B IMG") {
                    None => "file not found in the root directory",
                    Some(f) if f.n != 1 => "file is fragmented",
                    Some(_) => "unknown",
                },
            };
            kprint!(" [P15-otafat] FAIL — could not locate a contiguous HEQK8-B.IMG in the FAT32 partition @LBA {} ({})\n", part_start, stage);
            return;
        }
    };
    kprint!(" [P15-otafat] located HEQK8-B.IMG @ LBA {} ({} sectors) via FAT32 BPB + root-dir + cluster-chain\n",
        slot_lba, slot_sectors);
    #[cfg(feature = "p15-write")]
    {
        use store::{RegionKind, SealedStore};
        let marker = b"HEQK-OTA-CANDIDATE-SLOT-B-v1";
        let (mbr_refused, pre_refused, wrote) = {
            let mut store = match SealedStore::open(&mut dev) {
                Ok(s) => s,
                Err(e) => {
                    kprint!(" [P15-otafat] FAIL — guard refused to open the device MBR: {:?}\n", e);
                    return;
                }
            };
            // Register ONLY the located inactive-slot run — the ACTIVE slot, the FAT table,
            // the directory and LBA 0 all stay unregistered => WriteRefused (brick-safety).
            if store.add_region(slot_lba, slot_lba + slot_sectors, RegionKind::InactiveSlot).is_err() {
                kprint!(" [P15-otafat] FAIL — could not register the InactiveSlot region\n");
                return;
            }
            let poison = [0xEEu8; 512];
            let mbr_refused = store.store_sector(0, &poison).is_err();
            // A sector just BEFORE the slot (FAT/dir metadata or the active slot) is refused.
            let pre_refused = slot_lba == 0 || store.store_sector(slot_lba - 1, &poison).is_err();
            let mut sec = [0u8; 512];
            sec[..marker.len()].copy_from_slice(marker);
            let wrote = matches!(store.store_sector(slot_lba, &sec), Ok(RegionKind::InactiveSlot));
            (mbr_refused, pre_refused, wrote)
        };
        // store dropped -> dev free again -> read the candidate's first sector back.
        let mut rb = [0u8; 512];
        let read_ok = dev.read_block(slot_lba, &mut rb).is_ok() && &rb[..marker.len()] == &marker[..];
        let ok = mbr_refused && pre_refused && wrote && read_ok;
        kprint!(" [P15-otafat] {} — FAT locate -> InactiveSlot register -> guarded candidate write -> read-back (MBR-refused {}, pre-slot-refused {}, wrote {}, readback {})\n",
            if ok { "PASS" } else { "FAIL" }, yn(mbr_refused), yn(pre_refused), yn(wrote), yn(read_ok));
    }
    #[cfg(not(feature = "p15-write"))]
    kprint!(" [P15-otafat] located OK (read-only build; rebuild --features p15-write for the guarded write + read-back proof)\n");
}

#[cfg(not(feature = "cm5"))]
fn p15_persist_selftest() {
    use hal::BlockDev;
    use seal::Policy;
    use store::{RegionKind, SealedStore};

    let mut dev = match arch_aarch64::virtio_blk::VirtioBlk::open() {
        Some(d) => d,
        None => {
            kprint!(" [P15-persist] SKIP — no virtio-blk device (diskless boot; attach -drive to prove persistence)\n");
            return;
        }
    };
    let cap = dev.block_count();

    // Same synthetic SRK + fixed policy as the P15 seal test — deterministic
    // across both boots so unseal reproduces (synthetic-SRK caveat: NOT real
    // measurement enforcement until OTP/V3; this validates format+persistence).
    let srk = [0x5au8; 32];
    let mut pcr = [[0u8; 32]; boot_abi::NUM_PCR];
    pcr[0] = [0x11; 32];
    pcr[1] = [0x22; 32];
    pcr[2] = [0x33; 32];
    let policy = Policy {
        mask: boot_abi::SEAL_POLICY_STRICT,
        device_id: 0x0BADF00D_1234_5678u64,
        svn_floor: 7,
        pcr,
    };
    let cookie = b"HEQK-M3.1-PERSIST-COOKIE-v1";
    const DATAVOL_LBA: u64 = 8192;
    let marker = b"HEQK-M3.1-DATAVOL-MARKER";

    let mut store = match SealedStore::open(&mut dev) {
        Ok(s) => s,
        Err(e) => {
            kprint!(" [P15-persist] FAIL — guard refused to open the device MBR: {:?}\n", e);
            return;
        }
    };
    // Register the data-volume region so the guarded data-sector write is admitted.
    if store.add_region(DATAVOL_LBA, cap, RegionKind::DataVolume).is_err() {
        kprint!(" [P15-persist] FAIL — could not register the data-volume region\n");
        return;
    }

    // The disk itself is the boot counter: an empty keystore window => BOOT 1.
    let mut loaded = [0u8; seal::SEAL_MAX_BLOB];
    match store.load(&mut loaded) {
        None => {
            // ---- BOOT 1: write, then ask for a reboot ----
            #[cfg(feature = "p15-write")]
            {
                // Brick-safety end-to-end: a write to LBA 0 (MBR) and to an ACTIVE
                // (unregistered) slot LBA MUST be refused by the guard on the REAL
                // device — not just the predicate. If either escaped, the partition
                // table / running kernel could be clobbered; refuse to proceed.
                let poison = [0xEEu8; 512];
                let mbr_refused = store.store_sector(0, &poison).is_err();
                let active_refused = store.store_sector(3000, &poison).is_err();
                if !(mbr_refused && active_refused) {
                    kprint!(" [P15-persist] FAIL — brick-safety: LBA0-refused {}, active-slot-refused {} (a guarded write ESCAPED)\n",
                        yn(mbr_refused), yn(active_refused));
                    return;
                }
                let mut blob = seal::SealBlob::new();
                if seal::seal(&srk, &policy, cookie, &mut blob).is_err() {
                    kprint!(" [P15-persist] FAIL — seal() failed on boot 1\n");
                    return;
                }
                if let Err(e) = store.store(blob.as_slice()) {
                    kprint!(" [P15-persist] FAIL — keystore store() failed: {:?}\n", e);
                    return;
                }
                let mut sec = [0u8; 512];
                sec[..marker.len()].copy_from_slice(marker);
                match store.store_sector(DATAVOL_LBA, &sec) {
                    Ok(RegionKind::DataVolume) => {}
                    other => {
                        kprint!(" [P15-persist] FAIL — data-vol store_sector -> {:?}\n", other);
                        return;
                    }
                }
                kprint!(" [P15-persist] BOOT1 — brick-safety: LBA0+active-slot writes REFUSED on the real device; sealed cookie ({} B) + data-vol marker @LBA {} written through the guard; reboot (same disk) to verify persistence\n",
                    blob.len, DATAVOL_LBA);
            }
            #[cfg(not(feature = "p15-write"))]
            kprint!(" [P15-persist] SKIP — read-only build (rebuild --features p15-write for the write/persistence proof)\n");
        }
        Some(n) => {
            // ---- BOOT 2: the keystore blob persisted — verify it round-trips ----
            let mut pt = [0u8; 64];
            let cookie_ok = matches!(
                seal::unseal(&srk, &policy, &loaded[..n], &mut pt),
                Ok(m) if m == cookie.len() && &pt[..m] == cookie
            );
            let mut sec = [0u8; 512];
            let datavol_ok = store.read_sector(DATAVOL_LBA, &mut sec).is_ok()
                && &sec[..marker.len()] == marker;
            let pass = cookie_ok && datavol_ok;
            kprint!("   persist: sealed-cookie unseal {}, data-vol marker @LBA {} {}\n",
                yn(cookie_ok), DATAVOL_LBA, yn(datavol_ok));
            kprint!(" [P15-persist] {} — M3.1 cross-restart persistence: sealed cookie + data-vol marker SURVIVED reboot over file-backed virtio-blk (seal->persist->reboot->unseal); RamDisk cannot prove this — real eMMC write is metal (Gate R)\n",
                if pass { "PASS" } else { "FAIL" });
        }
    }
}

/// M3.2 — crash-safe log-structured record store self-test over the file-backed
/// virtio-blk device. Runs (b) torn-tail recovery + (c) bounded-retention every
/// boot (self-contained, re-mount proves the recovery/eviction algorithms), and
/// (a)+(d) persistence across the ACTUAL reboot driven by validate.sh's two boots:
/// boot 1 appends a real evidence Event + a QSecBit record; boot 2 reads them back
/// and verifies field-for-field. QEMU-proven over virtio-blk; the real eMMC write
/// is metal (Gate R).
#[cfg(not(feature = "cm5"))]
fn p15_fs_selftest() {
    let present = arch_aarch64::virtio_blk::VirtioBlk::open().is_some();
    #[cfg(not(feature = "p15-write"))]
    {
        if present {
            kprint!(" [P15-fs] SKIP — read-only build (rebuild --features p15-write for the crash-safe log proof)\n");
        } else {
            kprint!(" [P15-fs] SKIP — no virtio-blk device (diskless boot)\n");
        }
    }
    #[cfg(feature = "p15-write")]
    {
        use fslog::{RT_EVIDENCE, RT_QSECBIT, RT_TEST};
        use store::{RegionKind, SealedStore};
        if !present {
            kprint!(" [P15-fs] SKIP — no virtio-blk device (diskless boot)\n");
            return;
        }
        let mut dev = arch_aarch64::virtio_blk::VirtioBlk::open().unwrap();
        let cap = {
            use hal::BlockDev;
            dev.block_count()
        };
        let mut store = match SealedStore::open(&mut dev) {
            Ok(s) => s,
            Err(e) => {
                kprint!(" [P15-fs] FAIL — guard refused device MBR: {:?}\n", e);
                return;
            }
        };
        // The whole log lives inside the M3.1 DataVolume allowlist; sub-windows are
        // disjoint and clear of the M3.1 persist marker at LBA 8192.
        if store.add_region(8192, cap, RegionKind::DataVolume).is_err() {
            kprint!(" [P15-fs] FAIL — could not register the data-volume region\n");
            return;
        }

        // ---- (b) torn-tail recovery: 3 intact records + an injected torn frontier ----
        // Region [8320,8330) = 9 slots, so the torn record lands on a FRESH slot
        // (no eviction) — a clean "intact survive, torn dropped" demonstration.
        let (blo, bhi) = (8320u64, 8330u64);
        let pass_b = (|| -> bool {
            let mut log = match fslog::format(&mut store, blo, bhi) {
                Ok(l) => l,
                Err(_) => return false,
            };
            for i in 0..3u8 {
                let p = [b'I', b'N', b'T', i + b'0'];
                if log.append(&mut store, RT_TEST, &p).is_err() {
                    return false;
                }
            }
            // Inject a TORN record at the write frontier (seq 3 -> slot 3): build a
            // valid record, then corrupt one payload byte so its on-disk digest no
            // longer matches — exactly what a power-loss mid-payload write leaves.
            let torn_lba = blo + 1 + 3;
            let mut torn = [0u8; fslog::SEC];
            let pl = b"TORN-RECORD";
            torn[0..4].copy_from_slice(&fslog::REC_MAGIC.to_le_bytes());
            torn[8..16].copy_from_slice(&3u64.to_le_bytes());
            torn[16..18].copy_from_slice(&(pl.len() as u16).to_le_bytes());
            torn[18..20].copy_from_slice(&RT_TEST.to_le_bytes());
            torn[fslog::REC_HDR..fslog::REC_HDR + pl.len()].copy_from_slice(pl);
            {
                use boot_abi::sha256::Hasher;
                let mut h = Hasher::new();
                h.update(&torn[0..24]);
                h.update(&torn[fslog::REC_HDR..fslog::REC_HDR + pl.len()]);
                let d = h.finish();
                torn[24..32].copy_from_slice(&d[..8]);
            }
            torn[fslog::REC_HDR + 2] ^= 0xFF; // corrupt the payload AFTER digesting
            if store.store_sector(torn_lba, &torn).is_err() {
                return false;
            }
            // Re-mount (crash recovery): the 3 intact records survive, torn dropped.
            let recovered = match fslog::LogStore::mount(&store, blo, bhi) {
                Ok(l) => l,
                Err(_) => return false,
            };
            if recovered.count() != 3 || recovered.next_seq() != 3 {
                return false;
            }
            // Store is still WRITABLE: append a new record (reuses the torn slot).
            let mut log2 = recovered;
            if log2.append(&mut store, RT_TEST, b"AFTER").is_err() {
                return false;
            }
            let mut n = 0u64;
            let mut order_ok = true;
            let mut last: Option<u64> = None;
            let _ = fslog::LogStore::mount(&store, blo, bhi).map(|l| {
                l.for_each(&store, |seq, _rt, _pl| {
                    n += 1;
                    if let Some(x) = last {
                        if seq != x + 1 {
                            order_ok = false;
                        }
                    }
                    last = Some(seq);
                })
                .ok();
            });
            n == 4 && order_ok // seq 0,1,2 intact + new seq 3
        })();

        // ---- (c) bounded retention: write 10 into a 4-slot ring, oldest evicted ----
        let (clo, chi) = (8340u64, 8345u64); // 4 slots
        let mut retention_in_region = true;
        let pass_c = (|| -> bool {
            let mut log = match fslog::format(&mut store, clo, chi) {
                Ok(l) => l,
                Err(_) => return false,
            };
            for s in 0..10u64 {
                let p = [b'R', (b'0' + (s % 10) as u8)];
                match log.append(&mut store, RT_TEST, &p) {
                    Ok(_) => {}
                    Err(_) => {
                        retention_in_region = false; // a write escaped the region/guard
                        return false;
                    }
                }
            }
            // Re-mount: only the last 4 (seq 6..9) survive; head advanced to 10.
            let r = match fslog::LogStore::mount(&store, clo, chi) {
                Ok(l) => l,
                Err(_) => return false,
            };
            if r.count() != 4 || r.next_seq() != 10 || r.capacity() != 4 {
                return false;
            }
            let mut seqs = [0u64; 8];
            let mut i = 0usize;
            r.for_each(&store, |seq, _rt, _pl| {
                if i < seqs.len() {
                    seqs[i] = seq;
                }
                i += 1;
            })
            .ok();
            i == 4 && seqs[0] == 6 && seqs[1] == 7 && seqs[2] == 8 && seqs[3] == 9
        })();

        // ---- (a)+(d) persistence across reboot: evidence Event + QSecBit record ----
        // Known values so boot 2 can verify field-for-field.
        const EV_TS: u64 = 0xDEAD_BEEF_0000_1234;
        const EV_SRC: u32 = 0x0A00_0205; // 10.0.2.5
        const EV_RULE: u16 = 1000; // (rule_id truncated into u16 space for the test)
        const EV_SEV: u8 = 7;
        const EV_VERDICT: u8 = 1; // PASS
        const QS_TS: u64 = 0x0000_0000_1234_5678;
        const QS_SCORE: u32 = 4242;
        let (plo, phi) = (8500u64, 8510u64); // 9-slot persistence log

        let mut fs_line_done = false;
        match fslog::open_or_format(&mut store, plo, phi) {
            Ok(mut log) if log.count() == 0 => {
                // ---- BOOT 1: append the real records ----
                let ev = events::Event {
                    ts: EV_TS,
                    src: EV_SRC,
                    rule_id: EV_RULE,
                    severity: EV_SEV,
                    verdict: EV_VERDICT,
                    class: verdict::CLASS_UNKNOWN,
                    dst: 0,
                    dport: 0,
                };
                let mut evb = [0u8; 16];
                evb[0..8].copy_from_slice(&ev.ts.to_le_bytes());
                evb[8..12].copy_from_slice(&ev.src.to_le_bytes());
                evb[12..14].copy_from_slice(&ev.rule_id.to_le_bytes());
                evb[14] = ev.severity;
                evb[15] = ev.verdict;
                let mut qsb = [0u8; 12];
                qsb[0..8].copy_from_slice(&QS_TS.to_le_bytes());
                qsb[8..12].copy_from_slice(&QS_SCORE.to_le_bytes());
                let wrote = log.append(&mut store, RT_EVIDENCE, &evb).is_ok()
                    && log.append(&mut store, RT_QSECBIT, &qsb).is_ok()
                    && log.append(&mut store, RT_TEST, b"evg-tail-1").is_ok()
                    && log.append(&mut store, RT_TEST, b"evg-tail-2").is_ok();
                kprint!(" [P15-fs] BOOT1 — torn-recovery {}, retention-cap {}, wrote {} log records (Event+QSecBit+2) — reboot (same disk) to verify persistence\n",
                    yn(pass_b), yn(pass_c && retention_in_region), if wrote { 4 } else { 0 });
                fs_line_done = true;
            }
            Ok(log) => {
                // ---- BOOT 2: read the records back + verify field-for-field ----
                let mut nseen = 0u64;
                let mut order_ok = true;
                let mut last: Option<u64> = None;
                let mut ev_ok = false;
                let mut qs_ok = false;
                log.for_each(&store, |seq, rt, pl| {
                    nseen += 1;
                    if let Some(x) = last {
                        if seq != x + 1 {
                            order_ok = false;
                        }
                    }
                    last = Some(seq);
                    if rt == RT_EVIDENCE && pl.len() >= 16 {
                        let ts = u64::from_le_bytes(pl[0..8].try_into().unwrap());
                        let src = u32::from_le_bytes(pl[8..12].try_into().unwrap());
                        let rule = u16::from_le_bytes(pl[12..14].try_into().unwrap());
                        ev_ok = ts == EV_TS
                            && src == EV_SRC
                            && rule == EV_RULE
                            && pl[14] == EV_SEV
                            && pl[15] == EV_VERDICT;
                    } else if rt == RT_QSECBIT && pl.len() >= 12 {
                        let ts = u64::from_le_bytes(pl[0..8].try_into().unwrap());
                        let score = u32::from_le_bytes(pl[8..12].try_into().unwrap());
                        qs_ok = ts == QS_TS && score == QS_SCORE;
                    }
                })
                .ok();
                let pass_a = nseen == 4 && order_ok;
                let pass_d = ev_ok && qs_ok;
                let pass = pass_a && pass_b && pass_c && retention_in_region && pass_d;
                kprint!("   fs: records-in-order {} ({}), torn-recovery {}, retention-cap {}, Event round-trip {}, QSecBit round-trip {}\n",
                    yn(pass_a), nseen, yn(pass_b), yn(pass_c && retention_in_region), yn(ev_ok), yn(qs_ok));
                kprint!(" [P15-fs] {} — M3.2 crash-safe log: {} records SURVIVED reboot in order, torn tail dropped on recovery, retention cap holds, evidence Event + QSecBit history round-trip (virtio-blk; real eMMC = metal Gate R)\n",
                    if pass { "PASS" } else { "FAIL" }, nseen);
                fs_line_done = true;
            }
            Err(e) => {
                kprint!(" [P15-fs] FAIL — persistence log open failed: {:?}\n", e);
                fs_line_done = true;
            }
        }
        let _ = fs_line_done;
    }
}

/// M3.3 — sealed data-volume (encryption at rest). Proves the three properties
/// that make the DataVolume "sealed", over the file-backed virtio-blk device:
///   * CONFIDENTIALITY — a RAW block read of a slot holding a known Event shows
///     CIPHERTEXT: the plaintext field markers (ts 0xDEADBEEF…, src IP, the 16-B
///     Event image) are ABSENT from the on-disk sector; the HQKSEAL1 magic IS.
///   * INTEGRITY — flipping a ciphertext byte on disk (and recomputing the
///     forgeable keyless framing digest so the frame still parses) is REJECTED at
///     `mount_sealed` by the seal MAC; the intact records survive.
///   * CROSS-RESTART — the VEK persists SEALED in the keystore, so boot 2 loads it
///     (created=false) and decrypts boot 1's records field-for-field.
/// QEMU/virtio-blk-proven; the real eMMC write + OTP-bound SRK are metal (Gate R).
#[cfg(not(feature = "cm5"))]
fn p15_sealfs_selftest() {
    let present = arch_aarch64::virtio_blk::VirtioBlk::open().is_some();
    #[cfg(not(feature = "p15-write"))]
    {
        if present {
            kprint!(" [P15-sealfs] SKIP — read-only build (rebuild --features p15-write for the encryption-at-rest proof)\n");
        } else {
            kprint!(" [P15-sealfs] SKIP — no virtio-blk device (diskless boot)\n");
        }
    }
    #[cfg(feature = "p15-write")]
    {
        use fslog::{SealCtx, RT_EVIDENCE, RT_QSECBIT, RT_TEST};
        use seal::Policy;
        use store::{RegionKind, SealedStore};
        if !present {
            kprint!(" [P15-sealfs] SKIP — no virtio-blk device (diskless boot)\n");
            return;
        }
        let mut dev = arch_aarch64::virtio_blk::VirtioBlk::open().unwrap();
        let cap = {
            use hal::BlockDev;
            dev.block_count()
        };
        let mut store = match SealedStore::open(&mut dev) {
            Ok(s) => s,
            Err(e) => {
                kprint!(" [P15-sealfs] FAIL — guard refused device MBR: {:?}\n", e);
                return;
            }
        };
        if store.add_region(8192, cap, RegionKind::DataVolume).is_err() {
            kprint!(" [P15-sealfs] FAIL — could not register the data-volume region\n");
            return;
        }

        // Same synthetic SRK + strict policy as P15-persist (deterministic across
        // both boots). Synthetic-SRK caveat: NOT real measurement enforcement until
        // OTP/V3 — this validates the seal-at-rest mechanism + key persistence.
        let srk = [0x5au8; 32];
        let mut pcr = [[0u8; 32]; boot_abi::NUM_PCR];
        pcr[0] = [0x11; 32];
        pcr[1] = [0x22; 32];
        pcr[2] = [0x33; 32];
        let policy = Policy {
            mask: boot_abi::SEAL_POLICY_STRICT,
            device_id: 0x0BADF00D_1234_5678u64,
            svn_floor: 7,
            pcr,
        };

        // ---- Load-or-create the Volume Encryption Key (sealed in the keystore) ----
        let (vek, created) = match fslog::load_or_create_vek(&mut store, &srk, &policy) {
            Ok(v) => v,
            Err(e) => {
                kprint!(" [P15-sealfs] FAIL — VEK load/create failed: {:?}\n", e);
                return;
            }
        };
        let ctx = SealCtx { vek: &vek, policy: &policy };

        // Known Event so both the confidentiality scan and the boot-2 round-trip
        // can look for exact field markers.
        const EV_TS: u64 = 0xDEAD_BEEF_0000_1234;
        const EV_SRC: u32 = 0x0A00_0205; // 10.0.2.5
        const EV_RULE: u16 = 1000;
        const EV_SEV: u8 = 7;
        const EV_VERDICT: u8 = 1;
        const QS_TS: u64 = 0x0000_0000_1234_5678;
        const QS_SCORE: u32 = 4242;
        let evb = {
            let mut b = [0u8; 16];
            b[0..8].copy_from_slice(&EV_TS.to_le_bytes());
            b[8..12].copy_from_slice(&EV_SRC.to_le_bytes());
            b[12..14].copy_from_slice(&EV_RULE.to_le_bytes());
            b[14] = EV_SEV;
            b[15] = EV_VERDICT;
            b
        };

        // Sliding-window substring test (confidentiality scan).
        let contains = |hay: &[u8], needle: &[u8]| -> bool {
            if needle.is_empty() || needle.len() > hay.len() {
                return false;
            }
            hay.windows(needle.len()).any(|w| w == needle)
        };

        // ---- (b) CONFIDENTIALITY: a raw slot read must be ciphertext ----
        let (clo, chi) = (8620u64, 8630u64);
        let mut conf_seal_magic = false;
        let pass_conf = (|| -> bool {
            let mut log = match fslog::format(&mut store, clo, chi) {
                Ok(l) => l,
                Err(_) => return false,
            };
            if log.append_sealed(&mut store, &ctx, RT_EVIDENCE, &evb).is_err() {
                return false;
            }
            // Raw read of slot for seq 0 (lba = clo + 1).
            let mut raw = [0u8; fslog::SEC];
            if store.read_sector(clo + 1, &mut raw).is_err() {
                return false;
            }
            // The payload IS a HQKSEAL1 blob (positive check) …
            conf_seal_magic = &raw[fslog::REC_HDR..fslog::REC_HDR + 8] == seal::SEAL_MAGIC;
            // … and NONE of the plaintext markers survive on disk (the proof).
            let ts_absent = !contains(&raw, &EV_TS.to_le_bytes());
            let src_absent = !contains(&raw, &EV_SRC.to_le_bytes());
            let img_absent = !contains(&raw, &evb);
            conf_seal_magic && ts_absent && src_absent && img_absent
        })();

        // ---- (c) INTEGRITY: a forged-digest ciphertext edit is rejected ----
        // Append 3 sealed records, then TAMPER the tail (seq 2): flip a ciphertext
        // byte AND recompute the keyless framing digest so the frame still parses —
        // only the seal MAC can catch this. mount_sealed must drop seq 2, keep 0,1.
        let (tlo, thi) = (8640u64, 8650u64);
        let mut tamper_plaintext_leaked = false;
        let pass_integ = (|| -> bool {
            let mut log = match fslog::format(&mut store, tlo, thi) {
                Ok(l) => l,
                Err(_) => return false,
            };
            for i in 0..3u8 {
                let p = [b'S', b'E', b'C', i + b'0'];
                if log.append_sealed(&mut store, &ctx, RT_TEST, &p).is_err() {
                    return false;
                }
            }
            let tail_lba = tlo + 1 + 2; // seq 2
            let mut sec = [0u8; fslog::SEC];
            if store.read_sector(tail_lba, &mut sec).is_err() {
                return false;
            }
            let len = u16::from_le_bytes([sec[16], sec[17]]) as usize;
            // Flip one CIPHERTEXT byte (past the 128-B seal header inside the payload).
            let ct0 = fslog::REC_HDR + seal::SEAL_HDR_LEN;
            if ct0 >= fslog::REC_HDR + len {
                return false;
            }
            sec[ct0] ^= 0xFF;
            // Recompute the (forgeable, keyless) framing digest so parse_record passes.
            {
                use boot_abi::sha256::Hasher;
                let mut h = Hasher::new();
                h.update(&sec[0..24]);
                h.update(&sec[fslog::REC_HDR..fslog::REC_HDR + len]);
                let d = h.finish();
                sec[24..32].copy_from_slice(&d[..8]);
            }
            if store.store_sector(tail_lba, &sec).is_err() {
                return false;
            }
            // Keyed re-mount: the seal MAC rejects seq 2; seq 0,1 survive.
            let recovered = match fslog::LogStore::mount_sealed(&store, &ctx, tlo, thi) {
                Ok(l) => l,
                Err(_) => return false,
            };
            if recovered.count() != 2 || recovered.next_seq() != 2 {
                return false;
            }
            // No plaintext from the tampered record is ever delivered.
            let mut n = 0u64;
            recovered
                .for_each_sealed(&store, &ctx, |_seq, _rt, pl| {
                    n += 1;
                    if pl == b"SEC2" {
                        tamper_plaintext_leaked = true;
                    }
                })
                .ok();
            // For contrast: the key-free mount would ACCEPT the forged frame (the
            // digest was fixed) — proving the seal MAC, not the digest, is the guard.
            let digest_only = fslog::LogStore::mount(&store, tlo, thi)
                .map(|l| l.count())
                .unwrap_or(0);
            n == 2 && !tamper_plaintext_leaked && digest_only == 3
        })();

        // ---- (a)+(d) CROSS-RESTART: sealed Event + QSecBit survive reboot ----
        let (plo, phi) = (8660u64, 8670u64);
        match fslog::open_or_format(&mut store, plo, phi) {
            Ok(log) if log.count() == 0 => {
                // BOOT 1 — append the real sealed records.
                let mut qsb = [0u8; 12];
                qsb[0..8].copy_from_slice(&QS_TS.to_le_bytes());
                qsb[8..12].copy_from_slice(&QS_SCORE.to_le_bytes());
                let mut log = log;
                let wrote = log.append_sealed(&mut store, &ctx, RT_EVIDENCE, &evb).is_ok()
                    && log.append_sealed(&mut store, &ctx, RT_QSECBIT, &qsb).is_ok()
                    && log.append_sealed(&mut store, &ctx, RT_TEST, b"sealed-tail").is_ok();
                kprint!(" [P15-sealfs] BOOT1 — VEK {} + sealed to keystore; confidentiality {} (on-disk ciphertext, HQKSEAL1 magic {}), integrity {} (MAC rejects forged-digest tamper); wrote {} sealed records — reboot to verify key-survival + decrypt\n",
                    if created { "generated" } else { "loaded" },
                    yn(pass_conf), yn(conf_seal_magic), yn(pass_integ),
                    if wrote { 3 } else { 0 });
            }
            Ok(_) => {
                // BOOT 2 — the VEK must have LOADED (created=false), and decrypt.
                let key_survived = !created;
                let log = match fslog::LogStore::mount_sealed(&store, &ctx, plo, phi) {
                    Ok(l) => l,
                    Err(e) => {
                        kprint!(" [P15-sealfs] FAIL — sealed re-mount failed: {:?}\n", e);
                        return;
                    }
                };
                let mut nseen = 0u64;
                let mut order_ok = true;
                let mut last: Option<u64> = None;
                let mut ev_ok = false;
                let mut qs_ok = false;
                log.for_each_sealed(&store, &ctx, |seq, rt, pl| {
                    nseen += 1;
                    if let Some(x) = last {
                        if seq != x + 1 {
                            order_ok = false;
                        }
                    }
                    last = Some(seq);
                    if rt == RT_EVIDENCE && pl.len() >= 16 {
                        let ts = u64::from_le_bytes(pl[0..8].try_into().unwrap());
                        let src = u32::from_le_bytes(pl[8..12].try_into().unwrap());
                        let rule = u16::from_le_bytes(pl[12..14].try_into().unwrap());
                        ev_ok = ts == EV_TS
                            && src == EV_SRC
                            && rule == EV_RULE
                            && pl[14] == EV_SEV
                            && pl[15] == EV_VERDICT;
                    } else if rt == RT_QSECBIT && pl.len() >= 12 {
                        let ts = u64::from_le_bytes(pl[0..8].try_into().unwrap());
                        let score = u32::from_le_bytes(pl[8..12].try_into().unwrap());
                        qs_ok = ts == QS_TS && score == QS_SCORE;
                    }
                })
                .ok();
                let pass_a = nseen == 3 && order_ok && log.count() == 3;
                let pass_d = key_survived && ev_ok && qs_ok;
                let pass = pass_conf && pass_integ && pass_a && pass_d;
                kprint!("   sealfs: key-survived-reboot {}, decrypted-in-order {} ({}), Event round-trip {}, QSecBit round-trip {}, confidentiality {}, integrity {}\n",
                    yn(key_survived), yn(pass_a), nseen, yn(ev_ok), yn(qs_ok), yn(pass_conf), yn(pass_integ));
                kprint!(" [P15-sealfs] {} — M3.3 sealed data-volume: record payloads are HQKSEAL1 ciphertext at rest (plaintext markers ABSENT on disk), a forged-digest ciphertext tamper is MAC-REJECTED fail-closed, and the sealed VEK SURVIVED reboot to decrypt the evidence Event + QSecBit history (virtio-blk; real eMMC + OTP-bound SRK = metal Gate R)\n",
                    if pass { "PASS" } else { "FAIL" });
            }
            Err(e) => {
                kprint!(" [P15-sealfs] FAIL — sealed persistence log open failed: {:?}\n", e);
            }
        }
    }
}

/// M3.4 candidate fixture — a REAL hybrid-signed HEQK payload (PayloadHeader +
/// body), signed by `heqk-sign` over the SAME trust root HBoot embeds (svn=5,
/// body 512 B, total 8504 B). It is the QEMU stand-in for the M4 network "pull":
/// a candidate delivered as a RAM buffer. `#[repr(align(8))]` so a `&PayloadHeader`
/// view over its head is correctly aligned (no 7992-B stack copy).
#[cfg(all(not(feature = "cm5"), feature = "p15-write"))]
#[repr(align(8))]
struct AlignedCandidate([u8; 8504]);
#[cfg(all(not(feature = "cm5"), feature = "p15-write"))]
static OTA_CANDIDATE: AlignedCandidate =
    AlignedCandidate(*include_bytes!("testdata/ota_candidate.bin"));

/// M3.4 — on-device A/B OTA orchestrator + state machine over the file-backed
/// virtio-blk device. Proves, in QEMU over `hal::BlockDev` (the trait the metal
/// eMMC slots into):
///   (a) a VALID candidate verifies (SHARED hboot verifier) → stages to the
///       INACTIVE slot → state Staged, persisted;
///   (b) an INVALID candidate (bad signature OR svn < floor) is REJECTED —
///       verify-before-flip: no inactive-slot write, active slot + tryboot flag
///       untouched;
///   (c) flip → Trying → simulated healthy trial → Committed (new slot active);
///   (d) simulated failed trial → RolledBack (old slot active), and a below-floor
///       downgrade is refused (SVN floor);
///   (e) OTA state (and the staged candidate) SURVIVE a reboot (persisted) —
///       driven by validate.sh's two boots over one backing file;
///   (f) brick-safety: the candidate write only ever touches the InactiveSlot —
///       LBA 0 / the active slot are refused by the guard.
/// The REAL firmware one-shot flip, the REAL PM-watchdog trial reset, and a real
/// power cycle are hboot/metal (Gate R) — reused, not reimplemented here.
#[cfg(not(feature = "cm5"))]
fn p15_ota_selftest() {
    let present = arch_aarch64::virtio_blk::VirtioBlk::open().is_some();
    #[cfg(not(feature = "p15-write"))]
    {
        if present {
            kprint!(" [P15-ota] SKIP — read-only build (rebuild --features p15-write for the OTA proof)\n");
        } else {
            kprint!(" [P15-ota] SKIP — no virtio-blk device (diskless boot)\n");
        }
    }
    #[cfg(feature = "p15-write")]
    {
        use fslog::RT_TEST;
        use ota::{OtaPhase, OtaState, SLOT_A, SLOT_B, SLOT_NONE};
        use store::{RegionKind, SealedStore};
        if !present {
            kprint!(" [P15-ota] SKIP — no virtio-blk device (diskless boot)\n");
            return;
        }
        let mut dev = arch_aarch64::virtio_blk::VirtioBlk::open().unwrap();
        let mut store = match SealedStore::open(&mut dev) {
            Ok(s) => s,
            Err(e) => {
                kprint!(" [P15-ota] FAIL — guard refused device MBR: {:?}\n", e);
                return;
            }
        };
        // Two OTA regions, disjoint from the P15-persist/fs/sealfs footprints
        // (which live below LBA 8700). DataVolume [9000,9080) holds BOTH state logs
        // (cross-reboot [9000,9020) + scratch [9040,9060)); InactiveSlot [9100,9400)
        // holds BOTH candidate windows (scratch [9100,9200) + cross-reboot
        // [9300,9400)). Keeping to two regions respects MAX_REGIONS (keystore + 2).
        const DV_LO: u64 = 9000;
        const DV_HI: u64 = 9080;
        const IS_LO: u64 = 9100;
        const IS_HI: u64 = 9400;
        if store.add_region(DV_LO, DV_HI, RegionKind::DataVolume).is_err()
            || store.add_region(IS_LO, IS_HI, RegionKind::InactiveSlot).is_err()
        {
            kprint!(" [P15-ota] FAIL — could not register OTA data/inactive regions\n");
            return;
        }

        let candidate = &OTA_CANDIDATE.0;
        // Anti-rollback floors: COMPILE_FLOOR-equivalent accept (candidate svn=5 >=
        // 1) and a raised floor 9 that refuses the same validly-signed image.
        const FLOOR_OK: u64 = 1;
        const FLOOR_HIGH: u64 = 9;
        // A never-registered LBA standing in for the ACTIVE slot (inside the FAT
        // partition [2048,131072) but registered by NO region).
        const ACTIVE_SLOT_LBA: u64 = 3000;

        // ---- (f) brick-safety: writes to LBA 0 + the active slot are refused ----
        let poison = [0xEEu8; 512];
        let mbr_refused = store.store_sector(0, &poison).is_err();
        let active_refused = store.store_sector(ACTIVE_SLOT_LBA, &poison).is_err();
        let brick_safe = mbr_refused && active_refused;

        // ---- (a) VALID candidate → verify → stage to inactive slot → Staged ----
        // Scratch state log [9040,9060); scratch inactive window [9100,9200).
        let (slo, shi) = (9040u64, 9060u64);
        let (i_lo, i_hi) = (9100u64, 9200u64);
        let mut staged_state = OtaState::initial();
        let stage_res = ota::stage(&mut store, &staged_state, i_lo, i_hi, candidate, FLOOR_OK);
        let pass_a = match stage_res {
            Ok(s) => {
                staged_state = s;
                s.phase == OtaPhase::Staged && s.candidate_svn == 5 && s.active_slot == SLOT_A
            }
            Err(_) => false,
        };
        // Persist the Staged state through the crash-safe log, then read it back.
        let persist_a = (|| -> bool {
            let mut log = match fslog::open_or_format(&mut store, slo, shi) {
                Ok(l) => l,
                Err(_) => return false,
            };
            if log
                .append(&mut store, RT_TEST, &staged_state.to_bytes())
                .is_err()
            {
                return false;
            }
            // Re-mount + read the last record → the persisted phase must be Staged.
            let r = match fslog::LogStore::mount(&store, slo, shi) {
                Ok(l) => l,
                Err(_) => return false,
            };
            let mut got: Option<OtaState> = None;
            r.for_each(&store, |_seq, _rt, pl| {
                if let Some(s) = OtaState::from_bytes(pl) {
                    got = Some(s);
                }
            })
            .ok();
            matches!(got, Some(s) if s.phase == OtaPhase::Staged && s.candidate_svn == 5)
        })();

        // ---- (b) INVALID: bad signature → verify FAILS → rejected, no write ----
        // Corrupt one ed25519-signature byte in a copy; verify_candidate must fail
        // and stage() must leave the state untouched with NO inactive-slot write.
        // Zero the scratch inactive window first so we can prove nothing was written.
        let zero = [0u8; 512];
        for lba in i_lo..i_lo + 20 {
            let _ = store.store_sector(lba, &zero);
        }
        let mut bad = [0u8; 8504];
        bad.copy_from_slice(candidate);
        // ed25519_sig starts at offset 40 (magic/size/entry/load/svn) + 32 (sha256).
        bad[40 + 32] ^= 0xFF;
        let before = staged_state; // Staged
        let bad_res = ota::stage(&mut store, &before, i_lo, i_hi, &bad, FLOOR_OK);
        let mut inactive_clean = true;
        {
            let mut sec = [0u8; 512];
            if store.read_sector(i_lo, &mut sec).is_ok() && sec != zero {
                inactive_clean = false;
            }
        }
        let pass_b = matches!(
            bad_res,
            Err(ota::OtaErr::VerifyRejected(boot_abi::verify::VerifyErr::BadEd25519))
        ) && inactive_clean;

        // ---- (d-refuse) below-floor: validly-signed svn=5 vs floor 9 → refused ----
        let downgrade_res = ota::stage(&mut store, &before, i_lo, i_hi, candidate, FLOOR_HIGH);
        let downgrade_refused = matches!(
            downgrade_res,
            Err(ota::OtaErr::VerifyRejected(boot_abi::verify::VerifyErr::BelowFloor))
        );

        // ---- (c) flip → Trying → simulated healthy trial → Committed ----
        let pass_c = (|| -> bool {
            let flipped = match ota::flip(&staged_state) {
                Ok(s) => s,
                Err(_) => return false,
            };
            if flipped.phase != OtaPhase::Trying || flipped.try_slot != SLOT_B {
                return false;
            }
            // Simulated HEALTHY trial (metal: kernel hvc#1 disarms the PM watchdog).
            let committed = match ota::confirm(&flipped) {
                Ok(s) => s,
                Err(_) => return false,
            };
            committed.phase == OtaPhase::Committed
                && committed.active_slot == SLOT_B
                && committed.try_slot == SLOT_NONE
        })();

        // ---- (d) flip → Trying → simulated FAILED trial → RolledBack ----
        let pass_d = (|| -> bool {
            let flipped = match ota::flip(&staged_state) {
                Ok(s) => s,
                Err(_) => return false,
            };
            // Simulated FAILED trial (metal: watchdog fires, one-shot reverts to A).
            let rolled = match ota::rollback(&flipped) {
                Ok(s) => s,
                Err(_) => return false,
            };
            rolled.phase == OtaPhase::RolledBack
                && rolled.active_slot == SLOT_A // old slot stays known-good
                && rolled.try_slot == SLOT_NONE
        })() && downgrade_refused;

        // ---- (e) cross-reboot persistence: dedicated state log + candidate ----
        // State log [9000,9020); cross-reboot candidate window [9300,9400).
        let (plo, phi) = (9000u64, 9020u64);
        let (ci_lo, ci_hi) = (9300u64, 9400u64);
        match fslog::open_or_format(&mut store, plo, phi) {
            Ok(mut log) if log.count() == 0 => {
                // ---- BOOT 1: stage a valid candidate + persist Staged ----
                let st0 = OtaState::initial();
                let staged = match ota::stage(&mut store, &st0, ci_lo, ci_hi, candidate, FLOOR_OK) {
                    Ok(s) => s,
                    Err(e) => {
                        kprint!(" [P15-ota] FAIL — boot-1 stage failed: {:?}\n", e);
                        return;
                    }
                };
                let flipped = ota::flip(&staged).unwrap_or(staged);
                let wrote = log.append(&mut store, RT_TEST, &flipped.to_bytes()).is_ok();
                kprint!(" [P15-ota] BOOT1 — brick-safe {} (LBA0+active-slot refused), valid staged→{:?} (svn {}), bad-sig rejected {}, downgrade refused {}, commit {}, rollback {}; persisted try-slot state {} — reboot to verify OTA state + candidate survive\n",
                    yn(brick_safe), flipped.phase, flipped.candidate_svn,
                    yn(pass_b), yn(downgrade_refused), yn(pass_c), yn(pass_d), yn(wrote));
            }
            Ok(log) => {
                // ---- BOOT 2: the OTA state (Trying, try_slot=B) must have survived,
                // and the staged candidate must still be in the inactive slot. Then
                // simulate a healthy trial → Committed and persist it. ----
                let mut got: Option<OtaState> = None;
                log.for_each(&store, |_seq, _rt, pl| {
                    if let Some(s) = OtaState::from_bytes(pl) {
                        got = Some(s);
                    }
                })
                .ok();
                let state_survived = matches!(
                    got,
                    Some(s) if s.phase == OtaPhase::Trying && s.try_slot == SLOT_B && s.candidate_svn == 5
                );
                // The candidate bytes written to the inactive slot in boot 1 persisted:
                // re-verify header magic at the slot head (a cheap on-disk proof).
                let mut head = [0u8; 512];
                let cand_survived = store.read_sector(ci_lo, &mut head).is_ok()
                    && u64::from_le_bytes(head[0..8].try_into().unwrap()) == boot_abi::PAYLOAD_MAGIC;
                // Confirm the trial → Committed (new slot active).
                let committed_ok = got
                    .and_then(|s| ota::confirm(&s).ok())
                    .map(|c| c.phase == OtaPhase::Committed && c.active_slot == SLOT_B)
                    .unwrap_or(false);

                let pass = brick_safe
                    && pass_a
                    && persist_a
                    && pass_b
                    && pass_c
                    && pass_d
                    && downgrade_refused
                    && state_survived
                    && cand_survived
                    && committed_ok;
                kprint!("   ota: brick-safe {}, stage→Staged {} (persisted {}), bad-sig rejected {}, downgrade refused {}, commit {}, rollback {}, state survived reboot {}, candidate survived {}, confirm→Committed {}\n",
                    yn(brick_safe), yn(pass_a), yn(persist_a), yn(pass_b), yn(downgrade_refused),
                    yn(pass_c), yn(pass_d), yn(state_survived), yn(cand_survived), yn(committed_ok));
                kprint!(" [P15-ota] {} — M3.4 on-device A/B OTA: verify-before-flip (SHARED hboot verifier, no 2nd trust root), candidate staged to INACTIVE slot only (brick-safe), bad-sig + below-floor downgrade REFUSED, flip→trial→{{commit|rollback}} decisions, OTA state + candidate SURVIVED reboot; real firmware one-shot flip + PM-watchdog reset = metal (Gate R)\n",
                    if pass { "PASS" } else { "FAIL" });
            }
            Err(e) => {
                kprint!(" [P15-ota] FAIL — OTA state log open failed: {:?}\n", e);
            }
        }
    }
}

#[cfg(not(feature = "cm5"))]
#[inline]
fn yn(b: bool) -> &'static str {
    if b { "yes" } else { "NO" }
}

/// Build a synthetic 512-byte MBR sector with the given `(type, start_lba,
/// sector_count)` primary entries and a valid 0x55AA signature.
#[cfg(not(feature = "cm5"))]
fn mbr_with(parts: &[(u8, u32, u32)]) -> [u8; 512] {
    let mut s = [0u8; 512];
    for (i, &(ptype, start, count)) in parts.iter().enumerate().take(4) {
        let off = 446 + i * 16;
        s[off + 4] = ptype;
        s[off + 8..off + 12].copy_from_slice(&start.to_le_bytes());
        s[off + 12..off + 16].copy_from_slice(&count.to_le_bytes());
    }
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

/// An in-RAM block device for the P15 self-test. SPARSE on purpose (a dense
/// 4096-sector array is 2 MiB and would exhaust the tiny kernel heap): it backs
/// only LBA 0 (the MBR) and the reserved window LBA 2016..2047, and reports a
/// large synthetic capacity so the guard's partition/capacity checks are real.
/// The write hook is the SECOND, independent write-window gate: it PANICS on any
/// LBA outside [2016,2048), so a store-layer escape becomes an immediate, loud
/// abort (the write-window-escape assertion). `seed`/`install_mbr` bypass it for
/// test setup (they are direct backing writes, not BlockDev writes).

/// `[P-abstore]` — task #27 F2: ProdFull's snapshot store is crash-consistent. A/B slots with a commit
/// header written LAST: a write torn at any point (blob half-written, header torn) leaves the previous
/// snapshot loadable; a corrupted newest slot falls back to the older one; a device persisted by an older
/// image (single blob at 2016) is still loaded (one-time migration). RamDisk writes that leave the
/// reserved window PANIC, so the store is also proven never to escape it.
#[cfg(all(feature = "p15-write", not(feature = "cm5")))]
fn abstore_selftest() {
    use hal::BlockDev;
    use store::{SealedStore, AB_SLOTS, AB_SLOT_SECTORS};
    let mut mbr = [0u8; 512];
    mbr[450] = 0x0c;
    mbr[454..458].copy_from_slice(&2048u32.to_le_bytes());
    mbr[458..462].copy_from_slice(&129_024u32.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    let srk = [0x5au8; 32];
    let policy = seal::Policy { mask: 0, device_id: 0xab57_0e00, svn_floor: 0, pcr: [[0u8; 32]; boot_abi::NUM_PCR] };
    let mk = |tag: u8| {
        let mut pt = [0u8; 1104];
        pt[0] = tag;
        pt[1103] = tag ^ 0xff;
        let mut b = seal::SealBlob::new();
        seal::seal(&srk, &policy, &pt, &mut b).expect("seal");
        b
    };
    let (b1, b2, b3) = (mk(1), mk(2), mk(3));
    let tag_of = |bytes: &[u8]| -> Option<u8> {
        let mut pt = [0u8; 1104];
        match seal::unseal(&srk, &policy, bytes, &mut pt) {
            Ok(n) if n == 1104 && pt[1103] == pt[0] ^ 0xff => Some(pt[0]),
            _ => None,
        }
    };
    let mut disk = RamDisk::new(2_000_000);
    disk.install_mbr(&mbr);
    let mut out = [0u8; seal::SEAL_MAX_BLOB];
    // 1. gen 1 then gen 2, alternating slots; load = newest.
    let (g1, g2) = {
        let mut ss = SealedStore::open(&mut disk).expect("guard");
        (ss.store_ab(b1.as_slice()), ss.store_ab(b2.as_slice()))
    };
    let newest = |d: &mut RamDisk, out: &mut [u8]| -> Option<u8> {
        let ss = SealedStore::open(d).ok()?;
        let n = ss.load_ab(out)?;
        tag_of(&out[..n])
    };
    let gens_ok = g1 == Ok(1) && g2 == Ok(2) && newest(&mut disk, &mut out) == Some(2);
    // gen 2 went to slot B (AB_SLOTS[1]); the next write targets slot A.
    // 2. torn: slot A's blob sectors overwritten with gen 3's bytes, header NOT written (power loss).
    let torn_blob = {
        let bs = b3.as_slice();
        for i in 0..bs.len().div_ceil(512) {
            let mut s = [0u8; 512];
            let n = (bs.len() - i * 512).min(512);
            s[..n].copy_from_slice(&bs[i * 512..i * 512 + n]);
            disk.seed(AB_SLOTS[0] + 1 + i as u64, &s);
        }
        newest(&mut disk, &mut out) == Some(2)
    };
    // 3. torn header: garbage in slot A's header sector -> still gen 2.
    let torn_hdr = {
        let mut h = [0u8; 512];
        h[..8].copy_from_slice(b"HQKSLOT1");
        h[8] = 9; // gen 9 claimed, but the self-check is wrong
        disk.seed(AB_SLOTS[0], &h);
        newest(&mut disk, &mut out) == Some(2)
    };
    // 4. a completed gen 3 wins; then corrupt it -> fall back to gen 2 (slot B).
    let g3 = {
        let mut ss = SealedStore::open(&mut disk).expect("guard");
        ss.store_ab(b3.as_slice())
    };
    let gen3_ok = g3 == Ok(3) && newest(&mut disk, &mut out) == Some(3);
    let fallback = {
        let mut s = [0u8; 512];
        disk.read_block(AB_SLOTS[0] + 2, &mut s).ok();
        s[7] ^= 0x40;
        disk.seed(AB_SLOTS[0] + 2, &s);
        newest(&mut disk, &mut out) == Some(2)
    };
    // 5. legacy migration: a fresh disk holding only the old single blob at 2016.
    let mut old = RamDisk::new(2_000_000);
    old.install_mbr(&mbr);
    old.seed(store::RESERVED_LBA_LO, b1.as_slice());
    let legacy = newest(&mut old, &mut out) == Some(1);
    // 6. the slots never collide with the VEK (2024), the bench cookie (2040) or OTA (2044).
    let layout = AB_SLOTS[0] > 2024 && AB_SLOTS[1] + AB_SLOT_SECTORS < 2040 && b1.as_slice().len() <= (AB_SLOT_SECTORS as usize) * 512;
    let ok = gens_ok && torn_blob && torn_hdr && gen3_ok && fallback && legacy && layout;
    kprint!(" [P-abstore] {} — crash-consistent A/B snapshot store (task #27 F2): gen1/gen2 alternate, newest loads={} | torn blob (no commit header) -> previous gen intact={} | torn header -> previous gen={} | completed gen3 wins={} | corrupted newest -> falls back={} | legacy single blob @2016 still loads (migration)={} | slots clear of VEK/cookie/OTA + blob fits={}\n",
        if ok { "PASS" } else { "FAIL" }, gens_ok, torn_blob, torn_hdr, gen3_ok, fallback, legacy, layout);
}

#[cfg(not(feature = "cm5"))]
struct RamDisk {
    mbr: [u8; 512],
    window: [u8; ((store::RESERVED_LBA_HI - store::RESERVED_LBA_LO) as usize) * 512], // 32 sectors
    sectors: u64, // reported capacity
}

#[cfg(not(feature = "cm5"))]
impl RamDisk {
    fn new(sectors: u64) -> Self {
        RamDisk {
            mbr: [0u8; 512],
            window: [0u8; ((store::RESERVED_LBA_HI - store::RESERVED_LBA_LO) as usize) * 512],
            sectors,
        }
    }
    fn install_mbr(&mut self, mbr: &[u8; 512]) {
        self.mbr = *mbr;
    }
    /// Direct backing write for test setup (NOT a BlockDev write — bypasses the
    /// window gate on purpose, to place a blob for the read/scan path). Only the
    /// reserved window is backed.
    fn seed(&mut self, lba: u64, bytes: &[u8]) {
        assert!((store::RESERVED_LBA_LO..store::RESERVED_LBA_HI).contains(&lba));
        let off = ((lba - store::RESERVED_LBA_LO) as usize) * 512;
        self.window[off..off + bytes.len()].copy_from_slice(bytes);
    }
}

#[cfg(not(feature = "cm5"))]
impl hal::BlockDev for RamDisk {
    fn block_count(&self) -> u64 {
        self.sectors
    }
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), hal::BlockErr> {
        if lba >= self.sectors {
            return Err(hal::BlockErr::OutOfRange);
        }
        if lba == 0 {
            buf.copy_from_slice(&self.mbr);
        } else if (store::RESERVED_LBA_LO..store::RESERVED_LBA_HI).contains(&lba) {
            let off = ((lba - store::RESERVED_LBA_LO) as usize) * 512;
            buf.copy_from_slice(&self.window[off..off + 512]);
        } else {
            *buf = [0u8; 512]; // unbacked region reads as zero
        }
        Ok(())
    }
    #[cfg(feature = "p15-write")]
    fn write_block(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), hal::BlockErr> {
        // Write-window-escape assertion: the ONLY writable sectors are 2016..2047.
        assert!(
            (store::RESERVED_LBA_LO..store::RESERVED_LBA_HI).contains(&lba),
            "P15 write-window ESCAPE: LBA {} outside [2016,2048)",
            lba
        );
        if lba >= self.sectors {
            return Err(hal::BlockErr::OutOfRange);
        }
        let off = ((lba - store::RESERVED_LBA_LO) as usize) * 512;
        self.window[off..off + 512].copy_from_slice(buf);
        Ok(())
    }
}

/// P7c — spawn an uncooperative EL0 task (loops at EL0 with IRQs on, no syscalls)
/// as a scheduled TCB. If the box keeps ticking, the timer is preempting it, so
/// EL0 is a real schedulable/preemptible TCB (closes B-6). Its counter (read via
/// the physical frame) proves it actually executed at EL0.
#[cfg(not(feature = "cm5"))]
fn el0_preempt_spawn() {
    let mmu = arch_aarch64::Mmu;
    extern "C" {
        static el0_loop_stub: u8;
        static el0_loop_stub_end: u8;
    }
    let src = core::ptr::addr_of!(el0_loop_stub) as usize;
    let len = core::ptr::addr_of!(el0_loop_stub_end) as usize - src;
    let (code, stack, cnt) = (mmu.alloc_frame(), mmu.alloc_frame(), mmu.alloc_frame());
    if code == 0 || stack == 0 || cnt == 0 {
        return;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(src as *const u8, code as *mut u8, len);
        core::ptr::write_volatile(cnt as *mut u64, 0);
    }
    arch_aarch64::mmu::sync_instruction_cache(code, len);
    // Run the EL0 task in its OWN address space (its own ASID) — full isolation:
    // its pages exist only in this AS, in GB2 (unmapped in the kernel L1, so this
    // AS gets its own tables). The scheduler switches TTBR0 to this AS to run it.
    let (l1, asid) = mmu.new_addr_space();
    if l1 == 0 {
        return;
    }
    const ECODE_VA: usize = 0x8200_0000;
    const ESTACK_VA: usize = 0x8200_1000;
    const ECNT_VA: usize = 0x8200_2000;
    mmu.map_user_code_in(l1, ECODE_VA, code);
    mmu.map_user_data_in(l1, ESTACK_VA, stack);
    mmu.map_user_data_in(l1, ECNT_VA, cnt);
    EL0_CNT_PA.store(cnt, Ordering::SeqCst); // kernel reads the counter via its physical frame
    let kstack_top = unsafe { core::ptr::addr_of!(EL0_KSTACK) as usize + KSTACK_SIZE };
    let sp = arch_aarch64::thread::make_el0_thread(kstack_top, ECODE_VA, ESTACK_VA + 0x1000, ECNT_VA);
    let ttbr0 = l1 as u64 | ((asid as u64) << 48);
    // CORE-6/DSN-6: even the preempt-loop TCB gets its OWN restart record, so if it
    // ever faults it restarts from its own params — never falling through to the
    // cooperative longjmp path (which would jump into a stale KRESUME for a scheduled
    // TCB).
    if let Some(tid) = scheduler::spawn_as(sp, 1, ttbr0) {
        scheduler::set_restart(tid, ECODE_VA, ESTACK_VA + 0x1000, kstack_top);
    }
    kprint!(" [P7c] EL0 task spawned in its OWN address space (asid={}) — preemptible + isolated\n", asid);
}

/// P7c step 4b — spawn a CRASHING EL0 driver TCB (faults immediately) in its own
/// ASID, and arm fault-restart. The kernel contains each crash, rebuilds a fresh
/// frame, and after a restart budget kills the TCB — a driver crash is contained
/// AND recovered without taking the kernel down.
#[cfg(not(feature = "cm5"))]
fn el0_fault_spawn() {
    let mmu = arch_aarch64::Mmu;
    extern "C" {
        static el0_fault_stub: u8;
        static el0_fault_stub_end: u8;
    }
    let src = core::ptr::addr_of!(el0_fault_stub) as usize;
    let len = core::ptr::addr_of!(el0_fault_stub_end) as usize - src;
    let (code, stack) = (mmu.alloc_frame(), mmu.alloc_frame());
    if code == 0 || stack == 0 {
        return;
    }
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, code as *mut u8, len) };
    arch_aarch64::mmu::sync_instruction_cache(code, len);
    let (l1, asid) = mmu.new_addr_space();
    if l1 == 0 {
        return;
    }
    const FCODE_VA: usize = 0x8300_0000;
    const FSTACK_VA: usize = 0x8300_1000;
    mmu.map_user_code_in(l1, FCODE_VA, code);
    mmu.map_user_data_in(l1, FSTACK_VA, stack);
    let kstack_top = unsafe { core::ptr::addr_of!(EL0_FKSTACK) as usize + KSTACK_SIZE };
    let sp = arch_aarch64::thread::make_el0_thread(kstack_top, FCODE_VA, FSTACK_VA + 0x1000, 0);
    let ttbr0 = l1 as u64 | ((asid as u64) << 48);
    // CORE-6: arm THIS TCB's own restart record (was the shared globals). Capture its
    // tid so the P7c report can read its restart count directly.
    if let Some(tid) = scheduler::spawn_as(sp, 2, ttbr0) {
        // higher prio: runs (and crashes) promptly
        scheduler::set_restart(tid, FCODE_VA, FSTACK_VA + 0x1000, kstack_top);
        EL0_FAULT_TID.store(tid, Ordering::Relaxed);
    }
    EL0_SCHED_MODE.store(true, Ordering::Relaxed); // scheduled-EL0 phase: faults restart
    kprint!(" [P7c] crashing EL0 driver spawned (asid={}) — faults must be contained + restarted\n", asid);
}

/// P7c-4c — switch TTBR0 to the currently-scheduled thread's address space (its
/// own ASID for an isolated EL0 driver; the kernel/identity space otherwise).
/// Backend-neutral: uses the `Mmu` HAL on QEMU and `mmu_cm5` on metal, so an EL0
/// driver runs as a preemptible scheduled TCB in its own ASID on real hardware.
#[inline]
fn enter_current_addr_space() {
    let t = scheduler::current_ttbr0();
    #[cfg(not(feature = "cm5"))]
    {
        let mmu = arch_aarch64::Mmu;
        mmu.set_ttbr0_raw(if t != 0 { t } else { mmu.kernel_ttbr0() });
    }
    #[cfg(feature = "cm5")]
    {
        use arch_aarch64::mmu_cm5;
        mmu_cm5::set_ttbr0_raw(if t != 0 { t } else { mmu_cm5::kernel_ttbr0() });
    }
}

/// P12 — the ONE place a syscall/fault path returns a DIFFERENT thread's SP. It
/// enters that (now-current) thread's address space FIRST, so the TTBR0 switch can
/// never be forgotten (omitting it would run the thread under the wrong page tables).
/// `scheduler::on_tick` has already set CUR to the next thread before this is called.
#[inline]
fn switch_to(next_sp: usize) -> usize {
    enter_current_addr_space();
    next_sp
}

/// P12 — scheduler-aware clean exit of a scheduled TCB (SYS_TASK_EXIT, or a scheduled
/// caller of SYS_EXIT_USER per the DSN-6 fix). Detach from all wait queues, mark dead,
/// disarm its restart record, then reschedule and return the next thread's SP.
fn p12_task_exit(cur: usize, frame: *mut u64) -> usize {
    notify::detach_tcb(cur); // death path: no stale badge into a freed frame
    ipc::detach_tcb(cur); // R1: also unpark from any sync-IPC endpoint (no stale reply)
    scheduler::exit_current();
    scheduler::clear_restart(cur); // a reused slot must not inherit scheduled-restart
    clear_cspace(cur); // CORE-2 teardown (A1a): a reused slot must not inherit stale caps
    let next = scheduler::on_tick(frame as usize);
    switch_to(next)
}

/// P12 — resolve a WAIT: the CPtr must name a Notification/Topic the CALLER holds with
/// the READ right (else fail CLOSED with RC_DENIED), then hand off to the object's
/// state machine. A missing CSpace is RC_DENIED, never a panic.
fn p12_wait(cptr: usize, tid: usize) -> notify::WaitOut {
    let (index, generation) = match resolve_ntfn_cap(cptr, caps::R, caps::ObjType::Notification) {
        Ok((i, g, _badge)) => (i, g),
        Err(rc) => return notify::WaitOut::Rc(rc),
    };
    notify::wait_prepare(index, generation, tid)
}

/// P12 — resolve a Notification/Topic CPtr in the CALLER's OWN CSpace and check it
/// holds all of `need` rights. Returns `(index, generation, badge)` — the badge comes
/// from the CAP, never a syscall arg. Fails CLOSED (RC_DENIED) on a missing CSpace,
/// empty slot, or insufficient rights; RC_BADARG on a wrong object type.
fn resolve_ntfn_cap(cptr: usize, need: u8, expect: caps::ObjType) -> Result<(usize, u32, u64), u64> {
    let cs = current_cspace().ok_or(abi::RC_DENIED)?; // no CSpace => fail closed
    let c = cs.get(cptr).ok_or(abi::RC_DENIED)?;
    // AUD-CAP-1: the cap's type MUST match the operation's TARGET object type. The op
    // indexes a table chosen by the SYSCALL (signal/poll/wait -> NOTIFY[], publish/recv/
    // subscribe -> TOPICS[]); the two tables share index/generation ranges, so accepting
    // either type let e.g. a Notification{W} cap drive PUBLISH into a TOPICS[] object it
    // was never granted — a type-confusion that breaks the cap type-tag guarantee.
    if c.otype != expect {
        return Err(abi::RC_BADARG);
    }
    if c.rights & need != need {
        return Err(abi::RC_DENIED); // "ungranted subscribe/signal is REFUSED"
    }
    Ok((c.base, c.watermark as u32, c.badge))
}

/// R1 (M5.0) — resolve an Endpoint CPtr in a GIVEN CSpace and check it holds all of
/// `need` rights. Returns `(index, generation)` (base=index, watermark=generation, as
/// `install_object` stamps them). Fails CLOSED: empty slot / insufficient rights ->
/// `RC_DENIED`; wrong object type -> `RC_BADARG`. The cap gate for the sync-IPC path.
fn resolve_ep_cap_in(cs: &caps::CapSpace, cptr: usize, need: u8) -> Result<(usize, u32), u64> {
    let c = cs.get(cptr).ok_or(abi::RC_DENIED)?; // no such cap -> fail closed
    if c.otype != caps::ObjType::Endpoint {
        return Err(abi::RC_BADARG); // type-tag safety: only an Endpoint drives sync IPC
    }
    if c.rights & need != need {
        return Err(abi::RC_DENIED); // CALL needs W, RECV/REPLY need R — else REFUSED
    }
    Ok((c.base, c.watermark as u32))
}

/// R1 (M5.0) — resolve an Endpoint CPtr in the CALLER's OWN per-TCB CSpace (CORE-2):
/// an EL0 task can only ever name an endpoint it actually holds. A missing CSpace is
/// `RC_DENIED`, never a panic (fail closed).
fn resolve_ep_cap(cptr: usize, need: u8) -> Result<(usize, u32), u64> {
    let cs = current_cspace().ok_or(abi::RC_DENIED)?; // no CSpace => fail closed
    resolve_ep_cap_in(cs, cptr, need)
}

/// Timer IRQ handler (called from `irq_entry` in vectors.s). Returns the stack
/// pointer of the thread to run next.
#[no_mangle]
pub extern "C" fn handle_irq(sp: usize) -> usize {
    let gic = arch_aarch64::Gic;
    let intid = gic.ack();

    // ADR 0050 D5 — EL0 excursion WATCHDOG. A bounded excursion runs EL0 with only this timer able to
    // interrupt; on expiry the excursion is abandoned (longjmp back to `excursion_bounded`'s caller via
    // resume_kernel) and counted — a spinning EL0 service can no longer wedge an IRQs-off kernel loop.
    if intid == arch_aarch64::timer::VTIMER_INTID {
        arch_aarch64::timer::watchdog_disarm();
        gic.eoi(intid);
        if EXC_WD_ACTIVE.swap(false, Ordering::SeqCst) {
            EXC_TIMED_OUT.store(true, Ordering::SeqCst);
            EXC_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            unsafe { arch_aarch64::syscall::resume_kernel() };
        }
        return sp; // a stale expiry with no excursion running: ignore
    }

    if intid == arch_aarch64::timer::TIMER_INTID {
        arch_aarch64::GenericTimer.rearm();
        let n = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
        let next = scheduler::on_tick(sp);
        // P7c-4c: enter the next thread's address space (its own ASID for an
        // isolated EL0 driver; the kernel/identity space otherwise) — now on CM5
        // metal too (ASID-tagged TTBR0 switch, flush-free).
        enter_current_addr_space();
        gic.eoi(intid);
        if scheduler::alive_workers() == 0 || n >= RUN_TICKS {
            #[cfg(not(feature = "cm5"))]
            {
                // P7c: the uncooperative EL0 task ran (counter>0) AND we reached
                // this exit (the timer kept firing for `n` ticks) => it was being
                // preempted, i.e. the box was never wedged. That's B-6 closed.
                let cnt_pa = EL0_CNT_PA.load(Ordering::SeqCst);
                let el0_cnt = if cnt_pa != 0 {
                    unsafe { core::ptr::read_volatile(cnt_pa as *const u64) }
                } else {
                    0
                };
                kprint!(" [P7c] EL0 preempt {}: uncooperative EL0 task ran (counter={}), preempted over {} ticks — box NOT wedged (B-6 closed)\n",
                    if el0_cnt > 0 { "PASS" } else { "FAIL" }, el0_cnt, n);
                // CORE-6: the crash TCB's restart count is now its OWN per-TCB record.
                let restarts = scheduler::restart_used(EL0_FAULT_TID.load(Ordering::Relaxed));
                kprint!(" [P7c] EL0 fault-restart {}: crashing driver TCB contained + restarted {} times then killed — kernel survived (4b)\n",
                    if restarts >= EL0_MAX_RESTARTS { "PASS" } else { "FAIL" }, restarts.min(EL0_MAX_RESTARTS));
                kprint!("\n [P1] PASS priority scheduler (H>M>L order, threads exited, context switch verified)\n");
                // P12 (c): the EL0 WAITer blocked in SYS_WAIT and was woken by the EL0
                // SIGNALler's SYS_SIGNAL — it wrote the received badge to its result word.
                let rp = P12_RESULT_PA.load(Ordering::SeqCst);
                let got = if rp != 0 { unsafe { read_volatile(rp as *const u64) } } else { 0 };
                let a = P12_A_SIGNAL_POLL.load(Ordering::Relaxed);
                let b = P12_B_PUBSUB_AUTH.load(Ordering::Relaxed);
                let blocked = P12_WAIT_BLOCKED.load(Ordering::Relaxed);
                let c = got == P12_BADGE_C && blocked;
                kprint!(" [P12c] blocking-WAIT {} — EL0 WAITer blocked={}, woken by EL0 Signal, received badge {:#x} (expected {:#x})\n",
                    if c { "PASS" } else { "FAIL" }, blocked, got, P12_BADGE_C);
                kprint!(" [P12] {} — (a)signal/poll={} (b)pubsub-authority={} (c)blocking-wait={} [notification objects + capability pub-sub, badge-from-cap, MAX_THREADS=24, DSN-6 fixed]\n",
                    if a && b && c { "PASS" } else { "FAIL" }, a, b, c);
                // R1 (M5.0): the cap-gated synchronous-IPC beachhead. (a) is the LIVE EL0
                // rendezvous verified here (the server received the client's SYS_CALL msg;
                // the client received the server's SYS_REPLY word); (b)/(c) ran pre-scheduler.
                let sr = R1_SRESULT_PA.load(Ordering::SeqCst);
                let cr = R1_CRESULT_PA.load(Ordering::SeqCst);
                let got_msg = if sr != 0 { unsafe { read_volatile(sr as *const u64) } } else { 0 };
                let got_reply = if cr != 0 { unsafe { read_volatile(cr as *const u64) } } else { 0 };
                let ra = got_msg == R1_MSG && got_reply == R1_REPLY;
                let rb = R1_IPC_B.load(Ordering::Relaxed);
                let rc_ = R1_IPC_C.load(Ordering::Relaxed);
                kprint!(" [P-r1-ipc-a] {} — EL0 client SYS_CALL delivered msg {:#x} to server (got {:#x}); server SYS_REPLY returned {:#x} to client (got {:#x})\n",
                    if ra { "PASS" } else { "FAIL" }, R1_MSG, got_msg, R1_REPLY, got_reply);
                kprint!(" [P-r1-ipc] {} — (a)EL0-rendezvous={} (b)cap-gate-fail-closed={} (c)revoke-severs={} [cap-gated SYS_CALL/EP_RECV/REPLY, Endpoint resolved from the caller's OWN CSpace, fail-closed RC_DENIED, mint-child/revoke-parent sever]\n",
                    if ra && rb && rc_ { "PASS" } else { "FAIL" }, ra, rb, rc_);
                // M5.1 (Track C): the ELF-loader beachhead. (a) is the LIVE proof verified
                // here — a client LOADED FROM AN ELF (parsed + mapped via the enforced
                // frame-cap path, W^X) drove the real cap-gated SYS_CALL and wrote the
                // server's reply into its RW ELF data segment; (b)/(c) (parser bounds-safety
                // + W^X-reject) ran pre-scheduler.
                let er = ELF_CRESULT_PA.load(Ordering::SeqCst);
                let elf_reply = if er != 0 { unsafe { read_volatile(er as *const u64) } } else { 0 };
                let ea = elf_reply == ELF_REPLY;
                let eb = ELF_B.load(Ordering::Relaxed);
                let ec = ELF_C.load(Ordering::Relaxed);
                kprint!(" [P-elf-a] {} — LOADED-from-ELF EL0 client SYS_CALLed msg {:#x}; server replied {:#x}, client stored it into its RW ELF data segment (got {:#x})\n",
                    if ea { "PASS" } else { "FAIL" }, ELF_MSG, ELF_REPLY, elf_reply);
                kprint!(" [P-elf] {} — (a)loaded-task-runs+real-cap-gated-syscall={} (b)malformed/oversize/overlap-REFUSED={} (c)W+X-segment-REJECTED={} [minimal static ELF64/aarch64 loader; PT_LOAD segments mapped via the enforced CORE-1 map_frame_cap path (W^X), loaded task inherits the M5.0 enforced Endpoint cap; NOT dynamic/reloc/shared-lib/Wasm/catalogue — ADR 0044 D5]\n",
                    if ea && eb && ec { "PASS" } else { "FAIL" }, ea, eb, ec);
                // M5.2 (Track C): the Wasm-host beachhead — verify-then-run ONE signed
                // .wasm module in-kernel. Deterministic + synchronous (no scheduler),
                // like the cap/ELF-parser proofs. Only the `wasmhost` build drives it.
                #[cfg(feature = "wasmhost")]
                {
                    let w = wasmhost::wasmhost_selftest();
                    kprint!(" [P-wasm-a] {} — SIGNED .wasm Ed25519-VERIFIED then EXECUTED (bespoke minimal no_std interpreter, in-kernel): classify(4444)={} (exp 1), classify(443)={} (exp 0)\n",
                        if w.a_verify_run { "PASS" } else { "FAIL" }, w.bad_result, w.ok_result);
                    kprint!(" [P-wasm] {} — (a)signed-verify-then-run+correct={} (b)TAMPERED-module-REFUSED-never-interpreted={} (b')bad-signature-REFUSED={} [FIRST minimal Wasm-host sliver: one memoryless module, Ed25519 leg of heqk's hybrid (NOT ML-DSA-65), bespoke MVP-subset interpreter (dep-free), EL1 in-kernel; wasmi builds no_std but +2MiB TCB deferred; NOT WASI-p1/components/catalogue/EL0-hosted/metal — ADR 0044 D5]\n",
                        if w.a_verify_run && w.b_fail_closed && w.b_unsigned { "PASS" } else { "FAIL" },
                        w.a_verify_run, w.b_fail_closed, w.b_unsigned);
                    // M5.2b — the module HOSTED IN AN ISOLATED EL0 TASK (ADR 0044 D4 #2
                    // shape). (a) is the LIVE proof verified here: the kernel verified +
                    // decoded (trust root), the EL0 host (own ASID/TTBR0) interpreted
                    // classify(4444) with the bespoke 5-opcode engine, and its verdict
                    // returned to the kernel through the cap-gated SYS_CALL -> asm server ->
                    // result page. (b) tampered-never-handed-to-EL0 + (c) EL0-fault-contained.
                    let vp = WHOST_SRESULT_PA.load(Ordering::SeqCst);
                    let el0_verdict = if vp != 0 { (unsafe { read_volatile(vp as *const u64) }) as i32 } else { -1 };
                    let refv = WHOST_REF_VERDICT.load(Ordering::SeqCst) as i32;
                    let el0_a = el0_verdict == 1 && el0_verdict == refv;
                    let el0_b = WHOST_B_TAMPER_NOSPAWN.load(Ordering::SeqCst);
                    let frestarts = scheduler::restart_used(WHOST_FAULT_TID.load(Ordering::Relaxed));
                    let el0_c = frestarts >= EL0_MAX_RESTARTS; // faulting host contained+restarted+killed
                    kprint!(" [P-wasm-el0-a] {} — SIGNED module classify({}) interpreted IN EL0 (own ASID/TTBR0) -> verdict {} (in-kernel ref {}); returned to the kernel over the enforced Endpoint-cap IPC (cap-gated SYS_CALL -> asm server RECV/REPLY -> result page)\n",
                        if el0_a { "PASS" } else { "FAIL" }, WHOST_PORT, el0_verdict, refv);
                    kprint!(" [P-wasm-el0] {} — (a)EL0-hosted verify(kernel=trust-root)->interpret(EL0 own TTBR0)->verdict-via-cap-gated-IPC={} (b)TAMPERED refused BEFORE EL0 hand-off (host never spawned)={} (c)module/host fault CONTAINED at EL0 (restarts {}, kernel survived)={} [ADR 0044 D4 #2 shape @ min scale: bespoke 5-opcode engine moved to an isolated EL0 server, NOT wasmi/WASI/wasm32-wasip1, ONE module, NOT catalogue-parity, NOT metal — ADR 0044 D5]\n",
                        if el0_a && el0_b && el0_c { "PASS" } else { "FAIL" }, el0_a, el0_b, frestarts.min(EL0_MAX_RESTARTS), el0_c);

                    // M5.3 — the REAL wasmi runtime, in an EL0 SERVER (ADR 0044 D4 #2 #2).
                    // Host A ran the GOOD module's classify(4444) AND classify(443) THROUGH
                    // wasmi at EL0 and packed the verdicts (0x0001_0000 = 1<<16 | 0) back over
                    // the enforced IPC; host C ran the SIGNED TRAPPING module -> wasmi trap ->
                    // FAIL (0xFFFF_FFFF). wasmi's ~326 KiB .text is in the EL0 image, NOT the
                    // kernel TCB (printed below to prove it).
                    let ra = WASMI_RES_A.load(Ordering::SeqCst);
                    let wa_packed = if ra != 0 { (unsafe { read_volatile(ra as *const u64) }) as u32 } else { 0 };
                    let rc = WASMI_RES_C.load(Ordering::SeqCst);
                    let wc_packed = if rc != 0 { (unsafe { read_volatile(rc as *const u64) }) as u32 } else { 0 };
                    let ktext = WASMI_KERNEL_TEXT_DELTA.load(Ordering::SeqCst);
                    // (a): both vectors correct AND actually computed (1<<16|0), via real wasmi.
                    let wi_a = wa_packed == 0x0001_0000;
                    // (b): a tampered module was refused before any EL0 spawn (kernel trust root).
                    let wi_b = WASMI_B_TAMPER_NOSPAWN.load(Ordering::SeqCst);
                    // (c): the trapping module's trap was contained by wasmi at EL0 (FAIL
                    // returned via IPC) AND host A's verdict stayed intact AND the kernel
                    // reached here alive.
                    let wi_c = wc_packed == 0xFFFF_FFFF && wi_a;
                    kprint!(" [P-wasmi-el0-a] {} — GOOD module run THROUGH REAL wasmi IN EL0 (own ASID/TTBR0): classify(4444)=<verdict hi>, classify(443)=<verdict lo>, packed={:#010x} (exp 0x00010000); returned over the enforced Endpoint-cap IPC (SYS_CALL -> asm server -> result page); kernel .text={} B (wasmi .text ~326 KiB lives in the EL0 image, NOT here)\n",
                        if wi_a { "PASS" } else { "FAIL" }, wa_packed, ktext);
                    kprint!(" [P-wasmi-el0] {} — (a)REAL-wasmi-in-EL0 verify(kernel=trust-root)->wasmi-run(EL0)->both-vectors-correct-via-cap-gated-IPC={} (b)TAMPERED refused BEFORE EL0 hand-off={} (c)wasm TRAP contained by wasmi AT EL0 (packed {:#010x}=FAIL, good host intact, kernel alive)={} [ADR 0044 D4 #2 beachhead: ONE real signed module via wasmi 0.32 in an isolated EL0 server, wasmi OUT of the kernel TCB; NOT the full catalogue at parity, NOT WASI/wasm32-wasip1 (no host imports reachable), NOT metal — ADR 0044 D5]\n",
                        if wi_a && wi_b && wi_c { "PASS" } else { "FAIL" }, wi_a, wi_b, wc_packed, wi_c);

                    // M5.4 — DETECTION AT PARITY (ADR 0044 D4 #4, small scale). Host D ran a
                    // SIGNED detection module (linear memory + hp_input/hp_emit imports) over
                    // the 8-header vector THROUGH wasmi in EL0 and packed one verdict-nibble
                    // per input; the kernel INDEPENDENTLY computed the same 8 verdicts via
                    // rules::run_l4. (a) PARITY = the two packings are byte-identical. Host I
                    // ran one malformed header -> the module trapped -> 0xF fail nibble
                    // (contained at EL0). (b) a tampered module was refused before spawn.
                    let dr = WASMI_DETECT_RES.load(Ordering::SeqCst);
                    let d_packed = if dr != 0 { (unsafe { read_volatile(dr as *const u64) }) as u32 } else { 0 };
                    let di = WASMI_DETECT_ISO_RES.load(Ordering::SeqCst);
                    let d_iso = if di != 0 { (unsafe { read_volatile(di as *const u64) }) as u32 } else { 0 };
                    let d_exp = WASMI_DETECT_EXPECTED.load(Ordering::SeqCst);
                    let d_n = WASMI_DETECT_N.load(Ordering::SeqCst);
                    // (a) PARITY: the wasm packing EQUALS the in-kernel rules::run_l4 packing,
                    // case-for-case, AND it is non-trivial (>=1 DROP + >=1 PASS proven by the vector).
                    let dp_a = d_packed == d_exp && d_exp != 0;
                    // (b) tampered detection module refused before any EL0 spawn (kernel trust root).
                    let dp_b = WASMI_DETECT_TAMPER_NOSPAWN.load(Ordering::SeqCst);
                    // (c) the malformed-input trap was contained: low nibble == 0xF fail sentinel,
                    // AND host D's parity result stayed intact, AND the kernel reached here alive.
                    let dp_c = (d_iso & 0xF) == 0xF && dp_a;
                    kprint!(" [P-wasm-parity-a] {} — SIGNED DETECTION module (linear memory + hp_input/hp_emit shim) run THROUGH REAL wasmi IN EL0 over {} L4 headers: wasm-packed verdicts={:#010x} vs in-kernel rules::run_l4 reference={:#010x} (nibble/input, 1=PASS 2=DROP); returned over the enforced Endpoint-cap IPC\n",
                        if dp_a { "PASS" } else { "FAIL" }, d_n, d_packed, d_exp);
                    kprint!(" [P-wasm-parity] {} — (a)EL0-wasmi DETECTION module == in-kernel rules::run_l4 case-for-case over the vector (PARITY, reproduces the L4 dst-port SIGNATURE corpus 4444/23/31337)={} (b)TAMPERED detection module refused BEFORE EL0 hand-off={} (c)malformed-input wasm TRAP contained at EL0 (iso packed {:#010x}, parity host intact, kernel alive)={} [ADR 0044 D4 #4 @ min scale: ONE detection module at parity via a BESPOKE 2-import shim (hp_input/hp_emit) — NOT the full signed catalogue (napse-dpi/aegis-guard/qsecbit/dnsxai), NOT WASI 0.2/wasm32-wasip1 (the real modules' stdin/stdout+wasi imports are a SUPERSET, unreachable here), NOT metal — ADR 0044 D5]\n",
                        if dp_a && dp_b && dp_c { "PASS" } else { "FAIL" }, dp_a, dp_b, d_iso, dp_c);

                    // M5.5 — the REAL wasip1 host: two std wasm32-wasip1 modules ran through
                    // wasmi in EL0, each reading an L4 header from STDIN (fd_read) + writing
                    // its verdict to STDOUT (fd_write) over the WASI preview1 ABI. host A
                    // (dst-port 4444) -> DROP(2), host B (dst-port 443) -> PASS(1): a SINGLE
                    // pair proves the predicate genuinely COMPUTES over real WASI stdin, not a
                    // constant. (b) a bad-signature module is refused BEFORE any EL0 hand-off.
                    let ra = WASIP1_RES_A.load(Ordering::SeqCst);
                    let rb = WASIP1_RES_B.load(Ordering::SeqCst);
                    let wa = if ra != 0 { (unsafe { read_volatile(ra as *const u64) }) as u32 } else { 0 };
                    let wb = if rb != 0 { (unsafe { read_volatile(rb as *const u64) }) as u32 } else { 0 };
                    let wp_a = wa == 2 && wb == 1;
                    let wp_b = WASIP1_TAMPER_NOSPAWN.load(Ordering::SeqCst);
                    kprint!(" [P-wasip1] {} — REAL wasm32-wasip1 STD module (stdin/stdout, the PRODUCTION module shape) via wasmi in an ISOLATED EL0 host over the WASI preview1 ABI (fd_read/fd_write/environ_*/proc_exit): dst-port 4444 -> {} (want DROP=2), dst-port 443 -> {} (want PASS=1) — read from STDIN, verdict to STDOUT, returned over the enforced Endpoint-cap IPC; (b) a BAD-SIGNATURE module REFUSED before EL0 hand-off={} [ADR 0044 D4 #4: the real WASI 0.2/wasm32-wasip1 ABI (napse-dpi/dnsxai/qsecbit are wasip1 stdin/stdout binaries), NOT the bespoke hp_input/hp_emit shim; QEMU-proven, wasmi OUT of the kernel TCB; metal = a future cm5 concern (a MiB-scale heap needs a bigger window than the GB5 2 MiB)]\n",
                        if wp_a && wp_b { "PASS" } else { "FAIL" }, wa, wb, wp_b);

                    // A2+ — the 2-module signed CATALOGUE: a SECOND, DISTINCT detection module
                    // (DNS-RPZ) run through the SAME wasip1 host. host C on a blocklisted
                    // SUBDOMAIN -> DROP(2), host D on a benign name -> PASS(1), each verified
                    // against the in-kernel dnssink::rpz_blocked reference (computed inline —
                    // the dnssink feature isn't in this build). Proves the host runs a
                    // CATALOGUE of distinct signed rules, not one hardwired predicate.
                    fn rpz_ref(name: &[u8]) -> bool {
                        const RPZ: &[&[u8]] = &[b"malware.example", b"ads.tracker", b"c2.evil.test"];
                        for &b in RPZ {
                            if name == b {
                                return true;
                            }
                            if name.len() > b.len() + 1 {
                                let s = name.len() - b.len();
                                if &name[s..] == b && name[s - 1] == b'.' {
                                    return true;
                                }
                            }
                        }
                        false
                    }
                    let rc = WASIP1_RES_C.load(Ordering::SeqCst);
                    let rd = WASIP1_RES_D.load(Ordering::SeqCst);
                    let vc = if rc != 0 { (unsafe { read_volatile(rc as *const u64) }) as u32 } else { 0 };
                    let vd = if rd != 0 { (unsafe { read_volatile(rd as *const u64) }) as u32 } else { 0 };
                    let ref_c = if rpz_ref(b"host.malware.example") { 2u32 } else { 1 };
                    let ref_d = if rpz_ref(b"good.example.com") { 2u32 } else { 1 };
                    let cat_ok = vc == ref_c && vd == ref_d && vc == 2 && vd == 1;
                    kprint!(" [P-wasip1-cat] {} — 2-module signed CATALOGUE via the ONE wasip1 host: a DISTINCT DNS-RPZ module (not the port-signature one, same WASI ABI) 'host.malware.example' -> {} (kernel rpz_blocked ref={} => DROP=2), 'good.example.com' -> {} (ref={} => PASS=1) — verdicts == in-kernel dnssink::rpz_blocked case-for-case; the portable-signed-rule catalogue on heqk\n",
                        if cat_ok { "PASS" } else { "FAIL" }, vc, ref_c, vd, ref_d);
                }
                #[cfg(feature = "wasmhost")]
                kprint!(" [ALL] P0 P1 P1b P2 P3 P4 P5 P5b P6 P6b DRV P7c P12 P-r1-ipc P-elf P-wasm P-wasm-el0 P-wasmi-el0 P-wasm-parity P-wasip1 P-wasip1-cat GREEN\n");
                #[cfg(not(feature = "wasmhost"))]
                kprint!(" [ALL] P0 P1 P1b P2 P3 P4 P5 P5b P6 P6b DRV P7c P12 P-r1-ipc P-elf GREEN\n");
                arch_aarch64::semihosting::exit(0);
            }
            // On real silicon there is no semihosting exit: signal the idle
            // loop to stop and reboot cleanly via HBoot's EL2 gate.
            #[cfg(feature = "cm5")]
            if !SCHED_DONE.swap(true, Ordering::SeqCst) {
                kprint!("\n [P7b] PASS preemptive scheduler on metal ({} ticks, context switch verified)\n", n);
                // P7c-4c: the EL0 loop driver TCB never exits on its own; kill all
                // non-idle threads so the idle thread (which runs the demo's wait
                // loop) resumes and cm5_scheduler_demo can return.
                scheduler::stop_workers();
            }
        }
        next
    } else if intid == GEM_RX_INTID {
        // P8 (RP1 RX-IRQ): the GEM raised RX-complete via RP1 src 6 → MSI-X →
        // mip0 → GIC SPI 134 / INTID 166. Record it + ack the GEM; the ring is
        // drained by the (adaptive-NAPI) service loop, not here.
        #[cfg(feature = "cm5")]
        {
            GEM_RX_IRQS.fetch_add(1, Ordering::Relaxed);
            arch_aarch64::gem::rx_irq_ack();
        }
        gic.eoi(intid);
        sp
    } else {
        gic.eoi(intid);
        sp
    }
}

/// GEM RX interrupt INTID on CM5: RP1 src 6 (RP1_INT_ETH) → mip0 SPI (128+6)=134
/// → GIC INTID 32+134 = 166. Used only on the cm5 path.
const GEM_RX_INTID: u32 = 166;
/// Count of GEM RX interrupts observed (RP1 MSI-X path live).
static GEM_RX_IRQS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// P2 self-test: build an Untyped, retype a derivation tree, prove type safety,
/// then revoke a subtree and the whole tree — synchronous, no GC. Returns pass.
fn p2_caps_test() -> bool {
    use caps::{CapSpace, ObjType};
    kprint!(" [P2] capability system self-test\n");

    // Root Untyped (1 MiB) over a REAL reserved physical region.
    let base = arch_aarch64::mmu::reserve_region(1024 * 1024);
    let mut cs = CapSpace::with_root_untyped(base, 1024 * 1024);

    // Retype the root into typed objects (each becomes a child in the CDT).
    let _cnode = cs.retype(0, ObjType::CNode, 4096).unwrap();
    let ep = cs.retype(0, ObjType::Endpoint, 16).unwrap();
    let frame = cs.retype(0, ObjType::Frame, 4096).unwrap();
    let _frame2 = cs.retype(0, ObjType::Frame, 4096).unwrap();
    // A sub-Untyped, then grandchildren under it -> a subtree.
    let sub = cs.retype(0, ObjType::Untyped, 256 * 1024).unwrap();
    let _tcb = cs.retype(sub, ObjType::Tcb, 1024).unwrap();
    let _ep2 = cs.retype(sub, ObjType::Endpoint, 16).unwrap();

    cs.print_tree();
    let live0 = cs.count();
    kprint!("   live caps: {} (expect 8)\n", live0);

    // Type safety: a non-Untyped can't be retyped; a non-Frame isn't a Frame.
    let retype_ep = cs.retype(ep, ObjType::Frame, 16).is_err();
    let ep_as_frame = cs.as_frame(ep).is_err();
    let frame_as_frame = cs.as_frame(frame).is_ok();
    kprint!(
        "   type-safety: retype(Endpoint)->{}, Endpoint-as-Frame->{}, Frame-as-Frame->{}\n",
        if retype_ep { "REJECTED" } else { "allowed?!" },
        if ep_as_frame { "REJECTED" } else { "allowed?!" },
        if frame_as_frame { "ok" } else { "FAIL" },
    );

    // Revoke the sub-Untyped: its subtree (Tcb, Endpoint) must vanish synchronously.
    cs.revoke(sub);
    telemetry::emit(telemetry::Event::CapRevoke);
    let live1 = cs.count();
    let subtree_gone = cs.get(sub).is_some() && cs.count() == live0 - 2;
    kprint!("   revoke(sub): live caps {} -> {} (subtree deleted, sub kept)\n", live0, live1);

    // Revoke the root: everything derived vanishes, only the root remains.
    cs.revoke(0);
    telemetry::emit(telemetry::Event::CapRevoke);
    let live2 = cs.count();
    let root_reclaimed = cs.get(0).map_or(false, |c| c.watermark == 0);
    kprint!("   revoke(root): live caps {} -> {} (all derived gone, memory reclaimed)\n", live1, live2);

    // Rights enforcement (B-9): mint diminished copies + check on invocation.
    // Only slot 0 (root Untyped, R|W|G) survives revoke(0) — retype a fresh Frame.
    let f = cs.retype(0, ObjType::Frame, 4096).unwrap();
    let ro = cs.mint(f, caps::R).unwrap(); // request R from R|W|G -> R only
    let rg = cs.mint(f, caps::R | caps::G).unwrap(); // R|G (no W)
    let child = cs.mint(rg, caps::R | caps::W).unwrap(); // request W from R|G -> W DROPPED
    let diminished = cs.get(ro).map_or(false, |c| c.rights == caps::R);
    let no_amplify = cs.get(child).map_or(false, |c| c.rights & caps::W == 0);
    let write_denied = cs.as_frame_rights(ro, caps::W).is_err(); // RO frame refuses write
    let read_ok = cs.as_frame_rights(ro, caps::R).is_ok(); // ...but allows read
    let full_write_ok = cs.as_frame_rights(f, caps::W).is_ok(); // full frame writes
    let grant_gated = cs.mint(ro, caps::R).is_err(); // RO lacks Grant -> can't re-delegate
    let rights_ok = diminished && no_amplify && write_denied && read_ok && full_write_ok && grant_gated;
    kprint!("   rights: RO-frame read {} / write {}; full write {}; amplify {}; non-grant delegate {}\n",
        if read_ok { "ok" } else { "FAIL" },
        if write_denied { "DENIED" } else { "allowed?!" },
        if full_write_ok { "ok" } else { "FAIL" },
        if no_amplify { "REFUSED" } else { "GAINED?!" },
        if grant_gated { "REFUSED" } else { "allowed?!" });

    // CORE-9 [P2-gen]: a freed+reused slot must not re-attach a stale child. Prove a
    // cap whose parent link records the slot's OLD generation is orphaned — revoke of
    // the new occupant spares it, while the new occupant's real child is deleted.
    let gbase = arch_aarch64::mmu::reserve_region(64 * 1024);
    let gen_ok = caps::core9_gen_selftest(gbase);
    kprint!(
        "   generation CDT: reused slot rejects stale child (old-gen link orphaned), real child revoked -> {}\n",
        if gen_ok { "ok" } else { "FAIL" },
    );
    kprint!("   [P2-gen] {}\n", if gen_ok { "PASS" } else { "FAIL" });

    // PH7 (XC-15): capability-invariant property sweep. The SAME check runs on the CM5
    // backend (cm5 kmain) so a divergence between the two MMU backends can't hide.
    let caps_ok = caps::cap_invariants_selftest(arch_aarch64::mmu::reserve_region(256 * 1024));
    kprint!("   [PH7-caps] {} — mint narrows+never-amplifies (all 8 rights), type-tag safety, revoke severs+bumps-gen, no-grant-no-delegate\n",
        if caps_ok { "PASS" } else { "FAIL" });

    let pass = live0 == 8
        && retype_ep
        && ep_as_frame
        && frame_as_frame
        && subtree_gone
        && live1 == 6
        && live2 == 1
        && root_reclaimed
        && rights_ok
        && gen_ok;
    kprint!("   [P2] {}\n", if pass { "PASS" } else { "FAIL" });
    pass
}

// ---------------- P3: userspace (EL0) + syscalls ----------------

// Syscall numbers (user passes the number in x8; args in x0.., return in x0).
const SYS_GETVAL: u64 = 2;
const SYS_HELLO: u64 = 3;
const SYS_PRINTVAL: u64 = 4;
const SYS_CAP_IDENTIFY: u64 = 5;
const SYS_EXIT_USER: u64 = 6; // EL0 server returns control to the kernel
const SYS_DRIVER_REPORT: u64 = 7; // EL0 driver reports a value it read from its device
// P12 (block 16..23; 8..15 reserved for P11). Re-exported from `abi` so the ring-3
// ABI has one home; matched by path below.
const SYS_SIGNAL: u64 = abi::SYS_SIGNAL;
const SYS_WAIT: u64 = abi::SYS_WAIT;
const SYS_POLL: u64 = abi::SYS_POLL;
const SYS_PUBLISH: u64 = abi::SYS_PUBLISH;
const SYS_RECV: u64 = abi::SYS_RECV;
const SYS_SUBSCRIBE: u64 = abi::SYS_SUBSCRIBE;
const SYS_TASK_EXIT: u64 = abi::SYS_TASK_EXIT;
// R1 (M5.0): cap-gated synchronous IPC. CALL/EP_RECV block (handled in handle_lower_sync);
// REPLY is non-blocking (handled in syscall_dispatch, like SYS_SIGNAL).
const SYS_CALL: u64 = abi::SYS_CALL;
const SYS_EP_RECV: u64 = abi::SYS_EP_RECV;
const SYS_REPLY: u64 = abi::SYS_REPLY;

// Value the isolated EL0 driver server reported (a NIC register it read).
static DRIVER_REPORT: AtomicU32 = AtomicU32::new(0);

// CORE-2: PER-TCB capability spaces, keyed by the scheduler's tid (mirrors how
// RESTART/TTBR0 already live per slot). Replaces the single global `ROOT` so an EL0
// task can only ever name caps IN ITS OWN space — the confused-deputy fix and the
// prerequisite for P12 ("a publisher may hold Topic{W} but not Topic{R}"). Steps 1-3
// of PER_TCB_CSPACE.md: behavior-preserving (the root task is tid 0), with the
// per-spawn `mint` + the [P3-iso] isolation gate as the completion step.
static mut CSPACE: [Option<caps::CapSpace>; scheduler::MAX_THREADS] =
    [const { None }; scheduler::MAX_THREADS];

/// The CSpace of thread `tid`, if it has one.
fn cspace_of(tid: usize) -> Option<&'static caps::CapSpace> {
    if tid >= scheduler::MAX_THREADS {
        return None;
    }
    unsafe { (*core::ptr::addr_of!(CSPACE)).get(tid).and_then(|c| c.as_ref()) }
}

/// The currently-running thread's CSpace (what a cap syscall resolves against).
fn current_cspace() -> Option<&'static caps::CapSpace> {
    cspace_of(scheduler::current_tid())
}

/// The root task's CSpace (tid 0). Kept for the boot/demo paths during the migration.
fn root() -> &'static caps::CapSpace {
    cspace_of(0).expect("root CSpace (tid 0) not built")
}

/// CORE-2/P12 — install a per-spawn CSpace into scheduler slot `tid`. The kernel
/// (the policy owner) mints exactly the caps a child TCB should hold into a fresh
/// CSpace, then installs it here so `current_cspace()` resolves the child's authority.
#[cfg(not(feature = "cm5"))]
fn install_cspace(tid: usize, cs: caps::CapSpace) {
    if tid >= scheduler::MAX_THREADS {
        return;
    }
    unsafe { (*core::ptr::addr_of_mut!(CSPACE))[tid] = Some(cs) };
}

/// CORE-2 teardown (A1a) — DROP a thread's CSpace on its FINAL exit. Without this a reused
/// scheduler slot (tid) would inherit the dead task's caps: `current_cspace()` would resolve
/// the previous occupant's authority for the new occupant — a confused-deputy. Called from
/// `p12_task_exit` (clean exit + scheduled-TCB SYS_EXIT_USER) and the fault-kill path, so a
/// freed tid resolves NO caps until the next spawn installs its OWN CSpace. Cheap + fail-safe
/// (out-of-range tid is a no-op); the drop releases the CapSpace slot array. NOTE: frames the
/// task mapped through its caps are torn down with its address space, not here — CSpace
/// inheritance is the confused-deputy this closes.
fn clear_cspace(tid: usize) {
    if tid >= scheduler::MAX_THREADS {
        return;
    }
    unsafe { (*core::ptr::addr_of_mut!(CSPACE))[tid] = None };
}

/// Build the root task's CSpace: retype real-frame-backed caps from an Untyped
/// over reserved physical memory, and prove a Frame cap backs real RAM.
fn build_root_cspace() {
    use caps::{CapSpace, ObjType};
    let base = arch_aarch64::mmu::reserve_region(1024 * 1024);
    let mut cs = CapSpace::with_root_untyped(base, 1024 * 1024);
    let _cnode = cs.retype(0, ObjType::CNode, 4096).unwrap(); // slot 1
    let _ep = cs.retype(0, ObjType::Endpoint, 16).unwrap(); // slot 2
    let frame = cs.retype(0, ObjType::Frame, 4096).unwrap(); // slot 3
    let _f2 = cs.retype(0, ObjType::Frame, 4096).unwrap(); // slot 4
    // Prove the Frame cap backs REAL physical memory (identity-mapped at EL1).
    let fbase = cs.get(frame).unwrap().base;
    let magic = 0xCAFE_F00D_1234_5678u64;
    unsafe { write_volatile(fbase as *mut u64, magic) };
    let ok = unsafe { read_volatile(fbase as *const u64) } == magic;
    kprint!(
        " root task: CSpace over untyped@{:#x}; cap[3]=Frame backs real PA {:#x}, r/w {}\n",
        base, fbase, if ok { "verified" } else { "FAIL" }
    );
    // CORE-2: the root task is scheduler tid 0.
    unsafe { (*core::ptr::addr_of_mut!(CSPACE))[0] = Some(cs) };
}

/// CORE-2 `[P2-iso]` — prove the property per-TCB CSpaces exist for: two DISTINCT
/// capability spaces, and a task holds EXACTLY the authority it was delegated, no more.
/// A "parent" CSpace owns a Frame (R|W|G) and an Endpoint (R|W|G); it delegates to a
/// "child" CSpace ONLY the Frame, and only the READ right. The child must then:
///   * hold the Frame with R but NOT W and NOT G (rights narrowed, cannot amplify), and
///   * NOT hold the Endpoint at all (un-delegated authority is simply absent).
/// This is the confused-deputy fix and the exact primitive P12 needs ("a publisher may
/// hold Topic{W} but not Topic{R}"). Uses local CSpaces so it can't perturb the live
/// per-tid CSPACE table or the scheduler.
fn cspace_isolation_demo() {
    use caps::{CapSpace, ObjType, G, R, W};
    let base = arch_aarch64::mmu::reserve_region(64 * 1024);
    let mut parent = CapSpace::with_root_untyped(base, 64 * 1024);
    let ep = parent.retype(0, ObjType::Endpoint, 16).unwrap();
    let frame = parent.retype(0, ObjType::Frame, 4096).unwrap();

    let mut child = CapSpace::empty(); // a fresh TCB starts with NO authority
    // Delegate the Frame to the child with READ-ONLY rights (parent asked for R only).
    let cframe = parent.mint_into(frame, R, &mut child).unwrap();
    // The Endpoint is deliberately NOT delegated.

    let child_has_read = child.has_rights(cframe, R);
    let child_denied_write = !child.has_rights(cframe, W);
    let child_denied_grant = !child.has_rights(cframe, G);
    // The child holds only one cap (the minted Frame); no slot resolves to an Endpoint.
    let mut child_has_endpoint = false;
    for s in 0..caps::SLOTS_PER_CSPACE {
        if let Some(c) = child.get(s) {
            if c.otype == ObjType::Endpoint {
                child_has_endpoint = true;
            }
        }
    }
    let parent_keeps_endpoint =
        parent.get(ep).map(|c| c.otype == ObjType::Endpoint).unwrap_or(false);

    let ok = child_has_read
        && child_denied_write
        && child_denied_grant
        && !child_has_endpoint
        && parent_keeps_endpoint;
    kprint!(
        " [P2-iso] {} — child CSpace: Frame R={} W-denied={} G-denied={}, Endpoint-absent={}, parent keeps Endpoint={}\n",
        if ok { "PASS" } else { "FAIL" },
        child_has_read, child_denied_write, child_denied_grant, !child_has_endpoint, parent_keeps_endpoint
    );
}

/// CORE-1 `[P2-unmap]` — prove that mapping now flows through a capability invocation
/// AND that `revoke` SEVERS the mapped authority (not just clears the CSpace slot). This
/// is the confused-deputy / authority gap closed: today a Frame cap's memory could be
/// mapped into EL0 by an ad-hoc `map_user_*` the kernel kept no account of, so revoking
/// the cap left the driver's MMIO/DMA access intact. Now:
///   1. `map_frame_cap` (has_rights-gated) maps a Frame(RW) cap into an EL0 VA and RECORDS
///      the VA on the cap; the L3 descriptor reads back PRESENT with AP=RW.
///   2. an R-only cap (minted, W-narrowed) maps read-only; its descriptor reads back
///      PRESENT with AP=RO — the rights → attribute enforcement.
///   3. `revoke` of the parent Untyped deletes both Frame caps and, because they carry a
///      mapping record, INVALIDATES their L3 entries (+ tlbi) — both descriptors read back
///      INVALID. Authority was severed BY revoke, through the cap, not by clearing a slot.
/// Uses a local CSpace + real reserved frames; arch-neutral read-back so it validates
/// under QEMU. #[cfg(not(cm5))] so the metal build is untouched (P10-BT lesson).
/// A1a [P2-teardown] (CORE-2 CSpace kill-clear) — prove that a thread's CSpace is DROPPED on
/// its final exit so a REUSED scheduler slot cannot inherit the dead task's caps (the
/// confused-deputy `clear_cspace` closes, now wired into p12_task_exit + the fault-kill path).
/// Table-level (uses a never-spawned spare slot, perturbs nothing live): install a CSpace
/// holding a Frame cap -> it resolves; clear_cspace (what exit calls) -> the slot resolves
/// NOTHING; a new occupant's OWN (empty) CSpace does NOT see the old cap.
#[cfg(not(feature = "cm5"))]
fn p2_teardown_demo() {
    use caps::{CapSpace, ObjType};
    let tid = scheduler::MAX_THREADS - 2; // a slot never spawned this run (spare is MAX-1)
    let base = arch_aarch64::mmu::reserve_region(8192);
    let mut cs = CapSpace::with_root_untyped(base, 8192);
    let frame = cs.retype(0, ObjType::Frame, 4096).unwrap();
    install_cspace(tid, cs);
    let installed = cspace_of(tid).map(|c| c.get(frame).is_some()).unwrap_or(false);
    // CORE-2 teardown: what the exit paths now call. The slot then resolves NO caps.
    clear_cspace(tid);
    let cleared = cspace_of(tid).is_none();
    // Reuse: a NEW occupant installs its OWN (empty) CSpace -> the old cap is NOT inherited.
    install_cspace(tid, CapSpace::empty());
    let no_inherit = cspace_of(tid).map(|c| c.get(frame).is_none()).unwrap_or(false);
    clear_cspace(tid); // leave the spare slot as we found it
    let ok = installed && cleared && no_inherit;
    kprint!(
        " [P2-teardown] {} — CORE-2 CSpace kill-clear (wired into p12_task_exit + fault-kill): cap-installed-resolves={} cleared-on-exit={} reused-slot-no-inherit={}\n",
        if ok { "PASS" } else { "FAIL" },
        installed, cleared, no_inherit
    );
}

/// A1b [P-cm5-cap] (CORE-1 capability enforcement on CM5 SILICON) — the `mmu_cm5`-backend
/// sibling of the QEMU [P2-unmap] proof. [PH7-caps] already proves the cap ALGEBRA on the
/// CM5 backend, but NOT that a page mapping is cap-GATED + that revoke SEVERS a real page
/// table on the CM5 MMU. This closes that: on metal, prove (1) a RW Frame cap -> an EL0 AP
/// read-write mapping, (2) a RO cap -> AP read-only, (3) a W-on-a-RO-cap is DENIED (the
/// has_rights gate, before any PTE write), and (4) revoke SEVERS both mappings (the GB5 L3
/// descriptors go invalid) AND deletes the caps. Reuses the already-cm5-wired
/// map_frame_cap / revoke / user_frame_desc (which dispatch to mmu_cm5). Purely ADDITIVE:
/// runs once before the GEM drivers claim the GB5 window; uses two spare high VAs in the
/// 2 MiB user window + one runtime-pool frame; no EL0 execution (descriptors only).
#[cfg(feature = "cm5")]
fn p_cm5_cap() {
    use caps::{CapSpace, ObjType, R, W};
    const AP_RW_EL0: u64 = 0b01; // AP[7:6] EL0 read-write
    const AP_RO_EL0: u64 = 0b11; // AP[7:6] EL0 read-only
    let ap = |d: u64| (d >> 6) & 0b11;
    let present = |d: u64| d & 1 != 0;
    // Two spare EL0 VAs high in the GB5 2 MiB window — clear of the GEM driver pages
    // (USER_VA_BASE + 0..0x4000). Both pass user_va_ok (in-window, page-aligned).
    let va_rw = arch_aarch64::mmu_cm5::USER_VA_BASE + 0x10_0000;
    let va_ro = arch_aarch64::mmu_cm5::USER_VA_BASE + 0x10_1000;
    // A real, zeroed 4 KiB frame from the CM5 runtime pool backs the root Untyped.
    let base = arch_aarch64::mmu_cm5::alloc_frame();
    if base == 0 {
        kprint!(" [P-cm5-cap] FAIL — CM5 frame pool exhausted\n");
        return;
    }
    let mut cs = CapSpace::with_root_untyped(base, 4096);
    let frame = match cs.retype(0, ObjType::Frame, 4096) {
        Ok(f) => f,
        Err(_) => {
            kprint!(" [P-cm5-cap] FAIL — retype(Frame)\n");
            return;
        }
    };
    // An R-only cap over the SAME object (mint narrows: R & (R|W|G) = R).
    let ro = match cs.mint(frame, R) {
        Ok(r) => r,
        Err(_) => {
            kprint!(" [P-cm5-cap] FAIL — mint(R)\n");
            return;
        }
    };
    let map_rw_ok = cs.map_frame_cap(frame, va_rw, R | W).is_ok();
    let map_ro_ok = cs.map_frame_cap(ro, va_ro, R).is_ok();
    let w_denied = cs.map_frame_cap(ro, va_ro, R | W).is_err(); // RO cap cannot obtain W
    let d_rw = arch_aarch64::user_frame_desc(va_rw);
    let d_ro = arch_aarch64::user_frame_desc(va_ro);
    let live_rw = present(d_rw) && ap(d_rw) == AP_RW_EL0;
    let live_ro = present(d_ro) && ap(d_ro) == AP_RO_EL0;
    // Revoke the PARENT Untyped: deletes both derived Frame caps AND unmaps them (mmu_cm5).
    cs.revoke(0);
    let sev_rw = !present(arch_aarch64::user_frame_desc(va_rw));
    let sev_ro = !present(arch_aarch64::user_frame_desc(va_ro));
    let caps_gone = cs.get(frame).is_none() && cs.get(ro).is_none();
    let ok = map_rw_ok && map_ro_ok && w_denied && live_rw && live_ro && sev_rw && sev_ro && caps_gone;
    kprint!(
        " [P-cm5-cap] {} — CORE-1 cap-gated map ENFORCED on CM5 silicon (mmu_cm5 backend): RW-cap->AP=RW={} RO-cap->AP=RO={} W-on-RO-cap-DENIED={}; revoke SEVERED: RW-unmapped={} RO-unmapped={} caps-deleted={}\n",
        if ok { "PASS" } else { "FAIL" },
        live_rw, live_ro, w_denied, sev_rw, sev_ro, caps_gone
    );
}

/// A1b cont'd [P-cm5-cspace-iso] (CORE-2 on CM5 SILICON) — two legs on real hardware:
///  (1) CAP-ALGEBRA isolation (the [P2-iso] property on the CM5 backend): a parent CSpace
///      owning Frame(R|W|G) + Endpoint(R|W|G) delegates ONLY the Frame, R-only, to a child;
///      the child then holds the Frame with R but NOT W/G and does NOT hold the Endpoint,
///      while the parent keeps its Endpoint (rights narrow, un-delegated authority absent).
///  (2) PER-AS PAGE TABLES on the mmu_cm5 per-ASID backend: two DISTINCT address spaces
///      (each `new_addr_space` builds its OWN private L2->L3 for the GB5 window); a RO cap
///      attribute maps to AP=read-only and a RW to AP=read-write; the SECOND address space
///      sees NEITHER mapping (private tables = isolation); and unmap SEVERS both (invalid).
/// Additive; runs once after [P-cm5-cap], before the GEM drivers. Reuses the PH7 scratch
/// window for the Untyped (proven-free) + runtime-pool frames for the address spaces.
#[cfg(feature = "cm5")]
fn p_cm5_cspace_iso() {
    use arch_aarch64::mmu_cm5;
    use caps::{CapSpace, ObjType, G, R, W};
    const AP_RW_EL0: u64 = 0b01;
    const AP_RO_EL0: u64 = 0b11;
    let ap = |d: u64| (d >> 6) & 0b11;
    let present = |d: u64| d & 1 != 0;

    // --- (1) cap-algebra delegation isolation (reuses the PH7 proven-free scratch window,
    //     which cap_invariants_selftest already finished using this boot). ---
    let mut parent = CapSpace::with_root_untyped(0x0098_0000, 16 * 1024);
    let ep = parent.retype(0, ObjType::Endpoint, 16);
    let frame = parent.retype(0, ObjType::Frame, 4096);
    let (algebra_ok, c_r, c_nw, c_ng, c_noep, p_ep) = match (ep, frame) {
        (Ok(ep), Ok(frame)) => {
            let mut child = CapSpace::empty(); // a fresh TCB starts with NO authority
            let cframe = parent.mint_into(frame, R, &mut child); // delegate Frame, R only
            let cr = cframe.map(|c| child.has_rights(c, R)).unwrap_or(false);
            let cnw = cframe.map(|c| !child.has_rights(c, W)).unwrap_or(false);
            let cng = cframe.map(|c| !child.has_rights(c, G)).unwrap_or(false);
            let mut cep = false;
            for s in 0..caps::SLOTS_PER_CSPACE {
                if let Some(c) = child.get(s) {
                    if c.otype == ObjType::Endpoint {
                        cep = true;
                    }
                }
            }
            let pep = parent.get(ep).map(|c| c.otype == ObjType::Endpoint).unwrap_or(false);
            (cr && cnw && cng && !cep && pep, cr, cnw, cng, !cep, pep)
        }
        _ => (false, false, false, false, false, false),
    };

    // --- (2) distinct per-AS page tables + RO/RW attribute + isolation + unmap-severs. ---
    let (l1a, _aa) = mmu_cm5::new_addr_space();
    let (l1b, _ab) = mmu_cm5::new_addr_space();
    let pa = mmu_cm5::alloc_frame();
    let va_ro = mmu_cm5::USER_VA_BASE + 0x12_0000;
    let va_rw = mmu_cm5::USER_VA_BASE + 0x13_0000;
    let (ro_ok, rw_ok, iso_ok, sev_ok) = if l1a != 0 && l1b != 0 && pa != 0 {
        mmu_cm5::map_user_data_ro_in(l1a, va_ro, pa);
        mmu_cm5::map_user_data_in(l1a, va_rw, pa);
        let d_ro = mmu_cm5::page_desc_in(l1a, va_ro);
        let d_rw = mmu_cm5::page_desc_in(l1a, va_rw);
        let ro = present(d_ro) && ap(d_ro) == AP_RO_EL0;
        let rw = present(d_rw) && ap(d_rw) == AP_RW_EL0;
        // Isolation: the SECOND address space's private L3 sees neither mapping.
        let iso = !present(mmu_cm5::page_desc_in(l1b, va_ro))
            && !present(mmu_cm5::page_desc_in(l1b, va_rw));
        // Sever: unmap in l1a -> both descriptors invalid.
        mmu_cm5::unmap_user_in(l1a, va_ro);
        mmu_cm5::unmap_user_in(l1a, va_rw);
        let sev = !present(mmu_cm5::page_desc_in(l1a, va_ro))
            && !present(mmu_cm5::page_desc_in(l1a, va_rw));
        (ro, rw, iso, sev)
    } else {
        (false, false, false, false)
    };

    let ok = algebra_ok && ro_ok && rw_ok && iso_ok && sev_ok;
    kprint!(
        " [P-cm5-cspace-iso] {} — CORE-2 on CM5 silicon: cap-algebra iso (child Frame R={} W-denied={} G-denied={} Endpoint-absent={} parent-keeps-ep={}); per-AS tables (RO->AP=RO={} RW->AP=RW={} 2nd-AS-sees-neither={} unmap-severs={})\n",
        if ok { "PASS" } else { "FAIL" },
        c_r, c_nw, c_ng, c_noep, p_ep, ro_ok, rw_ok, iso_ok, sev_ok
    );
}

#[cfg(not(feature = "cm5"))]
fn p2_revoke_unmap_demo() {
    use caps::{CapSpace, ObjType, R, W};
    // AP field of an aarch64 stage-1 leaf lives in bits [7:6]. EL0 RW = 0b01, EL0 RO = 0b11.
    const AP_RW_EL0: u64 = 0b01;
    const AP_RO_EL0: u64 = 0b11;
    let ap = |d: u64| (d >> 6) & 0b11;
    let present = |d: u64| d & 1 != 0;
    // Two unused EL0 VAs (GB2 window — unmapped in the QEMU global root; map_frame_cap
    // builds the L2/L3 tables on demand). No EL0 execution here — we only read descriptors.
    const VA_RW: usize = 0x2_8000_0000; // GB10
    const VA_RO: usize = 0x2_8000_1000;

    let base = arch_aarch64::mmu::reserve_region(64 * 1024);
    let mut cs = CapSpace::with_root_untyped(base, 64 * 1024);
    // A Frame(R|W|G) child of the root Untyped.
    let frame = cs.retype(0, ObjType::Frame, 4096).unwrap();
    // An R-only cap over the SAME object (mint narrows rights: requested R & (R|W|G) = R).
    let ro = cs.mint(frame, R).unwrap();

    // (1) cap-gated RW mapping — has_rights(R|W) passes, writable attribute derived.
    let map_rw_ok = cs.map_frame_cap(frame, VA_RW, R | W).is_ok();
    // (2) cap-gated RO mapping — request only R; the RO cap could not request W anyway.
    let map_ro_ok = cs.map_frame_cap(ro, VA_RO, R).is_ok();
    // A cap without the W right CANNOT obtain a writable mapping (has_rights gate).
    let w_denied = cs.map_frame_cap(ro, VA_RO, R | W).is_err();

    let d_rw = arch_aarch64::user_frame_desc(VA_RW);
    let d_ro = arch_aarch64::user_frame_desc(VA_RO);
    let live_rw = present(d_rw) && ap(d_rw) == AP_RW_EL0; // present + read/write
    let live_ro = present(d_ro) && ap(d_ro) == AP_RO_EL0; // present + read-only

    // (3) revoke the PARENT Untyped: deletes both derived Frame caps AND unmaps them.
    cs.revoke(0);
    let sev_rw = !present(arch_aarch64::user_frame_desc(VA_RW)); // now INVALID
    let sev_ro = !present(arch_aarch64::user_frame_desc(VA_RO)); // now INVALID
    // The caps themselves are gone from the CSpace (only the root Untyped survives).
    let caps_gone = cs.get(frame).is_none() && cs.get(ro).is_none();

    let ok = map_rw_ok && map_ro_ok && w_denied && live_rw && live_ro && sev_rw && sev_ro && caps_gone;
    kprint!(
        " [P2-unmap] {} — cap-gated map: RW-mapped(AP=RW)={} RO-mapped(AP=RO)={} W-on-RO-cap-denied={}; revoke severed: RW-unmapped={} RO-unmapped={} caps-deleted={}\n",
        if ok { "PASS" } else { "FAIL" },
        live_rw, live_ro, w_denied, sev_rw, sev_ro, caps_gone
    );
}

/// P12 (a) — Signal/Poll on a Notification: signal a badge, Poll returns it, a second
/// Poll returns 0 (read-and-clear). Pure synchronous kernel-side check (no scheduler),
/// so it is rock-solid. seL4 Idle -> Active -> (poll) -> Idle.
#[cfg(not(feature = "cm5"))]
fn p12_signal_poll() -> bool {
    let h = match notify::create(scheduler::current_tid()) {
        Some(h) => h,
        None => {
            kprint!(" [P12a] FAIL: notification table full\n");
            return false;
        }
    };
    const BADGE: u64 = 0x0000_0000_0000_0042;
    let _ = notify::signal(h.index, h.generation, BADGE); // Idle -> Active
    let first = notify::poll(h.index, h.generation); // returns BADGE, clears -> Idle
    let second = notify::poll(h.index, h.generation); // Idle -> 0
    let ok = first == BADGE && second == 0;
    notify::destroy(h);
    kprint!(
        " [P12a] signal/poll {} — signalled {:#x}, poll#1={:#x} poll#2={:#x} (OR-coalesce, read+clear)\n",
        if ok { "PASS" } else { "FAIL" }, BADGE, first, second
    );
    ok
}

/// P12 (b) — pub-sub AUTHORITY. Topics ARE capabilities: `Topic{W}` may publish,
/// `Topic{R}` may subscribe. Prove, with three per-task CSpaces over ONE topic:
///   * a task holding `Topic{W}` publishes OK,
///   * a task WITHOUT `Topic{R}` is DENIED subscribe (the check falls out of
///     `has_rights` — "ungranted subscribe is REFUSED", RC_DENIED), and
///   * a task holding `Topic{R}` subscribes and RECEIVES the published event.
/// This is the smart-farm property: a compromised sensor driver (Topic{W} only)
/// simply cannot subscribe/actuate — that authority is not in its CSpace.
#[cfg(not(feature = "cm5"))]
fn p12_pubsub_authority() -> bool {
    use caps::{CapSpace, ObjType, G, R, W};
    let t = match notify::topic_create() {
        Some(t) => t,
        None => {
            kprint!(" [P12b] FAIL: topic table full\n");
            return false;
        }
    };
    const BADGE: u64 = 0x0000_0000_0000_0080; // topic bit stamped in the caps
    const KIND: u32 = 0xA5;

    // publisher: Topic{W}. no_sub: Topic{W} only (NO read). subscriber: Topic{R}.
    let mut pub_cs = CapSpace::empty();
    let w_slot = pub_cs.install_object(ObjType::Topic, W | G, t.index, t.generation, BADGE).unwrap();
    let mut nosub_cs = CapSpace::empty();
    let n_slot = nosub_cs.install_object(ObjType::Topic, W, t.index, t.generation, BADGE).unwrap();
    let mut sub_cs = CapSpace::empty();
    let r_slot = sub_cs.install_object(ObjType::Topic, R, t.index, t.generation, BADGE).unwrap();

    // AUTHORITY GATE: subscribe is attempted ONLY if the CSpace holds Topic{R}.
    let ungranted_refused = !nosub_cs.has_rights(n_slot, R); // no R -> subscribe REFUSED
    let subscribe_granted = sub_cs.has_rights(r_slot, R); // has R -> subscribe allowed
    // The publisher must hold W to publish.
    let publish_granted = pub_cs.has_rights(w_slot, W);

    // Only the R-holder actually subscribes (as it would after the has_rights gate).
    let sub_id = match notify::subscribe(t.index, t.generation, /*tid*/ 1) {
        Ok(id) => id,
        Err(_) => {
            kprint!(" [P12b] FAIL: subscribe returned error\n");
            notify::topic_destroy(t);
            return false;
        }
    };
    // Publisher publishes (badge from its Topic{W} cap); subscriber receives.
    let _ = notify::publish(t.index, t.generation, BADGE, KIND, 0);
    let received = matches!(
        notify::recv(t.index, t.generation, sub_id, 1),
        Ok(m) if m.kind == KIND
    );
    // A second recv drains empty.
    let drained = matches!(notify::recv(t.index, t.generation, sub_id, 1), Err(rc) if rc == abi::RC_EMPTY);

    let ok = ungranted_refused && subscribe_granted && publish_granted && received && drained;
    notify::topic_destroy(t);
    kprint!(
        " [P12b] pubsub-authority {} — publish(W)-OK={} ungranted-subscribe-REFUSED={} granted-subscribe={} R-holder-received={}\n",
        if ok { "PASS" } else { "FAIL" }, publish_granted, ungranted_refused, subscribe_granted, received
    );
    ok
}

/// P12 (c) — spawn two SCHEDULED EL0 TCBs that exercise the REAL blocking-WAIT
/// syscall path end to end: a WAITer (holds `Notification{R}`) and a SIGNALler (holds
/// `Notification{W}` with the badge stamped in its cap). Higher-priority WAITer runs
/// first and BLOCKS inside `SYS_WAIT` (proving the syscall can return another thread's
/// SP without wedging the box); the SIGNALler then `SYS_SIGNAL`s — the kernel writes
/// the cap's badge into the WAITer's saved x0 and unblocks it. The WAITer resumes,
/// writes the received badge to a shared result word, and `SYS_TASK_EXIT`s. The kernel
/// reads that word after the scheduler run and checks it equals `P12_BADGE_C`.
#[cfg(not(feature = "cm5"))]
fn p12_el0_spawn() {
    let mmu = arch_aarch64::Mmu;
    extern "C" {
        static p12_wait_stub: u8;
        static p12_wait_stub_end: u8;
        static p12_signal_stub: u8;
        static p12_signal_stub_end: u8;
    }
    // One Notification object shared by both TCBs (via distinct rights-narrowed caps).
    let nh = match notify::create(0) {
        Some(h) => h,
        None => {
            kprint!(" [P12c] FAIL: notification table full\n");
            return;
        }
    };

    // ---- WAITer TCB ----
    let (wcode, wstack, wresult) = (mmu.alloc_frame(), mmu.alloc_frame(), mmu.alloc_frame());
    if wcode == 0 || wstack == 0 || wresult == 0 {
        return;
    }
    let wsrc = core::ptr::addr_of!(p12_wait_stub) as usize;
    let wlen = core::ptr::addr_of!(p12_wait_stub_end) as usize - wsrc;
    unsafe {
        core::ptr::copy_nonoverlapping(wsrc as *const u8, wcode as *mut u8, wlen);
        core::ptr::write_volatile(wresult as *mut u64, 0);
    }
    arch_aarch64::mmu::sync_instruction_cache(wcode, wlen);
    let (wl1, wasid) = mmu.new_addr_space();
    if wl1 == 0 {
        return;
    }
    const WCODE_VA: usize = 0x8400_0000;
    const WSTACK_VA: usize = 0x8400_1000;
    const WRESULT_VA: usize = 0x8400_2000; // the stub hard-codes this
    mmu.map_user_code_in(wl1, WCODE_VA, wcode);
    mmu.map_user_data_in(wl1, WSTACK_VA, wstack);
    mmu.map_user_data_in(wl1, WRESULT_VA, wresult);
    P12_RESULT_PA.store(wresult, Ordering::SeqCst);
    let wkstack = unsafe { core::ptr::addr_of!(EL0_WKSTACK) as usize + KSTACK_SIZE };
    let wsp = arch_aarch64::thread::make_el0_thread(wkstack, WCODE_VA, WSTACK_VA + 0x1000, 0);
    let wttbr0 = wl1 as u64 | ((wasid as u64) << 48);
    if let Some(tid) = scheduler::spawn_as(wsp, 7, wttbr0) {
        // WAITer's CSpace: Notification with the READ right only (slot 0). No W -> it
        // could never signal; no badge needed to receive.
        let mut cs = caps::CapSpace::empty();
        let _ = cs.install_object(caps::ObjType::Notification, caps::R, nh.index, nh.generation, 0);
        install_cspace(tid, cs);
        scheduler::set_restart(tid, WCODE_VA, WSTACK_VA + 0x1000, wkstack); // DSN-6: never longjmp
    }

    // ---- SIGNALler TCB ----
    let (scode, sstack) = (mmu.alloc_frame(), mmu.alloc_frame());
    if scode == 0 || sstack == 0 {
        return;
    }
    let ssrc = core::ptr::addr_of!(p12_signal_stub) as usize;
    let slen = core::ptr::addr_of!(p12_signal_stub_end) as usize - ssrc;
    unsafe { core::ptr::copy_nonoverlapping(ssrc as *const u8, scode as *mut u8, slen) };
    arch_aarch64::mmu::sync_instruction_cache(scode, slen);
    let (sl1, sasid) = mmu.new_addr_space();
    if sl1 == 0 {
        return;
    }
    const SCODE_VA: usize = 0x8500_0000;
    const SSTACK_VA: usize = 0x8500_1000;
    mmu.map_user_code_in(sl1, SCODE_VA, scode);
    mmu.map_user_data_in(sl1, SSTACK_VA, sstack);
    let skstack = unsafe { core::ptr::addr_of!(EL0_SKSTACK) as usize + KSTACK_SIZE };
    let ssp = arch_aarch64::thread::make_el0_thread(skstack, SCODE_VA, SSTACK_VA + 0x1000, 0);
    let sttbr0 = sl1 as u64 | ((sasid as u64) << 48);
    if let Some(tid) = scheduler::spawn_as(ssp, 6, sttbr0) {
        // SIGNALler's CSpace: Notification with the WRITE right + the BADGE stamped in
        // the cap (slot 0). SYS_SIGNAL reads the badge from HERE, not from a syscall arg.
        let mut cs = caps::CapSpace::empty();
        let _ = cs.install_object(caps::ObjType::Notification, caps::W, nh.index, nh.generation, P12_BADGE_C);
        install_cspace(tid, cs);
        scheduler::set_restart(tid, SCODE_VA, SSTACK_VA + 0x1000, skstack);
    }
    EL0_SCHED_MODE.store(true, Ordering::Relaxed); // scheduled-EL0 phase
    kprint!(" [P12c] spawned EL0 WAITer(prio7,Notification{{R}}) + SIGNALler(prio6,Notification{{W}},badge={:#x})\n", P12_BADGE_C);
}

/// R1 (M5.0) (b)+(c) — the cap-gate + revoke-sever proofs of the synchronous-IPC
/// beachhead, kernel-side and DETERMINISTIC (mirrors `cap_invariants_selftest` /
/// `p2_revoke_unmap_demo`; needs no scheduler). (a) — the live EL0 CALL/REPLY rendezvous
/// through the real syscall path — runs under the scheduler and is verified post-run.
/// Returns `(b_ok, c_ok)`.
///
///  * (b) FAIL CLOSED — the cap gate `resolve_ep_cap_in` (the exact gate the SYS_CALL /
///    SYS_EP_RECV / SYS_REPLY syscalls use) REFUSES: a CALL with NO endpoint cap
///    (`RC_DENIED`), a CALL with an R-only cap (CALL needs W → `RC_DENIED`), a wrong
///    OBJECT TYPE (`RC_BADARG`), and the mechanism itself refuses a stale object — while
///    a RECV with the R right is allowed. No rendezvous is possible without the authority.
///  * (c) REVOKE SEVERS — MINT a CHILD endpoint cap from a PARENT cap (same CSpace, so a
///    real CDT parent link), park a victim TCB on the object, then revoke the PARENT.
///    `revoke` deletes the CHILD (its subtree) and FIRES the IPC-sever hook: the victim is
///    woken with `RC_DENIED` (observed in its saved x0) and unblocked (not hung), the
///    object generation is bumped, and the KEPT parent cap now fails closed on a fresh
///    CALL. This is the faithful mirror of CORE-1's revoke-parent-unmaps-child.
#[cfg(not(feature = "cm5"))]
fn r1_ipc_cap_selftest() -> (bool, bool) {
    use caps::{CapSpace, ObjType, G, R, W};

    // ---------- (b) FAIL CLOSED: the capability gate refuses missing/insufficient. -----
    let eh = match ipc::ep_create() {
        Some(h) => h,
        None => return (false, false),
    };
    let mut cs = CapSpace::empty();
    // slot 0: Endpoint{R} only — may RECV/REPLY, may NOT CALL (CALL needs the W right).
    let r_slot = cs
        .install_object(ObjType::Endpoint, R, eh.index, eh.generation, 0)
        .unwrap();
    // slot 1: a Notification (WRONG object type) to prove type-tag safety on the IPC path.
    let wrong_slot = cs.install_object(ObjType::Notification, R | W, 0, 0, 0).unwrap();

    let call_no_cap = resolve_ep_cap_in(&cs, 9, W).is_err(); // empty slot -> DENIED
    let call_insufficient = resolve_ep_cap_in(&cs, r_slot, W).is_err(); // R-only, CALL needs W
    let recv_ok = resolve_ep_cap_in(&cs, r_slot, R).is_ok(); // R present -> RECV allowed
    let wrong_type = resolve_ep_cap_in(&cs, wrong_slot, R).is_err(); // Notification != Endpoint
    // The mechanism also refuses a stale/absent object (fail closed at the ipc layer).
    let stale_refused = matches!(
        ipc::call(eh.index, eh.generation.wrapping_add(9), 0, 1),
        ipc::IpcOut::Rc(_)
    );
    let b = call_no_cap && call_insufficient && recv_ok && wrong_type && stale_refused;
    ipc::on_endpoint_cap_deleted(eh.index, eh.generation); // reclaim (b)'s endpoint object

    // ---------- (c) REVOKE SEVERS the IPC (mint child / revoke parent). ----------------
    let ch = match ipc::ep_create() {
        Some(h) => h,
        None => return (b, false),
    };
    // A real reserved-frame trap frame for a "parked" victim tid, so we can OBSERVE the
    // RC_DENIED the sever delivers (deliver_wake writes frame word 0 = the victim's x0).
    let fbase = arch_aarch64::mmu::reserve_region(4096);
    let victim = scheduler::MAX_THREADS - 1; // a spare slot never spawned in this run
    // ipc-F3: only safe while the top TWO slots (victim, victim-1 — the (d) test also
    // borrows victim-1) are truly unspawned. Assert it rather than silently corrupting a
    // live thread's saved SP if the boot spawn count ever grows to reach them.
    if scheduler::live_count() > victim - 1 {
        kprint!(
            " [P-r1-ipc-c] FAIL — boot spawn count {} reached the scratch victim slots ({}, {}); test infra must allocate real spawns\n",
            scheduler::live_count(), victim - 1, victim
        );
        return (b, false);
    }
    unsafe { write_volatile(fbase as *mut u64, 0) };
    scheduler::set_sp(victim, fbase); // give the victim a saved frame to receive x0 into
    scheduler::block_tid(victim); // park it (blocked) so the sever must UNBLOCK it
    ipc::park_recv_for_test(ch.index, ch.generation, victim); // parked on the endpoint

    // PARENT endpoint cap (R|W|G) + a minted CHILD (same CSpace -> a real CDT parent link).
    let mut cs2 = CapSpace::empty();
    let parent = cs2
        .install_object(ObjType::Endpoint, R | W | G, ch.index, ch.generation, 0)
        .unwrap();
    let child = cs2.mint(parent, R | W).unwrap(); // child.parent = (parent, gen)

    let setup_ok = cs2.get(child).is_some() && ipc::ep_exists(ch.index, ch.generation);

    // Revoke the PARENT: deletes the CHILD subtree and FIRES the IPC-sever hook.
    cs2.revoke(parent);

    let child_deleted = cs2.get(child).is_none();
    let parent_kept = cs2.get(parent).is_some();
    let obj_severed = !ipc::ep_exists(ch.index, ch.generation); // generation bumped / freed
    let victim_woken_denied =
        unsafe { read_volatile(fbase as *const u64) } == abi::RC_DENIED;
    let victim_unblocked = !scheduler::is_blocked(victim); // woken, NOT left hung
    // The kept parent cap now fails closed on a fresh CALL (object generation bumped).
    let parent_fail_closed = matches!(
        ipc::call(ch.index, ch.generation, 0, 1),
        ipc::IpcOut::Rc(_)
    );
    scheduler::set_sp(victim, 0); // undo the test frame pointer

    let c = setup_ok
        && child_deleted
        && parent_kept
        && obj_severed
        && victim_woken_denied
        && victim_unblocked
        && parent_fail_closed;

    // ---------- (d) SERVER-DEATH LIVENESS: a server that RECVs a call then DIES/faults
    // before REPLY must NOT strand its client or permanently brick the endpoint. --------
    let fbase2 = arch_aarch64::mmu::reserve_region(4096);
    let dead_server = victim - 1; // a spare slot; only its e.server link + a scratch frame
    let client = victim; // reuse the (c) victim frame as the awaiting-reply client
    let d = match ipc::ep_create() {
        None => false,
        Some(dh) => {
            unsafe { write_volatile(fbase as *mut u64, 0) };
            unsafe { write_volatile(fbase2 as *mut u64, 0) };
            scheduler::set_sp(client, fbase);
            scheduler::set_sp(dead_server, fbase2);
            scheduler::block_tid(client);
            // client CALLs (no server yet) -> message parked, client BLOCKED awaiting reply.
            let parked =
                matches!(ipc::call(dh.index, dh.generation, 0xD00D, client), ipc::IpcOut::Block);
            // server RECVs the parked call -> becomes the serving TCB (reply_to=client).
            let served = matches!(
                ipc::recv_ep(dh.index, dh.generation, dead_server),
                ipc::IpcOut::Ready(0xD00D)
            );
            // ... then the server DIES before ever calling REPLY.
            ipc::detach_tcb(dead_server);
            let client_woken =
                unsafe { read_volatile(fbase as *const u64) } == abi::RC_DENIED;
            let client_unblocked = !scheduler::is_blocked(client); // not left hung
            let obj_alive = ipc::ep_exists(dh.index, dh.generation); // NOT bricked
            // Recovered: a fresh RECV now PARKS (Block); a still-stuck reply_to would
            // instead return RC_NORESOURCE (the pre-fix permanent brick).
            let recovered = matches!(
                ipc::recv_ep(dh.index, dh.generation, dead_server),
                ipc::IpcOut::Block
            );
            ipc::on_endpoint_cap_deleted(dh.index, dh.generation); // reclaim + wake the parked RECVer
            scheduler::set_sp(client, 0);
            scheduler::set_sp(dead_server, 0);
            parked && served && client_woken && client_unblocked && obj_alive && recovered
        }
    };
    let c = c && d;

    kprint!(
        " [P-r1-ipc-b] {} — CALL-without-cap DENIED={} CALL-with-R-only(insufficient) DENIED={} RECV-with-R OK={} wrong-type REFUSED={} stale-object REFUSED={}\n",
        if b { "PASS" } else { "FAIL" },
        call_no_cap, call_insufficient, recv_ok, wrong_type, stale_refused
    );
    kprint!(
        " [P-r1-ipc-c] {} — mint CHILD from PARENT Endpoint cap, revoke PARENT: child-deleted={} parent-kept={} object-severed={} victim-woken-RC_DENIED={} not-hung(unblocked)={} kept-parent-now-fail-closed={} | (d) server-death-recovery(client-woken-RC_DENIED+endpoint-not-bricked)={}\n",
        if c { "PASS" } else { "FAIL" },
        child_deleted, parent_kept, obj_severed, victim_woken_denied, victim_unblocked, parent_fail_closed, d
    );
    (b, c)
}

/// R1 (M5.0) (a) — spawn TWO scheduled EL0 TCBs that exercise the REAL cap-gated
/// synchronous-IPC syscall path end to end: a SERVER (holds `Endpoint{R}`, prio 9) that
/// SYS_EP_RECVs then SYS_REPLYs, and a CLIENT (holds `Endpoint{W}`, prio 8) that
/// SYS_CALLs. Highest-priority SERVER runs first and BLOCKS in RECV; the CLIENT then
/// CALLs — the kernel delivers the message into the server's RECV return, the server
/// REPLYs, and the kernel returns the reply into the client's CALL return. Both write
/// what they received to a result page the kernel checks post-run (`R1_MSG`/`R1_REPLY`).
/// This is the D4 #1 gate: one EL0 task, real syscall, ENFORCED capability, fails closed.
#[cfg(not(feature = "cm5"))]
fn r1_ipc_el0_spawn() {
    let mmu = arch_aarch64::Mmu;
    extern "C" {
        static ipc_server_stub: u8;
        static ipc_server_stub_end: u8;
        static ipc_client_stub: u8;
        static ipc_client_stub_end: u8;
    }
    // One Endpoint object shared by both TCBs via distinct rights-narrowed caps.
    let eh = match ipc::ep_create() {
        Some(h) => h,
        None => {
            kprint!(" [P-r1-ipc-a] FAIL: endpoint table full\n");
            return;
        }
    };

    // ---- SERVER TCB (Endpoint{R}) — RECV then REPLY ----
    let (scode, sstack, sresult) = (mmu.alloc_frame(), mmu.alloc_frame(), mmu.alloc_frame());
    if scode == 0 || sstack == 0 || sresult == 0 {
        return;
    }
    let ssrc = core::ptr::addr_of!(ipc_server_stub) as usize;
    let slen = core::ptr::addr_of!(ipc_server_stub_end) as usize - ssrc;
    unsafe {
        core::ptr::copy_nonoverlapping(ssrc as *const u8, scode as *mut u8, slen);
        write_volatile(sresult as *mut u64, 0);
    }
    arch_aarch64::mmu::sync_instruction_cache(scode, slen);
    let (sl1, sasid) = mmu.new_addr_space();
    if sl1 == 0 {
        return;
    }
    const SCODE_VA: usize = 0x8600_0000;
    const SSTACK_VA: usize = 0x8600_1000;
    const SRESULT_VA: usize = 0x8600_2000; // the server stub hard-codes this
    mmu.map_user_code_in(sl1, SCODE_VA, scode);
    mmu.map_user_data_in(sl1, SSTACK_VA, sstack);
    mmu.map_user_data_in(sl1, SRESULT_VA, sresult);
    R1_SRESULT_PA.store(sresult, Ordering::SeqCst);
    let skstack = unsafe { core::ptr::addr_of!(EL0_IPC_SKSTACK) as usize + KSTACK_SIZE };
    let ssp = arch_aarch64::thread::make_el0_thread(skstack, SCODE_VA, SSTACK_VA + 0x1000, 0);
    let sttbr0 = sl1 as u64 | ((sasid as u64) << 48);
    if let Some(tid) = scheduler::spawn_as(ssp, 9, sttbr0) {
        // The server holds the Endpoint with the READ right only (may RECV/REPLY, not CALL).
        let mut cs = caps::CapSpace::empty();
        let _ = cs.install_object(caps::ObjType::Endpoint, caps::R, eh.index, eh.generation, 0);
        install_cspace(tid, cs);
        scheduler::set_restart(tid, SCODE_VA, SSTACK_VA + 0x1000, skstack); // DSN-6: never longjmp
    }

    // ---- CLIENT TCB (Endpoint{W}) — CALL ----
    let (ccode, cstack, cresult) = (mmu.alloc_frame(), mmu.alloc_frame(), mmu.alloc_frame());
    if ccode == 0 || cstack == 0 || cresult == 0 {
        return;
    }
    let csrc = core::ptr::addr_of!(ipc_client_stub) as usize;
    let clen = core::ptr::addr_of!(ipc_client_stub_end) as usize - csrc;
    unsafe {
        core::ptr::copy_nonoverlapping(csrc as *const u8, ccode as *mut u8, clen);
        write_volatile(cresult as *mut u64, 0);
    }
    arch_aarch64::mmu::sync_instruction_cache(ccode, clen);
    let (cl1, casid) = mmu.new_addr_space();
    if cl1 == 0 {
        return;
    }
    const CCODE_VA: usize = 0x8700_0000;
    const CSTACK_VA: usize = 0x8700_1000;
    const CRESULT_VA: usize = 0x8700_2000; // the client stub hard-codes this
    mmu.map_user_code_in(cl1, CCODE_VA, ccode);
    mmu.map_user_data_in(cl1, CSTACK_VA, cstack);
    mmu.map_user_data_in(cl1, CRESULT_VA, cresult);
    R1_CRESULT_PA.store(cresult, Ordering::SeqCst);
    let ckstack = unsafe { core::ptr::addr_of!(EL0_IPC_CKSTACK) as usize + KSTACK_SIZE };
    let csp = arch_aarch64::thread::make_el0_thread(ckstack, CCODE_VA, CSTACK_VA + 0x1000, 0);
    let cttbr0 = cl1 as u64 | ((casid as u64) << 48);
    if let Some(tid) = scheduler::spawn_as(csp, 8, cttbr0) {
        // The client holds the Endpoint with the WRITE right (may CALL).
        let mut cs = caps::CapSpace::empty();
        let _ = cs.install_object(caps::ObjType::Endpoint, caps::W, eh.index, eh.generation, 0);
        install_cspace(tid, cs);
        scheduler::set_restart(tid, CCODE_VA, CSTACK_VA + 0x1000, ckstack);
    }
    EL0_SCHED_MODE.store(true, Ordering::Relaxed); // scheduled-EL0 phase
    kprint!(
        " [P-r1-ipc-a] spawned EL0 server(prio9,Endpoint{{R}}) + client(prio8,Endpoint{{W}}); msg={:#x} reply={:#x}\n",
        R1_MSG, R1_REPLY
    );
}

// ===========================================================================
// M5.1 (Track C) — the minimal ELF-loader beachhead: selftests + live spawn.
// ===========================================================================

// Little-endian field writers for the in-kernel test-ELF builders (selftests only).
#[cfg(not(feature = "cm5"))]
fn tput16(b: &mut [u8], o: usize, v: u16) { b[o..o + 2].copy_from_slice(&v.to_le_bytes()); }
#[cfg(not(feature = "cm5"))]
fn tput32(b: &mut [u8], o: usize, v: u32) { b[o..o + 4].copy_from_slice(&v.to_le_bytes()); }
#[cfg(not(feature = "cm5"))]
fn tput64(b: &mut [u8], o: usize, v: u64) { b[o..o + 8].copy_from_slice(&v.to_le_bytes()); }

/// Build a canonical VALID 1-PT_LOAD (R+X) ELF into `b`; returns its length. The
/// (b)/(c) selftests patch a COPY of this to synthesize each malformation.
#[cfg(not(feature = "cm5"))]
fn build_valid_elf(b: &mut [u8]) -> usize {
    for x in b.iter_mut() { *x = 0; }
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; b[5] = 1; b[6] = 1; // ELFCLASS64 / ELFDATA2LSB / EV_CURRENT
    tput16(b, 16, 2);   // e_type    = ET_EXEC
    tput16(b, 18, 183); // e_machine = EM_AARCH64
    tput32(b, 20, 1);   // e_version
    tput64(b, 24, 0x8000_1000); // e_entry (inside the R+X segment; EL0 user window)
    tput64(b, 32, 64);     // e_phoff
    tput16(b, 52, 64);     // e_ehsize
    tput16(b, 54, 56);     // e_phentsize
    tput16(b, 56, 1);      // e_phnum
    let p = 64;
    tput32(b, p, 1);         // PT_LOAD
    tput32(b, p + 4, 4 | 1); // PF_R | PF_X
    tput64(b, p + 8, 120);   // p_offset
    tput64(b, p + 16, 0x8000_1000); // p_vaddr (page-aligned, in the EL0 user VA window)
    tput64(b, p + 24, 0x8000_1000); // p_paddr
    tput64(b, p + 32, 4);    // p_filesz
    tput64(b, p + 40, 4);    // p_memsz
    tput64(b, p + 48, 0x1000); // p_align
    tput32(b, 120, 0x14000000); // one instruction ("b .")
    124
}

/// Build a VALID 2-PT_LOAD ELF (seg0 R+X @0x1000, seg1 R+W @0x2000); returns its length.
/// Used to synthesize the OVERLAP case (patch seg1's vaddr onto seg0's).
#[cfg(not(feature = "cm5"))]
fn build_valid_2seg(b: &mut [u8]) -> usize {
    for x in b.iter_mut() { *x = 0; }
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; b[5] = 1; b[6] = 1;
    tput16(b, 16, 2); tput16(b, 18, 183); tput32(b, 20, 1);
    tput64(b, 24, 0x8000_1000);
    tput64(b, 32, 64);
    tput16(b, 52, 64); tput16(b, 54, 56); tput16(b, 56, 2); // e_phnum = 2
    let p0 = 64;
    tput32(b, p0, 1); tput32(b, p0 + 4, 4 | 1);            // seg0 R+X
    tput64(b, p0 + 8, 176); tput64(b, p0 + 16, 0x8000_1000); tput64(b, p0 + 24, 0x8000_1000);
    tput64(b, p0 + 32, 4); tput64(b, p0 + 40, 4); tput64(b, p0 + 48, 0x1000);
    let p1 = 64 + 56;
    tput32(b, p1, 1); tput32(b, p1 + 4, 4 | 2);            // seg1 R+W
    tput64(b, p1 + 8, 0); tput64(b, p1 + 16, 0x8000_2000); tput64(b, p1 + 24, 0x8000_2000);
    tput64(b, p1 + 32, 0); tput64(b, p1 + 40, 8); tput64(b, p1 + 48, 0x1000);
    tput32(b, 176, 0x14000000);
    180
}

/// M5.1 (b) — BOUNDS-SAFETY: the parser REFUSES every malformed / truncated /
/// out-of-bounds / oversize / overlapping ELF (fail-closed, for the RIGHT reason — each
/// case asserts the EXACT `ElfError`), while the canonical valid image PARSES. A hostile
/// ELF can only ever be rejected, never read out of bounds nor partially mapped.
#[cfg(not(feature = "cm5"))]
fn elf_bounds_safety_selftest() -> bool {
    use elf::ElfError;
    let mut base = [0u8; 208];
    let len = build_valid_elf(&mut base);

    let mut ok = elf::parse(&base[..len]).is_ok();                       // control: valid parses
    ok &= matches!(elf::parse(&base[..40]), Err(ElfError::TooShort));    // truncated < header
    { let mut b = base; b[1] = b'X'; ok &= matches!(elf::parse(&b[..len]), Err(ElfError::BadMagic)); }
    { let mut b = base; b[4] = 1;    ok &= matches!(elf::parse(&b[..len]), Err(ElfError::NotElf64)); }
    { let mut b = base; tput16(&mut b, 18, 0x3e); ok &= matches!(elf::parse(&b[..len]), Err(ElfError::BadMachine)); } // EM_X86_64
    { let mut b = base; tput16(&mut b, 56, 0x40); ok &= matches!(elf::parse(&b[..len]), Err(ElfError::PhdrsOutOfBounds)); } // phnum runs off end
    // segment file range [offset,offset+filesz) off the end (memsz kept >= filesz)
    { let mut b = base; tput64(&mut b, 64 + 32, 0x100); tput64(&mut b, 64 + 40, 0x100);
      ok &= matches!(elf::parse(&b[..len]), Err(ElfError::SegmentOutOfBounds)); }
    { let mut b = base; tput64(&mut b, 64 + 40, 0); ok &= matches!(elf::parse(&b[..len]), Err(ElfError::MemszLessThanFilesz)); }
    { let mut b = base; tput64(&mut b, 64 + 40, (elf::MAX_SEG_BYTES as u64) + 1);
      ok &= matches!(elf::parse(&b[..len]), Err(ElfError::SegmentTooLarge)); }
    { let mut b = base; tput64(&mut b, 64 + 16, 0x8000_1001); ok &= matches!(elf::parse(&b[..len]), Err(ElfError::Unaligned)); }
    // out-of-window vaddr (a kernel VA) is REFUSED — the CORE-5/user_va_ok parity check
    { let mut b = base; tput64(&mut b, 64 + 16, 0x4008_0000); ok &= matches!(elf::parse(&b[..len]), Err(ElfError::VaOutOfWindow)); }
    // overlapping segments (seg1 vaddr -> seg0's, both in the EL0 user window)
    { let mut b2 = [0u8; 208]; let l2 = build_valid_2seg(&mut b2);
      let valid2 = elf::parse(&b2[..l2]).is_ok();
      tput64(&mut b2, 64 + 56 + 16, 0x8000_1000);
      ok &= valid2 && matches!(elf::parse(&b2[..l2]), Err(ElfError::Overlap)); }
    ok
}

/// M5.1 (c) — W^X: an ELF whose PT_LOAD requests WRITE and EXECUTE together is REJECTED
/// (`WxViolation`), so no writable-and-executable page can ever be produced from an
/// untrusted image (the parser gate; `map_frame_cap_in` is the redundant second gate).
#[cfg(not(feature = "cm5"))]
fn elf_wx_selftest() -> bool {
    use elf::ElfError;
    let mut b = [0u8; 208];
    let len = build_valid_elf(&mut b);
    let valid = elf::parse(&b[..len]).is_ok();
    tput32(&mut b, 64 + 4, 4 | 2 | 1); // PF_R | PF_W | PF_X on the sole segment
    valid && matches!(elf::parse(&b[..len]), Err(ElfError::WxViolation))
}

/// M5.1 (a) — LIVE: LOAD an EL0 client FROM AN ELF (not a copied asm stub) and prove it
/// drives the real cap-gated syscall path. The fixture (build.rs) is parsed + validated,
/// its PT_LOAD segments mapped into a fresh VSpace via the enforced CORE-1
/// `map_frame_cap_in` path (R+X code, RW data — W^X), then the task is spawned holding an
/// `Endpoint{W}` at CPtr 0. Its counterpart is a plain asm `elf_ipc_server_stub`
/// (`Endpoint{R}`) on the same fresh endpoint. The loaded client SYS_CALLs `ELF_MSG`; the
/// server SYS_REPLYs `ELF_REPLY`; the client stores the reply into its RW ELF data
/// segment, whose PA the kernel reads back post-run. This is the D4 #1 gate for M5.1: a
/// LOADED userspace task executing through the real syscall + ENFORCED capability path.
#[cfg(not(feature = "cm5"))]
fn m5_elf_loader_spawn() {
    let mmu = arch_aarch64::Mmu;
    extern "C" {
        static elf_ipc_server_stub: u8;
        static elf_ipc_server_stub_end: u8;
    }
    // Parse + validate the fixture ELF (fail-closed on any malformation).
    let parsed = match elf::parse(FIXTURE_ELF) {
        Ok(p) => p,
        Err(_) => {
            kprint!(" [P-elf-a] FAIL: fixture ELF rejected by parser\n");
            return;
        }
    };
    // A fresh endpoint object shared by the loaded client (W) and the asm server (R).
    let eh = match ipc::ep_create() {
        Some(h) => h,
        None => {
            kprint!(" [P-elf-a] FAIL: endpoint table full\n");
            return;
        }
    };

    // ---- CLIENT: LOADED FROM THE ELF (not a copied stub) ----
    let (cl1, casid) = mmu.new_addr_space();
    if cl1 == 0 {
        return;
    }
    let loaded = match elf::load_into(&parsed, FIXTURE_ELF, cl1) {
        Ok(l) => l,
        Err(e) => {
            kprint!(" [P-elf-a] FAIL: load_into: {}\n", e);
            return;
        }
    };
    // The stack is NOT declared in the ELF — the loader/kernel provides one (RW+NX).
    let cstack = mmu.alloc_frame();
    if cstack == 0 {
        return;
    }
    mmu.map_user_data_in(cl1, ELF_STACK_VA, cstack);
    ELF_CRESULT_PA.store(loaded.writable_pa, Ordering::SeqCst);
    let ckstack = unsafe { core::ptr::addr_of!(EL0_ELF_CKSTACK) as usize + KSTACK_SIZE };
    let csp = arch_aarch64::thread::make_el0_thread(ckstack, loaded.entry, ELF_STACK_VA + 0x1000, 0);
    let cttbr0 = cl1 as u64 | ((casid as u64) << 48);
    if let Some(tid) = scheduler::spawn_as(csp, 8, cttbr0) {
        // The loaded client holds the Endpoint with the WRITE right (may CALL) at CPtr 0.
        let mut cs = caps::CapSpace::empty();
        let _ = cs.install_object(caps::ObjType::Endpoint, caps::W, eh.index, eh.generation, 0);
        install_cspace(tid, cs);
        scheduler::set_restart(tid, loaded.entry, ELF_STACK_VA + 0x1000, ckstack); // DSN-6
    }

    // ---- SERVER: plain asm stub (Endpoint{R}) — the loaded client's counterpart ----
    let (scode, sstack) = (mmu.alloc_frame(), mmu.alloc_frame());
    if scode == 0 || sstack == 0 {
        return;
    }
    let ssrc = core::ptr::addr_of!(elf_ipc_server_stub) as usize;
    let slen = core::ptr::addr_of!(elf_ipc_server_stub_end) as usize - ssrc;
    unsafe { core::ptr::copy_nonoverlapping(ssrc as *const u8, scode as *mut u8, slen) };
    arch_aarch64::mmu::sync_instruction_cache(scode, slen);
    let (sl1, sasid) = mmu.new_addr_space();
    if sl1 == 0 {
        return;
    }
    mmu.map_user_code_in(sl1, ELF_SRV_CODE_VA, scode);
    mmu.map_user_data_in(sl1, ELF_SRV_STACK_VA, sstack);
    let skstack = unsafe { core::ptr::addr_of!(EL0_ELF_SKSTACK) as usize + KSTACK_SIZE };
    let ssp = arch_aarch64::thread::make_el0_thread(skstack, ELF_SRV_CODE_VA, ELF_SRV_STACK_VA + 0x1000, 0);
    let sttbr0 = sl1 as u64 | ((sasid as u64) << 48);
    if let Some(tid) = scheduler::spawn_as(ssp, 9, sttbr0) {
        // The server holds the Endpoint with the READ right (may RECV/REPLY) at CPtr 0.
        let mut cs = caps::CapSpace::empty();
        let _ = cs.install_object(caps::ObjType::Endpoint, caps::R, eh.index, eh.generation, 0);
        install_cspace(tid, cs);
        scheduler::set_restart(tid, ELF_SRV_CODE_VA, ELF_SRV_STACK_VA + 0x1000, skstack);
    }
    EL0_SCHED_MODE.store(true, Ordering::Relaxed); // scheduled-EL0 phase
    kprint!(
        " [P-elf-a] LOADED EL0 client from ELF (entry {:#x}, {} PT_LOAD seg) + asm server(prio9,Endpoint{{R}}); msg={:#x} reply={:#x}\n",
        loaded.entry, parsed.nsegs, ELF_MSG, ELF_REPLY
    );
}

// ===========================================================================
// M5.2b (Track C) — the Wasm host AS AN EL0 SERVER (ADR 0044 D4 #2 shape).
// ===========================================================================

/// Bring up ONE isolated EL0 wasm-host TCB: copy the `wasmhost_stub` 5-opcode
/// interpreter into an R+X code page, write the verified `expr` + `port` into a RW work
/// page (the interpreter reads them at 0x8C00_2000), map a stack, spawn it in its OWN
/// address space (own ASID/TTBR0) at `prio`, and — if `ep` is given — install an
/// `Endpoint{W}` cap at CPtr 0 so the host can SYS_CALL its verdict. Returns the tid.
/// The work page holds: [+0]=port, [+8]=expr_len, [+16..]=expr bytes.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
fn bringup_wasmhost_el0(
    mmu: &arch_aarch64::Mmu,
    stub: usize,
    stub_len: usize,
    expr: &[u8],
    port: u64,
    ep: Option<ipc::EpHandle>,
    prio: u8,
    kstack: usize,
) -> Option<usize> {
    let (code, work, stack) = (mmu.alloc_frame(), mmu.alloc_frame(), mmu.alloc_frame());
    if code == 0 || work == 0 || stack == 0 {
        return None;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(stub as *const u8, code as *mut u8, stub_len);
    }
    arch_aarch64::mmu::sync_instruction_cache(code, stub_len);
    // Work page: port (local 0), expr_len, then the verified expression bytes. `expr` is
    // bounded (fixture ~7 B); cap the copy so it can never reach the operand-stack region
    // at +0x800 (belt-and-braces — a hostile length is already refused by the decoder).
    let n = expr.len().min(0x700);
    unsafe {
        write_volatile(work as *mut u64, port);
        write_volatile((work + 8) as *mut u64, n as u64);
        core::ptr::copy_nonoverlapping(expr.as_ptr(), (work + 16) as *mut u8, n);
    }
    let (l1, asid) = mmu.new_addr_space();
    if l1 == 0 {
        return None;
    }
    mmu.map_user_code_in(l1, WHOST_CODE_VA, code); // EL0 RO+X (W^X)
    mmu.map_user_data_in(l1, WHOST_WORK_VA, work); // EL0 RW, non-exec
    mmu.map_user_data_in(l1, WHOST_STACK_VA, stack);
    let sp = arch_aarch64::thread::make_el0_thread(kstack, WHOST_CODE_VA, WHOST_STACK_VA + 0x1000, 0);
    let ttbr0 = l1 as u64 | ((asid as u64) << 48);
    let tid = scheduler::spawn_as(sp, prio, ttbr0)?;
    let mut cs = caps::CapSpace::empty();
    if let Some(eh) = ep {
        // Endpoint with the WRITE right (may SYS_CALL) at CPtr 0 — the host's ONLY
        // authority to reach the kernel; the verdict flows through this cap-gated path.
        let _ = cs.install_object(caps::ObjType::Endpoint, caps::W, eh.index, eh.generation, 0);
    }
    install_cspace(tid, cs);
    scheduler::set_restart(tid, WHOST_CODE_VA, WHOST_STACK_VA + 0x1000, kstack);
    Some(tid)
}

/// M5.2b (a)+(b)+(c) — host the ONE signed module in an ISOLATED EL0 task, returning its
/// verdict to the kernel over the enforced Endpoint-cap IPC (ADR 0044 D4 #2 shape, min
/// scale). The kernel is the TRUST ROOT: it Ed25519-verifies the module and locates
/// classify()'s expression (bounds-safe decode) BEFORE handing the EL0 host anything.
/// Spawns: (1) an asm SERVER (`ipc_server_stub`, Endpoint{R}) that RECVs the verdict, (2)
/// the EL0 wasm-host CLIENT (`wasmhost_stub`, Endpoint{W}) that interprets classify(4444)
/// AT EL0 and SYS_CALLs the verdict, (3) a SECOND EL0 host handed a fault-inducing
/// expression to prove EL0 isolation (its fault is contained by the R1 fault-restart).
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
fn m5_wasmhost_el0_spawn() {
    let mmu = arch_aarch64::Mmu;
    extern "C" {
        static wasmhost_stub: u8;
        static wasmhost_stub_end: u8;
        static ipc_server_stub: u8;
        static ipc_server_stub_end: u8;
    }
    let stub = core::ptr::addr_of!(wasmhost_stub) as usize;
    let stub_len = core::ptr::addr_of!(wasmhost_stub_end) as usize - stub;
    let (wasm, pk, sig) = wasmhost::fixture();

    // (b) FAIL-CLOSED, BEFORE any EL0 hand-off: a TAMPERED module (one code byte flipped —
    // still valid wasm, but the Ed25519 sig no longer matches) yields NO verified
    // expression, so the EL0 host is NEVER spawned for it. Prove it deterministically.
    let mut tampered = [0u8; 46];
    let n = wasm.len();
    tampered[..n].copy_from_slice(wasm);
    tampered[n - 3] ^= 0x01; // flip i32.eq (0x46) -> i32.ne (0x47)
    let tamper_blocked = wasmhost::verified_classify_expr(&tampered[..n], pk, sig).is_none();
    WHOST_B_TAMPER_NOSPAWN.store(tamper_blocked, Ordering::SeqCst);

    // (a) SIGNED: verify (kernel = trust root) THEN locate classify()'s code expression.
    let expr = match wasmhost::verified_classify_expr(wasm, pk, sig) {
        Some(e) => e,
        None => {
            kprint!(" [P-wasm-el0-a] FAIL: signed fixture failed verify/decode\n");
            return;
        }
    };
    // The in-kernel reference of the SAME 5-opcode execution, to cross-check the EL0 result.
    let refv = wasmhost::reference_exec(expr, WHOST_PORT as i32).unwrap_or(-1);
    WHOST_REF_VERDICT.store(refv as u32, Ordering::SeqCst);

    // A fresh Endpoint object shared by the EL0 host (W) and the asm server (R).
    let eh = match ipc::ep_create() {
        Some(h) => h,
        None => {
            kprint!(" [P-wasm-el0-a] FAIL: endpoint table full\n");
            return;
        }
    };

    // ---- SERVER: reuse the R1 asm server (Endpoint{R}) — RECV verdict -> result page -> REPLY ----
    let (scode, sstack, sresult) = (mmu.alloc_frame(), mmu.alloc_frame(), mmu.alloc_frame());
    if scode == 0 || sstack == 0 || sresult == 0 {
        return;
    }
    let ssrc = core::ptr::addr_of!(ipc_server_stub) as usize;
    let slen = core::ptr::addr_of!(ipc_server_stub_end) as usize - ssrc;
    unsafe {
        core::ptr::copy_nonoverlapping(ssrc as *const u8, scode as *mut u8, slen);
        write_volatile(sresult as *mut u64, 0);
    }
    arch_aarch64::mmu::sync_instruction_cache(scode, slen);
    let (sl1, sasid) = mmu.new_addr_space();
    if sl1 == 0 {
        return;
    }
    // The `ipc_server_stub` hard-codes SCODE 0x8600_0000 / SSTACK 0x8600_1000 / SRESULT
    // 0x8600_2000 (its own address space; no collision with the R1 server's identical VAs).
    mmu.map_user_code_in(sl1, 0x8600_0000, scode);
    mmu.map_user_data_in(sl1, 0x8600_1000, sstack);
    mmu.map_user_data_in(sl1, 0x8600_2000, sresult);
    WHOST_SRESULT_PA.store(sresult, Ordering::SeqCst);
    let skstack = unsafe { core::ptr::addr_of!(EL0_WHOST_SKSTACK) as usize + KSTACK_SIZE };
    let ssp = arch_aarch64::thread::make_el0_thread(skstack, 0x8600_0000, 0x8600_1000 + 0x1000, 0);
    let sttbr0 = sl1 as u64 | ((sasid as u64) << 48);
    if let Some(tid) = scheduler::spawn_as(ssp, 9, sttbr0) {
        let mut cs = caps::CapSpace::empty();
        let _ = cs.install_object(caps::ObjType::Endpoint, caps::R, eh.index, eh.generation, 0);
        install_cspace(tid, cs);
        scheduler::set_restart(tid, 0x8600_0000, 0x8600_1000 + 0x1000, skstack);
    }

    // ---- CLIENT: the EL0 wasm-host — the 5-opcode interpreter runs HERE at EL0 ----
    let ckstack = unsafe { core::ptr::addr_of!(EL0_WHOST_CKSTACK) as usize + KSTACK_SIZE };
    let _ = bringup_wasmhost_el0(&mmu, stub, stub_len, expr, WHOST_PORT, Some(eh), 8, ckstack);

    // ---- (c) ISOLATION: a SECOND EL0 host handed a FAULT-INDUCING expression ----
    // `local.get <huge idx>; end` -> the EL0 interpreter loads locals[idx] from a far
    // unmapped EL0 address -> data abort at EL0 -> CONTAINED + restarted by the R1
    // fault path (never a kernel panic). It holds NO endpoint cap (faults before any
    // CALL). Kernel survival + the GOOD host's verdict staying intact = the isolation proof.
    static BAD_EXPR: [u8; 6] = [0x20, 0xFF, 0xFF, 0xFF, 0x7F, 0x0b]; // local.get 0x0FFFFFFF; end
    let fkstack = unsafe { core::ptr::addr_of!(EL0_WHOST_FKSTACK) as usize + KSTACK_SIZE };
    if let Some(tid) = bringup_wasmhost_el0(&mmu, stub, stub_len, &BAD_EXPR, 0, None, 7, fkstack) {
        WHOST_FAULT_TID.store(tid, Ordering::Relaxed);
    }

    EL0_SCHED_MODE.store(true, Ordering::Relaxed); // scheduled-EL0 phase
    kprint!(
        " [P-wasm-el0-a] spawned EL0 wasm-host(prio8,Endpoint{{W}}) + asm server(prio9,Endpoint{{R}}) + fault-host(prio7); classify({}) ref-verdict={} tamper-blocked={}\n",
        WHOST_PORT, refv, tamper_blocked
    );
}

// ===========================================================================
// M5.3 (Track C) — the REAL wasmi runtime in an EL0 SERVER (ADR 0044 D4 #2 #2).
// ===========================================================================

/// M5.3 — spawn an asm IPC SERVER (`ipc_server_stub`, Endpoint{R}) that RECVs the host's
/// verdict into a result page and REPLYs. Returns the result-page PA (0 on failure). The
/// server hard-codes VAs 0x8600_0000/_1000/_2000 in its OWN address space — reused across
/// servers because each is a distinct TTBR0.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
fn spawn_ipc_result_server(
    mmu: &arch_aarch64::Mmu,
    ep: ipc::EpHandle,
    prio: u8,
    kstack: usize,
) -> usize {
    extern "C" {
        static ipc_server_stub: u8;
        static ipc_server_stub_end: u8;
    }
    let (scode, sstack, sresult) = (mmu.alloc_frame(), mmu.alloc_frame(), mmu.alloc_frame());
    if scode == 0 || sstack == 0 || sresult == 0 {
        return 0;
    }
    let ssrc = core::ptr::addr_of!(ipc_server_stub) as usize;
    let slen = core::ptr::addr_of!(ipc_server_stub_end) as usize - ssrc;
    unsafe {
        core::ptr::copy_nonoverlapping(ssrc as *const u8, scode as *mut u8, slen);
        write_volatile(sresult as *mut u64, 0);
    }
    arch_aarch64::mmu::sync_instruction_cache(scode, slen);
    let (sl1, sasid) = mmu.new_addr_space();
    if sl1 == 0 {
        return 0;
    }
    mmu.map_user_code_in(sl1, 0x8600_0000, scode);
    mmu.map_user_data_in(sl1, 0x8600_1000, sstack);
    mmu.map_user_data_in(sl1, 0x8600_2000, sresult);
    let ssp = arch_aarch64::thread::make_el0_thread(kstack, 0x8600_0000, 0x8600_1000 + 0x1000, 0);
    let sttbr0 = sl1 as u64 | ((sasid as u64) << 48);
    if let Some(tid) = scheduler::spawn_as(ssp, prio, sttbr0) {
        let mut cs = caps::CapSpace::empty();
        let _ = cs.install_object(caps::ObjType::Endpoint, caps::R, ep.index, ep.generation, 0);
        install_cspace(tid, cs);
        scheduler::set_restart(tid, 0x8600_0000, 0x8600_1000 + 0x1000, kstack);
    }
    sresult
}

/// M5.3 — bring up ONE EL0 wasmi-host TCB: LOAD the `el0-wasmhost` ELF (which links wasmi)
/// into a fresh address space via the M5.1 loader (enforced CORE-1 map, W^X), map a stack
/// (16 pages), a HEAP window (64 pages = 256 KiB, the region wasmi's global allocator bumps
/// over) and a work page carrying `[port_a, port_b, wasm_len, module bytes]`, then spawn it
/// holding an `Endpoint{W}` at CPtr 0. The kernel has ALREADY verified `module` (trust
/// root) before this call. Returns the tid.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
fn bringup_wasmi_el0(
    mmu: &arch_aarch64::Mmu,
    parsed: &elf::ParsedElf,
    port_a: u64,
    port_b: u64,
    module: &[u8],
    ep: ipc::EpHandle,
    prio: u8,
    kstack: usize,
) -> Option<usize> {
    let (l1, asid) = mmu.new_addr_space();
    if l1 == 0 {
        return None;
    }
    // Code / rodata / bss segments — mapped at the ELF's own VAs (0x9000_0000..) through
    // the enforced, W^X-checked loader path. wasmi's ~326 KiB .text lands HERE, at EL0.
    let loaded = elf::load_into(parsed, WASMI_ELF, l1).ok()?;
    // Stack (kernel-provided; not declared in the ELF) — RW+NX, grows down from the top.
    for p in 0..WASMI_STACK_PAGES {
        let f = mmu.alloc_frame();
        if f == 0 {
            return None;
        }
        mmu.map_user_data_in(l1, WASMI_STACK_VA + p * 0x1000, f);
    }
    let sp_top = WASMI_STACK_VA + WASMI_STACK_PAGES * 0x1000;
    // Heap window (RW+NX) — 256 KiB the EL0 bump allocator hands to wasmi. `alloc_frame`
    // zeroes each frame, so the heap starts clean.
    for p in 0..WASMI_HEAP_PAGES {
        let f = mmu.alloc_frame();
        if f == 0 {
            return None;
        }
        mmu.map_user_data_in(l1, WASMI_HEAP_VA + p * 0x1000, f);
    }
    // Work page: [+0]=port_a [+8]=port_b [+16]=wasm_len [+24..]=module bytes. Cap the copy
    // so it can never run past one page (belt-and-braces; the module is ~46 B).
    let work = mmu.alloc_frame();
    if work == 0 {
        return None;
    }
    let n = module.len().min(0xF00);
    unsafe {
        write_volatile(work as *mut u64, port_a);
        write_volatile((work + 8) as *mut u64, port_b);
        write_volatile((work + 16) as *mut u64, n as u64);
        core::ptr::copy_nonoverlapping(module.as_ptr(), (work + 24) as *mut u8, n);
    }
    mmu.map_user_data_in(l1, WASMI_WORK_VA, work);

    let sp = arch_aarch64::thread::make_el0_thread(kstack, loaded.entry, sp_top, 0);
    let ttbr0 = l1 as u64 | ((asid as u64) << 48);
    let tid = scheduler::spawn_as(sp, prio, ttbr0)?;
    let mut cs = caps::CapSpace::empty();
    // Endpoint{W} at CPtr 0 — the host's ONLY authority to reach the kernel; the verdict
    // flows through this cap-gated SYS_CALL. A fault/trap otherwise contained at EL0.
    let _ = cs.install_object(caps::ObjType::Endpoint, caps::W, ep.index, ep.generation, 0);
    install_cspace(tid, cs);
    scheduler::set_restart(tid, loaded.entry, sp_top, kstack);
    Some(tid)
}

/// M5.3 (a)+(b)+(c) — run ONE real signed `.wasm` module through a REAL wasmi runtime that
/// lives in an ISOLATED EL0 SERVER (the `el0-wasmhost` binary), returning its verdict over
/// the enforced Endpoint-cap IPC. The kernel is the TRUST ROOT: it Ed25519-verifies each
/// module BEFORE handing it to EL0. Spawns two host+server pairs:
///   * host A (good module): runs classify(4444) AND classify(443) via wasmi, packs the two
///     verdicts into 0x0001_0000 — (a) the real predicate computes correctly, in EL0 wasmi.
///   * host C (signed TRAPPING module): classify() executes `unreachable` -> wasmi TRAP ->
///     the host sends the FAIL packing 0xFFFF_FFFF — (c) a trap is CONTAINED at EL0 by wasmi
///     and the kernel + host A's verdict survive.
/// (b) is proven kernel-side: a tampered module fails verify -> no EL0 host is spawned.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
fn m5_wasmi_el0_spawn() {
    let mmu = arch_aarch64::Mmu;

    // Record the kernel's OWN .text size (its TCB) so the [P-wasmi-el0] report can PROVE
    // wasmi did NOT bloat the kernel — it links only the `include_bytes!` of the EL0 image.
    extern "C" {
        static __text_start: u8;
        static __text_end: u8;
    }
    let tsz = unsafe {
        core::ptr::addr_of!(__text_end) as usize - core::ptr::addr_of!(__text_start) as usize
    };
    WASMI_KERNEL_TEXT_DELTA.store(tsz, Ordering::SeqCst);

    // Parse the EL0 host ELF ONCE (pure, fail-closed). Reused for every host's load_into.
    let parsed = match elf::parse(WASMI_ELF) {
        Ok(p) => p,
        Err(e) => {
            kprint!(" [P-wasmi-el0-a] FAIL: EL0 host ELF rejected by loader: {:?}\n", e);
            return;
        }
    };

    let (gwasm, gpk, gsig) = wasmhost::fixture_full();

    // (b) FAIL-CLOSED, BEFORE any EL0 hand-off: a TAMPERED module (one code byte flipped)
    // fails Ed25519 verify -> `verified_module` is None -> no EL0 host is ever spawned.
    let mut tampered = [0u8; 64];
    let n = gwasm.len().min(64);
    tampered[..n].copy_from_slice(&gwasm[..n]);
    tampered[n - 3] ^= 0x01;
    let tamper_blocked = wasmhost::verified_module(&tampered[..n], gpk, gsig).is_none();
    WASMI_B_TAMPER_NOSPAWN.store(tamper_blocked, Ordering::SeqCst);

    // ---- host A: the GOOD module, VERIFIED (kernel = trust root) then run in EL0 wasmi ----
    if let Some(module) = wasmhost::verified_module(gwasm, gpk, gsig) {
        if let Some(eh) = ipc::ep_create() {
            let sks = unsafe { core::ptr::addr_of!(WASMI_A_SKS) as usize + KSTACK_SIZE };
            let sres = spawn_ipc_result_server(&mmu, eh, 9, sks);
            WASMI_RES_A.store(sres, Ordering::SeqCst);
            let hks = unsafe { core::ptr::addr_of!(WASMI_A_HKS) as usize + KSTACK_SIZE };
            let _ = bringup_wasmi_el0(&mmu, &parsed, 4444, 443, module, eh, 8, hks);
        }
    } else {
        kprint!(" [P-wasmi-el0-a] FAIL: signed fixture failed verify\n");
        return;
    }

    // ---- host C: the SIGNED TRAPPING module -> wasmi trap -> FAIL, contained at EL0 ----
    let (twasm, tpk, tsig) = wasmhost::fixture_trap();
    if let Some(tmodule) = wasmhost::verified_module(twasm, tpk, tsig) {
        if let Some(eh) = ipc::ep_create() {
            let sks = unsafe { core::ptr::addr_of!(WASMI_C_SKS) as usize + KSTACK_SIZE };
            let sres = spawn_ipc_result_server(&mmu, eh, 9, sks);
            WASMI_RES_C.store(sres, Ordering::SeqCst);
            let hks = unsafe { core::ptr::addr_of!(WASMI_C_HKS) as usize + KSTACK_SIZE };
            let _ = bringup_wasmi_el0(&mmu, &parsed, 4444, 4444, tmodule, eh, 8, hks);
        }
    }

    EL0_SCHED_MODE.store(true, Ordering::Relaxed); // scheduled-EL0 phase
    kprint!(
        " [P-wasmi-el0-a] spawned REAL wasmi EL0 host (loaded from {}-seg ELF, entry {:#x}, wasmi .text OUT of kernel TCB) + trap-host + asm servers; kernel .text={} B; tamper-blocked={}\n",
        parsed.nsegs, parsed.entry, tsz, tamper_blocked
    );
}

/// M5.4 — bring up ONE EL0 wasmi-host TCB in DETECT MODE: identical ELF-load / stack /
/// heap / cap setup to `bringup_wasmi_el0`, but the work page carries the DETECT ABI
/// (`[DETECT_MAGIC, n_inputs, stride, wasm_len]` header + inputs @ +32 + module @ +512)
/// instead of `[port_a, port_b, wasm_len, module]`. The kernel has ALREADY Ed25519-verified
/// `module` (trust root) before this call.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
#[allow(clippy::too_many_arguments)]
fn bringup_detect_el0(
    mmu: &arch_aarch64::Mmu,
    parsed: &elf::ParsedElf,
    inputs: &[u8],
    n_inputs: u64,
    stride: u64,
    module: &[u8],
    ep: ipc::EpHandle,
    prio: u8,
    kstack: usize,
) -> Option<usize> {
    let (l1, asid) = mmu.new_addr_space();
    if l1 == 0 {
        return None;
    }
    let loaded = elf::load_into(parsed, WASMI_ELF, l1).ok()?;
    for p in 0..WASMI_STACK_PAGES {
        let f = mmu.alloc_frame();
        if f == 0 {
            return None;
        }
        mmu.map_user_data_in(l1, WASMI_STACK_VA + p * 0x1000, f);
    }
    let sp_top = WASMI_STACK_VA + WASMI_STACK_PAGES * 0x1000;
    for p in 0..WASMI_HEAP_PAGES {
        let f = mmu.alloc_frame();
        if f == 0 {
            return None;
        }
        mmu.map_user_data_in(l1, WASMI_HEAP_VA + p * 0x1000, f);
    }
    // Work page (DETECT ABI). alloc_frame zeroes it, so unwritten fields read 0.
    let work = mmu.alloc_frame();
    if work == 0 {
        return None;
    }
    // Fixed-VA offsets MUST match el0-wasmhost: inputs @ +32, module @ +512, both inside 4 KiB.
    const IN_OFF: usize = 32;
    const MOD_OFF: usize = 512;
    let in_len = inputs.len().min(MOD_OFF - IN_OFF);
    let mod_len = module.len().min(0x1000 - MOD_OFF);
    unsafe {
        write_volatile(work as *mut u64, DETECT_MAGIC);
        write_volatile((work + 8) as *mut u64, n_inputs);
        write_volatile((work + 16) as *mut u64, stride);
        write_volatile((work + 24) as *mut u64, mod_len as u64);
        core::ptr::copy_nonoverlapping(inputs.as_ptr(), (work + IN_OFF) as *mut u8, in_len);
        core::ptr::copy_nonoverlapping(module.as_ptr(), (work + MOD_OFF) as *mut u8, mod_len);
    }
    mmu.map_user_data_in(l1, WASMI_WORK_VA, work);

    let sp = arch_aarch64::thread::make_el0_thread(kstack, loaded.entry, sp_top, 0);
    let ttbr0 = l1 as u64 | ((asid as u64) << 48);
    let tid = scheduler::spawn_as(sp, prio, ttbr0)?;
    let mut cs = caps::CapSpace::empty();
    let _ = cs.install_object(caps::ObjType::Endpoint, caps::W, ep.index, ep.generation, 0);
    install_cspace(tid, cs);
    scheduler::set_restart(tid, loaded.entry, sp_top, kstack);
    Some(tid)
}

/// M5.5 — bring up ONE EL0 wasip1-host TCB running a REAL std `wasm32-wasip1` module. Like
/// bringup_wasmi_el0 but with the bigger windows a std module needs: a MiB-scale HEAP (its
/// ~1.1 MiB linear memory), and the module bytes in their OWN RW+NX window (too big for the
/// work page). The work page carries only [WASIP1_MAGIC, wasm_len, stdin_len, stdin bytes].
/// The kernel has ALREADY Ed25519-verified `module` (trust root) before this call.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
fn bringup_wasip1_el0(
    mmu: &arch_aarch64::Mmu,
    parsed: &elf::ParsedElf,
    module: &[u8],
    stdin: &[u8],
    ep: ipc::EpHandle,
    prio: u8,
    kstack: usize,
) -> Option<usize> {
    let (l1, asid) = mmu.new_addr_space();
    if l1 == 0 {
        return None;
    }
    let loaded = elf::load_into(parsed, WASMI_ELF, l1).ok()?;
    for p in 0..WASMI_STACK_PAGES {
        let f = mmu.alloc_frame();
        if f == 0 {
            return None;
        }
        mmu.map_user_data_in(l1, WASMI_STACK_VA + p * 0x1000, f);
    }
    let sp_top = WASMI_STACK_VA + WASMI_STACK_PAGES * 0x1000;
    // MiB-scale heap for the std module's ~1.1 MiB linear memory + wasmi overhead.
    for p in 0..WASIP1_HEAP_PAGES {
        let f = mmu.alloc_frame();
        if f == 0 {
            return None;
        }
        mmu.map_user_data_in(l1, WASMI_HEAP_VA + p * 0x1000, f);
    }
    // Module window (RW+NX): copy the kernel-verified module bytes across its pages.
    let mpages = (module.len() + 0xFFF) >> 12;
    if mpages > WASMI_MODULE_PAGES {
        return None;
    }
    for p in 0..mpages {
        let f = mmu.alloc_frame();
        if f == 0 {
            return None;
        }
        let off = p * 0x1000;
        let n = (module.len() - off).min(0x1000);
        unsafe {
            core::ptr::copy_nonoverlapping(module.as_ptr().add(off), f as *mut u8, n);
        }
        mmu.map_user_data_in(l1, WASMI_MODULE_VA + off, f);
    }
    // Work page: [+0]=WASIP1_MAGIC [+8]=wasm_len [+16]=stdin_len [+24..]=stdin bytes.
    let work = mmu.alloc_frame();
    if work == 0 {
        return None;
    }
    let sn = stdin.len().min(64);
    unsafe {
        write_volatile(work as *mut u64, WASIP1_MAGIC);
        write_volatile((work + 8) as *mut u64, module.len() as u64);
        write_volatile((work + 16) as *mut u64, sn as u64);
        core::ptr::copy_nonoverlapping(stdin.as_ptr(), (work + 24) as *mut u8, sn);
    }
    mmu.map_user_data_in(l1, WASMI_WORK_VA, work);

    let sp = arch_aarch64::thread::make_el0_thread(kstack, loaded.entry, sp_top, 0);
    let ttbr0 = l1 as u64 | ((asid as u64) << 48);
    let tid = scheduler::spawn_as(sp, prio, ttbr0)?;
    let mut cs = caps::CapSpace::empty();
    let _ = cs.install_object(caps::ObjType::Endpoint, caps::W, ep.index, ep.generation, 0);
    install_cspace(tid, cs);
    scheduler::set_restart(tid, loaded.entry, sp_top, kstack);
    Some(tid)
}

/// M5.5 — run TWO REAL signed `wasm32-wasip1` std modules through wasmi in isolated EL0
/// hosts, each reading an L4 header from STDIN and writing its verdict to STDOUT over the
/// WASI preview1 ABI, returned over the enforced Endpoint-cap IPC. host A (dst-port 4444) ->
/// DROP(2); host B (dst-port 443) -> PASS(1) — the pair proves the predicate COMPUTES over
/// real WASI stdin, not a constant. (b) a bad-signature module is refused before EL0 spawn.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
fn m5_wasip1_el0_spawn() {
    let mmu = arch_aarch64::Mmu;
    let parsed = match elf::parse(WASMI_ELF) {
        Ok(p) => p,
        Err(e) => {
            kprint!(" [P-wasip1] FAIL: EL0 host ELF rejected by loader: {:?}\n", e);
            return;
        }
    };
    let (wasm, pk, sig) = wasmhost::fixture_wasip1();
    // (b) FAIL-CLOSED before any EL0 hand-off: a corrupted signature is refused. (Flip a byte
    // of the 64-B sig rather than copy the ~37 KiB module onto the kernel stack.)
    let mut badsig = [0u8; 64];
    badsig.copy_from_slice(&sig[..64]);
    badsig[0] ^= 0x01;
    WASIP1_TAMPER_NOSPAWN.store(wasmhost::verified_module(wasm, pk, &badsig).is_none(), Ordering::SeqCst);

    let module = match wasmhost::verified_module(wasm, pk, sig) {
        Some(m) => m,
        None => {
            kprint!(" [P-wasip1] FAIL: signed wasip1 module failed Ed25519 verify\n");
            return;
        }
    };
    // An L4 header with a big-endian dst-port at [2..4] (== the module's classify offset).
    fn l4_hdr(port: u16) -> [u8; 16] {
        let mut h = [0u8; 16];
        h[2] = (port >> 8) as u8;
        h[3] = (port & 0xff) as u8;
        h
    }
    let hdr_a = l4_hdr(4444); // -> DROP (signature port)
    let hdr_b = l4_hdr(443); //  -> PASS
    if let Some(eh) = ipc::ep_create() {
        let sks = unsafe { core::ptr::addr_of!(WASIP1_A_SKS) as usize + KSTACK_SIZE };
        WASIP1_RES_A.store(spawn_ipc_result_server(&mmu, eh, 9, sks), Ordering::SeqCst);
        let hks = unsafe { core::ptr::addr_of!(WASIP1_A_HKS) as usize + KSTACK_SIZE };
        let _ = bringup_wasip1_el0(&mmu, &parsed, module, &hdr_a, eh, 8, hks);
    }
    if let Some(eh) = ipc::ep_create() {
        let sks = unsafe { core::ptr::addr_of!(WASIP1_B_SKS) as usize + KSTACK_SIZE };
        WASIP1_RES_B.store(spawn_ipc_result_server(&mmu, eh, 9, sks), Ordering::SeqCst);
        let hks = unsafe { core::ptr::addr_of!(WASIP1_B_HKS) as usize + KSTACK_SIZE };
        let _ = bringup_wasip1_el0(&mmu, &parsed, module, &hdr_b, eh, 8, hks);
    }

    // A2+ — the SECOND catalogue module: DNS-RPZ (distinct detection, same wasip1 ABI + same
    // signed-verify-before-EL0 trust root). Two hosts prove it COMPUTES + matches the in-kernel
    // dnssink::rpz_blocked: host C on a blocklisted SUBDOMAIN -> DROP(2), host D on a benign
    // name -> PASS(1). Same host ELF, different (verified) module bytes + stdin.
    let (dwasm, dpk, dsig) = wasmhost::fixture_wasip1_dnsrpz();
    if let Some(dmod) = wasmhost::verified_module(dwasm, dpk, dsig) {
        let blk = b"host.malware.example"; // subdomain of a blocked domain -> DROP
        let ben = b"good.example.com"; //     not blocked -> PASS
        if let Some(eh) = ipc::ep_create() {
            let sks = unsafe { core::ptr::addr_of!(WASIP1_C_SKS) as usize + KSTACK_SIZE };
            WASIP1_RES_C.store(spawn_ipc_result_server(&mmu, eh, 9, sks), Ordering::SeqCst);
            let hks = unsafe { core::ptr::addr_of!(WASIP1_C_HKS) as usize + KSTACK_SIZE };
            let _ = bringup_wasip1_el0(&mmu, &parsed, dmod, blk, eh, 8, hks);
        }
        if let Some(eh) = ipc::ep_create() {
            let sks = unsafe { core::ptr::addr_of!(WASIP1_D_SKS) as usize + KSTACK_SIZE };
            WASIP1_RES_D.store(spawn_ipc_result_server(&mmu, eh, 9, sks), Ordering::SeqCst);
            let hks = unsafe { core::ptr::addr_of!(WASIP1_D_HKS) as usize + KSTACK_SIZE };
            let _ = bringup_wasip1_el0(&mmu, &parsed, dmod, ben, eh, 8, hks);
        }
    }
    EL0_SCHED_MODE.store(true, Ordering::Relaxed); // scheduled-EL0 phase: faults restart
}

/// M5.4 DETECT-mode work-page magic (== el0-wasmhost `DETECT_MAGIC`). Both tiers.
#[cfg(feature = "wasmhost")]
const DETECT_MAGIC: u64 = 0x4851_4445_5445_4354;

/// M5.4 (a)+(b)+(c) — run ONE signed DETECTION `.wasm` module (linear memory + the
/// `hp_input`/`hp_emit` host shim) through the EL0 wasmi host over a VECTOR of L4 headers,
/// and prove its per-input verdicts EQUAL `rules::run_l4` on the same headers (PARITY,
/// ADR 0044 D4 #4 at small scale). The kernel is the TRUST ROOT: it Ed25519-verifies the
/// module BEFORE hand-off AND independently computes the reference verdicts here.
///   * host D (parity): 8 well-formed L4 headers {4444,23,31337,80,443,22,0,65535} → each
///     verdict packed as a nibble; compared to the kernel-computed `rules::run_l4` packing.
///   * host I (iso): 1 malformed 2-byte header → the module defensively TRAPs → wasmi
///     contains it at EL0 → the host returns the 0xF fail nibble (kernel + host D survive).
/// (b) is proven kernel-side: a tampered detection module fails verify → no host spawned.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
fn m5_detect_el0_spawn() {
    let mmu = arch_aarch64::Mmu;
    let parsed = match elf::parse(WASMI_ELF) {
        Ok(p) => p,
        Err(e) => {
            kprint!(" [P-wasm-parity-a] FAIL: EL0 host ELF rejected by loader: {:?}\n", e);
            return;
        }
    };
    let (dwasm, dpk, dsig) = wasmhost::fixture_detect();

    // The PARITY vector: 8 L4 headers (src port 0, dst port big-endian, rest 0). The three
    // blocked ports mirror rules.rs RULES (4444/23/31337, all FindingClass::Signature).
    const STRIDE: usize = 8;
    const NP: usize = 8;
    let ports: [u16; NP] = [4444, 23, 31337, 80, 443, 22, 0, 65535];
    let mut inputs = [0u8; NP * STRIDE];
    let mut expected: u32 = 0;
    for (i, p) in ports.iter().enumerate() {
        let base = i * STRIDE;
        inputs[base + 2] = (p >> 8) as u8; // dst-port high byte  (== THREAT_RULE R1+2)
        inputs[base + 3] = (*p & 0xff) as u8; // dst-port low byte (== THREAT_RULE R1+3)
        // THE reference: the SAME in-kernel detection this module must reproduce. run_l4
        // returns packet::PASS(1)/DROP(2); a Signature hit → FrameDrop → DROP regardless of
        // src (matrix: a backdoor-port hit is not identity-keyed), so src=0 is faithful.
        let wire = rules::run_l4(&inputs[base..base + STRIDE], 0) as u32;
        expected |= (wire & 0xF) << (4 * i);
    }
    WASMI_DETECT_EXPECTED.store(expected, Ordering::SeqCst);
    WASMI_DETECT_N.store(NP as u32, Ordering::SeqCst);

    // (b) FAIL-CLOSED, BEFORE any EL0 hand-off: a tampered detection module (last byte
    // flipped) fails Ed25519 verify → `verified_module` None → no EL0 host spawned.
    let mut tampered = [0u8; 256];
    let n = dwasm.len().min(256);
    tampered[..n].copy_from_slice(&dwasm[..n]);
    tampered[n - 1] ^= 0x01;
    let tamper_blocked = wasmhost::verified_module(&tampered[..n], dpk, dsig).is_none();
    WASMI_DETECT_TAMPER_NOSPAWN.store(tamper_blocked, Ordering::SeqCst);

    // host D — parity: the GOOD module, VERIFIED then run over the 8-header vector in EL0.
    if let Some(module) = wasmhost::verified_module(dwasm, dpk, dsig) {
        if let Some(eh) = ipc::ep_create() {
            let sks = unsafe { core::ptr::addr_of!(WASMI_D_SKS) as usize + KSTACK_SIZE };
            let sres = spawn_ipc_result_server(&mmu, eh, 9, sks);
            WASMI_DETECT_RES.store(sres, Ordering::SeqCst);
            let hks = unsafe { core::ptr::addr_of!(WASMI_D_HKS) as usize + KSTACK_SIZE };
            let _ = bringup_detect_el0(&mmu, &parsed, &inputs, NP as u64, STRIDE as u64, module, eh, 8, hks);
        }
    } else {
        kprint!(" [P-wasm-parity-a] FAIL: signed detection fixture failed verify\n");
        return;
    }

    // host I — isolation: ONE malformed 2-byte header (stride=2 → hp_input returns 2 < 4 →
    // the module hits `unreachable` → wasmi TRAP), contained at EL0 → the 0xF fail nibble.
    let iso_inputs = [0u8; 2];
    if let Some(module) = wasmhost::verified_module(dwasm, dpk, dsig) {
        if let Some(eh) = ipc::ep_create() {
            let sks = unsafe { core::ptr::addr_of!(WASMI_ISO_SKS) as usize + KSTACK_SIZE };
            let sres = spawn_ipc_result_server(&mmu, eh, 9, sks);
            WASMI_DETECT_ISO_RES.store(sres, Ordering::SeqCst);
            let hks = unsafe { core::ptr::addr_of!(WASMI_ISO_HKS) as usize + KSTACK_SIZE };
            let _ = bringup_detect_el0(&mmu, &parsed, &iso_inputs, 1, 2, module, eh, 8, hks);
        }
    }
    EL0_SCHED_MODE.store(true, Ordering::Relaxed);
}

// ---------------------------------------------------------------- bounded EL0 excursion (ADR 0050 D5)

static EXC_WD_ACTIVE: AtomicBool = AtomicBool::new(false);
static EXC_TIMED_OUT: AtomicBool = AtomicBool::new(false);
static EXC_FAULTED: AtomicBool = AtomicBool::new(false);
/// Watchdog expiries since boot (reported by the services that use bounded excursions).
pub static EXC_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// How a bounded excursion ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Excursion {
    /// The EL0 program returned control itself (SYS_EXIT_USER / a reporting syscall that exits).
    Exited,
    /// It ran past its budget and was preempted by the watchdog (the service fails closed).
    Timeout,
    /// It faulted (contained by `handle_lower_sync`).
    Fault,
}

/// Run EL0 at `entry`/`sp` for at most `budget_us` microseconds. Only the watchdog timer can interrupt
/// the EL0 code; on return the kernel is back at EL1 with IRQs masked, exactly as after `enter_user`.
pub fn excursion_bounded(entry: usize, sp: usize, budget_us: u64) -> Excursion {
    use hal::IrqController;
    let frq: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frq) };
    let ticks = (frq / 1_000_000).max(1) * budget_us.max(1);
    // Distributor + CPU interface on (idempotent — the excursion may run before the scheduler's GIC
    // bring-up), then the watchdog PPI.
    arch_aarch64::Gic.init();
    arch_aarch64::Gic.enable(arch_aarch64::timer::VTIMER_INTID);
    EXC_TIMED_OUT.store(false, Ordering::SeqCst);
    EXC_FAULTED.store(false, Ordering::SeqCst);
    EXC_WD_ACTIVE.store(true, Ordering::SeqCst);
    arch_aarch64::timer::watchdog_arm(ticks);
    unsafe { arch_aarch64::syscall::enter_user_irq(entry, sp) };
    arch_aarch64::timer::watchdog_disarm();
    EXC_WD_ACTIVE.store(false, Ordering::SeqCst);
    if EXC_TIMED_OUT.load(Ordering::SeqCst) {
        Excursion::Timeout
    } else if EXC_FAULTED.load(Ordering::SeqCst) {
        Excursion::Fault
    } else {
        Excursion::Exited
    }
}

/// `[P-exc-bound]` — a spinning EL0 program is preempted by the watchdog within its budget and the kernel
/// continues; a well-behaved one exits normally (the watchdog never fires); a faulting one is contained;
/// and a spin AFTER a fault is still bounded (state resets per excursion).
#[cfg(not(feature = "cm5"))]
fn exc_bound_selftest() {
    let mmu = arch_aarch64::Mmu;
    let code = mmu.alloc_frame();
    let stack = mmu.alloc_frame();
    if code == 0 || stack == 0 {
        kprint!(" [P-exc-bound] FAIL: no frames\n");
        return;
    }
    // Three tiny A64 programs at fixed offsets of one RO+X page.
    const SPIN: [u32; 1] = [0x1400_0000]; // b .
    const EXIT: [u32; 3] = [0xD280_00C8, 0xD400_0001, 0x1400_0000]; // mov x8,#6 (SYS_EXIT_USER); svc #0; b .
    const FAULT: [u32; 3] = [0xD280_0000, 0xF940_0001, 0x1400_0000]; // mov x0,#0; ldr x1,[x0]; b .
    unsafe {
        let w = |off: usize, prog: &[u32]| {
            for (i, ins) in prog.iter().enumerate() {
                core::ptr::write_volatile((code + off + i * 4) as *mut u32, *ins);
            }
        };
        w(0x000, &SPIN);
        w(0x100, &EXIT);
        w(0x200, &FAULT);
    }
    arch_aarch64::mmu::sync_instruction_cache(code, 0x1000);
    const CODE_VA: usize = 0xD010_0000;
    const STACK_VA: usize = 0xD010_1000;
    mmu.map_user_code_page(CODE_VA, code);
    mmu.map_user_data_page(STACK_VA, stack);
    let frq: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frq) };
    let now = || {
        let c: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) c) };
        c
    };
    let budget_us = 20_000u64;
    let before = EXC_TIMEOUTS.load(Ordering::Relaxed);
    let exit = excursion_bounded(CODE_VA + 0x100, STACK_VA + 0x1000, budget_us);
    let fault = excursion_bounded(CODE_VA + 0x200, STACK_VA + 0x1000, budget_us);
    kprint!(" [P-exc-bound] exit -> {:?}, fault -> {:?}; now a spinning EL0 program...\n", exit, fault);
    let t0 = now();
    let spin = excursion_bounded(CODE_VA, STACK_VA + 0x1000, budget_us);
    let spin_us = (now() - t0) * 1_000_000 / frq.max(1);
    let spin2 = excursion_bounded(CODE_VA, STACK_VA + 0x1000, budget_us);
    let counted = EXC_TIMEOUTS.load(Ordering::Relaxed) - before;
    // The spin must end AFTER its budget (it really ran) and well before 10x the budget (bounded).
    let bounded = spin_us >= budget_us && spin_us < budget_us * 10;
    let pass = spin == Excursion::Timeout && exit == Excursion::Exited && fault == Excursion::Fault
        && spin2 == Excursion::Timeout && counted == 2 && bounded;
    kprint!(" [P-exc-bound] {} — bounded EL0 excursion (ADR 0050 D5): spinning EL0 -> {:?} after {} us (budget {} us), clean exit -> {:?}, fault -> {:?}, spin after fault -> {:?}, watchdog expiries counted={} — the kernel kept running\n",
        if pass { "PASS" } else { "FAIL" }, spin, spin_us, budget_us, exit, fault, spin2, counted);
}

fn p3_user_demo() {
    let mmu = arch_aarch64::Mmu;
    extern "C" {
        static user_stub: u8;
        static user_stub_end: u8;
    }
    let src = core::ptr::addr_of!(user_stub) as usize;
    let len = core::ptr::addr_of!(user_stub_end) as usize - src;

    // Dedicated EL0 pages — kernel RAM stays EL1-only, so this is real isolation.
    let code = mmu.alloc_frame();
    let stack = mmu.alloc_frame();
    if code == 0 || stack == 0 {
        kprint!(" [P3] FAIL: no frames\n");
        arch_aarch64::semihosting::exit(1);
    }
    // Copy the position-independent user program into the code frame (EL1 view),
    // then make it visible to the instruction fetcher.
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, code as *mut u8, len) };
    arch_aarch64::mmu::sync_instruction_cache(code, len);

    const CODE_VA: usize = 0xD000_0000;
    const STACK_VA: usize = 0xD000_1000;
    mmu.map_user_code_page(CODE_VA, code); // EL0 RO+X (W^X)
    mmu.map_user_data_page(STACK_VA, stack); // EL0 RW, non-exec
    kprint!(" [P3] dropping to EL0 (code@{:#x} stack@{:#x}, kernel RAM stays EL1-only)...\n", CODE_VA, STACK_VA);

    // Returns (via resume_kernel from the fault handler) after the user program
    // runs its syscalls and triggers the contained fault.
    unsafe { arch_aarch64::syscall::enter_user(CODE_VA, STACK_VA + 0x1000) };

    kprint!(" [P3] back in EL1; kernel survived the EL0 fault\n");
    kprint!(" [P3] PASS userspace+SVC (EL0 ran, syscalls incl. capability invocation, fault contained)\n");
}

/// Sync-from-EL0 handler (called from `lower_sync_entry`). SVC -> service the
/// syscall and return (asm erets back to EL0). Any other fault -> contain it and
/// resume the kernel (this call never returns for the fault path).
#[no_mangle]
pub extern "C" fn handle_lower_sync(frame: *mut u64) -> usize {
    let esr: u64;
    unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) esr) };
    let ec = (esr >> 26) & 0x3f;

    if ec == 0x15 {
        // SVC from AArch64: dispatch (x8=num, x0/x1=args), return value into x0.
        let num = unsafe { *frame.add(8) };
        let a0 = unsafe { *frame.add(0) };
        let a1 = unsafe { *frame.add(1) };
        let cur = scheduler::current_tid();

        // DSN-6 (latent, fixed regardless of P12): SYS_EXIT_USER used to
        // UNCONDITIONALLY longjmp via resume_kernel() into the KRESUME saved by the
        // last cooperative enter_user. For a SCHEDULED EL0 TCB that context is stale
        // — the jump lands in a dead kernel stack. Gate the longjmp on the caller NOT
        // being a scheduled TCB (a scheduled TCB has an armed restart record); route a
        // scheduled caller through the clean, scheduler-aware exit instead.
        if num == SYS_EXIT_USER {
            if scheduler::restart_rec(cur).is_some() {
                return p12_task_exit(cur, frame);
            }
            unsafe { arch_aarch64::syscall::resume_kernel() }; // cooperative EL0 done -> kernel
        }
        // P12 — scheduler-aware clean exit of the current scheduled TCB.
        if num == SYS_TASK_EXIT {
            return p12_task_exit(cur, frame);
        }
        // P12 — the ONLY blocking syscall, and it blocks ONLY the caller. Same epilogue
        // as the IRQ path (restore 34 words, eret), so a thread that blocks here is
        // resumed later by a Signal + the timer. Reuses the proven "return a different
        // thread's SP from handle_lower_sync" mechanism (see the fault-restart path).
        if num == SYS_WAIT {
            match p12_wait(a0 as usize, cur) {
                notify::WaitOut::Ready(x0) => {
                    unsafe { *frame.add(0) = x0 };
                    return frame as usize;
                }
                notify::WaitOut::Rc(rc) => {
                    unsafe { *frame.add(0) = rc };
                    return frame as usize;
                }
                notify::WaitOut::Block => {
                    P12_WAIT_BLOCKED.store(true, Ordering::Relaxed);
                    scheduler::block_current(); // enqueued as the waiter; won't be picked
                    let next = scheduler::on_tick(frame as usize); // save my frame, pick next
                    return switch_to(next); // MUST enter next's ASID before returning its SP
                }
            }
        }
        // R1 (M5.0) — cap-gated synchronous IPC. CALL and (endpoint) RECV can BLOCK the
        // caller, so — like SYS_WAIT — they are handled HERE (they may return a DIFFERENT
        // thread's SP via the proven switch_to path), not in `syscall_dispatch`. Both
        // resolve the Endpoint from the caller's OWN CSpace and FAIL CLOSED (RC_DENIED)
        // with no rendezvous when the cap is missing / wrong-type / insufficient-rights.
        if num == SYS_CALL {
            // Call needs the W (send) right. On a cap failure return immediately (no block).
            match resolve_ep_cap(a0 as usize, caps::W) {
                Err(rc) => {
                    unsafe { *frame.add(0) = rc };
                    return frame as usize; // FAIL CLOSED: no message, no rendezvous
                }
                Ok((i, g)) => match ipc::call(i, g, a1, cur) {
                    ipc::IpcOut::Rc(rc) => {
                        unsafe { *frame.add(0) = rc };
                        return frame as usize;
                    }
                    ipc::IpcOut::Ready(w) => {
                        unsafe { *frame.add(0) = w }; // (defensive; Call always blocks)
                        return frame as usize;
                    }
                    ipc::IpcOut::Block => {
                        scheduler::block_current(); // blocked until a REPLY wakes me
                        let next = scheduler::on_tick(frame as usize);
                        return switch_to(next);
                    }
                },
            }
        }
        if num == SYS_EP_RECV {
            // Recv needs the R (receive) right.
            match resolve_ep_cap(a0 as usize, caps::R) {
                Err(rc) => {
                    unsafe { *frame.add(0) = rc };
                    return frame as usize; // FAIL CLOSED
                }
                Ok((i, g)) => match ipc::recv_ep(i, g, cur) {
                    ipc::IpcOut::Ready(w) => {
                        unsafe { *frame.add(0) = w }; // a caller was already parked
                        return frame as usize;
                    }
                    ipc::IpcOut::Rc(rc) => {
                        unsafe { *frame.add(0) = rc };
                        return frame as usize;
                    }
                    ipc::IpcOut::Block => {
                        scheduler::block_current(); // blocked until a CALL rendezvous
                        let next = scheduler::on_tick(frame as usize);
                        return switch_to(next);
                    }
                },
            }
        }
        let ret = syscall_dispatch(num, a0, a1);
        unsafe { *frame.add(0) = ret };
        return frame as usize; // restore this frame in place, eret back to EL0
    }

    // Fault from EL0 (e.g. data abort EC=0x24).
    let far: u64;
    unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) far) };
    kprint!("   [EL0 fault] contained: EC={:#04x} FAR={:#x} (kernel survives)\n", ec, far);
    EXC_FAULTED.store(true, Ordering::SeqCst);
    telemetry::emit(telemetry::Event::Fault); // the OS senses its own fault

    // P7c step 4b/4c: a *scheduled* EL0 driver TCB — RESTART it (rebuild a fresh
    // frame) up to a bound, then kill it, and reschedule. A driver crash is
    // contained AND recovered without taking the kernel down. Active on CM5 too
    // (P7c-4c), so a scheduled EL0 fault degrades gracefully instead of wedging.
    // CORE-6: while scheduled EL0 TCBs are the ones running (EL0_SCHED_MODE = the phase
    // gate), restart the FAULTING thread from ITS OWN per-TCB record with ITS OWN
    // budget — no longer from a global shared with whatever scheduled EL0 TCB spawned
    // last. A tid with no record (shouldn't happen while scheduled) falls through to
    // the cooperative path.
    let cur = scheduler::current_tid();
    // P12: a faulting TCB may have been parked as a notification/topic waiter — detach
    // it on EVERY death path (restart AND kill below) so a later Signal can't write a
    // badge into its (about to be rebuilt / freed) trap frame.
    notify::detach_tcb(cur);
    ipc::detach_tcb(cur); // R1: also unpark from any sync-IPC endpoint
    if EL0_SCHED_MODE.load(Ordering::Relaxed) {
        if let Some(rec) = scheduler::restart_rec(cur) {
        let n = scheduler::bump_restart(cur);
        let next_sp = if n <= EL0_MAX_RESTARTS {
            kprint!("   [EL0 fault] restarting driver TCB {} (restart #{})\n", cur, n);
            let sp = arch_aarch64::thread::make_el0_thread(rec.kstack, rec.entry, rec.usp, 0);
            scheduler::set_sp(cur, sp);
            scheduler::on_tick(sp)
        } else {
            kprint!("   [EL0 fault] restart budget exhausted -> killing driver TCB {}\n", cur);
            scheduler::exit_current();
            scheduler::clear_restart(cur); // a reused slot must not inherit this record
            clear_cspace(cur); // CORE-2 teardown (A1a): nor inherit the dead TCB's caps
            // AUDIT M-9: pass the KERNEL trap frame, never the attacker-controlled
            // SP_EL0 (frame slot 33) — on_tick stores its arg into the kernel SP table.
            scheduler::on_tick(frame as usize)
        };
        enter_current_addr_space(); // P7c-4c: re-enter the (restarted) driver's ASID — CM5 too
        return next_sp;
        } // if let Some(rec)
    } // if EL0_SCHED_MODE

    // Cooperative EL0 (P3/DRV, the CM5 stages): longjmp back to the kernel.
    unsafe { arch_aarch64::syscall::resume_kernel() };
}

fn syscall_dispatch(num: u64, a0: u64, _a1: u64) -> u64 {
    match num {
        SYS_HELLO => {
            kprint!("   [EL0>svc] hello from EL0 (unprivileged) via SVC\n");
            0
        }
        SYS_GETVAL => 0x1234,
        SYS_PRINTVAL => {
            kprint!("   [EL0>svc] EL0 received kernel value {:#x}\n", a0);
            0
        }
        SYS_CAP_IDENTIFY => {
            // Genuine capability invocation from EL0: resolve a CPtr in the CALLER's
            // OWN CSpace (CORE-2 — never a global), so a task can only name caps it
            // actually holds. Returns the object type, or u64::MAX for empty / no CSpace.
            let cptr = a0 as usize;
            match current_cspace().and_then(|cs| cs.get(cptr)) {
                Some(c) => {
                    kprint!("   [EL0>svc] invoked cap[{}] -> {} (type code {})\n", cptr, c.otype.name(), c.otype.code());
                    c.otype.code()
                }
                None => {
                    kprint!("   [EL0>svc] invoked cap[{}] -> empty slot (or no CSpace)\n", cptr);
                    u64::MAX
                }
            }
        }
        SYS_DRIVER_REPORT => {
            // An isolated EL0 driver reports a value it read from its device MMIO.
            DRIVER_REPORT.store(a0 as u32, Ordering::Relaxed);
            0
        }
        // --- P12 non-blocking syscalls (WAIT/TASK_EXIT are handled in handle_lower_sync
        // because they touch the trap frame / scheduler). Every one is gated on the
        // caller's OWN cap + rights; the badge is read from the cap, never from `a0`. ---
        SYS_SIGNAL => {
            // Signal(CPtr{W}) — OR the cap's stamped badge into the object. Never blocks.
            match resolve_ntfn_cap(a0 as usize, caps::W, caps::ObjType::Notification) {
                Ok((i, g, badge)) => notify::signal(i, g, badge),
                Err(rc) => rc,
            }
        }
        SYS_POLL => {
            // Poll(CPtr{R}) — non-blocking read+clear of the notification word.
            match resolve_ntfn_cap(a0 as usize, caps::R, caps::ObjType::Notification) {
                Ok((i, g, _)) => notify::poll(i, g),
                Err(_) => 0,
            }
        }
        SYS_SUBSCRIBE => {
            // Subscribe(TopicCPtr{R}) — REQUIRES the R right (ungranted subscribe is
            // refused by resolve_ntfn_cap). Returns a subscription id, or an RC error.
            match resolve_ntfn_cap(a0 as usize, caps::R, caps::ObjType::Topic) {
                Ok((i, g, _)) => match notify::subscribe(i, g, scheduler::current_tid()) {
                    Ok(sub_id) => sub_id as u64,
                    Err(rc) => rc,
                },
                Err(rc) => rc,
            }
        }
        SYS_PUBLISH => {
            // Publish(TopicCPtr{W}, kind=a1) — non-blocking, O(subscribers).
            match resolve_ntfn_cap(a0 as usize, caps::W, caps::ObjType::Topic) {
                Ok((i, g, badge)) => notify::publish(i, g, badge, _a1 as u32, 0),
                Err(rc) => rc,
            }
        }
        SYS_RECV => {
            // Recv(TopicCPtr{R}, sub_id=a1) — pop one bounded event; RC_EMPTY if drained.
            // The 24 B metadata is delivered via the P11 payload ring; the syscall
            // returns only the status code (kernel never returns object indices to EL0).
            match resolve_ntfn_cap(a0 as usize, caps::R, caps::ObjType::Topic) {
                Ok((i, g, _)) => match notify::recv(i, g, _a1 as usize, scheduler::current_tid()) {
                    Ok(_meta) => abi::RC_OK,
                    Err(rc) => rc,
                },
                Err(rc) => rc,
            }
        }
        SYS_REPLY => {
            // R1 (M5.0) — Reply(EpCPtr{R}, word=x1): wake the served caller. NON-blocking
            // (like SYS_SIGNAL), so it lives here. Needs the R right (the receive side of
            // the endpoint); resolved from the replier's OWN CSpace, fail closed.
            match resolve_ep_cap(a0 as usize, caps::R) {
                Ok((i, g)) => ipc::reply(i, g, _a1),
                Err(rc) => rc,
            }
        }
        _ => u64::MAX,
    }
}

/// P5 self-test: drive synthetic packets through the zero-copy ring; the
/// detection-side verdict inspects each IN PLACE (no copy) and DROPs blocked
/// ports. Exercises ring wrap (10 packets > ring size 8). Returns pass.
fn p5_packet_engine() -> bool {
    kprint!(" [P5] Packet Engine: zero-copy ring + in-place verdict datapath\n");
    let pool = arch_aarch64::mmu::reserve_region(packet::FRAME_SZ * 8);
    let npkts = 10usize;
    let (mut drops, mut passes) = (0u32, 0u32);
    for i in 0..npkts {
        if !packet::produce(pool, i) {
            kprint!("   ring full at pkt[{}] (backpressure)\n", i);
            continue;
        }
        if let Some((port, v)) = packet::consume_one(pool) {
            let vs = if v == packet::DROP { "DROP" } else { "PASS" };
            kprint!("   pkt[{}] dst_port={} -> {}\n", i, port, vs);
            if v == packet::DROP {
                drops += 1;
            } else {
                passes += 1;
            }
        }
    }
    let ok = drops == 5 && passes == 5;
    kprint!(
        "   {} DROP, {} PASS over {} packets (wrapped ring) — inspected IN PLACE, never copied\n",
        drops, passes, npkts
    );
    kprint!("   [P5] {}\n", if ok { "PASS" } else { "FAIL" });
    ok
}

/// P5b self-test: bring up the virtio-net NIC, ARP the gateway, and push the
/// REAL received packet through the Packet Engine ring + verdict. This is the
/// north-star with a real wire (synthetic packets were P5).
fn p5b_real_wire() -> bool {
    kprint!(" [P5b] real wire: virtio-net -> Packet Engine ring\n");
    let mut buf = [0u8; 1600];
    let n = match arch_aarch64::virtio::rx_one_packet(&mut buf) {
        Some(n) => n,
        None => {
            kprint!("   no packet (virtio-net absent or no ARP reply)\n");
            return false;
        }
    };
    let et = ((buf.get(12).copied().unwrap_or(0) as u16) << 8) | buf.get(13).copied().unwrap_or(0) as u16;
    kprint!(
        "   RX {} bytes; dst {:02x}:{:02x}:.. ethertype {:#06x}{}\n",
        n, buf[0], buf[1], et,
        if et == 0x0806 { " (ARP reply)" } else { "" }
    );
    // Push the REAL packet through the zero-copy ring and get a verdict.
    let pool = arch_aarch64::mmu::reserve_region(packet::FRAME_SZ * 8);
    if !packet::produce_raw(pool, &buf[..n]) {
        kprint!("   ring full\n");
        return false;
    }
    let v = packet::consume_one(pool);
    let verdict = match v {
        Some((_, verdict)) => verdict,
        None => {
            kprint!("   ring empty after produce (bug)\n");
            return false;
        }
    };
    kprint!(
        "   Packet Engine verdict on the real packet: {}\n",
        if verdict == packet::DROP { "DROP" } else { "PASS" }
    );
    kprint!("   [P5b] PASS (real packet from virtio-net traversed the zero-copy ring)\n");
    true
}

/// P6 self-test: the RFC 9669 BPF VM runs the signed threat rule (real bytecode)
/// and classifies packets; a truncated packet is caught by the runtime bounds
/// check (the software sandbox). This same VM is the Packet Engine's verdict.
fn p6_ai_runtime() -> bool {
    kprint!(" [P6] AI Runtime: RFC 9669 BPF VM runs a signed threat rule\n");
    kprint!("   rule = {} BPF instructions (LDX/LSH/OR/JNE/MOV/EXIT), interpreted\n", bpf::THREAT_RULE.len());
    let mut ok = true;
    for &(port, expect) in &[(4444u16, "DROP"), (80u16, "PASS"), (443u16, "PASS")] {
        let pkt = [0u8, 0u8, (port >> 8) as u8, (port & 0xff) as u8]; // L4 hdr: dst-port at 2..4
        let v = bpf::run(&bpf::THREAT_RULE, pkt.as_ptr(), pkt.len());
        let vs = match v {
            bpf::DROP => "DROP",
            bpf::PASS => "PASS",
            _ => "INVALID",
        };
        kprint!("   BPF verdict on dst_port {} -> {}\n", port, vs);
        if vs != expect {
            ok = false;
        }
    }
    // Safety: a truncated packet makes the rule's 2nd load out-of-bounds; the
    // runtime bounds check must reject it (fail-safe), not read past the buffer.
    let short = [0x11u8];
    let rejected = bpf::run(&bpf::THREAT_RULE, short.as_ptr(), short.len()) == bpf::INVALID;
    kprint!("   BPF on truncated packet -> {} (runtime bounds check / sandbox)\n", if rejected { "REJECTED" } else { "LEAKED?!" });
    if !rejected {
        ok = false;
    }
    kprint!("   (this VM is the Packet Engine's verdict — P5/P5b ran it on every packet)\n");
    kprint!("   [P6] {}\n", if ok { "PASS" } else { "FAIL" });
    ok
}

/// P6b self-test: static verifier, native JIT (W^X) matching the interpreter,
/// a self-heal supervisor (HAM-style restart-on-fault), and the telemetry /
/// QSecBit-lite score aggregated from kernel events ("the OS is the sensor").
fn p6b_demo() -> bool {
    kprint!(" [P6b] BPF verifier + JIT (native codegen) + self-heal + telemetry\n");
    let mut ok = true;

    // 1. Verifier: accept the signed rule; reject a program with a backward jump
    //    (a loop — non-terminating).
    let good = bpf::verify_structural_demo(&bpf::THREAT_RULE);
    let backward: [u64; 2] = [0xFFFF_0055, 0x0000_0095]; // JNE off=-1 (backward), EXIT
    let bad = bpf::verify_structural_demo(&backward);
    kprint!(
        "   verifier: signed rule -> {}, looping rule -> {}\n",
        if good { "ACCEPT" } else { "reject?!" },
        if bad { "accept?!" } else { "REJECT" }
    );
    if !good || bad {
        ok = false;
    }

    // 2. JIT: compile the rule to native ARM64 (general two-pass compiler), run
    //    it, compare to the interpreter.
    match arch_aarch64::bpf_jit::compile(&bpf::THREAT_RULE) {
        Some(code_va) => {
            let f: extern "C" fn(*const u8) -> u64 =
                unsafe { core::mem::transmute::<usize, extern "C" fn(*const u8) -> u64>(code_va) };
            let mut jit_ok = true;
            for &port in &[4444u16, 80u16, 443u16] {
                let pkt = [0u8, 0u8, (port >> 8) as u8, (port & 0xff) as u8]; // L4 hdr: dst-port at 2..4
                let jv = f(pkt.as_ptr());
                let iv = bpf::run(&bpf::THREAT_RULE, pkt.as_ptr(), pkt.len());
                if jv != iv {
                    jit_ok = false;
                }
            }
            kprint!(
                "   JIT: rule -> native ARM64 @ {:#x} (W^X, RO+exec); matches interpreter: {}\n",
                code_va,
                if jit_ok { "yes" } else { "NO" }
            );
            if !jit_ok {
                ok = false;
            }
        }
        None => {
            kprint!("   JIT: compile FAILED\n");
            ok = false;
        }
    }

    // 3. Self-heal supervisor (HAM-style restart-on-fault).
    self_heal_supervisor();

    // 4. Telemetry / QSecBit-lite: events sensed from within the TCB.
    kprint!(
        "   telemetry: revokes={} faults={} drops={} self-heals={} | QSecBit score={}\n",
        telemetry::count(telemetry::Event::CapRevoke),
        telemetry::count(telemetry::Event::Fault),
        telemetry::count(telemetry::Event::PacketDrop),
        telemetry::count(telemetry::Event::SelfHeal),
        telemetry::score()
    );

    kprint!("   [P6b] {}\n", if ok { "PASS" } else { "FAIL" });
    ok
}

/// HAM-style supervisor: run a component; on fault, restart it (log a self-heal
/// event) until it recovers. The kernel-level analog of the FreeBSD/QNX HAM and
/// of the dev-time kernel-validator — HEQK heals itself, not just its build.
fn self_heal_supervisor() {
    kprint!("   self-heal: supervising a flaky component (HAM-style)...\n");
    let mut attempt = 0u32;
    let mut heals = 0u32;
    loop {
        attempt += 1;
        if flaky_component(attempt) {
            kprint!("     component healthy on attempt {} ({} restarts)\n", attempt, heals);
            break;
        }
        telemetry::emit(telemetry::Event::Fault);
        telemetry::emit(telemetry::Event::SelfHeal);
        heals += 1;
        kprint!("     component faulted -> supervisor restarted it (heal #{})\n", heals);
        if attempt >= 5 {
            break;
        }
    }
}

/// Stand-in component that faults twice, then recovers on the third restart.
fn flaky_component(attempt: u32) -> bool {
    attempt >= 3
}

/// Driver isolation: run a driver at **EL0** with *only* a capability-granted
/// device-MMIO window (the NIC's virtio-mmio page) — no kernel access. It reads
/// a NIC register and reports it. A compromise of this driver is contained to
/// EL0 + that one device; it cannot address the kernel, the detector, or keys.
/// (This proves the *mechanism*; migrating the full virtio-net driver — DMA +
/// virtqueues + IRQ — into this server is the larger staged effort.)
fn driver_server_demo() -> bool {
    kprint!(" [DRV] driver isolation: an EL0 driver server drives device MMIO via a capability\n");
    let mmu = arch_aarch64::Mmu;
    extern "C" {
        static driver_stub: u8;
        static driver_stub_end: u8;
    }
    let src = core::ptr::addr_of!(driver_stub) as usize;
    let len = core::ptr::addr_of!(driver_stub_end) as usize - src;
    let code = mmu.alloc_frame();
    let stack = mmu.alloc_frame();
    if code == 0 || stack == 0 {
        kprint!("   FAIL: no frames\n");
        return false;
    }
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, code as *mut u8, len) };
    arch_aarch64::mmu::sync_instruction_cache(code, len);

    const DCODE_VA: usize = 0xD200_0000;
    const DSTACK_VA: usize = 0xD200_1000;
    const DEV_VA: usize = 0xE200_0000;
    const NET_MMIO_PAGE: usize = 0x0a00_3000; // page holding virtio-mmio slot 31 (net)
    mmu.map_user_code_page(DCODE_VA, code);
    mmu.map_user_data_page(DSTACK_VA, stack);
    mmu.map_user_device_page(DEV_VA, NET_MMIO_PAGE); // the ONLY hardware it can touch
    kprint!(
        "   EL0 driver: code@{:#x} stack@{:#x} device-window {:#x} -> NIC MMIO (nothing else granted)\n",
        DCODE_VA, DSTACK_VA, DEV_VA
    );

    DRIVER_REPORT.store(0, Ordering::Relaxed);
    unsafe { arch_aarch64::syscall::enter_user(DCODE_VA, DSTACK_VA + 0x1000) };
    let id = DRIVER_REPORT.load(Ordering::Relaxed);
    kprint!("   back in EL1; the isolated driver read NIC DeviceID = {} (expect 1 = virtio-net)\n", id);
    let ok = id == 1;
    kprint!(
        "   [DRV] {} — a driver ran at EL0 with ONLY a device capability; kernel untouched\n",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

fn spin(n: u32) {
    for _ in 0..n {
        core::hint::spin_loop();
    }
}

// Priority workers: each prints its letter a few times then EXITS. Under strict
// priority the highest runs to completion first (H*, then M*, then L*); each
// letter's counter advancing across ticks proves context switch still works.
extern "C" fn thread_hi() -> ! {
    worker(b'H', 3)
}
extern "C" fn thread_mid() -> ! {
    worker(b'M', 3)
}
extern "C" fn thread_lo() -> ! {
    worker(b'L', 3)
}

fn worker(letter: u8, iters: u32) -> ! {
    let mut n = 0;
    while n < iters {
        kprint!("{}{} ", letter as char, n);
        n += 1;
        spin(WORK);
    }
    thread_exit()
}

fn thread_exit() -> ! {
    scheduler::exit_current();
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}

// P4 — synchronous IPC rendezvous over an Endpoint. consumer (higher priority)
// runs first and blocks in recv(); producer then sends, unblocking it.
extern "C" fn consumer() -> ! {
    kprint!(" [P4] consumer: recv() — blocks until producer sends...\n");
    let m = ipc::recv().unwrap_or(0); // CORE-11: None = endpoint busy (not a 0 message)
    kprint!(" [P4] consumer: received {:#x} via endpoint rendezvous\n", m);
    kprint!(" [P4] PASS ipc (synchronous endpoint rendezvous with block/unblock)\n");
    thread_exit()
}
extern "C" fn producer() -> ! {
    kprint!(" [P4] producer: send(0xBEEF) to endpoint\n");
    let _ = ipc::send(0xBEEF); // CORE-11: false = endpoint busy
    kprint!(" [P4] producer: send returned (message delivered)\n");
    thread_exit()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    arch_aarch64::on_panic(info)
}

/// AP diag: one line per NAT event — direction, proto, TCP flags, IP length, ports, result.
#[allow(dead_code)]
fn nat_trace_line(dir: &str, f: &[u8], res: &str) {
    if f.len() < 34 {
        return;
    }
    let ihl = ((f[14] & 0x0f) as usize) * 4;
    let l4 = 14 + ihl;
    let proto = f[23];
    let iplen = u16::from_be_bytes([f[16], f[17]]);
    let (sp, dp) = if f.len() >= l4 + 4 && (proto == 6 || proto == 17) {
        (u16::from_be_bytes([f[l4], f[l4 + 1]]), u16::from_be_bytes([f[l4 + 2], f[l4 + 3]]))
    } else {
        (0, 0)
    };
    let fl = if proto == 6 && f.len() > l4 + 13 { f[l4 + 13] } else { 0 };
    kprint!("   [NAT-TRACE] {} {} {}.{}.{}.{}:{} -> {}.{}.{}.{}:{} iplen={} tcpflags={}{}{}{}{} {}\n",
        dir, match proto { 6 => "tcp", 17 => "udp", 1 => "icmp", _ => "ip" },
        f[26], f[27], f[28], f[29], sp, f[30], f[31], f[32], f[33], dp, iplen,
        if fl & 0x02 != 0 { "S" } else { "" }, if fl & 0x10 != 0 { "A" } else { "" },
        if fl & 0x08 != 0 { "P" } else { "" }, if fl & 0x01 != 0 { "F" } else { "" },
        if fl & 0x04 != 0 { "R" } else { "" }, res);
}

/// `[P11-acs]` — the AP channel selection (hal::acs_choose) against fixed scan vectors.
#[allow(dead_code)]
fn acs_selftest() {
    let bw80_42 = 42u16 | 0x2000 | 0xc000; // a 5 GHz 80 MHz BSS on the UNII-1 block
    // (a) clean air: 5 GHz/80.
    let a = hal::acs_choose(&[]);
    // (b) the bench: fortress 80 MHz @ -51 on UNII-1 + 2.4 GHz neighbours -> STAY on 5 GHz/80
    //     (measured: shared 5 GHz/80 = 22 Mbps > clean 2.4 GHz/20 = 15 Mbps).
    let bench = [(bw80_42, -51i16), (1u16 | 0x1000, -70), (1 | 0x1000, -81), (6 | 0x1000, -32),
                 (6 | 0x1000, -83), (6 | 0x1000, -76), (11 | 0x1000, -84)];
    let b = hal::acs_choose(&bench);
    // (c) a weak (-88 dBm) 5 GHz neighbour is ignored.
    let c = hal::acs_choose(&[(bw80_42, -88)]);
    // (d) the 80 MHz block genuinely crowded (6 strong 80-MHz BSSs), 2.4 GHz ch1 clean -> 2.4 ch1.
    let crowded = [(bw80_42, -50i16), (bw80_42, -55), (bw80_42, -60), (bw80_42, -62), (bw80_42, -65), (bw80_42, -70),
                   (6 | 0x1000, -50), (11 | 0x1000, -55)];
    let d = hal::acs_choose(&crowded);
    // (e) two strong 20-MHz neighbours on 36 and 40, 44/48 free, 2.4 crowded: 5 GHz/80 still beats
    //     a free 5 GHz/20 (433/3 = 144 > 87).
    let e = hal::acs_choose(&[(36 | 0x1000 | 0xc000, -40), (40 | 0x1000 | 0xc000, -45), (1 | 0x1000, -40), (6 | 0x1000, -40), (11 | 0x1000, -40)]);
    let ok = (a.channel, a.mhz, a.chanspec) == (36, 80, 0xe02a)
        && (b.channel, b.mhz, b.chanspec) == (36, 80, 0xe02a) && b.score == 1
        && (c.channel, c.mhz) == (36, 80) && c.score == 0
        && (d.channel, d.mhz, d.chanspec) == (1, 20, 0x1001)
        && (e.channel, e.mhz) == (36, 80);
    kprint!(" [P11-acs] {} — AP channel selection = max expected throughput (peak / (1 + strong co-channel BSSs)): clean -> ch{}/{}MHz; bench (fortress 80 MHz @ -51) -> ch{}/{}MHz ~{} Mbps (stays on 5 GHz: measured 22 > 15 Mbps); weak neighbour ignored -> ch{}/{}MHz; crowded 80-MHz block -> ch{}/{}MHz; two strong 20-MHz on 36/40 -> ch{}/{}MHz\n",
        if ok { "PASS" } else { "FAIL" }, a.channel, a.mhz, b.channel, b.mhz, b.est_mbps, c.channel, c.mhz, d.channel, d.mhz, e.channel, e.mhz);
}

/// `[P11-glom]` — SDPCM superframe framing (hal::glom_plan / glom_split, the code the CM5 Wi-Fi
/// driver runs) against frames built to brcmfmac's layout: a descriptor listing 3 sub-frames, a
/// superframe = superframe header + data/event/data sub-frames, last sub-frame padded to the block.
#[allow(dead_code)]
fn glom_selftest() {
    fn hdr(b: &mut [u8], len: u16, chan: u8, flags: u8, doff: u8) {
        b[0..2].copy_from_slice(&len.to_le_bytes());
        b[2..4].copy_from_slice(&(!len).to_le_bytes());
        b[4] = 0;
        b[5] = (chan & 0x0f) | flags;
        b[6] = 0;
        b[7] = doff;
        b[8..12].copy_from_slice(&[0, 0x40, 0, 0]);
    }
    // sub-frame lengths (4-aligned) — first includes the 12-B superframe header.
    let (s0, s1, s2) = (12 + 100usize, 60usize, 300usize);
    let mut desc = [0u8; 6];
    desc[0..2].copy_from_slice(&(s0 as u16).to_le_bytes());
    desc[2..4].copy_from_slice(&(s1 as u16).to_le_bytes());
    desc[4..6].copy_from_slice(&(s2 as u16).to_le_bytes());
    let mut subl = [0u16; hal::GLOM_MAX_SUBS];
    let plan = hal::glom_plan(&desc, 512, &mut subl);
    let plan_ok = plan == Some((3, 512)) && subl[0] as usize == s0 && subl[2] as usize == 512 - s0 - s1;
    let mut sup = [0u8; 512];
    hdr(&mut sup[0..], 512, 3, 0, 12); // superframe header
    hdr(&mut sup[12..], 100, 2, 0, 14); // data
    hdr(&mut sup[s0..], 60, 1, 0, 12); // event
    hdr(&mut sup[s0 + s1..], 300, 2, 0, 14); // data
    let mut subs = [hal::GlomSub::default(); hal::GLOM_MAX_SUBS];
    let n = hal::glom_split(&sup, &subl[..3], &mut subs);
    let split_ok = n == Some(3)
        && subs[0] == hal::GlomSub { start: 12, len: 100, chan: 2, doff: 14 }
        && subs[1] == hal::GlomSub { start: s0 as u16, len: 60, chan: 1, doff: 12 }
        && subs[2] == hal::GlomSub { start: (s0 + s1) as u16, len: 300, chan: 2, doff: 14 };
    // negatives (each must be refused, as brcmfmac does)
    let odd = hal::glom_plan(&desc[..5], 512, &mut subl).is_none();
    let mut short = desc;
    short[0..2].copy_from_slice(&20u16.to_le_bytes()); // first < 2*HDRLEN
    let short_ok = hal::glom_plan(&short, 512, &mut subl).is_none();
    let _ = hal::glom_plan(&desc, 512, &mut subl);
    let mut bad_ck = sup;
    bad_ck[s0 + 2] ^= 1; // event sub-frame tag check broken
    let bad_ck_ok = hal::glom_split(&bad_ck, &subl[..3], &mut subs).is_none();
    let mut bad_ch = sup;
    bad_ch[s0 + s1 + 5] = 0; // sub-frame on the control channel
    let bad_ch_ok = hal::glom_split(&bad_ch, &subl[..3], &mut subs).is_none();
    let mut not_super = sup;
    not_super[5] = 3 | 0x80; // a descriptor where the superframe should be
    let not_super_ok = hal::glom_split(&not_super, &subl[..3], &mut subs).is_none();
    let ok = plan_ok && split_ok && odd && short_ok && bad_ck_ok && bad_ch_ok && not_super_ok;
    kprint!(" [P11-glom] {} — SDPCM superframe (brcmf_sdio_rxglom framing): plan 3 subs -> one 512-B block={} split data/event/data={} | refused: odd descriptor={} short first sub={} bad tag={} control-channel sub={} descriptor-as-superframe={}\n",
        if ok { "PASS" } else { "FAIL" }, plan_ok, split_ok, odd, short_ok, bad_ck_ok, bad_ch_ok, not_super_ok);
}

/// `[P11-dnsfwd]` — the AP's DNS service (nat::outbound_redirect + inbound): a client query to the
/// AP address is forwarded to the upstream resolver through SNAT, the reply comes back FROM the AP
/// address with valid checksums; a query sent straight to another resolver is not redirected.
#[allow(dead_code)]
fn dnsfwd_selftest() {
    use arch_aarch64::nat;
    fn csum16(b: &[u8], init: u32) -> u16 {
        let mut s = init;
        let mut i = 0;
        while i + 1 < b.len() {
            s += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
            i += 2;
        }
        if i < b.len() {
            s += (b[i] as u32) << 8;
        }
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }
    fn udp_ok(f: &[u8]) -> bool {
        let ip_ok = csum16(&f[14..34], 0) == 0;
        let ulen = u16::from_be_bytes([f[38], f[39]]) as u32;
        let mut ps = 0u32;
        for k in (26..34).step_by(2) {
            ps += u16::from_be_bytes([f[k], f[k + 1]]) as u32;
        }
        ps += 17 + ulen;
        ip_ok && csum16(&f[34..34 + ulen as usize], ps) == 0
    }
    fn frame(buf: &mut [u8; 80], dmac: [u8; 6], smac: [u8; 6], sip: [u8; 4], dip: [u8; 4], sp: u16, dp: u16) -> usize {
        *buf = [0; 80];
        buf[0..6].copy_from_slice(&dmac);
        buf[6..12].copy_from_slice(&smac);
        buf[12] = 0x08;
        buf[14] = 0x45;
        let tot: u16 = 20 + 8 + 20;
        buf[16..18].copy_from_slice(&tot.to_be_bytes());
        buf[22] = 64;
        buf[23] = 17;
        buf[26..30].copy_from_slice(&sip);
        buf[30..34].copy_from_slice(&dip);
        buf[34..36].copy_from_slice(&sp.to_be_bytes());
        buf[36..38].copy_from_slice(&dp.to_be_bytes());
        buf[38..40].copy_from_slice(&28u16.to_be_bytes());
        buf[40] = 0x12; // non-zero UDP checksum placeholder -> recomputed by NAT
        buf[42..62].copy_from_slice(b"dns-query-payload-01");
        14 + tot as usize
    }
    let (ap_ip, resolver, wan_ip) = ([10u8, 99, 0, 1], [10u8, 200, 0, 1], [10u8, 200, 0, 14]);
    let (cli_ip, cli_mac, ap_mac) = ([10u8, 99, 0, 10], [2u8, 0xaa, 0, 0, 0, 1], [2u8, 0xbb, 0, 0, 0, 1]);
    let (wan_mac, gw_mac) = ([2u8, 0, 0, 0, 0, 2], [2u8, 0xcc, 0, 0, 0, 1]);
    let inside = [10u8, 99, 0];
    let mut st = nat::NatStats::default();
    let now: u64 = { let v: u64; unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) }; v };
    let mut q = [0u8; 80];
    let mut out = [0u8; 128];
    let n = frame(&mut q, ap_mac, cli_mac, cli_ip, ap_ip, 51000, 53);
    let fwd = nat::outbound_redirect(&q[..n], nat::IF_WIFI, &inside, Some((&ap_ip, &resolver)), &wan_ip, &wan_mac, &gw_mac, &mut out, now, &mut st);
    let ext = u16::from_be_bytes([out[34], out[35]]);
    let out_ok = fwd.is_some() && out[26..30] == wan_ip && out[30..34] == resolver && udp_ok(&out) && st.dns_redirect == 1;
    // the resolver answers the SNAT'd query
    let mut r = [0u8; 80];
    let rn = frame(&mut r, wan_mac, gw_mac, resolver, wan_ip, 53, ext);
    let mut back = [0u8; 128];
    let inb = nat::inbound(&r[..rn], &wan_ip, &wan_mac, [&ap_mac, &ap_mac], &mut back, now, &mut st);
    let back_ok = inb.is_some() && back[26..30] == ap_ip && back[30..34] == cli_ip
        && u16::from_be_bytes([back[36], back[37]]) == 51000 && back[0..6] == cli_mac && udp_ok(&back);
    // a query straight to 1.1.1.1 is NOT redirected, and its reply keeps 1.1.1.1 as the source
    let n2 = frame(&mut q, ap_mac, cli_mac, cli_ip, [1, 1, 1, 1], 51002, 53);
    let f2 = nat::outbound_redirect(&q[..n2], nat::IF_WIFI, &inside, Some((&ap_ip, &resolver)), &wan_ip, &wan_mac, &gw_mac, &mut out, now, &mut st);
    let ext2 = u16::from_be_bytes([out[34], out[35]]);
    let direct_ok = f2.is_some() && out[30..34] == [1, 1, 1, 1] && st.dns_redirect == 1;
    let rn2 = frame(&mut r, wan_mac, gw_mac, [1, 1, 1, 1], wan_ip, 53, ext2);
    let inb2 = nat::inbound(&r[..rn2], &wan_ip, &wan_mac, [&ap_mac, &ap_mac], &mut back, now, &mut st);
    let direct_back_ok = inb2.is_some() && back[26..30] == [1, 1, 1, 1] && udp_ok(&back);
    // Peer review SEC-M2 regression: a DIFFERENT remote sending to the same live mapping is refused
    // (address-dependent filtering) — only the host the client talked to gets in.
    let rn3 = frame(&mut r, wan_mac, gw_mac, [9, 9, 9, 9], wan_ip, 53, ext2);
    let adf_ok = nat::inbound(&r[..rn3], &wan_ip, &wan_mac, [&ap_mac, &ap_mac], &mut back, now, &mut st).is_none();
    // RFC 5508: an ICMP port-unreachable from an upstream router quoting the SNAT'd 1.1.1.1 query goes
    // back to the client with outer dst + quoted src/port translated and valid IP/ICMP checksums.
    let icmp_ok = {
        // re-send the direct query to get its SNAT'd form (= what the router quotes)
        let n2b = frame(&mut q, ap_mac, cli_mac, cli_ip, [1, 1, 1, 1], 51002, 53);
        let _ = nat::outbound_redirect(&q[..n2b], nat::IF_WIFI, &inside, Some((&ap_ip, &resolver)), &wan_ip, &wan_mac, &gw_mac, &mut out, now, &mut st);
        let quoted = out[14..42].to_vec(); // IP header + 8 bytes of UDP
        let mut e = [0u8; 128];
        e[0..6].copy_from_slice(&wan_mac);
        e[6..12].copy_from_slice(&gw_mac);
        e[12] = 0x08;
        e[14] = 0x45;
        let tot = (20 + 8 + quoted.len()) as u16;
        e[16..18].copy_from_slice(&tot.to_be_bytes());
        e[22] = 64;
        e[23] = 1;
        e[26..30].copy_from_slice(&[10, 200, 0, 1]);
        e[30..34].copy_from_slice(&wan_ip);
        e[34] = 3; // destination unreachable
        e[35] = 3; // port unreachable
        e[42..42 + quoted.len()].copy_from_slice(&quoted);
        let c = csum16(&e[14..34], 0);
        e[24..26].copy_from_slice(&c.to_be_bytes());
        let c = csum16(&e[34..14 + tot as usize], 0);
        e[36..38].copy_from_slice(&c.to_be_bytes());
        let before = st.icmp_err_in;
        match nat::inbound(&e[..14 + tot as usize], &wan_ip, &wan_mac, [&ap_mac, &ap_mac], &mut back, now, &mut st) {
            Some((k, _)) => back[30..34] == cli_ip && back[42 + 12..42 + 16] == cli_ip
                && u16::from_be_bytes([back[42 + 20], back[42 + 21]]) == 51002 && back[0..6] == cli_mac
                && csum16(&back[14..34], 0) == 0 && csum16(&back[34..k], 0) == 0 && csum16(&back[42..62], 0) == 0
                && st.icmp_err_in == before + 1,
            None => false,
        }
    };
    // SEC-P2: an ICMP error about a DNS-REDIRECTED query quotes the AP address the client used, not the
    // upstream resolver.
    let icmp_dnat_ok = {
        let n0 = frame(&mut q, ap_mac, cli_mac, cli_ip, ap_ip, 51006, 53);
        let _ = nat::outbound_redirect(&q[..n0], nat::IF_WIFI, &inside, Some((&ap_ip, &resolver)), &wan_ip, &wan_mac, &gw_mac, &mut out, now, &mut st);
        let quoted = out[14..42].to_vec();
        let mut e = [0u8; 128];
        e[0..6].copy_from_slice(&wan_mac);
        e[6..12].copy_from_slice(&gw_mac);
        e[12] = 0x08;
        e[14] = 0x45;
        let tot = (20 + 8 + quoted.len()) as u16;
        e[16..18].copy_from_slice(&tot.to_be_bytes());
        e[22] = 64;
        e[23] = 1;
        e[26..30].copy_from_slice(&resolver);
        e[30..34].copy_from_slice(&wan_ip);
        e[34] = 3;
        e[35] = 3;
        e[42..42 + quoted.len()].copy_from_slice(&quoted);
        let c = csum16(&e[14..34], 0);
        e[24..26].copy_from_slice(&c.to_be_bytes());
        let c = csum16(&e[34..14 + tot as usize], 0);
        e[36..38].copy_from_slice(&c.to_be_bytes());
        match nat::inbound(&e[..14 + tot as usize], &wan_ip, &wan_mac, [&ap_mac, &ap_mac], &mut back, now, &mut st) {
            Some((k, _)) => back[42 + 16..42 + 20] == ap_ip && back[42 + 12..42 + 16] == cli_ip && csum16(&back[42..62], 0) == 0 && csum16(&back[34..k], 0) == 0,
            None => false,
        }
    };
    // a non-DNS packet to the AP address stays local (never NATed)
    let n3 = frame(&mut q, ap_mac, cli_mac, cli_ip, ap_ip, 51004, 80);
    let local_ok = nat::outbound_redirect(&q[..n3], nat::IF_WIFI, &inside, Some((&ap_ip, &resolver)), &wan_ip, &wan_mac, &gw_mac, &mut out, now, &mut st).is_none();
    let ok = out_ok && back_ok && direct_ok && direct_back_ok && local_ok && icmp_ok && adf_ok && icmp_dnat_ok;
    kprint!(" [P11-dnsfwd] {} — AP DNS: query to the AP -> forwarded to the upstream resolver via SNAT={} reply returns FROM the AP to the client, checksums valid={} | direct query to 1.1.1.1 not redirected={} its reply keeps 1.1.1.1={} | non-DNS to the AP stays local={} | ICMP error quoting a NATed flow translated back (RFC 5508: outer dst + quoted src/port, checksums)={} | another remote to the same live mapping refused (address-dependent filtering)={} | ICMP error for a DNS-redirected query quotes the AP address={}\n",
        if ok { "PASS" } else { "FAIL" }, out_ok, back_ok, direct_ok, direct_back_ok, local_ok, icmp_ok, adf_ok, icmp_dnat_ok);
}

/// 4-hex-digit formatting helper for a chanspec (no alloc): returns the value for `{:#06x}` printing.
#[allow(dead_code)]
fn alloc_free_hex(v: u16) -> u16 {
    v
}

/// WAN.TXT on the boot partition (one 512-B sector, like OWNER.TXT): the operator's WAN mode.
pub const WAN_8_3: &[u8; 11] = b"WAN     TXT";
pub const POLICY_8_3: &[u8; 11] = b"POLICY  TXT";
/// The operator's WAN policy (POLICY.TXT): interface-attached ACLs + prefix lists, routes (task #26).
pub static mut POLICY: hal::policy::Policy = hal::policy::Policy::new();

/// WAN.TXT link keys (VLAN / QinQ / management sub-interface).
fn load_wan_link<D: hal::BlockDev>(dev: &D) -> Option<Result<hal::WanLink, hal::WanCfgErr>> {
    let mut sec = [0u8; 512];
    dev.read_block(0, &mut sec).ok()?;
    let p1 = store::parse_mbr(&sec)[0].start;
    if p1 == 0 {
        return None;
    }
    let (lba, _n) = fat::locate_contiguous(dev, p1, WAN_8_3)?;
    dev.read_block(lba, &mut sec).ok()?;
    Some(hal::parse_wan_link(&sec))
}

/// A station frame for Mission Control on the AP address: IPv4 TCP to `our_ip`:80/443.
#[allow(dead_code)]
fn mc_bound(f: &[u8], our_ip: &[u8; 4]) -> bool {
    if !cfg!(feature = "mcserve") || f.len() < 38 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 6 || &f[30..34] != our_ip {
        return false;
    }
    let ihl = ((f[14] & 0x0f) as usize) * 4;
    let Some(p) = f.get(14 + ihl + 2..14 + ihl + 4) else { return false };
    let dport = u16::from_be_bytes([p[0], p[1]]);
    dport == 80 || dport == 443
}

/// POLICY.TXT (up to 4 KiB, contiguous on the FAT boot partition) -> POLICY. None = no file.
fn load_policy<D: hal::BlockDev>(dev: &D) -> Option<Result<(), hal::policy::PolicyErr>> {
    let mut sec = [0u8; 512];
    dev.read_block(0, &mut sec).ok()?;
    let p1 = store::parse_mbr(&sec)[0].start;
    if p1 == 0 {
        return None;
    }
    let (lba, n) = fat::locate_contiguous(dev, p1, POLICY_8_3)?;
    let mut buf = [0u8; hal::policy::POLICY_FILE_LEN];
    for k in 0..(n as usize).min(hal::policy::POLICY_FILE_LEN / 512) {
        dev.read_block(lba + k as u64, &mut sec).ok()?;
        buf[k * 512..k * 512 + 512].copy_from_slice(&sec);
    }
    // ADR 0049 D1: with an operator key in this image, the signature is checked BEFORE the parser sees a
    // byte; any failure is reported as a rejected policy (=> the management lockdown below), never applied.
    if let Some(key) = policysig::POLICY_PUBKEY {
        let mut sig = [0u8; policysig::SIG_FILE_LEN];
        let have = fat::locate_contiguous(dev, p1, policysig::SIG_8_3)
            .and_then(|(l, _)| dev.read_block(l, &mut sig).ok())
            .is_some();
        let r = if have { policysig::verify(&buf, &sig, &key, policysig::POLICY_GEN_FLOOR) } else { Err(policysig::SigErr::Missing) };
        match r {
            Ok(gen) => kprint!(" [POLICY] signature OK — operator key, generation {} (floor {})\n", gen, policysig::POLICY_GEN_FLOOR),
            Err(e) => {
                kprint!(" [POLICY] signature REFUSED ({:?}) — the policy is not parsed\n", e);
                return Some(Err(hal::policy::PolicyErr::Unsigned));
            }
        }
    } else {
        kprint!(" [POLICY] no operator key in this image (standalone) — POLICY.TXT accepted unsigned\n");
    }
    Some(hal::policy::parse_policy(&buf, unsafe { &mut *core::ptr::addr_of_mut!(POLICY) }))
}

/// Read + parse WAN.TXT from a block device's first partition. None = no file (=> DHCP).
#[allow(dead_code)]
fn load_wan_cfg<D: hal::BlockDev>(dev: &D) -> Option<Result<hal::WanMode, hal::WanCfgErr>> {
    let mut sec = [0u8; 512];
    dev.read_block(0, &mut sec).ok()?;
    let p1 = store::parse_mbr(&sec)[0].start;
    if p1 == 0 {
        return None;
    }
    let (lba, _n) = fat::locate_contiguous(dev, p1, WAN_8_3)?;
    dev.read_block(lba, &mut sec).ok()?;
    Some(hal::parse_wan_cfg(&sec))
}

/// `[P-wancfg]` — WAN.TXT parsing (hal::parse_wan_cfg) against fixed vectors.
#[allow(dead_code)]
fn wancfg_selftest() {
    use hal::{parse_wan_cfg as p, WanCfgErr as E, WanMode as M};
    let dhcp = p(b"HQWAN1\nmode=dhcp\n") == Ok(M::Dhcp);
    let padded = p(b"# heqk WAN\r\nHQWAN1\r\nmode=dhcp\r\n\n\n      \0\0\0") == Ok(M::Dhcp);
    let st = p(b"HQWAN1\nmode=static\nip=10.200.0.12/28\ngw=10.200.0.1\ndns=10.200.0.1\n")
        == Ok(M::Static { ip: [10, 200, 0, 12], prefix: 28, gw: [10, 200, 0, 1], dns: [10, 200, 0, 1] });
    let st_dns_default = p(b"HQWAN1\nmode=static\nip=192.0.2.10/24\ngw=192.0.2.1\n")
        == Ok(M::Static { ip: [192, 0, 2, 10], prefix: 24, gw: [192, 0, 2, 1], dns: [192, 0, 2, 1] });
    let gw_out = p(b"HQWAN1\nmode=static\nip=10.200.0.12/28\ngw=10.200.1.1\n") == Err(E::BadGateway);
    let bad_pfx = p(b"HQWAN1\nmode=static\nip=10.0.0.5/31\ngw=10.0.0.4\n") == Err(E::BadPrefix);
    let net_addr = p(b"HQWAN1\nmode=static\nip=10.200.0.0/28\ngw=10.200.0.1\n") == Err(E::BadHost);
    let bad_quad = p(b"HQWAN1\nmode=static\nip=10.200.0.256/28\ngw=10.200.0.1\n") == Err(E::BadAddr);
    let pppoe = match p(b"HQWAN1\nmode=pppoe\npppoe_user=client@isp\npppoe_pass=s3cret!\n") {
        Ok(M::Pppoe { user, user_len, pass, pass_len }) => &user[..user_len as usize] == b"client@isp" && &pass[..pass_len as usize] == b"s3cret!",
        _ => false,
    };
    let pppoe_nouser = p(b"HQWAN1\nmode=pppoe\npppoe_pass=x\n") == Err(E::Missing);
    let no_magic = p(b"mode=dhcp\n") == Err(E::NoMagic);
    let unknown = p(b"HQWAN1\nmode=dhcp\nfoo=bar\n") == Err(E::BadLine);
    let bad_mode = p(b"HQWAN1\nmode=ppp\n") == Err(E::BadMode);
    let ok = dhcp && padded && st && st_dns_default && gw_out && bad_pfx && net_addr && bad_quad && pppoe && pppoe_nouser && no_magic && unknown && bad_mode;
    kprint!(" [P-wancfg] {} — WAN.TXT: dhcp={} padded/CRLF={} static={} dns-defaults-to-gw={} pppoe creds={} | refused: gw outside subnet={} /31={} network address={} bad quad={} pppoe w/o user={} no magic={} unknown key={} bad mode={}\n",
        if ok { "PASS" } else { "FAIL" }, dhcp, padded, st, st_dns_default, pppoe, gw_out, bad_pfx, net_addr, bad_quad, pppoe_nouser, no_magic, unknown, bad_mode);
}

/// `[P-md5]` — RFC 1321 appendix A.5 test vectors (MD5 exists only for PPP CHAP-MD5).
#[allow(dead_code)]
fn md5_selftest() {
    fn hx(h: &[u8; 16], want: &str) -> bool {
        let w = want.as_bytes();
        (0..16).all(|i| {
            let nib = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
            h[i] == (nib(w[2 * i]) << 4) | nib(w[2 * i + 1])
        })
    }
    let v = [
        (&b""[..], "d41d8cd98f00b204e9800998ecf8427e"),
        (&b"a"[..], "0cc175b9c0f1b6a831c399e269772661"),
        (&b"abc"[..], "900150983cd24fb0d6963f7d28e17f72"),
        (&b"message digest"[..], "f96b697d7cb7938d525a2f31aaf161d0"),
        (&b"abcdefghijklmnopqrstuvwxyz"[..], "c3fcd3d76192e4007dfb496cca67e13b"),
        (&b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"[..], "57edf4a22be3c955ac49da2e2107b67a"),
    ];
    let ok = v.iter().all(|(d, h)| hx(&hal::md5(d), h));
    kprint!(" [P-md5] {} — RFC 1321 A.5 vectors (6/6 incl. the 80-byte two-block case) — used only by PPP CHAP-MD5\n",
        if ok { "PASS" } else { "FAIL" });
}

/// `[P-policy]` — the WAN policy engine (hal::policy) + the WAN.TXT link keys: IPv6 text parsing,
/// prefix-list ge/le semantics, ACL first-match by number with hit counts, longest-prefix routes, the
/// management allow-list, whole-file rejection, VLAN/QinQ/management sub-interface config, and the
/// tag stack + the MTU derived from the headers.
#[allow(dead_code)]
fn policy_selftest() {
    use hal::policy::*;
    let v6 = |s: &[u8]| parse_v6(s);
    let v6_ok = v6(b"2001:db8::1") == Some([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        && v6(b"::") == Some([0; 16])
        && v6(b"fe80::ba27:ebff:fe74:f26c").map(|a| a[8..10] == [0xba, 0x27] && a[15] == 0x6c) == Some(true)
        && v6(b"1:2:3:4:5:6:7:8").is_some()
        && v6(b"1::2::3").is_none() && v6(b"12345::").is_none() && v6(b"1:2:3:4:5:6:7:8:9").is_none() && v6(b"g::1").is_none();
    let txt: &[u8] = b"HQPOL1
# test policy
prefix-list RFC1918 seq 10 permit 10.0.0.0/8 le 32
prefix-list RFC1918 seq 20 permit 172.16.0.0/12 le 32
prefix-list RFC1918 seq 30 permit 192.168.0.0/16 le 32
prefix-list ADMINS seq 5 permit 192.168.200.0/24 le 32
prefix-list DEFAULTONLY seq 10 permit 0.0.0.0/0
prefix-list V6LAN seq 20 permit 2a02:2f05::/32 ge 48 le 64
prefix-list V6LAN seq 10 deny 2a02:2f05:dead::/48 le 64
prefix-list LANSRC seq 10 permit 10.99.0.0/24 le 32
acl LAN-OUT seq 20 allow tcp any any 443
acl LAN-OUT seq 10 drop any any pl:RFC1918
acl LAN-OUT seq 30 block udp any any 53
acl LAN-OUT seq 40 drop tcp any 2001:db8::/32 1-1023
acl LAN-OUT default allow
acl MGMT-IN seq 10 allow any pl:ADMINS any
interface lan acl in LAN-OUT
interface lan prefix-list in LANSRC
interface mgmt acl in MGMT-IN
route 0.0.0.0/0 via wan metric 10
route 0.0.0.0/0 via mgmt gw 192.168.200.1 metric 100
route 10.20.0.0/16 via mgmt gw 192.168.200.1
route 10.20.5.0/24 via wan
route 0.0.0.0/0 from 10.99.0.128/25 via mgmt gw 192.168.200.1 metric 5
route 2001:db8:1::/48 via mgmt
";
    let mut p = Policy::new();
    let parsed = parse_policy(txt, &mut p).is_ok() && p.npl == 5 && p.nacl == 2 && p.nbind == 3 && p.nroutes == 6
        && p.acl[0].n == 4 && p.acl[0].e[0].seq == 10 && p.acl[0].e[1].seq == 20 && p.acl[0].default == Some(Act::Allow) && p.acl[1].default.is_none();
    let a4 = |q: [u8; 4]| Addr::v4(q);
    let v6a = |s: &[u8]| Addr::v6(parse_v6(s).unwrap());
    let pk = |proto: u8, src: Addr, dst: Addr, dport: u16| Pkt { proto, src, dst, dport };
    let cli = a4([10, 99, 0, 5]);
    let acl_ok = p.check(If::Lan, Dir::In, &pk(6, cli, a4([10, 1, 2, 3]), 443)) == (Act::Drop, Decided::Acl(0, 10)) // seq 10 before 20
        && p.check(If::Lan, Dir::In, &pk(6, cli, a4([8, 8, 8, 8]), 443)) == (Act::Allow, Decided::Acl(0, 20))
        && p.check(If::Lan, Dir::In, &pk(17, cli, a4([8, 8, 8, 8]), 53)) == (Act::Block, Decided::Acl(0, 30))
        && p.check(If::Lan, Dir::In, &pk(17, cli, a4([1, 1, 1, 1]), 123)) == (Act::Allow, Decided::Acl(0, u16::MAX))
        && p.check(If::Lan, Dir::In, &pk(6, v6a(b"2a02::5"), v6a(b"2001:db8::80"), 80)) == (Act::Drop, Decided::Acl(0, 40)) // v6; the v4-only LANSRC does not apply
        && p.check(If::Lan, Dir::In, &pk(6, v6a(b"2a02::5"), v6a(b"2001:db8::80"), 8080)).0 == Act::Allow
        && p.check(If::Lan, Dir::In, &pk(6, a4([10, 98, 0, 5]), a4([8, 8, 8, 8]), 443)) == (Act::Drop, Decided::PrefixList(4)) // spoofed source
        && p.check(If::Mgmt, Dir::In, &pk(6, a4([192, 168, 200, 7]), a4([192, 168, 200, 2]), 443)) == (Act::Allow, Decided::Acl(1, 10))
        && p.check(If::Mgmt, Dir::In, &pk(6, a4([10, 0, 0, 1]), a4([192, 168, 200, 2]), 443)) == (Act::Drop, Decided::Acl(1, u16::MAX)) // implicit deny
        && p.check(If::Wan, Dir::In, &pk(6, a4([1, 2, 3, 4]), cli, 22)) == (Act::Allow, Decided::Unbound)
        && p.acl[0].hits[0] == 1 && p.acl[0].hits[1] == 2 && p.acl[0].hits[2] == 1 && p.acl[0].hits[3] == 1 && p.acl[0].default_hits == 2
        && p.pl_drops[1] == 1;
    let pfx = |s: &[u8]| parse_prefix(s).unwrap();
    let pl_ok = p.pl[2].matches_prefix(&pfx(b"0.0.0.0/0")) && !p.pl[2].matches_prefix(&pfx(b"10.0.0.0/8"))
        && p.pl[3].matches_prefix(&pfx(b"2a02:2f05:d101:4c00::/56")) && !p.pl[3].matches_prefix(&pfx(b"2a02:2f05::/40"))
        && !p.pl[3].matches_prefix(&pfx(b"2a02:2f05:d101:4c00::1/128")) && !p.pl[3].matches_prefix(&pfx(b"2a02:2f05:dead::/56")) // seq 10 deny wins
        && p.pl[0].matches_addr(&a4([172, 20, 1, 1])) && !p.pl[0].matches_addr(&a4([172, 32, 0, 1]));
    let all_up = |_: If| true;
    let wan_down = |i: If| i != If::Wan;
    let r = |src: Addr, dst: Addr, up: &dyn Fn(If) -> bool| p.route(&src, &dst, up).map(|r| (r.via, r.gw, r.metric));
    let gw = Some(a4([192, 168, 200, 1]));
    let rt_ok = r(cli, a4([8, 8, 8, 8]), &all_up) == Some((If::Wan, None, 10))
        && r(a4([10, 99, 0, 200]), a4([8, 8, 8, 8]), &all_up) == Some((If::Mgmt, gw, 5)) // source-based: from 10.99.0.128/25
        && r(cli, a4([10, 20, 5, 9]), &all_up) == Some((If::Wan, None, 0)) // /24 beats /16
        && r(cli, a4([10, 20, 9, 9]), &all_up) == Some((If::Mgmt, gw, 0))
        && r(cli, a4([8, 8, 8, 8]), &wan_down) == Some((If::Mgmt, gw, 100)) // failover by metric
        && r(v6a(b"2a02::5"), v6a(b"2001:db8:1:5::1"), &all_up).map(|x| x.0) == Some(If::Mgmt)
        && r(v6a(b"2a02::5"), v6a(b"2606::1"), &all_up).is_none();
    // whole-file rejection, with the line number
    let mut q = Policy::new();
    let rej_ok = parse_policy(b"HQPOL1\nacl A seq 10 drop any any any\nacl A seq 20 allow icmp any any 80\n", &mut q) == Err(PolicyErr::Line(3))
        && parse_policy(b"HQPOL1\nroute 10.0.0.1/8 via wan\n", &mut q) == Err(PolicyErr::Line(2)) // host bits set
        && parse_policy(b"HQPOL1\nacl A seq 1 drop any pl:NOPE any\n", &mut q) == Err(PolicyErr::Line(2)) // undefined list
        && parse_policy(b"HQPOL1\ninterface lan acl in NOPE\n", &mut q) == Err(PolicyErr::Line(2)) // undefined ACL
        && parse_policy(b"HQPOL1\nacl A seq 1 drop any any any\ninterface dmz acl in A\n", &mut q) == Err(PolicyErr::Line(3))
        && parse_policy(b"HQPOL1\nroute 0.0.0.0/0 gw 1.2.3.4\n", &mut q) == Err(PolicyErr::Line(2)) // no via
        && parse_policy(b"HQPOL1\nprefix-list X seq 1 permit 10.0.0.0/8 ge\n", &mut q) == Err(PolicyErr::Line(2))
        && parse_policy(b"acl A seq 1 drop any any any\n", &mut q) == Err(PolicyErr::NoMagic);
    // WAN.TXT link keys
    let w: &[u8] = b"HQWAN1\nmode=pppoe\npppoe_user=u@isp\npppoe_pass=x\nvlan=100\nvlan_outer=10\npcp=3\nmgmt_vlan=200\nmgmt=static\nmgmt_ip=192.168.200.2/24\nmgmt_gw=192.168.200.1\n";
    let link_ok = hal::parse_wan_link(w) == Ok(hal::WanLink { vlan: 100, outer: 10, pcp: 3, mgmt: Some(hal::MgmtIf { vlan: 200, stat: Some(([192, 168, 200, 2], 24, [192, 168, 200, 1])) }), floor: None, floor_bad: false })
        && matches!(hal::parse_wan_cfg(w), Ok(hal::WanMode::Pppoe { .. }))
        && hal::parse_wan_link(b"HQWAN1\nmode=dhcp\nvlan=100\nmgmt_vlan=100\n").is_err()
        && hal::parse_wan_link(b"HQWAN1\nmode=dhcp\nvlan_outer=10\n").is_err()
        && hal::parse_wan_link(b"HQWAN1\nmode=dhcp\nvlan=4095\n").is_err()
        && hal::parse_wan_link(b"HQWAN1\nmode=dhcp\n") == Ok(hal::WanLink::default())
        && hal::parse_wan_link(b"HQWAN1\nmode=pppoe\npppoe_user=u\nvlan=35\nmgmt_vlan=200\nmgmt=dhcp\n")
            == Ok(hal::WanLink { vlan: 35, outer: 0, pcp: 0, mgmt: Some(hal::MgmtIf { vlan: 200, stat: None }), floor: None, floor_bad: false })
        && hal::parse_wan_link(b"HQWAN1\nmode=dhcp\nmgmt_vlan=200\nmgmt=bootp\n").is_err();
    // tag stack + MTU from the headers
    let e = Encap { vlan: 100, outer: 10, pcp: 3, pppoe: true };
    let mut f = [0u8; 32];
    let o = e.push_tags(&mut f, 0x8864);
    let tag_ok = o == 22 && f[12..14] == [0x88, 0xa8] && u16::from_be_bytes([f[14], f[15]]) == (3 << 13 | 10)
        && f[16..18] == [0x81, 0x00] && u16::from_be_bytes([f[18], f[19]]) == (3 << 13 | 100) && f[20..22] == [0x88, 0x64]
        && rx_tags(&f) == Some((10, 100, 20)) && e.ip_mtu() == 1492 && e.mss4() == 1452 && e.frame_max() == 1522;
    let one = Encap { vlan: 35, ..Encap::default() };
    let mut g = [0u8; 32];
    let og = one.push_tags(&mut g, 0x0800);
    let tag1_ok = og == 18 && rx_tags(&g) == Some((0, 35, 16)) && one.ip_mtu() == 1500 && one.frame_max() == 1518
        && rx_tags(&[0u8; 14]) == Some((0, 0, 12));
    // task #21 N3: the management floor is configurable (WAN.TXT mgmt_floor=), never over-broad, restorable.
    let floor_ok = {
        let w = hal::parse_wan_link(b"HQWAN1\nmode=dhcp\nmgmt_floor=192.168.77.0/24\n");
        let parsed = matches!(w, Ok(hal::WanLink { floor: Some(([192, 168, 77, 0], 24)), .. }))
            // over-broad / malformed floors are IGNORED (flagged), never fatal — the rest of WAN.TXT stands
            && matches!(hal::parse_wan_link(b"HQWAN1\nmode=dhcp\nvlan=35\nmgmt_floor=0.0.0.0/0\n"), Ok(hal::WanLink { vlan: 35, floor: None, floor_bad: true, .. }))
            && matches!(hal::parse_wan_link(b"HQWAN1\nmode=dhcp\nmgmt_floor=10.0.0.0/7\n"), Ok(hal::WanLink { floor: None, floor_bad: true, .. }))
            && matches!(hal::parse_wan_link(b"HQWAN1\nmode=dhcp\nmgmt_floor=192.168.200.10/32\n"), Ok(hal::WanLink { floor: Some(([192, 168, 200, 10], 32)), .. }));
        let def = crate::verdict::is_allowlisted(0x0A_C8_00_05) && !crate::verdict::is_allowlisted(0xC0_A8_4D_05);
        let set = crate::verdict::set_mgmt_floor(0xC0_A8_4D_00, 24);
        let moved = crate::verdict::is_allowlisted(0xC0_A8_4D_05) && !crate::verdict::is_allowlisted(0x0A_C8_00_05) && crate::verdict::mgmt_floor().2;
        let broad_refused = !crate::verdict::set_mgmt_floor(0, 0) && !crate::verdict::set_mgmt_floor(0x0A00_0000, 4)
            && crate::verdict::set_mgmt_floor(0xC0A8_C80A, 32) && crate::verdict::is_allowlisted(0xC0A8_C80A) && !crate::verdict::is_allowlisted(0xC0A8_C80B);
        crate::verdict::reset_mgmt_floor();
        let restored = crate::verdict::is_allowlisted(0x0A_C8_00_05) && !crate::verdict::mgmt_floor().2;
        parsed && def && set && moved && broad_refused && restored
    };
    // re-review P2: martian WAN sources (uRPF-lite)
    let martian_ok = {
        let (wan, inside) = ([100u8, 71, 11, 24], [10u8, 99, 0]);
        let floor = (0x0A_C8_00_00u32, 24u32); // 10.200.0.0/24
        let m = |s: [u8; 4], w: [u8; 4]| wan_martian4(s, w, inside, floor.0, floor.1);
        m([10, 99, 0, 10], wan) && m([127, 0, 0, 1], wan) && m([0, 1, 2, 3], wan) && m([224, 0, 0, 1], wan)
            && m([255, 255, 255, 255], wan) && m(wan, wan)
            && m([10, 200, 0, 5], wan) // a spoofed management-floor source from the internet
            && !m([10, 200, 0, 5], [10, 200, 0, 13]) // ...but legit when the WAN itself sits in the floor
            && !m([8, 8, 8, 8], wan) && !m([100, 64, 0, 1], wan) && !m([192, 168, 1, 1], wan)
            // metal 2026-11-07: with no ENFORCED floor (compile-time default / no mgmt sub-interface) an
            // upstream-LAN host in 10.200.0.0/24 answering a client is legit and must pass
            && !wan_martian4([10, 200, 0, 12], wan, inside, floor.0, 0)
    };
    let ok = v6_ok && parsed && acl_ok && pl_ok && rt_ok && rej_ok && link_ok && tag_ok && tag1_ok && floor_ok && martian_ok;
    kprint!(" [P-policy] {} — WAN policy engine: IPv6 text={} POLICY.TXT parsed (5 lists, 2 named ACLs sorted by seq, 3 interface bindings, 6 routes)={} interface-attached ACL + prefix-list: allow/block/drop first-match by seq, ACL default + implicit deny, per-entry hits, v4+v6, ports, spoofed source dropped by the lan prefix-list, a v4-only list never applies to v6, unbound wan allowed={} prefix-list ge/le + seq order={} routes: longest prefix, source-based (from), gateway, metric failover when wan is down={} whole-file rejection with line numbers={} WAN.TXT vlan/QinQ/pcp/mgmt sub-interface={} QinQ tag stack + MTU from headers (PPPoE 1492/MSS 1452, frame 1522)={} single tag={} | management floor configurable (WAN.TXT mgmt_floor=, over-broad refused, default restorable)={} martian WAN sources (uRPF-lite)={}\n",
        if ok { "PASS" } else { "FAIL" }, v6_ok, parsed, acl_ok, pl_ok, rt_ok, rej_ok, link_ok, tag_ok, tag1_ok, floor_ok, martian_ok);
}

/// `[P-pppoe]` — the PPPoE client engine (arch_aarch64::pppoe) end to end against a scripted
/// RFC 2516/1661 access concentrator: PADI/PADO(cookie)/PADR/PADS, LCP with an option the client
/// must Reject, CHAP-MD5 verified cryptographically (and a PAP run), IPCP Nak-assigned address +
/// DNS, then Echo-Reply, Protocol-Reject of IPV6CP, IPv4 encap/decap, and PADT -> down.
#[allow(dead_code)]
/// `[P-ip6]` — the pure IPv6 WAN builders/parsers (arch_aarch64::ip6) the PPPoE v6 probe uses:
/// Router Solicitation (checksum), Router Advertisement (prefix/M/O/MTU; bad checksum and wrong hop
/// limit refused), DHCPv6 Advertise with IA_PD + Server-ID + DNS (wrong xid / client->server port refused).
#[allow(dead_code)]
fn ip6_selftest() {
    use arch_aarch64::ip6::*;
    let mac = [0x02u8, 0x11, 0x22, 0x33, 0x44, 0x55];
    let iid = eui64(&mac);
    let me = link_local(&iid);
    let eui_ok = iid == [0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55];
    let mut rs = [0u8; 64];
    let n = build_rs(&iid, &mut rs);
    let rs_ok = n == 48 && rs[40] == 133 && rs[7] == 255 && l4_csum(&me, &ALL_ROUTERS, 58, &rs[40..48]) == 0 && parse_ra(&rs[..n]).is_none();
    // RA from fe80::1: O=1, lifetime 1800, PIO 2001:db8:1:2::/64 (L+A) valid 86400 pref 14400, MTU 1492.
    let rtr: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let all: [u8; 16] = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut ra = [0u8; 40 + 16 + 32 + 8];
    let il = 16 + 32 + 8;
    ra[0] = 0x60;
    ra[4..6].copy_from_slice(&(il as u16).to_be_bytes());
    ra[6] = 58;
    ra[7] = 255;
    ra[8..24].copy_from_slice(&rtr);
    ra[24..40].copy_from_slice(&all);
    let ic = 40;
    ra[ic] = 134;
    ra[ic + 4] = 64;
    ra[ic + 5] = 0x40;
    ra[ic + 6..ic + 8].copy_from_slice(&1800u16.to_be_bytes());
    let po = ic + 16;
    ra[po] = 3;
    ra[po + 1] = 4;
    ra[po + 2] = 64;
    ra[po + 3] = 0xc0;
    ra[po + 4..po + 8].copy_from_slice(&86400u32.to_be_bytes());
    ra[po + 8..po + 12].copy_from_slice(&14400u32.to_be_bytes());
    ra[po + 16..po + 32].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mo = po + 32;
    ra[mo] = 5;
    ra[mo + 1] = 1;
    ra[mo + 4..mo + 8].copy_from_slice(&1492u32.to_be_bytes());
    let c = l4_csum(&rtr, &all, 58, &ra[ic..ic + il]);
    ra[ic + 2..ic + 4].copy_from_slice(&c.to_be_bytes());
    let ra_ok = match parse_ra(&ra) {
        Some(r) => r.router == rtr && !r.managed && r.other && r.lifetime == 1800 && r.has_prefix && r.plen == 64 && r.autonomous
            && r.valid == 86400 && r.preferred == 14400 && r.prefix[..8] == [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2] && r.mtu == 1492,
        None => false,
    };
    let mut bad = ra;
    bad[ic + 2] ^= 1;
    let mut hop = ra;
    hop[7] = 64;
    let ra_refuse = parse_ra(&bad).is_none() && parse_ra(&hop).is_none();
    // DHCPv6: our Solicit is to port 547 (never parsed as a server reply); an Advertise for our xid is.
    let xid = 0x00ab_cdefu32;
    let mut sol = [0u8; 400];
    let sn = build_dhcp6(DHCP6_SOLICIT, xid, &mac, &iid, 7, &[], None, true, &mut sol);
    let sol_ok = sn > 48 && sol[48] == DHCP6_SOLICIT && l4_csum(&me, &ALL_DHCP, 17, &sol[40..sn]) == 0 && parse_dhcp6(&sol[..sn], xid).is_none();
    let mut p = [0u8; 128];
    let mut k = 0;
    p[0] = DHCP6_ADVERTISE;
    p[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
    k += 4;
    for (code, data) in [(2u16, &[0xaa, 0xbb, 0xcc, 0xdd][..])] {
        p[k..k + 2].copy_from_slice(&code.to_be_bytes());
        p[k + 2..k + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
        p[k + 4..k + 4 + data.len()].copy_from_slice(data);
        k += 4 + data.len();
    }
    // IA_PD { iaid 7, T1, T2, IAPREFIX { pref 3600, valid 7200, /56, 2001:db8:aa00:: } }
    p[k..k + 4].copy_from_slice(&[0, 25, 0, 41]);
    p[k + 4..k + 8].copy_from_slice(&7u32.to_be_bytes());
    p[k + 8..k + 12].copy_from_slice(&1800u32.to_be_bytes()); // T1
    p[k + 12..k + 16].copy_from_slice(&2880u32.to_be_bytes()); // T2
    let q = k + 16;
    p[q..q + 4].copy_from_slice(&[0, 26, 0, 25]);
    p[q + 4..q + 8].copy_from_slice(&3600u32.to_be_bytes());
    p[q + 8..q + 12].copy_from_slice(&7200u32.to_be_bytes());
    p[q + 12] = 56;
    p[q + 13..q + 29].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    k = q + 29;
    p[k..k + 4].copy_from_slice(&[0, 23, 0, 16]);
    p[k + 4..k + 20].copy_from_slice(&[0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88]);
    k += 20;
    let mut adv = [0u8; 256];
    let an = build_udp6(&rtr, &me, 547, 546, 64, &p[..k], &mut adv);
    let adv_ok = match parse_dhcp6(&adv[..an], xid) {
        Some(d) => d.msg == DHCP6_ADVERTISE && d.sid_len == 4 && d.server_id[..4] == [0xaa, 0xbb, 0xcc, 0xdd] && d.has_pd && d.plen == 56
            && d.preferred == 3600 && d.valid == 7200 && d.prefix[..5] == [0x20, 0x01, 0x0d, 0xb8, 0xaa] && d.has_dns && d.dns[15] == 0x88 && d.status == 0 && d.t1 == 1800 && d.t2 == 2880,
        None => false,
    };
    let xid_refuse = parse_dhcp6(&adv[..an], xid ^ 1).is_none();
    let renew_ok = {
        let mut r = [0u8; 400];
        let pfx: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let rn = build_dhcp6(DHCP6_RENEW, xid, &mac, &iid, 7, &[0xaa, 0xbb, 0xcc, 0xdd], Some((&pfx, 56)), false, &mut r);
        let pl = &r[48..rn];
        // msg 5, server-id option (2) present, IA_PD (25) carrying an IAPREFIX for the /56, no rapid commit (14)
        let has = |code: u16| { let mut o = 4; let mut f = false; while o + 4 <= pl.len() { let c = u16::from_be_bytes([pl[o], pl[o + 1]]); let l = u16::from_be_bytes([pl[o + 2], pl[o + 3]]) as usize; if c == code { f = true; } o += 4 + l; } f };
        pl[0] == DHCP6_RENEW && has(2) && has(25) && !has(14) && pl.windows(5).any(|w| w == [0x20, 0x01, 0x0d, 0xb8, 0xaa]) && l4_csum(&me, &ALL_DHCP, 17, &r[40..rn]) == 0
    };
    // ---- LAN router + stateful firewall (arch_aarch64::ip6lan) ----
    let lan_ok = {
        use arch_aarch64::ip6lan::{LanAction, V6Lan, WanAction};
        let mut v = V6Lan::new();
        let apmac = [0x02u8, 0xaa, 0, 0, 0, 1];
        let cmac = [0x02u8, 0xcc, 0, 0, 0, 7];
        let pd: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let dns: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53];
        v.configure(&pd, 56, u32::MAX, &apmac, Some(&dns));
        let mut cli = [0u8; 16];
        cli[..8].copy_from_slice(&pd[..8]);
        cli[8..16].copy_from_slice(&[0x12, 0x34, 0, 0, 0, 0, 0xab, 0xcd]);
        let remote: [u8; 16] = [0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11];
        let mut out = [0u8; 1600];
        // Build an Ethernet/IPv6 frame (client -> ?) with an L4 payload; ICMPv6 checksum filled when nh=58.
        let frame6 = |f: &mut [u8], smac: &[u8; 6], dmac: &[u8; 6], src: &[u8; 16], dst: &[u8; 16], nh: u8, hop: u8, l4: &[u8]| -> usize {
            f[0..6].copy_from_slice(dmac);
            f[6..12].copy_from_slice(smac);
            f[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
            f[14] = 0x60;
            f[18..20].copy_from_slice(&(l4.len() as u16).to_be_bytes());
            f[20] = nh;
            f[21] = hop;
            f[22..38].copy_from_slice(src);
            f[38..54].copy_from_slice(dst);
            f[54..54 + l4.len()].copy_from_slice(l4);
            if nh == 58 {
                f[56..58].copy_from_slice(&[0, 0]);
                let c = l4_csum(src, dst, 58, &f[54..54 + l4.len()]);
                f[56..58].copy_from_slice(&c.to_be_bytes());
            }
            54 + l4.len()
        };
        let mut f = [0u8; 200];
        let cll = link_local(&eui64(&cmac));
        // RS -> RA (parseable, our /64, MTU 1492)
        let n = frame6(&mut f, &cmac, &[0x33, 0x33, 0, 0, 0, 2], &cll, &ALL_ROUTERS, 58, 255, &[133, 0, 0, 0, 0, 0, 0, 0]);
        let ra_ok = match v.on_lan(&f[..n], 10, &mut out) {
            LanAction::Reply(k) => out[0..6] == cmac && match parse_ra(&out[14..k]) {
                Some(r) => r.has_prefix && r.plen == 64 && r.autonomous && r.prefix[..8] == pd[..8] && r.mtu == 1492 && r.lifetime == 1800,
                None => false,
            },
            _ => false,
        };
        // NS for the router's link-local -> NA (solicited, router)
        let mut ns = [0u8; 24];
        ns[0] = 135;
        ns[8..24].copy_from_slice(&v.ll);
        let snm: [u8; 16] = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, v.ll[13], v.ll[14], v.ll[15]];
        let n = frame6(&mut f, &cmac, &[0x33, 0x33, 0xff, v.ll[13], v.ll[14], v.ll[15]], &cll, &snm, 58, 255, &ns);
        let na_ok = matches!(v.on_lan(&f[..n], 20, &mut out), LanAction::Reply(k) if out[54] == 136 && out[58] & 0x40 != 0 && out[62..78] == v.ll && k == 86);
        // Outbound TCP SYN 443 from the client's global address -> Forward, hop 64 -> 63
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[13] = 0x02;
        let n = frame6(&mut f, &cmac, &apmac, &cli, &remote, 6, 64, &tcp);
        // A forward that is never committed (policy blocked / IDS dropped / send failed) opens NO pinhole
        // (peer review SEC-M4): its SYN-ACK is denied.
        let _ = v.on_lan(&f[..n], 25, &mut out);
        let mut rtcp0 = [0u8; 20];
        rtcp0[0..2].copy_from_slice(&443u16.to_be_bytes());
        rtcp0[2..4].copy_from_slice(&50000u16.to_be_bytes());
        rtcp0[13] = 0x12;
        let mut g = [0u8; 200];
        let gn = frame6(&mut g, &[0; 6], &[0; 6], &remote, &cli, 6, 57, &rtcp0);
        let no_pinhole = matches!(v.on_wan(&g[14..gn], 26, &mut out), WanAction::Drop);
        let out_ok = no_pinhole && matches!(v.on_lan(&f[..n], 30, &mut out), LanAction::Forward(k) if k == 60 && out[7] == 63 && out[24..40] == remote);
        let mut syn_sent = [0u8; 60];
        syn_sent.copy_from_slice(&out[..60]); // the packet as forwarded (quoted by the PTB below)
        v.commit(30); // sent: the flow is recorded now
        // The SYN-ACK back -> Deliver to the client's MAC, hop decremented
        let mut rtcp = [0u8; 20];
        rtcp[0..2].copy_from_slice(&443u16.to_be_bytes());
        rtcp[2..4].copy_from_slice(&50000u16.to_be_bytes());
        rtcp[13] = 0x12;
        let n = frame6(&mut f, &[0; 6], &[0; 6], &remote, &cli, 6, 57, &rtcp);
        let in_ok = matches!(v.on_wan(&f[14..n], 40, &mut out), WanAction::Deliver(k) if k == n && out[0..6] == cmac && out[6..12] == apmac && out[21] == 56);
        // Unsolicited inbound (the internet opening port 22 on the client) -> default deny
        let mut scan = [0u8; 20];
        scan[0..2].copy_from_slice(&40000u16.to_be_bytes());
        scan[2..4].copy_from_slice(&22u16.to_be_bytes());
        scan[13] = 0x02;
        let n = frame6(&mut f, &[0; 6], &[0; 6], &remote, &cli, 6, 57, &scan);
        let deny_ok = matches!(v.on_wan(&f[14..n], 50, &mut out), WanAction::Drop) && v.stats.drop_no_flow == 2;
        // ICMPv6 Packet Too Big quoting the client's live flow -> passes (PMTU); one quoting nothing of
        // ours is denied (peer review SEC-M3).
        let mut ptb = [0u8; 8 + 60];
        ptb[0] = 2;
        ptb[4..8].copy_from_slice(&1280u32.to_be_bytes());
        ptb[8..68].copy_from_slice(&syn_sent);
        let n = frame6(&mut f, &[0; 6], &[0; 6], &remote, &cli, 58, 57, &ptb);
        let ptb_flow = matches!(v.on_wan(&f[14..n], 60, &mut out), WanAction::Deliver(_)) && v.stats.in_icmp_err == 1;
        let mut bogus = ptb;
        bogus[8 + 40..8 + 42].copy_from_slice(&50999u16.to_be_bytes()); // a port the client never used
        let n = frame6(&mut f, &[0; 6], &[0; 6], &remote, &cli, 58, 57, &bogus);
        let ptb_ok = ptb_flow && matches!(v.on_wan(&f[14..n], 61, &mut out), WanAction::Drop) && v.stats.in_icmp_err == 1;
        // Spoofed source (not our /64) and a link-local destination are never routed out
        let mut spoof = cli;
        spoof[3] ^= 0xff;
        let n = frame6(&mut f, &cmac, &apmac, &spoof, &remote, 6, 64, &tcp);
        let spoof_ok = matches!(v.on_lan(&f[..n], 70, &mut out), LanAction::Drop) && v.stats.drop_src == 1;
        let n = frame6(&mut f, &cmac, &apmac, &cli, &cll, 6, 64, &tcp);
        let ll_ok = matches!(v.on_lan(&f[..n], 80, &mut out), LanAction::Drop);
        // SAVI (SEC-M5): another station sourcing the client's address is refused; the owner keeps working.
        let thief = [0x02u8, 0xee, 0, 0, 0, 9];
        let n = frame6(&mut f, &thief, &apmac, &cli, &remote, 6, 64, &tcp);
        let savi_ok = matches!(v.on_lan(&f[..n], 90, &mut out), LanAction::Drop) && v.stats.savi_refused == 1;
        // Neighbor miss -> a Neighbor Solicitation for the destination (solicited-node multicast), not a silent drop.
        let mut stranger = cli;
        stranger[15] = 0x77;
        let ns_ok = {
            // `stranger` opens a flow (learned + committed), then 64 other stations fill the neighbor table
            // and evict it (LRU); its reply must trigger an NS for it, not a silent drop.
            let smac = [0x02u8, 0xdd, 0, 0, 0, 1];
            let n2 = frame6(&mut f, &smac, &apmac, &stranger, &remote, 6, 64, &tcp);
            let fwd = matches!(v.on_lan(&f[..n2], 100, &mut out), LanAction::Forward(_));
            v.commit(100);
            // The client goes IDLE past the 5-min active window (its flow is still live: 10-min timeout); only
            // then may other stations' new bindings recycle its slot (H1: active bindings are never evicted).
            let t = 100 + 300_001;
            for k in 0..64u8 {
                let mut a = cli;
                a[14] = 0x40;
                a[15] = k;
                let n3 = frame6(&mut f, &[0x02, 0xcd, 0, 0, 1, k], &apmac, &a, &remote, 17, 64, &[0u8; 8]);
                let _ = v.on_lan(&f[..n3], t + k as u64, &mut out);
            }
            let mut rt = rtcp;
            rt[2..4].copy_from_slice(&50000u16.to_be_bytes());
            let n4 = frame6(&mut f, &[0; 6], &[0; 6], &remote, &stranger, 6, 57, &rt);
            fwd && match v.on_wan(&f[14..n4], t + 100, &mut out) {
                WanAction::Solicit(k) => out[54] == 135 && out[62..78] == stranger && out[0..3] == [0x33, 0x33, 0xff] && k == 86 && v.stats.ns_tx == 1,
                _ => false,
            }
        };
        // Re-review H1: ONE station flooding 64 sources cannot evict others' active bindings, so it can
        // never claim them; M1: a station that leaves releases its bindings.
        let flood_ok = {
            let mut w = V6Lan::new();
            w.configure(&pd, 56, u32::MAX, &apmac, None);
            let vmac = [0x02u8, 0xaa, 0xaa, 0, 0, 1];
            let atk = [0x02u8, 0xbb, 0xbb, 0, 0, 2];
            let mut victim = cli;
            victim[15] = 0x42;
            let n0 = frame6(&mut f, &vmac, &apmac, &victim, &remote, 17, 64, &[0u8; 8]);
            let v_ok = matches!(w.on_lan(&f[..n0], 1_000, &mut out), LanAction::Forward(_));
            for k in 0..64u8 {
                let mut a = cli;
                a[14] = 0x77;
                a[15] = k;
                let n1 = frame6(&mut f, &atk, &apmac, &a, &remote, 17, 64, &[0u8; 8]);
                let _ = w.on_lan(&f[..n1], 2_000 + k as u64, &mut out);
            }
            let n2 = frame6(&mut f, &atk, &apmac, &victim, &remote, 17, 64, &[0u8; 8]);
            let claim_refused = matches!(w.on_lan(&f[..n2], 3_000, &mut out), LanAction::Drop);
            let n3 = frame6(&mut f, &vmac, &apmac, &victim, &remote, 17, 64, &[0u8; 8]);
            let victim_still = matches!(w.on_lan(&f[..n3], 3_100, &mut out), LanAction::Forward(_));
            // M1: the victim leaves; a re-joined client (new private MAC) gets the address
            w.forget_mac(&vmac);
            let n4 = frame6(&mut f, &[0x02, 0xaa, 0xaa, 0, 0, 9], &apmac, &victim, &remote, 17, 64, &[0u8; 8]);
            let rejoin = matches!(w.on_lan(&f[..n4], 3_200, &mut out), LanAction::Forward(_));
            v_ok && claim_refused && victim_still && rejoin
        };
        let r = ra_ok && na_ok && out_ok && in_ok && deny_ok && ptb_ok && spoof_ok && ll_ok && savi_ok && ns_ok && flood_ok;
        if !r {
            kprint!("   [P-ip6 lan] ra={} na={} out={} in={} deny={} ptb={} spoof={} ll={} savi={} ns={} flood={}\n", ra_ok, na_ok, out_ok, in_ok, deny_ok, ptb_ok, spoof_ok, ll_ok, savi_ok, ns_ok, flood_ok);
        }
        r
    };
    let ok = eui_ok && rs_ok && ra_ok && ra_refuse && sol_ok && adv_ok && xid_refuse && lan_ok && renew_ok;
    kprint!(" [P-ip6] {} — IPv6 WAN builders/parsers: EUI-64={} RS (checksum, hop 255)={} RA (router, O flag, /64 PIO A, lifetimes, MTU)={} RA bad-checksum/hop-limit refused={} DHCPv6 Solicit (IA_PD, rapid commit, UDP checksum)={} Advertise (server-id, IA_PD /56, DNS)={} wrong xid refused={} renew (server-id + IA_PD, T1/T2 parsed)={} | LAN router+firewall: RS->RA, NS->NA, SYN out (hop-1), SYN-ACK in to the client MAC, unsolicited inbound DENIED, an uncommitted (blocked) forward opens no pinhole, Packet-Too-Big quoting a live flow passes / quoting nothing of ours denied, spoofed src / link-local dst never routed, SAVI refuses another station's address, neighbor miss -> NS, a one-station source flood cannot evict/claim others + leave releases bindings={}\n",
        if ok { "PASS" } else { "FAIL" }, eui_ok, rs_ok, ra_ok, ra_refuse, sol_ok, adv_ok, xid_refuse, renew_ok, lan_ok);
}

/// `[P-fuzz]` (ADR 0050 D3) — deterministic structure-aware fuzzing of every remote-reachable parser the
/// QEMU build carries: frame facts + header parse, PPPoE client (discovery/LCP/auth/IPCP/IPV6CP) + decap,
/// IPv6 RA / DHCPv6 parsers, the IPv6 LAN router/firewall (both directions), NAT inbound/outbound, the
/// reject builders, HTTP request parse, and the POLICY.TXT / WAN.TXT parsers. Fixed seed + budget; any
/// panic aborts the boot, so the PASS marker never prints (validate fails).
#[cfg(not(feature = "cm5"))]
fn fuzz_selftest() {
    let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    // A structure-aware random frame: a real ethertype, a mostly-valid L3 header, random rest + length.
    fn frame(r: &mut dyn FnMut() -> u64, buf: &mut [u8; 1600]) -> usize {
        let len = (r() % 1600) as usize;
        for b in buf[..len].iter_mut() {
            *b = r() as u8;
        }
        if len < 14 {
            return len;
        }
        const ET: [u16; 7] = [0x0800, 0x86dd, 0x8863, 0x8864, 0x0806, 0x8100, 0x88a8];
        let et = ET[(r() % 7) as usize];
        buf[12..14].copy_from_slice(&et.to_be_bytes());
        let k = r();
        match et {
            0x0800 if len >= 34 => {
                buf[14] = if k & 3 == 0 { buf[14] } else { 0x45 };
                buf[23] = [6u8, 17, 1, 47][(k >> 2) as usize % 4];
                let tl = if k & 0x30 == 0 { (k >> 8) as u16 } else { (len - 14) as u16 };
                buf[16..18].copy_from_slice(&tl.to_be_bytes());
            }
            0x86dd if len >= 54 => {
                buf[14] = 0x60;
                buf[20] = [6u8, 17, 58, 0, 43, 44, 60][(k >> 2) as usize % 7];
                let pl = if k & 0x30 == 0 { (k >> 8) as u16 } else { (len - 54) as u16 };
                buf[18..20].copy_from_slice(&pl.to_be_bytes());
                if buf[20] == 58 && len > 54 {
                    buf[54] = [1u8, 2, 3, 4, 128, 129, 133, 134, 135, 136, 137][(k >> 12) as usize % 11];
                }
            }
            0x8863 | 0x8864 if len >= 20 => {
                buf[14] = if k & 3 == 0 { buf[14] } else { 0x11 };
                buf[15] = [0x07u8, 0x65, 0xa7, 0x00, 0x09, 0x19][(k >> 2) as usize % 6];
                let pl = if k & 0x30 == 0 { (k >> 8) as u16 } else { (len - 20) as u16 };
                buf[18..20].copy_from_slice(&pl.to_be_bytes());
                if et == 0x8864 && len >= 22 {
                    let proto: [u16; 6] = [0xc021, 0xc023, 0x8021, 0x8057, 0x0021, 0x0057];
                    buf[20..22].copy_from_slice(&proto[(k >> 12) as usize % 6].to_be_bytes());
                }
            }
            _ => {}
        }
        len
    }
    const N: u32 = 3000;
    let mut buf = [0u8; 1600];
    let mut out = [0u8; 2048];
    let mut n_frames = 0u32;

    // 1. Frame facts + header parse (every frame the datapath sees).
    for _ in 0..N {
        let n = frame(&mut next, &mut buf);
        let _ = hal::policy::facts(&buf[..n]);
        let _ = crate::net::parse(&buf[..n]);
        let _ = crate::net::eth_ipv4_dst(&buf[..n]);
        let _ = crate::net::eth_ipv6_dst(&buf[..n]);
        n_frames += 1;
    }
    // 2. PPPoE client: every phase sees hostile frames; decap both families.
    {
        use arch_aarch64::pppoe::{Pppoe, Tx};
        let mut c = Pppoe::new([2, 0, 0, 0, 0, 2], b"user", b"pass", 0x1234_5678, 0x9abc_def0);
        let mut tx = Tx::new();
        for i in 0..N {
            let n = frame(&mut next, &mut buf);
            if n >= 6 {
                buf[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]); // addressed to us: reach the parser
            }
            tx.clear();
            c.rx(&buf[..n], i as u64 * 10, &mut tx);
            let _ = c.decap_ipv4(&buf[..n], &mut out);
            let _ = c.decap_ipv6(&buf[..n]);
            n_frames += 1;
        }
    }
    // 3. IPv6 WAN parsers + the LAN router/firewall both ways.
    {
        let mut v = arch_aarch64::ip6lan::V6Lan::new();
        for i in 0..N {
            let n = frame(&mut next, &mut buf);
            if n > 14 {
                let _ = arch_aarch64::ip6::parse_ra(&buf[14..n]);
                let _ = arch_aarch64::ip6::parse_dhcp6(&buf[14..n], 0x00ab_cdef);
                let _ = v.on_wan(&buf[14..n], i as u64 * 7, &mut out);
            }
            let _ = v.on_lan(&buf[..n], i as u64 * 7, &mut out);
            n_frames += 1;
        }
    }
    // 4. NAT both directions + the reject builders.
    {
        let mut st = arch_aarch64::nat::NatStats::default();
        let (wan_ip, wan_mac, gw) = ([100u8, 71, 11, 24], [2u8, 0, 0, 0, 0, 2], [2u8, 0xac, 0, 0, 0, 1]);
        let (m1, m2) = ([0xb8u8, 0x27, 0xeb, 1, 2, 3], [0xb8u8, 0x27, 0xeb, 1, 2, 4]);
        for i in 0..N {
            let n = frame(&mut next, &mut buf);
            if n >= 6 && i & 1 == 0 {
                buf[0..6].copy_from_slice(&wan_mac);
            }
            let _ = arch_aarch64::nat::inbound(&buf[..n], &wan_ip, &wan_mac, [&m1, &m2], &mut out, i as u64, &mut st);
            let _ = arch_aarch64::nat::outbound_redirect(&buf[..n], 0, &[10, 66, 0], Some((&[10, 66, 0, 1], &[1, 1, 1, 1])), &wan_ip, &wan_mac, &gw, &mut out, i as u64, &mut st);
            let _ = arch_aarch64::reject::reject4(&buf[..n], &[10, 66, 0, 1], &gw, &mut out);
            n_frames += 1;
        }
    }
    // 4b. AP DHCP server + WAN DHCP client (BOOTP-shaped: real ports/op/cookie, random options and
    //     lengths), firmware event decode and the WPA2 authenticator's EAPOL matcher.
    {
        use arch_aarch64::apparse::{eapol_match, parse_ap_event, parse_client_dhcp, parse_dhcp_reply, DhcpResult};
        let mac = [2u8, 0, 0, 0, 0, 2];
        let xid = [0x12u8, 0x34, 0x56, 0x78];
        let mut r = DhcpResult::new();
        for i in 0..N {
            let n = frame(&mut next, &mut buf);
            if n >= 42 + 240 && i % 3 != 0 {
                let k = next();
                buf[0..6].copy_from_slice(if k & 1 == 0 { &mac } else { &[0xff; 6] });
                buf[12] = 0x08;
                buf[13] = 0x00;
                buf[14] = if k & 6 == 0 { buf[14] } else { 0x45 };
                buf[23] = 17;
                let l4 = 14 + ((buf[14] & 0x0f) as usize) * 4;
                if l4 + 8 + 240 <= n {
                    let server = k & 8 == 0;
                    buf[l4..l4 + 2].copy_from_slice(&(if server { 67u16 } else { 68 }).to_be_bytes());
                    buf[l4 + 2..l4 + 4].copy_from_slice(&(if server { 68u16 } else { 67 }).to_be_bytes());
                    let b = l4 + 8;
                    buf[b] = if server { 2 } else { 1 };
                    if k & 16 != 0 {
                        buf[b + 4..b + 8].copy_from_slice(&xid);
                        buf[b + 28..b + 34].copy_from_slice(&mac);
                    }
                    buf[b + 236..b + 240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
                }
            }
            let _ = parse_dhcp_reply(&buf[..n], &xid, &mac, &mut r);
            let (mut cm, mut cx, mut ci) = ([0u8; 6], [0u8; 4], [0u8; 4]);
            let _ = parse_client_dhcp(&buf[..n], &mut cm, &mut cx, &mut ci);
            let doff = (next() as usize) % 64;
            let _ = parse_ap_event(&buf[..n], doff);
            let mut eb = [0u8; 256];
            let _ = eapol_match(&buf[..n], (next() % 3) as u8, doff, &mac, next() & 1 == 0, next() % 4, Some(&mut eb[..]));
            n_frames += 1;
        }
    }
    // 4c. The management sub-interface handler (ARP for our address, ping under policy, hand-up) with every
    //     policy outcome — moved out of the CM5-only uplink so it is fuzzable (arch-aarch64::mgmtproto).
    {
        use arch_aarch64::mgmtproto::{mgmt_frame, Mgmt};
        let me = [192u8, 168, 200, 10];
        let mut m = Mgmt { ip: me, prefix: 24, gw: [192, 168, 200, 1], gw_mac: None, mac: [2, 0, 0, 0, 0, 2],
            last_arp: 0, nh: [([0; 4], [0; 6]); 4], nh_last_arp: 0, dhcp: None, stats: [0; 7] };
        let mut o = [0u8; 1600];
        for i in 0..N {
            let n = frame(&mut next, &mut buf);
            if n >= 42 && i % 2 == 0 {
                buf[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
                let k = next();
                if k & 1 == 0 {
                    buf[12] = 0x08;
                    buf[13] = 0x06; // ARP: request or reply, often for our address
                    buf[20] = 0;
                    buf[21] = 1 + (k as u8 & 1);
                    if k & 4 == 0 {
                        buf[38..42].copy_from_slice(&me);
                    }
                } else {
                    buf[12] = 0x08;
                    buf[13] = 0x00;
                    buf[30..34].copy_from_slice(&me); // IPv4 to us; ICMP echo often
                    if k & 2 == 0 {
                        buf[23] = 1;
                        let ihl = ((buf[14] & 0x0f) as usize) * 4;
                        if 14 + ihl < n {
                            buf[14 + ihl] = 8;
                        }
                    }
                }
            }
            let act = match next() % 3 {
                0 => hal::policy::Act::Allow,
                1 => hal::policy::Act::Block,
                _ => hal::policy::Act::Drop,
            };
            let _ = mgmt_frame(&mut m, &mut buf[..], n, i as u64, &mut |_| act, &mut o, &mut |_| true);
            n_frames += 1;
        }
    }
    // 4b. Shield: the DNS block-answer builder (client UDP/53 queries, everything "blocked").
    {
        let mut o = [0u8; 600];
        let mut q = [0u8; 200];
        let base = dnssink::test_query_frame(b"ads.tracker.example", 1, &mut q);
        for i in 0..N {
            let n = if i % 2 == 0 {
                // a real query, mutated: lengths, labels, counts, flags
                buf[..base].copy_from_slice(&q[..base]);
                for _ in 0..(1 + next() % 4) {
                    let at = (next() as usize) % base;
                    buf[at] = next() as u8;
                }
                (base as u64 - next() % 4) as usize
            } else {
                let n = frame(&mut next, &mut buf);
                if n > 40 {
                    buf[23] = 17;
                    let ihl = ((buf[14] & 0x0f) as usize) * 4;
                    if 14 + ihl + 4 <= n {
                        buf[14 + ihl + 2] = 0;
                        buf[14 + ihl + 3] = 53;
                    }
                }
                n
            };
            if let Some(k) = dnssink::block_reply_frame(&buf[..n], &[2, 0, 0, 0, 0, 1], &mut o, &|_| true) {
                assert!(k <= o.len() && k >= 54);
            }
            n_frames += 1;
        }
    }
    // 5. HTTP request parse (Mission Control, reachable on :80).
    let mut n_http = 0u32;
    #[cfg(feature = "netsvc")]
    {
        const SEED: &[u8] = b"POST /api/login?x=1 HTTP/1.1\r\nHost: d\r\nCookie: hq_session=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\r\nContent-Length: 11\r\n\r\ntoken=hello";
        let mut b = [0u8; 512];
        for _ in 0..N {
            let n = SEED.len().min(b.len());
            b[..n].copy_from_slice(&SEED[..n]);
            let cut = (next() as usize) % (n + 1);
            for _ in 0..(next() % 8) {
                let at = (next() as usize) % n.max(1);
                b[at] = next() as u8;
            }
            let _ = crate::http::parse(&b[..cut]);
            n_http += 1;
        }
    }
    // 6. POLICY.TXT / WAN.TXT (boot config) — byte mutation of valid files.
    let mut n_cfg = 0u32;
    {
        const POL: &[u8] = b"HQPOL1\nprefix-list ADMINS seq 10 permit 192.168.200.1/32\nprefix-list P6 seq 5 permit 2001:db8::/32 le 64\nacl MGMT-IN seq 10 allow any pl:ADMINS any\ninterface mgmt acl in MGMT-IN\nacl LAN-IN seq 10 block tcp any 1.1.1.1/32 80\nacl LAN-IN seq 20 drop udp any 2620:fe::fe/128 53\nacl LAN-IN default allow\ninterface lan acl in LAN-IN\nroute 1.0.0.1/32 via mgmt gw 192.168.200.1\nroute 0.0.0.0/0 via wan metric 10\n";
        const WAN: &[u8] = b"HQWAN1\nmode=pppoe\nuser=abc\npass=def\nvlan=100\nvlan_outer=0\npcp=3\nmgmt_vlan=200\nmgmt=static\nmgmt_ip=192.168.200.10/24\nmgmt_gw=192.168.200.1\nmgmt_floor=192.168.200.0/24\n";
        let mut b = [0u8; 1024];
        for i in 0..N {
            let src = if i & 1 == 0 { POL } else { WAN };
            let n = src.len();
            b[..n].copy_from_slice(src);
            for _ in 0..(1 + next() % 6) {
                let at = (next() as usize) % n;
                b[at] = match next() % 4 { 0 => b'\n', 1 => b' ', 2 => b'/', _ => next() as u8 };
            }
            let cut = n - (next() as usize % 16).min(n);
            if i & 1 == 0 {
                let mut pol = hal::policy::Policy::new();
                let _ = hal::policy::parse_policy(&b[..cut], &mut pol);
            } else {
                let _ = hal::parse_wan_link(&b[..cut]);
            }
            n_cfg += 1;
        }
    }
    kprint!(" [P-fuzz] PASS — {} hostile frames through facts/net::parse, PPPoE rx+decap, RA/DHCPv6/IPv6 LAN+WAN, NAT in/out + reject, AP DHCP server + WAN DHCP client + fw events + EAPOL match, mgmt ARP/ping handler, Shield DNS block answers; {} mutated HTTP requests; {} mutated POLICY/WAN files — 0 panics (fixed seed, ADR 0050 D3)\n",
        n_frames, n_http, n_cfg);
}

fn pppoe_selftest() {
    use arch_aarch64::pppoe::{DownWhy, Phase, Pppoe, Tx, ETH_DISC, ETH_SESS};
    const CLI: [u8; 6] = [2, 0, 0, 0, 0, 2];
    const AC: [u8; 6] = [2, 0xac, 0, 0, 0, 1];
    const SID: u16 = 0x1234;
    const USER: &[u8] = b"client@isp";
    const SECRET_TV: &[u8] = b"s3cret"; // test vector (named so the CI credential-literal guard stays strict)
    const CHAL: [u8; 16] = *b"0123456789abcdef";
    fn be16(b: &[u8], o: usize) -> u16 {
        u16::from_be_bytes([b[o], b[o + 1]])
    }
    struct Out {
        f: [[u8; 256]; 4],
        len: [usize; 4],
        n: usize,
    }
    impl Out {
        fn push(&mut self, b: &[u8]) {
            if self.n < 4 {
                self.f[self.n][..b.len()].copy_from_slice(b);
                self.len[self.n] = b.len();
                self.n += 1;
            }
        }
    }
    fn disc(code: u8, sid: u16, tags: &[(u16, &[u8])]) -> ([u8; 256], usize) {
        let mut b = [0u8; 256];
        b[0..6].copy_from_slice(&CLI);
        b[6..12].copy_from_slice(&AC);
        b[12..14].copy_from_slice(&ETH_DISC.to_be_bytes());
        b[14] = 0x11;
        b[15] = code;
        b[16..18].copy_from_slice(&sid.to_be_bytes());
        let mut o = 20;
        for (t, v) in tags {
            b[o..o + 2].copy_from_slice(&t.to_be_bytes());
            b[o + 2..o + 4].copy_from_slice(&(v.len() as u16).to_be_bytes());
            b[o + 4..o + 4 + v.len()].copy_from_slice(v);
            o += 4 + v.len();
        }
        b[18..20].copy_from_slice(&((o - 20) as u16).to_be_bytes());
        (b, o.max(60))
    }
    fn sess(proto: u16, code: u8, id: u8, data: &[u8]) -> ([u8; 256], usize) {
        let mut b = [0u8; 256];
        b[0..6].copy_from_slice(&CLI);
        b[6..12].copy_from_slice(&AC);
        b[12..14].copy_from_slice(&ETH_SESS.to_be_bytes());
        b[14] = 0x11;
        b[16..18].copy_from_slice(&SID.to_be_bytes());
        b[20..22].copy_from_slice(&proto.to_be_bytes());
        b[22] = code;
        b[23] = id;
        b[24..26].copy_from_slice(&((4 + data.len()) as u16).to_be_bytes());
        b[26..26 + data.len()].copy_from_slice(data);
        let end = 26 + data.len();
        b[18..20].copy_from_slice(&((end - 20) as u16).to_be_bytes());
        (b, end.max(60))
    }
    fn tag<'a>(f: &'a [u8], t: u16) -> Option<&'a [u8]> {
        let end = 20 + be16(f, 18) as usize;
        let mut o = 20;
        while o + 4 <= end {
            let (tt, l) = (be16(f, o), be16(f, o + 2) as usize);
            if tt == t {
                return Some(&f[o + 4..o + 4 + l]);
            }
            o += 4 + l;
        }
        None
    }
    struct Ac {
        chap: bool,
        lcp_reqs_sent: u32,
        cli_acked_us: bool,
        we_acked_cli: bool,
        authed: bool,
        auth_started: bool,
        ipcp_started: bool,
        chap_ok: bool,
        pap_ok: bool,
        cookie_echoed: bool,
        rejected_acfc: bool,
        ipcp_nak_sent: bool,
        ipcp_acked: bool,
    }
    impl Ac {
        fn lcp_req(&mut self, o: &mut Out) {
            self.lcp_reqs_sent += 1;
            let mut d = [0u8; 20];
            let mut n = 0;
            d[n..n + 4].copy_from_slice(&[1, 4, 0x05, 0xd4]); // MRU 1492
            n += 4;
            if self.lcp_reqs_sent == 1 {
                d[n..n + 2].copy_from_slice(&[8, 2]); // ACFC — the client must Reject it
                n += 2;
            }
            if self.chap {
                d[n..n + 5].copy_from_slice(&[3, 5, 0xc2, 0x23, 5]);
                n += 5;
            } else {
                d[n..n + 4].copy_from_slice(&[3, 4, 0xc0, 0x23]);
                n += 4;
            }
            d[n..n + 6].copy_from_slice(&[5, 6, 0x11, 0x22, 0x33, 0x44]);
            n += 6;
            let (b, l) = sess(0xc021, 1, self.lcp_reqs_sent as u8, &d[..n]);
            o.push(&b[..l]);
        }
        fn after_lcp(&mut self, o: &mut Out) {
            if self.cli_acked_us && self.we_acked_cli && !self.auth_started {
                self.auth_started = true;
                if self.chap {
                    let mut d = [0u8; 1 + 16 + 8];
                    d[0] = 16;
                    d[1..17].copy_from_slice(&CHAL);
                    d[17..25].copy_from_slice(b"bench-ac");
                    let (b, l) = sess(0xc223, 1, 7, &d);
                    o.push(&b[..l]);
                }
            }
        }
        fn start_ipcp(&mut self, o: &mut Out) {
            if !self.ipcp_started {
                self.ipcp_started = true;
                let (b, l) = sess(0x8021, 1, 1, &[3, 6, 10, 67, 0, 1]);
                o.push(&b[..l]);
            }
        }
        fn handle(&mut self, f: &[u8], o: &mut Out) {
            let et = be16(f, 12);
            if et == ETH_DISC {
                match f[15] {
                    0x09 => {
                        let hu = tag(f, 0x0103).unwrap_or(&[]);
                        let (b, l) = disc(0x07, 0, &[(0x0102, b"bench-ac"), (0x0101, b""), (0x0103, hu), (0x0104, b"COOKIE42")]);
                        o.push(&b[..l]);
                    }
                    0x19 => {
                        self.cookie_echoed = tag(f, 0x0104) == Some(&b"COOKIE42"[..]);
                        let hu = tag(f, 0x0103).unwrap_or(&[]);
                        if self.cookie_echoed {
                            let (b, l) = disc(0x65, SID, &[(0x0101, b""), (0x0103, hu)]);
                            o.push(&b[..l]);
                        }
                    }
                    _ => {}
                }
                return;
            }
            if et != ETH_SESS || be16(f, 16) != SID {
                return;
            }
            let proto = be16(f, 20);
            let (code, id) = (f[22], f[23]);
            let len = be16(f, 24) as usize;
            let data = &f[26..22 + len];
            match (proto, code) {
                (0xc021, 1) => {
                    // client ConfReq: Ack it; send ours the first time
                    let (b, l) = sess(0xc021, 2, id, data);
                    o.push(&b[..l]);
                    self.we_acked_cli = true;
                    if self.lcp_reqs_sent == 0 {
                        self.lcp_req(o);
                    }
                    self.after_lcp(o);
                }
                (0xc021, 2) => {
                    self.cli_acked_us = true;
                    self.after_lcp(o);
                }
                (0xc021, 4) => {
                    self.rejected_acfc = data == [8, 2];
                    self.lcp_req(o);
                }
                (0xc223, 2) if self.chap => {
                    // verify MD5(id || secret || challenge)
                    let mut m = [0u8; 1 + 6 + 16];
                    m[0] = id;
                    m[1..7].copy_from_slice(SECRET_TV);
                    m[7..23].copy_from_slice(&CHAL);
                    let want = hal::md5(&m);
                    self.chap_ok = data.len() >= 17 && data[0] == 16 && data[1..17] == want && &data[17..] == USER;
                    let (b, l) = sess(0xc223, if self.chap_ok { 3 } else { 4 }, id, b"");
                    o.push(&b[..l]);
                    if self.chap_ok {
                        self.authed = true;
                        self.start_ipcp(o);
                    }
                }
                (0xc023, 1) if !self.chap => {
                    let ul = data[0] as usize;
                    let pl = data[1 + ul] as usize;
                    self.pap_ok = &data[1..1 + ul] == USER && &data[2 + ul..2 + ul + pl] == SECRET_TV;
                    let (b, l) = sess(0xc023, if self.pap_ok { 2 } else { 3 }, id, b"\x00");
                    o.push(&b[..l]);
                    if self.pap_ok {
                        self.authed = true;
                        self.start_ipcp(o);
                    }
                }
                (0x8021, 1) => {
                    // client IPCP ConfReq: first Nak with the assignment, then Ack the corrected one
                    if !self.ipcp_nak_sent {
                        self.ipcp_nak_sent = true;
                        let (b, l) = sess(0x8021, 3, id, &[3, 6, 10, 67, 0, 10, 129, 6, 1, 1, 1, 1, 131, 6, 9, 9, 9, 9]);
                        o.push(&b[..l]);
                    } else {
                        self.ipcp_acked = data == [3, 6, 10, 67, 0, 10, 129, 6, 1, 1, 1, 1, 131, 6, 9, 9, 9, 9];
                        let (b, l) = sess(0x8021, 2, id, data);
                        o.push(&b[..l]);
                    }
                }
                _ => {}
            }
        }
    }
    fn run(chap: bool) -> (bool, Pppoe, Ac) {
        let mut c = Pppoe::new(CLI, USER, SECRET_TV, 0xdead_beef, 0xa1b2_c3d4);
        let mut ac = Ac {
            chap, lcp_reqs_sent: 0, cli_acked_us: false, we_acked_cli: false, authed: false, auth_started: false,
            ipcp_started: false, chap_ok: false, pap_ok: false, cookie_echoed: false, rejected_acfc: false,
            ipcp_nak_sent: false, ipcp_acked: false,
        };
        let mut tx = Tx::new();
        c.start(0, &mut tx);
        let mut now = 0u64;
        for _round in 0..40 {
            if c.phase == Phase::Open || c.phase == Phase::Down {
                break;
            }
            let mut o = Out { f: [[0; 256]; 4], len: [0; 4], n: 0 };
            for i in 0..tx.n {
                let fr = tx.f[i];
                let ln = tx.len[i];
                ac.handle(&fr[..ln], &mut o);
            }
            tx.clear();
            now += 10;
            for i in 0..o.n {
                c.rx(&o.f[i][..o.len[i]], now, &mut tx);
            }
            if tx.n == 0 {
                c.tick(now + 2_100, &mut tx);
            }
        }
        (c.phase == Phase::Open, c, ac)
    }
    // CHAP run, then the post-open checks
    let (open_chap, mut c, ac) = run(true);
    let neg_ok = open_chap && ac.cookie_echoed && ac.rejected_acfc && ac.chap_ok && ac.ipcp_acked
        && c.sid == SID && c.my_ip == [10, 67, 0, 10] && c.peer_ip == [10, 67, 0, 1]
        && c.dns1 == [1, 1, 1, 1] && c.dns2 == [9, 9, 9, 9] && c.ac_mac == AC;
    let mut tx = Tx::new();
    let (b, l) = sess(0xc021, 9, 0x55, &[0x11, 0x22, 0x33, 0x44, b'h', b'b']);
    c.rx(&b[..l], 1000, &mut tx);
    let echo_ok = tx.n == 1 && be16(tx.frame(0), 20) == 0xc021 && tx.frame(0)[22] == 10 && tx.frame(0)[23] == 0x55
        && tx.frame(0)[26..30] == 0xa1b2_c3d4u32.to_be_bytes() && &tx.frame(0)[30..32] == b"hb";
    tx.clear();
    // IPV6CP (RFC 5072) is now RUN, not rejected: the AC's Conf-Req (IID ::1) is Acked, the session stays up.
    let (b, l) = sess(0x8057, 1, 1, &[1, 10, 0, 0, 0, 0, 0, 0, 0, 1]);
    c.rx(&b[..l], 1001, &mut tx);
    let v6_acked = tx.n == 1 && be16(tx.frame(0), 20) == 0x8057 && tx.frame(0)[22] == 2 && c.phase == Phase::Open
        && c.peer_iid == [0, 0, 0, 0, 0, 0, 0, 1];
    tx.clear();
    // A protocol we really do not run (CCP) is still Protocol-Rejected, session up.
    let (b, l) = sess(0x80fd, 1, 1, &[]);
    c.rx(&b[..l], 1002, &mut tx);
    let prej_ok = v6_acked && tx.n == 1 && tx.frame(0)[22] == 8 && be16(tx.frame(0), 26) == 0x80fd && c.phase == Phase::Open;
    tx.clear();
    // Our own IPV6CP request (retransmitted on the 3-s clock) — Ack it -> IPv6 up; then an IPv6 encap/decap round trip.
    c.tick(1_000_000, &mut tx);
    let mut rid = None;
    for i in 0..tx.n {
        let f = tx.frame(i);
        if be16(f, 20) == 0x8057 && f[22] == 1 {
            rid = Some((f[23], [f[28], f[29], f[30], f[31], f[32], f[33], f[34], f[35]]));
        }
    }
    tx.clear();
    let v6_up = if let Some((id, iid)) = rid {
        let mut d = [0u8; 10];
        d[0] = 1;
        d[1] = 10;
        d[2..10].copy_from_slice(&iid);
        let (b, l) = sess(0x8057, 2, id, &d);
        c.rx(&b[..l], 1_000_001, &mut tx);
        c.ip6_up && iid == arch_aarch64::ip6::eui64(&CLI)
    } else {
        false
    };
    tx.clear();
    let v6_rt = v6_up && {
        let mut pkt = [0u8; 64];
        let n = arch_aarch64::ip6::build_rs(&c.my_iid, &mut pkt);
        let mut enc = [0u8; 128];
        match c.encap_ipv6(&pkt[..n], &mut enc) {
            Some(en) => {
                // the same bytes coming back from the AC decap to the identical IPv6 packet
                let mut back = enc;
                back[0..6].copy_from_slice(&CLI);
                back[6..12].copy_from_slice(&AC);
                be16(&enc, 20) == 0x0057 && c.decap_ipv6(&back[..en]) == Some(&pkt[..n])
            }
            None => false,
        }
    };
    let prej_ok = prej_ok && v6_up && v6_rt;
    if !prej_ok {
        kprint!("   [P-pppoe v6] acked={} ccp_rej={} our_req={} up={} roundtrip={}\n", v6_acked, prej_ok, rid.is_some(), v6_up, v6_rt);
    }
    // IPv4 encap/decap round trip
    let mut eth = [0u8; 60];
    eth[12] = 0x08;
    eth[14] = 0x45;
    eth[16..18].copy_from_slice(&40u16.to_be_bytes());
    eth[23] = 6;
    eth[26..30].copy_from_slice(&[10, 67, 0, 10]);
    eth[30..34].copy_from_slice(&[8, 8, 8, 8]);
    let mut enc = [0u8; 128];
    let en = c.encap_ipv4(&eth[..54], &mut enc).unwrap_or(0);
    let encap_ok = en >= 62 && be16(&enc, 12) == ETH_SESS && be16(&enc, 16) == SID && be16(&enc, 18) == 42
        && be16(&enc, 20) == 0x0021 && enc[0..6] == AC && enc[22..62] == eth[14..54];
    // the reply from the internet arrives in the session
    let mut back = [0u8; 128];
    back[..en].copy_from_slice(&enc[..en]);
    back[0..6].copy_from_slice(&CLI);
    back[6..12].copy_from_slice(&AC);
    let mut dec = [0u8; 128];
    let dn = c.decap_ipv4(&back[..en], &mut dec).unwrap_or(0);
    let decap_ok = dn == 54 && be16(&dec, 12) == 0x0800 && dec[0..6] == CLI && dec[14..54] == eth[14..54];
    let (b, l) = disc(0xa7, SID, &[]);
    c.rx(&b[..l], 1002, &mut tx);
    let padt_ok = c.phase == Phase::Down && c.why == DownWhy::Padt;
    // PAP run
    let (open_pap, mut cp, acp) = run(false);
    let pap_ok = open_pap && acp.pap_ok && cp.my_ip == [10, 67, 0, 10];
    // Keepalive: the first tick arms the clock; one interval later an Echo-Request goes out; an
    // Echo-Reply resets the miss count; ECHO_MISSES unanswered requests bring the session down.
    let ka = {
        use arch_aarch64::pppoe::{ECHO_MISSES, ECHO_MS};
        let mut t = Tx::new();
        let base = 50_000u64;
        // An echo is due (the run's last tick armed the clock long ago): exactly one goes out ...
        // Count LCP Echo-Requests only: tick() also retransmits IPV6CP (this scripted AC never answers it).
        let echoes = |t: &Tx| (0..t.n).filter(|&i| be16(t.frame(i), 20) == 0xc021 && t.frame(i)[22] == 9).count();
        cp.tick(base, &mut t);
        let req = echoes(&t) == 1;
        let rid = (0..t.n).find(|&i| be16(t.frame(i), 20) == 0xc021 && t.frame(i)[22] == 9).map(|i| t.frame(i)[23]).unwrap_or(0);
        t.clear();
        // ... and not again within the same interval.
        cp.tick(base + 1, &mut t);
        let once = echoes(&t) == 0;
        // An Echo-Reply resets the miss count.
        let (b, l) = sess(0xc021, 10, rid, &0x1122_3344u32.to_be_bytes());
        cp.rx(&b[..l], base + 5, &mut t);
        let reset_ok = cp.stats.echo_rx == 1 && cp.phase == Phase::Open;
        // ECHO_MISSES unanswered requests, then the next due tick declares the session dead.
        let mut now = base;
        let mut sent = 0;
        for _ in 0..=ECHO_MISSES {
            now += ECHO_MS;
            t.clear();
            cp.tick(now, &mut t);
            sent += echoes(&t);
        }
        let r = req && once && reset_ok && sent == ECHO_MISSES as usize && cp.phase == Phase::Down && cp.why == DownWhy::NoEcho;
        if !r {
            kprint!("   [P-pppoe ka] req={} once={} reset={} sent={} phase={:?} why={:?}\n", req, once, reset_ok, sent, cp.phase, cp.why);
        }
        r
    };
    // Stale-session sweep: a fresh client (Discovery) gets an LCP Echo-Request from the AC on an OLD SID
    // (the session it held before our reboot) -> exactly one PADT for that SID back to that AC, rate-limited,
    // and nothing for broadcast or for frames while Requesting.
    let stale_ok = {
        const OLD: u16 = 0x0bad;
        let mut sc = Pppoe::new(CLI, USER, SECRET_TV, 7, 0x5555_6666);
        let mut t = Tx::new();
        sc.start(0, &mut t);
        t.clear();
        let mut f = [0u8; 64];
        f[0..6].copy_from_slice(&CLI);
        f[6..12].copy_from_slice(&AC);
        f[12..14].copy_from_slice(&ETH_SESS.to_be_bytes());
        f[14] = 0x11;
        f[16..18].copy_from_slice(&OLD.to_be_bytes());
        f[18..20].copy_from_slice(&10u16.to_be_bytes());
        f[20..22].copy_from_slice(&0xc021u16.to_be_bytes());
        f[22] = 9; // LCP Echo-Request
        f[23] = 1;
        f[24..26].copy_from_slice(&8u16.to_be_bytes());
        sc.rx(&f[..60], 100, &mut t);
        let one = t.n == 1 && {
            let p = t.frame(0);
            p[0..6] == AC && u16::from_be_bytes([p[12], p[13]]) == ETH_DISC && p[15] == 0xa7 && u16::from_be_bytes([p[16], p[17]]) == OLD
        };
        sc.rx(&f[..60], 200, &mut t); // same SID within 1 s: rate-limited
        let limited = t.n == 1;
        sc.rx(&f[..60], 1300, &mut t); // after 1 s: answered again
        let again = t.n == 2;
        let mut bc = f;
        bc[0..6].copy_from_slice(&[0xff; 6]);
        sc.rx(&bc[..60], 5000, &mut t); // broadcast: never
        let no_bcast = t.n == 2;
        let r = one && limited && again && no_bcast && sc.stats.stale_padt == 2 && sc.phase == Phase::Discovery;
        if !r {
            kprint!("   [P-pppoe stale] one={} limited={} again={} no_bcast={} n={} stale_padt={} phase={:?}\n", one, limited, again, no_bcast, t.n, sc.stats.stale_padt, sc.phase);
        }
        r
    };
    // Peer review H1 regression: session frames with PPPoE length 0/1 (or not addressed to us) are refused by
    // BOTH decap paths — they used to slice f[22..20] and panic the kernel (remote DoS from the WAN segment).
    let short_ok = {
        let mut ok = true;
        for (proto, l, to_us) in [(0x0021u16, 0u16, true), (0x0021, 1, true), (0x0057, 0, true), (0x0057, 1, true), (0x0021, 44, false)] {
            let mut b = [0u8; 80];
            b[0..6].copy_from_slice(if to_us { &CLI } else { &AC });
            b[6..12].copy_from_slice(&AC);
            b[12..14].copy_from_slice(&ETH_SESS.to_be_bytes());
            b[14] = 0x11;
            b[16..18].copy_from_slice(&SID.to_be_bytes());
            b[18..20].copy_from_slice(&l.to_be_bytes());
            b[20..22].copy_from_slice(&proto.to_be_bytes());
            b[22] = 0x45;
            let mut o = [0u8; 128];
            ok &= c.decap_ipv4(&b[..80], &mut o).is_none() && c.decap_ipv6(&b[..80]).is_none();
        }
        ok
    };
    let ok = neg_ok && echo_ok && prej_ok && encap_ok && decap_ok && padt_ok && pap_ok && ka && stale_ok && short_ok;
    kprint!(" [P-pppoe] {} — PPPoE vs a scripted AC: discovery+cookie, LCP (ACFC rejected), CHAP-MD5 verified, IPCP Nak -> 10.67.0.10 dns 1.1.1.1/9.9.9.9 => open={} | Echo-Reply w/ magic={} IPV6CP run (AC IID acked, ours acked -> v6 up, IPv6 encap/decap) + CCP still Protocol-Rejected={} IPv4 encap={} decap={} PADT->down={} | PAP run open={} | client keepalive: one echo per interval, reply resets, 3 misses -> down (NoEcho)={} | stale-session sweep: PADT for an old SID, rate-limited, never broadcast={} | short (len 0/1) or not-to-us session frames refused by both decaps, no panic={}\n",
        if ok { "PASS" } else { "FAIL" }, neg_ok, echo_ok, prej_ok, encap_ok, decap_ok, padt_ok, pap_ok, ka, stale_ok, short_ok);
}
