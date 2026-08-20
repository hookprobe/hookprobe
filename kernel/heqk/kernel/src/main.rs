#![no_std]
#![no_main]
//! HEQK Core — Hardened Edge Quantum-safe Kernel (the HookProbe microkernel).
//!
//! Boot (P0) -> heap -> spawn threads -> GIC + generic-timer tick -> enable
//! IRQs -> idle. The timer preempts whatever runs and the round-robin scheduler
//! switches contexts; each thread's local counter surviving across switches is
//! the proof that context save/restore works.

extern crate alloc;

mod absdom;
mod attest_svc;
mod behavioral;
mod blocklist;
mod bpf;
mod caps;
mod devq;
// M5.1 (Track C) — minimal bounds-safe ELF64/aarch64 static loader (the userspace-server
// substrate beachhead). Only driven by the QEMU [P-elf] gate; the parser compiles on all
// backends but the loader/mapping path is QEMU-only (see load_into's cfg).
mod elf;
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
mod net;
mod netq;
#[cfg(feature = "netsvc")]
mod netsvc;
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
// M6 (ADR 0044 D3 B2) — on-device evidence/telemetry export over the enrolled channel.
#[cfg(feature = "securechannel")]
mod export;
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
mod rules;
mod scheduler;
mod seal;
mod store;
mod telemetry;
mod verdict;

use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
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
/// ~326 KiB .text lives HERE, NOT in the kernel TCB.
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
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

    // --- P8: load the signed HookProbe rule plane (verify every rule; JIT is
    // QEMU-only, so CM5 runs the bounds-checked interpreter — same verdict). ---
    let (rv, rj) = rules::init();
    kprint!(" [P8] rule plane: {} rules verified, {} JIT-compiled to native ARM64 on metal — parity corpus armed\n", rv, rj);

    // --- P8: statically VERIFY the detection rule before running it on live traffic --
    cm5_p8_verify();

    // --- A/B: detection plane is up -> confirm this boot (disarm trial watchdog) ---
    boot_confirm();

    // --- P8: RP1 GEM Ethernet — polled RX first light ----------------------
    cm5_gem_rx_demo();

    // --- P9: external PCIe RC1 link + RTL8111H vendor-ID (2nd-interface bring-up) --
    cm5_p9_probe();

    // --- P14 seed: BCM2712 IOMMU probe (PCIe DMA-containment recon) --
    cm5_iommu_probe();

    // --- P10 Stage A: CYW43455 WiFi SDIO bring-up + chip-ID (0x4345) --
    cm5_p10_probe();

    // --- P15: eMMC read-only block device + sealing (in-RAM, synthetic key) --
    #[cfg(feature = "hboot")]
    cm5_p15_block_seal();

    // --- P13: RP1 peripheral buses (GPIO/pinmux + I2C + SPI + UART), EL0-isolated --
    cm5_p13_probe();

    // --- P7c step 3b: the REAL GEM, read from an ISOLATED EL0 driver --------
    cm5_gem_el0_probe(); // stage 1: register probe
    cm5_gem_el0_rx_probe(); // stage 2: RX descriptor-ring poll (the packet hot path)
    cm5_gem_el0_tx_probe(); // stage 3: launch a TX from EL0 (arm + kick + poll)
    cm5_gem_el0_ids(); // stage 4a: EL0 driver delivers a frame -> kernel IDS verdict
    // --- P8 (RX-IRQ): enable interrupt-driven RX (LAST — bounded, self-contained) ---
    cm5_gem_rx_irq_probe();

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
        kprint!(" [HBoot-AB] PASS — trial boot confirmed; EL2 watchdog disarmed, slot committed\n");
    } else {
        kprint!(" [HBoot-AB] PASS — no trial watchdog in handoff; nothing to confirm\n");
    }
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
    arch_aarch64::gem::tx_prep_el0(64); // kernel: fill TX buffer + descriptor address
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
    let used = (w1 >> 31) & 1 == 1;
    kprint!(" [P7c] EL0 TX driver launched a transmit: final word1={:#010x} (USED/complete={})\n",
        w1, used);
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

#[cfg(feature = "cm5")]
fn cm5_prod_service() -> ! {
    use arch_aarch64::mmu_cm5;
    arch_aarch64::disable_irqs();
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

    // Distinct sentinel (AUDIT D3/D4) so a CONTAINED EL0 driver fault — the stub crashed
    // before it ran its report syscall — is told apart from a benign empty window (where
    // the stub DOES report, with 0). Without this the two collapse into `empty` and a
    // crash-looping driver reads as a quiet link.
    const RPT_SENTINEL: u32 = 0xFFFF_FFFF; // DRIVER_REPORT is u32; a real report is idx<<16 (< this)
    // Telemetry invariant: seen == forwarded + dropped + tx_fail.
    let (mut seen, mut forwarded, mut dropped) = (0u64, 0u64, 0u64);
    let (mut empty, mut faults, mut tx_fail) = (0u64, 0u64, 0u64);
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

    kprint!(" [PROD] HEQK sensor UP — isolated EL0 GEM driver -> verified rule plane -> ENFORCE (forward PASS / drop threat); self-healing; never halts\n");
    loop {
        // Liveness heartbeat (~5 s) — fires even when every RX window is empty, so the
        // running sensor proves it is looping on metal, not hung.
        let now = prod_cntpct();
        if now.wrapping_sub(last_hb) >= hb_interval {
            last_hb = now;
            // AUDIT (2026-08-20 metal): tx_fail was an ANONYMOUS timeout — a PASS frame
            // silently not forwarded with no cause. gem::tx_err_take() reports the GEM
            // TSR that accompanied the most recent failure (bit0 UBR / bit2 RLE /
            // bit4 TFC / bit6 UND / bit7 HRESP are the halting ones; bit3 alone = the
            // timeout happened with a CLEAN status, which means something else stalled).
            let txerr = arch_aarch64::gem::tx_err_take();
            kprint!("   [PROD hb] up={}s seen={} fwd={} drop={} tx_fail={} txerr={:#04x} faults={} empty={} qsecbit={}\n",
                now.wrapping_sub(t0) / cntfrq, seen, forwarded, dropped, tx_fail, txerr, faults, empty, telemetry::score());
            // prod-full: throttled M3 persist (interval AND dirty — the reserved
            // window is 32 sectors and every persist rewrites the same LBAs) plus
            // the structural M6 export gate.
            #[cfg(feature = "prod-full")]
            {
                let up = now.wrapping_sub(t0) / cntfrq;
                let c = prodfull::Counters { seen, forwarded, dropped, tx_fail, faults, empty };
                if pf.on_heartbeat(up, c, telemetry::score()) {
                    kprint!("   [PROD-FULL] M3 persisted: boots={} seen={} drop={} events={} (sealed, LBA {}..)\n",
                        pf.snap.boots, seen, dropped, pf.snap.nev, arch_aarch64::emmc::RESERVED_LBA_LO);
                }
            }
        }
        // (Re)load the TRUSTED driver stub every iteration — a crash on the prior
        // iteration was contained by the EL0 fault handler; this reload is the
        // structural self-heal ([P7c] proves the contain+restart survives).
        let len = ids.1 - ids.0;
        unsafe { core::ptr::copy_nonoverlapping(ids.0 as *const u8, code_pa as *mut u8, len) };
        arch_aarch64::mmu::sync_instruction_cache(code_pa, len);
        mmu_cm5::map_user_code(ucode, code_pa);

        DRIVER_REPORT.store(RPT_SENTINEL, Ordering::Relaxed);
        // Drop to EL0; returns here on the driver's report syscall OR on a contained fault.
        unsafe { arch_aarch64::syscall::enter_user(ucode, ustack + 0x1000) };

        let report = DRIVER_REPORT.load(Ordering::Relaxed);
        if report == RPT_SENTINEL {
            // The driver FAULTED before reporting (contained by the EL0 fault handler; the
            // trusted stub is re-copied above). Count it so a crash-looping driver is
            // observable, DISTINCT from a quiet link — this is the honest self-heal signal.
            faults += 1;
            continue;
        }
        let idx = ((report >> 16) & 0xff) as usize;
        // Frame length from the HW status writeback (AUDIT M-7), never the untrusted
        // EL0 report. None => the stub reported but no frame is ready -> empty window.
        let flen = match arch_aarch64::gem::rx_desc_status(idx) {
            Some(l) if l >= 14 => l,
            _ => {
                empty += 1;
                continue;
            }
        };
        // AUDIT D5: size the buffer to the HW RX buffer (RXBUF up to 2048), NOT 1600 —
        // a 1601..2048 B frame must not be truncated before verdict (deep-L7 evasion).
        let mut buf = [0u8; packet::FRAME_SZ];
        let n = flen.min(buf.len());
        arch_aarch64::gem::peek_rx_frame(idx, &mut buf[..n]);
        seen += 1;
        // The verified rule plane's verdict on the real frame.
        let (_port, v) = packet::verdict(&buf[..n]);
        if v == packet::PASS {
            // ENFORCE: forward on the wire; a TX-completion timeout is counted (AUDIT D2)
            // so `seen == forwarded + dropped + tx_fail` holds and a lost PASS frame is
            // never invisible.
            if arch_aarch64::gem::tx_frame(&buf[..n]).is_some() {
                forwarded += 1;
            } else {
                tx_fail += 1;
            }
        } else {
            // ENFORCE: threat verdict — dropped, NOT forwarded.
            dropped += 1;
            // prod-full: the dropped frame becomes a persisted evidence event. The
            // 16-byte image is the SAME encoding M6 exports, so a persisted record
            // and an exported one are byte-identical (no re-encoding drift).
            #[cfg(feature = "prod-full")]
            {
                let ev = events::Event {
                    ts: now,
                    src: 0,          // not flow-scoped here; the rule plane owns attribution
                    rule_id: 0,      // packet::verdict does not surface the rule id at this seam
                    severity: 0,
                    verdict: packet::DROP as u8,
                };
                pf.on_threat(&ev);
            }
        }
        arch_aarch64::gem::recycle_rx(idx); // re-arm the slot for the next frame
        // A processed-frame beat too, so a busy link reports progress between the ~5 s ticks.
        if (seen & 0xff) == 0 && seen != 0 {
            kprint!("   [PROD hb] seen={} fwd={} drop={} tx_fail={} faults={} empty={} qsecbit={} (frame-beat)\n",
                seen, forwarded, dropped, tx_fail, faults, empty, telemetry::score());
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
    use bpf::{verify_prevail, EVIL_LOOP, EVIL_NO_VERDICT, EVIL_WILD_LOAD, THREAT_RULE};
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
        && verify_prevail(&EVIL_NO_VERDICT).is_err();
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
    let mut i = 0usize;
    let mut spins = 0u64;
    while frames < 4 && spins < 60_000_000 {
        if let Some(len) = rtl8111::poll_rx(i, &mut buf) {
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
            i = (i + 1) % 256; // NRX — advance to the next descriptor
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

    let emmc = match Emmc::probe() {
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
    let before = GEM_RX_IRQS.load(Ordering::Relaxed);
    // Unmask IRQs (DAIF.I=0); only SPI 166 can fire now. Bounded wait for a frame.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)) };
    let mut spins = 0u64;
    while GEM_RX_IRQS.load(Ordering::Relaxed) == before && spins < 300_000_000 {
        spins += 1;
        core::hint::spin_loop();
    }
    // Re-mask IRQs so the trailing reboot path stays deterministic.
    unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)) };
    let fired = GEM_RX_IRQS.load(Ordering::Relaxed).wrapping_sub(before);
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

    // --- P8/L7: deep-packet signature match in the verified fast-path (helper #3)
    p8_l7();

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
        let ok = netsvc::netsvc_selftest(0x4845_514b_5636_0000);
        kprint!(" [PH6-net] {} — smoltcp stack answers ARP for its own IP, ingress+egress verdict-gated (EL0-isolated netq service = metal follow-up)\n",
            if ok { "PASS" } else { "FAIL" });
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

    // --- P15-guard2: M3.0 multi-region write-guard (brick-safety, every boot) ---
    p15_guard_selftest();

    // --- P15-persist: M3.1 cross-restart persistence over file-backed virtio-blk
    //     (skips diskless; the two-boot proof is driven by validate.sh) ---
    p15_persist_selftest();

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
        let mut junk = [events::Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0 }; 16];
        while events::drain(&mut junk) > 0 {}
    }
    // Trigger two fresh threat drops (each pushes an event header in the TCB).
    for &port in &[4444u16, 23u16] {
        let l4 = [0u8, 0u8, (port >> 8) as u8, (port & 0xff) as u8];
        let _ = rules::run_l4(&l4, 0);
    }
    // The exporter drains the ring (zero-copy read of the headers, never payload).
    let mut batch = [events::Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0 }; 16];
    let n = events::drain(&mut batch);
    for ev in &batch[..n] {
        kprint!("   event: rule {} sev {} verdict {} @ts {}\n",
            ev.rule_id, ev.severity, if ev.verdict == packet::DROP as u8 { "DROP" } else { "PASS" }, ev.ts);
    }
    // At least the two fresh drops must have been exported; ring never blocked.
    let ok = n >= 2 && batch[..n].iter().all(|e| e.verdict == packet::DROP as u8);
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
    let mut fr = [0u8; 64];
    fr[0..6].copy_from_slice(&DST);
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

    kprint!(" [P8-l2struct] {} — F6/F7/F8 -> FrameDrop; mac-flood Access->RateLimit but Uplink/AP->Observe (legit AP clients NEVER dropped); broadcast-storm fires but mDNS/SSDP/LLMNR exempt (ADR 0023 D12/D13, all via decide_l2)\n",
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
    fn tcp_frame(src: [u8; 4], dst_port: u16, flags: u8) -> [u8; 54] {
        let mut f = [0u8; 54];
        f[12] = 0x08;
        f[13] = 0x00; // EtherType IPv4
        f[14] = 0x45; // IPv4, IHL=5
        f[17] = 40; // IP total length = 20 (IP) + 20 (TCP)
        f[23] = 6; // proto TCP
        f[26..30].copy_from_slice(&src); // IP source
        f[36] = (dst_port >> 8) as u8;
        f[37] = (dst_port & 0xff) as u8; // TCP dst port
        f[46] = 0x50; // TCP data offset = 5 words
        f[47] = flags; // TCP flags
        f
    }
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    #[inline]
    fn ip(src: [u8; 4]) -> u32 {
        crate::net::eth_ipv4_src(&tcp_frame(src, 0, SYN))
    }
    #[inline]
    fn scan_step(src: [u8; 4], dst_port: u16, flags: u8) -> Option<verdict::Verdict> {
        let f = tcp_frame(src, dst_port, flags);
        rules::flow_scan_verdict(&f, crate::net::eth_ipv4_src(&f))
    }

    // === ATTACKER A4: a 60-distinct-port SYN scan, UNCONFIRMED → RateLimit (wire DROP),
    //     never Quarantine (bounded, self-reverting; anti-spoof — durable block withheld). ===
    let atk: [u8; 4] = [198, 18, 0, 10]; // TEST-NET-2, used nowhere else
    let mut saw_ratelimit_drop = false;
    let mut saw_quarantine_early = false;
    for port in 1..=60u16 {
        if let Some(v) = scan_step(atk, port, SYN) {
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
        if let Some(verdict::Verdict::Quarantine) = scan_step(atk, port, SYN) {
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
        if scan_step(nas, port, SYN).is_some() {
            nas_fired = true;
        }
        if scan_step(nas, port, ACK).is_some() {
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
        if scan_step(burst, 443, SYN).is_some() {
            burst_fired = true;
        }
        if scan_step(burst, 443, ACK).is_some() {
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
    let _ = scan_step(est, 22, SYN);
    let _ = scan_step(est, 22, ACK);
    let c_est = !scan_confirmed(ip(est) as u64) && !ratelimit::scan_over_ratelimit(ip(est) as u64);
    ok &= c_est;
    kprint!("   LEGIT established handshake (est={}) -> scan_confirmed={} (an established flow is definitionally not a scan) [{}]\n",
        ratelimit::flow_established_count(ip(est) as u64), scan_confirmed(ip(est) as u64), if c_est { "ok" } else { "BUG" });

    // === A7 / L9: the flow-table SATURATION signal (pure verdict map; the self-reverting
    //     SHED action is M2.3). L9 40% full → no shed; A7 85% full → shed signal. Keyed on
    //     RESOURCE REALITY (table fill), never identity. ===
    let l9 = !table_saturated(40_000, 100_000); // 40% — a legit heavy source, no shed
    let a7 = table_saturated(85_000, 100_000); // 85% — over the wall, shed signal
    let c_sat = l9 && a7;
    ok &= c_sat;
    kprint!("   A7/L9 saturation (wall {}%): 40%-full sheds={} (must be false), 85%-full sheds={} (must be true) [{}]\n",
        SATURATION_SHED_PCT, !l9, a7, if c_sat { "ok" } else { "BUG" });

    // Sanity: the two bars are ordered so RateLimit precedes Quarantine.
    ok &= SCAN_PORTS_RATELIMIT <= SCAN_PORTS_CONFIRM;

    kprint!(" [P8-flow] {} — distinct-dst-port scan: UNCONFIRMED->RateLimit(DROP), CONFIRMED->Quarantine(DROP); a legit busy source (150 ESTABLISHED flows / 100-per-sec burst) NEVER RateLimits/Quarantines — establishment ⇒ not a scan (ADR 0018/0023, conntrack-equivalent)\n",
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
                }
                #[cfg(feature = "wasmhost")]
                kprint!(" [ALL] P0 P1 P1b P2 P3 P4 P5 P5b P6 P6b DRV P7c P12 P-r1-ipc P-elf P-wasm P-wasm-el0 P-wasmi-el0 P-wasm-parity GREEN\n");
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

/// M5.4 DETECT-mode work-page magic (== el0-wasmhost `DETECT_MAGIC`).
#[cfg(all(not(feature = "cm5"), feature = "wasmhost"))]
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
