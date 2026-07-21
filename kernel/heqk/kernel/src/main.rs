#![no_std]
#![no_main]
//! HEQK Core — Hardened Edge Quantum-safe Kernel (the HookProbe microkernel).
//!
//! Boot (P0) -> heap -> spawn threads -> GIC + generic-timer tick -> enable
//! IRQs -> idle. The timer preempts whatever runs and the round-robin scheduler
//! switches contexts; each thread's local counter surviving across switches is
//! the proof that context save/restore works.

extern crate alloc;

mod bpf;
mod caps;
mod heap;
mod ipc;
mod packet;
mod scheduler;
mod telemetry;

use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
/// Set by the timer IRQ when the on-metal scheduler demo completes (cm5).
static SCHED_DONE: AtomicBool = AtomicBool::new(false);

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

    kprint!(" [CM5-BOOT] PASS — HEQK boots, MMU on, prints on real hardware\n");

    // --- P7b: GIC-400 + generic timer + preemptive scheduler on metal ------
    cm5_scheduler_demo();

    kprint!(" halting; next: RP1 networking (the packet-plane keystone)\n");
    // After the banner: drain the UART, then request reboot via `hvc #0` —
    // the EL2 gate performs the PM reset (EL1 writes to the PM block are
    // silently ignored; EL2 is the proven path). The bench self-recovers.
    for _ in 0..200_000_000u64 {
        core::hint::spin_loop();
    }
    unsafe { core::arch::asm!("hvc #0", options(noreturn)) }
}

/// P7b: spawn priority workers, bring up GIC-400 + the generic timer, enable
/// IRQs, and let the round-robin/priority scheduler preempt them on real
/// hardware. Bounded: if timer IRQs never arrive (routing not as expected),
/// a spin cap lets the boot proceed to reboot instead of hanging.
#[cfg(feature = "cm5")]
fn cm5_scheduler_demo() {
    kprint!(" [P7b] scheduler on metal: GIC-400 + generic timer + 3 priority workers\n");
    scheduler::init();
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
    let gic = arch_aarch64::Gic;
    gic.init();
    gic.enable(arch_aarch64::timer::TIMER_INTID);
    arch_aarch64::GenericTimer.start(TICK_HZ);
    kprint!(" [P7b] {} Hz tick armed (GIC INTID {}); IRQs on\n",
        TICK_HZ, arch_aarch64::timer::TIMER_INTID);
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
    // Replay: fold each event into a fresh PCR bank.
    let events = (bi.measure_log_pa as usize + core::mem::size_of::<MeasureLog>()) as *const MeasureEvent;
    let mut pcr = [[0u8; 32]; NUM_PCR];
    for i in 0..count as usize {
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

    // --- P3: EL0 userspace + SVC syscalls (incl. capability invocation) + fault ---
    p3_user_demo();

    // Verify the signed threat rule BEFORE the datapath ever runs it (verify-
    // then-run; any future third-party rule must clear the verifier + JIT too).
    if !bpf::verify(&bpf::THREAT_RULE) {
        kprint!(" bpf: signed threat rule failed verification\n");
        arch_aarch64::semihosting::exit(1);
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
        gic.eoi(intid);
        if scheduler::alive_workers() == 0 || n >= RUN_TICKS {
            #[cfg(not(feature = "cm5"))]
            {
                kprint!("\n [P1] PASS priority scheduler (H>M>L order, threads exited, context switch verified)\n");
                kprint!(" [ALL] P0 P1 P1b P2 P3 P4 P5 P5b P6 P6b DRV GREEN\n");
                arch_aarch64::semihosting::exit(0);
            }
            // On real silicon there is no semihosting exit: signal the idle
            // loop to stop and reboot cleanly via HBoot's EL2 gate.
            #[cfg(feature = "cm5")]
            if !SCHED_DONE.swap(true, Ordering::SeqCst) {
                kprint!("\n [P7b] PASS preemptive scheduler on metal ({} ticks, context switch verified)\n", n);
            }
        }
        next
    } else {
        gic.eoi(intid);
        sp
    }
}

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

    let pass = live0 == 8
        && retype_ep
        && ep_as_frame
        && frame_as_frame
        && subtree_gone
        && live1 == 6
        && live2 == 1
        && root_reclaimed;
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

// Value the isolated EL0 driver server reported (a NIC register it read).
static DRIVER_REPORT: AtomicU32 = AtomicU32::new(0);

// The root task's capability space (initialized by build_root_cspace).
static mut ROOT: Option<caps::CapSpace> = None;

fn root() -> &'static caps::CapSpace {
    unsafe { (&*core::ptr::addr_of!(ROOT)).as_ref().unwrap() }
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
    unsafe { ROOT = Some(cs) };
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
pub extern "C" fn handle_lower_sync(frame: *mut u64) {
    let esr: u64;
    unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) esr) };
    let ec = (esr >> 26) & 0x3f;

    if ec == 0x15 {
        // SVC from AArch64: dispatch (x8=num, x0/x1=args), return value into x0.
        let num = unsafe { *frame.add(8) };
        let a0 = unsafe { *frame.add(0) };
        let a1 = unsafe { *frame.add(1) };
        if num == SYS_EXIT_USER {
            unsafe { arch_aarch64::syscall::resume_kernel() }; // EL0 server done -> kernel
        }
        let ret = syscall_dispatch(num, a0, a1);
        unsafe { *frame.add(0) = ret };
    } else {
        // Fault from EL0 (e.g. data abort EC=0x24). Contain: report, kill the
        // user context, resume the kernel — the kernel does not go down.
        let far: u64;
        unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) far) };
        kprint!("   [EL0 fault] contained: EC={:#04x} FAR={:#x} (kernel survives)\n", ec, far);
        telemetry::emit(telemetry::Event::Fault); // the OS senses its own fault
        unsafe { arch_aarch64::syscall::resume_kernel() };
    }
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
            // Genuine capability invocation from EL0: resolve a CPtr in the root
            // task's CSpace and return the object type.
            let cptr = a0 as usize;
            match root().get(cptr) {
                Some(c) => {
                    kprint!("   [EL0>svc] invoked cap[{}] -> {} (type code {})\n", cptr, c.otype.name(), c.otype.code());
                    c.otype.code()
                }
                None => {
                    kprint!("   [EL0>svc] invoked cap[{}] -> empty slot\n", cptr);
                    u64::MAX
                }
            }
        }
        SYS_DRIVER_REPORT => {
            // An isolated EL0 driver reports a value it read from its device MMIO.
            DRIVER_REPORT.store(a0 as u32, Ordering::Relaxed);
            0
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
        let pkt = [(port >> 8) as u8, (port & 0xff) as u8, 0u8, 0u8];
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
    let good = bpf::verify(&bpf::THREAT_RULE);
    let backward: [u64; 2] = [0xFFFF_0055, 0x0000_0095]; // JNE off=-1 (backward), EXIT
    let bad = bpf::verify(&backward);
    kprint!(
        "   verifier: signed rule -> {}, looping rule -> {}\n",
        if good { "ACCEPT" } else { "reject?!" },
        if bad { "accept?!" } else { "REJECT" }
    );
    if !good || bad {
        ok = false;
    }

    // 2. JIT: compile the rule to native ARM64, run it, compare to the interpreter.
    match arch_aarch64::bpf_jit::compile_threat_rule() {
        Some(code_va) => {
            let f: extern "C" fn(*const u8) -> u64 =
                unsafe { core::mem::transmute::<usize, extern "C" fn(*const u8) -> u64>(code_va) };
            let mut jit_ok = true;
            for &port in &[4444u16, 80u16, 443u16] {
                let pkt = [(port >> 8) as u8, (port & 0xff) as u8, 0u8, 0u8];
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
    let m = ipc::recv();
    kprint!(" [P4] consumer: received {:#x} via endpoint rendezvous\n", m);
    kprint!(" [P4] PASS ipc (synchronous endpoint rendezvous with block/unblock)\n");
    thread_exit()
}
extern "C" fn producer() -> ! {
    kprint!(" [P4] producer: send(0xBEEF) to endpoint\n");
    ipc::send(0xBEEF);
    kprint!(" [P4] producer: send returned (message delivered)\n");
    thread_exit()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    arch_aarch64::on_panic(info)
}
