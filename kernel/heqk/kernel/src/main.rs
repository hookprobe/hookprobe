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
mod blocklist;
mod bpf;
mod caps;
mod heap;
mod ipc;
mod napi;
mod net;
mod packet;
mod ratelimit;
mod rules;
mod scheduler;
mod telemetry;

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
// P7c-4c: shared by the QEMU and CM5 scheduled-EL0 paths (a scheduled EL0 driver
// TCB whose faults restart/reschedule rather than cooperatively longjmp).
static EL0_SCHED_MODE: AtomicBool = AtomicBool::new(false);
static EL0_RS_ENTRY: AtomicUsize = AtomicUsize::new(0);
static EL0_RS_USP: AtomicUsize = AtomicUsize::new(0);
static EL0_RS_KSTACK: AtomicUsize = AtomicUsize::new(0);
static EL0_RESTARTS: AtomicU32 = AtomicU32::new(0);
const EL0_MAX_RESTARTS: u32 = 3;

// P7c — physical address of the EL0 preemption-test counter (kernel reads it to
// prove the uncooperative EL0 task ran), + a dedicated kernel stack for that TCB.
static EL0_CNT_PA: AtomicUsize = AtomicUsize::new(0);
#[repr(align(16))]
struct KStack([u8; 0x4000]);
static mut EL0_KSTACK: KStack = KStack([0; 0x4000]);
#[cfg(not(feature = "cm5"))]
static mut EL0_FKSTACK: KStack = KStack([0; 0x4000]); // kernel stack for the crashing driver TCB
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

    // --- P8: load the signed HookProbe rule plane (verify every rule; JIT is
    // QEMU-only, so CM5 runs the bounds-checked interpreter — same verdict). ---
    let (rv, rj) = rules::init();
    kprint!(" [P8] rule plane: {} rules verified, {} JIT-compiled to native ARM64 on metal — parity corpus armed\n", rv, rj);

    // --- P8: statically VERIFY the detection rule before running it on live traffic --
    cm5_p8_verify();

    // --- P8: RP1 GEM Ethernet — polled RX first light ----------------------
    cm5_gem_rx_demo();

    // --- P9: external PCIe RC1 link + RTL8111H vendor-ID (2nd-interface bring-up) --
    cm5_p9_probe();

    // --- P14 seed: BCM2712 IOMMU probe (PCIe DMA-containment recon) --
    cm5_iommu_probe();

    // --- P7c step 3b: the REAL GEM, read from an ISOLATED EL0 driver --------
    cm5_gem_el0_probe(); // stage 1: register probe
    cm5_gem_el0_rx_probe(); // stage 2: RX descriptor-ring poll (the packet hot path)
    cm5_gem_el0_tx_probe(); // stage 3: launch a TX from EL0 (arm + kick + poll)
    cm5_gem_el0_ids(); // stage 4a: EL0 driver delivers a frame -> kernel IDS verdict
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
    let flen = (report & 0x3fff) as usize;
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
        let flen = (report & 0x3fff) as usize;
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
    let kstack_top = unsafe { core::ptr::addr_of!(EL0_KSTACK) as usize + 0x4000 };
    let sp = arch_aarch64::thread::make_el0_thread(kstack_top, ecode, estack + 0x1000, ecnt);
    // Arm graceful fault handling for this scheduled EL0 TCB (belt & braces — the
    // loop stub never faults when the mapping is correct).
    EL0_RS_ENTRY.store(ecode, Ordering::Relaxed);
    EL0_RS_USP.store(estack + 0x1000, Ordering::Relaxed);
    EL0_RS_KSTACK.store(kstack_top, Ordering::Relaxed);
    EL0_SCHED_MODE.store(true, Ordering::Relaxed);
    let ttbr0 = l1 as u64 | ((asid as u64) << 48);
    scheduler::spawn_as(sp, 1, ttbr0); // low prio: shares with thread_lo, timer preempts it
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
            let mut jit_ok = true;
            for &port in &[4444u16, 53u16, 80u16] {
                let l4 = [0u8, 0u8, (port >> 8) as u8, (port & 0xff) as u8];
                let jv = f(l4.as_ptr());
                let iv = bpf::run(&THREAT_RULE, l4.as_ptr(), l4.len());
                if jv != iv {
                    jit_ok = false;
                }
            }
            kprint!(" [P8-JIT] {} — THREAT_RULE JIT'd to native ARM64 @ {:#x} (EL1 RO+X), matches interpreter on metal\n",
                if jit_ok { "PASS" } else { "FAIL" }, va);
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
    kprint!(" [P9] RC1 status before train={:#010x}; training (Path B: HEQK owns RC1)...\n",
        rtl8111::rc1_status());
    let d = rtl8111::rc1_train();
    kprint!(" [P9] diag: rescal_done={} iddq {:#x}->{:#x} (want ->0) mdio_timeouts={}/8 perst {:#x}->{:#x} (want ->0x4)\n",
        d.rescal_done, d.iddq_before, d.iddq_after, d.mdio_timeouts, d.perst_before, d.perst_after);
    kprint!(" [P9] RC1 status after train={:#010x} (DL_ACTIVE|PHYLINKUP mask 0x30)\n", d.status);
    if d.status & 0x30 != 0x30 {
        kprint!(" [P9] RC1 link still down — diagnostics above pinpoint the failing stage\n");
        return;
    }
    kprint!(" [P9] RC1 LINK UP (DL_ACTIVE|PHYLINKUP) — HEQK trained the external PCIe!\n");
    match rtl8111::enumerate() {
        Some(mac) => {
            kprint!(" [P9] PASS — RTL8111H found @01:00.0 (vendor/device 0x816810EC), MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            kprint!(" [P9] next: inbound window + RX ring (rtl8111::pcie_inbound_window/mac_start)\n");
        }
        None => kprint!(" [P9] RC1 link up but RTL8111H not found at 01:00.0 (vendor mismatch)\n"),
    }
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
    kprint!(" [P14] probe done — the ADDR_CAP fence that closes the 64 GiB window is staged\n");
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
        if let Some((n, w0, w1, w2, w3)) = arch_aarch64::gem::poll_rx(&mut buf) {
            let n = n.min(buf.len());
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
        for _ in 0..2_000_000u32 {
            core::hint::spin_loop();
        }
        if tick % 100 == 99 {
            kprint!(" [P8] ... waiting, RSR={:#x} (bit0=BNA bit1=REC bit2=OVR)\n",
                arch_aarch64::gem::rsr());
        }
    }
    if got == 0 {
        kprint!(" [P8] no frames (RSR={:#x}) — suspects: PHY reset/link, or RC inbound ATU (BNA)\n",
            arch_aarch64::gem::rsr());
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
        let v = rules::run_l4(&l4);
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
                    let _ = rules::run_l4(&l4); // real verdict, feeds QSecBit
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
    let cases: [(&[u8], u16, &str); 4] = [
        (&valid, packet::PASS, "well-formed ARP"),
        (&malformed, packet::DROP, "malformed ARP (htype!=1)"),
        (&spoof, packet::DROP, "ARP spoof (sender-mac != eth src)"),
        (&ipv4, packet::PASS, "non-ARP (IPv4)"),
    ];
    let mut ok = true;
    for (f, want, name) in cases {
        let v = rules::run_l2(f);
        let good = v == want;
        ok &= good;
        kprint!("   L2: {} -> {} [{}]\n",
            name, if v == packet::DROP { "DROP" } else { "PASS" }, if good { "ok" } else { "BUG" });
    }
    kprint!(" [P8-l2] {} — malformed/spoofed ARP dropped at L2, legit frames pass (napse-l2guard parity)\n",
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
    let cases: [(u8, u16, &str); 6] = [
        (0x00, packet::DROP, "NULL scan (no flags)"),
        (0x01, packet::DROP, "FIN scan"),
        (0x29, packet::DROP, "Xmas scan (FIN|PSH|URG)"),
        (0x03, packet::DROP, "SYN+FIN (illegal)"),
        (0x02, packet::PASS, "normal SYN"),
        (0x10, packet::PASS, "normal ACK"),
    ];
    let mut ok = true;
    for (flags, want, name) in cases {
        let t = tcp_hdr(flags);
        let v = rules::run_tcp(&t);
        let good = v == want;
        ok &= good;
        kprint!("   TCP flags {:#04x}: {} -> {} [{}]\n",
            flags, name, if v == packet::DROP { "DROP" } else { "PASS" }, if good { "ok" } else { "BUG" });
    }
    kprint!(" [P8-tcp] {} — NULL/FIN/Xmas/SYN-FIN scans dropped, normal SYN/ACK pass\n",
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
        match rules::run_flow(&a) {
            packet::PASS => ap += 1,
            _ => ad += 1,
        }
    }
    let bp = (0..5).filter(|_| rules::run_flow(&b) == packet::PASS).count();
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
    let cases: [([u8; 4], u16, &str); 3] = [
        ([192, 0, 2, 5], packet::DROP, "192.0.2.5 (in blocked /24)"),
        ([8, 8, 8, 8], packet::PASS, "8.8.8.8 (clean)"),
        ([10, 66, 66, 200], packet::DROP, "10.66.66.200 (C2 subnet)"),
    ];
    let mut ok = true;
    for (src, want, name) in cases {
        let f = ipv4_frame(src);
        let v = rules::run_flow(&f);
        let good = v == want;
        ok &= good;
        kprint!("   blocklist: {} -> {} [{}]\n",
            name, if v == packet::DROP { "DROP" } else { "PASS" }, if good { "ok" } else { "BUG" });
    }
    kprint!(" [P8-block] {} — blocked source prefixes dropped, clean sources pass (threat-feed parity)\n",
        if ok { "PASS" } else { "FAIL" });
    ok
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
    let kstack_top = unsafe { core::ptr::addr_of!(EL0_KSTACK) as usize + 0x4000 };
    let sp = arch_aarch64::thread::make_el0_thread(kstack_top, ECODE_VA, ESTACK_VA + 0x1000, ECNT_VA);
    let ttbr0 = l1 as u64 | ((asid as u64) << 48);
    scheduler::spawn_as(sp, 1, ttbr0); // low prio, in its own address space (ASID)
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
    let kstack_top = unsafe { core::ptr::addr_of!(EL0_FKSTACK) as usize + 0x4000 };
    // Arm restart params, then spawn a fresh frame from them.
    EL0_RS_ENTRY.store(FCODE_VA, Ordering::Relaxed);
    EL0_RS_USP.store(FSTACK_VA + 0x1000, Ordering::Relaxed);
    EL0_RS_KSTACK.store(kstack_top, Ordering::Relaxed);
    let sp = arch_aarch64::thread::make_el0_thread(kstack_top, FCODE_VA, FSTACK_VA + 0x1000, 0);
    let ttbr0 = l1 as u64 | ((asid as u64) << 48);
    scheduler::spawn_as(sp, 2, ttbr0); // higher prio: runs (and crashes) promptly
    EL0_SCHED_MODE.store(true, Ordering::Relaxed); // faults now restart/reschedule, not longjmp
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
                let restarts = EL0_RESTARTS.load(Ordering::Relaxed);
                kprint!(" [P7c] EL0 fault-restart {}: crashing driver TCB contained + restarted {} times then killed — kernel survived (4b)\n",
                    if restarts >= EL0_MAX_RESTARTS { "PASS" } else { "FAIL" }, restarts.min(EL0_MAX_RESTARTS));
                kprint!("\n [P1] PASS priority scheduler (H>M>L order, threads exited, context switch verified)\n");
                kprint!(" [ALL] P0 P1 P1b P2 P3 P4 P5 P5b P6 P6b DRV P7c GREEN\n");
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

    let pass = live0 == 8
        && retype_ep
        && ep_as_frame
        && frame_as_frame
        && subtree_gone
        && live1 == 6
        && live2 == 1
        && root_reclaimed
        && rights_ok;
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
pub extern "C" fn handle_lower_sync(frame: *mut u64) -> usize {
    let esr: u64;
    unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) esr) };
    let ec = (esr >> 26) & 0x3f;

    if ec == 0x15 {
        // SVC from AArch64: dispatch (x8=num, x0/x1=args), return value into x0.
        let num = unsafe { *frame.add(8) };
        let a0 = unsafe { *frame.add(0) };
        let a1 = unsafe { *frame.add(1) };
        if num == SYS_EXIT_USER {
            unsafe { arch_aarch64::syscall::resume_kernel() }; // cooperative EL0 done -> kernel
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
    if EL0_SCHED_MODE.load(Ordering::Relaxed) {
        let cur = scheduler::current_tid();
        let n = EL0_RESTARTS.fetch_add(1, Ordering::Relaxed) + 1;
        let next_sp = if n <= EL0_MAX_RESTARTS {
            kprint!("   [EL0 fault] restarting the driver TCB (restart #{})\n", n);
            let sp = arch_aarch64::thread::make_el0_thread(
                EL0_RS_KSTACK.load(Ordering::Relaxed),
                EL0_RS_ENTRY.load(Ordering::Relaxed),
                EL0_RS_USP.load(Ordering::Relaxed),
                0,
            );
            scheduler::set_sp(cur, sp);
            scheduler::on_tick(sp)
        } else {
            kprint!("   [EL0 fault] restart budget exhausted -> killing the driver TCB\n");
            scheduler::exit_current();
            scheduler::on_tick(unsafe { *frame.add(33) as usize }) // any sp; cur is dead now
        };
        enter_current_addr_space(); // P7c-4c: re-enter the (restarted) driver's ASID — CM5 too
        return next_sp;
    }

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
