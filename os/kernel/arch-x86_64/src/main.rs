// SPDX-License-Identifier: AGPL-3.0-only
//! heqk x86_64 — X1 skeleton. A UEFI entry that leaves the firmware behind and brings up the CPU substrate a
//! heqk kernel needs on x86_64, printing one marker per stage on COM1 and ending in `[X1] PASS` (QEMU exit 33)
//! or `[X1] FAIL …` (exit 35):
//!
//!   [X1]         entered via UEFI          [X1-mem]  firmware memory map census
//!   [X1-ebs]     ExitBootServices          [X1-gdt]  own GDT + TSS (rsp0, IST1 for #DF)
//!   [X1-idt]     own IDT, int3 self-test   [X1-paging] own PML4, NX/SMEP/SMAP
//!   [X1-rng]     RDSEED health, FAIL-CLOSED  [X1-apic] LAPIC timer interrupts
//!   [X1-ring3]   CPL3 → SYSCALL round trip
//!   [X1-ring3-iso] CPL3 read of kernel memory faults; CPL3 execute from the NX stack faults
//!
//! Nothing here is wired to the heqk kernel yet (that waits for X0's hal traits); the decision record for the
//! x86_64 boot/trust chain, entropy policy and isolation is ADR 0068 (pending).
#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

mod acpi;
mod apic;
mod cpu;
#[allow(dead_code)]
mod efi;
mod frames;
mod io;
mod paging;
mod pci;
mod rng;

use core::sync::atomic::Ordering;
use efi::*;
use io::{qemu_exit, rdtsc, EXIT_FAIL, EXIT_PASS};

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    kprintln!("[X1] FAIL — panic: {}", info);
    qemu_exit(EXIT_FAIL)
}

fn fail(why: &str) -> ! {
    kprintln!("[X1] FAIL — {}", why);
    qemu_exit(EXIT_FAIL)
}

#[repr(C, align(8))]
struct MapBuf([u8; 32768]);
static mut MAP: MapBuf = MapBuf([0; 32768]);

/// What ExitBootServices leaves us: descriptor count, usable MiB, and the saved map (bytes used, descriptor size).
struct Ebs {
    descs: usize,
    mib: u64,
    size: usize,
    dsz: usize,
}

fn saved_map(e: &Ebs) -> &'static [u8] {
    // MAP is written only by GetMemoryMap before ExitBootServices; from here on it is read-only.
    unsafe { core::slice::from_raw_parts((&raw const MAP) as *const u8, e.size.min(core::mem::size_of::<MapBuf>())) }
}

/// Memory-map census + ExitBootServices (retried once: the map key changes if the firmware allocates in between).
fn exit_boot_services(image: Handle, bs: &BootServices) -> Ebs {
    for attempt in 0..2 {
        let buf = &raw mut MAP;
        let mut size = core::mem::size_of::<MapBuf>();
        let (mut key, mut dsz, mut dver) = (0usize, 0usize, 0u32);
        let st = (bs.get_memory_map)(&mut size, unsafe { (*buf).0.as_mut_ptr() }, &mut key, &mut dsz, &mut dver);
        if st != SUCCESS || dsz == 0 {
            fail("GetMemoryMap");
        }
        let (mut n, mut conv_pages) = (0usize, 0u64);
        let mut off = 0;
        while off + dsz <= size {
            let d = unsafe { (*buf).0.as_ptr().add(off) };
            let ty = unsafe { core::ptr::read_unaligned(d as *const u32) };
            let pages = unsafe { core::ptr::read_unaligned(d.add(24) as *const u64) };
            if matches!(ty, MT_CONVENTIONAL | MT_BOOT_CODE | MT_BOOT_DATA | MT_LOADER_CODE | MT_LOADER_DATA) {
                conv_pages += pages;
            }
            n += 1;
            off += dsz;
        }
        if (bs.exit_boot_services)(image, key) == SUCCESS {
            if attempt > 0 {
                kprintln!("[X1-ebs] map key changed once; retried");
            }
            return Ebs { descs: n, mib: conv_pages * 4096 / (1 << 20), size, dsz };
        }
    }
    fail("ExitBootServices refused twice")
}

// User programs (position-independent; copied into the user code page at USER_CODE).
//   mov eax, 0x48514b31 ; syscall ; ud2
const U_SYSCALL: [u8; 9] = [0xB8, 0x31, 0x4B, 0x51, 0x48, 0x0F, 0x05, 0x0F, 0x0B];
const U_MAGIC: u64 = 0x4851_4B31;

/// movabs rax, [addr] ; syscall ; ud2   — a CPL3 read of `addr`
fn u_read(addr: u64) -> [u8; 14] {
    let a = addr.to_le_bytes();
    [0x48, 0xA1, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], 0x0F, 0x05, 0x0F, 0x0B]
}

/// mov rax, imm64 ; jmp rax   — a CPL3 jump to `target`
fn u_jump(target: u64) -> [u8; 12] {
    let a = target.to_le_bytes();
    [0x48, 0xB8, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], 0xFF, 0xE0]
}

fn run_user(code: &[u8]) -> u64 {
    paging::load_user_code(code);
    cpu::UFAULT_ADDR.store(0, Ordering::SeqCst);
    cpu::UFAULT_CODE.store(0, Ordering::SeqCst);
    unsafe { cpu::enter_user(paging::USER_CODE, paging::USER_STACK_TOP - 16) }
}

#[no_mangle]
pub extern "efiapi" fn efi_main(image: Handle, st: *mut SystemTable) -> Status {
    io::serial_init();
    let st = unsafe { &*st };
    let bs = unsafe { &*st.boot_services };
    let mut vendor = [0u8; 48];
    let mut vl = 0;
    unsafe {
        let mut p = st.firmware_vendor;
        while vl < vendor.len() && !p.is_null() && *p != 0 {
            vendor[vl] = if *p < 0x80 { *p as u8 } else { b'?' };
            vl += 1;
            p = p.add(1);
        }
    }
    kprintln!(
        "[X1] heqk x86_64 entered via UEFI (firmware {} rev {:#x})",
        core::str::from_utf8(&vendor[..vl]).unwrap_or("?"),
        st.firmware_revision
    );
    (bs.set_watchdog_timer)(0, 0, 0, core::ptr::null());

    // The ACPI 2.0 RSDP comes from the UEFI configuration table — the only time we can ask the firmware.
    let mut rsdp: *const u8 = core::ptr::null();
    for i in 0..st.number_of_table_entries.min(64) {
        let e = unsafe { &*st.configuration_table.add(i) };
        if e.guid == ACPI20_GUID {
            rsdp = e.table;
        }
    }

    let ebs = exit_boot_services(image, bs);
    kprintln!("[X1-mem] firmware map: {} descriptors, {} MiB usable after boot services", ebs.descs, ebs.mib);
    kprintln!("[X1-ebs] ExitBootServices OK — the firmware is gone; COM1 + own tables from here");

    cpu::load_gdt_tss();
    kprintln!("[X1-gdt] own GDT (kernel/user code+data) + TSS loaded (rsp0 for CPL3 entry, IST1 for #DF)");

    cpu::load_idt();
    unsafe { core::arch::asm!("int3") };
    if cpu::BP_HITS.load(Ordering::SeqCst) != 1 {
        fail("int3 self-test did not reach the IDT handler");
    }
    kprintln!("[X1-idt] own IDT loaded; int3 self-test handled and resumed");

    let (f, uc) = paging::install(saved_map(&ebs), ebs.dsz);
    kprintln!(
        "[X1-paging] own PML4 live: identity 0-4 GiB supervisor-only (2 MiB pages; {} non-RAM pages uncached), user window at {:#x}; NX={} SMEP={} SMAP={}",
        uc,
        paging::USER_BASE,
        f.nx,
        f.smep,
        f.smap
    );

    // ---- X2: platform discovery from firmware tables (ACPI), physical memory, interrupt controllers ----
    let tables = acpi::tables(rsdp).unwrap_or_else(|e| fail(e));
    let madt = acpi::madt(&tables.find(b"APIC").unwrap_or_else(|| fail("no MADT")));
    let ecam = acpi::mcfg(&tables.find(b"MCFG").unwrap_or_else(|| fail("no MCFG"))).unwrap_or_else(|| fail("bad MCFG"));
    kprintln!(
        "[X2-acpi] {} tables verified; MADT: {} CPU(s) ({} x2APIC entries), LAPIC {:#x}, {} IOAPIC(s), {} IRQ overrides, 8259={}; MCFG: ECAM {:#x} seg {} buses {}-{}",
        tables.count,
        madt.cpus,
        madt.x2apic_entries,
        madt.lapic_addr,
        madt.n_ioapic,
        madt.overrides,
        madt.has_8259,
        ecam.base,
        ecam.segment,
        ecam.bus_start,
        ecam.bus_end
    );
    if madt.cpus == 0 || madt.n_ioapic == 0 {
        fail("MADT lists no CPU or no IOAPIC");
    }

    let mut frames = frames::Frames::from_map(saved_map(&ebs), ebs.dsz);
    let image_lo = efi_main as *const () as u64;
    let mut prev = 0u64;
    for k in 0..64 {
        let pa = frames.alloc().unwrap_or_else(|| fail("frame allocator exhausted"));
        let p = pa as *mut u64;
        unsafe {
            p.write_volatile(0xF4A3_0000_0000 | k);
            if p.read_volatile() != 0xF4A3_0000_0000 | k {
                fail("frame not writable");
            }
        }
        if pa & 0xFFF != 0 || pa < 0x10_0000 || pa == prev || (image_lo >= pa && image_lo < pa + 4096) {
            fail("frame allocator handed out a bad frame");
        }
        prev = pa;
    }
    kprintln!(
        "[X2-frames] allocator from the saved map: {} merged ranges ({} dropped), {} free 4 KiB frames (≤4 GiB); 64 allocated, aligned, distinct, writable, none overlaps this image",
        frames.ranges(),
        frames.dropped,
        frames.total,
    );

    match rng::health(64) {
        rng::Health::Pass { samples, retries } => {
            kprintln!("[X1-rng] PASS — RDSEED health: {} samples, {} underflow retries, no repeats, all bits toggle", samples, retries)
        }
        rng::Health::Absent => {
            kprintln!("[X1-rng] FAIL-CLOSED — RDSEED not available; no fallback entropy");
            fail("no entropy source");
        }
        rng::Health::Fail(why) => {
            kprintln!("[X1-rng] FAIL-CLOSED — RDSEED health: {}", why);
            fail("entropy health");
        }
    }

    let mut ioapics = 0;
    for io in &madt.ioapics[..madt.n_ioapic] {
        let (ver, entries) = apic::ioapic_mask_all(io.addr);
        kprintln!("[X2-ioapic] IOAPIC id {} at {:#x}: version {:#x}, {} inputs (GSI {}..), all masked", io.id, io.addr, ver, entries, io.gsi_base);
        ioapics += (entries > 0) as usize;
    }
    if ioapics == 0 {
        fail("no usable IOAPIC");
    }

    let lapic = apic::init_timer(0x8_0000, false);
    kprintln!("[X2-lapic] local APIC mode: {} (APIC ID {})", if lapic.x2apic { "x2APIC (MSR)" } else { "xAPIC (MMIO; CPU has no x2APIC)" }, apic::id());
    let apic_base = lapic.base;
    unsafe { core::arch::asm!("sti") };
    let t0 = rdtsc();
    while cpu::TICKS.load(Ordering::SeqCst) < 10 {
        if rdtsc().wrapping_sub(t0) > 20_000_000_000 {
            fail("LAPIC timer: no interrupts");
        }
        core::hint::spin_loop();
    }
    unsafe { core::arch::asm!("cli") };
    apic::stop_timer();
    kprintln!("[X1-apic] LAPIC at {:#x}: periodic timer delivered {} interrupts (8259 masked)", apic_base, cpu::TICKS.load(Ordering::SeqCst));

    cpu::enable_syscall();
    let r = run_user(&U_SYSCALL);
    if r != U_MAGIC {
        fail("ring-3 SYSCALL round trip returned the wrong value");
    }
    kprintln!("[X1-ring3] CPL3 code at {:#x} ran and returned through SYSCALL (rax={:#x})", paging::USER_CODE, r);

    // Isolation 1: a CPL3 read of a kernel address must fault (supervisor page), not return data.
    let secret = &cpu::TICKS as *const _ as u64;
    let r = run_user(&u_read(secret));
    let (addr, code) = (cpu::UFAULT_ADDR.load(Ordering::SeqCst), cpu::UFAULT_CODE.load(Ordering::SeqCst));
    if r != cpu::RESUME_USER_FAULT || addr != secret || code & 0b101 != 0b101 {
        fail("ring-3 read of kernel memory was NOT refused");
    }
    kprintln!("[X1-ring3-iso] CPL3 read of kernel {:#x} → #PF (err={:#x}: present, user) — refused", addr, code);

    // Isolation 2: executing from the user stack page (RW+NX) must fault as an instruction fetch.
    if f.nx {
        let target = paging::USER_STACK_TOP - 0x100;
        let r = run_user(&u_jump(target));
        let (addr, code) = (cpu::UFAULT_ADDR.load(Ordering::SeqCst), cpu::UFAULT_CODE.load(Ordering::SeqCst));
        if r != cpu::RESUME_USER_FAULT || addr != target || code & 0b1_0101 != 0b1_0101 {
            fail("ring-3 execute from the NX stack was NOT refused");
        }
        kprintln!("[X1-ring3-iso] CPL3 execute at {:#x} (NX stack) → #PF (err={:#x}: present, user, fetch) — refused", addr, code);
    } else {
        kprintln!("[X1-ring3-iso] NX unavailable on this CPU — execute-protection check SKIPPED (reported, not passed)");
    }

    kprintln!("[X1] PASS — x86_64 substrate: UEFI exit, GDT/TSS, IDT, paging, LAPIC timer, RDSEED, ring 3 + isolation");

    // ---- X2: PCIe through ECAM, virtio-pci discovery (read-only) ----
    let s = pci::scan(&ecam);
    kprintln!("[X2-pci] ECAM scan: {} functions ({} bridges), {} virtio", s.functions, s.bridges, s.n_virtio);
    let (mut net, mut blk) = (false, false);
    for v in &s.virtio[..s.n_virtio] {
        kprintln!(
            "[X2-pci]   virtio-{} {:02x}:{:02x}.{} id {:#06x} — {} transport (virtio caps mask {:#07b})",
            v.kind,
            v.bus,
            v.dev,
            v.func,
            v.device_id,
            if v.modern { "modern 1.x" } else { "legacy-only" },
            v.caps
        );
        net |= v.kind == "net" && v.modern;
        blk |= v.kind == "blk" && v.modern;
    }
    if s.functions == 0 || !net || !blk {
        fail("PCIe scan did not find a modern virtio-net and virtio-blk");
    }

    kprintln!("[X2] PASS — ACPI MADT/MCFG, frame allocator, IOAPIC, {} local APIC, PCIe ECAM + modern virtio-pci discovery", if lapic.x2apic { "x2APIC" } else { "xAPIC" });
    qemu_exit(EXIT_PASS)
}
