//! heqk efiboot — UEFI entry for the arm64-cloud tier (OCI Ampere A1 first).
//!
//! Stage 1: `probe`. A read-only census of the guest the firmware hands us — the facts the
//! heqk cloud HAL has to be driven from (EL, ACPI tables, GIC, timer, console UART, ECAM,
//! PCI/virtio inventory, RAM) — checked against the device model MEASURED on the real OCI
//! A1 instance (2026-11-09). Prints `[OCI-A1-model] PASS|FAIL` and powers off through UEFI
//! ResetSystem (works identically under QEMU and on a real OCI instance; no semihosting).
//!
//! Nothing is written anywhere: no variables, no disk, no ExitBootServices.
#![no_std]
#![no_main]

mod acpi;
mod efi;
#[cfg(heqk_payload)]
mod loader;

use core::fmt::Write;
use efi::*;

macro_rules! out {
    ($c:expr, $($a:tt)*) => { let _ = write!($c, $($a)*); };
}

fn current_el() -> u64 {
    let el: u64;
    unsafe { core::arch::asm!("mrs {}, CurrentEL", out(reg) el) };
    (el >> 2) & 3
}

fn midr() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, midr_el1", out(reg) v) };
    v
}

/// Virtio device type from a PCI device id (modern 0x1040+N, transitional 0x1000..0x103f).
fn virtio_type(did: u16) -> Option<u16> {
    match did {
        0x1040..=0x107f => Some(did - 0x1040),
        0x1000 => Some(1),
        0x1001 => Some(2),
        0x1002 => Some(5),
        0x1003 => Some(3),
        0x1004 => Some(8),
        0x1005 => Some(4),
        0x1009 => Some(9),
        _ => None,
    }
}

fn virtio_name(t: u16) -> &'static str {
    match t {
        1 => "net",
        2 => "blk",
        3 => "console",
        4 => "rng",
        8 => "scsi",
        16 => "gpu",
        _ => "other",
    }
}

#[derive(Default)]
struct PciCensus {
    devices: usize,
    virtio_net: usize,
    virtio_scsi: usize,
    virtio_blk: usize,
    virtio_gpu: usize,
    virtio_legacy: usize,
    gpex_bridge: bool,
}

fn pci_scan(c: &mut ConOut, ecam: u64, b0: u8, b1: u8) -> PciCensus {
    let mut s = PciCensus::default();
    for bus in b0..=b1 {
        for dev in 0u64..32 {
            for func in 0u64..8 {
                let cfg = ecam + (((bus - b0) as u64) << 20) + (dev << 15) + (func << 12);
                let id = unsafe { core::ptr::read_volatile(cfg as *const u32) };
                let (vid, did) = (id as u16, (id >> 16) as u16);
                if vid == 0xffff {
                    if func == 0 {
                        break;
                    }
                    continue;
                }
                s.devices += 1;
                let class = unsafe { core::ptr::read_volatile((cfg + 8) as *const u32) } >> 8;
                let hdr = unsafe { core::ptr::read_volatile((cfg + 0x0e) as *const u8) };
                out!(c, "  pci {:02x}:{:02x}.{} {:04x}:{:04x} class {:06x}", bus, dev, func, vid, did, class);
                if vid == 0x1b36 && did == 0x0008 {
                    s.gpex_bridge = true;
                    out!(c, "  (QEMU PCIe host bridge)");
                }
                if vid == 0x1af4 {
                    if let Some(t) = virtio_type(did) {
                        out!(c, "  virtio-{} (type {}){}", virtio_name(t), t,
                            if did < 0x1040 { " TRANSITIONAL" } else { " modern" });
                        if did < 0x1040 {
                            s.virtio_legacy += 1;
                        }
                        match t {
                            1 => s.virtio_net += 1,
                            2 => s.virtio_blk += 1,
                            8 => s.virtio_scsi += 1,
                            16 => s.virtio_gpu += 1,
                            _ => {}
                        }
                    }
                }
                out!(c, "\n");
                if func == 0 && hdr & 0x80 == 0 {
                    break; // single-function device
                }
            }
        }
    }
    s
}

struct Check<'a> {
    c: &'a mut ConOut,
    fails: usize,
}

impl Check<'_> {
    fn expect(&mut self, ok: bool, what: &str) {
        out!(self.c, "  [{}] {}\n", if ok { "ok  " } else { "FAIL" }, what);
        if !ok {
            self.fails += 1;
        }
    }
}

static mut MMAP: [u8; 32768] = [0; 32768];

#[no_mangle]
pub extern "efiapi" fn efi_main(_image: Handle, st: *const SystemTable) -> Status {
    let st = unsafe { &*st };
    let bs = unsafe { &*st.boot_services };
    let rt = unsafe { &*st.runtime_services };
    let mut c = ConOut(st.con_out);
    // Disable the 5-minute firmware watchdog (we may sit at a prompt under a human).
    (bs.set_watchdog_timer)(0, 0, 0, core::ptr::null());

    out!(c, "\n=== heqk efiboot probe (arm64 cloud / OCI A1 model) ===\n");
    let el = current_el();
    let m = midr();
    out!(c, "CurrentEL       : EL{}\n", el);
    out!(c, "MIDR_EL1        : {:#x} (implementer {:#x} part {:#x})\n", m, (m >> 24) & 0xff, (m >> 4) & 0xfff);
    out!(c, "UEFI revision   : {}.{}\n", st.hdr.revision >> 16, (st.hdr.revision & 0xffff) / 10);

    // --- ACPI ---
    let mut rsdp: *const u8 = core::ptr::null();
    for i in 0..st.number_of_table_entries {
        let e = unsafe { &*st.configuration_table.add(i) };
        if e.guid == ACPI20_GUID {
            rsdp = e.table;
        }
    }
    let mut chk_fail_early = 0;
    let tables = if rsdp.is_null() {
        out!(c, "ACPI            : NO ACPI 2.0 RSDP in config table\n");
        chk_fail_early += 1;
        None
    } else {
        match acpi::tables(rsdp) {
            Ok(t) => Some(t),
            Err(e) => {
                out!(c, "ACPI            : parse error: {}\n", e);
                chk_fail_early += 1;
                None
            }
        }
    };

    let mut gic = acpi::Gic::default();
    let mut timer = None;
    let mut uart = None;
    let mut ecam = None;
    if let Some(t) = &tables {
        out!(c, "ACPI rev {} tables:", t.rsdp_rev);
        for s in t.list[..t.count].iter().flatten() {
            out!(c, " {}", core::str::from_utf8(&s.sig).unwrap_or("????"));
        }
        out!(c, "\n");
        if let Some(s) = t.find(b"APIC") {
            gic = acpi::madt(s);
        }
        timer = t.find(b"GTDT").and_then(acpi::gtdt);
        uart = t.find(b"SPCR").and_then(acpi::spcr);
        ecam = t.find(b"MCFG").and_then(acpi::mcfg);
    }
    out!(c, "GIC             : v{} GICD {:#x}  GICR x{}", gic.version, gic.gicd, gic.n_gicr);
    for i in 0..gic.n_gicr.min(4) {
        out!(c, " [{:#x}+{:#x}]", gic.gicr[i], gic.gicr_len[i]);
    }
    out!(c, "  GICC x{}  ITS x{}\n", gic.n_gicc, gic.n_its);
    if let Some((p, v)) = timer {
        out!(c, "Timer (GTDT)    : NS-EL1 phys GSIV {}  virt GSIV {}\n", p, v);
    }
    if let Some((ty, base)) = uart {
        let n = match ty { 3 => "ARM PL011", 0x0e => "ARM SBSA generic", _ => "other" };
        out!(c, "Console (SPCR)  : type {:#x} ({}) @ {:#x}\n", ty, n, base);
    }
    if let Some((base, seg, b0, b1)) = ecam {
        out!(c, "ECAM (MCFG)     : {:#x} seg {} bus {}..{}\n", base, seg, b0, b1);
    }

    // --- PCI / virtio ---
    let pci = match ecam {
        Some((base, _, b0, b1)) => pci_scan(&mut c, base, b0, b1),
        None => PciCensus::default(),
    };
    out!(c, "PCI             : {} functions; virtio net x{} scsi x{} blk x{} gpu x{}\n",
        pci.devices, pci.virtio_net, pci.virtio_scsi, pci.virtio_blk, pci.virtio_gpu);

    // --- RAM ---
    let (mut size, mut key, mut dsz, mut dver) = (core::mem::size_of_val(unsafe { &*core::ptr::addr_of!(MMAP) }), 0usize, 0usize, 0u32);
    let buf = core::ptr::addr_of_mut!(MMAP) as *mut u8;
    let st_mm = (bs.get_memory_map)(&mut size, buf, &mut key, &mut dsz, &mut dver);
    let (mut conv, mut usable, mut lowest) = (0u64, 0u64, u64::MAX);
    if st_mm == SUCCESS && dsz >= 40 {
        for i in 0..size / dsz {
            let d = unsafe { buf.add(i * dsz) };
            let ty = unsafe { core::ptr::read_unaligned(d as *const u32) };
            let pa = unsafe { core::ptr::read_unaligned(d.add(8) as *const u64) };
            let pages = unsafe { core::ptr::read_unaligned(d.add(24) as *const u64) };
            match ty {
                MT_CONVENTIONAL => {
                    conv += pages * 4096;
                    usable += pages * 4096;
                    lowest = lowest.min(pa);
                }
                MT_LOADER_CODE | MT_LOADER_DATA | MT_BOOT_CODE | MT_BOOT_DATA => usable += pages * 4096,
                _ => {}
            }
        }
        out!(c, "RAM             : {} MiB free now, {} MiB usable after ExitBootServices, lowest free {:#x}\n",
            conv >> 20, usable >> 20, lowest);
    } else {
        out!(c, "RAM             : GetMemoryMap failed {:#x}\n", st_mm);
    }

    // --- verdict vs the measured OCI A1 device model ---
    out!(c, "Checks vs measured OCI A1 (2026-11-09):\n");
    let mut k = Check { c: &mut c, fails: chk_fail_early };
    k.expect(el == 1, "guest runs at EL1 (no EL2 -> no nested virt / no /dev/kvm)");
    k.expect(((m >> 24) & 0xff) == 0x41 && ((m >> 4) & 0xfff) == 0xd0c, "CPU is Arm Neoverse-N1 (MIDR part 0xd0c)");
    if let Some(t) = &tables {
        for sig in [b"FACP", b"APIC", b"GTDT", b"MCFG", b"SPCR", b"IORT", b"PPTT", b"DBG2"] {
            let ok = t.find(sig).is_some();
            let mut msg = *b"ACPI table XXXX present";
            msg[11..15].copy_from_slice(sig);
            k.expect(ok, core::str::from_utf8(&msg).unwrap_or("ACPI table"));
        }
    }
    k.expect(gic.version == 3 && gic.n_gicr > 0, "GICv3 with redistributor range(s) (MADT)");
    k.expect(timer.map(|t| t.1 == 27).unwrap_or(false), "virtual timer is PPI 27 (GTDT)");
    k.expect(uart.map(|u| u.0 == 3).unwrap_or(false), "console is PL011 (SPCR)");
    k.expect(pci.gpex_bridge, "QEMU PCIe host bridge 1b36:0008");
    k.expect(pci.virtio_net >= 1, "virtio-net on PCI");
    k.expect(pci.virtio_scsi >= 1, "virtio-scsi on PCI (boot volume)");
    k.expect(pci.virtio_blk == 0, "no virtio-blk (OCI uses virtio-scsi)");
    k.expect(pci.virtio_legacy == 0, "virtio is modern-only 1.0 (OCI: 1af4:1041 / 1af4:1048)");
    let fails = k.fails;
    out!(c, "[OCI-A1-model] {} ({} failed)\n", if fails == 0 { "PASS" } else { "FAIL" }, fails);
    #[cfg(heqk_payload)]
    {
        let _ = loader::boot(_image, bs, &mut c);
    }
    out!(c, "powering off via UEFI ResetSystem\n");
    (rt.reset_system)(RESET_SHUTDOWN, SUCCESS, 0, core::ptr::null())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}
