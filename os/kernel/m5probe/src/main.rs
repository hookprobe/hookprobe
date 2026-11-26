// SPDX-License-Identifier: AGPL-3.0-only
//! m5probe — NanoPi M5 (RK3576) bench bring-up probe. NOT heqk and never in a product image.
//!
//! U-Boot `booti`s it (netboot, runbook §7). It answers the day-one questions about the boot hand-off
//! that heqk's port depends on, then offers the recovery paths as single-key tests:
//!
//!   report: exception level, MPIDR/MIDR, CNTFRQ, image base, FDT (model, /memory, /reserved-memory,
//!           /cpus, /psci via the ONE boot-abi reader), PSCI_VERSION over the FDT's conduit, and on the
//!           RK3576 the reboot-mode register (PMU0_GRF+0x40) left by the previous boot.
//!   keys:   r PSCI SYSTEM_RESET · o PSCI SYSTEM_OFF · m reboot-to-maskrom (0xEF08A53C → 0x2602_4040, reset)
//!           w DW-WDT test (arm ~3 s, stop kicking) · l SYS LED toggle · h halt
//!
//! The platform (console, LED, watchdog, boot-mode register) is chosen from the FDT root `compatible`,
//! a bench-tool table, not product code. QEMU `virt` is supported so the whole netboot chain can be
//! rehearsed on the host (tools/diagnostics/m5-qemu-rehearsal.sh).
//!
//! Every hardware wait is bounded. Output lines start with `[m5probe]` (markers for m5-metal-loop.sh).
#![no_std]
#![no_main]

use boot_abi::fdt::{self, Conduit, EnableMethod};
use core::arch::{asm, global_asm};
use core::fmt::Write;
use core::ptr::{read_volatile, write_volatile};

global_asm!(include_str!("entry.s"));

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------- platform table (bench only)

#[derive(Clone, Copy)]
enum Uart {
    /// ARM PL011 (QEMU virt).
    Pl011(usize),
    /// Synopsys DW-APB 16550-class, reg-shift 2, 32-bit access (RK3576 UART0, left configured by U-Boot).
    DwApb(usize),
}

#[derive(Clone, Copy)]
struct Platform {
    name: &'static str,
    uart: Uart,
    /// Rockchip GPIO v2 bank base + pin index (0..31) of the SYS LED.
    led: Option<(usize, u32)>,
    /// Synopsys DW watchdog base.
    wdt: Option<usize>,
    /// Rockchip reboot-mode register (PMU0_GRF + 0x40).
    bootmode: Option<usize>,
}

const PLATFORMS: &[(&str, Platform)] = &[
    (
        "rockchip,rk3576",
        Platform {
            name: "RK3576",
            uart: Uart::DwApb(0x2ad4_0000),
            led: Some((0x2ae2_0000, 11)), // GPIO2_B3 = SYS LED (vendor DT; mainline gpio-leds)
            wdt: Some(0x2ace_0000),
            bootmode: Some(0x2602_4040),
        },
    ),
    (
        "linux,dummy-virt",
        Platform { name: "QEMU virt", uart: Uart::Pl011(0x0900_0000), led: None, wdt: None, bootmode: None },
    ),
];

const MASKROM_MAGIC: u32 = 0xEF08_A53C;

// ---------------------------------------------------------------- MMIO + console

fn r32(a: usize) -> u32 {
    // SAFETY: bench probe on a known board; addresses come from the platform table above.
    unsafe { read_volatile(a as *const u32) }
}
fn w32(a: usize, v: u32) {
    // SAFETY: as r32.
    unsafe { write_volatile(a as *mut u32, v) }
}

struct Con(Uart);

impl Con {
    fn putc(&self, c: u8) {
        let mut spins = 0u32;
        match self.0 {
            Uart::Pl011(b) => {
                while r32(b + 0x18) & (1 << 5) != 0 && spins < 1_000_000 {
                    spins += 1;
                }
                w32(b, c as u32);
            }
            Uart::DwApb(b) => {
                while r32(b + 0x14) & (1 << 5) == 0 && spins < 1_000_000 {
                    spins += 1;
                }
                w32(b, c as u32);
            }
        }
    }
    fn getc(&self) -> Option<u8> {
        match self.0 {
            Uart::Pl011(b) => (r32(b + 0x18) & (1 << 4) == 0).then(|| r32(b) as u8),
            Uart::DwApb(b) => (r32(b + 0x14) & 1 != 0).then(|| r32(b) as u8),
        }
    }
}

impl Write for Con {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.putc(b'\r');
            }
            self.putc(b);
        }
        Ok(())
    }
}

static mut CON: Option<Uart> = None;

fn con() -> Option<Con> {
    // SAFETY: single core, written once before any reader.
    unsafe { (*core::ptr::addr_of!(CON)).map(Con) }
}

macro_rules! say {
    ($($t:tt)*) => {{
        if let Some(mut c) = con() {
            let _ = write!(c, "[m5probe] ");
            let _ = writeln!(c, $($t)*);
        }
    }};
}

// ---------------------------------------------------------------- CPU helpers

fn current_el() -> u64 {
    let v: u64;
    // SAFETY: read-only system register.
    unsafe { asm!("mrs {}, CurrentEL", out(reg) v) };
    (v >> 2) & 3
}
fn mpidr() -> u64 {
    let v: u64;
    // SAFETY: read-only system register.
    unsafe { asm!("mrs {}, mpidr_el1", out(reg) v) };
    v
}
fn midr() -> u64 {
    let v: u64;
    // SAFETY: read-only system register.
    unsafe { asm!("mrs {}, midr_el1", out(reg) v) };
    v
}
fn cntfrq() -> u64 {
    let v: u64;
    // SAFETY: read-only system register.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) v) };
    v
}
fn cntpct() -> u64 {
    let v: u64;
    // SAFETY: read-only counter.
    unsafe { asm!("isb", "mrs {}, cntpct_el0", out(reg) v) };
    v
}

fn core_name(midr: u64) -> &'static str {
    match (midr >> 24 & 0xff, midr >> 4 & 0xfff) {
        (0x41, 0xd03) => "Cortex-A53",
        (0x41, 0xd08) => "Cortex-A72",
        (0x41, 0xd0b) => "Cortex-A76",
        (0x41, 0xd05) => "Cortex-A55",
        _ => "unknown",
    }
}

/// SMCCC fast call over the FDT's conduit. `None` when no usable conduit (e.g. HVC while at EL2).
fn smccc(conduit: Conduit, fid: u32, a1: u64) -> Option<i64> {
    let mut x0 = fid as u64;
    match conduit {
        // SAFETY: SMCCC call; the callee may clobber x0-x17 (clobber_abi covers the caller-saved set).
        Conduit::Smc => unsafe { asm!("smc #0", inout("x0") x0, inout("x1") a1 => _, clobber_abi("C")) },
        Conduit::Hvc if current_el() < 2 => unsafe {
            asm!("hvc #0", inout("x0") x0, inout("x1") a1 => _, clobber_abi("C"))
        },
        _ => return None,
    }
    Some(x0 as i64)
}

const PSCI_VERSION: u32 = 0x8400_0000;
const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;

fn wait_ms(ms: u64) {
    let f = cntfrq().max(1);
    let end = cntpct().wrapping_add(f / 1000 * ms);
    while cntpct() < end {
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------- FDT root properties

fn be32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// A property of the ROOT node (bounded walk over the root's own properties only).
fn root_prop<'a>(blob: &'a [u8], want: &str) -> Option<&'a [u8]> {
    let off_struct = be32(blob, 8)? as usize;
    let off_strings = be32(blob, 12)? as usize;
    let size_struct = be32(blob, 36)? as usize;
    let end = off_struct.checked_add(size_struct)?.min(blob.len());
    let mut p = off_struct;
    if be32(blob, p)? != 1 {
        return None; // first token must be BEGIN_NODE (root)
    }
    p += 4;
    while p < end && *blob.get(p)? != 0 {
        p += 1; // root name (empty)
    }
    p = (p + 4) & !3;
    for _ in 0..512 {
        match be32(blob, p)? {
            3 => {
                let len = be32(blob, p + 4)? as usize;
                let nameoff = be32(blob, p + 8)? as usize;
                let val = blob.get(p + 12..p.checked_add(12 + len)?)?;
                let ns = off_strings.checked_add(nameoff)?;
                let name = blob.get(ns..)?;
                let nlen = name.iter().position(|&c| c == 0)?;
                if &name[..nlen] == want.as_bytes() {
                    return Some(val);
                }
                p = (p + 12 + len + 3) & !3;
            }
            4 => p += 4,       // NOP
            _ => return None,  // BEGIN_NODE of the first child / END: root properties are done
        }
        if p >= end {
            return None;
        }
    }
    None
}

fn strlist_has(v: &[u8], s: &str) -> bool {
    v.split(|&c| c == 0).any(|x| x == s.as_bytes())
}

fn first_str(v: &[u8]) -> &str {
    let n = v.iter().position(|&c| c == 0).unwrap_or(v.len());
    core::str::from_utf8(&v[..n]).unwrap_or("?")
}

// ---------------------------------------------------------------- probe

#[no_mangle]
extern "C" fn probe_main(fdt_pa: usize, base: usize) -> ! {
    // The FDT header gives its own size; refuse anything implausible before building a slice.
    let total = if fdt_pa != 0 && fdt_pa.is_multiple_of(8) {
        // SAFETY: booti passes a valid FDT PA in x0; only the 8-byte header is read here.
        let hdr = unsafe { core::slice::from_raw_parts(fdt_pa as *const u8, 8) };
        if be32(hdr, 0) == Some(fdt::FDT_MAGIC) { be32(hdr, 4).unwrap_or(0) as usize } else { 0 }
    } else {
        0
    };
    let blob: &[u8] = if (40..=fdt::MAX_BLOB).contains(&total) {
        // SAFETY: header-declared size, bounded by MAX_BLOB.
        unsafe { core::slice::from_raw_parts(fdt_pa as *const u8, total) }
    } else {
        &[]
    };

    let compat = root_prop(blob, "compatible").unwrap_or(&[]);
    let plat = PLATFORMS.iter().find(|(c, _)| strlist_has(compat, c)).map(|(_, p)| *p);
    let Some(plat) = plat else {
        // No console we know for this board: nothing to say, nothing safe to poke.
        loop {
            // SAFETY: idle.
            unsafe { asm!("wfe") };
        }
    };
    // SAFETY: single core; set once before any reader.
    unsafe { CON = Some(plat.uart) };

    let el = current_el();
    say!("heqk bench bring-up probe m5probe v{VERSION}");
    say!("platform={} model=\"{}\" compatible=\"{}\"", plat.name,
        root_prop(blob, "model").map(first_str).unwrap_or("?"), first_str(compat));
    say!("EL{} MPIDR={:#x} MIDR={:#x} ({}) CNTFRQ={} Hz", el, mpidr(), midr(), core_name(midr()), cntfrq());
    say!("image base={:#x} fdt={:#x} fdt-size={}", base, fdt_pa, total);

    let mut ok = el == 2;
    let mut conduit = Conduit::None;
    match fdt::parse(blob) {
        Ok(inv) => {
            let mut ram = 0u64;
            for m in &inv.mem[..inv.nmem] {
                say!("mem    base={:#011x} size={:#011x} ({} MiB)", m.base, m.size, m.size >> 20);
                ram += m.size;
            }
            for r in &inv.resv[..inv.nresv] {
                say!("resv   base={:#011x} size={:#x}", r.base, r.size);
            }
            let psci_cpus = inv.cpus[..inv.ncpus].iter().filter(|c| c.method == EnableMethod::Psci).count();
            say!("RAM total {} MiB in {} range(s); cpus={} (psci {}); psci present={} conduit={:?} v0.2+={}{}",
                ram >> 20, inv.nmem, inv.ncpus, psci_cpus, inv.psci.present, inv.psci.method, inv.psci.v02_plus,
                if inv.truncated { " [TRUNCATED]" } else { "" });
            ok &= inv.nmem > 0 && ram > 0;
            conduit = inv.psci.method;
            // The image must not overlap a reserved range (BL31 / SCMI shmem / ramoops live below 0x4020_0000).
            for r in &inv.resv[..inv.nresv] {
                let (b, e) = (base as u64, base as u64 + 0x10_0000);
                if b < r.base + r.size && r.base < e {
                    say!("WARN image overlaps reserved {:#x}+{:#x}", r.base, r.size);
                    ok = false;
                }
            }
        }
        Err(e) => {
            say!("FDT parse error {:?} (size {})", e, total);
            ok = false;
        }
    }
    match smccc(conduit, PSCI_VERSION, 0) {
        Some(v) if v >= 0 => say!("PSCI_VERSION={}.{} via {:?}", (v >> 16) & 0xffff, v & 0xffff, conduit),
        Some(v) => {
            say!("PSCI_VERSION error {v}");
            ok = false;
        }
        None => {
            say!("PSCI not callable (conduit {:?} at EL{el})", conduit);
            ok = false;
        }
    }
    if let Some(bm) = plat.bootmode {
        let v = r32(bm);
        let what = match v {
            MASKROM_MAGIC => "maskrom request (not consumed?)",
            0x5242_C300 => "normal",
            0x5242_C301 => "loader",
            0x5242_C303 => "recovery",
            0x5242_C307 => "panic",
            0x5242_C308 => "watchdog",
            0x5242_C309 => "fastboot",
            0 => "clear",
            _ => "other",
        };
        say!("reboot-mode reg {:#x} = {:#010x} ({})", bm, v, what);
    }
    say!("RESULT: {}", if ok { "PASS" } else { "FAIL" });
    say!("keys: r=PSCI reset  o=PSCI off  m=maskrom+reset  w=watchdog test  l=LED  h=halt");

    let c = Con(plat.uart);
    let mut led_on = false;
    let mut next_blink = 0u64;
    loop {
        // Heartbeat on the SYS LED at ~1 Hz while idle.
        if let Some((gb, pin)) = plat.led {
            let now = cntpct();
            if now >= next_blink {
                led_on = !led_on;
                gpio_out(gb, pin, led_on);
                next_blink = now + cntfrq() / 2;
            }
        }
        let Some(k) = c.getc() else { continue };
        match k {
            b'r' => {
                say!("PSCI SYSTEM_RESET");
                wait_ms(20);
                let r = smccc(conduit, PSCI_SYSTEM_RESET, 0);
                say!("SYSTEM_RESET returned {:?}", r);
            }
            b'o' => {
                say!("PSCI SYSTEM_OFF (power back only via relay cycle or RTC alarm)");
                wait_ms(20);
                let r = smccc(conduit, PSCI_SYSTEM_OFF, 0);
                say!("SYSTEM_OFF returned {:?}", r);
            }
            b'm' => match plat.bootmode {
                Some(bm) => {
                    w32(bm, MASKROM_MAGIC);
                    say!("wrote {:#x} to {:#x} (read back {:#x}); PSCI SYSTEM_RESET -> expect USB 2207:350e",
                        MASKROM_MAGIC, bm, r32(bm));
                    wait_ms(20);
                    let r = smccc(conduit, PSCI_SYSTEM_RESET, 0);
                    say!("SYSTEM_RESET returned {:?}", r);
                }
                None => say!("no reboot-mode register on this platform"),
            },
            b'w' => match plat.wdt {
                Some(w) => wdt_test(w),
                None => say!("no watchdog on this platform"),
            },
            b'l' => match plat.led {
                Some((gb, pin)) => {
                    led_on = !led_on;
                    gpio_out(gb, pin, led_on);
                    say!("SYS LED {}", if led_on { "on" } else { "off" });
                }
                None => say!("no LED on this platform"),
            },
            b'h' => {
                say!("halt");
                loop {
                    // SAFETY: idle.
                    unsafe { asm!("wfe") };
                }
            }
            _ => {}
        }
    }
}

/// Rockchip GPIO v2: SWPORT_DR_L/H at 0x00/0x04, SWPORT_DDR_L/H at 0x08/0x0C, upper 16 bits = write mask.
fn gpio_out(bank: usize, pin: u32, on: bool) {
    let (dr, ddr, bit) = if pin < 16 { (bank, bank + 0x08, pin) } else { (bank + 0x04, bank + 0x0c, pin - 16) };
    w32(ddr, (1 << (bit + 16)) | (1 << bit));
    w32(dr, (1 << (bit + 16)) | ((on as u32) << bit));
}

/// Synopsys DW watchdog: TORR=0xA (2^26 cycles ≈ 2.8 s at 24 MHz), CR enable with RMOD=0 (system reset),
/// one restart kick, then stop kicking. Proves (or disproves) that tclk runs and the reset is routed.
fn wdt_test(w: usize) {
    say!("WDT before: CR={:#x} TORR={:#x} CCVR={:#x}", r32(w), r32(w + 4), r32(w + 8));
    w32(w + 0x4, 0xA);
    w32(w, 0x1);
    w32(w + 0xc, 0x76);
    let c0 = r32(w + 8);
    wait_ms(100);
    let c1 = r32(w + 8);
    say!("WDT armed: CR={:#x} CCVR {:#x} -> {:#x} ({}); not kicking", r32(w), c0, c1,
        if c1 != c0 { "counting" } else { "NOT counting: tclk gated?" });
    for s in 1..=10u32 {
        wait_ms(1000);
        say!("WDT still alive after {s} s");
    }
    say!("WDT FAIL: no reset within 10 s (clock gated or reset not routed to the CRU/PMU)");
}

#[no_mangle]
extern "C" fn m5p_exception(slot: u64) -> ! {
    let el = current_el();
    let (esr, elr, far): (u64, u64, u64);
    // SAFETY: reads of the syndrome registers for the current EL.
    unsafe {
        if el == 2 {
            asm!("mrs {}, esr_el2", "mrs {}, elr_el2", "mrs {}, far_el2", out(reg) esr, out(reg) elr, out(reg) far);
        } else {
            asm!("mrs {}, esr_el1", "mrs {}, elr_el1", "mrs {}, far_el1", out(reg) esr, out(reg) elr, out(reg) far);
        }
    }
    say!("EXCEPTION slot={slot} EL{el} ESR={esr:#x} (EC={:#x}) ELR={elr:#x} FAR={far:#x}", esr >> 26);
    say!("RESULT: FAIL");
    loop {
        // SAFETY: idle.
        unsafe { asm!("wfe") };
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("PANIC {info}");
    say!("RESULT: FAIL");
    loop {
        // SAFETY: idle.
        unsafe { asm!("wfe") };
    }
}
