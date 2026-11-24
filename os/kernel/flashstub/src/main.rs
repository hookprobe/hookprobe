// SPDX-License-Identifier: AGPL-3.0-only
//! The heqk flash stub image (ADR 0070): an HBoot payload, built only with `--features flashstub`.
//!
//! Boot: the BCM2712 firmware loads boot.img (rpiboot from the browser) -> HBoot verifies THIS payload with the
//! hybrid verifier and launches it at EL1 (arch-aarch64 boot_hboot.s -> `kmain`). Then:
//!  1. check the BootInfo handoff; disarm HBoot's trial watchdog (`hvc #1`: the stub is not an A/B trial, and a
//!     flash takes minutes);
//!  2. MMU + caches on (mmu_cm5, the kernel's own map: RAM Normal, peripherals Device);
//!  3. find HBoot's self-measurement (PCR0 event EV_HBOOT_SELF) — the reference for the HBoot-prefix rule;
//!  4. probe the eMMC (read-only bring-up; the write path is the driver's `flashstub` gate, opened by the server
//!     only after a positive verdict);
//!  5. print GSNPSID / GHWCFG1-4 of the OTG core BEFORE writing any of its registers, refuse a non-DWC2 ID;
//!  6. bring the core up in device mode and serve HQFL forever (polled).
//! No OTP or RPMB access anywhere: the board serial is not read (the USB serial string is derived from the build
//! hash), the eMMC driver has no CMD6 / CMD38 / CMD42 and no partition switch.
#![no_std]
#![no_main]

use arch_aarch64 as arch;
use arch::emmc::Emmc;
use boot_abi::{BootInfo, MeasureEvent, MeasureLog, BOOTINFO_MAGIC, BOOT_FLAG_TRIAL_WDOG, EV_HBOOT_SELF, MEASURE_LOG_ADDR, MEASURE_LOG_MAGIC, PCR_FIRMWARE};
use core::ptr::{read_volatile, write_volatile};
use flashstub::dwc2::{Dwc2, Event, InitErr, Regs};
use flashstub::image::{MeasuredHboot, IMG_MAX};
use flashstub::server::{Config, Medium, Server};
use hal::BlockDev;

/// BCM2712 USB 2.0 OTG core (DT `usb@480000`, compatible brcm,bcm2835-usb; ADR 0070 D6).
const USB_BASE: usize = 0x10_0048_0000;
/// Bulk OUT frame buffer: the largest HQFL frame rounded up to whole 512-byte packets.
const OUT_BUF: usize = flashstub::proto::MAX_FRAME.div_ceil(512) * 512;

/// The compiled-in anti-rollback floor (ADR 0070 D3.1). The release build sets HEQK_FLASHSTUB_SVN_FLOOR; the
/// default is HBoot's COMPILE_FLOOR (1).
const SVN_FLOOR: u64 = match option_env!("HEQK_FLASHSTUB_SVN_FLOOR") {
    Some(s) => parse_u64(s),
    None => 1,
};
const fn parse_u64(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut v = 0u64;
    let mut i = 0;
    assert!(!b.is_empty(), "HEQK_FLASHSTUB_SVN_FLOOR is empty");
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "HEQK_FLASHSTUB_SVN_FLOOR is not a number");
        v = v * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    v
}

macro_rules! kprint { ($($t:tt)*) => { arch::_print(format_args!($($t)*)) }; }

fn log(a: core::fmt::Arguments) {
    arch::_print(a);
}

/// The OTG core's MMIO window (Device-nGnRnE through mmu_cm5).
struct Mmio;
impl Regs for Mmio {
    fn read(&mut self, off: usize) -> u32 {
        // SAFETY: an aligned 32-bit register inside the 64 KiB window the DT gives the core.
        unsafe { read_volatile((USB_BASE + off) as *const u32) }
    }
    fn write(&mut self, off: usize, val: u32) {
        // SAFETY: as above.
        unsafe { write_volatile((USB_BASE + off) as *mut u32, val) }
    }
    fn delay_us(&mut self, us: u32) {
        delay_us(us as u64);
    }
}

fn delay_us(us: u64) {
    let (f, start): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) start, options(nomem, nostack));
    }
    let ticks = f.saturating_mul(us) / 1_000_000;
    loop {
        let now: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) now, options(nomem, nostack)) };
        if now.wrapping_sub(start) >= ticks {
            break;
        }
    }
}

/// The eMMC user area through the arch driver: reads via BlockDev, writes via its `flashstub` gate only.
struct EmmcMedium(Emmc);
impl Medium for EmmcMedium {
    fn sectors(&self) -> u64 {
        self.0.sec_count()
    }
    fn read(&mut self, lba: u64, out: &mut [u8]) -> bool {
        self.0.read_blocks(lba, out).is_ok()
    }
    fn write(&mut self, lba: u64, sec: &[u8; 512]) -> bool {
        self.0.write_block(lba, sec).is_ok()
    }
    fn admit_full_medium(&mut self) -> bool {
        self.0.admit_full_medium() > 0
    }
    fn revoke_full_medium(&mut self) {
        self.0.revoke_full_medium()
    }
    fn cache_on(&self) -> bool {
        self.0.cache_on()
    }
    fn wear(&self) -> (u8, u8) {
        let (_, a, b) = self.0.wear();
        (a, b)
    }
}

#[repr(C, align(4096))]
struct ImgBuf([u8; IMG_MAX]);
static mut IMG: ImgBuf = ImgBuf([0; IMG_MAX]);
#[repr(C, align(64))]
struct OutBuf([u8; OUT_BUF]);
static mut OUT: OutBuf = OutBuf([0; OUT_BUF]);

fn park(why: &str) -> ! {
    kprint!("\n flashstub: STOPPED — {}\n flashstub: nothing was written. Power-cycle the board.\n", why);
    loop {
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

/// HBoot's own measurement of its loaded bytes (PCR0, EV_HBOOT_SELF), from the measured-boot log.
fn hboot_self_digest() -> Option<[u8; 32]> {
    // SAFETY: the log page is RAM below 1 GiB that HBoot wrote and cleaned to DRAM before the EL1 handoff.
    let log = unsafe { &*(MEASURE_LOG_ADDR as *const MeasureLog) };
    if log.magic != MEASURE_LOG_MAGIC || log.count > 64 {
        return None;
    }
    let ev = (MEASURE_LOG_ADDR + core::mem::size_of::<MeasureLog>()) as *const MeasureEvent;
    (0..log.count as usize).find_map(|i| {
        let e = unsafe { &*ev.add(i) };
        (e.kind == EV_HBOOT_SELF && e.pcr == PCR_FIRMWARE).then_some(e.digest)
    })
}

#[no_mangle]
pub extern "C" fn kmain(bootinfo_pa: u64) -> ! {
    let console = arch::console();
    console.init();
    kprint!("\n================================================\n");
    kprint!(" heqk flash stub (ADR 0070) — HQFL v1, {} v{}\n", hal::release::PRODUCT, hal::release::VERSION);
    kprint!("================================================\n");

    // 1. the HBoot handoff
    let bi = unsafe { &*(bootinfo_pa as *const BootInfo) };
    if bi.magic != BOOTINFO_MAGIC {
        park("no BootInfo from HBoot (the stub must be launched by HBoot)");
    }
    let build = bi.kernel_hash;
    kprint!(" boot : HBoot v{} verified this stub: svn {} (floor {}), verify_flags {:#x}, sha256 ", bi.hboot_version, bi.svn, bi.svn_floor, bi.verify_flags);
    for b in &build {
        kprint!("{:02x}", b);
    }
    kprint!("\n");
    if bi.boot_flags & BOOT_FLAG_TRIAL_WDOG != 0 && bi.el2_gate != 0 {
        // Disarm HBoot's 15 s trial watchdog: the stub is not an A/B trial and a flash takes minutes. HBoot's gate
        // only clears the PM watchdog for #1; it touches nothing on the eMMC.
        unsafe { core::arch::asm!("hvc #1", options(nomem, nostack)) };
        kprint!(" boot : trial watchdog disarmed (hvc #1)\n");
    }

    // 2. MMU + caches (the verifier and the read-back hash run cached)
    arch::mmu_cm5::enable_identity();

    // 3. the HBoot-prefix reference
    let hboot = MeasuredHboot { digest: hboot_self_digest() };
    match hboot.digest {
        Some(d) => kprint!(" hboot: self-measurement {:02x}{:02x}{:02x}{:02x}… (slot prefixes must match it)\n", d[0], d[1], d[2], d[3]),
        None => kprint!(" hboot: NO self-measurement in the log — every image will be refused\n"),
    }
    let release = flashstub::release::trust_root_is_release();
    // The compiled-in floor, raised to the floor HBoot itself enforced on this board (never lowered): an image
    // below it would be refused by HBoot at the next boot anyway. HBoot read that floor; the stub reads no OTP.
    let floor = SVN_FLOOR.max(bi.svn_floor);
    kprint!(" trust: {} build (trust root {} the development block-list), SVN floor {} (compiled {}, HBoot {})\n",
        if release { "RELEASE" } else { "DEBUG" }, if release { "not on" } else { "ON" }, floor, SVN_FLOOR, bi.svn_floor);

    // 4. eMMC
    let emmc = match Emmc::probe() {
        Ok(e) => e,
        Err((step, e)) => {
            kprint!(" emmc : probe failed at step {} ({:?})\n", step, e);
            park("eMMC probe failed");
        }
    };
    kprint!(" emmc : {} sectors ({} MiB), sdclk {} Hz, cache {}, wear {:?}, multi-read {}\n",
        emmc.sec_count(), emmc.sec_count() / 2048, emmc.sdclk_hz(), if emmc.cache_on() { "ON" } else { "off" }, emmc.wear(), emmc.multi_read());
    let mut medium = EmmcMedium(emmc);

    // 5. the OTG core: read-only identification first
    let mut regs = Mmio;
    let hw = Dwc2::<Mmio>::identify(&mut regs);
    kprint!(" usb  : GSNPSID={:#010x} GHWCFG1={:#010x} GHWCFG2={:#010x} GHWCFG3={:#010x} GHWCFG4={:#010x} GUSBCFG={:#010x}\n",
        hw.snpsid, hw.hwcfg[0], hw.hwcfg[1], hw.hwcfg[2], hw.hwcfg[3], hw.gusbcfg_at_entry);
    kprint!(" usb  : FIFO {} words, {} device endpoints, {} TX FIFOs, HS PHY type {}, arch {}\n",
        hw.fifo_words, hw.dev_eps, if hw.dedicated_fifos { "dedicated" } else { "shared" }, hw.hs_phy(), hw.arch());
    // SAFETY: single-threaded; OUT is used only by the driver from here on.
    let out = unsafe { &mut (*core::ptr::addr_of_mut!(OUT)).0 };
    let mut usb = match Dwc2::init(regs, out, &build) {
        Ok(u) => u,
        Err((InitErr::NotDwc2(id), _)) => {
            kprint!(" usb  : GSNPSID {:#010x} is not a Synopsys DWC2 core (0x4F54xxxx)\n", id);
            park("usb@480000 is not a DWC2 core (or is not powered/clocked) — no register was written");
        }
        Err((e, _)) => {
            kprint!(" usb  : init failed: {:?}\n", e);
            park("USB device controller init failed");
        }
    };
    kprint!(" usb  : device mode up, soft-connected as {:04x}:{:04x} serial {} — waiting for the host\n",
        flashstub::desc::VID, flashstub::desc::PID, usb.serial());

    // 6. serve
    // SAFETY: single-threaded; IMG is used only by the server.
    let img = unsafe { &mut (*core::ptr::addr_of_mut!(IMG)).0 };
    let cfg = Config { svn_floor: floor, release, build, log };
    let mut srv = Server::new(cfg, &hboot, img);
    loop {
        match flashstub::service(&mut usb, &mut srv, &mut medium) {
            Some(Event::Reset) => kprint!(" usb  : bus reset\n"),
            Some(Event::Enumerated { high_speed }) => {
                kprint!(" usb  : enumerated at {} speed\n", if high_speed { "HIGH" } else { "FULL (HQFL needs high speed: frames may stall)" })
            }
            Some(Event::Configured) => kprint!(" usb  : configured at address {} — HQFL ready\n", usb.address()),
            Some(Event::Suspend) | None => {}
        }
    }
}

/// IRQs stay masked for the stub's whole life (polled driver); the vector table still links to these.
#[no_mangle]
pub extern "C" fn handle_irq(sp: usize) -> usize {
    kprint!(" flashstub: unexpected IRQ\n");
    sp
}

/// The stub has no EL0.
#[no_mangle]
pub extern "C" fn handle_lower_sync(_frame: *mut u64) -> usize {
    park("unexpected lower-EL exception");
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    arch::on_panic(info)
}
