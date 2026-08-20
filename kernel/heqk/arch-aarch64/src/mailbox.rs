//! VideoCore property mailbox (kernel side) — set the SDIO/WiFi clock + power so
//! the CYW43455 radio comes alive for P10. Ported from the proven HBoot mailbox
//! (same base/channel/pointer rule). Every poll is BOUNDED; a bad response returns
//! None/false rather than hanging. Buffer lives in the kernel's low-1 GB .bss so
//! the 32-bit VC pointer is valid.
//!
//! Only for `cfg(cm5)`: registers are BCM2712 CPU-physical, identity-mapped Normal.

use core::ptr::{read_volatile, write_volatile};

const MBOX: usize = 0x10_7C01_3880;
const RD: usize = 0x00; // MAIL0 read  (VC -> ARM)
const STA0: usize = 0x18; // MAIL0 status; EMPTY = bit30
const WRT: usize = 0x20; // MAIL1 write (ARM -> VC)
const STA1: usize = 0x38; // MAIL1 status; FULL = bit31
const EMPTY: u32 = 0x4000_0000;
const FULL: u32 = 0x8000_0000;
const CHAN: u32 = 8; // property channel
const RESP_OK: u32 = 0x8000_0000;
const POLL_MAX: u32 = 4_000_000;

/// VideoCore clock IDs (RPi firmware property interface).
pub const CLK_EMMC: u32 = 1;
pub const CLK_EMMC2: u32 = 12;
/// VideoCore power-domain device IDs.
pub const PWR_SDCARD: u32 = 0;

#[repr(align(64))]
struct MboxBuf([u32; 48]); // 3 cache lines, owns them outright
static mut MBOX_BUF: MboxBuf = MboxBuf([0; 48]);

#[inline(always)]
unsafe fn r(off: usize) -> u32 {
    read_volatile((MBOX + off) as *const u32)
}
#[inline(always)]
unsafe fn w(off: usize, v: u32) {
    write_volatile((MBOX + off) as *mut u32, v);
}
unsafe fn cvac(base: usize, len: usize) {
    const LINE: usize = 64;
    let mut a = base & !(LINE - 1);
    while a < base + len {
        core::arch::asm!("dc cvac, {}", in(reg) a);
        a += LINE;
    }
    core::arch::asm!("dsb sy");
}
unsafe fn ivac(base: usize, len: usize) {
    const LINE: usize = 64;
    let mut a = base & !(LINE - 1);
    while a < base + len {
        core::arch::asm!("dc ivac, {}", in(reg) a);
        a += LINE;
    }
    core::arch::asm!("dsb sy");
}

/// Run one property transaction (buffer already holds the request; `nwords` = its
/// length). Returns true on a RESP_OK reply. Tries the VC-alias pointer then identity.
unsafe fn transact(nwords: usize) -> bool {
    let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
    let phys = buf as usize;
    if phys >= 0x4000_0000 {
        return false; // VC pointer is 32-bit; buffer must be in the low 1 GB
    }
    let candidates = [0xC000_0000u32 | (phys as u32 & 0x3FFF_FFFF), phys as u32];
    for &vcaddr in &candidates {
        cvac(phys, nwords * 4);
        let mut drain = 0;
        while r(STA0) & EMPTY == 0 && drain < 16 {
            let _ = r(RD);
            drain += 1;
        }
        let mut spin = 0;
        while r(STA1) & FULL != 0 {
            spin += 1;
            if spin >= POLL_MAX {
                break;
            }
        }
        w(WRT, (vcaddr & !0xF) | CHAN);
        let mut got = false;
        let mut outer = 0u32;
        'recv: while outer < POLL_MAX {
            let mut s = 0;
            while r(STA0) & EMPTY != 0 {
                s += 1;
                if s >= POLL_MAX {
                    break 'recv;
                }
            }
            let msg = r(RD);
            if msg & 0xF == CHAN {
                got = true;
                break 'recv;
            }
            outer += 1;
        }
        if !got {
            continue;
        }
        ivac(phys, nwords * 4);
        if read_volatile(buf.add(1)) == RESP_OK {
            return true;
        }
    }
    false
}

/// SET_CLOCK_RATE (0x00038002): set `clock_id` to `rate` Hz (skip_turbo=0).
/// Returns the actual rate the firmware set, or None.
pub fn set_clock_rate(clock_id: u32, rate: u32) -> Option<u32> {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        // [size, req, tag, val_size(12), code, id, rate, skip_turbo, end]
        let req = [0x24u32, 0, 0x0003_8002, 12, 0, clock_id, rate, 0, 0];
        for (i, &v) in req.iter().enumerate() {
            write_volatile(buf.add(i), v);
        }
        if !transact(9) {
            return None;
        }
        Some(read_volatile(buf.add(6)))
    }
}

/// GET_CLOCK_RATE (0x00030002): current rate of `clock_id` in Hz (0 = off/unknown).
pub fn get_clock_rate(clock_id: u32) -> Option<u32> {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        let req = [0x20u32, 0, 0x0003_0002, 8, 0, clock_id, 0, 0];
        for (i, &v) in req.iter().enumerate() {
            write_volatile(buf.add(i), v);
        }
        if !transact(8) {
            return None;
        }
        Some(read_volatile(buf.add(6)))
    }
}

// ---------------------------------------------------------------------------
// Reboot flags — the ON-DEVICE `tryboot` mechanism (M1 criterion 4 / M3 OTA).
//
// `reboot "0 tryboot"` on Linux is NOT a magic userspace string: it is two VideoCore
// mailbox properties. From the reference driver, Linux
// drivers/firmware/raspberrypi.c:204 (source in builder/kernel-build/linux-rpi-*.tar.gz):
//
//     // 'tryboot': Sets a one-shot flag which is cleared upon reboot and
//     //           causes the tryboot.txt to be loaded instead of config.txt
//     if (data && strstr(data, " tryboot"))
//             reboot_flags |= 0x1;
//     if (reboot_flags)
//             rpi_firmware_property(fw, RPI_FIRMWARE_SET_REBOOT_FLAGS, ...);
//     rpi_firmware_property(fw, RPI_FIRMWARE_NOTIFY_REBOOT, NULL, 0);
//
// Tag numbers from include/soc/bcm2835/raspberrypi-firmware.h:
//     RPI_FIRMWARE_NOTIFY_REBOOT    = 0x00030048
//     RPI_FIRMWARE_GET_REBOOT_FLAGS = 0x00030064
//     RPI_FIRMWARE_SET_REBOOT_FLAGS = 0x00038064
//
// The flag is ONE-SHOT: the firmware clears it as it consumes it, so exactly one boot
// uses tryboot.txt (SLOT B) and any subsequent boot falls back to config.txt (SLOT A).
// That is what makes A/B rollback safe without a host PC.

/// The tryboot one-shot bit in the firmware's reboot-flags word.
pub const REBOOT_FLAG_TRYBOOT: u32 = 0x1;

/// GET_REBOOT_FLAGS (0x00030064). Returns the firmware's current reboot-flags word.
///
/// Lets the tryboot path be verified NON-DESTRUCTIVELY (set, read back, clear) before it
/// is ever used to actually reboot the board.
pub fn get_reboot_flags() -> Option<u32> {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        // [size, req, tag, val_size(4), code, value, end]
        let req = [0x1Cu32, 0, 0x0003_0064, 4, 0, 0, 0];
        for (i, &v) in req.iter().enumerate() {
            write_volatile(buf.add(i), v);
        }
        if !transact(7) {
            return None;
        }
        Some(read_volatile(buf.add(5)))
    }
}

/// SET_REBOOT_FLAGS (0x00038064). Returns the flags word the firmware reports back.
///
/// Pass `REBOOT_FLAG_TRYBOOT` to arm the one-shot; pass 0 to disarm it again.
pub fn set_reboot_flags(flags: u32) -> Option<u32> {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        let req = [0x1Cu32, 0, 0x0003_8064, 4, 0, flags, 0];
        for (i, &v) in req.iter().enumerate() {
            write_volatile(buf.add(i), v);
        }
        if !transact(7) {
            return None;
        }
        Some(read_volatile(buf.add(5)))
    }
}

/// NOTIFY_REBOOT (0x00030048): tell the firmware a reboot is imminent, so it can commit
/// any pending state (including the reboot flags) before the SoC resets. Linux issues
/// this on EVERY reboot, flags or not (raspberrypi.c:222).
pub fn notify_reboot() -> bool {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        // Zero-length value buffer.
        let req = [0x18u32, 0, 0x0003_0048, 0, 0, 0];
        for (i, &v) in req.iter().enumerate() {
            write_volatile(buf.add(i), v);
        }
        transact(6)
    }
}

/// NON-DESTRUCTIVE proof that the tryboot mechanism is reachable from heqk: read the
/// current flags, arm the tryboot one-shot, read it back, then DISARM it and confirm.
///
/// Returns `(before, armed_readback, after_disarm)`. Nothing reboots — this deliberately
/// verifies the mailbox path BEFORE it is used to actually trial a candidate slot, so a
/// failure here is a console line rather than a board that boots somewhere unexpected.
///
/// SAFETY NOTE: the flag is left DISARMED on exit. If this function is interrupted between
/// arm and disarm, the next reset would consume the one-shot and boot tryboot.txt (SLOT B)
/// exactly once, then fall back to SLOT A by itself.
pub fn tryboot_roundtrip() -> (Option<u32>, Option<u32>, Option<u32>) {
    let before = get_reboot_flags();
    let _ = set_reboot_flags(REBOOT_FLAG_TRYBOOT);
    let armed = get_reboot_flags();
    let _ = set_reboot_flags(0);
    let after = get_reboot_flags();
    (before, armed, after)
}

/// SET_POWER_STATE (0x00028001): power a device domain. `state` bit0=on, bit1=wait.
/// Returns the resulting state, or None.
pub fn set_power_state(device_id: u32, on: bool) -> Option<u32> {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        let state = if on { 0b11 } else { 0b10 }; // on|wait / off|wait
        let req = [0x20u32, 0, 0x0002_8001, 8, 0, device_id, state, 0];
        for (i, &v) in req.iter().enumerate() {
            write_volatile(buf.add(i), v);
        }
        if !transact(8) {
            return None;
        }
        Some(read_volatile(buf.add(6)))
    }
}
