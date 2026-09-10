//! P10 Stage A — CYW43455 WiFi (SDIO) bring-up to the chip-ID proof-point.
//!
//! The WiFi radio is an Infineon/Cypress CYW43455 (Broadcom silicon, Linux
//! `brcmfmac`) on a **BCM2712 SDHCI** host — CPU-phys `0x10_0110_0000`, a standard
//! SD Host Controller v3 (`brcm,bcm2712-sdhci`), GIC SPI 274 — NOT the RP1. This
//! module brings the SDIO link up far enough to read the chip common-core ID at
//! `SI_ENUM_BASE` and confirm `0x4345` (BCM4345/6 = CYW43455). That is Stage A of
//! `P9_P10_BRINGUP.md`; firmware/NVRAM upload (B) and the regulatory `country`
//! iovar (C, the regdomain backlog target) build on this.
//!
//! Scope + honesty: structured off-metal from the SD-spec + brcmfmac/Pico-W
//! `cyw43-driver` sequence. SDHCI init timing (DDR50, clock divisors, WL_ON assert
//! order) and the `cfg` quirk block need on-metal iteration — this compiles under
//! `cfg(cm5)` and is wired behind `[P10-A]`, to be flash-validated like `rtl8111`.

use core::ptr::{read_volatile, write_volatile};

// --- BCM2712 SDHCI host controller (SD Host Controller v3 register map) --------
const SDHCI: usize = 0x10_0110_0000;

const ARG2: usize = 0x00;
const BLK_SIZE_CNT: usize = 0x04; // [15:0]=block size, [31:16]=block count
const ARG1: usize = 0x08;
const CMD_XFER: usize = 0x0C; // [15:0]=transfer mode, [31:16]=command
const RESP0: usize = 0x10; // 0x10..0x1c = 128-bit response
const BUF_DATA: usize = 0x20; // PIO data port
const PRESENT_STATE: usize = 0x24;
const HOST_CTRL1: usize = 0x28; // [7:0] host control, [15:8] power, ...
const CLOCK_CTRL: usize = 0x2C; // [15:0] clock control, [23:16] timeout, [24+] reset
const INT_STATUS: usize = 0x30;
const INT_ENABLE: usize = 0x34;
const SIG_ENABLE: usize = 0x38;
const HOST_CTRL2: usize = 0x3E; // [15:0] — UHS mode, 1.8V signalling

// PRESENT_STATE bits.
const CMD_INHIBIT: u32 = 1 << 0;
const DAT_INHIBIT: u32 = 1 << 1;
const PS_BUF_RD_EN: u32 = 1 << 11; // Buffer Read Enable — FIFO holds valid data
// CLOCK_CTRL bits.
const INT_CLK_EN: u16 = 1 << 0;
const INT_CLK_STABLE: u16 = 1 << 1;
const SD_CLK_EN: u16 = 1 << 2;
const RST_ALL: u8 = 1 << 0; // in SW-reset byte @0x2F
const RST_CMD: u8 = 1 << 1;
const RST_DAT: u8 = 1 << 2;
// INT_STATUS bits.
const INT_CMD_DONE: u32 = 1 << 0;
const INT_XFER_DONE: u32 = 1 << 1;
const INT_BUF_WR_RDY: u32 = 1 << 4;
const INT_BUF_RD_RDY: u32 = 1 << 5;
const INT_CARD: u32 = 1 << 8; // SDIO Card Interrupt (in-band) — we poll instead
const PS_BUF_WR_EN: u32 = 1 << 10; // Buffer Write Enable — FIFO can accept data
const INT_ERR: u32 = 1 << 15;
// CMD flags (in the high half of CMD_XFER).
const RESP_48: u16 = 0b10; // response type 48-bit
const RESP_48_BUSY: u16 = 0b11;
const RESP_136: u16 = 0b01;
const CMD_CRC_CHK: u16 = 1 << 3;
const CMD_IDX_CHK: u16 = 1 << 4;
const CMD_DATA: u16 = 1 << 5;
// Transfer-mode bits (low half of CMD_XFER).
const XM_READ: u16 = 1 << 4;
const XM_BLKCNT_EN: u16 = 1 << 1;
const XM_MULTI: u16 = 1 << 5;
// SDIO func-1 block size (brcmfmac SDIO_FUNC1_BLOCKSIZE) + its FBR registers.
const F1_BLOCK_SIZE: u32 = 64;
const FBR_F1_BLKSIZE_LO: u32 = 0x110;
const FBR_F1_BLKSIZE_HI: u32 = 0x111;

#[inline]
fn r8(o: usize) -> u8 {
    unsafe { read_volatile((SDHCI + o) as *const u8) }
}
#[inline]
fn w8(o: usize, v: u8) {
    unsafe { write_volatile((SDHCI + o) as *mut u8, v) };
}
#[inline]
fn r16(o: usize) -> u16 {
    unsafe { read_volatile((SDHCI + o) as *const u16) }
}
#[inline]
fn w16(o: usize, v: u16) {
    unsafe { write_volatile((SDHCI + o) as *mut u16, v) };
}
#[inline]
fn r32(o: usize) -> u32 {
    unsafe { read_volatile((SDHCI + o) as *const u32) }
}
#[inline]
fn w32(o: usize, v: u32) {
    unsafe { write_volatile((SDHCI + o) as *mut u32, v) };
}

fn delay(us: u64) {
    let (freq, start): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) start, options(nomem, nostack));
    }
    let ticks = freq.saturating_mul(us) / 1_000_000;
    loop {
        let now: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) now, options(nomem, nostack)) };
        if now.wrapping_sub(start) >= ticks {
            break;
        }
    }
}

// --- SDIO command layer -------------------------------------------------------
/// SDIO command indices (SD spec + SDIO).
const CMD3_SEND_RCA: u16 = 3;
const CMD5_IO_OP_COND: u16 = 5;
const CMD7_SELECT: u16 = 7;
const CMD52_IO_RW_DIRECT: u16 = 52;
const CMD53_IO_RW_EXTENDED: u16 = 53;

/// Diagnostic: (PRESENT_STATE, INT_STATUS) captured at the last command failure —
/// distinguishes a card that never responds (timeout, INT_STATUS ~0) from a host
/// that rejected the response (INT_ERR bits set).
static mut SDIO_DIAG: (u32, u32) = (0, 0);
pub fn sdio_diag() -> (u32, u32) {
    unsafe { SDIO_DIAG }
}

/// Issue an SDHCI command; return the 32-bit RESP0 (or None on error/timeout).
/// `crc_idx` = check the response CRC + command index (true for R1/R5/R6/R1b;
/// FALSE for R3/R4 — e.g. CMD5's R4 has no CRC or index, so checking it errors).
fn cmd(idx: u16, arg: u32, resp_kind: u16, crc_idx: bool, data: bool) -> Option<u32> {
    let mut spin = 0u32;
    let inhibit = CMD_INHIBIT | if data { DAT_INHIBIT } else { 0 };
    while r32(PRESENT_STATE) & inhibit != 0 {
        spin += 1;
        if spin > 200_000 {
            // Inhibit stuck (e.g. the command engine wedged on an in-band card
            // interrupt) — soft-reset the CMD (+ DAT for data cmds) circuit to
            // recover, then proceed. Standard SDHCI error recovery.
            let mut rb = RST_CMD;
            if data {
                rb |= RST_DAT;
            }
            w8(0x2F, rb);
            let mut rs = 0u32;
            while r8(0x2F) & rb != 0 && rs < 200_000 {
                rs += 1;
            }
            break;
        }
    }
    w32(INT_STATUS, 0xFFFF_FFFF); // clear stale
    w32(ARG1, arg);
    let mut flags = resp_kind;
    if crc_idx && resp_kind != 0 {
        flags |= CMD_CRC_CHK | CMD_IDX_CHK;
    }
    if data {
        flags |= CMD_DATA;
    }
    w16(CMD_XFER + 2, (idx << 8) | flags);
    let mut spin = 0u32;
    loop {
        let st = r32(INT_STATUS);
        if st & INT_ERR != 0 {
            unsafe { SDIO_DIAG = (r32(PRESENT_STATE), st) };
            return None;
        }
        if st & INT_CMD_DONE != 0 {
            break;
        }
        spin += 1;
        if spin > 1_000_000 {
            unsafe { SDIO_DIAG = (r32(PRESENT_STATE), st) };
            return None;
        }
    }
    Some(r32(RESP0))
}

/// CMD52 (IO_RW_DIRECT): single-byte register access on SDIO function `fnum`.
/// `write`=true writes `val`; returns the read/echoed byte.
fn cmd52(write: bool, fnum: u32, addr: u32, val: u8) -> Option<u8> {
    let arg = ((write as u32) << 31)
        | ((fnum & 7) << 28)
        | ((write as u32) << 27) // RAW (read-after-write) when writing
        | ((addr & 0x1_FFFF) << 9)
        | (val as u32);
    cmd(CMD52_IO_RW_DIRECT, arg, RESP_48, true, false).map(|r| (r & 0xFF) as u8)
}

/// CMD53 (IO_RW_EXTENDED) block/byte read into `out` from function `fnum` at
/// `addr` (byte mode, incrementing). PIO via the buffer data port.
fn cmd53_read(fnum: u32, addr: u32, out: &mut [u8]) -> bool {
    let n = out.len().min(512);
    // block size 1 handled as a byte transfer; count = n bytes.
    w16(BLK_SIZE_CNT, n as u16); // byte count in low field for byte mode
    w16(BLK_SIZE_CNT + 2, 1);
    // Transfer Mode (0x0C low half) — REQUIRED for a data command. Linux
    // sdhci_set_transfer_mode sets BLK_CNT_EN whenever data is present (only adds
    // MULTI for >1 block), so a single-block read is BLK_CNT_EN | READ (0x12), not
    // just READ (0x10). Written before the Command reg (0x0E), which cmd() issues.
    w16(CMD_XFER, XM_READ | XM_BLKCNT_EN);
    let arg = (0 << 31)            // read
        | ((fnum & 7) << 28)
        | (0 << 27)                 // byte mode (not block)
        | (1 << 26)                 // op-code: incrementing address
        | ((addr & 0x1_FFFF) << 9)
        | (n as u32 & 0x1FF);
    if cmd(CMD53_IO_RW_EXTENDED, arg, RESP_48, true, true).is_none() {
        return false;
    }
    // PIO: wait buffer-read-ready (INT bit only — Present-State BUF_RD_EN b11 is
    // unreliable on this controller and spurious-times-out the wait).
    let mut spin = 0u32;
    while r32(INT_STATUS) & INT_BUF_RD_RDY == 0 {
        if r32(INT_STATUS) & INT_ERR != 0 {
            return false;
        }
        spin += 1;
        if spin > 1_000_000 {
            return false;
        }
    }
    let mut i = 0;
    while i < n {
        let word = r32(BUF_DATA);
        for b in 0..4 {
            if i < n {
                out[i] = ((word >> (b * 8)) & 0xFF) as u8;
                i += 1;
            }
        }
    }
    // Wait Transfer Complete — de-asserts DAT_INHIBIT so the NEXT data command can
    // issue. Skipping this left the re-read returning 0x00000000 (DAT stuck).
    spin = 0;
    while r32(INT_STATUS) & INT_XFER_DONE == 0 {
        if r32(INT_STATUS) & INT_ERR != 0 {
            return false;
        }
        spin += 1;
        if spin > 1_000_000 {
            return false;
        }
    }
    true
}

// --- Backplane (SI) access via F1 -------------------------------------------
// F1 holds a 15-bit window into the SoC backplane; the top address bits are set
// via SBADDRLOW/MID/HIGH so CMD53 on F1 reaches an arbitrary backplane address.
const SB_ADDR_LOW: u32 = 0x1000A;
const SB_ADDR_MID: u32 = 0x1000B;
const SB_ADDR_HIGH: u32 = 0x1000C;
const SI_ENUM_BASE: u32 = 0x1800_0000; // chipcommon core — chip-ID at +0x00

fn set_backplane_window(addr: u32) -> bool {
    // Window is 0x8000-aligned; program address bits [31:8] (brcmfmac masks the low
    // byte with 0xFF after clearing the 15-bit offset — 0x80 dropped real bits for
    // any window whose addr[14:8] != 0, e.g. cores above chipcommon).
    let a = cmd52(true, 1, SB_ADDR_LOW, ((addr >> 8) & 0xFF) as u8);
    let b = cmd52(true, 1, SB_ADDR_MID, ((addr >> 16) & 0xFF) as u8);
    let c = cmd52(true, 1, SB_ADDR_HIGH, ((addr >> 24) & 0xFF) as u8);
    a.is_some() && b.is_some() && c.is_some()
}

/// BCM2712 SDHCI `cfg` quirk-block init (@ base+0x400) — the piece the plan flagged.
/// Mirrors sdhci_brcmstb_cfginit_2712. The critical one for WiFi: FORCE CARD
/// PRESENCE — the CYW43455 is non-removable with no card-detect pin, so without the
/// SDCD_N test override the controller sees "no card" and never issues commands
/// (→ CMD5 timeout). Also select SD (not MMC) mode + tell it the base-clock MHz.
fn sdhci_cfg_init() {
    const CFG: usize = 0x10_0110_0400;
    unsafe {
        // SDIO_CFG_CTRL (0x00): force presence — SDCD_N_TEST_EN(bit31)=1, LEV(bit30)=0.
        let ctrl = read_volatile(CFG as *const u32);
        write_volatile(CFG as *mut u32, (ctrl & !(1u32 << 30)) | (1u32 << 31));
        // SDIO_CFG_SD_PIN_SEL (0x44): SD mode = BIT(1).
        let sel = read_volatile((CFG + 0x44) as *const u32);
        write_volatile((CFG + 0x44) as *mut u32, (sel & !0x3) | 0x2);
        // SDIO_CFG_CQ_CAPABILITY (0x4c): (3<<12) | base_clk_mhz (clk_emmc2 = 100 MHz).
        write_volatile((CFG + 0x4c) as *mut u32, (3 << 12) | 100);
        core::arch::asm!("dsb sy");
    }
}

// --- SDHCI host init ----------------------------------------------------------
fn host_reset() {
    w8(0x2F, RST_ALL); // SW reset all
    let mut spin = 0u32;
    while r8(0x2F) & RST_ALL != 0 && spin < 1_000_000 {
        spin += 1;
    }
    // CRITICAL (found via Linux oracle: 0x34 reads 0x03ff010b when WiFi is up):
    // the SDHCI only LATCHES a bit into INT_STATUS (0x30) if the matching bit in
    // the Normal/Error Interrupt STATUS-ENABLE register (0x34) is set. SW-reset
    // clears 0x34, so without this every command completes on the bus but
    // INT_STATUS stays 0x00000000 forever — cmd() then spins out and reports a
    // false "timeout" (the P10 "stalled step 1, INT=0" symptom). Enable ALL
    // status bits (we need CMD_DONE, XFER_DONE, BUF_RD_RDY for PIO, and every
    // error bit). We POLL, so leave the Signal-Enable (0x38) at 0 — no IRQ line.
    // EXCEPT the SDIO Card Interrupt (bit 8, 0x100): HEQK polls the backplane
    // (SDIO-core intstatus) for frames and never uses the SDHCI in-band SDIO IRQ.
    // Once the WiFi firmware boots it asserts that in-band interrupt (mailbox
    // DEVREADY/FWREADY); in 1-bit mode a latched, unserviced card interrupt wedges
    // the command engine (Command Inhibit stuck → the P10-C first F2 write fails,
    // fail_stage=1, INT=0x100, PRESENT bit0=1). Masking it out of INT_ENABLE stops
    // the controller from ever latching/acting on it.
    w32(INT_ENABLE, 0xFFFF_FFFF & !INT_CARD); // all status bits except Card Interrupt
    w32(SIG_ENABLE, 0x0000_0000);
    // Data Timeout Control (0x2E) — set the counter to max (0xE = 2^27 clocks). SW
    // reset clears it to 0 (the SHORTEST timeout); a large data transfer then trips
    // DATA TIMEOUT (INT err 0x0010) before it completes — the 4-bit CMD53 write
    // symptom. Linux sets a non-zero timeout here too.
    w8(0x2E, 0x0E);
}

/// Set the SD clock to `divisor` (SDCLK = base / (2*divisor)); enable it.
fn set_clock(divisor: u16) {
    w16(CLOCK_CTRL, 0); // stop
    let d = divisor & 0xFF;
    let dhi = (divisor >> 8) & 0x3;
    let mut v = INT_CLK_EN | (d << 8) | (dhi << 6);
    w16(CLOCK_CTRL, v);
    let mut spin = 0u32;
    while r16(CLOCK_CTRL) & INT_CLK_STABLE == 0 && spin < 1_000_000 {
        spin += 1;
    }
    v |= SD_CLK_EN;
    w16(CLOCK_CTRL, v);
}

/// P10 Stage A: bring the SDIO link up and read the CYW43455 chip-ID.
/// Returns the 16-bit chip-ID (expect 0x4345), or None on failure.
///
/// NOTE: WL_ON (the radio's power/reset GPIO, `wl_on_reg`) must be asserted and
/// `clk_emmc2` set via the VC mailbox BEFORE this runs — those live in the caller
/// (kernel) which owns the mailbox; here we assume the rail/clock are up.
/// P10 pre-req — power + clock the CYW43455 so the SDIO link can come up. After a
/// bare-metal boot (no WiFi DT overlay) both are OFF, so CMD5 gets no response
/// (SDIO step 1). WL_ON = `gio` GPIO 28 (active-high; the SDIO2 `vmmc-supply`
/// regulator, 150 ms startup); `clk_emmc2` (id 12) is the SDIO2 base clock the
/// SDHCI divides down. `gio` (brcmstb-gpio) @ CPU 0x10_7d50_8500: bank0 DATA=+0x04,
/// IODIR=+0x08 (0=output). Returns the clk_emmc2 rate read back (0 = clock off).
/// Mux the WL_ON + SDIO2 pins to their functions via the BCM2712 pinctrl
/// (@0x10_7d50_4100). CM5 = D0 stepping (bcm2712-ds.dtsi). fsel 0 = GPIO, fsel
/// 1..8 = the pin's alt1..alt8. WL_ON gpio28 → "gpio" (fsel 0, so the gio GPIO
/// write actually drives the pin); SDIO2 gpio30-35 → "sd2" (fsel 1). Offsets/shifts
/// derived from the D0 pin_regs (GPIO_REGS mr,mb → reg mr*4-ish, shift mb*4) +
/// pin_funcs tables in pinctrl-bcm2712.c. Read-modify-write to spare neighbor pins.
fn pinmux_wifi() {
    const PINCTRL: usize = 0x10_7D50_4100;
    // (reg offset, shift, fsel)
    let sets: [(usize, u32, u32); 7] = [
        (0x08, 16, 0), // gpio28 WL_ON     -> gpio
        (0x08, 24, 1), // gpio30 SDIO2_CLK -> sd2
        (0x08, 28, 1), // gpio31 SDIO2_CMD -> sd2
        (0x0c, 0, 1),  // gpio32 SDIO2_D0  -> sd2
        (0x0c, 4, 1),  // gpio33 SDIO2_D1  -> sd2
        (0x0c, 8, 1),  // gpio34 SDIO2_D2  -> sd2
        (0x0c, 12, 1), // gpio35 SDIO2_D3  -> sd2
    ];
    for (off, shift, fsel) in sets {
        unsafe {
            let p = (PINCTRL + off) as *mut u32;
            write_volatile(p, (read_volatile(p) & !(0xF << shift)) | (fsel << shift));
        }
    }
    unsafe { core::arch::asm!("dsb sy") };
}

pub fn radio_power_on() -> u32 {
    // Mux the pins FIRST — WL_ON's GPIO write and the SDHCI's SDIO2 signals only
    // reach the physical pads once their function-select is set.
    pinmux_wifi();
    const GIO: usize = 0x10_7D50_8500;
    unsafe {
        let iodir = (GIO + 0x08) as *mut u32;
        write_volatile(iodir, read_volatile(iodir) & !(1u32 << 28)); // WL_ON = output
        let data = (GIO + 0x04) as *mut u32;
        // RESET PULSE: drive WL_ON LOW first. Just holding it high never resets a chip
        // that was already powered from a prior boot — the BCM43455 PLL stays wedged so
        // HT_AVAIL never sets (CHIPCLKCSR 0x52, HT bit 0x80 clear) and F2 never comes
        // ready. Pulse low → settle → high for a clean power-on every boot.
        write_volatile(data, read_volatile(data) & !(1u32 << 28)); // WL_ON LOW (reset)
        core::arch::asm!("dsb sy");
        delay(20_000); // hold in reset
        write_volatile(data, read_volatile(data) | (1u32 << 28)); // WL_ON HIGH (radio on)
        core::arch::asm!("dsb sy");
    }
    // Ensure clk_emmc2 is running (the SDHCI clock-control divides it further).
    let _ = crate::mailbox::set_clock_rate(crate::mailbox::CLK_EMMC2, 100_000_000);
    delay(150_000); // wl_on_reg startup-delay-us
    crate::mailbox::get_clock_rate(crate::mailbox::CLK_EMMC2).unwrap_or(0)
}

/// P10 diagnosis dump: confirm each stage's register actually took.
/// [0]=gio bank0 DATA (WL_ON = bit28 should be 1), [1]=pinctrl mux 0x08 (gpio28
/// nibble@16 should be 0, gpio30/31 @24/28 should be 1), [2]=pinctrl mux 0x0c
/// (gpio32-35 @0/4/8/12 should be 1), [3]=SDHCI CAPS (base clock MHz in [13:8]),
/// [4]=SDHCI CLOCK_CTRL (SD_CLK_EN bit2 + INT_CLK_STABLE bit1 should be set),
/// [5]=SDHCI HOST_CTRL1/power (power-on bit8, 3.3V).
pub fn p10_regdump() -> [u32; 6] {
    unsafe {
        [
            read_volatile(0x10_7D50_8504 as *const u32), // gio DATA
            read_volatile(0x10_7D50_4108 as *const u32), // pinctrl mux 0x08
            read_volatile(0x10_7D50_410C as *const u32), // pinctrl mux 0x0c
            r32(0x40),                                    // SDHCI CAPABILITIES
            r32(CLOCK_CTRL),                              // clock control
            r32(HOST_CTRL1),                              // host ctrl + power
        ]
    }
}

/// Last SDIO bring-up step reached (diagnostic): 1=host init, 2=CMD5 OCR,
/// 3=CMD5 ready, 4=CMD3/7 select, 5=F1 enabled, 6=chip-ID read. On a SILENT probe
/// this localizes where the SDIO link stalls (clock/WL_ON vs a later step).
static mut SDIO_STEP: u8 = 0;
pub fn sdio_last_step() -> u8 {
    unsafe { SDIO_STEP }
}

pub fn chip_id_probe() -> Option<u16> {
    unsafe { SDIO_STEP = 1 };
    host_reset();
    sdhci_cfg_init(); // force card presence (non-removable) + SD mode — BEFORE CMD5
    // Bus power @ 3.3V (power control byte @0x29: bit0=on, [3:1]=voltage 0b111).
    w8(0x29, (0b111 << 1) | 1);
    delay(2_000);
    set_clock(0x80); // slow init clock (~400 kHz-ish; tuned on metal)
    delay(2_000);
    // NOTE: the CM5 WiFi SDIO2 bus runs at 3.3V I/O for init — the Linux oracle
    // showed HOST_CTRL2 = 0x0000 (no 1.8V signalling) with WiFi fully up, so we
    // leave HOST_CTRL2 alone here. (A UHS voltage switch, if ever needed, is a
    // CMD11 sequence done AFTER the card answers — not a blind bit-set before it.)

    // CMD5 arg=0 → OCR; then CMD5 arg=OCR until ready (bit31).
    let ocr = cmd(CMD5_IO_OP_COND, 0, RESP_48, false, false)?;
    unsafe { SDIO_STEP = 2 };
    let mut ready = false;
    for _ in 0..50 {
        if let Some(r) = cmd(CMD5_IO_OP_COND, ocr & 0x00FF_FFFF, RESP_48, false, false) {
            if r & (1 << 31) != 0 {
                ready = true;
                break;
            }
        }
        delay(2_000);
    }
    if !ready {
        return None;
    }
    unsafe { SDIO_STEP = 3 };
    // CMD3 → RCA (upper 16 bits of R6); CMD7 select.
    let rca = cmd(CMD3_SEND_RCA, 0, RESP_48, true, false)? >> 16;
    cmd(CMD7_SELECT, rca << 16, RESP_48_BUSY, true, false)?;
    unsafe { SDIO_STEP = 4 };
    // Bus WIDTH: stay 1-bit (D0 only) for now. 4-bit (card CCCR 0x07=0x02 + host
    // HOST_CTRL1 bit1) made CMD53 writes TIME OUT — the D1..D3 DAT lines don't
    // deliver data (pinmux/carrier routing to confirm). 1-bit uses only D0, which
    // is the same line CMD/CMD52 use and works. Keep card + host both at 1-bit
    // (card defaults to 1-bit at reset; leave CCCR 0x07 = 0x00, host bit1 = 0).
    cmd52(true, 0, 0x07, 0x00)?;
    // Enable F1 (I/O-enable 0x02 bit1), wait ready (I/O-ready 0x03 bit1).
    cmd52(true, 0, 0x02, 0x02)?;
    for _ in 0..50 {
        if cmd52(false, 0, 0x03, 0)? & 0x02 != 0 {
            break;
        }
        delay(1_000);
    }
    unsafe { SDIO_STEP = 5 };
    // Request the ALP clock on the backplane BEFORE any chipcommon read. Without it
    // the SI backplane is UNCLOCKED and F1 reads return noise — the observed
    // raw=0xff966a53/reread=0x00000000 (unstable) chip-ID garbage. Mirrors brcmfmac
    // brcmf_sdio_htclk/ALP path: write CHIPCLKCSR ALP_AVAIL_REQ, poll ALP_AVAIL.
    let _ = cmd52(true, 1, CHIPCLKCSR, SBSDIO_ALP_AVAIL_REQ);
    for _ in 0..200 {
        if let Some(v) = cmd52(false, 1, CHIPCLKCSR, 0) {
            if v & SBSDIO_ALP_AVAIL != 0 {
                break;
            }
        }
        delay(1_000);
    }
    // Point the F1 backplane window at chipcommon.
    let win_ok = set_backplane_window(SI_ENUM_BASE);
    // Read chipcommon[0..4] (the chip-ID reg) via 4 CMD52 BYTE reads — the proven
    // path (steps 1-4 use cmd52 fine). CMD53's data phase returns deterministic
    // garbage (0xff966a53); byte reads at the window offset (no 4-byte flag)
    // sidestep that and, per brcmfmac, are valid for register-sized backplane reads.
    let base = SI_ENUM_BASE & 0x7FFF;
    let mut id = [0u8; 4];
    for i in 0..4u32 {
        id[i as usize] = cmd52(false, 1, base + i, 0).unwrap_or(0xEE);
    }
    // Keep the CMD53 read as a side-by-side diagnostic (was it a CMD53 bug?).
    let mut c53 = [0u8; 4];
    let _ = cmd53_read(1, base | 0x8000, &mut c53);
    unsafe { CHIPID_DIAG = (u32::from_le_bytes(id), u32::from_le_bytes(c53), win_ok) };
    unsafe { SDIO_STEP = 6 };
    Some(u16::from_le_bytes([id[0], id[1]]))
}

static mut CHIPID_DIAG: (u32, u32, bool) = (0, 0, false);
/// (chipcommon[0..4] via CMD52 byte reads, same via CMD53, backplane-window ACK).
pub fn chipid_diag() -> (u32, u32, bool) {
    unsafe { CHIPID_DIAG }
}

static mut BUSWIDTH_DIAG: (u32, u32) = (0, 0); // (CCCR 0x07 readback, host_ctrl1)
/// Switch the SDIO bus to 4-bit — the fix for the DAT1 in-band-interrupt wedge that
/// takes down the whole device (incl F0) the instant F2 is enabled in 1-bit mode.
/// Order (mmc_sdio_init_card): set the CARD to 4-bit FIRST (CCCR 0x07 RMW |= 0x02, while
/// the host is still 1-bit), THEN flip the host Data-Transfer-Width (HOST_CTRL1 bit1).
/// Verifies the card accepted it (CCCR reads back 4-bit); reverts to 1-bit if not.
/// Returns true if 4-bit is active.
fn set_bus_width_4bit() -> bool {
    let cccr = cmd52(false, 0, 0x07, 0).unwrap_or(0);
    // card -> 4-bit (clear width bits[1:0], set 0x02; do NOT touch CD_DISABLE bit7).
    let _ = cmd52(true, 0, 0x07, (cccr & !0x03) | 0x02);
    // host -> 4-bit.
    w8(HOST_CTRL1, r8(HOST_CTRL1) | 0x02);
    let rb = cmd52(false, 0, 0x07, 0).unwrap_or(0);
    unsafe { BUSWIDTH_DIAG = (rb as u32, r8(HOST_CTRL1) as u32) };
    if rb & 0x03 == 0x02 {
        true
    } else {
        // revert to 1-bit (both card + host) — keep the proven 1-bit path.
        let _ = cmd52(true, 0, 0x07, cccr & !0x03);
        w8(HOST_CTRL1, r8(HOST_CTRL1) & !0x02);
        false
    }
}
/// (CCCR 0x07 readback — 0x02 = card in 4-bit; SDHCI HOST_CTRL1 — bit1 = host 4-bit).
pub fn buswidth_diag() -> (u32, u32) {
    unsafe { BUSWIDTH_DIAG }
}

// ============================================================================
// P10 Stage B — firmware / NVRAM / CLM upload + ARMCR4 start (F2 ready)
// P10 Stage C — BCDC control + clmload + country iovar (the regdomain target)
//
// The control-layer ENCODERS below (NVRAM strip, BCDC/iovar framing, CLM chunking,
// country struct) are pure logic and correct off-metal. The SDIO/backplane TIMING
// (ALP/HT clock, ARMCR4 halt/clear order, F2-ready, SDPCM credits) is structured
// from brcmfmac + OpenBSD bwfm and iterates on metal.
//
// REGDOMAIN — three metal-proven facts (2026-07-23, cross-checked vs a live CM5
// Linux, brcmfmac source, OpenWRT, FreeBSD net80211):
//   1. The CYW43455 FIRMWARE is the regulatory authority — it enforces per-country
//      channels/power from its CLM blob. No host stack (Linux cfg80211 or FreeBSD
//      net80211) can override it; both are advisory over a FullMAC radio.
//   2. FIRMWARE VERSION MATTERS: 7.45.234 (2021) SILENTLY IGNORES the country set —
//      the radio stays world/99, ch12/13 + full ETSI 5 GHz stay blocked (the "stuck
//      at country 99" symptom). Firmware >= 7.45.265 honors it. stage-wifi-firmware.sh
//      REQUIRES >= 7.45.265 and bakes ccode=RO into the NVRAM (verbatim loader → the
//      firmware's power-on domain, deterministic; no `iw reg set` negotiation needed).
//   3. set_regdomain() below is the runtime belt-and-braces (clmload → country iovar).
//      With ccode already in NVRAM it is a confirming no-op; kept for a live re-set.
// ALL-CHANNEL SENSING (HookProbe "the OS is the sensor"): the country iovar governs
// AP/TX legality only. The DETECTION plane monitors ALL channels via RX/monitor +
// channel-hop — the firmware permits passive receive on every channel under any
// regd — so wide spectrum visibility does NOT require (nor imply) illegal TX.
// ============================================================================

/// The CYW43455 blobs, baked into the self-contained HEQK image.
pub static FW_BIN: &[u8] = include_bytes!("../../firmware/brcm/cyw43455-sdio.bin");
pub static NVRAM_TXT: &[u8] = include_bytes!("../../firmware/brcm/cyw43455-sdio-cm5.nvram.txt");
pub static CLM_BLOB: &[u8] = include_bytes!("../../firmware/brcm/cyw43455-sdio.clm_blob");

// BCM4345/6 (CYW43455) ARMCR4 geometry + F1 chip-backplane control regs.
// CRITICAL (metal + brcmfmac brcmf_chip_tcm_rambase): the 4345 firmware loads at
// 0x198000 (the CR4 TCM base), NOT 0. Only the 4-byte reset VECTOR goes to addr 0.
const RAM_BASE: u32 = 0x0019_8000; // CR4 TCM base — full firmware image loads here
const RAM_SIZE: u32 = 0x0009_8000; // 608 KiB
const RESET_VEC_ADDR: u32 = 0x0000_0000; // fw[0..4] (reset vector) → backplane addr 0
const CHIPCLKCSR: u32 = 0x1000E; // F1 clock-control (backplane)
const SBSDIO_ALP_AVAIL_REQ: u8 = 0x08;
const SBSDIO_HT_AVAIL_REQ: u8 = 0x10;
const SBSDIO_ALP_AVAIL: u8 = 0x40;
const SBSDIO_HT_AVAIL: u8 = 0x80;
const SBSDIO_FORCE_HT: u8 = 0x02; // FORCE (latch) HT, not just request — F2 needs it
// KSO (Keep-Sdio-On). On the 43455 SDIO core (rev >= 12) the backplane is GATED until
// KSO is set: ALP-clocked F1 register reads still work, but the PMU never services an
// HT request (CHIPCLKCSR stuck at 0x5a, HT_AVAIL never asserts). brcmf_sdio_kso_init
// sets this in probe_attach, BEFORE firmware download. This is the bare-metal omission
// that was blocking HT (source-verified against brcmfmac/sdio.c).
const SBSDIO_SLEEPCSR: u32 = 0x1001F; // F1 SLEEPCSR
const SBSDIO_KSO_EN: u8 = 0x01; // SLEEPCSR bit0 = keep SDIO on
// 43455 F2 data-path watermark (brcmf_sdio_bus_init, CY_43455_* constants).
const SBSDIO_WATERMARK: u32 = 0x10008;
const SBSDIO_DEVICE_CTL: u32 = 0x10009;
const SBSDIO_DEVCTL_F2WM_ENAB: u8 = 0x10;
const SBSDIO_FUNC1_MESBUSYCTRL: u32 = 0x1001D;
const CY_43455_F2_WATERMARK: u8 = 0x60;
const CY_43455_MESBUSYCTRL: u8 = 0xD0; // MES_WATERMARK(0x50) | MESBUSYCTRL_ENAB(0x80)
// SDIO-dev core sdpcmd_regs offsets (from the SDIO_DEV core regbase).
const SD_REG_TOSBMAILBOX: u32 = 0x40; // host -> firmware mailbox (SMB_INT_ACK etc.)
const SD_REG_TOSBMAILBOXDATA: u32 = 0x48;
const SD_REG_TOHOSTMAILBOXDATA: u32 = 0x4C; // firmware -> host mailbox data (DEVREADY/FWREADY)
const SD_REG_HOSTINTMASK: u32 = 0x24;
const SMB_INT_ACK: u32 = 0x02; // ack the firmware's software mailbox interrupt
const SDPCM_VERSION_MB: u32 = 4 << 16; // SDPCM_PROT_VERSION(4) << SMB_DATA_VERSION_SHIFT(16)
const HOSTINTMASK: u32 = 0x2000_00F0; // I_HMB_SW_MASK(0xF0) | I_CHIPACTIVE(1<<29)
// SDIO func-2 (WLAN data) block size = 512 (FBR 0x210/0x211).
const FBR_F2_BLKSIZE_LO: u32 = 0x210;
const FBR_F2_BLKSIZE_HI: u32 = 0x211;
// F1 backplane SBADDR window registers (byte, F1).
const SBADDR_LOW: u32 = 0x1000A;
const SBADDR_MID: u32 = 0x1000B;
const SBADDR_HIGH: u32 = 0x1000C;
// Backplane core part numbers (DMP/AMBA) we look up in the EROM.
const CORE_ARM_CR4: u32 = 0x83E;
const CORE_80211: u32 = 0x812; // D11
const CORE_SDIO_DEV: u32 = 0x829;
// AI (aidmp) core-wrapper registers — offsets from a core's WRAPBASE.
const AI_IOCTL: u32 = 0x0408;
const AI_RESET_CTL: u32 = 0x0800;
const AI_IOCTL_CLK: u32 = 0x0001;
const AI_IOCTL_FGC: u32 = 0x0002;
const AI_RESET_CTL_RESET: u32 = 0x0001;
const ARMCR4_IOCTL_CPUHALT: u32 = 0x0020;
const D11_IOCTL_PHYCLOCKEN: u32 = 0x0004;
const D11_IOCTL_PHYRESET: u32 = 0x0008;
// EROM descriptor decode (brcmf_chip_dmp_erom_scan).
const DMP_DESC_MSK: u32 = 0xF;
const DMP_DESC_COMPONENT: u32 = 0x1;
const DMP_DESC_MASTER_PORT: u32 = 0x3;
const DMP_DESC_ADDRESS: u32 = 0x5;
const DMP_DESC_ADDRSIZE_GT32: u32 = 0x8;
const DMP_DESC_EOT: u32 = 0xF;
const DMP_COMP_PARTNUM_S: u32 = 8;
const DMP_COMP_PARTNUM: u32 = 0x000F_FF00;
const DMP_SLAVE_ADDR_BASE: u32 = 0xFFFF_F000;
const DMP_SLAVE_TYPE: u32 = 0x0000_00C0;
const DMP_SLAVE_TYPE_S: u32 = 6;
const DMP_SLAVE_SIZE_TYPE: u32 = 0x0000_0030;
const DMP_SLAVE_SIZE_TYPE_S: u32 = 4;
const DMP_SLAVE_SIZE_DESC: u32 = 0x3;
// CCCR: I/O-enable 0x02, I/O-ready 0x03. F2 = bit2.
const SDIO_FUNC_ENABLE: u32 = 0x02;
const SDIO_FUNC_READY: u32 = 0x03;
const SDIO_F2: u8 = 0x04;

/// Process the NVRAM text into the firmware's download format: strip comments +
/// whitespace, keep `key=value\0` pairs, pad to 4 bytes, then append the trailer
/// word `(len/4) | (~(len/4) << 16)`. Mirrors brcmfmac `brcmf_process_nvram`.
/// Returns the byte length written into `out`.
pub fn nvram_strip(src: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < src.len() {
        // Skip leading whitespace on a line.
        while i < src.len() && (src[i] == b' ' || src[i] == b'\t' || src[i] == b'\r' || src[i] == b'\n') {
            i += 1;
        }
        if i >= src.len() {
            break;
        }
        if src[i] == b'#' {
            // comment — skip to EOL
            while i < src.len() && src[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // copy "key=value" until EOL, dropping trailing spaces; emit a NUL.
        let start = n;
        while i < src.len() && src[i] != b'\n' && src[i] != b'\r' {
            if n < out.len() {
                out[n] = src[i];
                n += 1;
            }
            i += 1;
        }
        // trim trailing spaces of this entry
        while n > start && (out[n - 1] == b' ' || out[n - 1] == b'\t') {
            n -= 1;
        }
        if n > start && n < out.len() {
            out[n] = 0;
            n += 1;
        } else {
            n = start; // blank line — drop
        }
    }
    // pad to 4-byte boundary
    while n % 4 != 0 && n < out.len() {
        out[n] = 0;
        n += 1;
    }
    // trailer word = (tokens & 0xffff) | ((~tokens & 0xffff) << 16), tokens = n/4.
    // Mask both halves (brcmf_process_nvram) — correct even if the NVRAM grows past
    // 256 KiB (the unmasked form would corrupt the high half).
    let tokens = (n / 4) as u32;
    let trailer = (tokens & 0xffff) | ((!tokens & 0xffff) << 16);
    if n + 4 <= out.len() {
        out[n..n + 4].copy_from_slice(&trailer.to_le_bytes());
        n += 4;
    }
    n
}

/// Build the `country` iovar payload: `brcmf_fil_country_le`
/// `{ char country_abbrev[4]; __le32 rev; char ccode[4]; }` (12 B). `iso` is the
/// 2-letter code; `rev` is the CLM/NVRAM regulatory revision (NOT always 0 — see
/// the FreeBSD/OpenBSD cross-check: map the (ccode,rev) pair for correct limits).
pub fn country_payload(iso: &[u8; 2], rev: i32, out: &mut [u8; 12]) {
    *out = [0; 12];
    out[0] = iso[0];
    out[1] = iso[1];
    out[4..8].copy_from_slice(&rev.to_le_bytes());
    out[8] = iso[0];
    out[9] = iso[1];
}

/// Build a `"<name>\0<data>"` iovar buffer (brcmfmac iovar wire form). Returns len.
pub fn iovar_buf(name: &[u8], data: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0;
    for &b in name {
        if n < out.len() {
            out[n] = b;
            n += 1;
        }
    }
    if n < out.len() {
        out[n] = 0;
        n += 1;
    }
    for &b in data {
        if n < out.len() {
            out[n] = b;
            n += 1;
        }
    }
    n
}

/// `clmload` chunk header — `struct brcmf_dload_data_le` (OpenBSD `bwfm_dload_data`
/// is byte-identical): `{ u16 flag; u16 type; u32 len; u32 crc; data[] }`.
/// `flag = HANDLER_VER(1<<12) | BEGIN(1<<1) on first | END(1<<2) on last`; `type=CLM(2)`.
pub const DL_HANDLER_VER: u16 = 1 << 12;
pub const DL_BEGIN: u16 = 1 << 1;
pub const DL_END: u16 = 1 << 2;
pub const DL_TYPE_CLM: u16 = 2;
pub const DL_CHUNK: usize = 1400;

/// Fill `out` with one clmload dload chunk header + `chunk` bytes; returns total len.
pub fn clm_chunk(flag: u16, chunk: &[u8], out: &mut [u8]) -> usize {
    // AUDIT L-11: `out.len() - 12` underflows on a usize for a short buffer, so
    // `min` then returns chunk.len() and the copy_from_slice below panics ->
    // panic=abort -> hang on metal. This is pub, so guard it at the door.
    if out.len() < 12 {
        return 0;
    }
    let len = chunk.len() as u32;
    out[0..2].copy_from_slice(&(flag | DL_HANDLER_VER).to_le_bytes());
    out[2..4].copy_from_slice(&DL_TYPE_CLM.to_le_bytes());
    out[4..8].copy_from_slice(&len.to_le_bytes());
    out[8..12].copy_from_slice(&0u32.to_le_bytes()); // crc unused
    let n = chunk.len().min(out.len() - 12);
    out[12..12 + n].copy_from_slice(&chunk[..n]);
    12 + n
}

// --- SDIO CMD53 write (byte mode) + backplane windowed write ------------------
fn cmd53_write(fnum: u32, addr: u32, data: &[u8]) -> bool {
    let n = data.len().min(512);
    w16(BLK_SIZE_CNT, n as u16);
    w16(BLK_SIZE_CNT + 2, 1);
    // Transfer Mode = BLK_CNT_EN, WRITE direction (READ bit clear), single block.
    // Explicit write clears any stale READ bit a prior cmd53_read left.
    w16(CMD_XFER, XM_BLKCNT_EN);
    let arg = (1 << 31)            // write
        | ((fnum & 7) << 28)
        | (0 << 27)                 // byte mode
        | (1 << 26)                 // incrementing
        | ((addr & 0x1_FFFF) << 9)
        | (n as u32 & 0x1FF);
    if cmd(CMD53_IO_RW_EXTENDED, arg, RESP_48, true, true).is_none() {
        unsafe { CMD53_DIAG = (1, r32(INT_STATUS), r32(PRESENT_STATE)) };
        return false;
    }
    // Wait Buffer-Write-Ready before pushing the FIFO — writing 0x20 early loses the
    // block and XFER_COMPLETE never fires (the P10 step-3 firmware-write failure).
    // (Present-State BUF_WR_EN b10 never asserts on this controller — gate on the
    // INT bit only, or the wait spurious-times-out even though the FIFO is ready.)
    let mut spin = 0u32;
    while r32(INT_STATUS) & INT_BUF_WR_RDY == 0 {
        if r32(INT_STATUS) & INT_ERR != 0 {
            unsafe { CMD53_DIAG = (2, r32(INT_STATUS), r32(PRESENT_STATE)) };
            return false;
        }
        spin += 1;
        if spin > 1_000_000 {
            unsafe { CMD53_DIAG = (3, r32(INT_STATUS), r32(PRESENT_STATE)) };
            return false;
        }
    }
    // PIO out: pack bytes into the 32-bit data port.
    let mut i = 0;
    while i < n {
        let mut word = 0u32;
        for b in 0..4 {
            if i < n {
                word |= (data[i] as u32) << (b * 8);
                i += 1;
            }
        }
        w32(BUF_DATA, word);
    }
    spin = 0;
    while r32(INT_STATUS) & INT_XFER_DONE == 0 {
        if r32(INT_STATUS) & INT_ERR != 0 {
            unsafe { CMD53_DIAG = (4, r32(INT_STATUS), r32(PRESENT_STATE)) };
            return false;
        }
        spin += 1;
        if spin > 2_000_000 {
            unsafe { CMD53_DIAG = (5, r32(INT_STATUS), r32(PRESENT_STATE)) };
            return false;
        }
    }
    true
}

static mut CMD53_DIAG: (u8, u32, u32) = (0, 0, 0);
/// (fail stage 1=cmd 2=err-wait-wr 3=buf-wr-rdy-timeout 4=err-xfer 5=xfer-timeout,
/// INT_STATUS, PRESENT_STATE) from the last cmd53_write failure.
pub fn cmd53_diag() -> (u8, u32, u32) {
    unsafe { CMD53_DIAG }
}

/// Set the SDIO function-1 block size (FBR 0x110/0x111 = F1_BLOCK_SIZE) via CMD52.
/// brcmfmac does this BEFORE any block-mode CMD53; without it the card's F1 data
/// engine is framed to a 0-length block → every data transfer DATA-TIMEOUTs.
fn set_func_block_size() {
    let _ = cmd52(true, 0, FBR_F1_BLKSIZE_LO, (F1_BLOCK_SIZE & 0xFF) as u8);
    let _ = cmd52(true, 0, FBR_F1_BLKSIZE_HI, ((F1_BLOCK_SIZE >> 8) & 0xFF) as u8);
}

/// BLOCK-mode CMD53 write: `nblocks` blocks of F1_BLOCK_SIZE (64) B (data.len() ==
/// nblocks*64). This is how brcmfmac uploads firmware. PIO: wait BUF_WR_RDY before
/// EACH block, push 64 B, then wait Transfer-Complete once at the end.
fn cmd53_write_blocks(fnum: u32, addr: u32, data: &[u8], nblocks: u32) -> bool {
    // AUDIT L-10: the push loop below indexes data[i..i+3] for nblocks*64 bytes
    // with no length check. The sole caller currently pins nblocks to 1, but that
    // .min(1) is a documented temporary isolation measure -- relaxing it for
    // throughput would turn this into a slice-index panic (= abort = hang on metal).
    let need = (nblocks as usize) * F1_BLOCK_SIZE as usize;
    if data.len() < need {
        return false;
    }
    w16(BLK_SIZE_CNT, F1_BLOCK_SIZE as u16); // block size = 64
    w16(BLK_SIZE_CNT + 2, nblocks as u16); // block count
    w16(CMD_XFER, XM_BLKCNT_EN | XM_MULTI); // block mode, multi, write dir
    let arg = (1 << 31)               // write
        | ((fnum & 7) << 28)
        | (1 << 27)                    // BLOCK mode
        | (1 << 26)                    // incrementing address
        | ((addr & 0x1_FFFF) << 9)
        | (nblocks & 0x1FF);           // block count in the count field
    if cmd(CMD53_IO_RW_EXTENDED, arg, RESP_48, true, true).is_none() {
        unsafe { CMD53_DIAG = (1, r32(INT_STATUS), r32(PRESENT_STATE)) };
        return false;
    }
    let mut i = 0usize;
    for _ in 0..nblocks {
        let mut spin = 0u32;
        while r32(INT_STATUS) & INT_BUF_WR_RDY == 0 {
            if r32(INT_STATUS) & INT_ERR != 0 {
                unsafe { CMD53_DIAG = (2, r32(INT_STATUS), r32(PRESENT_STATE)) };
                return false;
            }
            spin += 1;
            if spin > 1_000_000 {
                unsafe { CMD53_DIAG = (3, r32(INT_STATUS), r32(PRESENT_STATE)) };
                return false;
            }
        }
        w32(INT_STATUS, INT_BUF_WR_RDY); // clear (W1C) so the next block waits fresh
        // push one 64-byte block (16 words)
        for _ in 0..(F1_BLOCK_SIZE / 4) {
            let word = (data[i] as u32)
                | ((data[i + 1] as u32) << 8)
                | ((data[i + 2] as u32) << 16)
                | ((data[i + 3] as u32) << 24);
            w32(BUF_DATA, word);
            i += 4;
        }
    }
    let mut spin = 0u32;
    while r32(INT_STATUS) & INT_XFER_DONE == 0 {
        if r32(INT_STATUS) & INT_ERR != 0 {
            unsafe { CMD53_DIAG = (4, r32(INT_STATUS), r32(PRESENT_STATE)) };
            return false;
        }
        spin += 1;
        if spin > 4_000_000 {
            unsafe { CMD53_DIAG = (5, r32(INT_STATUS), r32(PRESENT_STATE)) };
            return false;
        }
    }
    true
}

/// Write `data` to backplane address `addr` in ≤32 KiB windows (F1). Uses BLOCK-mode
/// CMD53 (64-B blocks, ≤256 per burst) for the bulk, byte-mode for a <64-B tail.
fn backplane_write(mut addr: u32, data: &[u8]) -> bool {
    let mut off = 0usize;
    while off < data.len() {
        set_backplane_window(addr);
        let win_off = (addr & 0x7FFF) as usize;
        let space = 0x8000 - win_off; // to the 32 KiB window edge
        let avail = (data.len() - off).min(space);
        let fbs = F1_BLOCK_SIZE as usize;
        if avail >= fbs {
            // SINGLE 64-B block per CMD53 — sidesteps the multi-block PIO FIFO flow
            // (the card holds DAT_INHIBIT busy and doesn't re-assert BUF_WR_RDY for
            // block 2). Slower (watchdog is disarmed by now) but isolates the issue.
            let nblocks = (avail / fbs).min(1);
            let bytes = nblocks * fbs;
            if !cmd53_write_blocks(1, (win_off as u32) | 0x8000, &data[off..off + bytes], nblocks as u32) {
                return false;
            }
            off += bytes;
            addr += bytes as u32;
        } else {
            // <64-B tail (end of image / window): byte-mode.
            if !cmd53_write(1, (win_off as u32) | 0x8000, &data[off..off + avail]) {
                return false;
            }
            off += avail;
            addr += avail as u32;
        }
    }
    true
}

// --- 32-bit backplane register access via the F1 window -------------------------
// Uses CMD52 BYTE access (offset 0..3, no 4-byte flag) — the proven path that read
// the chip-ID in Stage A. CMD53 data-phase register reads returned failure here
// (0xFFFFFFFF), so we do NOT rely on it for the EROM walk / AI reset registers.
fn bp_r32(addr: u32) -> u32 {
    set_backplane_window(addr);
    let base = addr & 0x7FFF;
    let mut b = [0u8; 4];
    for i in 0..4u32 {
        b[i as usize] = cmd52(false, 1, base + i, 0).unwrap_or(0xFF);
    }
    u32::from_le_bytes(b)
}
fn bp_w32(addr: u32, val: u32) -> bool {
    set_backplane_window(addr);
    // 32-bit ATOMIC write via CMD53 (4-byte-access flag 0x8000). CMD52 byte writes
    // do NOT take on the AI wrapper control regs (IOCTL/RESET_CTL) — they need a
    // single 32-bit access, so the CR4 CPUHALT never latched (halted=false) and the
    // TCM stayed non-writable. Needs the func block size set first (it is, in
    // firmware_upload before cr4_set_passive). Reads still use CMD52 bytes (work).
    cmd53_write(1, (addr & 0x7FFF) | 0x8000, &val.to_le_bytes())
}

// --- EROM walk: find a core's (regbase, wrapbase) by DMP part number -------------
// Mirrors brcmf_chip_dmp_erom_scan + _get_regaddr. The EROM lists each component
// (CIA/CIB) then its address descriptors; we take the first SLAVE address as regbase
// and the first WRAPPER (slave- or master-wrap) address as wrapbase.
static mut EROM_DIAG: (u32, u32, u32) = (0, 0, 0); // (eromptr, cr4_base, cr4_wrap)
#[inline]
fn erom_rd(a: &mut u32) -> u32 {
    let v = bp_r32(*a);
    *a += 4;
    v
}
/// Extract (regbase, wrapbase) for the component whose descriptors start at `*a`
/// (just past CIA+CIB). Faithful to brcmf_chip_dmp_get_regaddr: the first descriptor
/// sets the wrapper type (master-port → MWRAP; a non-slave address → MWRAP else SWRAP),
/// then we scan address descriptors for the first SLAVE (regbase) and first matching
/// WRAP (wrapbase), skipping GT32 upper words and size-descriptor words.
fn erom_get_regaddr(a: &mut u32) -> (u32, u32) {
    let (mut regbase, mut wrapbase) = (0u32, 0u32);
    let first = erom_rd(a);
    let fd = first & DMP_DESC_MSK;
    let wraptype: u32 = if fd == DMP_DESC_MASTER_PORT {
        3 // MWRAP
    } else if fd == DMP_DESC_ADDRESS {
        if (first & DMP_SLAVE_TYPE) >> DMP_SLAVE_TYPE_S != 0 { 3 } else { 2 }
    } else {
        *a -= 4; // not a valid component body
        return (0, 0);
    };
    let mut guard = 0u32;
    loop {
        guard += 1;
        if guard > 64 {
            break;
        }
        // find the next ADDRESS or COMPONENT/EOT descriptor
        //
        // AUDIT H-1: this scan MUST be bounded. bp_r32 returns 0x0000_0000 when the
        // backplane is unclocked/asleep (the documented deep-sleep state, see the
        // KSO/DEVON note in read_sdpcm_frame) — and desc==0 matches none of the three
        // exit conditions, so an unbounded loop here spins forever issuing 7 SDIO
        // commands per iteration. It is reachable from read_sdpcm_frame/bcdc_dcmd,
        // i.e. on the live WiFi RX path. (0xFFFF_FFFF escapes via EOT; 0 does not.)
        let mut val;
        let mut desc;
        let mut scan = 0u32;
        loop {
            val = erom_rd(a);
            desc = val & DMP_DESC_MSK;
            if desc == DMP_DESC_ADDRESS || desc == DMP_DESC_COMPONENT || desc == DMP_DESC_EOT {
                break;
            }
            scan += 1;
            if scan > 32 {
                return (0, 0); // brcmf_chip_dmp_get_regaddr never scans further
            }
        }
        if desc != DMP_DESC_ADDRESS {
            *a -= 4; // leave the COMPONENT/EOT for the outer scan
            break;
        }
        if val & DMP_DESC_ADDRSIZE_GT32 != 0 {
            let _ = erom_rd(a); // 64-bit address: skip high word
        }
        if (val & DMP_SLAVE_SIZE_TYPE) >> DMP_SLAVE_SIZE_TYPE_S == DMP_SLAVE_SIZE_DESC {
            let sz = erom_rd(a);
            if sz & DMP_DESC_ADDRSIZE_GT32 != 0 {
                let _ = erom_rd(a);
            }
        }
        let stype = (val & DMP_SLAVE_TYPE) >> DMP_SLAVE_TYPE_S;
        if regbase == 0 && stype == 0 {
            regbase = val & DMP_SLAVE_ADDR_BASE;
        }
        if wrapbase == 0 && stype == wraptype {
            wrapbase = val & DMP_SLAVE_ADDR_BASE;
        }
        if regbase != 0 && wrapbase != 0 {
            break;
        }
    }
    (regbase, wrapbase)
}
fn erom_find_core(partnum: u32) -> Option<(u32, u32)> {
    let eromptr = bp_r32(SI_ENUM_BASE + 0xFC);
    if partnum == CORE_ARM_CR4 {
        unsafe { EROM_DIAG.0 = eromptr };
    }
    // AUDIT H-1: bail immediately on an implausible EROM pointer rather than
    // walking nonexistent backplane space. 0 = backplane asleep, !0 = bus dead.
    if eromptr == 0 || eromptr == 0xFFFF_FFFF || eromptr & 3 != 0 {
        return None;
    }
    let mut a = eromptr;
    let mut guard = 0u32;
    while guard < 1024 {
        guard += 1;
        let cia = erom_rd(&mut a);
        if (cia & DMP_DESC_MSK) == DMP_DESC_EOT {
            break;
        }
        if (cia & DMP_DESC_MSK) != DMP_DESC_COMPONENT {
            continue; // skip stray non-component words
        }
        let pn = (cia & DMP_COMP_PARTNUM) >> DMP_COMP_PARTNUM_S;
        let _cib = erom_rd(&mut a); // CIB
        let (regbase, wrapbase) = erom_get_regaddr(&mut a);
        if pn == partnum {
            if partnum == CORE_ARM_CR4 {
                unsafe { EROM_DIAG.1 = regbase; EROM_DIAG.2 = wrapbase };
            }
            return Some((regbase, wrapbase));
        }
    }
    None
}
/// (eromptr, discovered CR4 regbase, CR4 wrapbase) — for the [P10-B] diag.
pub fn erom_diag() -> (u32, u32, u32) {
    unsafe { EROM_DIAG }
}
static mut CR4_HALT_DIAG: (u32, u32) = (0, 0);
/// (CR4 IOCTL, CR4 RESET_CTL) read back after the halt — CPUHALT(0x20) should be set,
/// RESET_CTL should be 0. Tells us if the CR4 is really halted (TCM writable).
pub fn cr4_halt_diag() -> (u32, u32) {
    unsafe { CR4_HALT_DIAG }
}
/// Raw EROM dump (first `out.len()` 32-bit words) — for decoding the descriptor
/// stream by hand if the walk still misses the CR4.
pub fn erom_dump(out: &mut [u32]) {
    let mut a = bp_r32(SI_ENUM_BASE + 0xFC);
    for w in out.iter_mut() {
        *w = erom_rd(&mut a);
    }
}

// --- AI (aidmp) core reset/enable (brcmf_chip_ai_coredisable / _resetcore) -------
fn ai_coredisable(wrapbase: u32, prereset: u32, reset: u32) {
    if bp_r32(wrapbase + AI_RESET_CTL) & AI_RESET_CTL_RESET == 0 {
        bp_w32(wrapbase + AI_IOCTL, prereset | AI_IOCTL_FGC | AI_IOCTL_CLK);
        let _ = bp_r32(wrapbase + AI_IOCTL); // posted-write flush
        bp_w32(wrapbase + AI_RESET_CTL, AI_RESET_CTL_RESET);
        delay(20);
        let mut g = 0;
        while bp_r32(wrapbase + AI_RESET_CTL) & AI_RESET_CTL_RESET == 0 && g < 300 {
            g += 1;
        }
    }
    bp_w32(wrapbase + AI_IOCTL, reset | AI_IOCTL_FGC | AI_IOCTL_CLK);
    let _ = bp_r32(wrapbase + AI_IOCTL);
}
fn ai_resetcore(wrapbase: u32, prereset: u32, reset: u32, postreset: u32) {
    ai_coredisable(wrapbase, prereset, reset);
    let mut count = 0;
    while bp_r32(wrapbase + AI_RESET_CTL) & AI_RESET_CTL_RESET != 0 {
        bp_w32(wrapbase + AI_RESET_CTL, 0); // out of reset
        count += 1;
        if count > 50 {
            break;
        }
        delay(60);
    }
    bp_w32(wrapbase + AI_IOCTL, postreset | AI_IOCTL_CLK); // note: no FGC
    let _ = bp_r32(wrapbase + AI_IOCTL);
}

/// CR4 "passive" — halt the CR4 CPU (TCM writable) + reset the D11 core. Returns
/// the CR4 (regbase, wrapbase) on success, or None if the EROM lookup failed.
fn cr4_set_passive() -> Option<(u32, u32)> {
    let (cr4b, cr4w) = erom_find_core(CORE_ARM_CR4)?;
    if cr4w == 0 {
        return None;
    }
    // disable_arm(CR4): keep only the CPUHALT bit, resetcore with CPUHALT held.
    let keep = bp_r32(cr4w + AI_IOCTL) & ARMCR4_IOCTL_CPUHALT;
    ai_resetcore(cr4w, keep, ARMCR4_IOCTL_CPUHALT, ARMCR4_IOCTL_CPUHALT);
    // DIAG: read back the halt state. Expect IOCTL & CPUHALT(0x20) set, RESET_CTL=0
    // (out of backplane reset, CPU halted). If not, the TCM at 0x198000 isn't
    // writable and the F1 firmware write stalls (no XFER_COMPLETE) — the step-3 wall.
    unsafe {
        CR4_HALT_DIAG = (bp_r32(cr4w + AI_IOCTL), bp_r32(cr4w + AI_RESET_CTL));
    }
    // Reset the D11 (802.11) core.
    if let Some((_, d11w)) = erom_find_core(CORE_80211) {
        if d11w != 0 {
            ai_resetcore(
                d11w,
                D11_IOCTL_PHYRESET | D11_IOCTL_PHYCLOCKEN,
                D11_IOCTL_PHYCLOCKEN,
                D11_IOCTL_PHYCLOCKEN,
            );
        }
    }
    Some((cr4b, cr4w))
}

// ARM CR4 core registers (from CR4 REGBASE 0x18002000) for TCM bank-size computation.
const ARMCR4_CAP: u32 = 0x04; // bank counts: TCBANB[3:0]=A banks, TCBBNB[7:4]=B banks
const ARMCR4_BANKIDX: u32 = 0x40; // select bank to inspect
const ARMCR4_BANKINFO: u32 = 0x44; // BSZ[5:0]: bank size = 8192*(BSZ+1)

/// Compute the real CR4 TCM size by summing bank sizes — brcmf_chip_tcm_ramsize.
/// HEQK hardcoded RAM_SIZE=0x98000; the hardware value drives correct NVRAM placement
/// (firmware reads NVRAM from the TOP of its real RAM) and the firmware-alive check.
fn cr4_ramsize(cr4b: u32) -> u32 {
    let cap = bp_r32(cr4b + ARMCR4_CAP);
    let totb = (cap & 0xf) + ((cap & 0xf0) >> 4); // A banks + B banks
    let mut ramsize = 0u32;
    let mut idx = 0u32;
    while idx < totb && idx < 32 {
        bp_w32(cr4b + ARMCR4_BANKIDX, idx);
        let bxinfo = bp_r32(cr4b + ARMCR4_BANKINFO);
        // bank size = ((BSZ & 0x7f) + 1) * blksize; blksize = 8192, or 1024 if BLK_1K.
        let blksize = if bxinfo & 0x200 != 0 { 1024 } else { 8192 };
        ramsize += ((bxinfo & 0x7f) + 1) * blksize;
        idx += 1;
    }
    ramsize
}

/// CR4 "activate" — write the reset vector to backplane addr 0 and release the CR4
/// (postreset IOCTL=0 clears CPUHALT → CPU boots from the vector).
fn cr4_activate(cr4w: u32, rstvec: u32) {
    // Clear the SDIO core's intstatus (brcmf_sdio_buscore_activate).
    if let Some((sdb, _)) = erom_find_core(CORE_SDIO_DEV) {
        if sdb != 0 {
            let _ = bp_w32(sdb + 0x20, 0xFFFF_FFFF); // sdpcmd intstatus
        }
    }
    let _ = bp_w32(RESET_VEC_ADDR, rstvec);
    unsafe { core::arch::asm!("dsb sy") };
    ai_resetcore(cr4w, ARMCR4_IOCTL_CPUHALT, 0, 0);
}

/// P10 Stage B — download firmware + NVRAM, start the ARMCR4 core, enable F2.
/// Returns true once F2 reports ready (firmware alive). Structured from brcmfmac
/// `brcmf_sdio_download_firmware` + OpenBSD `bwfm_sdio` — timing iterates on metal.
pub fn firmware_upload(nvram_scratch: &mut [u8]) -> bool {
    unsafe { FW_STEP = 1 };
    // 0. RAISE THE SDIO CLOCK before the bulk transfer. Enumeration ran at the ~400
    //    kHz init clock; pushing ~600 KB of firmware at that speed takes long enough
    //    to trip the boot watchdog before F2 comes up (no [P10-B], board reboots).
    //    clk_emmc2 = 100 MHz base; divisor 4 → 12.5 MHz. 25 MHz gave a DATA CRC
    //    ERROR (INT err 0x0020) — marginal signal integrity in default-speed mode on
    //    the CM5 SDIO2 traces; 12.5 MHz is conservative but still ~30x the init clock
    //    (600 KB in ~0.5 s), well under the watchdog. Tune up with high-speed mode later.
    set_clock(4);
    delay(1_000);
    // 1. ALP: request + wait.
    let _ = cmd52(true, 1, CHIPCLKCSR, SBSDIO_ALP_AVAIL_REQ);
    for _ in 0..50 {
        if cmd52(false, 1, CHIPCLKCSR, 0).map(|v| v & SBSDIO_ALP_AVAIL).unwrap_or(0) != 0 {
            break;
        }
        delay(1_000);
    }
    // 1b. ENABLE KSO — the actual root cause of the stuck HT. On the 43455 SDIO core
    //     (rev >= 12) the backplane is gated until KSO (SLEEPCSR bit0) is set: ALP-clocked
    //     register reads still work (so we saw a live 0x5a), but the PMU never services
    //     the backplane HT request, so HT_AVAIL never asserts no matter how we request it.
    //     brcmf_sdio_kso_init sets this in probe_attach, before firmware download.
    kso_enable();
    // 2. HALT the CR4, THEN acquire HT, THEN download — brcmf order: HT is requested and
    //    confirmed BEFORE firmware write and BEFORE CR4 release (HT is produced by the PMU
    //    from OTP defaults, independent of firmware). fwverify proved the ALP download is
    //    byte-perfect, so TCM corruption was never the issue — the missing KSO was.
    set_func_block_size();
    let (cr4b, cr4w) = match cr4_set_passive() {
        Some(v) => v,
        None => return false,
    };
    // Compute the REAL TCM size from the CR4 bank registers — HEQK's hardcoded 0x98000
    // may be wrong; the firmware reads NVRAM from the top of its actual RAM.
    // AUDIT M-5: cr4_ramsize is derived entirely from device reads, and bp_r32
    // returns 0xFFFF_FFFF when a backplane read fails. That yields 30 banks x 128 x
    // 8192 ~= 31 MB instead of the real 0xC8000, which would place the NVRAM blob
    // ~31 MB past the TCM (firmware then finds no trailer and silently never
    // readies F2) and walk ~960 windows of nonexistent backplane space -- presenting
    // as a mysterious timeout rather than a failed register read. Gate it to a
    // plausible band for BCM4345/6 and fall back to the known-good constant.
    let ramsize = cr4_ramsize(cr4b);
    let ramsize = if (0x4_0000..=0x20_0000).contains(&ramsize) {
        ramsize
    } else {
        RAM_SIZE
    };
    unsafe { RAM_SIZE_DIAG = ramsize };
    // 3. Request HT the CLEAN brcmf_sdio_htclk way: write CHIPCLKCSR = HT_AVAIL_REQ (0x10)
    //    ALONE (NOT OR'd with FORCE_HT — forcing HT during initial bring-up is what sr_init
    //    does post-firmware, and doing it early can leave the PLL never latching HT_AVAIL).
    //    Then poll for HT_AVAIL (0x80). Want clk = 0xC0 (HT_AVAIL | ALP_AVAIL).
    let _ = cmd52(true, 1, CHIPCLKCSR, SBSDIO_HT_AVAIL_REQ);
    let mut clk = 0u8;
    for _ in 0..300 {
        clk = cmd52(false, 1, CHIPCLKCSR, 0).unwrap_or(0);
        if clk & SBSDIO_HT_AVAIL != 0 {
            break;
        }
        delay(1_000);
    }
    unsafe { HT_DIAG = clk as u32 };
    unsafe { FW_STEP = 2 };
    // 3b. ISOLATION TEST — if the clean HT request produced NO PMU transition
    //     (res_pending stayed 0, HT_AVAIL never set), force the HT-chain resources
    //     directly through the PMU resource masks. This separates the two remaining
    //     causes definitively:
    //       - HT_AVAIL comes up now  => the PLL/LPO works; the bug is the request path
    //         (SDIO-core clock request not reaching the PMU).
    //       - HT_AVAIL still down     => the PLL/LPO physically can't produce HT under
    //         these conditions (LPO/sequencer/PLL-lock problem).
    //     max_res_mask is the ceiling, so widen it FIRST, then min_res_mask pulls the
    //     resource up; pulse PMU_CTL.PLL_UPD to kick the sequencer. Diagnostic only.
    if clk & SBSDIO_HT_AVAIL == 0 {
        let cc = SI_ENUM_BASE;
        let ht_bits = HT_RES_BITS;
        let maxr = bp_r32(cc + CC_MAX_RES_MASK);
        let minr = bp_r32(cc + CC_MIN_RES_MASK);
        bp_w32(cc + CC_MAX_RES_MASK, maxr | ht_bits);
        bp_w32(cc + CC_MIN_RES_MASK, minr | ht_bits);
        bp_w32(cc + CC_PMUCONTROL, bp_r32(cc + CC_PMUCONTROL) | PMU_CTL_PLL_UPD);
        let mut fclk = 0u8;
        let mut fres = 0u32;
        for _ in 0..300 {
            fclk = cmd52(false, 1, CHIPCLKCSR, 0).unwrap_or(0);
            fres = bp_r32(cc + CC_RES_STATE);
            if fclk & SBSDIO_HT_AVAIL != 0 {
                break;
            }
            delay(1_000);
        }
        unsafe {
            HT_FORCE_DIAG = (
                fclk as u32,                    // CHIPCLKCSR after forcing (want 0x80 bit)
                fres,                           // res_state (want HT bits 28/29 up)
                bp_r32(cc + CC_RES_PENDING),   // res_pending
                bp_r32(cc + CC_PMUSTATUS),     // pmustatus (PST_HTAVAIL 0x04)
            );
        }
    }
    // #4 register dump: PMU + ChipCommon after HALT + HT, before download.
    unsafe { PMU_DUMP[0] = pmu_dump() };
    unsafe { FW_STEP = 3 };
    // 4. Firmware → TCM 0x198000, then #1 BYTE-FOR-BYTE READ-BACK VERIFY (sampled).
    if !backplane_write(RAM_BASE, FW_BIN) {
        return false;
    }
    unsafe { FW_VERIFY = backplane_verify(RAM_BASE, FW_BIN) };
    unsafe { FW_STEP = 4 };
    // 5. NVRAM at the TOP OF THE *REAL* RAM (RAM_BASE + hardware ramsize - nlen). The
    //    closed CR4 firmware scans backward from the physical RAM top (0x198000+0xC8000
    //    = 0x260000) for the NVRAM magic trailer. HEQK's old hardcoded 0x98000 put the
    //    blob at ~0x230000 — the firmware found no trailer at 0x260000, silently aborted
    //    init (no MAC/RF params), and F2 never readied. Use the computed hardware size.
    let ram_top = if ramsize >= RAM_SIZE { ramsize } else { RAM_SIZE };
    let nlen = nvram_strip(NVRAM_TXT, nvram_scratch);
    let nvram_addr = RAM_BASE + ram_top - (nlen as u32);
    unsafe { NVRAM_ADDR_DIAG = nvram_addr };
    if !backplane_write(nvram_addr, &nvram_scratch[..nlen]) {
        return false;
    }
    unsafe { FW_STEP = 5 };
    // 6. CR4 ACTIVATE — reset vector (fw[0..4]) → addr 0, clear CPUHALT → CPU boots.
    let rstvec = u32::from_le_bytes([FW_BIN[0], FW_BIN[1], FW_BIN[2], FW_BIN[3]]);
    cr4_activate(cr4w, rstvec);
    unsafe { FW_STEP = 6 };
    // #4 register dump: PMU + ChipCommon AFTER CR4 release.
    unsafe { PMU_DUMP[1] = pmu_dump() };
    // CPU-ALIVE CHECK — once the firmware boots it consumes the NVRAM and writes the
    // SDPCM-shared-structure pointer to the last RAM word (RAM_BASE+ramsize-4). If that
    // word becomes a valid RAM pointer, the CR4 is EXECUTING; if it stays the NVRAM
    // trailer token / unchanged, the firmware never ran. Poll it during the F2 wait.
    let shared_ptr_addr = RAM_BASE + ram_top - 4;
    let mut shared = 0u32;
    for _ in 0..50 {
        shared = bp_r32(shared_ptr_addr);
        // valid = points inside RAM and isn't the NVRAM trailer we just wrote.
        if shared >= RAM_BASE && shared < RAM_BASE + ram_top {
            break;
        }
        delay(2_000);
    }
    unsafe { ALIVE_DIAG = (shared_ptr_addr, shared) };
    // 7. F2 block size 512 + SDPCM version, then enable F2.
    let _ = cmd52(true, 0, FBR_F2_BLKSIZE_LO, 0x00); // 512 & 0xff
    let _ = cmd52(true, 0, FBR_F2_BLKSIZE_HI, 0x02); // 512 >> 8
    if let Some((sdb, _)) = erom_find_core(CORE_SDIO_DEV) {
        let _ = bp_w32(sdb + SD_REG_TOSBMAILBOXDATA, SDPCM_VERSION_MB);
    }
    unsafe { FW_STEP = 7 };
    // DIAG: did the CR4 actually RESUME (CPUHALT cleared → IOCTL ~0x01), and is HT up?
    unsafe {
        F2_DIAG = (
            bp_r32(cr4w + AI_IOCTL),
            cmd52(false, 1, CHIPCLKCSR, 0).unwrap_or(0) as u32,
            0,
        );
    }
    // 6b. SWITCH TO 4-BIT before enabling F2. In 1-bit the firmware's in-band SDIO
    //     interrupt (DAT1, level-triggered low) wedges the whole SDIO front-end the
    //     instant F2 comes ready — every command incl F0/CCCR times out. 4-bit confines
    //     the interrupt to the defined interrupt period and the controller handles it.
    //     The firmware download above already completed in the proven 1-bit path, so
    //     this can't regress the firmware-alive result; falls back to 1-bit if rejected.
    let _ = set_bus_width_4bit();
    // 7. Enable F2, poll ready — F2 ready = firmware alive. READ-MODIFY-WRITE the CCCR
    //    IOE register: a blind write of SDIO_F2 (0x04) would CLEAR F1's enable bit (0x02),
    //    disabling function 1 so all F1 register/backplane access (CHIPCLKCSR, SLEEPCSR,
    //    the SDPCM control path) then times out. Preserve F1: IOE = existing | F2 = 0x06.
    let ioe = cmd52(false, 0, SDIO_FUNC_ENABLE, 0).unwrap_or(0);
    let _ = cmd52(true, 0, SDIO_FUNC_ENABLE, ioe | (SDIO_F2 as u8));
    for _ in 0..2000 {
        let ior = cmd52(false, 0, SDIO_FUNC_READY, 0).unwrap_or(0);
        unsafe { F2_DIAG.2 = ior as u32 };
        if ior & SDIO_F2 != 0 {
            // BASELINE probe the INSTANT F2 reads ready, before ANY post-ready write.
            // Read F0/CCCR (always-on domain) FIRST so an F1 access can't wedge the bus
            // ahead of it — this cleanly separates "backplane asleep" (F0 ok, F1 dead)
            // from "whole device dead" (F0 dead too).
            // [CCCR-rev(F0), F2-IOR(F0), CHIPCLKCSR(F1), chip_id(F1 backplane)].
            unsafe {
                READY_STATE = [
                    cmd52(false, 0, 0x00, 0).unwrap_or(0xEE) as u32, // F0 CCCR/SDIO revision
                    cmd52(false, 0, SDIO_FUNC_READY, 0).unwrap_or(0xEE) as u32, // F0 IOR (F2 ready)
                    cmd52(false, 1, CHIPCLKCSR, 0).unwrap_or(0xEE) as u32, // F1 clock
                    bp_r32(SI_ENUM_BASE) & 0xffff, // F1 backplane chip-id
                ];
            }
            // F2 up. brcmf_sdio_bus_init tail: HOSTINTMASK, then the 43455-SPECIFIC
            // watermark set (source-verified) — WITHOUT these the F2 data path / SDPCM
            // interrupts don't propagate reliably, which stalls the Stage-C control txn.
            if let Some((sdb, _)) = erom_find_core(CORE_SDIO_DEV) {
                let _ = bp_w32(sdb + SD_REG_HOSTINTMASK, HOSTINTMASK);
            }
            let _ = cmd52(true, 1, SBSDIO_WATERMARK, CY_43455_F2_WATERMARK); // 0x10008 = 0x60
            let dc = cmd52(false, 1, SBSDIO_DEVICE_CTL, 0).unwrap_or(0);
            let _ = cmd52(true, 1, SBSDIO_DEVICE_CTL, dc | SBSDIO_DEVCTL_F2WM_ENAB); // 0x10009 |= 0x10
            let _ = cmd52(true, 1, SBSDIO_FUNC1_MESBUSYCTRL, CY_43455_MESBUSYCTRL); // 0x1001D = 0xD0
            unsafe { FW_STEP = 8 };
            // STAGE C, IMMEDIATELY — no printing between here and the first SDPCM command.
            // The 43455 RTOS drops the backplane into SR sleep after ~100-150ms of an idle
            // SDIO bus; the chip is STILL AWAKE + HT still up right now (F2 just readied),
            // so fire the control round-trip NOW, before main.rs emits any diagnostics.
            // (ChatGPT + Gemini converge: the 200ms diag gap was letting the firmware sleep.)
            let mut ver = [0u8; 128];
            let ok = bcdc_ver_probe(&mut ver);
            unsafe {
                VER_OK = ok;
                VER_BUF = ver;
                VER_LEN = ver.iter().position(|&c| c == 0).unwrap_or(ver.len());
            }
            return true;
        }
        delay(2_000);
    }
    false
}

static mut READY_STATE: [u32; 4] = [0; 4];
/// Chip state captured the instant F2 reads ready (before any post-ready write):
/// [chip_id(0x4345=alive), SLEEPCSR(0x03=awake), CHIPCLKCSR, CCCR-rev]. If this is alive
/// but the later control-time probe is dead (0xffff), a post-ready op reset/slept it.
pub fn ready_state() -> [u32; 4] {
    unsafe { READY_STATE }
}
static mut VER_OK: bool = false;
static mut VER_BUF: [u8; 128] = [0; 128];
static mut VER_LEN: usize = 0;
/// P10-C control round-trip result captured at F2-ready (no idle window): (ok, version bytes).
pub fn ver_result() -> (bool, [u8; 128], usize) {
    unsafe { (VER_OK, VER_BUF, VER_LEN) }
}

static mut F2_DIAG: (u32, u32, u32) = (0, 0, 0);
/// (CR4 IOCTL after activate — expect CPUHALT(0x20) CLEARED; CHIPCLKCSR — expect
/// HT_AVAIL(0x80); last F2 IOR read) — diagnoses why F2 didn't come ready.
pub fn f2_diag() -> (u32, u32, u32) {
    unsafe { F2_DIAG }
}

// --- PMU / ChipCommon register dump + firmware read-back verify -----------------
// ChipCommon PMU register offsets (from SI_ENUM_BASE = 0x18000000). Standard across
// Broadcom chips; the #3 PMU audit will confirm the 4345 resource masks.
const CC_CHIPSTATUS: u32 = 0x2c;
const CC_PMUCONTROL: u32 = 0x600;
const CC_PMUCAPABILITIES: u32 = 0x604;
const CC_PMUSTATUS: u32 = 0x608;
const CC_RES_STATE: u32 = 0x60c;
const CC_RES_PENDING: u32 = 0x610; // resources mid-transition — HT_START(28)/HT_AVAIL(29)
const CC_MIN_RES_MASK: u32 = 0x618;
const CC_MAX_RES_MASK: u32 = 0x61c;
// RES4345 HT chain: HT_START=28, HT_AVAIL=29. Forcing these into the resource masks
// isolates PLL/LPO hardware health from the SDIO-core request path.
const HT_RES_BITS: u32 = (1 << 28) | (1 << 29);
const PMU_CTL_PLL_UPD: u32 = 0x400; // pmucontrol PLL_UPD — kick the PMU sequencer

static mut HT_FORCE_DIAG: (u32, u32, u32, u32) = (0, 0, 0, 0);
/// (CHIPCLKCSR, res_state, res_pending, pmustatus) after forcing HT via the resource
/// masks. HT_AVAIL(clk 0x80) up => PLL works, request-path bug; still down => PLL/LPO.
pub fn ht_force_diag() -> (u32, u32, u32, u32) {
    unsafe { HT_FORCE_DIAG }
}

static mut RAM_SIZE_DIAG: u32 = 0;
static mut NVRAM_ADDR_DIAG: u32 = 0;
static mut ALIVE_DIAG: (u32, u32) = (0, 0);
/// Hardware-computed CR4 TCM size (expect 0xc8000 for BCM4345, vs the old 0x98000).
pub fn ramsize_diag() -> u32 {
    unsafe { RAM_SIZE_DIAG }
}
/// Address the NVRAM blob was written to (expect ~0x260000-nlen, not ~0x230000-nlen).
pub fn nvram_addr_diag() -> u32 {
    unsafe { NVRAM_ADDR_DIAG }
}
/// (shared_ptr_addr, value) — firmware-alive: value in [RAM_BASE, RAM_BASE+ramsize)
/// means the CR4 booted and wrote its SDPCM-shared pointer; else firmware never ran.
pub fn alive_diag() -> (u32, u32) {
    unsafe { ALIVE_DIAG }
}

static mut KSO_DIAG: (u32, u32) = (0, 0); // (SLEEPCSR before, after KSO enable)
/// Enable KSO (Keep-Sdio-On) — ungates the backplane so the PMU services HT requests.
/// Read SLEEPCSR, set bit0 if clear, write back, read back for diagnosis.
fn kso_enable() {
    let before = cmd52(false, 1, SBSDIO_SLEEPCSR, 0).unwrap_or(0xEE);
    if before & SBSDIO_KSO_EN == 0 {
        let _ = cmd52(true, 1, SBSDIO_SLEEPCSR, before | SBSDIO_KSO_EN);
    }
    // brcmf retries the readback (device may be transitioning); a few polls suffice here.
    let mut after = before;
    for _ in 0..10 {
        after = cmd52(false, 1, SBSDIO_SLEEPCSR, 0).unwrap_or(0xEE);
        if after & SBSDIO_KSO_EN != 0 {
            break;
        }
        delay(1_000);
    }
    unsafe { KSO_DIAG = (before as u32, after as u32) };
}
/// (SLEEPCSR before, after) — after should have KSO_EN(0x01) set.
pub fn kso_diag() -> (u32, u32) {
    unsafe { KSO_DIAG }
}

/// Dump the key PMU/ChipCommon registers (+ CHIPCLKCSR) so we can compare HEQK's
/// clock/PMU state against a known-good sequence at each phase.
fn pmu_dump() -> [u32; 8] {
    let cc = SI_ENUM_BASE;
    [
        cmd52(false, 1, CHIPCLKCSR, 0).unwrap_or(0xEE) as u32, // [0] F1 CHIPCLKCSR
        bp_r32(cc + CC_CHIPSTATUS),                             // [1] chipstatus
        bp_r32(cc + CC_PMUCONTROL),                            // [2] pmucontrol
        bp_r32(cc + CC_PMUCAPABILITIES),                       // [3] pmucap (rev in [7:0])
        bp_r32(cc + CC_PMUSTATUS),                             // [4] pmustatus
        bp_r32(cc + CC_RES_STATE),                             // [5] res_state (UP resources)
        bp_r32(cc + CC_RES_PENDING),                           // [6] res_pending (mid-transition)
        bp_r32(cc + CC_MAX_RES_MASK),                          // [7] max_res_mask
    ]
}

/// Read back TCM after a firmware write and compare byte-for-byte (sampled ~48 words
/// across the image). Returns (mismatches, first_bad_addr, expected, got). All-zero =
/// perfect. Non-zero mismatches with the CR4 halted = the backplane write is corrupting.
fn backplane_verify(addr: u32, data: &[u8]) -> (u32, u32, u32, u32) {
    let words = data.len() / 4;
    if words == 0 {
        return (0, 0, 0, 0);
    }
    let step = (words / 48).max(1);
    let mut mism = 0u32;
    let mut first = (0u32, 0u32, 0u32);
    let mut i = 0usize;
    while i < words {
        let off = i * 4;
        let expected = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        let got = bp_r32(addr + off as u32);
        if got != expected {
            if mism == 0 {
                first = (addr + off as u32, expected, got);
            }
            mism += 1;
        }
        i += step;
    }
    (mism, first.0, first.1, first.2)
}

static mut HT_DIAG: u32 = 0;
static mut FW_VERIFY: (u32, u32, u32, u32) = (0, 0, 0, 0);
static mut PMU_DUMP: [[u32; 8]; 2] = [[0; 8]; 2];
/// CHIPCLKCSR after the early HT wait (want 0xC0 = HT_AVAIL|ALP_AVAIL; 0x52 = HT stuck).
pub fn ht_diag() -> u32 {
    unsafe { HT_DIAG }
}
/// (mismatches, first_bad_addr, expected, got) from the TCM read-back verify.
pub fn fw_verify() -> (u32, u32, u32, u32) {
    unsafe { FW_VERIFY }
}
/// PMU/ChipCommon dump at phase `i` (0 = after halt+HT before download, 1 = after CR4 release).
pub fn pmu_dump_get(i: usize) -> [u32; 8] {
    unsafe { PMU_DUMP[i & 1] }
}

static mut FW_STEP: u8 = 0;
/// Stage B progress: 1=clk 2=ALP (next: CR4 passive) 3=CR4 halted+D11 reset
/// 4=firmware written 5=NVRAM written 6=CR4 activated (vector+release) 7=HT/F2-req
/// 8=F2 ready (firmware alive). A stop at 2 = EROM CR4 lookup failed (see erom_diag).
pub fn fw_last_step() -> u8 {
    unsafe { FW_STEP }
}

/// P10 Stage C — the regdomain fix. clmload the CLM blob (chunked BEGIN/END), then
/// set the `country` iovar `{abbrev, rev, ccode}` and read it back. Requires F2 up
/// (Stage B) and the BCDC/SDPCM control channel (structured; SDPCM seq iterates on
/// metal). Returns Some(true) if the readback ISO != "00"/"99".
///
/// Per the FreeBSD/OpenBSD cross-check: clmload BEFORE the country set; map the
/// (ccode,rev) pair for correct channel/power (rev 0 = crude fallback).
static mut REG_DONE: bool = false;
/// Establish the WiFi regulatory domain ONCE (idempotent): clmload the CLM tables (the
/// firmware .bin has no embedded CLM, so a bare `country` SET returns BADARG) then SET the
/// `country` iovar. This is THE gate that enables the band for scanning on the honors-
/// country 7.45.265 firmware. Must run while the interface is DOWN, before WLC_UP.
fn wifi_regulatory(iso: &[u8; 2], rev: i32) {
    if unsafe { REG_DONE } {
        return;
    }
    let (clm_ok, clm_status) = clmload_small();
    let mut cp = [0u8; 12];
    country_payload(iso, rev, &mut cp);
    let mut iobc = [0u8; 48];
    let nc = iovar_buf(b"country", &cp, &mut iobc);
    let (cty_ok, cty_status) = bcdc_dcmd(WLC_SET_VAR, BCDC_SET, &iobc[..nc], &mut []);
    unsafe {
        REG_DIAG = (clm_ok, clm_status, cty_ok, cty_status, 0);
        REG_DONE = true;
    }
}

pub fn set_regdomain(iso: &[u8; 2], rev: i32) -> Option<bool> {
    // Establish the regulatory domain (clmload + country), then read it back to confirm.
    wifi_regulatory(iso, rev);
    // read back the 12-byte country struct {abbrev[4], rev[4], ccode[4]}; ISO is in ccode.
    let mut rb = [0u8; 12];
    let get_ok = bcdc_iovar_get(b"country", &mut rb);
    let ccode = [rb[8], rb[9]];
    let (_, _, set_ok, set_status, _) = unsafe { REG_DIAG };
    unsafe {
        REGDOM_DIAG = RegdomDiag {
            set_ok,
            set_status,
            get_ok,
            abbrev: [rb[0], rb[1]],
            ccode,
        };
    }
    if !get_ok {
        return None;
    }
    // A real ISO in ccode (not "00"/"99"/empty) = the firmware has a valid regdomain.
    Some(!(ccode[0] == b'0' && ccode[1] == b'0') && ccode[0] != 0 && ccode[0] != b'9')
}

#[derive(Clone, Copy)]
pub struct RegdomDiag {
    pub set_ok: bool,
    pub set_status: u32,
    pub get_ok: bool,
    pub abbrev: [u8; 2],
    pub ccode: [u8; 2],
}
static mut REGDOM_DIAG: RegdomDiag = RegdomDiag {
    set_ok: false,
    set_status: 0,
    get_ok: false,
    abbrev: [0; 2],
    ccode: [0; 2],
};
/// SET/GET status + the country abbrev and ccode fields of the readback.
pub fn regdom_diag() -> RegdomDiag {
    unsafe { REGDOM_DIAG }
}

// ============================================================================
// P10-D — WiFi data path: escan (enumerate nearby APs). Source-verified against
// brcmfmac cfg80211.c / fwil_types.h / fweh.h. The control channel (BCDC dcmd)
// carries the commands; the results arrive as WLC_E_ESCAN_RESULT EVENT frames on
// SDPCM channel 1 (BDC-framed, big-endian event header).
// ============================================================================
const WLC_UP: u32 = 2;
const WLC_SET_INFRA: u32 = 20;
const WLC_GET_BSSID: u32 = 23; // -4 NOTUP when down; other code when up = clean up-check
const WLC_SET_PM: u32 = 86;
const WLC_SET_SCAN_CHANNEL_TIME: u32 = 185;
const WLC_SET_SCAN_UNASSOC_TIME: u32 = 187;
const WLC_SET_FAKEFRAG: u32 = 219;
const WLC_GET_PHY_NOISE: u32 = 135; // brcmf's "is the radio really up" probe (-4 if not)
const WLC_E_ESCAN_RESULT: u32 = 69;

#[derive(Clone, Copy)]
pub struct ApInfo {
    pub bssid: [u8; 6],
    pub ssid: [u8; 32],
    pub ssid_len: u8,
    pub channel: u8,
    pub rssi: i16,
}
impl ApInfo {
    pub const fn new() -> Self {
        ApInfo { bssid: [0; 6], ssid: [0; 32], ssid_len: 0, channel: 0, rssi: 0 }
    }
}

static mut UP_CHECK_DIAG: (bool, bool, u32) = (false, false, 0);
/// (WLC_UP ok, GET_BSSID ok, GET_BSSID status). up_status != -4(0xfffffffc) => MAC domain up.
pub fn up_check_diag() -> (bool, bool, u32) {
    unsafe { UP_CHECK_DIAG }
}
static mut PHY_NOISE_DIAG: u32 = 0;
/// GET_PHY_NOISE status — the RADIO-up probe. -4(0xfffffffc) => radio not powered (scan NOTUP).
pub fn phy_noise_diag() -> u32 {
    unsafe { PHY_NOISE_DIAG }
}
static mut REG_DIAG: (bool, u32, bool, u32, u32) = (false, 0, false, 0, 0);
/// (clmload ok, clmload status, country SET ok, country status, chanspecs count).
/// chanspecs count > 0 after country => the band is enabled and escan can run.
pub fn reg_diag() -> (bool, u32, bool, u32, u32) {
    unsafe { REG_DIAG }
}
static mut MAC_DIAG: ([u8; 6], [u8; 6], bool) = ([0; 6], [0; 6], false);
/// (OTP cur_etheraddr readback, MAC actually in use, OTP was valid). If OTP invalid, a
/// locally-administered MAC is set so the primary bsscfg can enable (else escan NOTUPs).
pub fn mac_diag() -> ([u8; 6], [u8; 6], bool) {
    unsafe { MAC_DIAG }
}
static mut SCAN_VER_DIAG: (bool, u32) = (false, 0);
/// (scan_ver GET ok, reported version OR status if failed).
pub fn scan_ver_diag() -> (bool, u32) {
    unsafe { SCAN_VER_DIAG }
}
static mut ESCAN_STATUS_V1V2: (u32, u32) = (0, 0);
/// (v1 escan BCDC status, v2 escan BCDC status). err = -(idx): -14=BUFTOOSHORT -37=VERSION.
pub fn escan_status_v1v2() -> (u32, u32) {
    unsafe { ESCAN_STATUS_V1V2 }
}
static mut SCAN_DIAG: [u32; 8] = [0; 8]; // [ev,infra,up,escan_ok,frames,aps,escan_status,ver_used]
/// [event_msgs ok, SET_INFRA ok, WLC_UP ok, escan ok, frames, APs, escan status, params-ver used].
pub fn scan_diag() -> [u32; 8] {
    unsafe { SCAN_DIAG }
}

/// Build a v1 (72-byte) or v2 (80-byte) escan params payload into `out`; returns length.
/// v2 (brcmf_scan_params_v2_le) prepends {version le16, length le16} inside the scan
/// params and widens scan_type to le32 — newer firmware (incl 7.45.265) wants v2.
/// clmload the CLM regulatory blob in SMALL (<=384-byte data) chunks so every F2 frame
/// stays <=512 bytes (byte-mode CMD53) — avoids the multi-block PIO issue. BEGIN on the
/// first chunk, END on the last. Returns (all chunks ok, last BCDC status).
fn clmload_small() -> (bool, u32) {
    const CS: usize = 384;
    let total = CLM_BLOB.len();
    if total == 0 {
        return (true, 0);
    }
    let mut off = 0usize;
    let mut ok = true;
    let mut last_status = 0u32;
    let mut buf = [0u8; CS + 32];
    let mut iob = [0u8; CS + 48];
    while off < total {
        let n = (total - off).min(CS);
        let mut flag = 0u16;
        if off == 0 {
            flag |= DL_BEGIN;
        }
        if off + n >= total {
            flag |= DL_END;
        }
        let clen = clm_chunk(flag, &CLM_BLOB[off..off + n], &mut buf);
        let ilen = iovar_buf(b"clmload", &buf[..clen], &mut iob);
        let (o, st) = bcdc_dcmd(WLC_SET_VAR, BCDC_SET, &iob[..ilen], &mut []);
        if !o {
            ok = false;
            last_status = st;
        }
        off += n;
    }
    (ok, last_status)
}

fn build_escan_params(out: &mut [u8], v2: bool) -> usize {
    for b in out.iter_mut() {
        *b = 0;
    }
    if !v2 {
        // escan_params_le v1: version(4)=1, action(2)=1, sync_id(2), scan_params_le(64).
        out[0..4].copy_from_slice(&1u32.to_le_bytes());
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        out[6..8].copy_from_slice(&0x1234u16.to_le_bytes());
        // scan_params_le @8: ssid(36) bssid@44(6) bss_type@50 scan_type@51 nprobes@52..
        out[44..50].copy_from_slice(&[0xff; 6]);
        out[50] = 2; // bss_type ANY
        out[51] = 0; // scan_type ACTIVE (send broadcast probe requests — finds more APs)
        // Explicit dwell times: the firmware defaults (-1) combined with our 40ms
        // SCAN_CHANNEL_TIME are too short to hear beacons (~100ms apart), so weak APs were
        // missed (HEQK saw 3, the Pi saw 13). nprobes=2, active 120ms, passive 390ms.
        out[52..56].copy_from_slice(&2u32.to_le_bytes()); // nprobes
        out[56..60].copy_from_slice(&120u32.to_le_bytes()); // active_time (ms)
        out[60..64].copy_from_slice(&390u32.to_le_bytes()); // passive_time (ms)
        out[64..68].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // home_time = default
        // channel_num @68 = 0.
        72
    } else {
        // escan_params_v2_le: WRAPPER version(4)=2 (BRCMF_ESCAN_REQ_VERSION_V2 — the fix;
        // the firmware validates this outer field first and rejects 1 with BCME_VERSION),
        // action(2)=1, sync_id(2), then scan_params_v2_le.
        out[0..4].copy_from_slice(&2u32.to_le_bytes());
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        out[6..8].copy_from_slice(&0x1234u16.to_le_bytes());
        // scan_params_v2_le @8: version(2)=2, length(2)=72, ssid(36), bssid(6),
        //   bss_type(1), pad(1), scan_type(4), nprobes(4), active(4), passive(4),
        //   home(4), channel_num(4).
        let s = 8usize;
        out[s..s + 2].copy_from_slice(&2u16.to_le_bytes()); // params version 2
        out[s + 2..s + 4].copy_from_slice(&72u16.to_le_bytes()); // params length
        // ssid_le @ s+4 (36 zero). bssid @ s+40.
        out[s + 40..s + 46].copy_from_slice(&[0xff; 6]);
        out[s + 46] = 2; // bss_type ANY
        out[s + 47] = 0; // pad
        out[s + 48..s + 52].copy_from_slice(&0u32.to_le_bytes()); // scan_type active (le32)
        out[s + 52..s + 56].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // nprobes
        out[s + 56..s + 60].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // active_time
        out[s + 60..s + 64].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // passive_time
        out[s + 64..s + 68].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // home_time
        // channel_num @ s+68 = 0.
        80
    }
}

fn wlc_set_int(cmd: u32, val: u32) -> bool {
    bcdc_dcmd(cmd, BCDC_SET, &val.to_le_bytes(), &mut []).0
}

/// Read ONE SDPCM frame off F2 (poll intstatus, 64-B first read + remainder), advancing
/// tx_max from the SW window byte. Returns (channel, hw_len, doffset), or None if dry.
fn read_sdpcm_frame(rx: &mut [u8]) -> Option<(u8, u16, usize)> {
    let sdb = sdio_core_base();
    let mut hw_len;
    let mut hw_ck;
    let mut waited = 0u32;
    loop {
        let intstat = bp_r32(sdb + SD_REG_INTSTATUS);
        if intstat != 0 {
            let _ = bp_w32(sdb + SD_REG_INTSTATUS, intstat);
        }
        let ok = cmd53_read(2, F2_SDPCM_ADDR, &mut rx[..BRCMF_FIRSTREAD]);
        hw_len = u16::from_le_bytes([rx[0], rx[1]]);
        hw_ck = u16::from_le_bytes([rx[2], rx[3]]);
        if ok && (hw_len != 0 || hw_ck != 0) {
            break;
        }
        waited += 1;
        if waited > 1500 {
            return None; // dry — no more frames in the window
        }
        delay(1_000);
    }
    if hw_len == 0 || ((!(hw_len ^ hw_ck)) & 0xffff) != 0 {
        return None;
    }
    let w0r = u32::from_le_bytes([rx[4], rx[5], rx[6], rx[7]]);
    let w1r = u32::from_le_bytes([rx[8], rx[9], rx[10], rx[11]]);
    let channel = ((w0r >> 8) & 0xf) as u8;
    let doffset = ((w0r >> 24) & 0xff) as usize;
    let mut new_max = ((w1r >> 8) & 0xff) as u8;
    if new_max.wrapping_sub(unsafe { TX_SEQ }) > 0x40 {
        new_max = unsafe { TX_SEQ }.wrapping_add(2);
    }
    unsafe { TX_MAX = new_max };
    // AUDIT M-3 / L-15: cmd53_read silently caps a byte-mode transfer at 512 bytes
    // and still reports success, so for a frame claiming more than
    // BRCMF_FIRSTREAD+512 the tail of `rx` is NEVER written by this frame. `rx` is
    // reused across thousands of poll iterations, so every parser that keys its
    // bounds off the device-supplied hw_len (the escan BSS parser, the BCDC reply
    // copy) could assemble BSSIDs/SSIDs/ccode from STALE bytes of a previous frame.
    // That is not memory-unsafe (all indices are bounded by rx.len()) but it is a
    // data-integrity break across a trust boundary, and scan output IS a security
    // signal here. Two defences, both fail-closed:
    //   1. zero the region this frame could not fill, so a short read yields zeros
    //      (which de-dup/validation rejects) rather than a previous frame's bytes;
    //   2. clamp the hw_len we report to the bytes actually transferred, so every
    //      downstream bound tightens instead of over-reading.
    let mut valid = BRCMF_FIRSTREAD;
    if (hw_len as usize) > BRCMF_FIRSTREAD {
        let rest = ((hw_len as usize) - BRCMF_FIRSTREAD + 3) & !3;
        let end = (BRCMF_FIRSTREAD + rest).min(rx.len());
        let got = (end - BRCMF_FIRSTREAD).min(512); // what cmd53_read actually moves
        for b in rx[BRCMF_FIRSTREAD + got..end].iter_mut() {
            *b = 0;
        }
        let _ = cmd53_read(2, F2_SDPCM_ADDR, &mut rx[BRCMF_FIRSTREAD..end]);
        valid = BRCMF_FIRSTREAD + got;
    }
    let hw_len = hw_len.min(valid as u16);
    Some((channel, hw_len, doffset))
}

/// P10-D: enable events, bring the STA interface UP, start an escan, and collect the APs
/// the firmware reports via WLC_E_ESCAN_RESULT (channel-1) events. Returns the AP count.
pub fn wifi_scan(aps: &mut [ApInfo]) -> usize {
    // 0. Query the firmware's supported scan-params version (informs v1 vs v2). Capture
    //    the GET status: -23 (BCME_UNSUPPORTED) => firmware is v1; success => v2.
    let mut sv = [0u8; 8];
    let mut req = [0u8; 32];
    let rn = iovar_buf(b"scan_ver", &[], &mut req);
    let (sv_ok, sv_status) = bcdc_dcmd(WLC_GET_VAR, 0, &req[..rn], &mut sv);
    let scan_ver = if sv_ok { u32::from_le_bytes([sv[0], sv[1], sv[2], sv[3]]) } else { sv_status };
    unsafe { SCAN_VER_DIAG = (sv_ok, scan_ver) };
    // === PREINIT (mirror brcmf_c_preinit_dcmds, common.c) ===
    // P1. Establish the MAC — the ROOT of the escan NOTUP. GET the OTP cur_etheraddr; if
    //     it's invalid (all-zero, or multicast = odd first octet), the primary bsscfg can
    //     never enable (it needs a valid unicast source address), and escan returns NOTUP
    //     even though the radio is up. HEQK's NVRAM has no macaddr and the CM5 WiFi OTP MAC
    //     is unprogrammed -> zero. FIX (brcmf does the same via eth_random_addr): SET a
    //     valid locally-administered unicast MAC (02:..) while DOWN, before WLC_UP.
    let mut otp_mac = [0u8; 6];
    let _ = bcdc_iovar_get(b"cur_etheraddr", &mut otp_mac);
    let mac_valid = (otp_mac[0] & 1) == 0 && otp_mac.iter().any(|&b| b != 0);
    let mut mac = otp_mac;
    if !mac_valid {
        // Fixed LAA unicast MAC (02 = locally administered, bit0 clear = unicast). Stable
        // across boots so the device keeps one identity; derived tail keeps it distinctive.
        mac = [0x02, 0x43, 0x45, 0x48, 0x51, 0x4b]; // 02:43:45:48:51:4b ("CEHQK")
        let mut iobmac = [0u8; 32];
        let nmac = iovar_buf(b"cur_etheraddr", &mac, &mut iobmac);
        let _ = bcdc_iovar_set(&iobmac[..nmac]);
    }
    unsafe { MAC_DIAG = (otp_mac, mac, mac_valid) };
    // P1.5. REGULATORY — THE escan-NOTUP gate (clmload + country=RO), done once while DOWN.
    wifi_regulatory(b"RO", 0);
    // P2. event_msgs: GET the firmware's current mask, OR IN the escan-result + set-ssid
    //     bits (preserving BRCMF_E_IF etc. the fw already enabled), then SET it back.
    let mut mask = [0u8; 16];
    let _ = bcdc_iovar_get(b"event_msgs", &mut mask);
    mask[0] |= 0x01; // WLC_E_SET_SSID (0)
    mask[69 / 8] |= 1 << (69 % 8); // WLC_E_ESCAN_RESULT (69) -> mask[8] |= 0x20
    let mut iob = [0u8; 64];
    let n = iovar_buf(b"event_msgs", &mask, &mut iob);
    let ev_ok = bcdc_iovar_set(&iob[..n]);
    // P3. scan dwell tuning — longer than brcmf's 40ms default so we actually hear beacons
    //     (~100ms apart) from weaker APs; 40ms only caught the strongest few.
    let _ = wlc_set_int(WLC_SET_SCAN_CHANNEL_TIME, 120);
    let _ = wlc_set_int(WLC_SET_SCAN_UNASSOC_TIME, 120);

    // === BRING-UP (mirror brcmf_config_dongle, cfg80211.c:7968) — EXACT ORDER ===
    // B1. WLC_UP FIRST (value 1 via cmd_int_set — not an empty payload as HEQK had it).
    let up_ok = wlc_set_int(WLC_UP, 1);
    // B2. PM off (keep radio awake), roam off.
    let _ = wlc_set_int(WLC_SET_PM, 0);
    let mut iobr = [0u8; 32];
    let nr = iovar_buf(b"roam_off", &1u32.to_le_bytes(), &mut iobr);
    let _ = bcdc_iovar_set(&iobr[..nr]);
    // B3. THEN infra=1 (AFTER up, per brcmf — doing it before up left the radio not-up).
    let infra_ok = wlc_set_int(WLC_SET_INFRA, 1);
    // B4. fakefrag (optional).
    let _ = wlc_set_int(WLC_SET_FAKEFRAG, 1);
    // B5. mpc=0 — CRITICAL: preinit set mpc=1, which lets the firmware POWER DOWN THE RADIO
    //     when idle. Then the always-on MAC domain still answers ioctls (GET_BSSID) but the
    //     scan engine (needs the radio clocked) returns NOTUP. mpc=0 keeps the radio up.
    let mut iobm = [0u8; 32];
    let nm = iovar_buf(b"mpc", &0u32.to_le_bytes(), &mut iobm);
    let _ = bcdc_iovar_set(&iobm[..nm]);
    delay(80_000); // let the radio power up

    // === VERIFY the RADIO is really up === GET_BSSID(23) answers from the always-on domain
    // even when the radio is down, so it's not sufficient. GET_PHY_NOISE(135) is brcmf's
    // real radio-up probe: -4 => radio NOT powered (scan will NOTUP); a value => radio UP.
    // Re-assert HT first — the firmware may have let it drop, un-clocking the radio.
    ensure_ht_avail();
    let mut bssid = [0u8; 6];
    let (bssid_ok, up_status) = bcdc_dcmd(WLC_GET_BSSID, 0, &[], &mut bssid);
    let mut noise = [0u8; 4];
    let (_pn_ok, pn_status) = bcdc_dcmd(WLC_GET_PHY_NOISE, 0, &[], &mut noise);
    // GET chanspecs (now, AFTER bring-up) — brcmf_chanspec_list { count le32; list[] }.
    // count > 0 proves the band is enabled (the regulatory fix worked). Big buffer so the
    // firmware can return the list; we only read the count at offset 0.
    let mut chbuf = [0u8; 256];
    let mut chreq = [0u8; 32];
    let ncr = iovar_buf(b"chanspecs", &[], &mut chreq);
    let _ = bcdc_dcmd(WLC_GET_VAR, 0, &chreq[..ncr], &mut chbuf);
    let chan_count = u32::from_le_bytes([chbuf[0], chbuf[1], chbuf[2], chbuf[3]]);
    unsafe {
        UP_CHECK_DIAG = (up_ok, bssid_ok, up_status);
        PHY_NOISE_DIAG = pn_status;
        REG_DIAG.4 = chan_count;
    }
    // 4. escan. scan_ver=-23(UNSUPPORTED) => firmware is v1. The v1 escan initially returns
    //    BCME_NOTUP(-4) because the STA finishes coming up asynchronously after WLC_UP's ACK,
    //    so RETRY until it's accepted (status 0) or a non-NOTUP error. (If the fw ever reports
    //    scan_ver supported, use v2 instead.)
    let use_v2 = sv_ok; // scan_ver present => v2 firmware
    let mut p = [0u8; 80];
    let mut iob3 = [0u8; 112];
    let plen = build_escan_params(&mut p, use_v2);
    let n3 = iovar_buf(b"escan", &p[..plen], &mut iob3);
    let ver_used = if use_v2 { 2u32 } else { 1u32 };
    let mut scan_ok = false;
    let mut scan_status = 0u32;
    for _ in 0..20 {
        let (ok, st) = bcdc_dcmd(WLC_SET_VAR, BCDC_SET, &iob3[..n3], &mut []);
        scan_ok = ok;
        scan_status = st;
        if ok || st != 0xffff_fffc {
            break; // accepted, or a non-NOTUP error (stop retrying)
        }
        delay(60_000); // ~interface still coming up — wait and retry
    }
    unsafe { ESCAN_STATUS_V1V2 = (scan_status, ver_used) };
    // 5. read WLC_E_ESCAN_RESULT event frames (channel 1), parse each BSS. The scan spans
    //    several seconds across all channels, so tolerate inter-channel gaps (dry reads)
    //    rather than stopping at the first — else we only catch the first channel's APs.
    let mut rx = [0u8; DL_CHUNK + 64];
    let mut naps = 0usize;
    let mut frames = 0u32;
    // A passive all-channel scan takes several seconds with ~100-500ms per-channel dwell,
    // so the inter-channel gaps are long. Terminate on the ESCAN SUCCESS event (below); the
    // dry-read tolerance is generous so gaps between channels don't cut the scan short.
    let mut dry = 0u32;
    for _ in 0..12000 {
        let (channel, hw_len, doffset) = match read_sdpcm_frame(&mut rx) {
            Some(v) => {
                dry = 0;
                v
            }
            None => {
                dry += 1;
                if dry > 400 {
                    break; // sustained silence (well past any inter-channel gap) — done
                }
                continue;
            }
        };
        frames += 1;
        if channel != 1 {
            continue; // want the EVENT channel
        }
        // event frame: after SDPCM(doffset) -> BDC hdr(4) + bdc_doff*4 pad + brcmf_event(72).
        let bdc = doffset;
        if bdc + 4 > rx.len() {
            continue;
        }
        let bdc_doff = rx[bdc + 3] as usize;
        let ev = bdc + 4 + bdc_doff * 4; // start of brcmf_event
        if ev + 72 > (hw_len as usize) || ev + 72 > rx.len() {
            continue;
        }
        // event_type @ ev+28 (BE32), status @ ev+32 (BE32).
        let event_type = u32::from_be_bytes([rx[ev + 28], rx[ev + 29], rx[ev + 30], rx[ev + 31]]);
        let status = u32::from_be_bytes([rx[ev + 32], rx[ev + 33], rx[ev + 34], rx[ev + 35]]);
        if event_type != WLC_E_ESCAN_RESULT {
            continue;
        }
        if status == 0 {
            break; // SUCCESS = scan complete
        }
        if status != 8 {
            continue; // want PARTIAL (8) = one BSS follows
        }
        // escan_result @ ev+72; bss_info @ er+12.
        let bi = ev + 72 + 12;
        // AUDIT M-3: bound by the RECEIVED length, not by the buffer length —
        // rx is reused across poll iterations, so rx.len() would admit stale bytes
        // from a previous frame into BSSID/SSID/RSSI. hw_len is already clamped to
        // bytes actually transferred by read_sdpcm_frame.
        if bi + 80 > (hw_len as usize) || bi + 80 > rx.len() {
            continue;
        }
        let mut bssid = [0u8; 6];
        bssid.copy_from_slice(&rx[bi + 8..bi + 14]);
        // DE-DUP: the firmware can report the same BSS on multiple channels/events.
        if aps[..naps].iter().any(|a| a.bssid == bssid) {
            continue;
        }
        if naps < aps.len() {
            let mut ap = ApInfo::new();
            ap.bssid = bssid;
            let slen = rx[bi + 18].min(32);
            ap.ssid_len = slen;
            ap.ssid[..slen as usize].copy_from_slice(&rx[bi + 19..bi + 19 + slen as usize]);
            let chanspec = u16::from_le_bytes([rx[bi + 72], rx[bi + 73]]);
            ap.channel = (chanspec & 0xff) as u8;
            ap.rssi = i16::from_le_bytes([rx[bi + 78], rx[bi + 79]]);
            aps[naps] = ap;
            naps += 1;
        }
    }
    unsafe {
        SCAN_DIAG = [
            ev_ok as u32, infra_ok as u32, up_ok as u32, scan_ok as u32,
            frames, naps as u32, scan_status, ver_used,
        ];
    }
    naps
}

// ===========================================================================
// P10-E — STA-mode WPA2-PSK ASSOCIATION (firmware-offloaded supplicant).
//
// CYW43455 is a FullMAC part: the firmware runs PBKDF2 + the 802.11 association
// + the WPA2 4-way handshake + CCMP in-chip, so heqk needs NO WPA crypto. We
// only drive the standard wl-tool SET sequence through the proven `bcdc_dcmd`
// control path, then collect the async WLC_E_* events off SDPCM channel 1 with
// the same `read_sdpcm_frame` + brcmf_event parse the scan uses. Success = a
// WLC_E_LINK event with the LINK flag set (link up ⇒ keys installed).
// ===========================================================================

// WLC ioctl ids used by association (WLC_UP/WLC_SET_INFRA already defined above).
const WLC_DOWN: u32 = 3;
const WLC_SET_AUTH: u32 = 22; // 0 = Open System (WPA2-PSK does the security in the 4-way HS)
const WLC_SET_SSID: u32 = 26; // join: payload = wlc_ssid_t
const WLC_DISASSOC: u32 = 52;
const WLC_SET_WSEC: u32 = 134; // wsec bitmask
const WLC_SET_WPA_AUTH: u32 = 165;
const WLC_SET_WSEC_PMK: u32 = 268; // payload = wsec_pmk_t
const WLC_SET_PM_: u32 = 86; // power-mgmt (0 = CAM/awake through the handshake)

const AES_ENABLED: u32 = 0x0004; // wsec bit: CCMP/AES
const WPA2_AUTH_PSK: u32 = 0x0080; // wpa_auth: WPA2-PSK
const WSEC_PASSPHRASE: u16 = 0x0001; // wsec_pmk flag: `key` holds an ASCII passphrase (fw PBKDF2s)

// Association event ids (BE32 event_type in the brcmf_event header, ev+28).
const WLC_E_SET_SSID: u32 = 0;
const WLC_E_AUTH: u32 = 3;
const WLC_E_DEAUTH: u32 = 5;
const WLC_E_DEAUTH_IND: u32 = 6;
const WLC_E_ASSOC: u32 = 7;
const WLC_E_DISASSOC: u32 = 11;
const WLC_E_DISASSOC_IND: u32 = 12;
const WLC_E_LINK: u32 = 16;
const WLC_E_PSK_SUP: u32 = 46;
const WLC_EVENT_MSG_LINK: u16 = 0x01; // brcmf_event_msg.flags: link is UP
const WLC_SUP_KEYED: u32 = 6; // WLC_E_PSK_SUP status: 4-way handshake complete

/// The outcome + diagnostic trail of one association attempt. The trail is the
/// heart of the "validate + fix on metal" loop: every WLC_E_* the firmware emits
/// during the join is recorded (type, status, flags) so a failing handshake shows
/// exactly which stage it reached.
pub struct JoinResult {
    pub steps_ok: u16, // bit0 event_msgs,1 infra,2 auth,3 wsec,4 wpa_auth,5 sup_wpa,6 pmk,7 up
    pub pmk_status: u32, // bcdc status of WLC_SET_WSEC_PMK (0xfffffffc = NOTUP)
    pub sup_wpa_status: u32, // bcdc status of the bsscfg:sup_wpa SET
    pub set_ssid_ok: bool,
    pub set_ssid_status: u32,
    pub link_up: bool,
    pub psk_keyed: bool,
    pub deauth_seen: bool, // a WLC_E_DEAUTH/DISASSOC after link — keying failed / kicked
    pub events_seen: u32,
    pub last_event: u32,
    pub last_status: u32,
    pub trail: [(u32, u32, u16); 24],
    pub trail_len: usize,
    // WiFi DATA-path proof captured DURING association: the AP starts the WPA2 4-way
    // handshake by sending EAPOL-Key M1 (ethertype 0x888E) over SDPCM channel 2. Catching
    // it proves the data path AND gives the supplicant its first input (ANonce).
    pub data_frames: u32, // any channel-2 (data) frame seen during the join
    pub eapol_seen: bool, // an EAPOL (0x888E) frame arrived
    pub eapol_len: usize, // bytes captured of the first EAPOL frame
    pub eapol: [u8; 128], // first EAPOL frame head (EAPOL hdr + key descriptor + ANonce…)
}

impl JoinResult {
    pub fn new() -> Self {
        JoinResult {
            steps_ok: 0,
            pmk_status: 0,
            sup_wpa_status: 0,
            set_ssid_ok: false,
            set_ssid_status: 0,
            link_up: false,
            psk_keyed: false,
            deauth_seen: false,
            events_seen: 0,
            last_event: 0xffff_ffff,
            last_status: 0,
            trail: [(0, 0, 0); 24],
            trail_len: 0,
            data_frames: 0,
            eapol_seen: false,
            eapol_len: 0,
            eapol: [0; 128],
        }
    }
}

/// Dump the firmware's "cap" capability string (space-separated tokens). brcmfmac reads
/// this to detect features — crucially "sup"/"fwsup"/"idsup" (in-firmware WPA supplicant)
/// and "sae". Its presence tells us whether the CHIP runs the 4-way handshake (set the PMK)
/// or the HOST must (drive EAPOL). Returns the byte length written to `out`.
pub fn fw_cap(out: &mut [u8]) -> usize {
    let _ = wake_chip();
    let _ = ensure_ht_avail();
    for b in out.iter_mut() {
        *b = 0;
    }
    if bcdc_iovar_get(b"cap", out) {
        // length = up to the first NUL
        out.iter().position(|&c| c == 0).unwrap_or(out.len())
    } else {
        0
    }
}

/// Associate to a WPA2-PSK AP. `ssid` (<=32 B) + `passphrase` (8..63 B). Fills
/// `out` with the step-acks + the full event trail. Reuses the scan's wake/HT
/// preamble and the NOTUP-retry idiom (the STA finishes coming up asynchronously).
pub fn wifi_join(ssid: &[u8], passphrase: &[u8], open: bool, out: &mut JoinResult) {
    // Wake + backplane clock (the 43455 SR-sleeps on a quiet bus; the multi-second
    // handshake needs HT held up — we also re-ensure it inside the event loop).
    let _ = wake_chip();
    drain_firmware_mailbox();
    let _ = ensure_ht_avail();

    // Down to (re)configure the security suite cleanly.
    let _ = wlc_set_int(WLC_DOWN, 0);

    // Enable the association events on top of whatever the firmware already has.
    let mut mask = [0u8; 16];
    let _ = bcdc_iovar_get(b"event_msgs", &mut mask);
    for e in [
        WLC_E_SET_SSID, WLC_E_AUTH, WLC_E_DEAUTH, WLC_E_DEAUTH_IND, WLC_E_ASSOC,
        WLC_E_DISASSOC, WLC_E_DISASSOC_IND, WLC_E_LINK, WLC_E_PSK_SUP,
    ] {
        mask[(e / 8) as usize] |= 1 << (e % 8);
    }
    let mut iob = [0u8; 64];
    let nm = iovar_buf(b"event_msgs", &mask, &mut iob);
    if bcdc_iovar_set(&iob[..nm]) { out.steps_ok |= 1 << 0; }

    // Infrastructure (managed) mode + Open 802.11 auth (WPA2-PSK secures via the HS).
    if wlc_set_int(WLC_SET_INFRA, 1) { out.steps_ok |= 1 << 1; }
    if wlc_set_int(WLC_SET_AUTH, 0) { out.steps_ok |= 1 << 2; }
    // OPEN: wsec=0 + wpa_auth=0 (no encryption, no handshake). WPA2: CCMP + WPA2-PSK.
    let (wsec_val, wpa_auth_val) = if open { (0, 0) } else { (AES_ENABLED, WPA2_AUTH_PSK) };
    if wlc_set_int(WLC_SET_WSEC, wsec_val) { out.steps_ok |= 1 << 3; }
    if wlc_set_int(WLC_SET_WPA_AUTH, wpa_auth_val) { out.steps_ok |= 1 << 4; }
    // Power-save OFF (stay awake through the handshake), then bring the STA up.
    let _ = wlc_set_int(WLC_SET_PM_, 0);
    if wlc_set_int(WLC_UP, 1) { out.steps_ok |= 1 << 7; }
    delay(80_000);
    let _ = ensure_ht_avail();

    // --- credentials, set AFTER WLC_UP (they NOTUP'd on the down interface) ---
    // (No sup_wpa: this firmware reports that iovar UNSUPPORTED(-23), and the Infineon
    // WHD bare-metal driver for this exact chip doesn't use it — the fw supplicant is
    // implicit once wsec/wpa_auth/pmk are set.)
    //
    // WPA2 only: install the PMK. (Open networks skip all keying.)
    if !open {
    // Set the RAW 32-byte PMK (flags=0) in brcmfmac's EXACT wire format:
    // struct brcmf_wsec_pmk_le { u16 key_len; u16 flags; u8 key[BRCMF_WSEC_MAX_PSK_LEN=32] }
    // = 36 B. This firmware rejects a passphrase (WSEC_PASSPHRASE → BADARG) AND a 68-B
    // struct (BADARG — length ≠ sizeof), so we send the 36-B struct with the on-device
    // PBKDF2-HMAC-SHA1 PMK (KAT-verified) and let the firmware idsup run the 4-way HS.
    {
        let pmk_key = crate::wpa::wpa_pmk(passphrase, ssid);
        let mut pmk = [0u8; 4 + 32]; // 36 B — brcmf_wsec_pmk_le
        pmk[0..2].copy_from_slice(&32u16.to_le_bytes()); // key_len = 32 (raw PMK)
        pmk[2..4].copy_from_slice(&0u16.to_le_bytes()); // flags = 0 (not a passphrase)
        pmk[4..4 + 32].copy_from_slice(&pmk_key);
        let (ok, st) = bcdc_dcmd(WLC_SET_WSEC_PMK, BCDC_SET, &pmk, &mut []);
        out.pmk_status = st;
        if ok {
            out.steps_ok |= 1 << 6;
        } else {
            // Fallback: some firmwares moved the PMK to the "wsec_pmk" IOVAR (WLC_SET_VAR).
            // sup_wpa_status is repurposed to carry this attempt's status.
            let mut ib = [0u8; 64];
            let n = iovar_buf(b"wsec_pmk", &pmk, &mut ib);
            let (iok, ist) = bcdc_dcmd(WLC_SET_VAR, BCDC_SET, &ib[..n], &mut []);
            out.sup_wpa_status = ist;
            if iok {
                out.steps_ok |= 1 << 6;
            }
        }
    }
    } // end if !open
    // Give the firmware a moment to absorb the passphrase (WHD delays here before join).
    delay(20_000);

    // Join: WLC_SET_SSID with wlc_ssid_t { u32 SSID_len; u8 SSID[32] }. The STA
    // comes up asynchronously after WLC_UP, so retry while the firmware says NOTUP(-4).
    let slen = ssid.len().min(32);
    let mut sb = [0u8; 4 + 32];
    sb[0..4].copy_from_slice(&(slen as u32).to_le_bytes());
    sb[4..4 + slen].copy_from_slice(&ssid[..slen]);
    for _ in 0..20 {
        let (ok, st) = bcdc_dcmd(WLC_SET_SSID, BCDC_SET, &sb[..4 + slen], &mut []);
        out.set_ssid_ok = ok;
        out.set_ssid_status = st;
        if ok || st != 0xffff_fffc { break; }
        delay(60_000);
    }

    // Collect events. read_sdpcm_frame is the same primitive the scan uses; channel 1 =
    // event. We do NOT stop on link-up — for WPA2 the 4-way handshake (WLC_E_PSK_SUP
    // keyed) and any post-assoc deauth (keying failure / kick) can follow it — so once
    // link comes up we keep reading a grace window to see the TRUE outcome. Success =
    // PSK_SUP keyed with link up and no deauth. Keep HT alive across the handshake.
    let mut rx = [0u8; 2048];
    let mut i = 0u32;
    let mut grace = 0u32; // reads remaining after link-up before we call it
    while i < 8000 {
        i += 1;
        if i % 256 == 0 { let _ = ensure_ht_avail(); }
        let (channel, _hw, doff) = match read_sdpcm_frame(&mut rx) {
            Some(t) => t,
            None => {
                if out.link_up {
                    grace += 1;
                    if grace > 1200 { break; } // ~link is up and quiet ⇒ stable
                }
                continue;
            }
        };
        // Channel 2 = DATA. During a WPA2 join the AP's EAPOL-Key M1 arrives here — capture
        // it (proves the data path + is the supplicant's first input). BDC hdr then ethernet.
        if channel == 2 {
            let bdc_doff = rx[doff + 3] as usize;
            let eth = doff + 4 + bdc_doff * 4;
            if eth + 14 <= rx.len() {
                out.data_frames += 1;
                let etype = u16::from_be_bytes([rx[eth + 12], rx[eth + 13]]);
                if etype == 0x888E && !out.eapol_seen {
                    out.eapol_seen = true;
                    let n = (rx.len() - eth).min(out.eapol.len());
                    out.eapol[..n].copy_from_slice(&rx[eth..eth + n]);
                    out.eapol_len = n;
                }
            }
            continue;
        }
        if channel != 1 { continue; }
        let bdc_doff = rx[doff + 3] as usize;
        let ev = doff + 4 + bdc_doff * 4;
        if ev + 36 > rx.len() { continue; }
        let flags = u16::from_be_bytes([rx[ev + 26], rx[ev + 27]]);
        let etype = u32::from_be_bytes([rx[ev + 28], rx[ev + 29], rx[ev + 30], rx[ev + 31]]);
        let status = u32::from_be_bytes([rx[ev + 32], rx[ev + 33], rx[ev + 34], rx[ev + 35]]);
        out.events_seen += 1;
        out.last_event = etype;
        out.last_status = status;
        if out.trail_len < out.trail.len() {
            out.trail[out.trail_len] = (etype, status, flags);
            out.trail_len += 1;
        }
        match etype {
            WLC_E_PSK_SUP if status == WLC_SUP_KEYED => {
                out.psk_keyed = true;
                if out.link_up { break; } // keyed + linked ⇒ fully associated, done
            }
            WLC_E_LINK => {
                out.link_up = (flags & WLC_EVENT_MSG_LINK) != 0;
                if !out.link_up {
                    // link went DOWN after being up ⇒ kicked
                    if i > 100 { out.deauth_seen = true; break; }
                } else if out.psk_keyed {
                    break; // keyed already + link up ⇒ done
                }
            }
            WLC_E_DEAUTH | WLC_E_DEAUTH_IND | WLC_E_DISASSOC | WLC_E_DISASSOC_IND => {
                out.deauth_seen = true;
                break; // AP kicked us — keying failed or credentials rejected
            }
            _ => {}
        }
    }
}

/// What the WiFi data-path RX probe observed on SDPCM channel 2 after association.
pub struct DataProbe {
    pub frames: u32,     // channel-2 (data) frames seen
    pub l2_known: u32,   // frames with a recognizable ethertype (ARP/IPv4/IPv6)
    pub last_etype: u16, // ethertype of the last data frame
    pub sample: [u8; 32], // first data frame: eth dst[6] src[6] etype[2] + payload head
    pub sample_len: usize,
}

impl DataProbe {
    pub fn new() -> Self {
        DataProbe { frames: 0, l2_known: 0, last_etype: 0, sample: [0; 32], sample_len: 0 }
    }
}

/// After association, prove the WiFi DATA path: read SDPCM channel-2 (data) frames off F2
/// for a bounded window and parse their ethernet headers. Any network has background
/// broadcast/multicast (ARP, DHCP, mDNS, IPv6 RA), so on a live AP this should see frames —
/// proving heqk RECEIVES real 802.11 data through the firmware over SDIO. Channel-2 payload
/// layout mirrors events: a 4-B BDC header (data_offset in byte 3, in 4-B units) then the
/// ethernet frame.
pub fn wifi_data_probe(out: &mut DataProbe) {
    let mut rx = [0u8; 2048];
    let mut i = 0u32;
    while i < 5000 {
        i += 1;
        if i % 256 == 0 {
            let _ = ensure_ht_avail();
        }
        let (channel, _hw, doff) = match read_sdpcm_frame(&mut rx) {
            Some(t) => t,
            None => continue,
        };
        if channel != 2 {
            continue;
        }
        let bdc_doff = rx[doff + 3] as usize;
        let eth = doff + 4 + bdc_doff * 4;
        if eth + 14 > rx.len() {
            continue;
        }
        out.frames += 1;
        let etype = u16::from_be_bytes([rx[eth + 12], rx[eth + 13]]);
        out.last_etype = etype;
        if etype == 0x0806 || etype == 0x0800 || etype == 0x86dd {
            out.l2_known += 1;
        }
        if out.sample_len == 0 {
            let n = (rx.len() - eth).min(32);
            out.sample[..n].copy_from_slice(&rx[eth..eth + n]);
            out.sample_len = n;
        }
        if out.frames >= 64 {
            break; // enough evidence the RX data path is live
        }
    }
}

// ===========================================================================
// P10-E WPA2 HOST SUPPLICANT (the firmware has no idsup — we run the 4-way HS).
// Increment S1: derive the PTK from the captured M1, build + send M2, watch for M3.
// ===========================================================================

const SDPCM_DATA_CHANNEL: u8 = 2;

/// Send one ethernet frame as an SDPCM DATA frame (channel 2) over F2. Mirrors the control
/// TX framing (bcdc_dcmd) but channel=2 with a 4-byte BDC data header instead of the BCDC
/// dcmd header. Rides the same SDPCM tx-credit + sequence as control.
fn sdpcm_data_tx(eth: &[u8]) -> bool {
    if !txctl_ok() {
        return false;
    }
    let seq = unsafe { TX_SEQ };
    let mut frame = [0u8; DL_CHUNK + 64];
    let w0: u32 = (seq as u32)
        | ((SDPCM_DATA_CHANNEL as u32) << 8)
        | ((SDPCM_HDRLEN as u32) << 24);
    let bdc = SDPCM_HDRLEN; // 12
    frame[bdc] = 0x20; // BDC flags: proto ver 2 << 4
    frame[bdc + 1] = 0; // priority
    frame[bdc + 2] = 0; // flags2
    frame[bdc + 3] = 0; // data_offset (4-byte units past the BDC header)
    let body = bdc + 4;
    let n = eth.len().min(frame.len() - body);
    frame[body..body + n].copy_from_slice(&eth[..n]);
    let total = (body + n) as u16;
    frame[0..2].copy_from_slice(&total.to_le_bytes());
    frame[2..4].copy_from_slice(&(!total).to_le_bytes());
    frame[4..8].copy_from_slice(&w0.to_le_bytes());
    let padded = ((total as usize) + 3) & !3;
    let ok = cmd53_write(2, F2_SDPCM_ADDR, &frame[..padded]);
    if ok {
        unsafe { TX_SEQ = TX_SEQ.wrapping_add(1) };
    }
    ok
}

/// Outcome of the 4-way handshake attempt (S1 = up to M3).
pub struct Wpa4Way {
    pub have_m1: bool,
    pub kdv: u8,        // key-descriptor version from M1 key-info (2 = HMAC-SHA1/AES)
    pub snonce_ok: bool,
    pub m2_tx_ok: bool,
    pub m3_seen: bool,  // AP replied with another EAPOL after M2 ⇒ M2 (PTK+MIC) accepted
    pub m3_key_info: u16,
    pub m3_len: usize,
    pub deauth_after: bool,
    pub other_eapol: u32,
}

impl Wpa4Way {
    pub fn new() -> Self {
        Wpa4Way {
            have_m1: false, kdv: 0, snonce_ok: false, m2_tx_ok: false, m3_seen: false,
            m3_key_info: 0, m3_len: 0, deauth_after: false, other_eapol: 0,
        }
    }
}

/// The RSN information element for WPA2-PSK / CCMP. MUST match what the firmware put in the
/// (re)association request or the AP rejects M2. group=CCMP, pairwise=CCMP, akm=PSK, no caps.
const RSN_IE_PSK_CCMP: [u8; 22] = [
    0x30, 0x14, 0x01, 0x00, // id, len=20, version 1
    0x00, 0x0f, 0xac, 0x04, // group cipher = CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // pairwise count 1, CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, // akm count 1, PSK
    0x00, 0x00, // RSN capabilities
];

/// S1 of the host supplicant: parse M1, derive the PTK, build + send M2, and watch channel 2
/// for M3 (which proves M2's MIC — hence the PTK — was accepted) plus any deauth. `m1` is the
/// captured ethernet EAPOL frame (dst=STA, src=AP). Key install + M4 are S2.
pub fn wpa_handshake(m1: &[u8], m1_len: usize, pmk: &[u8; 32], out: &mut Wpa4Way) {
    let body = 18; // eth(14) + 802.1X hdr(4)
    if m1_len < body + 95 {
        return; // need a full EAPOL-Key body
    }
    out.have_m1 = true;
    let mut spa = [0u8; 6];
    spa.copy_from_slice(&m1[0..6]); // dst of M1 = us
    let mut aa = [0u8; 6];
    aa.copy_from_slice(&m1[6..12]); // src of M1 = AP
    let m1_ki = u16::from_be_bytes([m1[body + 1], m1[body + 2]]);
    out.kdv = (m1_ki & 0x0007) as u8;
    let x1ver = m1[14]; // 802.1X protocol version to echo
    let mut replay = [0u8; 8];
    replay.copy_from_slice(&m1[body + 5..body + 13]);
    let mut anonce = [0u8; 32];
    anonce.copy_from_slice(&m1[body + 13..body + 45]);

    // SNonce from the HW TRNG (fail-closed: no entropy ⇒ no handshake).
    let mut snonce = [0u8; 32];
    for k in 0..4 {
        match crate::rng200::next_word_strict() {
            Some(w) => snonce[k * 8..k * 8 + 8].copy_from_slice(&w.to_le_bytes()),
            None => return,
        }
    }
    out.snonce_ok = true;

    let ptk = crate::wpa::wpa_ptk(pmk, &aa, &spa, &anonce, &snonce);
    let mut kck = [0u8; 16];
    kck.copy_from_slice(&ptk[0..16]);

    // Build M2: EAPOL-Key, key info = M1 version | pairwise | MIC; key data = RSN IE.
    let kd = RSN_IE_PSK_CCMP.len(); // 22
    let mut m2 = [0u8; 14 + 4 + 95 + 22];
    m2[0..6].copy_from_slice(&aa); // dst = AP
    m2[6..12].copy_from_slice(&spa); // src = us
    m2[12] = 0x88;
    m2[13] = 0x8E; // EAPOL ethertype
    m2[14] = x1ver;
    m2[15] = 0x03; // EAPOL-Key
    let x1len = (95 + kd) as u16;
    m2[16..18].copy_from_slice(&x1len.to_be_bytes());
    m2[body] = 0x02; // descriptor type RSN
    let m2_ki = (m1_ki & 0x0007) | 0x0008 | 0x0100; // version | pairwise | MIC
    m2[body + 1..body + 3].copy_from_slice(&m2_ki.to_be_bytes());
    // key length @ +3 = 0; replay @ +5; nonce @ +13; iv/rsc/keyid zero; mic @ +77 zero.
    m2[body + 5..body + 13].copy_from_slice(&replay);
    m2[body + 13..body + 45].copy_from_slice(&snonce);
    m2[body + 93..body + 95].copy_from_slice(&(kd as u16).to_be_bytes());
    m2[body + 95..body + 95 + kd].copy_from_slice(&RSN_IE_PSK_CCMP);
    // MIC over the whole 802.1X frame (offset 14..end) with the MIC field zeroed.
    let mic = crate::wpa::wpa_mic_sha1(&kck, &m2[14..]);
    m2[body + 77..body + 93].copy_from_slice(&mic);

    out.m2_tx_ok = sdpcm_data_tx(&m2);

    // Watch for M3 (another EAPOL from the AP) or a deauth.
    let mut rx = [0u8; 2048];
    let mut i = 0u32;
    while i < 5000 {
        i += 1;
        if i % 256 == 0 {
            let _ = ensure_ht_avail();
        }
        match read_sdpcm_frame(&mut rx) {
            Some((2, _h, doff)) => {
                let bdc_doff = rx[doff + 3] as usize;
                let eth = doff + 4 + bdc_doff * 4;
                if eth + body + 3 > rx.len() {
                    continue;
                }
                if u16::from_be_bytes([rx[eth + 12], rx[eth + 13]]) == 0x888E {
                    let ki = u16::from_be_bytes([rx[eth + body + 1], rx[eth + body + 2]]);
                    // M3 has the ACK bit (0x80) set (AP->STA); M2's echo wouldn't.
                    if ki & 0x0080 != 0 {
                        out.m3_seen = true;
                        out.m3_key_info = ki;
                        out.m3_len = (rx.len() - eth).min(0xffff);
                        break;
                    }
                    out.other_eapol += 1;
                }
            }
            Some((1, _h, doff)) => {
                let bdc_doff = rx[doff + 3] as usize;
                let ev = doff + 4 + bdc_doff * 4;
                if ev + 32 <= rx.len() {
                    let et = u32::from_be_bytes([rx[ev + 28], rx[ev + 29], rx[ev + 30], rx[ev + 31]]);
                    if et == WLC_E_DEAUTH || et == WLC_E_DEAUTH_IND || et == WLC_E_DISASSOC || et == WLC_E_DISASSOC_IND {
                        out.deauth_after = true;
                        break;
                    }
                }
            }
            _ => {}
        }
    }
}

// --- BCDC control over SDIO F2 (SDPCM) — source-verified wire format ----------
// dcmd header: struct brcmf_proto_bcdc_dcmd { u32 cmd; u32 len; u32 flags; u32 status; }
const WLC_GET_VERSION: u32 = 1;
const WLC_SET_VAR: u32 = 263;
const WLC_GET_VAR: u32 = 262;
const BCDC_SET: u32 = 0x02; // flags bit1 = SET (0 = GET)
const SDPCM_HDRLEN: usize = 12; // 4 HW tag + 8 SW header
const BCDC_HDRLEN: usize = 16;
const SDPCM_CONTROL_CHANNEL: u8 = 0;
const SD_REG_INTSTATUS: u32 = 0x20;
const I_HMB_FRAME_IND: u32 = 0x40; // I_HMB_SW2 — a frame is ready on F2
const BRCMF_FIRSTREAD: usize = 64;

// SDPCM tx-credit + sequence state (brcmf init: tx_seq=255, tx_max=0 => 1 boot credit).
static mut TX_SEQ: u8 = 255;
static mut TX_MAX: u8 = 0;
static mut BCDC_REQID: u32 = 0;
// P10-C diagnostics for the first control round-trip (GET "ver").
// [0]=tx_seq used [1]=tx_ok [2]=credit_avail [3]=intstatus [4]=rx_ok [5]=hw_len
// [6]=cksum_ok [7]=channel [8]=doffset [9]=reqid_match [10]=bcdc_status [11]=tx_max_after
static mut BCDC_DIAG: [u32; 12] = [0; 12];
pub fn bcdc_diag() -> [u32; 12] {
    unsafe { BCDC_DIAG }
}

/// Cached SDIO-core regbase. AUDIT M-4: this is called from read_sdpcm_frame AND
/// bcdc_dcmd, i.e. once per frame poll. An EROM walk costs ~30 descriptor reads x
/// 7 SDIO commands each (~210 commands); wifi_scan polls up to 12000 times, so the
/// uncached form burned on the order of 2.5M SDIO transactions per scan. The core
/// layout is fixed for the life of the chip, so walk it once.
static mut SDIO_CORE_BASE: u32 = 0;
fn sdio_core_base() -> u32 {
    unsafe {
        if SDIO_CORE_BASE == 0 {
            SDIO_CORE_BASE = erom_find_core(CORE_SDIO_DEV).map(|(b, _)| b).unwrap_or(0);
        }
        SDIO_CORE_BASE
    }
}

/// Force the HT-chain resources up via the PMU min/max_res_mask (the SDIO-core
/// CHIPCLKCSR request path doesn't propagate on bare-metal HEQK). Idempotent.
fn force_ht_resmask() {
    let cc = SI_ENUM_BASE;
    let maxr = bp_r32(cc + CC_MAX_RES_MASK);
    bp_w32(cc + CC_MAX_RES_MASK, maxr | HT_RES_BITS);
    let minr = bp_r32(cc + CC_MIN_RES_MASK);
    bp_w32(cc + CC_MIN_RES_MASK, minr | HT_RES_BITS);
    bp_w32(cc + CC_PMUCONTROL, bp_r32(cc + CC_PMUCONTROL) | PMU_CTL_PLL_UPD);
}

static mut WAKE_DIAG: (u32, u32) = (0, 0); // (SLEEPCSR before, after wake)
/// Wake the chip: assert KSO (Keep-SDIO-On) and poll for DEVON (device on). After the
/// firmware boots it can idle into deep sleep (clocks off, KSO/DEVON drop) if unserviced
/// — then F1/F2 access returns 0 and CMD53-to-F2 times out. brcmf re-asserts KSO and
/// waits for DEVON before each transaction on SR-capable parts (43455 is SR-capable).
fn wake_chip() -> u8 {
    let before = cmd52(false, 1, SBSDIO_SLEEPCSR, 0).unwrap_or(0);
    let _ = cmd52(true, 1, SBSDIO_SLEEPCSR, before | SBSDIO_KSO_EN);
    let mut after = before;
    for _ in 0..200 {
        after = cmd52(false, 1, SBSDIO_SLEEPCSR, 0).unwrap_or(0);
        // DEVON (0x02) set = device awake and backplane reachable.
        if after & 0x02 != 0 {
            break;
        }
        let _ = cmd52(true, 1, SBSDIO_SLEEPCSR, after | SBSDIO_KSO_EN);
        delay(1_000);
    }
    unsafe { WAKE_DIAG = (before as u32, after as u32) };
    after
}
/// (SLEEPCSR before, after) the KSO wake — after should have DEVON(0x02) + KSO(0x01) set.
pub fn wake_diag() -> (u32, u32) {
    unsafe { WAKE_DIAG }
}

static mut P10C_STATE: [u32; 4] = [0; 4]; // [chip_id, f2_ior, sleepcsr, chipclkcsr] at txn time
/// Snapshot the SDIO link state at the control-path entry so we can tell a sleeping/dead
/// link (all reads 0) from a live one that just needs HT. [chip_id via CMD52, F2 IOR,
/// SLEEPCSR, CHIPCLKCSR].
fn p10c_state_probe() {
    let mut id = 0u32;
    // chip ID low byte via ChipCommon window (bp_r32) — proves the backplane is reachable.
    id = bp_r32(SI_ENUM_BASE) & 0xffff;
    let f2 = cmd52(false, 0, SDIO_FUNC_READY, 0).unwrap_or(0) as u32;
    let sleep = cmd52(false, 1, SBSDIO_SLEEPCSR, 0).unwrap_or(0) as u32;
    let clk = cmd52(false, 1, CHIPCLKCSR, 0).unwrap_or(0) as u32;
    unsafe { P10C_STATE = [id, f2, sleep, clk] };
}
/// [chip_id(0x4345=link alive), F2 IOR(0x04=ready), SLEEPCSR(0x03=awake), CHIPCLKCSR] at txn entry.
pub fn p10c_state() -> [u32; 4] {
    unsafe { P10C_STATE }
}

static mut HT_ENSURE_DIAG: u32 = 0;
/// Ensure the HT backplane clock is AVAILABLE (CHIPCLKCSR HT_AVAIL 0x80 reads back)
/// before F2 SDPCM traffic — the F2/DMA engine lives on HT; without it CMD53-to-F2
/// command-times-out (F1 always-on access still works). After the firmware boots it
/// takes over the PMU and lets the forced HT resources drop, so re-establish here:
/// try FORCE_HT (the running firmware may honor the request), else re-force via the
/// resource mask. Returns the final CHIPCLKCSR.
fn ensure_ht_avail() -> u8 {
    let clk = cmd52(false, 1, CHIPCLKCSR, 0).unwrap_or(0);
    if clk & SBSDIO_HT_AVAIL == 0 {
        let _ = cmd52(true, 1, CHIPCLKCSR, clk | SBSDIO_FORCE_HT);
        let mut up = false;
        for _ in 0..200 {
            if cmd52(false, 1, CHIPCLKCSR, 0).unwrap_or(0) & SBSDIO_HT_AVAIL != 0 {
                up = true;
                break;
            }
            delay(1_000);
        }
        if !up {
            force_ht_resmask();
            for _ in 0..300 {
                if cmd52(false, 1, CHIPCLKCSR, 0).unwrap_or(0) & SBSDIO_HT_AVAIL != 0 {
                    break;
                }
                delay(1_000);
            }
        }
    }
    let final_clk = cmd52(false, 1, CHIPCLKCSR, 0).unwrap_or(0);
    unsafe { HT_ENSURE_DIAG = final_clk as u32 };
    final_clk
}
/// CHIPCLKCSR after ensure_ht_avail (want HT_AVAIL 0x80 set before the F2 control txn).
pub fn ht_ensure_diag() -> u32 {
    unsafe { HT_ENSURE_DIAG }
}
/// SDIO F2 SDPCM access address: ChipCommon-window offset 0 with the 4-byte-access
/// flag (SBSDIO_SB_ACCESS_2_4B_FLAG 0x8000), matching brcmf_sdiod_send_buf.
const F2_SDPCM_ADDR: u32 = 0x8000;

static mut MAILBOX_DIAG: (u32, u32) = (0, 0); // (intstatus seen, tohostmailboxdata)
/// Service the firmware's software mailbox interrupt (DEVREADY/FWREADY posted right
/// after boot): read tohostmailboxdata, ACK via SMB_INT_ACK, then W1C the SDIO-core
/// intstatus. This de-asserts the firmware's in-band SDIO interrupt so it stops
/// wedging the SDHCI command engine. Safe to call repeatedly.
fn drain_firmware_mailbox() {
    let sdb = sdio_core_base();
    if sdb == 0 {
        return;
    }
    let intstat = bp_r32(sdb + SD_REG_INTSTATUS);
    let mbdata = bp_r32(sdb + SD_REG_TOHOSTMAILBOXDATA);
    // ACK the firmware's software mailbox, then clear the handled intstatus bits.
    let _ = bp_w32(sdb + SD_REG_TOSBMAILBOX, SMB_INT_ACK);
    if intstat != 0 {
        let _ = bp_w32(sdb + SD_REG_INTSTATUS, intstat);
    }
    unsafe { MAILBOX_DIAG = (intstat, mbdata) };
}
/// (SDIO-core intstatus, tohostmailboxdata) seen when the firmware's mailbox was drained.
pub fn mailbox_diag() -> (u32, u32) {
    unsafe { MAILBOX_DIAG }
}
/// Control credits available (u8 modulo-256), per brcmf txctl_ok.
fn credit_avail() -> u8 {
    unsafe { TX_MAX.wrapping_sub(TX_SEQ) }
}
fn txctl_ok() -> bool {
    let d = credit_avail();
    d != 0 && (d & 0x80) == 0
}

fn bcdc_iovar_set(iovar: &[u8]) -> bool {
    bcdc_dcmd(WLC_SET_VAR, BCDC_SET, iovar, &mut []).0
}
fn bcdc_iovar_get(name: &[u8], out: &mut [u8]) -> bool {
    let mut req = [0u8; 64];
    let n = iovar_buf(name, &[], &mut req);
    bcdc_dcmd(WLC_GET_VAR, 0, &req[..n], out).0
}

/// One BCDC dcmd request/reply on the SDPCM control channel (0) over F2. Returns
/// (ok, bcdc_status). Builds HW tag + 8-B SW header + 16-B BCDC dcmd + payload, gates
/// on tx credit, sends via CMD53 F2, then polls the SDIO-core intstatus frame-ind bit,
/// does the 64-B first read + remainder, validates the header, advances tx_max from the
/// reply's SW window byte, and copies the reply body (after doffset+16) into `reply`.
fn bcdc_dcmd(cmd: u32, flags: u32, payload: &[u8], reply: &mut [u8]) -> (bool, u32) {
    let reqid = unsafe {
        BCDC_REQID = BCDC_REQID.wrapping_add(1);
        BCDC_REQID
    };
    let want_diag = reqid == 1; // capture the first control round-trip (the ver probe)
    // --- credit gate. The very first control frame rides the boot credit (tx_max-tx_seq
    //     = 1). Later frames need the firmware to advance tx_max via a reply's window byte.
    let cred = credit_avail();
    if !txctl_ok() {
        if want_diag {
            unsafe { BCDC_DIAG[2] = cred as u32; }
        }
        return (false, 0);
    }
    let seq = unsafe { TX_SEQ };
    // --- build the frame.
    let mut frame = [0u8; DL_CHUNK + 64];
    // SW word0: seq[0:7] | channel[8:11] | nextlen[16:23]=0 | doffset[24:31]=12.
    let w0: u32 = (seq as u32)
        | ((SDPCM_CONTROL_CHANNEL as u32) << 8)
        | ((SDPCM_HDRLEN as u32) << 24);
    // BCDC header. `len` = for a GET, the OUTPUT buffer size the firmware may fill
    // (reply.len()); for a SET, the payload length. The frame still carries only the
    // actual payload bytes; len just tells the firmware how much it may return.
    let bcdc_len = if reply.is_empty() {
        payload.len()
    } else {
        reply.len().max(payload.len())
    };
    let bcdc = SDPCM_HDRLEN;
    frame[bcdc..bcdc + 4].copy_from_slice(&cmd.to_le_bytes());
    frame[bcdc + 4..bcdc + 8].copy_from_slice(&(bcdc_len as u32).to_le_bytes());
    let flg = flags | (reqid << 16); // SET bit + reqid in [31:16]
    frame[bcdc + 8..bcdc + 12].copy_from_slice(&flg.to_le_bytes());
    // status [bcdc+12..+16] left 0.
    let body = bcdc + BCDC_HDRLEN;
    let n = payload.len().min(frame.len() - body);
    frame[body..body + n].copy_from_slice(&payload[..n]);
    let total = (body + n) as u16; // SDPCM length: tag+swhdr+bcdc+payload (no tail pad)
    // HW tag (LE16 len, LE16 ~len).
    frame[0..2].copy_from_slice(&total.to_le_bytes());
    frame[2..4].copy_from_slice(&(!total).to_le_bytes());
    // SW header word0 @ off 4; word1 @ off 8 = 0 on TX.
    frame[4..8].copy_from_slice(&w0.to_le_bytes());
    // --- send on F2 (transfer padded to 4; firmware trims to the SDPCM length).
    //     F2 SDPCM address = 0x8000 (4-byte-access flag), incrementing — per brcmf.
    let padded = ((total as usize) + 3) & !3;
    let tx_ok = cmd53_write(2, F2_SDPCM_ADDR, &frame[..padded]);
    if tx_ok {
        unsafe { TX_SEQ = TX_SEQ.wrapping_add(1) }; // seq wraps at 256
    }
    if want_diag {
        unsafe {
            BCDC_DIAG[0] = seq as u32;
            BCDC_DIAG[1] = tx_ok as u32;
            BCDC_DIAG[2] = cred as u32;
        }
    }
    if !tx_ok {
        return (false, 0);
    }
    // --- RX DEMUX: the firmware interleaves channel-1 EVENT frames and channel-2 DATA
    //     frames with our channel-0 CONTROL reply. Read frames one at a time, advance
    //     tx_max from EACH frame's SW window byte (credits flow from all channels), and
    //     keep going until we get the control reply with our reqid (or run dry).
    let sdb = sdio_core_base();
    let mut rx = [0u8; DL_CHUNK + 64];
    let mut status = 0u32;
    let mut got_ctrl = false;
    let mut last_chan = 0xffu8;
    let mut last_len = 0u16;
    let mut last_doff = 0usize;
    let mut reqid_match = false;
    let mut last_cksum_ok = false;
    let mut any_rx = false;
    let mut intstat_seen = 0u32;
    'frames: for _frame in 0..40 {
        // poll for a frame indication, then read the 64-byte first chunk (retry until a
        // non-empty tag). An all-zero tag = no frame currently waiting.
        let mut rx_ok = false;
        let mut hw_len = 0u16;
        let mut hw_ck = 0u16;
        let mut waited_empty = 0u32;
        loop {
            let intstat = bp_r32(sdb + SD_REG_INTSTATUS);
            if intstat != 0 {
                intstat_seen = intstat;
                let _ = bp_w32(sdb + SD_REG_INTSTATUS, intstat); // W1C
            }
            rx_ok = cmd53_read(2, F2_SDPCM_ADDR, &mut rx[..BRCMF_FIRSTREAD]);
            hw_len = u16::from_le_bytes([rx[0], rx[1]]);
            hw_ck = u16::from_le_bytes([rx[2], rx[3]]);
            if rx_ok && (hw_len != 0 || hw_ck != 0) {
                break;
            }
            waited_empty += 1;
            if waited_empty > 800 {
                break 'frames; // dry — no more frames
            }
            delay(1_000);
        }
        any_rx = any_rx || rx_ok;
        let cksum_ok = hw_len != 0 && ((!(hw_len ^ hw_ck)) & 0xffff) == 0;
        if !cksum_ok {
            break 'frames; // malformed tag — stop
        }
        let w0r = u32::from_le_bytes([rx[4], rx[5], rx[6], rx[7]]);
        let w1r = u32::from_le_bytes([rx[8], rx[9], rx[10], rx[11]]);
        let channel = ((w0r >> 8) & 0xf) as u8;
        let doffset = ((w0r >> 24) & 0xff) as usize;
        // advance tx_max from this frame's window byte (brcmf clamp).
        let mut new_max = ((w1r >> 8) & 0xff) as u8;
        if new_max.wrapping_sub(unsafe { TX_SEQ }) > 0x40 {
            new_max = unsafe { TX_SEQ }.wrapping_add(2);
        }
        unsafe { TX_MAX = new_max };
        last_chan = channel;
        last_len = hw_len;
        last_doff = doffset;
        last_cksum_ok = cksum_ok;
        // read the remainder if the frame is longer than the first 64 bytes.
        // DRV-4 (mirrors the M-3 fix in read_sdpcm_frame): cmd53_read silently caps a
        // byte-mode transfer at 512 B and still returns true, so for hw_len >
        // FIRSTREAD+512 the tail of rx is NEVER written by this frame. rx is reused
        // across the frame loop, so the BCDC header/reply below could otherwise be
        // assembled from a PREVIOUS frame's bytes (stale firmware-control data crossing
        // the trust boundary). Zero the unfillable region and clamp every downstream
        // bound to `valid` = bytes actually transferred, not rx.len().
        let mut valid = BRCMF_FIRSTREAD;
        if (hw_len as usize) > BRCMF_FIRSTREAD {
            let rest = ((hw_len as usize) - BRCMF_FIRSTREAD + 3) & !3;
            let end = (BRCMF_FIRSTREAD + rest).min(rx.len());
            let got = (end - BRCMF_FIRSTREAD).min(512); // what cmd53_read actually moves
            for b in rx[BRCMF_FIRSTREAD + got..end].iter_mut() {
                *b = 0;
            }
            let _ = cmd53_read(2, F2_SDPCM_ADDR, &mut rx[BRCMF_FIRSTREAD..end]);
            valid = BRCMF_FIRSTREAD + got;
        }
        // A control (channel 0) frame with a BCDC header is our reply candidate.
        if channel == SDPCM_CONTROL_CHANNEL
            && doffset >= SDPCM_HDRLEN
            && doffset + BCDC_HDRLEN <= valid
            && (hw_len as usize) >= doffset + BCDC_HDRLEN
        {
            let bh = doffset;
            let rflags = u32::from_le_bytes([rx[bh + 8], rx[bh + 9], rx[bh + 10], rx[bh + 11]]);
            status = u32::from_le_bytes([rx[bh + 12], rx[bh + 13], rx[bh + 14], rx[bh + 15]]);
            if (rflags >> 16) == reqid {
                reqid_match = true;
                got_ctrl = true;
                let off = doffset + BCDC_HDRLEN;
                if !reply.is_empty() && off < valid {
                    let m = reply.len().min(valid - off);
                    reply[..m].copy_from_slice(&rx[off..off + m]);
                }
                break 'frames;
            }
        }
        // else: event/data frame or wrong reqid — skip it and read the next.
    }
    if want_diag {
        unsafe {
            BCDC_DIAG[3] = intstat_seen;
            BCDC_DIAG[4] = any_rx as u32;
            BCDC_DIAG[5] = last_len as u32;
            BCDC_DIAG[6] = last_cksum_ok as u32;
            BCDC_DIAG[7] = last_chan as u32;
            BCDC_DIAG[8] = last_doff as u32;
            BCDC_DIAG[9] = reqid_match as u32;
            BCDC_DIAG[10] = status;
            BCDC_DIAG[11] = TX_MAX as u32;
        }
    }
    // success = got the control reply with our reqid and no BCDC error status.
    (got_ctrl && reqid_match && status == 0, status)
}

/// P10-C metal gate — the canonical control round-trip: GET "ver". If this returns a
/// non-empty version string with status 0, the entire SDPCM/BCDC path works and
/// clmload/country will follow. `out` receives the version string.
pub fn bcdc_ver_probe(out: &mut [u8]) -> bool {
    // 1. Wake the chip (assert KSO, wait DEVON) — the firmware may have idled it into
    //    deep sleep between F2-ready and now, dropping all clocks (CHIPCLKCSR read 0x00).
    wake_chip();
    // 2. Snapshot link state (chip-id/F2-IOR/SLEEPCSR/CHIPCLKCSR) to tell sleep from dead.
    p10c_state_probe();
    // 3. Service the firmware's boot-time mailbox interrupt so it stops asserting the
    //    in-band SDIO card interrupt (which otherwise wedges the command engine).
    drain_firmware_mailbox();
    // 4. The F2/SDPCM DMA engine lives on the HT backplane clock, which the firmware let
    //    drop after boot. Re-establish HT (HT_AVAIL must read back) or CMD53-to-F2 times out.
    ensure_ht_avail();
    bcdc_iovar_get(b"ver", out)
}
