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
        let mut val;
        let mut desc;
        loop {
            val = erom_rd(a);
            desc = val & DMP_DESC_MSK;
            if desc == DMP_DESC_ADDRESS || desc == DMP_DESC_COMPONENT || desc == DMP_DESC_EOT {
                break;
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
    let ramsize = cr4_ramsize(cr4b);
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
    // 7. Enable F2, poll ready — F2 ready = firmware alive.
    let _ = cmd52(true, 0, SDIO_FUNC_ENABLE, SDIO_F2);
    for _ in 0..2000 {
        let ior = cmd52(false, 0, SDIO_FUNC_READY, 0).unwrap_or(0);
        unsafe { F2_DIAG.2 = ior as u32 };
        if ior & SDIO_F2 != 0 {
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
            return true;
        }
        delay(2_000);
    }
    false
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
pub fn set_regdomain(iso: &[u8; 2], rev: i32) -> Option<bool> {
    // clmload — chunk the CLM blob with BEGIN on first / END on last.
    let mut buf = [0u8; DL_CHUNK + 32];
    let total = CLM_BLOB.len();
    let mut off = 0usize;
    while off < total {
        let n = (total - off).min(DL_CHUNK);
        let mut flag = 0u16;
        if off == 0 {
            flag |= DL_BEGIN;
        }
        if off + n >= total {
            flag |= DL_END;
        }
        let clen = clm_chunk(flag, &CLM_BLOB[off..off + n], &mut buf);
        // iovar "clmload" carrying this dload chunk, via BCDC WLC_SET_VAR.
        let mut iob = [0u8; DL_CHUNK + 48];
        let ilen = iovar_buf(b"clmload", &buf[..clen], &mut iob);
        if !bcdc_iovar_set(&iob[..ilen]) {
            return None;
        }
        off += n;
    }
    // country iovar.
    let mut cp = [0u8; 12];
    country_payload(iso, rev, &mut cp);
    let mut iob = [0u8; 48];
    let ilen = iovar_buf(b"country", &cp, &mut iob);
    if !bcdc_iovar_set(&iob[..ilen]) {
        return None;
    }
    // read back.
    let mut rb = [0u8; 12];
    if !bcdc_iovar_get(b"country", &mut rb) {
        return None;
    }
    Some(!(rb[0] == b'0' && rb[1] == b'0') && rb[0] != 0)
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

fn sdio_core_base() -> u32 {
    erom_find_core(CORE_SDIO_DEV).map(|(b, _)| b).unwrap_or(0)
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
    // BCDC header.
    let bcdc = SDPCM_HDRLEN;
    frame[bcdc..bcdc + 4].copy_from_slice(&cmd.to_le_bytes());
    frame[bcdc + 4..bcdc + 8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
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
    // --- wait for the reply: poll the SDIO-core intstatus frame-ind bit.
    let sdb = sdio_core_base();
    let mut intstat = 0u32;
    for _ in 0..2000 {
        intstat = bp_r32(sdb + SD_REG_INTSTATUS);
        if intstat & I_HMB_FRAME_IND != 0 {
            break;
        }
        delay(1_000);
    }
    // W1C the handled intstatus bits.
    if intstat != 0 {
        let _ = bp_w32(sdb + SD_REG_INTSTATUS, intstat);
    }
    if want_diag {
        unsafe { BCDC_DIAG[3] = intstat; }
    }
    // --- 64-byte first read, retried until a non-empty frame tag appears (the reply
    //     may land a little after the frame-ind bit). An all-zero tag = nothing yet.
    let mut rx = [0u8; DL_CHUNK + 64];
    let mut rx_ok = false;
    let mut hw_len = 0u16;
    let mut hw_ck = 0u16;
    for _ in 0..1000 {
        rx_ok = cmd53_read(2, F2_SDPCM_ADDR, &mut rx[..BRCMF_FIRSTREAD]);
        hw_len = u16::from_le_bytes([rx[0], rx[1]]);
        hw_ck = u16::from_le_bytes([rx[2], rx[3]]);
        if rx_ok && (hw_len != 0 || hw_ck != 0) {
            break;
        }
        delay(1_000);
    }
    let cksum_ok = hw_len != 0 && ((!(hw_len ^ hw_ck)) & 0xffff) == 0;
    let w0r = u32::from_le_bytes([rx[4], rx[5], rx[6], rx[7]]);
    let w1r = u32::from_le_bytes([rx[8], rx[9], rx[10], rx[11]]);
    let channel = ((w0r >> 8) & 0xf) as u8;
    let doffset = ((w0r >> 24) & 0xff) as usize;
    // advance tx_max from the reply's window byte (SW word1 bits 8..15), brcmf clamp.
    let mut new_max = ((w1r >> 8) & 0xff) as u8;
    if new_max.wrapping_sub(unsafe { TX_SEQ }) > 0x40 {
        new_max = unsafe { TX_SEQ }.wrapping_add(2);
    }
    unsafe { TX_MAX = new_max };
    // read the remainder if the frame is longer than the first 64 bytes.
    if cksum_ok && (hw_len as usize) > BRCMF_FIRSTREAD {
        let rest = ((hw_len as usize) - BRCMF_FIRSTREAD + 3) & !3;
        let end = (BRCMF_FIRSTREAD + rest).min(rx.len());
        let _ = cmd53_read(2, F2_SDPCM_ADDR, &mut rx[BRCMF_FIRSTREAD..end]);
    }
    // locate + copy the reply body (after doffset + 16-byte BCDC header).
    let mut status = 0u32;
    let mut reqid_match = false;
    let valid = rx_ok && cksum_ok && channel == SDPCM_CONTROL_CHANNEL
        && doffset >= SDPCM_HDRLEN && doffset + BCDC_HDRLEN <= rx.len();
    if valid {
        let bh = doffset;
        let rflags = u32::from_le_bytes([rx[bh + 8], rx[bh + 9], rx[bh + 10], rx[bh + 11]]);
        status = u32::from_le_bytes([rx[bh + 12], rx[bh + 13], rx[bh + 14], rx[bh + 15]]);
        reqid_match = (rflags >> 16) == reqid;
        let off = doffset + BCDC_HDRLEN;
        if !reply.is_empty() && off < rx.len() {
            let m = reply.len().min(rx.len() - off);
            reply[..m].copy_from_slice(&rx[off..off + m]);
        }
    }
    if want_diag {
        unsafe {
            BCDC_DIAG[4] = rx_ok as u32;
            BCDC_DIAG[5] = hw_len as u32;
            BCDC_DIAG[6] = cksum_ok as u32;
            BCDC_DIAG[7] = channel as u32;
            BCDC_DIAG[8] = doffset as u32;
            BCDC_DIAG[9] = reqid_match as u32;
            BCDC_DIAG[10] = status;
            BCDC_DIAG[11] = TX_MAX as u32;
        }
    }
    // success = valid control reply, matching reqid, no BCDC error status.
    (valid && reqid_match && status == 0, status)
}

/// P10-C metal gate — the canonical control round-trip: GET "ver". If this returns a
/// non-empty version string with status 0, the entire SDPCM/BCDC path works and
/// clmload/country will follow. `out` receives the version string.
pub fn bcdc_ver_probe(out: &mut [u8]) -> bool {
    // Service the firmware's boot-time mailbox interrupt first so it stops asserting
    // the in-band SDIO card interrupt (which otherwise wedges the command engine).
    drain_firmware_mailbox();
    // The F2/SDPCM DMA engine lives on the HT backplane clock, which the firmware let
    // drop after boot. Re-establish HT (HT_AVAIL must read back) or CMD53-to-F2 times out.
    ensure_ht_avail();
    bcdc_iovar_get(b"ver", out)
}
