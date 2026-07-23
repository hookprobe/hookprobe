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
        if spin > 1_000_000 {
            unsafe { SDIO_DIAG = (r32(PRESENT_STATE), 0xDEAD_0001) };
            return None;
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
    // PIO: wait buffer-read-ready, then confirm Present State BUF_RD_EN (b11) before
    // touching the FIFO — reading 0x20 early yields deterministic garbage.
    let mut spin = 0u32;
    while r32(INT_STATUS) & INT_BUF_RD_RDY == 0 || r32(PRESENT_STATE) & PS_BUF_RD_EN == 0 {
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
    w32(INT_ENABLE, 0xFFFF_FFFF);
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
        write_volatile(data, read_volatile(data) | (1u32 << 28)); // drive high = radio on
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
    // trailer word = token_count | (~token_count << 16), token_count = n/4
    let tokens = (n / 4) as u32;
    let trailer = tokens | (!tokens << 16);
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
    let mut spin = 0u32;
    while r32(INT_STATUS) & INT_BUF_WR_RDY == 0 || r32(PRESENT_STATE) & PS_BUF_WR_EN == 0 {
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

/// Write `data` to backplane address `addr` in ≤32 KiB windows (F1).
fn backplane_write(mut addr: u32, data: &[u8]) -> bool {
    let mut off = 0usize;
    while off < data.len() {
        set_backplane_window(addr);
        let win_off = (addr & 0x7FFF) as usize;
        let space = 0x8000 - win_off;
        let n = space.min(data.len() - off).min(512); // CMD53 byte cap per burst
        if !cmd53_write(1, (win_off as u32) | 0x8000, &data[off..off + n]) {
            return false;
        }
        off += n;
        addr += n as u32;
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
    let base = addr & 0x7FFF;
    let bytes = val.to_le_bytes();
    let mut ok = true;
    for i in 0..4u32 {
        ok &= cmd52(true, 1, base + i, bytes[i as usize]).is_some();
    }
    ok
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
    // 1. Request the ALP clock (backplane clock for memory access).
    let _ = cmd52(true, 1, CHIPCLKCSR, SBSDIO_ALP_AVAIL_REQ);
    for _ in 0..50 {
        if cmd52(false, 1, CHIPCLKCSR, 0).map(|v| v & SBSDIO_ALP_AVAIL).unwrap_or(0) != 0 {
            break;
        }
        delay(1_000);
    }
    unsafe { FW_STEP = 2 };
    // 2. CR4 PASSIVE — EROM-find the CR4, halt its CPU (TCM writable), reset D11.
    let (_cr4b, cr4w) = match cr4_set_passive() {
        Some(v) => v,
        None => return false, // EROM lookup failed — FW_STEP stays 2
    };
    unsafe { FW_STEP = 3 };
    // 3. Firmware → CR4 TCM base (0x198000 — NOT 0). Window-split at 32 KiB.
    if !backplane_write(RAM_BASE, FW_BIN) {
        return false;
    }
    unsafe { FW_STEP = 4 };
    // 4. NVRAM (stripped + trailer) at rambase + ramsize - varsz (ends at top of RAM).
    let nlen = nvram_strip(NVRAM_TXT, nvram_scratch);
    let nvram_addr = RAM_BASE + RAM_SIZE - (nlen as u32);
    if !backplane_write(nvram_addr, &nvram_scratch[..nlen]) {
        return false;
    }
    unsafe { FW_STEP = 5 };
    // 5. CR4 ACTIVATE — reset vector (fw[0..4]) → addr 0, clear CPUHALT → CPU boots.
    let rstvec = u32::from_le_bytes([FW_BIN[0], FW_BIN[1], FW_BIN[2], FW_BIN[3]]);
    cr4_activate(cr4w, rstvec);
    unsafe { FW_STEP = 6 };
    // 6. Switch to the HT (fast) clock — firmware needs it to come up.
    let _ = cmd52(true, 1, CHIPCLKCSR, SBSDIO_HT_AVAIL_REQ);
    for _ in 0..100 {
        if cmd52(false, 1, CHIPCLKCSR, 0).map(|v| v & SBSDIO_HT_AVAIL).unwrap_or(0) != 0 {
            break;
        }
        delay(1_000);
    }
    unsafe { FW_STEP = 7 };
    // 7. Enable F2, poll ready — F2 ready = firmware alive (tens of ms typical).
    let _ = cmd52(true, 0, SDIO_FUNC_ENABLE, SDIO_F2);
    for _ in 0..500 {
        if cmd52(false, 0, SDIO_FUNC_READY, 0).map(|v| v & SDIO_F2).unwrap_or(0) != 0 {
            // Watermark (brcmf_sdio_bus_init) then done.
            let _ = cmd52(true, 1, 0x10008, 8);
            unsafe { FW_STEP = 8 };
            return true;
        }
        delay(2_000);
    }
    false
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

// --- BCDC control over SDIO F2 (SDPCM) — structured; metal-iterated -----------
// dcmd header: struct brcmf_proto_bcdc_dcmd { u32 cmd; u32 len; u32 flags; u32 status; }
const WLC_SET_VAR: u32 = 263;
const WLC_GET_VAR: u32 = 262;
const BCDC_SET: u32 = 0x02;

/// Send a BCDC set-iovar dcmd over F2. (SDPCM software header + seq/credit handling
/// is the metal-iterated part; the BCDC dcmd + iovar payload framing is exact.)
fn bcdc_iovar_set(iovar: &[u8]) -> bool {
    bcdc_dcmd(WLC_SET_VAR, BCDC_SET, iovar, &mut [])
}
fn bcdc_iovar_get(name: &[u8], out: &mut [u8]) -> bool {
    // "<name>\0" as the request payload; reply lands in `out`.
    let mut req = [0u8; 48];
    let n = iovar_buf(name, &[], &mut req);
    bcdc_dcmd(WLC_GET_VAR, 0, &req[..n], out)
}

/// One BCDC dcmd request/reply on the SDPCM control channel over F2. Builds the
/// 16-byte BCDC header + payload; sends via CMD53 on F2 with the SDPCM frame tag.
/// NOTE: the SDPCM software header (seq, channel, doffset) + tx-credit flow control
/// are structured here and confirmed on metal — this is the Stage C metal gate.
fn bcdc_dcmd(cmd: u32, flags: u32, payload: &[u8], reply: &mut [u8]) -> bool {
    static mut REQID: u32 = 0;
    let reqid = unsafe {
        REQID = REQID.wrapping_add(1);
        REQID
    };
    let mut frame = [0u8; DL_CHUNK + 64];
    // SDPCM hardware frame tag (len | ~len) + software header (8 B) precede BCDC.
    let sdpcm = 12usize; // hw tag(4) + sw header(8)
    let bcdc = sdpcm;
    // BCDC header.
    frame[bcdc..bcdc + 4].copy_from_slice(&cmd.to_le_bytes());
    frame[bcdc + 4..bcdc + 8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    let flg = flags | (reqid << 16);
    frame[bcdc + 8..bcdc + 12].copy_from_slice(&flg.to_le_bytes());
    frame[bcdc + 12..bcdc + 16].copy_from_slice(&0u32.to_le_bytes()); // status
    let body = bcdc + 16;
    let n = payload.len().min(frame.len() - body);
    frame[body..body + n].copy_from_slice(&payload[..n]);
    let total = (body + n) as u16;
    // SDPCM hw tag.
    frame[0..2].copy_from_slice(&total.to_le_bytes());
    frame[2..4].copy_from_slice(&(!total).to_le_bytes());
    // sw header doffset = header length (control channel = 0).
    frame[6] = sdpcm as u8; // doffset field position (structured)
    // Send on F2 (whole frame), pad to 4.
    let padded = ((total as usize) + 3) & !3;
    if !cmd53_write(2, 0, &frame[..padded]) {
        return false;
    }
    // Read the reply (GET) — drain one control frame off F2 and copy the BCDC body.
    if !reply.is_empty() {
        let mut rx = [0u8; DL_CHUNK + 64];
        if !cmd53_read(2, 0, &mut rx) {
            return false;
        }
        // Skip SDPCM + BCDC headers; copy the reply body.
        let off = sdpcm + 16;
        let m = reply.len().min(rx.len() - off);
        reply[..m].copy_from_slice(&rx[off..off + m]);
    }
    true
}
