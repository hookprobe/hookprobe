//! P10-BT — CYW43455 Bluetooth over HCI-UART (H4) on CM5 / BCM2712.
//!
//! The BT side of the combo chip is NOT on SDIO (that's the WiFi side, cyw43.rs) —
//! it hangs off `uarta`, a **NS16550A** (not the PL011 console, not the mini-UART)
//! at 0x10_7D50_C000 with `reg-shift = 2` (32-bit accesses, offsets x4) and a fixed
//! 96 MHz clock. Source-verified against the RPi kernel tree:
//!   - bcm2712-rpi-cm5.dtsi: `&uarta { ... bluetooth { compatible="brcm,bcm43438-bt";
//!     max-speed=<3000000>; shutdown-gpios=<&gio 29 GPIO_ACTIVE_HIGH>; } }`
//!   - bcm2712-ds.dtsi: uarta = serial@7d50c000 "brcm,bcm7271-uart" (NS16550A)
//!   - soc ranges add 0x10_0000_0000 -> physical 0x10_7D50_C000
//!   - gpio-brcmstb.c: GIO regs ODEN/DATA/IODIR at +0x00/+0x04/+0x08, IODIR 0=output
//!
//! SAFETY — WL_ON (WiFi enable) is **gpio28**, BT_ON is **gpio29**: they share the
//! SAME pinmux and GIO registers. Every write here is read-modify-write with gpio28's
//! field masked out, so bringing BT up can never knock the working WiFi down.
//!
//! The .hcd firmware patch is OPTIONAL: btbcm_initialize() treats a missing patch as
//! non-fatal and HCI (incl. LE scanning) works from ROM. We take the patch-free path;
//! only vendor tuning/coex is lost. Every wait here is bounded — this must never hang.

use core::ptr::{read_volatile, write_volatile};

const BT_UART: usize = 0x10_7D50_C000; // uarta (brcm,bcm7271-uart 16550 core), reg-shift 2
const GIO_BASE: usize = 0x10_7D50_8500; // SoC gio bank0 (BT_ON=gpio29, WL_ON=gpio28)
const PINCTRL: usize = 0x10_7D50_4100; // bcm2712 main pinctrl (D0)
// Register-EXACT from the working CM5 Linux + pinctrl-bcm2712.c (see P10BT_REFERENCE.md).
// uarta pins gpio24(RTS)/25(CTS)/26(TXD)/27(RXD) all live in mux reg 0x08 (nibbles
// 0/1/2/3), function uart0 = fsel index 4. Pull is reg 0x14 (2-bit fields @ 12/14/16/18).
// My first driver used 0x0C/0x24 and the gio line-name numbering (gpio22-25) — the WRONG
// controller namespace — which is why the BT core never answered.
const FSEL: usize = PINCTRL + 0x08; // gpio24..27 mux nibbles
const PULL: usize = PINCTRL + 0x14; // gpio24..27 pull, 2 bits each @ shift 12..

// NS16550A register offsets — reg-shift 2 => byte offset = reg * 4.
const RBR_THR: usize = 0x00; // RBR(r)/THR(w), DLL when DLAB=1
const IER_DLM: usize = 0x04;
const FCR: usize = 0x08; // write-only
const LCR: usize = 0x0C;
const MCR: usize = 0x10;
const LSR: usize = 0x14;

const LCR_DLAB: u32 = 0x80;
const LCR_8N1: u32 = 0x03;
const MCR_DTR: u32 = 0x01;
const MCR_RTS: u32 = 0x02;
const MCR_AFE: u32 = 0x20; // auto RTS/CTS — mandatory at 3 Mbaud
const LSR_DR: u32 = 0x01;
const LSR_THRE: u32 = 0x20;
const LSR_TEMT: u32 = 0x40;

const BT_ON_BIT: u32 = 1 << 29; // gpio29 (WL_ON is bit 28 — never touch it)

// 96 MHz / (16 * baud)
const DIV_115200: u32 = 52;
const DIV_3M: u32 = 2;

#[inline]
fn r32(a: usize) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
#[inline]
fn w32(a: usize, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) };
}

fn delay_us(us: u64) {
    let (freq, start): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) start, options(nomem, nostack));
    }
    let ticks = (freq / 1_000_000).saturating_mul(us);
    loop {
        let now: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) now, options(nomem, nostack)) };
        if now.wrapping_sub(start) >= ticks {
            return;
        }
    }
}

/// Route gpio24/25/26/27 to uart0 (fsel 4) on the bcm2712 main pinctrl.
///
/// Encoding (pinctrl-bcm2712.c): all four pins are 4-bit nibbles in mux reg 0x08 at
/// shifts 0/4/8/12; uart0 = fsel index 4 for each. RMW preserving bits [31:16] — pin28
/// (if present on this pinctrl) sits at shift 16, and WL_ON is a separate gio pin, so
/// this cannot disturb the working WiFi. Pull reg 0x14: bias-disable (0) at shifts
/// 12/14/16/18 to match the DT `uarta_24_pins`.
///
/// Muxing to uart0 also un-gates the UART's functional path — on this SoC the block
/// must be selected before its registers respond, which is why the FIRST UART access
/// must come AFTER this call (my first driver touched the UART before muxing → abort).
fn pinmux() {
    // gpio24..27 -> uart0 (0x4444 in the low 16 bits), preserve [31:16].
    w32(FSEL, (r32(FSEL) & !0x0000_FFFF) | 0x0000_4444);
    // pull: clear the 2-bit fields for pins 24..27 (shifts 12/14/16/18) -> bias-disable.
    w32(PULL, r32(PULL) & !0x000F_F000);
    unsafe { core::arch::asm!("dsb sy", "isb") };
}

/// Drive BT_ON (gpio29). Read-modify-write so WL_ON (bit 28) is untouched.
fn bt_power(on: bool) {
    w32(GIO_BASE + 0x00, r32(GIO_BASE + 0x00) & !BT_ON_BIT); // ODEN: push-pull
    w32(GIO_BASE + 0x08, r32(GIO_BASE + 0x08) & !BT_ON_BIT); // IODIR: 0 = output
    let d = r32(GIO_BASE + 0x04);
    w32(GIO_BASE + 0x04, if on { d | BT_ON_BIT } else { d & !BT_ON_BIT });
}

/// Program the NS16550A: 8N1, FIFOs on, polled, given divisor. `mcr` lets the
/// caller hold RTS low during power-up (the bcm43438 `drive_rts_on_open` quirk).
fn uart_init(div: u32, mcr: u32) {
    w32(BT_UART + LCR, LCR_DLAB);
    w32(BT_UART + RBR_THR, div & 0xff);
    w32(BT_UART + IER_DLM, (div >> 8) & 0xff);
    w32(BT_UART + LCR, LCR_8N1);
    w32(BT_UART + FCR, 0x07); // enable + clear RX/TX FIFOs
    w32(BT_UART + IER_DLM, 0x00); // polled
    w32(BT_UART + MCR, mcr);
}

/// Change baud only (after the controller acked its own switch). Waits for the
/// transmitter to drain first so we never reprogram mid-character.
fn uart_set_div(div: u32) {
    let mut spin = 0u32;
    while r32(BT_UART + LSR) & LSR_TEMT == 0 {
        spin += 1;
        if spin > 200_000 {
            break;
        }
    }
    w32(BT_UART + LCR, LCR_DLAB);
    w32(BT_UART + RBR_THR, div & 0xff);
    w32(BT_UART + IER_DLM, (div >> 8) & 0xff);
    w32(BT_UART + LCR, LCR_8N1);
}

fn putc(b: u8) -> bool {
    let mut spin = 0u32;
    while r32(BT_UART + LSR) & LSR_THRE == 0 {
        spin += 1;
        if spin > 500_000 {
            return false; // bounded — never hang
        }
    }
    w32(BT_UART + RBR_THR, b as u32);
    true
}

/// Read one byte with a bounded wait. `None` = timeout (not an error by itself).
fn getc(timeout: u32) -> Option<u8> {
    let mut spin = 0u32;
    loop {
        if r32(BT_UART + LSR) & LSR_DR != 0 {
            return Some((r32(BT_UART + RBR_THR) & 0xff) as u8);
        }
        spin += 1;
        if spin > timeout {
            return None;
        }
    }
}

/// Send an H4 HCI command: 0x01 | opcode LE16 | plen | params.
fn send_cmd(opcode: u16, params: &[u8]) -> bool {
    if !putc(0x01) {
        return false;
    }
    if !putc((opcode & 0xff) as u8) || !putc((opcode >> 8) as u8) {
        return false;
    }
    if !putc(params.len() as u8) {
        return false;
    }
    for &b in params {
        if !putc(b) {
            return false;
        }
    }
    true
}

/// Read one H4 packet into `buf`. Returns (type, len) of the payload written.
/// Handles EVT (0x04, 2-byte hdr) and ACL (0x02, 4-byte hdr); anything else is a
/// resync error we report rather than hang on.
fn read_pkt(buf: &mut [u8], timeout: u32) -> Option<(u8, usize)> {
    let t = getc(timeout)?;
    match t {
        0x04 => {
            let evt = getc(timeout)?;
            let plen = getc(timeout)? as usize;
            if plen + 2 > buf.len() {
                return None;
            }
            buf[0] = evt;
            buf[1] = plen as u8;
            for i in 0..plen {
                buf[2 + i] = getc(timeout)?;
            }
            Some((0x04, plen + 2))
        }
        0x02 => {
            let mut h = [0u8; 4];
            for i in 0..4 {
                h[i] = getc(timeout)?;
            }
            let dlen = u16::from_le_bytes([h[2], h[3]]) as usize;
            let n = dlen.min(buf.len());
            for i in 0..n {
                buf[i] = getc(timeout)?;
            }
            for _ in n..dlen {
                let _ = getc(timeout)?;
            }
            Some((0x02, n))
        }
        _ => None,
    }
}

/// Issue a command and wait for its Command Complete (0x0E) with a MATCHING opcode.
/// Returns the status byte (0 = success). Non-matching events (incl. LE meta that can
/// arrive while scanning) are skipped, bounded by `max_skip`.
fn hci_cmd(opcode: u16, params: &[u8]) -> Option<u8> {
    if !send_cmd(opcode, params) {
        return None;
    }
    let mut buf = [0u8; 260];
    for _ in 0..24 {
        let (t, n) = read_pkt(&mut buf, 4_000_000)?;
        if t != 0x04 || n < 2 {
            continue;
        }
        let evt = buf[0];
        let plen = buf[1] as usize;
        if evt == 0x0E && plen >= 3 {
            // 04 0E plen | ncmd | op_lo op_hi | status...
            let op = u16::from_le_bytes([buf[3], buf[4]]);
            if op == opcode {
                return Some(if plen >= 4 { buf[5] } else { 0 });
            }
        } else if evt == 0x0F && plen >= 4 {
            // Command Status: status, ncmd, opcode  — surfaces firmware errors.
            let op = u16::from_le_bytes([buf[4], buf[5]]);
            if op == opcode {
                return Some(buf[2]);
            }
        }
    }
    None
}

/// A BLE advertiser seen during the scan.
#[derive(Clone, Copy)]
pub struct BleDev {
    pub addr: [u8; 6], // little-endian on the wire; printed reversed
    pub addr_type: u8,
    pub rssi: i8,
    pub evt_type: u8,
}
impl BleDev {
    pub const fn new() -> Self {
        BleDev { addr: [0; 6], addr_type: 0, rssi: 0, evt_type: 0 }
    }
}

static mut BT_DIAG: [u32; 6] = [0; 6]; // [reset, baud, evtmask, le_evtmask, scanparm, scanen]
/// Per-step HCI status (0 = success, 0xFF = no response) for the bring-up sequence.
pub fn bt_diag() -> [u32; 6] {
    unsafe { BT_DIAG }
}

/// Does uarta decode after the pins are muxed? Scratch register (SCR) is a plain RW
/// register with no side effects — write two patterns, require read-back. MUST be
/// called AFTER pinmux(): on this SoC the UART's functional path is gated by the pin
/// function-select, so a scratch access before muxing aborts (that ordering bug in the
/// first driver is what produced the deferred SError). 0xFE in BT_DIAG[0] = block did
/// not decode even after muxing.
fn uart_present() -> bool {
    const SCR: usize = 7 << 2; // 16550 scratch register, reg-shift 2
    let saved = r32(BT_UART + SCR);
    let mut ok = true;
    for pat in [0xA5u32, 0x5A] {
        w32(BT_UART + SCR, pat);
        unsafe { core::arch::asm!("dsb sy", "isb") };
        if r32(BT_UART + SCR) & 0xFF != pat {
            ok = false;
            break;
        }
    }
    w32(BT_UART + SCR, saved);
    unsafe { core::arch::asm!("dsb sy", "isb") };
    ok
}

/// Mask SError (PSTATE.A) for the BT window. MUST bracket bringup() together with
/// `drain_errors()`: with A masked, a UART external abort stays pending instead of
/// being taken, so `esb` can then consume it into DISR_EL1 rather than escalating to
/// the fatal SError vector. Without this bracket, `esb` on an unmasked abort would
/// simply trigger the "UNEXPECTED KERNEL FAULT" handler early.
pub fn mask_serror() {
    unsafe { core::arch::asm!("msr daifset, #4", "isb", options(nomem, nostack)) };
}

/// Consume any pending external abort into DISR_EL1 (A is masked by mask_serror), read
/// and clear it, then unmask SError. Returns the DISR_EL1 syndrome — nonzero means a
/// BT access aborted and was CONTAINED here, never reaching a later phase. `esb` is
/// FEAT_RAS (present on Cortex-A76/BCM2712).
pub fn drain_errors() -> u64 {
    let disr: u64;
    unsafe {
        // Raw encodings so the assembler needs no `ras` target-feature flag:
        //   esb        = hint #16
        //   DISR_EL1   = S3_0_C12_C1_1
        core::arch::asm!(
            "dsb sy",
            "hint #16",                   // esb: A masked => pending SError -> DISR_EL1
            "mrs {d}, S3_0_c12_c1_1",     // read DISR_EL1
            "msr S3_0_c12_c1_1, xzr",     // clear it
            "msr daifclr, #4",            // safe now: the pending abort was drained
            "isb",
            d = out(reg) disr,
            options(nostack),
        );
    }
    disr
}

/// P10-BT bring-up: mux the UART pins, power the BT core, open the UART at 115200,
/// HCI Reset, switch to 3 Mbaud. Patch-free path (the .hcd is optional). Returns true
/// if the controller answered HCI Reset (i.e. the BT core is alive). Every wait is
/// bounded; a failure returns false and is contained by drain_errors() in the caller.
pub fn bringup() -> bool {
    // 1. Mux gpio24..27 -> uart0 FIRST — this un-gates the UART block on this SoC.
    pinmux();
    delay_us(1_000);
    // 2. Only now is a register access safe. Bail cleanly if it still doesn't decode.
    if !uart_present() {
        unsafe { BT_DIAG[0] = 0xFE }; // block did not decode even after muxing
        return false;
    }
    // Power-cycle the BT core. RTS held low across power-up (bcm43438 quirk).
    bt_power(false);
    delay_us(100_000);
    uart_init(DIV_115200, 0x00); // MCR=0 -> RTS de-asserted
    bt_power(true);
    delay_us(120_000);
    w32(BT_UART + MCR, MCR_DTR | MCR_RTS | MCR_AFE); // 0x23

    // Drain any power-on noise.
    while getc(20_000).is_some() {}

    // HCI Reset (0x0C03).
    let st = hci_cmd(0x0C03, &[]);
    unsafe { BT_DIAG[0] = st.map(|s| s as u32).unwrap_or(0xFF) };
    if st != Some(0) {
        return false;
    }
    delay_us(100_000);

    // Update Baud Rate (0xFC18) -> 3,000,000, THEN switch our own UART.
    let baud = 3_000_000u32.to_le_bytes();
    let p = [0u8, 0u8, baud[0], baud[1], baud[2], baud[3]];
    let st = hci_cmd(0xFC18, &p);
    unsafe { BT_DIAG[1] = st.map(|s| s as u32).unwrap_or(0xFF) };
    if st == Some(0) {
        uart_set_div(DIV_3M);
        delay_us(10_000);
    }
    true
}

/// Enable LE passive scanning and collect advertising reports into `out`.
/// Returns the number of unique devices seen. Bounded in time and iterations.
pub fn ble_scan(out: &mut [BleDev]) -> usize {
    // Set Event Mask (0x0C01) — all events.
    let st = hci_cmd(0x0C01, &[0xff; 8]);
    unsafe { BT_DIAG[2] = st.map(|s| s as u32).unwrap_or(0xFF) };
    // LE Set Event Mask (0x2001).
    let st = hci_cmd(0x2001, &[0xff; 8]);
    unsafe { BT_DIAG[3] = st.map(|s| s as u32).unwrap_or(0xFF) };
    // LE Set Scan Parameters (0x200B): passive, interval 0x0010, window 0x0010,
    // own addr public, accept all.
    let st = hci_cmd(0x200B, &[0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00]);
    unsafe { BT_DIAG[4] = st.map(|s| s as u32).unwrap_or(0xFF) };
    if st != Some(0) {
        return 0;
    }
    // LE Set Scan Enable (0x200C): enable, duplicates NOT filtered.
    let st = hci_cmd(0x200C, &[0x01, 0x00]);
    unsafe { BT_DIAG[5] = st.map(|s| s as u32).unwrap_or(0xFF) };
    if st != Some(0) {
        return 0;
    }

    // Collect LE Advertising Reports (04 3E plen 02 num { .. }) for a bounded window.
    let mut n = 0usize;
    let mut buf = [0u8; 260];
    let mut quiet = 0u32;
    for _ in 0..4000 {
        match read_pkt(&mut buf, 200_000) {
            None => {
                quiet += 1;
                if quiet > 60 {
                    break; // sustained silence — nothing more advertising
                }
                continue;
            }
            Some((t, len)) => {
                quiet = 0;
                if t != 0x04 || len < 2 || buf[0] != 0x3E {
                    continue; // not an LE meta event
                }
                let plen = buf[1] as usize;
                if plen < 2 || buf[2] != 0x02 {
                    continue; // not an Advertising Report
                }
                let nrep = buf[3] as usize;
                // reports are variable-length and concatenated; walk with each len
                let mut off = 4usize;
                for _ in 0..nrep {
                    if off + 9 > len {
                        break;
                    }
                    let evt_type = buf[off];
                    let addr_type = buf[off + 1];
                    let mut addr = [0u8; 6];
                    addr.copy_from_slice(&buf[off + 2..off + 8]);
                    let dlen = buf[off + 8] as usize;
                    // rssi sits immediately AFTER the AD data (not in the struct)
                    if off + 9 + dlen >= len {
                        break;
                    }
                    let rssi = buf[off + 9 + dlen] as i8;
                    // de-dup by address
                    if !out[..n].iter().any(|d| d.addr == addr) && n < out.len() {
                        out[n] = BleDev { addr, addr_type, rssi, evt_type };
                        n += 1;
                    }
                    off += 10 + dlen;
                }
                if n >= out.len() {
                    break;
                }
            }
        }
    }
    // Disable scanning so the radio isn't left running.
    let _ = hci_cmd(0x200C, &[0x00, 0x00]);
    n
}
