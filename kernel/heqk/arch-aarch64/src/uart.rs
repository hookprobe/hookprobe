use core::fmt;

/// PL011 UART console.
///
/// QEMU `virt`: one PL011 at 0x0900_0000, pre-initialized — just write DR.
///
/// CM5 (BCM2712): TWO PL011s matter, and the choice is wiring, not preference:
///  - **RP1 UART0 @ 0x1C_0003_0000** — the 40-pin-header UART (GPIO14/15),
///    where the bench FTDI actually sits (it's Linux's ttyAMA0 console on this
///    exact board). It lives behind the RP1 southbridge: reachable bare-metal
///    only with `pciex4_reset=0` in config.txt (otherwise the firmware resets
///    the PCIe RC before kernel entry), and it needs RP1 pinmux (FUNCSEL=4 on
///    GPIO14/15) + pad setup + explicit PL011 init (clk_uart = 50 MHz).
///  - **uart10 @ 0x10_7D00_1000** — the on-SoC debug UART. Always enabled and
///    pre-programmed (115200) by the firmware, but physically reachable only
///    on the CM5 module itself (JST-SH pads / testpoints TP35/36) — no carrier
///    board routes it. Kept as a firmware-guaranteed fallback.
/// The CM5 build prints every byte to BOTH.
pub struct Pl011;

#[cfg(not(feature = "cm5"))]
const UART0_BASE: usize = 0x0900_0000;
#[cfg(feature = "cm5")]
const UART0_BASE: usize = 0x1C_0003_0000; // RP1 UART0 — GPIO14/15 header (the FTDI)
#[cfg(feature = "cm5")]
const UART10_BASE: usize = 0x10_7D00_1000; // BCM2712 debug UART (module pads only)

// RP1 GPIO blocks (CPU view through the firmware-configured PCIe window).
#[cfg(feature = "cm5")]
const RP1_IO_BANK0: usize = 0x1C_000D_0000; // GPIOn CTRL at 8*n + 4
#[cfg(feature = "cm5")]
const RP1_PADS_BANK0: usize = 0x1C_000F_0000; // GPIOn pad at 4 + 4*n

// PL011 register offsets.
const R_DR: usize = 0x00;
const R_FR: usize = 0x18;
const R_IBRD: usize = 0x24;
const R_FBRD: usize = 0x28;
const R_LCR_H: usize = 0x2c;
const R_CR: usize = 0x30;
const R_ICR: usize = 0x44;

const FR_TXFF: u32 = 1 << 5; // transmit FIFO full
#[cfg(feature = "cm5")]
const FR_BUSY: u32 = 1 << 3; // UART busy transmitting

#[inline]
fn reg(base: usize, off: usize) -> *mut u32 {
    (base + off) as *mut u32
}

#[inline]
fn put_base(base: usize, byte: u8) {
    unsafe {
        // Bounded spin: a dead UART reads FR as 0xFFFFFFFF forever — drop the
        // byte rather than hang the kernel.
        let mut spins = 0u32;
        while core::ptr::read_volatile(reg(base, R_FR)) & FR_TXFF != 0 {
            spins += 1;
            if spins > 100_000 {
                return;
            }
        }
        core::ptr::write_volatile((base + R_DR) as *mut u8, byte);
    }
}

impl Pl011 {
    #[inline]
    fn put(&self, byte: u8) {
        // Single console owner: the RP1 header UART only. (The uart10 mirror
        // was removed — SoC-side accesses outside the boot path are exactly
        // the kind of surprise the bring-up saga taught us to avoid.)
        put_base(UART0_BASE, byte);
    }

    /// CM5: NO-OP by design. The boot stub (boot_cm5.s) is the single owner
    /// of console bring-up — clk_uart from xosc, pinmux, PL011 115200 — with
    /// the barrier/read-back discipline the bring-up proved necessary
    /// (posted-PCIe-write races killed the console when programmed twice).
    /// Rust must never reprogram a working console.
    #[cfg(feature = "cm5")]
    pub fn init(&self) {}

    #[cfg(not(feature = "cm5"))]
    #[inline]
    pub fn init(&self) {}
}

impl hal::Console for Pl011 {
    fn putc(&self, byte: u8) {
        self.put(byte);
    }
}

// `core::fmt::Write` gives us `write!`/`writeln!` for formatted diagnostics.
impl fmt::Write for Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.put(b'\r');
            }
            self.put(b);
        }
        Ok(())
    }
}
