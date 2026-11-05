#![no_std]
//! aarch64 implementation of the HookProbe HAL, plus the low-level boot stub
//! and exception/IRQ vector table. This is the ONE crate allowed to know the
//! architecture; `kernel` talks to it only through `hal` traits (plus the boot
//! seam: our `_start` calls `kmain`, and `irq_entry` calls `handle_irq`).

use core::arch::global_asm;
use core::fmt::{self, Write};

mod uart;
mod exception;
pub mod bpf_jit;
#[cfg(feature = "cm5")]
pub mod gem;
pub mod gic;
#[cfg(feature = "cm5")]
pub mod iommu;
pub mod mmu;
#[cfg(feature = "cm5")]
pub mod mmu_cm5;
// P13 — RP1 peripheral buses (GPIO/pinmux, I2C, SPI, UART). CM5-only, additive.
#[cfg(feature = "cm5")]
pub mod rp1;
#[cfg(feature = "cm5")]
pub mod rp1_gpio;
#[cfg(feature = "cm5")]
pub mod rp1_i2c;
#[cfg(feature = "cm5")]
pub mod rp1_spi;
#[cfg(feature = "cm5")]
pub mod rp1_uartp;
#[cfg(feature = "cm5")]
pub mod rtl8111;
#[cfg(feature = "cm5")]
pub mod uplink;
// NAT engine: pure frame translation (no MMIO) — built on every target so QEMU tests it.
pub mod nat;
// PPPoE client engine (pure frame state machine) — built on every target so QEMU tests it.
pub mod pppoe;
// IPv6 WAN builders/parsers (RS/RA, DHCPv6 IA_PD) — pure, built on every target so QEMU tests it.
pub mod ip6;
// IPv6 LAN router + stateful firewall for the AP (RA/ND, no-NAT forwarding) — pure, QEMU-tested.
pub mod ip6lan;
// WPA2 PMK KDF (PBKDF2-HMAC-SHA1) for P10-E STA association. CM5-only.
#[cfg(feature = "cm5")]
pub mod wpa;
// AES-128 + RFC-3394 key-unwrap — WPA2 GTK unwrap only (CCMP is in the CYW43455 fw). CM5-only.
#[cfg(feature = "cm5")]
pub mod aes;
// The STRICT (fail-closed, never counter-seeded) rng200 leaf behind the kernel's
// production entropy source. Distinct policy from hboot::rng — see rng200.rs.
#[cfg(feature = "cm5")]
pub mod rng200;
#[cfg(feature = "cm5")]
pub mod cyw43;
// P15 — eMMC block storage: base-parameterized SDHCI + read-only eMMC driver.
#[cfg(feature = "cm5")]
pub mod sdhci;
#[cfg(feature = "cm5")]
pub mod emmc;
#[cfg(feature = "cm5")]
pub mod bt;
#[cfg(feature = "cm5")]
pub mod mailbox;
pub mod semihosting;
pub mod syscall;
pub mod thread;
pub mod timer;
pub mod virtio;
pub mod virtio_blk;
pub mod virtio_net;

pub use gic::Gic;
pub use mmu::Mmu;
pub use timer::GenericTimer;
pub use uart::Pl011;

// _start (boot stub), __vectors / irq_entry / lower_sync_entry, and the EL0
// entry/resume glue.
#[cfg(not(feature = "cm5"))]
global_asm!(include_str!("boot.s"));
#[cfg(all(feature = "cm5", not(feature = "hboot")))]
global_asm!(include_str!("boot_cm5.s")); // firmware-direct: own console bring-up
#[cfg(feature = "hboot")]
global_asm!(include_str!("boot_hboot.s")); // launched by HBoot: minimal EL1 entry
global_asm!(include_str!("vectors.s"));
global_asm!(include_str!("syscall.s"));

/// Current Exception Level (1, 2, or 3) from `CurrentEL`.
#[inline]
pub fn current_el() -> u64 {
    let el: u64;
    unsafe { core::arch::asm!("mrs {}, CurrentEL", out(reg) el) };
    (el >> 2) & 0b11
}

/// Obtain the early debug console.
pub fn console() -> Pl011 {
    Pl011
}

/// Unmask IRQs at the CPU (PSTATE.I = 0).
#[inline]
pub fn enable_irqs() {
    unsafe { core::arch::asm!("msr daifclr, #2") };
}

/// Mask IRQs at the CPU (PSTATE.I = 1) — short critical sections (e.g. IPC).
#[inline]
pub fn disable_irqs() {
    unsafe { core::arch::asm!("msr daifset, #2") };
}

/// Formatted output to the early console (backs the kernel's `kprint!`).
pub fn _print(args: fmt::Arguments) {
    let mut u = Pl011;
    let _ = u.write_fmt(args);
}

// ===========================================================================
// CORE-1 — backend-neutral EL0 frame-mapping surface used by the capability
// system (`caps::map_frame_cap` / `caps::revoke`). Both backends map into the
// address space `page_desc`/`user_page_desc` reads back, so the map -> read ->
// revoke -> read proof is self-consistent per backend. QEMU maps into the
// GLOBAL kernel root (the p3-style demo path); CM5 into its single-AS GB5 user
// window. Migrating the live per-ASID driver grants onto this path is CORE-1's
// follow-up (they stay on the metal-proven `map_user_*_in` calls for now).
// ===========================================================================

/// Map a Frame cap's physical `pa` at EL0 `va`. `writable` => EL0 RW, else EL0
/// read-only (the rights-derived attribute a cap lacking the `W` right forces).
/// Always non-executable at EL0/EL1. Returns true on success.
pub fn map_user_frame(va: usize, pa: usize, writable: bool) -> bool {
    #[cfg(not(feature = "cm5"))]
    {
        let m = mmu::Mmu;
        if writable {
            m.map_user_data_page(va, pa)
        } else {
            m.map_user_data_ro_page(va, pa)
        }
    }
    #[cfg(feature = "cm5")]
    {
        if writable {
            mmu_cm5::map_user_data(va, pa)
        } else {
            mmu_cm5::map_user_data_ro(va, pa)
        }
    }
}

/// M5.1 (QEMU beachhead) — the CORE-1 enforced-cap mapping into a SPECIFIC per-TCB
/// address space `l1_root`, with a W^X-checked `executable` bit for the ELF loader.
/// Rights → attributes, W^X by construction:
///   * `executable`            => AP RO + EL0-executable (RO+X code)   [caller must !writable]
///   * `writable && !exec`     => AP RW + non-exec       (RW+NX data)
///   * `!writable && !exec`    => AP RO + non-exec       (RO+NX rodata)
/// The three cases are mutually exclusive; a W+X request is rejected by the caller
/// (`caps::map_frame_cap_in`) before reaching here, so no page is ever both W and X.
#[cfg(not(feature = "cm5"))]
pub fn map_user_frame_in(l1_root: usize, va: usize, pa: usize, writable: bool, executable: bool) -> bool {
    let m = mmu::Mmu;
    if executable {
        m.map_user_code_in(l1_root, va, pa) // RO + X
    } else if writable {
        m.map_user_data_in(l1_root, va, pa) // RW + NX
    } else {
        m.map_user_data_ro_in(l1_root, va, pa) // RO + NX
    }
}

/// Invalidate (unmap) the EL0 mapping at `va` + tlbi — the primitive `revoke`
/// uses to sever a Frame cap's authority. Returns true if an entry was cleared.
pub fn unmap_user_frame(va: usize) -> bool {
    #[cfg(not(feature = "cm5"))]
    {
        mmu::Mmu.unmap_user_page(va)
    }
    #[cfg(feature = "cm5")]
    {
        mmu_cm5::unmap_user(va)
    }
}

/// Read back the effective descriptor at EL0 `va` (0 = not mapped). The proof
/// helper: shows a mapping present with its AP bits, then invalid after revoke.
pub fn user_frame_desc(va: usize) -> u64 {
    #[cfg(not(feature = "cm5"))]
    {
        mmu::Mmu.page_desc(va)
    }
    #[cfg(feature = "cm5")]
    {
        mmu_cm5::page_desc(va)
    }
}

/// Entry point for the kernel's `#[panic_handler]`.
pub fn on_panic(info: &core::panic::PanicInfo) -> ! {
    let mut u = Pl011;
    let _ = writeln!(u, "\n[PANIC] {}", info);
    semihosting::exit(1)
}
