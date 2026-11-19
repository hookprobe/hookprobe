// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0065 S0 — every resident EL0 server in its OWN address space.
//!
//! Finding (2026-11-15): the resident servers (el0-wifi, el0-hsh, el0-lansvc, el0-tlshost) were all mapped into the
//! ONE global EL0 page table, so each could read the others' pages — e.g. el0-lansvc (which parses hostile station
//! frames) could read el0-wifi's WPA keys or el0-tlshost's TLS session keys. Each server now gets a private
//! address space: its own L1 root (the kernel's mappings copied, global) with private user tables, tagged with its
//! own ASID; TTBR0 is switched to it for the length of each excursion and back to the kernel's after. The kernel
//! keeps reaching a server's memory through the physical frames (identity map), never through its EL0 VAs.
//!
//! `[P-el0-as]` checks the result with the MMU itself (`AT S1E0R`): every server's probe VA translates in its own
//! address space only — not in the kernel's, not in any other server's.

// The isolation check and the device grant are used by the Mission Control builds (mctls: el0-wifi, el0-tlshost,
// el0-hsh); the netsvc-only build has just el0-lansvc.
#![cfg_attr(not(feature = "mctls"), allow(dead_code))]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Map {
    /// EL0 read-only + executable (W^X), never EL1-executable.
    Code,
    /// EL0 read-write, non-executable.
    Data,
    /// EL0 read-only, non-executable.
    DataRo,
    /// A device-MMIO grant: Device-nGnRE, EL0 read-write, non-executable.
    Dev,
}

/// One server's private address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct El0As {
    pub root: usize,
    pub asid: u16,
}

impl El0As {
    /// A fresh address space (None when the frame pool is exhausted).
    pub fn new() -> Option<Self> {
        #[cfg(feature = "cm5")]
        let (root, asid) = arch_aarch64::mmu_cm5::new_addr_space();
        #[cfg(not(feature = "cm5"))]
        let (root, asid) = arch_aarch64::Mmu.new_addr_space();
        (root != 0).then_some(El0As { root, asid })
    }

    /// Map one page into THIS address space only (fail-closed: false when refused).
    pub fn map(&self, va: usize, pa: usize, k: Map) -> bool {
        #[cfg(feature = "cm5")]
        {
            use arch_aarch64::mmu_cm5 as m;
            match k {
                Map::Code => m::map_user_code_in(self.root, va, pa),
                Map::Data => m::map_user_data_in(self.root, va, pa),
                Map::DataRo => m::map_user_data_ro_in(self.root, va, pa),
                Map::Dev => m::map_user_device_in(self.root, va, pa),
            }
        }
        #[cfg(not(feature = "cm5"))]
        {
            let m = arch_aarch64::Mmu;
            match k {
                Map::Code => m.map_user_code_in(self.root, va, pa),
                Map::Data => m.map_user_data_in(self.root, va, pa),
                Map::DataRo => m.map_user_data_ro_in(self.root, va, pa),
                Map::Dev => m.map_user_device_in(self.root, va, pa),
            }
        }
    }

    pub fn ttbr0(&self) -> u64 {
        self.root as u64 | (self.asid as u64) << 48
    }
}

fn kernel_ttbr0() -> u64 {
    #[cfg(feature = "cm5")]
    {
        arch_aarch64::mmu_cm5::kernel_ttbr0()
    }
    #[cfg(not(feature = "cm5"))]
    {
        arch_aarch64::Mmu.kernel_ttbr0()
    }
}

fn set_ttbr0(v: u64) {
    #[cfg(feature = "cm5")]
    arch_aarch64::mmu_cm5::set_ttbr0_raw(v);
    #[cfg(not(feature = "cm5"))]
    arch_aarch64::Mmu.set_ttbr0_raw(v);
}

/// One bounded excursion into a server, run in that server's address space; the kernel's is restored after
/// (whatever the outcome: exit, fault or timeout all return here).
pub fn excursion(a: &El0As, entry: usize, sp: usize, budget_us: u64) -> crate::Excursion {
    set_ttbr0(a.ttbr0());
    let r = crate::excursion_bounded(entry, sp, budget_us);
    set_ttbr0(kernel_ttbr0());
    r
}

// ---- [P-el0-as]: the isolation, checked with the MMU ----
const REG_MAX: usize = 12;
static mut REG: [Option<(&'static str, usize, El0As)>; REG_MAX] = [None; REG_MAX];

/// Record a loaded server (its name, a VA it has mapped, its address space) for the isolation check.
pub fn register(name: &'static str, probe_va: usize, a: El0As) {
    let reg = unsafe { &mut *core::ptr::addr_of_mut!(REG) };
    if let Some(slot) = reg.iter_mut().find(|s| s.is_none()) {
        *slot = Some((name, probe_va, a));
    }
}

/// The physical page `va` translates to for an EL0 read under `ttbr0` (`AT S1E0R` → PAR_EL1), None when it does
/// not translate. The caller's TTBR0 is restored.
fn el0_pa(ttbr0: u64, va: usize) -> Option<u64> {
    let par: u64;
    unsafe {
        let old: u64;
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) old, options(nomem, nostack));
        core::arch::asm!("msr ttbr0_el1, {}", "isb", in(reg) ttbr0, options(nostack));
        core::arch::asm!("at s1e0r, {}", "isb", "mrs {}, par_el1", in(reg) va, out(reg) par, options(nostack));
        core::arch::asm!("msr ttbr0_el1, {}", "isb", in(reg) old, options(nostack));
    }
    (par & 1 == 0).then_some(par & 0x0000_FFFF_FFFF_F000)
}

/// `[P-el0-as]`: each registered server's probe VA is readable in its own address space, and in no other (not
/// the kernel's, not another server's). Prints the result; returns pass.
pub fn report() -> bool {
    let reg = unsafe { &*core::ptr::addr_of!(REG) };
    let k = kernel_ttbr0();
    let mut n = 0;
    let mut own = true;
    let mut kernel_sees = 0;
    let mut cross = 0;
    // A leak = another address space reaching the SAME physical page. Several el0-wifi incarnations (the QEMU
    // selftests) share a VA window, each over its own frames: the same VA in another space is not a leak.
    for (name, va, a) in reg.iter().flatten() {
        n += 1;
        let Some(pa) = el0_pa(a.ttbr0(), *va) else {
            own = false;
            arch_aarch64::_print(format_args!("   [P-el0-as] {} is not mapped in its own address space\n", name));
            continue;
        };
        if el0_pa(k, *va).is_some() {
            kernel_sees += 1;
            arch_aarch64::_print(format_args!("   [P-el0-as] {} is mapped in the kernel's (global) EL0 table\n", name));
        }
        for (other, _, b) in reg.iter().flatten() {
            if b != a && el0_pa(b.ttbr0(), *va) == Some(pa) {
                cross += 1;
                arch_aarch64::_print(format_args!("   [P-el0-as] {} can read {}'s page {:#x}\n", other, name, pa));
            }
        }
    }
    let pass = n >= 2 && own && kernel_sees == 0 && cross == 0;
    arch_aarch64::_print(format_args!(
        " [P-el0-as] {} — ADR 0065 S0: {} resident EL0 servers each in their own address space (ASID): own page mapped={} in the kernel's EL0 table={} another server reaching the same page={}\n",
        if pass { "PASS" } else { "FAIL" }, n, own, kernel_sees, cross
    ));
    pass
}
