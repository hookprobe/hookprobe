//! ADR 0062 T0 inventory (feature `t0inv`; never in a production image). READ-ONLY platform discovery at EL2:
//! the CPU identification registers, the firmware DTB (bounded `boot_abi::fdt` reader), three VC-mailbox GET
//! tags, and — only when the DTB declares PSCI over SMC AND EL3 is implemented — the SMCCC/PSCI feature probe.
//! Nothing is written anywhere; every line is printed as `[T0-inv]` for the metal log.
//!
//! Runs AFTER the A/B safety watchdog is armed (main.rs), so even a fault here resets to the known-good slot.
//! Everything printed is DETECTED state. ADR 0062 V0: none of it is a mitigation PASS.

use crate::{puthex, puts};
use boot_abi::fdt;
use boot_abi::t0::{self, IdRegs, Probe};

/// EL2 maps GB0..3 as Normal memory (mmu.rs NORMAL_GBS); a DTB outside that is not read.
const MAPPED_END: u64 = 4 << 30;

macro_rules! sysreg {
    ($name:literal) => {{
        let v: u64;
        unsafe { core::arch::asm!(concat!("mrs {}, ", $name), out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }};
}

fn read_regs() -> IdRegs {
    IdRegs {
        midr: sysreg!("midr_el1"),
        revidr: sysreg!("revidr_el1"),
        mpidr: sysreg!("mpidr_el1"),
        pfr0: sysreg!("id_aa64pfr0_el1"),
        pfr1: sysreg!("id_aa64pfr1_el1"),
        isar0: sysreg!("id_aa64isar0_el1"),
        isar1: sysreg!("id_aa64isar1_el1"),
        isar2: sysreg!("s3_0_c0_c6_2"), // ID_AA64ISAR2_EL1 (RAZ where not implemented)
        mmfr0: sysreg!("id_aa64mmfr0_el1"),
        mmfr1: sysreg!("id_aa64mmfr1_el1"),
        mmfr2: sysreg!("s3_0_c0_c7_2"), // ID_AA64MMFR2_EL1
        dfr0: sysreg!("id_aa64dfr0_el1"),
        ctr: sysreg!("ctr_el0"),
        clidr: sysreg!("clidr_el1"),
        cntfrq: sysreg!("cntfrq_el0"),
    }
}

/// SMCCC call over SMC from EL2. SMCCC lets the callee corrupt x0-x17; all are declared clobbered.
fn smc(fid: u32, arg: u64) -> i64 {
    let r: u64;
    unsafe {
        core::arch::asm!(
            "smc #0",
            inlateout("x0") fid as u64 => r,
            inlateout("x1") arg => _,
            lateout("x2") _, lateout("x3") _, lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _,
            lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _, lateout("x12") _, lateout("x13") _,
            lateout("x14") _, lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack)
        );
    }
    r as i64
}

fn kv(k: &str, v: u64) {
    puts("[T0-inv] ");
    puts(k);
    puts("=");
    puthex(v);
    puts("\n");
}

fn kvs(k: &str, v: &str) {
    puts("[T0-inv] ");
    puts(k);
    puts("=");
    puts(v);
    puts("\n");
}

pub fn run(dtb_pa: u64) {
    puts("[T0-inv] BEGIN ADR-0062-T0 v1 (read-only; detected state only — never a PASS, ADR 0062 V0)\n");

    // 1. Identification registers (the platform-tuple CPU part).
    let r = read_regs();
    for (k, v) in [
        ("midr", r.midr), ("revidr", r.revidr), ("mpidr", r.mpidr), ("id_aa64pfr0", r.pfr0), ("id_aa64pfr1", r.pfr1),
        ("id_aa64isar0", r.isar0), ("id_aa64isar1", r.isar1), ("id_aa64isar2", r.isar2), ("id_aa64mmfr0", r.mmfr0),
        ("id_aa64mmfr1", r.mmfr1), ("id_aa64mmfr2", r.mmfr2), ("id_aa64dfr0", r.dfr0), ("ctr_el0", r.ctr),
        ("clidr_el1", r.clidr), ("cntfrq_el0", r.cntfrq),
    ] {
        kv(k, v);
    }
    let d = t0::decode(&r);
    kv("cpu.implementer", d.implementer as u64);
    kv("cpu.part", d.part as u64);
    kv("cpu.variant", d.variant as u64);
    kv("cpu.revision", d.revision as u64);
    kv("cpu.affinity", t0::affinity(r.mpidr));
    kv("feat.el3", d.el3 as u64);
    kv("feat.el2", d.el2 as u64);
    kv("feat.csv2", d.csv2 as u64);
    kv("feat.csv3", d.csv3 as u64);
    kv("feat.ssbs", d.ssbs as u64);
    kv("feat.bti", d.bti as u64);
    kv("feat.pauth", d.pauth as u64);
    kv("feat.sb", d.sb as u64);
    kv("feat.clrbhb", d.clrbhb as u64);
    kv("feat.aes", d.aes as u64);
    kv("feat.sha2", d.sha2 as u64);

    // 2. Firmware identity + RAM as the firmware reports it (VC mailbox, GET tags only).
    use crate::mailbox::get_u32x2;
    match get_u32x2(0x0000_0001) {
        Some((rev, _)) => kv("fw.revision", rev as u64),
        None => kvs("fw.revision", "unreadable"),
    }
    match get_u32x2(0x0001_0002) {
        Some((rev, _)) => kv("board.revision", rev as u64),
        None => kvs("board.revision", "unreadable"),
    }
    match get_u32x2(0x0001_0005) {
        Some((base, size)) => {
            kv("mbox.arm_mem.base", base as u64);
            kv("mbox.arm_mem.size", size as u64);
        }
        None => kvs("mbox.arm_mem", "unreadable"),
    }

    // 3. The firmware DTB (bounded read; the header's totalsize is clamped to MAX_BLOB and the EL2 map).
    let mut psci = fdt::Psci::default();
    if dtb_pa == 0 || !dtb_pa.is_multiple_of(8) || dtb_pa.saturating_add(40) > MAPPED_END {
        kvs("dtb", "absent-or-unmapped");
    } else {
        let hdr = unsafe { core::slice::from_raw_parts(dtb_pa as *const u8, 40) };
        let total = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as u64;
        let len = total.min(fdt::MAX_BLOB as u64).min(MAPPED_END - dtb_pa) as usize;
        let blob = unsafe { core::slice::from_raw_parts(dtb_pa as *const u8, len.max(40)) };
        match fdt::parse(blob) {
            Err(e) => {
                kvs("dtb", "PARSE-ERROR");
                kv("dtb.err", e as u64);
            }
            Ok(inv) => {
                kv("dtb.totalsize", total);
                kv("dtb.boot_cpuid_phys", inv.boot_cpuid_phys as u64);
                kv("dtb.truncated", inv.truncated as u64);
                kv("mem.ranges", inv.nmem as u64);
                for m in &inv.mem[..inv.nmem] {
                    kv("mem.base", m.base);
                    kv("mem.size", m.size);
                }
                kv("mem.total", inv.mem_total());
                kv("resv.ranges", inv.nresv as u64);
                kv("resv.nomap", inv.resv_nomap as u64);
                for m in &inv.resv[..inv.nresv] {
                    kv("resv.base", m.base);
                    kv("resv.size", m.size);
                }
                kv("cpus", inv.ncpus as u64);
                for c in &inv.cpus[..inv.ncpus] {
                    kv("cpu.mpidr", c.mpidr);
                    kvs("cpu.enable_method", match c.method {
                        fdt::EnableMethod::Psci => "psci",
                        fdt::EnableMethod::SpinTable => "spin-table",
                        fdt::EnableMethod::Other => "other",
                        fdt::EnableMethod::None => "none",
                    });
                    kv("cpu.release_addr", c.release_addr);
                    kv("cpu.enabled", c.enabled as u64);
                }
                psci = inv.psci;
                kv("psci.present", psci.present as u64);
                kvs("psci.method", match psci.method {
                    fdt::Conduit::Smc => "smc",
                    fdt::Conduit::Hvc => "hvc",
                    fdt::Conduit::Other => "other",
                    fdt::Conduit::None => "none",
                });
                kv("psci.v02_plus", psci.v02_plus as u64);
            }
        }
    }

    // 4. SMCCC/PSCI probe — only behind the gate (DTB PSCI over SMC AND EL3 implemented).
    match t0::probe_decision(&psci, &d) {
        Probe::Smc => {
            kvs("smccc.probe", "smc");
            let s = t0::probe(&mut |fid, arg| smc(fid, arg));
            kv("psci.version", s.psci_version as u64);
            kv("psci.features.cpu_on", s.cpu_on as u64);
            kv("psci.features.smccc_version", s.smccc_version_feature as u64);
            kv("smccc.version", s.smccc_version as u64);
            kv("smccc.arch_probed", s.arch_probed as u64);
            kv("smccc.workaround_1", s.wa1 as u64);
            kv("smccc.workaround_2", s.wa2 as u64);
            kv("smccc.workaround_3", s.wa3 as u64);
            kv("smccc.soc_id.version", s.soc_id_version as u64);
            kv("smccc.soc_id.revision", s.soc_id_revision as u64);
        }
        Probe::HvcNotFromEl2 => kvs("smccc.probe", "skipped:dtb-says-hvc"),
        Probe::NoPsciNode => kvs("smccc.probe", "skipped:no-psci-node"),
        Probe::SmcWithoutEl3 => kvs("smccc.probe", "skipped:dtb-smc-but-no-el3"),
        Probe::UnknownMethod => kvs("smccc.probe", "skipped:unknown-method"),
    }
    puts("[T0-inv] NOTE workaround results are for the BOOT core only; per-core values need SMP (ADR 0060)\n");
    puts("[T0-inv] END\n");
}
