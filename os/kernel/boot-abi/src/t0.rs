//! ADR 0062 T0 inventory: pure decoding of the CPU identification registers and the rule for when an SMCCC
//! probe is safe to issue. Everything here is DETECTED state. Under ADR 0062 V0 nothing decoded here is ever
//! a PASS by itself: a mitigation becomes PASS only with a configured-state self-test AND a metal verification
//! record for the platform tuple. This module only reports what the hardware and firmware say.

use crate::fdt::{Conduit, Psci};

/// The raw registers T0 reads (EL2 or EL1 can read all of them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IdRegs {
    pub midr: u64,
    pub revidr: u64,
    pub mpidr: u64,
    pub pfr0: u64,
    pub pfr1: u64,
    pub isar0: u64,
    pub isar1: u64,
    pub isar2: u64,
    pub mmfr0: u64,
    pub mmfr1: u64,
    pub mmfr2: u64,
    pub dfr0: u64,
    pub ctr: u64,
    pub clidr: u64,
    pub cntfrq: u64,
}

fn f(v: u64, lo: u32) -> u8 {
    ((v >> lo) & 0xf) as u8
}

/// Decoded fields relevant to ADR 0060/0061/0062 (Arm ARM field positions).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Decoded {
    pub implementer: u8,
    pub variant: u8,
    pub part: u16,
    pub revision: u8,
    /// ID_AA64PFR0_EL1.EL3 != 0: EL3 is implemented in hardware (firmware presence is a separate fact).
    pub el3: bool,
    /// ID_AA64PFR0_EL1.EL2.
    pub el2: bool,
    /// CSV2 (branch-target speculation restricted across contexts), 0 = not claimed.
    pub csv2: u8,
    /// CSV3 (no speculative data from faulting loads), 0 = not claimed.
    pub csv3: u8,
    /// ID_AA64PFR1_EL1.SSBS (PSTATE.SSBS available), 0 = absent.
    pub ssbs: u8,
    /// ID_AA64PFR1_EL1.BT (BTI), 0 = absent.
    pub bti: u8,
    /// ID_AA64ISAR0_EL1.AES: 1 = AES instructions, 2 = + PMULL.
    pub aes: u8,
    pub sha2: u8,
    /// ID_AA64ISAR1_EL1.SB (speculation barrier instruction).
    pub sb: u8,
    /// Pointer authentication present (APA/API/GPA/GPI any non-zero).
    pub pauth: bool,
    /// ID_AA64ISAR2_EL1.CLRBHB.
    pub clrbhb: u8,
    /// Aff0..Aff3 of MPIDR.
    pub aff: [u8; 4],
}

pub fn decode(r: &IdRegs) -> Decoded {
    Decoded {
        implementer: (r.midr >> 24) as u8,
        variant: f(r.midr, 20),
        part: ((r.midr >> 4) & 0xfff) as u16,
        revision: f(r.midr, 0),
        el3: f(r.pfr0, 12) != 0,
        el2: f(r.pfr0, 8) != 0,
        csv2: f(r.pfr0, 56),
        csv3: f(r.pfr0, 60),
        ssbs: f(r.pfr1, 4),
        bti: f(r.pfr1, 0),
        aes: f(r.isar0, 4),
        sha2: f(r.isar0, 12),
        sb: f(r.isar1, 36),
        pauth: f(r.isar1, 4) != 0 || f(r.isar1, 8) != 0 || f(r.isar1, 24) != 0 || f(r.isar1, 28) != 0,
        clrbhb: f(r.isar2, 28),
        aff: [r.mpidr as u8, (r.mpidr >> 8) as u8, (r.mpidr >> 16) as u8, (r.mpidr >> 32) as u8],
    }
}

/// The 4-level affinity of an MPIDR as one comparable value (Aff3:Aff2:Aff1:Aff0). Use this, never
/// `mpidr & 0xff`: on BCM2712 the cores differ in Aff1 (0x000, 0x100, 0x200, 0x300) and Aff0 is 0 on all.
pub fn affinity(mpidr: u64) -> u64 {
    (mpidr & 0x00ff_ffff) | ((mpidr >> 8) & 0xff00_0000)
}

/// Why an SMCCC probe is or is not issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// DTB `/psci` says `method = "smc"` AND EL3 is implemented: SMC is issued.
    Smc,
    /// DTB says HVC: only meaningful when running below a hypervisor (cloud). HBoot at EL2 does not probe it.
    HvcNotFromEl2,
    /// No `/psci` node or no method: an SMC could be UNDEFINED. Not issued.
    NoPsciNode,
    /// The DTB claims SMC but EL3 is not implemented: refuse (the DTB is wrong or hostile).
    SmcWithoutEl3,
    /// Unknown method string.
    UnknownMethod,
}

/// The ONLY gate for issuing an SMC from HBoot: the firmware DTB declares PSCI over SMC and the CPU
/// implements EL3. Anything else is reported, never probed (an SMC with no EL3 handler is UNDEFINED and would
/// land in HBoot's '!' park).
pub fn probe_decision(psci: &Psci, d: &Decoded) -> Probe {
    if !psci.present {
        return Probe::NoPsciNode;
    }
    match psci.method {
        Conduit::Smc if d.el3 => Probe::Smc,
        Conduit::Smc => Probe::SmcWithoutEl3,
        Conduit::Hvc => Probe::HvcNotFromEl2,
        Conduit::None => Probe::NoPsciNode,
        Conduit::Other => Probe::UnknownMethod,
    }
}

// SMCCC / PSCI function ids (SMC32 calling convention).
pub const PSCI_VERSION: u32 = 0x8400_0000;
pub const PSCI_CPU_ON64: u32 = 0xC400_0003;
pub const PSCI_FEATURES: u32 = 0x8400_000A;
pub const SMCCC_VERSION: u32 = 0x8000_0000;
pub const SMCCC_ARCH_FEATURES: u32 = 0x8000_0001;
pub const SMCCC_ARCH_SOC_ID: u32 = 0x8000_0002;
pub const SMCCC_ARCH_WORKAROUND_1: u32 = 0x8000_8000;
pub const SMCCC_ARCH_WORKAROUND_2: u32 = 0x8000_7FFF;
pub const SMCCC_ARCH_WORKAROUND_3: u32 = 0x8000_3FFF;
/// SMCCC NOT_SUPPORTED.
pub const NOT_SUPPORTED: i64 = -1;

/// The probe results, raw. Interpretation (e.g. "WORKAROUND_1 = 0 means the firmware call exists and is
/// required on this PE") belongs to the verification step, not to T0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmcccResults {
    pub psci_version: i64,
    pub cpu_on: i64,
    /// PSCI_FEATURES(SMCCC_VERSION): 0 = SMCCC_VERSION may be called (non-PSCI ids are then safe).
    pub smccc_version_feature: i64,
    pub smccc_version: i64,
    pub wa1: i64,
    pub wa2: i64,
    pub wa3: i64,
    pub soc_id_version: i64,
    pub soc_id_revision: i64,
    /// Non-PSCI ids were issued (only after SMCCC >= 1.1 was established).
    pub arch_probed: bool,
}

/// Run the documented probe order through `call(fid, arg) -> x0` (Linux `psci_init_smccc` procedure):
/// PSCI ids first; non-PSCI ids only once PSCI_FEATURES(SMCCC_VERSION) == 0 and SMCCC >= 1.1.
pub fn probe(call: &mut dyn FnMut(u32, u64) -> i64) -> SmcccResults {
    let mut r = SmcccResults {
        psci_version: call(PSCI_VERSION, 0),
        cpu_on: call(PSCI_FEATURES, PSCI_CPU_ON64 as u64),
        smccc_version_feature: call(PSCI_FEATURES, SMCCC_VERSION as u64),
        smccc_version: NOT_SUPPORTED,
        wa1: NOT_SUPPORTED,
        wa2: NOT_SUPPORTED,
        wa3: NOT_SUPPORTED,
        soc_id_version: NOT_SUPPORTED,
        soc_id_revision: NOT_SUPPORTED,
        arch_probed: false,
    };
    if r.smccc_version_feature != 0 {
        return r;
    }
    r.smccc_version = call(SMCCC_VERSION, 0);
    // SMCCC version is (major << 16) | minor; ARCH_FEATURES exists from 1.1.
    if r.smccc_version < 0x1_0001 {
        return r;
    }
    r.arch_probed = true;
    r.wa1 = call(SMCCC_ARCH_FEATURES, SMCCC_ARCH_WORKAROUND_1 as u64);
    r.wa2 = call(SMCCC_ARCH_FEATURES, SMCCC_ARCH_WORKAROUND_2 as u64);
    r.wa3 = call(SMCCC_ARCH_FEATURES, SMCCC_ARCH_WORKAROUND_3 as u64);
    if call(SMCCC_ARCH_FEATURES, SMCCC_ARCH_SOC_ID as u64) == 0 {
        r.soc_id_version = call(SMCCC_ARCH_SOC_ID, 0);
        r.soc_id_revision = call(SMCCC_ARCH_SOC_ID, 1);
    }
    r
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// Cortex-A76 r4p1-shaped MIDR (implementer 0x41 Arm, part 0xD0B).
    const A76: u64 = 0x414f_d0b1;

    #[test]
    fn decodes_a76_identity() {
        let d = decode(&IdRegs { midr: A76, pfr0: 0x1100_0000_1000_1111 | (1 << 56), mpidr: 0x8100_0300, ..IdRegs::default() });
        assert_eq!((d.implementer, d.part, d.variant, d.revision), (0x41, 0xd0b, 4, 1));
        assert!(d.el3 && d.el2);
        assert_eq!((d.csv2, d.csv3), (1, 1));
        assert_eq!(d.aff, [0x00, 0x03, 0x00, 0x00]);
    }

    #[test]
    fn affinity_distinguishes_bcm2712_cores() {
        let cores = [0x8000_0000u64, 0x8000_0100, 0x8000_0200, 0x8000_0300];
        assert!(cores.iter().all(|&m| m & 0xff == 0), "Aff0 is 0 on every BCM2712 core");
        let a: std::vec::Vec<u64> = cores.iter().map(|&m| affinity(m)).collect();
        assert_eq!(a, [0, 0x100, 0x200, 0x300]);
        // Aff3 (bits 39:32) lands in bits 31:24; the MT/U bits (24, 30, 31) are excluded.
        assert_eq!(affinity(0x0000_0012_c100_0000), 0x1200_0000);
    }

    #[test]
    fn smc_only_with_psci_smc_and_el3() {
        let el3 = Decoded { el3: true, ..Decoded::default() };
        let no3 = Decoded::default();
        let smc = Psci { present: true, method: Conduit::Smc, v02_plus: true };
        assert_eq!(probe_decision(&smc, &el3), Probe::Smc);
        assert_eq!(probe_decision(&smc, &no3), Probe::SmcWithoutEl3);
        assert_eq!(probe_decision(&Psci { method: Conduit::Hvc, ..smc }, &el3), Probe::HvcNotFromEl2);
        assert_eq!(probe_decision(&Psci::default(), &el3), Probe::NoPsciNode);
        assert_eq!(probe_decision(&Psci { method: Conduit::Other, ..smc }, &el3), Probe::UnknownMethod);
    }

    #[test]
    fn probe_order_never_issues_arch_ids_without_smccc_1_1() {
        // PSCI_FEATURES(SMCCC_VERSION) unsupported -> only the three PSCI ids are issued.
        let mut seen = std::vec::Vec::new();
        let r = probe(&mut |fid, _| {
            seen.push(fid);
            if fid == PSCI_VERSION { 0x1_0001 } else { NOT_SUPPORTED }
        });
        assert_eq!(seen, [PSCI_VERSION, PSCI_FEATURES, PSCI_FEATURES]);
        assert!(!r.arch_probed);
        // SMCCC 1.0 -> SMCCC_VERSION read, no ARCH_FEATURES.
        let mut seen = std::vec::Vec::new();
        let r = probe(&mut |fid, _| {
            seen.push(fid);
            match fid {
                PSCI_FEATURES => 0,
                SMCCC_VERSION => 0x1_0000,
                _ => 0x1_0001,
            }
        });
        assert_eq!(seen.last(), Some(&SMCCC_VERSION));
        assert!(!r.arch_probed);
        // SMCCC 1.2 -> workarounds + SOC_ID queried.
        let r = probe(&mut |fid, a| match (fid, a as u32) {
            (SMCCC_VERSION, _) => 0x1_0002,
            (SMCCC_ARCH_FEATURES, SMCCC_ARCH_WORKAROUND_1) => 0,
            (SMCCC_ARCH_FEATURES, SMCCC_ARCH_WORKAROUND_3) => NOT_SUPPORTED,
            (SMCCC_ARCH_FEATURES, _) => 0,
            (SMCCC_ARCH_SOC_ID, 0) => 0x5f0_0712,
            (SMCCC_ARCH_SOC_ID, _) => 0xc1,
            _ => 0,
        });
        assert!(r.arch_probed);
        assert_eq!((r.wa1, r.wa3, r.soc_id_version), (0, NOT_SUPPORTED, 0x5f0_0712));
    }
}
