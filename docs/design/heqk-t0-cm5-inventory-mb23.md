# ADR 0062 T0 inventory — CM5 metal results (batch MB23, 2026-11-13)

**What:** the read-only T0 inventory (HBoot feature `t0inv`, commit `0af7b544`, PR #1125), run on the bench CM5
by the heqk session in metal batch MB23. There were two boots:
- **t0-dtb:** firmware DTB loaded; disk sha256 `989501c5…`.
- **t0-nolinux:** the zero-Linux `config-nolinux.txt`, no DTB.

Kernel: the shipping AP features plus `wpa3`. Raw logs on the bench host: `t0-dtb.log` (84 lines) and
`t0-nolinux.log` (40 lines) under the heqk session's `mb23-1422/` directory.

**Status:** everything below is **detected** state (ADR 0062 V0). None of it is a mitigation PASS. Neither boot
trapped, parked or hit a watchdog reset. The DTB boot then passed secure boot and booted normally.

## Platform tuple (as measured)

| Item | Value | Decoded |
|---|---|---|
| MIDR_EL1 | `0x414fd0b1` | Arm Cortex-A76 **r4p1** |
| REVIDR_EL1 | `0x0` | — |
| MPIDR_EL1 (boot core) | `0x81000000` | **MT = 1**: cores are numbered in **Aff1**, Aff0 = 0 on every core |
| VC firmware revision | `0x6a15b5c5` | build time 2026-05-26 15:01:25 UTC |
| Board revision | `0xc04180` | new-style code: type 0x18 = CM5, processor BCM2712, manufacturer 0, memory code 4 = **4 GB** |
| CNTFRQ_EL0 | `0x0337f980` | **54 MHz**, 18.5 ns resolution (meets ADR 0060 D10's ≤ 1 µs) |
| CTR_EL0 / CLIDR_EL1 | `0x9444c004` / `0xc3000123` | split L1, unified L2 and L3 |
| ID_AA64MMFR0 | `0x101122` | PARange 40-bit, 16-bit ASIDs |

## Speculation-relevant features (detected)

| Feature | Register evidence | Detected value | ADR 0062 consequence |
|---|---|---|---|
| CSV2 | ID_AA64PFR0[59:56] | **1** | Hardware claims restricted branch-target speculation across contexts |
| CSV3 | ID_AA64PFR0[63:60] | **1** | Hardware claims no speculative data from faulting loads (the X9 mapping audit is still required) |
| SSBS | ID_AA64PFR1[7:4] | **1** (PSTATE.SSBS) | SSB control is available to the OS |
| BTI | ID_AA64PFR1[3:0] | 0 | Absent, as expected for v8.2 |
| PAuth | ID_AA64ISAR1 APA/API/GPA/GPI | 0 | Absent, as expected |
| SB | ID_AA64ISAR1[39:36] | 0 | Absent: use DSB + ISB |
| CLRBHB | ID_AA64ISAR2[31:28] | 0 (ISAR2 = 0) | **No CLRBHB instruction** |
| AES / PMULL | ID_AA64ISAR0[7:4] | **2** | Hardware AES with PMULL; constant-time AES-GCM is possible (ADR 0062 D3) |
| SHA2 | ID_AA64ISAR0[15:12] | 1 | SHA-256 instructions present |
| EL2 / EL3 | ID_AA64PFR0[11:8] / [15:12] | 1 / 1 | — |

## Firmware (EL3) answers, DTB boot

| Call | Result | Reading (per SMCCC / Linux conventions) |
|---|---|---|
| PSCI_VERSION | `0x10001` | **PSCI 1.1** |
| PSCI_FEATURES(CPU_ON64) | `0` | **CPU_ON supported**: the ADR 0060 D2 bring-up route is PSCI CPU_ON over SMC from HBoot at EL2 |
| PSCI_FEATURES(SMCCC_VERSION) | `0` | Non-PSCI ids are safe |
| SMCCC_VERSION | `0x10002` | **SMCCC 1.2** |
| ARCH_FEATURES(WORKAROUND_1) | `1` | "Not affected on this PE": the firmware agrees with CSV2 = 1 |
| ARCH_FEATURES(WORKAROUND_2) | `-2` (NOT_REQUIRED) | No firmware call is needed for SSB; the OS controls it through PSTATE.SSBS |
| ARCH_FEATURES(WORKAROUND_3) | `-1` (NOT_SUPPORTED) | **No firmware Spectre-BHB call** |
| ARCH_SOC_ID | `-1` | Not supported |

These workaround results cover **the boot core only**. Per-core values need SMP (ADR 0060).

## Memory and cores (DTB boot)

- **/memory:** `0x0–0x3fc00000` and `0x40000000–0x100000000`, total **0xffc00000** (4092 MiB). There is a 4 MiB
  hole at `0x3fc00000` (VideoCore).
  - The VC mailbox `GET_ARM_MEMORY` reports only `0x0 + 0x3fc00000` (1020 MiB, the legacy below-1 GiB split). **The
    mailbox cannot be the RAM source** for ADR 0061 D1.
- **/reserved-memory** (both `no-map`):
  - `0x0 + 0x80000`: TF-A (bl31);
  - `0x3fd23900 + 0x18a`: 394 bytes, added by the firmware at runtime (it is not in the static DTB).
  - Neither overlaps the kernel at `0x1000000` or the CM5 frame pool at `0x30000000–0x38000000`.
- **/cpus:** 4 cores at MPIDR `0x000 / 0x100 / 0x200 / 0x300`, `enable-method = "psci"`, all `okay`.
- **/psci:** `method = "smc"`, compatible PSCI 0.2+.
- **This bench unit is 4 GB.** The current 4 GiB boot map (`mmu_cm5.rs:33`) happens to cover all of its RAM. An 8 or
  16 GB module would not be covered (ADR 0061 M1).

## Zero-Linux boot (the shipping configuration)

- `dtb = absent-or-unmapped`, `smccc.probe = skipped:no-psci-node`. The registers, firmware revision, board revision
  and mailbox values are identical to the DTB boot.
- **Consequence:** the shipping image has **no DTB**, so today it has no source for:
  - the memory map (ADR 0061 D1);
  - the start method for secondary cores (ADR 0060 D2);
  - the PSCI conduit (ADR 0062 T0).

  This needs a decision (below).

## What this changes in ADR 0060 / 0061 / 0062

| Item | Before | After MB23 |
|---|---|---|
| ADR 0060 S3 (secondary-core start on CM5) | UNKNOWN | **PSCI 1.1 CPU_ON over SMC to TF-A**, detected (DTB boot) |
| ADR 0060 D2 (stage-2 on every core) | Design | Route confirmed: HBoot at EL2 issues CPU_ON; each core enters HBoot's EL2 path first |
| HBoot secondary park (`boot.s:29-30`) | Suspected | **Confirmed** by MPIDR MT = 1 / Aff1 numbering. Owned by the heqk session (PCR0/seal impact under review) |
| ADR 0061 M10 (RAM) | UNKNOWN | 4 GB on this unit (board code and DTB). The mailbox is not a valid RAM source |
| ADR 0062 Spectre-v2 | UNKNOWN | Still **UNKNOWN**. Detected: CSV2 = 1, firmware WA1 = "not affected". The route to PASS is *architectural immunity confirmed by metal record* (T3b with a positive control) |
| ADR 0062 BHB | UNKNOWN | Still **UNKNOWN**. Detected: **no CLRBHB and no firmware WA3**. The only route is the **in-kernel branch-history clearing loop** on EL0→EL1 entry (the Arm-recommended iteration count for the A76 must be confirmed from Arm's advisory), then T3c. Until then Decision 3 applies: **CM5 stays ineligible for multi-tenant** |
| ADR 0062 SSB | UNKNOWN | Still **UNKNOWN**. Detected: SSBS = 1, firmware WA2 = not required. Route: kernel PSTATE.SSBS control in tenant-parser contexts, then T3d |
| ADR 0062 Meltdown-class | UNKNOWN | Still **UNKNOWN**. Detected: CSV3 = 1. Needs the X9 audit (no kernel mapping reachable from EL0) and T3e |
| ADR 0062 constant-time crypto | UNKNOWN | Still UNKNOWN. **Hardware AES with PMULL detected**, so AES-GCM through instructions is a valid option. The timing test (T3h) is pending |
| ADR 0062 firmware floor | NI | Tuple identity now known: MIDR `0x414fd0b1`, VC firmware `0x6a15b5c5`. The TF-A build identity is still unknown (SOC_ID is not supported); the bl31 region must be measured to pin it |

## Decisions this raises (operator)

1. **Platform discovery on the shipping image.** Options:
   - **(a)** Load the firmware DTB in the zero-Linux config as well, with HBoot measuring it into a PCR before
     parsing it. It is firmware data, not Linux; `device_tree=` was dropped together with Linux.
   - **(b)** Derive the memory size from the board-revision code and keep a per-SoC table of the memory map and
     the PSCI conduit, compiled into HBoot.

   Recommendation: **(a)**. It is the only source of the real reserved regions, such as the runtime 394-byte block.
   Option (b) would bake in assumptions that one firmware update could invalidate.
2. **TF-A identity for the firmware floor (ADR 0062 D1).** SOC_ID is unsupported, so HBoot should measure the bl31
   region (`0x0–0x80000`, `no-map`) into the boot record, if EL2 can read it. That needs to be checked: the region may
   be protected by TF-A.
