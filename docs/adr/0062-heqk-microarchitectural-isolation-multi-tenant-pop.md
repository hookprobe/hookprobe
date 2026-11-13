# ADR 0062: Microarchitectural isolation and security eligibility for multi-tenant SASE PoPs

**Status:** 🟡 Proposed (2026-11-11). Operator decisions recorded 2026-11-11; the text needs operator
review.

**Scope:** hboot, os/kernel (vectors, context switch, parsers, crypto, capabilities, cfgd admission),
os/build (qualification pipeline, lint), lab (metal verification).

**Amends:**
- `os/kernel/HEQK_REMEDIATION_PLAN.md:162` ("scope the product to single-tenant edge"): the scope
  becomes multi-tenant PoP, under this ADR.
- `os/kernel/SECURITY.md:516-525`: the EL0 `CNTPCT` grant is re-scoped by D5.
- ADR 0050: adds tenant assurance-class service instances.

**Related:** ADR 0060 (core roles), ADR 0061 (budgets), ADR 0059 D1 (signed-bytes rule), ADR 0046
(key custody).

## Context: evidence (`origin/main` @ `fd6fb038`)

| # | Finding | Status | Evidence |
|---|---|---|---|
| X1 | `csdb` after bounds checks, in the device-class queue only | PARTIAL | `kernel/src/devq.rs:22, 193-198, 268` |
| X2 | No `csdb` or masking after BPF bounds checks; the remediation item is open | NOT IMPLEMENTED | `kernel/src/bpf.rs`, `arch-aarch64/src/bpf_jit.rs`; `HEQK_REMEDIATION_PLAN.md:162, 192`; `GAP_REGISTER.md:93` |
| X3 | Retpoline/BTI for indirect branches (JIT) | DESIGN ONLY | `BPF_THREAT_PLANE.md:67, 95` |
| X4 | No v2/BHB/SSB mitigations, no `SMCCC_ARCH_WORKAROUND_*`, no ID-register discovery | NOT IMPLEMENTED | No match in `os/kernel` |
| X5 | Product scoped as "single-tenant edge" | DESIGN (constraint) | `HEQK_REMEDIATION_PLAN.md:162` |
| X6 | EL0 can read `CNTPCT_EL0`; accepted because there is no second tenant | IMPLEMENTED (accepted risk) | `SECURITY.md:516-525`; `kernel/src/main.rs:1349-1357` |
| X7 | Table-based software AES (not constant-time); used only for the WPA2 GTK unwrap | IMPLEMENTED (narrow use) | `arch-aarch64/src/aes.rs:1-5` |
| X8 | G19 and TLS use ChaCha20-Poly1305; audited crates for X25519, Ed25519 and ML-KEM | IMPLEMENTED | `kernel/src/securechannel.rs:15, 35` |
| X9 | Whether EL0 page tables reach kernel mappings | UNKNOWN | Audit `mmu_cm5.rs`, `mmu.rs` |
| X10 | Tenant parsing in separate address spaces | NOT IMPLEMENTED | `el0-lansvc/src/main.rs:1-9` |
| X11 | Mitigation status reported to the operator or to admission | NOT IMPLEMENTED | `kernel/src/capabilities.rs` |

**Threat model.** Tenants run no code. They control packet bytes, tenant-facing protocols (CE-side
BGP, IKEv2, G19 handshakes) and traffic timing. Channels, in priority order:
- **T1:** non-constant-time crypto;
- **T2:** gadgets or bugs in tenant-facing parsers that share an address space with another
  tenant's state;
- **T3:** Spectre-v1 on tenant- or packet-indexed tables in EL1 (SPI/sid, FIB, NAT);
- **T4:** v2/BHB/SSB from a compromised EL0 service;
- **T5:** cache contention across tenants' flows.

Neither CM5 nor N100 has SMT (verify per SKU).

## Decision

**V0. Security eligibility is verified, never configured.**
- No configuration input, signature, session, CLI command or AI proposal can set a mitigation
  state or assurance class to PASS.
- HQCFG has no key for it; cfgd refuses one under the closed-key rule. The implemented schema 1.0
  accepts only the wan, wifi and policy sections and refuses any unknown kind or flag
  (`os/kernel/kernel/src/cfgbundle.rs:17, 30-32, 167-171`). A mitigation section would need a schema
  major bump, which the verifier refuses by default. V0 forbids defining one.
- **Mitigation state is computed each boot** by the boot-signed kernel from:
  1. detection (ID registers / CPUID, `IA32_ARCH_CAPABILITIES`, `SMCCC_ARCH_FEATURES`);
  2. configured-state self-tests;
  3. a **verification record**.
- **Verification record:**
  - Signed by a **qualification key**, separate from the owner key and the boot key. Its public
    half is compiled into the boot-signed image.
  - Bound to the platform tuple: `MIDR_EL1` part/revision or CPUID family/model/stepping; the
    measured firmware/EL3/microcode identity; the covered image-hash range.
  - Any tuple mismatch means UNKNOWN.
- **The owner key cannot sign verification records** (separated signature domains).
- Principle: performance is measured, capacity is admitted, security eligibility is verified.

**D1. Discovery** (detect once; written into the Platform Manifest `mitigations` section):
- Arm: `ID_AA64PFR0/1`, `ID_AA64ISAR0/1/2`, `MIDR_EL1`, `SMCCC_VERSION`,
  `SMCCC_ARCH_FEATURES(WORKAROUND_1/2/3)`, `SMCCC_ARCH_SOC_ID`.
- x86: CPUID, `IA32_ARCH_CAPABILITIES`, the microcode revision.

**D2. Controls at each boundary:**
- **EL0→EL1:** BHB clearing (CLRBHB, the Arm-recommended loop for the core, or WORKAROUND_3), plus
  a v2 workaround if CSV2 is absent.
- **Switches between trust classes:** branch-predictor invalidation (WORKAROUND_1 / IBPB).
- **SSB:** SSBS cleared (or WORKAROUND_2) in tenant-facing parser contexts.
- **Barriers:** index masking plus `csdb` (Arm) or LFENCE/masking (x86) after every bounds check on
  a tenant- or packet-derived index: BPF (X2), SA/session lookup, FIB/NHG, NAT/conntrack,
  devq/netq.
- **CI lints** check that these are present.

**D3. Constant-time cryptography for tenant traffic:**
- AES-GCM only through crypto-extension instructions that discovery confirms; otherwise
  ChaCha20-Poly1305.
- **Never table-based AES:** `aes.rs` stays limited to the WPA2 GTK unwrap.
- Constant-time secret comparisons; dudect-style CI timing tests.

**D4. Tenant-facing parsing:**
- Tenant-facing endpoints (CE-side bgpd, ikev2d, post-authentication G19 session state) run in
  **separate EL0 instances per assurance class**, each with its own address space, budget and keys.
- Pre-authentication listeners are shared, minimal and stateless, behind cookie/DoS guards.
- The underlay bgpd is separate from every tenant instance.

**D5. Timer exposure:** EL0 `CNTPCT` access stays for first-party, non-tenant services only.
Tenant-class instances get the kernel-published coarse time word, and their reads trap.

**D6. Assurance classes.**
- **Standard is the default** on a shared PoP. It is admitted only when every applicable item is
  PASS:
  - v1 barriers and masking on the listed paths;
  - v2 and BHB;
  - SSB;
  - Meltdown-class: CSV3 or equivalent **and** no kernel mapping reachable from EL0 (X9);
  - x86 data sampling, where flagged;
  - constant-time tenant crypto;
  - tenant parser isolation (D4);
  - timer coarsening (D5);
  - firmware/microcode at or above the floor.
- **Elevated** adds dedicated DP cores (no L1/L2 sharing), dedicated EL0 instances and key pages,
  the cross-core cache-channel test (T3f) and the assurance soak (T5). It also needs **explicit
  owner authorization plus a verification record whose scope includes Elevated**. The
  authorization can request Elevated; under V0 it cannot grant it.
- **Dedicated hardware** applies only when Elevated cannot be met, or a contract requires it. It is
  never the default.

**D7. Admission states** (all derived, never configured):

| State | Condition |
|---|---|
| **PASS** | Vulnerable or not proven immune **and** implemented in this image **and** configured (this boot's self-test) **and** verified (a valid metal record for the exact tuple). Or: architectural immunity reported by registers **and** confirmed by the metal record. |
| **FAIL** | Vulnerable with no mitigation available; or this boot's self-test fails; or the metal PoC leaked |
| **UNKNOWN** | Any missing input: no record, tuple changed, firmware not queryable, or evidence that would need inference (QEMU, CPU-family tables, firmware version, config flags) |
| **N/A** | The issue's architecture doesn't apply, stated per tuple |

- The three evidence levels (implemented, configured, verified) are each recorded separately.
- **Spectre-v2 or BHB UNKNOWN or FAIL: every multi-tenant class is refused** (Standard and
  Elevated alike).
- **Runtime loss of eligibility** (failed self-test, firmware change): that class's tenant
  attachments don't start (fail closed for tenants, alarmed). The operator's management plane and
  any single-tenant traffic under a valid exception continue.
- **Exposed through:** `/api/capabilities`, mgmtabi `GET_ASSURANCE`, the Mission Control
  Administration view (UNKNOWN shown distinctly from PASS) and the evidence graph.

**D8. Single-tenant exception (`HQRISK1`).**
- **Scope:** exactly one tenant id across all tenant VRFs. While it is active, cfgd refuses any
  second tenant id or second tenant key.
- **Artifact:** owner-signed, in its own signature domain. Contains: device id; the assessed
  tuple; the accepted UNKNOWN/FAIL mitigations with compensating controls; the accepting role; the
  hash of the written assessment; an expiry (**proposed maximum 90 days**); a review date.
- **Procedure:**
  1. Write the assessment from the device's `GET_ASSURANCE` output.
  2. Sign and stage; cfgd checks the tuple, the expiry and the scope.
  3. Every event is recorded in the HMAC-chained journal.
  4. Mission Control shows a persistent banner.
- **On expiry:** existing traffic continues; new tenant-scope changes are refused; the alarm
  escalates.
- **A tuple change invalidates the exception.**
- **Under V0 it never shows as PASS** and never contributes to multi-tenant eligibility.

**D9. Fail-safe:** a platform that cannot meet a class's requirements is refused for that class,
with a stated reason. Single-trust-domain operation remains available.

## Verification matrix (2026-11-11)

Levels: implemented / configured / verified. NI = not implemented; DO = design only.

| Mitigation | CM5 today | N100 today |
|---|---|---|
| Spectre-v1 barriers / masking | PARTIAL (`devq.rs`) / – / none → **UNKNOWN** | DO → **UNKNOWN** |
| Spectre-v2 | NI / NI / none → **UNKNOWN** (MB23 detected: CSV2=1, firmware WA1 = not affected) | DO → **UNKNOWN** |
| BHB | NI / NI / none → **UNKNOWN** (MB23 detected: no CLRBHB, firmware WA3 NOT_SUPPORTED → the in-kernel loop is the only route) | DO → **UNKNOWN** |
| SSB | NI / NI / none → **UNKNOWN** (MB23 detected: SSBS=1, firmware WA2 not required) | DO → **UNKNOWN** |
| Meltdown-class | not audited (X9) → **UNKNOWN** (MB23 detected: CSV3=1) | DO → **UNKNOWN** |
| x86 data sampling | N/A | DO → **UNKNOWN** |
| Constant-time tenant crypto | ChaCha20-Poly1305 implemented; timing test NI → **UNKNOWN** (MB23 detected: AES+PMULL and SHA2 instructions) | DO → **UNKNOWN** |
| Tenant parser isolation | NI → **UNKNOWN** | DO |
| Tenant timer coarsening | NI (EL0 `CNTPCT` granted) → **UNKNOWN** | DO |
| Firmware / microcode floor | NI (not measured) → **UNKNOWN** (MB23: MIDR 0x414fd0b1, VC fw 0x6a15b5c5; TF-A identity unknown, SOC_ID unsupported) | DO |

**Expected hardware facts (from vendor advisories; to be confirmed by discovery and verification,
never assumed):**
- **CM5 (Cortex-A76, v8.2):**
  - no PAuth and no BTI;
  - no SB instruction (use DSB + ISB);
  - listed as affected by Spectre-BHB in Arm's advisory;
  - SSBS is expected;
  - CSV3 is expected;
  - no MPAM, so isolation comes from core partitioning (private L1/L2, shared L3);
  - EL3 firmware (TF-A) answered on MB23: PSCI 1.1, SMCCC 1.2, WORKAROUND_1 = 1 (not affected),
    WORKAROUND_2 = -2 (not required), WORKAROUND_3 = -1 (not supported). Evidence:
    `docs/design/heqk-t0-cm5-inventory-mb23.md`. All of this is detected state, not verified.
- **N100 (Gracemont):** eIBRS/IBPB, BHI controls, SSBD, RDCL_NO and data-sampling flags (e.g.
  RFDS) all to be confirmed through `IA32_ARCH_CAPABILITIES` and microcode; CET expected.

**Result: CM5 and N100 are ineligible for multi-tenant admission until verified.**

## Tests to move CM5 from UNKNOWN to VERIFIED

**Preconditions:**
- a bench slot from the heqk session (the REL-05 soak was deferred by the operator on 2026-11-12);
- a dev-key-signed `spec-test` image that is **never shipped** and is refused by production trust
  roots. It contains the EL0 attack images and a switch to disable each mitigation for positive
  controls;
- **T3f needs SMP** (ADR 0060).

**T0 — inventory, per tuple** (implemented in PR #1125, HBoot feature `t0inv`; first run on CM5 in MB23, see
`docs/design/heqk-t0-cm5-inventory-mb23.md`):
- Dump the DTB `/cpus` `enable-method` and the `/psci` node with its method.
- Read `MIDR_EL1` (expect part 0xD0B; record rXpY) and `ID_AA64PFR0/1`, `ISAR0/1/2`, `MMFR*`.
- From hboot at EL2, call `SMCCC_VERSION`, `SMCCC_ARCH_FEATURES(WORKAROUND_1/2/3)` and `SOC_ID`.
  This establishes whether any EL3 firmware exists.
- If there is no EL3 workaround **and** no architecturally sound in-kernel route, v2/BHB is
  **FAIL**, not UNKNOWN.
- Measure the bootloader/EEPROM and firmware identity into the boot record.

**T1 — configured-state self-tests, every boot:**
- register read-back;
- a vector-table digest that includes the BHB sequence;
- workaround calls succeed;
- SSBS state on entry to tenant classes;
- the tenant-class timer trap.

**T2 — CI static checks, every image:** `csdb`/masking lint on the listed paths; the vector-entry
sequence is present; no table-based AES reachable from tenant paths.

**T3 — metal effectiveness.** Every test runs a **positive control** (mitigation disabled; the
attack must succeed above a stated accuracy) and a **mitigated run** (leak rate indistinguishable
from chance over N trials, at a stated confidence):
- **T3a, v1:** BPF map access, SA/session lookup and FIB index trained from EL0; flush+reload or
  prime+probe recovery of a planted kernel secret.
- **T3b, v2:** branch-target injection EL0→EL1, and EL0 ASID A → B across a trust-class switch.
- **T3c, BHB:** branch-history steering of an EL1 indirect branch.
- **T3d, SSB:** a store-bypass leak in a tenant-parser context.
- **T3e, Meltdown-class:** a speculative EL0 load of a kernel address, plus a page-table walk
  showing no kernel mapping is reachable from EL0.
- **T3f, Elevated:** the cross-core L3 channel between tenants on separate DP cores.
- **T3h:** dudect-style timing of the tenant AEAD and key exchange.

**T4 — functional isolation:** a compromised tenant-class instance (harness) cannot read another
class's memory or keys; timer reads trap; forged instance badges are refused.

**T5 — assurance soak:** at least 72 hours of the PoP mix with T1 repeated and periodic T3a–T3d.

**Output:**
- A qualification-key-signed verification record for the tuple and its image range.
- A change to vectors, scheduler, crypto or parser code outside the range re-runs T2/T3 before
  release.
- A firmware change resets the tuple to UNKNOWN.
- CM5 becomes Standard-eligible only after T0–T5 pass; Elevated also needs T3f.

## Consequences

- The BPF `csdb` item (X2) becomes a release blocker for the PoP profile.
- New key custody: the qualification key (ADR 0046 amendment).
- New artifact types: verification record and `HQRISK1`.
- Open for the operator: the `HQRISK1` expiry ceiling, custody of the qualification key, and
  confirmation of the `spec-test` image class.
