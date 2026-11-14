# ADR 0064 — Open hardware: from CM5 to a HookProbe board (RK3588), after CM5 is validated

**Status:** 🟡 **Proposed (2026-11-14)**. Operator review. Records the direction the operator set on 2026-11-14:
once HookProbe OS is validated on CM5, the open-source community expands into dedicated hardware, starting from
the HookProbe SBC research design that this change imports into `hardware/hookprobe-sbc/`. Clauses are tagged
**[realized]**, **[partial]** or **[vision]** (the ADR 0043/0044/0047 discipline).
**Deciders:** operator (ratification, the hardware licence D6, every Red step: fabrication, purchase, flashing);
os-architect (port design, D4/D5); security-auditor (boot chain and TPM, D5); verification-engineer (gates H0–H5);
release-engineer (board images and signing); market-intelligence (the D7 honesty floor on hardware claims).
**Relates to:** ADR 0003 (Platform Manifest: capabilities, crypto posture), ADR 0043/0044 (heqk; CM5 is the first
metal), **ADR 0047** (heqk everywhere: RK3588 is in its D1 platform list, and its D4 honesty floor), ADR 0060
(SMP core roles: the RK3588 is 4×A76 + 4×A55), ADR 0061 (memory budgets), ADR 0062 (multi-tenant PoP
eligibility), ADR 0063 (gate spine: the new hardware gate plugs into it).

## Context

- **CM5 is the only metal-proven heqk platform** [realized]. The zero-Linux factory image passed full acceptance on
  CM5 (2026-11-04). What is still open before CM5 can be called *validated* is release work: the REL-05 soak, the
  REL-06..08 thermal/scale/Wi-Fi-TX items, the G46 security sign-off (SEC-05), and a green g6 metal gate on the
  self-hosted bench (`docs/compliance/cra-matrix.md`, `docs/design/heqk-parity-gaps.md`, `tools/ci/gates.sh`).
- **CM5 limits the product.** BCM2712 has no TPM (device identity is HKDF over the OTP SRK), one GEM NIC plus a
  carrier NIC, no NVMe on most carriers, and no on-chip NPU. A security appliance needs at least two fast ports, a
  hardware root of key storage, and room for local retention and inference.
- **ADR 0047 D1 already names RK3588 as a heqk platform**, and `docs/design/heqk-everywhere-report-2026-10-09.md`
  §4 item 9 sizes the port at "weeks to months" (GICv3, stmmac GMAC, eMMC, a U-Boot/TF-A handoff).
- **Research design exists.** `hardware/hookprobe-sbc/` (imported by this change) is a chip-down RK3588 board, rev A:
  schematic and placement complete, **90/90 automated checks pass** (netlist, ERC, schematic↔board parity,
  JLCPCB DRC limits, power tree within every datasheet limit, interface allocation), **not routed, never built**.
  It follows the Radxa ROCK 5B v1.45 reference for SoC, memory and power.

| Board function | rev A implementation | CM5 today |
|---|---|---|
| SoC | RK3588: 4×Cortex-A76 + 4×Cortex-A55, 6 TOPS NPU | BCM2712: 4×Cortex-A76 |
| Memory / storage | 2× LPDDR4X (64-bit); eMMC; M.2 M-key NVMe 2280 | LPDDR4X; eMMC |
| Network | 2× 2.5 GbE, RTL8125BG, each on its own PCIe lane | GEM 1 GbE (+ carrier NIC) |
| Radios | M.2 E-key Wi-Fi (PCIe); M.2 B-key 5G (USB 3) + nano-SIM; ESP32-H2 Thread/Matter (UART) | CYW43455 (SDIO) |
| Accelerator | M.2 M-key slot for an NPU or FPGA card | — |
| Root of trust | **TPM 2.0 (Infineon SLB9670, SPI1)** + RK3588 OTP | OTP only |
| Power | 12–20 V DC jack, or USB-C PD (FUSB302) 5 V → 20 V | 5 V |
| Form | 140 × 128 mm, 8 layers, all ports on one edge, M.2 cards on the underside against the case | module + carrier |

## Decision

### D1 · CM5 stays the only product target until it is validated **[realized: this clause]**
No hardware engineering spend (routing contract, fabrication, components) and no RK3588 driver work in `os/kernel`
starts until gate **H0** below is green. Design research and documentation may continue. Hardware is a second
product line built on a validated OS, not a way to escape CM5's open items.

### D2 · The research design lives in the repo as open hardware **[realized: this change]**
`hardware/` is a new top-level directory for HookProbe-designed boards. `hardware/hookprobe-sbc/` holds the
generator scripts (the source of truth; the `.kicad_sch` / `.kicad_pcb` files are their output), the validation
script, the published renders/PDFs/BOM, and the project symbol libraries. Third-party datasheets and the Radxa
reference schematic are **not** redistributed (the design's own `.gitignore`). `appliance/hookprobe-sbc/` is the
board's hardware *profile* (how HookProbe OS sees it), keeping the CLAUDE.md design test: **adding hardware = one
profile in `appliance/`, no UI, installer or API change.**

### D3 · Port heqk to a commercial RK3588 board first, then to ours **[vision]**
Our board copies the ROCK 5B's SoC, memory and power circuits, so heqk is ported to a **ROCK 5B** first. That
separates "heqk on RK3588 works" from "our board works": a fault on our prototype is then a board fault, not a
port fault. The sequence, each step a gate:

| Gate | Exit criterion | Owner |
|---|---|---|
| **H0 · CM5 validated** | REL-05 soak passed; REL-06..08 closed or carried as named, operator-accepted residuals; SEC-05 (G46 review) signed off; `gates.sh g6` green on the bench; an operator-signed release built by `os/build/` | verification-engineer, operator |
| **H1 · HAL decoupling** | The kernel crate stops calling `arch_aarch64::` directly (report §4 item 8); CM5 and QEMU stay green through it | os-architect, code-developer |
| **H2 · heqk on ROCK 5B** | Signed heqk boots on ROCK 5B metal: GICv3, UART, eMMC, one Ethernet, `mc-e2e` assertions over the wire, separation-matrix rows that do not depend on Wi-Fi | verification-engineer |
| **H3 · rev A routed + reviewed** | Routed board passes `validate.py` plus signal- and power-integrity review by a design house or Rockchip FAE; the open items in `hardware/hookprobe-sbc/README.md` closed | hardware lead (to be named), operator |
| **H4 · Prototype bring-up** | A small prototype run boots the H2 image unchanged except for the board profile; both 2.5 GbE ports, NVMe, TPM and thermal proven under the same g6-style metal gate | verification-engineer |
| **H5 · Community release** | Manufacturing files, assembly docs, a reproducible board image, and the D7 claims checked | release-engineer, market-intelligence |

### D4 · Driver delta, stated honestly **[vision]**
The board needs more than the report's §4 item 9 lists. Its Ethernet is **RTL8125BG over PCIe**, not the SoC's
stmmac GMAC, so the port needs a DesignWare PCIe root complex and an RTL8125 driver. Required to reach H4, roughly
in order: GICv3; RK3588 UART; dwcmshc eMMC; DWC PCIe 3.0/2.0 RC + MSI(-X); RTL8125; NVMe; SPI + a TPM 2.0 TIS
driver; RK806 PMIC (SPI) and the RK860 core regulators (DVFS); I²C (HYM8563 RTC, FUSB302). Deferred, each later
capability-granted: xHCI + MBIM/QMI for the 5G modem, a driver for one chosen M.2 Wi-Fi chipset (a selection
decision of its own, as consequential as CYW43455 was), the ESP32-H2 Thread link, DisplayPort, the NPU, and the
accelerator slot. Each is a capability in the manifest, never a branch on the board name.

### D5 · Boot chain and root of trust **[vision]**
- **Chain:** RK3588 BootROM → Rockchip DDR-init (TPL) → SPL → TF-A BL31 → `hboot` → heqk, with A/B slots and
  rollback replacing CM5's `config.txt`/tryboot. The hybrid Ed25519 + SLH-DSA verification in `hboot` stays
  unchanged. RK3588 secure boot (BootROM-verified, OTP-fused key) anchors the first stage.
- **Honest gap:** the RK3588 DDR-init stage is a closed Rockchip binary today. It is recorded in the SBOM/CBOM as an
  unverifiable vendor blob, as CM5's VideoCore firmware is, and never described as open or verified.
- **TPM:** the SLB9670 gives the board a real TPM-held storage root key. Device identity (today HKDF over the CM5 OTP
  SRK) gains a TPM-backed variant, reported in the manifest's crypto posture. The derivation interface is the same;
  only the key source changes.
- **Power:** USB-C power above 5 V needs a FUSB302 PD negotiation in the boot chain. Until heqk (or the pre-heqk
  stages) does that, the **DC jack is the supported power input** and USB-C PD is a later capability.

### D6 · Licence: operator decision, recommendation recorded **[open]**
The software is AGPL-3.0 + commercial (`LICENSING.md`). Hardware design files need a hardware licence.
**Recommendation: CERN-OHL-S-2.0** (strongly reciprocal, the hardware counterpart of AGPL's intent). The commercial
side (a HookProbe-branded, certified unit) is a trademark and product matter, not a licence restriction on the
files. The design files carry no licence until the operator decides; `hardware/README.md` says so.

### D7 · Honesty floor for hardware claims **[realized: this clause]**
Extends ADR 0047 D4. Until H4 passes, no external material says HookProbe "has", "ships" or "sells" a board.
Allowed wording: "an open RK3588 reference design, in progress (schematic and placement complete, not routed)."
Performance figures (2.5 GbE line rate, NPU throughput) are claimed only from H4 measurements.

### D8 · A hardware gate in the spine **[partial]**
The design's checks join the ADR 0063 gate spine once KiCad is on a CI runner: `design/allocation_check.py` needs
only Python and can run on every PR touching `hardware/`. `validate.py` (about ten minutes, needs `kicad-cli`,
currently a KiCad 10.99 nightly file format) runs nightly or on demand. Until it is wired in, `VALIDATION.md` is the
evidence of record and must be regenerated in the same change as any edit to the generator scripts.

## Consequences

- The ADR 0047 D1 platform list gains a concrete RK3588 target and a reference board for it. The report §4 item 9
  ("stmmac GMAC") describes ROCK 5B-style onboard Ethernet. Our board uses PCIe RTL8125 instead (D4).
- Rev A's PCIe allocation shares the four `pcie30phy` lanes across NVMe, the accelerator and both NICs (one lane
  each, per `design/allocation_check.py`). That is enough for 2× 2.5 GbE, but caps NVMe and the accelerator at one
  Gen3 lane. This is a rev A review item for H3, not a defect.
- A TPM changes the crypto-posture story: on this board, "device identity in hardware key storage" becomes true,
  where on CM5 it is OTP-derived.
- No `os/kernel` work, purchase or fabrication follows from this ADR until H0 is green (D1). Red steps stay
  operator-run.

## Open items (for the operator)
1. Ratify D1–D8, in particular the licence (D6) and the ROCK 5B port-first sequence (D3).
2. Name a hardware lead or design house for H3 (routing, SI/PI review).
3. Choose the M.2 Wi-Fi chipset to support first (D4); it decides a driver of CYW43455-sized effort.
