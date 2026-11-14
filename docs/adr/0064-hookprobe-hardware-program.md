# ADR 0064 — HookProbe hardware program: from CM5 to a HookProbe board (RK3588), after CM5 is validated

**Status:** 🟡 **Proposed (2026-11-14)**; **D6 decided by the operator (2026-11-14): CERN-OHL-S-2.0 + commercial
hardware licence, design published at H5.** The rest awaits operator review. Records the direction the operator set on 2026-11-14:
once HookProbe OS is validated on CM5, HookProbe moves to dedicated hardware of its own, through an intermediate
board with the same processor. Clauses are tagged **[realized]**, **[partial]** or **[vision]** (the ADR
0043/0044/0047 discipline).
**Deciders:** operator (ratification, the publication model D6, every Red step: fabrication, purchase, flashing);
os-architect (port design, D4/D5); security-auditor (boot chain and TPM, D5); verification-engineer (gates H0–H5);
release-engineer (board images and signing); market-intelligence (the D7 honesty floor on hardware claims).
**Relates to:** ADR 0003 (Platform Manifest: capabilities, crypto posture), ADR 0043/0044 (heqk; CM5 is the first
metal), **ADR 0047** (heqk everywhere: RK3588 is in its D1 platform list, and its D4 honesty floor), ADR 0060
(SMP core roles: the RK3588 is 4×A76 + 4×A55), ADR 0061 (memory budgets), ADR 0063 (gate spine).

## Context

- **CM5 is the only metal-proven heqk platform** [realized]. The zero-Linux factory image passed full acceptance on
  CM5 (2026-11-04). What is still open before CM5 can be called *validated* is release work: the REL-05 soak, the
  REL-06..08 thermal/scale/Wi-Fi-TX items, the G46 security sign-off (SEC-05), and a green g6 metal gate on the
  self-hosted bench (`docs/compliance/cra-matrix.md`, `docs/design/heqk-parity-gaps.md`, `tools/ci/gates.sh`).
- **CM5 limits the product.** BCM2712 has no TPM (device identity is HKDF over the OTP SRK), one GEM NIC plus a
  carrier NIC, and no on-chip NPU. A security appliance needs at least two fast ports, hardware key storage,
  storage for local retention, and room for inference.
- **ADR 0047 D1 already names RK3588 as a heqk platform**. `docs/design/heqk-everywhere-report-2026-10-09.md` §4 item
  9 sizes the port at "weeks to months".
- **A board design exists** (rev A, RK3588, schematic and placement complete and checked, not routed, never built).
  It is a **company asset kept outside this public repository** (D2). This ADR records only what HookProbe OS
  needs to know about it.

| Function (OS-facing) | HookProbe board | CM5 today |
|---|---|---|
| SoC | RK3588: 4×Cortex-A76 + 4×Cortex-A55, NPU | BCM2712: 4×Cortex-A76 |
| Storage | eMMC + M.2 NVMe | eMMC |
| Wired network | 2× 2.5 GbE, Realtek RTL8125 on PCIe | GEM 1 GbE (+ carrier NIC) |
| Wi-Fi | **Qualcomm QCN9274 Wi-Fi 7** on M.2/PCIe (the Fortress card, `ath12k` on Linux) or an improved successor | CYW43455 (SDIO) |
| Cellular | **Sierra Wireless EM9293 5G** on M.2/USB 3, MBIM control (the Fortress modem) | — |
| Other radios | Thread/Matter module on a UART | — |
| Root of trust | **TPM 2.0 (SPI)** + RK3588 OTP | OTP only |
| Power | DC jack, or USB-C PD (needs negotiation in the boot chain) | 5 V |

## Decision

### D1 · CM5 stays the only product target until it is validated **[realized: this clause]**
No hardware engineering spend (routing, fabrication, components) and no RK3588 driver work in `os/kernel` starts
until gate **H0** below is green. Design research may continue. Hardware is a second product line built on a
validated OS, not a way around CM5's open items.

### D2 · Hardware design files stay private until H5 **[realized: this change]**
Schematics, layouts, generator scripts, BOMs and 3D models live in a **private** repository (`hookprobe-hardware`)
until a revision passes H4 and is published under D6. They never go into this AGPL software repository. A `.gitignore` guard here blocks KiCad files and a `hardware/` tree. The public repo
holds only the OS-facing view: this ADR and the board profile in `appliance/hookprobe-sbc/`, keeping the CLAUDE.md
design test (**adding hardware = one profile in `appliance/`, no UI, installer or API change**).

### D3 · Port through an intermediate board with the same processor **[vision]**
Before our board, heqk is ported to and validated on an **intermediate RK3588 board** (a commercial board such as
the Radxa ROCK 5B, whose processor, memory and power circuits our design follows). It does two jobs: it proves "heqk
on RK3588" separately from "our board works", and it is the bench for checking the next board's assumptions
(peripherals, Wi-Fi 7 card, modem, thermal) before our layout is committed. A fault on our prototype is then a board
fault, not a port fault.

| Gate | Exit criterion | Owner |
|---|---|---|
| **H0 · CM5 validated** | REL-05 soak passed; REL-06..08 closed or carried as named, operator-accepted residuals; SEC-05 (G46 review) signed off; `gates.sh g6` green on the bench; an operator-signed release built by `os/build/` | verification-engineer, operator |
| **H1 · HAL decoupling** | The kernel crate stops calling `arch_aarch64::` directly (report §4 item 8); CM5 and QEMU stay green | os-architect, code-developer |
| **H2 · heqk on the intermediate board** | Signed heqk boots on the intermediate RK3588 board: GICv3, UART, eMMC, PCIe + one 2.5 GbE port, `mc-e2e` over the wire, the separation-matrix rows that do not need Wi-Fi; QCN9274 and EM9293 brought up on it | verification-engineer |
| **H3 · Our board routed + reviewed** | Routed board passes the design's validation plus signal- and power-integrity review by a design house or Rockchip FAE; the rev A open items closed, including the Wi-Fi 7 power and PCIe items in *Consequences* | hardware lead (to be named), operator |
| **H4 · Prototype bring-up** | Prototypes boot the H2 image unchanged except for the board profile; both 2.5 GbE ports, NVMe, TPM, Wi-Fi 7, 5G and thermal proven under a g6-style metal gate | verification-engineer |
| **H5 · Release** | Manufacturing package, a reproducible board image, D7 claims checked, the D6 publication decision applied | release-engineer, operator |

### D4 · Driver delta, stated honestly **[vision]**
The report's §4 item 9 assumed the SoC's stmmac GMAC. This board's Ethernet is **RTL8125 over PCIe**, so the port
needs, roughly in order: GICv3; RK3588 UART; dwcmshc eMMC; DWC PCIe root complex + MSI(-X); RTL8125; NVMe; SPI + a
TPM 2.0 TIS driver; the RK806 PMIC and core regulators (DVFS); I²C (RTC, USB-PD controller). Then the two radios
the operator chose:
- **QCN9274 Wi-Fi 7.** The heaviest driver in the program: Qualcomm firmware with a host-side protocol
  (Linux `ath12k`: WMI/HTT over PCIe copy engines, board-data files). Larger than the CYW43455 work. The firmware
  and board-data blobs go through the firmware-staging path and are recorded in the SBOM as vendor blobs. Wireless
  assessment stays receive-only (no management-frame injection).
- **EM9293 5G.** xHCI (USB 3) + CDC-MBIM control + the data path. The Fortress already runs it on Linux
  (`cdc_mbim`), so it is the reference behaviour.

Each is a manifest capability (`inline_ips`, `tpm`/`tpm_sealed`, `wifi`/`wifi_ap`, `cellular`, `edge_ai`), never a
branch on the board name.

### D5 · Boot chain and root of trust **[vision]**
- **Chain:** RK3588 BootROM → Rockchip DDR-init (TPL) → SPL → TF-A BL31 → `hboot` → heqk, with A/B slots and
  rollback replacing CM5's `config.txt`/tryboot. The hybrid Ed25519 + SLH-DSA verification in `hboot` is unchanged.
  RK3588 secure boot (BootROM-verified, OTP-fused key) anchors the first stage.
- **Honest gap:** the RK3588 DDR-init stage is a closed Rockchip binary. It is recorded in the SBOM/CBOM as an
  unverifiable vendor blob, as CM5's VideoCore firmware is, and never described as open or verified.
- **TPM:** device identity (today HKDF over the CM5 OTP SRK) gains a TPM-backed variant, reported in the manifest's
  crypto posture. Same derivation interface, different key source.
- **Power:** until the boot chain negotiates USB-C PD, the **DC jack is the supported power input**.

### D6 · Publication model: dual licence, published at H5 **[decided: operator 2026-11-14]**
**Decision:** the hardware is dual-licensed, mirroring the software's AGPL-3.0 + commercial model:
- **CERN-OHL-S-2.0** for everyone. Anyone may study, build and sell the design. Anyone who distributes a modified
  board must publish their changed design sources under the same licence.
- **A commercial hardware licence** for manufacturers who want closed derivatives or white-label units without
  publishing their changes.
- **The trademark stays reserved.** "HookProbe" and any "HookProbe Certified" mark are not granted by either
  licence. Official signed releases, the device trust root and cloud/MSSP enrollment stay HookProbe's, so the
  certified board is the reference worth buying.
- **Timing:** the design stays **private until H5**. The first published revision is the one that passed H4
  prototype bring-up, never an unrouted or unproven one. Until then, only this OS-facing ADR and the
  `appliance/hookprobe-sbc/` profile are public. Each later revision is published when it passes its own H4-style
  gate.
- Third-party material in the design (vendor symbols, parts derived from the Radxa reference) is checked for
  redistribution rights before H5, and removed or replaced where needed.

Facts the decision rested on:
- Every CERN-OHL variant (P, W, S) lets anyone copy, build and sell the design. **S** additionally makes them
  publish their changes. A CERN licence does not keep a design a company asset. What protects you is the
  **HookProbe trademark** and being the reference source.
- Raspberry Pi is not open hardware. Its compute modules are closed, its boards ship only reduced schematic PDFs,
  and only the IO/carrier boards are released as design files.

Alternatives the operator considered and declined: a closed compute module with open carrier boards (the Raspberry
Pi model), and keeping the design private permanently.

### D7 · Honesty floor for hardware claims **[realized: this clause]**
Extends ADR 0047 D4. Until H4 passes, no external material says HookProbe "has", "ships" or "sells" a board.
Performance figures (2.5 GbE line rate, Wi-Fi 7, 5G, NPU throughput) are claimed only from H4 measurements.

### D8 · Hardware gate **[partial]**
The design's checks (allocation/load budget in plain Python; full validation with `kicad-cli`) run in the private
repository's own CI, not in this repository's gate spine, so no design file reaches public CI logs or artifacts.
This repository's gates cover the OS side: the board profile and, from H2, the board's heqk image under g2/g6.

## Consequences

- RK3588 in ADR 0047 D1 gains a concrete target and an intermediate validation board.
- **Rev A items the QCN9274/EM9293 choice raises (for H3):** the Wi-Fi slot's 3.3 V allowance in rev A
  (about 5 W) is likely below a QCN9274 card's peak, and that slot gets one PCIe **Gen2** lane (about 4 Gb/s),
  which can cap Wi-Fi 7 throughput. Re-budget both from the chosen module's datasheet. Also confirm the card's M.2
  key and size. The EM9293 fits the B-key-on-USB-3 slot as designed. Its peak current is checked against the modem
  budget.
- On this board, "device identity in hardware key storage" becomes true, where on CM5 it is OTP-derived.
- No `os/kernel` work, purchase or fabrication follows from this ADR until H0 is green (D1).

## Open items (for the operator)
1. Ratify D1–D5, D7, D8 (D6 decided 2026-11-14: CERN-OHL-S-2.0 + commercial, published at H5). Draft the
   commercial hardware licence terms and the "HookProbe Certified" criteria before H5.
2. Pick the intermediate RK3588 board (D3; ROCK 5B suggested).
3. Name a hardware lead or design house for H3 (routing, SI/PI review).
4. Confirm the exact QCN9274 module (Fortress board file suggests Compex WLE7002E25) or its successor.
