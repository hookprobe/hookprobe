# ADR 0064 — HookProbe hardware program: from CM5 to a HookProbe board (RK3588), after CM5 is validated

**Status:** 🟡 **Proposed (2026-11-14)**; **D6 decided by the operator (2026-11-14): CERN-OHL-S-2.0 + commercial
hardware licence; amended the same day: the design is published now, as work in progress.** The rest awaits operator review. Records the direction the operator set on 2026-11-14:
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
  It is published in `hardware/hookprobe-sbc/` as work in progress (D2, D6).

| Function (OS-facing) | HookProbe board | CM5 today |
|---|---|---|
| SoC | RK3588: 4×Cortex-A76 + 4×Cortex-A55, NPU | BCM2712: 4×Cortex-A76 |
| Storage | eMMC + M.2 NVMe | eMMC |
| Wired network | 2× 2.5 GbE, Realtek RTL8125 on PCIe | GEM 1 GbE (+ carrier NIC) |
| Wi-Fi | **Qualcomm QCN9274 Wi-Fi 7** on M.2/PCIe (the Fortress card, `ath12k` on Linux) or an improved successor | CYW43455 (SDIO) |
| Cellular | **Sierra Wireless EM9293 5G** on M.2/USB 3, MBIM control (the Fortress modem) | — |
| Other radios | Thread/Matter module on a UART | — |
| AI acceleration | RK3588 NPU (6 TOPS) + **M.2 M-key 2280 slot for an AI accelerator (NPU) or FPGA card** (rev A: PCIe 3.0 ×1, ~10 W) | — |
| Root of trust | **TPM 2.0 (SPI)** + RK3588 OTP | OTP only |
| Power | DC jack, or USB-C PD (needs negotiation in the boot chain) | 5 V |

## Decision

### D1 · CM5 stays the only product target until it is validated **[realized: this clause]**
No hardware engineering spend (routing, fabrication, components) and no RK3588 driver work in `os/kernel` starts
until gate **H0** below is green. Design research may continue. Hardware is a second product line built on a
validated OS, not a way around CM5's open items.

### D2 · Hardware design files live in `hardware/`, public, as work in progress **[realized]**
*Amended 2026-11-14 (operator): "share it public, so we get feedback and show proof of work". Earlier the same
day this clause kept the files private until H5.*
Schematics, layouts, generator scripts, BOMs, renders and 3D models live in `hardware/<board>/` in this repository,
under the D6 licence. The generator scripts are the source of truth; the `.kicad_*` files are their output. Every
published revision carries its status in its README (rev A: **not routed, never built, do not manufacture**).
Third-party datasheets and the Radxa reference schematic are not redistributed (`.gitignore` guard). The board's
OS-facing view stays its profile in `appliance/hookprobe-sbc/`, keeping the CLAUDE.md design test (**adding
hardware = one profile in `appliance/`, no UI, installer or API change**).

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

### D6 · Publication model: dual licence, published as work in progress **[decided: operator 2026-11-14]**
**Decision:** the hardware is dual-licensed, mirroring the software's AGPL-3.0 + commercial model:
- **CERN-OHL-S-2.0** for everyone. Anyone may study, build and sell the design. Anyone who distributes a modified
  board must publish their changed design sources under the same licence.
- **A commercial hardware licence** for manufacturers who want closed derivatives or white-label units without
  publishing their changes.
- **The trademark stays reserved.** "HookProbe" and any "HookProbe Certified" mark are not granted by either
  licence. Official signed releases, the device trust root and cloud/MSSP enrollment stay HookProbe's, so the
  certified board is the reference worth buying.
- **Timing (amended 2026-11-14, operator):** published **now, as work in progress**, from rev A onward, so the
  community can review it and the work is visible. (The same-day first version said "private until H5".) Every
  revision's README states its real status; D7 still forbids saying a board ships or performs until H4.
- **Licence notice and Source Location** (CERN-OHL-S §4) are in `hardware/README.md`; the full text is
  `hardware/LICENSE-CERN-OHL-S-2.0.txt`. Copyright holder: HookProbe, so the commercial licence can be granted.
- **Contributions** must be licensable under both options. Before merging hardware pull requests from outside
  HookProbe, the contributor agrees to HookProbe's contributor agreement (the same CLA as the software,
  `LICENSING.md` Contact), or the dual licence breaks.
- Third-party material (vendor symbols and footprints, values following the Radxa reference) stays under its
  owners' terms, is listed in `hardware/README.md`, and is replaced if its terms do not allow redistribution.

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
The design's checks join the ADR 0063 gate spine: `design/allocation_check.py` needs only Python and can run on
every PR touching `hardware/`; `validate.py` (about ten minutes, needs `kicad-cli`, currently a KiCad 10.99 nightly
file format) runs nightly or on demand once KiCad is on a runner. Until then, `VALIDATION.md` is the evidence of
record and is regenerated in the same change as any edit to the generator scripts. From H2 the board's heqk image
runs under g2/g6 like any platform.

### A1 · An RK3576 (NanoPi M5) Rockchip bench before H2 **[PROPOSED 2026-11-26 — awaiting operator decision; nothing below is decided]**
**Context.** The operator ordered a FriendlyElec NanoPi M5 (RK3576), arriving mid-December 2026, with a 512 GB NVMe.
The research, hardware data pack, vendor-firmware findings and bench runbook are in
`docs/design/heqk-nanopi-m5-*-2026-11-26.md`. RK3576 is a **sibling** of RK3588, not the same processor, so it does
not satisfy D3 as written. **What carries over to RK3588:**
- the BootROM/idbloader → TF-A → U-Boot chain and its blobs policy
- DWC PCIe
- DW-APB UART
- Rockchip GPIO v2, CRU/GRF and OTP
- the RK806 PMIC
- DW-MSHC SD/SDIO

**What does not:**
- GIC-400 (GICv2) vs GIC-600 (GICv3)
- PCIe Gen2 vs Gen3
- **no SMMU** on RK3576 *(RK3588's PCIe MMU-600: verify)*
- 2× 1 GbE SoC GMACs vs our board's RTL8125
- A72/A53 vs A76/A55

**Already done, and the D1 question it raises.** These items exist ahead of H0:
- the purchase itself, an operator Red step
- bench tooling (`tools/diagnostics/m5-*`, `tools/build/m5-firmware-build.sh`)
- the bring-up probe `os/kernel/m5probe`. It is a bench payload, not a heqk driver, not linked into any image, and its
  only shared code is the existing `boot-abi` FDT reader

None of these touches the kernel crate or CM5 behaviour (validate.sh build stage, clippy ratchet and release check
unchanged). D1 should still say explicitly whether this class of work is allowed before H0.

| Decision | Options | Recommendation |
|---|---|---|
| **D-M5-1 · role of the M5** | (a) **early Rockchip bench, before H2**: it does **not** replace D3's RK3588 intermediate board, and H2 still needs RK3588 · (b) replace the RK3588 intermediate board · (c) shelve until H0 | **(a)**: it de-risks the shared Rockchip IP and the boot chain cheaply, while (b) would validate a different SoC than our board's |
| **D1 scope before H0** | (i) bench tooling + research + the probe only; heqk port work (H1 HAL decoupling and every RK3576/RK3588 driver) after H0 · (ii) also start H1 now, on a branch, CM5/QEMU green as its exit criterion · (iii) full M5 port now | **(i)**: CM5 validation stays the priority (D1's reason); H1 touches ~939 kernel call sites and would compete with REL-05..08 for review |
| **D-M5-2 · radio** | (a) no BE200 · (b) BE200 in the M-key slot | **(a)**. The E-key slot is SDIO + UART only (PCIe/USB pins NC, schematic rev 2411). Intel firmware limits AP mode to 2.4 GHz. With no SMMU, a PCIe radio would be an unconfined DMA master (remediation doctrine X5). Use an SDIO BCM43456 module (Radxa A2) on the existing CYW stack; QCN9274 stays our board's AP radio (D4) |
| **D-M5-3 · storage** | NVMe in the M-key slot as the DataVolume/retention tier; first stage in SPI-NOR; UFS module later | as stated. The BootROM cannot boot NVMe, and its SD boot is unreliable on RK3576 |
| **D-M5-4 · sealing key** | (a) a SiP SMC in our upstream-TF-A build hands hboot a per-boot derived key (secure OTP is secure-world only) · (b) no sealing on the bench (unsealed builds) · (c) a discrete SPI TPM 2.0 on the 30-pin header, rehearsing our board's TPM path (D5) | **(b) now, (c) next**: (a) means maintaining a TF-A fork plus a security-auditor review for a bench board |

**Consequences if accepted as recommended:** M5 bench milestones are named `M5-0…M5-n` and are **not** H-gates. No
product, marketing or performance claim comes from the M5 (D7). The QEMU rehearsal
(`tools/diagnostics/m5-qemu-rehearsal.py`) joins the evidence for any change to the M5 boot path.

## Consequences

- RK3588 in ADR 0047 D1 gains a concrete target and an intermediate validation board.
- **Rev A items the QCN9274/EM9293 choice raises (for H3):** the Wi-Fi slot's 3.3 V allowance in rev A
  (about 5 W) is likely below a QCN9274 card's peak, and that slot gets one PCIe **Gen2** lane (about 4 Gb/s),
  which can cap Wi-Fi 7 throughput. Re-budget both from the chosen module's datasheet. Also confirm the card's M.2
  key and size. The EM9293 fits the B-key-on-USB-3 slot as designed. Its peak current is checked against the modem
  budget.
- **The M.2 AI slot is a product feature, not a spare slot.** It lets detection models run on the box and be upgraded
  with the card. Rev A gives it one PCIe 3.0 lane (the four `pcie30phy` lanes are split ×1 each) and a ~10 W
  budget: enough for inference-class NPU cards, which are latency-bound, but a ×2 link is worth keeping if H3
  re-allocates lanes. Supported cards are chosen at H2/H4 from what heqk can drive; none is claimed before then (D7).
- On this board, "device identity in hardware key storage" becomes true, where on CM5 it is OTP-derived.
- No `os/kernel` work, purchase or fabrication follows from this ADR until H0 is green (D1).

## Open items (for the operator)
1. Ratify D1–D5, D7, D8 (D6 decided 2026-11-14: CERN-OHL-S-2.0 + commercial, published now as work in progress). Draft the
   commercial hardware licence terms and the "HookProbe Certified" criteria before H5.
2. Pick the intermediate RK3588 board (D3; ROCK 5B suggested).
3. Name a hardware lead or design house for H3 (routing, SI/PI review).
4. Confirm the exact QCN9274 module (Fortress board file suggests Compex WLE7002E25) or its successor.
5. **Decide A1** (proposed 2026-11-26): the M5's role (D-M5-1), what D1 allows before H0, the radio (D-M5-2), the
   storage (D-M5-3) and the sealing key (D-M5-4). The board arrives mid-December 2026; the day-one bench work in
   `docs/design/heqk-nanopi-m5-bench-runbook-2026-11-26.md` needs only D-M5-1 (a) and D1 (i).
