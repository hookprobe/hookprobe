# ADR 0065 — The CYW43455 Wi-Fi driver moves out of the heqk kernel; the kernel keeps only bus plumbing

**Status:** 🟡 **Proposed (2026-11-14).** Direction set by the operator on 2026-11-14: an out-of-kernel (user-space)
Wi-Fi driver, with only the raw bus and interrupt plumbing inside the heqk kernel. D3 (where the keys live) and
the go / no-go at each step's metal gate are the operator's. Clauses are tagged **[realized]**, **[partial]** or
**[vision]** (the ADR 0043/0044/0047 discipline).
**Deciders:** operator (ratification, D3, each step's gate); os-architect (D1, D2, D4); security-auditor (D3, the
TCB claim); verification-engineer (the gates).
**Relates to:** ADR 0044 D4 #7 (drivers as user-space servers), **ADR 0050** (parser placement; this ADR is the
next step of its D4 step 5 and does not edit it), ADR 0047 (heqk everywhere), `docs/design/wifi-driver-el0.md`
(options A / B / C — this ADR chooses **A as the target, B as the first step**).

## Context

- **What is in EL1 today** (`os/kernel/arch-aarch64/src/cyw43.rs`, 6.4 k lines, 227 `unsafe` sites):
  - the SDIO bus: CMD52 / CMD53 through the BCM2712 SDHCI controller at `0x10_0110_0000`;
  - SDPCM framing and TX credit, BCDC ioctl / iovar;
  - firmware, NVRAM and CLM download; regdomain, ACS, the DFS watch;
  - event decoding; the WPA 4-way and the SAE engine with their keys;
  - self-heal: kick, BSS bounce, firmware reload.
- Steps 5a–5c of ADR 0050 D4 already walk every station frame (EAPOL, RSNE, SAE) in `el0-lansvc`. What a radio
  attacker still reaches in EL1 is fixed-offset header reads. What remains in EL1 is mostly the code that trusts
  the **firmware's** output. REL-08 (a firmware use-after-free) shows that this trust is not free.
- **This platform is the cheapest case for a user-space driver:** the CYW43455 is on **SDIO, polled PIO, with no
  host DMA and no interrupt line** (`cyw43.rs`: "we POLL, so leave the Signal-Enable at 0"). A server needs one
  4 KiB device mapping and no IOMMU programming or IRQ routing.
- **Unknown:** the per-call cost of an EL0 excursion on the CM5. Every forwarded frame crosses `ap_tx` /
  `ap_poll`, at up to ~12 k frames/s per direction. The AP throughput floor is 80–160 Mbps (2026-11-07 baseline).

## Decision

### D1 — What the kernel keeps **[vision]**

Only what a dead or hostile driver server must not be able to block or forge:

1. **One device-mapping capability:** the SDHCI register page, granted to the Wi-Fi server alone, as
   Device-nGnRE. On a platform with DMA or interrupts (a PCIe radio on the HookProbe board, ADR 0064), the kernel
   also keeps the IOMMU / SMMU programming and the interrupt routing. Neither exists on the CM5.
2. **The frame rings** between the server and the forwarding path:
   - fixed-size RX and TX slots;
   - lengths re-checked on the kernel side;
   - nothing in a slot is trusted beyond its bounds.
3. **Supervision:**
   - restart on a fault, bounded backoff (ADR 0050 D5), reported on `/api/health`;
   - the watchdog;
   - the reset of the chip (WL_REG_ON / the SDHCI soft reset). A wedged server cannot keep the radio wedged.
4. **The crash record**, written before a reset, so a firmware trap is recorded even when the server is the thing
   that died.

### D2 — What moves to the server (`el0-wifi`) **[vision]**

Everything else in `cyw43.rs`:
- the bus protocol, SDPCM and credit, BCDC;
- firmware / NVRAM / CLM download, the regdomain, ACS and DFS;
- event decoding;
- the authenticator and the SAE engine (D3);
- the self-heal actions, which the kernel's supervisor triggers.

The server is a new class: **resident for the whole boot and owning a device.** Today's EL0 servers are short,
stateless calls (`el0-lansvc`) or own no hardware (`el0-tlshost`).

### D3 — Keys (operator decision, required before step 3) **[vision]**

- Moving the authenticator and the SAE engine puts the PMK / PTK / GTK / IGTK and the SAE secrets in EL0, across
  calls. That **widens the 2A decision of 2026-11-11** (the PMK enters EL0 through one call and is wiped).
- Proposed safeguards:
  - the keys live only in `el0-wifi`, which holds no other service;
  - key installs (`WLC_SET_KEY`) are issued by the server through the device mapping, never through the
    management ABI;
  - the same wipe discipline and "no key on the IO page after a call" checks as 2A;
  - never logged.
- **Unchanged:** the device identity key and Noise stay in EL1 (operator decision 2026-11-11).

### D4 — Order, each step gated on metal **[partial]**

1. **Measure** the EL0 round-trip cost on the CM5, for 0 / 64 / 1514-B payloads, against an in-kernel copy
   (`lansvc::excursion_cost`, printed as `[EL0-COST]` at boot). **[realized: instrument; metal number pending]**
2. **Substrate:** a resident-server class with a device-mapping capability, RX / TX rings, supervision and restart.
   Proven in QEMU with a fake device (the `apcore` fake-NIC pattern).
3. **Control plane (option B):** the authenticator, SAE, PMKSA cache, ACS / DFS policy and event decoding move to
   `el0-wifi`. The bus stays in EL1. **Needs D3.** Per-frame cost is unchanged; only management frames cross.
4. **Bus and SDPCM (option A):** move the rest, but only if step 1 shows the cost fits, per frame or batched per
   loop iteration through the rings. Otherwise the bus stays in EL1, and this ADR records that with the number.

### D5 — Gates for every step **[vision]**

- AP throughput ≥ the 2026-11-07 baseline.
- `[WDOG] worst_loop_gap_ms` no worse than before the step (303 ms on `ge2`, 2026-11-14).
- `cm5-wpa3-check` and `cm5-lan-client` green: WPA3 transition, SAE and WPA2-only stations.
- No REL-08b regression on an SAE soak.
- The separation matrix and `mc-e2e` green.
- A server fault forgets only that server's state: stations re-join, and the AP's security mode never changes.
- The EL1 copy is deleted only after the step's gate.

## Consequences

- **TCB:** at the end, the kernel holds no Wi-Fi protocol code. A bug in the driver, or a firmware that feeds it
  hostile frames, is contained to `el0-wifi` and restarts it.
- **Cost:**
  - one EL0 round trip per ring batch (step 4) or per management frame (step 3);
  - a new resident-server substrate;
  - D3 widens where Wi-Fi keys live.
- **Honesty floor:** until step 4's gate, `SECURITY.md` keeps saying the Wi-Fi driver runs in EL1. If step 1's
  number rules out step 4, this ADR is amended to say the bus stays in EL1, by measurement.
