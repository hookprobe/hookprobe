# ADR 0065 — The CYW43455 Wi-Fi driver moves out of the heqk kernel; the kernel keeps only bus plumbing

**Status:** 🟡 **Proposed (2026-11-14).** **D3 approved by the operator (2026-11-15).** **D6 (two-server split) and D7
(D-a, D-c, D-d, PMKSA recovery) decided by the operator (2026-11-15 / 2026-11-16) — amendment below.** The split is
**not complete**: see *Implementation status*. Direction set by the operator on 2026-11-14: an out-of-kernel (user-space)
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

### D3 — Keys — **decided by the operator 2026-11-15: approved with the safeguards below** **[vision]**

- Moving the authenticator and the SAE engine puts the PMK / PTK / GTK / IGTK and the SAE secrets in EL0, across
  calls. That **widens the 2A decision of 2026-11-11** (the PMK enters EL0 through one call and is wiped).
- Proposed safeguards:
  - the keys live only in `el0-wifi`, which holds no other service;
  - key installs (`WLC_SET_KEY`) are issued by the server through the device mapping, never through the
    management ABI;
  - the same wipe discipline and "no key on the IO page after a call" checks as 2A;
  - never logged.
- **Unchanged:** the device identity key and Noise stay in EL1 (operator decision 2026-11-11).
- *Superseded in part by D6 (2026-11-15): the keys live in `el0-wpa`, not `el0-wifi`; "holds no other service" now
  applies to `el0-wpa`.*

### D4 — Order, each step gated on metal **[partial]**

1. **Measure** the EL0 round-trip cost on the CM5, for 0 / 64 / 1514-B payloads, against an in-kernel copy
   (`lansvc::excursion_cost`, printed as `[EL0-COST]` at boot). **[realized, metal 2026-11-14]**

   Image `ec1`, 2,000 calls per size, same results on the trial boot and the cold boot:

   | Payload | Median | Worst | In-kernel copy |
   |---|---|---|---|
   | 0 B | 388 ns | 3.1 µs (first call) | 0 ns |
   | 64 B | 425 ns | 0.5–0.8 µs | 0 ns |
   | 1514 B, copied in and out | 1.19–1.20 µs | 1.35 µs | 148 ns |

   - At the worst case of ~24 k frames/s, one round trip per frame with no batching, that is ~29 ms of CPU per
     second, ~3 % of one core.
   - One SDIO frame read already costs ~0.8 ms of PIO (profiler, metal 2026-11-05), so the boundary is ~0.15 % of
     the bus time.
   - **The cost does not rule out step 4.** Batching through the rings lowers it further.
2. **Substrate:** a resident-server class with a device-mapping capability, RX / TX rings, supervision and restart.
   Proven in QEMU with a fake device (the `apcore` fake-NIC pattern).
3. **Control plane (option B):** the authenticator, SAE, PMKSA cache, ACS / DFS policy and event decoding move to
   `el0-wifi`. The bus stays in EL1. **Needs D3.** Per-frame cost is unchanged; only management frames cross.
4. **Bus and SDPCM (option A):** move the rest. Step 1 shows the cost fits (~1.2 µs per full frame, against ~0.8 ms
   of SDIO PIO per frame). Its gate is still the D5 throughput floor on metal.

### D5 — Gates for every step **[vision]**

- AP throughput ≥ the 2026-11-07 baseline.
- `[WDOG] worst_loop_gap_ms` no worse than before the step (303 ms on `ge2`, 2026-11-14).
- `cm5-wpa3-check` and `cm5-lan-client` green: WPA3 transition, SAE and WPA2-only stations.
- No REL-08b regression on an SAE soak.
- The separation matrix and `mc-e2e` green.
- A server fault forgets only that server's state: stations re-join, and the AP's security mode never changes.
- The EL1 copy is deleted only after the step's gate.

### D6 — Two servers: bus and security — **decided by the operator 2026-11-15** **[partial]**

> The Wi-Fi driver is TWO resident EL0 servers. `el0-wifi` (bus: SDHCI/SDIO, SDPCM, firmware I/O) is stateless across
> a restart and may be restarted at any time. `el0-wpa` (4-way, SAE, PMKSA, GTK/IGTK, PSK PMK) keeps transactional
> state that survives its own restart, and is never reset by a bus fault. Keys reach the chip only through a
> key-transfer page (RW el0-wpa, RO el0-wifi) and the bus server's key-install call. The kernel brokers records and
> never reads, copies or retains key material. The D5 in-kernel keying fallback is removed.

Design: `docs/design/wifi-el0-split.md` (IPC, supervision and restart, timeouts, key isolation, performance).
A fault in one station's handshake may make that station retry; it never affects another station or the PMKSA
cache. A security-server fault outside a station call wipes every secret and forces full re-authentication.

### D7 — Operator decisions of 2026-11-16 **[partial]**

- **D-a — the AP passphrase stays in EL1 custody** (from the sealed configuration). The kernel may hand it to
  `el0-wpa` when (re)provisioning needs it; temporary copies are wiped. `el0-wpa` derives and owns the PSK PMK and
  all later key material. The kernel retains no derived key and no handshake state.
- **D-c — the hardware RNG stays in the kernel.** The kernel feeds fresh TRNG entropy to an `el0-wpa` DRBG at
  initialisation and on reseed; the RNG MMIO page is not granted to `el0-wpa`. Entropy failure fails closed.
  Direct access is reconsidered only on measured performance or availability need.
- **D-d — `validate.sh` QEMU per-boot timeout 600 s.** No assertion, test semantic or CM5 metal gate is relaxed; CI
  keeps a separate overall job timeout.
- **PMKSA recovery after a full wipe or reboot** — approved in principle, constrained: prefer a targeted
  association rejection with status 53 (Invalid PMKID) if the firmware / AP path supports it and real clients
  behave. **No generic MAC deny-list window** and nothing that could block a valid client. If targeted rejection is
  not supported, the current behaviour stays (post-association refusal; the client drops its stale PMKSA when its
  connection manager fails that attempt, then does a full SAE). Evidence required on CM5: after a full wipe and a
  reboot, clients with and without cached PMKIDs, full SAE fallback, no unnecessary failed retry, no regression to
  normal WPA3 reconnects.

## Implementation status (2026-11-17 — source and CM5 metal; QEMU evidence alone marks nothing)

| Clause | Status | Evidence |
|---|---|---|
| D4.1 measure | **[realized]** | metal `ec1`: 388 ns / 1.2 µs per EL0 round trip (#1206) |
| D4.2 substrate | **[realized]** | #1208 (rings, grant, supervision, backoff) |
| D4.3 control plane in EL0 | **[realized]** → moved to `el0-wpa` by D6 | #1209 #1211 #1212; S2 #1232 |
| D4.4 bus in EL0: frame RX / TX / control requests | **[realized]** | 4a #1219, 4b-1 #1220, 4b-2 #1222 #1223, 4c #1224, 4d #1226; metal 98–106 Mbps |
| D4.4 bus bring-up, firmware download, wifiheal reload | **[vision]** | still EL1 — the `SECURITY.md` honesty floor stands |
| D6 per-server address spaces (ASIDs) | **[realized]** | S0 #1229; metal `[P-el0-as] PASS` over 5 servers |
| D6 `el0-wpa` + independent supervision | **[realized]** | S1 #1231, S2 #1232; `/api/health` `wifi_driver` #1230 |
| D6 keys via the key-transfer page only; GTK/IGTK/PSK PMK in `el0-wpa` | **[realized]** | S3a/b/c #1233; metal WPA3 7/7, IPv6 SLAAC over the el0-wpa GTK |
| D6 in-kernel keying fallback removed (D-b) | **[realized]** | S3d #1235: compiled out of AP+MC images; `tools/el0keys-symcheck.sh` PASS on the shipping ELF; QEMU K1 scan (positive control) |
| D6 fault isolation (operator evidence E1–E7) | **[realized]** | S4 #1239: metal `s4-b060c8b9` E1–E7 PASS (soak 50/50 keyed + authorized, worst loop gap 846 ms); bus-fault cascade fix + episode escalation #1241 (one fault = 428–585 ms outage); firmware-reload bring-up 1964 → 533 ms (#1246, burst loop gap 954 ms) |
| D7 D-a | **[realized]** | passphrase handed to `el0-wpa` on (re)provisioning; temporary-copy audit in #1242: the sealed-config custody copy is the only kernel copy, transfer buffers and the shared page are wiped, the in-kernel SAE stack copy is compiled out (S3d) |
| D7 D-c | **[realized]** | #1242: SP 800-90A HMAC-DRBG in `el0-wpa` state pages, seeded by the kernel TRNG at load, reseeded hourly, `ST_NEED_SEED` fail-closed (strict TRNG); metal `dc-0f726481`: `drbg seeds=1` at load, survives a contained restart, reseeded after a full wipe, `seed_fails=0` |
| D7 D-d | **[realized]** | #1237: validate.sh QEMU timeout 600 s; the overall CI job timeout is kept separately |
| D7 PMKSA status-53 recovery | **[not supported by this firmware — current behaviour retained]** | CM5 experiment (2026-11-16): after a full wipe the firmware never rejects a stale PMKID with status 53, whether or not its PMKSA list is kept in sync. Per the decision, no deny-list and no workaround; the existing recovery stands. Related fix #1244: the keying decision follows the station's PMKID list (50/50 soak, 0 unkeyed handshakes) |

The split is complete only when every row above is **[realized]** with CM5 evidence.

## Consequences

- **TCB:** at the end, the kernel holds no Wi-Fi protocol code. A bug in the driver, or a firmware that feeds it
  hostile frames, is contained to `el0-wifi` and restarts it.
- **Cost:**
  - one EL0 round trip per ring batch (step 4) or per management frame (step 3);
  - a new resident-server substrate;
  - D3 widens where Wi-Fi keys live.
- **Honesty floor:** until step 4's gate, `SECURITY.md` keeps saying the Wi-Fi driver runs in EL1. If step 1's
  number rules out step 4, this ADR is amended to say the bus stays in EL1, by measurement.
