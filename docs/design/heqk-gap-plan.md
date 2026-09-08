# heqk → zero-Linux-on-CM5 — remaining-gap plan (2026-09-08)

**Status:** 🟡 living plan · synthesized from a deep gap-audit (product-steward inventory + os-architect technical deep-dive, 2026-09-08), grounded in `docs/BuildPlan.md` Track C, `docs/MIGRATION-heqk.md`, `docs/design/heqk-unbuild.md`, `docs/design/heqk-detection-parity.md`, and `kernel/heqk/GAP_REGISTER.md`. Drives the next work sessions. Amber (code/ADR changes operator-reviewed); irreversible items (fuse burns) are Red/operator-only.

## Headline

The **security underlay** (boot → capture → detect → enforce → persist-sealed) is **metal-real on CM5 today**: M1 accepted 4/4, M2 at 31/31 heqk-plane separation rows, M3 eMMC write + sealed store + per-device-OTP-SRK proven. The **connected / brain / experience half** (net stack on a real NIC, on-device Wasm host, WiFi data, app tier, UI) is **QEMU-green at best or not built**, and shares one recurring failure mode: *passes-QEMU, never run over real hardware*.

**The two structural facts that most define the remaining distance:**
1. **The on-device Wasm host is `!cm5`-gated** (`kernel/build.rs`: `build_el0_wasmhost` runs only when `WASMHOST && !CM5`). The "brain on device" (ADR 0044 D4 #2) has **never run on metal** — blocked behind an MMU multi-block-W^X fix (wasmi's ~326 KiB `.text` overran the single-2-MiB W^X block at MMU-enable) + an explicit TCB-expansion decision.
2. **There is no NIC↔smoltcp bridge in the prod datapath** (`kernel/src/prodfull.rs:30-35`): the sensor loop drives `gem::peek_rx_frame` directly; the entire M4 connected stack (smoltcp/Noise/enroll/kill-switch) is dead-stripped on the metal profile and has never touched a real NIC.

No U-batch is fireable yet. Nothing is deleted. The Linux M1 image keeps shipping.

## Where each phase stands

| Phase | State | Remaining |
|---|---|---|
| **M1** substrate beachhead | ✅ metal 4/4 | production key-custody ceremony (process) |
| **M2** detection parity | 🟢 31/31 heqk-plane metal + 2 off-device | Gate-R single adversarial pass on metal; manifest per-interface port-role reader (A1/A9 on a REAL interface); product-steward sign-off ruling |
| **M3** persistence & OTA | 🟢 write + sealed store + real-OTP-SRK metal | **DataVolume partition (in progress)**; A/B OTA forward tryboot flip on metal (rollback half already proven); V3/SEC-2 OTP hardening |
| **M4** control-plane/net | 🟡 QEMU-only, zero metal | **NIC↔smoltcp bridge over GEM (keystone)**; HW-TRNG-live Noise handshake + PCR3 seed; DNS-sinkhole/RPZ; WAN PBR/NAT/TUN-SASE; provisioning |
| **M5** module runtime / brain | 🟡 QEMU/EL0, `!cm5`-gated | **MMU multi-block-W^X fix → un-gate + build wasmi FOR cm5**; real wasip1 host; full signed catalogue; CORE-1 caps-enforced + CORE-2 per-TCB CSpace |
| **M6** app tier / UI | ⬜ vision | B1-vs-B2 decision (recommend B2 off-device); MC live vs heqk CM5; greedy-floor test |
| **M7** unbuild | plan done | all U1–U6 execution (metal-gated) |

## Parallel driver tracks

- **DRV-1 (RP1 GEM RX MSI):** correctly **BANKED** — host side fully replicated + mip0→GIC proven, but the RP1 DWC-EP won't emit the MSI (gap is below the kernel source: RP1 firmware/iATU). NOT a gate — polled RX is drop=0 at ~9k fps. Revisit only via a Linux-on-CM5 DWC/iATU dump.
- **P9-RTL8111 (eth1/WAN):** driver complete + RC1 link-train metal-proven, but the RX datapath first-light is **physically blocked on this board** (RC1 seating/connector fault — even clean Linux can't train it). Treat **GEM as the proven NIC**; don't build WAN metal claims on the possibly-dead RTL board.
- **P10-WiFi (CYW43455):** control plane + AP-scan work; **assoc/WPA2/EAPOL/data unbuilt** — the longest single-driver pole (XL). Product default is **AP mode** = heqk-as-authenticator (needs CCMP/PBKDF2/HMAC WPA2 crypto heqk lacks), harder than STA.
- **DRV-2 IOMMU:** protects nothing live (`iommu5`/GEM unfenced). The DMA-safety net; also why brute-forcing DRV-1 is unsafe.

## Prioritized plan

### Group A — buildable-now, bounded (safe, matches this session's self-test method) → unlocks U2
1. **Doc-hygiene** (done 2026-09-08): stripped stray tool artifacts, reconciled the 30/33→31/31 contradiction; still TODO: refresh stale "AK software-constant / anti-rollback inert" claims (metal shows OTP-derived AK + floor=1) and `LIFECYCLE.md` P7 (metal 4/4).
2. **Manifest per-interface port-role reader** — turns A1/A9 from self-test to live-interface-real (small, bounded; the `verdict::set_port_role` seam exists).
3. **Gate-R single adversarial pass on metal** — run `tools/gate-r-matrix.sh` as ONE pass (harness tracked) → the release-blocking artifact.
4. **Product-steward ruling** accepting L5/L6-off-device + A11-wire-rejected.
5. **M3 DataVolume (in progress) + OTA forward tryboot flip on metal** → advances M3 → unlocks U3.

### Group B — needs a decision
6. **Ratify ADR 0045 (dev/test creds) + 0046 (GitHub migration + heqk 316-commit history custody)** — Red blocker before any push.
7. **DataVolume partition layout** (image-factory) — operator authorized destroying Linux on this board (heqk-only, re-flashable).
8. **M6 B1-vs-B2 app-tier ruling** (recommend B2 off-device).

### Group C — large builds (the real remaining engineering), by D4 dependency
9. **CORE-1 caps-enforced + CORE-2 per-TCB CSpace per-spawn** (D4 #1 keystone; prereq for multi-server userspace).
10. **MMU multi-block-W^X fix → un-gate + build the Wasm host FOR cm5** (D4 #2) — *the* tallest pole on the critical path; the brain has never run on metal.
11. **Real wasip1 host + full signed catalogue** on heqk (L/XL).
12. **NIC↔smoltcp bridge over GEM** (M4 keystone) + HW-TRNG-live Noise + PCR3 → DNS-sinkhole, MSSP link, OTA-pull.
13. **P10 WiFi assoc/WPA2/EAPOL/data + AP-mode authenticator** (U4, XL).
14. **M4 PBR/NAT/TUN SASE dataplane** (L/XL). Bank the RTL WAN path until a known-good RC1 link.
15. **M6 MC-live-on-heqk + greedy-floor test** → unlocks U6 (terminal).

### Group D — security-hardening (some irreversible = operator-only)
16. **SEC-2/V3 OTP mailbox carve-out + hvc proxy** (`hboot/stage2.rs`: EL1 can read OTP via the VC mailbox → reconstruct AK/SRK). Makes the metal-proven sealed store + attestation **tamper-proof**. Buildable now, high value.
17. **DRV-2/XC-3 IOMMU** fence + relocate kernel above the 1 GiB ceiling.
18. **XC-11/DET-1 BPF helper ABI** (close the kernel-read oracle) before any dynamic/untrusted rule loading.
19. **Irreversible ceremonies (operator-only, never autonomous):** SEC-3 BCM2712 signed-boot fuse; SEC-6 SVN-floor advance; SEC-5 AK-PCR0 binding (re-enroll); SEC-9 EL2 W^X.

## Critical path to zero-Linux-on-CM5

```
M2 sign-off (port-role reader + Gate-R one-pass + steward ruling)          → U2
   → CORE-1 caps-enforced + CORE-2 per-TCB CSpace (D4 #1)
   → MMU multi-block-W^X fix → un-gate + wasmi on CM5 (D4 #2)   ← tallest pole
   → real wasip1 host + signed catalogue                                    → U5
   → M3 DataVolume partition + OTA flip                                     → U3
   → NIC↔smoltcp bridge over GEM + M4 metal → DNS / enroll / OTA-pull
   → P10 WiFi assoc/data (U4)  ∥  M6 UI-on-heqk + greedy-floor              → U6
   → U6 → M7 execute unbuild → delete Linux on rpi-native
```

The enforcing **sensor** is done on metal. The remaining distance is the **brain (M5, un-gate the Wasm host)** and the **connected half (M4, the GEM bridge)** — both currently QEMU-only. Nearest-term highest-value, matching the proven self-test method: **finish M3 (DataVolume + OTA flip) + M2 sign-off** (unlocks U2, the first real Linux teardown), then open the MMU-W^X + Wasm-host-on-cm5 work (the tallest pole).
