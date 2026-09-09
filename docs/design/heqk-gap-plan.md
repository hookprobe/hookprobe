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
| **M2** detection parity | ✅ **SIGNED OFF — CONDITIONAL-GO** (Gate-R closed, 4 carve-outs; 31/31 heqk-plane metal + 2 off-device); single adversarial pass done | (carve-outs only) manifest port-role reader = C-2 M4/P9-gated; A9 verdict-posture → security-auditor; A6 FIN-scan (202) miss RESOLVED (`[P8-scan]` — scan tier fires symmetrically; the metal miss was a harness artifact). Unlocks **U2a**, not U2b (segmentation plane) |
| **M3** persistence & OTA | 🟢 write + sealed store + real-OTP-SRK + DataVolume log-store + **A/B OTA forward-flip + rollback** all metal | physical OTA candidate DELIVERY (FAT32 writer: new image→slot B + B→A promotion); V3/SEC-2 OTP hardening; production DataVolume partition (image-factory) |
| **M4** control-plane/net | 🟢 **bridge FIRST-LIGHT metal-proven** (2026-09-08: host `arping 10.200.0.2` → 5/5 smoltcp replies on the real RP1 wire, `faults=0`); [PH6-metalbridge] QEMU-green | ~~NIC↔smoltcp bridge over GEM (keystone)~~ **DONE + on metal** (`MetalBridge` in the prod drain loop, dual-verdict-gated, static 10.200.0.2/28, TRNG-seeded fail-closed — heqk now TERMINATES a frame, not just forward/drop); the `is_for_heqk` demux (dst-MAC-is-ours ∪ ARP-for-us) + tx-checksum-compute are in place (groundwork for any IP reply). Remaining: **ICMP-echo is NOT free** — smoltcp 0.13 does not auto-answer echo, so `ping` needs an ICMP/raw socket + app-crafted reply (deprioritized; off the control-plane critical path). Next on the live bridge: a persistent-SocketSet UDP path → **DHCP ✅ metal-proven (2026-09-09, #3: heqk smoltcp dhcpv4 client full DORA over the GEM → leased 10.200.0.9/gw 10.200.0.1, feature `dhcp`)** → HW-TRNG-live Noise handshake + PCR3 seed → the authenticated reach channel that arms segmentation; then DNS-sinkhole/RPZ; WAN PBR/NAT/TUN-SASE; provisioning |
| **M5** module runtime / brain | 🟡 QEMU/EL0, `!cm5`-gated | **MMU multi-block-W^X fix → un-gate + build wasmi FOR cm5**; real wasip1 host; full signed catalogue; CORE-1 caps-enforced + CORE-2 per-TCB CSpace |
| **M6** app tier / UI | ⬜ vision | B1-vs-B2 decision (recommend B2 off-device); MC live vs heqk CM5; greedy-floor test |
| **M7** unbuild | plan done | all U1–U6 execution (metal-gated) |

## Parallel driver tracks

- **DRV-1 (RP1 GEM RX MSI):** correctly **BANKED** — host side fully replicated + mip0→GIC proven, but the RP1 DWC-EP won't emit the MSI (gap is below the kernel source: RP1 firmware/iATU). NOT a gate — polled RX is drop=0 at ~9k fps. Revisit only via a Linux-on-CM5 DWC/iATU dump.
- **P9-RTL8111 (eth1/WAN):** driver complete + RC1 link-train metal-proven, but the RX datapath first-light is **physically blocked on this board** (RC1 seating/connector fault — even clean Linux can't train it). Treat **GEM as the proven NIC**; don't build WAN metal claims on the possibly-dead RTL board.
- **P10-WiFi (CYW43455):** control plane + AP-scan work; **assoc/WPA2/EAPOL/data unbuilt** — the longest single-driver pole (XL). Product default is **AP mode** = heqk-as-authenticator (needs CCMP/PBKDF2/HMAC WPA2 crypto heqk lacks), harder than STA.
- **DRV-2 IOMMU:** protects nothing live (`iommu5`/GEM unfenced). The DMA-safety net; also why brute-forcing DRV-1 is unsafe.

## Prioritized plan

### Group A — buildable-now, bounded (safe, matches this session's self-test method) → unlocks **U2a**
1. **Doc-hygiene** ✅ (2026-09-08): stripped stray tool artifacts, reconciled 30/33→31/31; still TODO: refresh stale "AK software-constant / anti-rollback inert" claims (metal shows OTP-derived AK + floor=1) and `LIFECYCLE.md` P7 (metal 4/4).
2. **Manifest per-interface port-role reader** — ruled **carve-out C-2** (M4/P9-gated): needs a real Access interface = the physically-blocked RTL8111/eth1 datapath; live fail-safe `Uplink` default makes its absence a MISS-not-harm. Lands *with* the P9 datapath; A1/A9 re-driven with real frames then. **Not built now.**
3. **Gate-R single adversarial pass on metal** ✅ (2026-09-08): `tools/gate-r-matrix.sh` as ONE pass → `~/heqk-metal-logs/20260908-M2-gater-single-pass-consolidated.txt` (faults=0, all drops attacker/structural-sourced, zero mgmt/legit drops; rule 113 port-scan un-masked by a harness fix). Follow-up: A6 FIN-scan (rule 202) miss — observe-class, non-blocking.
4. **Product-steward ruling** ✅ (2026-09-08): **CONDITIONAL-GO — M2 Gate-R CLOSED with 4 carve-outs** (C-1 self-test-through-datapath OK for undrivable rows; C-2 above; C-3 A11 wire-rejected valid; C-4 L5/L6 off-device valid). Recorded in parity-doc §6 + BuildPlan.
5. **M3 DataVolume + OTA forward tryboot flip on metal** ✅ (2026-09-08) → M3 metal-complete for the mechanism → unlocks **U3** (pending the physical DataVolume partition + FAT candidate-delivery).

> **M2 Gate-R is signed off (CONDITIONAL-GO).** But it did **NOT** unlock the full U2 — see the U2a/U2b split below.

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

## The U2 split — U2a (detect/enforce) vs U2b (segmentation)

The M2 Gate-R CONDITIONAL-GO (2026-09-08, product-steward) signed off the **detect/enforce** plane but did **not** unlock the monolithic U2 (Dataplane) unbuild batch. Reason: U2's scope bundles two different things, and only one has its heqk replacement proven. So U2 is **split** (a future **Amber** proposal → ADR + operator sign-off; noted here so the plan reflects it):

| Batch | Linux primitive being retired | heqk replacement | Gate | Status |
|---|---|---|---|---|
| **U2a** | libbpf/CO-RE loaders, XDP/TC `.bpf.c` build, `bpftool`/`clang` CI stages, `nft`/conntrack *as inline IDS/IPS* | the RFC-9669 rule plane + tri-state `decide()`/`decide_l2` (M2) | **M2 Gate-R** | ✅ **gate MET** (31/31 heqk-plane metal + carve-outs) — U2a is unlock-able |
| **U2b** | **OVS + nftables/conntrack *as SEGMENTATION*** (inter-segment/VLAN policy, per-device reach, quarantine-to-segment) | a heqk **segmentation plane** — REACH-ENFORCEMENT (`segment.rs`) BUILT + metal-proven; the **AUTHORITY** (operator-signed reach policy that ARMS it) now BUILT + QEMU-proven (`[P19-seg-policy]`) INCLUDING persisted anti-rollback floor + operator-key TOFU-pin surviving reboot (`[P19-seg-policy-persist]`, C10/C11) | a future segmentation-plane milestone | 🟡 **enforcement + signed authority + reboot-persistence built; gate NOT met** — remaining: the metal reconcile orchestrator over the GEM bridge (rides Noise-over-bridge; carries C12 no-floor⇒no-arm) + P9 ingress-port binding |

**The segmentation plane** is the *same* reach-actuator behind three carved-out rows: **L5/L6 NAC** (reach = Full vs InternetOnly), **A11** (quarantine-*to-segment*), and **U2b**. heqk's datapath is a single aggregate port with a binary PASS/DROP verdict — no per-segment forwarding.

**Progress (2026-09-08):** the on-device **reach-ENFORCEMENT primitive is BUILT** (`segment.rs`, security-auditor CONDITIONAL-GO C1–C8): a per-device MAC-keyed reach policy (`Full`/`InternetOnly`/`Quarantine`) enforced as a separate policy gate after the threat pipeline PASSes (kill-switch pattern), fail-open (Full default, mgmt-floor + infra carve-out), authority-set (never inferred — the key distinction from A11, so no victim-framing path). QEMU-proven (P8-flow) + metal self-test (`[SEPDIAG-SEG]`). **DISARMED by default (C7)** — inert in production (no reach-drop on the wire) until armed. **Remaining to make it live (and unlock U2b):**
> 1. an **authenticated reach channel** (signed manifest / attested control link) to arm it (C7) — an attacker who forges it owns the reach table;
> 2. the **off-device authority** (reconciler/NAC, ADR 0044 D3) that actually SETS per-device reach;
> 3. **P9 ingress-port binding** (multi-port RX) for spoof-resistant containment (aggregate port 0 can't port-bind today; a MAC-spoofing on-segment attacker escapes containment — a documented residual);
> 4. the InternetOnly/Quarantine **infra allow-set** completed with the authority-supplied gateway/DNS (`set_infra`).

It stays a **first-class remaining milestone**, but the two hardest halves are now done: the **enforcement** primitive (metal-proven, disarmed) AND the **signed authority** that arms it (`[P19-seg-policy]` — an operator-signed, tenant-bound, generation-floored reach policy over the enrolled Noise channel; security-auditor CONDITIONAL-GO honored, C9 independent operator signature is the trust root, fail-open on every failure). The persisted anti-rollback floor + operator-key TOFU-pin now SURVIVE reboot (`[P19-seg-policy-persist]`, C10/C11 — a replayed old policy is refused across reboot, an operator-key swap is refused). **Remaining:** the metal `reconcile_reach_policy` over the GEM bridge (rides Noise-over-bridge; composes the shipped floor/key primitives + carries C12 no-floor⇒no-arm), and P9 ingress-port binding. **Noise-over-bridge progress:** the >MTU handshake datagram framing is DONE + QEMU-proven (`[P19-noise-over-udp]` — msg1 ≈ 2480 B chunks into 3 datagrams, fail-closed reassembly, the full PQ-hybrid handshake completes over the chunker). **Transport first-light METAL-PROVEN (2026-09-08)** after a Linux-`macb`-aligned fix. The road took 3 findings: (1) bring-up fired pre-link; (2) the RP1 `link_status()` RGMII bit reads 0 at negotiated 1G → `gem::phy_link_up` (PHY BMSR bit2; and NEVER write NCR=NCR_MPE in the datapath — it clears RE/TE); (3) **the BLOCKER — a 2nd RX-ring walker** (the pre-loop `GemPhy`/bring-up) did raw ring ops and left RX_USED bits set → GEM **BNA** → RX DMA wedged (`seen=0` forever). The RP1 GEM is a Cadence GEM (Linux `macb`): exactly ONE ring owner (NAPI `gem_rx`), stack receives THROUGH it. **Fix (committed `bf560a8`+`6042858`, metal-validated):** deleted the 2nd walker; the control plane rides the sensor's SINGLE drain (RX tee to MetalBridge, TX via the one `gem::tx_frame`); the transport first-light is a periodic BROADCAST UDP presence beacon (hand-built, no socket). Metal: sensor healthy (`seen=200 fwd=199 faults=0` — ring NOT corrupted), MetalBridge answers arping 3/3, beacon `10.200.0.2:7654 > 255.255.255.255:7654 UDP 48B` captured on the wire (on FTS — enp4s0 is OVS-enslaved). **Remaining (full Noise handshake):** a PERSISTENT smoltcp socket teed off the one drain (buffers in statics for the no_std lifetime) + a std host MSSP-sim → live msg1/msg2 → `reconcile_reach_policy` → metal segmentation arming. (Governance: never retire the Linux segmentation primitive before its heqk replacement is proven + armed; Track B is the sunset-on-parity fallback.)

## Critical path to zero-Linux-on-CM5

```
M2 Gate-R sign-off (CONDITIONAL-GO) ✅                                      → U2a (unlock-able)
   → CORE-1 caps-enforced + CORE-2 per-TCB CSpace (D4 #1)
   → MMU multi-block-W^X fix → un-gate + wasmi on CM5 (D4 #2)   ← tallest pole
   → real wasip1 host + signed catalogue                                    → U5
   → M3 DataVolume partition + FAT OTA candidate-delivery                    → U3
   → NIC↔smoltcp bridge over GEM + M4 metal → DNS / enroll / OTA-pull
   → SEGMENTATION PLANE (unlocks U2b; actuates L5/L6 + A11)                  → U2b
   → P10 WiFi assoc/data (U4)  ∥  M6 UI-on-heqk + greedy-floor              → U6
   → U6 → M7 execute unbuild → delete Linux on rpi-native
```

The enforcing **sensor**, **persistence**, and the **connected half's first-light** are on metal (M2 signed off; M3 write/seal/DataVolume/OTA-flip proven; **M4 GEM bridge + presence beacon metal-proven 2026-09-08**).

### 2026-09-08 QEMU build-out (metal validation queued for the next hardware session)

The connected control plane + arming logic are now built and QEMU-green end-to-end:
- **[P19-controlplane]** — the smoltcp-free `ControlPlane` initiator drives the FULL PQ-hybrid Noise handshake over the hand-framed UDP transport that rides the sensor's single drain (against an in-kernel responder); msg1 chunked → reassembled → `Established`, crossed keys match.
- **[P20-reconcile]** — `reconcile_reach_policy` arms `segment.rs` off a channel-fetched operator-signed policy (read floor → TOFU op-key → fetch → apply → persist), replay refused; the **QEMU half of the U2b gate**.
- **[P20-dns-sink]** — DNS-sinkhole/RPZ ("refuse a NAME, never a packet"). ✅ **NOW METAL-PROVEN (2026-09-09, #4)**: wired to the prod drain via `netsvc::build_dns_sinkhole_frame` (feature `dnssink`). On CM5, injected `ads.tracker`/`x.ads.tracker` (blocked) each got a spoofed resolver reply `A 10.200.0.254`; `good.example` (legit) was forwarded untouched; serial `[DNSSINK hb] sinkholed=8`. Evidence: `~/heqk-metal-logs/20260909-DNS-sinkhole-metal-proven.txt`.
- Plus (earlier today) [P19-seg-policy] / [P19-seg-policy-persist] / [P19-noise-over-udp].

**FLAG (product-steward):** the M5 "tallest pole" is **build-plumbing, not an unsolved MMU problem** — the multi-block W^X fix already exists ([P-wx]) with a cm5 mirror (`mmu_cm5.rs`); what remains is un-gating `build.rs`/`Cargo.toml` to build the EL0 wasmi host FOR cm5 + a metal-runtime proof.

**✅ GEM LARGE-FRAME TX BLOCKER — RESOLVED (metal 2026-09-09, commit `c7311cc`).** The `txsweep` size/alignment sweep (`gem::set_tx_override` + a pre-sensor-loop sweep in main.rs) settled it in 3 metal runs. RUN-1: frames 64..1024 B egress at EVERY alignment → the "~90 B cliff" and the 256 B PCIe/AXI-boundary theories are both REFUTED (failure is alignment-INDEPENDENT). RUN-2: a PERFECT positional pass/fail alternation at the boundary (1512✓ 1514✗ 1515✓ 1516✗ …), with 1520 AND 1600 B transmitting on the "pass" slots and every passing large frame reading **TSR.TGO=1** — and **1070 B (the msg1 datagram size) passes cleanly** (the handshake was never blocked). **Root cause:** `tx_frame` re-issued `TSTART` every `RETRIGGER_SPINS=512` spins UNCONDITIONALLY; a full-size frame takes >512 spins, so the re-kick fired MID-TRANSMIT and disturbed the in-flight DMA → timeout → TE-bounce → self-perpetuating alternation, triggered by frame SIZE. **Fix:** gate the retrigger re-kick on `TSR.TGO==0` (exactly as Linux `macb` macb_main.c:2517) in `tx_frame` + `tx_diag_burst`. RUN-3 VALIDATED: 32/32 back-to-back 1514 B frames egress (no alternation); 1024..1514 B all pass; 1515+ correctly MAC-dropped as oversized (`used=1 tsr=0`, jumbo off). Ships in `prod` → full-size FORWARDING fixed + the metal Noise handshake / segmentation arming UNBLOCKED. `txsram` (wrong SRAM addr) + jumbo (`enable_jumbo`, kept as a capability) were red herrings. See memory `hookprobe-heqk-m4-bridge`.

**Metal-tomorrow worklist** (needs hardware; do NOT fake in QEMU): (0) ✅ **GEM large-frame TX — DONE** (TGO-gated retrigger, RUN-3 metal-validated; no longer a gate); (1) ✅ **live full Noise handshake — DONE (2026-09-09)**: device `state=Established rx_seen=2` against `kernel/responder-sim --live` (a std host MSSP sim linking the exact securechannel.rs); full PQ-hybrid over the RP1 wire. Evidence: `~/heqk-metal-logs/20260909-M4-noise-handshake-metal-proven.txt`. Remaining sub-item — the older "(1) the live full Noise handshake" — a std host MSSP-sim (shared `heqk-noise` crate for byte-compat) replies on the wire → device `Established`; (2) ✅ **metal segmentation ARMING — DONE (2026-09-09)**: device `[SEGDIAG] phase=2 recon=Some(Ok(2)) armed=true` — an operator-signed ReachPolicy served over the live Session (`kernel/responder-sim` policy-serving) is verified (op-sig→tenant→gen>floor) + applied (2 entries) + arms `segment.rs` on metal (feature `segmetal`; key fix = arm the eMMC one-shot write window before the reach-floor fslog). C9/C10/C11/C12/C16 held on silicon. Evidence: `~/heqk-metal-logs/20260909-U2b-segmentation-arming-metal-proven.txt`. ✅ **armed DROP also metal-proven (2026-09-09)**: FTS injector, `reach_drops` 0→8 = ONLY the Quarantined MAC's LAN-lateral traffic dropped (8/8) while its WAN + Full-MAC LAN + mgmt-src all passed (C2/C3/C11/C16 live). **U2b behavioral demo COMPLETE on silicon.** ✅ **fresh-region one-boot arm also FIXED + metal-proven (#1b, 2026-09-09)**: `fslog::format()`+`append()` now accept the Keystore region (were DataVolume-only), so a fresh reach-floor region formats+pins+applies+persists+arms in ONE boot (RUN-8 `fslog_err=None phase=2 armed=true`; enforcement re-confirmed reach_drops 0→24). REMAINING for full U2b sign-off (smaller): P9 port-binding (HW-blocked) + product-steward ruling + (optional) move the floor to a dedicated DataVolume partition (M3 gap #7). The older item — (3) M5 wasm-on-cm5 runtime; (4) M3 eMMC-scale (DataVolume partition, torn-tail, power-cycle); (5) P9 RTL8111/port-role (hardware-blocked board); (6) WAN PBR/NAT/TUN-SASE dataplane; (7) WiFi assoc/data. The **segmentation plane** stays the true gate to *deleting* the Linux dataplane (U2b → M7) — its logic is now fully QEMU-proven; only the on-the-wire arm remains.
