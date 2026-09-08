# Linux → heqk Microkernel Migration Plan

**Status:** 🟡 Proposed (2026-07-24) · Companion to **[ADR 0043](adr/0043-heqk-microkernel-substrate.md)** (the keystone substrate-replacement ADR) · Authored under the "full authority to the cortex SDLC" mandate. Every phase is **Amber** (operator-reviewed) or gated **Red** (flashing/release — refused without explicit operator action), per contract C9.

> **Mandate:** replace Linux on the rpi-native tier with the `~/heqk` microkernel, reduce image size, and keep a *working* HookProbe OS — driven through the Product Cortex lifecycle (requirement → … → retirement), with all ADRs updated and all flows validated end-to-end.

---

## 1. Executive summary

- **This is feasible and already partly built.** heqk boots on CM5 metal today (attested, hybrid-PQC-signed, A/B-tryboot), drives the RP1 GEM NIC end-to-end, and runs its RFC 9669 BPF threat plane inline on the wire. Its boot artifact `heqk8.img` is a **reversible drop-in** for the Pi's `kernel8.img`.
- **The moat survives the swap.** HookProbe's differentiation is the detection rules + signed-artifact discipline + evidence graph — all **substrate-portable by contract** (event schema + RFC 9669 BPF ISA + WASI). The same clang-compiled rules run on Linux *and* heqk. ADR 0005's "eBPF is the moat" fear is about *Linux eBPF*; heqk targets the clean IETF ISA instead, so we do **not** reimplement Linux's verifier/JIT/CO-RE/BTF.
- **The repo splits into three strata**, which is what makes this tractable:
  - **(A) The brain** — ~47k LOC Rust (manifest, supervisor, reconciler, evidence, QSecBit, AEGIS, RBAC, hybrid PQC signing) + ~22k LOC Wasm detection modules → **carried over ~unchanged.**
  - **(B) The dataplane** — eBPF/XDP/TC, OVS, conntrack, nftables → **re-targeted** onto heqk's Packet Engine + BPF plane (heqk was *purpose-built* to receive exactly this).
  - **(C) The substrate/lifecycle** — Debian bootc, 42 systemd units, ~6.5k lines of bash, initramfs, greenboot, 7 out-of-tree WiFi drivers → **deleted** (much of it *evaporates*: sysctl/KSPP/systemd-sandboxing were faking what a capability microkernel gives natively).
- **Scope discipline:** rpi-native tier (CM5 → Pi5 → Pi4) only. The **amd64/N100/UEFI/cloud tiers stay on Linux/bootc** (heqk is aarch64-only). The **app tier (containers/heavy services) runs in a monitored Linux *guest VM*** (heqk `ARCHITECTURE_BLUEPRINT` Zone 4) — heqk replaces Linux-as-substrate, not Linux-as-app-host.
- **Governance:** the migration had *no home* and *contradicted* ADR 0035 D3. ADR 0043 supersedes that clause and reconciles ADR 0005; this plan is the epic that hangs off it, sequenced parallel to Track B per ADR 0035 D5 ("slide in underneath invisibly, neither track gates the other").

---

## 2. Where each of the four open engineering fronts stands

| Front | Today on heqk | The bridge |
|---|---|---|
| **Dataplane** (eBPF/XDP/TC → Packet Engine + BPF plane) | L2 inline IDS/IPS + RFC 9669 verifier/JIT metal-proven; ~11 signed rules | Add conntrack-equivalent flow state, OVS-class switching, tri-state `decide()` — gate on **P8 rule-parity** |
| **WiFi** (7 dongle drivers + brcmfmac AP) | CYW43455 control plane through AP-scan; **no assoc/data** | Finish heqk P10 D/E (assoc/WPA2/EAPOL/data); **drop the 7 USB dongle drivers on this tier**; expose AP-control + monitor surfaces for ADR 0034/0042 |
| **Storage** (SQLite/LUKS/dm-verity/journald) | **none** post-boot | Build eMMC/SDHCI block driver → minimal FS → sealed volume + on-device A/B transport |
| **Wasm host** (Wasmtime + WASI-p1) | **none** | `no_std`-capable runtime, or the `.cwasm` AOT path (ADR 0017); WASI-NN is vapor today — ignore |

Two pieces of good news shrink the bill: **Podman/Quadlet is paper coupling** (no `.container` files, no loader exists) and **the custom BTF kernel-rebuild problem class (ADR 0032) vanishes entirely**.

---

## 3. The phased plan

Each phase is independently gate-laddered; nothing that boots green today regresses. Phases map to Product Cortex personas (owner in **bold**).

> **PROGRESS 2026-07-25 — M0 RATIFIED, M1 beachhead landed.** Operator ratified ADR 0043 (gate cleared).
> heqk relocated to `kernel/heqk/` (own git repo, 316 commits + licensed firmware preserved); root Cargo
> workspace `exclude`s it; `builder/make-cm5-heqk-image.sh` builds the signed CM5 substrate image
> by-reference (verifier gate → hboot+prod build → hybrid sign → stage `config.txt`/`heqk8.img`/A-B/
> `tryboot.txt`; flash stays a Red operator step). heqk's PH1–PH7 production hardening (running IDS/IPS
> sensor, per-device OTP SRK, dual-backend cap sweep, smoltcp core) is metal-validated, so **M1's
> technical gate (forward :53 / drop :4444 / A/B rollback on metal) is met**. Next: de-git heqk into the
> parent tree; then M2 detection parity.

### Phase M0 — Governance & baseline *(this deliverable)* — **product-steward**
- Author **ADR 0043** (supersede 0035 D3, reconcile 0005) + this plan. Update all 42 ADRs with a heqk-migration footer. Register the epic + an `ideation-scout` "OS-is-the-sensor" requirement node.
- **Gate:** operator ratifies ADR 0043. *Until then, no heqk row may enter a release pass.*

### Phase M1 — heqk substrate beachhead (CM5) — **os-architect / release-engineer**
- heqk boots the CM5 as the rpi-native kernel via `config.txt kernel=heqk8.img`; GEM LAN up; inline IPS live; A/B tryboot + attested `hboot` verified on metal. *(Mostly **[realized]** in `~/heqk`; this phase is integrating it under the hookprobe-os build/release identity.)*
- Merge the trust chains: hookprobe-os hybrid ML-DSA-65+Ed25519 release key ↔ heqk `hboot` boot signing.
- **Gate:** CM5 boots heqk, forwards a legit `:53` flow, drops a `:4444` scan, survives a forced-bad-boot rollback — all on metal.

### Phase M2 — Detection parity (P8 rule-parity) — **os-architect / verification-engineer**
- Port the hookprobe-os detection catalogue to RFC 9669 bytecode (event schema + BPF ISA contract, ADR 0043 D2). Re-target napse-capture/-l2guard/-quarantine/host-telemetry semantics onto the Packet Engine.
- Stand up conntrack-equivalent flow accounting + the tri-state `decide()`/`decide_l2` enforcement-separation posture (ADR 0023) natively.
- **Gate (release-blocking):** the **heqk enforcement-separation matrix** (33 rows — 11 legit + 11 attacker + 11 frame-structural; distinct from the Linux `0.7-separation-matrix`) and **Gate R** (adversarial resilience) pass **on heqk metal**. Detection verdicts match Linux rule-for-rule on the shared corpus.
- **Status (2026-09-08): 🟡 PARTIAL — 30/33 rows PROVEN-ON-METAL on CM5** with zero legit-drops (all frame-drivable rows + the A7/A8/L9 resource-shed + A1/A2 port-role + F4/F7/L1 structural + L4/A9 RA-guard self-tests; A3 bcast-storm now sheds on any port role, A10 lateral Observe-only). **0 rows QEMU-only.** **3 rows still absent — each needs a stateful subsystem heqk lacks:** L5/L6 (a NAC onboarding-grace state machine) and A11 (a multi-signal corroboration engine) — off-device candidates per ADR 0044 D3. RA-guard (L4 legit / A9 rogue, RFC 6105) is frame inspection like ARP-spoof, so it was buildable now without the M4 stack. A1/A2/A9 closed via the per-port role table (`verdict::port_role_for`, manifest seam) that `classify()` now consults; a REAL Access *interface* on live traffic still awaits the manifest reader. The FULL 33 + Gate R is the release sign-off and is **not yet met**. Per-row evidence: `docs/design/heqk-detection-parity.md`.

### Phase M3 — Persistence & OTA — **os-architect / release-engineer**
- eMMC/SDHCI block driver → minimal filesystem → sealed/encrypted data volume (re-homing ADR 0007 off dm-crypt) → persistent evidence graph + QSecBit history + lifecycle-event log.
- On-device A/B update transport (no host PC): pull → inactive-slot verify (cosign policy + hybrid PQC) → slot flip → watchdog rollback. Fulfils ADR 0019 D3's "actionable rollback" natively.
- **Gate:** an OTA update installs to the inactive slot from a registry and a forced-bad boot rolls back; the evidence graph persists across reboot.

### Phase M4 — Control-plane connectivity — **os-architect / security-auditor**
- Userspace TCP/IP (smoltcp-class) as a heqk server over the ring + TLS (rustls-class over the `no_std` PQC crypto already present). DHCP client, DNS, NTP. Enables the MSSP link, update fetch, and the secure-edge transport envelope (ADR 0004) — kill-switch/PBR/NAT/TUN re-implemented on the native stack.
- **Gate:** heqk device enrolls to a control plane over hybrid-PQC TLS; standalone/air-gapped mode still fully functional with no account (core invariant preserved).

### Phase M5 — Module runtime & the brain on-device — **os-architect / code-developer**
- Process/loader ABI (ELF loader, root task, real syscall surface) replacing the 7 demo syscalls. A Wasm/WASI host (or `.cwasm` AOT path, ADR 0017) so the Wasm detection modules + the supervisor/reconciler run *on heqk* (not only in the guest).
- **Gate:** a signed Wasm detection module loads, verifies (ADR 0016), and fires into the persistent evidence graph on heqk.

### Phase M6 — App-tier overlay (Linux guest) & SOC UI — **os-architect / ux-architect**
- Stand up the monitored Linux guest VM (Zone 4) for heavy stateful services (HYDRA 11-service stack, api/planner/rbac tokio services) and containers (ADR 0041), under a hard capability-reserved slice (ADR 0035 D8, enforced by heqk cap-spaces not cgroups). Mission Control served from the guest or a hosted control node; capability-gated rendering keys off the (re-sourced) manifest — **invisible to the operator** (ADR 0035 D5).
- **Gate:** full SOC workspaces render live on a heqk-substrate CM5 with the app tier in the guest; the security plane's guaranteed floor holds under a greedy-workload test.

### Phase M7 — Unbuild & minimize — **retirement-agent / product-steward**
- Execute the retirement batches (§5). Delete the Debian base, stock+edge kernels, libbpf/glibc, dongle drivers, systemd/podman *from the rpi-native tier*. Mark ADRs 0029/0030/0032 obsolete on this tier.
- **Gate:** the rpi-native heqk image passes the standing minimization gate (ADR 0039 durable filter); measured size + attack-surface reduction reported by telemetry-analyst (§6).

**Parallel tracks (not gating the above):** heqk P10 D/E WiFi assoc/data; RTL8111 WAN datapath; capability-enforcement wiring + real IPC (heqk remediation R1) — R1 is a *prerequisite for M5's multi-server userspace* and should lead it.

---

## 4. Migration work → Cortex roster (who owns what)

| Persona | Ownership in this migration |
|---|---|
| **product-steward** | The epic; ADR 0043 supersession + ADR hygiene; BuildPlan truth; requirement↔ADR↔code↔gate traceability |
| **os-architect** | The kernel swap: boot chain, capability/IPC model, dataplane re-architecture, manifest continuity, Zone-4 VMM |
| **security-auditor** | The new TCB threat model; supply-chain of the heqk base; PQC continuity; capability-grant model; overlay isolation (D8) |
| **verification-engineer** | Gate ladder rebuilt on heqk (QEMU aarch64-virt → CM5 → Pi5/Pi4); the 0.7 separation matrix + Gate R must survive |
| **release-engineer** | New heqk build/flash pipeline; trust-store bake; **rollback parity** (A/B already metal-proven) |
| **retirement-agent** | The Linux teardown (§5) — batched `retirement` events, blast-radius, Amber |
| **telemetry-analyst** | Before/after benchmarks (boot time, detection latency, CPU headroom for on-device ML), `regressed_by` findings |
| **ideation-scout** | The "OS-is-the-sensor" requirement + CVE/attack-surface-reduction justification |
| **market-intelligence** | Positioning honesty — heqk is a sensor kernel today, not a shippable OS; no over-claim |
| **code-developer** | Implements approved kernel/HAL/driver/module-port work; benchmarks; never commits unapproved |
| **ux-architect** | Keeps the swap **invisible** to Mission Control — no operator-visible regression |

---

## 5. The unbuild — retirement batches (governed like a build, run in reverse)

Each is a batched `retirement` event: *what · why-it-looks-dead · evidence · confidence · blast-radius*. **Marked superseded, never deleted** until gates prove nothing broke on heqk. All **Amber**.

| Batch | Components | Blast radius | Fires after |
|---|---|---|---|
| **U1 — Kernel/boot** | stock Debian kernel, RPi edge kernel (ADR 0032), initramfs, dm-verity hooks, BTF/`pahole` tooling, ADR 0029/0030 fat-boot machinery | High (boot) | M1 green |
| **U2 — Dataplane** | libbpf/CO-RE loaders, XDP/TC `.bpf.c` build, `bpftool`/`clang` CI stages, OVS, nftables/conntrack apply | High (detect/enforce) | M2 Gate 0.7 + Gate R green — **NOT yet unlocked (2026-09-08: 30/33 matrix rows metal-proven; the final 3 need a stateful subsystem (NAC/corroboration); full 33 + Gate R required)** |
| **U3 — Storage/hardening** | dm-crypt/LUKS, initramfs unlock, journald, sysctl/kargs/KSPP knobs, systemd sandboxing boilerplate | Medium | M3 green |
| **U4 — WiFi dongles** | 7 out-of-tree Realtek drivers + hostapd stack (this tier) | Medium (feature drop) | M2/parallel WiFi green |
| **U5 — Lifecycle fabric** | 42 systemd units, ~6.5k lines bash glue, greenboot, bootc/OCI/composefs, Podman (paper coupling) | Medium | M5/M6 green |
| **U6 — Base image** | the entire Debian `base/Containerfile` + mkosi/bootc-image-builder machinery (rpi-native tier) | High (image) | M6 green |

---

## 6. End-to-end flow validation (every flow, status + gap + gate)

Legend: ✅ works on heqk metal · 🟡 partial · ⬜ absent (build) · N/A tier-excluded.

| Flow | Linux (today) | heqk status | Gap to close | Validation gate |
|---|---|---|---|---|
| **Boot → EL1 kernel** | mkosi image, `config.txt`→`kernel8.img`, initramfs | ✅ `hboot`→heqk, attested, hybrid-PQC-signed, EL2 stage-2 | — | M1: CM5 boots to inline-IPS in <target> s |
| **Secure/measured boot + attestation** | UKI/Secure-Boot, dm-verity, PCR | ✅ OTP-rooted AK, PCR chain, anti-rollback (arguably ahead of Linux) | first-stage TOFU; TPM-2.0 vs custom protocol | M1: measured-boot report verifies; M4: remote attest over TLS |
| **Rollback** | greenboot → bootc/A-B image-sync | ✅ A/B `heqk8.img`/`-b` + watchdog tryboot | on-device (vs host-PC) staging | M1: forced-bad-boot reverts; M3: OTA-driven |
| **Packet capture → detect** | AF_XDP/XDP/TC + CO-RE | ✅ GEM→zero-copy ring→RFC 9669 verifier/JIT | conntrack-equiv flow state; broader rule catalogue | M2: P8 rule-parity on shared corpus |
| **Enforce (tri-state, legit-always-passes)** | `decide()`/TC-bpf/nft, PSI shed | 🟡 **tri-state `decide()` live on CM5 metal; 30/33 matrix rows PROVEN-ON-METAL** (zero legit-drops); 0 QEMU-only, 3 scoped-absent (NAC L5/L6 + corroboration A11) | full 33-row matrix (real Access interface for A1 via manifest reader; NAC/RA-guard/corroboration for L4-6/A9/A11 need M4) | **M2: heqk matrix (33) + Gate R on metal — 30/33 done, not sign-off** |
| **Persist evidence / QSecBit history** | SQLite on `/var/lib/hookprobe` | ⬜ no storage; events only hit serial console | block driver + FS + sealed volume | M3: graph survives reboot |
| **DNS sinkhole / RPZ** | dnsmasq/systemd-resolved + RPZ | ⬜ no resolver/net stack | resolver over M4 net stack | M4: "refuse a NAME, never a PACKET" holds |
| **WiFi AP + WIDS** | brcmfmac + hostapd + nl80211 monitor | 🟡 scan only; no assoc/data/monitor | heqk P10 D/E + AP-control + monitor surface | Parallel: AP serves clients; ADR 0042 detectors fire |
| **WAN uplink** | RTL/cellular + PBR/NAT/TUN kill-switch | 🟡 RTL8111 link trained, datapath pending | RTL datapath + ADR 0004 envelope on native stack | M4: WAN up, kill-switch fails closed |
| **OTA update** | registry pull → bootc/image-sync | 🟡 A/B proven but needs host PC | M4 net stack + M3 storage | M3: registry OTA + rollback, no host PC |
| **Provisioning / zero-touch** | captive portal → reconciler → nft/hostapd | ⬜ needs net + FS + apply backend | re-target `reconcile_network` to heqk dataplane | M4/M5: intent→staged-diff→apply on heqk |
| **MSSP / control-plane link** | tokio/axum/rustls hybrid-PQC TLS | ⬜ no TCP/TLS | M4 net stack + TLS | M4: enroll over PQC-TLS; standalone still works |
| **SOC UI (Mission Control)** | Astro/Solid + Axum/SSE | ⬜ on heqk; runs in guest/host | Zone-4 guest or hosted control node | M6: live workspaces, swap invisible |
| **Heavy services / containers** | rootless Podman/Quadlet, HYDRA stack | ⬜ (deliberately) → Linux guest | Zone-4 monitored VMM + cap-reserved slice | M6: app tier in guest under guaranteed floor |
| **On-device ML inference** | WASI-NN (`cpu`/`npu`) — vapor today | ⬜ (no real users) | defer; CPU headroom freed by minimization | Post-M7: revisit if a real model ships |

**Reading of the matrix:** the *security underlay* (boot → capture → detect → enforce) is where heqk is strongest and closest to parity — that is the correct beachhead. The *stateful/connected/experience* half (persist → connect → UI → overlay) is the real build, sequenced M3–M6, with the app tier honestly kept in a Linux guest.

---

## 7. Size reduction (the "reduce size" mandate)

ADR 0035's byte-for-byte measurement of the current Pi image: **~89% Debian, ~4% HookProbe code, ~40% provable dead weight** (a 328 MB never-booted stock kernel + ~110 MB firmware for absent radios). Under heqk the rpi-native image becomes **kernel (ours, ~33k LOC Rust) + this-hardware firmware (CYW43455 blob) + static-Rust binaries + Wasm modules + BPF rules** — no apt/dpkg, no perl/python, no general coreutils, no second kernel, no shell, no SSH. This is ADR 0035 D6's Talos-radical end-state reached *structurally*, and per ADR 0035 D4 **the size win is a security win** — every package not shipped is a CVE that cannot apply and an exploit primitive that is absent. `telemetry-analyst` reports the measured before/after at M7 (target: order-of-magnitude image shrink on the rpi-native tier; freed CPU/RAM quantified for the edge-ML mission).

---

## 8. Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| heqk verifier bug = sandbox escape | High | v1 = signed first-party rules only (no open verifier); independent capability wall; machine-checked reduced-width soundness harness |
| No per-device IOMMU on BCM2712; Spectre unmitigated | High | **single-tenant edge doctrine** — no untrusted multi-tenant VMs on this tier; ceiling-containment + cap-checked DMA descriptors |
| Storage/net-stack/loader are large unbuilt items | High | Sequenced M3–M5, each independently gated; app tier stays in Linux guest until ready |
| Over-claiming heqk readiness | Medium | market-intelligence gate; honesty tags in ADR 0043; "sensor kernel, not OS yet" |
| Regressing the shipping M1 Linux image | Medium | heqk is a parallel tier; Linux rpi-native keeps shipping; promotion only on P8 + Gate 0.7 + Gate R |
| WiFi feature regression (drop 7 dongles) | Medium | scope to the one heqk-supported radio on this tier; dongles remain on Linux tiers |
| Single-core invariant (all lock-free structures) | Medium | documented hard invariant; SMP is a post-migration research phase (heqk P11+) |

---

## 9. What lands in `docs/BuildPlan.md`

A new **Track C — heqk substrate (rpi-native)** parallel to Track B, with phases M0–M7 and their gates, plus the U1–U6 retirement batches and the §6 flow-validation matrix as the acceptance ledger. Track B (Linux) continues unchanged for the UEFI/amd64 tiers and as the shipping rpi-native image until Track C promotes. Neither track gates the other (ADR 0035 D5).
