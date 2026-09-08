# heqk unbuild — Track C Milestone M7: plan, measurement, and metal gating

**Status:** 🟡 Proposed (2026-07-30) — a `retirement-agent` deliverable. **Green** work only (scanning,
measurement, drafting the retirement batches); every actual deletion below is **Amber** (product-steward
triages, operator approves) and additionally **metal-gated** — no batch may execute before its heqk
replacement passes on CM5 metal (ADR 0044 D4/D5, ADR 0043). **Nothing in this document has been executed.**
No code was changed, nothing was deleted, nothing was committed.
**Author:** retirement-agent. **Relates to:** [ADR 0039](../adr/0039-system-minimization-image-cleaning.md)
(the minimization gate this batch feeds), [ADR 0043](../adr/0043-heqk-microkernel-substrate.md) /
[ADR 0044](../adr/0044-zero-linux-rpi-native-cm5.md) (the substrate/app-host replacement), ADR 0029/0030/0032
(the rpi-native Linux-kernel decisions being superseded), `docs/MIGRATION-heqk.md` §5/§6 (the source U1–U6
batches this refines), `docs/BuildPlan.md` Track C (the M0–M7 phase ledger and C-unbuild table).

---

## 0. Honesty floor (ADR 0044 D5) — read this before reading anything else

**M7 execution is metal-gated.** As of 2026-07-30, `docs/BuildPlan.md` Track C shows M1–M4 QEMU-green
(M1 additionally CI-green + signing-beachhead-validated; M2–M4 QEMU-green 2026-07-28/29), M5 only
~15–20% scaffolded (R1 IPC + ELF loader QEMU-green; the production Wasm/WASI host and detection-parity-on-metal
are still multi-year work), and M6 is `[vision]` — unstarted. **Zero Track-C phases have passed their metal
gate yet** (M1's metal acceptance — `:53` pass / `:4444` drop / forced-bad-boot rollback on CM5 — is still
an operator action, marked ⬜ in the BuildPlan). Consequently:

- **No U-batch below is ready to fire today.** This document is the plan + the measurement, not the unbuild.
- **The Linux M1 image keeps shipping on rpi-native** until each heqk component it depends on passes its
  metal gate, component by component (ADR 0044 D4 ordering, ADR 0043's reversibility promise).
- Every batch is tagged with its **current readiness** (QEMU-green / metal-pending / not-yet-built) so
  product-steward can see exactly how far each is from being fireable — none are fireable now.
- This document does not modify `docs/MIGRATION-heqk.md` or `docs/BuildPlan.md`; it is offered as the
  companion detail doc those two already point to (BuildPlan Track C cites `docs/MIGRATION-heqk.md` §5 as
  the U1–U6 source; this doc is the retirement-agent's grounded expansion of that table, cross-linked, not a
  replacement).

---

## 1. The U1–U6 unbuild plan — component → heqk replacement → metal gate

Each row: **what ships on rpi-native Linux today** → **which heqk M-phase is its replacement** →
**the specific metal-proof required before deletion is even proposable for execution** → **current status**
(against `docs/BuildPlan.md` Track C, 2026-07-30) → **confidence this component is correctly identified as
retirement-eligible once gated** (this is a confidence in the *mapping*, not a green light to delete).

### U1 — Kernel/boot

| | |
|---|---|
| **What** | Stock Debian kernel meta-package (`linux-image-arm64`, never boots — ballast); the self-built RPi edge kernel + BTF (`kernel8.img`/`kernel_2712.img`, ADR 0032); initramfs + dm-verity hooks; BTF/`pahole` tooling; the ADR 0029/0030 fat-boot dual-kernel/DTB-union machinery |
| **heqk replacement** | M1 — heqk substrate beachhead: `hboot` → `heqk8.img` boots CM5 directly via `config.txt kernel=heqk8.img`, attested + hybrid-PQC-signed, A/B tryboot |
| **Metal gate required** | M1's testable gate: CM5 boots heqk, forwards a legit `:53` flow, drops a `:4444` scan, survives a forced-bad-boot rollback — **all on metal** |
| **Status (2026-07-30)** | 🟡 QEMU-green + CI-green (`build-heqk.yml`, 35/35 `validate.sh` phases) + signing beachhead validated; **metal acceptance ⬜ (operator action, not yet run)** |
| **Evidence** | `kernel/heqk/cm5-boot/heqk8.img` (3,051,896 bytes, built 2026-07-28) present on disk; `kernel/heqk/validate.sh` PHASES array defines the QEMU gate; `docs/BuildPlan.md` M1 row |
| **Blast radius** | High — this is the boot path itself; nothing else on the device works if this regresses |
| **Confidence (mapping)** | High — heqk8.img is a documented drop-in replacement for `kernel8.img`/`kernel_2712.img` in `config.txt`, already proven to boot in QEMU and single-run metal |
| **Fires after** | M1 green **on metal** (unchanged from `MIGRATION-heqk.md`/BuildPlan) |

### U2 — Dataplane

| | |
|---|---|
| **What** | libbpf/CO-RE loaders, XDP/TC `.bpf.c` build stages, `bpftool`/`clang` CI stages, OVS, nftables/conntrack apply logic |
| **heqk replacement** | M2 — Detection parity: detection catalogue ported to RFC 9669 bytecode (ADR 0043 D2, *not* Linux eBPF), tri-state `decide()`/`decide_l2` |
| **Metal gate required** | **Release-blocking**: the 0.7 enforcement-separation matrix (33 rows, legit-passes + attacks-caught, both directions) **and** Gate R (adversarial resilience) pass **on heqk metal**; verdicts match Linux rule-for-rule on the shared corpus |
| **Status (2026-09-08)** | 🟡 QEMU-green (M2.0–M2.4). **Gate-R METAL PARTIAL: 24/33 rows PROVEN-ON-METAL on CM5** (all frame-drivable + the A7/A8/L9 resource-shed self-test + the A1/A2 port-role self-test, zero legit-drops). **9 rows still open: 4 QEMU-only/metal-not-drivable** (L1/L2 topology, F4/F7 host runt-padding/MTU) + **5 scoped-absent** (L4/L5/L6 NAC+RA-guard, A9 rogue-RA, A11 multi-signal corroboration). A1/A2 closed via the per-port role table (`verdict::port_role_for`, manifest seam) `classify()` consults; a real Access interface on live traffic awaits the manifest reader. **U2 stays gated — the FULL 33 + Gate R is the sign-off, not yet met.** Detail: `docs/design/heqk-detection-parity.md` |
| **Evidence** | `docs/BuildPlan.md` M2 row; `docs/design/heqk-detection-parity.md`; ADR 0023 (requires the matrix on heqk metal, not QEMU, for release sign-off) |
| **Blast radius** | High — this is the detect/enforce core; a regression here silently reopens the "legit customer always passes" invariant |
| **Confidence (mapping)** | Medium-High — the QEMU semantics match, but "QEMU-green ≠ sign-off" is stated explicitly in BuildPlan; do not read QEMU-green as metal-equivalent |
| **Fires after** | M2 Gate 0.7 + Gate R green **on metal** (unchanged) |

### U3 — Storage/hardening

| | |
|---|---|
| **What** | dm-crypt/LUKS, initramfs unlock, journald, sysctl/kargs/KSPP hardening knobs, systemd sandboxing boilerplate |
| **heqk replacement** | M3 — Persistence & OTA: eMMC/SDHCI block driver → minimal FS → sealed/encrypted data volume (re-homes ADR 0007 off dm-crypt); on-device A/B OTA |
| **Metal gate required** | OTA installs to inactive slot from a registry + forced-bad boot rolls back; **the evidence graph persists across reboot on real hardware** |
| **Status (2026-07-30)** | 🟡 QEMU-green (M3.1–M3.4, 2026-07-29): file-backed virtio-blk behind `hal::BlockDev`, crash-safe log-structured store, sealed data volume (HQKSEAL1), A/B OTA state machine — **~70–75% QEMU-green over the block trait**. **Gate-R METAL ⬜: real eMMC write driver on `brcm,bcm2712-sdhci`, firmware tryboot flip, PM-watchdog + power-cycle persistence, OTP-bound SRK not yet run** |
| **Evidence** | `docs/BuildPlan.md` M3 row; `docs/design/heqk-persistence.md`; note the doc's own caveat that the eMMC write driver is `cfg(cm5)`-gated and *not* exercised by the QEMU harness |
| **Blast radius** | Medium — loses the evidence graph / QSecBit history durability if regressed, but does not break boot or detect/enforce |
| **Confidence (mapping)** | Medium — the write path is proven only against a file-backed block device today; the real eMMC driver is the load-bearing unproven piece |
| **Fires after** | M3 green **on metal** (unchanged) |

### U4 — Wi-Fi dongles

| | |
|---|---|
| **What** | 7 out-of-tree Realtek USB Wi-Fi drivers (`rtl8812au`, `rtl8821cu`, `rtl8821au`, `rtl88x2bu`, `rtl8852au`, `rtl8188eu`, `rtl8192eu`) + the hostapd stack, on this tier |
| **heqk replacement** | Parallel track — heqk P10 D/E Wi-Fi AP assoc/WPA2/EAPOL/data on the on-board CYW43455 (the SASE-edge default) |
| **Metal gate required** | AP serves clients over CYW43455 assoc/data; ADR 0042 WIDS detectors fire — on metal |
| **Status (2026-07-30)** | 🟡 partial — CYW43455 scan/control only; **no assoc/data yet** (`docs/BuildPlan.md` "Parallel tracks" line). This is explicitly a **capability drop, not a like-for-like replacement**: the 7 USB dongles support *additional/aftermarket* radios; the heqk replacement targets only the *on-board* CYW43455 |
| **Evidence** | `base/drivers/SOURCES.md` (7 pinned driver repos, ~228 MB of vendored source trees under `base/drivers/rtl*`); `docs/BuildPlan.md` "Parallel tracks" note on heqk P10 D/E |
| **Blast radius** | Medium — feature drop, not a security regression; any device relying on a USB dongle for its AP or as a monitor-mode radio loses that specific hardware option on the CM5/heqk tier only (Linux tiers keep the dongles) |
| **Confidence (mapping)** | High that the dongles are dead-weight-on-heqk **once decided as out-of-scope**, but this is a **product decision, not a technical retirement** — flag to product-steward: U4 is a *scope* call (drop USB Wi-Fi expansion on CM5-heqk) as much as a *technical* unbuild. Recommend explicit product-steward sign-off distinct from the other five batches |
| **Fires after** | M2 / parallel Wi-Fi green **on metal**, and an explicit product decision that USB-dongle AP support is out-of-scope for the heqk tier |

### U5 — Lifecycle fabric

| | |
|---|---|
| **What** | 42 systemd units (`base/units/*.service`/`.timer`/`.socket`/`.slice`/`.mount`), ~6.5k lines of bash glue (of the ~24.5k total lines across `base/`+`builder/`, of which this tier's slice is a subset — see §2), greenboot, bootc/OCI/composefs, Podman/Quadlet |
| **heqk replacement** | M5 — Module runtime & the brain on-device (loader/syscall/Wasm-WASI host) + M6 — App tier native-or-hosted |
| **Metal gate required** | A signed Wasm detection module loads, verifies (ADR 0016), and fires into the persistent evidence graph **on heqk metal** (M5); full SOC workspaces render live with the app tier native-or-hosted and the security floor holding under a greedy-workload test (M6) |
| **Status (2026-07-30)** | 🟡 M5 substrate keystones QEMU-green only (M5.0 IPC beachhead, M5.1 ELF loader — both landed 2026-07-29); **M5.2 production Wasm/WASI host and M5.3 signed-catalogue-at-parity are ⬜, explicitly flagged multi-year**. M6 is ⬜ `[vision]`, unstarted | 
| **Evidence** | `docs/BuildPlan.md` M5/M6 rows ("Only ~15–20% of M5 is QEMU-scaffoldable... the rest is genuine multi-year build + metal"); `docs/design/heqk-module-runtime.md` |
| **Blast radius** | Medium-High — this is the module runtime + lifecycle glue; Podman is noted as "paper coupling" (no `.container` files, no loader exists) so that specific sub-piece is *already* dead code today, independent of heqk (see §1a below) |
| **Confidence (mapping)** | Low-Medium for the *timing* — this is the batch furthest from its metal gate; the Podman-is-paper-coupling sub-finding is high-confidence today, independently of M5/M6 |
| **Fires after** | M5/M6 green **on metal** (unchanged; currently the least-ready gate in the whole ladder) |

### U6 — Base image

| | |
|---|---|
| **What** | The entire Debian `base/Containerfile` (851 lines / 56,590 bytes, ~32 `apt-get install` blocks) + mkosi/bootc-image-builder machinery, rpi-native tier only |
| **heqk replacement** | M6 — App tier & SOC UI, the terminal Track-C phase before M7 |
| **Metal gate required** | Full SOC workspaces render live against a heqk-substrate CM5 (app tier native-or-hosted, zero on-device Linux); security floor holds under a greedy-workload test |
| **Status (2026-07-30)** | ⬜ M6 unstarted (`[vision]`) |
| **Evidence** | `docs/BuildPlan.md` M6 row; ADR 0044 D3 (B1/B2 sub-fork still open) |
| **Blast radius** | High (image) — this is the whole rpi-native Linux image; nothing in U1–U5 should be deleted piecemeal ahead of U6, and U6 itself cannot fire until U1–U5's dependents are all gone |
| **Confidence (mapping)** | High that this is the correct terminal batch (it is definitionally "delete what's left"), zero readiness today |
| **Fires after** | M6 green **on metal** (unchanged; the last domino) |

**§1a — one sub-finding surfaced while grounding this table (Green, not part of U-batch timing):**
`docs/MIGRATION-heqk.md` §2 states *"Podman/Quadlet is paper coupling (no `.container` files, no loader
exists)"* for the rpi-native tier. If that is still true today, the Podman/Quadlet piece of U5 is not
merely *heqk-superseded-later* — it may already be **unused on this tier independent of heqk** and worth a
separate, non-metal-gated retirement candidate for product-steward to triage now (grep the current
`base/Containerfile`/`base/units` for any `.container`/Quadlet unit; if none exist, this is a same-day
"remove the paper coupling" candidate, distinct from and *not blocked by* the U5 metal gate). Flagging only
— not actioned here, and not verified against today's Containerfile in this pass (would need a dedicated
grep sweep; noted as a follow-up for a focused dead-code scan, not folded into this metal-gated table since
its blast radius and gate are different in kind).

---

## 2. The minimization measurement

**Legend:** **[measured]** = counted on this disk, this session, 2026-07-30. **[cited]** = pulled from an
existing ADR/doc's own prior measurement (dated, not re-verified today unless noted). **[estimate]** =
honest order-of-magnitude reasoning, explicitly not a byte-count.

### 2.1 heqk footprint — measured today

| Artifact | Size | Note |
|---|---|---|
| `kernel/heqk/cm5-boot/heqk8.img` (production, signed) | **3,051,896 bytes ≈ 2.9 MiB** [measured] | Built 2026-07-28; the whole bootable kernel image for CM5 |
| `kernel/heqk/cm5-boot/heqk8-b.img` (A/B slot B) | 3,024,728 bytes ≈ 2.9 MiB [measured] | Same order — A/B doubles to ~6 MiB total for both slots |
| `kernel/heqk/cm5-boot/hboot8-demo.img` | 2,194,864 bytes ≈ 2.1 MiB [measured] | Boot-signing stage-1 loader (demo variant) |
| EL0 Wasm-host ELF (`el0_wasmhost.elf`, release) | **430,432 bytes ≈ 420 KiB** [measured] | The M5.2 detached EL0 binary that will host wasmi 0.32 for signed `.wasm` module execution — the kernel only `include_bytes!`s this, keeping wasmi's `.text` **out of the kernel TCB**. `el0-wasmhost/Cargo.toml`'s own comment estimates wasmi's `.text` at **~326 KiB**; the 420 KiB figure is the *whole compiled ELF* (includes non-wasmi glue/runtime), so both numbers are honest and consistent |
| heqk source (all `*.rs`, excluding `target/` and worktree checkouts) | **34,151 LOC** [measured] | `kernel/`, `hal/`, `arch-aarch64/`, `abi/`, `boot-abi/`, `firmware/`, `el0-wasmhost/`, `tools/` combined |
| heqk kernel-crate transitive dependency closure | **52 crates** [measured] (`kernel/heqk/Cargo.lock`) | Mostly `no_std`, several feature-gated OFF by default (smoltcp, ml-kem, x25519-dalek, chacha20poly1305 are all `optional = true`, so the *default* TCB pulls in fewer than 52) |
| el0-wasmhost dependency closure | 28 crates [measured] (`el0-wasmhost/Cargo.lock`) | Detached workspace — never enters the kernel's own build graph or `Cargo.lock` |

**Reading:** the entire bootable heqk substrate — kernel + both A/B image slots + the boot-signing stage — is
**single-digit megabytes on disk**, built from **~34k LOC of Rust** with a **52-crate** transitive dependency
closure (many of those gated off by default). This is the *whole substrate*: boot, TCB, dataplane skeleton,
persistence skeleton, control-plane skeleton, module-runtime skeleton — not a subset.

### 2.2 Linux rpi-native footprint — measured / cited

| Component | Size | Source |
|---|---|---|
| Built debug Pi image, actual bytes (`hookprobe-os-pi-debug-v8.img`, sparse 8 GB file) | **1.3 GB actual** [measured, 2026-07-30] | Confirms ADR 0039's own 2026-07-16 byte-for-byte `debugfs rdump` measurement of ~1.3 GB — same order today |
| — of which Debian | ~89% [cited, ADR 0039] | Not re-verified byte-for-byte this session; consistent with the file existing at ~1.3 GB with a ~40 MB HookProbe payload noted below |
| — of which HookProbe's own code | ~4% (≈40 MB) [cited, ADR 0039] | |
| — of which provable dead weight (never-booted stock kernel + unused-radio firmware) | ~40% (~438 MB: 328 MB stock kernel + 110 MB firmware) [cited, ADR 0039] | This dead weight is orthogonal to heqk — ADR 0039 D1/D2 already propose removing it from the *Linux* image regardless of the heqk migration |
| Self-built edge kernel image (`kernel8.img`/`kernel_2712.img`, ADR 0032) | 32 MB each [measured] | `kernel/heqk/cm5-boot/linux-boot-backup/*.img` — the two boot-partition kernel binaries actually consumed at boot (distinct from the 328 MB never-booted `linux-image-arm64` meta-package) |
| Edge kernel `.ko` modules | 1,910–1,911 modules per flavour [cited, `base/drivers/SOURCES.md`] | |
| Edge kernel `.BTF` section | 5,105,845 bytes ≈ 4.9 MiB, per flavour [cited] | Exists solely to make Linux eBPF CO-RE loading work — has no heqk analogue need (RFC 9669 BPF needs no BTF) |
| `base/Containerfile` | 851 lines / 56,590 bytes [measured], ~32 `apt-get install`/`RUN`-family install blocks [measured] | |
| Approx. distinct package tokens referenced across install blocks | ~377 distinct tokens [measured, rough `awk`/`sort -u` sweep — an approximation, not a definitive package count, since it token-matches package-name-shaped strings inside RUN blocks] | Order-of-magnitude signal only |
| systemd units (`.service`/`.timer`/`.socket`/`.slice`/`.mount`) | **42** [measured] | Matches the "42 systemd units" figure already cited in `MIGRATION-heqk.md`/BuildPlan |
| Bash glue across `base/`+`builder/` | 24,468 lines [measured] | This is the *whole* base+builder tree (all platforms, not rpi-native-only); the "~6.5k lines" figure in `MIGRATION-heqk.md` is a narrower rpi-native-specific estimate from that doc's own prior audit and was not independently re-decomposed in this pass — flagged as an estimate to refine, not re-derived here |
| 7 out-of-tree Realtek Wi-Fi driver source trees | **228 MB** vendored source [measured, `base/drivers/rtl*`] | This is *source-tree* size (repo footprint / build-time attack surface), not the much smaller compiled `.ko` size that actually ships in the image — flagged as such to avoid conflating build-time and runtime footprint |
| CYW43455 firmware (the one radio heqk keeps) | 20 KB [measured, `base/drivers/brcm-firmware-rpt`] | For scale: this is the *only* radio firmware heqk's replacement needs; the 228 MB of Realtek dongle source trees is orthogonal to the on-board radio |

### 2.3 The reduction, stated honestly

- **Bootable-substrate size:** heqk's whole kernel image (`heqk8.img`) is **~2.9 MiB**, vs. the Linux
  rpi-native image's **~1.3 GB actual on-disk footprint** — roughly a **~450×** reduction at the
  whole-image level. This is the headline number, but it compares *the entire current Linux appliance
  image* (OS + services + drivers + firmware + HookProbe payload) against *only the heqk kernel binary* —
  not yet an apples-to-apples "full working SOC" comparison, because M3–M6 (storage, control-plane,
  module runtime, app tier) are not yet built/shipped inside `heqk8.img`. **The honest framing is
  structural, not final:** heqk's *architecture* (kernel + this-hardware firmware + static Rust binaries +
  Wasm modules + BPF rules, no apt/dpkg/perl/python/coreutils/shell/SSH/second-kernel) is the ADR 0035 D6
  Talos-radical end-state reached *by construction*, and every M-phase that lands adds bytes to `heqk8.img`
  while Linux's ~1.3 GB stays roughly flat or grows. The gap will compress as M3–M6 land but will very
  plausibly remain **one to two orders of magnitude**, because the components being dropped (Debian
  userland, `apt`/`dpkg`, `systemd`, general-purpose shells/coreutils, a second never-booted kernel, 6
  unused-radio firmware blobs) are categorically absent from heqk's design, not merely trimmed.
- **Dependency-closure / build-time attack surface:** heqk's transitive Rust dependency closure is
  **52 crates** (kernel) + **28 crates** (detached EL0 Wasm host, never entering the kernel's build graph),
  vs. the Linux image's **~377 distinct package-name tokens** referenced in `apt-get install` blocks alone
  (a rough sweep, not a resolved transitive-dependency count — Debian's actual transitive closure including
  library dependencies of those ~377 packages would be substantially larger again). Order of magnitude: a
  **single-digit-vs-triple-digit** dependency-surface reduction, even before counting Debian's own
  transitive `Depends:` chains.
- **CVE-attack-surface reasoning (ADR 0035 D4's "size win is a security win," reapplied here):** every
  package heqk does not ship is a CVE that cannot apply against this device. The 328 MB never-booted stock
  kernel, the 1,910 `.ko` modules per edge-kernel flavour, the 110 MB of firmware for radios the board does
  not have, `apt`/`dpkg`, and the general-purpose coreutils/shell/SSH surface are each an open-ended stream
  of future CVEs against code that literally does not run (the stock kernel) or is not present in the
  device's actual hardware set (foreign-radio firmware). heqk structurally cannot accumulate this class of
  CVE because the code is not there to begin with — this is the same D4 argument ADR 0039 already made for
  the Debian-trim, now made structurally rather than by subtraction.
- **What this measurement does NOT yet show:** heqk does not yet have a working equivalent of persistent
  storage (M3 metal-pending), a control-plane network stack (M4 metal-pending, QEMU-green), a production
  Wasm/WASI module host (M5, ~15–20% built), or an app tier (M6, unstarted). The size comparison above is
  therefore a **substrate-to-substrate** comparison, honestly labelled — it is not yet a
  full-working-SOC-to-full-working-SOC comparison, because the heqk side of that comparison does not exist
  on metal yet. `telemetry-analyst` should re-run this measurement at each M-phase's metal gate and again at
  M7, per `docs/BuildPlan.md`'s own instruction ("measured size + attack-surface reduction reported").

---

## 3. The ADR 0039 minimization gate for the rpi-native heqk image

ADR 0039 D4 already states the durable filter: *"A component earns its place only if it is on the
boot → detect → enforce → report critical path, OR it is a capability the Platform Manifest grants on this
hardware. Everything else is noise."* ADR 0039's own heqk-migration footer (bottom of that ADR) already
records: *"the durable 'only what we need' standing gate transfers, and heqk achieves this ADR's goal
structurally... → Phase M7."* This document **confirms and operationalizes** that transfer rather than
re-deciding it:

**Standing gate definition, rpi-native/heqk (proposed, for product-steward + verification-engineer to
formally adopt at M7):**

1. **Budget:** the rpi-native heqk image (`heqk8.img` + whatever M3–M6 add to on-device storage) carries an
   explicit size/attack-surface budget it must stay under, re-baselined at each M-phase metal gate. Given
   §2.3's structural argument, a reasonable first budget ceiling is **low tens of MB** for the whole
   on-device artifact set (kernel + signed module catalogue + firmware) — to be set precisely once M3–M5
   land real numbers, not asserted here as final.
2. **Gate mechanic (reuses ADR 0039 D4's filter verbatim):** a build-time check (verification-engineer,
   alongside the existing `validate.sh` gate ladder) flags any newly-added component that is not on the
   boot → detect → enforce → report critical path and not a manifest-granted capability on CM5, before it
   merges. This is the same discipline ADR 0039 D4 established for the Debian image, ported to the heqk
   build.
3. **No re-bloat invariant:** because heqk has no package manager and no general-purpose userland, the
   *class* of re-bloat ADR 0039 guarded against (an apt dependency dragging in a second kernel or foreign
   firmware) is structurally harder to reintroduce — but the gate still applies to what heqk *can* re-bloat
   with: an unnecessary crate dependency, a signed module that duplicates detection coverage, an
   over-broad capability grant. `security-auditor` co-owns this angle (a broad capability grant is both a
   size and a TCB concern).
4. **Sign-off:** M7's own BuildPlan gate is *"the rpi-native heqk image passes the standing minimization
   gate (ADR 0039); measured size + attack-surface reduction reported (telemetry-analyst)"* — this document
   proposes that ADR 0039 be updated (by product-steward, Amber) with a short "D5 — rpi-native/heqk
   standing gate" clause formalizing items 1–3 above, so M7 has a written gate to point at rather than an
   inferred one. **Proposal only — ADR 0039 is not edited by this document.**

---

## 4. ADR 0029 / 0030 / 0032 supersession-marker confirmation

All three ADRs already carry the rpi-native supersession footer from the earlier Phase-0 alignment work —
**verified present today, unchanged, nothing further needed from this pass:**

- **ADR 0029** (`docs/adr/0029-unified-pi-fatboot-dual-kernel.md:180-182`): *"Coupling: OBSOLETE
  (rpi-native tier). Superseded by ADR 0043: the dual-RPi-kernel fat-boot, DTBs, `config.txt` kernel
  selection, unioned initrds, and shipped BTF blob have no place when heqk is the kernel. Marked
  superseded, not deleted. → Phase M1/M7 (retirement batch U1)."*
- **ADR 0030** (`docs/adr/0030-single-kernel-convergence-bridge.md:96-98`): *"Coupling: OBSOLETE
  (rpi-native tier). Superseded by ADR 0043. The page-size gate, cpufreq/NVMe/IRQ tuning, and
  mainline-Debian-kernel exit criteria are moot when the kernel is heqk. Marked superseded, retained as
  history. → Phase M1/M7 (retirement batch U1)."*
- **ADR 0032** (`docs/adr/0032-custom-edge-kernel-btf-mainline-rp1.md:94-96`): *"Coupling: OBSOLETE
  (rpi-native tier). Superseded by ADR 0043. The BTF-enabled RPi kernel recompile existed solely to make
  Linux eBPF CO-RE work; heqk's RFC 9669 BPF plane needs none of it. Marked superseded, retained as
  history. → Phase M7 (retirement batch U2)."*

All three are correctly **marked, not deleted** (product-steward's ADR-hygiene rule, ADR 0011 D5) and all
three correctly point at the U-batch that will retire the code they governed (U1 for 0029/0030, U2 for
0032). No action needed here beyond this confirmation.

---

## 5. Summary for the operator / product-steward

| Batch | Component | heqk replacement (M-phase) | Metal gate | Status today | Fires after |
|---|---|---|---|---|---|
| U1 | Stock+edge kernel, initramfs, dm-verity, BTF/pahole, ADR 0029/0030 fat-boot | M1 | `:53` pass / `:4444` drop / rollback on CM5 metal | QEMU+CI-green; **metal ⬜** | M1 metal-green |
| U2 | libbpf/CO-RE, XDP/TC build, bpftool/clang CI, OVS, nftables/conntrack | M2 | 0.7 separation matrix + Gate R, both directions, **on metal** | 24/33 metal-proven; **9 rows ⬜ (4 QEMU-only/not-drivable + 5 scoped-absent)** — NOT unlocked | M2 Gate 0.7 + Gate R metal-green (full 33) |
| U3 | dm-crypt/LUKS, initramfs unlock, journald, sysctl/KSPP, systemd sandboxing | M3 | OTA + rollback + evidence-graph persistence **on real eMMC** | ~70-75% QEMU-green; **real eMMC driver ⬜** | M3 metal-green |
| U4 | 7 Realtek USB Wi-Fi drivers + hostapd (this tier) | Parallel (P10 D/E) | CYW43455 AP serves clients + ADR 0042 detectors fire, on metal | 🟡 scan/control only, no assoc/data | Wi-Fi green + explicit scope decision |
| U5 | 42 systemd units, ~6.5k LOC bash (rpi-native slice), greenboot, bootc/OCI/composefs, Podman | M5/M6 | Signed Wasm module fires on-device (M5); full SOC live, app-tier native-or-hosted (M6) | M5 ~15-20% QEMU-scaffolded; **M6 unstarted** | M5 + M6 metal-green (furthest from ready) |
| U6 | Entire `base/Containerfile` (851 lines) + mkosi/bootc-image-builder, rpi-native tier | M6 | Full SOC workspaces live on heqk-substrate CM5 | ⬜ M6 unstarted | M6 metal-green (terminal batch) |

**Measured/estimated reduction:** heqk's bootable substrate today is **~2.9 MiB** (`heqk8.img`) against
Linux rpi-native's **~1.3 GB actual image** — a **~450×** whole-image size reduction at the current
substrate-only stage, with a **52-crate** (kernel) / **28-crate** (EL0 Wasm host) dependency closure against
Linux's **~377-token** (rough) `apt-get install` surface. This is honestly a **substrate-vs-full-image**
comparison (heqk's storage/network/module-runtime/app-tier layers are not yet built), expected to narrow as
M3–M6 land but very plausibly remaining a one-to-two-order-of-magnitude reduction given the categorical
absence of apt/dpkg/systemd/general-purpose-userland/second-kernel/foreign-radio-firmware from heqk's
design. Every package not shipped is a CVE that cannot apply (ADR 0035 D4 / ADR 0039), and heqk achieves
ADR 0039's minimization goal **structurally**, per that ADR's own migration footer.

**ADR-hygiene confirmation:** ADR 0029, 0030, and 0032 all already carry correct, unchanged rpi-native
supersession markers pointing at their respective U-batches. No further marking action needed.

**Execution status:** **metal-gated, not executed.** No U-batch is ready to fire today (M1's metal
acceptance is the nearest, and it is still an outstanding operator action). The Linux M1 image continues
shipping on rpi-native. This document is the plan and the measurement only.
