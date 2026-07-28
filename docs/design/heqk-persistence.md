# heqk persistence & OTA — Track C / Milestone M3 scoping

> **Track-C honesty header.** heqk has **no post-boot storage today** (`docs/BuildPlan.md`
> M3: "no post-boot storage today"). What *does* exist is a **P15 keystore beachhead**:
> a `hal::BlockDev` trait, a metal-gated **read-only** eMMC driver, full DICE-style
> sealing crypto, and an MBR write-guard — all QEMU-green over a RAM disk, plus a
> host-PC A/B updater. None of it persists a byte across reboot on the device, and the
> **real eMMC *write* driver is metal-gated (Gate R) — unproven on silicon.** M3 is the
> build that turns the keystore beachhead into a durable data volume + on-device OTA.
> This doc scopes it; it changes no code. Companion to `docs/design/heqk-detection-parity.md`
> (M2) and `docs/design/heqk-signing-identity.md` (M1). Canon: `docs/BuildPlan.md` Track C
> M3, ADR 0007, ADR 0043/0044 D4, `kernel/heqk/SEALED_STORAGE.md`.

---

## 1. What heqk has today (the storage / FS / OTA surface)

The M3 substrate is **not** a blank sheet. The P15 ("sealed storage") beachhead already
landed a keystore-grade write path. Ground truth from the tree:

| Surface | File | State | QEMU / metal |
|---|---|---|---|
| **Block-device trait** | `kernel/heqk/hal/src/lib.rs` (`BlockDev`) | ✅ done — 512-B sectors; read always; `write_block` **defaults to `WriteRefused`** (write is opt-in per arch behind `p15-write`) | arch-agnostic |
| **eMMC driver (read)** | `kernel/heqk/arch-aarch64/src/emmc.rs` | ✅ read-only bring-up (CMD0/1/2/3/7/8/9/16/17); `cfg(feature="cm5")` | **metal-only** |
| **eMMC driver (write)** | same, `write_block_impl` (CMD24) behind `p15-write` | 🟡 **coded, NOT metal-validated** | **metal-only** |
| **SDHCI primitives** | `kernel/heqk/arch-aarch64/src/sdhci.rs` | ✅ transcribed from the metal-proven `cyw43.rs` SDHCI | metal-only |
| **Sealed store (guard + read/scan + write)** | `kernel/heqk/kernel/src/store.rs` (`SealedStore<D: BlockDev>`) | ✅ runtime MBR-derived `LbaGuard`; read/scan always; store behind `p15-write`, read-back verified; **two independent gates** | QEMU-green (RamDisk) |
| **Sealing crypto** | `kernel/heqk/kernel/src/seal.rs` (`HQKSEAL1`) | ✅ DICE-style KDF over `boot-abi` SHA-256; Encrypt-then-MAC; per-seal nonce; policy = device_id ∥ svn_floor ∥ PCR-mask; zeroize-on-drop | **QEMU-green (arch-agnostic)** |
| **QEMU block backend** | `RamDisk` in `kernel/heqk/kernel/src/main.rs` | ✅ implements `BlockDev`; write-hook **PANICs** on any out-of-window LBA | QEMU/host |
| **P15 selftest** | `p15_seal_selftest()` in `main.rs` | ✅ seal↔unseal round-trip, wrong-policy/tamper/device-mismatch refusals, guard accept/reject, write-window-escape | QEMU-gated |
| **A/B updater** | `kernel/heqk/cm5-boot/ab-update.sh` + `tryboot.txt`/`config.txt` | ✅ **host-PC** stage/commit/status over rpiboot | host-PC, not on-device |
| **Anti-rollback (SVN floor)** | `kernel/heqk/hboot/src/rollback.rs` | ✅ `effective_floor = max(compile, OTP-thermometer, fail-closed watermark)`; `svn` bound into the signed image; `SecureCounter` backend abstraction | metal (OTP) / logic QEMU |
| **Trial-boot watchdog** | `kernel/heqk/hboot/src/watchdog.rs` | ✅ BCM2712 PM watchdog; armed pre-launch, disarmed by the `hvc #1` EL2 gate; fires → full reset → firmware one-shot consumed → known-good slot | metal (real reset) |

### What this means honestly

**The write surface today is a 16 KiB keystore, not a data volume.** `SealedStore` writes
**only** the reserved window **LBA 2016..2047** — 32 sectors in sfdisk's 1 MiB alignment
gap, clear of the MBR (LBA 0) and butting against but never entering the first partition
(LBA 2048). `SEAL_MAX_BLOB = 4096` (8 sectors): it holds **one ~3.5 KiB sealed blob**.
That is exactly right for a **master/sealing key or an SVN sequence counter** — and exactly
wrong for an evidence graph. Nothing in the tree persists **detection events, the evidence
graph, or QSecBit history**: `events.rs` pushes 24-byte headers into an SPSC ring drained
to serial/SIEM (never disk); `telemetry.rs` keeps the QSecBit-lite score **in RAM only**.

**On-device OTA does not exist.** `ab-update.sh` is a **host-PC** script: it mounts the
FAT boot partition over rpiboot and copies `heqk8-b.img`. The device cannot rewrite its own
boot slot — the boot partition lives at LBA ≥ 2048, which the current guard **refuses by
design**. What the *device* already owns is the **fallback half** of A/B: the firmware
one-shot `tryboot` flag + hboot's EL2 trial watchdog + the SVN anti-rollback floor. M3 OTA
**rides on that machinery** (reuse, don't reinvent) and adds only the missing front half —
on-device *pull, inactive-slot write, verify, slot-flip*.

### What M3 OTA inherits from the existing hboot A/B + SVN

- **One-shot trial boot**: `reboot "0 tryboot"` → next boot uses `tryboot.txt` → SLOT B.
  Consumed on use, so any reset after a bad candidate lands on SLOT A (`ab-update.sh` header).
- **Automatic rollback**: `hboot/src/watchdog.rs` — candidate hangs/panics before the
  `hvc #1` confirm → PM watchdog full-resets → one-shot already spent → known-good slot.
  **No mutable persistent state required in hboot** for the safety property.
- **Anti-rollback**: `hboot/src/rollback.rs` — a validly-signed candidate whose `svn` is
  below `effective_floor()` is refused; `svn` is inside the signed message so it can't be
  edited past. Backend is pluggable (compile floor now; OTP thermometer / RPMB later).
- **Signature/verify path**: the M1 signing identity (`docs/design/heqk-signing-identity.md`)
  — hboot verifies Ed25519 + SLH-DSA-SHA2-128s over the image before launch.

M3's inactive-slot verify is **the existing hboot verify path, run on the candidate before
the slot flip** — same keys, same SVN floor, same refusal semantics. OTA adds transport +
staging + flip, not a second trust root.

---

## 2. The CM5 eMMC / SDHCI controller reality

Ground truth from `SEALED_STORAGE.md` (decoded from the CM5 device tree) and `emmc.rs`:

- The eMMC is a **second `brcm,bcm2712-sdhci`** at CPU-phys **`0x10_00FF_F000`** (cfg block
  `+0x400`), SPI 273, **8-bit**, `broken-cd`, **fixed 1.8 V VCCQ**.
- **`clk-emmc2` is shared with the WiFi (cyw43) host.** The driver may call
  `get_clock_rate` **only** — never `set_clock_rate` (it would retune the live WiFi host
  mid-operation) — and derives the SDCLK divisor from the read-back.
- Fixed 1.8 V ⇒ signalling voltage is a board property, not negotiated: stay in legacy
  timing, **never touch `HOST_CTRL2`**.
- The controller region is **already device-mapped** by stage-1/stage-2; no MMU work.
- **Brick-safety is structural**: the driver contains **no code path** that can emit
  CMD6/SWITCH, CMD38/ERASE, CMD42/LOCK or any RPMB/boot-area switch — one wrong `EXT_CSD`
  index (`BOOT_WP[173]`, `PARTITION_SETTING_COMPLETED[155]`) is an unrecoverable brick, so
  those commands simply do not exist in the driver. The sole write command is CMD24.

### Driver target vs QEMU-emulable — the hard line

| Layer | Emulable in QEMU? | Why |
|---|---|---|
| The **BCM2712 second-SDHCI eMMC driver** (`emmc.rs`/`sdhci.rs`) | **No — metal-only** | QEMU's `virt` machine has no `brcm,bcm2712-sdhci`; the `clk-emmc2`-shared-with-WiFi, `broken-cd`, 1.8 V, INT_ENABLE-latch quirks are exactly what QEMU does not model. Proving this is **Gate R (metal)**. |
| **`hal::BlockDev` (the trait)** | **Yes** | Arch-agnostic; `RamDisk` already implements it, `virtio-blk` can (heqk already has a `virtio-net` mmio driver — `arch-aarch64/src/virtio.rs`). |
| **Everything above the trait** — FS layout, sealed-volume crypto, OTA state machine, rollback logic, evidence store | **Yes** | All consume `BlockDev`, not the controller. QEMU-green over `RamDisk` (single-run) or `virtio-blk` (cross-restart). |

**The whole M3 value is designed around this line**: put the hardware on one side of
`BlockDev`, put every stateful/security-bearing decision on the other, and the second side
is CI-gateable in QEMU. The eMMC driver is the *only* metal-gated new code in M3.

---

## 3. Phased M3 plan

Each phase has a testable gate that slots into `kernel-validator/validate.sh` beside the
existing `P8-*` / `P15` gates. **A phase-0 design gate precedes them:** the current
write-safety model forbids all partition sectors — M3.2/M3.4 must **widen** the write
surface (a data partition + the inactive boot slot) **without** losing the two-independent-
gates brick-safety discipline. That widening is a design deliverable, not a wiring task.

### M3.0 — widened write-safety model (design + guard extension) — QEMU

Extend `store.rs`'s single-window `LbaGuard` into a **multi-region guard**: (a) the existing
16 KiB keystore gap [2016,2048) — **key material only**; (b) a **data-volume partition**
(from the MBR/GPT, a whole partition ≥ 2048); (c) the **inactive boot slot** file/region.
Preserve the invariant: **LBA 0 (MBR) and the *active* boot slot are never writable**, and a
second independent gate (driver window / RamDisk assert) still backstops every write. This
is the ADR-level change M3 hinges on — capture it as an amendment to `SEALED_STORAGE.md`.

- **Gate `P15-guard2`** (QEMU): the multi-region guard admits keystore-gap, data-partition
  and inactive-slot LBAs; **rejects** MBR (LBA 0), the active slot, and any out-of-region
  LBA (panic-on-escape, as the RamDisk does today). Data-driven from a synthetic MBR.

### M3.1 — block abstraction hardening + a cross-restart QEMU backend — QEMU keystone

The `BlockDev` trait and `RamDisk` exist, but `RamDisk` **cannot prove "survives reboot"**
(it is reconstructed every QEMU run). Add a **file-backed `virtio-blk` driver** behind the
**same `hal::BlockDev` trait** (mirroring the existing `virtio-net` mmio driver), so QEMU
launched with `-drive file=disk.img,if=none,format=raw -device virtio-blk-device` gives a
block device whose contents **survive a QEMU restart** — the honest QEMU proxy for
power-cycle persistence. The real `emmc.rs` stays the metal slot-in behind the identical
trait. **This is the recommended first implementation target (§5).**

- **Gate `P15-vblk`** (QEMU): write N sectors to the data region, **stop and relaunch QEMU**,
  read them back identical — persistence across a process restart, over the real trait the
  metal driver will later back.

### M3.2 — minimal FS / on-disk layout — QEMU

A tiny, `no_std`, crash-consistent, append-oriented on-disk format over `BlockDev` for the
data partition (deliberately **not** ext4/FAT — a purpose-built log-structured layout sized
for an appliance: a superblock + a monotonic append region + a small object index). Optimize
for (a) append-only evidence/score records, (b) power-fail atomicity (torn-write tolerance
via seq-numbered records + a checksum, same discipline as the two-slot `seq` in
`SEALED_STORAGE.md`), (c) bounded/honest retention (ring-buffer reclamation, capped window
surfaced to the operator — invariant #6 / ADR 0007).

- **Gate `P15-fs`** (QEMU): format → append records → replay after a simulated torn write
  (truncate mid-record) → recovery discards only the torn tail, all prior records intact.

### M3.3 — sealed / encrypted data volume (heqk-native, off dm-crypt) — QEMU

Re-home ADR 0007's "encrypted data volume" **off Linux dm-crypt onto heqk-native sealing**.
Reuse the existing `seal.rs` crypto **unchanged**: the master/volume key is a `HQKSEAL1`
blob in the **existing keystore window** (bound to `base` policy = PCR0 + device_id +
svn_floor, so it survives a signed kernel update but dies on foreign firmware / rolled-back
floor). The FS data region is encrypted under a subkey **derived from** that unsealed volume
key (CTR + Encrypt-then-MAC per record/extent — the same `boot-abi` primitives, no new AEAD
TCB). No dm-crypt, no LUSK header, no Linux (ADR 0044).

- **Gate `P15-vol`** (QEMU): volume key sealed to keystore → unseal at boot → mount → read
  back records; **modified-measurement refuses to unseal** the volume key (the demo gate,
  same property `seal.rs` already proves for a single blob, now for the whole volume).

> **Honest crypto limit (carried from `seal.rs`/`SEALED_STORAGE.md`).** The measurement
> binding is only *real* once hboot derives the SRK from OTP with EL1 unable to read OTP
> (audit V3). Until V3 closes, the volume uses a **synthetic SRK** and M3.3 **must print**
> that measurement enforcement is not yet real. Likewise: **no rollback-protection claim**
> for stored data before OTP/RPMB — `svn_floor` + two-slot `seq` defend torn writes and one
> downgrade class, not physical restore of an old volume image.

### M3.4 — on-device A/B OTA + persistent evidence/QSecBit store — QEMU logic, metal sign-off

Two deliverables on the M3.1–M3.3 stack:

**(a) OTA state machine** — on-device, no host PC:
`pull` (fetch a signed candidate from the registry/control plane) → `stage` (write it to the
**inactive** boot slot via the widened guard) → `verify` (**run the existing hboot signature
+ SVN-floor path** over the candidate — reuse, don't reinvent) → `arm` (set the firmware
one-shot `tryboot` + arm the PM watchdog) → `trial` (reboot into the candidate) → `confirm`
(candidate reaches health → `hvc #1` disarms watchdog → **commit**: promote inactive→active,
save prior as known-good) OR `rollback` (hang/panic/health-fail → watchdog fires → one-shot
spent → known-good slot). This is a small deterministic state machine over `BlockDev` +
the existing hboot primitives — the logic is fully QEMU-testable; only the **real PM reset**
and **real slot flip on eMMC** are metal.

**(b) Persistent evidence graph + QSecBit history** — append detection events (the `events.rs`
`Event` header: ts, src, rule_id, severity, verdict) and periodic QSecBit-lite scores
(`telemetry.rs`) as sealed records into the M3.2 FS, so the graph and score history **survive
reboot** (the C-acceptance ledger gate: "Persist evidence graph + QSecBit history").

- **Gate `P16-ota`** (QEMU): fake registry → pull → stage-to-inactive → verify accepts a
  good-SVN signed candidate and **refuses** a bad-signature / below-floor one → flip → a
  **forced-bad candidate** drives the rollback branch (watchdog-fire modelled) → active slot
  is unchanged. Mirrors `ab-update.sh` stage/commit/status semantics, on-device.
- **Gate `P16-evg`** (QEMU): emit events + scores → **relaunch QEMU** (M3.1 virtio-blk) →
  evidence graph + QSecBit history replay intact; retention cap enforced (oldest reclaimed).
- **Gate R (metal, CM5)** — the M3 **release sign-off**: real eMMC write to the data
  partition; power-cycle → evidence graph + score persist; OTA installs to the inactive slot
  from a registry and a **forced-bad boot rolls back** on silicon (the `docs/BuildPlan.md`
  M3 acceptance line + the C-acceptance ledger "Persist evidence graph" row).

---

## 4. QEMU-provable vs metal (Gate R) split

**The block driver is metal; everything above the `BlockDev` trait is QEMU-provable.**

| M3 piece | QEMU-green | Needs CM5 silicon (Gate R) |
|---|---|---|
| Multi-region write guard (M3.0) | ✅ over synthetic MBR + RamDisk | — |
| `virtio-blk` cross-restart backend (M3.1) | ✅ `-drive file=…` survives QEMU restart | — |
| **eMMC/SDHCI *write* driver** | ❌ — QEMU can't model `brcm,bcm2712-sdhci` | ✅ real CMD24 write, INT_ENABLE latch, shared-clk, 1.8 V |
| Minimal FS layout + crash recovery (M3.2) | ✅ simulated torn write | (real power-fail atomicity confirmed on metal) |
| Sealed-volume crypto (M3.3) | ✅ `seal.rs` is arch-agnostic | measurement binding **real** only after OTP/V3 (metal + hboot) |
| OTA state machine + rollback **logic** (M3.4a) | ✅ state transitions + verify refusals | ✅ real PM-watchdog reset + real slot flip + firmware one-shot on metal |
| Persistent evidence/QSecBit store (M3.4b) | ✅ append + replay across QEMU restart | ✅ real power-cycle persistence on eMMC |
| Anti-rollback SVN floor | ✅ `max()` logic + refusal | OTP thermometer is metal (already so in M1) |

**Rough split:** **~70–75 % of M3 goes QEMU-green** — the multi-region guard, the FS layout
and crash recovery, the sealed-volume crypto (already arch-agnostic), the OTA state machine
and its verify/rollback *decisions*, and the evidence/score persistence *format* (proven
across a QEMU restart via virtio-blk). **~25–30 % needs CM5 silicon (Gate R):** the eMMC
*write* driver on real hardware, real power-cycle persistence, the real PM-watchdog-triggered
rollback, and the real firmware one-shot flip. As in M1/M2: **QEMU-green is the engineering
milestone; Gate R on CM5 metal is the release sign-off** (ADR 0023 discipline, carried).

---

## 5. Recommended first implementation target — the M3.1 keystone

**A file-backed `virtio-blk` driver behind the existing `hal::BlockDev` trait, plus the
M3.0 multi-region guard.** Rationale:

1. **The trait and a backend already exist** — the keystone is *not* "invent a block trait."
   `hal::BlockDev` + `RamDisk` + a metal `emmc.rs` are done. The one missing capability is a
   QEMU backend whose contents **survive a process restart** — `RamDisk` cannot, so nothing
   above it can prove *"persists across reboot,"* which is the entire M3 acceptance claim.
2. **heqk already has the precedent** — `arch-aarch64/src/virtio.rs` is a working
   virtio-mmio (net) driver; virtio-blk is the same discovery/queue discipline over a
   different device id. Low risk, high leverage.
3. **It unlocks the whole stack for CI** — with a persistent QEMU block device behind the
   trait, M3.2 (FS), M3.3 (sealed volume), and M3.4 (OTA + evidence store) are **all
   QEMU-green**, each with a `validate.sh` gate, before any silicon is touched.
4. **The metal driver is a pure slot-in** — `emmc.rs` (already written, read path proven,
   write path coded behind `p15-write`) drops in behind the identical `BlockDev` trait for
   Gate R. No logic above `BlockDev` changes between QEMU and metal.

Sequence the keystone as: **M3.0 multi-region guard (design + `P15-guard2`)** → **M3.1
virtio-blk backend (`P15-vblk`)**, then build M3.2→M3.4 on top. Do **not** start with the
eMMC write driver: it is metal-gated, un-CI-able, and brick-adjacent — it should be the
*last* thing added (behind everything already proven in QEMU), exactly as `SEALED_STORAGE.md`
phased the read driver last.

---

## 6. Residual risks & honesty ledger

- **Write-surface widening is the real risk.** Today's guard is safe *because* it writes only
  16 KiB in the alignment gap. M3 deliberately opens a data partition + the inactive boot
  slot to on-device writes. The two-independent-gates discipline must extend to the wider
  surface or brick-safety regresses — treat M3.0 as an ADR-grade change to `SEALED_STORAGE.md`,
  security-auditor-gated.
- **Measurement enforcement is provisional** until audit V3 closes (EL1 must not read OTP).
  Until then the sealed volume prints the synthetic-SRK limitation; do not claim measurement
  enforcement or data rollback-protection.
- **eMMC write on metal is unproven.** `write_block_impl` (CMD24) is coded behind `p15-write`
  but has never run on silicon; Gate R must validate it before any persistence claim ships.
- **The FS is purpose-built, not a standard.** A custom log-structured format is right for an
  appliance but carries its own correctness burden; the torn-write / recovery gate (`P15-fs`)
  is load-bearing and must be adversarial.
- **Docs-ahead-of-kernel drift** (Track-C standing caveat): this doc specifies M3; the kernel
  has M3.0–M3.4 as **⬜ absent** today. Keep `LIFECYCLE.md` / `buildPlan.md` §5a and this doc
  in sync as phases land, and never let the doc imply a phase is built before its gate is green.
