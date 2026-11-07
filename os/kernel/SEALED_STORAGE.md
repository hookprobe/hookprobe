# P15 — eMMC block storage + sealed persistence — frozen design

Status: **DESIGNED, not yet implemented.** Ground truth taken from the CM5 device
tree and the board's own image-build script.

## The controller

The eMMC is a **second `brcm,bcm2712-sdhci`** at CPU-phys **`0x10_00FF_F000`**
(cfg block at `+0x400`), SPI 273, 8-bit, `broken-cd`. Decoded from
`/soc/mmc@fff000` with `ranges` child0 -> CPU `0x10_0000_0000`; cross-checked
against three known-good nodes (mailbox, pinctrl, gio) that all decode correctly.

**Already Device-mapped** by both stage-1 and stage-2 (GB64). No MMU work needed.

Three consequences that shape the driver:
1. **`clk-emmc2` is shared with the WiFi controller.** P15 must never call
   `set_clock_rate` (it would retune the live WiFi host mid-operation) — only
   `get_clock_rate`, and derive divisors from the read-back.
2. VCCQ is a **fixed 1.8 V** rail, so signalling voltage is a board property, not
   negotiated. Stay in legacy timing and **never touch `HOST_CTRL2`**.
3. `broken-cd` ⇒ the upstream force-card-presence quirk applies.

Reuse `cyw43.rs`'s hard-won SDHCI tribal knowledge verbatim — above all the
**`INT_ENABLE` latch discovery** (0x34 must be armed or `INT_STATUS` never latches)
and "wait on `INT_BUF_RD_RDY`, not `PRESENT_STATE` bit11". Do **not** modify
`cyw43.rs`; transcribe into a new base-parameterized `sdhci.rs`.

## The write-safety model — the part that matters most

Board partition layout (`make-cm5-image.sh`): p1 FAT32 at LBA 2048, p2 ext4 at
526336. So:

- **LBA 0** = MBR. Read-only, always.
- **LBA 1..2047** = sfdisk's 1 MiB alignment gap. No filesystem, no bootloader code
  (unlike x86, the BCM2712 EEPROM executes nothing from the gap).
- **LBA >= 2048** = partitions. **Never touched.**

**Reserved window: LBA 2016..2047** (32 sectors), i.e. 2015 sectors clear of the
MBR and butting against — never entering — the first partition. Both edges checked
at runtime against the actual MBR, never assumed. The guard refuses unless the MBR
signature is present, no `0xEE` (GPT protective) entry exists, every partition
starts at >= 2048 and fits within capacity, and at least one partition exists.

Two **independent** gates: the store layer's `LbaGuard`, and the driver's one-shot
narrowing-only `arm_write_window`, so a store-layer arithmetic bug cannot escape.
Writes are compiled out by default (`--features p15-write`).

**Rejected: eMMC boot partitions / RPMB.** Superficially safest (address-isolated)
but reaching them needs **CMD6 SWITCH** writes to `EXT_CSD PARTITION_CONFIG[179]`,
one index away from `BOOT_WP[173]` (permanent write-protect) and
`PARTITION_SETTING_COMPLETED[155]` (one-time). A single wrong index is an
unrecoverable brick. The driver contains **no code path that can emit CMD6, CMD38
ERASE, CMD42, or any RPMB/boot-area switch.**

## Sealing without a TPM

DICE-style key derivation: `CDI_{n+1} = KDF(CDI_n, measurement)`. A layer that is
not the measured one derives a different key and simply **cannot decrypt** —
unsealing failure is automatic, with no policy-evaluation engine.

```
SRK      = SHA256("HEQK-SEAL-SRK-v1" || OTP_secret)        -- derived IN HBOOT
policy   = SHA256(tag || mask || device_id || svn_floor || PCRs...)
SK       = HKDF-Expand(HKDF-Extract(SRK), policy)
per blob = CTR keystream from SHA-256 + HMAC-SHA256 (Encrypt-then-MAC)
```

Building blocks are HMAC/HKDF/CTR over the SHA-256 already in `boot-abi` — ~120
lines — rather than pulling a RustCrypto AEAD in and doubling the crypto TCB for a
<=3.5 KiB blob.

**Two policies, and the difference is the whole update story:**
- **`base`** (PCR0 only) — production default. Survives a signed kernel update,
  still refuses foreign firmware or a downgraded floor.
- **`strict`** (PCR0|1|2) — the demo gate ("boot a modified image -> refuses to
  unseal") and assets that *should* die on any change.

Raw-PCR brittleness is a real availability bug in an appliance; this is why the
two-policy split exists rather than sealing everything to strict.

## The non-negotiable rule

**The kernel must never see the OTP secret.** If EL1 can read OTP — and it can
today via the VC mailbox (audit finding V3) — then a modified kernel derives SRK
and hence a key for *any* policy, and measurement binding is **cosmetic**.

So: closing V3 (split GB64 in stage-2 and leave the mailbox page invalid for EL1;
add an HBoot `hvc` mailbox proxy with a tag allowlist that hard-refuses the OTP
tags) is a **hard prerequisite for the P15 security claim**. Until it ships, P15
must print the limitation and the docs must not claim measurement enforcement.

Likewise **do not claim rollback protection** before RPMB or an OTP monotonic
counter exists — `svn_floor` in the policy plus two-slot `seq` defends against torn
writes and one class of downgrade, not against physical restore of an old slot.

## Phasing

**A** read-only bring-up + MBR parse + guard (zero disk risk) -> **B** seal/unseal
in RAM, wrong-measurement and tamper refusals (no disk) -> **C** write behind the
feature flag, 8 sectors, read-back verified -> **D** power-cycle + modified-image
refusal -> **SEC** close V3 and V7. `seal.rs`/`store.rs` are arch-agnostic, so the
whole crypto half is CI-gateable in QEMU over a RamDisk, including a
write-window-escape test.

## M3.0 — the multi-region write model (the ADR-grade widening)

Phases A–D above write **one** region: the 16 KiB keystore window (LBA 2016..2047)
— right for a sealing key, wrong for a data volume or an OTA slot. **M3 widens the
write surface**, and the write-safety model widens with it: the single `[lo, hi)`
window becomes a **strict multi-region allowlist** (`store::LbaGuard`), still
brick-safe by the same two-independent-gates discipline.

**The region map — an ALLOWLIST, never a denylist. Only these are writable:**

| Region | Kind | Who registers it | Contents |
|---|---|---|---|
| LBA 2016..2047 | `Keystore` | `guard_from_mbr` (always) | the sealing/volume key blob (unchanged) |
| a data partition (LBA ≥ 2048, ≥ first-part) | `DataVolume` | the layout module (`add_region`) | evidence graph + QSecBit history |
| the **inactive** A/B boot slot | `InactiveSlot` | the OTA module (`add_region`) | a staged OTA candidate |

**Everything else stays `WriteRefused` by construction** — there is no denylist to
get wrong. LBA 0 (MBR / partition table) is refused *twice*: `LbaGuard::allows`
returns false for LBA 0 unconditionally (gate 1, even if a region were
mis-registered), and the device driver refuses LBA 0 independently (gate 2 — the
virtio-blk backend refuses it outright; the metal eMMC's one-shot `arm_write_window`
is the hardware analogue). The **active** boot slot, the active FAT partition, and
every alignment/boot gap are simply **never registered**, so they are refused by the
allowlist default. `with_region` **rejects fail-closed** any registration that
includes LBA 0, overlaps the keystore or another region, inverts its range, or runs
past capacity — a bad layout can never widen the guard.

## M3.1 — the block backend + cross-restart persistence proof

`hal::BlockDev` is the seam. Two backends sit behind it:

- **`RamDisk`** (host/CI) — volatile; proves the write-window *logic* but **cannot
  prove "survives reboot."**
- **`arch_aarch64::virtio_blk::VirtioBlk`** (QEMU) — a file-backed
  `virtio-blk-device`; its contents **survive a QEMU restart**, so it is the honest
  QEMU proxy for power-cycle persistence.
- **`arch_aarch64::emmc::Emmc`** (`cfg(cm5)`) — the real `brcm,bcm2712-sdhci` write
  path, **metal-only (Gate R)**; it is the slot-in behind the *identical* trait and
  is **not built in QEMU**.

The `[P15-persist]` gate boots QEMU **twice against one backing file**: boot 1 seals
a cookie into the keystore + writes a `DataVolume` marker through the guard (and
proves an LBA-0 and active-slot write are *refused* on the real device); boot 2 reads
both back and unseals — proving `seal → persist → reboot → unseal` across a restart.
The `[P15-guard2]` gate proves the allowlist/refusal predicate every boot (no device
needed). **Honesty:** the virtio-blk path proves the write-path logic + persistence
in QEMU; the real eMMC write on `brcm,bcm2712-sdhci`, real power-cycle persistence,
and the measurement binding (OTP/V3) remain **metal (Gate R)** — not claimed here.

## M3.2 — the crash-safe record store (`fslog.rs`)

The `DataVolume` region gains a **log-structured record store** (`kernel/src/fslog.rs`)
so the evidence graph + QSecBit history **persist** (today they reach only the
serial/SIEM ring + RAM). It is deliberately **not a POSIX FS** — a ring of
self-validating fixed-size records is the right shape for append-mostly telemetry:

- **Layout:** a `HQKFSLOG` superblock at the region base, then N one-sector RECORD
  slots. Record `seq` → slot `seq % N`, so the log is a **ring** — append past
  capacity overwrites the oldest slot (**bounded, honest retention**, CLAUDE.md).
- **Record (512 B, sector-atomic):** `magic · seq · len · rtype · digest[8] ·
  payload(≤480 B)`. The digest is a keyless truncated SHA-256 over the header
  (digest field excluded) + payload — integrity only; **per-record/volume
  ENCRYPTION is M3.3** (`seal.rs`), not this phase.
- **Crash recovery (load-bearing):** every record self-validates, so no separate
  write cursor exists to get torn. On `mount`, scan all slots, keep the valid ones,
  set next seq = (max valid seq)+1. A power-loss torn write leaves exactly one
  invalid slot at the frontier — it fails its digest and is **dropped**; every
  intact record survives and the store is immediately writable again.
- **Every write is guarded:** `format`/`append` go through `store_sector`, so a
  record can only ever land inside the `DataVolume` allowlist — a ring-math or
  region bug is `WindowEscape`, never a partition-table or boot-slot write.

The `[P15-fs]` gate proves all four on virtio-blk: (a) N records survive an actual
reboot **in order**; (b) an **injected torn-tail** record (valid header, one payload
byte corrupted after digesting) is dropped on re-mount while the intact records
survive and a new append succeeds; (c) a 4-slot ring fed 10 records keeps only the
last 4 (oldest evicted) and never writes outside the region; (d) a real `events::Event`
+ a QSecBit history record round-trip field-for-field across the reboot. **Honesty:**
QEMU/virtio-blk-proven; the real eMMC write + real power-fail atomicity are **metal
(Gate R)**, and record confidentiality waits on **M3.3** (this phase is integrity only).

## M3.3 — the sealed data-volume (encryption at rest)

M3.2 left the record PAYLOAD in the clear (integrity-only digest). **M3.3 encrypts
it at rest** (ADR 0007 confidentiality) by reusing the existing `seal.rs` HQKSEAL1
Encrypt-then-MAC — no new crypto.

**The Volume Encryption Key (VEK).** A 32-byte key is generated at first mount
(best-effort entropy = `cntpct_el0 || SRK` through SHA-256 — QEMU has no TRNG, so a
real RNG/OTP seed is **metal (Gate R)**, the same caveat `seal.rs`'s nonce carries)
and **sealed** under the boot-measurement SRK + policy into the keystore at
**LBA 2024** (distinct from the P15-persist cookie at LBA 2016; both inside the
always-registered `Keystore` window 2016..2047). It **never lands cleartext on the
DataVolume**; every subsequent mount **loads + unseals** it. A wrong measurement
cannot even load the VEK (DICE), and the guarded write lands only in the keystore.

**Per-record sealing.** `append_sealed` seals the plaintext with the VEK (playing
the role of the seal SRK) + the volume policy, and writes the resulting blob
(128-B header + ciphertext + HMAC tag) as the record's opaque payload through the
normal guarded `append`. The **framing stays cleartext** (`magic·seq·len·rtype·
digest`) so the key-free ring scan + torn-tail recovery (`mount`) still work with no
key; only the payload bytes are ciphertext. Max sealed plaintext = 480 − 128 =
**352 B/record**.

**Two integrity layers, distinct jobs.** The keyless framing digest is **cheap,
key-free torn-write detection** — an attacker CAN forge it, so it is not an
authenticity claim. The seal's HMAC tag over the ciphertext is the **real, keyed
tamper check**: `mount_sealed` / `for_each_sealed` verify it and **drop any record
that fails, fail-closed, revealing no plaintext** — so a ciphertext edit that
recomputes the forgeable digest (which `mount` would accept) is still rejected.

The `[P15-sealfs]` gate proves the three "sealed" properties on virtio-blk:
- **Confidentiality** — a RAW block read of a slot holding a known Event is
  ciphertext: the plaintext markers (`ts` 0xDEADBEEF…, the src IP, the 16-B Event
  image) are **absent** from the on-disk sector, while the HQKSEAL1 magic is present.
- **Integrity** — a ciphertext byte flipped on disk **with the keyless framing
  digest recomputed** is MAC-rejected at `mount_sealed` (proving the seal MAC, not
  the digest, is the guard), while the intact records survive.
- **Cross-restart** — the sealed VEK persists in the keystore, so boot 2 loads it
  (`created=false`) and decrypts boot 1's evidence Event + QSecBit history
  field-for-field.

**Honesty:** QEMU/virtio-blk-proven; the real eMMC write on `brcm,bcm2712-sdhci`,
hardware-grade VEK entropy, and the **OTP-bound SRK / measurement binding (audit V3)**
remain **metal (Gate R)** — until V3 closes, the SRK is synthetic and the docs do not
claim measurement enforcement. Cross-boot CTR-nonce uniqueness is inherited from
`seal.rs` (per-boot unique today; a persistent monotonic seed is the deferred HBoot
SealHandoff) — the M3.3 test only *reads* on boot 2, so no same-key/same-nonce reuse
occurs across the two boots.
