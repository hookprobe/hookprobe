# heqk M3 — persistence (eMMC block storage, sealed store, A/B OTA)

> **Status: reconstructed 2026-09-11 from the authoritative in-tree sources.** Code
> is the source of truth. The **frozen hardware/write-safety design is
> `SEALED_STORAGE.md`** (read that first); this doc is the M3 status + map onto the
> proven phases. Canonical sources: `SEALED_STORAGE.md`, `validate.sh` (`[P15-seal]`,
> `[P15-guard2]`, `[P15-persist]`, `[P15-fs]`, `[P15-sealfs]`, `[P15-ota]`,
> `[P15-otafat]`, `[HBoot-AB]`), `kernel/src/{store,seal,fslog,ota,fat}.rs`,
> `arch-aarch64/src/{sdhci,emmc}.rs`. Cited by `store.rs` before it existed.

## 0. The one rule — never brick

The eMMC is the boot device. Every persistence feature is designed so that **no
code path can damage the boot chain**: the MBR (LBA 0) and the ACTIVE boot slot are
never writable; writes are compiled out by default (`--features p15-write`) and, when
enabled, pass **two independent gates** (the store's `LbaGuard` + the driver's
one-shot narrowing-only `arm_write_window`) so a store-layer arithmetic bug cannot
escape. The driver contains **no** code path that can emit CMD6 SWITCH, CMD38 ERASE,
CMD42, or any RPMB/boot-area switch (one wrong `EXT_CSD` index = permanent brick —
`SEALED_STORAGE.md` §"Rejected").

## 1. The controller (`sdhci.rs`, `emmc.rs`)

A second `brcm,bcm2712-sdhci` at CPU-phys `0x10_00FF_F000`, 8-bit, `broken-cd`,
fixed 1.8 V VCCQ (legacy timing, never touch `HOST_CTRL2`), `clk-emmc2` SHARED with
the WiFi controller (never `set_clock_rate` — derive divisors from read-back).
Transcribes `cyw43.rs`'s hard-won SDHCI knowledge (the `INT_ENABLE` latch; wait on
`INT_BUF_RD_RDY`) into a base-parameterized driver. Read-only by default.

## 2. Proven phases (QEMU file-backed virtio-blk two-boot harness + CM5 metal)

| Phase | What it proves |
|-------|----------------|
| `[P15-seal]` M3.x | **HQKSEAL1** Encrypt-then-MAC seal/unseal (SHA-256 HMAC / HKDF / CTR); tamper + wrong-measurement refused; MBR write-guard (RamDisk). |
| `[P15-guard2]` M3.0 | multi-region write allowlist: REFUSES LBA 0/MBR, the ACTIVE slot, unregistered gaps, past-capacity; ALLOWS keystore + DataVolume + INACTIVE slot; bad region registration rejected fail-closed. Runs every boot. |
| `[P15-persist]` M3.1 | seal → persist → **reboot** → unseal SURVIVES restart over a file-backed virtio-blk (the same `hal::BlockDev` the metal eMMC slots into). |
| `[P15-fs]` M3.2 | crash-safe **log-structured record store** on the DataVolume: N records survive reboot in order; an injected torn-tail record is DROPPED on recovery while intact records survive; bounded ring evicts oldest-first, never writes outside the guard; a real evidence Event + QSecBit history round-trip. |
| `[P15-sealfs]` M3.3 | **encryption at rest**: payloads sealed under a Volume Encryption Key itself SEALED in the keystore — a raw block read of a known Event is ciphertext (magic present, plaintext absent); a flipped ciphertext byte with the framing digest recomputed is still MAC-rejected at `mount_sealed`; the VEK survives reboot. |
| `[P15-ota]` M3.4 | on-device **A/B OTA** state machine: a valid hybrid-signed candidate is verified by the SHARED `boot_abi::verify` (HBoot's exact verifier — no 2nd trust root) → staged to the INACTIVE slot only → Staged; a bad signature is rejected verify-before-flip (no write, active slot + tryboot untouched); flip→Trying→healthy→Committed / failed→RolledBack; below-floor SVN downgrade refused; state survives reboot; brick-safety (candidate only ever lands in `RegionKind::InactiveSlot`). |
| `[P15-otafat]` B2 | OTA **delivery**: a read-only FAT32 locator (MBR → BPB → root dir → `HEQK8-B.IMG` cluster chain → contiguous LBA run, fail-closed if fragmented/absent) registers the inactive slot and writes a candidate through the guard on a genuine `mkfs.vfat` image — FAT metadata never mutated. |
| `[HBoot-AB]` | A/B trial boot: the kernel confirms health (`hvc #1` disarms HBoot's EL2 watchdog) or firmware falls back to the known-good slot. |

**Metal (CM5, 2026-09-08):** a real **CMD24 write** + a SEALED evidence Event
surviving a **power-cycle** proven on silicon (`[SEPDIAG-EMMC-WRITE]`,
`[SEPDIAG-EMMC-SEAL]`: seal → store → power-cycle → unseal, ciphertext at rest,
Gate-1 clamp holds; `p15-write` feature). See memory `hookprobe-heqk-m3-persistence`.

## 3. Keys: sealing without a TPM

DICE-style derivation `CDI_{n+1} = KDF(CDI_n, measurement)`: a layer that is not
the measured one derives a different key and simply cannot decrypt — unsealing
failure is automatic, no policy engine. The Storage Root Key is derived from **OTP
inside HBoot at EL2** and the EL1 kernel cannot re-read OTP (SEC-2 / V3, metal-proven
2026-09-10) — see `heqk-signing-identity.md` §5.

## 4. Remaining (M3 is mechanism-complete; these are capacity/factory items)

- A **dedicated DataVolume PARTITION** (image-factory change; today the reserved
  window is LBA 2016..2047 — 32 sectors — and p2/p3 remain the recoverable Linux),
  for real evidence capacity.
- The **real firmware one-shot tryboot flip** + PM-watchdog trial reset + power
  cycle on metal (the QEMU `[P15-ota]` proves the state machine; hboot/metal proves
  the flip) — Gate R.
- Metal eMMC **InactiveSlot write arming** (`emmc.rs` clamp) — a separate Gate-R
  item.
- Journald/dm-crypt retirement on the Linux tier (unbuild batch U3) is gated on the
  above.
