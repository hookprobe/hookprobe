# heqk — SVN advancement procedure and SEC-3 (signed first stage) plan

Phase 1 of the operator decision register (`heqk-decisions-2026-11-08.md`): "SVN advancement procedure
validated, SEC-3 plan". Nothing here programs a fuse; every irreversible step is listed as an operator
ceremony and is out of scope for development sessions.

## 1. SVN advancement (anti-rollback) — procedure, validated

What is enforced today (HBoot, `os/kernel/hboot/src/rollback.rs`): an image boots only if BOTH
signatures (Ed25519 + SLH-DSA-128s) verify over `sha256(LE64(svn) ‖ sha256(payload))` AND
`svn >= max(COMPILE_FLOOR, EXPECTED_MIN_HW_FLOOR, OTP block-3 popcount)`. The OTP thermometer is blank
(operator decision: no further fuse programming), so the effective floor is `COMPILE_FLOOR` (= 1).
OTP block 1 holds the device secret (AK / SRK source); block 3 is reserved for the thermometer and must
never hold key material.

Release procedure for a fix that must not be rolled back past:

1. Build and ship release **N+1 with `SVN=N+1`** (`SVN` env of `os/build/make-cm5-heqk-image.sh` /
   `mkimage-hboot.sh`), **floor unchanged**. It boots everywhere; older images still boot (A/B fallback
   keeps working during the roll-out).
2. When the fleet runs N+1, raise **`COMPILE_FLOOR` to N+1** in `rollback.rs` and ship that HBoot (with
   the same or a newer SVN). From then on SVN ≤ N images are refused by HBoot.
3. (Hardware floor — deferred, separate approved ceremony) `advance_floor(N+1)` burns the OTP thermometer
   and `EXPECTED_MIN_HW_FLOOR` is raised in the same release, so a forced OTP-read failure cannot drop the
   floor back.

Validation (host, the real signer which mirrors HBoot's verify, on the real kernel payload):
`os/build/svn-advance-check.sh [PAYLOAD] [N]` — expectations, all met on 2026-11-08:

| Case | Expect |
|---|---|
| release N under floor N | PASS |
| release N+1 under floor N (step 1) | PASS |
| release N+1 under floor N+1 (after step 2) | PASS |
| release N under floor N+1 (rollback) | FAIL |
| release N re-labelled SVN N+1 | FAIL (SVN is inside the signature) |
| release N+1 re-labelled SVN N | FAIL |

Device-side coverage already in `validate.sh`: `[P15-ota]` runs HBoot's exact `boot_abi::verify` in the
kernel's OTA orchestrator (bad signature or `svn < floor` never leaves Staged).

Open point: HBoot itself is not covered by a QEMU boot; a metal round with an SVN=2 image on the bench
(possible with the relay rig, `tools/diagnostics/cm5-metal-loop.sh`) is the remaining proof of step 1.

## 2. SEC-3 — the first stage is trust-on-first-use

Today the BCM2712 boot ROM / EEPROM bootloader loads `heqk8-a.img` (HBoot + signed kernel) from the
FAT partition **without verifying it** (`config.txt` has no signed boot; GAP_REGISTER SEC-3 / XC-9).
HBoot verifies the kernel, so the chain is sound only if HBoot itself is genuine: someone who can write
the card can replace HBoot. Raspberry Pi "secure boot" closes this: the bootloader verifies a signed
`boot.img` (a FAT ramdisk) + `boot.sig` against a customer public key whose hash is fused into OTP.

### Consequences for heqk (design work before any ceremony)

1. **Packaging.** Signed boot loads a `boot.img` ramdisk, not files from the FAT partition. heqk's boot
   set (`heqk8-a.img`, `heqk8-b.img`, `config.txt`, `tryboot.txt`) must move into `boot.img`; the factory
   produces `boot.img` + `boot.sig` (customer RSA-2048 key, as the bootloader requires).
2. **A/B + tryboot.** The `tryboot` A/B flip happens inside the bootloader; with signed boot each slot
   becomes its own signed `boot.img` (`tryboot_a_b=1` style) — the OTA writer stages a signed `boot.img`
   produced by the operator, never one the device signs itself.
3. **Operator files** (POLICY / BLOCK / WIFI / …) stay outside `boot.img` on the FAT partition: they are
   already operator-signed and verified by the kernel (ADR 0049), so they need no change.
4. **Key custody.** The customer signing key is a release key (HSM), separate from the heqk boot keys.

### Rehearsal without fuses (development-safe)

`usbboot`'s `secure-boot-recovery` can write an EEPROM with `SIGNED_BOOT=1` and the customer public key
**with `program_pubkey=0`** — the bootloader then verifies `boot.img` exactly as in production, but nothing
is fused and the EEPROM can be restored. Steps:

1. Factory: emit `boot.img` (the boot set) + `boot.sig` with a **test** customer key.
2. Bench: flash the signed-boot EEPROM (`program_pubkey=0`) via the relay rig; boot the signed image —
   expect the normal boot contract.
3. Negative: flip one byte of `boot.img` — expect the bootloader to refuse (serial shows the signature
   failure), then the A/B fallback behaviour to be defined.
4. Restore the stock EEPROM.

### The ceremony (operator only, irreversible — NOT part of development)

Program the customer key hash into OTP (`program_pubkey=1`), optionally revoke the RPi dev key and lock
JTAG. Preconditions: rehearsal passed on the bench; HSM custody of the customer key; the factory and the
OTA path produce only signed `boot.img`; recovery procedure documented (a fused board accepts only images
signed with that key, forever).

| Step | Reversible | Who |
|---|---|---|
| Packaging + factory `boot.img` / `boot.sig` | yes | development |
| Signed-boot EEPROM, `program_pubkey=0` (rehearsal) | yes | development, bench |
| `program_pubkey=1`, revoke dev key, JTAG lock | **no** | operator ceremony |
