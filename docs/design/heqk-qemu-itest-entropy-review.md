# QEMU integration-test profile (`qemu-itest`): entropy design and key-generation call-path review (2026-11-22)

**Decision:** operator, 2026-11-22. The decision was relayed by the G19 PoP session; operator confirmation is to be
recorded in the PR.
- virtio-rng is allowed for a dedicated QEMU integration-test profile only, subject to an independent security review
  and explicit fail-closed behaviour.
- It is never in CM5 or cloud builds.
- There is no timer, counter, fixed-seed or weak-entropy fallback.
- Deterministic entropy stays self-test-only.
- A unique per-VM VEK from that source, protected separately from the backing volume.

**Status:** implemented on `feat/qemu-itest-entropy`; QEMU-local tests only. **No metal claim; no release-gate
change.**

## 1. Profile separation (compile time)

| Combination | Result |
|---|---|
| `qemu-itest` + `cm5` / `cloud` / `hboot` / `apmode` / `prod` | `compile_error!`, verified for `cm5` |
| `qemu-itest` + `securechannel-selftest` / `securechannel-host-responder` | `compile_error!`, verified |
| CM5 build | `HwTrng` = RNG200 (unchanged); virtio-rng not compiled in (arch feature `virtio-rng` off) |
| cloud build | `HwTrng` = SMCCC TRNG (unchanged) |
| plain QEMU builds (validate.sh, mc-e2e) | unchanged: `HwTrng` = `None` (fail-closed) and their existing QEMU-only stand-ins |

## 2. The virtio-rng leaf (`arch-aarch64/src/virtio_rng.rs`)

- virtio-mmio entropy device (type 4), one request queue, 64-byte device-writable requests.
- **Strict:** `None` when the device is absent, negotiation fails, a request times out, the fill is short (never
  padded), or the continuous test fails. The continuous test is two identical consecutive 64-bit words. Failure
  **latches** for the rest of the boot.
- The request buffer is poisoned before each request, and consumed bytes are wiped.
- It feeds the existing `MetalEntropy<HwTrng>` (fill + startup health check). Every key path still goes through that
  contract.

## 3. Key-generation call paths

What each path uses as its source in each profile. **Bold** = changed by this work.

| Path | CM5 (production) | cloud | `qemu-itest` | plain QEMU (validate / mc-e2e) |
|---|---|---|---|---|
| Noise / G19 ephemerals (`InitiatorRandomness::from_entropy(MetalEntropy<HwTrng>)`) | RNG200 | SMCCC TRNG | **virtio-rng** | fails closed (no handshake) |
| TLS handshake entropy (`tlshost::fill_entropy`) | RNG200, fail-closed | — | **virtio-rng, fail-closed** | counter + `cntpct` hash (QEMU-only, compiled out of this profile) |
| el0-wpa DRBG seed (`el0srv::trng_seed`) | RNG200, fail-closed | — | **virtio-rng, fail-closed** | fixed test pattern (QEMU-only, compiled out of this profile) |
| Mission Control session ids (`mcserve::rand16`) | RNG200, fail-closed | — | **virtio-rng, fail-closed** | `cntpct` hash (QEMU-only, compiled out of this profile) |
| Management boot epoch (`mgmtenv::rand8`) | RNG200, fail-closed | — | **virtio-rng, fail-closed** | `cntpct` hash (QEMU-only, compiled out of this profile) |
| Seal nonce salt (`seal::boot_salt`) | RNG200 | — | **virtio-rng** | none: the SIV nonce is safe without it by construction (W4) |
| Per-VM VEK (`itest::volume_selftest`) | n/a (CM5: `evlog::vek_of` = HKDF(SRK)) | — | **virtio-rng, sealed under the fw_cfg KEK** | n/a |
| Per-VM device identity seed | n/a (CM5: HKDF(SRK)) | — | **virtio-rng, sealed under the VEK** | n/a |
| `fslog::create_vek` (`cntpct` ‖ synthetic SRK) | **not reachable**: called only from the `P15-sealfs` QEMU self-test | — | **not used** (the itest path never calls it) | self-test only |

## 4. Findings

1. **CM5 production, outside this profile (needs a separate PR, operator merge).** `main.rs` AP loop:
   `McNode::new(..., rng200::next_word_strict().unwrap_or(0) ^ mc_t0)`.
   - The Mission Control TCP stack's `random_seed` (smoltcp: TCP initial sequence numbers and ephemeral ports) falls
     back to a **timer value** when the TRNG fails.
   - A failed TRNG already makes every login fail closed (`rand16` → `None`), so the node is unusable anyway.
   - **Recommendation:** fail closed (no AP-side MC node without a TRNG word), or reseed from the next good TRNG
     read. It is not changed here, to keep this PR to the test profile.
2. **`fslog::load_or_create_vek` replaces an unsealable VEK with a fresh one** instead of refusing. It is only
   reachable from the QEMU self-test. The itest path implements the strict rule instead: no blob means create one;
   a blob that does not unseal means refuse, and never replace it.
3. `fslog::create_vek` mixes `cntpct` with a synthetic SRK. It is self-test only and documented as such in the code;
   recommend renaming it or gating it behind the self-test feature so it can never be wired to a real volume.
4. **No other production key path uses a timer or counter.** `lanaccess`, `netcfg`, `ratelimit`, `segment` and
   `rtwdog` read `cntpct` as a clock only.

## 5. Tests (QEMU-local; `tools/itest-qemu.sh`)

Entropy:
- **R1:** health-checked, bit balance in a 6σ window, two fills differ, device round trips counted, a stuck source is
  refused.
- **R2:** with no device, entropy and the volume both fail closed.

Volume:
- **V1:** a blank disk is formatted, the per-VM VEK is created from virtio-rng and sealed under the KEK, and the
  identity is printed.
- **V2:** reboot loads the VEK, keeps the same identity, and verifies the boot-1 record.
- **V3:** with another VM's KEK the volume is refused and the disk stays byte-identical.
- **V4:** rotation to `kek-next` goes through the staging slot.
- **V5:** the rotated KEK opens the volume, with the same identity and all records.
- **V6:** after rotation the old KEK is refused.
- **V7:** a second VM gets a different identity and VEK.
- **V8:** with no KEK, the volume and keys are refused.

In-boot checks:
- authenticated integrity: a flipped ciphertext byte, with the keyless framing digest re-forged, is rejected by the
  seal MAC;
- at rest: no plaintext marker, VEK, seed or KEK in the keystore window or the ring.

Host:
- a raw-disk scan finds no plaintext marker and no KEK bytes.

## 6. Not shown

- **Interoperability with the real PoP (G19 S1):** a separate evidence set, run with the S1 harness (PR #1489) once
  the operator runs S0.
- **CM5 metal:** not applicable to this profile. The CM5 keeps its RNG200 paths, unchanged.
- **Independent security review:** requested; this document is its input.
