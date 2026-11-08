# heqk Phase 2 — libcrux ML-KEM-768 evaluated in parallel (operator decision 2026-11-08: CONDITIONAL)

Decision register §B: integrate libcrux in parallel behind the ML-KEM interface; switch only after FIPS 203
vectors, no_std/CM5 build, memory, CM5 benchmarks, Chromium hybrid interop, differential/fuzz and a secret
review; keep `X25519MLKEM768` hybrid, never ML-KEM alone. **Nothing is switched.** The shipping
implementation stays RustCrypto `ml-kem 0.2.3` (kernel `securechannel`, TLS provider `tlsprov`).

Harness: `os/build/kem-diff/` (host differential) and `os/build/kem-diff/nostd-check/` (CM5-target build).

## Gate status (2026-11-08)

| Gate | Status | Evidence |
|---|---|---|
| Differential vs the shipping implementation | **PASS** | 1000 seeds (FIPS 203 internal API keygen(d,z) / encaps(m)): identical ek, dk, ct, ss; cross-decapsulation both ways; identical implicit-rejection output on tampered ciphertexts; transcript SHA-256 `eaad66b3…f6f4f9` identical on libcrux's SIMD and portable paths |
| Public-key validation (FIPS 203 §7.2) | **PASS** | honest keys accepted; a key with an unreduced coefficient (q = 3329) rejected |
| no_std build for the CM5 target | **PASS, with a mandatory flag** | builds for `aarch64-unknown-none-softfloat` (core only) — see the NEON finding |
| Code size | measured | portable keygen+encaps+decaps: **77 KB** .text (opt-z, LTO); the NEON build is 189 KB |
| FIPS 203 / NIST ACVP vectors run directly | **PASS** | `kem-diff acvp` (vectors via `fetch-acvp.sh`, NIST ACVP-Server internalProjection): ML-KEM-768 keyGen 25, encapsulation 25, decapsulation 10 (incl. implicit rejection), encapsulationKeyCheck 10, decapsulationKeyCheck 10 — **160/160** on RustCrypto and libcrux |
| FIPS 203 input checks in the shipping code | **fixed** | RustCrypto ml-kem 0.2.3 `from_bytes` performs no §7.2 encapsulation-key check. `tlsprov` already checked the client share (`mlkem_ek_ok`); the kernel control-plane channel (`securechannel::ek_from_bytes`) did not — added, with a `[P19-pqc-kat]` sub-check. Both helpers agree with NIST's encapsulationKeyCheck verdicts |
| Fuzzing | open | a cargo-fuzz target over decapsulate (malformed ciphertexts / keys) on both implementations |
| Stack / memory on the device | open | needs an EL0 TLS-host build with libcrux and a stack watermark |
| CM5 benchmarks | open (metal) | host only so far: portable libcrux 272 µs vs RustCrypto 360 µs per keygen+encaps+decaps (x86-64) |
| Chromium hybrid interop | open | the mc-e2e HTTPS leg already negotiates `X25519MLKEM768` with Chromium on RustCrypto; repeat with a libcrux-backed tlsprov |
| Secret-independence review | open | libcrux ships a `check-secret-independence` feature (type-level secret tracking) — build with it and review |

## Finding: libcrux forces NEON on every aarch64 build

`libcrux-ml-kem`'s `build.rs` enables its `simd128` (NEON) backend on **every** `target_arch = "aarch64"`,
including the softfloat bare-metal target, unless `LIBCRUX_DISABLE_SIMD128=1` is set. The default CM5 build
therefore contains NEON code (220 SIMD instructions in keygen/encaps/decaps). heqk keeps FP/SIMD trapped
(GAP_REGISTER CORE-7: no `CPACR_EL1.FPEN`, no q-register save), so the first ML-KEM call would take an
FP/SIMD trap. Two traps in one:

1. the flag is **mandatory** for any heqk build: `LIBCRUX_DISABLE_SIMD128=1`;
2. libcrux's `build.rs` does not declare `rerun-if-env-changed`, so setting the flag on an existing target
   directory silently keeps the cached NEON build — a clean build of the crate is required.

If libcrux is adopted, the build must assert the result (no SIMD instructions in the linked libcrux code),
the same way `build.rs` now refuses a dev-API UI bundle.

## Recommendation

Keep RustCrypto as the shipping ML-KEM. Next increments, in order: ACVP vectors + fuzz target (host), a
`tlsprov` backend switch behind a cargo feature (default off) with the SIMD guard, then the device gates
(stack, CM5 timing, Chromium interop over the metal HTTPS leg). Switch only when every row above is green.
