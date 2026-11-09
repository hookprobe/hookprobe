# heqk Phase 2 — libcrux ML-KEM-768 evaluated in parallel (operator decision 2026-11-08: CONDITIONAL)

Decision register §B: integrate libcrux in parallel behind the ML-KEM interface; switch only after FIPS 203
vectors, no_std/CM5 build, memory, CM5 benchmarks, Chromium hybrid interop, differential/fuzz and a secret
review; keep `X25519MLKEM768` hybrid, never ML-KEM alone. **Nothing is switched.** The shipping
implementation stays RustCrypto ml-kem — **0.3.4 since 2026-11-08** (was 0.2.3; see the constant-time finding).

Harness: `os/build/kem-diff/` (host differential, `acvp`, `fuzz`), `os/build/kem-diff/nostd-check/` (CM5-target build),
`os/build/kem-diff/ctgrind/` (constant-time under valgrind).

## Gate status (2026-11-08)

| Gate | Status | Evidence |
|---|---|---|
| Differential vs the shipping implementation | **PASS** | 1000 seeds (FIPS 203 internal API keygen(d,z) / encaps(m)): identical ek, dk, ct, ss; cross-decapsulation both ways; identical implicit-rejection output on tampered ciphertexts; transcript SHA-256 `eaad66b3…f6f4f9` identical on libcrux's SIMD and portable paths |
| Public-key validation (FIPS 203 §7.2) | **PASS** | honest keys accepted; a key with an unreduced coefficient (q = 3329) rejected |
| no_std build for the CM5 target | **PASS, with a mandatory flag** | builds for `aarch64-unknown-none-softfloat` (core only) — see the NEON finding |
| Code size | measured | portable keygen+encaps+decaps: **77 KB** .text (opt-z, LTO); the NEON build is 189 KB |
| FIPS 203 / NIST ACVP vectors run directly | **PASS** | `kem-diff acvp` (vectors via `fetch-acvp.sh`, NIST ACVP-Server internalProjection): ML-KEM-768 keyGen 25, encapsulation 25, decapsulation 10 (incl. implicit rejection), encapsulationKeyCheck 10, decapsulationKeyCheck 10 — **160/160** on RustCrypto and libcrux |
| FIPS 203 input checks in the shipping code | **fixed** | RustCrypto ml-kem 0.2.3 `from_bytes` performs no §7.2 encapsulation-key check. `tlsprov` already checked the client share (`mlkem_ek_ok`); the kernel control-plane channel (`securechannel::ek_from_bytes`) did not — added, with a `[P19-pqc-kat]` sub-check. Both helpers agree with NIST's encapsulationKeyCheck verdicts |
| Fuzzing (differential) | **PASS** | `kem-diff fuzz 1000000` (288 s, seed `0x6865716b2d6b656d`, reproducible): 600 301 hostile ciphertexts (mutated + random) against honest keys → 0 disagreements (implicit rejection identical); 32 567 encapsulations to mutated/random public keys that pass the FIPS 203 §7.2 check → 0 disagreements; 0 panics. Keys that FAIL §7.2 (167 074) give different results in every case — each library treats out-of-range input its own way — which is why the §7.2 check added to the shipping code (`5545d122`) is load-bearing, not cosmetic. Coverage-guided cargo-fuzz still open (no cargo-fuzz on the build host) |
| Stack / memory on the device | open | needs an EL0 TLS-host build with libcrux and a stack watermark |
| CM5 benchmarks | open (metal) | host only so far: portable libcrux 272 µs vs RustCrypto 360 µs per keygen+encaps+decaps (x86-64) |
| Chromium hybrid interop | open | the mc-e2e HTTPS leg already negotiates `X25519MLKEM768` with Chromium on RustCrypto; repeat with a libcrux-backed tlsprov |
| Secret-independence (type-level) | **PASS with a caveat** | `check-secret-independence` does not build in the published 0.0.11 (its generic KEM-trait impl uses `u8` where the trait expects `Secret<u8>`); with that one macro removed, the whole ML-KEM-768 portable code builds for `aarch64-unknown-none-softfloat` under the checker (feature confirmed active via `cargo tree`). Caveat: 0.0.11 classifies only in the polynomial/vector layer |
| Constant time (dynamic, ctgrind-style) | **libcrux PASS; RustCrypto 0.2.3 FLAGGED → shipping moved to 0.3.4 (PASS)** | `os/build/kem-diff/ctgrind` under valgrind memcheck, secrets marked undefined at the API boundary (decapsulation key s and z, encapsulation randomness m; public ek/ct declared defined). libcrux 0.0.11: **0 errors**. RustCrypto ml-kem 0.2.3: 32 256 errors from 84 contexts, ALL one root cause — SamplePolyCBD (FIPS 203 Alg. 7) is a table lookup indexed by secret bits (`Eta::ONES[val.0 as usize]`, `algebra.rs:148`): a secret-dependent load plus its bounds-check branch, in encaps and in decaps' re-encryption (`kem.rs:97`). The table is 16 × u16 = 32 bytes (one cache line when aligned), so a practical cache attack is hard — but it is exactly what a constant-time review must not pass. Positive control (a branch on a classified byte) is flagged, so the harness is live. Marking keygen seeds too gives false positives by design (ρ is derived from d but public: matrix rejection sampling) |

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

## Finding: the shipping ML-KEM had a secret-indexed table lookup — fixed by upgrading (2026-11-08)

See the constant-time row. Upstream had already fixed it: RustCrypto ml-kem **0.3.3** (2026-10-17, Security:
"Eliminate secret-dependent CBD table lookups", RustCrypto/KEMs#386); **0.3.4** (2026-10-31) also hardens
equality, reduction and zeroization. heqk now ships **ml-kem 0.3.4** (kernel `securechannel`, `tlsprov` /
el0-tlshost, `responder-sim`) — within the decision to keep RustCrypto; libcrux stays the parallel candidate.

| Check on 0.3.4 | Result |
|---|---|
| ctgrind (`kem-diff/ctgrind/mlkem034`, `public-rho.supp` excuses only rejection sampling of the public matrix from rho) | **0 errors** (0.2.3 under the same file: 32 256, all SamplePolyCBD; libcrux: 0) |
| kem-diff 1000 seeds vs libcrux | 0 mismatches; transcript `eaad66b3…f6f4f9` **identical to the 0.2.3 pin** (byte-for-byte same outputs) |
| NIST ACVP | **180/180** (the 160 + 0.3.4's own encapsulation/decapsulation key checks agree with NIST's verdicts) |
| kem-diff fuzz 200 000 | 0 disagreements, 0 panics; 0.3.4 itself refuses all 33 510 keys failing FIPS 203 §7.2 |
| tlsprov tests (hybrid X25519MLKEM768 agreement, tampered key share refused) | 4/4 |
| responder-sim PQ-hybrid handshake selftest | transcript identical to the 0.2.3 build (wire-compatible) |
| kernel `[P19-pqc-kat]` pinned KAT, mc-e2e Chromium HTTPS (X25519MLKEM768) | PASS |

Found on the way: the kernel's build.rs did not rebuild the EL0 TLS host when `tlsprov` (a path dependency) or
its lockfile changed — a crypto change would have shipped a stale binary. It now tracks src/, the lockfile and
every `path =` dependency.

## Recommendation

Keep RustCrypto as the shipping ML-KEM. Next increments, in order: ACVP vectors + fuzz target (host), a
`tlsprov` backend switch behind a cargo feature (default off) with the SIMD guard, then the device gates
(stack, CM5 timing, Chromium interop over the metal HTTPS leg). Switch only when every row above is green.
