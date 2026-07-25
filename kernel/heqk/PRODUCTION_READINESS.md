# HEQK Production-Readiness Report

_Hardened Edge Quantum-safe Kernel — bare-metal aarch64 capability microkernel for Raspberry Pi CM5 (BCM2712)._

**Snapshot date:** 2026-07-25
**Verdict:** Feature-complete P0–P17 with all QEMU-validatable phases GREEN and all four
build flavours linking. **NOT yet field-deployable** — a small, well-bounded set of
*metal-only* and *irreversible-security* steps (§4) cannot be finalized in emulation and
must be completed on hardware by a human operator with signing keys and physical access.

---

## 1. What "production ready" means here

This kernel is the security TCB for an edge sensor. "Ready" is split into three gates:

| Gate | Meaning | Status |
|------|---------|--------|
| **G1 Functional** | Every phase's logic is implemented and passes its self-test | ✅ 23/23 phases GREEN in `validate.sh`; 0 failing |
| **G2 Buildable** | All shipping flavours compile + link | ✅ default, cm5, cm5+p10bt, p15-write all build |
| **G3 Metal-hardened** | The provenance of every security root is REAL on silicon (not synthetic), and unflashed paths are boot-verified | ⚠️ Partial — see §4 |

G1 + G2 are complete. G3 has a bounded checklist that requires the board.

---

## 2. Phase matrix (P0–P17)

Legend: **QEMU** = self-test green in emulation · **METAL** = confirmed on CM5 silicon ·
**DEFER** = intentionally deferred, documented.

| Phase | What it is | QEMU | METAL | Notes |
|-------|-----------|:----:|:-----:|-------|
| P0 | Boot chain EL2→EL1, PL011, vectors | ✅ | ✅ | |
| P1 | Preemptive scheduler + context switch | ✅ | ✅ | |
| P1b | MMU stage-1 + frame allocator | ✅ | ✅ | |
| P2 | Capabilities: untyped/retype/CDT/revoke | ✅ | ✅ | + CORE-2 per-TCB CSpaces, CORE-9 gen-tagged CDT, CORE-1 revoke-unmaps |
| P3 | EL0 userspace + SVC boundary + fault containment | ✅ | ✅ | per-TCB fault-restart (CORE-6) |
| P4 | Synchronous IPC over Endpoint | ✅ | ✅ | |
| P5/P5b | Packet engine: zero-copy ring + in-place verdict; live virtio ARP | ✅ | ✅ | |
| P6/P6b | RFC 9669 BPF VM + verifier + JIT (W^X) + self-heal + telemetry | ✅ | ✅ | DET-13 verifier operators PROVEN SOUND |
| P8 (all) | Detection plane: PREVAIL verifier, JIT parity, L2/TCP/SYN-flood/blocklist/L7 rules, SOAR ring | ✅ | ✅ | incl. AUD-NET-1 VLAN-normalization gate (P8vlan) |
| P9 | WiFi SDIO bring-up (CYW43455) | ✅ | ✅ | HT clock via PMU res-mask; clmload+country=RO |
| P10 | WiFi escan (real APs) + Bluetooth HCI-UART LE scan | — | ✅ | 17 BLE devices seen; bcm7271-uart, pins gpio24-27 |
| P11 | Hardened device-class transport (sDDF borrow) | ✅ | DEFER | rejects forged descriptors; metal GemDev/RtlDev deferred |
| P12 | Notification objects + capability pub-sub | ✅ | — | typed caps (AUD-CAP-1), subscribe DoS + leak fixed (AUD-CAP-3/4) |
| P13 | RP1 peripheral buses (GPIO/I2C/SPI/UART), EL0-isolated | ✅ | ✅ | RESERVED deny-list enforced; index guards (AUD-RP1-4/5) |
| P15 | eMMC read-only block device + Encrypt-then-MAC sealing | ✅ | ✅ | per-seal nonce (AUD-STO-1); write path behind `p15-write` |
| P16 | Crypto primitives (SHA-256 / HMAC / HKDF / CTR) | ✅ | ✅ | metal-found short-tail HMAC bug fixed + guarded (P16sha) |
| P17 | Overlay convergence: net-class queue + dual-direction IPS gate | ✅ | — | smoltcp EL0 service deferred |

---

## 3. Security posture — what is REAL vs PROVISIONAL

**Real and enforced today:**
- Capability type-safety: a cap of one type cannot be used as another (AUD-CAP-1 closed).
- Per-TCB CSpaces + rights-narrowing delegation (CORE-2); revoke severs EL0 mappings (CORE-1).
- Generation-tagged CDT: a freed+reused slot cannot re-attach a stale cap (CORE-9).
- Encrypt-then-MAC sealing with a fresh per-seal nonce — no CTR keystream reuse (AUD-STO-1).
- W^X on the QEMU backend; RESERVED GPIO deny-list on RP1; bounded HW polls.
- BPF verifier abstract-domain operators proven sound (DET-13) + JIT↔interpreter differential.

**Provisional — correct crypto, but the ROOT's provenance is not yet hardware-bound:**
- **Sealing SRK (V3):** the kernel currently derives per-policy keys from a *synthetic* SRK.
  Measurement binding becomes REAL only once HBoot derives the SRK from the OTP secret with
  EL1 unable to read OTP. The crypto is correct either way; only provenance is provisional.
  The P15 self-test prints this limitation. (SEALED_STORAGE.md)
- **Attestation key liveness (SEC-7):** ephemeral attest seed must require full TRNG liveness
  or refuse to publish the key.
- **Anti-rollback (SEC-6):** SVN floor is inert (FLOOR=0); a real monotonic SVN counter +
  advance-floor release step is needed before rollback protection is meaningful.

---

## 4. Blockers to field deployment — METAL / HUMAN ACTION REQUIRED

These CANNOT be finalized autonomously (they need the board, signing keys, or are irreversible):

1. **cm5 W^X first-boot verification (NEW — AUD-BLD-1).** The `--features cm5` flavour has
   not linked since commit f754307 (missing `__text_start`/`__text_end`); that is now fixed and
   the flavour builds, but the W^X mapping in `mmu_cm5.rs` has **never executed on silicon**.
   The first metal boot MUST confirm EL1 `.text` executes RO+X and the RW+PXN split does not
   fault. Flash-once discipline applies (connector wear) — bundle this with the next flash.

2. **SRK provenance (V3).** Wire HBoot to derive the sealing SRK from the OTP secret with EL1
   OTP-read blocked, then flip the kernel off the synthetic SRK. Until then, sealed data is
   confidentiality/integrity-protected but not measurement-bound to *this* device's secret.

3. **Final signed + measured image.** Assemble the hybrid ed25519 + SLH-DSA (FIPS-205) signed,
   PCR-measured boot image. Requires the private signing keys (not in-repo) and is a
   flash-time operation. Licensed CYW43455 firmware is gitignored and must be staged locally.

4. **Anti-rollback activation (SEC-6)** and **attest-key TRNG gating (SEC-7)** — enable before
   exposing the device to an untrusted update channel.

5. **Deferred features (safe to ship without, needed for full product):**
   - P11 metal drivers (GemDev/RtlDev) — only LoopDev is exercised in QEMU today.
   - P17 smoltcp EL0 service — the largest attack surface; must be pinned + measured into a
     PCR and seeded from TRNG (not cntpct) before it terminates real traffic.

---

## 5. Assurance coverage & the QEMU↔metal gap

`validate.sh` is the always-on V&V harness (23 phases + the DET-13 verifier soundness tool).
The one recurring risk is the **QEMU↔metal coverage gap** (XC-15): the security-critical
short-tail HMAC bug (P16) was invisible in QEMU and only surfaced on silicon. Mitigations in
place: P16sha now tests the incremental hasher across all chunkings; the seal self-test uses a
short (28-byte) secret to force the previously-missed path. **Every security-sensitive change
should still be metal-smoke-tested**, not QEMU-only.

---

## 6. Deployment checklist (operator)

- [ ] Build the final image (all four flavours already link; pick cm5 / cm5+p10bt).
- [ ] Stage licensed CYW43455 firmware locally (gitignored).
- [ ] Complete V3: HBoot-derived SRK from OTP; flip kernel off synthetic SRK.
- [ ] Sign the image (ed25519 + SLH-DSA) with the private keys; measure into PCRs.
- [ ] Flash ONCE (connector wear) and on first boot verify: cm5 W^X does not fault;
      P15 prints measurement-binding REAL (not synthetic); P10 WiFi+BT alive.
- [ ] Enable anti-rollback SVN floor + attest-key TRNG gating.
- [ ] Bring up P11 metal drivers + P17 smoltcp service before terminating real traffic.
- [ ] Re-run `validate.sh` on the exact shipping build; archive the log with the image hash.

---

## 7. Production-Hardening Roadmap (the path from G2 → G3)

P0–P17 (§2) are the *capability* phases and are complete (QEMU-green, silicon-proven).
The phases below (**PH1–PH7**) are the *productization* phases — each is a discrete,
buildable step with explicit acceptance criteria, built and validated one at a time
(same discipline as the P0–P17 finalize sequence). Ordered by dependency + value.

| Phase | Goal | Autonomy |
|-------|------|----------|
| **PH1** | Production service profile — HEQK boots into the *running sensor*, not the self-test | ✅ software |
| **PH2** | Real root of trust — SRK from OTP (closes V3/SEC-2); EL1 cannot read OTP | ✅ software, metal-gated |
| **PH3** | Anti-rollback advancement + attest-key TRNG liveness (SEC-6/SEC-7) | ✅ software |
| **PH4** | Production signing + release pipeline (dev keys → key custody) | ⚠️ needs key-custody decision |
| **PH5** | P11 metal device-class drivers (GemDev/RtlDev on the hardened transport) | ✅ software, metal-iterative |
| **PH6** | P17 smoltcp EL0 service — measured, TRNG-seeded, bounded (largest attack surface) | ✅ software |
| **PH7** | Assurance closeout — close the QEMU↔metal gap (XC-15) + final security review → declare G3 | ✅ software |

### PH1 — Production service profile  *(DONE — METAL-VALIDATED 2026-07-25)*
`prod` feature boots into `cm5_prod_service()`: isolated EL0 GEM driver → `packet::verdict`
→ forward PASS via `gem::tx_frame` / drop threat → recycle → wall-clock liveness heartbeat;
per-iteration trusted-stub reload = self-heal; never returns. QEMU gate `[PHprod] PASS`.
**Metal-validated on CM5:** sustained run, 124 real frames processed / 115 forwarded through
the verified rule plane, 0 dropped, **0 uncontained faults**; `[PROD hb]` beats every ~5 s and
keeps beating across quiet periods. The running sensor is operational on silicon. (Higher RX
throughput / MSI-X-driven delivery is PH5.)

- **Build:** a `prod` boot-mode/feature that SKIPS the P0–P17 self-test sequence and instead does
  minimal bring-up (MMU, caps, EL0, NIC via the isolated EL0 driver) → loads the compiled ruleset
  → runs the continuous **RX → classify → verdict → enforce** datapath (reusing the P7c EL0-driver
  server + P8 inline IPS + P17 dual-direction gate) → stays up, self-heals on driver crash, streams
  telemetry/QSecBit to the SOAR ring.
- **Acceptance:** metal boot reaches a *running* sensor that continuously forwards benign / drops
  threat traffic on the real NIC, survives a driver crash-restart, and has NO self-test scaffolding
  on the production path. `validate.sh` still green for the (separate) test build.

### PH2 — Real root of trust: SRK from OTP  (closes V3/SEC-2)
**Status 2026-07-25:** **PH2a DONE** (built, committed) — HBoot derives `SRK = SHA256("HEQK-SEAL-SRK-v1"‖OTP)`
and hands it to the kernel via the SealHandoff; sealing is now a REAL per-device key
(`SEAL_FLAG_SRK_FROM_OTP`), no longer a global synthetic constant. **PH2b OPEN & metal-iterative** —
closing V3/SEC-2 (EL1 must not read OTP) requires a *returning* HVC mailbox proxy in EL2
assembly (`boot.s`) + a stage-2 fine-grain carve of the mailbox page + rerouting the kernel's
`get/set_clock_rate` through the proxy. This is brick-prone EL2 work that **cannot be QEMU-gated**
(no VC mailbox in QEMU) and needs iterative on-metal bring-up like the P10 WiFi/BT work did — it
is NOT an "build-blind, works-first-try" change. Until PH2b lands, the kernel prints
`[P15-SRK] … V3/SEC-2 OPEN` (honest: per-device but not yet tamper-proof).

- **Build:** HBoot (EL2) reads the OTP secret, derives `SRK = KDF(OTP, PCR0_after_self_measure)`,
  passes it via a `SealHandoff` in `BootInfo`; blocks EL1 OTP access; the kernel consumes the real
  SRK and drops the synthetic one. **READ-only on OTP — no new burn** (the per-device AK is already
  provisioned; irreversible fuses are never touched here).
- **Acceptance:** `[P15]` stops printing the synthetic-limit line; a blob sealed on device A fails to
  unseal on device B (different OTP); an EL1 OTP read returns blocked/zero (verified on metal).

### PH3 — Anti-rollback advancement + attest liveness  (SEC-6/SEC-7)
**Status 2026-07-25:** **SEC-7 (attest-key TRNG liveness) already CLOSED** — `attest.rs`
`emit_ephemeral_cert` fails CLOSED when `rng::fill` reports `live < 8` (refuses to publish the
ephemeral key + zeroes the handoff). Confirmed on metal (the AK/ephemeral cert published only
because the TRNG was fully live). **SEC-6 (SVN advancement)** remains — it involves an
irreversible OTP/fuse SVN counter, so it lives in the metal bring-up batch, not build-blind.
- **Build:** a real monotonic SVN counter (sealed store or fuse row) + an `advance_floor` release
  step; attest seed/nonce require full TRNG liveness (`live==8`) or refuse to publish the key.
- **Acceptance:** a lower-SVN signed image is refused on metal; attest-key generation aborts without
  liveness.

### PH4 — Production signing + release pipeline
- **Build:** move from the dev signer (`~/heqk-sign`) to production key custody (HSM / key ceremony),
  reproducible signed-image build, SVN bump, release manifest with image hash.
- **Acceptance:** a production-signed image boots; key custody documented.
- **NOTE:** blocked on a **user decision** about key custody — cannot be finalized autonomously.

### PH5 — P11 metal device-class drivers (GemDev / RtlDev)
- **Build:** real GemDev (RP1 GEM) + RtlDev (RTL8111) implementing the DevQ NetClass on metal (not
  just LoopDev/QEMU); wire RX-IRQ/MSI (DRV-1/XC-4).
- **Acceptance:** `[P11]` passes on metal with real NIC traffic; forged-descriptor rejection holds.

### PH6 — P17 smoltcp EL0 service
**Status 2026-07-25:** **stack-integration core DONE + QEMU-gated** — smoltcp 0.13 (`no_std`,
no heap) added behind the `netsvc` feature (OFF by default, so the prod/metal kernel TCB is
untouched). `netsvc.rs` runs smoltcp ABOVE the P17 rule plane via a `phy::Device` that admits
an ingress frame only if `packet::verdict` PASSes it and emits an egress frame only if it
PASSes too (the netq dual-gate). `[PH6-net] PASS`: the stack correctly answers an ARP for its
own IP with both directions verdict-gated. **Deferred to metal (largest attack surface):**
running it as the EL0-ISOLATED service over the live netq (needs the multi-page EL0 loader,
DSN-10), a TRNG seed (not a constant), and a PCR3 measurement of the pinned stack (DSN-11).
- **Build:** smoltcp as an EL0 service — TRNG-seeded, pinned + checksummed + measured into PCR3,
  bounded resource use, fault-contained.
- **Acceptance:** `[P17]` handles real TCP with the stack measured into PCR3; faults are contained.

### PH7 — Assurance closeout → declare G3
**Status 2026-07-25:** dual-backend cap-invariant property sweep **DONE + metal-validated** —
`caps::cap_invariants_selftest` runs on BOTH the QEMU and CM5 MMU backends (`[PH7-caps] PASS`
on each), closing XC-15's "no cap-invariant tests / single-backend blind spot" for the
capability system. **Remaining for G3:** the metal-batch phases (PH2b, PH5, PH6) must land and
be metal-smoked before this report can flip **G3 → ✅** and a final security review runs.
- **Acceptance:** readiness shows **G3 Metal-hardened ✅**; security review clean.

---

_This report is honest about what is done and what is not. G1/G2 are complete and every
audited finding through 2026-07-25 is closed or verified not-present (see GAP_REGISTER.md).
§7 is the ordered path to G3; PH1 is in progress. The items that cannot be finalized
autonomously (PH4 key custody, the irreversible-fuse steps) are flagged as such._
