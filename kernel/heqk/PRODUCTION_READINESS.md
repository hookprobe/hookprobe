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

_This report is honest about what is done and what is not. G1/G2 are complete and every
audited finding through 2026-07-25 is closed or verified not-present (see GAP_REGISTER.md).
The remaining work in §4 is bounded, metal-gated, and largely tied to hardware roots of trust
and signing keys that must not — and cannot — be exercised from an emulator._
