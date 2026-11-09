# heqk decision register — 2026-11-08 (operator)

Principles: (1) no irreversible hardware change until the software security model and recovery are
independently validated; (2) nothing ships to end users merely because it works on the bench — production
needs secure provisioning, safe defaults and a defined recovery path. Priority: a production-ready,
recoverable, secure CM5 appliance over feature count.

| Item | Decision | Record |
|---|---|---|
| G14 Mission Control writes | **ACCEPT WITH MODIFICATIONS** — reversible, TTL-bound authenticated operations; permanent security policy stays signed | ADR 0053 (accepted, safeguards S1–S7) |
| G12 shipping Wi-Fi AP | **ACCEPT** — unique per-device credentials, secure onboarding, management isolation; production release gated on provisioning + isolation tests | ADR 0054 |
| RPMB anti-rollback | **DEFER** — do not program the irreversible eMMC RPMB key; keep the compile-time SVN floor active, retain the OTP thermometer design (no further fuse programming); irreversible provisioning = a separate, explicitly approved manufacturing/release operation | this file §A |
| PQC (libcrux) | **CONDITIONAL ACCEPT** — integrate in parallel behind the existing ML-KEM interface; switch only after FIPS 203 vectors, no_std/CM5 build, bounded memory, CM5 benchmarks, Chromium hybrid interop, differential + fuzz + secret-handling review pass. Keep X25519MLKEM768 hybrid; never ML-KEM alone | this file §B |
| G17 IPv6 WAN | **APPROVE** — staged: G17.1 static + link-local + ND, G17.2 SLAAC/RA, G17.3 DHCPv6 + PD, G17.4 forwarding/firewall/failover; routed prefixes + stateful firewall (no default NAT66); IPv6 must pass the same adversarial tests as IPv4 | after Phase 1 |
| G24a/G18 IPv6 identity + detection | **APPROVE DESIGN** — joint architecture; implement after G17. Identity from device/link-layer/ND/DHCPv6 bindings with validity + confidence, never the IPv6 address alone; detection consumes identity | after G17 |

Roadmap: Phase 1 security foundations (G14, AP provisioning, SVN advancement procedure validated, SEC-3
plan) → Phase 2 crypto assurance (libcrux parallel) → Phase 3 IPv6 (G17) → Phase 4 identity +
detection (G24a/G18) → Phase 5 production readiness (flasher + owner CA, onboarding, recovery/reset,
update/rollback, full CM5 acceptance). The Nov 7 metal results (HTTPS, VLANs, firewall, Mission Control)
are preserved as explicit regression gates (`heqk-metal-test-plan.md` §R).

## A. Anti-rollback — the record straightened out (doc drift fixed)

Three different floors were being described as one item:

| Floor | What it protects | State |
|---|---|---|
| Boot image SVN, compile-time | an older signed heqk image | **active** — `hboot/src/rollback.rs` `COMPILE_FLOOR = 1` |
| Boot image SVN, BCM2712 OTP thermometer | the same, as a one-way hardware counter | **designed + implemented as a path** (`hardware_floor()`, fail-closed watermark, `advance_floor()`); `hardware_floor()` reads 0 until fuses are blown; **no further fuse programming** (decision) |
| Boot image SVN, eMMC RPMB | the same | **not implemented** (needs an SDHCI/RPMB driver; `emmc.rs` deliberately excludes RPMB/partition commands) — **deferred** |
| POLICY.TXT generation floor (ADR 0049 D1) | an older signed policy file | compile-time floor in the image (`HEQK_POLICY_GEN_FLOOR`); a persisted floor would need RPMB or OTP — **deferred** with RPMB |

SEC-2 (EL1 reading OTP via the VC mailbox) is **closed** (metal, 2026-09-10: EL2 mailbox proxy +
stage-2 carve). SEC-3 (BCM2712 signed boot not enabled → first stage TOFU) is **open**; enabling it
programs boot-key fuses (irreversible) — it needs the same approved manufacturing/release operation as
any fuse step. `GAP_REGISTER.md` is historical (July) and still lists SEC-2 open.

## B. PQC migration gates (libcrux)

FIPS 203 KATs incl. the published errata · same `heqk-tlsprov` interface · aarch64-none no_std build ·
peak allocation bounded and measured · encaps/decaps timing on CM5 vs RustCrypto `ml-kem` · Chromium
X25519MLKEM768 handshake from the e2e browser leg + metal · differential test vs `ml-kem` on random
seeds · fuzzing of decapsulation inputs · secret zeroization review. Default switches only when all pass.
