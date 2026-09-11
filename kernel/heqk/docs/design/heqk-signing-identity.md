# heqk — signing, trust roots, and device identity

> **Status: reconstructed 2026-09-11 from the authoritative in-tree sources.** The
> source of truth is the CODE, not this prose. Canonical sources:
> `boot-abi/src/verify.rs` (the shared hybrid verifier + embedded trust root),
> `cm5-boot/mkimage-hboot.sh` + `builder/make-cm5-heqk-image.sh` (the signing
> pipeline), `kernel/src/{ota,seal,securechannel}.rs`, `hboot/`, `SEALED_STORAGE.md`,
> `validate.sh` (`[HBoot-AB]`, `[P15-*]`, `[P16-sha]`, `[P19-noise]`), and
> `PRODUCTION_READINESS.md` (PH4). This file was cited by `PRODUCTION_READINESS.md`
> and the ADR 0002 heqk-coupling note before it existed; reconstructed so the canon
> reference resolves.

## 1. Two trust roots, deliberately distinct, ONE custody process

heqk's boot key and hookprobe-os's module-signing key are **different keys in
different algorithm families**, and must stay that way — but they must be
**co-rooted under one governed custody process** (NOT one shared key). This is the
ADR 0002 heqk-coupling note in one line.

| Root | Algorithms | Signs | Verifier |
|------|-----------|-------|----------|
| **heqk boot root** (this doc) | hybrid **Ed25519 + SLH-DSA-SHA2-128s** (FIPS 205 — stateless hash-based PQ, NOT ML-DSA) | the `heqk8.img` payload (kernel) with an SVN | `boot_abi::verify` — embedded in HBoot (EL2) and reused byte-identically by on-device OTA |
| hookprobe-os module root (ADR 0016/0017) | hybrid **ML-DSA-65 + Ed25519** | Wasm modules / native binaries on the Linux/UEFI tier | the Linux-tier supervisor |

Why SLH-DSA for boot: a boot root is long-lived and must survive a future
signature-scheme break; SLH-DSA's security rests only on the hash function
(conservative, stateless, no key-state to corrupt on-device). Why the split: a
compromise of one tier's key must not sign the other tier's artifacts.

## 2. The boot trust root (`boot-abi/src/verify.rs`)

- **Embedded public keys:** `TRUSTED_ED25519_PUBKEY` (classical half) and
  `TRUSTED_SLHDSA_PUBKEY` (post-quantum half) are compiled into HBoot.
- **Signed message:** `SHA-256( LE64(svn) || sha256(payload) )` via `digest_signed`
  — the SVN is BOUND into what is signed, so a signature cannot be replayed onto a
  different version.
- **Acceptance rule:** BOTH signatures must verify **AND** `svn >= floor`
  (anti-rollback). Either failing ⇒ refuse to boot / refuse to stage.
- **One verifier, two callers, no second trust root:** HBoot verifies at boot; the
  on-device A/B OTA orchestrator (`ota.rs`, `[P15-ota]`) verifies a fetched candidate
  with the SAME `boot_abi::verify` + SAME embedded root BEFORE staging it to the
  INACTIVE slot only. A candidate with a bad signature is rejected verify-before-flip
  (no inactive-slot write, active slot + tryboot flag untouched); a below-floor
  candidate is refused (SVN floor). The M4.3 enrolled channel is transport only — a
  compromised MSSP still cannot ship an image the root would reject (`[P19-enroll]`(e)).
- **A/B + trial boot** (`[HBoot-AB]`): the kernel confirms health (`hvc #1` disarms
  HBoot's EL2 watchdog) or firmware falls back to the known-good slot. Operationally:
  flash slot A only; keep the known-good slot B as the brick net.

## 3. The signing pipeline

- `cm5-boot/mkimage-hboot.sh` hybrid-signs the kernel payload (Ed25519 sig 64 B +
  SLH-DSA sig 7856 B, self-verified after signing) and packs `heqk8.img` =
  HBoot + header (sigs + svn) + payload.
- `builder/make-cm5-heqk-image.sh` invokes it; **fail-closed `HEQK_KEYDIR`** — the
  build refuses to sign with an unset/absent key directory rather than silently
  falling back.
- **Release-blocking dev-key gate:** today the DEV signer at `~/heqk-sign` is used;
  a release build is blocked from shipping dev-key-signed images (M1 CI gate,
  `build-heqk.yml`). `HOOKPROBE_DEBUG_ACCESS=1` is required to pass the gate for
  validation/diagnostic images.
- **Open decision — PH4, production key custody** (`PRODUCTION_READINESS.md`): the
  pipeline is realized; what remains is the governed custody model — HSM vs offline
  key ceremony vs KMS — under which the heqk boot root and the hookprobe-os module root
  are **co-rooted** (one process, two keys). "One decision from done." This is an
  operator/governance decision, not code.

## 4. Device identity — the PUF-anchored attestation key

- The device authenticates itself on the M4.2b Noise channel with an **Ed25519
  transcript signature over `h`** (`[P19-noise]`) using the `attest_svc` key model —
  the "software-PUF" device key that anchors enrollment (`enroll.rs`: device Ed25519 ⟷
  enrolled MSSP static; mutual auth).
- **Known gate:** the attestation private keys live in the tracked `attest_keys.rs`
  today; the release gate blocks that from shipping (M1). Production device identity
  must be per-device and generated/sealed on-device — the OTP/sealed-store path below
  is its home.

## 5. Sealed storage, the SRK, and OTP (why the boot root and the on-device secrets don't mix)

- Data at rest is sealed with **`HQKSEAL1` Encrypt-then-MAC** (SHA-256 HMAC / HKDF /
  CTR; `seal.rs`, `[P15-seal]`); tamper and wrong-measurement are refused. The
  DataVolume is a crash-safe log-structured record store (`[P15-fs]`) whose payloads
  are sealed under a **Volume Encryption Key that is itself sealed in the keystore**
  (`[P15-sealfs]`); a flipped ciphertext byte is MAC-rejected at mount, and the VEK +
  evidence survive reboot.
- The **Storage Root Key is derived from OTP inside HBoot at EL2 (SEC-2 / V3)**; the
  EL1 kernel can neither re-read OTP nor bypass the EL2 mailbox proxy (`hvc #2`
  6-tag whitelist refusing OTP/serial; the mailbox page is INVALID to EL1 via the
  stage-2 carve). So a compromised EL1 kernel cannot recover the SRK — the sealed
  store and attestation are tamper-proof on-device (metal-proven 2026-09-10,
  `[P-sec2-carve]`, `[P15-BOUND]`).
- The `[P16-sha]` incremental-SHA-256 gate guards the metal-found short-tail HMAC
  authentication bug — the standing reason every crypto primitive here is KAT-gated.
- **Brick-safety** (`[P15-guard2]`): the write allowlist REFUSES LBA 0/MBR + the
  ACTIVE boot slot + unregistered gaps; only keystore / DataVolume / the INACTIVE slot
  are writable. A signed image can only ever land in the inactive slot.

## 6. What is proven vs open

| Item | Status |
|------|--------|
| Hybrid Ed25519+SLH-DSA boot verify, SVN-bound, anti-rollback, one shared verifier | proven (QEMU + metal boots) |
| A/B trial boot + fallback | proven (`[HBoot-AB]`, metal) |
| OTA verify-before-flip to the inactive slot, brick-safety guard | proven (`[P15-ota]`, `[P15-otafat]`, `[P15-guard2]`) |
| SRK from OTP at EL2, EL1 blocked (SEC-2) | proven on metal 2026-09-10 |
| Sealed VEK + evidence surviving reboot | proven (`[P15-sealfs]`) |
| Production key custody (HSM / ceremony / KMS) + co-rooting | **OPEN — PH4 governance decision** |
| Per-device generated + sealed attestation identity (replace tracked `attest_keys.rs`) | open (release-gated) |
| ML-DSA-65 co-signature on the secure channel (#10), CBOM `kem-0.3.0-pre` (#4) | open, tracked |
| SVN floor advance = irreversible OTP fuse burn (SEC-6 / PH3) | **must never be autonomous** |
