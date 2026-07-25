# ADR 0045 — Default dev/test credentials: `hookprobe`/`hookprobe` gated, never in a release

**Status:** 🟡 **Proposed (2026-07-25)** — operator-review. Drafted under Phase-0 of the heqk migration (`docs/BuildPlan.md` Track C). Formalizes and hardens the existing ad-hoc test-access pattern (the Linux tier's `HOOKPROBE_DEBUG_ACCESS=1` → `andrei`/`DEV-CRED-SCRUBBED` SSH) into a governed, product-neutral policy that also covers the **heqk tier** (which today ships a software-constant AK and 7 demo syscalls, `kernel/heqk/buildPlan.md:185`). Every clause is tagged **[realized]** (already true in-repo), **[partial]**, or **[vision]**.
**Deciders:** security-auditor (author — from the G1–G5 findings), release-engineer (image/build gates), os-architect (heqk access surface), verification-engineer (the gate that enforces it), product-steward (this record), operator (ratification — **required; not yet given**).
**Relates to:** [ADR 0008](0008-rbac-admin-operator.md) (admin/operator RBAC — the identity model these creds must not bypass), [ADR 0028](0028-rbac-enforcement.md) (RBAC enforcement), [ADR 0006](0006-os-hardening.md) (OS hardening / SSH posture), [ADR 0016](0016-artifact-hash-signing.md) (trust-nothing-unsigned — a debug creds must never ride into a signed release), [ADR 0044](0044-zero-linux-rpi-native-cm5.md) (the zero-Linux CM5 tier whose access surface this scopes), [ADR 0046](0046-github-migration-and-key-custody.md) (companion — secrets must not enter the repo), `docs/BuildPlan.md` RBAC row + Change Log 2026-07-04 (`HOOKPROBE_DEBUG_ACCESS` gate landed).

> **One-line thesis:** a **known** dev/test credential (`hookprobe`/`hookprobe`) is a legitimate developer-velocity tool, but it is only safe if it is (1) **impossible to ship in a release**, (2) **fail-closed on the WAN**, (3) **forced to change before any real use**, and (4) **penalized in the security posture until removed.** Convenience never silently becomes an exposure.

---

## Context — why this ADR must exist

Two realities force a governed policy:

1. **The Linux tier already uses personal, hard-coded test creds.** Debug images enable SSH as `andrei`/`DEV-CRED-SCRUBBED` behind `HOOKPROBE_DEBUG_ACCESS=1` (BuildPlan Change Log 2026-07-04; `builder/mkosi-arm64/make-pi4-image.sh`). This is fine for a single-operator bench but is (a) a *personal* identity leaking into a product artifact, (b) undocumented as policy, and (c) one build-flag mistake away from a release. As the repo goes public (ADR 0046), that pattern must become a **product-neutral, auditable policy** — not a person's username.
2. **The heqk tier has no access model yet.** heqk ships a software-constant AK (`buildPlan.md:185` — "forgeable") and 7 demo syscalls. Before heqk grows a net stack (Track C M4) and any remote surface, the test-access posture must be decided **up front**, fail-closed, so a demo credential never becomes a shipped backdoor.

The security-auditor's G1–G5 findings (below) are the decision content.

## Decision

### D1 · The canonical dev/test credential is `hookprobe` / `hookprobe` — DEBUG images ONLY **[partial]** (G1)
Replace the personal `andrei`/`DEV-CRED-SCRUBBED` with a **product-neutral** `hookprobe`/`hookprobe` account, present **only** when the image is built with `HOOKPROBE_DEBUG_ACCESS=1`. Retires the personal identity from all build artifacts. The credential is **documented, expected, and boring** — its safety comes entirely from D2–D5, never from secrecy.

### D2 · It is structurally impossible to ship in a release **[vision → gate]** (G2)
A **release build ignores `HOOKPROBE_DEBUG_ACCESS` entirely**: no interactive user, root locked, SSH publickey-only or absent (Linux tier as today; heqk tier = no login surface). A release-blocking gate (**verification-engineer**, folded into the existing gate ladder / `release-pass.sh`) **greps the assembled rootfs/image for the debug account, a known-default password hash, and any `andrei`/`DEV-CRED-SCRUBBED` residue** and hard-fails the release if found. "Debug creds in a release image" is a RED breach, non-overridable (parity with ADR 0016's tamper-evidence bar).

### D3 · Forced change before first real use **[vision]** (G3)
On a debug device, the default password is a **first-login forced-change** (or the account auto-expires) — a device that has been *used* (net-connected, enrolled, or promoted past first-boot) must not still accept `hookprobe`/`hookprobe`. Standalone/air-gapped bench use may defer the change, but the posture penalty (D5) stays lit until it happens.

### D4 · No default-credential login over the WAN — ever **[vision]** (G4)
The debug account is **reachable only on the management/LAN plane**, never the WAN uplink, and never through the SASE tunnel. Fail-closed: if plane attribution is unavailable, the debug login is refused. This is the ADR 0023 "legit always passes, but a management-plane floor is not a WAN backdoor" discipline applied to credentials. On heqk, the same rule binds to the manifest's management-interface attribution.

### D5 · A live default credential is a QSecBit posture penalty **[vision]** (G5)
While `hookprobe`/`hookprobe` (or any known-default) is active and unchanged, the device's QSecBit / posture score carries an explicit, operator-visible **penalty with a named reason** ("default debug credential active — change or remove"). The score cannot read "green" with a live default credential. This makes the convenience *self-advertising* and gives the operator a standing nudge to close it.

### D6 · Keys and real secrets are never in this class **[realized principle]**
This ADR governs **dev/test login convenience only.** Signing keys, TLS material, and device identity are out of scope here and governed by ADR 0016/0002/0046 (keys-never-in-repo, cosign-keyless-OIDC). A default *password* is a bounded, penalized, LAN-only, release-excluded convenience; a default *key* is never acceptable.

---

## Consequences / risks
- **Developer velocity preserved** — a known bench credential stays available, just governed.
- **Public-repo safe** — no personal identity, no secret, and a documented policy reviewers can audit (feeds ADR 0046's gitleaks gate: the *policy* is public, the *password* is a well-known default, neither is a leaked secret).
- **The gate is the enforcement, not the doc** — D2's rootfs grep must exist in the gate ladder before the first public release image, or this ADR is theatre (the exact failure mode ADR 0016 was written to prevent).
- **heqk residual** — until heqk has a real identity/login surface, "no login surface" is the safe default; this ADR pre-commits heqk to fail-closed access rather than retrofitting it after a net stack lands (M4).

## Alternatives considered
- **Keep `andrei`/`DEV-CRED-SCRUBBED`.** Rejected: a personal identity in a product artifact, unauditable as policy, and embarrassing/leaky once public.
- **No default credential at all (keys-only everywhere, even debug).** Rejected as the *default* dev path — too much friction for bench iteration; but it is exactly the *release* posture (D2), so this ADR is really "keys-only in release, governed password in debug."
- **A random per-build password printed at build time.** Considered; better secrecy but worse reproducibility/usability and still needs D2/D4/D5. A known default + strong gates is simpler and honest. Revisit if debug images ever leave the single-operator bench.
