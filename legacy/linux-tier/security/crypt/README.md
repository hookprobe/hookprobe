# Data-at-rest encryption + unlock policy (ADR 0006 H3c)

**What is encrypted:** only the **data partition** (`/var/lib/hookprobe` — pcaps, events, evidence,
device keys). The **rootfs is NOT encrypted** — it's a public signed image; it gets **integrity** from
dm-verity (H3), not confidentiality. Encrypt where the secrets are; verify where the code is.

**LUKS2 + dm-integrity** on the data partition = Confidentiality **and** Integrity (authenticated
encryption). The open question is always *how does it unlock with no human at the console?*

## The invariant: network unlock is ADDITIVE, never required

This mirrors the whole product thesis — *the cloud/account layer is additive, never a precondition*.
Applied to disk: **a standalone / air-gapped device MUST unlock on its own.** So we never bind unlock
to Tang alone. The `enroll-clevis.sh` policy always keeps a **local** path, and every device keeps a
**recovery passphrase** keyslot so no policy can ever brick it.

## Policy matrix — chosen from what the device HAS (capabilities, not branches)

| Device | Clevis policy | Standalone / air-gapped? | Confidential at rest? |
|---|---|---|---|
| **TPM + fleet (Tang)** | `sss t=1 {tpm2, tang}` | ✅ unlocks via the **local TPM** | ✅ |
| **TPM, no network** (N100/appliance standalone) | `tpm2` (sealed to PCR 7,11) | ✅ **fully local** sealed unlock | ✅ |
| **No TPM + fleet (Tang)** (Pi in a fleet) | `tang` + recovery slot | ⚠️ networked = auto; air-gapped = **recovery passphrase** | ✅ (when unlocked) |
| **No TPM, no network** (Pi standalone, headless) | *(skip Clevis)* | ✅ boots — **integrity-only** (dm-verity) | ❌ *(see below)* |

## So — will standalone devices work on their own? **Yes.**

- **With a local root of trust (TPM / secure element)** — including a **~$10 TPM HAT on a Pi**, or the
  future **HookProbe silicon** — a standalone device unlocks **fully offline** via the `tpm2` pin,
  sealed to the boot-integrity PCRs. Confidential *and* air-gapped. This is the future-proof path.
- **Without any local root of trust** (bare Pi, no TPM, headless, air-gapped) there is a genuine,
  unavoidable trilemma: you cannot have **auto-unlock + confidentiality-at-rest + no-local-secret** all
  at once. We resolve it honestly and per policy:
  - **Default: integrity-only.** dm-verity makes the rootfs tamper-evident (fail-closed); the data
    partition is unencrypted or uses a keyfile. You get **Integrity + Availability** — correct when the
    threat model is the *network*, not physical theft (the common edge case).
  - **Opt-in confidentiality:** a recovery **passphrase** (needs a human once per boot) or a **keyfile**
    (auto, but the key is local → protects a *stolen data disk*, not a *stolen whole device*).
  - **Recommended:** fit a TPM/secure-element for standalone confidentiality — or wait for HookProbe
    silicon, which bakes the secure element in.

**Tang** (network-bound disk encryption server) runs on the **super-PoP / control plane**, not the
device — it's stateless (McCallum–Relyea, stores no keys). A fleet Pi auto-unlocks from it when
networked; the same Pi off-network falls back to its local pin or recovery slot. Additive, never
required — exactly like the rest of the cloud layer.
