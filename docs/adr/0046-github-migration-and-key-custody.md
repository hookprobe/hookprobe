# ADR 0046 — GitHub migration: git-history inheritance, key custody, and the secret-leak gate

**Status:** 🟡 **Proposed (2026-07-25)** — operator-review. Drafted under Phase-0 of the heqk migration (`docs/BuildPlan.md` Track C). Records the decision for taking `hookprobe-os` (a monorepo that now inlines the heqk microkernel) to GitHub **without losing heqk's history and without leaking a single key.** This ADR is a **decision record only** — it authorizes no Red git operation (no `git rm`, no history rewrite, no key rotation, no subtree import, no push); those are Amber/Red steps the operator runs after ratification. Clauses tagged **[realized]** / **[partial]** / **[vision]**.
**Deciders:** release-engineer (author — CI/CD + variants + custody), security-auditor (secret-leak surface, G1–G5), os-architect (monorepo boundary vs heqk), product-steward (this record + history-integrity governance), operator (ratification + all Red execution — **required; not yet given**).
**Relates to:** [ADR 0043](0043-heqk-microkernel-substrate.md) (the heqk relocation into `kernel/heqk/` this preserves the lineage of), [ADR 0044](0044-zero-linux-rpi-native-cm5.md) (the zero-Linux CM5 epic whose CI this stands up), [ADR 0016](0016-artifact-hash-signing.md)/[ADR 0002](0002-crypto-agility-pqc.md) (signing keys — cosign-keyless is the custody answer), [ADR 0045](0045-default-dev-test-credentials.md) (companion — no dev secret enters the repo either), [ADR 0012](0012-release-definition-cortex-pass.md) (the release/CI pass GitHub Actions must run), [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md) (verifiable-build north star the public repo enables). Evidence: parent repo has **2 commits** (`git rev-list --count HEAD` = 2); no `.git`/`.bundle` under `kernel/heqk/`; the `kernel/heqk/.claude/worktrees/*` are orphaned worktrees of the deleted heqk repo.

> **One-line thesis:** the monorepo was git-init'd fresh (2 commits) and **heqk's 316-commit lineage is not in it** — before any public push we must (1) **prove or graft** that history, (2) **purge and rotate any key that ever touched a working tree** *before* import, and (3) **gate every future push** so a secret can never land in a public object. History integrity and key custody are governance-critical (losing history / leaking a key are both irreversible).

---

## Context — why this ADR must exist before the push

Three findings from Phase-0 discovery:

1. **The 316-commit heqk history is unaccounted-for in-tree.** ADR 0043's header and `docs/MIGRATION-heqk.md:11` assert heqk was relocated "own git repo, 316 commits + licensed firmware preserved." On disk: the parent monorepo has **2 commits**, there is **no `.git` and no `.bundle`** under `kernel/heqk/`, and the worktrees are orphaned. So heqk's lineage is either preserved **outside this tree** (a bundle/clone elsewhere — unverified) or **lost**. Per product-steward governance, **deleting history is Red** — this must be resolved, not assumed.
2. **A public push is a one-way secret exposure.** Once an object with a key is pushed to GitHub, rotation is the *only* remedy (deletion doesn't undo forks/caches). The custody posture must be decided and gated **before** the first push.
3. **The repo carries a licensed firmware blob and its own `.github` CI.** heqk ships `LICENSE`/`LICENSING.md` and `.github/workflows/validation-matrix.yml`; the parent has `.github/workflows/{gate-ladder,build-os,build-modules,manifest-validate}.yml`. GitHub-readiness means reconciling these, not just `git push`.

## Decision

### D1 · Monorepo, heqk inlined — history inherited by git-subtree import **[vision]**
`hookprobe-os` stays a **single monorepo** with heqk at `kernel/heqk/` (already the on-disk layout, ADR 0043 M1). heqk is **not** re-split into a submodule (the whole point of the Product Cortex is one governed lifecycle). heqk's 316-commit history is **inherited via `git subtree add --prefix=kernel/heqk <heqk-source>`** (or an equivalent graft/`replace`), so `git log kernel/heqk/` shows real lineage instead of one squashed import. **Prerequisite (D2): the source history must first be located and scanned.** If it genuinely cannot be recovered, the fallback is an **explicitly-recorded, operator-accepted snapshot import** with a `HISTORY.md` note stating the lineage break and why — never a silent squash presented as history.

### D2 · Locate + scan the heqk source history BEFORE import **[vision]** — Red, operator-run
Before any subtree import: (a) **find** the authoritative heqk repo/bundle (the pre-relocation clone); (b) run a **full-history secret scan** (`gitleaks detect --log-opts=--all`, `trufflehog git`) over *every* object, not just the tip; (c) enumerate any committed keys/tokens across the whole DAG. Import is blocked until the scan is clean or every finding is triaged. **product-steward** records the outcome; **security-auditor** signs off.

### D3 · Purge + rotate any key that ever touched a tree — BEFORE import, not after **[vision]** (G-custody)
Any signing/TLS/identity key found in history (heqk's or the parent's — e.g. a `release.key`) is (1) **rotated** (a fresh keypair minted, trust store re-baked, artifacts re-signed) and (2) **purged from history** (`git filter-repo --invert-paths`) *before* the object reaches GitHub. Rotating *after* a push is too late. This is Red and operator-run; this ADR only records that it is a **hard precondition of the first push.**

### D4 · Keys are never in the repo — cosign-keyless OIDC is the custody model **[partial]**
The steady-state answer to "where do keys live" is **not** "encrypted in the repo" — it is **keyless**: image signing is cosign-keyless ECDSA-P256 via OIDC (already the posture, BuildPlan Supply-chain row), and the ML-DSA-65/Ed25519 module-signing private keys live in **CI secrets / an operator keystore**, referenced by the build, never committed. Public keys and trust stores *are* in the repo (they are meant to be public). `.gitignore` fences the private material (already hardened this session per the coordinator).

### D5 · A gitleaks pre-push gate, wired into CI and local hooks **[vision]** — the standing enforcement
A **secret-scan gate** (`gitleaks`) runs (a) as a **pre-push git hook** locally and (b) as a **required GitHub Actions job** on every PR/push — a hit is a hard block. This is the durable guard that keeps D3's one-time purge from silently regressing. Reconcile the two `.github` CI sets (parent `gate-ladder.yml` + heqk `validation-matrix.yml`) under one workflow tree; heqk's `validate.sh` QEMU gate becomes a job (owned by verification-engineer, who has absorbed the `kernel-validator`).

### D6 · License + provenance reconciled at the boundary **[partial]**
The monorepo's top-level LICENSE governs; heqk's `kernel/heqk/LICENSE`/`LICENSING.md` and its licensed firmware blob's terms are **preserved in place** and cross-referenced, not overwritten. The public repo is the enabler for ADR 0036's verifiable-build / binary-transparency north star.

---

## Consequences / risks
- **Irreversibility is the whole risk** — both a lost history and a leaked key are one-way. D2/D3 front-load both mitigations *before* the push, which is the only order that works.
- **Subtree import can be noisy** (path rewrites, large firmware blobs in history). Accept a documented snapshot fallback (D1) rather than a half-grafted DAG; `HISTORY.md` records whichever path was taken.
- **The gate must precede the push** — D5's gitleaks job existing *after* the repo is already public protects nothing. Order: locate+scan (D2) → rotate+purge (D3) → wire gate (D5) → import (D1) → push.
- **No Red op is performed by this ADR or by product-steward** — every mutating step (import, purge, rotate, push) is the operator's, gate-verified, per contract C9.

## Alternatives considered
- **Submodule instead of monorepo.** Rejected: fractures the single-lifecycle Product Cortex and complicates atomic cross-cutting changes (kernel + userspace + docs in one PR).
- **Squash-import heqk, drop the 316 commits.** Rejected as a *silent* default (loses attribution + bisect + the safety record); permitted only as an explicitly-recorded, operator-accepted fallback with `HISTORY.md` (D1).
- **Encrypt keys and commit them (git-crypt/SOPS-in-repo).** Rejected: keyless-OIDC + CI-secrets is stronger and leaves nothing to leak; in-repo encrypted keys are a rotation-nightmare and a single-passphrase-compromise away from exposure.
- **Push first, scan later.** Rejected outright — a public object with a key cannot be un-leaked.
