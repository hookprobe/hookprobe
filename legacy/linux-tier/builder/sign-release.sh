#!/usr/bin/env bash
# =============================================================================
# builder/sign-release.sh — OFF-DEVICE release signing of modules + trust store.
# =============================================================================
# Production: the release HSM holds the signing key (ADR 0002); the device only
# VERIFIES. Here a deterministic DEV key stands in. Produces:
#   modules/<id>/module.yaml  artifacts[].digest.value refreshed IN PLACE (ADR 0016 D3)
#   modules/<id>/module.sig   detached Ed25519 over the module artifact digest
#   <trust>/release.pub       the public key the OS image bakes into its trust store
#
# These are BAKED into the bootc image: the Containerfile already COPYs modules/
# (so the .sig files ride along); add `COPY builder/trust/ /usr/share/hookprobe/trust/`
# and point the supervisor at `--trust /usr/share/hookprobe/trust`.
#
# "Trust nothing unsigned": without these, the supervisor refuses every
# `signature: required` module — so an image MUST ship them or it runs nothing.
#
# ADR 0016 (artifact-hash signing) STRICT ORDER — build -> digest -> sign, per module:
#   1. BUILD   (this script assumes the payloads are already built — see build-*.sh)
#   2. DIGEST  `--write-artifact-digests all` computes each declared artifact's digest
#              from the bytes ACTUALLY on disk and writes the value into module.yaml
#              IN PLACE (comments/formatting preserved — a surgical text edit, not a
#              full YAML reserialize).
#   3. SIGN    `--sign-modules` hashes the FINAL module.yaml (now carrying the payload
#              digests) — so the signature transitively covers the payload, not just
#              the metadata. Inverting this order (sign, then digest) would silently
#              invalidate the .sig; `builder/release-pass.sh`'s post-sign gate catches
#              exactly that inversion (re-verifies signature AFTER this script runs).
#
# ADR 0017 D3 — the DIGEST step now ALSO writes each built arch's `role: aot` `.cwasm`
# digest, but SIGN is still a single, one-shot step over the WHOLE module tree (ADR 0015's
# one-`.sig`-per-module invariant, preserved) — so a genuine multi-arch release is a
# COLLECT-then-SIGN pipeline, not "digest+sign per arch":
#   - each arch's CI runner builds its `.wasm`+`.cwasm` (native precompile, no cross-AOT —
#     the `build` stage already runs AS that arch) into a SHARED modules/ tree (e.g. a CI
#     artifact merge step, or sequential runners sharing one checkout) and runs THIS script
#     in `--digest-only` mode (writes only ITS OWN arch's `role: aot` entries — main.rs's
#     `--write-artifact-digests` already skips every other arch untouched, ADR 0017 D3) —
#     runnable safely any number of times, any order, before signing.
#   - the LAST arch's runner (once every target arch's digest pass has landed in the shared
#     tree) runs this script in `--sign-only` mode: one `--sign-modules` over the complete,
#     multi-arch-digested module.yaml set.
#   - the plain, no-flag invocation (below) is the SINGLE-ARCH case (today's dev/CI reality
#     on this box: one arch, one digest pass, one sign step in one command) — unchanged
#     behavior, `--digest-only`/`--sign-only` are additive.
# =============================================================================
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
KEY="${RELEASE_KEY:-$REPO/builder/release.key}"   # HSM-backed in production
TRUST="${TRUST_OUT:-$REPO/builder/trust}"
cd "$REPO"

MODE="full"
case "${1:-}" in
  --digest-only) MODE="digest-only" ;;
  --sign-only)   MODE="sign-only" ;;
  "") ;;
  *) echo "sign-release.sh: unknown arg '$1' (expected: [--digest-only|--sign-only])" >&2; exit 1 ;;
esac

BOOT="$REPO/target/release/hookprobe-bootstrap"
SUP="$REPO/target/release/hookprobe-supervisor"
if [ ! -x "$BOOT" ] || [ ! -x "$SUP" ]; then
  command -v cargo >/dev/null || { echo "ERROR: need cargo to build the signing tools" >&2; exit 1; }
  if cargo build --release -p hookprobe-bootstrap -p hookprobe-supervisor >/dev/null 2>&1; then :; else
    cargo build -p hookprobe-bootstrap -p hookprobe-supervisor >/dev/null 2>&1
    BOOT="$REPO/target/debug/hookprobe-bootstrap"
    SUP="$REPO/target/debug/hookprobe-supervisor"
  fi
fi

# Step 2 (DIGEST) — ADR 0016 D3 / ADR 0017 D3: MUST run before Step 3 (SIGN) below. Refreshes
# artifacts[].digest.value for every module that has already declared an `artifacts:`
# block (path+role[+arch] are hand-authored once by the module's owner; this only recomputes
# `value` — arch-selectively for `role: aot`, per THIS run's own arch, ADR 0017 D3). A module
# with no `artifacts:` block yet is left untouched here — it will correctly fail the D5
# release-hard-fail gate (`verify_artifact_digests`) and `verify-staging.sh`'s ADR 0016 check,
# which is the intended fail-closed signal, not a bug in this step.
if [ "$MODE" != "sign-only" ]; then
  "$SUP" --write-artifact-digests all --modules "$REPO/modules"
fi
[ "$MODE" = "digest-only" ] && { echo "sign-release.sh: --digest-only done (this arch's role:aot + role:executable digests refreshed; NOT signed yet)"; exit 0; }

# Step 3 (SIGN) — `--sign-modules` signs the module tree (now including the refreshed
# artifacts[] digests, across every arch that has run --digest-only, or this single run's own
# arch in the plain single-arch case) + writes the trust pubkey. The manifest argument is
# incidental to signing (we discard the reconcile output).
TMPMAN="$(mktemp)"
"$BOOT" -o "$TMPMAN" >/dev/null 2>&1 || true
"$SUP" "$TMPMAN" --modules "$REPO/modules" --sign-modules "$KEY" --trust "$TRUST" >/dev/null 2>&1
rm -f "$TMPMAN"

n="$(ls "$REPO"/modules/*/module.sig 2>/dev/null | wc -l | tr -d ' ')"
echo "release-signed $n modules; trust store -> $TRUST/release.pub"
