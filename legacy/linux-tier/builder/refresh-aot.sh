#!/usr/bin/env bash
# builder/refresh-aot.sh — ADR 0017 D3 build-time AOT-refresh pre-step, shared by
# builder/mkosi/build-vm.sh (amd64) and builder/mkosi-arm64/build-arm64.sh (arm64).
#
# FIXES the "AOT drift" gap found in the 2026-07-05 end-to-end validation: build-vm.sh /
# build-arm64.sh staged WHATEVER `.cwasm` happened to sit in `target/wasm32-wasip1/release/`
# (`{wasm}` in gen-staging.sh's own convention) without ever regenerating it — stale vs the
# engine-config the CURRENT supervisor binary actually runs (e.g. the `consume_fuel(true)`
# resource-budgets change), so `wasm_loader::verify_aot_binding` correctly (fail-closed, ADR
# 0016/0017) refused every stale blob and every module silently JIT-fell-back. Only
# `base/Containerfile`'s own `build` stage did this refresh (precompile -> digest -> sign,
# right before staging) — this script brings the SAME flow to the two mkosi dev-build paths,
# instead of forking a parallel one-off.
#
# ORDER (ADR 0016 D3 / ADR 0017 D3 — build -> precompile -> digest -> sign -> THEN stage):
#   1. PRECOMPILE  `hookprobe-supervisor --precompile all` — native to THIS run's --arch, using
#                  the CURRENT engine config (Config::new() bakes in whatever
#                  supervisor/src/wasm_loader.rs's `new_engine_config()` says NOW, e.g.
#                  `consume_fuel(true)`) — writes `<id>.cwasm` next to the shared
#                  `target/wasm32-wasip1/release/<id>.wasm` (the SAME location gen-staging.sh's
#                  `{wasm}` placeholder stages FROM — no separate --precompile-out needed).
#   2. SYNC        hard-link the freshly-written `.wasm`/`.cwasm` into `modules/<id>/` too (the
#                  CO-LOCATED convention `--write-artifact-digests`/`resolve_artifact_path`
#                  reads FROM for a plain wasm module, no `staging:` override) — otherwise the
#                  digest step below would hash a STALE co-located copy while gen-staging.sh
#                  stages the FRESH target-tree one: two diverging "sources of truth" for the
#                  exact same artifact is what let this drift happen in the first place.
#   2.5 ENSURE-ARCH-ENTRY  (2026-07-05 fix — the "AOT amd64-only" gap: `--write-artifact-digests`
#                  (main.rs) ONLY EVER REFRESHES a `role: aot` entry's `value` for an arch that is
#                  ALREADY DECLARED in module.yaml — module_sig::write_digest_value_matching
#                  deliberately bails ("no matching artifact entry found") rather than inventing
#                  one, by design (ADR 0017 D1: path+role[+arch] is hand-authored once). Before
#                  this fix, aegis-guard/dnsxai/napse/qsecbit's module.yaml each carried ONLY a
#                  `role: aot, arch: amd64` entry — so an arm64 build of THIS script silently
#                  skipped the aot digest write entirely (no error, no line printed for it) and
#                  arm64 devices ran the verified-JIT floor forever, never the AOT fast path (the
#                  "silent 1000x regression" ADR 0017 warns of). This step appends a
#                  `role: aot, arch: $ARCH` stub entry (`value: "PENDING"`) for every synced
#                  module that declares `role: aot` at all but has no entry for THIS run's own
#                  arch yet — so step 3 below has something to populate instead of silently
#                  no-op'ing. Idempotent: a module that already has an entry for this arch is
#                  left untouched.
#   3. DIGEST      `hookprobe-supervisor --write-artifact-digests all` — re-pins each module's
#                  `role: aot` (+ `role: executable`) digest, arch-qualified
#                  (`module_sig::running_arch()`, matched to THIS run's own arch — see the
#                  qemu-user note below for arm64 on a non-arm64 dev box).
#   4. SIGN        `--sign-modules <key>` (module_sig::dev_sign_all — the SAME dev-key path
#                  `builder/sign-release.sh` already uses; production signs OFF-device with the
#                  same command shape against an HSM-backed key) re-signs BOTH legs in one call
#                  (`module.sig` Ed25519 + `module.mldsa.sig` ML-DSA-65, ADR 0002 F5 hybrid).
#   5. (caller)    build-vm.sh/build-arm64.sh THEN run gen-staging.sh + stage-apply.sh, which now
#                  stage the byte-identical, freshly-signed `.cwasm` this script just produced.
#
# SINGLE-CHECKOUT CAVEAT (read before running amd64 then arm64 back-to-back on ONE dev box):
# unlike a real per-arch CI runner (an ISOLATED checkout per arch, ADR 0017's own assumption),
# this script and `target/wasm32-wasip1/release/` are SHARED across arches on one box. Each
# `role: aot` entry in module.yaml is arch-qualified (safe: step 3 only ever touches the entry
# matching its OWN arch, never clobbers the other arch's already-signed value) — but the
# PHYSICAL `.cwasm` file used to STAGE the image is not arch-qualified; run this script (and
# the caller's own gen-staging.sh + stage-apply.sh) for ONE arch, finish staging/building that
# image, THEN move to the other arch — never interleave two arches' image builds against the
# same checkout without re-running this script first.
#
# Usage:
#   builder/refresh-aot.sh --arch amd64
#   builder/refresh-aot.sh --arch arm64                 # needs a cross-built aarch64-gnu
#                                                        # supervisor + a qemu-user runner (see
#                                                        # ARM64_QEMU/ARM64_SYSROOT below) — this
#                                                        # dev box has both; a from-scratch CI
#                                                        # arm64 runner instead builds NATIVE (no
#                                                        # qemu needed there at all, ADR 0017).
#   builder/refresh-aot.sh --arch amd64 --skip-sign      # precompile+digest only (rehearsal)
#
# F7 (2026-07-06 Pi4 pentest finding) — arm64 CPU-baseline pin for the PRECOMPILE step only:
# a Pi 4's Cortex-A72 is ARMv8.0 (no LSE atomics). Wasmtime's Cranelift bakes the BUILD host's
# detected CPU features (Linux getauxval(AT_HWCAP)/HWCAP_ATOMICS) into the `.cwasm` header at
# precompile time; loading that blob later on real A72 silicon, Wasmtime's own compatibility
# check refuses it ("has_lse enabled but not available on host") and falls back to JIT for
# EVERY module — silently losing the ADR 0017 authenticated-AOT property for the whole Pi-4
# hardware class. (This is exactly why it passed under plain `qemu-aarch64-static`: verified
# empirically on this box, qemu-aarch64-static 8.2.2's DEFAULT cpu model reports
# HWCAP_ATOMICS=1/LSE=yes — a "max"-like CPU — to any guest process, which is what let a
# non-A72-safe `.cwasm` through.) Fix: PRECOMP_RUNNER below always pins `-cpu cortex-a72`
# (verified empirically to report LSE=no, matching the Pi4's BCM2711 SoC) for the precompile
# step, EVEN on a native aarch64 build host (self-emulation via qemu-user, purely to constrain
# the CPU-feature view Wasmtime's host-detection sees — correctness-neutral, just slower) —
# because a native arm64 CI runner is not guaranteed to itself be A72-class (e.g. Graviton/
# Cortex-A76+ CI hardware has LSE and would reproduce the identical bug). CHOSEN: one
# conservative no-LSE arm64 baseline for every arm64 device (Pi4 AND Pi5/RK3588) — matching the
# repo's existing one-arch-one-blob convention; Pi5/RK3588 still gets the AOT speedup over JIT,
# just not LSE-optimized codegen. Per-device-tier baselines (Pi5/RK3588 = Cortex-A76, HAS LSE —
# verified `-cpu cortex-a76` -> LSE=yes) are future work gated on deriving the baseline from the
# Platform Manifest CPU tier inside `supervisor/src/wasm_loader.rs::engine_config()`, which this
# agent does not own (flagged for os-architect, not silently done here). Override the pinned
# model with `--cpu <qemu-cpu-name>` (e.g. `--cpu cortex-a76` for an RK3588/Pi5-only build) or
# `ARM64_CPU=<name>`. `qemu-aarch64-static` (or $ARM64_QEMU) is now a HARD requirement for
# `--arch arm64` on every build host, including native aarch64 ones.
#
# --with-a76 (2026-07-07 enhancement — per-microarch arm64 AOT) — GENERATE A SECOND arm64
# `.cwasm` tier IN ADDITION TO the A72-safe baseline above, never instead of it: a `-cpu
# cortex-a76` precompile (LSE atomics ON — verified empirically on this box,
# `qemu-aarch64-static -cpu cortex-a76` -> HWCAP_ATOMICS=1), written to a SIBLING file
# `modules/<id>/<id>.a76.cwasm` (the baseline `modules/<id>/<id>.cwasm` is never touched by this
# flag — zero regression risk by construction: a different output path, appended-only
# module.yaml edits). Declares a NEW `role: aot, arch: arm64, cpu: cortex-a76` artifact entry per
# module (idempotent stub-append, mirroring step 2.5's existing convention) so
# `--write-artifact-digests`/`--sign-modules` cover it in the SAME pass as the baseline.
#
# Rust-side gap (FLAGGED, not silently wired around — os-architect's lane, not this script's):
# `wasm_loader::locate_rootfs_aot` hardcodes a SINGLE `<id>.cwasm` filename per install dir and
# `module_sig::verify_aot_binding`/`ArtifactDigest` have no `cpu`-tier selection concept at all —
# so this second entry is honestly generated, digested, and signed metadata, but the supervisor
# has NO runtime code path that ever picks the `.a76.cwasm` variant over the baseline today. The
# `cpu:` field is informational only until a Rust-side change (reads a CPU tier from the Platform
# Manifest, or an equivalent build-time "which blob is THE `<id>.cwasm` for this image" symlink
# swap in `builder/gen-staging.sh`, already scoped to rpi5/rk3588 there) consumes it. Do not
# report the A76 path as "live" on a device without that change landing and being verified.
#
# Usage: builder/refresh-aot.sh --arch arm64 --with-a76 [--a76-cpu cortex-a76]
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

ARCH=""
KEY="${RELEASE_KEY:-$REPO/builder/release.key}"
TRUST="${TRUST_OUT:-$REPO/builder/trust}"
SKIP_SIGN=0
# Dev-box qemu-user stand-in for a real arm64 CI runner (ADR 0017: the real `build` stage runs
# NATIVE, as the target arch — no qemu needed there). Overridable; these are this box's own
# proven paths (modules/napse-quarantine/README.md's cross-compile trail).
ARM64_QEMU="${ARM64_QEMU:-qemu-aarch64-static}"
ARM64_SYSROOT="${ARM64_SYSROOT:-/tmp/bookworm-arm64-sysroot}"
# F7: conservative arm64 AOT CPU baseline for the PRECOMPILE step (see the doc header). cortex-a72
# = Pi4's BCM2711 (ARMv8.0, no LSE) — verified empirically on this box's qemu-aarch64-static 8.2.2
# (`-cpu cortex-a72` -> HWCAP_ATOMICS=0). Override with --cpu/ARM64_CPU (e.g. cortex-a76 for an
# RK3588/Pi5-only build — verified LSE=yes there).
ARM64_CPU="${ARM64_CPU:-cortex-a72}"
# --with-a76 (see the doc header) — off by default, zero effect on any existing caller
# (build-arm64.sh's plain `--arch arm64` stays byte-for-byte the A72-safe baseline it always was).
WITH_A76="${ARM64_WITH_A76:-0}"
ARM64_A76_CPU="${ARM64_A76_CPU:-cortex-a76}"

while [ $# -gt 0 ]; do
  case "$1" in
    --arch)      ARCH="$2"; shift 2 ;;
    --key)       KEY="$2"; shift 2 ;;
    --trust)     TRUST="$2"; shift 2 ;;
    --cpu)       ARM64_CPU="$2"; shift 2 ;;
    --with-a76)  WITH_A76=1; shift ;;
    --a76-cpu)   ARM64_A76_CPU="$2"; WITH_A76=1; shift 2 ;;
    --skip-sign) SKIP_SIGN=1; shift ;;
    *) echo "refresh-aot.sh: unknown arg $1" >&2; exit 1 ;;
  esac
done
case "$ARCH" in
  amd64|arm64) ;;
  *) echo "refresh-aot.sh: --arch must be amd64 or arm64 (got '${ARCH}')" >&2; exit 1 ;;
esac
if [ "$WITH_A76" = 1 ] && [ "$ARCH" != "arm64" ]; then
  echo "refresh-aot.sh: --with-a76/--a76-cpu only apply to --arch arm64 (got '${ARCH}')" >&2
  exit 1
fi

MODULES="$REPO/modules"
WASM_DIR="$REPO/target/wasm32-wasip1/release"

# --- locate this run's own native (or qemu-user-emulated) hookprobe-supervisor/-bootstrap ---
# RUNNER is a prefix array (empty for native; the qemu-user wrapper for a cross-built arm64
# binary on a non-arm64 dev box) applied UNIFORMLY to every binary this script executes --
# `hookprobe-bootstrap` needs it exactly as much as `hookprobe-supervisor` does (an aarch64 ELF
# is an aarch64 ELF; forgetting the wrapper on just one of the two is the first bug this script
# hit in testing, 2026-07-05 — fixed here, not papered over with `|| true`).
RUNNER=()
case "$ARCH" in
  amd64)
    SUP_BIN="$REPO/target/release/hookprobe-supervisor"
    [ -x "$SUP_BIN" ] || SUP_BIN="$REPO/target/x86_64-unknown-linux-gnu/release/hookprobe-supervisor"
    BOOT_BIN="$REPO/target/release/hookprobe-bootstrap"
    [ -x "$BOOT_BIN" ] || BOOT_BIN="$REPO/target/x86_64-unknown-linux-gnu/release/hookprobe-bootstrap"
    if [ ! -x "$SUP_BIN" ]; then
      echo "refresh-aot.sh: no amd64 hookprobe-supervisor found -- build it first:" >&2
      echo "  cargo build --release -p hookprobe-bootstrap -p hookprobe-supervisor --features wasm" >&2
      exit 1
    fi
    ;;
  arm64)
    # Prefer the STATIC-musl supervisor/bootstrap: they are exactly what ships on the Pi
    # (build-arm64.sh installs the musl leg), they run under qemu-user with NO $ARM64_SYSROOT
    # (static → no glibc-version skew), and the precompile/digest/sign steps here have zero C
    # deps (only libbpf-linking loaders need gnu — see napse-quarantine/README.md §1; those are
    # NOT built by this tool). This kills the 2026-07-09 glibc-2.39-host-vs-2.36-sysroot failure
    # class permanently and makes the .cwasm precompiled by exactly the binary that loads them.
    MUSL_SUP="$REPO/target/aarch64-unknown-linux-musl/release/hookprobe-supervisor"
    MUSL_BOOT="$REPO/target/aarch64-unknown-linux-musl/release/hookprobe-bootstrap"
    GNU_SUP="$REPO/target/aarch64-unknown-linux-gnu/release/hookprobe-supervisor"
    GNU_BOOT="$REPO/target/aarch64-unknown-linux-gnu/release/hookprobe-bootstrap"
    if [ "$(uname -m)" = "aarch64" ] && [ -x "$MUSL_SUP" ]; then
      SUP_BIN="$MUSL_SUP"; BOOT_BIN="$MUSL_BOOT"   # native arm64 host, static leg
    elif [ "$(uname -m)" = "aarch64" ] && [ -x "$GNU_SUP" ]; then
      SUP_BIN="$GNU_SUP"; BOOT_BIN="$GNU_BOOT"     # native arm64 host, gnu leg
    elif [ -x "$MUSL_SUP" ] && command -v "$ARM64_QEMU" >/dev/null 2>&1; then
      SUP_BIN="$MUSL_SUP"; BOOT_BIN="$MUSL_BOOT"   # dev-box: static musl under qemu-user, NO sysroot needed
      RUNNER=("$ARM64_QEMU")
    elif [ -x "$GNU_SUP" ] && command -v "$ARM64_QEMU" >/dev/null 2>&1 && [ -d "$ARM64_SYSROOT" ]; then
      SUP_BIN="$GNU_SUP"; BOOT_BIN="$GNU_BOOT"     # fallback: gnu under qemu + pinned sysroot
      RUNNER=("$ARM64_QEMU" -L "$ARM64_SYSROOT")
    else
      echo "refresh-aot.sh: no usable arm64 hookprobe-supervisor path." >&2
      echo "  PREFERRED (no sysroot, no glibc skew): cross-build the STATIC-musl leg, which is also" >&2
      echo "  what ships on the Pi -- then this tool runs it directly under qemu-user:" >&2
      echo "     CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \\" >&2
      echo "       cargo build --release --target aarch64-unknown-linux-musl \\" >&2
      echo "       -p hookprobe-bootstrap -p hookprobe-supervisor --features wasm" >&2
      echo "     (needs qemu-user-static: 'apt-get install -y qemu-user-static')." >&2
      echo "  FALLBACK: the aarch64-gnu leg + a matching \$ARM64_SYSROOT (bookworm, glibc must match" >&2
      echo "  the binary's -- see the 2026-07-09 glibc-2.39-vs-2.36 skew note; musl avoids this)." >&2
      exit 1
    fi
    ;;
esac
SUP=("${RUNNER[@]}" "$SUP_BIN")
BOOT=("${RUNNER[@]}" "$BOOT_BIN")

echo "refresh-aot.sh: arch=$ARCH supervisor=[${SUP[*]}]"

# --- 1. PRECOMPILE (F7: CPU-baseline-pinned for arm64 -- see the doc header) ----------------
# PRECOMP_SUP is a SEPARATE invocation from SUP/BOOT (used below for digest/sign, which don't
# care about CPU features and keep the existing native-or-qemu logic unchanged) -- only the
# precompile step bakes host-detected CPU flags into the .cwasm, so only it needs pinning.
if [ "$ARCH" = "arm64" ]; then
  command -v "$ARM64_QEMU" >/dev/null 2>&1 || {
    echo "refresh-aot.sh: F7 requires \$ARM64_QEMU ($ARM64_QEMU, e.g. qemu-user-static) on EVERY" >&2
    echo "  arm64 build host now -- even a native aarch64 one -- to pin the precompiled .cwasm to" >&2
    echo "  a conservative cortex-a72 (no-LSE) CPU baseline instead of whatever CPU features the" >&2
    echo "  build host's own silicon happens to have (see the F7 doc-header note above)." >&2
    echo "  Install it (e.g. 'apt-get install -y qemu-user-static') and retry." >&2
    exit 1
  }
  PRECOMP_RUNNER=("$ARM64_QEMU" -cpu "$ARM64_CPU")
  # Cross-build (non-aarch64 dev box): still need the aarch64 sysroot for ld.so/libc resolution.
  # Native aarch64 host (incl. self-emulation to constrain CPU features): default "-L /" is right.
  [ -d "$ARM64_SYSROOT" ] && PRECOMP_RUNNER+=(-L "$ARM64_SYSROOT")
  PRECOMP_SUP=("${PRECOMP_RUNNER[@]}" "$SUP_BIN")
  echo "refresh-aot.sh: F7 CPU-baseline pin -- precompile via [${PRECOMP_SUP[*]}] (cpu=$ARM64_CPU, no LSE)"
else
  PRECOMP_SUP=("${SUP[@]}")
fi
"${PRECOMP_SUP[@]}" --precompile all --modules "$MODULES"

# --- 1.5 A76-VARIANT PRECOMPILE (--with-a76 only; see the doc header) -----------------------
# A SEPARATE precompile pass, into an ISOLATED temp dir (`--precompile-out`) so it never touches
# `$WASM_DIR`/the baseline `.cwasm` step 1 just wrote there -- the two tiers are fully independent
# outputs of the SAME `.wasm` input, at all times. Copied (not hard-linked: a different directory
# tree, `ln -f` across filesystems would fail) to `modules/<id>/<id>.a76.cwasm` -- ONE canonical
# co-located copy, the exact file both `--write-artifact-digests` (step 3, resolves relative to
# the module dir) and `gen-staging.sh`'s `{repo}/modules/<id>/<id>.a76.cwasm` staging src (rpi5/
# rk3588 targets only) read from -- no second, independently-drifting location.
if [ "$WITH_A76" = 1 ]; then
  A76_OUT="$(mktemp -d -t hp-aot-a76-XXXXXX)"
  trap 'rm -rf "$A76_OUT"' EXIT
  A76_RUNNER=("$ARM64_QEMU" -cpu "$ARM64_A76_CPU")
  [ -d "$ARM64_SYSROOT" ] && A76_RUNNER+=(-L "$ARM64_SYSROOT")
  A76_SUP=("${A76_RUNNER[@]}" "$SUP_BIN")
  echo "refresh-aot.sh: --with-a76 -- precompile via [${A76_SUP[*]}] (cpu=$ARM64_A76_CPU, LSE on) -> $A76_OUT"
  "${A76_SUP[@]}" --precompile all --modules "$MODULES" --precompile-out "$A76_OUT"
  shopt -s nullglob
  for cwasm in "$A76_OUT"/*.cwasm; do
    id="$(basename "$cwasm" .cwasm)"
    [ -d "$MODULES/$id" ] || continue
    cp -f "$cwasm" "$MODULES/$id/$id.a76.cwasm"
    echo "refresh-aot.sh: a76 variant -> modules/$id/$id.a76.cwasm ($(stat -c%s "$cwasm") bytes)"
  done
  shopt -u nullglob

  # Idempotent stub-append (mirrors step 2.5 below, but keyed on the DISTINCT a76 path, never
  # touching the existing baseline `role: aot, arch: arm64` block): a module that already has a
  # `path: <id>.a76.cwasm` entry is left untouched; one that has `role: aot` at all but no such
  # entry gets a `PENDING` stub appended right after its LAST `role: aot` block, for step 3 to
  # populate. A module with no `role: aot` block at all (no arm64 AOT support declared) is
  # skipped -- same "nothing to ensure" rule as step 2.5.
  MODULES="$MODULES" python3 - <<'PY'
import glob, os, re

modules_dir = os.environ["MODULES"]

for a76 in glob.glob(os.path.join(modules_dir, "*", "*.a76.cwasm")):
    mid = os.path.basename(os.path.dirname(a76))
    a76_name = os.path.basename(a76)
    ypath = os.path.join(modules_dir, mid, "module.yaml")
    if not os.path.isfile(ypath):
        continue
    with open(ypath) as f:
        text = f.read()
    lines = text.splitlines(keepends=True)

    # Block boundaries -- same fix as step 2.5's own copy of this logic: a block ends at the
    # next `- path:` start OR the next top-level (column-0) `key:` line (e.g. `signature:
    # required`, which follows `artifacts:` in every module.yaml here), never unconditionally at
    # EOF -- see step 2.5's longer comment for the "list item after a top-level key" breakage
    # this avoids.
    starts = [i for i, l in enumerate(lines) if re.match(r'^\s*-\s*path:', l)]
    if not starts:
        continue
    top_level_key_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]*:')

    def block_end(s):
        e = s + 1
        while e < len(lines):
            if re.match(r'^\s*-\s*path:', lines[e]) or top_level_key_re.match(lines[e]):
                break
            e += 1
        return e

    blocks = []
    for bi, s in enumerate(starts):
        end = block_end(s)
        block = "".join(lines[s:end])
        path_m = re.search(r'-\s*path:\s*([^\s#]+)', lines[s])
        role_m = re.search(r'^\s*role:\s*([^\s#]+)', block, re.M)
        alg_m = re.search(r'^\s*alg:\s*([^\s#]+)', block, re.M)
        blocks.append({
            "start": s, "end": end,
            "path": path_m.group(1) if path_m else None,
            "role": role_m.group(1) if role_m else None,
            "alg": alg_m.group(1) if alg_m else "sha256",
            "indent": re.match(r'^(\s*)', lines[s]).group(1),
        })

    aot_blocks = [b for b in blocks if b["role"] == "aot"]
    if not aot_blocks:
        continue  # no arm64 (or any) role:aot declared at all -- nothing to ensure
    if any(b["path"] == a76_name for b in aot_blocks):
        continue  # already declared -- idempotent, leave untouched

    last = aot_blocks[-1]
    indent = last["indent"]
    inner = indent + "  "
    new_block = (
        f"{indent}- path: {a76_name}\n"
        f"{inner}role: aot\n"
        f"{inner}arch: arm64\n"
        f"{inner}cpu: cortex-a76  # A76-tier (LSE) variant of the same path's A72-safe baseline;\n"
        f"{inner}                 # defaults to A72-safe when `cpu:` is absent (every other entry).\n"
        f"{inner}                 # informational until the Rust-side selection lands (see\n"
        f"{inner}                 # builder/refresh-aot.sh --with-a76's doc header).\n"
        f"{inner}digest:\n"
        f"{inner}  alg: {last['alg']}\n"
        f"{inner}  value: \"PENDING\"\n"
    )
    insert_at = last["end"]
    new_lines = lines[:insert_at] + [new_block] + lines[insert_at:]
    with open(ypath, "w") as f:
        f.write("".join(new_lines))
    print(f"refresh-aot.sh: {mid}: appended missing role:aot arch:arm64 cpu:cortex-a76 stub entry "
          f"(path: {a76_name}) to module.yaml (step 3 will populate its digest)")
PY
fi

# --- 2. SYNC the co-located modules/<id>/{<id>.wasm,<id>.cwasm} copies ----------------------
# (only wasm-convention modules -- no staging: override -- have a co-located pair at all;
# `--precompile all` only ever touches those, so globbing the .cwasm it just wrote is exact.)
shopt -s nullglob
for cwasm in "$WASM_DIR"/*.cwasm; do
  id="$(basename "$cwasm" .cwasm)"
  [ -d "$MODULES/$id" ] || continue
  ln -f "$cwasm" "$MODULES/$id/$id.cwasm"
  [ -f "$WASM_DIR/$id.wasm" ] && ln -f "$WASM_DIR/$id.wasm" "$MODULES/$id/$id.wasm"
  echo "refresh-aot.sh: synced $id.{wasm,cwasm} -> modules/$id/ (co-located digest source == staged {wasm} source)"
done
shopt -u nullglob

# --- 2.5 ENSURE-ARCH-ENTRY (append a missing role:aot arch entry -- see the doc header) -------
# Arch token convention matches module_sig::running_arch() exactly (amd64/arm64/riscv64), NOT
# bash's own $ARCH ("arm64"/"amd64" -- already the same tokens here, kept identical on purpose).
ARCH="$ARCH" MODULES="$MODULES" WASM_DIR="$WASM_DIR" python3 - <<'PY'
import glob, os, re

arch = os.environ["ARCH"]
modules_dir = os.environ["MODULES"]
wasm_dir = os.environ["WASM_DIR"]

for cwasm in glob.glob(os.path.join(wasm_dir, "*.cwasm")):
    mid = os.path.splitext(os.path.basename(cwasm))[0]
    ypath = os.path.join(modules_dir, mid, "module.yaml")
    if not os.path.isfile(ypath):
        continue
    with open(ypath) as f:
        text = f.read()
    lines = text.splitlines(keepends=True)

    # Find every "- path:" block start (same block-boundary convention as
    # module_sig::write_digest_value_matching) and classify role/arch/path/alg per block.
    #
    # Block END (2026-07-07 fix): NOT simply "next `- path:` start, else EOF" -- for the LAST
    # artifacts entry in the file that's wrong whenever a top-level key (e.g. `signature:
    # required`) follows the `artifacts:` list, which is every module.yaml in this repo. The old
    # `else len(lines)` fallback silently swallowed `signature: required` (and anything after)
    # INTO the last block's span, so an append keyed off that block's `end` landed the new stub
    # AFTER `signature: required` -- a YAML-breaking "list item after a top-level scalar key"
    # (caught 2026-07-07 by the --with-a76 enhancement actually exercising this path for the
    # first time; the same bug was latent here too, just never triggered because every module
    # already had its arm64 entry by the time this script existed). Fixed generally: a block ends
    # at the next `- path:` start, OR the next top-level (column-0, non-comment) `key:` line,
    # whichever comes first.
    starts = [i for i, l in enumerate(lines) if re.match(r'^\s*-\s*path:', l)]
    if not starts:
        continue
    top_level_key_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]*:')

    def block_end(s):
        e = s + 1
        while e < len(lines):
            if re.match(r'^\s*-\s*path:', lines[e]) or top_level_key_re.match(lines[e]):
                break
            e += 1
        return e

    blocks = []
    for bi, s in enumerate(starts):
        end = block_end(s)
        block = "".join(lines[s:end])
        path_m = re.search(r'-\s*path:\s*([^\s#]+)', lines[s])
        role_m = re.search(r'^\s*role:\s*([^\s#]+)', block, re.M)
        arch_m = re.search(r'^\s*arch:\s*([^\s#]+)', block, re.M)
        alg_m = re.search(r'^\s*alg:\s*([^\s#]+)', block, re.M)
        blocks.append({
            "start": s, "end": end,
            "path": path_m.group(1) if path_m else None,
            "role": role_m.group(1) if role_m else None,
            "arch": arch_m.group(1) if arch_m else None,
            "alg": alg_m.group(1) if alg_m else "sha256",
            "indent": re.match(r'^(\s*)', lines[s]).group(1),
        })

    aot_blocks = [b for b in blocks if b["role"] == "aot"]
    if not aot_blocks:
        continue  # this module declares no role:aot at all -- nothing to ensure (unchanged)
    if any(b["arch"] == arch for b in aot_blocks):
        continue  # already has an entry for THIS arch -- idempotent, leave untouched

    # Append a new stub block right after the LAST existing role:aot block for the same path
    # (keeps every arch's entries grouped, matching the hand-authored convention).
    last = aot_blocks[-1]
    indent = last["indent"]
    inner = indent + "  "
    new_block = (
        f"{indent}- path: {last['path']}\n"
        f"{inner}role: aot\n"
        f"{inner}arch: {arch}\n"
        f"{inner}digest:\n"
        f"{inner}  alg: {last['alg']}\n"
        f"{inner}  value: \"PENDING\"\n"
    )
    insert_at = last["end"]
    new_lines = lines[:insert_at] + [new_block] + lines[insert_at:]
    with open(ypath, "w") as f:
        f.write("".join(new_lines))
    print(f"refresh-aot.sh: {mid}: appended missing role:aot arch:{arch} stub entry to module.yaml "
          f"(step 3 will populate its digest)")
PY

# --- 3. DIGEST (re-pin role:aot [+role:executable] digests, arch-qualified) -----------------
"${SUP[@]}" --write-artifact-digests all --modules "$MODULES"

# --- 4. SIGN (both legs: module.sig Ed25519 + module.mldsa.sig ML-DSA-65, ADR 0002 F5) ------
if [ "$SKIP_SIGN" = 1 ]; then
  echo "refresh-aot.sh: --skip-sign set -- precompiled + digested, NOT re-signed (rehearsal only; a device will refuse these modules until signed)."
  exit 0
fi
if [ ! -x "$BOOT_BIN" ]; then
  echo "refresh-aot.sh: no matching hookprobe-bootstrap found for --sign-modules's throwaway manifest -- skipping sign (pass --skip-sign to silence this)." >&2
  exit 1
fi
TMPMAN="$(mktemp)"
"${BOOT[@]}" -o "$TMPMAN" >/dev/null 2>&1 || true
"${SUP[@]}" "$TMPMAN" --modules "$MODULES" --sign-modules "$KEY" --trust "$TRUST" >/dev/null 2>&1
rm -f "$TMPMAN"
n="$(ls "$MODULES"/*/module.sig 2>/dev/null | wc -l | tr -d ' ')"
echo "refresh-aot.sh: re-signed $n module(s) (key $KEY) -> trust $TRUST (both legs: module.sig + module.mldsa.sig)"
