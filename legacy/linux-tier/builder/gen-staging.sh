#!/usr/bin/env bash
# builder/gen-staging.sh — ADR 0015 (registry-driven module inclusion) D1/D2 generator.
#
# Enumerates modules/*/module.yaml (the SOLE inclusion list — D0) and emits:
#   builder/generated/staging-plan.json              — one plan, consumed by all 3 build
#                                                       paths + builder/verify-staging.sh
#   builder/generated/85-hookprobe-modules.preset     — the module-enable/managed lines,
#                                                       split out of base/config/presets/
#                                                       80-hookprobe.preset (which keeps
#                                                       only the BASE-unit lines)
#
# This is "the ONE place that reads YAML" (ADR 0015 D1) — builder/stage-apply.sh, every
# build script, and builder/verify-staging.sh consume the plan's JSON only.
#
# Usage:
#   builder/gen-staging.sh --arch {arm64|amd64|riscv64} [--target platforms/<p>.yaml]
#                           [--out builder/generated/staging-plan.json]
#                           [--preset-out builder/generated/85-hookprobe-modules.preset]
#
# Mirrors builder/gen-matrix.sh's shape: bash argument handling + a Python heredoc.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

ARCH=""
TARGET=""
OUT="$REPO/builder/generated/staging-plan.json"
PRESET_OUT="$REPO/builder/generated/85-hookprobe-modules.preset"

while [ $# -gt 0 ]; do
  case "$1" in
    --arch)        ARCH="$2"; shift 2 ;;
    --target)      TARGET="$2"; shift 2 ;;
    --out)         OUT="$2"; shift 2 ;;
    --preset-out)  PRESET_OUT="$2"; shift 2 ;;
    *) echo "gen-staging.sh: unknown arg $1" >&2; exit 1 ;;
  esac
done

case "$ARCH" in
  arm64|amd64|riscv64) ;;
  *) echo "gen-staging.sh: --arch must be one of arm64|amd64|riscv64 (got '${ARCH}')" >&2; exit 1 ;;
esac

mkdir -p "$(dirname "$OUT")" "$(dirname "$PRESET_OUT")"

ARCH="$ARCH" TARGET="$TARGET" OUT="$OUT" PRESET_OUT="$PRESET_OUT" \
python3 - "$REPO" <<'PY'
import glob, json, os, sys, yaml

REPO = sys.argv[1]
ARCH = os.environ["ARCH"]
TARGET = os.environ.get("TARGET") or None
OUT = os.environ["OUT"]
PRESET_OUT = os.environ["PRESET_OUT"]

# D4: the "always-on baseline" vs "hardware-gated" split. A module never omitted (D0);
# these two sets decide only whether the GENERATED PRESET enables it or leaves it
# supervisor-managed (staged, no preset line, gate.reason recorded).
HARDWARE_GATED_CAPS = {"edge_ai", "inline_ips", "ddos_mitigation"}
BASELINE_CAPS = {"soc", "ids", "capture", "host_telemetry", "dns_filtering"}

# --- Resource budgets (cgroups / Wasm fuel) feature: build-time cgroup drop-in generation. ---
# These constants MUST stay numerically in sync with the Rust-side defaults
# (crates/hookprobe-manifest/src/resource_budget.rs) — flagged there too as a cross-language
# drift risk (no automated cross-check exists; a change to one side without the other is a real
# maintenance hazard, not just a style nit).
WASM_MEM_HIGH_PCT = 80
CONTAINER_MEM_HIGH_PCT = 85
DEFAULT_CPU_WEIGHT = 100
# The absolute-last-resort floor when NEITHER the module's own `resources:` block NOR a
# `--target platforms/<p>.yaml` supply numbers (e.g. a `--target`-less dev/CI build). Deliberately
# NOT a new invented number: this is `platforms/generic.yaml`'s own already-checked-in
# `resources.defaults` (the repo's "conservative baseline ONLY" platform) copied here, not a
# second, independently-drifting constant.
GENERIC_RESOURCE_DEFAULTS = {
    "wasm": {"cpu_pct": 25, "memory_mb": 128},
    "container": {"cpu_pct": 100, "memory_mb": 512},
}


def load_target_resources_defaults(target_path):
    """`resources.defaults.{wasm,container}` from `--target platforms/<p>.yaml`, when given — the
    SAME per-platform numbers `allocate_resources()` (bootstrap, device-side) would resolve into
    `manifest.resources.defaults` for THIS platform class, so a build's static cgroup floor already
    matches the platform it's actually built for instead of a one-size-fits-all guess. `None` when
    no `--target` was passed (falls back to `GENERIC_RESOURCE_DEFAULTS` per module, below)."""
    if not target_path:
        return None
    with open(os.path.join(REPO, target_path)) as f:
        doc = yaml.safe_load(f) or {}
    return ((doc.get("resources") or {}).get("defaults")) or {}


def resolve_budget(mod_resources, runtime, target_defaults):
    """Effective (cpu_pct, memory_mb, mem_high_mb, cpu_weight) for one module — module.yaml's own
    `resources:` block wins field-by-field, else the `--target` platform's runtime default, else
    the generic floor. Mirrors `hookprobe_manifest::resource_budget::Budget::effective_*` /
    `supervisor::module_budget`'s merge order exactly (module overrides layered onto a runtime
    default, never a wholesale replace-or-nothing)."""
    mod_resources = mod_resources or {}
    base = (target_defaults or {}).get(runtime) or GENERIC_RESOURCE_DEFAULTS.get(runtime) or {}
    cpu_pct = mod_resources.get("cpu_pct") or base.get("cpu_pct", 0) or 0
    memory_mb = mod_resources.get("memory_mb") or base.get("memory_mb", 0) or 0
    mem_high_mb = mod_resources.get("mem_high_mb") or base.get("mem_high_mb")
    cpu_weight = mod_resources.get("cpu_weight") or base.get("cpu_weight")
    return cpu_pct, memory_mb, mem_high_mb, cpu_weight


def render_cgroup_dropin(cpu_pct, memory_mb, mem_high_mb, cpu_weight, runtime):
    """Render the `[Service]` cgroup drop-in text — same shape as
    `Budget::render_cgroup_dropin` (Rust side) and the hand-authored `MemoryMax=64M`-style lines
    already in e.g. `modules/qsecbit/units/qsecbit.service` (a drop-in OVERRIDES/adds to those,
    systemd's normal `.d/` layering — this generator never hand-edits the committed unit files)."""
    lines = ["[Service]"]
    if memory_mb:
        lines.append(f"MemoryMax={memory_mb}M")
        pct = WASM_MEM_HIGH_PCT if runtime == "wasm" else CONTAINER_MEM_HIGH_PCT
        high = mem_high_mb if mem_high_mb else max(1, (memory_mb * pct) // 100)
        if high:
            lines.append(f"MemoryHigh={high}M")
    if cpu_pct:
        lines.append(f"CPUQuota={cpu_pct}%")
    lines.append(f"CPUWeight={cpu_weight if cpu_weight else DEFAULT_CPU_WEIGHT}")
    return "\n".join(lines) + "\n"


def resolve_src(src):
    """Placeholder tokens ({wasm}/{bin}/{gnu_bin}/{repo}) pass through unchanged;
    a bare repo-relative path (module.yaml `staging.artifacts[].src` convention,
    ADR 0015 D1) is prefixed with {repo}/."""
    if src.startswith("{"):
        return src
    return "{repo}/" + src


def load_target_policy(target_path):
    if not target_path:
        return None
    with open(os.path.join(REPO, target_path)) as f:
        doc = yaml.safe_load(f) or {}
    return doc.get("capabilities", {}) or {}


target_policy = load_target_policy(TARGET)
target_resources_defaults = load_target_resources_defaults(TARGET)

# --- arm64 microarch AOT tier (builder-owned; 2026-07-07 enhancement) -----------------------
# Cortex-A76-class arm64 platforms (rpi5, rk3588 -- LSE atomics) get the `-cpu cortex-a76`
# `.cwasm` `builder/refresh-aot.sh --with-a76` produces (co-located at
# `modules/<id>/<id>.a76.cwasm`, a SIBLING of the A72-safe baseline `<id>.cwasm`, never replacing
# it); every other arm64 platform (rpi4/generic, no `--target` at all) stages nothing extra --
# byte-for-byte identical to before this enhancement.
#
# DELIBERATELY NOT a `platforms/*.yaml` field: adding a microarch/`cpu` capability key to the
# platform manifest schema is os-architect's lane (platform capability YAML), not
# release-engineer's. This lookup is a build-time-only staging convenience — flagged here,
# loudly, as the interim state: `supervisor/src/wasm_loader.rs::locate_rootfs_aot` hardcodes a
# SINGLE `<id>.cwasm` filename per install dir and has NO runtime selection mechanism between the
# baseline and the A76 variant staged below -- the A76 blob rides along on-disk, signed and
# digest-verified, but is NEVER loaded by the supervisor until a Rust-side change (reading a CPU
# tier from the Platform Manifest, or an equivalent build-time symlink swap) picks it. Do not
# treat its presence in a staged image as "the fast path is live for rpi5/rk3588" — it is not,
# yet.
ARM64_A76_PLATFORMS = {"rpi5", "rk3588"}
_target_basename = os.path.splitext(os.path.basename(TARGET))[0] if TARGET else None
STAGE_A76_VARIANT = ARCH == "arm64" and _target_basename in ARM64_A76_PLATFORMS

module_dirs = sorted(glob.glob(os.path.join(REPO, "modules", "*", "module.yaml")))

build_targets = []  # deduplicated, in first-seen order
build_targets_seen = set()


def add_build_target(entry):
    key = (entry["crate"], entry["toolchain"], tuple(sorted(entry.get("features", []))))
    if key in build_targets_seen:
        return
    build_targets_seen.add(key)
    build_targets.append(entry)


modules_out = []
errors = []

for path in module_dirs:
    mdir = os.path.dirname(path)
    with open(path) as f:
        m = yaml.safe_load(f) or {}

    mid = m.get("id")
    if not mid:
        errors.append(f"{path}: missing `id`")
        continue
    runtime = m.get("runtime")
    signature = m.get("signature", "optional")
    status = m.get("status")
    requires_caps = set((m.get("requires") or {}).get("capabilities", []) or [])
    rel_mdir = os.path.relpath(mdir, REPO)

    entry = {
        "id": mid,
        "runtime": runtime,
        "signature": signature,
        "status": status,
        "gate": None,
        "actions": [],
        "preset": [],
    }

    # status: stub — the D3 escape hatch (ADR 0015). Nothing buildable exists yet;
    # stage NOTHING (no build_targets, no actions, no preset line). Exempted from the
    # orphan check by verify-staging.sh; surfaced honestly as "shipped: no (stub)".
    if status == "stub":
        modules_out.append(entry)
        continue

    staging = m.get("staging")

    if staging is None:
        if runtime != "wasm":
            errors.append(
                f"{mid}: runtime={runtime!r} has no `staging:` block — irregular runtimes "
                f"(sysext/host/image-layer/container) MUST supply one explicitly (ADR 0015 D1). "
                f"Add modules/{mid}/module.yaml `staging:` or gen-staging.sh cannot include it."
            )
            continue
        # --- wasm convention (D1 table): no staging: block needed. ---
        add_build_target({"crate": mid, "toolchain": "wasm"})
        entry["actions"].append({
            "op": "install",
            "src": f"{{wasm}}/{mid}.wasm",
            "dest": f"/usr/lib/hookprobe/modules/{mid}/{mid}.wasm",
            "mode": "0644",
        })
        # ADR 0017 D3 — the build-time-precompiled AOT blob, co-located with the .wasm (the
        # `build` stage precompiles it right after compiling {mid}.wasm, into the SAME {wasm}
        # dir this arch's build already outputs to — see base/Containerfile Layer D2). `optional`
        # (stage-apply.sh): a missing .cwasm for THIS arch is a WARNING, never a build failure
        # (ADR 0017 D3) — the module simply falls back to the verified-JIT floor at runtime; it
        # is NOT staged for a `signature: unsigned` module (dev-only; never gets the ADR 0017
        # authenticated path, `hookprobe-precompile.service` covers those on-device instead).
        if signature == "required":
            entry["actions"].append({
                "op": "install",
                "src": f"{{wasm}}/{mid}.cwasm",
                "dest": f"/usr/lib/hookprobe/modules/{mid}/{mid}.cwasm",
                "mode": "0644",
                "optional": True,
            })
            # arm64 A76-tier sibling (see ARM64_A76_PLATFORMS note above) -- only for a
            # `--target` that resolves to an A76-class platform; staged from the co-located
            # `modules/<id>/<id>.a76.cwasm` (the SAME file `--write-artifact-digests` hashes),
            # never from `{wasm}` (this is the ONE canonical copy, not a second diverging one --
            # exactly the drift this script's own refresh-aot.sh sibling was written to close).
            # `optional: true`: a platform not yet re-built through `refresh-aot.sh --with-a76`
            # simply has no such file -- a warning at stage-apply time, never a build failure.
            if STAGE_A76_VARIANT:
                entry["actions"].append({
                    "op": "install",
                    "src": f"{{repo}}/{rel_mdir}/{mid}.a76.cwasm",
                    "dest": f"/usr/lib/hookprobe/modules/{mid}/{mid}.a76.cwasm",
                    "mode": "0644",
                    "optional": True,
                })
        units_glob = sorted(
            glob.glob(os.path.join(mdir, "units", "*.service"))
            + glob.glob(os.path.join(mdir, "units", "*.timer"))
        )
        unit_paths = []
        for u in units_glob:
            base = os.path.basename(u)
            unit_paths.append((base, u))
            entry["actions"].append({
                "op": "copy",
                "src": f"{{repo}}/{rel_mdir}/units/{base}",
                "dest": f"/usr/lib/systemd/system/{base}",
                "mode": "0644",
            })
    else:
        # --- explicit override block (irregular runtime, or a wasm module that opts in). ---
        for b in staging.get("build", []) or []:
            add_build_target({
                "crate": b["crate"],
                "toolchain": b.get("toolchain", "gnu"),
                "features": b.get("features", []),
            })
        for a in staging.get("artifacts", []) or []:
            entry["actions"].append({
                "op": "install",
                "src": resolve_src(a["src"]),
                "dest": a["dest"],
                "mode": a.get("mode", "0644"),
            })
        unit_paths = []
        for u in staging.get("units", []) or []:
            base = os.path.basename(u)
            unit_paths.append((base, os.path.join(REPO, u)))
            entry["actions"].append({
                "op": "copy",
                "src": resolve_src(u),
                "dest": f"/usr/lib/systemd/system/{base}",
                "mode": "0644",
            })

    # --- Resource budgets (cgroups / Wasm fuel) feature: per-unit cgroup drop-in. ---
    # Only `runtime: wasm`/`container` modules get a per-module cgroup budget here — sysext/
    # image-layer/host modules are bounded by their declared HOST SLICE instead (unchanged;
    # matches `supervisor::module_budget`'s `Budget::default()` for those runtimes: no per-module
    # MemoryMax/CPUQuota, bounded by the slice's own aggregate cap). Writes a REAL file into
    # builder/generated/ (this generator's own output tree, same convention as
    # 85-hookprobe-modules.preset) and stages it via a normal `op: install` action — no new `op`
    # vocabulary needed in stage-apply.sh, and the source genuinely exists on disk by the time
    # stage-apply.sh runs it.
    if runtime in ("wasm", "container") and unit_paths:
        cpu_pct, memory_mb, mem_high_mb, cpu_weight = resolve_budget(
            m.get("resources"), runtime, target_resources_defaults
        )
        dropin_text = render_cgroup_dropin(cpu_pct, memory_mb, mem_high_mb, cpu_weight, runtime)
        for unit, _upath in unit_paths:
            out_path = os.path.join(
                REPO, "builder", "generated", "resource-budgets", mid, f"{unit}.d", "50-hookprobe-budget.conf"
            )
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w") as df:
                df.write(dropin_text)
            rel_out = os.path.relpath(out_path, REPO)
            entry["actions"].append({
                "op": "install",
                "src": f"{{repo}}/{rel_out}",
                "dest": f"/usr/lib/systemd/system/{unit}.d/50-hookprobe-budget.conf",
                "mode": "0644",
            })

    # Uniform registry mirror (D0: "every staged artifact must have a module.yaml"; D3 #1
    # needs a module.sig it can find at a KNOWN path for every signature:required module,
    # not just the wasm-convention ones) — every non-stub module gets its module.yaml (+
    # module.sig, if signed) mirrored under /usr/lib/hookprobe/modules/<id>/, regardless of
    # its runtime-specific functional artifact living elsewhere.
    entry["actions"].append({
        "op": "copy",
        "src": f"{{repo}}/{rel_mdir}/module.yaml",
        "dest": f"/usr/lib/hookprobe/modules/{mid}/module.yaml",
        "mode": "0644",
    })
    sig_path = os.path.join(mdir, "module.sig")
    if os.path.isfile(sig_path):
        entry["actions"].append({
            "op": "copy",
            "src": f"{{repo}}/{rel_mdir}/module.sig",
            "dest": f"/usr/lib/hookprobe/modules/{mid}/module.sig",
            "mode": "0644",
            "requires_sig": True,
        })
    elif signature == "required":
        errors.append(f"{mid}: signature: required but modules/{mid}/module.sig is absent")

    # The ML-DSA-65 leg (ADR 0002 F5 hybrid signing). Every platforms/*.yaml defaults to
    # crypto_suite: hookprobe-pqc-hybrid-2026, whose anti-downgrade dispatch
    # (module_sig.rs::verify_module_for_suite) reads a MISSING mldsa leg as Unsigned and
    # REFUSES a signature:required module — never a silent Ed25519-only pass. So the mldsa.sig
    # MUST be staged alongside module.sig, or the whole SOC boots refused-but-healthy-looking.
    mldsa_sig_path = os.path.join(mdir, "module.mldsa.sig")
    if os.path.isfile(mldsa_sig_path):
        entry["actions"].append({
            "op": "copy",
            "src": f"{{repo}}/{rel_mdir}/module.mldsa.sig",
            "dest": f"/usr/lib/hookprobe/modules/{mid}/module.mldsa.sig",
            "mode": "0644",
            "requires_sig": True,
        })
    elif signature == "required":
        errors.append(f"{mid}: signature: required but modules/{mid}/module.mldsa.sig is absent "
                       f"(hybrid ML-DSA leg — ADR 0002/F5; the default crypto suite requires both legs)")

    # --- D4: gate classification (staged always; preset-enable decided here). ---
    # `staging.self_gated: true` (ADR 0015 D4 sense, arch F4 fix): the module's OWN loader
    # reads the manifest at startup and exits 0 when its hardware-gated capability isn't
    # granted (mirrors modules/ovs/config/ovs-bringup's `granted <cap> || exit 0` pattern —
    # see e.g. modules/napse-quarantine/loader/src/main.rs). The supervisor never starts
    # `managed` units (no such runtime path exists), so a hardware-gated module WITHOUT
    # self-gating would stage but never run anywhere (the exact bug this fixes: napse-
    # quarantine's Ring-0 TC-bpf enforcement shipped staged-but-inert). For a self-gated
    # module, preset-enabling it everywhere is a harmless, capability-checked no-op on
    # platforms that don't grant the capability (e.g. cloud/single-NIC) — the binary itself
    # refuses to do anything, honestly and immediately, instead of the preset silently never
    # starting it at all.
    hw_hit = sorted(requires_caps & HARDWARE_GATED_CAPS)
    self_gated = bool((staging or {}).get("self_gated", False))
    if hw_hit:
        cap = hw_hit[0]
        if self_gated:
            entry["gate"] = {
                "capability": cap,
                "reason": (
                    f"requires hardware-gated capability '{cap}'; preset-enabled everywhere "
                    f"because the module is self_gated — its own loader checks "
                    f"capabilities.{cap}.state == granted at startup and exits 0 cleanly if not"
                ),
            }
            default_verb = "enable"
        else:
            entry["gate"] = {
                "capability": cap,
                "reason": (
                    f"requires hardware-gated capability '{cap}'; staged but not preset-enabled — "
                    f"the supervisor enables/loads it at runtime when the manifest grants '{cap}'"
                ),
            }
            default_verb = "managed"
    else:
        default_verb = "enable"

    # Optional --target downgrade (D4): a profile-aware pass may tighten a baseline
    # `enable` to `disable` where THIS class's platform policy denies the capability
    # (e.g. `ovs` on `cloud`). Never used to loosen a `managed` module to `enable`.
    if target_policy is not None and default_verb == "enable":
        for cap in requires_caps:
            pol = (target_policy.get(cap) or {}).get("policy")
            if pol == "disabled":
                default_verb = "disable"
                break

    preset_overrides = (staging or {}).get("preset", {}) or {}
    for unit, upath in unit_paths:
        if unit in preset_overrides:
            # explicit per-unit author decision always wins.
            entry["preset"].append({"unit": unit, "verb": preset_overrides[unit]})
            continue
        # A unit with no [Install] section (e.g. a Type=oneshot .service that only its
        # sibling .timer's [Install] WantedBy=timers.target activates) cannot be
        # `systemctl enable`d at all — `systemctl preset-all` errors on it. Emit no
        # preset line for it rather than a broken `enable` (matches every existing
        # timer+oneshot-service pair in this repo: hookprobe-evidence, hookprobe-retention).
        try:
            with open(upath) as uf:
                has_install = any(line.strip() == "[Install]" for line in uf)
        except OSError:
            has_install = True  # unreadable — don't silently drop it; default applies
        if not has_install:
            continue
        entry["preset"].append({"unit": unit, "verb": default_verb})

    modules_out.append(entry)

if errors:
    for e in errors:
        print(f"gen-staging.sh: ERROR: {e}", file=sys.stderr)
    sys.exit(1)

plan = {
    "schema": 1,
    "arch": ARCH,
    "target_profile": TARGET,
    "build_targets": build_targets,
    "modules": modules_out,
}

with open(OUT, "w") as f:
    json.dump(plan, f, indent=2, sort_keys=False)
    f.write("\n")

# --- the generated preset (D2: module-enable lines, split out of 80-hookprobe.preset) ---
lines = [
    "# builder/generated/85-hookprobe-modules.preset — GENERATED by builder/gen-staging.sh",
    "# from modules/*/module.yaml. DO NOT EDIT BY HAND (ADR 0015 D1/D2) — edit the owning",
    "# module's module.yaml `staging.preset` override, or its `requires.capabilities`, and",
    "# regenerate. Base-unit lines (bootstrap/supervisor/mounts/measured-boot/network-",
    "# reconcile/etc.) stay in base/config/presets/80-hookprobe.preset, unchanged.",
    f"# arch={ARCH} target_profile={TARGET}",
    "",
]
for entry in modules_out:
    if entry["status"] == "stub":
        continue
    for p in entry["preset"]:
        verb = p["verb"]
        unit = p["unit"]
        if verb == "managed":
            if entry.get("gate"):
                lines.append(f"# managed: {unit} — capability-gated (gate: {entry['gate']['capability']}); supervisor starts it at runtime when granted")
            else:
                lines.append(f"# managed: {unit} — explicit staging.preset override (no capability gate); supervisor starts it on demand")
            continue
        lines.append(f"{verb} {unit}")

with open(PRESET_OUT, "w") as f:
    f.write("\n".join(lines) + "\n")

n_staged = sum(1 for e in modules_out if e["status"] != "stub")
n_stub = sum(1 for e in modules_out if e["status"] == "stub")
n_gated = sum(1 for e in modules_out if e.get("gate"))
print(f"gen-staging.sh: wrote {OUT}", file=sys.stderr)
print(f"gen-staging.sh: wrote {PRESET_OUT}", file=sys.stderr)
print(f"gen-staging.sh: {len(modules_out)} module(s) — {n_staged} staged, {n_stub} stub, {n_gated} supervisor-managed, {len(build_targets)} build target(s)", file=sys.stderr)
PY
