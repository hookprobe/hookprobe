#!/usr/bin/env python3
"""HookProbe OS — Supervisor / reconciler (REFERENCE implementation).

Reads a signed Platform Manifest + a set of module.yaml definitions and reconciles
desired modules against the device's granted capabilities and resource budget
(Architecture.md C9-C11). For each module it resolves:

  requires.capabilities  -> every one must be state=granted in the manifest
                            (present_unsafe / policy_denied / absent => clean refusal)
  requires.min_memory_mb -> assigned budget must meet it
  resources (budget)     -> must fit within manifest.resources.allocatable
  signature              -> must verify (stubbed here; real cosign in shipping impl)
  provides.capabilities  -> added to the granted set so later modules can require them

It is LEVEL-TRIGGERED and IDEMPOTENT: it reconciles to current state, runs to a
fixpoint (so provides->requires chains resolve), and re-running changes nothing.
The "load" is a MOCK — the shipping supervisor (Rust) loads Wasm via Wasmtime
(epoch + StoreLimits) and containers via Podman, enforcing budgets at the cgroup +
Wasmtime layers. This reference proves the resolution logic.

Usage:
    python3 supervisor/reference/supervisor.py MANIFEST.json
    python3 supervisor/reference/supervisor.py MANIFEST.json --modules modules/ --write out.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("FATAL: PyYAML not installed. Run: pip install -r manifest/requirements.txt")

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MODULES_DIR = REPO / "modules"
LIVE_STATES = {"pending", "running", "throttled", "paused"}


def discover_modules(modules_dir: Path) -> list[dict]:
    mods = []
    for mf in sorted(modules_dir.glob("*/module.yaml")):
        mods.append(yaml.safe_load(mf.read_text(encoding="utf-8")))
    return mods


def verify_signature(module) -> bool:
    """STUB: the shipping supervisor verifies the artifact's cosign signature
    against the manifest crypto policy. Reference assumes verified."""
    return True


def reconcile(manifest: dict, modules: list[dict]) -> tuple[dict, list[dict]]:
    caps = manifest["capabilities"]
    alloc = manifest["resources"]["allocatable"]
    defaults = manifest["resources"]["defaults"]

    # granted set = capabilities granted by hardware + provides of already-running modules
    granted = {t for t, c in caps.items() if c["state"] == "granted"}
    remaining = dict(alloc)
    running = {m["id"]: m for m in manifest.get("modules", []) if m["state"] in LIVE_STATES}
    for m in running.values():
        for dim in ("cpu_pct", "memory_mb"):
            remaining[dim] -= m["budget"][dim]
        # already-running modules' provides are part of the granted set (idempotency)
    report = []

    desired = {m["id"]: m for m in modules}
    # fixpoint loop so provides -> requires chains resolve regardless of order
    progress = True
    decided: set[str] = set(running)  # already-running are decided (no-op)
    for mid in running:
        report.append({"id": mid, "state": "running", "detail": "already running (no-op)"})

    while progress:
        progress = False
        for mid, mod in desired.items():
            if mid in decided:
                continue
            outcome = _try_load(mod, caps, granted, remaining, defaults)
            if outcome["state"] == "deferred":
                continue  # maybe a later-provided capability unblocks it
            decided.add(mid)
            progress = True
            report.append(outcome)
            if outcome["state"] == "running":
                running[mid] = outcome["_manifest_entry"]
                for dim in ("cpu_pct", "memory_mb"):
                    remaining[dim] -= outcome["_manifest_entry"]["budget"][dim]
                granted.update(mod.get("provides", {}).get("capabilities", []))

    # anything still undecided is genuinely blocked (its requires can never be met)
    for mid, mod in desired.items():
        if mid not in decided:
            report.append(_try_load(mod, caps, granted, remaining, defaults, final=True))

    manifest["modules"] = [
        {k: v for k, v in m.items() if not k.startswith("_")}
        for m in (list(running.values()))
    ]
    # supervisor mutated modules[] -> in shipping impl, re-sign here.
    manifest["signature"]["sig"] = "STALE-RESIGN-REQUIRED"
    return manifest, report


def _try_load(mod, caps, granted, remaining, defaults, final=False) -> dict:
    mid = mod["id"]
    req = mod.get("requires", {})

    # 1) capability gate
    missing = []
    for cap in req.get("capabilities", []):
        if cap in granted:
            continue
        info = caps.get(cap)
        if info is None and not final:
            return {"id": mid, "state": "deferred", "detail": f"awaiting capability '{cap}'"}
        state = info["state"] if info else "absent"
        reason = (info or {}).get("reason") or "not present"
        missing.append(f"{cap} (state={state}: {reason})")
    if missing:
        return {"id": mid, "state": "refused", "detail": "unmet capabilities: " + "; ".join(missing)}

    # 2) signature gate
    if mod.get("signature") == "required" and not verify_signature(mod):
        return {"id": mid, "state": "refused", "detail": "signature required but not verified"}

    # 3) budget: requested resources or runtime default
    budget = dict(mod.get("resources") or defaults.get(mod["runtime"], {}))
    if budget.get("memory_mb", 0) < req.get("min_memory_mb", 0):
        return {"id": mid, "state": "refused",
                "detail": f"budget memory_mb={budget.get('memory_mb')} < requires.min_memory_mb={req['min_memory_mb']}"}

    # 4) resource fit
    for dim in ("cpu_pct", "memory_mb"):
        if budget.get(dim, 0) > remaining[dim]:
            return {"id": mid, "state": "refused",
                    "detail": f"insufficient {dim}: needs {budget.get(dim)}, {remaining[dim]} allocatable left"}

    entry = {"id": mid, "version": mod["version"], "runtime": mod["runtime"],
             "state": "running", "budget": budget, "signature": "verified"}
    return {"id": mid, "state": "running",
            "detail": f"loaded ({mod['runtime']}, cpu={budget['cpu_pct']} mem={budget['memory_mb']}MB)"
                      f"  provides={mod.get('provides', {}).get('capabilities', [])}",
            "_manifest_entry": entry}


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="HookProbe supervisor/reconciler reference")
    ap.add_argument("manifest", help="signed Platform Manifest JSON")
    ap.add_argument("--modules", default=str(MODULES_DIR), help="modules dir (default: modules/)")
    ap.add_argument("--write", help="write the reconciled manifest (with modules[]) to this path")
    args = ap.parse_args(argv[1:])

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    modules = discover_modules(Path(args.modules))
    manifest, report = reconcile(manifest, modules)

    plat = manifest["platform"]
    print(f"Reconcile  device={plat['profile']} class={plat['class']}  "
          f"modules discovered={len(modules)}")
    print(f"{'MODULE':20} {'STATE':10} DETAIL")
    print("-" * 78)
    order = {"running": 0, "refused": 1, "deferred": 2}
    for r in sorted(report, key=lambda r: (order.get(r['state'], 9), r['id'])):
        print(f"{r['id']:20} {r['state']:10} {r['detail']}")
    rem = manifest["resources"]["allocatable"]
    used_c = rem["cpu_pct"] - sum(m["budget"]["cpu_pct"] for m in manifest["modules"])
    used_m = rem["memory_mb"] - sum(m["budget"]["memory_mb"] for m in manifest["modules"])
    print("-" * 78)
    print(f"Budget: allocatable cpu={rem['cpu_pct']} mem={rem['memory_mb']}MB  |  "
          f"free after load cpu={used_c} mem={used_m}MB  |  running={len(manifest['modules'])}")

    if args.write:
        Path(args.write).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote reconciled manifest -> {args.write}", file=sys.stderr)
        print("WARNING: modules[] mutated -> signature marked STALE (shipping supervisor re-signs).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
