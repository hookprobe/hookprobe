#!/usr/bin/env bash
# builder/gen-matrix.sh — emit the CI image-build matrix from base/profiles/*.yaml
# `bib.variants`, as GitHub-Actions matrix JSON. Closes the build-os.yml TODO:
# "GENERATE this matrix from base/profiles/*.yaml so adding a platform stays one file."
# Usage (in CI):  echo "matrix=$(builder/gen-matrix.sh)" >> "$GITHUB_OUTPUT"
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$REPO/base/profiles" <<'PY'
import sys, os, glob, json, yaml
TA = {"x86_64": "amd64", "aarch64": "arm64"}
include = []
for f in sorted(glob.glob(os.path.join(sys.argv[1], "*.yaml"))):
    p = yaml.safe_load(open(f)) or {}
    prof = p.get("profile")
    if not prof:
        continue
    for v in p.get("bib", {}).get("variants", []):
        arch = v.get("arch")
        for t in v.get("types", ["raw"]):
            include.append({
                "profile": prof,
                "arch": TA.get(arch, arch),  # Containerfile TARGETARCH token
                "bib_arch": arch,            # bootc-image-builder --target-arch token
                "type": t,
            })
print(json.dumps({"include": include}))
PY
