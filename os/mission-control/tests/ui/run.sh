#!/usr/bin/env bash
# tests/ui/run.sh — the Mission Control UI behaviour suite (gate g3, tools/ci/gates.sh).
#
# Serves the built UI (os/mission-control/dist) on a free local port and drives it with Playwright
# Chromium in PREVIEW mode: no device API answers, so every screen renders its labelled sample data
# deterministically. It proves behaviour the device e2e (os/kernel/tools/mc-e2e.sh) does not:
# shell, capability gating, drawers, PlanDiff states, filters, exports, tabs and phone layouts.
#
#   os/mission-control/tests/ui/run.sh            build dist if missing, run every spec
#   UI_SPECS="shell layer0" tests/ui/run.sh       run some specs
#   UI_SHOTS=/tmp/shots tests/ui/run.sh           also save screenshots
#
# Playwright comes from os/kernel/tools/mc-e2e/node_modules (installed by gate g3) — no extra
# npm dependency here. Exit code = number of failed checks (0 = green).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI="$(cd "$HERE/../.." && pwd)"
ROOT="$(cd "$UI/../.." && pwd)"
[ -d "$HOME/.local/node/bin" ] && export PATH="$HOME/.local/node/bin:$PATH"
PW_DIR="${PW_DIR:-$ROOT/os/kernel/tools/mc-e2e/node_modules}"

if [ ! -d "$PW_DIR/playwright" ]; then
  echo "  [ui] Playwright not installed at $PW_DIR — run: (cd os/kernel/tools/mc-e2e && npm ci && npx playwright install chromium)"
  exit 2
fi
# Rebuild when there is no build, or any source is newer than it (a stale dist tests old code).
if [ ! -f "$UI/dist/index.html" ] || [ -n "$(find "$UI/src" "$UI/public" "$UI/astro.config.mjs" -newer "$UI/dist/index.html" -print -quit 2>/dev/null)" ]; then
  echo "  [ui] building os/mission-control/dist"
  (cd "$UI" && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && PUBLIC_API_BASE='' npm run build >/dev/null) || { echo "  [ui] build failed"; exit 2; }
fi

PORT="$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
python3 -I -m http.server "$PORT" --bind 127.0.0.1 --directory "$UI/dist" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done

node "$HERE/run.mjs" "$PW_DIR" "http://127.0.0.1:$PORT" ${UI_SPECS:-}
