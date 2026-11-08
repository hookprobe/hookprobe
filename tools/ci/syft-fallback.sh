#!/usr/bin/env bash
# =============================================================================
# tools/ci/syft-fallback.sh — install a `syft` that runs the digest-pinned container image, for when
# the GitHub release CDN is down (2026-11-08: 504 on every syft/gitleaks download for >30 min, so a
# same-source retry cannot help). Container registries are independent infrastructure.
#
# Puts a `syft` wrapper on PATH (GITHUB_PATH in Actions). The image digest is the one the operator's
# dev box already trusts (~/.local/bin/syft), so CI and local SBOMs come from the same bytes.
# =============================================================================
set -euo pipefail
IMG="docker.io/anchore/syft@sha256:a64166d91c83c2881b6c449c834c2e7259efee55eab863d8708ddf31e9a0ed37"  # v1.48.0
RT="${CONTAINER_RUNTIME:-docker}"
BIN="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/syft-fallback/bin"
mkdir -p "$BIN"
# Rootless podman maps the container uid to a subuid that cannot write the workspace — keep-id fixes
# that; rootful docker (GitHub runners) needs only --user.
USERNS=""; [ "$(basename "$RT")" = podman ] && USERNS="--userns=keep-id"
cat > "$BIN/syft" <<EOF
#!/usr/bin/env bash
# syft via the pinned container image; the workspace is mounted at the same path so relative
# paths and output files (e.g. out/ci/sbom/*.cdx.json) land where the caller expects them.
exec $RT run --rm -i --network none $USERNS --user "\$(id -u):\$(id -g)" \\
  -e HOME=/tmp -e SYFT_CHECK_FOR_APP_UPDATE=false -v "\$PWD:\$PWD" -w "\$PWD" "$IMG" "\$@"
EOF
chmod +x "$BIN/syft"
"$RT" pull -q "$IMG" >/dev/null
[ -n "${GITHUB_PATH:-}" ] && echo "$BIN" >> "$GITHUB_PATH"
echo "syft fallback ready: $BIN/syft ($($BIN/syft version 2>/dev/null | awk '/^Version:/{print $2}'))"
