#!/bin/bash
# Build Fortress containers directly with podman
#
# podman-compose 1.0.6 has issues with dockerfile path resolution,
# so we build images directly with podman build.
#
# Usage: ./build-images.sh [--no-cache]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FORTRESS_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$(dirname "$FORTRESS_DIR")")"

NO_CACHE=""
if [ "$1" = "--no-cache" ]; then
    NO_CACHE="--no-cache"
fi

echo "========================================"
echo "  HookProbe Fortress - Building Images"
echo "========================================"
echo ""
echo "  Script dir:   $SCRIPT_DIR"
echo "  Fortress dir: $FORTRESS_DIR"
echo "  Root dir:     $ROOT_DIR"
echo ""

cd "$ROOT_DIR"

echo "=== Building fts-web ==="
podman build $NO_CACHE \
    -f products/fortress/containers/Containerfile.web \
    -t localhost/fts-web:latest \
    products/fortress/

echo ""
echo "=== Building fts-dnsxai ==="
podman build $NO_CACHE \
    -f products/fortress/containers/Containerfile.dnsxai \
    -t localhost/fts-dnsxai:latest \
    .

echo ""
echo "=== Building fts-dfs ==="
podman build $NO_CACHE \
    -f products/fortress/containers/Containerfile.dfs \
    -t localhost/fts-dfs:latest \
    .

echo ""
echo "=== Building fts-agent ==="
podman build $NO_CACHE \
    -f products/fortress/containers/Containerfile.agent \
    -t localhost/fts-agent:latest \
    .

echo ""
echo "=== Building fts-xdp ==="
podman build $NO_CACHE \
    -f products/fortress/containers/Containerfile.xdp \
    -t localhost/fts-xdp:latest \
    .

echo ""
echo "========================================"
echo "  All images built successfully!"
echo "========================================"
echo ""
podman images | grep -E "^REPOSITORY|fortress"
echo ""
echo "To start containers: podman-compose up -d"
