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

echo "=== Building fortress-web ==="
podman build $NO_CACHE \
    -f products/fortress/containers/Containerfile.web \
    -t localhost/fortress-web:latest \
    products/fortress/

echo ""
echo "=== Building fortress-dnsxai ==="
podman build $NO_CACHE \
    -f products/fortress/containers/Containerfile.dnsxai \
    -t localhost/fortress-dnsxai:latest \
    .

echo ""
echo "=== Building fortress-dfs ==="
podman build $NO_CACHE \
    -f products/fortress/containers/Containerfile.dfs \
    -t localhost/fortress-dfs:latest \
    .

echo ""
echo "=== Building fortress-agent ==="
podman build $NO_CACHE \
    -f products/fortress/containers/Containerfile.agent \
    -t localhost/fortress-agent:latest \
    .

echo ""
echo "========================================"
echo "  All images built successfully!"
echo "========================================"
echo ""
podman images | grep -E "^REPOSITORY|fortress"
echo ""
echo "To start containers: podman-compose up -d"
