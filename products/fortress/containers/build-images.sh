#!/bin/bash
# Build Fortress containers directly with podman
#
# podman-compose 1.0.6 has issues with dockerfile path resolution,
# so we build images directly with podman build.
#
# Usage: ./build-images.sh [--no-cache] [--quick]
#
# Options:
#   --no-cache  Force rebuild without cache
#   --quick     Skip preflight checks

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FORTRESS_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$(dirname "$FORTRESS_DIR")")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

NO_CACHE=""
QUICK_MODE=false

for arg in "$@"; do
    case "$arg" in
        --no-cache) NO_CACHE="--no-cache" ;;
        --quick) QUICK_MODE=true ;;
    esac
done

echo "========================================"
echo "  HookProbe Fortress - Building Images"
echo "========================================"
echo ""
echo "  Script dir:   $SCRIPT_DIR"
echo "  Fortress dir: $FORTRESS_DIR"
echo "  Root dir:     $ROOT_DIR"
echo ""

# ============================================================
# PREFLIGHT VALIDATION
# ============================================================

preflight_check() {
    echo -e "${CYAN}=== Preflight Checks ===${NC}"
    local errors=0

    # Check podman is installed
    if ! command -v podman &>/dev/null; then
        log_error "podman not found - install with: apt install podman"
        errors=$((errors + 1))
    else
        log_info "podman: $(podman --version | head -1)"
    fi

    # Check required Containerfiles exist
    local containerfiles=(
        "Containerfile.web"
        "Containerfile.dnsxai"
        "Containerfile.dfs"
        "Containerfile.agent"
        "Containerfile.xdp"
        "Containerfile.lstm"
    )
    for cf in "${containerfiles[@]}"; do
        if [ ! -f "$SCRIPT_DIR/$cf" ]; then
            log_error "Missing Containerfile: $cf"
            errors=$((errors + 1))
        fi
    done
    if [ $errors -eq 0 ]; then
        log_info "All Containerfiles present (${#containerfiles[@]} files)"
    fi

    # Check required source directories
    if [ ! -d "$FORTRESS_DIR/web" ]; then
        log_error "Missing source directory: web/"
        errors=$((errors + 1))
    fi
    if [ ! -d "$ROOT_DIR/shared/dnsXai" ]; then
        log_error "Missing shared module: shared/dnsXai/"
        errors=$((errors + 1))
    fi
    if [ ! -d "$ROOT_DIR/shared/wireless" ]; then
        log_error "Missing shared module: shared/wireless/"
        errors=$((errors + 1))
    fi
    if [ ! -d "$ROOT_DIR/core/qsecbit" ]; then
        log_error "Missing core module: core/qsecbit/"
        errors=$((errors + 1))
    fi
    if [ $errors -eq 0 ]; then
        log_info "All source directories present"
    fi

    # Check disk space (need at least 5GB free)
    local free_space_gb
    free_space_gb=$(df -BG "$ROOT_DIR" 2>/dev/null | awk 'NR==2{print $4}' | tr -d 'G')
    if [ -n "$free_space_gb" ] && [ "$free_space_gb" -lt 5 ]; then
        log_warn "Low disk space: ${free_space_gb}GB free (recommend 5GB+)"
    else
        log_info "Disk space: ${free_space_gb}GB free"
    fi

    # Check network connectivity (needed to pull base images)
    if ! timeout 5 podman pull --quiet docker.io/library/alpine:3.19 2>/dev/null; then
        log_warn "Cannot pull images - check network connectivity"
        log_warn "Builds will fail if base images are not cached"
    else
        log_info "Network connectivity: OK (can pull base images)"
    fi

    # Check podman storage
    local podman_storage
    podman_storage=$(podman info --format '{{.Store.GraphRoot}}' 2>/dev/null || echo "unknown")
    if [ -d "$podman_storage" ]; then
        local storage_free
        storage_free=$(df -BG "$podman_storage" 2>/dev/null | awk 'NR==2{print $4}' | tr -d 'G')
        if [ -n "$storage_free" ] && [ "$storage_free" -lt 3 ]; then
            log_warn "Low podman storage space: ${storage_free}GB in $podman_storage"
        else
            log_info "Podman storage: ${storage_free}GB free in $podman_storage"
        fi
    fi

    echo ""

    if [ $errors -gt 0 ]; then
        log_error "Preflight check failed with $errors error(s)"
        log_error "Fix the issues above before building images"
        exit 1
    fi

    log_info "Preflight checks passed"
    echo ""
}

# Run preflight unless --quick
if [ "$QUICK_MODE" = false ]; then
    preflight_check
fi

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
echo "=== Building fts-lstm ==="
podman build $NO_CACHE \
    -f products/fortress/containers/Containerfile.lstm \
    -t localhost/fts-lstm:latest \
    .

echo ""
echo "========================================"
echo "  All images built successfully!"
echo "========================================"
echo ""
podman images | grep -E "^REPOSITORY|fts-"
echo ""
echo "To start containers: podman-compose up -d"
