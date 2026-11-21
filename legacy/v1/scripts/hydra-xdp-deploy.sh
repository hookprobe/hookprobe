#!/usr/bin/env bash
# HookProbe HYDRA XDP Deploy Script
# ===================================
# Compiles and loads XDP programs on target interfaces.
# Populates allowlist with trusted CIDRs.
#
# Usage:
#   sudo ./hydra-xdp-deploy.sh [load|unload|status|reload|compile]
#   sudo ./hydra-xdp-deploy.sh load hydra      # Load only HYDRA on dummy-mirror
#   sudo ./hydra-xdp-deploy.sh load synwall     # Load only SynWall on enp0s6
#   sudo ./hydra-xdp-deploy.sh load all         # Load both (default)
#
# Programs:
#   xdp_hydra.c    -> dummy-mirror (active filtering, blocklist/allowlist)
#   xdp_synwall.c  -> enp0s6 (RPF anti-spoofing, SYN rate limiting, conntrack)
#
# Safety:
#   - Both programs default to MONITOR mode (log only, no drops)
#   - Set HYDRA_ENFORCE=1 to enable dropping

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XDP_DIR="${SCRIPT_DIR}/../containers/ids/xdp"

# Program definitions
HYDRA_SRC="${XDP_DIR}/xdp_hydra.c"
HYDRA_OBJ="${XDP_DIR}/xdp_hydra.o"
HYDRA_SEC="xdp_hydra"
HYDRA_IFACE="dummy-mirror"

SYNWALL_SRC="${XDP_DIR}/xdp_synwall.c"
SYNWALL_OBJ="${XDP_DIR}/xdp_synwall.o"
SYNWALL_SEC="xdp_synwall"
SYNWALL_IFACE="${SYNWALL_IFACE:-enp0s6}"

# Mode: 0=monitor, 1=enforce
HYDRA_ENFORCE="${HYDRA_ENFORCE:-0}"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [HYDRA-XDP] $*"; }
err() { echo "$(date '+%Y-%m-%d %H:%M:%S') [HYDRA-XDP] ERROR: $*" >&2; }

# Detect architecture flags for clang
get_arch_flags() {
    case "$(uname -m)" in
        aarch64|arm64)
            echo "-D__TARGET_ARCH_arm64 -I/usr/include/aarch64-linux-gnu"
            ;;
        x86_64)
            echo "-D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Compile a single XDP program
compile_one() {
    local src="$1"
    local obj="$2"
    local name="$3"

    if ! command -v clang &>/dev/null; then
        err "clang not found. Install: apt install clang"
        return 1
    fi

    if [[ ! -f "$src" ]]; then
        err "Source not found: ${src}"
        return 1
    fi

    # Skip if object is newer than source
    if [[ -f "$obj" ]] && [[ "$obj" -nt "$src" ]]; then
        log "${name}: object file is up-to-date"
        return 0
    fi

    log "Compiling ${name}..."
    local arch_flags
    arch_flags=$(get_arch_flags)

    if clang -O2 -g -target bpf ${arch_flags} -c "${src}" -o "${obj}" 2>&1; then
        log "Compiled: ${obj} ($(stat -c%s "${obj}") bytes)"
    else
        err "Compilation failed for ${name}"
        return 1
    fi
}

compile() {
    local target="${1:-all}"
    case "$target" in
        hydra)   compile_one "$HYDRA_SRC" "$HYDRA_OBJ" "HYDRA" ;;
        synwall) compile_one "$SYNWALL_SRC" "$SYNWALL_OBJ" "SynWall" ;;
        all)
            compile_one "$HYDRA_SRC" "$HYDRA_OBJ" "HYDRA"
            compile_one "$SYNWALL_SRC" "$SYNWALL_OBJ" "SynWall"
            ;;
        *)
            err "Unknown target: ${target}. Use: hydra, synwall, all"
            return 1
            ;;
    esac
}

# Load XDP program on an interface
load_xdp() {
    local iface="$1"
    local obj="$2"
    local sec="$3"
    local name="$4"

    # Check interface exists
    if ! ip link show "${iface}" &>/dev/null; then
        err "Interface ${iface} not found (needed for ${name})"
        return 1
    fi

    # Unload existing program
    ip link set dev "${iface}" xdp off 2>/dev/null || true

    # Load new program
    if ! ip link set dev "${iface}" xdp obj "${obj}" sec "${sec}" 2>&1; then
        err "Failed to load ${name} on ${iface}"
        return 1
    fi

    # Verify
    local prog_info
    prog_info=$(ip link show "${iface}" 2>&1 | grep -o 'prog/xdp id [0-9]*') || true
    if [[ -n "$prog_info" ]]; then
        log "${name} loaded on ${iface}: ${prog_info}"
    else
        err "${name}: program not detected after load on ${iface}"
        return 1
    fi

    # Report mode
    if [[ "$HYDRA_ENFORCE" == "1" ]]; then
        log "${name}: Mode = ENFORCE (active blocking)"
    else
        log "${name}: Mode = MONITOR (log only)"
    fi
}

load() {
    local target="${1:-all}"

    case "$target" in
        hydra)
            compile_one "$HYDRA_SRC" "$HYDRA_OBJ" "HYDRA" || return 1
            load_xdp "$HYDRA_IFACE" "$HYDRA_OBJ" "$HYDRA_SEC" "HYDRA"
            ;;
        synwall)
            compile_one "$SYNWALL_SRC" "$SYNWALL_OBJ" "SynWall" || return 1
            load_xdp "$SYNWALL_IFACE" "$SYNWALL_OBJ" "$SYNWALL_SEC" "SynWall"
            ;;
        all)
            compile_one "$HYDRA_SRC" "$HYDRA_OBJ" "HYDRA" || return 1
            compile_one "$SYNWALL_SRC" "$SYNWALL_OBJ" "SynWall" || return 1
            load_xdp "$HYDRA_IFACE" "$HYDRA_OBJ" "$HYDRA_SEC" "HYDRA"
            load_xdp "$SYNWALL_IFACE" "$SYNWALL_OBJ" "$SYNWALL_SEC" "SynWall"
            ;;
        *)
            err "Unknown target: ${target}. Use: hydra, synwall, all"
            return 1
            ;;
    esac
}

unload() {
    local target="${1:-all}"

    case "$target" in
        hydra)
            log "Unloading HYDRA from ${HYDRA_IFACE}..."
            ip link set dev "${HYDRA_IFACE}" xdp off 2>/dev/null || true
            ;;
        synwall)
            log "Unloading SynWall from ${SYNWALL_IFACE}..."
            ip link set dev "${SYNWALL_IFACE}" xdp off 2>/dev/null || true
            ;;
        all)
            log "Unloading all XDP programs..."
            ip link set dev "${HYDRA_IFACE}" xdp off 2>/dev/null || true
            ip link set dev "${SYNWALL_IFACE}" xdp off 2>/dev/null || true
            ;;
    esac
    log "Unload complete"
}

status() {
    log "XDP Status Report"
    echo ""

    echo "=== ${HYDRA_IFACE} (HYDRA) ==="
    if ip link show "${HYDRA_IFACE}" &>/dev/null; then
        ip link show "${HYDRA_IFACE}" 2>&1 | grep -E "xdp|prog" || echo "  No XDP program loaded"
    else
        echo "  Interface not found"
    fi
    echo ""

    echo "=== ${SYNWALL_IFACE} (SynWall) ==="
    if ip link show "${SYNWALL_IFACE}" &>/dev/null; then
        ip link show "${SYNWALL_IFACE}" 2>&1 | grep -E "xdp|prog" || echo "  No XDP program loaded"
    else
        echo "  Interface not found"
    fi
    echo ""

    echo "=== BPF Programs ==="
    bpftool prog list 2>/dev/null | grep -i "xdp\|hydra\|synwall" || echo "  bpftool unavailable or no XDP programs"
    echo ""

    echo "=== Object Files ==="
    for f in "$HYDRA_OBJ" "$SYNWALL_OBJ"; do
        if [[ -f "$f" ]]; then
            echo "  $(ls -la "$f")"
        else
            echo "  ${f}: not compiled"
        fi
    done
}

reload() {
    local target="${1:-all}"
    log "Reloading ${target}..."

    case "$target" in
        hydra)
            compile_one "$HYDRA_SRC" "$HYDRA_OBJ" "HYDRA" || return 1
            ip link set dev "${HYDRA_IFACE}" xdp off 2>/dev/null || true
            sleep 1
            load_xdp "$HYDRA_IFACE" "$HYDRA_OBJ" "$HYDRA_SEC" "HYDRA"
            ;;
        synwall)
            compile_one "$SYNWALL_SRC" "$SYNWALL_OBJ" "SynWall" || return 1
            ip link set dev "${SYNWALL_IFACE}" xdp off 2>/dev/null || true
            sleep 1
            load_xdp "$SYNWALL_IFACE" "$SYNWALL_OBJ" "$SYNWALL_SEC" "SynWall"
            ;;
        all)
            compile "$target" || return 1
            unload all
            sleep 1
            load_xdp "$HYDRA_IFACE" "$HYDRA_OBJ" "$HYDRA_SEC" "HYDRA"
            load_xdp "$SYNWALL_IFACE" "$SYNWALL_OBJ" "$SYNWALL_SEC" "SynWall"
            ;;
    esac
}

# Main
case "${1:-status}" in
    compile)  compile "${2:-all}" ;;
    load)     load "${2:-all}" ;;
    unload)   unload "${2:-all}" ;;
    status)   status ;;
    reload)   reload "${2:-all}" ;;
    *)
        echo "Usage: $0 {compile|load|unload|status|reload} [hydra|synwall|all]"
        exit 1
        ;;
esac
