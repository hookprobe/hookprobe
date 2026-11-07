#!/bin/bash
# =============================================================================
# HookProbe One-Line Installer with NPU Auto-Detection
# =============================================================================
# Usage: curl -sSL https://hookprobe.com/install | bash
#   or:  curl -sSL https://hookprobe.com/install | bash -s -- --tier guardian
#
# Detects: OS, CPU architecture, NPU hardware, RAM → recommends tier
# Installs: podman, python3, git, hookprobe repo, system services
# =============================================================================
set -euo pipefail

HOOKPROBE_VERSION="5.5.0"
HOOKPROBE_REPO="https://github.com/hookprobe/hookprobe.git"
INSTALL_DIR="${HOOKPROBE_DIR:-/opt/hookprobe}"
TIER="${1#--tier=}"  # Allow --tier=guardian or positional

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
err()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# =============================================================================
# Hardware Detection
# =============================================================================
detect_hardware() {
    local arch=$(uname -m)
    local os=$(uname -s)
    local ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}' || sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1048576)}')

    info "Detecting hardware..."
    echo "  OS: $os $arch"
    echo "  RAM: ${ram_mb}MB"

    # NPU Detection
    local npu="none"
    local tops=0

    if [[ "$os" == "Darwin" ]]; then
        npu="apple-neural-engine"
        tops=38
    elif [[ -e /dev/hailo0 ]]; then
        npu="hailo"
        # Detect Hailo-8 vs Hailo-8L
        if [[ -f /sys/class/hailo_chardev/hailo0/board_info ]] && grep -q "hailo8[^l]" /sys/class/hailo_chardev/hailo0/board_info 2>/dev/null; then
            tops=26
        else
            tops=13
        fi
    elif [[ -e /dev/rknpu ]] || [[ -e /dev/rknpu_service ]]; then
        npu="rockchip-rk3588"
        tops=6
    elif [[ -e /dev/apex_0 ]]; then
        npu="google-coral"
        tops=4
    elif [[ -d /sys/class/accel ]]; then
        npu="intel-npu"
        tops=11
    elif command -v nvidia-smi &>/dev/null; then
        npu="nvidia-gpu"
        tops=67
    fi

    echo "  NPU: $npu (${tops} TOPS)"

    # Auto-detect tier if not specified
    if [[ -z "$TIER" || "$TIER" == "--tier" ]]; then
        if (( ram_mb < 512 )); then
            TIER="sentinel"
        elif (( ram_mb < 3072 )); then
            TIER="guardian"
        elif (( ram_mb < 12288 )); then
            TIER="fortress"
        else
            TIER="nexus"
        fi
    fi

    ok "Recommended tier: $TIER (NPU: $npu)"
    export HOOKPROBE_NPU="$npu"
    export HOOKPROBE_TOPS="$tops"
    export HOOKPROBE_TIER="$TIER"
}

# =============================================================================
# Dependency Installation
# =============================================================================
install_deps() {
    info "Installing dependencies..."

    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq podman python3 python3-pip git curl jq >/dev/null 2>&1
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y -q podman python3 python3-pip git curl jq >/dev/null 2>&1
    elif command -v brew &>/dev/null; then
        brew install -q podman python3 git curl jq 2>/dev/null
    else
        err "Unsupported package manager. Install manually: podman python3 git curl jq"
        exit 1
    fi

    ok "Dependencies installed"
}

# =============================================================================
# Clone & Setup
# =============================================================================
clone_repo() {
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        info "Updating existing installation at $INSTALL_DIR..."
        cd "$INSTALL_DIR"
        git pull --rebase --quiet
    else
        info "Cloning HookProbe to $INSTALL_DIR..."
        sudo mkdir -p "$INSTALL_DIR"
        sudo chown "$(id -u):$(id -g)" "$INSTALL_DIR"
        git clone --depth 1 "$HOOKPROBE_REPO" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
    ok "Repository ready"
}

# =============================================================================
# Tier-Specific Setup
# =============================================================================
setup_tier() {
    info "Setting up $TIER tier..."

    # Create config
    cat > "$INSTALL_DIR/.hookprobe.env" << EOF
HOOKPROBE_TIER=$TIER
HOOKPROBE_NPU=$HOOKPROBE_NPU
HOOKPROBE_TOPS=$HOOKPROBE_TOPS
HOOKPROBE_VERSION=$HOOKPROBE_VERSION
INSTALL_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

    case "$TIER" in
        sentinel)
            info "Sentinel: Minimal IDS (RPi 4/5, <512MB model budget)"
            # CPU-only inference, no LLM
            ;;
        guardian)
            info "Guardian: Edge IDS + NPU acceleration"
            # Install NPU-specific packages
            if [[ "$HOOKPROBE_NPU" == "hailo" ]]; then
                info "  Installing Hailo SDK..."
                pip3 install --quiet hailort 2>/dev/null || true
            fi
            ;;
        fortress)
            info "Fortress: Full SOC with local LLM"
            pip3 install --quiet llama-cpp-python 2>/dev/null || true
            ;;
        nexus)
            info "Nexus: Enterprise with 70B local models"
            pip3 install --quiet llama-cpp-python 2>/dev/null || true
            ;;
    esac

    ok "$TIER tier configured"
}

# =============================================================================
# Verify
# =============================================================================
verify() {
    info "Verifying installation..."

    # Test hookprobe-ctl
    if [[ -x "$INSTALL_DIR/bin/hookprobe-ctl" ]]; then
        "$INSTALL_DIR/bin/hookprobe-ctl" hw-info 2>/dev/null || true
    fi

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  HookProbe $HOOKPROBE_VERSION Installed!              ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  Tier:    $TIER                           ${NC}"
    echo -e "${GREEN}║  NPU:     $HOOKPROBE_NPU                 ${NC}"
    echo -e "${GREEN}║  Path:    $INSTALL_DIR                    ${NC}"
    echo -e "${GREEN}║                                           ║${NC}"
    echo -e "${GREEN}║  Next: hookprobe-ctl status               ║${NC}"
    echo -e "${GREEN}║  Docs: https://docs.hookprobe.com         ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  HookProbe Installer v${HOOKPROBE_VERSION}              ║${NC}"
    echo -e "${CYAN}║  Cognitive Defense at Machine Speed       ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════╝${NC}"
    echo ""

    detect_hardware
    install_deps
    clone_repo
    setup_tier
    verify
}

# Handle --tier flag
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tier) TIER="$2"; shift 2 ;;
        --tier=*) TIER="${1#*=}"; shift ;;
        sentinel|guardian|fortress|nexus) TIER="$1"; shift ;;
        --help|-h) echo "Usage: $0 [--tier sentinel|guardian|fortress|nexus]"; exit 0 ;;
        *) shift ;;
    esac
done

main
