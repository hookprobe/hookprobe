#!/usr/bin/env bash
#
# install.sh - HookProbe Unified Installer
# Version: 6.2
# License: MIT
#
# Capability-based installation menu with branded deployment tiers:
#   - Sentinel   : Lightweight validator for constrained devices
#   - Guardian   : Travel-secure gateway for home/SMB
#   - Fortress   : Full-featured edge with monitoring
#   - Nexus      : Multi-tenant MSSP command center
#

# Check bash version (need 4.0+)
if [ -z "$BASH_VERSION" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "ERROR: This script requires bash 4.0 or higher"
    echo "Current: ${BASH_VERSION:-not bash}"
    exit 1
fi

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set TERM if not set (for non-interactive environments)
export TERM="${TERM:-xterm}"

# Safe clear function that won't fail
safe_clear() {
    clear 2>/dev/null || printf '\033[2J\033[H' || true
}

# ============================================================
# BRANDING & COLORS
# ============================================================

# Product Names
readonly PRODUCT_NAME="HookProbe"
readonly TIER_SENTINEL="Sentinel"
readonly TIER_GUARDIAN="Guardian"
readonly TIER_FORTRESS="Fortress"
readonly TIER_NEXUS="Nexus"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
ITALIC='\033[3m'
NC='\033[0m' # No Color

# ============================================================
# SYSTEM CAPABILITY DETECTION
# ============================================================

# Global capability variables (set by detect_capabilities)
declare -g SYS_RAM_MB=0
declare -g SYS_RAM_GB=0
declare -g SYS_STORAGE_GB=0
declare -g SYS_STORAGE_TOTAL_GB=0
declare -g SYS_CPU_CORES=0
declare -g SYS_CPU_MODEL=""
declare -g SYS_CPU_FREQ_MHZ=0
declare -g SYS_ARCH=""
declare -g SYS_KERNEL_VERSION=""
declare -g SYS_KERNEL_MAJOR=0
declare -g SYS_KERNEL_MINOR=0
declare -g SYS_OS_NAME=""
declare -g SYS_OS_VERSION=""
declare -g SYS_OS_PRETTY=""
declare -g SYS_HOSTNAME=""

# Network capabilities
declare -g SYS_ETH_COUNT=0
declare -g SYS_ETH_INTERFACES=""
declare -g SYS_WIFI_COUNT=0
declare -g SYS_WIFI_INTERFACES=""
declare -g SYS_WIFI_HOTSPOT=false
declare -g SYS_WIFI_5GHZ=false
declare -g SYS_WIFI_2GHZ=false
declare -g SYS_LTE_COUNT=0
declare -g SYS_LTE_INTERFACES=""
declare -g SYS_BRIDGE_COUNT=0
declare -g SYS_BRIDGES=""
declare -g SYS_WIFI_BRIDGE_COUNT=0
declare -g SYS_WIFI_BRIDGES=""
declare -g SYS_WAN_INTERFACE=""
declare -g SYS_WAN_GATEWAY=""
declare -g SYS_HOOKPROBE_BRIDGE=""
declare -g SYS_DEFAULT_ROUTE=""
declare -g SYS_HAS_INTERNET=false

# Virtualization capabilities
declare -g SYS_IS_VM=false
declare -g SYS_VM_TYPE=""
declare -g SYS_NESTED_VIRT=false
declare -g SYS_IS_PROXMOX=false
declare -g SYS_IS_LXC=false
declare -g SYS_IS_DOCKER=false
declare -g SYS_CGROUPS_VERSION=1

# Security capabilities
declare -g SYS_APPARMOR=false
declare -g SYS_APPARMOR_ENFORCING=false
declare -g SYS_SELINUX=false
declare -g SYS_SELINUX_MODE=""
declare -g SYS_BPF_SUPPORT=false
declare -g SYS_SECCOMP=false

# GPU capabilities
declare -g SYS_HAS_GPU=false
declare -g SYS_GPU_TYPE=""
declare -g SYS_GPU_MEMORY_MB=0

# Container runtime
declare -g SYS_HAS_PODMAN=false
declare -g SYS_PODMAN_VERSION=""
declare -g SYS_HAS_DOCKER=false
declare -g SYS_DOCKER_VERSION=""

# Hardware platform detection
declare -g SYS_IS_RASPBERRY_PI=false
declare -g SYS_PI_MODEL=""
declare -g SYS_IS_JETSON=false
declare -g SYS_IS_ROCKCHIP=false
declare -g SYS_IS_NUC=false
declare -g SYS_IS_GENERIC_X86=false
declare -g SYS_PLATFORM_NAME=""

# Deployment tier eligibility
declare -g CAN_SENTINEL=false
declare -g CAN_GUARDIAN=false
declare -g CAN_FORTRESS=false
declare -g CAN_NEXUS=false

# ============================================================
# DETECTION FUNCTIONS
# ============================================================

detect_os() {
    SYS_HOSTNAME=$(hostname 2>/dev/null || echo "unknown")

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        SYS_OS_NAME=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
        SYS_OS_VERSION="$VERSION_ID"
        SYS_OS_PRETTY="$PRETTY_NAME"
        SYS_OS_ID_LIKE="$ID_LIKE"
    else
        SYS_OS_NAME="unknown"
        SYS_OS_VERSION="unknown"
        SYS_OS_PRETTY="Unknown Linux"
        SYS_OS_ID_LIKE=""
    fi
}

# ============================================================
# RHEL/CENTOS/FEDORA SUPPORT CHECK
# ============================================================

check_debian_based() {
    # Check if the OS is Debian-based (Ubuntu, Debian, Raspberry Pi OS, etc.)
    # RHEL-based systems (RHEL, CentOS, Fedora, Rocky, Alma) are NOT currently supported
    # due to OpenVSwitch networking compatibility issues.
    #
    # Returns:
    #   0 if Debian-based (supported)
    #   1 if RHEL-based or unsupported (not supported)

    case "$SYS_OS_NAME" in
        ubuntu|debian|raspbian|pop|linuxmint|elementary|zorin|kali)
            return 0  # Supported Debian-based
            ;;
        rhel|centos|fedora|rocky|almalinux|ol|scientific)
            return 1  # RHEL-based - not currently supported
            ;;
        *)
            # Check ID_LIKE for Debian-based derivatives
            if [[ "$SYS_OS_ID_LIKE" == *"debian"* ]] || [[ "$SYS_OS_ID_LIKE" == *"ubuntu"* ]]; then
                return 0  # Debian-based derivative
            elif [[ "$SYS_OS_ID_LIKE" == *"rhel"* ]] || [[ "$SYS_OS_ID_LIKE" == *"fedora"* ]] || [[ "$SYS_OS_ID_LIKE" == *"centos"* ]]; then
                return 1  # RHEL-based derivative
            fi
            # Default: allow unknown distributions to proceed
            return 0
            ;;
    esac
}

show_rhel_not_supported() {
    # Display a friendly message that RHEL-based systems are not yet supported.

    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  RHEL-Based Systems Not Yet Supported${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  HookProbe v5.x currently supports ${CYAN}Debian-based${NC} systems only:"
    echo ""
    echo -e "    ${GREEN}✓${NC} Ubuntu 22.04+, 24.04+"
    echo -e "    ${GREEN}✓${NC} Debian 11+, 12+"
    echo -e "    ${GREEN}✓${NC} Raspberry Pi OS (Bookworm)"
    echo ""
    echo -e "  ${RED}Detected OS: ${SYS_OS_PRETTY}${NC}"
    echo ""
    echo -e "  ${YELLOW}Why?${NC}"
    echo "  The container networking stack (OpenVSwitch + CNI) has compatibility"
    echo "  issues with RHEL/CentOS/Fedora/Rocky/AlmaLinux that we're actively"
    echo "  working to resolve."
    echo ""
    echo -e "  ${CYAN}RHEL Support Roadmap:${NC}"
    echo "  We are working on nmcli-based networking for RHEL compatibility."
    echo "  RHEL/Fedora support is planned for a future release."
    echo ""
    echo "  Want to help? Contributions welcome at:"
    echo "    https://github.com/hookprobe/hookprobe"
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

detect_architecture() {
    SYS_ARCH=$(uname -m)
}

detect_kernel() {
    SYS_KERNEL_VERSION=$(uname -r)
    SYS_KERNEL_MAJOR=$(echo "$SYS_KERNEL_VERSION" | cut -d. -f1)
    SYS_KERNEL_MINOR=$(echo "$SYS_KERNEL_VERSION" | cut -d. -f2)
}

detect_cpu() {
    SYS_CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)

    if [ -f /proc/cpuinfo ]; then
        SYS_CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "")

        # ARM processors may use different field
        if [ -z "$SYS_CPU_MODEL" ]; then
            SYS_CPU_MODEL=$(grep -m1 "Model" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "")
        fi
        if [ -z "$SYS_CPU_MODEL" ]; then
            SYS_CPU_MODEL=$(grep -m1 "Hardware" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "Unknown CPU")
        fi

        # Get CPU frequency
        local freq=$(grep -m1 "cpu MHz" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs | cut -d. -f1)
        [ -n "$freq" ] && SYS_CPU_FREQ_MHZ=$freq
    fi
}

detect_ram() {
    if [ -f /proc/meminfo ]; then
        local ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        SYS_RAM_MB=$((ram_kb / 1024))
        SYS_RAM_GB=$((ram_kb / 1024 / 1024))
    fi
}

detect_storage() {
    # Get available storage on root partition
    local storage_kb=$(df / 2>/dev/null | awk 'NR==2 {print $4}')
    SYS_STORAGE_GB=$((storage_kb / 1024 / 1024))

    # Get total storage
    local total_kb=$(df / 2>/dev/null | awk 'NR==2 {print $2}')
    SYS_STORAGE_TOTAL_GB=$((total_kb / 1024 / 1024))
}

detect_platform() {
    SYS_IS_RASPBERRY_PI=false
    SYS_IS_JETSON=false
    SYS_IS_ROCKCHIP=false
    SYS_IS_NUC=false
    SYS_IS_GENERIC_X86=false
    SYS_PLATFORM_NAME="Generic Linux"

    # Check for Raspberry Pi
    if [ -f /proc/device-tree/model ]; then
        local model=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')
        if echo "$model" | grep -qi "raspberry"; then
            SYS_IS_RASPBERRY_PI=true
            SYS_PI_MODEL="$model"
            SYS_PLATFORM_NAME="Raspberry Pi"

            # Detect specific Pi model
            if echo "$model" | grep -qi "pi 5"; then
                SYS_PLATFORM_NAME="Raspberry Pi 5"
            elif echo "$model" | grep -qi "pi 4"; then
                SYS_PLATFORM_NAME="Raspberry Pi 4"
            elif echo "$model" | grep -qi "pi 3"; then
                SYS_PLATFORM_NAME="Raspberry Pi 3"
            elif echo "$model" | grep -qi "zero"; then
                SYS_PLATFORM_NAME="Raspberry Pi Zero"
            fi
        elif echo "$model" | grep -qi "jetson"; then
            SYS_IS_JETSON=true
            SYS_PLATFORM_NAME="NVIDIA Jetson"
        elif echo "$model" | grep -qi "rock\|radxa\|orange"; then
            SYS_IS_ROCKCHIP=true
            SYS_PLATFORM_NAME="Rockchip SBC"
        fi
    fi

    # Check for Intel NUC or similar
    if [ -f /sys/class/dmi/id/product_name ]; then
        local product=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
        if echo "$product" | grep -qi "nuc"; then
            SYS_IS_NUC=true
            SYS_PLATFORM_NAME="Intel NUC"
        elif echo "$product" | grep -qi "n100\|n95\|n97"; then
            SYS_IS_NUC=true
            SYS_PLATFORM_NAME="Intel N-Series Mini PC"
        fi
    fi

    # Generic x86_64
    if [ "$SYS_ARCH" = "x86_64" ] && [ "$SYS_IS_NUC" = false ]; then
        SYS_IS_GENERIC_X86=true
        if [ "$SYS_IS_VM" = true ]; then
            SYS_PLATFORM_NAME="Virtual Machine ($SYS_VM_TYPE)"
        else
            SYS_PLATFORM_NAME="x86_64 Server"
        fi
    fi
}

detect_network_interfaces() {
    SYS_ETH_COUNT=0
    SYS_WIFI_COUNT=0
    SYS_LTE_COUNT=0
    SYS_BRIDGE_COUNT=0
    SYS_WIFI_BRIDGE_COUNT=0
    SYS_ETH_INTERFACES=""
    SYS_WIFI_INTERFACES=""
    SYS_LTE_INTERFACES=""
    SYS_BRIDGES=""
    SYS_WIFI_BRIDGES=""
    SYS_HOOKPROBE_BRIDGE=""

    for iface in /sys/class/net/*; do
        local name=$(basename "$iface")
        [ "$name" = "lo" ] && continue

        if [ -d "$iface" ]; then
            local type_file="$iface/type"
            local wireless_dir="$iface/wireless"

            # Determine interface state by IP address presence (more reliable than operstate)
            # Has IP = UP, No IP = DOWN
            local iface_ip=$(ip -4 addr show "$name" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
            local state="down"
            if [ -n "$iface_ip" ]; then
                state="up"
            fi

            # Check for bridge interfaces
            if [ -d "$iface/bridge" ]; then
                SYS_BRIDGE_COUNT=$((SYS_BRIDGE_COUNT + 1))
                SYS_BRIDGES="${SYS_BRIDGES}${name}:${state} "

                # Check if it's a WiFi/AP bridge (ap*, wifi-br*, wlan-br*, hostap*)
                if echo "$name" | grep -qiE "^(ap[0-9]|wifi[-_]?br|wlan[-_]?br|hostap|wap)"; then
                    SYS_WIFI_BRIDGE_COUNT=$((SYS_WIFI_BRIDGE_COUNT + 1))
                    SYS_WIFI_BRIDGES="${SYS_WIFI_BRIDGES}${name}:${state} "
                fi

                # Check for HookProbe bridge specifically
                if echo "$name" | grep -qiE "^(hookprobe|hpbr|hp[-_]?br)"; then
                    SYS_HOOKPROBE_BRIDGE="$name"
                fi
                continue
            fi

            if [ -d "$wireless_dir" ]; then
                # WiFi interface
                SYS_WIFI_COUNT=$((SYS_WIFI_COUNT + 1))
                SYS_WIFI_INTERFACES="${SYS_WIFI_INTERFACES}${name}:${state} "

                # Check WiFi capabilities using iw
                if command -v iw &>/dev/null; then
                    local phy=$(iw dev "$name" info 2>/dev/null | grep wiphy | awk '{print $2}')
                    if [ -n "$phy" ]; then
                        local phy_info=$(iw phy "phy$phy" info 2>/dev/null)

                        # Check bands
                        if echo "$phy_info" | grep -q "Band 1:"; then
                            SYS_WIFI_2GHZ=true
                        fi
                        if echo "$phy_info" | grep -q "Band 2:"; then
                            SYS_WIFI_5GHZ=true
                        fi

                        # Check AP mode support (hotspot)
                        if echo "$phy_info" | grep -q "\* AP"; then
                            SYS_WIFI_HOTSPOT=true
                        fi
                    fi
                fi
            elif [ -f "$type_file" ] && [ "$(cat "$type_file" 2>/dev/null)" = "1" ]; then
                # Check if it's an LTE/5G/mobile interface
                # Patterns: wwan*, lte*, wwp* (double W like wwp0s20f0u4), usb*, ppp*, cdc*, mbim*
                if echo "$name" | grep -qiE "^(wwan|wwp|lte|usb|ppp|cdc|mbim)"; then
                    SYS_LTE_COUNT=$((SYS_LTE_COUNT + 1))
                    SYS_LTE_INTERFACES="${SYS_LTE_INTERFACES}${name}:${state} "
                elif echo "$name" | grep -qiE "^(veth|docker|br-|virbr|cni|flannel|calico)"; then
                    # Virtual/container interface, skip
                    continue
                else
                    # Regular ethernet
                    SYS_ETH_COUNT=$((SYS_ETH_COUNT + 1))
                    SYS_ETH_INTERFACES="${SYS_ETH_INTERFACES}${name}:${state} "
                fi
            fi
        fi
    done
}

detect_internet_connectivity() {
    SYS_HAS_INTERNET=false
    SYS_DEFAULT_ROUTE=""
    SYS_WAN_INTERFACE=""
    SYS_WAN_GATEWAY=""

    # Detect WAN interface and gateway using ip route get (most reliable method)
    # This shows the actual interface used to reach the internet
    local route_info=$(ip route get 1.1.1.1 2>/dev/null)
    if [ -n "$route_info" ]; then
        # Extract WAN interface (dev <interface>)
        SYS_WAN_INTERFACE=$(echo "$route_info" | grep -oP 'dev \K\S+' | head -1)
        # Extract gateway (via <gateway>)
        SYS_WAN_GATEWAY=$(echo "$route_info" | grep -oP 'via \K\S+' | head -1)
    fi

    # Fallback: Get default route from routing table if ip route get failed
    if [ -z "$SYS_WAN_INTERFACE" ]; then
        local default_route=$(ip route show default 2>/dev/null | head -1)
        SYS_DEFAULT_ROUTE=$(echo "$default_route" | awk '{print $3}')
        SYS_WAN_INTERFACE=$(echo "$default_route" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
        SYS_WAN_GATEWAY="$SYS_DEFAULT_ROUTE"
    else
        SYS_DEFAULT_ROUTE="$SYS_WAN_GATEWAY"
    fi

    # Quick connectivity check (timeout 3 seconds)
    if [ -n "$SYS_WAN_INTERFACE" ] || [ -n "$SYS_DEFAULT_ROUTE" ]; then
        if ping -c 1 -W 3 8.8.8.8 &>/dev/null || ping -c 1 -W 3 1.1.1.1 &>/dev/null; then
            SYS_HAS_INTERNET=true
        fi
    fi
}

detect_virtualization() {
    SYS_IS_VM=false
    SYS_VM_TYPE=""
    SYS_NESTED_VIRT=false
    SYS_IS_PROXMOX=false
    SYS_IS_LXC=false
    SYS_IS_DOCKER=false

    # Check for Docker container
    if [ -f /.dockerenv ] || grep -q "docker\|containerd" /proc/1/cgroup 2>/dev/null; then
        SYS_IS_DOCKER=true
        SYS_IS_VM=true
        SYS_VM_TYPE="docker"
    fi

    # Check for LXC container
    if grep -qa "container=lxc" /proc/1/environ 2>/dev/null || [ -f /dev/lxd/sock ]; then
        SYS_IS_LXC=true
        SYS_IS_VM=true
        SYS_VM_TYPE="lxc"
    fi

    # Detect if running in a VM
    if [ -f /sys/class/dmi/id/product_name ]; then
        local product=$(cat /sys/class/dmi/id/product_name 2>/dev/null | tr '[:upper:]' '[:lower:]')
        case "$product" in
            *vmware*) SYS_IS_VM=true; SYS_VM_TYPE="vmware" ;;
            *virtualbox*) SYS_IS_VM=true; SYS_VM_TYPE="virtualbox" ;;
            *kvm*|*qemu*) SYS_IS_VM=true; SYS_VM_TYPE="kvm" ;;
            *hyper-v*|*virtual*machine*) SYS_IS_VM=true; SYS_VM_TYPE="hyperv" ;;
            *xen*) SYS_IS_VM=true; SYS_VM_TYPE="xen" ;;
        esac
    fi

    # Check for systemd-detect-virt
    if command -v systemd-detect-virt &>/dev/null; then
        local virt=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [ "$virt" != "none" ]; then
            SYS_IS_VM=true
            [ -z "$SYS_VM_TYPE" ] && SYS_VM_TYPE="$virt"
        fi
    fi

    # Check for Proxmox host
    if [ -f /etc/pve/.version ] || command -v pvesh &>/dev/null; then
        SYS_IS_PROXMOX=true
    fi

    # Check nested virtualization
    if [ -f /sys/module/kvm_intel/parameters/nested ]; then
        [ "$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null)" = "Y" ] && SYS_NESTED_VIRT=true
    elif [ -f /sys/module/kvm_amd/parameters/nested ]; then
        [ "$(cat /sys/module/kvm_amd/parameters/nested 2>/dev/null)" = "1" ] && SYS_NESTED_VIRT=true
    fi
}

detect_cgroups() {
    SYS_CGROUPS_VERSION=1

    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        SYS_CGROUPS_VERSION=2
    elif [ -d /sys/fs/cgroup/unified ]; then
        SYS_CGROUPS_VERSION=2  # Hybrid mode
    fi
}

detect_security() {
    SYS_APPARMOR=false
    SYS_APPARMOR_ENFORCING=false
    SYS_SELINUX=false
    SYS_SELINUX_MODE=""
    SYS_BPF_SUPPORT=false
    SYS_SECCOMP=false

    # AppArmor
    if [ -d /sys/kernel/security/apparmor ]; then
        SYS_APPARMOR=true
        if command -v aa-status &>/dev/null; then
            aa-status --enabled 2>/dev/null && SYS_APPARMOR_ENFORCING=true
        fi
    fi

    # SELinux
    if command -v getenforce &>/dev/null; then
        SYS_SELINUX_MODE=$(getenforce 2>/dev/null || echo "Disabled")
        if [ "$SYS_SELINUX_MODE" != "Disabled" ]; then
            SYS_SELINUX=true
        fi
    fi

    # BPF/eBPF support
    if [ -d /sys/fs/bpf ]; then
        SYS_BPF_SUPPORT=true
    elif [ "$SYS_KERNEL_MAJOR" -ge 5 ] || ([ "$SYS_KERNEL_MAJOR" -eq 4 ] && [ "$SYS_KERNEL_MINOR" -ge 15 ]); then
        SYS_BPF_SUPPORT=true
    fi

    # Seccomp support
    if [ -f /proc/sys/kernel/seccomp/actions_avail ] || grep -q "seccomp" /proc/self/status 2>/dev/null; then
        SYS_SECCOMP=true
    fi
}

detect_gpu() {
    SYS_HAS_GPU=false
    SYS_GPU_TYPE=""
    SYS_GPU_MEMORY_MB=0

    # Check for NVIDIA GPU
    if command -v nvidia-smi &>/dev/null; then
        SYS_HAS_GPU=true
        SYS_GPU_TYPE="nvidia"
        # Get GPU memory
        local mem=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1)
        [ -n "$mem" ] && SYS_GPU_MEMORY_MB=$mem
    elif [ -d /proc/driver/nvidia ]; then
        SYS_HAS_GPU=true
        SYS_GPU_TYPE="nvidia"
    # Check for AMD GPU
    elif lspci 2>/dev/null | grep -qi "vga.*amd\|display.*amd\|radeon"; then
        SYS_HAS_GPU=true
        SYS_GPU_TYPE="amd"
    # Check for Intel GPU (integrated)
    elif lspci 2>/dev/null | grep -qi "vga.*intel"; then
        SYS_HAS_GPU=true
        SYS_GPU_TYPE="intel-integrated"
    fi
}

detect_container_runtime() {
    SYS_HAS_PODMAN=false
    SYS_PODMAN_VERSION=""
    SYS_HAS_DOCKER=false
    SYS_DOCKER_VERSION=""

    if command -v podman &>/dev/null; then
        SYS_HAS_PODMAN=true
        SYS_PODMAN_VERSION=$(podman --version 2>/dev/null | awk '{print $3}' || echo "unknown")
    fi

    if command -v docker &>/dev/null; then
        SYS_HAS_DOCKER=true
        SYS_DOCKER_VERSION=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',' || echo "unknown")
    fi
}

# Run all detection functions
detect_capabilities() {
    # Disable exit on error for detection (many commands may fail on different systems)
    set +e

    detect_os

    # Check for supported OS (Debian-based only in v5.x)
    if ! check_debian_based; then
        show_rhel_not_supported
        exit 1
    fi

    detect_architecture
    detect_kernel
    detect_cpu
    detect_ram
    detect_storage
    detect_virtualization
    detect_platform
    detect_network_interfaces
    detect_internet_connectivity
    detect_cgroups
    detect_security
    detect_gpu
    detect_container_runtime
    evaluate_deployment_tiers

    # Re-enable exit on error
    set -e
}

# ============================================================
# DEPLOYMENT TIER EVALUATION
# ============================================================

evaluate_deployment_tiers() {
    # Reset all tiers
    CAN_SENTINEL=false
    CAN_GUARDIAN=false
    CAN_FORTRESS=false
    CAN_NEXUS=false

    local total_net=$((SYS_ETH_COUNT + SYS_WIFI_COUNT))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SENTINEL - "The Watchful Eye"
    # Ultra-lightweight validator for constrained devices
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Requirements:
    #   - RAM: 512MB - 3GB
    #   - Storage: 1GB+ (minimal footprint ~50MB)
    #   - Network: 1 interface (WAN only - modem or ethernet)
    #   - Internet: Required (no offline mode)
    # Purpose: Validates edge nodes, lightweight monitoring
    # Target: RPi Zero, small SBCs, IoT gateways
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if [ "$SYS_RAM_MB" -ge 512 ] && [ "$SYS_STORAGE_GB" -ge 1 ]; then
        if [ "$total_net" -ge 1 ]; then
            CAN_SENTINEL=true
        fi
    fi

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # GUARDIAN - "Protection on the Move"
    # Travel-secure router / Home gateway
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Requirements:
    #   - RAM: 3GB+
    #   - Storage: 16GB - 64GB+
    #   - Network: 2+ interfaces (2 eth OR 1 eth + 1 wifi)
    #   - Internet: Required (MSSP connectivity)
    #   - Bridge: HookProbe bridge required for WiFi deployments
    # Features: QSecBit, OpenFlow, WAF, IDS/IPS, Lite AI
    # Platforms: Raspberry Pi 4/5, Radxa, Banana Pi, etc.
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if [ "$SYS_RAM_MB" -ge 3072 ] && [ "$SYS_STORAGE_GB" -ge 16 ]; then
        # Need at least 2 network interfaces for WAN + LAN
        if [ "$SYS_ETH_COUNT" -ge 2 ] || ([ "$SYS_ETH_COUNT" -ge 1 ] && [ "$SYS_WIFI_COUNT" -ge 1 ]); then
            CAN_GUARDIAN=true
        fi
        # Also allow if we have WiFi bridges that can be controlled
        if [ "$SYS_WIFI_BRIDGE_COUNT" -gt 0 ] && [ "$SYS_ETH_COUNT" -ge 1 ]; then
            CAN_GUARDIAN=true
        fi
    fi

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # FORTRESS - "Your Digital Stronghold"
    # Full-featured edge with local monitoring
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Requirements:
    #   - RAM: 8GB+
    #   - Storage: 32GB+
    #   - Network: 2+ ethernet ports (optional LTE/5G)
    #   - Bridge: HookProbe bridge mandatory for traffic routing
    #   - Kernel: 5.x+ recommended
    # Features: All Guardian + Victoria Metrics, Grafana,
    #           n8n automation, web dashboard, local AI
    # Platforms: Intel N100, NUC, mini PCs, small servers
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if [ "$SYS_RAM_MB" -ge 8192 ] && [ "$SYS_STORAGE_GB" -ge 32 ]; then
        # Primary: 2+ ethernet ports
        if [ "$SYS_ETH_COUNT" -ge 2 ]; then
            CAN_FORTRESS=true
        fi
        # Alternative: 1 eth + WiFi bridges with HookProbe bridge for traffic control
        if [ "$SYS_ETH_COUNT" -ge 1 ] && [ "$SYS_WIFI_BRIDGE_COUNT" -gt 0 ]; then
            CAN_FORTRESS=true
        fi
    fi

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # NEXUS - "The Central Command"
    # Multi-tenant MSSP command center
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Requirements:
    #   - CPU: 8+ cores
    #   - RAM: 64GB+
    #   - Storage: 1TB+
    #   - GPU: Recommended for AI workloads
    # Features: Multi-tenant SOC, ClickHouse analytics,
    #           long-term retention, edge orchestration,
    #           GPU-accelerated threat detection
    # Platforms: Datacenter servers, cloud instances
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if [ "$SYS_CPU_CORES" -ge 8 ] && [ "$SYS_RAM_MB" -ge 65536 ] && [ "$SYS_STORAGE_GB" -ge 1000 ]; then
        CAN_NEXUS=true
    fi
}

# ============================================================
# NETWORK CONFIGURATION HELPERS
# ============================================================

# Configure HookProbe bridge with route metrics for traffic control
# This is called during Guardian/Fortress installation when WiFi bridges are present
configure_hookprobe_bridge() {
    local bridge_name="${1:-hpbr0}"
    local metric="${2:-100}"

    echo -e "${CYAN}Configuring HookProbe bridge...${NC}"

    # Check if bridge-utils is available
    if ! command -v brctl &>/dev/null && ! command -v ip &>/dev/null; then
        echo -e "${YELLOW}Installing bridge-utils...${NC}"
        apt-get install -y bridge-utils iproute2 2>/dev/null || true
    fi

    # Create HookProbe bridge if it doesn't exist
    if ! ip link show "$bridge_name" &>/dev/null; then
        ip link add name "$bridge_name" type bridge
        ip link set "$bridge_name" up
        echo -e "${GREEN}✓ Created bridge: $bridge_name${NC}"
    else
        echo -e "${GREEN}✓ Bridge exists: $bridge_name${NC}"
    fi

    # Configure route metric for traffic prioritization
    # Lower metric = higher priority
    if [ -n "$SYS_WAN_INTERFACE" ] && [ -n "$SYS_WAN_GATEWAY" ]; then
        # Remove existing default route and re-add with metric
        ip route del default via "$SYS_WAN_GATEWAY" dev "$SYS_WAN_INTERFACE" 2>/dev/null || true
        ip route add default via "$SYS_WAN_GATEWAY" dev "$SYS_WAN_INTERFACE" metric 200
        echo -e "${GREEN}✓ WAN route configured: metric 200 (lower priority)${NC}"

        # Add bridge route with higher priority (lower metric number)
        ip route add default via "$SYS_WAN_GATEWAY" dev "$bridge_name" metric "$metric" 2>/dev/null || true
        echo -e "${GREEN}✓ Bridge route configured: metric $metric (higher priority)${NC}"
    fi

    # Save configuration for persistence
    mkdir -p /etc/hookprobe/network
    cat > /etc/hookprobe/network/bridge.conf << BRIDGEEOF
# HookProbe Bridge Configuration
HOOKPROBE_BRIDGE="$bridge_name"
BRIDGE_METRIC=$metric
WAN_INTERFACE="$SYS_WAN_INTERFACE"
WAN_GATEWAY="$SYS_WAN_GATEWAY"
WIFI_BRIDGES="$SYS_WIFI_BRIDGES"
BRIDGEEOF
    chmod 644 /etc/hookprobe/network/bridge.conf
    echo -e "${GREEN}✓ Bridge configuration saved${NC}"

    # Update global variable
    SYS_HOOKPROBE_BRIDGE="$bridge_name"
}

# Display detected network topology
show_network_topology() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    NETWORK TOPOLOGY                           ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # WAN
    if [ -n "$SYS_WAN_INTERFACE" ]; then
        echo -e "  ${GREEN}[WAN]${NC} ─── $SYS_WAN_INTERFACE ─── Gateway: $SYS_WAN_GATEWAY"
    fi

    # Bridges
    if [ "$SYS_BRIDGE_COUNT" -gt 0 ]; then
        echo "     │"
        for br in $SYS_BRIDGES; do
            br_name="${br%%:*}"
            echo -e "     ├── ${CYAN}[BR]${NC} $br_name"
        done
    fi

    # Ethernet
    if [ "$SYS_ETH_COUNT" -gt 0 ]; then
        echo "     │"
        for eth in $SYS_ETH_INTERFACES; do
            eth_name="${eth%%:*}"
            [ "$eth_name" = "$SYS_WAN_INTERFACE" ] && continue
            echo -e "     ├── ${BLUE}[ETH]${NC} $eth_name"
        done
    fi

    # WiFi
    if [ "$SYS_WIFI_COUNT" -gt 0 ]; then
        echo "     │"
        for wifi in $SYS_WIFI_INTERFACES; do
            wifi_name="${wifi%%:*}"
            echo -e "     └── ${YELLOW}[WiFi]${NC} $wifi_name"
        done
    fi

    echo ""
}

# ============================================================
# UI HELPERS
# ============================================================

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ╦ ╦╔═╗╔═╗╦╔═╔═╗╦═╗╔═╗╔╗ ╔═╗
    ╠═╣║ ║║ ║╠╩╗╠═╝╠╦╝║ ║╠╩╗║╣
    ╩ ╩╚═╝╚═╝╩ ╩╩  ╩╚═╚═╝╚═╝╚═╝
EOF
    echo -e "${NC}"
    echo -e "${DIM}    Cyber Resilience at the Edge${NC}"
    echo -e "${DIM}    Unified Installer v6.1${NC}"
    echo ""
}

print_header() {
    local title="$1"
    local color="${2:-$GREEN}"
    echo -e "${color}╔════════════════════════════════════════════════════════════╗${NC}"
    printf "${color}║  %-57s ║${NC}\n" "$title"
    echo -e "${color}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    local title="$1"
    echo -e "${CYAN}━━━ $title ━━━${NC}"
}

print_ok() { echo -e "  ${GREEN}✓${NC} $1"; }
print_warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
print_fail() { echo -e "  ${RED}✗${NC} $1"; }
print_info() { echo -e "  ${BLUE}•${NC} $1"; }

show_nav_footer() {
    echo ""
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}b${NC}) Back    ${BOLD}m${NC}) Main Menu    ${BOLD}q${NC}) Quit"
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo ""
}

# ============================================================
# MAIN MENU
# ============================================================

show_main_menu() {
    print_header "HOOKPROBE UNIFIED INSTALLER"

    echo -e "${YELLOW}┌─ Main Menu ────────────────────────────────────────────────┐${NC}"
    echo -e "│                                                            │"
    echo -e "│  ${BOLD}1${NC}) Check System & Install                                 │"
    echo -e "│     ${DIM}Analyze hardware, select tier, and deploy${NC}              │"
    echo -e "│                                                            │"
    echo -e "│  ${BOLD}2${NC}) Uninstall / Cleanup                                    │"
    echo -e "│     ${DIM}Remove containers, networks, configurations${NC}            │"
    echo -e "│                                                            │"
    echo -e "│  ${BOLD}q${NC}) Quit                                                   │"
    echo -e "│                                                            │"
    echo -e "${YELLOW}└────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ============================================================
# CAPABILITY CHECK
# ============================================================

show_capability_summary() {
    safe_clear
    show_banner
    print_header "SYSTEM CAPABILITY ANALYSIS" "$CYAN"

    # System Overview
    print_section "System Identity"
    print_info "Hostname: $SYS_HOSTNAME"
    print_info "Platform: $SYS_PLATFORM_NAME"
    print_info "OS: $SYS_OS_PRETTY"
    print_info "Kernel: $SYS_KERNEL_VERSION"
    print_info "Architecture: $SYS_ARCH"
    echo ""

    # Hardware Resources
    print_section "Hardware Resources"
    print_info "CPU: $SYS_CPU_MODEL"
    print_info "Cores: $SYS_CPU_CORES"
    [ "$SYS_CPU_FREQ_MHZ" -gt 0 ] && print_info "Frequency: ${SYS_CPU_FREQ_MHZ}MHz"

    # RAM evaluation
    if [ "$SYS_RAM_GB" -ge 64 ]; then
        print_ok "RAM: ${SYS_RAM_GB}GB ${GREEN}(Nexus-ready)${NC}"
    elif [ "$SYS_RAM_GB" -ge 8 ]; then
        print_ok "RAM: ${SYS_RAM_GB}GB ${GREEN}(Fortress-ready)${NC}"
    elif [ "$SYS_RAM_GB" -ge 3 ]; then
        print_ok "RAM: ${SYS_RAM_GB}GB ${YELLOW}(Guardian-ready)${NC}"
    elif [ "$SYS_RAM_MB" -ge 512 ]; then
        print_warn "RAM: ${SYS_RAM_MB}MB ${YELLOW}(Sentinel only)${NC}"
    else
        print_fail "RAM: ${SYS_RAM_MB}MB ${RED}(Insufficient)${NC}"
    fi

    # Storage evaluation
    if [ "$SYS_STORAGE_GB" -ge 1000 ]; then
        print_ok "Storage: ${SYS_STORAGE_GB}GB available ${GREEN}(Nexus-ready)${NC}"
    elif [ "$SYS_STORAGE_GB" -ge 32 ]; then
        print_ok "Storage: ${SYS_STORAGE_GB}GB available ${GREEN}(Fortress-ready)${NC}"
    elif [ "$SYS_STORAGE_GB" -ge 16 ]; then
        print_ok "Storage: ${SYS_STORAGE_GB}GB available ${YELLOW}(Guardian-ready)${NC}"
    elif [ "$SYS_STORAGE_GB" -ge 1 ]; then
        print_warn "Storage: ${SYS_STORAGE_GB}GB available ${YELLOW}(Sentinel only)${NC}"
    else
        print_fail "Storage: ${SYS_STORAGE_GB}GB available ${RED}(Insufficient)${NC}"
    fi
    echo ""

    # GPU
    print_section "GPU / Accelerator"
    if [ "$SYS_HAS_GPU" = true ]; then
        if [ "$SYS_GPU_MEMORY_MB" -gt 0 ]; then
            print_ok "GPU: $SYS_GPU_TYPE (${SYS_GPU_MEMORY_MB}MB VRAM)"
        else
            print_ok "GPU: $SYS_GPU_TYPE"
        fi
    else
        print_info "No dedicated GPU detected"
    fi
    echo ""

    # Network Interfaces
    print_section "Network Interfaces"
    if [ "$SYS_ETH_COUNT" -gt 0 ]; then
        print_ok "Ethernet: $SYS_ETH_COUNT interface(s) [$SYS_ETH_INTERFACES]"
    else
        print_warn "Ethernet: None detected"
    fi

    if [ "$SYS_WIFI_COUNT" -gt 0 ]; then
        print_ok "WiFi: $SYS_WIFI_COUNT interface(s) [$SYS_WIFI_INTERFACES]"
    else
        print_info "WiFi: None detected"
    fi

    if [ "$SYS_LTE_COUNT" -gt 0 ]; then
        print_ok "LTE/5G: $SYS_LTE_COUNT interface(s) [$SYS_LTE_INTERFACES]"
    fi

    # Bridge Interfaces
    if [ "$SYS_BRIDGE_COUNT" -gt 0 ]; then
        echo ""
        print_section "Network Bridges"
        print_ok "Bridges: $SYS_BRIDGE_COUNT [$SYS_BRIDGES]"
        if [ "$SYS_WIFI_BRIDGE_COUNT" -gt 0 ]; then
            print_ok "WiFi/AP Bridges: $SYS_WIFI_BRIDGE_COUNT [$SYS_WIFI_BRIDGES]"
        fi
        if [ -n "$SYS_HOOKPROBE_BRIDGE" ]; then
            print_ok "HookProbe Bridge: $SYS_HOOKPROBE_BRIDGE (configured)"
        else
            print_info "HookProbe Bridge: Not configured"
        fi
    fi

    # WiFi Capabilities
    if [ "$SYS_WIFI_COUNT" -gt 0 ]; then
        echo ""
        print_section "WiFi Capabilities"
        [ "$SYS_WIFI_2GHZ" = true ] && print_ok "2.4GHz band supported"
        [ "$SYS_WIFI_5GHZ" = true ] && print_ok "5GHz band supported"
        if [ "$SYS_WIFI_HOTSPOT" = true ]; then
            print_ok "Hotspot/AP mode supported"
        else
            print_warn "Hotspot/AP mode not available"
        fi
    fi

    # Internet Connectivity / WAN Detection
    echo ""
    print_section "WAN / Connectivity"
    if [ -n "$SYS_WAN_INTERFACE" ]; then
        print_ok "WAN Interface: $SYS_WAN_INTERFACE"
    fi
    if [ -n "$SYS_WAN_GATEWAY" ]; then
        print_ok "Gateway: $SYS_WAN_GATEWAY"
    fi
    if [ "$SYS_HAS_INTERNET" = true ]; then
        print_ok "Internet: Connected"
    else
        print_warn "Internet: Not detected or unreachable"
    fi
    echo ""

    # Virtualization Environment
    print_section "Virtualization"
    if [ "$SYS_IS_VM" = true ]; then
        print_info "Running in: $SYS_VM_TYPE"
        [ "$SYS_IS_LXC" = true ] && print_info "Container: LXC"
        [ "$SYS_IS_DOCKER" = true ] && print_info "Container: Docker"
    else
        print_info "Running on: Bare metal"
    fi
    [ "$SYS_IS_PROXMOX" = true ] && print_info "Proxmox VE host detected"
    [ "$SYS_NESTED_VIRT" = true ] && print_ok "Nested virtualization: Enabled"
    print_info "cgroups: v$SYS_CGROUPS_VERSION"
    echo ""

    # Security Features
    print_section "Security Features"
    if [ "$SYS_APPARMOR" = true ]; then
        if [ "$SYS_APPARMOR_ENFORCING" = true ]; then
            print_ok "AppArmor: Enforcing"
        else
            print_warn "AppArmor: Available (not enforcing)"
        fi
    fi
    if [ "$SYS_SELINUX" = true ]; then
        print_ok "SELinux: $SYS_SELINUX_MODE"
    fi
    [ "$SYS_BPF_SUPPORT" = true ] && print_ok "BPF/eBPF: Supported"
    [ "$SYS_SECCOMP" = true ] && print_ok "Seccomp: Available"
    echo ""

    # Container Runtime
    print_section "Container Runtime"
    if [ "$SYS_HAS_PODMAN" = true ]; then
        print_ok "Podman: $SYS_PODMAN_VERSION"
    else
        print_info "Podman: Not installed"
    fi
    if [ "$SYS_HAS_DOCKER" = true ]; then
        print_ok "Docker: $SYS_DOCKER_VERSION"
    fi
    echo ""

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # ELIGIBLE DEPLOYMENT TIERS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    echo ""
    print_section "Eligible Deployment Tiers"
    echo ""

    local tier_num=1

    # NEXUS
    if [ "$CAN_NEXUS" = true ]; then
        echo -e "  ${BOLD}${tier_num}${NC}) ${GREEN}████${NC} ${BOLD}${WHITE}NEXUS${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "       ${ITALIC}\"The Central Command\"${NC}"
        echo -e "       ${DIM}Multi-tenant MSSP backend with full analytics${NC}"
        tier_num=$((tier_num + 1))
    else
        echo -e "  ${DIM}░░░░ NEXUS [NOT AVAILABLE]${NC}"
        echo -e "       ${DIM}Requires: 8+ cores, 64GB+ RAM, 1TB+ storage${NC}"
    fi
    echo ""

    # FORTRESS
    if [ "$CAN_FORTRESS" = true ]; then
        echo -e "  ${BOLD}${tier_num}${NC}) ${GREEN}███${NC}░ ${BOLD}${WHITE}FORTRESS${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "       ${ITALIC}\"Your Digital Stronghold\"${NC}"
        echo -e "       ${DIM}Full monitoring, dashboards, local AI${NC}"
        tier_num=$((tier_num + 1))
    else
        echo -e "  ${DIM}░░░░ FORTRESS [NOT AVAILABLE]${NC}"
        echo -e "       ${DIM}Requires: 8GB+ RAM, 32GB+ storage, 2+ ethernet${NC}"
    fi
    echo ""

    # GUARDIAN
    if [ "$CAN_GUARDIAN" = true ]; then
        echo -e "  ${BOLD}${tier_num}${NC}) ${GREEN}██${NC}░░ ${BOLD}${WHITE}GUARDIAN${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "       ${ITALIC}\"Protection on the Move\"${NC}"
        echo -e "       ${DIM}Secure gateway with IDS/IPS, WAF, lite AI${NC}"
        tier_num=$((tier_num + 1))
    else
        echo -e "  ${DIM}░░░░ GUARDIAN [NOT AVAILABLE]${NC}"
        echo -e "       ${DIM}Requires: 3GB+ RAM, 16GB+ storage, 2+ NICs${NC}"
    fi
    echo ""

    # SENTINEL
    if [ "$CAN_SENTINEL" = true ]; then
        echo -e "  ${BOLD}${tier_num}${NC}) ${GREEN}█${NC}░░░ ${BOLD}${WHITE}SENTINEL${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "       ${ITALIC}\"The Watchful Eye\"${NC}"
        echo -e "       ${DIM}Lightweight edge validator${NC}"
    else
        echo -e "  ${DIM}░░░░ SENTINEL [NOT AVAILABLE]${NC}"
        echo -e "       ${DIM}Requires: 512MB+ RAM, 1GB+ storage, 1+ NIC${NC}"
    fi

    echo ""
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}Enter number to install${NC} | ${BOLD}b${NC}) Back | ${BOLD}m${NC}) Main Menu | ${BOLD}q${NC}) Quit"
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
}

handle_capability_check() {
    while true; do
        show_capability_summary
        read -p "Select option: " choice

        # Build list of available tiers in order
        local available_tiers=()
        [ "$CAN_NEXUS" = true ] && available_tiers+=("nexus")
        [ "$CAN_FORTRESS" = true ] && available_tiers+=("fortress")
        [ "$CAN_GUARDIAN" = true ] && available_tiers+=("guardian")
        [ "$CAN_SENTINEL" = true ] && available_tiers+=("sentinel")

        case $choice in
            b|B|m|M) return ;;
            q|Q) exit 0 ;;
            [1-9])
                local idx=$((choice - 1))
                if [ $idx -ge 0 ] && [ $idx -lt ${#available_tiers[@]} ]; then
                    local tier="${available_tiers[$idx]}"
                    case "$tier" in
                        sentinel) install_sentinel; return ;;
                        guardian) install_guardian; return ;;
                        fortress) install_fortress; return ;;
                        nexus) install_nexus; return ;;
                    esac
                else
                    echo -e "${RED}Invalid selection${NC}"; sleep 1
                fi
                ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# INSTALL MENU
# ============================================================

show_install_menu() {
    safe_clear
    show_banner
    print_header "INSTALL HOOKPROBE" "$GREEN"

    echo -e "${CYAN}Available deployment tiers for your system:${NC}"
    echo ""

    local option_num=1
    local options=()

    # SENTINEL
    if [ "$CAN_SENTINEL" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${GREEN}█${NC}░░░ ${BOLD}SENTINEL${NC} - ${ITALIC}\"The Watchful Eye\"${NC}"
        echo -e "        ${DIM}Lightweight validator for constrained devices${NC}"
        echo -e "        ${DIM}RAM: 512MB-3GB | Storage: 1GB+ | Network: 1+ interface${NC}"
        echo -e "        ${DIM}Features: Edge validation, health monitoring${NC}"
        echo ""
        options+=("sentinel")
        option_num=$((option_num + 1))
    fi

    # GUARDIAN
    if [ "$CAN_GUARDIAN" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${GREEN}██${NC}░░ ${BOLD}GUARDIAN${NC} - ${ITALIC}\"Protection on the Move\"${NC}"
        echo -e "        ${DIM}Travel-secure router / Home gateway${NC}"
        echo -e "        ${DIM}RAM: 3GB+ | Storage: 16GB+ | Network: 2+ interfaces${NC}"
        echo -e "        ${DIM}Features: QSecBit, OpenFlow, WAF, IDS/IPS, Lite AI${NC}"
        if [ "$SYS_WIFI_HOTSPOT" = true ]; then
            echo -e "        ${GREEN}WiFi hotspot available${NC}"
        fi
        echo -e "        ${YELLOW}Requires: MSSP ID for management${NC}"
        echo ""
        options+=("guardian")
        option_num=$((option_num + 1))
    fi

    # FORTRESS
    if [ "$CAN_FORTRESS" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${GREEN}███${NC}░ ${BOLD}FORTRESS${NC} - ${ITALIC}\"Your Digital Stronghold\"${NC}"
        echo -e "        ${DIM}Full-featured edge with local monitoring${NC}"
        echo -e "        ${DIM}RAM: 8GB+ | Storage: 32GB+ | Network: 2+ ethernet${NC}"
        echo -e "        ${DIM}Features: Guardian + Victoria Metrics, Grafana, n8n, Dashboard${NC}"
        if [ "$SYS_LTE_COUNT" -gt 0 ]; then
            echo -e "        ${GREEN}LTE/5G failover available${NC}"
        fi
        echo ""
        options+=("fortress")
        option_num=$((option_num + 1))
    fi

    # NEXUS
    if [ "$CAN_NEXUS" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${GREEN}████${NC} ${BOLD}NEXUS${NC} - ${ITALIC}\"The Central Command\"${NC}"
        echo -e "        ${DIM}Multi-tenant MSSP command center${NC}"
        echo -e "        ${DIM}Cores: 8+ | RAM: 64GB+ | Storage: 1TB+${NC}"
        echo -e "        ${DIM}Features: Multi-tenant SOC, ClickHouse, long-term retention${NC}"
        if [ "$SYS_HAS_GPU" = true ]; then
            echo -e "        ${GREEN}GPU acceleration: $SYS_GPU_TYPE${NC}"
        fi
        echo ""
        options+=("nexus")
        option_num=$((option_num + 1))
    fi

    # No options available
    if [ ${#options[@]} -eq 0 ]; then
        echo -e "  ${RED}No deployment tiers available for this system.${NC}"
        echo ""
        echo -e "  ${YELLOW}Minimum requirements:${NC}"
        echo -e "    • RAM: 512MB+"
        echo -e "    • Storage: 1GB+"
        echo -e "    • Network: 1+ interface"
        echo ""
        echo -e "  ${CYAN}For ultra-constrained devices, try Sentinel Lite:${NC}"
        echo -e "  ${DIM}curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel/bootstrap.sh | sudo bash${NC}"
        echo ""
    fi

    show_nav_footer
    printf '%s\n' "${options[@]}"
}

# ============================================================
# TIER INSTALLATION FUNCTIONS
# ============================================================

install_sentinel() {
    safe_clear
    show_banner
    print_header "INSTALL: SENTINEL" "$GREEN"

    echo -e "${GREEN}█${NC}░░░ ${BOLD}${WHITE}SENTINEL${NC} - ${ITALIC}\"The Watchful Eye\"${NC}"
    echo ""
    echo "Sentinel is a lightweight validator service for constrained devices"
    echo "like Raspberry Pi 3, IoT gateways, and edge nodes with limited resources."
    echo ""
    echo -e "${YELLOW}What will be installed:${NC}"
    echo "  • HookProbe Sentinel service (no containers)"
    echo "  • Health monitoring endpoint"
    echo "  • Edge node validation"
    echo "  • Minimal footprint (~50MB)"
    echo ""
    echo -e "${YELLOW}Network Requirements:${NC}"
    echo "  • Internet connectivity to MSSP backend"
    echo "  • Outbound HTP (port 8443) - HookProbe Transport Protocol"
    echo "  • Health endpoint on port 9090 (HTTP)"
    echo ""

    read -p "Proceed with Sentinel installation? (yes/no) [no]: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""
        if [ -f "$SCRIPT_DIR/releases/sentinel/bootstrap.sh" ]; then
            bash "$SCRIPT_DIR/releases/sentinel/bootstrap.sh"
        elif [ -f "$SCRIPT_DIR/install-sentinel-lite.sh" ]; then
            bash "$SCRIPT_DIR/install-sentinel-lite.sh"
        else
            echo -e "${YELLOW}Downloading Sentinel installer...${NC}"
            curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel/bootstrap.sh | bash
        fi
    else
        echo "Installation cancelled."
    fi
}

install_guardian() {
    safe_clear
    show_banner
    print_header "INSTALL: GUARDIAN" "$GREEN"

    echo -e "${GREEN}██${NC}░░ ${BOLD}${WHITE}GUARDIAN${NC} - ${ITALIC}\"Protection on the Move\"${NC}"
    echo ""
    echo "Guardian is a travel-secure router and home gateway suitable for"
    echo "protecting networks at home, small businesses, and on the road."
    echo ""
    echo -e "${YELLOW}What will be installed:${NC}"
    echo "  • QSecBit quantum-resistant security"
    echo "  • OpenFlow software-defined networking"
    echo "  • Web Application Firewall (WAF)"
    echo "  • IDS/IPS (Suricata/Zeek)"
    echo "  • Lite AI threat detection"
    echo "  • Ad blocking (optional)"
    echo "  • Container runtime (Podman)"
    echo ""
    echo -e "${YELLOW}Network Configuration:${NC}"
    if [ -n "$SYS_WAN_INTERFACE" ]; then
        echo "  • WAN Interface: $SYS_WAN_INTERFACE (detected)"
    else
        echo "  • WAN: Internet uplink (DHCP or static)"
    fi
    echo "  • LAN: Protected network"
    if [ "$SYS_WIFI_HOTSPOT" = true ]; then
        echo "  • WiFi: Hotspot available for LAN clients"
    fi
    if [ "$SYS_WIFI_BRIDGE_COUNT" -gt 0 ]; then
        echo ""
        echo -e "${CYAN}Bridge Configuration (WiFi deployment detected):${NC}"
        echo "  • WiFi Bridges: $SYS_WIFI_BRIDGES"
        if [ -n "$SYS_HOOKPROBE_BRIDGE" ]; then
            echo -e "  • HookProbe Bridge: ${GREEN}$SYS_HOOKPROBE_BRIDGE (configured)${NC}"
        else
            echo -e "  • HookProbe Bridge: ${YELLOW}Will be created during install${NC}"
        fi
        echo "  • Route metric: 100 (HookProbe bridge priority)"
    fi
    echo ""

    # MSSP ID
    echo -e "${RED}MSSP Registration Required${NC}"
    echo "Guardian requires an MSSP ID for signature updates and management."
    echo ""
    read -p "Enter your MSSP ID (or 'skip' to configure later): " mssp_id

    if [ "$mssp_id" != "skip" ] && [ -n "$mssp_id" ]; then
        mkdir -p /etc/hookprobe/secrets
        echo "$mssp_id" > /etc/hookprobe/secrets/mssp-id
        chmod 600 /etc/hookprobe/secrets/mssp-id
        echo -e "${GREEN}✓ MSSP ID saved${NC}"
    fi

    # WiFi configuration
    if [ "$SYS_WIFI_HOTSPOT" = true ]; then
        echo ""
        echo -e "${CYAN}WiFi Hotspot Configuration:${NC}"
        read -p "Enable WiFi hotspot? (yes/no) [yes]: " enable_hotspot
        enable_hotspot=${enable_hotspot:-yes}

        if [ "$enable_hotspot" = "yes" ]; then
            read -p "WiFi SSID [HookProbe-Guardian]: " wifi_ssid
            wifi_ssid=${wifi_ssid:-HookProbe-Guardian}
            read -sp "WiFi Password (min 8 chars): " wifi_pass
            echo ""

            mkdir -p /etc/hookprobe
            cat > /etc/hookprobe/wifi.conf << WIFIEOF
WIFI_ENABLED=true
WIFI_SSID="$wifi_ssid"
WIFI_PASS="$wifi_pass"
WIFI_BAND="${SYS_WIFI_5GHZ:+5GHz}${SYS_WIFI_5GHZ:-2.4GHz}"
WIFIEOF
            chmod 600 /etc/hookprobe/wifi.conf
            echo -e "${GREEN}✓ WiFi configuration saved${NC}"
        fi
    fi

    # Ad blocking
    echo ""
    read -p "Enable ad blocking? (yes/no) [yes]: " enable_adblock
    enable_adblock=${enable_adblock:-yes}

    echo ""
    read -p "Proceed with Guardian installation? (yes/no) [no]: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""
        export HOOKPROBE_TIER="guardian"
        export HOOKPROBE_ADBLOCK="$enable_adblock"
        if [ -f "$SCRIPT_DIR/install/guardian/setup.sh" ]; then
            bash "$SCRIPT_DIR/install/guardian/setup.sh"
        elif [ -f "$SCRIPT_DIR/scripts/install-edge.sh" ]; then
            bash "$SCRIPT_DIR/scripts/install-edge.sh" --tier guardian
        else
            echo -e "${RED}Guardian installer not found${NC}"
        fi
    else
        echo "Installation cancelled."
    fi
}

install_fortress() {
    safe_clear
    show_banner
    print_header "INSTALL: FORTRESS" "$GREEN"

    echo -e "${GREEN}███${NC}░ ${BOLD}${WHITE}FORTRESS${NC} - ${ITALIC}\"Your Digital Stronghold\"${NC}"
    echo ""
    echo "Fortress is a full-featured edge gateway with local monitoring,"
    echo "dashboards, and automation capabilities for advanced deployments."
    echo ""
    echo -e "${YELLOW}Core Components:${NC}"
    echo "  • All Guardian features, plus:"
    echo "  • Nginx Web Server (reverse proxy)"
    echo "  • PostgreSQL Database"
    echo "  • Logto IAM (Identity & Access Management)"
    echo "  • n8n Workflow Automation"
    echo "  • Kali Security Module (pentest tools)"
    echo "  • Victoria Metrics (time-series database)"
    echo "  • Grafana Dashboards"
    echo "  • Local AI Threat Detection"
    if [ "$SYS_LTE_COUNT" -gt 0 ]; then
        echo "  • LTE/5G failover support"
    fi
    echo ""
    echo -e "${YELLOW}Resource Usage:${NC}"
    echo "  • RAM: ~4-6GB under normal operation"
    echo "  • Storage: ~20GB for containers and data"
    echo ""
    echo -e "${YELLOW}Network Configuration:${NC}"
    if [ -n "$SYS_WAN_INTERFACE" ]; then
        echo "  • WAN Interface: $SYS_WAN_INTERFACE (detected)"
    else
        echo "  • WAN: Internet uplink"
    fi
    echo "  • LAN: Protected network(s)"
    if [ "$SYS_BRIDGE_COUNT" -gt 0 ]; then
        echo ""
        echo -e "${CYAN}Bridge Configuration:${NC}"
        echo "  • Detected Bridges: $SYS_BRIDGES"
        if [ "$SYS_WIFI_BRIDGE_COUNT" -gt 0 ]; then
            echo "  • WiFi Bridges: $SYS_WIFI_BRIDGES"
        fi
        if [ -n "$SYS_HOOKPROBE_BRIDGE" ]; then
            echo -e "  • HookProbe Bridge: ${GREEN}$SYS_HOOKPROBE_BRIDGE (active)${NC}"
        else
            echo -e "  • HookProbe Bridge: ${YELLOW}Required - will be configured${NC}"
        fi
        echo "  • Route metrics will be configured for traffic control"
    fi
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # Logto IAM Configuration
    # ─────────────────────────────────────────────────────────────────
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}LOGTO IAM CONFIGURATION${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Logto provides identity and access management for the Fortress."
    echo ""
    echo -e "${YELLOW}Deployment Options:${NC}"
    echo "  1) Local - Deploy Logto container locally (recommended)"
    echo "  2) Cloud - Use external Logto cloud service"
    echo ""
    read -p "Select Logto deployment [1]: " logto_deployment
    logto_deployment=${logto_deployment:-1}

    local logto_endpoint=""
    local logto_app_id=""
    local logto_app_secret=""
    local logto_local=false

    if [ "$logto_deployment" = "1" ]; then
        # Local Logto deployment
        logto_local=true
        logto_endpoint="http://localhost:3001"
        logto_app_id="local-fortress-app"
        logto_app_secret="auto-generated-on-startup"
        echo -e "${GREEN}✓ Using local Logto container${NC}"
        echo "  Logto will be deployed as part of Fortress installation"
    else
        # Cloud Logto
        local default_endpoint="https://dvvud6.logto.app/"
        echo ""
        echo -e "Default Cloud Endpoint: ${GREEN}$default_endpoint${NC}"
        read -p "Use default endpoint? (yes/no) [yes]: " use_default_logto
        use_default_logto=${use_default_logto:-yes}
        if [ "$use_default_logto" = "yes" ]; then
            logto_endpoint="$default_endpoint"
        else
            read -p "Enter Logto endpoint URL: " logto_endpoint
        fi

        read -p "Enter Logto App ID: " logto_app_id
        while [ -z "$logto_app_id" ]; do
            echo -e "${RED}App ID is required${NC}"
            read -p "Enter Logto App ID: " logto_app_id
        done

        read -sp "Enter Logto App Secret: " logto_app_secret
        echo ""
        while [ -z "$logto_app_secret" ]; do
            echo -e "${RED}App Secret is required${NC}"
            read -sp "Enter Logto App Secret: " logto_app_secret
            echo ""
        done
        echo -e "${GREEN}✓ Logto cloud configuration captured${NC}"
    fi
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # Cloudflare Tunnel Configuration
    # ─────────────────────────────────────────────────────────────────
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}CLOUDFLARE TUNNEL CONFIGURATION${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Cloudflare Tunnel provides secure access to your Fortress without"
    echo "exposing ports to the internet."
    echo ""
    echo -e "${YELLOW}How to get your Tunnel Token:${NC}"
    echo "  1. Go to: https://one.dash.cloudflare.com/"
    echo "  2. Navigate to: Networks > Tunnels"
    echo "  3. Create a new tunnel or select existing"
    echo "  4. Click 'Configure' > 'Install connector'"
    echo "  5. Copy the token from the install command"
    echo ""
    echo -e "${DIM}The token looks like: eyJhIjoiNz...${NC}"
    echo ""

    # Minimum required: Tunnel Token
    read -sp "Enter Cloudflare Tunnel Token (required): " cf_tunnel_token
    echo ""
    while [ -z "$cf_tunnel_token" ]; do
        echo -e "${RED}Tunnel Token is required${NC}"
        read -sp "Enter Cloudflare Tunnel Token: " cf_tunnel_token
        echo ""
    done
    echo -e "${GREEN}✓ Tunnel Token captured${NC}"
    echo ""

    # Optional: Tunnel ID and Account ID (for advanced API operations)
    echo -e "${YELLOW}Optional - for advanced management:${NC}"
    read -p "Enter Tunnel ID (or press Enter to skip): " cf_tunnel_id
    read -p "Enter Account ID (or press Enter to skip): " cf_account_id

    echo -e "${GREEN}✓ Cloudflare configuration complete${NC}"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # Optional Features
    # ─────────────────────────────────────────────────────────────────
    echo -e "${YELLOW}Optional Features:${NC}"
    read -p "Enable Kali security module? (yes/no) [yes]: " enable_kali
    enable_kali=${enable_kali:-yes}

    read -p "Enable n8n automation? (yes/no) [yes]: " enable_n8n
    enable_n8n=${enable_n8n:-yes}

    read -p "Enable Grafana dashboards? (yes/no) [yes]: " enable_grafana
    enable_grafana=${enable_grafana:-yes}

    read -p "Enable ClickHouse analytics? (yes/no) [no]: " enable_clickhouse
    enable_clickhouse=${enable_clickhouse:-no}

    local enable_lte="no"
    if [ "$SYS_LTE_COUNT" -gt 0 ]; then
        read -p "Enable LTE/5G failover? (yes/no) [yes]: " enable_lte
        enable_lte=${enable_lte:-yes}
    fi

    echo ""
    read -p "Proceed with Fortress installation? (yes/no) [no]: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""

        # Save Logto configuration
        mkdir -p /etc/hookprobe/secrets
        cat > /etc/hookprobe/logto.conf << LOGTOEOF
# Logto IAM Configuration
LOGTO_LOCAL=$logto_local
LOGTO_ENDPOINT="$logto_endpoint"
LOGTO_APP_ID="$logto_app_id"
LOGTO_APP_SECRET="$logto_app_secret"
LOGTOEOF
        chmod 600 /etc/hookprobe/logto.conf
        echo -e "${GREEN}✓ Logto configuration saved${NC}"

        # Save Cloudflare configuration
        cat > /etc/hookprobe/cloudflare.conf << CFEOF
# Cloudflare Tunnel Configuration
# Minimum required: TUNNEL_TOKEN
CF_TUNNEL_TOKEN="$cf_tunnel_token"
# Optional - for advanced API operations
CF_TUNNEL_ID="${cf_tunnel_id:-}"
CF_ACCOUNT_ID="${cf_account_id:-}"
CFEOF
        chmod 600 /etc/hookprobe/cloudflare.conf
        echo -e "${GREEN}✓ Cloudflare configuration saved${NC}"

        echo ""
        echo -e "${CYAN}Starting Fortress installation...${NC}"
        echo ""

        export HOOKPROBE_TIER="fortress"
        local extra_args="--non-interactive"
        [ "$enable_kali" = "yes" ] && extra_args="$extra_args --enable-kali"
        [ "$enable_n8n" = "yes" ] && extra_args="$extra_args --enable-n8n"
        [ "$enable_grafana" = "yes" ] && extra_args="$extra_args --enable-monitoring"
        [ "$enable_clickhouse" = "yes" ] && extra_args="$extra_args --enable-clickhouse"
        [ "$enable_lte" = "yes" ] && extra_args="$extra_args --enable-lte"
        [ "$logto_local" = true ] && extra_args="$extra_args --enable-iam"

        if [ -f "$SCRIPT_DIR/install/fortress/setup.sh" ]; then
            bash "$SCRIPT_DIR/install/fortress/setup.sh" $extra_args
        elif [ -f "$SCRIPT_DIR/scripts/install-edge.sh" ]; then
            bash "$SCRIPT_DIR/scripts/install-edge.sh" --tier fortress $extra_args
        else
            echo -e "${RED}Fortress installer not found${NC}"
        fi
    else
        echo "Installation cancelled."
    fi
}

install_nexus() {
    safe_clear
    show_banner
    print_header "INSTALL: NEXUS" "$GREEN"

    echo -e "${GREEN}████${NC} ${BOLD}${WHITE}NEXUS${NC} - ${ITALIC}\"The Central Command\"${NC}"
    echo ""
    echo "Nexus is a multi-tenant MSSP command center for managing"
    echo "distributed edge deployments at enterprise scale."
    echo ""
    echo -e "${YELLOW}What will be installed:${NC}"
    echo "  • Multi-tenant management platform"
    echo "  • ClickHouse analytics database"
    echo "  • Long-term data retention"
    echo "  • Centralized SIEM & logging"
    echo "  • Edge node orchestration"
    echo "  • Tenant isolation & RBAC"
    if [ "$SYS_HAS_GPU" = true ]; then
        echo "  • GPU-accelerated AI ($SYS_GPU_TYPE)"
    fi
    echo ""
    echo -e "${YELLOW}Resource Usage:${NC}"
    echo "  • RAM: ~32-48GB under normal operation"
    echo "  • Storage: Depends on retention policy"
    echo "  • CPU: High utilization during analysis"
    echo ""
    echo -e "${RED}Production Deployment${NC}"
    echo "This tier is intended for production environments."
    echo "Ensure you have:"
    echo "  • Proper backup strategy"
    echo "  • TLS certificates"
    echo "  • DNS configuration"
    echo "  • Database replication (recommended)"
    echo ""

    read -p "Proceed with Nexus installation? (yes/no) [no]: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""
        export HOOKPROBE_TIER="nexus"
        if [ -f "$SCRIPT_DIR/install/nexus/setup.sh" ]; then
            bash "$SCRIPT_DIR/install/nexus/setup.sh"
        elif [ -f "$SCRIPT_DIR/install/cloud/setup.sh" ]; then
            bash "$SCRIPT_DIR/install/cloud/setup.sh" --tier nexus
        else
            echo -e "${RED}Nexus installer not found${NC}"
        fi
    else
        echo "Installation cancelled."
    fi
}

handle_install() {
    while true; do
        local options_output
        options_output=$(show_install_menu)

        local options=()
        while IFS= read -r line; do
            [ -n "$line" ] && options+=("$line")
        done <<< "$options_output"

        read -p "Select tier: " choice

        case $choice in
            b|B|m|M) return ;;
            q|Q) exit 0 ;;
            [0-9]*)
                local idx=$((choice - 1))
                if [ $idx -ge 0 ] && [ $idx -lt ${#options[@]} ]; then
                    case "${options[$idx]}" in
                        sentinel) install_sentinel ;;
                        guardian) install_guardian ;;
                        fortress) install_fortress ;;
                        nexus) install_nexus ;;
                    esac
                    echo ""
                    read -p "Press Enter to continue..."
                else
                    echo -e "${RED}Invalid option${NC}"
                    sleep 1
                fi
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

# ============================================================
# UNINSTALL MENU
# ============================================================

show_uninstall_menu() {
    safe_clear
    show_banner
    print_header "UNINSTALL / CLEANUP" "$RED"

    echo -e "${YELLOW}Select components to remove:${NC}"
    echo ""
    echo -e "  ${BOLD}1${NC}) Stop All Services"
    echo -e "     ${DIM}Stop HookProbe containers and systemd services${NC}"
    echo ""
    echo -e "  ${BOLD}2${NC}) Remove Containers"
    echo -e "     ${DIM}Remove all HookProbe containers (preserves data)${NC}"
    echo ""
    echo -e "  ${BOLD}3${NC}) Remove Container Images"
    echo -e "     ${DIM}Remove downloaded container images${NC}"
    echo ""
    echo -e "  ${BOLD}4${NC}) Remove Volumes & Data"
    echo -e "     ${RED}WARNING: Deletes databases, logs, analytics${NC}"
    echo ""
    echo -e "  ${BOLD}5${NC}) Remove Pod Networks"
    echo -e "     ${DIM}Remove Podman networks created by HookProbe${NC}"
    echo ""
    echo -e "  ${BOLD}6${NC}) Remove OVS Bridges"
    echo -e "     ${DIM}Remove Open vSwitch bridges and flows${NC}"
    echo ""
    echo -e "  ${BOLD}7${NC}) Remove Linux Bridges"
    echo -e "     ${DIM}Remove Linux network bridges${NC}"
    echo ""
    echo -e "  ${BOLD}8${NC}) Reset WiFi Configuration"
    echo -e "     ${DIM}Remove hotspot config, restore defaults${NC}"
    echo ""
    echo -e "  ${BOLD}9${NC}) Complete Uninstall"
    echo -e "     ${RED}DESTRUCTIVE: Remove everything!${NC}"
    echo ""
    show_nav_footer
}

uninstall_stop_services() {
    echo -e "${CYAN}Stopping all HookProbe services...${NC}"
    echo ""

    for service in hookprobe-sentinel hookprobe-guardian hookprobe-fortress hookprobe-nexus hookprobe-edge hookprobe-neuro; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "Stopping $service..."
            systemctl stop "$service" 2>/dev/null || true
        fi
    done

    if command -v podman &>/dev/null; then
        local containers=$(podman ps -q --filter "name=hookprobe" 2>/dev/null)
        [ -n "$containers" ] && podman stop $containers 2>/dev/null || true

        local pods=$(podman pod ps -q --filter "name=hookprobe" 2>/dev/null)
        [ -n "$pods" ] && podman pod stop $pods 2>/dev/null || true
    fi

    echo -e "${GREEN}✓ Services stopped${NC}"
}

uninstall_containers() {
    echo -e "${CYAN}Removing HookProbe containers...${NC}"

    if command -v podman &>/dev/null; then
        local containers=$(podman ps -aq --filter "name=hookprobe" 2>/dev/null)
        [ -n "$containers" ] && podman rm -f $containers 2>/dev/null || true

        local pods=$(podman pod ps -q --filter "name=hookprobe" 2>/dev/null)
        [ -n "$pods" ] && podman pod rm -f $pods 2>/dev/null || true
    fi

    echo -e "${GREEN}✓ Containers removed${NC}"
}

uninstall_images() {
    echo -e "${CYAN}Removing container images...${NC}"

    if command -v podman &>/dev/null; then
        local images=$(podman images -q --filter "reference=*hookprobe*" 2>/dev/null)
        [ -n "$images" ] && podman rmi -f $images 2>/dev/null || true

        for img in postgres redis valkey grafana victoria-metrics n8n suricata zeek clickhouse; do
            podman rmi -f "$img" 2>/dev/null || true
        done
    fi

    echo -e "${GREEN}✓ Images removed${NC}"
}

uninstall_volumes() {
    echo -e "${RED}WARNING: This will delete all persistent data!${NC}"
    read -p "Type 'DELETE' to confirm: " confirm

    if [ "$confirm" = "DELETE" ]; then
        echo -e "${CYAN}Removing volumes...${NC}"

        if command -v podman &>/dev/null; then
            local volumes=$(podman volume ls -q --filter "name=hookprobe" 2>/dev/null)
            [ -n "$volumes" ] && podman volume rm -f $volumes 2>/dev/null || true
        fi

        rm -rf /var/lib/hookprobe 2>/dev/null || true
        rm -rf /var/log/hookprobe 2>/dev/null || true

        echo -e "${GREEN}✓ Volumes removed${NC}"
    else
        echo "Cancelled."
    fi
}

uninstall_networks() {
    echo -e "${CYAN}Removing pod networks...${NC}"

    if command -v podman &>/dev/null; then
        local networks=$(podman network ls -q --filter "name=hookprobe" 2>/dev/null)
        [ -n "$networks" ] && podman network rm -f $networks 2>/dev/null || true
    fi

    echo -e "${GREEN}✓ Networks removed${NC}"
}

uninstall_ovs() {
    echo -e "${CYAN}Removing OVS bridges...${NC}"

    if command -v ovs-vsctl &>/dev/null; then
        for br in $(ovs-vsctl list-br 2>/dev/null | grep -E "^(hookprobe|hp-|guardian|fortress)" || true); do
            ovs-vsctl del-br "$br" 2>/dev/null || true
        done
    fi

    echo -e "${GREEN}✓ OVS bridges removed${NC}"
}

uninstall_bridges() {
    echo -e "${CYAN}Removing Linux bridges...${NC}"

    for br in $(ip -brief link show type bridge 2>/dev/null | awk '{print $1}' | grep -E "^(hookprobe|hp-|br-hp|guardian|fortress)" || true); do
        ip link set "$br" down 2>/dev/null || true
        ip link delete "$br" 2>/dev/null || true
    done

    echo -e "${GREEN}✓ Bridges removed${NC}"
}

uninstall_wifi() {
    echo -e "${CYAN}Resetting WiFi configuration...${NC}"

    systemctl stop hostapd 2>/dev/null || true
    systemctl disable hostapd 2>/dev/null || true
    rm -f /etc/hostapd/hookprobe*.conf 2>/dev/null || true
    rm -f /etc/dnsmasq.d/hookprobe*.conf 2>/dev/null || true
    rm -f /etc/hookprobe/wifi.conf 2>/dev/null || true
    systemctl restart NetworkManager 2>/dev/null || true

    echo -e "${GREEN}✓ WiFi reset${NC}"
}

uninstall_complete() {
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  COMPLETE UNINSTALL - ALL DATA WILL BE DELETED!           ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "This will remove:"
    echo "  • All containers, pods, and images"
    echo "  • All volumes and persistent data"
    echo "  • All network configurations"
    echo "  • All configuration files"
    echo "  • All systemd services"
    echo ""
    read -p "Type 'UNINSTALL EVERYTHING' to confirm: " confirm

    if [ "$confirm" = "UNINSTALL EVERYTHING" ]; then
        uninstall_stop_services
        uninstall_containers
        uninstall_images

        # Force remove volumes
        command -v podman &>/dev/null && podman volume rm -f $(podman volume ls -q) 2>/dev/null || true
        rm -rf /var/lib/hookprobe /var/log/hookprobe 2>/dev/null || true

        uninstall_networks
        uninstall_ovs
        uninstall_bridges
        uninstall_wifi

        # Remove configs
        rm -rf /etc/hookprobe 2>/dev/null || true

        # Remove services
        for svc in hookprobe-sentinel hookprobe-guardian hookprobe-fortress hookprobe-nexus hookprobe-edge hookprobe-neuro; do
            systemctl disable "$svc" 2>/dev/null || true
            rm -f "/etc/systemd/system/${svc}.service" 2>/dev/null || true
        done
        systemctl daemon-reload 2>/dev/null || true

        echo ""
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  UNINSTALL COMPLETE                                        ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    else
        echo "Cancelled."
    fi
}

handle_uninstall() {
    while true; do
        show_uninstall_menu
        read -p "Select option: " choice

        case $choice in
            1) uninstall_stop_services ;;
            2) uninstall_containers ;;
            3) uninstall_images ;;
            4) uninstall_volumes ;;
            5) uninstall_networks ;;
            6) uninstall_ovs ;;
            7) uninstall_bridges ;;
            8) uninstall_wifi ;;
            9) uninstall_complete ;;
            b|B|m|M) return ;;
            q|Q) exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1; continue ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ============================================================
# CLI INTERFACE
# ============================================================

show_usage() {
    cat << EOF
${CYAN}HookProbe Unified Installer v6.1${NC}

${BOLD}Usage:${NC}
  $0                        Interactive menu mode
  $0 --check                Check system capabilities
  $0 --tier <TIER>          Automated installation

${BOLD}Tiers:${NC}
  sentinel    Lightweight validator (512MB+ RAM)
  guardian    Travel-secure gateway (3GB+ RAM, 2+ NICs)
  fortress    Full-featured edge (8GB+ RAM, 2+ ethernet)
  nexus       Multi-tenant MSSP (64GB+ RAM, 8+ cores)

${BOLD}Examples:${NC}
  sudo ./install.sh --check
  sudo ./install.sh --tier sentinel
  sudo ./install.sh --tier guardian

${BOLD}Tier Descriptions:${NC}
  ${GREEN}█${NC}░░░ SENTINEL  "The Watchful Eye"      - Edge validator
  ${GREEN}██${NC}░░ GUARDIAN  "Protection on the Move" - Secure gateway
  ${GREEN}███${NC}░ FORTRESS  "Your Digital Stronghold" - Full monitoring
  ${GREEN}████${NC} NEXUS     "The Central Command"    - MSSP backend

EOF
}

automated_install() {
    local tier="$1"
    detect_capabilities

    case "$tier" in
        sentinel)
            [ "$CAN_SENTINEL" = true ] && install_sentinel || {
                echo -e "${RED}System does not meet Sentinel requirements${NC}"
                exit 1
            }
            ;;
        guardian)
            [ "$CAN_GUARDIAN" = true ] && install_guardian || {
                echo -e "${RED}System does not meet Guardian requirements${NC}"
                exit 1
            }
            ;;
        fortress)
            [ "$CAN_FORTRESS" = true ] && install_fortress || {
                echo -e "${RED}System does not meet Fortress requirements${NC}"
                exit 1
            }
            ;;
        nexus)
            [ "$CAN_NEXUS" = true ] && install_nexus || {
                echo -e "${RED}System does not meet Nexus requirements${NC}"
                exit 1
            }
            ;;
        *)
            echo -e "${RED}Unknown tier: $tier${NC}"
            show_usage
            exit 1
            ;;
    esac
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

# ============================================================
# MAIN
# ============================================================

main() {
    # Debug: confirm script is running
    echo "HookProbe Installer v6.2 starting..." >&2

    check_root
    echo "Root check passed..." >&2

    # Parse CLI arguments
    if [ $# -gt 0 ]; then
        case "$1" in
            --check)
                echo "Running capability check..." >&2
                detect_capabilities
                show_capability_summary
                exit 0
                ;;
            --tier|--role)
                [ -z "$2" ] && { echo -e "${RED}--tier requires an argument${NC}"; show_usage; exit 1; }
                automated_install "$2"
                exit $?
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    fi

    # Interactive mode
    echo "Detecting capabilities..." >&2
    detect_capabilities || { echo "Capability detection failed" >&2; }
    echo "Starting interactive mode..." >&2

    while true; do
        safe_clear
        show_banner
        show_main_menu

        read -p "Select option: " choice

        case $choice in
            1) handle_capability_check ;;
            2) handle_uninstall ;;
            q|Q) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
    done
}

main "$@"
