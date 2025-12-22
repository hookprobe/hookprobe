#!/usr/bin/env bash
#
# install.sh - HookProbe Unified Installer
# Version: 5.0.0
# License: AGPL-3.0 - see LICENSE file
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
declare -g CAN_MSSP=false

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
    CAN_MSSP=false

    local total_net=$((SYS_ETH_COUNT + SYS_WIFI_COUNT))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SENTINEL - "The Watchful Eye"
    # Ultra-lightweight validator for constrained devices
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Requirements:
    #   - RAM: 256MB minimum (512MB comfortable)
    #   - Storage: 1GB+ (minimal footprint ~50MB)
    #   - Network: 1 interface (WAN only - modem or ethernet)
    #   - Internet: Required (no offline mode)
    # Actual usage: ~150-250MB (single Python service)
    # Purpose: Validates edge nodes, lightweight monitoring
    # Target: RPi Zero, small SBCs, IoT gateways
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if [ "$SYS_RAM_MB" -ge 256 ] && [ "$SYS_STORAGE_GB" -ge 1 ]; then
        if [ "$total_net" -ge 1 ]; then
            CAN_SENTINEL=true
        fi
    fi

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # GUARDIAN - "Protection on the Move"
    # Travel-secure router / Home gateway
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Requirements:
    #   - RAM: 1.5GB+ (2GB recommended)
    #   - Storage: 8GB+ (16GB recommended)
    #   - Network: 2+ interfaces (2 eth OR 1 eth + 1 wifi)
    #   - Internet: Required (MSSP connectivity)
    #   - Bridge: HookProbe bridge required for WiFi deployments
    # Actual usage: ~500-800MB (14% on 4GB RPi4)
    # Features: QSecBit, OpenFlow, WAF, IDS/IPS, Lite AI
    # Platforms: Raspberry Pi 4/5, Radxa, Banana Pi, etc.
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if [ "$SYS_RAM_MB" -ge 1536 ] && [ "$SYS_STORAGE_GB" -ge 8 ]; then
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
    #   - RAM: 4GB+ (8GB recommended)
    #   - Storage: 16GB+ (32GB recommended)
    #   - Network: 2+ ethernet ports (optional LTE/5G)
    #   - Bridge: HookProbe bridge mandatory for traffic routing
    #   - Kernel: 5.x+ recommended
    # Actual usage: ~2-3GB (Guardian + monitoring stack)
    # Features: All Guardian + Victoria Metrics, Grafana,
    #           n8n automation, web dashboard, local AI
    # Platforms: Intel N100, NUC, mini PCs, small servers
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if [ "$SYS_RAM_MB" -ge 4096 ] && [ "$SYS_STORAGE_GB" -ge 16 ]; then
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
    # ML/AI compute hub for edge orchestration
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Requirements:
    #   - CPU: 4+ cores (8+ recommended for ML)
    #   - RAM: 16GB+ (32GB+ recommended for ML workloads)
    #   - Storage: 100GB+ (500GB+ recommended)
    #   - GPU: Optional, recommended for AI workloads
    # Actual usage: ~4-8GB base, 16-32GB with ML
    # Features: ClickHouse analytics, long-term retention,
    #           edge orchestration, GPU-accelerated threat detection
    # Platforms: Datacenter servers, cloud instances
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if [ "$SYS_CPU_CORES" -ge 4 ] && [ "$SYS_RAM_MB" -ge 16384 ] && [ "$SYS_STORAGE_GB" -ge 100 ]; then
        CAN_NEXUS=true
    fi

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # MSSP - "The Central Brain"
    # Cloud-based MSSP platform for POC and production
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Requirements:
    #   - CPU: 4+ cores (8+ recommended)
    #   - RAM: 16GB+ (32GB+ recommended for production)
    #   - Storage: 100GB+ (500GB+ recommended)
    #   - Network: Public IP required
    # Actual usage: ~8-12GB for all PODs
    # Features: Multi-tenant MSSP backend, Django web portal,
    #           PostgreSQL, ClickHouse, VictoriaMetrics, Grafana,
    #           Logto IAM, n8n automation, HTP validator endpoint
    # Purpose: Central coordination of Sentinel/Guardian/Fortress/Nexus
    # Platforms: Cloud instances, dedicated servers
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if [ "$SYS_CPU_CORES" -ge 4 ] && [ "$SYS_RAM_MB" -ge 16384 ] && [ "$SYS_STORAGE_GB" -ge 100 ]; then
        CAN_MSSP=true
    fi
    # Allow MSSP on smaller systems for lightweight POC (8GB RAM)
    if [ "$SYS_CPU_CORES" -ge 2 ] && [ "$SYS_RAM_MB" -ge 8192 ] && [ "$SYS_STORAGE_GB" -ge 50 ]; then
        CAN_MSSP=true  # POC mode with reduced resources
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
    echo ""
    echo -e "${CYAN}    ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗${NC}${WHITE}██████╗ ██████╗  ██████╗ ██████╗ ███████╗${NC}"
    echo -e "${CYAN}    ██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝${NC}${WHITE}██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝${NC}"
    echo -e "${CYAN}    ███████║██║   ██║██║   ██║█████╔╝ ${NC}${WHITE}██████╔╝██████╔╝██║   ██║██████╔╝█████╗  ${NC}"
    echo -e "${CYAN}    ██╔══██║██║   ██║██║   ██║██╔═██╗ ${NC}${WHITE}██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  ${NC}"
    echo -e "${CYAN}    ██║  ██║╚██████╔╝╚██████╔╝██║  ██╗${NC}${WHITE}██║     ██║  ██║╚██████╔╝██████╔╝███████╗${NC}"
    echo -e "${CYAN}    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝${NC}${WHITE}╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝${NC}"
    echo ""
    echo -e "    ${BOLD}${GREEN}⬡${NC} ${DIM}Cyber Resilience at the Edge${NC}  ${BOLD}${YELLOW}v6.2${NC}"
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
    print_section "Deployment Tiers"
    echo ""

    local tier_num=1

    # ─────────────────────────────────────────────────────────────
    # AVAILABLE TIERS (Sentinel & Guardian only for now)
    # ─────────────────────────────────────────────────────────────

    # SENTINEL
    if [ "$CAN_SENTINEL" = true ]; then
        echo -e "  ${BOLD}${tier_num}${NC}) ${GREEN}█${NC}░░░ ${BOLD}${WHITE}SENTINEL${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "       ${ITALIC}\"The Watchful Eye\"${NC}"
        echo -e "       ${DIM}Lightweight edge validator for IoT devices${NC}"
        echo -e "       ${DIM}Installs: Health monitoring, edge validation (~50MB)${NC}"
        tier_num=$((tier_num + 1))
    else
        echo -e "  ${DIM}░░░░ SENTINEL [NOT AVAILABLE]${NC}"
        echo -e "       ${DIM}Requires: 256MB+ RAM, 1GB+ storage, 1+ NIC${NC}"
    fi
    echo ""

    # GUARDIAN
    if [ "$CAN_GUARDIAN" = true ]; then
        echo -e "  ${BOLD}${tier_num}${NC}) ${GREEN}██${NC}░░ ${BOLD}${WHITE}GUARDIAN${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "       ${ITALIC}\"Protection on the Move\"${NC}"
        echo -e "       ${DIM}Travel-secure router / Home gateway${NC}"
        echo -e "       ${DIM}Installs: WiFi AP, IDS/IPS (Suricata), WAF, dnsXai, Web UI${NC}"
        tier_num=$((tier_num + 1))
    else
        echo -e "  ${DIM}░░░░ GUARDIAN [NOT AVAILABLE]${NC}"
        echo -e "       ${DIM}Requires: 1.5GB+ RAM, 8GB+ storage, 2+ NICs${NC}"
    fi
    echo ""

    # FORTRESS
    if [ "$CAN_FORTRESS" = true ]; then
        echo -e "  ${BOLD}${tier_num}${NC}) ${GREEN}███${NC}░ ${BOLD}${WHITE}FORTRESS${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "       ${ITALIC}\"Your Digital Stronghold\"${NC}"
        echo -e "       ${DIM}Full-featured edge router with monitoring${NC}"
        echo -e "       ${DIM}Installs: OVS, VLANs, MACsec, Grafana, VictoriaMetrics, LTE failover${NC}"
        tier_num=$((tier_num + 1))
    else
        echo -e "  ${DIM}░░░░ FORTRESS [NOT AVAILABLE]${NC}"
        echo -e "       ${DIM}Requires: 4GB+ RAM, 16GB+ storage, 2+ ethernet ports${NC}"
    fi
    echo ""

    # ─────────────────────────────────────────────────────────────
    # COMING SOON TIERS (greyed out regardless of system capability)
    # ─────────────────────────────────────────────────────────────


    # NEXUS - Coming Soon
    echo -e "  ${DIM}░░░░ NEXUS ${YELLOW}[COMING SOON]${NC}"
    echo -e "       ${DIM}\"The Central Command\"${NC}"
    echo -e "       ${DIM}ML/AI compute hub with edge orchestration${NC}"
    echo ""

    # MSSP - Coming Soon
    echo -e "  ${DIM}░░░░░ MSSP ${YELLOW}[COMING SOON]${NC}"
    echo -e "       ${DIM}\"The Central Brain\"${NC}"
    echo -e "       ${DIM}Cloud MSSP platform with Django portal${NC}"

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
        # Nexus and MSSP are coming soon and not selectable
        local available_tiers=()
        [ "$CAN_SENTINEL" = true ] && available_tiers+=("sentinel")
        [ "$CAN_GUARDIAN" = true ] && available_tiers+=("guardian")
        [ "$CAN_FORTRESS" = true ] && available_tiers+=("fortress")

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
                    esac
                else
                    echo -e "${RED}Invalid selection. Choose from available tiers.${NC}"; sleep 1
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

    # ─────────────────────────────────────────────────────────────
    # AVAILABLE TIERS (Sentinel & Guardian only for now)
    # ─────────────────────────────────────────────────────────────

    # SENTINEL
    if [ "$CAN_SENTINEL" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${GREEN}█${NC}░░░ ${BOLD}SENTINEL${NC} - ${ITALIC}\"The Watchful Eye\"${NC}"
        echo -e "        ${DIM}Lightweight validator for constrained devices${NC}"
        echo -e "        ${DIM}RAM: 256MB+ | Storage: 1GB+ | Network: 1+ interface${NC}"
        echo -e "        ${CYAN}Installs:${NC}"
        echo -e "          • HookProbe Sentinel service (~50MB)"
        echo -e "          • Health monitoring endpoint (port 9090)"
        echo -e "          • Edge node validation"
        echo ""
        options+=("sentinel")
        option_num=$((option_num + 1))
    fi

    # GUARDIAN
    if [ "$CAN_GUARDIAN" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${GREEN}██${NC}░░ ${BOLD}GUARDIAN${NC} - ${ITALIC}\"Protection on the Move\"${NC}"
        echo -e "        ${DIM}Travel-secure router / Home gateway${NC}"
        echo -e "        ${DIM}RAM: 1.5GB+ | Storage: 8GB+ | Network: 2+ interfaces${NC}"
        echo -e "        ${CYAN}Installs:${NC}"
        echo -e "          • WiFi Access Point (hostapd, dnsmasq)"
        echo -e "          • IDS/IPS (Suricata container)"
        echo -e "          • Web Application Firewall"
        echo -e "          • dnsXai DNS Protection (ML-based ad/tracker blocking)"
        echo -e "          • Guardian Web UI (Flask)"
        echo -e "          • Cortex 3D Globe Visualization"
        echo -e "          • XDP/eBPF DDoS Mitigation"
        echo -e "          • nftables Firewall Rules"
        if [ "$SYS_WIFI_HOTSPOT" = true ]; then
            echo -e "        ${GREEN}✓ WiFi hotspot mode available${NC}"
        fi
        echo ""
        options+=("guardian")
        option_num=$((option_num + 1))
    fi

    # FORTRESS
    if [ "$CAN_FORTRESS" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${GREEN}███${NC}░ ${BOLD}FORTRESS${NC} - ${ITALIC}\"Your Digital Stronghold\"${NC}"
        echo -e "        ${DIM}Full-featured edge router with monitoring${NC}"
        echo -e "        ${DIM}RAM: 4GB+ | Storage: 16GB+ | Network: 2+ ethernet ports${NC}"
        echo -e "        ${CYAN}Installs:${NC}"
        echo -e "          • Open vSwitch with OpenFlow 1.3"
        echo -e "          • VLAN Segmentation (management, trusted, iot, guest, quarantine)"
        echo -e "          • MACsec (802.1AE) Layer 2 encryption"
        echo -e "          • VXLAN tunnels with PSK encryption"
        echo -e "          • Grafana + VictoriaMetrics monitoring"
        echo -e "          • FreeRADIUS with dynamic VLAN assignment"
        echo -e "          • QSecBit Fortress Agent"
        if [ "$SYS_HAS_LTE" = true ] 2>/dev/null || lsusb 2>/dev/null | grep -qiE "quectel|sierra|huawei|fibocom"; then
            echo -e "        ${GREEN}✓ LTE modem detected - failover available${NC}"
        fi
        echo ""
        options+=("fortress")
        option_num=$((option_num + 1))
    fi

    # No options available
    if [ ${#options[@]} -eq 0 ]; then
        echo -e "  ${RED}No deployment tiers available for this system.${NC}"
        echo ""
        echo -e "  ${YELLOW}Minimum requirements:${NC}"
        echo -e "    • RAM: 256MB+ (Sentinel), 1.5GB+ (Guardian), 4GB+ (Fortress)"
        echo -e "    • Storage: 1GB+ (Sentinel), 8GB+ (Guardian), 16GB+ (Fortress)"
        echo -e "    • Network: 1+ interface (Sentinel), 2+ (Guardian/Fortress)"
        echo ""
        echo -e "  ${CYAN}For ultra-constrained devices, try Sentinel Lite:${NC}"
        echo -e "  ${DIM}curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/products/sentinel/bootstrap.sh | sudo bash${NC}"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────
    # COMING SOON TIERS (always greyed out)
    # ─────────────────────────────────────────────────────────────
    echo ""
    echo -e "${YELLOW}Coming Soon:${NC}"
    echo ""
    echo -e "  ${DIM}░░░░ NEXUS - \"The Central Command\"${NC}"
    echo -e "       ${DIM}ML/AI compute hub with ClickHouse analytics${NC}"
    echo ""
    echo -e "  ${DIM}░░░░░ MSSP - \"The Central Brain\"${NC}"
    echo -e "       ${DIM}Cloud MSSP platform with Django portal${NC}"

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
        if [ -f "$SCRIPT_DIR/products/sentinel/bootstrap.sh" ]; then
            bash "$SCRIPT_DIR/products/sentinel/bootstrap.sh"
        elif [ -f "$SCRIPT_DIR/install-sentinel-lite.sh" ]; then
            bash "$SCRIPT_DIR/install-sentinel-lite.sh"
        else
            echo -e "${YELLOW}Downloading Sentinel installer...${NC}"
            curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/products/sentinel/bootstrap.sh | bash
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
    echo "  • OpenFlow SDN with VLAN segmentation"
    echo "  • MAC-based device categorization via RADIUS"
    echo "  • WebSocket VPN with Noise Protocol"
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
    echo "  • LAN: Protected network with VLAN isolation"
    if [ "$SYS_WIFI_HOTSPOT" = true ]; then
        echo "  • WiFi: Hotspot with dynamic VLAN assignment"
    fi
    echo ""

    # ─────────────────────────────────────────────────────────────
    # WiFi Configuration
    # ─────────────────────────────────────────────────────────────
    local wifi_ssid="HookProbe-Guardian"
    local wifi_pass=""

    if [ "$SYS_WIFI_HOTSPOT" = true ]; then
        echo -e "${CYAN}WiFi Hotspot Configuration:${NC}"
        read -p "WiFi SSID [HookProbe-Guardian]: " wifi_ssid_input
        wifi_ssid=${wifi_ssid_input:-HookProbe-Guardian}

        while true; do
            read -sp "WiFi Password (min 8 chars): " wifi_pass
            echo ""
            if [ ${#wifi_pass} -ge 8 ]; then
                break
            else
                echo -e "${RED}Password must be at least 8 characters${NC}"
            fi
        done
        echo -e "${GREEN}✓ WiFi configuration saved${NC}"
    fi

    # ─────────────────────────────────────────────────────────────
    # Ad blocking
    # ─────────────────────────────────────────────────────────────
    echo ""
    read -p "Enable ad blocking? (yes/no) [yes]: " enable_adblock
    enable_adblock=${enable_adblock:-yes}

    # ─────────────────────────────────────────────────────────────
    # Confirmation and Installation
    # ─────────────────────────────────────────────────────────────
    echo ""
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo -e "${BOLD}Installation Summary:${NC}"
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo -e "  WiFi SSID:   ${BOLD}$wifi_ssid${NC}"
    echo -e "  Ad Blocking: ${BOLD}$enable_adblock${NC}"
    echo ""

    read -p "Proceed with Guardian installation? (yes/no) [yes]: " confirm
    confirm=${confirm:-yes}

    if [ "$confirm" = "yes" ]; then
        echo ""
        # Export configuration for setup script
        export HOOKPROBE_TIER="guardian"
        export HOOKPROBE_WIFI_SSID="$wifi_ssid"
        export HOOKPROBE_WIFI_PASS="$wifi_pass"
        export HOOKPROBE_ADBLOCK="$enable_adblock"

        # Save WiFi configuration
        if [ -n "$wifi_pass" ]; then
            mkdir -p /etc/hookprobe
            cat > /etc/hookprobe/wifi.conf << WIFIEOF
WIFI_ENABLED=true
WIFI_SSID="$wifi_ssid"
WIFI_PASS="$wifi_pass"
WIFI_BAND="${SYS_WIFI_5GHZ:+5GHz}${SYS_WIFI_5GHZ:-2.4GHz}"
WIFIEOF
            chmod 600 /etc/hookprobe/wifi.conf
        fi

        # Run Guardian setup script
        local guardian_setup="$SCRIPT_DIR/products/guardian/scripts/setup.sh"
        if [ -f "$guardian_setup" ]; then
            echo -e "${GREEN}Launching Guardian setup...${NC}"
            bash "$guardian_setup"
        else
            echo -e "${RED}Guardian installer not found at: $guardian_setup${NC}"
            echo -e "${YELLOW}Please ensure products/guardian/scripts/setup.sh exists${NC}"
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
    echo "Fortress is a full-featured edge gateway for small businesses."
    echo "Container-based deployment with simple local authentication."
    echo ""
    echo -e "${YELLOW}Core Components:${NC}"
    echo "  • Linux Bridge with LAN interface bridging"
    echo "  • Dual-band WiFi Access Point (hostapd)"
    echo "  • DHCP Server (dnsmasq)"
    echo "  • QSecBit AI Threat Detection"
    echo "  • dnsXai DNS ML Protection"
    echo "  • DFS WiFi Intelligence"
    echo "  • PostgreSQL + Redis (containerized)"
    echo "  • Flask Admin UI (https://localhost:8443)"
    if [ "$SYS_LTE_COUNT" -gt 0 ]; then
        echo "  • LTE/5G failover support"
    fi
    echo ""
    echo -e "${YELLOW}Resource Usage:${NC}"
    echo "  • RAM: ~2-4GB under normal operation"
    echo "  • Storage: ~15GB for containers and data"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # WiFi Access Point Configuration (FIRST)
    # ─────────────────────────────────────────────────────────────────
    local wifi_ssid="hookprobe"
    local wifi_password=""
    if [ "$SYS_WIFI_COUNT" -gt 0 ]; then
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}WIFI ACCESS POINT CONFIGURATION${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "Fortress will create a WiFi Access Point for your devices."
        echo ""

        read -p "WiFi SSID [hookprobe]: " wifi_ssid
        wifi_ssid=${wifi_ssid:-hookprobe}

        echo ""
        echo "Enter a password for the WiFi network (min 8 characters)."
        echo "Leave blank to auto-generate a secure password."
        read -sp "WiFi Password: " wifi_password
        echo ""

        if [ -z "$wifi_password" ]; then
            wifi_password=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
            echo -e "${GREEN}✓ Generated password: ${wifi_password}${NC}"
        elif [ ${#wifi_password} -lt 8 ]; then
            echo -e "${RED}Password too short. Auto-generating secure password...${NC}"
            wifi_password=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
            echo -e "${GREEN}✓ Generated password: ${wifi_password}${NC}"
        else
            echo -e "${GREEN}✓ WiFi password set${NC}"
        fi
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────────
    # Network Size Configuration
    # ─────────────────────────────────────────────────────────────────
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}NETWORK SIZE CONFIGURATION${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Network size determines how many devices can connect:"
    echo "  /29 = 6 devices     (very small office)"
    echo "  /28 = 14 devices    (small office)"
    echo "  /27 = 30 devices    (small business)"
    echo "  /26 = 62 devices    (medium business)"
    echo "  /25 = 126 devices   (larger office)"
    echo "  /24 = 254 devices   (large network)"
    echo "  /23 = 510 devices   (default - recommended)"
    echo ""
    read -p "Network size [/23]: " network_prefix
    network_prefix=${network_prefix:-/23}
    # Remove leading slash if present
    network_prefix=${network_prefix#/}
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # LTE Configuration
    # ─────────────────────────────────────────────────────────────────
    local enable_lte="no"
    local lte_apn=""
    local lte_auth="none"
    local lte_user=""
    local lte_pass=""

    if [ "$SYS_LTE_COUNT" -gt 0 ]; then
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}LTE/5G FAILOVER CONFIGURATION${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${GREEN}✓ LTE modem detected${NC}"
        read -p "Enable LTE/5G failover? (yes/no) [yes]: " enable_lte
        enable_lte=${enable_lte:-yes}

        if [ "$enable_lte" = "yes" ]; then
            echo ""
            echo "Common APNs: internet, internet.vodafone.ro, orange, vzwinternet"
            read -p "Enter your carrier APN [internet]: " lte_apn
            lte_apn=${lte_apn:-internet}

            echo ""
            echo "Authentication type (most carriers use 'none'):"
            echo "  1. none     - No authentication (default, most common)"
            echo "  2. pap      - PAP authentication"
            echo "  3. chap     - CHAP authentication"
            echo "  4. mschapv2 - MS-CHAPv2 authentication"
            echo ""
            read -p "Select [1-4] (default: 1): " auth_choice
            auth_choice=${auth_choice:-1}

            case "$auth_choice" in
                2) lte_auth="pap" ;;
                3) lte_auth="chap" ;;
                4) lte_auth="mschapv2" ;;
                *) lte_auth="none" ;;
            esac

            if [ "$lte_auth" != "none" ]; then
                echo ""
                echo -e "${YELLOW}Authentication: $lte_auth${NC}"
                read -p "Username: " lte_user
                read -sp "Password: " lte_pass
                echo ""
            fi
        fi
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────────
    # Cloudflare Tunnel (OPTIONAL)
    # ─────────────────────────────────────────────────────────────────
    local cf_tunnel_token=""
    local enable_remote="no"

    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}REMOTE ACCESS (OPTIONAL)${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Cloudflare Tunnel allows secure remote access to your dashboard."
    echo "You can configure this later via the Web UI."
    echo ""
    read -p "Configure Cloudflare Tunnel now? (yes/no) [no]: " setup_cf
    setup_cf=${setup_cf:-no}

    if [ "$setup_cf" = "yes" ]; then
        enable_remote="yes"
        echo ""
        echo -e "${YELLOW}How to get your Tunnel Token:${NC}"
        echo "  1. Go to: https://one.dash.cloudflare.com/"
        echo "  2. Navigate to: Networks > Tunnels"
        echo "  3. Create a new tunnel, copy the token"
        echo ""
        read -sp "Enter Cloudflare Tunnel Token: " cf_tunnel_token
        echo ""
        if [ -n "$cf_tunnel_token" ]; then
            echo -e "${GREEN}✓ Tunnel Token captured${NC}"
        fi
    fi
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # Optional Features
    # ─────────────────────────────────────────────────────────────────
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}OPTIONAL FEATURES${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    read -p "Enable n8n automation? (yes/no) [yes]: " enable_n8n
    enable_n8n=${enable_n8n:-yes}

    read -p "Enable Grafana dashboards? (yes/no) [yes]: " enable_grafana
    enable_grafana=${enable_grafana:-yes}

    read -p "Enable ClickHouse analytics? (yes/no) [no]: " enable_clickhouse
    enable_clickhouse=${enable_clickhouse:-no}
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # Configuration Summary
    # ─────────────────────────────────────────────────────────────────
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}CONFIGURATION SUMMARY${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${BOLD}Network Settings:${NC}"
    echo "  • Network size: /${network_prefix}"
    [ -n "$wifi_ssid" ] && echo "  • WiFi SSID: $wifi_ssid"
    echo ""
    echo -e "${BOLD}Core Features:${NC}"
    echo "  ✓ Linux Bridge (fortress) for LAN"
    echo "  ✓ QSecBit Security Agent"
    echo "  ✓ dnsXai DNS Protection"
    echo "  ✓ DFS WiFi Intelligence"
    echo "  ✓ Web Dashboard (https://localhost:8443)"
    echo "  ✓ Local Auth (max 5 users)"
    echo ""
    echo -e "${BOLD}Optional Features:${NC}"
    [ "$enable_lte" = "yes" ] && echo "  ✓ LTE Failover (APN: $lte_apn, Auth: $lte_auth)"
    [ "$enable_remote" = "yes" ] && echo "  ✓ Remote Access (Cloudflare Tunnel)"
    [ "$enable_grafana" = "yes" ] && echo "  ✓ Monitoring (Grafana + Victoria Metrics)"
    [ "$enable_n8n" = "yes" ] && echo "  ✓ n8n Workflow Automation"
    [ "$enable_clickhouse" = "yes" ] && echo "  ✓ ClickHouse Analytics"
    echo ""

    # Default YES for confirmation
    read -p "Proceed with Fortress installation? (yes/no) [yes]: " confirm
    confirm=${confirm:-yes}

    if [ "$confirm" = "yes" ]; then
        echo ""

        # Save Cloudflare configuration if provided
        mkdir -p /etc/hookprobe/secrets
        if [ -n "$cf_tunnel_token" ]; then
            cat > /etc/hookprobe/cloudflare.conf << CFEOF
# Cloudflare Tunnel Configuration
CF_TUNNEL_TOKEN="$cf_tunnel_token"
CFEOF
            chmod 600 /etc/hookprobe/cloudflare.conf
            echo -e "${GREEN}✓ Cloudflare configuration saved${NC}"
        fi

        echo ""
        echo -e "${CYAN}Starting Fortress installation...${NC}"
        echo ""

        export HOOKPROBE_TIER="fortress"
        export FORTRESS_WIFI_SSID="$wifi_ssid"
        export FORTRESS_WIFI_PASSWORD="$wifi_password"
        export FORTRESS_NETWORK_PREFIX="$network_prefix"

        local extra_args="--non-interactive"
        [ "$enable_n8n" = "yes" ] && extra_args="$extra_args --enable-n8n"
        [ "$enable_grafana" = "yes" ] && extra_args="$extra_args --enable-monitoring"
        [ "$enable_clickhouse" = "yes" ] && extra_args="$extra_args --enable-clickhouse"
        [ "$enable_remote" = "yes" ] && extra_args="$extra_args --enable-remote-access"

        if [ "$enable_lte" = "yes" ]; then
            extra_args="$extra_args --enable-lte"
            extra_args="$extra_args --lte-apn $lte_apn"
            extra_args="$extra_args --lte-auth $lte_auth"
            [ -n "$lte_user" ] && extra_args="$extra_args --lte-user $lte_user"
            [ -n "$lte_pass" ] && extra_args="$extra_args --lte-pass $lte_pass"
        fi

        # Container-based Fortress installation (primary method)
        if [ -f "$SCRIPT_DIR/products/fortress/install.sh" ]; then
            # Export environment variables for the container installer
            export WIFI_SSID="$wifi_ssid"
            export WIFI_PASSWORD="$wifi_password"
            export FORTRESS_NETWORK_PREFIX="$network_prefix"
            export NON_INTERACTIVE=true
            [ "$enable_grafana" = "yes" ] && export INSTALL_MONITORING=true

            # Run the container installer with args (non-interactive uses env vars)
            bash "$SCRIPT_DIR/products/fortress/install.sh" $extra_args
            local exit_code=$?

            if [ $exit_code -eq 0 ]; then
                echo ""
                read -p "Press ENTER to continue..." < /dev/tty
            fi
        elif [ -f "$SCRIPT_DIR/products/fortress/install-container.sh" ]; then
            # Fallback to direct container installer
            export WIFI_SSID="$wifi_ssid"
            export WIFI_PASSWORD="$wifi_password"
            export FORTRESS_NETWORK_PREFIX="$network_prefix"
            export NON_INTERACTIVE=true
            [ "$enable_grafana" = "yes" ] && export INSTALL_MONITORING=true

            bash "$SCRIPT_DIR/products/fortress/install-container.sh" $extra_args
        else
            echo -e "${RED}Fortress installer not found${NC}"
            echo "Expected: $SCRIPT_DIR/products/fortress/install.sh"
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
        if [ -f "$SCRIPT_DIR/products/nexus/setup.sh" ]; then
            bash "$SCRIPT_DIR/products/nexus/setup.sh"
        elif [ -f "$SCRIPT_DIR/deploy/cloud/setup.sh" ]; then
            bash "$SCRIPT_DIR/deploy/cloud/setup.sh" --tier nexus
        else
            echo -e "${RED}Nexus installer not found${NC}"
        fi
    else
        echo "Installation cancelled."
    fi
}

install_mssp() {
    safe_clear
    show_banner
    print_header "INSTALL: MSSP" "$GREEN"

    echo -e "${GREEN}█████${NC} ${BOLD}${WHITE}MSSP${NC} - ${ITALIC}\"The Central Brain\"${NC}"
    echo ""
    echo "MSSP is the cloud-based Managed Security Service Provider platform"
    echo "that coordinates and aggregates intelligence from all edge tiers."
    echo ""
    echo -e "${YELLOW}What will be installed:${NC}"
    echo "  • Django web portal with MSSP dashboard"
    echo "  • PostgreSQL database (app data)"
    echo "  • ClickHouse analytics (security events)"
    echo "  • VictoriaMetrics (time-series metrics)"
    echo "  • Grafana dashboards"
    echo "  • Logto IAM (OAuth 2.0 / OIDC)"
    echo "  • Valkey cache (Redis-compatible)"
    echo "  • n8n workflow automation"
    echo "  • HTP validator endpoint (UDP/TCP 4478)"
    echo "  • Qsecbit global aggregation"
    echo ""
    echo -e "${YELLOW}POD-based Architecture:${NC}"
    echo "  • POD-001: DMZ (Nginx + Django)"
    echo "  • POD-002: IAM (Logto)"
    echo "  • POD-003: Database (PostgreSQL)"
    echo "  • POD-004: Cache (Valkey)"
    echo "  • POD-005: Monitoring (ClickHouse, VictoriaMetrics, Grafana)"
    echo "  • POD-006: Security (Qsecbit)"
    echo "  • POD-008: Automation (n8n)"
    echo ""
    echo -e "${YELLOW}Network Architecture:${NC}"
    echo "  • OVS bridge with OpenFlow 1.3/1.4"
    echo "  • VXLAN mesh tunnels (VNI 201-208)"
    echo "  • PSK-encrypted inter-POD communication"
    echo ""
    echo -e "${YELLOW}Resource Usage:${NC}"
    echo "  • RAM: ~32GB baseline (64GB+ recommended)"
    echo "  • Storage: ~250GB for containers and data"
    echo "  • CPU: Moderate-high utilization"
    echo ""
    echo -e "${RED}Production Deployment${NC}"
    echo "This tier is intended for POC and production MSSP deployments."
    echo "Ensure you have:"
    echo "  • Static public IP address"
    echo "  • DNS records configured (or use localhost for POC)"
    echo "  • Firewall rules allowing ports 80, 443, 4478"
    echo ""

    local mssp_domain=""
    local admin_email=""

    read -p "Enter MSSP domain (or 'localhost' for POC) [localhost]: " mssp_domain
    mssp_domain="${mssp_domain:-localhost}"

    read -p "Enter admin email [admin@hookprobe.local]: " admin_email
    admin_email="${admin_email:-admin@hookprobe.local}"

    echo ""
    read -p "Proceed with MSSP installation? (yes/no) [no]: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""
        export HOOKPROBE_TIER="mssp"
        export MSSP_DOMAIN="$mssp_domain"
        export MSSP_ADMIN_EMAIL="$admin_email"

        if [ -f "$SCRIPT_DIR/products/mssp/setup.sh" ]; then
            bash "$SCRIPT_DIR/products/mssp/setup.sh" --domain "$mssp_domain" --admin-email "$admin_email"
        else
            echo -e "${RED}MSSP installer not found at $SCRIPT_DIR/products/mssp/setup.sh${NC}"
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
                    esac
                    echo ""
                    read -p "Press Enter to continue..."
                else
                    echo -e "${RED}Invalid selection. Choose from available tiers.${NC}"
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

    echo -e "${YELLOW}Uninstall by Tier:${NC}"
    echo ""
    echo -e "  ${BOLD}1${NC}) ${GREEN}█${NC}░░░ Sentinel Uninstall"
    echo -e "     ${DIM}Service, firewall rules (iptables), fail2ban config${NC}"
    echo ""
    echo -e "  ${BOLD}2${NC}) ${GREEN}██${NC}░░ Guardian Uninstall"
    echo -e "     ${DIM}Containers, bridges, WiFi, VPN, SDN, IDS/IPS${NC}"
    echo ""
    echo -e "  ${BOLD}3${NC}) ${GREEN}███${NC}░ Fortress Uninstall"
    echo -e "     ${DIM}Guardian + monitoring stack (Grafana, VictoriaMetrics, n8n)${NC}"
    echo ""
    echo -e "  ${BOLD}4${NC}) ${GREEN}████${NC} Nexus Uninstall"
    echo -e "     ${DIM}ML/AI compute hub, ClickHouse, edge orchestration${NC}"
    echo ""
    echo -e "  ${BOLD}5${NC}) ${GREEN}█████${NC} MSSP Uninstall"
    echo -e "     ${DIM}Central brain, Django portal, all PODs, databases${NC}"
    echo ""
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}Cleanup Utilities:${NC}"
    echo ""
    echo -e "  ${BOLD}6${NC}) Stop All Services"
    echo -e "     ${DIM}Stop all HookProbe containers and systemd services${NC}"
    echo ""
    echo -e "  ${BOLD}7${NC}) Clean Everything Else"
    echo -e "     ${RED}OVS bridges, Linux bridges, VXLANs, WiFi, volumes, containers, images${NC}"
    echo ""
    echo -e "  ${BOLD}8${NC}) ${RED}NUCLEAR: Complete System Wipe${NC}"
    echo -e "     ${RED}Remove ALL HookProbe components from ALL tiers!${NC}"
    echo ""
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e " ${BOLD}99${NC}) ${RED}${BOLD}⚠️  FULL SYSTEM PURGE + REBOOT${NC}"
    echo -e "     ${RED}Complete removal of EVERYTHING and automatic reboot${NC}"
    echo -e "     ${DIM}Returns system to clean state for fresh install${NC}"
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

uninstall_guardian() {
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  GUARDIAN COMPLETE UNINSTALL                               ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local guardian_uninstall="$SCRIPT_DIR/products/guardian/scripts/uninstall.sh"

    if [ -f "$guardian_uninstall" ]; then
        echo "Running Guardian uninstall script..."
        echo ""
        bash "$guardian_uninstall"
    else
        echo -e "${YELLOW}Guardian uninstall script not found at:${NC}"
        echo "  $guardian_uninstall"
        echo ""
        echo "Performing manual cleanup..."
        echo ""

        # Stop all Guardian services (core + security stack)
        echo "Stopping Guardian services..."
        local guardian_services=(
            guardian-webui
            guardian-suricata
            guardian-zeek
            guardian-waf
            guardian-xdp
            guardian-aggregator
            guardian-neuro
            guardian-adguard
            guardian-qsecbit
            hostapd
            dnsmasq
        )
        for svc in "${guardian_services[@]}"; do
            echo "  - Stopping $svc..."
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
        done

        # Remove Guardian systemd services
        echo "Removing systemd service files..."
        rm -f /etc/systemd/system/guardian-*.service
        systemctl daemon-reload

        # Complete Podman cleanup
        if command -v podman &>/dev/null; then
            echo ""
            echo "=== Complete Podman Cleanup ==="

            # Stop ALL running containers
            echo "Stopping all containers..."
            podman stop -a 2>/dev/null || true

            # Remove ALL containers (including stopped)
            echo "Removing all containers..."
            podman rm -af 2>/dev/null || true

            # Remove ALL volumes
            echo "Removing all volumes..."
            podman volume rm -af 2>/dev/null || true

            # Remove ALL podman networks (except default)
            echo "Removing podman networks..."
            for net in $(podman network ls --format '{{.Name}}' 2>/dev/null | grep -v "^podman$" || true); do
                echo "  - Removing network: $net"
                podman network rm "$net" 2>/dev/null || true
            done

            # Remove guardian-related images
            echo "Removing container images..."
            local images_to_remove=(
                "docker.io/owasp/modsecurity-crs"
                "docker.io/jasonish/suricata"
                "docker.io/zeek/zeek"
                "docker.io/adguard/adguardhome"
                "modsecurity"
                "suricata"
                "zeek"
                "adguard"
                "snort"
            )
            for img_pattern in "${images_to_remove[@]}"; do
                for img in $(podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -i "$img_pattern" || true); do
                    echo "  - Removing image: $img"
                    podman rmi -f "$img" 2>/dev/null || true
                done
            done

            # Prune unused images, networks, volumes
            echo "Pruning unused podman resources..."
            podman system prune -af 2>/dev/null || true

            # Remove podman network interfaces (podman0, veth*)
            echo "Removing podman network interfaces..."
            ip link set podman0 down 2>/dev/null || true
            ip link delete podman0 2>/dev/null || true

            # Remove all veth interfaces related to podman
            for veth in $(ip link show 2>/dev/null | grep -oP 'veth[^@:]+' | sort -u || true); do
                echo "  - Removing $veth..."
                ip link delete "$veth" 2>/dev/null || true
            done

            # Clean up network namespaces
            echo "Cleaning up network namespaces..."
            for netns in $(ip netns list 2>/dev/null | grep -E "netns-|cni-" | awk '{print $1}' || true); do
                echo "  - Removing netns: $netns"
                ip netns delete "$netns" 2>/dev/null || true
            done

            # Remove CNI configuration
            echo "Removing CNI configuration..."
            rm -rf /etc/cni/net.d/87-podman-bridge.conflist 2>/dev/null || true
            rm -rf /etc/cni/net.d/*guardian* 2>/dev/null || true

            # Reset podman storage (nuclear option)
            echo "Resetting podman storage..."
            podman system reset -f 2>/dev/null || true
        fi

        # Remove XDP/eBPF programs
        echo ""
        echo "Removing XDP/eBPF programs..."
        if command -v ip &>/dev/null; then
            for iface in wlan0 wlan1 eth0 br0; do
                ip link set dev "$iface" xdp off 2>/dev/null || true
            done
        fi
        rm -rf /opt/hookprobe/guardian/xdp

        # Remove Threat Aggregator
        echo "Removing Threat Aggregator..."
        rm -rf /opt/hookprobe/guardian/aggregator

        # Remove Attack Simulator
        echo "Removing Attack Simulator..."
        rm -rf /opt/hookprobe/guardian/simulator

        # Remove Zeek configuration
        echo "Removing Zeek configuration..."
        rm -rf /opt/hookprobe/guardian/zeek

        # Remove network interfaces
        echo "Removing network interfaces..."
        for vlan in 10 20 30 40 50 60 70 80 999; do
            ip link delete "br${vlan}" 2>/dev/null || true
        done
        ip link delete br0 2>/dev/null || true

        # Remove OVS bridges if present
        if command -v ovs-vsctl &>/dev/null; then
            echo "Removing OVS bridges..."
            for br in $(ovs-vsctl list-br 2>/dev/null | grep -E "^(guardian|hp-)" || true); do
                ovs-vsctl del-br "$br" 2>/dev/null || true
            done
        fi

        # Remove configurations
        echo "Removing configuration files..."
        rm -f /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.vlan
        rm -f /etc/hostapd/hostapd.accept /etc/hostapd/hostapd.deny
        rm -f /etc/dnsmasq.d/guardian.conf
        rm -f /etc/nftables.d/guardian*.nft
        rm -f /etc/sysctl.d/99-guardian.conf
        rm -f /etc/default/hostapd

        # Remove dhcpcd guardian configuration
        if [ -f /etc/dhcpcd.conf ]; then
            echo "Removing dhcpcd guardian configuration..."
            sed -i '/# Guardian WAN failover/,/^$/d' /etc/dhcpcd.conf
        fi

        # Remove log directories
        echo "Removing log directories..."
        rm -rf /var/log/hookprobe/threats
        rm -rf /var/log/zeek
        rm -rf /var/log/suricata

        # Remove container storage
        echo "Removing container storage..."
        rm -rf /var/lib/containers/storage/volumes/guardian-* 2>/dev/null || true

        # Remove Guardian installation directory
        echo "Removing Guardian installation..."
        rm -rf /opt/hookprobe/guardian

        # Final verification
        echo ""
        echo "=== Verification ==="
        echo "Checking for remaining containers..."
        if command -v podman &>/dev/null; then
            local remaining=$(podman ps -a --format '{{.Names}}' 2>/dev/null | wc -l)
            if [ "$remaining" -gt 0 ]; then
                echo -e "${YELLOW}Warning: $remaining container(s) still exist${NC}"
                podman ps -a 2>/dev/null
            else
                echo -e "${GREEN}✓ No containers remaining${NC}"
            fi
        fi

        echo "Checking for podman interfaces..."
        if ip link show podman0 &>/dev/null; then
            echo -e "${YELLOW}Warning: podman0 interface still exists${NC}"
        else
            echo -e "${GREEN}✓ podman0 interface removed${NC}"
        fi

        echo ""
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  Guardian cleanup complete                                  ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "If any issues remain, you can manually run:"
        echo "  sudo podman system reset -f"
        echo "  sudo rm -rf /var/lib/containers"
        echo ""
    fi
}

uninstall_sentinel() {
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  SENTINEL COMPLETE UNINSTALL                               ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local sentinel_uninstall="$SCRIPT_DIR/products/sentinel/uninstall.sh"

    if [ -f "$sentinel_uninstall" ]; then
        echo "Running Sentinel uninstall script..."
        echo ""
        bash "$sentinel_uninstall"
    else
        echo -e "${YELLOW}Sentinel uninstall script not found at:${NC}"
        echo "  $sentinel_uninstall"
        echo ""
        echo "Performing manual cleanup..."
        echo ""

        # Stop Sentinel service
        echo "Stopping Sentinel service..."
        systemctl stop hookprobe-sentinel 2>/dev/null || true
        systemctl disable hookprobe-sentinel 2>/dev/null || true

        # Remove systemd service file
        echo "Removing systemd service..."
        rm -f /etc/systemd/system/hookprobe-sentinel.service
        systemctl daemon-reload

        # Remove firewall rules
        echo "Removing firewall rules..."
        iptables -D INPUT -j HOOKPROBE 2>/dev/null || true
        iptables -F HOOKPROBE 2>/dev/null || true
        iptables -X HOOKPROBE 2>/dev/null || true

        # Remove fail2ban config
        echo "Removing fail2ban configuration..."
        rm -f /etc/fail2ban/jail.d/hookprobe-sentinel.conf 2>/dev/null || true
        rm -f /etc/fail2ban/filter.d/hookprobe-sentinel.conf 2>/dev/null || true
        systemctl restart fail2ban 2>/dev/null || true

        # Remove configuration
        echo "Removing configuration..."
        rm -f /etc/hookprobe/sentinel.env 2>/dev/null || true
        rm -f /etc/hookprobe/secrets/mssp-token 2>/dev/null || true

        # Remove installation directory
        echo "Removing installation directory..."
        rm -rf /opt/hookprobe/sentinel

        # Remove data directory
        echo "Removing data directory..."
        rm -rf /var/lib/hookprobe/sentinel

        # Remove uninstall command
        rm -f /usr/local/bin/sentinel-uninstall 2>/dev/null || true

        # Clean up empty directories
        [ -d /etc/hookprobe/secrets ] && [ -z "$(ls -A /etc/hookprobe/secrets 2>/dev/null)" ] && rmdir /etc/hookprobe/secrets 2>/dev/null || true
        [ -d /etc/hookprobe ] && [ -z "$(ls -A /etc/hookprobe 2>/dev/null)" ] && rmdir /etc/hookprobe 2>/dev/null || true
        [ -d /var/lib/hookprobe ] && [ -z "$(ls -A /var/lib/hookprobe 2>/dev/null)" ] && rmdir /var/lib/hookprobe 2>/dev/null || true
        [ -d /opt/hookprobe ] && [ -z "$(ls -A /opt/hookprobe 2>/dev/null)" ] && rmdir /opt/hookprobe 2>/dev/null || true

        echo ""
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  Sentinel cleanup complete                                  ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "Removed:"
        echo "  • hookprobe-sentinel service"
        echo "  • Firewall rules (HOOKPROBE chain)"
        echo "  • Fail2ban configuration"
        echo "  • Configuration files"
        echo "  • Installation directory"
        echo "  • Data directory"
        echo ""
    fi
}

uninstall_fortress() {
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  FORTRESS COMPLETE UNINSTALL                               ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}This will remove:${NC}"
    echo "  • Fortress systemd services"
    echo "  • OVS bridge and VLAN configuration"
    echo "  • MACsec and VXLAN tunnels"
    echo "  • QSecBit agent"
    echo "  • Monitoring stack (VictoriaMetrics, Grafana)"
    echo "  • LTE failover configuration"
    echo "  • Web dashboard"
    echo "  • All configuration and secrets"
    echo ""
    read -p "Are you sure? Type 'yes' to confirm: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""
        # Use the dedicated Fortress uninstall script with --force (already confirmed)
        if [ -f "$SCRIPT_DIR/products/fortress/uninstall.sh" ]; then
            bash "$SCRIPT_DIR/products/fortress/uninstall.sh" --force
        else
            # Fallback if script not found
            log_warn "Fortress uninstall script not found, performing basic cleanup..."

            # Stop services
            for svc in hookprobe-fortress fortress-qsecbit fortress-lte-failover fortress-tunnel; do
                systemctl stop "$svc" 2>/dev/null || true
                systemctl disable "$svc" 2>/dev/null || true
                rm -f "/etc/systemd/system/${svc}.service" 2>/dev/null || true
            done
            systemctl daemon-reload

            # Remove directories
            rm -rf /opt/hookprobe/fortress 2>/dev/null || true
            rm -rf /var/lib/hookprobe/fortress 2>/dev/null || true
            rm -rf /var/lib/fortress 2>/dev/null || true
            rm -rf /etc/fortress 2>/dev/null || true
            rm -f /etc/hookprobe/fortress.conf 2>/dev/null || true

            echo -e "${GREEN}✓ Fortress uninstall complete${NC}"
        fi
    else
        echo "Cancelled."
    fi
}

uninstall_nexus() {
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  NEXUS COMPLETE UNINSTALL                                  ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}This will remove:${NC}"
    echo "  • MSSP backend services"
    echo "  • ClickHouse (analytics database)"
    echo "  • Multi-tenant SOC components"
    echo "  • All edge agent registrations"
    echo ""
    echo -e "${RED}WARNING: This will disconnect all managed edge devices!${NC}"
    echo ""
    read -p "Are you sure? Type 'DELETE-NEXUS' to confirm: " confirm
    if [ "$confirm" = "DELETE-NEXUS" ]; then
        echo ""

        # Stop Nexus services
        echo "Stopping Nexus services..."
        for svc in hookprobe-nexus clickhouse hookprobe-mssp hookprobe-soc; do
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
        done

        # Remove Nexus containers
        if command -v podman &>/dev/null; then
            echo "Removing Nexus containers..."
            for container in clickhouse hookprobe-mssp hookprobe-soc hookprobe-api hookprobe-web; do
                podman stop "$container" 2>/dev/null || true
                podman rm -f "$container" 2>/dev/null || true
            done

            # Remove Nexus volumes
            echo "Removing Nexus volumes..."
            for vol in clickhouse-data nexus-data mssp-data soc-data; do
                podman volume rm -f "$vol" 2>/dev/null || true
            done
        fi

        # Remove Nexus directories
        rm -rf /opt/hookprobe/nexus 2>/dev/null || true
        rm -rf /var/lib/hookprobe/nexus 2>/dev/null || true
        rm -rf /var/lib/clickhouse 2>/dev/null || true

        # Remove systemd service files
        rm -f /etc/systemd/system/hookprobe-nexus.service
        rm -f /etc/systemd/system/hookprobe-mssp.service
        systemctl daemon-reload

        echo ""
        echo -e "${GREEN}✓ Nexus uninstall complete${NC}"
    else
        echo "Cancelled."
    fi
}

uninstall_mssp() {
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  MSSP COMPLETE UNINSTALL                                   ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}This will remove:${NC}"
    echo "  • Django web portal and all PODs"
    echo "  • PostgreSQL database (all app data)"
    echo "  • ClickHouse analytics (all security events)"
    echo "  • VictoriaMetrics (all metrics)"
    echo "  • Grafana dashboards"
    echo "  • Logto IAM configuration"
    echo "  • Valkey cache"
    echo "  • n8n workflows"
    echo "  • HTP validator endpoint"
    echo "  • OVS bridge and VXLAN tunnels"
    echo ""
    echo -e "${RED}WARNING: This will disconnect all managed edge devices!${NC}"
    echo -e "${RED}WARNING: All MSSP data will be lost!${NC}"
    echo ""
    read -p "Are you sure? Type 'DELETE-MSSP' to confirm: " confirm
    if [ "$confirm" = "DELETE-MSSP" ]; then
        echo ""

        # Use the MSSP uninstall script if available
        if [ -f "$SCRIPT_DIR/products/mssp/uninstall.sh" ]; then
            bash "$SCRIPT_DIR/products/mssp/uninstall.sh" --complete --force
        else
            # Fallback: manual cleanup
            echo "Stopping MSSP services..."
            systemctl stop hookprobe-mssp 2>/dev/null || true
            systemctl disable hookprobe-mssp 2>/dev/null || true

            # Stop all MSSP containers
            if command -v podman &>/dev/null; then
                echo "Stopping MSSP containers..."
                for container in mssp-htp mssp-n8n mssp-qsecbit mssp-nginx mssp-celery mssp-django mssp-logto mssp-grafana mssp-clickhouse mssp-victoriametrics mssp-valkey mssp-postgres; do
                    podman stop "$container" 2>/dev/null || true
                    podman rm -f "$container" 2>/dev/null || true
                done

                # Remove MSSP networks
                echo "Removing MSSP networks..."
                for net in mssp-pod-001-dmz mssp-pod-002-iam mssp-pod-003-db mssp-pod-004-cache mssp-pod-005-monitoring mssp-pod-006-security mssp-pod-007-response mssp-pod-008-automation mssp-external; do
                    podman network rm "$net" 2>/dev/null || true
                done

                # Remove custom images
                for img in localhost/mssp-django localhost/mssp-qsecbit localhost/mssp-htp; do
                    podman rmi "$img" 2>/dev/null || true
                done
            fi

            # Remove OVS bridge
            if command -v ovs-vsctl &>/dev/null; then
                echo "Removing OVS bridge..."
                for vni in 201 202 203 204 205 206 207 208; do
                    ovs-vsctl del-port mssp-bridge "vxlan_${vni}" 2>/dev/null || true
                done
                ovs-vsctl del-port mssp-bridge vxlan_edge 2>/dev/null || true
                ip link set mssp-bridge down 2>/dev/null || true
                ovs-vsctl del-br mssp-bridge 2>/dev/null || true
            fi

            # Remove directories
            echo "Removing MSSP directories..."
            rm -rf /opt/hookprobe/mssp 2>/dev/null || true
            rm -rf /var/lib/hookprobe/mssp 2>/dev/null || true
            rm -rf /var/log/hookprobe/mssp 2>/dev/null || true
            rm -rf /etc/hookprobe/mssp 2>/dev/null || true
            rm -rf /etc/hookprobe/secrets/mssp 2>/dev/null || true

            # Remove systemd files
            rm -f /etc/systemd/system/hookprobe-mssp.service
            rm -f /usr/local/bin/hookprobe-mssp-start
            rm -f /usr/local/bin/hookprobe-mssp-stop
            systemctl daemon-reload
        fi

        echo ""
        echo -e "${GREEN}✓ MSSP uninstall complete${NC}"
    else
        echo "Cancelled."
    fi
}

uninstall_cleanup_everything() {
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  CLEANUP EVERYTHING ELSE                                   ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}This will clean up leftover components:${NC}"
    echo "  • OVS bridges (Open vSwitch)"
    echo "  • Linux bridges"
    echo "  • VXLAN tunnels"
    echo "  • WiFi/hostapd configuration"
    echo "  • Podman volumes and networks"
    echo "  • Container images"
    echo "  • Orphaned network interfaces"
    echo ""
    read -p "Proceed with cleanup? (yes/no) [no]: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""

        # ─────────────────────────────────────────────────────────────
        # OVS Bridges
        # ─────────────────────────────────────────────────────────────
        echo "=== Removing OVS Bridges ==="
        if command -v ovs-vsctl &>/dev/null; then
            for br in $(ovs-vsctl list-br 2>/dev/null || true); do
                echo "  Removing OVS bridge: $br"
                ovs-vsctl del-br "$br" 2>/dev/null || true
            done
            echo -e "${GREEN}✓ OVS bridges removed${NC}"
        else
            echo "  OVS not installed, skipping"
        fi
        echo ""

        # ─────────────────────────────────────────────────────────────
        # Linux Bridges
        # ─────────────────────────────────────────────────────────────
        echo "=== Removing Linux Bridges ==="
        for br in $(ip -brief link show type bridge 2>/dev/null | awk '{print $1}' || true); do
            if [[ "$br" =~ ^(br|hookprobe|hp-|guardian|fortress) ]]; then
                echo "  Removing bridge: $br"
                ip link set "$br" down 2>/dev/null || true
                ip link delete "$br" 2>/dev/null || true
            fi
        done
        echo -e "${GREEN}✓ Linux bridges removed${NC}"
        echo ""

        # ─────────────────────────────────────────────────────────────
        # VXLAN Tunnels
        # ─────────────────────────────────────────────────────────────
        echo "=== Removing VXLAN Tunnels ==="
        for vxlan in $(ip -brief link show type vxlan 2>/dev/null | awk '{print $1}' || true); do
            echo "  Removing VXLAN: $vxlan"
            ip link set "$vxlan" down 2>/dev/null || true
            ip link delete "$vxlan" 2>/dev/null || true
        done
        echo -e "${GREEN}✓ VXLAN tunnels removed${NC}"
        echo ""

        # ─────────────────────────────────────────────────────────────
        # VLAN Interfaces
        # ─────────────────────────────────────────────────────────────
        echo "=== Removing VLAN Interfaces ==="
        for vlan in $(ip -brief link show type vlan 2>/dev/null | awk '{print $1}' || true); do
            echo "  Removing VLAN interface: $vlan"
            ip link set "$vlan" down 2>/dev/null || true
            ip link delete "$vlan" 2>/dev/null || true
        done
        echo -e "${GREEN}✓ VLAN interfaces removed${NC}"
        echo ""

        # ─────────────────────────────────────────────────────────────
        # WiFi Configuration
        # ─────────────────────────────────────────────────────────────
        echo "=== Resetting WiFi Configuration ==="
        systemctl stop hostapd 2>/dev/null || true
        systemctl disable hostapd 2>/dev/null || true
        rm -f /etc/hostapd/hostapd.conf 2>/dev/null || true
        rm -f /etc/hostapd/hostapd.vlan 2>/dev/null || true
        rm -f /etc/hostapd/hostapd.accept 2>/dev/null || true
        rm -f /etc/hostapd/hostapd.deny 2>/dev/null || true
        rm -f /etc/default/hostapd 2>/dev/null || true

        systemctl stop dnsmasq 2>/dev/null || true
        rm -f /etc/dnsmasq.d/guardian*.conf 2>/dev/null || true
        rm -f /etc/dnsmasq.d/hookprobe*.conf 2>/dev/null || true

        echo -e "${GREEN}✓ WiFi configuration reset${NC}"
        echo ""

        # ─────────────────────────────────────────────────────────────
        # Podman Cleanup
        # ─────────────────────────────────────────────────────────────
        if command -v podman &>/dev/null; then
            echo "=== Podman Cleanup ==="

            # Stop and remove all containers
            echo "Stopping all containers..."
            podman stop -a 2>/dev/null || true
            podman rm -af 2>/dev/null || true

            # Remove all volumes
            echo "Removing all volumes..."
            podman volume rm -af 2>/dev/null || true

            # Remove all networks except default
            echo "Removing custom networks..."
            for net in $(podman network ls --format '{{.Name}}' 2>/dev/null | grep -v "^podman$" || true); do
                podman network rm "$net" 2>/dev/null || true
            done

            # Remove images
            echo "Removing container images..."
            podman rmi -af 2>/dev/null || true

            # System prune
            echo "Pruning podman system..."
            podman system prune -af 2>/dev/null || true

            # Remove podman network interface
            ip link set podman0 down 2>/dev/null || true
            ip link delete podman0 2>/dev/null || true

            # Remove veth interfaces
            for veth in $(ip link show 2>/dev/null | grep -oP 'veth[^@:]+' | sort -u || true); do
                ip link delete "$veth" 2>/dev/null || true
            done

            echo -e "${GREEN}✓ Podman cleanup complete${NC}"
        fi
        echo ""

        # ─────────────────────────────────────────────────────────────
        # Network Namespaces
        # ─────────────────────────────────────────────────────────────
        echo "=== Cleaning Network Namespaces ==="
        for netns in $(ip netns list 2>/dev/null | awk '{print $1}' || true); do
            if [[ "$netns" =~ ^(netns-|cni-|hookprobe) ]]; then
                echo "  Removing netns: $netns"
                ip netns delete "$netns" 2>/dev/null || true
            fi
        done
        echo -e "${GREEN}✓ Network namespaces cleaned${NC}"
        echo ""

        # ─────────────────────────────────────────────────────────────
        # CNI Configuration
        # ─────────────────────────────────────────────────────────────
        echo "=== Removing CNI Configuration ==="
        rm -rf /etc/cni/net.d/*.conflist 2>/dev/null || true
        rm -rf /var/lib/cni/networks/* 2>/dev/null || true
        echo -e "${GREEN}✓ CNI configuration removed${NC}"
        echo ""

        # ─────────────────────────────────────────────────────────────
        # nftables Rules
        # ─────────────────────────────────────────────────────────────
        echo "=== Cleaning nftables Rules ==="
        rm -f /etc/nftables.d/guardian*.nft 2>/dev/null || true
        rm -f /etc/nftables.d/hookprobe*.nft 2>/dev/null || true
        nft flush ruleset 2>/dev/null || true
        echo -e "${GREEN}✓ nftables rules cleaned${NC}"
        echo ""

        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  Cleanup complete!                                         ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    else
        echo "Cancelled."
    fi
}

# Full system purge with reboot (Option 99)
uninstall_full_purge_reboot() {
    safe_clear
    show_banner
    echo ""
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║            ⚠️  FULL SYSTEM PURGE + REBOOT  ⚠️                  ║${NC}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}This will COMPLETELY remove ALL HookProbe components and reboot:${NC}"
    echo ""
    echo "  • All containers, images, pods, volumes, networks (Podman)"
    echo "  • All systemd services and timers"
    echo "  • All OVS bridges, VLANs, network interfaces"
    echo "  • All Linux bridges (fortress, br-lan, etc.)"
    echo "  • All udev rules (WiFi, LTE)"
    echo "  • All configuration files and secrets"
    echo "  • All data directories and databases"
    echo "  • All log files"
    echo "  • All sysctl and iptables/nftables rules"
    echo "  • All management scripts"
    echo ""
    echo -e "${RED}${BOLD}THE SYSTEM WILL AUTOMATICALLY REBOOT AFTER PURGE${NC}"
    echo ""
    echo -e "${CYAN}This returns the system to a clean state for fresh install.${NC}"
    echo ""

    read -p "Type 'PURGE AND REBOOT' to confirm: " confirm

    if [ "$confirm" != "PURGE AND REBOOT" ]; then
        echo -e "${YELLOW}Purge cancelled${NC}"
        return 1
    fi

    echo ""
    echo -e "${CYAN}Starting full system purge...${NC}"

    # Stop all services first
    uninstall_stop_services

    # Remove containers
    uninstall_containers

    # Remove images
    uninstall_images

    # Remove volumes
    uninstall_volumes

    # Remove networks
    uninstall_networks

    # Remove OVS
    uninstall_ovs

    # Remove bridges
    uninstall_bridges

    # Remove WiFi configuration
    uninstall_wifi

    # Run tier-specific uninstallers if available
    [ -f "$SCRIPT_DIR/products/fortress/uninstall.sh" ] && bash "$SCRIPT_DIR/products/fortress/uninstall.sh" --purge --force 2>/dev/null || true
    [ -f "$SCRIPT_DIR/products/guardian/scripts/uninstall.sh" ] && bash "$SCRIPT_DIR/products/guardian/scripts/uninstall.sh" --force 2>/dev/null || true
    [ -f "$SCRIPT_DIR/products/sentinel/uninstall.sh" ] && bash "$SCRIPT_DIR/products/sentinel/uninstall.sh" --force 2>/dev/null || true

    # Final cleanup
    echo -e "${CYAN}Final cleanup...${NC}"

    # Prune all podman artifacts
    if command -v podman &>/dev/null; then
        podman system prune -af --volumes 2>/dev/null || true
    fi

    # Remove routing tables
    if [ -f /etc/iproute2/rt_tables ]; then
        sed -i '/wan_primary/d' /etc/iproute2/rt_tables 2>/dev/null || true
        sed -i '/wan_backup/d' /etc/iproute2/rt_tables 2>/dev/null || true
        sed -i '/primary_wan/d' /etc/iproute2/rt_tables 2>/dev/null || true
        sed -i '/backup_wan/d' /etc/iproute2/rt_tables 2>/dev/null || true
    fi

    # Flush nftables
    nft flush ruleset 2>/dev/null || true

    # Remove all hookprobe directories
    rm -rf /opt/hookprobe 2>/dev/null || true
    rm -rf /etc/hookprobe 2>/dev/null || true
    rm -rf /etc/fortress 2>/dev/null || true
    rm -rf /var/lib/hookprobe 2>/dev/null || true
    rm -rf /var/lib/fortress 2>/dev/null || true
    rm -rf /var/log/hookprobe 2>/dev/null || true
    rm -rf /var/backups/fortress 2>/dev/null || true
    rm -rf /var/backups/hookprobe 2>/dev/null || true

    # Remove udev rules
    rm -f /etc/udev/rules.d/*fts*.rules 2>/dev/null || true
    rm -f /etc/udev/rules.d/*hookprobe*.rules 2>/dev/null || true
    rm -f /etc/udev/rules.d/*fortress*.rules 2>/dev/null || true
    rm -f /etc/udev/rules.d/*modem*.rules 2>/dev/null || true
    udevadm control --reload-rules 2>/dev/null || true

    # Remove LTE/Modem configuration
    echo -e "${CYAN}Removing LTE/Modem configuration...${NC}"
    if command -v nmcli &>/dev/null; then
        # Remove all HookProbe/Fortress related NetworkManager connections
        for conn in $(nmcli -t -f NAME con show 2>/dev/null | grep -iE "fts|hookprobe|fortress|lte|wwan|gsm" || true); do
            echo "  Removing nmcli connection: $conn"
            nmcli con delete "$conn" 2>/dev/null || true
        done
    fi
    # Remove ModemManager config
    rm -f /etc/ModemManager/fcc-unlock.d/* 2>/dev/null || true
    rm -rf /var/lib/fortress/lte 2>/dev/null || true
    rm -f /etc/hookprobe/lte*.conf 2>/dev/null || true
    rm -f /etc/hookprobe/wan-failover.conf 2>/dev/null || true
    # Stop and reset WWAN interfaces
    for iface in $(ip link show 2>/dev/null | grep -oE "wwan[0-9]+" || true); do
        echo "  Resetting WWAN interface: $iface"
        ip link set "$iface" down 2>/dev/null || true
    done

    # Remove sysctl configs
    rm -f /etc/sysctl.d/*hookprobe*.conf 2>/dev/null || true
    rm -f /etc/sysctl.d/*fortress*.conf 2>/dev/null || true
    rm -f /etc/sysctl.d/*fts*.conf 2>/dev/null || true
    sysctl --system &>/dev/null || true

    # Reload systemd
    systemctl daemon-reload 2>/dev/null || true

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Full System Purge Complete!                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}System will reboot in 5 seconds...${NC}"
    echo ""

    sleep 5
    reboot
}

handle_uninstall() {
    while true; do
        show_uninstall_menu
        read -p "Select option: " choice

        case $choice in
            1) uninstall_sentinel ;;
            2) uninstall_guardian ;;
            3) uninstall_fortress ;;
            4) uninstall_nexus ;;
            5) uninstall_mssp ;;
            6) uninstall_stop_services ;;
            7) uninstall_cleanup_everything ;;
            8) uninstall_complete ;;
            99) uninstall_full_purge_reboot ;;
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
  sentinel    Lightweight validator (256MB+ RAM)
  guardian    Travel-secure gateway (1.5GB+ RAM, 2+ NICs)
  fortress    Full-featured edge (4GB+ RAM, 2+ ethernet)
  nexus       ML/AI compute hub (16GB+ RAM, 4+ cores)
  mssp        Central brain MSSP (16GB+ RAM, 4+ cores)

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
        mssp)
            [ "$CAN_MSSP" = true ] && install_mssp || {
                echo -e "${RED}System does not meet MSSP requirements${NC}"
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
