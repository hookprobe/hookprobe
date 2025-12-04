#!/bin/bash
#
# install.sh - HookProbe Installation Menu
# Version: 6.0
# License: MIT
#
# Capability-based installation menu - shows only what your system supports
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# ============================================================
# SYSTEM CAPABILITY DETECTION
# ============================================================

# Global capability variables (set by detect_capabilities)
declare -g SYS_RAM_MB=0
declare -g SYS_RAM_GB=0
declare -g SYS_STORAGE_GB=0
declare -g SYS_CPU_CORES=0
declare -g SYS_CPU_MODEL=""
declare -g SYS_ARCH=""
declare -g SYS_KERNEL_VERSION=""
declare -g SYS_KERNEL_MAJOR=0
declare -g SYS_OS_NAME=""
declare -g SYS_OS_VERSION=""
declare -g SYS_OS_PRETTY=""

# Network capabilities
declare -g SYS_ETH_COUNT=0
declare -g SYS_WIFI_COUNT=0
declare -g SYS_WIFI_HOTSPOT=false
declare -g SYS_WIFI_5GHZ=false
declare -g SYS_WIFI_2GHZ=false
declare -g SYS_LTE_COUNT=0
declare -g SYS_NET_INTERFACES=""

# Virtualization capabilities
declare -g SYS_IS_VM=false
declare -g SYS_VM_TYPE=""
declare -g SYS_NESTED_VIRT=false
declare -g SYS_IS_PROXMOX=false
declare -g SYS_IS_LXC=false
declare -g SYS_CGROUPS_V2=false

# Security capabilities
declare -g SYS_APPARMOR=false
declare -g SYS_SELINUX=false
declare -g SYS_BPF_SUPPORT=false

# GPU capabilities
declare -g SYS_HAS_GPU=false
declare -g SYS_GPU_TYPE=""

# Deployment tier eligibility
declare -g CAN_VALIDATOR=false
declare -g CAN_ROUTER_EDGE=false
declare -g CAN_ADVANCED_EDGE=false
declare -g CAN_MSSP_SERVER=false

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        SYS_OS_NAME=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
        SYS_OS_VERSION="$VERSION_ID"
        SYS_OS_PRETTY="$PRETTY_NAME"
    elif [ -f /etc/redhat-release ]; then
        SYS_OS_NAME="rhel"
        SYS_OS_VERSION=$(cat /etc/redhat-release | sed 's/.*release \([0-9.]*\).*/\1/')
        SYS_OS_PRETTY=$(cat /etc/redhat-release)
    else
        SYS_OS_NAME="unknown"
        SYS_OS_VERSION="unknown"
        SYS_OS_PRETTY="Unknown Linux"
    fi
}

detect_architecture() {
    SYS_ARCH=$(uname -m)
}

detect_kernel() {
    SYS_KERNEL_VERSION=$(uname -r)
    SYS_KERNEL_MAJOR=$(echo "$SYS_KERNEL_VERSION" | cut -d. -f1)
}

detect_cpu() {
    SYS_CPU_CORES=$(nproc 2>/dev/null || echo 1)
    if [ -f /proc/cpuinfo ]; then
        SYS_CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "Unknown")
        if [ -z "$SYS_CPU_MODEL" ] || [ "$SYS_CPU_MODEL" = "Unknown" ]; then
            # ARM processors may use different field
            SYS_CPU_MODEL=$(grep -m1 "Model" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "Unknown")
        fi
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
}

detect_network_interfaces() {
    SYS_ETH_COUNT=0
    SYS_WIFI_COUNT=0
    SYS_LTE_COUNT=0
    SYS_NET_INTERFACES=""

    # Detect ethernet interfaces
    for iface in /sys/class/net/*; do
        local name=$(basename "$iface")
        [ "$name" = "lo" ] && continue

        if [ -d "$iface" ]; then
            local type_file="$iface/type"
            local wireless_dir="$iface/wireless"
            local device_type=""

            if [ -d "$wireless_dir" ]; then
                # WiFi interface
                SYS_WIFI_COUNT=$((SYS_WIFI_COUNT + 1))
                device_type="wifi"

                # Check WiFi capabilities using iw
                if command -v iw &>/dev/null; then
                    local phy=$(iw dev "$name" info 2>/dev/null | grep wiphy | awk '{print $2}')
                    if [ -n "$phy" ]; then
                        local bands=$(iw phy "phy$phy" info 2>/dev/null | grep -E "Band [0-9]:" || true)
                        if echo "$bands" | grep -q "Band 1:"; then
                            SYS_WIFI_2GHZ=true
                        fi
                        if echo "$bands" | grep -q "Band 2:"; then
                            SYS_WIFI_5GHZ=true
                        fi

                        # Check AP mode support (hotspot)
                        if iw phy "phy$phy" info 2>/dev/null | grep -q "* AP"; then
                            SYS_WIFI_HOTSPOT=true
                        fi
                    fi
                fi
            elif [ -f "$type_file" ] && [ "$(cat "$type_file" 2>/dev/null)" = "1" ]; then
                # Check if it's an LTE/mobile interface
                if echo "$name" | grep -qiE "^(wwan|lte|usb|ppp)"; then
                    SYS_LTE_COUNT=$((SYS_LTE_COUNT + 1))
                    device_type="lte"
                else
                    # Regular ethernet
                    SYS_ETH_COUNT=$((SYS_ETH_COUNT + 1))
                    device_type="eth"
                fi
            fi

            if [ -n "$device_type" ]; then
                local state="down"
                [ -f "$iface/operstate" ] && state=$(cat "$iface/operstate" 2>/dev/null || echo "unknown")
                SYS_NET_INTERFACES="${SYS_NET_INTERFACES}${name}:${device_type}:${state}\n"
            fi
        fi
    done
}

detect_virtualization() {
    SYS_IS_VM=false
    SYS_VM_TYPE=""
    SYS_NESTED_VIRT=false
    SYS_IS_PROXMOX=false
    SYS_IS_LXC=false

    # Detect if running in a VM
    if [ -f /sys/class/dmi/id/product_name ]; then
        local product=$(cat /sys/class/dmi/id/product_name 2>/dev/null | tr '[:upper:]' '[:lower:]')
        case "$product" in
            *vmware*) SYS_IS_VM=true; SYS_VM_TYPE="vmware" ;;
            *virtualbox*) SYS_IS_VM=true; SYS_VM_TYPE="virtualbox" ;;
            *kvm*|*qemu*) SYS_IS_VM=true; SYS_VM_TYPE="kvm" ;;
            *hyper-v*|*virtual*machine*) SYS_IS_VM=true; SYS_VM_TYPE="hyperv" ;;
        esac
    fi

    # Check for systemd-detect-virt
    if command -v systemd-detect-virt &>/dev/null; then
        local virt=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [ "$virt" != "none" ]; then
            SYS_IS_VM=true
            [ -z "$SYS_VM_TYPE" ] && SYS_VM_TYPE="$virt"
        fi
        if [ "$virt" = "lxc" ]; then
            SYS_IS_LXC=true
        fi
    fi

    # Check for LXC container
    if grep -qa "container=lxc" /proc/1/environ 2>/dev/null || [ -f /dev/lxd/sock ]; then
        SYS_IS_LXC=true
        SYS_IS_VM=true
        SYS_VM_TYPE="lxc"
    fi

    # Check for Proxmox
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
    SYS_CGROUPS_V2=false
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        SYS_CGROUPS_V2=true
    fi
}

detect_security() {
    SYS_APPARMOR=false
    SYS_SELINUX=false
    SYS_BPF_SUPPORT=false

    # AppArmor
    if [ -d /sys/kernel/security/apparmor ] || command -v apparmor_status &>/dev/null; then
        SYS_APPARMOR=true
    fi

    # SELinux
    if command -v getenforce &>/dev/null && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
        SYS_SELINUX=true
    fi

    # BPF/eBPF support
    if [ -d /sys/fs/bpf ] || [ "$SYS_KERNEL_MAJOR" -ge 5 ]; then
        SYS_BPF_SUPPORT=true
    fi
}

detect_gpu() {
    SYS_HAS_GPU=false
    SYS_GPU_TYPE=""

    # Check for NVIDIA GPU
    if command -v nvidia-smi &>/dev/null || [ -d /proc/driver/nvidia ]; then
        SYS_HAS_GPU=true
        SYS_GPU_TYPE="nvidia"
    # Check for AMD GPU
    elif lspci 2>/dev/null | grep -qi "vga.*amd\|display.*amd"; then
        SYS_HAS_GPU=true
        SYS_GPU_TYPE="amd"
    # Check for Intel GPU
    elif lspci 2>/dev/null | grep -qi "vga.*intel"; then
        SYS_HAS_GPU=true
        SYS_GPU_TYPE="intel"
    fi
}

# Run all detection functions
detect_capabilities() {
    detect_os
    detect_architecture
    detect_kernel
    detect_cpu
    detect_ram
    detect_storage
    detect_network_interfaces
    detect_virtualization
    detect_cgroups
    detect_security
    detect_gpu
    evaluate_deployment_tiers
}

# ============================================================
# DEPLOYMENT TIER EVALUATION
# ============================================================

evaluate_deployment_tiers() {
    # Reset all tiers
    CAN_VALIDATOR=false
    CAN_ROUTER_EDGE=false
    CAN_ADVANCED_EDGE=false
    CAN_MSSP_SERVER=false

    local total_net=$((SYS_ETH_COUNT + SYS_WIFI_COUNT))

    # VALIDATOR ONLY
    # Requirements: 512MB-3GB RAM, 8-64GB storage, 1 ethernet (WAN only), no LAN, no WiFi requirement
    # Purpose: Validates edge nodes, needs internet connectivity
    if [ "$SYS_RAM_MB" -ge 512 ] && [ "$SYS_STORAGE_GB" -ge 8 ]; then
        if [ "$SYS_ETH_COUNT" -ge 1 ] || [ "$total_net" -ge 1 ]; then
            CAN_VALIDATOR=true
        fi
    fi

    # ROUTER EDGE
    # Requirements: 3GB+ RAM, 16-64GB+ storage, 2+ network interfaces (2 eth OR 1 eth + 1 wifi)
    # Platforms: Raspberry Pi style devices - secure gateway with qsecbit, openflow, WAF, IDS/IPS, lite AI
    # Requires: MSSP ID for management
    if [ "$SYS_RAM_MB" -ge 3072 ] && [ "$SYS_STORAGE_GB" -ge 16 ]; then
        # Need at least 2 network interfaces for WAN + LAN
        if [ "$SYS_ETH_COUNT" -ge 2 ] || ([ "$SYS_ETH_COUNT" -ge 1 ] && [ "$SYS_WIFI_COUNT" -ge 1 ]); then
            CAN_ROUTER_EDGE=true
        fi
    fi

    # ADVANCED ROUTER EDGE
    # Requirements: 8GB+ RAM, 2+ ethernet ports, optional LTE/5G
    # Platforms: N100/NUC style systems - includes monitoring, victoria metrics, n8n, web dashboard
    if [ "$SYS_RAM_MB" -ge 8192 ] && [ "$SYS_STORAGE_GB" -ge 32 ]; then
        if [ "$SYS_ETH_COUNT" -ge 2 ]; then
            CAN_ADVANCED_EDGE=true
        fi
    fi

    # MSSP SERVER
    # Requirements: 8+ cores, dedicated GPU (optional but recommended), 64GB+ RAM, 1TB+ storage
    # Purpose: Heavy lifting multi-tenant backend
    if [ "$SYS_CPU_CORES" -ge 8 ] && [ "$SYS_RAM_MB" -ge 65536 ] && [ "$SYS_STORAGE_GB" -ge 1000 ]; then
        CAN_MSSP_SERVER=true
    fi
}

# ============================================================
# BANNER AND UI HELPERS
# ============================================================

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ╦ ╦╔═╗╔═╗╦╔═╔═╗╦═╗╔═╗╔╗ ╔═╗
    ╠═╣║ ║║ ║╠╩╗╠═╝╠╦╝║ ║╠╩╗║╣
    ╩ ╩╚═╝╚═╝╩ ╩╩  ╩╚═╚═╝╚═╝╚═╝

    Cyber Resilience at the Edge
    Version 6.0 - Capability-Based Install
EOF
    echo -e "${NC}"
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

print_ok() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
}

print_fail() {
    echo -e "  ${RED}✗${NC} $1"
}

print_info() {
    echo -e "  ${BLUE}•${NC} $1"
}

format_bytes() {
    local bytes=$1
    if [ "$bytes" -ge 1024 ]; then
        echo "${bytes}GB"
    else
        echo "${bytes}MB"
    fi
}

# ============================================================
# MAIN MENU
# ============================================================

show_main_menu() {
    print_header "HOOKPROBE INSTALLER"

    echo -e "${YELLOW}┌─ Main Menu ────────────────────────────────────────────────┐${NC}"
    echo -e "│                                                            │"
    echo -e "│  ${BOLD}1${NC}) Check System Capabilities                              │"
    echo -e "│  ${BOLD}2${NC}) Install HookProbe                                      │"
    echo -e "│  ${BOLD}3${NC}) Uninstall / Cleanup                                    │"
    echo -e "│                                                            │"
    echo -e "│  ${BOLD}q${NC}) Quit                                                   │"
    echo -e "│                                                            │"
    echo -e "${YELLOW}└────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ============================================================
# CAPABILITY CHECK MENU
# ============================================================

show_capability_summary() {
    clear
    show_banner
    print_header "SYSTEM CAPABILITY CHECK" "$CYAN"

    # System Overview
    print_section "System Overview"
    print_info "OS: $SYS_OS_PRETTY"
    print_info "Architecture: $SYS_ARCH"
    print_info "Kernel: $SYS_KERNEL_VERSION"
    echo ""

    # Hardware
    print_section "Hardware"
    print_info "CPU: $SYS_CPU_MODEL"
    print_info "Cores: $SYS_CPU_CORES"

    if [ "$SYS_RAM_GB" -ge 64 ]; then
        print_ok "RAM: ${SYS_RAM_GB}GB (excellent for MSSP)"
    elif [ "$SYS_RAM_GB" -ge 8 ]; then
        print_ok "RAM: ${SYS_RAM_GB}GB (good for advanced edge)"
    elif [ "$SYS_RAM_GB" -ge 3 ]; then
        print_ok "RAM: ${SYS_RAM_GB}GB (sufficient for router edge)"
    elif [ "$SYS_RAM_MB" -ge 512 ]; then
        print_warn "RAM: ${SYS_RAM_MB}MB (validator only)"
    else
        print_fail "RAM: ${SYS_RAM_MB}MB (insufficient)"
    fi

    if [ "$SYS_STORAGE_GB" -ge 1000 ]; then
        print_ok "Storage: ${SYS_STORAGE_GB}GB available (excellent)"
    elif [ "$SYS_STORAGE_GB" -ge 32 ]; then
        print_ok "Storage: ${SYS_STORAGE_GB}GB available (good)"
    elif [ "$SYS_STORAGE_GB" -ge 8 ]; then
        print_warn "Storage: ${SYS_STORAGE_GB}GB available (minimal)"
    else
        print_fail "Storage: ${SYS_STORAGE_GB}GB available (insufficient)"
    fi
    echo ""

    # GPU
    print_section "GPU"
    if [ "$SYS_HAS_GPU" = true ]; then
        print_ok "GPU detected: $SYS_GPU_TYPE"
    else
        print_info "No dedicated GPU detected"
    fi
    echo ""

    # Network Interfaces
    print_section "Network Interfaces"
    print_info "Ethernet: $SYS_ETH_COUNT interface(s)"
    print_info "WiFi: $SYS_WIFI_COUNT interface(s)"
    if [ "$SYS_LTE_COUNT" -gt 0 ]; then
        print_info "LTE/Mobile: $SYS_LTE_COUNT interface(s)"
    fi

    if [ "$SYS_WIFI_COUNT" -gt 0 ]; then
        echo ""
        print_section "WiFi Capabilities"
        if [ "$SYS_WIFI_2GHZ" = true ]; then
            print_ok "2.4GHz band supported"
        fi
        if [ "$SYS_WIFI_5GHZ" = true ]; then
            print_ok "5GHz band supported"
        fi
        if [ "$SYS_WIFI_HOTSPOT" = true ]; then
            print_ok "Hotspot/AP mode supported"
        else
            print_warn "Hotspot/AP mode not available"
        fi
    fi
    echo ""

    # Virtualization
    print_section "Virtualization Environment"
    if [ "$SYS_IS_VM" = true ]; then
        print_info "Running in: $SYS_VM_TYPE"
        if [ "$SYS_IS_LXC" = true ]; then
            print_info "Container type: LXC"
        fi
    else
        print_info "Running on bare metal"
    fi
    if [ "$SYS_IS_PROXMOX" = true ]; then
        print_info "Proxmox VE detected"
    fi
    if [ "$SYS_NESTED_VIRT" = true ]; then
        print_ok "Nested virtualization enabled"
    fi
    if [ "$SYS_CGROUPS_V2" = true ]; then
        print_ok "cgroups v2 enabled"
    else
        print_info "cgroups v1 (legacy)"
    fi
    echo ""

    # Security
    print_section "Security Features"
    if [ "$SYS_APPARMOR" = true ]; then
        print_ok "AppArmor available"
    fi
    if [ "$SYS_SELINUX" = true ]; then
        print_ok "SELinux enabled"
    fi
    if [ "$SYS_BPF_SUPPORT" = true ]; then
        print_ok "BPF/eBPF supported"
    else
        print_warn "BPF/eBPF not available (kernel 5.x+ recommended)"
    fi
    echo ""

    # Eligible Deployment Tiers
    print_section "Eligible Deployment Modes"
    echo ""

    if [ "$CAN_MSSP_SERVER" = true ]; then
        echo -e "  ${GREEN}█${NC} ${BOLD}MSSP Server${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "    ${DIM}Multi-tenant backend with full analytics${NC}"
    else
        echo -e "  ${DIM}░ MSSP Server [NOT AVAILABLE]${NC}"
        echo -e "    ${DIM}Requires: 8+ cores, 64GB+ RAM, 1TB+ storage${NC}"
    fi

    if [ "$CAN_ADVANCED_EDGE" = true ]; then
        echo -e "  ${GREEN}█${NC} ${BOLD}Advanced Router Edge${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "    ${DIM}Full monitoring, dashboards, automation${NC}"
    else
        echo -e "  ${DIM}░ Advanced Router Edge [NOT AVAILABLE]${NC}"
        echo -e "    ${DIM}Requires: 8GB+ RAM, 2+ ethernet ports${NC}"
    fi

    if [ "$CAN_ROUTER_EDGE" = true ]; then
        echo -e "  ${GREEN}█${NC} ${BOLD}Router Edge${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "    ${DIM}Secure gateway with IDS/IPS, WAF, lite AI${NC}"
    else
        echo -e "  ${DIM}░ Router Edge [NOT AVAILABLE]${NC}"
        echo -e "    ${DIM}Requires: 3GB+ RAM, 2+ network interfaces${NC}"
    fi

    if [ "$CAN_VALIDATOR" = true ]; then
        echo -e "  ${GREEN}█${NC} ${BOLD}Validator Only${NC} ${GREEN}[AVAILABLE]${NC}"
        echo -e "    ${DIM}Lightweight edge node validator${NC}"
    else
        echo -e "  ${DIM}░ Validator Only [NOT AVAILABLE]${NC}"
        echo -e "    ${DIM}Requires: 512MB+ RAM, 8GB+ storage, network${NC}"
    fi

    echo ""
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}b${NC}) Back to Main Menu    ${BOLD}q${NC}) Quit"
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo ""
}

handle_capability_check() {
    while true; do
        show_capability_summary
        read -p "Select option: " choice

        case $choice in
            b|B) return ;;
            q|Q) exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# INSTALL MENU
# ============================================================

show_install_menu() {
    clear
    show_banner
    print_header "INSTALL HOOKPROBE" "$GREEN"

    echo -e "${CYAN}Available deployment modes for your system:${NC}"
    echo ""

    local option_num=1
    local options=()

    # Show only available options based on system capabilities
    if [ "$CAN_VALIDATOR" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${BOLD}Validator Only${NC}"
        echo -e "     ${DIM}Lightweight validator for constrained devices${NC}"
        echo -e "     ${DIM}RAM: 512MB-3GB | Storage: 8GB+ | Network: 1+ interface${NC}"
        echo -e "     ${DIM}Features: Edge node validation, health monitoring${NC}"
        echo ""
        options+=("validator")
        option_num=$((option_num + 1))
    fi

    if [ "$CAN_ROUTER_EDGE" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${BOLD}Router Edge${NC}"
        echo -e "     ${DIM}Secure gateway for home/SMB/branch office${NC}"
        echo -e "     ${DIM}RAM: 3GB+ | Storage: 16GB+ | Network: 2+ interfaces${NC}"
        echo -e "     ${DIM}Features: QSecBit, OpenFlow, WAF, IDS/IPS, Lite AI${NC}"
        echo -e "     ${YELLOW}Requires: MSSP ID for management${NC}"
        echo ""
        options+=("router-edge")
        option_num=$((option_num + 1))
    fi

    if [ "$CAN_ADVANCED_EDGE" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${BOLD}Advanced Router Edge${NC}"
        echo -e "     ${DIM}Full-featured edge with monitoring & automation${NC}"
        echo -e "     ${DIM}RAM: 8GB+ | Storage: 32GB+ | Network: 2+ ethernet${NC}"
        echo -e "     ${DIM}Features: All Router Edge + Victoria Metrics, n8n, Dashboard${NC}"
        if [ "$SYS_LTE_COUNT" -gt 0 ]; then
            echo -e "     ${GREEN}LTE/5G failover available${NC}"
        fi
        echo ""
        options+=("advanced-edge")
        option_num=$((option_num + 1))
    fi

    if [ "$CAN_MSSP_SERVER" = true ]; then
        echo -e "  ${BOLD}${option_num}${NC}) ${BOLD}MSSP Server${NC}"
        echo -e "     ${DIM}Multi-tenant backend for service providers${NC}"
        echo -e "     ${DIM}Cores: 8+ | RAM: 64GB+ | Storage: 1TB+${NC}"
        echo -e "     ${DIM}Features: Multi-tenant SOC, analytics, long-term retention${NC}"
        if [ "$SYS_HAS_GPU" = true ]; then
            echo -e "     ${GREEN}GPU acceleration available ($SYS_GPU_TYPE)${NC}"
        fi
        echo ""
        options+=("mssp-server")
        option_num=$((option_num + 1))
    fi

    # If no options available
    if [ ${#options[@]} -eq 0 ]; then
        echo -e "  ${RED}No deployment modes available for this system.${NC}"
        echo ""
        echo -e "  ${YELLOW}Minimum requirements:${NC}"
        echo -e "    • RAM: 512MB+"
        echo -e "    • Storage: 8GB+"
        echo -e "    • Network: 1+ interface"
        echo ""
        echo -e "  ${CYAN}Consider using Sentinel Lite for ultra-constrained devices:${NC}"
        echo -e "    curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel-lite/bootstrap.sh | sudo bash"
        echo ""
    fi

    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}b${NC}) Back to Main Menu    ${BOLD}m${NC}) Main Menu    ${BOLD}q${NC}) Quit"
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo ""

    # Return the options array for use by handler
    printf '%s\n' "${options[@]}"
}

install_validator() {
    clear
    show_banner
    print_header "INSTALL: VALIDATOR ONLY" "$GREEN"

    echo -e "${CYAN}Validator Only Deployment${NC}"
    echo ""
    echo "This deployment mode installs a lightweight validator service"
    echo "suitable for constrained devices like Raspberry Pi 3, IoT gateways,"
    echo "and systems with limited resources."
    echo ""
    echo -e "${YELLOW}What will be installed:${NC}"
    echo "  • HookProbe Sentinel Lite service"
    echo "  • Health monitoring endpoint"
    echo "  • Edge node validation"
    echo "  • Minimal resource footprint (~50MB)"
    echo ""
    echo -e "${YELLOW}Network Requirements:${NC}"
    echo "  • Internet connectivity to reach MSSP backend"
    echo "  • Outbound HTTPS (port 443)"
    echo ""

    read -p "Proceed with installation? (yes/no) [no]: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""
        if [ -f "$SCRIPT_DIR/install-sentinel-lite.sh" ]; then
            bash "$SCRIPT_DIR/install-sentinel-lite.sh"
        elif [ -f "$SCRIPT_DIR/releases/sentinel-lite/bootstrap.sh" ]; then
            bash "$SCRIPT_DIR/releases/sentinel-lite/bootstrap.sh"
        else
            echo -e "${RED}Installer not found. Downloading...${NC}"
            curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel-lite/bootstrap.sh | bash
        fi
    else
        echo "Installation cancelled."
    fi
}

install_router_edge() {
    clear
    show_banner
    print_header "INSTALL: ROUTER EDGE" "$GREEN"

    echo -e "${CYAN}Router Edge Deployment${NC}"
    echo ""
    echo "This deployment mode installs a secure gateway suitable for"
    echo "home networks, small businesses, and branch offices."
    echo ""
    echo -e "${YELLOW}What will be installed:${NC}"
    echo "  • QSecBit quantum-resistant security"
    echo "  • OpenFlow software-defined networking"
    echo "  • Web Application Firewall (WAF)"
    echo "  • IDS/IPS (Suricata/Zeek)"
    echo "  • Lite AI threat detection"
    echo "  • Container runtime (Podman)"
    echo ""
    echo -e "${YELLOW}Network Configuration:${NC}"
    echo "  • WAN interface: Internet uplink"
    echo "  • LAN interface: Protected network"
    if [ "$SYS_WIFI_COUNT" -gt 0 ] && [ "$SYS_WIFI_HOTSPOT" = true ]; then
        echo "  • WiFi hotspot: Available for LAN"
    fi
    echo ""
    echo -e "${RED}MSSP Registration Required${NC}"
    echo "You will need to provide your MSSP ID to connect this edge"
    echo "device to your management backend."
    echo ""

    read -p "Enter your MSSP ID (or 'skip' to configure later): " mssp_id

    if [ "$mssp_id" != "skip" ] && [ -n "$mssp_id" ]; then
        # Save MSSP ID
        mkdir -p /etc/hookprobe/secrets
        echo "$mssp_id" > /etc/hookprobe/secrets/mssp-id
        chmod 600 /etc/hookprobe/secrets/mssp-id
        echo -e "${GREEN}✓ MSSP ID saved${NC}"
    fi

    echo ""
    read -p "Proceed with installation? (yes/no) [no]: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""
        export HOOKPROBE_DEPLOYMENT_MODE="router-edge"
        if [ -f "$SCRIPT_DIR/scripts/install-edge.sh" ]; then
            bash "$SCRIPT_DIR/scripts/install-edge.sh" --mode router-edge
        else
            echo -e "${RED}Edge installer not found${NC}"
        fi
    else
        echo "Installation cancelled."
    fi
}

install_advanced_edge() {
    clear
    show_banner
    print_header "INSTALL: ADVANCED ROUTER EDGE" "$GREEN"

    echo -e "${CYAN}Advanced Router Edge Deployment${NC}"
    echo ""
    echo "This deployment mode installs a full-featured edge gateway"
    echo "with monitoring, metrics, and automation capabilities."
    echo ""
    echo -e "${YELLOW}What will be installed:${NC}"
    echo "  • All Router Edge features, plus:"
    echo "  • Victoria Metrics (time-series database)"
    echo "  • Grafana dashboards"
    echo "  • n8n workflow automation"
    echo "  • Web management interface"
    echo "  • Full AI threat detection"
    if [ "$SYS_LTE_COUNT" -gt 0 ]; then
        echo "  • LTE/5G failover support"
    fi
    echo ""
    echo -e "${YELLOW}Resource Usage:${NC}"
    echo "  • RAM: ~4-6GB under normal operation"
    echo "  • Storage: ~20GB for containers and data"
    echo "  • CPU: Moderate utilization"
    echo ""

    # Optional features
    echo -e "${YELLOW}Optional Features:${NC}"
    read -p "Enable n8n automation? (yes/no) [yes]: " enable_n8n
    enable_n8n=${enable_n8n:-yes}

    read -p "Enable Grafana dashboards? (yes/no) [yes]: " enable_grafana
    enable_grafana=${enable_grafana:-yes}

    if [ "$SYS_LTE_COUNT" -gt 0 ]; then
        read -p "Enable LTE failover? (yes/no) [yes]: " enable_lte
        enable_lte=${enable_lte:-yes}
    fi

    echo ""
    read -p "Proceed with installation? (yes/no) [no]: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""
        export HOOKPROBE_DEPLOYMENT_MODE="advanced-edge"
        local extra_args=""
        [ "$enable_n8n" = "yes" ] && extra_args="$extra_args --enable-n8n"
        [ "$enable_grafana" = "yes" ] && extra_args="$extra_args --enable-monitoring"
        [ "$enable_lte" = "yes" ] && extra_args="$extra_args --enable-lte"

        if [ -f "$SCRIPT_DIR/scripts/install-edge.sh" ]; then
            bash "$SCRIPT_DIR/scripts/install-edge.sh" --mode advanced-edge $extra_args
        else
            echo -e "${RED}Edge installer not found${NC}"
        fi
    else
        echo "Installation cancelled."
    fi
}

install_mssp_server() {
    clear
    show_banner
    print_header "INSTALL: MSSP SERVER" "$GREEN"

    echo -e "${CYAN}MSSP Server Deployment${NC}"
    echo ""
    echo "This deployment mode installs a multi-tenant backend suitable"
    echo "for Managed Security Service Providers (MSSPs) and enterprise SOCs."
    echo ""
    echo -e "${YELLOW}What will be installed:${NC}"
    echo "  • Multi-tenant management platform"
    echo "  • ClickHouse analytics database"
    echo "  • Long-term data retention"
    echo "  • Centralized logging and SIEM"
    echo "  • Edge node orchestration"
    echo "  • Tenant isolation and RBAC"
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
    echo "This is intended for production environments. Ensure you have:"
    echo "  • Proper backup strategy"
    echo "  • TLS certificates"
    echo "  • DNS configuration"
    echo ""

    read -p "Proceed with installation? (yes/no) [no]: " confirm
    if [ "$confirm" = "yes" ]; then
        echo ""
        if [ -f "$SCRIPT_DIR/install/cloud/setup.sh" ]; then
            bash "$SCRIPT_DIR/install/cloud/setup.sh"
        else
            echo -e "${RED}Cloud installer not found${NC}"
        fi
    else
        echo "Installation cancelled."
    fi
}

handle_install() {
    while true; do
        # Get available options
        local options_output
        options_output=$(show_install_menu)

        # Parse options into array
        local options=()
        while IFS= read -r line; do
            [ -n "$line" ] && options+=("$line")
        done <<< "$options_output"

        read -p "Select option: " choice

        case $choice in
            b|B|m|M) return ;;
            q|Q) exit 0 ;;
            [0-9]*)
                local idx=$((choice - 1))
                if [ $idx -ge 0 ] && [ $idx -lt ${#options[@]} ]; then
                    case "${options[$idx]}" in
                        validator) install_validator ;;
                        router-edge) install_router_edge ;;
                        advanced-edge) install_advanced_edge ;;
                        mssp-server) install_mssp_server ;;
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
    clear
    show_banner
    print_header "UNINSTALL / CLEANUP" "$RED"

    echo -e "${YELLOW}Select what to remove:${NC}"
    echo ""
    echo -e "  ${BOLD}1${NC}) Stop All Services"
    echo -e "     ${DIM}Stop all HookProbe containers and services${NC}"
    echo ""
    echo -e "  ${BOLD}2${NC}) Remove Containers"
    echo -e "     ${DIM}Remove all HookProbe containers (preserves data)${NC}"
    echo ""
    echo -e "  ${BOLD}3${NC}) Remove Container Images"
    echo -e "     ${DIM}Remove downloaded container images${NC}"
    echo ""
    echo -e "  ${BOLD}4${NC}) Remove Volumes & Data"
    echo -e "     ${DIM}Remove persistent volumes (databases, logs)${NC}"
    echo -e "     ${RED}WARNING: This will delete all data!${NC}"
    echo ""
    echo -e "  ${BOLD}5${NC}) Remove Pod Networks"
    echo -e "     ${DIM}Remove Podman networks created by HookProbe${NC}"
    echo ""
    echo -e "  ${BOLD}6${NC}) Remove OVS Bridges"
    echo -e "     ${DIM}Remove Open vSwitch bridges and configurations${NC}"
    echo ""
    echo -e "  ${BOLD}7${NC}) Remove Network Bridges"
    echo -e "     ${DIM}Remove Linux bridges created by HookProbe${NC}"
    echo ""
    echo -e "  ${BOLD}8${NC}) Reset WiFi Configuration"
    echo -e "     ${DIM}Remove hotspot configuration, restore defaults${NC}"
    echo ""
    echo -e "  ${BOLD}9${NC}) Complete Uninstall"
    echo -e "     ${DIM}Remove everything - containers, data, configs${NC}"
    echo -e "     ${RED}WARNING: This is destructive and irreversible!${NC}"
    echo ""
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}b${NC}) Back to Main Menu    ${BOLD}m${NC}) Main Menu    ${BOLD}q${NC}) Quit"
    echo -e "${YELLOW}────────────────────────────────────────────────────────────${NC}"
    echo ""
}

uninstall_stop_services() {
    echo -e "${CYAN}Stopping all HookProbe services...${NC}"
    echo ""

    # Stop systemd services
    for service in hookprobe-edge hookprobe-sentinel-lite hookprobe-neuro hookprobe-validator; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "Stopping $service..."
            systemctl stop "$service" 2>/dev/null || true
        fi
    done

    # Stop Podman containers
    if command -v podman &>/dev/null; then
        local containers=$(podman ps -q --filter "name=hookprobe" 2>/dev/null)
        if [ -n "$containers" ]; then
            echo "Stopping containers..."
            podman stop $containers 2>/dev/null || true
        fi

        # Stop any pods
        local pods=$(podman pod ps -q --filter "name=hookprobe" 2>/dev/null)
        if [ -n "$pods" ]; then
            echo "Stopping pods..."
            podman pod stop $pods 2>/dev/null || true
        fi
    fi

    echo -e "${GREEN}✓ Services stopped${NC}"
}

uninstall_containers() {
    echo -e "${CYAN}Removing HookProbe containers...${NC}"
    echo ""

    if command -v podman &>/dev/null; then
        # Remove containers
        local containers=$(podman ps -aq --filter "name=hookprobe" 2>/dev/null)
        if [ -n "$containers" ]; then
            echo "Removing containers..."
            podman rm -f $containers 2>/dev/null || true
        fi

        # Remove pods
        local pods=$(podman pod ps -q --filter "name=hookprobe" 2>/dev/null)
        if [ -n "$pods" ]; then
            echo "Removing pods..."
            podman pod rm -f $pods 2>/dev/null || true
        fi

        echo -e "${GREEN}✓ Containers removed${NC}"
    else
        echo -e "${YELLOW}Podman not installed${NC}"
    fi
}

uninstall_images() {
    echo -e "${CYAN}Removing container images...${NC}"
    echo ""

    if command -v podman &>/dev/null; then
        local images=$(podman images -q --filter "reference=*hookprobe*" 2>/dev/null)
        if [ -n "$images" ]; then
            podman rmi -f $images 2>/dev/null || true
        fi

        # Also remove common images used by HookProbe
        for img in postgres redis valkey grafana victoria-metrics n8n suricata zeek; do
            podman rmi -f "$img" 2>/dev/null || true
        done

        echo -e "${GREEN}✓ Images removed${NC}"
    else
        echo -e "${YELLOW}Podman not installed${NC}"
    fi
}

uninstall_volumes() {
    echo -e "${RED}WARNING: This will delete all persistent data!${NC}"
    read -p "Type 'DELETE' to confirm: " confirm

    if [ "$confirm" = "DELETE" ]; then
        echo ""
        echo -e "${CYAN}Removing volumes...${NC}"

        if command -v podman &>/dev/null; then
            local volumes=$(podman volume ls -q --filter "name=hookprobe" 2>/dev/null)
            if [ -n "$volumes" ]; then
                podman volume rm -f $volumes 2>/dev/null || true
            fi
        fi

        # Remove data directories
        rm -rf /var/lib/hookprobe 2>/dev/null || true
        rm -rf /var/log/hookprobe 2>/dev/null || true

        echo -e "${GREEN}✓ Volumes and data removed${NC}"
    else
        echo "Cancelled."
    fi
}

uninstall_networks() {
    echo -e "${CYAN}Removing pod networks...${NC}"
    echo ""

    if command -v podman &>/dev/null; then
        local networks=$(podman network ls -q --filter "name=hookprobe" 2>/dev/null)
        if [ -n "$networks" ]; then
            podman network rm -f $networks 2>/dev/null || true
        fi
        echo -e "${GREEN}✓ Pod networks removed${NC}"
    else
        echo -e "${YELLOW}Podman not installed${NC}"
    fi
}

uninstall_ovs() {
    echo -e "${CYAN}Removing OVS bridges...${NC}"
    echo ""

    if command -v ovs-vsctl &>/dev/null; then
        for br in $(ovs-vsctl list-br 2>/dev/null | grep -E "^(hookprobe|hp-)" || true); do
            echo "Removing bridge: $br"
            ovs-vsctl del-br "$br" 2>/dev/null || true
        done
        echo -e "${GREEN}✓ OVS bridges removed${NC}"
    else
        echo -e "${YELLOW}OVS not installed${NC}"
    fi
}

uninstall_bridges() {
    echo -e "${CYAN}Removing Linux bridges...${NC}"
    echo ""

    for br in $(ip -brief link show type bridge 2>/dev/null | awk '{print $1}' | grep -E "^(hookprobe|hp-|br-hp)" || true); do
        echo "Removing bridge: $br"
        ip link set "$br" down 2>/dev/null || true
        ip link delete "$br" 2>/dev/null || true
    done

    echo -e "${GREEN}✓ Bridges removed${NC}"
}

uninstall_wifi() {
    echo -e "${CYAN}Resetting WiFi configuration...${NC}"
    echo ""

    # Stop hostapd if running
    systemctl stop hostapd 2>/dev/null || true
    systemctl disable hostapd 2>/dev/null || true

    # Remove hostapd config
    rm -f /etc/hostapd/hookprobe.conf 2>/dev/null || true

    # Remove dnsmasq config
    rm -f /etc/dnsmasq.d/hookprobe.conf 2>/dev/null || true

    # Restart network manager
    systemctl restart NetworkManager 2>/dev/null || true

    echo -e "${GREEN}✓ WiFi configuration reset${NC}"
}

uninstall_complete() {
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  COMPLETE UNINSTALL - ALL DATA WILL BE DELETED            ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "This will remove:"
    echo "  • All containers and pods"
    echo "  • All container images"
    echo "  • All volumes and persistent data"
    echo "  • All network configurations"
    echo "  • All configuration files"
    echo "  • All systemd services"
    echo ""
    echo -e "${RED}THIS CANNOT BE UNDONE!${NC}"
    echo ""
    read -p "Type 'UNINSTALL EVERYTHING' to confirm: " confirm

    if [ "$confirm" = "UNINSTALL EVERYTHING" ]; then
        echo ""
        echo -e "${CYAN}Starting complete uninstall...${NC}"
        echo ""

        uninstall_stop_services
        echo ""
        uninstall_containers
        echo ""
        uninstall_images
        echo ""

        # Force delete volumes without prompt
        if command -v podman &>/dev/null; then
            podman volume rm -f $(podman volume ls -q) 2>/dev/null || true
        fi
        rm -rf /var/lib/hookprobe 2>/dev/null || true
        rm -rf /var/log/hookprobe 2>/dev/null || true
        echo -e "${GREEN}✓ Volumes removed${NC}"
        echo ""

        uninstall_networks
        echo ""
        uninstall_ovs
        echo ""
        uninstall_bridges
        echo ""
        uninstall_wifi
        echo ""

        # Remove config files
        echo -e "${CYAN}Removing configuration files...${NC}"
        rm -rf /etc/hookprobe 2>/dev/null || true
        echo -e "${GREEN}✓ Configuration removed${NC}"
        echo ""

        # Remove systemd services
        echo -e "${CYAN}Removing systemd services...${NC}"
        for service in hookprobe-edge hookprobe-sentinel-lite hookprobe-neuro hookprobe-validator; do
            systemctl disable "$service" 2>/dev/null || true
            rm -f "/etc/systemd/system/${service}.service" 2>/dev/null || true
        done
        systemctl daemon-reload 2>/dev/null || true
        echo -e "${GREEN}✓ Services removed${NC}"
        echo ""

        # Run edge uninstaller if available
        if [ -f "$SCRIPT_DIR/install/edge/uninstall.sh" ]; then
            bash "$SCRIPT_DIR/install/edge/uninstall.sh" --force 2>/dev/null || true
        fi

        echo ""
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  UNINSTALL COMPLETE                                        ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    else
        echo "Uninstall cancelled."
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
            *)
                echo -e "${RED}Invalid option${NC}"
                sleep 1
                continue
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ============================================================
# COMMAND-LINE ARGUMENT PARSING
# ============================================================

show_usage() {
    echo -e "${CYAN}HookProbe Installer v6.0${NC}"
    echo ""
    echo "Usage:"
    echo "  $0                        # Interactive menu mode"
    echo "  $0 --check                # Check system capabilities only"
    echo "  $0 --role <ROLE>          # Automated installation"
    echo ""
    echo "Roles:"
    echo "  validator                 # Lightweight validator (512MB+ RAM)"
    echo "  router-edge               # Secure gateway (3GB+ RAM, 2+ NICs)"
    echo "  advanced-edge             # Full-featured edge (8GB+ RAM)"
    echo "  mssp-server               # Multi-tenant backend (64GB+ RAM)"
    echo ""
    echo "Examples:"
    echo "  sudo ./install.sh --check"
    echo "  sudo ./install.sh --role validator"
    echo "  sudo ./install.sh --role router-edge"
    echo ""
}

automated_install() {
    local role="$1"

    # Detect capabilities first
    detect_capabilities

    case "$role" in
        validator|sentinel-lite)
            if [ "$CAN_VALIDATOR" = true ]; then
                install_validator
            else
                echo -e "${RED}System does not meet requirements for Validator deployment${NC}"
                echo "Required: 512MB+ RAM, 8GB+ storage, 1+ network interface"
                exit 1
            fi
            ;;
        router-edge|edge)
            if [ "$CAN_ROUTER_EDGE" = true ]; then
                install_router_edge
            else
                echo -e "${RED}System does not meet requirements for Router Edge deployment${NC}"
                echo "Required: 3GB+ RAM, 16GB+ storage, 2+ network interfaces"
                exit 1
            fi
            ;;
        advanced-edge|advanced)
            if [ "$CAN_ADVANCED_EDGE" = true ]; then
                install_advanced_edge
            else
                echo -e "${RED}System does not meet requirements for Advanced Edge deployment${NC}"
                echo "Required: 8GB+ RAM, 32GB+ storage, 2+ ethernet ports"
                exit 1
            fi
            ;;
        mssp-server|mssp|cloud)
            if [ "$CAN_MSSP_SERVER" = true ]; then
                install_mssp_server
            else
                echo -e "${RED}System does not meet requirements for MSSP Server deployment${NC}"
                echo "Required: 8+ cores, 64GB+ RAM, 1TB+ storage"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Unknown role: $role${NC}"
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
    check_root

    # Parse command-line arguments
    if [ $# -gt 0 ]; then
        case "$1" in
            --check)
                detect_capabilities
                show_capability_summary
                exit 0
                ;;
            --role)
                if [ -z "$2" ]; then
                    echo -e "${RED}ERROR: --role requires an argument${NC}"
                    show_usage
                    exit 1
                fi
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

    # Detect capabilities for interactive mode
    detect_capabilities

    # Interactive menu mode
    while true; do
        clear
        show_banner
        show_main_menu

        read -p "Select option: " choice

        case $choice in
            1) handle_capability_check ;;
            2) handle_install ;;
            3) handle_uninstall ;;
            q|Q)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

main "$@"
