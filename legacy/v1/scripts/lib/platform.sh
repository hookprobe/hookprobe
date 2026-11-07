#!/bin/bash
#
# platform.sh - Platform Detection Library
# Part of HookProbe unified installation system
#
# Detects: OS, architecture, RAM, Raspberry Pi, cgroups
#

# ============================================================
# PLATFORM DETECTION
# ============================================================

detect_platform() {
    # Detect platform information and export variables.
    #
    # Exports:
    #   PLATFORM_OS       - Pretty OS name (e.g., "Raspberry Pi OS")
    #   PLATFORM_ARCH     - Architecture (x86_64, ARM64, ARM32)
    #   TOTAL_RAM_GB      - Total RAM in GB
    #   IS_RASPBERRY_PI   - true/false
    #   CPU_CORES         - Number of CPU cores

    # Detect OS
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        PLATFORM_OS="$PRETTY_NAME"
        OS_ID="$ID"
        OS_VERSION_ID="$VERSION_ID"
    else
        PLATFORM_OS="Unknown Linux"
        OS_ID="unknown"
        OS_VERSION_ID="unknown"
    fi

    # Detect architecture
    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            PLATFORM_ARCH="x86_64"
            ;;
        aarch64|arm64)
            PLATFORM_ARCH="ARM64"
            ;;
        armv7l|armv7)
            PLATFORM_ARCH="ARM32"
            ;;
        *)
            PLATFORM_ARCH="$arch"
            ;;
    esac

    # Detect total RAM in GB
    local ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_RAM_GB=$((ram_kb / 1024 / 1024))

    # Calculate available RAM (more accurate than total)
    local ram_available_kb=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    AVAILABLE_RAM_GB=$((ram_available_kb / 1024 / 1024))

    # Detect CPU cores
    CPU_CORES=$(nproc)

    # Detect if Raspberry Pi
    IS_RASPBERRY_PI=false
    RASPBERRY_PI_MODEL=""

    if [ -f /proc/device-tree/model ]; then
        # Use tr to remove null bytes that cause warnings
        local model=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "")
        if [[ "$model" == *"Raspberry Pi"* ]]; then
            IS_RASPBERRY_PI=true
            RASPBERRY_PI_MODEL="$model"
        fi
    fi

    # Alternative RPi detection via /proc/cpuinfo
    if [ "$IS_RASPBERRY_PI" = false ] && [ -f /proc/cpuinfo ]; then
        if grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
            IS_RASPBERRY_PI=true
            RASPBERRY_PI_MODEL=$(grep "Model" /proc/cpuinfo | cut -d':' -f2 | xargs)
        fi
    fi

    # Export all variables
    export PLATFORM_OS PLATFORM_ARCH TOTAL_RAM_GB AVAILABLE_RAM_GB
    export IS_RASPBERRY_PI RASPBERRY_PI_MODEL CPU_CORES
    export OS_ID OS_VERSION_ID
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

    local os_id="${OS_ID:-$(. /etc/os-release 2>/dev/null && echo "$ID")}"

    case "$os_id" in
        ubuntu|debian|raspbian|pop|linuxmint|elementary|zorin|kali)
            return 0  # Supported Debian-based
            ;;
        rhel|centos|fedora|rocky|almalinux|ol|scientific)
            return 1  # RHEL-based - not currently supported
            ;;
        *)
            # Check ID_LIKE for Debian-based derivatives
            local os_like="${ID_LIKE:-$(. /etc/os-release 2>/dev/null && echo "$ID_LIKE")}"
            if [[ "$os_like" == *"debian"* ]] || [[ "$os_like" == *"ubuntu"* ]]; then
                return 0  # Debian-based derivative
            elif [[ "$os_like" == *"rhel"* ]] || [[ "$os_like" == *"fedora"* ]] || [[ "$os_like" == *"centos"* ]]; then
                return 1  # RHEL-based derivative
            fi
            # Default: allow unknown distributions to proceed
            return 0
            ;;
    esac
}

show_rhel_not_supported() {
    # Display a friendly message that RHEL-based systems are not yet supported.

    local RED=$'\033[0;31m'
    local YELLOW=$'\033[1;33m'
    local CYAN=$'\033[0;36m'
    local NC=$'\033[0m'

    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  RHEL-Based Systems Not Yet Supported${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  HookProbe v5.x currently supports ${CYAN}Debian-based${NC} systems only:"
    echo ""
    echo -e "    ${CYAN}✓${NC} Ubuntu 22.04+, 24.04+"
    echo -e "    ${CYAN}✓${NC} Debian 11+, 12+"
    echo -e "    ${CYAN}✓${NC} Raspberry Pi OS (Bookworm)"
    echo ""
    echo -e "  ${RED}Detected OS: ${PLATFORM_OS:-$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")}${NC}"
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

# ============================================================
# CGROUP DETECTION
# ============================================================

check_cgroup_enabled() {
    # Check if cgroups are enabled and functional.
    #
    # Uses multiple detection methods:
    #   1. stat -fc %T /sys/fs/cgroup/ - detects cgroup filesystem type
    #   2. mount | grep cgroup - verifies cgroup is mounted
    #   3. /proc/cgroups check for memory controller
    #
    # Returns:
    #   0 if enabled
    #   1 if not enabled

    # Method 1: Check cgroup filesystem type using stat
    # cgroup2fs = cgroup v2, tmpfs/cgroup = cgroup v1
    if [ -d /sys/fs/cgroup ]; then
        local cgroup_type=$(stat -fc %T /sys/fs/cgroup/ 2>/dev/null)
        if [ "$cgroup_type" = "cgroup2fs" ]; then
            # cgroup v2 detected, check if memory controller is available
            if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
                if grep -q "memory" /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
                    return 0  # cgroup v2 with memory controller
                fi
            fi
            # cgroup v2 mounted but might not have memory controller enabled
            # Still return success as cgroup is functional
            return 0
        elif [ "$cgroup_type" = "tmpfs" ] || [ "$cgroup_type" = "cgroup" ]; then
            # cgroup v1 or hybrid - check if memory controller exists
            if [ -d /sys/fs/cgroup/memory ] || [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
                return 0  # cgroup v1 with memory controller
            fi
        fi
    fi

    # Method 2: Check if cgroup is mounted using mount command
    if mount | grep -q "cgroup" 2>/dev/null; then
        # cgroup is mounted - check for memory controller
        if mount | grep -q "cgroup.*memory" 2>/dev/null || \
           mount | grep -q "cgroup2" 2>/dev/null; then
            return 0  # Memory cgroup is mounted
        fi
        # cgroup mounted but memory might not be enabled
        # Check /proc/cgroups as fallback
    fi

    # Method 3: Check /proc/cgroups for memory controller status
    if [ -f /proc/cgroups ]; then
        # Format: name hierarchy num_cgroups enabled
        # We check if memory is enabled (last column = 1)
        if awk '$1 == "memory" && $4 == 1 {exit 0} END {exit 1}' /proc/cgroups 2>/dev/null; then
            return 0  # Memory controller enabled in kernel
        fi
    fi

    return 1  # cgroups not properly enabled
}

get_cgroup_version() {
    # Detect cgroup version (v1, v2, or hybrid).
    #
    # Uses stat -fc %T to detect filesystem type
    #
    # Outputs:
    #   "v2" or "v1" or "hybrid" or "none"

    if [ ! -d /sys/fs/cgroup ]; then
        echo "none"
        return
    fi

    local cgroup_type=$(stat -fc %T /sys/fs/cgroup/ 2>/dev/null)

    case "$cgroup_type" in
        cgroup2fs)
            echo "v2"
            ;;
        tmpfs)
            # Hybrid mode - cgroup v1 with v2 unified hierarchy
            if [ -d /sys/fs/cgroup/unified ]; then
                echo "hybrid"
            else
                echo "v1"
            fi
            ;;
        cgroup)
            echo "v1"
            ;;
        *)
            # Fallback: check for v2 controller file
            if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
                echo "v2"
            elif [ -d /sys/fs/cgroup/memory ]; then
                echo "v1"
            else
                echo "none"
            fi
            ;;
    esac
}

get_boot_config_path() {
    # Determine the correct boot configuration path for Raspberry Pi.
    #
    # Outputs:
    #   Path to cmdline.txt or empty string if not found

    # Raspberry Pi OS Bookworm (Debian 12+)
    if [ -f /boot/firmware/cmdline.txt ]; then
        echo "/boot/firmware/cmdline.txt"
        return 0
    fi

    # Older Raspberry Pi OS
    if [ -f /boot/cmdline.txt ]; then
        echo "/boot/cmdline.txt"
        return 0
    fi

    # Not found
    return 1
}

check_cgroup_boot_params() {
    # Check if cgroup parameters are present in boot config.
    #
    # Returns:
    #   0 if present
    #   1 if not present or file not found

    local boot_config=$(get_boot_config_path)

    if [ -z "$boot_config" ]; then
        return 1
    fi

    if [ ! -f "$boot_config" ]; then
        return 1
    fi

    # Check for required parameters
    local content=$(cat "$boot_config")

    if [[ "$content" == *"cgroup_enable=memory"* ]] && \
       [[ "$content" == *"cgroup_memory=1"* ]]; then
        return 0
    fi

    return 1
}

# ============================================================
# MEMORY CALCULATION
# ============================================================

calculate_memory_limits() {
    # Calculate appropriate memory limits based on total RAM.
    #
    # Exports:
    #   POD_MEMORY_WEB
    #   POD_MEMORY_DATABASE
    #   POD_MEMORY_CACHE
    #   POD_MEMORY_NEURO
    #   POD_MEMORY_IAM
    #   POD_MEMORY_SENTINEL
    #   MEMORY_PROFILE (Ultra/Lightweight/Moderate/Full)

    # Calculate total RAM in MB for finer granularity
    local ram_mb=$((TOTAL_RAM_GB * 1024))
    if [ -f /proc/meminfo ]; then
        ram_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    fi

    if [ "$ram_mb" -le 512 ]; then
        # Ultra-constrained for 512MB systems (Pi Zero, Pico-class)
        # Only sentinel-lite supported - no PODs
        export POD_MEMORY_WEB="0"
        export POD_MEMORY_DATABASE="0"
        export POD_MEMORY_CACHE="0"
        export POD_MEMORY_NEURO="0"
        export POD_MEMORY_IAM="0"
        export POD_MEMORY_SENTINEL="128M"
        export MEMORY_PROFILE="Ultra"

    elif [ "$ram_mb" -le 1024 ]; then
        # Ultra-lightweight for 1GB systems (Raspberry Pi 3, Pi Zero 2)
        # Sentinel-lite only, no full POD support
        export POD_MEMORY_WEB="0"
        export POD_MEMORY_DATABASE="0"
        export POD_MEMORY_CACHE="0"
        export POD_MEMORY_NEURO="0"
        export POD_MEMORY_IAM="0"
        export POD_MEMORY_SENTINEL="192M"
        export MEMORY_PROFILE="Ultra"

    elif [ "$ram_mb" -le 2048 ]; then
        # Minimal for 2GB systems (Pi 3B+, low-end ARM)
        # Supports sentinel + minimal edge, no AI/monitoring
        export POD_MEMORY_WEB="256M"
        export POD_MEMORY_DATABASE="256M"
        export POD_MEMORY_CACHE="64M"
        export POD_MEMORY_NEURO="256M"
        export POD_MEMORY_IAM="128M"
        export POD_MEMORY_SENTINEL="256M"
        export MEMORY_PROFILE="Minimal"

    elif [ "$TOTAL_RAM_GB" -le 4 ]; then
        # Lightweight for 4GB systems (Raspberry Pi 4B)
        # Total POD usage: ~1.75GB, leaves ~2.25GB for OS/buffers
        export POD_MEMORY_WEB="512M"
        export POD_MEMORY_DATABASE="512M"
        export POD_MEMORY_CACHE="128M"
        export POD_MEMORY_NEURO="384M"
        export POD_MEMORY_IAM="256M"
        export POD_MEMORY_SENTINEL="256M"
        export MEMORY_PROFILE="Lightweight"

    elif [ "$TOTAL_RAM_GB" -le 8 ]; then
        # Moderate for 8GB systems
        export POD_MEMORY_WEB="1536M"
        export POD_MEMORY_DATABASE="1536M"
        export POD_MEMORY_CACHE="512M"
        export POD_MEMORY_NEURO="1024M"
        export POD_MEMORY_IAM="512M"
        export POD_MEMORY_SENTINEL="512M"
        export MEMORY_PROFILE="Moderate"

    else
        # Full for 16GB+ systems
        export POD_MEMORY_WEB="2048M"
        export POD_MEMORY_DATABASE="2048M"
        export POD_MEMORY_CACHE="1024M"
        export POD_MEMORY_NEURO="1024M"
        export POD_MEMORY_IAM="512M"
        export POD_MEMORY_SENTINEL="512M"
        export MEMORY_PROFILE="Full"
    fi
}

get_sentinel_memory_limit() {
    # Get appropriate memory limit for sentinel based on available RAM
    #
    # Args:
    #   $1 - mode: "lite" for sentinel-lite, "full" for containerized sentinel
    #
    # Outputs:
    #   Memory limit in MB

    local mode=${1:-"lite"}

    # Get available RAM in MB
    local ram_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo "512")

    if [ "$mode" = "lite" ]; then
        # Sentinel Lite (native, no container)
        if [ "$ram_mb" -le 384 ]; then
            echo "128"    # Ultra-constrained: 128MB
        elif [ "$ram_mb" -le 768 ]; then
            echo "192"    # Constrained: 192MB
        elif [ "$ram_mb" -le 1536 ]; then
            echo "256"    # Low: 256MB
        else
            echo "384"    # Standard: 384MB
        fi
    else
        # Full Sentinel (containerized)
        if [ "$ram_mb" -le 1024 ]; then
            echo "256"    # Minimal container
        elif [ "$ram_mb" -le 2048 ]; then
            echo "384"    # Low container
        else
            echo "512"    # Standard container
        fi
    fi
}

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

get_total_memory_usage() {
    # Calculate total memory usage for selected PODs.
    #
    # Args:
    #   $1 - enable_ai (true/false)
    #   $2 - enable_monitoring (true/false)
    #   $3 - enable_iam (true/false)
    #
    # Outputs:
    #   Total memory in MB

    local enable_ai=${1:-false}
    local enable_monitoring=${2:-false}
    local enable_iam=${3:-false}

    # Convert memory limits to MB
    local web_mb=$(echo "$POD_MEMORY_WEB" | sed 's/M$//')
    local db_mb=$(echo "$POD_MEMORY_DATABASE" | sed 's/M$//')
    local cache_mb=$(echo "$POD_MEMORY_CACHE" | sed 's/M$//')
    local neuro_mb=$(echo "$POD_MEMORY_NEURO" | sed 's/M$//')

    local total=$((web_mb + db_mb + cache_mb + neuro_mb))

    if [ "$enable_iam" = true ]; then
        local iam_mb=$(echo "$POD_MEMORY_IAM" | sed 's/M$//')
        total=$((total + iam_mb))
    fi

    if [ "$enable_ai" = true ]; then
        # AI PODs (Detection + Analysis)
        total=$((total + 2048 + 2048))  # ~4GB for AI
    fi

    if [ "$enable_monitoring" = true ]; then
        # Monitoring PODs
        total=$((total + 2048))  # ~2GB for monitoring
    fi

    echo "$total"
}

format_bytes() {
    # Format bytes to human-readable format.
    #
    # Args:
    #   $1 - bytes
    #
    # Outputs:
    #   Formatted string (e.g., "4.2GB")

    local bytes=$1

    if [ "$bytes" -ge 1073741824 ]; then
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1073741824}")GB"
    elif [ "$bytes" -ge 1048576 ]; then
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1048576}")MB"
    elif [ "$bytes" -ge 1024 ]; then
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1024}")KB"
    else
        echo "${bytes}B"
    fi
}
