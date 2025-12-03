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
    """
    Detect platform information and export variables.

    Exports:
        PLATFORM_OS       - Pretty OS name (e.g., "Raspberry Pi OS")
        PLATFORM_ARCH     - Architecture (x86_64, ARM64, ARM32)
        TOTAL_RAM_GB      - Total RAM in GB
        IS_RASPBERRY_PI   - true/false
        CPU_CORES         - Number of CPU cores
    """

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
        local model=$(cat /proc/device-tree/model 2>/dev/null || echo "")
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
# CGROUP DETECTION
# ============================================================

check_cgroup_enabled() {
    """
    Check if cgroup v2 memory controller is enabled.

    Returns:
        0 if enabled
        1 if not enabled
    """

    # Check for cgroup v2 memory controller
    if [ -f /sys/fs/cgroup/memory.max ]; then
        return 0  # Enabled
    fi

    # Check for cgroup v1 memory controller (older systems)
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        return 0  # Enabled (v1)
    fi

    # Check /proc/cgroups
    if [ -f /proc/cgroups ]; then
        if grep -q "^memory.*1$" /proc/cgroups; then
            return 0  # Enabled
        fi
    fi

    return 1  # Not enabled
}

get_cgroup_version() {
    """
    Detect cgroup version (v1 or v2).

    Outputs:
        "v2" or "v1" or "none"
    """

    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        echo "v2"
    elif [ -d /sys/fs/cgroup/memory ]; then
        echo "v1"
    else
        echo "none"
    fi
}

get_boot_config_path() {
    """
    Determine the correct boot configuration path for Raspberry Pi.

    Outputs:
        Path to cmdline.txt or empty string if not found
    """

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
    """
    Check if cgroup parameters are present in boot config.

    Returns:
        0 if present
        1 if not present or file not found
    """

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
    """
    Calculate appropriate memory limits based on total RAM.

    Exports:
        POD_MEMORY_WEB
        POD_MEMORY_DATABASE
        POD_MEMORY_CACHE
        POD_MEMORY_NEURO
        POD_MEMORY_IAM
        MEMORY_PROFILE (Lightweight/Moderate/Full)
    """

    if [ "$TOTAL_RAM_GB" -le 4 ]; then
        # Conservative for 4GB systems (Raspberry Pi 4B)
        export POD_MEMORY_WEB="768M"
        export POD_MEMORY_DATABASE="512M"
        export POD_MEMORY_CACHE="256M"
        export POD_MEMORY_NEURO="512M"
        export POD_MEMORY_IAM="384M"
        export MEMORY_PROFILE="Lightweight"

    elif [ "$TOTAL_RAM_GB" -le 8 ]; then
        # Moderate for 8GB systems
        export POD_MEMORY_WEB="1536M"
        export POD_MEMORY_DATABASE="1536M"
        export POD_MEMORY_CACHE="512M"
        export POD_MEMORY_NEURO="1024M"
        export POD_MEMORY_IAM="512M"
        export MEMORY_PROFILE="Moderate"

    else
        # Full for 16GB+ systems
        export POD_MEMORY_WEB="2048M"
        export POD_MEMORY_DATABASE="2048M"
        export POD_MEMORY_CACHE="1024M"
        export POD_MEMORY_NEURO="1024M"
        export POD_MEMORY_IAM="512M"
        export MEMORY_PROFILE="Full"
    fi
}

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

get_total_memory_usage() {
    """
    Calculate total memory usage for selected PODs.

    Args:
        $1 - enable_ai (true/false)
        $2 - enable_monitoring (true/false)
        $3 - enable_iam (true/false)

    Outputs:
        Total memory in MB
    """

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
    """
    Format bytes to human-readable format.

    Args:
        $1 - bytes

    Outputs:
        Formatted string (e.g., "4.2GB")
    """

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
