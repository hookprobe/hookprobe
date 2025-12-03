#!/bin/bash
#
# requirements.sh - System Requirements Validation
# Part of HookProbe unified installation system
#
# Validates: RAM, disk space, dependencies, permissions
#

# Source platform detection if not already loaded
if [ -z "$PLATFORM_OS" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/platform.sh"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================
# SYSTEM REQUIREMENTS VALIDATION
# ============================================================

check_root() {
    # Check if running as root.

    #

    # Returns:

    # 0 if root

    # 1 if not root

    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}✗ ERROR: This script must be run as root${NC}"
        echo ""
        echo "Usage: sudo $0"
        return 1
    fi

    echo -e "${GREEN}✓${NC} Running as root"
    return 0
}

check_ram() {
    # Check if system has sufficient RAM.

    #

    # Args:

    # $1 - minimum required RAM in GB (default: 4)

    #

    # Returns:

    # 0 if sufficient

    # 1 if insufficient

    local min_ram_gb=${1:-4}

    if [ "$TOTAL_RAM_GB" -lt "$min_ram_gb" ]; then
        echo -e "${RED}✗${NC} Insufficient RAM: ${RED}${TOTAL_RAM_GB}GB${NC} (minimum ${min_ram_gb}GB required)"
        return 1
    fi

    echo -e "${GREEN}✓${NC} RAM sufficient: ${TOTAL_RAM_GB}GB"
    return 0
}

check_disk_space() {
    # Check if / has sufficient free space.

    #

    # Args:

    # $1 - minimum required space in GB (default: 20)

    #

    # Returns:

    # 0 if sufficient

    # 1 if insufficient

    local min_space_gb=${1:-20}

    # Get free space in GB for root filesystem
    local free_space_kb=$(df / | awk 'NR==2 {print $4}')
    local free_space_gb=$((free_space_kb / 1024 / 1024))

    if [ "$free_space_gb" -lt "$min_space_gb" ]; then
        echo -e "${RED}✗${NC} Insufficient disk space: ${RED}${free_space_gb}GB${NC} free (minimum ${min_space_gb}GB required)"
        return 1
    fi

    echo -e "${GREEN}✓${NC} Disk space sufficient: ${free_space_gb}GB free"
    return 0
}

check_cgroup_requirements() {
    # Check cgroup requirements for Raspberry Pi.

    #

    # Returns:

    # 0 if OK or not Raspberry Pi

    # 1 if Raspberry Pi and cgroups not enabled

    # Only check on Raspberry Pi
    if [ "$IS_RASPBERRY_PI" != true ]; then
        return 0
    fi

    if ! check_cgroup_enabled; then
        echo -e "${RED}✗${NC} Cgroups not enabled (required for Raspberry Pi)"
        return 1
    fi

    echo -e "${GREEN}✓${NC} Cgroups enabled"
    return 0
}

# ============================================================
# DEPENDENCY CHECKS
# ============================================================

check_podman() {
    # Check if Podman is installed.

    #

    # Returns:

    # 0 if installed

    # 1 if not installed

    if command -v podman &> /dev/null; then
        local version=$(podman --version | awk '{print $3}')
        echo -e "${GREEN}✓${NC} Podman installed: $version"
        return 0
    else
        echo -e "${YELLOW}⚠${NC} Podman not installed (will be installed)"
        return 1
    fi
}

check_git() {
    # Check if Git is installed.

    #

    # Returns:

    # 0 if installed

    # 1 if not installed

    if command -v git &> /dev/null; then
        local version=$(git --version | awk '{print $3}')
        echo -e "${GREEN}✓${NC} Git installed: $version"
        return 0
    else
        echo -e "${YELLOW}⚠${NC} Git not installed (will be installed)"
        return 1
    fi
}

check_python() {
    # Check if Python 3.9+ is installed.

    #

    # Returns:

    # 0 if installed and version OK

    # 1 if not installed or version too old

    if command -v python3 &> /dev/null; then
        local version=$(python3 --version | awk '{print $2}')
        local major=$(echo "$version" | cut -d. -f1)
        local minor=$(echo "$version" | cut -d. -f2)

        if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
            echo -e "${GREEN}✓${NC} Python installed: $version"
            return 0
        else
            echo -e "${YELLOW}⚠${NC} Python $version too old (need 3.9+, will upgrade)"
            return 1
        fi
    else
        echo -e "${YELLOW}⚠${NC} Python not installed (will be installed)"
        return 1
    fi
}

# ============================================================
# NETWORK CHECKS
# ============================================================

check_network() {
    # Check if system has network connectivity.

    #

    # Returns:

    # 0 if connected

    # 1 if not connected

    # Try to ping a reliable DNS server
    if ping -c 1 -W 2 8.8.8.8 &> /dev/null; then
        echo -e "${GREEN}✓${NC} Network connectivity OK"
        return 0
    else
        echo -e "${RED}✗${NC} No network connectivity"
        return 1
    fi
}

check_dns() {
    # Check if DNS resolution works.
    #
    # Uses multiple methods for reliability:
    #   1. getent hosts - standard glibc resolver
    #   2. ping with hostname - fallback test
    #
    # Returns:
    #   0 if DNS works
    #   1 if DNS fails

    # Method 1: Use getent (most reliable, uses system resolver)
    if getent hosts github.com &> /dev/null; then
        echo -e "${GREEN}✓${NC} DNS resolution OK"
        return 0
    fi

    # Method 2: Try ping with hostname (tests DNS indirectly)
    if ping -c 1 -W 2 github.com &> /dev/null; then
        echo -e "${GREEN}✓${NC} DNS resolution OK"
        return 0
    fi

    # Method 3: Fallback to nslookup/host if available
    if command -v nslookup &> /dev/null && nslookup github.com &> /dev/null; then
        echo -e "${GREEN}✓${NC} DNS resolution OK"
        return 0
    fi

    if command -v host &> /dev/null && host github.com &> /dev/null; then
        echo -e "${GREEN}✓${NC} DNS resolution OK"
        return 0
    fi

    echo -e "${YELLOW}!${NC} DNS resolution issues (may affect installation)"
    return 1
}

# ============================================================
# COMPREHENSIVE SYSTEM CHECK
# ============================================================

run_system_check() {
    # Run comprehensive system requirements check.

    #

    # Args:

    # $1 - enable_ai (true/false)

    # $2 - enable_monitoring (true/false)

    #

    # Returns:

    # 0 if all checks pass

    # 1 if any critical check fails

    local enable_ai=${1:-false}
    local enable_monitoring=${2:-false}

    echo ""
    echo "Running system requirements check..."
    echo ""

    local failed=0

    # Critical checks (must pass)
    if ! check_root; then
        failed=1
    fi

    # Detect platform if not already done
    if [ -z "$PLATFORM_OS" ]; then
        detect_platform
    fi

    # RAM check
    if [ "$enable_ai" = true ]; then
        if ! check_ram 8; then  # AI needs at least 8GB
            show_low_ram_warning "$TOTAL_RAM_GB" 8
            failed=1
        fi
    else
        if ! check_ram 3; then  # Edge lightweight needs at least 3GB
            show_low_ram_warning "$TOTAL_RAM_GB" 3
            failed=1
        fi
    fi

    # Disk space check (Raspberry Pi may have smaller SD cards)
    if [ "$IS_RASPBERRY_PI" = true ]; then
        if ! check_disk_space 15; then  # Relaxed for RPi
            show_low_disk_warning "$(df / | awk 'NR==2 {print int($4/1024/1024)}')" 15
            failed=1
        fi
    else
        if ! check_disk_space 20; then
            show_low_disk_warning "$(df / | awk 'NR==2 {print int($4/1024/1024)}')" 20
            failed=1
        fi
    fi

    # Cgroup check (critical for Raspberry Pi)
    if ! check_cgroup_requirements; then
        failed=1
    fi

    echo ""
    echo "Dependency check..."
    echo ""

    # Dependency checks (can be fixed)
    check_podman || true
    check_git || true
    check_python || true

    echo ""
    echo "Network check..."
    echo ""

    # Network checks
    if ! check_network; then
        echo -e "${RED}✗ Network connectivity required for installation${NC}"
        failed=1
    fi
    check_dns || true  # Not critical

    echo ""

    if [ "$failed" -eq 1 ]; then
        echo -e "${RED}✗ System requirements check FAILED${NC}"
        echo ""
        echo "Please fix the issues above and re-run the installer."
        return 1
    else
        echo -e "${GREEN}✓ System requirements check PASSED${NC}"
        return 0
    fi
}

# ============================================================
# MEMORY SUFFICIENCY CHECK
# ============================================================

check_memory_sufficiency() {
    # Check if available RAM is sufficient for selected PODs.

    #

    # Args:

    # $1 - enable_ai (true/false)

    # $2 - enable_monitoring (true/false)

    # $3 - enable_iam (true/false)

    #

    # Returns:

    # 0 if sufficient

    # 1 if insufficient

    local enable_ai=${1:-false}
    local enable_monitoring=${2:-false}
    local enable_iam=${3:-true}

    # Calculate total memory needed
    local total_mb=$(get_total_memory_usage "$enable_ai" "$enable_monitoring" "$enable_iam")
    local total_gb=$(awk "BEGIN {printf \"%.1f\", $total_mb/1024}")

    # Available RAM should be at least 80% of total
    local usable_ram=$((TOTAL_RAM_GB * 80 / 100))

    echo ""
    echo "Memory allocation check:"
    echo "  Total RAM:        ${TOTAL_RAM_GB}GB"
    echo "  Usable RAM:       ~${usable_ram}GB (80% of total)"
    echo "  Required for PODs: ~${total_gb}GB"
    echo ""

    if [ $(awk "BEGIN {print ($total_mb/1024 > $usable_ram)}") -eq 1 ]; then
        echo -e "${YELLOW}⚠ WARNING: Memory usage may be tight${NC}"
        echo ""

        # If AI is enabled on low RAM, show specific warning
        if [ "$enable_ai" = true ] && [ "$TOTAL_RAM_GB" -lt 16 ]; then
            show_ai_enable_warning "$TOTAL_RAM_GB" "$total_mb"
            return 1
        fi

        return 1
    else
        echo -e "${GREEN}✓ Memory allocation looks good${NC}"
        return 0
    fi
}

# ============================================================
# PORT AVAILABILITY CHECK
# ============================================================

check_port_available() {
    # Check if a port is available.

    #

    # Args:

    # $1 - port number

    #

    # Returns:

    # 0 if available

    # 1 if in use

    local port=$1

    if netstat -tuln 2>/dev/null | grep -q ":$port " || \
       ss -tuln 2>/dev/null | grep -q ":$port "; then
        return 1  # Port in use
    else
        return 0  # Port available
    fi
}

check_required_ports() {
    # Check if required ports are available.

    #

    # Returns:

    # 0 if all available

    # 1 if any port is in use

    local ports=(80 443 5432 6379 3001 3002)
    local in_use=()

    for port in "${ports[@]}"; do
        if ! check_port_available "$port"; then
            in_use+=("$port")
        fi
    done

    if [ ${#in_use[@]} -gt 0 ]; then
        echo -e "${YELLOW}⚠${NC} The following ports are in use: ${in_use[*]}"
        echo "   These may cause conflicts with HookProbe PODs"
        return 1
    else
        echo -e "${GREEN}✓${NC} Required ports available"
        return 0
    fi
}
