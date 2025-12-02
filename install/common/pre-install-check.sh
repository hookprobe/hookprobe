#!/bin/bash
#
# pre-install-check.sh - HookProbe Pre-Installation System Check
# Version: 5.0
# License: MIT
#
# Validates system requirements before installation
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNING=0

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  HookProbe Pre-Installation System Check                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================================
# CHECK 1: OS COMPATIBILITY
# ============================================================

check_os() {
    echo -n "Checking OS compatibility... "

    if [ ! -f /etc/os-release ]; then
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Error: Cannot detect OS (/etc/os-release missing)"
        ((CHECKS_FAILED++))
        return 1
    fi

    source /etc/os-release

    case "$ID" in
        rhel|centos|fedora|rocky|almalinux|debian|ubuntu)
            echo -e "${GREEN}✓ PASSED${NC}"
            echo "  OS: $PRETTY_NAME"
            ((CHECKS_PASSED++))
            return 0
            ;;
        *)
            echo -e "${YELLOW}⚠ WARNING${NC}"
            echo "  OS: $PRETTY_NAME (untested)"
            echo "  Supported: RHEL 9+, Fedora 40+, Debian 12+, Ubuntu 22.04+"
            ((CHECKS_WARNING++))
            return 0
            ;;
    esac
}

# ============================================================
# CHECK 2: KERNEL VERSION
# ============================================================

check_kernel() {
    echo -n "Checking kernel version... "

    KERNEL_VERSION=$(uname -r | cut -d. -f1)

    if [ "$KERNEL_VERSION" -ge 5 ]; then
        echo -e "${GREEN}✓ PASSED${NC}"
        echo "  Kernel: $(uname -r)"
        ((CHECKS_PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Kernel: $(uname -r)"
        echo "  Required: 5.x or higher"
        ((CHECKS_FAILED++))
        return 1
    fi
}

# ============================================================
# CHECK 3: ARCHITECTURE
# ============================================================

check_architecture() {
    echo -n "Checking architecture... "

    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64|aarch64)
            echo -e "${GREEN}✓ PASSED${NC}"
            echo "  Architecture: $ARCH"
            ((CHECKS_PASSED++))
            return 0
            ;;
        armv7l)
            echo -e "${RED}✗ FAILED${NC}"
            echo "  Architecture: $ARCH"
            echo "  Error: ARMv7 (32-bit) not supported"
            echo "  Required: ARM64 (aarch64) or x86_64"
            ((CHECKS_FAILED++))
            return 1
            ;;
        *)
            echo -e "${YELLOW}⚠ WARNING${NC}"
            echo "  Architecture: $ARCH (untested)"
            ((CHECKS_WARNING++))
            return 0
            ;;
    esac
}

# ============================================================
# CHECK 4: RAM
# ============================================================

check_ram() {
    echo -n "Checking RAM... "

    TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

    if [ "$TOTAL_RAM_GB" -ge 4 ]; then
        echo -e "${GREEN}✓ PASSED${NC}"
        echo "  RAM: ${TOTAL_RAM_GB}GB"
        ((CHECKS_PASSED++))
        return 0
    elif [ "$TOTAL_RAM_GB" -ge 2 ]; then
        echo -e "${YELLOW}⚠ WARNING${NC}"
        echo "  RAM: ${TOTAL_RAM_GB}GB"
        echo "  Recommended: 4GB+"
        echo "  Note: Lightweight setup available for 2-4GB systems"
        ((CHECKS_WARNING++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  RAM: ${TOTAL_RAM_GB}GB"
        echo "  Minimum: 2GB"
        ((CHECKS_FAILED++))
        return 1
    fi
}

# ============================================================
# CHECK 5: DISK SPACE
# ============================================================

check_disk() {
    echo -n "Checking disk space... "

    AVAILABLE_GB=$(df -BG / | tail -1 | awk '{print $4}' | sed 's/G//')

    if [ "$AVAILABLE_GB" -ge 50 ]; then
        echo -e "${GREEN}✓ PASSED${NC}"
        echo "  Available: ${AVAILABLE_GB}GB"
        ((CHECKS_PASSED++))
        return 0
    elif [ "$AVAILABLE_GB" -ge 20 ]; then
        echo -e "${YELLOW}⚠ WARNING${NC}"
        echo "  Available: ${AVAILABLE_GB}GB"
        echo "  Recommended: 50GB+"
        ((CHECKS_WARNING++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Available: ${AVAILABLE_GB}GB"
        echo "  Minimum: 20GB"
        ((CHECKS_FAILED++))
        return 1
    fi
}

# ============================================================
# CHECK 6: ROOT PRIVILEGES
# ============================================================

check_root() {
    echo -n "Checking root privileges... "

    if [ "$EUID" -eq 0 ]; then
        echo -e "${GREEN}✓ PASSED${NC}"
        echo "  Running as: root"
        ((CHECKS_PASSED++))
        return 0
    else
        echo -e "${YELLOW}⚠ WARNING${NC}"
        echo "  Running as: $(whoami)"
        echo "  Note: Installation requires root/sudo"
        ((CHECKS_WARNING++))
        return 0
    fi
}

# ============================================================
# CHECK 7: NETWORK CONNECTIVITY
# ============================================================

check_network() {
    echo -n "Checking network connectivity... "

    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        echo -e "${GREEN}✓ PASSED${NC}"
        echo "  Internet: Connected"
        ((CHECKS_PASSED++))
        return 0
    else
        echo -e "${YELLOW}⚠ WARNING${NC}"
        echo "  Internet: Not detected"
        echo "  Note: Required for downloading container images"
        ((CHECKS_WARNING++))
        return 0
    fi
}

# ============================================================
# CHECK 8: CONTAINER RUNTIME
# ============================================================

check_container_runtime() {
    echo -n "Checking container runtime... "

    if command -v podman &>/dev/null; then
        echo -e "${GREEN}✓ PASSED${NC}"
        echo "  Podman: $(podman --version | head -1)"
        ((CHECKS_PASSED++))
        return 0
    elif command -v docker &>/dev/null; then
        echo -e "${GREEN}✓ PASSED${NC}"
        echo "  Docker: $(docker --version | head -1)"
        ((CHECKS_PASSED++))
        return 0
    else
        echo -e "${YELLOW}⚠ WARNING${NC}"
        echo "  Container runtime: Not installed"
        echo "  Will be installed: Podman (recommended)"
        ((CHECKS_WARNING++))
        return 0
    fi
}

# ============================================================
# CHECK 9: PYTHON 3
# ============================================================

check_python() {
    echo -n "Checking Python 3... "

    if command -v python3 &>/dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        echo -e "${GREEN}✓ PASSED${NC}"
        echo "  Python: $PYTHON_VERSION"
        ((CHECKS_PASSED++))
        return 0
    else
        echo -e "${YELLOW}⚠ WARNING${NC}"
        echo "  Python 3: Not installed"
        echo "  Will be installed during setup"
        ((CHECKS_WARNING++))
        return 0
    fi
}

# ============================================================
# CHECK 10: VIRTUALIZATION DETECTION
# ============================================================

check_virtualization() {
    echo -n "Checking virtualization... "

    if [ -f /proc/cpuinfo ]; then
        if grep -q "hypervisor" /proc/cpuinfo; then
            echo -e "${GREEN}✓ DETECTED${NC}"
            echo "  Type: Virtual machine"
        else
            echo -e "${GREEN}✓ DETECTED${NC}"
            echo "  Type: Physical hardware"
        fi
        ((CHECKS_PASSED++))
        return 0
    else
        echo -e "${YELLOW}⚠ UNKNOWN${NC}"
        ((CHECKS_WARNING++))
        return 0
    fi
}

# ============================================================
# RUN ALL CHECKS
# ============================================================

echo "Running system compatibility checks..."
echo ""

check_os
echo ""

check_kernel
echo ""

check_architecture
echo ""

check_ram
echo ""

check_disk
echo ""

check_root
echo ""

check_network
echo ""

check_container_runtime
echo ""

check_python
echo ""

check_virtualization
echo ""

# ============================================================
# SUMMARY
# ============================================================

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Pre-Installation Check Summary                          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

TOTAL_CHECKS=$((CHECKS_PASSED + CHECKS_FAILED + CHECKS_WARNING))

echo -e "  ${GREEN}✓ Passed: $CHECKS_PASSED${NC}"
echo -e "  ${YELLOW}⚠ Warnings: $CHECKS_WARNING${NC}"
echo -e "  ${RED}✗ Failed: $CHECKS_FAILED${NC}"
echo -e "  Total Checks: $TOTAL_CHECKS"
echo ""

if [ "$CHECKS_FAILED" -eq 0 ]; then
    if [ "$CHECKS_WARNING" -eq 0 ]; then
        echo -e "${GREEN}✓ System is ready for HookProbe installation!${NC}"
        echo ""
        echo "Next step: Run ./install.sh"
        exit 0
    else
        echo -e "${YELLOW}⚠ System has warnings but can proceed${NC}"
        echo ""
        echo "Warnings should be addressed before production use"
        echo "For testing/development, you can proceed with installation"
        echo ""
        echo "Next step: Run ./install.sh"
        exit 0
    fi
else
    echo -e "${RED}✗ System does not meet minimum requirements${NC}"
    echo ""
    echo "Please address the failed checks before installation"
    exit 1
fi
