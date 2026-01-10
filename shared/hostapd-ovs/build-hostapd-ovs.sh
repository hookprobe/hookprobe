#!/bin/bash
#
# build-hostapd-ovs.sh - Build hostapd 2.10/2.11 with OVS bridge support
#
# Part of HookProbe - Federated Cybersecurity Mesh
# This patch allows hostapd to directly bridge WiFi interfaces to OVS switches
# without requiring veth pairs and Linux bridges as intermediaries.
#
# The patch adds an OVS fallback to linux_br_get() function, which queries
# ovs-vsctl to find the bridge that owns an interface when the standard
# sysfs/ioctl method fails (as it does for OVS bridges).
#
# Supported: hostapd 2.10, 2.11 ONLY
#
# Usage:
#   ./build-hostapd-ovs.sh                    # Build with default (2.11)
#   HOSTAPD_VERSION=2.10 ./build-hostapd-ovs.sh  # Build with 2.10
#   ./build-hostapd-ovs.sh --check            # Check if already installed
#   ./build-hostapd-ovs.sh --uninstall        # Remove hostapd-ovs
#
# Post-install:
#   - hostapd-ovs is installed to /usr/local/bin/hostapd-ovs
#   - hostapd_cli-ovs is installed to /usr/local/bin/hostapd_cli-ovs
#   - Original system hostapd is preserved
#   - Use bridge= directive pointing directly to OVS bridge name in hostapd.conf
#
# Author: HookProbe Team
# License: AGPL-3.0
# Version: 1.0.0
#

set -e

HOSTAPD_VERSION="${HOSTAPD_VERSION:-2.11}"
BUILD_DIR="/tmp/hostapd-ovs-build"
INSTALL_PREFIX="/usr/local"
STATE_FILE="/var/lib/hookprobe/hostapd-ovs.state"
VERSION="1.0.0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok() { echo -e "${GREEN}[✓]${NC} $1"; }
log_info() { echo -e "${CYAN}[i]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build hostapd with OVS bridge support for HookProbe.

OPTIONS:
    --check         Check if hostapd-ovs is already installed
    --uninstall     Remove hostapd-ovs binaries
    --version       Show version information
    -h, --help      Show this help

ENVIRONMENT:
    HOSTAPD_VERSION    Version to build (2.10 or 2.11, default: 2.11)
    INSTALL_PREFIX     Installation prefix (default: /usr/local)

EXAMPLES:
    sudo $0                              # Build and install hostapd 2.11 + OVS
    sudo HOSTAPD_VERSION=2.10 $0         # Build hostapd 2.10 + OVS
    $0 --check                           # Check installation status
    sudo $0 --uninstall                  # Remove hostapd-ovs

EOF
}

check_installation() {
    if [ -x "${INSTALL_PREFIX}/bin/hostapd-ovs" ]; then
        local version
        version=$("${INSTALL_PREFIX}/bin/hostapd-ovs" -v 2>&1 | head -1 || echo "unknown")
        echo -e "${GREEN}[✓]${NC} hostapd-ovs is installed"
        echo "    Binary: ${INSTALL_PREFIX}/bin/hostapd-ovs"
        echo "    Version: $version"
        if [ -f "$STATE_FILE" ]; then
            echo "    Build info: $(cat "$STATE_FILE")"
        fi
        return 0
    else
        echo -e "${YELLOW}[i]${NC} hostapd-ovs is not installed"
        return 1
    fi
}

uninstall() {
    log_info "Removing hostapd-ovs..."

    rm -f "${INSTALL_PREFIX}/bin/hostapd-ovs"
    rm -f "${INSTALL_PREFIX}/bin/hostapd_cli-ovs"
    rm -f "$STATE_FILE"

    # Cleanup build dir if exists
    rm -rf "$BUILD_DIR"

    log_ok "hostapd-ovs removed"
}

check_deps() {
    log_info "Checking dependencies..."

    local MISSING=""
    for pkg in build-essential git pkg-config libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev wget; do
        if ! dpkg -l 2>/dev/null | grep -q "^ii  $pkg"; then
            MISSING="$MISSING $pkg"
        fi
    done

    if [ -n "$MISSING" ]; then
        log_info "Installing:$MISSING"
        apt-get update -qq
        # shellcheck disable=SC2086
        apt-get install -y -qq $MISSING
    fi

    # Ensure OVS is available (for runtime)
    if ! command -v ovs-vsctl &>/dev/null; then
        log_warn "openvswitch-switch not installed - hostapd-ovs requires it at runtime"
    fi

    log_ok "Dependencies ready"
}

get_source() {
    log_info "Downloading hostapd ${HOSTAPD_VERSION}..."

    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Try primary download location, then mirror
    if ! wget -q "https://w1.fi/releases/hostapd-${HOSTAPD_VERSION}.tar.gz" 2>/dev/null; then
        log_warn "Primary download failed, trying mirror..."
        wget -q "https://mirrors.edge.kernel.org/pub/software/network/hostapd/hostapd-${HOSTAPD_VERSION}.tar.gz" || \
            log_error "Failed to download hostapd-${HOSTAPD_VERSION}"
    fi

    tar xzf "hostapd-${HOSTAPD_VERSION}.tar.gz"
    cd "hostapd-${HOSTAPD_VERSION}"

    log_ok "Source ready"
}

apply_patch() {
    log_info "Applying OVS bridge patch..."

    local TARGET="src/drivers/linux_ioctl.c"

    # Verify we have the expected source structure
    if ! grep -q "^int linux_br_get(" "$TARGET" 2>/dev/null; then
        log_error "linux_br_get not found in linux_ioctl.c - only hostapd 2.10+ supported"
    fi

    # Check if already patched
    if grep -q "linux_br_get_ovs" "$TARGET"; then
        log_warn "Already patched - skipping"
        return 0
    fi

    # Backup original
    cp "$TARGET" "${TARGET}.orig"

    # Add ctype.h include for isalnum() used in input validation
    if ! grep -q "#include <ctype.h>" "$TARGET"; then
        sed -i '/#include <sys\/ioctl.h>/a #include <ctype.h>' "$TARGET"
    fi

    # Find the line number where linux_br_get function starts
    local BR_LINE
    BR_LINE=$(grep -n "^int linux_br_get(" "$TARGET" | cut -d: -f1)
    if [ -z "$BR_LINE" ]; then
        log_error "Cannot find linux_br_get function"
    fi

    log_info "Found linux_br_get at line $BR_LINE"

    # Create OVS helper function
    # This function queries ovs-vsctl to find which OVS bridge owns an interface
    # Security: Input validation prevents command injection
    cat > /tmp/ovs_patch.c << 'EOF'

/* === OVS Bridge Support (HookProbe Patch) ===
 *
 * This function provides OVS bridge lookup as a fallback when the standard
 * sysfs/ioctl method fails. OVS bridges don't appear in sysfs brif directory
 * so we query ovs-vsctl directly.
 *
 * Security: Interface name is validated to prevent command injection.
 * Only alphanumeric characters, hyphens, underscores, and dots are allowed.
 */
static int linux_br_get_ovs(char *brname, const char *ifname)
{
	FILE *fp;
	char cmd[128], line[IFNAMSIZ];
	const char *p;

	if (!ifname || !brname || strlen(ifname) >= IFNAMSIZ)
		return -1;

	/* Validate interface name - prevent command injection */
	for (p = ifname; *p; p++) {
		if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.')
			return -1;
	}

	snprintf(cmd, sizeof(cmd), "ovs-vsctl --timeout=1 port-to-br %s 2>/dev/null", ifname);
	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	if (fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\n")] = '\0';
		if (strlen(line) > 0 && strlen(line) < IFNAMSIZ) {
			strncpy(brname, line, IFNAMSIZ - 1);
			brname[IFNAMSIZ - 1] = '\0';
			pclose(fp);
			return 0;
		}
	}
	pclose(fp);
	return -1;
}

EOF

    # Insert the helper function just before linux_br_get
    head -n $((BR_LINE - 1)) "$TARGET" > /tmp/new.c
    cat /tmp/ovs_patch.c >> /tmp/new.c
    tail -n +$BR_LINE "$TARGET" >> /tmp/new.c
    mv /tmp/new.c "$TARGET"

    # Find return -1 in linux_br_get and add OVS fallback before it
    # We need to re-find the line since we modified the file
    BR_LINE=$(grep -n "^int linux_br_get(" "$TARGET" | cut -d: -f1)

    # Find the FIRST "return -1;" line within linux_br_get function
    # Must use head -1 to get the one in linux_br_get, not linux_master_get
    local RET_LINE
    RET_LINE=$(sed -n "${BR_LINE},$((BR_LINE+20))p" "$TARGET" | grep -n "return -1;" | head -1 | cut -d: -f1)
    if [ -z "$RET_LINE" ]; then
        log_error "Cannot find return -1 in linux_br_get function"
    fi
    RET_LINE=$((BR_LINE + RET_LINE - 1))

    log_info "Adding OVS fallback before line $RET_LINE"

    # Create fallback code that calls our OVS helper before returning -1
    printf '\t/* OVS bridge fallback - query ovs-vsctl when sysfs lookup fails */\n\tif (linux_br_get_ovs(brname, ifname) == 0) {\n\t\treturn 0;\n\t}\n' > /tmp/fallback.c

    # Insert fallback before return -1
    head -n $((RET_LINE - 1)) "$TARGET" > /tmp/final.c
    cat /tmp/fallback.c >> /tmp/final.c
    tail -n +$RET_LINE "$TARGET" >> /tmp/final.c
    mv /tmp/final.c "$TARGET"

    # Cleanup temp files
    rm -f /tmp/fallback.c /tmp/ovs_patch.c

    # Verify patch was applied
    if ! grep -q "linux_br_get_ovs" "$TARGET"; then
        log_error "Patch failed - linux_br_get_ovs not found in patched file"
    fi

    log_ok "Patch applied to linux_ioctl.c"

    # Show diff for verification
    if command -v diff &>/dev/null; then
        log_info "Patch summary:"
        diff -u "${TARGET}.orig" "$TARGET" | head -50 || true
    fi
}

build() {
    log_info "Configuring build..."

    cd "$BUILD_DIR/hostapd-${HOSTAPD_VERSION}/hostapd"
    cp defconfig .config

    # Enable features needed for HookProbe deployment
    cat >> .config << 'CONF'
# Core driver support
CONFIG_DRIVER_NL80211=y
CONFIG_LIBNL32=y

# 802.11 standards
CONFIG_IEEE80211AC=y
CONFIG_IEEE80211N=y
CONFIG_IEEE80211AX=y

# VLAN support for network segmentation
CONFIG_FULL_DYNAMIC_VLAN=y
CONFIG_VLAN_NETLINK=y

# Automatic Channel Selection
CONFIG_ACS=y

# Modern security (WPA3)
CONFIG_SAE=y
CONFIG_OWE=y
CONFIG_IEEE80211W=y

# DPP (Device Provisioning Protocol) for easy onboarding
CONFIG_DPP=y
CONFIG_DPP2=y
CONF

    # WiFi 7 support for hostapd 2.11
    if [ "$HOSTAPD_VERSION" = "2.11" ]; then
        echo "CONFIG_IEEE80211BE=y" >> .config
        log_info "WiFi 7 (802.11be) support enabled"
    fi

    log_info "Compiling (this may take a few minutes)..."
    make -j"$(nproc)" -s

    log_ok "Build complete"
}

do_install() {
    log_info "Installing..."

    cd "$BUILD_DIR/hostapd-${HOSTAPD_VERSION}/hostapd"

    # Install with -ovs suffix to not conflict with system hostapd
    install -m 755 hostapd "${INSTALL_PREFIX}/bin/hostapd-ovs"
    install -m 755 hostapd_cli "${INSTALL_PREFIX}/bin/hostapd_cli-ovs"

    # Save state for tracking
    mkdir -p "$(dirname "$STATE_FILE")"
    cat > "$STATE_FILE" << EOF
HOSTAPD_VERSION=${HOSTAPD_VERSION}
BUILD_DATE=$(date -Iseconds)
BUILDER_VERSION=${VERSION}
INSTALL_PREFIX=${INSTALL_PREFIX}
EOF

    log_ok "Installed: ${INSTALL_PREFIX}/bin/hostapd-ovs"

    # Show version
    echo ""
    "${INSTALL_PREFIX}/bin/hostapd-ovs" -v 2>&1 | head -1
    echo ""
}

cleanup() {
    log_info "Cleaning up build directory..."
    rm -rf "$BUILD_DIR"
}

# ============================================================
# MAIN
# ============================================================

echo ""
echo "============================================"
echo "  hostapd ${HOSTAPD_VERSION} + OVS Bridge Patch"
echo "  HookProbe Federated Security Mesh"
echo "============================================"
echo ""

# Parse arguments
case "${1:-}" in
    --check)
        check_installation
        exit $?
        ;;
    --uninstall)
        if [ "$(id -u)" -ne 0 ]; then
            log_error "Run as root: sudo $0 --uninstall"
        fi
        uninstall
        exit 0
        ;;
    --version)
        echo "hostapd-ovs builder v${VERSION}"
        echo "Default hostapd version: ${HOSTAPD_VERSION}"
        exit 0
        ;;
    -h|--help)
        show_usage
        exit 0
        ;;
    "")
        # Normal build
        ;;
    *)
        log_error "Unknown option: $1 (use --help for usage)"
        ;;
esac

# Validate version
case "$HOSTAPD_VERSION" in
    2.10|2.11) ;;
    *) log_error "Only hostapd 2.10 and 2.11 supported. Set HOSTAPD_VERSION=2.10 or 2.11" ;;
esac

# Root check
if [ "$(id -u)" -ne 0 ]; then
    log_error "Run as root: sudo $0"
fi

# Check if already installed
if check_installation >/dev/null 2>&1; then
    log_warn "hostapd-ovs already installed"
    read -p "Rebuild and reinstall? [y/N]: " confirm
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
        log_info "Skipping - use existing installation"
        exit 0
    fi
fi

# Build and install
check_deps
get_source
apply_patch
build
do_install
cleanup

echo ""
echo "============================================"
echo -e "  ${GREEN}Installation Complete${NC}"
echo "============================================"
echo ""
echo "Binaries installed:"
echo "  hostapd-ovs:     ${INSTALL_PREFIX}/bin/hostapd-ovs"
echo "  hostapd_cli-ovs: ${INSTALL_PREFIX}/bin/hostapd_cli-ovs"
echo ""
echo "Usage in hostapd.conf:"
echo "  # Point bridge= directly to OVS bridge name"
echo "  interface=wlan0"
echo "  bridge=FTS           # OVS bridge name"
echo "  ap_isolate=1         # Recommended for security"
echo ""
echo "Test: sudo hostapd-ovs -dd /path/to/config"
echo ""
