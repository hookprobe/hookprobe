#!/bin/bash
#
# hookprobe-bootstrap.sh - HookProbe Unified Bootstrap Installer
# Version: 5.0
# License: MIT
#
# This script installs HookProbe as systemd services with automatic provisioning,
# monitoring, and update capabilities.
#

set -e
set -u

# ============================================================================
# CONSTANTS
# ============================================================================

readonly SCRIPT_VERSION="5.0"
readonly BASE_DIR="/opt/hookprobe"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly LOG_DIR="/var/log/hookprobe"
readonly CONFIG_DIR="/etc/hookprobe"

readonly SERVICES=(
    "hookprobe-provision.service"
    "hookprobe-agent.service"
)

readonly TIMER="hookprobe-update.timer"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_fatal() {
    echo -e "${RED}[FATAL]${NC} $*"
    exit 1
}

# ============================================================================
# ENVIRONMENT DETECTION
# ============================================================================

detect_os() {
    log_info "Detecting operating system..."

    if [ ! -f /etc/os-release ]; then
        log_fatal "Cannot detect OS: /etc/os-release not found"
    fi

    source /etc/os-release

    case "$ID" in
        rhel|fedora|centos|rocky|almalinux)
            OS_FAMILY="rhel"
            PKG_MGR="dnf"
            ;;
        debian|ubuntu)
            OS_FAMILY="debian"
            PKG_MGR="apt"
            ;;
        *)
            log_fatal "Unsupported OS: $ID (only RHEL/Debian-based distros supported)"
            ;;
    esac

    log_success "Detected OS: $PRETTY_NAME ($OS_FAMILY)"
}

detect_architecture() {
    log_info "Detecting architecture..."

    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64|amd64)
            ARCH_TYPE="x86_64"
            ;;
        aarch64|arm64)
            ARCH_TYPE="arm64"
            ;;
        *)
            log_fatal "Unsupported architecture: $ARCH (only x86_64 and ARM64 supported)"
            ;;
    esac

    log_success "Detected architecture: $ARCH_TYPE"
}

detect_virtualization() {
    log_info "Detecting virtualization..."

    if command -v systemd-detect-virt >/dev/null 2>&1; then
        VIRT_TYPE=$(systemd-detect-virt || echo "none")
    else
        VIRT_TYPE="unknown"
    fi

    if [ "$VIRT_TYPE" = "docker" ] || [ "$VIRT_TYPE" = "lxc" ]; then
        log_warning "Running in container ($VIRT_TYPE) - networking may be limited"
    elif [ "$VIRT_TYPE" != "none" ]; then
        log_info "Running on virtual machine: $VIRT_TYPE"
    else
        log_success "Running on bare metal"
    fi
}

check_kernel_version() {
    log_info "Checking kernel version..."

    KERNEL_VERSION=$(uname -r)
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

    # XDP requires kernel 4.8+, but 5.4+ recommended
    if [ "$KERNEL_MAJOR" -lt 5 ]; then
        if [ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -ge 8 ]; then
            log_warning "Kernel $KERNEL_VERSION supported but 5.4+ recommended for XDP"
        else
            log_warning "Kernel $KERNEL_VERSION may not support XDP (4.8+ required)"
        fi
    else
        log_success "Kernel version: $KERNEL_VERSION (XDP supported)"
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_fatal "This script must be run as root"
    fi
}

# ============================================================================
# DEPENDENCY INSTALLATION
# ============================================================================

install_dependencies() {
    log_info "Installing dependencies..."

    local deps_common=(
        git
        curl
        wget
        python3
        python3-pip
        podman
        openvswitch
        nftables
    )

    local deps_rhel=(
        kernel-devel
        clang
        llvm
        bpftool
        libbpf-devel
    )

    local deps_debian=(
        linux-headers-generic
        clang
        llvm
        bpftool
        libbpf-dev
    )

    if [ "$OS_FAMILY" = "rhel" ]; then
        log_info "Installing RHEL-based dependencies..."
        dnf install -y "${deps_common[@]}" "${deps_rhel[@]}" || log_warning "Some packages may have failed to install"
    else
        log_info "Installing Debian-based dependencies..."
        apt update
        apt install -y "${deps_common[@]}" "${deps_debian[@]}" || log_warning "Some packages may have failed to install"
    fi

    # Python dependencies
    log_info "Installing Python dependencies..."
    pip3 install --upgrade pip
    pip3 install -r "$SCRIPT_DIR/../../../requirements.txt" 2>/dev/null || log_warning "requirements.txt not found or failed"

    log_success "Dependencies installed"
}

# ============================================================================
# DIRECTORY STRUCTURE SETUP
# ============================================================================

setup_directories() {
    log_info "Setting up directory structure..."

    mkdir -p "$BASE_DIR"/{scripts,agent,xdp,config,data}
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"

    # Set permissions
    chmod 755 "$BASE_DIR"
    chmod 755 "$LOG_DIR"
    chmod 700 "$CONFIG_DIR"  # Config contains secrets

    log_success "Directory structure created"
}

# ============================================================================
# FILE INSTALLATION
# ============================================================================

install_files() {
    log_info "Installing HookProbe files..."

    local repo_root="$SCRIPT_DIR/../../.."

    # Copy scripts
    cp -r "$repo_root/Scripts/autonomous/install/"* "$BASE_DIR/scripts/"
    cp -r "$repo_root/Scripts/autonomous/qsecbit/"* "$BASE_DIR/agent/"

    # Copy systemd units
    cp "$SCRIPT_DIR/systemd/"*.service "$SYSTEMD_DIR/" 2>/dev/null || log_warning "systemd units not found in expected location"
    cp "$SCRIPT_DIR/systemd/"*.timer "$SYSTEMD_DIR/" 2>/dev/null || log_warning "systemd timers not found"

    # Make scripts executable
    chmod +x "$BASE_DIR"/scripts/*.sh
    chmod +x "$BASE_DIR"/agent/*.py

    # Copy configuration
    if [ -f "$repo_root/Scripts/autonomous/install/network-config.sh" ]; then
        cp "$repo_root/Scripts/autonomous/install/network-config.sh" "$CONFIG_DIR/"
        chmod 600 "$CONFIG_DIR/network-config.sh"  # Contains secrets
    fi

    log_success "Files installed to $BASE_DIR"
}

# ============================================================================
# SYSTEMD SERVICE INSTALLATION
# ============================================================================

install_systemd_services() {
    log_info "Installing systemd services..."

    # Reload systemd
    systemctl daemon-reload

    # Enable services
    for service in "${SERVICES[@]}"; do
        if [ -f "$SYSTEMD_DIR/$service" ]; then
            systemctl enable "$service"
            log_success "Enabled $service"
        else
            log_error "Service file not found: $service"
        fi
    done

    # Enable timer (optional)
    if [ -f "$SYSTEMD_DIR/$TIMER" ]; then
        log_info "Auto-update timer available. Enable with: systemctl enable $TIMER"
    fi

    log_success "Systemd services installed"
}

# ============================================================================
# INITIAL PROVISIONING
# ============================================================================

run_initial_provision() {
    log_info "Running initial provisioning..."

    # Start provision service
    systemctl start hookprobe-provision.service

    # Wait for completion
    local timeout=300
    local elapsed=0

    while systemctl is-active hookprobe-provision.service >/dev/null 2>&1; do
        if [ $elapsed -ge $timeout ]; then
            log_error "Provisioning timeout after ${timeout}s"
            return 1
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        echo -n "."
    done
    echo

    # Check result
    if systemctl is-failed hookprobe-provision.service >/dev/null 2>&1; then
        log_error "Provisioning failed. Check logs: journalctl -u hookprobe-provision.service"
        return 1
    fi

    log_success "Initial provisioning completed"
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_installation() {
    log_info "Verifying installation..."

    local errors=0

    # Check directories
    for dir in "$BASE_DIR" "$LOG_DIR" "$CONFIG_DIR"; do
        if [ ! -d "$dir" ]; then
            log_error "Directory missing: $dir"
            ((errors++))
        fi
    done

    # Check services
    for service in "${SERVICES[@]}"; do
        if ! systemctl is-enabled "$service" >/dev/null 2>&1; then
            log_error "Service not enabled: $service"
            ((errors++))
        fi
    done

    # Check agent
    if [ ! -f "$BASE_DIR/agent/qsecbit.py" ]; then
        log_error "Qsecbit agent not found"
        ((errors++))
    fi

    # Check XDP capability
    if command -v ip >/dev/null 2>&1; then
        local primary_iface=$(ip route | grep default | awk '{print $5}' | head -n1)
        if [ -n "$primary_iface" ]; then
            log_info "Primary interface: $primary_iface"
        fi
    fi

    if [ $errors -eq 0 ]; then
        log_success "Installation verification passed"
        return 0
    else
        log_error "Installation verification failed with $errors error(s)"
        return 1
    fi
}

# ============================================================================
# INSTALLATION STATUS
# ============================================================================

show_status() {
    echo
    echo "======================================"
    echo "  HookProbe Installation Status"
    echo "======================================"
    echo

    echo "Services:"
    for service in "${SERVICES[@]}"; do
        local status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
        local enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")
        printf "  %-35s %s (%s)\n" "$service" "$status" "$enabled"
    done

    echo
    echo "Timer:"
    local timer_status=$(systemctl is-active "$TIMER" 2>/dev/null || echo "inactive")
    local timer_enabled=$(systemctl is-enabled "$TIMER" 2>/dev/null || echo "disabled")
    printf "  %-35s %s (%s)\n" "$TIMER" "$timer_status" "$timer_enabled"

    echo
    echo "Directories:"
    echo "  Base:   $BASE_DIR"
    echo "  Logs:   $LOG_DIR"
    echo "  Config: $CONFIG_DIR"

    echo
    echo "Management Commands:"
    echo "  Start agent:    systemctl start hookprobe-agent.service"
    echo "  Stop agent:     systemctl stop hookprobe-agent.service"
    echo "  View logs:      journalctl -u hookprobe-agent.service -f"
    echo "  Re-provision:   systemctl start hookprobe-provision.service"
    echo "  Enable updates: systemctl enable --now $TIMER"
    echo
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================

main_install() {
    echo
    echo "======================================"
    echo "  HookProbe Bootstrap Installer v$SCRIPT_VERSION"
    echo "======================================"
    echo

    check_root

    # Get script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Environment detection
    detect_os
    detect_architecture
    detect_virtualization
    check_kernel_version

    echo
    read -p "Continue with installation? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi

    # Installation steps
    install_dependencies
    setup_directories
    install_files
    install_systemd_services
    run_initial_provision

    # Verification
    if verify_installation; then
        echo
        log_success "HookProbe installation completed successfully!"
        show_status

        echo
        log_info "Next steps:"
        echo "  1. Review configuration: $CONFIG_DIR/network-config.sh"
        echo "  2. Start the agent: systemctl start hookprobe-agent.service"
        echo "  3. Enable auto-updates: systemctl enable --now $TIMER"
        echo "  4. View logs: journalctl -u hookprobe-agent.service -f"
        echo
    else
        log_error "Installation completed with errors. Please review logs."
        exit 1
    fi
}

# ============================================================================
# ENTRY POINT
# ============================================================================

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main_install
fi
