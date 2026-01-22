#!/bin/bash
#
# hookprobe-bootstrap.sh - HookProbe Unified Bootstrap Installer
# Version: 5.0
# License: AGPL-3.0 - see LICENSE file
#
# This script installs HookProbe as systemd services with automatic provisioning,
# monitoring, and update capabilities.
#
# Supported device types:
#   - Guardian: Raspberry Pi 4/5 portable SDN gateway (WiFi AP + VLAN)
#   - Fortress: On-premise network security appliance (full XDP/eBPF)
#   - Sentinel: Cloud validator node (consensus layer)
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
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m' # No Color

# Device type (set during detection/selection)
DEVICE_TYPE=""
IS_RASPBERRY_PI=false
RPI_MODEL=""

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
        debian|ubuntu|raspbian)
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
        armv7l|armhf)
            ARCH_TYPE="armv7"
            ;;
        *)
            log_fatal "Unsupported architecture: $ARCH"
            ;;
    esac

    log_success "Detected architecture: $ARCH_TYPE"
}

detect_raspberry_pi() {
    log_info "Checking for Raspberry Pi..."

    IS_RASPBERRY_PI=false
    RPI_MODEL=""

    # Check /proc/cpuinfo for Raspberry Pi
    if [ -f /proc/cpuinfo ]; then
        if grep -q "Raspberry Pi 5" /proc/cpuinfo 2>/dev/null; then
            IS_RASPBERRY_PI=true
            RPI_MODEL="Raspberry Pi 5"
        elif grep -q "Raspberry Pi 4" /proc/cpuinfo 2>/dev/null; then
            IS_RASPBERRY_PI=true
            RPI_MODEL="Raspberry Pi 4"
        elif grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
            IS_RASPBERRY_PI=true
            RPI_MODEL="Raspberry Pi"
        fi
    fi

    # Also check /proc/device-tree/model
    if [ -f /proc/device-tree/model ]; then
        local model=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')
        if [[ "$model" == *"Raspberry Pi"* ]]; then
            IS_RASPBERRY_PI=true
            RPI_MODEL="$model"
        fi
    fi

    if [ "$IS_RASPBERRY_PI" = true ]; then
        log_success "Detected: $RPI_MODEL"
    else
        log_info "Not a Raspberry Pi"
    fi
}

detect_wifi_capability() {
    log_info "Detecting WiFi capability..."

    WIFI_INTERFACES=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | tr '\n' ' ')
    WIFI_COUNT=$(echo $WIFI_INTERFACES | wc -w)

    if [ "$WIFI_COUNT" -gt 0 ]; then
        # Check AP mode support
        WIFI_AP_SUPPORT=false
        if iw list 2>/dev/null | grep -A 10 "Supported interface modes" | grep -q "AP"; then
            WIFI_AP_SUPPORT=true
        fi
        log_success "WiFi interfaces ($WIFI_COUNT): $WIFI_INTERFACES"
        if [ "$WIFI_AP_SUPPORT" = true ]; then
            log_success "WiFi AP mode: supported"
        else
            log_warning "WiFi AP mode: not supported"
        fi
    else
        log_info "No WiFi interfaces detected"
        WIFI_AP_SUPPORT=false
    fi
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
# DEVICE TYPE SELECTION
# ============================================================================

show_device_menu() {
    echo ""
    echo -e "${BOLD}${WHITE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${WHITE}║           HookProbe - Select Device Type                   ║${NC}"
    echo -e "${BOLD}${WHITE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Guardian option (recommended for Raspberry Pi with WiFi)
    if [ "$IS_RASPBERRY_PI" = true ] && [ "$WIFI_AP_SUPPORT" = true ]; then
        echo -e "  ${BOLD}1)${NC} ${GREEN}Guardian${NC} ${YELLOW}← Recommended for $RPI_MODEL${NC}"
    else
        echo -e "  ${BOLD}1)${NC} ${GREEN}Guardian${NC} - Portable SDN Gateway"
    fi
    echo -e "     ${DIM}• WiFi Access Point with VLAN segmentation${NC}"
    echo -e "     ${DIM}• MAC-based device categorization via RADIUS${NC}"
    echo -e "     ${DIM}• OpenFlow SDN with IoT isolation${NC}"
    echo -e "     ${DIM}• Perfect for: Travel, home IoT, small office${NC}"
    echo ""

    # Fortress option
    echo -e "  ${BOLD}2)${NC} ${CYAN}Fortress${NC} - On-Premise Security Appliance"
    echo -e "     ${DIM}• Full XDP/eBPF packet processing${NC}"
    echo -e "     ${DIM}• OVS bridge with neural protection${NC}"
    echo -e "     ${DIM}• Qsecbit AI threat detection${NC}"
    echo -e "     ${DIM}• Perfect for: Datacenter, enterprise, homelab${NC}"
    echo ""

    # Sentinel option
    echo -e "  ${BOLD}3)${NC} ${BLUE}Sentinel${NC} - Cloud Validator Node"
    echo -e "     ${DIM}• Participates in threat consensus${NC}"
    echo -e "     ${DIM}• Neural resonance protocol${NC}"
    echo -e "     ${DIM}• Minimal footprint${NC}"
    echo -e "     ${DIM}• Perfect for: VPS, cloud instances${NC}"
    echo ""
}

select_device_type() {
    local default_choice="2"  # Default to Fortress

    # Auto-recommend Guardian for Raspberry Pi with WiFi AP support
    if [ "$IS_RASPBERRY_PI" = true ] && [ "$WIFI_AP_SUPPORT" = true ]; then
        default_choice="1"
    fi

    # Check if device type was passed via environment
    if [ -n "${HOOKPROBE_DEVICE_TYPE:-}" ]; then
        case "${HOOKPROBE_DEVICE_TYPE,,}" in
            guardian) DEVICE_TYPE="guardian"; return ;;
            fortress) DEVICE_TYPE="fortress"; return ;;
            sentinel) DEVICE_TYPE="sentinel"; return ;;
        esac
    fi

    show_device_menu

    while true; do
        read -p "Select device type [$default_choice]: " choice
        choice=${choice:-$default_choice}

        case $choice in
            1)
                DEVICE_TYPE="guardian"
                if [ "$WIFI_AP_SUPPORT" != true ]; then
                    echo ""
                    echo -e "${YELLOW}Warning: No WiFi AP support detected.${NC}"
                    echo -e "${YELLOW}Guardian requires WiFi AP capability for hotspot mode.${NC}"
                    read -p "Continue anyway? (yes/no) [no]: " continue_guardian
                    if [ "$continue_guardian" != "yes" ]; then
                        continue
                    fi
                fi
                break
                ;;
            2)
                DEVICE_TYPE="fortress"
                break
                ;;
            3)
                DEVICE_TYPE="sentinel"
                break
                ;;
            *)
                echo -e "${RED}Invalid selection. Please choose 1, 2, or 3.${NC}"
                ;;
        esac
    done

    log_success "Selected device type: $DEVICE_TYPE"
}

# ============================================================================
# GUARDIAN INSTALLATION
# ============================================================================

install_guardian() {
    log_info "Installing HookProbe Guardian..."

    local guardian_setup="$SCRIPT_DIR/../guardian/scripts/setup.sh"

    if [ -f "$guardian_setup" ]; then
        # Make sure it's executable
        chmod +x "$guardian_setup"

        # Run Guardian setup
        log_info "Launching Guardian setup..."
        bash "$guardian_setup"
    else
        log_error "Guardian setup script not found: $guardian_setup"
        log_info "Expected location: products/guardian/scripts/setup.sh"
        exit 1
    fi
}

# ============================================================================
# FORTRESS INSTALLATION (Standard Edge)
# ============================================================================

install_fortress() {
    log_info "Installing HookProbe Fortress..."

    # Standard edge installation
    install_dependencies
    setup_directories
    install_files
    install_systemd_services
    run_initial_provision

    # Verification
    if verify_installation; then
        echo
        log_success "HookProbe Fortress installation completed successfully!"
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
# SENTINEL INSTALLATION
# ============================================================================

install_sentinel() {
    log_info "Installing HookProbe Sentinel..."

    # Minimal installation for cloud validators
    setup_directories

    # Install minimal dependencies
    if [ "$OS_FAMILY" = "rhel" ]; then
        dnf install -y python3 python3-pip curl || log_warning "Some packages failed"
    else
        apt update
        apt install -y python3 python3-pip curl || log_warning "Some packages failed"
    fi

    # Install Python agent only
    pip3 install --upgrade pip
    pip3 install requests pynacl cryptography || log_warning "Some Python packages failed"

    # Create minimal systemd service for sentinel
    cat > "$SYSTEMD_DIR/hookprobe-sentinel.service" << 'EOF'
[Unit]
Description=HookProbe Sentinel - Cloud Validator Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/hookprobe/agent
ExecStart=/usr/bin/python3 /opt/hookprobe/agent/sentinel.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hookprobe-sentinel.service

    echo
    log_success "HookProbe Sentinel installation completed!"
    echo
    log_info "Next steps:"
    echo "  1. Configure mesh connection: /etc/hookprobe/sentinel.conf"
    echo "  2. Start sentinel: systemctl start hookprobe-sentinel.service"
    echo "  3. View logs: journalctl -u hookprobe-sentinel.service -f"
    echo
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

    local repo_root="$SCRIPT_DIR/../.."

    # Copy scripts (from deploy/edge/)
    cp -r "$repo_root/deploy/edge/"*.sh "$BASE_DIR/scripts/" 2>/dev/null || true
    cp -r "$repo_root/core/qsecbit/"* "$BASE_DIR/agent/" 2>/dev/null || true

    # Copy systemd units
    cp "$SCRIPT_DIR/systemd/"*.service "$SYSTEMD_DIR/" 2>/dev/null || log_warning "systemd units not found in expected location"
    cp "$SCRIPT_DIR/systemd/"*.timer "$SYSTEMD_DIR/" 2>/dev/null || log_warning "systemd timers not found"

    # Make scripts executable
    chmod +x "$BASE_DIR"/scripts/*.sh 2>/dev/null || true
    chmod +x "$BASE_DIR"/agent/*.py 2>/dev/null || true

    # Copy configuration (if exists)
    if [ -f "$repo_root/deploy/edge/network-config.sh" ]; then
        cp "$repo_root/deploy/edge/network-config.sh" "$CONFIG_DIR/"
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
            log_warning "Service file not found: $service"
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

    # Check if provision service exists
    if [ ! -f "$SYSTEMD_DIR/hookprobe-provision.service" ]; then
        log_warning "Provision service not found, skipping"
        return 0
    fi

    # Start provision service
    systemctl start hookprobe-provision.service || {
        log_warning "Provision service failed to start"
        return 0
    }

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
            log_warning "Service not enabled: $service"
            # Don't count as error if service file doesn't exist
        fi
    done

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

    echo "Device Type: $DEVICE_TYPE"
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
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          HookProbe Unified Installer v$SCRIPT_VERSION                 ║${NC}"
    echo -e "${GREEN}║       Democratizing Cybersecurity for Everyone             ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo

    check_root

    # Get script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Environment detection
    detect_os
    detect_architecture
    detect_raspberry_pi
    detect_wifi_capability
    detect_virtualization
    check_kernel_version

    # Device type selection
    select_device_type

    echo
    echo -e "${BOLD}Selected: $DEVICE_TYPE${NC}"
    echo
    read -p "Continue with installation? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi

    # Route to appropriate installer
    case $DEVICE_TYPE in
        guardian)
            install_guardian
            ;;
        fortress)
            install_fortress
            ;;
        sentinel)
            install_sentinel
            ;;
        *)
            log_fatal "Unknown device type: $DEVICE_TYPE"
            ;;
    esac
}

# ============================================================================
# ENTRY POINT
# ============================================================================

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main_install
fi
