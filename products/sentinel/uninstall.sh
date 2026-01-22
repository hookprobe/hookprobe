#!/bin/bash
#
# HookProbe Sentinel Uninstall Script
# Version: 5.0.0
# License: AGPL-3.0 - see LICENSE file
#
# Removes all Sentinel components:
# - Systemd service (hookprobe-sentinel)
# - Firewall rules (iptables HOOKPROBE chain)
# - Fail2ban configuration
# - Configuration files
# - Data and log directories
# - Uninstall command
#

set -e

# ============================================================
# COLORS
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ============================================================
# PATHS (must match bootstrap.sh)
# ============================================================
INSTALL_DIR="/opt/hookprobe/sentinel"
CONFIG_DIR="/etc/hookprobe"
SECRETS_DIR="/etc/hookprobe/secrets"
DATA_DIR="/var/lib/hookprobe/sentinel"
LOG_DIR="/var/log/hookprobe"
RUN_DIR="/run/hookprobe"

# ============================================================
# LOGGING
# ============================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ============================================================
# PARSE ARGUMENTS
# ============================================================
FORCE_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE_MODE=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# ============================================================
# PREREQUISITES
# ============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo "Usage: sudo $0"
        exit 1
    fi
}

# ============================================================
# STOP SENTINEL SERVICE
# ============================================================
stop_service() {
    log_step "Stopping Sentinel service..."

    if systemctl is-active hookprobe-sentinel &>/dev/null; then
        log_info "Stopping hookprobe-sentinel..."
        systemctl stop hookprobe-sentinel 2>/dev/null || true
    else
        log_info "Service hookprobe-sentinel is not running"
    fi

    log_info "Service stopped"
}

# ============================================================
# DISABLE AND REMOVE SYSTEMD SERVICE
# ============================================================
remove_systemd_service() {
    log_step "Removing systemd service..."

    if systemctl is-enabled hookprobe-sentinel &>/dev/null; then
        log_info "Disabling hookprobe-sentinel..."
        systemctl disable hookprobe-sentinel 2>/dev/null || true
    fi

    if [ -f "/etc/systemd/system/hookprobe-sentinel.service" ]; then
        log_info "Removing hookprobe-sentinel.service..."
        rm -f "/etc/systemd/system/hookprobe-sentinel.service"
    fi

    # Reload systemd
    systemctl daemon-reload

    log_info "Systemd service removed"
}

# ============================================================
# REMOVE FIREWALL RULES
# ============================================================
remove_firewall_rules() {
    log_step "Removing firewall rules..."

    if ! command -v iptables &>/dev/null; then
        log_warn "iptables not found, skipping firewall cleanup"
        return 0
    fi

    # Remove HOOKPROBE chain from INPUT
    if iptables -C INPUT -j HOOKPROBE 2>/dev/null; then
        log_info "Removing HOOKPROBE chain from INPUT..."
        iptables -D INPUT -j HOOKPROBE 2>/dev/null || true
    fi

    # Flush and delete HOOKPROBE chain
    if iptables -L HOOKPROBE &>/dev/null 2>&1; then
        log_info "Flushing HOOKPROBE chain..."
        iptables -F HOOKPROBE 2>/dev/null || true
        log_info "Deleting HOOKPROBE chain..."
        iptables -X HOOKPROBE 2>/dev/null || true
    fi

    # Save iptables rules
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    elif [ -f /etc/redhat-release ]; then
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
    fi

    log_info "Firewall rules removed"
}

# ============================================================
# REMOVE FAIL2BAN CONFIGURATION
# ============================================================
remove_fail2ban() {
    log_step "Removing fail2ban configuration..."

    if ! command -v fail2ban-client &>/dev/null; then
        log_info "fail2ban not installed, skipping"
        return 0
    fi

    # Remove jail configuration
    if [ -f "/etc/fail2ban/jail.d/hookprobe-sentinel.conf" ]; then
        log_info "Removing fail2ban jail configuration..."
        rm -f "/etc/fail2ban/jail.d/hookprobe-sentinel.conf"
    fi

    # Remove filter configuration
    if [ -f "/etc/fail2ban/filter.d/hookprobe-sentinel.conf" ]; then
        log_info "Removing fail2ban filter configuration..."
        rm -f "/etc/fail2ban/filter.d/hookprobe-sentinel.conf"
    fi

    # Restart fail2ban to apply changes
    if systemctl is-active fail2ban &>/dev/null; then
        log_info "Restarting fail2ban..."
        systemctl restart fail2ban 2>/dev/null || true
    fi

    log_info "fail2ban configuration removed"
}

# ============================================================
# REMOVE CONFIGURATION FILES
# ============================================================
remove_configuration() {
    log_step "Removing configuration files..."

    # Remove Sentinel configuration
    if [ -f "$CONFIG_DIR/sentinel.env" ]; then
        log_info "Removing sentinel.env..."
        rm -f "$CONFIG_DIR/sentinel.env"
    fi

    # Remove secrets
    if [ -f "$SECRETS_DIR/mesh-token" ]; then
        log_info "Removing mesh token..."
        rm -f "$SECRETS_DIR/mesh-token"
    fi

    # Clean up empty directories
    if [ -d "$SECRETS_DIR" ] && [ -z "$(ls -A $SECRETS_DIR 2>/dev/null)" ]; then
        log_info "Removing empty secrets directory..."
        rmdir "$SECRETS_DIR" 2>/dev/null || true
    fi

    if [ -d "$CONFIG_DIR" ] && [ -z "$(ls -A $CONFIG_DIR 2>/dev/null)" ]; then
        log_info "Removing empty config directory..."
        rmdir "$CONFIG_DIR" 2>/dev/null || true
    fi

    log_info "Configuration files removed"
}

# ============================================================
# REMOVE INSTALLATION DIRECTORY
# ============================================================
remove_installation() {
    log_step "Removing Sentinel installation..."

    if [ -d "$INSTALL_DIR" ]; then
        log_info "Removing $INSTALL_DIR..."
        rm -rf "$INSTALL_DIR"
    fi

    # Remove data directory
    if [ -d "$DATA_DIR" ]; then
        log_info "Removing $DATA_DIR..."
        rm -rf "$DATA_DIR"
    fi

    # Clean up parent directories if empty
    if [ -d "/var/lib/hookprobe" ] && [ -z "$(ls -A /var/lib/hookprobe 2>/dev/null)" ]; then
        log_info "Removing empty /var/lib/hookprobe..."
        rmdir "/var/lib/hookprobe" 2>/dev/null || true
    fi

    if [ -d "/opt/hookprobe" ] && [ -z "$(ls -A /opt/hookprobe 2>/dev/null)" ]; then
        log_info "Removing empty /opt/hookprobe..."
        rmdir "/opt/hookprobe" 2>/dev/null || true
    fi

    # Remove run directory
    if [ -d "$RUN_DIR" ]; then
        rm -rf "$RUN_DIR" 2>/dev/null || true
    fi

    log_info "Installation removed"
}

# ============================================================
# REMOVE UNINSTALL COMMAND
# ============================================================
remove_uninstall_command() {
    log_step "Removing uninstall command..."

    if [ -f "/usr/local/bin/sentinel-uninstall" ]; then
        log_info "Removing sentinel-uninstall command..."
        rm -f "/usr/local/bin/sentinel-uninstall"
    fi

    log_info "Uninstall command removed"
}

# ============================================================
# OPTIONAL: PRESERVE LOGS
# ============================================================
handle_logs() {
    log_step "Handling log files..."

    if [ -d "$LOG_DIR" ]; then
        local remove_logs="no"
        if [ "$FORCE_MODE" = false ]; then
            echo ""
            echo -e "${YELLOW}Log files are preserved at:${NC} $LOG_DIR"
            echo ""
            read -p "Remove log files too? (yes/no) [no]: " remove_logs
        else
            log_info "Force mode - preserving log files"
        fi
        if [ "$remove_logs" = "yes" ]; then
            log_info "Removing log directory..."
            rm -rf "$LOG_DIR/sentinel.log"*
            # Only remove LOG_DIR if it's now empty
            if [ -z "$(ls -A $LOG_DIR 2>/dev/null)" ]; then
                rm -rf "$LOG_DIR"
            fi
        else
            log_info "Log files preserved"
        fi
    fi
}

# ============================================================
# MAIN
# ============================================================
main() {
    echo ""
    echo -e "${BOLD}${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${RED}║              HookProbe Sentinel Uninstaller                ║${NC}"
    echo -e "${BOLD}${RED}║                   \"The Watchful Eye\"                       ║${NC}"
    echo -e "${BOLD}${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    check_root

    echo -e "${YELLOW}This will remove all Sentinel components including:${NC}"
    echo -e "  - Sentinel systemd service"
    echo -e "  - Firewall rules (iptables HOOKPROBE chain)"
    echo -e "  - Fail2ban configuration"
    echo -e "  - Configuration files ($CONFIG_DIR)"
    echo -e "  - Installation directory ($INSTALL_DIR)"
    echo -e "  - Data directory ($DATA_DIR)"
    echo -e "  - sentinel-uninstall command"
    echo ""

    if [ "$FORCE_MODE" = false ]; then
        read -p "Are you sure you want to continue? (yes/no) [no]: " confirm
        if [ "$confirm" != "yes" ]; then
            log_info "Uninstall cancelled"
            exit 0
        fi
    else
        log_info "Force mode enabled - skipping confirmation"
    fi

    echo ""

    # Remove components in order
    stop_service
    remove_systemd_service
    remove_firewall_rules
    remove_fail2ban
    remove_configuration
    remove_installation
    remove_uninstall_command
    handle_logs

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Sentinel Uninstall Complete!                     ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Removed:${NC}"
    echo -e "  • hookprobe-sentinel service"
    echo -e "  • Firewall rules (HOOKPROBE chain)"
    echo -e "  • Fail2ban integration"
    echo -e "  • Configuration: $CONFIG_DIR/sentinel.env"
    echo -e "  • Installation: $INSTALL_DIR"
    echo -e "  • Data: $DATA_DIR"
    echo ""
    echo -e "  ${DIM}To reinstall Sentinel:${NC}"
    echo -e "  ${DIM}curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/products/sentinel/bootstrap.sh | sudo bash${NC}"
    echo ""
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
