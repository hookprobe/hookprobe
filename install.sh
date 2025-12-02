#!/bin/bash
#
# install.sh - HookProbe Installation Menu
# Version: 5.0
# License: MIT
#
# Comprehensive hierarchical installation menu
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
NC='\033[0m' # No Color

# ============================================================
# SYSTEM DETECTION FUNCTIONS
# ============================================================

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
        OS_VERSION="$VERSION_ID"
        OS_PRETTY="$PRETTY_NAME"
    elif [ -f /etc/redhat-release ]; then
        OS_NAME="rhel"
        OS_VERSION=$(cat /etc/redhat-release | sed 's/.*release \([0-9.]*\).*/\1/')
        OS_PRETTY=$(cat /etc/redhat-release)
    else
        OS_NAME="unknown"
        OS_VERSION="unknown"
        OS_PRETTY="Unknown Linux"
    fi
    echo "$OS_PRETTY"
}

detect_architecture() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64) echo "x86_64 (AMD64)" ;;
        aarch64) echo "ARM64 (aarch64)" ;;
        armv7l) echo "ARM32 (armv7l)" ;;
        *) echo "$arch" ;;
    esac
}

detect_ram() {
    local ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_gb=$((ram_kb / 1024 / 1024))
    echo "${ram_gb}GB"
}

get_container_status() {
    local container_count=0
    local running_count=0

    if command -v podman &> /dev/null; then
        container_count=$(podman ps -a --format "{{.Names}}" 2>/dev/null | wc -l)
        running_count=$(podman ps --format "{{.Names}}" 2>/dev/null | wc -l)

        if [ "$container_count" -eq 0 ]; then
            echo "No containers"
        else
            echo "$running_count/$container_count running"
        fi
    else
        echo "Podman not installed"
    fi
}

# ============================================================
# BANNER DISPLAY
# ============================================================

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ╦ ╦╔═╗╔═╗╦╔═╔═╗╦═╗╔═╗╔╗ ╔═╗
    ╠═╣║ ║║ ║╠╩╗╠═╝╠╦╝║ ║╠╩╗║╣
    ╩ ╩╚═╝╚═╝╩ ╩╩  ╩╚═╚═╝╚═╝╚═╝

    Cyber Resilience at the Edge
    Version 5.0 - GPL-FREE Edition
EOF
    echo -e "${NC}"
}

# ============================================================
# MAIN MENU
# ============================================================

show_main_menu() {
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  HOOKPROBE INSTALL / CONFIGURATION MENU                   ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # System Information
    echo -e "${CYAN}System Information:${NC}"
    echo -e "  OS:           $(detect_os)"
    echo -e "  Architecture: $(detect_architecture)"
    echo -e "  RAM:          $(detect_ram)"
    echo -e "  Containers:   $(get_container_status)"
    echo ""

    echo -e "${YELLOW}┌─ Main Menu ────────────────────────────────────────────┐${NC}"
    echo -e "│                                                        │"
    echo -e "│  ${YELLOW}1${NC}) Pre-Install / System Check                       │"
    echo -e "│  ${YELLOW}2${NC}) Select Deployment Mode                           │"
    echo -e "│  ${YELLOW}3${NC}) Install Core Infrastructure (PODs 001-007)       │"
    echo -e "│  ${YELLOW}4${NC}) Basic Configuration                              │"
    echo -e "│  ${YELLOW}5${NC}) Optional Extensions / Add-ons                    │"
    echo -e "│  ${YELLOW}6${NC}) MSSP / Multi-Tenant Specific                     │"
    echo -e "│  ${YELLOW}7${NC}) Post-Install: Dashboards & Interfaces            │"
    echo -e "│  ${YELLOW}8${NC}) Advanced / Optional Configurations               │"
    echo -e "│  ${YELLOW}9${NC}) Uninstall / Cleanup                              │"
    echo -e "│                                                        │"
    echo -e "│  ${YELLOW}q${NC}) Quit                                              │"
    echo -e "│                                                        │"
    echo -e "${YELLOW}└────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ============================================================
# SUBMENU 1: PRE-INSTALL / SYSTEM CHECK
# ============================================================

show_preinstall_menu() {
    clear
    show_banner
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  1. PRE-INSTALL / SYSTEM CHECK                            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) Hardware / Platform Check"
    echo -e "  ${YELLOW}2${NC}) OS / Kernel Compatibility Check"
    echo -e "  ${YELLOW}3${NC}) Network Topology / Requirements"
    echo -e "  ${YELLOW}4${NC}) Backup / Data-Storage Plan"
    echo -e "  ${YELLOW}5${NC}) Run Complete Pre-Install Check ${GREEN}[Recommended]${NC}"
    echo ""
    echo -e "  ${YELLOW}b${NC}) Back to Main Menu"
    echo ""
}

handle_preinstall() {
    while true; do
        show_preinstall_menu
        read -p "Select option: " choice
        echo ""

        case $choice in
            1)
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${BLUE}Hardware / Platform Check${NC}"
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                echo "CPU Architecture: $(uname -m)"
                echo "CPU Cores: $(nproc)"
                echo "RAM: $(detect_ram)"
                echo "Disk Space: $(df -h / | awk 'NR==2 {print $4}') available"
                echo ""
                echo "Network Interfaces:"
                ip -brief addr show | grep -v "^lo"
                echo ""
                echo "Checking for XDP/eBPF support..."
                if [ -d /sys/fs/bpf ]; then
                    echo "  ✓ BPF filesystem mounted"
                else
                    echo "  ⚠ BPF filesystem not mounted"
                fi
                ;;
            2)
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${BLUE}OS / Kernel Compatibility Check${NC}"
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                echo "OS: $(detect_os)"
                echo "Kernel: $(uname -r)"
                echo "Kernel Version: $(uname -v)"
                echo ""
                echo "Checking requirements..."

                # Check kernel version
                kernel_ver=$(uname -r | cut -d. -f1)
                if [ "$kernel_ver" -ge 5 ]; then
                    echo "  ✓ Kernel version $kernel_ver (5.x+ required)"
                else
                    echo "  ✗ Kernel version $kernel_ver (5.x+ required)"
                fi

                # Check for Podman
                if command -v podman &> /dev/null; then
                    echo "  ✓ Podman installed: $(podman --version)"
                else
                    echo "  ⚠ Podman not installed"
                fi

                # Check for OVS
                if command -v ovs-vsctl &> /dev/null; then
                    echo "  ✓ Open vSwitch installed"
                else
                    echo "  ⚠ Open vSwitch not installed"
                fi
                ;;
            3)
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${BLUE}Network Topology / Requirements${NC}"
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                echo "Available Network Interfaces:"
                echo ""
                ip -brief addr show | grep -v "^lo" | while read line; do
                    iface=$(echo $line | awk '{print $1}')
                    state=$(echo $line | awk '{print $2}')
                    ip=$(echo $line | awk '{print $3}')
                    echo "  • $iface: $ip ($state)"

                    # Check link speed if available
                    if [ -f "/sys/class/net/$iface/speed" ]; then
                        speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo "unknown")
                        if [ "$speed" != "unknown" ] && [ "$speed" != "-1" ]; then
                            echo "    Link Speed: ${speed}Mbps"
                        fi
                    fi
                done
                ;;
            4)
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${BLUE}Backup / Data-Storage Plan${NC}"
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                echo "Storage Requirements:"
                echo "  • Database (PostgreSQL): ~50GB minimum"
                echo "  • Logs & Analytics: ~100GB minimum"
                echo "  • Container Images: ~10GB"
                echo "  • Total Recommended: 200GB+"
                echo ""
                echo "Current Disk Usage:"
                df -h /
                ;;
            5)
                echo -e "${GREEN}Running complete pre-install check...${NC}"
                echo ""
                # Run all checks
                bash "$SCRIPT_DIR/install/common/pre-install-check.sh" 2>/dev/null || echo "Pre-install check script not found"
                ;;
            b|B)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ============================================================
# SUBMENU 2: SELECT DEPLOYMENT MODE
# ============================================================

show_deployment_menu() {
    clear
    show_banner
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  2. SELECT DEPLOYMENT MODE                                ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) Edge Deployment ${CYAN}[Single-Tenant]${NC}"
    echo -e "     └─ For: Home users, small business, branch office, standalone"
    echo -e "     └─ Platforms: N100/Core/AMD (x86_64), Pi/Jetson/Radxa (ARM)"
    echo ""
    echo -e "  ${YELLOW}2${NC}) MSSP Cloud Backend ${CYAN}[Multi-Tenant]${NC}"
    echo -e "     └─ For: MSSPs, enterprise multi-site, SOC operations"
    echo -e "     └─ Platforms: Datacenter servers, cloud instances"
    echo ""
    echo -e "  ${YELLOW}3${NC}) Lightweight Testing/Development ${CYAN}[Testing Only]${NC}"
    echo -e "     └─ For: Testing, development, CI/CD, Raspberry Pi 4"
    echo -e "     └─ Includes: PODs 001-003, 005 only (excludes monitoring & AI)"
    echo -e "     └─ RAM Usage: ~2.5GB (suitable for 4GB systems)"
    echo -e "     ${RED}└─ NOT FOR PRODUCTION USE${NC}"
    echo ""
    echo -e "  ${YELLOW}b${NC}) Back to Main Menu"
    echo ""
}

handle_deployment() {
    while true; do
        show_deployment_menu
        read -p "Select deployment mode: " choice
        echo ""

        case $choice in
            1)
                run_installer "$SCRIPT_DIR/install/edge/setup.sh" "Edge Deployment" "edge"
                return
                ;;
            2)
                run_installer "$SCRIPT_DIR/install/cloud/setup.sh" "Cloud Backend Deployment" "cloud"
                return
                ;;
            3)
                run_installer "$SCRIPT_DIR/install/testing/lightweight-setup.sh" "Lightweight Testing/Development" "testing"
                return
                ;;
            b|B)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                echo ""
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# ============================================================
# SUBMENU 3: INSTALL CORE INFRASTRUCTURE
# ============================================================

show_core_infrastructure_menu() {
    clear
    show_banner
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  3. INSTALL CORE INFRASTRUCTURE (PODs 001-007)            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${GREEN}Note: Core PODs are installed automatically with deployment mode${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) POD-001: Web / DMZ / Management"
    echo -e "  ${YELLOW}2${NC}) POD-002: IAM / Auth / SSO / RBAC"
    echo -e "  ${YELLOW}3${NC}) POD-003: Persistent Database (PostgreSQL)"
    echo -e "  ${YELLOW}4${NC}) POD-004: Cache / Redis / Valkey"
    echo -e "  ${YELLOW}5${NC}) POD-005: Monitoring & Analytics"
    echo -e "  ${YELLOW}6${NC}) POD-006: Security Detection (Zeek, Snort, Suricata)"
    echo -e "  ${YELLOW}7${NC}) POD-007: AI Response / Mitigation Engine"
    echo ""
    echo -e "  ${YELLOW}a${NC}) Install All Core PODs ${GREEN}[Recommended]${NC}"
    echo -e "  ${YELLOW}b${NC}) Back to Main Menu"
    echo ""
}

handle_core_infrastructure() {
    while true; do
        show_core_infrastructure_menu
        read -p "Select option: " choice
        echo ""

        case $choice in
            a|A)
                echo -e "${GREEN}Installing all core PODs...${NC}"
                echo "This is typically done via deployment mode (option 2)"
                echo "Would you like to run edge or cloud deployment?"
                ;;
            1|2|3|4|5|6|7)
                echo -e "${YELLOW}Individual POD installation not yet implemented${NC}"
                echo "Core PODs are installed as part of the deployment process"
                echo "Please use option 2 (Select Deployment Mode)"
                ;;
            b|B)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ============================================================
# SUBMENU 4: BASIC CONFIGURATION
# ============================================================

show_configuration_menu() {
    clear
    show_banner
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  4. BASIC CONFIGURATION                                   ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) Network Configuration (VXLAN, OpenFlow, Subnets)"
    echo -e "  ${YELLOW}2${NC}) Firewall / WAF Configuration"
    echo -e "  ${YELLOW}3${NC}) Security Policy / Zero-Trust Setup"
    echo -e "  ${YELLOW}4${NC}) Database & Storage Settings"
    echo -e "  ${YELLOW}5${NC}) Monitoring & Logging Settings"
    echo -e "  ${YELLOW}6${NC}) Run Configuration Wizard ${GREEN}[Interactive]${NC}"
    echo ""
    echo -e "  ${YELLOW}b${NC}) Back to Main Menu"
    echo ""
}

handle_configuration() {
    while true; do
        show_configuration_menu
        read -p "Select option: " choice
        echo ""

        case $choice in
            1|2|3|4|5)
                echo -e "${YELLOW}Individual configuration sections not yet implemented${NC}"
                echo "Please use option 6 (Configuration Wizard)"
                ;;
            6)
                echo "Select deployment type for configuration:"
                echo "  1) Edge Deployment"
                echo "  2) Cloud Backend"
                echo "  3) n8n Addon"
                read -p "Select: " config_choice

                case $config_choice in
                    1) run_config_wizard "edge" "$SCRIPT_DIR/install/edge/config.sh" ;;
                    2) run_config_wizard "cloud" "$SCRIPT_DIR/install/cloud/config.sh" ;;
                    3) run_config_wizard "n8n" "$SCRIPT_DIR/install/addons/n8n/config.sh" ;;
                    *) echo -e "${RED}Invalid option${NC}" ;;
                esac
                ;;
            b|B)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ============================================================
# SUBMENU 5: OPTIONAL EXTENSIONS / ADD-ONS
# ============================================================

show_extensions_menu() {
    clear
    show_banner
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  5. OPTIONAL EXTENSIONS / ADD-ONS                         ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) POD-008: Automation / Workflow (n8n) ${GREEN}[Automated]${NC}"
    echo -e "  ${YELLOW}2${NC}) POD-009: Email System & Notification ${CYAN}[Manual Guide]${NC}"
    echo -e "  ${YELLOW}3${NC}) Remote Access / Cloud Tunnel (Cloudflare) ${CYAN}[Manual Guide]${NC}"
    echo -e "  ${YELLOW}4${NC}) GDPR / Privacy & Compliance Settings ${CYAN}[Configuration]${NC}"
    echo -e "  ${YELLOW}5${NC}) LTE/5G Connectivity ${CYAN}[Manual Guide]${NC}"
    echo -e "  ${YELLOW}6${NC}) ClickHouse Analytics ${CYAN}[Manual Guide]${NC}"
    echo ""
    echo -e "  ${YELLOW}b${NC}) Back to Main Menu"
    echo ""
}

handle_extensions() {
    while true; do
        show_extensions_menu
        read -p "Select option: " choice
        echo ""

        case $choice in
            1)
                run_installer "$SCRIPT_DIR/install/addons/n8n/setup.sh" "n8n Workflow Automation" "n8n"
                ;;
            2)
                show_email_guide
                ;;
            3)
                show_cloudflare_guide
                ;;
            4)
                show_gdpr_config
                ;;
            5)
                show_lte_guide
                ;;
            6)
                show_clickhouse_guide
                ;;
            b|B)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# Extension guide functions
show_email_guide() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}POD-009 Email System Deployment (Manual)${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Enterprise email with DMZ architecture"
    echo ""
    echo "📖 README: infrastructure/pod-009-email/README.md"
    echo "📖 Deployment: infrastructure/pod-009-email/DEPLOYMENT.md"
    echo "📖 Podman Guide: infrastructure/pod-009-email/PODMAN.md"
    echo ""
    echo "Features:"
    echo "  • Dual-firewall DMZ architecture"
    echo "  • Postfix SMTP relay + mail server"
    echo "  • DKIM/SPF/DMARC authentication"
    echo "  • Suricata IDS monitoring"
    echo ""
    if [ -f "$SCRIPT_DIR/infrastructure/pod-009-email/DEPLOYMENT.md" ]; then
        read -p "Open deployment guide? (yes/no) [no]: " open_docs
        if [ "$open_docs" = "yes" ]; then
            less "$SCRIPT_DIR/infrastructure/pod-009-email/DEPLOYMENT.md"
        fi
    fi
}

show_cloudflare_guide() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Cloudflare Tunnel Setup${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "See POD-009 Email documentation for Cloudflare Tunnel setup"
}

show_gdpr_config() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}GDPR / Privacy & Compliance Settings${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "GDPR compliance configuration"
    echo "See: install/edge/gdpr-config.sh for settings"
}

show_lte_guide() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}LTE/5G Connectivity Setup (Manual)${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "📖 Documentation: install/addons/lte/README.md"
    echo ""
    echo "Covers:"
    echo "  • Hardware requirements (modems, SIM cards)"
    echo "  • Driver installation"
    echo "  • Network configuration"
    echo "  • Failover setup"
    echo ""
    if [ -f "$SCRIPT_DIR/install/addons/lte/README.md" ]; then
        read -p "Open documentation? (yes/no) [no]: " open_docs
        if [ "$open_docs" = "yes" ]; then
            less "$SCRIPT_DIR/install/addons/lte/README.md"
        fi
    fi
}

show_clickhouse_guide() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}ClickHouse Analytics Setup (Manual)${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "📖 Quick Start: docs/guides/clickhouse-quick-start.md"
    echo "📖 Integration: docs/guides/clickhouse-integration.md"
    echo ""
    echo "Covers:"
    echo "  • ClickHouse installation with Podman"
    echo "  • Database schema setup"
    echo "  • Qsecbit integration"
    echo "  • Security analytics queries"
    echo ""
    if [ -f "$SCRIPT_DIR/docs/guides/clickhouse-quick-start.md" ]; then
        read -p "Open quick start guide? (yes/no) [no]: " open_docs
        if [ "$open_docs" = "yes" ]; then
            less "$SCRIPT_DIR/docs/guides/clickhouse-quick-start.md"
        fi
    fi
}

# ============================================================
# SUBMENU 6: MSSP / MULTI-TENANT
# ============================================================

show_mssp_menu() {
    clear
    show_banner
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  6. MSSP / MULTI-TENANT SPECIFIC                          ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) Cluster Setup (Storage + Compute)"
    echo -e "  ${YELLOW}2${NC}) Tenant Onboarding / Management"
    echo -e "  ${YELLOW}3${NC}) Ingest Streams Configuration (TLS from edges)"
    echo -e "  ${YELLOW}4${NC}) Long-term Data Retention & Analytics"
    echo ""
    echo -e "  ${YELLOW}b${NC}) Back to Main Menu"
    echo ""
}

handle_mssp() {
    while true; do
        show_mssp_menu
        read -p "Select option: " choice
        echo ""

        case $choice in
            1|2|3|4)
                echo -e "${YELLOW}MSSP features are available via Cloud Backend deployment${NC}"
                echo "Please use option 2 (Select Deployment Mode) → Cloud Backend"
                ;;
            b|B)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ============================================================
# SUBMENU 7: POST-INSTALL DASHBOARDS
# ============================================================

show_dashboards_menu() {
    clear
    show_banner
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  7. POST-INSTALL: DASHBOARDS & INTERFACES                 ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) Admin Dashboard (CMS, Blog Management)"
    echo -e "  ${YELLOW}2${NC}) Security / SIEM Dashboard (Threat Hunting, SOAR)"
    echo -e "  ${YELLOW}3${NC}) Alerting / Notification Settings"
    echo -e "  ${YELLOW}4${NC}) Maintenance Tools (Update, Backup, Logs)"
    echo ""
    echo -e "  ${YELLOW}b${NC}) Back to Main Menu"
    echo ""
}

handle_dashboards() {
    while true; do
        show_dashboards_menu
        read -p "Select option: " choice
        echo ""

        case $choice in
            1)
                echo "Admin Dashboard access:"
                echo "  URL: http://localhost:3000/admin"
                echo "  Default credentials are set during deployment"
                ;;
            2)
                echo "Security Dashboard access:"
                echo "  URL: http://localhost:3000/dashboard"
                echo "  Grafana: http://localhost:3000"
                ;;
            3|4)
                echo -e "${YELLOW}Feature under development${NC}"
                ;;
            b|B)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ============================================================
# SUBMENU 8: ADVANCED CONFIGURATIONS
# ============================================================

show_advanced_menu() {
    clear
    show_banner
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  8. ADVANCED / OPTIONAL CONFIGURATIONS                    ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) Hardware Acceleration / NIC Tuning (XDP/eBPF)"
    echo -e "  ${YELLOW}2${NC}) Custom Rules / Signatures (IDS/IPS, WAF)"
    echo -e "  ${YELLOW}3${NC}) Integration with External Tools (SIEM, SOC)"
    echo -e "  ${YELLOW}4${NC}) Disaster Recovery & Hardening"
    echo ""
    echo -e "  ${YELLOW}b${NC}) Back to Main Menu"
    echo ""
}

handle_advanced() {
    while true; do
        show_advanced_menu
        read -p "Select option: " choice
        echo ""

        case $choice in
            1|2|3|4)
                echo -e "${YELLOW}Advanced configurations are documented in:${NC}"
                echo "  • docs/guides/"
                echo "  • install/edge/config.sh"
                ;;
            b|B)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ============================================================
# SUBMENU 9: UNINSTALL / CLEANUP
# ============================================================

show_uninstall_menu() {
    clear
    show_banner
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  9. UNINSTALL / CLEANUP                                   ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) Stop All PODs / Services"
    echo -e "  ${YELLOW}2${NC}) Remove Containers / Services / Configs"
    echo -e "  ${YELLOW}3${NC}) Uninstall Edge Deployment"
    echo -e "  ${YELLOW}4${NC}) Uninstall Cloud Backend"
    echo -e "  ${YELLOW}5${NC}) Uninstall n8n Only"
    echo -e "  ${YELLOW}6${NC}) Wipe Data / Logs / DB ${RED}[DESTRUCTIVE]${NC}"
    echo ""
    echo -e "  ${YELLOW}b${NC}) Back to Main Menu"
    echo ""
}

handle_uninstall() {
    while true; do
        show_uninstall_menu
        read -p "Select option: " choice
        echo ""

        case $choice in
            1)
                echo "Stopping all containers..."
                podman stop $(podman ps -q) 2>/dev/null || echo "No running containers"
                ;;
            2)
                echo "Removing all containers..."
                podman rm $(podman ps -aq) 2>/dev/null || echo "No containers to remove"
                ;;
            3)
                if [ -f "$SCRIPT_DIR/install/edge/uninstall.sh" ]; then
                    bash "$SCRIPT_DIR/install/edge/uninstall.sh"
                else
                    echo "Edge uninstall script not found"
                fi
                ;;
            4)
                if [ -f "$SCRIPT_DIR/install/cloud/uninstall.sh" ]; then
                    bash "$SCRIPT_DIR/install/cloud/uninstall.sh"
                else
                    echo "Cloud uninstall script not found"
                fi
                ;;
            5)
                if [ -f "$SCRIPT_DIR/install/addons/n8n/uninstall.sh" ]; then
                    bash "$SCRIPT_DIR/install/addons/n8n/uninstall.sh"
                else
                    echo "n8n uninstall script not found"
                fi
                ;;
            6)
                echo -e "${RED}⚠ WARNING: This will permanently delete all data!${NC}"
                read -p "Type 'DELETE' to confirm: " confirm
                if [ "$confirm" = "DELETE" ]; then
                    echo "Wiping data..."
                    podman volume rm $(podman volume ls -q) 2>/dev/null || echo "No volumes to remove"
                    echo "Data wiped"
                else
                    echo "Cancelled"
                fi
                ;;
            b|B)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

run_config_wizard() {
    local deployment_type="$1"
    local config_file="$2"

    if [ -f "$SCRIPT_DIR/install/common/config-wizard.sh" ]; then
        source "$SCRIPT_DIR/install/common/config-wizard.sh"
        if run_configuration_wizard "$deployment_type" "$config_file"; then
            echo -e "${GREEN}✓ Configuration completed${NC}"
            return 0
        else
            echo -e "${RED}✗ Configuration failed or cancelled${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}⚠ Configuration wizard not found${NC}"
        echo "Manually edit: $config_file"
        return 1
    fi
}

run_installer() {
    local script_path="$1"
    local description="$2"
    local deployment_type="$3"

    if [ ! -f "$script_path" ]; then
        echo -e "${RED}ERROR: Installer not found: $script_path${NC}"
        return 1
    fi

    local config_dir=$(dirname "$script_path")
    local config_file=""

    # Determine correct config file based on deployment type
    case "$deployment_type" in
        testing)
            config_file="$config_dir/lightweight-config.sh"
            ;;
        edge|cloud|n8n)
            config_file="$config_dir/config.sh"
            ;;
        *)
            # Fallback: try lightweight-config.sh first, then config.sh
            if [ -f "$config_dir/lightweight-config.sh" ]; then
                config_file="$config_dir/lightweight-config.sh"
            else
                config_file="$config_dir/config.sh"
            fi
            ;;
    esac

    # Check if configuration exists
    if [ ! -f "$config_file" ] || [ ! -s "$config_file" ]; then
        echo -e "${YELLOW}⚠ No configuration found${NC}"
        echo ""
        read -p "Run configuration wizard first? (yes/no) [yes]: " run_wizard
        run_wizard=${run_wizard:-yes}

        if [ "$run_wizard" = "yes" ]; then
            if ! run_config_wizard "$deployment_type" "$config_file"; then
                echo -e "${RED}Cannot proceed without configuration${NC}"
                return 1
            fi
            echo ""
        else
            echo -e "${RED}Cannot proceed without configuration${NC}"
            return 1
        fi
    fi

    echo -e "${GREEN}Starting: $description${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if bash "$script_path"; then
        echo -e "${GREEN}✓ $description completed successfully${NC}"
    else
        echo -e "${RED}✗ $description failed${NC}"
        return 1
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

# ============================================================
# COMMAND-LINE ARGUMENT PARSING
# ============================================================

show_usage() {
    echo -e "${CYAN}HookProbe Installer${NC}"
    echo ""
    echo "Usage:"
    echo "  $0                    # Interactive menu mode"
    echo "  $0 --role <ROLE>      # Automated installation"
    echo ""
    echo "Roles:"
    echo "  edge                  # Edge node deployment (home/SMB/branch office)"
    echo "  validator             # Cloud validator deployment (MSSP backend)"
    echo "  cloud                 # Alias for 'validator'"
    echo ""
    echo "Examples:"
    echo "  sudo ./install.sh --role edge        # Install edge node"
    echo "  sudo ./install.sh --role validator   # Install cloud validator"
    echo ""
    echo "After installation:"
    echo "  # Initialize Neuro protocol"
    echo "  python3 -m neuro.tools.init_weights --node-id <YOUR-NODE-ID>"
    echo ""
    echo "  # Start services"
    echo "  sudo systemctl start hookprobe-edge   # (edge nodes)"
    echo "  sudo systemctl start hookprobe-neuro  # (all nodes with Neuro)"
    echo ""
}

automated_install() {
    local role="$1"

    clear
    show_banner

    case "$role" in
        edge)
            echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║  AUTOMATED EDGE NODE INSTALLATION                         ║${NC}"
            echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
            echo ""
            echo -e "${CYAN}Installing HookProbe Edge Node...${NC}"
            echo -e "${CYAN}Target: Home/SMB/Branch Office deployment${NC}"
            echo ""

            if run_installer "$SCRIPT_DIR/install/edge/setup.sh" "Edge Deployment" "edge"; then
                echo ""
                echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${GREEN}║  ✓ EDGE NODE INSTALLATION COMPLETE                        ║${NC}"
                echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}Next Steps:${NC}"
                echo ""
                echo -e "1. Initialize Neuro Protocol:"
                echo -e "   ${CYAN}python3 -m neuro.tools.init_weights --node-id edge-001${NC}"
                echo ""
                echo -e "2. Start HookProbe services:"
                echo -e "   ${CYAN}sudo systemctl start hookprobe-edge${NC}"
                echo -e "   ${CYAN}sudo systemctl start hookprobe-neuro${NC}"
                echo ""
                echo -e "3. Verify installation:"
                echo -e "   ${CYAN}sudo systemctl status hookprobe-edge${NC}"
                echo ""
                echo -e "4. Access dashboard:"
                echo -e "   ${CYAN}https://$(hostname -I | awk '{print $1}'):8443${NC}"
                echo ""
                exit 0
            else
                echo -e "${RED}✗ Edge installation failed${NC}"
                exit 1
            fi
            ;;

        validator|cloud)
            echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║  AUTOMATED CLOUD VALIDATOR INSTALLATION                   ║${NC}"
            echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
            echo ""
            echo -e "${CYAN}Installing HookProbe Cloud Validator...${NC}"
            echo -e "${CYAN}Target: MSSP backend / Multi-tenant SOC${NC}"
            echo ""

            if run_installer "$SCRIPT_DIR/install/cloud/setup.sh" "Cloud Validator Deployment" "cloud"; then
                echo ""
                echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${GREEN}║  ✓ CLOUD VALIDATOR INSTALLATION COMPLETE                  ║${NC}"
                echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}Next Steps:${NC}"
                echo ""
                echo -e "1. Configure validator settings:"
                echo -e "   ${CYAN}nano /etc/hookprobe/validator.conf${NC}"
                echo ""
                echo -e "2. Start validator services:"
                echo -e "   ${CYAN}sudo systemctl start hookprobe-validator${NC}"
                echo -e "   ${CYAN}sudo systemctl start hookprobe-neuro-validator${NC}"
                echo ""
                echo -e "3. Verify Neuro deterministic replay:"
                echo -e "   ${CYAN}curl http://localhost:8080/neuro/status${NC}"
                echo ""
                echo -e "4. Configure edge nodes to connect:"
                echo -e "   ${CYAN}Set VALIDATOR_URL in edge config${NC}"
                echo ""
                exit 0
            else
                echo -e "${RED}✗ Cloud validator installation failed${NC}"
                exit 1
            fi
            ;;

        *)
            echo -e "${RED}ERROR: Invalid role '$role'${NC}"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# ============================================================
# MAIN LOOP
# ============================================================

main() {
    check_root

    # Parse command-line arguments
    if [ $# -gt 0 ]; then
        case "$1" in
            --role)
                if [ -z "$2" ]; then
                    echo -e "${RED}ERROR: --role requires an argument${NC}"
                    echo ""
                    show_usage
                    exit 1
                fi
                automated_install "$2"
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                echo -e "${RED}ERROR: Unknown option '$1'${NC}"
                echo ""
                show_usage
                exit 1
                ;;
        esac
    fi

    # Interactive menu mode (no arguments provided)
    while true; do
        clear
        show_banner
        show_main_menu

        read -p "Select option: " choice
        echo ""

        case $choice in
            1) handle_preinstall ;;
            2) handle_deployment ;;
            3) handle_core_infrastructure ;;
            4) handle_configuration ;;
            5) handle_extensions ;;
            6) handle_mssp ;;
            7) handle_dashboards ;;
            8) handle_advanced ;;
            9) handle_uninstall ;;
            q|Q)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

main "$@"
