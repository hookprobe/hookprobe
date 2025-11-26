#!/bin/bash
#
# install.sh - HookProbe Installation Menu
# Version: 5.0
# License: MIT
#
# Main entry point for HookProbe deployment
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================
# SYSTEM DETECTION FUNCTIONS
# ============================================================

detect_os() {
    # Detect OS distribution and version
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

get_container_status() {
    # Check if containers are running
    local container_count=0
    local running_count=0

    if command -v podman &> /dev/null; then
        container_count=$(podman ps -a --format "{{.Names}}" 2>/dev/null | wc -l)
        running_count=$(podman ps --format "{{.Names}}" 2>/dev/null | wc -l)

        if [ "$container_count" -eq 0 ]; then
            echo "${YELLOW}No containers deployed${NC}"
        else
            echo "${GREEN}$running_count${NC}/${CYAN}$container_count${NC} running"
        fi
    else
        echo "${RED}Podman not installed${NC}"
    fi
}

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ╦ ╦╔═╗╔═╗╦╔═╔═╗╦═╗╔═╗╔╗ ╔═╗
    ╠═╣║ ║║ ║╠╩╗╠═╝╠╦╝║ ║╠╩╗║╣
    ╩ ╩╚═╝╚═╝╩ ╩╩  ╩╚═╚═╝╚═╝╚═╝

    Cyber Resilience at the Edge
    Version 5.0
EOF
    echo -e "${NC}"
}

show_menu() {
    echo -e "${GREEN}HookProbe Installer${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # System Information
    echo -e "${CYAN}System Information:${NC}"
    echo -e "  OS: $(detect_os)"
    echo -e "  Containers: $(get_container_status)"
    echo ""

    echo "Main Deployments:"
    echo -e "  ${YELLOW}1${NC}) Edge Deployment (x86_64: N100/Core/AMD | ARM: Pi/Jetson/Radxa)"
    echo -e "  ${YELLOW}2${NC}) Cloud Backend (MSSP Multi-Tenant)"
    echo ""
    echo "Configuration:"
    echo -e "  ${YELLOW}c${NC}) Run Configuration Wizard"
    echo ""
    echo "Optional Add-ons (can be installed separately anytime):"
    echo -e "  ${YELLOW}3${NC}) Install n8n Workflow Automation (POD 008) ${GREEN}[Automated]${NC}"
    echo -e "  ${YELLOW}4${NC}) LTE/5G Connectivity Setup ${CYAN}[Manual Guide]${NC}"
    echo -e "  ${YELLOW}5${NC}) ClickHouse Analytics Setup ${CYAN}[Manual Guide]${NC}"
    echo ""
    echo "Maintenance:"
    echo -e "  ${YELLOW}6${NC}) Uninstall HookProbe"
    echo -e "  ${YELLOW}7${NC}) Update Containers"
    echo ""
    echo -e "  ${YELLOW}q${NC}) Quit"
    echo ""
}

run_config_wizard() {
    local deployment_type="$1"
    local config_file="$2"

    # Source the configuration wizard
    source "$SCRIPT_DIR/install/common/config-wizard.sh"

    if run_configuration_wizard "$deployment_type" "$config_file"; then
        echo -e "${GREEN}✓ Configuration completed${NC}"
        return 0
    else
        echo -e "${RED}✗ Configuration failed or cancelled${NC}"
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

    # Determine config file path based on deployment type
    local config_dir=$(dirname "$script_path")
    local config_file="$config_dir/config.sh"

    # Check if configuration exists
    if [ ! -f "$config_file" ] || [ ! -s "$config_file" ]; then
        echo -e "${YELLOW}⚠ No configuration found${NC}"
        echo ""
        if prompt_user "Run configuration wizard first?" "y"; then
            if ! run_config_wizard "$deployment_type" "$config_file"; then
                echo -e "${RED}Cannot proceed without configuration${NC}"
                return 1
            fi
            echo ""
        else
            echo -e "${RED}Cannot proceed without configuration${NC}"
            echo "Please run the configuration wizard first (option 'c')"
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

prompt_user() {
    local prompt="$1"
    local default="$2"

    if [ "$default" = "y" ]; then
        read -p "$(echo -e ${YELLOW}${prompt}${NC} [${GREEN}Y${NC}/n]: )" answer
        answer=${answer:-y}
    else
        read -p "$(echo -e ${YELLOW}${prompt}${NC} [y/${GREEN}N${NC}]: )" answer
        answer=${answer:-n}
    fi

    [[ "$answer" =~ ^[Yy] ]]
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

main() {
    check_root

    while true; do
        clear
        show_banner
        show_menu

        read -p "Select option: " choice
        echo ""

        case $choice in
            1)
                run_installer "$SCRIPT_DIR/install/edge/setup.sh" "Edge Deployment" "edge"
                ;;
            2)
                run_installer "$SCRIPT_DIR/install/cloud/setup.sh" "Cloud Backend Deployment" "cloud"
                ;;
            c|C)
                echo ""
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
            3)
                run_installer "$SCRIPT_DIR/install/addons/n8n/setup.sh" "n8n Workflow Automation" "n8n"
                ;;
            4)
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${BLUE}LTE/5G Connectivity Setup (Manual)${NC}"
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                echo "This is a manual setup process for adding LTE/5G connectivity."
                echo ""
                echo "📖 Documentation: install/addons/lte/README.md"
                echo ""
                echo "The guide covers:"
                echo "  • Hardware requirements (modems, SIM cards)"
                echo "  • Driver installation"
                echo "  • Network configuration"
                echo "  • Failover setup"
                echo ""
                if [ -f "$SCRIPT_DIR/install/addons/lte/README.md" ]; then
                    read -p "Open documentation now? (yes/no) [no]: " open_lte_docs
                    if [ "$open_lte_docs" = "yes" ]; then
                        less "$SCRIPT_DIR/install/addons/lte/README.md"
                    fi
                fi
                ;;
            5)
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${BLUE}ClickHouse Analytics Setup (Manual)${NC}"
                echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                echo "This is a manual setup process for ClickHouse analytics."
                echo ""
                echo "📖 Quick Start: docs/guides/clickhouse-quick-start.md"
                echo "📖 Integration Guide: docs/guides/clickhouse-integration.md"
                echo ""
                echo "The guides cover:"
                echo "  • ClickHouse installation with Podman"
                echo "  • Database schema setup"
                echo "  • Qsecbit integration"
                echo "  • Security analytics queries"
                echo "  • Performance optimization"
                echo ""
                if [ -f "$SCRIPT_DIR/docs/guides/clickhouse-quick-start.md" ]; then
                    read -p "Open quick start guide now? (yes/no) [no]: " open_ch_docs
                    if [ "$open_ch_docs" = "yes" ]; then
                        less "$SCRIPT_DIR/docs/guides/clickhouse-quick-start.md"
                    fi
                fi
                ;;
            6)
                echo -e "${YELLOW}Uninstall Options:${NC}"
                echo "1) Uninstall Edge Deployment"
                echo "2) Uninstall Cloud Backend"
                echo "3) Uninstall n8n Only"
                read -p "Select: " uninstall_choice

                case $uninstall_choice in
                    1) bash "$SCRIPT_DIR/install/edge/uninstall.sh" ;;
                    2) bash "$SCRIPT_DIR/install/cloud/uninstall.sh" ;;
                    3) bash "$SCRIPT_DIR/install/addons/n8n/uninstall.sh" ;;
                    *) echo -e "${RED}Invalid option${NC}" ;;
                esac
                ;;
            7)
                bash "$SCRIPT_DIR/install/edge/update.sh"
                ;;
            q|Q)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

main
