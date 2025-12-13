#!/bin/bash
#
# uninstall.sh - HookProbe Uninstallation Menu
# Version: 5.1
# License: AGPL-3.0 - see LICENSE file
#
# Supports uninstallation of all HookProbe tiers:
# - Sentinel (Lightweight Validator)
# - Guardian (Travel Companion)
# - Fortress (Edge Router)
# - Nexus (ML/AI Compute)
# - MSSP (Cloud Platform)
# - Edge Deployment (PODs 001-007)
# - Cloud Backend (Doris, Kafka, etc.)
# - n8n Automation (POD 008)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root${NC}"
        exit 1
    fi
}

show_menu() {
    echo ""
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║              HookProbe Uninstaller v5.1                    ║${NC}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Available Product Tiers:${NC}"
    echo -e "  ${BOLD}1${NC}) Uninstall Sentinel     (Lightweight Validator)"
    echo -e "       ${DIM}Removes: Service, firewall rules, health endpoint${NC}"
    echo -e "  ${BOLD}2${NC}) Uninstall Guardian     (Travel Companion)"
    echo -e "       ${DIM}Removes: Containers, WiFi AP, IDS/IPS, WAF, dnsXai, Web UI${NC}"
    echo ""
    echo -e "${YELLOW}Coming Soon (Not Yet Installable):${NC}"
    echo -e "  ${DIM}─) Fortress              (Edge Router) [COMING SOON]${NC}"
    echo -e "  ${DIM}─) Nexus                 (ML/AI Compute) [COMING SOON]${NC}"
    echo -e "  ${DIM}─) MSSP                  (Cloud Platform) [COMING SOON]${NC}"
    echo ""
    echo -e "${YELLOW}Infrastructure:${NC}"
    echo -e "  ${BOLD}3${NC}) Uninstall Edge Deployment (PODs 001-007)"
    echo -e "  ${BOLD}4${NC}) Uninstall Cloud Backend"
    echo -e "  ${BOLD}5${NC}) Uninstall n8n Only (POD 008)"
    echo ""
    echo -e "${RED}Complete Removal:${NC}"
    echo -e "  ${BOLD}9${NC}) Uninstall EVERYTHING"
    echo ""
    echo "  q) Cancel"
    echo ""
}

uninstall_sentinel() {
    if [ -f "$SCRIPT_DIR/products/sentinel/uninstall.sh" ]; then
        echo -e "${YELLOW}Uninstalling Sentinel...${NC}"
        bash "$SCRIPT_DIR/products/sentinel/uninstall.sh"
    else
        echo -e "${RED}Sentinel uninstall script not found${NC}"
        return 1
    fi
}

uninstall_guardian() {
    if [ -f "$SCRIPT_DIR/products/guardian/scripts/uninstall.sh" ]; then
        echo -e "${YELLOW}Uninstalling Guardian...${NC}"
        bash "$SCRIPT_DIR/products/guardian/scripts/uninstall.sh"
    else
        echo -e "${RED}Guardian uninstall script not found${NC}"
        return 1
    fi
}

uninstall_fortress() {
    if [ -f "$SCRIPT_DIR/products/fortress/uninstall.sh" ]; then
        echo -e "${YELLOW}Uninstalling Fortress...${NC}"
        bash "$SCRIPT_DIR/products/fortress/uninstall.sh"
    else
        echo -e "${RED}Fortress uninstall script not found${NC}"
        return 1
    fi
}

uninstall_nexus() {
    if [ -f "$SCRIPT_DIR/products/nexus/uninstall.sh" ]; then
        echo -e "${YELLOW}Uninstalling Nexus...${NC}"
        bash "$SCRIPT_DIR/products/nexus/uninstall.sh"
    else
        echo -e "${RED}Nexus uninstall script not found${NC}"
        return 1
    fi
}

uninstall_mssp() {
    if [ -f "$SCRIPT_DIR/products/mssp/uninstall.sh" ]; then
        echo -e "${YELLOW}Uninstalling MSSP...${NC}"
        bash "$SCRIPT_DIR/products/mssp/uninstall.sh"
    else
        echo -e "${RED}MSSP uninstall script not found${NC}"
        return 1
    fi
}

uninstall_edge() {
    if [ -f "$SCRIPT_DIR/deploy/edge/uninstall.sh" ]; then
        echo -e "${YELLOW}Uninstalling Edge Deployment...${NC}"
        bash "$SCRIPT_DIR/deploy/edge/uninstall.sh"
    else
        echo -e "${RED}Edge uninstall script not found${NC}"
        return 1
    fi
}

uninstall_cloud() {
    if [ -f "$SCRIPT_DIR/deploy/cloud/uninstall.sh" ]; then
        echo -e "${YELLOW}Uninstalling Cloud Backend...${NC}"
        bash "$SCRIPT_DIR/deploy/cloud/uninstall.sh"
    else
        echo -e "${RED}Cloud uninstall script not found${NC}"
        return 1
    fi
}

uninstall_n8n() {
    if [ -f "$SCRIPT_DIR/deploy/addons/n8n/uninstall.sh" ]; then
        echo -e "${YELLOW}Uninstalling n8n...${NC}"
        bash "$SCRIPT_DIR/deploy/addons/n8n/uninstall.sh"
    else
        echo -e "${RED}n8n uninstall script not found${NC}"
        return 1
    fi
}

uninstall_everything() {
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                       WARNING                              ║${NC}"
    echo -e "${RED}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║  This will REMOVE ALL HookProbe components:                ║${NC}"
    echo -e "${RED}║  • All product tiers (Sentinel, Guardian, Fortress, Nexus) ║${NC}"
    echo -e "${RED}║  • MSSP Cloud Platform                                     ║${NC}"
    echo -e "${RED}║  • Edge Deployment (PODs 001-007)                          ║${NC}"
    echo -e "${RED}║  • Cloud Backend                                           ║${NC}"
    echo -e "${RED}║  • n8n Automation (POD 008)                                ║${NC}"
    echo -e "${RED}║  • All data, containers, and configurations                ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    read -p "Are you sure? (type 'DELETE-ALL'): " confirm
    if [ "$confirm" != "DELETE-ALL" ]; then
        echo "Cancelled."
        return 0
    fi

    echo ""
    echo -e "${YELLOW}Starting complete uninstallation...${NC}"
    echo ""

    # Uninstall all product tiers (ignore errors - component may not be installed)
    bash "$SCRIPT_DIR/products/sentinel/uninstall.sh" 2>/dev/null || true
    bash "$SCRIPT_DIR/products/guardian/scripts/uninstall.sh" 2>/dev/null || true
    bash "$SCRIPT_DIR/products/fortress/uninstall.sh" 2>/dev/null || true
    bash "$SCRIPT_DIR/products/nexus/uninstall.sh" 2>/dev/null || true
    bash "$SCRIPT_DIR/products/mssp/uninstall.sh" --complete --force 2>/dev/null || true

    # Uninstall infrastructure
    bash "$SCRIPT_DIR/deploy/addons/n8n/uninstall.sh" 2>/dev/null || true
    bash "$SCRIPT_DIR/deploy/edge/uninstall.sh" 2>/dev/null || true
    bash "$SCRIPT_DIR/deploy/cloud/uninstall.sh" 2>/dev/null || true

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Complete Uninstall Finished!                     ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Removed:${NC}"
    echo -e "  • Sentinel (Lightweight Validator)"
    echo -e "  • Guardian (Travel Companion)"
    echo -e "  • Fortress (Edge Router)"
    echo -e "  • Nexus (ML/AI Compute)"
    echo -e "  • MSSP (Cloud Platform)"
    echo -e "  • Edge Deployment (PODs 001-007)"
    echo -e "  • Cloud Backend"
    echo -e "  • n8n Automation (POD 008)"
    echo ""
    echo -e "  ${DIM}To reinstall, run: sudo ./install.sh${NC}"
    echo ""
}

main() {
    check_root

    show_menu
    read -p "Select option: " choice

    case $choice in
        1)
            uninstall_sentinel
            ;;
        2)
            uninstall_guardian
            ;;
        3)
            uninstall_edge
            ;;
        4)
            uninstall_cloud
            ;;
        5)
            uninstall_n8n
            ;;
        9)
            uninstall_everything
            ;;
        q|Q)
            echo "Cancelled."
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            exit 1
            ;;
    esac
}

main
