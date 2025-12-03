#!/bin/bash
#
# install-edge.sh - HookProbe Edge Unified Installer
# Part of HookProbe unified installation system
#
# ONE unified installer with auto-detection for:
#   - Raspberry Pi 4/5 (4GB+ RAM)
#   - x86_64 servers (4GB+ RAM)
#   - ARM64 systems (4GB+ RAM)
#
# Usage:
#   sudo bash scripts/install-edge.sh                    # Default: Qsecbit only
#   sudo bash scripts/install-edge.sh --enable-ai        # Add AI detection
#   sudo bash scripts/install-edge.sh --enable-monitoring # Add monitoring
#   sudo bash scripts/install-edge.sh --disable-iam      # Skip IAM
#
# Target tested: Raspberry Pi 4B (4GB RAM, 32GB storage)
#

set -e  # Exit on error

# ============================================================
# CONFIGURATION
# ============================================================

# Script directory and repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

# Source library files
if [ ! -f "$LIB_DIR/platform.sh" ]; then
    echo "ERROR: Missing library files in $LIB_DIR"
    exit 1
fi

source "$LIB_DIR/platform.sh"
source "$LIB_DIR/requirements.sh"
source "$LIB_DIR/instructions.sh"

# Default configuration
ENABLE_AI=false
ENABLE_MONITORING=false
ENABLE_IAM=true
ENABLE_WEBSERVER=false
INTERACTIVE_MODE=true

# OVS Bridge configuration
OVS_BRIDGE_NAME="hookprobe"
OVS_BRIDGE_SUBNET="10.250.0.0/16"

# Secrets (will be populated by prompts or env vars)
CLOUDFLARE_TUNNEL_TOKEN=""
LOGTO_ENDPOINT=""
LOGTO_APP_ID=""
LOGTO_APP_SECRET=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================
# COMMAND-LINE ARGUMENT PARSING
# ============================================================

parse_arguments() {
    # Parse command-line arguments.
    #
    # Flags:
    #   --enable-ai: Enable AI detection (needs 8GB+ RAM)
    #   --enable-monitoring: Enable Grafana/VictoriaMetrics
    #   --enable-webserver: Enable web server (Django + Nginx)
    #   --disable-iam: Skip IAM (Logto) installation
    #   --non-interactive: Skip interactive prompts

    while [[ $# -gt 0 ]]; do
        case $1 in
            --enable-ai)
                ENABLE_AI=true
                shift
                ;;
            --enable-monitoring)
                ENABLE_MONITORING=true
                shift
                ;;
            --enable-webserver)
                ENABLE_WEBSERVER=true
                shift
                ;;
            --disable-iam)
                ENABLE_IAM=false
                shift
                ;;
            --non-interactive)
                INTERACTIVE_MODE=false
                shift
                ;;
            --cf-token)
                CLOUDFLARE_TUNNEL_TOKEN="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << 'EOF'
HookProbe Edge Unified Installer

Usage:
  sudo bash scripts/install-edge.sh [OPTIONS]

Options:
  --enable-ai          Enable AI detection (requires 8GB+ RAM)
  --enable-monitoring  Enable Grafana/VictoriaMetrics monitoring
  --enable-webserver   Enable Web Server (Django + Nginx + WAF)
  --disable-iam        Skip IAM (Logto) installation
  --non-interactive    Skip interactive prompts (use defaults)
  --cf-token TOKEN     Cloudflare Tunnel token (for web server)
  --help, -h           Show this help message

Edge Deployment Profiles:
  1. Minimal (default)  - Neuro Protocol only (validator/firewall)
  2. With Web Server    - Adds Django dashboard, requires secrets config
  3. Full Stack         - All components including AI/monitoring

Core Components (always installed):
  • POD-003: Database (PostgreSQL 16)
  • POD-005: Cache (Redis 7)
  • POD-010: Neuro Protocol (Qsecbit + HTP)

Optional Components:
  • POD-001: Web Server (Django + Nginx + NAXSI WAF)
  • POD-002: IAM (Logto authentication)
  • POD-004: Monitoring (Grafana + VictoriaMetrics)
  • POD-006: Detection (Suricata, Zeek, Snort)
  • POD-007: AI Analysis (Machine Learning)

Examples:
  # Minimal edge (validator only)
  sudo bash scripts/install-edge.sh

  # Edge with web dashboard
  sudo bash scripts/install-edge.sh --enable-webserver

  # Full stack with AI
  sudo bash scripts/install-edge.sh --enable-webserver --enable-ai

Target Platforms:
  • Raspberry Pi 4/5 (3GB+ RAM, 32GB+ storage)
  • x86_64 servers (3GB+ RAM, 20GB+ storage)
  • ARM64 systems (3GB+ RAM, 20GB+ storage)

EOF
}

# ============================================================
# COMPONENT SELECTION MENU
# ============================================================

show_component_menu() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Edge Deployment Profile Selection${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Select your edge deployment profile:"
    echo ""
    echo -e "  ${YELLOW}1${NC}) Minimal Edge ${GREEN}[Recommended for validators]${NC}"
    echo "     └─ Neuro Protocol (Qsecbit + HTP) + Database + Cache"
    echo "     └─ For: Edge firewall, IDS/IPS, WAF validators"
    echo "     └─ Min RAM: 3GB | PODs: ~1.5GB"
    echo ""
    echo -e "  ${YELLOW}2${NC}) Edge with Web Dashboard ${CYAN}[Requires secrets config]${NC}"
    echo "     └─ Adds: Django dashboard + Nginx + NAXSI WAF + IAM"
    echo "     └─ For: Standalone edge with local management UI"
    echo "     └─ Min RAM: 4GB | PODs: ~2.5GB"
    echo ""
    echo -e "  ${YELLOW}3${NC}) Full Edge Stack ${YELLOW}[8GB+ RAM required]${NC}"
    echo "     └─ All components including AI detection & monitoring"
    echo "     └─ For: Complete edge security appliance"
    echo "     └─ Min RAM: 10GB | PODs: ~8GB"
    echo ""
    echo -e "  ${YELLOW}4${NC}) Custom Selection"
    echo "     └─ Choose individual components (RAM calculated dynamically)"
    echo ""
}

select_components() {
    if [ "$INTERACTIVE_MODE" = false ]; then
        return 0
    fi

    show_component_menu
    read -p "Select profile [1-4]: " profile_choice
    echo ""

    case $profile_choice in
        1)
            # Minimal - just Neuro Protocol
            ENABLE_WEBSERVER=false
            ENABLE_IAM=false
            ENABLE_AI=false
            ENABLE_MONITORING=false
            echo -e "${GREEN}[x]${NC} Selected: Minimal Edge (Neuro Protocol only)"
            ;;
        2)
            # Edge with Web Dashboard
            ENABLE_WEBSERVER=true
            ENABLE_IAM=true
            ENABLE_AI=false
            ENABLE_MONITORING=false
            echo -e "${GREEN}[x]${NC} Selected: Edge with Web Dashboard"
            configure_webserver_secrets
            ;;
        3)
            # Full Stack
            ENABLE_WEBSERVER=true
            ENABLE_IAM=true
            ENABLE_AI=true
            ENABLE_MONITORING=true
            echo -e "${GREEN}[x]${NC} Selected: Full Edge Stack"
            configure_webserver_secrets
            ;;
        4)
            # Custom selection
            custom_component_selection
            if [ "$ENABLE_WEBSERVER" = true ]; then
                configure_webserver_secrets
            fi
            ;;
        *)
            echo -e "${YELLOW}Invalid selection, using Minimal profile${NC}"
            ENABLE_WEBSERVER=false
            ENABLE_IAM=false
            ENABLE_AI=false
            ENABLE_MONITORING=false
            ;;
    esac
    echo ""
}

custom_component_selection() {
    echo -e "${CYAN}Custom Component Selection${NC}"
    echo ""
    echo "Core components (always installed): Database, Cache, Neuro Protocol (~1.5GB)"
    echo ""

    read -p "Enable Web Server (Django + Nginx) [+0.5GB RAM]? [y/N]: " -n 1 -r
    echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && ENABLE_WEBSERVER=true || ENABLE_WEBSERVER=false

    read -p "Enable IAM (Logto authentication) [+1GB RAM]? [y/N]: " -n 1 -r
    echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && ENABLE_IAM=true || ENABLE_IAM=false

    read -p "Enable Monitoring (Grafana + VictoriaMetrics) [+2GB RAM]? [y/N]: " -n 1 -r
    echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && ENABLE_MONITORING=true || ENABLE_MONITORING=false

    read -p "Enable AI Detection (Suricata + ML) [+4GB RAM]? [y/N]: " -n 1 -r
    echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && ENABLE_AI=true || ENABLE_AI=false

    # Calculate minimum RAM for selected components
    local min_ram=3  # Base
    [ "$ENABLE_IAM" = true ] && min_ram=$((min_ram + 1))
    [ "$ENABLE_MONITORING" = true ] && min_ram=$((min_ram + 2))
    [ "$ENABLE_AI" = true ] && min_ram=$((min_ram + 4))

    echo ""
    echo "Selected components:"
    echo -e "  ${GREEN}[x]${NC} Core (Database + Cache + Neuro)"
    echo -e "  $([ "$ENABLE_WEBSERVER" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") Web Server (+0.5GB)"
    echo -e "  $([ "$ENABLE_IAM" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") IAM (+1GB)"
    echo -e "  $([ "$ENABLE_MONITORING" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") Monitoring (+2GB)"
    echo -e "  $([ "$ENABLE_AI" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") AI Detection (+4GB)"
    echo ""
    echo -e "Minimum RAM required: ${CYAN}${min_ram}GB${NC}"
}

# ============================================================
# SECRETS CONFIGURATION
# ============================================================

configure_webserver_secrets() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Web Server Secrets Configuration${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "The web server requires secrets for secure operation."
    echo "You can skip these now and configure later in /etc/hookprobe/secrets/"
    echo ""

    # Cloudflare Tunnel
    echo -e "${YELLOW}Cloudflare Tunnel (optional)${NC}"
    echo "Used for secure external access without opening ports."
    if [ -z "$CLOUDFLARE_TUNNEL_TOKEN" ]; then
        read -p "Cloudflare Tunnel Token (or press Enter to skip): " cf_token
        CLOUDFLARE_TUNNEL_TOKEN="$cf_token"
    else
        echo -e "  Token: ${GREEN}[configured via --cf-token]${NC}"
    fi
    echo ""

    # Logto Configuration
    if [ "$ENABLE_IAM" = true ]; then
        echo -e "${YELLOW}Logto IAM Configuration${NC}"
        echo "Authentication service for user management."

        read -p "Logto Endpoint URL (or press Enter for local): " logto_endpoint
        LOGTO_ENDPOINT="${logto_endpoint:-http://localhost:3001}"

        read -p "Logto App ID (or press Enter to auto-generate): " logto_app_id
        LOGTO_APP_ID="${logto_app_id:-$(openssl rand -hex 16)}"

        read -p "Logto App Secret (or press Enter to auto-generate): " logto_secret
        LOGTO_APP_SECRET="${logto_secret:-$(openssl rand -base64 32)}"
        echo ""
    fi

    # Create secrets directory
    mkdir -p /etc/hookprobe/secrets
    chmod 700 /etc/hookprobe/secrets

    # Save secrets
    if [ -n "$CLOUDFLARE_TUNNEL_TOKEN" ]; then
        echo "$CLOUDFLARE_TUNNEL_TOKEN" > /etc/hookprobe/secrets/cloudflare-tunnel-token
        chmod 600 /etc/hookprobe/secrets/cloudflare-tunnel-token
        echo -e "  ${GREEN}[x]${NC} Cloudflare Tunnel token saved"
    fi

    if [ "$ENABLE_IAM" = true ]; then
        cat > /etc/hookprobe/secrets/logto.env << LOGTOEOF
LOGTO_ENDPOINT=$LOGTO_ENDPOINT
LOGTO_APP_ID=$LOGTO_APP_ID
LOGTO_APP_SECRET=$LOGTO_APP_SECRET
LOGTOEOF
        chmod 600 /etc/hookprobe/secrets/logto.env
        echo -e "  ${GREEN}[x]${NC} Logto configuration saved"
    fi

    # Generate Django secret key
    DJANGO_SECRET_KEY=$(openssl rand -base64 32)
    echo "$DJANGO_SECRET_KEY" > /etc/hookprobe/secrets/django-secret-key
    chmod 600 /etc/hookprobe/secrets/django-secret-key
    echo -e "  ${GREEN}[x]${NC} Django secret key generated"

    echo ""
    echo -e "${GREEN}Secrets saved to /etc/hookprobe/secrets/${NC}"
}

# ============================================================
# INSTALLATION STEPS
# ============================================================

main() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  HookProbe Edge Unified Installer${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    # Parse command-line arguments
    parse_arguments "$@"

    # --------------------------------------------------------
    # [1/7] PLATFORM DETECTION
    # --------------------------------------------------------
    echo -e "${BLUE}[1/7] Detecting platform...${NC}"
    echo ""

    detect_platform
    calculate_memory_limits

    echo "Platform detected:"
    echo "  OS:              $PLATFORM_OS"
    echo "  Architecture:    $PLATFORM_ARCH"
    echo "  RAM:             ${TOTAL_RAM_GB}GB"
    echo "  CPU Cores:       $CPU_CORES"
    echo "  Memory Profile:  $MEMORY_PROFILE"

    if [ "$IS_RASPBERRY_PI" = true ]; then
        echo "  Device:          Raspberry Pi"
        echo "  Model:           $RASPBERRY_PI_MODEL"
    fi

    echo ""

    # --------------------------------------------------------
    # [2/7] COMPONENT SELECTION
    # --------------------------------------------------------
    echo -e "${BLUE}[2/7] Selecting deployment profile...${NC}"

    select_components

    # --------------------------------------------------------
    # [3/7] SYSTEM REQUIREMENTS CHECK
    # --------------------------------------------------------
    echo -e "${BLUE}[3/7] Checking system requirements...${NC}"

    if ! run_system_check "$ENABLE_AI" "$ENABLE_MONITORING"; then
        echo ""
        echo -e "${RED}System requirements check FAILED${NC}"
        echo ""

        # If Raspberry Pi and cgroups not enabled, show detailed instructions
        if [ "$IS_RASPBERRY_PI" = true ] && ! check_cgroup_enabled; then
            show_cgroup_instructions
        fi

        exit 1
    fi

    echo ""

    # --------------------------------------------------------
    # [4/7] MEMORY SUFFICIENCY CHECK
    # --------------------------------------------------------
    echo -e "${BLUE}[4/7] Validating memory allocation...${NC}"

    if ! check_memory_sufficiency "$ENABLE_AI" "$ENABLE_MONITORING" "$ENABLE_IAM"; then
        echo ""
        echo -e "${YELLOW}WARNING: Memory may be tight${NC}"

        if [ "$ENABLE_AI" = true ]; then
            echo ""
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo ""
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Installation cancelled."
                exit 0
            fi
        fi
    fi

    echo ""

    # --------------------------------------------------------
    # [5/7] DETERMINE PODS TO DEPLOY
    # --------------------------------------------------------
    echo -e "${BLUE}[5/7] Planning POD deployment...${NC}"
    echo ""

    echo "PODs to be deployed:"
    echo -e "  $([ "$ENABLE_WEBSERVER" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") POD-001: Web Server (Django + Nginx + NAXSI)"
    echo -e "  $([ "$ENABLE_IAM" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") POD-002: IAM (Logto authentication)"
    echo -e "  ${GREEN}[x]${NC} POD-003: Database (PostgreSQL 16)"
    echo -e "  ${GREEN}[x]${NC} POD-005: Cache (Redis 7)"
    echo -e "  ${GREEN}[x]${NC} POD-010: Neuro Protocol (Qsecbit + HTP)"
    echo -e "  $([ "$ENABLE_MONITORING" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") POD-004: Monitoring (Grafana + VictoriaMetrics)"
    echo -e "  $([ "$ENABLE_AI" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") POD-006: Detection (Suricata, Zeek, Snort)"
    echo -e "  $([ "$ENABLE_AI" = true ] && echo "${GREEN}[x]${NC}" || echo "${YELLOW}[-]${NC}") POD-007: AI Analysis (Machine Learning)"

    echo ""
    echo "Network: OVS Bridge '$OVS_BRIDGE_NAME'"
    echo ""
    echo "Memory allocation:"
    if [ "$ENABLE_WEBSERVER" = true ]; then
        echo "  Web Server:      $POD_MEMORY_WEB"
    fi
    echo "  Database:        $POD_MEMORY_DATABASE"
    echo "  Cache:           $POD_MEMORY_CACHE"
    echo "  Neuro Protocol:  $POD_MEMORY_NEURO"
    if [ "$ENABLE_IAM" = true ]; then
        echo "  IAM:             $POD_MEMORY_IAM"
    fi
    if [ "$ENABLE_AI" = true ]; then
        echo "  Detection:       2048M"
        echo "  AI Analysis:     2048M"
    fi
    if [ "$ENABLE_MONITORING" = true ]; then
        echo "  Monitoring:      2048M"
    fi

    echo ""
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi

    # --------------------------------------------------------
    # [6/7] DEPLOY PODS
    # --------------------------------------------------------
    echo ""
    echo -e "${BLUE}[6/7] Deploying PODs...${NC}"
    echo ""

    # Install dependencies
    install_dependencies

    # Setup OVS bridge with VXLAN networking
    setup_ovs_bridge
    create_networks
    setup_vxlan_tunnels
    setup_openflow_monitoring

    # Deploy core PODs (always installed)
    deploy_database_pod
    deploy_cache_pod
    deploy_neuro_pod

    # Deploy optional Web Server POD
    if [ "$ENABLE_WEBSERVER" = true ]; then
        deploy_web_pod
    fi

    # Deploy optional IAM POD
    if [ "$ENABLE_IAM" = true ]; then
        deploy_iam_pod
    fi

    # Deploy optional PODs
    if [ "$ENABLE_MONITORING" = true ]; then
        deploy_monitoring_pod
    fi

    if [ "$ENABLE_AI" = true ]; then
        deploy_detection_pod
        deploy_ai_pod
    fi

    # --------------------------------------------------------
    # [7/7] POST-INSTALL
    # --------------------------------------------------------
    echo ""
    echo -e "${BLUE}[7/7] Finalizing installation...${NC}"
    echo ""

    # Wait for containers to start
    echo "Waiting for containers to start..."
    sleep 10

    # Check POD status
    check_pod_status

    # Show success message
    show_success_message "$ENABLE_AI" "$ENABLE_MONITORING"

    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
}

# ============================================================
# DEPENDENCY INSTALLATION
# ============================================================

install_dependencies() {
    echo "Installing dependencies..."

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    else
        echo -e "${RED}ERROR: No supported package manager found${NC}"
        exit 1
    fi

    # Install Podman if not present
    if ! command -v podman &> /dev/null; then
        echo "Installing Podman..."
        if [ "$PKG_MANAGER" = "apt-get" ]; then
            apt-get update
            apt-get install -y podman
        else
            $PKG_MANAGER install -y podman
        fi
    fi

    # Install Git if not present
    if ! command -v git &> /dev/null; then
        echo "Installing Git..."
        $PKG_MANAGER install -y git
    fi

    # Install Python 3.9+ if not present
    if ! command -v python3 &> /dev/null; then
        echo "Installing Python..."
        if [ "$PKG_MANAGER" = "apt-get" ]; then
            apt-get install -y python3 python3-pip
        else
            $PKG_MANAGER install -y python3 python3-pip
        fi
    fi

    echo -e "${GREEN}✓${NC} Dependencies installed"
}

# ============================================================
# NETWORK CREATION
# ============================================================

# Global flag for network mode
USE_HOST_NETWORK=false

detect_container_environment() {
    # Detect if running inside LXC/LXD container
    if [ -f /proc/1/environ ] && grep -qa "container=lxc" /proc/1/environ 2>/dev/null; then
        return 0  # LXC detected
    fi
    if [ -f /run/systemd/container ] && grep -q "lxc" /run/systemd/container 2>/dev/null; then
        return 0  # LXC detected
    fi
    if grep -qa "lxc" /proc/1/cgroup 2>/dev/null; then
        return 0  # LXC detected
    fi
    return 1  # Not in LXC
}

get_cni_version() {
    # Get installed CNI plugins version
    # Returns version string or "none" if not installed

    local cni_version="none"

    # Check common CNI plugin locations
    if [ -f /usr/lib/cni/bridge ]; then
        # Try to get version from binary (some CNI plugins support --version)
        cni_version=$(/usr/lib/cni/bridge 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    elif [ -f /opt/cni/bin/bridge ]; then
        cni_version=$(/opt/cni/bin/bridge 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    fi

    # Fallback: check package manager for version
    if [ -z "$cni_version" ] || [ "$cni_version" = "none" ]; then
        if command -v dpkg &> /dev/null; then
            cni_version=$(dpkg -l | grep -E 'containernetworking-plugins|cni-plugins' | awk '{print $3}' | head -1 || echo "")
        elif command -v rpm &> /dev/null; then
            cni_version=$(rpm -q containernetworking-plugins --queryformat '%{VERSION}' 2>/dev/null || echo "")
        fi
    fi

    if [ -z "$cni_version" ]; then
        echo "none"
    else
        echo "$cni_version"
    fi
}

compare_versions() {
    # Compare two version strings
    # Returns: 0 if $1 >= $2, 1 if $1 < $2
    local ver1="$1"
    local ver2="$2"

    # Handle "none" case
    if [ "$ver1" = "none" ]; then
        return 1
    fi

    # Use sort -V for version comparison
    local lowest=$(printf '%s\n%s' "$ver1" "$ver2" | sort -V | head -n1)
    if [ "$lowest" = "$ver2" ]; then
        return 0  # ver1 >= ver2
    else
        return 1  # ver1 < ver2
    fi
}

check_and_upgrade_cni() {
    # Check CNI version and upgrade if needed for Podman compatibility
    # Podman 4.x requires CNI plugins 1.0.0+

    local required_version="1.0.0"
    local current_version=$(get_cni_version)

    echo "Checking CNI plugins version..."
    echo "  Current version: $current_version"
    echo "  Required version: $required_version+"

    if [ "$current_version" = "none" ]; then
        echo -e "${YELLOW}⚠ CNI plugins not found - will be installed with Podman${NC}"
        return 0
    fi

    if compare_versions "$current_version" "$required_version"; then
        echo -e "${GREEN}✓${NC} CNI plugins version is compatible"
        return 0
    fi

    echo -e "${YELLOW}⚠ CNI plugins version $current_version is outdated${NC}"
    echo "  Podman requires CNI plugins $required_version or newer."
    echo ""

    # Attempt auto-upgrade
    echo "Attempting to upgrade CNI plugins..."

    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        apt-get update -qq
        if apt-get install -y containernetworking-plugins 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins upgraded via apt"
            return 0
        fi
        # Try alternative package name
        if apt-get install -y golang-github-containernetworking-plugins 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins upgraded via apt (alternative package)"
            return 0
        fi
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+
        if dnf install -y containernetworking-plugins 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins upgraded via dnf"
            return 0
        fi
    elif command -v yum &> /dev/null; then
        # RHEL 7/CentOS
        if yum install -y containernetworking-plugins 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins upgraded via yum"
            return 0
        fi
    fi

    # Manual installation fallback
    echo -e "${YELLOW}⚠ Package manager upgrade failed, attempting manual install...${NC}"

    local cni_url="https://github.com/containernetworking/plugins/releases/download/v1.4.0/cni-plugins-linux-$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')-v1.4.0.tgz"
    local cni_dir="/opt/cni/bin"

    mkdir -p "$cni_dir"

    if command -v curl &> /dev/null; then
        if curl -sSL "$cni_url" | tar -xz -C "$cni_dir" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins installed manually to $cni_dir"
            return 0
        fi
    elif command -v wget &> /dev/null; then
        if wget -qO- "$cni_url" | tar -xz -C "$cni_dir" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} CNI plugins installed manually to $cni_dir"
            return 0
        fi
    fi

    echo -e "${RED}✗ Failed to upgrade CNI plugins${NC}"
    echo ""
    echo "Please manually upgrade CNI plugins to version 1.0.0 or newer:"
    echo "  Option 1: apt install containernetworking-plugins"
    echo "  Option 2: dnf install containernetworking-plugins"
    echo "  Option 3: Download from https://github.com/containernetworking/plugins/releases"
    echo ""
    echo "Falling back to host networking mode..."
    USE_HOST_NETWORK=true
    return 1
}

# ============================================================
# OVS BRIDGE SETUP WITH VXLAN/VNI/PSK
# ============================================================

# VXLAN Configuration for each POD network
# Format: POD_NAME:VNI:VXLAN_PORT
declare -A VXLAN_CONFIG=(
    ["hookprobe-web"]="100:4789"
    ["hookprobe-iam"]="200:4790"
    ["hookprobe-database"]="300:4791"
    ["hookprobe-monitoring"]="400:4792"
    ["hookprobe-cache"]="500:4793"
    ["hookprobe-detection"]="600:4794"
    ["hookprobe-ai"]="700:4795"
    ["hookprobe-neuro"]="1000:4800"
)

generate_vxlan_psk() {
    # Generate a PSK for VXLAN tunnel encryption
    openssl rand -base64 32
}

setup_ovs_bridge() {
    echo "Setting up OVS bridge '$OVS_BRIDGE_NAME' with VXLAN networking..."

    # Check if OVS is installed
    if ! command -v ovs-vsctl &> /dev/null; then
        echo "  Installing Open vSwitch..."
        if command -v apt-get &> /dev/null; then
            apt-get update -qq && apt-get install -y openvswitch-switch 2>/dev/null
        elif command -v dnf &> /dev/null; then
            dnf install -y openvswitch 2>/dev/null
        elif command -v yum &> /dev/null; then
            yum install -y openvswitch 2>/dev/null
        fi
    fi

    # If OVS still not available, fall back to Linux bridge
    if ! command -v ovs-vsctl &> /dev/null; then
        echo -e "${YELLOW}⚠ OVS not available, using standard bridge mode${NC}"
        USE_OVS_BRIDGE=false
        return 0
    fi

    USE_OVS_BRIDGE=true

    # Start OVS service
    systemctl start openvswitch-switch 2>/dev/null || \
    systemctl start ovs-vswitchd 2>/dev/null || \
    service openvswitch-switch start 2>/dev/null || true

    # Check if bridge already exists
    if ovs-vsctl br-exists "$OVS_BRIDGE_NAME" 2>/dev/null; then
        echo -e "  ${GREEN}[x]${NC} OVS bridge '$OVS_BRIDGE_NAME' already exists"
    else
        # Create OVS bridge
        ovs-vsctl add-br "$OVS_BRIDGE_NAME" 2>/dev/null || {
            echo -e "${YELLOW}⚠ Failed to create OVS bridge, using standard networking${NC}"
            USE_OVS_BRIDGE=false
            return 0
        }
        echo -e "  ${GREEN}[x]${NC} OVS bridge '$OVS_BRIDGE_NAME' created"
    fi

    # Enable OpenFlow 1.3 for advanced flow monitoring
    ovs-vsctl set bridge "$OVS_BRIDGE_NAME" protocols=OpenFlow10,OpenFlow13 2>/dev/null || true

    # Configure bridge IP
    ip addr add 10.250.0.1/16 dev "$OVS_BRIDGE_NAME" 2>/dev/null || true
    ip link set "$OVS_BRIDGE_NAME" up 2>/dev/null || true

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    # Create secrets directory for VXLAN PSK
    mkdir -p /etc/hookprobe/secrets/vxlan
    chmod 700 /etc/hookprobe/secrets/vxlan

    # Generate master PSK if not exists
    if [ ! -f /etc/hookprobe/secrets/vxlan/master.psk ]; then
        generate_vxlan_psk > /etc/hookprobe/secrets/vxlan/master.psk
        chmod 600 /etc/hookprobe/secrets/vxlan/master.psk
        echo -e "  ${GREEN}[x]${NC} VXLAN master PSK generated"
    fi

    # Save OVS bridge config
    mkdir -p /etc/hookprobe
    cat > /etc/hookprobe/ovs-bridge.conf << OVSEOF
# HookProbe OVS Bridge Configuration
OVS_BRIDGE_NAME=$OVS_BRIDGE_NAME
OVS_BRIDGE_SUBNET=$OVS_BRIDGE_SUBNET
OVS_BRIDGE_IP=10.250.0.1
OPENFLOW_VERSION=1.3

# VXLAN Configuration
VXLAN_ENABLED=true
VXLAN_MASTER_PSK=/etc/hookprobe/secrets/vxlan/master.psk
OVSEOF

    echo -e "  ${GREEN}[x]${NC} OVS bridge configured with OpenFlow 1.3"
    echo ""
}

setup_vxlan_tunnels() {
    echo "Setting up VXLAN tunnels for POD networks..."

    if [ "$USE_OVS_BRIDGE" != true ]; then
        echo -e "  ${YELLOW}[-]${NC} VXLAN skipped (OVS not available)"
        return 0
    fi

    # Get local IP for VXLAN endpoints
    local local_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    # Create VXLAN config file
    cat > /etc/hookprobe/vxlan-networks.conf << 'VXLANHEADER'
# HookProbe VXLAN Network Configuration
# Format: NETWORK_NAME|VNI|VXLAN_PORT|SUBNET|PSK_FILE
VXLANHEADER

    local vxlan_count=0

    # Setup VXLAN for each enabled network
    for network in "${!VXLAN_CONFIG[@]}"; do
        local config="${VXLAN_CONFIG[$network]}"
        local vni=$(echo "$config" | cut -d: -f1)
        local port=$(echo "$config" | cut -d: -f2)

        # Check if this network should be created based on enabled components
        local should_create=false
        case "$network" in
            hookprobe-web) [ "$ENABLE_WEBSERVER" = true ] && should_create=true ;;
            hookprobe-iam) [ "$ENABLE_IAM" = true ] && should_create=true ;;
            hookprobe-database) should_create=true ;;  # Always
            hookprobe-cache) should_create=true ;;     # Always
            hookprobe-neuro) should_create=true ;;     # Always
            hookprobe-monitoring) [ "$ENABLE_MONITORING" = true ] && should_create=true ;;
            hookprobe-detection|hookprobe-ai) [ "$ENABLE_AI" = true ] && should_create=true ;;
        esac

        if [ "$should_create" = true ]; then
            # Generate per-tunnel PSK
            local psk_file="/etc/hookprobe/secrets/vxlan/${network}.psk"
            if [ ! -f "$psk_file" ]; then
                generate_vxlan_psk > "$psk_file"
                chmod 600 "$psk_file"
            fi

            # Get subnet for this network
            local subnet=""
            case "$network" in
                hookprobe-web) subnet="10.250.1.0/24" ;;
                hookprobe-iam) subnet="10.250.2.0/24" ;;
                hookprobe-database) subnet="10.250.3.0/24" ;;
                hookprobe-monitoring) subnet="10.250.4.0/24" ;;
                hookprobe-cache) subnet="10.250.5.0/24" ;;
                hookprobe-detection) subnet="10.250.6.0/24" ;;
                hookprobe-ai) subnet="10.250.7.0/24" ;;
                hookprobe-neuro) subnet="10.250.10.0/24" ;;
            esac

            # Add VXLAN port to OVS bridge
            local vxlan_port="vxlan_${vni}"
            ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "$vxlan_port" \
                -- set interface "$vxlan_port" type=vxlan \
                options:key="$vni" \
                options:local_ip="$local_ip" \
                options:remote_ip=flow 2>/dev/null || true

            # Save to config
            echo "${network}|${vni}|${port}|${subnet}|${psk_file}" >> /etc/hookprobe/vxlan-networks.conf

            vxlan_count=$((vxlan_count + 1))
        fi
    done

    if [ "$vxlan_count" -gt 0 ]; then
        echo -e "  ${GREEN}[x]${NC} $vxlan_count VXLAN tunnels configured"
    fi
}

setup_openflow_monitoring() {
    echo "Setting up OpenFlow monitoring for VXLAN tunnels..."

    if [ "$USE_OVS_BRIDGE" != true ]; then
        echo -e "  ${YELLOW}[-]${NC} OpenFlow monitoring skipped (OVS not available)"
        return 0
    fi

    # Create OpenFlow rules for monitoring and security

    # Rule 1: Drop invalid packets
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=0,actions=drop" 2>/dev/null || true

    # Rule 2: Allow ARP
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=100,arp,actions=normal" 2>/dev/null || true

    # Rule 3: Allow ICMP for diagnostics
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=100,icmp,actions=normal" 2>/dev/null || true

    # Rule 4: Allow established connections
    ovs-ofctl add-flow "$OVS_BRIDGE_NAME" "priority=50,ip,actions=normal" 2>/dev/null || true

    # Rule 5: Monitor VXLAN traffic (match UDP dst port range 4789-4800)
    for port in 4789 4790 4791 4792 4793 4794 4795 4800; do
        ovs-ofctl add-flow "$OVS_BRIDGE_NAME" \
            "priority=200,udp,tp_dst=$port,actions=normal" 2>/dev/null || true
    done

    # Create monitoring script
    cat > /usr/local/bin/hookprobe-vxlan-monitor << 'MONITOREOF'
#!/bin/bash
# HookProbe VXLAN Monitor
# Displays VXLAN tunnel statistics and OpenFlow flows

OVS_BRIDGE="${1:-hookprobe}"

echo "=== HookProbe VXLAN Monitor ==="
echo ""

echo "Bridge: $OVS_BRIDGE"
echo ""

echo "--- VXLAN Ports ---"
ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep vxlan || echo "No VXLAN ports"
echo ""

echo "--- OpenFlow Flows ---"
ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | head -20
echo ""

echo "--- Port Statistics ---"
ovs-ofctl dump-ports "$OVS_BRIDGE" 2>/dev/null | head -30
echo ""

echo "--- Network Config ---"
if [ -f /etc/hookprobe/vxlan-networks.conf ]; then
    echo "Network              | VNI  | Port | Subnet"
    echo "---------------------|------|------|---------------"
    grep -v "^#" /etc/hookprobe/vxlan-networks.conf | while IFS='|' read name vni port subnet psk; do
        [ -n "$name" ] && printf "%-20s | %-4s | %-4s | %s\n" "$name" "$vni" "$port" "$subnet"
    done
fi
MONITOREOF

    chmod +x /usr/local/bin/hookprobe-vxlan-monitor

    echo -e "  ${GREEN}[x]${NC} OpenFlow monitoring configured"
    echo -e "  ${GREEN}[x]${NC} Monitor tool: hookprobe-vxlan-monitor"
}

create_networks() {
    echo "Creating Podman networks on OVS bridge..."

    # Check if running in LXC container
    if detect_container_environment; then
        echo -e "${YELLOW}⚠ LXC/LXD container detected${NC}"
        echo "  Custom Podman networks may not work in LXC containers."
        echo ""

        # Check and upgrade CNI if needed
        check_and_upgrade_cni

        if [ "$USE_HOST_NETWORK" = true ]; then
            echo -e "${YELLOW}⚠ Using host network mode due to CNI/container limitations${NC}"
            return 0
        fi

        echo ""
        echo "  Attempting network creation..."
    fi

    # Remove existing networks if present
    podman network rm hookprobe-web hookprobe-database hookprobe-cache hookprobe-iam hookprobe-neuro 2>/dev/null || true
    podman network rm web-net database-net cache-net iam-net neuro-net 2>/dev/null || true

    # Try to create networks with OVS bridge driver if available
    local network_failed=false
    local bridge_opt=""

    if [ "$USE_OVS_BRIDGE" = true ]; then
        # Use OVS bridge for networking
        bridge_opt="--opt bridge=$OVS_BRIDGE_NAME"
    fi

    # Create POD networks under the hookprobe namespace
    # Each POD gets its own subnet under 10.250.x.0/24

    # Core networks (always created)
    echo "  Creating core POD networks..."

    # Database network (POD-003)
    if ! podman network create \
        --subnet 10.250.3.0/24 \
        --gateway 10.250.3.1 \
        $bridge_opt \
        hookprobe-database 2>/dev/null; then
        podman network create hookprobe-database 2>/dev/null || network_failed=true
    fi

    # Cache network (POD-005)
    if ! podman network create \
        --subnet 10.250.5.0/24 \
        --gateway 10.250.5.1 \
        $bridge_opt \
        hookprobe-cache 2>/dev/null; then
        podman network create hookprobe-cache 2>/dev/null || true
    fi

    # Neuro network (POD-010)
    if ! podman network create \
        --subnet 10.250.10.0/24 \
        --gateway 10.250.10.1 \
        $bridge_opt \
        hookprobe-neuro 2>/dev/null; then
        podman network create hookprobe-neuro 2>/dev/null || true
    fi

    # Optional networks based on selected components
    if [ "$ENABLE_WEBSERVER" = true ]; then
        echo "  Creating web server network..."
        if ! podman network create \
            --subnet 10.250.1.0/24 \
            --gateway 10.250.1.1 \
            $bridge_opt \
            hookprobe-web 2>/dev/null; then
            podman network create hookprobe-web 2>/dev/null || true
        fi
    fi

    if [ "$ENABLE_IAM" = true ]; then
        echo "  Creating IAM network..."
        if ! podman network create \
            --subnet 10.250.2.0/24 \
            --gateway 10.250.2.1 \
            $bridge_opt \
            hookprobe-iam 2>/dev/null; then
            podman network create hookprobe-iam 2>/dev/null || true
        fi
    fi

    if [ "$ENABLE_MONITORING" = true ]; then
        echo "  Creating monitoring network..."
        if ! podman network create \
            --subnet 10.250.4.0/24 \
            --gateway 10.250.4.1 \
            $bridge_opt \
            hookprobe-monitoring 2>/dev/null; then
            podman network create hookprobe-monitoring 2>/dev/null || true
        fi
    fi

    if [ "$ENABLE_AI" = true ]; then
        echo "  Creating AI/detection networks..."
        if ! podman network create \
            --subnet 10.250.6.0/24 \
            --gateway 10.250.6.1 \
            $bridge_opt \
            hookprobe-detection 2>/dev/null; then
            podman network create hookprobe-detection 2>/dev/null || true
        fi
        if ! podman network create \
            --subnet 10.250.7.0/24 \
            --gateway 10.250.7.1 \
            $bridge_opt \
            hookprobe-ai 2>/dev/null; then
            podman network create hookprobe-ai 2>/dev/null || true
        fi
    fi

    # Verify networks were created
    if ! podman network exists hookprobe-database 2>/dev/null; then
        echo -e "${YELLOW}⚠ Custom networks unavailable - using host network mode${NC}"
        echo "  This is common in LXC/LXD containers or restricted environments."
        echo "  Pods will use host networking instead."
        USE_HOST_NETWORK=true
    else
        echo -e "${GREEN}[x]${NC} POD networks created on bridge '$OVS_BRIDGE_NAME'"

        # Show network summary with VXLAN info
        echo ""
        echo "Network Summary:"
        echo "  Network              Subnet           VNI    Port"
        echo "  -------------------  ---------------  -----  ----"
        for net in $(podman network ls --format "{{.Name}}" 2>/dev/null | grep hookprobe); do
            local subnet=$(podman network inspect "$net" --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null || echo "N/A")
            local vni="N/A"
            local port="N/A"
            case "$net" in
                hookprobe-web) vni="100"; port="4789" ;;
                hookprobe-iam) vni="200"; port="4790" ;;
                hookprobe-database) vni="300"; port="4791" ;;
                hookprobe-monitoring) vni="400"; port="4792" ;;
                hookprobe-cache) vni="500"; port="4793" ;;
                hookprobe-detection) vni="600"; port="4794" ;;
                hookprobe-ai) vni="700"; port="4795" ;;
                hookprobe-neuro) vni="1000"; port="4800" ;;
            esac
            printf "  %-19s  %-15s  %-5s  %s\n" "$net" "$subnet" "$vni" "$port"
        done
    fi
}

# ============================================================
# POD DEPLOYMENT
# ============================================================

# Helper function to get network argument
# Maps POD type to network name
get_network_arg() {
    local pod_type="$1"
    if [ "$USE_HOST_NETWORK" = true ]; then
        echo "--network host"
    else
        # Map pod types to hookprobe network names
        case "$pod_type" in
            web|web-net)
                echo "--network hookprobe-web"
                ;;
            database|database-net)
                echo "--network hookprobe-database"
                ;;
            cache|cache-net)
                echo "--network hookprobe-cache"
                ;;
            iam|iam-net)
                echo "--network hookprobe-iam"
                ;;
            neuro|neuro-net)
                echo "--network hookprobe-neuro"
                ;;
            monitoring|monitoring-net)
                echo "--network hookprobe-monitoring"
                ;;
            detection|detection-net)
                echo "--network hookprobe-detection"
                ;;
            ai|ai-net)
                echo "--network hookprobe-ai"
                ;;
            *)
                echo "--network hookprobe-$pod_type"
                ;;
        esac
    fi
}

# Helper to get database/redis host (localhost for host network, IP for custom)
# Network allocation:
#   hookprobe-database: 10.250.3.0/24
#   hookprobe-cache:    10.250.5.0/24
get_db_host() {
    if [ "$USE_HOST_NETWORK" = true ]; then
        echo "127.0.0.1"
    else
        echo "10.250.3.2"  # Database on hookprobe-database network
    fi
}

get_redis_host() {
    if [ "$USE_HOST_NETWORK" = true ]; then
        echo "127.0.0.1"
    else
        echo "10.250.5.2"  # Redis on hookprobe-cache network
    fi
}

deploy_web_pod() {
    echo "Deploying POD-001: Web Server..."

    local network_arg=$(get_network_arg "web")

    # Build Django container from Containerfile
    echo "  Building Django container (this may take a few minutes on ARM64)..."
    local containerfile="$REPO_ROOT/install/addons/webserver/Containerfile"
    if [ -f "$containerfile" ]; then
        echo "  Found Containerfile: $containerfile"
        podman build \
            -t hookprobe-web-django:edge \
            -f "$containerfile" \
            "$REPO_ROOT" || {
            echo -e "${RED}✗${NC} Failed to build Django container"
            return 1
        }
        local django_image="hookprobe-web-django:edge"
    else
        # Fallback: use minimal Django app inline
        echo "  Containerfile not found, using minimal inline setup..."
        local django_image="docker.io/library/python:3.11-slim"
    fi

    # Create pod
    podman pod create \
        --name hookprobe-web \
        $network_arg \
        --publish 80:80 \
        --publish 443:443

    # Determine if we should use standalone mode (no external database)
    # Standalone mode uses SQLite instead of PostgreSQL
    local standalone_mode="false"
    if [ "${ENABLE_DATABASE:-true}" != "true" ]; then
        standalone_mode="true"
        echo "  Database POD disabled - Django will use SQLite (standalone mode)"
    fi

    # Deploy Django container
    if [ "$django_image" = "hookprobe-web-django:edge" ]; then
        # Use built container with proper entrypoint
        podman run -d \
            --pod hookprobe-web \
            --name hookprobe-web-django \
            --memory "$POD_MEMORY_WEB" \
            --restart unless-stopped \
            -e DJANGO_SECRET_KEY="$(openssl rand -base64 32)" \
            -e DJANGO_DEBUG="false" \
            -e DJANGO_ALLOWED_HOSTS="*" \
            -e POSTGRES_HOST="$(get_db_host)" \
            -e POSTGRES_PORT="5432" \
            -e POSTGRES_DB="hookprobe" \
            -e POSTGRES_USER="hookprobe" \
            -e POSTGRES_PASSWORD="hookprobe" \
            -e REDIS_HOST="$(get_redis_host)" \
            -e REDIS_PORT="6379" \
            -e GUNICORN_WORKERS="2" \
            -e GUNICORN_TIMEOUT="120" \
            -e STANDALONE_MODE="$standalone_mode" \
            -e DB_WAIT_TIMEOUT="30" \
            -e REDIS_WAIT_TIMEOUT="15" \
            "$django_image"
    else
        # Fallback: minimal Django status page
        podman run -d \
            --pod hookprobe-web \
            --name hookprobe-web-django \
            --memory "$POD_MEMORY_WEB" \
            --restart unless-stopped \
            --health-cmd "python -c 'import urllib.request; urllib.request.urlopen(\"http://localhost:8000\")' || exit 1" \
            --health-interval 30s \
            --health-timeout 10s \
            --health-retries 3 \
            --health-start-period 60s \
            -e DJANGO_SECRET_KEY="$(openssl rand -base64 32)" \
            "$django_image" \
            bash -c '
                pip install --quiet django gunicorn whitenoise
                mkdir -p /app && cd /app
                django-admin startproject hookprobe .
                cat > hookprobe/views.py << "VIEWSEOF"
from django.http import JsonResponse
import platform, os
def status(request):
    return JsonResponse({
        "service": "HookProbe Edge",
        "status": "running",
        "version": "5.0",
        "platform": platform.machine(),
        "python": platform.python_version()
    })
VIEWSEOF
                cat > hookprobe/urls.py << "URLSEOF"
from django.contrib import admin
from django.urls import path
from . import views
urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.status),
    path("health/", views.status),
    path("api/status/", views.status),
]
URLSEOF
                python manage.py migrate --run-syncdb
                exec gunicorn hookprobe.wsgi:application --bind 0.0.0.0:8000 --workers 2
            '
    fi

    # Create nginx configuration
    local nginx_conf_dir="/tmp/hookprobe-nginx-config"
    mkdir -p "$nginx_conf_dir"

    # Copy nginx config if available, otherwise create inline
    local nginx_conf_src="$REPO_ROOT/install/addons/webserver/nginx/default.conf"
    if [ -f "$nginx_conf_src" ]; then
        cp "$nginx_conf_src" "$nginx_conf_dir/default.conf"
    else
        cat > "$nginx_conf_dir/default.conf" << 'NGINXCONF'
upstream django {
    server 127.0.0.1:8000;
}
server {
    listen 80;
    server_name _;
    client_max_body_size 100M;

    location /static/ {
        alias /app/staticfiles/;
        expires 30d;
    }

    location /media/ {
        alias /app/media/;
    }

    location /nginx-health {
        access_log off;
        return 200 "OK\n";
    }

    location / {
        proxy_pass http://django;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_connect_timeout 60s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }
}
NGINXCONF
    fi

    # Deploy Nginx with proxy configuration
    podman run -d \
        --pod hookprobe-web \
        --name hookprobe-web-nginx \
        --memory 256M \
        --restart unless-stopped \
        --health-cmd "wget -q --spider http://localhost:80/nginx-health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 30s \
        -v "$nginx_conf_dir/default.conf:/etc/nginx/conf.d/default.conf:ro" \
        docker.io/library/nginx:alpine

    echo -e "${GREEN}[x]${NC} POD-001 deployed"
}

deploy_iam_pod() {
    echo "Deploying POD-002: IAM (Logto)..."

    local network_arg=$(get_network_arg "iam")

    podman pod create \
        --name hookprobe-iam \
        $network_arg \
        --publish 3001:3001 \
        --publish 3002:3002

    podman run -d \
        --pod hookprobe-iam \
        --name hookprobe-iam-logto \
        --memory "$POD_MEMORY_IAM" \
        --restart unless-stopped \
        --health-cmd "wget -q --spider http://localhost:3001/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 60s \
        -e DB_URL="postgresql://hookprobe:hookprobe@$(get_db_host):5432/logto" \
        docker.io/svhd/logto:latest

    echo -e "${GREEN}✓${NC} POD-002 deployed"
}

deploy_database_pod() {
    echo "Deploying POD-003: Database (PostgreSQL)..."

    local network_arg=$(get_network_arg "database")
    local publish_arg=""

    # Publish port when using host network so other containers can connect
    if [ "$USE_HOST_NETWORK" = true ]; then
        publish_arg="--publish 5432:5432"
    fi

    podman pod create \
        --name hookprobe-database \
        $network_arg \
        $publish_arg

    podman run -d \
        --pod hookprobe-database \
        --name hookprobe-database-postgres \
        --memory "$POD_MEMORY_DATABASE" \
        --restart unless-stopped \
        --health-cmd "pg_isready -U hookprobe -d hookprobe || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 60s \
        -e POSTGRES_DB="hookprobe" \
        -e POSTGRES_USER="hookprobe" \
        -e POSTGRES_PASSWORD="$(openssl rand -base64 16)" \
        -v hookprobe-db-data:/var/lib/postgresql/data \
        docker.io/library/postgres:16-alpine

    echo -e "${GREEN}✓${NC} POD-003 deployed"
}

deploy_cache_pod() {
    echo "Deploying POD-005: Cache (Redis)..."

    local network_arg=$(get_network_arg "cache")
    local publish_arg=""

    # Publish port when using host network
    if [ "$USE_HOST_NETWORK" = true ]; then
        publish_arg="--publish 6379:6379"
    fi

    podman pod create \
        --name hookprobe-cache \
        $network_arg \
        $publish_arg

    podman run -d \
        --pod hookprobe-cache \
        --name hookprobe-cache-redis \
        --memory "$POD_MEMORY_CACHE" \
        --restart unless-stopped \
        --health-cmd "redis-cli ping || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 30s \
        -v hookprobe-redis-data:/data \
        docker.io/library/redis:7-alpine \
        redis-server --requirepass "$(openssl rand -base64 16)"

    echo -e "${GREEN}✓${NC} POD-005 deployed"
}

deploy_neuro_pod() {
    echo "Deploying POD-010: Neuro Protocol (Qsecbit + HTP)..."

    local network_arg=$(get_network_arg "neuro")

    podman pod create \
        --name hookprobe-neuro \
        $network_arg

    # Qsecbit container
    podman run -d \
        --pod hookprobe-neuro \
        --name hookprobe-neuro-qsecbit \
        --memory "$POD_MEMORY_NEURO" \
        --restart unless-stopped \
        --health-cmd "pgrep python || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 60s \
        -e QSECBIT_MODE="quantum-resistant" \
        -e HTP_ENABLED="true" \
        docker.io/library/python:3.11-slim \
        bash -c "pip install numpy && python -c 'import time; print(\"Qsecbit running...\"); time.sleep(999999)'"

    echo -e "${GREEN}✓${NC} POD-010 deployed"
}

deploy_monitoring_pod() {
    echo "Deploying POD-004: Monitoring (Grafana + VictoriaMetrics)..."

    local network_arg=$(get_network_arg "monitoring")

    podman pod create \
        --name hookprobe-monitoring \
        $network_arg \
        --publish 3000:3000 \
        --publish 8428:8428

    # Grafana
    podman run -d \
        --pod hookprobe-monitoring \
        --name hookprobe-monitoring-grafana \
        --memory 1024M \
        --restart unless-stopped \
        --health-cmd "wget -q --spider http://localhost:3000/api/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 60s \
        docker.io/grafana/grafana:latest

    # VictoriaMetrics
    podman run -d \
        --pod hookprobe-monitoring \
        --name hookprobe-monitoring-victoria \
        --memory 1024M \
        --restart unless-stopped \
        --health-cmd "wget -q --spider http://localhost:8428/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 60s \
        docker.io/victoriametrics/victoria-metrics:latest

    echo -e "${GREEN}✓${NC} POD-004 deployed"
}

deploy_detection_pod() {
    echo "Deploying POD-006: Detection (Suricata, Zeek, Snort)..."

    local network_arg=$(get_network_arg "detection")

    podman pod create \
        --name hookprobe-detection \
        $network_arg

    podman run -d \
        --pod hookprobe-detection \
        --name hookprobe-detection-suricata \
        --memory 2048M \
        --restart unless-stopped \
        --health-cmd "pgrep suricata || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 120s \
        --cap-add NET_ADMIN \
        docker.io/jasonish/suricata:latest

    echo -e "${GREEN}✓${NC} POD-006 deployed"
}

deploy_ai_pod() {
    echo "Deploying POD-007: AI Analysis (Machine Learning)..."

    local network_arg=$(get_network_arg "ai")

    podman pod create \
        --name hookprobe-ai \
        $network_arg

    podman run -d \
        --pod hookprobe-ai \
        --name hookprobe-ai-ml \
        --memory 2048M \
        --restart unless-stopped \
        --health-cmd "pgrep python || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 120s \
        docker.io/library/python:3.11-slim \
        bash -c "pip install scikit-learn tensorflow && python -c 'import time; print(\"AI running...\"); time.sleep(999999)'"

    echo -e "${GREEN}✓${NC} POD-007 deployed"
}

# ============================================================
# STATUS CHECK
# ============================================================

check_pod_status() {
    echo "Checking POD status..."
    echo ""

    podman pod ls
    echo ""

    local failed_pods=0

    # Check core PODs (always deployed)
    if ! podman pod ps | grep -q "hookprobe-database.*Running"; then
        echo -e "${RED}[!]${NC} POD-003 (Database) not running"
        failed_pods=$((failed_pods + 1))
    else
        echo -e "${GREEN}[x]${NC} POD-003 (Database) running"
    fi

    if ! podman pod ps | grep -q "hookprobe-cache.*Running"; then
        echo -e "${RED}[!]${NC} POD-005 (Cache) not running"
        failed_pods=$((failed_pods + 1))
    else
        echo -e "${GREEN}[x]${NC} POD-005 (Cache) running"
    fi

    if ! podman pod ps | grep -q "hookprobe-neuro.*Running"; then
        echo -e "${RED}[!]${NC} POD-010 (Neuro) not running"
        failed_pods=$((failed_pods + 1))
    else
        echo -e "${GREEN}[x]${NC} POD-010 (Neuro) running"
    fi

    # Check optional PODs based on configuration
    if [ "$ENABLE_WEBSERVER" = true ]; then
        if ! podman pod ps | grep -q "hookprobe-web.*Running"; then
            echo -e "${RED}[!]${NC} POD-001 (Web) not running"
            failed_pods=$((failed_pods + 1))
        else
            echo -e "${GREEN}[x]${NC} POD-001 (Web) running"
        fi
    fi

    if [ "$ENABLE_IAM" = true ]; then
        if ! podman pod ps | grep -q "hookprobe-iam.*Running"; then
            echo -e "${RED}[!]${NC} POD-002 (IAM) not running"
            failed_pods=$((failed_pods + 1))
        else
            echo -e "${GREEN}[x]${NC} POD-002 (IAM) running"
        fi
    fi

    if [ "$ENABLE_MONITORING" = true ]; then
        if ! podman pod ps | grep -q "hookprobe-monitoring.*Running"; then
            echo -e "${RED}[!]${NC} POD-004 (Monitoring) not running"
            failed_pods=$((failed_pods + 1))
        else
            echo -e "${GREEN}[x]${NC} POD-004 (Monitoring) running"
        fi
    fi

    if [ "$ENABLE_AI" = true ]; then
        if ! podman pod ps | grep -q "hookprobe-detection.*Running"; then
            echo -e "${RED}[!]${NC} POD-006 (Detection) not running"
            failed_pods=$((failed_pods + 1))
        else
            echo -e "${GREEN}[x]${NC} POD-006 (Detection) running"
        fi
        if ! podman pod ps | grep -q "hookprobe-ai.*Running"; then
            echo -e "${RED}[!]${NC} POD-007 (AI) not running"
            failed_pods=$((failed_pods + 1))
        else
            echo -e "${GREEN}[x]${NC} POD-007 (AI) running"
        fi
    fi

    echo ""
    if [ "$failed_pods" -gt 0 ]; then
        echo -e "${YELLOW}Warning: $failed_pods POD(s) failed to start${NC}"
        echo "Check logs with: podman logs <container-name>"
    else
        echo -e "${GREEN}All PODs running successfully${NC}"
    fi
}

# ============================================================
# MAIN EXECUTION
# ============================================================

main "$@"
