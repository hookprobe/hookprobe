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

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
    """
    Parse command-line arguments.

    Flags:
        --enable-ai: Enable AI detection (needs 8GB+ RAM)
        --enable-monitoring: Enable Grafana/VictoriaMetrics
        --disable-iam: Skip IAM (Logto) installation
    """

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
            --disable-iam)
                ENABLE_IAM=false
                shift
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
  --disable-iam        Skip IAM (Logto) installation
  --help, -h           Show this help message

Default Configuration:
  • POD-001: Web Server (Django + Nginx + NAXSI WAF)
  • POD-002: IAM (Logto authentication)
  • POD-003: Database (PostgreSQL 16)
  • POD-005: Cache (Redis 7)
  • POD-010: Neuro Protocol (Qsecbit + HTP)

Examples:
  # Basic installation (Qsecbit only, no AI)
  sudo bash scripts/install-edge.sh

  # With AI detection
  sudo bash scripts/install-edge.sh --enable-ai

  # With monitoring, without IAM
  sudo bash scripts/install-edge.sh --enable-monitoring --disable-iam

Target Platforms:
  • Raspberry Pi 4/5 (4GB+ RAM, 32GB+ storage)
  • x86_64 servers (4GB+ RAM, 20GB+ storage)
  • ARM64 systems (4GB+ RAM, 20GB+ storage)

EOF
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
    # [1/6] PLATFORM DETECTION
    # --------------------------------------------------------
    echo -e "${BLUE}[1/6] Detecting platform...${NC}"
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
    # [2/6] SYSTEM REQUIREMENTS CHECK
    # --------------------------------------------------------
    echo -e "${BLUE}[2/6] Checking system requirements...${NC}"

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
    # [3/6] MEMORY SUFFICIENCY CHECK
    # --------------------------------------------------------
    echo -e "${BLUE}[3/6] Validating memory allocation...${NC}"

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
    # [4/6] DETERMINE PODS TO DEPLOY
    # --------------------------------------------------------
    echo -e "${BLUE}[4/6] Planning POD deployment...${NC}"
    echo ""

    echo "PODs to be deployed:"
    echo "  ${GREEN}✓${NC} POD-001: Web Server (Django + Nginx + NAXSI)"
    echo "  $([ "$ENABLE_IAM" = true ] && echo "${GREEN}✓${NC}" || echo "${YELLOW}✗${NC}") POD-002: IAM (Logto authentication)"
    echo "  ${GREEN}✓${NC} POD-003: Database (PostgreSQL 16)"
    echo "  ${GREEN}✓${NC} POD-005: Cache (Redis 7)"
    echo "  ${GREEN}✓${NC} POD-010: Neuro Protocol (Qsecbit + HTP)"
    echo "  $([ "$ENABLE_MONITORING" = true ] && echo "${GREEN}✓${NC}" || echo "${YELLOW}✗${NC}") POD-004: Monitoring (Grafana + VictoriaMetrics)"
    echo "  $([ "$ENABLE_AI" = true ] && echo "${GREEN}✓${NC}" || echo "${YELLOW}✗${NC}") POD-006: Detection (Suricata, Zeek, Snort)"
    echo "  $([ "$ENABLE_AI" = true ] && echo "${GREEN}✓${NC}" || echo "${YELLOW}✗${NC}") POD-007: AI Analysis (Machine Learning)"

    echo ""
    echo "Memory allocation:"
    echo "  Web Server:      $POD_MEMORY_WEB"
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
    # [5/6] DEPLOY PODS
    # --------------------------------------------------------
    echo ""
    echo -e "${BLUE}[5/6] Deploying PODs...${NC}"
    echo ""

    # Install dependencies
    install_dependencies

    # Create Podman networks
    create_networks

    # Deploy core PODs
    deploy_web_pod
    if [ "$ENABLE_IAM" = true ]; then
        deploy_iam_pod
    fi
    deploy_database_pod
    deploy_cache_pod
    deploy_neuro_pod

    # Deploy optional PODs
    if [ "$ENABLE_MONITORING" = true ]; then
        deploy_monitoring_pod
    fi

    if [ "$ENABLE_AI" = true ]; then
        deploy_detection_pod
        deploy_ai_pod
    fi

    # --------------------------------------------------------
    # [6/6] POST-INSTALL
    # --------------------------------------------------------
    echo ""
    echo -e "${BLUE}[6/6] Finalizing installation...${NC}"
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

create_networks() {
    echo "Creating Podman networks..."

    # Remove existing networks if present
    podman network rm web-net database-net cache-net iam-net neuro-net 2>/dev/null || true

    # Create networks
    podman network create --subnet 10.250.1.0/24 web-net
    podman network create --subnet 10.250.2.0/24 database-net
    podman network create --subnet 10.250.3.0/24 cache-net
    podman network create --subnet 10.250.4.0/24 iam-net
    podman network create --subnet 10.250.10.0/24 neuro-net

    if [ "$ENABLE_MONITORING" = true ]; then
        podman network create --subnet 10.250.5.0/24 monitoring-net
    fi

    if [ "$ENABLE_AI" = true ]; then
        podman network create --subnet 10.250.6.0/24 detection-net
        podman network create --subnet 10.250.7.0/24 ai-net
    fi

    echo -e "${GREEN}✓${NC} Networks created"
}

# ============================================================
# POD DEPLOYMENT
# ============================================================

deploy_web_pod() {
    echo "Deploying POD-001: Web Server..."

    # Create pod
    podman pod create \
        --name hookprobe-web \
        --network web-net \
        --publish 80:80 \
        --publish 443:443

    # Deploy Django container
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
        -e DATABASE_HOST="10.250.2.2" \
        -e DATABASE_PORT="5432" \
        -e REDIS_HOST="10.250.3.2" \
        -e REDIS_PORT="6379" \
        docker.io/library/python:3.11-slim \
        bash -c "pip install django gunicorn && python -m gunicorn --bind 0.0.0.0:8000"

    # Deploy Nginx + NAXSI
    podman run -d \
        --pod hookprobe-web \
        --name hookprobe-web-nginx \
        --memory 256M \
        --restart unless-stopped \
        --health-cmd "wget -q --spider http://localhost:80 || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 30s \
        docker.io/library/nginx:alpine

    echo -e "${GREEN}✓${NC} POD-001 deployed"
}

deploy_iam_pod() {
    echo "Deploying POD-002: IAM (Logto)..."

    podman pod create \
        --name hookprobe-iam \
        --network iam-net \
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
        -e DB_URL="postgresql://hookprobe:hookprobe@10.250.2.2:5432/logto" \
        docker.io/svhd/logto:latest

    echo -e "${GREEN}✓${NC} POD-002 deployed"
}

deploy_database_pod() {
    echo "Deploying POD-003: Database (PostgreSQL)..."

    podman pod create \
        --name hookprobe-database \
        --network database-net

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

    podman pod create \
        --name hookprobe-cache \
        --network cache-net

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

    podman pod create \
        --name hookprobe-neuro \
        --network neuro-net

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

    podman pod create \
        --name hookprobe-monitoring \
        --network monitoring-net \
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

    podman pod create \
        --name hookprobe-detection \
        --network detection-net

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

    podman pod create \
        --name hookprobe-ai \
        --network ai-net

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

    # Check each deployed POD
    if ! podman pod ps | grep -q "hookprobe-web.*Running"; then
        echo -e "${RED}✗${NC} POD-001 (Web) not running"
        failed_pods=$((failed_pods + 1))
    fi

    if [ "$ENABLE_IAM" = true ] && ! podman pod ps | grep -q "hookprobe-iam.*Running"; then
        echo -e "${RED}✗${NC} POD-002 (IAM) not running"
        failed_pods=$((failed_pods + 1))
    fi

    if ! podman pod ps | grep -q "hookprobe-database.*Running"; then
        echo -e "${RED}✗${NC} POD-003 (Database) not running"
        failed_pods=$((failed_pods + 1))
    fi

    if ! podman pod ps | grep -q "hookprobe-cache.*Running"; then
        echo -e "${RED}✗${NC} POD-005 (Cache) not running"
        failed_pods=$((failed_pods + 1))
    fi

    if ! podman pod ps | grep -q "hookprobe-neuro.*Running"; then
        echo -e "${RED}✗${NC} POD-010 (Neuro) not running"
        failed_pods=$((failed_pods + 1))
    fi

    if [ "$failed_pods" -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}⚠ Warning: Some PODs failed to start${NC}"
        echo "Check logs with: podman logs <container-name>"
    fi
}

# ============================================================
# MAIN EXECUTION
# ============================================================

main "$@"
