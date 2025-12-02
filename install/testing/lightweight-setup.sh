#!/bin/bash
#
# lightweight-setup.sh - HookProbe Lightweight Testing/Development Setup
# Optimized for resource-constrained devices (Raspberry Pi 4B 4GB RAM)
# Version: 5.0.0
#
# This script provides a minimal HookProbe installation suitable for:
# - Development and testing
# - Learning and experimentation
# - Resource-constrained devices (4-8GB RAM)
#

set -e  # Exit on error
set -u  # Exit on undefined variable

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "   HOOKPROBE v5.0 - LIGHTWEIGHT TESTING/DEVELOPMENT SETUP"
echo "   Optimized for Raspberry Pi 4B / Low-Resource Devices"
echo "============================================================"

# ============================================================
# CONFIGURATION - Minimal Setup
# ============================================================

# Volume names (simplified for testing)
VOLUME_POSTGRES_DATA="${VOLUME_POSTGRES_DATA:-hookprobe-postgres-test}"
VOLUME_DJANGO_STATIC="${VOLUME_DJANGO_STATIC:-hookprobe-django-static-test}"
VOLUME_DJANGO_MEDIA="${VOLUME_DJANGO_MEDIA:-hookprobe-django-media-test}"
VOLUME_VICTORIAMETRICS_DATA="${VOLUME_VICTORIAMETRICS_DATA:-hookprobe-victoriametrics-test}"
VOLUME_GRAFANA_DATA="${VOLUME_GRAFANA_DATA:-hookprobe-grafana-test}"
VOLUME_QSECBIT_DATA="${VOLUME_QSECBIT_DATA:-hookprobe-qsecbit-test}"

# Container/Pod names
POD_WEB="${POD_WEB:-hookprobe-web-test}"
POD_DATABASE="${POD_DATABASE:-hookprobe-database-test}"
POD_MONITORING="${POD_MONITORING:-hookprobe-monitoring-test}"

# Port mappings
PORT_HTTP="${PORT_HTTP:-8000}"
PORT_HTTPS="${PORT_HTTPS:-8443}"
PORT_POSTGRES="${PORT_POSTGRES:-5432}"
PORT_GRAFANA="${PORT_GRAFANA:-3000}"

# Installation mode
INSTALL_MODE="${INSTALL_MODE:-minimal}"  # minimal, standard, full

# ============================================================
# STEP 1: DETECT PLATFORM
# ============================================================
echo ""
echo "[STEP 1] Detecting platform..."

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root or with sudo"
   exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    source /etc/os-release
    PLATFORM_OS="$NAME"
    echo "✓ OS Detected: $NAME ($VERSION_ID)"
else
    echo "ERROR: Cannot detect OS (missing /etc/os-release)"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ARCH_TYPE="x86_64"
        ;;
    aarch64|arm64)
        ARCH_TYPE="arm64"
        echo "✓ ARM64 detected (Raspberry Pi compatible)"
        ;;
    armv7l)
        echo "ERROR: ARMv7 (32-bit) is not supported. Use ARMv8/ARM64."
        exit 1
        ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac
echo "✓ Architecture: $ARCH_TYPE"

# ============================================================
# STEP 2: CHECK SYSTEM RESOURCES
# ============================================================
echo ""
echo "[STEP 2] Checking system resources..."

# Check RAM
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

echo "✓ Total RAM: ${TOTAL_RAM_GB}GB"

if [ "$TOTAL_RAM_GB" -lt 2 ]; then
    echo "ERROR: Minimum 2GB RAM required. Found: ${TOTAL_RAM_GB}GB"
    exit 1
elif [ "$TOTAL_RAM_GB" -lt 4 ]; then
    echo "⚠ WARNING: Low RAM (${TOTAL_RAM_GB}GB). Some services will be disabled."
    INSTALL_MODE="minimal"
fi

# Check disk space
AVAILABLE_SPACE=$(df -BG / | tail -1 | awk '{print $4}' | sed 's/G//')
echo "✓ Available disk space: ${AVAILABLE_SPACE}GB"

if [ "$AVAILABLE_SPACE" -lt 10 ]; then
    echo "ERROR: Minimum 10GB free disk space required"
    exit 1
fi

# ============================================================
# STEP 3: INSTALL CONTAINER RUNTIME
# ============================================================
echo ""
echo "[STEP 3] Installing container runtime..."

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
else
    echo "ERROR: No supported package manager found"
    exit 1
fi

# Check if Docker or Podman is installed
if command -v podman &> /dev/null; then
    CONTAINER_RUNTIME="podman"
    echo "✓ Podman already installed: $(podman --version)"
elif command -v docker &> /dev/null; then
    CONTAINER_RUNTIME="docker"
    echo "✓ Docker already installed: $(docker --version)"
else
    echo "Installing Podman..."

    case "$PKG_MANAGER" in
        apt)
            apt-get update
            apt-get install -y podman
            ;;
        dnf|yum)
            $PKG_MANAGER install -y podman
            ;;
    esac

    CONTAINER_RUNTIME="podman"
    echo "✓ Podman installed: $(podman --version)"
fi

# ============================================================
# STEP 4: INSTALL REQUIRED TOOLS
# ============================================================
echo ""
echo "[STEP 4] Installing required tools..."

REQUIRED_TOOLS="python3 python3-pip git curl wget"

case "$PKG_MANAGER" in
    apt)
        apt-get update
        apt-get install -y $REQUIRED_TOOLS
        ;;
    dnf|yum)
        $PKG_MANAGER install -y $REQUIRED_TOOLS
        ;;
esac

echo "✓ Required tools installed"

# ============================================================
# STEP 5: CONFIGURE CONTAINER RUNTIME
# ============================================================
echo ""
echo "[STEP 5] Configuring container runtime..."

if [ "$CONTAINER_RUNTIME" = "podman" ]; then
    # Enable podman socket for rootless mode (if not root)
    if [[ $EUID -eq 0 ]]; then
        systemctl enable --now podman.socket || true
    else
        systemctl --user enable --now podman.socket || true
    fi
    echo "✓ Podman socket enabled"
fi

# ============================================================
# STEP 6: CREATE PERSISTENT VOLUMES
# ============================================================
echo ""
echo "[STEP 6] Creating persistent volumes..."

create_volume() {
    local volume_name="$1"

    if [ "$CONTAINER_RUNTIME" = "podman" ]; then
        if ! podman volume exists "$volume_name" 2>/dev/null; then
            podman volume create "$volume_name"
            echo "✓ Created volume: $volume_name"
        else
            echo "✓ Volume already exists: $volume_name"
        fi
    else
        if ! docker volume inspect "$volume_name" &>/dev/null; then
            docker volume create "$volume_name"
            echo "✓ Created volume: $volume_name"
        else
            echo "✓ Volume already exists: $volume_name"
        fi
    fi
}

# Create all required volumes
create_volume "$VOLUME_POSTGRES_DATA"
create_volume "$VOLUME_DJANGO_STATIC"
create_volume "$VOLUME_DJANGO_MEDIA"
create_volume "$VOLUME_VICTORIAMETRICS_DATA"
create_volume "$VOLUME_GRAFANA_DATA"
create_volume "$VOLUME_QSECBIT_DATA"

# ============================================================
# STEP 7: PULL CONTAINER IMAGES
# ============================================================
echo ""
echo "[STEP 7] Pulling container images..."

pull_image() {
    local image="$1"
    echo "Pulling $image..."

    if [ "$CONTAINER_RUNTIME" = "podman" ]; then
        podman pull "$image"
    else
        docker pull "$image"
    fi
}

# Minimal image set for testing
pull_image "docker.io/library/postgres:16-alpine"
pull_image "docker.io/library/python:3.11-slim"
pull_image "docker.io/grafana/grafana:latest"
pull_image "docker.io/victoriametrics/victoria-metrics:latest"

echo "✓ Container images pulled"

# ============================================================
# STEP 8: CREATE NETWORK
# ============================================================
echo ""
echo "[STEP 8] Creating container network..."

NETWORK_NAME="hookprobe-test-net"

if [ "$CONTAINER_RUNTIME" = "podman" ]; then
    if ! podman network exists "$NETWORK_NAME" 2>/dev/null; then
        podman network create "$NETWORK_NAME"
        echo "✓ Created network: $NETWORK_NAME"
    else
        echo "✓ Network already exists: $NETWORK_NAME"
    fi
else
    if ! docker network inspect "$NETWORK_NAME" &>/dev/null; then
        docker network create "$NETWORK_NAME"
        echo "✓ Created network: $NETWORK_NAME"
    else
        echo "✓ Network already exists: $NETWORK_NAME"
    fi
fi

# ============================================================
# STEP 9: GENERATE CONFIGURATION
# ============================================================
echo ""
echo "[STEP 9] Generating configuration files..."

CONFIG_DIR="/opt/hookprobe/testing"
mkdir -p "$CONFIG_DIR"

# Create environment file
cat > "$CONFIG_DIR/env" <<EOF
# HookProbe Lightweight Testing Configuration
POSTGRES_PASSWORD=$(openssl rand -base64 32)
DJANGO_SECRET_KEY=$(openssl rand -base64 64)
DJANGO_DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
DATABASE_URL=postgresql://hookprobe:changeme@postgres:5432/hookprobe
REDIS_URL=redis://redis:6379/0
EOF

echo "✓ Configuration generated in $CONFIG_DIR"

# ============================================================
# STEP 10: CREATE START SCRIPT
# ============================================================
echo ""
echo "[STEP 10] Creating start script..."

cat > "$CONFIG_DIR/start-testing.sh" <<'EOFSTART'
#!/bin/bash
#
# start-testing.sh - Start HookProbe testing environment
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env"

CONTAINER_RUNTIME="podman"
if command -v docker &> /dev/null && ! command -v podman &> /dev/null; then
    CONTAINER_RUNTIME="docker"
fi

echo "Starting HookProbe testing environment..."

# Start PostgreSQL
$CONTAINER_RUNTIME run -d \
    --name hookprobe-postgres-test \
    --network hookprobe-test-net \
    -e POSTGRES_DB=hookprobe \
    -e POSTGRES_USER=hookprobe \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -v hookprobe-postgres-test:/var/lib/postgresql/data \
    postgres:16-alpine

echo "✓ PostgreSQL started"

# Start VictoriaMetrics
$CONTAINER_RUNTIME run -d \
    --name hookprobe-victoriametrics-test \
    --network hookprobe-test-net \
    -p 8428:8428 \
    -v hookprobe-victoriametrics-test:/victoria-metrics-data \
    victoriametrics/victoria-metrics:latest

echo "✓ VictoriaMetrics started"

# Start Grafana
$CONTAINER_RUNTIME run -d \
    --name hookprobe-grafana-test \
    --network hookprobe-test-net \
    -p 3000:3000 \
    -e GF_SECURITY_ADMIN_PASSWORD=admin \
    -v hookprobe-grafana-test:/var/lib/grafana \
    grafana/grafana:latest

echo "✓ Grafana started"

echo ""
echo "============================================================"
echo "   HookProbe Testing Environment Started"
echo "============================================================"
echo ""
echo "Services:"
echo "  - PostgreSQL: hookprobe-postgres-test (internal)"
echo "  - VictoriaMetrics: http://localhost:8428"
echo "  - Grafana: http://localhost:3000 (admin/admin)"
echo ""
echo "To stop: $SCRIPT_DIR/stop-testing.sh"
echo ""

EOFSTART

chmod +x "$CONFIG_DIR/start-testing.sh"

# ============================================================
# STEP 11: CREATE STOP SCRIPT
# ============================================================

cat > "$CONFIG_DIR/stop-testing.sh" <<'EOFSTOP'
#!/bin/bash
#
# stop-testing.sh - Stop HookProbe testing environment
#

CONTAINER_RUNTIME="podman"
if command -v docker &> /dev/null && ! command -v podman &> /dev/null; then
    CONTAINER_RUNTIME="docker"
fi

echo "Stopping HookProbe testing environment..."

for container in hookprobe-postgres-test hookprobe-victoriametrics-test hookprobe-grafana-test; do
    if $CONTAINER_RUNTIME ps -a --format "{{.Names}}" | grep -q "^${container}$"; then
        $CONTAINER_RUNTIME stop "$container" 2>/dev/null || true
        $CONTAINER_RUNTIME rm "$container" 2>/dev/null || true
        echo "✓ Stopped and removed: $container"
    fi
done

echo ""
echo "HookProbe testing environment stopped"

EOFSTOP

chmod +x "$CONFIG_DIR/stop-testing.sh"

echo "✓ Management scripts created"

# ============================================================
# INSTALLATION COMPLETE
# ============================================================
echo ""
echo "============================================================"
echo "   ✓ LIGHTWEIGHT TESTING/DEVELOPMENT SETUP COMPLETE"
echo "============================================================"
echo ""
echo "Installation Summary:"
echo "  - Configuration: $CONFIG_DIR"
echo "  - Container Runtime: $CONTAINER_RUNTIME"
echo "  - Install Mode: $INSTALL_MODE"
echo "  - System RAM: ${TOTAL_RAM_GB}GB"
echo ""
echo "Next Steps:"
echo "  1. Start testing environment:"
echo "     $CONFIG_DIR/start-testing.sh"
echo ""
echo "  2. Access services:"
echo "     - Grafana: http://localhost:3000 (admin/admin)"
echo "     - VictoriaMetrics: http://localhost:8428"
echo ""
echo "  3. Stop testing environment:"
echo "     $CONFIG_DIR/stop-testing.sh"
echo ""
echo "For development, see: https://github.com/hookprobe/hookprobe/wiki"
echo ""
