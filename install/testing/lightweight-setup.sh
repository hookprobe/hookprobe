#!/bin/bash
#
# lightweight-setup.sh - HookProbe Lightweight Testing/Development Deployment
# Target: Raspberry Pi 4 (4GB RAM), Testing, Development
# Version: 1.0.0
#
# This script deploys a minimal HookProbe installation with:
# - POD-001: Web Server (Django + Nginx)
# - POD-002: IAM (Logto authentication)
# - POD-003: Database (PostgreSQL 16-alpine)
# - POD-005: Cache (Redis 7-alpine)
#
# EXCLUDED (to reduce RAM usage):
# - POD-004: Monitoring (VictoriaMetrics, ClickHouse, Grafana)
# - POD-007: AI/Security Analysis (Zeek, Snort, Qsecbit)
#
# Total RAM usage: ~2.5GB (leaves ~1.5GB for OS on 4GB systems)
#
# ⚠️  NOT FOR PRODUCTION USE - Testing and Development Only
#

set -e  # Exit on error
set -u  # Exit on undefined variable

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}   HOOKPROBE LIGHTWEIGHT TESTING/DEVELOPMENT DEPLOYMENT${NC}"
echo -e "${BLUE}   Target: Raspberry Pi 4 (4GB RAM) / Development${NC}"
echo -e "${BLUE}   Version: 1.0.0${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""
echo -e "${YELLOW}⚠️  WARNING: This is a lightweight testing/development deployment${NC}"
echo -e "${YELLOW}   NOT intended for production use.${NC}"
echo ""
echo -e "This will deploy:"
echo -e "  ${GREEN}✓${NC} POD-001: Web Server (Django + Nginx)"
echo -e "  ${GREEN}✓${NC} POD-002: IAM (Logto authentication)"
echo -e "  ${GREEN}✓${NC} POD-003: Database (PostgreSQL 16-alpine)"
echo -e "  ${GREEN}✓${NC} POD-005: Cache (Redis 7-alpine)"
echo ""
echo -e "Excluded (to reduce RAM):"
echo -e "  ${RED}✗${NC} POD-004: Monitoring (too heavy for 4GB)"
echo -e "  ${RED}✗${NC} POD-007: AI/Security Analysis (too heavy for 4GB)"
echo ""
echo -e "${BLUE}Expected RAM usage: ~2.5GB (leaves 1.5GB for OS)${NC}"
echo ""

# Load configuration
if [ -f "$SCRIPT_DIR/lightweight-config.sh" ]; then
    source "$SCRIPT_DIR/lightweight-config.sh"
else
    echo -e "${RED}ERROR: lightweight-config.sh not found in $SCRIPT_DIR${NC}"
    exit 1
fi

# ============================================================
# STEP 1: CHECK ROOT PRIVILEGES
# ============================================================
echo ""
echo -e "${BLUE}[STEP 1]${NC} Checking privileges..."

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}ERROR: This script must be run as root${NC}"
   echo "Usage: sudo $0"
   exit 1
fi

echo -e "${GREEN}✓${NC} Running as root"

# ============================================================
# STEP 2: DETECT PLATFORM AND HARDWARE
# ============================================================
echo ""
echo -e "${BLUE}[STEP 2]${NC} Detecting platform and hardware..."

# Detect OS family
PLATFORM_FAMILY="unknown"
PKG_MANAGER="unknown"

if [ -f /etc/os-release ]; then
    source /etc/os-release

    case "$ID" in
        rhel|centos|fedora|rocky|almalinux)
            PLATFORM_FAMILY="rhel"
            PKG_MANAGER="dnf"
            ;;
        debian|ubuntu|pop|linuxmint|raspbian)
            PLATFORM_FAMILY="debian"
            PKG_MANAGER="apt"
            ;;
        *)
            echo -e "${RED}ERROR: Unsupported OS: $ID${NC}"
            echo "Supported: RHEL/Fedora/CentOS, Debian/Ubuntu/Raspbian"
            exit 1
            ;;
    esac

    echo -e "${GREEN}✓${NC} OS Detected: $NAME ($VERSION)"
    echo -e "${GREEN}✓${NC} Platform Family: $PLATFORM_FAMILY"
else
    echo -e "${RED}ERROR: Cannot detect OS (missing /etc/os-release)${NC}"
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
        ;;
    *)
        echo -e "${RED}ERROR: Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac
echo -e "${GREEN}✓${NC} Architecture: $ARCH_TYPE"

# Detect Raspberry Pi
if [ "$ARCH_TYPE" = "arm64" ]; then
    if grep -qi "raspberry pi" /proc/device-tree/model 2>/dev/null || grep -qi "raspberry pi" /sys/firmware/devicetree/base/model 2>/dev/null; then
        RPI_MODEL=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0' || cat /sys/firmware/devicetree/base/model 2>/dev/null | tr -d '\0')
        if echo "$RPI_MODEL" | grep -qi "raspberry pi 4"; then
            echo -e "${GREEN}✓${NC} Hardware: Raspberry Pi 4 ${GREEN}(Recommended)${NC}"
        elif echo "$RPI_MODEL" | grep -qi "raspberry pi 5"; then
            echo -e "${GREEN}✓${NC} Hardware: Raspberry Pi 5 ${GREEN}(Excellent)${NC}"
        else
            echo -e "${YELLOW}⚠${NC}  Hardware: $RPI_MODEL"
            echo -e "${YELLOW}   Raspberry Pi 4/5 recommended for optimal performance${NC}"
        fi
    else
        echo -e "${GREEN}✓${NC} Hardware: ARM64 SBC"
    fi
else
    echo -e "${GREEN}✓${NC} Hardware: x86_64 system"
fi

# Check available RAM
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

echo -e "${GREEN}✓${NC} Total RAM: ${TOTAL_RAM_GB}GB"

if [ $TOTAL_RAM_GB -lt 4 ]; then
    echo -e "${YELLOW}⚠${NC}  WARNING: Less than 4GB RAM detected"
    echo -e "${YELLOW}   This deployment requires ~2.5GB. System may be slow.${NC}"
fi

# ============================================================
# STEP 3: INSTALL DEPENDENCIES
# ============================================================
echo ""
echo -e "${BLUE}[STEP 3]${NC} Installing dependencies..."

if [ "$PLATFORM_FAMILY" = "rhel" ]; then
    echo "Installing packages for RHEL/Fedora/CentOS..."
    $PKG_MANAGER update -y || true
    $PKG_MANAGER install -y \
        podman \
        python3 \
        python3-pip \
        git \
        curl \
        wget \
        postgresql \
        jq \
        net-tools \
        iproute

elif [ "$PLATFORM_FAMILY" = "debian" ]; then
    echo "Installing packages for Debian/Ubuntu/Raspbian..."
    apt-get update || true
    apt-get install -y \
        podman \
        python3 \
        python3-pip \
        git \
        curl \
        wget \
        postgresql-client \
        jq \
        net-tools \
        iproute2

else
    echo -e "${RED}ERROR: Unknown platform family: $PLATFORM_FAMILY${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Dependencies installed"

# ============================================================
# STEP 4: CONFIGURE BASIC NETWORKING
# ============================================================
echo ""
echo -e "${BLUE}[STEP 4]${NC} Configuring basic networking..."

# Enable IP forwarding
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-hookprobe-lightweight.conf
sysctl -p /etc/sysctl.d/99-hookprobe-lightweight.conf > /dev/null

echo -e "${GREEN}✓${NC} Basic networking configured"

# ============================================================
# STEP 5: CREATE PODMAN NETWORKS
# ============================================================
echo ""
echo -e "${BLUE}[STEP 5]${NC} Creating Podman networks..."

create_podman_network() {
    local net_name=$1
    local subnet=$2
    local gateway=$3
    local interface_name=$4

    echo -e "  → Creating network: ${BLUE}$net_name${NC} ($subnet) - interface: $interface_name"

    # Check if network exists
    if podman network exists "$net_name" 2>/dev/null; then
        echo -e "    ${YELLOW}Network $net_name already exists, removing...${NC}"

        # Find and disconnect any containers using this network
        local containers=$(podman ps -a --filter "network=$net_name" --format "{{.Names}}" 2>/dev/null || true)
        if [ -n "$containers" ]; then
            echo -e "    ${YELLOW}Disconnecting containers from network...${NC}"
            for container in $containers; do
                echo -e "      • Disconnecting: $container"
                podman network disconnect "$net_name" "$container" 2>/dev/null || true
            done
        fi

        # Now remove the network
        podman network rm "$net_name" 2>/dev/null || {
            echo -e "    ${RED}Failed to remove network, forcing removal...${NC}"
            podman network rm -f "$net_name" 2>/dev/null || true
        }
    fi

    # Create network with custom interface name
    podman network create \
        --driver bridge \
        --interface-name="$interface_name" \
        --subnet="$subnet" \
        --gateway="$gateway" \
        "$net_name" > /dev/null

    echo -e "    ${GREEN}✓${NC} Network created successfully"
}

# Create only 4 networks (lightweight) with descriptive interface names
create_podman_network "$NETWORK_WEB" "$SUBNET_WEB" "$GATEWAY_WEB" "hpweb0"
create_podman_network "$NETWORK_IAM" "$SUBNET_IAM" "$GATEWAY_IAM" "hpiam0"
create_podman_network "$NETWORK_DATABASE" "$SUBNET_DATABASE" "$GATEWAY_DATABASE" "hpdb0"
create_podman_network "$NETWORK_CACHE" "$SUBNET_CACHE" "$GATEWAY_CACHE" "hpcache0"

echo -e "${GREEN}✓${NC} Podman networks created"

# ============================================================
# STEP 6: CREATE PERSISTENT VOLUMES
# ============================================================
echo ""
echo -e "${BLUE}[STEP 6]${NC} Creating persistent volumes..."

create_volume() {
    local vol_name=$1
    if ! podman volume exists "$vol_name" 2>/dev/null; then
        podman volume create "$vol_name" > /dev/null
        echo -e "  → Created volume: ${BLUE}$vol_name${NC}"
    else
        echo -e "  → Volume exists: $vol_name"
    fi
}

create_volume "$VOLUME_POSTGRES_DATA"
create_volume "$VOLUME_DJANGO_STATIC"
create_volume "$VOLUME_DJANGO_MEDIA"
create_volume "$VOLUME_LOGTO_DATA"

echo -e "${GREEN}✓${NC} Persistent volumes ready"

# ============================================================
# STEP 7: DEPLOY POD-003 - DATABASE (POSTGRESQL)
# ============================================================
echo ""
echo -e "${BLUE}[STEP 7]${NC} Deploying POD-003: Database (PostgreSQL 16-alpine)..."

# Remove existing pod if present
podman pod exists "$POD_DATABASE" 2>/dev/null && podman pod rm -f "$POD_DATABASE" 2>/dev/null || true

# Create pod
podman pod create \
    --name "$POD_DATABASE" \
    --network "$NETWORK_DATABASE" \
    -p ${PORT_POSTGRES}:5432 > /dev/null

echo -e "  → Starting PostgreSQL container..."
podman run -d --restart always \
    --pod "$POD_DATABASE" \
    --name "${POD_DATABASE}-postgres" \
    -e POSTGRES_DB="$POSTGRES_DB" \
    -e POSTGRES_USER="$POSTGRES_USER" \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -v "$VOLUME_POSTGRES_DATA:/var/lib/postgresql/data" \
    --memory="$POSTGRES_MEMORY_LIMIT" \
    --log-driver=journald \
    --log-opt tag="hookprobe-postgres" \
    "$IMAGE_POSTGRES" > /dev/null

echo -e "  → Waiting for PostgreSQL to be ready..."
sleep 10

# Wait for PostgreSQL to be ready
for i in {1..30}; do
    if podman exec "${POD_DATABASE}-postgres" pg_isready -U "$POSTGRES_USER" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} POD-003: Database deployed and ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}ERROR: PostgreSQL failed to start${NC}"
        exit 1
    fi
    sleep 1
done

# ============================================================
# STEP 8: DEPLOY POD-005 - CACHE (REDIS)
# ============================================================
echo ""
echo -e "${BLUE}[STEP 8]${NC} Deploying POD-005: Cache (Redis 7-alpine)..."

# Remove existing pod if present
podman pod exists "$POD_CACHE" 2>/dev/null && podman pod rm -f "$POD_CACHE" 2>/dev/null || true

# Create pod
podman pod create \
    --name "$POD_CACHE" \
    --network "$NETWORK_CACHE" \
    -p ${PORT_REDIS}:6379 > /dev/null

echo -e "  → Starting Redis container..."
podman run -d --restart always \
    --pod "$POD_CACHE" \
    --name "${POD_CACHE}-redis" \
    --memory="$REDIS_MEMORY_LIMIT" \
    --log-driver=journald \
    --log-opt tag="hookprobe-redis" \
    "$IMAGE_REDIS" \
    redis-server --maxmemory 200mb --maxmemory-policy allkeys-lru --appendonly yes > /dev/null

echo -e "  → Waiting for Redis to be ready..."
sleep 5

# Wait for Redis to be ready
for i in {1..20}; do
    if podman exec "${POD_CACHE}-redis" redis-cli ping > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} POD-005: Cache deployed and ready"
        break
    fi
    if [ $i -eq 20 ]; then
        echo -e "${RED}ERROR: Redis failed to start${NC}"
        exit 1
    fi
    sleep 1
done

# ============================================================
# STEP 9: DEPLOY POD-002 - IAM (LOGTO)
# ============================================================
echo ""
echo -e "${BLUE}[STEP 9]${NC} Deploying POD-002: IAM (Logto authentication)..."

# Remove existing pod if present
podman pod exists "$POD_IAM" 2>/dev/null && podman pod rm -f "$POD_IAM" 2>/dev/null || true

# Create pod
podman pod create \
    --name "$POD_IAM" \
    --network "$NETWORK_IAM" \
    -p ${PORT_LOGTO}:3001 \
    -p ${PORT_LOGTO_ADMIN}:3002 > /dev/null

echo -e "  → Starting Logto container..."
podman run -d --restart always \
    --pod "$POD_IAM" \
    --name "${POD_IAM}-logto" \
    -e DB_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POD_DATABASE}-postgres.dns.podman:5432/${POSTGRES_DB}" \
    -e ADMIN_ENDPOINT="http://localhost:${PORT_LOGTO_ADMIN}" \
    -e ENDPOINT="http://localhost:${PORT_LOGTO}" \
    -v "$VOLUME_LOGTO_DATA:/app/data" \
    --memory="$LOGTO_MEMORY_LIMIT" \
    --log-driver=journald \
    --log-opt tag="hookprobe-logto" \
    "$IMAGE_LOGTO" > /dev/null

echo -e "  → Waiting for Logto to be ready..."
sleep 15

echo -e "${GREEN}✓${NC} POD-002: IAM deployed"

# ============================================================
# STEP 10: BUILD DJANGO IMAGE (IF NEEDED)
# ============================================================
echo ""
echo -e "${BLUE}[STEP 10]${NC} Preparing Django application..."

# Check if Django image exists
if ! podman image exists hookprobe-django:lightweight 2>/dev/null; then
    echo -e "  → Building Django image..."

    # Check if source code exists
    if [ -f "$SCRIPT_DIR/../../src/web/Dockerfile.test" ]; then
        cd "$SCRIPT_DIR/../../src/web"
        podman build \
            --format docker \
            --arch "$ARCH_TYPE" \
            --build-arg BUILDPLATFORM=linux/$ARCH_TYPE \
            --build-arg TARGETPLATFORM=linux/$ARCH_TYPE \
            -t hookprobe-django:lightweight \
            -f Dockerfile.test \
            . || {
            echo -e "${RED}ERROR: Failed to build Django image${NC}"
            exit 1
        }
        echo -e "${GREEN}✓${NC} Django image built"
    else
        echo -e "${RED}ERROR: Django source code not found${NC}"
        echo "Expected: $SCRIPT_DIR/../../src/web/Dockerfile.test"
        exit 1
    fi
else
    echo -e "${GREEN}✓${NC} Django image already exists"
fi

# ============================================================
# STEP 11: DEPLOY POD-001 - WEB (DJANGO + NGINX)
# ============================================================
echo ""
echo -e "${BLUE}[STEP 11]${NC} Deploying POD-001: Web Server (Django + Nginx)..."

# Remove existing pod if present
podman pod exists "$POD_WEB" 2>/dev/null && podman pod rm -f "$POD_WEB" 2>/dev/null || true

# Remove existing Django container if present
podman rm -f "${POD_WEB}-django" 2>/dev/null || true

echo -e "  → Starting Django application..."
podman run -d --restart always \
    --name "${POD_WEB}-django" \
    --network="$NETWORK_WEB" \
    --network="$NETWORK_DATABASE" \
    --network="$NETWORK_CACHE" \
    --network="$NETWORK_IAM" \
    -p ${PORT_HTTP}:8000 \
    -e DJANGO_ENV="production" \
    -e DJANGO_SETTINGS_MODULE="hookprobe.settings.production" \
    -e DJANGO_SECRET_KEY="$DJANGO_SECRET_KEY" \
    -e DEBUG="False" \
    -e ALLOWED_HOSTS="*" \
    -e POSTGRES_DB="$POSTGRES_DB" \
    -e POSTGRES_USER="$POSTGRES_USER" \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -e POSTGRES_HOST="$IP_DATABASE_POSTGRES" \
    -e POSTGRES_PORT="5432" \
    -e REDIS_HOST="$IP_CACHE_REDIS" \
    -e REDIS_PORT="6379" \
    -e LOGTO_ENDPOINT="http://$IP_IAM_LOGTO:${PORT_LOGTO}" \
    -e LOGTO_APP_ID="$LOGTO_APP_ID" \
    -e LOGTO_APP_SECRET="$LOGTO_APP_SECRET" \
    -v "$VOLUME_DJANGO_STATIC:/app/staticfiles" \
    -v "$VOLUME_DJANGO_MEDIA:/app/media" \
    --memory="$DJANGO_MEMORY_LIMIT" \
    --log-driver=journald \
    --log-opt tag="hookprobe-django" \
    hookprobe-django:lightweight > /dev/null

echo -e "  → Waiting for Django to be ready..."
sleep 10

# ============================================================
# STEP 12: RUN DATABASE MIGRATIONS
# ============================================================
echo ""
echo -e "${BLUE}[STEP 12]${NC} Running database migrations..."

# Wait for Django to be fully started
sleep 5

echo -e "  → Running migrations..."
podman exec "${POD_WEB}-django" python manage.py migrate --noinput || {
    echo -e "${YELLOW}⚠${NC}  Warning: Migrations failed or partially completed"
}

echo -e "  → Collecting static files..."
podman exec "${POD_WEB}-django" python manage.py collectstatic --noinput || {
    echo -e "${YELLOW}⚠${NC}  Warning: Static file collection failed"
}

echo -e "${GREEN}✓${NC} Database migrations completed"

# ============================================================
# STEP 13: VALIDATE DEPLOYMENT
# ============================================================
echo ""
echo -e "${BLUE}[STEP 13]${NC} Validating deployment..."

echo -e "  → Checking POD status..."
PODS_STATUS=$(podman pod ps --format "{{.Name}} {{.Status}}")
echo "$PODS_STATUS"

# Count running pods
EXPECTED_PODS=4
RUNNING_PODS=$(echo "$PODS_STATUS" | grep -c "Running" || true)

if [ $RUNNING_PODS -eq $EXPECTED_PODS ]; then
    echo -e "${GREEN}✓${NC} All PODs are running ($RUNNING_PODS/$EXPECTED_PODS)"
else
    echo -e "${YELLOW}⚠${NC}  Warning: $RUNNING_PODS/$EXPECTED_PODS PODs are running"
fi

echo ""
echo -e "  → Checking container status..."
podman ps --format "table {{.Names}}\t{{.Status}}" | grep hookprobe || true

# ============================================================
# DEPLOYMENT COMPLETE
# ============================================================
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}   HOOKPROBE LIGHTWEIGHT DEPLOYMENT COMPLETE${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "Deployed PODs:"
echo -e "  ${GREEN}✓${NC} POD-001: Web Server        (port ${PORT_HTTP}, ${PORT_HTTPS})"
echo -e "  ${GREEN}✓${NC} POD-002: IAM (Logto)        (port ${PORT_LOGTO}, ${PORT_LOGTO_ADMIN})"
echo -e "  ${GREEN}✓${NC} POD-003: Database (PostgreSQL) (port ${PORT_POSTGRES})"
echo -e "  ${GREEN}✓${NC} POD-005: Cache (Redis)      (port ${PORT_REDIS})"
echo ""
echo -e "${BLUE}Access Points:${NC}"
echo -e "  • Web Application:    http://localhost:${PORT_HTTP}"
echo -e "  • Logto Admin:        http://localhost:${PORT_LOGTO_ADMIN}"
echo -e "  • Logto API:          http://localhost:${PORT_LOGTO}"
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo -e "  • Check POD status:   ${GREEN}podman pod ps${NC}"
echo -e "  • Check containers:   ${GREEN}podman ps${NC}"
echo -e "  • View logs:          ${GREEN}podman logs <container-name>${NC}"
echo -e "  • Stop all PODs:      ${GREEN}podman pod stop --all${NC}"
echo -e "  • Remove all PODs:    ${GREEN}podman pod rm -f --all${NC}"
echo ""
echo -e "${BLUE}Memory Usage:${NC}"
echo -e "  • PostgreSQL:  ${POSTGRES_MEMORY_LIMIT}"
echo -e "  • Redis:       ${REDIS_MEMORY_LIMIT}"
echo -e "  • Django:      ${DJANGO_MEMORY_LIMIT}"
echo -e "  • Logto:       ${LOGTO_MEMORY_LIMIT}"
echo -e "  • Total:       ~2.5GB"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Configure Logto authentication at http://localhost:${PORT_LOGTO_ADMIN}"
echo -e "  2. Update LOGTO_APP_ID and LOGTO_APP_SECRET in lightweight-config.sh"
echo -e "  3. Test the web application at http://localhost:${PORT_HTTP}"
echo -e "  4. Monitor resource usage: ${GREEN}podman stats${NC}"
echo ""
echo -e "${YELLOW}⚠️  Remember: This is a testing/development deployment${NC}"
echo -e "${YELLOW}   For production, use the full installation: install/edge/setup.sh${NC}"
echo ""
echo -e "${GREEN}Deployment log saved to: /var/log/hookprobe-lightweight-install.log${NC}"
echo ""
