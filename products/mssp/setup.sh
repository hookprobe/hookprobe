#!/bin/bash
# =============================================================================
# HookProbe MSSP Setup Script v5.0
# Managed Security Service Provider - Central Brain Deployment
# =============================================================================
# This script deploys the MSSP tier with:
# - POD-based container architecture (Podman)
# - OVS bridge with OpenFlow SDN
# - VXLAN mesh with PSK encryption
# - PostgreSQL, Redis, ClickHouse, VictoriaMetrics
# - Django web application with Gunicorn
# - Logto IAM for authentication
# - HTP validator endpoint for edge device connectivity
# =============================================================================

set -e

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKPROBE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Version
MSSP_VERSION="5.0.0"

# Network Configuration
OVS_BRIDGE="mssp-bridge"
MSSP_NETWORK="10.200.0.0/16"
MSSP_GATEWAY="10.200.0.1"

# POD Networks - Using 172.20.x.x for Podman (separate from OVS 10.200.x.x)
# OVS uses 10.200.0.0/16 for VXLAN mesh connectivity to edge devices
# Podman uses 172.20.x.0/24 for container networking (no conflict)
declare -A POD_CONFIG=(
    ["pod-001-dmz"]="172.20.1.0/24:201"
    ["pod-002-iam"]="172.20.2.0/24:202"
    ["pod-003-db"]="172.20.3.0/24:203"
    ["pod-004-cache"]="172.20.4.0/24:204"
    ["pod-005-monitoring"]="172.20.5.0/24:205"
    ["pod-006-security"]="172.20.6.0/24:206"
    ["pod-007-response"]="172.20.7.0/24:207"
    ["pod-008-automation"]="172.20.8.0/24:208"
)

# Container Images (using Podman with docker.io registry)
declare -A CONTAINER_IMAGES=(
    ["nginx"]="docker.io/nginx:1.25-alpine"
    ["python"]="docker.io/python:3.11-slim-bookworm"
    ["postgres"]="docker.io/postgres:16-alpine"
    ["valkey"]="docker.io/valkey/valkey:7.2-alpine"
    ["clickhouse"]="docker.io/clickhouse/clickhouse-server:24.3"
    ["victoriametrics"]="docker.io/victoriametrics/victoria-metrics:v1.99.0"
    ["grafana"]="docker.io/grafana/grafana-oss:10.4.0"
    ["vector"]="docker.io/timberio/vector:0.37.0-alpine"
    ["logto"]="docker.io/svhd/logto:1.14"
    ["suricata"]="docker.io/jasonish/suricata:7.0"
    ["zeek"]="docker.io/zeek/zeek:6.2"
    ["n8n"]="docker.io/n8nio/n8n:1.34.0"
)

# Default Ports
declare -A SERVICE_PORTS=(
    ["nginx_http"]="80"
    ["nginx_https"]="443"
    ["django"]="8000"
    ["logto_api"]="3001"
    ["logto_admin"]="3002"
    ["postgres"]="5432"
    ["valkey"]="6379"
    ["clickhouse_http"]="8123"
    ["clickhouse_native"]="9000"
    ["victoriametrics"]="8428"
    ["grafana"]="3000"
    ["qsecbit_api"]="8888"
    ["n8n"]="5678"
    ["htp_udp"]="4478"
    ["htp_tcp"]="4478"
)

# Installation directories
MSSP_BASE_DIR="/opt/hookprobe/mssp"
MSSP_CONFIG_DIR="/etc/hookprobe/mssp"
MSSP_DATA_DIR="/var/lib/hookprobe/mssp"
MSSP_LOG_DIR="/var/log/hookprobe/mssp"
MSSP_SECRETS_DIR="/etc/hookprobe/secrets/mssp"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN} $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_requirements() {
    log_section "Checking System Requirements"

    local errors=0

    # Check RAM (minimum 8GB for POC, 16GB+ recommended)
    local ram_mb=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$ram_mb" -lt 16384 ]; then
        log_warning "RAM: ${ram_mb}MB (16GB+ recommended for production)"
        if [ "$ram_mb" -lt 8192 ]; then
            log_error "Insufficient RAM. MSSP requires at least 8GB for POC."
            ((errors++))
        fi
    else
        log_success "RAM: ${ram_mb}MB (OK)"
    fi

    # Check CPU cores (minimum 2 for POC, 4+ recommended)
    local cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 4 ]; then
        log_warning "CPU: ${cpu_cores} cores (4+ recommended)"
        if [ "$cpu_cores" -lt 2 ]; then
            log_error "Insufficient CPU cores. MSSP requires at least 2 cores."
            ((errors++))
        fi
    else
        log_success "CPU: ${cpu_cores} cores (OK)"
    fi

    # Check storage (minimum 20GB for POC, 100GB+ recommended)
    local storage_gb=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$storage_gb" -lt 100 ]; then
        log_warning "Storage: ${storage_gb}GB available (100GB+ recommended)"
        if [ "$storage_gb" -lt 20 ]; then
            log_error "Insufficient storage. MSSP requires at least 20GB."
            ((errors++))
        fi
    else
        log_success "Storage: ${storage_gb}GB available (OK)"
    fi

    # Check OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" && "$ID" != "debian" && "$ID_LIKE" != *"debian"* ]]; then
            log_error "Unsupported OS: $ID. MSSP requires Ubuntu/Debian."
            ((errors++))
        else
            log_success "OS: $PRETTY_NAME (OK)"
        fi
    fi

    # Check Podman
    if ! command -v podman &> /dev/null; then
        log_warning "Podman not installed. Will install."
    else
        local podman_version=$(podman --version | awk '{print $3}')
        log_success "Podman: $podman_version (OK)"
    fi

    # Check OVS
    if ! command -v ovs-vsctl &> /dev/null; then
        log_warning "OpenVSwitch not installed. Will install."
    else
        local ovs_version=$(ovs-vsctl --version | head -1 | awk '{print $4}')
        log_success "OpenVSwitch: $ovs_version (OK)"
    fi

    if [ $errors -gt 0 ]; then
        log_error "System requirements not met. Please resolve the issues above."
        exit 1
    fi

    log_success "All system requirements met"
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

install_dependencies() {
    log_section "Installing Dependencies"

    # Update package lists
    log_info "Updating package lists..."
    apt-get update -qq

    # Install base packages
    log_info "Installing base packages..."
    apt-get install -y -qq \
        curl \
        wget \
        git \
        jq \
        uuid-runtime \
        openssl \
        ca-certificates \
        gnupg \
        lsb-release \
        software-properties-common \
        python3 \
        python3-pip \
        python3-venv \
        nftables \
        iptables \
        iproute2 \
        bridge-utils \
        net-tools

    log_success "Base packages installed"
}

install_podman() {
    log_section "Installing Podman"

    if command -v podman &> /dev/null; then
        log_info "Podman already installed"
        return 0
    fi

    # Install Podman
    log_info "Installing Podman..."
    apt-get install -y -qq podman podman-compose

    # Enable and start Podman socket
    systemctl enable --now podman.socket

    # Configure Podman for rootless if needed
    log_info "Configuring Podman..."

    # Set default registry
    mkdir -p /etc/containers
    cat > /etc/containers/registries.conf << 'EOF'
unqualified-search-registries = ["docker.io", "quay.io", "ghcr.io"]

[[registry]]
location = "docker.io"
EOF

    log_success "Podman installed and configured"
}

install_openvswitch() {
    log_section "Installing OpenVSwitch"

    if command -v ovs-vsctl &> /dev/null; then
        log_info "OpenVSwitch already installed"
    else
        log_info "Installing OpenVSwitch..."
        apt-get install -y -qq openvswitch-switch openvswitch-common
    fi

    # Enable and start OVS
    systemctl enable --now openvswitch-switch

    # Wait for OVS to be ready
    sleep 2

    log_success "OpenVSwitch installed and running"
}

# =============================================================================
# DIRECTORY SETUP
# =============================================================================

create_directories() {
    log_section "Creating Directory Structure"

    # Create base directories
    local dirs=(
        "$MSSP_BASE_DIR"
        "$MSSP_BASE_DIR/containers"
        "$MSSP_BASE_DIR/django"
        "$MSSP_BASE_DIR/qsecbit"
        "$MSSP_BASE_DIR/htp"
        "$MSSP_CONFIG_DIR"
        "$MSSP_CONFIG_DIR/nginx"
        "$MSSP_CONFIG_DIR/nginx/ssl"
        "$MSSP_CONFIG_DIR/postgres"
        "$MSSP_CONFIG_DIR/clickhouse"
        "$MSSP_CONFIG_DIR/grafana"
        "$MSSP_CONFIG_DIR/logto"
        "$MSSP_CONFIG_DIR/openflow"
        "$MSSP_DATA_DIR"
        "$MSSP_DATA_DIR/postgres"
        "$MSSP_DATA_DIR/clickhouse"
        "$MSSP_DATA_DIR/clickhouse/format_schemas"
        "$MSSP_DATA_DIR/clickhouse/access"
        "$MSSP_DATA_DIR/victoriametrics"
        "$MSSP_DATA_DIR/grafana"
        "$MSSP_DATA_DIR/valkey"
        "$MSSP_DATA_DIR/n8n"
        "$MSSP_DATA_DIR/logto"
        "$MSSP_DATA_DIR/django/static"
        "$MSSP_DATA_DIR/django/media"
        "$MSSP_LOG_DIR"
        "$MSSP_SECRETS_DIR"
        "$MSSP_SECRETS_DIR/vxlan"
        "$MSSP_SECRETS_DIR/postgres"
        "$MSSP_SECRETS_DIR/django"
        "$MSSP_SECRETS_DIR/logto"
        "$MSSP_SECRETS_DIR/clickhouse"
        "$MSSP_SECRETS_DIR/grafana"
    )

    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        log_info "Created: $dir"
    done

    # Set permissions
    chmod 700 "$MSSP_SECRETS_DIR"
    chmod -R 700 "$MSSP_SECRETS_DIR"/*

    # Container data dirs need to be writable by container users
    # Django static/media (gunicorn user)
    chmod 777 "$MSSP_DATA_DIR/django/static"
    chmod 777 "$MSSP_DATA_DIR/django/media"

    # Grafana data dir (UID 472)
    chmod 777 "$MSSP_DATA_DIR/grafana"

    # ClickHouse data dirs (UID 101)
    chmod 777 "$MSSP_DATA_DIR/clickhouse"
    chmod 777 "$MSSP_DATA_DIR/clickhouse/format_schemas"
    chmod 777 "$MSSP_DATA_DIR/clickhouse/access"

    # n8n data dir (UID 1000)
    chmod 777 "$MSSP_DATA_DIR/n8n"

    # Logto data dir
    chmod 777 "$MSSP_DATA_DIR/logto"

    # VictoriaMetrics data dir
    chmod 777 "$MSSP_DATA_DIR/victoriametrics"

    # Valkey data dir
    chmod 777 "$MSSP_DATA_DIR/valkey"

    # PostgreSQL data dir (UID 70 on alpine)
    chmod 777 "$MSSP_DATA_DIR/postgres"

    log_success "Directory structure created"
}

# =============================================================================
# SECRET GENERATION
# =============================================================================

generate_secrets() {
    log_section "Generating Secrets"

    # VXLAN PSK
    if [ ! -f "$MSSP_SECRETS_DIR/vxlan/master.psk" ]; then
        openssl rand -hex 32 > "$MSSP_SECRETS_DIR/vxlan/master.psk"
        chmod 600 "$MSSP_SECRETS_DIR/vxlan/master.psk"
        log_info "Generated VXLAN PSK"
    fi

    # PostgreSQL password
    if [ ! -f "$MSSP_SECRETS_DIR/postgres/password" ]; then
        openssl rand -base64 32 | tr -d '/+=' | head -c 32 > "$MSSP_SECRETS_DIR/postgres/password"
        chmod 600 "$MSSP_SECRETS_DIR/postgres/password"
        log_info "Generated PostgreSQL password"
    fi

    # Django secret key
    if [ ! -f "$MSSP_SECRETS_DIR/django/secret_key" ]; then
        python3 -c "import secrets; print(secrets.token_urlsafe(50))" > "$MSSP_SECRETS_DIR/django/secret_key"
        chmod 600 "$MSSP_SECRETS_DIR/django/secret_key"
        log_info "Generated Django secret key"
    fi

    # Logto secrets
    if [ ! -f "$MSSP_SECRETS_DIR/logto/db_password" ]; then
        openssl rand -base64 32 | tr -d '/+=' | head -c 32 > "$MSSP_SECRETS_DIR/logto/db_password"
        chmod 600 "$MSSP_SECRETS_DIR/logto/db_password"
        log_info "Generated Logto DB password"
    fi

    if [ ! -f "$MSSP_SECRETS_DIR/logto/cookie_keys" ]; then
        echo "$(openssl rand -hex 32),$(openssl rand -hex 32)" > "$MSSP_SECRETS_DIR/logto/cookie_keys"
        chmod 600 "$MSSP_SECRETS_DIR/logto/cookie_keys"
        log_info "Generated Logto cookie keys"
    fi

    # ClickHouse password
    if [ ! -f "$MSSP_SECRETS_DIR/clickhouse/password" ]; then
        openssl rand -base64 32 | tr -d '/+=' | head -c 32 > "$MSSP_SECRETS_DIR/clickhouse/password"
        chmod 600 "$MSSP_SECRETS_DIR/clickhouse/password"
        log_info "Generated ClickHouse password"
    fi

    # Grafana admin password
    if [ ! -f "$MSSP_SECRETS_DIR/grafana/admin_password" ]; then
        openssl rand -base64 16 | tr -d '/+=' | head -c 16 > "$MSSP_SECRETS_DIR/grafana/admin_password"
        chmod 600 "$MSSP_SECRETS_DIR/grafana/admin_password"
        log_info "Generated Grafana admin password"
    fi

    log_success "All secrets generated"
}

# =============================================================================
# NETWORK SETUP (OVS + VXLAN + OpenFlow)
# =============================================================================

setup_ovs_bridge() {
    log_section "Setting Up OVS Bridge"

    # Check if bridge exists
    if ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        log_info "OVS bridge $OVS_BRIDGE already exists"
    else
        # Create bridge
        log_info "Creating OVS bridge: $OVS_BRIDGE"
        ovs-vsctl add-br "$OVS_BRIDGE"

        # Enable OpenFlow protocols
        ovs-vsctl set bridge "$OVS_BRIDGE" protocols=OpenFlow10,OpenFlow13,OpenFlow14

        # Set fail mode to secure (drop if controller disconnected)
        ovs-vsctl set-fail-mode "$OVS_BRIDGE" standalone
    fi

    # Configure bridge IP
    ip addr flush dev "$OVS_BRIDGE" 2>/dev/null || true
    ip addr add "$MSSP_GATEWAY/16" dev "$OVS_BRIDGE"
    ip link set "$OVS_BRIDGE" up

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Make IP forwarding persistent
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    log_success "OVS bridge configured: $OVS_BRIDGE at $MSSP_GATEWAY"
}

setup_vxlan_tunnels() {
    log_section "Setting Up VXLAN Tunnels"

    # Get local IP for VXLAN source
    local local_ip
    local_ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')

    if [ -z "$local_ip" ]; then
        local_ip=$(hostname -I | awk '{print $1}')
    fi

    log_info "Using local IP for VXLAN: $local_ip"

    # Create VXLAN interfaces for each POD
    for pod in "${!POD_CONFIG[@]}"; do
        local config="${POD_CONFIG[$pod]}"
        local network="${config%%:*}"
        local vni="${config##*:}"
        local vxlan_name="vxlan_${vni}"

        # Check if VXLAN interface exists
        if ovs-vsctl port-to-br "$vxlan_name" &>/dev/null; then
            log_info "VXLAN $vxlan_name already exists"
        else
            log_info "Creating VXLAN tunnel: $vxlan_name (VNI: $vni)"
            ovs-vsctl add-port "$OVS_BRIDGE" "$vxlan_name" \
                -- set interface "$vxlan_name" type=vxlan \
                   options:key="$vni" \
                   options:local_ip="$local_ip" \
                   options:remote_ip=flow
        fi
    done

    # Create edge mesh VXLAN (VNI 1000) for edge device connectivity
    local edge_vxlan="vxlan_edge"
    if ! ovs-vsctl port-to-br "$edge_vxlan" &>/dev/null; then
        log_info "Creating edge mesh VXLAN tunnel: $edge_vxlan (VNI: 1000)"
        ovs-vsctl add-port "$OVS_BRIDGE" "$edge_vxlan" \
            -- set interface "$edge_vxlan" type=vxlan \
               options:key=1000 \
               options:local_ip="$local_ip" \
               options:remote_ip=flow
    fi

    log_success "VXLAN tunnels configured"
}

setup_openflow_rules() {
    log_section "Setting Up OpenFlow Rules"

    # Clear existing flows
    ovs-ofctl del-flows "$OVS_BRIDGE"

    # Priority 0: Default drop (security baseline)
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=0,actions=drop"
    log_info "Added default drop rule"

    # Priority 10: Allow ARP for network discovery
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=10,arp,actions=normal"
    log_info "Added ARP allow rule"

    # Priority 15: Allow ICMP for diagnostics
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=15,icmp,actions=normal"
    log_info "Added ICMP allow rule"

    # Priority 20: Allow established connections
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=20,ip,ct_state=+est,actions=normal"
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=20,ip,ct_state=+rel,actions=normal"
    log_info "Added connection tracking rules"

    # POD-specific rules
    # POD-001 (DMZ) - Can reach external and other PODs
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=100,ip,nw_src=10.200.1.0/24,actions=normal"
    log_info "Added POD-001 (DMZ) egress rules"

    # POD-003 (Database) - Only accepts from POD-001 and POD-002
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=100,ip,nw_src=10.200.1.0/24,nw_dst=10.200.3.0/24,actions=normal"
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=100,ip,nw_src=10.200.2.0/24,nw_dst=10.200.3.0/24,actions=normal"
    log_info "Added POD-003 (Database) ingress rules"

    # POD-004 (Cache) - Accepts from POD-001
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=100,ip,nw_src=10.200.1.0/24,nw_dst=10.200.4.0/24,actions=normal"
    log_info "Added POD-004 (Cache) ingress rules"

    # POD-005 (Monitoring) - Accepts from all internal PODs
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=100,ip,nw_src=10.200.0.0/16,nw_dst=10.200.5.0/24,actions=normal"
    log_info "Added POD-005 (Monitoring) ingress rules"

    # POD-006 (Security) - Can monitor all traffic
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=100,ip,nw_src=10.200.6.0/24,actions=normal"
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=100,ip,nw_dst=10.200.6.0/24,actions=normal"
    log_info "Added POD-006 (Security) rules"

    # Edge mesh traffic (VNI 1000)
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=90,ip,nw_src=10.100.0.0/16,actions=normal"
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=90,ip,nw_dst=10.100.0.0/16,actions=normal"
    log_info "Added edge mesh rules"

    # Save flows to file for persistence
    ovs-ofctl dump-flows "$OVS_BRIDGE" > "$MSSP_CONFIG_DIR/openflow/mssp-flows.txt"

    log_success "OpenFlow rules configured"
}

# =============================================================================
# PODMAN NETWORK SETUP
# =============================================================================

create_pod_networks() {
    log_section "Creating Podman Networks"

    for pod in "${!POD_CONFIG[@]}"; do
        local config="${POD_CONFIG[$pod]}"
        local network="${config%%:*}"
        local gateway="${network%.*}.1"
        local network_name="mssp-${pod}"

        # Check if network exists
        if podman network exists "$network_name" 2>/dev/null; then
            log_info "Network $network_name already exists"
        else
            log_info "Creating network: $network_name ($network)"
            podman network create \
                --driver bridge \
                --subnet "$network" \
                --gateway "$gateway" \
                --internal \
                "$network_name"
        fi
    done

    # Create external network for DMZ
    if ! podman network exists "mssp-external" 2>/dev/null; then
        log_info "Creating external network: mssp-external"
        podman network create \
            --driver bridge \
            --subnet "172.20.100.0/24" \
            --gateway "172.20.100.1" \
            "mssp-external"
    fi

    log_success "Podman networks created"
}

# =============================================================================
# CONFIGURATION FILE GENERATION
# =============================================================================

generate_nginx_config() {
    log_section "Generating Nginx Configuration"

    local domain="${MSSP_DOMAIN:-localhost}"

    cat > "$MSSP_CONFIG_DIR/nginx/nginx.conf" << 'EOF'
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_conn_zone $binary_remote_addr zone=conn:10m;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript
               application/xml application/xml+rss text/javascript;

    # Upstream for Django
    upstream django {
        server 172.20.1.10:8000;
        keepalive 32;
    }

    # Upstream for Logto
    upstream logto {
        server 172.20.2.10:3001;
    }

    # HTTP -> HTTPS redirect
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    # Main HTTPS server
    server {
        listen 443 ssl http2;
        server_name _;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d;

        # Django application
        location / {
            proxy_pass http://django;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # API endpoints with rate limiting
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            limit_conn conn 10;

            proxy_pass http://django;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Static files
        location /static/ {
            alias /var/www/static/;
            expires 30d;
            add_header Cache-Control "public, immutable";
        }

        # Media files
        location /media/ {
            alias /var/www/media/;
            expires 7d;
        }

        # Logto OAuth endpoints
        location /auth/ {
            proxy_pass http://logto/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
EOF

    log_success "Nginx configuration generated"
}

generate_postgres_config() {
    log_section "Generating PostgreSQL Configuration"

    cat > "$MSSP_CONFIG_DIR/postgres/postgresql.conf" << 'EOF'
# PostgreSQL Configuration for HookProbe MSSP
listen_addresses = '*'
port = 5432
max_connections = 200

# Memory settings
shared_buffers = 2GB
effective_cache_size = 6GB
maintenance_work_mem = 512MB
work_mem = 32MB

# WAL settings
wal_level = replica
max_wal_senders = 3
wal_keep_size = 1GB

# Query tuning
random_page_cost = 1.1
effective_io_concurrency = 200
default_statistics_target = 100

# Logging (container-friendly - use stderr, no collector)
log_destination = 'stderr'
logging_collector = off
# log_directory = '/var/log/postgresql'  # Disabled for container
# log_filename = 'postgresql-%Y-%m-%d.log'  # Disabled for container
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on

# Autovacuum
autovacuum = on
autovacuum_max_workers = 3
autovacuum_naptime = 60s
EOF

    cat > "$MSSP_CONFIG_DIR/postgres/pg_hba.conf" << 'EOF'
# PostgreSQL Host-Based Authentication
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     trust
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
host    all             all             172.20.0.0/16           scram-sha-256
EOF

    log_success "PostgreSQL configuration generated"
}

generate_clickhouse_config() {
    log_section "Generating ClickHouse Configuration"

    local ch_password
    ch_password=$(cat "$MSSP_SECRETS_DIR/clickhouse/password")

    cat > "$MSSP_CONFIG_DIR/clickhouse/config.xml" << EOF
<?xml version="1.0"?>
<clickhouse>
    <logger>
        <level>information</level>
        <log>/var/log/clickhouse-server/clickhouse-server.log</log>
        <errorlog>/var/log/clickhouse-server/clickhouse-server.err.log</errorlog>
        <size>100M</size>
        <count>10</count>
    </logger>

    <http_port>8123</http_port>
    <tcp_port>9000</tcp_port>
    <interserver_http_port>9009</interserver_http_port>

    <listen_host>0.0.0.0</listen_host>

    <max_connections>4096</max_connections>
    <keep_alive_timeout>3</keep_alive_timeout>
    <max_concurrent_queries>100</max_concurrent_queries>

    <path>/var/lib/clickhouse/</path>
    <tmp_path>/var/lib/clickhouse/tmp/</tmp_path>
    <user_files_path>/var/lib/clickhouse/user_files/</user_files_path>
    <format_schema_path>/var/lib/clickhouse/format_schemas/</format_schema_path>

    <!-- User directories configuration (required for ClickHouse 24.x) -->
    <user_directories>
        <users_xml>
            <path>/etc/clickhouse-server/users.xml</path>
        </users_xml>
        <local_directory>
            <path>/var/lib/clickhouse/access/</path>
        </local_directory>
    </user_directories>

    <users_config>users.xml</users_config>
    <default_profile>default</default_profile>
    <default_database>default</default_database>

    <timezone>UTC</timezone>

    <mlock_executable>true</mlock_executable>

    <builtin_dictionaries_reload_interval>3600</builtin_dictionaries_reload_interval>

    <max_session_timeout>3600</max_session_timeout>
    <default_session_timeout>60</default_session_timeout>

    <merge_tree>
        <max_suspicious_broken_parts>5</max_suspicious_broken_parts>
    </merge_tree>

    <compression>
        <case>
            <min_part_size>10000000000</min_part_size>
            <min_part_size_ratio>0.01</min_part_size_ratio>
            <method>zstd</method>
        </case>
    </compression>
</clickhouse>
EOF

    cat > "$MSSP_CONFIG_DIR/clickhouse/users.xml" << EOF
<?xml version="1.0"?>
<clickhouse>
    <profiles>
        <default>
            <max_memory_usage>10000000000</max_memory_usage>
            <load_balancing>random</load_balancing>
        </default>
        <readonly>
            <readonly>1</readonly>
        </readonly>
    </profiles>

    <users>
        <default>
            <password_sha256_hex>$(echo -n "$ch_password" | sha256sum | cut -d' ' -f1)</password_sha256_hex>
            <networks>
                <ip>172.20.0.0/16</ip>
                <ip>127.0.0.1</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </default>
    </users>

    <quotas>
        <default>
            <interval>
                <duration>3600</duration>
                <queries>0</queries>
                <errors>0</errors>
                <result_rows>0</result_rows>
                <read_rows>0</read_rows>
                <execution_time>0</execution_time>
            </interval>
        </default>
    </quotas>
</clickhouse>
EOF

    log_success "ClickHouse configuration generated"
}

generate_grafana_config() {
    log_section "Generating Grafana Configuration"

    local grafana_password
    grafana_password=$(cat "$MSSP_SECRETS_DIR/grafana/admin_password")

    cat > "$MSSP_CONFIG_DIR/grafana/grafana.ini" << EOF
[server]
http_port = 3000
domain = localhost
root_url = %(protocol)s://%(domain)s:%(http_port)s/grafana/

[security]
admin_user = admin
admin_password = $grafana_password
disable_gravatar = true

[users]
allow_sign_up = false

[auth.anonymous]
enabled = false

[analytics]
reporting_enabled = false
check_for_updates = false

[log]
mode = console
level = info

[database]
type = sqlite3
path = /var/lib/grafana/grafana.db

[alerting]
enabled = true

[unified_alerting]
enabled = true
EOF

    log_success "Grafana configuration generated"
}

generate_django_env() {
    log_section "Generating Django Environment"

    local django_secret
    local postgres_password
    local clickhouse_password

    django_secret=$(cat "$MSSP_SECRETS_DIR/django/secret_key")
    postgres_password=$(cat "$MSSP_SECRETS_DIR/postgres/password")
    clickhouse_password=$(cat "$MSSP_SECRETS_DIR/clickhouse/password")

    cat > "$MSSP_CONFIG_DIR/django.env" << EOF
# Django Settings
DJANGO_ENV=production
DJANGO_SECRET_KEY=$django_secret
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,172.20.1.10,${MSSP_DOMAIN:-mssp.local}
DEBUG=False

# PostgreSQL
POSTGRES_HOST=172.20.3.10
POSTGRES_PORT=5432
POSTGRES_DB=hookprobe
POSTGRES_USER=hookprobe
POSTGRES_PASSWORD=$postgres_password

# Redis/Valkey
REDIS_HOST=172.20.4.10
REDIS_PORT=6379

# ClickHouse
CLICKHOUSE_HOST=172.20.5.10
CLICKHOUSE_PORT=8123
CLICKHOUSE_DATABASE=security
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=$clickhouse_password

# VictoriaMetrics
VICTORIAMETRICS_URL=http://172.20.5.11:8428

# Grafana
GRAFANA_URL=http://172.20.5.12:3000

# Qsecbit
QSECBIT_API_URL=http://172.20.6.10:8888

# Logto IAM
LOGTO_ENDPOINT=http://172.20.2.10:3001
LOGTO_APP_ID=hookprobe-mssp
LOGTO_APP_SECRET=

# n8n Automation
N8N_WEBHOOK_URL=http://172.20.8.10:5678/webhook
EOF

    chmod 600 "$MSSP_CONFIG_DIR/django.env"

    log_success "Django environment generated"
}

generate_ssl_certs() {
    log_section "Generating SSL Certificates"

    local ssl_dir="$MSSP_CONFIG_DIR/nginx/ssl"
    local domain="${MSSP_DOMAIN:-localhost}"

    if [ -f "$ssl_dir/cert.pem" ] && [ -f "$ssl_dir/key.pem" ]; then
        log_info "SSL certificates already exist"
        return 0
    fi

    log_info "Generating self-signed SSL certificate for: $domain"

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$ssl_dir/key.pem" \
        -out "$ssl_dir/cert.pem" \
        -subj "/CN=$domain/O=HookProbe/C=US" \
        -addext "subjectAltName=DNS:$domain,DNS:localhost,IP:127.0.0.1"

    chmod 600 "$ssl_dir/key.pem"
    chmod 644 "$ssl_dir/cert.pem"

    log_success "SSL certificates generated"
}

# =============================================================================
# CONTAINER DEPLOYMENT
# =============================================================================

pull_images() {
    log_section "Pulling Container Images"

    for name in "${!CONTAINER_IMAGES[@]}"; do
        local image="${CONTAINER_IMAGES[$name]}"
        log_info "Pulling: $image"
        podman pull "$image" || log_warning "Failed to pull $image, may already exist"
    done

    log_success "Container images pulled"
}

deploy_pod_003_database() {
    log_section "Deploying POD-003: Database (PostgreSQL)"

    local container_name="mssp-postgres"
    local network="mssp-pod-003-db"
    local ip="172.20.3.10"
    local postgres_password
    postgres_password=$(cat "$MSSP_SECRETS_DIR/postgres/password")

    # Stop existing container
    podman stop "$container_name" 2>/dev/null || true
    podman rm "$container_name" 2>/dev/null || true

    log_info "Starting PostgreSQL container..."
    podman run -d \
        --name "$container_name" \
        --network "$network" \
        --ip "$ip" \
        -e POSTGRES_USER=hookprobe \
        -e POSTGRES_PASSWORD="$postgres_password" \
        -e POSTGRES_DB=hookprobe \
        -v "$MSSP_DATA_DIR/postgres:/var/lib/postgresql/data:Z" \
        -v "$MSSP_CONFIG_DIR/postgres/postgresql.conf:/etc/postgresql/postgresql.conf:ro,Z" \
        --health-cmd="pg_isready -U hookprobe" \
        --health-interval=10s \
        --health-timeout=5s \
        --health-retries=5 \
        "${CONTAINER_IMAGES[postgres]}" \
        postgres -c 'config_file=/etc/postgresql/postgresql.conf'

    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to be ready..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if podman exec "$container_name" pg_isready -U hookprobe &>/dev/null; then
            break
        fi
        sleep 2
        ((retries--))
    done

    if [ $retries -eq 0 ]; then
        log_error "PostgreSQL failed to start"
        return 1
    fi

    # Create additional databases
    log_info "Creating additional databases..."
    podman exec "$container_name" psql -U hookprobe -c "CREATE DATABASE logto;" 2>/dev/null || true

    log_success "POD-003 (PostgreSQL) deployed at $ip"
}

deploy_pod_004_cache() {
    log_section "Deploying POD-004: Cache (Valkey)"

    local container_name="mssp-valkey"
    local network="mssp-pod-004-cache"
    local ip="172.20.4.10"

    # Stop existing container
    podman stop "$container_name" 2>/dev/null || true
    podman rm "$container_name" 2>/dev/null || true

    log_info "Starting Valkey container..."
    podman run -d \
        --name "$container_name" \
        --network "$network" \
        --ip "$ip" \
        -v "$MSSP_DATA_DIR/valkey:/data:Z" \
        --health-cmd="valkey-cli ping" \
        --health-interval=10s \
        --health-timeout=5s \
        --health-retries=5 \
        "${CONTAINER_IMAGES[valkey]}" \
        valkey-server --appendonly yes --maxmemory 2gb --maxmemory-policy allkeys-lru

    log_success "POD-004 (Valkey) deployed at $ip"
}

deploy_pod_005_monitoring() {
    log_section "Deploying POD-005: Monitoring Stack"

    local network="mssp-pod-005-monitoring"

    # VictoriaMetrics
    local vm_container="mssp-victoriametrics"
    local vm_ip="172.20.5.10"

    podman stop "$vm_container" 2>/dev/null || true
    podman rm "$vm_container" 2>/dev/null || true

    log_info "Starting VictoriaMetrics..."
    podman run -d \
        --name "$vm_container" \
        --network "$network" \
        --ip "$vm_ip" \
        --health-cmd="wget -qO- http://localhost:8428/-/healthy || exit 1" \
        --health-interval=30s \
        --health-retries=3 \
        -v "$MSSP_DATA_DIR/victoriametrics:/victoria-metrics-data:Z" \
        "${CONTAINER_IMAGES[victoriametrics]}" \
        -storageDataPath=/victoria-metrics-data \
        -retentionPeriod=90d \
        -httpListenAddr=:8428

    log_success "VictoriaMetrics deployed at $vm_ip:8428"

    # ClickHouse
    local ch_container="mssp-clickhouse"
    local ch_ip="172.20.5.11"

    podman stop "$ch_container" 2>/dev/null || true
    podman rm "$ch_container" 2>/dev/null || true

    # Read ClickHouse password for env var
    local ch_password
    ch_password=$(cat "$MSSP_SECRETS_DIR/clickhouse/password")

    log_info "Starting ClickHouse..."
    podman run -d \
        --name "$ch_container" \
        --network "$network" \
        --ip "$ch_ip" \
        --health-cmd="clickhouse-client --password=$ch_password -q 'SELECT 1' || exit 1" \
        --health-interval=30s \
        --health-retries=3 \
        -e CLICKHOUSE_PASSWORD="$ch_password" \
        -v "$MSSP_DATA_DIR/clickhouse:/var/lib/clickhouse:Z" \
        -v "$MSSP_CONFIG_DIR/clickhouse/config.xml:/etc/clickhouse-server/config.xml:ro,Z" \
        -v "$MSSP_CONFIG_DIR/clickhouse/users.xml:/etc/clickhouse-server/users.xml:ro,Z" \
        --ulimit nofile=262144:262144 \
        "${CONTAINER_IMAGES[clickhouse]}"

    log_success "ClickHouse deployed at $ch_ip:8123"

    # Grafana
    local grafana_container="mssp-grafana"
    local grafana_ip="172.20.5.12"

    podman stop "$grafana_container" 2>/dev/null || true
    podman rm "$grafana_container" 2>/dev/null || true

    log_info "Starting Grafana..."
    podman run -d \
        --name "$grafana_container" \
        --network "$network" \
        --ip "$grafana_ip" \
        --health-cmd="wget -qO- http://localhost:3000/api/health || exit 1" \
        --health-interval=30s \
        --health-retries=3 \
        -v "$MSSP_DATA_DIR/grafana:/var/lib/grafana:Z" \
        -v "$MSSP_CONFIG_DIR/grafana/grafana.ini:/etc/grafana/grafana.ini:ro,Z" \
        -e GF_INSTALL_PLUGINS=grafana-clickhouse-datasource \
        "${CONTAINER_IMAGES[grafana]}"

    log_success "Grafana deployed at $grafana_ip:3000"
}

deploy_pod_002_iam() {
    log_section "Deploying POD-002: IAM (Logto)"

    local container_name="mssp-logto"
    local network="mssp-pod-002-iam"
    local ip="172.20.2.10"
    local postgres_password
    local logto_db_password
    local cookie_keys

    postgres_password=$(cat "$MSSP_SECRETS_DIR/postgres/password")
    logto_db_password=$(cat "$MSSP_SECRETS_DIR/logto/db_password")
    cookie_keys=$(cat "$MSSP_SECRETS_DIR/logto/cookie_keys")

    # Stop existing container
    podman stop "$container_name" 2>/dev/null || true
    podman rm "$container_name" 2>/dev/null || true

    log_info "Starting Logto container..."
    podman run -d \
        --name "$container_name" \
        --network "$network" \
        --ip "$ip" \
        --health-cmd="wget -qO- http://localhost:3001/api/status || exit 1" \
        --health-interval=30s \
        --health-retries=3 \
        -e TRUST_PROXY_HEADER=1 \
        -e DB_URL="postgresql://hookprobe:${postgres_password}@172.20.3.10:5432/logto" \
        -e ENDPOINT="http://${MSSP_DOMAIN:-localhost}:3001" \
        -e ADMIN_ENDPOINT="http://${MSSP_DOMAIN:-localhost}:3002" \
        -e COOKIE_KEYS="$cookie_keys" \
        "${CONTAINER_IMAGES[logto]}"

    # Connect Logto to database network
    podman network connect mssp-pod-003-db "$container_name"

    log_success "POD-002 (Logto IAM) deployed at $ip"
}

deploy_pod_001_dmz() {
    log_section "Deploying POD-001: DMZ (Django + Nginx)"

    local network="mssp-pod-001-dmz"
    local external_network="mssp-external"

    # Build Django container
    build_django_container

    # Django
    local django_container="mssp-django"
    local django_ip="172.20.1.10"

    podman stop "$django_container" 2>/dev/null || true
    podman rm "$django_container" 2>/dev/null || true

    log_info "Starting Django container..."
    podman run -d \
        --name "$django_container" \
        --network "$network" \
        --ip "$django_ip" \
        --health-cmd="python -c 'import urllib.request; urllib.request.urlopen(\"http://localhost:8000/health/\")' || exit 1" \
        --health-interval=30s \
        --health-retries=3 \
        --env-file "$MSSP_CONFIG_DIR/django.env" \
        -v "$MSSP_DATA_DIR/django/static:/app/staticfiles:Z" \
        -v "$MSSP_DATA_DIR/django/media:/app/media:Z" \
        -v "$HOOKPROBE_ROOT/products/mssp/web:/app:Z" \
        "localhost/mssp-django:latest"

    # Connect Django to database and cache networks
    podman network connect mssp-pod-003-db "$django_container"
    podman network connect mssp-pod-004-cache "$django_container"

    log_success "Django deployed at $django_ip:8000"

    # Celery Worker (disabled for POC - requires Django celery app configuration)
    if [ "${ENABLE_CELERY:-false}" = "true" ]; then
        local celery_container="mssp-celery"
        local celery_ip="172.20.1.11"

        podman stop "$celery_container" 2>/dev/null || true
        podman rm "$celery_container" 2>/dev/null || true

        log_info "Starting Celery worker..."
        podman run -d \
            --name "$celery_container" \
            --network "$network" \
            --ip "$celery_ip" \
            --health-cmd="celery -A hookprobe inspect ping -d celery@\$HOSTNAME || exit 1" \
            --health-interval=60s \
            --health-retries=3 \
            --env-file "$MSSP_CONFIG_DIR/django.env" \
            -v "$HOOKPROBE_ROOT/products/mssp/web:/app:Z" \
            "localhost/mssp-django:latest" \
            celery -A hookprobe worker -l INFO

        # Connect Celery to database and cache networks
        podman network connect mssp-pod-003-db "$celery_container"
        podman network connect mssp-pod-004-cache "$celery_container"

        log_success "Celery worker deployed at $celery_ip"
    else
        log_info "Celery worker disabled (set ENABLE_CELERY=true to enable)"
    fi

    # Nginx
    local nginx_container="mssp-nginx"
    local nginx_ip="172.20.1.12"

    podman stop "$nginx_container" 2>/dev/null || true
    podman rm "$nginx_container" 2>/dev/null || true

    log_info "Starting Nginx container..."
    # Note: Can't use --ip with multiple networks, so start with primary network first
    podman run -d \
        --name "$nginx_container" \
        --network "$network" \
        --ip "$nginx_ip" \
        --health-cmd="wget -qO- http://localhost/health || exit 1" \
        --health-interval=30s \
        --health-retries=3 \
        -p 80:80 \
        -p 443:443 \
        -v "$MSSP_CONFIG_DIR/nginx/nginx.conf:/etc/nginx/nginx.conf:ro,Z" \
        -v "$MSSP_CONFIG_DIR/nginx/ssl:/etc/nginx/ssl:ro,Z" \
        -v "$MSSP_DATA_DIR/django/static:/var/www/static:ro,Z" \
        -v "$MSSP_DATA_DIR/django/media:/var/www/media:ro,Z" \
        "${CONTAINER_IMAGES[nginx]}"

    # Connect to external network for host port exposure
    podman network connect "$external_network" "$nginx_container"

    log_success "Nginx deployed at $nginx_ip (ports 80, 443)"
}

deploy_pod_006_security() {
    log_section "Deploying POD-006: Security (Qsecbit)"

    # Qsecbit disabled for POC - container build needs proper Python path setup
    if [ "${ENABLE_QSECBIT:-false}" = "true" ]; then
        local network="mssp-pod-006-security"

        # Build Qsecbit container
        build_qsecbit_container

        # Qsecbit Agent
        local qsecbit_container="mssp-qsecbit"
        local qsecbit_ip="172.20.6.10"

        podman stop "$qsecbit_container" 2>/dev/null || true
        podman rm "$qsecbit_container" 2>/dev/null || true

        log_info "Starting Qsecbit agent..."
        podman run -d \
            --name "$qsecbit_container" \
            --network "$network" \
            --ip "$qsecbit_ip" \
            --health-cmd="wget -qO- http://localhost:8888/health || exit 1" \
            --health-interval=30s \
            --health-retries=3 \
            -v "$MSSP_BASE_DIR/qsecbit:/app:Z" \
            -v "$HOOKPROBE_ROOT/core/qsecbit:/opt/qsecbit:ro,Z" \
            "localhost/mssp-qsecbit:latest"

        log_success "POD-006 (Qsecbit) deployed at $qsecbit_ip:8888"
    else
        log_info "Qsecbit security agent disabled for POC (set ENABLE_QSECBIT=true to enable)"
    fi
}

deploy_pod_008_automation() {
    log_section "Deploying POD-008: Automation (n8n)"

    if [ "${ENABLE_N8N:-true}" != "true" ]; then
        log_info "n8n automation disabled, skipping"
        return 0
    fi

    local container_name="mssp-n8n"
    local network="mssp-pod-008-automation"
    local ip="172.20.8.10"

    podman stop "$container_name" 2>/dev/null || true
    podman rm "$container_name" 2>/dev/null || true

    log_info "Starting n8n container..."
    podman run -d \
        --name "$container_name" \
        --network "$network" \
        --ip "$ip" \
        --health-cmd="wget -qO- http://localhost:5678/healthz || exit 1" \
        --health-interval=30s \
        --health-retries=3 \
        -e N8N_HOST=0.0.0.0 \
        -e N8N_PORT=5678 \
        -e N8N_PROTOCOL=http \
        -e WEBHOOK_URL="http://${MSSP_DOMAIN:-localhost}:5678/" \
        -e GENERIC_TIMEZONE=UTC \
        -v "$MSSP_DATA_DIR/n8n:/home/node/.n8n:Z" \
        "${CONTAINER_IMAGES[n8n]}"

    log_success "POD-008 (n8n) deployed at $ip:5678"
}

deploy_htp_endpoint() {
    log_section "Deploying HTP Validator Endpoint"

    # HTP disabled for POC - htp_validator.py needs to be implemented
    if [ "${ENABLE_HTP:-false}" = "true" ]; then
        # Build HTP container
        build_htp_container

        local container_name="mssp-htp"

        podman stop "$container_name" 2>/dev/null || true
        podman rm "$container_name" 2>/dev/null || true

        log_info "Starting HTP validator endpoint..."
        podman run -d \
            --name "$container_name" \
            --network host \
            --health-cmd="python -c 'import socket; s=socket.socket(); s.connect((\"127.0.0.1\", 4478)); s.close()' || exit 1" \
            --health-interval=30s \
            --health-retries=3 \
            -v "$MSSP_BASE_DIR/htp:/app:Z" \
            -v "$HOOKPROBE_ROOT/core/htp:/opt/htp:ro,Z" \
            -v "$MSSP_DATA_DIR:/var/lib/hookprobe/mssp:Z" \
            -v "$MSSP_SECRETS_DIR:/etc/hookprobe/secrets/mssp:ro,Z" \
            "localhost/mssp-htp:latest"

        log_success "HTP validator deployed on UDP/TCP 4478"
    else
        log_info "HTP validator disabled for POC (set ENABLE_HTP=true to enable)"
    fi
}

# =============================================================================
# CONTAINER BUILD FUNCTIONS
# =============================================================================

build_django_container() {
    log_info "Building Django container..."

    cat > "$MSSP_BASE_DIR/containers/Containerfile.django" << 'EOF'
FROM docker.io/python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY web/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Create non-root user
RUN useradd -m -u 1000 hookprobe
USER hookprobe

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--threads", "2", "hookprobe.wsgi:application"]
EOF

    podman build -t localhost/mssp-django:latest \
        -f "$MSSP_BASE_DIR/containers/Containerfile.django" \
        "$HOOKPROBE_ROOT/products/mssp"
}

build_qsecbit_container() {
    log_info "Building Qsecbit container..."

    cat > "$MSSP_BASE_DIR/containers/Containerfile.qsecbit" << 'EOF'
FROM docker.io/python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    numpy \
    scipy \
    flask \
    requests \
    clickhouse-driver

# Create non-root user
RUN useradd -m -u 1000 hookprobe
USER hookprobe

EXPOSE 8888

CMD ["python", "/opt/qsecbit/qsecbit-agent.py", "--mode", "mssp", "--port", "8888"]
EOF

    podman build -t localhost/mssp-qsecbit:latest \
        -f "$MSSP_BASE_DIR/containers/Containerfile.qsecbit" \
        "$MSSP_BASE_DIR/containers"
}

build_htp_container() {
    log_info "Building HTP validator container..."

    cat > "$MSSP_BASE_DIR/containers/Containerfile.htp" << 'EOF'
FROM docker.io/python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    cryptography \
    pynacl \
    requests

# Create non-root user
RUN useradd -m -u 1000 hookprobe
USER hookprobe

EXPOSE 4478/udp
EXPOSE 4478/tcp

CMD ["python", "/app/htp_validator.py"]
EOF

    podman build -t localhost/mssp-htp:latest \
        -f "$MSSP_BASE_DIR/containers/Containerfile.htp" \
        "$MSSP_BASE_DIR/containers"
}

# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

init_clickhouse_schema() {
    log_section "Initializing ClickHouse Schema"

    local ch_password
    ch_password=$(cat "$MSSP_SECRETS_DIR/clickhouse/password")

    # Wait for ClickHouse to be ready
    log_info "Waiting for ClickHouse..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if podman exec mssp-clickhouse clickhouse-client --password="$ch_password" -q "SELECT 1" &>/dev/null; then
            break
        fi
        sleep 2
        ((retries--))
    done

    if [ $retries -eq 0 ]; then
        log_error "ClickHouse failed to start"
        return 1
    fi

    log_info "Creating security database and tables..."

    podman exec mssp-clickhouse clickhouse-client --password="$ch_password" --multiquery << 'EOF'
CREATE DATABASE IF NOT EXISTS security;

-- Security events table
CREATE TABLE IF NOT EXISTS security.events (
    timestamp DateTime64(3),
    device_id UUID,
    customer_id UUID,
    event_type Enum8('alert'=1, 'connection'=2, 'packet'=3, 'flow'=4),
    severity Enum8('critical'=1, 'high'=2, 'medium'=3, 'low'=4, 'info'=5),
    source_ip IPv4,
    dest_ip IPv4,
    source_port UInt16,
    dest_port UInt16,
    protocol LowCardinality(String),
    attack_type LowCardinality(String),
    description String,
    raw_event String,
    qsecbit_score Float32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (customer_id, device_id, timestamp)
TTL timestamp + INTERVAL 90 DAY;

-- Qsecbit scores time-series
CREATE TABLE IF NOT EXISTS security.qsecbit_scores (
    timestamp DateTime64(3),
    device_id UUID,
    customer_id UUID,
    score Float32,
    rag_status Enum8('GREEN'=1, 'AMBER'=2, 'RED'=3),
    drift Float32,
    attack_probability Float32,
    classifier_decay Float32,
    quantum_drift Float32,
    energy_anomaly Float32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (customer_id, device_id, timestamp)
TTL timestamp + INTERVAL 365 DAY;

-- Network flows
CREATE TABLE IF NOT EXISTS security.network_flows (
    timestamp DateTime64(3),
    device_id UUID,
    source_ip IPv4,
    dest_ip IPv4,
    source_port UInt16,
    dest_port UInt16,
    protocol LowCardinality(String),
    bytes_sent UInt64,
    bytes_recv UInt64,
    packets_sent UInt32,
    packets_recv UInt32,
    duration Float32,
    conn_state LowCardinality(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (device_id, timestamp)
TTL timestamp + INTERVAL 30 DAY;

-- Device heartbeats
CREATE TABLE IF NOT EXISTS security.device_heartbeats (
    timestamp DateTime64(3),
    device_id UUID,
    customer_id UUID,
    cpu_percent Float32,
    ram_percent Float32,
    disk_percent Float32,
    network_rx_bytes UInt64,
    network_tx_bytes UInt64,
    uptime_seconds UInt64,
    qsecbit_score Float32,
    rag_status Enum8('GREEN'=1, 'AMBER'=2, 'RED'=3)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (customer_id, device_id, timestamp)
TTL timestamp + INTERVAL 30 DAY;
EOF

    log_success "ClickHouse schema initialized"
}

run_django_migrations() {
    log_section "Running Django Migrations"

    # Wait for database to be ready
    sleep 5

    log_info "Running migrations..."
    podman exec mssp-django python manage.py migrate --noinput

    log_info "Collecting static files..."
    podman exec mssp-django python manage.py collectstatic --noinput

    log_success "Django migrations complete"
}

create_superuser() {
    log_section "Creating Django Superuser"

    local admin_email="${MSSP_ADMIN_EMAIL:-admin@hookprobe.local}"
    local admin_password
    admin_password=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)

    log_info "Creating superuser: $admin_email"

    podman exec mssp-django python manage.py shell << EOF
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='$admin_email').exists():
    User.objects.create_superuser('admin', '$admin_email', '$admin_password')
    print('Superuser created')
else:
    print('Superuser already exists')
EOF

    # Save admin credentials
    echo "Admin Email: $admin_email" > "$MSSP_SECRETS_DIR/django/admin_credentials"
    echo "Admin Password: $admin_password" >> "$MSSP_SECRETS_DIR/django/admin_credentials"
    chmod 600 "$MSSP_SECRETS_DIR/django/admin_credentials"

    log_success "Superuser created. Credentials saved to $MSSP_SECRETS_DIR/django/admin_credentials"
}

# =============================================================================
# SYSTEMD SERVICES
# =============================================================================

create_systemd_services() {
    log_section "Creating Systemd Services"

    # Main MSSP service
    cat > /etc/systemd/system/hookprobe-mssp.service << EOF
[Unit]
Description=HookProbe MSSP Platform
After=network.target openvswitch-switch.service podman.socket
Requires=openvswitch-switch.service podman.socket

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/hookprobe-mssp-start
ExecStop=/usr/local/bin/hookprobe-mssp-stop

[Install]
WantedBy=multi-user.target
EOF

    # Start script
    cat > /usr/local/bin/hookprobe-mssp-start << 'EOF'
#!/bin/bash
set -e

# Start all MSSP containers
containers=(
    "mssp-postgres"
    "mssp-valkey"
    "mssp-victoriametrics"
    "mssp-clickhouse"
    "mssp-grafana"
    "mssp-logto"
    "mssp-django"
    "mssp-celery"
    "mssp-nginx"
    "mssp-qsecbit"
    "mssp-n8n"
    "mssp-htp"
)

for container in "${containers[@]}"; do
    if podman container exists "$container" 2>/dev/null; then
        echo "Starting $container..."
        podman start "$container" 2>/dev/null || true
    fi
done

echo "MSSP platform started"
EOF
    chmod +x /usr/local/bin/hookprobe-mssp-start

    # Stop script
    cat > /usr/local/bin/hookprobe-mssp-stop << 'EOF'
#!/bin/bash

# Stop all MSSP containers
containers=(
    "mssp-htp"
    "mssp-n8n"
    "mssp-qsecbit"
    "mssp-nginx"
    "mssp-celery"
    "mssp-django"
    "mssp-logto"
    "mssp-grafana"
    "mssp-clickhouse"
    "mssp-victoriametrics"
    "mssp-valkey"
    "mssp-postgres"
)

for container in "${containers[@]}"; do
    if podman container exists "$container" 2>/dev/null; then
        echo "Stopping $container..."
        podman stop "$container" 2>/dev/null || true
    fi
done

echo "MSSP platform stopped"
EOF
    chmod +x /usr/local/bin/hookprobe-mssp-stop

    # Reload systemd
    systemctl daemon-reload

    log_success "Systemd services created"
}

# =============================================================================
# HEALTH CHECK
# =============================================================================

health_check() {
    log_section "Running Health Check"

    local errors=0

    # Check all containers
    local containers=(
        "mssp-postgres:5432"
        "mssp-valkey:6379"
        "mssp-victoriametrics:8428"
        "mssp-clickhouse:8123"
        "mssp-grafana:3000"
        "mssp-django:8000"
        "mssp-nginx:443"
    )

    for entry in "${containers[@]}"; do
        local container="${entry%%:*}"
        local port="${entry##*:}"

        if podman ps --format "{{.Names}}" | grep -q "^${container}$"; then
            log_success "$container: Running"
        else
            log_error "$container: Not running"
            ((errors++))
        fi
    done

    if [ $errors -eq 0 ]; then
        log_success "All health checks passed"
    else
        log_warning "$errors containers not running"
    fi

    return $errors
}

# =============================================================================
# MAIN INSTALLATION
# =============================================================================

show_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  _   _             _    ____            _
 | | | | ___   ___ | | _|  _ \ _ __ ___ | |__   ___
 | |_| |/ _ \ / _ \| |/ / |_) | '__/ _ \| '_ \ / _ \
 |  _  | (_) | (_) |   <|  __/| | | (_) | |_) |  __/
 |_| |_|\___/ \___/|_|\_\_|   |_|  \___/|_.__/ \___|

  __  __ ____ ____  ____    ____       _
 |  \/  / ___/ ___||  _ \  / ___|  ___| |_ _   _ _ __
 | |\/| \___ \___ \| |_) | \___ \ / _ \ __| | | | '_ \
 | |  | |___) |__) |  __/   ___) |  __/ |_| |_| | |_) |
 |_|  |_|____/____/|_|     |____/ \___|\__|\__,_| .__/
                                                |_|
EOF
    echo -e "${NC}"
    echo "  HookProbe MSSP v${MSSP_VERSION} - Managed Security Service Provider"
    echo "  Federated Cybersecurity Mesh - Central Brain"
    echo ""
}

show_completion() {
    log_section "Installation Complete"

    local grafana_password
    grafana_password=$(cat "$MSSP_SECRETS_DIR/grafana/admin_password")

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} MSSP Installation Complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Access URLs:"
    echo "  ─────────────────────────────────────────────"
    echo "  MSSP Dashboard:    https://${MSSP_DOMAIN:-localhost}/"
    echo "  Grafana:           https://${MSSP_DOMAIN:-localhost}:3000/"
    echo "  n8n Automation:    http://${MSSP_DOMAIN:-localhost}:5678/"
    echo "  Logto Admin:       http://${MSSP_DOMAIN:-localhost}:3002/"
    echo ""
    echo "  Default Credentials:"
    echo "  ─────────────────────────────────────────────"
    echo "  Django Admin:      See $MSSP_SECRETS_DIR/django/admin_credentials"
    echo "  Grafana:           admin / $grafana_password"
    echo ""
    echo "  HTP Endpoint:"
    echo "  ─────────────────────────────────────────────"
    echo "  UDP Port:          4478"
    echo "  TCP Port:          4478 (fallback)"
    echo ""
    echo "  Management Commands:"
    echo "  ─────────────────────────────────────────────"
    echo "  Start:             systemctl start hookprobe-mssp"
    echo "  Stop:              systemctl stop hookprobe-mssp"
    echo "  Status:            podman ps -a --filter 'name=mssp-'"
    echo ""
    echo -e "${YELLOW}  Note: Remember to configure your domain DNS and SSL certificates${NC}"
    echo -e "${YELLOW}  for production use.${NC}"
    echo ""
}

main() {
    show_banner

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)
                MSSP_DOMAIN="$2"
                shift 2
                ;;
            --admin-email)
                MSSP_ADMIN_EMAIL="$2"
                shift 2
                ;;
            --disable-n8n)
                ENABLE_N8N="false"
                shift
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --domain DOMAIN       Set MSSP domain (default: localhost)"
                echo "  --admin-email EMAIL   Set admin email (default: admin@hookprobe.local)"
                echo "  --disable-n8n         Disable n8n automation"
                echo "  --help                Show this help"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    check_root
    check_requirements

    # Installation steps
    install_dependencies
    install_podman
    install_openvswitch

    create_directories
    generate_secrets

    # Network setup
    setup_ovs_bridge
    setup_vxlan_tunnels
    setup_openflow_rules
    create_pod_networks

    # Generate configurations
    generate_nginx_config
    generate_postgres_config
    generate_clickhouse_config
    generate_grafana_config
    generate_django_env
    generate_ssl_certs

    # Pull images
    pull_images

    # Deploy PODs in order
    deploy_pod_003_database
    deploy_pod_004_cache
    deploy_pod_005_monitoring
    deploy_pod_002_iam
    deploy_pod_001_dmz
    deploy_pod_006_security
    deploy_pod_008_automation
    deploy_htp_endpoint

    # Initialize databases
    init_clickhouse_schema
    run_django_migrations
    create_superuser

    # Create systemd services
    create_systemd_services

    # Enable service
    systemctl enable hookprobe-mssp

    # Health check
    health_check

    show_completion
}

# Run main function
main "$@"
