#!/bin/bash
#
# HookProbe Fortress - Container Pod Infrastructure
# Creates the Fortress pod with VXLAN networking and container services
#
# Pod Architecture:
#   fortress-pod
#   ├── fortress-postgres     (Database)
#   ├── fortress-web          (Admin Portal)
#   ├── fortress-agent        (QSecBit Agent)
#   └── fortress-redis        (Cache/Sessions)
#
# Network Architecture:
#   - Internal pod network: 10.250.100.0/24
#   - VXLAN VNI 1000 for core services
#   - VXLAN VNI 2000 for MSSP uplink
#
# Version: 5.0.0
# License: AGPL-3.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/container_utils.sh" 2>/dev/null || true

# ============================================================
# CONFIGURATION
# ============================================================
POD_NAME="fortress-pod"
POD_NETWORK="10.250.100.0/24"
POD_GATEWAY="10.250.100.1"

# Container images
POSTGRES_IMAGE="docker.io/library/postgres:15-alpine"
REDIS_IMAGE="docker.io/library/redis:7-alpine"

# Secrets directory
SECRETS_DIR="/etc/hookprobe/secrets"
DATA_DIR="/opt/hookprobe/fortress/data"

# VXLAN Configuration
VXLAN_CORE_VNI=1000
VXLAN_CORE_PORT=4800
VXLAN_MSSP_VNI=2000
VXLAN_MSSP_PORT=4900

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ============================================================
# SECRETS MANAGEMENT
# ============================================================
generate_secret() {
    openssl rand -base64 32 | tr -d '/+=' | head -c 32
}

setup_secrets() {
    log_step "Setting up secrets..."

    mkdir -p "$SECRETS_DIR"/{database,vxlan,web}
    chmod 700 "$SECRETS_DIR"

    # PostgreSQL secrets
    if [ ! -f "$SECRETS_DIR/database/postgres_password" ]; then
        generate_secret > "$SECRETS_DIR/database/postgres_password"
        chmod 600 "$SECRETS_DIR/database/postgres_password"
        log_info "Generated PostgreSQL password"
    fi

    # Redis secret (optional auth)
    if [ ! -f "$SECRETS_DIR/database/redis_password" ]; then
        generate_secret > "$SECRETS_DIR/database/redis_password"
        chmod 600 "$SECRETS_DIR/database/redis_password"
        log_info "Generated Redis password"
    fi

    # Web secret key
    if [ ! -f "$SECRETS_DIR/web/secret_key" ]; then
        generate_secret > "$SECRETS_DIR/web/secret_key"
        chmod 600 "$SECRETS_DIR/web/secret_key"
        log_info "Generated web secret key"
    fi

    # VXLAN PSK
    if [ ! -f "$SECRETS_DIR/vxlan/core.psk" ]; then
        generate_secret > "$SECRETS_DIR/vxlan/core.psk"
        chmod 600 "$SECRETS_DIR/vxlan/core.psk"
        log_info "Generated VXLAN core PSK"
    fi

    if [ ! -f "$SECRETS_DIR/vxlan/mssp.psk" ]; then
        generate_secret > "$SECRETS_DIR/vxlan/mssp.psk"
        chmod 600 "$SECRETS_DIR/vxlan/mssp.psk"
        log_info "Generated VXLAN MSSP PSK"
    fi

    log_info "Secrets initialized"
}

# ============================================================
# DATA DIRECTORIES
# ============================================================
setup_data_dirs() {
    log_step "Setting up data directories..."

    mkdir -p "$DATA_DIR"/{postgres,redis,logs,reports}
    chmod 755 "$DATA_DIR"

    # PostgreSQL needs specific permissions
    mkdir -p "$DATA_DIR/postgres"
    # Note: PostgreSQL container will set correct ownership

    log_info "Data directories created"
}

# ============================================================
# VXLAN SETUP
# ============================================================
setup_vxlan() {
    log_step "Setting up VXLAN tunnels..."

    local LOCAL_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

    # Create VXLAN interface for core services
    if ! ip link show vxlan${VXLAN_CORE_VNI} &>/dev/null; then
        ip link add vxlan${VXLAN_CORE_VNI} type vxlan \
            id ${VXLAN_CORE_VNI} \
            local ${LOCAL_IP} \
            dstport ${VXLAN_CORE_PORT} \
            nolearning 2>/dev/null || true
        ip link set vxlan${VXLAN_CORE_VNI} up 2>/dev/null || true
        log_info "Created VXLAN interface vxlan${VXLAN_CORE_VNI}"
    fi

    # Create VXLAN interface for MSSP uplink
    if ! ip link show vxlan${VXLAN_MSSP_VNI} &>/dev/null; then
        ip link add vxlan${VXLAN_MSSP_VNI} type vxlan \
            id ${VXLAN_MSSP_VNI} \
            local ${LOCAL_IP} \
            dstport ${VXLAN_MSSP_PORT} \
            nolearning 2>/dev/null || true
        ip link set vxlan${VXLAN_MSSP_VNI} up 2>/dev/null || true
        log_info "Created VXLAN interface vxlan${VXLAN_MSSP_VNI}"
    fi

    # Save VXLAN configuration
    cat > /etc/hookprobe/vxlan.conf << VXLANEOF
# HookProbe Fortress VXLAN Configuration
# Generated: $(date -Iseconds)

LOCAL_IP=${LOCAL_IP}

# Core Services VXLAN
VXLAN_CORE_VNI=${VXLAN_CORE_VNI}
VXLAN_CORE_PORT=${VXLAN_CORE_PORT}
VXLAN_CORE_PSK=${SECRETS_DIR}/vxlan/core.psk

# MSSP Uplink VXLAN
VXLAN_MSSP_VNI=${VXLAN_MSSP_VNI}
VXLAN_MSSP_PORT=${VXLAN_MSSP_PORT}
VXLAN_MSSP_PSK=${SECRETS_DIR}/vxlan/mssp.psk
VXLANEOF

    log_info "VXLAN configuration saved"
}

# ============================================================
# POD CREATION
# ============================================================
create_pod() {
    log_step "Creating Fortress pod..."

    # Remove existing pod if present
    podman pod exists "$POD_NAME" 2>/dev/null && {
        log_warn "Removing existing pod..."
        podman pod rm -f "$POD_NAME" 2>/dev/null || true
    }

    # Create pod with exposed ports
    podman pod create \
        --name "$POD_NAME" \
        --network bridge \
        --publish 8443:8443 \
        --publish 5432:5432 \
        --publish 6379:6379 \
        --publish 9090:9090 \
        --infra-name fortress-infra

    log_info "Pod '$POD_NAME' created"
}

# ============================================================
# POSTGRESQL CONTAINER
# ============================================================
create_postgres_container() {
    log_step "Creating PostgreSQL container..."

    local POSTGRES_PASSWORD=$(cat "$SECRETS_DIR/database/postgres_password")

    podman run -d \
        --pod "$POD_NAME" \
        --name fortress-postgres \
        --restart unless-stopped \
        -e POSTGRES_DB=fortress \
        -e POSTGRES_USER=fortress \
        -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
        -e PGDATA=/var/lib/postgresql/data/pgdata \
        -v "$DATA_DIR/postgres:/var/lib/postgresql/data:Z" \
        "${POSTGRES_IMAGE}"

    log_info "PostgreSQL container created"

    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to initialize..."
    sleep 5

    local retries=30
    while [ $retries -gt 0 ]; do
        if podman exec fortress-postgres pg_isready -U fortress &>/dev/null; then
            log_info "PostgreSQL is ready"
            break
        fi
        sleep 1
        ((retries--))
    done

    if [ $retries -eq 0 ]; then
        log_error "PostgreSQL failed to start"
        return 1
    fi

    # Initialize database schema
    init_database_schema
}

init_database_schema() {
    log_step "Initializing database schema..."

    local POSTGRES_PASSWORD=$(cat "$SECRETS_DIR/database/postgres_password")

    podman exec -i fortress-postgres psql -U fortress -d fortress << 'SCHEMA'
-- HookProbe Fortress Database Schema
-- Version: 5.0.0

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Devices table (connected clients)
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mac_address VARCHAR(17) UNIQUE NOT NULL,
    ip_address INET,
    hostname VARCHAR(255),
    device_type VARCHAR(50),
    manufacturer VARCHAR(255),
    vlan_id INTEGER DEFAULT 40,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_blocked BOOLEAN DEFAULT FALSE,
    is_known BOOLEAN DEFAULT FALSE,
    notes TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_vlan ON devices(vlan_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

-- VLANs table
CREATE TABLE IF NOT EXISTS vlans (
    id SERIAL PRIMARY KEY,
    vlan_id INTEGER UNIQUE NOT NULL,
    name VARCHAR(50) NOT NULL,
    description TEXT,
    subnet CIDR NOT NULL,
    gateway INET,
    dhcp_enabled BOOLEAN DEFAULT TRUE,
    dhcp_range_start INET,
    dhcp_range_end INET,
    dns_policy VARCHAR(20) DEFAULT 'standard',
    bandwidth_limit_mbps INTEGER,
    is_isolated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default VLANs
INSERT INTO vlans (vlan_id, name, description, subnet, gateway, is_isolated)
VALUES
    (10, 'Management', 'Admin and management devices', '10.250.10.0/24', '10.250.10.1', false),
    (20, 'POS', 'Point of Sale terminals', '10.250.20.0/24', '10.250.20.1', true),
    (30, 'Staff', 'Staff devices', '10.250.30.0/24', '10.250.30.1', false),
    (40, 'Guest', 'Guest WiFi network', '10.250.40.0/24', '10.250.40.1', true),
    (99, 'IoT', 'IoT devices and sensors', '10.250.99.0/24', '10.250.99.1', true)
ON CONFLICT (vlan_id) DO NOTHING;

-- Threats table
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    threat_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source_ip INET,
    source_mac VARCHAR(17),
    destination_ip INET,
    destination_port INTEGER,
    protocol VARCHAR(10),
    description TEXT,
    mitre_attack_id VARCHAR(20),
    is_blocked BOOLEAN DEFAULT FALSE,
    blocked_at TIMESTAMP WITH TIME ZONE,
    evidence JSONB DEFAULT '{}'::jsonb,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_detected ON threats(detected_at);
CREATE INDEX IF NOT EXISTS idx_threats_source ON threats(source_ip);

-- QSecBit scores history
CREATE TABLE IF NOT EXISTS qsecbit_history (
    id SERIAL PRIMARY KEY,
    score DECIMAL(5,4) NOT NULL,
    rag_status VARCHAR(10) NOT NULL,
    components JSONB NOT NULL,
    layer_stats JSONB,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_qsecbit_recorded ON qsecbit_history(recorded_at);

-- DNS queries log (for analytics)
CREATE TABLE IF NOT EXISTS dns_queries (
    id BIGSERIAL PRIMARY KEY,
    client_ip INET NOT NULL,
    client_mac VARCHAR(17),
    domain VARCHAR(255) NOT NULL,
    query_type VARCHAR(10),
    response_code VARCHAR(20),
    is_blocked BOOLEAN DEFAULT FALSE,
    block_reason VARCHAR(50),
    category VARCHAR(50),
    queried_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries USING gin(domain gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_dns_client ON dns_queries(client_ip);
CREATE INDEX IF NOT EXISTS idx_dns_blocked ON dns_queries(is_blocked) WHERE is_blocked = TRUE;
CREATE INDEX IF NOT EXISTS idx_dns_queried ON dns_queries(queried_at);

-- Audit log for admin actions
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    parameters JSONB,
    file_path VARCHAR(500),
    file_size INTEGER,
    generated_by VARCHAR(50),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scheduled reports
CREATE TABLE IF NOT EXISTS scheduled_reports (
    id SERIAL PRIMARY KEY,
    report_type VARCHAR(50) NOT NULL,
    schedule VARCHAR(50) NOT NULL,
    parameters JSONB,
    email_recipients TEXT[],
    is_enabled BOOLEAN DEFAULT TRUE,
    last_run TIMESTAMP WITH TIME ZONE,
    next_run TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create views for common queries
CREATE OR REPLACE VIEW v_device_summary AS
SELECT
    vlan_id,
    COUNT(*) as device_count,
    COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '5 minutes') as active_count,
    COUNT(*) FILTER (WHERE is_blocked) as blocked_count
FROM devices
GROUP BY vlan_id;

CREATE OR REPLACE VIEW v_threat_summary AS
SELECT
    DATE_TRUNC('hour', detected_at) as hour,
    threat_type,
    severity,
    COUNT(*) as count
FROM threats
WHERE detected_at > NOW() - INTERVAL '24 hours'
GROUP BY DATE_TRUNC('hour', detected_at), threat_type, severity
ORDER BY hour DESC;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO fortress;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO fortress;

SCHEMA

    log_info "Database schema initialized"
}

# ============================================================
# REDIS CONTAINER
# ============================================================
create_redis_container() {
    log_step "Creating Redis container..."

    local REDIS_PASSWORD=$(cat "$SECRETS_DIR/database/redis_password")

    podman run -d \
        --pod "$POD_NAME" \
        --name fortress-redis \
        --restart unless-stopped \
        -v "$DATA_DIR/redis:/data:Z" \
        "${REDIS_IMAGE}" \
        redis-server --appendonly yes --requirepass "${REDIS_PASSWORD}"

    log_info "Redis container created"
}

# ============================================================
# STATUS CHECK
# ============================================================
check_status() {
    echo ""
    echo "=== Fortress Pod Status ==="
    echo ""
    podman pod ps --filter name="$POD_NAME"
    echo ""
    echo "=== Container Status ==="
    podman ps --filter pod="$POD_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
}

# ============================================================
# CLEANUP
# ============================================================
cleanup() {
    log_step "Cleaning up Fortress containers..."

    podman pod exists "$POD_NAME" 2>/dev/null && {
        podman pod stop "$POD_NAME" 2>/dev/null || true
        podman pod rm -f "$POD_NAME" 2>/dev/null || true
        log_info "Pod removed"
    }

    # Remove VXLAN interfaces
    ip link del vxlan${VXLAN_CORE_VNI} 2>/dev/null || true
    ip link del vxlan${VXLAN_MSSP_VNI} 2>/dev/null || true

    log_info "Cleanup complete"
}

# ============================================================
# MAIN
# ============================================================
main() {
    case "${1:-}" in
        start|up)
            setup_secrets
            setup_data_dirs
            setup_vxlan
            create_pod
            create_postgres_container
            create_redis_container
            check_status
            log_info "Fortress pod started successfully"
            log_info "PostgreSQL: localhost:5432 (user: fortress)"
            log_info "Redis: localhost:6379"
            log_info "Web Portal: https://localhost:8443"
            ;;
        stop|down)
            podman pod stop "$POD_NAME" 2>/dev/null || true
            log_info "Fortress pod stopped"
            ;;
        restart)
            podman pod restart "$POD_NAME" 2>/dev/null || {
                $0 stop
                $0 start
            }
            ;;
        status)
            check_status
            ;;
        logs)
            local container="${2:-fortress-postgres}"
            podman logs -f "$container"
            ;;
        shell)
            local container="${2:-fortress-postgres}"
            podman exec -it "$container" /bin/sh
            ;;
        psql)
            local POSTGRES_PASSWORD=$(cat "$SECRETS_DIR/database/postgres_password")
            podman exec -it fortress-postgres psql -U fortress -d fortress
            ;;
        cleanup|remove)
            cleanup
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|status|logs|shell|psql|cleanup}"
            echo ""
            echo "Commands:"
            echo "  start    - Start Fortress pod and containers"
            echo "  stop     - Stop Fortress pod"
            echo "  restart  - Restart Fortress pod"
            echo "  status   - Show pod and container status"
            echo "  logs     - Show container logs (default: postgres)"
            echo "  shell    - Open shell in container"
            echo "  psql     - Open PostgreSQL shell"
            echo "  cleanup  - Remove all containers and data"
            exit 1
            ;;
    esac
}

main "$@"
