#!/bin/bash
#
# backend-setup.sh
# HookProbe MSSP Cloud Backend Deployment
# Version: 5.0
# License: AGPL-3.0 - see LICENSE file
#
# Deploys Apache Doris cluster for multi-tenant MSSP backend
# Cross-compatible: RHEL, Ubuntu, Fedora, CentOS Stream
#

set -euo pipefail

# ============================================================
# SCRIPT INITIALIZATION
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.sh"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Configuration file not found: $CONFIG_FILE"
    exit 1
fi

source "$CONFIG_FILE"

# Require root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root"
    exit 1
fi

# ============================================================
# LOGGING
# ============================================================
LOG_DIR="/var/log/hookprobe"
LOG_FILE="$LOG_DIR/backend-setup.log"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

exec > >(tee -a "$LOG_FILE")
exec 2>&1

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
}

# ============================================================
# OS-SPECIFIC PACKAGE INSTALLATION
# ============================================================
install_packages() {
    log "Installing required packages for $OS_NAME..."

    case "$OS_NAME" in
        rhel|centos|fedora|rocky|almalinux)
            # Core packages
            log "  → Installing core packages..."
            dnf install -y \
                podman \
                jq \
                curl \
                wget \
                git \
                vim \
                iotop \
                sysstat \
                nftables \
                firewalld \
                chrony \
                logrotate \
                tar \
                gzip \
                unzip || true

            # Optional packages (don't fail if not available)
            log "  → Installing optional packages..."
            dnf install -y htop 2>/dev/null || log "    ⚠ htop not available (using top instead)"

            # Note: podman-compose is not available in RHEL 10
            # We use 'podman compose' (native quadlet support) instead
            log "    ℹ Using native 'podman compose' (no podman-compose needed)"
            ;;
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                podman \
                jq \
                curl \
                wget \
                git \
                vim \
                htop \
                iotop \
                sysstat \
                nftables \
                ufw \
                chrony \
                logrotate \
                tar \
                gzip \
                unzip

            # podman-compose for Debian/Ubuntu (if available)
            apt-get install -y podman-compose 2>/dev/null || log "    ⚠ podman-compose not available"
            ;;
        *)
            error "Unsupported OS: $OS_NAME"
            exit 1
            ;;
    esac

    log "✓ Packages installed successfully"
}

# ============================================================
# SYSTEM TUNING FOR DORIS
# ============================================================
tune_system() {
    log "Tuning system for Doris cluster..."

    # Kernel parameters
    cat > /etc/sysctl.d/99-doris.conf << 'EOF'
# Doris performance tuning
vm.max_map_count=2000000
vm.swappiness=10
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.ip_local_port_range=1024 65535
fs.file-max=6553600
EOF

    sysctl -p /etc/sysctl.d/99-doris.conf

    # Increase user limits
    cat > /etc/security/limits.d/99-doris.conf << 'EOF'
* soft nofile 655360
* hard nofile 655360
* soft nproc 655360
* hard nproc 655360
* soft memlock unlimited
* hard memlock unlimited
EOF

    log "✓ System tuning complete"
}

# ============================================================
# STORAGE SETUP
# ============================================================
setup_storage() {
    log "Setting up storage directories..."

    mkdir -p "$DORIS_BE_STORAGE"/{be1,be2,be3}/{storage,log,temp}
    mkdir -p /opt/hookprobe/{certs,backups,logs}
    mkdir -p /var/lib/hookprobe/{kafka,postgres,grafana}

    # Set permissions
    chmod -R 755 "$DORIS_BE_STORAGE"
    chmod -R 755 /opt/hookprobe
    chmod -R 700 /opt/hookprobe/certs

    log "✓ Storage directories created"
}

# ============================================================
# PODMAN VOLUME CREATION
# ============================================================
create_volume() {
    local volume_name=$1
    if ! podman volume exists "$volume_name" 2>/dev/null; then
        podman volume create "$volume_name"
        log "  Created volume: $volume_name"
    else
        log "  Volume already exists: $volume_name"
    fi
}

create_volumes() {
    log "Creating Podman volumes..."

    create_volume "$VOLUME_DORIS_FE_1"
    create_volume "$VOLUME_DORIS_FE_2"
    create_volume "$VOLUME_DORIS_FE_3"
    create_volume "$VOLUME_DORIS_BE_1"
    create_volume "$VOLUME_DORIS_BE_2"
    create_volume "$VOLUME_DORIS_BE_3"
    create_volume "$VOLUME_KAFKA_DATA"
    create_volume "$VOLUME_POSTGRES_MGMT"
    create_volume "$VOLUME_GRAFANA_DATA"
    create_volume "$VOLUME_KEYCLOAK_DATA"

    log "✓ Volumes created"
}

# ============================================================
# NETWORK CREATION
# ============================================================
create_networks() {
    log "Creating Podman networks..."

    for network in "$NETWORK_DORIS_FE" "$NETWORK_DORIS_BE" "$NETWORK_INGESTION" "$NETWORK_MANAGEMENT"; do
        if ! podman network exists "$network" 2>/dev/null; then
            podman network create "$network"
            log "  Created network: $network"
        else
            log "  Network already exists: $network"
        fi
    done

    log "✓ Networks created"
}

# ============================================================
# DORIS FRONTEND CLUSTER DEPLOYMENT
# ============================================================
deploy_doris_frontends() {
    log "Deploying Doris Frontend cluster ($DORIS_FE_COUNT nodes)..."

    # Frontend 1 (Master)
    log "  → Starting Doris Frontend 1 (Master)..."
    podman run -d --restart always \
        --name doris-fe-1 \
        --network "$NETWORK_DORIS_FE" \
        --ip "$IP_DORIS_FE_1" \
        -p ${PORT_DORIS_FE_HTTP}:8030 \
        -p ${PORT_DORIS_FE_QUERY}:9030 \
        -v "$VOLUME_DORIS_FE_1:/opt/apache-doris/fe/doris-meta" \
        -e FE_SERVERS="fe1:$IP_DORIS_FE_1:9010" \
        -e FE_ID=1 \
        -e JAVA_OPTS="-Xmx${DORIS_FE_MEMORY}" \
        --health-cmd "curl -f http://localhost:8030/api/bootstrap || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 120s \
        --log-driver=journald \
        --log-opt tag="doris-fe-1" \
        "$IMAGE_DORIS" \
        /opt/apache-doris/fe/bin/start_fe.sh

    sleep 10

    # Frontend 2 (Follower)
    log "  → Starting Doris Frontend 2 (Follower)..."
    podman run -d --restart always \
        --name doris-fe-2 \
        --network "$NETWORK_DORIS_FE" \
        --ip "$IP_DORIS_FE_2" \
        -v "$VOLUME_DORIS_FE_2:/opt/apache-doris/fe/doris-meta" \
        -e FE_SERVERS="fe1:$IP_DORIS_FE_1:9010,fe2:$IP_DORIS_FE_2:9010" \
        -e FE_ID=2 \
        -e FE_MASTER_HOST="$IP_DORIS_FE_1" \
        -e FE_MASTER_PORT=9010 \
        -e JAVA_OPTS="-Xmx${DORIS_FE_MEMORY}" \
        --health-cmd "curl -f http://localhost:8030/api/bootstrap || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 120s \
        --log-driver=journald \
        --log-opt tag="doris-fe-2" \
        "$IMAGE_DORIS" \
        /opt/apache-doris/fe/bin/start_fe.sh

    sleep 10

    # Frontend 3 (Follower)
    log "  → Starting Doris Frontend 3 (Follower)..."
    podman run -d --restart always \
        --name doris-fe-3 \
        --network "$NETWORK_DORIS_FE" \
        --ip "$IP_DORIS_FE_3" \
        -v "$VOLUME_DORIS_FE_3:/opt/apache-doris/fe/doris-meta" \
        -e FE_SERVERS="fe1:$IP_DORIS_FE_1:9010,fe2:$IP_DORIS_FE_2:9010,fe3:$IP_DORIS_FE_3:9010" \
        -e FE_ID=3 \
        -e FE_MASTER_HOST="$IP_DORIS_FE_1" \
        -e FE_MASTER_PORT=9010 \
        -e JAVA_OPTS="-Xmx${DORIS_FE_MEMORY}" \
        --health-cmd "curl -f http://localhost:8030/api/bootstrap || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 120s \
        --log-driver=journald \
        --log-opt tag="doris-fe-3" \
        "$IMAGE_DORIS" \
        /opt/apache-doris/fe/bin/start_fe.sh

    log "  → Waiting for Frontend cluster to stabilize..."
    sleep 30

    log "✓ Doris Frontend cluster deployed"
}

# ============================================================
# DORIS BACKEND CLUSTER DEPLOYMENT
# ============================================================
deploy_doris_backends() {
    log "Deploying Doris Backend cluster ($DORIS_BE_COUNT nodes)..."

    # Backend 1
    log "  → Starting Doris Backend 1..."
    podman run -d --restart always \
        --name doris-be-1 \
        --network "$NETWORK_DORIS_BE" \
        --ip "$IP_DORIS_BE_1" \
        -v "$VOLUME_DORIS_BE_1:/opt/apache-doris/be/storage" \
        -v "${DORIS_BE_STORAGE}/be1:/data" \
        -e FE_SERVERS="$IP_DORIS_FE_1:9010" \
        -e BE_ADDR="$IP_DORIS_BE_1:9050" \
        --memory="${DORIS_BE_MEMORY}" \
        --cpus=16 \
        --health-cmd "curl -f http://localhost:8040/api/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 120s \
        --log-driver=journald \
        --log-opt tag="doris-be-1" \
        "$IMAGE_DORIS" \
        /opt/apache-doris/be/bin/start_be.sh

    # Backend 2
    log "  → Starting Doris Backend 2..."
    podman run -d --restart always \
        --name doris-be-2 \
        --network "$NETWORK_DORIS_BE" \
        --ip "$IP_DORIS_BE_2" \
        -v "$VOLUME_DORIS_BE_2:/opt/apache-doris/be/storage" \
        -v "${DORIS_BE_STORAGE}/be2:/data" \
        -e FE_SERVERS="$IP_DORIS_FE_1:9010" \
        -e BE_ADDR="$IP_DORIS_BE_2:9050" \
        --memory="${DORIS_BE_MEMORY}" \
        --cpus=16 \
        --health-cmd "curl -f http://localhost:8040/api/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 120s \
        --log-driver=journald \
        --log-opt tag="doris-be-2" \
        "$IMAGE_DORIS" \
        /opt/apache-doris/be/bin/start_be.sh

    # Backend 3
    log "  → Starting Doris Backend 3..."
    podman run -d --restart always \
        --name doris-be-3 \
        --network "$NETWORK_DORIS_BE" \
        --ip "$IP_DORIS_BE_3" \
        -v "$VOLUME_DORIS_BE_3:/opt/apache-doris/be/storage" \
        -v "${DORIS_BE_STORAGE}/be3:/data" \
        -e FE_SERVERS="$IP_DORIS_FE_1:9010" \
        -e BE_ADDR="$IP_DORIS_BE_3:9050" \
        --memory="${DORIS_BE_MEMORY}" \
        --cpus=16 \
        --health-cmd "curl -f http://localhost:8040/api/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 120s \
        --log-driver=journald \
        --log-opt tag="doris-be-3" \
        "$IMAGE_DORIS" \
        /opt/apache-doris/be/bin/start_be.sh

    log "  → Waiting for Backend cluster to register..."
    sleep 20

    log "✓ Doris Backend cluster deployed"
}

# ============================================================
# DORIS CLUSTER INITIALIZATION
# ============================================================
initialize_doris_cluster() {
    log "Initializing Doris cluster..."

    # Wait for FE to be ready
    log "  → Waiting for Frontend to be ready..."
    for i in {1..30}; do
        if curl -s "http://${IP_DORIS_FE_1}:8030/api/bootstrap" >/dev/null 2>&1; then
            log "  ✓ Frontend is ready"
            break
        fi
        sleep 5
    done

    # Register backends with frontend (via MySQL protocol)
    log "  → Registering Backend nodes..."

    # Note: In production, use mysql client to connect to FE:9030 and run:
    # ALTER SYSTEM ADD BACKEND "IP:PORT";
    # For automated setup, we'll create a helper script

    cat > /tmp/doris-init.sql << EOF
-- Add Backend nodes
ALTER SYSTEM ADD BACKEND "$IP_DORIS_BE_1:9050";
ALTER SYSTEM ADD BACKEND "$IP_DORIS_BE_2:9050";
ALTER SYSTEM ADD BACKEND "$IP_DORIS_BE_3:9050";

-- Create security database
CREATE DATABASE IF NOT EXISTS $DORIS_DB_SECURITY;

-- Set root password
SET PASSWORD FOR 'root'@'%' = PASSWORD('$DORIS_ADMIN_PASSWORD');
EOF

    log "  → Cluster initialization SQL created at /tmp/doris-init.sql"
    log "  → MANUAL STEP REQUIRED: Connect to Doris and run the SQL"
    log "    mysql -h $IP_DORIS_FE_1 -P 9030 -uroot < /tmp/doris-init.sql"

    log "✓ Doris cluster initialization prepared"
}

# ============================================================
# KAFKA DEPLOYMENT (Edge Data Ingestion)
# ============================================================
deploy_kafka() {
    log "Deploying Kafka for edge data ingestion..."

    podman run -d --restart always \
        --name hookprobe-kafka \
        --network "$NETWORK_INGESTION" \
        --ip "$IP_KAFKA" \
        -p ${PORT_KAFKA_EXTERNAL}:9092 \
        -v "$VOLUME_KAFKA_DATA:/bitnami/kafka" \
        -e KAFKA_CFG_NODE_ID=1 \
        -e KAFKA_CFG_PROCESS_ROLES=controller,broker \
        -e KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
        -e KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
        -e KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=1@$IP_KAFKA:9093 \
        -e KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER \
        -e KAFKA_CFG_AUTO_CREATE_TOPICS_ENABLE=true \
        --health-cmd "kafka-broker-api-versions.sh --bootstrap-server=localhost:9092 || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 60s \
        --log-driver=journald \
        --log-opt tag="hookprobe-kafka" \
        "$IMAGE_KAFKA"

    log "  → Waiting for Kafka to start..."
    sleep 15

    log "✓ Kafka deployed"
}

# ============================================================
# POSTGRESQL MANAGEMENT DATABASE
# ============================================================
deploy_postgres() {
    log "Deploying PostgreSQL management database..."

    podman run -d --restart always \
        --name hookprobe-postgres-mgmt \
        --network "$NETWORK_MANAGEMENT" \
        --ip "$IP_POSTGRES_MGMT" \
        -v "$VOLUME_POSTGRES_MGMT:/var/lib/postgresql/data" \
        -e POSTGRES_USER="$POSTGRES_MGMT_USER" \
        -e POSTGRES_PASSWORD="$POSTGRES_MGMT_PASSWORD" \
        -e POSTGRES_DB="$POSTGRES_MGMT_DB" \
        --health-cmd "pg_isready -U $POSTGRES_MGMT_USER -d $POSTGRES_MGMT_DB || exit 1" \
        --health-interval 30s \
        --health-timeout 5s \
        --health-retries 3 \
        --health-start-period 60s \
        --log-driver=journald \
        --log-opt tag="hookprobe-postgres-mgmt" \
        "$IMAGE_POSTGRES"

    log "  → Waiting for PostgreSQL to start..."
    sleep 10

    log "✓ PostgreSQL deployed"
}

# ============================================================
# GRAFANA MULTI-TENANT DEPLOYMENT
# ============================================================
deploy_grafana() {
    log "Deploying Grafana (multi-tenant mode)..."

    podman run -d --restart always \
        --name hookprobe-grafana-backend \
        --network "$NETWORK_MANAGEMENT" \
        --ip "$IP_GRAFANA" \
        -p ${PORT_GRAFANA}:3000 \
        -v "$VOLUME_GRAFANA_DATA:/var/lib/grafana" \
        -e GF_SECURITY_ADMIN_USER="$GRAFANA_ADMIN_USER" \
        -e GF_SECURITY_ADMIN_PASSWORD="$GRAFANA_ADMIN_PASSWORD" \
        -e GF_USERS_ALLOW_SIGN_UP=false \
        -e GF_AUTH_ANONYMOUS_ENABLED=false \
        -e GF_INSTALL_PLUGINS=vertamedia-clickhouse-datasource,yesoreyeram-infinity-datasource \
        --health-cmd "wget -q --spider http://localhost:3000/api/health || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 60s \
        --log-driver=journald \
        --log-opt tag="hookprobe-grafana-backend" \
        "$IMAGE_GRAFANA"

    log "✓ Grafana deployed"
}

# ============================================================
# MAIN DEPLOYMENT ORCHESTRATION
# ============================================================
main() {
    log "============================================================"
    log "HookProbe MSSP Cloud Backend Deployment"
    log "Version: 5.0 | License: AGPL-3.0"
    log "============================================================"
    log "OS: $OS_NAME $OS_VERSION"
    log "Host: $LOCAL_HOST_IP"
    log "============================================================"

    # Step 1: Install packages
    install_packages

    # Step 2: System tuning
    tune_system

    # Step 3: Storage setup
    setup_storage

    # Step 4: Create volumes
    create_volumes

    # Step 5: Create networks
    create_networks

    # Step 6: Deploy Doris Frontend cluster
    deploy_doris_frontends

    # Step 7: Deploy Doris Backend cluster
    deploy_doris_backends

    # Step 8: Initialize Doris cluster
    initialize_doris_cluster

    # Step 9: Deploy Kafka
    deploy_kafka

    # Step 10: Deploy PostgreSQL
    deploy_postgres

    # Step 11: Deploy Grafana
    deploy_grafana

    log "============================================================"
    log "DEPLOYMENT COMPLETE!"
    log "============================================================"
    log ""
    log "Next Steps:"
    log "1. Initialize Doris cluster:"
    log "   mysql -h $IP_DORIS_FE_1 -P 9030 -uroot < /tmp/doris-init.sql"
    log ""
    log "2. Access Grafana:"
    log "   http://$LOCAL_HOST_IP:$PORT_GRAFANA"
    log "   User: $GRAFANA_ADMIN_USER | Pass: (set in config)"
    log ""
    log "3. Configure edge devices to send data to:"
    log "   Kafka: $LOCAL_HOST_IP:$PORT_KAFKA_EXTERNAL"
    log ""
    log "4. Review logs:"
    log "   tail -f $LOG_FILE"
    log ""
    log "============================================================"
}

# Run main deployment
main
