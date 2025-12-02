#!/bin/bash
#
# backend-network-config.sh
# HookProbe MSSP Cloud Backend Configuration
# Version: 5.0
# License: MIT
#
# This configuration is for the centralized MSSP backend that receives
# data from multiple edge HookProbe deployments.
#

set -euo pipefail

# ============================================================
# DEPLOYMENT TYPE
# ============================================================
DEPLOYMENT_TYPE="cloud-backend"  # cloud-backend vs edge
MSSP_MODE="true"                  # Enable multi-tenant features

# ============================================================
# SYSTEM DETECTION (Cross-Compatible)
# ============================================================
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="$ID"
        OS_VERSION="$VERSION_ID"
    elif [ -f /etc/redhat-release ]; then
        OS_NAME="rhel"
        OS_VERSION=$(cat /etc/redhat-release | grep -oE '[0-9]+\.[0-9]+')
    else
        OS_NAME="unknown"
        OS_VERSION="unknown"
    fi

    export OS_NAME OS_VERSION
}

detect_os

# ============================================================
# PHYSICAL HOST CONFIGURATION
# ============================================================
# Detected: $OS_NAME $OS_VERSION
LOCAL_HOST_IP=$(ip route get 1.1.1.1 | awk '{print $7; exit}')
EXTERNAL_DOMAIN="mssp.hookprobe.com"         # Your MSSP domain
CLOUDFLARE_TUNNEL_TOKEN="CHANGE_ME"          # Cloudflare tunnel token

# ============================================================
# PODMAN POD DEFINITIONS
# ============================================================
POD_DORIS_FE="hookprobe-backend-doris-frontend"
POD_DORIS_BE="hookprobe-backend-doris-backend"
POD_INGESTION="hookprobe-backend-ingestion"
POD_MANAGEMENT="hookprobe-backend-management"

NETWORK_DORIS_FE="doris-frontend-net"
NETWORK_DORIS_BE="doris-backend-net"
NETWORK_INGESTION="ingestion-net"
NETWORK_MANAGEMENT="management-net"

# ============================================================
# DORIS FRONTEND NETWORK (Query Coordinators)
# ============================================================
SUBNET_DORIS_FE="10.100.1.0/24"
GATEWAY_DORIS_FE="10.100.1.1"
IP_DORIS_FE_1="10.100.1.10"
IP_DORIS_FE_2="10.100.1.11"
IP_DORIS_FE_3="10.100.1.12"

# ============================================================
# DORIS BACKEND NETWORK (Storage + Compute)
# ============================================================
SUBNET_DORIS_BE="10.100.2.0/24"
GATEWAY_DORIS_BE="10.100.2.1"
IP_DORIS_BE_1="10.100.2.10"
IP_DORIS_BE_2="10.100.2.11"
IP_DORIS_BE_3="10.100.2.12"
# Add more backend nodes as needed
# IP_DORIS_BE_4="10.100.2.13"
# IP_DORIS_BE_5="10.100.2.14"

# ============================================================
# INGESTION NETWORK (Data from Edge Devices)
# ============================================================
SUBNET_INGESTION="10.100.3.0/24"
GATEWAY_INGESTION="10.100.3.1"
IP_KAFKA="10.100.3.10"
IP_VECTOR="10.100.3.11"
IP_REDIS_STREAM="10.100.3.12"

# ============================================================
# MANAGEMENT NETWORK (Grafana, PostgreSQL, Admin)
# ============================================================
SUBNET_MANAGEMENT="10.100.4.0/24"
GATEWAY_MANAGEMENT="10.100.4.1"
IP_GRAFANA="10.100.4.10"
IP_POSTGRES_MGMT="10.100.4.11"
IP_KEYCLOAK="10.100.4.12"
IP_REDIS_CACHE="10.100.4.13"
IP_NGINX="10.100.4.14"

# ============================================================
# CONTAINER IMAGES
# ============================================================
IMAGE_DORIS="apache/doris:2.1.0"                                    # Apache 2.0
IMAGE_KAFKA="docker.io/bitnami/kafka:3.6"                          # Apache 2.0
IMAGE_VECTOR="docker.io/timberio/vector:latest-alpine"             # Apache 2.0
IMAGE_GRAFANA="docker.io/grafana/grafana:11.4.0"                   # AGPL-3 (service use OK)
IMAGE_POSTGRES="docker.io/postgres:16-alpine"                      # PostgreSQL License
IMAGE_KEYCLOAK="quay.io/keycloak/keycloak:23.0"                    # Apache 2.0
IMAGE_REDIS="docker.io/redis:7-alpine"                              # BSD-3-Clause
IMAGE_NGINX="docker.io/nginx:1.25-alpine"                          # BSD-2-Clause

# ============================================================
# DORIS CLUSTER CONFIGURATION
# ============================================================
DORIS_CLUSTER_NAME="hookprobe-mssp"
DORIS_FE_COUNT=3                    # Number of Frontend nodes (HA: 3 or 5)
DORIS_BE_COUNT=3                    # Number of Backend nodes (scale as needed)
DORIS_REPLICATION=3                 # Data replication factor

# Frontend configuration
DORIS_FE_HTTP_PORT=8030
DORIS_FE_RPC_PORT=9020
DORIS_FE_QUERY_PORT=9030
DORIS_FE_EDIT_LOG_PORT=9010

# Backend configuration
DORIS_BE_HEARTBEAT_PORT=9050
DORIS_BE_THRIFT_PORT=9060
DORIS_BE_BRPC_PORT=8060
DORIS_BE_HTTP_PORT=8040

# Resource limits
DORIS_FE_MEMORY="16GB"              # Frontend JVM heap
DORIS_BE_MEMORY="64GB"              # Backend memory limit
DORIS_BE_STORAGE="/mnt/doris"       # Backend storage path (NVMe SSD)

# ============================================================
# DORIS DATABASE CONFIGURATION
# ============================================================
DORIS_ADMIN_USER="admin"
DORIS_ADMIN_PASSWORD="CHANGE_ME_DORIS_ADMIN_STRONG_PASSWORD"
DORIS_DB_SECURITY="security"        # Main database for security events
DORIS_RETENTION_DAYS=365            # Default retention (1 year)
DORIS_COMPRESSION="ZSTD"            # Compression algorithm

# Multi-tenant configuration
TENANT_ISOLATION="true"             # Enable row-level security
DEFAULT_TENANT_QUOTA_CPU="10%"      # Default CPU quota per tenant
DEFAULT_TENANT_QUOTA_MEMORY="10GB"  # Default memory quota per tenant

# ============================================================
# KAFKA CONFIGURATION (Edge Data Ingestion)
# ============================================================
KAFKA_CLUSTER_ID="hookprobe-mssp-kafka"
KAFKA_TOPICS="security-events,qsecbit-scores,waf-events,network-flows,honeypot-attacks"
KAFKA_PARTITIONS=32                 # Partitions per topic
KAFKA_REPLICATION=3                 # Topic replication factor
KAFKA_RETENTION_HOURS=72            # Keep data for 3 days (before Doris ingestion)

# ============================================================
# GRAFANA MULTI-TENANT CONFIGURATION
# ============================================================
GRAFANA_ADMIN_USER="admin"
GRAFANA_ADMIN_PASSWORD="CHANGE_ME_GRAFANA_ADMIN_PASSWORD"
GRAFANA_ORG_MODE="multi-org"        # Multi-organization mode
GRAFANA_ALLOW_SIGNUP="false"        # Disable public signup
GRAFANA_DISABLE_GRAVATAR="true"     # Privacy

# ============================================================
# POSTGRESQL MANAGEMENT DATABASE
# ============================================================
POSTGRES_MGMT_USER="hookprobe_mgmt"
POSTGRES_MGMT_PASSWORD="CHANGE_ME_POSTGRES_MGMT_PASSWORD"
POSTGRES_MGMT_DB="mssp_management"

# Tenant management tables
POSTGRES_TENANT_TABLE="tenants"
POSTGRES_EDGE_DEVICES_TABLE="edge_devices"
POSTGRES_BILLING_TABLE="billing"

# ============================================================
# KEYCLOAK SSO (Multi-Tenant Authentication)
# ============================================================
KEYCLOAK_ADMIN_USER="admin"
KEYCLOAK_ADMIN_PASSWORD="CHANGE_ME_KEYCLOAK_ADMIN_PASSWORD"
KEYCLOAK_DB_VENDOR="postgres"
KEYCLOAK_DB_ADDR="$IP_POSTGRES_MGMT"
KEYCLOAK_DB_DATABASE="keycloak"
KEYCLOAK_DB_USER="keycloak"
KEYCLOAK_DB_PASSWORD="CHANGE_ME_KEYCLOAK_DB_PASSWORD"

# ============================================================
# REDIS CONFIGURATION
# ============================================================
REDIS_STREAM_PASSWORD="CHANGE_ME_REDIS_STREAM_PASSWORD"
REDIS_CACHE_PASSWORD="CHANGE_ME_REDIS_CACHE_PASSWORD"

# ============================================================
# VECTOR CONFIGURATION (Log Aggregation from Edge)
# ============================================================
VECTOR_API_PORT=8686
VECTOR_KAFKA_BOOTSTRAP="$IP_KAFKA:9092"
VECTOR_DORIS_ENDPOINT="http://$IP_DORIS_FE_1:$DORIS_FE_HTTP_PORT"

# ============================================================
# STORAGE VOLUMES
# ============================================================
VOLUME_DORIS_FE_1="hookprobe-doris-fe-1-meta"
VOLUME_DORIS_FE_2="hookprobe-doris-fe-2-meta"
VOLUME_DORIS_FE_3="hookprobe-doris-fe-3-meta"

VOLUME_DORIS_BE_1="hookprobe-doris-be-1-storage"
VOLUME_DORIS_BE_2="hookprobe-doris-be-2-storage"
VOLUME_DORIS_BE_3="hookprobe-doris-be-3-storage"

VOLUME_KAFKA_DATA="hookprobe-kafka-data"
VOLUME_POSTGRES_MGMT="hookprobe-postgres-mgmt"
VOLUME_GRAFANA_DATA="hookprobe-grafana-backend"
VOLUME_KEYCLOAK_DATA="hookprobe-keycloak-data"

# ============================================================
# PORT MAPPINGS (External Access)
# ============================================================
PORT_DORIS_FE_HTTP=8030             # Doris Frontend HTTP
PORT_DORIS_FE_QUERY=9030            # Doris MySQL protocol
PORT_KAFKA_EXTERNAL=9092            # Kafka from edge devices
PORT_GRAFANA=3000                   # Grafana dashboards
PORT_KEYCLOAK=8080                  # Keycloak SSO
PORT_NGINX_HTTP=80                  # Nginx reverse proxy
PORT_NGINX_HTTPS=443                # Nginx SSL

# ============================================================
# FEATURE FLAGS
# ============================================================
ENABLE_GPU_INTEGRATION="false"      # Enable GPU ML nodes
ENABLE_THREAT_INTEL="true"          # Cross-customer threat intelligence
ENABLE_AUTOMATED_RESPONSE="true"    # Automated mitigation
ENABLE_COMPLIANCE_LOGGING="true"    # Audit logs for compliance
ENABLE_DATA_ENCRYPTION="true"       # Encrypt data at rest

# GPU Configuration (if enabled)
GPU_NODE_COUNT=0                    # Number of GPU nodes
GPU_TYPE="nvidia-a100"              # GPU type
GPU_MEMORY="80GB"                   # GPU memory per node

# ============================================================
# SECURITY CONFIGURATION
# ============================================================
TLS_ENABLED="true"
TLS_CERT_PATH="/opt/hookprobe/certs/tls.crt"
TLS_KEY_PATH="/opt/hookprobe/certs/tls.key"
TLS_CA_PATH="/opt/hookprobe/certs/ca.crt"

# Firewall
FIREWALL_ENABLED="true"
FIREWALL_ALLOWED_SOURCES="0.0.0.0/0"  # Restrict to edge device IPs in production

# ============================================================
# BACKUP CONFIGURATION
# ============================================================
BACKUP_ENABLED="true"
BACKUP_S3_BUCKET="s3://hookprobe-mssp-backups"
BACKUP_RETENTION_DAYS=30
BACKUP_SCHEDULE="0 2 * * *"         # Daily at 2 AM

# ============================================================
# MONITORING CONFIGURATION
# ============================================================
ENABLE_METRICS="true"
PROMETHEUS_ENDPOINT="http://prometheus.mssp.hookprobe.com"
ALERTMANAGER_ENDPOINT="http://alertmanager.mssp.hookprobe.com"

# ============================================================
# EXPORTS (for use in setup.sh)
# ============================================================
export DEPLOYMENT_TYPE MSSP_MODE OS_NAME OS_VERSION
export LOCAL_HOST_IP EXTERNAL_DOMAIN
export POD_DORIS_FE POD_DORIS_BE POD_INGESTION POD_MANAGEMENT
export NETWORK_DORIS_FE NETWORK_DORIS_BE NETWORK_INGESTION NETWORK_MANAGEMENT
export SUBNET_DORIS_FE SUBNET_DORIS_BE SUBNET_INGESTION SUBNET_MANAGEMENT
export IP_DORIS_FE_1 IP_DORIS_FE_2 IP_DORIS_FE_3
export IP_DORIS_BE_1 IP_DORIS_BE_2 IP_DORIS_BE_3
export IP_KAFKA IP_VECTOR IP_REDIS_STREAM
export IP_GRAFANA IP_POSTGRES_MGMT IP_KEYCLOAK IP_REDIS_CACHE IP_NGINX
export DORIS_CLUSTER_NAME DORIS_FE_COUNT DORIS_BE_COUNT DORIS_REPLICATION
export DORIS_ADMIN_USER DORIS_ADMIN_PASSWORD DORIS_DB_SECURITY
export KAFKA_CLUSTER_ID KAFKA_TOPICS
export GRAFANA_ADMIN_USER GRAFANA_ADMIN_PASSWORD
export POSTGRES_MGMT_USER POSTGRES_MGMT_PASSWORD POSTGRES_MGMT_DB
export KEYCLOAK_ADMIN_USER KEYCLOAK_ADMIN_PASSWORD
export TLS_ENABLED BACKUP_ENABLED ENABLE_GPU_INTEGRATION

# ============================================================
# CONFIGURATION SUMMARY
# ============================================================
echo "============================================================"
echo "HookProbe MSSP Cloud Backend Configuration Loaded"
echo "============================================================"
echo "OS: $OS_NAME $OS_VERSION"
echo "Host IP: $LOCAL_HOST_IP"
echo "Deployment: $DEPLOYMENT_TYPE"
echo ""
echo "Doris Cluster:"
echo "  Frontend Nodes: $DORIS_FE_COUNT"
echo "  Backend Nodes: $DORIS_BE_COUNT"
echo "  Replication Factor: $DORIS_REPLICATION"
echo ""
echo "Features:"
echo "  Multi-Tenant: $MSSP_MODE"
echo "  GPU Integration: $ENABLE_GPU_INTEGRATION"
echo "  Threat Intel: $ENABLE_THREAT_INTEL"
echo "  TLS: $TLS_ENABLED"
echo "  Backups: $BACKUP_ENABLED"
echo "============================================================"
