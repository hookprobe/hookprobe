#!/bin/bash
#
# network-config.sh - Enhanced Network Configuration for HookProbe Architecture
# Version: 1.0 - Complete 6-POD Infrastructure with IAM and Monitoring
#

# ============================================================
# PHYSICAL HOST CONFIGURATION
# ============================================================
# (!!!) EDIT THESE TO MATCH YOUR ENVIRONMENT (!!!)
HOST_A_IP="192.168.1.100"              # Physical IP of Host A
HOST_B_IP="192.168.1.101"              # Physical IP of Host B (if multi-host)
PHYSICAL_HOST_INTERFACE="eth0"         # Physical network interface
INTERNET_GATEWAY="192.168.1.1"         # Default gateway to internet

# ============================================================
# OVS BRIDGE CONFIGURATION
# ============================================================
OVS_MAIN_BRIDGE="ovs-br0"              # Main OVS bridge
OVS_DMZ_BRIDGE="ovs-br-dmz"            # DMZ bridge for POD 001
OVS_INTERNAL_BRIDGE="ovs-br-internal"  # Internal services bridge

# ============================================================
# VXLAN ENCRYPTION (PSK)
# ============================================================
# CRITICAL: Must be identical on all hosts in cluster
OVS_PSK_MAIN="HookProbe_Main_VXLAN_Key_2025_CHANGE_ME"
OVS_PSK_DMZ="HookProbe_DMZ_VXLAN_Key_2025_CHANGE_ME"
OVS_PSK_INTERNAL="HookProbe_Internal_VXLAN_Key_2025_CHANGE_ME"

# ============================================================
# VXLAN NETWORK IDENTIFIERS (VNI)
# ============================================================
VNI_MAIN=100                           # Main management network
VNI_DMZ=101                            # DMZ network (POD 001)
VNI_IAM=102                            # IAM network (POD 002)
VNI_DB_PERSISTENT=103                  # Persistent DB network (POD 003)
VNI_DB_TRANSIENT=104                   # Transient DB network (POD 004)
VNI_MONITORING=105                     # Monitoring network (POD 005)
VNI_SECURITY=106                       # Security/IDS network (POD 006)

VXLAN_PORT=4789                        # Standard VXLAN port

# ============================================================
# IP SUBNET ALLOCATION
# ============================================================
# Management Network
SUBNET_MAIN="10.100.0.0/24"
GATEWAY_MAIN="10.100.0.1"

# POD 001 - Web App/DMZ Network
SUBNET_POD001="10.101.0.0/24"
GATEWAY_POD001="10.101.0.1"
IP_POD001_DJANGO="10.101.0.10"
IP_POD001_NGINX="10.101.0.11"
IP_POD001_RESERVED_1="10.101.0.20"      # Reserved for expansion
IP_POD001_RESERVED_2="10.101.0.21"      # Reserved for expansion

# POD 002 - IAM/Authentication Services Network
SUBNET_POD002="10.102.0.0/24"
GATEWAY_POD002="10.102.0.1"
IP_POD002_LOGTO="10.102.0.10"
IP_POD002_LOGTO_DB="10.102.0.11"
IP_POD002_KEYCLOAK="10.102.0.12"        # Alternative IAM
IP_POD002_LDAP="10.102.0.13"            # LDAP for PAM integration
IP_POD002_RESERVED_1="10.102.0.20"      # Reserved for expansion
IP_POD002_RESERVED_2="10.102.0.21"      # Reserved for expansion
IP_POD002_RESERVED_3="10.102.0.22"      # Reserved for expansion

# POD 003 - Persistent Database Network
SUBNET_POD003="10.103.0.0/24"
GATEWAY_POD003="10.103.0.1"
IP_POD003_POSTGRES="10.103.0.10"
IP_POD003_NFS="10.103.0.11"
IP_POD003_RADIUS="10.103.0.12"
IP_POD003_RESERVED_1="10.103.0.20"      # Reserved for expansion
IP_POD003_RESERVED_2="10.103.0.21"      # Reserved for expansion

# POD 004 - Transient Database Network
SUBNET_POD004="10.104.0.0/24"
GATEWAY_POD004="10.104.0.1"
IP_POD004_REDIS="10.104.0.10"
IP_POD004_TRANSIENT_DB="10.104.0.11"
IP_POD004_RESERVED_1="10.104.0.20"      # Reserved for expansion
IP_POD004_RESERVED_2="10.104.0.21"      # Reserved for expansion

# POD 005 - Monitoring/Development Network
SUBNET_POD005="10.105.0.0/24"
GATEWAY_POD005="10.105.0.1"
IP_POD005_GRAFANA="10.105.0.10"
IP_POD005_PROMETHEUS="10.105.0.11"
IP_POD005_LOKI="10.105.0.12"
IP_POD005_PROMTAIL="10.105.0.13"
IP_POD005_ALERTMANAGER="10.105.0.14"
IP_POD005_NODE_EXPORTER="10.105.0.15"
IP_POD005_CADVISOR="10.105.0.16"        # Container metrics
IP_POD005_LEARNING="10.105.0.20"        # Development/Testing
IP_POD005_RESERVED_1="10.105.0.30"      # Reserved for expansion
IP_POD005_RESERVED_2="10.105.0.31"      # Reserved for expansion

# POD 006 - Security/IDS Network
SUBNET_POD006="10.106.0.0/24"
GATEWAY_POD006="10.106.0.1"
IP_POD006_IDS="10.106.0.10"
IP_POD006_IPS="10.106.0.11"
IP_POD006_FIREWALL="10.106.0.12"
IP_POD006_RESERVED_1="10.106.0.20"      # Reserved for expansion
IP_POD006_RESERVED_2="10.106.0.21"      # Reserved for expansion

# ============================================================
# CONTAINER IMAGES
# ============================================================
IMAGE_DJANGO="docker.io/library/python:3.12-slim"
IMAGE_NGINX="docker.io/library/nginx:1.27-alpine"
IMAGE_POSTGRES="docker.io/library/postgres:16-alpine"
IMAGE_REDIS="docker.io/library/redis:7-alpine"
IMAGE_SURICATA="docker.io/jasonish/suricata:latest"
IMAGE_SNORT="docker.io/ciscotalos/snort3:latest"
IMAGE_LOGTO="docker.io/svhd/logto:latest"
IMAGE_GRAFANA="docker.io/grafana/grafana:latest"
IMAGE_PROMETHEUS="docker.io/prom/prometheus:latest"
IMAGE_LOKI="docker.io/grafana/loki:latest"
IMAGE_PROMTAIL="docker.io/grafana/promtail:latest"
IMAGE_ALERTMANAGER="docker.io/prom/alertmanager:latest"
IMAGE_NODE_EXPORTER="docker.io/prom/node-exporter:latest"
IMAGE_CADVISOR="gcr.io/cadvisor/cadvisor:latest"

# ============================================================
# DATABASE CREDENTIALS
# ============================================================
POSTGRES_DB="hookprobe_db"
POSTGRES_USER="hookprobe_admin"
POSTGRES_PASSWORD="CHANGE_ME_STRONG_PASSWORD_123"

# Logto IAM Database
LOGTO_DB="logto_db"
LOGTO_DB_USER="logto_admin"
LOGTO_DB_PASSWORD="CHANGE_ME_LOGTO_DB_PASSWORD"

# ============================================================
# DJANGO CONFIGURATION
# ============================================================
DJANGO_SECRET_KEY="CHANGE_ME_DJANGO_SECRET_KEY_LONG_RANDOM_STRING"
DJANGO_DEBUG="False"
DJANGO_ALLOWED_HOSTS="*"  # Change in production

# ============================================================
# LOGTO IAM CONFIGURATION
# ============================================================
LOGTO_ENDPOINT="http://10.102.0.10:3001"
LOGTO_ADMIN_ENDPOINT="http://10.102.0.10:3002"

# ============================================================
# VOLUME NAMES
# ============================================================
VOLUME_POSTGRES_DATA="hookprobe-postgres-data"
VOLUME_DJANGO_STATIC="hookprobe-django-static"
VOLUME_DJANGO_MEDIA="hookprobe-django-media"
VOLUME_NGINX_CONF="hookprobe-nginx-conf"
VOLUME_MONITORING_DATA="hookprobe-monitoring-data"
VOLUME_IDS_LOGS="hookprobe-ids-logs"
VOLUME_LOGTO_DB="hookprobe-logto-db"
VOLUME_GRAFANA_DATA="hookprobe-grafana-data"
VOLUME_PROMETHEUS_DATA="hookprobe-prometheus-data"
VOLUME_LOKI_DATA="hookprobe-loki-data"
VOLUME_ALERTMANAGER_DATA="hookprobe-alertmanager-data"

# ============================================================
# POD NAMES
# ============================================================
POD_001_NAME="hookprobe-pod-001-web-dmz"
POD_002_NAME="hookprobe-pod-002-iam"
POD_003_NAME="hookprobe-pod-003-db-persistent"
POD_004_NAME="hookprobe-pod-004-db-transient"
POD_005_NAME="hookprobe-pod-005-monitoring"
POD_006_NAME="hookprobe-pod-006-security"

# ============================================================
# NETWORK NAMES (PODMAN)
# ============================================================
NETWORK_POD001="pod001-dmz-net"
NETWORK_POD002="pod002-iam-net"
NETWORK_POD003="pod003-db-persistent-net"
NETWORK_POD004="pod004-db-transient-net"
NETWORK_POD005="pod005-monitoring-net"
NETWORK_POD006="pod006-security-net"

# ============================================================
# PORT MAPPINGS (Host -> Container)
# ============================================================
# POD 001 - Web/DMZ
PORT_HTTP=80
PORT_HTTPS=443

# POD 002 - IAM
PORT_LOGTO=3001
PORT_LOGTO_ADMIN=3002

# POD 003 - Databases
PORT_POSTGRES=5432
PORT_RADIUS=1812

# POD 005 - Monitoring
PORT_GRAFANA=3000
PORT_PROMETHEUS=9090
PORT_ALERTMANAGER=9093
PORT_LOKI=3100

# ============================================================
# HELPER FUNCTIONS
# ============================================================

# Function to validate IP address format
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        echo "ERROR: Invalid IP address format: $ip"
        return 1
    fi
}

# Function to check if subnet is valid
validate_subnet() {
    local subnet=$1
    if [[ $subnet =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 0
    else
        echo "ERROR: Invalid subnet format: $subnet"
        return 1
    fi
}

# Export all variables
export HOST_A_IP HOST_B_IP PHYSICAL_HOST_INTERFACE INTERNET_GATEWAY
export OVS_MAIN_BRIDGE OVS_DMZ_BRIDGE OVS_INTERNAL_BRIDGE
export OVS_PSK_MAIN OVS_PSK_DMZ OVS_PSK_INTERNAL
export VNI_MAIN VNI_DMZ VNI_IAM VNI_DB_PERSISTENT VNI_DB_TRANSIENT VNI_MONITORING VNI_SECURITY
export SUBNET_MAIN GATEWAY_MAIN
export SUBNET_POD001 GATEWAY_POD001 IP_POD001_DJANGO IP_POD001_NGINX
export SUBNET_POD002 GATEWAY_POD002 IP_POD002_LOGTO IP_POD002_LOGTO_DB IP_POD002_KEYCLOAK IP_POD002_LDAP
export SUBNET_POD003 GATEWAY_POD003 IP_POD003_POSTGRES IP_POD003_NFS IP_POD003_RADIUS
export SUBNET_POD004 GATEWAY_POD004 IP_POD004_REDIS IP_POD004_TRANSIENT_DB
export SUBNET_POD005 GATEWAY_POD005 IP_POD005_GRAFANA IP_POD005_PROMETHEUS IP_POD005_LOKI IP_POD005_PROMTAIL IP_POD005_ALERTMANAGER
export SUBNET_POD006 GATEWAY_POD006 IP_POD006_IDS IP_POD006_IPS IP_POD006_FIREWALL
export POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD
export LOGTO_DB LOGTO_DB_USER LOGTO_DB_PASSWORD
export LOGTO_ENDPOINT LOGTO_ADMIN_ENDPOINT
export DJANGO_SECRET_KEY DJANGO_DEBUG DJANGO_ALLOWED_HOSTS

echo "============================================================"
echo "   HOOKPROBE NETWORK CONFIGURATION LOADED - v2.0"
echo "============================================================"
echo "Network Topology:"
echo "  Main Management: $SUBNET_MAIN"
echo "  POD 001 (Web DMZ): $SUBNET_POD001"
echo "  POD 002 (IAM): $SUBNET_POD002"
echo "  POD 003 (DB Persistent): $SUBNET_POD003"
echo "  POD 004 (DB Transient): $SUBNET_POD004"
echo "  POD 005 (Monitoring): $SUBNET_POD005"
echo "  POD 006 (Security): $SUBNET_POD006"
echo ""
echo "VXLAN Configuration:"
echo "  VNI 100: Management"
echo "  VNI 101: DMZ (PSK: DMZ)"
echo "  VNI 102: IAM (PSK: Main)"
echo "  VNI 103: DB Persistent (PSK: Internal)"
echo "  VNI 104: DB Transient (PSK: Internal)"
echo "  VNI 105: Monitoring (PSK: Main)"
echo "  VNI 106: Security (PSK: Internal)"
echo ""
echo "Key Services:"
echo "  Django CMS: ${IP_POD001_DJANGO}"
echo "  Logto IAM: ${IP_POD002_LOGTO}"
echo "  PostgreSQL: ${IP_POD003_POSTGRES}"
echo "  Redis: ${IP_POD004_REDIS}"
echo "  Grafana: ${IP_POD005_GRAFANA}"
echo "  Prometheus: ${IP_POD005_PROMETHEUS}"
echo "  Loki: ${IP_POD005_LOKI}"
echo "============================================================"
