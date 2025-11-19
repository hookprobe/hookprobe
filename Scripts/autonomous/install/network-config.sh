#!/bin/bash
#
# network-config.sh - Enhanced Network Configuration for HookProbe Architecture
# Defines all network parameters for the 6-POD infrastructure
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
VNI_APP=102                            # Application network (POD 002)
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

# POD 002 - Application Services Network
SUBNET_POD002="10.102.0.0/24"
GATEWAY_POD002="10.102.0.1"
IP_POD002_APP="10.102.0.10"

# POD 003 - Persistent Database Network
SUBNET_POD003="10.103.0.0/24"
GATEWAY_POD003="10.103.0.1"
IP_POD003_POSTGRES="10.103.0.10"
IP_POD003_NFS="10.103.0.11"
IP_POD003_RADIUS="10.103.0.12"

# POD 004 - Transient Database Network
SUBNET_POD004="10.104.0.0/24"
GATEWAY_POD004="10.104.0.1"
IP_POD004_REDIS="10.104.0.10"
IP_POD004_TRANSIENT_DB="10.104.0.11"

# POD 005 - Monitoring/Development Network
SUBNET_POD005="10.105.0.0/24"
GATEWAY_POD005="10.105.0.1"
IP_POD005_MONITORING="10.105.0.10"
IP_POD005_LEARNING="10.105.0.11"

# POD 006 - Security/IDS Network
SUBNET_POD006="10.106.0.0/24"
GATEWAY_POD006="10.106.0.1"
IP_POD006_IDS="10.106.0.10"
IP_POD006_IPS="10.106.0.11"
IP_POD006_FIREWALL="10.106.0.12"

# ============================================================
# CONTAINER IMAGES
# ============================================================
IMAGE_DJANGO="docker.io/library/python:3.12-slim"
IMAGE_NGINX="docker.io/library/nginx:1.27-alpine"
IMAGE_POSTGRES="docker.io/library/postgres:16-alpine"
IMAGE_REDIS="docker.io/library/redis:7-alpine"
IMAGE_SURICATA="docker.io/jasonish/suricata:latest"
IMAGE_SNORT="docker.io/ciscotalos/snort3:latest"

# ============================================================
# DATABASE CREDENTIALS
# ============================================================
POSTGRES_DB="hookprobe_db"
POSTGRES_USER="hookprobe_admin"
POSTGRES_PASSWORD="CHANGE_ME_STRONG_PASSWORD_123"

# ============================================================
# DJANGO CONFIGURATION
# ============================================================
DJANGO_SECRET_KEY="CHANGE_ME_DJANGO_SECRET_KEY_LONG_RANDOM_STRING"
DJANGO_DEBUG="False"
DJANGO_ALLOWED_HOSTS="*"  # Change in production

# ============================================================
# VOLUME NAMES
# ============================================================
VOLUME_POSTGRES_DATA="hookprobe-postgres-data"
VOLUME_DJANGO_STATIC="hookprobe-django-static"
VOLUME_DJANGO_MEDIA="hookprobe-django-media"
VOLUME_NGINX_CONF="hookprobe-nginx-conf"
VOLUME_MONITORING_DATA="hookprobe-monitoring-data"
VOLUME_IDS_LOGS="hookprobe-ids-logs"

# ============================================================
# POD NAMES
# ============================================================
POD_001_NAME="hookprobe-pod-001-web-dmz"
POD_002_NAME="hookprobe-pod-002-app"
POD_003_NAME="hookprobe-pod-003-db-persistent"
POD_004_NAME="hookprobe-pod-004-db-transient"
POD_005_NAME="hookprobe-pod-005-monitoring"
POD_006_NAME="hookprobe-pod-006-security"

# ============================================================
# NETWORK NAMES (PODMAN)
# ============================================================
NETWORK_POD001="pod001-dmz-net"
NETWORK_POD002="pod002-app-net"
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

# POD 003 - Databases
PORT_POSTGRES=5432
PORT_RADIUS=1812

# POD 005 - Monitoring
PORT_MONITORING=9090

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
export VNI_MAIN VNI_DMZ VNI_APP VNI_DB_PERSISTENT VNI_DB_TRANSIENT VNI_MONITORING VNI_SECURITY
export SUBNET_MAIN GATEWAY_MAIN
export SUBNET_POD001 GATEWAY_POD001 IP_POD001_DJANGO IP_POD001_NGINX
export SUBNET_POD002 GATEWAY_POD002 IP_POD002_APP
export SUBNET_POD003 GATEWAY_POD003 IP_POD003_POSTGRES IP_POD003_NFS IP_POD003_RADIUS
export SUBNET_POD004 GATEWAY_POD004 IP_POD004_REDIS IP_POD004_TRANSIENT_DB
export SUBNET_POD005 GATEWAY_POD005 IP_POD005_MONITORING IP_POD005_LEARNING
export SUBNET_POD006 GATEWAY_POD006 IP_POD006_IDS IP_POD006_IPS IP_POD006_FIREWALL
export POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD
export DJANGO_SECRET_KEY DJANGO_DEBUG DJANGO_ALLOWED_HOSTS

echo "Network configuration loaded successfully."
echo "Main Management Network: $SUBNET_MAIN"
echo "POD 001 (DMZ): $SUBNET_POD001"
echo "POD 002 (APP): $SUBNET_POD002"
echo "POD 003 (DB-P): $SUBNET_POD003"
echo "POD 004 (DB-T): $SUBNET_POD004"
echo "POD 005 (MON): $SUBNET_POD005"
echo "POD 006 (SEC): $SUBNET_POD006"
