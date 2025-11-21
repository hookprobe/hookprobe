#!/bin/bash
#
# setup.sh (v9 - Complete HookProbe Architecture with WAF + Cloudflare + Enhanced Logging)
#
# Automated deployment of HookProbe infrastructure with:
# - 7 PODs with isolated networks
# - OVS + VXLAN with PSK encryption
# - NAXSI WAF for web protection
# - Cloudflare Tunnel for secure access
# - Django CMS in POD 001
# - Logto IAM in POD 002
# - Database services in POD 003/004
# - Complete monitoring + centralized logging in POD 005
# - IDS/IPS in POD 006
# - Ai Automation response 007/003/004/005/006
#
# Target OS: RHEL/RedHat 10 / Fedora / CentOS Stream
#

set -e  # Exit on error
set -u  # Exit on undefined variable

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load network configuration
if [ -f "$SCRIPT_DIR/network-config.sh" ]; then
    source "$SCRIPT_DIR/network-config.sh"
else
    echo "ERROR: network-config.sh not found in $SCRIPT_DIR"
    exit 1
fi

echo "============================================================"
echo "   HOOKPROBE AUTONOMOUS DEPLOYMENT - 7 POD ARCHITECTURE"
echo "   Version 3.0 - WAF + Cloudflare Tunnel + Enhanced Logging"
echo "============================================================"

# ============================================================
# STEP 1: VALIDATE ENVIRONMENT
# ============================================================
echo ""
echo "[STEP 1] Validating environment..."

# Detect local host IP
LOCAL_HOST_IP=$(ip -4 addr show "$PHYSICAL_HOST_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "")
if [ -z "$LOCAL_HOST_IP" ]; then
    echo "ERROR: Could not detect IP on interface '$PHYSICAL_HOST_INTERFACE'"
    exit 1
fi
echo "✓ Local Host IP: $LOCAL_HOST_IP"

# Determine remote peer (for multi-host setups)
if [ "$LOCAL_HOST_IP" == "$HOST_A_IP" ]; then
    REMOTE_HOST_IP="$HOST_B_IP"
else
    REMOTE_HOST_IP="$HOST_A_IP"
fi
echo "✓ Remote Peer IP: $REMOTE_HOST_IP"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root"
   exit 1
fi

# Check Cloudflare token
if [ "$CLOUDFLARE_TUNNEL_TOKEN" == "CHANGE_ME_GET_FROM_CLOUDFLARE_DASHBOARD" ]; then
    echo "⚠️  WARNING: Cloudflare Tunnel token not configured"
    echo "   Cloudflare Tunnel will be skipped. Configure in network-config.sh to enable."
    SKIP_CLOUDFLARED=true
else
    echo "✓ Cloudflare Tunnel token configured"
    SKIP_CLOUDFLARED=false
fi

# Validate Qsecbit configuration
echo "✓ Qsecbit AI Response System configured"
echo "  Amber Threshold: $QSECBIT_AMBER_THRESHOLD"
echo "  Red Threshold: $QSECBIT_RED_THRESHOLD"
echo "  Auto-Response: $KALI_AUTO_RESPONSE"

# ============================================================
# STEP 2: INSTALL DEPENDENCIES
# ============================================================
echo ""
echo "[STEP 2] Installing required packages..."

REQUIRED_PACKAGES=(
    git curl wget unzip tar
    podman buildah skopeo
    openvswitch openvswitch-ipsec
    python3 python3-pip
    net-tools iproute bridge-utils
    kernel-modules-extra
    iptables firewalld
    postgresql-client
    rsyslog
    jq
)

dnf update -y
dnf install -y epel-release
dnf install -y "${REQUIRED_PACKAGES[@]}"

echo "✓ All dependencies installed"

# ============================================================
# STEP 3: CONFIGURE KERNEL MODULES
# ============================================================
echo ""
echo "[STEP 3] Loading kernel modules..."

modprobe openvswitch
modprobe vxlan
modprobe ip_tables
modprobe nf_conntrack

# Make modules persistent
cat > /etc/modules-load.d/hookprobe.conf << EOF
openvswitch
vxlan
ip_tables
nf_conntrack
EOF

echo "✓ Kernel modules loaded"

# ============================================================
# STEP 4: CREATE OVS BRIDGES AND VXLAN TUNNELS
# ============================================================
echo ""
echo "[STEP 4] Setting up Open vSwitch infrastructure..."

# Start OVS service
systemctl enable --now openvswitch
sleep 2

# Create main OVS bridge
echo "Creating main OVS bridge: $OVS_MAIN_BRIDGE"
ovs-vsctl --may-exist add-br "$OVS_MAIN_BRIDGE"

# Function to create VXLAN tunnel
create_vxlan_tunnel() {
    local bridge=$1
    local vni=$2
    local psk=$3
    local port_name="vxlan-${vni}"
    
    echo "  → Creating VXLAN tunnel: VNI=$vni on $bridge"
    
    ovs-vsctl --may-exist add-port "$bridge" "$port_name" -- \
        set interface "$port_name" type=vxlan \
        options:key="$vni" \
        options:remote_ip="$REMOTE_HOST_IP" \
        options:local_ip="$LOCAL_HOST_IP" \
        options:dst_port="$VXLAN_PORT" \
        options:psk="$psk"
}

# Create VXLAN tunnels for each POD network
create_vxlan_tunnel "$OVS_MAIN_BRIDGE" "$VNI_MAIN" "$OVS_PSK_MAIN"
create_vxlan_tunnel "$OVS_MAIN_BRIDGE" "$VNI_DMZ" "$OVS_PSK_DMZ"
create_vxlan_tunnel "$OVS_MAIN_BRIDGE" "$VNI_IAM" "$OVS_PSK_MAIN"
create_vxlan_tunnel "$OVS_MAIN_BRIDGE" "$VNI_DB_PERSISTENT" "$OVS_PSK_INTERNAL"
create_vxlan_tunnel "$OVS_MAIN_BRIDGE" "$VNI_DB_TRANSIENT" "$OVS_PSK_INTERNAL"
create_vxlan_tunnel "$OVS_MAIN_BRIDGE" "$VNI_MONITORING" "$OVS_PSK_MAIN"
create_vxlan_tunnel "$OVS_MAIN_BRIDGE" "$VNI_SECURITY" "$OVS_PSK_INTERNAL"
create_vxlan_tunnel "$OVS_MAIN_BRIDGE" "$VNI_AI_RESPONSE" "$OVS_PSK_INTERNAL"

# Configure main bridge IP
ip addr flush dev "$OVS_MAIN_BRIDGE" 2>/dev/null || true
ip addr add "$GATEWAY_MAIN" dev "$OVS_MAIN_BRIDGE"
ip link set "$OVS_MAIN_BRIDGE" up

echo "✓ OVS bridges and VXLAN tunnels created"

# ============================================================
# STEP 5: CONFIGURE FIREWALL
# ============================================================
echo ""
echo "[STEP 5] Configuring firewall rules..."

if command -v firewall-cmd &> /dev/null; then
    # Allow VXLAN
    firewall-cmd --permanent --add-port=${VXLAN_PORT}/udp
    
    # Allow IPsec
    firewall-cmd --permanent --add-port=500/udp
    firewall-cmd --permanent --add-port=4500/udp
    
    # Allow HTTP/HTTPS for POD 001
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    
    # Allow WAF management port
    firewall-cmd --permanent --add-port=${PORT_WAF}/tcp
    
    # Allow Logto ports
    firewall-cmd --permanent --add-port=${PORT_LOGTO}/tcp
    firewall-cmd --permanent --add-port=${PORT_LOGTO_ADMIN}/tcp
    
    # Allow monitoring ports
    firewall-cmd --permanent --add-port=${PORT_GRAFANA}/tcp
    firewall-cmd --permanent --add-port=${PORT_PROMETHEUS}/tcp
    firewall-cmd --permanent --add-port=${PORT_ALERTMANAGER}/tcp
    firewall-cmd --permanent --add-port=${PORT_LOKI}/tcp
    
    # Allow syslog ports
    firewall-cmd --permanent --add-port=${RSYSLOG_PORT}/udp
    firewall-cmd --permanent --add-port=${RSYSLOG_PORT}/tcp
    firewall-cmd --permanent --add-port=${RSYSLOG_TLS_PORT}/tcp
    
    # Trust OVS bridge
    firewall-cmd --permanent --zone=trusted --add-interface="$OVS_MAIN_BRIDGE"
    
    # Allow inter-pod communication
    firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.100.0.0/16" accept'
    
    firewall-cmd --reload
    echo "✓ Firewall configured"
else
    echo "⚠ firewalld not found, skipping firewall configuration"
fi

# ============================================================
# STEP 6: CONFIGURE RSYSLOG ON HOST
# ============================================================
echo ""
echo "[STEP 6] Configuring rsyslog for container log forwarding..."

# Create rsyslog configuration for container logs
cat > /etc/rsyslog.d/50-hookprobe-containers.conf << EOF
# Forward all container logs to centralized rsyslog server
*.* @@${IP_POD005_RSYSLOG}:${RSYSLOG_PORT}

# Also forward kernel logs
kern.* @@${IP_POD005_RSYSLOG}:${RSYSLOG_PORT}

# Forward authentication logs
auth,authpriv.* @@${IP_POD005_RSYSLOG}:${RSYSLOG_PORT}
EOF

# Restart rsyslog to apply changes
systemctl restart rsyslog
echo "✓ Rsyslog configured to forward logs to monitoring POD"

# ============================================================
# STEP 7: CREATE PODMAN NETWORKS
# ============================================================
echo ""
echo "[STEP 7] Creating Podman networks..."

# Function to create Podman network
create_podman_network() {
    local net_name=$1
    local subnet=$2
    local gateway=$3
    
    echo "  → Creating network: $net_name ($subnet)"
    
    # Remove if exists
    podman network exists "$net_name" 2>/dev/null && podman network rm "$net_name"
    
    # Create network
    podman network create \
        --driver bridge \
        --subnet="$subnet" \
        --gateway="$gateway" \
        "$net_name"
}

create_podman_network "$NETWORK_POD001" "$SUBNET_POD001" "$GATEWAY_POD001"
create_podman_network "$NETWORK_POD002" "$SUBNET_POD002" "$GATEWAY_POD002"
create_podman_network "$NETWORK_POD003" "$SUBNET_POD003" "$GATEWAY_POD003"
create_podman_network "$NETWORK_POD004" "$SUBNET_POD004" "$GATEWAY_POD004"
create_podman_network "$NETWORK_POD005" "$SUBNET_POD005" "$GATEWAY_POD005"
create_podman_network "$NETWORK_POD006" "$SUBNET_POD006" "$GATEWAY_POD006"
create_podman_network "$NETWORK_POD007" "$SUBNET_POD007" "$GATEWAY_POD007"

echo "✓ Podman networks created"

# ============================================================
# STEP 8: CREATE PERSISTENT VOLUMES
# ============================================================
echo ""
echo "[STEP 8] Creating persistent volumes..."

# Function to create volume if it doesn't exist
create_volume() {
    local vol_name=$1
    if ! podman volume exists "$vol_name" 2>/dev/null; then
        podman volume create "$vol_name"
        echo "  → Created volume: $vol_name"
    else
        echo "  → Volume exists: $vol_name"
    fi
}

create_volume "$VOLUME_POSTGRES_DATA"
create_volume "$VOLUME_DJANGO_STATIC"
create_volume "$VOLUME_DJANGO_MEDIA"
create_volume "$VOLUME_NGINX_CONF"
create_volume "$VOLUME_MONITORING_DATA"
create_volume "$VOLUME_IDS_LOGS"
create_volume "$VOLUME_LOGTO_DB"
create_volume "$VOLUME_GRAFANA_DATA"
create_volume "$VOLUME_PROMETHEUS_DATA"
create_volume "$VOLUME_LOKI_DATA"
create_volume "$VOLUME_ALERTMANAGER_DATA"
create_volume "$VOLUME_RSYSLOG_DATA"
create_volume "$VOLUME_WAF_LOGS"
create_volume "$VOLUME_CLOUDFLARED_CREDS"
create_volume "$VOLUME_QSECBIT_DATA"
create_volume "$VOLUME_QSECBIT_MODELS"
create_volume "$VOLUME_KALI_TOOLS"
create_volume "$VOLUME_KALI_REPORTS"

echo "✓ Persistent volumes ready"

# ============================================================
# STEP 9: DEPLOY POD 003 - PERSISTENT DATABASE
# ============================================================
echo ""
echo "[STEP 9] Deploying POD 003 - Persistent Database..."

# Remove existing pod
podman pod exists "$POD_003_NAME" 2>/dev/null && podman pod rm -f "$POD_003_NAME"

# Create pod
podman pod create \
    --name "$POD_003_NAME" \
    --network "$NETWORK_POD003" \
    -p ${PORT_POSTGRES}:5432

# Deploy PostgreSQL
echo "  → Starting PostgreSQL container..."
podman run -d --restart always \
    --pod "$POD_003_NAME" \
    --name "${POD_003_NAME}-postgres" \
    -e POSTGRES_DB="$POSTGRES_DB" \
    -e POSTGRES_USER="$POSTGRES_USER" \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -v "$VOLUME_POSTGRES_DATA:/var/lib/postgresql/data" \
    --log-driver=journald \
    --log-opt tag="hookprobe-postgres" \
    "$IMAGE_POSTGRES"

# Wait for PostgreSQL to be ready
echo "  → Waiting for PostgreSQL to be ready..."
sleep 10

echo "✓ POD 003 deployed (Persistent Database)"

# ============================================================
# STEP 10: DEPLOY POD 004 - TRANSIENT DATABASE
# ============================================================
echo ""
echo "[STEP 10] Deploying POD 004 - Transient Database (Redis)..."

# Remove existing pod
podman pod exists "$POD_004_NAME" 2>/dev/null && podman pod rm -f "$POD_004_NAME"

# Create pod
podman pod create \
    --name "$POD_004_NAME" \
    --network "$NETWORK_POD004"

# Deploy Redis
echo "  → Starting Redis container..."
podman run -d --restart always \
    --pod "$POD_004_NAME" \
    --name "${POD_004_NAME}-redis" \
    --log-driver=journald \
    --log-opt tag="hookprobe-redis" \
    "$IMAGE_REDIS" \
    redis-server --appendonly yes

echo "✓ POD 004 deployed (Transient Database)"

# ============================================================
# STEP 11: BUILD DJANGO APPLICATION IMAGE
# ============================================================
echo ""
echo "[STEP 11] Building Django application..."

DJANGO_BUILD_DIR="/tmp/hookprobe-django-build"
rm -rf "$DJANGO_BUILD_DIR"
mkdir -p "$DJANGO_BUILD_DIR"

cat > "$DJANGO_BUILD_DIR/Dockerfile" << 'EOF'
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=hookprobe.settings

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN python manage.py collectstatic --noinput || true
RUN mkdir -p /app/static /app/media

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "hookprobe.wsgi:application"]
EOF

cat > "$DJANGO_BUILD_DIR/requirements.txt" << 'EOF'
Django==5.0.1
django-cms==4.1.1
djangocms-admin-style==3.3.1
djangocms-text-ckeditor==5.1.5
gunicorn==21.2.0
psycopg2-binary==2.9.9
redis==5.0.1
celery==5.3.4
django-environ==0.11.2
Pillow==10.2.0
djangorestframework==3.14.0
social-auth-app-django==5.4.0
requests==2.31.0
PyJWT==2.8.0
cryptography==41.0.7
EOF

mkdir -p "$DJANGO_BUILD_DIR/hookprobe"

cat > "$DJANGO_BUILD_DIR/manage.py" << 'EOF'
#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hookprobe.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError("Couldn't import Django.") from exc
    execute_from_command_line(sys.argv)
EOF
chmod +x "$DJANGO_BUILD_DIR/manage.py"

cat > "$DJANGO_BUILD_DIR/hookprobe/settings.py" << EOF
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = '${DJANGO_SECRET_KEY}'
DEBUG = ${DJANGO_DEBUG}
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'djangocms_admin_style',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'cms',
    'menus',
    'treebeard',
    'sekizai',
    'djangocms_text_ckeditor',
    'rest_framework',
    'social_django',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'cms.middleware.user.CurrentUserMiddleware',
    'cms.middleware.page.CurrentPageMiddleware',
    'cms.middleware.toolbar.ToolbarMiddleware',
    'cms.middleware.language.LanguageCookieMiddleware',
    'social_django.middleware.SocialAuthExceptionMiddleware',
]

ROOT_URLCONF = 'hookprobe.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'sekizai.context_processors.sekizai',
                'cms.context_processors.cms_settings',
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
            ],
        },
    },
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': '${POSTGRES_DB}',
        'USER': '${POSTGRES_USER}',
        'PASSWORD': '${POSTGRES_PASSWORD}',
        'HOST': '${IP_POD003_POSTGRES}',
        'PORT': '5432',
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://${IP_POD004_REDIS}:6379/1',
    }
}

LOGTO_ENDPOINT = '${LOGTO_ENDPOINT}'
LOGTO_ADMIN_ENDPOINT = '${LOGTO_ADMIN_ENDPOINT}'

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'social_core.backends.open_id_connect.OpenIdConnectAuth',
]

SOCIAL_AUTH_JSONFIELD_ENABLED = True
SOCIAL_AUTH_URL_NAMESPACE = 'social'

LOGIN_URL = '/auth/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

SITE_ID = 1

CMS_TEMPLATES = [
    ('home.html', 'Home Page Template'),
    ('page.html', 'Content Page Template'),
]

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
EOF

cat > "$DJANGO_BUILD_DIR/hookprobe/urls.py" << 'EOF'
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('social_django.urls', namespace='social')),
    path('', include('cms.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
EOF

cat > "$DJANGO_BUILD_DIR/hookprobe/wsgi.py" << 'EOF'
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hookprobe.settings')
application = get_wsgi_application()
EOF

touch "$DJANGO_BUILD_DIR/hookprobe/__init__.py"

echo "  → Building Django container image..."
cd "$DJANGO_BUILD_DIR"
podman build -t hookprobe-django:latest .

echo "✓ Django application built"

# ============================================================
# STEP 12: DEPLOY POD 002 - IAM/AUTHENTICATION
# ============================================================
echo ""
echo "[STEP 12] Deploying POD 002 - IAM/Authentication Services (Logto)..."

podman pod exists "$POD_002_NAME" 2>/dev/null && podman pod rm -f "$POD_002_NAME"

podman pod create \
    --name "$POD_002_NAME" \
    --network "$NETWORK_POD002" \
    -p ${PORT_LOGTO}:3001 \
    -p ${PORT_LOGTO_ADMIN}:3002

echo "  → Starting Logto PostgreSQL database..."
podman run -d --restart always \
    --pod "$POD_002_NAME" \
    --name "${POD_002_NAME}-logto-db" \
    -e POSTGRES_DB="$LOGTO_DB" \
    -e POSTGRES_USER="$LOGTO_DB_USER" \
    -e POSTGRES_PASSWORD="$LOGTO_DB_PASSWORD" \
    -v "$VOLUME_LOGTO_DB:/var/lib/postgresql/data" \
    --log-driver=journald \
    --log-opt tag="hookprobe-logto-db" \
    "$IMAGE_POSTGRES"

sleep 10

echo "  → Starting Logto IAM service..."
podman run -d --restart always \
    --pod "$POD_002_NAME" \
    --name "${POD_002_NAME}-logto" \
    -e DB_URL="postgresql://${LOGTO_DB_USER}:${LOGTO_DB_PASSWORD}@localhost:5432/${LOGTO_DB}" \
    -e ENDPOINT="http://${LOCAL_HOST_IP}:${PORT_LOGTO}" \
    -e ADMIN_ENDPOINT="http://${LOCAL_HOST_IP}:${PORT_LOGTO_ADMIN}" \
    --log-driver=journald \
    --log-opt tag="hookprobe-logto" \
    "$IMAGE_LOGTO"

echo "✓ POD 002 deployed (IAM - Logto)"

# ============================================================
# STEP 13: DEPLOY POD 005 - MONITORING + CENTRALIZED LOGGING
# ============================================================
echo ""
echo "[STEP 13] Deploying POD 005 - Monitoring + Centralized Logging..."

podman pod exists "$POD_005_NAME" 2>/dev/null && podman pod rm -f "$POD_005_NAME"

podman pod create \
    --name "$POD_005_NAME" \
    --network "$NETWORK_POD005" \
    -p ${PORT_GRAFANA}:3000 \
    -p ${PORT_PROMETHEUS}:9090 \
    -p ${PORT_ALERTMANAGER}:9093 \
    -p ${PORT_LOKI}:3100 \
    -p ${RSYSLOG_PORT}:514/udp \
    -p ${RSYSLOG_PORT}:514/tcp \
    -p ${RSYSLOG_TLS_PORT}:6514/tcp

# Deploy Rsyslog Server
echo "  → Configuring centralized Rsyslog server..."
RSYSLOG_CONFIG_DIR="/tmp/rsyslog-config"
mkdir -p "$RSYSLOG_CONFIG_DIR"

cat > "$RSYSLOG_CONFIG_DIR/rsyslog.conf" << 'EOF'
# Rsyslog configuration for HookProbe centralized logging

module(load="imudp")
input(type="imudp" port="514")

module(load="imtcp")
input(type="imtcp" port="514")

# Template for log files
template(name="DynamicFile" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")

# Store logs by hostname and program
*.* ?DynamicFile

# Also send to Loki via Promtail
*.* @@localhost:1514
EOF

echo "  → Starting Rsyslog server..."
podman run -d --restart always \
    --pod "$POD_005_NAME" \
    --name "${POD_005_NAME}-rsyslog" \
    -v "$RSYSLOG_CONFIG_DIR/rsyslog.conf:/etc/rsyslog.conf:ro" \
    -v "$VOLUME_RSYSLOG_DATA:/var/log/remote" \
    --log-driver=journald \
    --log-opt tag="hookprobe-rsyslog" \
    "$IMAGE_RSYSLOG"

# Deploy Prometheus
echo "  → Configuring Prometheus..."
PROMETHEUS_CONFIG_DIR="/tmp/prometheus-config"
mkdir -p "$PROMETHEUS_CONFIG_DIR"

cat > "$PROMETHEUS_CONFIG_DIR/prometheus.yml" << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - localhost:9093

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['localhost:8080']
EOF

echo "  → Starting Prometheus..."
podman run -d --restart always \
    --pod "$POD_005_NAME" \
    --name "${POD_005_NAME}-prometheus" \
    -v "$PROMETHEUS_CONFIG_DIR/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
    -v "$VOLUME_PROMETHEUS_DATA:/prometheus" \
    --user root \
    --log-driver=journald \
    --log-opt tag="hookprobe-prometheus" \
    "$IMAGE_PROMETHEUS" \
    --config.file=/etc/prometheus/prometheus.yml \
    --storage.tsdb.path=/prometheus

# Deploy Loki
echo "  → Configuring Loki..."
LOKI_CONFIG_DIR="/tmp/loki-config"
mkdir -p "$LOKI_CONFIG_DIR"

cat > "$LOKI_CONFIG_DIR/loki-config.yml" << 'EOF'
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

limits_config:
  reject_old_samples: true
  reject_old_samples_max_age: 168h
EOF

echo "  → Starting Loki..."
podman run -d --restart always \
    --pod "$POD_005_NAME" \
    --name "${POD_005_NAME}-loki" \
    -v "$LOKI_CONFIG_DIR/loki-config.yml:/etc/loki/local-config.yaml:ro" \
    -v "$VOLUME_LOKI_DATA:/loki" \
    --user root \
    --log-driver=journald \
    --log-opt tag="hookprobe-loki" \
    "$IMAGE_LOKI" \
    -config.file=/etc/loki/local-config.yaml

# Deploy Promtail
echo "  → Configuring Promtail..."
PROMTAIL_CONFIG_DIR="/tmp/promtail-config"
mkdir -p "$PROMTAIL_CONFIG_DIR"

cat > "$PROMTAIL_CONFIG_DIR/promtail-config.yml" << 'EOF'
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          __path__: /var/log/*log

  - job_name: rsyslog
    static_configs:
      - targets:
          - localhost
        labels:
          job: rsyslog
          __path__: /var/log/remote/**/*.log

  - job_name: containers
    static_configs:
      - targets:
          - localhost
        labels:
          job: containerlogs
          __path__: /var/lib/containers/storage/overlay-containers/*/userdata/ctr.log
EOF

echo "  → Starting Promtail..."
podman run -d --restart always \
    --pod "$POD_005_NAME" \
    --name "${POD_005_NAME}-promtail" \
    -v "$PROMTAIL_CONFIG_DIR/promtail-config.yml:/etc/promtail/config.yml:ro" \
    -v /var/log:/var/log:ro \
    -v "$VOLUME_RSYSLOG_DATA:/var/log/remote:ro" \
    -v /var/lib/containers:/var/lib/containers:ro \
    --user root \
    --log-driver=journald \
    --log-opt tag="hookprobe-promtail" \
    "$IMAGE_PROMTAIL" \
    -config.file=/etc/promtail/config.yml

# Deploy Alertmanager
echo "  → Configuring Alertmanager..."
ALERTMANAGER_CONFIG_DIR="/tmp/alertmanager-config"
mkdir -p "$ALERTMANAGER_CONFIG_DIR"

cat > "$ALERTMANAGER_CONFIG_DIR/alertmanager.yml" << 'EOF'
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'default'

receivers:
  - name: 'default'
EOF

echo "  → Starting Alertmanager..."
podman run -d --restart always \
    --pod "$POD_005_NAME" \
    --name "${POD_005_NAME}-alertmanager" \
    -v "$ALERTMANAGER_CONFIG_DIR/alertmanager.yml:/etc/alertmanager/config.yml:ro" \
    -v "$VOLUME_ALERTMANAGER_DATA:/alertmanager" \
    --user root \
    --log-driver=journald \
    --log-opt tag="hookprobe-alertmanager" \
    "$IMAGE_ALERTMANAGER" \
    --config.file=/etc/alertmanager/config.yml \
    --storage.path=/alertmanager

# Deploy Node Exporter
echo "  → Starting Node Exporter..."
podman run -d --restart always \
    --pod "$POD_005_NAME" \
    --name "${POD_005_NAME}-node-exporter" \
    --pid=host \
    -v "/:/host:ro,rslave" \
    --log-driver=journald \
    --log-opt tag="hookprobe-node-exporter" \
    "$IMAGE_NODE_EXPORTER" \
    --path.rootfs=/host

# Deploy cAdvisor
echo "  → Starting cAdvisor..."
podman run -d --restart always \
    --pod "$POD_005_NAME" \
    --name "${POD_005_NAME}-cadvisor" \
    --privileged \
    -v /:/rootfs:ro \
    -v /var/run:/var/run:ro \
    -v /sys:/sys:ro \
    -v /var/lib/containers:/var/lib/containers:ro \
    -v /dev/disk:/dev/disk:ro \
    --log-driver=journald \
    --log-opt tag="hookprobe-cadvisor" \
    "$IMAGE_CADVISOR" || echo "⚠ cAdvisor may require adjustments"

# Deploy Grafana
echo "  → Starting Grafana..."
GRAFANA_DATASOURCES_DIR="/tmp/grafana-provisioning/datasources"
mkdir -p "$GRAFANA_DATASOURCES_DIR"

cat > "$GRAFANA_DATASOURCES_DIR/datasources.yml" << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
    editable: true

  - name: Loki
    type: loki
    access: proxy
    url: http://localhost:3100
    editable: true
EOF

GRAFANA_DASHBOARDS_DIR="/tmp/grafana-provisioning/dashboards"
mkdir -p "$GRAFANA_DASHBOARDS_DIR"

cat > "$GRAFANA_DASHBOARDS_DIR/dashboards.yml" << 'EOF'
apiVersion: 1

providers:
  - name: 'HookProbe Dashboards'
    orgId: 1
    folder: 'HookProbe'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

podman run -d --restart always \
    --pod "$POD_005_NAME" \
    --name "${POD_005_NAME}-grafana" \
    -e GF_SECURITY_ADMIN_USER=admin \
    -e GF_SECURITY_ADMIN_PASSWORD=admin \
    -e GF_USERS_ALLOW_SIGN_UP=false \
    -v "$VOLUME_GRAFANA_DATA:/var/lib/grafana" \
    -v "$GRAFANA_DATASOURCES_DIR:/etc/grafana/provisioning/datasources:ro" \
    -v "$GRAFANA_DASHBOARDS_DIR:/etc/grafana/provisioning/dashboards:ro" \
    --user root \
    --log-driver=journald \
    --log-opt tag="hookprobe-grafana" \
    "$IMAGE_GRAFANA"

echo "✓ POD 005 deployed (Monitoring + Centralized Logging)"

# ============================================================
# STEP 14: DEPLOY POD 001 - WEB DMZ WITH WAF + CLOUDFLARE
# ============================================================
echo ""
echo "[STEP 14] Deploying POD 001 - Web DMZ with NAXSI WAF + Cloudflare Tunnel..."

podman pod exists "$POD_001_NAME" 2>/dev/null && podman pod rm -f "$POD_001_NAME"

podman pod create \
    --name "$POD_001_NAME" \
    --network "$NETWORK_POD001" \
    -p ${PORT_HTTP}:80 \
    -p ${PORT_HTTPS}:443 \
    -p ${PORT_WAF}:8080

# Deploy Django application
echo "  → Starting Django/Gunicorn container..."
podman run -d --restart always \
    --pod "$POD_001_NAME" \
    --name "${POD_001_NAME}-django" \
    -e DJANGO_SETTINGS_MODULE="hookprobe.settings" \
    -e LOGTO_ENDPOINT="${LOGTO_ENDPOINT}" \
    -e LOGTO_ADMIN_ENDPOINT="${LOGTO_ADMIN_ENDPOINT}" \
    -v "$VOLUME_DJANGO_STATIC:/app/static" \
    -v "$VOLUME_DJANGO_MEDIA:/app/media" \
    --log-driver=journald \
    --log-opt tag="hookprobe-django" \
    hookprobe-django:latest

sleep 5

# Run migrations
echo "  → Running database migrations..."
podman exec "${POD_001_NAME}-django" python manage.py migrate --noinput || true

# Create superuser
echo "  → Creating Django superuser..."
podman exec "${POD_001_NAME}-django" python manage.py shell << 'PYEOF'
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@hookprobe.local', 'admin')
    print('Superuser created: admin/admin')
else:
    print('Superuser already exists')
PYEOF

# Deploy NAXSI WAF + Nginx
echo "  → Configuring NAXSI WAF with Nginx..."
NAXSI_CONF_DIR="/tmp/naxsi-config"
mkdir -p "$NAXSI_CONF_DIR"

# Create NAXSI core rules
cat > "$NAXSI_CONF_DIR/naxsi_core.rules" << 'EOF'
# NAXSI Core Rules
MainRule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1000;
MainRule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1001;
MainRule "str:[" "msg:square bracket" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1002;
MainRule "str:]" "msg:square bracket" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1003;
MainRule "str:~" "msg:tilde character" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1004;
MainRule "str:\`" "msg:grave accent" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1005;
MainRule "rx:%[2-3]." "msg:double encoding" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1006;

# SQL Injection
MainRule "str:select" "msg:select keyword" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1100;
MainRule "str:union" "msg:union keyword" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1101;
MainRule "str:insert" "msg:insert keyword" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1102;
MainRule "str:delete" "msg:delete keyword" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1103;
MainRule "str:update" "msg:update keyword" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1104;
MainRule "str:drop" "msg:drop keyword" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1105;

# File Upload
MainRule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
MainRule "str:/etc/passwd" "msg:passwd file" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:8" id:1201;
MainRule "str:c:\\" "msg:windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:8" id:1202;

# Command Injection
MainRule "str:;|" "msg:semicolon or pipe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$RCE:8" id:1300;
MainRule "str:\$(" "msg:command substitution" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$RCE:8" id:1301;
MainRule "str:\`" "msg:backtick" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$RCE:8" id:1302;
EOF

# Create Nginx configuration with NAXSI
cat > "$NAXSI_CONF_DIR/nginx.conf" << 'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    sendfile on;
    keepalive_timeout 65;

    # NAXSI Rules
    include /etc/nginx/naxsi_core.rules;

    upstream django {
        server localhost:8000;
    }

    server {
        listen 80;
        server_name _;
        client_max_body_size 100M;

        # NAXSI Configuration
        location / {
            # Enable NAXSI
            SecRulesEnabled;
            DeniedUrl "/RequestDenied";
            
            # Check rules
            CheckRule "$SQL >= 8" BLOCK;
            CheckRule "$RCE >= 8" BLOCK;
            CheckRule "$TRAVERSAL >= 4" BLOCK;
            CheckRule "$XSS >= 8" BLOCK;
            
            # Learning mode (set to 0 for production)
            LearningMode;
            
            # Log to dedicated file
            error_log /var/log/nginx/naxsi.log;
            
            proxy_pass http://django;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /static/ {
            alias /var/www/static/;
            expires 30d;
        }

        location /media/ {
            alias /var/www/media/;
            expires 30d;
        }

        location /RequestDenied {
            return 403;
        }
    }
}
EOF

# Build custom Nginx with NAXSI
echo "  → Building Nginx with NAXSI WAF..."
NGINX_BUILD_DIR="/tmp/nginx-naxsi-build"
mkdir -p "$NGINX_BUILD_DIR"

cat > "$NGINX_BUILD_DIR/Dockerfile" << 'EOF'
FROM nginx:1.27-alpine

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    make \
    libc-dev \
    pcre-dev \
    zlib-dev \
    linux-headers \
    curl \
    git

# Download and compile NAXSI
WORKDIR /tmp
RUN git clone https://github.com/nbs-system/naxsi.git && \
    cd naxsi/naxsi_src && \
    ./configure && \
    make && \
    make install

# Copy NAXSI module
RUN mkdir -p /etc/nginx/modules
COPY naxsi_core.rules /etc/nginx/

WORKDIR /
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
EOF

cp "$NAXSI_CONF_DIR/naxsi_core.rules" "$NGINX_BUILD_DIR/"

cd "$NGINX_BUILD_DIR"
echo "  → Building NAXSI-enabled Nginx (this may take a few minutes)..."
podman build -t hookprobe-nginx-naxsi:latest . || {
    echo "⚠️  NAXSI build failed, using standard Nginx instead"
    USE_STANDARD_NGINX=true
}

if [ "$USE_STANDARD_NGINX" = true ]; then
    # Use standard Nginx without NAXSI
    cat > "$NAXSI_CONF_DIR/default.conf" << 'EOF'
upstream django {
    server localhost:8000;
}

server {
    listen 80;
    server_name _;
    client_max_body_size 100M;

    location /static/ {
        alias /var/www/static/;
        expires 30d;
    }

    location /media/ {
        alias /var/www/media/;
        expires 30d;
    }

    location / {
        proxy_pass http://django;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }
}
EOF

    echo "  → Starting standard Nginx..."
    podman run -d --restart always \
        --pod "$POD_001_NAME" \
        --name "${POD_001_NAME}-nginx" \
        -v "$NAXSI_CONF_DIR/default.conf:/etc/nginx/conf.d/default.conf:ro" \
        -v "$VOLUME_DJANGO_STATIC:/var/www/static:ro" \
        -v "$VOLUME_DJANGO_MEDIA:/var/www/media:ro" \
        -v "$VOLUME_WAF_LOGS:/var/log/nginx" \
        --log-driver=journald \
        --log-opt tag="hookprobe-nginx" \
        "$IMAGE_NGINX"
else
    echo "  → Starting NAXSI-enabled Nginx..."
    podman run -d --restart always \
        --pod "$POD_001_NAME" \
        --name "${POD_001_NAME}-nginx-naxsi" \
        -v "$NAXSI_CONF_DIR/nginx.conf:/etc/nginx/nginx.conf:ro" \
        -v "$NAXSI_CONF_DIR/naxsi_core.rules:/etc/nginx/naxsi_core.rules:ro" \
        -v "$VOLUME_DJANGO_STATIC:/var/www/static:ro" \
        -v "$VOLUME_DJANGO_MEDIA:/var/www/media:ro" \
        -v "$VOLUME_WAF_LOGS:/var/log/nginx" \
        --log-driver=journald \
        --log-opt tag="hookprobe-naxsi-waf" \
        hookprobe-nginx-naxsi:latest
fi

# Deploy Cloudflare Tunnel
if [ "$SKIP_CLOUDFLARED" = false ]; then
    echo "  → Starting Cloudflare Tunnel..."
    podman run -d --restart always \
        --pod "$POD_001_NAME" \
        --name "${POD_001_NAME}-cloudflared" \
        --log-driver=journald \
        --log-opt tag="hookprobe-cloudflared" \
        "$IMAGE_CLOUDFLARED" \
        tunnel --no-autoupdate run --token "$CLOUDFLARE_TUNNEL_TOKEN"
    
    echo "✓ Cloudflare Tunnel started"
else
    echo "⊘ Cloudflare Tunnel skipped (token not configured)"
fi

echo "✓ POD 001 deployed (Web DMZ with WAF)"

# ============================================================
# STEP 15: DEPLOY POD 006 - SECURITY / IDS / IPS
# ============================================================
echo ""
echo "[STEP 15] Deploying POD 006 - Security / IDS / IPS..."

podman pod exists "$POD_006_NAME" 2>/dev/null && podman pod rm -f "$POD_006_NAME"

podman pod create \
    --name "$POD_006_NAME" \
    --network "$NETWORK_POD006"

echo "  → Starting Suricata IDS container..."
podman run -d --restart always \
    --pod "$POD_006_NAME" \
    --name "${POD_006_NAME}-suricata" \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -v "$VOLUME_IDS_LOGS:/var/log/suricata" \
    --log-driver=journald \
    --log-opt tag="hookprobe-suricata" \
    "$IMAGE_SURICATA" || echo "⚠ Suricata may need additional configuration"

echo "✓ POD 006 deployed (Security / IDS / IPS)"

# ============================================================
# STEP 16: DEPLOY POD 007 - AI THREAT RESPONSE & QSECBIT
# ============================================================
echo ""
echo "[STEP 16] Deploying POD 007 - AI Threat Response & Qsecbit Analysis..."

podman pod exists "$POD_007_NAME" 2>/dev/null && podman pod rm -f "$POD_007_NAME"

podman pod create \
    --name "$POD_007_NAME" \
    --network "$NETWORK_POD007" \
    -p ${PORT_QSECBIT_API}:8888

# Deploy Redis for Qsecbit state management
echo "  → Starting Redis for Qsecbit state..."
podman run -d --restart always \
    --pod "$POD_007_NAME" \
    --name "${POD_007_NAME}-redis" \
    --log-driver=journald \
    --log-opt tag="hookprobe-qsecbit-redis" \
    "$IMAGE_REDIS" \
    redis-server --appendonly yes

# Build Qsecbit Analysis Container
echo "  → Building Qsecbit AI analysis container..."
QSECBIT_BUILD_DIR="/tmp/qsecbit-build"
rm -rf "$QSECBIT_BUILD_DIR"
mkdir -p "$QSECBIT_BUILD_DIR"

# Copy the Qsecbit Python script
cat > "$QSECBIT_BUILD_DIR/qsecbit.py" << 'QSECEOF'
"""
Qsecbit: Quantum Security Bit
A resilience metric for AI-driven cybersecurity systems

Author: Andrei Toma
License: MIT
"""

import numpy as np
from scipy.spatial.distance import mahalanobis
from scipy.special import expit as logistic
from scipy.stats import entropy
from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict, List
from datetime import datetime
import json


@dataclass
class QsecbitConfig:
    """Configuration for Qsecbit calculation"""
    # Normalization thresholds
    lambda_crit: float = 0.15  # Critical classifier drift threshold
    q_crit: float = 0.25       # Critical quantum drift threshold
    
    # Component weights (must sum to 1.0)
    alpha: float = 0.30   # System drift weight
    beta: float = 0.30    # Attack probability weight
    gamma: float = 0.20   # Classifier decay weight
    delta: float = 0.20   # Quantum drift weight
    
    # RAG (Red/Amber/Green) thresholds
    amber_threshold: float = 0.45
    red_threshold: float = 0.70
    
    # Logistic function parameters for drift normalization
    drift_slope: float = 3.5
    drift_center: float = 2.0
    
    # Temporal parameters
    max_history_size: int = 1000
    convergence_window: int = 10  # Number of samples to check convergence
    
    def __post_init__(self):
        """Validate configuration"""
        weight_sum = self.alpha + self.beta + self.gamma + self.delta
        if not np.isclose(weight_sum, 1.0, atol=0.01):
            raise ValueError(f"Weights must sum to 1.0, got {weight_sum}")
        
        if not 0 < self.amber_threshold < self.red_threshold < 1:
            raise ValueError("Thresholds must satisfy: 0 < amber < red < 1")


@dataclass
class QsecbitSample:
    """Single qsecbit measurement"""
    timestamp: datetime
    score: float
    components: Dict[str, float]
    rag_status: str
    system_state: np.ndarray
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'score': float(self.score),
            'components': {k: float(v) for k, v in self.components.items()},
            'rag_status': self.rag_status,
            'system_state': self.system_state.tolist(),
            'metadata': self.metadata
        }


class Qsecbit:
    """
    Qsecbit: Quantum Security Bit
    
    Measures cyber resilience as the smallest unit where AI-driven attack 
    and defense reach equilibrium through continuous error correction.
    
    The metric combines:
    - Statistical drift from baseline (Mahalanobis distance)
    - ML-predicted attack probability
    - Classifier confidence decay rate
    - System entropy deviation (quantum drift)
    """
    
    def __init__(
        self,
        baseline_mu: np.ndarray,
        baseline_cov: np.ndarray,
        quantum_anchor: float,
        config: Optional[QsecbitConfig] = None
    ):
        """
        Initialize Qsecbit calculator
        
        Args:
            baseline_mu: Mean vector of baseline system telemetry
            baseline_cov: Covariance matrix of baseline system
            quantum_anchor: Baseline system entropy value
            config: Configuration object (uses defaults if None)
        """
        self.mu = np.array(baseline_mu)
        self.cov = np.array(baseline_cov)
        self.q_anchor = float(quantum_anchor)
        self.config = config or QsecbitConfig()
        
        # Precompute inverse covariance for efficiency
        self.inv_cov = np.linalg.inv(self.cov)
        
        # State tracking
        self.prev_classifier: Optional[np.ndarray] = None
        self.history: List[QsecbitSample] = []
        self.baseline_entropy = self._calculate_baseline_entropy()
        
    def _calculate_baseline_entropy(self) -> float:
        """Calculate theoretical baseline entropy from covariance"""
        # Differential entropy for multivariate Gaussian
        k = len(self.mu)
        det_cov = np.linalg.det(self.cov)
        return 0.5 * k * (1 + np.log(2 * np.pi)) + 0.5 * np.log(det_cov)
    
    def _drift(self, x_t: np.ndarray) -> float:
        """
        Compute normalized Mahalanobis drift from baseline
        
        Mahalanobis distance accounts for correlations in the data,
        making it more robust than Euclidean distance.
        Normalized via logistic function to [0, 1] range.
        """
        d = mahalanobis(x_t, self.mu, self.inv_cov)
        k = self.config.drift_slope
        theta = self.config.drift_center
        return float(logistic(k * (d - theta)))
    
    def _classifier_decay(self, c_t: np.ndarray, dt: float) -> float:
        """
        Compute normalized rate of change in classifier confidence
        
        Measures how quickly the AI classifier's predictions are changing,
        which indicates either adversarial manipulation or concept drift.
        """
        if self.prev_classifier is None:
            self.prev_classifier = c_t.copy()
            return 0.0
        
        # Rate of change in confidence vector
        delta = np.linalg.norm(c_t - self.prev_classifier) / max(dt, 1e-9)
        self.prev_classifier = c_t.copy()
        
        # Normalize to [0, 1]
        return float(min(1.0, delta / self.config.lambda_crit))
    
    def _quantum_drift(self, q_t: float) -> float:
        """
        Compute normalized entropy drift from baseline
        
        System entropy deviation indicates disorder or adversarial
        manipulation at the information-theoretic level.
        """
        q = abs(q_t - self.q_anchor)
        return float(min(1.0, q / self.config.q_crit))
    
    def _system_entropy(self, x_t: np.ndarray) -> float:
        """
        Calculate current system entropy
        
        Uses Shannon entropy of discretized telemetry values
        """
        # Discretize continuous values for entropy calculation
        bins = 10
        hist, _ = np.histogram(x_t, bins=bins, density=True)
        hist = hist + 1e-10  # Avoid log(0)
        return float(entropy(hist))
    
    def calculate(
        self,
        x_t: np.ndarray,
        p_attack: float,
        c_t: np.ndarray,
        q_t: Optional[float] = None,
        dt: float = 1.0,
        metadata: Optional[Dict] = None
    ) -> QsecbitSample:
        """
        Calculate qsecbit score for current system state
        
        Args:
            x_t: Current system telemetry vector
            p_attack: Predicted attack probability from ML model [0, 1]
            c_t: Classifier confidence vector
            q_t: Current system entropy (calculated if None)
            dt: Time elapsed since last measurement
            metadata: Additional context to store with sample
            
        Returns:
            QsecbitSample object with score and components
        """
        # Calculate entropy if not provided
        if q_t is None:
            q_t = self._system_entropy(x_t)
        
        # Compute components
        drift = self._drift(x_t)
        decay = self._classifier_decay(c_t, dt)
        qdrift = self._quantum_drift(q_t)
        
        # Weighted combination
        R = (
            self.config.alpha * drift +
            self.config.beta * p_attack +
            self.config.gamma * decay +
            self.config.delta * qdrift
        )
        
        # RAG classification
        rag = self._classify_rag(R)
        
        # Create sample
        sample = QsecbitSample(
            timestamp=datetime.now(),
            score=float(R),
            components={
                'drift': float(drift),
                'attack_probability': float(p_attack),
                'classifier_decay': float(decay),
                'quantum_drift': float(qdrift)
            },
            rag_status=rag,
            system_state=x_t.copy(),
            metadata=metadata or {}
        )
        
        # Store in history
        self.history.append(sample)
        if len(self.history) > self.config.max_history_size:
            self.history.pop(0)
        
        return sample
    
    def _classify_rag(self, R: float) -> str:
        """Classify score into Red/Amber/Green status"""
        if R >= self.config.red_threshold:
            return "RED"
        elif R >= self.config.amber_threshold:
            return "AMBER"
        return "GREEN"
    
    def convergence_rate(self, window: Optional[int] = None) -> Optional[float]:
        """
        Calculate convergence rate (how quickly system returns to safe state)
        
        This is the key metric: time to return to GREEN status after RED/AMBER
        
        Returns:
            Average time to convergence in the recent window, or None if insufficient data
        """
        window = window or self.config.convergence_window
        
        if len(self.history) < window:
            return None
        
        recent = self.history[-window:]
        
        # Find transitions from RED/AMBER to GREEN
        convergence_times = []
        in_alert = False
        alert_start = None
        
        for i, sample in enumerate(recent):
            if sample.rag_status in ['RED', 'AMBER'] and not in_alert:
                in_alert = True
                alert_start = i
            elif sample.rag_status == 'GREEN' and in_alert:
                convergence_time = i - alert_start
                convergence_times.append(convergence_time)
                in_alert = False
        
        if not convergence_times:
            return None
        
        return float(np.mean(convergence_times))
    
    def trend(self, window: int = 20) -> str:
        """
        Analyze trend in recent qsecbit scores
        
        Returns: 'IMPROVING', 'STABLE', or 'DEGRADING'
        """
        if len(self.history) < window:
            return "INSUFFICIENT_DATA"
        
        recent_scores = [s.score for s in self.history[-window:]]
        
        # Linear regression on recent scores
        x = np.arange(len(recent_scores))
        slope, _ = np.polyfit(x, recent_scores, 1)
        
        if slope < -0.01:
            return "IMPROVING"
        elif slope > 0.01:
            return "DEGRADING"
        return "STABLE"
    
    def export_history(self, filepath: str):
        """Export measurement history to JSON"""
        data = {
            'config': {
                'alpha': self.config.alpha,
                'beta': self.config.beta,
                'gamma': self.config.gamma,
                'delta': self.config.delta,
                'amber_threshold': self.config.amber_threshold,
                'red_threshold': self.config.red_threshold
            },
            'baseline': {
                'mu': self.mu.tolist(),
                'cov': self.cov.tolist(),
                'quantum_anchor': self.q_anchor
            },
            'history': [s.to_dict() for s in self.history]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def summary_stats(self) -> Dict:
        """Get summary statistics of qsecbit measurements"""
        if not self.history:
            return {}
        
        scores = [s.score for s in self.history]
        rag_counts = {'GREEN': 0, 'AMBER': 0, 'RED': 0}
        for s in self.history:
            rag_counts[s.rag_status] += 1
        
        return {
            'mean_score': float(np.mean(scores)),
            'std_score': float(np.std(scores)),
            'min_score': float(np.min(scores)),
            'max_score': float(np.max(scores)),
            'rag_distribution': rag_counts,
            'convergence_rate': self.convergence_rate(),
            'trend': self.trend(),
            'total_samples': len(self.history)
        }
QSECEOF

# Create the main Qsecbit integration script
cat > "$QSECBIT_BUILD_DIR/qsecbit_service.py" << 'EOF'
#!/usr/bin/env python3
"""
Qsecbit Service - Continuous threat analysis and response
Integrates with HookProbe infrastructure
"""

import os
import sys
import time
import json
import redis
import requests
import numpy as np
from datetime import datetime
from qsecbit import Qsecbit, QsecbitConfig
from flask import Flask, jsonify, request

# Configuration from environment
LOKI_URL = os.getenv('LOKI_URL', 'http://10.105.0.12:3100')
PROMETHEUS_URL = os.getenv('PROMETHEUS_URL', 'http://10.105.0.11:9090')
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

# Qsecbit configuration
QSECBIT_ALPHA = float(os.getenv('QSECBIT_ALPHA', 0.30))
QSECBIT_BETA = float(os.getenv('QSECBIT_BETA', 0.30))
QSECBIT_GAMMA = float(os.getenv('QSECBIT_GAMMA', 0.20))
QSECBIT_DELTA = float(os.getenv('QSECBIT_DELTA', 0.20))
QSECBIT_AMBER_THRESHOLD = float(os.getenv('QSECBIT_AMBER_THRESHOLD', 0.45))
QSECBIT_RED_THRESHOLD = float(os.getenv('QSECBIT_RED_THRESHOLD', 0.70))
QSECBIT_CHECK_INTERVAL = int(os.getenv('QSECBIT_CHECK_INTERVAL', 30))
KALI_AUTO_RESPONSE = os.getenv('KALI_AUTO_RESPONSE', 'true').lower() == 'true'

# Baseline configuration
baseline_mu_str = os.getenv('QSECBIT_BASELINE_MU', '0.1,0.2,0.15,0.33')
BASELINE_MU = np.array([float(x) for x in baseline_mu_str.split(',')])
BASELINE_COV = np.eye(len(BASELINE_MU)) * 0.02
QUANTUM_ANCHOR = float(os.getenv('QSECBIT_QUANTUM_ANCHOR', 6.144))

# Initialize services
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
app = Flask(__name__)

# Initialize Qsecbit
config = QsecbitConfig(
    alpha=QSECBIT_ALPHA,
    beta=QSECBIT_BETA,
    gamma=QSECBIT_GAMMA,
    delta=QSECBIT_DELTA,
    amber_threshold=QSECBIT_AMBER_THRESHOLD,
    red_threshold=QSECBIT_RED_THRESHOLD
)

qsecbit = Qsecbit(BASELINE_MU, BASELINE_COV, QUANTUM_ANCHOR, config)

def fetch_system_metrics():
    """Fetch current system telemetry from Prometheus"""
    try:
        # Query Prometheus for metrics
        queries = {
            'cpu': 'rate(container_cpu_usage_seconds_total[5m])',
            'memory': 'container_memory_usage_bytes / container_spec_memory_limit_bytes',
            'network': 'rate(container_network_receive_bytes_total[5m])',
            'disk': 'rate(container_fs_reads_bytes_total[5m]) + rate(container_fs_writes_bytes_total[5m])'
        }
        
        metrics = []
        for metric_name, query in queries.items():
            response = requests.get(f'{PROMETHEUS_URL}/api/v1/query', params={'query': query}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data['data']['result']:
                    value = float(data['data']['result'][0]['value'][1])
                    metrics.append(value)
                else:
                    metrics.append(0.0)
            else:
                metrics.append(0.0)
        
        return np.array(metrics)
    except Exception as e:
        print(f"Error fetching metrics: {e}")
        return BASELINE_MU.copy()

def calculate_attack_probability():
    """Calculate attack probability from IDS/IPS/WAF logs"""
    try:
        # Query Loki for security events
        query = '{job="containerlogs"} |~ "ALERT|BLOCK|ATTACK" | json'
        response = requests.get(
            f'{LOKI_URL}/loki/api/v1/query_range',
            params={
                'query': query,
                'start': str(int(time.time() - 300)),  # Last 5 minutes
                'end': str(int(time.time()))
            },
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            event_count = len(data.get('data', {}).get('result', []))
            # Normalize to [0, 1]
            p_attack = min(1.0, event_count / 100.0)
            return p_attack
        return 0.05
    except Exception as e:
        print(f"Error calculating attack probability: {e}")
        return 0.05

def get_classifier_confidence():
    """Get ML classifier confidence (simulated for now)"""
    # In production, this would query your ML model
    # For now, use inverse of attack probability
    p_attack = calculate_attack_probability()
    confidence = 1.0 - p_attack
    return np.array([confidence, confidence * 0.95, confidence * 0.98])

def trigger_kali_response(sample):
    """Trigger Kali Linux automated response"""
    print(f"🚨 TRIGGERING KALI RESPONSE - Status: {sample.rag_status}")
    
    response_data = {
        'timestamp': sample.timestamp.isoformat(),
        'qsecbit_score': sample.score,
        'rag_status': sample.rag_status,
        'components': sample.components,
        'recommended_actions': []
    }
    
    # Determine response actions based on threat type
    if sample.components['attack_probability'] > 0.7:
        response_data['recommended_actions'].extend([
            'Network scan to identify attack source',
            'Traffic analysis and packet capture',
            'Deploy honeypot to analyze attacker behavior'
        ])
    
    if sample.components['quantum_drift'] > 0.5:
        response_data['recommended_actions'].extend([
            'System integrity check',
            'File integrity monitoring scan',
            'Configuration drift analysis'
        ])
    
    if sample.components['drift'] > 0.6:
        response_data['recommended_actions'].extend([
            'Resource utilization analysis',
            'Process tree inspection',
            'Network connection audit'
        ])
    
    # Store response in Redis for Django to consume
    redis_client.setex(
        f'kali_response:{sample.timestamp.isoformat()}',
        3600,  # 1 hour expiry
        json.dumps(response_data)
    )
    
    # Log to file
    with open('/data/kali_responses.jsonl', 'a') as f:
        f.write(json.dumps(response_data) + '\n')
    
    return response_data

def analysis_loop():
    """Main analysis loop"""
    print("🔍 Starting Qsecbit analysis loop...")
    
    while True:
        try:
            # Fetch current metrics
            x_t = fetch_system_metrics()
            p_attack = calculate_attack_probability()
            c_t = get_classifier_confidence()
            
            # Calculate Qsecbit
            sample = qsecbit.calculate(
                x_t=x_t,
                p_attack=p_attack,
                c_t=c_t,
                dt=QSECBIT_CHECK_INTERVAL,
                metadata={'source': 'hookprobe_continuous'}
            )
            
            # Log result
            print(f"[{sample.timestamp}] Qsecbit: {sample.score:.4f} - Status: {sample.rag_status}")
            
            # Store latest in Redis
            redis_client.set('qsecbit:latest', json.dumps(sample.to_dict()))
            redis_client.lpush('qsecbit:history', json.dumps(sample.to_dict()))
            redis_client.ltrim('qsecbit:history', 0, 999)  # Keep last 1000
            
            # Trigger response if needed
            if sample.rag_status in ['RED', 'AMBER'] and KALI_AUTO_RESPONSE:
                trigger_kali_response(sample)
            
            # Sleep before next check
            time.sleep(QSECBIT_CHECK_INTERVAL)
            
        except Exception as e:
            print(f"Error in analysis loop: {e}")
            time.sleep(QSECBIT_CHECK_INTERVAL)

# API endpoints for Django integration
@app.route('/api/qsecbit/latest', methods=['GET'])
def get_latest():
    """Get latest Qsecbit measurement"""
    data = redis_client.get('qsecbit:latest')
    if data:
        return jsonify(json.loads(data))
    return jsonify({'error': 'No data available'}), 404

@app.route('/api/qsecbit/history', methods=['GET'])
def get_history():
    """Get Qsecbit history"""
    limit = int(request.args.get('limit', 100))
    history = redis_client.lrange('qsecbit:history', 0, limit - 1)
    return jsonify([json.loads(h) for h in history])

@app.route('/api/qsecbit/stats', methods=['GET'])
def get_stats():
    """Get summary statistics"""
    stats = qsecbit.summary_stats()
    return jsonify(stats)

@app.route('/api/kali/responses', methods=['GET'])
def get_kali_responses():
    """Get recent Kali responses"""
    keys = redis_client.keys('kali_response:*')
    responses = []
    for key in sorted(keys, reverse=True)[:20]:
        data = redis_client.get(key)
        if data:
            responses.append(json.loads(data))
    return jsonify(responses)

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'qsecbit_enabled': True})

if __name__ == '__main__':
    # Start analysis loop in background thread
    import threading
    analysis_thread = threading.Thread(target=analysis_loop, daemon=True)
    analysis_thread.start()
    
    # Start API server
    app.run(host='0.0.0.0', port=8888, debug=False)
EOF

chmod +x "$QSECBIT_BUILD_DIR/qsecbit_service.py"

# Create Dockerfile
cat > "$QSECBIT_BUILD_DIR/Dockerfile" << 'EOF'
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    numpy==1.26.3 \
    scipy==1.11.4 \
    redis==5.0.1 \
    flask==3.0.0 \
    requests==2.31.0

# Copy application files
COPY qsecbit.py .
COPY qsecbit_service.py .

# Create data directory
RUN mkdir -p /data

EXPOSE 8888

CMD ["python", "qsecbit_service.py"]
EOF

echo "  → Building Qsecbit container image..."
cd "$QSECBIT_BUILD_DIR"
podman build -t hookprobe-qsecbit:latest .

echo "  → Starting Qsecbit analysis container..."
podman run -d --restart always \
    --pod "$POD_007_NAME" \
    --name "${POD_007_NAME}-qsecbit" \
    -e LOKI_URL="http://${IP_POD005_LOKI}:3100" \
    -e PROMETHEUS_URL="http://${IP_POD005_PROMETHEUS}:9090" \
    -e REDIS_HOST="localhost" \
    -e REDIS_PORT="6379" \
    -e QSECBIT_ALPHA="$QSECBIT_ALPHA" \
    -e QSECBIT_BETA="$QSECBIT_BETA" \
    -e QSECBIT_GAMMA="$QSECBIT_GAMMA" \
    -e QSECBIT_DELTA="$QSECBIT_DELTA" \
    -e QSECBIT_AMBER_THRESHOLD="$QSECBIT_AMBER_THRESHOLD" \
    -e QSECBIT_RED_THRESHOLD="$QSECBIT_RED_THRESHOLD" \
    -e QSECBIT_BASELINE_MU="$QSECBIT_BASELINE_MU" \
    -e QSECBIT_QUANTUM_ANCHOR="$QSECBIT_QUANTUM_ANCHOR" \
    -e QSECBIT_CHECK_INTERVAL="$QSECBIT_CHECK_INTERVAL" \
    -e KALI_AUTO_RESPONSE="$KALI_AUTO_RESPONSE" \
    -v "$VOLUME_QSECBIT_DATA:/data" \
    -v "$VOLUME_QSECBIT_MODELS:/models" \
    --log-driver=journald \
    --log-opt tag="hookprobe-qsecbit" \
    hookprobe-qsecbit:latest

echo "  → Starting Kali Linux response container..."
podman run -d --restart always \
    --pod "$POD_007_NAME" \
    --name "${POD_007_NAME}-kali" \
    --privileged \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -v "$VOLUME_KALI_TOOLS:/tools" \
    -v "$VOLUME_KALI_REPORTS:/reports" \
    --log-driver=journald \
    --log-opt tag="hookprobe-kali" \
    "$IMAGE_KALI" \
    /bin/bash -c "apt-get update && apt-get install -y nmap metasploit-framework nikto sqlmap && tail -f /dev/null"

echo "✓ POD 007 deployed (AI Threat Response & Qsecbit)"
echo "  Qsecbit API: http://${LOCAL_HOST_IP}:${PORT_QSECBIT_API}"

# ============================================================
# FINAL SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   🎉 HOOKPROBE DEPLOYMENT COMPLETE!"
echo "============================================================"
echo ""
echo "✨ Deployed Infrastructure:"
echo "  ✓ POD 001 - Web DMZ (Django CMS + NAXSI WAF + Nginx)"
if [ "$SKIP_CLOUDFLARED" = false ]; then
    echo "      • Cloudflare Tunnel enabled"
fi
echo "  ✓ POD 002 - IAM/Authentication (Logto)"
echo "  ✓ POD 003 - Persistent Database (PostgreSQL)"
echo "  ✓ POD 004 - Transient Database (Redis)"
echo "  ✓ POD 005 - Complete Monitoring + Centralized Logging"
echo "      • Grafana (Dashboards)"
echo "      • Prometheus (Metrics)"
echo "      • Loki (Log Storage)"
echo "      • Promtail (Log Shipping)"
echo "      • Rsyslog (Centralized Syslog Server)"
echo "      • Alertmanager (Alerting)"
echo "      • Node Exporter (Host Metrics)"
echo "      • cAdvisor (Container Metrics)"
echo "  ✓ POD 006 - Security (Suricata IDS/IPS)"
echo "  ✓ POD 007 - AI Threat Response"
echo "      • Qsecbit Analysis Engine"
echo "      • Kali Linux Response Container"
echo "      • Automated Countermeasures"
echo "      • REST API for Django Integration"
echo ""
echo "🌐 Network Configuration:"
echo "  • Main Management: $SUBNET_MAIN"
echo "  • POD 001 (DMZ + WAF): $SUBNET_POD001"
echo "  • POD 002 (IAM): $SUBNET_POD002"
echo "  • POD 003 (DB-P): $SUBNET_POD003"
echo "  • POD 004 (DB-T): $SUBNET_POD004"
echo "  • POD 005 (MON + LOG): $SUBNET_POD005"
echo "  • POD 006 (SEC): $SUBNET_POD006"
echo "  • POD 007 (AI): $SUBNET_POD007"
echo ""
echo "🔐 Access Information:"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🌐 Web Application:"
echo "     Django Admin: http://$LOCAL_HOST_IP/admin"
echo "     Username: admin"
echo "     Password: admin"
echo "     Django CMS: http://$LOCAL_HOST_IP"

if [ "$SKIP_CLOUDFLARED" = false ]; then
    echo ""
    echo "     Cloudflare Tunnel: https://${CLOUDFLARE_DOMAIN}"
    echo "     (Configure in Cloudflare Zero Trust Dashboard)"
fi

echo ""
echo "  🛡️  Web Application Firewall:"
echo "     NAXSI WAF protecting all web traffic"
echo "     WAF Logs: /var/log/nginx/naxsi.log"
echo ""
echo "  🔐 IAM / Authentication (Logto):"
echo "     Logto Admin Console: http://$LOCAL_HOST_IP:${PORT_LOGTO_ADMIN}"
echo "     Logto API Endpoint: http://$LOCAL_HOST_IP:${PORT_LOGTO}"
echo ""
echo "  📊 Monitoring Stack:"
echo "     Grafana Dashboard: http://$LOCAL_HOST_IP:${PORT_GRAFANA}"
echo "     Username: admin | Password: admin"
echo ""
echo "     Prometheus: http://$LOCAL_HOST_IP:${PORT_PROMETHEUS}"
echo "     Alertmanager: http://$LOCAL_HOST_IP:${PORT_ALERTMANAGER}"
echo "     Loki API: http://$LOCAL_HOST_IP:${PORT_LOKI}"
echo ""
echo "  📝 Centralized Logging:"
echo "     Rsyslog Server: ${IP_POD005_RSYSLOG}:${RSYSLOG_PORT}"
echo "     All container logs forwarded to Loki via Promtail"
echo "     System logs forwarded to centralized rsyslog"
echo "     Kernel logs aggregated in Loki"
echo ""
echo "  🤖 AI Threat Response (Qsecbit):"
echo "     Qsecbit API: http://$LOCAL_HOST_IP:${PORT_QSECBIT_API}"
echo "     Latest Score: curl http://$LOCAL_HOST_IP:${PORT_QSECBIT_API}/api/qsecbit/latest"
echo "     History: curl http://$LOCAL_HOST_IP:${PORT_QSECBIT_API}/api/qsecbit/history"
echo "     Kali Responses: curl http://$LOCAL_HOST_IP:${PORT_QSECBIT_API}/api/kali/responses"
echo ""
echo "     Qsecbit Thresholds:"
echo "       - Amber: ${QSECBIT_AMBER_THRESHOLD} (Warning)"
echo "       - Red: ${QSECBIT_RED_THRESHOLD} (Critical)"
echo "     Auto-Response: ${KALI_AUTO_RESPONSE}"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 Next Steps:"
echo "  1. 🔐 Change all default passwords immediately"
echo "  2. 🔗 Configure Logto IAM application"
echo "  3. 📊 Access Grafana and explore dashboards"
echo "  4. 🛡️  Review WAF logs and tune rules"

if [ "$SKIP_CLOUDFLARED" = false ]; then
    echo "  5. ☁️  Configure Cloudflare Tunnel routing"
fi

echo "  6. 🎨 Upload your ThemeForest template"
echo "  7. 🔒 Configure SSL/TLS certificates"
echo "  8. 📧 Set up alert notifications"
echo "  9. 🤖 Integrate Qsecbit API with Django admin:"
echo "     - Add API calls to fetch latest Qsecbit score"
echo "     - Display RAG status in dashboard"
echo "     - Show Kali response recommendations"
echo "     - Create views in Django templates"
echo ""
echo "📊 Logging Features:"
echo "  ✓ Centralized syslog server collecting all system logs"
echo "  ✓ All containers logging via journald"
echo "  ✓ Promtail shipping logs to Loki"
echo "  ✓ Kernel logs aggregated"
echo "  ✓ WAF logs tracked separately"
echo "  ✓ Security events from IDS/IPS"
echo "  ✓ Query all logs in Grafana"
echo ""
echo "🛡️  Security Features:"
echo "  ✓ NAXSI WAF filtering web threats"
echo "  ✓ PSK-encrypted VXLAN tunnels"
echo "  ✓ Isolated network segments"
echo "  ✓ Centralized IAM with Logto"
echo "  ✓ IDS/IPS monitoring (Suricata)"

if [ "$SKIP_CLOUDFLARED" = false ]; then
    echo "  ✓ Cloudflare Tunnel (Zero Trust Access)"
fi

echo "  ✓ Complete audit trail in logs"
echo "  ✓ Qsecbit AI threat analysis"
echo "  ✓ Automated Kali Linux response"
echo "  ✓ Real-time threat scoring (RAG)"
echo ""
echo "🔧 Log Query Examples:"
echo "  View all logs:"
echo "    Grafana → Explore → Loki → {job=~\".*\"}"
echo ""
echo "  View WAF blocks:"
echo "    {job=\"containerlogs\"} |~ \"NAXSI.*BLOCK\""
echo ""
echo "  View Django errors:"
echo "    {job=\"containerlogs\"} | json | container_name=~\".*django.*\" |~ \"ERROR\""
echo ""
echo "  View security alerts:"
echo "    {job=\"containerlogs\"} | container_name=~\".*suricata.*\" |~ \"ALERT\""
echo ""
echo "🤖 Qsecbit AI Integration:"
echo "  To integrate with Django, add these to your views.py:"
echo ""
echo "  import requests"
echo "  QSECBIT_API = 'http://10.107.0.10:8888'"
echo ""
echo "  def get_qsecbit_status(request):"
echo "      response = requests.get(f'{QSECBIT_API}/api/qsecbit/latest')"
echo "      data = response.json()"
echo "      return JsonResponse(data)"
echo ""
echo "  # Export to template context:"
echo "  context['qsecbit_score'] = data['score']"
echo "  context['rag_status'] = data['rag_status']"
echo "  context['threat_level'] = data['components']['attack_probability']"
echo ""
echo "============================================================"
echo "  🎉 HookProbe v4.0 is now running!"
echo "  🚀 Full-Stack AI-Powered Cybersecurity Platform!"
echo "  🤖 Qsecbit AI analyzing threats in real-time!"
echo "============================================================"
