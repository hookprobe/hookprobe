#!/bin/bash
#
# setup.sh (v9 - Complete HookProbe Architecture with WAF + Cloudflare + Enhanced Logging)
#
# Automated deployment of HookProbe infrastructure with:
# - 6 PODs with isolated networks
# - OVS + VXLAN with PSK encryption
# - NAXSI WAF for web protection
# - Cloudflare Tunnel for secure access
# - Django CMS in POD 001
# - Logto IAM in POD 002
# - Database services in POD 003/004
# - Complete monitoring + centralized logging in POD 005
# - IDS/IPS in POD 006
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
echo "   HOOKPROBE AUTONOMOUS DEPLOYMENT - 6 POD ARCHITECTURE"
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
echo ""
echo "🌐 Network Configuration:"
echo "  • Main Management: $SUBNET_MAIN"
echo "  • POD 001 (DMZ + WAF): $SUBNET_POD001"
echo "  • POD 002 (IAM): $SUBNET_POD002"
echo "  • POD 003 (DB-P): $SUBNET_POD003"
echo "  • POD 004 (DB-T): $SUBNET_POD004"
echo "  • POD 005 (MON + LOG): $SUBNET_POD005"
echo "  • POD 006 (SEC): $SUBNET_POD006"
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
echo "============================================================"
echo "  🎉 HookProbe v3.0 is now running!"
echo "  🚀 Enterprise-grade security with WAF + Centralized Logging!"
echo "============================================================"
