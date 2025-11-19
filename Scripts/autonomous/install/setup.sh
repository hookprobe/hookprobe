#!/bin/bash
#
# setup.sh (v7 - Complete HookProbe 6-POD Architecture)
#
# Automated deployment of HookProbe infrastructure with:
# - 6 PODs with isolated networks
# - OVS + VXLAN with PSK encryption
# - Django CMS in POD 001
# - Database services in POD 003/004
# - Monitoring in POD 005
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
create_vxlan_tunnel "$OVS_MAIN_BRIDGE" "$VNI_APP" "$OVS_PSK_MAIN"
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
# STEP 6: CREATE PODMAN NETWORKS
# ============================================================
echo ""
echo "[STEP 6] Creating Podman networks..."

# Function to create Podman network
create_podman_network() {
    local net_name=$1
    local subnet=$2
    local gateway=$3
    
    echo "  → Creating network: $net_name ($subnet)"
    
    # Remove if exists
    podman network exists "$net_name" && podman network rm "$net_name"
    
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
# STEP 7: CREATE PERSISTENT VOLUMES
# ============================================================
echo ""
echo "[STEP 7] Creating persistent volumes..."

# Function to create volume if it doesn't exist
create_volume() {
    local vol_name=$1
    if ! podman volume exists "$vol_name"; then
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

echo "✓ Persistent volumes ready"

# ============================================================
# STEP 8: DEPLOY POD 003 - PERSISTENT DATABASE
# ============================================================
echo ""
echo "[STEP 8] Deploying POD 003 - Persistent Database..."

# Remove existing pod
podman pod exists "$POD_003_NAME" && podman pod rm -f "$POD_003_NAME"

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
    "$IMAGE_POSTGRES"

# Wait for PostgreSQL to be ready
echo "  → Waiting for PostgreSQL to be ready..."
sleep 10

echo "✓ POD 003 deployed (Persistent Database)"

# ============================================================
# STEP 9: DEPLOY POD 004 - TRANSIENT DATABASE
# ============================================================
echo ""
echo "[STEP 9] Deploying POD 004 - Transient Database (Redis)..."

# Remove existing pod
podman pod exists "$POD_004_NAME" && podman pod rm -f "$POD_004_NAME"

# Create pod
podman pod create \
    --name "$POD_004_NAME" \
    --network "$NETWORK_POD004"

# Deploy Redis
echo "  → Starting Redis container..."
podman run -d --restart always \
    --pod "$POD_004_NAME" \
    --name "${POD_004_NAME}-redis" \
    "$IMAGE_REDIS" \
    redis-server --appendonly yes

echo "✓ POD 004 deployed (Transient Database)"

# ============================================================
# STEP 10: BUILD DJANGO APPLICATION IMAGE
# ============================================================
echo ""
echo "[STEP 10] Building Django application..."

# Create Django project directory
DJANGO_BUILD_DIR="/tmp/hookprobe-django-build"
rm -rf "$DJANGO_BUILD_DIR"
mkdir -p "$DJANGO_BUILD_DIR"

# Create Dockerfile
cat > "$DJANGO_BUILD_DIR/Dockerfile" << 'EOF'
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=hookprobe.settings

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput || true

# Create necessary directories
RUN mkdir -p /app/static /app/media

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "hookprobe.wsgi:application"]
EOF

# Create requirements.txt
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
EOF

# Create basic Django project structure
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
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed?"
        ) from exc
    execute_from_command_line(sys.argv)
EOF
chmod +x "$DJANGO_BUILD_DIR/manage.py"

# Create settings.py
cat > "$DJANGO_BUILD_DIR/hookprobe/settings.py" << EOF
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = '${DJANGO_SECRET_KEY}'
DEBUG = ${DJANGO_DEBUG}
ALLOWED_HOSTS = ['${DJANGO_ALLOWED_HOSTS}'.split(',')]

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

# Create urls.py
cat > "$DJANGO_BUILD_DIR/hookprobe/urls.py" << 'EOF'
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('cms.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
EOF

# Create wsgi.py
cat > "$DJANGO_BUILD_DIR/hookprobe/wsgi.py" << 'EOF'
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hookprobe.settings')
application = get_wsgi_application()
EOF

# Create __init__.py files
touch "$DJANGO_BUILD_DIR/hookprobe/__init__.py"

# Build Django image
echo "  → Building Django container image..."
cd "$DJANGO_BUILD_DIR"
podman build -t hookprobe-django:latest .

echo "✓ Django application built"

# ============================================================
# STEP 11: DEPLOY POD 001 - WEB APP / DMZ
# ============================================================
echo ""
echo "[STEP 11] Deploying POD 001 - Web App / DMZ..."

# Remove existing pod
podman pod exists "$POD_001_NAME" && podman pod rm -f "$POD_001_NAME"

# Create pod with port forwarding
podman pod create \
    --name "$POD_001_NAME" \
    --network "$NETWORK_POD001" \
    -p ${PORT_HTTP}:80 \
    -p ${PORT_HTTPS}:443

# Deploy Django application
echo "  → Starting Django/Gunicorn container..."
podman run -d --restart always \
    --pod "$POD_001_NAME" \
    --name "${POD_001_NAME}-django" \
    -e DJANGO_SETTINGS_MODULE="hookprobe.settings" \
    -v "$VOLUME_DJANGO_STATIC:/app/static" \
    -v "$VOLUME_DJANGO_MEDIA:/app/media" \
    hookprobe-django:latest

# Wait for Django to start
sleep 5

# Run migrations
echo "  → Running database migrations..."
podman exec "${POD_001_NAME}-django" python manage.py migrate --noinput || true

# Create superuser (non-interactive)
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

# Create Nginx configuration
echo "  → Configuring Nginx reverse proxy..."
NGINX_CONF_DIR="/tmp/nginx-hookprobe"
mkdir -p "$NGINX_CONF_DIR"

cat > "$NGINX_CONF_DIR/default.conf" << 'EOF'
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

# Deploy Nginx
echo "  → Starting Nginx container..."
podman run -d --restart always \
    --pod "$POD_001_NAME" \
    --name "${POD_001_NAME}-nginx" \
    -v "$NGINX_CONF_DIR/default.conf:/etc/nginx/conf.d/default.conf:ro" \
    -v "$VOLUME_DJANGO_STATIC:/var/www/static:ro" \
    -v "$VOLUME_DJANGO_MEDIA:/var/www/media:ro" \
    "$IMAGE_NGINX"

echo "✓ POD 001 deployed (Web App / DMZ)"

# ============================================================
# STEP 12: DEPLOY POD 006 - SECURITY / IDS / IPS
# ============================================================
echo ""
echo "[STEP 12] Deploying POD 006 - Security / IDS / IPS..."

# Remove existing pod
podman pod exists "$POD_006_NAME" && podman pod rm -f "$POD_006_NAME"

# Create pod
podman pod create \
    --name "$POD_006_NAME" \
    --network "$NETWORK_POD006"

# Deploy Suricata IDS
echo "  → Starting Suricata IDS container..."
podman run -d --restart always \
    --pod "$POD_006_NAME" \
    --name "${POD_006_NAME}-suricata" \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -v "$VOLUME_IDS_LOGS:/var/log/suricata" \
    "$IMAGE_SURICATA" || echo "⚠ Suricata image not available, skipping"

echo "✓ POD 006 deployed (Security / IDS / IPS)"

# ============================================================
# STEP 13: DEPLOY POD 005 - MONITORING
# ============================================================
echo ""
echo "[STEP 13] Deploying POD 005 - Container Monitoring..."

# Remove existing pod
podman pod exists "$POD_005_NAME" && podman pod rm -f "$POD_005_NAME"

# Create pod
podman pod create \
    --name "$POD_005_NAME" \
    --network "$NETWORK_POD005" \
    -p ${PORT_MONITORING}:9090

echo "✓ POD 005 deployed (Monitoring)"

# ============================================================
# STEP 14: DEPLOY POD 002 - APPLICATION SERVICES
# ============================================================
echo ""
echo "[STEP 14] Deploying POD 002 - Application Services..."

# Remove existing pod
podman pod exists "$POD_002_NAME" && podman pod rm -f "$POD_002_NAME"

# Create pod
podman pod create \
    --name "$POD_002_NAME" \
    --network "$NETWORK_POD002"

echo "✓ POD 002 deployed (Application Services)"

# ============================================================
# FINAL SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   HOOKPROBE DEPLOYMENT COMPLETE!"
echo "============================================================"
echo ""
echo "Deployed Infrastructure:"
echo "  ✓ POD 001 - Web App / DMZ (Django CMS + Nginx)"
echo "  ✓ POD 002 - Application Services"
echo "  ✓ POD 003 - Persistent Database (PostgreSQL)"
echo "  ✓ POD 004 - Transient Database (Redis)"
echo "  ✓ POD 005 - Container Monitoring"
echo "  ✓ POD 006 - Security / IDS / IPS"
echo ""
echo "Network Configuration:"
echo "  • Main Management: $SUBNET_MAIN"
echo "  • POD 001 (DMZ): $SUBNET_POD001"
echo "  • POD 002 (APP): $SUBNET_POD002"
echo "  • POD 003 (DB-P): $SUBNET_POD003"
echo "  • POD 004 (DB-T): $SUBNET_POD004"
echo "  • POD 005 (MON): $SUBNET_POD005"
echo "  • POD 006 (SEC): $SUBNET_POD006"
echo ""
echo "Access Information:"
echo "  • Django Admin: http://$LOCAL_HOST_IP/admin"
echo "    Username: admin"
echo "    Password: admin"
echo ""
echo "  • Django CMS: http://$LOCAL_HOST_IP"
echo ""
echo "Next Steps:"
echo "  1. Access Django admin and configure your CMS"
echo "  2. Upload your ThemeForest template files"
echo "  3. Configure monitoring tools in POD 005"
echo "  4. Review IDS/IPS logs in POD 006"
echo ""
echo "For multi-host deployment:"
echo "  • Run this script on the second host"
echo "  • Ensure network-config.sh has matching PSK keys"
echo "============================================================"
