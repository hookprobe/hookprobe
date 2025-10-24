#!/bin/bash
#
# setup.sh (v3 - Consolidated)
#
# This single, consolidated script sets up the entire 'autonomous autonomous' ecosystem:
# 1. Installs all host dependencies (Podman, Terraform, Cloudflared).
# 2. Creates a *persistent* VXLAN (vxlan0) interface using NetworkManager.
# 3. Configures the Podman network to bridge to the VXLAN.
# 4. Deploys the full application stack (Postgres, Django, Nginx) in a Podman pod.
#
# Target OS: RHEL/RedHat 10 (or compatible Fedora/CentOS Stream)
#
# --- !! Configuration Required !! ---

# Safely exit if any command fails
set -e

# --- 1. DEFINE CORE PARAMETERS ---

# (!!!) EDIT THESE VXLAN VALUES TO MATCH YOUR ENVIRONMENT (!!!)
REMOTE_HOST_IP="192.168.1.101" # <--- EDIT THIS (IP of the *other* host)
PHYSICAL_HOST_INTERFACE="eth0" # <--- EDIT THIS (use 'ip a' to find)

# VXLAN Network Settings (Should be identical on both hosts)
VXLAN_IF="vxlan0"
VXLAN_CONN_NAME="vxlan-autonomous"
VNI=100
VXLAN_SUBNET="172.25.0.0/24"
VXLAN_GATEWAY="172.25.0.1"
VXLAN_PORT=4789

# Podman Settings
PODMAN_NETWORK_NAME="autonomous-vxlan-net"
PODMAN_POD_NAME="autonomous-pod"
POSTGRES_VOLUME="autonomous-db-volume"

# Service Settings
POSTGRES_DB="autonomydb"
POSTGRES_USER="autonomysuser"
POSTGRES_PASSWORD="a_very_secure_password_change_me"

# Container Images
# (!! You must build this Django image or change to a public one !!)
DJANGO_IMAGE="autonomous-django:latest" 
POSTGRES_IMAGE="docker.io/library/postgres:16-alpine"
NGINX_IMAGE="docker.io/library/nginx:1.27-alpine"

# Other Tools
TERRAFORM_VERSION="1.8.5"

echo "========================================================"
echo "    AUTONOMOUS AUTONOMOUS FULL STACK SETUP STARTING     "
echo "========================================================"

# --- 2. VALIDATE ENVIRONMENT ---
echo "1. Validating environment..."
if [[ $(uname -m) != "x86_64" ]]; then
    echo "WARNING: Detected architecture is not x86_64."
fi
if ! command -v dnf &> /dev/null; then
    echo "ERROR: 'dnf' command not found. This script requires a RHEL/Fedora-based system."
    exit 1
fi
if ! command -v nmcli &> /dev/null; then
    echo "ERROR: 'nmcli' (NetworkManager) not found. Please install 'NetworkManager'."
    exit 1
fi
if ! command -v firewall-cmd &> /dev/null; then
    echo "WARNING: 'firewall-cmd' not found. Skipping firewall setup."
fi
echo "System checks passed."

# --- 3. INSTALL DEPENDENCIES ---
echo "2. Installing all system dependencies..."
REQUIRED_PACKAGES=(
    git curl wget unzip podman python3 python3-pip net-tools kernel-modules-extra
)
sudo dnf update -y
sudo dnf install -y "${REQUIRED_PACKAGES[@]}"

# Install Terraform
echo "Installing Terraform v${TERRAFORM_VERSION}..."
if ! command -v terraform &> /dev/null; then
    TERRAFORM_URL="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip"
    wget -q "$TERRAFORM_URL"
    unzip -q "terraform_${TERRAFORM_VERSION}_linux_amd64.zip"
    sudo mv terraform /usr/local/bin/
    rm "terraform_${TERRAFORM_VERSION}_linux_amd64.zip"
else
    echo "Terraform already installed."
fi
terraform version

# Install Cloudflared
echo "Installing Cloudflared..."
if ! command -v cloudflared &> /dev/null; then
    CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    sudo wget -q -O /usr/local/bin/cloudflared "$CLOUDFLARED_URL"
    sudo chmod +x /usr/local/bin/cloudflared
else
    echo "Cloudflared already installed."
fi
cloudflared --version

# --- 4. CREATE PERSISTENT VXLAN INTERFACE ---
echo "3. Creating persistent VXLAN interface '$VXLAN_IF'..."

# Get the local host's IP address
LOCAL_HOST_IP=$(ip -4 addr show "$PHYSICAL_HOST_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
if [ -z "$LOCAL_HOST_IP" ]; then
    echo "ERROR: Could not find IP for interface '$PHYSICAL_HOST_INTERFACE'."
    exit 1
fi
echo "Local Host IP (via $PHYSICAL_HOST_INTERFACE): $LOCAL_HOST_IP"

# Check if the connection profile already exists and delete it
if nmcli connection show "$VXLAN_CONN_NAME" &> /dev/null; then
    echo "NetworkManager connection '$VXLAN_CONN_NAME' already exists. Recreating..."
    sudo nmcli connection delete "$VXLAN_CONN_NAME"
fi

# Create the new NetworkManager connection profile
sudo nmcli connection add \
    type vxlan \
    con-name "$VXLAN_CONN_NAME" \
    ifname "$VXLAN_IF" \
    vxlan.id "$VNI" \
    vxlan.parent "$PHYSICAL_HOST_INTERFACE" \
    vxlan.remote "$REMOTE_HOST_IP" \
    vxlan.local "$LOCAL_HOST_IP" \
    vxlan.dst-port "$VXLAN_PORT" \
    ipv4.method "manual" \
    ipv4.addresses "$VXLAN_GATEWAY/24"

# Bring the connection online
sudo nmcli connection up "$VXLAN_CONN_NAME"
echo "VXLAN interface '$VXLAN_IF' is up with IP $VXLAN_GATEWAY."

# --- 5. CONFIGURE FIREWALL ---
echo "4. Configuring firewall (firewalld)..."
if command -v firewall-cmd &> /dev/null; then
    echo "Allowing VXLAN (UDP port $VXLAN_PORT) and HTTP/S traffic..."
    sudo firewall-cmd --permanent --add-port=${VXLAN_PORT}/udp
    sudo firewall-cmd --permanent --add-service=http
    sudo firewall-cmd --permanent --add-service=httpsa
    
    echo "Trusting new interface '$VXLAN_IF' in firewalld..."
    sudo firewall-cmd --permanent --zone=trusted --add-interface="$VXLAN_IF"
    
    sudo firewall-cmd --reload
    echo "Firewall rules applied."
fi

# --- 6. CONFIGURE PODMAN NETWORK ---
echo "5. Setting up Podman network '$PODMAN_NETWORK_NAME'..."

# Remove the network if it exists for a clean setup
podman network inspect "$PODMAN_NETWORK_NAME" &> /dev/null && podman network rm "$PODMAN_NETWORK_NAME"

# Create the new Podman network, using the VXLAN gateway
podman network create \
    --driver bridge \
    --subnet="$VXLAN_SUBNET" \
    --gateway="$VXLAN_GATEWAY" \
    "$PODMAN_NETWORK_NAME"
echo "Podman network '$PODMAN_NETWORK_NAME' created."

# --- 7. DEPLOY APPLICATION POD & CONTAINERS ---
echo "6. Deploying application pod '$PODMAN_POD_NAME'..."

# Stop and remove pod if it exists
podman pod exists "$PODMAN_POD_NAME" && podman pod rm -f "$PODMAN_POD_NAME"

# Create the pod, publishing ports 80/443 from the pod to the host
podman pod create \
    --name "$PODMAN_POD_NAME" \
    --network "$PODMAN_NETWORK_NAME" \
    -p 80:80 \
    -p 443:443

echo "Pod '$PODMAN_POD_NAME' created. Deploying services..."

# Create persistent volume for database
podman volume inspect "$POSTGRES_VOLUME" &> /dev/null || podman volume create "$POSTGRES_VOLUME"

# 1. Run PostgreSQL Container
podman run -d --restart always \
    --pod "$PODMAN_POD_NAME" \
    -e POSTGRES_DB="$POSTGRES_DB" \
    -e POSTGRES_USER="$POSTGRES_USER" \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -v "$POSTGRES_VOLUME:/var/lib/postgresql/data" \
    --name "autonomous-db" \
    "$POSTGRES_IMAGE"
echo "PostgreSQL container started."

# 2. Run Django (Gunicorn) Container
#    This container connects to 'autonomous-db' (localhost within the pod)
echo "Starting Django container... (Make sure image '$DJANGO_IMAGE' exists)"
# (Note: Assumes your Django app is configured via env vars)
podman run -d --restart always \
    --pod "$PODMAN_POD_NAME" \
    -e DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@localhost:5432/$POSTGRES_DB" \
    -e DJANGO_SETTINGS_MODULE="your_project.settings" \
    --name "autonomous-django" \
    "$DJANGO_IMAGE" 
echo "Django container started."

# 3. Run Nginx Container
#    This requires a custom nginx.conf file. We'll create a basic one.
echo "Creating default Nginx configuration..."
mkdir -p /tmp/nginx_conf
cat << EOF > /tmp/nginx_conf/default.conf
server {
    listen 80;
    server_name _;

    location /static/ {
        # Path to your static files INSIDE the Django container
        # This requires a shared volume or building static files into Nginx
        alias /var/www/static/; 
    }

    location / {
        proxy_pass http://localhost:8000; # Gunicorn runs on port 8000 (localhost in pod)
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

podman run -d --restart always \
    --pod "$PODMAN_POD_NAME" \
    -v "/tmp/nginx_conf/default.conf:/etc/nginx/conf.d/default.conf:ro" \
    --name "autonomous-nginx" \
    "$NGINX_IMAGE"
echo "Nginx container started."

echo "========================================================"
echo "          AUTONOMOUS AUTONOMOUS SETUP COMPLETE!         "
echo "========================================================"
echo "Pod Status:"
podman pod ps
echo -e "\nContainer Status:"
podman ps -f "pod=$PODMAN_POD_NAME"
echo -e "\nTry accessing the service at http://localhost or http://$VXLAN_GATEWAY"
