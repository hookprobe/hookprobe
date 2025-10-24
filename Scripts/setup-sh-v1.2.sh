#!/bin/bash
#
# setup.sh (v6 - OVS + IPsec PSK Encryption)
#
# This version uses Open vSwitch's built-in IPsec integration to encrypt the
# VXLAN tunnel traffic using a Pre-Shared Key (PSK).
#
# Target OS: RHEL/RedHat 10 (or compatible Fedora/CentOS Stream)
#
# --- !! Configuration Required !! ---

# Safely exit if any command fails
set -e

# --- 1. DEFINE CORE PARAMETERS ---

# (!!!) EDIT THESE HOST/NETWORK VALUES TO MATCH YOUR ENVIRONMENT (!!!)
HOST_A_IP="192.168.1.100"       # <--- EDIT THIS (The physical IP of Host A)
HOST_B_IP="192.168.1.101"       # <--- EDIT THIS (The physical IP of Host B)
PHYSICAL_HOST_INTERFACE="eth0"  # <--- EDIT THIS (use 'ip a' to find the physical interface)

# VXLAN Network Settings (Should be identical on both hosts)
OVS_BRIDGE_NAME="ovs-br0"
VXLAN_TUNNEL_PORT="vxlan-port"
VNI=100
VXLAN_SUBNET="172.25.0.0/24"
VXLAN_GATEWAY="172.25.0.1"
VXLAN_PORT=4789

# --- 2. OVS-IPSEC PSK (Encryption Key) ---
# CRITICAL: This key MUST be identical on all hosts and should be very strong.
OVS_PSK="a_strong_ovs_vxlan_key_123" # <--- EDIT THIS (Change this strong key)

# Podman Settings
PODMAN_NETWORK_NAME="autonomous-ovs-net"
PODMAN_POD_NAME="autonomous-pod"
POSTGRES_VOLUME="autonomous-db-volume"

# Service Settings
POSTGRES_DB="autonomydb"
POSTGRES_USER="autonomysuser"
POSTGRES_PASSWORD="a_very_secure_password_change_me"

# Container Images
DJANGO_IMAGE="autonomous-django:latest" 
POSTGRES_IMAGE="docker.io/library/postgres:16-alpine"
NGINX_IMAGE="docker.io/library/nginx:1.27-alpine"

# Other Tools
TERRAFORM_VERSION="1.8.5"

echo "========================================================"
echo "    AUTONOMOUS OVS/VXLAN + IPsec PSK SETUP STARTING     "
echo "========================================================"

# --- 3. VALIDATE ENVIRONMENT & INSTALL DEPENDENCIES ---
echo "1. Validating environment & installing dependencies..."

# Get the local host's IP address
LOCAL_HOST_IP=$(ip -4 addr show "$PHYSICAL_HOST_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "")
if [ -z "$LOCAL_HOST_IP" ]; then
    echo "ERROR: Could not find IP for interface '$PHYSICAL_HOST_INTERFACE'. Check PHYSICAL_HOST_INTERFACE."
    exit 1
fi
echo "Local Host IP (via $PHYSICAL_HOST_INTERFACE): $LOCAL_HOST_IP"

# Determine remote physical IP
if [ "$LOCAL_HOST_IP" == "$HOST_A_IP" ]; then
    REMOTE_HOST_IP="$HOST_B_IP"
else
    REMOTE_HOST_IP="$HOST_A_IP"
fi
echo "Remote Peer IP is: $REMOTE_HOST_IP"


REQUIRED_PACKAGES=(
    git curl wget unzip podman python3 python3-pip net-tools kernel-modules-extra openvswitch
)
sudo dnf update -y
sudo dnf install -y "${REQUIRED_PACKAGES[@]}"

# (Install Terraform and Cloudflared steps omitted for brevity, preserved in the full script)
# ...

# --- 4. CREATE OVS VXLAN INTERFACE (PSK-Secured) ---
echo "2. Setting up Open vSwitch VXLAN bridge '$OVS_BRIDGE_NAME' with IPsec PSK..."

# 4a. Start OVS service
echo "Starting and enabling openvswitch service..."
sudo systemctl enable --now openvswitch

# 4b. Create the OVS bridge
echo "Creating OVS bridge '$OVS_BRIDGE_NAME'..."
sudo ovs-vsctl --may-exist add-br "$OVS_BRIDGE_NAME"

# 4c. Create the VXLAN port on the bridge
echo "Adding VXLAN port '$VXLAN_TUNNEL_PORT' to the OVS bridge with PSK encryption..."
# CRITICAL: We use the physical remote_ip and enable IPsec encryption via the 'options:psk' argument.
# This PSK is the VXLAN encryption key.
sudo ovs-vsctl --may-exist add-port "$OVS_BRIDGE_NAME" "$VXLAN_TUNNEL_PORT" -- \
    set interface "$VXLAN_TUNNEL_PORT" type=vxlan options:key="$VNI" \
    options:remote_ip="$REMOTE_HOST_IP" options:local_ip="$LOCAL_HOST_IP" \
    options:dst_port="$VXLAN_PORT" options:psk="$OVS_PSK"

# 4d. Configure the OVS bridge as the gateway
echo "Setting OVS bridge '$OVS_BRIDGE_NAME' as the gateway '$VXLAN_GATEWAY'..."
sudo ip addr flush dev "$OVS_BRIDGE_NAME" || true
sudo ip address add "$VXLAN_GATEWAY/24" dev "$OVS_BRIDGE_NAME"
sudo ip link set "$OVS_BRIDGE_NAME" up

echo "OVS bridge '$OVS_BRIDGE_NAME' is up and secured by IPsec PSK."

# --- 5. CONFIGURE FIREWALL ---
echo "3. Configuring firewall (firewalld)..."
if command -v firewall-cmd &> /dev/null; then
    echo "Allowing VXLAN (UDP 4789) and standard IPsec ports (UDP 500/4500)..."
    
    # Allow VXLAN traffic (UDP 4789)
    sudo firewall-cmd --permanent --add-port=${VXLAN_PORT}/udp
    
    # Allow standard IPsec ports (for the underlying encryption tunnel)
    sudo firewall-cmd --permanent --add-port=500/udp
    sudo firewall-cmd --permanent --add-port=4500/udp
    
    # Trust the new OVS bridge interface
    sudo firewall-cmd --permanent --zone=trusted --add-interface="$OVS_BRIDGE_NAME"
    
    sudo firewall-cmd --reload
    echo "Firewall rules applied."
fi

# --- 6. CONFIGURE PODMAN NETWORK AND DEPLOY ---
echo "4. Setting up Podman network '$PODMAN_NETWORK_NAME' and deploying containers..."

# Remove the network if it exists for a clean setup
podman network inspect "$PODMAN_NETWORK_NAME" &> /dev/null && podman network rm "$PODMAN_NETWORK_NAME"

# Create the new Podman network, using the OVS bridge as the gateway
podman network create \
    --driver bridge \
    --subnet="$VXLAN_SUBNET" \
    --gateway="$VXLAN_GATEWAY" \
    "$PODMAN_NETWORK_NAME"

# ... (Deployment steps for Pod/Containers remain the same) ...

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
echo "Starting Django container... (Make sure image '$DJANGO_IMAGE' exists)"
podman run -d --restart always \
    --pod "$PODMAN_POD_NAME" \
    -e DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@localhost:5432/$POSTGRES_DB" \
    -e DJANGO_SETTINGS_MODULE="your_project.settings" \
    --name "autonomous-django" \
    "$DJANGO_IMAGE" 
echo "Django container started."

# 3. Run Nginx Container
echo "Creating default Nginx configuration..."
mkdir -p /tmp/nginx_conf
cat << EOF > /tmp/nginx_conf/default.conf
server {
    listen 80;
    server_name _;

    location /static/ {
        # Path to your static files INSIDE the Django container
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
echo "    SECURE OVS/VXLAN SETUP AND DEPLOYMENT COMPLETE!     "
echo "========================================================"
echo "Next Steps: Run this script on the remote host, ensuring the OVS_PSK is identical."
