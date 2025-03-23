#!/bin/bash
# -- version 1.0 hookprobe.com --- Ubuntu 24.10
set -e

# --- Update system and install podman & OpenVirtualSwitch ---
echo "Updating package lists and installing podman..."
sudo apt-get update
sudo apt-get install -y podman

sudo apt-get install -y openvswitch-switch

# --- podman images for the web app containers ---
podman image pull postgres:alpine
podman image pull python:3.12-slim
podman image pull nginx:alpine

source network-config.sh

#---------------------
echo "Setup Application. Please wait ...."

# --- Begin by starting fresh a new network ap from here ---
podman app create ${APP_NAME}
podman volume create ${DB_APP}

# --- Create a podman network for inter-container communication with ROOT containers ^change --net to ${NETWORK_NAME} ---
#NETWORK_NAME="mynetwork"
#echo "Creating podman network '${NETWORK_NAME}'..."
#sudo podman network create ${NETWORK_NAME} || echo "Network '${NETWORK_NAME}' already exists."
#      ${NETWORK_NAME}

# --- Create a OVS Bridge ---
sudo ip netns add ${APP_NAME}
sudo ip netns exec ${APP_NAME} ovs-vsctl add-br ${APP_NAME}
sudo ip link set ${APP_NAME} up

# --- Create a VXLAN over the Bridged Interface with IP, password, and key TAG ---
sudo ovs-vsctl add-port ${APP_NAME} vxlanA -- set interface vxlanA type=vxlan options:remote_ip=${VXLAN_IP} options:key=${PSQL_KEY} options:psk=${APP_PSK}
sudo ip link set ovs-system up

# --- Run PostgreSQL container ---
echo "Starting PostgreSQL container..."
podman run -d \
  --name ${DB_CONTAINER_NAME} \
  --app=${APP_NAME} \
  --net=${NETWORK_NAME} \
  -e POSTGRES_USER=${DB_USER} \
  -e POSTGRES_PASSWORD=${DB_PASSWORD} \
  -e POSTGRES_DB=${DB_NAME} \
  -v ${DB_APP}:/var/lib/pgsql/data:Z \
  postgres:alpine

# Get the container's PID using podman inspect.
CONT_PERSISTENT_PID=$(podman inspect --format '{{.State.Pid}}' "${DB_CONTAINER_NAME}")


# Use nsenter to add a virtual Ethernet interface pair in the container's network namespace.
sudo ip link add dev ${PSQL_OVS} type veth peer name ${PSQL_NETNS}
sudo ip link set ${PSQL_OVS} up
sudo ip link set netns "$CONT_PERSISTENT_PID" dev ${PSQL_NETNS}
sudo ovs-vsctl add-port ${APP_NAME} ${PSQL_OVS}
sudo nsenter -t "$CONT_PERSISTENT_PID" -n ip link set ${PSQL_NETNS} up
sudo nsenter -t "$CONT_PERSISTENT_PID" -n ip addr add ${PSQL_IP}/24 dev ${PSQL_NETNS}
sudo nsenter -t "$CONT_PERSISTENT_PID" -n ip route add default via ${CT_DEF_GW} dev ${PSQL_NETNS}

# --- Add a gateway to the App Brige to pass traffic SNAT/DNAT or PAT.
sudo ip link add app-gatewayhost type veth peer name app-gatewayovs
sudo ovs-vsctl add-port ${APP_NAME} app-gatewayovs
sudo ip link set app-gatewayovs up
sudo ip link set app-gatewayhost up
sudo ip addr add ${CT_DEF_GW}/24 dev app-gatewayhost
sudo nsenter -t "$CONT_PERSISTENT_PID" -n ping -c 1 ${CT_DEF_GW}


# --- Prepare Django application ---
APP_DIR="web_app"
mkdir -p ${APP_DIR}
cd ${APP_DIR}
DJANGO_APP_NAME="django_app"

# If you don't already have a Django project, create one.
if [ ! -d "${DJANGO_APP_NAME}" ]; then
    echo "Setting up a new Django project..."
    python3 -m venv venv
    source venv/bin/activate
    pip install Django gunicorn psycopg2-binary
    django-admin startproject ${DJANGO_APP_NAME} .
    deactivate
fi

# Create a requirements file for the Django project.
cat > requirements.txt << 'EOF'
Django>=3.2,<4.0
gunicorn
psycopg2-binary
EOF

# --- Create a Dockerfile for the Django container ---
cat > Dockerfile << 'EOF'
FROM python:3.12-slim

# Ensure Python output is not buffered.
ENV PYTHONUNBUFFERED=1

# Install build dependencies.
RUN apt-get update && apt-get install -y build-essential libpq-dev gcc && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies.
COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the Django project code.
COPY . /app/

# Use Gunicorn to serve the Django application.
CMD ["gunicorn", "${DJANGO_APP_NAME}.wsgi:application", "--bind", "0.0.0.0:8000"]
EOF

# Build the Django container image.
IMAGE_NAME="django-app"
echo "Building Django image '${IMAGE_NAME}'..."
podman build -t ${IMAGE_NAME} .

# Run the Django container.
echo "Starting Django container..."
podman run -d \
  --name ${DJANGO_CT_NAME} \
  --net=${NETWORK_NAME} \
  --app=${APP_NAME} \
  -e DATABASE_NAME=${DB_NAME} \
  -e DATABASE_USER=${DB_USER} \
  -e DATABASE_PASSWORD=${DB_PASSWORD} \
  -e DATABASE_HOST=${PSQL_IP} \
  ${IMAGE_NAME}

cd ..
CONT_DJANGO_PID=$(podman inspect --format '{{.State.Pid}}' "${DJANGO_CT_NAME}")
# Use nsenter to add a virtual Ethernet interface pair in the container's network namespace.
sudo ip link add dev ${DJANGO_OVS} type veth peer name ${DJANGO_NETNS}
sudo ip link set ${DJANGO_OVS} up
sudo ip link set netns "$CONT_DJANGO_PID" dev ${DJANGO_NETNS}
sudo ovs-vsctl add-port ${APP_NAME} ${DJANGO_OVS}
sudo nsenter -t "$CONT_DJANGO_PID" -n ip link set ${DJANGO_NETNS} up
sudo nsenter -t "$CONT_DJANGO_PID" -n ip addr add ${DJANGO_IP}/24 dev ${DJANGO_NETNS}
sudo nsenter -t "$CONT_DJANGO_PID" -n ip route add default via ${CT_DEF_GW} dev ${DJANGO_NETNS}
sudo nsenter -t "$CONT_DJANGO_PID" -n ping -c 1 ${CT_DEF_GW}
echo "Fininshed Django container installation for '${IMAGE_NAME}'..."

# --- Setup Nginx container ---
NGINX_DIR="nginx_conf"
mkdir -p ${NGINX_DIR}

# Create a basic Nginx configuration to proxy requests to the Django container.
cat > ${NGINX_DIR}/default.conf << 'EOF'
server {
    listen 80;
    server_name your-website.com;  # Replace with your actual domain

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

echo "Starting Nginx container..."
podman run -d \
  --name ${NGINX_CT_NAME} \
  --app=${APP_NAME} \
  --net=${NETWORK_NAME} \
  -v "$(pwd)/${NGINX_DIR}/default.conf":/etc/nginx/conf.d/default.conf:ro \
  nginx:alpine


CONT_NGINX_PID=$(podman inspect --format '{{.State.Pid}}' "${NGINX_CT_NAME}")
# Use nsenter to add a virtual Ethernet interface pair in the container's network namespace.
sudo ip link add dev ${NGINX_OVS} type veth peer name ${NGINX_NETNS}
sudo ip link set ${NGINX_OVS} up
sudo ip link set netns "$CONT_NGINX_PID" dev ${NGINX_NETNS}
sudo ovs-vsctl add-port ${APP_NAME} ${NGINX_OVS}
sudo nsenter -t "$CONT_NGINX_PID" -n ip link set ${NGINX_NETNS} up
sudo nsenter -t "$CONT_NGINX_PID" -n ip addr add ${NGINX_IP}/24 dev ${NGINX_NETNS}
sudo nsenter -t "$CONT_NGINX_PID" -n ip route add default via ${CT_DEF_GW} dev ${NGINX_NETNS}
sudo nsenter -t "$CONT_NGINX_PID" -n ping -c 1 ${CT_DEF_GW}

echo "Fininshed NGINX container installation ..."

# --- Setup Cloudflared container ---
CLOUDFLARED_DIR="cloudflared"
mkdir -p ${CLOUDFLARED_DIR}

# Create a sample Cloudflared configuration.
cat > ${CLOUDFLARED_DIR}/config.yml << 'EOF'
tunnel: YOUR_TUNNEL_ID           # Replace with your Cloudflare Tunnel ID
credentials-file: /etc/cloudflared/credentials.json

ingress:
  - hostname: your-webiste.com    # Replace with your actual domain
    service: http://nginx:80
  - service: http_status:404
EOF

echo "Please place your Cloudflare credentials JSON file in the '${CLOUDFLARED_DIR}' directory as 'credentials.json'."
echo "Starting Cloudflared container..."
podman run -d \
  --name ${CLOUDFLARED_CT_NAME} \
  --app=${APP_NAME} \
  --net=${NETWORK_NAME} \
  -v "$(pwd)/${CLOUDFLARED_DIR}":/etc/cloudflared \
  cloudflare/cloudflared:alpine tunnel --config /etc/cloudflared/config.yml run

CONT_CLOUDFLARED_PID=$(podman inspect --format '{{.State.Pid}}' "${CLOUDFLARED_CT_NAME}")

# Use nsenter to add a virtual Ethernet interface pair in the container's network namespace.
sudo ip link add dev ${CFL_OVS} type veth peer name ${CLF_NETNS}
sudo ip link set ${CFL_OVS} up
sudo ip link set netns "$CONT_CLOUDFLARED_PID" dev ${CFL_NETNS}
sudo ovs-vsctl add-port ${APP_NAME} ${CFL_OVS}
sudo nsenter -t "$CONT_CLOUDFLARED_PID" -n ip link set ${CFL_NETNS} up
sudo nsenter -t "$CONT_CLOUDFLARED_PID" -n ip addr add ${CFL_IP}/24 dev ${CLF_NETNS}
sudo nsenter -t "$CONT_CLOUDFLARED_PID" -n ip route add default via ${CT_DEF_GW} dev ${CFL_NETNS}
sudo nsenter -t "$CONT_CLOUDFLARED_PID" -n ping -c 1 ${CT_DEF_GW}

echo "Setup complete."
echo "Your Django web server (with PostgreSQL) is now running behind Nginx (port 80)."
echo "Cloudflared is active and forwarding traffic from Cloudflare to your Nginx container."
