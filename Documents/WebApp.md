## Hookprobe.com Web APP - Nginx, python, gunicorn, Django, 

Below is an expanded Ubuntu bash script that installs Podman and then sets up four containers:

1. **PostgreSQL** – your database.
2. **Django** – your web application (built with a custom Dockerfile using Gunicorn).
3. **Nginx** – acting as a reverse proxy in front of Django.
4. **Cloudflared** – to create a secure tunnel from Cloudflare to your Nginx server.

Before running the script, adjust variables (e.g. database credentials, domain names, tunnel IDs) and be sure to provide your Cloudflare credentials file as indicated.

Save the script (e.g. as **setup.sh**), make it executable (`chmod +x setup.sh`), then run it.

```bash
#!/bin/bash
set -e

# --- Update system and install Podman ---
echo "Updating package lists and installing Podman..."
sudo apt-get update
sudo apt-get install -y podman

# --- Create a Podman network for inter-container communication ---
NETWORK_NAME="mynetwork"
echo "Creating Podman network '${NETWORK_NAME}'..."
sudo podman network create ${NETWORK_NAME} || echo "Network '${NETWORK_NAME}' already exists."

# --- Run PostgreSQL container ---
DB_CONTAINER_NAME="postgres"
DB_USER="myuser"
DB_PASSWORD="mypassword"
DB_NAME="mydb"
echo "Starting PostgreSQL container..."
sudo podman run -d \
  --name ${DB_CONTAINER_NAME} \
  --network ${NETWORK_NAME} \
  -e POSTGRES_USER=${DB_USER} \
  -e POSTGRES_PASSWORD=${DB_PASSWORD} \
  -e POSTGRES_DB=${DB_NAME} \
  -p 5432:5432 \
  postgres:latest

# --- Prepare Django application ---
APP_DIR="django_app"
mkdir -p ${APP_DIR}
cd ${APP_DIR}

# If you don't already have a Django project, create one.
if [ ! -d "myproject" ]; then
    echo "Setting up a new Django project..."
    python3 -m venv venv
    source venv/bin/activate
    pip install Django gunicorn psycopg2-binary
    django-admin startproject myproject .
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
FROM python:3.9-slim

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
CMD ["gunicorn", "myproject.wsgi:application", "--bind", "0.0.0.0:8000"]
EOF

# Build the Django container image.
IMAGE_NAME="mydjango"
echo "Building Django image '${IMAGE_NAME}'..."
sudo podman build -t ${IMAGE_NAME} .

# Run the Django container.
echo "Starting Django container..."
sudo podman run -d \
  --name django \
  --network ${NETWORK_NAME} \
  -p 8000:8000 \
  -e DATABASE_NAME=${DB_NAME} \
  -e DATABASE_USER=${DB_USER} \
  -e DATABASE_PASSWORD=${DB_PASSWORD} \
  -e DATABASE_HOST=${DB_CONTAINER_NAME} \
  ${IMAGE_NAME}

cd ..

# --- Setup Nginx container ---
NGINX_DIR="nginx_conf"
mkdir -p ${NGINX_DIR}

# Create a basic Nginx configuration to proxy requests to the Django container.
cat > ${NGINX_DIR}/default.conf << 'EOF'
server {
    listen 80;
    server_name your.domain.com;  # Replace with your actual domain

    location / {
        proxy_pass http://django:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

echo "Starting Nginx container..."
sudo podman run -d \
  --name nginx \
  --network ${NETWORK_NAME} \
  -p 80:80 \
  -v "$(pwd)/${NGINX_DIR}/default.conf":/etc/nginx/conf.d/default.conf:ro \
  nginx:alpine

# --- Setup Cloudflared container ---
CLOUDFLARED_DIR="cloudflared"
mkdir -p ${CLOUDFLARED_DIR}

# Create a sample Cloudflared configuration.
cat > ${CLOUDFLARED_DIR}/config.yml << 'EOF'
tunnel: YOUR_TUNNEL_ID           # Replace with your Cloudflare Tunnel ID
credentials-file: /etc/cloudflared/credentials.json

ingress:
  - hostname: your.domain.com    # Replace with your actual domain
    service: http://nginx:80
  - service: http_status:404
EOF

echo "Please place your Cloudflare credentials JSON file in the '${CLOUDFLARED_DIR}' directory as 'credentials.json'."
echo "Starting Cloudflared container..."
sudo podman run -d \
  --name cloudflared \
  --network ${NETWORK_NAME} \
  -v "$(pwd)/${CLOUDFLARED_DIR}":/etc/cloudflared \
  cloudflare/cloudflared:latest tunnel --config /etc/cloudflared/config.yml run

echo "Setup complete."
echo "Your Django web server (with PostgreSQL) is now running behind Nginx (port 80)."
echo "Cloudflared is active and forwarding traffic from Cloudflare to your Nginx container."
```

---

### Explanation

- **PostgreSQL Container:**  
  Runs a PostgreSQL instance with defined environment variables for user, password, and database.

- **Django Application:**  
  The script creates (or reuses) a Django project, builds a container image using a simple Dockerfile, and runs it. The Django app expects database connection details from environment variables.

- **Nginx Container:**  
  An Nginx container is started with a custom configuration (saved in `nginx_conf/default.conf`) that reverse-proxies incoming HTTP traffic on port 80 to the Django container running on port 8000. Update the `server_name` with your actual domain.

- **Cloudflared Container:**  
  A Cloudflared container is set up to establish a secure tunnel from Cloudflare to your Nginx container. A sample configuration (`cloudflared/config.yml`) is created—you must replace placeholder values (like `YOUR_TUNNEL_ID` and `your.domain.com`) with your actual Cloudflare Tunnel ID and domain, and place your Cloudflare credentials JSON file in the `cloudflared` directory.

This comprehensive setup leverages Podman to run each service in its own container while ensuring they can communicate via a custom network. Adjust configurations as needed for your environment.
